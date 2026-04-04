use std::net::TcpListener;
use std::path::PathBuf;
use std::process::{
  Child,
  Command,
  Stdio,
};
use std::time::Duration;

use aes_gcm::aead::{
  Aead,
  KeyInit,
};
use aes_gcm::{
  Aes256Gcm,
  Nonce,
};
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use chrono::Utc;
use hmac::{
  Hmac,
  Mac,
};
use jsonwebtoken::{
  Algorithm,
  EncodingKey,
  Header,
  encode,
};
use reqwest::StatusCode;
use serde::Serialize;
use sha1::Sha1;
use sha2::{
  Digest,
  Sha256,
};
use sqlx::PgPool;
use uuid::Uuid;

const JWT_SECRET: &str = "integration-test-jwt-secret-with-32-bytes";
const MFA_KEY_MATERIAL: &str = "integration-test-mfa-key-material-32bytes";
const TOTP_PERIOD_SECS: i64 = 30;
const TOTP_DIGITS: u32 = 6;

type HmacSha1 = Hmac<Sha1>;

struct TestContext {
  pool: PgPool,
  client: reqwest::Client,
  base_url: String,
  issuer: String,
  jwt_secret: String,
  mfa_key_material: String,
  child: Child,
}

impl Drop for TestContext {
  fn drop(&mut self) {
    let _ = self.child.kill();
    let _ = self.child.wait();
  }
}

#[derive(Debug, Serialize)]
struct TestClaims {
  sub: String,
  aud: String,
  exp: i64,
  iat: i64,
  iss: String,
  email: Option<String>,
  phone: Option<String>,
  role: String,
  aal: String,
  amr: Vec<serde_json::Value>,
  session_id: String,
  is_anonymous: bool,
  user_metadata: serde_json::Value,
  app_metadata: serde_json::Value,
}

fn database_url() -> Option<String> {
  std::env::var("DATABASE_URL").ok()
}

fn unique_suffix() -> String {
  Uuid::new_v4().simple().to_string()
}

fn reserve_port() -> u16 {
  let listener = TcpListener::bind("127.0.0.1:0").expect("bind test port");
  listener.local_addr().expect("read test port").port()
}

fn pid_file_path(port: u16) -> PathBuf {
  std::env::temp_dir().join(format!("haya-integration-{port}.pid"))
}

async fn migrate_database(database_url: &str) {
  let status = Command::new(env!("CARGO_BIN_EXE_haya"))
    .env("DATABASE_URL", database_url)
    .env("JWT_SECRET", JWT_SECRET)
    .env("MFA_ENCRYPTION_KEY", MFA_KEY_MATERIAL)
    .arg("db")
    .arg("migrate")
    .status()
    .expect("run db migrate");
  assert!(status.success(), "db migrate failed");
}

async fn wait_for_health(client: &reqwest::Client, base_url: &str) {
  let deadline = std::time::Instant::now() + Duration::from_secs(10);
  loop {
    if let Ok(response) = client.get(format!("{base_url}/health")).send().await
      && response.status().is_success()
    {
      return;
    }
    assert!(
      std::time::Instant::now() < deadline,
      "server did not become healthy in time"
    );
    tokio::time::sleep(Duration::from_millis(100)).await;
  }
}

async fn test_context() -> Option<TestContext> {
  let database_url = database_url()?;
  migrate_database(&database_url).await;

  let port = reserve_port();
  let base_url = format!("http://127.0.0.1:{port}");
  let pid_file = pid_file_path(port);
  let child = Command::new(env!("CARGO_BIN_EXE_haya"))
    .env("DATABASE_URL", &database_url)
    .env("JWT_SECRET", JWT_SECRET)
    .env("MFA_ENCRYPTION_KEY", MFA_KEY_MATERIAL)
    .env("PORT", port.to_string())
    .env("SITE_URL", &base_url)
    .env("HAYA_PID_FILE", &pid_file)
    .stdout(Stdio::null())
    .stderr(Stdio::null())
    .spawn()
    .expect("spawn haya server");

  let client = reqwest::Client::new();
  wait_for_health(&client, &base_url).await;

  Some(TestContext {
    pool: PgPool::connect(&database_url).await.expect("connect test db"),
    client,
    base_url: base_url.clone(),
    issuer: base_url,
    jwt_secret: JWT_SECRET.to_string(),
    mfa_key_material: MFA_KEY_MATERIAL.to_string(),
    child,
  })
}

async fn insert_user(pool: &PgPool, email: &str) -> Uuid {
  let user_id = Uuid::new_v4();
  let now = Utc::now();
  sqlx::query(
    "INSERT INTO auth.users (id, aud, role, email, email_confirmed_at, created_at, updated_at) VALUES ($1, 'authenticated', 'authenticated', $2, $3, $3, $3)",
  )
  .bind(user_id)
  .bind(email)
  .bind(now)
  .execute(pool)
  .await
  .expect("insert user");
  user_id
}

async fn cleanup_user(pool: &PgPool, user_id: Uuid) {
  let _ = sqlx::query("DELETE FROM auth.users WHERE id = $1")
    .bind(user_id)
    .execute(pool)
    .await;
}

async fn create_session(pool: &PgPool, user_id: Uuid) -> Uuid {
  let session_id = Uuid::new_v4();
  let now = Utc::now();
  sqlx::query(
    "INSERT INTO auth.sessions (id, user_id, aal, created_at, updated_at) VALUES ($1, $2, 'aal1'::auth.aal_level, $3, $3)",
  )
  .bind(session_id)
  .bind(user_id)
  .bind(now)
  .execute(pool)
  .await
  .expect("insert session");
  session_id
}

fn issue_access_token(
  issuer: &str,
  jwt_secret: &str,
  user_id: Uuid,
  session_id: Uuid,
  email: &str,
) -> String {
  let now = Utc::now().timestamp();
  let claims = TestClaims {
    sub: user_id.to_string(),
    aud: "authenticated".to_string(),
    exp: now + 300,
    iat: now,
    iss: issuer.to_string(),
    email: Some(email.to_string()),
    phone: None,
    role: "authenticated".to_string(),
    aal: "aal1".to_string(),
    amr: vec![serde_json::json!({"method": "password", "timestamp": now})],
    session_id: session_id.to_string(),
    is_anonymous: false,
    user_metadata: serde_json::json!({}),
    app_metadata: serde_json::json!({}),
  };

  encode(
    &Header::new(Algorithm::HS256),
    &claims,
    &EncodingKey::from_secret(jwt_secret.as_bytes()),
  )
  .expect("encode test token")
}

fn derive_encryption_key(material: &str) -> [u8; 32] {
  let digest = Sha256::digest(material.as_bytes());
  let mut key = [0u8; 32];
  key.copy_from_slice(&digest);
  key
}

fn encrypt_secret(secret: &[u8], key_material: &[u8; 32]) -> String {
  let cipher = Aes256Gcm::new_from_slice(key_material).expect("init cipher");
  let nonce_bytes = [7u8; 12];
  let ciphertext = cipher
    .encrypt(Nonce::from_slice(&nonce_bytes), secret)
    .expect("encrypt secret");
  format!(
    "v1.{}.{}",
    URL_SAFE_NO_PAD.encode(nonce_bytes),
    URL_SAFE_NO_PAD.encode(ciphertext)
  )
}

fn generate_totp(secret: &[u8], timestamp: i64) -> String {
  let counter = timestamp.div_euclid(TOTP_PERIOD_SECS) as u64;
  let mut mac = <HmacSha1 as Mac>::new_from_slice(secret).expect("init hmac");
  mac.update(&counter.to_be_bytes());
  let result = mac.finalize().into_bytes();
  let offset = (result[19] & 0x0f) as usize;
  let binary = ((u32::from(result[offset]) & 0x7f) << 24)
    | (u32::from(result[offset + 1]) << 16)
    | (u32::from(result[offset + 2]) << 8)
    | u32::from(result[offset + 3]);
  format!("{:06}", binary % 10u32.pow(TOTP_DIGITS))
}

async fn insert_unverified_totp_factor(pool: &PgPool, user_id: Uuid, key_material: &str) -> (Uuid, Vec<u8>) {
  let factor_id = Uuid::new_v4();
  let secret = b"12345678901234567890".to_vec();
  let encrypted_secret = encrypt_secret(&secret, &derive_encryption_key(key_material));
  let now = Utc::now();
  sqlx::query(
    "INSERT INTO auth.mfa_factors (id, user_id, friendly_name, factor_type, status, secret, created_at, updated_at) VALUES ($1, $2, 'Primary', 'totp'::auth.factor_type, 'unverified'::auth.factor_status, $3, $4, $4)",
  )
  .bind(factor_id)
  .bind(user_id)
  .bind(encrypted_secret)
  .bind(now)
  .execute(pool)
  .await
  .expect("insert totp factor");
  (factor_id, secret)
}

#[tokio::test]
async fn recover_respects_token_regeneration_cooldown() {
  let Some(ctx) = test_context().await else {
    return;
  };

  let email = format!("recover-{}@example.com", unique_suffix());
  let user_id = insert_user(&ctx.pool, &email).await;
  let original_token = "existing-recovery-token";
  let sent_at = Utc::now();
  sqlx::query("UPDATE auth.users SET recovery_token = $1, recovery_sent_at = $2 WHERE id = $3")
    .bind(original_token)
    .bind(sent_at)
    .bind(user_id)
    .execute(&ctx.pool)
    .await
    .expect("seed recovery token");

  let response = ctx
    .client
    .post(format!("{}/recover", ctx.base_url))
    .json(&serde_json::json!({ "email": email }))
    .send()
    .await
    .expect("call recover");
  assert_eq!(response.status(), StatusCode::OK);

  let row: (String, Option<chrono::DateTime<Utc>>) =
    sqlx::query_as("SELECT recovery_token, recovery_sent_at FROM auth.users WHERE id = $1")
      .bind(user_id)
      .fetch_one(&ctx.pool)
      .await
      .expect("fetch recovery state");
  assert_eq!(row.0, original_token);
  assert_eq!(row.1, Some(sent_at));

  cleanup_user(&ctx.pool, user_id).await;
}

#[tokio::test]
async fn resend_signup_respects_token_regeneration_cooldown() {
  let Some(ctx) = test_context().await else {
    return;
  };

  let email = format!("resend-{}@example.com", unique_suffix());
  let user_id = insert_user(&ctx.pool, &email).await;
  let original_token = "existing-confirmation-token";
  let sent_at = Utc::now();
  sqlx::query("UPDATE auth.users SET confirmation_token = $1, confirmation_sent_at = $2 WHERE id = $3")
    .bind(original_token)
    .bind(sent_at)
    .bind(user_id)
    .execute(&ctx.pool)
    .await
    .expect("seed confirmation token");

  let response = ctx
    .client
    .post(format!("{}/resend", ctx.base_url))
    .json(&serde_json::json!({ "type": "signup", "email": email }))
    .send()
    .await
    .expect("call resend");
  assert_eq!(response.status(), StatusCode::OK);

  let row: (String, Option<chrono::DateTime<Utc>>) =
    sqlx::query_as("SELECT confirmation_token, confirmation_sent_at FROM auth.users WHERE id = $1")
      .bind(user_id)
      .fetch_one(&ctx.pool)
      .await
      .expect("fetch confirmation state");
  assert_eq!(row.0, original_token);
  assert_eq!(row.1, Some(sent_at));

  cleanup_user(&ctx.pool, user_id).await;
}

#[tokio::test]
async fn totp_enrollment_rejects_replay_of_same_step() {
  let Some(ctx) = test_context().await else {
    return;
  };

  let email = format!("mfa-replay-{}@example.com", unique_suffix());
  let user_id = insert_user(&ctx.pool, &email).await;
  let session_id = create_session(&ctx.pool, user_id).await;
  let token = issue_access_token(&ctx.issuer, &ctx.jwt_secret, user_id, session_id, &email);
  let (factor_id, secret) = insert_unverified_totp_factor(&ctx.pool, user_id, &ctx.mfa_key_material).await;
  let code = generate_totp(&secret, Utc::now().timestamp());

  let first = ctx
    .client
    .post(format!("{}/factors/{factor_id}/verify", ctx.base_url))
    .bearer_auth(&token)
    .json(&serde_json::json!({ "code": code }))
    .send()
    .await
    .expect("first factor verify");
  assert_eq!(first.status(), StatusCode::OK);

  let second = ctx
    .client
    .post(format!("{}/factors/{factor_id}/verify", ctx.base_url))
    .bearer_auth(&token)
    .json(&serde_json::json!({ "code": code }))
    .send()
    .await
    .expect("second factor verify");
  assert_eq!(second.status(), StatusCode::UNPROCESSABLE_ENTITY);
  let body: serde_json::Value = second.json().await.expect("decode replay error");
  assert!(
    body["msg"]
      .as_str()
      .unwrap_or_default()
      .contains("already been used")
  );

  cleanup_user(&ctx.pool, user_id).await;
}

#[tokio::test]
async fn totp_enrollment_blocks_after_too_many_attempts() {
  let Some(ctx) = test_context().await else {
    return;
  };

  let email = format!("mfa-attempts-{}@example.com", unique_suffix());
  let user_id = insert_user(&ctx.pool, &email).await;
  let session_id = create_session(&ctx.pool, user_id).await;
  let token = issue_access_token(&ctx.issuer, &ctx.jwt_secret, user_id, session_id, &email);
  let (factor_id, secret) = insert_unverified_totp_factor(&ctx.pool, user_id, &ctx.mfa_key_material).await;

  for _ in 0..10 {
    let response = ctx
      .client
      .post(format!("{}/factors/{factor_id}/verify", ctx.base_url))
      .bearer_auth(&token)
      .json(&serde_json::json!({ "code": "000000" }))
      .send()
      .await
      .expect("invalid factor verify");
    assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);
  }

  let valid_code = generate_totp(&secret, Utc::now().timestamp());
  let blocked = ctx
    .client
    .post(format!("{}/factors/{factor_id}/verify", ctx.base_url))
    .bearer_auth(&token)
    .json(&serde_json::json!({ "code": valid_code }))
    .send()
    .await
    .expect("blocked factor verify");
  assert_eq!(blocked.status(), StatusCode::UNPROCESSABLE_ENTITY);
  let body: serde_json::Value = blocked.json().await.expect("decode blocked response");
  assert!(
    body["msg"]
      .as_str()
      .unwrap_or_default()
      .contains("Too many TOTP verification attempts")
  );

  cleanup_user(&ctx.pool, user_id).await;
}
