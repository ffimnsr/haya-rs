use std::io::{
  BufRead,
  BufReader,
};
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
  DecodingKey,
  EncodingKey,
  Header,
  Validation,
  decode,
  encode,
};
use passkey_authenticator::{
  Authenticator,
  MockUserValidationMethod,
};
use passkey_client::{
  Client,
  DefaultClientData,
};
use passkey_crypto::AvailableBackend;
use passkey_types::Passkey;
use passkey_types::ctap2::Aaguid;
use passkey_types::webauthn::{
  CreatedPublicKeyCredential,
  CredentialCreationOptions,
  CredentialRequestOptions,
};
use reqwest::StatusCode;
use serde::{
  Deserialize,
  Serialize,
};
use sha1::Sha1;
use sha2::{
  Digest,
  Sha256,
};
use sqlx::PgPool;
use uuid::Uuid;

const JWT_SECRET: &str = "integration-test-jwt-secret-with-32-bytes";
const MFA_KEY_MATERIAL: &str = "integration-test-mfa-key-material-32bytes";
const TEST_ISSUER: &str = "https://haya.test.invalid";
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

#[derive(Debug, Deserialize, Serialize)]
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

fn pid_file_path() -> PathBuf {
  std::env::temp_dir().join(format!("haya-integration-{}.pid", unique_suffix()))
}

fn parse_listen_port(line: &str) -> Option<u16> {
  let (_, addr) = line.split_once("Haya Auth is now listening at ")?;
  addr.rsplit(':').next()?.trim().parse().ok()
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

  let port = 0u16;
  let pid_file = pid_file_path();
  let site_url = "http://127.0.0.1".to_string();
  let mut child = Command::new(env!("CARGO_BIN_EXE_haya"))
    .env("DATABASE_URL", &database_url)
    .env("JWT_SECRET", JWT_SECRET)
    .env("MFA_ENCRYPTION_KEY", MFA_KEY_MATERIAL)
    .env("JWT_ISSUER", TEST_ISSUER)
    .env("PORT", port.to_string())
    .env("SITE_URL", &site_url)
    .env("HAYA_PID_FILE", &pid_file)
    .env("HAYA_DEV_MODE", "true")
    .env("PASSKEY_ENABLED", "true")
    .env("PASSKEY_RP_ID", "localhost")
    .env("PASSKEY_RP_NAME", "Haya Integration")
    .env("PASSKEY_RP_ORIGINS", "http://localhost")
    .stdout(Stdio::piped())
    .stderr(Stdio::null())
    .spawn()
    .expect("spawn haya server");

  let stdout = child.stdout.take().expect("capture haya stdout");
  let mut stdout = BufReader::new(stdout);
  let mut line = String::new();
  let mut bound_port = None;
  while stdout.read_line(&mut line).expect("read haya stdout") > 0 {
    if let Some(parsed_port) = parse_listen_port(&line) {
      bound_port = Some(parsed_port);
      break;
    }
    line.clear();
  }
  let port = bound_port.expect("parse bound haya port");
  let base_url = format!("http://127.0.0.1:{port}");

  let client = reqwest::Client::new();
  wait_for_health(&client, &base_url).await;

  Some(TestContext {
    pool: PgPool::connect(&database_url).await.expect("connect test db"),
    client,
    base_url: base_url.clone(),
    issuer: TEST_ISSUER.to_string(),
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
  aal: &str,
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
    aal: aal.to_string(),
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

fn valid_es256_cose_key() -> Vec<u8> {
  let x = [
    0x6b, 0x17, 0xd1, 0xf2, 0xe1, 0x2c, 0x42, 0x47, 0xf8, 0xbc, 0xe6, 0xe5, 0x63, 0xa4, 0x40, 0xf2, 0x77,
    0x03, 0x7d, 0x81, 0x2d, 0xeb, 0x33, 0xa0, 0xf4, 0xa1, 0x39, 0x45, 0xd8, 0x98, 0xc2, 0x96,
  ];
  let y = [
    0x4f, 0xe3, 0x42, 0xe2, 0xfe, 0x1a, 0x7f, 0x9b, 0x8e, 0xe7, 0xeb, 0x4a, 0x7c, 0x0f, 0x9e, 0x16, 0x2b,
    0xce, 0x33, 0x57, 0x6b, 0x31, 0x5e, 0xce, 0xcb, 0xb6, 0x40, 0x68, 0x37, 0xbf, 0x51, 0xf5,
  ];
  let mut key = vec![0xa5, 0x01, 0x02, 0x03, 0x26, 0x20, 0x01, 0x21, 0x58, 0x20];
  key.extend_from_slice(&x);
  key.extend_from_slice(&[0x22, 0x58, 0x20]);
  key.extend_from_slice(&y);
  key
}

async fn insert_web_authn_factor(pool: &PgPool, user_id: Uuid, credential_id: &[u8]) -> Uuid {
  let factor_id = Uuid::new_v4();
  let now = Utc::now();
  let credential = serde_json::json!({
    "credential_id": credential_id,
    "user_handle": user_id.as_bytes(),
    "public_key_cose": valid_es256_cose_key(),
    "algorithm": -7,
    "sign_count": 0,
    "aaguid": vec![0; 16],
    "transports": [],
    "backup_eligible": false,
    "backup_state": false,
  });
  sqlx::query(
    "INSERT INTO auth.mfa_factors (id, user_id, friendly_name, factor_type, status, web_authn_credential_id, web_authn_credential, web_authn_aaguid, created_at, updated_at) VALUES ($1, $2, 'Existing passkey', 'webauthn'::auth.factor_type, 'verified'::auth.factor_status, $3, $4, $5, $6, $6)",
  )
  .bind(factor_id)
  .bind(user_id)
  .bind(credential_id)
  .bind(credential)
  .bind(Uuid::nil())
  .bind(now)
  .execute(pool)
  .await
  .expect("insert WebAuthn factor");
  factor_id
}

async fn create_software_passkey(options: CredentialCreationOptions) -> CreatedPublicKeyCredential {
  let authenticator = Authenticator::new(
    Aaguid::new_empty(),
    None::<Passkey>,
    MockUserValidationMethod::verified_user(2),
    AvailableBackend,
  );
  let mut client = Client::new(authenticator);
  client
    .register(
      &url::Url::parse("http://localhost").expect("registration origin"),
      options,
      DefaultClientData,
    )
    .await
    .expect("create software passkey")
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
async fn passkey_registration_options_enforce_auth_reauthentication_and_rp_policy() {
  let Some(ctx) = test_context().await else {
    return;
  };

  let unauthenticated = ctx
    .client
    .post(format!("{}/passkeys/register/options", ctx.base_url))
    .json(&serde_json::json!({ "friendlyName": "Laptop" }))
    .send()
    .await
    .expect("call unauthenticated passkey options");
  assert_eq!(unauthenticated.status(), StatusCode::UNAUTHORIZED);

  let email = format!("passkey-options-{}@example.com", unique_suffix());
  let user_id = insert_user(&ctx.pool, &email).await;
  let session_id = create_session(&ctx.pool, user_id).await;
  let credential_id = vec![0xfb, 0xff, 0x01, 0x02];
  insert_web_authn_factor(&ctx.pool, user_id, &credential_id).await;

  let aal1_token = issue_access_token(&ctx.issuer, &ctx.jwt_secret, user_id, session_id, &email, "aal1");
  let needs_reauthentication = ctx
    .client
    .post(format!("{}/passkeys/register/options", ctx.base_url))
    .bearer_auth(&aal1_token)
    .json(&serde_json::json!({ "friendlyName": "Laptop" }))
    .send()
    .await
    .expect("call passkey options without AAL2");
  assert_eq!(needs_reauthentication.status(), StatusCode::UNAUTHORIZED);

  let aal2_token = issue_access_token(&ctx.issuer, &ctx.jwt_secret, user_id, session_id, &email, "aal2");
  let response = ctx
    .client
    .post(format!("{}/passkeys/register/options", ctx.base_url))
    .bearer_auth(&aal2_token)
    .json(&serde_json::json!({ "friendlyName": "Laptop" }))
    .send()
    .await
    .expect("call passkey options with AAL2");
  assert_eq!(response.status(), StatusCode::OK);
  let body: serde_json::Value = response.json().await.expect("decode passkey options");
  let public_key = &body["options"]["publicKey"];
  assert_eq!(public_key["rp"]["id"], "localhost");
  assert_eq!(public_key["rp"]["name"], "Haya Integration");
  assert_eq!(public_key["pubKeyCredParams"].as_array().unwrap().len(), 1);
  assert_eq!(public_key["pubKeyCredParams"][0]["alg"], -7);
  assert_eq!(public_key["authenticatorSelection"]["residentKey"], "required");
  assert_eq!(public_key["authenticatorSelection"]["requireResidentKey"], true);
  assert_eq!(
    public_key["authenticatorSelection"]["userVerification"],
    "required"
  );
  assert_eq!(public_key["attestation"], "none");
  assert_eq!(
    public_key["excludeCredentials"][0]["id"],
    URL_SAFE_NO_PAD.encode(&credential_id)
  );

  let flow_id = Uuid::parse_str(body["flowId"].as_str().unwrap()).unwrap();
  let flow_owner: Option<Uuid> = sqlx::query_scalar("SELECT user_id FROM auth.web_authn_flows WHERE id = $1")
    .bind(flow_id)
    .fetch_one(&ctx.pool)
    .await
    .expect("fetch persisted registration flow");
  assert_eq!(flow_owner, Some(user_id));

  let options: CredentialCreationOptions =
    serde_json::from_value(body["options"].clone()).expect("decode creation options");
  let credential = serde_json::to_value(create_software_passkey(options).await).expect("encode credential");
  let verify_body = serde_json::json!({
    "flowId": flow_id,
    "credential": credential,
  });
  let verified = ctx
    .client
    .post(format!("{}/passkeys/register/verify", ctx.base_url))
    .bearer_auth(&aal2_token)
    .json(&verify_body)
    .send()
    .await
    .expect("verify software passkey");
  assert_eq!(verified.status(), StatusCode::OK);
  let factor: serde_json::Value = verified.json().await.expect("decode passkey factor");
  assert_eq!(factor["friendlyName"], "Laptop");
  assert_eq!(factor["status"], "verified");
  for forbidden in [
    "credentialId",
    "publicKey",
    "clientData",
    "signature",
    "challenge",
  ] {
    assert!(factor.get(forbidden).is_none());
  }

  let stored_credentials: Vec<serde_json::Value> = sqlx::query_scalar(
    "SELECT web_authn_credential FROM auth.mfa_factors WHERE user_id = $1 AND factor_type = 'webauthn'::auth.factor_type ORDER BY created_at",
  )
  .bind(user_id)
  .fetch_all(&ctx.pool)
  .await
  .expect("fetch stored passkeys");
  assert_eq!(stored_credentials.len(), 2);
  let stored = stored_credentials.last().unwrap();
  assert!(stored.get("public_key_cose").is_some());
  assert!(stored.get("private_key").is_none());
  assert!(stored.get("d").is_none());

  let replay = ctx
    .client
    .post(format!("{}/passkeys/register/verify", ctx.base_url))
    .bearer_auth(&aal2_token)
    .json(&verify_body)
    .send()
    .await
    .expect("replay passkey registration");
  assert_eq!(replay.status(), StatusCode::BAD_REQUEST);
  let factor_count: i64 = sqlx::query_scalar(
    "SELECT COUNT(*) FROM auth.mfa_factors WHERE user_id = $1 AND factor_type = 'webauthn'::auth.factor_type",
  )
  .bind(user_id)
  .fetch_one(&ctx.pool)
  .await
  .expect("count passkeys after replay");
  assert_eq!(factor_count, 2);

  sqlx::query("UPDATE auth.sessions SET not_after = $1 WHERE id = $2")
    .bind(Utc::now() - chrono::Duration::seconds(1))
    .bind(session_id)
    .execute(&ctx.pool)
    .await
    .expect("expire session");
  let stale = ctx
    .client
    .post(format!("{}/passkeys/register/options", ctx.base_url))
    .bearer_auth(&aal2_token)
    .json(&serde_json::json!({ "friendlyName": "Other" }))
    .send()
    .await
    .expect("call passkey options with stale session");
  assert_eq!(stale.status(), StatusCode::UNAUTHORIZED);

  cleanup_user(&ctx.pool, user_id).await;
}

#[tokio::test]
async fn discoverable_passkey_authentication_issues_atomic_aal2_session() {
  let Some(ctx) = test_context().await else {
    return;
  };

  let email = format!("passkey-login-{}@example.com", unique_suffix());
  let user_id = insert_user(&ctx.pool, &email).await;
  let enrollment_session_id = create_session(&ctx.pool, user_id).await;
  let enrollment_token = issue_access_token(
    &ctx.issuer,
    &ctx.jwt_secret,
    user_id,
    enrollment_session_id,
    &email,
    "aal2",
  );
  let registration_options = ctx
    .client
    .post(format!("{}/passkeys/register/options", ctx.base_url))
    .bearer_auth(&enrollment_token)
    .json(&serde_json::json!({ "friendlyName": "Login passkey" }))
    .send()
    .await
    .expect("request passkey registration options");
  assert_eq!(registration_options.status(), StatusCode::OK);
  let registration_body: serde_json::Value = registration_options.json().await.unwrap();
  let registration_flow_id = registration_body["flowId"].as_str().unwrap();
  let creation_options: CredentialCreationOptions =
    serde_json::from_value(registration_body["options"].clone()).unwrap();
  let authenticator = Authenticator::new(
    Aaguid::new_empty(),
    None::<Passkey>,
    MockUserValidationMethod::verified_user(10),
    AvailableBackend,
  );
  let mut software_client = Client::new(authenticator);
  let registered = software_client
    .register(
      &url::Url::parse("http://localhost").unwrap(),
      creation_options,
      DefaultClientData,
    )
    .await
    .expect("register software passkey");
  let registration = ctx
    .client
    .post(format!("{}/passkeys/register/verify", ctx.base_url))
    .bearer_auth(&enrollment_token)
    .json(&serde_json::json!({
      "flowId": registration_flow_id,
      "credential": registered,
    }))
    .send()
    .await
    .expect("complete passkey registration");
  assert_eq!(registration.status(), StatusCode::OK);
  let factor: serde_json::Value = registration.json().await.unwrap();
  let factor_id = Uuid::parse_str(factor["id"].as_str().unwrap()).unwrap();

  let options_response = ctx
    .client
    .post(format!("{}/passkeys/authenticate/options", ctx.base_url))
    .header(reqwest::header::USER_AGENT, "haya-passkey-test/1")
    .json(&serde_json::json!({}))
    .send()
    .await
    .expect("request discoverable authentication options");
  assert_eq!(options_response.status(), StatusCode::OK);
  let options_body: serde_json::Value = options_response.json().await.unwrap();
  let flow_id = options_body["flowId"].as_str().unwrap();
  let request_options: CredentialRequestOptions =
    serde_json::from_value(options_body["options"].clone()).unwrap();
  assert!(request_options.public_key.allow_credentials.is_none());
  let assertion = software_client
    .authenticate(
      &url::Url::parse("http://localhost").unwrap(),
      request_options,
      DefaultClientData,
    )
    .await
    .expect("create discoverable assertion");
  let assertion_json = serde_json::to_value(assertion).unwrap();
  let grant_body = serde_json::json!({
    "flowId": flow_id,
    "credential": assertion_json,
  });
  let token_response = ctx
    .client
    .post(format!("{}/token?grant_type=passkey", ctx.base_url))
    .header(reqwest::header::USER_AGENT, "haya-passkey-test/1")
    .json(&grant_body)
    .send()
    .await
    .expect("exchange passkey assertion");
  assert_eq!(token_response.status(), StatusCode::OK);
  let token_body: serde_json::Value = token_response.json().await.unwrap();
  let access_token = token_body["access_token"].as_str().unwrap();
  let refresh_token = token_body["refresh_token"].as_str().unwrap();
  let mut validation = Validation::new(Algorithm::HS256);
  validation.set_audience(&["authenticated"]);
  validation.set_issuer(&[ctx.issuer.as_str()]);
  let claims = decode::<TestClaims>(
    access_token,
    &DecodingKey::from_secret(ctx.jwt_secret.as_bytes()),
    &validation,
  )
  .expect("decode passkey JWT")
  .claims;
  assert_eq!(claims.sub, user_id.to_string());
  assert_eq!(claims.aal, "aal2");
  assert_eq!(claims.amr.len(), 1);
  assert_eq!(claims.amr[0]["method"], "webauthn");

  let session_id = Uuid::parse_str(&claims.session_id).unwrap();
  let session: (Option<Uuid>, String, Option<String>, Option<String>) =
    sqlx::query_as("SELECT factor_id, aal::text, user_agent, host(ip) FROM auth.sessions WHERE id = $1")
      .bind(session_id)
      .fetch_one(&ctx.pool)
      .await
      .expect("fetch passkey session");
  assert_eq!(session.0, Some(factor_id));
  assert_eq!(session.1, "aal2");
  assert_eq!(session.2.as_deref(), Some("haya-passkey-test/1"));
  assert_eq!(session.3.as_deref(), Some("127.0.0.1"));
  let amr: Vec<String> = sqlx::query_scalar(
    "SELECT authentication_method FROM auth.mfa_amr_claims WHERE session_id = $1 ORDER BY authentication_method",
  )
  .bind(session_id)
  .fetch_all(&ctx.pool)
  .await
  .expect("fetch passkey AMR");
  assert_eq!(amr, vec!["webauthn"]);

  let replay = ctx
    .client
    .post(format!("{}/token?grant_type=passkey", ctx.base_url))
    .header(reqwest::header::USER_AGENT, "haya-passkey-test/1")
    .json(&grant_body)
    .send()
    .await
    .expect("replay assertion");
  assert_eq!(replay.status(), StatusCode::BAD_REQUEST);
  let session_count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM auth.sessions WHERE factor_id = $1")
    .bind(factor_id)
    .fetch_one(&ctx.pool)
    .await
    .unwrap();
  assert_eq!(session_count, 1);

  let refreshed = ctx
    .client
    .post(format!("{}/token?grant_type=refresh_token", ctx.base_url))
    .header(reqwest::header::USER_AGENT, "haya-passkey-test/1")
    .json(&serde_json::json!({ "refresh_token": refresh_token }))
    .send()
    .await
    .expect("refresh passkey session");
  assert_eq!(refreshed.status(), StatusCode::OK);

  cleanup_user(&ctx.pool, user_id).await;
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
  let token = issue_access_token(&ctx.issuer, &ctx.jwt_secret, user_id, session_id, &email, "aal1");
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
  let token = issue_access_token(&ctx.issuer, &ctx.jwt_secret, user_id, session_id, &email, "aal1");
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
