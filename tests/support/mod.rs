#![allow(dead_code, reason = "shared integration-test helpers vary by test binary")]

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

use chrono::Utc;
use jsonwebtoken::{
  Algorithm,
  EncodingKey,
  Header,
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
  AuthenticatedPublicKeyCredential,
  CreatedPublicKeyCredential,
  CredentialCreationOptions,
  CredentialRequestOptions,
};
use serde::Serialize;
use sqlx::PgPool;
use url::Url;
use uuid::Uuid;

pub const JWT_SECRET: &str = "phase5-integration-test-jwt-secret";
const MFA_KEY_MATERIAL: &str = "phase5-integration-test-mfa-key-material";
pub const TEST_ISSUER: &str = "https://phase5.haya.test.invalid";
pub const PASSKEY_TEST_ORIGIN: &str = "http://localhost";

type TestPasskeyClient =
  Client<Option<Passkey>, MockUserValidationMethod, AvailableBackend, public_suffix::PublicSuffixList, ()>;

pub struct SoftwarePasskeyPeer {
  client: TestPasskeyClient,
  origin: Url,
}

impl SoftwarePasskeyPeer {
  pub fn new() -> Self {
    let mut authenticator = Authenticator::new(
      Aaguid::new_empty(),
      None::<Passkey>,
      MockUserValidationMethod::verified_user(100),
      AvailableBackend,
    );
    authenticator.set_make_credentials_with_signature_counter(true);
    Self {
      client: Client::new(authenticator),
      origin: Url::parse(PASSKEY_TEST_ORIGIN).expect("valid passkey test origin"),
    }
  }

  pub async fn register(&mut self, options: CredentialCreationOptions) -> CreatedPublicKeyCredential {
    self
      .client
      .register(&self.origin, options, DefaultClientData)
      .await
      .expect("software passkey registration")
  }

  pub async fn authenticate(
    &mut self,
    options: CredentialRequestOptions,
  ) -> AuthenticatedPublicKeyCredential {
    self
      .client
      .authenticate(&self.origin, options, DefaultClientData)
      .await
      .expect("software passkey authentication")
  }
}

pub struct TestContext {
  pub pool: PgPool,
  pub client: reqwest::Client,
  pub base_url: String,
  pub issuer: String,
  pub jwt_secret: String,
  child: Child,
  stderr_path: PathBuf,
  database_cleanup: DatabaseCleanup,
}

struct DatabaseCleanup {
  admin_url: String,
  database_name: String,
  active: bool,
}

struct ProcessGuard {
  child: Option<Child>,
}

impl ProcessGuard {
  fn new(child: Child) -> Self {
    Self { child: Some(child) }
  }

  fn child_mut(&mut self) -> &mut Child {
    self.child.as_mut().expect("guard owns Haya child")
  }

  fn into_child(mut self) -> Child {
    self.child.take().expect("guard owns Haya child")
  }
}

impl Drop for ProcessGuard {
  fn drop(&mut self) {
    if let Some(child) = self.child.as_mut() {
      let _ = child.kill();
      let _ = child.wait();
    }
  }
}

impl TestContext {
  pub async fn finish(mut self) -> String {
    let _ = self.child.kill();
    let _ = self.child.wait();
    let logs = std::fs::read_to_string(&self.stderr_path).expect("read Haya stderr");
    self.pool.close().await;
    self
      .database_cleanup
      .cleanup()
      .await
      .expect("drop isolated test database");
    logs
  }
}

impl Drop for TestContext {
  fn drop(&mut self) {
    let _ = self.child.kill();
    let _ = self.child.wait();
    let _ = std::fs::remove_file(&self.stderr_path);
  }
}

impl DatabaseCleanup {
  async fn cleanup(&mut self) -> Result<(), sqlx::Error> {
    if !self.active {
      return Ok(());
    }
    let admin = PgPool::connect(&self.admin_url).await?;
    let statement = format!("DROP DATABASE IF EXISTS \"{}\" WITH (FORCE)", self.database_name);
    sqlx::query(&statement).execute(&admin).await?;
    admin.close().await;
    self.active = false;
    Ok(())
  }
}

impl Drop for DatabaseCleanup {
  fn drop(&mut self) {
    if !self.active {
      return;
    }
    let admin_url = self.admin_url.clone();
    let database_name = self.database_name.clone();
    let thread = std::thread::spawn(move || {
      let Ok(runtime) = tokio::runtime::Builder::new_current_thread().enable_all().build() else {
        return;
      };
      runtime.block_on(async move {
        let Ok(admin) = PgPool::connect(&admin_url).await else {
          return;
        };
        let statement = format!("DROP DATABASE IF EXISTS \"{database_name}\" WITH (FORCE)");
        let _ = sqlx::query(&statement).execute(&admin).await;
        admin.close().await;
      });
    });
    let _ = thread.join();
  }
}

#[derive(Serialize)]
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

pub fn unique_suffix() -> String {
  Uuid::new_v4().simple().to_string()
}

fn pid_file_path() -> PathBuf {
  std::env::temp_dir().join(format!("haya-phase5-{}.pid", unique_suffix()))
}

fn parse_listen_port(line: &str) -> Option<u16> {
  let (_, addr) = line.split_once("Haya Auth is now listening at ")?;
  addr.rsplit(':').next()?.trim().parse().ok()
}

async fn create_isolated_database(database_url: &str) -> (String, DatabaseCleanup) {
  let mut admin_url = Url::parse(database_url).expect("DATABASE_URL must be a PostgreSQL URL");
  admin_url.set_path("/postgres");
  let database_name = format!("haya_test_{}", unique_suffix());
  let admin = PgPool::connect(admin_url.as_str())
    .await
    .expect("connect PostgreSQL administration database");
  let statement = format!("CREATE DATABASE \"{database_name}\"");
  sqlx::query(&statement)
    .execute(&admin)
    .await
    .expect("create isolated test database");
  admin.close().await;

  let mut isolated_url = Url::parse(database_url).expect("DATABASE_URL must be a PostgreSQL URL");
  isolated_url.set_path(&format!("/{database_name}"));
  (
    isolated_url.to_string(),
    DatabaseCleanup {
      admin_url: admin_url.to_string(),
      database_name,
      active: true,
    },
  )
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

pub async fn test_context() -> Option<TestContext> {
  test_context_with_options(None, true).await
}

pub async fn test_context_with_oidc_provider(provider_name: Option<&str>) -> Option<TestContext> {
  test_context_with_options(provider_name, true).await
}

pub async fn test_context_without_passkeys() -> Option<TestContext> {
  test_context_with_options(None, false).await
}

async fn test_context_with_options(
  provider_name: Option<&str>,
  passkey_enabled: bool,
) -> Option<TestContext> {
  let source_database_url = std::env::var("DATABASE_URL").ok()?;
  let (database_url, database_cleanup) = create_isolated_database(&source_database_url).await;
  migrate_database(&database_url).await;
  let pool = PgPool::connect(&database_url)
    .await
    .expect("connect test database");
  if let Some(provider_name) = provider_name {
    let now = Utc::now();
    sqlx::query(
      "INSERT INTO auth.oidc_providers (id, name, issuer, client_id, client_secret, redirect_uri, created_at, updated_at) VALUES ($1, $2, $3, 'phase6-client', 'phase6-secret', $4, $5, $5)",
    )
    .bind(Uuid::new_v4())
    .bind(provider_name)
    .bind(format!("https://{provider_name}.test.invalid"))
    .bind(format!("https://haya.test.invalid/callback/{provider_name}"))
    .bind(now)
    .execute(&pool)
    .await
    .expect("insert Phase 6 OIDC provider");
  }
  let pid_file = pid_file_path();
  let stderr_path = std::env::temp_dir().join(format!("haya-phase7-{}.log", unique_suffix()));
  let stderr = std::fs::File::create(&stderr_path).expect("create Haya stderr capture");
  let child = Command::new(env!("CARGO_BIN_EXE_haya"))
    .env("DATABASE_URL", &database_url)
    .env("JWT_SECRET", JWT_SECRET)
    .env("MFA_ENCRYPTION_KEY", MFA_KEY_MATERIAL)
    .env("JWT_ISSUER", TEST_ISSUER)
    .env("PORT", "0")
    .env("SITE_URL", "http://127.0.0.1")
    .env("HAYA_PID_FILE", &pid_file)
    .env("HAYA_DEV_MODE", "true")
    .env("PASSKEY_ENABLED", passkey_enabled.to_string())
    .env("PASSKEY_RP_ID", "localhost")
    .env("PASSKEY_RP_NAME", "Haya Phase 5")
    .env("PASSKEY_RP_ORIGINS", PASSKEY_TEST_ORIGIN)
    .env("RUST_LOG", "haya=trace,tower_http=trace")
    .stdout(Stdio::piped())
    .stderr(Stdio::from(stderr))
    .spawn()
    .expect("spawn Haya server");
  let mut child_guard = ProcessGuard::new(child);

  let mut stdout = BufReader::new(
    child_guard
      .child_mut()
      .stdout
      .take()
      .expect("capture Haya stdout"),
  );
  let mut line = String::new();
  let port = loop {
    assert!(stdout.read_line(&mut line).expect("read Haya stdout") > 0);
    if let Some(port) = parse_listen_port(&line) {
      break port;
    }
    line.clear();
  };
  let base_url = format!("http://127.0.0.1:{port}");
  let client = reqwest::Client::new();
  let deadline = std::time::Instant::now() + Duration::from_secs(10);
  loop {
    if let Ok(response) = client.get(format!("{base_url}/health")).send().await
      && response.status().is_success()
    {
      break;
    }
    assert!(
      std::time::Instant::now() < deadline,
      "server did not become healthy"
    );
    tokio::time::sleep(Duration::from_millis(100)).await;
  }

  Some(TestContext {
    pool,
    client,
    base_url,
    issuer: TEST_ISSUER.to_owned(),
    jwt_secret: JWT_SECRET.to_owned(),
    child: child_guard.into_child(),
    stderr_path,
    database_cleanup,
  })
}

pub async fn insert_user(pool: &PgPool, email: &str) -> Uuid {
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

pub async fn create_session(pool: &PgPool, user_id: Uuid) -> Uuid {
  let session_id = Uuid::new_v4();
  let now = Utc::now();
  sqlx::query(
    "INSERT INTO auth.sessions (id, user_id, aal, created_at, updated_at) VALUES ($1, $2, 'aal2'::auth.aal_level, $3, $3)",
  )
  .bind(session_id)
  .bind(user_id)
  .bind(now)
  .execute(pool)
  .await
  .expect("insert session");
  session_id
}

pub fn issue_access_token(
  issuer: &str,
  jwt_secret: &str,
  user_id: Uuid,
  session_id: Uuid,
  email: &str,
) -> String {
  issue_access_token_with_aal(issuer, jwt_secret, user_id, session_id, email, "aal2")
}

pub fn issue_access_token_with_aal(
  issuer: &str,
  jwt_secret: &str,
  user_id: Uuid,
  session_id: Uuid,
  email: &str,
  aal: &str,
) -> String {
  let now = Utc::now().timestamp();
  encode(
    &Header::new(Algorithm::HS256),
    &TestClaims {
      sub: user_id.to_string(),
      aud: "authenticated".to_owned(),
      exp: now + 300,
      iat: now,
      iss: issuer.to_owned(),
      email: Some(email.to_owned()),
      phone: None,
      role: "authenticated".to_owned(),
      aal: aal.to_owned(),
      amr: vec![serde_json::json!({"method": "totp", "timestamp": now})],
      session_id: session_id.to_string(),
      is_anonymous: false,
      user_metadata: serde_json::json!({}),
      app_metadata: serde_json::json!({}),
    },
    &EncodingKey::from_secret(jwt_secret.as_bytes()),
  )
  .expect("encode test token")
}

pub async fn cleanup_user(pool: &PgPool, user_id: Uuid) {
  let _ = sqlx::query("DELETE FROM auth.users WHERE id = $1")
    .bind(user_id)
    .execute(pool)
    .await;
}
