use std::collections::HashMap;
use std::sync::Arc;

use sqlx::PgPool;
use tokio::sync::RwLock;
use uuid::Uuid;

use crate::auth::oidc::OidcProviderConfig;
use crate::mailer::Mailer;

#[derive(Debug, Clone)]
pub struct AppState {
  pub db: PgPool,
  pub http_client: reqwest::Client,
  pub jwt_secret: String,
  pub mfa_encryption_key: [u8; 32],
  pub jwt_exp: i64,
  pub refresh_token_exp: i64,
  pub session_idle_timeout_secs: i64,
  /// Base URL of the site (used for generating email links in recovery/confirmation)
  pub site_url: String,
  pub allowed_redirect_origins: Vec<String>,
  /// Display name shown in email templates (env: `SITE_NAME`)
  pub site_name: String,
  pub issuer: String,
  pub instance_id: Uuid,
  pub oidc_providers: Arc<RwLock<HashMap<String, OidcProviderConfig>>>,
  /// When true, users can sign in without confirming their email
  pub mailer_autoconfirm: bool,
  /// SMTP mailer; `None` when `SMTP_HOST` is not configured
  pub mailer: Option<Arc<Mailer>>,
}

#[derive(Debug, Clone)]
pub struct RuntimeConfig {
  pub port: u16,
  pub database_url: String,
  pub site_url: String,
  pub redirect_allowed_origins: Vec<String>,
  pub allowed_redirect_origins: Vec<String>,
  pub cors_allowed_origins: Vec<String>,
  pub site_name: String,
  pub issuer: String,
  pub jwt_exp: i64,
  pub refresh_token_exp: i64,
  pub session_idle_timeout_secs: i64,
  pub pid_file: String,
  pub jwt_secret_len: usize,
  pub mailer_autoconfirm: bool,
  pub smtp_configured: bool,
  pub dev_mode: bool,
  pub mfa_key_source: &'static str,
}
