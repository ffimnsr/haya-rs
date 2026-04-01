use std::sync::Arc;

use sqlx::PgPool;
use uuid::Uuid;

use crate::mailer::Mailer;

#[derive(Debug, Clone)]
pub struct AppState {
    pub db: PgPool,
    pub jwt_secret: String,
    pub jwt_exp: i64,
    /// Lifetime of refresh tokens in seconds (used for token expiry checks)
    #[allow(dead_code)]
    pub refresh_token_exp: i64,
    /// Base URL of the site (used for generating email links in recovery/confirmation)
    pub site_url: String,
    /// Display name shown in email templates (env: `SITE_NAME`)
    pub site_name: String,
    pub issuer: String,
    pub instance_id: Uuid,
    /// When true, users can sign in without confirming their email
    pub mailer_autoconfirm: bool,
    /// SMTP mailer; `None` when `SMTP_HOST` is not configured
    pub mailer: Option<Arc<Mailer>>,
}
