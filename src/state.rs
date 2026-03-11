use sqlx::PgPool;
use uuid::Uuid;

#[derive(Debug, Clone)]
pub struct AppState {
    pub db: PgPool,
    pub jwt_secret: String,
    pub jwt_exp: i64,
    /// Lifetime of refresh tokens in seconds (used for token expiry checks)
    #[allow(dead_code)]
    pub refresh_token_exp: i64,
    /// Base URL of the site (used for generating email links in recovery/confirmation)
    #[allow(dead_code)]
    pub site_url: String,
    pub issuer: String,
    pub instance_id: Uuid,
    /// When true, users can sign in without confirming their email
    pub mailer_autoconfirm: bool,
}
