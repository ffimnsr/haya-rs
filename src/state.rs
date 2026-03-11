use sqlx::PgPool;
use uuid::Uuid;

#[derive(Debug, Clone)]
pub struct AppState {
    pub db: PgPool,
    pub jwt_secret: String,
    pub jwt_exp: i64,
    pub refresh_token_exp: i64,
    pub site_url: String,
    pub issuer: String,
    pub instance_id: Uuid,
}
