use sqlx::postgres::PgPoolOptions;
use sqlx::{
    Error,
    PgPool,
};
use std::time::Duration;

// Initializes the database pool
pub async fn init_pool(database_url: &str) -> Result<PgPool, Error> {
    PgPoolOptions::new()
        .max_connections(5)
        .acquire_timeout(Duration::from_secs(1))
        .connect(database_url)
        .await
}
