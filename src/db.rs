use sqlx::postgres::PgPoolOptions;
use sqlx::{
  Error,
  PgPool,
};
use std::time::Duration;

const DEFAULT_MAX_CONNECTIONS: u32 = 20;
const DEFAULT_ACQUIRE_TIMEOUT_SECS: u64 = 5;

// Initializes the database pool
pub async fn init_pool(database_url: &str) -> Result<PgPool, Error> {
  let max_connections = std::env::var("DATABASE_MAX_CONNECTIONS")
    .ok()
    .and_then(|value| value.parse::<u32>().ok())
    .filter(|value| *value > 0)
    .unwrap_or(DEFAULT_MAX_CONNECTIONS);
  let acquire_timeout_secs = std::env::var("DATABASE_ACQUIRE_TIMEOUT_SECS")
    .ok()
    .and_then(|value| value.parse::<u64>().ok())
    .filter(|value| *value > 0)
    .unwrap_or(DEFAULT_ACQUIRE_TIMEOUT_SECS);

  PgPoolOptions::new()
    .max_connections(max_connections)
    .acquire_timeout(Duration::from_secs(acquire_timeout_secs))
    .connect(database_url)
    .await
}
