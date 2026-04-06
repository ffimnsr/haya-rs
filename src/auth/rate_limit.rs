use sqlx::PgPool;

use crate::error::Result;

pub async fn is_limited(db: &PgPool, key: &str, max_attempts: u32) -> Result<bool> {
  let row = sqlx::query_as::<_, (i32,)>(
    "SELECT attempts FROM auth.rate_limits WHERE key = $1 AND expires_at > NOW()",
  )
  .bind(key)
  .fetch_optional(db)
  .await?;

  Ok(row.is_some_and(|(attempts,)| attempts >= max_attempts as i32))
}

pub async fn record_attempt(db: &PgPool, key: &str, window_secs: i64) -> Result<()> {
  upsert_attempt_window(db, key, window_secs).await
}

pub async fn record_failure(db: &PgPool, key: &str, window_secs: i64) -> Result<()> {
  upsert_attempt_window(db, key, window_secs).await
}

async fn upsert_attempt_window(db: &PgPool, key: &str, window_secs: i64) -> Result<()> {
  sqlx::query(
    "INSERT INTO auth.rate_limits (key, attempts, expires_at, created_at, updated_at)
     VALUES ($1, 1, NOW() + make_interval(secs => $2), NOW(), NOW())
     ON CONFLICT (key) DO UPDATE SET
       attempts = CASE
         WHEN auth.rate_limits.expires_at <= NOW() THEN 1
         ELSE auth.rate_limits.attempts + 1
       END,
       expires_at = CASE
         WHEN auth.rate_limits.expires_at <= NOW() THEN NOW() + make_interval(secs => $2)
         ELSE auth.rate_limits.expires_at
       END,
       updated_at = NOW()",
  )
  .bind(key)
  .bind(window_secs)
  .execute(db)
  .await?;

  Ok(())
}

pub async fn clear(db: &PgPool, key: &str) -> Result<()> {
  sqlx::query("DELETE FROM auth.rate_limits WHERE key = $1")
    .bind(key)
    .execute(db)
    .await?;
  Ok(())
}

pub async fn delete_expired(db: &PgPool) -> Result<u64> {
  let result = sqlx::query("DELETE FROM auth.rate_limits WHERE expires_at <= NOW()")
    .execute(db)
    .await?;
  Ok(result.rows_affected())
}
