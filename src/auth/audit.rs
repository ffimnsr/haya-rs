use std::net::IpAddr;

use serde_json::{
  Value,
  json,
};
use sqlx::PgPool;
use uuid::Uuid;

use crate::error::Result;

pub async fn log_event(
  db: &PgPool,
  instance_id: Uuid,
  ip_address: Option<IpAddr>,
  event: &str,
  payload: Value,
) -> Result<()> {
  insert_entry(db, instance_id, ip_address, event, payload).await
}

pub async fn log_event_tx(
  conn: &mut sqlx::PgConnection,
  instance_id: Uuid,
  ip_address: Option<IpAddr>,
  event: &str,
  payload: Value,
) -> Result<()> {
  insert_entry(conn, instance_id, ip_address, event, payload).await
}

async fn insert_entry<'e, E>(
  executor: E,
  instance_id: Uuid,
  ip_address: Option<IpAddr>,
  event: &str,
  payload: Value,
) -> Result<()>
where
  E: sqlx::Executor<'e, Database = sqlx::Postgres>,
{
  let payload = match payload {
    Value::Object(mut map) => {
      map.insert("event".to_string(), json!(event));
      Value::Object(map)
    },
    value => json!({
      "event": event,
      "details": value,
    }),
  };

  sqlx::query(
    "INSERT INTO auth.audit_log_entries (instance_id, id, payload, ip_address, created_at)
     VALUES ($1, $2, $3, $4, NOW())",
  )
  .bind(instance_id)
  .bind(Uuid::new_v4())
  .bind(payload)
  .bind(ip_address.map(|addr| addr.to_string()).unwrap_or_default())
  .execute(executor)
  .await?;

  Ok(())
}
