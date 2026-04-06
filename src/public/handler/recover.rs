use axum::Json;
use axum::extract::{
  ConnectInfo,
  State,
};
use chrono::{
  Duration,
  Utc,
};
use serde::Deserialize;
use std::net::{
  IpAddr,
  SocketAddr,
};

use crate::auth::{
  rate_limit,
  session,
};
use crate::error::{
  AuthError,
  Result,
};
use crate::mailer::EmailKind;
use crate::public::handler::signup::is_valid_email;
use crate::state::AppState;
use crate::utils::sha256_hex;

pub(crate) const EMAIL_TOKEN_COOLDOWN_SECONDS: i64 = 300;
const RECOVER_RATE_LIMIT_WINDOW_SECS: i64 = 900;
const RECOVER_RATE_LIMIT_ATTEMPTS: u32 = 5;

type RecoveryLookup = (
  uuid::Uuid,
  Option<chrono::DateTime<Utc>>,
  Option<chrono::DateTime<Utc>>,
);

#[derive(Debug, Deserialize)]
pub struct RecoverRequest {
  pub email: String,
}

pub async fn recover(
  State(state): State<AppState>,
  ConnectInfo(client_addr): ConnectInfo<SocketAddr>,
  Json(req): Json<RecoverRequest>,
) -> Result<Json<serde_json::Value>> {
  let rate_limit_key = recover_ip_rate_limit_key(client_addr.ip());
  if rate_limit::is_limited(&state.db, &rate_limit_key, RECOVER_RATE_LIMIT_ATTEMPTS).await? {
    return Err(AuthError::TooManyRequests);
  }
  rate_limit::record_attempt(&state.db, &rate_limit_key, RECOVER_RATE_LIMIT_WINDOW_SECS).await?;

  if !is_valid_email(&req.email) {
    // Return 200 to avoid leaking which emails are valid
    return Ok(Json(serde_json::json!({})));
  }

  let user_exists: Option<RecoveryLookup> = sqlx::query_as::<_, RecoveryLookup>(
    "SELECT id, recovery_sent_at, email_confirmed_at FROM auth.users WHERE email = $1",
  )
  .bind(&req.email)
  .fetch_optional(&state.db)
  .await?;

  let Some((user_id, recovery_sent_at, email_confirmed_at)) = user_exists else {
    // Return 200 regardless to prevent email enumeration
    return Ok(Json(serde_json::json!({})));
  };
  if email_confirmed_at.is_none() {
    return Ok(Json(serde_json::json!({})));
  }
  let now = Utc::now();
  if email_token_cooldown_active(recovery_sent_at, now) {
    tracing::info!("Recovery token regeneration suppressed by cooldown");
    return Ok(Json(serde_json::json!({})));
  }

  let recovery_token = session::generate_refresh_token();
  let recovery_token_hash = sha256_hex(&recovery_token);

  sqlx::query(
    "UPDATE auth.users SET recovery_token = $1, recovery_sent_at = $2, updated_at = $3 WHERE id = $4",
  )
  .bind(&recovery_token_hash)
  .bind(now)
  .bind(now)
  .bind(user_id)
  .execute(&state.db)
  .await?;

  let recovery_url = format!("{}/verify?token={}&type=recovery", state.site_url, recovery_token);
  if let Some(ref mailer) = state.mailer {
    if let Err(e) = mailer
      .send(
        EmailKind::Recovery,
        &req.email,
        &[
          ("site_name", state.site_name.as_str()),
          ("recovery_url", recovery_url.as_str()),
          ("email", req.email.as_str()),
        ],
      )
      .await
    {
      tracing::error!(error = %e, "Failed to send recovery email");
    }
  } else {
    tracing::warn!("SMTP not configured; recovery email not sent");
  }
  tracing::info!("Password recovery email requested");

  Ok(Json(serde_json::json!({})))
}

pub(crate) fn email_token_cooldown_active(
  sent_at: Option<chrono::DateTime<Utc>>,
  now: chrono::DateTime<Utc>,
) -> bool {
  sent_at.is_some_and(|sent_at| sent_at > now - Duration::seconds(EMAIL_TOKEN_COOLDOWN_SECONDS))
}

fn recover_ip_rate_limit_key(client_ip: IpAddr) -> String {
  format!("recover-ip:{client_ip}")
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn cooldown_is_active_within_window() {
    let now = Utc::now();
    assert!(email_token_cooldown_active(
      Some(now - Duration::seconds(EMAIL_TOKEN_COOLDOWN_SECONDS - 1)),
      now
    ));
  }

  #[test]
  fn cooldown_is_inactive_after_window() {
    let now = Utc::now();
    assert!(!email_token_cooldown_active(
      Some(now - Duration::seconds(EMAIL_TOKEN_COOLDOWN_SECONDS + 1)),
      now
    ));
  }
}
