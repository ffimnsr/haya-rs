use axum::Json;
use axum::extract::State;
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use chrono::{
  Duration,
  Utc,
};
use rand::RngCore;
use serde::Deserialize;

use crate::error::Result;
use crate::mailer::EmailKind;
use crate::public::handler::signup::is_valid_email;
use crate::state::AppState;

pub(crate) const EMAIL_TOKEN_COOLDOWN_SECONDS: i64 = 60;

#[derive(Debug, Deserialize)]
pub struct RecoverRequest {
  pub email: String,
}

pub async fn recover(
  State(state): State<AppState>,
  Json(req): Json<RecoverRequest>,
) -> Result<Json<serde_json::Value>> {
  if !is_valid_email(&req.email) {
    // Return 200 to avoid leaking which emails are valid
    return Ok(Json(serde_json::json!({})));
  }

  let user_exists: Option<(uuid::Uuid, Option<chrono::DateTime<Utc>>)> =
    sqlx::query_as::<_, (uuid::Uuid, Option<chrono::DateTime<Utc>>)>(
      "SELECT id, recovery_sent_at FROM auth.users WHERE email = $1",
    )
    .bind(&req.email)
    .fetch_optional(&state.db)
    .await?;

  if user_exists.is_none() {
    // Return 200 regardless to prevent email enumeration
    return Ok(Json(serde_json::json!({})));
  }

  let (user_id, recovery_sent_at) = user_exists.unwrap();
  let now = Utc::now();
  if email_token_cooldown_active(recovery_sent_at, now) {
    tracing::info!("Recovery token regeneration suppressed by cooldown");
    return Ok(Json(serde_json::json!({})));
  }

  let mut bytes = [0u8; 32];
  rand::rng().fill_bytes(&mut bytes);
  let recovery_token = URL_SAFE_NO_PAD.encode(bytes);

  sqlx::query(
    "UPDATE auth.users SET recovery_token = $1, recovery_sent_at = $2, updated_at = $3 WHERE id = $4",
  )
  .bind(&recovery_token)
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
