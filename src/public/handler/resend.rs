use axum::Json;
use axum::extract::{
  ConnectInfo,
  State,
};
use chrono::Utc;
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
use crate::public::handler::recover::email_token_cooldown_active;
use crate::public::handler::signup::is_valid_email;
use crate::state::AppState;
use crate::utils::sha256_hex;

const RESEND_RATE_LIMIT_WINDOW_SECS: i64 = 900;
const RESEND_RATE_LIMIT_ATTEMPTS: u32 = 5;

#[derive(Debug, Deserialize)]
pub struct ResendRequest {
  #[serde(rename = "type")]
  pub resend_type: String,
  pub email: Option<String>,
  // Reserved for future phone OTP resend support
  #[allow(dead_code)]
  pub phone: Option<String>,
}

#[derive(Debug, sqlx::FromRow)]
struct ResendUserRow {
  id: uuid::Uuid,
  confirmation_sent_at: Option<chrono::DateTime<Utc>>,
  recovery_sent_at: Option<chrono::DateTime<Utc>>,
}

pub async fn resend(
  State(state): State<AppState>,
  ConnectInfo(client_addr): ConnectInfo<SocketAddr>,
  Json(req): Json<ResendRequest>,
) -> Result<Json<serde_json::Value>> {
  let rate_limit_key = resend_ip_rate_limit_key(client_addr.ip());
  if rate_limit::is_limited(&state.db, &rate_limit_key, RESEND_RATE_LIMIT_ATTEMPTS).await? {
    return Err(AuthError::TooManyRequests);
  }
  rate_limit::record_attempt(&state.db, &rate_limit_key, RESEND_RATE_LIMIT_WINDOW_SECS).await?;

  let email = req
    .email
    .as_deref()
    .ok_or_else(|| AuthError::ValidationFailed("email is required".to_string()))?;

  if !is_valid_email(email) {
    return Err(AuthError::ValidationFailed("Invalid email format".to_string()));
  }

  let user_id: Option<ResendUserRow> = sqlx::query_as::<_, ResendUserRow>(
    "SELECT id, confirmation_sent_at, recovery_sent_at FROM auth.users WHERE email = $1",
  )
  .bind(email)
  .fetch_optional(&state.db)
  .await?;

  let Some(ResendUserRow {
    id: user_id,
    confirmation_sent_at,
    recovery_sent_at,
  }) = user_id
  else {
    let _ = sqlx::query("SELECT 1").execute(&state.db).await?;
    return Ok(Json(serde_json::json!({})));
  };
  let token = session::generate_refresh_token();
  let token_hash = sha256_hex(&token);
  let now = Utc::now();

  match req.resend_type.as_str() {
    "signup" => {
      if email_token_cooldown_active(confirmation_sent_at, now) {
        tracing::info!("Signup confirmation regeneration suppressed by cooldown");
        let _ = sqlx::query("SELECT 1").execute(&state.db).await?;
        return Ok(Json(serde_json::json!({})));
      }
      sqlx::query(
                "UPDATE auth.users SET confirmation_token = $1, confirmation_sent_at = $2, updated_at = $3 WHERE id = $4"
            )
            .bind(&token_hash)
            .bind(now)
            .bind(now)
            .bind(user_id)
            .execute(&state.db)
            .await?;
      let confirmation_url = format!("{}/verify?token={}&type=signup", state.site_url, token);
      if let Some(mailer) = state.mailer.clone() {
        let site_name = state.site_name.clone();
        let email = email.to_string();
        tokio::spawn(async move {
          if let Err(e) = mailer
            .send(
              EmailKind::Confirmation,
              &email,
              &[
                ("site_name", site_name.as_str()),
                ("confirmation_url", confirmation_url.as_str()),
                ("email", email.as_str()),
              ],
            )
            .await
          {
            tracing::error!(error = %e, "Failed to resend confirmation email");
          }
        });
      } else {
        tracing::warn!("SMTP not configured; confirmation email not sent");
      }
      tracing::info!("Signup confirmation token regenerated");
    },
    "recovery" => {
      if email_token_cooldown_active(recovery_sent_at, now) {
        tracing::info!("Recovery token regeneration suppressed by cooldown");
        let _ = sqlx::query("SELECT 1").execute(&state.db).await?;
        return Ok(Json(serde_json::json!({})));
      }
      sqlx::query(
        "UPDATE auth.users SET recovery_token = $1, recovery_sent_at = $2, updated_at = $3 WHERE id = $4",
      )
      .bind(&token_hash)
      .bind(now)
      .bind(now)
      .bind(user_id)
      .execute(&state.db)
      .await?;
      let recovery_url = format!("{}/verify?token={}&type=recovery", state.site_url, token);
      if let Some(mailer) = state.mailer.clone() {
        let site_name = state.site_name.clone();
        let email = email.to_string();
        tokio::spawn(async move {
          if let Err(e) = mailer
            .send(
              EmailKind::Recovery,
              &email,
              &[
                ("site_name", site_name.as_str()),
                ("recovery_url", recovery_url.as_str()),
                ("email", email.as_str()),
              ],
            )
            .await
          {
            tracing::error!(error = %e, "Failed to resend recovery email");
          }
        });
      } else {
        tracing::warn!("SMTP not configured; recovery email not sent");
      }
      tracing::info!("Recovery token regenerated");
    },
    _ => {
      return Err(AuthError::ValidationFailed(format!(
        "Unsupported resend type: {}",
        req.resend_type
      )));
    },
  }

  Ok(Json(serde_json::json!({})))
}

fn resend_ip_rate_limit_key(client_ip: IpAddr) -> String {
  format!("resend-ip:{client_ip}")
}
