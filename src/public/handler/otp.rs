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
use uuid::Uuid;

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

const OTP_RATE_LIMIT_WINDOW_SECS: i64 = 900;
const OTP_RATE_LIMIT_ATTEMPTS: u32 = 5;

#[derive(Debug, Deserialize)]
pub struct OtpRequest {
  pub email: Option<String>,
  // Reserved for future phone OTP support
  #[allow(dead_code)]
  pub phone: Option<String>,
  pub create_user: Option<bool>,
  #[allow(dead_code)]
  pub data: Option<serde_json::Value>,
}

#[derive(Debug, Deserialize)]
pub struct MagicLinkRequest {
  pub email: String,
}

pub async fn send_otp(
  State(state): State<AppState>,
  ConnectInfo(client_addr): ConnectInfo<SocketAddr>,
  Json(req): Json<OtpRequest>,
) -> Result<Json<serde_json::Value>> {
  let rate_limit_key = otp_ip_rate_limit_key(client_addr.ip());
  if rate_limit::is_limited(&state.db, &rate_limit_key, OTP_RATE_LIMIT_ATTEMPTS).await? {
    return Err(AuthError::TooManyRequests);
  }
  rate_limit::record_attempt(&state.db, &rate_limit_key, OTP_RATE_LIMIT_WINDOW_SECS).await?;

  if let Some(ref email) = req.email {
    if !is_valid_email(email) {
      return Err(AuthError::ValidationFailed("Invalid email format".to_string()));
    }
    let _create_user = req.create_user.unwrap_or(false);

    let existing: Option<(Uuid, Option<chrono::DateTime<Utc>>)> =
      sqlx::query_as::<_, (Uuid, Option<chrono::DateTime<Utc>>)>(
        "SELECT id, magic_link_sent_at FROM auth.users WHERE email = $1",
      )
      .bind(email)
      .fetch_optional(&state.db)
      .await?;

    let (user_id, magic_link_sent_at) = if let Some((id, magic_link_sent_at)) = existing {
      (id, magic_link_sent_at)
    } else {
      // Do not create auth.users rows until the mailbox is proven by a completed verification flow.
      return Ok(Json(serde_json::json!({})));
    };

    let token = session::generate_refresh_token();
    let token_hash = sha256_hex(&token);
    let now = Utc::now();
    if email_token_cooldown_active(magic_link_sent_at, now) {
      tracing::info!("Magic link regeneration suppressed by cooldown");
      return Ok(Json(serde_json::json!({})));
    }

    sqlx::query(
      "UPDATE auth.users SET magic_link_token = $1, magic_link_sent_at = $2, updated_at = $3 WHERE id = $4",
    )
    .bind(&token_hash)
    .bind(now)
    .bind(now)
    .bind(user_id)
    .execute(&state.db)
    .await?;

    // Send magic-link / OTP email.
    let magic_link_url = format!("{}/verify?token={}&type=magiclink", state.site_url, token);
    if let Some(ref mailer) = state.mailer {
      if let Err(e) = mailer
        .send(
          EmailKind::MagicLink,
          email,
          &[
            ("site_name", state.site_name.as_str()),
            ("magic_link_url", magic_link_url.as_str()),
            ("email", email),
          ],
        )
        .await
      {
        tracing::error!(error = %e, "Failed to send magic link email");
      }
    } else {
      tracing::warn!("SMTP not configured; magic link email not sent");
    }
    tracing::info!("OTP/magic link token generated");
  }

  Ok(Json(serde_json::json!({})))
}

pub async fn magiclink(
  State(state): State<AppState>,
  ConnectInfo(client_addr): ConnectInfo<SocketAddr>,
  Json(req): Json<MagicLinkRequest>,
) -> Result<Json<serde_json::Value>> {
  let otp_req = OtpRequest {
    email: Some(req.email),
    phone: None,
    create_user: Some(false),
    data: None,
  };
  send_otp(State(state), ConnectInfo(client_addr), Json(otp_req)).await
}

fn otp_ip_rate_limit_key(client_ip: IpAddr) -> String {
  format!("otp-ip:{client_ip}")
}
