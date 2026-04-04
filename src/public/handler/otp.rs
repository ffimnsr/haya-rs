use axum::Json;
use axum::extract::State;
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use chrono::Utc;
use rand::RngCore;
use serde::Deserialize;
use uuid::Uuid;

use crate::error::{
  AuthError,
  Result,
};
use crate::mailer::EmailKind;
use crate::public::handler::signup::is_valid_email;
use crate::state::AppState;

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
  Json(req): Json<OtpRequest>,
) -> Result<Json<serde_json::Value>> {
  if let Some(ref email) = req.email {
    if !is_valid_email(email) {
      return Err(AuthError::ValidationFailed("Invalid email format".to_string()));
    }
    let _create_user = req.create_user.unwrap_or(false);

    let existing: Option<(Uuid,)> =
      sqlx::query_as::<_, (Uuid,)>("SELECT id FROM auth.users WHERE email = $1")
        .bind(email)
        .fetch_optional(&state.db)
        .await?;

    let user_id = if let Some((id,)) = existing {
      id
    } else {
      // Do not create auth.users rows until the mailbox is proven by a completed verification flow.
      return Ok(Json(serde_json::json!({})));
    };

    let mut bytes = [0u8; 32];
    rand::rng().fill_bytes(&mut bytes);
    let token = URL_SAFE_NO_PAD.encode(bytes);
    let now = Utc::now();

    sqlx::query(
            "UPDATE auth.users SET confirmation_token = $1, confirmation_sent_at = $2, updated_at = $3 WHERE id = $4"
        )
        .bind(&token)
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
  Json(req): Json<MagicLinkRequest>,
) -> Result<Json<serde_json::Value>> {
  let otp_req = OtpRequest {
    email: Some(req.email),
    phone: None,
    create_user: Some(false),
    data: None,
  };
  send_otp(State(state), Json(otp_req)).await
}
