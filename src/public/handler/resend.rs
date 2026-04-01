use axum::{Json, extract::State};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use chrono::Utc;
use rand::RngCore;
use serde::Deserialize;

use crate::{
    error::{AuthError, Result},
    mailer::EmailKind,
    public::handler::signup::is_valid_email,
    state::AppState,
};

#[derive(Debug, Deserialize)]
pub struct ResendRequest {
    #[serde(rename = "type")]
    pub resend_type: String,
    pub email: Option<String>,
    // Reserved for future phone OTP resend support
    #[allow(dead_code)]
    pub phone: Option<String>,
}

pub async fn resend(
    State(state): State<AppState>,
    Json(req): Json<ResendRequest>,
) -> Result<Json<serde_json::Value>> {
    let email = req
        .email
        .as_deref()
        .ok_or_else(|| AuthError::ValidationFailed("email is required".to_string()))?;

    if !is_valid_email(email) {
        return Err(AuthError::ValidationFailed("Invalid email format".to_string()));
    }

    let user_id: Option<(uuid::Uuid,)> = sqlx::query_as::<_, (uuid::Uuid,)>(
        "SELECT id FROM auth.users WHERE email = $1"
    )
    .bind(email)
    .fetch_optional(&state.db)
    .await?;

    if user_id.is_none() {
        return Ok(Json(serde_json::json!({})));
    }

    let (user_id,) = user_id.unwrap();
    let mut bytes = [0u8; 32];
    rand::rng().fill_bytes(&mut bytes);
    let token = URL_SAFE_NO_PAD.encode(bytes);
    let now = Utc::now();

    match req.resend_type.as_str() {
        "signup" => {
            sqlx::query(
                "UPDATE auth.users SET confirmation_token = $1, confirmation_sent_at = $2, updated_at = $3 WHERE id = $4"
            )
            .bind(&token)
            .bind(now)
            .bind(now)
            .bind(user_id)
            .execute(&state.db)
            .await?;
            let confirmation_url =
                format!("{}/verify?token={}&type=signup", state.site_url, token);
            if let Some(ref mailer) = state.mailer {
                if let Err(e) = mailer
                    .send(
                        EmailKind::Confirmation,
                        email,
                        &[
                            ("site_name", state.site_name.as_str()),
                            ("confirmation_url", confirmation_url.as_str()),
                            ("email", email),
                        ],
                    )
                    .await
                {
                    tracing::error!(error = %e, %email, "Failed to resend confirmation email");
                }
            } else {
                tracing::warn!(%email, "SMTP not configured; confirmation email not sent");
            }
            tracing::info!(%email, "Signup confirmation token regenerated");
        }
        "recovery" => {
            sqlx::query(
                "UPDATE auth.users SET recovery_token = $1, recovery_sent_at = $2, updated_at = $3 WHERE id = $4"
            )
            .bind(&token)
            .bind(now)
            .bind(now)
            .bind(user_id)
            .execute(&state.db)
            .await?;
            let recovery_url =
                format!("{}/verify?token={}&type=recovery", state.site_url, token);
            if let Some(ref mailer) = state.mailer {
                if let Err(e) = mailer
                    .send(
                        EmailKind::Recovery,
                        email,
                        &[
                            ("site_name", state.site_name.as_str()),
                            ("recovery_url", recovery_url.as_str()),
                            ("email", email),
                        ],
                    )
                    .await
                {
                    tracing::error!(error = %e, %email, "Failed to resend recovery email");
                }
            } else {
                tracing::warn!(%email, "SMTP not configured; recovery email not sent");
            }
            tracing::info!(%email, "Recovery token regenerated");
        }
        _ => {
            return Err(AuthError::ValidationFailed(format!(
                "Unsupported resend type: {}",
                req.resend_type
            )));
        }
    }

    Ok(Json(serde_json::json!({})))
}
