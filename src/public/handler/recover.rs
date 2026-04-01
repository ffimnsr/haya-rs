use axum::{Json, extract::State};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use chrono::Utc;
use rand::RngCore;
use serde::Deserialize;

use crate::{
    error::Result,
    mailer::EmailKind,
    public::handler::signup::is_valid_email,
    state::AppState,
};

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

    let user_exists: Option<(uuid::Uuid,)> = sqlx::query_as::<_, (uuid::Uuid,)>(
        "SELECT id FROM auth.users WHERE email = $1"
    )
    .bind(&req.email)
    .fetch_optional(&state.db)
    .await?;

    if user_exists.is_none() {
        // Return 200 regardless to prevent email enumeration
        return Ok(Json(serde_json::json!({})));
    }

    let (user_id,) = user_exists.unwrap();

    let mut bytes = [0u8; 32];
    rand::rng().fill_bytes(&mut bytes);
    let recovery_token = URL_SAFE_NO_PAD.encode(bytes);

    let now = Utc::now();
    sqlx::query(
        "UPDATE auth.users SET recovery_token = $1, recovery_sent_at = $2, updated_at = $3 WHERE id = $4"
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
            tracing::error!(error = %e, email = %req.email, "Failed to send recovery email");
        }
    } else {
        tracing::warn!(email = %req.email, "SMTP not configured; recovery email not sent");
    }
    tracing::info!(email = %req.email, "Password recovery email requested");

    Ok(Json(serde_json::json!({})))
}
