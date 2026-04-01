use axum::{Json, extract::State};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use chrono::Utc;
use rand::RngCore;
use serde::Deserialize;
use uuid::Uuid;

use crate::{
    error::{AuthError, Result},
    public::handler::signup::is_valid_email,
    state::AppState,
};

#[derive(Debug, Deserialize)]
pub struct OtpRequest {
    pub email: Option<String>,
    // Reserved for future phone OTP support
    #[allow(dead_code)]
    pub phone: Option<String>,
    pub create_user: Option<bool>,
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
        let create_user = req.create_user.unwrap_or(true);

        let existing: Option<(Uuid,)> = sqlx::query_as::<_, (Uuid,)>(
            "SELECT id FROM auth.users WHERE email = $1"
        )
        .bind(email)
        .fetch_optional(&state.db)
        .await?;

        let user_id = if let Some((id,)) = existing {
            id
        } else if create_user {
            let id = Uuid::new_v4();
            let now = Utc::now();
            let user_metadata = req.data.clone().unwrap_or(serde_json::json!({}));
            let app_metadata = serde_json::json!({"provider": "email", "providers": ["email"]});
            sqlx::query(
                "INSERT INTO auth.users (id, instance_id, aud, role, email, raw_app_meta_data, raw_user_meta_data, is_anonymous, created_at, updated_at) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)"
            )
            .bind(id)
            .bind(state.instance_id)
            .bind("authenticated")
            .bind("authenticated")
            .bind(email)
            .bind(&app_metadata)
            .bind(&user_metadata)
            .bind(false)
            .bind(now)
            .bind(now)
            .execute(&state.db)
            .await?;
            id
        } else {
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

        // TODO: send token to email via your mailer
        tracing::info!(email = %email, "OTP token generated");
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
        create_user: Some(true),
        data: None,
    };
    send_otp(State(state), Json(otp_req)).await
}
