use axum::{Json, extract::State};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use chrono::Utc;
use rand::RngCore;
use serde::Deserialize;
use uuid::Uuid;

use crate::{
    auth::jwt,
    error::{AuthError, Result},
    model::{TokenResponse, User, UserResponse},
    state::AppState,
};

#[derive(Debug, Deserialize)]
pub struct VerifyRequest {
    #[serde(rename = "type")]
    pub verify_type: String,
    pub token: String,
    pub email: Option<String>,
}

#[derive(Debug, serde::Serialize)]
#[serde(untagged)]
pub enum VerifyResponse {
    Token(TokenResponse),
    User(UserResponse),
}

pub async fn verify(
    State(state): State<AppState>,
    Json(req): Json<VerifyRequest>,
) -> Result<Json<VerifyResponse>> {
    match req.verify_type.as_str() {
        "signup" => handle_signup_verify(state, req).await,
        "recovery" => handle_recovery_verify(state, req).await,
        _ => Err(AuthError::ValidationFailed(format!(
            "Unsupported verify type: {}",
            req.verify_type
        ))),
    }
}

async fn handle_signup_verify(
    state: AppState,
    req: VerifyRequest,
) -> Result<Json<VerifyResponse>> {
    let user: User = sqlx::query_as::<_, User>(
        "SELECT id, instance_id, aud, role, email, encrypted_password, email_confirmed_at, phone, phone_confirmed_at, confirmed_at, last_sign_in_at, raw_app_meta_data, raw_user_meta_data, is_super_admin, is_anonymous, banned_until, created_at, updated_at FROM auth.users WHERE confirmation_token = $1"
    )
    .bind(&req.token)
    .fetch_optional(&state.db)
    .await?
    .ok_or(AuthError::InvalidToken)?;

    let now = Utc::now();
    sqlx::query(
        "UPDATE auth.users SET email_confirmed_at = $1, confirmation_token = NULL, updated_at = $2 WHERE id = $3"
    )
    .bind(now)
    .bind(now)
    .bind(user.id)
    .execute(&state.db)
    .await?;

    let updated_user: User = sqlx::query_as::<_, User>(
        "SELECT id, instance_id, aud, role, email, encrypted_password, email_confirmed_at, phone, phone_confirmed_at, confirmed_at, last_sign_in_at, raw_app_meta_data, raw_user_meta_data, is_super_admin, is_anonymous, banned_until, created_at, updated_at FROM auth.users WHERE id = $1"
    )
    .bind(user.id)
    .fetch_one(&state.db)
    .await?;

    Ok(Json(VerifyResponse::User(UserResponse::from(updated_user))))
}

async fn handle_recovery_verify(
    state: AppState,
    req: VerifyRequest,
) -> Result<Json<VerifyResponse>> {
    let user: User = sqlx::query_as::<_, User>(
        "SELECT id, instance_id, aud, role, email, encrypted_password, email_confirmed_at, phone, phone_confirmed_at, confirmed_at, last_sign_in_at, raw_app_meta_data, raw_user_meta_data, is_super_admin, is_anonymous, banned_until, created_at, updated_at FROM auth.users WHERE recovery_token = $1"
    )
    .bind(&req.token)
    .fetch_optional(&state.db)
    .await?
    .ok_or(AuthError::InvalidToken)?;

    let now = Utc::now();
    sqlx::query(
        "UPDATE auth.users SET recovery_token = NULL, updated_at = $1 WHERE id = $2"
    )
    .bind(now)
    .bind(user.id)
    .execute(&state.db)
    .await?;

    let session_id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO auth.sessions (id, user_id, aal, created_at, updated_at) VALUES ($1, $2, $3, $4, $5)"
    )
    .bind(session_id)
    .bind(user.id)
    .bind("aal1")
    .bind(now)
    .bind(now)
    .execute(&state.db)
    .await?;

    let mut bytes = [0u8; 32];
    rand::rng().fill_bytes(&mut bytes);
    let refresh_token_str = URL_SAFE_NO_PAD.encode(bytes);

    sqlx::query(
        "INSERT INTO auth.refresh_tokens (instance_id, user_id, token, session_id, revoked, created_at, updated_at) VALUES ($1, $2, $3, $4, false, $5, $6)"
    )
    .bind(state.instance_id)
    .bind(user.id.to_string())
    .bind(&refresh_token_str)
    .bind(session_id)
    .bind(now)
    .bind(now)
    .execute(&state.db)
    .await?;

    let app_meta = user.raw_app_meta_data.clone().unwrap_or(serde_json::json!({}));
    let user_meta = user.raw_user_meta_data.clone().unwrap_or(serde_json::json!({}));
    let role = user.role.as_deref().unwrap_or("authenticated");

    let access_token = jwt::encode_token(
        user.id,
        user.email.clone(),
        user.phone.clone(),
        role,
        session_id,
        user.is_anonymous,
        "recovery",
        user_meta,
        app_meta,
        &state.jwt_secret,
        state.jwt_exp,
        &state.issuer,
    )?;

    let expires_at = Utc::now().timestamp() + state.jwt_exp;
    Ok(Json(VerifyResponse::Token(TokenResponse {
        access_token,
        token_type: "bearer".to_string(),
        expires_in: state.jwt_exp,
        expires_at,
        refresh_token: refresh_token_str,
        user: UserResponse::from(user),
    })))
}
