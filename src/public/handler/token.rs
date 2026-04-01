use axum::{
    Json,
    extract::{Query, State},
};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use chrono::Utc;
use rand::RngCore;
use serde::Deserialize;
use uuid::Uuid;

use crate::{
    auth::{jwt, password},
    error::{AuthError, Result},
    model::{RefreshToken, TokenResponse, User, UserResponse},
    state::AppState,
};

#[derive(Debug, Deserialize)]
pub struct TokenQuery {
    pub grant_type: String,
}

pub async fn token(
    State(state): State<AppState>,
    Query(query): Query<TokenQuery>,
    Json(body): Json<serde_json::Value>,
) -> Result<Json<TokenResponse>> {
    match query.grant_type.as_str() {
        "password" => handle_password_grant(state, body).await,
        "refresh_token" => handle_refresh_grant(state, body).await,
        _ => Err(AuthError::ValidationFailed(format!(
            "Unsupported grant_type: {}",
            query.grant_type
        ))),
    }
}

async fn handle_password_grant(
    state: AppState,
    body: serde_json::Value,
) -> Result<Json<TokenResponse>> {
    let email = body
        .get("email")
        .and_then(|v| v.as_str())
        .ok_or_else(|| AuthError::ValidationFailed("email is required".to_string()))?;
    let pw = body
        .get("password")
        .and_then(|v| v.as_str())
        .ok_or_else(|| AuthError::ValidationFailed("password is required".to_string()))?;

    let user: User = sqlx::query_as::<_, User>(
        "SELECT id, instance_id, aud, role, email, encrypted_password, email_confirmed_at, phone, phone_confirmed_at, confirmed_at, last_sign_in_at, raw_app_meta_data, raw_user_meta_data, is_super_admin, is_anonymous, banned_until, created_at, updated_at FROM auth.users WHERE email = $1"
    )
    .bind(email)
    .fetch_optional(&state.db)
    .await?
    .ok_or(AuthError::InvalidCredentials)?;

    if let Some(banned_until) = user.banned_until {
        if banned_until > Utc::now() {
            return Err(AuthError::UserBanned);
        }
    }

    let hash = user
        .encrypted_password
        .as_deref()
        .ok_or(AuthError::InvalidCredentials)?;

    if !password::verify_password(pw, hash)? {
        return Err(AuthError::InvalidCredentials);
    }

    // Require email confirmation when mailer_autoconfirm is disabled
    if !state.mailer_autoconfirm && user.email.is_some() && user.email_confirmed_at.is_none() {
        return Err(AuthError::EmailNotConfirmed);
    }

    let now = Utc::now();
    let session_id = Uuid::new_v4();

    sqlx::query(
        "INSERT INTO auth.sessions (id, user_id, aal, created_at, updated_at) VALUES ($1, $2, $3::auth.aal_level, $4, $5)"
    )
    .bind(session_id)
    .bind(user.id)
    .bind("aal1")
    .bind(now)
    .bind(now)
    .execute(&state.db)
    .await?;

    let refresh_token_str = generate_refresh_token();
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

    sqlx::query("UPDATE auth.users SET last_sign_in_at = $1, updated_at = $2 WHERE id = $3")
        .bind(now)
        .bind(now)
        .bind(user.id)
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
        "password",
        user_meta,
        app_meta,
        &state.jwt_secret,
        state.jwt_exp,
        &state.issuer,
    )?;

    let expires_at = now.timestamp() + state.jwt_exp;
    Ok(Json(TokenResponse {
        access_token,
        token_type: "bearer".to_string(),
        expires_in: state.jwt_exp,
        expires_at,
        refresh_token: refresh_token_str,
        user: UserResponse::from(user),
    }))
}

async fn handle_refresh_grant(
    state: AppState,
    body: serde_json::Value,
) -> Result<Json<TokenResponse>> {
    let rt_str = body
        .get("refresh_token")
        .and_then(|v| v.as_str())
        .ok_or_else(|| AuthError::ValidationFailed("refresh_token is required".to_string()))?;

    let rt: RefreshToken = sqlx::query_as::<_, RefreshToken>(
        "SELECT id, instance_id, user_id, token, created_at, updated_at, parent, session_id, revoked FROM auth.refresh_tokens WHERE token = $1 AND revoked = false"
    )
    .bind(rt_str)
    .fetch_optional(&state.db)
    .await?
    .ok_or(AuthError::InvalidToken)?;

    let session_id = rt.session_id.ok_or(AuthError::SessionNotFound)?;
    let user_id_str = rt.user_id.ok_or(AuthError::UserNotFound)?;
    let user_id: Uuid = user_id_str
        .parse()
        .map_err(|_| AuthError::InternalError("Invalid user_id in refresh token".to_string()))?;

    let session_exists: Option<(Uuid,)> = sqlx::query_as::<_, (Uuid,)>(
        "SELECT id FROM auth.sessions WHERE id = $1"
    )
    .bind(session_id)
    .fetch_optional(&state.db)
    .await?;

    if session_exists.is_none() {
        return Err(AuthError::SessionNotFound);
    }

    let user: User = sqlx::query_as::<_, User>(
        "SELECT id, instance_id, aud, role, email, encrypted_password, email_confirmed_at, phone, phone_confirmed_at, confirmed_at, last_sign_in_at, raw_app_meta_data, raw_user_meta_data, is_super_admin, is_anonymous, banned_until, created_at, updated_at FROM auth.users WHERE id = $1"
    )
    .bind(user_id)
    .fetch_optional(&state.db)
    .await?
    .ok_or(AuthError::UserNotFound)?;

    let now = Utc::now();

    sqlx::query("UPDATE auth.refresh_tokens SET revoked = true, updated_at = $1 WHERE id = $2")
        .bind(now)
        .bind(rt.id)
        .execute(&state.db)
        .await?;

    let new_refresh_token = generate_refresh_token();
    sqlx::query(
        "INSERT INTO auth.refresh_tokens (instance_id, user_id, token, session_id, revoked, parent, created_at, updated_at) VALUES ($1, $2, $3, $4, false, $5, $6, $7)"
    )
    .bind(state.instance_id)
    .bind(user.id.to_string())
    .bind(&new_refresh_token)
    .bind(session_id)
    .bind(rt_str)
    .bind(now)
    .bind(now)
    .execute(&state.db)
    .await?;

    sqlx::query("UPDATE auth.sessions SET refreshed_at = $1, updated_at = $2 WHERE id = $3")
        // refreshed_at is 'timestamp without time zone' in the schema, so use naive_utc()
        .bind(now.naive_utc())
        .bind(now)
        .bind(session_id)
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
        "password",
        user_meta,
        app_meta,
        &state.jwt_secret,
        state.jwt_exp,
        &state.issuer,
    )?;

    let expires_at = now.timestamp() + state.jwt_exp;
    Ok(Json(TokenResponse {
        access_token,
        token_type: "bearer".to_string(),
        expires_in: state.jwt_exp,
        expires_at,
        refresh_token: new_refresh_token,
        user: UserResponse::from(user),
    }))
}

fn generate_refresh_token() -> String {
    let mut bytes = [0u8; 32];
    rand::rng().fill_bytes(&mut bytes);
    URL_SAFE_NO_PAD.encode(bytes)
}
