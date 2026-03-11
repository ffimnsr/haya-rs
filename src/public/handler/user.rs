use axum::{Json, extract::State};
use chrono::Utc;
use serde::Deserialize;
use uuid::Uuid;

use crate::{
    auth::password,
    error::{AuthError, Result},
    middleware::auth::AuthUser,
    model::{User, UserResponse},
    state::AppState,
};

pub async fn get_user(
    State(state): State<AppState>,
    AuthUser(claims): AuthUser,
) -> Result<Json<UserResponse>> {
    let user_id: Uuid = claims
        .sub
        .parse()
        .map_err(|_| AuthError::InternalError("Invalid user_id in token".to_string()))?;

    let user: User = sqlx::query_as::<_, User>(
        "SELECT id, instance_id, aud, role, email, encrypted_password, email_confirmed_at, phone, phone_confirmed_at, confirmed_at, last_sign_in_at, raw_app_meta_data, raw_user_meta_data, is_super_admin, is_anonymous, banned_until, created_at, updated_at FROM auth.users WHERE id = $1"
    )
    .bind(user_id)
    .fetch_optional(&state.db)
    .await?
    .ok_or(AuthError::UserNotFound)?;

    Ok(Json(UserResponse::from(user)))
}

#[derive(Debug, Deserialize)]
pub struct UpdateUserRequest {
    pub email: Option<String>,
    pub password: Option<String>,
    pub phone: Option<String>,
    pub data: Option<serde_json::Value>,
}

pub async fn update_user(
    State(state): State<AppState>,
    AuthUser(claims): AuthUser,
    Json(req): Json<UpdateUserRequest>,
) -> Result<Json<UserResponse>> {
    let user_id: Uuid = claims
        .sub
        .parse()
        .map_err(|_| AuthError::InternalError("Invalid user_id in token".to_string()))?;

    let now = Utc::now();

    if let Some(ref pw) = req.password {
        if pw.len() < 6 {
            return Err(AuthError::ValidationFailed(
                "Password must be at least 6 characters.".to_string(),
            ));
        }
        let hashed = password::hash_password(pw)?;
        sqlx::query(
            "UPDATE auth.users SET encrypted_password = $1, updated_at = $2 WHERE id = $3"
        )
        .bind(hashed)
        .bind(now)
        .bind(user_id)
        .execute(&state.db)
        .await?;
    }

    if let Some(ref meta) = req.data {
        sqlx::query(
            "UPDATE auth.users SET raw_user_meta_data = $1, updated_at = $2 WHERE id = $3"
        )
        .bind(meta)
        .bind(now)
        .bind(user_id)
        .execute(&state.db)
        .await?;
    }

    if let Some(ref email) = req.email {
        sqlx::query("UPDATE auth.users SET email = $1, updated_at = $2 WHERE id = $3")
            .bind(email)
            .bind(now)
            .bind(user_id)
            .execute(&state.db)
            .await?;
    }

    if let Some(ref phone) = req.phone {
        sqlx::query("UPDATE auth.users SET phone = $1, updated_at = $2 WHERE id = $3")
            .bind(phone)
            .bind(now)
            .bind(user_id)
            .execute(&state.db)
            .await?;
    }

    let user: User = sqlx::query_as::<_, User>(
        "SELECT id, instance_id, aud, role, email, encrypted_password, email_confirmed_at, phone, phone_confirmed_at, confirmed_at, last_sign_in_at, raw_app_meta_data, raw_user_meta_data, is_super_admin, is_anonymous, banned_until, created_at, updated_at FROM auth.users WHERE id = $1"
    )
    .bind(user_id)
    .fetch_optional(&state.db)
    .await?
    .ok_or(AuthError::UserNotFound)?;

    Ok(Json(UserResponse::from(user)))
}
