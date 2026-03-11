use axum::{
    Json,
    extract::{Path, Query, State},
    http::StatusCode,
    response::IntoResponse,
};
use chrono::Utc;
use serde::Deserialize;
use uuid::Uuid;

use crate::{
    auth::password,
    error::{AuthError, Result},
    middleware::auth::AdminUser,
    model::{User, UserResponse},
    state::AppState,
};

#[derive(Debug, Deserialize)]
pub struct PaginationQuery {
    pub page: Option<i64>,
    pub per_page: Option<i64>,
}

pub async fn admin_list_users(
    State(state): State<AppState>,
    Query(query): Query<PaginationQuery>,
    AdminUser(_claims): AdminUser,
) -> Result<Json<serde_json::Value>> {
    let page = query.page.unwrap_or(1);
    let per_page = query.per_page.unwrap_or(50);
    let offset = (page - 1) * per_page;

    let users: Vec<User> = sqlx::query_as::<_, User>(
        "SELECT id, instance_id, aud, role, email, encrypted_password, email_confirmed_at, phone, phone_confirmed_at, confirmed_at, last_sign_in_at, raw_app_meta_data, raw_user_meta_data, is_super_admin, is_anonymous, banned_until, created_at, updated_at FROM auth.users ORDER BY created_at DESC LIMIT $1 OFFSET $2"
    )
    .bind(per_page)
    .bind(offset)
    .fetch_all(&state.db)
    .await?;

    let total: (i64,) = sqlx::query_as::<_, (i64,)>("SELECT COUNT(*) FROM auth.users")
        .fetch_one(&state.db)
        .await?;

    let user_responses: Vec<UserResponse> = users.into_iter().map(UserResponse::from).collect();

    Ok(Json(serde_json::json!({
        "users": user_responses,
        "aud": "authenticated",
        "total": total.0,
    })))
}

#[derive(Debug, Deserialize)]
pub struct AdminCreateUserRequest {
    pub email: Option<String>,
    pub password: Option<String>,
    pub phone: Option<String>,
    pub role: Option<String>,
    pub user_metadata: Option<serde_json::Value>,
    pub app_metadata: Option<serde_json::Value>,
    pub email_confirm: Option<bool>,
    pub phone_confirm: Option<bool>,
    pub ban_duration: Option<String>,
}

pub async fn admin_create_user(
    State(state): State<AppState>,
    AdminUser(_claims): AdminUser,
    Json(req): Json<AdminCreateUserRequest>,
) -> Result<Json<UserResponse>> {
    if let Some(ref email) = req.email {
        let existing: Option<(Uuid,)> = sqlx::query_as::<_, (Uuid,)>(
            "SELECT id FROM auth.users WHERE email = $1"
        )
        .bind(email)
        .fetch_optional(&state.db)
        .await?;
        if existing.is_some() {
            return Err(AuthError::UserAlreadyExists);
        }
    }

    let user_id = Uuid::new_v4();
    let now = Utc::now();
    let hashed = if let Some(ref pw) = req.password {
        Some(password::hash_password(pw)?)
    } else {
        None
    };

    let role = req.role.as_deref().unwrap_or("authenticated");
    let user_metadata = req.user_metadata.unwrap_or(serde_json::json!({}));
    let app_metadata = req
        .app_metadata
        .unwrap_or(serde_json::json!({"provider": "email", "providers": ["email"]}));
    let email_confirmed_at = if req.email_confirm.unwrap_or(false) {
        Some(now)
    } else {
        None
    };
    let phone_confirmed_at = if req.phone_confirm.unwrap_or(false) {
        Some(now)
    } else {
        None
    };

    let user: User = sqlx::query_as::<_, User>(
        "INSERT INTO auth.users (id, instance_id, aud, role, email, encrypted_password, phone, raw_app_meta_data, raw_user_meta_data, email_confirmed_at, phone_confirmed_at, is_anonymous, created_at, updated_at) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14) RETURNING id, instance_id, aud, role, email, encrypted_password, email_confirmed_at, phone, phone_confirmed_at, confirmed_at, last_sign_in_at, raw_app_meta_data, raw_user_meta_data, is_super_admin, is_anonymous, banned_until, created_at, updated_at"
    )
    .bind(user_id)
    .bind(state.instance_id)
    .bind("authenticated")
    .bind(role)
    .bind(&req.email)
    .bind(hashed)
    .bind(&req.phone)
    .bind(&app_metadata)
    .bind(&user_metadata)
    .bind(email_confirmed_at)
    .bind(phone_confirmed_at)
    .bind(false)
    .bind(now)
    .bind(now)
    .fetch_one(&state.db)
    .await?;

    // Apply ban_duration if provided
    if let Some(ref ban_duration) = req.ban_duration {
        if ban_duration != "none" {
            let duration_secs = parse_ban_duration(ban_duration)?;
            let banned_until = now + chrono::Duration::seconds(duration_secs);
            sqlx::query(
                "UPDATE auth.users SET banned_until = $1, updated_at = $2 WHERE id = $3"
            )
            .bind(banned_until)
            .bind(now)
            .bind(user_id)
            .execute(&state.db)
            .await?;
        }
    }

    Ok(Json(UserResponse::from(user)))
}

pub async fn admin_get_user(
    State(state): State<AppState>,
    AdminUser(_claims): AdminUser,
    Path(user_id): Path<Uuid>,
) -> Result<Json<UserResponse>> {
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
pub struct AdminUpdateUserRequest {
    pub email: Option<String>,
    pub password: Option<String>,
    pub phone: Option<String>,
    pub role: Option<String>,
    pub user_metadata: Option<serde_json::Value>,
    pub app_metadata: Option<serde_json::Value>,
    pub email_confirm: Option<bool>,
    pub ban_duration: Option<String>,
}

pub async fn admin_update_user(
    State(state): State<AppState>,
    AdminUser(_claims): AdminUser,
    Path(user_id): Path<Uuid>,
    Json(req): Json<AdminUpdateUserRequest>,
) -> Result<Json<UserResponse>> {
    let now = Utc::now();

    if let Some(ref pw) = req.password {
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

    if let Some(ref role) = req.role {
        sqlx::query("UPDATE auth.users SET role = $1, updated_at = $2 WHERE id = $3")
            .bind(role)
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

    if let Some(ref meta) = req.user_metadata {
        sqlx::query(
            "UPDATE auth.users SET raw_user_meta_data = $1, updated_at = $2 WHERE id = $3"
        )
        .bind(meta)
        .bind(now)
        .bind(user_id)
        .execute(&state.db)
        .await?;
    }

    if let Some(ref meta) = req.app_metadata {
        sqlx::query(
            "UPDATE auth.users SET raw_app_meta_data = $1, updated_at = $2 WHERE id = $3"
        )
        .bind(meta)
        .bind(now)
        .bind(user_id)
        .execute(&state.db)
        .await?;
    }

    if let Some(true) = req.email_confirm {
        sqlx::query(
            "UPDATE auth.users SET email_confirmed_at = $1, updated_at = $2 WHERE id = $3"
        )
        .bind(now)
        .bind(now)
        .bind(user_id)
        .execute(&state.db)
        .await?;
    }

    if let Some(ref ban_duration) = req.ban_duration {
        if ban_duration == "none" {
            sqlx::query(
                "UPDATE auth.users SET banned_until = NULL, updated_at = $1 WHERE id = $2"
            )
            .bind(now)
            .bind(user_id)
            .execute(&state.db)
            .await?;
        } else {
            let duration_secs = parse_ban_duration(ban_duration)?;
            let banned_until = now + chrono::Duration::seconds(duration_secs);
            sqlx::query(
                "UPDATE auth.users SET banned_until = $1, updated_at = $2 WHERE id = $3"
            )
            .bind(banned_until)
            .bind(now)
            .bind(user_id)
            .execute(&state.db)
            .await?;
        }
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

pub async fn admin_delete_user(
    State(state): State<AppState>,
    AdminUser(_claims): AdminUser,
    Path(user_id): Path<Uuid>,
) -> Result<impl IntoResponse> {
    let result = sqlx::query("DELETE FROM auth.users WHERE id = $1")
        .bind(user_id)
        .execute(&state.db)
        .await?;

    if result.rows_affected() == 0 {
        return Err(AuthError::UserNotFound);
    }

    Ok(StatusCode::NO_CONTENT)
}

fn parse_ban_duration(duration: &str) -> Result<i64, AuthError> {
    if let Some(hours) = duration.strip_suffix('h') {
        hours.parse::<i64>()
            .map(|h| h * 3600)
            .map_err(|_| AuthError::ValidationFailed(format!("Invalid ban duration: {}", duration)))
    } else if let Some(days) = duration.strip_suffix('d') {
        days.parse::<i64>()
            .map(|d| d * 86400)
            .map_err(|_| AuthError::ValidationFailed(format!("Invalid ban duration: {}", duration)))
    } else if let Some(minutes) = duration.strip_suffix('m') {
        minutes.parse::<i64>()
            .map(|m| m * 60)
            .map_err(|_| AuthError::ValidationFailed(format!("Invalid ban duration: {}", duration)))
    } else {
        Err(AuthError::ValidationFailed(format!(
            "Invalid ban duration format: {}. Use format like '24h', '7d', or '30m'.",
            duration
        )))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_ban_duration_hours() {
        assert_eq!(parse_ban_duration("1h").unwrap(), 3600);
        assert_eq!(parse_ban_duration("24h").unwrap(), 86400);
        assert_eq!(parse_ban_duration("0h").unwrap(), 0);
    }

    #[test]
    fn test_parse_ban_duration_days() {
        assert_eq!(parse_ban_duration("1d").unwrap(), 86400);
        assert_eq!(parse_ban_duration("7d").unwrap(), 604800);
    }

    #[test]
    fn test_parse_ban_duration_minutes() {
        assert_eq!(parse_ban_duration("30m").unwrap(), 1800);
        assert_eq!(parse_ban_duration("60m").unwrap(), 3600);
    }

    #[test]
    fn test_parse_ban_duration_invalid() {
        assert!(parse_ban_duration("24x").is_err());
        assert!(parse_ban_duration("invalid").is_err());
        assert!(parse_ban_duration("").is_err());
        assert!(parse_ban_duration("abch").is_err());
    }
}
