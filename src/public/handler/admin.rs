use axum::Json;
use axum::extract::{
  ConnectInfo,
  Path,
  Query,
  State,
};
use axum::http::StatusCode;
use axum::response::IntoResponse;
use chrono::Utc;
use serde::Deserialize;
use std::net::SocketAddr;
use uuid::Uuid;

use crate::auth::{
  audit,
  password,
};
use crate::error::{
  AuthError,
  Result,
};
use crate::middleware::auth::AdminUser;
use crate::model::{
  User,
  UserResponse,
  identity_values_by_user_id,
};
use crate::public::handler::signup::{
  is_valid_e164_phone,
  is_valid_email,
};
use crate::state::AppState;

const ALLOWED_USER_ROLES: &[&str] = &["authenticated", "service_role", "supabase_admin", "anon"];
const RESERVED_APP_METADATA_KEYS: &[&str] = &["provider", "providers", "role"];

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
  let page = query.page.unwrap_or(1).max(1);
  let per_page = query.per_page.unwrap_or(50).clamp(1, 100);
  let offset = (page - 1) * per_page;

  let users: Vec<User> = sqlx::query_as::<_, User>(
        "SELECT id, instance_id, aud, role, email, encrypted_password, email_confirmed_at, phone, phone_confirmed_at, confirmed_at, last_sign_in_at, raw_app_meta_data, raw_user_meta_data, is_super_admin, is_sso_user, is_anonymous, banned_until, deleted_at, created_at, updated_at FROM auth.users ORDER BY created_at DESC LIMIT $1 OFFSET $2"
    )
    .bind(per_page)
    .bind(offset)
    .fetch_all(&state.db)
    .await?;

  let total: (i64,) = sqlx::query_as::<_, (i64,)>("SELECT COUNT(*) FROM auth.users")
    .fetch_one(&state.db)
    .await?;

  let user_ids = users.iter().map(|user| user.id).collect::<Vec<_>>();
  let identity_map = identity_values_by_user_id(&state.db, &user_ids).await?;
  let user_responses: Vec<UserResponse> = users
    .into_iter()
    .map(|user| UserResponse {
      id: user.id,
      instance_id: user.instance_id,
      aud: user.aud.unwrap_or_else(|| "authenticated".to_string()),
      role: user.role.unwrap_or_else(|| "authenticated".to_string()),
      email: user.email,
      email_confirmed_at: user.email_confirmed_at,
      phone: user.phone,
      phone_confirmed_at: user.phone_confirmed_at,
      confirmed_at: user.confirmed_at,
      last_sign_in_at: user.last_sign_in_at,
      app_metadata: user.raw_app_meta_data.unwrap_or(serde_json::json!({})),
      user_metadata: user.raw_user_meta_data.unwrap_or(serde_json::json!({})),
      identities: identity_map.get(&user.id).cloned().unwrap_or_default(),
      is_super_admin: user.is_super_admin.unwrap_or(false),
      is_sso_user: user.is_sso_user,
      banned_until: user.banned_until,
      deleted_at: user.deleted_at,
      created_at: user.created_at,
      updated_at: user.updated_at,
      is_anonymous: user.is_anonymous,
    })
    .collect();

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
  ConnectInfo(client_addr): ConnectInfo<SocketAddr>,
  AdminUser(_claims): AdminUser,
  Json(req): Json<AdminCreateUserRequest>,
) -> Result<Json<UserResponse>> {
  if let Some(ref email) = req.email {
    if !is_valid_email(email) {
      return Err(AuthError::ValidationFailed("Invalid email format".to_string()));
    }
    let existing: Option<(Uuid,)> =
      sqlx::query_as::<_, (Uuid,)>("SELECT id FROM auth.users WHERE email = $1")
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
    validate_password_policy(pw)?;
    Some(password::hash_password(pw)?)
  } else {
    None
  };

  let role = req.role.as_deref().unwrap_or("authenticated");
  validate_role(role)?;
  let user_metadata = req.user_metadata.unwrap_or(serde_json::json!({}));
  let app_metadata = validate_admin_app_metadata(
    req
      .app_metadata
      .unwrap_or(serde_json::json!({"provider": "email", "providers": ["email"]})),
  )?;
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

  let banned_until = match req.ban_duration.as_deref() {
    Some("none") | None => None,
    Some(duration) => Some(now + chrono::Duration::seconds(parse_ban_duration(duration)?)),
  };

  let mut tx = state.db.begin().await?;
  let user: User = sqlx::query_as::<_, User>(
        "INSERT INTO auth.users (id, instance_id, aud, role, email, encrypted_password, phone, raw_app_meta_data, raw_user_meta_data, email_confirmed_at, phone_confirmed_at, is_anonymous, banned_until, created_at, updated_at) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15) RETURNING id, instance_id, aud, role, email, encrypted_password, email_confirmed_at, phone, phone_confirmed_at, confirmed_at, last_sign_in_at, raw_app_meta_data, raw_user_meta_data, is_super_admin, is_sso_user, is_anonymous, banned_until, deleted_at, created_at, updated_at"
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
    .bind(banned_until)
    .bind(now)
    .bind(now)
    .fetch_one(&mut *tx)
    .await?;
  audit::log_event_tx(
    tx.as_mut(),
    state.instance_id,
    Some(client_addr.ip()),
    "admin_user_created",
    serde_json::json!({
      "target_user_id": user.id,
      "email": user.email,
      "role": user.role,
    }),
  )
  .await?;
  tx.commit().await?;

  Ok(Json(UserResponse::from_user(&state.db, user).await?))
}

pub async fn admin_get_user(
  State(state): State<AppState>,
  AdminUser(_claims): AdminUser,
  Path(user_id): Path<Uuid>,
) -> Result<Json<UserResponse>> {
  let user: User = sqlx::query_as::<_, User>(
        "SELECT id, instance_id, aud, role, email, encrypted_password, email_confirmed_at, phone, phone_confirmed_at, confirmed_at, last_sign_in_at, raw_app_meta_data, raw_user_meta_data, is_super_admin, is_sso_user, is_anonymous, banned_until, deleted_at, created_at, updated_at FROM auth.users WHERE id = $1"
    )
    .bind(user_id)
    .fetch_optional(&state.db)
    .await?
    .ok_or(AuthError::UserNotFound)?;

  Ok(Json(UserResponse::from_user(&state.db, user).await?))
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
  ConnectInfo(client_addr): ConnectInfo<SocketAddr>,
  AdminUser(_claims): AdminUser,
  Path(user_id): Path<Uuid>,
  Json(req): Json<AdminUpdateUserRequest>,
) -> Result<Json<UserResponse>> {
  let now = Utc::now();
  let mut tx = state.db.begin().await?;
  let mut password_changed = false;

  if let Some(ref pw) = req.password {
    validate_password_policy(pw)?;
    let hashed = password::hash_password(pw)?;
    sqlx::query("UPDATE auth.users SET encrypted_password = $1, updated_at = $2 WHERE id = $3")
      .bind(hashed)
      .bind(now)
      .bind(user_id)
      .execute(&mut *tx)
      .await?;
    sqlx::query("UPDATE auth.refresh_tokens SET revoked = true, updated_at = $1 WHERE user_id = $2")
      .bind(now)
      .bind(user_id.to_string())
      .execute(&mut *tx)
      .await?;
    sqlx::query("DELETE FROM auth.sessions WHERE user_id = $1")
      .bind(user_id)
      .execute(&mut *tx)
      .await?;
    password_changed = true;
  }

  if let Some(ref role) = req.role {
    validate_role(role)?;
    sqlx::query("UPDATE auth.users SET role = $1, updated_at = $2 WHERE id = $3")
      .bind(role)
      .bind(now)
      .bind(user_id)
      .execute(&mut *tx)
      .await?;
  }

  if let Some(ref email) = req.email {
    if !is_valid_email(email) {
      return Err(AuthError::ValidationFailed("Invalid email format".to_string()));
    }
    let existing: Option<(Uuid,)> =
      sqlx::query_as::<_, (Uuid,)>("SELECT id FROM auth.users WHERE email = $1 AND id != $2")
        .bind(email)
        .bind(user_id)
        .fetch_optional(&mut *tx)
        .await?;
    if existing.is_some() {
      return Err(AuthError::ValidationFailed(
        "Email address is already in use".to_string(),
      ));
    }
    sqlx::query("UPDATE auth.users SET email = $1, email_confirmed_at = NULL, updated_at = $2 WHERE id = $3")
      .bind(email)
      .bind(now)
      .bind(user_id)
      .execute(&mut *tx)
      .await?;
  }

  if let Some(ref phone) = req.phone {
    if !is_valid_e164_phone(phone) {
      return Err(AuthError::ValidationFailed(
        "Phone must be a valid E.164 number".to_string(),
      ));
    }
    sqlx::query("UPDATE auth.users SET phone = $1, phone_confirmed_at = NULL, updated_at = $2 WHERE id = $3")
      .bind(phone)
      .bind(now)
      .bind(user_id)
      .execute(&mut *tx)
      .await?;
  }

  if let Some(ref meta) = req.user_metadata {
    sqlx::query("UPDATE auth.users SET raw_user_meta_data = $1, updated_at = $2 WHERE id = $3")
      .bind(meta)
      .bind(now)
      .bind(user_id)
      .execute(&mut *tx)
      .await?;
  }

  if let Some(ref meta) = req.app_metadata {
    validate_admin_app_metadata(meta.clone())?;
    sqlx::query("UPDATE auth.users SET raw_app_meta_data = $1, updated_at = $2 WHERE id = $3")
      .bind(meta)
      .bind(now)
      .bind(user_id)
      .execute(&mut *tx)
      .await?;
  }

  if let Some(true) = req.email_confirm {
    sqlx::query("UPDATE auth.users SET email_confirmed_at = $1, updated_at = $2 WHERE id = $3")
      .bind(now)
      .bind(now)
      .bind(user_id)
      .execute(&mut *tx)
      .await?;
  }

  if let Some(ref ban_duration) = req.ban_duration {
    if ban_duration == "none" {
      sqlx::query("UPDATE auth.users SET banned_until = NULL, updated_at = $1 WHERE id = $2")
        .bind(now)
        .bind(user_id)
        .execute(&mut *tx)
        .await?;
    } else {
      let duration_secs = parse_ban_duration(ban_duration)?;
      let banned_until = now + chrono::Duration::seconds(duration_secs);
      sqlx::query("UPDATE auth.users SET banned_until = $1, updated_at = $2 WHERE id = $3")
        .bind(banned_until)
        .bind(now)
        .bind(user_id)
        .execute(&mut *tx)
        .await?;
    }
  }

  audit::log_event_tx(
    tx.as_mut(),
    state.instance_id,
    Some(client_addr.ip()),
    "admin_user_updated",
    serde_json::json!({
      "target_user_id": user_id,
      "password_changed": password_changed,
      "fields": {
        "email": req.email.is_some(),
        "phone": req.phone.is_some(),
        "role": req.role.is_some(),
        "user_metadata": req.user_metadata.is_some(),
        "app_metadata": req.app_metadata.is_some(),
        "email_confirm": req.email_confirm == Some(true),
        "ban_duration": req.ban_duration.is_some(),
      }
    }),
  )
  .await?;

  tx.commit().await?;

  let user: User = sqlx::query_as::<_, User>(
        "SELECT id, instance_id, aud, role, email, encrypted_password, email_confirmed_at, phone, phone_confirmed_at, confirmed_at, last_sign_in_at, raw_app_meta_data, raw_user_meta_data, is_super_admin, is_sso_user, is_anonymous, banned_until, deleted_at, created_at, updated_at FROM auth.users WHERE id = $1"
    )
    .bind(user_id)
    .fetch_optional(&state.db)
    .await?
    .ok_or(AuthError::UserNotFound)?;

  Ok(Json(UserResponse::from_user(&state.db, user).await?))
}

pub async fn admin_delete_user(
  State(state): State<AppState>,
  ConnectInfo(client_addr): ConnectInfo<SocketAddr>,
  AdminUser(_claims): AdminUser,
  Path(user_id): Path<Uuid>,
) -> Result<impl IntoResponse> {
  let mut tx = state.db.begin().await?;
  let result = sqlx::query("DELETE FROM auth.users WHERE id = $1")
    .bind(user_id)
    .execute(&mut *tx)
    .await?;

  if result.rows_affected() == 0 {
    tx.rollback().await?;
    return Err(AuthError::UserNotFound);
  }

  audit::log_event_tx(
    tx.as_mut(),
    state.instance_id,
    Some(client_addr.ip()),
    "admin_user_deleted",
    serde_json::json!({
      "target_user_id": user_id,
    }),
  )
  .await?;
  tx.commit().await?;

  Ok(StatusCode::NO_CONTENT)
}

pub(crate) fn parse_ban_duration(duration: &str) -> Result<i64, AuthError> {
  if let Some(hours) = duration.strip_suffix('h') {
    hours
      .parse::<i64>()
      .map(|h| h * 3600)
      .map_err(|_| AuthError::ValidationFailed(format!("Invalid ban duration: {}", duration)))
  } else if let Some(days) = duration.strip_suffix('d') {
    days
      .parse::<i64>()
      .map(|d| d * 86400)
      .map_err(|_| AuthError::ValidationFailed(format!("Invalid ban duration: {}", duration)))
  } else if let Some(minutes) = duration.strip_suffix('m') {
    minutes
      .parse::<i64>()
      .map(|m| m * 60)
      .map_err(|_| AuthError::ValidationFailed(format!("Invalid ban duration: {}", duration)))
  } else {
    Err(AuthError::ValidationFailed(format!(
      "Invalid ban duration format: {}. Use format like '24h', '7d', or '30m'.",
      duration
    )))
  }
}

pub(crate) fn validate_password_policy(password: &str) -> Result<(), AuthError> {
  if password.len() < 12 {
    return Err(AuthError::ValidationFailed(
      "Password must be at least 12 characters.".to_string(),
    ));
  }
  if password.len() > 128 {
    return Err(AuthError::ValidationFailed(
      "Password must not exceed 128 characters.".to_string(),
    ));
  }
  if password.chars().all(char::is_alphabetic) {
    return Err(AuthError::ValidationFailed(
      "Password must include at least one non-letter character.".to_string(),
    ));
  }
  Ok(())
}

pub(crate) fn validate_role(role: &str) -> Result<(), AuthError> {
  if ALLOWED_USER_ROLES.contains(&role) {
    return Ok(());
  }

  Err(AuthError::ValidationFailed(format!("Unsupported role: {role}")))
}

fn validate_admin_app_metadata(metadata: serde_json::Value) -> Result<serde_json::Value> {
  let serde_json::Value::Object(map) = &metadata else {
    return Ok(metadata);
  };

  for key in RESERVED_APP_METADATA_KEYS {
    if map.contains_key(*key) {
      return Err(AuthError::ValidationFailed(format!(
        "app_metadata must not override reserved key: {key}"
      )));
    }
  }

  Ok(metadata)
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

  #[test]
  fn test_password_policy_requires_minimum_length() {
    assert!(validate_password_policy("short123").is_err());
    assert!(validate_password_policy("long-enough1").is_ok());
  }

  #[test]
  fn test_password_policy_requires_non_letter_character() {
    assert!(validate_password_policy("LettersOnlyPw").is_err());
    assert!(validate_password_policy("LettersOnly1").is_ok());
  }
}
