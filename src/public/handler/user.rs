use axum::Json;
use axum::extract::State;
use chrono::Utc;
use serde::Deserialize;
use uuid::Uuid;

use crate::auth::password;
use crate::error::{
  AuthError,
  Result,
};
use crate::middleware::auth::AuthUser;
use crate::model::{
  MfaFactorRow,
  User,
  UserResponse,
};
use crate::state::AppState;

pub async fn get_user(
  State(state): State<AppState>,
  AuthUser(claims): AuthUser,
) -> Result<Json<UserResponse>> {
  let user_id: Uuid = claims
    .sub
    .parse()
    .map_err(|_| AuthError::InternalError("Invalid user_id in token".to_string()))?;

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
pub struct UpdateUserRequest {
  pub email: Option<String>,
  pub password: Option<String>,
  pub phone: Option<String>,
  pub data: Option<serde_json::Value>,
  pub current_password: Option<String>,
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
  let user: User = sqlx::query_as::<_, User>(
    "SELECT id, instance_id, aud, role, email, encrypted_password, email_confirmed_at, phone, phone_confirmed_at, confirmed_at, last_sign_in_at, raw_app_meta_data, raw_user_meta_data, is_super_admin, is_sso_user, is_anonymous, banned_until, deleted_at, created_at, updated_at FROM auth.users WHERE id = $1",
  )
  .bind(user_id)
  .fetch_optional(&state.db)
  .await?
  .ok_or(AuthError::UserNotFound)?;

  let now = Utc::now();
  let changing_sensitive_fields = req.password.is_some() || req.email.is_some() || req.phone.is_some();

  if changing_sensitive_fields {
    require_sensitive_change_reauth(&state, &claims, &user, req.current_password.as_deref()).await?;
  }

  let mut tx = state.db.begin().await?;

  if let Some(ref pw) = req.password {
    if pw.len() < 6 {
      return Err(AuthError::ValidationFailed(
        "Password must be at least 6 characters.".to_string(),
      ));
    }
    if pw.len() > 128 {
      return Err(AuthError::ValidationFailed(
        "Password must not exceed 128 characters.".to_string(),
      ));
    }
    let hashed = password::hash_password(pw)?;
    sqlx::query("UPDATE auth.users SET encrypted_password = $1, updated_at = $2 WHERE id = $3")
      .bind(hashed)
      .bind(now)
      .bind(user_id)
      .execute(&mut *tx)
      .await?;
  }

  if let Some(ref meta) = req.data {
    sqlx::query("UPDATE auth.users SET raw_user_meta_data = $1, updated_at = $2 WHERE id = $3")
      .bind(meta)
      .bind(now)
      .bind(user_id)
      .execute(&mut *tx)
      .await?;
  }

  if let Some(ref email) = req.email {
    // Validate email format
    if !crate::public::handler::signup::is_valid_email(email) {
      return Err(AuthError::ValidationFailed("Invalid email format".to_string()));
    }
    // Check if email is already in use by another user
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
    // Clear email_confirmed_at since the email has changed (requires re-confirmation)
    sqlx::query("UPDATE auth.users SET email = $1, email_confirmed_at = NULL, updated_at = $2 WHERE id = $3")
      .bind(email)
      .bind(now)
      .bind(user_id)
      .execute(&mut *tx)
      .await?;
  }

  if let Some(ref phone) = req.phone {
    // Clear phone_confirmed_at since the phone number has changed (requires re-verification)
    sqlx::query("UPDATE auth.users SET phone = $1, phone_confirmed_at = NULL, updated_at = $2 WHERE id = $3")
      .bind(phone)
      .bind(now)
      .bind(user_id)
      .execute(&mut *tx)
      .await?;
  }

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

async fn require_sensitive_change_reauth(
  state: &AppState,
  claims: &crate::auth::jwt::Claims,
  user: &User,
  current_password: Option<&str>,
) -> Result<()> {
  let has_verified_mfa = sqlx::query_as::<_, MfaFactorRow>(
    "SELECT id, user_id, friendly_name, factor_type::text as factor_type, status::text as status, secret, created_at, updated_at, last_challenged_at FROM auth.mfa_factors WHERE user_id = $1 AND status = 'verified'::auth.factor_status LIMIT 1",
  )
  .bind(user.id)
  .fetch_optional(&state.db)
  .await?
  .is_some();

  if has_verified_mfa && claims.aal != "aal2" {
    return Err(AuthError::NotAuthorized);
  }

  if let Some(hash) = user.encrypted_password.as_deref() {
    let current_password = current_password
      .ok_or_else(|| AuthError::ValidationFailed("current_password is required".to_string()))?;
    if !password::verify_password(current_password, hash)? {
      return Err(AuthError::InvalidCredentials);
    }
  } else if !has_verified_mfa {
    return Err(AuthError::NotAuthorized);
  }

  Ok(())
}
