use axum::Json;
use axum::extract::{
  Query,
  State,
};
use axum::http::HeaderMap;
use chrono::Utc;
use serde::Deserialize;
use uuid::Uuid;

use crate::auth::{
  password,
  session,
};
use crate::error::{
  AuthError,
  Result,
};
use crate::model::{
  RefreshToken,
  TokenGrantResponse,
  TokenResponse,
  User,
};
use crate::public::handler::{
  mfa,
  sso,
};
use crate::state::AppState;

#[derive(Debug, Deserialize)]
pub struct TokenQuery {
  pub grant_type: String,
}

pub async fn token(
  State(state): State<AppState>,
  Query(query): Query<TokenQuery>,
  headers: HeaderMap,
  Json(body): Json<serde_json::Value>,
) -> Result<Json<TokenGrantResponse>> {
  match query.grant_type.as_str() {
    "password" => handle_password_grant(state, body).await.map(Json),
    "refresh_token" => handle_refresh_grant(state, body)
      .await
      .map(|response| Json(TokenGrantResponse::Token(Box::new(response)))),
    "mfa_totp" => handle_mfa_totp_grant(state, headers, body)
      .await
      .map(|response| Json(TokenGrantResponse::Token(Box::new(response)))),
    "oidc_callback" => sso::exchange_callback_code(state, body).await.map(Json),
    _ => Err(AuthError::ValidationFailed(format!(
      "Unsupported grant_type: {}",
      query.grant_type
    ))),
  }
}

async fn handle_password_grant(state: AppState, body: serde_json::Value) -> Result<TokenGrantResponse> {
  let email = body
    .get("email")
    .and_then(|v| v.as_str())
    .ok_or_else(|| AuthError::ValidationFailed("email is required".to_string()))?;
  let pw = body
    .get("password")
    .and_then(|v| v.as_str())
    .ok_or_else(|| AuthError::ValidationFailed("password is required".to_string()))?;

  let Some(user) = sqlx::query_as::<_, User>(
        "SELECT id, instance_id, aud, role, email, encrypted_password, email_confirmed_at, phone, phone_confirmed_at, confirmed_at, last_sign_in_at, raw_app_meta_data, raw_user_meta_data, is_super_admin, is_sso_user, is_anonymous, banned_until, deleted_at, created_at, updated_at FROM auth.users WHERE email = $1"
    )
    .bind(email)
    .fetch_optional(&state.db)
    .await? else {
      password::burn_password_work(pw)?;
      return Err(AuthError::InvalidCredentials);
    };

  if user.deleted_at.is_some() {
    password::burn_password_work(pw)?;
    return Err(AuthError::InvalidCredentials);
  }

  if user.banned_until.map(|value| value > Utc::now()).unwrap_or(false) {
    password::burn_password_work(pw)?;
    return Err(AuthError::InvalidCredentials);
  }

  let Some(hash) = user.encrypted_password.as_deref() else {
    password::burn_password_work(pw)?;
    return Err(AuthError::InvalidCredentials);
  };

  if !password::verify_password(pw, hash)? {
    return Err(AuthError::InvalidCredentials);
  }

  // Require email confirmation when mailer_autoconfirm is disabled
  if !state.mailer_autoconfirm && user.email.is_some() && user.email_confirmed_at.is_none() {
    password::burn_password_work(pw)?;
    return Err(AuthError::InvalidCredentials);
  }

  let factors = mfa::verified_factors_by_user_id(&state.db, user.id).await?;
  if !factors.is_empty() {
    let pending = mfa::create_pending_login(&state, user.id, "password").await?;
    return Ok(TokenGrantResponse::PendingMfa(pending));
  }

  session::issue_session(&state, &user, "password")
    .await
    .map(|response| TokenGrantResponse::Token(Box::new(response)))
}

async fn handle_refresh_grant(state: AppState, body: serde_json::Value) -> Result<TokenResponse> {
  let rt_str = body
    .get("refresh_token")
    .and_then(|v| v.as_str())
    .ok_or_else(|| AuthError::ValidationFailed("refresh_token is required".to_string()))?;

  let now = Utc::now();
  let refresh_expires_after = chrono::Duration::seconds(state.refresh_token_exp);
  let mut tx = state.db.begin().await?;

  let rt: RefreshToken = sqlx::query_as::<_, RefreshToken>(
        "UPDATE auth.refresh_tokens SET revoked = true, updated_at = $1 WHERE token = $2 AND revoked = false AND created_at >= $3 RETURNING id, instance_id, user_id, token, created_at, updated_at, parent, session_id, revoked"
    )
    .bind(now)
    .bind(rt_str)
    .bind(now - refresh_expires_after)
    .fetch_optional(&mut *tx)
    .await?
    .ok_or(AuthError::InvalidToken)?;

  let session_id = rt.session_id.ok_or(AuthError::SessionNotFound)?;
  let user_id_str = rt.user_id.ok_or(AuthError::UserNotFound)?;
  let user_id: Uuid = user_id_str
    .parse()
    .map_err(|_| AuthError::InternalError("Invalid user_id in refresh token".to_string()))?;

  let (session_row, amr) = session::load_session_context(&state, session_id)
    .await
    .map_err(|_| AuthError::SessionNotFound)?;
  if session_row.user_id != user_id {
    return Err(AuthError::InvalidToken);
  }
  if session_row.not_after.map(|value| value <= now).unwrap_or(false) {
    return Err(AuthError::SessionNotFound);
  }

  let user: User = sqlx::query_as::<_, User>(
        "SELECT id, instance_id, aud, role, email, encrypted_password, email_confirmed_at, phone, phone_confirmed_at, confirmed_at, last_sign_in_at, raw_app_meta_data, raw_user_meta_data, is_super_admin, is_sso_user, is_anonymous, banned_until, deleted_at, created_at, updated_at FROM auth.users WHERE id = $1"
    )
    .bind(user_id)
    .fetch_optional(&state.db)
    .await?
    .ok_or(AuthError::UserNotFound)?;

  session::ensure_user_is_active(&user)?;

  // Reject banned users before issuing a new token
  // Perform token rotation atomically: revoke old, insert new, update session.
  let new_refresh_token = session::generate_refresh_token();

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
    .execute(&mut *tx)
    .await?;

  sqlx::query("UPDATE auth.sessions SET refreshed_at = $1, updated_at = $2 WHERE id = $3")
    // refreshed_at is 'timestamp without time zone' in the schema, so use naive_utc()
    .bind(now.naive_utc())
    .bind(now)
    .bind(session_id)
    .execute(&mut *tx)
    .await?;

  tx.commit().await?;

  session::build_token_response(
    &state,
    &user,
    session_id,
    session_row.aal.as_deref().unwrap_or("aal1"),
    amr,
    new_refresh_token,
  )
  .await
}

async fn handle_mfa_totp_grant(
  state: AppState,
  headers: HeaderMap,
  body: serde_json::Value,
) -> Result<TokenResponse> {
  let mfa_token = headers
    .get(axum::http::header::AUTHORIZATION)
    .and_then(|value| value.to_str().ok())
    .and_then(|value| value.strip_prefix("Bearer "))
    .ok_or_else(|| {
      AuthError::ValidationFailed("Authorization header with Bearer MFA token is required".to_string())
    })?;
  let factor_id = body
    .get("factor_id")
    .and_then(|v| v.as_str())
    .ok_or_else(|| AuthError::ValidationFailed("factor_id is required".to_string()))?;
  let factor_id = factor_id
    .parse::<Uuid>()
    .map_err(|_| AuthError::ValidationFailed("factor_id must be a UUID".to_string()))?;
  let code = body
    .get("code")
    .and_then(|v| v.as_str())
    .ok_or_else(|| AuthError::ValidationFailed("code is required".to_string()))?;

  mfa::verify_pending_totp(&state, &headers, mfa_token, factor_id, code).await
}
