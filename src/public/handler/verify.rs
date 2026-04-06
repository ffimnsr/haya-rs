use axum::Json;
use axum::extract::{
  ConnectInfo,
  State,
};
use chrono::Utc;
use serde::Deserialize;
use sha2::{
  Digest,
  Sha256,
};
use std::net::{
  IpAddr,
  SocketAddr,
};

use crate::auth::{
  rate_limit,
  session,
};
use crate::error::{
  AuthError,
  Result,
};
use crate::model::{
  User,
  UserResponse,
  VerifyGrantResponse,
};
use crate::public::handler::mfa;
use crate::state::AppState;

const VERIFY_RATE_LIMIT_WINDOW_SECS: u64 = 900;
const VERIFY_RATE_LIMIT_ATTEMPTS: u32 = 10;

#[derive(Debug, Deserialize)]
pub struct VerifyRequest {
  #[serde(rename = "type")]
  pub verify_type: String,
  pub token: String,
  // Used for additional verification in some flows
  #[allow(dead_code)]
  pub email: Option<String>,
}

pub async fn verify(
  State(state): State<AppState>,
  ConnectInfo(client_addr): ConnectInfo<SocketAddr>,
  Json(req): Json<VerifyRequest>,
) -> Result<Json<VerifyGrantResponse>> {
  let client_ip = client_addr.ip();
  match req.verify_type.as_str() {
    "signup" => handle_signup_verify(state, client_ip, req).await,
    "recovery" => handle_recovery_verify(state, client_ip, req).await,
    "magiclink" => handle_magiclink_verify(state, client_ip, req).await,
    _ => Err(AuthError::ValidationFailed(format!(
      "Unsupported verify type: {}",
      req.verify_type
    ))),
  }
}

async fn handle_signup_verify(
  state: AppState,
  client_ip: IpAddr,
  req: VerifyRequest,
) -> Result<Json<VerifyGrantResponse>> {
  let user = consume_confirmation_token(&state, &req.token, client_ip, Utc::now()).await?;
  let user_response = UserResponse::from_user(&state.db, user).await?;
  Ok(Json(VerifyGrantResponse::User(Box::new(user_response))))
}

async fn handle_recovery_verify(
  state: AppState,
  client_ip: IpAddr,
  req: VerifyRequest,
) -> Result<Json<VerifyGrantResponse>> {
  let user = consume_recovery_token(&state, &req.token, client_ip, Utc::now()).await?;
  session::ensure_user_is_active(&user)?;

  let factors = mfa::verified_factors_by_user_id(&state.db, user.id).await?;
  if !factors.is_empty() {
    let pending = mfa::create_pending_login(&state, user.id, "recovery").await?;
    return Ok(Json(VerifyGrantResponse::PendingMfa(pending)));
  }

  let response =
    session::issue_session_with_context(&state, &user, "aal1", None, vec!["recovery".to_string()]).await?;
  Ok(Json(VerifyGrantResponse::Token(Box::new(response))))
}

async fn handle_magiclink_verify(
  state: AppState,
  client_ip: IpAddr,
  req: VerifyRequest,
) -> Result<Json<VerifyGrantResponse>> {
  let user = consume_magic_link_token(&state, &req.token, client_ip, Utc::now()).await?;
  session::ensure_user_is_active(&user)?;

  let factors = mfa::verified_factors_by_user_id(&state.db, user.id).await?;
  if !factors.is_empty() {
    let pending = mfa::create_pending_login(&state, user.id, "magiclink").await?;
    return Ok(Json(VerifyGrantResponse::PendingMfa(pending)));
  }

  let response =
    session::issue_session_with_context(&state, &user, "aal1", None, vec!["magiclink".to_string()]).await?;
  Ok(Json(VerifyGrantResponse::Token(Box::new(response))))
}

async fn consume_confirmation_token(
  state: &AppState,
  token: &str,
  client_ip: IpAddr,
  now: chrono::DateTime<Utc>,
) -> Result<User> {
  let rate_limit_key = verify_rate_limit_key("confirmation", token, client_ip);
  let ip_rate_limit_key = verify_ip_rate_limit_key("confirmation", client_ip);
  if rate_limit::is_limited(&state.db, &rate_limit_key, VERIFY_RATE_LIMIT_ATTEMPTS).await?
    || rate_limit::is_limited(&state.db, &ip_rate_limit_key, VERIFY_RATE_LIMIT_ATTEMPTS * 3).await?
  {
    return Err(AuthError::TooManyRequests);
  }
  let user = sqlx::query_as::<_, User>(
        "UPDATE auth.users SET email_confirmed_at = COALESCE(email_confirmed_at, $1), confirmation_token = NULL, updated_at = $1 WHERE confirmation_token = $2 AND confirmation_sent_at > NOW() - INTERVAL '24 hours' RETURNING id, instance_id, aud, role, email, encrypted_password, email_confirmed_at, phone, phone_confirmed_at, COALESCE(confirmed_at, email_confirmed_at, phone_confirmed_at) as confirmed_at, last_sign_in_at, raw_app_meta_data, raw_user_meta_data, is_super_admin, is_sso_user, is_anonymous, banned_until, deleted_at, created_at, updated_at"
    )
    .bind(now)
    .bind(token)
    .fetch_optional(&state.db)
    .await?;
  let Some(user) = user else {
    rate_limit::record_failure(&state.db, &rate_limit_key, VERIFY_RATE_LIMIT_WINDOW_SECS as i64).await?;
    rate_limit::record_failure(
      &state.db,
      &ip_rate_limit_key,
      VERIFY_RATE_LIMIT_WINDOW_SECS as i64,
    )
    .await?;
    return Err(AuthError::InvalidToken);
  };
  rate_limit::clear(&state.db, &rate_limit_key).await?;
  Ok(user)
}

async fn consume_recovery_token(
  state: &AppState,
  token: &str,
  client_ip: IpAddr,
  now: chrono::DateTime<Utc>,
) -> Result<User> {
  let rate_limit_key = verify_rate_limit_key("recovery", token, client_ip);
  let ip_rate_limit_key = verify_ip_rate_limit_key("recovery", client_ip);
  if rate_limit::is_limited(&state.db, &rate_limit_key, VERIFY_RATE_LIMIT_ATTEMPTS).await?
    || rate_limit::is_limited(&state.db, &ip_rate_limit_key, VERIFY_RATE_LIMIT_ATTEMPTS * 3).await?
  {
    return Err(AuthError::TooManyRequests);
  }
  let user = sqlx::query_as::<_, User>(
        "UPDATE auth.users SET recovery_token = NULL, updated_at = $1 WHERE recovery_token = $2 AND recovery_sent_at > NOW() - INTERVAL '1 hour' RETURNING id, instance_id, aud, role, email, encrypted_password, email_confirmed_at, phone, phone_confirmed_at, COALESCE(confirmed_at, email_confirmed_at, phone_confirmed_at) as confirmed_at, last_sign_in_at, raw_app_meta_data, raw_user_meta_data, is_super_admin, is_sso_user, is_anonymous, banned_until, deleted_at, created_at, updated_at"
    )
    .bind(now)
    .bind(token)
    .fetch_optional(&state.db)
    .await?;
  let Some(user) = user else {
    rate_limit::record_failure(&state.db, &rate_limit_key, VERIFY_RATE_LIMIT_WINDOW_SECS as i64).await?;
    rate_limit::record_failure(
      &state.db,
      &ip_rate_limit_key,
      VERIFY_RATE_LIMIT_WINDOW_SECS as i64,
    )
    .await?;
    return Err(AuthError::InvalidToken);
  };
  rate_limit::clear(&state.db, &rate_limit_key).await?;
  Ok(user)
}

async fn consume_magic_link_token(
  state: &AppState,
  token: &str,
  client_ip: IpAddr,
  now: chrono::DateTime<Utc>,
) -> Result<User> {
  let rate_limit_key = verify_rate_limit_key("magiclink", token, client_ip);
  let ip_rate_limit_key = verify_ip_rate_limit_key("magiclink", client_ip);
  if rate_limit::is_limited(&state.db, &rate_limit_key, VERIFY_RATE_LIMIT_ATTEMPTS).await?
    || rate_limit::is_limited(&state.db, &ip_rate_limit_key, VERIFY_RATE_LIMIT_ATTEMPTS * 3).await?
  {
    return Err(AuthError::TooManyRequests);
  }
  let user = sqlx::query_as::<_, User>(
        "UPDATE auth.users SET email_confirmed_at = COALESCE(email_confirmed_at, $1), magic_link_token = NULL, magic_link_sent_at = NULL, updated_at = $1 WHERE magic_link_token = $2 AND magic_link_sent_at > NOW() - INTERVAL '24 hours' RETURNING id, instance_id, aud, role, email, encrypted_password, email_confirmed_at, phone, phone_confirmed_at, COALESCE(confirmed_at, email_confirmed_at, phone_confirmed_at) as confirmed_at, last_sign_in_at, raw_app_meta_data, raw_user_meta_data, is_super_admin, is_sso_user, is_anonymous, banned_until, deleted_at, created_at, updated_at"
    )
    .bind(now)
    .bind(token)
    .fetch_optional(&state.db)
    .await?;
  let Some(user) = user else {
    rate_limit::record_failure(&state.db, &rate_limit_key, VERIFY_RATE_LIMIT_WINDOW_SECS as i64).await?;
    rate_limit::record_failure(
      &state.db,
      &ip_rate_limit_key,
      VERIFY_RATE_LIMIT_WINDOW_SECS as i64,
    )
    .await?;
    return Err(AuthError::InvalidToken);
  };
  rate_limit::clear(&state.db, &rate_limit_key).await?;
  Ok(user)
}

fn verify_rate_limit_key(prefix: &str, token: &str, client_ip: IpAddr) -> String {
  let digest = Sha256::digest(token.as_bytes());
  format!("{prefix}:{client_ip}:{digest:x}")
}

fn verify_ip_rate_limit_key(prefix: &str, client_ip: IpAddr) -> String {
  format!("{prefix}-ip:{client_ip}")
}
