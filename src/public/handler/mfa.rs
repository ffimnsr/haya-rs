use std::net::{
  IpAddr,
  SocketAddr,
};

use axum::Json;
use axum::extract::{
  ConnectInfo,
  Path,
  State,
};
use axum::http::HeaderMap;
use chrono::{
  Duration,
  Utc,
};
use serde::Deserialize;
use sqlx::PgPool;
use uuid::Uuid;

use crate::auth::{
  audit,
  mfa,
  session,
};
use crate::error::{
  AuthError,
  Result,
};
use crate::middleware::auth::{
  AuthUser,
  extract_bearer_token_value,
};
use crate::model::{
  MfaEnrollResponse,
  MfaFactorResponse,
  MfaFactorRow,
  PendingMfaResponse,
  TokenResponse,
  User,
};
use crate::state::AppState;
use crate::utils::sha256_hex;

const MFA_PENDING_TTL_MINUTES: i64 = 5;
const MFA_MAX_VERIFY_ATTEMPTS: i32 = 10;
const MFA_ENROLL_MAX_VERIFY_ATTEMPTS: i32 = 10;
const MFA_ENROLL_VERIFY_WINDOW_MINUTES: i64 = 5;
const MFA_MAX_UNVERIFIED_FACTORS_PER_USER: i64 = 10;

#[derive(Debug, Deserialize)]
pub struct CreateTotpFactorRequest {
  pub friendly_name: Option<String>,
  pub issuer: Option<String>,
  pub current_password: Option<String>,
  pub reauthentication_token: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct VerifyTotpCodeRequest {
  pub code: String,
}

#[derive(Debug, Deserialize)]
pub struct PendingMfaFactorsRequest {
  pub mfa_token: Option<String>,
}

#[derive(Debug, sqlx::FromRow)]
struct PendingFlowRow {
  id: Uuid,
  user_id: Option<Uuid>,
  authentication_method: String,
  expires_at: chrono::DateTime<Utc>,
}

#[derive(Debug, sqlx::FromRow)]
struct TotpFactorVerifyStateRow {
  id: Uuid,
  secret: Option<String>,
  last_verified_totp_step: Option<i64>,
  enrollment_verify_attempts: i32,
  last_enrollment_verify_attempt_at: Option<chrono::DateTime<Utc>>,
}

pub async fn list_factors(
  State(state): State<AppState>,
  AuthUser { user, .. }: AuthUser,
) -> Result<Json<Vec<MfaFactorResponse>>> {
  let factors = factors_by_user_id(&state.db, user.id).await?;
  Ok(Json(factors.into_iter().map(Into::into).collect()))
}

pub async fn create_totp_factor(
  State(state): State<AppState>,
  ConnectInfo(client_addr): ConnectInfo<SocketAddr>,
  AuthUser { claims, user }: AuthUser,
  Json(req): Json<CreateTotpFactorRequest>,
) -> Result<Json<MfaEnrollResponse>> {
  let user_id = user.id;
  session::require_reauthentication(
    &state,
    &claims,
    &user,
    client_addr.ip(),
    req.current_password.as_deref(),
    req.reauthentication_token.as_deref(),
  )
  .await?;
  let friendly_name = normalize_friendly_name(req.friendly_name)?;

  ensure_friendly_name_available(&state.db, user_id, friendly_name.as_deref()).await?;
  ensure_unverified_factor_limit_not_reached(&state.db, user_id).await?;

  let raw_secret = mfa::generate_totp_secret();
  let secret = mfa::encode_secret(&raw_secret);
  let encrypted_secret = mfa::encrypt_secret(&raw_secret, &state.mfa_encryption_key)?;
  let account_name = user.email.clone().unwrap_or_else(|| user.id.to_string());
  let issuer = req.issuer.unwrap_or_else(|| state.site_name.clone());
  let uri = mfa::build_otpauth_url(&issuer, &account_name, &secret)?;
  let now = Utc::now();
  let factor_id = Uuid::new_v4();

  sqlx::query(
    "INSERT INTO auth.mfa_factors (id, user_id, friendly_name, factor_type, status, secret, created_at, updated_at) VALUES ($1, $2, $3, 'totp'::auth.factor_type, 'unverified'::auth.factor_status, $4, $5, $6)",
  )
  .bind(factor_id)
  .bind(user_id)
  .bind(&friendly_name)
  .bind(&encrypted_secret)
  .bind(now)
  .bind(now)
  .execute(&state.db)
  .await?;

  audit::log_event(
    &state.db,
    state.instance_id,
    Some(client_addr.ip()),
    "mfa_enrollment_created",
    serde_json::json!({
      "user_id": user_id,
      "factor_id": factor_id,
      "factor_type": "totp",
    }),
  )
  .await?;

  Ok(Json(MfaEnrollResponse {
    id: factor_id,
    friendly_name,
    factor_type: "totp".to_string(),
    status: "unverified".to_string(),
    totp: crate::model::TotpEnrollment { secret, uri },
  }))
}

pub async fn verify_totp_factor(
  State(state): State<AppState>,
  ConnectInfo(client_addr): ConnectInfo<SocketAddr>,
  AuthUser { user, .. }: AuthUser,
  Path(factor_id): Path<Uuid>,
  Json(req): Json<VerifyTotpCodeRequest>,
) -> Result<Json<MfaFactorResponse>> {
  let user_id = user.id;
  let now = Utc::now();
  let mut tx = state.db.begin().await?;
  let factor = factor_verify_state_by_id(tx.as_mut(), factor_id, user_id).await?;
  ensure_enrollment_verify_attempts_available(&factor, now)?;
  let secret = factor
    .secret
    .as_deref()
    .ok_or_else(|| AuthError::InternalError("missing TOTP secret".to_string()))?;
  let decrypted = mfa::decrypt_secret(secret, &state.mfa_encryption_key)?;
  let matched_step = mfa::matching_code_step(&decrypted, &req.code, now.timestamp())?;
  let Some(matched_step) = matched_step else {
    record_failed_enrollment_attempt(tx.as_mut(), factor.id, &factor, now).await?;
    tx.commit().await?;
    return Err(AuthError::ValidationFailed("Invalid TOTP code".to_string()));
  };

  if factor.last_verified_totp_step == Some(matched_step) {
    tx.rollback().await?;
    return Err(AuthError::ValidationFailed(
      "TOTP code has already been used for this factor".to_string(),
    ));
  }

  let verified: MfaFactorRow = sqlx::query_as::<_, MfaFactorRow>(
    "UPDATE auth.mfa_factors SET status = 'verified'::auth.factor_status, last_challenged_at = $1, last_verified_totp_step = $2, enrollment_verify_attempts = 0, last_enrollment_verify_attempt_at = NULL, updated_at = $3 WHERE id = $4 AND user_id = $5 RETURNING id, user_id, friendly_name, factor_type::text as factor_type, status::text as status, secret, created_at, updated_at, last_challenged_at",
  )
  .bind(now)
  .bind(matched_step)
  .bind(now)
  .bind(factor_id)
  .bind(user_id)
  .fetch_one(tx.as_mut())
  .await?;
  tx.commit().await?;

  audit::log_event(
    &state.db,
    state.instance_id,
    Some(client_addr.ip()),
    "mfa_enrollment_verified",
    serde_json::json!({
      "user_id": user_id,
      "factor_id": factor_id,
      "factor_type": "totp",
    }),
  )
  .await?;

  Ok(Json(verified.into()))
}

pub async fn delete_factor(
  State(state): State<AppState>,
  AuthUser { claims, user }: AuthUser,
  Path(factor_id): Path<Uuid>,
) -> Result<Json<serde_json::Value>> {
  let user_id = user.id;
  let factor = factor_by_id(&state.db, factor_id, user_id).await?;

  if factor.status == "verified" && claims.aal != "aal2" {
    return Err(AuthError::NotAuthorized);
  }

  let now = Utc::now();
  let mut tx = state.db.begin().await?;

  sqlx::query("DELETE FROM auth.sessions WHERE factor_id = $1")
    .bind(factor_id)
    .execute(&mut *tx)
    .await?;
  sqlx::query("DELETE FROM auth.mfa_factors WHERE id = $1 AND user_id = $2")
    .bind(factor_id)
    .bind(user_id)
    .execute(&mut *tx)
    .await?;
  sqlx::query("UPDATE auth.users SET updated_at = $1 WHERE id = $2")
    .bind(now)
    .bind(user_id)
    .execute(&mut *tx)
    .await?;

  tx.commit().await?;

  Ok(Json(serde_json::json!({ "id": factor_id })))
}

pub async fn list_pending_factors(
  State(state): State<AppState>,
  headers: HeaderMap,
  Json(req): Json<PendingMfaFactorsRequest>,
) -> Result<Json<Vec<MfaFactorResponse>>> {
  let mfa_token = extract_mfa_token(&headers, &req)?;
  let flow = pending_flow_by_token(&state.db, mfa_token).await?;
  ensure_pending_flow_valid(&flow)?;
  let user_id = flow
    .user_id
    .ok_or_else(|| AuthError::InternalError("pending MFA flow missing user".to_string()))?;
  let factors = verified_factors_by_user_id(&state.db, user_id).await?;

  Ok(Json(factors.into_iter().map(Into::into).collect()))
}

pub async fn create_pending_login(
  state: &AppState,
  user_id: Uuid,
  authentication_method: &str,
) -> Result<PendingMfaResponse> {
  let factors = verified_factors_by_user_id(&state.db, user_id).await?;
  if factors.is_empty() {
    return Err(AuthError::InternalError(
      "no verified TOTP factor available".to_string(),
    ));
  }

  let now = Utc::now();
  let flow_id = Uuid::new_v4();
  let mfa_token = session::generate_refresh_token();
  let mfa_token_hash = sha256_hex(&mfa_token);
  let expires_at = now + Duration::minutes(MFA_PENDING_TTL_MINUTES);

  sqlx::query("DELETE FROM auth.flow_state WHERE user_id = $1 AND provider_type = 'totp'")
    .bind(user_id)
    .execute(&state.db)
    .await?;
  sqlx::query(
    "INSERT INTO auth.flow_state (id, user_id, auth_code, code_challenge_method, code_challenge, provider_type, provider_access_token, provider_refresh_token, authentication_method, created_at, updated_at, factor_id, expires_at, attempts) VALUES ($1, $2, $3, 'plain'::auth.code_challenge_method, $4, 'totp', NULL, NULL, $5, $6, $7, NULL, $8, 0)",
  )
  .bind(flow_id)
  .bind(user_id)
  .bind(&mfa_token_hash)
  .bind("totp")
  .bind(authentication_method)
  .bind(now)
  .bind(now)
  .bind(expires_at)
  .execute(&state.db)
  .await?;

  Ok(PendingMfaResponse {
    mfa_required: true,
    mfa_token,
    factors: factors.into_iter().map(Into::into).collect(),
  })
}

pub async fn verify_pending_totp(
  state: &AppState,
  client_ip: IpAddr,
  user_agent: Option<String>,
  mfa_token: &str,
  factor_id: Uuid,
  code: &str,
) -> Result<TokenResponse> {
  let now = Utc::now();
  let flow = pending_flow_attempt(&state.db, mfa_token, factor_id, now).await?;
  ensure_pending_flow_valid(&flow)?;

  let user_id = flow
    .user_id
    .ok_or_else(|| AuthError::InternalError("pending MFA flow missing user".to_string()))?;
  let factor = verified_factor_verify_state_by_id(&state.db, factor_id, user_id).await?;
  let encrypted_secret = factor
    .secret
    .as_deref()
    .ok_or_else(|| AuthError::InternalError("missing TOTP secret".to_string()))?;
  let decrypted_secret = mfa::decrypt_secret(encrypted_secret, &state.mfa_encryption_key)?;
  let matched_step = mfa::matching_code_step(&decrypted_secret, code, now.timestamp())?;
  let Some(matched_step) = matched_step else {
    return Err(AuthError::ValidationFailed("Invalid TOTP code".to_string()));
  };
  if factor.last_verified_totp_step == Some(matched_step) {
    return Err(AuthError::ValidationFailed(
      "TOTP code has already been used for this factor".to_string(),
    ));
  }
  let challenge_id = Uuid::new_v4();
  let ip_address = client_ip;

  sqlx::query(
    "INSERT INTO auth.mfa_challenges (id, factor_id, created_at, verified_at, ip_address, otp_code) VALUES ($1, $2, $3, NULL, $4::inet, NULL)",
  )
  .bind(challenge_id)
  .bind(factor_id)
  .bind(now)
  .bind(ip_address.to_string())
  .execute(&state.db)
  .await?;

  sqlx::query("UPDATE auth.mfa_challenges SET verified_at = $1 WHERE id = $2")
    .bind(now)
    .bind(challenge_id)
    .execute(&state.db)
    .await?;
  sqlx::query(
    "UPDATE auth.mfa_factors SET last_challenged_at = $1, last_verified_totp_step = $2, updated_at = $3 WHERE id = $4",
  )
    .bind(now)
    .bind(matched_step)
    .bind(now)
    .bind(factor_id)
    .execute(&state.db)
    .await?;

  let user = fetch_user(&state.db, user_id).await?;
  let response = session::issue_session_with_client_context(
    state,
    &user,
    "aal2",
    Some(factor_id),
    vec![flow.authentication_method, "totp".to_string()],
    session::ClientContext {
      user_agent,
      ip: Some(client_ip),
    },
  )
  .await?;

  sqlx::query("DELETE FROM auth.flow_state WHERE id = $1")
    .bind(flow.id)
    .execute(&state.db)
    .await?;

  Ok(response)
}

pub async fn verified_factors_by_user_id(db: &PgPool, user_id: Uuid) -> Result<Vec<MfaFactorRow>> {
  let factors = sqlx::query_as::<_, MfaFactorRow>(
    "SELECT id, user_id, friendly_name, factor_type::text as factor_type, status::text as status, secret, created_at, updated_at, last_challenged_at FROM auth.mfa_factors WHERE user_id = $1 AND factor_type = 'totp'::auth.factor_type AND status = 'verified'::auth.factor_status ORDER BY created_at ASC",
  )
  .bind(user_id)
  .fetch_all(db)
  .await?;

  Ok(factors)
}

async fn factors_by_user_id(db: &PgPool, user_id: Uuid) -> Result<Vec<MfaFactorRow>> {
  let factors = sqlx::query_as::<_, MfaFactorRow>(
    "SELECT id, user_id, friendly_name, factor_type::text as factor_type, status::text as status, secret, created_at, updated_at, last_challenged_at FROM auth.mfa_factors WHERE user_id = $1 AND factor_type = 'totp'::auth.factor_type ORDER BY created_at ASC",
  )
  .bind(user_id)
  .fetch_all(db)
  .await?;

  Ok(factors)
}

async fn ensure_unverified_factor_limit_not_reached(db: &PgPool, user_id: Uuid) -> Result<()> {
  let (count,): (i64,) = sqlx::query_as(
    "SELECT COUNT(*) FROM auth.mfa_factors WHERE user_id = $1 AND factor_type = 'totp'::auth.factor_type AND status = 'unverified'::auth.factor_status",
  )
  .bind(user_id)
  .fetch_one(db)
  .await?;

  if count >= MFA_MAX_UNVERIFIED_FACTORS_PER_USER {
    return Err(AuthError::ValidationFailed(format!(
      "Too many unverified TOTP factors. Remove an existing unverified factor before creating another (limit: {MFA_MAX_UNVERIFIED_FACTORS_PER_USER})."
    )));
  }

  Ok(())
}

async fn factor_by_id(db: &PgPool, factor_id: Uuid, user_id: Uuid) -> Result<MfaFactorRow> {
  sqlx::query_as::<_, MfaFactorRow>(
    "SELECT id, user_id, friendly_name, factor_type::text as factor_type, status::text as status, secret, created_at, updated_at, last_challenged_at FROM auth.mfa_factors WHERE id = $1 AND user_id = $2 AND factor_type = 'totp'::auth.factor_type",
  )
  .bind(factor_id)
  .bind(user_id)
  .fetch_optional(db)
  .await?
  .ok_or(AuthError::UserNotFound)
}

async fn verified_factor_verify_state_by_id(
  db: &PgPool,
  factor_id: Uuid,
  user_id: Uuid,
) -> Result<TotpFactorVerifyStateRow> {
  sqlx::query_as::<_, TotpFactorVerifyStateRow>(
    "SELECT id, secret, last_verified_totp_step, enrollment_verify_attempts, last_enrollment_verify_attempt_at FROM auth.mfa_factors WHERE id = $1 AND user_id = $2 AND factor_type = 'totp'::auth.factor_type AND status = 'verified'::auth.factor_status",
  )
  .bind(factor_id)
  .bind(user_id)
  .fetch_optional(db)
  .await?
  .ok_or(AuthError::NotAuthorized)
}

async fn factor_verify_state_by_id(
  db: &mut sqlx::PgConnection,
  factor_id: Uuid,
  user_id: Uuid,
) -> Result<TotpFactorVerifyStateRow> {
  sqlx::query_as::<_, TotpFactorVerifyStateRow>(
    "SELECT id, secret, last_verified_totp_step, enrollment_verify_attempts, last_enrollment_verify_attempt_at FROM auth.mfa_factors WHERE id = $1 AND user_id = $2 AND factor_type = 'totp'::auth.factor_type FOR UPDATE",
  )
  .bind(factor_id)
  .bind(user_id)
  .fetch_optional(db)
  .await?
  .ok_or(AuthError::UserNotFound)
}

async fn fetch_user(db: &PgPool, user_id: Uuid) -> Result<User> {
  sqlx::query_as::<_, User>(
    "SELECT id, instance_id, aud, role, email, encrypted_password, email_confirmed_at, phone, phone_confirmed_at, confirmed_at, last_sign_in_at, raw_app_meta_data, raw_user_meta_data, is_super_admin, is_sso_user, is_anonymous, banned_until, deleted_at, created_at, updated_at FROM auth.users WHERE id = $1",
  )
  .bind(user_id)
  .fetch_optional(db)
  .await?
  .ok_or(AuthError::UserNotFound)
}

async fn pending_flow_by_token(db: &PgPool, token: &str) -> Result<PendingFlowRow> {
  sqlx::query_as::<_, PendingFlowRow>(
    "SELECT id, user_id, authentication_method, expires_at FROM auth.flow_state WHERE auth_code = $1 AND provider_type = 'totp'",
  )
  .bind(sha256_hex(token))
  .fetch_optional(db)
  .await?
  .ok_or(AuthError::InvalidToken)
}

async fn pending_flow_attempt(
  db: &PgPool,
  token: &str,
  factor_id: Uuid,
  now: chrono::DateTime<Utc>,
) -> Result<PendingFlowRow> {
  if let Some(flow) = sqlx::query_as::<_, PendingFlowRow>(
    "UPDATE auth.flow_state SET factor_id = $1, attempts = attempts + 1, updated_at = $2 WHERE auth_code = $3 AND provider_type = 'totp' AND expires_at >= $2 AND attempts < $4 RETURNING id, user_id, authentication_method, expires_at",
  )
  .bind(factor_id)
  .bind(now)
  .bind(sha256_hex(token))
  .bind(MFA_MAX_VERIFY_ATTEMPTS)
  .fetch_optional(db)
  .await?
  {
    return Ok(flow);
  }

  let flow = pending_flow_by_token(db, token).await?;
  ensure_pending_flow_valid(&flow)?;
  sqlx::query("DELETE FROM auth.flow_state WHERE id = $1 AND attempts >= $2")
    .bind(flow.id)
    .bind(MFA_MAX_VERIFY_ATTEMPTS)
    .execute(db)
    .await?;
  Err(AuthError::NotAuthorized)
}

fn ensure_pending_flow_valid(flow: &PendingFlowRow) -> Result<()> {
  if flow.expires_at < Utc::now() {
    return Err(AuthError::TokenExpired);
  }

  Ok(())
}

async fn ensure_friendly_name_available(
  db: &PgPool,
  user_id: Uuid,
  friendly_name: Option<&str>,
) -> Result<()> {
  let Some(name) = friendly_name else {
    return Ok(());
  };
  let existing: Option<(Uuid,)> =
    sqlx::query_as::<_, (Uuid,)>("SELECT id FROM auth.mfa_factors WHERE user_id = $1 AND friendly_name = $2")
      .bind(user_id)
      .bind(name)
      .fetch_optional(db)
      .await?;

  if existing.is_some() {
    return Err(AuthError::ValidationFailed(
      "Factor friendly name is already in use".to_string(),
    ));
  }

  Ok(())
}

fn normalize_friendly_name(value: Option<String>) -> Result<Option<String>> {
  match value {
    Some(name) => {
      let trimmed = name.trim().to_string();
      if trimmed.is_empty() {
        Ok(None)
      } else if trimmed.len() > 255 {
        Err(AuthError::ValidationFailed(
          "Factor friendly name must not exceed 255 characters".to_string(),
        ))
      } else {
        Ok(Some(trimmed))
      }
    },
    None => Ok(None),
  }
}

fn current_enrollment_attempts(factor: &TotpFactorVerifyStateRow, now: chrono::DateTime<Utc>) -> i32 {
  let window_start = now - Duration::minutes(MFA_ENROLL_VERIFY_WINDOW_MINUTES);
  if factor
    .last_enrollment_verify_attempt_at
    .is_some_and(|last_attempt| last_attempt >= window_start)
  {
    factor.enrollment_verify_attempts
  } else {
    0
  }
}

fn ensure_enrollment_verify_attempts_available(
  factor: &TotpFactorVerifyStateRow,
  now: chrono::DateTime<Utc>,
) -> Result<()> {
  if current_enrollment_attempts(factor, now) >= MFA_ENROLL_MAX_VERIFY_ATTEMPTS {
    return Err(AuthError::ValidationFailed(
      "Too many TOTP verification attempts. Please wait before retrying.".to_string(),
    ));
  }

  Ok(())
}

async fn record_failed_enrollment_attempt(
  db: &mut sqlx::PgConnection,
  factor_id: Uuid,
  factor: &TotpFactorVerifyStateRow,
  now: chrono::DateTime<Utc>,
) -> Result<()> {
  let attempts = current_enrollment_attempts(factor, now) + 1;
  sqlx::query(
    "UPDATE auth.mfa_factors SET enrollment_verify_attempts = $1, last_enrollment_verify_attempt_at = $2, updated_at = $3 WHERE id = $4",
  )
  .bind(attempts)
  .bind(now)
  .bind(now)
  .bind(factor_id)
  .execute(db)
  .await?;
  Ok(())
}

fn extract_mfa_token<'a>(headers: &'a HeaderMap, req: &'a PendingMfaFactorsRequest) -> Result<&'a str> {
  if let Some(value) = headers
    .get(axum::http::header::AUTHORIZATION)
    .and_then(|value| value.to_str().ok())
    .and_then(extract_bearer_token_value)
  {
    return Ok(value);
  }

  if req
    .mfa_token
    .as_deref()
    .is_some_and(|value| !value.trim().is_empty())
  {
    return Err(AuthError::ValidationFailed(
      "mfa_token must be sent in the Authorization header".to_string(),
    ));
  }

  Err(AuthError::ValidationFailed(
    "Authorization header with Bearer MFA token is required".to_string(),
  ))
}

#[cfg(test)]
mod tests {
  use super::*;

  fn sample_factor_state() -> TotpFactorVerifyStateRow {
    TotpFactorVerifyStateRow {
      id: Uuid::new_v4(),
      secret: Some("secret".to_string()),
      last_verified_totp_step: None,
      enrollment_verify_attempts: 0,
      last_enrollment_verify_attempt_at: None,
    }
  }

  #[test]
  fn enrollment_attempts_reset_outside_window() {
    let mut factor = sample_factor_state();
    let now = Utc::now();
    factor.enrollment_verify_attempts = MFA_ENROLL_MAX_VERIFY_ATTEMPTS;
    factor.last_enrollment_verify_attempt_at =
      Some(now - Duration::minutes(MFA_ENROLL_VERIFY_WINDOW_MINUTES + 1));

    assert_eq!(current_enrollment_attempts(&factor, now), 0);
  }

  #[test]
  fn enrollment_attempts_block_within_window() {
    let mut factor = sample_factor_state();
    let now = Utc::now();
    factor.enrollment_verify_attempts = MFA_ENROLL_MAX_VERIFY_ATTEMPTS;
    factor.last_enrollment_verify_attempt_at = Some(now);

    assert!(ensure_enrollment_verify_attempts_available(&factor, now).is_err());
  }
}
