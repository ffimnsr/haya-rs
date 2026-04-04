use std::net::{
  IpAddr,
  Ipv4Addr,
};

use axum::Json;
use axum::extract::{
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
  jwt,
  mfa,
  session,
};
use crate::error::{
  AuthError,
  Result,
};
use crate::middleware::auth::AuthUser;
use crate::model::{
  MfaEnrollResponse,
  MfaFactorResponse,
  MfaFactorRow,
  PendingMfaResponse,
  TokenResponse,
  User,
};
use crate::state::AppState;

const MFA_PENDING_TTL_MINUTES: i64 = 5;
const MFA_MAX_VERIFY_ATTEMPTS: i32 = 10;

#[derive(Debug, Deserialize)]
pub struct CreateTotpFactorRequest {
  pub friendly_name: Option<String>,
  pub issuer: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct VerifyTotpCodeRequest {
  pub code: String,
}

#[derive(Debug, Deserialize)]
pub struct PendingMfaFactorsRequest {
  pub mfa_token: String,
}

#[derive(Debug, sqlx::FromRow)]
struct PendingFlowRow {
  id: Uuid,
  user_id: Option<Uuid>,
  authentication_method: String,
  expires_at: chrono::DateTime<Utc>,
}

pub async fn list_factors(
  State(state): State<AppState>,
  AuthUser(claims): AuthUser,
) -> Result<Json<Vec<MfaFactorResponse>>> {
  let user_id = user_id_from_claims(&claims)?;
  let factors = factors_by_user_id(&state.db, user_id).await?;
  Ok(Json(factors.into_iter().map(Into::into).collect()))
}

pub async fn create_totp_factor(
  State(state): State<AppState>,
  AuthUser(claims): AuthUser,
  Json(req): Json<CreateTotpFactorRequest>,
) -> Result<Json<MfaEnrollResponse>> {
  let user_id = user_id_from_claims(&claims)?;
  let user = fetch_user(&state.db, user_id).await?;
  let friendly_name = normalize_friendly_name(req.friendly_name)?;

  ensure_friendly_name_available(&state.db, user_id, friendly_name.as_deref()).await?;

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
  AuthUser(claims): AuthUser,
  Path(factor_id): Path<Uuid>,
  Json(req): Json<VerifyTotpCodeRequest>,
) -> Result<Json<MfaFactorResponse>> {
  let user_id = user_id_from_claims(&claims)?;
  let factor = factor_by_id(&state.db, factor_id, user_id).await?;
  let secret = factor
    .secret
    .as_deref()
    .ok_or_else(|| AuthError::InternalError("missing TOTP secret".to_string()))?;
  let decrypted = mfa::decrypt_secret(secret, &state.mfa_encryption_key)?;
  let now = Utc::now();

  if !mfa::verify_code(&decrypted, &req.code, now.timestamp())? {
    return Err(AuthError::ValidationFailed("Invalid TOTP code".to_string()));
  }

  let verified: MfaFactorRow = sqlx::query_as::<_, MfaFactorRow>(
    "UPDATE auth.mfa_factors SET status = 'verified'::auth.factor_status, last_challenged_at = $1, updated_at = $2 WHERE id = $3 AND user_id = $4 RETURNING id, user_id, friendly_name, factor_type::text as factor_type, status::text as status, secret, created_at, updated_at, last_challenged_at",
  )
  .bind(now)
  .bind(now)
  .bind(factor_id)
  .bind(user_id)
  .fetch_one(&state.db)
  .await?;

  Ok(Json(verified.into()))
}

pub async fn delete_factor(
  State(state): State<AppState>,
  AuthUser(claims): AuthUser,
  Path(factor_id): Path<Uuid>,
) -> Result<Json<serde_json::Value>> {
  let user_id = user_id_from_claims(&claims)?;
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
  .bind(&mfa_token)
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
  headers: &HeaderMap,
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
  let factor = verified_factor_by_id(&state.db, factor_id, user_id).await?;
  let encrypted_secret = factor
    .secret
    .as_deref()
    .ok_or_else(|| AuthError::InternalError("missing TOTP secret".to_string()))?;
  let decrypted_secret = mfa::decrypt_secret(encrypted_secret, &state.mfa_encryption_key)?;
  let challenge_id = Uuid::new_v4();
  let ip_address = client_ip(headers);

  sqlx::query(
    "INSERT INTO auth.mfa_challenges (id, factor_id, created_at, verified_at, ip_address, otp_code) VALUES ($1, $2, $3, NULL, $4::inet, NULL)",
  )
  .bind(challenge_id)
  .bind(factor_id)
  .bind(now)
  .bind(ip_address.to_string())
  .execute(&state.db)
  .await?;

  if !mfa::verify_code(&decrypted_secret, code, now.timestamp())? {
    return Err(AuthError::ValidationFailed("Invalid TOTP code".to_string()));
  }

  sqlx::query("UPDATE auth.mfa_challenges SET verified_at = $1 WHERE id = $2")
    .bind(now)
    .bind(challenge_id)
    .execute(&state.db)
    .await?;
  sqlx::query("UPDATE auth.mfa_factors SET last_challenged_at = $1, updated_at = $2 WHERE id = $3")
    .bind(now)
    .bind(now)
    .bind(factor_id)
    .execute(&state.db)
    .await?;

  let user = fetch_user(&state.db, user_id).await?;
  let response = session::issue_session_with_context(
    state,
    &user,
    "aal2",
    Some(factor_id),
    vec![flow.authentication_method, "totp".to_string()],
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

fn user_id_from_claims(claims: &jwt::Claims) -> Result<Uuid> {
  claims
    .sub
    .parse()
    .map_err(|_| AuthError::InternalError("Invalid user_id in token".to_string()))
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

async fn verified_factor_by_id(db: &PgPool, factor_id: Uuid, user_id: Uuid) -> Result<MfaFactorRow> {
  sqlx::query_as::<_, MfaFactorRow>(
    "SELECT id, user_id, friendly_name, factor_type::text as factor_type, status::text as status, secret, created_at, updated_at, last_challenged_at FROM auth.mfa_factors WHERE id = $1 AND user_id = $2 AND factor_type = 'totp'::auth.factor_type AND status = 'verified'::auth.factor_status",
  )
  .bind(factor_id)
  .bind(user_id)
  .fetch_optional(db)
  .await?
  .ok_or(AuthError::NotAuthorized)
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
  .bind(token)
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
  .bind(token)
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

fn client_ip(headers: &HeaderMap) -> IpAddr {
  headers
    .get("x-forwarded-for")
    .and_then(|value| value.to_str().ok())
    .and_then(|value| value.split(',').next())
    .or_else(|| headers.get("x-real-ip").and_then(|value| value.to_str().ok()))
    .and_then(|value| value.trim().parse::<IpAddr>().ok())
    .unwrap_or(IpAddr::V4(Ipv4Addr::UNSPECIFIED))
}

fn extract_mfa_token<'a>(headers: &'a HeaderMap, req: &'a PendingMfaFactorsRequest) -> Result<&'a str> {
  if let Some(value) = headers
    .get(axum::http::header::AUTHORIZATION)
    .and_then(|value| value.to_str().ok())
    .and_then(|value| value.strip_prefix("Bearer "))
  {
    return Ok(value);
  }

  if req.mfa_token.trim().is_empty() {
    return Err(AuthError::ValidationFailed("mfa_token is required".to_string()));
  }

  Ok(req.mfa_token.as_str())
}
