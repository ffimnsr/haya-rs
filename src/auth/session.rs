use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use chrono::{
  DateTime,
  Duration,
  Utc,
};
use rand::RngCore;
use std::net::IpAddr;
use uuid::Uuid;

use crate::auth::{
  jwt,
  password,
  rate_limit,
};
use crate::error::{
  AuthError,
  Result,
};
use crate::mailer::EmailKind;
use crate::model::{
  MfaFactorRow,
  SessionAmrClaimRow,
  SessionRow,
  TokenResponse,
  User,
  UserResponse,
};
use crate::state::AppState;
use crate::utils::sha256_hex;

const REAUTHENTICATION_TTL_MINUTES: i64 = 10;
const REAUTHENTICATION_RATE_LIMIT_WINDOW_SECS: u64 = 900;
const REAUTHENTICATION_RATE_LIMIT_ATTEMPTS: u32 = 10;

#[derive(Debug, Clone, Default)]
pub struct ClientContext {
  pub user_agent: Option<String>,
  pub ip: Option<IpAddr>,
}

pub async fn issue_session(state: &AppState, user: &User, method: &str) -> Result<TokenResponse> {
  issue_session_with_client_context(
    state,
    user,
    "aal1",
    None,
    vec![method.to_string()],
    ClientContext::default(),
  )
  .await
}

pub async fn issue_session_for_client(
  state: &AppState,
  user: &User,
  method: &str,
  client_context: ClientContext,
) -> Result<TokenResponse> {
  issue_session_with_client_context(
    state,
    user,
    "aal1",
    None,
    vec![method.to_string()],
    client_context,
  )
  .await
}

pub async fn issue_session_with_context(
  state: &AppState,
  user: &User,
  aal: &str,
  factor_id: Option<Uuid>,
  methods: Vec<String>,
) -> Result<TokenResponse> {
  issue_session_with_client_context(state, user, aal, factor_id, methods, ClientContext::default()).await
}

pub async fn issue_session_with_client_context(
  state: &AppState,
  user: &User,
  aal: &str,
  factor_id: Option<Uuid>,
  methods: Vec<String>,
  client_context: ClientContext,
) -> Result<TokenResponse> {
  let now = Utc::now();
  let session_id = Uuid::new_v4();
  let mut tx = state.db.begin().await?;

  sqlx::query(
    "INSERT INTO auth.sessions (id, user_id, factor_id, aal, user_agent, ip, refreshed_at, created_at, updated_at) VALUES ($1, $2, $3, $4::auth.aal_level, $5, $6::inet, $7, $8, $9)",
  )
  .bind(session_id)
  .bind(user.id)
  .bind(factor_id)
  .bind(aal)
  .bind(client_context.user_agent)
  .bind(client_context.ip.map(|value| value.to_string()))
  .bind(now.naive_utc())
  .bind(now)
  .bind(now)
  .execute(&mut *tx)
  .await?;

  for method in &methods {
    sqlx::query(
      "INSERT INTO auth.mfa_amr_claims (id, session_id, created_at, updated_at, authentication_method) VALUES ($1, $2, $3, $4, $5) ON CONFLICT (session_id, authentication_method) DO NOTHING",
    )
    .bind(Uuid::new_v4())
    .bind(session_id)
    .bind(now)
    .bind(now)
    .bind(method)
    .execute(&mut *tx)
    .await?;
  }

  let refresh_token = generate_refresh_token();
  let refresh_token_hash = sha256_hex(&refresh_token);
  sqlx::query(
    "INSERT INTO auth.refresh_tokens (instance_id, user_id, token, session_id, revoked, created_at, updated_at) VALUES ($1, $2, $3, $4, false, $5, $6)",
  )
  .bind(state.instance_id)
  .bind(user.id.to_string())
  .bind(&refresh_token_hash)
  .bind(session_id)
  .bind(now)
  .bind(now)
  .execute(&mut *tx)
  .await?;

  sqlx::query("UPDATE auth.users SET last_sign_in_at = $1, updated_at = $2 WHERE id = $3")
    .bind(now)
    .bind(now)
    .bind(user.id)
    .execute(&mut *tx)
    .await?;

  tx.commit().await?;

  let amr = methods
    .into_iter()
    .map(|method| jwt::AmrEntry {
      method,
      timestamp: now.timestamp(),
    })
    .collect();

  build_token_response(state, user, session_id, aal, amr, refresh_token).await
}

pub fn generate_refresh_token() -> String {
  let mut bytes = [0u8; 32];
  rand::rng().fill_bytes(&mut bytes);
  URL_SAFE_NO_PAD.encode(bytes)
}

pub async fn build_token_response(
  state: &AppState,
  user: &User,
  session_id: Uuid,
  aal: &str,
  amr: Vec<jwt::AmrEntry>,
  refresh_token: String,
) -> Result<TokenResponse> {
  let now = Utc::now();
  let app_meta = user.raw_app_meta_data.clone().unwrap_or(serde_json::json!({}));
  let user_meta = user.raw_user_meta_data.clone().unwrap_or(serde_json::json!({}));
  let role = user.role.as_deref().unwrap_or("authenticated");
  let access_token = jwt::encode_token(jwt::EncodeTokenParams {
    user_id: user.id,
    email: user.email.clone(),
    phone: user.phone.clone(),
    role,
    session_id,
    is_anonymous: user.is_anonymous,
    aal,
    amr,
    user_metadata: user_meta,
    app_metadata: app_meta,
    jwt_secret: &state.jwt_secret,
    jwt_exp: state.jwt_exp,
    issuer: &state.issuer,
  })?;

  let expires_at = now.timestamp() + state.jwt_exp;
  let user_response = UserResponse::from_user(&state.db, user.clone()).await?;
  Ok(TokenResponse {
    access_token,
    token_type: "bearer".to_string(),
    expires_in: state.jwt_exp,
    expires_at,
    refresh_token,
    user: user_response,
  })
}

pub async fn load_session_context(
  state: &AppState,
  session_id: Uuid,
) -> Result<(SessionRow, Vec<jwt::AmrEntry>)> {
  let session: SessionRow = sqlx::query_as::<_, SessionRow>(
    "SELECT id, user_id, factor_id, aal::text as aal, not_after, user_agent, host(ip) as ip, refreshed_at, created_at, updated_at FROM auth.sessions WHERE id = $1",
  )
  .bind(session_id)
  .fetch_one(&state.db)
  .await?;
  ensure_session_is_active(state, &session)?;
  let claims: Vec<SessionAmrClaimRow> = sqlx::query_as::<_, SessionAmrClaimRow>(
    "SELECT authentication_method, created_at FROM auth.mfa_amr_claims WHERE session_id = $1 ORDER BY created_at ASC",
  )
  .bind(session_id)
  .fetch_all(&state.db)
  .await?;

  let amr = claims
    .into_iter()
    .map(|claim| jwt::AmrEntry {
      method: claim.authentication_method,
      timestamp: claim.created_at.timestamp(),
    })
    .collect();

  Ok((session, amr))
}

pub async fn ensure_active_session(state: &AppState, claims: &jwt::Claims) -> Result<SessionRow> {
  let session_id = claims
    .session_id
    .parse::<Uuid>()
    .map_err(|_| AuthError::NotAuthorized)?;
  let user_id = claims.sub.parse::<Uuid>().map_err(|_| AuthError::NotAuthorized)?;
  let session: SessionRow = sqlx::query_as::<_, SessionRow>(
    "SELECT id, user_id, factor_id, aal::text as aal, not_after, user_agent, host(ip) as ip, refreshed_at, created_at, updated_at FROM auth.sessions WHERE id = $1",
  )
  .bind(session_id)
  .fetch_optional(&state.db)
  .await?
  .ok_or(AuthError::NotAuthorized)?;

  if session.user_id != user_id {
    return Err(AuthError::NotAuthorized);
  }

  ensure_session_is_active(state, &session)?;

  Ok(session)
}

pub async fn load_current_user(state: &AppState, claims: &jwt::Claims) -> Result<User> {
  let user_id = claims.sub.parse::<Uuid>().map_err(|_| AuthError::NotAuthorized)?;
  let user: User = sqlx::query_as::<_, User>(
    "SELECT id, instance_id, aud, role, email, encrypted_password, email_confirmed_at, phone, phone_confirmed_at, confirmed_at, last_sign_in_at, raw_app_meta_data, raw_user_meta_data, is_super_admin, is_sso_user, is_anonymous, banned_until, deleted_at, created_at, updated_at FROM auth.users WHERE id = $1",
  )
  .bind(user_id)
  .fetch_optional(&state.db)
  .await?
  .ok_or(AuthError::NotAuthorized)?;

  ensure_user_is_active(&user)?;

  Ok(user)
}

pub fn ensure_user_is_active(user: &User) -> Result<()> {
  if user.deleted_at.is_some() {
    return Err(AuthError::NotAuthorized);
  }

  if user.banned_until.map(|value| value > Utc::now()).unwrap_or(false) {
    return Err(AuthError::UserBanned);
  }

  Ok(())
}

fn ensure_session_is_active(state: &AppState, session: &SessionRow) -> Result<()> {
  let now = Utc::now();
  if session.not_after.map(|value| value <= now).unwrap_or(false) {
    return Err(AuthError::NotAuthorized);
  }

  let last_active_at = session
    .refreshed_at
    .map(|value| DateTime::from_naive_utc_and_offset(value, Utc))
    .or(session.created_at)
    .ok_or(AuthError::NotAuthorized)?;
  if last_active_at + Duration::seconds(state.session_idle_timeout_secs) <= now {
    return Err(AuthError::NotAuthorized);
  }

  Ok(())
}

pub async fn require_reauthentication(
  state: &AppState,
  claims: &jwt::Claims,
  user: &User,
  client_ip: IpAddr,
  current_password: Option<&str>,
  reauthentication_token: Option<&str>,
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

  if let Some(token) = reauthentication_token
    .map(str::trim)
    .filter(|token| !token.is_empty())
  {
    let token_limiter_key = reauthentication_token_rate_limit_key(user.id, client_ip);
    if rate_limit::is_limited(
      &state.db,
      &token_limiter_key,
      REAUTHENTICATION_RATE_LIMIT_ATTEMPTS,
    )
    .await?
    {
      return Err(AuthError::TooManyRequests);
    }
    if consume_reauthentication_token(state, user.id, token, Utc::now()).await? {
      rate_limit::clear(&state.db, &token_limiter_key).await?;
      return Ok(());
    }
    rate_limit::record_failure(
      &state.db,
      &token_limiter_key,
      REAUTHENTICATION_RATE_LIMIT_WINDOW_SECS as i64,
    )
    .await?;
    return Err(AuthError::InvalidToken);
  }

  if let Some(hash) = user.encrypted_password.as_deref() {
    let password_limiter_key = reauthentication_password_rate_limit_key(user.id, client_ip);
    if rate_limit::is_limited(
      &state.db,
      &password_limiter_key,
      REAUTHENTICATION_RATE_LIMIT_ATTEMPTS,
    )
    .await?
    {
      return Err(AuthError::TooManyRequests);
    }
    let current_password = current_password.ok_or_else(|| {
      AuthError::ValidationFailed("current_password or reauthentication_token is required".to_string())
    })?;
    if !password::verify_password(current_password, hash)? {
      rate_limit::record_failure(
        &state.db,
        &password_limiter_key,
        REAUTHENTICATION_RATE_LIMIT_WINDOW_SECS as i64,
      )
      .await?;
      return Err(AuthError::InvalidCredentials);
    }
    rate_limit::clear(&state.db, &password_limiter_key).await?;
    return Ok(());
  }

  if !has_verified_mfa {
    return Err(AuthError::NotAuthorized);
  }

  Ok(())
}

fn reauthentication_token_rate_limit_key(user_id: Uuid, client_ip: IpAddr) -> String {
  format!("reauth-token:{user_id}:{client_ip}")
}

fn reauthentication_password_rate_limit_key(user_id: Uuid, client_ip: IpAddr) -> String {
  format!("reauth-password:{user_id}:{client_ip}")
}

pub async fn send_reauthentication_token(state: &AppState, user: &User) -> Result<()> {
  let email = user.email.as_deref().ok_or_else(|| {
    AuthError::ValidationFailed("reauthentication requires an email-backed account".to_string())
  })?;
  let mailer = state.mailer.as_ref().ok_or_else(|| {
    AuthError::ValidationFailed("reauthentication email delivery is unavailable".to_string())
  })?;

  let token = generate_refresh_token();
  let token_hash = sha256_hex(&token);
  let now = Utc::now();
  let expires_minutes = REAUTHENTICATION_TTL_MINUTES.to_string();

  sqlx::query(
    "UPDATE auth.users SET reauthentication_token = $1, reauthentication_sent_at = $2, updated_at = $3 WHERE id = $4",
  )
  .bind(&token_hash)
  .bind(now)
  .bind(now)
  .bind(user.id)
  .execute(&state.db)
  .await?;

  if let Err(e) = mailer
    .send(
      EmailKind::Reauthentication,
      email,
      &[
        ("site_name", state.site_name.as_str()),
        ("reauthentication_token", token.as_str()),
        ("email", email),
        ("expires_minutes", expires_minutes.as_str()),
      ],
    )
    .await
  {
    tracing::error!(error = %e, "Failed to send reauthentication email");
    return Err(AuthError::InternalError(
      "failed to send reauthentication email".to_string(),
    ));
  }

  tracing::info!("Sensitive-action reauthentication token issued");
  Ok(())
}

async fn consume_reauthentication_token(
  state: &AppState,
  user_id: Uuid,
  token: &str,
  now: chrono::DateTime<Utc>,
) -> Result<bool> {
  let valid_after = now - chrono::Duration::minutes(REAUTHENTICATION_TTL_MINUTES);
  let updated = sqlx::query(
    "UPDATE auth.users SET reauthentication_token = '', reauthentication_sent_at = NULL, updated_at = $1 WHERE id = $2 AND reauthentication_token = $3 AND reauthentication_sent_at > $4",
  )
  .bind(now)
  .bind(user_id)
  .bind(sha256_hex(token))
  .bind(valid_after)
  .execute(&state.db)
  .await?;

  Ok(updated.rows_affected() == 1)
}

#[cfg(test)]
mod tests {
  use std::collections::HashMap;
  use std::sync::Arc;

  use sqlx::postgres::PgPoolOptions;
  use tokio::sync::RwLock;

  use super::*;

  fn sample_state(session_idle_timeout_secs: i64) -> AppState {
    AppState {
      db: PgPoolOptions::new()
        .connect_lazy("postgres://localhost:5432/haya")
        .expect("lazy pool"),
      http_client: reqwest::Client::new(),
      jwt_secret: "a-very-long-test-secret-with-at-least-32-chars".to_string(),
      mfa_encryption_key: [0; 32],
      jwt_exp: 3600,
      refresh_token_exp: 3600,
      session_idle_timeout_secs,
      site_url: "http://localhost:9999".to_string(),
      allowed_redirect_origins: vec![],
      allowed_redirect_path_prefixes: vec![],
      oidc_form_post: false,
      site_name: "Haya".to_string(),
      issuer: "http://localhost:9999".to_string(),
      instance_id: Uuid::nil(),
      oidc_providers: Arc::new(RwLock::new(HashMap::new())),
      oidc_jwks_cache: Arc::new(RwLock::new(HashMap::new())),
      mailer_autoconfirm: false,
      mailer: None,
    }
  }

  fn sample_session(last_active_at: DateTime<Utc>) -> SessionRow {
    SessionRow {
      id: Uuid::nil(),
      user_id: Uuid::nil(),
      factor_id: None,
      aal: Some("aal1".to_string()),
      not_after: None,
      user_agent: None,
      ip: None,
      refreshed_at: Some(last_active_at.naive_utc()),
      created_at: Some(last_active_at),
      updated_at: Some(last_active_at),
    }
  }

  #[tokio::test]
  async fn active_session_with_recent_activity_is_allowed() {
    let state = sample_state(3600);
    let session = sample_session(Utc::now() - Duration::minutes(30));

    assert!(ensure_session_is_active(&state, &session).is_ok());
  }

  #[tokio::test]
  async fn idle_session_is_rejected() {
    let state = sample_state(300);
    let session = sample_session(Utc::now() - Duration::minutes(10));

    assert!(matches!(
      ensure_session_is_active(&state, &session),
      Err(AuthError::NotAuthorized)
    ));
  }
}
