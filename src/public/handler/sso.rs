use axum::extract::{
  ConnectInfo,
  Form,
  Query,
  State,
};
use axum::http::header::{
  COOKIE,
  SET_COOKIE,
};
use axum::http::{
  HeaderMap,
  HeaderValue,
};
use axum::response::{
  IntoResponse,
  Redirect,
  Response,
};
use chrono::{
  Duration,
  Utc,
};
use hmac::Mac;
use serde::Deserialize;
use std::net::{
  IpAddr,
  SocketAddr,
};
use uuid::Uuid;

use crate::auth::{
  audit,
  mfa as crypto_mfa,
  oidc,
  rate_limit,
  session,
};
use crate::defaults::AUTHORIZATION_CODE_LIFETIME;
use crate::error::{
  AuthError,
  Result,
};
use crate::model::{
  TokenGrantResponse,
  User,
};
use crate::public::handler::mfa;
use crate::state::AppState;

const OIDC_RESULT_TTL_MINUTES: i64 = 1;
const OIDC_STATE_COOKIE_NAME: &str = "haya_oidc_state";
const OIDC_CALLBACK_RATE_LIMIT_ATTEMPTS: u32 = 15;
const OIDC_CALLBACK_RATE_LIMIT_WINDOW_SECS: i64 = 300;

#[derive(Debug, Deserialize)]
pub struct AuthorizeQuery {
  pub provider: String,
  pub redirect_to: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct CallbackQuery {
  pub code: String,
  pub state: String,
}

#[derive(Debug, Deserialize)]
pub struct CallbackForm {
  pub code: String,
  pub state: String,
}

#[allow(dead_code)]
#[derive(Debug, sqlx::FromRow)]
struct FlowStateRow {
  id: Uuid,
  provider_type: String,
  auth_code: String,
  provider_access_token: Option<String>,
  provider_refresh_token: Option<String>,
  pkce_verifier: Option<String>,
  nonce: Option<String>,
  redirect_to: Option<String>,
  expires_at: Option<chrono::DateTime<Utc>>,
}

#[derive(Debug, sqlx::FromRow)]
struct IdentityLookup {
  user_id: Uuid,
}

#[derive(Debug, sqlx::FromRow)]
struct OidcResultRow {
  provider_access_token: Option<String>,
  expires_at: Option<chrono::DateTime<Utc>>,
}

pub async fn authorize(
  State(state): State<AppState>,
  Query(query): Query<AuthorizeQuery>,
) -> Result<Response> {
  let redirect_to = validated_redirect_to(&state, query.redirect_to.as_deref())?;
  let provider = state
    .oidc_providers
    .read()
    .await
    .get(&query.provider)
    .cloned()
    .ok_or_else(|| AuthError::ValidationFailed(format!("Unsupported provider: {}", query.provider)))?;
  let discovery = oidc::discover_provider(&state.http_client, &provider).await?;
  let flow = oidc::generate_flow_tokens(provider.pkce);
  let flow_id = Uuid::new_v4();
  let now = Utc::now();
  let expires_at = now + Duration::seconds(AUTHORIZATION_CODE_LIFETIME);

  sqlx::query(
    "INSERT INTO auth.flow_state (id, user_id, auth_code, code_challenge_method, code_challenge, provider_type, provider_access_token, provider_refresh_token, authentication_method, created_at, updated_at, nonce, redirect_to, pkce_verifier, expires_at) VALUES ($1, NULL, $2, $3::auth.code_challenge_method, $4, $5, NULL, NULL, $6, $7, $8, $9, $10, $11, $12)",
  )
  .bind(flow_id)
  .bind(&flow.state)
  .bind(if provider.pkce { "s256" } else { "plain" })
  .bind(
    flow
      .pkce_verifier
      .as_deref()
      .map(oidc::pkce_challenge)
      .unwrap_or_default(),
  )
  .bind(&provider.name)
  .bind("oidc")
  .bind(now)
  .bind(now)
  .bind(&flow.nonce)
  .bind(Some(redirect_to))
  .bind(flow.pkce_verifier.clone())
  .bind(expires_at)
  .execute(&state.db)
  .await?;

  let auth_url = oidc::build_authorization_url(&discovery, &provider, &flow, state.oidc_form_post)?;
  let mut response = Redirect::to(auth_url.as_str()).into_response();
  response.headers_mut().append(
    SET_COOKIE,
    build_oidc_state_cookie(&state, &flow.state, AUTHORIZATION_CODE_LIFETIME)?,
  );
  Ok(response)
}

pub async fn callback(
  State(state): State<AppState>,
  ConnectInfo(client_addr): ConnectInfo<SocketAddr>,
  headers: HeaderMap,
  Query(query): Query<CallbackQuery>,
) -> Result<Response> {
  handle_callback(state, Some(client_addr.ip()), headers, query.code, query.state).await
}

pub async fn callback_form(
  State(state): State<AppState>,
  ConnectInfo(client_addr): ConnectInfo<SocketAddr>,
  headers: HeaderMap,
  Form(form): Form<CallbackForm>,
) -> Result<Response> {
  handle_callback(state, Some(client_addr.ip()), headers, form.code, form.state).await
}

async fn handle_callback(
  state: AppState,
  client_ip: Option<IpAddr>,
  headers: HeaderMap,
  code: String,
  state_param: String,
) -> Result<Response> {
  let Some(cookie_state) = oidc_state_cookie(&headers) else {
    return Err(AuthError::InvalidToken);
  };
  if !constant_time_eq(cookie_state, &state_param) {
    return Err(AuthError::InvalidToken);
  }

  let flow: FlowStateRow = sqlx::query_as::<_, FlowStateRow>(
    "DELETE FROM auth.flow_state WHERE auth_code = $1 RETURNING id, provider_type, auth_code, provider_access_token, provider_refresh_token, pkce_verifier, nonce, redirect_to, expires_at",
  )
  .bind(&state_param)
  .fetch_optional(&state.db)
  .await?
  .ok_or(AuthError::InvalidToken)?;

  if flow
    .expires_at
    .map(|expires_at| expires_at < Utc::now())
    .unwrap_or(true)
  {
    return Err(AuthError::TokenExpired);
  }

  let provider = state
    .oidc_providers
    .read()
    .await
    .get(&flow.provider_type)
    .cloned()
    .ok_or_else(|| AuthError::ValidationFailed(format!("Unsupported provider: {}", flow.provider_type)))?;
  let discovery = oidc::discover_provider(&state.http_client, &provider).await?;
  let token_response = oidc::exchange_code(
    &state.http_client,
    &discovery,
    &provider,
    &code,
    flow.pkce_verifier.as_deref(),
  )
  .await?;
  let validated = oidc::validate_id_token(
    &state,
    &discovery,
    &provider,
    &token_response.id_token,
    flow
      .nonce
      .as_deref()
      .ok_or_else(|| AuthError::InternalError("missing OIDC nonce".to_string()))?,
  )
  .await?;
  let userinfo = oidc::fetch_userinfo(&state.http_client, &discovery, &token_response.access_token).await?;
  let profile = oidc::normalize_profile(&validated, userinfo);
  oidc::enforce_allowed_domains(&provider, &profile)?;
  let user = provision_sso_user(&state, &provider, &profile).await?;
  ensure_user_signin_allowed(&user)?;
  let factors = mfa::verified_factors_by_user_id(&state.db, user.id).await?;

  if !factors.is_empty() {
    let pending = mfa::create_pending_login(&state, user.id, "oidc").await?;
    let exchange_code = persist_oidc_result(&state, TokenGrantResponse::PendingMfa(pending)).await?;
    audit::log_event(
      &state.db,
      state.instance_id,
      client_ip,
      "oidc_login_challenged",
      serde_json::json!({
        "user_id": user.id,
        "provider": flow.provider_type,
        "mfa_required": true,
      }),
    )
    .await?;

    let mut response = Redirect::to(&build_redirect_url(
      validated_redirect_to(&state, flow.redirect_to.as_deref())?,
      &exchange_code,
    )?)
    .into_response();
    response
      .headers_mut()
      .append(SET_COOKIE, clear_oidc_state_cookie(&state)?);
    return Ok(response);
  }

  let response = session::issue_session_for_client(
    &state,
    &user,
    "oidc",
    session::ClientContext {
      user_agent: user_agent_from_headers(&headers),
      ip: client_ip,
    },
  )
  .await?;
  let exchange_code = persist_oidc_result(&state, TokenGrantResponse::Token(Box::new(response))).await?;
  audit::log_event(
    &state.db,
    state.instance_id,
    client_ip,
    "oidc_login_succeeded",
    serde_json::json!({
      "user_id": user.id,
      "provider": flow.provider_type,
    }),
  )
  .await?;

  let mut response = Redirect::to(&build_redirect_url(
    validated_redirect_to(&state, flow.redirect_to.as_deref())?,
    &exchange_code,
  )?)
  .into_response();
  response
    .headers_mut()
    .append(SET_COOKIE, clear_oidc_state_cookie(&state)?);
  Ok(response)
}

async fn provision_sso_user(
  state: &AppState,
  provider: &oidc::OidcProviderConfig,
  profile: &oidc::NormalizedOidcProfile,
) -> Result<User> {
  let now = Utc::now();
  if let Some(identity) = sqlx::query_as::<_, IdentityLookup>(
    "SELECT user_id FROM auth.identities WHERE provider = $1 AND provider_id = $2",
  )
  .bind(&provider.name)
  .bind(&profile.subject)
  .fetch_optional(&state.db)
  .await?
  {
    sqlx::query(
      "UPDATE auth.identities SET identity_data = $1, last_sign_in_at = $2, updated_at = $3 WHERE provider = $4 AND provider_id = $5",
    )
    .bind(&profile.raw_claims)
    .bind(now)
    .bind(now)
    .bind(&provider.name)
    .bind(&profile.subject)
    .execute(&state.db)
    .await?;

    return fetch_user(&state.db, identity.user_id).await;
  }

  if let Some(email) = profile.email.as_deref() {
    let existing: Option<User> = sqlx::query_as::<_, User>(
      "SELECT id, instance_id, aud, role, email, encrypted_password, email_confirmed_at, phone, phone_confirmed_at, confirmed_at, last_sign_in_at, raw_app_meta_data, raw_user_meta_data, is_super_admin, is_sso_user, is_anonymous, banned_until, deleted_at, created_at, updated_at FROM auth.users WHERE lower(email) = lower($1)",
    )
        .bind(email)
        .fetch_optional(&state.db)
        .await?;
    if let Some(existing_user) = existing {
      if !can_auto_link_sso_user(&existing_user) {
        return Err(AuthError::NotAuthorized);
      }
      return link_sso_user(state, provider, profile, existing_user, now).await;
    }
  }

  let user_id = Uuid::new_v4();
  let user_metadata = serde_json::json!({
    "name": profile.name,
    "avatar_url": profile.avatar_url,
  });
  let app_metadata = serde_json::json!({
    "provider": provider.name,
    "providers": [provider.name],
  });
  let email_confirmed_at = profile.email_verified.then_some(now);

  let user: User = sqlx::query_as::<_, User>(
    "INSERT INTO auth.users (id, instance_id, aud, role, email, encrypted_password, email_confirmed_at, raw_app_meta_data, raw_user_meta_data, is_sso_user, is_anonymous, created_at, updated_at) VALUES ($1, $2, $3, $4, $5, NULL, $6, $7, $8, true, false, $9, $10) RETURNING id, instance_id, aud, role, email, encrypted_password, email_confirmed_at, phone, phone_confirmed_at, confirmed_at, last_sign_in_at, raw_app_meta_data, raw_user_meta_data, is_super_admin, is_sso_user, is_anonymous, banned_until, deleted_at, created_at, updated_at",
  )
  .bind(user_id)
  .bind(state.instance_id)
  .bind("authenticated")
  .bind("authenticated")
  .bind(&profile.email)
  .bind(email_confirmed_at)
  .bind(&app_metadata)
  .bind(&user_metadata)
  .bind(now)
  .bind(now)
  .fetch_one(&state.db)
  .await?;

  sqlx::query(
    "INSERT INTO auth.identities (id, provider_id, user_id, identity_data, provider, last_sign_in_at, created_at, updated_at) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)",
  )
  .bind(Uuid::new_v4())
  .bind(&profile.subject)
  .bind(user_id)
  .bind(&profile.raw_claims)
  .bind(&provider.name)
  .bind(now)
  .bind(now)
  .bind(now)
  .execute(&state.db)
  .await?;

  Ok(user)
}

async fn link_sso_user(
  state: &AppState,
  provider: &oidc::OidcProviderConfig,
  profile: &oidc::NormalizedOidcProfile,
  user: User,
  now: chrono::DateTime<Utc>,
) -> Result<User> {
  if !profile.email_verified {
    return Err(AuthError::NotAuthorized);
  }
  ensure_user_signin_allowed(&user)?;

  let app_metadata = merged_app_metadata(user.raw_app_meta_data.clone(), &provider.name);
  sqlx::query(
    "UPDATE auth.users SET raw_app_meta_data = $1, is_sso_user = true, updated_at = $2 WHERE id = $3",
  )
  .bind(&app_metadata)
  .bind(now)
  .bind(user.id)
  .execute(&state.db)
  .await?;
  sqlx::query(
    "INSERT INTO auth.identities (id, provider_id, user_id, identity_data, provider, last_sign_in_at, created_at, updated_at) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)",
  )
  .bind(Uuid::new_v4())
  .bind(&profile.subject)
  .bind(user.id)
  .bind(&profile.raw_claims)
  .bind(&provider.name)
  .bind(now)
  .bind(now)
  .bind(now)
  .execute(&state.db)
  .await?;

  fetch_user(&state.db, user.id).await
}

fn can_auto_link_sso_user(user: &User) -> bool {
  user.email_confirmed_at.is_some() && user.encrypted_password.is_none()
}

fn merged_app_metadata(existing: Option<serde_json::Value>, provider_name: &str) -> serde_json::Value {
  let mut metadata = match existing {
    Some(serde_json::Value::Object(map)) => serde_json::Value::Object(map),
    _ => serde_json::json!({}),
  };
  let object = metadata
    .as_object_mut()
    .expect("app metadata initialization must yield an object");
  let providers = object
    .entry("providers".to_string())
    .or_insert_with(|| serde_json::json!([]));
  if !providers.is_array() {
    *providers = serde_json::json!([]);
  }
  let providers_array = providers
    .as_array_mut()
    .expect("providers initialization must yield an array");
  if !providers_array
    .iter()
    .any(|value| value.as_str() == Some(provider_name))
  {
    providers_array.push(serde_json::Value::String(provider_name.to_string()));
  }
  metadata
}

fn oidc_state_cookie(headers: &HeaderMap) -> Option<&str> {
  headers
    .get(COOKIE)
    .and_then(|value| value.to_str().ok())
    .and_then(|cookie_header| {
      cookie_header.split(';').find_map(|pair| {
        let (name, value) = pair.trim().split_once('=')?;
        (name == OIDC_STATE_COOKIE_NAME).then_some(value)
      })
    })
}

fn user_agent_from_headers(headers: &HeaderMap) -> Option<String> {
  headers
    .get(axum::http::header::USER_AGENT)
    .and_then(|value| value.to_str().ok())
    .map(str::to_owned)
}

fn build_oidc_state_cookie(state: &AppState, value: &str, max_age_seconds: i64) -> Result<HeaderValue> {
  validate_oidc_cookie_value(value)?;
  let secure = state.site_url.starts_with("https://");
  let cookie = format!(
    // Lax is required for standard OIDC GET redirects; deployments that want stricter CSRF isolation
    // can switch providers to form_post and use the POST callback handler.
    "{OIDC_STATE_COOKIE_NAME}={value}; Max-Age={max_age_seconds}; Path=/callback; HttpOnly; SameSite=Lax{}",
    if secure { "; Secure" } else { "" }
  );
  HeaderValue::from_str(&cookie)
    .map_err(|e| AuthError::InternalError(format!("failed to build OIDC state cookie: {e}")))
}

fn clear_oidc_state_cookie(state: &AppState) -> Result<HeaderValue> {
  build_oidc_state_cookie(state, "", 0)
}

fn validate_oidc_cookie_value(value: &str) -> Result<()> {
  if value
    .bytes()
    .any(|byte| matches!(byte, b';' | b'\r' | b'\n') || byte.is_ascii_control())
  {
    return Err(AuthError::ValidationFailed(
      "OIDC state cookie contains invalid characters".to_string(),
    ));
  }
  Ok(())
}

fn constant_time_eq(left: &str, right: &str) -> bool {
  let mut left_mac =
    hmac::Hmac::<sha2::Sha256>::new_from_slice(b"haya-oidc-state-compare").expect("static key is valid");
  left_mac.update(left.as_bytes());
  let left_tag = left_mac.finalize().into_bytes();

  let mut right_mac =
    hmac::Hmac::<sha2::Sha256>::new_from_slice(b"haya-oidc-state-compare").expect("static key is valid");
  right_mac.update(right.as_bytes());
  right_mac.verify_slice(&left_tag).is_ok()
}

async fn fetch_user(db: &sqlx::PgPool, user_id: Uuid) -> Result<User> {
  sqlx::query_as::<_, User>(
    "SELECT id, instance_id, aud, role, email, encrypted_password, email_confirmed_at, phone, phone_confirmed_at, confirmed_at, last_sign_in_at, raw_app_meta_data, raw_user_meta_data, is_super_admin, is_sso_user, is_anonymous, banned_until, deleted_at, created_at, updated_at FROM auth.users WHERE id = $1",
  )
  .bind(user_id)
  .fetch_optional(db)
  .await?
  .ok_or(AuthError::UserNotFound)
}

fn ensure_user_signin_allowed(user: &User) -> Result<()> {
  session::ensure_user_is_active(user)
}

pub async fn exchange_callback_code(
  state: AppState,
  client_ip: IpAddr,
  body: serde_json::Value,
) -> Result<TokenGrantResponse> {
  let code = body
    .get("code")
    .and_then(|value| value.as_str())
    .ok_or_else(|| AuthError::ValidationFailed("code is required".to_string()))?;
  let rate_limit_key = format!("oidc-callback-ip:{client_ip}");

  if rate_limit::is_limited(&state.db, &rate_limit_key, OIDC_CALLBACK_RATE_LIMIT_ATTEMPTS).await? {
    return Err(AuthError::TooManyRequests);
  }

  let row = sqlx::query_as::<_, OidcResultRow>(
    "DELETE FROM auth.flow_state WHERE auth_code = $1 AND provider_type = 'oidc_result' RETURNING provider_access_token, expires_at",
  )
  .bind(code)
  .fetch_optional(&state.db)
  .await?;

  let Some(row) = row else {
    rate_limit::record_failure(&state.db, &rate_limit_key, OIDC_CALLBACK_RATE_LIMIT_WINDOW_SECS).await?;
    audit::log_event(
      &state.db,
      state.instance_id,
      Some(client_ip),
      "oidc_callback_exchange_failed",
      serde_json::json!({
        "reason": "invalid_code",
      }),
    )
    .await?;
    return Err(AuthError::InvalidToken);
  };

  if row.expires_at.map(|value| value < Utc::now()).unwrap_or(true) {
    rate_limit::record_failure(&state.db, &rate_limit_key, OIDC_CALLBACK_RATE_LIMIT_WINDOW_SECS).await?;
    return Err(AuthError::TokenExpired);
  }

  let payload = row
    .provider_access_token
    .ok_or_else(|| AuthError::InternalError("OIDC callback result is missing".to_string()))?;
  let decrypted = crypto_mfa::decrypt_secret(&payload, &state.mfa_encryption_key)?;
  let response = serde_json::from_slice(&decrypted)
    .map_err(|e| AuthError::InternalError(format!("invalid OIDC callback result payload: {e}")))?;
  rate_limit::clear(&state.db, &rate_limit_key).await?;
  Ok(response)
}

async fn persist_oidc_result(state: &AppState, response: TokenGrantResponse) -> Result<String> {
  let exchange_code = session::generate_refresh_token();
  let now = Utc::now();
  let expires_at = now + Duration::minutes(OIDC_RESULT_TTL_MINUTES);
  let payload = serde_json::to_vec(&response)
    .map_err(|e| AuthError::InternalError(format!("failed to serialize OIDC callback result: {e}")))?;
  let encrypted_payload = crypto_mfa::encrypt_secret(&payload, &state.mfa_encryption_key)?;

  sqlx::query(
    "INSERT INTO auth.flow_state (id, user_id, auth_code, code_challenge_method, code_challenge, provider_type, provider_access_token, provider_refresh_token, authentication_method, created_at, updated_at, expires_at) VALUES ($1, NULL, $2, 'plain'::auth.code_challenge_method, '', 'oidc_result', $3, NULL, 'oidc', $4, $5, $6)",
  )
  .bind(Uuid::new_v4())
  .bind(&exchange_code)
  .bind(encrypted_payload)
  .bind(now)
  .bind(now)
  .bind(expires_at)
  .execute(&state.db)
  .await?;

  Ok(exchange_code)
}

fn build_redirect_url(redirect_to: String, exchange_code: &str) -> Result<String> {
  let mut url = url::Url::parse(&redirect_to)
    .map_err(|e| AuthError::ValidationFailed(format!("invalid redirect_to: {e}")))?;
  url.query_pairs_mut().append_pair("code", exchange_code);
  Ok(url.to_string())
}

fn validated_redirect_to(state: &AppState, redirect_to: Option<&str>) -> Result<String> {
  let value = redirect_to.unwrap_or(&state.site_url);
  let url =
    url::Url::parse(value).map_err(|e| AuthError::ValidationFailed(format!("invalid redirect_to: {e}")))?;
  match url.scheme() {
    "http" | "https" => {},
    _ => {
      return Err(AuthError::ValidationFailed(
        "redirect_to must use http or https".to_string(),
      ));
    },
  }
  let host = url
    .host_str()
    .ok_or_else(|| AuthError::ValidationFailed("redirect_to must include a host".to_string()))?;
  let mut origin = format!("{}://{}", url.scheme(), host);
  if let Some(port) = url.port() {
    origin.push(':');
    origin.push_str(&port.to_string());
  }
  if !state
    .allowed_redirect_origins
    .iter()
    .any(|allowed| allowed == &origin)
  {
    return Err(AuthError::ValidationFailed(
      "redirect_to origin is not allowed".to_string(),
    ));
  }
  if !state.allowed_redirect_path_prefixes.is_empty()
    && !state
      .allowed_redirect_path_prefixes
      .iter()
      .any(|prefix| url.path().starts_with(prefix))
  {
    return Err(AuthError::ValidationFailed(
      "redirect_to path is not allowed".to_string(),
    ));
  }

  Ok(url.to_string())
}

#[cfg(test)]
mod tests {
  use super::*;

  fn sample_user() -> User {
    User {
      id: Uuid::nil(),
      instance_id: None,
      aud: None,
      role: None,
      email: Some("user@example.com".to_string()),
      encrypted_password: None,
      email_confirmed_at: Some(Utc::now()),
      phone: None,
      phone_confirmed_at: None,
      confirmed_at: None,
      last_sign_in_at: None,
      raw_app_meta_data: None,
      raw_user_meta_data: None,
      is_super_admin: None,
      is_sso_user: false,
      is_anonymous: false,
      banned_until: None,
      deleted_at: None,
      created_at: None,
      updated_at: None,
    }
  }

  #[test]
  fn auto_link_requires_confirmed_email() {
    let mut user = sample_user();
    user.email_confirmed_at = None;

    assert!(!can_auto_link_sso_user(&user));
  }

  #[test]
  fn auto_link_rejects_password_accounts() {
    let mut user = sample_user();
    user.encrypted_password = Some("hash".to_string());

    assert!(!can_auto_link_sso_user(&user));
  }

  #[test]
  fn appends_one_time_code_query_to_redirect() {
    let redirect =
      build_redirect_url("https://app.example.com/welcome".to_string(), "one-time-code").unwrap();

    assert!(redirect.contains("?code=one-time-code"));
    assert!(!redirect.contains('#'));
  }

  #[test]
  fn constant_time_compare_accepts_equal_values() {
    assert!(constant_time_eq("state-value", "state-value"));
  }

  #[test]
  fn constant_time_compare_rejects_different_values() {
    assert!(!constant_time_eq("state-value", "other-state"));
  }
}
