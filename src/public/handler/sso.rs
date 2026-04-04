use axum::extract::{
  Query,
  State,
};
use axum::response::{
  IntoResponse,
  Redirect,
};
use chrono::{
  Duration,
  Utc,
};
use serde::Deserialize;
use uuid::Uuid;

use crate::auth::{
  oidc,
  session,
};
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
) -> Result<impl IntoResponse> {
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
  let expires_at = now + Duration::minutes(10);

  sqlx::query(
    "INSERT INTO auth.flow_state (id, user_id, auth_code, code_challenge_method, code_challenge, provider_type, provider_access_token, provider_refresh_token, authentication_method, created_at, updated_at, nonce, redirect_to, pkce_verifier, expires_at) VALUES ($1, NULL, $2, $3::auth.code_challenge_method, $4, $5, NULL, NULL, $6, $7, $8, $9, $10, $11, $12)",
  )
  .bind(flow_id)
  .bind(&flow.state)
  .bind(if provider.pkce { "s256" } else { "plain" })
  .bind(flow.pkce_verifier.clone().unwrap_or_default())
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

  let auth_url = oidc::build_authorization_url(&discovery, &provider, &flow)?;
  Ok(Redirect::to(auth_url.as_str()))
}

pub async fn callback(
  State(state): State<AppState>,
  Query(query): Query<CallbackQuery>,
) -> Result<impl IntoResponse> {
  let flow: FlowStateRow = sqlx::query_as::<_, FlowStateRow>(
    "DELETE FROM auth.flow_state WHERE auth_code = $1 RETURNING id, provider_type, auth_code, provider_access_token, provider_refresh_token, pkce_verifier, nonce, redirect_to, expires_at",
  )
  .bind(&query.state)
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
    &query.code,
    flow.pkce_verifier.as_deref(),
  )
  .await?;
  let validated = oidc::validate_id_token(
    &state.http_client,
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

    return Ok(Redirect::to(&build_redirect_url(
      validated_redirect_to(&state, flow.redirect_to.as_deref())?,
      &exchange_code,
    )?));
  }

  let response = session::issue_session(&state, &user, "oidc").await?;
  let exchange_code = persist_oidc_result(&state, TokenGrantResponse::Token(Box::new(response))).await?;

  Ok(Redirect::to(&build_redirect_url(
    validated_redirect_to(&state, flow.redirect_to.as_deref())?,
    &exchange_code,
  )?))
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
    let existing: Option<(Uuid, bool)> =
      sqlx::query_as::<_, (Uuid, bool)>("SELECT id, is_sso_user FROM auth.users WHERE email = $1")
        .bind(email)
        .fetch_optional(&state.db)
        .await?;
    if existing.is_some() {
      return Err(AuthError::NotAuthorized);
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

pub async fn exchange_callback_code(state: AppState, body: serde_json::Value) -> Result<TokenGrantResponse> {
  let code = body
    .get("code")
    .and_then(|value| value.as_str())
    .ok_or_else(|| AuthError::ValidationFailed("code is required".to_string()))?;

  let row: OidcResultRow = sqlx::query_as::<_, OidcResultRow>(
    "DELETE FROM auth.flow_state WHERE auth_code = $1 AND provider_type = 'oidc_result' RETURNING provider_access_token, expires_at",
  )
  .bind(code)
  .fetch_optional(&state.db)
  .await?
  .ok_or(AuthError::InvalidToken)?;

  if row.expires_at.map(|value| value < Utc::now()).unwrap_or(true) {
    return Err(AuthError::TokenExpired);
  }

  let payload = row
    .provider_access_token
    .ok_or_else(|| AuthError::InternalError("OIDC callback result is missing".to_string()))?;
  serde_json::from_str(&payload)
    .map_err(|e| AuthError::InternalError(format!("invalid OIDC callback result payload: {e}")))
}

async fn persist_oidc_result(state: &AppState, response: TokenGrantResponse) -> Result<String> {
  let exchange_code = session::generate_refresh_token();
  let now = Utc::now();
  let expires_at = now + Duration::minutes(OIDC_RESULT_TTL_MINUTES);
  let payload = serde_json::to_string(&response)
    .map_err(|e| AuthError::InternalError(format!("failed to serialize OIDC callback result: {e}")))?;

  sqlx::query(
    "INSERT INTO auth.flow_state (id, user_id, auth_code, code_challenge_method, code_challenge, provider_type, provider_access_token, provider_refresh_token, authentication_method, created_at, updated_at, expires_at) VALUES ($1, NULL, $2, 'plain'::auth.code_challenge_method, '', 'oidc_result', $3, NULL, 'oidc', $4, $5, $6)",
  )
  .bind(Uuid::new_v4())
  .bind(&exchange_code)
  .bind(payload)
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

  Ok(url.to_string())
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn appends_one_time_code_query_to_redirect() {
    let redirect =
      build_redirect_url("https://app.example.com/welcome".to_string(), "one-time-code").unwrap();

    assert!(redirect.contains("?code=one-time-code"));
    assert!(!redirect.contains('#'));
  }
}
