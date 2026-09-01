use std::net::SocketAddr;

use axum::Json;
use axum::extract::{
  ConnectInfo,
  State,
};
use axum::http::HeaderMap;
use chrono::{
  DateTime,
  Utc,
};
use haya_passkey_rp::{
  AuthenticatedPublicKeyCredential,
  AuthenticatorTransport,
  CreatedPublicKeyCredential,
  CredentialCreationOptions,
  CredentialRequestOptions,
  PasskeyRp,
  RegistrationInput,
};
use serde::{
  Deserialize,
  Serialize,
};
use uuid::Uuid;

use crate::auth::{
  audit,
  passkey_repository,
  rate_limit,
  session,
};
use crate::error::{
  AuthError,
  Result,
};
use crate::middleware::auth::AuthUser;
use crate::model::{
  TokenResponse,
  User,
  UserResponse,
};
use crate::state::AppState;

use super::mfa::{
  ensure_friendly_name_available,
  normalize_friendly_name,
};

const REGISTRATION_OPTIONS_MAX_ATTEMPTS: u32 = 10;
const REGISTRATION_OPTIONS_WINDOW_SECS: i64 = 300;
const REGISTRATION_VERIFY_MAX_FAILURES: u32 = 10;
const REGISTRATION_VERIFY_WINDOW_SECS: i64 = 300;
const AUTHENTICATION_OPTIONS_MAX_ATTEMPTS: u32 = 20;
const AUTHENTICATION_OPTIONS_WINDOW_SECS: i64 = 300;
const AUTHENTICATION_VERIFY_MAX_FAILURES: u32 = 10;
const AUTHENTICATION_VERIFY_WINDOW_SECS: i64 = 300;

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PasskeyRegistrationOptionsRequest {
  pub friendly_name: Option<String>,
  pub current_password: Option<String>,
  pub reauthentication_token: Option<String>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PasskeyRegistrationOptionsResponse {
  pub flow_id: Uuid,
  pub expires_at: DateTime<Utc>,
  pub options: CredentialCreationOptions,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PasskeyRegistrationVerifyRequest {
  pub flow_id: Uuid,
  pub credential: CreatedPublicKeyCredential,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PasskeyAuthenticationOptionsRequest {}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PasskeyAuthenticationOptionsResponse {
  pub flow_id: Uuid,
  pub expires_at: DateTime<Utc>,
  pub options: CredentialRequestOptions,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PasskeyTokenGrantRequest {
  pub flow_id: Uuid,
  pub credential: AuthenticatedPublicKeyCredential,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PasskeyFactorResponse {
  pub id: Uuid,
  pub friendly_name: Option<String>,
  pub status: String,
  pub aaguid: Uuid,
  pub transports: Vec<AuthenticatorTransport>,
  pub created_at: DateTime<Utc>,
  pub updated_at: DateTime<Utc>,
  pub last_challenged_at: Option<DateTime<Utc>>,
}

impl From<passkey_repository::WebAuthnFactor> for PasskeyFactorResponse {
  fn from(factor: passkey_repository::WebAuthnFactor) -> Self {
    Self {
      id: factor.id,
      friendly_name: factor.friendly_name,
      status: factor.status,
      aaguid: Uuid::from_bytes(factor.credential.aaguid),
      transports: factor.credential.transports,
      created_at: factor.created_at,
      updated_at: factor.updated_at,
      last_challenged_at: factor.last_challenged_at,
    }
  }
}

pub async fn registration_options(
  State(state): State<AppState>,
  ConnectInfo(client_addr): ConnectInfo<SocketAddr>,
  AuthUser { claims, user }: AuthUser,
  Json(request): Json<PasskeyRegistrationOptionsRequest>,
) -> Result<Json<PasskeyRegistrationOptionsResponse>> {
  let rp = passkey_rp(&state)?;
  let client_ip = client_addr.ip();
  let rate_limit_keys = registration_options_rate_limit_keys(user.id, client_ip);

  session::require_reauthentication(
    &state,
    &claims,
    &user,
    client_ip,
    request.current_password.as_deref(),
    request.reauthentication_token.as_deref(),
  )
  .await?;

  let friendly_name = normalize_friendly_name(request.friendly_name)?;
  ensure_friendly_name_available(&state.db, user.id, friendly_name.as_deref()).await?;
  if passkey_repository::web_authn_factor_count(&state.db, user.id).await?
    >= passkey_repository::MAX_WEB_AUTHN_FACTORS_PER_USER
  {
    return Err(AuthError::ValidationFailed(format!(
      "Passkey factor limit reached (limit: {})",
      passkey_repository::MAX_WEB_AUTHN_FACTORS_PER_USER
    )));
  }

  let exclude_credentials = passkey_repository::web_authn_factors_by_user_id(&state.db, user.id)
    .await?
    .iter()
    .map(passkey_repository::WebAuthnFactor::credential_descriptor)
    .collect();
  let account_name = user.email.clone().unwrap_or_else(|| user.id.to_string());
  let start = rp
    .start_registration(RegistrationInput {
      user_handle: user.id.as_bytes().to_vec(),
      user_name: account_name.clone(),
      user_display_name: account_name,
      exclude_credentials,
    })
    .map_err(AuthError::from_passkey_registration_error)?;
  reserve_rate_limits(
    &state,
    &rate_limit_keys,
    REGISTRATION_OPTIONS_MAX_ATTEMPTS,
    REGISTRATION_OPTIONS_WINDOW_SECS,
  )
  .await?;
  let flow = match passkey_repository::create_registration_flow(
    &state.db,
    user.id,
    &start.state,
    friendly_name.as_deref(),
    start.expires_in_secs,
  )
  .await
  {
    Ok(flow) => flow,
    Err(error) => {
      release_rate_limit_reservations(&state, &rate_limit_keys).await;
      return Err(error);
    },
  };

  if let Err(error) = audit::log_event(
    &state.db,
    state.instance_id,
    Some(client_ip),
    "passkey_enrollment_started",
    enrollment_audit_payload(user.id, None, flow.id, None),
  )
  .await
  {
    tracing::warn!(error = %error, "failed to record passkey enrollment start audit event");
  }

  Ok(Json(PasskeyRegistrationOptionsResponse {
    flow_id: flow.id,
    expires_at: flow.expires_at,
    options: start.options,
  }))
}

pub async fn registration_verify(
  State(state): State<AppState>,
  ConnectInfo(client_addr): ConnectInfo<SocketAddr>,
  AuthUser { user, .. }: AuthUser,
  Json(request): Json<PasskeyRegistrationVerifyRequest>,
) -> Result<Json<PasskeyFactorResponse>> {
  let rp = passkey_rp(&state)?;
  let client_ip = client_addr.ip();
  let rate_limit_keys = registration_verify_rate_limit_keys(request.flow_id, client_ip);
  reserve_rate_limits(
    &state,
    &rate_limit_keys,
    REGISTRATION_VERIFY_MAX_FAILURES,
    REGISTRATION_VERIFY_WINDOW_SECS,
  )
  .await?;

  let now = Utc::now();
  let mut tx = match state.db.begin().await {
    Ok(tx) => tx,
    Err(error) => {
      release_rate_limit_reservations(&state, &rate_limit_keys).await;
      return Err(AuthError::DatabaseError(error));
    },
  };
  let flow = match passkey_repository::lock_registration_flow(&mut tx, request.flow_id, user.id, now).await {
    Ok(flow) => flow,
    Err(AuthError::DatabaseError(error)) => {
      release_rate_limit_reservations(&state, &rate_limit_keys).await;
      return Err(AuthError::DatabaseError(error));
    },
    Err(_) => {
      drop(tx);
      record_registration_failure(&state, client_ip, user.id, request.flow_id, "flow_unavailable").await;
      return Err(AuthError::PasskeyRegistrationFailed);
    },
  };

  let registration_state = match flow.registration_state() {
    Ok(registration_state) => registration_state,
    Err(_) => {
      tx.commit().await?;
      record_registration_failure(
        &state,
        client_ip,
        user.id,
        request.flow_id,
        "stored_state_invalid",
      )
      .await;
      return Err(AuthError::PasskeyRegistrationFailed);
    },
  };
  let credential = match rp.finish_registration(registration_state, request.credential) {
    Ok(credential) => credential,
    Err(_) => {
      tx.commit().await?;
      record_registration_failure(&state, client_ip, user.id, request.flow_id, "protocol_validation").await;
      return Err(AuthError::PasskeyRegistrationFailed);
    },
  };
  let factor = match passkey_repository::complete_registration(&mut tx, &flow, &credential, now).await {
    Ok(factor) => factor,
    Err(AuthError::PasskeyRegistrationFailed) => {
      tx.commit().await?;
      record_registration_failure(&state, client_ip, user.id, request.flow_id, "credential_conflict").await;
      return Err(AuthError::PasskeyRegistrationFailed);
    },
    Err(error) => {
      release_rate_limit_reservations(&state, &rate_limit_keys).await;
      return Err(error);
    },
  };

  if let Err(error) = audit::log_event_tx(
    tx.as_mut(),
    state.instance_id,
    Some(client_ip),
    "passkey_enrollment_succeeded",
    enrollment_audit_payload(user.id, Some(factor.id), flow.id, None),
  )
  .await
  {
    release_rate_limit_reservations(&state, &rate_limit_keys).await;
    return Err(error);
  }
  tx.commit().await?;
  release_successful_verification_reservation(&state, &rate_limit_keys).await;

  Ok(Json(factor.into()))
}

pub async fn authentication_options(
  State(state): State<AppState>,
  ConnectInfo(client_addr): ConnectInfo<SocketAddr>,
  headers: HeaderMap,
  Json(_request): Json<PasskeyAuthenticationOptionsRequest>,
) -> Result<Json<PasskeyAuthenticationOptionsResponse>> {
  let rp = passkey_rp(&state)?;
  let client_ip = client_addr.ip();
  let rate_limit_key = authentication_options_rate_limit_key(client_ip);
  if rate_limit::check_and_record(
    &state.db,
    &rate_limit_key,
    AUTHENTICATION_OPTIONS_MAX_ATTEMPTS,
    AUTHENTICATION_OPTIONS_WINDOW_SECS,
  )
  .await?
  {
    return Err(AuthError::TooManyRequests);
  }

  let _client_user_agent = user_agent_from_headers(&headers);
  let start = rp.start_authentication();
  let flow = match passkey_repository::create_authentication_flow(
    &state.db,
    &start.state,
    start.expires_in_secs,
  )
  .await
  {
    Ok(flow) => flow,
    Err(error) => {
      release_rate_limit_reservations(&state, &[rate_limit_key]).await;
      return Err(error);
    },
  };

  Ok(Json(PasskeyAuthenticationOptionsResponse {
    flow_id: flow.id,
    expires_at: flow.expires_at,
    options: start.options,
  }))
}

pub async fn malformed_authentication_error(
  state: &AppState,
  client_ip: std::net::IpAddr,
  flow_id: Option<Uuid>,
) -> Result<AuthError> {
  passkey_rp(state)?;
  let keys = match flow_id {
    Some(flow_id) => authentication_verify_rate_limit_keys(flow_id, client_ip).to_vec(),
    None => vec![format!("passkey-authenticate-verify:ip:{client_ip}")],
  };
  reserve_rate_limits(
    state,
    &keys,
    AUTHENTICATION_VERIFY_MAX_FAILURES,
    AUTHENTICATION_VERIFY_WINDOW_SECS,
  )
  .await?;
  record_authentication_failure(state, client_ip).await;
  Ok(AuthError::PasskeyAuthenticationFailed)
}

pub async fn complete_authentication(
  state: AppState,
  client_ip: std::net::IpAddr,
  user_agent: Option<String>,
  request: PasskeyTokenGrantRequest,
) -> Result<TokenResponse> {
  let rp = passkey_rp(&state)?;
  let rate_limit_keys = authentication_verify_rate_limit_keys(request.flow_id, client_ip);
  reserve_rate_limits(
    &state,
    &rate_limit_keys,
    AUTHENTICATION_VERIFY_MAX_FAILURES,
    AUTHENTICATION_VERIFY_WINDOW_SECS,
  )
  .await?;

  let now = Utc::now();
  let mut tx = match state.db.begin().await {
    Ok(tx) => tx,
    Err(error) => {
      release_rate_limit_reservations(&state, &rate_limit_keys).await;
      return Err(AuthError::DatabaseError(error));
    },
  };
  let flow = match passkey_repository::lock_authentication_flow(&mut tx, request.flow_id, now).await {
    Ok(flow) => flow,
    Err(AuthError::DatabaseError(error)) => {
      return abort_authentication(&state, tx, &rate_limit_keys, AuthError::DatabaseError(error)).await;
    },
    Err(_) => {
      drop(tx);
      record_authentication_failure(&state, client_ip).await;
      return Err(AuthError::PasskeyAuthenticationFailed);
    },
  };
  let authentication_state = match flow.authentication_state() {
    Ok(authentication_state) => authentication_state,
    Err(_) => return fail_authentication(&state, tx, &rate_limit_keys, client_ip).await,
  };
  let factor =
    match passkey_repository::lock_factor_by_credential_id(&mut tx, request.credential.raw_id.as_slice())
      .await
    {
      Ok(factor) => factor,
      Err(AuthError::DatabaseError(error)) => {
        return abort_authentication(&state, tx, &rate_limit_keys, AuthError::DatabaseError(error)).await;
      },
      Err(_) => return fail_authentication(&state, tx, &rate_limit_keys, client_ip).await,
    };
  let authentication =
    match rp.finish_authentication(authentication_state, &factor.credential, request.credential) {
      Ok(authentication) => authentication,
      Err(_) => return fail_authentication(&state, tx, &rate_limit_keys, client_ip).await,
    };
  let user_id = match Uuid::from_slice(&authentication.user_handle) {
    Ok(user_id) if user_id == factor.user_id => user_id,
    _ => return fail_authentication(&state, tx, &rate_limit_keys, client_ip).await,
  };
  let user = match fetch_active_user(&mut tx, user_id, now).await {
    Ok(user) => user,
    Err(AuthError::DatabaseError(error)) => {
      return abort_authentication(&state, tx, &rate_limit_keys, AuthError::DatabaseError(error)).await;
    },
    Err(_) => return fail_authentication(&state, tx, &rate_limit_keys, client_ip).await,
  };
  let factor =
    match passkey_repository::complete_authentication(&mut tx, &flow, &factor, &authentication, now).await {
      Ok(factor) => factor,
      Err(AuthError::DatabaseError(error)) => {
        return abort_authentication(&state, tx, &rate_limit_keys, AuthError::DatabaseError(error)).await;
      },
      Err(_) => return fail_authentication(&state, tx, &rate_limit_keys, client_ip).await,
    };
  let issued = match session::issue_session_in_transaction(
    &state,
    &mut tx,
    &user,
    "aal2",
    Some(factor.id),
    vec!["webauthn".to_owned()],
    session::ClientContext {
      user_agent,
      ip: Some(client_ip),
    },
  )
  .await
  {
    Ok(issued) => issued,
    Err(error) => return abort_authentication(&state, tx, &rate_limit_keys, error).await,
  };
  let user_response = match UserResponse::from_user_in_transaction(tx.as_mut(), user.clone()).await {
    Ok(user_response) => user_response,
    Err(error) => return abort_authentication(&state, tx, &rate_limit_keys, error).await,
  };
  let response = match session::build_issued_session_response_with_user(&state, &user, user_response, issued)
  {
    Ok(response) => response,
    Err(error) => return abort_authentication(&state, tx, &rate_limit_keys, error).await,
  };
  if let Err(error) = audit::log_event_tx(
    tx.as_mut(),
    state.instance_id,
    Some(client_ip),
    "passkey_login_succeeded",
    serde_json::json!({
      "user_id": user.id,
      "factor_id": factor.id,
    }),
  )
  .await
  {
    return abort_authentication(&state, tx, &rate_limit_keys, error).await;
  }
  if let Err(error) = tx.commit().await {
    release_rate_limit_reservations(&state, &rate_limit_keys).await;
    return Err(AuthError::DatabaseError(error));
  }
  release_successful_verification_reservation(&state, &rate_limit_keys).await;

  Ok(response)
}

async fn fetch_active_user(
  tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
  user_id: Uuid,
  now: DateTime<Utc>,
) -> Result<User> {
  let user = sqlx::query_as::<_, User>(
    "SELECT id, instance_id, aud, role, email, encrypted_password, email_confirmed_at, phone, phone_confirmed_at, confirmed_at, last_sign_in_at, raw_app_meta_data, raw_user_meta_data, is_super_admin, is_sso_user, is_anonymous, banned_until, deleted_at, created_at, updated_at FROM auth.users WHERE id = $1 FOR SHARE",
  )
  .bind(user_id)
  .fetch_optional(tx.as_mut())
  .await?
  .ok_or(AuthError::PasskeyAuthenticationFailed)?;
  if user.deleted_at.is_some() || user.banned_until.is_some_and(|until| until > now) {
    return Err(AuthError::PasskeyAuthenticationFailed);
  }
  Ok(user)
}

async fn abort_authentication(
  state: &AppState,
  tx: sqlx::Transaction<'_, sqlx::Postgres>,
  rate_limit_keys: &[String],
  error: AuthError,
) -> Result<TokenResponse> {
  drop(tx);
  release_rate_limit_reservations(state, rate_limit_keys).await;
  Err(error)
}

async fn fail_authentication(
  state: &AppState,
  tx: sqlx::Transaction<'_, sqlx::Postgres>,
  rate_limit_keys: &[String],
  client_ip: std::net::IpAddr,
) -> Result<TokenResponse> {
  if let Err(error) = tx.commit().await {
    release_rate_limit_reservations(state, rate_limit_keys).await;
    return Err(AuthError::DatabaseError(error));
  }
  record_authentication_failure(state, client_ip).await;
  Err(AuthError::PasskeyAuthenticationFailed)
}

async fn record_authentication_failure(state: &AppState, client_ip: std::net::IpAddr) {
  if let Err(error) = audit::log_event(
    &state.db,
    state.instance_id,
    Some(client_ip),
    "passkey_login_failed",
    authentication_failure_audit_payload(),
  )
  .await
  {
    tracing::warn!(error = %error, "failed to record passkey authentication audit event");
  }
}

fn passkey_rp(state: &AppState) -> Result<&PasskeyRp> {
  state.passkey.as_deref().ok_or(AuthError::PasskeyDisabled)
}

fn registration_options_rate_limit_keys(user_id: Uuid, client_ip: std::net::IpAddr) -> [String; 2] {
  [
    format!("passkey-register-options:user:{user_id}"),
    format!("passkey-register-options:ip:{client_ip}"),
  ]
}

fn registration_verify_rate_limit_keys(flow_id: Uuid, client_ip: std::net::IpAddr) -> [String; 2] {
  [
    format!("passkey-register-verify:flow:{flow_id}"),
    format!("passkey-register-verify:ip:{client_ip}"),
  ]
}

fn authentication_options_rate_limit_key(client_ip: std::net::IpAddr) -> String {
  format!("passkey-authenticate-options:ip:{client_ip}")
}

fn authentication_verify_rate_limit_keys(flow_id: Uuid, client_ip: std::net::IpAddr) -> [String; 2] {
  [
    format!("passkey-authenticate-verify:flow:{flow_id}"),
    format!("passkey-authenticate-verify:ip:{client_ip}"),
  ]
}

fn user_agent_from_headers(headers: &HeaderMap) -> Option<String> {
  headers
    .get(axum::http::header::USER_AGENT)
    .and_then(|value| value.to_str().ok())
    .map(str::to_owned)
}

async fn reserve_rate_limits(
  state: &AppState,
  keys: &[String],
  max_attempts: u32,
  window_secs: i64,
) -> Result<()> {
  for (index, key) in keys.iter().enumerate() {
    match rate_limit::check_and_record(&state.db, key, max_attempts, window_secs).await {
      Ok(false) => {},
      Ok(true) => {
        release_rate_limit_reservations(state, &keys[..index]).await;
        return Err(AuthError::TooManyRequests);
      },
      Err(error) => {
        release_rate_limit_reservations(state, &keys[..index]).await;
        return Err(error);
      },
    }
  }
  Ok(())
}

async fn release_rate_limit_reservations(state: &AppState, keys: &[String]) {
  for key in keys {
    if let Err(error) = rate_limit::release_attempt(&state.db, key).await {
      tracing::warn!(error = %error, "failed to release passkey rate-limit reservation");
    }
  }
}

async fn release_successful_verification_reservation(state: &AppState, keys: &[String; 2]) {
  if let Err(error) = rate_limit::clear(&state.db, &keys[0]).await {
    tracing::warn!(error = %error, "failed to clear completed passkey flow rate limit");
  }
  if let Err(error) = rate_limit::release_attempt(&state.db, &keys[1]).await {
    tracing::warn!(error = %error, "failed to release successful passkey IP rate-limit reservation");
  }
}

async fn record_registration_failure(
  state: &AppState,
  client_ip: std::net::IpAddr,
  user_id: Uuid,
  flow_id: Uuid,
  reason: &'static str,
) {
  if let Err(error) = audit::log_event(
    &state.db,
    state.instance_id,
    Some(client_ip),
    "passkey_enrollment_failed",
    enrollment_audit_payload(user_id, None, flow_id, Some(reason)),
  )
  .await
  {
    tracing::warn!(error = %error, "failed to record passkey registration audit event");
  }
}

fn authentication_failure_audit_payload() -> serde_json::Value {
  serde_json::json!({ "reason": "authentication_failed" })
}

fn enrollment_audit_payload(
  user_id: Uuid,
  factor_id: Option<Uuid>,
  flow_id: Uuid,
  reason: Option<&'static str>,
) -> serde_json::Value {
  let mut payload = serde_json::json!({
    "user_id": user_id,
    "flow_id": flow_id,
    "factor_type": "webauthn",
  });
  let object = payload.as_object_mut().expect("audit payload is an object");
  if let Some(factor_id) = factor_id {
    object.insert("factor_id".to_owned(), serde_json::json!(factor_id));
  }
  if let Some(reason) = reason {
    object.insert("reason".to_owned(), serde_json::json!(reason));
  }
  payload
}

#[cfg(test)]
mod tests {
  use haya_passkey_rp::{
    PasskeyConfig,
    RegistrationInput,
  };
  use url::Url;

  use super::*;

  fn rp() -> PasskeyRp {
    PasskeyRp::new(PasskeyConfig {
      rp_id: "example.com".to_owned(),
      rp_name: "Haya".to_owned(),
      origins: vec![Url::parse("https://app.example.com").unwrap()],
      challenge_ttl_secs: 300,
      allow_insecure_localhost: false,
    })
    .unwrap()
  }

  #[test]
  fn registration_options_json_uses_browser_field_names_and_base64url_bytes() {
    let start = rp()
      .start_registration(RegistrationInput {
        user_handle: vec![0xfb, 0xff],
        user_name: "user@example.com".to_owned(),
        user_display_name: "user@example.com".to_owned(),
        exclude_credentials: Vec::new(),
      })
      .unwrap();
    let response = PasskeyRegistrationOptionsResponse {
      flow_id: Uuid::nil(),
      expires_at: Utc::now(),
      options: start.options,
    };

    let value = serde_json::to_value(response).unwrap();
    assert!(value.get("flowId").is_some());
    assert!(value.get("expiresAt").is_some());
    let public_key = &value["options"]["publicKey"];
    assert_eq!(public_key["rp"]["id"], "example.com");
    assert_eq!(public_key["user"]["id"], "-_8");
    assert!(
      public_key["challenge"]
        .as_str()
        .is_some_and(|value| !value.contains('='))
    );
    assert!(public_key.get("pubKeyCredParams").is_some());
    assert!(public_key.get("authenticatorSelection").is_some());
  }

  #[test]
  fn authentication_dtos_use_browser_json_and_reject_identity_fields() {
    let request: PasskeyAuthenticationOptionsRequest = serde_json::from_value(serde_json::json!({})).unwrap();
    let _ = request;
    for identity in ["email", "username", "userId"] {
      assert!(
        serde_json::from_value::<PasskeyAuthenticationOptionsRequest>(
          serde_json::json!({ (identity): "account@example.com" }),
        )
        .is_err()
      );
    }

    let start = rp().start_authentication();
    let response = PasskeyAuthenticationOptionsResponse {
      flow_id: Uuid::nil(),
      expires_at: Utc::now(),
      options: start.options,
    };
    let value = serde_json::to_value(response).unwrap();
    assert!(value.get("flowId").is_some());
    assert!(value.get("expiresAt").is_some());
    let public_key = &value["options"]["publicKey"];
    assert_eq!(public_key["rpId"], "example.com");
    assert_eq!(public_key["userVerification"], "required");
    assert!(public_key.get("allowCredentials").is_none());
    assert!(
      public_key["challenge"]
        .as_str()
        .is_some_and(|value| !value.contains('='))
    );

    let grant = serde_json::json!({
      "flowId": Uuid::nil(),
      "credential": {
        "id": "AQ",
        "rawId": "AQ",
        "type": "public-key",
        "response": {
          "clientDataJSON": "e30",
          "authenticatorData": "AQ",
          "signature": "AQ",
          "userHandle": "AQ"
        },
        "authenticatorAttachment": null,
        "clientExtensionResults": {}
      }
    });
    let decoded: PasskeyTokenGrantRequest = serde_json::from_value(grant.clone()).unwrap();
    assert_eq!(decoded.flow_id, Uuid::nil());
    let encoded = serde_json::to_value(decoded.credential).unwrap();
    assert_eq!(encoded["id"], "AQ");
    assert_eq!(encoded["rawId"], "AQ");
    assert_eq!(encoded["type"], "public-key");
    assert_eq!(encoded["response"]["userHandle"], "AQ");
  }

  #[test]
  fn authentication_failure_audits_are_credential_independent() {
    let unknown_credential = authentication_failure_audit_payload();
    let bad_signature = authentication_failure_audit_payload();
    assert_eq!(unknown_credential, bad_signature);
    assert_eq!(unknown_credential["reason"], "authentication_failed");
    for forbidden in [
      "user_id",
      "factor_id",
      "credential_id",
      "user_handle",
      "signature",
    ] {
      assert!(unknown_credential.get(forbidden).is_none());
    }
  }

  #[test]
  fn factor_response_and_audit_payload_exclude_sensitive_credential_material() {
    let now = Utc::now();
    let response = PasskeyFactorResponse {
      id: Uuid::nil(),
      friendly_name: Some("Laptop".to_owned()),
      status: "verified".to_owned(),
      aaguid: Uuid::nil(),
      transports: Vec::new(),
      created_at: now,
      updated_at: now,
      last_challenged_at: None,
    };
    let response_json = serde_json::to_string(&response).unwrap();
    for forbidden in [
      "credentialId",
      "publicKey",
      "clientData",
      "signature",
      "challenge",
    ] {
      assert!(!response_json.contains(forbidden));
    }

    let payload = enrollment_audit_payload(
      Uuid::nil(),
      Some(Uuid::nil()),
      Uuid::nil(),
      Some("protocol_validation"),
    );
    assert!(payload.get("user_id").is_some());
    assert!(payload.get("factor_id").is_some());
    for forbidden in [
      "challenge",
      "credential_id",
      "public_key",
      "client_data",
      "signature",
    ] {
      assert!(payload.get(forbidden).is_none());
    }
  }

  #[test]
  fn disabled_feature_has_stable_public_error() {
    let error = AuthError::PasskeyDisabled;
    assert_eq!(error.to_string(), "Passkeys are not enabled");
  }
}
