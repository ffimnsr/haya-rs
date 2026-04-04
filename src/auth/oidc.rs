use sqlx::PgPool;
use std::collections::HashMap;
use uuid::Uuid;

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use jsonwebtoken::jwk::JwkSet;
use jsonwebtoken::{
  DecodingKey,
  Validation,
  decode,
  decode_header,
};
use rand::RngCore;
use serde::{
  Deserialize,
  Serialize,
};
use serde_json::{
  Map,
  Value,
};
use sha2::{
  Digest,
  Sha256,
};
use url::Url;

use crate::error::AuthError;

const DEFAULT_SCOPES: &[&str] = &["openid", "email", "profile"];

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct OidcProviderConfig {
  pub name: String,
  pub issuer: String,
  pub client_id: String,
  pub client_secret: String,
  pub redirect_uri: String,
  #[serde(default = "default_scopes")]
  pub scopes: Vec<String>,
  #[serde(default = "default_true")]
  pub pkce: bool,
  #[serde(default)]
  pub allowed_email_domains: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct OidcFlowTokens {
  pub state: String,
  pub nonce: String,
  pub pkce_verifier: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OidcDiscoveryDocument {
  pub issuer: String,
  pub authorization_endpoint: String,
  pub token_endpoint: String,
  pub userinfo_endpoint: Option<String>,
  pub jwks_uri: String,
}

#[allow(dead_code)]
#[derive(Debug, Clone, Deserialize)]
pub struct OidcTokenResponse {
  pub access_token: String,
  pub token_type: String,
  pub expires_in: Option<i64>,
  pub refresh_token: Option<String>,
  pub id_token: String,
}

#[derive(Debug, Clone)]
pub struct ValidatedIdToken {
  pub claims: OidcIdTokenClaims,
  pub raw_claims: Value,
}

#[derive(Debug, Clone)]
pub struct NormalizedOidcProfile {
  pub subject: String,
  pub email: Option<String>,
  pub email_verified: bool,
  pub name: Option<String>,
  pub avatar_url: Option<String>,
  pub raw_claims: Value,
}

#[allow(dead_code)]
#[derive(Debug, Clone, Deserialize)]
pub struct OidcIdTokenClaims {
  pub iss: String,
  pub sub: String,
  pub aud: Value,
  pub exp: i64,
  pub iat: Option<i64>,
  pub nonce: Option<String>,
  pub email: Option<String>,
  pub email_verified: Option<bool>,
  pub name: Option<String>,
  pub picture: Option<String>,
  #[serde(flatten)]
  pub extra: Map<String, Value>,
}

#[derive(Debug, sqlx::FromRow)]
struct OidcProviderRow {
  #[allow(dead_code)]
  id: Uuid,
  name: String,
  issuer: String,
  client_id: String,
  client_secret: String,
  redirect_uri: String,
  scopes: Value,
  pkce: bool,
  allowed_email_domains: Value,
}

fn default_scopes() -> Vec<String> {
  DEFAULT_SCOPES.iter().map(|scope| (*scope).to_string()).collect()
}

fn default_true() -> bool {
  true
}

pub async fn load_providers_from_db(db: &PgPool) -> anyhow::Result<HashMap<String, OidcProviderConfig>> {
  let rows: Vec<OidcProviderRow> = sqlx::query_as::<_, OidcProviderRow>(
    "SELECT id, name, issuer, client_id, client_secret, redirect_uri, scopes, pkce, allowed_email_domains FROM auth.oidc_providers ORDER BY created_at ASC NULLS LAST, name ASC",
  )
  .fetch_all(db)
  .await?;

  let mut providers = HashMap::new();
  for row in rows {
    let provider = row.into_config()?;
    provider.validate()?;
    providers.insert(provider.name.clone(), provider);
  }

  Ok(providers)
}

impl OidcProviderConfig {
  fn validate(&self) -> anyhow::Result<()> {
    if self.name.trim().is_empty() {
      anyhow::bail!("OIDC provider name must not be empty");
    }
    if self.client_id.trim().is_empty() || self.client_secret.trim().is_empty() {
      anyhow::bail!(
        "OIDC provider {} must define client_id and client_secret",
        self.name
      );
    }
    Url::parse(&self.issuer)?;
    Url::parse(&self.redirect_uri)?;
    Ok(())
  }
}

impl OidcProviderRow {
  fn into_config(self) -> anyhow::Result<OidcProviderConfig> {
    let scopes = json_array_to_strings(self.scopes, "scopes")?;
    let allowed_email_domains = json_array_to_strings(self.allowed_email_domains, "allowed_email_domains")?;

    Ok(OidcProviderConfig {
      name: self.name,
      issuer: self.issuer,
      client_id: self.client_id,
      client_secret: self.client_secret,
      redirect_uri: self.redirect_uri,
      scopes: if scopes.is_empty() {
        default_scopes()
      } else {
        scopes
      },
      pkce: self.pkce,
      allowed_email_domains,
    })
  }
}

fn json_array_to_strings(value: Value, field_name: &str) -> anyhow::Result<Vec<String>> {
  let Value::Array(items) = value else {
    anyhow::bail!("OIDC provider field {field_name} must be a JSON array");
  };

  items
    .into_iter()
    .map(|item| match item {
      Value::String(value) => Ok(value),
      _ => anyhow::bail!("OIDC provider field {field_name} must contain only strings"),
    })
    .collect()
}

pub fn generate_flow_tokens(use_pkce: bool) -> OidcFlowTokens {
  OidcFlowTokens {
    state: random_token(32),
    nonce: random_token(32),
    pkce_verifier: use_pkce.then(|| random_token(48)),
  }
}

pub fn build_authorization_url(
  discovery: &OidcDiscoveryDocument,
  config: &OidcProviderConfig,
  flow: &OidcFlowTokens,
) -> Result<Url, AuthError> {
  let mut url = Url::parse(&discovery.authorization_endpoint)
    .map_err(|e| AuthError::InternalError(format!("invalid authorization endpoint: {e}")))?;
  let mut query = url.query_pairs_mut();
  query.append_pair("response_type", "code");
  query.append_pair("client_id", &config.client_id);
  query.append_pair("redirect_uri", &config.redirect_uri);
  query.append_pair("state", &flow.state);
  query.append_pair("nonce", &flow.nonce);
  query.append_pair("scope", &config.scopes.join(" "));

  if let Some(ref verifier) = flow.pkce_verifier {
    query.append_pair("code_challenge_method", "S256");
    query.append_pair("code_challenge", &pkce_challenge(verifier));
  }
  drop(query);
  Ok(url)
}

pub async fn discover_provider(
  client: &reqwest::Client,
  config: &OidcProviderConfig,
) -> Result<OidcDiscoveryDocument, AuthError> {
  let issuer = config.issuer.trim_end_matches('/');
  let discovery_url = format!("{issuer}/.well-known/openid-configuration");
  let response = client
    .get(discovery_url)
    .send()
    .await
    .map_err(|e| AuthError::InternalError(format!("OIDC discovery request failed: {e}")))?;

  if !response.status().is_success() {
    return Err(AuthError::InternalError(format!(
      "OIDC discovery failed with status {}",
      response.status()
    )));
  }

  let discovery: OidcDiscoveryDocument = response
    .json()
    .await
    .map_err(|e| AuthError::InternalError(format!("invalid OIDC discovery document: {e}")))?;

  if discovery.issuer.trim_end_matches('/') != issuer {
    return Err(AuthError::ValidationFailed(
      "OIDC issuer mismatch in discovery document".to_string(),
    ));
  }

  Ok(discovery)
}

pub async fn exchange_code(
  client: &reqwest::Client,
  discovery: &OidcDiscoveryDocument,
  config: &OidcProviderConfig,
  code: &str,
  pkce_verifier: Option<&str>,
) -> Result<OidcTokenResponse, AuthError> {
  let mut form = vec![
    ("grant_type", "authorization_code".to_string()),
    ("code", code.to_string()),
    ("redirect_uri", config.redirect_uri.clone()),
    ("client_id", config.client_id.clone()),
    ("client_secret", config.client_secret.clone()),
  ];

  if let Some(verifier) = pkce_verifier {
    form.push(("code_verifier", verifier.to_string()));
  }

  let response = client
    .post(&discovery.token_endpoint)
    .form(&form)
    .send()
    .await
    .map_err(|e| AuthError::InternalError(format!("OIDC token exchange failed: {e}")))?;

  if !response.status().is_success() {
    let status = response.status();
    let body = response.text().await.unwrap_or_default();
    tracing::warn!(%status, body = %body, "OIDC token exchange failed");
    return Err(AuthError::ValidationFailed(
      "OIDC token exchange failed".to_string(),
    ));
  }

  response
    .json()
    .await
    .map_err(|e| AuthError::InternalError(format!("invalid OIDC token response: {e}")))
}

pub async fn fetch_userinfo(
  client: &reqwest::Client,
  discovery: &OidcDiscoveryDocument,
  access_token: &str,
) -> Result<Option<Value>, AuthError> {
  let Some(ref endpoint) = discovery.userinfo_endpoint else {
    return Ok(None);
  };

  let response = client
    .get(endpoint)
    .bearer_auth(access_token)
    .send()
    .await
    .map_err(|e| AuthError::InternalError(format!("OIDC userinfo request failed: {e}")))?;

  if !response.status().is_success() {
    return Ok(None);
  }

  let value = response
    .json()
    .await
    .map_err(|e| AuthError::InternalError(format!("invalid OIDC userinfo payload: {e}")))?;
  Ok(Some(value))
}

pub async fn validate_id_token(
  client: &reqwest::Client,
  discovery: &OidcDiscoveryDocument,
  config: &OidcProviderConfig,
  id_token: &str,
  expected_nonce: &str,
) -> Result<ValidatedIdToken, AuthError> {
  let header = decode_header(id_token).map_err(|_| AuthError::InvalidToken)?;
  let jwks: JwkSet = client
    .get(&discovery.jwks_uri)
    .send()
    .await
    .map_err(|e| AuthError::InternalError(format!("OIDC JWKS request failed: {e}")))?
    .json()
    .await
    .map_err(|e| AuthError::InternalError(format!("invalid OIDC JWKS payload: {e}")))?;

  let jwk = if let Some(ref kid) = header.kid {
    jwks
      .find(kid)
      .ok_or_else(|| AuthError::ValidationFailed("OIDC signing key not found".to_string()))?
  } else {
    jwks
      .keys
      .first()
      .ok_or_else(|| AuthError::ValidationFailed("OIDC provider did not expose signing keys".to_string()))?
  };

  let key = DecodingKey::from_jwk(jwk).map_err(|e| AuthError::InternalError(e.to_string()))?;
  let mut validation = Validation::new(header.alg);
  validation.set_audience(std::slice::from_ref(&config.client_id));
  validation.set_issuer(std::slice::from_ref(&discovery.issuer));

  let raw_claims = decode::<Value>(id_token, &key, &validation)
    .map_err(|_| AuthError::InvalidToken)?
    .claims;
  let claims: OidcIdTokenClaims = serde_json::from_value(raw_claims.clone())
    .map_err(|e| AuthError::InternalError(format!("invalid OIDC id_token claims: {e}")))?;

  if claims.nonce.as_deref() != Some(expected_nonce) {
    return Err(AuthError::ValidationFailed(
      "OIDC nonce validation failed".to_string(),
    ));
  }

  Ok(ValidatedIdToken { claims, raw_claims })
}

pub fn normalize_profile(id_token: &ValidatedIdToken, userinfo: Option<Value>) -> NormalizedOidcProfile {
  let email = userinfo
    .as_ref()
    .and_then(|value| value.get("email"))
    .and_then(Value::as_str)
    .map(str::to_string)
    .or_else(|| id_token.claims.email.clone());
  let email_verified = userinfo
    .as_ref()
    .and_then(|value| value.get("email_verified"))
    .and_then(Value::as_bool)
    .or(id_token.claims.email_verified)
    .unwrap_or(false);
  let name = userinfo
    .as_ref()
    .and_then(|value| value.get("name"))
    .and_then(Value::as_str)
    .map(str::to_string)
    .or_else(|| id_token.claims.name.clone());
  let avatar_url = userinfo
    .as_ref()
    .and_then(|value| value.get("picture"))
    .and_then(Value::as_str)
    .map(str::to_string)
    .or_else(|| id_token.claims.picture.clone());

  let mut raw_claims = match &id_token.raw_claims {
    Value::Object(map) => map.clone(),
    _ => Map::new(),
  };
  if let Some(Value::Object(userinfo_map)) = userinfo {
    raw_claims.insert("userinfo".to_string(), Value::Object(userinfo_map));
  }

  NormalizedOidcProfile {
    subject: id_token.claims.sub.clone(),
    email,
    email_verified,
    name,
    avatar_url,
    raw_claims: Value::Object(raw_claims),
  }
}

pub fn enforce_allowed_domains(
  config: &OidcProviderConfig,
  profile: &NormalizedOidcProfile,
) -> Result<(), AuthError> {
  if config.allowed_email_domains.is_empty() {
    return Ok(());
  }

  let Some(email) = profile.email.as_deref() else {
    return Err(AuthError::ValidationFailed(
      "OIDC provider did not supply an email address".to_string(),
    ));
  };

  let domain = email
    .split('@')
    .nth(1)
    .ok_or_else(|| AuthError::ValidationFailed("OIDC email address is invalid".to_string()))?;
  let domain_allowed = config
    .allowed_email_domains
    .iter()
    .any(|allowed| allowed.eq_ignore_ascii_case(domain));

  if !domain_allowed {
    return Err(AuthError::NotAuthorized);
  }
  Ok(())
}

pub fn provider_names(providers: &HashMap<String, OidcProviderConfig>) -> Vec<String> {
  let mut names = providers.keys().cloned().collect::<Vec<_>>();
  names.sort();
  names
}

fn pkce_challenge(verifier: &str) -> String {
  let digest = Sha256::digest(verifier.as_bytes());
  URL_SAFE_NO_PAD.encode(digest)
}

fn random_token(bytes: usize) -> String {
  let mut data = vec![0u8; bytes];
  rand::rng().fill_bytes(&mut data);
  URL_SAFE_NO_PAD.encode(data)
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn converts_row_to_provider_config() {
    let row = OidcProviderRow {
      id: Uuid::new_v4(),
      name: "acme".to_string(),
      issuer: "https://issuer.example.com".to_string(),
      client_id: "abc".to_string(),
      client_secret: "secret".to_string(),
      redirect_uri: "https://app.example.com/callback".to_string(),
      scopes: serde_json::json!(["openid", "email", "profile"]),
      pkce: true,
      allowed_email_domains: serde_json::json!(["example.com"]),
    };

    let provider = row.into_config().unwrap();
    assert_eq!(provider.scopes, default_scopes());
    assert!(provider.pkce);
    assert_eq!(provider.allowed_email_domains, vec!["example.com".to_string()]);
  }

  #[test]
  fn authorization_url_contains_required_params() {
    let discovery = OidcDiscoveryDocument {
      issuer: "https://issuer.example.com".to_string(),
      authorization_endpoint: "https://issuer.example.com/authorize".to_string(),
      token_endpoint: "https://issuer.example.com/token".to_string(),
      userinfo_endpoint: None,
      jwks_uri: "https://issuer.example.com/jwks".to_string(),
    };
    let config = OidcProviderConfig {
      name: "acme".to_string(),
      issuer: "https://issuer.example.com".to_string(),
      client_id: "client".to_string(),
      client_secret: "secret".to_string(),
      redirect_uri: "https://app.example.com/callback".to_string(),
      scopes: default_scopes(),
      pkce: true,
      allowed_email_domains: vec![],
    };
    let flow = OidcFlowTokens {
      state: "state".to_string(),
      nonce: "nonce".to_string(),
      pkce_verifier: Some("verifier".to_string()),
    };

    let url = build_authorization_url(&discovery, &config, &flow).unwrap();
    let query = url.query_pairs().collect::<HashMap<_, _>>();

    assert_eq!(query.get("response_type"), Some(&"code".into()));
    assert_eq!(query.get("state"), Some(&"state".into()));
    assert_eq!(query.get("nonce"), Some(&"nonce".into()));
    assert_eq!(query.get("code_challenge_method"), Some(&"S256".into()));
  }

  #[test]
  fn normalizes_profile_preferring_userinfo() {
    let id_token = ValidatedIdToken {
      claims: OidcIdTokenClaims {
        iss: "https://issuer.example.com".to_string(),
        sub: "subject-1".to_string(),
        aud: Value::String("client".to_string()),
        exp: 100,
        iat: None,
        nonce: Some("nonce".to_string()),
        email: Some("id-token@example.com".to_string()),
        email_verified: Some(false),
        name: Some("ID Token".to_string()),
        picture: None,
        extra: Map::new(),
      },
      raw_claims: serde_json::json!({"sub":"subject-1"}),
    };

    let profile = normalize_profile(
      &id_token,
      Some(serde_json::json!({
        "email":"userinfo@example.com",
        "email_verified": true,
        "name":"User Info",
        "picture":"https://example.com/avatar.png"
      })),
    );

    assert_eq!(profile.subject, "subject-1");
    assert_eq!(profile.email.as_deref(), Some("userinfo@example.com"));
    assert!(profile.email_verified);
    assert_eq!(profile.name.as_deref(), Some("User Info"));
    assert_eq!(
      profile.avatar_url.as_deref(),
      Some("https://example.com/avatar.png")
    );
  }
}
