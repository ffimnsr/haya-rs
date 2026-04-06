use sqlx::PgPool;
use std::collections::HashMap;
use std::net::{
  IpAddr,
  Ipv4Addr,
  Ipv6Addr,
  SocketAddr,
};
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
use serde::de::DeserializeOwned;
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

use crate::auth::jwt::JWT_LEEWAY_SECONDS;
use crate::error::AuthError;

const DEFAULT_SCOPES: &[&str] = &["openid", "email", "profile"];
const JWKS_CACHE_TTL_MINUTES: i64 = 10;

#[derive(Debug, Clone)]
pub struct CachedJwks {
  pub jwks: JwkSet,
  pub fetched_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct OidcProviderConfig {
  pub name: String,
  pub issuer: String,
  pub client_id: String,
  #[serde(skip)]
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
    validate_discovery_issuer(&self.issuer)?;
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
  use_form_post: bool,
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
  if use_form_post {
    query.append_pair("response_mode", "form_post");
  }

  if let Some(ref verifier) = flow.pkce_verifier {
    query.append_pair("code_challenge_method", "S256");
    query.append_pair("code_challenge", &pkce_challenge(verifier));
  }
  drop(query);
  Ok(url)
}

pub async fn discover_provider(
  _client: &reqwest::Client,
  config: &OidcProviderConfig,
) -> Result<OidcDiscoveryDocument, AuthError> {
  let issuer = validate_discovery_issuer(&config.issuer)?;
  let discovery_url = format!("{issuer}/.well-known/openid-configuration");
  let response = get_with_resolved_client(&discovery_url)
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

  if discovery.issuer.trim_end_matches('/') != issuer.as_str().trim_end_matches('/') {
    return Err(AuthError::ValidationFailed(
      "OIDC issuer mismatch in discovery document".to_string(),
    ));
  }
  resolve_public_endpoint(&discovery.authorization_endpoint).await?;
  resolve_public_endpoint(&discovery.token_endpoint).await?;
  if let Some(endpoint) = discovery.userinfo_endpoint.as_deref() {
    resolve_public_endpoint(endpoint).await?;
  }
  resolve_public_endpoint(&discovery.jwks_uri).await?;

  Ok(discovery)
}

fn validate_discovery_issuer(issuer: &str) -> Result<Url, AuthError> {
  let url =
    Url::parse(issuer).map_err(|e| AuthError::ValidationFailed(format!("invalid OIDC issuer: {e}")))?;
  if url.scheme() != "https" {
    return Err(AuthError::ValidationFailed(
      "OIDC issuer must use https".to_string(),
    ));
  }
  if url.host_str().is_none() {
    return Err(AuthError::ValidationFailed(
      "OIDC issuer must include a host".to_string(),
    ));
  }
  Ok(url)
}

fn is_disallowed_oidc_ip(ip: &IpAddr) -> bool {
  match ip {
    IpAddr::V4(ip) => {
      ip.is_private()
        || ip.is_loopback()
        || ip.is_link_local()
        || ip.is_multicast()
        || ip.is_broadcast()
        || is_documentation_ipv4(ip)
        || ip.is_unspecified()
    },
    IpAddr::V6(ip) => {
      ip.is_loopback()
        || ip.is_multicast()
        || ip.is_unspecified()
        || ip.is_unique_local()
        || ip.is_unicast_link_local()
        || is_documentation_ipv6(ip)
    },
  }
}

fn is_documentation_ipv4(ip: &Ipv4Addr) -> bool {
  let octets = ip.octets();
  matches!(octets, [192, 0, 2, _] | [198, 51, 100, _] | [203, 0, 113, _])
}

fn is_documentation_ipv6(ip: &Ipv6Addr) -> bool {
  let segments = ip.segments();
  segments[0] == 0x2001 && segments[1] == 0x0db8
}

pub async fn exchange_code(
  _client: &reqwest::Client,
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

  let client = client_for_endpoint(&discovery.token_endpoint).await?;
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
  _client: &reqwest::Client,
  discovery: &OidcDiscoveryDocument,
  access_token: &str,
) -> Result<Option<Value>, AuthError> {
  let Some(ref endpoint) = discovery.userinfo_endpoint else {
    return Ok(None);
  };

  let client = client_for_endpoint(endpoint).await?;
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
  state: &crate::state::AppState,
  discovery: &OidcDiscoveryDocument,
  config: &OidcProviderConfig,
  id_token: &str,
  expected_nonce: &str,
) -> Result<ValidatedIdToken, AuthError> {
  let header = decode_header(id_token).map_err(|_| AuthError::InvalidToken)?;
  let jwks = get_cached_jwks(state, &discovery.jwks_uri).await?;

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
  validation.leeway = JWT_LEEWAY_SECONDS;

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

async fn get_cached_jwks(state: &crate::state::AppState, jwks_uri: &str) -> Result<JwkSet, AuthError> {
  {
    let cache = state.oidc_jwks_cache.read().await;
    if let Some(entry) = cache.get(jwks_uri)
      && entry.fetched_at + chrono::Duration::minutes(JWKS_CACHE_TTL_MINUTES) > chrono::Utc::now()
    {
      return Ok(entry.jwks.clone());
    }
  }

  let jwks: JwkSet = get_json_with_resolved_client(jwks_uri)
    .await
    .map_err(|e| AuthError::InternalError(format!("OIDC JWKS request failed: {e}")))?;
  let mut cache = state.oidc_jwks_cache.write().await;
  cache.insert(
    jwks_uri.to_string(),
    CachedJwks {
      jwks: jwks.clone(),
      fetched_at: chrono::Utc::now(),
    },
  );
  Ok(jwks)
}

async fn resolve_public_endpoint(endpoint: &str) -> Result<(Url, Vec<SocketAddr>), AuthError> {
  let url =
    Url::parse(endpoint).map_err(|e| AuthError::ValidationFailed(format!("invalid OIDC endpoint: {e}")))?;
  if url.scheme() != "https" {
    return Err(AuthError::ValidationFailed(
      "OIDC endpoints must use https".to_string(),
    ));
  }
  let host = url
    .host_str()
    .ok_or_else(|| AuthError::ValidationFailed("OIDC endpoint must include a host".to_string()))?;
  let port = url
    .port_or_known_default()
    .ok_or_else(|| AuthError::ValidationFailed("OIDC endpoint must include a known port".to_string()))?;
  let addrs = resolve_public_host(host, port).await?;
  Ok((url, addrs))
}

async fn resolve_public_host(host: &str, port: u16) -> Result<Vec<SocketAddr>, AuthError> {
  if let Ok(ip) = host.parse::<IpAddr>() {
    if is_disallowed_oidc_ip(&ip) {
      return Err(AuthError::ValidationFailed(
        "OIDC endpoint host must not resolve to a private or local IP".to_string(),
      ));
    }
    return Ok(vec![SocketAddr::new(ip, port)]);
  }

  let addrs = tokio::net::lookup_host((host, port))
    .await
    .map_err(|e| AuthError::InternalError(format!("failed to resolve OIDC host: {e}")))?
    .collect::<Vec<_>>();
  if addrs.is_empty() {
    return Err(AuthError::ValidationFailed(
      "OIDC endpoint host did not resolve to any address".to_string(),
    ));
  }
  if addrs.iter().any(|addr| is_disallowed_oidc_ip(&addr.ip())) {
    return Err(AuthError::ValidationFailed(
      "OIDC endpoint host must not resolve to a private or local IP".to_string(),
    ));
  }
  Ok(addrs)
}

async fn client_for_endpoint(endpoint: &str) -> Result<reqwest::Client, AuthError> {
  let (url, addrs) = resolve_public_endpoint(endpoint).await?;
  let host = url
    .host_str()
    .ok_or_else(|| AuthError::ValidationFailed("OIDC endpoint must include a host".to_string()))?;
  reqwest::Client::builder()
    .redirect(reqwest::redirect::Policy::none())
    .resolve_to_addrs(host, &addrs)
    .build()
    .map_err(|e| AuthError::InternalError(format!("failed to build OIDC client: {e}")))
}

async fn get_with_resolved_client(endpoint: &str) -> Result<reqwest::Response, AuthError> {
  let client = client_for_endpoint(endpoint).await?;
  client
    .get(endpoint)
    .send()
    .await
    .map_err(|e| AuthError::InternalError(format!("OIDC request failed: {e}")))
}

async fn get_json_with_resolved_client<T: DeserializeOwned>(endpoint: &str) -> Result<T, AuthError> {
  get_with_resolved_client(endpoint)
    .await?
    .json()
    .await
    .map_err(|e| AuthError::InternalError(format!("invalid OIDC payload: {e}")))
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

    let url = build_authorization_url(&discovery, &config, &flow, false).unwrap();
    let query = url.query_pairs().collect::<HashMap<_, _>>();

    assert_eq!(query.get("response_type"), Some(&"code".into()));
    assert_eq!(query.get("state"), Some(&"state".into()));
    assert_eq!(query.get("nonce"), Some(&"nonce".into()));
    assert_eq!(query.get("code_challenge_method"), Some(&"S256".into()));
  }

  #[test]
  fn rejects_non_https_issuer() {
    let error = validate_discovery_issuer("http://issuer.example.com").unwrap_err();
    assert!(matches!(error, AuthError::ValidationFailed(_)));
  }

  #[test]
  fn rejects_private_ip_issuer_hosts() {
    assert!(is_disallowed_oidc_ip(&"127.0.0.1".parse().unwrap()));
    assert!(is_disallowed_oidc_ip(&"169.254.169.254".parse().unwrap()));
    assert!(!is_disallowed_oidc_ip(&"8.8.8.8".parse().unwrap()));
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
