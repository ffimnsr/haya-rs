use url::{
  Host,
  Url,
};

use crate::RpError;

const MIN_CHALLENGE_TTL_SECS: i64 = 60;
const MAX_CHALLENGE_TTL_SECS: i64 = 600;
const DEFAULT_CHALLENGE_TTL_SECS: i64 = 300;

/// Immutable relying-party settings validated by [`crate::PasskeyRp::new`].
#[derive(Debug, Clone)]
pub struct PasskeyConfig {
  pub rp_id: String,
  pub rp_name: String,
  pub origins: Vec<Url>,
  pub challenge_ttl_secs: i64,
  pub allow_insecure_localhost: bool,
}

impl PasskeyConfig {
  pub(crate) fn validate(mut self) -> Result<Self, RpError> {
    self.rp_id = normalize_rp_id(&self.rp_id)?;
    self.rp_name = self.rp_name.trim().to_owned();
    if self.rp_name.is_empty() {
      return Err(RpError::EmptyRpName);
    }
    if self.origins.is_empty() {
      return Err(RpError::EmptyOrigins);
    }
    if !(MIN_CHALLENGE_TTL_SECS..=MAX_CHALLENGE_TTL_SECS).contains(&self.challenge_ttl_secs) {
      return Err(RpError::InvalidChallengeTtl);
    }

    self.origins = self
      .origins
      .into_iter()
      .map(|origin| normalize_origin(origin, &self.rp_id, self.allow_insecure_localhost))
      .collect::<Result<Vec<_>, _>>()?;
    self.origins.sort_by_key(origin_key);
    self
      .origins
      .dedup_by(|left, right| origin_key(left) == origin_key(right));
    Ok(self)
  }

  pub(crate) fn origin_is_allowed(&self, origin: Url) -> bool {
    normalize_origin(origin, &self.rp_id, self.allow_insecure_localhost)
      .ok()
      .is_some_and(|candidate| {
        self
          .origins
          .iter()
          .any(|allowed| origin_key(allowed) == origin_key(&candidate))
      })
  }
}

impl Default for PasskeyConfig {
  fn default() -> Self {
    Self {
      rp_id: String::new(),
      rp_name: String::new(),
      origins: Vec::new(),
      challenge_ttl_secs: DEFAULT_CHALLENGE_TTL_SECS,
      allow_insecure_localhost: false,
    }
  }
}

fn normalize_rp_id(value: &str) -> Result<String, RpError> {
  let value = value.trim();
  if value.is_empty()
    || value.contains("://")
    || value.contains(['/', ':', '?', '#', '@'])
    || value.starts_with('.')
    || value.ends_with('.')
  {
    return Err(RpError::InvalidRpId);
  }

  let parsed = Url::parse(&format!("https://{value}")).map_err(|_| RpError::InvalidRpId)?;
  let host = parsed.host().ok_or(RpError::InvalidRpId)?;
  match host {
    Host::Domain(domain) if !domain.is_empty() => Ok(domain.to_owned()),
    Host::Ipv4(_) | Host::Ipv6(_) | Host::Domain(_) => Err(RpError::InvalidRpId),
  }
}

fn normalize_origin(mut origin: Url, rp_id: &str, allow_insecure_localhost: bool) -> Result<Url, RpError> {
  let original = origin.to_string();
  if !origin.username().is_empty()
    || origin.password().is_some()
    || origin.query().is_some()
    || origin.fragment().is_some()
    || origin.path() != "/"
  {
    return Err(RpError::InvalidOrigin(original));
  }

  let host = origin
    .host_str()
    .ok_or_else(|| RpError::InvalidOrigin(original.clone()))?;
  if host != rp_id && !host.ends_with(&format!(".{rp_id}")) {
    return Err(RpError::InvalidOrigin(original));
  }

  let secure = origin.scheme() == "https";
  let allowed_local_http =
    origin.scheme() == "http" && allow_insecure_localhost && matches!(host, "localhost" | "127.0.0.1");
  if !secure && !allowed_local_http {
    return Err(RpError::InvalidOrigin(original));
  }

  let effective_port = origin
    .port_or_known_default()
    .ok_or_else(|| RpError::InvalidOrigin(original.clone()))?;
  origin.set_path("");
  origin
    .set_port(Some(effective_port))
    .map_err(|()| RpError::InvalidOrigin(original))?;
  Ok(origin)
}

fn origin_key(origin: &Url) -> (String, String, u16) {
  (
    origin.scheme().to_owned(),
    origin.host_str().unwrap_or_default().to_owned(),
    origin.port_or_known_default().unwrap_or_default(),
  )
}

#[cfg(test)]
mod tests {
  use super::*;

  fn config(rp_id: &str, origins: &[&str]) -> PasskeyConfig {
    PasskeyConfig {
      rp_id: rp_id.to_owned(),
      rp_name: "Haya".to_owned(),
      origins: origins.iter().map(|value| Url::parse(value).unwrap()).collect(),
      challenge_ttl_secs: 300,
      allow_insecure_localhost: false,
    }
  }

  #[test]
  fn accepts_rp_origin_and_subdomain_origin() {
    assert!(config("example.com", &["https://example.com"]).validate().is_ok());
    assert!(
      config("example.com", &["https://app.example.com"])
        .validate()
        .is_ok()
    );
  }

  #[test]
  fn rejects_unrelated_and_suffix_confusion_origins() {
    assert!(
      config("example.com", &["https://example.net"])
        .validate()
        .is_err()
    );
    assert!(
      config("example.com", &["https://badexample.com"])
        .validate()
        .is_err()
    );
  }

  #[test]
  fn rejects_non_origin_url_components() {
    for origin in [
      "https://example.com/path",
      "https://example.com/?query=yes",
      "https://example.com/#fragment",
      "https://user@example.com/",
      "https://user:password@example.com/",
    ] {
      assert!(
        config("example.com", &[origin]).validate().is_err(),
        "accepted {origin}"
      );
    }
  }

  #[test]
  fn controls_insecure_local_origins() {
    assert!(
      config("localhost", &["http://localhost:9999"])
        .validate()
        .is_err()
    );

    let mut localhost = config("localhost", &["http://localhost:9999"]);
    localhost.allow_insecure_localhost = true;
    assert!(localhost.validate().is_ok());

    let mut loopback = config("127.0.0.1", &["http://127.0.0.1:9999"]);
    loopback.allow_insecure_localhost = true;
    assert!(matches!(loopback.validate(), Err(RpError::InvalidRpId)));

    let mut remote = config("example.com", &["http://example.com"]);
    remote.allow_insecure_localhost = true;
    assert!(remote.validate().is_err());
  }

  #[test]
  fn enforces_challenge_ttl_bounds() {
    for ttl in [59, 601] {
      let mut value = config("example.com", &["https://example.com"]);
      value.challenge_ttl_secs = ttl;
      assert!(matches!(value.validate(), Err(RpError::InvalidChallengeTtl)));
    }
    for ttl in [60, 600] {
      let mut value = config("example.com", &["https://example.com"]);
      value.challenge_ttl_secs = ttl;
      assert!(value.validate().is_ok());
    }
  }

  #[test]
  fn sorts_and_deduplicates_normalized_origins() {
    let value = config(
      "example.com",
      &[
        "https://example.com:443",
        "https://app.example.com",
        "https://example.com",
      ],
    )
    .validate()
    .unwrap();
    assert_eq!(value.origins.len(), 2);
    assert_eq!(value.origins[0].host_str(), Some("app.example.com"));
    assert_eq!(value.origins[1].host_str(), Some("example.com"));
  }

  #[test]
  fn rejects_ip_rp_ids_and_malformed_rp_ids() {
    for rp_id in [
      "127.0.0.1",
      "https://example.com",
      "example.com:443",
      "example.com/path",
    ] {
      assert!(config(rp_id, &["https://example.com"]).validate().is_err());
    }
  }
}
