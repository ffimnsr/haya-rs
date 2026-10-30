use std::fmt;
use std::time::Duration;

use anyhow::{
  Context,
  bail,
};
use url::Url;

use super::verify::DEFAULT_VERIFY_URL;

/// Validated Turnstile configuration.
#[derive(Clone)]
pub struct TurnstileConfig {
  pub(super) secret_key: String,
  pub(super) allowed_hostnames: Vec<String>,
  pub(super) expected_action: Option<String>,
  pub(super) verify_url: String,
  pub(super) timeout: Duration,
}

impl fmt::Debug for TurnstileConfig {
  fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
    formatter
      .debug_struct("TurnstileConfig")
      .field("secret_key", &"<redacted>")
      .field("allowed_hostnames", &self.allowed_hostnames)
      .field("expected_action", &self.expected_action)
      .field("verify_url", &self.verify_url)
      .field("timeout", &self.timeout)
      .finish()
  }
}

impl TurnstileConfig {
  /// Build a config from trusted startup values.
  pub fn new(
    secret_key: String,
    allowed_hostnames: Vec<String>,
    expected_action: Option<String>,
    verify_url: Option<String>,
    timeout: Duration,
  ) -> anyhow::Result<Self> {
    if secret_key.trim().is_empty() {
      bail!("TURNSTILE_SECRET_KEY must not be empty");
    }
    let allowed_hostnames = normalize_hostnames(allowed_hostnames)?;
    if allowed_hostnames.is_empty() {
      bail!("TURNSTILE_ALLOWED_HOSTNAMES must not be empty when Turnstile is enabled");
    }
    let expected_action = expected_action
      .map(|value| value.trim().to_string())
      .filter(|value| !value.is_empty());
    let verify_url = verify_url.unwrap_or_else(|| DEFAULT_VERIFY_URL.to_string());
    let parsed = Url::parse(&verify_url).context("TURNSTILE_VERIFY_URL is not a valid URL")?;
    if parsed.scheme() != "https" && !is_loopback_http(&parsed) {
      bail!("TURNSTILE_VERIFY_URL must use HTTPS; HTTP is allowed only for loopback");
    }
    if timeout.is_zero() {
      bail!("TURNSTILE_TIMEOUT_SECS must be positive");
    }

    Ok(Self {
      secret_key,
      allowed_hostnames,
      expected_action,
      verify_url,
      timeout,
    })
  }
}

fn normalize_hostnames(values: Vec<String>) -> anyhow::Result<Vec<String>> {
  let mut hosts = Vec::new();
  for value in values {
    let host = value.trim().trim_end_matches('.').to_ascii_lowercase();
    if host.is_empty() {
      continue;
    }
    if host.contains("://")
      || host.contains('/')
      || host
        .chars()
        .any(|character| !(character.is_ascii_alphanumeric() || character == '.' || character == '-'))
    {
      bail!("TURNSTILE_ALLOWED_HOSTNAMES contains an invalid hostname: {value}");
    }
    hosts.push(host);
  }
  hosts.sort();
  hosts.dedup();
  Ok(hosts)
}

fn is_loopback_http(url: &Url) -> bool {
  url.scheme() == "http"
    && matches!(
      url.host_str(),
      Some("localhost") | Some("127.0.0.1") | Some("::1")
    )
}
