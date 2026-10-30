use serde::Deserialize;

use super::config::TurnstileConfig;

pub const DEFAULT_VERIFY_URL: &str = "https://challenges.cloudflare.com/turnstile/v0/siteverify";
pub(super) const MAX_TOKEN_BYTES: usize = 4096;
const MAX_RESPONSE_BYTES: u64 = 64 * 1024;

/// Result of a Turnstile verification call.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TurnstileError {
  /// Token was missing, invalid, expired, replayed, or did not match the
  /// configured hostname/action.
  Rejected,
  /// Verification service was unreachable, timed out, or returned an
  /// unusable response. Callers should fail closed and report retryable.
  Unavailable,
}

#[derive(Debug, Deserialize)]
struct SiteverifyResponse {
  #[serde(default)]
  success: bool,
  #[serde(default, rename = "error-codes")]
  error_codes: Vec<String>,
  #[serde(default)]
  hostname: Option<String>,
  #[serde(default)]
  action: Option<String>,
}

impl TurnstileConfig {
  /// Verify a Turnstile response token with Cloudflare's siteverify endpoint.
  pub async fn verify(&self, http_client: &reqwest::Client, token: &str) -> Result<(), TurnstileError> {
    let token = token.trim();
    if token.is_empty() || token.len() > MAX_TOKEN_BYTES {
      return Err(TurnstileError::Rejected);
    }

    let body = url::form_urlencoded::Serializer::new(String::new())
      .append_pair("secret", &self.secret_key)
      .append_pair("response", token)
      .finish();

    let payload = tokio::time::timeout(self.timeout, self.request_siteverify(http_client, body))
      .await
      .map_err(|_| TurnstileError::Unavailable)??;

    if !payload.success {
      tracing::warn!(
        error_codes = ?payload.error_codes,
        "Turnstile rejected a signup verification token"
      );
      return Err(TurnstileError::Rejected);
    }

    let hostname = payload.hostname.as_deref().unwrap_or_default();
    if !self
      .allowed_hostnames
      .iter()
      .any(|allowed| allowed.eq_ignore_ascii_case(hostname))
    {
      tracing::warn!(
        hostname = %hostname,
        "Turnstile verification returned an unexpected hostname"
      );
      return Err(TurnstileError::Rejected);
    }

    if let Some(expected_action) = &self.expected_action
      && payload.action.as_deref() != Some(expected_action.as_str())
    {
      tracing::warn!(
        action = ?payload.action,
        "Turnstile verification returned an unexpected action"
      );
      return Err(TurnstileError::Rejected);
    }

    Ok(())
  }

  async fn request_siteverify(
    &self,
    http_client: &reqwest::Client,
    body: String,
  ) -> Result<SiteverifyResponse, TurnstileError> {
    let response = http_client
      .post(&self.verify_url)
      .header(reqwest::header::CONTENT_TYPE, "application/x-www-form-urlencoded")
      .body(body)
      .send()
      .await
      .map_err(|_| TurnstileError::Unavailable)?;

    if !response.status().is_success() {
      return Err(TurnstileError::Unavailable);
    }
    if response
      .content_length()
      .is_some_and(|length| length > MAX_RESPONSE_BYTES)
    {
      return Err(TurnstileError::Unavailable);
    }

    let bytes = response.bytes().await.map_err(|_| TurnstileError::Unavailable)?;
    if bytes.len() as u64 > MAX_RESPONSE_BYTES {
      return Err(TurnstileError::Unavailable);
    }

    serde_json::from_slice(&bytes).map_err(|_| TurnstileError::Unavailable)
  }
}
