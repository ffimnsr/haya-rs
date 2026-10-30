use serde::Deserialize;

#[derive(Debug, Deserialize)]
pub(crate) struct SignupRequest {
  pub email: Option<String>,
  pub password: Option<String>,
  pub phone: Option<String>,
  pub data: Option<serde_json::Value>,
  /// Explicit Turnstile token. When absent, the GoTrue-compatible
  /// `gotrue_meta_security.captcha_token` field is used instead.
  pub turnstile_token: Option<String>,
  pub gotrue_meta_security: Option<GoTrueMetaSecurity>,
}

#[derive(Debug, Deserialize)]
pub(crate) struct GoTrueMetaSecurity {
  pub captcha_token: Option<String>,
}

impl SignupRequest {
  pub(crate) fn captcha_token(&self) -> Option<&str> {
    self.turnstile_token.as_deref().or_else(|| {
      self
        .gotrue_meta_security
        .as_ref()
        .and_then(|meta| meta.captcha_token.as_deref())
    })
  }
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn signup_request_accepts_gotrue_compatible_captcha_shape() {
    let request: SignupRequest = serde_json::from_value(serde_json::json!({
      "email": "user@example.com",
      "password": "long-enough1",
      "gotrue_meta_security": { "captcha_token": "compat-token" }
    }))
    .expect("GoTrue-compatible signup body");

    assert_eq!(request.captcha_token(), Some("compat-token"));
  }

  #[test]
  fn captcha_token_prefers_explicit_turnstile_field() {
    let request = SignupRequest {
      email: Some("user@example.com".to_string()),
      password: Some("long-enough1".to_string()),
      phone: None,
      data: None,
      turnstile_token: Some("explicit-token".to_string()),
      gotrue_meta_security: Some(GoTrueMetaSecurity {
        captcha_token: Some("compat-token".to_string()),
      }),
    };
    assert_eq!(request.captcha_token(), Some("explicit-token"));

    let compat = SignupRequest {
      turnstile_token: None,
      ..request
    };
    assert_eq!(compat.captcha_token(), Some("compat-token"));
  }
}
