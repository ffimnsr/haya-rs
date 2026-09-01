use axum::Json;
use axum::extract::State;
use serde_json::{
  Map,
  Value,
};

use crate::error::Result;
use crate::middleware::auth::AdminUser;
use crate::state::AppState;

pub async fn get_settings(
  State(state): State<AppState>,
  AdminUser(_claims): AdminUser,
) -> Result<Json<Value>> {
  let providers = state.oidc_providers.read().await;
  Ok(Json(settings_response(
    state.mailer_autoconfirm,
    crate::auth::oidc::provider_names(&providers),
    state.passkey.is_some(),
  )))
}

fn settings_response(mailer_autoconfirm: bool, providers: Vec<String>, passkey_enabled: bool) -> Value {
  let mut external = Map::new();
  external.insert("email".to_owned(), Value::Bool(true));
  for provider in providers {
    external.insert(provider, Value::Bool(true));
  }
  external.insert("passkey".to_owned(), Value::Bool(passkey_enabled));

  serde_json::json!({
    "mailer_autoconfirm": mailer_autoconfirm,
    "external": Value::Object(external),
    "mfa": {
      "totp": true,
      "webauthn": passkey_enabled,
    },
  })
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn settings_advertise_passkeys_only_when_enabled() {
    let disabled = settings_response(false, vec!["github".to_owned(), "passkey".to_owned()], false);
    assert_eq!(disabled["external"]["email"], true);
    assert_eq!(disabled["external"]["github"], true);
    assert_eq!(disabled["external"]["passkey"], false);
    assert_eq!(disabled["mfa"]["totp"], true);
    assert_eq!(disabled["mfa"]["webauthn"], false);

    let enabled = settings_response(true, vec!["github".to_owned()], true);
    assert_eq!(enabled["mailer_autoconfirm"], true);
    assert_eq!(enabled["external"]["passkey"], true);
    assert_eq!(enabled["mfa"]["webauthn"], true);
  }
}
