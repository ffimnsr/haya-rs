use axum::Json;
use axum::extract::State;
use serde_json::{
  Map,
  Value,
};

use crate::error::Result;
use crate::state::AppState;

pub async fn get_settings(State(state): State<AppState>) -> Result<Json<Value>> {
  let mut external = Map::new();
  external.insert("email".to_string(), Value::Bool(true));
  for provider in crate::auth::oidc::provider_names(&state.oidc_providers) {
    external.insert(provider, Value::Bool(true));
  }

  Ok(Json(serde_json::json!({
    "mailer_autoconfirm": state.mailer_autoconfirm,
    "external": Value::Object(external),
    "mfa": {
      "totp": true,
    },
  })))
}
