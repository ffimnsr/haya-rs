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
  let mut external = Map::new();
  external.insert("email".to_string(), Value::Bool(true));
  let providers = state.oidc_providers.read().await;
  for provider in crate::auth::oidc::provider_names(&providers) {
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
