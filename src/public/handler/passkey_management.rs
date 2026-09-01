use std::net::SocketAddr;

use axum::Json;
use axum::extract::{
  ConnectInfo,
  Path,
  State,
};
use chrono::Utc;
use serde::{
  Deserialize,
  Serialize,
};
use uuid::Uuid;

use crate::auth::{
  audit,
  oidc,
  passkey_management_repository,
  passkey_repository,
  session,
};
use crate::error::{
  AuthError,
  Result,
};
use crate::middleware::auth::AuthUser;
use crate::state::AppState;

use super::passkey::PasskeyFactorResponse;

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DeletePasskeyRequest {
  pub current_password: Option<String>,
  pub reauthentication_token: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct DeletePasskeyResponse {
  pub id: Uuid,
}

pub async fn list_passkeys(
  State(state): State<AppState>,
  AuthUser { user, .. }: AuthUser,
) -> Result<Json<Vec<PasskeyFactorResponse>>> {
  ensure_passkeys_enabled(&state)?;
  let factors = passkey_repository::web_authn_factors_by_user_id(&state.db, user.id).await?;
  Ok(Json(factors.into_iter().map(Into::into).collect()))
}

pub async fn delete_passkey(
  State(state): State<AppState>,
  ConnectInfo(client_addr): ConnectInfo<SocketAddr>,
  AuthUser { claims, user }: AuthUser,
  Path(factor_id): Path<Uuid>,
  Json(request): Json<DeletePasskeyRequest>,
) -> Result<Json<DeletePasskeyResponse>> {
  ensure_passkeys_enabled(&state)?;
  session::require_reauthentication(
    &state,
    &claims,
    &user,
    client_addr.ip(),
    request.current_password.as_deref(),
    request.reauthentication_token.as_deref(),
  )
  .await?;

  let active_oidc_providers = {
    let providers = state.oidc_providers.read().await;
    oidc::provider_names(&providers)
  };
  let now = Utc::now();
  let mut tx = state.db.begin().await?;
  passkey_management_repository::delete_owned_passkey(
    &mut tx,
    user.id,
    factor_id,
    &active_oidc_providers,
    now,
  )
  .await?;
  audit::log_event_tx(
    tx.as_mut(),
    state.instance_id,
    Some(client_addr.ip()),
    "passkey_deleted",
    serde_json::json!({
      "user_id": user.id,
      "factor_id": factor_id,
    }),
  )
  .await?;
  tx.commit().await?;

  Ok(Json(DeletePasskeyResponse { id: factor_id }))
}

fn ensure_passkeys_enabled(state: &AppState) -> Result<()> {
  state
    .passkey
    .as_ref()
    .map(|_| ())
    .ok_or(AuthError::PasskeyDisabled)
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn management_response_types_exclude_credential_material() {
    let response = DeletePasskeyResponse { id: Uuid::nil() };
    let json = serde_json::to_string(&response).unwrap();
    assert_eq!(json, format!("{{\"id\":\"{}\"}}", Uuid::nil()));
    for forbidden in ["credential", "publicKey", "counter", "userHandle", "challenge"] {
      assert!(!json.contains(forbidden));
    }
  }

  #[test]
  fn delete_request_uses_browser_field_names_and_rejects_unknown_fields() {
    let request: DeletePasskeyRequest = serde_json::from_value(serde_json::json!({
      "currentPassword": "secret",
      "reauthenticationToken": null,
    }))
    .unwrap();
    assert_eq!(request.current_password.as_deref(), Some("secret"));
    assert!(
      serde_json::from_value::<DeletePasskeyRequest>(serde_json::json!({ "factorId": "bad" })).is_err()
    );
  }
}
