use axum::Json;
use axum::extract::State;

use crate::auth::session;
use crate::error::Result;
use crate::middleware::auth::AuthUser;
use crate::state::AppState;

pub async fn reauthenticate(
  State(state): State<AppState>,
  AuthUser { user, .. }: AuthUser,
) -> Result<Json<serde_json::Value>> {
  session::send_reauthentication_token(&state, &user).await?;
  Ok(Json(serde_json::json!({})))
}
