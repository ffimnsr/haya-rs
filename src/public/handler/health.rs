use crate::error::Result;
use crate::state::AppState;
use axum::Json;
use axum::extract::State;
use serde_json::json;

pub async fn health_check(State(state): State<AppState>) -> Result<Json<serde_json::Value>> {
  sqlx::query("SELECT 1")
    .execute(&state.db)
    .await
    .map_err(crate::error::AuthError::DatabaseError)?;
  Ok(Json(json!({
      "version": env!("CARGO_PKG_VERSION"),
      "name": env!("CARGO_PKG_NAME"),
      "description": env!("CARGO_PKG_DESCRIPTION"),
  })))
}
