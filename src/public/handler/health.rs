use axum::{Json, extract::State};
use serde_json::json;
use crate::error::Result;
use crate::state::AppState;

pub async fn health_check(State(state): State<AppState>) -> Result<Json<serde_json::Value>> {
    sqlx::query("SELECT 1")
        .execute(&state.db)
        .await
        .map_err(crate::error::AuthError::DatabaseError)?;
    Ok(Json(json!({
        "version": "0.2.0",
        "name": "Haya Auth"
    })))
}
