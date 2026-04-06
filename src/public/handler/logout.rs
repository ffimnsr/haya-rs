use axum::extract::{
  Query,
  State,
};
use axum::http::StatusCode;
use axum::response::IntoResponse;
use chrono::Utc;
use serde::Deserialize;
use uuid::Uuid;

use crate::error::Result;
use crate::middleware::auth::AuthUser;
use crate::state::AppState;

#[derive(Debug, Deserialize)]
pub struct LogoutQuery {
  pub scope: Option<String>,
}

pub async fn logout(
  State(state): State<AppState>,
  Query(query): Query<LogoutQuery>,
  AuthUser { claims, user }: AuthUser,
) -> Result<impl IntoResponse> {
  let session_id: Uuid = claims
    .session_id
    .parse()
    .map_err(|_| crate::error::AuthError::InternalError("Invalid session_id".to_string()))?;
  let user_id = user.id;
  let now = Utc::now();

  match query.scope.as_deref() {
    Some("global") => {
      sqlx::query("UPDATE auth.refresh_tokens SET revoked = true, updated_at = $1 WHERE user_id = $2")
        .bind(now)
        .bind(user_id.to_string())
        .execute(&state.db)
        .await?;
      sqlx::query("DELETE FROM auth.sessions WHERE user_id = $1")
        .bind(user_id)
        .execute(&state.db)
        .await?;
    },
    Some("others") => {
      sqlx::query(
                "UPDATE auth.refresh_tokens SET revoked = true, updated_at = $1 WHERE user_id = $2 AND session_id != $3"
            )
            .bind(now)
            .bind(user_id.to_string())
            .bind(session_id)
            .execute(&state.db)
            .await?;
      sqlx::query("DELETE FROM auth.sessions WHERE user_id = $1 AND id != $2")
        .bind(user_id)
        .bind(session_id)
        .execute(&state.db)
        .await?;
    },
    _ => {
      sqlx::query("UPDATE auth.refresh_tokens SET revoked = true, updated_at = $1 WHERE session_id = $2")
        .bind(now)
        .bind(session_id)
        .execute(&state.db)
        .await?;
      sqlx::query("DELETE FROM auth.sessions WHERE id = $1")
        .bind(session_id)
        .execute(&state.db)
        .await?;
    },
  }

  Ok(StatusCode::NO_CONTENT)
}
