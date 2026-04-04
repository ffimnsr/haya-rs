use axum::Json;
use axum::extract::State;
use uuid::Uuid;

use crate::auth::session;
use crate::error::{
  AuthError,
  Result,
};
use crate::middleware::auth::AuthUser;
use crate::model::User;
use crate::state::AppState;

pub async fn reauthenticate(
  State(state): State<AppState>,
  AuthUser(claims): AuthUser,
) -> Result<Json<serde_json::Value>> {
  let user_id: Uuid = claims
    .sub
    .parse()
    .map_err(|_| AuthError::InternalError("Invalid user_id in token".to_string()))?;
  let user: User = sqlx::query_as::<_, User>(
    "SELECT id, instance_id, aud, role, email, encrypted_password, email_confirmed_at, phone, phone_confirmed_at, confirmed_at, last_sign_in_at, raw_app_meta_data, raw_user_meta_data, is_super_admin, is_sso_user, is_anonymous, banned_until, deleted_at, created_at, updated_at FROM auth.users WHERE id = $1",
  )
  .bind(user_id)
  .fetch_optional(&state.db)
  .await?
  .ok_or(AuthError::UserNotFound)?;

  session::send_reauthentication_token(&state, &user).await?;
  Ok(Json(serde_json::json!({})))
}
