use axum::Json;
use axum::extract::{
  ConnectInfo,
  State,
};
use std::net::SocketAddr;

use crate::auth::{
  rate_limit,
  session,
};
use crate::error::{
  AuthError,
  Result,
};
use crate::middleware::auth::AuthUser;
use crate::state::AppState;

const REAUTHENTICATE_IP_RATE_LIMIT_ATTEMPTS: u32 = 5;
const REAUTHENTICATE_IP_RATE_LIMIT_WINDOW_SECS: i64 = 900;

pub async fn reauthenticate(
  State(state): State<AppState>,
  ConnectInfo(client_addr): ConnectInfo<SocketAddr>,
  AuthUser { user, .. }: AuthUser,
) -> Result<Json<serde_json::Value>> {
  let ip_limiter_key = format!("reauthenticate-ip:{}", client_addr.ip());
  let user_limiter_key = format!("reauthenticate-user:{}", user.id);
  if rate_limit::is_limited(&state.db, &ip_limiter_key, REAUTHENTICATE_IP_RATE_LIMIT_ATTEMPTS).await?
    || rate_limit::is_limited(
      &state.db,
      &user_limiter_key,
      REAUTHENTICATE_IP_RATE_LIMIT_ATTEMPTS,
    )
    .await?
  {
    return Err(AuthError::TooManyRequests);
  }
  rate_limit::record_attempt(
    &state.db,
    &ip_limiter_key,
    REAUTHENTICATE_IP_RATE_LIMIT_WINDOW_SECS,
  )
  .await?;
  rate_limit::record_attempt(
    &state.db,
    &user_limiter_key,
    REAUTHENTICATE_IP_RATE_LIMIT_WINDOW_SECS,
  )
  .await?;
  session::send_reauthentication_token(&state, &user).await?;
  Ok(Json(serde_json::json!({})))
}
