use axum::extract::FromRequestParts;
use axum::http::request::Parts;

use crate::auth::{
  jwt,
  session,
};
use crate::error::AuthError;
use crate::model::User;
use crate::state::AppState;

pub struct AuthUser(pub jwt::Claims);
pub struct AdminUser(pub jwt::Claims);

impl FromRequestParts<AppState> for AuthUser {
  type Rejection = AuthError;

  async fn from_request_parts(parts: &mut Parts, state: &AppState) -> Result<Self, Self::Rejection> {
    let token = extract_bearer_token(parts)?;
    let claims = jwt::decode_token(&token, &state.jwt_secret, &state.issuer)
      .map_err(|_| AuthError::NotAuthorized)?
      .claims;
    session::ensure_active_session(state, &claims)
      .await
      .map_err(|_| AuthError::NotAuthorized)?;
    session::load_current_user(state, &claims)
      .await
      .map_err(|_| AuthError::NotAuthorized)?;
    Ok(AuthUser(claims))
  }
}

impl FromRequestParts<AppState> for AdminUser {
  type Rejection = AuthError;

  async fn from_request_parts(parts: &mut Parts, state: &AppState) -> Result<Self, Self::Rejection> {
    let token = extract_bearer_token(parts)?;
    let claims = jwt::decode_token(&token, &state.jwt_secret, &state.issuer)
      .map_err(|_| AuthError::NotAuthorized)?
      .claims;
    session::ensure_active_session(state, &claims)
      .await
      .map_err(|_| AuthError::NotAuthorized)?;
    let user: User = session::load_current_user(state, &claims)
      .await
      .map_err(|_| AuthError::NotAuthorized)?;
    let role = user.role.as_deref().unwrap_or("authenticated");
    if role != "service_role" && role != "supabase_admin" {
      return Err(AuthError::NotAdmin);
    }
    Ok(AdminUser(claims))
  }
}

fn extract_bearer_token(parts: &Parts) -> Result<String, AuthError> {
  let auth_header = parts
    .headers
    .get(axum::http::header::AUTHORIZATION)
    .and_then(|v| v.to_str().ok())
    .ok_or(AuthError::NotAuthorized)?;

  let token = auth_header
    .strip_prefix("Bearer ")
    .ok_or(AuthError::NotAuthorized)?;

  Ok(token.to_string())
}
