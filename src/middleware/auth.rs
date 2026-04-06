use axum::extract::FromRequestParts;
use axum::http::request::Parts;

use crate::auth::{
  jwt,
  session,
};
use crate::error::AuthError;
use crate::model::User;
use crate::state::AppState;

pub struct AuthUser {
  pub claims: jwt::Claims,
  pub user: User,
}
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
    let user = session::load_current_user(state, &claims)
      .await
      .map_err(|_| AuthError::NotAuthorized)?;
    Ok(AuthUser { claims, user })
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

  extract_bearer_token_value(auth_header)
    .map(ToOwned::to_owned)
    .ok_or(AuthError::NotAuthorized)
}

pub(crate) fn extract_bearer_token_value(auth_header: &str) -> Option<&str> {
  let (scheme, token) = auth_header.split_once(' ')?;
  if !scheme.eq_ignore_ascii_case("bearer") || token.is_empty() {
    return None;
  }
  Some(token)
}

#[cfg(test)]
mod tests {
  use super::extract_bearer_token_value;

  #[test]
  fn bearer_scheme_is_case_insensitive() {
    assert_eq!(extract_bearer_token_value("Bearer token"), Some("token"));
    assert_eq!(extract_bearer_token_value("bearer token"), Some("token"));
    assert_eq!(extract_bearer_token_value("BeArEr token"), Some("token"));
  }

  #[test]
  fn bearer_scheme_rejects_invalid_headers() {
    assert_eq!(extract_bearer_token_value("Basic token"), None);
    assert_eq!(extract_bearer_token_value("Bearer"), None);
    assert_eq!(extract_bearer_token_value("Bearer "), None);
  }
}
