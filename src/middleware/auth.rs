use axum::extract::FromRequestParts;
use axum::http::request::Parts;

use crate::{auth::jwt, error::AuthError, state::AppState};

pub struct AuthUser(pub jwt::Claims);
pub struct AdminUser(pub jwt::Claims);

impl FromRequestParts<AppState> for AuthUser {
    type Rejection = AuthError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        let token = extract_bearer_token(parts)?;
        let claims = jwt::decode_token(&token, &state.jwt_secret)
            .map_err(|_| AuthError::NotAuthorized)?
            .claims;
        Ok(AuthUser(claims))
    }
}

impl FromRequestParts<AppState> for AdminUser {
    type Rejection = AuthError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        let token = extract_bearer_token(parts)?;
        let claims = jwt::decode_token(&token, &state.jwt_secret)
            .map_err(|_| AuthError::NotAuthorized)?
            .claims;
        if claims.role != "service_role" && claims.role != "supabase_admin" {
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
