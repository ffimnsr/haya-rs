use axum::Json;
use axum::http::StatusCode;
use axum::response::{
  IntoResponse,
  Response,
};
use serde_json::json;
use std::result::Result as StdResult;

pub type Result<T, E = AuthError> = StdResult<T, E>;

#[derive(Debug, thiserror::Error)]
pub enum AuthError {
  #[error("Invalid credentials")]
  InvalidCredentials,
  #[allow(dead_code)]
  #[error("Email not confirmed")]
  EmailNotConfirmed,
  #[error("User already exists")]
  UserAlreadyExists,
  #[error("Validation failed: {0}")]
  ValidationFailed(String),
  #[error("User not found")]
  UserNotFound,
  #[error("Session not found")]
  SessionNotFound,
  #[error("Invalid token")]
  InvalidToken,
  #[error("Token expired")]
  TokenExpired,
  #[error("Not authorized")]
  NotAuthorized,
  #[error("Not admin")]
  NotAdmin,
  #[error("User banned")]
  UserBanned,
  #[error("Database error: {0}")]
  DatabaseError(#[from] sqlx::Error),
  #[error("Internal error: {0}")]
  InternalError(String),
}

impl AuthError {
  fn status_code(&self) -> StatusCode {
    match self {
      AuthError::InvalidCredentials => StatusCode::UNAUTHORIZED,
      AuthError::EmailNotConfirmed => StatusCode::UNAUTHORIZED,
      AuthError::UserAlreadyExists => StatusCode::UNPROCESSABLE_ENTITY,
      AuthError::ValidationFailed(_) => StatusCode::UNPROCESSABLE_ENTITY,
      AuthError::UserNotFound => StatusCode::NOT_FOUND,
      AuthError::SessionNotFound => StatusCode::NOT_FOUND,
      AuthError::InvalidToken => StatusCode::UNAUTHORIZED,
      AuthError::TokenExpired => StatusCode::UNAUTHORIZED,
      AuthError::NotAuthorized => StatusCode::UNAUTHORIZED,
      AuthError::NotAdmin => StatusCode::FORBIDDEN,
      AuthError::UserBanned => StatusCode::FORBIDDEN,
      AuthError::DatabaseError(_) => StatusCode::INTERNAL_SERVER_ERROR,
      AuthError::InternalError(_) => StatusCode::INTERNAL_SERVER_ERROR,
    }
  }

  fn error_code(&self) -> &'static str {
    match self {
      AuthError::InvalidCredentials => "invalid_credentials",
      AuthError::EmailNotConfirmed => "email_not_confirmed",
      AuthError::UserAlreadyExists => "user_already_exists",
      AuthError::ValidationFailed(_) => "validation_failed",
      AuthError::UserNotFound => "user_not_found",
      AuthError::SessionNotFound => "session_not_found",
      AuthError::InvalidToken => "bad_jwt",
      AuthError::TokenExpired => "bad_jwt",
      AuthError::NotAuthorized => "no_authorization",
      AuthError::NotAdmin => "not_admin",
      AuthError::UserBanned => "user_banned",
      AuthError::DatabaseError(_) => "unexpected_failure",
      AuthError::InternalError(_) => "unexpected_failure",
    }
  }
}

impl IntoResponse for AuthError {
  fn into_response(self) -> Response {
    let status = self.status_code();
    // Never send internal implementation details or SQL errors to clients.
    // Log them server-side instead.
    let msg = match &self {
      AuthError::DatabaseError(e) => {
        tracing::error!("Database error: {e}");
        "An unexpected error occurred".to_string()
      },
      AuthError::InternalError(e) => {
        tracing::error!("Internal error: {e}");
        "An unexpected error occurred".to_string()
      },
      _ => self.to_string(),
    };
    let body = json!({
        "code": status.as_u16(),
        "error_code": self.error_code(),
        "msg": msg,
    });
    (status, Json(body)).into_response()
  }
}

/// Generic error wrapper for anyhow errors - kept for extensibility.
#[allow(dead_code)]
pub struct AppError(anyhow::Error);

impl IntoResponse for AppError {
  fn into_response(self) -> Response {
    tracing::error!("Unhandled application error: {}", self.0);
    (
      StatusCode::INTERNAL_SERVER_ERROR,
      Json(json!({
        "code": StatusCode::INTERNAL_SERVER_ERROR.as_u16(),
        "error_code": "unexpected_failure",
        "msg": "An unexpected error occurred",
      })),
    )
      .into_response()
  }
}

impl<E> From<E> for AppError
where
  E: Into<anyhow::Error>,
{
  fn from(value: E) -> Self {
    Self(value.into())
  }
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn test_error_codes() {
    assert_eq!(AuthError::InvalidCredentials.error_code(), "invalid_credentials");
    assert_eq!(AuthError::EmailNotConfirmed.error_code(), "email_not_confirmed");
    assert_eq!(AuthError::UserAlreadyExists.error_code(), "user_already_exists");
    assert_eq!(
      AuthError::ValidationFailed("bad input".into()).error_code(),
      "validation_failed"
    );
    assert_eq!(AuthError::UserNotFound.error_code(), "user_not_found");
    assert_eq!(AuthError::SessionNotFound.error_code(), "session_not_found");
    assert_eq!(AuthError::InvalidToken.error_code(), "bad_jwt");
    assert_eq!(AuthError::TokenExpired.error_code(), "bad_jwt");
    assert_eq!(AuthError::NotAuthorized.error_code(), "no_authorization");
    assert_eq!(AuthError::NotAdmin.error_code(), "not_admin");
    assert_eq!(AuthError::UserBanned.error_code(), "user_banned");
    assert_eq!(
      AuthError::InternalError("oops".into()).error_code(),
      "unexpected_failure"
    );
  }

  #[test]
  fn test_status_codes() {
    assert_eq!(
      AuthError::InvalidCredentials.status_code(),
      StatusCode::UNAUTHORIZED
    );
    assert_eq!(
      AuthError::EmailNotConfirmed.status_code(),
      StatusCode::UNAUTHORIZED
    );
    assert_eq!(
      AuthError::UserAlreadyExists.status_code(),
      StatusCode::UNPROCESSABLE_ENTITY
    );
    assert_eq!(
      AuthError::ValidationFailed("".into()).status_code(),
      StatusCode::UNPROCESSABLE_ENTITY
    );
    assert_eq!(AuthError::UserNotFound.status_code(), StatusCode::NOT_FOUND);
    assert_eq!(AuthError::SessionNotFound.status_code(), StatusCode::NOT_FOUND);
    assert_eq!(AuthError::InvalidToken.status_code(), StatusCode::UNAUTHORIZED);
    assert_eq!(AuthError::TokenExpired.status_code(), StatusCode::UNAUTHORIZED);
    assert_eq!(AuthError::NotAuthorized.status_code(), StatusCode::UNAUTHORIZED);
    assert_eq!(AuthError::NotAdmin.status_code(), StatusCode::FORBIDDEN);
    assert_eq!(AuthError::UserBanned.status_code(), StatusCode::FORBIDDEN);
    assert_eq!(
      AuthError::InternalError("".into()).status_code(),
      StatusCode::INTERNAL_SERVER_ERROR
    );
  }

  #[test]
  fn test_error_display() {
    assert_eq!(AuthError::InvalidCredentials.to_string(), "Invalid credentials");
    assert_eq!(AuthError::UserAlreadyExists.to_string(), "User already exists");
    assert_eq!(
      AuthError::ValidationFailed("Password too short".into()).to_string(),
      "Validation failed: Password too short"
    );
    assert_eq!(
      AuthError::InternalError("DB failure".into()).to_string(),
      "Internal error: DB failure"
    );
  }
}
