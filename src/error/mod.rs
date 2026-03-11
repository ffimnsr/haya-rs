use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde_json::json;
use std::result::Result as StdResult;

pub type Result<T, E = AuthError> = StdResult<T, E>;

#[derive(Debug, thiserror::Error)]
pub enum AuthError {
    #[error("Invalid credentials")]
    InvalidCredentials,
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
            AuthError::InvalidCredentials => StatusCode::BAD_REQUEST,
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
        let body = json!({
            "code": status.as_u16(),
            "error_code": self.error_code(),
            "msg": self.to_string(),
        });
        (status, Json(body)).into_response()
    }
}

pub struct AppError(anyhow::Error);

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Something went wrong: {}", self.0),
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
