//! This module contains all error definitions.

use std::{error, fmt};

pub(crate) use hyper::http::Error as HttpError;

pub(crate) type GenericError = Box<dyn error::Error + Send + Sync>;
pub(crate) type ServiceResult<T> = Result<T, ServiceError>;

#[derive(Debug)]
#[non_exhaustive]
pub(crate) enum ServiceError {
    Router(String),
    Http(HttpError),
    Database(String),
    Env(String),
    Io(String),
    Serializer(String),
    Parser(String),
    Other(String),
}

impl error::Error for ServiceError {}

impl fmt::Display for ServiceError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            ServiceError::Http(ref err) => write!(f, "Hyper http error: {}", err),
            ServiceError::Router(_) => todo!(),
            ServiceError::Other(_) => todo!(),
            ServiceError::Serializer(_) => todo!(),
            ServiceError::Parser(_) => todo!(),
            ServiceError::Io(_) => todo!(),
            ServiceError::Database(_) => todo!(),
            ServiceError::Env(_) => todo!(),
        }
    }
}

impl From<HttpError> for ServiceError {
    fn from(e: HttpError) -> Self {
        Self::Http(e)
    }
}

pub(crate) type ApiResult<T> = Result<T, ApiError>;

#[derive(Debug)]
#[non_exhaustive]
pub(crate) enum ApiError {
    MissingRouteData(String),
    Http(HttpError),
    Serializer(String),
}

impl error::Error for ApiError {}

impl fmt::Display for ApiError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            ApiError::Http(ref err) => write!(f, "Hyper http error: {}", err),
            ApiError::Serializer(_) => todo!(),
            ApiError::MissingRouteData(_) => todo!(),
        }
    }
}

/// Error in retrieving user info.
#[derive(Debug)]
#[non_exhaustive]
pub(crate) enum UserInfoError<RE>
where
    RE: std::error::Error + 'static,
{
    ClaimsVerification,
    Parse,
    Request(RE),
    Response,
    Other,
}
