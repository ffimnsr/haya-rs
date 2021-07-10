//! This module contains all error definitions.

use std::{error, fmt};

pub use hyper::http::Error as HttpError;

pub type GenericError = Box<dyn error::Error + Send + Sync>;
pub type ServiceResult<T> = Result<T, ServiceError>;


#[derive(Debug)]
pub enum ServiceError {
    Router(String),
    Http(HttpError),
    Serializer(String),
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

    }
  }
}

impl From<HttpError> for ServiceError {
  fn from(e: HttpError) -> Self {
      Self::Http(e)
  }
}

///
/// Error in retrieving user info.
///
#[derive(Debug)]
pub enum UserInfoError<RE>
where
  RE: std::error::Error + 'static,
{
  ClaimsVerification,
  Parse,
  Request(RE),
  Response,
  Other,
}
