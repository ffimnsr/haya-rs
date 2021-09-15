use std::{error, fmt};
use super::{HttpError, GenericError};

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
            ServiceError::Parser(ref err) => write!(f, "Parser error: {}", err),
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

