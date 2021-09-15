use std::{error, fmt};
use super::HttpError;

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
            ApiError::Http(ref err) => write!(f, "Http error: {}", err),
            ApiError::Serializer(ref cause) => write!(f, "Serializer error: {}", cause),
            ApiError::MissingRouteData(ref cause) => {
                write!(f, "Missing route data error: {}", cause)
            }
        }
    }
}
