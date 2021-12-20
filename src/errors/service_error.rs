use super::{
    AddrParseError, GenericError, HttpError, HyperError, IoError, PgError, VarError,
    YamlParseError,
};
use std::{error, fmt};

pub(crate) type ServiceResult<T> = Result<T, ServiceError>;

#[derive(Debug)]
#[non_exhaustive]
pub(crate) enum ServiceError {
    AddrParser(AddrParseError),
    Database(PgError),
    Http(HttpError),
    Hyper(HyperError),
    Io(IoError),
    Router(GenericError),
    Var(VarError),
    YamlParser(YamlParseError),
}

impl error::Error for ServiceError {}

impl fmt::Display for ServiceError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            Self::AddrParser(ref err) => write!(f, "Addr parser error: {}", err),
            Self::Database(ref err) => write!(f, "Database error: {}", err),
            Self::Http(ref err) => write!(f, "Hyper http error: {}", err),
            Self::Hyper(ref err) => write!(f, "Hyper error: {}", err),
            Self::Io(ref err) => write!(f, "Io error: {}", err),
            Self::Router(ref err) => write!(f, "Router error: {}", err),
            Self::Var(ref err) => write!(f, "Var env error: {}", err),
            Self::YamlParser(ref err) => write!(f, "Yaml parser error: {}", err),
        }
    }
}

impl From<HttpError> for ServiceError {
    fn from(e: HttpError) -> Self {
        Self::Http(e)
    }
}
