use super::{
    AddrParseError, BsonDeError, BsonOidError, BsonSerError, GenericError, HttpError,
    HyperError, IoError, MongoError, VarError, SerdeJsonError, SerdeYamlError,
};

pub(crate) type ServiceResult<T> = Result<T, ServiceError>;

#[derive(Debug)]
#[non_exhaustive]
pub(crate) enum ServiceError {
    AddrParser(AddrParseError),
    Mongo(MongoError),
    BsonOid(BsonOidError),
    BsonDe(BsonDeError),
    BsonSer(BsonSerError),
    SerdeJson(SerdeJsonError),
    Http(HttpError),
    Hyper(HyperError),
    Io(IoError),
    Var(VarError),
    Yaml(SerdeYamlError),
    Router(GenericError),
    DefinedError(&'static str),
}

impl std::error::Error for ServiceError {}

impl std::fmt::Display for ServiceError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match *self {
            Self::AddrParser(ref err) => write!(f, "Addr parser error: {}", err),
            Self::Mongo(ref err) => write!(f, "Mongo error: {}", err),
            Self::BsonOid(ref err) => {
                write!(f, "Bson OID parsing error: {}", err)
            }
            Self::BsonDe(ref err) => {
                write!(f, "Bson deserializer error: {}", err)
            }
            Self::BsonSer(ref err) => {
                write!(f, "Bson serializer error: {}", err)
            }
            Self::SerdeJson(ref err) => {
                write!(f, "Serde JSON parsing error: {}", err)
            }
            Self::Http(ref err) => write!(f, "Hyper http error: {}", err),
            Self::Hyper(ref err) => write!(f, "Hyper error: {}", err),
            Self::Io(ref err) => write!(f, "Io error: {}", err),
            Self::Router(ref err) => write!(f, "Router error: {}", err),
            Self::Var(ref err) => write!(f, "Var env error: {}", err),
            Self::Yaml(ref err) => write!(f, "Yaml error: {}", err),
            Self::DefinedError(err) => write!(f, "Fatal error: {}", err),
        }
    }
}

impl From<HttpError> for ServiceError {
    fn from(e: HttpError) -> Self {
        Self::Http(e)
    }
}
