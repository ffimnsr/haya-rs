//! This module contains all error definitions.

pub mod api_error;
pub mod service_error;

pub(crate) use api_error::{ApiError, ApiResult};
pub(crate) use bson::de::Error as BsonDeError;
pub(crate) use bson::oid::Error as BsonOidError;
pub(crate) use bson::ser::Error as BsonSerError;
pub(crate) use hyper::Error as HyperError;
pub(crate) use hyper::header::ToStrError as HeaderToStrError;
pub(crate) use hyper::http::Error as HttpError;
pub(crate) use jsonwebtoken::errors::Error as JwtError;
pub(crate) use mongodb::error::Error as MongoError;
pub(crate) use serde_json::Error as SerdeJsonError;
pub(crate) use serde_yaml::Error as SerdeYamlError;
pub(crate) use service_error::{ServiceError, ServiceResult};
pub(crate) use std::env::VarError;
pub(crate) use std::io::Error as IoError;
pub(crate) use std::net::AddrParseError;
pub(crate) use std::string::FromUtf8Error as StringFromUtf8Error;
pub(crate) use sys_info::Error as SysInfoError;
pub(crate) use url::ParseError as UrlParseError;

pub(crate) type GenericError = Box<dyn std::error::Error + Send + Sync>;
pub(crate) type GenericResult<T> = Result<T, GenericError>;
