//! This module contains all error definitions.

pub mod api_error;
pub mod service_error;

pub(crate) use hyper::http::Error as HttpError;
pub(crate) use api_error::{ApiError, ApiResult};
pub(crate) use service_error::{ServiceError, ServiceResult};

pub(crate) type GenericError = Box<dyn std::error::Error + Send + Sync>;
