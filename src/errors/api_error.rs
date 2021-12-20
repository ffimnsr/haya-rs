use super::{
    GenericError, HeaderToStrError, HttpError, HyperError, JwtError,
    StringFromUtf8Error, UrlParseError,
};
use std::{error, fmt};

pub(crate) type ApiResult<T> = Result<T, ApiError>;

#[derive(Debug, Clone)]
pub(crate) enum OauthErrorCode {
    InvalidRequest,
    AccessDenied,
    UnsupportedResponseType,
    InvalidScope,
    ServerError,
    TemporarilyUnavailable,
}

impl Default for OauthErrorCode {
    fn default() -> Self {
        Self::InvalidRequest
    }
}

impl fmt::Display for OauthErrorCode {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            Self::InvalidRequest => write!(f, "invalid_request"),
            Self::AccessDenied => write!(f, "access_denied"),
            Self::UnsupportedResponseType => write!(f, "unsupported_response_type"),
            Self::InvalidScope => write!(f, "invalid_scope"),
            Self::ServerError => write!(f, "server_error"),
            Self::TemporarilyUnavailable => write!(f, "temporarily_unavailable"),
        }
    }
}

#[derive(Debug, Default, Clone)]
pub(crate) struct OauthError {
    pub redirect_uri: String,
    pub error: OauthErrorCode,
    pub error_description: String,
    pub error_uri: Option<String>,
    pub state: String,
}

#[allow(dead_code)]
impl OauthError {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn uri<'a>(&'a mut self, redirect_uri: &str) -> &'a mut Self {
        self.redirect_uri = redirect_uri.to_string();
        self
    }

    pub fn description<'a>(&'a mut self, error_description: &str) -> &'a mut Self {
        self.error_description = error_description.to_string();
        self
    }

    pub fn error_uri<'a>(&'a mut self, error_uri: &str) -> &'a mut Self {
        self.error_uri = Some(error_uri.to_string());
        self
    }

    pub fn state<'a>(&'a mut self, state: &str) -> &'a mut Self {
        self.state = state.to_string();
        self
    }

    pub fn invalid_request<'a>(&'a mut self) -> &'a mut Self {
        self.error = OauthErrorCode::InvalidRequest;
        self
    }

    pub fn access_denied<'a>(&'a mut self) -> &'a mut Self {
        self.error = OauthErrorCode::AccessDenied;
        self
    }

    pub fn unsupported_response_type<'a>(&'a mut self) -> &'a mut Self {
        self.error = OauthErrorCode::UnsupportedResponseType;
        self
    }

    pub fn invalid_scope<'a>(&'a mut self) -> &'a mut Self {
        self.error = OauthErrorCode::InvalidScope;
        self
    }

    pub fn server_error<'a>(&'a mut self) -> &'a mut Self {
        self.error = OauthErrorCode::ServerError;
        self
    }

    pub fn temporary_unavailable<'a>(&'a mut self) -> &'a mut Self {
        self.error = OauthErrorCode::TemporarilyUnavailable;
        self
    }

    pub fn to_json(&self) -> ApiError {
        unimplemented!()
    }

    pub fn build_token(&self) -> ApiError {
        ApiError::Token(self.clone())
    }

    pub fn build(&self) -> ApiError {
        ApiError::Authorize(self.clone())
    }
}

#[derive(Debug)]
#[non_exhaustive]
pub(crate) enum ApiError {
    Http(HttpError),
    Hyper(HyperError),
    Jwt(JwtError),
    Url(UrlParseError),
    Authorize(OauthError),
    Token(OauthError),
    StringFromUtf8(StringFromUtf8Error),
    HeaderToStr(HeaderToStrError),
    BadRequest(String),
    Fatal(String),
    Other(GenericError),
}

impl ApiError {
    pub fn bad_request<'a>(cause: &'a str) -> Box<dyn FnOnce() -> Self + 'a> {
        Box::new(move || Self::BadRequest(cause.to_string()))
    }

    pub fn bad_request_err<'a, T>(cause: &'a str) -> ApiResult<T> {
        Err(Self::BadRequest(cause.to_string()))
    }

    pub fn fatal<'a>(cause: &'a str) -> Box<dyn FnOnce() -> Self + 'a> {
        Box::new(move || Self::Fatal(cause.to_string()))
    }
}

impl error::Error for ApiError {}

impl fmt::Display for ApiError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            Self::Http(ref err) => write!(f, "Http error: {}", err),
            Self::Hyper(ref err) => write!(f, "Hyper error: {}", err),
            Self::Jwt(ref err) => write!(f, "Jwt error: {}", err),
            Self::Url(ref err) => write!(f, "Url parse error: {}", err),
            Self::Authorize(ref err) => write!(f, "Authorize error: {:?}", err),
            Self::Token(ref err) => write!(f, "Token error: {:?}", err),
            Self::StringFromUtf8(ref err) => {
                write!(f, "String from utf8 error: {:?}", err)
            }
            Self::HeaderToStr(ref err) => write!(f, "Header to string error: {:?}", err),
            Self::BadRequest(ref cause) => write!(f, "Bad request error: {}", cause),
            Self::Fatal(ref cause) => write!(f, "Fatal error: {}", cause),
            Self::Other(ref err) => write!(f, "Other error: {:?}", err),
        }
    }
}
