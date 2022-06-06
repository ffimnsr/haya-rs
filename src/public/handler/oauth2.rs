use crate::error::{ApiError, ApiResult};
use crate::{HeaderValues, MimeValues, DbContext};
use hyper::{Body, Request, Response, StatusCode};
use routerify::prelude::*;

/// OpenID Connect Front-Backchannel Enabled Logout
///
/// Path: /oauth2/sessions/logout
/// Action: GET POST
pub(crate) async fn handler_logout(req: Request<Body>) -> ApiResult<Response<Body>> {
    let db = req
        .data::<DbContext>()
        .ok_or_else(ApiError::fatal("Unable to get database connection"))?
        .clone();

    let data = serde_json::json!({
        "success": true,
        "message": "How long is forever?",
    });

    Response::builder()
        .status(StatusCode::OK)
        .header(HeaderValues::CONTENT_TYPE, MimeValues::JSON_MIME_TYPE)
        .body(Body::from(data.to_string()))
        .map_err(ApiError::Http)
}


/// Revoke Oauth2 Token
///
/// Path: /oauth2/revoke
/// Action: POST
pub(crate) async fn handler_revoke_oauth2_token(req: Request<Body>) -> ApiResult<Response<Body>> {
    let db = req
        .data::<DbContext>()
        .ok_or_else(ApiError::fatal("Unable to get database connection"))?
        .clone();

    let data = serde_json::json!({
        "success": true,
        "message": "How long is forever?",
    });

    Response::builder()
        .status(StatusCode::OK)
        .header(HeaderValues::CONTENT_TYPE, MimeValues::JSON_MIME_TYPE)
        .body(Body::from(data.to_string()))
        .map_err(ApiError::Http)
}

/// Delete OAuth2 Access Token from a Client
///
/// Path: /oauth2/tokens
/// Action: DELETE
pub(crate) async fn handler_delete_oauth2_token(_: Request<Body>) -> ApiResult<Response<Body>> {
    let data = serde_json::json!({
        "success": true,
        "message": "How long is forever?",
    });

    Response::builder()
        .status(StatusCode::OK)
        .header(HeaderValues::CONTENT_TYPE, MimeValues::JSON_MIME_TYPE)
        .body(Body::from(data.to_string()))
        .map_err(ApiError::Http)
}

/// Instropect Oauth2 Tokens
///
/// Path: /oauth2/introspect
/// Action: POST
pub(crate) async fn handler_introspect(_: Request<Body>) -> ApiResult<Response<Body>> {
    let data = serde_json::json!({
        "success": true,
        "message": "How long is forever?",
    });

    Response::builder()
        .status(StatusCode::OK)
        .header(HeaderValues::CONTENT_TYPE, MimeValues::JSON_MIME_TYPE)
        .body(Body::from(data.to_string()))
        .map_err(ApiError::Http)
}

/// Flush Expired OAuth2 Access Tokens
///
/// Path: /oauth2/flush
/// Action: POST
pub(crate) async fn handler_flush(_: Request<Body>) -> ApiResult<Response<Body>> {
    let data = serde_json::json!({
        "success": true,
        "message": "How long is forever?",
    });

    Response::builder()
        .status(StatusCode::OK)
        .header(HeaderValues::CONTENT_TYPE, MimeValues::JSON_MIME_TYPE)
        .body(Body::from(data.to_string()))
        .map_err(ApiError::Http)
}

/// The OAuth 2.0 Token Endpoint
///
/// Path: /oauth2/token
/// Action: POST
pub(crate) async fn handler_token(_: Request<Body>) -> ApiResult<Response<Body>> {
    let data = serde_json::json!({
        "success": true,
        "message": "How long is forever?",
    });

    Response::builder()
        .status(StatusCode::OK)
        .header(HeaderValues::CONTENT_TYPE, MimeValues::JSON_MIME_TYPE)
        .body(Body::from(data.to_string()))
        .map_err(ApiError::Http)
}

/// The OAuth 2.0 Authorize Endpoint
///
/// Path: /oauth2/auth
/// Action: GET POST
pub(crate) async fn handler_auth(_: Request<Body>) -> ApiResult<Response<Body>> {
    let data = serde_json::json!({
        "success": true,
        "message": "How long is forever?",
    });

    Response::builder()
        .status(StatusCode::OK)
        .header(HeaderValues::CONTENT_TYPE, MimeValues::JSON_MIME_TYPE)
        .body(Body::from(data.to_string()))
        .map_err(ApiError::Http)
}
