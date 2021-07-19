use hyper::{Body, Request, Response, StatusCode};
use routerify::prelude::*;

use crate::config::Config;
use crate::errors::{ApiError, ApiResult};
use crate::well_known::WellKnown;
use crate::{HeaderValues, MimeValues};

pub(crate) async fn handler_get_end_session(
    _req: Request<Body>,
) -> ApiResult<Response<Body>> {
    let data = serde_json::json!({
        "success": true,
        "message": "How long is forever?",
    });

    Ok(Response::builder()
        .status(StatusCode::OK)
        .header(HeaderValues::CONTENT_TYPE, MimeValues::JSON_MIME_TYPE)
        .body(Body::from(data.to_string()))
        .map_err(ApiError::Http)?)
}

pub(crate) async fn handler_process_logout(
    _req: Request<Body>,
) -> ApiResult<Response<Body>> {
    let data = serde_json::json!({
        "success": true,
        "message": "How long is forever?",
    });

    Ok(Response::builder()
        .status(StatusCode::OK)
        .header(HeaderValues::CONTENT_TYPE, MimeValues::JSON_MIME_TYPE)
        .body(Body::from(data.to_string()))
        .map_err(ApiError::Http)?)
}
