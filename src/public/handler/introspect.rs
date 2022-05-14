use crate::error::{ApiError, ApiResult};
use crate::{HeaderValues, MimeValues};
use hyper::{Body, Request, Response, StatusCode};

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
