use crate::errors::{ApiError, ApiResult};
use crate::{HeaderValues, MimeValues};
use hyper::{Body, Request, Response, StatusCode};

pub(crate) async fn handler_trace(req: Request<Body>) -> ApiResult<Response<Body>> {
    log::info!("TRACE {:?}", req);

    Response::builder()
        .status(StatusCode::OK)
        .header(HeaderValues::CONTENT_TYPE, MimeValues::JSON_MIME_TYPE)
        .body(Body::from(
            "TRACE: See the internal server logs.".to_string(),
        ))
        .map_err(ApiError::Http)
}
