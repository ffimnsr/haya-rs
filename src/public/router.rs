use hyper::header::HeaderValue;
use hyper::{Body, Request, Response};
use routerify::prelude::*;
use routerify::{Middleware, RequestInfo, Router};
use std::sync::Arc;
use uuid::Uuid;

use super::handlers::{
    error_handler, handler_authorize, handler_index, handler_not_found, handler_test_cb,
    handler_token,
};
use crate::config::Config;
use crate::db::Pool;
use crate::errors::{ApiError, ApiResult, ServiceError, ServiceResult};

async fn add_request_id(req: Request<Body>) -> ApiResult<Request<Body>> {
    req.set_context(Uuid::new_v4());
    Ok(req)
}

async fn logger(
    res: Response<Body>,
    req_info: RequestInfo,
) -> ApiResult<Response<Body>> {
    let request_id = req_info
        .context::<Uuid>()
        .ok_or_else(|| ApiError::BadRequest("Unable to get request id".into()))?;
    log::info!(
        "[request-id:{}] {} {} {}",
        request_id,
        res.status().as_u16(),
        req_info.method(),
        req_info.uri().path()
    );
    Ok(res)
}

async fn set_request_id_header(
    mut res: Response<Body>,
    req_info: RequestInfo,
) -> ApiResult<Response<Body>> {
    let request_id = req_info
        .context::<Uuid>()
        .ok_or_else(|| ApiError::BadRequest("Unable to get request id".into()))
        .map(|c| c.to_string())?;
    let value = HeaderValue::from_str(request_id.as_str()).unwrap();
    res.headers_mut().append("x-request-id", value);
    Ok(res)
}

pub(crate) fn router(
    config: Arc<Config>,
    db: Pool,
) -> ServiceResult<Router<Body, ApiError>> {
    Router::<Body, ApiError>::builder()
        .data(config.clone())
        .data(db.clone())
        .middleware(Middleware::pre(add_request_id))
        .middleware(Middleware::post_with_info(set_request_id_header))
        .middleware(Middleware::post_with_info(logger))
        .get("/", handler_index)
        .get("/.well-known/jwks.json", handler_index)
        .get("/.well-known/oauth-authorization-server", handler_index)
        .get("/.well-known/openid-configuration", handler_index)
        .get("/.well-known/webfinger", handler_index)
        .get("/oauth/authorize", handler_authorize)
        .post("/oauth/token", handler_token)
        .get("/oauth/auth_test", handler_authorize)
        .get("/oauth/test_cb", handler_test_cb)
        .get("/oauth/sessions/logout", handler_index)
        .get("/oauth/revoke", handler_index)
        .get("/oauth/token/introspect", handler_index)
        .get("/userinfo", handler_index)
        .get("/health/alive", handler_index)
        .get("/health/ready", handler_index)
        .any(handler_not_found)
        .err_handler(error_handler)
        .build()
        .map_err(ServiceError::Router)
}
