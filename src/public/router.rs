use hyper::header::HeaderValue;
use hyper::{Body, Request, Response};
use routerify::prelude::*;
use routerify::{Middleware, RequestInfo, Router};
use uuid::Uuid;

use super::handler::*;
use crate::DbContext;
use crate::error::{ApiError, ApiResult, ServiceError, ServiceResult};

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

fn wellknown_router() -> Router<Body, ApiError> {
    Router::<Body, ApiError>::builder()
        .get("/jwks.json", handler_jwks)
        .get("/oauth-authorization-server", handler_metadata)
        .get("/openid-configuration", handler_metadata)
        .build()
        .unwrap()
}

fn health_router() -> Router<Body, ApiError> {
    Router::<Body, ApiError>::builder()
        .get("/alive", handler_health_alive)
        .get("/ready", handler_health_ready)
        .build()
        .unwrap()
}

fn clients_router() -> Router<Body, ApiError> {
    Router::<Body, ApiError>::builder()
        .get("/", handler_metadata)
        .post("/", handler_metadata)
        .get("/:id", handler_metadata)
        .put("/:id", handler_metadata)
        .patch("/:id", handler_metadata)
        .delete("/:id", handler_metadata)
        .build()
        .unwrap()
}

fn keys_router() -> Router<Body, ApiError> {
    Router::<Body, ApiError>::builder()
        .get("/:set", handler_metadata)
        .put("/:set", handler_metadata)
        .post("/:set", handler_metadata)
        .delete("/:set", handler_metadata)
        .get("/:set/:kid", handler_metadata)
        .put("/:set/:kid", handler_metadata)
        .delete("/:set/:kid", handler_metadata)
        .build()
        .unwrap()
}

fn oauth2_auth_router() -> Router<Body, ApiError> {
    Router::<Body, ApiError>::builder()
    .get("/", handler_authorize)
    .get("/requests/consent", handler_introspect)
    .put("/requests/consent/accept", handler_introspect)
    .put("/requests/consent/reject", handler_introspect)
    .get("/requests/login", handler_introspect)
    .put("/requests/login/accept", handler_introspect)
    .put("/requests/login/reject", handler_introspect)
    .get("/requests/logout", handler_introspect)
    .put("/requests/logout/accept", handler_introspect)
    .put("/requests/logout/reject", handler_introspect)
    .get("/sessions/consent", handler_introspect)
    .delete("/sessions/consent", handler_introspect)
    .delete("/sessions/login", handler_introspect)
    .build()
    .unwrap()
}

fn oauth2_router() -> Router<Body, ApiError> {
    Router::<Body, ApiError>::builder()
        .scope("/auth", oauth2_auth_router())
        .post("/flush", handler_introspect)
        .post("/instropect", handler_introspect)
        .post("/revoke", handler_introspect)
        .get("/sessions/logout", handler_introspect)
        .post("/token", handler_token)
        .delete("/tokens", handler_token)
        .build()
        .unwrap()
}

pub(crate) fn router(
    db: DbContext,
) -> ServiceResult<Router<Body, ApiError>> {
    Router::<Body, ApiError>::builder()
        .data(db.clone())
        .middleware(Middleware::pre(add_request_id))
        .middleware(Middleware::post_with_info(set_request_id_header))
        .middleware(Middleware::post_with_info(logger))
        .get("/", handler_index)
        .get("/trace", handler_trace)
        .get("/userinfo", handler_trace)
        .get("/version", handler_trace)
        .scope("/.well-known", wellknown_router())
        .scope("/clients", clients_router())
        .scope("/keys", keys_router())
        .scope("/oauth2", oauth2_router())
        .scope("/health", health_router())
        .any(handler_not_found)
        .err_handler(error_handler)
        .build()
        .map_err(ServiceError::Router)
}
