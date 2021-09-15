use std::sync::Arc;
use hyper::Body;
use routerify::Router;

use crate::db::Pool;
use crate::config::Config;
use crate::errors::{ApiError, ServiceError, ServiceResult};
use super::handlers::{handler_index, handler_not_found,  error_handler};

pub(crate) fn router(config: Arc<Config>, db: Pool) -> ServiceResult<Router<Body, ApiError>> {
    Router::<Body, ApiError>::builder()
        .data(config.clone())
        .data(db.clone())
        .get("/", handler_index)
        .get("/.well-known/jwks.json", handler_index)
        .get("/.well-known/oauth-authorization-server", handler_index)
        .get("/.well-known/openid-configuration", handler_index)
        .get("/.well-known/webfinger", handler_index)
        .get("/oauth2/auth", handler_index)
        .get("/oauth2/auth/device", handler_index)
        .get("/oauth2/sessions/logout", handler_index)
        .get("/oauth2/revoke", handler_index)
        .get("/oauth2/token", handler_index)
        .get("/oauth2/token/introspect", handler_index)
        .get("/userinfo", handler_index)
        .get("/ext/ciba/auth", handler_index)
        .get("/health/alive", handler_index)
        .get("/health/ready", handler_index)
        .any(handler_not_found)
        .err_handler(error_handler)
        .build()
        .map_err(|e| ServiceError::Router(e.to_string()))
}
