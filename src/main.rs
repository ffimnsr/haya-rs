//! This module is the main entrypoint for haya auth.

use std::env;
use std::fs::File;
use std::sync::Arc;

use clap::App;
use hyper::{Body, Method, Request, Response, Server, StatusCode};
use log::{error, info};
use routerify::{Router, RouterService};

pub(crate) use crate::mime as MimeValues;
pub(crate) use hyper::header as HeaderValues;

use crate::config::Config;
use crate::db::get_db_pool;
use crate::discovery::{handler_provider_configuration, handler_webfinger};
use crate::errors::{ApiError, ApiResult, ServiceError, ServiceResult};
use crate::well_known::WellKnown;

mod authentication;
mod claims;
mod config;
mod db;
mod discovery;
mod end_session;
mod errors;
mod id_token;
mod introspection;
mod mime;
mod strategy;
mod well_known;

const APP_NAME: &str = env!("CARGO_PKG_NAME");
const APP_DESCRIPTION: &str = env!("CARGO_PKG_DESCRIPTION");
const VERSION: &str = env!("CARGO_PKG_VERSION");
const AUTHORS: &str = env!("CARGO_PKG_AUTHORS");
const MANIFEST_DIR: &str = env!("CARGO_MANIFEST_DIR");

async fn handler_index(_req: Request<Body>) -> ApiResult<Response<Body>> {
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

async fn handler_not_found(req: Request<Body>) -> ApiResult<Response<Body>> {
    match *req.method() {
        Method::OPTIONS => Ok(Response::builder()
            .status(StatusCode::NO_CONTENT)
            .header(HeaderValues::CONTENT_LENGTH, "0")
            .body(Body::empty())
            .map_err(ApiError::Http)?),

        _ => {
            let data = serde_json::json!({
                "success": false,
                "message": "Route not found",
            });

            Ok(Response::builder()
                .status(StatusCode::NOT_FOUND)
                .header(HeaderValues::CONTENT_TYPE, MimeValues::JSON_MIME_TYPE)
                .body(Body::from(data.to_string()))
                .map_err(ApiError::Http)?)
        }
    }
}

async fn error_handler(err: routerify::RouteError) -> Response<Body> {
    let svc_err = err.downcast::<ApiError>().unwrap();

    match svc_err.as_ref() {
        ApiError::Http(e) => {
            let data = serde_json::json!({
                "success": false,
                "message": e.to_string(),
            });

            Response::builder()
                .status(StatusCode::INTERNAL_SERVER_ERROR)
                .header(HeaderValues::CONTENT_TYPE, MimeValues::JSON_MIME_TYPE)
                .body(Body::from(data.to_string()))
                .map_err(ServiceError::Http)
                .unwrap()
        }
        _ => {
            let data = serde_json::json!({
                "success": false,
                "message": svc_err.to_string(),
            });

            Response::builder()
                .status(StatusCode::INTERNAL_SERVER_ERROR)
                .header(HeaderValues::CONTENT_TYPE, MimeValues::JSON_MIME_TYPE)
                .body(Body::from(data.to_string()))
                .map_err(ServiceError::Http)
                .unwrap()
        }
    }
}

fn router(config_path: &String) -> ServiceResult<Router<Body, ApiError>> {
    let dbpool = get_db_pool()?;
    let config = parse_config(&config_path)?;

    Router::<Body, ApiError>::builder()
        .data(config.clone())
        .data(dbpool.clone())
        .get("/", handler_index)
        .get("/.well-known/oauth-authorization-server", handler_index)
        .get(
            "/.well-known/openid-configuration",
            handler_provider_configuration,
        )
        .get("/.well-known/webfinger", handler_webfinger)
        .get("/authorize", handler_index)
        .get("/authorize/device", handler_index)
        .get("/token", handler_index)
        .get("/token/introspect", handler_index)
        .get("/userinfo", handler_index)
        .get("/logout", handler_index)
        .get("/revoke", handler_index)
        .get("/ext/ciba/auth", handler_index)
        .get("/clients", handler_index)
        .get("/clients/:id", handler_index)
        .get("/health/alive", handler_index)
        .get("/health/ready", handler_index)
        .get("/flush", handler_index)
        .any(handler_not_found)
        .err_handler(error_handler)
        .build()
        .map_err(|e| ServiceError::Router(e.to_string()))
}

fn parse_config(config_path: &String) -> ServiceResult<Arc<Config>> {
    let config_file =
        File::open(config_path).map_err(|e| ServiceError::Io(e.to_string()))?;
    let config = serde_yaml::from_reader(config_file)
        .map(|u| Arc::new(u))
        .map_err(|e| ServiceError::Parser(e.to_string()));

    config
}

#[tokio::main]
async fn main() -> ServiceResult<()> {
    dotenv::dotenv().ok();

    if env::var("RUST_LOG").is_err() {
        env::set_var("RUST_LOG", "haya=info,hyper=info");
    }

    env_logger::init();

    let config_path = format!("{}/config.yaml", MANIFEST_DIR);

    let _ = App::new(APP_NAME)
        .version(VERSION)
        .author(AUTHORS)
        .about(APP_DESCRIPTION)
        .get_matches();

    info!("Booting up Haya OP v{}", VERSION);
    info!("Config file: {}", config_path);

    let router = router(&config_path)?;
    let service =
        RouterService::new(router).map_err(|e| ServiceError::Router(e.to_string()))?;

    let addr = ([0, 0, 0, 0], 8008).into();
    info!("Haya OP is now listening at {}", addr);

    let server = Server::bind(&addr).serve(service);

    if let Err(e) = server.await {
        error!("Fatal error occurred: {}", e);
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_handler_index_should_ok() {
        let req = Request::<Body>::default();
        let resp = handler_index(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_handler_404_should_ok() {
        let _data = serde_json::json!({
            "success": true,
            "message": "How long is forever?",
        });

        let req = Request::<Body>::default();
        let resp = handler_not_found(req).await.unwrap();
        let (parts, _body) = resp.into_parts();
        assert_eq!(parts.status, StatusCode::NOT_FOUND);
    }
}
