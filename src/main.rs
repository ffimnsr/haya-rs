//! This module is the main entrypoint for charon auth.

use std::env;

use hyper::{Body, Method, Request, Response, Server, StatusCode};
use log::{error, info};
use routerify::{Router, RouterService};

use crate::errors::{ServiceError, ServiceResult};

mod errors;
mod token;

const VERSION: &str = env!("CARGO_PKG_VERSION");

async fn handler_index(_: Request<Body>) -> ServiceResult<Response<Body>> {
  let data = serde_json::json!({
      "success": true,
      "message": "How long is forever?",
  });

  Ok(Response::builder()
      .status(StatusCode::OK)
      .header(
          hyper::header::CONTENT_TYPE,
          "application/json; charset=utf-8",
      )
      .body(Body::from(data.to_string()))
      .map_err(ServiceError::Http)?)
}

async fn handler_not_found(req: Request<Body>) -> ServiceResult<Response<Body>> {
    match *req.method() {
        Method::OPTIONS => Ok(Response::builder()
            .status(StatusCode::NO_CONTENT)
            .header(hyper::header::CONTENT_LENGTH, "0")
            .body(Body::empty())
            .map_err(ServiceError::Http)?),

        _ => {
            let data = serde_json::json!({
                "success": false,
                "message": "Route not found",
            });

            Ok(Response::builder()
                .status(StatusCode::NOT_FOUND)
                .header(
                    hyper::header::CONTENT_TYPE,
                    "application/json; charset=utf-8",
                )
                .body(Body::from(data.to_string()))
                .map_err(ServiceError::Http)?)

        }
    }
}

async fn error_handler(err: routerify::RouteError) -> Response<Body> {
  let svc_err = err.downcast::<ServiceError>().unwrap();

  match svc_err.as_ref() {
      ServiceError::Router { .. } => {
          let data = serde_json::json!({
              "success": false,
              "message": svc_err.to_string(),
          });

          Response::builder()
              .status(StatusCode::INTERNAL_SERVER_ERROR)
              .header(
                  hyper::header::CONTENT_TYPE,
                  "application/json; charset=utf-8",
              )
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
              .header(
                  hyper::header::CONTENT_TYPE,
                  "application/json; charset=utf-8",
              )
              .body(Body::from(data.to_string()))
              .map_err(ServiceError::Http)
              .unwrap()
      }
  }
}

fn router() -> ServiceResult<Router<Body, ServiceError>> {
  Router::<Body, ServiceError>::builder()
    .err_handler(error_handler)
    .get("/", handler_index)
    .any(handler_not_found)
    .build()
    .map_err(|e| ServiceError::Router(e.to_string()))
}

#[tokio::main]
async fn main() -> ServiceResult<()> {
    dotenv::dotenv().ok();

    if env::var("RUST_LOG").is_err() {
      env::set_var("RUST_LOG", "charon=info,hyper=info");
    }

    env_logger::init();

    info!("Booting up Charon IdP v{}", VERSION);

    let router = router()?;
    let service = RouterService::new(router).map_err(|e| ServiceError::Router(e.to_string()))?;

    let addr = ([0, 0, 0, 0], 8008).into();
    info!("Charon IdP is now listening at {}", addr);

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
