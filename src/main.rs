//! This module is the main entrypoint for charon auth.

use std::env;

use hyper::{Body, Method, Request, Response, Server, StatusCode};
use log::{error, info};
use routerify::{Router, RouterService};

use crate::well_known::WellKnown;
use crate::errors::{ServiceError, ServiceResult};

mod errors;
mod token;
mod well_known;

const VERSION: &str = env!("CARGO_PKG_VERSION");
const JSON_MIME_TYPE: &str = "application/json; charset=utf-8";

fn s<S: ToString + ?Sized>(string: &S) -> String {
  string.to_string()
}

async fn handler_index(_: Request<Body>) -> ServiceResult<Response<Body>> {
  let data = serde_json::json!({
      "success": true,
      "message": "How long is forever?",
  });

  Ok(Response::builder()
      .status(StatusCode::OK)
      .header(
          hyper::header::CONTENT_TYPE,
          JSON_MIME_TYPE,
      )
      .body(Body::from(data.to_string()))
      .map_err(ServiceError::Http)?)
}

///
/// The well known endpoint an be used to retrieve information for OpenID Connect clients. We encourage you to not roll
/// your own OpenID Connect client but to use an OpenID Connect client library instead. You can learn more on this
/// flow at https://openid.net/specs/openid-connect-discovery-1_0.html .
///
async fn handler_well_known(req: Request<Body>) -> ServiceResult<Response<Body>> {
  let data = WellKnown {
    issuer: (),
    authorization_endpoint: (),
    token_endpoint: (),
    introspection_endpoint: (),
    userinfo_endpoint: (),
    end_session_endpoint: (),
    registration_endpoint: (),
    revocation_endpoint: (),
    device_authorization_endpoint: (),
    backchannel_authentication_endpoint: (),
    jwks_uri: (),
    grant_types_supported: vec![
      s("authorization_code"),
      s("implicit"),
      s("client_credentials"),
      s("refresh_token"),
    ],
    response_types_supported: vec![
      s("code"),
      s("id_token"),
      s("id_token token"),
      s("code token"),
      s("code id_token token"),
      s("token"),
    ],
    subject_types_supported: vec![s("public")],
    id_token_signing_alg_values_supported: vec![s("RS256")],
    id_token_encryption_alg_values_supported: (),
    id_token_encryption_enc_values_supported: (),
    userinfo_signing_alg_values_supported: vec![s("RS256")],
    request_object_signing_alg_values_supported: vec![
      s("RS256"),
      s("none"),
    ],
    response_modes_supported: vec![s("query"), s("fragment")],
    token_endpoint_auth_methods_supported: (),
    token_endpoint_auth_signing_alg_values_supported: (),
    introspection_endpoint_auth_methods_supported: (),
    introspection_endpoint_auth_signing_alg_values_supported: (),
    claims_supported: (),
    claims_parameter_supported: (),
    claim_types_supported: (),
    scopes_supported: (),
    request_parameter_supported: true,
    request_uri_parameter_supported: true,
    require_request_uri_registration: true,
    code_challenge_methods_supported: vec![s("plain"), s("S256")],
    revocation_endpoint_auth_methods_supported: (),
    revocation_endpoint_auth_signing_alg_values_supported: (),
    backchannel_logout_supported: true,
    backchannel_logout_session_supported: true,
    backchannel_token_delivery_modes_supported: (),
};

  let json = serde_json::to_string(&data)
    .map_err(|e| ServiceError::Serializer(e.to_string()))?;

  Ok(Response::builder()
      .status(StatusCode::OK)
      .header(
          hyper::header::CONTENT_TYPE,
          JSON_MIME_TYPE,
      )
      .body(Body::from(json))
      .map_err(ServiceError::Http)?)
}

async fn handler_userinfo(req: Request<Body>) -> ServiceResult<Response<Body>> {

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
                    JSON_MIME_TYPE,
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
                  JSON_MIME_TYPE,
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
                  JSON_MIME_TYPE,
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
    .get("/.well-known/openid-configuration", handler_well_known)
    .get("/authorize", handler_index)
    .get("/authorize/device", handler_index)
    .get("/token", handler_index)
    .get("/token/introspect", handler_index)
    .get("/userinfo", handler_userinfo)
    .get("/logout", handler_index)
    .get("/revoke", handler_index)
    .get("/ext/ciba/auth", handler_index)
    .get("/revoke", handler_index)
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
