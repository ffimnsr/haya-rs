use hyper::{StatusCode, Response, Request, Body};

use crate::models::OauthAuthorizationServerMetadata;
use crate::errors::{ApiResult, ApiError};
use crate::{HeaderValues, MimeValues};

pub(crate) async fn handler_metadata(_: Request<Body>) -> ApiResult<Response<Body>> {
    let metadata = OauthAuthorizationServerMetadata {
        issuer: String::from("/"),
        authorization_endpoint: String::from("/oauth/authorize"),
        token_endpoint: Some(String::from("/oauth/token")),
        jwks_uri: String::from("/.well-known/jwks.json"),
        registration_endpoint: None,
        scopes_supported: Some(vec![
            String::from("profile"),
        ]),
        response_types_supported: vec![
            String::from("code"),
        ],
        response_modes_supported: Some(vec![
            String::from("query"),
            String::from("fragment"),
            String::from("form_post"),
        ]),
        grant_types_supported: Some(vec![
            String::from("authorization_code"),
            String::from("refresh_token"),
        ]),
        token_endpoint_auth_methods_supported: Some(vec![
            String::from("private_key_jwt"),
        ]),
        token_endpoint_auth_signing_alg_values_supported: Some(vec![
            String::from("ES256"),
        ]),
        service_documentation: None,
        op_policy_uri: None,
        op_tos_uri: None,
        ui_locales_supported: Some(vec![
            String::from("en-US"),
        ]),
        revocation_endpoint: Some(String::from("/oauth/revoke")),
        revocation_endpoint_auth_methods_supported: Some(vec![
            String::from("private_key_jwt"),
        ]),
        revocation_endpoint_auth_signing_alg_values_supported: Some(vec![
            String::from("ES256"),
        ]),
        introspection_endpoint: Some(String::from("/oauth/token/introspect")),
        introspection_endpoint_auth_methods_supported: Some(vec![
            String::from("private_key_jwt"),
        ]),
        introspection_endpoint_auth_signing_alg_values_supported: Some(vec![
            String::from("ES256"),
        ]),
        code_challenge_methods_supported: Some(vec![
            String::from("S256"),
            String::from("plain"),
        ]),
    };

    let json =
        serde_json::to_string(&metadata).map_err(ApiError::Json)?;

    Response::builder()
        .status(StatusCode::OK)
        .header(HeaderValues::CONTENT_TYPE, MimeValues::JSON_MIME_TYPE)
        .body(Body::from(json))
        .map_err(ApiError::Http)
}
