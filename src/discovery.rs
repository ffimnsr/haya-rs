//! This module handles the well known endpoints.

use hyper::{Body, Request, Response, StatusCode};
use routerify::prelude::*;

use crate::config::Config;
use crate::errors::{ApiError, ApiResult};
use crate::well_known::WellKnown;
use crate::{HeaderValues, MimeValues};

pub(crate) async fn handler_webfinger(_req: Request<Body>) -> ApiResult<Response<Body>> {
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

/// The provider configuration endpoint an be used to retrieve information
/// for OpenID Connect clients. We encourage you to not roll your own OpenID
/// Connect client but to use an OpenID Connect client library instead. You can
/// learn more on this flow at https://openid.net/specs/openid-connect-discovery-1_0.html.
pub(crate) async fn handler_provider_configuration(
    req: Request<Body>,
) -> ApiResult<Response<Body>> {
    let config = req
        .data::<Config>()
        .ok_or_else(|| ApiError::MissingRouteData("Config is missing".to_string()))?;

    let data = WellKnown {
        issuer: config.get_issuer_url(),
        authorization_endpoint: config.get_authorization_url(),
        token_endpoint: config.get_token_url(),
        introspection_endpoint: config.get_introspection_url(),
        userinfo_endpoint: config.get_userinfo_url(),
        end_session_endpoint: config.get_logout_url(),
        registration_endpoint: config.get_client_registration_url(),
        revocation_endpoint: config.get_revocation_url(),
        device_authorization_endpoint: config.get_device_authorization_url(),
        backchannel_authentication_endpoint: config.get_backchannel_authentication_url(),
        jwks_uri: config.get_jwks_certs_url(),
        op_policy_uri: config.get_jwks_certs_url(),
        op_tos_uri: config.get_jwks_certs_url(),
        service_documentation_uri: config.get_jwks_certs_url(),
        grant_types_supported: vec![
            String::from("authorization_code"),
            String::from("implicit"),
            String::from("client_credentials"),
            String::from("refresh_token"),
            String::from("urn:ietf:params:oauth:grant-type:device_code"),
            String::from("urn:openid:params:grant-type:ciba"),
        ],
        response_types_supported: vec![
            String::from("code"),
            String::from("id_token"),
            String::from("id_token token"),
            String::from("code token"),
            String::from("code id_token token"),
            String::from("token"),
            String::from("none"),
        ],
        subject_types_supported: vec![String::from("public")],
        id_token_signing_alg_values_supported: vec![String::from("RS256")],
        id_token_encryption_alg_values_supported: vec![],
        id_token_encryption_enc_values_supported: vec![],
        userinfo_signing_alg_values_supported: vec![String::from("RS256")],
        request_object_signing_alg_values_supported: vec![
            String::from("RS256"),
            String::from("none"),
        ],
        response_modes_supported: vec![String::from("query"), String::from("fragment")],
        token_endpoint_auth_methods_supported: vec![],
        token_endpoint_auth_signing_alg_values_supported: vec![],
        introspection_endpoint_auth_methods_supported: vec![],
        introspection_endpoint_auth_signing_alg_values_supported: vec![],
        claims_supported: vec![
            String::from("sub"),
            String::from("name"),
            String::from("preferred_username"),
            String::from("given_name"),
            String::from("family_name"),
            String::from("middle_name"),
            String::from("nickname"),
            String::from("profile"),
            String::from("picture"),
            String::from("website"),
            String::from("gender"),
            String::from("zoneinfo"),
            String::from("locale"),
            String::from("updated_at"),
            String::from("birthdate"),
            String::from("email"),
            String::from("email_verified"),
            String::from("phone_number"),
            String::from("phone_number_verified"),
            String::from("address"),
        ],
        claims_parameter_supported: true,
        claim_types_supported: vec![],
        scopes_supported: vec![
            String::from("offline_access"),
            String::from("offline"),
            String::from("openid"),
        ],
        request_parameter_supported: true,
        request_uri_parameter_supported: false,
        require_request_uri_registration: false,
        code_challenge_methods_supported: vec![
            String::from("plain"),
            String::from("S256"),
        ],
        revocation_endpoint_auth_methods_supported: vec![],
        revocation_endpoint_auth_signing_alg_values_supported: vec![],
        backchannel_logout_supported: true,
        backchannel_logout_session_supported: true,
        backchannel_token_delivery_modes_supported: vec![],
    };

    let data = WellKnown::default();
    let json =
        serde_json::to_string(&data).map_err(|e| ApiError::Serializer(e.to_string()))?;

    Ok(Response::builder()
        .status(StatusCode::OK)
        .header(HeaderValues::CONTENT_TYPE, MimeValues::JSON_MIME_TYPE)
        .body(Body::from(json))
        .map_err(ApiError::Http)?)
}
