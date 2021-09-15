//! This module handles the well known endpoints.

use hyper::{Body, Request, Response, StatusCode};
use routerify::prelude::*;
use serde::{Deserialize, Serialize};
use std::sync::Arc;

use crate::config::Config;
use crate::errors::{ApiError, ApiResult};
use crate::{HeaderValues, MimeValues};

/// ProviderMetadata represents important OpenID Connect discovery metadata
///
/// It includes links to several endpoints and exposes information on supported
/// signature algorithms among others.
#[derive(Debug, Default, Clone, PartialEq, Serialize, Deserialize)]
pub(crate) struct ProviderMetadata {
    /// URL using the https scheme with no query or fragment component that the
    /// OP asserts as its IssuerURL Identifier. If IssuerURL discovery is
    /// supported , this value MUST be identical to the issuer value returned by
    /// WebFinger. This also MUST be identical to the iss Claim value in ID
    /// Tokens issued from this IssuerURL.
    pub issuer: String,

    /// URL of the OP's OAuth 2.0 Authorization Endpoint.
    pub authorization_endpoint: String,

    /// URL of the OP's OAuth 2.0 Token Endpoint. his is REQUIRED unless only
    /// the Implicit Flow is used.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub token_endpoint: Option<String>,

    /// URL of the OP's UserInfo Endpoint. This URL MUST use the https scheme
    /// and MAY contain port, path, and query parameter components.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub userinfo_endpoint: Option<String>,

    /// URL of the OP's JSON Web Key Set document. This contains the signing
    /// key(s) the RP uses to validate signatures from the OP. The JWK Set MAY
    /// also contain the Server's encryption key(s), which are used by RPs to
    /// encrypt requests to the Server. When both signing and encryption keys
    /// are made available, a use (Key Use) parameter value is REQUIRED for all
    /// keys in the referenced JWK Set to indicate each key's intended usage.
    /// Although some algorithms allow the same key to be used for both
    /// signatures and encryption, doing so is NOT RECOMMENDED, as it is less
    /// secure. The JWK x5c parameter MAY be used to provide X.509
    /// representations of keys provided. When used, the bare key values MUST
    /// still be present and MUST match those in the certificate.
    pub jwks_uri: String,

    /// URL of the OP's Dynamic Client Registration Endpoint.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub registration_endpoint: Option<String>,

    /// JSON array containing a list of the OAuth 2.0 [RFC6749] scope values
    /// that this server supports. The server MUST support the openid scope
    /// value. Servers MAY choose not to advertise some supported scope values
    /// even when this parameter is used.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scopes_supported: Option<Vec<String>>,

    /// JSON array containing a list of the OAuth 2.0 response_type values that
    /// this OP supports. Dynamic OpenID Providers MUST support the code,
    /// id_token, and the token id_token Response Type values.
    pub response_types_supported: Vec<String>,

    /// JSON array containing a list of the OAuth 2.0 response_mode values that
    /// this OP supports.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub response_modes_supported: Option<Vec<String>>,

    /// JSON array containing a list of the OAuth 2.0 Grant Type values that
    /// this OP supports.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub grant_types_supported: Option<Vec<String>>,

    /// JSON array containing a list of the Authentication Context Class
    /// References that this OP supports.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub acr_values_supported: Option<Vec<String>>,

    /// JSON array containing a list of the Subject Identifier types that this
    /// OP supports. Valid types include pairwise and public.
    pub subject_types_supported: Vec<String>,

    /// JSON array containing a list of the JWS signing algorithms (alg values)
    /// supported by the OP for the ID Token to encode the Claims in a JWT. The
    /// algorithm RS256 MUST be included. The value none MAY be supported, but
    /// MUST NOT be used unless the Response Type used returns no ID Token from
    /// the Authorization Endpoint (such as when using the Authorization Code
    /// Flow).
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub id_token_signing_alg_values_supported: Vec<String>,

    /// JSON array containing a list of the JWE encryption algorithms (alg
    /// values) supported by the OP for the ID Token to encode the Claims in a
    /// JWT.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id_token_encryption_alg_values_supported: Option<Vec<String>>,

    /// JSON array containing a list of the JWE encryption algorithms (enc
    /// values) supported by the OP for the ID Token to encode the Claims in a
    /// JWT.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id_token_encryption_enc_values_supported: Option<Vec<String>>,

    /// JSON array containing a list of the JWS signing algorithms (alg values)
    /// supported by the UserInfo Endpoint to encode the Claims in a JWT.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub userinfo_signing_alg_values_supported: Option<Vec<String>>,

    /// JSON array containing a list of the JWS encryption algorithms (alg
    /// values) supported by the UserInfo Endpoint to encode the Claims in a
    /// JWT.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub userinfo_encryption_alg_values_supported: Option<Vec<String>>,

    /// JSON array containing a list of the JWS encryption algorithms (enc
    /// values) supported by the UserInfo Endpoint to encode the Claims in a
    /// JWT.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub userinfo_encryption_enc_values_supported: Option<Vec<String>>,

    /// JSON array containing a list of the JWS signing algorithms (alg values)
    /// supported by the OP for Request Objects, which are described in Section
    /// 6.1 of OpenID Connect Core 1.0. hese algorithms are used both when the
    /// Request Object is passed by value (using the request parameter) and when
    /// it is passed by reference (using the request_uri parameter). Servers
    /// SHOULD support none and RS256.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request_object_signing_alg_values_supported: Option<Vec<String>>,

    /// JSON array containing a list of the JWE encryption algorithms (alg
    /// values) supported by the OP for Request Objects. These algorithms are
    /// used both when the Request Object is passed by value and when it is
    /// passed by reference.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request_object_encryption_alg_values_supported: Option<Vec<String>>,

    /// JSON array containing a list of the JWE encryption algorithms (enc
    /// values) supported by the OP for Request Objects. These algorithms are
    /// used both when the Request Object is passed by value and when it is
    /// passed by reference.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request_object_encryption_enc_values_supported: Option<Vec<String>>,

    /// JSON array containing a list of Client Authentication methods supported
    /// by this Token Endpoint. The options are client_secret_post,
    /// client_secret_basic, client_secret_jwt, and private_key_jwt, as
    /// described in Section 9 of OpenID Connect Core 1.0.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub token_endpoint_auth_methods_supported: Option<Vec<String>>,

    /// JSON array containing a list of the JWS signing algorithms (alg values)
    /// supported by the Token Endpoint for the signature on the JWT used to
    /// authenticate the Client at the Token Endpoint for the private_key_jwt
    /// and client_secret_jwt authentication methods. Servers SHOULD support
    /// RS256. The value none MUST NOT be used.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub token_endpoint_auth_signing_alg_values_supported: Option<Vec<String>>,

    /// JSON array containing a list of the display parameter values that the
    /// OpenID Provider supports. These values are described in Section 3.1.2.1
    /// of OpenID Connect Core 1.0.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub display_values_supported: Option<Vec<String>>,

    /// JSON array containing a list of the Claim Types that the OpenID Provider
    /// supports. These Claim Types are described in Section 5.6 of OpenID
    /// Connect Core 1.0. Values defined by this specification are normal,
    /// aggregated, and distributed. If omitted, the implementation supports
    /// only normal Claims.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub claim_types_supported: Option<Vec<String>>,

    /// JSON array containing a list of the Claim Names of the Claims that the
    /// OpenID Provider MAY be able to supply values for. Note that for privacy
    /// or other reasons, this might not be an exhaustive list.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub claims_supported: Option<Vec<String>>,

    /// URL of a page containing human-readable information that developers
    /// might want or need to know when using the OpenID Provider. In
    /// particular, if the OpenID Provider does not support Dynamic Client
    /// Registration, then information on how to register Clients needs to be
    /// provided in this documentation.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub service_documentation: Option<String>,

    /// Languages and scripts supported for values in Claims being returned,
    /// represented as a JSON array of BCP47 language tag values. Not all
    /// languages and scripts are necessarily supported for all Claim values.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub claims_locales_supported: Option<Vec<String>>,

    /// Languages and scripts supported for the user interface, represented as a
    /// JSON array of BCP47 language tag values.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ui_locales_supported: Option<Vec<String>>,

    /// Boolean value specifying whether the OP supports use of the claims
    /// parameter, with true indicating support. If omitted, the default value
    /// is false.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub claims_parameter_supported: Option<bool>,

    /// Boolean value specifying whether the OP supports use of the request
    /// parameter, with true indicating support. If omitted, the default value
    /// is false.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request_parameter_supported: Option<bool>,

    /// Boolean value specifying whether the OP supports use of the request_uri
    /// parameter, with true indicating support. If omitted, the default value
    /// is true.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request_uri_parameter_supported: Option<bool>,

    /// Boolean value specifying whether the OP requires any request_uri values
    /// used to be pre-registered using the request_uris registration parameter.
    /// Pre-registration is REQUIRED when the value is true. If omitted, the
    /// default value is false.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub require_request_uri_registration: Option<bool>,

    /// URL that the OpenID Provider provides to the person registering the
    /// Client to read about the OP's requirements on how the Relying Party can
    /// use the data provided by the OP. The registration process SHOULD display
    /// this URL to the person registering the Client if it is given.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub op_policy_uri: Option<String>,

    /// URL that the OpenID Provider provides to the person registering the
    /// Client to read about OpenID Provider's terms of service. The
    /// registration process SHOULD display this URL to the person registering
    /// the Client if it is given.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub op_tos_uri: Option<String>,

    /// URL of the OP's Introspection Endpoint
    #[serde(skip_serializing_if = "Option::is_none")]
    pub introspection_endpoint: Option<String>,

    /// JSON array containing a list of client authentication methods supported
    /// by this introspection endpoint.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub introspection_endpoint_auth_methods_supported: Option<Vec<String>>,

    /// JSON array containing a list of the JWS signing algorithms ("alg"
    /// values) supported by the introspection endpoint for the signature on the
    /// JWT used to authenticate the client at the introspection endpoint for
    /// the "private_key_jwt" and "client_secret_jwt" authentication methods.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub introspection_endpoint_auth_signing_alg_values_supported: Option<Vec<String>>,

    /// URL of the authorization server's OAuth 2.0 revocation endpoint.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub revocation_endpoint: Option<String>,

    /// JSON array containing a list of client authentication methods supported
    /// by this revocation endpoint. The valid client authentication method
    /// values are those registered in the IANA "OAuth Token Endpoint
    /// Authentication Methods" registry.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub revocation_endpoint_auth_methods_supported: Option<Vec<String>>,

    /// JSON array containing a list of the JWS signing algorithms ("alg"
    /// values) supported by the revocation endpoint for the signature on the
    /// JWT used to authenticate the client at the revocation endpoint for the
    /// "private_key_jwt" and "client_secret_jwt" authentication methods. This
    /// metadata entry MUST be present if either of these authentication methods
    /// are specified in the "revocation_endpoint_auth_methods_supported" entry.
    /// No default algorithms are implied if this entry is  omitted. The value
    /// "none" MUST NOT be used.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub revocation_endpoint_auth_signing_alg_values_supported: Option<Vec<String>>,

    /// JSON array containing a list of Proof Key for Code Exchange (PKCE) code
    /// challenge methods supported by this authorization server.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub code_challenge_methods_supported: Option<Vec<String>>,

    /// JSON array containing one or more of the following values: poll, ping,
    /// and push.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub backchannel_token_delivery_modes_supported: Vec<String>,

    /// URL of the OP's Backchannel Authentication Endpoint
    pub backchannel_authentication_endpoint: String,

    /// JSON array containing a list of the JWS signing algorithms (alg values)
    /// supported by the OP for signed authentication requests, which are
    /// described in Section 7.1.1. If omitted, signed authentication requests
    /// are not supported by the OP.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub backchannel_authentication_request_signing_alg_values_supported:
        Option<Vec<String>>,

    /// Boolean value specifying whether the OP supports the use of the
    /// user_code parameter, with true indicating support. If omitted, the
    /// default value is false.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub backchannel_user_code_parameter_supported: Option<bool>,

    /// Boolean value specifying whether the OP supports back-channel logout,
    /// with true indicating support. If omitted, the default value is false.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub backchannel_logout_supported: Option<bool>,

    /// Boolean value specifying whether the OP can pass a sid (session ID)
    /// Claim in the Logout Token to identify the RP session with the OP. If
    /// supported, the sid Claim is also included in ID Tokens issued by the OP.
    /// If omitted, the default value is false.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub backchannel_logout_session_supported: Option<bool>,

    /// URL at the OP to which an RP can perform a redirect to request that the
    /// End-User be logged out at the OP.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub end_session_endpoint: Option<String>,

    /// URL of the authorization server's device authorization endpoint.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub device_authorization_endpoint: Option<String>,
}

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

/// The provider configuration endpoint an be used to retrieve information for
/// OpenID Connect clients. We encourage you to not roll your own OpenID Connect
/// client but to use an OpenID Connect client library instead. You can learn
/// more on this flow at
/// https://openid.net/specs/openid-connect-discovery-1_0.html.
pub(crate) async fn handler_metadata(req: Request<Body>) -> ApiResult<Response<Body>> {
    let config = req
        .data::<Arc<Config>>()
        .ok_or_else(|| ApiError::MissingRouteData("Config is missing".to_string()))?;

    let data = ProviderMetadata {
        issuer: config.get_issuer_url(),
        authorization_endpoint: config.get_authorization_url(),
        token_endpoint: Some(config.get_token_url()),
        userinfo_endpoint: Some(config.get_userinfo_url()),
        end_session_endpoint: Some(config.get_logout_url()),
        registration_endpoint: Some(config.get_client_registration_url()),
        device_authorization_endpoint: Some(config.get_device_authorization_url()),
        jwks_uri: config.get_jwks_certs_url(),
        op_policy_uri: Some(config.get_jwks_certs_url()),
        op_tos_uri: Some(config.get_jwks_certs_url()),
        service_documentation: Some(config.get_jwks_certs_url()),
        grant_types_supported: Some(vec![
            String::from("authorization_code"),
            String::from("implicit"),
            String::from("client_credentials"),
            String::from("refresh_token"),
            String::from("urn:ietf:params:oauth:grant-type:device_code"),
            String::from("urn:openid:params:grant-type:ciba"),
        ]),
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
        id_token_encryption_alg_values_supported: None,
        id_token_encryption_enc_values_supported: None,
        userinfo_signing_alg_values_supported: Some(vec![String::from("RS256")]),
        request_object_signing_alg_values_supported: Some(vec![
            String::from("RS256"),
            String::from("none"),
        ]),
        response_modes_supported: Some(vec![
            String::from("query"),
            String::from("fragment"),
        ]),
        token_endpoint_auth_methods_supported: None,
        token_endpoint_auth_signing_alg_values_supported: None,
        introspection_endpoint: Some(config.get_introspection_url()),
        introspection_endpoint_auth_methods_supported: None,
        introspection_endpoint_auth_signing_alg_values_supported: None,
        claims_supported: Some(vec![
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
        ]),
        claims_parameter_supported: Some(true),
        claim_types_supported: None,
        scopes_supported: Some(vec![
            String::from("offline_access"),
            String::from("offline"),
            String::from("openid"),
        ]),
        request_parameter_supported: Some(true),
        request_uri_parameter_supported: Some(false),
        require_request_uri_registration: Some(false),
        code_challenge_methods_supported: Some(vec![
            String::from("plain"),
            String::from("S256"),
        ]),
        revocation_endpoint: Some(config.get_revocation_url()),
        revocation_endpoint_auth_methods_supported: None,
        revocation_endpoint_auth_signing_alg_values_supported: None,
        acr_values_supported: None,
        userinfo_encryption_alg_values_supported: None,
        userinfo_encryption_enc_values_supported: None,
        request_object_encryption_alg_values_supported: None,
        request_object_encryption_enc_values_supported: None,
        display_values_supported: None,
        claims_locales_supported: None,
        ui_locales_supported: None,
        backchannel_token_delivery_modes_supported: vec![],
        backchannel_authentication_endpoint: config.get_backchannel_authentication_url(),
        backchannel_authentication_request_signing_alg_values_supported: None,
        backchannel_user_code_parameter_supported: None,
        backchannel_logout_supported: Some(true),
        backchannel_logout_session_supported: Some(true),
    };

    let json =
        serde_json::to_string(&data).map_err(|e| ApiError::Serializer(e.to_string()))?;

    Ok(Response::builder()
        .status(StatusCode::OK)
        .header(HeaderValues::CONTENT_TYPE, MimeValues::JSON_MIME_TYPE)
        .body(Body::from(json))
        .map_err(ApiError::Http)?)
}
