use serde::{Deserialize, Serialize};

/// OauthAuthorizationServerMetadata represents important OAuth 2.0
/// authorization server metadata
///
/// It includes links to several endpoints and exposes information on supported
/// signature algorithms among others.
/// https://tools.ietf.org/id/draft-ietf-oauth-discovery-08.html
#[derive(Debug, Default, Clone, PartialEq, Serialize, Deserialize)]
pub(crate) struct OauthServerMetadata {
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

    /// JSON array containing a list of Client Authentication methods supported
    /// by this Token Endpoint. The options are client_secret_post,
    /// client_secret_basic, client_secret_jwt, and private_key_jwt, as
    /// described in Section 9 of OpenID Connect Core 1.0.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub token_endpoint_auth_methods_supported: Option<Vec<String>>,

    /// JSON array containing a list of the JWS signing algorithms (alg values)
    /// supported by the Token Endpoint for the signature on the JWT used to
    /// authenticate the Client at the Token Endpoint for the private_key_jwt
    /// and client_secret_jwt authentication methods. The value none MUST NOT be
    /// used.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub token_endpoint_auth_signing_alg_values_supported: Option<Vec<String>>,

    /// URL of a page containing human-readable information that developers
    /// might want or need to know when using the OpenID Provider. In
    /// particular, if the OpenID Provider does not support Dynamic Client
    /// Registration, then information on how to register Clients needs to be
    /// provided in this documentation.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub service_documentation: Option<String>,

    /// Languages and scripts supported for the user interface, represented as a
    /// JSON array of BCP47 language tag values.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ui_locales_supported: Option<Vec<String>>,

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

    /// JSON array containing a list of Proof Key for Code Exchange (PKCE) code
    /// challenge methods supported by this authorization server.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub code_challenge_methods_supported: Option<Vec<String>>,
}
