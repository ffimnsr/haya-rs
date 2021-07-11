use serde::{Deserialize, Serialize};

pub(crate) type VecString = Vec<String>;

/// WellKnown represents important OpenID Connect discovery metadata
///
/// It includes links to several endpoints and exposes information on supported signature algorithms
/// among others.
#[derive(Debug, Default, PartialEq, Serialize, Deserialize)]
pub(crate) struct WellKnown {
    /// URL using the https scheme with no query or fragment component that the OP asserts as its IssuerURL Identifier.
    /// If IssuerURL discovery is supported , this value MUST be identical to the issuer value returned
    /// by WebFinger. This also MUST be identical to the iss Claim value in ID Tokens issued from this IssuerURL.
    /// Required: true
    pub issuer: String,

    /// URL of the OP's OAuth 2.0 Authorization Endpoint.
    /// Required: true
    pub authorization_endpoint: String,

    /// URL of the OP's OAuth 2.0 Token Endpoint.
    /// Required: true
    pub token_endpoint: String,

    /// URL of the OP's Introspection Endpoint
    pub introspection_endpoint: String,

    /// URL of the OP's UserInfo Endpoint.
    pub userinfo_endpoint: String,

    /// URL at the OP to which an RP can perform a redirect to request that the End-User be logged out at the OP.
    pub end_session_endpoint: String,

    /// URL of the OP's Dynamic Client Registration Endpoint.
    pub registration_endpoint: String,

    /// URL of the authorization server's OAuth 2.0 revocation endpoint.
    pub revocation_endpoint: String,

    /// TODO
    pub device_authorization_endpoint: String,

    /// TODO
    pub backchannel_authentication_endpoint: String,

    /// URL of the OP's JSON Web Key Set [JWK] document. This contains the signing key(s) the RP uses to validate
    /// signatures from the OP. The JWK Set MAY also contain the Server's encryption key(s), which are used by RPs
    /// to encrypt requests to the Server. When both signing and encryption keys are made available, a use (Key Use)
    /// parameter value is REQUIRED for all keys in the referenced JWK Set to indicate each key's intended usage.
    /// Although some algorithms allow the same key to be used for both signatures and encryption, doing so is
    /// NOT RECOMMENDED, as it is less secure. The JWK x5c parameter MAY be used to provide X.509 representations of
    /// keys provided. When used, the bare key values MUST still be present and MUST match those in the certificate.
    /// Required: true
    pub jwks_uri: String,

    /// JSON array containing a list of the OAuth 2.0 Grant Type values that this OP supports.
    pub grant_types_supported: VecString,

    /// JSON array containing a list of the OAuth 2.0 response_type values that this OP supports. Dynamic OpenID
    /// Providers MUST support the code, id_token, and the token id_token Response Type values.
    /// Required: true
    pub response_types_supported: VecString,

    /// JSON array containing a list of the Subject Identifier types that this OP supports. Valid types include
    /// pairwise and public.
    /// Required: true
    pub subject_types_supported: VecString,

    /// JSON array containing a list of the JWS signing algorithms (alg values) supported by the OP for the ID Token
    /// to encode the Claims in a JWT.
    /// Required: true
    pub id_token_signing_alg_values_supported: VecString,

    /// TODO
    pub id_token_encryption_alg_values_supported: VecString,

    /// TODO
    pub id_token_encryption_enc_values_supported: VecString,

    /// JSON array containing a list of the JWS [JWS] signing algorithms (alg values) [JWA] supported by the UserInfo Endpoint to encode the Claims in a JWT [JWT].
    pub userinfo_signing_alg_values_supported: VecString,

    /// TODO
    pub request_object_signing_alg_values_supported: VecString,

    /// JSON array containing a list of the OAuth 2.0 response_mode values that this OP supports.
    pub response_modes_supported: VecString,

    /// JSON array containing a list of Client Authentication methods supported by this Token Endpoint. The options are
    /// client_secret_post, client_secret_basic, client_secret_jwt, and private_key_jwt, as described in Section 9 of OpenID Connect Core 1.0.
    pub token_endpoint_auth_methods_supported: VecString,

    /// TODO
    pub token_endpoint_auth_signing_alg_values_supported: VecString,

    /// TODO
    pub introspection_endpoint_auth_methods_supported: VecString,

    /// TODO
    pub introspection_endpoint_auth_signing_alg_values_supported: VecString,

    /// JSON array containing a list of the Claim Names of the Claims that the OpenID Provider MAY be able to supply
    /// values for. Note that for privacy or other reasons, this might not be an exhaustive list.
    pub claims_supported: VecString,

    /// Boolean value specifying whether the OP supports use of the claims parameter, with true indicating support.
    pub claims_parameter_supported: bool,

    /// TODO
    pub claim_types_supported: VecString,

    /// JSON array containing a list of the OAuth 2.0 [RFC6749] scope values that this server supports. The server MUST
    /// support the openid scope value. Servers MAY choose not to advertise some supported scope values even when this parameter is used.
    pub scopes_supported: VecString,

    /// Boolean value specifying whether the OP supports use of the request parameter, with true indicating support.
    pub request_parameter_supported: bool,

    /// Boolean value specifying whether the OP supports use of the request_uri parameter, with true indicating support.
    pub request_uri_parameter_supported: bool,

    /// Boolean value specifying whether the OP requires any request_uri values used to be pre-registered
    /// using the request_uris registration parameter.
    pub require_request_uri_registration: bool,

    /// JSON array containing a list of Proof Key for Code Exchange (PKCE) [RFC7636] code challenge methods supported
    /// by this authorization server.
    pub code_challenge_methods_supported: VecString,

    /// TODO
    pub revocation_endpoint_auth_methods_supported: VecString,

    /// TODO
    pub revocation_endpoint_auth_signing_alg_values_supported: VecString,

    /// TODO
    pub backchannel_logout_supported: bool,

    /// TODO
    pub backchannel_token_delivery_modes_supported: VecString,

    /// Boolean value specifying whether the OP can pass a sid (session ID) Claim in the Logout Token to identify the RP
    /// session with the OP. If supported, the sid Claim is also included in ID Tokens issued by the OP.
    pub backchannel_logout_session_supported: bool,
}

#[derive(Debug, PartialEq, Serialize, Deserialize)]
pub(crate) struct DeleteOAuth2Token {
    pub client_id: String,
}

#[derive(Debug, PartialEq, Serialize, Deserialize)]
pub(crate) struct FlushInactiveOAuth2TokensRequest {
    pub not_after: String,
}

#[derive(Debug, PartialEq, Serialize, Deserialize)]
pub(crate) struct RevokeOAuth2TokenParameters {
    pub token: String,
}

#[derive(Debug, PartialEq, Serialize, Deserialize)]
pub(crate) struct OAuth2TokenParameters {
    pub grant_type: String,
    pub code: String,
    pub refresh_token: String,
    pub redirect_uri: String,
    pub client_id: String,
}

#[derive(Debug, PartialEq, Serialize, Deserialize)]
pub(crate) struct OAuth2TokenResponse {
    pub access_token: String,
    pub token_type: String,
    pub expires_in: i64,
    pub refresh_token: String,
    pub id_token: String,
    pub scope: String,
}

#[derive(Debug, PartialEq, Serialize, Deserialize)]
pub(crate) struct FlushInactiveAccessTokens {
    pub body: FlushInactiveOAuth2TokensRequest,
}

#[derive(Debug, PartialEq, Serialize, Deserialize)]
pub(crate) struct UserInfoResponsePayload {
    /// Subject - Identifier for the End-User at the IssuerURL.
    #[serde(rename = "sub")]
    pub subject: String,

	/// End-User's full name in displayable form including all name parts,
    /// possibly including titles and suffixes, ordered according to the
    /// End-User's locale and preferences.
    pub name: Option<String>,

    /// Given name(s) or first name(s) of the End-User. Note that in some cultures,
    /// people can have multiple given names; all can be present, with the names
    /// being separated by space characters.
    pub given_name: Option<String>,

    /// Surname(s) or last name(s) of the End-User. Note that in some cultures,
    /// people can have multiple family names or no family name; all can be present,
    /// with the names being separated by space characters.
    pub family_name: Option<String>,

	/// Middle name(s) of the End-User. Note that in some cultures, people can have
    /// multiple middle names; all can be present, with the names being separated
    /// by space characters. Also note that in some cultures, middle names are not used.
    pub middle_name: Option<String>,

	/// Casual name of the End-User that may or may not be the same as the given_name.
    /// For instance, a nickname value of Mike might be returned alongside a given_name
    /// value of Michael.
    pub nickname: Option<String>,

	/// Non-unique shorthand name by which the End-User wishes to be referred to at the RP,
    /// such as janedoe or j.doe. This value MAY be any valid JSON string including special
    /// characters such as @, /, or whitespace.
    pub preferred_username: Option<String>,

	/// URL of the End-User's profile page. The contents of this Web page SHOULD be about
    /// the End-User.
    pub profile: Option<String>,

	/// URL of the End-User's profile picture. This URL MUST refer to an image file (for
    /// example, a PNG, JPEG, or GIF image file), rather than to a Web page containing an
    /// image. Note that this URL SHOULD specifically reference a profile photo of the
    /// End-User suitable for displaying when describing the End-User, rather than an
    /// arbitrary photo taken by the End-User.
    pub picture: Option<String>,

    /// URL of the End-User's Web page or blog. This Web page SHOULD contain information
    /// published by the End-User or an organization that the End-User is affiliated with.
    pub website: Option<String>,

	/// End-User's preferred e-mail address. Its value MUST conform to the RFC 5322
    /// [RFC5322] addr-spec syntax. The RP MUST NOT rely upon this value being unique,
    /// as discussed in Section 5.7.
    pub email: Option<String>,

	/// True if the End-User's e-mail address has been verified; otherwise false. When
    /// this Claim Value is true, this means that the OP took affirmative steps to ensure
    /// that this e-mail address was controlled by the End-User at the time the verification
    /// was performed. The means by which an e-mail address is verified is context-specific,
    /// and dependent upon the trust framework or contractual agreements within which the
    /// parties are operating.
    pub email_verified: Option<bool>,

	/// End-User's gender. Values defined by this specification are female and male. Other
    /// values MAY be used when neither of the defined values are applicable.
    pub gender: Option<String>,

	/// End-User's birthday, represented as an ISO 8601:2004 [ISO8601‑2004] YYYY-MM-DD
    /// format. The year MAY be 0000, indicating that it is omitted. To represent only
    /// the year, YYYY format is allowed. Note that depending on the underlying platform's
    /// date related function, providing just year can result in varying month and day,
    /// so the implementers need to take this factor into account to correctly process
    /// the dates.
    pub birthdate: Option<String>,

	/// String from zoneinfo [zoneinfo] time zone database representing the End-User's
    /// time zone. For example, Europe/Paris or America/Los_Angeles.
    pub zoneinfo: Option<String>,

	/// End-User's locale, represented as a BCP47 [RFC5646] language tag. This is
    /// typically an ISO 639-1 Alpha-2 [ISO639‑1] language code in lowercase and an
    /// ISO 3166-1 Alpha-2 [ISO3166‑1] country code in uppercase, separated by a dash.
    /// For example, en-US or fr-CA. As a compatibility note, some implementations
    /// have used an underscore as the separator rather than a dash, for example,
    /// en_US; Relying Parties MAY choose to accept this locale syntax as well.
    pub locale: Option<String>,

	/// End-User's preferred telephone number. E.164 [E.164] is RECOMMENDED as the format
    /// of this Claim, for example, +1 (425) 555-1212 or +56 (2) 687 2400. If the phone
    /// number contains an extension, it is RECOMMENDED that the extension be represented
    /// using the RFC 3966 [RFC3966] extension syntax, for example, +1 (604) 555-1234;ext=5678.
    pub phone_number: Option<String>,

	/// True if the End-User's phone number has been verified; otherwise false. When this
    /// Claim Value is true, this means that the OP took affirmative steps to ensure that
    /// this phone number was controlled by the End-User at the time the verification was
    /// performed. The means by which a phone number is verified is context-specific,
    /// and dependent upon the trust framework or contractual agreements within which
    /// the parties are operating. When true, the phone_number Claim MUST be in E.164
    /// format and any extensions MUST be represented in RFC 3966 format.
    pub phone_number_verified: Option<bool>,

    /// Time the End-User's information was last updated.
    /// Its value is a JSON number representing the number of
    /// seconds from 1970-01-01T0:0:0Z as measured in UTC until the date/time.
    pub updated_at: Option<i64>,
}
