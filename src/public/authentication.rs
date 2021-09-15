use hyper::{Body, Method, Request, Response, StatusCode};
use routerify::prelude::*;
use serde::{Deserialize, Serialize};

use crate::config::Config;
use crate::errors::{ApiError, ApiResult};
use crate::{HeaderValues, MimeValues};

#[derive(Debug, Serialize, Deserialize)]
pub(crate) enum AuthenticationError {
    /// The Authorization Server requires End-User interaction of some form to
    /// proceed. This error MAY be returned when the prompt parameter value in
    /// the Authentication Request is none, but the Authentication Request
    /// cannot be completed without displaying a user interface for End-User
    /// interaction.
    #[serde(rename = "interaction_required")]
    InteractionRequired,

    /// The Authorization Server requires End-User authentication. This error
    /// MAY be returned when the prompt parameter value in the Authentication
    /// Request is none, but the Authentication Request cannot be completed
    /// without displaying a user interface for End-User authentication.
    #[serde(rename = "login_required")]
    LoginRequired,

    /// The End-User is REQUIRED to select a session at the Authorization
    /// Server. The End-User MAY be authenticated at the Authorization Server
    /// with different associated accounts, but the End-User did not select a
    /// session. This error MAY be returned when the prompt parameter value in
    /// the Authentication Request is none, but the Authentication Request
    /// cannot be completed without displaying a user interface to prompt for a
    /// session to use.
    #[serde(rename = "account_selection_required")]
    AccountSelectionRequired,

    /// The Authorization Server requires End-User consent. This error MAY be
    /// returned when the prompt parameter value in the Authentication Request
    /// is none, but the Authentication Request cannot be completed without
    /// displaying a user interface for End-User consent.
    #[serde(rename = "consent_required")]
    ConsentRequired,

    /// The request_uri in the Authorization Request returns an error or
    /// contains invalid data.
    #[serde(rename = "invalid_request_uri")]
    InvalidRequestUri,

    /// The request parameter contains an invalid Request Object.
    #[serde(rename = "invalid_request_object")]
    InvalidRequestObject,

    /// The OP does not support use of the request parameter defined in Section
    /// 6.
    #[serde(rename = "request_not_supported")]
    RequestNotSupported,

    /// The OP does not support use of the request_uri parameter defined in
    /// Section 6.
    #[serde(rename = "request_uri_not_supported")]
    RequestUriNotSupported,

    /// The OP does not support use of the registration parameter defined in
    /// Section 7.2.1
    #[serde(rename = "registration_not_supported")]
    RegistrationNotSupported,
}

#[derive(Debug, Serialize, Deserialize)]
pub(crate) struct AuthenticationErrorResponse {
    /// Error code.
    pub error: AuthenticationError,

    /// Human-readable ASCII encoded text description of the error.
    pub error_description: Option<String>,

    /// URI of a web page that includes additional information about the error.
    pub error_uri: Option<String>,

    /// OAuth 2.0 state value. REQUIRED if the Authorization Request included
    /// the state parameter. Set to the value received from the Client.
    pub state: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub(crate) enum DisplayOptions {
    /// The Authorization Server SHOULD display the authentication and consent
    /// UI consistent with a full User Agent page view. If the display parameter
    /// is not specified, this is the default display mode.
    #[serde(rename = "page")]
    Page,

    /// The Authorization Server SHOULD display the authentication and consent
    /// UI consistent with a popup User Agent window. The popup User Agent
    /// window should be of an appropriate size for a login-focused dialog and
    /// should not obscure the entire window that it is popping up over.
    #[serde(rename = "popup")]
    Popup,

    /// The Authorization Server SHOULD display the authentication and consent
    /// UI consistent with a device that leverages a touch interface.
    #[serde(rename = "touch")]
    Touch,

    /// The Authorization Server SHOULD display the authentication and consent
    /// UI consistent with a "feature phone" type display.
    #[serde(rename = "wap")]
    Wap,
}

#[derive(Debug, Serialize, Deserialize)]
pub(crate) enum PromptOptions {
    /// The Authorization Server MUST NOT display any authentication or consent
    /// user interface pages. An error is returned if an End-User is not already
    /// authenticated or the Client does not have pre-configured consent for the
    /// requested Claims or does not fulfill other conditions for processing the
    /// request. The error code will typically be login_required,
    /// interaction_required, or another code defined in Section 3.1.2.6. This
    /// can be used as a method to check for existing authentication and/or
    /// consent.
    #[serde(rename = "none")]
    None,

    /// The Authorization Server SHOULD prompt the End-User for
    /// reauthentication. If it cannot reauthenticate the End-User, it MUST
    /// return an error, typically login_required.
    #[serde(rename = "login")]
    Login,

    /// The Authorization Server SHOULD prompt the End-User for consent before
    /// returning information to the Client. If it cannot obtain consent, it
    /// MUST return an error, typically consent_required.
    #[serde(rename = "consent")]
    Consent,

    /// The Authorization Server SHOULD prompt the End-User to select a user
    /// account. This enables an End-User who has multiple accounts at the
    /// Authorization Server to select amongst the multiple accounts that they
    /// might have current sessions for. If it cannot obtain an account
    /// selection choice made by the End-User, it MUST return an error,
    /// typically account_selection_required.
    #[serde(rename = "select_account")]
    SelectAccount,
}

#[derive(Debug, Serialize, Deserialize)]
pub(crate) struct AuthenticationRequest {
    /// OpenID Connect requests MUST contain the openid scope value. If the
    /// openid scope value is not present, the behavior is entirely unspecified.
    /// Other scope values MAY be present. Scope values used that are not
    /// understood by an implementation SHOULD be ignored. See Sections 5.4 and
    /// 11 for additional scope values defined by this specification.
    pub scope: String,

    /// OAuth 2.0 Response Type value that determines the authorization
    /// processing flow to be used, including what parameters are returned from
    /// the endpoints used. When using the Authorization Code Flow, this value
    /// is code.
    pub response_type: String,

    /// OAuth 2.0 Client Identifier valid at the Authorization Server.
    pub client_id: String,

    /// Redirection URI to which the response will be sent. This URI MUST
    /// exactly match one of the Redirection URI values for the Client
    /// pre-registered at the OpenID Provider, with the matching performed as
    /// described in Section 6.2.1 of (Simple String Comparison). When using
    /// this flow, the Redirection URI SHOULD use the https scheme; however, it
    /// MAY use the http scheme, provided that the Client Type is confidential,
    /// as defined in Section 2.1 of OAuth 2.0, and provided the OP allows the
    /// use of http Redirection URIs in this case. The Redirection URI MAY use
    /// an alternate scheme, such as one that is intended to identify a callback
    /// into a native application.
    pub redirect_uri: String,

    /// Opaque value used to maintain state between the request and the
    /// callback. Typically, Cross-Site Request Forgery (CSRF, XSRF) mitigation
    /// is done by cryptographically binding the value of this parameter with a
    /// browser cookie.
    pub state: Option<String>,

    /// Informs the Authorization Server of the mechanism to be used for
    /// returning parameters from the Authorization Endpoint. This use of this
    /// parameter is NOT RECOMMENDED when the Response Mode that would be
    /// requested is the default mode specified for the Response Type.
    pub response_mode: Option<String>,

    /// String value used to associate a Client session with an ID Token, and to
    /// mitigate replay attacks. The value is passed through unmodified from the
    /// Authentication Request to the ID Token. Sufficient entropy MUST be
    /// present in the nonce values used to prevent attackers from guessing
    /// values. For implementation notes, see Section 15.5.2.
    pub nonce: Option<String>,

    /// ASCII string value that specifies how the Authorization Server displays
    /// the authentication and consent user interface pages to the End-User.
    pub display: Option<DisplayOptions>,

    /// Space delimited, case sensitive list of ASCII string values that
    /// specifies whether the Authorization Server prompts the End-User for
    /// reauthentication and consent The prompt parameter can be used by the
    /// Client to make sure that the End-User is still present for the current
    /// session or to bring attention to the request. If this parameter contains
    /// none with any other value, an error is returned
    pub prompt: Option<PromptOptions>,

    /// Maximum Authentication Age. Specifies the allowable elapsed time in
    /// seconds since the last time the End-User was actively authenticated by
    /// the OP. If the elapsed time is greater than this value, the OP MUST
    /// attempt to actively re-authenticate the End-User. (The max_age request
    /// parameter corresponds to the OpenID 2.0 PAPE [OpenID.PAPE] max_auth_age
    /// request parameter.) When max_age is used, the ID Token returned MUST
    /// include an auth_time Claim Value.
    pub max_age: Option<i64>,

    /// End-User's preferred languages and scripts for the user interface,
    /// represented as a space-separated list of BCP47 [RFC5646] language tag
    /// values, ordered by preference. For instance, the value "fr-CA fr en"
    /// represents a preference for French as spoken in Canada, then French
    /// (without a region designation), followed by English (without a region
    /// designation). An error SHOULD NOT result if some or all of the requested
    /// locales are not supported by the OpenID Provider.
    pub ui_locales: Option<String>,

    /// ID Token previously issued by the Authorization Server being passed as a
    /// hint about the End-User's current or past authenticated session with the
    /// Client. If the End-User identified by the ID Token is logged in or is
    /// logged in by the request, then the Authorization Server returns a
    /// positive response; otherwise, it SHOULD return an error, such as
    /// login_required. When possible, an id_token_hint SHOULD be present when
    /// prompt=none is used and an invalid_request error MAY be returned if it
    /// is not; however, the server SHOULD respond successfully when possible,
    /// even if it is not present. The Authorization Server need not be listed
    /// as an audience of the ID Token when it is used as an id_token_hint
    /// value.
    /// If the ID Token received by the RP from the OP is encrypted, to use it
    /// as an id_token_hint, the Client MUST decrypt the signed ID Token
    /// contained within the encrypted ID Token. The Client MAY re-encrypt the
    /// signed ID token to the Authentication Server using a key that enables
    /// the server to decrypt the ID Token, and use the re-encrypted ID token as
    /// the id_token_hint value.
    pub id_token_hint: Option<String>,

    /// Hint to the Authorization Server about the login identifier the End-User
    /// might use to log in (if necessary). This hint can be used by an RP if it
    /// first asks the End-User for their e-mail address (or other identifier)
    /// and then wants to pass that value as a hint to the discovered
    /// authorization service. It is RECOMMENDED that the hint value match the
    /// value used for discovery. This value MAY also be a phone number in the
    /// format specified for the phone_number Claim. The use of this parameter
    /// is left to the OP's discretion.
    pub login_hint: Option<String>,

    /// Requested Authentication Context Class Reference values. Space-separated
    /// string that specifies the acr values that the Authorization Server is
    /// being requested to use for processing this Authentication Request, with
    /// the values appearing in order of preference. The Authentication Context
    /// Class satisfied by the authentication performed is returned as the acr
    /// Claim Value, as specified in Section 2. The acr Claim is requested as a
    /// Voluntary Claim by this parameter.
    pub acr_values: Option<String>,
}

/// The OAuth 2.0 Authorize Endpoint
///
/// This endpoint is not documented here because you should never use your own
/// implementation to perform OAuth2 flows. OAuth2 is a very popular protocol
/// and a library for your programming language will exists.
///
/// To learn more about this flow please refer to the specification:
/// https://tools.ietf.org/html/rfc6749
pub(crate) async fn handler_get_authorization(
    req: Request<Body>,
) -> ApiResult<Response<Body>> {
    match *req.method() {
        Method::POST => Ok(Response::builder()
            .status(StatusCode::NO_CONTENT)
            .header(HeaderValues::CONTENT_LENGTH, "0")
            .body(Body::empty())
            .map_err(ApiError::Http)?),

        _ => {
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
    }
}

pub(crate) async fn handler_post_authorization(
    _req: Request<Body>,
) -> ApiResult<Response<Body>> {
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
