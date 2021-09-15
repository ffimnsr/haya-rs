use serde::{Deserialize, Serialize};

/// Introspection contains an access token's session data as specified by IETF
/// RFC 7662, see: https://tools.ietf.org/html/rfc7662
#[derive(Debug, PartialEq, Serialize, Deserialize, Clone)]
pub(crate) struct Introspection {
    /// Active is a boolean indicator of whether or not the presented token is
    /// currently active.  The specifics of a token's "active" state will vary
    /// depending on the implementation of the authorization server and the
    /// information it keeps about its tokens, but a "true" value return for the
    /// "active" property will generally indicate that a given token has been
    /// issued by this authorization server, has not been revoked by the
    /// resource owner, and is within its given time window of validity (e.g.,
    /// after its issuance time and before its expiration time).
    pub active: bool,

    /// Scope is a JSON string containing a space-separated list of scopes
    /// associated with this token.
    pub scope: String,

    /// ID is aclient identifier for the OAuth 2.0 client that
    /// requested this token.
    pub client_id: String,

    /// Subject of the token, as defined in JWT [RFC7519]. Usually a
    /// machine-readable identifier of the resource owner who authorized this
    /// token.
    #[serde(rename = "sub")]
    pub subject: String,

    /// Obfuscated subject is set when the subject identifier algorithm was set
    /// to "pairwise" during authorization. It is the `sub` value of the ID
    /// Token that was issued.
    pub obfuscated_subject: String,

    /// Expires at is an integer timestamp, measured in the number of seconds
    /// since January 1 1970 UTC, indicating when this token will expire.
    #[serde(rename = "exp")]
    pub expires_at: i64,

    /// Issued at is an integer timestamp, measured in the number of seconds
    /// since January 1 1970 UTC, indicating when this token was
    /// originally issued.
    #[serde(rename = "iat")]
    pub issued_at: i64,

    /// Not before is an integer timestamp, measured in the number of seconds
    /// since January 1 1970 UTC, indicating when this token is not to be
    /// used before.
    #[serde(rename = "nbf")]
    pub not_before: i64,

    /// Username is a human-readable identifier for the resource owner who
    /// authorized this token.
    pub username: String,

    /// Audience contains a list of the token's intended audiences.
    #[serde(rename = "aud")]
    pub audience: Vec<String>,

    /// Issuer URL is a string representing the issuer of this token
    #[serde(rename = "iss")]
    pub issuer: String,

    /// TokenType is the introspected token's type, typically `Bearer`.
    pub token_type: String,

    /// TokenUse is the introspected token's use, for example `access_token` or
    /// `refresh_token`.
    pub token_use: String,

    /// Extra is arbitrary data set by the session.
    #[serde(rename = "ext")]
    pub extra: String,
}
