use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub(crate) struct StandardTokenClaims {
    /// Subject identifier.
    #[serde(rename = "sub")]
    pub subject: Uuid,

    /// Unique identifier; can be used to prevent the JWT from being replayed.
    #[serde(rename = "jti")]
    pub jwt_id: Uuid,

    /// Time at which the JWT was issued.
    #[serde(rename = "iat")]
    pub issued_at_time: i64,

    /// Expiration time on or after which the ID Token MUST NOT be accepted for
    /// processing.
    #[serde(rename = "exp")]
    pub expiration_time: i64,

    /// Not before is an integer timestamp, measured in the number of seconds
    /// since January 1 1970 UTC, indicating when this token is not to be
    /// used before.
    #[serde(rename = "nbf")]
    pub not_before: i64,

    /// Audience(s) that this ID token is inteded for.
    #[serde(rename = "aud")]
    pub audience: Uuid,

    /// Scope is a JSON string containing a space-separated list of scopes
    /// associated with this token.
    pub scope: String,

    /// Scope is a JSON string containing a space-separated list of scopes
    /// associated with this token.
    pub token_type: String,
}
