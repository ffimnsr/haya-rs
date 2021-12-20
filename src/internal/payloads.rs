use serde::{Deserialize, Serialize};

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
