use bson::oid::ObjectId;
use chrono::{DateTime, Utc};
use serde::{Serialize, Deserialize};

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
struct OauthAuthenticationRequest {
    #[serde(rename = "_id", skip_serializing_if = "Option::is_none")]
    pub id: Option<ObjectId>,

    pub challenge: String,
    pub requested_scope: String,
    pub verifier: String,
    pub csrf: String,
    pub subject: String,
    pub request_url: String,
    pub skip: bool,
    pub client_id: String,
    pub requested_at_audience: String,
    pub requested_at: DateTime<Utc>,
    pub authenticated_at: DateTime<Utc>,
    pub oidc_context: DateTime<Utc>,
    pub login_session_id: String,
}
