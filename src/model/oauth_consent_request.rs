use bson::oid::ObjectId;
use chrono::{DateTime, Utc};
use serde::{Serialize, Deserialize};

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
struct OauthConsentRequest {
    #[serde(rename = "_id", skip_serializing_if = "Option::is_none")]
    pub id: Option<ObjectId>,

    pub challenge: String,
    pub verifier: String,
    pub client_id: String,
    pub subject: String,
    pub request_url: String,
    pub skip: bool,
    pub requested_scope: String,
    pub csrf: String,
    pub authenticated_at: DateTime<Utc>,
    pub requested_at_audience: String,
    pub requested_at: DateTime<Utc>,
    pub oidc_context: DateTime<Utc>,
    pub login_session_id: String,
    pub login_challenge: String,
    pub acr: String,
    pub context: String,
    pub amr: String,
}
