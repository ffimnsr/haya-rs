use bson::oid::ObjectId;
use chrono::{DateTime, Utc};
use serde::{Serialize, Deserialize};

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
struct OauthConsentRequestHandled {
    #[serde(rename = "_id", skip_serializing_if = "Option::is_none")]
    pub id: Option<ObjectId>,

    pub challenge: String,
    pub granted_scope: String,
    pub remember: bool,
    pub remeber_for: i32,
    pub error: String,
    pub requested_at: DateTime<Utc>,
    pub authenticated_at: DateTime<Utc>,
    pub session_access_token: String,
    pub session_id: String,
    pub was_used: bool,
    pub granted_at_audience: String,
    pub handled_at: DateTime<Utc>,
}
