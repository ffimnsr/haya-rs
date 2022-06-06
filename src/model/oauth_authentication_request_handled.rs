use bson::oid::ObjectId;
use chrono::{DateTime, Utc};
use serde::{Serialize, Deserialize};

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
struct OauthAuthenticationRequestHandled {
    #[serde(rename = "_id", skip_serializing_if = "Option::is_none")]
    pub id: Option<ObjectId>,

    pub challenge: String,
    pub subject: String,
    pub remember: bool,
    pub remeber_for: i32,
    pub error: String,
    pub acr: String,
    pub requested_at: DateTime<Utc>,
    pub authenticated_at: DateTime<Utc>,
    pub was_used: bool,
    pub forced_subject_identifier: String,
    pub context: String,
    pub amr: String,
}
