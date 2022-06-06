use bson::oid::ObjectId;
use chrono::{DateTime, Utc};
use serde::{Serialize, Deserialize};

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
struct OauthRefresh {
    #[serde(rename = "_id", skip_serializing_if = "Option::is_none")]
    pub id: Option<ObjectId>,

    pub signature: String,
    pub request_id: String,
    pub requested_at: DateTime<Utc>,
    pub client_id: String,
    pub scope: String,
    pub granted_scope: String,
    pub form_data: String,
    pub session_data: String,
    pub subject: String,
    pub active: bool,
    pub requested_audience: String,
    pub granted_audience: String,
    pub challenge_id: String,
}
