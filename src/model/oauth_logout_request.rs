use bson::oid::ObjectId;
use chrono::{DateTime, Utc};
use serde::{Serialize, Deserialize};

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
struct OauthLogoutRequest {
    #[serde(rename = "_id", skip_serializing_if = "Option::is_none")]
    pub id: Option<ObjectId>,

    pub challenge: String,
    pub verifier: String,
    pub subject: String,
    pub sid: String,
    pub client_id: String,
    pub request_url: String,
    pub redir_url: String,
    pub was_used: bool,
    pub accepted: bool,
    pub rejected: bool,
    pub rp_initiated: bool,
}
