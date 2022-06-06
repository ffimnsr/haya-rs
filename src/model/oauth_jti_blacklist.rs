use bson::oid::ObjectId;
use chrono::{DateTime, Utc};
use serde::{Serialize, Deserialize};

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
struct OauthJtiBlacklist {
    #[serde(rename = "_id", skip_serializing_if = "Option::is_none")]
    pub id: Option<ObjectId>,

    pub signature: String,
    pub expires_at: DateTime<Utc>,
}
