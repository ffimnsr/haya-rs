use bson::oid::ObjectId;
use chrono::{DateTime, Utc};
use serde::{Serialize, Deserialize};

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
struct OauthJwk {
    #[serde(rename = "_id", skip_serializing_if = "Option::is_none")]
    pub id: Option<ObjectId>,

    /// The "kid" (key ID) parameter is used to match a specific key. The "kid"
    /// value is a case-sensitive string. Use of this member is OPTIONAL.
    pub sid: String,
    pub kid: String,
    pub version: i32,
    pub keydata: String,
    pub created_at: DateTime<Utc>,
}
