use bson::oid::ObjectId;
use chrono::{DateTime, Utc};
use serde::{Serialize, Deserialize};
use uuid::Uuid;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
struct OauthClient {
    #[serde(rename = "_id", skip_serializing_if = "Option::is_none")]
    pub id: Option<ObjectId>,

    #[serde(with = "bson::serde_helpers::uuid_as_binary")]
    pub client_id: Uuid,

    pub client_name: String,
    pub client_secret: String,
    pub redirect_uris: Vec<String>,
    pub grant_types: Vec<String>,
    pub response_types: Vec<String>,
    pub scope: String,
    pub owner: String,
    pub policy_uri: String,
    pub tos_uri: String,
    pub client_uri: String,
    pub logo_uri: String,
    pub contacts: Vec<String>,
    pub client_secret_expires_at: DateTime<Utc>,
    pub sector_identifier_uri: String,
    pub jwks: Option<String>,
    pub jwks_uri: Option<String>,
    pub request_uris: Vec<String>,
    pub token_endpoint_auth_method: String,
    pub request_object_signing_alg: String,
    pub userinfo_signed_response_alg: String,
    pub subject_type: String,
    pub allowed_cors_origins: Option<Vec<String>>,
    pub audience: Option<Vec<String>>,
    pub frontchannel_logout_uri: String,
    pub frontchannel_logout_session_required: bool,
    pub post_logout_redirect_uris: Vec<String>,
    pub backchannel_logout_uri: String,
    pub backchannel_logout_session_required: bool,
    pub metadata: Option<String>,
    pub token_endpoint_auth_signing_alg: String,
    pub registration_access_token_signature: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl OauthClient {
    fn before_save(&mut self) {
        if self.jwks.is_none() {
            // TODO: set and create new jwks set
            unimplemented!();
        }

        if self.metadata.is_none() {
            self.metadata = Some("{}".into());
        }

        if self.audience.is_none() {
            self.audience = Some(vec!());
        }

        if self.allowed_cors_origins.is_none() {
            self.allowed_cors_origins = Some(vec!());
        }
    }
}
