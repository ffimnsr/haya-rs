use std::sync::Arc;

use crate::error::GenericResult;
use chrono::{DateTime, Utc};
use mongodb::Database;
use mongodb::bson::doc;
use serde::{Serialize, Deserialize};
use uuid::Uuid;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub(crate) struct OauthAuthorizationCode {
    pub jwt_id: Uuid,
    pub client_id: Uuid,
    pub request_id: Uuid,
    pub subject: Uuid,
    pub requested_scope: String,
    pub granted_scope: String,
    pub requested_audience: String,
    pub granted_audience: String,
    pub code_challenge: String,
    pub code_challenge_method: String,
    pub redirect_uri: String,
    pub requested_at: DateTime<Utc>,
}

impl OauthAuthorizationCode {
    const DEFAULT_COLLECTION: &'static str = "oauth_authorization_code";

    pub fn new(
        jwt_id: Uuid,
        client_id: Uuid,
        request_id: Uuid,
        subject: Uuid,
        requested_scope: &str,
        granted_scope: &str,
        requested_audience: &str,
        granted_audience: &str,
        code_challenge: &str,
        code_challenge_method: &str,
        redirect_uri: &str,
        requested_at: DateTime<Utc>,
    ) -> Self {
        Self {
            jwt_id,
            client_id,
            request_id,
            subject,
            requested_scope: requested_scope.to_string(),
            granted_scope: granted_scope.to_string(),
            requested_audience: requested_audience.to_string(),
            granted_audience: granted_audience.to_string(),
            code_challenge: code_challenge.to_string(),
            code_challenge_method: code_challenge_method.to_string(),
            redirect_uri: redirect_uri.to_string(),
            requested_at,
        }
    }

    pub async fn save_authorization_code(&self, db: Arc<Database>) -> GenericResult<()> {
        let collection = db.collection::<Self>(Self::DEFAULT_COLLECTION);

        let result = collection.insert_one(self, None)
            .await
            .map_err(|e| e.to_string())?;

        Ok(())
    }

    pub async fn get_authorization_code(
        db: Arc<Database>,
        jwt_id: &Uuid,
    ) -> GenericResult<Self> {
        let collection = db.collection::<Self>(Self::DEFAULT_COLLECTION);

        let result = collection
            .find_one(doc! { "jwt_id": jwt_id }, None)
            .await
            .map_err(|e| e.to_string())?
            .unwrap();

        Ok(result)
    }

    pub async fn revoke_authorization_code(
        db: Arc<Database>,
        jwt_id: &Uuid,
    ) -> GenericResult<()> {
        let collection = db.collection::<Self>(Self::DEFAULT_COLLECTION);

        let result = collection
            .delete_one(doc! { "jwt_id": jwt_id }, None)
            .await
            .map_err(|e| e.to_string())?;

        Ok(())
    }
}
