#![allow(dead_code)]

use crate::{error::GenericResult, DbContext};
use chrono::{DateTime, Utc};
use mongodb::bson::doc;
use serde::{Serialize, Deserialize};
use uuid::Uuid;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub(crate) struct OauthRefreshToken {
    pub jwt_id: Uuid,
    pub client_id: Uuid,
    pub request_id: Uuid,
    pub subject: Uuid,
    pub scope: String,
    pub audience: String,
    pub requested_at: DateTime<Utc>,
}

impl OauthRefreshToken {
    const DEFAULT_COLLECTION: &'static str = "oauth_refresh_code";

    pub fn new(
        jwt_id: Uuid,
        client_id: Uuid,
        request_id: Uuid,
        subject: Uuid,
        scope: &str,
        audience: &str,
        requested_at: DateTime<Utc>,
    ) -> Self {
        Self {
            jwt_id,
            client_id,
            request_id,
            subject,
            scope: scope.to_string(),
            audience: audience.to_string(),
            requested_at,
        }
    }

    pub async fn save_refresh_token(&self, db: DbContext) -> GenericResult<()> {
        let collection = db.collection::<Self>(Self::DEFAULT_COLLECTION);

        collection.insert_one(self, None)
            .await
            .map_err(|e| e.to_string())?;

        Ok(())
    }

    pub async fn get_refresh_token(db: DbContext, jwt_id: &Uuid) -> GenericResult<Self> {
        let collection = db.collection::<Self>(Self::DEFAULT_COLLECTION);

        let result = collection
            .find_one(doc! { "jwt_id": jwt_id }, None)
            .await
            .map_err(|e| e.to_string())?
            .unwrap();

        Ok(result)
    }

    pub async fn revoke_refresh_token(db: DbContext, jwt_id: &Uuid) -> GenericResult<()> {
        let collection = db.collection::<Self>(Self::DEFAULT_COLLECTION);

        let result = collection
            .delete_one(doc! { "jwt_id": jwt_id }, None)
            .await
            .map_err(|e| e.to_string())?;

        Ok(())
    }
}
