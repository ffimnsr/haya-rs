use chrono::{DateTime, Utc};
use mongodb::bson::oid::ObjectId;
use mongodb::bson::doc;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::{error::{ServiceError, GenericResult}, DbContext};

#[allow(dead_code)]
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub(crate) struct Client {
    #[serde(rename = "_id", skip_serializing_if = "Option::is_none")]
    pub id: Option<ObjectId>,

    #[serde(with = "bson::serde_helpers::uuid_as_binary")]
    pub client_id: Uuid,
    pub client_secret: String,
    pub owner: String,
    pub audience: String,
    pub grants: Vec<String>,
    pub response_types: Vec<String>,
    pub scopes: Vec<String>,
    pub redirect_uris: Vec<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl Client {
    const DEFAULT_COLLECTION: &'static str = "client";

    pub async fn get_client(db: DbContext, client_id: Uuid) -> Self {
        let collection = db.collection::<Self>(Self::DEFAULT_COLLECTION);

        let client = collection
            .find_one(doc! { "client_id": client_id }, None)
            .await
            .map_err(ServiceError::Mongo).unwrap().unwrap();

        client
    }

    pub async fn create(&self, db: DbContext) -> GenericResult<()> {
        let collection = db.collection::<Self>(Self::DEFAULT_COLLECTION);

        collection.insert_one(self, None)
            .await
            .map_err(|e| e.to_string())?;

        Ok(())
    }

    pub async fn get_by_id(db: DbContext, client_id: Uuid) -> Self {
        let collection = db.collection::<Self>(Self::DEFAULT_COLLECTION);

        let client = collection
            .find_one(doc! { "client_id": client_id }, None)
            .await
            .map_err(|e| e.to_string());

        client
            .unwrap()
            .unwrap()
    }
}
