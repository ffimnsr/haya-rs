#![allow(dead_code)]

use super::Parameter;
use crate::{db::Pool, errors::GenericResult};
use chrono::{DateTime, Utc};
use postgres_types::ToSql;
use uuid::Uuid;

#[derive(Debug, ToSql)]
pub(crate) struct OauthAccessToken {
    pub jwt_id: Uuid,
    pub client_id: Uuid,
    pub request_id: Uuid,
    pub subject: Uuid,
    pub scope: String,
    pub audience: String,
    pub requested_at: DateTime<Utc>,
}

impl<'a> OauthAccessToken {
    pub fn parameters(&'a self) -> Vec<Parameter<'a>> {
        let params: Vec<Parameter<'a>> = vec![
            &self.jwt_id,
            &self.client_id,
            &self.request_id,
            &self.subject,
            &self.scope,
            &self.audience,
            &self.requested_at,
        ];

        params
    }

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

    pub async fn save_access_token(&self, pool: &Pool) -> GenericResult<()> {
        let db = pool.get().await.map_err(|e| e.to_string())?;

        let query = String::from(
            "INSERT INTO oauth_access_token \
                (jwt_id, client_id, request_id, subject, scope, \
                    audience, requested_at) \
            VALUES ($1, $2, $3, $4, $5, $6, $7) \
            RETURNING jwt_id",
        );

        db.query_one(&query, &self.parameters())
            .await
            .map_err(|e| e.to_string())?;

        Ok(())
    }

    pub async fn get_access_token(pool: &Pool, jwt_id: &Uuid) -> GenericResult<Self> {
        let db = pool.get().await.map_err(|e| e.to_string())?;

        let query = String::from(
            "SELECT
                jwt_id, client_id, request_id, subject, scope, \
                audience, requested_at \
            FROM oauth_access_token \
            WHERE active = true AND jwt_id = $1",
        );

        let row = db
            .query_one(&query, &[&jwt_id])
            .await
            .map_err(|e| e.to_string())?;

        let tmp = Self {
            jwt_id: row.get("jwt_id"),
            client_id: row.get("client_id"),
            request_id: row.get("request_id"),
            subject: row.get("subject"),
            scope: row.get("scope"),
            audience: row.get("audience"),
            requested_at: row.get("requested_at"),
        };

        Ok(tmp)
    }

    pub async fn revoke_access_token(pool: &Pool, jwt_id: &Uuid) -> GenericResult<()> {
        let db = pool.get().await.map_err(|e| e.to_string())?;
        let query = String::from(
            "UPDATE public.oauth_access_token SET active = false WHERE jwt_id = $1",
        );
        db.execute(&query, &[&jwt_id])
            .await
            .map_err(|e| e.to_string())?;
        Ok(())
    }
}
