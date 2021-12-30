use crate::{db::Pool, errors::GenericResult};
use chrono::{DateTime, Utc};
use postgres_types::ToSql;
use uuid::Uuid;
use super::Parameter;

#[derive(Debug, ToSql)]
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

impl<'a> OauthAuthorizationCode {
    pub fn parameters(&'a self) -> Vec<Parameter<'a>> {
        let params: Vec<Parameter<'a>> = vec![
            &self.jwt_id,
            &self.client_id,
            &self.request_id,
            &self.subject,
            &self.requested_scope,
            &self.granted_scope,
            &self.requested_audience,
            &self.granted_audience,
            &self.code_challenge,
            &self.code_challenge_method,
            &self.redirect_uri,
            &self.requested_at,
        ];

        params
    }

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

    pub async fn save_authorization_code(&self, pool: &Pool) -> GenericResult<()> {
        let db = pool.get().await.map_err(|e| e.to_string())?;

        let query = String::from(
            "INSERT INTO oauth_authorization_code \
                (jwt_id, client_id, request_id, subject, requested_scope, \
                    granted_scope, requested_audience, granted_audience, \
                    code_challenge, code_challenge_method, redirect_uri, \
                    requested_at) \
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12) \
            RETURNING jwt_id",
        );

        db.query_one(&query, &self.parameters())
            .await
            .map_err(|e| e.to_string())?;

        Ok(())
    }

    pub async fn get_authorization_code(pool: &Pool, jwt_id: &Uuid) -> GenericResult<Self> {
        let db = pool.get().await.map_err(|e| e.to_string())?;

        let query = String::from(
            "SELECT
                jwt_id, client_id, request_id, subject, requested_scope, \
                granted_scope, requested_audience, granted_audience, \
                code_challenge, code_challenge_method, redirect_uri, \
                requested_at \
            FROM oauth_authorization_code \
            WHERE active = true AND jwt_id = $1"
        );

        let row = db.query_one(&query, &[&jwt_id])
            .await
            .map_err(|e| e.to_string())?;

        let tmp = Self {
            jwt_id: row.get("jwt_id"),
            client_id: row.get("client_id"),
            request_id: row.get("request_id"),
            subject: row.get("subject"),
            requested_scope: row.get("requested_scope"),
            granted_scope: row.get("granted_scope"),
            requested_audience: row.get("requested_audience"),
            granted_audience: row.get("granted_audience"),
            code_challenge: row.get("code_challenge"),
            code_challenge_method: row.get("code_challenge_method"),
            redirect_uri: row.get("redirect_uri"),
            requested_at: row.get("requested_at"),
        };

        Ok(tmp)
    }

    pub async fn revoke_authorization_code(pool: &Pool, jwt_id: &Uuid) -> GenericResult<()> {
        let db = pool.get().await.map_err(|e| e.to_string())?;
        let query = String::from("UPDATE public.oauth_authorization_code SET active = false WHERE jwt_id = $1");
        db.execute(&query, &[&jwt_id])
            .await
            .map_err(|e| e.to_string())?;
        Ok(())
    }
}
