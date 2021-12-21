use crate::{db::Pool, errors::GenericResult};
use chrono::{DateTime, Utc};
use postgres_types::ToSql;
use uuid::Uuid;
use super::Parameter;

#[derive(Debug, ToSql)]
pub(crate) struct OauthAuthorizationCode {
    jwt_id: Uuid,
    client_id: Uuid,
    request_id: Uuid,
    requested_scope: String,
    granted_scope: String,
    requested_audience: String,
    granted_audience: String,
    code_challenge: String,
    code_challenge_method: String,
    redirect_uri: String,
    requested_at: DateTime<Utc>,
}

impl<'a> OauthAuthorizationCode {
    pub fn parameters(&'a self) -> Vec<Parameter<'a>> {
        let params: Vec<Parameter<'a>> = vec![
            &self.jwt_id,
            &self.client_id,
            &self.request_id,
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
                (jwt_id, client_id, request_id, requested_scope, \
                    granted_scope, requested_audience, granted_audience, \
                    code_challenge, code_challenge_method, redirect_uri, \
                    requested_at) \
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11) \
            RETURNING jwt_id",
        );

        db.query_one(&query, &self.parameters())
            .await
            .map_err(|e| e.to_string())?;

        Ok(())
    }
}
