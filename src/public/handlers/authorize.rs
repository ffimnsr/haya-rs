use crate::errors::api_error::OauthError;
use crate::errors::{ApiError, ApiResult, GenericResult};
use crate::models::{AuthorizationCodeClaims, Client};
use crate::{defaults::AUTHORIZATION_CODE_LIFETIME, HeaderValues};
use chrono::{DateTime, Duration, Utc};
use deadpool_postgres::Pool;
use hyper::{Body, Request, Response, StatusCode};
use jsonwebtoken::{encode, EncodingKey, Header};
use routerify::prelude::*;
use std::collections::HashMap;
use std::ops::{Add, Sub};
use tokio_postgres::types::ToSql;
use url::Url;
use uuid::Uuid;

#[derive(Debug, ToSql)]
struct Access {
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

type Parameter<'a> = &'a (dyn ToSql + Sync);

impl<'a> Access {
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
}

async fn save_access(
    pool: Pool,
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
) -> GenericResult<()> {
    let db = pool.get().await.map_err(|e| e.to_string())?;

    let query = String::from(
        "INSERT INTO access \
            (jwt_id, client_id, request_id, requested_scope, \
                granted_scope, requested_audience, granted_audience, \
                code_challenge, code_challenge_method, redirect_uri, \
                requested_at) \
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11) \
        RETURNING jwt_id",
    );

    let access = Access {
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
    };

    db.query_one(&query, &access.parameters())
        .await
        .map_err(|e| e.to_string())?;

    Ok(())
}

/// The OAuth 2.0 Authorize Endpoint
///
/// This endpoint is not documented here because you should never use your own
/// implementation to perform OAuth2 flows. OAuth2 is a very popular protocol
/// and a library for your programming language will exists.
///
/// To learn more about this flow please refer to the specification:
/// https://tools.ietf.org/html/rfc6749
pub(crate) async fn handler_authorize(req: Request<Body>) -> ApiResult<Response<Body>> {
    let pool = req
        .data::<Pool>()
        .ok_or_else(ApiError::fatal("Unable to get database pool connection"))?;

    let params: HashMap<String, String> = req
        .uri()
        .query()
        .map(|v| {
            url::form_urlencoded::parse(v.as_bytes())
                .into_owned()
                .collect()
        })
        .unwrap_or_else(HashMap::new);

    if params.is_empty() {
        return ApiError::bad_request_err::<_>("Url query parameters is empty");
    }

    log::info!("authorize params {:?}", params);

    let redirect_uri = params
        .get("redirect_uri")
        .map(|c| c.to_owned())
        .ok_or_else(ApiError::bad_request(
            "Missing url query parameters 'redirect_uri'",
        ))?;

    let state = params.get("state").map(|c| c.to_owned()).ok_or(
        OauthError::new()
            .uri(redirect_uri.as_str())
            .invalid_request()
            .description("Missing url query parameters 'state'")
            .build(),
    )?;

    let client_id = params
        .get("client_id")
        .map(|c| c.to_owned())
        .ok_or(
            OauthError::new()
                .uri(redirect_uri.as_str())
                .invalid_request()
                .description("Missing url query parameters 'client_id'")
                .state(state.as_str())
                .build(),
        )
        .and_then(|c| {
            Uuid::parse_str(c.as_str()).map_err(|_| {
                OauthError::new()
                    .uri(redirect_uri.as_str())
                    .server_error()
                    .description("Unable to parse 'client_id'")
                    .state(state.as_str())
                    .build()
            })
        })?;

    let client = Client::get_client(pool.clone(), client_id).await;
    if client.grants.is_empty() {
        return Err(OauthError::new()
            .uri(redirect_uri.as_str())
            .server_error()
            .description("Client entry missing 'grants'")
            .state(state.as_str())
            .build());
    }

    if !client.grants.contains(&"authorization_code".into()) {
        return Err(OauthError::new()
            .uri(redirect_uri.as_str())
            .server_error()
            .description("Client entry missing 'authorization_code' grant")
            .state(state.as_str())
            .build());
    }

    if client.redirect_uris.is_empty() {
        return Err(OauthError::new()
            .uri(redirect_uri.as_str())
            .server_error()
            .description("Client entry missing 'redirect_uris'")
            .state(state.as_str())
            .build());
    }

    if !client.redirect_uris.contains(&redirect_uri) {
        return Err(OauthError::new()
            .uri(redirect_uri.as_str())
            .server_error()
            .description(
                "Client entry 'redirect_uri' does not match the provided 'redirect_uri'",
            )
            .state(state.as_str())
            .build());
    }

    let requested_scope = params.get("scope").map(|c| c.to_owned()).ok_or(
        OauthError::new()
            .uri(redirect_uri.as_str())
            .invalid_request()
            .description("Missing url query parameters 'scope'")
            .state(state.as_str())
            .build(),
    )?;

    if !client.scopes.contains(&requested_scope) {
        return Err(OauthError::new()
            .uri(redirect_uri.as_str())
            .server_error()
            .description("Client entry 'scope' does not match the provided 'scope'")
            .state(state.as_str())
            .build());
    }

    let response_type = params.get("response_type").map(|c| c.to_owned()).ok_or(
        OauthError::new()
            .uri(redirect_uri.as_str())
            .invalid_request()
            .description("Missing url query parameters 'response_type'")
            .state(state.as_str())
            .build(),
    )?;

    if !client.response_types.contains(&response_type) {
        return Err(OauthError::new()
            .uri(redirect_uri.as_str())
            .server_error()
            .description("Client entry 'response_type' does not match the provided 'response_type'")
            .state(state.as_str())
            .build());
    }

    let code_challenge = params.get("code_challenge").map(|c| c.to_owned()).ok_or(
        OauthError::new()
            .uri(redirect_uri.as_str())
            .invalid_request()
            .description("Missing url query parameters 'code_challenge'")
            .state(state.as_str())
            .build(),
    )?;

    let code_challenge_method = params
        .get("code_challenge_method")
        .map(|c| c.to_owned())
        .ok_or(
            OauthError::new()
                .uri(redirect_uri.as_str())
                .invalid_request()
                .description("Missing url query parameters 'code_challenge_method'")
                .state(state.as_str())
                .build(),
        )?;

    let request_id = req.context::<Uuid>().ok_or(
        OauthError::new()
            .uri(redirect_uri.as_str())
            .invalid_request()
            .description("Missing context 'request_id'")
            .state(state.as_str())
            .build(),
    )?;

    let current_time = Utc::now();
    let issued_at_time = current_time.timestamp();
    let expiration_time = current_time
        .add(Duration::seconds(AUTHORIZATION_CODE_LIFETIME))
        .timestamp();
    let not_before = current_time.sub(Duration::seconds(1)).timestamp();
    let jwt_id = Uuid::new_v4();

    let claims = AuthorizationCodeClaims {
        jwt_id,
        subject: Uuid::new_v4(),
        issued_at_time,
        expiration_time,
        not_before,
        audience: client_id,
        scope: requested_scope.clone(),
        redirect_uri: redirect_uri.clone(),
    };

    let authorization_code = encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret("secret".as_ref()),
    )
    .map_err(|_| {
        OauthError::new()
            .uri(redirect_uri.as_str())
            .server_error()
            .description("Unable to encode 'authorization_code'")
            .state(state.as_str())
            .build()
    })?;

    save_access(
        pool.clone(),
        jwt_id,
        client_id,
        request_id,
        &requested_scope,
        &requested_scope,
        "",
        "",
        &code_challenge,
        &code_challenge_method,
        &redirect_uri,
        current_time,
    )
    .await
    .map_err(ApiError::Other)?;

    let mut url = Url::parse(redirect_uri.as_str()).map_err(ApiError::Url)?;
    url.query_pairs_mut()
        .clear()
        .append_pair("code", authorization_code.as_str())
        .append_pair("state", state.as_str());

    Response::builder()
        .status(StatusCode::FOUND)
        .header(HeaderValues::LOCATION, url.as_str())
        .body(Body::empty())
        .map_err(ApiError::Http)
}
