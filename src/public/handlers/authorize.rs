use crate::defaults::{AUTHORIZATION_CODE_LIFETIME, SHARED_ENCODING_KEY};
use crate::errors::api_error::OauthError;
use crate::errors::{ApiError, ApiResult};
use crate::models::{AuthorizationCodeClaims, Client, OauthAuthorizationCode};
use crate::db::Pool;
use crate::HeaderValues;
use chrono::{Duration, Utc};
use hyper::{Body, Request, Response, StatusCode};
use jsonwebtoken::{Header, Algorithm};
use routerify::prelude::*;
use std::collections::HashMap;
use std::ops::{Add, Sub};
use url::Url;
use uuid::Uuid;

/// The OAuth 2.0 Authorize Endpoint
///
/// The authorization endpoint is used to interact with the resource owner and
/// obtain an authorization grant. The authorization server MUST first verify
/// the identity of the resource owner. The way in which the authorization
/// server authenticates the resource owner (e.g., username and password login,
/// session cookies) is beyond the scope of this specification.
///
/// To learn more about this, please refer to the specification:
/// https://datatracker.ietf.org/doc/html/rfc6749#section-3.1
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

    let priv_encode_key = SHARED_ENCODING_KEY.as_ref().map_err(|e| ApiError::BadRequest(e.to_string()))?;

    let authorization_code = jsonwebtoken::encode(
        &Header::new(Algorithm::ES256),
        &claims,
        &priv_encode_key,
    )
    .map_err(|_| {
        OauthError::new()
            .uri(redirect_uri.as_str())
            .server_error()
            .description("Unable to encode 'authorization_code'")
            .state(state.as_str())
            .build()
    })?;

    let auth_db = OauthAuthorizationCode::new(
        jwt_id,
        client_id,
        request_id,
        Uuid::new_v4(),
        &requested_scope,
        &requested_scope,
        "",
        "",
        &code_challenge,
        &code_challenge_method,
        &redirect_uri,
        current_time,
    );

    auth_db.save_authorization_code(&pool)
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
