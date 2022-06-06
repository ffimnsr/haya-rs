use crate::defaults::{AUTHORIZATION_CODE_LIFETIME, SHARED_ENCODING_KEY};
use crate::error::api_error::OauthError;
use crate::error::{ApiError, ApiResult};
use crate::model::{AuthorizationCodeClaims, Client, OauthAuthorizationCode};
use crate::{HeaderValues, DbContext};
use chrono::{DateTime, Duration, Utc};
use hyper::{Body, Request, Response, StatusCode, Uri};
use jsonwebtoken::{Algorithm, Header};
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
pub(crate) async fn handler_authorize(
    mut req: Request<Body>,
) -> ApiResult<Response<Body>> {
    let db = req
        .data::<DbContext>()
        .ok_or_else(ApiError::fatal("Unable to get database connection"))?
        .clone();

    let request_id = req
        .context::<Uuid>()
        .ok_or_else(ApiError::fatal("Unable to get missing field `request_id`"))?;

    let params = get_params(&mut req).await?;

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

    let client = Client::get_client(db.clone(), client_id).await;
    validate_grants(&client, &redirect_uri, &state)?;
    validate_redirect_uris(&client, &redirect_uri, &state)?;
    validate_response_type(&params, &client, &redirect_uri, &state)?;

    let requested_scope =
        validate_requested_scope(&params, &client, &redirect_uri, &state)?;

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

    let authorization_code = generate_authorization_code(
        db.clone(),
        request_id,
        client_id,
        &requested_scope,
        &redirect_uri,
        &code_challenge,
        &code_challenge_method,
        &state,
    )
    .await?;

    build_response(&authorization_code, &redirect_uri, &state)
}

async fn get_params(req: &mut Request<Body>) -> ApiResult<HashMap<String, String>> {
    let params = get_url_query_params(req.uri());

    if !params.is_none() {
        return Ok(params.unwrap_or_else(HashMap::new));
    }

    let params = get_body_params(req).await;
    Ok(params.unwrap_or_else(HashMap::new))
}

fn get_url_query_params(uri: &Uri) -> Option<HashMap<String, String>> {
    uri.query().map(|v| {
        url::form_urlencoded::parse(v.as_bytes())
            .into_owned()
            .collect::<_>()
    })
}

async fn get_body_params(req: &mut Request<Body>) -> Option<HashMap<String, String>> {
    hyper::body::to_bytes(req.body_mut())
        .await
        .map(|v| url::form_urlencoded::parse(&v).into_owned().collect::<_>())
        .ok()
}

fn build_response(
    authorization_code: &str,
    redirect_uri: &str,
    state: &str,
) -> ApiResult<Response<Body>> {
    let mut url = Url::parse(redirect_uri).map_err(ApiError::UrlParse)?;
    url.query_pairs_mut()
        .clear()
        .append_pair("code", authorization_code)
        .append_pair("state", state);

    Response::builder()
        .status(StatusCode::FOUND)
        .header(HeaderValues::LOCATION, url.as_str())
        .body(Body::empty())
        .map_err(ApiError::Http)
}

fn validate_grants(client: &Client, redirect_uri: &str, state: &str) -> ApiResult<()> {
    if client.grants.is_empty() {
        return Err(OauthError::new()
            .uri(redirect_uri)
            .server_error()
            .description("Client entry missing 'grants'")
            .state(state)
            .build());
    }

    if !client.grants.contains(&"authorization_code".into()) {
        return Err(OauthError::new()
            .uri(redirect_uri)
            .server_error()
            .description("Client entry missing 'authorization_code' grant")
            .state(state)
            .build());
    }

    return Ok(());
}

fn validate_redirect_uris(
    client: &Client,
    redirect_uri: &str,
    state: &str,
) -> ApiResult<()> {
    if client.redirect_uris.is_empty() {
        return Err(OauthError::new()
            .uri(redirect_uri)
            .server_error()
            .description("Client entry missing 'redirect_uris'")
            .state(state)
            .build());
    }

    if !client.redirect_uris.contains(&redirect_uri.to_string()) {
        return Err(OauthError::new()
            .uri(redirect_uri)
            .server_error()
            .description(
                "Client entry 'redirect_uri' does not match the provided 'redirect_uri'",
            )
            .state(state)
            .build());
    }

    return Ok(());
}

fn validate_requested_scope(
    params: &HashMap<String, String>,
    client: &Client,
    redirect_uri: &str,
    state: &str,
) -> ApiResult<String> {
    let requested_scope = params.get("scope").map(|c| c.to_owned()).ok_or(
        OauthError::new()
            .uri(redirect_uri)
            .invalid_request()
            .description("Missing url query parameters 'scope'")
            .state(state)
            .build(),
    )?;

    if !client.scopes.contains(&requested_scope) {
        return Err(OauthError::new()
            .uri(redirect_uri)
            .server_error()
            .description("Client entry 'scope' does not match the provided 'scope'")
            .state(state)
            .build());
    }

    return Ok(requested_scope);
}

fn validate_response_type(
    params: &HashMap<String, String>,
    client: &Client,
    redirect_uri: &str,
    state: &str,
) -> ApiResult<()> {
    let response_type = params.get("response_type").map(|c| c.to_owned()).ok_or(
        OauthError::new()
            .uri(redirect_uri)
            .invalid_request()
            .description("Missing url query parameters 'response_type'")
            .state(state)
            .build(),
    )?;

    if !client.response_types.contains(&response_type) {
        return Err(OauthError::new()
            .uri(redirect_uri)
            .server_error()
            .description("Client entry 'response_type' does not match the provided 'response_type'")
            .state(state)
            .build());
    }

    return Ok(());
}

async fn generate_authorization_code(
    db: DbContext,
    request_id: Uuid,
    client_id: Uuid,
    requested_scope: &str,
    redirect_uri: &str,
    code_challenge: &str,
    code_challenge_method: &str,
    state: &str,
) -> ApiResult<String> {
    let current_time = Utc::now();
    let issued_at_time = current_time.timestamp();
    let expiration_time = current_time
        .add(Duration::seconds(AUTHORIZATION_CODE_LIFETIME))
        .timestamp();
    let not_before = current_time.sub(Duration::seconds(1)).timestamp();
    let jwt_id = Uuid::new_v4();
    let subject = Uuid::new_v4();

    let claims = AuthorizationCodeClaims {
        jwt_id,
        subject,
        issued_at_time,
        expiration_time,
        not_before,
        audience: client_id,
        scope: requested_scope.to_string(),
        redirect_uri: redirect_uri.to_string(),
    };

    let priv_encode_key = SHARED_ENCODING_KEY
        .as_ref()
        .map_err(|e| ApiError::BadRequest(e.to_string()))?;

    let authorization_code =
        jsonwebtoken::encode(&Header::new(Algorithm::ES256), &claims, &priv_encode_key)
            .map_err(|_| {
                OauthError::new()
                    .uri(redirect_uri)
                    .server_error()
                    .description("Unable to encode 'authorization_code'")
                    .state(state)
                    .build()
            })?;

    save_authorization_code(
        db.clone(),
        jwt_id,
        client_id,
        request_id,
        subject,
        &requested_scope,
        "",
        "",
        "",
        &code_challenge,
        &code_challenge_method,
        &redirect_uri,
        current_time,
    )
    .await?;

    Ok(authorization_code)
}

async fn save_authorization_code(
    db: DbContext,
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
) -> ApiResult<()> {
    let auth_db = OauthAuthorizationCode::new(
        jwt_id,
        client_id,
        request_id,
        subject,
        &requested_scope,
        &granted_scope,
        &requested_audience,
        &granted_audience,
        &code_challenge,
        &code_challenge_method,
        &redirect_uri,
        requested_at,
    );

    auth_db
        .save_authorization_code(db)
        .await
        .map_err(ApiError::Other)
}
