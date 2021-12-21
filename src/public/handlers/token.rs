use crate::defaults::{ACCESS_TOKEN_LIFETIME, REFRESH_TOKEN_LIFETIME};
use crate::errors::api_error::OauthError;
use crate::errors::{ApiError, ApiResult};
use crate::models::{AuthorizationCodeClaims, Client, StandardTokenClaims};
use crate::db::Pool;
use crate::{HeaderValues, MimeValues};
use chrono::{DateTime, Duration, NaiveDateTime, Utc};
use hyper::{Body, Request, Response, StatusCode};
use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey, Header, Validation};
use routerify::prelude::*;
use std::collections::HashMap;
use std::ops::{Add, Sub};
use uuid::Uuid;
use sha2::Sha256;

/// The OAuth 2.0 Token Endpoint
///
/// The token endpoint is used by the client to obtain an access token by
/// presenting its authorization grant or refresh token. The token endpoint is
/// used with every authorization grant except for the implicit grant type
/// (since an access token is issued directly).
///
/// To learn more about this, please refer to the specification:
/// https://datatracker.ietf.org/doc/html/rfc6749#section-3.2
pub(crate) async fn handler_token(req: Request<Body>) -> ApiResult<Response<Body>> {
    let pool = req
        .data::<Pool>()
        .ok_or_else(ApiError::fatal("Unable to get database pool connection"))?
        .clone();

    let content_type = req
        .headers()
        .get(HeaderValues::CONTENT_TYPE)
        .ok_or_else(ApiError::bad_request("Unable to get content type header"))
        .and_then(|v| v.to_str().map_err(ApiError::HeaderToStr))?;

    if content_type != MimeValues::WWW_FORM_URLENCODED_MIME_TYPE {
        return ApiError::bad_request_err(
            "Content must be of type 'application/x-www-form-urlencoded'",
        );
    }

    let authorization = req
        .headers()
        .get(HeaderValues::AUTHORIZATION)
        .ok_or_else(ApiError::bad_request("Unable to get authorization header"))
        .and_then(|v| {
            v.to_str()
                .map(|v| v.split_whitespace().collect::<Vec<_>>())
                .map(|v| v[1])
                .map_err(ApiError::HeaderToStr)
        })?;

    let credentials = base64::decode(authorization)
        .map_err(|c| ApiError::BadRequest(c.to_string()))
        .and_then(|c| String::from_utf8(c).map_err(ApiError::StringFromUtf8))?;

    let credentials = credentials.split(":").collect::<Vec<_>>();

    let params: HashMap<String, String> = hyper::body::to_bytes(req.into_body())
        .await
        .map(|v| url::form_urlencoded::parse(&v).into_owned().collect())
        .map_err(ApiError::Hyper)?;

    if params.is_empty() {
        return ApiError::bad_request_err("Unable to parse request body");
    }

    log::info!("token params {:?}", params);

    let client_id = credentials
        .get(0)
        .map(|c| c.to_owned())
        .ok_or_else(ApiError::bad_request("Missing auth parameters 'client_id'"))
        .and_then(|c| {
            Uuid::parse_str(c)
                .map_err(|_| ApiError::BadRequest("Unable to parse 'client_id'".into()))
        })?;

    let client = Client::get_client(pool.clone(), client_id).await;
    let grant_type = params.get("grant_type").map(|c| c.to_owned()).ok_or_else(
        ApiError::bad_request("Missing body parameters 'grant_type'"),
    )?;

    if client.grants.is_empty() {
        return ApiError::bad_request_err("Client entry missing 'grants'");
    }

    if !client.grants.contains(&grant_type) {
        return ApiError::bad_request_err(
            format!("Client entry missing '{}' grant", grant_type).as_str(),
        );
    }

    if grant_type == "authorization_code" {
        let code = params
            .get("code")
            .map(|c| c.to_owned())
            .ok_or_else(ApiError::bad_request("Missing body parameters 'code'"))?;

        let state = params
            .get("state")
            .map(|c| c.to_owned())
            .ok_or_else(ApiError::bad_request("Missing body parameters 'state'"))?;

        let redirect_uri = params
            .get("redirect_uri")
            .map(|c| c.to_owned())
            .ok_or_else(ApiError::bad_request(
                "Missing body parameters 'redirect_uri'",
            ))?;

        let claims = jsonwebtoken::decode::<AuthorizationCodeClaims>(
            &code,
            &DecodingKey::from_secret("secret".as_ref()),
            &Validation::new(Algorithm::HS256),
        )
        .map_err(ApiError::Jwt)?
        .claims;

        if claims.audience.ne(&client_id) {
            return ApiError::bad_request_err(
                "The provided client id does not match jwt client id",
            );
        }

        let exp = DateTime::<Utc>::from_utc(
            NaiveDateTime::from_timestamp(claims.expiration_time, 0),
            Utc,
        );

        if exp.le(&Utc::now()) {
            return ApiError::bad_request_err(
                "The provided authorization code already expired",
            );
        }

        if claims.redirect_uri.ne(&redirect_uri) {
            return ApiError::bad_request_err(
                "The provided redirect_uri does not match jwt redirect uri",
            );
        }

        let code_verifier = params
            .get("code_verifier")
            .map(|c| c.to_owned())
            .ok_or_else(ApiError::bad_request(
                "Missing body parameters 'code_verifier'",
            ))?;

        // TODO: verify first pkce before proceeding
        // TODO: revoke authorization code using the active bool column

        let current_time = Utc::now();
        let access_token_expiration_time =
            current_time.add(Duration::seconds(ACCESS_TOKEN_LIFETIME));
        let access_token_not_before = current_time.sub(Duration::seconds(1));

        let access_token_claims = StandardTokenClaims {
            jwt_id: Uuid::new_v4(),
            subject: claims.subject,
            issued_at_time: current_time.timestamp(),
            expiration_time: access_token_expiration_time.timestamp(),
            not_before: access_token_not_before.timestamp(),
            audience: client_id,
            scope: claims.scope.clone(),
            token_type: "access_token".to_string(),
        };

        let access_token = jsonwebtoken::encode(
            &Header::default(),
            &access_token_claims,
            &EncodingKey::from_secret("secret".as_ref()),
        )
        .map_err(|_| {
            OauthError::new()
                .server_error()
                .description("Unable to encode 'access_token'")
                .state(state.as_str())
                .build_token()
        })?;

        let refresh_token_expiration_time =
            current_time.add(Duration::seconds(REFRESH_TOKEN_LIFETIME));
        let refresh_token_not_before =
            access_token_expiration_time.sub(Duration::seconds(1));

        let refresh_token_claims = StandardTokenClaims {
            jwt_id: Uuid::new_v4(),
            subject: claims.subject,
            issued_at_time: current_time.timestamp(),
            expiration_time: refresh_token_expiration_time.timestamp(),
            not_before: refresh_token_not_before.timestamp(),
            audience: client_id,
            scope: claims.scope.clone(),
            token_type: "refresh_token".to_string(),
        };

        let refresh_token = jsonwebtoken::encode(
            &Header::default(),
            &refresh_token_claims,
            &EncodingKey::from_secret("secret".as_ref()),
        )
        .map_err(|_| {
            OauthError::new()
                .server_error()
                .description("Unable to encode 'refresh_token'")
                .state(state.as_str())
                .build_token()
        })?;

        let data = serde_json::json!({
            "token_type": "Bearer",
            "access_token": access_token,
            "expires_in": ACCESS_TOKEN_LIFETIME,
            "refresh_token": refresh_token,
            "scope": claims.scope,
        });

        Response::builder()
            .status(StatusCode::OK)
            .header(HeaderValues::CONTENT_TYPE, MimeValues::JSON_MIME_TYPE)
            .header(HeaderValues::CACHE_CONTROL, "no-store")
            .header(HeaderValues::PRAGMA, "no-cache")
            .body(Body::from(data.to_string()))
            .map_err(ApiError::Http)
    } else {
        let refresh_token = params
            .get("refresh_token")
            .map(|c| c.to_owned())
            .ok_or_else(ApiError::bad_request("Missing body parameters 'refresh_token'"))?;

        let scope = params
            .get("scope")
            .map(|c| c.to_owned())
            .ok_or_else(ApiError::bad_request("Missing body parameters 'scope'"))?;

        let claims = jsonwebtoken::decode::<StandardTokenClaims>(
            &refresh_token,
            &DecodingKey::from_secret("secret".as_ref()),
            &Validation::new(Algorithm::HS256),
        )
        .map_err(ApiError::Jwt)?
        .claims;

        if claims.token_type.ne(&"refresh_token".to_string()) {
            return Err(OauthError::new()
                .server_error()
                .description("Refresh token invalid")
                .build_token());
        }

        if claims.audience.ne(&client_id) {
            return ApiError::bad_request_err(
                "The provided client id does not match jwt client id",
            );
        }

        let exp = DateTime::<Utc>::from_utc(
            NaiveDateTime::from_timestamp(claims.expiration_time, 0),
            Utc,
        );

        if exp.le(&Utc::now()) {
            return ApiError::bad_request_err(
                "The provided authorization code already expired",
            );
        }

        // TODO: revoke token if its only specified for one time use

        let current_time = Utc::now();
        let access_token_expiration_time =
            current_time.add(Duration::seconds(ACCESS_TOKEN_LIFETIME));
        let access_token_not_before = current_time.sub(Duration::seconds(1));

        let access_token_claims = StandardTokenClaims {
            jwt_id: Uuid::new_v4(),
            subject: claims.subject,
            issued_at_time: current_time.timestamp(),
            expiration_time: access_token_expiration_time.timestamp(),
            not_before: access_token_not_before.timestamp(),
            audience: client_id,
            scope: claims.scope.clone(),
            token_type: "access_token".to_string(),
        };

        let access_token = jsonwebtoken::encode(
            &Header::default(),
            &access_token_claims,
            &EncodingKey::from_secret("secret".as_ref()),
        )
        .map_err(|_| {
            OauthError::new()
                .server_error()
                .description("Unable to encode 'access_token'")
                .build_token()
        })?;

        let refresh_token_expiration_time =
            current_time.add(Duration::seconds(REFRESH_TOKEN_LIFETIME));
        let refresh_token_not_before =
            access_token_expiration_time.sub(Duration::seconds(1));

        let refresh_token_claims = StandardTokenClaims {
            jwt_id: Uuid::new_v4(),
            subject: claims.subject,
            issued_at_time: current_time.timestamp(),
            expiration_time: refresh_token_expiration_time.timestamp(),
            not_before: refresh_token_not_before.timestamp(),
            audience: client_id,
            scope: claims.scope.clone(),
            token_type: "refresh_token".to_string(),
        };

        let refresh_token = jsonwebtoken::encode(
            &Header::default(),
            &refresh_token_claims,
            &EncodingKey::from_secret("secret".as_ref()),
        )
        .map_err(|_| {
            OauthError::new()
                .server_error()
                .description("Unable to encode 'refresh_token'")
                .build_token()
        })?;

        let data = serde_json::json!({
            "token_type": "Bearer",
            "access_token": access_token,
            "expires_in": ACCESS_TOKEN_LIFETIME,
            "refresh_token": refresh_token,
            "scope": claims.scope,
        });

        Response::builder()
            .status(StatusCode::OK)
            .header(HeaderValues::CONTENT_TYPE, MimeValues::JSON_MIME_TYPE)
            .header(HeaderValues::CACHE_CONTROL, "no-store")
            .header(HeaderValues::PRAGMA, "no-cache")
            .body(Body::from(data.to_string()))
            .map_err(ApiError::Http)
    }
}
