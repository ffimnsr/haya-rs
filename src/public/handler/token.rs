use crate::{defaults::*, DbContext};
use crate::error::api_error::OauthError;
use crate::error::{ApiError, ApiResult};
use crate::model::{
    AuthorizationCodeClaims, Client, OauthAccessToken, OauthAuthorizationCode,
    OauthRefreshToken, StandardTokenClaims,
};
use crate::{HeaderValues, MimeValues};
use chrono::{DateTime, Duration, NaiveDateTime, Utc};
use hyper::{Body, Request, Response, StatusCode};
use jsonwebtoken::{Algorithm, Header, Validation};
use routerify::prelude::*;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::ops::{Add, Sub};
use uuid::Uuid;

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
    let db = req
        .data::<DbContext>()
        .ok_or_else(ApiError::fatal("Unable to get database connection"))?
        .clone();

    let request_id = req.context::<Uuid>().ok_or(
        OauthError::new()
            .invalid_request()
            .description("Missing context 'request_id'")
            .build(),
    )?;

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

    let client = Client::get_client(db.clone(), client_id).await;
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

    let priv_encode_key = SHARED_ENCODING_KEY
        .as_ref()
        .map_err(|e| ApiError::BadRequest(e.to_string()))?;
    let priv_decode_key = SHARED_DECODING_KEY
        .as_ref()
        .map_err(|e| ApiError::BadRequest(e.to_string()))?;

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
            &priv_decode_key,
            &Validation::new(Algorithm::ES256),
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

        let stored_auth_code =
            OauthAuthorizationCode::get_authorization_code(db.clone(), &claims.jwt_id)
                .await
                .map_err(ApiError::Other)?;

        if stored_auth_code.code_challenge_method.eq("S256") {
            let mut hasher = Sha256::new();
            hasher.update(code_verifier.as_bytes());
            let generate_code_challenge = base64::encode(hasher.finalize())
                .replace("+", "-")
                .replace("/", "_")
                .replace("=", "");

            if generate_code_challenge.ne(&stored_auth_code.code_challenge) {
                return ApiError::bad_request_err(
                    "The provided 'code_verifier' does not equate to the stored 'code_challenge'",
                );
            }
        }

        OauthAuthorizationCode::revoke_authorization_code(db.clone(), &claims.jwt_id)
            .await
            .map_err(ApiError::Other)?;

        let current_time = Utc::now();
        let access_token_expiration_time =
            current_time.add(Duration::seconds(ACCESS_TOKEN_LIFETIME));
        let access_token_not_before = current_time.sub(Duration::seconds(1));
        let access_token_jwt_id = Uuid::new_v4();

        let access_token_claims = StandardTokenClaims {
            jwt_id: access_token_jwt_id,
            subject: claims.subject,
            issued_at_time: current_time.timestamp(),
            expiration_time: access_token_expiration_time.timestamp(),
            not_before: access_token_not_before.timestamp(),
            audience: client_id,
            scope: claims.scope.clone(),
            token_type: "access_token".to_string(),
        };

        let access_token = jsonwebtoken::encode(
            &Header::new(Algorithm::ES256),
            &access_token_claims,
            &priv_encode_key,
        )
        .map_err(|_| {
            OauthError::new()
                .server_error()
                .description("Unable to encode 'access_token'")
                .state(state.as_str())
                .build_token()
        })?;

        let access_token_client = OauthAccessToken::new(
            access_token_jwt_id,
            client_id,
            request_id,
            claims.subject,
            claims.scope.clone().as_str(),
            claims.audience.clone().to_string().as_str(),
            current_time,
        );

        access_token_client.save_access_token(db.clone()).await.unwrap();

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
            &Header::new(Algorithm::ES256),
            &refresh_token_claims,
            &priv_encode_key,
        )
        .map_err(|_| {
            OauthError::new()
                .server_error()
                .description("Unable to encode 'refresh_token'")
                .state(state.as_str())
                .build_token()
        })?;

        let refresh_token_client = OauthRefreshToken::new(
            access_token_jwt_id,
            client_id,
            request_id,
            claims.subject,
            claims.scope.clone().as_str(),
            claims.audience.clone().to_string().as_str(),
            current_time,
        );

        refresh_token_client
            .save_refresh_token(db.clone())
            .await
            .unwrap();

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
            .ok_or_else(ApiError::bad_request(
                "Missing body parameters 'refresh_token'",
            ))?;

        let scope = params
            .get("scope")
            .map(|c| c.to_owned())
            .ok_or_else(ApiError::bad_request("Missing body parameters 'scope'"))?;

        let claims = jsonwebtoken::decode::<StandardTokenClaims>(
            &refresh_token,
            &priv_decode_key,
            &Validation::new(Algorithm::ES256),
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

        OauthRefreshToken::revoke_refresh_token(db, &claims.jwt_id)
            .await
            .unwrap();

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
            &Header::new(Algorithm::ES256),
            &access_token_claims,
            &priv_encode_key,
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
            &Header::new(Algorithm::ES256),
            &refresh_token_claims,
            &priv_encode_key,
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
