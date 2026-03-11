use chrono::Utc;
use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey, Header, TokenData, Validation, decode, encode};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::error::AuthError;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AmrEntry {
    pub method: String,
    pub timestamp: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Claims {
    pub sub: String,
    pub aud: String,
    pub exp: i64,
    pub iat: i64,
    pub iss: String,
    pub email: Option<String>,
    pub phone: Option<String>,
    pub role: String,
    pub aal: String,
    pub amr: Vec<AmrEntry>,
    pub session_id: String,
    pub is_anonymous: bool,
    pub user_metadata: serde_json::Value,
    pub app_metadata: serde_json::Value,
}

pub fn encode_token(
    user_id: Uuid,
    email: Option<String>,
    phone: Option<String>,
    role: &str,
    session_id: Uuid,
    is_anonymous: bool,
    method: &str,
    user_metadata: serde_json::Value,
    app_metadata: serde_json::Value,
    jwt_secret: &str,
    jwt_exp: i64,
    issuer: &str,
) -> Result<String, AuthError> {
    let now = Utc::now().timestamp();
    let claims = Claims {
        sub: user_id.to_string(),
        aud: "authenticated".to_string(),
        exp: now + jwt_exp,
        iat: now,
        iss: issuer.to_string(),
        email,
        phone,
        role: role.to_string(),
        aal: "aal1".to_string(),
        amr: vec![AmrEntry {
            method: method.to_string(),
            timestamp: now,
        }],
        session_id: session_id.to_string(),
        is_anonymous,
        user_metadata,
        app_metadata,
    };
    encode(
        &Header::new(Algorithm::HS256),
        &claims,
        &EncodingKey::from_secret(jwt_secret.as_bytes()),
    )
    .map_err(|e| AuthError::InternalError(e.to_string()))
}

pub fn decode_token(token: &str, jwt_secret: &str) -> Result<TokenData<Claims>, AuthError> {
    let mut validation = Validation::new(Algorithm::HS256);
    validation.set_audience(&["authenticated"]);
    decode::<Claims>(
        token,
        &DecodingKey::from_secret(jwt_secret.as_bytes()),
        &validation,
    )
    .map_err(|e| match e.kind() {
        jsonwebtoken::errors::ErrorKind::ExpiredSignature => AuthError::TokenExpired,
        _ => AuthError::InvalidToken,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encode_decode_token() {
        let user_id = Uuid::new_v4();
        let session_id = Uuid::new_v4();
        let secret = "test-secret-key";

        let token = encode_token(
            user_id,
            Some("test@example.com".to_string()),
            None,
            "authenticated",
            session_id,
            false,
            "password",
            serde_json::json!({}),
            serde_json::json!({"provider": "email"}),
            secret,
            3600,
            "https://example.com",
        )
        .unwrap();

        let decoded = decode_token(&token, secret).unwrap();
        assert_eq!(decoded.claims.sub, user_id.to_string());
        assert_eq!(decoded.claims.aud, "authenticated");
        assert_eq!(decoded.claims.role, "authenticated");
    }

    #[test]
    fn test_expired_token_returns_token_expired() {
        let user_id = Uuid::new_v4();
        let session_id = Uuid::new_v4();
        let secret = "test-secret-key";

        let token = encode_token(
            user_id,
            None,
            None,
            "authenticated",
            session_id,
            false,
            "password",
            serde_json::json!({}),
            serde_json::json!({}),
            secret,
            -3700, // expired beyond the default 60s leeway
            "https://example.com",
        )
        .unwrap();

        let result = decode_token(&token, secret);
        assert!(matches!(result, Err(AuthError::TokenExpired)));
    }
}
