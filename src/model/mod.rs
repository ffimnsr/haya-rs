use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sqlx::FromRow;
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct User {
    pub id: Uuid,
    pub instance_id: Option<Uuid>,
    pub aud: Option<String>,
    pub role: Option<String>,
    pub email: Option<String>,
    pub encrypted_password: Option<String>,
    pub email_confirmed_at: Option<DateTime<Utc>>,
    pub phone: Option<String>,
    pub phone_confirmed_at: Option<DateTime<Utc>>,
    pub confirmed_at: Option<DateTime<Utc>>,
    pub last_sign_in_at: Option<DateTime<Utc>>,
    pub raw_app_meta_data: Option<Value>,
    pub raw_user_meta_data: Option<Value>,
    pub is_super_admin: Option<bool>,
    pub is_anonymous: bool,
    pub banned_until: Option<DateTime<Utc>>,
    pub created_at: Option<DateTime<Utc>>,
    pub updated_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserResponse {
    pub id: Uuid,
    pub aud: String,
    pub role: String,
    pub email: Option<String>,
    pub email_confirmed_at: Option<DateTime<Utc>>,
    pub phone: Option<String>,
    pub phone_confirmed_at: Option<DateTime<Utc>>,
    pub confirmed_at: Option<DateTime<Utc>>,
    pub last_sign_in_at: Option<DateTime<Utc>>,
    pub app_metadata: Value,
    pub user_metadata: Value,
    pub identities: Vec<Value>,
    pub created_at: Option<DateTime<Utc>>,
    pub updated_at: Option<DateTime<Utc>>,
    pub is_anonymous: bool,
}

impl From<User> for UserResponse {
    fn from(u: User) -> Self {
        Self {
            id: u.id,
            aud: u.aud.unwrap_or_else(|| "authenticated".to_string()),
            role: u.role.unwrap_or_else(|| "authenticated".to_string()),
            email: u.email,
            email_confirmed_at: u.email_confirmed_at,
            phone: u.phone,
            phone_confirmed_at: u.phone_confirmed_at,
            confirmed_at: u.confirmed_at,
            last_sign_in_at: u.last_sign_in_at,
            app_metadata: u.raw_app_meta_data.unwrap_or(serde_json::json!({})),
            user_metadata: u.raw_user_meta_data.unwrap_or(serde_json::json!({})),
            identities: vec![],
            created_at: u.created_at,
            updated_at: u.updated_at,
            is_anonymous: u.is_anonymous,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenResponse {
    pub access_token: String,
    pub token_type: String,
    pub expires_in: i64,
    pub expires_at: i64,
    pub refresh_token: String,
    pub user: UserResponse,
}

/// Session model - kept for future session management endpoints.
#[allow(dead_code)]
#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct Session {
    pub id: Uuid,
    pub user_id: Uuid,
    pub aal: Option<String>,
    pub created_at: Option<DateTime<Utc>>,
    pub updated_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct RefreshToken {
    pub id: i64,
    pub instance_id: Option<Uuid>,
    pub user_id: Option<String>,
    pub token: Option<String>,
    pub created_at: Option<DateTime<Utc>>,
    pub updated_at: Option<DateTime<Utc>>,
    pub parent: Option<String>,
    pub session_id: Option<Uuid>,
    pub revoked: Option<bool>,
}
