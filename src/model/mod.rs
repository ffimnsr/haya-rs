use std::collections::HashMap;

use chrono::{
  DateTime,
  Utc,
};
use serde::{
  Deserialize,
  Serialize,
};
use serde_json::Value;
use sqlx::{
  FromRow,
  PgPool,
};
use uuid::Uuid;

use crate::error::Result;

#[derive(Debug, Clone, Deserialize, FromRow)]
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
  pub is_sso_user: bool,
  pub is_anonymous: bool,
  pub banned_until: Option<DateTime<Utc>>,
  pub deleted_at: Option<DateTime<Utc>>,
  pub created_at: Option<DateTime<Utc>>,
  pub updated_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct Identity {
  pub id: Uuid,
  pub provider_id: String,
  pub user_id: Uuid,
  pub identity_data: Value,
  pub provider: String,
  pub last_sign_in_at: Option<DateTime<Utc>>,
  pub email: Option<String>,
  pub created_at: Option<DateTime<Utc>>,
  pub updated_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserResponse {
  pub id: Uuid,
  pub instance_id: Option<Uuid>,
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
  pub is_super_admin: bool,
  pub is_sso_user: bool,
  pub banned_until: Option<DateTime<Utc>>,
  pub deleted_at: Option<DateTime<Utc>>,
  pub created_at: Option<DateTime<Utc>>,
  pub updated_at: Option<DateTime<Utc>>,
  pub is_anonymous: bool,
}

impl UserResponse {
  pub async fn from_user(db: &PgPool, u: User) -> Result<Self> {
    Ok(Self {
      id: u.id,
      instance_id: u.instance_id,
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
      identities: fetch_identity_values(db, u.id).await?,
      is_super_admin: u.is_super_admin.unwrap_or(false),
      is_sso_user: u.is_sso_user,
      banned_until: u.banned_until,
      deleted_at: u.deleted_at,
      created_at: u.created_at,
      updated_at: u.updated_at,
      is_anonymous: u.is_anonymous,
    })
  }
}

pub async fn identity_values_by_user_id(db: &PgPool, user_ids: &[Uuid]) -> Result<HashMap<Uuid, Vec<Value>>> {
  if user_ids.is_empty() {
    return Ok(HashMap::new());
  }

  let identities: Vec<Identity> = sqlx::query_as::<_, Identity>(
    "SELECT id, provider_id, user_id, identity_data, provider, last_sign_in_at, email, created_at, updated_at FROM auth.identities WHERE user_id = ANY($1) ORDER BY created_at ASC",
  )
  .bind(user_ids)
  .fetch_all(db)
  .await?;

  let mut grouped = HashMap::<Uuid, Vec<Value>>::new();
  for identity in identities {
    grouped
      .entry(identity.user_id)
      .or_default()
      .push(identity.as_response_value());
  }
  Ok(grouped)
}

async fn fetch_identity_values(db: &PgPool, user_id: Uuid) -> Result<Vec<Value>> {
  let identities: Vec<Identity> = sqlx::query_as::<_, Identity>(
    "SELECT id, provider_id, user_id, identity_data, provider, last_sign_in_at, email, created_at, updated_at FROM auth.identities WHERE user_id = $1 ORDER BY created_at ASC",
  )
  .bind(user_id)
  .fetch_all(db)
  .await?;

  Ok(
    identities
      .into_iter()
      .map(|identity| identity.as_response_value())
      .collect(),
  )
}

impl Identity {
  pub fn as_response_value(&self) -> Value {
    serde_json::json!({
      "identity_id": self.id,
      "id": self.id,
      "user_id": self.user_id,
      "identity_data": self.identity_data,
      "provider": self.provider,
      "provider_id": self.provider_id,
      "email": self.email,
      "last_sign_in_at": self.last_sign_in_at,
      "created_at": self.created_at,
      "updated_at": self.updated_at,
    })
  }
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn user_response_exposes_extended_metadata() {
    let user = User {
      id: Uuid::nil(),
      instance_id: Some(Uuid::nil()),
      aud: None,
      role: None,
      email: Some("user@example.com".to_string()),
      encrypted_password: None,
      email_confirmed_at: None,
      phone: None,
      phone_confirmed_at: None,
      confirmed_at: None,
      last_sign_in_at: None,
      raw_app_meta_data: None,
      raw_user_meta_data: None,
      is_super_admin: None,
      is_sso_user: true,
      is_anonymous: false,
      banned_until: None,
      deleted_at: None,
      created_at: None,
      updated_at: None,
    };

    let response = UserResponse {
      id: user.id,
      instance_id: user.instance_id,
      aud: "authenticated".to_string(),
      role: "authenticated".to_string(),
      email: user.email,
      email_confirmed_at: user.email_confirmed_at,
      phone: user.phone,
      phone_confirmed_at: user.phone_confirmed_at,
      confirmed_at: user.confirmed_at,
      last_sign_in_at: user.last_sign_in_at,
      app_metadata: serde_json::json!({}),
      user_metadata: serde_json::json!({}),
      identities: vec![],
      is_super_admin: false,
      is_sso_user: true,
      banned_until: user.banned_until,
      deleted_at: user.deleted_at,
      created_at: user.created_at,
      updated_at: user.updated_at,
      is_anonymous: user.is_anonymous,
    };

    assert_eq!(response.instance_id, Some(Uuid::nil()));
    assert!(!response.is_super_admin);
    assert!(response.is_sso_user);
    assert_eq!(response.app_metadata, serde_json::json!({}));
    assert_eq!(response.user_metadata, serde_json::json!({}));
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

#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct MfaFactorRow {
  pub id: Uuid,
  pub user_id: Uuid,
  pub friendly_name: Option<String>,
  pub factor_type: String,
  pub status: String,
  pub secret: Option<String>,
  pub created_at: DateTime<Utc>,
  pub updated_at: DateTime<Utc>,
  pub last_challenged_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MfaFactorResponse {
  pub id: Uuid,
  pub friendly_name: Option<String>,
  pub factor_type: String,
  pub status: String,
  pub created_at: DateTime<Utc>,
  pub updated_at: DateTime<Utc>,
  pub last_challenged_at: Option<DateTime<Utc>>,
}

impl From<MfaFactorRow> for MfaFactorResponse {
  fn from(value: MfaFactorRow) -> Self {
    Self {
      id: value.id,
      friendly_name: value.friendly_name,
      factor_type: value.factor_type,
      status: value.status,
      created_at: value.created_at,
      updated_at: value.updated_at,
      last_challenged_at: value.last_challenged_at,
    }
  }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MfaEnrollResponse {
  pub id: Uuid,
  pub friendly_name: Option<String>,
  pub factor_type: String,
  pub status: String,
  pub totp: TotpEnrollment,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TotpEnrollment {
  pub secret: String,
  pub uri: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PendingMfaResponse {
  pub mfa_required: bool,
  pub mfa_token: String,
  pub factors: Vec<MfaFactorResponse>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum TokenGrantResponse {
  Token(Box<TokenResponse>),
  PendingMfa(PendingMfaResponse),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum VerifyGrantResponse {
  Token(Box<TokenResponse>),
  PendingMfa(PendingMfaResponse),
  User(Box<UserResponse>),
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
pub struct SessionRow {
  pub id: Uuid,
  pub user_id: Uuid,
  pub factor_id: Option<Uuid>,
  pub aal: Option<String>,
  pub not_after: Option<DateTime<Utc>>,
  pub user_agent: Option<String>,
  pub ip: Option<String>,
  pub refreshed_at: Option<chrono::NaiveDateTime>,
  pub created_at: Option<DateTime<Utc>>,
  pub updated_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct SessionAmrClaimRow {
  pub authentication_method: String,
  pub created_at: DateTime<Utc>,
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
