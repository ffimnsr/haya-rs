use axum::Json;
use axum::extract::{
  ConnectInfo,
  State,
};
use chrono::Utc;
use serde::Deserialize;
use std::net::{
  IpAddr,
  SocketAddr,
};
use uuid::Uuid;

use crate::auth::{
  password,
  rate_limit,
  session,
};
use crate::error::{
  AuthError,
  Result,
};
use crate::mailer::EmailKind;
use crate::model::User;
use crate::public::handler::admin::validate_password_policy;
use crate::state::AppState;
use crate::utils::sha256_hex;

const SIGNUP_RATE_LIMIT_WINDOW_SECS: i64 = 900;
const SIGNUP_RATE_LIMIT_ATTEMPTS: u32 = 10;

#[derive(Debug, Deserialize)]
pub struct SignupRequest {
  pub email: Option<String>,
  pub password: Option<String>,
  pub phone: Option<String>,
  pub data: Option<serde_json::Value>,
}

pub async fn signup(
  State(state): State<AppState>,
  ConnectInfo(client_addr): ConnectInfo<SocketAddr>,
  Json(req): Json<SignupRequest>,
) -> Result<Json<serde_json::Value>> {
  let rate_limit_key = signup_ip_rate_limit_key(client_addr.ip());
  if rate_limit::is_limited(&state.db, &rate_limit_key, SIGNUP_RATE_LIMIT_ATTEMPTS).await? {
    return Err(AuthError::TooManyRequests);
  }
  rate_limit::record_attempt(&state.db, &rate_limit_key, SIGNUP_RATE_LIMIT_WINDOW_SECS).await?;

  if req.email.is_none() {
    return Err(AuthError::ValidationFailed("Email is required.".to_string()));
  }

  if let Some(ref email) = req.email
    && !is_valid_email(email)
  {
    return Err(AuthError::ValidationFailed("Invalid email format".to_string()));
  }
  if let Some(ref password) = req.password {
    validate_password_policy(password)?;
  }
  if req.password.is_none() && state.mailer.is_none() {
    return Err(AuthError::ValidationFailed(
      "Passwordless signups require SMTP to be configured.".to_string(),
    ));
  }
  if let Some(ref phone) = req.phone
    && !is_valid_e164_phone(phone)
  {
    return Err(AuthError::ValidationFailed(
      "Phone must be a valid E.164 number".to_string(),
    ));
  }

  if let Some(ref email) = req.email {
    let existing: Option<User> = sqlx::query_as::<_, User>(
            "SELECT id, instance_id, aud, role, email, encrypted_password, email_confirmed_at, phone, phone_confirmed_at, confirmed_at, last_sign_in_at, raw_app_meta_data, raw_user_meta_data, is_super_admin, is_sso_user, is_anonymous, banned_until, deleted_at, created_at, updated_at FROM auth.users WHERE email = $1"
        )
        .bind(email)
        .fetch_optional(&state.db)
        .await?;

    if existing.is_some() {
      password::burn_password_work(req.password.as_deref().unwrap_or("passwordless-signup-padding"))?;
      return Ok(Json(serde_json::json!({})));
    }
  }

  let user_id = Uuid::new_v4();
  let now = Utc::now();
  let hashed = if let Some(ref pw) = req.password {
    Some(password::hash_password(pw)?)
  } else {
    None
  };
  let user_metadata = req.data.unwrap_or(serde_json::json!({}));
  let app_metadata = serde_json::json!({"provider": "email", "providers": ["email"]});

  // Generate a confirmation token when auto-confirm is disabled.
  let (confirmation_token, confirmation_sent_at) = if !state.mailer_autoconfirm {
    (Some(session::generate_refresh_token()), Some(now))
  } else {
    (None, None)
  };
  let confirmation_token_hash = confirmation_token.as_deref().map(sha256_hex);

  let user: User = match sqlx::query_as::<_, User>(
        "INSERT INTO auth.users (id, instance_id, aud, role, email, encrypted_password, phone, raw_app_meta_data, raw_user_meta_data, is_anonymous, confirmation_token, confirmation_sent_at, created_at, updated_at) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14) RETURNING id, instance_id, aud, role, email, encrypted_password, email_confirmed_at, phone, phone_confirmed_at, confirmed_at, last_sign_in_at, raw_app_meta_data, raw_user_meta_data, is_super_admin, is_sso_user, is_anonymous, banned_until, deleted_at, created_at, updated_at"
    )
    .bind(user_id)
    .bind(state.instance_id)
    .bind("authenticated")
    .bind("authenticated")
    .bind(&req.email)
    .bind(hashed)
    .bind(&req.phone)
    .bind(&app_metadata)
    .bind(&user_metadata)
    .bind(false)
    .bind(&confirmation_token_hash)
    .bind(confirmation_sent_at)
    .bind(now)
    .bind(now)
    .fetch_one(&state.db)
    .await {
    Ok(user) => user,
    Err(sqlx::Error::Database(err)) if err.is_unique_violation() => {
      password::burn_password_work(req.password.as_deref().unwrap_or("passwordless-signup-padding"))?;
      return Ok(Json(serde_json::json!({})));
    },
    Err(err) => return Err(err.into()),
  };

  // Send confirmation email when auto-confirm is disabled.
  if let Some(ref token) = confirmation_token {
    let email = req.email.as_deref().unwrap_or_default();
    let confirmation_url = format!("{}/verify?token={}&type=signup", state.site_url, token);
    if let Some(ref mailer) = state.mailer {
      if let Err(e) = mailer
        .send(
          EmailKind::Confirmation,
          email,
          &[
            ("site_name", state.site_name.as_str()),
            ("confirmation_url", confirmation_url.as_str()),
            ("email", email),
          ],
        )
        .await
      {
        tracing::error!(error = %e, %email, "Failed to send confirmation email");
      }
    } else {
      tracing::warn!(%email, "SMTP not configured; confirmation email not sent");
    }
  }

  let _ = user;
  Ok(Json(serde_json::json!({})))
}

fn signup_ip_rate_limit_key(client_ip: IpAddr) -> String {
  format!("signup-ip:{client_ip}")
}

pub fn is_valid_email(email: &str) -> bool {
  // Basic but reasonable email validation: local@domain.tld
  let parts: Vec<&str> = email.splitn(2, '@').collect();
  if parts.len() != 2 {
    return false;
  }
  let local = parts[0];
  let domain = parts[1];
  !local.is_empty() && domain.contains('.') && !domain.starts_with('.') && !domain.ends_with('.')
}

pub fn is_valid_e164_phone(phone: &str) -> bool {
  let bytes = phone.as_bytes();
  if !(8..=16).contains(&bytes.len()) || bytes.first() != Some(&b'+') {
    return false;
  }

  match bytes.get(1) {
    Some(b'1'..=b'9') => {},
    _ => return false,
  }

  bytes[2..].iter().all(u8::is_ascii_digit)
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn test_valid_emails() {
    assert!(is_valid_email("user@example.com"));
    assert!(is_valid_email("user+tag@example.co.uk"));
    assert!(is_valid_email("first.last@domain.org"));
    assert!(is_valid_email("user@sub.domain.com"));
  }

  #[test]
  fn test_invalid_emails() {
    assert!(!is_valid_email("not-an-email"));
    assert!(!is_valid_email("@nodomain.com"));
    assert!(!is_valid_email("noatsign"));
    assert!(!is_valid_email("user@.domain.com"));
    assert!(!is_valid_email("user@domain."));
    assert!(!is_valid_email("user@nodot"));
    assert!(!is_valid_email(""));
  }

  #[test]
  fn test_valid_e164_phone_numbers() {
    assert!(is_valid_e164_phone("+15555550123"));
    assert!(is_valid_e164_phone("+639171234567"));
  }

  #[test]
  fn test_invalid_e164_phone_numbers() {
    assert!(!is_valid_e164_phone("15555550123"));
    assert!(!is_valid_e164_phone("+05555550123"));
    assert!(!is_valid_e164_phone("+1 555 555 0123"));
    assert!(!is_valid_e164_phone("+123"));
  }
}
