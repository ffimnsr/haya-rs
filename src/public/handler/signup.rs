use axum::{Json, extract::State};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use chrono::Utc;
use rand::RngCore;
use serde::Deserialize;
use uuid::Uuid;

use crate::{
    auth::password,
    error::{AuthError, Result},
    mailer::EmailKind,
    model::{User, UserResponse},
    state::AppState,
};

#[derive(Debug, Deserialize)]
pub struct SignupRequest {
    pub email: Option<String>,
    pub password: Option<String>,
    pub phone: Option<String>,
    pub data: Option<serde_json::Value>,
}

pub async fn signup(
    State(state): State<AppState>,
    Json(req): Json<SignupRequest>,
) -> Result<Json<UserResponse>> {
    if req.email.is_none() {
        return Err(AuthError::ValidationFailed(
            "Email is required.".to_string(),
        ));
    }

    if let Some(ref email) = req.email {
        if !is_valid_email(email) {
            return Err(AuthError::ValidationFailed("Invalid email format".to_string()));
        }
    }
    if let Some(ref password) = req.password {
        if password.len() < 6 {
            return Err(AuthError::ValidationFailed(
                "Password must be at least 6 characters.".to_string(),
            ));
        }
        if password.len() > 128 {
            return Err(AuthError::ValidationFailed(
                "Password must not exceed 128 characters.".to_string(),
            ));
        }
    }

    if let Some(ref email) = req.email {
        let existing: Option<User> = sqlx::query_as::<_, User>(
            "SELECT id, instance_id, aud, role, email, encrypted_password, email_confirmed_at, phone, phone_confirmed_at, confirmed_at, last_sign_in_at, raw_app_meta_data, raw_user_meta_data, is_super_admin, is_anonymous, banned_until, created_at, updated_at FROM auth.users WHERE email = $1"
        )
        .bind(email)
        .fetch_optional(&state.db)
        .await?;

        if existing.is_some() {
            return Err(AuthError::UserAlreadyExists);
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
        let mut bytes = [0u8; 32];
        rand::rng().fill_bytes(&mut bytes);
        (Some(URL_SAFE_NO_PAD.encode(bytes)), Some(now))
    } else {
        (None, None)
    };

    let user: User = sqlx::query_as::<_, User>(
        "INSERT INTO auth.users (id, instance_id, aud, role, email, encrypted_password, phone, raw_app_meta_data, raw_user_meta_data, is_anonymous, confirmation_token, confirmation_sent_at, created_at, updated_at) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14) RETURNING id, instance_id, aud, role, email, encrypted_password, email_confirmed_at, phone, phone_confirmed_at, confirmed_at, last_sign_in_at, raw_app_meta_data, raw_user_meta_data, is_super_admin, is_anonymous, banned_until, created_at, updated_at"
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
    .bind(&confirmation_token)
    .bind(confirmation_sent_at)
    .bind(now)
    .bind(now)
    .fetch_one(&state.db)
    .await?;

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

    Ok(Json(UserResponse::from(user)))
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
}
