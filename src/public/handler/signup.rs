use axum::{Json, extract::State};
use chrono::Utc;
use serde::Deserialize;
use uuid::Uuid;

use crate::{
    auth::password,
    error::{AuthError, Result},
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

    let user: User = sqlx::query_as::<_, User>(
        "INSERT INTO auth.users (id, instance_id, aud, role, email, encrypted_password, phone, raw_app_meta_data, raw_user_meta_data, is_anonymous, created_at, updated_at) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12) RETURNING id, instance_id, aud, role, email, encrypted_password, email_confirmed_at, phone, phone_confirmed_at, confirmed_at, last_sign_in_at, raw_app_meta_data, raw_user_meta_data, is_super_admin, is_anonymous, banned_until, created_at, updated_at"
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
    .bind(now)
    .bind(now)
    .fetch_one(&state.db)
    .await?;

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
