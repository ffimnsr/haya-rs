use axum::{Json, extract::State};
use serde_json::json;
use crate::error::Result;
use crate::state::AppState;

pub async fn get_settings(State(state): State<AppState>) -> Result<Json<serde_json::Value>> {
    Ok(Json(json!({
        "disable_signup": false,
        "mailer_autoconfirm": state.mailer_autoconfirm,
        "phone_autoconfirm": false,
        "sms_provider": "",
        "mfa_enabled": false,
        "saml_enabled": false,
        "external": {
            "apple": false,
            "azure": false,
            "bitbucket": false,
            "discord": false,
            "facebook": false,
            "figma": false,
            "fly": false,
            "github": false,
            "gitlab": false,
            "google": false,
            "kakao": false,
            "keycloak": false,
            "linkedin": false,
            "notion": false,
            "spotify": false,
            "slack": false,
            "twitch": false,
            "twitter": false,
            "workos": false,
            "zoom": false,
            "email": true,
            "phone": false
        }
    })))
}
