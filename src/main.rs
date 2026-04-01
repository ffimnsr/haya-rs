mod auth;
mod db;
mod defaults;
mod error;
mod mailer;
mod middleware;
mod mime;
mod model;
mod public;
mod state;
mod utils;

use std::env;
use std::sync::Arc;

use crate::defaults::DEFAULT_DATABASE_URL;
use crate::mailer::{Mailer, MailerConfig};
use crate::state::AppState;
use tracing_subscriber::{layer::SubscriberExt as _, util::SubscriberInitExt as _};
use uuid::Uuid;

const APP_NAME: &str = env!("CARGO_PKG_NAME");

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    dotenvy::dotenv().ok();

    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| {
                format!("{}=debug,tower_http=debug,axum::rejection=trace", APP_NAME).into()
            }),
        )
        .with(tracing_subscriber::fmt::layer())
        .init();

    let db_url = env::var("DATABASE_URL")
        .or_else(|_| env::var("DEFAULT_DATABASE_URL"))
        .unwrap_or_else(|_| DEFAULT_DATABASE_URL.to_string());

    let db = db::init_pool(&db_url).await?;

    let jwt_secret = match env::var("JWT_SECRET") {
        Ok(secret) if secret.len() >= 32 => secret,
        Ok(secret) if secret.is_empty() => {
            anyhow::bail!("JWT_SECRET must not be empty");
        }
        Ok(_) => {
            anyhow::bail!("JWT_SECRET must be at least 32 characters long");
        }
        Err(_) => {
            if env::var("HAYA_DEV_MODE").is_ok() {
                let dev_secret = "super-secret-jwt-token-with-at-least-32-characters-long";
                tracing::warn!(
                    "⚠️  JWT_SECRET not set! Using insecure development secret. \
                     Set HAYA_DEV_MODE= to suppress this warning. \
                     NEVER use this configuration in production!"
                );
                dev_secret.to_string()
            } else {
                anyhow::bail!(
                    "JWT_SECRET environment variable is required. \
                     Set a strong secret of at least 32 characters. \
                     For development mode only, set HAYA_DEV_MODE=1 to use a default secret."
                );
            }
        }
    };

    let jwt_exp: i64 = env::var("JWT_EXPIRY")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(3600);

    let refresh_token_exp: i64 = env::var("REFRESH_TOKEN_EXPIRY")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(1_209_600);

    let site_url = env::var("SITE_URL").unwrap_or_else(|_| "http://localhost:9999".to_string());
    let site_name = env::var("SITE_NAME").unwrap_or_else(|_| "Haya".to_string());
    let issuer = env::var("GOTRUE_JWT_ISSUER")
        .or_else(|_| env::var("JWT_ISSUER"))
        .unwrap_or_else(|_| site_url.clone());

    let instance_id = env::var("INSTANCE_ID")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or_else(Uuid::new_v4);

    let mailer_autoconfirm = env::var("MAILER_AUTOCONFIRM")
        .map(|v| v.to_lowercase() == "true" || v == "1")
        .unwrap_or(false);

    let mailer: Option<Arc<Mailer>> = if let Ok(smtp_host) = env::var("SMTP_HOST") {
        let smtp_port: u16 = env::var("SMTP_PORT")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(587);
        let smtp_username = env::var("SMTP_USERNAME").unwrap_or_default();
        let smtp_password = env::var("SMTP_PASSWORD").unwrap_or_default();
        let smtp_tls = env::var("SMTP_TLS")
            .map(|v| v.to_lowercase() != "false" && v != "0")
            .unwrap_or(true);
        let smtp_from_email = env::var("SMTP_FROM_EMAIL")
            .unwrap_or_else(|_| "noreply@example.com".to_string());
        let smtp_from_name =
            env::var("SMTP_FROM_NAME").unwrap_or_else(|_| site_name.clone());
        let templates_dir = env::var("EMAIL_TEMPLATES_DIR")
            .unwrap_or_else(|_| "./templates/email".to_string());
        tracing::info!(%smtp_host, smtp_port, "Configuring SMTP mailer");
        match Mailer::new(MailerConfig {
            from_email: smtp_from_email,
            from_name: smtp_from_name,
            smtp_host,
            smtp_port,
            smtp_username,
            smtp_password,
            smtp_tls,
            templates_dir,
        }) {
            Ok(m) => {
                tracing::info!("SMTP mailer ready");
                Some(Arc::new(m))
            }
            Err(e) => {
                tracing::warn!(error = %e, "Failed to configure SMTP mailer; emails will not be sent");
                None
            }
        }
    } else {
        tracing::info!("SMTP_HOST not set; email sending is disabled");
        None
    };

    let state = AppState {
        db,
        jwt_secret,
        jwt_exp,
        refresh_token_exp,
        site_url,
        site_name,
        issuer,
        instance_id,
        mailer_autoconfirm,
        mailer,
    };

    let version = env!("CARGO_PKG_VERSION");
    println!("Booting up Haya Auth v{}", version);

    let port: u16 = env::var("PORT")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(9999);

    public::serve(port, state).await
}
