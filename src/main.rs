mod auth;
mod db;
mod defaults;
mod error;
mod middleware;
mod mime;
mod model;
mod public;
mod state;
mod utils;

use crate::defaults::DEFAULT_DATABASE_URL;
use crate::state::AppState;
use std::env;
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

    let jwt_secret = env::var("JWT_SECRET").unwrap_or_else(|_| {
        tracing::warn!("JWT_SECRET not set, using insecure default secret");
        "super-secret-jwt-token-with-at-least-32-characters-long".to_string()
    });

    let jwt_exp: i64 = env::var("JWT_EXPIRY")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(3600);

    let refresh_token_exp: i64 = env::var("REFRESH_TOKEN_EXPIRY")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(1_209_600);

    let site_url = env::var("SITE_URL").unwrap_or_else(|_| "http://localhost:9999".to_string());
    let issuer = env::var("GOTRUE_JWT_ISSUER")
        .or_else(|_| env::var("JWT_ISSUER"))
        .unwrap_or_else(|_| site_url.clone());

    let instance_id = env::var("INSTANCE_ID")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or_else(Uuid::new_v4);

    let state = AppState {
        db,
        jwt_secret,
        jwt_exp,
        refresh_token_exp,
        site_url,
        issuer,
        instance_id,
    };

    let version = env!("CARGO_PKG_VERSION");
    println!("Booting up Haya Auth v{}", version);

    let port: u16 = env::var("PORT")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(9999);

    public::serve(port, state).await
}
