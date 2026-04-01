use std::time::Duration;

use axum::routing::{get, post};
use axum::Router;
use axum::http::{HeaderValue, Method};
use tower_http::cors::{AllowOrigin, CorsLayer};
use tower_http::timeout::TimeoutLayer;
use tower_http::trace::TraceLayer;

use super::handler;
use crate::state::AppState;

fn build_cors_layer() -> CorsLayer {
    let allowed_origins = std::env::var("CORS_ALLOWED_ORIGINS").unwrap_or_default();
    let origins: Vec<HeaderValue> = allowed_origins
        .split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .filter_map(|s| s.parse::<HeaderValue>().ok())
        .collect();

    let allow_origin = if origins.is_empty() {
        // Default: permissive only when no origins are configured
        // In production, CORS_ALLOWED_ORIGINS should be set explicitly
        AllowOrigin::any()
    } else {
        AllowOrigin::list(origins)
    };

    CorsLayer::new()
        .allow_origin(allow_origin)
        .allow_methods([
            Method::GET,
            Method::POST,
            Method::PUT,
            Method::DELETE,
            Method::OPTIONS,
        ])
        .allow_headers([
            axum::http::header::AUTHORIZATION,
            axum::http::header::CONTENT_TYPE,
            axum::http::header::ACCEPT,
        ])
        .allow_credentials(false)
        .max_age(Duration::from_secs(3600))
}

pub fn create_router(state: AppState) -> Router {
    Router::new()
        .route("/health", get(handler::health::health_check))
        .route("/settings", get(handler::settings::get_settings))
        .route("/signup", post(handler::signup::signup))
        .route("/token", post(handler::token::token))
        .route("/verify", post(handler::verify::verify))
        .route("/recover", post(handler::recover::recover))
        .route("/resend", post(handler::resend::resend))
        .route("/magiclink", post(handler::otp::magiclink))
        .route("/otp", post(handler::otp::send_otp))
        .route("/logout", post(handler::logout::logout))
        .route(
            "/user",
            get(handler::user::get_user).put(handler::user::update_user),
        )
        .route(
            "/admin/users",
            get(handler::admin::admin_list_users).post(handler::admin::admin_create_user),
        )
        .route(
            "/admin/users/{id}",
            get(handler::admin::admin_get_user)
                .put(handler::admin::admin_update_user)
                .delete(handler::admin::admin_delete_user),
        )
        .fallback(handler::not_found)
        .with_state(state)
        .layer(build_cors_layer())
        .layer(TraceLayer::new_for_http())
        .layer(TimeoutLayer::new(Duration::from_secs(30)))
}
