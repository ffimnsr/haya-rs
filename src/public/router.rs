use std::time::Duration;

use axum::routing::{get, post};
use axum::Router;
use tower_http::cors::CorsLayer;
use tower_http::timeout::TimeoutLayer;
use tower_http::trace::TraceLayer;

use super::handler;
use crate::state::AppState;

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
            "/admin/users/:id",
            get(handler::admin::admin_get_user)
                .put(handler::admin::admin_update_user)
                .delete(handler::admin::admin_delete_user),
        )
        .fallback(handler::not_found)
        .with_state(state)
        .layer(CorsLayer::permissive())
        .layer(TraceLayer::new_for_http())
        .layer(TimeoutLayer::new(Duration::from_secs(30)))
}
