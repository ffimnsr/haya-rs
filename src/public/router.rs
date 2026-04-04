use std::time::Duration;

use axum::Router;
use axum::http::{
  HeaderValue,
  Method,
};
use axum::routing::{
  get,
  post,
};
use tower_http::cors::{
  AllowOrigin,
  CorsLayer,
};
use tower_http::timeout::TimeoutLayer;
use tower_http::trace::TraceLayer;
use url::Url;

use super::handler;
use crate::state::AppState;

fn dev_mode_enabled() -> bool {
  std::env::var("HAYA_DEV_MODE")
    .map(|value| {
      let value = value.trim();
      value == "1" || value.eq_ignore_ascii_case("true")
    })
    .unwrap_or(false)
}

fn build_cors_layer() -> CorsLayer {
  let allowed_origins = std::env::var("CORS_ALLOWED_ORIGINS").unwrap_or_default();
  let origins: Vec<HeaderValue> = allowed_origins
    .split(',')
    .map(str::trim)
    .filter(|s| !s.is_empty())
    .filter_map(|s| s.parse::<HeaderValue>().ok())
    .collect();

  let allow_origin = if origins.is_empty() {
    if dev_mode_enabled() {
      // Development fallback: CORS is `*` when no explicit origins are configured.
      AllowOrigin::any()
    } else {
      AllowOrigin::list(default_cors_origins())
    }
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

fn default_cors_origins() -> Vec<HeaderValue> {
  let site_url = std::env::var("SITE_URL").unwrap_or_else(|_| "http://localhost:9999".to_string());
  cors_origin_from_url(&site_url)
    .or_else(|| cors_origin_from_url("http://localhost:9999"))
    .into_iter()
    .collect()
}

fn cors_origin_from_url(value: &str) -> Option<HeaderValue> {
  let url = Url::parse(value).ok()?;
  let host = url.host_str()?;
  let mut origin = format!("{}://{}", url.scheme(), host);
  if let Some(port) = url.port() {
    origin.push(':');
    origin.push_str(&port.to_string());
  }
  origin.parse::<HeaderValue>().ok()
}

pub fn create_router(state: AppState) -> Router {
  Router::new()
    .route("/health", get(handler::health::health_check))
    .route("/settings", get(handler::settings::get_settings))
    .route("/authorize", get(handler::sso::authorize))
    .route("/callback", get(handler::sso::callback))
    .route("/signup", post(handler::signup::signup))
    .route("/token", post(handler::token::token))
    .route("/verify", post(handler::verify::verify))
    .route("/recover", post(handler::recover::recover))
    .route("/reauthenticate", post(handler::reauthenticate::reauthenticate))
    .route("/resend", post(handler::resend::resend))
    .route("/magiclink", post(handler::otp::magiclink))
    .route("/otp", post(handler::otp::send_otp))
    .route(
      "/factors",
      get(handler::mfa::list_factors).post(handler::mfa::create_totp_factor),
    )
    .route("/mfa/factors", post(handler::mfa::list_pending_factors))
    .route("/factors/{id}/verify", post(handler::mfa::verify_totp_factor))
    .route(
      "/factors/{id}",
      axum::routing::delete(handler::mfa::delete_factor),
    )
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
