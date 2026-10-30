use std::sync::{
  Arc,
  Mutex,
};
use std::time::Duration;

use axum::extract::State;
use axum::routing::post;
use axum::{
  Json,
  Router,
};
use serde_json::json;
use tokio::net::TcpListener;

use super::verify::{
  DEFAULT_VERIFY_URL,
  MAX_TOKEN_BYTES,
};
use super::{
  TurnstileConfig,
  TurnstileError,
};

fn config(verify_url: String) -> TurnstileConfig {
  TurnstileConfig::new(
    "test-secret".to_string(),
    vec!["app.example.com".to_string()],
    Some("signup".to_string()),
    Some(verify_url),
    Duration::from_secs(2),
  )
  .expect("valid test config")
}

async fn mock_siteverify(response: serde_json::Value, received: Arc<Mutex<Option<String>>>) -> String {
  let listener = TcpListener::bind("127.0.0.1:0")
    .await
    .expect("bind mock siteverify");
  let address = listener.local_addr().expect("mock address");
  let app = Router::new()
    .route(
      "/verify",
      post(
        move |State(received): State<Arc<Mutex<Option<String>>>>, body: String| {
          let response = response.clone();
          async move {
            *received.lock().expect("received body lock") = Some(body);
            Json(response)
          }
        },
      ),
    )
    .with_state(received);
  tokio::spawn(async move {
    axum::serve(listener, app).await.expect("serve mock siteverify");
  });
  format!("http://{address}/verify")
}

#[tokio::test]
async fn accepts_valid_turnstile_response_and_posts_form_fields() {
  let received = Arc::new(Mutex::new(None));
  let url = mock_siteverify(
    json!({
      "success": true,
      "hostname": "app.example.com",
      "action": "signup"
    }),
    received.clone(),
  )
  .await;

  let result = config(url).verify(&reqwest::Client::new(), "token-value").await;

  assert_eq!(result, Ok(()));
  let body = received
    .lock()
    .expect("received body lock")
    .clone()
    .expect("siteverify request body");
  assert!(body.contains("secret=test-secret"));
  assert!(body.contains("response=token-value"));
}

#[tokio::test]
async fn rejects_failed_verification() {
  let received = Arc::new(Mutex::new(None));
  let url = mock_siteverify(
    json!({"success": false, "error-codes": ["invalid-input-response"]}),
    received,
  )
  .await;

  let result = config(url).verify(&reqwest::Client::new(), "token-value").await;

  assert_eq!(result, Err(TurnstileError::Rejected));
}

#[tokio::test]
async fn rejects_hostname_mismatch() {
  let received = Arc::new(Mutex::new(None));
  let url = mock_siteverify(
    json!({
      "success": true,
      "hostname": "evil.example.com",
      "action": "signup"
    }),
    received,
  )
  .await;

  let result = config(url).verify(&reqwest::Client::new(), "token-value").await;

  assert_eq!(result, Err(TurnstileError::Rejected));
}

#[tokio::test]
async fn rejects_action_mismatch() {
  let received = Arc::new(Mutex::new(None));
  let url = mock_siteverify(
    json!({
      "success": true,
      "hostname": "app.example.com",
      "action": "login"
    }),
    received,
  )
  .await;

  let result = config(url).verify(&reqwest::Client::new(), "token-value").await;

  assert_eq!(result, Err(TurnstileError::Rejected));
}

#[tokio::test]
async fn rejects_missing_hostname_when_hostnames_are_enforced() {
  let received = Arc::new(Mutex::new(None));
  let url = mock_siteverify(json!({"success": true}), received).await;

  let result = config(url).verify(&reqwest::Client::new(), "token-value").await;

  assert_eq!(result, Err(TurnstileError::Rejected));
}

#[tokio::test]
async fn reports_unavailable_on_http_failure() {
  let listener = TcpListener::bind("127.0.0.1:0")
    .await
    .expect("bind mock siteverify");
  let address = listener.local_addr().expect("mock address");
  let app = Router::new().route(
    "/verify",
    post(|| async { (axum::http::StatusCode::BAD_GATEWAY, "upstream failed") }),
  );
  tokio::spawn(async move {
    axum::serve(listener, app).await.expect("serve mock siteverify");
  });

  let result = config(format!("http://{address}/verify"))
    .verify(&reqwest::Client::new(), "token-value")
    .await;

  assert_eq!(result, Err(TurnstileError::Unavailable));
}

#[tokio::test]
async fn rejects_empty_or_oversized_tokens_without_calling_the_service() {
  let config = config(DEFAULT_VERIFY_URL.to_string());

  assert_eq!(
    config.verify(&reqwest::Client::new(), "  ").await,
    Err(TurnstileError::Rejected)
  );
  let oversized = "x".repeat(MAX_TOKEN_BYTES + 1);
  assert_eq!(
    config.verify(&reqwest::Client::new(), &oversized).await,
    Err(TurnstileError::Rejected)
  );
}

#[test]
fn rejects_insecure_verify_urls_except_loopback() {
  let error = TurnstileConfig::new(
    "secret".to_string(),
    vec!["app.example.com".to_string()],
    None,
    Some("http://siteverify.example.com/verify".to_string()),
    Duration::from_secs(5),
  )
  .expect_err("non-loopback HTTP must be rejected");

  assert!(error.to_string().contains("HTTPS"));
}

#[test]
fn requires_hostnames_when_enabled() {
  let error = TurnstileConfig::new(
    "secret".to_string(),
    Vec::new(),
    None,
    None,
    Duration::from_secs(5),
  )
  .expect_err("empty hostname list must be rejected");

  assert!(error.to_string().contains("TURNSTILE_ALLOWED_HOSTNAMES"));
}
