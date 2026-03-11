pub mod admin;
pub mod health;
pub mod logout;
pub mod otp;
pub mod recover;
pub mod resend;
pub mod settings;
pub mod signup;
pub mod token;
pub mod user;
pub mod verify;

use axum::http::StatusCode;
use axum::response::IntoResponse;

pub async fn not_found() -> impl IntoResponse {
    (StatusCode::NOT_FOUND, "Not found")
}
