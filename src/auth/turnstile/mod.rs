//! Optional Cloudflare Turnstile verification for public signup.
//!
//! Turnstile is enabled only when `TURNSTILE_SECRET_KEY` is configured. When
//! disabled, signup keeps its previous behavior. Verification is fail-closed:
//! network errors, timeouts, non-success HTTP responses, malformed payloads,
//! hostname mismatches, and action mismatches all deny the request.
//!
//! No token, secret, or remote IP is logged.

mod config;
mod verify;

#[cfg(test)]
mod tests;

pub use config::TurnstileConfig;
pub use verify::TurnstileError;
