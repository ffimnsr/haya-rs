use aes_gcm::aead::{
  Aead,
  KeyInit,
};
use aes_gcm::{
  Aes256Gcm,
  Nonce,
};
use base32::Alphabet;
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use hmac::{
  Hmac,
  Mac,
};
use rand::RngCore;
use sha1::Sha1;
use sha2::{
  Digest,
  Sha256,
};
use url::Url;

use crate::error::AuthError;

const MFA_SECRET_BYTES: usize = 20;
const TOTP_PERIOD_SECS: i64 = 30;
const TOTP_DIGITS: u32 = 6;
const TOTP_SKEW_STEPS: i64 = 1;
const ENCRYPTION_VERSION: &str = "v1";

type HmacSha1 = Hmac<Sha1>;

pub fn derive_encryption_key(material: &str) -> [u8; 32] {
  let digest = Sha256::digest(material.as_bytes());
  let mut key = [0u8; 32];
  key.copy_from_slice(&digest);
  key
}

pub fn generate_totp_secret() -> Vec<u8> {
  let mut secret = vec![0u8; MFA_SECRET_BYTES];
  rand::rng().fill_bytes(&mut secret);
  secret
}

pub fn encode_secret(secret: &[u8]) -> String {
  base32::encode(Alphabet::Rfc4648 { padding: false }, secret)
}

pub fn encrypt_secret(secret: &[u8], key_material: &[u8; 32]) -> Result<String, AuthError> {
  let cipher = Aes256Gcm::new_from_slice(key_material)
    .map_err(|e| AuthError::InternalError(format!("failed to initialize MFA cipher: {e}")))?;
  let mut nonce_bytes = [0u8; 12];
  rand::rng().fill_bytes(&mut nonce_bytes);
  let ciphertext = cipher
    .encrypt(Nonce::from_slice(&nonce_bytes), secret)
    .map_err(|e| AuthError::InternalError(format!("failed to encrypt MFA secret: {e}")))?;

  Ok(format!(
    "{ENCRYPTION_VERSION}.{}.{}",
    URL_SAFE_NO_PAD.encode(nonce_bytes),
    URL_SAFE_NO_PAD.encode(ciphertext)
  ))
}

pub fn decrypt_secret(secret: &str, key_material: &[u8; 32]) -> Result<Vec<u8>, AuthError> {
  let mut parts = secret.split('.');
  let version = parts.next().ok_or_else(|| AuthError::InvalidToken)?;
  let nonce_b64 = parts.next().ok_or_else(|| AuthError::InvalidToken)?;
  let ciphertext_b64 = parts.next().ok_or_else(|| AuthError::InvalidToken)?;

  if version != ENCRYPTION_VERSION || parts.next().is_some() {
    return Err(AuthError::InvalidToken);
  }

  let nonce_bytes = URL_SAFE_NO_PAD
    .decode(nonce_b64)
    .map_err(|_| AuthError::InvalidToken)?;
  let ciphertext = URL_SAFE_NO_PAD
    .decode(ciphertext_b64)
    .map_err(|_| AuthError::InvalidToken)?;
  let cipher = Aes256Gcm::new_from_slice(key_material)
    .map_err(|e| AuthError::InternalError(format!("failed to initialize MFA cipher: {e}")))?;

  cipher
    .decrypt(Nonce::from_slice(&nonce_bytes), ciphertext.as_ref())
    .map_err(|_| AuthError::InvalidToken)
}

pub fn build_otpauth_url(issuer: &str, account_name: &str, secret_b32: &str) -> Result<String, AuthError> {
  let label = format!("{issuer}:{account_name}");
  let mut url = Url::parse(&format!("otpauth://totp/{label}"))
    .map_err(|e| AuthError::InternalError(format!("failed to build otpauth url: {e}")))?;
  url
    .query_pairs_mut()
    .append_pair("secret", secret_b32)
    .append_pair("issuer", issuer)
    .append_pair("algorithm", "SHA1")
    .append_pair("digits", &TOTP_DIGITS.to_string())
    .append_pair("period", &TOTP_PERIOD_SECS.to_string());
  Ok(url.to_string())
}

pub fn verify_code(secret: &[u8], code: &str, now: i64) -> Result<bool, AuthError> {
  let normalized = normalize_code(code)?;
  let counter = now.div_euclid(TOTP_PERIOD_SECS);

  for step in -TOTP_SKEW_STEPS..=TOTP_SKEW_STEPS {
    if generate_totp(secret, counter + step)? == normalized {
      return Ok(true);
    }
  }

  Ok(false)
}

fn normalize_code(code: &str) -> Result<u32, AuthError> {
  let trimmed = code.trim();
  if trimmed.len() != TOTP_DIGITS as usize || !trimmed.chars().all(|c| c.is_ascii_digit()) {
    return Err(AuthError::ValidationFailed(
      "TOTP code must be a 6-digit number".to_string(),
    ));
  }

  trimmed
    .parse::<u32>()
    .map_err(|_| AuthError::ValidationFailed("TOTP code must be numeric".to_string()))
}

fn generate_totp(secret: &[u8], counter: i64) -> Result<u32, AuthError> {
  let mut mac = <HmacSha1 as Mac>::new_from_slice(secret)
    .map_err(|e| AuthError::InternalError(format!("failed to initialize TOTP HMAC: {e}")))?;
  let mut msg = [0u8; 8];
  msg.copy_from_slice(&(counter as u64).to_be_bytes());
  mac.update(&msg);
  let result = mac.finalize().into_bytes();

  let offset = (result[19] & 0x0f) as usize;
  let binary = ((u32::from(result[offset]) & 0x7f) << 24)
    | (u32::from(result[offset + 1]) << 16)
    | (u32::from(result[offset + 2]) << 8)
    | u32::from(result[offset + 3]);

  Ok(binary % 10u32.pow(TOTP_DIGITS))
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn encryption_round_trip_preserves_secret() {
    let key = derive_encryption_key("test-material");
    let secret = generate_totp_secret();
    let encrypted = encrypt_secret(&secret, &key).unwrap();
    let decrypted = decrypt_secret(&encrypted, &key).unwrap();

    assert_eq!(secret, decrypted);
  }

  #[test]
  fn rfc_totp_vector_is_accepted() {
    let secret = b"12345678901234567890";
    assert!(verify_code(secret, "287082", 59).unwrap());
  }

  #[test]
  fn otpauth_url_contains_expected_fields() {
    let url = build_otpauth_url("Haya", "user@example.com", "JBSWY3DPEHPK3PXP").unwrap();

    assert!(url.starts_with("otpauth://totp/Haya:user@example.com?"));
    assert!(url.contains("secret=JBSWY3DPEHPK3PXP"));
    assert!(url.contains("issuer=Haya"));
    assert!(url.contains("algorithm=SHA1"));
  }
}
