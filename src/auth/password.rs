use crate::error::AuthError;
use argon2::password_hash::SaltString;
use argon2::password_hash::rand_core::OsRng;
use argon2::{
  Argon2,
  PasswordHash,
  PasswordHasher,
  PasswordVerifier,
};

pub fn hash_password(password: &str) -> Result<String, AuthError> {
  let salt = SaltString::generate(&mut OsRng);
  let argon2 = Argon2::default();
  argon2
    .hash_password(password.as_bytes(), &salt)
    .map(|h| h.to_string())
    .map_err(|e| AuthError::InternalError(e.to_string()))
}

pub fn verify_password(password: &str, hash: &str) -> Result<bool, AuthError> {
  let parsed = PasswordHash::new(hash).map_err(|e| AuthError::InternalError(e.to_string()))?;
  Ok(
    Argon2::default()
      .verify_password(password.as_bytes(), &parsed)
      .is_ok(),
  )
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn test_hash_and_verify_password() {
    let password = "super-secret-password";
    let hash = hash_password(password).unwrap();
    assert!(verify_password(password, &hash).unwrap());
    assert!(!verify_password("wrong-password", &hash).unwrap());
  }
}
