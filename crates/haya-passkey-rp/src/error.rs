use thiserror::Error;

/// Errors produced while configuring or executing passkey ceremonies.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum RpError {
  #[error("the relying-party ID is invalid")]
  InvalidRpId,
  #[error("the relying-party display name must not be empty")]
  EmptyRpName,
  #[error("at least one relying-party origin is required")]
  EmptyOrigins,
  #[error("the relying-party origin is invalid: {0}")]
  InvalidOrigin(String),
  #[error("the challenge lifetime must be between 60 and 600 seconds")]
  InvalidChallengeTtl,
  #[error("the user handle must contain between 1 and 64 bytes")]
  InvalidUserHandle,
  #[error("the collected client data is invalid")]
  InvalidClientData,
  #[error("the authenticator data is invalid")]
  InvalidAuthenticatorData,
  #[error("the attestation object is invalid or unsupported")]
  InvalidAttestation,
  #[error("the public credential is invalid or unsupported")]
  InvalidCredential,
  #[error("the assertion signature is invalid")]
  InvalidSignature,
  #[error("the authenticator signature counter rolled back")]
  SignatureCounterRollback,
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn protocol_errors_keep_actionable_internal_categories() {
    let errors = [
      RpError::InvalidClientData,
      RpError::InvalidAuthenticatorData,
      RpError::InvalidAttestation,
      RpError::InvalidCredential,
      RpError::InvalidSignature,
      RpError::SignatureCounterRollback,
    ];
    let messages = errors.map(|error| error.to_string());

    assert!(messages.iter().all(|message| !message.is_empty()));
    for (index, message) in messages.iter().enumerate() {
      assert!(!messages[..index].contains(message));
    }
  }
}
