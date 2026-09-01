//! Application-independent WebAuthn relying-party protocol primitives.

use std::fmt;

mod assertion;
mod attestation;
mod authenticator_data;
mod client_data;
mod config;
mod credential;
mod error;

use passkey_crypto::iana::Algorithm;
pub use passkey_types::Bytes;
use passkey_types::webauthn::{
  AttestationConveyancePreference,
  AuthenticatorSelectionCriteria,
  PublicKeyCredentialCreationOptions,
  PublicKeyCredentialParameters,
  PublicKeyCredentialRequestOptions,
  PublicKeyCredentialRpEntity,
  PublicKeyCredentialUserEntity,
  ResidentKeyRequirement,
  UserVerificationRequirement,
};
pub use passkey_types::webauthn::{
  AuthenticatedPublicKeyCredential,
  AuthenticatorTransport,
  CreatedPublicKeyCredential,
  CredentialCreationOptions,
  CredentialRequestOptions,
  PublicKeyCredentialDescriptor,
  PublicKeyCredentialType,
};
use rand::RngCore as _;
use serde::{
  Deserialize,
  Serialize,
};

pub use config::PasskeyConfig;
pub use credential::RpCredential;
pub use error::RpError;

const CHALLENGE_LENGTH: usize = 32;
const REDACTED: &str = "[redacted]";

/// A validated, immutable WebAuthn relying party.
#[derive(Debug, Clone)]
pub struct PasskeyRp {
  config: PasskeyConfig,
}

/// Account data needed to construct a registration request.
#[derive(Clone)]
pub struct RegistrationInput {
  pub user_handle: Vec<u8>,
  pub user_name: String,
  pub user_display_name: String,
  pub exclude_credentials: Vec<PublicKeyCredentialDescriptor>,
}

/// One-use protocol state that Haya persists for a registration ceremony.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RegistrationState {
  pub challenge: Vec<u8>,
  pub user_handle: Vec<u8>,
}

/// Registration options and state returned without performing persistence.
#[derive(Serialize)]
pub struct RegistrationStart {
  pub options: CredentialCreationOptions,
  pub state: RegistrationState,
  pub expires_in_secs: i64,
}

/// One-use protocol state that Haya persists for an authentication ceremony.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthenticationState {
  pub challenge: Vec<u8>,
}

/// Authentication options and state returned without performing persistence.
#[derive(Serialize)]
pub struct AuthenticationStart {
  pub options: CredentialRequestOptions,
  pub state: AuthenticationState,
  pub expires_in_secs: i64,
}

/// Verified changes that Haya applies to the stored credential transactionally.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthenticationResult {
  pub user_handle: Vec<u8>,
  pub sign_count: u32,
  pub backup_state: bool,
}

impl fmt::Debug for RegistrationInput {
  fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
    formatter
      .debug_struct("RegistrationInput")
      .field("user_handle", &REDACTED)
      .field("user_name", &REDACTED)
      .field("user_display_name", &REDACTED)
      .field("exclude_credentials", &REDACTED)
      .finish()
  }
}

impl fmt::Debug for RegistrationState {
  fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
    formatter
      .debug_struct("RegistrationState")
      .field("challenge", &REDACTED)
      .field("user_handle", &REDACTED)
      .finish()
  }
}

impl fmt::Debug for RegistrationStart {
  fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
    formatter
      .debug_struct("RegistrationStart")
      .field("options", &REDACTED)
      .field("state", &self.state)
      .field("expires_in_secs", &self.expires_in_secs)
      .finish()
  }
}

impl fmt::Debug for AuthenticationState {
  fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
    formatter
      .debug_struct("AuthenticationState")
      .field("challenge", &REDACTED)
      .finish()
  }
}

impl fmt::Debug for AuthenticationStart {
  fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
    formatter
      .debug_struct("AuthenticationStart")
      .field("options", &REDACTED)
      .field("state", &self.state)
      .field("expires_in_secs", &self.expires_in_secs)
      .finish()
  }
}

impl fmt::Debug for AuthenticationResult {
  fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
    formatter
      .debug_struct("AuthenticationResult")
      .field("user_handle", &REDACTED)
      .field("sign_count", &self.sign_count)
      .field("backup_state", &self.backup_state)
      .finish()
  }
}

impl PasskeyRp {
  /// Validate configuration and construct a relying party.
  pub fn new(config: PasskeyConfig) -> Result<Self, RpError> {
    Ok(Self {
      config: config.validate()?,
    })
  }

  /// Return the normalized immutable configuration.
  pub fn config(&self) -> &PasskeyConfig {
    &self.config
  }

  /// Construct ES256-only, discoverable registration options and serializable state.
  pub fn start_registration(&self, input: RegistrationInput) -> Result<RegistrationStart, RpError> {
    if input.user_handle.is_empty() || input.user_handle.len() > 64 {
      return Err(RpError::InvalidUserHandle);
    }
    let challenge = generate_challenge();
    let user_handle = input.user_handle.clone();
    let options = CredentialCreationOptions {
      public_key: PublicKeyCredentialCreationOptions {
        rp: PublicKeyCredentialRpEntity {
          id: Some(self.config.rp_id.clone()),
          name: self.config.rp_name.clone(),
        },
        user: PublicKeyCredentialUserEntity {
          id: Bytes::from(input.user_handle),
          display_name: input.user_display_name,
          name: input.user_name,
        },
        challenge: Bytes::from(challenge.as_slice()),
        pub_key_cred_params: vec![PublicKeyCredentialParameters {
          ty: PublicKeyCredentialType::PublicKey,
          alg: Algorithm::ES256,
        }],
        timeout: Some(timeout_millis(self.config.challenge_ttl_secs)),
        exclude_credentials: (!input.exclude_credentials.is_empty()).then_some(input.exclude_credentials),
        authenticator_selection: Some(AuthenticatorSelectionCriteria {
          authenticator_attachment: None,
          resident_key: Some(ResidentKeyRequirement::Required),
          require_resident_key: true,
          user_verification: UserVerificationRequirement::Required,
        }),
        hints: None,
        attestation: AttestationConveyancePreference::None,
        attestation_formats: None,
        extensions: None,
      },
    };

    Ok(RegistrationStart {
      options,
      state: RegistrationState {
        challenge,
        user_handle,
      },
      expires_in_secs: self.config.challenge_ttl_secs,
    })
  }

  /// Validate a browser registration response without database access.
  pub fn finish_registration(
    &self,
    state: RegistrationState,
    credential: CreatedPublicKeyCredential,
  ) -> Result<RpCredential, RpError> {
    attestation::verify(&self.config, state, credential)
  }

  /// Construct username-less authentication options and serializable state.
  pub fn start_authentication(&self) -> AuthenticationStart {
    let challenge = generate_challenge();
    let options = CredentialRequestOptions {
      public_key: PublicKeyCredentialRequestOptions {
        challenge: Bytes::from(challenge.as_slice()),
        timeout: Some(timeout_millis(self.config.challenge_ttl_secs)),
        rp_id: Some(self.config.rp_id.clone()),
        allow_credentials: None,
        user_verification: UserVerificationRequirement::Required,
        hints: None,
        attestation: AttestationConveyancePreference::None,
        attestation_formats: None,
        extensions: None,
      },
    };
    AuthenticationStart {
      options,
      state: AuthenticationState { challenge },
      expires_in_secs: self.config.challenge_ttl_secs,
    }
  }

  /// Validate a browser assertion without database access.
  pub fn finish_authentication(
    &self,
    state: AuthenticationState,
    stored_credential: &RpCredential,
    assertion: AuthenticatedPublicKeyCredential,
  ) -> Result<AuthenticationResult, RpError> {
    assertion::verify(&self.config, state, stored_credential, assertion)
  }
}

fn generate_challenge() -> Vec<u8> {
  let mut challenge = vec![0; CHALLENGE_LENGTH];
  rand::rng().fill_bytes(&mut challenge);
  challenge
}

fn timeout_millis(ttl_secs: i64) -> u32 {
  u32::try_from(ttl_secs * 1_000).expect("validated challenge TTL fits in u32")
}

#[cfg(test)]
mod tests {
  use p256::ecdsa::signature::Signer as _;
  use p256::ecdsa::{
    Signature,
    SigningKey,
  };

  use passkey_crypto::coset::{
    CborSerializable as _,
    CoseKeyBuilder,
  };
  use passkey_crypto::hash::Sha256Backend as _;
  use passkey_crypto::{
    AvailableSha2,
    iana,
  };
  use passkey_types::ctap2::Flags;
  use passkey_types::webauthn::{
    AuthenticatedPublicKeyCredential,
    AuthenticationExtensionsClientOutputs,
    AuthenticatorAssertionResponse,
    AuthenticatorAttestationResponse,
    CreatedPublicKeyCredential,
  };
  use url::Url;

  use super::*;

  fn rp() -> PasskeyRp {
    PasskeyRp::new(PasskeyConfig {
      rp_id: "example.com".to_owned(),
      rp_name: "Haya".to_owned(),
      origins: vec![Url::parse("https://app.example.com").unwrap()],
      challenge_ttl_secs: 300,
      allow_insecure_localhost: false,
    })
    .unwrap()
  }

  #[test]
  fn registration_options_enforce_initial_policy() {
    let excluded = PublicKeyCredentialDescriptor {
      ty: PublicKeyCredentialType::PublicKey,
      id: Bytes::from(vec![9; 16]),
      transports: None,
    };
    let start = rp()
      .start_registration(RegistrationInput {
        user_handle: vec![7; 32],
        user_name: "user@example.com".to_owned(),
        user_display_name: "User".to_owned(),
        exclude_credentials: vec![excluded.clone()],
      })
      .unwrap();

    assert_eq!(start.state.challenge.len(), CHALLENGE_LENGTH);
    assert_eq!(start.expires_in_secs, 300);
    assert_eq!(start.options.public_key.pub_key_cred_params.len(), 1);
    assert_eq!(
      start.options.public_key.pub_key_cred_params[0].alg,
      Algorithm::ES256
    );
    let selection = start.options.public_key.authenticator_selection.unwrap();
    assert_eq!(selection.resident_key, Some(ResidentKeyRequirement::Required));
    assert!(selection.require_resident_key);
    assert_eq!(selection.user_verification, UserVerificationRequirement::Required);
    assert_eq!(
      start.options.public_key.attestation,
      AttestationConveyancePreference::None
    );
    assert_eq!(start.options.public_key.exclude_credentials, Some(vec![excluded]));
  }

  #[test]
  fn registration_rejects_invalid_user_handle_lengths() {
    for user_handle in [Vec::new(), vec![1; 65]] {
      let result = rp().start_registration(RegistrationInput {
        user_handle,
        user_name: "user@example.com".to_owned(),
        user_display_name: "User".to_owned(),
        exclude_credentials: Vec::new(),
      });
      assert!(matches!(result, Err(RpError::InvalidUserHandle)));
    }
  }

  #[test]
  fn authentication_options_are_discoverable_and_require_verification() {
    let start = rp().start_authentication();
    assert_eq!(start.state.challenge.len(), CHALLENGE_LENGTH);
    assert!(start.options.public_key.allow_credentials.is_none());
    assert_eq!(
      start.options.public_key.user_verification,
      UserVerificationRequirement::Required
    );
  }

  #[test]
  fn challenges_are_fresh() {
    assert_ne!(
      rp().start_authentication().state.challenge,
      rp().start_authentication().state.challenge
    );
  }

  #[test]
  fn bytes_json_is_exact_unpadded_url_safe_base64() {
    let bytes = Bytes::from([0xfb, 0xff, 0xef, 0xff].as_slice());
    let json = serde_json::to_string(&bytes).unwrap();
    assert_eq!(json, r#""-__v_w""#);
    assert!(!json.contains(['+', '/', '=']));

    let decoded: Bytes = serde_json::from_str(&json).unwrap();
    assert_eq!(decoded, bytes);
  }

  #[test]
  fn ceremony_debug_output_redacts_protected_fields() {
    let input = RegistrationInput {
      user_handle: vec![0x71; 32],
      user_name: "debug-user@example.com".to_owned(),
      user_display_name: "Debug User".to_owned(),
      exclude_credentials: vec![PublicKeyCredentialDescriptor {
        ty: PublicKeyCredentialType::PublicKey,
        id: Bytes::from(vec![0x72; 16]),
        transports: None,
      }],
    };
    let input_debug = format!("{input:?}");
    assert!(input_debug.contains(REDACTED));
    assert!(!input_debug.contains("debug-user@example.com"));
    assert!(!input_debug.contains("Debug User"));
    assert!(!input_debug.contains(&format!("{:?}", input.user_handle)));

    let registration = rp().start_registration(input).unwrap();
    let challenge_debug = format!("{:?}", registration.state.challenge);
    let user_handle_debug = format!("{:?}", registration.state.user_handle);
    let registration_debug = format!("{registration:?}");
    assert!(registration_debug.contains("options: \"[redacted]\""));
    assert!(!registration_debug.contains("example.com"));
    assert!(!registration_debug.contains(&challenge_debug));
    assert!(!registration_debug.contains(&user_handle_debug));

    let authentication = rp().start_authentication();
    let challenge_debug = format!("{:?}", authentication.state.challenge);
    let authentication_debug = format!("{authentication:?}");
    assert!(authentication_debug.contains("options: \"[redacted]\""));
    assert!(!authentication_debug.contains("example.com"));
    assert!(!authentication_debug.contains(&challenge_debug));

    let result = AuthenticationResult {
      user_handle: vec![0x73; 32],
      sign_count: 7,
      backup_state: true,
    };
    let user_handle_debug = format!("{:?}", result.user_handle);
    let result_debug = format!("{result:?}");
    assert!(result_debug.contains("user_handle: \"[redacted]\""));
    assert!(!result_debug.contains(&user_handle_debug));
  }

  #[test]
  fn finish_registration_and_authentication_validate_a_complete_ceremony() {
    let rp = rp();
    let user_handle = vec![7; 32];
    let registration = rp
      .start_registration(RegistrationInput {
        user_handle: user_handle.clone(),
        user_name: "user@example.com".to_owned(),
        user_display_name: "User".to_owned(),
        exclude_credentials: Vec::new(),
      })
      .unwrap();
    let signing_key = SigningKey::from_slice(&[1; 32]).unwrap();
    let point = signing_key.verifying_key().to_sec1_point(false);
    let cose_key = CoseKeyBuilder::new_ec2_pub_key(
      iana::EllipticCurve::P_256,
      point.x().unwrap().to_vec(),
      point.y().unwrap().to_vec(),
    )
    .algorithm(iana::Algorithm::ES256)
    .build()
    .to_vec()
    .unwrap();
    let credential_id = vec![9; 32];
    let registration_authenticator_data = registration_authenticator_data(&credential_id, &cose_key);
    let registration_client_data = client_data("webauthn.create", &registration.state.challenge);
    let attestation_object = none_attestation_object(&registration_authenticator_data);
    let created = CreatedPublicKeyCredential {
      id: String::from(Bytes::from(credential_id.clone())),
      raw_id: Bytes::from(credential_id.clone()),
      ty: PublicKeyCredentialType::PublicKey,
      response: AuthenticatorAttestationResponse {
        client_data_json: Bytes::from(registration_client_data),
        authenticator_data: Bytes::from(registration_authenticator_data),
        public_key: None,
        public_key_algorithm: -7,
        attestation_object: Bytes::from(attestation_object),
        transports: None,
      },
      authenticator_attachment: None,
      client_extension_results: AuthenticationExtensionsClientOutputs::default(),
    };
    let stored = rp.finish_registration(registration.state, created).unwrap();
    assert_eq!(stored.credential_id, credential_id);
    assert_eq!(stored.user_handle, user_handle);

    let authentication = rp.start_authentication();
    let assertion_client_data = client_data("webauthn.get", &authentication.state.challenge);
    let assertion_authenticator_data = assertion_authenticator_data(1);
    let client_hash = AvailableSha2::sha256(&assertion_client_data);
    let mut signed = assertion_authenticator_data.clone();
    signed.extend_from_slice(&client_hash);
    let signature: Signature = signing_key.sign(&signed);
    let assertion = AuthenticatedPublicKeyCredential {
      id: String::from(Bytes::from(credential_id.clone())),
      raw_id: Bytes::from(credential_id),
      ty: PublicKeyCredentialType::PublicKey,
      response: AuthenticatorAssertionResponse {
        client_data_json: Bytes::from(assertion_client_data),
        authenticator_data: Bytes::from(assertion_authenticator_data),
        signature: Bytes::from(signature.to_der().as_bytes()),
        user_handle: Some(Bytes::from(user_handle.clone())),
        attestation_object: None,
      },
      authenticator_attachment: None,
      client_extension_results: AuthenticationExtensionsClientOutputs::default(),
    };
    let result = rp
      .finish_authentication(authentication.state, &stored, assertion)
      .unwrap();
    assert_eq!(result.user_handle, user_handle);
    assert_eq!(result.sign_count, 1);
  }

  fn client_data(ceremony_type: &str, challenge: &[u8]) -> Vec<u8> {
    serde_json::to_vec(&serde_json::json!({
      "type": ceremony_type,
      "challenge": String::from(Bytes::from(challenge)),
      "origin": "https://app.example.com",
      "crossOrigin": false
    }))
    .unwrap()
  }

  fn registration_authenticator_data(credential_id: &[u8], cose_key: &[u8]) -> Vec<u8> {
    let mut data = assertion_authenticator_data(0);
    data[32] = u8::from(Flags::UP | Flags::UV | Flags::AT);
    data.extend_from_slice(&[0; 16]);
    data.extend_from_slice(&u16::try_from(credential_id.len()).unwrap().to_be_bytes());
    data.extend_from_slice(credential_id);
    data.extend_from_slice(cose_key);
    data
  }

  fn assertion_authenticator_data(counter: u32) -> Vec<u8> {
    let mut data = AvailableSha2::sha256(b"example.com").to_vec();
    data.push(u8::from(Flags::UP | Flags::UV));
    data.extend_from_slice(&counter.to_be_bytes());
    data
  }

  fn none_attestation_object(authenticator_data: &[u8]) -> Vec<u8> {
    let value = ciborium::Value::Map(vec![
      (
        ciborium::Value::Text("fmt".to_owned()),
        ciborium::Value::Text("none".to_owned()),
      ),
      (
        ciborium::Value::Text("attStmt".to_owned()),
        ciborium::Value::Map(Vec::new()),
      ),
      (
        ciborium::Value::Text("authData".to_owned()),
        ciborium::Value::Bytes(authenticator_data.to_vec()),
      ),
    ]);
    let mut output = Vec::new();
    ciborium::ser::into_writer(&value, &mut output).unwrap();
    output
  }
}
