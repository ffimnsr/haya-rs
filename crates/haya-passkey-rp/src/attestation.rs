use std::io::Cursor;

use passkey_crypto::hash::Sha256Backend as _;
use passkey_crypto::rust_crypto::RustCryptoPublicKey;
use passkey_crypto::{
  AvailableSha2,
  PublicKeyT as _,
};

use passkey_types::webauthn::{
  CreatedPublicKeyCredential,
  PublicKeyCredentialType,
};
use subtle::ConstantTimeEq as _;

use crate::authenticator_data::parse;
use crate::client_data::{
  CeremonyType,
  validate,
};
use crate::credential::validate_public_key;
use crate::{
  PasskeyConfig,
  RegistrationState,
  RpCredential,
  RpError,
};

const MAX_ATTESTATION_OBJECT_LENGTH: usize = 128 * 1024;

pub(crate) fn verify(
  config: &PasskeyConfig,
  state: RegistrationState,
  credential: CreatedPublicKeyCredential,
) -> Result<RpCredential, RpError> {
  if credential.ty != PublicKeyCredentialType::PublicKey {
    return Err(RpError::InvalidCredential);
  }
  let response = credential.response;
  validate(
    response.client_data_json.as_slice(),
    &state.challenge,
    CeremonyType::Registration,
    config,
  )?;
  let authenticator_bytes = parse_attestation_object(response.attestation_object.as_slice())?;
  if response.authenticator_data.len() != authenticator_bytes.len()
    || !bool::from(
      response
        .authenticator_data
        .as_slice()
        .ct_eq(authenticator_bytes.as_slice()),
    )
  {
    return Err(RpError::InvalidAttestation);
  }

  let authenticator = parse(&authenticator_bytes)?;
  if !authenticator.up || !authenticator.uv || !authenticator.at {
    return Err(RpError::InvalidAuthenticatorData);
  }
  verify_rp_id_hash(config, &authenticator.rp_id_hash)?;
  let attested = authenticator
    .attested_credential
    .ok_or(RpError::InvalidAuthenticatorData)?;
  if credential.raw_id.len() != attested.credential_id.len()
    || !bool::from(credential.raw_id.as_slice().ct_eq(&attested.credential_id))
  {
    return Err(RpError::InvalidCredential);
  }
  validate_public_key(&attested.public_key)?;
  if response.public_key_algorithm != -7 {
    return Err(RpError::InvalidCredential);
  }
  if let Some(browser_public_key) = response.public_key {
    let expected =
      RustCryptoPublicKey::der_from_cose_key(&attested.public_key).map_err(|_| RpError::InvalidCredential)?;
    if browser_public_key.len() != expected.len()
      || !bool::from(browser_public_key.as_slice().ct_eq(&expected))
    {
      return Err(RpError::InvalidCredential);
    }
  }

  let credential = RpCredential {
    credential_id: attested.credential_id,
    user_handle: state.user_handle,
    public_key_cose: attested.public_key_cose,
    algorithm: -7,
    sign_count: authenticator.sign_count,
    aaguid: attested.aaguid,
    transports: response.transports.unwrap_or_default(),
    backup_eligible: authenticator.be,
    backup_state: authenticator.bs,
  };
  credential.validate()?;
  Ok(credential)
}

pub(crate) fn verify_rp_id_hash(
  config: &PasskeyConfig,
  authenticator_hash: &[u8; 32],
) -> Result<(), RpError> {
  let expected = AvailableSha2::sha256(config.rp_id.as_bytes());
  if bool::from(expected.ct_eq(authenticator_hash)) {
    Ok(())
  } else {
    Err(RpError::InvalidAuthenticatorData)
  }
}

fn parse_attestation_object(bytes: &[u8]) -> Result<Vec<u8>, RpError> {
  if bytes.is_empty() || bytes.len() > MAX_ATTESTATION_OBJECT_LENGTH {
    return Err(RpError::InvalidAttestation);
  }
  let mut cursor = Cursor::new(bytes);
  let value: ciborium::Value =
    ciborium::de::from_reader(&mut cursor).map_err(|_| RpError::InvalidAttestation)?;
  if cursor.position() != bytes.len() as u64 {
    return Err(RpError::InvalidAttestation);
  }
  let ciborium::Value::Map(entries) = value else {
    return Err(RpError::InvalidAttestation);
  };
  if entries.len() != 3 {
    return Err(RpError::InvalidAttestation);
  }

  let mut format = None;
  let mut statement = None;
  let mut authenticator_data = None;
  for (key, value) in entries {
    let ciborium::Value::Text(key) = key else {
      return Err(RpError::InvalidAttestation);
    };
    match key.as_str() {
      "fmt" if format.is_none() => format = value.as_text().map(ToOwned::to_owned),
      "attStmt" if statement.is_none() => statement = value.as_map().map(Vec::len),
      "authData" if authenticator_data.is_none() => authenticator_data = value.into_bytes().ok(),
      _ => return Err(RpError::InvalidAttestation),
    }
  }
  if format.as_deref() != Some("none") || statement != Some(0) {
    return Err(RpError::InvalidAttestation);
  }
  authenticator_data.ok_or(RpError::InvalidAttestation)
}

#[cfg(test)]
mod tests {
  use p256::ecdsa::SigningKey;
  use passkey_crypto::coset::{
    CborSerializable as _,
    CoseKeyBuilder,
  };
  use passkey_crypto::{
    PublicKeyT as _,
    iana,
  };
  use passkey_types::Bytes;
  use passkey_types::ctap2::Flags;
  use passkey_types::webauthn::{
    AuthenticationExtensionsClientOutputs,
    AuthenticatorAttestationResponse,
  };
  use url::Url;

  use super::*;

  fn config() -> PasskeyConfig {
    PasskeyConfig {
      rp_id: "example.com".to_owned(),
      rp_name: "Haya".to_owned(),
      origins: vec![Url::parse("https://example.com").unwrap()],
      challenge_ttl_secs: 300,
      allow_insecure_localhost: false,
    }
    .validate()
    .unwrap()
  }

  fn object(format: &str, statement: ciborium::Value, auth_data: ciborium::Value) -> Vec<u8> {
    encode(ciborium::Value::Map(vec![
      (
        ciborium::Value::Text("fmt".to_owned()),
        ciborium::Value::Text(format.to_owned()),
      ),
      (ciborium::Value::Text("attStmt".to_owned()), statement),
      (ciborium::Value::Text("authData".to_owned()), auth_data),
    ]))
  }

  fn encode(value: ciborium::Value) -> Vec<u8> {
    let mut bytes = Vec::new();
    ciborium::ser::into_writer(&value, &mut bytes).unwrap();
    bytes
  }

  #[test]
  fn verifies_rp_id_hash_exactly() {
    let expected = AvailableSha2::sha256(b"example.com");
    assert!(verify_rp_id_hash(&config(), &expected).is_ok());

    let wrong = AvailableSha2::sha256(b"example.net");
    assert_eq!(
      verify_rp_id_hash(&config(), &wrong),
      Err(RpError::InvalidAuthenticatorData)
    );

    let mut mutated = expected;
    mutated[17] ^= 1;
    assert_eq!(
      verify_rp_id_hash(&config(), &mutated),
      Err(RpError::InvalidAuthenticatorData)
    );
  }

  #[test]
  fn accepts_only_none_attestation_with_empty_statement() {
    let auth_data = vec![1, 2, 3];
    let valid = object(
      "none",
      ciborium::Value::Map(Vec::new()),
      ciborium::Value::Bytes(auth_data.clone()),
    );
    assert_eq!(parse_attestation_object(&valid), Ok(auth_data));

    for format in [
      "packed",
      "tpm",
      "android-key",
      "android-safetynet",
      "apple",
      "fido-u2f",
    ] {
      let bytes = object(
        format,
        ciborium::Value::Map(Vec::new()),
        ciborium::Value::Bytes(vec![1]),
      );
      assert_eq!(parse_attestation_object(&bytes), Err(RpError::InvalidAttestation));
    }

    let nonempty = object(
      "none",
      ciborium::Value::Map(vec![(ciborium::Value::Text("sig".to_owned()), 1.into())]),
      ciborium::Value::Bytes(vec![1]),
    );
    assert_eq!(
      parse_attestation_object(&nonempty),
      Err(RpError::InvalidAttestation)
    );
  }

  struct RegistrationCase {
    flags: Flags,
    rp_id: &'static str,
    raw_id: Vec<u8>,
    credential_type: PublicKeyCredentialType,
    browser_algorithm: i64,
    browser_public_key: Option<Vec<u8>>,
    cose_algorithm: iana::Algorithm,
    mismatch_reported_authenticator_data: bool,
  }

  impl Default for RegistrationCase {
    fn default() -> Self {
      Self {
        flags: Flags::UP | Flags::UV | Flags::AT,
        rp_id: "example.com",
        raw_id: vec![9; 32],
        credential_type: PublicKeyCredentialType::PublicKey,
        browser_algorithm: -7,
        browser_public_key: None,
        cose_algorithm: iana::Algorithm::ES256,
        mismatch_reported_authenticator_data: false,
      }
    }
  }

  fn verify_case(case: RegistrationCase) -> Result<RpCredential, RpError> {
    let signing_key = SigningKey::from_slice(&[1; 32]).unwrap();
    let point = signing_key.verifying_key().to_sec1_point(false);
    let cose_key = CoseKeyBuilder::new_ec2_pub_key(
      iana::EllipticCurve::P_256,
      point.x().unwrap().to_vec(),
      point.y().unwrap().to_vec(),
    )
    .algorithm(case.cose_algorithm)
    .build();
    let cose_bytes = cose_key.clone().to_vec().unwrap();
    let credential_id = vec![9; 32];
    let challenge = vec![0x11; 32];
    let client_data = serde_json::to_vec(&serde_json::json!({
      "type": "webauthn.create",
      "challenge": String::from(Bytes::from(challenge.clone())),
      "origin": "https://example.com",
      "crossOrigin": false,
    }))
    .unwrap();
    let mut authenticator_data = AvailableSha2::sha256(case.rp_id.as_bytes()).to_vec();
    authenticator_data.push(u8::from(case.flags));
    authenticator_data.extend_from_slice(&0_u32.to_be_bytes());
    if case.flags.contains(Flags::AT) {
      authenticator_data.extend_from_slice(&[0; 16]);
      authenticator_data.extend_from_slice(&32_u16.to_be_bytes());
      authenticator_data.extend_from_slice(&credential_id);
      authenticator_data.extend_from_slice(&cose_bytes);
    }
    if case.flags.contains(Flags::ED) {
      authenticator_data.push(0xa0);
    }
    let attestation_object = object(
      "none",
      ciborium::Value::Map(Vec::new()),
      ciborium::Value::Bytes(authenticator_data.clone()),
    );
    let mut reported_authenticator_data = authenticator_data;
    if case.mismatch_reported_authenticator_data {
      reported_authenticator_data[0] ^= 1;
    }
    let browser_public_key = case
      .browser_public_key
      .or_else(|| Some(RustCryptoPublicKey::der_from_cose_key(&cose_key).unwrap()));
    let credential = CreatedPublicKeyCredential {
      id: "ignored".to_owned(),
      raw_id: Bytes::from(case.raw_id),
      ty: case.credential_type,
      response: AuthenticatorAttestationResponse {
        client_data_json: Bytes::from(client_data),
        authenticator_data: Bytes::from(reported_authenticator_data),
        public_key: browser_public_key.map(Bytes::from),
        public_key_algorithm: case.browser_algorithm,
        attestation_object: Bytes::from(attestation_object),
        transports: None,
      },
      authenticator_attachment: None,
      client_extension_results: AuthenticationExtensionsClientOutputs::default(),
    };
    verify(
      &config(),
      RegistrationState {
        challenge,
        user_handle: vec![0x22; 32],
      },
      credential,
    )
  }

  #[test]
  fn validates_consistent_registration_and_rejects_untrusted_fields() {
    assert!(verify_case(RegistrationCase::default()).is_ok());

    for case in [
      RegistrationCase {
        credential_type: PublicKeyCredentialType::Unknown,
        ..RegistrationCase::default()
      },
      RegistrationCase {
        raw_id: vec![8; 32],
        ..RegistrationCase::default()
      },
      RegistrationCase {
        browser_algorithm: -257,
        ..RegistrationCase::default()
      },
      RegistrationCase {
        browser_public_key: Some(vec![1, 2, 3]),
        ..RegistrationCase::default()
      },
      RegistrationCase {
        browser_public_key: Some(Vec::new()),
        cose_algorithm: iana::Algorithm::RS256,
        ..RegistrationCase::default()
      },
    ] {
      assert_eq!(verify_case(case), Err(RpError::InvalidCredential));
    }
    assert_eq!(
      verify_case(RegistrationCase {
        mismatch_reported_authenticator_data: true,
        ..RegistrationCase::default()
      }),
      Err(RpError::InvalidAttestation)
    );
  }

  #[test]
  fn enforces_every_registration_flag_combination() {
    for up in [false, true] {
      for uv in [false, true] {
        for be in [false, true] {
          for bs in [false, true] {
            for at in [false, true] {
              for ed in [false, true] {
                let mut flags = Flags::empty();
                for (enabled, flag) in [
                  (up, Flags::UP),
                  (uv, Flags::UV),
                  (be, Flags::BE),
                  (bs, Flags::BS),
                  (at, Flags::AT),
                  (ed, Flags::ED),
                ] {
                  if enabled {
                    flags |= flag;
                  }
                }
                let result = verify_case(RegistrationCase {
                  flags,
                  ..RegistrationCase::default()
                });
                let expected_valid = up && uv && at && (!bs || be);
                assert_eq!(
                  result.is_ok(),
                  expected_valid,
                  "UP={up} UV={uv} BE={be} BS={bs} AT={at} ED={ed}"
                );
              }
            }
          }
        }
      }
    }
  }

  #[test]
  fn registration_requires_up_uv_at_and_matching_rp_hash() {
    for case in [
      RegistrationCase {
        flags: Flags::UV | Flags::AT,
        ..RegistrationCase::default()
      },
      RegistrationCase {
        flags: Flags::UP | Flags::AT,
        ..RegistrationCase::default()
      },
      RegistrationCase {
        flags: Flags::UP | Flags::UV,
        ..RegistrationCase::default()
      },
      RegistrationCase {
        rp_id: "example.net",
        ..RegistrationCase::default()
      },
    ] {
      assert_eq!(verify_case(case), Err(RpError::InvalidAuthenticatorData));
    }
  }

  #[test]
  fn rejects_malformed_or_inconsistent_attestation_objects() {
    let valid = object(
      "none",
      ciborium::Value::Map(Vec::new()),
      ciborium::Value::Bytes(vec![1]),
    );
    let mut trailing = valid.clone();
    trailing.push(0);

    let duplicate = encode(ciborium::Value::Map(vec![
      (
        ciborium::Value::Text("fmt".to_owned()),
        ciborium::Value::Text("none".to_owned()),
      ),
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
        ciborium::Value::Bytes(vec![1]),
      ),
    ]));
    let unknown = encode(ciborium::Value::Map(vec![
      (
        ciborium::Value::Text("fmt".to_owned()),
        ciborium::Value::Text("none".to_owned()),
      ),
      (
        ciborium::Value::Text("attStmt".to_owned()),
        ciborium::Value::Map(Vec::new()),
      ),
      (
        ciborium::Value::Text("other".to_owned()),
        ciborium::Value::Bytes(vec![1]),
      ),
    ]));

    for bytes in [
      Vec::new(),
      vec![0; MAX_ATTESTATION_OBJECT_LENGTH + 1],
      vec![0xff],
      encode(ciborium::Value::Array(Vec::new())),
      trailing,
      duplicate,
      unknown,
      object(
        "none",
        ciborium::Value::Map(Vec::new()),
        ciborium::Value::Text("not bytes".to_owned()),
      ),
    ] {
      assert_eq!(parse_attestation_object(&bytes), Err(RpError::InvalidAttestation));
    }
  }
}
