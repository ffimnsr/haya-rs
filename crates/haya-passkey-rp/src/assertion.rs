use p256::ecdsa::Signature;
use p256::ecdsa::signature::Verifier as _;

use passkey_types::webauthn::{
  AuthenticatedPublicKeyCredential,
  PublicKeyCredentialType,
};
use subtle::ConstantTimeEq as _;

use crate::attestation::verify_rp_id_hash;
use crate::authenticator_data::parse;
use crate::client_data::{
  CeremonyType,
  validate,
};
use crate::credential::parse_and_validate_public_key;
use crate::{
  AuthenticationResult,
  AuthenticationState,
  PasskeyConfig,
  RpCredential,
  RpError,
};

const MAX_ES256_DER_SIGNATURE_LENGTH: usize = 80;

pub(crate) fn verify(
  config: &PasskeyConfig,
  state: AuthenticationState,
  stored: &RpCredential,
  assertion: AuthenticatedPublicKeyCredential,
) -> Result<AuthenticationResult, RpError> {
  stored.validate()?;
  if assertion.ty != PublicKeyCredentialType::PublicKey
    || assertion.raw_id.len() != stored.credential_id.len()
    || !bool::from(assertion.raw_id.as_slice().ct_eq(&stored.credential_id))
  {
    return Err(RpError::InvalidCredential);
  }
  let response = assertion.response;
  if response.attestation_object.is_some() {
    return Err(RpError::InvalidAuthenticatorData);
  }
  let user_handle = response.user_handle.ok_or(RpError::InvalidCredential)?;
  if user_handle.len() != stored.user_handle.len()
    || !bool::from(user_handle.as_slice().ct_eq(&stored.user_handle))
  {
    return Err(RpError::InvalidCredential);
  }

  let client = validate(
    response.client_data_json.as_slice(),
    &state.challenge,
    CeremonyType::Authentication,
    config,
  )?;
  let authenticator = parse(response.authenticator_data.as_slice())?;
  if !authenticator.up
    || !authenticator.uv
    || authenticator.at
    || authenticator.attested_credential.is_some()
    || authenticator.be != stored.backup_eligible
  {
    return Err(RpError::InvalidAuthenticatorData);
  }
  verify_rp_id_hash(config, &authenticator.rp_id_hash)?;

  if response.signature.len() > MAX_ES256_DER_SIGNATURE_LENGTH {
    return Err(RpError::InvalidSignature);
  }
  let verifying_key = parse_and_validate_public_key(&stored.public_key_cose)?;
  let signature =
    Signature::from_der(response.signature.as_slice()).map_err(|_| RpError::InvalidSignature)?;
  let client_data_hash = client.hash();
  let mut signed = Vec::with_capacity(response.authenticator_data.len() + client_data_hash.len());
  signed.extend_from_slice(response.authenticator_data.as_slice());
  signed.extend_from_slice(&client_data_hash);
  verifying_key
    .verify(&signed, &signature)
    .map_err(|_| RpError::InvalidSignature)?;

  let sign_count = accepted_sign_count(stored.sign_count, authenticator.sign_count)?;
  Ok(AuthenticationResult {
    user_handle: stored.user_handle.clone(),
    sign_count,
    backup_state: authenticator.bs,
  })
}

fn accepted_sign_count(stored: u32, returned: u32) -> Result<u32, RpError> {
  if stored == 0 && returned == 0 {
    return Ok(0);
  }
  if returned > stored {
    return Ok(returned);
  }
  Err(RpError::SignatureCounterRollback)
}

#[cfg(test)]
mod tests {
  use p256::ecdsa::SigningKey;
  use p256::ecdsa::signature::Signer as _;
  use passkey_crypto::coset::{
    CborSerializable as _,
    CoseKeyBuilder,
  };
  use passkey_crypto::hash::Sha256Backend as _;
  use passkey_crypto::{
    AvailableSha2,
    iana,
  };
  use passkey_types::Bytes;
  use passkey_types::ctap2::Flags;
  use passkey_types::webauthn::{
    AuthenticationExtensionsClientOutputs,
    AuthenticatorAssertionResponse,
  };
  use url::Url;

  use super::*;

  const CHALLENGE: [u8; 32] = [0x11; 32];
  const CREDENTIAL_ID: [u8; 32] = [0x22; 32];
  const USER_HANDLE: [u8; 32] = [0x33; 32];

  struct Case {
    flags: Flags,
    returned_counter: u32,
    stored_counter: u32,
    user_handle: Option<Vec<u8>>,
    rp_id: &'static str,
    raw_id: Vec<u8>,
    credential_type: PublicKeyCredentialType,
    signing_key_byte: u8,
    signature_override: Option<Vec<u8>>,
    mutate_authenticator_after_signing: bool,
    sign_wrong_client_hash: bool,
    stored_algorithm: i64,
    stored_backup_eligible: bool,
  }

  impl Default for Case {
    fn default() -> Self {
      Self {
        flags: Flags::UP | Flags::UV,
        returned_counter: 0,
        stored_counter: 0,
        user_handle: Some(USER_HANDLE.to_vec()),
        rp_id: "example.com",
        raw_id: CREDENTIAL_ID.to_vec(),
        credential_type: PublicKeyCredentialType::PublicKey,
        signing_key_byte: 1,
        signature_override: None,
        mutate_authenticator_after_signing: false,
        sign_wrong_client_hash: false,
        stored_algorithm: -7,
        stored_backup_eligible: false,
      }
    }
  }

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

  fn run(case: Case) -> Result<AuthenticationResult, RpError> {
    let credential_key = SigningKey::from_slice(&[1; 32]).unwrap();
    let point = credential_key.verifying_key().to_sec1_point(false);
    let public_key_cose = CoseKeyBuilder::new_ec2_pub_key(
      iana::EllipticCurve::P_256,
      point.x().unwrap().to_vec(),
      point.y().unwrap().to_vec(),
    )
    .algorithm(iana::Algorithm::ES256)
    .build()
    .to_vec()
    .unwrap();
    let stored = RpCredential {
      credential_id: CREDENTIAL_ID.to_vec(),
      user_handle: USER_HANDLE.to_vec(),
      public_key_cose: public_key_cose.clone(),
      algorithm: case.stored_algorithm,
      sign_count: case.stored_counter,
      aaguid: [0; 16],
      transports: Vec::new(),
      backup_eligible: case.stored_backup_eligible,
      backup_state: false,
    };
    let client_data = serde_json::to_vec(&serde_json::json!({
      "type": "webauthn.get",
      "challenge": String::from(Bytes::from(CHALLENGE.as_slice())),
      "origin": "https://example.com",
      "crossOrigin": false,
    }))
    .unwrap();
    let mut authenticator_data = AvailableSha2::sha256(case.rp_id.as_bytes()).to_vec();
    authenticator_data.push(u8::from(case.flags));
    authenticator_data.extend_from_slice(&case.returned_counter.to_be_bytes());
    if case.flags.contains(Flags::AT) {
      authenticator_data.extend_from_slice(&[0; 16]);
      authenticator_data.extend_from_slice(&1_u16.to_be_bytes());
      authenticator_data.push(0x44);
      authenticator_data.extend_from_slice(&public_key_cose);
    }
    if case.flags.contains(Flags::ED) {
      authenticator_data.push(0xa0);
    }
    let mut signed = authenticator_data.clone();
    let client_hash = if case.sign_wrong_client_hash {
      AvailableSha2::sha256(b"different client data")
    } else {
      AvailableSha2::sha256(&client_data)
    };
    signed.extend_from_slice(&client_hash);
    let signing_key = SigningKey::from_slice(&[case.signing_key_byte; 32]).unwrap();
    let signature: p256::ecdsa::Signature = signing_key.sign(&signed);
    if case.mutate_authenticator_after_signing {
      authenticator_data[36] ^= 1;
    }
    let signature = case
      .signature_override
      .unwrap_or_else(|| signature.to_der().as_bytes().to_vec());
    let assertion = AuthenticatedPublicKeyCredential {
      id: "ignored".to_owned(),
      raw_id: Bytes::from(case.raw_id),
      ty: case.credential_type,
      response: AuthenticatorAssertionResponse {
        client_data_json: Bytes::from(client_data),
        authenticator_data: Bytes::from(authenticator_data),
        signature: Bytes::from(signature),
        user_handle: case.user_handle.map(Bytes::from),
        attestation_object: None,
      },
      authenticator_attachment: None,
      client_extension_results: AuthenticationExtensionsClientOutputs::default(),
    };

    verify(
      &config(),
      AuthenticationState {
        challenge: CHALLENGE.to_vec(),
      },
      &stored,
      assertion,
    )
  }

  #[test]
  fn counter_policy_accepts_counterless_and_increments() {
    assert_eq!(accepted_sign_count(0, 0), Ok(0));
    assert_eq!(accepted_sign_count(0, 1), Ok(1));
    assert_eq!(accepted_sign_count(7, 8), Ok(8));
    assert_eq!(run(Case::default()).unwrap().sign_count, 0);
    assert_eq!(
      run(Case {
        stored_counter: 7,
        returned_counter: 8,
        ..Case::default()
      })
      .unwrap()
      .sign_count,
      8
    );
  }

  #[test]
  fn counter_policy_rejects_rollbacks() {
    assert_eq!(accepted_sign_count(7, 7), Err(RpError::SignatureCounterRollback));
    assert_eq!(accepted_sign_count(7, 6), Err(RpError::SignatureCounterRollback));
    assert_eq!(
      run(Case {
        stored_counter: 7,
        returned_counter: 7,
        ..Case::default()
      }),
      Err(RpError::SignatureCounterRollback)
    );
  }

  #[test]
  fn rejects_credential_and_user_handle_mismatches() {
    for case in [
      Case {
        credential_type: PublicKeyCredentialType::Unknown,
        ..Case::default()
      },
      Case {
        raw_id: vec![9; 32],
        ..Case::default()
      },
      Case {
        user_handle: None,
        ..Case::default()
      },
      Case {
        user_handle: Some(vec![9; 32]),
        ..Case::default()
      },
      Case {
        stored_algorithm: -257,
        ..Case::default()
      },
    ] {
      assert_eq!(run(case), Err(RpError::InvalidCredential));
    }
  }

  #[test]
  fn enforces_every_assertion_flag_combination() {
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
                let result = run(Case {
                  flags,
                  stored_backup_eligible: be,
                  ..Case::default()
                });
                let expected_valid = up && uv && !at && (!bs || be);
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
  fn rejects_missing_flags_rp_mismatch_and_backup_inconsistency() {
    for case in [
      Case {
        flags: Flags::UV,
        ..Case::default()
      },
      Case {
        flags: Flags::UP,
        ..Case::default()
      },
      Case {
        rp_id: "example.net",
        ..Case::default()
      },
      Case {
        flags: Flags::UP | Flags::UV | Flags::BE,
        stored_backup_eligible: false,
        ..Case::default()
      },
    ] {
      assert_eq!(run(case), Err(RpError::InvalidAuthenticatorData));
    }
  }

  #[test]
  fn updates_validated_backup_state() {
    let result = run(Case {
      flags: Flags::UP | Flags::UV | Flags::BE | Flags::BS,
      stored_backup_eligible: true,
      ..Case::default()
    })
    .unwrap();
    assert!(result.backup_state);
  }

  #[test]
  fn rejects_wrong_signatures_and_changed_signed_data() {
    for case in [
      Case {
        signing_key_byte: 2,
        ..Case::default()
      },
      Case {
        mutate_authenticator_after_signing: true,
        ..Case::default()
      },
      Case {
        sign_wrong_client_hash: true,
        ..Case::default()
      },
      Case {
        signature_override: Some(vec![1, 2, 3]),
        ..Case::default()
      },
      Case {
        signature_override: Some(vec![0x30, 0x82, 0xff, 0xff]),
        ..Case::default()
      },
      Case {
        signature_override: Some(vec![0; MAX_ES256_DER_SIGNATURE_LENGTH + 1]),
        ..Case::default()
      },
    ] {
      assert!(matches!(run(case), Err(RpError::InvalidSignature)));
    }
  }
}
