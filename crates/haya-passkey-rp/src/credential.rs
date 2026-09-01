use std::fmt;

use p256::ecdsa::VerifyingKey;
use passkey_crypto::coset::{
  CborSerializable as _,
  Label,
  RegisteredLabel,
  RegisteredLabelWithPrivate,
};
use passkey_crypto::{
  CoseKey,
  iana,
};
use passkey_types::webauthn::AuthenticatorTransport;
use serde::{
  Deserialize,
  Serialize,
};

use crate::RpError;

/// Public credential material persisted by the Haya application.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RpCredential {
  pub credential_id: Vec<u8>,
  pub user_handle: Vec<u8>,
  pub public_key_cose: Vec<u8>,
  pub algorithm: i64,
  pub sign_count: u32,
  pub aaguid: [u8; 16],
  pub transports: Vec<AuthenticatorTransport>,
  pub backup_eligible: bool,
  pub backup_state: bool,
}

impl RpCredential {
  /// Validate credential material loaded from storage.
  pub fn validate(&self) -> Result<(), RpError> {
    if !(1..=1023).contains(&self.credential_id.len())
      || !(1..=64).contains(&self.user_handle.len())
      || self.algorithm != -7
    {
      return Err(RpError::InvalidCredential);
    }
    parse_and_validate_public_key(&self.public_key_cose)?;
    Ok(())
  }
}

impl fmt::Debug for RpCredential {
  fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
    formatter
      .debug_struct("RpCredential")
      .field("credential_id", &"[redacted]")
      .field("user_handle", &"[redacted]")
      .field("public_key_cose", &"[redacted]")
      .field("algorithm", &self.algorithm)
      .field("sign_count", &self.sign_count)
      .field("aaguid", &self.aaguid)
      .field("transports", &self.transports)
      .field("backup_eligible", &self.backup_eligible)
      .field("backup_state", &self.backup_state)
      .finish()
  }
}

pub(crate) fn parse_and_validate_public_key(bytes: &[u8]) -> Result<VerifyingKey, RpError> {
  let key = CoseKey::from_slice(bytes).map_err(|_| RpError::InvalidCredential)?;
  validate_public_key(&key)
}

pub(crate) fn validate_public_key(key: &CoseKey) -> Result<VerifyingKey, RpError> {
  if key.kty != RegisteredLabel::Assigned(iana::KeyType::EC2)
    || key.alg != Some(RegisteredLabelWithPrivate::Assigned(iana::Algorithm::ES256))
    || !key.base_iv.is_empty()
  {
    return Err(RpError::InvalidCredential);
  }

  let mut curve_valid = false;
  let mut x = None;
  let mut y = None;
  for (label, value) in &key.params {
    let Label::Int(label) = label else {
      return Err(RpError::InvalidCredential);
    };
    match *label {
      label_value if label_value == iana::Ec2KeyParameter::Crv as i64 => {
        if curve_valid || value_as_i64(value) != Some(iana::EllipticCurve::P_256 as i64) {
          return Err(RpError::InvalidCredential);
        }
        curve_valid = true;
      },
      label_value if label_value == iana::Ec2KeyParameter::X as i64 => {
        if x
          .replace(value.as_bytes().ok_or(RpError::InvalidCredential)?)
          .is_some()
        {
          return Err(RpError::InvalidCredential);
        }
      },
      label_value if label_value == iana::Ec2KeyParameter::Y as i64 => {
        if y
          .replace(value.as_bytes().ok_or(RpError::InvalidCredential)?)
          .is_some()
        {
          return Err(RpError::InvalidCredential);
        }
      },
      _ => return Err(RpError::InvalidCredential),
    }
  }
  let (Some(x), Some(y)) = (x, y) else {
    return Err(RpError::InvalidCredential);
  };
  if !curve_valid || x.len() != 32 || y.len() != 32 {
    return Err(RpError::InvalidCredential);
  }

  let mut sec1 = [0u8; 65];
  sec1[0] = 0x04;
  sec1[1..33].copy_from_slice(x);
  sec1[33..].copy_from_slice(y);
  VerifyingKey::from_sec1_bytes(&sec1).map_err(|_| RpError::InvalidCredential)
}

fn value_as_i64(value: &ciborium::Value) -> Option<i64> {
  value.as_integer()?.try_into().ok()
}

#[cfg(test)]
mod tests {
  use p256::ecdsa::SigningKey;
  use passkey_crypto::coset::{
    CborSerializable as _,
    CoseKeyBuilder,
  };

  use super::*;

  fn credential() -> RpCredential {
    let signing_key = SigningKey::from_slice(&[1; 32]).unwrap();
    let point = signing_key.verifying_key().to_sec1_point(false);
    let public_key_cose = CoseKeyBuilder::new_ec2_pub_key(
      iana::EllipticCurve::P_256,
      point.x().unwrap().to_vec(),
      point.y().unwrap().to_vec(),
    )
    .algorithm(iana::Algorithm::ES256)
    .build()
    .to_vec()
    .unwrap();

    RpCredential {
      credential_id: vec![0xde, 0xad, 0xbe, 0xef],
      user_handle: vec![0xca, 0xfe, 0xba, 0xbe],
      public_key_cose,
      algorithm: -7,
      sign_count: 42,
      aaguid: [7; 16],
      transports: Vec::new(),
      backup_eligible: true,
      backup_state: false,
    }
  }

  #[test]
  fn validates_length_algorithm_and_public_key_constraints() {
    let valid = credential();
    let mut cases = Vec::new();

    cases.push((
      "minimum lengths",
      {
        let mut value = valid.clone();
        value.credential_id = vec![1];
        value.user_handle = vec![1];
        value
      },
      true,
    ));
    cases.push((
      "maximum lengths",
      {
        let mut value = valid.clone();
        value.credential_id = vec![1; 1023];
        value.user_handle = vec![1; 64];
        value
      },
      true,
    ));
    cases.push((
      "empty credential id",
      {
        let mut value = valid.clone();
        value.credential_id.clear();
        value
      },
      false,
    ));
    cases.push((
      "oversized credential id",
      {
        let mut value = valid.clone();
        value.credential_id = vec![1; 1024];
        value
      },
      false,
    ));
    cases.push((
      "empty user handle",
      {
        let mut value = valid.clone();
        value.user_handle.clear();
        value
      },
      false,
    ));
    cases.push((
      "oversized user handle",
      {
        let mut value = valid.clone();
        value.user_handle = vec![1; 65];
        value
      },
      false,
    ));
    cases.push((
      "non-ES256 algorithm",
      {
        let mut value = valid.clone();
        value.algorithm = -257;
        value
      },
      false,
    ));
    cases.push((
      "malformed COSE public key",
      {
        let mut value = valid;
        value.public_key_cose = vec![0xa0];
        value
      },
      false,
    ));

    for (name, value, expected_valid) in cases {
      assert_eq!(value.validate().is_ok(), expected_valid, "{name}");
    }
  }

  #[test]
  fn rejects_unsupported_or_private_cose_keys() {
    let valid = CoseKey::from_slice(&credential().public_key_cose).unwrap();

    let mut wrong_type = valid.clone();
    wrong_type.kty = RegisteredLabel::Assigned(iana::KeyType::RSA);
    assert_eq!(validate_public_key(&wrong_type), Err(RpError::InvalidCredential));

    let mut wrong_algorithm = valid.clone();
    wrong_algorithm.alg = Some(RegisteredLabelWithPrivate::Assigned(iana::Algorithm::RS256));
    assert_eq!(
      validate_public_key(&wrong_algorithm),
      Err(RpError::InvalidCredential)
    );

    let mut wrong_curve = valid.clone();
    wrong_curve.params[0].1 = ciborium::Value::from(iana::EllipticCurve::P_384 as i64);
    assert_eq!(validate_public_key(&wrong_curve), Err(RpError::InvalidCredential));

    let mut short_coordinate = valid.clone();
    short_coordinate.params[1].1 = ciborium::Value::Bytes(vec![1; 31]);
    assert_eq!(
      validate_public_key(&short_coordinate),
      Err(RpError::InvalidCredential)
    );

    let mut private_key = valid.clone();
    private_key.params.push((
      Label::Int(iana::Ec2KeyParameter::D as i64),
      ciborium::Value::Bytes(vec![1; 32]),
    ));
    assert_eq!(validate_public_key(&private_key), Err(RpError::InvalidCredential));

    let mut off_curve = valid;
    off_curve.params[1].1 = ciborium::Value::Bytes(vec![0; 32]);
    off_curve.params[2].1 = ciborium::Value::Bytes(vec![0; 32]);
    assert_eq!(validate_public_key(&off_curve), Err(RpError::InvalidCredential));
  }

  #[test]
  fn rejects_duplicate_missing_unknown_and_wrong_type_cose_parameters() {
    let valid = CoseKey::from_slice(&credential().public_key_cose).unwrap();

    for index in 0..3 {
      let mut duplicate = valid.clone();
      duplicate.params.push(duplicate.params[index].clone());
      assert_eq!(
        validate_public_key(&duplicate),
        Err(RpError::InvalidCredential),
        "duplicate parameter at index {index}"
      );
    }

    for index in 0..3 {
      let mut missing = valid.clone();
      missing.params.remove(index);
      assert_eq!(
        validate_public_key(&missing),
        Err(RpError::InvalidCredential),
        "missing parameter at index {index}"
      );
    }

    let mut unknown = valid.clone();
    unknown
      .params
      .push((Label::Int(-99), ciborium::Value::Bytes(vec![1])));
    assert_eq!(validate_public_key(&unknown), Err(RpError::InvalidCredential));

    let mut wrong_label_type = valid.clone();
    wrong_label_type.params[0].0 = Label::Text("curve".to_owned());
    assert_eq!(
      validate_public_key(&wrong_label_type),
      Err(RpError::InvalidCredential)
    );

    let mut wrong_value_type = valid;
    wrong_value_type.params[1].1 = ciborium::Value::Integer(1.into());
    assert_eq!(
      validate_public_key(&wrong_value_type),
      Err(RpError::InvalidCredential)
    );
  }

  #[test]
  fn serialization_roundtrip_preserves_credential() {
    let expected = credential();
    let serialized = serde_json::to_vec(&expected).unwrap();
    let actual: RpCredential = serde_json::from_slice(&serialized).unwrap();

    assert_eq!(actual, expected);
    assert!(actual.validate().is_ok());
  }

  #[test]
  fn debug_redacts_sensitive_material() {
    let value = credential();
    let credential_id = format!("{:?}", value.credential_id);
    let user_handle = format!("{:?}", value.user_handle);
    let public_key_cose = format!("{:?}", value.public_key_cose);
    let debug = format!("{value:?}");

    assert!(debug.contains("credential_id: \"[redacted]\""));
    assert!(debug.contains("user_handle: \"[redacted]\""));
    assert!(debug.contains("public_key_cose: \"[redacted]\""));
    assert!(!debug.contains(&credential_id));
    assert!(!debug.contains(&user_handle));
    assert!(!debug.contains(&public_key_cose));
  }
}
