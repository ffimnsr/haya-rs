use std::io::Cursor;

use passkey_crypto::CoseKey;
use passkey_crypto::coset::AsCborValue as _;
use passkey_types::ctap2::Flags;

use crate::RpError;

const BASE_LENGTH: usize = 37;
const MAX_AUTHENTICATOR_DATA_LENGTH: usize = 128 * 1024;
const MAX_CREDENTIAL_ID_LENGTH: usize = 1023;

pub(crate) struct AttestedCredential {
  pub aaguid: [u8; 16],
  pub credential_id: Vec<u8>,
  pub public_key: CoseKey,
  pub public_key_cose: Vec<u8>,
}

pub(crate) struct ParsedAuthenticatorData {
  pub rp_id_hash: [u8; 32],
  pub up: bool,
  pub uv: bool,
  pub be: bool,
  pub bs: bool,
  pub at: bool,
  #[allow(dead_code, reason = "parsed now for future signed-extension handling")]
  pub ed: bool,
  pub sign_count: u32,
  pub attested_credential: Option<AttestedCredential>,
}

pub(crate) fn parse(bytes: &[u8]) -> Result<ParsedAuthenticatorData, RpError> {
  if bytes.len() < BASE_LENGTH || bytes.len() > MAX_AUTHENTICATOR_DATA_LENGTH {
    return Err(RpError::InvalidAuthenticatorData);
  }
  let rp_id_hash = bytes[..32]
    .try_into()
    .map_err(|_| RpError::InvalidAuthenticatorData)?;
  let flags = Flags::from_bits(bytes[32]).ok_or(RpError::InvalidAuthenticatorData)?;
  if flags.contains(Flags::BS) && !flags.contains(Flags::BE) {
    return Err(RpError::InvalidAuthenticatorData);
  }
  let sign_count = u32::from_be_bytes(
    bytes[33..37]
      .try_into()
      .map_err(|_| RpError::InvalidAuthenticatorData)?,
  );

  let remaining = &bytes[BASE_LENGTH..];
  let mut cursor = Cursor::new(remaining);
  let attested_credential = if flags.contains(Flags::AT) {
    Some(parse_attested_credential(remaining, &mut cursor)?)
  } else {
    None
  };
  if flags.contains(Flags::ED) {
    let extension: ciborium::Value =
      ciborium::de::from_reader(&mut cursor).map_err(|_| RpError::InvalidAuthenticatorData)?;
    if !matches!(extension, ciborium::Value::Map(_)) {
      return Err(RpError::InvalidAuthenticatorData);
    }
  }
  if cursor.position() != remaining.len() as u64 {
    return Err(RpError::InvalidAuthenticatorData);
  }

  Ok(ParsedAuthenticatorData {
    rp_id_hash,
    up: flags.contains(Flags::UP),
    uv: flags.contains(Flags::UV),
    be: flags.contains(Flags::BE),
    bs: flags.contains(Flags::BS),
    at: flags.contains(Flags::AT),
    ed: flags.contains(Flags::ED),
    sign_count,
    attested_credential,
  })
}

fn parse_attested_credential(
  remaining: &[u8],
  cursor: &mut Cursor<&[u8]>,
) -> Result<AttestedCredential, RpError> {
  if remaining.len() < 18 {
    return Err(RpError::InvalidAuthenticatorData);
  }
  let aaguid = remaining[..16]
    .try_into()
    .map_err(|_| RpError::InvalidAuthenticatorData)?;
  let credential_id_length = u16::from_be_bytes(
    remaining[16..18]
      .try_into()
      .map_err(|_| RpError::InvalidAuthenticatorData)?,
  ) as usize;
  if credential_id_length == 0 || credential_id_length > MAX_CREDENTIAL_ID_LENGTH {
    return Err(RpError::InvalidAuthenticatorData);
  }
  let credential_end = 18usize
    .checked_add(credential_id_length)
    .ok_or(RpError::InvalidAuthenticatorData)?;
  if remaining.len() <= credential_end {
    return Err(RpError::InvalidAuthenticatorData);
  }
  let credential_id = remaining[18..credential_end].to_vec();
  cursor.set_position(credential_end as u64);
  let key_start = cursor.position() as usize;
  let key_value: ciborium::Value =
    ciborium::de::from_reader(&mut *cursor).map_err(|_| RpError::InvalidAuthenticatorData)?;
  let key_end = cursor.position() as usize;
  let public_key = CoseKey::from_cbor_value(key_value).map_err(|_| RpError::InvalidCredential)?;

  Ok(AttestedCredential {
    aaguid,
    credential_id,
    public_key,
    public_key_cose: remaining[key_start..key_end].to_vec(),
  })
}

#[cfg(test)]
mod tests {
  use std::panic::catch_unwind;

  use passkey_crypto::coset::{
    CborSerializable as _,
    CoseKeyBuilder,
  };
  use passkey_crypto::iana;

  use super::*;

  const AAGUID: [u8; 16] = [0xa5; 16];

  fn base(flags: Flags) -> Vec<u8> {
    let mut data = vec![0x11; 32];
    data.push(u8::from(flags));
    data.extend_from_slice(&0x0102_0304_u32.to_be_bytes());
    data
  }

  fn cose_key() -> Vec<u8> {
    CoseKeyBuilder::new_ec2_pub_key(iana::EllipticCurve::P_256, vec![1; 32], vec![2; 32])
      .algorithm(iana::Algorithm::ES256)
      .build()
      .to_vec()
      .unwrap()
  }

  fn with_attested_credential(flags: Flags, credential_id: &[u8]) -> Vec<u8> {
    let mut data = base(flags | Flags::AT);
    data.extend_from_slice(&AAGUID);
    data.extend_from_slice(&u16::try_from(credential_id.len()).unwrap().to_be_bytes());
    data.extend_from_slice(credential_id);
    data.extend_from_slice(&cose_key());
    data
  }

  #[test]
  fn parses_base_fields_and_false_flags() {
    let parsed = parse(&base(Flags::empty())).unwrap();

    assert_eq!(parsed.rp_id_hash, [0x11; 32]);
    assert_eq!(parsed.sign_count, 0x0102_0304);

    assert!(!parsed.up);
    assert!(!parsed.uv);
    assert!(!parsed.be);
    assert!(!parsed.bs);
    assert!(!parsed.at);
    assert!(!parsed.ed);
    assert!(parsed.attested_credential.is_none());
  }

  #[test]
  fn exposes_every_flag() {
    let flags = Flags::UP | Flags::UV | Flags::BE | Flags::BS | Flags::AT | Flags::ED;
    let mut data = with_attested_credential(flags, &[7, 8, 9]);
    data.push(0xa0);

    let parsed = parse(&data).unwrap();

    assert!(parsed.up);
    assert!(parsed.uv);
    assert!(parsed.be);
    assert!(parsed.bs);
    assert!(parsed.at);
    assert!(parsed.ed);
  }

  #[test]
  fn accepts_each_independent_flag_path() {
    for flag in [Flags::UP, Flags::UV, Flags::BE] {
      assert!(parse(&base(flag)).is_ok(), "flag {flag:?}");
    }
    assert!(parse(&base(Flags::BE | Flags::BS)).is_ok());
    assert!(parse(&with_attested_credential(Flags::empty(), &[1])).is_ok());

    let mut extension_data = base(Flags::ED);
    extension_data.push(0xa0);
    assert!(parse(&extension_data).is_ok());
  }

  #[test]
  fn rejects_unknown_flag_bits() {
    let mut data = base(Flags::empty());
    data[32] = 0x02;
    assert_eq!(parse(&data).map(|_| ()), Err(RpError::InvalidAuthenticatorData));
  }

  #[test]
  fn rejects_backup_state_without_backup_eligibility() {
    assert!(matches!(
      parse(&base(Flags::BS)),
      Err(RpError::InvalidAuthenticatorData)
    ));
  }

  #[test]
  fn parses_attested_credential() {
    let credential_id = [0x5c; 32];
    let expected_key = cose_key();
    let parsed = parse(&with_attested_credential(Flags::UP, &credential_id)).unwrap();
    let attested = parsed.attested_credential.unwrap();

    assert_eq!(attested.aaguid, AAGUID);
    assert_eq!(attested.credential_id, credential_id);
    assert_eq!(attested.public_key_cose, expected_key);
    assert!(!attested.public_key.params.is_empty());
  }

  #[test]
  fn parses_extension_map() {
    let mut data = base(Flags::ED);
    data.extend_from_slice(&[0xa1, 0x63, b'l', b'o', b'c', 0xf5]);

    let parsed = parse(&data).unwrap();

    assert!(parsed.ed);
    assert!(parsed.attested_credential.is_none());
  }

  #[test]
  fn rejects_malformed_or_non_map_extension() {
    for extension in [&[0xff][..], &[0x81, 0x01][..]] {
      let mut data = base(Flags::ED);
      data.extend_from_slice(extension);
      assert!(matches!(parse(&data), Err(RpError::InvalidAuthenticatorData)));
    }
  }

  #[test]
  fn rejects_inputs_shorter_than_base_fields() {
    for length in 0..BASE_LENGTH {
      assert!(matches!(
        parse(&vec![0; length]),
        Err(RpError::InvalidAuthenticatorData)
      ));
    }
  }

  #[test]
  fn rejects_every_truncation_of_valid_at_and_ed_data() {
    let mut complete = with_attested_credential(Flags::UP | Flags::UV | Flags::ED, &[0x44; 32]);
    complete.extend_from_slice(&[0xa1, 0x63, b'l', b'o', b'c', 0xf5]);
    assert!(parse(&complete).is_ok());

    for length in 0..complete.len() {
      assert!(
        matches!(parse(&complete[..length]), Err(RpError::InvalidAuthenticatorData)),
        "accepted truncation at byte {length} of {}",
        complete.len()
      );
    }
  }

  #[test]
  fn rejects_oversized_authenticator_data_before_parsing() {
    let oversized = vec![0; MAX_AUTHENTICATOR_DATA_LENGTH + 1];
    assert!(matches!(
      parse(&oversized),
      Err(RpError::InvalidAuthenticatorData)
    ));
  }

  #[test]
  fn rejects_truncated_aaguid_and_credential_length() {
    for payload_length in 0..18 {
      let mut data = base(Flags::AT);
      data.extend(std::iter::repeat_n(0, payload_length));
      assert!(matches!(parse(&data), Err(RpError::InvalidAuthenticatorData)));
    }
  }

  #[test]
  fn rejects_truncated_credential_id_and_key() {
    let mut truncated_id = base(Flags::AT);
    truncated_id.extend_from_slice(&AAGUID);
    truncated_id.extend_from_slice(&2_u16.to_be_bytes());
    truncated_id.push(1);
    assert!(matches!(
      parse(&truncated_id),
      Err(RpError::InvalidAuthenticatorData)
    ));

    let mut missing_key = base(Flags::AT);
    missing_key.extend_from_slice(&AAGUID);
    missing_key.extend_from_slice(&1_u16.to_be_bytes());
    missing_key.push(1);
    assert!(matches!(
      parse(&missing_key),
      Err(RpError::InvalidAuthenticatorData)
    ));

    let mut truncated_key = missing_key;
    truncated_key.push(0xa1);
    assert!(matches!(
      parse(&truncated_key),
      Err(RpError::InvalidAuthenticatorData)
    ));
  }

  #[test]
  fn rejects_zero_and_oversized_credential_ids() {
    let mut zero = base(Flags::AT);
    zero.extend_from_slice(&AAGUID);
    zero.extend_from_slice(&0_u16.to_be_bytes());
    zero.extend_from_slice(&cose_key());
    assert!(matches!(parse(&zero), Err(RpError::InvalidAuthenticatorData)));

    let oversized_id = vec![3; MAX_CREDENTIAL_ID_LENGTH + 1];
    assert!(matches!(
      parse(&with_attested_credential(Flags::empty(), &oversized_id)),
      Err(RpError::InvalidAuthenticatorData)
    ));
  }

  #[test]
  fn accepts_maximum_credential_id_length() {
    let credential_id = vec![4; MAX_CREDENTIAL_ID_LENGTH];
    let parsed = parse(&with_attested_credential(Flags::empty(), &credential_id)).unwrap();

    assert_eq!(parsed.attested_credential.unwrap().credential_id, credential_id);
  }

  #[test]
  fn rejects_trailing_data() {
    let mut base_trailing = base(Flags::empty());
    base_trailing.push(0);
    assert!(matches!(
      parse(&base_trailing),
      Err(RpError::InvalidAuthenticatorData)
    ));

    let mut attested_trailing = with_attested_credential(Flags::empty(), &[1]);
    attested_trailing.push(0);
    assert!(matches!(
      parse(&attested_trailing),
      Err(RpError::InvalidAuthenticatorData)
    ));

    let mut extension_trailing = base(Flags::ED);
    extension_trailing.extend_from_slice(&[0xa0, 0]);
    assert!(matches!(
      parse(&extension_trailing),
      Err(RpError::InvalidAuthenticatorData)
    ));
  }

  #[test]
  fn arbitrary_inputs_never_panic() {
    let mut state = 0x6a09_e667_f3bc_c909_u64;
    for case in 0..4_096_usize {
      state ^= state << 13;
      state ^= state >> 7;
      state ^= state << 17;
      let length = (state as usize) % 513;
      let mut data = Vec::with_capacity(length);
      for index in 0..length {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        data.push((state >> ((index % 8) * 8)) as u8);
      }

      assert!(catch_unwind(|| parse(&data)).is_ok(), "case {case}");
    }
  }
}
