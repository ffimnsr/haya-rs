use passkey_crypto::hash::Sha256Backend;
use passkey_types::Bytes;
use passkey_types::webauthn::{
  ClientDataType,
  CollectedClientData,
};
use subtle::ConstantTimeEq as _;
use url::Url;

use crate::{
  PasskeyConfig,
  RpError,
};

const MAX_CLIENT_DATA_LEN: usize = 64 * 1024;

pub(crate) enum CeremonyType {
  Registration,
  Authentication,
}

pub(crate) struct ValidatedClientData<'a> {
  exact_bytes: &'a [u8],
}

impl ValidatedClientData<'_> {
  pub fn hash(&self) -> [u8; 32] {
    <passkey_crypto::AvailableSha2 as Sha256Backend>::sha256(self.exact_bytes)
  }
}

pub(crate) fn validate<'a>(
  bytes: &'a [u8],
  expected_challenge: &[u8],
  ceremony: CeremonyType,
  config: &PasskeyConfig,
) -> Result<ValidatedClientData<'a>, RpError> {
  if bytes.is_empty() || bytes.len() > MAX_CLIENT_DATA_LEN {
    return Err(RpError::InvalidClientData);
  }
  let client: CollectedClientData = serde_json::from_slice(bytes).map_err(|_| RpError::InvalidClientData)?;
  let expected_type = match ceremony {
    CeremonyType::Registration => ClientDataType::Create,
    CeremonyType::Authentication => ClientDataType::Get,
  };
  if client.ty != expected_type || client.cross_origin.unwrap_or(false) {
    return Err(RpError::InvalidClientData);
  }

  let challenge = Bytes::try_from(client.challenge.as_str()).map_err(|_| RpError::InvalidClientData)?;
  if challenge.len() != expected_challenge.len()
    || !bool::from(challenge.as_slice().ct_eq(expected_challenge))
  {
    return Err(RpError::InvalidClientData);
  }

  let origin = Url::parse(&client.origin).map_err(|_| RpError::InvalidClientData)?;
  if !config.origin_is_allowed(origin) {
    return Err(RpError::InvalidClientData);
  }

  Ok(ValidatedClientData { exact_bytes: bytes })
}

#[cfg(test)]
mod tests {
  use passkey_crypto::AvailableSha2;

  use super::*;

  const CHALLENGE: [u8; 32] = [0x11; 32];

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

  fn client_data(ty: &str, challenge: &str, origin: &str, cross_origin: bool) -> Vec<u8> {
    serde_json::to_vec(&serde_json::json!({
      "type": ty,
      "challenge": challenge,
      "origin": origin,
      "crossOrigin": cross_origin,
    }))
    .unwrap()
  }

  #[test]
  fn validates_registration_authentication_and_rejection_cases() {
    let expected_challenge = String::from(Bytes::from(CHALLENGE.as_slice()));
    let wrong_challenge = String::from(Bytes::from([0x22; 32].as_slice()));
    let cases = vec![
      (
        "registration",
        CeremonyType::Registration,
        client_data(
          "webauthn.create",
          &expected_challenge,
          "https://example.com",
          false,
        ),
        true,
      ),
      (
        "authentication",
        CeremonyType::Authentication,
        client_data("webauthn.get", &expected_challenge, "https://example.com", false),
        true,
      ),
      (
        "normalized explicit default port",
        CeremonyType::Authentication,
        client_data(
          "webauthn.get",
          &expected_challenge,
          "https://example.com:443",
          false,
        ),
        true,
      ),
      ("empty input", CeremonyType::Registration, Vec::new(), false),
      (
        "over 64 KiB",
        CeremonyType::Registration,
        vec![b' '; MAX_CLIENT_DATA_LEN + 1],
        false,
      ),
      (
        "malformed JSON",
        CeremonyType::Registration,
        br#"{"type":"webauthn.create""#.to_vec(),
        false,
      ),
      (
        "malformed base64url challenge",
        CeremonyType::Registration,
        client_data("webauthn.create", "***", "https://example.com", false),
        false,
      ),
      (
        "payment ceremony",
        CeremonyType::Authentication,
        client_data("payment.get", &expected_challenge, "https://example.com", false),
        false,
      ),
      (
        "unknown ceremony",
        CeremonyType::Registration,
        client_data(
          "webauthn.unknown",
          &expected_challenge,
          "https://example.com",
          false,
        ),
        false,
      ),
      (
        "registration type during authentication",
        CeremonyType::Authentication,
        client_data(
          "webauthn.create",
          &expected_challenge,
          "https://example.com",
          false,
        ),
        false,
      ),
      (
        "wrong challenge",
        CeremonyType::Registration,
        client_data("webauthn.create", &wrong_challenge, "https://example.com", false),
        false,
      ),
      (
        "wrong origin",
        CeremonyType::Registration,
        client_data(
          "webauthn.create",
          &expected_challenge,
          "https://evil.example.net",
          false,
        ),
        false,
      ),
      (
        "cross-origin",
        CeremonyType::Authentication,
        client_data("webauthn.get", &expected_challenge, "https://example.com", true),
        false,
      ),
    ];
    let config = config();

    for (name, ceremony, bytes, expected_valid) in cases {
      let result = validate(&bytes, &CHALLENGE, ceremony, &config);
      assert_eq!(result.is_ok(), expected_valid, "{name}");
    }
  }

  #[test]
  fn rejects_every_single_byte_challenge_mutation() {
    let config = config();
    for index in 0..CHALLENGE.len() {
      for replacement in u8::MIN..=u8::MAX {
        if replacement == CHALLENGE[index] {
          continue;
        }
        let mut mutated = CHALLENGE;
        mutated[index] = replacement;
        let encoded = String::from(Bytes::from(mutated.as_slice()));
        let bytes = client_data("webauthn.get", &encoded, "https://example.com", false);
        assert!(
          matches!(
            validate(&bytes, &CHALLENGE, CeremonyType::Authentication, &config),
            Err(RpError::InvalidClientData)
          ),
          "accepted challenge mutation at byte {index}: {replacement:#04x}"
        );
      }
    }
  }

  #[test]
  fn hashes_exact_client_data_bytes() {
    let challenge = String::from(Bytes::from(CHALLENGE.as_slice()));
    let bytes = format!(
      "{{\n  \"origin\": \"https://example.com:443\", \"challenge\": \"{challenge}\",\n  \"type\": \"webauthn.get\", \"crossOrigin\": false\n}}"
    )
    .into_bytes();

    let validated = validate(&bytes, &CHALLENGE, CeremonyType::Authentication, &config()).unwrap();

    assert_eq!(validated.exact_bytes, bytes);
    assert_eq!(validated.hash(), AvailableSha2::sha256(&bytes));
  }
}
