mod support;

use argon2::password_hash::SaltString;
use argon2::password_hash::rand_core::OsRng;
use argon2::{
  Argon2,
  PasswordHasher,
};
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use chrono::Utc;
use passkey_authenticator::{
  Authenticator,
  MockUserValidationMethod,
};
use passkey_client::{
  Client,
  DefaultClientData,
};
use passkey_crypto::AvailableBackend;
use passkey_types::Passkey;
use passkey_types::ctap2::Aaguid;
use passkey_types::webauthn::{
  CredentialCreationOptions,
  CredentialRequestOptions,
};
use reqwest::StatusCode;
use uuid::Uuid;

use support::{
  cleanup_user,
  create_session,
  insert_user,
  issue_access_token,
  test_context,
  unique_suffix,
};

fn mutate_client_data(credential: &mut serde_json::Value, key: &str, value: serde_json::Value) {
  let encoded = credential["response"]["clientDataJSON"].as_str().unwrap();
  let mut client_data: serde_json::Value =
    serde_json::from_slice(&URL_SAFE_NO_PAD.decode(encoded).unwrap()).unwrap();
  client_data[key] = value;
  credential["response"]["clientDataJSON"] =
    serde_json::json!(URL_SAFE_NO_PAD.encode(serde_json::to_vec(&client_data).unwrap()));
}

fn mutate_authenticator_data(credential: &mut serde_json::Value, mutation: impl FnOnce(&mut [u8])) {
  let encoded = credential["response"]["authenticatorData"].as_str().unwrap();
  let mut authenticator_data = URL_SAFE_NO_PAD.decode(encoded).unwrap();
  mutation(&mut authenticator_data);
  credential["response"]["authenticatorData"] = serde_json::json!(URL_SAFE_NO_PAD.encode(authenticator_data));
}

fn known_wrong_es256_key() -> Vec<u8> {
  let x = [
    0x6b, 0x17, 0xd1, 0xf2, 0xe1, 0x2c, 0x42, 0x47, 0xf8, 0xbc, 0xe6, 0xe5, 0x63, 0xa4, 0x40, 0xf2, 0x77,
    0x03, 0x7d, 0x81, 0x2d, 0xeb, 0x33, 0xa0, 0xf4, 0xa1, 0x39, 0x45, 0xd8, 0x98, 0xc2, 0x96,
  ];
  let y = [
    0x4f, 0xe3, 0x42, 0xe2, 0xfe, 0x1a, 0x7f, 0x9b, 0x8e, 0xe7, 0xeb, 0x4a, 0x7c, 0x0f, 0x9e, 0x16, 0x2b,
    0xce, 0x33, 0x57, 0x6b, 0x31, 0x5e, 0xce, 0xcb, 0xb6, 0x40, 0x68, 0x37, 0xbf, 0x51, 0xf5,
  ];
  let mut key = vec![0xa5, 0x01, 0x02, 0x03, 0x26, 0x20, 0x01, 0x21, 0x58, 0x20];
  key.extend_from_slice(&x);
  key.extend_from_slice(&[0x22, 0x58, 0x20]);
  key.extend_from_slice(&y);
  key
}

#[tokio::test]
async fn password_flow_challenges_only_for_verified_totp_factors() {
  let Some(ctx) = test_context().await else {
    return;
  };
  let email = format!("phase5-totp-scope-{}@example.com", unique_suffix());
  let user_id = insert_user(&ctx.pool, &email).await;
  let password = "phase5-test-password";
  let hash = Argon2::default()
    .hash_password(password.as_bytes(), &SaltString::generate(&mut OsRng))
    .unwrap()
    .to_string();
  sqlx::query("UPDATE auth.users SET encrypted_password = $1 WHERE id = $2")
    .bind(hash)
    .bind(user_id)
    .execute(&ctx.pool)
    .await
    .unwrap();
  let now = Utc::now();
  sqlx::query(
    "INSERT INTO auth.mfa_factors (id, user_id, friendly_name, factor_type, status, web_authn_credential_id, web_authn_credential, web_authn_aaguid, created_at, updated_at) VALUES ($1, $2, 'Passkey', 'webauthn'::auth.factor_type, 'verified'::auth.factor_status, $3, $4, $5, $6, $6)",
  )
  .bind(Uuid::new_v4())
  .bind(user_id)
  .bind(vec![0x44; 32])
  .bind(serde_json::json!({"public_only": true}))
  .bind(Uuid::nil())
  .bind(now)
  .execute(&ctx.pool)
  .await
  .unwrap();

  let passkey_only = ctx
    .client
    .post(format!("{}/token?grant_type=password", ctx.base_url))
    .json(&serde_json::json!({ "email": email, "password": password }))
    .send()
    .await
    .unwrap();
  assert_eq!(passkey_only.status(), StatusCode::OK);
  let passkey_only_body: serde_json::Value = passkey_only.json().await.unwrap();
  assert!(passkey_only_body.get("access_token").is_some());
  assert!(passkey_only_body.get("mfa_token").is_none());

  sqlx::query(
    "INSERT INTO auth.mfa_factors (id, user_id, friendly_name, factor_type, status, secret, created_at, updated_at) VALUES ($1, $2, 'TOTP', 'totp'::auth.factor_type, 'verified'::auth.factor_status, 'test-secret', $3, $3)",
  )
  .bind(Uuid::new_v4())
  .bind(user_id)
  .bind(now)
  .execute(&ctx.pool)
  .await
  .unwrap();
  let totp = ctx
    .client
    .post(format!("{}/token?grant_type=password", ctx.base_url))
    .json(&serde_json::json!({ "email": email, "password": password }))
    .send()
    .await
    .unwrap();
  assert_eq!(totp.status(), StatusCode::OK);
  let totp_body: serde_json::Value = totp.json().await.unwrap();
  assert!(totp_body.get("access_token").is_none());
  assert!(totp_body.get("mfa_token").is_some());

  cleanup_user(&ctx.pool, user_id).await;
}

#[tokio::test]
async fn passkey_failures_reject_inactive_users_and_concurrent_replay() {
  let Some(ctx) = test_context().await else {
    return;
  };
  let email = format!("phase5-negative-{}@example.com", unique_suffix());
  let user_id = insert_user(&ctx.pool, &email).await;
  let enrollment_session_id = create_session(&ctx.pool, user_id).await;
  let enrollment_token = issue_access_token(
    &ctx.issuer,
    &ctx.jwt_secret,
    user_id,
    enrollment_session_id,
    &email,
  );

  let registration_options = ctx
    .client
    .post(format!("{}/passkeys/register/options", ctx.base_url))
    .bearer_auth(&enrollment_token)
    .json(&serde_json::json!({ "friendlyName": "Phase 5 passkey" }))
    .send()
    .await
    .unwrap();
  assert_eq!(registration_options.status(), StatusCode::OK);
  let registration_body: serde_json::Value = registration_options.json().await.unwrap();
  let creation_options: CredentialCreationOptions =
    serde_json::from_value(registration_body["options"].clone()).unwrap();
  let authenticator = Authenticator::new(
    Aaguid::new_empty(),
    None::<Passkey>,
    MockUserValidationMethod::verified_user(20),
    AvailableBackend,
  );
  let mut software_client = Client::new(authenticator);
  let registered = software_client
    .register(
      &url::Url::parse("http://localhost").unwrap(),
      creation_options,
      DefaultClientData,
    )
    .await
    .unwrap();
  let registration = ctx
    .client
    .post(format!("{}/passkeys/register/verify", ctx.base_url))
    .bearer_auth(&enrollment_token)
    .json(&serde_json::json!({
      "flowId": registration_body["flowId"],
      "credential": registered,
    }))
    .send()
    .await
    .unwrap();
  assert_eq!(registration.status(), StatusCode::OK);
  let factor: serde_json::Value = registration.json().await.unwrap();
  let factor_id = Uuid::parse_str(factor["id"].as_str().unwrap()).unwrap();

  let identity_input = ctx
    .client
    .post(format!("{}/passkeys/authenticate/options", ctx.base_url))
    .json(&serde_json::json!({ "email": email }))
    .send()
    .await
    .unwrap();
  assert_eq!(identity_input.status(), StatusCode::UNPROCESSABLE_ENTITY);

  macro_rules! fresh_assertion {
    () => {{
      let options = ctx
        .client
        .post(format!("{}/passkeys/authenticate/options", ctx.base_url))
        .json(&serde_json::json!({}))
        .send()
        .await
        .unwrap();
      assert_eq!(options.status(), StatusCode::OK);
      let body: serde_json::Value = options.json().await.unwrap();
      let request: CredentialRequestOptions = serde_json::from_value(body["options"].clone()).unwrap();
      let assertion = software_client
        .authenticate(
          &url::Url::parse("http://localhost").unwrap(),
          request,
          DefaultClientData,
        )
        .await
        .unwrap();
      (
        body["flowId"].as_str().unwrap().to_owned(),
        serde_json::to_value(assertion).unwrap(),
      )
    }};
  }

  async fn exchange(
    ctx: &support::TestContext,
    flow_id: &str,
    credential: &serde_json::Value,
  ) -> reqwest::Response {
    ctx
      .client
      .post(format!("{}/token?grant_type=passkey", ctx.base_url))
      .header(reqwest::header::USER_AGENT, "phase5-negative-test/1")
      .json(&serde_json::json!({
        "flowId": flow_id,
        "credential": credential,
      }))
      .send()
      .await
      .unwrap()
  }

  let (unknown_flow, mut unknown_credential) = fresh_assertion!();
  unknown_credential["rawId"] = serde_json::json!("AQ");
  unknown_credential["id"] = serde_json::json!("AQ");
  let unknown = exchange(&ctx, &unknown_flow, &unknown_credential).await;
  assert_eq!(unknown.status(), StatusCode::BAD_REQUEST);
  let unknown_error: serde_json::Value = unknown.json().await.unwrap();

  let (protocol_flow, base_assertion) = fresh_assertion!();
  let mut wrong_challenge = base_assertion.clone();
  mutate_client_data(&mut wrong_challenge, "challenge", serde_json::json!("AQ"));
  let mut wrong_origin = base_assertion.clone();
  mutate_client_data(
    &mut wrong_origin,
    "origin",
    serde_json::json!("https://wrong.example"),
  );
  let mut wrong_rp_id = base_assertion.clone();
  mutate_authenticator_data(&mut wrong_rp_id, |data| data[0] ^= 1);
  let mut missing_up = base_assertion.clone();
  mutate_authenticator_data(&mut missing_up, |data| data[32] &= !0x01);
  let mut missing_uv = base_assertion.clone();
  mutate_authenticator_data(&mut missing_uv, |data| data[32] &= !0x04);
  let mut missing_user_handle = base_assertion.clone();
  missing_user_handle["response"]["userHandle"] = serde_json::Value::Null;
  let mut wrong_user_handle = base_assertion.clone();
  wrong_user_handle["response"]["userHandle"] = serde_json::json!(URL_SAFE_NO_PAD.encode([0x77; 16]));
  let mut malformed_signature = base_assertion.clone();
  malformed_signature["response"]["signature"] = serde_json::json!("AQ");
  for invalid in [
    wrong_challenge,
    wrong_origin,
    wrong_rp_id,
    missing_up,
    missing_uv,
    missing_user_handle,
    wrong_user_handle,
    malformed_signature,
  ] {
    let response = exchange(&ctx, &protocol_flow, &invalid).await;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(response.json::<serde_json::Value>().await.unwrap(), unknown_error);
  }

  sqlx::query("DELETE FROM auth.rate_limits WHERE key = 'passkey-authenticate-verify:ip:127.0.0.1'")
    .execute(&ctx.pool)
    .await
    .unwrap();

  let (expired_flow, expired_assertion) = fresh_assertion!();
  sqlx::query("UPDATE auth.web_authn_flows SET expires_at = $1 WHERE id = $2")
    .bind(Utc::now() - chrono::Duration::seconds(1))
    .bind(Uuid::parse_str(&expired_flow).unwrap())
    .execute(&ctx.pool)
    .await
    .unwrap();
  let expired = exchange(&ctx, &expired_flow, &expired_assertion).await;
  assert_eq!(expired.status(), StatusCode::BAD_REQUEST);
  assert_eq!(expired.json::<serde_json::Value>().await.unwrap(), unknown_error);

  sqlx::query("UPDATE auth.users SET banned_until = $1 WHERE id = $2")
    .bind(Utc::now() + chrono::Duration::minutes(5))
    .bind(user_id)
    .execute(&ctx.pool)
    .await
    .unwrap();
  let (banned_flow, banned_assertion) = fresh_assertion!();
  let banned = exchange(&ctx, &banned_flow, &banned_assertion).await;
  assert_eq!(banned.status(), StatusCode::BAD_REQUEST);
  sqlx::query("UPDATE auth.users SET banned_until = NULL WHERE id = $1")
    .bind(user_id)
    .execute(&ctx.pool)
    .await
    .unwrap();

  sqlx::query("UPDATE auth.users SET deleted_at = $1 WHERE id = $2")
    .bind(Utc::now())
    .bind(user_id)
    .execute(&ctx.pool)
    .await
    .unwrap();
  let (deleted_flow, deleted_assertion) = fresh_assertion!();
  let deleted = exchange(&ctx, &deleted_flow, &deleted_assertion).await;
  assert_eq!(deleted.status(), StatusCode::BAD_REQUEST);
  sqlx::query("UPDATE auth.users SET deleted_at = NULL WHERE id = $1")
    .bind(user_id)
    .execute(&ctx.pool)
    .await
    .unwrap();

  let original_credential: serde_json::Value =
    sqlx::query_scalar("SELECT web_authn_credential FROM auth.mfa_factors WHERE id = $1")
      .bind(factor_id)
      .fetch_one(&ctx.pool)
      .await
      .unwrap();
  let mut wrong_key_credential = original_credential.clone();
  wrong_key_credential["public_key_cose"] = serde_json::json!(known_wrong_es256_key());
  sqlx::query("UPDATE auth.mfa_factors SET web_authn_credential = $1 WHERE id = $2")
    .bind(&wrong_key_credential)
    .bind(factor_id)
    .execute(&ctx.pool)
    .await
    .unwrap();
  let (wrong_key_flow, wrong_key_assertion) = fresh_assertion!();
  let wrong_key = exchange(&ctx, &wrong_key_flow, &wrong_key_assertion).await;
  assert_eq!(wrong_key.status(), StatusCode::BAD_REQUEST);
  assert_eq!(
    wrong_key.json::<serde_json::Value>().await.unwrap(),
    unknown_error
  );
  sqlx::query("UPDATE auth.mfa_factors SET web_authn_credential = $1 WHERE id = $2")
    .bind(&original_credential)
    .bind(factor_id)
    .execute(&ctx.pool)
    .await
    .unwrap();

  sqlx::query(
    "UPDATE auth.mfa_factors SET web_authn_credential = jsonb_set(web_authn_credential, '{sign_count}', '4294967295'::jsonb) WHERE id = $1",
  )
  .bind(factor_id)
  .execute(&ctx.pool)
  .await
  .unwrap();
  let (rollback_flow, rollback_assertion) = fresh_assertion!();
  let rollback = exchange(&ctx, &rollback_flow, &rollback_assertion).await;
  assert_eq!(rollback.status(), StatusCode::BAD_REQUEST);
  sqlx::query("UPDATE auth.mfa_factors SET web_authn_credential = $1 WHERE id = $2")
    .bind(original_credential)
    .bind(factor_id)
    .execute(&ctx.pool)
    .await
    .unwrap();

  let (concurrent_flow, concurrent_assertion) = fresh_assertion!();
  let first = exchange(&ctx, &concurrent_flow, &concurrent_assertion);
  let second = exchange(&ctx, &concurrent_flow, &concurrent_assertion);
  let (first, second) = tokio::join!(first, second);
  let statuses = [first.status(), second.status()];
  assert_eq!(statuses.iter().filter(|status| status.is_success()).count(), 1);
  assert_eq!(
    statuses
      .iter()
      .filter(|status| **status == StatusCode::BAD_REQUEST)
      .count(),
    1
  );
  let session_count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM auth.sessions WHERE factor_id = $1")
    .bind(factor_id)
    .fetch_one(&ctx.pool)
    .await
    .unwrap();
  assert_eq!(session_count, 1);

  cleanup_user(&ctx.pool, user_id).await;
}
