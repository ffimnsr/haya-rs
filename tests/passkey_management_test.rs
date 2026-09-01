mod support;

use argon2::password_hash::SaltString;
use argon2::password_hash::rand_core::OsRng;
use argon2::{
  Argon2,
  PasswordHasher,
};
use chrono::{
  Duration,
  Utc,
};
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
use sqlx::PgPool;
use uuid::Uuid;

use support::{
  cleanup_user,
  create_session,
  insert_user,
  issue_access_token,
  issue_access_token_with_aal,
  test_context,
  test_context_with_oidc_provider,
  test_context_without_passkeys,
  unique_suffix,
};

fn valid_es256_cose_key() -> Vec<u8> {
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

async fn insert_passkey(pool: &PgPool, user_id: Uuid, factor_id: Uuid, created_at: chrono::DateTime<Utc>) {
  let credential_id = factor_id.as_bytes().to_vec();
  let credential = serde_json::json!({
    "credential_id": credential_id,
    "user_handle": user_id.as_bytes(),
    "public_key_cose": valid_es256_cose_key(),
    "algorithm": -7,
    "sign_count": 0,
    "aaguid": vec![0; 16],
    "transports": [],
    "backup_eligible": false,
    "backup_state": false,
  });
  sqlx::query(
    "INSERT INTO auth.mfa_factors (id, user_id, friendly_name, factor_type, status, web_authn_credential_id, web_authn_credential, web_authn_aaguid, created_at, updated_at) VALUES ($1, $2, $3, 'webauthn'::auth.factor_type, 'verified'::auth.factor_status, $4, $5, $6, $7, $7)",
  )
  .bind(factor_id)
  .bind(user_id)
  .bind(format!("Passkey {factor_id}"))
  .bind(factor_id.as_bytes().as_slice())
  .bind(credential)
  .bind(Uuid::nil())
  .bind(created_at)
  .execute(pool)
  .await
  .unwrap();
}

async fn delete_passkey(ctx: &support::TestContext, token: &str, factor_id: Uuid) -> reqwest::Response {
  ctx
    .client
    .delete(format!("{}/passkeys/{factor_id}", ctx.base_url))
    .bearer_auth(token)
    .json(&serde_json::json!({}))
    .send()
    .await
    .unwrap()
}

#[tokio::test]
async fn disabled_settings_do_not_advertise_passkeys() {
  let Some(ctx) = test_context_without_passkeys().await else {
    return;
  };
  let email = format!("phase6-disabled-{}@example.com", unique_suffix());
  let user_id = insert_user(&ctx.pool, &email).await;
  sqlx::query("UPDATE auth.users SET role = 'supabase_admin' WHERE id = $1")
    .bind(user_id)
    .execute(&ctx.pool)
    .await
    .unwrap();
  let session_id = create_session(&ctx.pool, user_id).await;
  let token = issue_access_token(&ctx.issuer, &ctx.jwt_secret, user_id, session_id, &email);
  let settings = ctx
    .client
    .get(format!("{}/settings", ctx.base_url))
    .bearer_auth(&token)
    .send()
    .await
    .unwrap();
  assert_eq!(settings.status(), StatusCode::OK);
  let settings: serde_json::Value = settings.json().await.unwrap();
  assert_eq!(settings["external"]["passkey"], false);
  assert_eq!(settings["mfa"]["webauthn"], false);
  let passkeys = ctx
    .client
    .get(format!("{}/passkeys", ctx.base_url))
    .bearer_auth(&token)
    .send()
    .await
    .unwrap();
  assert_eq!(passkeys.status(), StatusCode::NOT_FOUND);
  cleanup_user(&ctx.pool, user_id).await;
}

#[tokio::test]
async fn passkey_management_lists_safely_deletes_and_revokes_authentication() {
  let Some(ctx) = test_context().await else {
    return;
  };
  let email = format!("phase6-manage-{}@example.com", unique_suffix());
  let user_id = insert_user(&ctx.pool, &email).await;
  let session_id = create_session(&ctx.pool, user_id).await;
  let token = issue_access_token(&ctx.issuer, &ctx.jwt_secret, user_id, session_id, &email);

  let options = ctx
    .client
    .post(format!("{}/passkeys/register/options", ctx.base_url))
    .bearer_auth(&token)
    .json(&serde_json::json!({ "friendlyName": "Managed passkey" }))
    .send()
    .await
    .unwrap();
  assert_eq!(options.status(), StatusCode::OK);
  let options_body: serde_json::Value = options.json().await.unwrap();
  let creation_options: CredentialCreationOptions =
    serde_json::from_value(options_body["options"].clone()).unwrap();
  let authenticator = Authenticator::new(
    Aaguid::new_empty(),
    None::<Passkey>,
    MockUserValidationMethod::verified_user(10),
    AvailableBackend,
  );
  let mut software_client = Client::new(authenticator);
  let credential = software_client
    .register(
      &url::Url::parse("http://localhost").unwrap(),
      creation_options,
      DefaultClientData,
    )
    .await
    .unwrap();
  let registered = ctx
    .client
    .post(format!("{}/passkeys/register/verify", ctx.base_url))
    .bearer_auth(&token)
    .json(&serde_json::json!({
      "flowId": options_body["flowId"],
      "credential": credential,
    }))
    .send()
    .await
    .unwrap();
  assert_eq!(registered.status(), StatusCode::OK);
  let registered_body: serde_json::Value = registered.json().await.unwrap();
  let managed_factor_id = Uuid::parse_str(registered_body["id"].as_str().unwrap()).unwrap();
  let second_factor_id = Uuid::new_v4();
  insert_passkey(
    &ctx.pool,
    user_id,
    second_factor_id,
    Utc::now() + Duration::seconds(1),
  )
  .await;

  let other_email = format!("phase6-other-{}@example.com", unique_suffix());
  let other_user_id = insert_user(&ctx.pool, &other_email).await;
  let other_session_id = create_session(&ctx.pool, other_user_id).await;
  let other_token = issue_access_token(
    &ctx.issuer,
    &ctx.jwt_secret,
    other_user_id,
    other_session_id,
    &other_email,
  );
  let other_factor_id = Uuid::new_v4();
  insert_passkey(&ctx.pool, other_user_id, other_factor_id, Utc::now()).await;

  let listed = ctx
    .client
    .get(format!("{}/passkeys", ctx.base_url))
    .bearer_auth(&token)
    .send()
    .await
    .unwrap();
  assert_eq!(listed.status(), StatusCode::OK);
  let factors: Vec<serde_json::Value> = listed.json().await.unwrap();
  assert_eq!(factors.len(), 2);
  assert_eq!(factors[0]["id"], managed_factor_id.to_string());
  assert_eq!(factors[1]["id"], second_factor_id.to_string());
  let serialized = serde_json::to_string(&factors).unwrap();
  for forbidden in [
    "credentialId",
    "publicKey",
    "signCount",
    "userHandle",
    "credential_id",
  ] {
    assert!(!serialized.contains(forbidden));
  }

  let generic = ctx
    .client
    .get(format!("{}/factors", ctx.base_url))
    .bearer_auth(&token)
    .send()
    .await
    .unwrap();
  assert_eq!(generic.status(), StatusCode::OK);
  let generic: Vec<serde_json::Value> = generic.json().await.unwrap();
  assert_eq!(
    generic
      .iter()
      .filter(|factor| factor["factor_type"] == "webauthn")
      .count(),
    2
  );
  assert!(!serde_json::to_string(&generic).unwrap().contains("credential"));

  let totp_verify = ctx
    .client
    .post(format!("{}/factors/{managed_factor_id}/verify", ctx.base_url))
    .bearer_auth(&token)
    .json(&serde_json::json!({ "code": "000000" }))
    .send()
    .await
    .unwrap();
  assert_eq!(totp_verify.status(), StatusCode::NOT_FOUND);
  let generic_delete = ctx
    .client
    .delete(format!("{}/factors/{managed_factor_id}", ctx.base_url))
    .bearer_auth(&token)
    .send()
    .await
    .unwrap();
  assert_eq!(generic_delete.status(), StatusCode::NOT_FOUND);
  let cross_user_delete = delete_passkey(&ctx, &other_token, managed_factor_id).await;
  assert_eq!(cross_user_delete.status(), StatusCode::NOT_FOUND);

  let aal1_token =
    issue_access_token_with_aal(&ctx.issuer, &ctx.jwt_secret, user_id, session_id, &email, "aal1");
  let stale = delete_passkey(&ctx, &aal1_token, managed_factor_id).await;
  assert_eq!(stale.status(), StatusCode::UNAUTHORIZED);

  let authentication_options = ctx
    .client
    .post(format!("{}/passkeys/authenticate/options", ctx.base_url))
    .json(&serde_json::json!({}))
    .send()
    .await
    .unwrap();
  let authentication_body: serde_json::Value = authentication_options.json().await.unwrap();
  let request_options: CredentialRequestOptions =
    serde_json::from_value(authentication_body["options"].clone()).unwrap();
  let assertion = software_client
    .authenticate(
      &url::Url::parse("http://localhost").unwrap(),
      request_options,
      DefaultClientData,
    )
    .await
    .unwrap();
  let login = ctx
    .client
    .post(format!("{}/token?grant_type=passkey", ctx.base_url))
    .json(&serde_json::json!({
      "flowId": authentication_body["flowId"],
      "credential": assertion,
    }))
    .send()
    .await
    .unwrap();
  assert_eq!(login.status(), StatusCode::OK);
  let factor_session_id: Uuid = sqlx::query_scalar("SELECT id FROM auth.sessions WHERE factor_id = $1")
    .bind(managed_factor_id)
    .fetch_one(&ctx.pool)
    .await
    .unwrap();
  let inconsistent_session_id = Uuid::new_v4();
  sqlx::query(
    "INSERT INTO auth.sessions (id, user_id, factor_id, aal, created_at, updated_at) VALUES ($1, $2, $3, 'aal2'::auth.aal_level, $4, $4)",
  )
  .bind(inconsistent_session_id)
  .bind(other_user_id)
  .bind(managed_factor_id)
  .bind(Utc::now())
  .execute(&ctx.pool)
  .await
  .unwrap();

  let deleted = delete_passkey(&ctx, &token, managed_factor_id).await;
  assert_eq!(deleted.status(), StatusCode::OK);
  for revoked_session_id in [factor_session_id, inconsistent_session_id] {
    assert!(
      !sqlx::query_scalar::<_, bool>("SELECT EXISTS(SELECT 1 FROM auth.sessions WHERE id = $1)")
        .bind(revoked_session_id)
        .fetch_one(&ctx.pool)
        .await
        .unwrap()
    );
  }

  let after_delete_options = ctx
    .client
    .post(format!("{}/passkeys/authenticate/options", ctx.base_url))
    .json(&serde_json::json!({}))
    .send()
    .await
    .unwrap();
  let after_delete_body: serde_json::Value = after_delete_options.json().await.unwrap();
  let request_options: CredentialRequestOptions =
    serde_json::from_value(after_delete_body["options"].clone()).unwrap();
  let deleted_assertion = software_client
    .authenticate(
      &url::Url::parse("http://localhost").unwrap(),
      request_options,
      DefaultClientData,
    )
    .await
    .unwrap();
  let rejected = ctx
    .client
    .post(format!("{}/token?grant_type=passkey", ctx.base_url))
    .json(&serde_json::json!({
      "flowId": after_delete_body["flowId"],
      "credential": deleted_assertion,
    }))
    .send()
    .await
    .unwrap();
  assert_eq!(rejected.status(), StatusCode::BAD_REQUEST);

  sqlx::query("UPDATE auth.users SET role = 'supabase_admin' WHERE id = $1")
    .bind(user_id)
    .execute(&ctx.pool)
    .await
    .unwrap();
  let settings = ctx
    .client
    .get(format!("{}/settings", ctx.base_url))
    .bearer_auth(&token)
    .send()
    .await
    .unwrap();
  assert_eq!(settings.status(), StatusCode::OK);
  let settings: serde_json::Value = settings.json().await.unwrap();
  assert_eq!(settings["external"]["passkey"], true);
  assert_eq!(settings["mfa"]["webauthn"], true);

  cleanup_user(&ctx.pool, user_id).await;
  cleanup_user(&ctx.pool, other_user_id).await;
}

#[tokio::test]
async fn final_sign_in_method_protection_covers_password_totp_passkeys_and_active_oidc() {
  let provider_name = format!("phase6-provider-{}", unique_suffix());
  let Some(ctx) = test_context_with_oidc_provider(Some(&provider_name)).await else {
    return;
  };

  let passkey_only_email = format!("phase6-only-{}@example.com", unique_suffix());
  let passkey_only_user = insert_user(&ctx.pool, &passkey_only_email).await;
  let passkey_only_session = create_session(&ctx.pool, passkey_only_user).await;
  let passkey_only_token = issue_access_token(
    &ctx.issuer,
    &ctx.jwt_secret,
    passkey_only_user,
    passkey_only_session,
    &passkey_only_email,
  );
  let only_factor = Uuid::new_v4();
  insert_passkey(&ctx.pool, passkey_only_user, only_factor, Utc::now()).await;
  sqlx::query(
    "INSERT INTO auth.mfa_factors (id, user_id, factor_type, status, secret, created_at, updated_at) VALUES ($1, $2, 'totp'::auth.factor_type, 'verified'::auth.factor_status, 'not-a-primary-method', $3, $3)",
  )
  .bind(Uuid::new_v4())
  .bind(passkey_only_user)
  .bind(Utc::now())
  .execute(&ctx.pool)
  .await
  .unwrap();
  let protected = delete_passkey(&ctx, &passkey_only_token, only_factor).await;
  assert_eq!(protected.status(), StatusCode::UNPROCESSABLE_ENTITY);

  let password_hash = Argon2::default()
    .hash_password(b"phase6-password", &SaltString::generate(&mut OsRng))
    .unwrap()
    .to_string();
  sqlx::query("UPDATE auth.users SET encrypted_password = $1 WHERE id = $2")
    .bind(password_hash)
    .bind(passkey_only_user)
    .execute(&ctx.pool)
    .await
    .unwrap();
  let passkey_only_aal1 = issue_access_token_with_aal(
    &ctx.issuer,
    &ctx.jwt_secret,
    passkey_only_user,
    passkey_only_session,
    &passkey_only_email,
    "aal1",
  );
  let password_reauthenticated = ctx
    .client
    .delete(format!("{}/passkeys/{only_factor}", ctx.base_url))
    .bearer_auth(&passkey_only_aal1)
    .json(&serde_json::json!({ "currentPassword": "phase6-password" }))
    .send()
    .await
    .unwrap();
  assert_eq!(password_reauthenticated.status(), StatusCode::OK);

  let two_email = format!("phase6-two-{}@example.com", unique_suffix());
  let two_user = insert_user(&ctx.pool, &two_email).await;
  let two_session = create_session(&ctx.pool, two_user).await;
  let two_token = issue_access_token(&ctx.issuer, &ctx.jwt_secret, two_user, two_session, &two_email);
  let first = Uuid::new_v4();
  let second = Uuid::new_v4();
  insert_passkey(&ctx.pool, two_user, first, Utc::now()).await;
  insert_passkey(&ctx.pool, two_user, second, Utc::now()).await;
  let delete_first = delete_passkey(&ctx, &two_token, first);
  let delete_second = delete_passkey(&ctx, &two_token, second);
  let (delete_first, delete_second) = tokio::join!(delete_first, delete_second);
  let statuses = [delete_first.status(), delete_second.status()];
  assert_eq!(statuses.iter().filter(|status| status.is_success()).count(), 1);
  assert_eq!(
    statuses
      .iter()
      .filter(|status| **status == StatusCode::UNPROCESSABLE_ENTITY)
      .count(),
    1
  );
  let remaining: i64 = sqlx::query_scalar(
    "SELECT COUNT(*) FROM auth.mfa_factors WHERE user_id = $1 AND factor_type = 'webauthn'::auth.factor_type",
  )
  .bind(two_user)
  .fetch_one(&ctx.pool)
  .await
  .unwrap();
  assert_eq!(remaining, 1);

  let oidc_email = format!("phase6-oidc-{}@example.com", unique_suffix());
  let oidc_user = insert_user(&ctx.pool, &oidc_email).await;
  let oidc_session = create_session(&ctx.pool, oidc_user).await;
  let oidc_token = issue_access_token(&ctx.issuer, &ctx.jwt_secret, oidc_user, oidc_session, &oidc_email);
  let oidc_factor = Uuid::new_v4();
  insert_passkey(&ctx.pool, oidc_user, oidc_factor, Utc::now()).await;
  sqlx::query(
    "INSERT INTO auth.identities (id, provider_id, user_id, identity_data, provider, created_at, updated_at) VALUES ($1, $2, $3, $4, $5, $6, $6)",
  )
  .bind(Uuid::new_v4())
  .bind(format!("subject-{}", unique_suffix()))
  .bind(oidc_user)
  .bind(serde_json::json!({ "email": oidc_email }))
  .bind(&provider_name)
  .bind(Utc::now())
  .execute(&ctx.pool)
  .await
  .unwrap();
  assert_eq!(
    delete_passkey(&ctx, &oidc_token, oidc_factor).await.status(),
    StatusCode::OK
  );

  let inactive_email = format!("phase6-inactive-oidc-{}@example.com", unique_suffix());
  let inactive_user = insert_user(&ctx.pool, &inactive_email).await;
  let inactive_session = create_session(&ctx.pool, inactive_user).await;
  let inactive_token = issue_access_token(
    &ctx.issuer,
    &ctx.jwt_secret,
    inactive_user,
    inactive_session,
    &inactive_email,
  );
  let inactive_factor = Uuid::new_v4();
  insert_passkey(&ctx.pool, inactive_user, inactive_factor, Utc::now()).await;
  sqlx::query(
    "INSERT INTO auth.identities (id, provider_id, user_id, identity_data, provider, created_at, updated_at) VALUES ($1, $2, $3, $4, $5, $6, $6)",
  )
  .bind(Uuid::new_v4())
  .bind(format!("subject-{}", unique_suffix()))
  .bind(inactive_user)
  .bind(serde_json::json!({ "email": inactive_email }))
  .bind(format!("inactive-{}", unique_suffix()))
  .bind(Utc::now())
  .execute(&ctx.pool)
  .await
  .unwrap();
  assert_eq!(
    delete_passkey(&ctx, &inactive_token, inactive_factor)
      .await
      .status(),
    StatusCode::UNPROCESSABLE_ENTITY
  );

  cleanup_user(&ctx.pool, passkey_only_user).await;
  cleanup_user(&ctx.pool, two_user).await;
  cleanup_user(&ctx.pool, oidc_user).await;
  cleanup_user(&ctx.pool, inactive_user).await;
}
