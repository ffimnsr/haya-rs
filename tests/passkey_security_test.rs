mod support;

use std::collections::BTreeSet;

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use chrono::Utc;
use passkey_types::webauthn::{
  CredentialCreationOptions,
  CredentialRequestOptions,
};
use reqwest::StatusCode;
use uuid::Uuid;

use support::{
  SoftwarePasskeyPeer,
  cleanup_user,
  create_session,
  insert_user,
  issue_access_token,
  test_context,
  unique_suffix,
};

fn assert_no_stored_credential_fields(value: &serde_json::Value) {
  match value {
    serde_json::Value::Object(object) => {
      for key in object.keys() {
        assert!(
          ![
            "credential_id",
            "credentialId",
            "user_handle",
            "userHandle",
            "public_key_cose",
            "sign_count",
            "signCount",
            "backup_eligible",
            "backupEligible",
            "backup_state",
            "backupState",
          ]
          .contains(&key.as_str()),
          "stored credential field {key} appeared in public response"
        );
      }
      for child in object.values() {
        assert_no_stored_credential_fields(child);
      }
    },
    serde_json::Value::Array(values) => {
      for child in values {
        assert_no_stored_credential_fields(child);
      }
    },
    _ => {},
  }
}

async fn registration_options(
  ctx: &support::TestContext,
  token: &str,
  friendly_name: &str,
) -> reqwest::Response {
  ctx
    .client
    .post(format!("{}/passkeys/register/options", ctx.base_url))
    .bearer_auth(token)
    .json(&serde_json::json!({ "friendlyName": friendly_name }))
    .send()
    .await
    .unwrap()
}

async fn authentication_options(ctx: &support::TestContext) -> reqwest::Response {
  ctx
    .client
    .post(format!("{}/passkeys/authenticate/options", ctx.base_url))
    .json(&serde_json::json!({}))
    .send()
    .await
    .unwrap()
}

async fn register_credential(
  ctx: &support::TestContext,
  token: &str,
  peer: &mut SoftwarePasskeyPeer,
  friendly_name: &str,
) -> (Uuid, serde_json::Value) {
  let response = registration_options(ctx, token, friendly_name).await;
  assert_eq!(response.status(), StatusCode::OK);
  let body: serde_json::Value = response.json().await.unwrap();
  assert_no_stored_credential_fields(&body);
  let options: CredentialCreationOptions = serde_json::from_value(body["options"].clone()).unwrap();
  let credential = serde_json::to_value(peer.register(options).await).unwrap();
  let verify = ctx
    .client
    .post(format!("{}/passkeys/register/verify", ctx.base_url))
    .bearer_auth(token)
    .json(&serde_json::json!({
      "flowId": body["flowId"],
      "credential": credential,
    }))
    .send()
    .await
    .unwrap();
  assert_eq!(verify.status(), StatusCode::OK);
  let factor: serde_json::Value = verify.json().await.unwrap();
  assert_no_stored_credential_fields(&factor);
  (
    Uuid::parse_str(factor["id"].as_str().unwrap()).unwrap(),
    credential,
  )
}

async fn assertion(
  ctx: &support::TestContext,
  peer: &mut SoftwarePasskeyPeer,
) -> (Uuid, serde_json::Value, serde_json::Value) {
  let response = authentication_options(ctx).await;
  assert_eq!(response.status(), StatusCode::OK);
  let body: serde_json::Value = response.json().await.unwrap();
  assert_no_stored_credential_fields(&body);
  let options: CredentialRequestOptions = serde_json::from_value(body["options"].clone()).unwrap();
  let credential = serde_json::to_value(peer.authenticate(options).await).unwrap();
  (
    Uuid::parse_str(body["flowId"].as_str().unwrap()).unwrap(),
    credential,
    body,
  )
}

async fn exchange(
  ctx: &support::TestContext,
  flow_id: Uuid,
  credential: &serde_json::Value,
) -> reqwest::Response {
  ctx
    .client
    .post(format!("{}/token?grant_type=passkey", ctx.base_url))
    .header(reqwest::header::USER_AGENT, "phase7-security-test/1")
    .json(&serde_json::json!({
      "flowId": flow_id,
      "credential": credential,
    }))
    .send()
    .await
    .unwrap()
}

fn corrupt_challenge(credential: &serde_json::Value) -> serde_json::Value {
  let mut credential = credential.clone();
  let encoded = credential["response"]["clientDataJSON"].as_str().unwrap();
  let mut client_data: serde_json::Value =
    serde_json::from_slice(&URL_SAFE_NO_PAD.decode(encoded).unwrap()).unwrap();
  client_data["challenge"] = serde_json::json!(URL_SAFE_NO_PAD.encode([0x5a; 32]));
  credential["response"]["clientDataJSON"] =
    serde_json::json!(URL_SAFE_NO_PAD.encode(serde_json::to_vec(&client_data).unwrap()));
  credential
}

async fn clear_rate_limits(ctx: &support::TestContext) {
  sqlx::query("DELETE FROM auth.rate_limits WHERE key LIKE 'passkey-%'")
    .execute(&ctx.pool)
    .await
    .unwrap();
}

async fn install_failure_trigger(
  ctx: &support::TestContext,
  table: &str,
  operation: &str,
  predicate: &str,
) -> (String, String) {
  let suffix = unique_suffix();
  let function = format!("phase7_fail_{suffix}");
  let trigger = format!("phase7_trigger_{suffix}");
  let create_function = format!(
    "CREATE FUNCTION auth.{function}() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF {predicate} THEN RAISE EXCEPTION 'phase7 injected failure'; END IF; RETURN NEW; END $$"
  );
  sqlx::query(&create_function).execute(&ctx.pool).await.unwrap();
  let create_trigger = format!(
    "CREATE TRIGGER {trigger} BEFORE {operation} ON auth.{table} FOR EACH ROW EXECUTE FUNCTION auth.{function}()"
  );
  sqlx::query(&create_trigger).execute(&ctx.pool).await.unwrap();
  (trigger, function)
}

async fn remove_failure_trigger(ctx: &support::TestContext, table: &str, trigger: &str, function: &str) {
  sqlx::query(&format!("DROP TRIGGER {trigger} ON auth.{table}"))
    .execute(&ctx.pool)
    .await
    .unwrap();
  sqlx::query(&format!("DROP FUNCTION auth.{function}()"))
    .execute(&ctx.pool)
    .await
    .unwrap();
}

#[tokio::test]
async fn phase7_abuse_atomicity_and_leakage_gates() {
  let Some(ctx) = test_context().await else {
    return;
  };
  clear_rate_limits(&ctx).await;
  let started_at = Utc::now();
  let email = format!("phase7-security-{}@example.com", unique_suffix());
  let user_id = insert_user(&ctx.pool, &email).await;
  let session_id = create_session(&ctx.pool, user_id).await;
  let token = issue_access_token(&ctx.issuer, &ctx.jwt_secret, user_id, session_id, &email);
  let mut peer = SoftwarePasskeyPeer::new();
  let (factor_id, registered_credential) =
    register_credential(&ctx, &token, &mut peer, "Phase 7 primary").await;
  let raw_credential_id = registered_credential["rawId"].as_str().unwrap().to_owned();
  let user_handle = URL_SAFE_NO_PAD.encode(user_id.as_bytes());

  // A valid response is bound to its exact one-use challenge, not another flow.
  let (first_flow, first_assertion, first_options) = assertion(&ctx, &mut peer).await;
  let second_options_response = authentication_options(&ctx).await;
  assert_eq!(second_options_response.status(), StatusCode::OK);
  let second_options: serde_json::Value = second_options_response.json().await.unwrap();
  let second_flow = Uuid::parse_str(second_options["flowId"].as_str().unwrap()).unwrap();
  assert_eq!(
    exchange(&ctx, second_flow, &first_assertion).await.status(),
    StatusCode::BAD_REQUEST
  );
  assert_eq!(
    exchange(&ctx, first_flow, &first_assertion).await.status(),
    StatusCode::OK
  );

  // A valid assertion from another account cannot be relabeled as this user's credential.
  clear_rate_limits(&ctx).await;
  let second_email = format!("phase7-swap-{}@example.com", unique_suffix());
  let second_user_id = insert_user(&ctx.pool, &second_email).await;
  let second_session_id = create_session(&ctx.pool, second_user_id).await;
  let second_token = issue_access_token(
    &ctx.issuer,
    &ctx.jwt_secret,
    second_user_id,
    second_session_id,
    &second_email,
  );
  let mut second_peer = SoftwarePasskeyPeer::new();
  let (second_factor_id, _) =
    register_credential(&ctx, &second_token, &mut second_peer, "Phase 7 second user").await;
  let (cross_user_flow, cross_user_assertion, _) = assertion(&ctx, &mut second_peer).await;
  sqlx::query("UPDATE auth.mfa_factors SET user_id = $1 WHERE id = $2")
    .bind(user_id)
    .bind(second_factor_id)
    .execute(&ctx.pool)
    .await
    .unwrap();
  assert_eq!(
    exchange(&ctx, cross_user_flow, &cross_user_assertion)
      .await
      .status(),
    StatusCode::BAD_REQUEST
  );
  sqlx::query("UPDATE auth.mfa_factors SET user_id = $1 WHERE id = $2")
    .bind(second_user_id)
    .bind(second_factor_id)
    .execute(&ctx.pool)
    .await
    .unwrap();

  // Same registration response raced twice stores exactly one credential.
  clear_rate_limits(&ctx).await;
  let race_options = registration_options(&ctx, &token, "Phase 7 race").await;
  assert_eq!(race_options.status(), StatusCode::OK);
  let race_body: serde_json::Value = race_options.json().await.unwrap();
  let race_flow = Uuid::parse_str(race_body["flowId"].as_str().unwrap()).unwrap();
  let race_creation: CredentialCreationOptions =
    serde_json::from_value(race_body["options"].clone()).unwrap();
  let mut race_peer = SoftwarePasskeyPeer::new();
  let race_credential = serde_json::to_value(race_peer.register(race_creation).await).unwrap();
  let race_request = serde_json::json!({ "flowId": race_flow, "credential": race_credential });
  let send_race = || {
    ctx
      .client
      .post(format!("{}/passkeys/register/verify", ctx.base_url))
      .bearer_auth(&token)
      .json(&race_request)
      .send()
  };
  let (race_one, race_two) = tokio::join!(send_race(), send_race());
  let statuses = [race_one.unwrap().status(), race_two.unwrap().status()];
  assert_eq!(statuses.iter().filter(|status| status.is_success()).count(), 1);
  let race_id = URL_SAFE_NO_PAD
    .decode(race_request["credential"]["rawId"].as_str().unwrap())
    .unwrap();
  let race_factor_count: i64 =
    sqlx::query_scalar("SELECT COUNT(*) FROM auth.mfa_factors WHERE web_authn_credential_id = $1")
      .bind(race_id)
      .fetch_one(&ctx.pool)
      .await
      .unwrap();
  assert_eq!(race_factor_count, 1);

  // Session insertion failure rolls credential and flow changes back.
  clear_rate_limits(&ctx).await;
  let (session_failure_flow, session_failure_assertion, _) = assertion(&ctx, &mut peer).await;
  let before_counter: i64 = sqlx::query_scalar(
    "SELECT (web_authn_credential->>'sign_count')::bigint FROM auth.mfa_factors WHERE id = $1",
  )
  .bind(factor_id)
  .fetch_one(&ctx.pool)
  .await
  .unwrap();
  let factor_literal = factor_id.to_string();
  let (session_trigger, session_function) = install_failure_trigger(
    &ctx,
    "sessions",
    "INSERT",
    &format!("NEW.factor_id = '{factor_literal}'::uuid"),
  )
  .await;
  assert!(
    !exchange(&ctx, session_failure_flow, &session_failure_assertion)
      .await
      .status()
      .is_success()
  );
  remove_failure_trigger(&ctx, "sessions", &session_trigger, &session_function).await;
  let after_counter: i64 = sqlx::query_scalar(
    "SELECT (web_authn_credential->>'sign_count')::bigint FROM auth.mfa_factors WHERE id = $1",
  )
  .bind(factor_id)
  .fetch_one(&ctx.pool)
  .await
  .unwrap();
  assert_eq!(after_counter, before_counter);
  let consumed: Option<chrono::DateTime<Utc>> =
    sqlx::query_scalar("SELECT consumed_at FROM auth.web_authn_flows WHERE id = $1")
      .bind(session_failure_flow)
      .fetch_one(&ctx.pool)
      .await
      .unwrap();
  assert!(consumed.is_none());

  // Credential-update failure cannot create a session or consume the flow.
  clear_rate_limits(&ctx).await;
  let (update_failure_flow, update_failure_assertion, _) = assertion(&ctx, &mut peer).await;
  let sessions_before: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM auth.sessions WHERE factor_id = $1")
    .bind(factor_id)
    .fetch_one(&ctx.pool)
    .await
    .unwrap();
  let (update_trigger, update_function) = install_failure_trigger(
    &ctx,
    "mfa_factors",
    "UPDATE OF web_authn_credential",
    &format!("NEW.id = '{factor_literal}'::uuid"),
  )
  .await;
  assert!(
    !exchange(&ctx, update_failure_flow, &update_failure_assertion)
      .await
      .status()
      .is_success()
  );
  remove_failure_trigger(&ctx, "mfa_factors", &update_trigger, &update_function).await;
  let sessions_after: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM auth.sessions WHERE factor_id = $1")
    .bind(factor_id)
    .fetch_one(&ctx.pool)
    .await
    .unwrap();
  assert_eq!(sessions_after, sessions_before);
  let consumed: Option<chrono::DateTime<Utc>> =
    sqlx::query_scalar("SELECT consumed_at FROM auth.web_authn_flows WHERE id = $1")
      .bind(update_failure_flow)
      .fetch_one(&ctx.pool)
      .await
      .unwrap();
  assert!(consumed.is_none());

  // Success removes flow limiter and releases its transient IP reservation.
  clear_rate_limits(&ctx).await;
  let (success_flow, success_assertion, _) = assertion(&ctx, &mut peer).await;
  let flow_key = format!("passkey-authenticate-verify:flow:{success_flow}");
  let ip_key = "passkey-authenticate-verify:ip:127.0.0.1";
  for key in [&flow_key, ip_key] {
    sqlx::query(
      "INSERT INTO auth.rate_limits (key, attempts, expires_at, created_at, updated_at) VALUES ($1, 3, NOW() + INTERVAL '5 minutes', NOW(), NOW()) ON CONFLICT (key) DO UPDATE SET attempts = 3, expires_at = NOW() + INTERVAL '5 minutes'",
    )
    .bind(key)
    .execute(&ctx.pool)
    .await
    .unwrap();
  }
  assert_eq!(
    exchange(&ctx, success_flow, &success_assertion).await.status(),
    StatusCode::OK
  );
  let flow_limit_exists: bool =
    sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM auth.rate_limits WHERE key = $1)")
      .bind(&flow_key)
      .fetch_one(&ctx.pool)
      .await
      .unwrap();
  assert!(!flow_limit_exists);
  let ip_attempts: i32 = sqlx::query_scalar("SELECT attempts FROM auth.rate_limits WHERE key = $1")
    .bind(ip_key)
    .fetch_one(&ctx.pool)
    .await
    .unwrap();
  assert_eq!(ip_attempts, 3);

  // Ten failed assertions exhaust both verification policy and persisted flow attempts.
  clear_rate_limits(&ctx).await;
  let (exhausted_auth_flow, valid_assertion, _) = assertion(&ctx, &mut peer).await;
  let mut invalid_assertion = valid_assertion.clone();
  invalid_assertion["response"]["signature"] = serde_json::json!("AQ");
  for _ in 0..10 {
    assert_eq!(
      exchange(&ctx, exhausted_auth_flow, &invalid_assertion)
        .await
        .status(),
      StatusCode::BAD_REQUEST
    );
  }
  let attempts: i32 = sqlx::query_scalar("SELECT attempts FROM auth.web_authn_flows WHERE id = $1")
    .bind(exhausted_auth_flow)
    .fetch_one(&ctx.pool)
    .await
    .unwrap();
  assert_eq!(attempts, 10);
  clear_rate_limits(&ctx).await;
  assert_eq!(
    exchange(&ctx, exhausted_auth_flow, &valid_assertion)
      .await
      .status(),
    StatusCode::BAD_REQUEST
  );

  // Ten failed registrations likewise make their flow permanently unavailable.
  clear_rate_limits(&ctx).await;
  let exhausted_registration = registration_options(&ctx, &token, "Phase 7 exhausted").await;
  assert_eq!(exhausted_registration.status(), StatusCode::OK);
  let exhausted_body: serde_json::Value = exhausted_registration.json().await.unwrap();
  let exhausted_flow = Uuid::parse_str(exhausted_body["flowId"].as_str().unwrap()).unwrap();
  let exhausted_creation: CredentialCreationOptions =
    serde_json::from_value(exhausted_body["options"].clone()).unwrap();
  let valid_registration = serde_json::to_value(peer.register(exhausted_creation).await).unwrap();
  let invalid_registration = corrupt_challenge(&valid_registration);
  for _ in 0..10 {
    let response = ctx
      .client
      .post(format!("{}/passkeys/register/verify", ctx.base_url))
      .bearer_auth(&token)
      .json(&serde_json::json!({
        "flowId": exhausted_flow,
        "credential": invalid_registration,
      }))
      .send()
      .await
      .unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
  }
  clear_rate_limits(&ctx).await;
  let exhausted_valid = ctx
    .client
    .post(format!("{}/passkeys/register/verify", ctx.base_url))
    .bearer_auth(&token)
    .json(&serde_json::json!({
      "flowId": exhausted_flow,
      "credential": valid_registration,
    }))
    .send()
    .await
    .unwrap();
  assert_eq!(exhausted_valid.status(), StatusCode::BAD_REQUEST);

  // Public option creation is bounded by user/IP and anonymous-IP limits.
  clear_rate_limits(&ctx).await;
  for index in 0..10 {
    assert_eq!(
      registration_options(&ctx, &token, &format!("Rate limited {index}"))
        .await
        .status(),
      StatusCode::OK
    );
  }
  assert_eq!(
    registration_options(&ctx, &token, "Rate limited final")
      .await
      .status(),
    StatusCode::TOO_MANY_REQUESTS
  );
  clear_rate_limits(&ctx).await;
  let mut anonymous_flows = Vec::new();
  for _ in 0..20 {
    let response = authentication_options(&ctx).await;
    assert_eq!(response.status(), StatusCode::OK);
    let body: serde_json::Value = response.json().await.unwrap();
    anonymous_flows.push(Uuid::parse_str(body["flowId"].as_str().unwrap()).unwrap());
  }
  assert_eq!(
    authentication_options(&ctx).await.status(),
    StatusCode::TOO_MANY_REQUESTS
  );

  // Persisted keys/audits and actual tracing output exclude protected WebAuthn material.
  let rate_keys: Vec<String> =
    sqlx::query_scalar("SELECT key FROM auth.rate_limits WHERE key LIKE 'passkey-%'")
      .fetch_all(&ctx.pool)
      .await
      .unwrap();
  let audit_payloads: Vec<serde_json::Value> = sqlx::query_scalar(
    "SELECT payload FROM auth.audit_log_entries WHERE created_at >= $1 AND payload->>'event' LIKE 'passkey_%'",
  )
  .bind(started_at)
  .fetch_all(&ctx.pool)
  .await
  .unwrap();
  for serialized in rate_keys
    .iter()
    .cloned()
    .chain(audit_payloads.iter().map(serde_json::Value::to_string))
  {
    assert!(!serialized.contains(&raw_credential_id));
    assert!(!serialized.contains(&user_handle));
    assert!(!serialized.contains("clientDataJSON"));
    assert!(!serialized.contains("authenticatorData"));
    assert!(!serialized.contains("public_key_cose"));
    assert!(!serialized.contains("signature"));
  }
  let events = audit_payloads
    .iter()
    .map(|payload| payload["event"].as_str().unwrap())
    .collect::<BTreeSet<_>>();
  for required in [
    "passkey_enrollment_started",
    "passkey_enrollment_succeeded",
    "passkey_enrollment_failed",
    "passkey_login_succeeded",
    "passkey_login_failed",
  ] {
    assert!(
      events.contains(required),
      "missing expected audit event {required}"
    );
  }
  for payload in &audit_payloads {
    let object = payload.as_object().unwrap();
    let event = object["event"].as_str().unwrap();
    let allowed: &[&str] = match event {
      "passkey_enrollment_started" => &["event", "user_id", "flow_id", "factor_type"],
      "passkey_enrollment_succeeded" => &["event", "user_id", "flow_id", "factor_id", "factor_type"],
      "passkey_enrollment_failed" => &["event", "user_id", "flow_id", "factor_type", "reason"],
      "passkey_login_succeeded" => &["event", "user_id", "factor_id"],
      "passkey_login_failed" => &["event", "reason"],
      other => panic!("unexpected passkey audit event {other}"),
    };
    let actual_keys = object.keys().map(String::as_str).collect::<BTreeSet<_>>();
    let expected_keys = allowed.iter().copied().collect::<BTreeSet<_>>();
    assert_eq!(actual_keys, expected_keys, "wrong fields in {event}: {object:?}");
    for id_key in ["user_id", "flow_id", "factor_id"] {
      if expected_keys.contains(id_key) {
        assert!(
          object[id_key].as_str().is_some(),
          "{event}.{id_key} must be a UUID string"
        );
      }
    }
    if expected_keys.contains("factor_type") {
      assert_eq!(object["factor_type"], "webauthn");
    }
    if event == "passkey_login_failed" {
      assert_eq!(object["reason"], "authentication_failed");
    }
    if event == "passkey_enrollment_failed" {
      assert!(matches!(
        object["reason"].as_str(),
        Some("flow_unavailable" | "stored_state_invalid" | "protocol_validation" | "credential_conflict")
      ));
    }
  }

  let stored_credential: serde_json::Value =
    sqlx::query_scalar("SELECT web_authn_credential FROM auth.mfa_factors WHERE id = $1")
      .bind(factor_id)
      .fetch_one(&ctx.pool)
      .await
      .unwrap();
  let public_key_bytes = stored_credential["public_key_cose"]
    .as_array()
    .unwrap()
    .iter()
    .map(|byte| u8::try_from(byte.as_u64().unwrap()).unwrap())
    .collect::<Vec<_>>();

  for flow_id in anonymous_flows {
    sqlx::query("DELETE FROM auth.web_authn_flows WHERE id = $1")
      .bind(flow_id)
      .execute(&ctx.pool)
      .await
      .unwrap();
  }
  cleanup_user(&ctx.pool, second_user_id).await;
  cleanup_user(&ctx.pool, user_id).await;
  clear_rate_limits(&ctx).await;

  let logs = ctx.finish().await;
  let client_data_encoded = first_assertion["response"]["clientDataJSON"].as_str().unwrap();
  let authenticator_data_encoded = first_assertion["response"]["authenticatorData"].as_str().unwrap();
  let signature_encoded = first_assertion["response"]["signature"].as_str().unwrap();
  let mut protected_values = vec![
    raw_credential_id.clone(),
    user_handle.clone(),
    first_options["options"]["publicKey"]["challenge"]
      .as_str()
      .unwrap()
      .to_owned(),
    client_data_encoded.to_owned(),
    authenticator_data_encoded.to_owned(),
    signature_encoded.to_owned(),
    String::from_utf8(URL_SAFE_NO_PAD.decode(client_data_encoded).unwrap()).unwrap(),
    format!("{:?}", URL_SAFE_NO_PAD.decode(&raw_credential_id).unwrap()),
    format!("{:?}", URL_SAFE_NO_PAD.decode(&user_handle).unwrap()),
    format!(
      "{:?}",
      URL_SAFE_NO_PAD.decode(authenticator_data_encoded).unwrap()
    ),
    format!("{:?}", URL_SAFE_NO_PAD.decode(signature_encoded).unwrap()),
    URL_SAFE_NO_PAD.encode(&public_key_bytes),
    format!("{public_key_bytes:?}"),
  ];
  if let Some(browser_public_key) = registered_credential["response"]["publicKey"].as_str() {
    protected_values.push(browser_public_key.to_owned());
  }
  for protected in protected_values {
    assert!(protected.len() > 8);
    assert!(
      !logs.contains(&protected),
      "protected WebAuthn material leaked to logs"
    );
  }
}
