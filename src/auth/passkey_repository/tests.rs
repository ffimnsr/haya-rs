use super::*;

fn valid_cose_key() -> Vec<u8> {
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

fn credential() -> RpCredential {
  RpCredential {
    credential_id: vec![7; 32],
    user_handle: vec![8; 32],
    public_key_cose: valid_cose_key(),
    algorithm: -7,
    sign_count: 0,
    aaguid: [9; 16],
    transports: Vec::new(),
    backup_eligible: false,
    backup_state: false,
  }
}

fn factor_row(value: Value) -> WebAuthnFactorRow {
  let credential = credential();
  let now = Utc::now();
  WebAuthnFactorRow {
    id: Uuid::new_v4(),
    user_id: Uuid::new_v4(),
    friendly_name: Some("Laptop".to_owned()),
    factor_type: "webauthn".to_owned(),
    status: "verified".to_owned(),
    web_authn_credential_id: Some(credential.credential_id.clone()),
    web_authn_credential: Some(value),
    web_authn_aaguid: Some(Uuid::from_bytes(credential.aaguid)),
    last_challenged_at: None,
    created_at: now,
    updated_at: now,
  }
}

#[test]
fn migration_contains_reversible_schema_contract() {
  let sql = include_str!("../../../migrations/202609020001_add_web_authn_credentials_and_flows.sql");
  let (up, down) = sql.split_once("-- !DOWN").unwrap();
  for required in [
    "web_authn_credential_id bytea",
    "mfa_factors_web_authn_credential_id_unique_idx",
    "create table auth.web_authn_flows",
    "octet_length(challenge) = 32",
    "on delete cascade",
    "web_authn_flows_active_lookup_idx",
  ] {
    assert!(up.to_ascii_lowercase().contains(required), "missing {required}");
  }
  for required in [
    "drop table if exists auth.web_authn_flows",
    "drop column if exists web_authn_credential_id",
  ] {
    assert!(down.to_ascii_lowercase().contains(required), "missing {required}");
  }
}

#[test]
fn converts_valid_factor_row_to_domain() {
  let expected = credential();
  let row = factor_row(serde_json::to_value(&expected).unwrap());
  let factor = WebAuthnFactor::try_from(row).unwrap();
  assert_eq!(factor.credential, expected);
}

#[test]
fn rejects_malformed_or_inconsistent_stored_factor() {
  assert!(WebAuthnFactor::try_from(factor_row(serde_json::json!({"bad": true}))).is_err());

  let mut mismatched = credential();
  mismatched.credential_id = vec![1; 32];
  assert!(WebAuthnFactor::try_from(factor_row(serde_json::to_value(mismatched).unwrap())).is_err());
}

#[test]
fn converts_flow_state_and_rejects_malformed_state() {
  let now = Utc::now();
  let state = RegistrationState {
    challenge: vec![1; 32],
    user_handle: vec![2; 32],
  };
  let row = WebAuthnFlowRow {
    id: Uuid::new_v4(),
    user_id: Some(Uuid::new_v4()),
    purpose: "registration".to_owned(),
    challenge: state.challenge.clone(),
    state: serde_json::to_value(&state).unwrap(),
    friendly_name: None,
    attempts: 0,
    expires_at: now + Duration::minutes(5),
    consumed_at: None,
    created_at: now,
    updated_at: now,
  };
  assert_eq!(row.registration_state().unwrap(), state);

  let mut malformed = row;
  malformed.state = serde_json::json!({"challenge": []});
  assert!(malformed.registration_state().is_err());
}

#[test]
fn flow_debug_redacts_challenge_and_serialized_state() {
  let now = Utc::now();
  let challenge = vec![0x6a; 32];
  let state = serde_json::json!({
    "challenge": challenge,
    "user_handle": vec![0x7b; 16],
  });
  let row = WebAuthnFlowRow {
    id: Uuid::new_v4(),
    user_id: Some(Uuid::new_v4()),
    purpose: "registration".to_owned(),
    challenge: vec![0x6a; 32],
    state,
    friendly_name: Some("Laptop".to_owned()),
    attempts: 1,
    expires_at: now + Duration::minutes(5),
    consumed_at: None,
    created_at: now,
    updated_at: now,
  };

  let debug = format!("{row:?}");
  assert!(debug.contains("challenge: \"[redacted]\""));
  assert!(debug.contains("state: \"[redacted]\""));
  assert!(!debug.contains("106, 106, 106"));
  assert!(!debug.contains("123, 123, 123"));
}

#[tokio::test]
async fn postgres_schema_transactions_cleanup_and_concurrency() {
  let Some(database_url) = std::env::var("DATABASE_URL").ok() else {
    return;
  };
  let pool = PgPool::connect(&database_url).await.unwrap();
  apply_pending_migrations(&pool).await;
  verify_migration_down_and_up(&pool).await;

  let user_one = insert_test_user(&pool).await;
  let user_two = insert_test_user(&pool).await;
  let replacement_credential = credential_for(vec![0x50; 32], vec![0x60; 32]);
  let replaced_flow = create_registration_flow(
    &pool,
    user_two,
    &registration_state(&replacement_credential),
    None,
    300,
  )
  .await
  .unwrap();
  let replacement_flow = create_registration_flow(
    &pool,
    user_two,
    &RegistrationState {
      challenge: vec![0x42; 32],
      user_handle: replacement_credential.user_handle.clone(),
    },
    None,
    300,
  )
  .await
  .unwrap();
  assert!(!flow_exists(&pool, replaced_flow.id).await);
  assert!(flow_exists(&pool, replacement_flow.id).await);

  let credential_id = vec![0x51; 32];
  let credential_one = credential_for(credential_id.clone(), vec![0x61; 32]);
  let factor_one = register_factor(&pool, user_one, &credential_one).await;

  let fetched = fetch_factor(&pool, &credential_id).await;
  assert_eq!(fetched.id, factor_one.id);
  assert_eq!(fetched.credential, credential_one);

  let credential_two = credential_for(credential_id.clone(), vec![0x62; 32]);
  let duplicate_flow = create_registration_flow(
    &pool,
    user_two,
    &registration_state(&credential_two),
    Some("Duplicate"),
    300,
  )
  .await
  .unwrap();
  let mut duplicate_tx = pool.begin().await.unwrap();
  let duplicate_flow = lock_registration_flow(&mut duplicate_tx, duplicate_flow.id, user_two, Utc::now())
    .await
    .unwrap();
  assert!(matches!(
    complete_registration(&mut duplicate_tx, &duplicate_flow, &credential_two, Utc::now()).await,
    Err(AuthError::PasskeyRegistrationFailed)
  ));
  duplicate_tx.commit().await.unwrap();
  let duplicate_attempts: i32 = sqlx::query_scalar("SELECT attempts FROM auth.web_authn_flows WHERE id = $1")
    .bind(duplicate_flow.id)
    .fetch_one(&pool)
    .await
    .unwrap();
  assert_eq!(duplicate_attempts, 1);

  let owned_flow = create_registration_flow(
    &pool,
    user_one,
    &registration_state(&credential_for(vec![0x52; 32], vec![0x63; 32])),
    None,
    300,
  )
  .await
  .unwrap();
  let mut wrong_owner_tx = pool.begin().await.unwrap();
  assert!(matches!(
    lock_registration_flow(&mut wrong_owner_tx, owned_flow.id, user_two, Utc::now()).await,
    Err(AuthError::PasskeyRegistrationFailed)
  ));
  wrong_owner_tx.rollback().await.unwrap();

  let expired_id = insert_test_flow(
    &pool,
    Some(user_one),
    FlowPurpose::Registration,
    Utc::now() - Duration::minutes(1),
    None,
  )
  .await;
  let mut expired_tx = pool.begin().await.unwrap();
  assert!(matches!(
    lock_registration_flow(&mut expired_tx, expired_id, user_one, Utc::now()).await,
    Err(AuthError::PasskeyRegistrationFailed)
  ));
  expired_tx.rollback().await.unwrap();

  let wrong_purpose_id = insert_test_flow(
    &pool,
    Some(user_one),
    FlowPurpose::Authentication,
    Utc::now() + Duration::minutes(5),
    None,
  )
  .await;
  let mut wrong_purpose_tx = pool.begin().await.unwrap();
  assert!(matches!(
    lock_registration_flow(&mut wrong_purpose_tx, wrong_purpose_id, user_one, Utc::now(),).await,
    Err(AuthError::PasskeyRegistrationFailed)
  ));
  wrong_purpose_tx.rollback().await.unwrap();

  let attempts_id = insert_test_flow(
    &pool,
    None,
    FlowPurpose::Authentication,
    Utc::now() + Duration::minutes(5),
    None,
  )
  .await;
  sqlx::query("UPDATE auth.web_authn_flows SET attempts = $1 WHERE id = $2")
    .bind(MAX_FLOW_ATTEMPTS)
    .bind(attempts_id)
    .execute(&pool)
    .await
    .unwrap();
  let mut attempts_tx = pool.begin().await.unwrap();
  assert!(matches!(
    lock_authentication_flow(&mut attempts_tx, attempts_id, Utc::now()).await,
    Err(AuthError::PasskeyAuthenticationFailed)
  ));
  attempts_tx.rollback().await.unwrap();

  let consumed_id = insert_test_flow(
    &pool,
    None,
    FlowPurpose::Authentication,
    Utc::now() + Duration::minutes(5),
    Some(Utc::now()),
  )
  .await;
  let mut consumed_tx = pool.begin().await.unwrap();
  assert!(matches!(
    lock_authentication_flow(&mut consumed_tx, consumed_id, Utc::now()).await,
    Err(AuthError::PasskeyAuthenticationFailed)
  ));
  consumed_tx.rollback().await.unwrap();

  let concurrent_credential = credential_for(vec![0x53; 32], vec![0x64; 32]);
  let concurrent_flow = create_registration_flow(
    &pool,
    user_two,
    &registration_state(&concurrent_credential),
    Some("Concurrent"),
    300,
  )
  .await
  .unwrap();
  let first = consume_registration_once(
    pool.clone(),
    concurrent_flow.id,
    user_two,
    concurrent_credential.clone(),
  );
  let second = consume_registration_once(pool.clone(), concurrent_flow.id, user_two, concurrent_credential);
  let (first, second) = tokio::join!(first, second);
  assert_eq!(usize::from(first) + usize::from(second), 1);

  let shared_credential_id = vec![0x56; 32];
  let first_shared_credential = credential_for(shared_credential_id.clone(), user_one.as_bytes().to_vec());
  let second_shared_credential = credential_for(shared_credential_id.clone(), user_two.as_bytes().to_vec());
  let first_shared_flow = create_registration_flow(
    &pool,
    user_one,
    &registration_state(&first_shared_credential),
    Some("Shared credential one"),
    300,
  )
  .await
  .unwrap();
  let second_shared_flow = create_registration_flow(
    &pool,
    user_two,
    &registration_state(&second_shared_credential),
    Some("Shared credential two"),
    300,
  )
  .await
  .unwrap();
  let first = consume_registration_once(
    pool.clone(),
    first_shared_flow.id,
    user_one,
    first_shared_credential,
  );
  let second = consume_registration_once(
    pool.clone(),
    second_shared_flow.id,
    user_two,
    second_shared_credential,
  );
  let (first, second) = tokio::join!(first, second);
  assert_eq!(usize::from(first) + usize::from(second), 1);
  let shared_factor_count: i64 =
    sqlx::query_scalar("SELECT COUNT(*) FROM auth.mfa_factors WHERE web_authn_credential_id = $1")
      .bind(shared_credential_id)
      .fetch_one(&pool)
      .await
      .unwrap();
  assert_eq!(shared_factor_count, 1);

  let auth_flow = create_authentication_flow(
    &pool,
    &AuthenticationState {
      challenge: vec![0x71; 32],
    },
    300,
  )
  .await
  .unwrap();
  let before = fetch_factor(&pool, &credential_id).await;
  let mut rollback_tx = pool.begin().await.unwrap();
  let locked_flow = lock_authentication_flow(&mut rollback_tx, auth_flow.id, Utc::now())
    .await
    .unwrap();
  let locked_factor = lock_factor_by_credential_id(&mut rollback_tx, &credential_id)
    .await
    .unwrap();
  complete_authentication(
    &mut rollback_tx,
    &locked_flow,
    &locked_factor,
    &AuthenticationResult {
      user_handle: locked_factor.credential.user_handle.clone(),
      sign_count: 1,
      backup_state: false,
    },
    Utc::now(),
  )
  .await
  .unwrap();
  rollback_tx.rollback().await.unwrap();
  let after_rollback = fetch_factor(&pool, &credential_id).await;
  assert_eq!(after_rollback.credential.sign_count, before.credential.sign_count);
  assert_flow_unconsumed(&pool, auth_flow.id).await;

  let mut commit_tx = pool.begin().await.unwrap();
  let locked_flow = lock_authentication_flow(&mut commit_tx, auth_flow.id, Utc::now())
    .await
    .unwrap();
  let locked_factor = lock_factor_by_credential_id(&mut commit_tx, &credential_id)
    .await
    .unwrap();
  complete_authentication(
    &mut commit_tx,
    &locked_flow,
    &locked_factor,
    &AuthenticationResult {
      user_handle: locked_factor.credential.user_handle.clone(),
      sign_count: 1,
      backup_state: false,
    },
    Utc::now(),
  )
  .await
  .unwrap();
  commit_tx.commit().await.unwrap();
  assert_eq!(fetch_factor(&pool, &credential_id).await.credential.sign_count, 1);
  assert_flow_consumed(&pool, auth_flow.id).await;

  let active_id = insert_test_flow(
    &pool,
    None,
    FlowPurpose::Authentication,
    Utc::now() + Duration::minutes(5),
    None,
  )
  .await;
  let expired_cleanup_id = insert_test_flow(
    &pool,
    None,
    FlowPurpose::Authentication,
    Utc::now() - Duration::minutes(1),
    None,
  )
  .await;
  let old_consumed_id = insert_test_flow(
    &pool,
    None,
    FlowPurpose::Authentication,
    Utc::now() + Duration::minutes(5),
    Some(Utc::now() - Duration::hours(2)),
  )
  .await;
  cleanup_flows(&pool, Utc::now()).await.unwrap();
  assert!(flow_exists(&pool, active_id).await);
  assert!(!flow_exists(&pool, expired_cleanup_id).await);
  assert!(!flow_exists(&pool, old_consumed_id).await);

  let cascade_credential = credential_for(vec![0x54; 32], vec![0x65; 32]);
  register_factor(&pool, user_one, &cascade_credential).await;
  let cascade_flow = create_registration_flow(
    &pool,
    user_one,
    &registration_state(&credential_for(vec![0x55; 32], vec![0x66; 32])),
    None,
    300,
  )
  .await
  .unwrap();
  sqlx::query("DELETE FROM auth.users WHERE id = $1")
    .bind(user_one)
    .execute(&pool)
    .await
    .unwrap();
  assert!(!flow_exists(&pool, cascade_flow.id).await);
  let factor_count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM auth.mfa_factors WHERE user_id = $1")
    .bind(user_one)
    .fetch_one(&pool)
    .await
    .unwrap();
  assert_eq!(factor_count, 0);

  sqlx::query("DELETE FROM auth.users WHERE id = $1")
    .bind(user_two)
    .execute(&pool)
    .await
    .unwrap();
}

fn credential_for(credential_id: Vec<u8>, user_handle: Vec<u8>) -> RpCredential {
  RpCredential {
    credential_id,
    user_handle,
    public_key_cose: valid_cose_key(),
    algorithm: -7,
    sign_count: 0,
    aaguid: [9; 16],
    transports: Vec::new(),
    backup_eligible: false,
    backup_state: false,
  }
}

fn registration_state(credential: &RpCredential) -> RegistrationState {
  RegistrationState {
    challenge: vec![0x41; 32],
    user_handle: credential.user_handle.clone(),
  }
}

async fn insert_test_user(pool: &PgPool) -> Uuid {
  let user_id = Uuid::new_v4();
  let now = Utc::now();
  sqlx::query(
    "INSERT INTO auth.users (id, aud, role, email, email_confirmed_at, created_at, updated_at) VALUES ($1, 'authenticated', 'authenticated', $2, $3, $3, $3)",
  )
  .bind(user_id)
  .bind(format!("passkey-{user_id}@example.invalid"))
  .bind(now)
  .execute(pool)
  .await
  .unwrap();
  user_id
}

async fn register_factor(pool: &PgPool, user_id: Uuid, credential: &RpCredential) -> WebAuthnFactor {
  let flow = create_registration_flow(
    pool,
    user_id,
    &registration_state(credential),
    Some("Test passkey"),
    300,
  )
  .await
  .unwrap();
  let mut tx = pool.begin().await.unwrap();
  let flow = lock_registration_flow(&mut tx, flow.id, user_id, Utc::now())
    .await
    .unwrap();
  let factor = complete_registration(&mut tx, &flow, credential, Utc::now())
    .await
    .unwrap();
  tx.commit().await.unwrap();
  factor
}

async fn fetch_factor(pool: &PgPool, credential_id: &[u8]) -> WebAuthnFactor {
  let mut tx = pool.begin().await.unwrap();
  let factor = lock_factor_by_credential_id(&mut tx, credential_id)
    .await
    .unwrap();
  tx.rollback().await.unwrap();
  factor
}

async fn consume_registration_once(
  pool: PgPool,
  flow_id: Uuid,
  user_id: Uuid,
  credential: RpCredential,
) -> bool {
  let mut tx = pool.begin().await.unwrap();
  let Ok(flow) = lock_registration_flow(&mut tx, flow_id, user_id, Utc::now()).await else {
    tx.rollback().await.unwrap();
    return false;
  };
  if complete_registration(&mut tx, &flow, &credential, Utc::now())
    .await
    .is_err()
  {
    tx.rollback().await.unwrap();
    return false;
  }
  tx.commit().await.unwrap();
  true
}

async fn insert_test_flow(
  pool: &PgPool,
  user_id: Option<Uuid>,
  purpose: FlowPurpose,
  expires_at: DateTime<Utc>,
  consumed_at: Option<DateTime<Utc>>,
) -> Uuid {
  let id = Uuid::new_v4();
  let challenge = vec![0x31; 32];
  let state = match purpose {
    FlowPurpose::Registration => serde_json::to_value(RegistrationState {
      challenge: challenge.clone(),
      user_handle: vec![0x32; 32],
    })
    .unwrap(),
    FlowPurpose::Authentication => serde_json::to_value(AuthenticationState {
      challenge: challenge.clone(),
    })
    .unwrap(),
  };
  let now = Utc::now();
  sqlx::query(
    "INSERT INTO auth.web_authn_flows (id, user_id, purpose, challenge, state, attempts, expires_at, consumed_at, created_at, updated_at) VALUES ($1, $2, $3, $4, $5, 0, $6, $7, $8, $8)",
  )
  .bind(id)
  .bind(user_id)
  .bind(purpose.as_str())
  .bind(challenge)
  .bind(state)
  .bind(expires_at)
  .bind(consumed_at)
  .bind(now)
  .execute(pool)
  .await
  .unwrap();
  id
}

async fn assert_flow_unconsumed(pool: &PgPool, id: Uuid) {
  let consumed: Option<DateTime<Utc>> =
    sqlx::query_scalar("SELECT consumed_at FROM auth.web_authn_flows WHERE id = $1")
      .bind(id)
      .fetch_one(pool)
      .await
      .unwrap();
  assert!(consumed.is_none());
}

async fn assert_flow_consumed(pool: &PgPool, id: Uuid) {
  let consumed: Option<DateTime<Utc>> =
    sqlx::query_scalar("SELECT consumed_at FROM auth.web_authn_flows WHERE id = $1")
      .bind(id)
      .fetch_one(pool)
      .await
      .unwrap();
  assert!(consumed.is_some());
}

async fn flow_exists(pool: &PgPool, id: Uuid) -> bool {
  sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM auth.web_authn_flows WHERE id = $1)")
    .bind(id)
    .fetch_one(pool)
    .await
    .unwrap()
}

async fn apply_pending_migrations(pool: &PgPool) {
  let mut files = std::fs::read_dir(concat!(env!("CARGO_MANIFEST_DIR"), "/migrations"))
    .unwrap()
    .filter_map(|entry| entry.ok())
    .map(|entry| entry.path())
    .filter(|path| path.extension().is_some_and(|extension| extension == "sql"))
    .collect::<Vec<_>>();
  files.sort();

  for path in files {
    let version = path
      .file_name()
      .unwrap()
      .to_str()
      .unwrap()
      .split('_')
      .next()
      .unwrap()
      .to_owned();
    let migrations_table_exists: bool =
      sqlx::query_scalar("SELECT to_regclass('auth.schema_migrations') IS NOT NULL")
        .fetch_one(pool)
        .await
        .unwrap();
    if migrations_table_exists {
      let applied: bool =
        sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM auth.schema_migrations WHERE version = $1)")
          .bind(&version)
          .fetch_one(pool)
          .await
          .unwrap();
      if applied {
        continue;
      }
    }
    let sql = std::fs::read_to_string(&path).unwrap();
    let up = sql.split_once("-- !DOWN").map_or(sql.as_str(), |(up, _)| up);
    let mut tx = pool.begin().await.unwrap();
    sqlx::raw_sql(up).execute(tx.as_mut()).await.unwrap();
    sqlx::query("INSERT INTO auth.schema_migrations (version) VALUES ($1)")
      .bind(version)
      .execute(tx.as_mut())
      .await
      .unwrap();
    tx.commit().await.unwrap();
  }
}

async fn verify_migration_down_and_up(pool: &PgPool) {
  let sql = include_str!("../../../migrations/202609020001_add_web_authn_credentials_and_flows.sql");
  let (up, down) = sql.split_once("-- !DOWN").unwrap();
  let mut tx = pool.begin().await.unwrap();
  sqlx::raw_sql(down).execute(tx.as_mut()).await.unwrap();
  sqlx::raw_sql(up).execute(tx.as_mut()).await.unwrap();
  tx.rollback().await.unwrap();
}
