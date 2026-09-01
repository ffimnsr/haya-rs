#![allow(dead_code, reason = "repository API is consumed by passkey HTTP phases")]

use std::fmt;

use chrono::{
  DateTime,
  Duration,
  Utc,
};
use haya_passkey_rp::{
  AuthenticationResult,
  AuthenticationState,
  PublicKeyCredentialDescriptor,
  PublicKeyCredentialType,
  RegistrationState,
  RpCredential,
};
use serde_json::Value;
use sqlx::{
  FromRow,
  PgPool,
  Postgres,
  Transaction,
};
use uuid::Uuid;

use crate::error::{
  AuthError,
  Result,
};

pub(crate) const MAX_FLOW_ATTEMPTS: i32 = 10;
pub(crate) const MAX_WEB_AUTHN_FACTORS_PER_USER: i64 = 10;
const CLEANUP_BATCH_SIZE: i64 = 100;
const CONSUMED_FLOW_RETENTION_HOURS: i64 = 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum FlowPurpose {
  Registration,
  Authentication,
}

impl FlowPurpose {
  fn as_str(self) -> &'static str {
    match self {
      Self::Registration => "registration",
      Self::Authentication => "authentication",
    }
  }
}

#[derive(Debug, Clone, FromRow)]
pub(crate) struct WebAuthnFactorRow {
  pub id: Uuid,
  pub user_id: Uuid,
  pub friendly_name: Option<String>,
  pub factor_type: String,
  pub status: String,
  pub web_authn_credential_id: Option<Vec<u8>>,
  pub web_authn_credential: Option<Value>,
  pub web_authn_aaguid: Option<Uuid>,
  pub last_challenged_at: Option<DateTime<Utc>>,
  pub created_at: DateTime<Utc>,
  pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone)]
pub(crate) struct WebAuthnFactor {
  pub id: Uuid,
  pub user_id: Uuid,
  pub friendly_name: Option<String>,
  pub factor_type: String,
  pub status: String,
  pub credential: RpCredential,
  pub last_challenged_at: Option<DateTime<Utc>>,
  pub created_at: DateTime<Utc>,
  pub updated_at: DateTime<Utc>,
}

impl WebAuthnFactor {
  pub(crate) fn credential_descriptor(&self) -> PublicKeyCredentialDescriptor {
    PublicKeyCredentialDescriptor {
      ty: PublicKeyCredentialType::PublicKey,
      id: self.credential.credential_id.clone().into(),
      transports: (!self.credential.transports.is_empty()).then(|| self.credential.transports.clone()),
    }
  }
}

impl TryFrom<WebAuthnFactorRow> for WebAuthnFactor {
  type Error = AuthError;

  fn try_from(row: WebAuthnFactorRow) -> Result<Self> {
    if row.factor_type != "webauthn" || row.status != "verified" {
      return Err(stored_data_error("stored WebAuthn factor metadata is invalid"));
    }
    let credential_id = row
      .web_authn_credential_id
      .ok_or_else(|| stored_data_error("WebAuthn factor is missing its credential ID"))?;
    let credential_value = row
      .web_authn_credential
      .ok_or_else(|| stored_data_error("WebAuthn factor is missing credential state"))?;
    let credential: RpCredential = serde_json::from_value(credential_value)
      .map_err(|error| stored_data_error(format!("invalid stored WebAuthn credential: {error}")))?;
    credential
      .validate()
      .map_err(|error| stored_data_error(format!("invalid stored WebAuthn credential: {error}")))?;
    if credential.credential_id != credential_id {
      return Err(stored_data_error(
        "stored WebAuthn credential ID does not match indexed credential ID",
      ));
    }
    if row.web_authn_aaguid != Some(Uuid::from_bytes(credential.aaguid)) {
      return Err(stored_data_error(
        "stored WebAuthn credential AAGUID does not match factor AAGUID",
      ));
    }

    Ok(Self {
      id: row.id,
      user_id: row.user_id,
      friendly_name: row.friendly_name,
      factor_type: row.factor_type,
      status: row.status,
      credential,
      last_challenged_at: row.last_challenged_at,
      created_at: row.created_at,
      updated_at: row.updated_at,
    })
  }
}

#[derive(Clone, FromRow)]
pub(crate) struct WebAuthnFlowRow {
  pub id: Uuid,
  pub user_id: Option<Uuid>,
  pub purpose: String,
  pub challenge: Vec<u8>,
  pub state: Value,
  pub friendly_name: Option<String>,
  pub attempts: i32,
  pub expires_at: DateTime<Utc>,
  pub consumed_at: Option<DateTime<Utc>>,
  pub created_at: DateTime<Utc>,
  pub updated_at: DateTime<Utc>,
}

impl fmt::Debug for WebAuthnFlowRow {
  fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
    formatter
      .debug_struct("WebAuthnFlowRow")
      .field("id", &self.id)
      .field("user_id", &self.user_id)
      .field("purpose", &self.purpose)
      .field("challenge", &"[redacted]")
      .field("state", &"[redacted]")
      .field("friendly_name", &self.friendly_name)
      .field("attempts", &self.attempts)
      .field("expires_at", &self.expires_at)
      .field("consumed_at", &self.consumed_at)
      .field("created_at", &self.created_at)
      .field("updated_at", &self.updated_at)
      .finish()
  }
}

impl WebAuthnFlowRow {
  pub fn registration_state(&self) -> Result<RegistrationState> {
    if self.purpose != FlowPurpose::Registration.as_str() {
      return Err(stored_data_error(
        "WebAuthn flow purpose does not match registration state",
      ));
    }
    let state: RegistrationState = serde_json::from_value(self.state.clone())
      .map_err(|error| stored_data_error(format!("invalid stored registration state: {error}")))?;
    ensure_challenge_matches(&self.challenge, &state.challenge)?;
    Ok(state)
  }

  pub fn authentication_state(&self) -> Result<AuthenticationState> {
    if self.purpose != FlowPurpose::Authentication.as_str() {
      return Err(stored_data_error(
        "WebAuthn flow purpose does not match authentication state",
      ));
    }
    let state: AuthenticationState = serde_json::from_value(self.state.clone())
      .map_err(|error| stored_data_error(format!("invalid stored authentication state: {error}")))?;
    ensure_challenge_matches(&self.challenge, &state.challenge)?;
    Ok(state)
  }
}

pub(crate) async fn web_authn_factors_by_user_id(
  pool: &PgPool,
  user_id: Uuid,
) -> Result<Vec<WebAuthnFactor>> {
  let rows = sqlx::query_as::<_, WebAuthnFactorRow>(
    "SELECT id, user_id, friendly_name, factor_type::text AS factor_type, status::text AS status, web_authn_credential_id, web_authn_credential, web_authn_aaguid, last_challenged_at, created_at, updated_at FROM auth.mfa_factors WHERE user_id = $1 AND factor_type = 'webauthn'::auth.factor_type AND status = 'verified'::auth.factor_status ORDER BY created_at ASC, id ASC",
  )
  .bind(user_id)
  .fetch_all(pool)
  .await?;
  rows.into_iter().map(TryInto::try_into).collect()
}

pub(crate) async fn web_authn_factor_count(pool: &PgPool, user_id: Uuid) -> Result<i64> {
  sqlx::query_scalar(
    "SELECT COUNT(*) FROM auth.mfa_factors WHERE user_id = $1 AND factor_type = 'webauthn'::auth.factor_type",
  )
  .bind(user_id)
  .fetch_one(pool)
  .await
  .map_err(Into::into)
}

pub(crate) async fn create_registration_flow(
  pool: &PgPool,
  user_id: Uuid,
  state: &RegistrationState,
  friendly_name: Option<&str>,
  ttl_secs: i64,
) -> Result<WebAuthnFlowRow> {
  validate_flow_state(&state.challenge, ttl_secs)?;
  let now = Utc::now();
  let expires_at = now
    .checked_add_signed(Duration::seconds(ttl_secs))
    .ok_or_else(|| stored_data_error("WebAuthn registration expiry overflow"))?;
  let mut tx = pool.begin().await?;
  let owner_locked: Option<Uuid> = sqlx::query_scalar("SELECT id FROM auth.users WHERE id = $1 FOR UPDATE")
    .bind(user_id)
    .fetch_optional(tx.as_mut())
    .await?;
  if owner_locked.is_none() {
    return Err(AuthError::PasskeyRegistrationFailed);
  }
  sqlx::query(
    "DELETE FROM auth.web_authn_flows WHERE user_id = $1 AND purpose = 'registration' AND consumed_at IS NULL",
  )
  .bind(user_id)
  .execute(tx.as_mut())
  .await?;
  let row = insert_flow(
    &mut tx,
    NewFlow {
      user_id: Some(user_id),
      purpose: FlowPurpose::Registration,
      challenge: &state.challenge,
      state: serde_json::to_value(state).map_err(serialization_error)?,
      friendly_name,
      expires_at,
      now,
    },
  )
  .await?;
  tx.commit().await?;
  spawn_cleanup(pool);
  Ok(row)
}

pub(crate) async fn create_authentication_flow(
  pool: &PgPool,
  state: &AuthenticationState,
  ttl_secs: i64,
) -> Result<WebAuthnFlowRow> {
  validate_flow_state(&state.challenge, ttl_secs)?;
  let now = Utc::now();
  let expires_at = now
    .checked_add_signed(Duration::seconds(ttl_secs))
    .ok_or_else(|| stored_data_error("WebAuthn authentication expiry overflow"))?;
  let mut tx = pool.begin().await?;
  let row = insert_flow(
    &mut tx,
    NewFlow {
      user_id: None,
      purpose: FlowPurpose::Authentication,
      challenge: &state.challenge,
      state: serde_json::to_value(state).map_err(serialization_error)?,
      friendly_name: None,
      expires_at,
      now,
    },
  )
  .await?;
  tx.commit().await?;
  spawn_cleanup(pool);
  Ok(row)
}

struct NewFlow<'a> {
  user_id: Option<Uuid>,
  purpose: FlowPurpose,
  challenge: &'a [u8],
  state: Value,
  friendly_name: Option<&'a str>,
  expires_at: DateTime<Utc>,
  now: DateTime<Utc>,
}

async fn insert_flow(tx: &mut Transaction<'_, Postgres>, flow: NewFlow<'_>) -> Result<WebAuthnFlowRow> {
  sqlx::query_as::<_, WebAuthnFlowRow>(
    "INSERT INTO auth.web_authn_flows (id, user_id, purpose, challenge, state, friendly_name, attempts, expires_at, consumed_at, created_at, updated_at) VALUES ($1, $2, $3, $4, $5, $6, 0, $7, NULL, $8, $8) RETURNING id, user_id, purpose, challenge, state, friendly_name, attempts, expires_at, consumed_at, created_at, updated_at",
  )
  .bind(Uuid::new_v4())
  .bind(flow.user_id)
  .bind(flow.purpose.as_str())
  .bind(flow.challenge)
  .bind(flow.state)
  .bind(flow.friendly_name)
  .bind(flow.expires_at)
  .bind(flow.now)
  .fetch_one(tx.as_mut())
  .await
  .map_err(Into::into)
}

pub(crate) async fn lock_registration_flow(
  tx: &mut Transaction<'_, Postgres>,
  flow_id: Uuid,
  user_id: Uuid,
  now: DateTime<Utc>,
) -> Result<WebAuthnFlowRow> {
  let row = lock_flow(tx, flow_id)
    .await
    .map_err(map_registration_repository_error)?;
  validate_locked_flow(&row, FlowPurpose::Registration, Some(user_id), now)
    .map_err(map_registration_repository_error)?;
  increment_flow_attempts(tx, row, now)
    .await
    .map_err(map_registration_repository_error)
}

pub(crate) async fn lock_authentication_flow(
  tx: &mut Transaction<'_, Postgres>,
  flow_id: Uuid,
  now: DateTime<Utc>,
) -> Result<WebAuthnFlowRow> {
  let row = lock_flow(tx, flow_id)
    .await
    .map_err(map_authentication_repository_error)?;
  validate_locked_flow(&row, FlowPurpose::Authentication, None, now)
    .map_err(map_authentication_repository_error)?;
  increment_flow_attempts(tx, row, now)
    .await
    .map_err(map_authentication_repository_error)
}

async fn lock_flow(
  tx: &mut Transaction<'_, Postgres>,
  flow_id: Uuid,
) -> std::result::Result<WebAuthnFlowRow, RepositoryError> {
  sqlx::query_as::<_, WebAuthnFlowRow>(
    "SELECT id, user_id, purpose, challenge, state, friendly_name, attempts, expires_at, consumed_at, created_at, updated_at FROM auth.web_authn_flows WHERE id = $1 FOR UPDATE",
  )
  .bind(flow_id)
  .fetch_optional(tx.as_mut())
  .await
  .map_err(RepositoryError::Database)?
  .ok_or(RepositoryError::Unavailable)
}

fn validate_locked_flow(
  row: &WebAuthnFlowRow,
  purpose: FlowPurpose,
  expected_user_id: Option<Uuid>,
  now: DateTime<Utc>,
) -> std::result::Result<(), RepositoryError> {
  if row.purpose != purpose.as_str()
    || row.user_id != expected_user_id
    || row.consumed_at.is_some()
    || row.expires_at <= now
    || row.attempts >= MAX_FLOW_ATTEMPTS
  {
    return Err(RepositoryError::Unavailable);
  }
  Ok(())
}

async fn increment_flow_attempts(
  tx: &mut Transaction<'_, Postgres>,
  mut row: WebAuthnFlowRow,
  now: DateTime<Utc>,
) -> std::result::Result<WebAuthnFlowRow, RepositoryError> {
  let updated = sqlx::query(
    "UPDATE auth.web_authn_flows SET attempts = attempts + 1, updated_at = $1 WHERE id = $2 AND consumed_at IS NULL AND attempts = $3",
  )
  .bind(now)
  .bind(row.id)
  .bind(row.attempts)
  .execute(tx.as_mut())
  .await
  .map_err(RepositoryError::Database)?;
  if updated.rows_affected() != 1 {
    return Err(RepositoryError::Unavailable);
  }
  row.attempts += 1;
  row.updated_at = now;
  Ok(row)
}

pub(crate) async fn complete_registration(
  tx: &mut Transaction<'_, Postgres>,
  flow: &WebAuthnFlowRow,
  credential: &RpCredential,
  now: DateTime<Utc>,
) -> Result<WebAuthnFactor> {
  credential
    .validate()
    .map_err(AuthError::from_passkey_registration_error)?;
  let user_id = flow.user_id.ok_or(AuthError::PasskeyRegistrationFailed)?;
  let state = flow.registration_state()?;
  if !flow_is_ready_for_completion(flow, FlowPurpose::Registration, now)
    || credential.user_handle != state.user_handle
  {
    return Err(AuthError::PasskeyRegistrationFailed);
  }
  let factor_count: i64 = sqlx::query_scalar(
    "SELECT COUNT(*) FROM auth.mfa_factors WHERE user_id = $1 AND factor_type = 'webauthn'::auth.factor_type",
  )
  .bind(user_id)
  .fetch_one(tx.as_mut())
  .await?;
  if factor_count >= MAX_WEB_AUTHN_FACTORS_PER_USER {
    return Err(AuthError::PasskeyRegistrationFailed);
  }
  if let Some(friendly_name) = flow.friendly_name.as_deref() {
    let name_exists: bool = sqlx::query_scalar(
      "SELECT EXISTS(SELECT 1 FROM auth.mfa_factors WHERE user_id = $1 AND friendly_name = $2)",
    )
    .bind(user_id)
    .bind(friendly_name)
    .fetch_one(tx.as_mut())
    .await?;
    if name_exists {
      return Err(AuthError::PasskeyRegistrationFailed);
    }
  }
  let factor_id = Uuid::new_v4();
  let credential_json = serde_json::to_value(credential).map_err(serialization_error)?;
  let row = sqlx::query_as::<_, WebAuthnFactorRow>(
    "INSERT INTO auth.mfa_factors (id, user_id, friendly_name, factor_type, status, web_authn_credential_id, web_authn_credential, web_authn_aaguid, created_at, updated_at) VALUES ($1, $2, $3, 'webauthn'::auth.factor_type, 'verified'::auth.factor_status, $4, $5, $6, $7, $7) ON CONFLICT DO NOTHING RETURNING id, user_id, friendly_name, factor_type::text AS factor_type, status::text AS status, web_authn_credential_id, web_authn_credential, web_authn_aaguid, last_challenged_at, created_at, updated_at",
  )
  .bind(factor_id)
  .bind(user_id)
  .bind(&flow.friendly_name)
  .bind(&credential.credential_id)
  .bind(credential_json)
  .bind(Uuid::from_bytes(credential.aaguid))
  .bind(now)
  .fetch_optional(tx.as_mut())
  .await?
  .ok_or(AuthError::PasskeyRegistrationFailed)?;
  consume_flow(tx, flow.id, now)
    .await
    .map_err(map_registration_repository_error)?;
  row.try_into()
}

pub(crate) async fn lock_factor_by_credential_id(
  tx: &mut Transaction<'_, Postgres>,
  credential_id: &[u8],
) -> Result<WebAuthnFactor> {
  let user_id: Uuid = sqlx::query_scalar(
    "SELECT user_id FROM auth.mfa_factors WHERE factor_type = 'webauthn'::auth.factor_type AND status = 'verified'::auth.factor_status AND web_authn_credential_id = $1",
  )
  .bind(credential_id)
  .fetch_optional(tx.as_mut())
  .await?
  .ok_or(AuthError::PasskeyAuthenticationFailed)?;
  let owner_locked: Option<Uuid> = sqlx::query_scalar("SELECT id FROM auth.users WHERE id = $1 FOR UPDATE")
    .bind(user_id)
    .fetch_optional(tx.as_mut())
    .await?;
  if owner_locked.is_none() {
    return Err(AuthError::PasskeyAuthenticationFailed);
  }
  let row = sqlx::query_as::<_, WebAuthnFactorRow>(
    "SELECT id, user_id, friendly_name, factor_type::text AS factor_type, status::text AS status, web_authn_credential_id, web_authn_credential, web_authn_aaguid, last_challenged_at, created_at, updated_at FROM auth.mfa_factors WHERE user_id = $1 AND factor_type = 'webauthn'::auth.factor_type AND status = 'verified'::auth.factor_status AND web_authn_credential_id = $2 FOR UPDATE",
  )
  .bind(user_id)
  .bind(credential_id)
  .fetch_optional(tx.as_mut())
  .await?
  .ok_or(AuthError::PasskeyAuthenticationFailed)?;
  row.try_into()
}

pub(crate) async fn complete_authentication(
  tx: &mut Transaction<'_, Postgres>,
  flow: &WebAuthnFlowRow,
  factor: &WebAuthnFactor,
  result: &AuthenticationResult,
  now: DateTime<Utc>,
) -> Result<WebAuthnFactor> {
  flow.authentication_state()?;
  if !flow_is_ready_for_completion(flow, FlowPurpose::Authentication, now)
    || result.user_handle != factor.credential.user_handle
    || (factor.credential.sign_count > 0 && result.sign_count <= factor.credential.sign_count)
    || (!factor.credential.backup_eligible && result.backup_state)
  {
    return Err(AuthError::PasskeyAuthenticationFailed);
  }
  let mut credential = factor.credential.clone();
  credential.sign_count = result.sign_count;
  credential.backup_state = result.backup_state;
  credential
    .validate()
    .map_err(AuthError::from_passkey_authentication_error)?;
  let credential_json = serde_json::to_value(&credential).map_err(serialization_error)?;
  let previous_credential_json = serde_json::to_value(&factor.credential).map_err(serialization_error)?;
  let row = sqlx::query_as::<_, WebAuthnFactorRow>(
    "UPDATE auth.mfa_factors SET web_authn_credential = $1, last_challenged_at = $2, updated_at = $2 WHERE id = $3 AND factor_type = 'webauthn'::auth.factor_type AND web_authn_credential = $4 RETURNING id, user_id, friendly_name, factor_type::text AS factor_type, status::text AS status, web_authn_credential_id, web_authn_credential, web_authn_aaguid, last_challenged_at, created_at, updated_at",
  )
  .bind(credential_json)
  .bind(now)
  .bind(factor.id)
  .bind(previous_credential_json)
  .fetch_optional(tx.as_mut())
  .await?
  .ok_or(AuthError::PasskeyAuthenticationFailed)?;
  consume_flow(tx, flow.id, now)
    .await
    .map_err(map_authentication_repository_error)?;
  row.try_into()
}

fn flow_is_ready_for_completion(flow: &WebAuthnFlowRow, purpose: FlowPurpose, now: DateTime<Utc>) -> bool {
  flow.purpose == purpose.as_str()
    && flow.consumed_at.is_none()
    && flow.expires_at > now
    && (1..=MAX_FLOW_ATTEMPTS).contains(&flow.attempts)
}

async fn consume_flow(
  tx: &mut Transaction<'_, Postgres>,
  flow_id: Uuid,
  now: DateTime<Utc>,
) -> std::result::Result<(), RepositoryError> {
  let result = sqlx::query(
    "UPDATE auth.web_authn_flows SET consumed_at = $1, updated_at = $1 WHERE id = $2 AND consumed_at IS NULL",
  )
  .bind(now)
  .bind(flow_id)
  .execute(tx.as_mut())
  .await
  .map_err(RepositoryError::Database)?;
  if result.rows_affected() == 1 {
    Ok(())
  } else {
    Err(RepositoryError::Unavailable)
  }
}

pub(crate) async fn cleanup_flows(pool: &PgPool, now: DateTime<Utc>) -> Result<u64> {
  let expired = sqlx::query(
    "WITH doomed AS (SELECT id FROM auth.web_authn_flows WHERE expires_at <= $1 ORDER BY updated_at ASC LIMIT $2) DELETE FROM auth.web_authn_flows AS flows USING doomed WHERE flows.id = doomed.id",
  )
  .bind(now)
  .bind(CLEANUP_BATCH_SIZE)
  .execute(pool)
  .await?
  .rows_affected();
  let consumed_cutoff = now - Duration::hours(CONSUMED_FLOW_RETENTION_HOURS);
  let consumed = sqlx::query(
    "WITH doomed AS (SELECT id FROM auth.web_authn_flows WHERE consumed_at IS NOT NULL AND consumed_at <= $1 ORDER BY updated_at ASC LIMIT $2) DELETE FROM auth.web_authn_flows AS flows USING doomed WHERE flows.id = doomed.id",
  )
  .bind(consumed_cutoff)
  .bind(CLEANUP_BATCH_SIZE)
  .execute(pool)
  .await?
  .rows_affected();
  Ok(expired + consumed)
}

fn spawn_cleanup(pool: &PgPool) {
  let pool = pool.clone();
  tokio::spawn(async move {
    if let Err(error) = cleanup_flows(&pool, Utc::now()).await {
      tracing::warn!(error = %error, "WebAuthn flow cleanup failed");
    }
  });
}

fn validate_flow_state(challenge: &[u8], ttl_secs: i64) -> Result<()> {
  if challenge.len() != 32 || !(60..=600).contains(&ttl_secs) {
    return Err(AuthError::InternalError(
      "invalid WebAuthn flow state supplied by validated RP".to_owned(),
    ));
  }
  Ok(())
}

fn ensure_challenge_matches(indexed: &[u8], state: &[u8]) -> Result<()> {
  if indexed == state && indexed.len() == 32 {
    Ok(())
  } else {
    Err(stored_data_error(
      "stored WebAuthn flow challenge does not match serialized state",
    ))
  }
}

fn serialization_error(error: serde_json::Error) -> AuthError {
  AuthError::InternalError(format!("failed to serialize WebAuthn state: {error}"))
}

fn stored_data_error(message: impl Into<String>) -> AuthError {
  AuthError::InternalError(message.into())
}

#[derive(Debug)]
enum RepositoryError {
  Database(sqlx::Error),
  Unavailable,
}

fn map_registration_repository_error(error: RepositoryError) -> AuthError {
  match error {
    RepositoryError::Database(error) => AuthError::DatabaseError(error),
    RepositoryError::Unavailable => AuthError::PasskeyRegistrationFailed,
  }
}

fn map_authentication_repository_error(error: RepositoryError) -> AuthError {
  match error {
    RepositoryError::Database(error) => AuthError::DatabaseError(error),
    RepositoryError::Unavailable => AuthError::PasskeyAuthenticationFailed,
  }
}

#[cfg(test)]
mod tests;
