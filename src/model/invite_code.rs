use chrono::{
  DateTime,
  Utc,
};
use serde::Serialize;
use sqlx::{
  FromRow,
  PgConnection,
  PgPool,
};
use uuid::Uuid;

use crate::error::{
  AuthError,
  Result,
};
use crate::utils::sha256_hex;

pub(crate) const MAX_INVITE_CODE_LEN: usize = 256;
pub(crate) const MAX_INVITE_LABEL_LEN: usize = 120;
pub(crate) const MAX_INVITE_NOTE_LEN: usize = 500;

const INVITE_CODE_COLUMNS: &str = "id, label, note, created_by, expires_at, used_at, used_by, revoked_at, created_at, updated_at, \
  case \
    when revoked_at is not null then 'revoked' \
    when used_at is not null then 'used' \
    when expires_at is not null and expires_at <= now() then 'expired' \
    else 'active' \
  end as status";

#[derive(Debug, Clone, Serialize, FromRow)]
pub(crate) struct InviteCode {
  pub id: Uuid,
  pub label: Option<String>,
  pub note: Option<String>,
  pub created_by: Option<Uuid>,
  pub expires_at: Option<DateTime<Utc>>,
  pub used_at: Option<DateTime<Utc>>,
  pub used_by: Option<Uuid>,
  pub revoked_at: Option<DateTime<Utc>>,
  pub created_at: DateTime<Utc>,
  pub updated_at: DateTime<Utc>,
  /// Derived in SQL: `active`, `used`, `expired`, or `revoked`.
  pub status: String,
}

/// Generate an opaque, high-entropy invite code. `Uuid::new_v4` provides 122
/// random bits; the hex form is easy to paste and has no ambiguous separators.
pub(crate) fn generate_invite_code() -> String {
  Uuid::new_v4().simple().to_string()
}

fn normalize_invite_code(raw: &str) -> Option<String> {
  let code = raw.trim().to_ascii_lowercase();
  if code.is_empty() || code.len() > MAX_INVITE_CODE_LEN {
    return None;
  }
  Some(code)
}

fn invite_code_hash(code: &str) -> String {
  sha256_hex(&code.trim().to_ascii_lowercase())
}

fn normalize_optional_text(value: Option<String>, field: &str, max_len: usize) -> Result<Option<String>> {
  let Some(value) = value else {
    return Ok(None);
  };
  let value = value.trim();
  if value.is_empty() {
    return Ok(None);
  }
  if value.chars().count() > max_len {
    return Err(AuthError::ValidationFailed(format!(
      "{field} must be at most {max_len} characters."
    )));
  }
  Ok(Some(value.to_string()))
}

pub(crate) async fn create_invite_code(
  conn: &mut PgConnection,
  created_by: Option<Uuid>,
  label: Option<String>,
  note: Option<String>,
  expires_at: Option<DateTime<Utc>>,
) -> Result<(InviteCode, String)> {
  let label = normalize_optional_text(label, "label", MAX_INVITE_LABEL_LEN)?;
  let note = normalize_optional_text(note, "note", MAX_INVITE_NOTE_LEN)?;
  if let Some(expires_at) = expires_at
    && expires_at <= Utc::now()
  {
    return Err(AuthError::ValidationFailed(
      "expires_at must be in the future.".to_string(),
    ));
  }

  let plaintext = generate_invite_code();
  let code_hash = invite_code_hash(&plaintext);
  let id = Uuid::new_v4();
  let invite = sqlx::query_as::<_, InviteCode>(&format!(
    "INSERT INTO auth.invite_codes (id, code_hash, label, note, created_by, expires_at, created_at, updated_at) \
     VALUES ($1, $2, $3, $4, $5, $6, now(), now()) \
     RETURNING {INVITE_CODE_COLUMNS}"
  ))
  .bind(id)
  .bind(code_hash)
  .bind(&label)
  .bind(&note)
  .bind(created_by)
  .bind(expires_at)
  .fetch_one(conn)
  .await?;

  Ok((invite, plaintext))
}

pub(crate) async fn list_invite_codes(db: &PgPool, limit: i64) -> Result<Vec<InviteCode>> {
  let limit = limit.clamp(1, 200);
  let invites = sqlx::query_as::<_, InviteCode>(&format!(
    "SELECT {INVITE_CODE_COLUMNS} FROM auth.invite_codes ORDER BY created_at DESC LIMIT $1"
  ))
  .bind(limit)
  .fetch_all(db)
  .await?;
  Ok(invites)
}

pub(crate) async fn revoke_invite_code(conn: &mut PgConnection, id: Uuid) -> Result<InviteCode> {
  let invite = sqlx::query_as::<_, InviteCode>(&format!(
    "UPDATE auth.invite_codes SET revoked_at = now(), updated_at = now() \
     WHERE id = $1 AND used_at IS NULL AND revoked_at IS NULL \
     RETURNING {INVITE_CODE_COLUMNS}"
  ))
  .bind(id)
  .fetch_optional(&mut *conn)
  .await?;

  if let Some(invite) = invite {
    return Ok(invite);
  }

  let exists: Option<(Uuid,)> =
    sqlx::query_as::<_, (Uuid,)>("SELECT id FROM auth.invite_codes WHERE id = $1")
      .bind(id)
      .fetch_optional(conn)
      .await?;
  if exists.is_none() {
    return Err(AuthError::InviteCodeNotFound);
  }
  Err(AuthError::InviteCodeNotActive)
}

/// Validate a code without consuming it. Signup uses this before its
/// anti-enumeration email check so an invalid code cannot distinguish existing
/// accounts from new ones; the authoritative check remains the atomic consume.
pub(crate) async fn validate_invite_code(db: &PgPool, raw: &str) -> Result<()> {
  let code = normalize_invite_code(raw).ok_or(AuthError::InvalidInviteCode)?;
  let invite: Option<(Uuid,)> = sqlx::query_as(
    "SELECT id FROM auth.invite_codes \
     WHERE code_hash = $1 AND used_at IS NULL AND revoked_at IS NULL \
       AND (expires_at IS NULL OR expires_at > now())",
  )
  .bind(invite_code_hash(&code))
  .fetch_optional(db)
  .await?;
  invite.map(|_| ()).ok_or(AuthError::InvalidInviteCode)
}

/// Atomically consume a one-time code. A concurrent signup using the same code
/// loses the `used_at IS NULL` predicate after the first transaction commits,
/// so only one user can redeem it.
pub(crate) async fn consume_invite_code(conn: &mut PgConnection, raw: &str) -> Result<Uuid> {
  let code = normalize_invite_code(raw).ok_or(AuthError::InvalidInviteCode)?;
  let invite: Option<(Uuid,)> = sqlx::query_as(
    "UPDATE auth.invite_codes SET used_at = now(), updated_at = now() \
     WHERE code_hash = $1 AND used_at IS NULL AND revoked_at IS NULL \
       AND (expires_at IS NULL OR expires_at > now()) \
     RETURNING id",
  )
  .bind(invite_code_hash(&code))
  .fetch_optional(conn)
  .await?;

  invite.map(|(id,)| id).ok_or(AuthError::InvalidInviteCode)
}

pub(crate) async fn mark_invite_code_used_by(
  conn: &mut PgConnection,
  invite_id: Uuid,
  user_id: Uuid,
) -> Result<()> {
  let result = sqlx::query(
    "UPDATE auth.invite_codes SET used_by = $1, updated_at = now() WHERE id = $2 AND used_at IS NOT NULL",
  )
  .bind(user_id)
  .bind(invite_id)
  .execute(conn)
  .await?;
  if result.rows_affected() != 1 {
    return Err(AuthError::InternalError(
      "invite code consumption could not be persisted".to_string(),
    ));
  }
  Ok(())
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn generated_codes_are_high_entropy_and_normalizable() {
    let code = generate_invite_code();
    assert_eq!(code.len(), 32);
    assert!(code.chars().all(|c| c.is_ascii_hexdigit()));

    let normalized = normalize_invite_code(&format!("  {}  ", code.to_uppercase())).expect("valid code");
    assert_eq!(normalized, code);
  }

  #[test]
  fn blank_and_oversized_codes_are_rejected() {
    assert_eq!(normalize_invite_code("   "), None);
    assert_eq!(normalize_invite_code(&"a".repeat(MAX_INVITE_CODE_LEN + 1)), None);
  }

  #[test]
  fn code_hashes_are_stable_and_case_insensitive() {
    let code = generate_invite_code();
    assert_eq!(invite_code_hash(&code), invite_code_hash(&code.to_uppercase()));
    assert_ne!(invite_code_hash(&code), invite_code_hash(&generate_invite_code()));
  }

  #[test]
  fn optional_text_is_trimmed_and_bounded() {
    assert_eq!(
      normalize_optional_text(Some("  team-a  ".to_string()), "label", 10).unwrap(),
      Some("team-a".to_string())
    );
    assert_eq!(
      normalize_optional_text(Some("   ".to_string()), "label", 10).unwrap(),
      None
    );
    assert!(normalize_optional_text(Some("x".repeat(11)), "label", 10).is_err());
  }
}
