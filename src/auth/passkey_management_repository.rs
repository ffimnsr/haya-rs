use chrono::{
  DateTime,
  Utc,
};
use sqlx::{
  Postgres,
  Transaction,
};
use uuid::Uuid;

use crate::error::{
  AuthError,
  Result,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct SignInMethods {
  has_password: bool,
  other_passkey_count: usize,
  has_active_oidc_identity: bool,
}

impl SignInMethods {
  fn can_remove_passkey(self) -> bool {
    self.has_password || self.other_passkey_count > 0 || self.has_active_oidc_identity
  }
}

pub(crate) async fn delete_owned_passkey(
  tx: &mut Transaction<'_, Postgres>,
  user_id: Uuid,
  factor_id: Uuid,
  active_oidc_providers: &[String],
  now: DateTime<Utc>,
) -> Result<()> {
  let encrypted_password: Option<String> =
    sqlx::query_scalar("SELECT encrypted_password FROM auth.users WHERE id = $1 FOR UPDATE")
      .bind(user_id)
      .fetch_optional(tx.as_mut())
      .await?
      .ok_or(AuthError::UserNotFound)?;

  let passkey_ids: Vec<Uuid> = sqlx::query_scalar(
    "SELECT id FROM auth.mfa_factors WHERE user_id = $1 AND factor_type = 'webauthn'::auth.factor_type AND status = 'verified'::auth.factor_status ORDER BY id FOR UPDATE",
  )
  .bind(user_id)
  .fetch_all(tx.as_mut())
  .await?;
  if !passkey_ids.contains(&factor_id) {
    return Err(AuthError::UserNotFound);
  }

  let has_active_oidc_identity = if active_oidc_providers.is_empty() {
    false
  } else {
    sqlx::query_scalar::<_, String>(
      "SELECT providers.name FROM auth.oidc_providers AS providers INNER JOIN auth.identities AS identities ON identities.provider = providers.name AND identities.user_id = $1 WHERE providers.name = ANY($2) ORDER BY providers.name LIMIT 1 FOR KEY SHARE OF providers",
    )
    .bind(user_id)
    .bind(active_oidc_providers)
    .fetch_optional(tx.as_mut())
    .await?
    .is_some()
  };
  let methods = SignInMethods {
    has_password: encrypted_password.is_some_and(|hash| !hash.trim().is_empty()),
    other_passkey_count: passkey_ids.len().saturating_sub(1),
    has_active_oidc_identity,
  };
  if !methods.can_remove_passkey() {
    return Err(AuthError::ValidationFailed(
      "Cannot delete the final usable sign-in method".to_owned(),
    ));
  }

  sqlx::query("DELETE FROM auth.sessions WHERE factor_id = $1")
    .bind(factor_id)
    .execute(tx.as_mut())
    .await?;
  let deleted = sqlx::query(
    "DELETE FROM auth.mfa_factors WHERE id = $1 AND user_id = $2 AND factor_type = 'webauthn'::auth.factor_type AND status = 'verified'::auth.factor_status",
  )
  .bind(factor_id)
  .bind(user_id)
  .execute(tx.as_mut())
  .await?;
  if deleted.rows_affected() != 1 {
    return Err(AuthError::UserNotFound);
  }
  sqlx::query("UPDATE auth.users SET updated_at = $1 WHERE id = $2")
    .bind(now)
    .bind(user_id)
    .execute(tx.as_mut())
    .await?;
  Ok(())
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn final_sign_in_method_policy_covers_supported_account_shapes() {
    let methods = |has_password, other_passkey_count, has_active_oidc_identity| SignInMethods {
      has_password,
      other_passkey_count,
      has_active_oidc_identity,
    };

    assert!(methods(true, 0, false).can_remove_passkey());
    assert!(methods(false, 1, false).can_remove_passkey());
    assert!(methods(false, 0, true).can_remove_passkey());
    assert!(!methods(false, 0, false).can_remove_passkey());
  }
}
