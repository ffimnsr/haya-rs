mod support;

use serde_json::Value;
use sha2::{
  Digest,
  Sha256,
};
use sqlx::PgPool;
use support::{
  create_session,
  insert_user,
  issue_access_token,
  test_context_with_require_invite_code,
  unique_suffix,
};
use uuid::Uuid;

struct AdminSession {
  token: String,
}

async fn admin_session(ctx: &support::TestContext) -> AdminSession {
  let email = format!("invite-admin-{}@example.com", unique_suffix());
  let user_id = insert_user(&ctx.pool, &email).await;
  sqlx::query("UPDATE auth.users SET role = 'service_role' WHERE id = $1")
    .bind(user_id)
    .execute(&ctx.pool)
    .await
    .expect("promote invite admin");
  let session_id = create_session(&ctx.pool, user_id).await;
  let token = issue_access_token(&ctx.issuer, &ctx.jwt_secret, user_id, session_id, &email);
  AdminSession { token }
}

async fn count_users_with_email(pool: &PgPool, email: &str) -> i64 {
  sqlx::query_scalar("SELECT COUNT(*) FROM auth.users WHERE email = $1")
    .bind(email)
    .fetch_one(pool)
    .await
    .expect("count users")
}

fn invite_code_hash(code: &str) -> String {
  let digest = Sha256::digest(code.as_bytes());
  format!("{digest:x}")
}

async fn create_code(ctx: &support::TestContext, admin: &AdminSession, label: &str) -> Value {
  let response = ctx
    .client
    .post(format!("{}/admin/invite-codes", ctx.base_url))
    .bearer_auth(&admin.token)
    .json(&serde_json::json!({ "label": label }))
    .send()
    .await
    .expect("create invite code");
  assert_eq!(response.status(), reqwest::StatusCode::OK);
  response.json().await.expect("invite code json")
}

#[tokio::test]
async fn signup_requires_a_one_time_invite_code_when_enabled() {
  let Some(ctx) = test_context_with_require_invite_code().await else {
    return;
  };
  let admin = admin_session(&ctx).await;

  let blocked_email = format!("invite-blocked-{}@example.com", unique_suffix());
  let blocked = ctx
    .client
    .post(format!("{}/signup", ctx.base_url))
    .json(&serde_json::json!({
      "email": blocked_email,
      "password": "N3w-Password!2026",
    }))
    .send()
    .await
    .expect("signup without invite");
  assert_eq!(blocked.status(), reqwest::StatusCode::BAD_REQUEST);
  let blocked: Value = blocked.json().await.expect("blocked signup json");
  assert_eq!(blocked["error_code"], "invite_code_required");
  assert_eq!(count_users_with_email(&ctx.pool, &blocked_email).await, 0);

  let created = create_code(&ctx, &admin, "single-use").await;
  let code = created["code"]
    .as_str()
    .expect("plaintext invite code")
    .to_string();

  let invited_email = format!("invite-used-{}@example.com", unique_suffix());
  let invited = ctx
    .client
    .post(format!("{}/signup", ctx.base_url))
    .json(&serde_json::json!({
      "email": invited_email,
      "password": "N3w-Password!2026",
      "invite_code": code,
    }))
    .send()
    .await
    .expect("signup with invite");
  assert_eq!(invited.status(), reqwest::StatusCode::OK);
  assert_eq!(count_users_with_email(&ctx.pool, &invited_email).await, 1);

  let invite_id = Uuid::parse_str(created["id"].as_str().expect("invite id")).expect("uuid");
  let used_by: Option<Uuid> = sqlx::query_scalar("SELECT used_by FROM auth.invite_codes WHERE id = $1")
    .bind(invite_id)
    .fetch_one(&ctx.pool)
    .await
    .expect("used_by");
  let invited_user_id: Uuid = sqlx::query_scalar("SELECT id FROM auth.users WHERE email = $1")
    .bind(&invited_email)
    .fetch_one(&ctx.pool)
    .await
    .expect("invited user id");
  assert_eq!(used_by, Some(invited_user_id));

  let listed = ctx
    .client
    .get(format!("{}/admin/invite-codes", ctx.base_url))
    .bearer_auth(&admin.token)
    .send()
    .await
    .expect("list invite codes");
  assert_eq!(listed.status(), reqwest::StatusCode::OK);
  let listed: Value = listed.json().await.expect("invite list json");
  let listed_invite = listed["invite_codes"]
    .as_array()
    .expect("invite_codes array")
    .iter()
    .find(|invite| invite["id"] == created["id"])
    .expect("created invite in list");
  assert_eq!(listed_invite["status"], "used");

  // A used code must not create a second account.
  let second_email = format!("invite-reused-{}@example.com", unique_suffix());
  let reused = ctx
    .client
    .post(format!("{}/signup", ctx.base_url))
    .json(&serde_json::json!({
      "email": second_email,
      "password": "N3w-Password!2026",
      "invite_code": code,
    }))
    .send()
    .await
    .expect("reuse invite");
  assert_eq!(reused.status(), reqwest::StatusCode::BAD_REQUEST);
  let reused: Value = reused.json().await.expect("reuse json");
  assert_eq!(reused["error_code"], "invite_code_invalid");
  assert_eq!(count_users_with_email(&ctx.pool, &second_email).await, 0);

  // Revoking an unused code blocks redemption and is idempotency-safe.
  let revoked = create_code(&ctx, &admin, "revoked").await;
  let revoke_url = format!(
    "{}/admin/invite-codes/{}",
    ctx.base_url,
    revoked["id"].as_str().expect("revoke id")
  );
  let response = ctx
    .client
    .delete(&revoke_url)
    .bearer_auth(&admin.token)
    .send()
    .await
    .expect("revoke invite");
  assert_eq!(response.status(), reqwest::StatusCode::OK);

  let revoked_email = format!("invite-revoked-{}@example.com", unique_suffix());
  let rejected = ctx
    .client
    .post(format!("{}/signup", ctx.base_url))
    .json(&serde_json::json!({
      "email": revoked_email,
      "password": "N3w-Password!2026",
      "invite_code": revoked["code"].as_str().expect("revoked code"),
    }))
    .send()
    .await
    .expect("signup with revoked code");
  assert_eq!(rejected.status(), reqwest::StatusCode::BAD_REQUEST);
  assert_eq!(count_users_with_email(&ctx.pool, &revoked_email).await, 0);

  // Expired codes are rejected by the database predicate.
  let expired_code = format!("expired-{}", unique_suffix());
  sqlx::query(
    "INSERT INTO auth.invite_codes (id, code_hash, label, expires_at, created_at, updated_at) VALUES ($1, $2, 'expired', now() - interval '1 hour', now(), now())",
  )
  .bind(Uuid::new_v4())
  .bind(invite_code_hash(&expired_code))
  .execute(&ctx.pool)
  .await
  .expect("insert expired invite code");
  let expired_email = format!("invite-expired-{}@example.com", unique_suffix());
  let expired = ctx
    .client
    .post(format!("{}/signup", ctx.base_url))
    .json(&serde_json::json!({
      "email": expired_email,
      "password": "N3w-Password!2026",
      "invite_code": expired_code,
    }))
    .send()
    .await
    .expect("signup with expired code");
  assert_eq!(expired.status(), reqwest::StatusCode::BAD_REQUEST);
  let expired: Value = expired.json().await.expect("expired signup json");
  assert_eq!(expired["error_code"], "invite_code_invalid");
  assert_eq!(count_users_with_email(&ctx.pool, &expired_email).await, 0);

  let repeat = ctx
    .client
    .delete(&revoke_url)
    .bearer_auth(&admin.token)
    .send()
    .await
    .expect("revoke invite again");
  assert_eq!(repeat.status(), reqwest::StatusCode::CONFLICT);
  let repeat: Value = repeat.json().await.expect("repeat revoke json");
  assert_eq!(repeat["error_code"], "invite_code_not_active");
}
