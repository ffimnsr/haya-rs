use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use chrono::Utc;
use rand::RngCore;
use uuid::Uuid;

use crate::auth::jwt;
use crate::error::{
  AuthError,
  Result,
};
use crate::model::{
  SessionAmrClaimRow,
  SessionRow,
  TokenResponse,
  User,
  UserResponse,
};
use crate::state::AppState;

pub async fn issue_session(state: &AppState, user: &User, method: &str) -> Result<TokenResponse> {
  issue_session_with_context(state, user, "aal1", None, vec![method.to_string()]).await
}

pub async fn issue_session_with_context(
  state: &AppState,
  user: &User,
  aal: &str,
  factor_id: Option<Uuid>,
  methods: Vec<String>,
) -> Result<TokenResponse> {
  let now = Utc::now();
  let session_id = Uuid::new_v4();
  let mut tx = state.db.begin().await?;

  sqlx::query(
    "INSERT INTO auth.sessions (id, user_id, factor_id, aal, created_at, updated_at) VALUES ($1, $2, $3, $4::auth.aal_level, $5, $6)",
  )
  .bind(session_id)
  .bind(user.id)
  .bind(factor_id)
  .bind(aal)
  .bind(now)
  .bind(now)
  .execute(&mut *tx)
  .await?;

  for method in &methods {
    sqlx::query(
      "INSERT INTO auth.mfa_amr_claims (id, session_id, created_at, updated_at, authentication_method) VALUES ($1, $2, $3, $4, $5) ON CONFLICT (session_id, authentication_method) DO NOTHING",
    )
    .bind(Uuid::new_v4())
    .bind(session_id)
    .bind(now)
    .bind(now)
    .bind(method)
    .execute(&mut *tx)
    .await?;
  }

  let refresh_token = generate_refresh_token();
  sqlx::query(
    "INSERT INTO auth.refresh_tokens (instance_id, user_id, token, session_id, revoked, created_at, updated_at) VALUES ($1, $2, $3, $4, false, $5, $6)",
  )
  .bind(state.instance_id)
  .bind(user.id.to_string())
  .bind(&refresh_token)
  .bind(session_id)
  .bind(now)
  .bind(now)
  .execute(&mut *tx)
  .await?;

  sqlx::query("UPDATE auth.users SET last_sign_in_at = $1, updated_at = $2 WHERE id = $3")
    .bind(now)
    .bind(now)
    .bind(user.id)
    .execute(&mut *tx)
    .await?;

  tx.commit().await?;

  let amr = methods
    .into_iter()
    .map(|method| jwt::AmrEntry {
      method,
      timestamp: now.timestamp(),
    })
    .collect();

  build_token_response(state, user, session_id, aal, amr, refresh_token).await
}

pub fn generate_refresh_token() -> String {
  let mut bytes = [0u8; 32];
  rand::rng().fill_bytes(&mut bytes);
  URL_SAFE_NO_PAD.encode(bytes)
}

pub async fn build_token_response(
  state: &AppState,
  user: &User,
  session_id: Uuid,
  aal: &str,
  amr: Vec<jwt::AmrEntry>,
  refresh_token: String,
) -> Result<TokenResponse> {
  let now = Utc::now();
  let app_meta = user.raw_app_meta_data.clone().unwrap_or(serde_json::json!({}));
  let user_meta = user.raw_user_meta_data.clone().unwrap_or(serde_json::json!({}));
  let role = user.role.as_deref().unwrap_or("authenticated");
  let access_token = jwt::encode_token(
    user.id,
    user.email.clone(),
    user.phone.clone(),
    role,
    session_id,
    user.is_anonymous,
    aal,
    amr,
    user_meta,
    app_meta,
    &state.jwt_secret,
    state.jwt_exp,
    &state.issuer,
  )?;

  let expires_at = now.timestamp() + state.jwt_exp;
  let user_response = UserResponse::from_user(&state.db, user.clone()).await?;
  Ok(TokenResponse {
    access_token,
    token_type: "bearer".to_string(),
    expires_in: state.jwt_exp,
    expires_at,
    refresh_token,
    user: user_response,
  })
}

pub async fn load_session_context(
  state: &AppState,
  session_id: Uuid,
) -> Result<(SessionRow, Vec<jwt::AmrEntry>)> {
  let session: SessionRow = sqlx::query_as::<_, SessionRow>(
    "SELECT id, user_id, factor_id, aal::text as aal, not_after, created_at, updated_at FROM auth.sessions WHERE id = $1",
  )
  .bind(session_id)
  .fetch_one(&state.db)
  .await?;
  let claims: Vec<SessionAmrClaimRow> = sqlx::query_as::<_, SessionAmrClaimRow>(
    "SELECT authentication_method, created_at FROM auth.mfa_amr_claims WHERE session_id = $1 ORDER BY created_at ASC",
  )
  .bind(session_id)
  .fetch_all(&state.db)
  .await?;

  let amr = claims
    .into_iter()
    .map(|claim| jwt::AmrEntry {
      method: claim.authentication_method,
      timestamp: claim.created_at.timestamp(),
    })
    .collect();

  Ok((session, amr))
}

pub async fn ensure_active_session(state: &AppState, claims: &jwt::Claims) -> Result<SessionRow> {
  let session_id = claims
    .session_id
    .parse::<Uuid>()
    .map_err(|_| AuthError::NotAuthorized)?;
  let user_id = claims.sub.parse::<Uuid>().map_err(|_| AuthError::NotAuthorized)?;
  let session: SessionRow = sqlx::query_as::<_, SessionRow>(
    "SELECT id, user_id, factor_id, aal::text as aal, not_after, created_at, updated_at FROM auth.sessions WHERE id = $1",
  )
  .bind(session_id)
  .fetch_optional(&state.db)
  .await?
  .ok_or(AuthError::NotAuthorized)?;

  if session.user_id != user_id {
    return Err(AuthError::NotAuthorized);
  }

  if session
    .not_after
    .map(|value| value <= Utc::now())
    .unwrap_or(false)
  {
    return Err(AuthError::NotAuthorized);
  }

  Ok(session)
}
