use axum::Json;
use axum::extract::{
  ConnectInfo,
  Path,
  Query,
  State,
};
use chrono::{
  DateTime,
  Utc,
};
use serde::Deserialize;
use serde_json::{
  Value,
  json,
};
use std::net::SocketAddr;
use uuid::Uuid;

use crate::auth::audit;
use crate::error::Result;
use crate::middleware::auth::AdminUser;
use crate::model::invite_code::{
  create_invite_code,
  list_invite_codes,
  revoke_invite_code,
};
use crate::state::AppState;

#[derive(Debug, Deserialize)]
pub struct CreateInviteCodeRequest {
  pub label: Option<String>,
  pub note: Option<String>,
  /// RFC 3339 timestamp. Omit for a code that does not expire.
  pub expires_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Deserialize)]
pub struct ListInviteCodesQuery {
  pub limit: Option<i64>,
}

pub async fn admin_create_invite_code(
  State(state): State<AppState>,
  ConnectInfo(client_addr): ConnectInfo<SocketAddr>,
  AdminUser(claims): AdminUser,
  Json(req): Json<CreateInviteCodeRequest>,
) -> Result<Json<Value>> {
  let created_by = Uuid::parse_str(&claims.sub).ok();
  let mut tx = state.db.begin().await?;
  let (invite, plaintext) =
    create_invite_code(&mut tx, created_by, req.label, req.note, req.expires_at).await?;
  audit::log_event_tx(
    tx.as_mut(),
    state.instance_id,
    Some(client_addr.ip()),
    "invite_code_created",
    json!({
      "invite_code_id": invite.id,
      "label": invite.label,
      "expires_at": invite.expires_at,
      "created_by": created_by,
    }),
  )
  .await?;
  tx.commit().await?;

  Ok(Json(json!({
    "id": invite.id,
    "code": plaintext,
    "label": invite.label,
    "note": invite.note,
    "expires_at": invite.expires_at,
    "status": invite.status,
    "created_at": invite.created_at,
  })))
}

pub async fn admin_list_invite_codes(
  State(state): State<AppState>,
  Query(query): Query<ListInviteCodesQuery>,
  AdminUser(_claims): AdminUser,
) -> Result<Json<Value>> {
  let invites = list_invite_codes(&state.db, query.limit.unwrap_or(100)).await?;
  Ok(Json(json!({ "invite_codes": invites })))
}

pub async fn admin_revoke_invite_code(
  State(state): State<AppState>,
  ConnectInfo(client_addr): ConnectInfo<SocketAddr>,
  AdminUser(claims): AdminUser,
  Path(id): Path<Uuid>,
) -> Result<Json<Value>> {
  let revoked_by = Uuid::parse_str(&claims.sub).ok();
  let mut tx = state.db.begin().await?;
  let invite = revoke_invite_code(&mut tx, id).await?;
  audit::log_event_tx(
    tx.as_mut(),
    state.instance_id,
    Some(client_addr.ip()),
    "invite_code_revoked",
    json!({
      "invite_code_id": invite.id,
      "label": invite.label,
      "revoked_by": revoked_by,
    }),
  )
  .await?;
  tx.commit().await?;

  Ok(Json(json!({ "id": invite.id, "status": invite.status })))
}
