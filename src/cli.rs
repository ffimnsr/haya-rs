use std::process::Command as ProcessCommand;

use anyhow::{
  Context,
  bail,
};
use chrono::Utc;
use clap::{
  ArgAction,
  Args,
  Parser,
  Subcommand,
  ValueEnum,
};
use serde::Serialize;
use serde_json::Value;
use sqlx::{
  FromRow,
  PgPool,
  Postgres,
  QueryBuilder,
};
use tokio::time::{
  Duration,
  sleep,
};
use uuid::Uuid;

use crate::auth::{
  jwt,
  oidc,
  password,
  session,
};
use crate::mailer::EmailKind;
use crate::model::{
  User,
  UserResponse,
};
use crate::public::handler::admin::{
  parse_ban_duration,
  validate_password_policy,
  validate_role,
};
use crate::public::handler::signup::is_valid_email;
use crate::state::{
  AppState,
  RuntimeConfig,
};
use crate::{
  public,
  utils,
};

const USER_SELECT_SQL: &str = "SELECT id, instance_id, aud, role, email, encrypted_password, email_confirmed_at, phone, phone_confirmed_at, confirmed_at, last_sign_in_at, raw_app_meta_data, raw_user_meta_data, is_super_admin, is_sso_user, is_anonymous, banned_until, deleted_at, created_at, updated_at FROM auth.users";
const ADMIN_ROLES: &[&str] = &["service_role", "supabase_admin"];

#[derive(Debug, Parser)]
#[command(name = "haya", about = "Haya auth server and database administration CLI")]
pub struct Cli {
  #[command(subcommand)]
  pub command: Option<Command>,
}

impl Cli {
  pub fn runs_server(&self) -> bool {
    matches!(self.command, None | Some(Command::Serve(_)))
  }

  pub fn needs_app_state(&self) -> bool {
    matches!(
      self.command,
      None
        | Some(Command::Serve(_))
        | Some(Command::Status)
        | Some(Command::Token { .. })
        | Some(Command::Sso { .. })
        | Some(Command::Admin { .. })
        | Some(Command::User { .. })
    )
  }

  pub fn needs_database(&self) -> bool {
    matches!(
      self.command,
      Some(Command::Doctor)
        | Some(Command::Db { .. })
        | Some(Command::Session { .. })
        | Some(Command::Mfa { .. })
        | Some(Command::Audit { .. })
    )
  }
}

#[derive(Debug, Subcommand)]
pub enum Command {
  Serve(ServeArgs),
  Heartbeat,
  Status,
  Settings,
  Reload,
  Doctor,
  Config {
    #[command(subcommand)]
    command: ConfigCommand,
  },
  Db {
    #[command(subcommand)]
    command: DbCommand,
  },
  Session {
    #[command(subcommand)]
    command: SessionCommand,
  },
  Mfa {
    #[command(subcommand)]
    command: MfaCommand,
  },
  Token {
    #[command(subcommand)]
    command: TokenCommand,
  },
  Audit {
    #[command(subcommand)]
    command: AuditCommand,
  },
  Sso {
    #[command(subcommand)]
    command: SsoCommand,
  },
  Admin {
    #[command(subcommand)]
    command: AdminCommand,
  },
  User {
    #[command(subcommand)]
    command: UserCommand,
  },
}

#[derive(Debug, Args)]
pub struct ServeArgs {
  #[arg(long)]
  pub port: Option<u16>,
}

#[derive(Debug, Subcommand)]
pub enum AuditCommand {
  List(AuditListArgs),
  Tail(AuditTailArgs),
  User(AuditUserArgs),
}

#[derive(Debug, Subcommand)]
pub enum ConfigCommand {
  Validate,
}

#[derive(Debug, Subcommand)]
pub enum DbCommand {
  Status,
  Migrate,
  VacuumTokenTables,
}

#[derive(Debug, Subcommand)]
pub enum SessionCommand {
  List(SessionListArgs),
  Show(SessionShowArgs),
  Revoke(SessionRevokeArgs),
  RevokeOthers(SessionRevokeOthersArgs),
}

#[derive(Debug, Subcommand)]
pub enum MfaCommand {
  List(MfaListArgs),
  Delete(MfaDeleteArgs),
  Reset(MfaResetArgs),
}

#[derive(Debug, Subcommand)]
pub enum TokenCommand {
  Cleanup(TokenCleanupArgs),
  Issue(TokenIssueArgs),
  Inspect(TokenInspectArgs),
}

#[derive(Debug, Subcommand)]
pub enum SsoCommand {
  List,
  Show(ShowSsoArgs),
  Add(AddSsoArgs),
  Update(UpdateSsoArgs),
  Delete(DeleteSsoArgs),
  Test(TestSsoArgs),
  Discover(TestSsoArgs),
  SyncCache,
}

#[derive(Debug, Subcommand)]
pub enum AdminCommand {
  List(ListUsersArgs),
  Add(AddAdminArgs),
  Delete(DeleteUserArgs),
  Update(UpdateAdminArgs),
  Verify(VerifyUserArgs),
}

#[derive(Debug, Subcommand)]
pub enum UserCommand {
  List(ListUsersArgs),
  Show(ShowUserArgs),
  Sessions(UserSessionsArgs),
  ResetPassword(ResetPasswordArgs),
  Add(AddUserArgs),
  Delete(DeleteUserArgs),
  Update(UpdateUserArgs),
  Verify(VerifyUserArgs),
}

#[derive(Debug, Args)]
pub struct ListUsersArgs {
  #[arg(long, default_value_t = 100)]
  pub limit: i64,
  #[arg(long)]
  pub include_deleted: bool,
  #[arg(long)]
  pub email_like: Option<String>,
}

#[derive(Debug, Args)]
pub struct AuditListArgs {
  #[arg(long, default_value_t = 100)]
  pub limit: i64,
}

#[derive(Debug, Args)]
pub struct AuditTailArgs {
  #[arg(long, default_value_t = 20)]
  pub limit: i64,
  #[arg(long)]
  pub follow: bool,
  #[arg(long, default_value_t = 2)]
  pub interval_seconds: u64,
}

#[derive(Debug, Args)]
pub struct AuditUserArgs {
  pub identifier: String,
  #[arg(long, default_value_t = 100)]
  pub limit: i64,
}

#[derive(Debug, Args)]
pub struct SessionListArgs {
  #[arg(long, default_value_t = 100)]
  pub limit: i64,
  #[arg(long)]
  pub user: Option<String>,
  #[arg(long)]
  pub include_expired: bool,
}

#[derive(Debug, Args)]
pub struct SessionShowArgs {
  pub session_id: Uuid,
}

#[derive(Debug, Args)]
pub struct SessionRevokeArgs {
  #[arg(long)]
  pub session_id: Option<Uuid>,
  #[arg(long)]
  pub user: Option<String>,
}

#[derive(Debug, Args)]
pub struct SessionRevokeOthersArgs {
  #[arg(long)]
  pub session_id: Uuid,
}

#[derive(Debug, Args)]
pub struct MfaListArgs {
  pub user: String,
}

#[derive(Debug, Args)]
pub struct MfaDeleteArgs {
  pub user: String,
  #[arg(long)]
  pub factor_id: Uuid,
}

#[derive(Debug, Args)]
pub struct MfaResetArgs {
  pub user: String,
}

#[derive(Debug, Args)]
pub struct TokenCleanupArgs {
  #[arg(long)]
  pub dry_run: bool,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
pub enum AalLevelArg {
  Aal1,
  Aal2,
}

#[derive(Debug, Args)]
pub struct TokenIssueArgs {
  pub user: String,
  #[arg(long, default_value = "admin_cli")]
  pub method: String,
  #[arg(long, value_enum, default_value_t = AalLevelArg::Aal1)]
  pub aal: AalLevelArg,
}

#[derive(Debug, Args)]
pub struct TokenInspectArgs {
  pub token: String,
}

#[derive(Debug, Args)]
pub struct ShowUserArgs {
  pub identifier: String,
}

#[derive(Debug, Args)]
pub struct UserSessionsArgs {
  pub identifier: String,
  #[arg(long, default_value_t = 100)]
  pub limit: i64,
  #[arg(long)]
  pub include_expired: bool,
}

#[derive(Debug, Args)]
pub struct ResetPasswordArgs {
  pub identifier: String,
  #[arg(long)]
  pub password: Option<String>,
  #[arg(long)]
  pub send_link: bool,
}

#[derive(Debug, Args)]
pub struct AddAdminArgs {
  #[arg(long)]
  pub email: String,
  #[arg(long)]
  pub password: Option<String>,
  #[arg(long)]
  pub phone: Option<String>,
  #[arg(long, default_value = "service_role")]
  pub role: String,
  #[arg(long)]
  pub verified: bool,
}

#[derive(Debug, Args)]
pub struct AddUserArgs {
  #[arg(long)]
  pub email: String,
  #[arg(long)]
  pub password: Option<String>,
  #[arg(long)]
  pub phone: Option<String>,
  #[arg(long)]
  pub verified: bool,
}

#[derive(Debug, Args)]
pub struct DeleteUserArgs {
  pub identifier: String,
}

#[derive(Debug, Args)]
pub struct VerifyUserArgs {
  pub identifier: String,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
pub enum AccountStatus {
  Active,
  Deleted,
}

#[derive(Debug, Args)]
pub struct UpdateAdminArgs {
  pub identifier: String,
  #[arg(long)]
  pub email: Option<String>,
  #[arg(long)]
  pub phone: Option<String>,
  #[arg(long)]
  pub password: Option<String>,
  #[arg(long)]
  pub role: Option<String>,
  #[arg(long)]
  pub ban_duration: Option<String>,
  #[arg(long)]
  pub unban: bool,
  #[arg(long, value_enum)]
  pub status: Option<AccountStatus>,
}

#[derive(Debug, Args)]
pub struct UpdateUserArgs {
  pub identifier: String,
  #[arg(long)]
  pub email: Option<String>,
  #[arg(long)]
  pub phone: Option<String>,
  #[arg(long)]
  pub password: Option<String>,
  #[arg(long)]
  pub ban_duration: Option<String>,
  #[arg(long)]
  pub unban: bool,
  #[arg(long, value_enum)]
  pub status: Option<AccountStatus>,
}

#[derive(Debug, Args)]
pub struct AddSsoArgs {
  #[arg(long)]
  pub name: String,
  #[arg(long)]
  pub issuer: String,
  #[arg(long)]
  pub client_id: String,
  #[arg(long)]
  pub client_secret: String,
  #[arg(long)]
  pub redirect_uri: String,
  #[arg(long, value_delimiter = ',', default_values_t = default_scopes())]
  pub scopes: Vec<String>,
  #[arg(long, action = ArgAction::Set, default_value_t = true)]
  pub pkce: bool,
  #[arg(long = "allowed-domain", value_delimiter = ',')]
  pub allowed_domains: Vec<String>,
}

#[derive(Debug, Args)]
pub struct UpdateSsoArgs {
  pub name: String,
  #[arg(long)]
  pub issuer: Option<String>,
  #[arg(long)]
  pub client_id: Option<String>,
  #[arg(long)]
  pub client_secret: Option<String>,
  #[arg(long)]
  pub redirect_uri: Option<String>,
  #[arg(long, value_delimiter = ',')]
  pub scopes: Option<Vec<String>>,
  #[arg(long)]
  pub pkce: Option<bool>,
  #[arg(long = "allowed-domain", value_delimiter = ',')]
  pub allowed_domains: Option<Vec<String>>,
}

#[derive(Debug, Args)]
pub struct DeleteSsoArgs {
  pub name: String,
}

#[derive(Debug, Args)]
pub struct ShowSsoArgs {
  pub name: String,
}

#[derive(Debug, Args)]
pub struct TestSsoArgs {
  pub name: String,
}

#[derive(Debug, Serialize)]
struct CliStatus {
  version: &'static str,
  name: &'static str,
  database_connected: bool,
  database_url: String,
  port: u16,
  pid_file: String,
  site_url: String,
  issuer: String,
  site_name: String,
  mailer_autoconfirm: bool,
  smtp_configured: bool,
  oidc_provider_count: usize,
  user_count: i64,
  admin_count: i64,
}

#[derive(Debug, Serialize)]
struct SettingsView {
  port: u16,
  database_url: String,
  pid_file: String,
  site_url: String,
  issuer: String,
  site_name: String,
  redirect_allowed_origins: Vec<String>,
  allowed_redirect_origins: Vec<String>,
  cors_allowed_origins: Vec<String>,
  jwt_exp: i64,
  refresh_token_exp: i64,
  jwt_secret_len: usize,
  mfa_key_source: &'static str,
  mailer_autoconfirm: bool,
  smtp_configured: bool,
  dev_mode: bool,
}

#[derive(Debug, Serialize)]
struct UserSummary {
  id: Uuid,
  email: Option<String>,
  role: Option<String>,
  email_confirmed_at: Option<chrono::DateTime<Utc>>,
  banned_until: Option<chrono::DateTime<Utc>>,
  deleted_at: Option<chrono::DateTime<Utc>>,
  is_super_admin: Option<bool>,
  is_sso_user: bool,
  is_anonymous: bool,
  created_at: Option<chrono::DateTime<Utc>>,
  updated_at: Option<chrono::DateTime<Utc>>,
}

#[derive(Debug, Serialize)]
struct DoctorReport {
  database_connected: bool,
  pid_file_present: bool,
  server_process_reachable: bool,
  oidc_table_present: bool,
  audit_table_present: bool,
  smtp_configured: bool,
  site_url: String,
  issues: Vec<String>,
}

#[derive(Debug, Serialize, FromRow)]
struct AuditLogRow {
  instance_id: Option<Uuid>,
  id: Uuid,
  payload: Option<Value>,
  ip_address: String,
  created_at: Option<chrono::DateTime<Utc>>,
}

#[derive(Debug, Serialize, FromRow)]
struct OidcProviderView {
  id: Uuid,
  name: String,
  issuer: String,
  client_id: String,
  redirect_uri: String,
  scopes: Value,
  pkce: bool,
  allowed_email_domains: Value,
  created_at: Option<chrono::DateTime<Utc>>,
  updated_at: Option<chrono::DateTime<Utc>>,
}

#[derive(Debug, Serialize)]
struct OidcProviderDetailView {
  name: String,
  issuer: String,
  client_id: String,
  client_secret_configured: bool,
  redirect_uri: String,
  scopes: Vec<String>,
  pkce: bool,
  allowed_email_domains: Vec<String>,
}

#[derive(Debug, Serialize, FromRow)]
struct SessionListRow {
  id: Uuid,
  user_id: Uuid,
  email: Option<String>,
  aal: Option<String>,
  factor_id: Option<Uuid>,
  not_after: Option<chrono::DateTime<Utc>>,
  user_agent: Option<String>,
  ip: Option<String>,
  tag: Option<String>,
  refreshed_at: Option<chrono::NaiveDateTime>,
  active_refresh_tokens: i64,
  created_at: Option<chrono::DateTime<Utc>>,
  updated_at: Option<chrono::DateTime<Utc>>,
}

#[derive(Debug, Serialize, FromRow)]
struct SessionShowRow {
  id: Uuid,
  user_id: Uuid,
  email: Option<String>,
  aal: Option<String>,
  factor_id: Option<Uuid>,
  not_after: Option<chrono::DateTime<Utc>>,
  user_agent: Option<String>,
  ip: Option<String>,
  tag: Option<String>,
  refreshed_at: Option<chrono::NaiveDateTime>,
  created_at: Option<chrono::DateTime<Utc>>,
  updated_at: Option<chrono::DateTime<Utc>>,
}

#[derive(Debug, Serialize, FromRow)]
struct MfaListRow {
  id: Uuid,
  user_id: Uuid,
  email: Option<String>,
  friendly_name: Option<String>,
  factor_type: String,
  status: String,
  phone: Option<String>,
  last_challenged_at: Option<chrono::DateTime<Utc>>,
  created_at: chrono::DateTime<Utc>,
  updated_at: chrono::DateTime<Utc>,
}

#[derive(Debug, Serialize)]
struct TokenCleanupResult {
  dry_run: bool,
  revoked_refresh_tokens_removed: i64,
  expired_refresh_tokens_removed: i64,
  expired_sessions_removed: i64,
  expired_flow_states_removed: i64,
}

#[derive(Debug, Serialize)]
struct SsoTestResult {
  name: String,
  issuer: String,
  redirect_uri: String,
  discovery_issuer: String,
  authorization_endpoint: String,
  token_endpoint: String,
  userinfo_endpoint: Option<String>,
  jwks_uri: String,
  jwks_key_count: usize,
  status: &'static str,
}

#[derive(Debug, Serialize)]
struct ResetPasswordResult {
  password_reset: bool,
  mode: &'static str,
  user_id: Uuid,
  email_sent: bool,
  recovery_link_generated: bool,
}

#[derive(Debug, Serialize)]
struct SessionShowResult {
  session: SessionShowRow,
  amr: Vec<String>,
  refresh_token_count: i64,
  active_refresh_token_count: i64,
}

#[derive(Debug, Serialize)]
struct ConfigValidateReport {
  valid: bool,
  issues: Vec<String>,
  site_url: String,
  issuer: String,
  port: u16,
  pid_file: String,
  redirect_allowed_origins: Vec<String>,
  cors_allowed_origins: Vec<String>,
  allowed_redirect_origins: Vec<String>,
}

#[derive(Debug, Serialize)]
struct DbStatusReport {
  current_versions: Vec<String>,
  available_versions: Vec<String>,
  pending_versions: Vec<String>,
  oidc_provider_count: i64,
  user_count: i64,
  session_count: i64,
}

pub async fn run(cli: Cli, state: AppState, config: RuntimeConfig) -> anyhow::Result<()> {
  match cli.command {
    None => public::serve(config.port, state).await,
    Some(Command::Serve(args)) => public::serve(args.port.unwrap_or(config.port), state).await,
    Some(Command::Status) => show_status(&state.db, &state, &config).await,
    Some(Command::Token { command }) => run_token_command(command, &state, &config).await,
    Some(Command::Sso { command }) => run_sso_command(command, &state).await,
    Some(Command::Admin { command }) => run_admin_command(command, &state).await,
    Some(Command::User { command }) => run_user_command(command, &state).await,
    Some(Command::Heartbeat)
    | Some(Command::Settings)
    | Some(Command::Reload)
    | Some(Command::Doctor)
    | Some(Command::Config { .. })
    | Some(Command::Db { .. })
    | Some(Command::Session { .. })
    | Some(Command::Mfa { .. })
    | Some(Command::Audit { .. }) => bail!("this command should not use the full application runtime"),
  }
}

pub async fn run_with_db(cli: Cli, db: PgPool, config: RuntimeConfig) -> anyhow::Result<()> {
  match cli.command {
    Some(Command::Doctor) => doctor(&db, &config).await,
    Some(Command::Db { command }) => run_db_command(command, &db).await,
    Some(Command::Session { command }) => run_session_command(command, &db).await,
    Some(Command::Mfa { command }) => run_mfa_command(command, &db).await,
    Some(Command::Audit { command }) => run_audit_command(command, &db).await,
    _ => bail!("this command does not use the database-only runtime"),
  }
}

pub async fn run_without_state(
  cli: Cli,
  config: RuntimeConfig,
  http_client: reqwest::Client,
) -> anyhow::Result<()> {
  match cli.command {
    Some(Command::Heartbeat) => heartbeat(&config, &http_client).await,
    Some(Command::Settings) => show_settings(&config),
    Some(Command::Reload) => reload_server(&config),
    Some(Command::Config { command }) => run_config_command(command, &config).await,
    _ => bail!("this command requires the full application runtime"),
  }
}

async fn heartbeat(config: &RuntimeConfig, http_client: &reqwest::Client) -> anyhow::Result<()> {
  let response = utils::probe_local_health(http_client, config.port, Duration::from_secs(3)).await?;

  print_json(&serde_json::json!({
    "ok": true,
    "status": response.status,
    "target": response.target,
    "response": response.body,
  }))
}

async fn show_status(db: &PgPool, state: &AppState, config: &RuntimeConfig) -> anyhow::Result<()> {
  sqlx::query("SELECT 1")
    .execute(db)
    .await
    .context("database connectivity check failed")?;

  let (user_count,): (i64,) = sqlx::query_as("SELECT COUNT(*) FROM auth.users")
    .fetch_one(db)
    .await?;
  let (admin_count,): (i64,) = sqlx::query_as(
    "SELECT COUNT(*) FROM auth.users WHERE role = ANY($1) OR COALESCE(is_super_admin, false) = true",
  )
  .bind(ADMIN_ROLES)
  .fetch_one(db)
  .await?;
  let oidc_provider_count = state.oidc_providers.read().await.len();

  print_json(&CliStatus {
    version: env!("CARGO_PKG_VERSION"),
    name: env!("CARGO_PKG_NAME"),
    database_connected: true,
    database_url: redact_database_url(&config.database_url),
    port: config.port,
    pid_file: config.pid_file.clone(),
    site_url: config.site_url.clone(),
    issuer: config.issuer.clone(),
    site_name: config.site_name.clone(),
    mailer_autoconfirm: config.mailer_autoconfirm,
    smtp_configured: config.smtp_configured,
    oidc_provider_count,
    user_count,
    admin_count,
  })
}

fn show_settings(config: &RuntimeConfig) -> anyhow::Result<()> {
  print_json(&SettingsView {
    port: config.port,
    database_url: redact_database_url(&config.database_url),
    pid_file: config.pid_file.clone(),
    site_url: config.site_url.clone(),
    issuer: config.issuer.clone(),
    site_name: config.site_name.clone(),
    redirect_allowed_origins: config.redirect_allowed_origins.clone(),
    allowed_redirect_origins: config.allowed_redirect_origins.clone(),
    cors_allowed_origins: config.cors_allowed_origins.clone(),
    jwt_exp: config.jwt_exp,
    refresh_token_exp: config.refresh_token_exp,
    jwt_secret_len: config.jwt_secret_len,
    mfa_key_source: config.mfa_key_source,
    mailer_autoconfirm: config.mailer_autoconfirm,
    smtp_configured: config.smtp_configured,
    dev_mode: config.dev_mode,
  })
}

fn reload_server(config: &RuntimeConfig) -> anyhow::Result<()> {
  #[cfg(unix)]
  {
    let pid_contents = std::fs::read_to_string(&config.pid_file)
      .with_context(|| format!("failed to read pid file {}", config.pid_file))?;
    let pid = pid_contents.trim();
    if pid.is_empty() {
      bail!("pid file is empty");
    }
    let status = ProcessCommand::new("kill")
      .args(["-HUP", pid])
      .status()
      .context("failed to invoke kill -HUP")?;
    if !status.success() {
      bail!("kill -HUP {pid} failed with status {status}");
    }
    print_json(&serde_json::json!({
      "reloaded": true,
      "pid": pid,
      "pid_file": config.pid_file,
    }))
  }

  #[cfg(not(unix))]
  {
    let _ = config;
    bail!("reload is only supported on unix-like systems");
  }
}

async fn doctor(db: &PgPool, config: &RuntimeConfig) -> anyhow::Result<()> {
  let mut issues = Vec::new();
  let database_connected = sqlx::query("SELECT 1").execute(db).await.is_ok();
  if !database_connected {
    issues.push("database connectivity check failed".to_string());
  }

  let pid_file_present = std::path::Path::new(&config.pid_file).exists();
  if !pid_file_present {
    issues.push(format!("pid file not found at {}", config.pid_file));
  }

  let server_process_reachable = if pid_file_present {
    ping_server_process(&config.pid_file).is_ok()
  } else {
    false
  };
  if pid_file_present && !server_process_reachable {
    issues.push("pid file exists but process is not reachable".to_string());
  }

  let oidc_table_present = table_exists(db, "auth", "oidc_providers").await?;
  if !oidc_table_present {
    issues.push("missing auth.oidc_providers migration".to_string());
  }

  let audit_table_present = table_exists(db, "auth", "audit_log_entries").await?;
  if !audit_table_present {
    issues.push("missing auth.audit_log_entries table".to_string());
  }

  print_json(&DoctorReport {
    database_connected,
    pid_file_present,
    server_process_reachable,
    oidc_table_present,
    audit_table_present,
    smtp_configured: config.smtp_configured,
    site_url: config.site_url.clone(),
    issues,
  })
}

async fn run_audit_command(command: AuditCommand, db: &PgPool) -> anyhow::Result<()> {
  match command {
    AuditCommand::List(args) => {
      let rows: Vec<AuditLogRow> = sqlx::query_as::<_, AuditLogRow>(
        "SELECT instance_id, id, payload, ip_address, created_at FROM auth.audit_log_entries ORDER BY created_at DESC NULLS LAST LIMIT $1",
      )
      .bind(args.limit.max(1))
      .fetch_all(db)
      .await?;
      print_json(&rows)
    },
    AuditCommand::Tail(args) => audit_tail(db, args).await,
    AuditCommand::User(args) => audit_user(db, &args.identifier, args.limit).await,
  }
}

async fn run_sso_command(command: SsoCommand, state: &AppState) -> anyhow::Result<()> {
  match command {
    SsoCommand::List => list_sso_providers(&state.db).await,
    SsoCommand::Show(args) => show_sso_provider(&state.db, &args.name).await,
    SsoCommand::Add(args) => add_sso_provider(state, args).await,
    SsoCommand::Update(args) => update_sso_provider(state, args).await,
    SsoCommand::Delete(args) => delete_sso_provider(state, &args.name).await,
    SsoCommand::Test(args) => test_sso_provider(state, &args.name).await,
    SsoCommand::Discover(args) => discover_sso_provider(state, &args.name).await,
    SsoCommand::SyncCache => sync_sso_cache(state).await,
  }
}

async fn run_config_command(command: ConfigCommand, config: &RuntimeConfig) -> anyhow::Result<()> {
  match command {
    ConfigCommand::Validate => validate_config(config),
  }
}

async fn run_db_command(command: DbCommand, db: &PgPool) -> anyhow::Result<()> {
  match command {
    DbCommand::Status => db_status(db).await,
    DbCommand::Migrate => db_migrate(db).await,
    DbCommand::VacuumTokenTables => db_vacuum_token_tables(db).await,
  }
}

async fn run_session_command(command: SessionCommand, db: &PgPool) -> anyhow::Result<()> {
  match command {
    SessionCommand::List(args) => list_sessions(db, args).await,
    SessionCommand::Show(args) => show_session(db, args.session_id).await,
    SessionCommand::Revoke(args) => revoke_sessions(db, args).await,
    SessionCommand::RevokeOthers(args) => revoke_other_sessions(db, args.session_id).await,
  }
}

async fn run_mfa_command(command: MfaCommand, db: &PgPool) -> anyhow::Result<()> {
  match command {
    MfaCommand::List(args) => list_mfa_factors(db, &args.user).await,
    MfaCommand::Delete(args) => delete_mfa_factor(db, &args.user, args.factor_id).await,
    MfaCommand::Reset(args) => reset_mfa_factors(db, &args.user).await,
  }
}

async fn run_token_command(
  command: TokenCommand,
  state: &AppState,
  config: &RuntimeConfig,
) -> anyhow::Result<()> {
  match command {
    TokenCommand::Cleanup(args) => cleanup_tokens(&state.db, config, args).await,
    TokenCommand::Issue(args) => issue_token_for_user(state, args).await,
    TokenCommand::Inspect(args) => inspect_token(state, &args.token).await,
  }
}

async fn run_admin_command(command: AdminCommand, state: &AppState) -> anyhow::Result<()> {
  match command {
    AdminCommand::List(args) => list_users(&state.db, UserListKind::Admins, args).await,
    AdminCommand::Add(args) => {
      ensure_admin_role(&args.role)?;
      let user = insert_user(
        state,
        &args.email,
        args.phone.as_deref(),
        args.password.as_deref(),
        &args.role,
        args.verified,
      )
      .await?;
      print_json(&user)
    },
    AdminCommand::Delete(args) => delete_user(&state.db, &args.identifier).await,
    AdminCommand::Update(args) => {
      if let Some(ref role) = args.role {
        ensure_admin_role(role)?;
      }
      let user = update_user_record(
        state,
        &args.identifier,
        UserUpdateOptions {
          email: args.email,
          phone: args.phone,
          password: args.password,
          role: args.role,
          ban_duration: args.ban_duration,
          unban: args.unban,
          status: args.status,
        },
      )
      .await?;
      print_json(&user)
    },
    AdminCommand::Verify(args) => verify_user(&state.db, &args.identifier).await,
  }
}

async fn run_user_command(command: UserCommand, state: &AppState) -> anyhow::Result<()> {
  match command {
    UserCommand::List(args) => list_users(&state.db, UserListKind::RegularUsers, args).await,
    UserCommand::Show(args) => show_user(&state.db, &args.identifier).await,
    UserCommand::Sessions(args) => {
      let user_id = resolve_user_identifier(&state.db, &args.identifier).await?;
      list_sessions(
        &state.db,
        SessionListArgs {
          limit: args.limit,
          user: Some(user_id.to_string()),
          include_expired: args.include_expired,
        },
      )
      .await
    },
    UserCommand::ResetPassword(args) => reset_user_password(state, args).await,
    UserCommand::Add(args) => {
      let user = insert_user(
        state,
        &args.email,
        args.phone.as_deref(),
        args.password.as_deref(),
        "authenticated",
        args.verified,
      )
      .await?;
      print_json(&user)
    },
    UserCommand::Delete(args) => delete_user(&state.db, &args.identifier).await,
    UserCommand::Update(args) => {
      let user = update_user_record(
        state,
        &args.identifier,
        UserUpdateOptions {
          email: args.email,
          phone: args.phone,
          password: args.password,
          role: None,
          ban_duration: args.ban_duration,
          unban: args.unban,
          status: args.status,
        },
      )
      .await?;
      print_json(&user)
    },
    UserCommand::Verify(args) => verify_user(&state.db, &args.identifier).await,
  }
}

#[derive(Debug, Clone, Copy)]
enum UserListKind {
  Admins,
  RegularUsers,
}

async fn list_users(db: &PgPool, kind: UserListKind, args: ListUsersArgs) -> anyhow::Result<()> {
  let limit = args.limit.max(1);
  let mut query = QueryBuilder::<Postgres>::new(USER_SELECT_SQL);
  match kind {
    UserListKind::Admins => {
      query.push(" WHERE (role = ANY(");
      query.push_bind(ADMIN_ROLES);
      query.push(") OR COALESCE(is_super_admin, false) = true)");
    },
    UserListKind::RegularUsers => {
      query.push(" WHERE role <> ALL(");
      query.push_bind(ADMIN_ROLES);
      query.push(") AND COALESCE(is_super_admin, false) = false");
    },
  }

  if !args.include_deleted {
    query.push(" AND deleted_at IS NULL");
  }

  if let Some(pattern) = args.email_like.as_deref() {
    query.push(" AND email ILIKE ");
    query.push_bind(format!("%{pattern}%"));
  }

  query.push(" ORDER BY created_at DESC LIMIT ");
  query.push_bind(limit);

  let users: Vec<User> = query.build_query_as().fetch_all(db).await?;
  let summary = users
    .into_iter()
    .map(|user| UserSummary {
      id: user.id,
      email: user.email,
      role: user.role,
      email_confirmed_at: user.email_confirmed_at,
      banned_until: user.banned_until,
      deleted_at: user.deleted_at,
      is_super_admin: user.is_super_admin,
      is_sso_user: user.is_sso_user,
      is_anonymous: user.is_anonymous,
      created_at: user.created_at,
      updated_at: user.updated_at,
    })
    .collect::<Vec<_>>();

  print_json(&summary)
}

async fn list_sessions(db: &PgPool, args: SessionListArgs) -> anyhow::Result<()> {
  let limit = args.limit.max(1);
  let mut query = QueryBuilder::<Postgres>::new(
    "SELECT s.id, s.user_id, u.email, s.aal::text as aal, s.factor_id, s.not_after, s.user_agent, host(s.ip) as ip, s.tag, s.refreshed_at, COUNT(rt.id) FILTER (WHERE rt.revoked = false) as active_refresh_tokens, s.created_at, s.updated_at FROM auth.sessions s JOIN auth.users u ON u.id = s.user_id LEFT JOIN auth.refresh_tokens rt ON rt.session_id = s.id",
  );
  query.push(" WHERE 1=1");
  if let Some(identifier) = args.user.as_deref() {
    let user_id = resolve_user_identifier(db, identifier).await?;
    query.push(" AND s.user_id = ");
    query.push_bind(user_id);
  }
  if !args.include_expired {
    query.push(" AND (s.not_after IS NULL OR s.not_after > NOW())");
  }
  query.push(" GROUP BY s.id, s.user_id, u.email, s.aal, s.factor_id, s.not_after, s.user_agent, s.ip, s.tag, s.refreshed_at, s.created_at, s.updated_at");
  query.push(" ORDER BY s.created_at DESC NULLS LAST LIMIT ");
  query.push_bind(limit);

  let rows: Vec<SessionListRow> = query.build_query_as().fetch_all(db).await?;
  print_json(&rows)
}

async fn show_session(db: &PgPool, session_id: Uuid) -> anyhow::Result<()> {
  let session: SessionShowRow = sqlx::query_as::<_, SessionShowRow>(
    "SELECT s.id, s.user_id, u.email, s.aal::text as aal, s.factor_id, s.not_after, s.user_agent, host(s.ip) as ip, s.tag, s.refreshed_at, s.created_at, s.updated_at FROM auth.sessions s JOIN auth.users u ON u.id = s.user_id WHERE s.id = $1",
  )
  .bind(session_id)
  .fetch_optional(db)
  .await?
  .with_context(|| format!("session not found for id {session_id}"))?;

  let amr_rows: Vec<(String,)> = sqlx::query_as(
    "SELECT authentication_method FROM auth.mfa_amr_claims WHERE session_id = $1 ORDER BY created_at ASC",
  )
  .bind(session_id)
  .fetch_all(db)
  .await?;
  let (refresh_token_count,): (i64,) =
    sqlx::query_as("SELECT COUNT(*) FROM auth.refresh_tokens WHERE session_id = $1")
      .bind(session_id)
      .fetch_one(db)
      .await?;
  let (active_refresh_token_count,): (i64,) =
    sqlx::query_as("SELECT COUNT(*) FROM auth.refresh_tokens WHERE session_id = $1 AND revoked = false")
      .bind(session_id)
      .fetch_one(db)
      .await?;

  print_json(&SessionShowResult {
    session,
    amr: amr_rows.into_iter().map(|row| row.0).collect(),
    refresh_token_count,
    active_refresh_token_count,
  })
}

async fn revoke_sessions(db: &PgPool, args: SessionRevokeArgs) -> anyhow::Result<()> {
  if args.session_id.is_none() && args.user.is_none() {
    bail!("provide either --session-id or --user");
  }
  if args.session_id.is_some() && args.user.is_some() {
    bail!("use either --session-id or --user, not both");
  }

  let now = Utc::now();
  let affected = if let Some(session_id) = args.session_id {
    sqlx::query("UPDATE auth.refresh_tokens SET revoked = true, updated_at = $1 WHERE session_id = $2")
      .bind(now)
      .bind(session_id)
      .execute(db)
      .await?;
    sqlx::query("DELETE FROM auth.sessions WHERE id = $1")
      .bind(session_id)
      .execute(db)
      .await?
      .rows_affected()
  } else {
    let user_id = resolve_user_identifier(db, args.user.as_deref().unwrap_or_default()).await?;
    sqlx::query("UPDATE auth.refresh_tokens SET revoked = true, updated_at = $1 WHERE user_id = $2")
      .bind(now)
      .bind(user_id.to_string())
      .execute(db)
      .await?;
    sqlx::query("DELETE FROM auth.sessions WHERE user_id = $1")
      .bind(user_id)
      .execute(db)
      .await?
      .rows_affected()
  };

  print_json(&serde_json::json!({
    "revoked": true,
    "sessions_removed": affected,
  }))
}

async fn revoke_other_sessions(db: &PgPool, session_id: Uuid) -> anyhow::Result<()> {
  let (user_id,): (Uuid,) = sqlx::query_as("SELECT user_id FROM auth.sessions WHERE id = $1")
    .bind(session_id)
    .fetch_optional(db)
    .await?
    .with_context(|| format!("session not found for id {session_id}"))?;
  let now = Utc::now();

  sqlx::query(
    "UPDATE auth.refresh_tokens SET revoked = true, updated_at = $1 WHERE user_id = $2 AND session_id <> $3",
  )
  .bind(now)
  .bind(user_id.to_string())
  .bind(session_id)
  .execute(db)
  .await?;

  let removed = sqlx::query("DELETE FROM auth.sessions WHERE user_id = $1 AND id <> $2")
    .bind(user_id)
    .bind(session_id)
    .execute(db)
    .await?
    .rows_affected();

  print_json(&serde_json::json!({
    "revoked_others": true,
    "user_id": user_id,
    "kept_session_id": session_id,
    "sessions_removed": removed,
  }))
}

async fn insert_user(
  state: &AppState,
  email: &str,
  phone: Option<&str>,
  password_value: Option<&str>,
  role: &str,
  verified: bool,
) -> anyhow::Result<UserResponse> {
  validate_role(role)?;
  if !is_valid_email(email) {
    bail!("invalid email format");
  }

  let existing: Option<(Uuid,)> = sqlx::query_as("SELECT id FROM auth.users WHERE email = $1")
    .bind(email)
    .fetch_optional(&state.db)
    .await?;
  if existing.is_some() {
    bail!("user already exists for email {email}");
  }

  let encrypted_password = if let Some(password_value) = password_value {
    validate_password_policy(password_value)?;
    Some(password::hash_password(password_value)?)
  } else {
    None
  };

  let now = Utc::now();
  let email_confirmed_at = verified.then_some(now);
  let user: User = sqlx::query_as::<_, User>(
    "INSERT INTO auth.users (id, instance_id, aud, role, email, encrypted_password, phone, raw_app_meta_data, raw_user_meta_data, email_confirmed_at, is_anonymous, created_at, updated_at) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, false, $11, $12) RETURNING id, instance_id, aud, role, email, encrypted_password, email_confirmed_at, phone, phone_confirmed_at, confirmed_at, last_sign_in_at, raw_app_meta_data, raw_user_meta_data, is_super_admin, is_sso_user, is_anonymous, banned_until, deleted_at, created_at, updated_at",
  )
  .bind(Uuid::new_v4())
  .bind(state.instance_id)
  .bind("authenticated")
  .bind(role)
  .bind(email)
  .bind(encrypted_password)
  .bind(phone)
  .bind(serde_json::json!({ "provider": "email", "providers": ["email"] }))
  .bind(serde_json::json!({}))
  .bind(email_confirmed_at)
  .bind(now)
  .bind(now)
  .fetch_one(&state.db)
  .await?;

  Ok(UserResponse::from_user(&state.db, user).await?)
}

async fn show_user(db: &PgPool, identifier: &str) -> anyhow::Result<()> {
  let user_id = resolve_user_identifier(db, identifier).await?;
  let user = fetch_user_by_id(db, user_id).await?;
  let response = UserResponse::from_user(db, user).await?;
  print_json(&response)
}

async fn reset_user_password(state: &AppState, args: ResetPasswordArgs) -> anyhow::Result<()> {
  if args.password.is_none() && !args.send_link {
    bail!("provide --password or --send-link");
  }
  if args.password.is_some() && args.send_link {
    bail!("use either --password or --send-link, not both");
  }

  let user_id = resolve_user_identifier(&state.db, &args.identifier).await?;
  let user = fetch_user_by_id(&state.db, user_id).await?;
  let now = Utc::now();

  if let Some(password_value) = args.password.as_deref() {
    validate_password_policy(password_value)?;
    let hashed = password::hash_password(password_value)?;
    sqlx::query(
      "UPDATE auth.users SET encrypted_password = $1, recovery_token = NULL, recovery_sent_at = NULL, updated_at = $2 WHERE id = $3",
    )
    .bind(hashed)
    .bind(now)
    .bind(user_id)
    .execute(&state.db)
    .await?;

    return print_json(&serde_json::json!({
      "password_reset": true,
      "mode": "set-password",
      "user_id": user_id,
    }));
  }

  let email = user
    .email
    .as_deref()
    .ok_or_else(|| anyhow::anyhow!("user does not have an email address"))?;
  let recovery_token = session::generate_refresh_token();
  sqlx::query(
    "UPDATE auth.users SET recovery_token = $1, recovery_sent_at = $2, updated_at = $3 WHERE id = $4",
  )
  .bind(&recovery_token)
  .bind(now)
  .bind(now)
  .bind(user_id)
  .execute(&state.db)
  .await?;

  let recovery_url = format!("{}/verify?token={}&type=recovery", state.site_url, recovery_token);
  if let Some(ref mailer) = state.mailer {
    mailer
      .send(
        EmailKind::Recovery,
        email,
        &[
          ("site_name", state.site_name.as_str()),
          ("recovery_url", recovery_url.as_str()),
          ("email", email),
        ],
      )
      .await?;
  }

  print_json(&ResetPasswordResult {
    password_reset: true,
    mode: "recovery-link",
    user_id,
    email_sent: state.mailer.is_some(),
    recovery_link_generated: true,
  })
}

async fn list_mfa_factors(db: &PgPool, identifier: &str) -> anyhow::Result<()> {
  let user_id = resolve_user_identifier(db, identifier).await?;
  let rows: Vec<MfaListRow> = sqlx::query_as::<_, MfaListRow>(
    "SELECT f.id, f.user_id, u.email, f.friendly_name, f.factor_type::text as factor_type, f.status::text as status, f.phone, f.last_challenged_at, f.created_at, f.updated_at FROM auth.mfa_factors f JOIN auth.users u ON u.id = f.user_id WHERE f.user_id = $1 ORDER BY f.created_at ASC",
  )
  .bind(user_id)
  .fetch_all(db)
  .await?;
  print_json(&rows)
}

async fn delete_mfa_factor(db: &PgPool, identifier: &str, factor_id: Uuid) -> anyhow::Result<()> {
  let user_id = resolve_user_identifier(db, identifier).await?;
  sqlx::query("DELETE FROM auth.sessions WHERE factor_id = $1")
    .bind(factor_id)
    .execute(db)
    .await?;
  let removed = sqlx::query("DELETE FROM auth.mfa_factors WHERE id = $1 AND user_id = $2")
    .bind(factor_id)
    .bind(user_id)
    .execute(db)
    .await?
    .rows_affected();
  if removed == 0 {
    bail!("mfa factor not found");
  }

  print_json(&serde_json::json!({
    "deleted": true,
    "user_id": user_id,
    "factor_id": factor_id,
  }))
}

async fn reset_mfa_factors(db: &PgPool, identifier: &str) -> anyhow::Result<()> {
  let user_id = resolve_user_identifier(db, identifier).await?;
  let factor_ids: Vec<(Uuid,)> = sqlx::query_as("SELECT id FROM auth.mfa_factors WHERE user_id = $1")
    .bind(user_id)
    .fetch_all(db)
    .await?;
  for (factor_id,) in &factor_ids {
    sqlx::query("DELETE FROM auth.sessions WHERE factor_id = $1")
      .bind(*factor_id)
      .execute(db)
      .await?;
  }

  let removed = sqlx::query("DELETE FROM auth.mfa_factors WHERE user_id = $1")
    .bind(user_id)
    .execute(db)
    .await?
    .rows_affected();

  print_json(&serde_json::json!({
    "reset": true,
    "user_id": user_id,
    "factors_removed": removed,
  }))
}

#[derive(Debug)]
struct UserUpdateOptions {
  email: Option<String>,
  phone: Option<String>,
  password: Option<String>,
  role: Option<String>,
  ban_duration: Option<String>,
  unban: bool,
  status: Option<AccountStatus>,
}

async fn update_user_record(
  state: &AppState,
  identifier: &str,
  options: UserUpdateOptions,
) -> anyhow::Result<UserResponse> {
  let user_id = resolve_user_identifier(&state.db, identifier).await?;

  if let Some(ref email) = options.email {
    if !is_valid_email(email) {
      bail!("invalid email format");
    }
    let existing: Option<(Uuid,)> = sqlx::query_as("SELECT id FROM auth.users WHERE email = $1 AND id <> $2")
      .bind(email)
      .bind(user_id)
      .fetch_optional(&state.db)
      .await?;
    if existing.is_some() {
      bail!("email address is already in use");
    }
  }

  let hashed_password = if let Some(ref password_value) = options.password {
    validate_password_policy(password_value)?;
    Some(password::hash_password(password_value)?)
  } else {
    None
  };

  if let Some(ref role) = options.role {
    validate_role(role)?;
  }

  if options.ban_duration.is_some() && options.unban {
    bail!("use either --ban-duration or --unban, not both");
  }

  let mut builder = QueryBuilder::<Postgres>::new("UPDATE auth.users SET ");
  let mut separated = builder.separated(", ");
  let now = Utc::now();
  let mut changed = false;

  if let Some(ref email) = options.email {
    separated.push("email = ").push_bind(email);
    changed = true;
  }
  if let Some(ref phone) = options.phone {
    separated.push("phone = ").push_bind(phone);
    changed = true;
  }
  if let Some(ref password_hash) = hashed_password {
    separated.push("encrypted_password = ").push_bind(password_hash);
    changed = true;
  }
  if let Some(ref role) = options.role {
    separated.push("role = ").push_bind(role);
    changed = true;
  }
  if options.unban {
    separated.push("banned_until = NULL");
    changed = true;
  } else if let Some(ref duration) = options.ban_duration {
    let seconds = parse_ban_duration(duration)?;
    separated
      .push("banned_until = ")
      .push_bind(now + chrono::Duration::seconds(seconds));
    changed = true;
  }
  if let Some(status) = options.status {
    match status {
      AccountStatus::Active => {
        separated.push("deleted_at = NULL");
        if !options.unban && options.ban_duration.is_none() {
          separated.push("banned_until = NULL");
        }
      },
      AccountStatus::Deleted => {
        separated.push("deleted_at = ").push_bind(now);
      },
    }
    changed = true;
  }

  if !changed {
    bail!("no updates requested");
  }

  {
    let mut separated = separated;
    separated.push("updated_at = ").push_bind(now);
  }
  builder.push(" WHERE id = ");
  builder.push_bind(user_id);
  builder.build().execute(&state.db).await?;

  let user = fetch_user_by_id(&state.db, user_id).await?;
  Ok(UserResponse::from_user(&state.db, user).await?)
}

async fn verify_user(db: &PgPool, identifier: &str) -> anyhow::Result<()> {
  let user_id = resolve_user_identifier(db, identifier).await?;
  let now = Utc::now();
  sqlx::query("UPDATE auth.users SET email_confirmed_at = $1, updated_at = $2 WHERE id = $3")
    .bind(now)
    .bind(now)
    .bind(user_id)
    .execute(db)
    .await?;

  print_json(&serde_json::json!({
    "verified": true,
    "user_id": user_id,
    "email_confirmed_at": now,
  }))
}

async fn delete_user(db: &PgPool, identifier: &str) -> anyhow::Result<()> {
  let user_id = resolve_user_identifier(db, identifier).await?;
  let result = sqlx::query("DELETE FROM auth.users WHERE id = $1")
    .bind(user_id)
    .execute(db)
    .await?;

  if result.rows_affected() == 0 {
    bail!("user not found");
  }

  print_json(&serde_json::json!({
    "deleted": true,
    "user_id": user_id,
  }))
}

async fn cleanup_tokens(db: &PgPool, config: &RuntimeConfig, args: TokenCleanupArgs) -> anyhow::Result<()> {
  let cutoff = Utc::now() - chrono::Duration::seconds(config.refresh_token_exp);

  let revoked_refresh_tokens_removed = count_query(
    db,
    "SELECT COUNT(*) FROM auth.refresh_tokens WHERE revoked = true",
  )
  .await?;
  let expired_refresh_tokens_removed = count_query_with_cutoff(
    db,
    "SELECT COUNT(*) FROM auth.refresh_tokens WHERE created_at < $1",
    cutoff,
  )
  .await?;
  let expired_sessions_removed = count_query(
    db,
    "SELECT COUNT(*) FROM auth.sessions WHERE not_after IS NOT NULL AND not_after <= NOW()",
  )
  .await?;
  let expired_flow_states_removed = count_query(
    db,
    "SELECT COUNT(*) FROM auth.flow_state WHERE COALESCE(expires_at, created_at + INTERVAL '1 day') <= NOW()",
  )
  .await?;

  if !args.dry_run {
    sqlx::query("DELETE FROM auth.refresh_tokens WHERE revoked = true")
      .execute(db)
      .await?;
    sqlx::query("DELETE FROM auth.refresh_tokens WHERE created_at < $1")
      .bind(cutoff)
      .execute(db)
      .await?;
    sqlx::query("DELETE FROM auth.sessions WHERE not_after IS NOT NULL AND not_after <= NOW()")
      .execute(db)
      .await?;
    sqlx::query(
      "DELETE FROM auth.flow_state WHERE COALESCE(expires_at, created_at + INTERVAL '1 day') <= NOW()",
    )
    .execute(db)
    .await?;
  }

  print_json(&TokenCleanupResult {
    dry_run: args.dry_run,
    revoked_refresh_tokens_removed,
    expired_refresh_tokens_removed,
    expired_sessions_removed,
    expired_flow_states_removed,
  })
}

async fn issue_token_for_user(state: &AppState, args: TokenIssueArgs) -> anyhow::Result<()> {
  let user_id = resolve_user_identifier(&state.db, &args.user).await?;
  let user = fetch_user_by_id(&state.db, user_id).await?;
  let response = match args.aal {
    AalLevelArg::Aal1 => session::issue_session(state, &user, &args.method).await?,
    AalLevelArg::Aal2 => {
      session::issue_session_with_context(state, &user, "aal2", None, vec![args.method]).await?
    },
  };
  print_json(&response)
}

async fn inspect_token(state: &AppState, token: &str) -> anyhow::Result<()> {
  let token_data = jwt::decode_token(token, &state.jwt_secret, &state.issuer)
    .map_err(|error| anyhow::anyhow!("token decode failed: {error}"))?;
  let session_active = session::ensure_active_session(state, &token_data.claims)
    .await
    .is_ok();
  let current_user = session::load_current_user(state, &token_data.claims).await.ok();

  print_json(&serde_json::json!({
    "valid": true,
    "session_active": session_active,
    "claims": token_data.claims,
    "current_user": current_user.map(|user| serde_json::json!({
      "id": user.id,
      "email": user.email,
      "role": user.role,
      "banned_until": user.banned_until,
      "deleted_at": user.deleted_at,
    })),
  }))
}

fn validate_config(config: &RuntimeConfig) -> anyhow::Result<()> {
  let mut issues = Vec::new();

  if url::Url::parse(&config.site_url).is_err() {
    issues.push("SITE_URL is not a valid absolute URL".to_string());
  }
  if url::Url::parse(&config.issuer).is_err() {
    issues.push("issuer is not a valid absolute URL".to_string());
  }
  if config.jwt_secret_len < 32 {
    issues.push("JWT secret is shorter than 32 characters".to_string());
  }
  if config.port == 0 {
    issues.push("port must be non-zero".to_string());
  }
  for origin in &config.cors_allowed_origins {
    if url::Url::parse(origin).is_err() {
      issues.push(format!("invalid CORS origin: {origin}"));
    }
  }
  for origin in &config.allowed_redirect_origins {
    if url::Url::parse(origin).is_err() {
      issues.push(format!("invalid redirect origin: {origin}"));
    }
  }

  print_json(&ConfigValidateReport {
    valid: issues.is_empty(),
    issues,
    site_url: config.site_url.clone(),
    issuer: config.issuer.clone(),
    port: config.port,
    pid_file: config.pid_file.clone(),
    redirect_allowed_origins: config.redirect_allowed_origins.clone(),
    cors_allowed_origins: config.cors_allowed_origins.clone(),
    allowed_redirect_origins: config.allowed_redirect_origins.clone(),
  })
}

async fn audit_tail(db: &PgPool, args: AuditTailArgs) -> anyhow::Result<()> {
  let limit = args.limit.max(1);
  let mut last_seen = None::<chrono::DateTime<Utc>>;

  loop {
    let rows: Vec<AuditLogRow> = if let Some(last_seen) = last_seen {
      sqlx::query_as::<_, AuditLogRow>(
        "SELECT instance_id, id, payload, ip_address, created_at FROM auth.audit_log_entries WHERE created_at > $1 ORDER BY created_at ASC NULLS LAST LIMIT $2",
      )
      .bind(last_seen)
      .bind(limit)
      .fetch_all(db)
      .await?
    } else {
      sqlx::query_as::<_, AuditLogRow>(
        "SELECT instance_id, id, payload, ip_address, created_at FROM auth.audit_log_entries ORDER BY created_at DESC NULLS LAST LIMIT $1",
      )
      .bind(limit)
      .fetch_all(db)
      .await?
      .into_iter()
      .rev()
      .collect()
    };

    if let Some(created_at) = rows.iter().filter_map(|row| row.created_at).max() {
      last_seen = Some(created_at);
    }

    if !rows.is_empty() {
      print_json(&rows)?;
    }

    if !args.follow {
      return Ok(());
    }

    sleep(Duration::from_secs(args.interval_seconds.max(1))).await;
  }
}

async fn audit_user(db: &PgPool, identifier: &str, limit: i64) -> anyhow::Result<()> {
  let rows: Vec<AuditLogRow> = sqlx::query_as::<_, AuditLogRow>(
    "SELECT instance_id, id, payload, ip_address, created_at FROM auth.audit_log_entries WHERE payload::text ILIKE $1 ORDER BY created_at DESC NULLS LAST LIMIT $2",
  )
  .bind(format!("%{identifier}%"))
  .bind(limit.max(1))
  .fetch_all(db)
  .await?;
  print_json(&rows)
}

async fn add_sso_provider(state: &AppState, args: AddSsoArgs) -> anyhow::Result<()> {
  let provider = oidc::OidcProviderConfig {
    name: args.name.clone(),
    issuer: args.issuer,
    client_id: args.client_id,
    client_secret: args.client_secret,
    redirect_uri: args.redirect_uri,
    scopes: args.scopes,
    pkce: args.pkce,
    allowed_email_domains: args.allowed_domains,
  };
  validate_sso_provider(&provider)?;

  let now = Utc::now();
  sqlx::query(
    "INSERT INTO auth.oidc_providers (id, name, issuer, client_id, client_secret, redirect_uri, scopes, pkce, allowed_email_domains, created_at, updated_at) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)",
  )
  .bind(Uuid::new_v4())
  .bind(&provider.name)
  .bind(&provider.issuer)
  .bind(&provider.client_id)
  .bind(&provider.client_secret)
  .bind(&provider.redirect_uri)
  .bind(serde_json::json!(provider.scopes))
  .bind(provider.pkce)
  .bind(serde_json::json!(provider.allowed_email_domains))
  .bind(now)
  .bind(now)
  .execute(&state.db)
  .await?;

  reload_oidc_cache(state).await?;
  maybe_reload_running_server()?;
  list_sso_providers(&state.db).await
}

async fn update_sso_provider(state: &AppState, args: UpdateSsoArgs) -> anyhow::Result<()> {
  let current = load_sso_provider(&state.db, &args.name).await?;
  let provider = oidc::OidcProviderConfig {
    name: current.name,
    issuer: args.issuer.unwrap_or(current.issuer),
    client_id: args.client_id.unwrap_or(current.client_id),
    client_secret: args.client_secret.unwrap_or(current.client_secret),
    redirect_uri: args.redirect_uri.unwrap_or(current.redirect_uri),
    scopes: args.scopes.unwrap_or(current.scopes),
    pkce: args.pkce.unwrap_or(current.pkce),
    allowed_email_domains: args.allowed_domains.unwrap_or(current.allowed_email_domains),
  };
  validate_sso_provider(&provider)?;

  sqlx::query(
    "UPDATE auth.oidc_providers SET issuer = $1, client_id = $2, client_secret = $3, redirect_uri = $4, scopes = $5, pkce = $6, allowed_email_domains = $7, updated_at = $8 WHERE lower(name) = lower($9)",
  )
  .bind(&provider.issuer)
  .bind(&provider.client_id)
  .bind(&provider.client_secret)
  .bind(&provider.redirect_uri)
  .bind(serde_json::json!(provider.scopes))
  .bind(provider.pkce)
  .bind(serde_json::json!(provider.allowed_email_domains))
  .bind(Utc::now())
  .bind(&provider.name)
  .execute(&state.db)
  .await?;

  reload_oidc_cache(state).await?;
  maybe_reload_running_server()?;
  list_sso_providers(&state.db).await
}

async fn delete_sso_provider(state: &AppState, name: &str) -> anyhow::Result<()> {
  let result = sqlx::query("DELETE FROM auth.oidc_providers WHERE lower(name) = lower($1)")
    .bind(name)
    .execute(&state.db)
    .await?;
  if result.rows_affected() == 0 {
    bail!("sso provider not found");
  }

  reload_oidc_cache(state).await?;
  maybe_reload_running_server()?;
  print_json(&serde_json::json!({
    "deleted": true,
    "name": name,
  }))
}

async fn test_sso_provider(state: &AppState, name: &str) -> anyhow::Result<()> {
  let provider = load_sso_provider(&state.db, name).await?;
  let discovery = oidc::discover_provider(&state.http_client, &provider).await?;
  let jwks: jsonwebtoken::jwk::JwkSet = state
    .http_client
    .get(&discovery.jwks_uri)
    .send()
    .await
    .context("failed to fetch OIDC JWKS")?
    .error_for_status()
    .context("OIDC JWKS endpoint returned an error")?
    .json()
    .await
    .context("failed to decode OIDC JWKS response")?;

  print_json(&SsoTestResult {
    name: provider.name,
    issuer: provider.issuer,
    redirect_uri: provider.redirect_uri,
    discovery_issuer: discovery.issuer,
    authorization_endpoint: discovery.authorization_endpoint,
    token_endpoint: discovery.token_endpoint,
    userinfo_endpoint: discovery.userinfo_endpoint,
    jwks_uri: discovery.jwks_uri,
    jwks_key_count: jwks.keys.len(),
    status: "ok",
  })
}

async fn discover_sso_provider(state: &AppState, name: &str) -> anyhow::Result<()> {
  let provider = load_sso_provider(&state.db, name).await?;
  let discovery = oidc::discover_provider(&state.http_client, &provider).await?;
  print_json(&discovery)
}

async fn db_status(db: &PgPool) -> anyhow::Result<()> {
  let current_versions = current_migration_versions(db).await?;

  let available_versions = std::fs::read_dir("migrations")?
    .filter_map(|entry| entry.ok())
    .filter_map(|entry| entry.file_name().into_string().ok())
    .filter_map(|name| name.split('_').next().map(|value| value.to_string()))
    .collect::<std::collections::BTreeSet<_>>()
    .into_iter()
    .collect::<Vec<_>>();

  let pending_versions = available_versions
    .iter()
    .filter(|version| !current_versions.iter().any(|current| current == *version))
    .cloned()
    .collect::<Vec<_>>();

  let oidc_provider_count = count_if_table_exists(
    db,
    "auth",
    "oidc_providers",
    "SELECT COUNT(*) FROM auth.oidc_providers",
  )
  .await?;
  let user_count = count_if_table_exists(db, "auth", "users", "SELECT COUNT(*) FROM auth.users").await?;
  let session_count =
    count_if_table_exists(db, "auth", "sessions", "SELECT COUNT(*) FROM auth.sessions").await?;

  print_json(&DbStatusReport {
    current_versions,
    available_versions,
    pending_versions,
    oidc_provider_count,
    user_count,
    session_count,
  })
}

async fn db_migrate(db: &PgPool) -> anyhow::Result<()> {
  let mut applied = current_migration_versions(db).await?;
  let mut files = std::fs::read_dir("migrations")?
    .filter_map(|entry| entry.ok())
    .filter_map(|entry| {
      let path = entry.path();
      let name = path.file_name()?.to_str()?.to_string();
      let version = name.split('_').next()?.to_string();
      Some((version, path))
    })
    .collect::<Vec<_>>();
  files.sort_by(|a, b| a.0.cmp(&b.0));

  let mut applied_now = Vec::new();
  for (version, path) in files {
    if applied.iter().any(|current| current == &version) {
      continue;
    }

    let sql = std::fs::read_to_string(&path)
      .with_context(|| format!("failed to read migration {}", path.display()))?;
    let sql = migration_up_sql(&sql);
    let mut tx = db.begin().await?;
    sqlx::raw_sql(&sql).execute(&mut *tx).await?;
    sqlx::query("INSERT INTO auth.schema_migrations (version) VALUES ($1)")
      .bind(&version)
      .execute(&mut *tx)
      .await?;
    tx.commit().await?;
    applied.push(version.clone());
    applied_now.push(version);
  }

  print_json(&serde_json::json!({
    "migrated": true,
    "applied_versions": applied_now,
  }))
}

async fn db_vacuum_token_tables(db: &PgPool) -> anyhow::Result<()> {
  sqlx::raw_sql("VACUUM ANALYZE auth.refresh_tokens")
    .execute(db)
    .await?;
  sqlx::raw_sql("VACUUM ANALYZE auth.flow_state")
    .execute(db)
    .await?;
  sqlx::raw_sql("VACUUM ANALYZE auth.sessions").execute(db).await?;
  print_json(&serde_json::json!({
    "vacuumed": true,
    "tables": ["auth.refresh_tokens", "auth.flow_state", "auth.sessions"],
  }))
}

async fn list_sso_providers(db: &PgPool) -> anyhow::Result<()> {
  let providers: Vec<OidcProviderView> = sqlx::query_as::<_, OidcProviderView>(
    "SELECT id, name, issuer, client_id, redirect_uri, scopes, pkce, allowed_email_domains, created_at, updated_at FROM auth.oidc_providers ORDER BY name ASC",
  )
  .fetch_all(db)
  .await?;
  print_json(&providers)
}

async fn show_sso_provider(db: &PgPool, name: &str) -> anyhow::Result<()> {
  let provider = load_sso_provider(db, name).await?;
  print_json(&OidcProviderDetailView::from(provider))
}

async fn load_sso_provider(db: &PgPool, name: &str) -> anyhow::Result<oidc::OidcProviderConfig> {
  #[derive(FromRow)]
  struct Row {
    name: String,
    issuer: String,
    client_id: String,
    client_secret: String,
    redirect_uri: String,
    scopes: Value,
    pkce: bool,
    allowed_email_domains: Value,
  }

  let row: Row = sqlx::query_as::<_, Row>(
    "SELECT name, issuer, client_id, client_secret, redirect_uri, scopes, pkce, allowed_email_domains FROM auth.oidc_providers WHERE lower(name) = lower($1)",
  )
  .bind(name)
  .fetch_optional(db)
  .await?
  .with_context(|| format!("sso provider not found: {name}"))?;

  Ok(oidc::OidcProviderConfig {
    name: row.name,
    issuer: row.issuer,
    client_id: row.client_id,
    client_secret: row.client_secret,
    redirect_uri: row.redirect_uri,
    scopes: decode_string_array(row.scopes, "scopes")?,
    pkce: row.pkce,
    allowed_email_domains: decode_string_array(row.allowed_email_domains, "allowed_email_domains")?,
  })
}

async fn reload_oidc_cache(state: &AppState) -> anyhow::Result<()> {
  let providers = oidc::load_providers_from_db(&state.db).await?;
  *state.oidc_providers.write().await = providers;
  Ok(())
}

async fn sync_sso_cache(state: &AppState) -> anyhow::Result<()> {
  reload_oidc_cache(state).await?;
  maybe_reload_running_server()?;
  print_json(&serde_json::json!({
    "synced": true,
    "provider_count": state.oidc_providers.read().await.len(),
  }))
}

fn validate_sso_provider(provider: &oidc::OidcProviderConfig) -> anyhow::Result<()> {
  if provider.name.trim().is_empty() {
    bail!("provider name must not be empty");
  }
  if provider.client_id.trim().is_empty() || provider.client_secret.trim().is_empty() {
    bail!("client_id and client_secret are required");
  }
  url::Url::parse(&provider.issuer)?;
  url::Url::parse(&provider.redirect_uri)?;
  Ok(())
}

fn decode_string_array(value: Value, field_name: &str) -> anyhow::Result<Vec<String>> {
  match value {
    Value::Array(values) => values
      .into_iter()
      .map(|value| match value {
        Value::String(value) => Ok(value),
        _ => bail!("{field_name} must contain only strings"),
      })
      .collect(),
    _ => bail!("{field_name} must be an array"),
  }
}

async fn resolve_user_identifier(db: &PgPool, identifier: &str) -> anyhow::Result<Uuid> {
  if let Ok(id) = identifier.parse::<Uuid>() {
    let existing: Option<(Uuid,)> = sqlx::query_as("SELECT id FROM auth.users WHERE id = $1")
      .bind(id)
      .fetch_optional(db)
      .await?;
    if let Some((id,)) = existing {
      return Ok(id);
    }
  }

  let by_email: Option<(Uuid,)> = sqlx::query_as("SELECT id FROM auth.users WHERE email = $1")
    .bind(identifier)
    .fetch_optional(db)
    .await?;

  by_email
    .map(|(id,)| id)
    .with_context(|| format!("user not found for identifier {identifier}"))
}

async fn fetch_user_by_id(db: &PgPool, user_id: Uuid) -> anyhow::Result<User> {
  sqlx::query_as::<_, User>(&format!("{USER_SELECT_SQL} WHERE id = $1"))
    .bind(user_id)
    .fetch_optional(db)
    .await?
    .with_context(|| format!("user not found for id {user_id}"))
}

fn ensure_admin_role(role: &str) -> anyhow::Result<()> {
  if ADMIN_ROLES.contains(&role) {
    return Ok(());
  }
  bail!("admin commands only allow roles: {}", ADMIN_ROLES.join(", "))
}

fn ping_server_process(pid_file: &str) -> anyhow::Result<()> {
  #[cfg(unix)]
  {
    let pid = std::fs::read_to_string(pid_file)?;
    let pid = pid.trim();
    let status = ProcessCommand::new("kill")
      .args(["-0", pid])
      .status()
      .context("failed to invoke kill -0")?;
    if !status.success() {
      bail!("process {pid} is not reachable");
    }
    Ok(())
  }

  #[cfg(not(unix))]
  {
    let _ = pid_file;
    bail!("pid probing is only supported on unix-like systems");
  }
}

fn maybe_reload_running_server() -> anyhow::Result<()> {
  let pid_file = utils::pid_file_path();
  let pid_file = pid_file.to_string_lossy().to_string();
  if !std::path::Path::new(&pid_file).exists() {
    return Ok(());
  }

  if ping_server_process(&pid_file).is_err() {
    return Ok(());
  }

  #[cfg(unix)]
  {
    let pid = std::fs::read_to_string(&pid_file)?;
    let pid = pid.trim().to_string();
    let status = ProcessCommand::new("kill")
      .args(["-HUP", &pid])
      .status()
      .context("failed to invoke kill -HUP")?;
    if !status.success() {
      bail!("kill -HUP {pid} failed with status {status}");
    }
    tracing::info!(pid, "Reloaded active Haya server after SSO configuration change");
    Ok(())
  }

  #[cfg(not(unix))]
  {
    Ok(())
  }
}

async fn table_exists(db: &PgPool, schema: &str, table: &str) -> anyhow::Result<bool> {
  let exists: Option<(bool,)> = sqlx::query_as(
    "SELECT EXISTS (SELECT 1 FROM information_schema.tables WHERE table_schema = $1 AND table_name = $2)",
  )
  .bind(schema)
  .bind(table)
  .fetch_optional(db)
  .await?;
  Ok(exists.map(|row| row.0).unwrap_or(false))
}

async fn current_migration_versions(db: &PgPool) -> anyhow::Result<Vec<String>> {
  if !table_exists(db, "auth", "schema_migrations").await? {
    return Ok(Vec::new());
  }

  Ok(
    sqlx::query_as::<_, (String,)>("SELECT version FROM auth.schema_migrations ORDER BY version ASC")
      .fetch_all(db)
      .await?
      .into_iter()
      .map(|row| row.0)
      .collect(),
  )
}

async fn count_if_table_exists(db: &PgPool, schema: &str, table: &str, sql: &str) -> anyhow::Result<i64> {
  if !table_exists(db, schema, table).await? {
    return Ok(0);
  }

  count_query(db, sql).await
}

fn migration_up_sql(sql: &str) -> String {
  let mut in_up = false;
  let mut saw_marker = false;
  let mut lines = Vec::new();

  for line in sql.lines() {
    match line.trim() {
      "-- !UP" => {
        in_up = true;
        saw_marker = true;
      },
      "-- !DOWN" => {
        in_up = false;
      },
      _ if in_up => lines.push(line),
      _ => {},
    }
  }

  if saw_marker {
    let mut up_sql = lines.join("\n");
    up_sql.push('\n');
    up_sql
  } else {
    sql.to_string()
  }
}

async fn count_query(db: &PgPool, sql: &str) -> anyhow::Result<i64> {
  let (count,): (i64,) = sqlx::query_as(sql).fetch_one(db).await?;
  Ok(count)
}

async fn count_query_with_cutoff(
  db: &PgPool,
  sql: &str,
  cutoff: chrono::DateTime<Utc>,
) -> anyhow::Result<i64> {
  let (count,): (i64,) = sqlx::query_as(sql).bind(cutoff).fetch_one(db).await?;
  Ok(count)
}

fn redact_database_url(value: &str) -> String {
  let Ok(mut url) = url::Url::parse(value) else {
    return "<invalid database url>".to_string();
  };
  if url.password().is_some() {
    let _ = url.set_password(Some("***"));
  }
  if !url.username().is_empty() {
    let _ = url.set_username("***");
  }
  url.to_string()
}

fn print_json<T: Serialize>(value: &T) -> anyhow::Result<()> {
  println!("{}", serde_json::to_string_pretty(value)?);
  Ok(())
}

fn default_scopes() -> Vec<String> {
  vec!["openid".to_string(), "email".to_string(), "profile".to_string()]
}

impl From<oidc::OidcProviderConfig> for OidcProviderDetailView {
  fn from(provider: oidc::OidcProviderConfig) -> Self {
    Self {
      name: provider.name,
      issuer: provider.issuer,
      client_id: provider.client_id,
      client_secret_configured: !provider.client_secret.trim().is_empty(),
      redirect_uri: provider.redirect_uri,
      scopes: provider.scopes,
      pkce: provider.pkce,
      allowed_email_domains: provider.allowed_email_domains,
    }
  }
}

#[cfg(test)]
mod tests {
  use super::*;

  fn base_add_sso_args() -> Vec<&'static str> {
    vec![
      "haya",
      "sso",
      "add",
      "--name",
      "example",
      "--issuer",
      "https://issuer.example.com",
      "--client-id",
      "client-id",
      "--client-secret",
      "client-secret",
      "--redirect-uri",
      "https://app.example.com/callback",
    ]
  }

  #[test]
  fn cli_detects_server_commands() {
    assert!(Cli::parse_from(["haya"]).runs_server());
    assert!(Cli::parse_from(["haya", "serve"]).runs_server());
    assert!(!Cli::parse_from(["haya", "settings"]).runs_server());
  }

  #[test]
  fn cli_only_builds_app_state_for_runtime_commands() {
    assert!(!Cli::parse_from(["haya", "settings"]).needs_app_state());
    assert!(!Cli::parse_from(["haya", "heartbeat"]).needs_app_state());
    assert!(!Cli::parse_from(["haya", "reload"]).needs_app_state());
    assert!(!Cli::parse_from(["haya", "db", "migrate"]).needs_app_state());
    assert!(!Cli::parse_from(["haya", "config", "validate"]).needs_app_state());
    assert!(Cli::parse_from(["haya", "status"]).needs_app_state());
    assert!(Cli::parse_from(["haya"]).needs_app_state());
  }

  #[test]
  fn cli_detects_database_only_commands() {
    assert!(Cli::parse_from(["haya", "db", "migrate"]).needs_database());
    assert!(Cli::parse_from(["haya", "doctor"]).needs_database());
    assert!(!Cli::parse_from(["haya", "heartbeat"]).needs_database());
    assert!(!Cli::parse_from(["haya", "status"]).needs_database());
  }

  #[test]
  fn add_sso_pkce_defaults_to_true() {
    let cli = Cli::parse_from(base_add_sso_args());
    let Some(Command::Sso {
      command: SsoCommand::Add(args),
    }) = cli.command
    else {
      panic!("expected sso add command");
    };

    assert!(args.pkce);
  }

  #[test]
  fn add_sso_pkce_accepts_false() {
    let mut argv = base_add_sso_args();
    argv.push("--pkce");
    argv.push("false");

    let cli = Cli::parse_from(argv);
    let Some(Command::Sso {
      command: SsoCommand::Add(args),
    }) = cli.command
    else {
      panic!("expected sso add command");
    };

    assert!(!args.pkce);
  }

  #[test]
  fn redact_database_url_removes_credentials() {
    let value = redact_database_url("postgres://user:password@example.com:5432/haya");

    assert_eq!(value, "postgres://***:***@example.com:5432/haya");
  }

  #[test]
  fn sso_show_view_redacts_client_secret() {
    let view = OidcProviderDetailView::from(oidc::OidcProviderConfig {
      name: "example".to_string(),
      issuer: "https://issuer.example.com".to_string(),
      client_id: "client-id".to_string(),
      client_secret: "super-secret".to_string(),
      redirect_uri: "https://app.example.com/callback".to_string(),
      scopes: vec!["openid".to_string()],
      pkce: true,
      allowed_email_domains: vec!["example.com".to_string()],
    });

    let json = serde_json::to_value(view).expect("serialize sso show view");
    assert_eq!(json["client_secret_configured"], true);
    assert!(json.get("client_secret").is_none());
  }
}
