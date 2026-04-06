mod auth;
mod cli;
mod db;
mod defaults;
mod error;
mod mailer;
mod middleware;
mod model;
mod public;
mod state;
mod utils;

use std::env;
use std::sync::Arc;

use clap::Parser;
use tokio::sync::RwLock;

use crate::auth::{
  mfa,
  oidc,
};
use crate::cli::Cli;
use crate::defaults::{
  ACCESS_TOKEN_LIFETIME,
  DEFAULT_DATABASE_URL,
  DEFAULT_PORT,
  REFRESH_TOKEN_LIFETIME,
};
use crate::mailer::{
  Mailer,
  MailerConfig,
};
use crate::state::{
  AppState,
  RuntimeConfig,
};
use tracing_subscriber::layer::SubscriberExt as _;
use tracing_subscriber::util::SubscriberInitExt as _;
use url::Url;
use uuid::Uuid;

const APP_NAME: &str = env!("CARGO_PKG_NAME");

#[derive(Clone)]
struct RuntimeBootstrap {
  config: RuntimeConfig,
  http_client: reqwest::Client,
  jwt_secret: String,
  mfa_encryption_key: [u8; 32],
  instance_id: Uuid,
  mailer: Option<Arc<Mailer>>,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
  dotenvy::dotenv().ok();
  let cli = Cli::parse();

  tracing_subscriber::registry()
    .with(
      tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| format!("{}=debug,tower_http=debug,axum::rejection=trace", APP_NAME).into()),
    )
    .with(tracing_subscriber::fmt::layer())
    .init();

  let runs_server = cli.runs_server();
  let needs_app_state = cli.needs_app_state();
  let needs_database = cli.needs_database();
  let bootstrap = build_runtime_bootstrap(needs_app_state || needs_database)?;
  let runtime_config = bootstrap.config.clone();
  if runs_server {
    let version = env!("CARGO_PKG_VERSION");
    println!("Booting up Haya Auth v{}", version);
  }
  if needs_app_state {
    let state = build_app_state(&bootstrap).await?;
    return crate::cli::run(cli, state, runtime_config).await;
  }

  if needs_database {
    let db = db::init_pool(&runtime_config.database_url).await?;
    return crate::cli::run_with_db(cli, db, runtime_config).await;
  }

  crate::cli::run_without_state(cli, runtime_config, bootstrap.http_client).await
}

fn origin_from_url(value: &str) -> anyhow::Result<String> {
  let url = Url::parse(value)?;
  let host = url
    .host_str()
    .ok_or_else(|| anyhow::anyhow!("URL must include a host: {value}"))?;
  let mut origin = format!("{}://{}", url.scheme(), host);
  if let Some(port) = url.port() {
    origin.push(':');
    origin.push_str(&port.to_string());
  }
  Ok(origin)
}

fn parse_origin_list_env(name: &str) -> Vec<String> {
  env::var(name)
    .map(|value| {
      value
        .split(',')
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned)
        .collect::<Vec<_>>()
    })
    .unwrap_or_default()
}

fn env_flag_enabled(name: &str) -> bool {
  env::var(name)
    .map(|value| {
      let value = value.trim();
      value == "1" || value.eq_ignore_ascii_case("true")
    })
    .unwrap_or(false)
}

fn build_runtime_bootstrap(require_database: bool) -> anyhow::Result<RuntimeBootstrap> {
  let database_url = env::var("DATABASE_URL")
    .or_else(|_| env::var("DEFAULT_DATABASE_URL"))
    .unwrap_or_else(|_| DEFAULT_DATABASE_URL.to_string());
  if require_database && database_url == DEFAULT_DATABASE_URL {
    anyhow::bail!("DATABASE_URL must be set explicitly");
  }
  let http_client = reqwest::Client::builder()
    .redirect(reqwest::redirect::Policy::none())
    .build()?;

  let dev_mode = env_flag_enabled("HAYA_DEV_MODE");
  let jwt_secret = match env::var("JWT_SECRET") {
    Ok(secret) if secret.len() >= 32 => secret,
    Ok(secret) if secret.is_empty() && require_database => {
      anyhow::bail!("JWT_SECRET must not be empty");
    },
    Ok(secret) if require_database => {
      let _ = secret;
      anyhow::bail!("JWT_SECRET must be at least 32 characters long");
    },
    Ok(secret) => secret,
    Err(_) if dev_mode => {
      let dev_secret = "super-secret-jwt-token-with-at-least-32-characters-long";
      tracing::warn!(
        "⚠️  JWT_SECRET not set! Using insecure development secret. \
                   Set HAYA_DEV_MODE=1 only for local development. \
                   NEVER use this configuration in production!"
      );
      dev_secret.to_string()
    },
    Err(_) if require_database => {
      anyhow::bail!(
        "JWT_SECRET environment variable is required. \
                   Set a strong secret of at least 32 characters. \
                   For development mode only, set HAYA_DEV_MODE=1 to use a default secret."
      );
    },
    Err(_) => String::new(),
  };

  let jwt_exp: i64 = env::var("JWT_EXPIRY")
    .ok()
    .and_then(|v| v.parse().ok())
    .unwrap_or(ACCESS_TOKEN_LIFETIME);

  let (mfa_encryption_key, mfa_key_source) = match env::var("MFA_ENCRYPTION_KEY") {
    Ok(value) if !value.trim().is_empty() => (mfa::derive_encryption_key(&value), "env"),
    Ok(_) if require_database => anyhow::bail!("MFA_ENCRYPTION_KEY must not be empty when set"),
    Ok(_) => ([0; 32], "unset"),
    Err(_) if require_database => anyhow::bail!(
      "MFA_ENCRYPTION_KEY environment variable is required and must be set independently from JWT_SECRET"
    ),
    Err(_) => ([0; 32], "unset"),
  };

  let refresh_token_exp: i64 = env::var("REFRESH_TOKEN_EXPIRY")
    .ok()
    .and_then(|v| v.parse().ok())
    .unwrap_or(REFRESH_TOKEN_LIFETIME);

  let site_url = env::var("SITE_URL").unwrap_or_else(|_| "http://localhost:9999".to_string());
  let cors_allowed_origins = parse_origin_list_env("CORS_ALLOWED_ORIGINS");
  let redirect_allowed_origins = parse_origin_list_env("ALLOWED_REDIRECT_ORIGINS");
  let mut allowed_redirect_origins = vec![origin_from_url(&site_url)?];
  for origin in &redirect_allowed_origins {
    allowed_redirect_origins.push(origin_from_url(origin)?);
  }
  allowed_redirect_origins.sort();
  allowed_redirect_origins.dedup();
  let site_name = env::var("SITE_NAME").unwrap_or_else(|_| "Haya".to_string());
  let issuer = env::var("GOTRUE_JWT_ISSUER")
    .or_else(|_| env::var("JWT_ISSUER"))
    .unwrap_or_else(|_| site_url.clone());

  let instance_id = env::var("INSTANCE_ID")
    .ok()
    .and_then(|v| v.parse().ok())
    .unwrap_or_else(Uuid::new_v4);

  let mailer_autoconfirm = env::var("MAILER_AUTOCONFIRM")
    .map(|v| v.to_lowercase() == "true" || v == "1")
    .unwrap_or(false);

  let (mailer, smtp_configured): (Option<Arc<Mailer>>, bool) = if let Ok(smtp_host) = env::var("SMTP_HOST") {
    let smtp_port: u16 = env::var("SMTP_PORT")
      .ok()
      .and_then(|v| v.parse().ok())
      .unwrap_or(587);
    let smtp_username = env::var("SMTP_USERNAME").unwrap_or_default();
    let smtp_password = env::var("SMTP_PASSWORD").unwrap_or_default();
    let smtp_tls = env::var("SMTP_TLS")
      .map(|v| v.to_lowercase() != "false" && v != "0")
      .unwrap_or(true);
    let smtp_from_email = env::var("SMTP_FROM_EMAIL").unwrap_or_else(|_| "noreply@example.com".to_string());
    let smtp_from_name = env::var("SMTP_FROM_NAME").unwrap_or_else(|_| site_name.clone());
    let templates_dir = env::var("EMAIL_TEMPLATES_DIR").unwrap_or_else(|_| "./templates/email".to_string());
    tracing::info!(%smtp_host, smtp_port, "Configuring SMTP mailer");
    match Mailer::new(MailerConfig {
      from_email: smtp_from_email,
      from_name: smtp_from_name,
      smtp_host,
      smtp_port,
      smtp_username,
      smtp_password,
      smtp_tls,
      templates_dir,
    }) {
      Ok(m) => {
        tracing::info!("SMTP mailer ready");
        (Some(Arc::new(m)), true)
      },
      Err(e) => {
        tracing::warn!(error = %e, "Failed to configure SMTP mailer; emails will not be sent");
        (None, false)
      },
    }
  } else {
    tracing::info!("SMTP_HOST not set; email sending is disabled");
    (None, false)
  };

  let port: u16 = env::var("PORT")
    .ok()
    .and_then(|v| v.parse().ok())
    .unwrap_or(DEFAULT_PORT);
  let pid_file = env::var("HAYA_PID_FILE").unwrap_or_else(|_| "/tmp/haya.pid".to_string());
  let config = RuntimeConfig {
    port,
    database_url,
    site_url,
    redirect_allowed_origins,
    allowed_redirect_origins,
    cors_allowed_origins,
    site_name,
    issuer,
    jwt_exp,
    refresh_token_exp,
    pid_file,
    jwt_secret_len: jwt_secret.len(),
    mailer_autoconfirm,
    smtp_configured,
    dev_mode,
    mfa_key_source,
  };

  Ok(RuntimeBootstrap {
    config,
    http_client,
    jwt_secret,
    mfa_encryption_key,
    instance_id,
    mailer,
  })
}

async fn build_app_state(bootstrap: &RuntimeBootstrap) -> anyhow::Result<AppState> {
  let db = db::init_pool(&bootstrap.config.database_url).await?;
  let oidc_providers = oidc::load_providers_from_db(&db).await?;

  Ok(AppState {
    db,
    http_client: bootstrap.http_client.clone(),
    jwt_secret: bootstrap.jwt_secret.clone(),
    mfa_encryption_key: bootstrap.mfa_encryption_key,
    jwt_exp: bootstrap.config.jwt_exp,
    refresh_token_exp: bootstrap.config.refresh_token_exp,
    site_url: bootstrap.config.site_url.clone(),
    allowed_redirect_origins: bootstrap.config.allowed_redirect_origins.clone(),
    site_name: bootstrap.config.site_name.clone(),
    issuer: bootstrap.config.issuer.clone(),
    instance_id: bootstrap.instance_id,
    oidc_providers: Arc::new(RwLock::new(oidc_providers)),
    mailer_autoconfirm: bootstrap.config.mailer_autoconfirm,
    mailer: bootstrap.mailer.clone(),
  })
}
