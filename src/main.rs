//! This module is the main entrypoint for haya auth.

mod db;
mod defaults;
mod error;
mod mime;
mod model;
mod public;
mod utils;

use crate::defaults::{
  DEFAULT_DATABASE_URL,
  DEFAULT_PORT,
};
use clap::Command;
use tracing_subscriber::{layer::SubscriberExt as _, util::SubscriberInitExt as _};
use std::env;

const APP_NAME: &str = env!("CARGO_PKG_NAME");
const APP_DESCRIPTION: &str = env!("CARGO_PKG_DESCRIPTION");
const VERSION: &str = env!("CARGO_PKG_VERSION");
const AUTHORS: &str = env!("CARGO_PKG_AUTHORS");

fn cli() -> Command<'static> {
  Command::new(APP_NAME)
    .version(VERSION)
    .author(AUTHORS)
    .about(APP_DESCRIPTION)
    .subcommand_required(true)
    .arg_required_else_help(true)
    .allow_external_subcommands(true)
    .allow_invalid_utf8_for_external_subcommands(true)
    .subcommand(
      Command::new("client")
        .about("Manage OAuth 2.0 Clients")
        .subcommand_required(true)
        .arg_required_else_help(true)
        .subcommand(Command::new("create").about("Create a new OAuth 2.0 Client"))
        .subcommand(Command::new("delete").about("Delete an OAuth 2.0 Client"))
        .subcommand(Command::new("get").about("Get an OAuth 2.0 Client"))
        .subcommand(Command::new("list").about("List OAuth 2.0 Clients"))
        .subcommand(Command::new("update").about("Update an entire OAuth 2.0 Client")),
    )
    .subcommand(Command::new("serve").arg_required_else_help(true))
    .subcommand(Command::new("token").about("Issue and Manage OAuth2 tokens"))
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
  dotenv::dotenv().ok();

  tracing_subscriber::registry()
    .with(
        tracing_subscriber::EnvFilter::try_from_default_env()
            .unwrap_or_else(|_| {
                format!("{}=debug,tower_http=debug,axum::rejection=trace", APP_NAME)
                    .into()
            })
    )
    .with(tracing_subscriber::fmt::layer())
    .init();

  let _ = cli().get_matches();

  let db_url = env::var("DEFAULT_DATABASE_URL").ok();
  let db_url = match db_url {
    Some(x) => x,
    None => DEFAULT_DATABASE_URL.to_string(),
  };

  let db = db::init_pool(&db_url).await?;

  println!("Booting up Haya v{}", VERSION);

  let port = env::var("PORT").map(|x| x.parse::<u16>()).ok();
  let port = match port {
    Some(x) => x?,
    None => DEFAULT_PORT,
  };

  public::serve(port, db.clone()).await
}
