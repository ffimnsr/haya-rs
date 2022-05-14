//! This module is the main entrypoint for haya auth.

mod defaults;
mod error;
mod mime;
mod model;
mod public;

use crate::defaults::{DEFAULT_DSN, DEFAULT_DB};
pub(crate) use crate::mime as MimeValues;
pub(crate) use hyper::header as HeaderValues;
use clap::{Command, arg};
use mongodb::options::ClientOptions;
use std::{env, sync::Arc};

use crate::error::{ServiceResult, ServiceError};

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
                .subcommand(
                    Command::new("create")
                        .about("Create a new OAuth 2.0 Client")
                )
                .subcommand(
                    Command::new("delete")
                        .about("Delete an OAuth 2.0 Client")
                )
                .subcommand(
                    Command::new("get")
                        .about("Get an OAuth 2.0 Client")
                )
                .subcommand(
                    Command::new("list")
                        .about("List OAuth 2.0 Clients")
                )
                .subcommand(
                    Command::new("update")
                        .about("Update an entire OAuth 2.0 Client")
                )
        )
        .subcommand(
            Command::new("serve")
                .arg_required_else_help(true)
        )
        .subcommand(
            Command::new("token")
                .about("Issue and Manage OAuth2 tokens")
        )
}

#[tokio::main]
async fn main() -> ServiceResult<()> {
    dotenv::dotenv().ok();

    if env::var("RUST_LOG").is_err() {
        env::set_var("RUST_LOG", "haya=info,hyper=info");
    }

    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    let _ = cli().get_matches();

    let dsn = env::var("DSN").ok();
    let dsn = match dsn {
        Some(x) => x,
        None => DEFAULT_DSN.to_string(),
    };

    let client_options = ClientOptions::parse(dsn)
        .await
        .map_err(ServiceError::Mongo)?;
    let client = mongodb::Client::with_options(client_options).map_err(ServiceError::Mongo)?;
    let db = Arc::new(client.database(DEFAULT_DB));


    log::info!("Booting up Haya OP v{}", VERSION);

    let port = env::var("PORT")
        .map(|x| x.parse::<u16>())
        .ok();

    let port = match port {
        Some(x) => x.map_err(|_| ServiceError::DefinedError("Unable to parse PORT environment variable."))?,
        None => 8080,
    };

    public::serve(port, db.clone()).await
}
