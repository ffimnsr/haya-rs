//! This module is the main entrypoint for haya auth.

use std::borrow::BorrowMut;
use std::env;

use clap::App;

pub(crate) use crate::mime as MimeValues;
pub(crate) use hyper::header as HeaderValues;

use crate::config::Config;
use crate::errors::ServiceResult;

mod config;
mod cors;
mod db;
mod errors;
mod mime;
mod public;

const APP_NAME: &str = env!("CARGO_PKG_NAME");
const APP_DESCRIPTION: &str = env!("CARGO_PKG_DESCRIPTION");
const VERSION: &str = env!("CARGO_PKG_VERSION");
const AUTHORS: &str = env!("CARGO_PKG_AUTHORS");
const MANIFEST_DIR: &str = env!("CARGO_MANIFEST_DIR");

#[tokio::main]
async fn main() -> ServiceResult<()> {
    dotenv::dotenv().ok();

    if env::var("RUST_LOG").is_err() {
        env::set_var("RUST_LOG", "haya=info,hyper=info");
    }

    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    let _ = App::new(APP_NAME)
        .version(VERSION)
        .author(AUTHORS)
        .about(APP_DESCRIPTION)
        .get_matches();

    log::info!("Booting up Haya OP v{}", VERSION);

    let config_path = format!("{}/config.yaml", MANIFEST_DIR);
    let config = Config::parse_config(&config_path)?;
    log::info!("Config file: {}", config_path);

    let db = db::get_db_pool()?;
    public::serve(config, db.clone()).await?;

    Ok(())
}
