mod router;
mod handlers;

use crate::config::Config;
use crate::db::Pool;
use crate::errors::{ServiceError, ServiceResult};

use std::net::AddrParseError;
use std::sync::Arc;
use routerify::RouterService;
use hyper::Server;

pub(crate) async fn serve(config: Arc<Config>, db: Pool) -> ServiceResult<()> {
    let router = router::router(config, db)?;

    let service =
        RouterService::new(router).map_err(|e| ServiceError::Router(e.to_string()))?;

    let addr = "[::]:4444".parse().map_err(|e: AddrParseError| ServiceError::Parser(e.to_string()))?;
    log::info!("Haya OP is now listening at {}", addr);

    let server = Server::bind(&addr).serve(service);

    if let Err(e) = server.await {
        log::error!(
            "Fatal error occurred while booting up the public server: {}",
            e
        );
    }

    Ok(())
}
