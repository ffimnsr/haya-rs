mod handlers;
mod router;

use crate::config::Config;
use crate::db::Pool;
use crate::errors::{ServiceError, ServiceResult};
use hyper::Server;
use routerify::RouterService;
use std::sync::Arc;

pub(crate) async fn serve(config: Arc<Config>, db: Pool) -> ServiceResult<()> {
    let router = router::router(config, db)?;

    let service = RouterService::new(router).map_err(ServiceError::Router)?;

    let addr = "[::]:4444".parse().map_err(ServiceError::AddrParser)?;

    log::info!("Haya OP is now listening at {}", addr);
    Server::bind(&addr)
        .http1_preserve_header_case(true)
        .http1_title_case_headers(true)
        .serve(service)
        .await
        .map_err(ServiceError::Hyper)
}
