mod handler;
mod router;

use hyper::Server;
use routerify::RouterService;

use crate::{error::{ServiceError, ServiceResult}, DbContext};

pub(crate) async fn serve(port: u16, db: DbContext) -> ServiceResult<()> {
    let router = router::router(db)?;

    let service = RouterService::new(router).map_err(ServiceError::Router)?;

    let addr = format!("[::]:{}", port).parse().map_err(ServiceError::AddrParser)?;

    log::info!("Haya OP is now listening at {}", addr);
    Server::bind(&addr)
        .http1_preserve_header_case(true)
        .http1_title_case_headers(true)
        .serve(service)
        .await
        .map_err(ServiceError::Hyper)
}
