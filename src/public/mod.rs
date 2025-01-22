// mod handler;
mod router;

use anyhow::Context;
use axum::Router;
use tokio::net::TcpListener;

use crate::{error::{ServiceError, ServiceResult}, DbContext};

pub(crate) async fn serve(port: u16, db: DbContext) -> anyhow::Result<()> {
    let service = Router::new();

    let addr = format!("[::]:{port}");
    let listener = TcpListener::bind(&addr).await
        .with_context(|| format!("Failed to bind to address {}", addr))?;

    log::info!("Haya OP is now listening at {}", addr);
    axum::serve(listener, service)
        .await?;

    Ok(())
}
