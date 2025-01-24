mod handler;
mod router;

use anyhow::Context;
use sqlx::PgPool;
use tokio::net::TcpListener;

use crate::utils;

pub async fn serve(port: u16, db: PgPool) -> anyhow::Result<()> {
    let service = router::create_router(db)?;

    let addr = format!("[::]:{port}");
    let listener = TcpListener::bind(&addr).await
        .with_context(|| format!("Failed to bind to address {}", addr))?;

    println!("Haya is now listening at {}", listener.local_addr()?);
    axum::serve(listener, service)
      .with_graceful_shutdown(utils::shutdown_signal())
      .await?;

    Ok(())
}
