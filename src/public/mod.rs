pub(crate) mod handler;
mod router;

use anyhow::Context;
use tokio::net::TcpListener;

use crate::auth::oidc;
use crate::state::AppState;
use crate::utils;

pub async fn serve(port: u16, state: AppState) -> anyhow::Result<()> {
  utils::write_pid_file()?;
  let reload_state = state.clone();
  tokio::spawn(async move {
    utils::reload_signal(move || {
      let reload_state = reload_state.clone();
      async move {
        let providers = oidc::load_providers_from_db(&reload_state.db).await?;
        *reload_state.oidc_providers.write().await = providers;
        tracing::info!("Reloaded OIDC provider configuration");
        Ok(())
      }
    })
    .await;
  });

  let service = router::create_router(state);

  let addr = format!("[::]:{port}");
  let listener = TcpListener::bind(&addr)
    .await
    .with_context(|| format!("Failed to bind to address {}", addr))?;

  println!("Haya Auth is now listening at {}", listener.local_addr()?);
  axum::serve(listener, service)
    .with_graceful_shutdown(utils::shutdown_signal())
    .await?;
  let _ = utils::remove_pid_file();

  Ok(())
}
