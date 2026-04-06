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
  let watchdog_client = state.http_client.clone();
  let reload_task = tokio::spawn(async move {
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
  let local_addr = listener.local_addr()?;
  let watchdog = utils::spawn_systemd_watchdog(watchdog_client, port);

  println!("Haya Auth is now listening at {}", local_addr);
  utils::notify_ready(&format!("Haya Auth is listening at {local_addr}"));
  let serve_result = axum::serve(listener, service)
    .with_graceful_shutdown(utils::shutdown_signal())
    .await;
  utils::notify_stopping("Haya Auth is stopping");
  if let Some(watchdog) = watchdog {
    watchdog.abort();
  }
  reload_task.abort();
  if let Err(error) = reload_task.await
    && !error.is_cancelled()
  {
    tracing::error!(error = %error, "Reload task terminated unexpectedly");
  }
  serve_result?;
  let _ = utils::remove_pid_file();

  Ok(())
}
