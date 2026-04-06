pub(crate) mod handler;
mod router;

use anyhow::Context;
use std::net::SocketAddr;
use std::time::Duration;
use tokio::net::TcpListener;

use crate::auth::{
  oidc,
  rate_limit,
};
use crate::state::AppState;
use crate::utils;

const RATE_LIMIT_CLEANUP_INTERVAL: Duration = Duration::from_secs(3600);

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
  let cleanup_db = state.db.clone();
  let rate_limit_cleanup_task = tokio::spawn(async move {
    let mut interval = tokio::time::interval(RATE_LIMIT_CLEANUP_INTERVAL);
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    interval.tick().await;

    loop {
      interval.tick().await;
      match rate_limit::delete_expired(&cleanup_db).await {
        Ok(removed) => {
          if removed > 0 {
            tracing::debug!(removed, "Removed expired rate limit rows");
          }
        },
        Err(error) => {
          tracing::warn!(error = %error, "Failed to clean expired rate limit rows");
        },
      }
    }
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
  let serve_result = axum::serve(
    listener,
    service.into_make_service_with_connect_info::<SocketAddr>(),
  )
  .with_graceful_shutdown(utils::shutdown_signal())
  .await;
  utils::notify_stopping("Haya Auth is stopping");
  if let Some(watchdog) = watchdog {
    watchdog.abort();
  }
  rate_limit_cleanup_task.abort();
  match rate_limit_cleanup_task.await {
    Err(error) if !error.is_cancelled() => {
      tracing::error!(error = %error, "Rate limit cleanup task terminated unexpectedly");
    },
    _ => {},
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
