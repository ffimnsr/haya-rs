use std::fs;
use std::path::PathBuf;
use std::time::Duration;

use anyhow::Context;
use tokio::signal;
use tokio::task::JoinHandle;
use tokio::time::MissedTickBehavior;

pub async fn shutdown_signal() {
  let ctrl_c = async {
    signal::ctrl_c().await.expect("failed to install Ctrl+C handler");
  };

  #[cfg(unix)]
  let terminate = async {
    signal::unix::signal(signal::unix::SignalKind::terminate())
      .expect("failed to install signal handler")
      .recv()
      .await;
  };

  #[cfg(not(unix))]
  let terminate = std::future::pending::<()>();

  tokio::select! {
      _ = ctrl_c => {},
      _ = terminate => {},
  }
}

#[cfg(unix)]
pub async fn reload_signal<F, Fut>(mut on_reload: F)
where
  F: FnMut() -> Fut + Send + 'static,
  Fut: std::future::Future<Output = anyhow::Result<()>> + Send,
{
  let mut hup =
    signal::unix::signal(signal::unix::SignalKind::hangup()).expect("failed to install SIGHUP handler");
  while hup.recv().await.is_some() {
    if let Err(error) = on_reload().await {
      tracing::error!(error = %error, "Reload handler failed");
    }
  }
}

#[cfg(not(unix))]
pub async fn reload_signal<F, Fut>(_on_reload: F)
where
  F: FnMut() -> Fut + Send + 'static,
  Fut: std::future::Future<Output = anyhow::Result<()>> + Send,
{
}

pub fn write_pid_file() -> anyhow::Result<()> {
  let pid_path = pid_file_path();
  if let Some(parent) = pid_path.parent() {
    fs::create_dir_all(parent).with_context(|| format!("failed to create {}", parent.display()))?;
  }
  fs::write(&pid_path, std::process::id().to_string())
    .with_context(|| format!("failed to write pid file {}", pid_path.display()))
}

pub fn remove_pid_file() -> anyhow::Result<()> {
  let pid_path = pid_file_path();
  if pid_path.exists() {
    fs::remove_file(&pid_path)
      .with_context(|| format!("failed to remove pid file {}", pid_path.display()))?;
  }
  Ok(())
}

pub fn pid_file_path() -> PathBuf {
  std::env::var("HAYA_PID_FILE")
    .map(PathBuf::from)
    .unwrap_or_else(|_| PathBuf::from("/tmp/haya.pid"))
}

pub struct LocalHealthResponse {
  pub target: String,
  pub status: u16,
  pub body: serde_json::Value,
}

pub async fn probe_local_health(
  http_client: &reqwest::Client,
  port: u16,
  timeout: Duration,
) -> anyhow::Result<LocalHealthResponse> {
  let targets = [
    format!("http://127.0.0.1:{port}/health"),
    format!("http://[::1]:{port}/health"),
  ];
  let mut last_error = None;

  for target in targets {
    let response = match tokio::time::timeout(timeout, http_client.get(&target).send()).await {
      Ok(Ok(response)) => response,
      Ok(Err(error)) => {
        last_error = Some(anyhow::Error::new(error).context(format!("health probe failed for {target}")));
        continue;
      },
      Err(_) => {
        last_error = Some(anyhow::anyhow!("health probe timed out for {target}"));
        continue;
      },
    };
    let status = response.status();
    let response = match response.error_for_status() {
      Ok(response) => response,
      Err(error) => {
        last_error = Some(
          anyhow::Error::new(error)
            .context(format!("health probe returned a non-success status for {target}")),
        );
        continue;
      },
    };
    let body = response
      .json()
      .await
      .with_context(|| format!("health probe returned invalid JSON for {target}"))?;

    return Ok(LocalHealthResponse {
      target,
      status: status.as_u16(),
      body,
    });
  }

  Err(
    last_error
      .unwrap_or_else(|| anyhow::anyhow!("local health probe targets were exhausted without a result")),
  )
}

#[cfg(unix)]
pub fn notify_ready(status: &str) {
  if let Err(error) = sd_notify::notify(&[
    sd_notify::NotifyState::Status(status),
    sd_notify::NotifyState::Ready,
  ]) {
    tracing::warn!(error = %error, "Failed to send systemd ready notification");
  }
}

#[cfg(not(unix))]
pub fn notify_ready(_status: &str) {}

#[cfg(unix)]
pub fn notify_stopping(status: &str) {
  if let Err(error) = sd_notify::notify(&[
    sd_notify::NotifyState::Status(status),
    sd_notify::NotifyState::Stopping,
  ]) {
    tracing::warn!(error = %error, "Failed to send systemd stopping notification");
  }
}

#[cfg(not(unix))]
pub fn notify_stopping(_status: &str) {}

#[cfg(unix)]
pub fn spawn_systemd_watchdog(http_client: reqwest::Client, port: u16) -> Option<JoinHandle<()>> {
  let timeout = sd_notify::watchdog_enabled()?;
  let interval = std::cmp::max(timeout / 2, Duration::from_secs(1));

  Some(tokio::spawn(async move {
    let mut ticker = tokio::time::interval(interval);
    ticker.set_missed_tick_behavior(MissedTickBehavior::Skip);
    ticker.tick().await;

    loop {
      ticker.tick().await;
      match probe_local_health(&http_client, port, Duration::from_secs(3)).await {
        Ok(_) => {
          if let Err(error) = sd_notify::notify(&[sd_notify::NotifyState::Watchdog]) {
            tracing::warn!(error = %error, "Failed to send systemd watchdog notification");
          }
        },
        Err(error) => {
          let status = format!("watchdog probe failed: {error}");
          tracing::warn!(error = %error, "Systemd watchdog probe failed");
          if let Err(notify_error) = sd_notify::notify(&[sd_notify::NotifyState::Status(&status)]) {
            tracing::warn!(error = %notify_error, "Failed to send watchdog failure status to systemd");
          }
        },
      }
    }
  }))
}

#[cfg(not(unix))]
pub fn spawn_systemd_watchdog(_http_client: reqwest::Client, _port: u16) -> Option<JoinHandle<()>> {
  None
}
