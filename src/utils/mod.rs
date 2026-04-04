use std::fs;
use std::path::PathBuf;

use anyhow::Context;
use tokio::signal;

// fn generate_authorization_code() -> String {
//     let random_bytes = rand::thread_rng().gen::<[u8; 256]>();
//     let mut hasher = Sha1::new();
//     hasher.update(random_bytes);
//     let hash = format!("{:x}", hasher.finalize());
//     hash
// }

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
