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
      signal::ctrl_c()
          .await
          .expect("failed to install Ctrl+C handler");
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
