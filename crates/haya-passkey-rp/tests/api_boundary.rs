use std::process::Command;

use haya_passkey_rp::{
  AuthenticationResult,
  AuthenticationStart,
  AuthenticationState,
  PasskeyConfig,
  PasskeyRp,
  RegistrationInput,
  RegistrationStart,
  RegistrationState,
  RpCredential,
  RpError,
};

#[test]
fn ceremony_api_is_importable_from_crate_root() {
  fn use_type<T>() {}

  use_type::<PasskeyRp>();
  use_type::<PasskeyConfig>();
  use_type::<RegistrationInput>();
  use_type::<RegistrationStart>();
  use_type::<RegistrationState>();
  use_type::<AuthenticationStart>();
  use_type::<AuthenticationState>();
  use_type::<AuthenticationResult>();
  use_type::<RpCredential>();
  use_type::<RpError>();
}

#[test]
fn normal_dependency_graph_excludes_forbidden_roles() {
  let manifest_dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
  let workspace_root = manifest_dir.parent().and_then(std::path::Path::parent).unwrap();
  let output = Command::new(env!("CARGO"))
    .args([
      "tree",
      "--package",
      "haya-passkey-rp",
      "--edges",
      "normal",
      "--prefix",
      "none",
    ])
    .current_dir(workspace_root)
    .output()
    .expect("run cargo tree");
  assert!(
    output.status.success(),
    "cargo tree failed: {}",
    String::from_utf8_lossy(&output.stderr)
  );

  let tree = String::from_utf8(output.stdout).expect("cargo tree output is UTF-8");
  let package_names = tree
    .lines()
    .filter_map(|line| line.split_whitespace().next())
    .collect::<Vec<_>>();
  for forbidden in [
    "haya",
    "axum",
    "sqlx",
    "jsonwebtoken",
    "webauthn-rs",
    "passkey-client",
    "passkey-authenticator",
  ] {
    assert!(
      !package_names.contains(&forbidden),
      "forbidden dependency {forbidden} found in:\n{tree}"
    );
  }
}
