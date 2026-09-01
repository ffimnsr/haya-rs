use std::process::Command;

#[test]
fn workspace_contains_haya_and_passkey_rp_packages() {
  let output = Command::new(env!("CARGO"))
    .args(["metadata", "--format-version", "1", "--no-deps"])
    .current_dir(env!("CARGO_MANIFEST_DIR"))
    .output()
    .expect("run cargo metadata");
  assert!(
    output.status.success(),
    "cargo metadata failed: {}",
    String::from_utf8_lossy(&output.stderr)
  );

  let metadata: serde_json::Value =
    serde_json::from_slice(&output.stdout).expect("parse cargo metadata JSON");
  let members = metadata["workspace_members"]
    .as_array()
    .expect("workspace_members array");
  for package in ["haya@0.2.0", "haya-passkey-rp#0.1.0"] {
    assert!(
      members
        .iter()
        .any(|member| member.as_str().is_some_and(|member| member.contains(package))),
      "workspace member {package} not found in {members:?}"
    );
  }
}
