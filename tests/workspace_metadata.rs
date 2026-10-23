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
  let packages = metadata["packages"].as_array().expect("packages array");
  let expected_version = env!("CARGO_PKG_VERSION");

  for package_name in ["haya", "haya-passkey-rp"] {
    let package = packages
      .iter()
      .find(|package| package["name"].as_str() == Some(package_name))
      .unwrap_or_else(|| panic!("workspace package {package_name} not found"));

    assert!(
      members.contains(&package["id"]),
      "workspace member {package_name} ({}) not found in {members:?}",
      package["id"]
    );
    assert_eq!(
      package["version"].as_str(),
      Some(expected_version),
      "workspace package {package_name} must use the root package version"
    );
  }
}
