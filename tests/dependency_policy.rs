use std::collections::BTreeSet;
use std::path::Path;
use std::process::Command;

use serde_json::Value;

const SOFTWARE_PEERS: [&str; 2] = ["passkey-client", "passkey-authenticator"];

fn cargo_output(args: &[&str]) -> String {
  let output = Command::new(env!("CARGO"))
    .args(args)
    .current_dir(env!("CARGO_MANIFEST_DIR"))
    .output()
    .unwrap_or_else(|error| panic!("failed to run `cargo {}`: {error}", args.join(" ")));

  assert!(
    output.status.success(),
    "`cargo {}` failed with {}:\n{}",
    args.join(" "),
    output.status,
    String::from_utf8_lossy(&output.stderr)
  );

  String::from_utf8(output.stdout)
    .unwrap_or_else(|error| panic!("`cargo {}` output was not UTF-8: {error}", args.join(" ")))
}

fn tree_package_names(args: &[&str]) -> (BTreeSet<String>, String) {
  let tree = cargo_output(args);
  let package_names = tree
    .lines()
    .filter_map(|line| line.split_whitespace().next())
    .map(str::to_owned)
    .collect();
  (package_names, tree)
}

fn assert_tree_excludes(args: &[&str], forbidden: &[&str]) {
  let (package_names, tree) = tree_package_names(args);
  for package in forbidden {
    assert!(
      !package_names.contains(*package),
      "forbidden package {package} found in `cargo {}` output:\n{tree}",
      args.join(" ")
    );
  }
}

#[test]
fn dependency_trees_follow_workspace_boundaries() {
  assert_tree_excludes(
    &[
      "--color",
      "never",
      "tree",
      "--workspace",
      "--edges",
      "all",
      "--target",
      "all",
      "--prefix",
      "none",
      "--format",
      "{p}",
    ],
    &["webauthn-rs"],
  );

  assert_tree_excludes(
    &[
      "--color",
      "never",
      "tree",
      "--package",
      "haya-passkey-rp",
      "--edges",
      "normal,build",
      "--target",
      "all",
      "--prefix",
      "none",
      "--format",
      "{p}",
    ],
    &[
      "haya",
      "axum",
      "sqlx",
      "jsonwebtoken",
      "passkey-client",
      "passkey-authenticator",
    ],
  );

  assert_tree_excludes(
    &[
      "--color",
      "never",
      "tree",
      "--package",
      "haya",
      "--edges",
      "normal,build",
      "--target",
      "all",
      "--prefix",
      "none",
      "--format",
      "{p}",
    ],
    &SOFTWARE_PEERS,
  );
}

#[test]
fn software_peers_are_declared_only_by_root_as_dev_dependencies() {
  let metadata: Value =
    serde_json::from_str(&cargo_output(&["metadata", "--format-version", "1", "--no-deps"]))
      .expect("parse cargo metadata JSON");
  let workspace_root = metadata["workspace_root"]
    .as_str()
    .expect("workspace_root must be a string");
  let workspace_members = metadata["workspace_members"]
    .as_array()
    .expect("workspace_members must be an array")
    .iter()
    .map(|member| member.as_str().expect("workspace member ID must be a string"))
    .collect::<BTreeSet<_>>();
  let packages = metadata["packages"]
    .as_array()
    .expect("packages must be an array");
  let mut root_peers = BTreeSet::new();
  let mut found_root = false;

  for package in packages {
    let package_id = package["id"].as_str().expect("package ID must be a string");
    if !workspace_members.contains(package_id) {
      continue;
    }

    let manifest_path = package["manifest_path"]
      .as_str()
      .expect("manifest_path must be a string");
    let is_root = Path::new(manifest_path).parent() == Some(Path::new(workspace_root));
    found_root |= is_root;

    for dependency in package["dependencies"]
      .as_array()
      .expect("dependencies must be an array")
    {
      let name = dependency["name"]
        .as_str()
        .expect("dependency name must be a string");
      if !SOFTWARE_PEERS.contains(&name) {
        continue;
      }

      let kind = dependency["kind"].as_str().unwrap_or("normal");
      assert!(
        is_root,
        "non-root manifest {manifest_path} directly declares {name} as a {kind} dependency"
      );
      assert_eq!(
        kind, "dev",
        "root manifest must declare {name} only as a dev dependency"
      );
      assert!(
        root_peers.insert(name),
        "root manifest declares {name} more than once"
      );
    }
  }

  assert!(found_root, "cargo metadata did not include root package");
  assert_eq!(
    root_peers,
    SOFTWARE_PEERS.into_iter().collect(),
    "root manifest must directly declare both software peers as dev dependencies"
  );
}
