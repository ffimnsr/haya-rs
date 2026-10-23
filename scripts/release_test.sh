#!/usr/bin/env bash

set -euo pipefail

readonly SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=release.sh
source "$SCRIPT_DIR/release.sh"

assert_eq() {
  local expected="$1"
  local actual="$2"
  local label="$3"

  if [[ "$expected" != "$actual" ]]; then
    printf 'FAIL: %s: expected %q, got %q\n' "$label" "$expected" "$actual" >&2
    exit 1
  fi
}

assert_contains() {
  local file="$1"
  local text="$2"

  grep -Fq -- "$text" "$file" || {
    printf 'FAIL: %s does not contain %q\n' "$file" "$text" >&2
    exit 1
  }
}

assert_eq "2.0.0" "$(increment_version 1.2.3 major)" "major bump"
assert_eq "1.3.0" "$(increment_version 1.2.3 minor)" "minor bump"
assert_eq "1.2.4" "$(increment_version 1.2.3 patch)" "patch bump"
is_valid_version 0.2.0 || { printf 'FAIL: valid version rejected\n' >&2; exit 1; }
if is_valid_version 01.2.3; then
  printf 'FAIL: leading-zero version accepted\n' >&2
  exit 1
fi

work_dir="$(mktemp -d)"
trap 'rm -rf "$work_dir"' EXIT

cat >"$work_dir/Cargo.toml" <<'EOF'
[workspace]
members = [".", "crates/internal"]
resolver = "2"

[package]
name = "fixture"
version = "1.2.3"
EOF

mkdir -p "$work_dir/crates/internal"
cat >"$work_dir/crates/internal/Cargo.toml" <<'EOF'
[package]
name = "internal"
version = "0.1.0"
publish = false
EOF

assert_eq "1.2.3" "$(manifest_version "$work_dir/Cargo.toml")" "manifest read"
update_manifest_version "$work_dir/Cargo.toml" 1.3.0
assert_eq "1.3.0" "$(manifest_version "$work_dir/Cargo.toml")" "manifest update"

(
  cd "$work_dir"
  assert_eq $'.\ncrates/internal' "$(workspace_manifests)" "workspace manifests"
  update_workspace_manifest_versions 2.0.0
  assert_eq "2.0.0" "$(manifest_version Cargo.toml)" "root workspace version"
  assert_eq "2.0.0" "$(manifest_version crates/internal/Cargo.toml)" "crate workspace version"
)

(
  cd "$work_dir"
  git init --quiet
  git config user.email release-test@example.com
  git config user.name release-test
  printf 'initial\n' >fixture.txt
  git add fixture.txt
  git commit --quiet -m 'feat: add fixture'
  printf 'fixed\n' >>fixture.txt
  git add fixture.txt
  git commit --quiet -m 'fix(core): repair fixture'

  update_changelog 1.3.0 2026-09-02 ""
  assert_contains CHANGELOG.md '## 1.3.0 - 2026-09-02'
  assert_contains CHANGELOG.md '### Features'
  assert_contains CHANGELOG.md '- add fixture (`'
  assert_contains CHANGELOG.md '### Fixes'
  assert_contains CHANGELOG.md '- repair fixture (`'
)

printf 'release script tests passed\n'
