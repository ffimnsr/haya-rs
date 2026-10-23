#!/usr/bin/env bash

set -euo pipefail

readonly RELEASE_MANIFEST="Cargo.toml"
readonly CHANGELOG_FILE="CHANGELOG.md"
readonly REMOTE_NAME="origin"

usage() {
  cat <<'EOF'
Usage: scripts/release.sh [options] [<version>]

Bump every workspace package version, update Cargo.lock and CHANGELOG.md, run
release quality checks, create a signed release commit, create a v-prefixed
annotated tag, and optionally push commit and tag.

Options:
  --major      Increment major version and reset minor/patch to zero.
  --minor      Increment minor version and reset patch to zero.
  --patch      Increment patch version.
  --skip-push  Create commit and tag locally without pushing to origin.
  -h, --help   Show this help message.

Examples:
  scripts/release.sh --patch
  scripts/release.sh --minor --skip-push
  scripts/release.sh 0.3.0
EOF
}

die() {
  printf 'error: %s\n' "$*" >&2
  exit 1
}

need_cmd() {
  command -v "$1" >/dev/null 2>&1 || die "required command not found: $1"
}

append_section_entry() {
  local section_name="$1"
  local entry="$2"

  printf -v "$section_name" '%s- %s\n' "${!section_name}" "$entry"
}

manifest_version() {
  local manifest="$1"

  awk '
    BEGIN { in_package = 0 }
    /^\[package\]$/ { in_package = 1; next }
    /^\[/ && $0 != "[package]" && in_package { in_package = 0 }
    in_package && /^version = "/ {
      gsub(/^version = "/, "", $0)
      gsub(/"$/, "", $0)
      print
      exit
    }
  ' "$manifest"
}

is_valid_version() {
  [[ "$1" =~ ^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$ ]]
}

increment_version() {
  local current="$1"
  local bump_kind="$2"
  local major minor patch

  IFS='.' read -r major minor patch <<<"$current"

  case "$bump_kind" in
    major)
      ((major += 1))
      minor=0
      patch=0
      ;;
    minor)
      ((minor += 1))
      patch=0
      ;;
    patch)
      ((patch += 1))
      ;;
    *)
      die "unsupported bump kind: $bump_kind"
      ;;
  esac

  printf '%s.%s.%s\n' "$major" "$minor" "$patch"
}

update_manifest_version() {
  local manifest="$1"
  local version="$2"
  local tmp

  tmp="$(mktemp)"
  awk -v version="$version" '
    BEGIN { in_package = 0; replaced = 0 }
    /^\[package\]$/ { in_package = 1 }
    /^\[/ && $0 != "[package]" && in_package { in_package = 0 }
    in_package && /^version = "/ && !replaced {
      print "version = \"" version "\""
      replaced = 1
      next
    }
    { print }
    END { if (!replaced) exit 1 }
  ' "$manifest" >"$tmp" || {
    rm -f "$tmp"
    die "failed to update version in $manifest"
  }
  mv "$tmp" "$manifest"
}

workspace_manifests() {
  awk '
    function trim(value) {
      gsub(/^[[:space:]]+|[[:space:]]+$/, "", value)
      return value
    }
    BEGIN { in_workspace = 0; in_members = 0 }
    /^\[workspace\][[:space:]]*$/ { in_workspace = 1; next }
    in_workspace && /^\[/ { exit }
    in_workspace {
      if (!in_members && $0 ~ /^[[:space:]]*members[[:space:]]*=/) {
        line = $0
        sub(/^[^=]*=/, "", line)
        in_members = ($0 !~ /\]/)
        sub(/^[[:space:]]*\[/, "", line)
      } else if (in_members) {
        line = $0
        in_members = ($0 !~ /\]/)
      } else {
        next
      }
      sub(/\].*$/, "", line)
      sub(/#.*/, "", line)
      gsub(/"/, "", line)
      count = split(line, parts, ",")
      for (i = 1; i <= count; i++) {
        member = trim(parts[i])
        if (length(member)) print member
      }
    }
  ' "$RELEASE_MANIFEST"
}

update_workspace_manifest_versions() {
  local version="$1"
  local member manifest

  while IFS= read -r member; do
    manifest="${member%/}/Cargo.toml"
    [[ -f "$manifest" ]] || die "workspace manifest not found: $manifest"
    update_manifest_version "$manifest" "$version"
  done < <(workspace_manifests)
}

stage_workspace_manifests() {
  local member manifest

  while IFS= read -r member; do
    manifest="${member%/}/Cargo.toml"
    git add "$manifest"
  done < <(workspace_manifests)
}

ensure_clean_worktree() {
  local status

  status="$(git status --porcelain)"
  [[ -z "$status" ]] || die "working tree must be clean before release"
}

previous_release_tag() {
  git describe --tags --abbrev=0 --match 'v[0-9]*.[0-9]*.[0-9]*' 2>/dev/null || true
}

render_changelog_group() {
  local title="$1"
  local content="$2"

  [[ -n "$content" ]] || return 0
  printf '### %s\n\n%s\n\n' "$title" "$content"
}

update_changelog() {
  local version="$1"
  local release_date="$2"
  local previous_tag="$3"
  local log_range="HEAD"
  local features=""
  local fixes=""
  local docs=""
  local tests=""
  local ci=""
  local maintenance=""
  local other=""
  local entry_count=0
  local conventional_commit_regex='^([[:alnum:]_-]+)(\([^)]+\))?(!)?:[[:space:]]*(.+)$'

  [[ -z "$previous_tag" ]] || log_range="${previous_tag}..HEAD"

  while IFS=$'\t' read -r commit_sha subject; do
    local short_sha category message commit_type
    [[ -n "$commit_sha" ]] || continue

    short_sha="$(git rev-parse --short "$commit_sha")"
    category="other"
    message="$subject"

    if [[ "$subject" =~ $conventional_commit_regex ]]; then
      commit_type="${BASH_REMATCH[1]}"
      message="${BASH_REMATCH[4]}"
      case "$commit_type" in
        feat) category="features" ;;
        fix) category="fixes" ;;
        docs) category="docs" ;;
        test) category="tests" ;;
        ci) category="ci" ;;
        build|style|refactor|perf|chore) category="maintenance" ;;
      esac
    fi

    case "$category" in
      features) append_section_entry features "${message} (\`${short_sha}\`)" ;;
      fixes) append_section_entry fixes "${message} (\`${short_sha}\`)" ;;
      docs) append_section_entry docs "${message} (\`${short_sha}\`)" ;;
      tests) append_section_entry tests "${message} (\`${short_sha}\`)" ;;
      ci) append_section_entry ci "${message} (\`${short_sha}\`)" ;;
      maintenance) append_section_entry maintenance "${message} (\`${short_sha}\`)" ;;
      *) append_section_entry other "${message} (\`${short_sha}\`)" ;;
    esac
    ((entry_count += 1))
  done < <(git log --reverse --format='%H%x09%s' "$log_range")

  ((entry_count > 0)) || die "no commits found for changelog range: $log_range"

  if [[ -f "$CHANGELOG_FILE" ]] && grep -Eq "^## ${version//./\\.}([[:space:]]|$)" "$CHANGELOG_FILE"; then
    die "$CHANGELOG_FILE already contains version $version"
  fi

  local tmp preface="" existing_releases=""
  tmp="$(mktemp)"

  if [[ -f "$CHANGELOG_FILE" ]]; then
    preface="$(awk '
      /^## [0-9]+\.[0-9]+\.[0-9]+([[:space:]]|$)/ { exit }
      { print }
    ' "$CHANGELOG_FILE")"
    existing_releases="$(awk '
      BEGIN { seen_release = 0 }
      /^## [0-9]+\.[0-9]+\.[0-9]+([[:space:]]|$)/ { seen_release = 1 }
      seen_release { print }
    ' "$CHANGELOG_FILE")"
  fi

  {
    if [[ -n "$preface" ]]; then
      printf '%s\n\n' "$preface"
    else
      printf '# Changelog\n\n'
    fi
    printf '## %s - %s\n\n' "$version" "$release_date"
    render_changelog_group "Features" "$features"
    render_changelog_group "Fixes" "$fixes"
    render_changelog_group "Documentation" "$docs"
    render_changelog_group "Tests" "$tests"
    render_changelog_group "CI" "$ci"
    render_changelog_group "Maintenance" "$maintenance"
    render_changelog_group "Other Changes" "$other"
    [[ -z "$existing_releases" ]] || printf '%s\n' "$existing_releases"
  } >"$tmp"

  mv "$tmp" "$CHANGELOG_FILE"
}

ensure_remote_exists() {
  git remote get-url "$REMOTE_NAME" >/dev/null 2>&1 ||
    die "git remote '$REMOTE_NAME' is not configured"
}

ensure_tag_absent() {
  local tag_name="$1"

  if git rev-parse --verify "refs/tags/$tag_name" >/dev/null 2>&1; then
    die "tag '$tag_name' already exists locally"
  fi

  if git remote get-url "$REMOTE_NAME" >/dev/null 2>&1 &&
    git ls-remote --exit-code --tags "$REMOTE_NAME" "refs/tags/$tag_name" >/dev/null 2>&1; then
    die "tag '$tag_name' already exists on '$REMOTE_NAME'"
  fi
}

run_quality_gates() {
  cargo generate-lockfile
  cargo +nightly fmt --all -- --check
  cargo test --quiet --package haya-passkey-rp
  cargo test --quiet --package haya
  cargo clippy --workspace --all-targets --all-features -- -D warnings
}

main() {
  local run_push=1
  local version=""
  local bump_kind=""

  while (($# > 0)); do
    case "$1" in
      --major|--minor|--patch)
        [[ -z "$bump_kind" ]] || die "only one version bump flag may be used"
        bump_kind="${1#--}"
        shift
        ;;
      --skip-push)
        run_push=0
        shift
        ;;
      -h|--help)
        usage
        exit 0
        ;;
      -*) die "unknown option: $1" ;;
      *)
        [[ -z "$version" ]] || die "version may only be provided once"
        version="$1"
        shift
        ;;
    esac
  done

  if [[ -z "$version" && -z "$bump_kind" ]]; then
    usage
    exit 1
  fi
  [[ -z "$version" || -z "$bump_kind" ]] ||
    die "pass either an explicit version or one bump flag"

  need_cmd awk
  need_cmd cargo
  need_cmd date
  need_cmd git
  need_cmd mktemp

  local repo_root old_version tag_name previous_tag release_date
  repo_root="$(git rev-parse --show-toplevel 2>/dev/null)" ||
    die "must be run inside a git repository"
  cd "$repo_root"

  ensure_clean_worktree
  old_version="$(manifest_version "$RELEASE_MANIFEST")"
  is_valid_version "$old_version" || die "current version must match x.y.z"

  if [[ -n "$bump_kind" ]]; then
    version="$(increment_version "$old_version" "$bump_kind")"
  fi
  is_valid_version "$version" || die "version must match x.y.z without leading zeroes"
  [[ "$version" != "$old_version" ]] || die "version is already $version"

  tag_name="v$version"
  ((run_push == 0)) || ensure_remote_exists
  ensure_tag_absent "$tag_name"
  previous_tag="$(previous_release_tag)"
  release_date="$(date +%Y-%m-%d)"

  update_workspace_manifest_versions "$version"
  update_changelog "$version" "$release_date" "$previous_tag"
  run_quality_gates

  git add Cargo.lock "$CHANGELOG_FILE"
  stage_workspace_manifests
  git commit -s -m "chore(release): $tag_name" \
    -m "bump workspace packages to $version and update generated release notes"
  git tag -a "$tag_name" -m "release: $tag_name"

  if ((run_push)); then
    git push "$REMOTE_NAME" HEAD
    git push "$REMOTE_NAME" "$tag_name"
  fi

  printf 'Released %s -> %s (%s)\n' "$old_version" "$version" "$tag_name"
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
  main "$@"
fi
