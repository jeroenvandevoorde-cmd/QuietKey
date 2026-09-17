#!/bin/sh
# QuietKey canonical checker. Fixed invariants only; fails closed.
# Contains no commit hashes, byte pins, ancestry checks, or phrase bans.
set -u

status=0
fail() { printf 'FAIL: %s\n' "$1" >&2; status=1; }
info() { printf 'INFO: %s\n' "$1"; }
ok() { printf 'OK: %s\n' "$1"; }

# --- 1. README warning header (must be the first line) -------------------
if [ -f README.md ] && [ "$(head -n 1 README.md)" = 'EXPERIMENTAL — NO REAL FUNDS — NOT A WALLET' ]; then
  ok 'README warning header present as first line'
else
  fail 'README.md first line is not the required warning header'
fi

# --- 2. No external dependency entries in any tracked Cargo.toml ---------
# Internal path-only references to members inside the canonical host workspace
# are allowed. An optional edge is accepted only in the exact two-key form
# needed for a compile-time feature boundary.
dependency_manifest_is_internal() {
  dependency_manifest=$1
  dependency_host_root=$2
  dependency_paths=$(mktemp) || return 2
  if ! awk '
    /^[[:space:]]*\[/ { insec = ($0 ~ /dependencies/) ? 1 : 0; next }
    insec && $0 !~ /^[[:space:]]*(#|$)/ {
      path_only = "^[A-Za-z0-9_-]+[[:space:]]*=[[:space:]]*\\{[[:space:]]*path[[:space:]]*=[[:space:]]*\\\"[^\\\"]+\\\"[[:space:]]*\\}[[:space:]]*$"
      path_optional = "^[A-Za-z0-9_-]+[[:space:]]*=[[:space:]]*\\{[[:space:]]*path[[:space:]]*=[[:space:]]*\\\"[^\\\"]+\\\"[[:space:]]*,[[:space:]]*optional[[:space:]]*=[[:space:]]*true[[:space:]]*\\}[[:space:]]*$"
      optional_path = "^[A-Za-z0-9_-]+[[:space:]]*=[[:space:]]*\\{[[:space:]]*optional[[:space:]]*=[[:space:]]*true[[:space:]]*,[[:space:]]*path[[:space:]]*=[[:space:]]*\\\"[^\\\"]+\\\"[[:space:]]*\\}[[:space:]]*$"
      if ($0 !~ path_only && $0 !~ path_optional && $0 !~ optional_path) exit 1
      path = $0
      sub(/^.*path[[:space:]]*=[[:space:]]*"/, "", path)
      sub(/".*$/, "", path)
      print path
    }
  ' "$dependency_manifest" > "$dependency_paths"; then
    rm -f "$dependency_paths"
    return 1
  fi

  dependency_manifest_dir=$(
    CDPATH=
    cd "$(dirname "$dependency_manifest")" 2>/dev/null && pwd -P
  ) || {
    rm -f "$dependency_paths"
    return 2
  }
  case "$dependency_manifest_dir" in
    "$dependency_host_root"|"$dependency_host_root"/*) ;;
    *)
      rm -f "$dependency_paths"
      return 1
      ;;
  esac

  dependency_paths_valid=1
  while IFS= read -r dependency_path; do
    case "$dependency_path" in
      /*)
        dependency_paths_valid=0
        break
        ;;
    esac
    dependency_resolved=$(
      CDPATH=
      cd "$dependency_manifest_dir/$dependency_path" 2>/dev/null && pwd -P
    ) || {
      dependency_paths_valid=0
      break
    }
    case "$dependency_resolved" in
      "$dependency_host_root"|"$dependency_host_root"/*) ;;
      *)
        dependency_paths_valid=0
        break
        ;;
    esac
  done < "$dependency_paths"
  rm -f "$dependency_paths"
  [ "$dependency_paths_valid" = 1 ]
}

dependency_self_test_root=$(mktemp -d) || dependency_self_test_root=''
dependency_self_tests=1
if [ -z "$dependency_self_test_root" ] ||
    ! mkdir -p "$dependency_self_test_root/host/member" \
      "$dependency_self_test_root/host/internal" "$dependency_self_test_root/outside"; then
  dependency_self_tests=0
else
  dependency_self_test_host=$(
    CDPATH=
    cd "$dependency_self_test_root/host" 2>/dev/null && pwd -P
  ) || dependency_self_test_host=''
  dependency_self_test_manifest="$dependency_self_test_root/host/member/Cargo.toml"
  for dependency_accepted in \
    'accepted = { path = "../internal" }' \
    'accepted = { path = "../internal", optional = true }' \
    'accepted = { optional = true, path = "../internal" }'; do
    printf '[dependencies]\n%s\n' "$dependency_accepted" > "$dependency_self_test_manifest" || \
      dependency_self_tests=0
    dependency_manifest_is_internal "$dependency_self_test_manifest" \
      "$dependency_self_test_host" || dependency_self_tests=0
  done

  while IFS= read -r dependency_rejected; do
    printf '[dependencies]\n%s\n' "$dependency_rejected" > "$dependency_self_test_manifest" || \
      dependency_self_tests=0
    if dependency_manifest_is_internal "$dependency_self_test_manifest" \
        "$dependency_self_test_host"; then
      dependency_self_tests=0
    fi
  done <<'EOF'
rejected = "1.0.0"
rejected = { git = "https://example.invalid/repository" }
rejected = { path = "../internal", version = "1.0.0" }
rejected = { path = "../internal", git = "https://example.invalid/repository" }
rejected = { path = "../internal", registry = "external" }
rejected = { path = "../internal", branch = "main" }
rejected = { path = "../internal", tag = "v1" }
rejected = { path = "../internal", rev = "deadbeef" }
rejected = { path = "../internal", features = [] }
rejected = { path = "../internal", default-features = false }
rejected = { path = "../internal", package = "other" }
rejected = { path = "../internal", workspace = true }
rejected = { path = "../internal", optional = false }
rejected = { path = "../internal", unknown = true }
rejected = { path = "../internal", path = "../internal" }
rejected = { optional = true }
EOF

  printf '[dependencies]\nrejected = { path = "../../outside" }\n' > \
    "$dependency_self_test_manifest" || dependency_self_tests=0
  if dependency_manifest_is_internal "$dependency_self_test_manifest" \
      "$dependency_self_test_host"; then
    dependency_self_tests=0
  fi
  printf '[dependencies]\nrejected = { path = "%s" }\n' \
    "$dependency_self_test_root/host/internal" > "$dependency_self_test_manifest" || \
    dependency_self_tests=0
  if dependency_manifest_is_internal "$dependency_self_test_manifest" \
      "$dependency_self_test_host"; then
    dependency_self_tests=0
  fi
fi
if [ -n "$dependency_self_test_root" ]; then
  rm -rf "$dependency_self_test_root"
fi
if [ "$dependency_self_tests" = 1 ]; then
  ok 'internal dependency checker self-tests passed'
else
  fail 'internal dependency checker self-tests failed'
fi

dependency_host_root=$(
  CDPATH=
  cd host 2>/dev/null && pwd -P
) || dependency_host_root=''
manifests=$(git ls-files | grep -E '(^|/)Cargo\.toml$') || manifests=''
if [ -z "$dependency_host_root" ]; then
  fail 'canonical host workspace is unavailable'
elif [ -z "$manifests" ]; then
  fail 'no tracked Cargo.toml found'
else
  for m in $manifests; do
    case "$m" in
      fuzz/Cargo.toml|fuzz/*/Cargo.toml)
        info "$m is governed by the reviewed fuzz dependency allowlist"
        continue
        ;;
      bench/card-enrollment/Cargo.toml)
        info "$m is governed by the reviewed bench dependency allowlist"
        continue
        ;;
    esac
    if dependency_manifest_is_internal "$m" "$dependency_host_root"; then
      ok "$m has only canonical internal dependency entries"
    else
      fail "$m dependency check failed (external, escaped or noncanonical entry)"
    fi
  done
fi

# --- 3. Ring-fenced fuzz dependency policy -------------------------------
if [ ! -x tools/check-fuzz-dependencies.sh ]; then
  fail 'tools/check-fuzz-dependencies.sh is missing or not executable'
elif ! command -v cargo >/dev/null 2>&1; then
  fail 'cargo unavailable; cannot prepare the host dependency lock'
elif ! cargo generate-lockfile --manifest-path host/Cargo.toml \
    --offline >/dev/null 2>&1; then
  fail 'host Cargo.lock generation failed offline'
elif tools/check-fuzz-dependencies.sh --require-ipc-isolation; then
  ok 'fuzz manifests match the reviewed pinned dependency allowlist'
else
  fail 'fuzz dependency allowlist check failed'
fi

# --- 3b. Ring-fenced bench dependency policy -----------------------------
if tools/check-bench-dependencies.sh; then
  ok 'bench manifest matches the reviewed pinned dependency allowlist and remains isolated'
else
  fail 'bench dependency allowlist or isolation check failed'
fi

tools/check-process-harness.sh || fail 'HOST process harness check failed'
tools/check-card-applet.sh || fail 'card applet build contract check failed'

# --- 4. Persistent fuzz corpus registry ---------------------------------
if [ ! -x tools/check-fuzz-corpora.sh ]; then
  fail 'tools/check-fuzz-corpora.sh is missing or not executable'
elif tools/check-fuzz-corpora.sh; then
  ok 'fuzz corpora match the registered byte counts and hashes'
else
  fail 'fuzz corpus registry check failed'
fi

# --- 5. Lexical secret scan of tracked files -----------------------------
p_key='-----BEGIN [A-Z ]*PRIVATE KEY-----'
p_xprv='xprv[1-9A-HJ-NP-Za-km-z]{40,}'
p_aws='AKIA[0-9A-Z]{16}'
p_ghp='ghp_[A-Za-z0-9]{36}'
p_gpat='github_pat_[A-Za-z0-9_]{22,}'
p_stripe='sk_live_[A-Za-z0-9]{16,}'
p_slack='xox[abprs]-[A-Za-z0-9-]{10,}'
probe_ok=1
printf '%s%s\n' '-----BEGIN ' 'PRIVATE KEY-----' | grep -q -E -e "$p_key" || probe_ok=0
printf '%s%s\n' 'AKIA' 'ABCDEFGHIJKLMNOP' | grep -q -E -e "$p_aws" || probe_ok=0
printf '%s%s\n' 'xprv' 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA' | grep -q -E -e "$p_xprv" || probe_ok=0
if [ "$probe_ok" = 1 ]; then
  scan_tmp=$(mktemp) && scan_err=$(mktemp) || { fail 'mktemp failed for secret scan'; scan_tmp=''; }
  if [ -n "$scan_tmp" ]; then
    # -a scans binary files as text (no -I skip); stderr is captured and any
    # diagnostic output fails the check, so scanner errors cannot pass silently.
    git ls-files -z | xargs -0 grep -a -n -E \
      -e "$p_key" -e "$p_xprv" -e "$p_aws" -e "$p_ghp" \
      -e "$p_gpat" -e "$p_stripe" -e "$p_slack" \
      > "$scan_tmp" 2> "$scan_err"
    scan_rc=$?
    if [ -s "$scan_tmp" ]; then
      fail 'likely real secret pattern found at:'
      cut -d: -f1,2 "$scan_tmp" >&2
    elif [ -s "$scan_err" ]; then
      fail 'secret scan reported errors:'
      cat "$scan_err" >&2
    # GNU xargs maps grep's no-match status to 123; BSD xargs returns 1.
    # Empty output and stderr above distinguish both from scan failures.
    elif [ "$scan_rc" = 0 ] || [ "$scan_rc" = 1 ] || [ "$scan_rc" = 123 ]; then
      ok 'no likely real secret patterns in tracked files'
    else
      fail "secret scan tool failure (exit $scan_rc)"
    fi
    rm -f "$scan_tmp" "$scan_err"
  fi
else
  fail 'secret scan self-test failed; scanner unreliable'
fi

# --- 5b. SEC1210/T=1 unsafe-code confinement ----------------------------
unsafe_token_pattern='(^|[^_[:alnum:]])unsafe([^_[:alnum:]]|$)'
for unsafe_crate in host/qk-sec1210-wire host/qk-t1; do
  unsafe_lib=$unsafe_crate/src/lib.rs
  unsafe_wipe=$unsafe_crate/src/wipe.rs
  if [ ! -f "$unsafe_lib" ] || [ ! -f "$unsafe_wipe" ]; then
    fail "$unsafe_crate unsafe-confinement source is missing"
    continue
  fi
  unsafe_sources=''
  unsafe_allow_matches=''
  unsafe_token_matches=''
  unsafe_link_matches=''
  unsafe_sources=$(mktemp) && unsafe_allow_matches=$(mktemp) && \
    unsafe_token_matches=$(mktemp) && unsafe_link_matches=$(mktemp) || {
      fail "$unsafe_crate cannot allocate unsafe-confinement scan files"
      [ -z "${unsafe_sources:-}" ] || rm -f "$unsafe_sources"
      [ -z "${unsafe_allow_matches:-}" ] || rm -f "$unsafe_allow_matches"
      [ -z "${unsafe_token_matches:-}" ] || rm -f "$unsafe_token_matches"
      continue
    }
  if ! find "$unsafe_crate/src" -type l -print > "$unsafe_link_matches" || \
      [ -s "$unsafe_link_matches" ]; then
    fail "$unsafe_crate source inventory contains a symlink or could not inspect symlinks"
    rm -f "$unsafe_sources" "$unsafe_allow_matches" "$unsafe_token_matches" \
      "$unsafe_link_matches"
    continue
  fi
  if ! find "$unsafe_crate/src" -type f -print > "$unsafe_sources" || \
      [ ! -s "$unsafe_sources" ]; then
    fail "$unsafe_crate complete source inventory failed"
    rm -f "$unsafe_sources" "$unsafe_allow_matches" "$unsafe_token_matches" \
      "$unsafe_link_matches"
    continue
  fi

  unsafe_scan_failed=0
  while IFS= read -r unsafe_source; do
    if [ ! -f "$unsafe_source" ] || [ ! -r "$unsafe_source" ]; then
      unsafe_scan_failed=1
      continue
    fi
    unsafe_file_matches=$(grep -a -n -F '#[allow(unsafe_code)]' "$unsafe_source" 2>&1)
    unsafe_file_rc=$?
    case "$unsafe_file_rc" in
      0)
        printf '%s\n' "$unsafe_file_matches" | \
          sed "s#^#$unsafe_source:#" >> "$unsafe_allow_matches" || unsafe_scan_failed=1
        ;;
      1) ;;
      *)
        unsafe_scan_failed=1
        [ -z "$unsafe_file_matches" ] || printf '%s\n' "$unsafe_file_matches" >&2
        ;;
    esac
    if [ "$unsafe_source" != "$unsafe_wipe" ]; then
      unsafe_file_matches=$(grep -a -n -E "$unsafe_token_pattern" "$unsafe_source" 2>&1)
      unsafe_file_rc=$?
      case "$unsafe_file_rc" in
        0)
          printf '%s\n' "$unsafe_file_matches" | \
            sed "s#^#$unsafe_source:#" >> "$unsafe_token_matches" || unsafe_scan_failed=1
          ;;
        1) ;;
        *)
          unsafe_scan_failed=1
          [ -z "$unsafe_file_matches" ] || printf '%s\n' "$unsafe_file_matches" >&2
          ;;
      esac
    fi
  done < "$unsafe_sources"

  if [ "$unsafe_scan_failed" != 0 ]; then
    fail "$unsafe_crate complete unsafe-confinement scan failed"
  elif awk -F: -v file="$unsafe_lib" '
      NR == 1 && NF == 3 && $1 == file && $2 ~ /^[0-9]+$/ &&
          $3 == "#[allow(unsafe_code)]" { valid = 1 }
      END { exit !(NR == 1 && valid == 1) }
    ' "$unsafe_allow_matches" && awk '
      previous == "#[allow(unsafe_code)]" && $0 == "mod wipe;" { attached++ }
      { previous = $0 }
      END { exit !(attached == 1) }
    ' "$unsafe_lib"; then
    ok "$unsafe_crate allows unsafe_code exactly once, on mod wipe"
  else
    fail "$unsafe_crate must allow unsafe_code exactly once and only on mod wipe"
  fi

  if [ "$unsafe_scan_failed" = 0 ] && [ ! -s "$unsafe_token_matches" ]; then
    ok "$unsafe_crate confines the unsafe token to wipe.rs"
  else
    fail "$unsafe_crate source outside wipe.rs contains the unsafe token"
    [ ! -s "$unsafe_token_matches" ] || cat "$unsafe_token_matches" >&2
  fi
  rm -f "$unsafe_sources" "$unsafe_allow_matches" "$unsafe_token_matches" \
    "$unsafe_link_matches"
done

# --- 6. Rust checks (host workspace, locked/offline) ----------------------
if [ ! -f host/Cargo.toml ]; then
  fail 'host/Cargo.toml is missing'
elif ! command -v cargo >/dev/null 2>&1; then
  fail 'cargo unavailable; required tests cannot run'
else
  if ! cargo fmt --version >/dev/null 2>&1; then
    fail 'rustfmt unavailable; required fmt check cannot run'
  elif cargo fmt --all --check --manifest-path host/Cargo.toml >/dev/null 2>&1; then
    ok 'cargo fmt --check passed'
  else
    fail 'cargo fmt --check reported formatting differences'
  fi
  if ! clippy_version=$(cargo clippy --version 2>/dev/null); then
    fail 'clippy unavailable; required clippy check cannot run'
  else
    clippy_patch=$(printf '%s\n' "$clippy_version" |
      sed -n 's/^clippy 0\.1\.\([0-9][0-9]*\) .*/\1/p')
    if [ -z "$clippy_patch" ]; then
      fail "unrecognized clippy version: $clippy_version"
    elif [ "$clippy_patch" -lt 98 ]; then
      fail "clippy 1.98 or newer required; found $clippy_version"
    # Clippy 1.98 introduced two style-only lints over frozen pre-M17 source.
    # Keep all warnings denied while exempting only those non-semantic rewrites;
    # the frozen crates remain byte-identical.
    elif cargo clippy --workspace --manifest-path host/Cargo.toml \
        --offline --quiet -- -D warnings \
        -A clippy::chunks_exact_to_as_chunks \
        -A clippy::collapsible_match >/dev/null 2>&1; then
      ok 'cargo clippy (warnings denied) passed'
    else
      fail 'cargo clippy (warnings denied) failed'
    fi
  fi
  if cargo clippy --manifest-path host/Cargo.toml -p qk-core --locked --offline \
      --no-default-features --features sec1210-production --all-targets -- \
      -D warnings -A clippy::chunks_exact_to_as_chunks \
      -A clippy::collapsible_match >/dev/null 2>&1; then
    ok 'qk-core sec1210-production clippy (no default features, all targets, warnings denied) passed'
  else
    fail 'qk-core sec1210-production clippy failed; tests using feature-gated APIs need the matching cfg'
  fi
  if cargo clippy --manifest-path host/Cargo.toml -p qk-core --locked --offline \
      --no-default-features --features sec1210-production,normal-process --all-targets -- \
      -D warnings -A clippy::chunks_exact_to_as_chunks \
      -A clippy::collapsible_match >/dev/null 2>&1; then
    ok 'qk-core sec1210-production,normal-process clippy (no default features, all targets, warnings denied) passed'
  else
    fail 'qk-core sec1210-production,normal-process clippy failed; tests using feature-gated APIs need the matching cfg'
  fi
  if cargo test --workspace --manifest-path host/Cargo.toml \
      --offline --quiet >/dev/null 2>&1; then
    ok 'cargo test (locked, offline) passed'
  else
    fail 'cargo test (locked, offline) failed'
  fi
fi

# --- Result ---------------------------------------------------------------
if [ "$status" = 0 ]; then
  printf 'CHECK PASS\n'
else
  printf 'CHECK FAIL\n' >&2
fi
exit "$status"
