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
# Internal path-only references to sibling workspace members are allowed;
# any registry, git, version, or other external dependency entry fails.
manifests=$(git ls-files | grep -E '(^|/)Cargo\.toml$') || manifests=''
if [ -z "$manifests" ]; then
  fail 'no tracked Cargo.toml found'
else
  for m in $manifests; do
    n=$(awk '
      /^[[:space:]]*\[/ { insec = ($0 ~ /dependencies/) ? 1 : 0; next }
      insec && $0 !~ /^[[:space:]]*(#|$)/ {
        if ($0 !~ /^[A-Za-z0-9_-]+[[:space:]]*=[[:space:]]*\{[[:space:]]*path[[:space:]]*=[[:space:]]*"[^"]*"[[:space:]]*\}[[:space:]]*$/) bad++
      }
      END { print bad + 0 }
    ' "$m") || n=err
    if [ "$n" = 0 ]; then
      ok "$m has no external dependency entries"
    else
      fail "$m dependency check failed (external entries or tool error: $n)"
    fi
  done
fi

# --- 3. Lexical secret scan of tracked files -----------------------------
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

# --- 4. Rust checks (host workspace, locked/offline) ----------------------
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
  if ! cargo clippy --version >/dev/null 2>&1; then
    fail 'clippy unavailable; required clippy check cannot run'
  elif cargo clippy --workspace --manifest-path host/Cargo.toml \
      --offline --quiet -- -D warnings >/dev/null 2>&1; then
    ok 'cargo clippy (warnings denied) passed'
  else
    fail 'cargo clippy (warnings denied) failed'
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
