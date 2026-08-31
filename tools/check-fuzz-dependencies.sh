#!/bin/sh
# Fail-closed validator for QK-DEC-106's ring-fenced fuzz manifests.
set -u

fail() { printf 'FAIL: %s\n' "$1" >&2; exit 1; }

case "$#" in
  0) ;;
  1) [ "$1" = '--require-ipc-isolation' ] || fail "unknown argument: $1" ;;
  *) fail 'usage: tools/check-fuzz-dependencies.sh [--require-ipc-isolation]' ;;
esac

sha256_file() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1" | awk '{print $1}'
  elif command -v shasum >/dev/null 2>&1; then
    shasum -a 256 "$1" | awk '{print $1}'
  else
    return 1
  fi
}

root=$(git rev-parse --show-toplevel 2>/dev/null) || fail 'not inside a Git worktree'
cd "$root" || fail 'cannot enter worktree root'

allowlist='fuzz/DEPENDENCY-ALLOWLIST.tsv'
[ -f "$allowlist" ] || fail "$allowlist is missing"
[ "$(sed -n 's/^channel = "\([^"]*\)"$/\1/p' fuzz/rust-toolchain.toml)" = \
  'nightly-2026-08-25' ] || fail 'fuzz toolchain channel is not the reviewed pin'

profile_flags=$(awk '
  /^[[:space:]]*\[/ { release = ($0 == "[profile.release]"); next }
  release && $0 == "overflow-checks = true" { overflow++ }
  release && $0 == "debug-assertions = true" { assertions++ }
  END { print overflow + 0, assertions + 0 }
' fuzz/Cargo.toml) || fail 'cannot inspect fuzz build profile'
[ "$profile_flags" = '1 1' ] || fail 'fuzz release profile must enable overflow checks and debug assertions exactly once'

process_feature_counts=$(awk '
  $0 == "process-s2-decoy = [\"dep:qk-decoy\", \"qk-decoy/fuzzing\"]" { decoy++ }
  $0 == "process-s2-supervisor = [\"dep:qk-supervisor\", \"qk-supervisor/fuzzing\"]" { supervisor++ }
  $0 == "process-s3-io = [" { io_start = 1; io_blocks++ }
  io_start && $0 == "    \"dep:qk-bbqr\"," { bbqr++ }
  io_start && $0 == "    \"dep:qk-io\"," { io_dep++ }
  io_start && $0 == "    \"dep:qk-ipc\"," { ipc++ }
  io_start && $0 == "    \"qk-io/fuzzing\"," { io_fuzz++ }
  io_start && $0 == "    \"qk-ipc/fuzzing\"," { ipc_fuzz++ }
  io_start && $0 == "]" { io_end++; io_start = 0 }
  $0 == "process-s4-core = [" { core_s4_start = 1; core_s4_blocks++ }
  core_s4_start && $0 == "    \"dep:qk-core\"," { core_s4_dep++ }
  core_s4_start && $0 == "    \"dep:qk-ipc\"," { core_s4_ipc++ }
  core_s4_start && $0 == "    \"qk-core/fuzzing\"," { core_s4_fuzz++ }
  core_s4_start && $0 == "    \"qk-ipc/fuzzing\"," { core_s4_ipc_fuzz++ }
  core_s4_start && $0 == "]" { core_s4_end++; core_s4_start = 0 }
  $0 == "process-s5-core = [" { core_s5_start = 1; core_s5_blocks++ }
  core_s5_start && $0 == "    \"dep:qk-core\"," { core_s5_dep++ }
  core_s5_start && $0 == "    \"dep:qk-ipc\"," { core_s5_ipc++ }
  core_s5_start && $0 == "    \"qk-core/fuzzing\"," { core_s5_fuzz++ }
  core_s5_start && $0 == "    \"qk-ipc/fuzzing\"," { core_s5_ipc_fuzz++ }
  core_s5_start && $0 == "]" { core_s5_end++; core_s5_start = 0 }
  END { print decoy + 0, supervisor + 0, io_blocks + 0, io_start + 0, io_end + 0, bbqr + 0, io_dep + 0, ipc + 0, io_fuzz + 0, ipc_fuzz + 0, core_s4_blocks + 0, core_s4_start + 0, core_s4_end + 0, core_s4_dep + 0, core_s4_ipc + 0, core_s4_fuzz + 0, core_s4_ipc_fuzz + 0, core_s5_blocks + 0, core_s5_start + 0, core_s5_end + 0, core_s5_dep + 0, core_s5_ipc + 0, core_s5_fuzz + 0, core_s5_ipc_fuzz + 0 }
' fuzz/Cargo.toml) || fail 'cannot inspect process fuzz feature declarations'
[ "$process_feature_counts" = '1 1 1 0 1 1 1 1 1 1 1 0 1 1 1 1 1 1 0 1 1 1 1 1' ] || \
  fail 'process fuzz features are not declared exactly once in canonical form'

if ! awk '
  function flush_bin() {
    if (!in_bin) return
    if (name == "qk_decoy_calculator") {
      decoy++
      if (required != "process-s2-decoy") bad = 1
    } else if (name == "qk_supervisor_lifecycle") {
      supervisor++
      if (required != "process-s2-supervisor") bad = 1
    } else if (name == "qk_io_ingress" || name == "qk_io_egress" || name == "qk_io_session") {
      io++
      if (required != "process-s3-io") bad = 1
    } else if (name == "qk_core_io_peer" || name == "qk_core_session") {
      core_s4++
      if (required != "process-s4-core") bad = 1
    } else if (name == "qk_core_provisioning_entry" || name == "qk_core_provisioning_run") {
      core_s5++
      if (required != "process-s5-core") bad = 1
    } else if (required == "process-s2-decoy" || required == "process-s2-supervisor" || required == "process-s3-io" || required == "process-s4-core" || required == "process-s5-core") {
      bad = 1
    }
  }
  /^\[\[bin\]\]$/ {
    flush_bin()
    in_bin = 1
    name = ""
    required = ""
    next
  }
  /^\[/ {
    flush_bin()
    in_bin = 0
    next
  }
  in_bin && /^name = "/ {
    name = $0
    sub(/^name = "/, "", name)
    sub(/"$/, "", name)
    next
  }
  in_bin && /^required-features = \["/ {
    required = $0
    sub(/^required-features = \["/, "", required)
    sub(/"\]$/, "", required)
  }
  END {
    flush_bin()
    exit (bad || decoy != 1 || supervisor != 1 || io != 3 || core_s4 != 2 || core_s5 != 2) ? 1 : 0
  }
' fuzz/Cargo.toml; then
  fail 'process fuzz target-to-feature mapping is not exact'
fi

fuzz_manifests=$(git ls-files | grep -E '^fuzz/(.*/)?Cargo\.toml$') || fuzz_manifests=''
[ -n "$fuzz_manifests" ] || fail 'no tracked fuzz/**/Cargo.toml manifest found'

dep_tmp=$(mktemp) || fail 'mktemp failed for fuzz dependency declarations'
tree_tmp=$(mktemp) || fail 'mktemp failed for fuzz dependency tree'
default_raw_tmp=$(mktemp) || fail 'mktemp failed for raw default fuzz dependency closure'
default_tmp=$(mktemp) || fail 'mktemp failed for default fuzz dependency closure'
ipc_raw_tmp=$(mktemp) || fail 'mktemp failed for raw IPC fuzz dependency closure'
ipc_tmp=$(mktemp) || fail 'mktemp failed for IPC fuzz dependency closure'
decoy_raw_tmp=$(mktemp) || fail 'mktemp failed for raw process-s2-decoy fuzz dependency closure'
decoy_tmp=$(mktemp) || fail 'mktemp failed for process-s2-decoy fuzz dependency closure'
supervisor_raw_tmp=$(mktemp) || fail 'mktemp failed for raw process-s2-supervisor fuzz dependency closure'
supervisor_tmp=$(mktemp) || fail 'mktemp failed for process-s2-supervisor fuzz dependency closure'
io_raw_tmp=$(mktemp) || fail 'mktemp failed for raw process-s3-io fuzz dependency closure'
io_tmp=$(mktemp) || fail 'mktemp failed for process-s3-io fuzz dependency closure'
core_raw_tmp=$(mktemp) || fail 'mktemp failed for raw process-s4-core fuzz dependency closure'
core_tmp=$(mktemp) || fail 'mktemp failed for process-s4-core fuzz dependency closure'
core_s5_raw_tmp=$(mktemp) || fail 'mktemp failed for raw process-s5-core fuzz dependency closure'
core_s5_tmp=$(mktemp) || fail 'mktemp failed for process-s5-core fuzz dependency closure'
host_decoy_raw_tmp=$(mktemp) || fail 'mktemp failed for raw qk-decoy host dependency closure'
host_decoy_tmp=$(mktemp) || fail 'mktemp failed for qk-decoy host dependency closure'
host_supervisor_raw_tmp=$(mktemp) || fail 'mktemp failed for raw qk-supervisor host dependency closure'
host_supervisor_tmp=$(mktemp) || fail 'mktemp failed for qk-supervisor host dependency closure'
host_io_raw_tmp=$(mktemp) || fail 'mktemp failed for raw qk-io host dependency closure'
host_io_tmp=$(mktemp) || fail 'mktemp failed for qk-io host dependency closure'
host_core_raw_tmp=$(mktemp) || fail 'mktemp failed for raw qk-core host dependency closure'
host_core_tmp=$(mktemp) || fail 'mktemp failed for qk-core host dependency closure'
closure_raw_tmp=$(mktemp) || fail 'mktemp failed for raw union fuzz dependency closure'
closure_tmp=$(mktemp) || fail 'mktemp failed for union fuzz dependency closure'
trap 'rm -f "$dep_tmp" "$tree_tmp" "$default_raw_tmp" "$default_tmp" \
  "$ipc_raw_tmp" "$ipc_tmp" "$decoy_raw_tmp" "$decoy_tmp" \
  "$supervisor_raw_tmp" "$supervisor_tmp" "$io_raw_tmp" "$io_tmp" "$host_decoy_raw_tmp" \
  "$core_raw_tmp" "$core_tmp" "$core_s5_raw_tmp" "$core_s5_tmp" \
  "$host_decoy_tmp" "$host_supervisor_raw_tmp" "$host_supervisor_tmp" \
  "$host_io_raw_tmp" "$host_io_tmp" "$host_core_raw_tmp" "$host_core_tmp" \
  "$closure_raw_tmp" "$closure_tmp"' EXIT HUP INT TERM

for manifest in $fuzz_manifests; do
  [ -f "$manifest" ] || fail "tracked fuzz manifest is missing: $manifest"
  awk -v manifest="$manifest" '
    /^[[:space:]]*\[/ {
      dependency_section = ($0 == "[dependencies]" ||
        $0 == "[dev-dependencies]" || $0 == "[build-dependencies]")
      if (!dependency_section &&
          ($0 ~ /^[[:space:]]*\[((dev-|build-)?dependencies)(\.|\])/ ||
           $0 ~ /\.((dev-|build-)?dependencies)(\.|\])/) ) {
        print "ERROR|" manifest "|" NR "|non-top-level dependency tables are forbidden"
      }
      if ($0 ~ /^\[(patch|replace)(\.|\])/) {
        print "ERROR|" manifest "|" NR "|patch and replace tables are forbidden"
      }
      next
    }
    dependency_section && $0 !~ /^[[:space:]]*(#|$)/ {
      line = $0
      name = line
      sub(/[[:space:]]*=.*/, "", name)
      if (name !~ /^[A-Za-z0-9_-]+$/) {
        print "ERROR|" manifest "|" NR "|invalid dependency name"
        next
      }
      version = line
      if (version !~ /version[[:space:]]*=[[:space:]]*"=[0-9A-Za-z.+-]+"/) {
        print "ERROR|" manifest "|" NR "|dependency version is not exact"
        next
      }
      sub(/^.*version[[:space:]]*=[[:space:]]*"=/, "", version)
      sub(/".*$/, "", version)
      if (line ~ /path[[:space:]]*=/) {
        kind = "path"
        if (line ~ /optional[[:space:]]*=/) {
          expected = "../host/" name
          pattern = "^" name "[[:space:]]*=[[:space:]]*\\{[[:space:]]*path[[:space:]]*=[[:space:]]*\\\"" expected "\\\"[[:space:]]*,[[:space:]]*version[[:space:]]*=[[:space:]]*\\\"=0\\.0\\.1\\\"[[:space:]]*,[[:space:]]*optional[[:space:]]*=[[:space:]]*true[[:space:]]*\\}[[:space:]]*$"
          if (line !~ pattern) {
            print "ERROR|" manifest "|" NR "|" name " optional dependency is not canonical"
            next
          }
        } else if (line !~ /^[A-Za-z0-9_-]+[[:space:]]*=[[:space:]]*\{[[:space:]]*path[[:space:]]*=[[:space:]]*"[^"]+"[[:space:]]*,[[:space:]]*version[[:space:]]*=[[:space:]]*"=[0-9A-Za-z.+-]+"[[:space:]]*\}[[:space:]]*$/) {
          print "ERROR|" manifest "|" NR "|path dependency is not canonical"
          next
        }
      } else {
        kind = "registry"
        if (line !~ /^[A-Za-z0-9_-]+[[:space:]]*=[[:space:]]*\{[[:space:]]*version[[:space:]]*=[[:space:]]*"=[0-9A-Za-z.+-]+"[[:space:]]*\}[[:space:]]*$/) {
          print "ERROR|" manifest "|" NR "|registry dependency is not canonical"
          next
        }
      }
      print "DEP|" manifest "|" name "|" version "|" kind
    }
  ' "$manifest" >> "$dep_tmp" || fail "cannot parse $manifest"
done

if grep -q '^ERROR|' "$dep_tmp"; then
  sed -n 's/^ERROR|/fuzz manifest error: /p' "$dep_tmp" >&2
  exit 1
fi
[ -s "$dep_tmp" ] || fail 'fuzz manifests contain no dependencies'

if ! awk -F '\t' '
  /^#/ { next }
  NF != 7 { bad = 1; next }
  $1 != "registry" && $1 != "path" { bad = 1 }
  $2 !~ /^[A-Za-z0-9_-]+$/ || $3 !~ /^[0-9A-Za-z.+-]+$/ { bad = 1 }
  length($4) != 64 || $4 ~ /[^0-9a-f]/ { bad = 1 }
  $5 == "" || $6 == "" || $7 == "" { bad = 1 }
  seen[$1 SUBSEP $2 SUBSEP $3]++ { bad = 1 }
  END { exit bad ? 1 : 0 }
' "$allowlist"; then
  fail "$allowlist has a malformed or duplicate row"
fi

tab=$(printf '\t')
while IFS='|' read -r marker manifest name version kind; do
  [ "$marker" = DEP ] || continue
  matches=$(awk -F '\t' -v k="$kind" -v n="$name" -v v="$version" \
    '!/^#/ && $1 == k && $2 == n && $3 == v { count++ } END { print count + 0 }' \
    "$allowlist") || fail 'allowlist lookup failed'
  [ "$matches" = 1 ] || fail "$manifest dependency $name $version is not uniquely allowed"
done < "$dep_tmp"

command -v cargo >/dev/null 2>&1 || fail 'cargo is required to resolve the fuzz dependency closure'
command -v rustc >/dev/null 2>&1 || fail 'rustc is required to identify the fuzz build target'
host_target=$(rustc -vV | sed -n 's/^host: //p')
[ -n "$host_target" ] || fail 'cannot identify the fuzz build target'
if ! CARGO_NET_OFFLINE=true cargo tree --manifest-path fuzz/Cargo.toml --locked --offline \
    --target "$host_target" --edges normal,build --prefix none --format '{p}' > "$tree_tmp"; then
  fail 'cannot resolve the locked default fuzz dependency closure offline'
fi
if ! awk '
  {
    line = $0
    sub(/[[:space:]]+\(\*\)$/, "", line)
    split(line, fields, " ")
    name = fields[1]
    version = fields[2]
    sub(/^v/, "", version)
    if (name == "quietkey-fuzz") next
    kind = (name ~ /^qk-/) ? "path" : "registry"
    if (name == "" || version == "") exit 1
    print kind "|" name "|" version
  }
  ' "$tree_tmp" > "$default_raw_tmp"; then
  fail 'cannot parse default fuzz dependency closure'
fi
sort -u "$default_raw_tmp" > "$default_tmp" || fail 'cannot normalize default fuzz dependency closure'
[ -s "$default_tmp" ] || fail 'default fuzz dependency closure is empty'
if awk -F '|' '$1 == "path" && ($2 == "qk-ipc" || $2 == "qk-decoy" || $2 == "qk-supervisor" || $2 == "qk-io" || $2 == "qk-core") { found = 1 } END { exit found ? 0 : 1 }' \
    "$default_tmp"; then
  fail 'a ring-fenced process dependency is reachable from the default fuzz dependency closure'
fi

if ! CARGO_NET_OFFLINE=true cargo tree --manifest-path fuzz/Cargo.toml --locked --offline \
    --features ipc --target "$host_target" --edges normal,build --prefix none --format '{p}' \
    > "$tree_tmp"; then
  fail 'cannot resolve the locked IPC-feature fuzz dependency closure offline'
fi
if ! awk '
  {
    line = $0
    sub(/[[:space:]]+\(\*\)$/, "", line)
    split(line, fields, " ")
    name = fields[1]
    version = fields[2]
    sub(/^v/, "", version)
    if (name == "quietkey-fuzz") next
    kind = (name ~ /^qk-/) ? "path" : "registry"
    if (name == "" || version == "") exit 1
    print kind "|" name "|" version
  }
' "$tree_tmp" > "$ipc_raw_tmp"; then
  fail 'cannot parse IPC-feature fuzz dependency closure'
fi
sort -u "$ipc_raw_tmp" > "$ipc_tmp" || fail 'cannot normalize IPC-feature fuzz dependency closure'
[ -s "$ipc_tmp" ] || fail 'IPC-feature fuzz dependency closure is empty'
ipc_matches=$(awk -F '|' \
  '$1 == "path" && $2 == "qk-ipc" && $3 == "0.0.1" { count++ } END { print count + 0 }' \
  "$ipc_tmp") || fail 'cannot inspect IPC-feature fuzz dependency closure'
[ "$ipc_matches" = 1 ] || fail 'qk-ipc 0.0.1 is not present exactly once in the IPC-feature fuzz dependency closure'
if awk -F '|' '$1 == "path" && ($2 == "qk-decoy" || $2 == "qk-supervisor" || $2 == "qk-io" || $2 == "qk-core") { found = 1 } END { exit found ? 0 : 1 }' \
    "$ipc_tmp"; then
  fail 'a process dependency is reachable from the IPC-only fuzz dependency closure'
fi

if ! CARGO_NET_OFFLINE=true cargo tree --manifest-path fuzz/Cargo.toml --locked --offline \
    --no-default-features --features process-s2-decoy --target "$host_target" --edges normal,build \
    --prefix none --format '{p}' > "$tree_tmp"; then
  fail 'cannot resolve the locked process-s2-decoy fuzz dependency closure offline'
fi
if ! awk '
  {
    line = $0
    sub(/[[:space:]]+\(\*\)$/, "", line)
    split(line, fields, " ")
    name = fields[1]
    version = fields[2]
    sub(/^v/, "", version)
    if (name == "quietkey-fuzz") next
    kind = (name ~ /^qk-/) ? "path" : "registry"
    if (name == "" || version == "") exit 1
    print kind "|" name "|" version
  }
' "$tree_tmp" > "$decoy_raw_tmp"; then
  fail 'cannot parse process-s2-decoy fuzz dependency closure'
fi
sort -u "$decoy_raw_tmp" > "$decoy_tmp" || \
  fail 'cannot normalize process-s2-decoy fuzz dependency closure'
[ -s "$decoy_tmp" ] || fail 'process-s2-decoy fuzz dependency closure is empty'
decoy_matches=$(awk -F '|' \
  '$1 == "path" && $2 == "qk-decoy" && $3 == "0.0.1" { count++ } END { print count + 0 }' \
  "$decoy_tmp") || fail 'cannot inspect process-s2-decoy fuzz dependency closure'
[ "$decoy_matches" = 1 ] || \
  fail 'qk-decoy 0.0.1 is not present exactly once in the process-s2-decoy fuzz dependency closure'
decoy_path_set=$(awk -F '|' '$1 == "path" { print $2 "|" $3 }' "$decoy_tmp") || \
  fail 'cannot enumerate process-s2-decoy path dependencies'
[ "$decoy_path_set" = 'qk-decoy|0.0.1' ] || \
  fail 'process-s2-decoy path dependency closure is not exactly qk-decoy 0.0.1'

if ! CARGO_NET_OFFLINE=true cargo tree --manifest-path fuzz/Cargo.toml --locked --offline \
    --no-default-features --features process-s2-supervisor --target "$host_target" --edges normal,build \
    --prefix none --format '{p}' > "$tree_tmp"; then
  fail 'cannot resolve the locked process-s2-supervisor fuzz dependency closure offline'
fi
if ! awk '
  {
    line = $0
    sub(/[[:space:]]+\(\*\)$/, "", line)
    split(line, fields, " ")
    name = fields[1]
    version = fields[2]
    sub(/^v/, "", version)
    if (name == "quietkey-fuzz") next
    kind = (name ~ /^qk-/) ? "path" : "registry"
    if (name == "" || version == "") exit 1
    print kind "|" name "|" version
  }
' "$tree_tmp" > "$supervisor_raw_tmp"; then
  fail 'cannot parse process-s2-supervisor fuzz dependency closure'
fi
sort -u "$supervisor_raw_tmp" > "$supervisor_tmp" || \
  fail 'cannot normalize process-s2-supervisor fuzz dependency closure'
[ -s "$supervisor_tmp" ] || fail 'process-s2-supervisor fuzz dependency closure is empty'
supervisor_matches=$(awk -F '|' \
  '$1 == "path" && $2 == "qk-supervisor" && $3 == "0.0.1" { count++ } END { print count + 0 }' \
  "$supervisor_tmp") || fail 'cannot inspect process-s2-supervisor fuzz dependency closure'
[ "$supervisor_matches" = 1 ] || \
  fail 'qk-supervisor 0.0.1 is not present exactly once in the process-s2-supervisor fuzz dependency closure'
ipc_matches=$(awk -F '|' \
  '$1 == "path" && $2 == "qk-ipc" && $3 == "0.0.1" { count++ } END { print count + 0 }' \
  "$supervisor_tmp") || fail 'cannot inspect process-s2-supervisor qk-ipc dependency'
[ "$ipc_matches" = 1 ] || \
  fail 'qk-ipc 0.0.1 is not present exactly once in the process-s2-supervisor fuzz dependency closure'
supervisor_path_set=$(awk -F '|' '$1 == "path" { print $2 "|" $3 }' "$supervisor_tmp") || \
  fail 'cannot enumerate process-s2-supervisor path dependencies'
expected_supervisor_path_set='qk-ipc|0.0.1
qk-supervisor|0.0.1'
[ "$supervisor_path_set" = "$expected_supervisor_path_set" ] || \
  fail 'process-s2-supervisor path dependency closure is not exactly qk-ipc and qk-supervisor 0.0.1'

if ! CARGO_NET_OFFLINE=true cargo tree --manifest-path fuzz/Cargo.toml --locked --offline \
    --no-default-features --features process-s3-io --target "$host_target" --edges normal,build \
    --prefix none --format '{p}' > "$tree_tmp"; then
  fail 'cannot resolve the locked process-s3-io fuzz dependency closure offline'
fi
if ! awk '
  {
    line = $0
    sub(/[[:space:]]+\(\*\)$/, "", line)
    split(line, fields, " ")
    name = fields[1]
    version = fields[2]
    sub(/^v/, "", version)
    if (name == "quietkey-fuzz") next
    kind = (name ~ /^qk-/) ? "path" : "registry"
    if (name == "" || version == "") exit 1
    print kind "|" name "|" version
  }
' "$tree_tmp" > "$io_raw_tmp"; then
  fail 'cannot parse process-s3-io fuzz dependency closure'
fi
sort -u "$io_raw_tmp" > "$io_tmp" || \
  fail 'cannot normalize process-s3-io fuzz dependency closure'
[ -s "$io_tmp" ] || fail 'process-s3-io fuzz dependency closure is empty'
io_path_set=$(awk -F '|' '$1 == "path" { print $2 "|" $3 }' "$io_tmp") || \
  fail 'cannot enumerate process-s3-io path dependencies'
expected_io_path_set='qk-bbqr|0.0.1
qk-io|0.0.1
qk-ipc|0.0.1'
[ "$io_path_set" = "$expected_io_path_set" ] || \
  fail 'process-s3-io path dependency closure is not exactly qk-bbqr, qk-io and qk-ipc 0.0.1'

if ! CARGO_NET_OFFLINE=true cargo tree --manifest-path fuzz/Cargo.toml --locked --offline \
    --no-default-features --features process-s4-core --target "$host_target" --edges normal,build \
    --prefix none --format '{p}' > "$tree_tmp"; then
  fail 'cannot resolve the locked process-s4-core fuzz dependency closure offline'
fi
if ! awk '
  {
    line = $0
    sub(/[[:space:]]+\(\*\)$/, "", line)
    split(line, fields, " ")
    name = fields[1]
    version = fields[2]
    sub(/^v/, "", version)
    if (name == "quietkey-fuzz") next
    kind = (name ~ /^qk-/) ? "path" : "registry"
    if (name == "" || version == "") exit 1
    print kind "|" name "|" version
  }
' "$tree_tmp" > "$core_raw_tmp"; then
  fail 'cannot parse process-s4-core fuzz dependency closure'
fi
sort -u "$core_raw_tmp" > "$core_tmp" || \
  fail 'cannot normalize process-s4-core fuzz dependency closure'
[ -s "$core_tmp" ] || fail 'process-s4-core fuzz dependency closure is empty'
core_path_set=$(awk -F '|' '$1 == "path" { print $2 "|" $3 }' "$core_tmp") || \
  fail 'cannot enumerate process-s4-core path dependencies'
expected_core_path_set='qk-a1|0.0.1
qk-bip32|0.0.1
qk-core|0.0.1
qk-descriptor|0.0.1
qk-ipc|0.0.1
qk-kit|0.0.1
qk-provisioning|0.0.1
qk-psbt|0.0.1
qk-secp|0.0.1
qk-wallet-v2|0.0.1'
[ "$core_path_set" = "$expected_core_path_set" ] || \
  fail 'process-s4-core path dependency closure is not the exact ten-crate qk-core closure'

if ! CARGO_NET_OFFLINE=true cargo tree --manifest-path fuzz/Cargo.toml --locked --offline \
    --no-default-features --features process-s5-core --target "$host_target" --edges normal,build \
    --prefix none --format '{p}' > "$tree_tmp"; then
  fail 'cannot resolve the locked process-s5-core fuzz dependency closure offline'
fi
if ! awk '
  {
    line = $0
    sub(/[[:space:]]+\(\*\)$/, "", line)
    split(line, fields, " ")
    name = fields[1]
    version = fields[2]
    sub(/^v/, "", version)
    if (name == "quietkey-fuzz") next
    kind = (name ~ /^qk-/) ? "path" : "registry"
    if (name == "" || version == "") exit 1
    print kind "|" name "|" version
  }
' "$tree_tmp" > "$core_s5_raw_tmp"; then
  fail 'cannot parse process-s5-core fuzz dependency closure'
fi
sort -u "$core_s5_raw_tmp" > "$core_s5_tmp" || \
  fail 'cannot normalize process-s5-core fuzz dependency closure'
[ -s "$core_s5_tmp" ] || fail 'process-s5-core fuzz dependency closure is empty'
core_s5_path_set=$(awk -F '|' '$1 == "path" { print $2 "|" $3 }' "$core_s5_tmp") || \
  fail 'cannot enumerate process-s5-core path dependencies'
[ "$core_s5_path_set" = "$expected_core_path_set" ] || \
  fail 'process-s5-core path dependency closure is not the exact ten-crate qk-core closure'

cat "$default_tmp" "$ipc_tmp" "$decoy_tmp" "$supervisor_tmp" "$io_tmp" "$core_tmp" \
  "$core_s5_tmp" > "$closure_raw_tmp" || \
  fail 'cannot combine fuzz dependency closures'
sort -u "$closure_raw_tmp" > "$closure_tmp" || fail 'cannot normalize union fuzz dependency closure'
[ -s "$closure_tmp" ] || fail 'union fuzz dependency closure is empty'

while IFS='|' read -r kind name version; do
  matches=$(awk -F '\t' -v k="$kind" -v n="$name" -v v="$version" \
    '!/^#/ && $1 == k && $2 == n && $3 == v { count++ } END { print count + 0 }' \
    "$allowlist") || fail 'union-closure allowlist lookup failed'
  [ "$matches" = 1 ] || fail "union dependency $kind $name $version is not uniquely allowed"
done < "$closure_tmp"

if ! CARGO_NET_OFFLINE=true cargo tree --manifest-path host/Cargo.toml --workspace --locked \
    --offline --target "$host_target" --edges normal,build --prefix none --format '{p}' \
    > "$tree_tmp"; then
  fail 'cannot resolve the locked host dependency closure offline'
fi
if grep -E '^(quietkey-fuzz|libfuzzer-sys) v' "$tree_tmp" >/dev/null 2>&1; then
  fail 'ring-fenced fuzz packages are reachable from the host workspace'
fi

if ! CARGO_NET_OFFLINE=true cargo tree --manifest-path host/Cargo.toml --package qk-decoy \
    --locked --offline --target "$host_target" --edges normal,build --prefix none \
    --format '{p}' > "$tree_tmp"; then
  fail 'cannot resolve the locked qk-decoy host dependency closure offline'
fi
if ! awk '
  {
    line = $0
    sub(/[[:space:]]+\(\*\)$/, "", line)
    split(line, fields, " ")
    name = fields[1]
    version = fields[2]
    sub(/^v/, "", version)
    if (name == "" || version == "") exit 1
    print name "|" version
  }
' "$tree_tmp" > "$host_decoy_raw_tmp"; then
  fail 'cannot parse qk-decoy host dependency closure'
fi
sort -u "$host_decoy_raw_tmp" > "$host_decoy_tmp" || \
  fail 'cannot normalize qk-decoy host dependency closure'
[ "$(cat "$host_decoy_tmp")" = 'qk-decoy|0.0.1' ] || \
  fail 'qk-decoy host dependency closure is not dependency-free'

if ! CARGO_NET_OFFLINE=true cargo tree --manifest-path host/Cargo.toml --package qk-supervisor \
    --locked --offline --target "$host_target" --edges normal,build --prefix none \
    --format '{p}' > "$tree_tmp"; then
  fail 'cannot resolve the locked qk-supervisor host dependency closure offline'
fi
if ! awk '
  {
    line = $0
    sub(/[[:space:]]+\(\*\)$/, "", line)
    split(line, fields, " ")
    name = fields[1]
    version = fields[2]
    sub(/^v/, "", version)
    if (name == "" || version == "") exit 1
    print name "|" version
  }
' "$tree_tmp" > "$host_supervisor_raw_tmp"; then
  fail 'cannot parse qk-supervisor host dependency closure'
fi
sort -u "$host_supervisor_raw_tmp" > "$host_supervisor_tmp" || \
  fail 'cannot normalize qk-supervisor host dependency closure'
if ! printf '%s\n' 'qk-ipc|0.0.1' 'qk-supervisor|0.0.1' | \
    cmp -s - "$host_supervisor_tmp"; then
  fail 'qk-supervisor host dependency closure is not exactly qk-supervisor plus qk-ipc'
fi

if ! CARGO_NET_OFFLINE=true cargo tree --manifest-path host/Cargo.toml --package qk-io \
    --locked --offline --target "$host_target" --edges normal,build --prefix none \
    --format '{p}' > "$tree_tmp"; then
  fail 'cannot resolve the locked qk-io host dependency closure offline'
fi
if ! awk '
  {
    line = $0
    sub(/[[:space:]]+\(\*\)$/, "", line)
    split(line, fields, " ")
    name = fields[1]
    version = fields[2]
    sub(/^v/, "", version)
    if (name == "" || version == "") exit 1
    print name "|" version
  }
' "$tree_tmp" > "$host_io_raw_tmp"; then
  fail 'cannot parse qk-io host dependency closure'
fi
sort -u "$host_io_raw_tmp" > "$host_io_tmp" || \
  fail 'cannot normalize qk-io host dependency closure'
if ! printf '%s\n' 'qk-bbqr|0.0.1' 'qk-io|0.0.1' 'qk-ipc|0.0.1' | \
    cmp -s - "$host_io_tmp"; then
  fail 'qk-io host dependency closure is not exactly qk-io, qk-ipc and qk-bbqr'
fi

if ! CARGO_NET_OFFLINE=true cargo tree --manifest-path host/Cargo.toml --package qk-core \
    --locked --offline --target "$host_target" --edges normal,build --prefix none \
    --format '{p}' > "$tree_tmp"; then
  fail 'cannot resolve the locked qk-core host dependency closure offline'
fi
if ! awk '
  {
    line = $0
    sub(/[[:space:]]+\(\*\)$/, "", line)
    split(line, fields, " ")
    name = fields[1]
    version = fields[2]
    sub(/^v/, "", version)
    if (name == "" || version == "") exit 1
    print name "|" version
  }
' "$tree_tmp" > "$host_core_raw_tmp"; then
  fail 'cannot parse qk-core host dependency closure'
fi
sort -u "$host_core_raw_tmp" > "$host_core_tmp" || \
  fail 'cannot normalize qk-core host dependency closure'
if ! printf '%s\n' \
    'qk-a1|0.0.1' \
    'qk-bip32|0.0.1' \
    'qk-core|0.0.1' \
    'qk-descriptor|0.0.1' \
    'qk-ipc|0.0.1' \
    'qk-kit|0.0.1' \
    'qk-provisioning|0.0.1' \
    'qk-psbt|0.0.1' \
    'qk-secp|0.0.1' \
    'qk-wallet-v2|0.0.1' | cmp -s - "$host_core_tmp"; then
  fail 'qk-core host dependency closure is not the exact ten-crate qk-core closure'
fi

while IFS="$tab" read -r kind name version checksum subject license purpose; do
  case "$kind" in ''|'#'*) continue ;; esac
  if ! awk -F '|' -v k="$kind" -v n="$name" -v v="$version" \
      '$1 == k && $2 == n && $3 == v { found = 1 } END { exit found ? 0 : 1 }' \
      "$closure_tmp"; then
    fail "inactive allowlist row: $kind $name $version"
  fi
  case "$kind" in
    registry)
      lock='fuzz/Cargo.lock'
      [ -f "$lock" ] || fail "$lock is missing"
      locked_checksum=$(awk -v wanted_name="$name" -v wanted_version="$version" '
        BEGIN { RS = ""; FS = "\n" }
        {
          name = version = checksum = ""
          for (line_number = 1; line_number <= NF; line_number++) {
            if ($line_number ~ /^name = "/) { name = $line_number; sub(/^name = "/, "", name); sub(/"$/, "", name) }
            if ($line_number ~ /^version = "/) { version = $line_number; sub(/^version = "/, "", version); sub(/"$/, "", version) }
            if ($line_number ~ /^checksum = "/) { checksum = $line_number; sub(/^checksum = "/, "", checksum); sub(/"$/, "", checksum) }
          }
          if (name == wanted_name && version == wanted_version) {
            found++
            result = checksum
          }
        }
        END { if (found == 1 && result != "") print result; else exit 1 }
      ' "$lock") || fail "cannot resolve $name $version uniquely in $lock"
      [ "$locked_checksum" = "$checksum" ] || fail "$name checksum differs from allowlist"
      ;;
    path)
      case "$subject" in host/*/Cargo.toml) ;; *) fail "$name has unsafe checksum subject: $subject" ;; esac
      [ -f "$subject" ] || fail "$name checksum subject is missing: $subject"
      actual=$(sha256_file "$subject") || fail 'no SHA-256 tool available'
      [ "$actual" = "$checksum" ] || fail "$name path-manifest checksum differs from allowlist"
      ;;
    *) fail "unknown allowlist kind: $kind" ;;
  esac
done < "$allowlist"

exit 0
