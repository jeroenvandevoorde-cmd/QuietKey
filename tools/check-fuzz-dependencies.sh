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
  core_s5_start && $0 != "process-s5-core = [" && $0 != "]" && \
    $0 != "    \"dep:qk-core\"," && $0 != "    \"dep:qk-ipc\"," && \
    $0 != "    \"qk-core/fuzzing\"," && $0 != "    \"qk-ipc/fuzzing\"," { core_s5_extra++ }
  core_s5_start && $0 == "]" { core_s5_end++; core_s5_start = 0 }
  $0 == "process-s6-core = [" { core_s6_start = 1; core_s6_blocks++ }
  core_s6_start && $0 == "    \"dep:qk-core\"," { core_s6_dep++ }
  core_s6_start && $0 == "    \"dep:qk-ipc\"," { core_s6_ipc++ }
  core_s6_start && $0 == "    \"qk-core/fuzzing\"," { core_s6_fuzz++ }
  core_s6_start && $0 == "    \"qk-ipc/fuzzing\"," { core_s6_ipc_fuzz++ }
  core_s6_start && $0 != "process-s6-core = [" && $0 != "]" && \
    $0 != "    \"dep:qk-core\"," && $0 != "    \"dep:qk-ipc\"," && \
    $0 != "    \"qk-core/fuzzing\"," && $0 != "    \"qk-ipc/fuzzing\"," { core_s6_extra++ }
  core_s6_start && $0 == "]" { core_s6_end++; core_s6_start = 0 }
  $0 == "process-s7-core = [" { core_s7_start = 1; core_s7_blocks++ }
  core_s7_start && $0 == "    \"dep:qk-core\"," { core_s7_dep++ }
  core_s7_start && $0 == "    \"dep:qk-ipc\"," { core_s7_ipc++ }
  core_s7_start && $0 == "    \"dep:qk-psbt\"," { core_s7_psbt++ }
  core_s7_start && $0 == "    \"qk-core/fuzzing\"," { core_s7_fuzz++ }
  core_s7_start && $0 == "    \"qk-ipc/fuzzing\"," { core_s7_ipc_fuzz++ }
  core_s7_start && $0 != "process-s7-core = [" && $0 != "]" && \
    $0 != "    \"dep:qk-core\"," && $0 != "    \"dep:qk-ipc\"," && $0 != "    \"dep:qk-psbt\"," && \
    $0 != "    \"qk-core/fuzzing\"," && $0 != "    \"qk-ipc/fuzzing\"," { core_s7_extra++ }
  core_s7_start && $0 == "]" { core_s7_end++; core_s7_start = 0 }
  END { print decoy + 0, supervisor + 0, io_blocks + 0, io_start + 0, io_end + 0, bbqr + 0, io_dep + 0, ipc + 0, io_fuzz + 0, ipc_fuzz + 0, core_s4_blocks + 0, core_s4_start + 0, core_s4_end + 0, core_s4_dep + 0, core_s4_ipc + 0, core_s4_fuzz + 0, core_s4_ipc_fuzz + 0, core_s5_blocks + 0, core_s5_start + 0, core_s5_end + 0, core_s5_dep + 0, core_s5_ipc + 0, core_s5_fuzz + 0, core_s5_ipc_fuzz + 0, core_s5_extra + 0, core_s6_blocks + 0, core_s6_start + 0, core_s6_end + 0, core_s6_dep + 0, core_s6_ipc + 0, core_s6_fuzz + 0, core_s6_ipc_fuzz + 0, core_s6_extra + 0, core_s7_blocks + 0, core_s7_start + 0, core_s7_end + 0, core_s7_dep + 0, core_s7_ipc + 0, core_s7_psbt + 0, core_s7_fuzz + 0, core_s7_ipc_fuzz + 0, core_s7_extra + 0 }
' fuzz/Cargo.toml) || fail 'cannot inspect process fuzz feature declarations'
[ "$process_feature_counts" = '1 1 1 0 1 1 1 1 1 1 1 0 1 1 1 1 1 1 0 1 1 1 1 1 0 1 0 1 1 1 1 1 0 1 0 1 1 1 1 1 1 0' ] || \
  fail 'process fuzz features are not declared exactly once in canonical form'
process_s8_feature_count=$(grep -Fxc \
  'process-s8-supervisor = ["dep:qk-supervisor", "qk-supervisor/fuzzing"]' \
  fuzz/Cargo.toml) || fail 'cannot inspect process-s8-supervisor fuzz feature'
[ "$process_s8_feature_count" = 1 ] || \
  fail 'process-s8-supervisor fuzz feature is not declared exactly once in canonical form'
process_s9_feature_counts=$(awk '
  $0 == "process-s9-wire = [" { wire_start = 1; wire_blocks++ }
  wire_start && $0 == "    \"dep:qk-device-wire\"," { wire_dep++ }
  wire_start && $0 == "    \"qk-device-wire/fuzzing\"," { wire_fuzz++ }
  wire_start && $0 != "process-s9-wire = [" && $0 != "]" && \
    $0 != "    \"dep:qk-device-wire\"," && $0 != "    \"qk-device-wire/fuzzing\"," { wire_extra++ }
  wire_start && $0 == "]" { wire_ends++; wire_start = 0 }
  $0 == "process-s9-core = [" { core_start = 1; core_blocks++ }
  core_start && $0 == "    \"dep:qk-core\"," { core++ }
  core_start && $0 == "    \"dep:qk-device-wire\"," { core_wire++ }
  core_start && $0 == "    \"dep:qk-ipc\"," { ipc++ }
  core_start && $0 == "    \"qk-core/fuzzing\"," { core_fuzz++ }
  core_start && $0 == "    \"qk-core/normal-process\"," { normal_process++ }
  core_start && $0 == "    \"qk-device-wire/fuzzing\"," { core_wire_fuzz++ }
  core_start && $0 == "    \"qk-ipc/fuzzing\"," { ipc_fuzz++ }
  core_start && $0 != "process-s9-core = [" && $0 != "]" && \
    $0 != "    \"dep:qk-core\"," && $0 != "    \"dep:qk-device-wire\"," && $0 != "    \"dep:qk-ipc\"," && \
    $0 != "    \"qk-core/fuzzing\"," && $0 != "    \"qk-core/normal-process\"," && \
    $0 != "    \"qk-device-wire/fuzzing\"," && $0 != "    \"qk-ipc/fuzzing\"," { core_extra++ }
  core_start && $0 == "]" { core_ends++; core_start = 0 }
  END { print wire_blocks + 0, wire_start + 0, wire_ends + 0, wire_dep + 0, wire_fuzz + 0, wire_extra + 0, core_blocks + 0, core_start + 0, core_ends + 0, core + 0, core_wire + 0, ipc + 0, core_fuzz + 0, normal_process + 0, core_wire_fuzz + 0, ipc_fuzz + 0, core_extra + 0 }
' fuzz/Cargo.toml) || fail 'cannot inspect process-s9 fuzz features'
[ "$process_s9_feature_counts" = '1 0 1 1 1 0 1 0 1 1 1 1 1 1 1 1 0' ] || \
  fail 'process-s9 fuzz features are not declared exactly once in canonical form'

if ! awk '
  function flush_bin() {
    if (!in_bin) return
    if (name == "qk_decoy_calculator") {
      decoy++
      if (required != "process-s2-decoy") bad = 1
    } else if (name == "qk_supervisor_lifecycle") {
      supervisor++
      if (required != "process-s2-supervisor") bad = 1
    } else if (name == "qk_supervisor_process_lifecycle") {
      supervisor_s8++
      if (required != "process-s8-supervisor") bad = 1
    } else if (name == "qk_io_ingress" || name == "qk_io_egress" || name == "qk_io_session") {
      io++
      if (required != "process-s3-io") bad = 1
    } else if (name == "qk_core_io_peer" || name == "qk_core_session") {
      core_s4++
      if (required != "process-s4-core") bad = 1
    } else if (name == "qk_core_provisioning_entry" || name == "qk_core_provisioning_run") {
      core_s5++
      if (required != "process-s5-core") bad = 1
    } else if (name == "qk_core_normal_entry" || name == "qk_core_normal_run") {
      core_s6++
      if (required != "process-s6-core") bad = 1
    } else if (name == "qk_core_kit_intake" || name == "qk_core_kit_restore" || name == "qk_core_kit_spend") {
      core_s7++
      if (required != "process-s7-core") bad = 1
    } else if (name == "qk_device_wire") {
      process_s9_wire++
      if (required != "process-s9-wire") bad = 1
    } else if (name == "qk_core_normal_process") {
      process_s9_core++
      if (required != "process-s9-core") bad = 1
    } else if (required == "process-s2-decoy" || required == "process-s2-supervisor" || required == "process-s8-supervisor" || required == "process-s3-io" || required == "process-s4-core" || required == "process-s5-core" || required == "process-s6-core" || required == "process-s7-core" || required == "process-s9-wire" || required == "process-s9-core") {
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
    exit (bad || decoy != 1 || supervisor != 1 || supervisor_s8 != 1 || io != 3 || core_s4 != 2 || core_s5 != 2 || core_s6 != 2 || core_s7 != 3 || process_s9_wire != 1 || process_s9_core != 1) ? 1 : 0
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
supervisor_s8_raw_tmp=$(mktemp) || fail 'mktemp failed for raw process-s8-supervisor fuzz dependency closure'
supervisor_s8_tmp=$(mktemp) || fail 'mktemp failed for process-s8-supervisor fuzz dependency closure'
io_raw_tmp=$(mktemp) || fail 'mktemp failed for raw process-s3-io fuzz dependency closure'
io_tmp=$(mktemp) || fail 'mktemp failed for process-s3-io fuzz dependency closure'
core_raw_tmp=$(mktemp) || fail 'mktemp failed for raw process-s4-core fuzz dependency closure'
core_tmp=$(mktemp) || fail 'mktemp failed for process-s4-core fuzz dependency closure'
core_s5_raw_tmp=$(mktemp) || fail 'mktemp failed for raw process-s5-core fuzz dependency closure'
core_s5_tmp=$(mktemp) || fail 'mktemp failed for process-s5-core fuzz dependency closure'
core_s6_raw_tmp=$(mktemp) || fail 'mktemp failed for raw process-s6-core fuzz dependency closure'
core_s6_tmp=$(mktemp) || fail 'mktemp failed for process-s6-core fuzz dependency closure'
core_s7_raw_tmp=$(mktemp) || fail 'mktemp failed for raw process-s7-core fuzz dependency closure'
core_s7_tmp=$(mktemp) || fail 'mktemp failed for process-s7-core fuzz dependency closure'
process_s9_wire_raw_tmp=$(mktemp) || fail 'mktemp failed for raw process-s9-wire fuzz dependency closure'
process_s9_wire_tmp=$(mktemp) || fail 'mktemp failed for process-s9-wire fuzz dependency closure'
process_s9_core_raw_tmp=$(mktemp) || fail 'mktemp failed for raw process-s9-core fuzz dependency closure'
process_s9_core_tmp=$(mktemp) || fail 'mktemp failed for process-s9-core fuzz dependency closure'
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
  "$supervisor_raw_tmp" "$supervisor_tmp" "$supervisor_s8_raw_tmp" "$supervisor_s8_tmp" \
  "$io_raw_tmp" "$io_tmp" "$host_decoy_raw_tmp" \
  "$core_raw_tmp" "$core_tmp" "$core_s5_raw_tmp" "$core_s5_tmp" \
  "$core_s6_raw_tmp" "$core_s6_tmp" \
  "$core_s7_raw_tmp" "$core_s7_tmp" \
  "$process_s9_wire_raw_tmp" "$process_s9_wire_tmp" \
  "$process_s9_core_raw_tmp" "$process_s9_core_tmp" \
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

expected_path_set() {
  case "$1" in
    decoy) printf '%s\n' 'qk-decoy|0.0.1' ;;
    supervisor) printf '%s\n' 'qk-ipc|0.0.1' 'qk-supervisor|0.0.1' ;;
    io) printf '%s\n' \
      'qk-bbqr|0.0.1' \
      'qk-device-wire|0.0.1' \
      'qk-io|0.0.1' \
      'qk-ipc|0.0.1' ;;
    core) printf '%s\n' \
      'qk-a1|0.0.1' \
      'qk-bbqr|0.0.1' \
      'qk-bip32|0.0.1' \
      'qk-core|0.0.1' \
      'qk-descriptor|0.0.1' \
      'qk-device-wire|0.0.1' \
      'qk-ipc|0.0.1' \
      'qk-kit|0.0.1' \
      'qk-provisioning|0.0.1' \
      'qk-psbt|0.0.1' \
      'qk-secp|0.0.1' \
      'qk-wallet-v2|0.0.1' ;;
    wire) printf '%s\n' 'qk-device-wire|0.0.1' ;;
  esac
}

assert_exact_path_set() {
  normalized_output=$1
  closure_label=$2
  expected_key=$3
  mismatch_message=$4

  actual_path_set=$(awk -F '|' '$1 == "path" { print $2 "|" $3 }' \
    "$normalized_output") || fail "cannot enumerate $closure_label path dependencies"
  wanted_path_set=$(expected_path_set "$expected_key")
  [ "$actual_path_set" = "$wanted_path_set" ] || fail "$mismatch_message"
}

check_fuzz_closure() {
  closure_id=$1
  closure_label=$2
  feature=$3
  raw_output_name=$4
  normalized_output_name=$5
  assertion=$6
  expected_key=$7
  mismatch_message=$8
  eval "raw_output=\${$raw_output_name}"
  eval "normalized_output=\${$normalized_output_name}"

  case "$closure_id" in
    default)
      if ! CARGO_NET_OFFLINE=true cargo tree --manifest-path fuzz/Cargo.toml --locked --offline \
          --target "$host_target" --edges normal,build --prefix none --format '{p}' > "$tree_tmp"; then
        fail "cannot resolve the locked $closure_label fuzz dependency closure offline"
      fi
      ;;
    ipc)
      if ! CARGO_NET_OFFLINE=true cargo tree --manifest-path fuzz/Cargo.toml --locked --offline \
          --features "$feature" --target "$host_target" --edges normal,build --prefix none \
          --format '{p}' > "$tree_tmp"; then
        fail "cannot resolve the locked $closure_label fuzz dependency closure offline"
      fi
      ;;
    *)
      if ! CARGO_NET_OFFLINE=true cargo tree --manifest-path fuzz/Cargo.toml --locked --offline \
          --no-default-features --features "$feature" --target "$host_target" \
          --edges normal,build --prefix none --format '{p}' > "$tree_tmp"; then
        fail "cannot resolve the locked $closure_label fuzz dependency closure offline"
      fi
      ;;
  esac
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
  ' "$tree_tmp" > "$raw_output"; then
    fail "cannot parse $closure_label fuzz dependency closure"
  fi
  sort -u "$raw_output" > "$normalized_output" || \
    fail "cannot normalize $closure_label fuzz dependency closure"
  [ -s "$normalized_output" ] || fail "$closure_label fuzz dependency closure is empty"

  case "$assertion" in
    default)
      if awk -F '|' '$1 == "path" && ($2 == "qk-ipc" || $2 == "qk-decoy" || $2 == "qk-supervisor" || $2 == "qk-io" || $2 == "qk-core" || $2 == "qk-device-wire") { found = 1 } END { exit found ? 0 : 1 }' \
          "$normalized_output"; then
        fail 'a ring-fenced process dependency is reachable from the default fuzz dependency closure'
      fi
      ;;
    ipc)
      ipc_matches=$(awk -F '|' \
        '$1 == "path" && $2 == "qk-ipc" && $3 == "0.0.1" { count++ } END { print count + 0 }' \
        "$normalized_output") || fail 'cannot inspect IPC-feature fuzz dependency closure'
      [ "$ipc_matches" = 1 ] || \
        fail 'qk-ipc 0.0.1 is not present exactly once in the IPC-feature fuzz dependency closure'
      if awk -F '|' '$1 == "path" && ($2 == "qk-decoy" || $2 == "qk-supervisor" || $2 == "qk-io" || $2 == "qk-core" || $2 == "qk-device-wire") { found = 1 } END { exit found ? 0 : 1 }' \
          "$normalized_output"; then
        fail 'a process dependency is reachable from the IPC-only fuzz dependency closure'
      fi
      ;;
    decoy)
      decoy_matches=$(awk -F '|' \
        '$1 == "path" && $2 == "qk-decoy" && $3 == "0.0.1" { count++ } END { print count + 0 }' \
        "$normalized_output") || fail 'cannot inspect process-s2-decoy fuzz dependency closure'
      [ "$decoy_matches" = 1 ] || \
        fail 'qk-decoy 0.0.1 is not present exactly once in the process-s2-decoy fuzz dependency closure'
      assert_exact_path_set "$normalized_output" "$closure_label" "$expected_key" "$mismatch_message"
      ;;
    supervisor)
      supervisor_matches=$(awk -F '|' \
        '$1 == "path" && $2 == "qk-supervisor" && $3 == "0.0.1" { count++ } END { print count + 0 }' \
        "$normalized_output") || fail 'cannot inspect process-s2-supervisor fuzz dependency closure'
      [ "$supervisor_matches" = 1 ] || \
        fail 'qk-supervisor 0.0.1 is not present exactly once in the process-s2-supervisor fuzz dependency closure'
      ipc_matches=$(awk -F '|' \
        '$1 == "path" && $2 == "qk-ipc" && $3 == "0.0.1" { count++ } END { print count + 0 }' \
        "$normalized_output") || fail 'cannot inspect process-s2-supervisor qk-ipc dependency'
      [ "$ipc_matches" = 1 ] || \
        fail 'qk-ipc 0.0.1 is not present exactly once in the process-s2-supervisor fuzz dependency closure'
      assert_exact_path_set "$normalized_output" "$closure_label" "$expected_key" "$mismatch_message"
      ;;
    exact)
      assert_exact_path_set "$normalized_output" "$closure_label" "$expected_key" "$mismatch_message"
      ;;
  esac
}

# id | diagnostic label | feature | raw file | normalized file | assertion | expected set | mismatch diagnostic
while IFS='|' read -r closure_id closure_label feature raw_output normalized_output \
    assertion expected_key mismatch_message; do
  check_fuzz_closure "$closure_id" "$closure_label" "$feature" "$raw_output" \
    "$normalized_output" "$assertion" "$expected_key" "$mismatch_message"
done <<'EOF'
default|default|-|default_raw_tmp|default_tmp|default|-|-
ipc|IPC-feature|ipc|ipc_raw_tmp|ipc_tmp|ipc|-|-
process-s2-decoy|process-s2-decoy|process-s2-decoy|decoy_raw_tmp|decoy_tmp|decoy|decoy|process-s2-decoy path dependency closure is not exactly qk-decoy 0.0.1
process-s2-supervisor|process-s2-supervisor|process-s2-supervisor|supervisor_raw_tmp|supervisor_tmp|supervisor|supervisor|process-s2-supervisor path dependency closure is not exactly qk-ipc and qk-supervisor 0.0.1
process-s8-supervisor|process-s8-supervisor|process-s8-supervisor|supervisor_s8_raw_tmp|supervisor_s8_tmp|exact|supervisor|process-s8-supervisor path dependency closure is not exactly qk-ipc and qk-supervisor 0.0.1
process-s3-io|process-s3-io|process-s3-io|io_raw_tmp|io_tmp|exact|io|process-s3-io path dependency closure is not the exact four-crate qk-io closure
process-s4-core|process-s4-core|process-s4-core|core_raw_tmp|core_tmp|exact|core|process-s4-core path dependency closure is not the exact twelve-crate qk-core closure
process-s5-core|process-s5-core|process-s5-core|core_s5_raw_tmp|core_s5_tmp|exact|core|process-s5-core path dependency closure is not the exact twelve-crate qk-core closure
process-s6-core|process-s6-core|process-s6-core|core_s6_raw_tmp|core_s6_tmp|exact|core|process-s6-core path dependency closure is not the exact twelve-crate qk-core closure
process-s7-core|process-s7-core|process-s7-core|core_s7_raw_tmp|core_s7_tmp|exact|core|process-s7-core path dependency closure is not the exact twelve-crate qk-core closure
process-s9-wire|process-s9-wire|process-s9-wire|process_s9_wire_raw_tmp|process_s9_wire_tmp|exact|wire|process-s9-wire path dependency closure is not exactly qk-device-wire
process-s9-core|process-s9-core|process-s9-core|process_s9_core_raw_tmp|process_s9_core_tmp|exact|core|process-s9-core path dependency closure is not the exact twelve-crate qk-core plus qk-device-wire closure
EOF

cat "$default_tmp" "$ipc_tmp" "$decoy_tmp" "$supervisor_tmp" "$supervisor_s8_tmp" \
  "$io_tmp" "$core_tmp" \
  "$core_s5_tmp" "$core_s6_tmp" "$core_s7_tmp" "$process_s9_wire_tmp" \
  "$process_s9_core_tmp" > "$closure_raw_tmp" || \
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

check_product_closure() {
  package=$1
  feature=$2
  closure_label=$3
  raw_output_name=$4
  normalized_output_name=$5
  expected_key=$6
  mismatch_message=$7
  eval "raw_output=\${$raw_output_name}"
  eval "normalized_output=\${$normalized_output_name}"

  if [ "$feature" = '-' ]; then
    if ! CARGO_NET_OFFLINE=true cargo tree --manifest-path host/Cargo.toml --package "$package" \
        --locked --offline --target "$host_target" --edges normal,build --prefix none \
        --format '{p}' > "$tree_tmp"; then
      fail "cannot resolve the locked $closure_label host dependency closure offline"
    fi
  elif ! CARGO_NET_OFFLINE=true cargo tree --manifest-path host/Cargo.toml --package "$package" \
      --features "$feature" --locked --offline --target "$host_target" \
      --edges normal,build --prefix none --format '{p}' > "$tree_tmp"; then
    fail "cannot resolve the locked $closure_label host dependency closure offline"
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
  ' "$tree_tmp" > "$raw_output"; then
    fail "cannot parse $closure_label host dependency closure"
  fi
  sort -u "$raw_output" > "$normalized_output" || \
    fail "cannot normalize $closure_label host dependency closure"
  wanted_path_set=$(expected_path_set "$expected_key")
  [ "$(cat "$normalized_output")" = "$wanted_path_set" ] || fail "$mismatch_message"
}

# package | feature | diagnostic label | raw file | normalized file | expected set | mismatch diagnostic
while IFS='|' read -r package feature closure_label raw_output normalized_output \
    expected_key mismatch_message; do
  check_product_closure "$package" "$feature" "$closure_label" "$raw_output" \
    "$normalized_output" "$expected_key" "$mismatch_message"
done <<'EOF'
qk-decoy|-|qk-decoy|host_decoy_raw_tmp|host_decoy_tmp|decoy|qk-decoy host dependency closure is not dependency-free
qk-supervisor|-|qk-supervisor|host_supervisor_raw_tmp|host_supervisor_tmp|supervisor|qk-supervisor host dependency closure is not exactly qk-supervisor plus qk-ipc
qk-io|qk-io/host-runtime|qk-io|host_io_raw_tmp|host_io_tmp|io|qk-io host-runtime dependency closure is not the exact four-crate qk-io closure
qk-core|qk-core/host-runtime|qk-core|host_core_raw_tmp|host_core_tmp|core|qk-core host-runtime dependency closure is not the exact twelve-crate qk-core closure
EOF

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
