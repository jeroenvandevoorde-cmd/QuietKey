#!/bin/sh
# Fail-closed validator for QK-DEC-106's ring-fenced fuzz manifests.
set -u

fail() { printf 'FAIL: %s\n' "$1" >&2; exit 1; }

case "$#" in
  0) ;;
  1) [ "$1" = '--require-ipc-isolation' ] || fail "unknown argument: $1" ;;
  *) fail 'usage: tools/check-fuzz-dependencies.sh [--require-ipc-isolation]' ;;
esac

root=$(git rev-parse --show-toplevel 2>/dev/null) || fail 'not inside a Git worktree'
cd "$root" || fail 'cannot enter worktree root'

package_fact() {
  awk '
    function package_key(line, separator, key, value) {
      separator = index(line, " = ")
      if (separator < 2) return ""
      key = substr(line, 1, separator - 1)
      if (key !~ /^(name|version|edition|license|publish|description|autobins)$/) return ""
      value = substr(line, separator + 3)
      if (value == "" || index(value, "\\") || index(value, "\"\"\"") ||
          index(value, triple_single)) return ""
      return key
    }
    BEGIN {
      single_quote = sprintf("%c", 39)
      triple_single = single_quote single_quote single_quote
    }
    $0 == "[package]" { packages++; in_package = 1; next }
    /^\[/ { in_package = 0; next }
    in_package {
      if ($0 == "" || $0 ~ /^[[:space:]]*#/) next
      key = package_key($0)
      if (key == "") {
        if (!invalid_line) invalid_line = NR
        next
      }
      if (key == "name") {
        if ($0 !~ /^name = "[A-Za-z0-9_-]+"$/) {
          if (!invalid_line) invalid_line = NR
          next
        }
        names++
        name = $0
        sub(/^name = "/, "", name)
        sub(/"$/, "", name)
      } else if (key == "version") {
        if ($0 !~ /^version = "[0-9A-Za-z.+-]+"$/) {
          if (!invalid_line) invalid_line = NR
          next
        }
        versions++
        version = $0
        sub(/^version = "/, "", version)
        sub(/"$/, "", version)
      }
    }
    END {
      if (invalid_line) {
        print "invalid|" invalid_line
        exit
      }
      if (packages != 1 || names != 1 || versions != 1) exit 1
      print name "|" version
    }
  ' "$1"
}

host_workspace='host/Cargo.toml'
[ -f "$host_workspace" ] && [ ! -L "$host_workspace" ] || \
  fail "$host_workspace is missing or linked"
host_members=$(awk '
  /^members = \[/ {
    declarations++
    line = $0
    sub(/^members = \[/, "", line)
    if (line !~ /\]$/) exit 1
    sub(/\]$/, "", line)
    count = split(line, entries, /, /)
    for (member_index = 1; member_index <= count; member_index++) {
      member = entries[member_index]
      if (member !~ /^"[A-Za-z0-9_-]+"$/) exit 1
      sub(/^"/, "", member)
      sub(/"$/, "", member)
      if (seen[member]++) exit 1
      print member
    }
  }
  END { if (declarations != 1) exit 1 }
' "$host_workspace") || fail 'cannot derive the exact host workspace member set'
[ -n "$host_members" ] || fail 'the host workspace has no members'

host_build_scripts=''
for host_member in $host_members; do
  host_manifest="host/$host_member/Cargo.toml"
  [ -f "$host_manifest" ] && [ ! -L "$host_manifest" ] || \
    fail "host workspace member manifest is missing or linked: $host_manifest"
  host_package_fact=$(package_fact "$host_manifest") || \
    fail "host workspace member package identity is unreadable: $host_manifest"
  case "$host_package_fact" in
    invalid\|*)
      host_package_line=${host_package_fact#invalid|}
      fail "host workspace member [package] line is outside the exact shape: $host_manifest:$host_package_line"
      ;;
    "$host_member|"*) ;;
    *) fail "host workspace member package name is not exact: $host_manifest" ;;
  esac
  host_build_script="host/$host_member/build.rs"
  [ ! -L "$host_build_script" ] || \
    fail "host workspace build script is linked: $host_build_script"
  if [ -e "$host_build_script" ]; then
    [ -f "$host_build_script" ] || \
      fail "host workspace build script is not a regular file: $host_build_script"
    if [ -n "$host_build_scripts" ]; then
      host_build_scripts="$host_build_scripts
$host_build_script"
    else
      host_build_scripts=$host_build_script
    fi
  fi
done
[ "$host_build_scripts" = 'host/qk-secp/build.rs' ] || \
  fail 'host workspace build-script set is not exactly host/qk-secp/build.rs'

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

[ "$(grep -Fxc 'sec1210-wire = ["dep:qk-sec1210-wire"]' fuzz/Cargo.toml)" = 1 ] || \
  fail 'sec1210-wire fuzz feature is not declared exactly once in canonical form'
[ "$(grep -Fxc 'sec1210-production = ["dep:qk-core", "qk-core/sec1210-production"]' fuzz/Cargo.toml)" = 1 ] || \
  fail 'sec1210-production fuzz feature is not declared exactly once in canonical form'
normal_sec1210_feature=$(awk '
  $0 == "normal-sec1210 = [" { active = 1; blocks++; next }
  active && $0 == "]" { active = 0; ends++; next }
  active {
    expected[++lines] = $0
  }
  END {
    if (blocks != 1 || active || ends != 1 || lines != 7) exit 1
    if (expected[1] != "    \"dep:qk-card-protocol\",") exit 1
    if (expected[2] != "    \"dep:qk-core\",") exit 1
    if (expected[3] != "    \"dep:qk-ipc\",") exit 1
    if (expected[4] != "    \"qk-core/fuzzing\",") exit 1
    if (expected[5] != "    \"qk-core/normal-process\",") exit 1
    if (expected[6] != "    \"qk-core/sec1210-production\",") exit 1
    if (expected[7] != "    \"qk-ipc/fuzzing\",") exit 1
    print "PASS"
  }
' fuzz/Cargo.toml) || fail 'normal-sec1210 fuzz feature is not declared in exact canonical form'
[ "$normal_sec1210_feature" = PASS ] || \
  fail 'normal-sec1210 fuzz feature is not declared in exact canonical form'
[ "$(grep -Fxc 't1-readback = ["dep:qk-sec1210-wire", "dep:qk-t1"]' fuzz/Cargo.toml)" = 1 ] || \
  fail 't1-readback fuzz feature is not declared exactly once in canonical form'

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
  wire_start && $0 == "    \"qk-device-wire/legacy-normal-factor-fixture\"," { wire_legacy++ }
  wire_start && $0 != "process-s9-wire = [" && $0 != "]" && \
    $0 != "    \"dep:qk-device-wire\"," && $0 != "    \"qk-device-wire/fuzzing\"," && \
    $0 != "    \"qk-device-wire/legacy-normal-factor-fixture\"," { wire_extra++ }
  wire_start && $0 == "]" { wire_ends++; wire_start = 0 }
  $0 == "process-s9-core = [" { core_start = 1; core_blocks++ }
  core_start && $0 == "    \"dep:qk-card-protocol\"," { core_protocol++ }
  core_start && $0 == "    \"dep:qk-core\"," { core++ }
  core_start && $0 == "    \"dep:qk-device-wire\"," { core_wire++ }
  core_start && $0 == "    \"dep:qk-ipc\"," { ipc++ }
  core_start && $0 == "    \"qk-core/fuzzing\"," { core_fuzz++ }
  core_start && $0 == "    \"qk-core/normal-process\"," { normal_process++ }
  core_start && $0 == "    \"qk-ipc/fuzzing\"," { ipc_fuzz++ }
  core_start && $0 != "process-s9-core = [" && $0 != "]" && \
    $0 != "    \"dep:qk-card-protocol\"," && $0 != "    \"dep:qk-core\"," && \
    $0 != "    \"dep:qk-device-wire\"," && $0 != "    \"dep:qk-ipc\"," && \
    $0 != "    \"qk-core/fuzzing\"," && $0 != "    \"qk-core/normal-process\"," && \
    $0 != "    \"qk-ipc/fuzzing\"," { core_extra++ }
  core_start && $0 == "]" { core_ends++; core_start = 0 }
  END { print wire_blocks + 0, wire_start + 0, wire_ends + 0, wire_dep + 0, wire_fuzz + 0, wire_legacy + 0, wire_extra + 0, core_blocks + 0, core_start + 0, core_ends + 0, core_protocol + 0, core + 0, core_wire + 0, ipc + 0, core_fuzz + 0, normal_process + 0, ipc_fuzz + 0, core_extra + 0 }
' fuzz/Cargo.toml) || fail 'cannot inspect process-s9 fuzz features'
[ "$process_s9_feature_counts" = '1 0 1 1 1 1 0 1 0 1 1 1 1 1 1 1 1 0' ] || \
  fail 'process-s9 fuzz features are not declared exactly once in canonical form'
card_s1_feature_counts=$(awk '
  $0 == "card-s1-protocol = [\"dep:qk-card-protocol\", \"qk-card-protocol/fuzzing\"]" { protocol++ }
  $0 == "card-s1-model = [" { model_start = 1; model_blocks++ }
  model_start && $0 == "    \"dep:qk-card-model\"," { model_dep++ }
  model_start && $0 == "    \"dep:qk-card-protocol\"," { protocol_dep++ }
  model_start && $0 == "    \"qk-card-model/fuzzing\"," { model_fuzz++ }
  model_start && $0 == "    \"qk-card-protocol/fuzzing\"," { protocol_fuzz++ }
  model_start && $0 != "card-s1-model = [" && $0 != "]" && \
    $0 != "    \"dep:qk-card-model\"," && $0 != "    \"dep:qk-card-protocol\"," && \
    $0 != "    \"qk-card-model/fuzzing\"," && \
    $0 != "    \"qk-card-protocol/fuzzing\"," { model_extra++ }
  model_start && $0 == "]" { model_ends++; model_start = 0 }
  END { print protocol + 0, model_blocks + 0, model_start + 0, model_ends + 0, \
    model_dep + 0, protocol_dep + 0, model_fuzz + 0, protocol_fuzz + 0, model_extra + 0 }
' fuzz/Cargo.toml) || fail 'cannot inspect card-s1 fuzz features'
[ "$card_s1_feature_counts" = '1 1 0 1 1 1 1 1 0' ] || \
  fail 'card-s1 fuzz features are not declared exactly once in canonical form'

if ! awk '
  function flush_bin() {
    if (!in_bin) return
    if (name == "qk_t1") {
      t1++
      if (required != "t1-readback") bad = 1
    } else if (name == "qk_sec1210_wire") {
      sec1210++
      if (required != "sec1210-wire") bad = 1
    } else if (name == "qk_core_sec1210_transport") {
      sec1210_production++
      if (required != "sec1210-production") bad = 1
    } else if (name == "qk_core_normal_sec1210") {
      normal_sec1210++
      if (required != "normal-sec1210") bad = 1
    } else if (name == "qk_decoy_calculator") {
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
    } else if (name == "qk_card_protocol") {
      card_protocol++
      if (required != "card-s1-protocol") bad = 1
    } else if (name == "qk_card_model") {
      card_model++
      if (required != "card-s1-model") bad = 1
    } else if (required == "t1-readback" || required == "sec1210-wire" || required == "sec1210-production" || required == "normal-sec1210" || required == "process-s2-decoy" || required == "process-s2-supervisor" || required == "process-s8-supervisor" || required == "process-s3-io" || required == "process-s4-core" || required == "process-s5-core" || required == "process-s6-core" || required == "process-s7-core" || required == "process-s9-wire" || required == "process-s9-core" || required == "card-s1-protocol" || required == "card-s1-model") {
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
    exit (bad || t1 != 1 || sec1210 != 1 || sec1210_production != 1 || normal_sec1210 != 1 || decoy != 1 || supervisor != 1 || supervisor_s8 != 1 || io != 3 || core_s4 != 2 || core_s5 != 2 || core_s6 != 2 || core_s7 != 3 || process_s9_wire != 1 || process_s9_core != 1 || card_protocol != 1 || card_model != 1) ? 1 : 0
  }
' fuzz/Cargo.toml; then
  fail 'process fuzz target-to-feature mapping is not exact'
fi

fuzz_manifests=$(git ls-files | grep -E '^fuzz/(.*/)?Cargo\.toml$') || fuzz_manifests=''
[ -n "$fuzz_manifests" ] || fail 'no tracked fuzz/**/Cargo.toml manifest found'

dep_tmp=$(mktemp) || fail 'mktemp failed for fuzz dependency declarations'
tree_tmp=$(mktemp) || fail 'mktemp failed for fuzz dependency tree'
sec1210_raw_tmp=$(mktemp) || fail 'mktemp failed for raw SEC1210 fuzz closure'
sec1210_tmp=$(mktemp) || fail 'mktemp failed for SEC1210 fuzz closure'
sec1210_production_raw_tmp=$(mktemp) || fail 'mktemp failed for raw production SEC1210 fuzz closure'
sec1210_production_tmp=$(mktemp) || fail 'mktemp failed for production SEC1210 fuzz closure'
normal_sec1210_raw_tmp=$(mktemp) || fail 'mktemp failed for raw Normal SEC1210 fuzz closure'
normal_sec1210_tmp=$(mktemp) || fail 'mktemp failed for Normal SEC1210 fuzz closure'
t1_raw_tmp=$(mktemp) || fail 'mktemp failed for raw T=1 fuzz closure'
t1_tmp=$(mktemp) || fail 'mktemp failed for T=1 fuzz closure'
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
card_protocol_raw_tmp=$(mktemp) || fail 'mktemp failed for raw card-s1-protocol fuzz dependency closure'
card_protocol_tmp=$(mktemp) || fail 'mktemp failed for card-s1-protocol fuzz dependency closure'
card_model_raw_tmp=$(mktemp) || fail 'mktemp failed for raw card-s1-model fuzz dependency closure'
card_model_tmp=$(mktemp) || fail 'mktemp failed for card-s1-model fuzz dependency closure'
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
trap 'rm -f "$t1_raw_tmp" "$t1_tmp" "$sec1210_raw_tmp" "$sec1210_tmp" "$sec1210_production_raw_tmp" "$sec1210_production_tmp" "$normal_sec1210_raw_tmp" "$normal_sec1210_tmp" "$dep_tmp" "$tree_tmp" "$default_raw_tmp" "$default_tmp" \
  "$ipc_raw_tmp" "$ipc_tmp" "$decoy_raw_tmp" "$decoy_tmp" \
  "$supervisor_raw_tmp" "$supervisor_tmp" "$supervisor_s8_raw_tmp" "$supervisor_s8_tmp" \
  "$io_raw_tmp" "$io_tmp" "$host_decoy_raw_tmp" \
  "$core_raw_tmp" "$core_tmp" "$core_s5_raw_tmp" "$core_s5_tmp" \
  "$core_s6_raw_tmp" "$core_s6_tmp" \
  "$core_s7_raw_tmp" "$core_s7_tmp" \
  "$process_s9_wire_raw_tmp" "$process_s9_wire_tmp" \
  "$process_s9_core_raw_tmp" "$process_s9_core_tmp" \
  "$card_protocol_raw_tmp" "$card_protocol_tmp" \
  "$card_model_raw_tmp" "$card_model_tmp" \
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
  $1 == "registry" && (length($4) != 64 || $4 ~ /[^0-9a-f]/ || $5 != "crates.io-package") { bad = 1 }
  $1 == "path" && ($4 != "-" || $5 != "workspace") { bad = 1 }
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
    sec1210) printf '%s\n' 'qk-sec1210-wire|0.0.1' ;;
    t1) printf '%s\n' 'qk-sec1210-wire|0.0.1' 'qk-t1|0.0.1' ;;
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
      'qk-card-protocol|0.0.1' \
      'qk-core|0.0.1' \
      'qk-descriptor|0.0.1' \
      'qk-ipc|0.0.1' \
      'qk-kit|0.0.1' \
      'qk-provisioning|0.0.1' \
      'qk-psbt|0.0.1' \
      'qk-secp|0.0.1' \
      'qk-wallet-v2|0.0.1' ;;
    core_sec1210) printf '%s\n' \
      'qk-a1|0.0.1' \
      'qk-bbqr|0.0.1' \
      'qk-bip32|0.0.1' \
      'qk-card-protocol|0.0.1' \
      'qk-core|0.0.1' \
      'qk-descriptor|0.0.1' \
      'qk-ipc|0.0.1' \
      'qk-kit|0.0.1' \
      'qk-provisioning|0.0.1' \
      'qk-psbt|0.0.1' \
      'qk-sec1210-wire|0.0.1' \
      'qk-secp|0.0.1' \
      'qk-t1|0.0.1' \
      'qk-wallet-v2|0.0.1' ;;
    core_normal_sec1210) printf '%s\n' \
      'qk-a1|0.0.1' \
      'qk-bbqr|0.0.1' \
      'qk-bip32|0.0.1' \
      'qk-card-protocol|0.0.1' \
      'qk-core|0.0.1' \
      'qk-descriptor|0.0.1' \
      'qk-device-wire|0.0.1' \
      'qk-ipc|0.0.1' \
      'qk-kit|0.0.1' \
      'qk-provisioning|0.0.1' \
      'qk-psbt|0.0.1' \
      'qk-sec1210-wire|0.0.1' \
      'qk-secp|0.0.1' \
      'qk-t1|0.0.1' \
      'qk-wallet-v2|0.0.1' ;;
    core_normal) printf '%s\n' \
      'qk-a1|0.0.1' \
      'qk-bbqr|0.0.1' \
      'qk-bip32|0.0.1' \
      'qk-card-protocol|0.0.1' \
      'qk-core|0.0.1' \
      'qk-descriptor|0.0.1' \
      'qk-device-wire|0.0.1' \
      'qk-ipc|0.0.1' \
      'qk-kit|0.0.1' \
      'qk-provisioning|0.0.1' \
      'qk-psbt|0.0.1' \
      'qk-secp|0.0.1' \
      'qk-wallet-v2|0.0.1' ;;
    card_protocol) printf '%s\n' 'qk-card-protocol|0.0.1' ;;
    card_model) printf '%s\n' \
      'qk-card-model|0.0.1' \
      'qk-card-protocol|0.0.1' \
      'qk-secp|0.0.1' ;;
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
      if awk -F '|' '$1 == "path" && ($2 == "qk-ipc" || $2 == "qk-decoy" || $2 == "qk-supervisor" || $2 == "qk-io" || $2 == "qk-core" || $2 == "qk-device-wire" || $2 == "qk-card-protocol" || $2 == "qk-card-model" || $2 == "qk-sec1210-wire" || $2 == "qk-t1") { found = 1 } END { exit found ? 0 : 1 }' \
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
      if awk -F '|' '$1 == "path" && ($2 == "qk-decoy" || $2 == "qk-supervisor" || $2 == "qk-io" || $2 == "qk-core" || $2 == "qk-device-wire" || $2 == "qk-card-protocol" || $2 == "qk-card-model" || $2 == "qk-sec1210-wire" || $2 == "qk-t1") { found = 1 } END { exit found ? 0 : 1 }' \
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
sec1210|SEC1210|sec1210-wire|sec1210_raw_tmp|sec1210_tmp|exact|sec1210|SEC1210 path closure is not exactly qk-sec1210-wire 0.0.1
sec1210-production|production SEC1210 transport|sec1210-production|sec1210_production_raw_tmp|sec1210_production_tmp|exact|core_sec1210|production SEC1210 transport path closure is not the exact fourteen-crate qk-core closure
normal-sec1210|Normal SEC1210|normal-sec1210|normal_sec1210_raw_tmp|normal_sec1210_tmp|exact|core_normal_sec1210|Normal SEC1210 path closure is not the exact fifteen-crate integrated qk-core closure
t1|T=1 readback|t1-readback|t1_raw_tmp|t1_tmp|exact|t1|T=1 readback path closure is not exactly qk-sec1210-wire and qk-t1 0.0.1
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
process-s9-core|process-s9-core|process-s9-core|process_s9_core_raw_tmp|process_s9_core_tmp|exact|core_normal|process-s9-core path dependency closure is not the exact thirteen-crate qk-core normal-process closure
card-s1-protocol|card-s1-protocol|card-s1-protocol|card_protocol_raw_tmp|card_protocol_tmp|exact|card_protocol|card-s1-protocol path dependency closure is not exactly qk-card-protocol
card-s1-model|card-s1-model|card-s1-model|card_model_raw_tmp|card_model_tmp|exact|card_model|card-s1-model path dependency closure is not exactly qk-card-model, qk-card-protocol, and qk-secp
EOF

cat "$t1_tmp" "$sec1210_tmp" "$sec1210_production_tmp" "$normal_sec1210_tmp" "$default_tmp" "$ipc_tmp" "$decoy_tmp" "$supervisor_tmp" "$supervisor_s8_tmp" \
  "$io_tmp" "$core_tmp" \
  "$core_s5_tmp" "$core_s6_tmp" "$core_s7_tmp" "$process_s9_wire_tmp" \
  "$process_s9_core_tmp" "$card_protocol_tmp" "$card_model_tmp" > "$closure_raw_tmp" || \
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
qk-core|qk-core/host-runtime|qk-core|host_core_raw_tmp|host_core_tmp|core_normal|qk-core host-runtime dependency closure is not the exact thirteen-crate qk-core normal-process closure
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
      derived_manifest="host/$name/Cargo.toml"
      printf '%s\n' "$host_members" | grep -Fqx "$name" || \
        fail "$name is not a host workspace member"
      [ -f "$derived_manifest" ] && [ ! -L "$derived_manifest" ] || \
        fail "$name path manifest is missing or linked: $derived_manifest"
      [ "$(package_fact "$derived_manifest")" = "$name|$version" ] || \
        fail "$name path-manifest package identity differs from allowlist"
      ;;
    *) fail "unknown allowlist kind: $kind" ;;
  esac
done < "$allowlist"

exit 0
