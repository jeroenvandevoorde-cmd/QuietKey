#!/bin/sh
# Fail-closed HOST process-harness verification for QK-DEC-154, QK-DEC-156,
# QK-DEC-161, and QK-DEC-169.
set -u

fail() { printf 'FAIL: %s\n' "$1" >&2; exit 1; }

process_root=$(git rev-parse --show-toplevel 2>/dev/null) || \
  fail 'not inside a Git worktree'
cd "$process_root" || fail 'cannot enter worktree root'

command -v cargo >/dev/null 2>&1 || fail 'cargo is required'
command -v cmp >/dev/null 2>&1 || fail 'cmp is required'
command -v nm >/dev/null 2>&1 || fail 'nm is required for the release symbol proof'
process_build=$(mktemp -d) || fail 'cannot create process build directory'
process_runs=$(mktemp -d) || fail 'cannot create process run directory'
sec1210_tree_raw=$(mktemp) || fail 'cannot create SEC1210 raw closure file'
sec1210_tree=$(mktemp) || fail 'cannot create SEC1210 closure file'
sec1210_expected=$(mktemp) || fail 'cannot create SEC1210 expected-closure file'
sec1210_artifacts=$(mktemp) || fail 'cannot create SEC1210 artifact inventory'
sec1210_symbols=$(mktemp) || fail 'cannot create SEC1210 symbol file'
sec1210_symbol_stderr=$(mktemp) || fail 'cannot create SEC1210 symbol diagnostic file'
trap 'rm -rf "$process_build" "$process_runs"; rm -f "$sec1210_tree_raw" "$sec1210_tree" "$sec1210_expected" "$sec1210_artifacts" "$sec1210_symbols" "$sec1210_symbol_stderr"' EXIT HUP INT TERM

build_package() {
  package=$1
  binary=$2
  shift 2
  CARGO_TARGET_DIR="$process_build" cargo build --manifest-path host/Cargo.toml \
    --offline --quiet -p "$package" --bin "$binary" "$@" || \
    fail "$binary build failed"
}

build_package qk-decoy qk-decoy-host
build_package qk-core qk-core-host --features host-runtime
build_package qk-io qk-io-host --features host-runtime
build_package qk-supervisor qk-supervisor-host --features host-runtime
build_package qk-process-fixture qk-normal-process-harness
build_package qk-process-fixture qk-normal-fixture-driver

for package in qk-ipc qk-supervisor; do
  CARGO_TARGET_DIR="$process_build" cargo test --manifest-path host/Cargo.toml \
    --offline --quiet -p "$package" --features host-runtime || \
    fail "$package host-runtime tests failed"
done
for package in qk-core qk-io; do
  CARGO_TARGET_DIR="$process_build" cargo test --manifest-path host/Cargo.toml \
    --offline --quiet -p "$package" --features host-runtime || \
    fail "$package host-process tests failed"
done
CARGO_TARGET_DIR="$process_build" cargo test --manifest-path host/Cargo.toml \
  --offline --quiet -p qk-core \
  --features host-runtime,fuzzing,legacy-normal-factor-fixture || \
  fail 'qk-core complete Normal-process feature tests failed'
CARGO_TARGET_DIR="$process_build" cargo test --manifest-path host/Cargo.toml \
  --locked --offline --quiet -p qk-core --test sec1210_transport_v2 \
  --no-default-features --features sec1210-production,normal-process || \
  fail 'qk-core SEC1210 production PTY and differential tests failed'
CARGO_TARGET_DIR="$process_build" cargo test --manifest-path host/Cargo.toml \
  --offline --quiet -p qk-device-wire --features fuzzing || \
  fail 'qk-device-wire fuzzing-feature tests failed'
CARGO_TARGET_DIR="$process_build" cargo test --manifest-path host/Cargo.toml \
  --offline --quiet -p qk-io --features host-runtime,fuzzing || \
  fail 'qk-io complete host-process feature tests failed'
for package in qk-card-protocol qk-card-model; do
  CARGO_TARGET_DIR="$process_build" cargo test --manifest-path host/Cargo.toml \
    --offline --quiet -p "$package" --all-features || \
    fail "$package card-boundary tests failed"
done
CARGO_TARGET_DIR="$process_build" cargo test --manifest-path host/Cargo.toml \
  --offline --quiet -p qk-process-fixture || \
  fail 'qk-process-fixture tests failed'

if ! CARGO_NET_OFFLINE=true cargo tree --manifest-path host/Cargo.toml --locked --offline \
    -p qk-core --no-default-features --features sec1210-production \
    --edges normal,build --prefix none --format '{p}' >"$sec1210_tree_raw"; then
  fail 'cannot resolve the locked SEC1210 production closure offline'
fi
if ! awk '
    {
      line = $0
      sub(/[[:space:]]+\(\*\)$/, "", line)
      sub(/[[:space:]]+\([^)]*\)$/, "", line)
      if (!seen[line]++) print line
    }
  ' "$sec1210_tree_raw" >"$sec1210_tree"; then
  fail 'cannot normalize the locked SEC1210 production closure'
fi
LC_ALL=C sort -u "$sec1210_tree" -o "$sec1210_tree" || \
  fail 'cannot sort the locked SEC1210 production closure'
cat >"$sec1210_expected" <<'EOF'
qk-a1 v0.0.1
qk-bbqr v0.0.1
qk-bip32 v0.0.1
qk-card-protocol v0.0.1
qk-core v0.0.1
qk-descriptor v0.0.1
qk-ipc v0.0.1
qk-kit v0.0.1
qk-provisioning v0.0.1
qk-psbt v0.0.1
qk-sec1210-wire v0.0.1
qk-secp v0.0.1
qk-t1 v0.0.1
qk-wallet-v2 v0.0.1
EOF
[ -s "$sec1210_expected" ] || fail 'cannot write SEC1210 expected closure'
cmp "$sec1210_expected" "$sec1210_tree" >/dev/null 2>&1 || \
  fail 'SEC1210 production closure is not the exact fourteen-crate closure'

CARGO_TARGET_DIR="$process_build" cargo build --manifest-path host/Cargo.toml \
  --locked --offline --release -p qk-core --no-default-features \
  --features sec1210-production || fail 'qk-core SEC1210 release build failed'
if ! find "$process_build/release/deps" -maxdepth 1 -type f \
    -name 'libqk_core-*.rlib' -print >"$sec1210_artifacts"; then
  fail 'cannot inventory release-profile qk-core library artifacts'
fi
sec1210_artifact_count=$(awk 'NF { count++ } END { print count + 0 }' \
  "$sec1210_artifacts") || fail 'cannot count release-profile qk-core library artifacts'
[ "$sec1210_artifact_count" = 1 ] || \
  fail 'release-profile SEC1210 build did not produce exactly one qk-core library artifact'
sec1210_artifact=$(sed -n '1p' "$sec1210_artifacts")
[ -n "$sec1210_artifact" ] && [ -f "$sec1210_artifact" ] && \
  [ -r "$sec1210_artifact" ] && [ -s "$sec1210_artifact" ] || \
  fail 'release-profile qk-core library artifact is unreadable or empty'
if ! nm -C "$sec1210_artifact" >"$sec1210_symbols" 2>"$sec1210_symbol_stderr"; then
  [ ! -s "$sec1210_symbol_stderr" ] || cat "$sec1210_symbol_stderr" >&2
  fail 'cannot read release-profile qk-core symbols'
fi
[ -s "$sec1210_symbols" ] || fail 'release-profile qk-core symbol output is empty'
grep -a -F 'qk_core::sec1210_transport_v2::CardTransportErrorV2' \
  "$sec1210_symbols" >/dev/null 2>&1 || \
  fail 'release-profile qk-core symbols contain no named SEC1210 transport marker'
for forbidden_symbol in \
  'qk_core::process' \
  'run_normal_core_host_process' \
  'NormalDeviceRuntime' \
  'qk_device_wire' \
  'CardApduRequest' \
  'CardApduResponse'
do
  if grep -a -F "$forbidden_symbol" "$sec1210_symbols" >/dev/null 2>&1; then
    fail "release-profile SEC1210 qk-core contains forbidden symbol $forbidden_symbol"
  fi
done

launcher="$process_build/debug/qk-supervisor-host"
[ -x "$launcher" ] || fail 'qk-supervisor-host executable is missing'
for mode in setup kit; do
  runtime="$process_runs/$mode-runtime"
  stdout="$process_runs/$mode.stdout"
  stderr="$process_runs/$mode.stderr"
  [ ! -e "$runtime" ] || fail "$mode runtime path already exists"
  if ! "$launcher" "$mode" "$runtime" >"$stdout" 2>"$stderr"; then
    fail "$mode process cycle failed"
  fi
  [ ! -e "$runtime" ] || fail "$mode runtime directory was not removed"
  [ ! -s "$stdout" ] || fail "$mode process cycle wrote standard output"
  [ ! -s "$stderr" ] || fail "$mode process cycle wrote standard error"
done

normal_harness="$process_build/debug/qk-normal-process-harness"
normal_driver="$process_build/debug/qk-normal-fixture-driver"
[ -x "$normal_harness" ] || fail 'qk-normal-process-harness executable is missing'
[ -x "$normal_driver" ] || fail 'qk-normal-fixture-driver executable is missing'
normal_stdout="$process_runs/normal.stdout"
normal_stderr="$process_runs/normal.stderr"
normal_expected="$process_runs/normal.expected"
printf 'cycles=24 passed=24 failed=0 timed_out=0\n' >"$normal_expected" || \
  fail 'cannot write expected Normal summary'
if ! "$normal_harness" "$launcher" "$normal_driver" \
  >"$normal_stdout" 2>"$normal_stderr"; then
  fail 'Normal 24-cycle process matrix failed'
fi
[ ! -s "$normal_stderr" ] || fail 'Normal process matrix wrote standard error'
cmp "$normal_expected" "$normal_stdout" >/dev/null 2>&1 || \
  fail 'Normal process matrix summary mismatch'

printf 'OK: SEC1210 production closure and release-profile no-QKDV symbol proof passed\n'
printf 'OK: HOST process harness passed Setup/Kit controls and 24-cycle Normal matrix\n'
