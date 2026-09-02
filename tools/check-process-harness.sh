#!/bin/sh
# Fail-closed HOST process-harness verification for QK-DEC-154 and QK-DEC-156.
set -u

fail() { printf 'FAIL: %s\n' "$1" >&2; exit 1; }

process_root=$(git rev-parse --show-toplevel 2>/dev/null) || \
  fail 'not inside a Git worktree'
cd "$process_root" || fail 'cannot enter worktree root'

command -v cargo >/dev/null 2>&1 || fail 'cargo is required'
command -v cmp >/dev/null 2>&1 || fail 'cmp is required'
process_build=$(mktemp -d) || fail 'cannot create process build directory'
process_runs=$(mktemp -d) || fail 'cannot create process run directory'
trap 'rm -rf "$process_build" "$process_runs"' EXIT HUP INT TERM

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
  --offline --quiet -p qk-process-fixture || \
  fail 'qk-process-fixture tests failed'

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
printf 'cycles=19 passed=19 failed=0 timed_out=0\n' >"$normal_expected" || \
  fail 'cannot write expected Normal summary'
if ! "$normal_harness" "$launcher" "$normal_driver" \
  >"$normal_stdout" 2>"$normal_stderr"; then
  fail 'Normal 19-cycle process matrix failed'
fi
[ ! -s "$normal_stderr" ] || fail 'Normal process matrix wrote standard error'
cmp "$normal_expected" "$normal_stdout" >/dev/null 2>&1 || \
  fail 'Normal process matrix summary mismatch'

printf 'OK: HOST process harness passed Setup/Kit controls and 19-cycle Normal matrix\n'
