#!/bin/sh
# Fail-closed validator for QK-DEC-147/165's ring-fenced observation and sitting tool.
set -u

fail() { printf 'FAIL: %s\n' "$1" >&2; exit 1; }

normalize_tree() {
  normalize_tmp=$(mktemp) || return 1
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
  ' "$1" > "$normalize_tmp"; then
    rm -f "$normalize_tmp"
    return 1
  fi
  LC_ALL=C sort -u "$normalize_tmp"
  normalize_status=$?
  rm -f "$normalize_tmp"
  return "$normalize_status"
}

root=$(git rev-parse --show-toplevel 2>/dev/null) || fail 'not inside a Git worktree'
cd "$root" || fail 'cannot enter worktree root'

manifest='bench/card-enrollment/Cargo.toml'
lock='bench/card-enrollment/Cargo.lock'
allowlist='bench/card-enrollment/DEPENDENCY-ALLOWLIST.tsv'

for required in "$manifest" "$lock" "$allowlist"; do
  [ -f "$required" ] || fail "$required is missing"
  [ ! -L "$required" ] || fail "$required must not be a symbolic link"
  git ls-files --error-unmatch "$required" >/dev/null 2>&1 || \
    fail "$required is not tracked"
done

[ ! -e bench/card-enrollment/build.rs ] || \
  fail 'bench/card-enrollment/build.rs is forbidden'
for cargo_config in \
    .cargo/config .cargo/config.toml \
    bench/.cargo/config bench/.cargo/config.toml \
    bench/card-enrollment/.cargo/config bench/card-enrollment/.cargo/config.toml; do
  [ ! -e "$cargo_config" ] || \
    fail "repository Cargo configuration is forbidden for the bench build: $cargo_config"
done

bench_manifests=$(git ls-files | grep -E '^bench/(.*/)?Cargo\.toml$') || bench_manifests=''
[ "$bench_manifests" = "$manifest" ] || \
  fail 'the ring-fenced bench Cargo manifest set is not exact'

package_shape=$(awk '
  $0 == "[package]" { package_sections++; in_package = 1; next }
  /^\[/ { in_package = 0; next }
  in_package && $0 == "name = \"qk-card-enrollment\"" { names++ }
  in_package && $0 == "version = \"0.0.4\"" { versions++ }
  in_package && $0 == "publish = false" { publish++ }
  in_package && $0 == "edition = \"2021\"" { editions++ }
  in_package && $0 == "license = \"Apache-2.0\"" { licenses++ }
  END { print package_sections + 0, names + 0, versions + 0, publish + 0, editions + 0, licenses + 0 }
' "$manifest") || fail 'cannot inspect bench package declaration'
[ "$package_shape" = '1 1 1 1 1 1' ] || \
  fail 'bench package declaration is not the reviewed canonical form'

dependency_shape=$(awk '
  /^\[/ {
    in_dependencies = ($0 == "[dependencies]")
    in_dev = ($0 == "[dev-dependencies]")
    if ($0 == "[dependencies]") dependency_sections++
    else if ($0 == "[dev-dependencies]") dev_sections++
    else if ($0 ~ /dependencies/ || $0 ~ /^\[(patch|replace)(\.|\])/) forbidden_sections++
    next
  }
  in_dependencies && $0 !~ /^[[:space:]]*(#|$)/ {
    entries++
    if ($0 == "pcsc = { version = \"=2.9.0\" }") pcsc++
    else bad++
  }
  in_dev && $0 !~ /^[[:space:]]*(#|$)/ {
    dev_entries++
    if ($0 == "qk-card-model = { path = \"../../host/qk-card-model\" }") model++
    else if ($0 == "qk-card-protocol = { path = \"../../host/qk-card-protocol\" }") protocol++
    else bad++
  }
  END { print dependency_sections + 0, entries + 0, pcsc + 0, dev_sections + 0, dev_entries + 0, model + 0, protocol + 0, bad + 0, forbidden_sections + 0 }
' "$manifest") || fail 'cannot inspect bench dependency declaration'
[ "$dependency_shape" = '1 1 1 1 2 1 1 0 0' ] || \
  fail 'bench direct dependencies are not exactly pcsc 2.9.0 plus the two reviewed dev-only paths'

workspace_shape=$(awk '
  $0 == "[workspace]" { workspace_sections++; in_workspace = 1; next }
  /^\[/ { in_workspace = 0; next }
  in_workspace && $0 == "resolver = \"2\"" { resolvers++ }
  END { print workspace_sections + 0, resolvers + 0 }
' "$manifest") || fail 'cannot inspect bench workspace declaration'
[ "$workspace_shape" = '1 1' ] || \
  fail 'bench workspace declaration is not the reviewed canonical form'

bench_sources=$(git ls-files | grep -E '^bench/card-enrollment/.*\.rs$') || bench_sources=''
[ -n "$bench_sources" ] || fail 'bench Rust sources are missing'
expected_bench_sources='bench/card-enrollment/src/identity.rs
bench/card-enrollment/src/identity_transcript.rs
bench/card-enrollment/src/lib.rs
bench/card-enrollment/src/main.rs
bench/card-enrollment/src/model.rs
bench/card-enrollment/src/pcsc_adapter.rs
bench/card-enrollment/src/pcsc_identity_adapter.rs
bench/card-enrollment/src/pcsc_sitting_adapter.rs
bench/card-enrollment/src/sitting.rs
bench/card-enrollment/src/sitting_transcript.rs
bench/card-enrollment/src/transcript.rs
bench/card-enrollment/tests/identity_mock.rs
bench/card-enrollment/tests/identity_transcript.rs
bench/card-enrollment/tests/mock.rs
bench/card-enrollment/tests/sitting_guard.rs
bench/card-enrollment/tests/sitting_mock.rs
bench/card-enrollment/tests/sitting_model.rs
bench/card-enrollment/tests/sitting_transcript.rs
bench/card-enrollment/tests/surface.rs
bench/card-enrollment/tests/transcript.rs'
[ "$(printf '%s\n' "$bench_sources" | LC_ALL=C sort)" = "$expected_bench_sources" ] || \
  fail 'bench Rust source set is not exact'
for source in $bench_sources; do
  [ -f "$source" ] || fail "tracked bench source is missing: $source"
  [ ! -L "$source" ] || fail "tracked bench source must not be a symbolic link: $source"
done

identity_adapter='bench/card-enrollment/src/pcsc_identity_adapter.rs'
sitting_adapter='bench/card-enrollment/src/pcsc_sitting_adapter.rs'
bench_production_sources=$(printf '%s\n' "$bench_sources" | grep '^bench/card-enrollment/src/') || \
  fail 'bench production Rust sources are missing'
identity_transmit_count=$(grep -F -c '.transmit(' "$identity_adapter") || \
  identity_transmit_count=0
[ "$identity_transmit_count" = 3 ] || \
  fail 'the private identity adapter must contain exactly three transmit calls'
sitting_transmit_count=$(grep -F -c '.transmit(' "$sitting_adapter") || sitting_transmit_count=0
[ "$sitting_transmit_count" = 1 ] || \
  fail 'the private sitting adapter must contain exactly one fixed-plan transmit call'
for source in $bench_production_sources; do
  [ "$source" = "$identity_adapter" ] && continue
  [ "$source" = "$sitting_adapter" ] && continue
  if grep -F '.transmit(' "$source" >/dev/null 2>&1; then
    fail "transmit call exists outside the two private fixed-plan adapters: $source"
  fi
done
for forbidden_surface in '.control(' '.get_attribute(' '.begin_transaction(' 'pub fn card' 'pub fn context' 'pub use pcsc::'; do
  if grep -F "$forbidden_surface" $bench_production_sources >/dev/null 2>&1; then
    fail "bench source exposes forbidden PC/SC surface: $forbidden_surface"
  fi
done
grep -F 'pub const SELECT_DEFAULT_APPLICATION_COMMAND: [u8; 5] = [0x00, 0xa4, 0x04, 0x00, 0x00];' \
  bench/card-enrollment/src/identity.rs >/dev/null 2>&1 || \
  fail 'default-application SELECT command bytes are not exact'
grep -F 'pub const CARD_RECOGNITION_COMMAND: [u8; 5] = [0x80, 0xca, 0x00, 0x66, 0x00];' \
  bench/card-enrollment/src/identity.rs >/dev/null 2>&1 || \
  fail 'card-recognition command bytes are not exact'
grep -F 'pub const CPLC_COMMAND: [u8; 5] = [0x80, 0xca, 0x9f, 0x7f, 0x00];' \
  bench/card-enrollment/src/identity.rs >/dev/null 2>&1 || \
  fail 'CPLC command bytes are not exact'
grep -F 'EnrollmentOperation::Transmit => Err(EnrollmentError::ApduTransmitNotAuthorized)' \
  bench/card-enrollment/src/model.rs >/dev/null 2>&1 || \
  fail 'generic transmit refusal is missing'
grep -n -E \
  '(^|[^[:alnum:]_])unsafe([^[:alnum:]_]|$)|extern[[:space:]]*"C"|#\[[[:space:]]*link|pcsc[_-]sys' \
  $bench_sources >/dev/null 2>&1
source_scan_status=$?
case "$source_scan_status" in
  0) fail 'bench source contains unsafe code, direct FFI or pcsc-sys use' ;;
  1) ;;
  *) fail 'cannot scan bench sources for unsafe code or direct FFI' ;;
esac
for crate_root in bench/card-enrollment/src/lib.rs bench/card-enrollment/src/main.rs; do
  [ -f "$crate_root" ] || fail "$crate_root is missing"
  count=$(grep -c '^#!\[forbid(unsafe_code)\]$' "$crate_root") || count=0
  [ "$count" = 1 ] || fail "$crate_root does not forbid unsafe code exactly once"
done

override_pattern='PCSC_LIB_DIR|PCSC_LIB_NAME|LIBPCSCLITE_(NO_PKG_CONFIG|STATIC|DYNAMIC)|PKG_CONFIG|PKG_CONFIG_(PATH|LIBDIR|SYSROOT_DIR|ALLOW_CROSS|ALL_STATIC|ALL_DYNAMIC|ALLOW_SYSTEM_CFLAGS|ALLOW_SYSTEM_LIBS|PATH_FOR_TARGET)|HOST_PKG_CONFIG|TARGET_PKG_CONFIG|HOST_PKG_CONFIG_(PATH|LIBDIR|SYSROOT_DIR|ALLOW_CROSS)|TARGET_PKG_CONFIG_(PATH|LIBDIR|SYSROOT_DIR|ALLOW_CROSS)|PKG_CONFIG_(PATH|LIBDIR|SYSROOT_DIR|ALLOW_CROSS)_[A-Za-z0-9_-]+|PKG_CONFIG_[A-Za-z0-9_-]+|[A-Za-z0-9_-]+_PKG_CONFIG|[A-Za-z0-9_-]+_PKG_CONFIG_(PATH|LIBDIR|SYSROOT_DIR|ALLOW_CROSS)'
override_names=$(env | LC_ALL=C sed 's/=.*//' | grep -E \
  "^($override_pattern)$") || \
  override_names=''
[ -z "$override_names" ] || \
  fail "unregistered native-library override environment is present: $(printf '%s' "$override_names" | tr '\n' ' ')"

cargo_config_home=${CARGO_HOME:-"$HOME/.cargo"}
config_dir=$root
while :; do
  for config_name in .cargo/config .cargo/config.toml; do
    config_path=$config_dir/$config_name
    if [ -f "$config_path" ] && grep -E \
      "^[[:space:]]*\"?($override_pattern)\"?[[:space:]]*=" \
      "$config_path" >/dev/null 2>&1; then
      fail "unregistered native-library override is configured in $config_path"
    fi
  done
  parent_dir=$(dirname "$config_dir")
  [ "$parent_dir" != "$config_dir" ] || break
  config_dir=$parent_dir
done
for config_path in "$cargo_config_home/config" "$cargo_config_home/config.toml"; do
  if [ -f "$config_path" ] && grep -E \
    "^[[:space:]]*\"?($override_pattern)\"?[[:space:]]*=" \
    "$config_path" >/dev/null 2>&1; then
    fail "unregistered native-library override is configured in $config_path"
  fi
done

if ! awk -F '\t' '
  /^#/ { next }
  NF != 7 { bad = 1; next }
  $1 != "registry" && $1 != "path" { bad = 1 }
  $2 !~ /^[A-Za-z0-9_-]+$/ || $3 !~ /^[0-9A-Za-z.+-]+$/ { bad = 1 }
  length($4) != 64 || $4 ~ /[^0-9a-f]/ { bad = 1 }
  $1 == "registry" && $5 != "crates.io-package" { bad = 1 }
  $1 == "path" && $5 != "host/" $2 "/Cargo.toml" { bad = 1 }
  $6 == "" || $7 == "" { bad = 1 }
  seen[$1 SUBSEP $2 SUBSEP $3]++ { bad = 1 }
  $1 == "registry" { registry_rows++ }
  $1 == "path" { path_rows++ }
  END { exit (bad || registry_rows != 4 || path_rows != 3) ? 1 : 0 }
' "$allowlist"; then
  fail "$allowlist does not contain exactly four registry and three path rows"
fi

allowlist_facts=$(awk -F '\t' '
  $1 == "registry" { print $2 "|" $3 "|" $4 "|" $6 }
' "$allowlist" | LC_ALL=C sort) || fail 'cannot normalize bench dependency allowlist'
expected_allowlist_facts='bitflags|2.13.1|b588b76d00fde79687d7646a9b5bdf3cc0f655e0bbd080335a95d7e96f3587da|MIT OR Apache-2.0
pcsc-sys|1.3.0|e14ef017e15d2e5592a9e39a346c1dbaea5120bab7ed7106b210ef58ebd97003|MIT
pcsc|2.9.0|7dd833ecf8967e65934c49d3521a175929839bf6d0e497f3bd0d3a2ca08943da|MIT
pkg-config|0.3.34|f6b464fbc74e149a392436b17d523f769e057cb6877f6a5c4618bc6f11800548|MIT OR Apache-2.0'
[ "$allowlist_facts" = "$expected_allowlist_facts" ] || \
  fail 'bench dependency allowlist facts differ from QK-DEC-147'

path_facts=$(awk -F '\t' '$1 == "path" { print $2 "|" $3 "|" $4 "|" $5 "|" $6 }' "$allowlist" | LC_ALL=C sort) || \
  fail 'cannot normalize bench test path facts'
expected_path_facts='qk-card-model|0.0.1|cff6eea5fa8b3c66bee2173f406b348f8cb819217fa6cc1d51271badd8a39127|host/qk-card-model/Cargo.toml|Apache-2.0
qk-card-protocol|0.0.1|dc58fd821c4409c7477ec9b471e469b24222ed76b4c50e8efc71cadefa9913b5|host/qk-card-protocol/Cargo.toml|Apache-2.0
qk-secp|0.0.1|4dd98b27cac64c0b4e90528e38e430cb98b1da225d8da793cece95b8079c59f0|host/qk-secp/Cargo.toml|Apache-2.0'
[ "$path_facts" = "$expected_path_facts" ] || fail 'bench dev path allowlist differs from QK-DEC-165'
for path_crate in qk-card-model qk-card-protocol qk-secp; do
  path_manifest="host/$path_crate/Cargo.toml"
  [ -f "$path_manifest" ] && [ ! -L "$path_manifest" ] || fail "path manifest is missing or linked: $path_manifest"
  expected_hash=$(awk -F '\t' -v name="$path_crate" '$1 == "path" && $2 == name { print $4 }' "$allowlist")
  actual_hash=$(shasum -a 256 "$path_manifest" | awk '{print $1}') || fail 'cannot hash test path manifest'
  [ "$actual_hash" = "$expected_hash" ] || fail "bench test path manifest checksum mismatch: $path_manifest"
done

fixture_names=$(git ls-files 'bench/card-enrollment/tests/fixtures/*' | LC_ALL=C sort) || \
  fail 'cannot enumerate registered sitting fixtures'
[ "$fixture_names" = 'bench/card-enrollment/tests/fixtures/sitting_install_v1.tsv
bench/card-enrollment/tests/fixtures/sitting_provision_v1.tsv' ] || \
  fail 'registered sitting fixture set is not exact'
for fixture_kind in install provision; do
  fixture="bench/card-enrollment/tests/fixtures/sitting_${fixture_kind}_v1.tsv"
  [ -f "$fixture" ] && [ ! -L "$fixture" ] || fail "registered sitting fixture is missing or linked: $fixture"
  case "$fixture_kind" in
    install) fixture_bytes=1421; fixture_lines=10; fixture_hash=8e3fba7d4d1cfe077bfe73806adc0f46a60db7471717909684b3caccf66a117e ;;
    provision) fixture_bytes=6203; fixture_lines=24; fixture_hash=2e142641399b652f39093d7297445af589feb58afb9963e9e0728bf8d9dda5e3 ;;
  esac
  actual_bytes=$(wc -c < "$fixture" | tr -d '[:space:]') || fail 'cannot count sitting fixture bytes'
  actual_lines=$(wc -l < "$fixture" | tr -d '[:space:]') || fail 'cannot count sitting fixture lines'
  actual_hash=$(shasum -a 256 "$fixture" | awk '{print $1}') || fail 'cannot hash sitting fixture'
  [ "$actual_bytes" = "$fixture_bytes" ] && [ "$actual_lines" = "$fixture_lines" ] && \
    [ "$actual_hash" = "$fixture_hash" ] || fail "registered sitting fixture identity mismatch: $fixture"
done

[ "$(sed -n 's/^version = \([0-9][0-9]*\)$/\1/p' "$lock" | head -n 1)" = 4 ] || \
  fail 'bench Cargo.lock format version is not 4'

lock_raw_tmp=$(mktemp) || fail 'mktemp failed for raw bench lock facts'
lock_facts_tmp=$(mktemp) || fail 'mktemp failed for bench lock facts'
normal_tree_tmp=$(mktemp) || fail 'mktemp failed for bench normal closure'
build_tree_tmp=$(mktemp) || fail 'mktemp failed for bench build closure'
test_tree_tmp=$(mktemp) || fail 'mktemp failed for bench test closure'
host_tree_tmp=$(mktemp) || fail 'mktemp failed for host closure'
fuzz_tree_tmp=$(mktemp) || fail 'mktemp failed for fuzz closure'
trap 'rm -f "$lock_raw_tmp" "$lock_facts_tmp" "$normal_tree_tmp" "$build_tree_tmp" "$test_tree_tmp" "$host_tree_tmp" "$fuzz_tree_tmp"' EXIT HUP INT TERM

if ! awk '
  BEGIN { RS = ""; FS = "\n" }
  /^\[\[package\]\]/ {
    name = version = source = checksum = ""
    for (i = 1; i <= NF; i++) {
      if ($i ~ /^name = "/) { name = $i; sub(/^name = "/, "", name); sub(/"$/, "", name) }
      if ($i ~ /^version = "/) { version = $i; sub(/^version = "/, "", version); sub(/"$/, "", version) }
      if ($i ~ /^source = "/) { source = $i; sub(/^source = "/, "", source); sub(/"$/, "", source) }
      if ($i ~ /^checksum = "/) { checksum = $i; sub(/^checksum = "/, "", checksum); sub(/"$/, "", checksum) }
    }
    if (name == "" || version == "") exit 1
    print name "|" version "|" source "|" checksum
  }
' "$lock" > "$lock_raw_tmp"; then
  fail 'cannot parse bench Cargo.lock'
fi
LC_ALL=C sort "$lock_raw_tmp" > "$lock_facts_tmp" || \
  fail 'cannot normalize bench Cargo.lock facts'
expected_lock_facts='bitflags|2.13.1|registry+https://github.com/rust-lang/crates.io-index|b588b76d00fde79687d7646a9b5bdf3cc0f655e0bbd080335a95d7e96f3587da
pcsc-sys|1.3.0|registry+https://github.com/rust-lang/crates.io-index|e14ef017e15d2e5592a9e39a346c1dbaea5120bab7ed7106b210ef58ebd97003
pcsc|2.9.0|registry+https://github.com/rust-lang/crates.io-index|7dd833ecf8967e65934c49d3521a175929839bf6d0e497f3bd0d3a2ca08943da
pkg-config|0.3.34|registry+https://github.com/rust-lang/crates.io-index|f6b464fbc74e149a392436b17d523f769e057cb6877f6a5c4618bc6f11800548
qk-card-enrollment|0.0.4||
qk-card-model|0.0.1||
qk-card-protocol|0.0.1||
qk-secp|0.0.1||'
[ "$(cat "$lock_facts_tmp")" = "$expected_lock_facts" ] || \
  fail 'bench Cargo.lock package set or checksum facts differ from QK-DEC-147'

command -v cargo >/dev/null 2>&1 || fail 'cargo is required to resolve dependency closures'
command -v rustc >/dev/null 2>&1 || fail 'rustc is required to identify the build target'
host_target=$(rustc -vV | sed -n 's/^host: //p')
[ -n "$host_target" ] || fail 'cannot identify the build target'
if ! cargo generate-lockfile --manifest-path host/Cargo.toml --offline >/dev/null 2>&1; then
  fail 'host Cargo.lock generation failed offline'
fi

if ! CARGO_NET_OFFLINE=true cargo tree --manifest-path "$manifest" --locked --offline \
    --target "$host_target" --edges normal --prefix none --format '{p}' \
    > "$normal_tree_tmp"; then
  fail 'cannot resolve the locked bench normal dependency closure offline'
fi
normal_facts=$(normalize_tree "$normal_tree_tmp") || fail 'cannot normalize bench normal closure'
expected_normal_facts='bitflags|2.13.1
pcsc-sys|1.3.0
pcsc|2.9.0
qk-card-enrollment|0.0.4'
[ "$normal_facts" = "$expected_normal_facts" ] || \
  fail 'bench normal dependency closure is not the exact reviewed four-package set'

if ! CARGO_NET_OFFLINE=true cargo tree --manifest-path "$manifest" --locked --offline \
    --target "$host_target" --edges normal,build --prefix none --format '{p}' \
    > "$build_tree_tmp"; then
  fail 'cannot resolve the locked bench normal/build dependency closure offline'
fi
build_facts=$(normalize_tree "$build_tree_tmp") || fail 'cannot normalize bench build closure'
expected_build_facts='bitflags|2.13.1
pcsc-sys|1.3.0
pcsc|2.9.0
pkg-config|0.3.34
qk-card-enrollment|0.0.4'
[ "$build_facts" = "$expected_build_facts" ] || \
  fail 'bench normal/build dependency closure is not the exact reviewed five-package set'

if ! CARGO_NET_OFFLINE=true cargo tree --manifest-path "$manifest" --locked --offline \
    --target "$host_target" --edges normal,build,dev --prefix none --format '{p}' \
    > "$test_tree_tmp"; then
  fail 'cannot resolve the locked bench test dependency closure offline'
fi
test_facts=$(normalize_tree "$test_tree_tmp") || fail 'cannot normalize bench test closure'
expected_test_facts='bitflags|2.13.1
pcsc-sys|1.3.0
pcsc|2.9.0
pkg-config|0.3.34
qk-card-enrollment|0.0.4
qk-card-model|0.0.1
qk-card-protocol|0.0.1
qk-secp|0.0.1'
[ "$test_facts" = "$expected_test_facts" ] || \
  fail 'bench test closure is not the exact eight-package reviewed set'
for path_crate in qk-card-model qk-card-protocol qk-secp; do
  grep -F "$path_crate v0.0.1 ($root/host/$path_crate)" "$test_tree_tmp" >/dev/null 2>&1 || \
    fail "bench test crate did not resolve to its reviewed local path: $path_crate"
done

if ! CARGO_NET_OFFLINE=true cargo tree --manifest-path host/Cargo.toml --workspace --locked \
    --offline --target "$host_target" --edges normal,build --prefix none --format '{p}' \
    > "$host_tree_tmp"; then
  fail 'cannot resolve the locked host dependency closure offline'
fi
grep -E '^(qk-card-enrollment|pcsc|pcsc-sys|pkg-config) v|^bitflags v2\.13\.1([[:space:]]|$)' \
  "$host_tree_tmp" >/dev/null 2>&1
host_isolation_status=$?
case "$host_isolation_status" in
  0) fail 'a bench package is reachable from the host/product dependency closure' ;;
  1) ;;
  *) fail 'cannot inspect the host/product dependency closure for bench packages' ;;
esac

if ! CARGO_NET_OFFLINE=true cargo tree --manifest-path fuzz/Cargo.toml --locked --offline \
    --all-features --target "$host_target" --edges normal,build --prefix none --format '{p}' \
    > "$fuzz_tree_tmp"; then
  fail 'cannot resolve the locked all-feature fuzz dependency closure offline'
fi
grep -E '^(qk-card-enrollment|pcsc|pcsc-sys|pkg-config) v|^bitflags v2\.13\.1([[:space:]]|$)' \
  "$fuzz_tree_tmp" >/dev/null 2>&1
fuzz_isolation_status=$?
case "$fuzz_isolation_status" in
  0) fail 'a bench package is reachable from the fuzz dependency closure' ;;
  1) ;;
  *) fail 'cannot inspect the fuzz dependency closure for bench packages' ;;
esac

if ! CARGO_NET_OFFLINE=true cargo test --manifest-path "$manifest" --locked --offline; then
  fail 'locked offline bench model and sitting tests failed'
fi
printf 'OK: bench normal/build/test closures, isolation and locked tests match QK-DEC-165\n'
exit 0
