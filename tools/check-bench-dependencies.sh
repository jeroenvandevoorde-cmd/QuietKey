#!/bin/sh
# Fail-closed validator for QK-DEC-147's ring-fenced card-enrollment tool.
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
  in_package && $0 == "version = \"0.0.2\"" { versions++ }
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
    if ($0 == "[dependencies]") dependency_sections++
    else if ($0 ~ /dependencies/ || $0 ~ /^\[(patch|replace)(\.|\])/) forbidden_sections++
    next
  }
  in_dependencies && $0 !~ /^[[:space:]]*(#|$)/ {
    entries++
    if ($0 == "pcsc = { version = \"=2.9.0\" }") pcsc++
    else bad++
  }
  END { print dependency_sections + 0, entries + 0, pcsc + 0, bad + 0, forbidden_sections + 0 }
' "$manifest") || fail 'cannot inspect bench dependency declaration'
[ "$dependency_shape" = '1 1 1 0 0' ] || \
  fail 'bench direct dependency set is not exactly pcsc 2.9.0'

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
for source in $bench_sources; do
  [ -f "$source" ] || fail "tracked bench source is missing: $source"
  [ ! -L "$source" ] || fail "tracked bench source must not be a symbolic link: $source"
done
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
  $1 != "registry" { bad = 1 }
  $2 !~ /^[A-Za-z0-9_-]+$/ || $3 !~ /^[0-9A-Za-z.+-]+$/ { bad = 1 }
  length($4) != 64 || $4 ~ /[^0-9a-f]/ { bad = 1 }
  $5 != "crates.io-package" || $6 == "" || $7 == "" { bad = 1 }
  seen[$1 SUBSEP $2 SUBSEP $3]++ { bad = 1 }
  { rows++ }
  END { exit (bad || rows != 4) ? 1 : 0 }
' "$allowlist"; then
  fail "$allowlist does not contain exactly four well-formed registry rows"
fi

allowlist_facts=$(awk -F '\t' '
  !/^#/ { print $2 "|" $3 "|" $4 "|" $6 }
' "$allowlist" | LC_ALL=C sort) || fail 'cannot normalize bench dependency allowlist'
expected_allowlist_facts='bitflags|2.13.1|b588b76d00fde79687d7646a9b5bdf3cc0f655e0bbd080335a95d7e96f3587da|MIT OR Apache-2.0
pcsc-sys|1.3.0|e14ef017e15d2e5592a9e39a346c1dbaea5120bab7ed7106b210ef58ebd97003|MIT
pcsc|2.9.0|7dd833ecf8967e65934c49d3521a175929839bf6d0e497f3bd0d3a2ca08943da|MIT
pkg-config|0.3.34|f6b464fbc74e149a392436b17d523f769e057cb6877f6a5c4618bc6f11800548|MIT OR Apache-2.0'
[ "$allowlist_facts" = "$expected_allowlist_facts" ] || \
  fail 'bench dependency allowlist facts differ from QK-DEC-147'

[ "$(sed -n 's/^version = \([0-9][0-9]*\)$/\1/p' "$lock" | head -n 1)" = 4 ] || \
  fail 'bench Cargo.lock format version is not 4'

lock_raw_tmp=$(mktemp) || fail 'mktemp failed for raw bench lock facts'
lock_facts_tmp=$(mktemp) || fail 'mktemp failed for bench lock facts'
normal_tree_tmp=$(mktemp) || fail 'mktemp failed for bench normal closure'
build_tree_tmp=$(mktemp) || fail 'mktemp failed for bench build closure'
host_tree_tmp=$(mktemp) || fail 'mktemp failed for host closure'
fuzz_tree_tmp=$(mktemp) || fail 'mktemp failed for fuzz closure'
trap 'rm -f "$lock_raw_tmp" "$lock_facts_tmp" "$normal_tree_tmp" "$build_tree_tmp" "$host_tree_tmp" "$fuzz_tree_tmp"' EXIT HUP INT TERM

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
qk-card-enrollment|0.0.2||'
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
qk-card-enrollment|0.0.2'
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
qk-card-enrollment|0.0.2'
[ "$build_facts" = "$expected_build_facts" ] || \
  fail 'bench normal/build dependency closure is not the exact reviewed five-package set'

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

exit 0
