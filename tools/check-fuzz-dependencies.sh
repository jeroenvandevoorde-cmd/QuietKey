#!/bin/sh
# Fail-closed validator for QK-DEC-106's ring-fenced fuzz manifests.
set -u

fail() { printf 'FAIL: %s\n' "$1" >&2; exit 1; }

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

fuzz_manifests=$(git ls-files | grep -E '^fuzz/(.*/)?Cargo\.toml$') || fuzz_manifests=''
[ -n "$fuzz_manifests" ] || fail 'no tracked fuzz/**/Cargo.toml manifest found'

dep_tmp=$(mktemp) || fail 'mktemp failed for fuzz dependency declarations'
tree_tmp=$(mktemp) || fail 'mktemp failed for fuzz dependency tree'
closure_raw_tmp=$(mktemp) || fail 'mktemp failed for raw fuzz dependency closure'
closure_tmp=$(mktemp) || fail 'mktemp failed for fuzz dependency closure'
trap 'rm -f "$dep_tmp" "$tree_tmp" "$closure_raw_tmp" "$closure_tmp"' EXIT HUP INT TERM

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
        if (line !~ /^[A-Za-z0-9_-]+[[:space:]]*=[[:space:]]*\{[[:space:]]*path[[:space:]]*=[[:space:]]*"[^"]+"[[:space:]]*,[[:space:]]*version[[:space:]]*=[[:space:]]*"=[0-9A-Za-z.+-]+"[[:space:]]*\}[[:space:]]*$/) {
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
  fail 'cannot resolve the locked active fuzz dependency closure offline'
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
' "$tree_tmp" > "$closure_raw_tmp"; then
  fail 'cannot parse active fuzz dependency closure'
fi
sort -u "$closure_raw_tmp" > "$closure_tmp" || fail 'cannot normalize active fuzz dependency closure'
[ -s "$closure_tmp" ] || fail 'active fuzz dependency closure is empty'

while IFS='|' read -r kind name version; do
  matches=$(awk -F '\t' -v k="$kind" -v n="$name" -v v="$version" \
    '!/^#/ && $1 == k && $2 == n && $3 == v { count++ } END { print count + 0 }' \
    "$allowlist") || fail 'active-closure allowlist lookup failed'
  [ "$matches" = 1 ] || fail "active dependency $kind $name $version is not uniquely allowed"
done < "$closure_tmp"

if ! CARGO_NET_OFFLINE=true cargo tree --manifest-path host/Cargo.toml --workspace --locked \
    --offline --target "$host_target" --edges normal,build --prefix none --format '{p}' \
    > "$tree_tmp"; then
  fail 'cannot resolve the locked host dependency closure offline'
fi
if grep -E '^(quietkey-fuzz|libfuzzer-sys) v' "$tree_tmp" >/dev/null 2>&1; then
  fail 'ring-fenced fuzz packages are reachable from the host workspace'
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
