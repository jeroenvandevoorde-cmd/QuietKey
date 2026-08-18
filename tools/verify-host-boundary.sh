#!/bin/sh
# QuietKey host-boundary verifier.
# Additive, POSIX, verify-only, offline, non-mutating: all temporary files
# and all Cargo build artifacts go into a temporary directory that is
# removed on every exit path. Checks the HOST bootstrap scope only.
# It never asserts project, security, or cryptographic conformance.
#
# The grep-based source checks below are heuristic boundary checks, not
# complete semantic proof of the absence of any capability.
#
# Modes:
#   (no argument)  — strict publication mode: requires a completely clean
#                    tracked AND untracked worktree. This is the only mode
#                    valid as publication validation evidence.
#   --local-dev    — local-development mode, solely for pre-commit use:
#                    skips ONLY the clean-worktree requirement and labels
#                    its pass line as non-evidence.

set -u

mode="publication"
case "${1:-}" in
  "") : ;;
  --local-dev) mode="local-dev" ;;
  *) echo "HOST BOUNDARY FAIL: unknown argument '$1' (only --local-dev is accepted)" >&2; exit 1 ;;
esac

fail=0
err() { printf 'HOST BOUNDARY FAIL: %s\n' "$1" >&2; fail=1; }

# Portable private temporary directory (mkdir is atomic and POSIX).
tmpdir="${TMPDIR:-/tmp}/qk-host-boundary.$$"
umask 077
mkdir "$tmpdir" || { echo "HOST BOUNDARY FAIL: cannot create temp dir" >&2; exit 1; }
trap 'rm -rf "$tmpdir"' EXIT INT TERM

# Keep all Cargo output out of the repository worktree.
CARGO_TARGET_DIR="$tmpdir/target"
export CARGO_TARGET_DIR

# 0. Publication mode requires a clean tracked and untracked worktree
#    (ignored files, such as build caches, are acceptable).
if [ "$mode" = "publication" ]; then
  dirty=$(git --no-optional-locks status --porcelain -uall)
  [ -z "$dirty" ] || err "worktree not clean in publication mode: $dirty"
fi

# 1. Exact authorized host file set (tracked).
git --no-optional-locks ls-files -- host/ docs/f3/ docs/f4/ tools/verify-host-boundary.sh | LC_ALL=C sort > "$tmpdir/actual"
cat > "$tmpdir/expected" <<'EOF'
docs/f3/README.md
docs/f4/README.md
host/.gitignore
host/Cargo.lock
host/Cargo.toml
host/TOOLCHAIN.md
host/qk-host-model/Cargo.toml
host/qk-host-model/src/lib.rs
host/qk-host-sim/Cargo.toml
host/qk-host-sim/src/lib.rs
host/qk-host-sim/tests/state_skeleton.rs
tools/verify-host-boundary.sh
EOF
if ! diff "$tmpdir/expected" "$tmpdir/actual" > "$tmpdir/filesdiff" 2>&1; then
  err "tracked host file set differs from the authorized set: $(cat "$tmpdir/filesdiff")"
fi

# 2. Lockfile: only the two local workspace packages, no source/checksum.
if grep -E '^(source|checksum) *=' host/Cargo.lock >/dev/null 2>&1; then
  err "host/Cargo.lock contains external source/checksum entries"
fi
names=$(grep -c '^name = ' host/Cargo.lock)
[ "$names" = "2" ] || err "host/Cargo.lock does not contain exactly two packages (found $names)"
grep '^name = "qk-host-model"$' host/Cargo.lock >/dev/null || err "qk-host-model missing from lockfile"
grep '^name = "qk-host-sim"$' host/Cargo.lock >/dev/null || err "qk-host-sim missing from lockfile"

# 3. No tracked build output, env files, key/seed-like fixtures, or
#    unexpected manifests.
git --no-optional-locks ls-files | grep -E '^host/target/|(^|/)\.env' >/dev/null 2>&1 \
  && err "tracked build output or .env file present"
git --no-optional-locks ls-files | grep -iE '(^|/)(.*(seed|mnemonic|xprv|private[_-]?key).*)$' >/dev/null 2>&1 \
  && err "key/seed-like fixture filename tracked"
manifests=$(git --no-optional-locks ls-files -- '*Cargo.toml' | grep -v -e '^host/Cargo.toml$' -e '^host/qk-host-model/Cargo.toml$' -e '^host/qk-host-sim/Cargo.toml$' || :)
[ -z "$manifests" ] || err "unexpected Cargo manifest(s): $manifests"

# 4. Rust sources: unsafe forbidden, no prohibited capability imports.
for f in host/qk-host-model/src/lib.rs host/qk-host-sim/src/lib.rs; do
  grep -F '#![forbid(unsafe_code)]' "$f" >/dev/null || err "$f missing #![forbid(unsafe_code)]"
done
git --no-optional-locks ls-files -- 'host/*.rs' > "$tmpdir/rsfiles"
while IFS= read -r f; do
  grep -nE '(^|[^_[:alnum:]])unsafe([^_[:alnum:]]|$)' "$f" | grep -v 'forbid(unsafe_code)' >/dev/null 2>&1 \
    && err "$f contains unsafe code"
  grep -nE 'std *:: *(fs|net|env|process|thread|time)|core *:: *arch|extern +"C"|include_(str|bytes)!|std *:: *io *:: *(stdin|stdout|stderr)|(^|[^_[:alnum:]])(println|eprintln|print|eprint|dbg)!' "$f" >/dev/null 2>&1 \
    && err "$f uses a prohibited I/O/network/environment/process/logging capability"
done < "$tmpdir/rsfiles"

# 4b. Manifest invariants: edition, publish, no license fields, resolver 2.
grep '^resolver = "2"$' host/Cargo.toml >/dev/null || err "host/Cargo.toml missing resolver = \"2\""
grep '^overflow-checks = true$' host/Cargo.toml >/dev/null || err "host/Cargo.toml missing release overflow-checks = true"
grep '^panic = "abort"$' host/Cargo.toml >/dev/null || err "host/Cargo.toml missing release panic = \"abort\""
for m in host/qk-host-model/Cargo.toml host/qk-host-sim/Cargo.toml; do
  grep '^edition = "2021"$' "$m" >/dev/null || err "$m missing edition = \"2021\""
  grep '^publish = false$' "$m" >/dev/null || err "$m missing publish = false"
  grep -E '^(license|license-file) *=' "$m" >/dev/null 2>&1 && err "$m contains a license field while OD-08 is open"
done

# 4c. .replit: exactly the authorized content (run command, single module,
#     nix channel, agent and packager settings untouched).
cat > "$tmpdir/replit.expected" <<'EOF'
run = "bash tools/verify-current-stage.sh"
modules = ["rust-stable"]

[nix]
channel = "stable-25_05"

[agent]
expertMode = true

[packager.features]
guessImports = false
packageSearch = false
enabledForHosting = false
EOF
diff "$tmpdir/replit.expected" .replit > "$tmpdir/replitdiff" 2>&1 \
  || err ".replit differs from the authorized host-bootstrap content: $(cat "$tmpdir/replitdiff")"

# 5. Required status banners.
grep -F 'STATUS: AUTHORIZED — HOST-ONLY PROFILE AND PUBLIC TEST-VECTOR PREPARATION — INCOMPLETE — NO PROFILE ACCEPTED — NO TARGET EVIDENCE.' docs/f3/README.md >/dev/null \
  || err "docs/f3/README.md missing required status banner"
grep -F 'STATUS: AUTHORIZED — HOST-ONLY INTERFACE AND STATE-MACHINE SCAFFOLD — INCOMPLETE — NO TARGET CLAIM.' docs/f4/README.md >/dev/null \
  || err "docs/f4/README.md missing required status banner"
grep -F 'HOST BOOTSTRAP TOOLCHAIN ONLY — NOT THE PRODUCTION TOOLCHAIN — OD-01 OPEN' host/TOOLCHAIN.md >/dev/null \
  || err "host/TOOLCHAIN.md missing required status banner"

# 6. Unchanged gate and open-decision language.
for g in A B C D E; do
  grep -E "Gate $g.*OPEN|OPEN.*Gate $g" docs/MATURITY-GATES.md >/dev/null 2>&1 \
    || err "Gate $g OPEN language not found in docs/MATURITY-GATES.md"
done
for od in OD-01 OD-02 OD-03 OD-04 OD-05 OD-06 OD-07 OD-08; do
  grep -F "$od" docs/OPEN-DECISIONS.md >/dev/null || err "$od missing from docs/OPEN-DECISIONS.md"
done

# 7. Formatting. rustfmt is REQUIRED; never silently skipped.
if command -v cargo-fmt >/dev/null 2>&1; then
  cargo fmt --manifest-path host/Cargo.toml --all --check > "$tmpdir/fmt" 2>&1 \
    || err "cargo fmt --check failed: $(cat "$tmpdir/fmt")"
else
  err "rustfmt (cargo-fmt) is not installed; formatting check cannot be skipped"
fi

# 8. Tests, locked and offline.
cargo test --manifest-path host/Cargo.toml --locked --offline > "$tmpdir/test" 2>&1 \
  || err "cargo test --locked --offline failed: $(tail -20 "$tmpdir/test")"

# 9. Exactly two local packages in metadata.
cargo metadata --manifest-path host/Cargo.toml --locked --offline --no-deps --format-version 1 > "$tmpdir/meta" 2>&1 \
  || err "cargo metadata failed: $(tail -5 "$tmpdir/meta")"
pkgcount=$(tr ',' '\n' < "$tmpdir/meta" | grep -c '"manifest_path":')
[ "$pkgcount" = "2" ] || err "cargo metadata does not report exactly two local packages (found $pkgcount)"
tr ',' '\n' < "$tmpdir/meta" | grep '"manifest_path":' | grep -v 'host/qk-host-\(model\|sim\)/Cargo.toml' >/dev/null 2>&1 \
  && err "cargo metadata reports a package outside the authorized workspace"

if [ "$fail" -eq 0 ]; then
  if [ "$mode" = "publication" ]; then
    echo "HOST BOOTSTRAP SCOPE PASS"
  else
    echo "HOST BOOTSTRAP SCOPE PASS (LOCAL-DEVELOPMENT MODE — NOT PUBLICATION EVIDENCE)"
  fi
  exit 0
else
  exit 1
fi
