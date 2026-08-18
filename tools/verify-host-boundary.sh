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

# forbid <msg> <grep args...>: the pattern must NOT match. grep exit 1
# (no match) is the ONLY pass; exit 0 (found) and exit >1 (scan error)
# both fail, so a broken scan can never pass silently.
forbid() {
  fmsg=$1; shift
  grep "$@" >/dev/null 2>&1
  frc=$?
  [ "$frc" -eq 1 ] || err "$fmsg (grep exit $frc: 0=found, >1=scan error)"
}

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
  dirty=$(git --no-optional-locks status --porcelain -uall) \
    || err "git status failed (enumeration fail-closed)"
  [ -z "$dirty" ] || err "worktree not clean in publication mode: $dirty"
fi

# Full tracked-file listing, fail-closed: every later filename scan
# reads this file instead of re-running git in a maskable pipeline.
git --no-optional-locks ls-files > "$tmpdir/allfiles" \
  || err "git ls-files failed (enumeration fail-closed)"
[ -s "$tmpdir/allfiles" ] || err "git ls-files returned no tracked files (enumeration fail-closed)"

# 1. Exact authorized host file set (tracked).
git --no-optional-locks ls-files -- host/ docs/f3/ docs/f4/ tools/verify-host-boundary.sh > "$tmpdir/hostfiles.raw" \
  || err "git ls-files (host scope) failed (enumeration fail-closed)"
[ -s "$tmpdir/hostfiles.raw" ] || err "no tracked host-scope files found (enumeration fail-closed)"
LC_ALL=C sort "$tmpdir/hostfiles.raw" > "$tmpdir/actual"
cat > "$tmpdir/expected" <<'EOF'
docs/f3/README.md
docs/f4/README.md
docs/f4/TRANSACTION-AUTHORITY-POLICY.md
host/.gitignore
host/Cargo.lock
host/Cargo.toml
host/TOOLCHAIN.md
host/qk-host-model/Cargo.toml
host/qk-host-model/src/lib.rs
host/qk-host-model/src/transaction_policy.rs
host/qk-host-sim/Cargo.toml
host/qk-host-sim/src/lib.rs
host/qk-host-sim/tests/state_skeleton.rs
host/qk-host-sim/tests/transaction_policy.rs
tools/verify-host-boundary.sh
EOF
if ! diff "$tmpdir/expected" "$tmpdir/actual" > "$tmpdir/filesdiff" 2>&1; then
  err "tracked host file set differs from the authorized set: $(cat "$tmpdir/filesdiff")"
fi

# 1b. Manifests and lockfile byte-identical to the published anchor
#     8f3154d0e7845ed5a4c69b73b9479821fdf06765 (no dependency drift).
MANIFEST_ANCHOR=8f3154d0e7845ed5a4c69b73b9479821fdf06765
for m in host/Cargo.toml host/Cargo.lock host/qk-host-model/Cargo.toml host/qk-host-sim/Cargo.toml; do
  git --no-optional-locks show "$MANIFEST_ANCHOR:$m" > "$tmpdir/anchor" 2>/dev/null \
    || err "cannot read $m from anchor $MANIFEST_ANCHOR"
  diff "$tmpdir/anchor" "$m" >/dev/null 2>&1 \
    || err "$m differs from anchor $MANIFEST_ANCHOR (manifests/lockfile must be byte-identical)"
done

# 2. Lockfile: only the two local workspace packages, no source/checksum.
forbid "host/Cargo.lock contains external source/checksum entries" \
  -E '^(source|checksum) *=' host/Cargo.lock
names=$(grep -c '^name = ' host/Cargo.lock)
[ "$names" = "2" ] || err "host/Cargo.lock does not contain exactly two packages (found $names)"
grep '^name = "qk-host-model"$' host/Cargo.lock >/dev/null || err "qk-host-model missing from lockfile"
grep '^name = "qk-host-sim"$' host/Cargo.lock >/dev/null || err "qk-host-sim missing from lockfile"

# 3. No tracked build output, env files, key/seed-like fixtures, or
#    unexpected manifests.
forbid "tracked build output or .env file present" \
  -E '^host/target/|(^|/)\.env' "$tmpdir/allfiles"
forbid "key/seed-like fixture filename tracked" \
  -iE '(^|/)(.*(seed|mnemonic|xprv|private[_-]?key).*)$' "$tmpdir/allfiles"
# grep exit 0 = matches, 1 = no match (allowed here), >1 = error (fail).
grep -E '(^|/)Cargo\.toml$' "$tmpdir/allfiles" > "$tmpdir/alltoml"
rc=$?
[ "$rc" -le 1 ] || err "manifest enumeration grep failed (fail-closed)"
grep -v -e '^host/Cargo.toml$' -e '^host/qk-host-model/Cargo.toml$' -e '^host/qk-host-sim/Cargo.toml$' "$tmpdir/alltoml" > "$tmpdir/badtoml"
rc=$?
[ "$rc" -le 1 ] || err "manifest allowlist grep failed (fail-closed)"
[ ! -s "$tmpdir/badtoml" ] || err "unexpected Cargo manifest(s): $(cat "$tmpdir/badtoml")"

# 4. Rust sources: unsafe forbidden, no prohibited capability imports.
for f in host/qk-host-model/src/lib.rs host/qk-host-sim/src/lib.rs; do
  grep -F '#![forbid(unsafe_code)]' "$f" >/dev/null || err "$f missing #![forbid(unsafe_code)]"
done
grep -E '^host/.*\.rs$' "$tmpdir/allfiles" > "$tmpdir/rsfiles"
rc=$?
[ "$rc" -le 1 ] || err "host Rust source enumeration grep failed (fail-closed)"
[ -s "$tmpdir/rsfiles" ] || err "no tracked host Rust sources found (enumeration fail-closed)"
while IFS= read -r f; do
  grep -nE '(^|[^_[:alnum:]])unsafe([^_[:alnum:]]|$)' "$f" > "$tmpdir/unsafe" 2>&1
  urc=$?
  [ "$urc" -le 1 ] || err "unsafe scan failed on $f (grep exit $urc)"
  forbid "$f contains unsafe code" \
    -v 'forbid(unsafe_code)' "$tmpdir/unsafe"
  forbid "$f uses a prohibited I/O/network/environment/process/logging capability" \
    -nE 'std *:: *(fs|net|env|process|thread|time)|core *:: *arch|extern +"C"|include_(str|bytes)!|std *:: *io *:: *(stdin|stdout|stderr)|(^|[^_[:alnum:]])(println|eprintln|print|eprint|dbg)!' "$f"
done < "$tmpdir/rsfiles"

# 4a. Library-only: no binary entry point in any host Rust source.
# HEURISTIC SUPPORTING CHECK, NOT PROOF: textual scans cannot prove the
# semantic absence of a capability; they only catch direct spellings.
while IFS= read -r f; do
  forbid "$f contains a fn main entry point (library-only crates required)" \
    -nE '(^|[^_[:alnum:]])fn +main *\(' "$f"
done < "$tmpdir/rsfiles"
forbid "binary source layout present under host/ (library-only crates required)" \
  -E '^host/.*/src/(main\.rs|bin/)' "$tmpdir/allfiles"

# 4d. Payload/data boundary in non-test host sources: no textual payload
# fields, byte buffers, or wallet-data vocabulary. HEURISTIC SUPPORTING
# CHECKS, NOT PROOF of payload absence.
grep -v '/tests/' "$tmpdir/rsfiles" > "$tmpdir/rslib"
rc=$?
[ "$rc" -le 1 ] || err "non-test source enumeration grep failed (fail-closed)"
[ -s "$tmpdir/rslib" ] || err "no non-test host Rust sources found (enumeration fail-closed)"

# 4e. Regression: normal exported (non-test) Rust source must contain no
# public arbitrary-start workflow/scenario helper for the transaction
# model — the only exported transaction runner accepts events only and
# begins Locked. grep exit 1 (no match) is the REQUIRED result here.
while IFS= read -r f; do
    forbid "$f exports a public arbitrary-start transaction workflow/scenario helper" \
        -nE 'pub +fn +[a-z_]*(scenario|workflow)[a-z_]*\([^)]*TransactionState' "$f"
    forbid "$f contains a from_state arbitrary-start helper in exported source" \
        -nE 'from_state' "$f"
done < "$tmpdir/rslib"
while IFS= read -r f; do
  forbid "$f contains a textual/byte payload type (String, &str, Vec<u8>, or u8 buffer)" \
    -nE '(^|[^_[:alnum:]])(String|str|Vec *< *u8 *>|\[ *u8 *(;|\])])([^_[:alnum:]]|$)' "$f"
  forbid "$f contains wallet-data vocabulary" \
    -niE '(^|[^_[:alnum:]])(psbt|txid|satoshi|address|script|descriptor|mainnet|testnet|seed|entropy|mnemonic|xprv|xpub|apdu)([^_[:alnum:]]|$)' "$f"
  forbid "$f references a prohibited serialization/crypto/randomness/clock capability" \
    -nE '(^|[^_[:alnum:]])(serde|bincode|rand|getrandom)([^_[:alnum:]]|$)|include_(str|bytes)!|std *:: *(fs|net|env|process|thread|time)' "$f"
done < "$tmpdir/rslib"

# 4b. Manifest invariants: edition, publish, no license fields, resolver 2.
grep '^resolver = "2"$' host/Cargo.toml >/dev/null || err "host/Cargo.toml missing resolver = \"2\""
grep '^overflow-checks = true$' host/Cargo.toml >/dev/null || err "host/Cargo.toml missing release overflow-checks = true"
grep '^panic = "abort"$' host/Cargo.toml >/dev/null || err "host/Cargo.toml missing release panic = \"abort\""
for m in host/qk-host-model/Cargo.toml host/qk-host-sim/Cargo.toml; do
  grep '^edition = "2021"$' "$m" >/dev/null || err "$m missing edition = \"2021\""
  grep '^publish = false$' "$m" >/dev/null || err "$m missing publish = false"
  forbid "$m contains a license field while OD-08 is open" \
    -E '^(license|license-file) *=' "$m"
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

# 5b. Transaction authority policy documentation: required banners,
# symbolic-assertion wording, and status-preservation wording.
TAP=docs/f4/TRANSACTION-AUTHORITY-POLICY.md
[ -f "$TAP" ] || err "$TAP missing"
grep -F 'HOST-ONLY — PAYLOAD-FREE — NOT PRODUCT CODE — NOT TARGET EVIDENCE — INCOMPLETE' "$TAP" >/dev/null \
  || err "$TAP missing the HOST-ONLY/PAYLOAD-FREE/NOT PRODUCT CODE/NOT TARGET EVIDENCE/INCOMPLETE banner"
grep -F 'EXPERIMENTAL — NO REAL FUNDS — NOT A WALLET' "$TAP" >/dev/null \
  || err "$TAP missing the no-funds warning"
grep -F 'UNAUTHENTICATED symbolic assertion' "$TAP" >/dev/null \
  || err "$TAP missing the symbolic-assertion limitation wording"
grep -F 'No canonical test status, gate, open decision, limit, or evidence' "$TAP" >/dev/null \
  || err "$TAP missing the status-preservation wording"
grep -F 'NON-NORMATIVE scaffold until the corresponding' "$TAP" >/dev/null \
  || err "$TAP missing the non-normative-until-F3-acceptance wording"
grep -F 'TRANSACTION-AUTHORITY-POLICY.md' docs/f4/README.md >/dev/null \
  || err "docs/f4/README.md does not link the transaction authority policy model"
grep -F 'HOST policy model' host/qk-host-sim/tests/transaction_policy.rs >/dev/null \
  || err "transaction policy tests missing the HOST policy model label"
# Approval semantics wording: stale per-invocation forms are FALSE
# (a second cycle in the same invocation may validly Approve again)
# and must not recur; the precise per-cycle language must be present.
forbid "stale per-invocation approval/reparse claim present (must use per-authorization-cycle wording)" \
  -E 'same invocation rejects|single-use per invocation|single-use per function invocation|mandatory before returning|second .Approve. in (that|the) same invocation' \
  host/qk-host-model/src/transaction_policy.rs \
  host/qk-host-sim/src/lib.rs \
  host/qk-host-sim/tests/transaction_policy.rs \
  docs/f4/TRANSACTION-AUTHORITY-POLICY.md \
  docs/f4/README.md
grep -F 'per authorization cycle, not per function invocation' "$TAP" >/dev/null \
  || err "$TAP missing the per-authorization-cycle approval wording"
grep -F 'only through' "$TAP" >/dev/null \
  || err "$TAP missing the signed-completion-path OutputReparsed wording"
grep -nE 'Gate C evidence' host/qk-host-sim/tests/transaction_policy.rs >/dev/null \
  || err "transaction policy tests missing the no-Gate-C-evidence disclaimer"

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
tr ',' '\n' < "$tmpdir/meta" > "$tmpdir/metalines" \
  || err "cargo metadata post-processing failed (fail-closed)"
grep '"manifest_path":' "$tmpdir/metalines" > "$tmpdir/manifpaths"
mrc=$?
[ "$mrc" -le 1 ] || err "cargo metadata manifest scan failed (grep exit $mrc)"
[ -s "$tmpdir/manifpaths" ] || err "cargo metadata reports no manifest paths (fail-closed)"
forbid "cargo metadata reports a package outside the authorized workspace" \
  -v 'host/qk-host-\(model\|sim\)/Cargo.toml' "$tmpdir/manifpaths"

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
