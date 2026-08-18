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
LC_ALL=C sort "$tmpdir/hostfiles.raw" > "$tmpdir/actual" \
  || err "host-scope file-set sort failed (fail-closed)"
cat > "$tmpdir/expected" <<'EOF'
docs/f3/PSBT-V0-REVIEW-PROFILE-DRAFT.md
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
# grep -c exit 0 = matches counted, 1 = zero matches (count printed),
# >1 = error; rc checked explicitly before the exact-count comparison.
names=$(grep -c '^name = ' host/Cargo.lock)
rc=$?
[ "$rc" -le 1 ] || err "host/Cargo.lock package-name count failed (grep exit $rc)"
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
# u8 payload detector pattern (POSIX ERE; ']' first inside the bracket
# class so it is literal): catches both '[u8]' and '[u8; N]' forms.
# Heuristic supporting check, not semantic proof.
u8pat='(^|[^_[:alnum:]])(String|str|Vec *< *u8 *>|\[ *u8 *[];])([^_[:alnum:]]|$)'
# Fail-closed synthetic regression for the detector itself: two
# positive controls MUST match (grep rc 0) and one negative control
# MUST NOT match (grep rc 1); any other rc is a scan error. No
# pipelines; every rc checked; a broken detector can never pass.
printf 'let a: [u8] = b;\n' > "$tmpdir/u8pos1" \
  || err "u8 regression fixture write failed (fail-closed)"
printf 'let a: [u8; 32] = b;\n' > "$tmpdir/u8pos2" \
  || err "u8 regression fixture write failed (fail-closed)"
printf 'let a = 9u8; let b = a + a;\n' > "$tmpdir/u8neg" \
  || err "u8 regression fixture write failed (fail-closed)"
for pf in "$tmpdir/u8pos1" "$tmpdir/u8pos2"; do
  grep -E "$u8pat" "$pf" >/dev/null 2>&1
  urc=$?
  [ "$urc" -eq 0 ] || err "u8 detector regression: positive control $pf not detected (grep exit $urc)"
done
grep -E "$u8pat" "$tmpdir/u8neg" >/dev/null 2>&1
urc=$?
[ "$urc" -eq 1 ] || err "u8 detector regression: negative control matched or scan error (grep exit $urc)"
while IFS= read -r f; do
  forbid "$f contains a textual/byte payload type (String, &str, Vec<u8>, or u8 buffer)" \
    -nE "$u8pat" "$f"
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

# 5c. F3.1 PSBT v0 review-profile DRAFT: static supporting checks only.
# These greps are heuristic evidence, never proof, and never assert
# acceptance of anything. Every grep pipeline is split into separately
# rc-checked steps: POSIX sh has no pipefail.
DRAFT=docs/f3/PSBT-V0-REVIEW-PROFILE-DRAFT.md
[ -f "$DRAFT" ] || err "$DRAFT missing"
grep -F 'EXPERIMENTAL — NO REAL FUNDS — NOT A WALLET' "$DRAFT" >/dev/null \
  || err "$DRAFT missing the no-funds warning"
grep -F 'STATUS: AUTHORIZED — F3.1 HOST-ONLY PSBT v0 REVIEW-PROFILE DRAFT — NON-NORMATIVE — INCOMPLETE — NO PROFILE ACCEPTED — NO TEST VECTORS GENERATED — NO TARGET EVIDENCE.' "$DRAFT" >/dev/null \
  || err "$DRAFT missing the mandatory draft status banner"
grep -F 'AUTHORIZATION: QK-AUTH-F3F4-001 — DRAFTING ONLY; F3.1a remediation recorded as QK-AUTH-F3.1A-001; F3.1b Revision 2 owner policy directions recorded as QK-AUTH-F3.1B-R2-001.' "$DRAFT" >/dev/null \
  || err "$DRAFT missing the drafting-only authorization line with the Revision 2 recording"
grep -F 'REVISION: F3.1b REVISION 2 — OWNER DIRECTIONS RECORDED — PROFILE NOT ACCEPTED.' "$DRAFT" >/dev/null \
  || err "$DRAFT missing the exact F3.1b Revision 2 revision marker"
grep -F 'REVIEW DRAFT — F3.1b REVISION 2 OWNER DIRECTIONS RECORDED — NOT ACCEPTED' "$DRAFT" >/dev/null \
  || err "$DRAFT missing the mandatory Revision 2 end status"
grep -F 'QK-AUTH-F3.1B-R2-001' docs/DECISION-LOG.md >/dev/null \
  || err "docs/DECISION-LOG.md missing the QK-AUTH-F3.1B-R2-001 authorization entry"
forbid "$DRAFT still carries the superseded F3.1a revision marker" \
  -F 'REVISION: F3.1a — CORRECTION-ONLY REVIEW DRAFT' "$DRAFT"
# Required primary-source citations: commit-pinned links only (H).
grep -F 'https://github.com/bitcoin/bips/blob/857a7debc6625a3dadbaecee1ee7b2ed5e8ada75/bip-0174.mediawiki' "$DRAFT" >/dev/null \
  || err "$DRAFT missing the pinned BIP 174 link"
grep -F 'https://github.com/bitcoin/bips/blob/857a7debc6625a3dadbaecee1ee7b2ed5e8ada75/bip-0174/type-registry.mediawiki' "$DRAFT" >/dev/null \
  || err "$DRAFT missing the pinned PSBT type-registry link"
grep -F 'https://github.com/bitcoin/bips/blob/857a7debc6625a3dadbaecee1ee7b2ed5e8ada75/bip-0370.mediawiki' "$DRAFT" >/dev/null \
  || err "$DRAFT missing the pinned BIP 370 link"
grep -F 'https://github.com/bitcoin/bitcoin/blob/15a7a4ed7c4d0952ce966087e55a9a3e2f28ec1d/doc/psbt.md' "$DRAFT" >/dev/null \
  || err "$DRAFT missing the pinned Bitcoin Core psbt.md link"
# Pinned 40-hex provenance rows must exist in the source register.
grep -F '857a7debc6625a3dadbaecee1ee7b2ed5e8ada75' docs/SOURCE-REGISTER.md >/dev/null \
  || err "docs/SOURCE-REGISTER.md missing the pinned bitcoin/bips commit row"
grep -F '15a7a4ed7c4d0952ce966087e55a9a3e2f28ec1d' docs/SOURCE-REGISTER.md >/dev/null \
  || err "docs/SOURCE-REGISTER.md missing the pinned bitcoin/bitcoin commit row"
# Required matrices/topics present.
for topic in 'Field-disposition matrices' 'reject-reason taxonomy' \
  'Traceability matrix' 'test-plan matrix' 'decision packet' \
  'Threat and trust contract' 'Proposed validation order'; do
  grep -F "$topic" "$DRAFT" >/dev/null \
    || err "$DRAFT missing required topic: $topic"
done
# Exact contiguous clause-ID set QK-F3-PSBT-001..034: no missing,
# extra, duplicate, or gap. Generated expected list, separately
# checked cmp; nonempty+unique alone is insufficient.
grep -E '^\*\*QK-F3-PSBT-[0-9]{3}\*\*' "$DRAFT" > "$tmpdir/clausedefs"
rc=$?
[ "$rc" -eq 0 ] || err "clause-definition scan failed or found nothing (grep exit $rc)"
awk '{ s = $0
  while (match(s, /QK-F3-PSBT-[0-9][0-9][0-9]/)) {
    print substr(s, RSTART, RLENGTH)
    s = substr(s, RSTART + RLENGTH) } }' \
  "$tmpdir/clausedefs" > "$tmpdir/clauseids.raw"
rc=$?
[ "$rc" -eq 0 ] || err "clause-ID extraction failed (awk exit $rc)"
[ -s "$tmpdir/clauseids.raw" ] || err "clause-ID extraction found nothing (exact-empty is a failure)"
LC_ALL=C sort "$tmpdir/clauseids.raw" > "$tmpdir/clauseids" \
  || err "clause-ID sort failed (fail-closed)"
: > "$tmpdir/clauseexp"
i=1
while [ "$i" -le 34 ]; do
  printf 'QK-F3-PSBT-%03d\n' "$i" >> "$tmpdir/clauseexp" \
    || err "clause expected-list generation failed (fail-closed)"
  i=$((i+1))
done
cmp -s "$tmpdir/clauseexp" "$tmpdir/clauseids"
rc=$?
[ "$rc" -eq 0 ] || err "clause-ID set is not exactly QK-F3-PSBT-001..034 contiguous (cmp exit $rc)"
# Exact contiguous plan-ID set QK-F3-PLAN-001..090, same method. Only
# the row-leading plan ID defines a row; oracle-column cross-references
# are not definitions.
grep -E '^\| QK-F3-PLAN-[0-9]{3} ' "$DRAFT" > "$tmpdir/planrows"
rc=$?
[ "$rc" -eq 0 ] || err "plan-row scan failed or found nothing (grep exit $rc)"
awk '/^\| QK-F3-PLAN-[0-9][0-9][0-9]/ { print substr($0, 1, 16) }' \
  "$tmpdir/planrows" > "$tmpdir/planlead"
rc=$?
[ "$rc" -eq 0 ] || err "plan lead-ID scan failed (awk exit $rc)"
[ -s "$tmpdir/planlead" ] || err "plan lead-ID scan found nothing (exact-empty is a failure)"
awk '{ s = $0
  while (match(s, /QK-F3-PLAN-[0-9][0-9][0-9]/)) {
    print substr(s, RSTART, RLENGTH)
    s = substr(s, RSTART + RLENGTH) } }' \
  "$tmpdir/planlead" > "$tmpdir/planids.raw"
rc=$?
[ "$rc" -eq 0 ] || err "plan-ID extraction failed (awk exit $rc)"
[ -s "$tmpdir/planids.raw" ] || err "plan-ID extraction found nothing (exact-empty is a failure)"
LC_ALL=C sort "$tmpdir/planids.raw" > "$tmpdir/planids" \
  || err "plan-ID sort failed (fail-closed)"
: > "$tmpdir/planexp"
i=1
while [ "$i" -le 90 ]; do
  printf 'QK-F3-PLAN-%03d\n' "$i" >> "$tmpdir/planexp" \
    || err "plan expected-list generation failed (fail-closed)"
  i=$((i+1))
done
cmp -s "$tmpdir/planexp" "$tmpdir/planids"
rc=$?
[ "$rc" -eq 0 ] || err "plan-ID set is not exactly QK-F3-PLAN-001..090 contiguous (cmp exit $rc)"
forbid "plan row without the exact PLANNED — NOT GENERATED — NOT RUN status" \
  -v 'PLANNED — NOT GENERATED — NOT RUN |$' "$tmpdir/planrows"
forbid "generated/run/pass/fail status form present in plan rows" \
  -E ' PASSED| FAILED|WAS GENERATED|WAS RUN' "$tmpdir/planrows"
# B: complete PSBT-v0 field handling — the five named BIP-370 v2-only
# input fields must each carry an explicit REJECT row; unknown and
# proprietary fields must be policy-rejected in every scope; full-key
# (not key-type) uniqueness must be stated.
for f in 'PSBT_IN_PREVIOUS_TXID 0x0e' 'PSBT_IN_OUTPUT_INDEX 0x0f' \
  'PSBT_IN_SEQUENCE 0x10' 'PSBT_IN_REQUIRED_TIME_LOCKTIME 0x11' \
  'PSBT_IN_REQUIRED_HEIGHT_LOCKTIME 0x12'; do
  grep -F "| $f (v2-only) | PROPOSED REJECT |" "$DRAFT" >/dev/null \
    || err "$DRAFT missing explicit REJECT row for v2-only input field: $f"
done
for scope in 'global scope' 'input scope' 'output scope'; do
  grep -F "Unregistered/unrecognized key types ($scope) | PROPOSED REJECT" "$DRAFT" >/dev/null \
    || err "$DRAFT missing unregistered/unrecognized-key REJECT row for $scope"
done
# Closed-world allowlist: the exact default-deny row must appear once
# per scope (exactly 3 times), and the old 'Unknown key types' catch-all
# row form must be gone. Count via grep -c, rc-checked, no pipeline.
cwrow='| Every key type not explicitly allowed by this profile, whether registered/known or unrecognized (closed-world default) | PROPOSED REJECT |'
cwcount=$(grep -cF "$cwrow" "$DRAFT") \
  || err "$DRAFT missing the closed-world default-deny row (grep -c failed or zero)"
[ "$cwcount" -eq 3 ] || err "closed-world default-deny row count is $cwcount, expected exactly 3 (one per scope)"
forbid "$DRAFT still uses the 'Unknown key types' catch-all row form" \
  -F '| Unknown key types (' "$DRAFT"
# Representative registered-but-unsupported fields, exact registry
# names and type values from the pinned type-registry commit, each an
# explicit profile-ineligible REJECT row.
for f in 'PSBT_GLOBAL_SP_ECDH_SHARE 0x07' 'PSBT_GLOBAL_SP_DLEQ 0x08' \
  'PSBT_GLOBAL_GENERIC_SIGNED_MESSAGE 0x09' 'PSBT_IN_POR_COMMITMENT 0x09' \
  'PSBT_IN_MUSIG2_PARTICIPANT_PUBKEYS 0x1a' 'PSBT_IN_MUSIG2_PUB_NONCE 0x1b' \
  'PSBT_IN_MUSIG2_PARTIAL_SIG 0x1c' 'PSBT_IN_SP_ECDH_SHARE 0x1d' \
  'PSBT_IN_SP_DLEQ 0x1e' 'PSBT_IN_SP_SPEND_BIP32_DERIVATION 0x1f' \
  'PSBT_IN_SP_TWEAK 0x20' 'PSBT_OUT_MUSIG2_PARTICIPANT_PUBKEYS 0x08' \
  'PSBT_OUT_SP_V0_INFO 0x09' 'PSBT_OUT_SP_V0_LABEL 0x0a' \
  'PSBT_OUT_DNSSEC_PROOF 0x35'; do
  grep -F "| Registered-but-unsupported: $f | PROPOSED REJECT (registered/valid generally; profile-ineligible) |" "$DRAFT" >/dev/null \
    || err "$DRAFT missing registered-but-unsupported REJECT row: $f"
done
grep -F 'not malformed in the standard' "$DRAFT" >/dev/null \
  || err "$DRAFT missing the registered/valid-generally vs profile-ineligible distinction"
grep -F 'same key type' "$DRAFT" >/dev/null \
  || err "$DRAFT missing the same-key-type/distinct-keydata uniqueness statement"
grep -F 'malformed 0xFC is never called valid' "$DRAFT" >/dev/null \
  || err "$DRAFT missing the malformed-0xFC statement"
forbid "$DRAFT still uses a PRESERVE-OPAQUE disposition (v1 candidate must reject)" \
  -F 'PROPOSED PRESERVE-OPAQUE' "$DRAFT"
# C: owner-directed D-01 prevout policy with exact validation wording;
# the false 'matches witness_utxo exactly' phrase is forbidden and the
# superseded both-UTXO requirement must be gone.
grep -F "output's amount and scriptPubKey as the EFFECTIVE PREVOUT" "$DRAFT" >/dev/null \
  || err "$DRAFT missing the D-01 effective-prevout derivation wording"
grep -F '`witness_utxo` is OPTIONAL-VALIDATE: its ABSENCE' "$DRAFT" >/dev/null \
  || err "$DRAFT missing the D-01 witness_utxo OPTIONAL-VALIDATE/absence-not-rejection wording"
forbid "$DRAFT still requires BOTH witness_utxo AND non_witness_utxo" \
  -F 'require BOTH `witness_utxo` AND `non_witness_utxo`' "$DRAFT"
forbid "$DRAFT still frames prevout policy as the both-UTXO candidate" \
  -F 'both-UTXO' "$DRAFT"
grep -F 'repeated-signing fee' "$DRAFT" >/dev/null \
  || err "$DRAFT missing the repeated-signing fee attack rationale"
grep -F 'double-SHA256' "$DRAFT" >/dev/null \
  || err "$DRAFT missing the txid recomputation wording"
grep -F 'never the wtxid and never a hash of' "$DRAFT" >/dev/null \
  || err "$DRAFT missing the standard-txid-not-wtxid wording"
grep -F 'non-witness (stripped) serialization' "$DRAFT" >/dev/null \
  || err "$DRAFT missing the stripped-serialization txid basis"
grep -F 'bounds-check the' "$DRAFT" >/dev/null \
  || err "$DRAFT missing the vout bounds-check wording"
grep -F 'validated indexed output of the supplied full' "$DRAFT" >/dev/null \
  || err "$DRAFT missing the validated-indexed-output derivation wording"
forbid "$DRAFT claims a full previous transaction matches witness_utxo exactly" \
  -iE 'match(es)? witness_utxo exactly' "$DRAFT"
forbid "$DRAFT calls a pre-signature fee rate exact" \
  -iE 'exact fee[- ]?rate|fee[- ]?rate is exact' "$DRAFT"
# D/E: arithmetic/money-range clause, approval binding, allowed-delta,
# narrowed oracle and limit wording.
grep -F 'monetary range at every computation and comparison' "$DRAFT" >/dev/null \
  || err "$DRAFT missing the checked-arithmetic/monetary-range clause wording"
grep -F 'overflow or underflow' "$DRAFT" >/dev/null \
  || err "$DRAFT missing fail-closed overflow wording"
for bnd in QK-REQ-BND-001 QK-REQ-BND-002 QK-REQ-BND-003; do
  grep -F "$bnd" "$DRAFT" >/dev/null \
    || err "$DRAFT does not trace $bnd"
done
grep -F 'allowed-delta rule' "$DRAFT" >/dev/null \
  || err "$DRAFT missing the signer allowed-delta rule"
grep -F 'MUST accept only the exact two newly created signature records per' "$DRAFT" >/dev/null \
  || err "$DRAFT missing the D-03 output-reparse exact-two-records rule"
grep -F 'computed BEFORE any parsing re-encoding, map reordering, CompactSize normalization, or serialization' "$DRAFT" >/dev/null \
  || err "$DRAFT missing the original-bytes-before-reencoding digest definition"
grep -F 'not the imported-bytes digest' "$DRAFT" >/dev/null \
  || err "$DRAFT missing the reserialized-digest disqualification"
grep -F 'each input map index and each output map index' "$DRAFT" >/dev/null \
  || err "$DRAFT missing the explicit index-binding commitment wording"
grep -F 'NON-SECRET identifiers or domain-separated' "$DRAFT" >/dev/null \
  || err "$DRAFT missing the non-secret identity commitment wording"
grep -F 'limited decode/interoperability oracle only' "$DRAFT" >/dev/null \
  || err "$DRAFT missing the narrowed decodepsbt oracle wording"
grep -F 'not rejected solely by that limit' "$DRAFT" >/dev/null \
  || err "$DRAFT missing the narrowed at/below-limit wording"
# A: P2TR recipient exclusion scope.
grep -F 'P2TR recipient outputs are EXCLUDED' "$DRAFT" >/dev/null \
  || err "$DRAFT missing the v1 P2TR recipient exclusion"
grep -F 'separate architecture-owner' "$DRAFT" >/dev/null \
  || err "$DRAFT missing the architecture-owner amendment requirement for P2TR"
# F: BND-001 agreement precondition — enforced fail-closed semantics,
# not mere binding, plus its dedicated mismatch plan row.
grep -F 'BEFORE review-object construction/approval and again BEFORE signing' "$DRAFT" >/dev/null \
  || err "$DRAFT missing the BND-001 before-approval/before-signing agreement precondition"
grep -F 'comparison material or ANY mismatch MUST fail' "$DRAFT" >/dev/null \
  || err "$DRAFT missing the BND-001 missing-material/mismatch fail-closed wording"
grep -F 'A stable mismatch is still fatal' "$DRAFT" >/dev/null \
  || err "$DRAFT missing the stable-mismatch-is-fatal wording"
grep -F 'QK-F3-PLAN-066' "$DRAFT" >/dev/null \
  || err "$DRAFT missing the factor-agreement mismatch plan row QK-F3-PLAN-066"
# F: owner-directed D-12 sequence display — PRESENT/ABSENT encoding
# facts required; the retired OPEN-phase literal and stale
# implication/show-signaling phrasing forbidden.
grep -F 'strictly as PRESENT or ABSENT and MUST NOT be presented as' "$DRAFT" >/dev/null \
  || err "$DRAFT missing the D-12 PRESENT/ABSENT BIP125 encoding display rule"
forbid "$DRAFT still carries the retired 'replacement policy not evaluated' literal" \
  -F 'replacement policy not evaluated' "$DRAFT"
forbid "$DRAFT still derives a replacement-signaling implication" \
  -F 'with its replacement-signaling implication' "$DRAFT"
forbid "$DRAFT still shows replacement signaling while OPEN" \
  -F 'replacement signaling shown' "$DRAFT"
grep -F '| D-12 |' "$DRAFT" >/dev/null \
  || err "$DRAFT missing decision-packet item D-12"
# F: minimum unsigned-transaction admissibility rules and plans; the
# no-consensus-overclaim disclaimer must be present.
grep -F 'at least one input and at least one output' "$DRAFT" >/dev/null \
  || err "$DRAFT missing the nonempty vin/vout admissibility rule"
grep -F 'every input outpoint MUST be non-null' "$DRAFT" >/dev/null \
  || err "$DRAFT missing the non-null outpoint admissibility rule"
grep -F 'coinbase-form unsigned' "$DRAFT" >/dev/null \
  || err "$DRAFT missing the coinbase-form rejection rule"
grep -F 'no two inputs may spend the same' "$DRAFT" >/dev/null \
  || err "$DRAFT missing the duplicate-outpoint rejection rule"
grep -F 'exhaustive Bitcoin transaction or consensus validation' "$DRAFT" >/dev/null \
  || err "$DRAFT missing the admissibility no-overclaim disclaimer"
for p in QK-F3-PLAN-067 QK-F3-PLAN-068 QK-F3-PLAN-069 QK-F3-PLAN-070; do
  grep -F "$p" "$DRAFT" >/dev/null \
    || err "$DRAFT missing inner-transaction admissibility plan row $p"
done
# F: accepted typed-field encoding validation clause and per-scope
# plan rows.
grep -F '**QK-F3-PSBT-034**' "$DRAFT" >/dev/null \
  || err "$DRAFT missing the accepted typed-field encoding clause QK-F3-PSBT-034"
grep -F 'full value consumption' "$DRAFT" >/dev/null \
  || err "$DRAFT missing the full-value-consumption typed-field wording"
grep -F 'field REJECTS' "$DRAFT" >/dev/null \
  || err "$DRAFT missing the malformed-accepted-type reject wording"
for p in QK-F3-PLAN-071 QK-F3-PLAN-072 QK-F3-PLAN-073 QK-F3-PLAN-074; do
  grep -F "$p" "$DRAFT" >/dev/null \
    || err "$DRAFT missing typed-field/inner-transaction plan row $p"
done
# F3.1a correction checks (heuristic supporting evidence, never proof
# and never acceptance): every phrase below must exist verbatim on one
# line of the corrected draft.
for phrase in \
  'MUST be exactly native P2WSH: the 34-byte' \
  'full chain D → all three derived keys at one common' \
  'derivation records alone NEVER' \
  'descriptor branch/index coordinate and match D at that' \
  'MUST be a strict-DER ECDSA signature per' \
  'Bitcoin Core standardness/relay policy alignment, not a consensus' \
  'during bounded map framing/key parsing' \
  'P2PKH, P2SH, P2WPKH, and P2WSH; every other recipient script class' \
  'prevout committed by the supplied full transaction and' \
  'the masked low 16 bits of nSequence' \
  'nLockTime finality' \
  'INTERPRET-AND-DISPLAY' \
  'retained exact imported byte' \
  'MUST NOT reread QR, SD,' \
  'MUST preserve every pre-existing accepted byte' \
  '2,100,000,000,000,000 satoshis inclusive' \
  'The profile MUST NOT be accepted until' \
  'QK-TST IDs through separately authorized canonical edits' \
  'Mapping' \
  'full-prevtx-committed' \
  'is a TRANSACTION-LEVEL field, never per-input' \
  'nLockTime=0 means no' \
  'height-class and values at or above 500,000,000 are time-class' \
  'strict less-than comparison' \
  'the prior-block median time past' \
  'ignored ONLY when EVERY input has nSequence=0xffffffff' \
  'transaction-level absolute lock' \
  'blocks vs 512-second units' \
  'below 0xfffffffe; this is mempool policy, never consensus' \
  'INTERPRET-AND-DISPLAY the exact encoded facts with BIP125 encoding PRESENT/ABSENT only' \
  '0x00 0x20 <32-byte SHA256(witnessScript)>' \
  'one-byte direct-push opcode' \
  'outcome is CANNOT VERIFY FEE RATE and the PSBT is REJECTED before' \
  'an unproven fee rate is never an approvable outcome and' \
  'common branch/index mismatch' \
  'produced-signature-record' \
  '9–73 bytes; strict low-S reduces the MAXIMUM to' \
  'Readiness/Status' \
  'OWNER DIRECTION RECORDED — CLAUSE REMAINS PROPOSED — PROFILE NOT ACCEPTED' \
  ; do
  grep -F "$phrase" "$DRAFT" >/dev/null \
    || err "$DRAFT missing required F3.1a correction phrase: $phrase"
done
forbid "$DRAFT still claims the whole candidate bundle is the default recommendation" \
  -F 'default recommendation is the candidate bundle' "$DRAFT"
# F3.1a semantics negative checks: stale/incorrect wording must be gone.
forbid "$DRAFT still contains the incorrect per-input locktime-disable claim" \
  -F 'locktime enforcement for that input' "$DRAFT"
forbid "$DRAFT still allows an ESTIMATE fee-rate status" \
  -F 'ESTIMATE' "$DRAFT"
forbid "$DRAFT still uses the loose authenticated-prevout mismatch class" \
  -F 'reject: authenticated prevout/P2WSH commitment mismatch' "$DRAFT"
grep -F '| D-00 |' "$DRAFT" >/dev/null \
  || err "$DRAFT missing decision-packet item D-00"
# F3.1a/F3.1b source-register rows: fail-closed COMPLETE-LITERAL-FULL-ROW
# checks plus resource uniqueness. For each of the 19 rows the helper
# requires (1) the resource selector — the backticked filename/path
# token ONLY, deliberately independent of the mutable leading
# source-label cell, spacing, or table formatting — to occur exactly
# ONCE in SOURCE-REGISTER, so a second conflicting row for the same
# file fails regardless of how its source label is written, and (2) the COMPLETE
# literal Markdown row — from its initial pipe through its final
# closing pipe, including leading source cell, filename, exact 40-hex
# pin, exact license, complete purpose, and complete status — to match
# exactly one whole line via POSIX grep -Fxc. No substring, regex, or
# phrase-count shortcut. rc 0/1/>1 are distinguished explicitly.
# Supporting lexical/shape evidence only, never semantic proof.
exact_row() {
  # $1 = label, $2 = filename/path-only resource selector, $3 = complete literal row
  selcount=$(grep -cF "$2" docs/SOURCE-REGISTER.md)
  selrc=$?
  [ "$selrc" -le 1 ] || err "SOURCE-REGISTER resource scan failed for $1 (grep exit $selrc)"
  [ "$selcount" = "1" ] || err "SOURCE-REGISTER resource $1 does not occur on exactly one source-table row (found $selcount)"
  rowcount=$(grep -Fxc "$3" docs/SOURCE-REGISTER.md)
  rowrc=$?
  [ "$rowrc" -le 1 ] || err "SOURCE-REGISTER full-row scan failed for $1 (grep exit $rowrc)"
  [ "$rowcount" = "1" ] || err "SOURCE-REGISTER row for $1 does not match the complete literal expected row exactly once (found $rowcount)"
}
exact_row 'bip-0174/type-registry' \
  '`bip-0174/type-registry.mediawiki`' \
  '| bitcoin/bips — `bip-0174/type-registry.mediawiki` | `857a7debc6625a3dadbaecee1ee7b2ed5e8ada75` | No per-file license declaration at this commit; citation-only; no text/code imported; no license inferred | F3.1 citation-only reference for PSBT field/type identifiers (including v2-only input types 0x0e–0x12 and proprietary type 0xFC). Nothing imported. | Citation-only remote review at the pinned commit; nothing imported. |'
exact_row 'BIP 66' \
  '`bip-0066.mediawiki`' \
  '| bitcoin/bips — `bip-0066.mediawiki` | `857a7debc6625a3dadbaecee1ee7b2ed5e8ada75` | BSD-2-Clause (per the BIP 66 preamble at this commit) | F3.1a citation-only reference for strict DER signature encoding rules. Nothing imported. | Citation-only remote review at the pinned commit; nothing imported. |'
exact_row 'BIP 68' \
  '`bip-0068.mediawiki`' \
  '| bitcoin/bips — `bip-0068.mediawiki` | `857a7debc6625a3dadbaecee1ee7b2ed5e8ada75` | No per-file license declaration at this commit; citation-only; no text/code imported; no license inferred | F3.1a citation-only reference for relative lock-time encoding (version threshold, disable bit 31, type bit 22, masked value). Nothing imported. | Citation-only remote review at the pinned commit; nothing imported. |'
exact_row 'BIP 113' \
  '`bip-0113.mediawiki`' \
  '| bitcoin/bips — `bip-0113.mediawiki` | `857a7debc6625a3dadbaecee1ee7b2ed5e8ada75` | PD (per the pinned BIP preamble) | F3.1a citation-only reference for median-time-past locktime context in the time/lock semantics family. Nothing imported. | Citation-only remote review at the pinned commit; nothing imported. |'
exact_row 'BIP 125' \
  '`bip-0125.mediawiki`' \
  '| bitcoin/bips — `bip-0125.mediawiki` | `857a7debc6625a3dadbaecee1ee7b2ed5e8ada75` | PD (per the pinned BIP preamble) | F3.1a citation-only reference for opt-in replacement signaling as mempool signaling only, never a network replaceability guarantee. Nothing imported. | Citation-only remote review at the pinned commit; nothing imported. |'
exact_row 'BIP 141' \
  '`bip-0141.mediawiki`' \
  '| bitcoin/bips — `bip-0141.mediawiki` | `857a7debc6625a3dadbaecee1ee7b2ed5e8ada75` | PD (per the pinned BIP preamble) | F3.1a citation-only reference for the native P2WSH witness program form (OP_0 plus 32-byte SHA256 program) and weight/vsize definitions. Nothing imported. | Citation-only remote review at the pinned commit; nothing imported. |'
exact_row 'amount.h' \
  '`src/consensus/amount.h`' \
  '| bitcoin/bitcoin — `src/consensus/amount.h` | `15a7a4ed7c4d0952ce966087e55a9a3e2f28ec1d` | MIT (repository COPYING at this commit) | F3.1a citation-only reference for the MoneyRange bound of 0..2,100,000,000,000,000 satoshis inclusive. No code imported. | Citation-only remote review at the pinned commit; nothing imported. |'
exact_row 'policy.h' \
  '`src/policy/policy.h`' \
  '| bitcoin/bitcoin — `src/policy/policy.h` | `15a7a4ed7c4d0952ce966087e55a9a3e2f28ec1d` | MIT (repository COPYING at this commit) | F3.1a citation-only reference distinguishing standardness/relay policy (including low-S) from consensus. No code imported. | Citation-only remote review at the pinned commit; nothing imported. |'
exact_row 'tx_verify.cpp' \
  '`src/consensus/tx_verify.cpp`' \
  '| bitcoin/bitcoin — `src/consensus/tx_verify.cpp` | `15a7a4ed7c4d0952ce966087e55a9a3e2f28ec1d` | MIT (repository COPYING at this commit) | F3.1a citation-only reference narrowly for IsFinalTx nLockTime finality, BIP68 sequence-lock evaluation, and CheckTxInputs value/fee checks. No code imported. | Citation-only remote review at the pinned commit; nothing imported. |'
exact_row 'tx_check.cpp' \
  '`src/consensus/tx_check.cpp`' \
  '| bitcoin/bitcoin — `src/consensus/tx_check.cpp` | `15a7a4ed7c4d0952ce966087e55a9a3e2f28ec1d` | MIT (repository COPYING at this commit) | F3.1a citation-only reference for context-free structural checks: empty vin/vout, null/coinbase-form outpoint, and duplicate-input detection. No code imported. | Citation-only remote review at the pinned commit; nothing imported. |'
exact_row 'script.h' \
  '`src/script/script.h`' \
  '| bitcoin/bitcoin — `src/script/script.h` | `15a7a4ed7c4d0952ce966087e55a9a3e2f28ec1d` | MIT (repository COPYING at this commit) | F3.1a citation-only reference for LOCKTIME_THRESHOLD 500,000,000 only. No code imported. | Citation-only remote review at the pinned commit; nothing imported. |'
exact_row 'primitives/transaction.h' \
  '`src/primitives/transaction.h`' \
  '| bitcoin/bitcoin — `src/primitives/transaction.h` | `15a7a4ed7c4d0952ce966087e55a9a3e2f28ec1d` | MIT (repository COPYING at this commit) | F3.1a citation-only reference limited to SEQUENCE_FINAL, MAX_SEQUENCE_NONFINAL, SEQUENCE_LOCKTIME_DISABLE_FLAG, SEQUENCE_LOCKTIME_TYPE_FLAG, SEQUENCE_LOCKTIME_MASK, and the sequence granularity/constants used by the time/lock draft. Nothing imported. | Citation-only remote review at the pinned commit; nothing imported. |'
exact_row 'solver.cpp' \
  '`src/script/solver.cpp`' \
  '| bitcoin/bitcoin — `src/script/solver.cpp` | `15a7a4ed7c4d0952ce966087e55a9a3e2f28ec1d` | MIT (repository COPYING at this commit) | F3.1a citation-only reference for canonical standard script template classification (P2PKH/P2SH/P2WPKH/P2WSH) relevant to the proposed D-05 allowlist. No code imported. | Citation-only remote review at the pinned commit; nothing imported. |'
exact_row 'BIP 341' \
  '`bip-0341.mediawiki`' \
  '| bitcoin/bips — `bip-0341.mediawiki` | `857a7debc6625a3dadbaecee1ee7b2ed5e8ada75` | BSD-3-Clause (per the pinned BIP preamble) | F3.1b Revision 2 citation-only rationale for the FUTURE recipient-only P2TR direction (D-05). No Taproot signing, no Taproot capability, no text/code/vectors imported. | Citation-only remote review at the pinned commit; nothing imported. |'
exact_row 'BIP 350' \
  '`bip-0350.mediawiki`' \
  '| bitcoin/bips — `bip-0350.mediawiki` | `857a7debc6625a3dadbaecee1ee7b2ed5e8ada75` | BSD-2-Clause (per the pinned BIP preamble) | F3.1b Revision 2 citation-only rationale for FUTURE Bech32m v1–v16 witness-address rendering/vector work only. Nothing imported; no runtime capability. | Citation-only remote review at the pinned commit; nothing imported. |'
exact_row 'BIP 431' \
  '`bip-0431.mediawiki`' \
  '| bitcoin/bips — `bip-0431.mediawiki` | `857a7debc6625a3dadbaecee1ee7b2ed5e8ada75` | BSD-3-Clause (per the pinned BIP preamble; Status Draft, Type Informational — never cited as consensus) | F3.1b Revision 2 citation-only rationale for v3/TRUC transaction rejection in the v1 profile and for a separately reviewed future v3 extension profile. Nothing imported. | Citation-only remote review at the pinned commit; nothing imported. |'
exact_row 'release-notes-28.0.md' \
  '`doc/release-notes/release-notes-28.0.md`' \
  '| bitcoin/bitcoin — `doc/release-notes/release-notes-28.0.md` | `15a7a4ed7c4d0952ce966087e55a9a3e2f28ec1d` | MIT (repository COPYING at this commit) | F3.1b Revision 2 citation-only context for the Bitcoin Core v28 deployment of v3/TRUC transaction policy. No code imported; never a network guarantee. | Citation-only remote review at the pinned commit; nothing imported. |'
exact_row 'mempool-replacements.md' \
  '`doc/policy/mempool-replacements.md`' \
  '| bitcoin/bitcoin — `doc/policy/mempool-replacements.md` | `15a7a4ed7c4d0952ce966087e55a9a3e2f28ec1d` | MIT (repository COPYING at this commit) | F3.1b Revision 2 citation-only context for current replacement-policy/full-RBF behavior as node policy only — never a network replaceability guarantee. No code imported. | Citation-only remote review at the pinned commit; nothing imported. |'
exact_row 'BIP 143' \
  '`bip-0143.mediawiki`' \
  '| bitcoin/bips — `bip-0143.mediawiki` | `857a7debc6625a3dadbaecee1ee7b2ed5e8ada75` | PD (per the pinned BIP preamble; Status Deployed, Type Specification, Layer Consensus (soft fork)) | F3.1b Revision 2 citation-only reference for SegWit-v0 signature-digest semantics: the digest commits to the 8-byte value of the output spent by the input; for native P2WSH, scriptCode is the witnessScript serialized as a script inside CTxOut when it contains no OP_CODESEPARATOR, otherwise it is the witnessScript suffix after and excluding the last executed OP_CODESEPARATOR before the signature-checking opcode, serialized the same way. Nothing imported. | Citation-only remote review at the pinned commit; nothing imported. |'
for fb in 'BSD-2-Clause (per the BIP 68 preamble' \
  'BSD-2-Clause (per the BIP 113 preamble' \
  'BSD-2-Clause (per the BIP 125 preamble' \
  'BSD-2-Clause (per the BIP 141 preamble'; do
  forbid "SOURCE-REGISTER still carries a false BSD classification: $fb" \
    -F "$fb" docs/SOURCE-REGISTER.md
done
forbid "SOURCE-REGISTER still overclaims general transaction admissibility for tx_verify.cpp" \
  -F 'reference for transaction admissibility' docs/SOURCE-REGISTER.md
forbid "SOURCE-REGISTER script.h row still falsely claims nSequence constant definitions" \
  -F 'LOCKTIME_THRESHOLD 500,000,000 and nSequence constant' docs/SOURCE-REGISTER.md
# F3.1b Revision 2 owner-directed policy checks (heuristic supporting
# evidence, never proof and never acceptance).
# D-01: effective-prevout policy; witness_utxo-absence never a
# rejection reason; corrected BIP143 provenance: amount from the
# effective prevout, scriptCode the descriptor-derived witnessScript
# serialized inside CTxOut (no OP_CODESEPARATOR in the fixed
# template), never both "from the effective prevout".
grep -F 'ABSENCE' "$DRAFT" >/dev/null \
  || err "$DRAFT missing the D-01 absence-is-not-rejection emphasis"
grep -F 'the 8-byte amount digest field comes from the EFFECTIVE' "$DRAFT" >/dev/null \
  || err "$DRAFT missing the corrected BIP143 amount-provenance wording"
grep -F 'exact descriptor-derived and validated witnessScript serialized as a' "$DRAFT" >/dev/null \
  || err "$DRAFT missing the corrected BIP143 scriptCode-provenance wording"
grep -F 'OP_CODESEPARATOR' "$DRAFT" >/dev/null \
  || err "$DRAFT missing the fixed-template no-OP_CODESEPARATOR statement"
grep -F 'effective-prevout P2WSH scriptPubKey' "$DRAFT" >/dev/null \
  || err "$DRAFT missing the witnessScript-SHA256-commitment wording"
forbid "$DRAFT still claims amount and scriptCode both come from the effective prevout" \
  -F 'digest inputs (amount and scriptCode) come from' "$DRAFT"
forbid "$DRAFT still rejects for a missing witness_utxo" \
  -F 'input missing witness_utxo' "$DRAFT"
# D-03: import-stage rejection before card access; exact pair; exactly
# two produced signatures; single SIGN pass; no partial export.
grep -F 'REJECTS at import, BEFORE any' "$DRAFT" >/dev/null \
  || err "$DRAFT missing the D-03 import-stage pre-card rejection rule"
grep -F 'exactly two signatures are created per' "$DRAFT" >/dev/null \
  || err "$DRAFT missing the D-03 exactly-two-signatures rule"
grep -F 'at most one SIGN invocation is permitted per' "$DRAFT" >/dev/null \
  || err "$DRAFT missing the D-03 single-SIGN-pass rule"
grep -F 'NO one-signature/intermediate signed PSBT or other incomplete' "$DRAFT" >/dev/null \
  || err "$DRAFT missing the D-03 no-incomplete-artifact rule"
forbid "$DRAFT still uses the contradictory 'NO partial PSBT' phrasing" \
  -F 'NO partial PSBT' "$DRAFT"
grep -F 'no third or out-of-pair' "$DRAFT" >/dev/null \
  || err "$DRAFT missing the selected-pair no-third-signature rule"
grep -F 'reject missing, foreign, third,' "$DRAFT" >/dev/null \
  || err "$DRAFT missing the output-exact-pair rejection enumeration"
forbid "$DRAFT still validates-and-counts incoming partial signatures" \
  -F 'Existing partial signatures are allowed' "$DRAFT"
forbid "$DRAFT still leaves the already-threshold-signed policy open" \
  -F 'already threshold-signed PSBT is D-03 OPEN' "$DRAFT"
# D-08: four exact review totals, checked identity, proven range only.
grep -F 'proven descriptor-owned outputs = not-proven-owned outputs + fee' "$DRAFT" >/dev/null \
  || err "$DRAFT missing the D-08 conservative-wallet-debit checked identity"
grep -F 'the exact not-proven-owned output total' "$DRAFT" >/dev/null \
  || err "$DRAFT missing the not-proven-owned output total review fact"
grep -F 'debit is an upper bound on the actual economic' "$DRAFT" >/dev/null \
  || err "$DRAFT missing the conservative-wallet-debit upper-bound statement"
forbid "$DRAFT still overclaims an exact external-recipient total" \
  -F 'exact external-recipient total' "$DRAFT"
forbid "$DRAFT still overclaims an exact net outflow" \
  -F 'exact net outflow' "$DRAFT"
forbid "$DRAFT still carries the stale external+fee identity" \
  -F 'external-recipient total + fee' "$DRAFT"
grep -F 'CANNOT VERIFY FEE RATE' "$DRAFT" >/dev/null \
  || err "$DRAFT missing the D-08 CANNOT VERIFY FEE RATE rejection"
forbid "$DRAFT still allows an approvable UNAVAILABLE fee-rate status" \
  -F 'RANGE versus UNAVAILABLE' "$DRAFT"
forbid "$DRAFT still frames D-08 as RANGE-or-UNAVAILABLE" \
  -F 'RANGE or UNAVAILABLE' "$DRAFT"
# D-12: version eligibility and PRESENT/ABSENT-only presentation.
grep -F 'UNSUPPORTED TRANSACTION POLICY' "$DRAFT" >/dev/null \
  || err "$DRAFT missing the D-12 unsupported-version rejection reason"
grep -F 'nVersion exactly 1 or exactly 2 is eligible' "$DRAFT" >/dev/null \
  || err "$DRAFT missing the D-12 version-eligibility rule"
forbid "$DRAFT still presents replaceability as a yes/no fact" \
  -F 'replaceable: yes' "$DRAFT"
forbid "$DRAFT still accepts transaction version 3" \
  -F 'version 3 is eligible' "$DRAFT"
# F3.1b Revision 2 CORRECTION pass (reconstructed B'): section-6 truth,
# derivation-boundary honesty, output-ownership classes, complete
# fee-range weight accounting, D-03/D-10 stage boundary, route
# availability, record-level delta, qualified taxonomy, plan-class
# honesty, D-00 readiness, and P2TR/nonce boundaries. All supporting
# lexical evidence only, never proof and never acceptance.
grep -F 'remains PROPOSED/NON-NORMATIVE and the' "$DRAFT" >/dev/null \
  || err "$DRAFT section 6 missing the corrected proposed/non-normative preamble"
forbid "$DRAFT section 6 still claims nothing was owner-decided" \
  -F 'has been owner-decided' "$DRAFT"
grep -F 'a PROPOSED, open descriptor/QK-LIM' "$DRAFT" >/dev/null \
  || err "$DRAFT missing the corrected derivation-boundary dependency wording"
forbid "$DRAFT still misattributes the derivation boundary to a D-08 family" \
  -F 'D-08 boundary family' "$DRAFT"
grep -F 'not-proven-owned / treated as' "$DRAFT" >/dev/null \
  || err "$DRAFT missing the not-proven-owned ownership class"
grep -F 'NOT a claim' "$DRAFT" >/dev/null \
  || err "$DRAFT missing the not-economically-external clarification"
grep -F 'exclusive and exhaustive' "$DRAFT" >/dev/null \
  || err "$DRAFT missing the mutually-exclusive ownership classification rule"
grep -F 'marker 0x00 and flag 0x01 exactly' "$DRAFT" >/dev/null \
  || err "$DRAFT missing the SegWit marker/flag exactly-once weight rule"
grep -F 'they contribute 2 WU and must never be omitted' "$DRAFT" >/dev/null \
  || err "$DRAFT missing the marker/flag 2-WU never-omitted statement"
grep -F 'item count and every CompactSize/item byte' "$DRAFT" >/dev/null \
  || err "$DRAFT missing the witness-vector CompactSize/item accounting rule"
grep -F 'zero-length dummy' "$DRAFT" >/dev/null \
  || err "$DRAFT missing the four-stack-item witness template enumeration"
grep -F 'ARTIFACT required by QK-REQ-TRN-007' "$DRAFT" >/dev/null \
  || err "$DRAFT missing the QK-REQ-TRN-007 unfinalized-artifact definition"
grep -F 'D-10/OD-05 OPEN and is wholly unspecified here' "$DRAFT" >/dev/null \
  || err "$DRAFT missing the open D-10 finalization boundary statement"
grep -F 'MUST be AVAILABLE over both' "$DRAFT" >/dev/null \
  || err "$DRAFT missing the route-availability (not simultaneous-emission) rule"
grep -F 'if both routes are selected, the exported bytes MUST' "$DRAFT" >/dev/null \
  || err "$DRAFT missing the identical-bytes rule for dual-route export"
forbid "$DRAFT still mandates export over each authorized route" \
  -F 'over each authorized route' "$DRAFT"
grep -F 'POSITION/ORDER of the new records is NOT a security predicate' "$DRAFT" >/dev/null \
  || err "$DRAFT missing the insertion-order non-predicate statement"
grep -F 'record encoding remains byte-identical in its original map and' "$DRAFT" >/dev/null \
  || err "$DRAFT missing the record-level byte-preservation predicate"
grep -F 'produced-signature malformed/non-strict-DER' "$DRAFT" >/dev/null \
  || err "$DRAFT missing the qualified produced-signature DER taxonomy entry"
grep -F 'produced-signature high-S policy failure' "$DRAFT" >/dev/null \
  || err "$DRAFT missing the qualified produced-signature high-S taxonomy entry"
grep -F 'by PRESENCE and never parses' "$DRAFT" >/dev/null \
  || err "$DRAFT missing the import presence-only (no DER/S parsing) statement"
forbid "$DRAFT still carries the unqualified DER-encoding taxonomy literal" \
  -F 'malformed/non-strict DER signature encoding;' "$DRAFT"
forbid "$DRAFT still carries the unqualified high-S taxonomy literal" \
  -F 'high-S proposed-policy rejection' "$DRAFT"
grep -F 'The Class vocabulary is finite and' "$DRAFT" >/dev/null \
  || err "$DRAFT missing the finite closed plan-class vocabulary"
for mpid in QK-F3-PLAN-034 QK-F3-PLAN-084 QK-F3-PLAN-085 QK-F3-PLAN-088; do
  grep -F "| $mpid " "$DRAFT" > "$tmpdir/mixrow.$mpid"
  mrc=$?
  [ "$mrc" -le 1 ] || err "mixed-class row extraction failed for $mpid (grep exit $mrc)"
  grep -F '| mixed/table-driven boundary (positive + adversarial) |' "$tmpdir/mixrow.$mpid" >/dev/null \
    || err "$DRAFT $mpid row is not classed mixed/table-driven boundary"
done
grep -F 'not rejected solely by QK-F3-PSBT-031 arithmetic/range' "$tmpdir/mixrow.QK-F3-PLAN-084" >/dev/null \
  || err "$DRAFT PLAN-084 row lacks the not-rejected-solely-by-031 qualification"
grep -F 'unprovable/checked-arithmetic-failure case' "$tmpdir/mixrow.QK-F3-PLAN-088" >/dev/null \
  || err "$DRAFT PLAN-088 row lacks the unprovable CANNOT VERIFY FEE RATE case"
grep -F 'BLOCKED — MUST NOT ACCEPT' "$DRAFT" >/dev/null \
  || err "$DRAFT D-00 row missing the BLOCKED / MUST NOT ACCEPT readiness status"
grep -F 'D-09 exact commitment construction; D-10 output/finalization choice' "$DRAFT" >/dev/null \
  || err "$DRAFT D-00 row missing the explicit prerequisite list"
grep -F '| D-00 | Base clause bundle acceptance' "$DRAFT" > "$tmpdir/d00row"
d0rc=$?
[ "$d0rc" -le 1 ] || err "D-00 row extraction failed (grep exit $d0rc)"
forbid "$DRAFT D-00 row still carries the misleading finite-proposed-candidate readiness" \
  -F 'finite proposed candidate' "$tmpdir/d00row"
grep -F 'neither RFC6979 nor any card nonce or anti-exfil' "$DRAFT" >/dev/null \
  || err "$DRAFT missing the nonce/anti-exfil non-selection boundary"
grep -F 'no anti-exfil claim is made' "$DRAFT" >/dev/null \
  || err "$DRAFT missing the explicit no-anti-exfil-claim statement"
grep -F 'requires a separate explicit architecture-owner amendment' "$DRAFT" >/dev/null \
  || err "$DRAFT missing the P2TR separate-amendment activation boundary"
grep -F 'still rejects P2TR everywhere' "$DRAFT" >/dev/null \
  || err "$DRAFT missing the present P2TR rejection statement"
grep -F 'Bech32m runtime capability' "$DRAFT" >/dev/null \
  || err "$DRAFT missing the no-Bech32m-runtime-capability statement"
# Final audit wording fixes: exhaustive README decision-status
# summary, byte-exact honesty, route-availability summaries, and the
# exact BIP141 weight equation in three scopes. Supporting lexical
# evidence only, never proof and never acceptance.
grep -F "D-00, D-02, D-04, D-06, D-07, D-09, D-10, and D-11 remain owner-open/structurally open as classified in the decision table; D-05's present-profile allowlist remains owner-open while only its FUTURE recipient-only P2TR direction is recorded" docs/f3/README.md >/dev/null \
  || err "docs/f3/README.md missing the exhaustive open-decision status summary"
forbid "docs/f3/README.md still carries the incomplete open-decision summary" \
  -F 'D-00, D-09 and D-11 remain open' docs/f3/README.md
grep -F 'No proposed byte-level rule is normative or frozen; no byte-exact vector or implementation artifact exists.' docs/f3/README.md >/dev/null \
  || err "docs/f3/README.md missing the corrected byte-exact honesty sentence"
forbid "docs/f3/README.md still carries the stale byte-exact sentence" \
  -F 'Nothing here is byte-exact or frozen.' docs/f3/README.md
grep -F 'signed-PSBT artifact availability over both approved capabilities' "$DRAFT" >/dev/null \
  || err "$DRAFT missing the route-availability summary phrasing"
forbid "$DRAFT still summarizes export over both routes" \
  -F 'signed-PSBT export over both routes' "$DRAFT"
fwcnt=$(grep -cF 'weight_min/max = 4 × stripped_size + 2 (SegWit marker+flag) +' "$DRAFT")
fw_rc=$?
[ "$fw_rc" -le 1 ] || err "weight-equation occurrence count failed (grep exit $fw_rc)"
[ "$fwcnt" = "3" ] || err "$DRAFT must state the BIP141 weight equation exactly three times (QK-022, section-12 D-08 method, PLAN-088); found $fwcnt"
grep -F 'in the checked formula' "$DRAFT" >/dev/null \
  || err "$DRAFT QK-F3-PSBT-022 missing its scoped weight-equation statement"
grep -F 'apply the checked formula' "$DRAFT" >/dev/null \
  || err "$DRAFT section-12 D-08 method missing its scoped weight-equation statement"
grep -F '| QK-F3-PLAN-088 ' "$DRAFT" > "$tmpdir/wrow.plan088"
wr_rc=$?
[ "$wr_rc" -le 1 ] || err "PLAN-088 weight-equation row extraction failed (grep exit $wr_rc)"
grep -F 'the checked formula weight_min/max = 4 × stripped_size + 2 (SegWit marker+flag) + witness_min/max' "$tmpdir/wrow.plan088" >/dev/null \
  || err "$DRAFT PLAN-088 row missing its scoped weight-equation statement"
grep -F 'EXCLUDES the marker/flag' "$DRAFT" >/dev/null \
  || err "$DRAFT missing the witness_min/max marker/flag exclusion definition"
# F3.1b Revision 2 plan-disposition rule: PLAN-056/085/086/087 must
# each carry the owner-directed D-12 disposition IN THEIR OWN exact
# row, with the retired OPEN-phase/Alternative language gone.
# Row-scoped, fail-closed; not a generic occurrence count.
for pid in QK-F3-PLAN-056 QK-F3-PLAN-085 QK-F3-PLAN-086 QK-F3-PLAN-087; do
  grep -F "| $pid " "$DRAFT" > "$tmpdir/planrow.$pid"
  prc=$?
  [ "$prc" -le 1 ] || err "plan-row extraction failed for $pid (grep exit $prc)"
  prcount=$(grep -cF "| $pid " "$tmpdir/planrow.$pid")
  prc=$?
  [ "$prc" -le 1 ] || err "plan-row count failed for $pid (grep exit $prc)"
  [ "$prcount" = "1" ] || err "$DRAFT does not contain exactly one row for $pid (found $prcount)"
  grep -F 'owner-directed D-12' "$tmpdir/planrow.$pid" >/dev/null \
    || err "$DRAFT $pid row lacks the owner-directed D-12 disposition"
  forbid "$DRAFT $pid row still carries the retired unresolved-D-12 disposition" \
    -F 'disposition follows unresolved D-12' "$tmpdir/planrow.$pid"
  forbid "$DRAFT $pid row still carries retired Alternative A/B phasing" \
    -F 'Alternative' "$tmpdir/planrow.$pid"
  forbid "$DRAFT $pid row still contains an unconditional accept disposition" \
    -F '| accept;' "$tmpdir/planrow.$pid"
done
# Revision 2 PLAN-056 owner-directed display facts.
grep -F 'BIP125 opt-in encoding strictly PRESENT/ABSENT' "$tmpdir/planrow.QK-F3-PLAN-056" >/dev/null \
  || err "$DRAFT PLAN-056 row lacks the PRESENT/ABSENT encoding-display clause"
grep -F 'actual/network replaceability UNKNOWN and never guaranteed' "$tmpdir/planrow.QK-F3-PLAN-056" >/dev/null \
  || err "$DRAFT PLAN-056 row lacks the replaceability-UNKNOWN clause"
grep -F 'raw-value fidelity always required' "$tmpdir/planrow.QK-F3-PLAN-056" >/dev/null \
  || err "$DRAFT PLAN-056 row lacks the raw-value fidelity clause"
# Revision 2 version-eligibility coverage in PLAN-085.
grep -F 'UNSUPPORTED TRANSACTION POLICY VERSION' "$tmpdir/planrow.QK-F3-PLAN-085" >/dev/null \
  || err "$DRAFT PLAN-085 row lacks the UNSUPPORTED TRANSACTION POLICY VERSION rejection"
grep -F '(nSequence below 0xfffffffe) distinguished' "$DRAFT" >/dev/null \
  || err "$DRAFT PLAN-087 does not distinguish direct BIP125 encoding from actual replaceability"
# G: exact decision-set verification — row-leading decision-table IDs
# must be exactly D-00..D-12, each exactly once, no gap/extra/dup.
grep -E '^\| D-[0-9]{2} \|' "$DRAFT" > "$tmpdir/decrows"
rc=$?
[ "$rc" -eq 0 ] || err "decision-row scan failed or found nothing (grep exit $rc)"
awk '/^\| D-[0-9][0-9]/ { print substr($0, 1, 6) }' \
  "$tmpdir/decrows" > "$tmpdir/declead"
rc=$?
[ "$rc" -eq 0 ] || err "decision lead-ID scan failed (awk exit $rc)"
[ -s "$tmpdir/declead" ] || err "decision lead-ID scan found nothing (exact-empty is a failure)"
awk '{ s = $0
  while (match(s, /D-[0-9][0-9]/)) {
    print substr(s, RSTART, RLENGTH)
    s = substr(s, RSTART + RLENGTH) } }' \
  "$tmpdir/declead" > "$tmpdir/decids.raw"
rc=$?
[ "$rc" -eq 0 ] || err "decision-ID extraction failed (awk exit $rc)"
[ -s "$tmpdir/decids.raw" ] || err "decision-ID extraction found nothing (exact-empty is a failure)"
LC_ALL=C sort "$tmpdir/decids.raw" > "$tmpdir/decids" \
  || err "decision-ID sort failed (fail-closed)"
: > "$tmpdir/decexp"
i=0
while [ "$i" -le 12 ]; do
  printf 'D-%02d\n' "$i" >> "$tmpdir/decexp" \
    || err "decision expected-list generation failed (fail-closed)"
  i=$((i+1))
done
cmp -s "$tmpdir/decexp" "$tmpdir/decids"
rc=$?
[ "$rc" -eq 0 ] || err "decision-ID set is not exactly D-00..D-12, each exactly once (cmp exit $rc)"
# G: allowed-field schema matrix — every allowed row must be present,
# and the exhaustive/sweep planning language must be explicit.
for row in 'GLOBAL: PSBT_GLOBAL_UNSIGNED_TX 0x00' \
  'GLOBAL: PSBT_GLOBAL_XPUB 0x01' 'GLOBAL: version field 0xFB' \
  'INPUT: PSBT_IN_NON_WITNESS_UTXO 0x00' 'INPUT: PSBT_IN_WITNESS_UTXO 0x01' \
  'INPUT: PSBT_IN_SIGHASH_TYPE 0x03' \
  'INPUT: PSBT_IN_WITNESS_SCRIPT 0x05' 'INPUT: PSBT_IN_BIP32_DERIVATION 0x06' \
  'OUTPUT: PSBT_OUT_WITNESS_SCRIPT 0x01' 'OUTPUT: PSBT_OUT_BIP32_DERIVATION 0x02'; do
  grep -F "| $row" "$DRAFT" >/dev/null \
    || err "$DRAFT allowed-field schema matrix missing row: $row"
done
grep -F 'table-driven exhaustive plan over the QK-F3-PSBT-034 allowed-field schema, GLOBAL scope' "$DRAFT" >/dev/null \
  || err "$DRAFT PLAN-071 is not a table-driven exhaustive global-scope plan"
grep -F 'table-driven exhaustive plan over the QK-F3-PSBT-034 allowed-field schema, INPUT scope' "$DRAFT" >/dev/null \
  || err "$DRAFT PLAN-072 is not a table-driven exhaustive input-scope plan"
grep -F 'table-driven exhaustive plan over the QK-F3-PSBT-034 allowed-field schema, OUTPUT scope' "$DRAFT" >/dev/null \
  || err "$DRAFT PLAN-073 is not a table-driven exhaustive output-scope plan"
cnt=$(grep -cF 'not merely representatives' "$DRAFT") \
  || err "$DRAFT missing the not-merely-representatives exhaustiveness wording"
[ "$cnt" -eq 3 ] || err "not-merely-representatives wording count is $cnt, expected exactly 3"
grep -F 'exhaustive sweep of EVERY matrix-enumerated registered MuSig2 field' "$DRAFT" >/dev/null \
  || err "$DRAFT PLAN-061 is not an exhaustive MuSig2 sweep"
grep -F 'exhaustive sweep of EVERY matrix-enumerated registered Silent Payments field' "$DRAFT" >/dev/null \
  || err "$DRAFT PLAN-062 is not an exhaustive Silent Payments sweep"
grep -F 'not-fully-consumed INNER unsigned-transaction value' "$DRAFT" >/dev/null \
  || err "$DRAFT missing the dedicated inner-transaction malformation plan wording"
# G: full changed-content material scan across the four named
# protocol/provenance/checker files below; replit.md is separately
# bounded elsewhere and is NOT scanned here (this loop does not cover
# all five content-commit paths). Supporting evidence only, never
# proof of absence. Patterns are
# written self-scan-safe (bracketed first character) so the literals in
# this authorized script do not match themselves.
for cf in "$DRAFT" docs/f3/README.md docs/SOURCE-REGISTER.md tools/verify-host-boundary.sh; do
  [ -f "$cf" ] || err "content-scan target missing: $cf"
  forbid "$cf contains PSBT magic hex" -E '[7]0736274' "$cf"
  forbid "$cf contains PSBT base64 magic" -E '[c]HNidP' "$cf"
  forbid "$cf contains xpub-like material" -E '[x]pub[1-9A-HJ-NP-Za-km-z]{20,}' "$cf"
  forbid "$cf contains xprv-like material" -E '[x]prv[1-9A-HJ-NP-Za-km-z]{20,}' "$cf"
  forbid "$cf contains WIF-like material" -E '(^|[^1-9A-HJ-NP-Za-km-z])[5KL][1-9A-HJ-NP-Za-km-z]{50,51}([^1-9A-HJ-NP-Za-km-z]|$)' "$cf"
  forbid "$cf contains bech32-address-like material" -E '(^|[^0-9a-z])[b]c1[02-9ac-hj-np-z]{20,}' "$cf"
  forbid "$cf contains suspicious 41+ hex run" -E '[0-9a-fA-F]{41,}' "$cf"
done
# G: exact 40-hex token allowlist. Enumerate every exact-40-hex token
# in the four content paths; every token must be deliberately
# classified below; any unclassified token is a blocker.
#   857a7debc6625a3dadbaecee1ee7b2ed5e8ada75  pinned bitcoin/bips commit (BIP 174 / type registry / BIP 370 citations)
#   15a7a4ed7c4d0952ce966087e55a9a3e2f28ec1d  pinned bitcoin/bitcoin commit (doc/psbt.md citation)
#   de71c22328b24e0848bbe1bd12ac8974ca83b5b8  pinned Ian Coleman BIP39 tool commit (SOURCE-REGISTER row)
#   5088588dd4f913a489329d2422b0f925ed281856  pinned SeedSigner commit (SOURCE-REGISTER row)
#   55f93844b56e3637468321e1c68638a8138a3a2b  pinned COLDCARD firmware commit (SOURCE-REGISTER row)
#   1e9dfb9518bd90d4531180d9a3258dd21e54dee3  retired QuietKey laboratory pin (SOURCE-REGISTER row)
#   8f3154d0e7845ed5a4c69b73b9479821fdf06765  governance manifest-ancestry constant required by this authorized script
{
  printf '%s\n' \
    15a7a4ed7c4d0952ce966087e55a9a3e2f28ec1d \
    1e9dfb9518bd90d4531180d9a3258dd21e54dee3 \
    5088588dd4f913a489329d2422b0f925ed281856 \
    55f93844b56e3637468321e1c68638a8138a3a2b \
    857a7debc6625a3dadbaecee1ee7b2ed5e8ada75 \
    8f3154d0e7845ed5a4c69b73b9479821fdf06765 \
    de71c22328b24e0848bbe1bd12ac8974ca83b5b8
} > "$tmpdir/hexallow" || err "40-hex allowlist generation failed (fail-closed)"
LC_ALL=C sort -c "$tmpdir/hexallow" \
  || err "40-hex allowlist is not sorted (fail-closed self-check)"
: > "$tmpdir/hexfound.raw"
for cf in "$DRAFT" docs/f3/README.md docs/SOURCE-REGISTER.md tools/verify-host-boundary.sh; do
  awk '{ s = $0
    while (match(s, /[0-9a-fA-F]+/)) {
      t = substr(s, RSTART, RLENGTH)
      if (length(t) >= 40) print t
      s = substr(s, RSTART + RLENGTH) } }' \
    "$cf" > "$tmpdir/hexruns"
  rc=$?
  [ "$rc" -eq 0 ] || err "40-hex enumeration scan error in $cf (awk exit $rc; empty output is legitimate here and distinguished from error)"
  awk 'length($0) == 40' "$tmpdir/hexruns" >> "$tmpdir/hexfound.raw" \
    || err "40-hex length filter failed for $cf (fail-closed)"
done
LC_ALL=C sort -u "$tmpdir/hexfound.raw" > "$tmpdir/hexfound" \
  || err "40-hex token sort failed (fail-closed)"
LC_ALL=C comm -23 "$tmpdir/hexfound" "$tmpdir/hexallow" > "$tmpdir/hexextra"
rc=$?
[ "$rc" -eq 0 ] || err "40-hex comm comparison failed (comm exit $rc)"
if [ -s "$tmpdir/hexextra" ]; then
  # rc-checked message formatting on the already-failing path; a tr
  # failure here must still fail closed, never soften the report.
  tr '\n' ' ' < "$tmpdir/hexextra" > "$tmpdir/hexextra.flat" \
    || err "unclassified 40-hex token report formatting failed (fail-closed)"
  err "unclassified exact-40-hex token(s) present in content paths: $(cat "$tmpdir/hexextra.flat")"
fi
# G: portability self-regression guard — the active verifiers MUST NOT
# reintroduce non-POSIX grep extraction or context options. Patterns
# are written so they do not match their own literals (bracketed first
# character; long-form names never directly preceded by two dashes on
# this guard's own lines).
for vf in tools/verify-host-boundary.sh tools/verify-current-stage.sh; do
  forbid "$vf reintroduces a non-POSIX short grep option cluster containing o, A, B, or C" \
    -E '[g]rep +(-[A-Za-z]+ +)*-[A-Za-z]*[oABC]' "$vf"
  forbid "$vf reintroduces a non-POSIX long grep option (only-matching or a context form)" \
    -E '[g]rep +[^|]*--(only-matching|after-context|before-context|context)' "$vf"
done
# README: status banner unchanged (checked in section 5) plus inventory
# link with draft-only language.
grep -F 'PSBT-V0-REVIEW-PROFILE-DRAFT.md' docs/f3/README.md >/dev/null \
  || err "docs/f3/README.md does not link the F3.1 draft"
grep -F 'OWNER DIRECTIONS RECORDED — PROFILE NOT ACCEPTED, per QK-AUTH-F3.1B-R2-001' docs/f3/README.md >/dev/null \
  || err "docs/f3/README.md inventory line missing the Revision 2 directions-recorded-not-accepted language"
grep -F 'every clause remains PROPOSED/NON-NORMATIVE until separate profile acceptance' docs/f3/README.md >/dev/null \
  || err "docs/f3/README.md inventory line missing the clauses-remain-proposed language"
grep -F 'zero vectors generated or run, NO IMPLEMENTATION authorized' docs/f3/README.md >/dev/null \
  || err "docs/f3/README.md inventory line missing NO VECTORS/NO IMPLEMENTATION language"
# Forbidden repository content: no new fixture/vector/payload sources.
forbid "fixture/vector/payload-like file tracked (.psbt/.bin/.hex/.b64/vector)" \
  -iE '\.(psbt|bin|hex|b64|base64)$|(^|/)(fixtures?|vectors?)(/|$)' "$tmpdir/allfiles"
# No PSBT magic or long encoded payloads anywhere in the draft, and no
# address/xpub/mnemonic-like wallet fixture material. Hex runs of
# exactly 40 are permitted solely as pinned commit identifiers; 32-39
# and 41+ hex runs stay forbidden. The base64 class omits '/' so that
# pinned URLs never false-positive; PSBT payloads are still caught by
# the [c]HNidP prefix and magic checks.
forbid "$DRAFT contains PSBT magic or an encoded payload" \
  -E '[c]HNidP|[7]0736274ff|magic bytes [0-9a-fA-F]{8}|[A-Za-z0-9+=]{60,}' "$DRAFT"
forbid "$DRAFT contains xpub/xprv/address/mnemonic-like fixture material" \
  -E 'xpub[0-9A-Za-z]{20,}|xprv[0-9A-Za-z]{20,}|bc1[0-9a-z]{20,}|(^|[^A-Za-z])[13][a-km-zA-HJ-NP-Z1-9]{25,34}([^A-Za-z]|$)' "$DRAFT"
forbid "$DRAFT contains overlong hex material (41+ hex chars)" \
  -E '[0-9a-fA-F]{41}' "$DRAFT"
forbid "$DRAFT contains non-commit hex material (32-39 hex chars)" \
  -E '(^|[^0-9a-fA-F])[0-9a-fA-F]{32,39}([^0-9a-fA-F]|$)' "$DRAFT"
# No affirmative acceptance/production claims. Closed grammar: only the
# affirmative verb forms are forbidden, so explicit warning sentences
# ("NOT ACCEPTED", "accepts no profile") never false-positive.
forbid "$DRAFT contains an affirmative acceptance/production claim" \
  -iE '(is|are|was|were|has been|have been)[[:space:]]+(now[[:space:]]+)?(accepted|approved|frozen|implemented|validated|conformant)|production[- ]ready|gate[- ][a-e][[:space:]]+(is[[:space:]]+)?closed' "$DRAFT"
forbid "$DRAFT authorizes a numeric QK-LIM value" \
  -E 'QK-LIM[-A-Z0-9]*[[:space:]]*(=|:)[[:space:]]*[0-9]' "$DRAFT"

# F3.1b status-accuracy erratum (QK-AUTH-F3.1B-001): fail-closed POSIX
# checks that the corrected present-state wording and the append-only
# CARD-006 evidence-family erratum are present, and that the identified
# stale claims are gone. Lexical, heuristic supporting evidence only —
# never proof of any status.
grep -F 'the owner-approved specification baseline, dependency-free payload-free HOST-only non-product state/policy models and tests, and a non-normative PSBT review-profile draft' README.md >/dev/null \
  || err "README.md missing the truthful current-state statement"
grep -F 'no wallet product, no PSBT parser/serializer, no cryptographic or signing implementation, no seed generation, no QR/SD/card integration, no target UI/runtime, no production evidence, and no fitness for funds' README.md >/dev/null \
  || err "README.md missing the truthful exclusion statement"
grep -F 'historical status-at-creation rows preserved unedited; effective status is set by the appended owner-approval records' README.md >/dev/null \
  || err "README.md missing the historical-vs-effective decision-record wording"
forbid "README.md still carries the stale architecture-foundation-only claim" \
  -F 'contains an architecture foundation only' README.md
forbid "README.md still describes the decision record as all DRAFT" \
  -F 'decision record (all DRAFT)' README.md
grep -F 'QuietKey remains an unvalidated development specification; the tracked Rust is HOST-only non-product scaffold, and no product or target implementation evidence exists.' README.md >/dev/null \
  || err "README.md missing the corrected unvalidated-specification sentence"
forbid "README.md still carries the stale development-specification-only sentence" \
  -F 'This repository is a development specification only; no implementation evidence exists.' README.md
grep -F 'the owner-approved specification baseline, dependency-free payload-free HOST-only non-product state/policy models and tests, and a non-normative PSBT review-profile draft' SECURITY.md >/dev/null \
  || err "SECURITY.md missing the truthful current-state classification"
grep -F 'unsafe for funds' SECURITY.md >/dev/null \
  || err "SECURITY.md missing the unsafe-for-funds statement"
forbid "SECURITY.md still carries the stale architecture-foundation-only claim" \
  -F 'It contains an architecture foundation only.' SECURITY.md
grep -F 'the baseline status block below records which preparation work has been completed or authorized to date' docs/BUILD-ROADMAP.md >/dev/null \
  || err "BUILD-ROADMAP.md missing the truthful roadmap-summary wording"
forbid "BUILD-ROADMAP.md still claims no milestone was executed" \
  -F 'without executing any of them' docs/BUILD-ROADMAP.md
grep -F 'STATUS: F2 PHYSICAL/EXACT-TARGET WORK BLOCKED — OVERALL INCOMPLETE; F3 HOST-ONLY DRAFTING AUTHORIZED — INCOMPLETE — NO PROFILE ACCEPTED — NO TARGET EVIDENCE; F4 HOST-ONLY SCAFFOLD AUTHORIZED — INCOMPLETE — NO TARGET CLAIM — NOT PRODUCT CODE — OD-01 OPEN — NO GATE CLOSED.' docs/HOST-WORK-AUTHORIZATION.md >/dev/null \
  || err "HOST-WORK-AUTHORIZATION.md missing the truthful current status banner"
forbid "HOST-WORK-AUTHORIZATION.md still carries the stale F2-only status banner" \
  -F 'STATUS: F2 SOFTWARE PREPARATION — HOST PROBE ONLY — CANDIDATE TOOLCHAIN' docs/HOST-WORK-AUTHORIZATION.md
grep -F 'QK-ERR-REQ-2026-08-18-001 — Effective erratum: QK-REQ-CARD-006 Evidence family (append-only)' docs/REQUIREMENTS.md >/dev/null \
  || err "REQUIREMENTS.md missing the CARD-006 evidence-family erratum heading"
grep -F 'The effective Evidence cell for QK-REQ-CARD-006 is "recovery-rehearsal, target-bench"; its Tst cell remains "QK-TST-REH-004, QK-TST-BENCH-005".' docs/REQUIREMENTS.md >/dev/null \
  || err "REQUIREMENTS.md erratum missing the exact effective Evidence/Tst statement"
grep -F 'QK-TST-BENCH-005 remains conditional on OD-02 and no non-exportable-signer direction is selected.' docs/REQUIREMENTS.md >/dev/null \
  || err "REQUIREMENTS.md erratum missing the OD-02 conditionality statement"
grep -F '| QK-REQ-CARD-006 | Card content rescue SHALL be possible with a commodity reader and the open rescue tool. | QK-DEC-006 | QK-THR-001 | NONE (availability property; implementation OPEN per OD-02) | QK-TST-REH-004, QK-TST-BENCH-005 | recovery-rehearsal | Gate B |' docs/REQUIREMENTS.md >/dev/null \
  || err "REQUIREMENTS.md historical QK-REQ-CARD-006 row is missing or was edited"

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
  || err "cargo test --locked --offline failed: $(tail -n 20 "$tmpdir/test")"

# 9. Exactly two local packages in metadata.
cargo metadata --manifest-path host/Cargo.toml --locked --offline --no-deps --format-version 1 > "$tmpdir/meta" 2>&1 \
  || err "cargo metadata failed: $(tail -n 5 "$tmpdir/meta")"
# Step-by-step temp-file implementation only (the former redundant
# tr-to-grep pipeline pre-check has been deleted): tr rc-checked, grep
# 0/1/>1 handled, nonempty and exact package count enforced explicitly.
tr ',' '\n' < "$tmpdir/meta" > "$tmpdir/metalines" \
  || err "cargo metadata post-processing failed (fail-closed)"
grep '"manifest_path":' "$tmpdir/metalines" > "$tmpdir/manifpaths"
mrc=$?
[ "$mrc" -le 1 ] || err "cargo metadata manifest scan failed (grep exit $mrc)"
[ -s "$tmpdir/manifpaths" ] || err "cargo metadata reports no manifest paths (fail-closed)"
pkgcount=$(grep -c '"manifest_path":' "$tmpdir/metalines")
mrc=$?
[ "$mrc" -le 1 ] || err "cargo metadata manifest count failed (grep exit $mrc)"
[ "$pkgcount" = "2" ] || err "cargo metadata does not report exactly two local packages (found $pkgcount)"
forbid "cargo metadata reports a package outside the authorized workspace" \
  -Ev 'host/qk-host-(model|sim)/Cargo.toml' "$tmpdir/manifpaths"

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
