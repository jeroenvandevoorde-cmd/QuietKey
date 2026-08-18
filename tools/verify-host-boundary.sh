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
grep -F 'AUTHORIZATION: QK-AUTH-F3F4-001 — DRAFTING ONLY.' "$DRAFT" >/dev/null \
  || err "$DRAFT missing the drafting-only authorization line"
grep -F 'REVIEW DRAFT COMPLETE — NOT ACCEPTED' "$DRAFT" >/dev/null \
  || err "$DRAFT missing the mandatory end status"
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
# Exact contiguous plan-ID set QK-F3-PLAN-001..074, same method. Only
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
while [ "$i" -le 74 ]; do
  printf 'QK-F3-PLAN-%03d\n' "$i" >> "$tmpdir/planexp" \
    || err "plan expected-list generation failed (fail-closed)"
  i=$((i+1))
done
cmp -s "$tmpdir/planexp" "$tmpdir/planids"
rc=$?
[ "$rc" -eq 0 ] || err "plan-ID set is not exactly QK-F3-PLAN-001..074 contiguous (cmp exit $rc)"
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
# C: robust prevout recommendation with exact validation wording; the
# false 'matches witness_utxo exactly' phrase is forbidden.
grep -F 'require BOTH `witness_utxo` AND `non_witness_utxo`' "$DRAFT" >/dev/null \
  || err "$DRAFT missing the both-UTXO recommended candidate"
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
grep -F "indexed output's amount and scriptPubKey" "$DRAFT" >/dev/null \
  || err "$DRAFT missing the indexed-output comparison wording"
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
grep -F 'adds NO replacement or duplicate record' "$DRAFT" >/dev/null \
  || err "$DRAFT missing the same-signer no-delta rule"
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
# F: raw-only nSequence handling while D-12 is OPEN — exact literal
# status required; stale implication/show-signaling phrasing forbidden.
grep -F 'replacement policy not evaluated' "$DRAFT" >/dev/null \
  || err "$DRAFT missing the literal 'replacement policy not evaluated' status"
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
# G: exact decision-set verification — row-leading decision-table IDs
# must be exactly D-01..D-12, each exactly once, no gap/extra/dup.
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
i=1
while [ "$i" -le 12 ]; do
  printf 'D-%02d\n' "$i" >> "$tmpdir/decexp" \
    || err "decision expected-list generation failed (fail-closed)"
  i=$((i+1))
done
cmp -s "$tmpdir/decexp" "$tmpdir/decids"
rc=$?
[ "$rc" -eq 0 ] || err "decision-ID set is not exactly D-01..D-12, each exactly once (cmp exit $rc)"
# G: allowed-field schema matrix — every allowed row must be present,
# and the exhaustive/sweep planning language must be explicit.
for row in 'GLOBAL: PSBT_GLOBAL_UNSIGNED_TX 0x00' \
  'GLOBAL: PSBT_GLOBAL_XPUB 0x01' 'GLOBAL: version field 0xFB' \
  'INPUT: PSBT_IN_NON_WITNESS_UTXO 0x00' 'INPUT: PSBT_IN_WITNESS_UTXO 0x01' \
  'INPUT: PSBT_IN_PARTIAL_SIG 0x02' 'INPUT: PSBT_IN_SIGHASH_TYPE 0x03' \
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
# G: full changed-content material scan across all four content-commit
# paths. Supporting evidence only, never proof of absence. Patterns are
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
grep -F 'NOT ACCEPTED, NO VECTORS generated or run, NO IMPLEMENTATION authorized' docs/f3/README.md >/dev/null \
  || err "docs/f3/README.md inventory line missing DRAFT/NOT ACCEPTED/NO VECTORS/NO IMPLEMENTATION language"
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
