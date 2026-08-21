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

# Fail-closed utility canaries. Each command must prove both output and
# return-code behavior before it can support later evidence checks.
printf 'qk-canary\n' > "$tmpdir/tool.in" || err "utility canary input generation failed"
sed 's/qk-canary/qk-sed-ok/' "$tmpdir/tool.in" > "$tmpdir/tool.sed" \
  || err "sed utility canary failed"
[ "$(cat "$tmpdir/tool.sed")" = "qk-sed-ok" ] || err "sed utility canary produced empty or wrong output"
awk '{ print "qk-awk-ok" }' "$tmpdir/tool.in" > "$tmpdir/tool.awk" \
  || err "awk utility canary failed"
[ "$(cat "$tmpdir/tool.awk")" = "qk-awk-ok" ] || err "awk utility canary produced empty or wrong output"
printf 'b\na\n' | LC_ALL=C sort > "$tmpdir/tool.sort" || err "sort utility canary failed"
[ -s "$tmpdir/tool.sort" ] || err "sort utility canary produced empty output"
printf 'a\nb\n' > "$tmpdir/tool.sort.exp" || err "sort utility canary expected generation failed"
cmp -s "$tmpdir/tool.sort.exp" "$tmpdir/tool.sort"
rc=$?
[ "$rc" -eq 0 ] || err "sort utility canary output is not exactly the complete expected a,b sequence"
printf 'a\n' > "$tmpdir/tool.cmp.a" || err "cmp utility canary A generation failed"
printf 'b\n' > "$tmpdir/tool.cmp.b" || err "cmp utility canary B generation failed"
cmp -s "$tmpdir/tool.cmp.a" "$tmpdir/tool.cmp.a"
rc=$?
[ "$rc" -eq 0 ] || err "cmp utility canary rejected identical files"
cmp -s "$tmpdir/tool.cmp.a" "$tmpdir/tool.cmp.b"
rc=$?
[ "$rc" -eq 1 ] || err "cmp utility canary did not report different files"
diff "$tmpdir/tool.cmp.a" "$tmpdir/tool.cmp.b" > "$tmpdir/tool.diff" 2>&1
rc=$?
[ "$rc" -eq 1 ] || err "diff utility canary did not report different files"
[ -s "$tmpdir/tool.diff" ] || err "diff utility canary produced empty difference output"

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
docs/f3/F3.2B-PSBT-DECISION-PACKET.md
docs/f3/F3.2B-PSBT-OWNER-RESPONSE-RECORD.md
docs/f3/F3.2C-D11-MEDIA-WRITE-LIFECYCLE-CONSTRUCTION-PACKET.md
docs/f3/F3.2D-D11-Q001-OWNER-CLARIFICATION-RECORD.md
docs/f3/F3.2E-PSBT-OUTPUT-TEST-ALIGNMENT-PACKET.md
docs/f3/F3.2F-PSBT-OUTPUT-TEST-OWNER-DIRECTION-RECORD.md
docs/f3/F3.2H-QK-LIM-PSBT-027-CROSS-DOCUMENT-ALIGNMENT-PACKET.md
docs/f3/F3.2I-QK-LIM-PSBT-027-OWNER-DIRECTION-RECORD.md
docs/f3/F3.2J-QK-LIM-PSBT-027-EXACT-TOMBSTONE-CONSTRUCTION-PACKET.md
docs/f3/F3.2K-QK-LIM-PSBT-027-EXACT-CONSTRUCTION-OWNER-DIRECTION-RECORD.md
docs/f3/F3.2M-D11-Q002-SD-ATTACHMENT-EPOCH-DECISION-PACKET.md
docs/f3/F3.2N-D11-Q002-SD-ATTACHMENT-EPOCH-OWNER-DIRECTION-RECORD.md
docs/f3/PSBT-V0-REVIEW-PROFILE-DRAFT.md
docs/f3/README.md
docs/f3/WALLET-TRUST-SPINE-DRAFT.md
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
# F3.1a/F3.1b/F3.2a source-register rows: fail-closed COMPLETE-LITERAL-FULL-ROW
# checks plus resource uniqueness. For each of the 26 rows the helper
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
exact_row 'BIP 32' \
  '`bip-0032.mediawiki`' \
  '| bitcoin/bips — `bip-0032.mediawiki` | `857a7debc6625a3dadbaecee1ee7b2ed5e8ada75` | BSD-2-Clause (per the pinned BIP preamble) | F3.2a citation-only reference for HD extended keys, fingerprints and child derivation. Nothing imported. | Citation-only remote review at the pinned commit; nothing imported. |'
exact_row 'BIP 48' \
  '`bip-0048.mediawiki`' \
  '| bitcoin/bips — `bip-0048.mediawiki` | `857a7debc6625a3dadbaecee1ee7b2ed5e8ada75` | MIT (per the pinned BIP preamble) | F3.2a citation-only reference for the m/48h/0h/0h/2h multi-sig hierarchy, receive/change branches and the native P2WSH script type. Nothing imported. | Citation-only remote review at the pinned commit; nothing imported. |'
exact_row 'BIP 67' \
  '`bip-0067.mediawiki`' \
  '| bitcoin/bips — `bip-0067.mediawiki` | `857a7debc6625a3dadbaecee1ee7b2ed5e8ada75` | PD (per the pinned BIP preamble) | F3.2a citation-only reference for deterministic compressed-public-key lexicographic ordering rationale. Nothing imported. | Citation-only remote review at the pinned commit; nothing imported. |'
exact_row 'BIP 380' \
  '`bip-0380.mediawiki`' \
  '| bitcoin/bips — `bip-0380.mediawiki` | `857a7debc6625a3dadbaecee1ee7b2ed5e8ada75` | BSD-2-Clause (per the pinned BIP preamble) | F3.2a citation-only reference for descriptor syntax, key-origin expressions and the descriptor checksum. Nothing imported. | Citation-only remote review at the pinned commit; nothing imported. |'
exact_row 'BIP 382' \
  '`bip-0382.mediawiki`' \
  '| bitcoin/bips — `bip-0382.mediawiki` | `857a7debc6625a3dadbaecee1ee7b2ed5e8ada75` | BSD-2-Clause (per the pinned BIP preamble) | F3.2a citation-only reference for wsh()/P2WSH descriptor semantics. Nothing imported. | Citation-only remote review at the pinned commit; nothing imported. |'
exact_row 'BIP 383' \
  '`bip-0383.mediawiki`' \
  '| bitcoin/bips — `bip-0383.mediawiki` | `857a7debc6625a3dadbaecee1ee7b2ed5e8ada75` | BSD-2-Clause (per the pinned BIP preamble) | F3.2a citation-only reference for multi()/sortedmulti() semantics and sorting of derived public keys. Nothing imported. | Citation-only remote review at the pinned commit; nothing imported. |'
exact_row 'BIP 39' \
  '`bip-0039.mediawiki`' \
  '| bitcoin/bips — `bip-0039.mediawiki` | `857a7debc6625a3dadbaecee1ee7b2ed5e8ada75` | MIT (per the pinned BIP preamble) | F3.2a citation-only reference limited to mnemonic-to-seed mechanics used by the inherited 24-word English/empty-passphrase profile; QuietKey'\''s 24-word English/empty-passphrase selection remains controlled by local QK-REQ-CUS-005. Nothing imported. | Citation-only remote review at the pinned commit; nothing imported. |'
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

# 5d. F3.2a Wallet Trust Spine DRAFT: static supporting checks only.
# Heuristic lexical evidence, never proof, never acceptance. Every
# grep is separately rc-checked; no pipelines.
WTS=docs/f3/WALLET-TRUST-SPINE-DRAFT.md
[ -f "$WTS" ] || err "$WTS missing"
grep -F '# QK-F3.2a — Wallet Trust Spine DRAFT' "$WTS" >/dev/null \
  || err "$WTS missing the exact title"
grep -F 'EXPERIMENTAL — NO REAL FUNDS — NOT A WALLET' "$WTS" >/dev/null \
  || err "$WTS missing the no-funds warning"
grep -F 'STATUS: AUTHORIZED — F3.2a HOST-ONLY WALLET TRUST-SPINE DRAFT — PROPOSED/NON-NORMATIVE — INCOMPLETE — NO PROFILE ACCEPTED OR FROZEN — NO TEST VECTORS GENERATED OR RUN — NO IMPLEMENTATION — NO TARGET EVIDENCE.' "$WTS" >/dev/null \
  || err "$WTS missing the exact mandatory status banner"
grep -F 'AUTHORIZATION: QK-AUTH-F3F4-001 — DRAFTING ONLY; QK-AUTH-F3.2A-001 authorizes preparation of this draft only. Every rule remains PROPOSED/NON-NORMATIVE until separate explicit profile acceptance.' "$WTS" >/dev/null \
  || err "$WTS missing the exact authorization line"
grep -F 'QK-AUTH-F3.2A-001 — F3.2a Wallet Trust Spine drafting authorization' docs/DECISION-LOG.md >/dev/null \
  || err "docs/DECISION-LOG.md missing the QK-AUTH-F3.2A-001 record"
grep -F '“Agreed, please continue”' docs/DECISION-LOG.md >/dev/null \
  || err "docs/DECISION-LOG.md missing the exact F3.2a owner words"
# Closed-world WTS clause set: extract the ENTIRE row-leading clause
# heading ID token (the maximal alphanumeric/hyphen run after the
# exact heading prefix, not merely a numeric prefix) and compare
# against the exact expected 001-015 list. Duplicates, omissions,
# numeric extras (016, 100, 999, ...) and malformed suffix tokens
# (100A, ABC, 001-extra, missing/extra zeroes) all yield a token that
# differs from the expected set and fail. The count of row-leading
# heading-prefix lines must equal the count of extracted tokens, so a
# malformed heading line cannot become invisible by omitting an
# expected delimiter. Every stage rc-checked; no pipelines.
# Every clause-prefix line must satisfy the complete anchored heading
# grammar; IDs are derived ONLY from fully valid heading lines, so a
# malformed heading (001X, ABC, altered marker) can never contribute a
# backtracked ID and can never hide: prefix-line count must equal
# valid-complete-heading count.
wclines=$(grep -c '^\*\*QK-F3-WTS' "$WTS")
wcrc=$?
[ "$wcrc" -le 1 ] || err "WTS clause heading-prefix line count failed (grep exit $wcrc)"
wcvalid=$(grep -cE '^\*\*QK-F3-WTS-[0-9][0-9][0-9] \(PROPOSED/NON-NORMATIVE\)\.\*\*' "$WTS")
wcrc=$?
[ "$wcrc" -le 1 ] || err "WTS valid clause heading count failed (grep exit $wcrc)"
[ "$wclines" = "$wcvalid" ] || err "$WTS has $wclines clause heading-prefix lines but only $wcvalid satisfy the complete anchored heading grammar '**QK-F3-WTS-NNN (PROPOSED/NON-NORMATIVE).**': malformed clause heading grammar"
sed -n 's/^\*\*\(QK-F3-WTS-[0-9][0-9][0-9]\) (PROPOSED\/NON-NORMATIVE)\.\*\*.*/\1/p' "$WTS" > "$tmpdir/wts.clauses.actual"
wcrc=$?
[ "$wcrc" -eq 0 ] || err "WTS clause heading extraction failed (sed exit $wcrc)"
[ -s "$tmpdir/wts.clauses.actual" ] || err "$WTS contains no valid WTS clause headings (fail-closed)"
: > "$tmpdir/wts.clauses.expected" || err "WTS clause expected-list init failed"
i=1
while [ "$i" -le 15 ]; do
  printf 'QK-F3-WTS-%03d\n' "$i" >> "$tmpdir/wts.clauses.expected" \
    || err "WTS clause expected-list generation failed at $i"
  i=$((i + 1))
done
[ -s "$tmpdir/wts.clauses.expected" ] || err "WTS clause expected list empty (fail-closed)"
LC_ALL=C sort "$tmpdir/wts.clauses.actual" > "$tmpdir/wts.clauses.sorted" \
  || err "WTS clause sort failed (fail-closed)"
cmp -s "$tmpdir/wts.clauses.expected" "$tmpdir/wts.clauses.sorted"
wcmp=$?
[ "$wcmp" -eq 0 ] || err "$WTS clause heading set is not exactly QK-F3-WTS-001..015 (cmp exit $wcmp): $(diff "$tmpdir/wts.clauses.expected" "$tmpdir/wts.clauses.sorted" 2>/dev/null | head -n 6)"
# Each heading must carry the PROPOSED/NON-NORMATIVE marker exactly once.
i=1
while [ "$i" -le 15 ]; do
  id=$(printf 'QK-F3-WTS-%03d' "$i") || err "WTS clause id formatting failed"
  ccount=$(grep -cE "^\\*\\*$id \\(PROPOSED/NON-NORMATIVE\\)\\.\\*\\*" "$WTS")
  crc=$?
  [ "$crc" -le 1 ] || err "WTS clause scan failed for $id (grep exit $crc)"
  [ "$ccount" = "1" ] || err "$WTS clause $id must occur exactly once as a line-anchored PROPOSED/NON-NORMATIVE heading (found $ccount)"
  i=$((i + 1))
done
# Closed-world WTS plan set: extract the ENTIRE row-leading plan-table
# ID token (the maximal alphanumeric/hyphen run after the exact table
# prefix, not merely a numeric prefix) and compare against the exact
# expected 001-020 list. Malformed suffix tokens (100A, ABC,
# 001-extra), missing/extra zeroes, duplicates, omissions and numeric
# extras all differ from the expected set and fail. The count of
# row-leading plan-prefix lines must equal the count of extracted
# tokens, so a malformed row cannot hide by dropping a delimiter.
# Every plan-prefix row must satisfy the exact anchored first-cell
# grammar; IDs are derived ONLY from valid anchored rows, so malformed
# first cells (100A, ABC, EXTRA suffixes, dropped delimiters) can
# never contribute a backtracked ID and can never hide.
wplines=$(grep -cE '^\|[ ]*QK-F3-WTS-PLAN' "$WTS")
wprc=$?
[ "$wprc" -le 1 ] || err "WTS plan row-prefix line count failed (grep exit $wprc)"
wpvalid=$(grep -cE '^\| QK-F3-WTS-PLAN-[0-9][0-9][0-9] \|' "$WTS")
wprc=$?
[ "$wprc" -le 1 ] || err "WTS valid plan first-cell count failed (grep exit $wprc)"
[ "$wplines" = "$wpvalid" ] || err "$WTS has $wplines plan-prefix rows but only $wpvalid satisfy the exact anchored first-cell grammar '| QK-F3-WTS-PLAN-NNN |': malformed plan row grammar"
sed -n 's/^| \(QK-F3-WTS-PLAN-[0-9][0-9][0-9]\) |.*/\1/p' "$WTS" > "$tmpdir/wts.plans.actual"
wprc=$?
[ "$wprc" -eq 0 ] || err "WTS plan ID extraction failed (sed exit $wprc)"
[ -s "$tmpdir/wts.plans.actual" ] || err "$WTS contains no valid WTS plan rows (fail-closed)"
: > "$tmpdir/wts.plans.expected" || err "WTS plan expected-list init failed"
i=1
while [ "$i" -le 20 ]; do
  printf 'QK-F3-WTS-PLAN-%03d\n' "$i" >> "$tmpdir/wts.plans.expected" \
    || err "WTS plan expected-list generation failed at $i"
  i=$((i + 1))
done
[ -s "$tmpdir/wts.plans.expected" ] || err "WTS plan expected list empty (fail-closed)"
LC_ALL=C sort "$tmpdir/wts.plans.actual" > "$tmpdir/wts.plans.sorted" \
  || err "WTS plan sort failed (fail-closed)"
cmp -s "$tmpdir/wts.plans.expected" "$tmpdir/wts.plans.sorted"
wpcmp=$?
[ "$wpcmp" -eq 0 ] || err "$WTS plan row set is not exactly QK-F3-WTS-PLAN-001..020 (cmp exit $wpcmp): $(diff "$tmpdir/wts.plans.expected" "$tmpdir/wts.plans.sorted" 2>/dev/null | head -n 6)"
# Each plan row must END with the exact final Markdown status cell.
# Result language such as "/ PASSED", GENERATED, RUN, PASSED or FAILED
# after the status makes the line no longer end with the cell and fails.
i=1
while [ "$i" -le 20 ]; do
  pid=$(printf 'QK-F3-WTS-PLAN-%03d' "$i") || err "WTS plan id formatting failed"
  grep -E "^\\| $pid \\|" "$WTS" > "$tmpdir/wtsplan.$pid"
  prc=$?
  [ "$prc" -le 1 ] || err "WTS plan row extraction failed for $pid (grep exit $prc)"
  [ -s "$tmpdir/wtsplan.$pid" ] || err "$WTS plan $pid row missing as a line-anchored table row (fail-closed)"
  pcount=$(awk 'END { print NR }' "$tmpdir/wtsplan.$pid") \
    || err "WTS plan row count failed for $pid (awk fail-closed)"
  [ "$pcount" = "1" ] || err "$WTS plan $pid must occur on exactly one line-anchored table row (found $pcount)"
  grep -E '\| PLANNED — NOT GENERATED — NOT RUN \|$' "$tmpdir/wtsplan.$pid" >/dev/null \
    || err "$WTS plan $pid row does not END with the exact final status cell '| PLANNED — NOT GENERATED — NOT RUN |'"
  i=$((i + 1))
done
# Semantic positives with paired stale/contradiction forbids.
grep -F 'a signer and A2 is not a signer role' "$WTS" >/dev/null \
  || err "$WTS missing the A1-not-a-signer/A2-not-a-role distinction"
grep -F "authenticated A1 is combined with the same wallet's card-held A2" "$WTS" >/dev/null \
  || err "$WTS missing the role-A A1+A2 combination rule"
grep -F 'No single custody object alone satisfies the threshold' "$WTS" >/dev/null \
  || err "$WTS missing the no-single-object-threshold rule"
forbid "$WTS still carries the retired no-role-split wording" \
  -F 'no role is ever split across' "$WTS"
grep -F 'not factors, not authentication, and not proof' "$WTS" >/dev/null \
  || err "$WTS missing the metadata-not-authority rule"
grep -F 'A fingerprint alone is NEVER identity' "$WTS" >/dev/null \
  || err "$WTS missing the fingerprint-not-identity rule"
forbid "$WTS treats a fingerprint as sufficient identity" \
  -iE 'fingerprint (alone )?(is|as) (sufficient|identity proof|proof of identity)' "$WTS"
grep -F 'NO persistent wallet registration and NO' "$WTS" >/dev/null \
  || err "$WTS missing the no-registration/no-pairing rule"
grep -F 'MUST NOT be silently replaced by a single or multipath descriptor' "$WTS" >/dev/null \
  || err "$WTS missing the no-single/multipath-replacement rule"
forbid "$WTS still names the unpinned BIP389" \
  -F 'BIP389' "$WTS"
grep -F 'no whitespace, newline, or NUL' "$WTS" >/dev/null \
  || err "$WTS missing the descriptor byte-hygiene constraints"
grep -F 'eight lowercase hex characters' "$WTS" >/dev/null \
  || err "$WTS missing the eight-lowercase-hex fingerprint format"
grep -F 'canonical hardened marker is `h`' "$WTS" >/dev/null \
  || err "$WTS missing the canonical hardened-marker rule"
grep -F 'never ypub/zpub and' "$WTS" >/dev/null \
  || err "$WTS missing the xpub-only serialization rule"
grep -F 'wsh(sortedmulti(2,...))' "$WTS" >/dev/null \
  || err "$WTS missing the wsh(sortedmulti(2,...)) template rule"
grep -F 'canonical descriptor bytes' "$WTS" >/dev/null \
  || err "$WTS missing the canonical-descriptor-bytes statement"
grep -F 'wallet_id = SHA256(canonical_receive_descriptor_ASCII || 0x00 || canonical_change_descriptor_ASCII)' "$WTS" >/dev/null \
  || err "$WTS missing the exact preserved wallet_id formula"
grep -F 'Receive first, then exactly one raw zero byte, then change' "$WTS" >/dev/null \
  || err "$WTS missing the wallet_id byte-order rule"
grep -F 'A QuietKey domain prefix MUST NOT be added' "$WTS" >/dev/null \
  || err "$WTS missing the no-domain-prefix rule"
forbid "$WTS adds a wallet_id domain tag/prefix" \
  -iE 'wallet_id[^.]*(with|includes|prepend(s|ed)?)[^.]*(domain (tag|prefix)|"QuietKey" prefix)' "$WTS"
grep -F 'PERMANENT SEMANTIC ROLE ORDER A,B,C' "$WTS" >/dev/null \
  || err "$WTS missing the permanent textual role-order rule"
grep -F 'NEVER redefines the semantic roles A/B/C' "$WTS" >/dev/null \
  || err "$WTS missing the slot-never-redefines-role rule"
forbid "$WTS claims witnessScript slot order defines roles" \
  -iE 'slot (order )?(defines|determines) (the )?role' "$WTS"
grep -F 'never script slot and never fingerprint alone' "$WTS" >/dev/null \
  || err "$WTS missing the full-material identity-comparison rule"
grep -F 'REJECTS fail-closed' "$WTS" >/dev/null \
  || err "$WTS missing the duplicate-material rejection rule"
grep -F 'D itself is not an authenticator' "$WTS" >/dev/null \
  || err "$WTS missing the D-not-an-authenticator rule"
grep -F 'ONLY as card-independent semantic states and invariants' "$WTS" >/dev/null \
  || err "$WTS missing the card-independent provisioning scope"
grep -F 'one wallet-level FINAL ACCEPTANCE point' "$WTS" >/dev/null \
  || err "$WTS missing the single FINAL ACCEPTANCE point"
grep -F 'atomically committed as one physical transaction' "$WTS" >/dev/null \
  || err "$WTS missing the no-atomic-provisioning statement"
grep -F 'deliberately does NOT invent' "$WTS" >/dev/null \
  || err "$WTS missing the no-invented-retirement-procedure statement"
grep -F 'zeroizes terminal-held secret state' "$WTS" >/dev/null \
  || err "$WTS missing the zeroization intent"
grep -F 'the exact role-C analogue' "$WTS" >/dev/null \
  || err "$WTS missing the A1+C recovery analogue"
grep -F 'REQUIRES byte-identical canonical D on both cards' "$WTS" >/dev/null \
  || err "$WTS missing the B+C byte-identical-D requirement"
grep -F "independently recomputed from each card's D" "$WTS" >/dev/null \
  || err "$WTS missing the recomputed-not-stored wallet_id rule"
grep -F 'wallet_id is never stored on the cards' "$WTS" >/dev/null \
  || err "$WTS missing the wallet_id-never-stored rule"
grep -F 'stores D and A2, not a persistent wallet_id' "$WTS" >/dev/null \
  || err "$WTS missing the canonical card payload statement"
forbid "$WTS claims wallet_id is stored on the cards" \
  -iE 'wallet_id (is )?(stored|held|kept) on (both|the) cards' "$WTS"
grep -F 'MUST match its OWN assigned role entry' "$WTS" >/dev/null \
  || err "$WTS missing the per-role public-material agreement rule"
grep -F "authenticate A1 with the B-held" "$WTS" >/dev/null \
  || err "$WTS missing the A1+B B-held-A2 authentication rule"
grep -F 'derived A to match role A' "$WTS" >/dev/null \
  || err "$WTS missing the derived-A-matches-role-A rule"
grep -F 'stateless replacement terminal with no prior wallet registration' "$WTS" >/dev/null \
  || err "$WTS missing the stateless-replacement-terminal statement"
grep -F 'contain the same A2 value' "$WTS" >/dev/null \
  || err "$WTS missing the same-A2 canonical invariant"
grep -F 'is OD-02/APDU-blocked and is NOT selected here' "$WTS" >/dev/null \
  || err "$WTS missing the same-A2 mechanism-blocked qualifier"
grep -F 'cannot be reached without establishing this same-A2 invariant' "$WTS" >/dev/null \
  || err "$WTS missing the FINAL-ACCEPTANCE same-A2 precondition"
grep -F 'rotate-and-sweep' "$WTS" >/dev/null \
  || err "$WTS missing the preserved rotate-and-sweep obligation"
grep -F 'BOUND BEFORE REVIEW' "$WTS" >/dev/null \
  || err "$WTS missing the pair-bound-before-review invariant"
grep -F 'no third or out-of-pair signer' "$WTS" >/dev/null \
  || err "$WTS missing the no-out-of-pair-signer rule"
grep -F 'MUST NOT choose the construction' "$WTS" >/dev/null \
  || err "$WTS missing the D-09-construction-open boundary"
grep -F 'INSIDE the authorization trust boundary' "$WTS" >/dev/null \
  || err "$WTS missing the malicious-terminal limitation"
grep -F 'independent-device review security' "$WTS" >/dev/null \
  || err "$WTS missing the independent-device disclaimer"
grep -F 'the requirements currently CONFLICT' "$WTS" >/dev/null \
  || err "$WTS missing the BND-003/D-03 conflict statement"
grep -F 'single-interface B+C choreography is BLOCKED' "$WTS" >/dev/null \
  || err "$WTS missing the B+C BLOCKED marker"
forbid "$WTS invents a B+C sequencing solution" \
  -iE '(preauthorization token|persistent card session) (is|are) (selected|adopted|introduced)' "$WTS"
grep -F 'QK-REQ-BND-003' "$WTS" >/dev/null \
  || err "$WTS missing the QK-REQ-BND-003 trace"
grep -F 'ONLY as unselected analysis' "$WTS" >/dev/null \
  || err "$WTS missing the unselected-analysis qualifier"
grep -F 'stateless terminal boundary' "$WTS" >/dev/null \
  || err "$WTS missing the card-independent contract column entries"
grep -F 'power-cut behavior' "$WTS" >/dev/null \
  || err "$WTS missing the blocked-column card unknowns"
grep -F 'Coverage listing NEVER proves correctness' "$WTS" >/dev/null \
  || err "$WTS missing the coverage-not-correctness caveat"
grep -F 'traceability is NOT DONE' "$WTS" >/dev/null \
  || err "$WTS missing the honest traceability-NOT-DONE boundary"
grep -F 'canonical QK-TST ID' "$WTS" >/dev/null \
  || err "$WTS missing the no-plan-to-QK-TST-mapping statement"
grep -F 'an explicit profile-acceptance prerequisite and remains NOT' "$WTS" >/dev/null \
  || err "$WTS missing the traceability acceptance-prerequisite statement"
grep -F 'proves nothing, runs nothing, and creates no' "$WTS" >/dev/null \
  || err "$WTS missing the future-mapping-proves-nothing statement"
forbid "$WTS still claims completed traceability to existing QK-TST IDs" \
  -F 'traces only to existing' "$WTS"
grep -F 'nothing here accepts the PSBT profile' "$WTS" >/dev/null \
  || err "$WTS missing the PSBT-profile-not-accepted statement"
# Corrected plan-link coverage cells (row-scoped).
grep -F 'QK-F3-WTS-001, QK-F3-WTS-007, QK-F3-WTS-008, QK-F3-WTS-011, QK-F3-WTS-012, QK-F3-WTS-013' "$tmpdir/wtsplan.QK-F3-WTS-PLAN-017" >/dev/null \
  || err "$WTS PLAN-017 row does not cover WTS-001/007/008/011/012/013"
grep -F 'duplicate role/signer material' "$tmpdir/wtsplan.QK-F3-WTS-PLAN-017" >/dev/null \
  || err "$WTS PLAN-017 row missing the duplicate role/signer material wording"
forbid "$WTS PLAN-017 row still says duplicate-card" \
  -F 'duplicate-card' "$tmpdir/wtsplan.QK-F3-WTS-PLAN-017"
grep -F 'post-approval invalidation included' "$tmpdir/wtsplan.QK-F3-WTS-PLAN-017" >/dev/null \
  || err "$WTS PLAN-017 row missing the post-approval invalidation coverage"
grep -F 'QK-F3-WTS-010, QK-F3-WTS-013, QK-F3-WTS-014' "$tmpdir/wtsplan.QK-F3-WTS-PLAN-018" >/dev/null \
  || err "$WTS PLAN-018 row does not cover WTS-010/013/014"
grep -F 'failure/interruption behavior' "$tmpdir/wtsplan.QK-F3-WTS-PLAN-018" >/dev/null \
  || err "$WTS PLAN-018 row missing failure/interruption behavior"
forbid "$WTS PLAN-018 row still references an undefined timeout" \
  -F 'timeout' "$tmpdir/wtsplan.QK-F3-WTS-PLAN-018"
grep -F 'same-A2 invariant (mechanism OD-02/APDU-blocked, not selected)' "$tmpdir/wtsplan.QK-F3-WTS-PLAN-011" >/dev/null \
  || err "$WTS PLAN-011 row missing the same-A2 invariant coverage"
grep -F 'END OF DRAFT — PROPOSED/NON-NORMATIVE — NO PROFILE ACCEPTED — NO VECTORS — NO IMPLEMENTATION — NO TARGET EVIDENCE.' "$WTS" >/dev/null \
  || err "$WTS missing the exact end-of-draft status line"
# Broad material guards on all F3.2a B paths: real extended keys, WIF,
# addresses, DER signatures, long secret-like hex runs (>= 64 hex),
# arbitrary exact-40-hex commit-like tokens not on the approved pin
# allowlist, and base64/PSBT/raw fixture payload patterns. Placeholder
# tokens (XPUB_A etc.), eight-hex fingerprint placeholders and prose
# are not flagged. No mnemonic-phrase detector is claimed or present:
# detecting arbitrary 24-word English prose lexically would be
# dishonest, so mnemonic material is covered only by review plus the
# no-secret rules, not by a fake pattern here.
for bpath in "$WTS" docs/SOURCE-REGISTER.md docs/f3/README.md; do
  forbid "$bpath contains what looks like a real extended key" \
    -E '[xyz](pub|prv)[1-9A-HJ-NP-Za-km-z]{20,}' "$bpath"
  forbid "$bpath contains what looks like a WIF private key" \
    -E '(^|[^1-9A-HJ-NP-Za-km-z])[KL5][1-9A-HJ-NP-Za-km-z]{50,51}([^1-9A-HJ-NP-Za-km-z]|$)' "$bpath"
  forbid "$bpath contains what looks like a mainnet address" \
    -E '(^|[^0-9A-Za-z])(bc1[qp][0-9a-z]{20,}|[13][1-9A-HJ-NP-Za-km-z]{25,34})([^0-9A-Za-z]|$)' "$bpath"
  forbid "$bpath contains what looks like a DER signature blob" \
    -E '30[0-9a-fA-F]{2}02[0-9a-fA-F]{2}[0-9a-fA-F]{60,}' "$bpath"
  forbid "$bpath contains a long secret-like hex run (>= 64 hex chars)" \
    -E '[0-9a-fA-F]{64}' "$bpath"
  forbid "$bpath contains what looks like a base64 payload blob" \
    -E '[A-Za-z0-9+/]{44,}={0,2}([^A-Za-z0-9+/=]|$)' "$bpath"
  forbid "$bpath contains what looks like raw PSBT material" \
    -E '([c]HNidP|[7]0736274ff)' "$bpath"
done
# Exact-40-hex tokens in the WTS draft are classified by the
# established closed 40-hex pin classifier below (the WTS draft is a
# scanned content path there); no separate allowlist is kept here.
# Exactly one STATUS: line, and it must equal the mandatory banner as
# a FULL line — a standalone affirmative STATUS line anywhere fails.
stlines=$(grep -c '^STATUS:' "$WTS")
strc=$?
[ "$strc" -le 1 ] || err "WTS STATUS-line count failed (grep exit $strc)"
[ "$stlines" = "1" ] || err "$WTS must contain exactly one line beginning 'STATUS:' (found $stlines)"
grep '^STATUS:' "$WTS" > "$tmpdir/wts.status"
strc=$?
[ "$strc" -le 1 ] || err "WTS STATUS-line extraction failed (grep exit $strc)"
printf '%s\n' 'STATUS: AUTHORIZED — F3.2a HOST-ONLY WALLET TRUST-SPINE DRAFT — PROPOSED/NON-NORMATIVE — INCOMPLETE — NO PROFILE ACCEPTED OR FROZEN — NO TEST VECTORS GENERATED OR RUN — NO IMPLEMENTATION — NO TARGET EVIDENCE.' > "$tmpdir/wts.status.expected" \
  || err "WTS expected-status generation failed (fail-closed)"
cmp -s "$tmpdir/wts.status.expected" "$tmpdir/wts.status"
stcmp=$?
[ "$stcmp" -eq 0 ] || err "$WTS STATUS line is not exactly the mandatory banner (cmp exit $stcmp)"
# Affirmative-status guards: any mutation of the WTS draft toward an
# accepted/implemented/production status must fail while the exact
# negative/non-normative banner remains allowed. The tokens APPROVED,
# IMPLEMENTED, VALIDATED, CONFORMANT and COMPLETE are globally
# rejected in the WTS draft (none are legitimate there); matching is
# letter-boundary aware so INCOMPLETE never trips COMPLETE.
forbid "$WTS carries an affirmative APPROVED token" \
  -E '(^|[^A-Za-z])APPROVED([^A-Za-z]|$)' "$WTS"
forbid "$WTS carries an affirmative IMPLEMENTED token" \
  -E '(^|[^A-Za-z])IMPLEMENTED([^A-Za-z]|$)' "$WTS"
forbid "$WTS carries an affirmative VALIDATED token" \
  -E '(^|[^A-Za-z])VALIDATED([^A-Za-z]|$)' "$WTS"
forbid "$WTS carries an affirmative CONFORMANT token" \
  -E '(^|[^A-Za-z])CONFORMANT([^A-Za-z]|$)' "$WTS"
forbid "$WTS carries an affirmative COMPLETE token" \
  -E '(^|[^A-Za-z])COMPLETE([^A-Za-z]|$)' "$WTS"
forbid "$WTS claims production readiness" \
  -iE 'production[- ]ready' "$WTS"
forbid "$WTS claims a closed gate" \
  -iE 'Gate [A-E][^.]*CLOSED' "$WTS"
forbid "$WTS claims an ACCEPTED profile" \
  -E '(is|are|now|been) +ACCEPTED' "$WTS"
forbid "$WTS claims vectors were generated or run" \
  -E '(vectors? (were|have been|are) (GENERATED|RUN|generated|run))' "$WTS"
# Exact bounded append content (not prefix-only), via checked stages.
# The earlier F3.2l Decision Log predicate is frozen at its published C.
git --no-optional-locks show 4af6166dc23eed7285a3d65b339924cda7b07962:docs/DECISION-LOG.md > "$tmpdir/dlog.a" 2>/dev/null \
  || err "cannot read docs/DECISION-LOG.md from the reviewed F3.2l A"
git --no-optional-locks show 1408fa98961e62ba6316515b1e277b6952a96e18:docs/DECISION-LOG.md > "$tmpdir/dlog.frozen" 2>/dev/null \
  || err "cannot read docs/DECISION-LOG.md from the published F3.2l C"
cmp -s "$tmpdir/dlog.a" "$tmpdir/dlog.frozen"
dlrc=$?
[ "$dlrc" -eq 0 ] || err "F3.2l published Decision Log differs from the reviewed A (cmp exit $dlrc): extra or altered governance text"
# docs/SOURCE-REGISTER.md must equal the exact published-base bytes
# plus exactly the seven authorized F3.2a rows in declared order.
git --no-optional-locks show a9d1f205cfa879a6f54b8838256d36e469cfed97:docs/SOURCE-REGISTER.md > "$tmpdir/sreg.base" 2>/dev/null \
  || err "cannot read docs/SOURCE-REGISTER.md from the published base"
cat "$tmpdir/sreg.base" > "$tmpdir/sreg.expected" \
  || err "source-register expected reconstruction failed (fail-closed)"
for bipres in bip-0032 bip-0048 bip-0067 bip-0380 bip-0382 bip-0383 bip-0039; do
  grep -F "| bitcoin/bips — \`$bipres.mediawiki\` |" docs/SOURCE-REGISTER.md > "$tmpdir/sreg.row.$bipres"
  srrc=$?
  [ "$srrc" -le 1 ] || err "source-register row extraction failed for $bipres (grep exit $srrc)"
  [ -s "$tmpdir/sreg.row.$bipres" ] || err "docs/SOURCE-REGISTER.md missing the authorized $bipres row"
  cat "$tmpdir/sreg.row.$bipres" >> "$tmpdir/sreg.expected" \
    || err "source-register expected append failed for $bipres (fail-closed)"
done
cmp -s "$tmpdir/sreg.expected" docs/SOURCE-REGISTER.md
srcmp=$?
[ "$srcmp" -eq 0 ] || err "docs/SOURCE-REGISTER.md is not exactly the published base plus the seven authorized F3.2a rows in declared order (cmp exit $srcmp)"
# README inventory must list the new draft with exact status language.
grep -F '[WALLET-TRUST-SPINE-DRAFT.md](WALLET-TRUST-SPINE-DRAFT.md)' docs/f3/README.md >/dev/null \
  || err "docs/f3/README.md inventory missing the F3.2a draft entry"
grep -F 'clauses QK-F3-WTS-001–015, plans QK-F3-WTS-PLAN-001–020' docs/f3/README.md >/dev/null \
  || err "docs/f3/README.md missing the F3.2a clause/plan set statement"
grep -F 'single-interface B+C choreography BLOCKED pending QK-REQ-BND-003 versus D-03 reconciliation plus OD-02 evidence' docs/f3/README.md >/dev/null \
  || err "docs/f3/README.md missing the F3.2a B+C BLOCKED summary"
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
# F3.2b owner-response record. These are fail-closed lexical and
# structural checks that provide supporting evidence only; they do not
# independently prove the semantics or authenticity of the record.
RSP32=docs/f3/F3.2B-PSBT-OWNER-RESPONSE-RECORD.md
[ -f "$RSP32" ] || err "$RSP32 missing"
r32first=$(head -n 1 "$RSP32") || err "$RSP32 first-line read failed (fail-closed)"
[ "$r32first" = "EXPERIMENTAL — NO REAL FUNDS — NOT A WALLET" ] \
  || err "$RSP32 does not begin with the exact no-funds warning"
r32title=$(grep -cFx -e '# F3.2b PSBT Decision Packet — Owner-Response Record' "$RSP32")
r32rc=$?
[ "$r32rc" -le 1 ] || err "$RSP32 title count failed (grep exit $r32rc)"
[ "$r32title" = "1" ] || err "$RSP32 exact title not present exactly once (found $r32title)"
r32status='STATUS: OWNER DIRECTION RECORDED — NON-ENACTING — POLICY DIRECTION ONLY — PROFILE NOT ACCEPTED — D-04 OWNER-OPEN — D-07, D-09, AND D-11 EVIDENCE/CONSTRUCTION-BLOCKED — NO IMPLEMENTATION — NO VECTORS GENERATED OR RUN — NO LICENSE APPLICATION — NO HARDWARE OR SETTINGS CHANGE — LOCAL AND UNPUBLISHED.'
r32sc=$(grep -cFx -e "$r32status" "$RSP32")
r32rc=$?
[ "$r32rc" -le 1 ] || err "$RSP32 exact STATUS count failed (grep exit $r32rc)"
[ "$r32sc" = "1" ] || err "$RSP32 exact STATUS line not present exactly once (found $r32sc)"
r32sp=$(grep -c '^STATUS:' "$RSP32")
r32rc=$?
[ "$r32rc" -le 1 ] || err "$RSP32 STATUS-prefix count failed (grep exit $r32rc)"
[ "$r32sp" = "1" ] || err "$RSP32 must contain exactly one STATUS line (found $r32sp)"
r32cnt() {
  r32msg=$1
  r32exp=$2
  r32pat=$3
  r32n=$(grep -cF -e "$r32pat" "$RSP32")
  r32rc=$?
  [ "$r32rc" -le 1 ] || err "$RSP32 $r32msg count failed (grep exit $r32rc)"
  [ "$r32n" = "$r32exp" ] || err "$RSP32 $r32msg: expected $r32exp, found $r32n"
}
r32cnt "source-base hash" 1 'bb6601f3b97528a72c55622251a4b475680ec21b'
r32cnt "source-packet path" 1 'docs/f3/F3.2B-PSBT-DECISION-PACKET.md'
r32cnt "exact owner quotation" 1 '“Approve all four F3.2b directions.”'
r32cnt "governance-provenance limitation" 1 'This record is governance provenance, not cryptographic identity proof, audit proof, or profile acceptance.'
r32cnt "D-04 OWNER-OPEN boundary" 1 'D-04 remains OWNER-OPEN, with representative coordinator-corpus review required before selection.'
r32cnt "D-07 classified boundary" 1 'D-07 remains EVIDENCE/CONSTRUCTION-BLOCKED pending target/human QK-LIM evidence.'
r32cnt "D-09 classified boundary" 1 'D-09 remains EVIDENCE/CONSTRUCTION-BLOCKED pending the exact commitment construction.'
r32cnt "D-11 classified boundary" 1 'D-11 remains EVIDENCE/CONSTRUCTION-BLOCKED pending the media/write lifecycle.'
r32cnt "D-00-open boundary" 1 'D-00 remains blocked.'
r32cnt "OD-05-open boundary" 1 'OD-05 remains open.'
r32cnt "QK-LIM-open boundary" 1 'Every QK-LIM remains open.'
r32cnt "QK-TST/evidence unchanged boundary" 1 'QK-TST and all evidence statuses remain unchanged.'
r32cnt "packet/profile non-normative boundary" 1 'The source packet and PSBT profile draft remain non-normative and are not accepted.'
r32cnt "no-publication-authority boundary" 1 'No publication authority is granted.'
r32cnt "GLOBAL_XPUB optional bound" 1 'PSBT_GLOBAL_XPUB is optional, with zero to three entries.'
r32cnt "GLOBAL_XPUB strict match" 1 'full raw 78-byte serialization and full origin tuple'
r32cnt "GLOBAL_XPUB rejection set" 1 'Any malformed, foreign, duplicate, conflicting, alternate-depth, alternate-network, alternate-origin, or ambiguous entry rejects the whole PSBT; invalid entries are never ignored.'
r32cnt "GLOBAL_XPUB non-authority" 1 'Presence is a non-authoritative consistency cross-check only, and absence is neutral.'
r32cnt "recipient exact classes" 1 'exactly canonical P2PKH, P2SH, P2WPKH, and P2WSH recipient scriptPubKey templates'
r32cnt "P2TR future-only boundary" 1 'P2TR remains future-only and requires a later explicit architecture and profile action.'
r32cnt "D-06 change class" 1 'PROVEN D CHANGE-BRANCH SCRIPT'
r32cnt "D-06 self-transfer class" 1 'PROVEN D RECEIVE-BRANCH SELF-TRANSFER SCRIPT'
r32cnt "D-06 recipient class" 1 'NOT PROVEN D-DERIVED — TREATED AS RECIPIENT'
r32cnt "D-06 branch distinction" 1 'Branch 1 is change; branch 0 is the distinct receive-branch self-transfer class, and they are never merged.'
r32cnt "D-06 complete output-derivation trio" 1 'complete trio specifically as PSBT_OUT_BIP32_DERIVATION records, one each for A, B, and C'
r32cnt "D-06 class-3 fallback boundary" 1 'The class-3 fallback applies only to missing, coherent-but-incomplete, or unrelated, structurally valid output BIP32-derivation metadata'
r32cnt "D-06 witnessScript rule" 1 'PSBT_OUT_WITNESS_SCRIPT is unnecessary. If present, it is allowed only with a complete D-derived candidate and must byte-match the independently derived witnessScript; otherwise reject.'
r32cnt "D-06 label neutrality" 1 'PSBT_GLOBAL_XPUB and external/coordinator labels neither prove ownership nor alone cause rejection.'
r32cnt "D-06 contradiction rejection" 1 'rejects the whole PSBT and is never downgraded.'
r32cnt "D-06 never-proven-external boundary" 1 'Class 3 means not proven D-derived, never proven external.'
r32cnt "D-06 proof limitation" 1 'not key possession, spendability, freshness, intent, chain state, or non-reuse'
r32cnt "D-10 signer-only boundary" 1 'QuietKey acts only as a BIP174 Signer.'
r32cnt "D-10 sole artifact" 1 'The sole releasable artifact is a fully serialized, freshly and independently reparsed unfinalized signed PSBT.'
r32cnt "D-10 incoming-signature import rejection" 1 'Any pre-existing PSBT_IN_PARTIAL_SIG record, selected or non-selected, or any finalization field makes the PSBT ineligible and rejects at import before private-key/card access.'
r32cnt "D-10 incoming-signature non-output boundary" 1 'Such a record or field is never validate-counted, preserved into output, overwritten, or stripped; therefore no pre-existing signature or final field can appear in an eligible output.'
r32cnt "D-10 accepted non-signature preservation" 1 'Only accepted pre-existing NON-SIGNATURE key-value encodings are preserved byte-for-byte and in relative order.'
r32cnt "D-10 exactly-two signatures" 1 'output has exactly the authorized two new selected-pair PSBT_IN_PARTIAL_SIG records'
r32cnt "D-10 no-overwrite" 1 'no overwrite or substitution'
r32cnt "D-10 all-or-nothing" 1 'all-or-nothing across every input'
r32cnt "D-10 independent reparse" 1 'freshly parsed independently of builder or in-memory construction state'
r32cnt "D-10 finalization prohibition" 1 'never creates or retains FINAL_SCRIPTSIG or FINAL_SCRIPTWITNESS, never finalizes, never extracts or releases a raw transaction, never creates a broadcast artifact, and never broadcasts.'
r32cnt "D-10 failure boundary" 1 'Failure releases no artifact or partial output.'
r32cnt "D-11 unresolved boundary" 1 'D-11 remains EVIDENCE/CONSTRUCTION-BLOCKED pending the media/write lifecycle; this direction does not resolve route, naming, insertion order, atomic write, media lifecycle, or a second independent implementation.'
# Closed-world response-ID enumeration: four table rows plus four
# section headings, with no hidden or suffix-smuggled occurrence.
r32qocc=$(awk 'BEGIN { n = 0 } { s = $0
  while ((i = index(s, "F32B-PSBT-Q-")) > 0) { n = n + 1; s = substr(s, i + 12) } }
  END { print n }' "$RSP32") \
  || err "$RSP32 Q-ID enumeration failed (awk fail-closed)"
[ "$r32qocc" = "8" ] || err "$RSP32 must contain exactly 8 Q-ID occurrences (4 rows + 4 headings; found $r32qocc)"
grep '^| F32B-PSBT-Q-' "$RSP32" > "$tmpdir/r32.rows"
r32rc=$?
[ "$r32rc" -le 1 ] || err "$RSP32 response-row extraction failed (grep exit $r32rc)"
cat > "$tmpdir/r32.rows.expected" <<'QK_F32B_RSP_ROWS_EOF' || err "$RSP32 expected-row generation failed"
| F32B-PSBT-Q-001 | D-02 | APPROVE RECOMMENDED DIRECTION (NON-ENACTING) |
| F32B-PSBT-Q-002 | present-profile D-05 | APPROVE RECOMMENDED DIRECTION (NON-ENACTING) |
| F32B-PSBT-Q-003 | D-06 | APPROVE RECOMMENDED DIRECTION (NON-ENACTING) |
| F32B-PSBT-Q-004 | D-10 | APPROVE RECOMMENDED DIRECTION (NON-ENACTING) |
QK_F32B_RSP_ROWS_EOF
cmp -s "$tmpdir/r32.rows.expected" "$tmpdir/r32.rows"
r32rc=$?
[ "$r32rc" -eq 0 ] || err "$RSP32 rows are missing, duplicated, reordered, malformed, or extra (cmp exit $r32rc)"
for r32head in \
  '### F32B-PSBT-Q-001 — D-02 direction' \
  '### F32B-PSBT-Q-002 — present-profile D-05 direction' \
  '### F32B-PSBT-Q-003 — D-06 direction' \
  '### F32B-PSBT-Q-004 — D-10 direction'; do
  r32hc=$(grep -cFx -e "$r32head" "$RSP32")
  r32rc=$?
  [ "$r32rc" -le 1 ] || err "$RSP32 heading check failed (grep exit $r32rc)"
  [ "$r32hc" = "1" ] || err "$RSP32 heading missing or duplicated: $r32head"
done
# Clause-scoped rejection of superseded Q-003/Q-004 semantics.
sed -n '/^### F32B-PSBT-Q-003 — D-06 direction$/,/^### F32B-PSBT-Q-004 — D-10 direction$/p' "$RSP32" > "$tmpdir/r32.q003"
r32rc=$?
[ "$r32rc" -eq 0 ] || err "$RSP32 Q-003 section extraction failed (sed exit $r32rc)"
[ -s "$tmpdir/r32.q003" ] || err "$RSP32 Q-003 section extraction was empty"
sed -n '/^### F32B-PSBT-Q-004 — D-10 direction$/,/^## Non-effect and open boundaries$/p' "$RSP32" > "$tmpdir/r32.q004"
r32rc=$?
[ "$r32rc" -eq 0 ] || err "$RSP32 Q-004 section extraction failed (sed exit $r32rc)"
[ -s "$tmpdir/r32.q004" ] || err "$RSP32 Q-004 section extraction was empty"
forbid "$RSP32 Q-003 allows witnessScript fall-through" \
  -iE 'WITNESS_SCRIPT[^.]*(optional|ignored|accepted without|allowed without)|mismatch[^.]*(class 3|recipient)' "$tmpdir/r32.q003"
forbid "$RSP32 Q-003 rejects solely on an external/coordinator label" \
  -iE '(external/coordinator|external|coordinator) labels? (alone|solely) (cause|trigger) rejection' "$tmpdir/r32.q003"
forbid "$RSP32 Q-004 allows incoming non-selected partial signatures" \
  -iE '(pre-existing|incoming)[^.]*non-selected[^.]*(allowed|accepted)' "$tmpdir/r32.q004"
forbid "$RSP32 Q-004 preserves incoming partial signatures" \
  -iE '(pre-existing|incoming)[^.]*PARTIAL_SIG[^.]*(preserved|retained|copied|output)' "$tmpdir/r32.q004"
forbid "$RSP32 carries the stale allowed-non-selected-signature sentence" \
  -F 'Any allowed pre-existing non-selected signature remains pre-existing and byte-preserved' "$RSP32"
forbid "$RSP32 carries the stale flattened D-item status" \
  -F 'D-04, D-07, D-09, and D-11 remain open.' "$RSP32"
# Prohibited widening or enactment concepts.
forbid "$RSP32 gives GLOBAL_XPUB authoritative force" -iE 'GLOBAL_XPUB[^.]*authoritative (proof|authority)' "$RSP32"
forbid "$RSP32 permits ignoring invalid GLOBAL_XPUB entries" -iE 'invalid[^.]*GLOBAL_XPUB[^.]*ignored|ignore[^.]*invalid[^.]*GLOBAL_XPUB' "$RSP32"
forbid "$RSP32 activates P2TR" -iE 'P2TR (is( now)?|now|becomes) (accepted|allowed|enabled|active)' "$RSP32"
forbid "$RSP32 folds self-transfer into change" -iE 'self-transfer[^.]*treated as change|self-transfer[^.]*is change' "$RSP32"
forbid "$RSP32 claims proven external" -iE 'class 3 (is|means) proven external' "$RSP32"
forbid "$RSP32 downgrades contradictory proof" -iE 'contradictory[^.]*(may be|is) downgraded' "$RSP32"
forbid "$RSP32 weakens exactly-two signatures to up-to-two" -iE 'up to two[^.]*PARTIAL_SIG' "$RSP32"
forbid "$RSP32 permits final fields or a final PSBT" -iE 'final PSBT|final fields? (is|are) (allowed|permitted|retained)' "$RSP32"
forbid "$RSP32 permits a raw transaction or broadcast alternative" -iE 'raw transaction[^.]*alternative|broadcast[^.]*alternative' "$RSP32"
forbid "$RSP32 resolves D-11" -iE 'D-11 (is( now)?|now|has been) (resolved|closed|selected)' "$RSP32"
forbid "$RSP32 claims profile acceptance" -iE 'profile (is( now)?|now|has been) accepted' "$RSP32"
forbid "$RSP32 claims implementation or conformance" -iE '(implementation|conformance) (is( now)?|now|has been) (authorized|approved|complete|validated)' "$RSP32"
forbid "$RSP32 claims vectors or evidence were produced" -iE '(vectors?|evidence) (were|have been|are) (generated|run|produced|accepted)' "$RSP32"
forbid "$RSP32 claims a gate closed" -iE 'Gate [A-E][^.]*CLOSED' "$RSP32"
forbid "$RSP32 claims license application" -iE 'license (is|was|has been) applied' "$RSP32"
forbid "$RSP32 claims hardware or settings work" -iE '(hardware|settings?) (were|was|have been|has been) (changed|implemented|configured)' "$RSP32"
forbid "$RSP32 claims publication" -iE '(record|chain|profile) (is|was|has been) published' "$RSP32"
# Record formatting and material scans.
tail -c 1 "$RSP32" | od -An -tuC > "$tmpdir/r32.lastbyte" \
  || err "$RSP32 final-byte inspection failed"
r32last=$(tr -d '[:space:]' < "$tmpdir/r32.lastbyte") \
  || err "$RSP32 final-byte normalization failed"
[ "$r32last" = "10" ] || err "$RSP32 must end in LF"
tail -c 2 "$RSP32" | od -An -tuC > "$tmpdir/r32.lasttwo" \
  || err "$RSP32 final-two-byte inspection failed"
r32lasttwo=$(tr -d '[:space:]' < "$tmpdir/r32.lasttwo") \
  || err "$RSP32 final-two-byte normalization failed"
[ "$r32lasttwo" != "1010" ] || err "$RSP32 must end in exactly one LF"
forbid "$RSP32 contains a tab" -F "$(printf '\t')" "$RSP32"
forbid "$RSP32 contains trailing whitespace" -E '[[:blank:]]$' "$RSP32"
forbid "$RSP32 contains hidden HTML" -iE '<!--|-->' "$RSP32"
# Actual-byte bidi scan. Whitespace is removed from od's checked hex
# transcript so a UTF-8 sequence cannot hide across an od line break.
# Reject U+202A/U+202B/U+202D/U+202E and U+2066..U+2069.
od -An -tx1 "$RSP32" > "$tmpdir/r32.bytes.raw" \
  || err "$RSP32 byte scan failed (od fail-closed)"
[ -s "$tmpdir/r32.bytes.raw" ] || err "$RSP32 byte scan produced no output"
tr -d '[:space:]' < "$tmpdir/r32.bytes.raw" > "$tmpdir/r32.bytes.hex" \
  || err "$RSP32 byte scan normalization failed (tr fail-closed)"
[ -s "$tmpdir/r32.bytes.hex" ] || err "$RSP32 normalized byte scan is empty"
r32bidi=$(grep -cE 'e280a[abde]|e281a[6-9]' "$tmpdir/r32.bytes.hex")
r32rc=$?
[ "$r32rc" -le 1 ] || err "$RSP32 actual-byte bidi scan failed (grep exit $r32rc)"
[ "$r32bidi" = "0" ] || err "$RSP32 contains an actual UTF-8 bidirectional control sequence"
forbid "$RSP32 contains a real extended key" -E '[xyz](pub|prv)[1-9A-HJ-NP-Za-km-z]{20,}' "$RSP32"
forbid "$RSP32 contains a WIF-like key" -E '(^|[^1-9A-HJ-NP-Za-km-z])[KL5][1-9A-HJ-NP-Za-km-z]{50,51}([^1-9A-HJ-NP-Za-km-z]|$)' "$RSP32"
forbid "$RSP32 contains an address-like value" -E '(^|[^0-9A-Za-z])(bc1[qp][0-9a-z]{20,}|[13mn2][1-9A-HJ-NP-Za-km-z]{25,34})([^0-9A-Za-z]|$)' "$RSP32"
forbid "$RSP32 contains a long secret-like hex run" -E '[0-9a-fA-F]{64}' "$RSP32"
forbid "$RSP32 contains base64-like payload material" -E '[A-Za-z0-9+/]{44,}={0,2}([^A-Za-z0-9+/=]|$)' "$RSP32"
forbid "$RSP32 contains raw PSBT material" -E '([c]HNidP|[7]0736274ff)' "$RSP32"

# F3.2c D-11 construction/readiness packet: supporting lexical and
# structural evidence only, never self-authentication or independent proof.
PKT32C=docs/f3/F3.2C-D11-MEDIA-WRITE-LIFECYCLE-CONSTRUCTION-PACKET.md
[ -f "$PKT32C" ] || err "$PKT32C missing"
# This exact Git blob is an audit locator and supporting byte-identity
# invariant only; it is never self-authentication or independent proof.
p32blob=b4594210975940df71b0e941841320d11defaa4c
p32blobact=$(git --no-optional-locks hash-object -- "$PKT32C"); p32rc=$?
[ "$p32rc" -eq 0 ] || err "$PKT32C git hash-object audit-locator scan failed (exit $p32rc)"
p32blobfmt=$(printf '%s\n' "$p32blobact" | grep -cE '^[0-9a-f]{40}$'); p32rc=$?
[ "$p32rc" -le 1 ] || err "$PKT32C git hash-object audit-locator format scan failed"
[ "$p32blobfmt" = 1 ] || err "$PKT32C git hash-object audit-locator output is not one lowercase 40-hex OID"
[ "$p32blobact" = "$p32blob" ] || err "$PKT32C audit-locator blob identity differs from the approved packet blob"
p32title='# QK-F3.2c — D-11 Media/Write Lifecycle Construction and Readiness Packet (Non-Binding)'
p32warn='EXPERIMENTAL — NO REAL FUNDS — NOT A WALLET'
p32status='STATUS: OWNER-AUTHORIZED CONSTRUCTION/READINESS INPUT ONLY — NON-NORMATIVE — D-11 EVIDENCE/CONSTRUCTION-BLOCKED — D-11 NOT SELECTED — OWNER QUESTIONS UNANSWERED — PSBT PROFILE NOT ACCEPTED — NO IMPLEMENTATION OR DEPENDENCIES — NO VECTORS, FIXTURES, OR SPECIMENS GENERATED OR RUN — NO MEDIA I/O OR TESTING — NO TARGET EVIDENCE — NO QK-LIM VALUE SELECTED — NO QK-TST/EVIDENCE/GATE CHANGE — NO LICENSE APPLICATION — NO HARDWARE, FIRMWARE, SETTINGS, OR CREDENTIAL CHANGE — LOCAL AND UNPUBLISHED.'
p32end='END OF PACKET — F3.2c D-11 CONSTRUCTION/READINESS INPUT ONLY — D-11 NOT SELECTED — OWNER QUESTIONS UNANSWERED — TARGET EVIDENCE ABSENT — PSBT PROFILE NOT ACCEPTED — LOCAL AND UNPUBLISHED.'
[ "$(sed -n '1p' "$PKT32C")" = "$p32title" ] || err "$PKT32C exact title is not first"
[ "$(sed -n '2p' "$PKT32C")" = "$p32warn" ] || err "$PKT32C exact warning is not second"
for p32line in "$p32title" "$p32warn" "$p32status" "$p32end" \
  '26e075704cdd172fce62b9b7cd38b4035db384d8' \
  'QK-AUTH-F3.2C-D11-PKT-001' \
  'D-11 selection is blocked until owner meaning is resolved.' \
  'D-09 and every QK-LIM remain open.' \
  'No QK-LIM value, default, or example is selected.'; do
  p32n=$(grep -cF -e "$p32line" "$PKT32C"); p32rc=$?
  [ "$p32rc" -le 1 ] || err "$PKT32C exact essential scan failed"
  [ "$p32n" = 1 ] || err "$PKT32C essential must occur exactly once: $p32line"
done
[ "$(grep -c '^STATUS:' "$PKT32C")" = 1 ] || err "$PKT32C must contain exactly one canonical STATUS line"
p32statusany=$(awk '{s=$0; while (match(s,/STATUS:/)) {c++; s=substr(s,RSTART+RLENGTH)}} END {print c+0}' "$PKT32C"); p32rc=$?
[ "$p32rc" -eq 0 ] || err "$PKT32C global STATUS occurrence scan failed"
case $p32statusany in ''|*[!0-9]*) err "$PKT32C global STATUS occurrence scan produced empty or non-numeric output" ;; esac
[ "$p32statusany" = 1 ] || err "$PKT32C must contain exactly one STATUS: occurrence anywhere (found $p32statusany)"
# Exact full-line STATUS binding: the one canonical STATUS: line must equal the
# complete required banner byte-for-byte, not merely contain it.
grep '^STATUS:' "$PKT32C" > "$tmpdir/p32.status.act" || err "$PKT32C STATUS line extraction failed"
printf '%s\n' "$p32status" > "$tmpdir/p32.status.exp" || err "$PKT32C STATUS expected generation failed"
cmp -s "$tmpdir/p32.status.exp" "$tmpdir/p32.status.act"
p32rc=$?
[ "$p32rc" -eq 0 ] || err "$PKT32C STATUS line is not exactly the complete required banner"
# Fail-closed suffix canaries: any appended text (including a
# 'D-11 SELECTED' claim) must break the exact full-line binding.
for p32sfx in ' — D-11 SELECTED' ' EXTRA' '.'; do
  printf '%s%s\n' "$p32status" "$p32sfx" > "$tmpdir/p32.status.bad" || err "STATUS suffix canary generation failed"
  cmp -s "$tmpdir/p32.status.exp" "$tmpdir/p32.status.bad"
  p32rc=$?
  [ "$p32rc" -eq 1 ] || err "STATUS suffix canary failed to detect appended text (cmp exit $p32rc)"
done
# Global STATUS-uniqueness canaries cover visible Markdown forms that do
# not begin at column zero, plus a same-line duplicate occurrence.
for p32statusbad in '> STATUS: SECONDARY' '>> STATUS: SECONDARY' ' STATUS: SECONDARY'; do
  printf '%s\n%s\n' "$p32status" "$p32statusbad" > "$tmpdir/p32.status.unique.bad" \
    || err "STATUS uniqueness canary generation failed"
  p32statusn=$(awk '{s=$0; while (match(s,/STATUS:/)) {c++; s=substr(s,RSTART+RLENGTH)}} END {print c+0}' "$tmpdir/p32.status.unique.bad"); p32rc=$?
  [ "$p32rc" -eq 0 ] || err "STATUS uniqueness canary scan failed"
  case $p32statusn in ''|*[!0-9]*) err "STATUS uniqueness canary scan produced empty or non-numeric output" ;; esac
  [ "$p32statusn" = 2 ] || err "STATUS uniqueness canary did not count exactly two occurrences"
done
printf '%s STATUS: SECONDARY\n' "$p32status" > "$tmpdir/p32.status.unique.bad" \
  || err "STATUS same-line uniqueness canary generation failed"
p32statusn=$(awk '{s=$0; while (match(s,/STATUS:/)) {c++; s=substr(s,RSTART+RLENGTH)}} END {print c+0}' "$tmpdir/p32.status.unique.bad"); p32rc=$?
[ "$p32rc" -eq 0 ] || err "STATUS same-line uniqueness canary scan failed"
case $p32statusn in ''|*[!0-9]*) err "STATUS same-line uniqueness canary scan produced empty or non-numeric output" ;; esac
[ "$p32statusn" = 2 ] || err "STATUS same-line uniqueness canary did not count exactly two occurrences"
[ "$(tail -n 1 "$PKT32C")" = "$p32end" ] || err "$PKT32C exact terminal line missing"
p32set() {
  pfx=$1; max=$2; status=$3; out=$4
  grep "^| $pfx" "$PKT32C" > "$tmpdir/p32.rows" || err "$PKT32C $pfx rows missing"
  : > "$tmpdir/p32.exp" || err "$PKT32C expected-set init failed"
  i=1
  while [ "$i" -le "$max" ]; do printf '%s-%03d\n' "$pfx" "$i" >> "$tmpdir/p32.exp" || err "$PKT32C expected ID failed"; i=$((i + 1)); done
  sed -n "s/^| \\($pfx-[0-9][0-9][0-9]\\) |.*| $status |$/\\1/p" "$tmpdir/p32.rows" > "$tmpdir/p32.act" \
    || err "$PKT32C $pfx row parse failed"
  cmp -s "$tmpdir/p32.exp" "$tmpdir/p32.act"; p32rc=$?
  [ "$p32rc" -eq 0 ] || err "$PKT32C $pfx rows/order/status are not exact"
  p32occ=$(awk -v p="$pfx-" '{s=$0; while (match(s,p"[0-9][0-9][0-9]")) {c++; s=substr(s,RSTART+RLENGTH)}} END{print c+0}' "$PKT32C") \
    || err "$PKT32C $pfx occurrence scan failed"
  [ "$p32occ" = "$max" ] || err "$PKT32C $pfx IDs are missing, duplicated, or smuggled"
}
p32set F32C-D11-C 8 'PROPOSED — UNSELECTED — TARGET EVIDENCE REQUIRED' construction
p32set F32C-D11-E 10 'PLANNED — NOT RUN — NO EVIDENCE' evidence
p32set F32C-D11-Q 12 'OWNER QUESTION — UNANSWERED — NO RESPONSE REQUESTED — NOT READY FOR SELECTION' questions
p32set F32C-D11-F 22 'PROPOSED — UNSELECTED — TARGET EVIDENCE REQUIRED' failures
p32q001='| F32C-D11-Q-001 | Does D-10 “failure releases no artifact or partial output” prohibit any signed-PSBT bytes or transport fragments becoming observable through either route after an attempt later fails, including QR frames already displayed and SD prefixes or objects already written, or only prohibit recognizing or presenting an incomplete route representation as a complete signed-PSBT output? Interrupted QR cannot retract observed frames; frames from interrupted or retried cycles may be accumulated by a receiver; conventional SD staging cannot guarantee no residue; neither route may silently assume the weaker interpretation. | OWNER QUESTION — UNANSWERED — NO RESPONSE REQUESTED — NOT READY FOR SELECTION |'
p32q001n=$(grep -cFx -e "$p32q001" "$PKT32C")
p32rc=$?
[ "$p32rc" -le 1 ] || err "$PKT32C exact Q-001 scan failed"
[ "$p32q001n" = 1 ] || err "$PKT32C Q-001 is not the exact route-general ambiguity row"
# Closed-world union: every exact F32C-D11 token and every row-leading
# packet ID must be exactly the ordered C/E/Q/F union. Unknown families,
# malformed or suffixed IDs, prose smuggling, duplicate rows, and extra
# table sections all fail. Supporting self-authored evidence only.
: > "$tmpdir/p32.union.exp" || err "$PKT32C union expected-list init failed"
for p32spec in 'C 8' 'E 10' 'Q 12' 'F 22'; do
  set -- $p32spec; p32i=1
  while [ "$p32i" -le "$2" ]; do
    printf 'F32C-D11-%s-%03d\n' "$1" "$p32i" >> "$tmpdir/p32.union.exp" \
      || err "$PKT32C union expected-ID generation failed"
    p32i=$((p32i + 1))
  done
done
grep '^| F32C-D11-' "$PKT32C" > "$tmpdir/p32.union.rows"
p32rc=$?
[ "$p32rc" -eq 0 ] || err "$PKT32C global row enumeration failed or found no rows"
p32raw=$(awk 'END { print NR }' "$tmpdir/p32.union.rows") || err "$PKT32C raw row count failed"
[ "$p32raw" = 52 ] || err "$PKT32C raw F32C-D11 row count is $p32raw, expected exactly 52"
sed -n 's/^| \(F32C-D11-[CEQF]-[0-9][0-9][0-9]\) |.*$/\1/p' "$tmpdir/p32.union.rows" > "$tmpdir/p32.union.rowids" \
  || err "$PKT32C global row-ID extraction failed"
p32ids=$(awk 'END { print NR }' "$tmpdir/p32.union.rowids") || err "$PKT32C valid row-ID count failed"
[ "$p32ids" = "$p32raw" ] || err "$PKT32C only $p32ids of $p32raw rows carry exact valid IDs"
cmp -s "$tmpdir/p32.union.exp" "$tmpdir/p32.union.rowids"
p32rc=$?
[ "$p32rc" -eq 0 ] || err "$PKT32C row-leading IDs are not the exact ordered C/E/Q/F union"
awk '{s=$0; while (match(s,/F32C-D11-[A-Z]-[0-9][0-9][0-9]/)) {print substr(s,RSTART,RLENGTH); s=substr(s,RSTART+RLENGTH)}}' \
  "$PKT32C" > "$tmpdir/p32.union.tokens" || err "$PKT32C global ID-token enumeration failed"
cmp -s "$tmpdir/p32.union.exp" "$tmpdir/p32.union.tokens"
p32rc=$?
[ "$p32rc" -eq 0 ] || err "$PKT32C exact ID tokens are missing, duplicated, reordered, unknown, or smuggled"
# Closed-world broad token scan: enumerate every maximal F32C-D11-prefixed
# token over letters, digits, underscore, hyphen, and literal asterisk
# (any family width, digit width, suffix, or delimiter residue) and
# require each to be an exact allowed ID or the single permitted exact
# E-family glob token F32C-D11-E-*. Anything else fails closed.
awk '{s=$0; while (match(s,/F32C-D11-[A-Za-z0-9_*-]*/)) {print substr(s,RSTART,RLENGTH); s=substr(s,RSTART+RLENGTH)}}' \
  "$PKT32C" > "$tmpdir/p32.union.broad" || err "$PKT32C broad F32C-D11 token enumeration failed"
[ -s "$tmpdir/p32.union.broad" ] || err "$PKT32C broad F32C-D11 token enumeration produced no tokens"
sort -u "$tmpdir/p32.union.broad" > "$tmpdir/p32.union.broad.sorted" || err "$PKT32C broad token sort failed"
sort -u "$tmpdir/p32.union.exp" > "$tmpdir/p32.union.allow" || err "$PKT32C expected union sort failed"
printf 'F32C-D11-E-*\n' >> "$tmpdir/p32.union.allow" || err "$PKT32C family-glob allowance append failed"
sort -o "$tmpdir/p32.union.allow" "$tmpdir/p32.union.allow" || err "$PKT32C allowance resort failed"
comm -23 "$tmpdir/p32.union.broad.sorted" "$tmpdir/p32.union.allow" > "$tmpdir/p32.union.stray" \
  || err "$PKT32C stray-token comparison failed"
[ ! -s "$tmpdir/p32.union.stray" ] || err "$PKT32C contains F32C-D11-prefixed tokens outside the exact allowed IDs"
p32glob=$(grep -cF -e 'F32C-D11-E-*' "$PKT32C"); p32rc=$?
[ "$p32rc" -le 1 ] || err "$PKT32C family-glob scan failed"
[ "$p32glob" = 1 ] || err "$PKT32C family-glob mention F32C-D11-E-* must occur exactly once"
p32globtok=$(grep -cxF -e 'F32C-D11-E-*' "$tmpdir/p32.union.broad"); p32rc=$?
[ "$p32rc" -le 1 ] || err "$PKT32C family-glob token count scan failed"
[ "$p32globtok" = 1 ] || err "$PKT32C exact glob token F32C-D11-E-* must occur exactly once"
# Fail-closed regression probes: the broad closed-world scan must reject
# unknown and multi-letter families, wrong digit widths, suffixes, and
# malformed delimiters. Supporting self-authored evidence only.
cat > "$tmpdir/p32.probe.bad" <<'QK_F32C_PROBE_EOF' || err "F3.2c probe sample generation failed"
F32C-D11-XX-001
F32C-D11-F-01
F32C-D11-F-0001
F32C-D11-F-001X
F32C-D11-F_001
F32C-D11-FF-010
F32C-D11-E-***
QK_F32C_PROBE_EOF
awk '{s=$0; while (match(s,/F32C-D11-[A-Za-z0-9_*-]*/)) {print substr(s,RSTART,RLENGTH); s=substr(s,RSTART+RLENGTH)}}' \
  "$tmpdir/p32.probe.bad" > "$tmpdir/p32.probe.tok" || err "F3.2c probe tokenization failed"
p32ptok=$(awk 'END { print NR }' "$tmpdir/p32.probe.tok") || err "F3.2c probe token count failed"
[ "$p32ptok" = 7 ] || err "F3.2c probe tokenizer missed malformed IDs ($p32ptok of 7)"
sort -u "$tmpdir/p32.probe.tok" > "$tmpdir/p32.probe.tok.sorted" || err "F3.2c probe token sort failed"
comm -23 "$tmpdir/p32.probe.tok.sorted" "$tmpdir/p32.union.allow" > "$tmpdir/p32.probe.stray" \
  || err "F3.2c probe comparison failed"
p32pstray=$(awk 'END { print NR }' "$tmpdir/p32.probe.stray") || err "F3.2c probe stray count failed"
[ "$p32pstray" = 7 ] || err "F3.2c closed-world probe failed to reject malformed IDs ($p32pstray of 7)"
cat > "$tmpdir/p32.failure.expected" <<'QK_F32C_FAILURE_ROWS_EOF' || err "$PKT32C failure expected rows generation failed"
| F32C-D11-F-001 | preapproval context change | rebuild review | no reuse | PROPOSED — UNSELECTED — TARGET EVIDENCE REQUIRED |
| F32C-D11-F-002 | postapproval bound change | D11-X1 plus full reparse/review | no stale approval | PROPOSED — UNSELECTED — TARGET EVIDENCE REQUIRED |
| F32C-D11-F-003 | signing uncertainty or failure | D11-X2; no representation leaves trusted volatile state | no retry, re-sign, or one-signature output | PROPOSED — UNSELECTED — TARGET EVIDENCE REQUIRED |
| F32C-D11-F-004 | output parse, delta, signature, or final-field failure | no route output begins | no ready claim | PROPOSED — UNSELECTED — TARGET EVIDENCE REQUIRED |
| F32C-D11-F-005 | QR planning or self-check failure before display | no frames shown | no partial stream | PROPOSED — UNSELECTED — TARGET EVIDENCE REQUIRED |
| F32C-D11-F-006 | QR interruption after display | stop further frames; previously observed frames cannot be withdrawn or assumed absent; Q-001 remains unresolved | no completion or delivery claim; no automatic SD fallback | PROPOSED — UNSELECTED — TARGET EVIDENCE REQUIRED |
| F32C-D11-F-007 | SD absent, read-only, full, or failure before create | no object | no overwrite | PROPOSED — UNSELECTED — TARGET EVIDENCE REQUIRED |
| F32C-D11-F-008 | collision or exclusive-create failure | end attempt | no truncate or replace | PROPOSED — UNSELECTED — TARGET EVIDENCE REQUIRED |
| F32C-D11-F-009 | short write or removal during write | end attempt and attachment epoch; residue may remain; Q-001 remains unresolved | no commit or completion; no continue after reinsertion | PROPOSED — UNSELECTED — TARGET EVIDENCE REQUIRED |
| F32C-D11-F-010 | sync or close failure | no commit; residue may remain | no durability claim | PROPOSED — UNSELECTED — TARGET EVIDENCE REQUIRED |
| F32C-D11-F-011 | temp readback mismatch | no commit; orphan handling remains open | no repair or normalization | PROPOSED — UNSELECTED — TARGET EVIDENCE REQUIRED |
| F32C-D11-F-012 | no-replace visibility-transition failure | no final or completion claim | no overwrite | PROPOSED — UNSELECTED — TARGET EVIDENCE REQUIRED |
| F32C-D11-F-013 | metadata-barrier failure | durability unknown | no completion | PROPOSED — UNSELECTED — TARGET EVIDENCE REQUIRED |
| F32C-D11-F-014 | final readback or reparse mismatch | stop; final-name bytes may already be observable and cannot be withdrawn; Q-001 remains unresolved | no completion, repair, overwrite, normalization, or treatment as the verified artifact | PROPOSED — UNSELECTED — TARGET EVIDENCE REQUIRED |
| F32C-D11-F-015 | power cut after visibility transition | ambiguous final object and lost session | no auto-adoption or retroactive success | PROPOSED — UNSELECTED — TARGET EVIDENCE REQUIRED |
| F32C-D11-F-016 | orphan next session | only later-selected bounded handling | no resume or secure-erasure claim | PROPOSED — UNSELECTED — TARGET EVIDENCE REQUIRED |
| F32C-D11-F-017 | media replacement | attachment epoch ends; Q-002 decides attempt-versus-approval invalidation | never treat replacement as the same medium | PROPOSED — UNSELECTED — TARGET EVIDENCE REQUIRED |
| F32C-D11-F-018 | first route succeeds and second fails | Q-004 reviewed policy applies; first release cannot be undone | no silent downgrade | PROPOSED — UNSELECTED — TARGET EVIDENCE REQUIRED |
| F32C-D11-F-019 | retry request | same frozen bytes only if later selected; cross-attempt QR accumulation remains evidence-relevant | never re-sign or change plan | PROPOSED — UNSELECTED — TARGET EVIDENCE REQUIRED |
| F32C-D11-F-020 | restart | new session and review | no old-approval resume | PROPOSED — UNSELECTED — TARGET EVIDENCE REQUIRED |
| F32C-D11-F-021 | receiver acknowledgement | untrusted UX only | no cryptographic or coordinator acceptance | PROPOSED — UNSELECTED — TARGET EVIDENCE REQUIRED |
| F32C-D11-F-022 | any qk-io mutation | fatal; stop further output; if artifact-bearing I/O began, observed fragments or residue cannot be withdrawn and Q-001 remains unresolved | no continuation, normalization, completion, or treatment of altered bytes as the signed artifact | PROPOSED — UNSELECTED — TARGET EVIDENCE REQUIRED |
QK_F32C_FAILURE_ROWS_EOF
grep '^| F32C-D11-F-' "$PKT32C" > "$tmpdir/p32.failure.actual" || err "$PKT32C failure-row enumeration failed"
cmp -s "$tmpdir/p32.failure.expected" "$tmpdir/p32.failure.actual"
p32rc=$?
[ "$p32rc" -eq 0 ] || err "$PKT32C failure rows or outcomes are not exact"
# Closed-world pipe transcript: every '|'-carrying line in the packet
# must be exactly the ordered concatenation of the four closed tables
# below (60 lines, no prose pipes); leading-pipe-omitted, indented,
# extra-cell, appended, dropped, and reordered rows and any extra table
# section all fail. Supporting self-authored evidence only.
grep '|' "$PKT32C" > "$tmpdir/p32.pipes.act"
p32rc=$?
[ "$p32rc" -eq 0 ] || err "$PKT32C pipe-line enumeration failed or found no pipe lines"
p32pn=$(awk 'END { print NR }' "$tmpdir/p32.pipes.act") || err "$PKT32C pipe-line count failed"
[ "$p32pn" = 60 ] || err "$PKT32C pipe-carrying line count is $p32pn, expected exactly 60"
cat > "$tmpdir/p32.pipes.exp" <<'QK_F32C_PIPES_EOF' || err "$PKT32C expected pipe transcript generation failed"
| ID | Construction input | Status |
| --- | --- | --- |
| F32C-D11-C-001 | eligible retained artifact and approval/route binding | PROPOSED — UNSELECTED — TARGET EVIDENCE REQUIRED |
| F32C-D11-C-002 | semantic route-set/media-attempt/session vocabulary | PROPOSED — UNSELECTED — TARGET EVIDENCE REQUIRED |
| F32C-D11-C-003 | new-output naming/collision/input-output separation/no overwrite; no concrete name or hash | PROPOSED — UNSELECTED — TARGET EVIDENCE REQUIRED |
| F32C-D11-C-004 | proposed SD staging, write, sync, close, reopen, compare, reparse, exact-delta, signature, no-replace publication, and final reopen sequence | PROPOSED — UNSELECTED — TARGET EVIDENCE REQUIRED |
| F32C-D11-C-005 | filesystem, controller, cache, sync, rename, and directory durability assumptions UNKNOWN; refuse SD if reliable no-replace publication cannot be proven | PROPOSED — UNSELECTED — TARGET EVIDENCE REQUIRED |
| F32C-D11-C-006 | cancellation/removal/power-cut/short-write/corrupt/full/read-only/write-protected/failure/orphan handling; no cleanup guarantee | PROPOSED — UNSELECTED — TARGET EVIDENCE REQUIRED |
| F32C-D11-C-007 | retry/idempotence/stale/duplicate alternatives; never blind re-sign; retry policy unselected | PROPOSED — UNSELECTED — TARGET EVIDENCE REQUIRED |
| F32C-D11-C-008 | QR lifecycle/cross-route equivalence/receiver and second-implementation evidence | PROPOSED — UNSELECTED — TARGET EVIDENCE REQUIRED |
| ID | Planned evidence | Status |
| --- | --- | --- |
| F32C-D11-E-001 | exact-target filesystem/controller/cache/write ordering | PLANNED — NOT RUN — NO EVIDENCE |
| F32C-D11-E-002 | forced power loss at every transition | PLANNED — NOT RUN — NO EVIDENCE |
| F32C-D11-E-003 | removal at every read/write/sync/close/reopen/publish boundary | PLANNED — NOT RUN — NO EVIDENCE |
| F32C-D11-E-004 | full/read-only/write-protected/damaged/stale/duplicate media | PLANNED — NOT RUN — NO EVIDENCE |
| F32C-D11-E-005 | short-write/I/O/corruption/inconsistent metadata | PLANNED — NOT RUN — NO EVIDENCE |
| F32C-D11-E-006 | collision/input-output alias/no-overwrite | PLANNED — NOT RUN — NO EVIDENCE |
| F32C-D11-E-007 | retry/idempotence/orphan/stale-attempt | PLANNED — NOT RUN — NO EVIDENCE |
| F32C-D11-E-008 | independent reopen/byte compare/reparse/exact-delta/signatures | PLANNED — NOT RUN — NO EVIDENCE |
| F32C-D11-E-009 | QR/SD decoded-byte equivalence/coordinator interoperability | PLANNED — NOT RUN — NO EVIDENCE |
| F32C-D11-E-010 | human completion/safe-removal/error/retry plus independent second implementation | PLANNED — NOT RUN — NO EVIDENCE |
| ID | Owner question | Status |
| --- | --- | --- |
| F32C-D11-Q-001 | Does D-10 “failure releases no artifact or partial output” prohibit any signed-PSBT bytes or transport fragments becoming observable through either route after an attempt later fails, including QR frames already displayed and SD prefixes or objects already written, or only prohibit recognizing or presenting an incomplete route representation as a complete signed-PSBT output? Interrupted QR cannot retract observed frames; frames from interrupted or retried cycles may be accumulated by a receiver; conventional SD staging cannot guarantee no residue; neither route may silently assume the weaker interpretation. | OWNER QUESTION — UNANSWERED — NO RESPONSE REQUESTED — NOT READY FOR SELECTION |
| F32C-D11-Q-002 | Must exact physical SD attachment epoch be present/approval-bound, or may logical SD route accept later insertion/replacement; reconcile broad media-change invalidation. | OWNER QUESTION — UNANSWERED — NO RESPONSE REQUESTED — NOT READY FOR SELECTION |
| F32C-D11-Q-003 | One approval: exactly one route or closed QR+SD route set. | OWNER QUESTION — UNANSWERED — NO RESPONSE REQUESTED — NOT READY FOR SELECTION |
| F32C-D11-Q-004 | If both, all required vs either sufficient vs independent outcomes; first succeeds/second fails. | OWNER QUESTION — UNANSWERED — NO RESPONSE REQUESTED — NOT READY FOR SELECTION |
| F32C-D11-Q-005 | Same frozen artifact retry under unchanged session vs new review; neither allows re-signing. | OWNER QUESTION — UNANSWERED — NO RESPONSE REQUESTED — NOT READY FOR SELECTION |
| F32C-D11-Q-006 | Same SD for input/output vs distinct already-bound media; prove directory/allocation writes cannot lose/overwrite input. | OWNER QUESTION — UNANSWERED — NO RESPONSE REQUESTED — NOT READY FOR SELECTION |
| F32C-D11-Q-007 | Eligible visibility/commit construction and exact evidence before any atomic/complete claim. | OWNER QUESTION — UNANSWERED — NO RESPONSE REQUESTED — NOT READY FOR SELECTION |
| F32C-D11-Q-008 | Filename and bounded collision policy without input overwrite, wallet metadata, or silent post-approval change. | OWNER QUESTION — UNANSWERED — NO RESPONSE REQUESTED — NOT READY FOR SELECTION |
| F32C-D11-Q-009 | Orphan/ambiguous final objects: leave-ignore, quarantine, or bounded best-effort cleanup; no secure erasure/resume. | OWNER QUESTION — UNANSWERED — NO RESPONSE REQUESTED — NOT READY FOR SELECTION |
| F32C-D11-Q-010 | Complete QR self-decode/reparse before display and wording separating presentation from receipt. | OWNER QUESTION — UNANSWERED — NO RESPONSE REQUESTED — NOT READY FOR SELECTION |
| F32C-D11-Q-011 | Deterministic insertion position/order of two new partial signatures while old records keep exact bytes/relative order. | OWNER QUESTION — UNANSWERED — NO RESPONSE REQUESTED — NOT READY FOR SELECTION |
| F32C-D11-Q-012 | Which semantic fields later enter D-09 commitment; serialization/hash/domain remain D-09-open. | OWNER QUESTION — UNANSWERED — NO RESPONSE REQUESTED — NOT READY FOR SELECTION |
| ID | Event | Proposed fail-closed result | Forbidden conclusion/action | Status |
| --- | --- | --- | --- | --- |
| F32C-D11-F-001 | preapproval context change | rebuild review | no reuse | PROPOSED — UNSELECTED — TARGET EVIDENCE REQUIRED |
| F32C-D11-F-002 | postapproval bound change | D11-X1 plus full reparse/review | no stale approval | PROPOSED — UNSELECTED — TARGET EVIDENCE REQUIRED |
| F32C-D11-F-003 | signing uncertainty or failure | D11-X2; no representation leaves trusted volatile state | no retry, re-sign, or one-signature output | PROPOSED — UNSELECTED — TARGET EVIDENCE REQUIRED |
| F32C-D11-F-004 | output parse, delta, signature, or final-field failure | no route output begins | no ready claim | PROPOSED — UNSELECTED — TARGET EVIDENCE REQUIRED |
| F32C-D11-F-005 | QR planning or self-check failure before display | no frames shown | no partial stream | PROPOSED — UNSELECTED — TARGET EVIDENCE REQUIRED |
| F32C-D11-F-006 | QR interruption after display | stop further frames; previously observed frames cannot be withdrawn or assumed absent; Q-001 remains unresolved | no completion or delivery claim; no automatic SD fallback | PROPOSED — UNSELECTED — TARGET EVIDENCE REQUIRED |
| F32C-D11-F-007 | SD absent, read-only, full, or failure before create | no object | no overwrite | PROPOSED — UNSELECTED — TARGET EVIDENCE REQUIRED |
| F32C-D11-F-008 | collision or exclusive-create failure | end attempt | no truncate or replace | PROPOSED — UNSELECTED — TARGET EVIDENCE REQUIRED |
| F32C-D11-F-009 | short write or removal during write | end attempt and attachment epoch; residue may remain; Q-001 remains unresolved | no commit or completion; no continue after reinsertion | PROPOSED — UNSELECTED — TARGET EVIDENCE REQUIRED |
| F32C-D11-F-010 | sync or close failure | no commit; residue may remain | no durability claim | PROPOSED — UNSELECTED — TARGET EVIDENCE REQUIRED |
| F32C-D11-F-011 | temp readback mismatch | no commit; orphan handling remains open | no repair or normalization | PROPOSED — UNSELECTED — TARGET EVIDENCE REQUIRED |
| F32C-D11-F-012 | no-replace visibility-transition failure | no final or completion claim | no overwrite | PROPOSED — UNSELECTED — TARGET EVIDENCE REQUIRED |
| F32C-D11-F-013 | metadata-barrier failure | durability unknown | no completion | PROPOSED — UNSELECTED — TARGET EVIDENCE REQUIRED |
| F32C-D11-F-014 | final readback or reparse mismatch | stop; final-name bytes may already be observable and cannot be withdrawn; Q-001 remains unresolved | no completion, repair, overwrite, normalization, or treatment as the verified artifact | PROPOSED — UNSELECTED — TARGET EVIDENCE REQUIRED |
| F32C-D11-F-015 | power cut after visibility transition | ambiguous final object and lost session | no auto-adoption or retroactive success | PROPOSED — UNSELECTED — TARGET EVIDENCE REQUIRED |
| F32C-D11-F-016 | orphan next session | only later-selected bounded handling | no resume or secure-erasure claim | PROPOSED — UNSELECTED — TARGET EVIDENCE REQUIRED |
| F32C-D11-F-017 | media replacement | attachment epoch ends; Q-002 decides attempt-versus-approval invalidation | never treat replacement as the same medium | PROPOSED — UNSELECTED — TARGET EVIDENCE REQUIRED |
| F32C-D11-F-018 | first route succeeds and second fails | Q-004 reviewed policy applies; first release cannot be undone | no silent downgrade | PROPOSED — UNSELECTED — TARGET EVIDENCE REQUIRED |
| F32C-D11-F-019 | retry request | same frozen bytes only if later selected; cross-attempt QR accumulation remains evidence-relevant | never re-sign or change plan | PROPOSED — UNSELECTED — TARGET EVIDENCE REQUIRED |
| F32C-D11-F-020 | restart | new session and review | no old-approval resume | PROPOSED — UNSELECTED — TARGET EVIDENCE REQUIRED |
| F32C-D11-F-021 | receiver acknowledgement | untrusted UX only | no cryptographic or coordinator acceptance | PROPOSED — UNSELECTED — TARGET EVIDENCE REQUIRED |
| F32C-D11-F-022 | any qk-io mutation | fatal; stop further output; if artifact-bearing I/O began, observed fragments or residue cannot be withdrawn and Q-001 remains unresolved | no continuation, normalization, completion, or treatment of altered bytes as the signed artifact | PROPOSED — UNSELECTED — TARGET EVIDENCE REQUIRED |
QK_F32C_PIPES_EOF
cmp -s "$tmpdir/p32.pipes.exp" "$tmpdir/p32.pipes.act"
p32rc=$?
[ "$p32rc" -eq 0 ] || err "$PKT32C pipe-carrying lines are not exactly the four closed tables"
# Fail-closed pipe canaries: appended, dropped, indented, leading-pipe-
# omitted, and extra-cell variants must each break the byte compare.
{ cat "$tmpdir/p32.pipes.exp"; printf '%s\n' '| F32C-D11-C-001 | smuggled duplicate | EXTRA |'; } > "$tmpdir/p32.pipes.bad1" || err "pipe canary 1 generation failed"
sed '$d' "$tmpdir/p32.pipes.exp" > "$tmpdir/p32.pipes.bad2" || err "pipe canary 2 generation failed"
sed '1s/^/ /' "$tmpdir/p32.pipes.exp" > "$tmpdir/p32.pipes.bad3" || err "pipe canary 3 generation failed"
sed '3s/^|//' "$tmpdir/p32.pipes.exp" > "$tmpdir/p32.pipes.bad4" || err "pipe canary 4 generation failed"
sed '3s/|$/| EXTRA |/' "$tmpdir/p32.pipes.exp" > "$tmpdir/p32.pipes.bad5" || err "pipe canary 5 generation failed"
for p32badp in "$tmpdir/p32.pipes.bad1" "$tmpdir/p32.pipes.bad2" "$tmpdir/p32.pipes.bad3" "$tmpdir/p32.pipes.bad4" "$tmpdir/p32.pipes.bad5"; do
  cmp -s "$tmpdir/p32.pipes.exp" "$p32badp"
  p32rc=$?
  [ "$p32rc" -eq 1 ] || err "pipe transcript canary failed to detect a mutated table (cmp exit $p32rc for $p32badp)"
done
# Closed-world heading transcript: every '#'-carrying line in the packet
# must be exactly the one H1 plus the eleven H2 headings below, in order
# (12 lines, no prose hashes); extra, renamed, reordered, indented, or
# deeper ATX headings all fail. Supporting self-authored evidence only.
grep '#' "$PKT32C" > "$tmpdir/p32.heads.act"
p32rc=$?
[ "$p32rc" -eq 0 ] || err "$PKT32C heading-line enumeration failed or found no hash lines"
p32hn=$(awk 'END { print NR }' "$tmpdir/p32.heads.act") || err "$PKT32C heading-line count failed"
[ "$p32hn" = 12 ] || err "$PKT32C hash-carrying line count is $p32hn, expected exactly 12"
cat > "$tmpdir/p32.heads.exp" <<'QK_F32C_HEADS_EOF' || err "$PKT32C expected heading transcript generation failed"
# QK-F3.2c — D-11 Media/Write Lifecycle Construction and Readiness Packet (Non-Binding)
## Standing, source boundary, and labels
## Inherited fixed requirements and recorded directions
## Analysis-only vocabulary
## Construction rows
## Evidence rows
## Owner questions
## Mandatory contradiction warning
## Proposed state and route analyses
## Closed-world failure matrix
## Dependency and evidence boundary
## Explicit do-not-claim boundary
QK_F32C_HEADS_EOF
cmp -s "$tmpdir/p32.heads.exp" "$tmpdir/p32.heads.act"
p32rc=$?
[ "$p32rc" -eq 0 ] || err "$PKT32C hash-carrying lines are not exactly the one H1 and eleven H2 headings"
# Fail-closed heading canaries: appended, dropped, indented, and renamed
# heading variants must each break the byte compare.
{ cat "$tmpdir/p32.heads.exp"; printf '%s\n' '### Smuggled deeper heading'; } > "$tmpdir/p32.heads.bad1" || err "heading canary 1 generation failed"
sed '$d' "$tmpdir/p32.heads.exp" > "$tmpdir/p32.heads.bad2" || err "heading canary 2 generation failed"
sed '2s/^/ /' "$tmpdir/p32.heads.exp" > "$tmpdir/p32.heads.bad3" || err "heading canary 3 generation failed"
sed '2s/labels/labels renamed/' "$tmpdir/p32.heads.exp" > "$tmpdir/p32.heads.bad4" || err "heading canary 4 generation failed"
for p32badh in "$tmpdir/p32.heads.bad1" "$tmpdir/p32.heads.bad2" "$tmpdir/p32.heads.bad3" "$tmpdir/p32.heads.bad4"; do
  cmp -s "$tmpdir/p32.heads.exp" "$p32badh"
  p32rc=$?
  [ "$p32rc" -eq 1 ] || err "heading transcript canary failed to detect a mutated heading set (cmp exit $p32rc for $p32badh)"
done
# Setext headings carry no '#', a one-column GFM table delimiter line
# (":---", "---:", ":---:") carries no pipe, and either may hide behind
# repeated blockquote '>' prefixes ("> :---", ">> :---:") while still
# rendering, so all bypass the heading and pipe transcripts: forbid any
# full-line '='/'-' run with optional leading/trailing alignment colons
# and any run of blockquote prefixes, with positive canaries proving
# the pattern matches Setext underline runs and pipe-free aligned-table
# delimiter runs alike. Legitimate table separator lines carry pipes
# and never match.
forbid "$PKT32C contains a Setext underline or pipe-free GFM table delimiter run" -E '^[[:blank:]]*(>[[:blank:]]*)*:?(=+|-+):?[[:blank:]]*$' "$PKT32C"
for p32sx in '=' '=====' '-' '-----' '   ---' ':---' '---:' ':---:' '   :---:' '> :---' '>> :---:' '> > ---:'; do
  printf '%s\n' "$p32sx" > "$tmpdir/p32.setext.canary" || err "Setext/GFM delimiter canary generation failed"
  grep -E '^[[:blank:]]*(>[[:blank:]]*)*:?(=+|-+):?[[:blank:]]*$' "$tmpdir/p32.setext.canary" >/dev/null
  p32rc=$?
  [ "$p32rc" -eq 0 ] || err "Setext/GFM delimiter canary pattern failed to match run '$p32sx' (grep exit $p32rc)"
done
printf '%s\n' '| :--- | ---: |' > "$tmpdir/p32.setext.negative" || err "Setext/GFM negative canary generation failed"
grep -E '^[[:blank:]]*(>[[:blank:]]*)*:?(=+|-+):?[[:blank:]]*$' "$tmpdir/p32.setext.negative" >/dev/null
p32rc=$?
[ "$p32rc" -eq 1 ] || err "Setext/GFM delimiter pattern wrongly matched a legitimate piped separator line (grep exit $p32rc)"
# Direct contradictory-claim forbids: none of these case-insensitive
# fixed contradictory phrases may occur anywhere in the packet, in any
# letter case; each would contradict the recorded non-selected,
# unanswered, evidence-absent, unpublished state, and each rejection is
# direct and recorded rather than implied by transcripts. This is a
# closed fixed-phrase list, not exhaustive language coverage.
for p32claim in 'D-11 SELECTED' 'D-11: SELECTED' 'PROFILE ACCEPTED' \
  'OWNER QUESTIONS ANSWERED' 'TARGET EVIDENCE PRESENT' 'GATE CLOSED' \
  'TESTS RUN' 'EVIDENCE RECORDED' 'IMPLEMENTATION ENABLED' \
  'PUBLICATION AUTHORIZED'; do
  p32cn=$(LC_ALL=C grep -ciF -e "$p32claim" "$PKT32C"); p32rc=$?
  [ "$p32rc" -le 1 ] || err "$PKT32C contradictory-claim scan failed"
  [ "$p32cn" = 0 ] || err "$PKT32C contains a contradictory claim: $p32claim"
done
# Fail-closed claim canaries: lowercase and mixed-case variants of the
# fixed phrases must each be counted by the case-insensitive scan, so a
# case-folding regression can never pass silently; a claim-free sample
# must count zero (grep exit 1 tolerated), and a missing-file scan must
# report an error exit greater than 1.
cat > "$tmpdir/p32.claim.canary" <<'QK_F32C_CLAIM_CANARY_EOF' || err "claim canary generation failed"
D-11 selected
d-11: Selected
Profile Accepted
owner questions answered
Target Evidence Present
gate Closed
tests run
Evidence recorded
implementation Enabled
Publication Authorized
QK_F32C_CLAIM_CANARY_EOF
for p32claim in 'D-11 SELECTED' 'D-11: SELECTED' 'PROFILE ACCEPTED' \
  'OWNER QUESTIONS ANSWERED' 'TARGET EVIDENCE PRESENT' 'GATE CLOSED' \
  'TESTS RUN' 'EVIDENCE RECORDED' 'IMPLEMENTATION ENABLED' \
  'PUBLICATION AUTHORIZED'; do
  p32cc=$(LC_ALL=C grep -ciF -e "$p32claim" "$tmpdir/p32.claim.canary"); p32rc=$?
  [ "$p32rc" -eq 0 ] || err "claim canary scan failed for: $p32claim (grep exit $p32rc)"
  [ "$p32cc" = 1 ] || err "case-insensitive claim canary missed a mixed-case variant of: $p32claim"
done
printf 'no claims here\n' > "$tmpdir/p32.claim.zero" || err "claim zero-sample generation failed"
p32cz=$(LC_ALL=C grep -ciF -e 'D-11 SELECTED' "$tmpdir/p32.claim.zero"); p32rc=$?
[ "$p32rc" -eq 1 ] || err "claim zero-stage probe returned unexpected grep exit $p32rc"
[ "$p32cz" = 0 ] || err "claim zero-stage probe counted a phantom claim"
LC_ALL=C grep -ciF -e 'D-11 SELECTED' "$tmpdir/p32.claim.does-not-exist" >/dev/null 2>&1
p32rc=$?
[ "$p32rc" -gt 1 ] || err "claim error-stage probe failed to report a scan error (grep exit $p32rc)"
forbid "$PKT32C authorizes a numeric QK-LIM value" -E 'QK-LIM[-A-Z0-9]*[[:space:]]*(=|:)[[:space:]]*[0-9]' "$PKT32C"
for p32req in \
  'binary `.psbt` only; no base64 or hex autodetection' \
  'input is never overwritten under interruption, retry, or failure' \
  'exactly two new selected-pair PSBT_IN_PARTIAL_SIG records per input' \
  'no route retry may re-sign' \
  'decoded QR payload bytes equal final SD file bytes, never frame bytes' \
  'No automatic fallback is selected.' \
  'no ARTIFACT-BEARING route output begins before D11-S6' \
  'A bounded read-only SD preflight is an unselected candidate that may precede review' \
  'Any bound preflight fact changing after approval goes to D11-X1.' \
  'S9 does not prove receipt, finalization, broadcast, or durability.' \
  'Interrupted QR cannot retract observed frames' \
  'a receiver may accumulate frames across interrupted or retried cycles' \
  'Neither route may silently assume the weaker interpretation.' \
  'QR-Q2 SELF_CHECKED is an explicit candidate branch, not a universal transition' \
  'At most one stream is active; a different artifact requires a reset' \
  'exact-length write success before sync/close' \
  'successful sync/close return before temp readback while not proving durability' \
  'exact temp-byte equality plus `qk-core` fresh reparse before commit' \
  'successful target-proven no-replace visibility-transition return before the metadata barrier while not proving atomicity' \
  'successful target-specific metadata-barrier return before final readback while not proving durability' \
  'exact final-byte equality plus fresh reparse before local completion indication' \
  'QK-F2E-008, QK-F2E-009, and QK-F2E-015 are protocol templates only — NOT RUN — NOT GATE EVIDENCE.' \
  'QK-TST-UNIT-009, QK-TST-DIFF-004, QK-TST-SAN-004, QK-TST-CORP-003, QK-TST-PWR-003, QK-TST-PWR-004, QK-TST-PWR-005, QK-TST-REH-004, and QK-TST-AUD-001 remain PLANNED — NOT RUN.' \
  'OD-05 and OD-06 remain OPEN.' \
  'Packet-local F32C-D11-E-* IDs create no canonical QK-TST, run registration, evidence record, or gate input.' \
  'QK-REQ-BND-003 requires that any intervening input, card, media, session, or state change after approval invalidates approval before signing.' \
  'binding and invalidation for extra factor, descriptor, wallet, profile, and policy-context facts come from the unaccepted profile' \
  'Tested cuts never prove impossibility.'; do
  grep -F -e "$p32req" "$PKT32C" >/dev/null || err "$PKT32C missing semantic boundary: $p32req"
done
forbid "$PKT32C claims D-11 selection" -iE 'D-11 (is|has been|now) selected' "$PKT32C"
forbid "$PKT32C claims target validation" -iE '(target|hardware|media)[^.]* (validated|proven|tested successfully)' "$PKT32C"
forbid "$PKT32C claims atomicity/durability" -iE '(rename|write|close|sync)[^.]* (guarantees|proves) (atomicity|durability)' "$PKT32C"
forbid "$PKT32C retains stale preflight wording" -F 'no route I/O occurs before S6' "$PKT32C"
forbid "$PKT32C retains stale S9 wording" -F 'S9 proves no receipt' "$PKT32C"
forbid "$PKT32C retains stale blanket failure paragraph" -F 'For every row the proposed fail-closed outcome forbids' "$PKT32C"
forbid "$PKT32C contains hidden HTML or link definition" -E '<!--|-->|^\[[^]]+\]:' "$PKT32C"
forbid "$PKT32C contains tab/trailing whitespace" -E '	|[[:blank:]]$' "$PKT32C"
od -An -tx1 "$PKT32C" > "$tmpdir/p32.bytes.raw" || err "$PKT32C od byte scan failed"
[ -s "$tmpdir/p32.bytes.raw" ] || err "$PKT32C od byte scan produced empty output"
tr -d '[:space:]' < "$tmpdir/p32.bytes.raw" > "$tmpdir/p32.bytes.hex" || err "$PKT32C byte normalization failed"
[ -s "$tmpdir/p32.bytes.hex" ] || err "$PKT32C normalized byte scan produced empty output"
p32bad=$(grep -cE '(^efbbbf)|00|0d|e2808[ef]|e280a[a-e]|e281a[6-9]' "$tmpdir/p32.bytes.hex"); p32rc=$?
[ "$p32rc" -le 1 ] || err "$PKT32C control/bidi byte scan failed"
[ "$p32bad" = 0 ] || err "$PKT32C contains BOM, NUL, CR, or actual bidi controls"
[ "$(tail -c 1 "$PKT32C" | od -An -tuC | tr -d '[:space:]')" = 10 ] || err "$PKT32C must end in LF"
[ "$(tail -c 2 "$PKT32C" | od -An -tuC | tr -d '[:space:]')" != 1010 ] || err "$PKT32C must end in exactly one LF"
forbid "$PKT32C contains URL/URI/email" -iE '(https?://|[a-z][a-z0-9+.-]*://|[[:alnum:]_.+-]+@[[:alnum:].-]+)' "$PKT32C"
forbid "$PKT32C contains license application" -E 'SPDX-License-Identifier:|^LICENSE$' "$PKT32C"
forbid "$PKT32C contains extended-key material" -iE '(^|[^0-9A-Za-z])([xyztuv](pub|prv))[1-9A-HJ-NP-Za-km-z]{20,}([^0-9A-Za-z]|$)' "$PKT32C"
forbid "$PKT32C contains WIF material" -E '(^|[^1-9A-HJ-NP-Za-km-z])([5KL9c])[1-9A-HJ-NP-Za-km-z]{49,51}([^1-9A-HJ-NP-Za-km-z]|$)' "$PKT32C"
forbid "$PKT32C contains Base58 address material" -E '(^|[^1-9A-HJ-NP-Za-km-z])([13mn2])[1-9A-HJ-NP-Za-km-z]{25,34}([^1-9A-HJ-NP-Za-km-z]|$)' "$PKT32C"
forbid "$PKT32C contains bech32 address material" -iE '(^|[^0-9a-z])((bc|tb|bcrt)1[02-9ac-hj-np-z]{20,})([^0-9a-z]|$)' "$PKT32C"
forbid "$PKT32C contains raw PSBT material" -E '([c]HNidP|[7]0736274ff)' "$PKT32C"
awk '{ s=$0
  while (match(s, /[A-Za-z0-9+\/=]+/)) {
    t=substr(s,RSTART,RLENGTH)
    if (length(t) >= 44) { print t; exit }
    s=substr(s,RSTART+RLENGTH)
  }
}' "$PKT32C" > "$tmpdir/p32.base64"
p32rc=$?
[ "$p32rc" -eq 0 ] || err "$PKT32C base64 material scan failed (awk exit $p32rc)"
[ ! -s "$tmpdir/p32.base64" ] || err "$PKT32C contains base64-like payload material"
command -v iconv > "$tmpdir/p32.iconv.path" 2>/dev/null || err "iconv unavailable for strict UTF-8 validation"
[ -s "$tmpdir/p32.iconv.path" ] || err "iconv lookup produced empty output"
iconv -f UTF-8 -t UTF-8 "$PKT32C" > "$tmpdir/p32.utf8" 2> "$tmpdir/p32.iconv.err"
p32rc=$?
[ "$p32rc" -eq 0 ] || err "$PKT32C is not strict UTF-8 (iconv exit $p32rc)"
[ -s "$tmpdir/p32.utf8" ] || err "$PKT32C UTF-8 validation produced empty output"
cmp -s "$PKT32C" "$tmpdir/p32.utf8"
p32rc=$?
[ "$p32rc" -eq 0 ] || err "$PKT32C UTF-8 validation changed bytes"
printf '\300\257' > "$tmpdir/p32.utf8.overlong" || err "UTF-8 overlong regression generation failed"
printf '\342\202' > "$tmpdir/p32.utf8.truncated" || err "UTF-8 truncated regression generation failed"
printf '\377' > "$tmpdir/p32.utf8.invalid" || err "UTF-8 invalid regression generation failed"
for p32badutf in "$tmpdir/p32.utf8.overlong" "$tmpdir/p32.utf8.truncated" "$tmpdir/p32.utf8.invalid"; do
  iconv -f UTF-8 -t UTF-8 "$p32badutf" > "$tmpdir/p32.utf8.badout" 2>/dev/null
  p32rc=$?
  [ "$p32rc" -ne 0 ] || err "iconv accepted malformed UTF-8 regression input $p32badutf"
done

# F3.2d Q-001 owner-clarification record: the whole-record blob is the
# primary closed-world identity invariant. The lexical and structural
# checks below are supporting evidence only, never self-authentication,
# independent audit proof, or a trust anchor.
CLR32D=docs/f3/F3.2D-D11-Q001-OWNER-CLARIFICATION-RECORD.md
[ -f "$CLR32D" ] || err "$CLR32D missing"
q1blob=a996a6d7c2bfa3a15109085475868410fe354422
q1blobact=$(git --no-optional-locks hash-object -- "$CLR32D"); q1rc=$?
[ "$q1rc" -eq 0 ] || err "$CLR32D whole-record blob scan failed (exit $q1rc)"
q1blobfmt=$(printf '%s\n' "$q1blobact" | grep -cE '^[0-9a-f]{40}$'); q1rc=$?
[ "$q1rc" -le 1 ] || err "$CLR32D whole-record blob format scan failed"
[ "$q1blobfmt" = 1 ] || err "$CLR32D whole-record blob output is not one lowercase 40-hex OID"
[ "$q1blobact" = "$q1blob" ] || err "$CLR32D differs from the reviewed whole-record blob"
q1title='# F3.2d D-11 Q-001 Owner-Clarification Record (Non-Enacting)'
q1status='STATUS: OWNER CLARIFICATION RECORDED — NON-ENACTING — F32C-D11-Q-001 FAILURE/COMPLETION MEANING CLARIFIED — D-11 NOT SELECTED — D-11 EVIDENCE/CONSTRUCTION-BLOCKED — F32C-D11-Q-002 THROUGH F32C-D11-Q-012 UNANSWERED — PSBT PROFILE NOT ACCEPTED — D-09 AND EVERY QK-LIM OPEN — NO IMPLEMENTATION — NO TESTING OR MEDIA I/O — NO QK-TST/EVIDENCE/GATE CHANGE — NO LICENSE APPLICATION — NO HARDWARE, FIRMWARE, SETTINGS, OR CREDENTIAL CHANGE — LOCAL AND UNPUBLISHED.'
q1end='END OF RECORD — F32C-D11-Q-001 OWNER CLARIFICATION RECORDED — NON-ENACTING — D-11 NOT SELECTED — Q-002 THROUGH Q-012 UNANSWERED — TARGET EVIDENCE ABSENT — D-09 AND EVERY QK-LIM OPEN — PSBT PROFILE NOT ACCEPTED — LOCAL AND UNPUBLISHED.'
sed -n '1p' "$CLR32D" > "$tmpdir/q1.title.act"; q1rc=$?
[ "$q1rc" -eq 0 ] || err "$CLR32D title read failed (exit $q1rc)"
[ -s "$tmpdir/q1.title.act" ] || err "$CLR32D title read produced empty output"
printf '%s\n' "$q1title" > "$tmpdir/q1.title.exp" \
  || err "$CLR32D title fixture generation failed"
cmp -s "$tmpdir/q1.title.exp" "$tmpdir/q1.title.act"; q1rc=$?
[ "$q1rc" -eq 0 ] || err "$CLR32D exact title is not first"
tail -n 1 "$CLR32D" > "$tmpdir/q1.end.act"; q1rc=$?
[ "$q1rc" -eq 0 ] || err "$CLR32D terminal-line read failed (exit $q1rc)"
[ -s "$tmpdir/q1.end.act" ] || err "$CLR32D terminal-line read produced empty output"
printf '%s\n' "$q1end" > "$tmpdir/q1.end.exp" \
  || err "$CLR32D terminal-line fixture generation failed"
cmp -s "$tmpdir/q1.end.exp" "$tmpdir/q1.end.act"; q1rc=$?
[ "$q1rc" -eq 0 ] || err "$CLR32D exact terminal line missing"
cat > "$tmpdir/q1.essential" <<'QK_F32D_Q001_ESSENTIAL_EOF' || err "$CLR32D essential-line fixture generation failed"
- Source base: `e4cdf7771e189fc0f729358334aafd35177048c6`.
- Source packet: `docs/f3/F3.2C-D11-MEDIA-WRITE-LIFECYCLE-CONSTRUCTION-PACKET.md` at that source base.
- Source packet Git blob: `b4594210975940df71b0e941841320d11defaa4c`.
- The source base and packet blob are audit locators and supporting byte-identity references only. They are not authentication, audit proof, or trust anchors.
- Preparation and independent read-only audit were authorized by `QK-AUTH-F3.2D-D11-Q001-CLR-001`. Publication was not authorized.
F32C-D11-Q-001 DISPOSITION: OWNER CLARIFICATION RECORDED — NON-ENACTING — D-11 NOT SELECTED.
- The source F3.2c packet remains byte-identical.
The Q-001 “no retry” clarification does not answer Q-005 future-new-attempt policy. The Q-001 “no automatic fallback” clarification does not answer Q-003 or Q-004 route cardinality or outcomes.
- D-11 remains EVIDENCE/CONSTRUCTION-BLOCKED and NOT SELECTED.
- OD-05 and OD-06 remain OPEN.
- Tests remain PLANNED — NOT RUN. No test or media I/O was run for this record.
- Gates A–E remain OPEN. STOP-SHIP remains unchanged.
QK_F32D_Q001_ESSENTIAL_EOF
q1exp=$(awk 'END {print NR+0}' "$tmpdir/q1.essential") || err "$CLR32D essential-line fixture count failed"
[ "$q1exp" = 12 ] || err "$CLR32D essential-line fixture is incomplete (found $q1exp of 12)"
q1proc=0
while IFS= read -r q1line; do
  q1n=$(grep -cFx -e "$q1line" "$CLR32D"); q1rc=$?
  [ "$q1rc" -le 1 ] || err "$CLR32D exact essential-line scan failed"
  [ "$q1n" = 1 ] || err "$CLR32D essential line must occur exactly once: $q1line"
  q1proc=$((q1proc + 1))
done < "$tmpdir/q1.essential"
[ "$q1proc" = 12 ] || err "$CLR32D essential-line loop processed $q1proc of 12 lines"
# The canonical STATUS line is full-line bound, and every STATUS:
# occurrence in any letter case is counted globally so indentation,
# blockquotes, prose, and same-line duplication cannot hide a second one.
q1statuslines=$(grep -c '^STATUS:' "$CLR32D"); q1rc=$?
[ "$q1rc" -eq 0 ] || err "$CLR32D canonical STATUS line scan failed"
[ "$q1statuslines" = 1 ] || err "$CLR32D must contain exactly one canonical STATUS line"
grep '^STATUS:' "$CLR32D" > "$tmpdir/q1.status.act" || err "$CLR32D STATUS extraction failed"
printf '%s\n' "$q1status" > "$tmpdir/q1.status.exp" || err "$CLR32D STATUS fixture generation failed"
cmp -s "$tmpdir/q1.status.exp" "$tmpdir/q1.status.act"; q1rc=$?
[ "$q1rc" -eq 0 ] || err "$CLR32D STATUS line is not exactly the complete required banner"
q1statusany=$(awk '{s=toupper($0); while (match(s,/STATUS:/)) {c++; s=substr(s,RSTART+RLENGTH)}} END {print c+0}' "$CLR32D"); q1rc=$?
[ "$q1rc" -eq 0 ] || err "$CLR32D case-insensitive global STATUS occurrence scan failed"
case $q1statusany in ''|*[!0-9]*) err "$CLR32D case-insensitive STATUS occurrence scan produced non-numeric output" ;; esac
[ "$q1statusany" = 1 ] || err "$CLR32D must contain exactly one case-insensitive STATUS: occurrence anywhere (found $q1statusany)"
printf '%s status: SECONDARY\n' "$q1status" > "$tmpdir/q1.status.canary" || err "$CLR32D STATUS canary generation failed"
q1statuscanary=$(awk '{s=toupper($0); while (match(s,/STATUS:/)) {c++; s=substr(s,RSTART+RLENGTH)}} END {print c+0}' "$tmpdir/q1.status.canary"); q1rc=$?
[ "$q1rc" -eq 0 ] || err "$CLR32D STATUS canary scan failed"
[ "$q1statuscanary" = 2 ] || err "$CLR32D case-insensitive same-line STATUS canary did not count two occurrences"
# Exact literal two-paragraph owner transcript, including the one blank
# line between paragraphs and the surrounding section boundaries.
sed -n '/^## Owner words exactly$/,/^## Q-001 disposition$/p' "$CLR32D" > "$tmpdir/q1.owner.act" \
  || err "$CLR32D owner-word section extraction failed"
cat > "$tmpdir/q1.owner.exp" <<'QK_F32D_Q001_OWNER_EOF' || err "$CLR32D owner-word fixture generation failed"
## Owner words exactly

Approve the recommended F32C-D11-Q-001 clarification: “Failure releases no artifact or partial output” does not claim that already observed QR frames or SD residue can be withdrawn or proven absent. Before route output begins, failure releases nothing; after output begins, a later failure stops further output, permits no complete-artifact, delivery, receipt, finalization, broadcast, atomicity, or durability claim, and permits no automatic fallback, retry, or re-signing.

Authorize preparation and independent audit of a non-enacting docs-only F3.2d Q-001 owner-clarification record from e4cdf7771e189fc0f729358334aafd35177048c6, with only the mechanically necessary verifier bindings. No D-11 selection; no answer to Q-002 through Q-012; no profile acceptance, D-09 or QK-LIM selection, implementation, testing, media I/O, hardware work, settings changes, or publication.

## Q-001 disposition
QK_F32D_Q001_OWNER_EOF
cmp -s "$tmpdir/q1.owner.exp" "$tmpdir/q1.owner.act"; q1rc=$?
[ "$q1rc" -eq 0 ] || err "$CLR32D owner words or required blank-line transcript differ from the authorization"
# Ordered exact Q-002..Q-012 transcript, with no table grammar.
grep '^- F32C-D11-Q-0' "$CLR32D" > "$tmpdir/q1.questions.act"
q1rc=$?
[ "$q1rc" -eq 0 ] || err "$CLR32D Q-002 through Q-012 transcript extraction failed"
cat > "$tmpdir/q1.questions.exp" <<'QK_F32D_Q001_QUESTIONS_EOF' || err "$CLR32D question transcript fixture generation failed"
- F32C-D11-Q-002 — Must exact physical SD attachment epoch be present/approval-bound, or may logical SD route accept later insertion/replacement; reconcile broad media-change invalidation. — UNANSWERED — NO RESPONSE RECORDED — NOT READY FOR SELECTION
- F32C-D11-Q-003 — One approval: exactly one route or closed QR+SD route set. — UNANSWERED — NO RESPONSE RECORDED — NOT READY FOR SELECTION
- F32C-D11-Q-004 — If both, all required vs either sufficient vs independent outcomes; first succeeds/second fails. — UNANSWERED — NO RESPONSE RECORDED — NOT READY FOR SELECTION
- F32C-D11-Q-005 — Same frozen artifact retry under unchanged session vs new review; neither allows re-signing. — UNANSWERED — NO RESPONSE RECORDED — NOT READY FOR SELECTION
- F32C-D11-Q-006 — Same SD for input/output vs distinct already-bound media; prove directory/allocation writes cannot lose/overwrite input. — UNANSWERED — NO RESPONSE RECORDED — NOT READY FOR SELECTION
- F32C-D11-Q-007 — Eligible visibility/commit construction and exact evidence before any atomic/complete claim. — UNANSWERED — NO RESPONSE RECORDED — NOT READY FOR SELECTION
- F32C-D11-Q-008 — Filename and bounded collision policy without input overwrite, wallet metadata, or silent post-approval change. — UNANSWERED — NO RESPONSE RECORDED — NOT READY FOR SELECTION
- F32C-D11-Q-009 — Orphan/ambiguous final objects: leave-ignore, quarantine, or bounded best-effort cleanup; no secure erasure/resume. — UNANSWERED — NO RESPONSE RECORDED — NOT READY FOR SELECTION
- F32C-D11-Q-010 — Complete QR self-decode/reparse before display and wording separating presentation from receipt. — UNANSWERED — NO RESPONSE RECORDED — NOT READY FOR SELECTION
- F32C-D11-Q-011 — Deterministic insertion position/order of two new partial signatures while old records keep exact bytes/relative order. — UNANSWERED — NO RESPONSE RECORDED — NOT READY FOR SELECTION
- F32C-D11-Q-012 — Which semantic fields later enter D-09 commitment; serialization/hash/domain remain D-09-open. — UNANSWERED — NO RESPONSE RECORDED — NOT READY FOR SELECTION
QK_F32D_Q001_QUESTIONS_EOF
cmp -s "$tmpdir/q1.questions.exp" "$tmpdir/q1.questions.act"; q1rc=$?
[ "$q1rc" -eq 0 ] || err "$CLR32D Q-002 through Q-012 transcript is missing, answered, malformed, duplicated, or reordered"
# Closed heading transcript; any extra, renamed, reordered, indented, or
# deeper ATX heading fails.
grep '#' "$CLR32D" > "$tmpdir/q1.heads.act"
q1rc=$?
[ "$q1rc" -eq 0 ] || err "$CLR32D heading transcript extraction failed"
cat > "$tmpdir/q1.heads.exp" <<'QK_F32D_Q001_HEADS_EOF' || err "$CLR32D heading transcript fixture generation failed"
# F3.2d D-11 Q-001 Owner-Clarification Record (Non-Enacting)
## Standing and provenance
## Owner words exactly
## Q-001 disposition
## Narrow clarification
## Source packet historical boundary
## Questions remaining unanswered
## Non-effects and open boundaries
QK_F32D_Q001_HEADS_EOF
cmp -s "$tmpdir/q1.heads.exp" "$tmpdir/q1.heads.act"; q1rc=$?
[ "$q1rc" -eq 0 ] || err "$CLR32D headings are not the exact closed ordered transcript"
# The clarification core is closed to exactly the five owner-authorized
# bullets. The retained boundary/F-row/S9 non-effects are exact unbulleted
# lines so no broader policy consequence can be smuggled into the core.
sed -n '/^## Narrow clarification$/,/^## Source packet historical boundary$/p' "$CLR32D" > "$tmpdir/q1.narrow.act" \
  || err "$CLR32D narrow-clarification extraction failed"
cat > "$tmpdir/q1.narrow.exp" <<'QK_F32D_Q001_NARROW_EOF' || err "$CLR32D narrow-clarification fixture generation failed"
## Narrow clarification

- “Failure releases no artifact or partial output” does not claim that already observed QR frames or SD residue can be withdrawn or proven absent.
- Before route output begins, failure releases nothing.
- After route output begins, a later failure stops further output.
- A later failure permits no complete-artifact, delivery, receipt, finalization, broadcast, atomicity, or durability claim.
- A later failure permits no automatic fallback, retry, or re-signing.

This clarification defines no route-output-begins boundary and selects no D-11 construction, state, route, or route set.

F32C-D11-F-006, F32C-D11-F-009, F32C-D11-F-014, and F32C-D11-F-022 remain PROPOSED — UNSELECTED — TARGET EVIDENCE REQUIRED.

S9 does not prove receipt, finalization, broadcast, or durability.

## Source packet historical boundary
QK_F32D_Q001_NARROW_EOF
cmp -s "$tmpdir/q1.narrow.exp" "$tmpdir/q1.narrow.act"; q1rc=$?
[ "$q1rc" -eq 0 ] || err "$CLR32D narrow clarification is not the exact closed owner-authorized transcript"
for q1req in \
  '- “Failure releases no artifact or partial output” does not claim that already observed QR frames or SD residue can be withdrawn or proven absent.' \
  '- Before route output begins, failure releases nothing.' \
  '- After route output begins, a later failure stops further output.' \
  '- A later failure permits no complete-artifact, delivery, receipt, finalization, broadcast, atomicity, or durability claim.' \
  '- A later failure permits no automatic fallback, retry, or re-signing.' \
  'This clarification defines no route-output-begins boundary and selects no D-11 construction, state, route, or route set.' \
  'F32C-D11-F-006, F32C-D11-F-009, F32C-D11-F-014, and F32C-D11-F-022 remain PROPOSED — UNSELECTED — TARGET EVIDENCE REQUIRED.' \
  '- No D-11 construction, state, route, route set, filesystem, filename, attachment, retry, orphan, QR-preflight, or signature-order policy is selected.' \
  '- D-09 remains open. No D-09 field, serialization, hash, or domain is selected.' \
  '- Every QK-LIM remains open. No QK-LIM value is selected.' \
  '- The PSBT profile remains not accepted. No profile or clause is accepted.' \
  '- No OD, QK-TST, evidence, gate, or STOP-SHIP status changes.' \
  '- This record makes no audit, authentication, publication, target-validation, atomicity, or durability claim.'; do
  q1n=$(grep -cFx -e "$q1req" "$CLR32D"); q1rc=$?
  [ "$q1rc" -le 1 ] || err "$CLR32D exact semantic-line scan failed"
  [ "$q1n" = 1 ] || err "$CLR32D required semantic must occur exactly once: $q1req"
done
for q1claim in 'D-11 IS SELECTED' 'D-11 HAS BEEN SELECTED' 'D-11 IS CLOSED' \
  'Q-001 IS CLOSED' 'PROFILE IS ACCEPTED' 'TESTS WERE RUN' \
  'GATE IS CLOSED' 'PUBLICATION IS AUTHORIZED' 'RECORD IS AUDITED' \
  'RECORD IS AUTHENTICATED' 'RECORD IS PUBLISHED'; do
  q1cn=$(LC_ALL=C grep -ciF -e "$q1claim" "$CLR32D"); q1rc=$?
  [ "$q1rc" -le 1 ] || err "$CLR32D contradictory-claim scan failed"
  [ "$q1cn" = 0 ] || err "$CLR32D contains a contradictory claim: $q1claim"
done
# Prefer no tables and close Markdown rendering bypasses.
forbid "$CLR32D contains a table/prose pipe" -F '|' "$CLR32D"
forbid "$CLR32D contains a blockquote-prefixed line" -E '^[[:blank:]]*>' "$CLR32D"
forbid "$CLR32D contains a Setext underline or pipe-free GFM table delimiter run" -E '^[[:blank:]]*(>[[:blank:]]*)*:?(=+|-+):?[[:blank:]]*$' "$CLR32D"
forbid "$CLR32D contains hidden HTML or a link definition" -E '<!--|-->|^\[[^]]+\]:' "$CLR32D"
forbid "$CLR32D contains a tab or trailing whitespace" -E '	|[[:blank:]]$' "$CLR32D"
forbid "$CLR32D contains URL/URI/email material" -iE '(https?://|[a-z][a-z0-9+.-]*://|[[:alnum:]_.+-]+@[[:alnum:].-]+)' "$CLR32D"
od -An -tx1 "$CLR32D" > "$tmpdir/q1.bytes.raw" || err "$CLR32D byte scan failed"
[ -s "$tmpdir/q1.bytes.raw" ] || err "$CLR32D byte scan produced empty output"
tr -d '[:space:]' < "$tmpdir/q1.bytes.raw" > "$tmpdir/q1.bytes.hex" || err "$CLR32D byte normalization failed"
[ -s "$tmpdir/q1.bytes.hex" ] || err "$CLR32D normalized byte scan produced empty output"
q1bad=$(grep -cE '(^efbbbf)|00|0d|e2808[ef]|e280a[a-e]|e281a[6-9]' "$tmpdir/q1.bytes.hex"); q1rc=$?
[ "$q1rc" -le 1 ] || err "$CLR32D control/bidi byte scan failed"
[ "$q1bad" = 0 ] || err "$CLR32D contains BOM, NUL, CR, LRM/RLM, or bidi controls"
iconv -f UTF-8 -t UTF-8 "$CLR32D" > "$tmpdir/q1.utf8" 2> "$tmpdir/q1.iconv.err"
q1rc=$?
[ "$q1rc" -eq 0 ] || err "$CLR32D strict UTF-8 validation failed"
[ -s "$tmpdir/q1.utf8" ] || err "$CLR32D UTF-8 validation produced empty output"
cmp -s "$CLR32D" "$tmpdir/q1.utf8"; q1rc=$?
[ "$q1rc" -eq 0 ] || err "$CLR32D UTF-8 validation changed bytes"
tail -c 1 "$CLR32D" > "$tmpdir/q1.tail1.raw"
q1rc=$?
[ "$q1rc" -eq 0 ] || err "$CLR32D final-one-byte tail stage failed"
[ -s "$tmpdir/q1.tail1.raw" ] || err "$CLR32D final-one-byte tail stage produced empty output"
od -An -tuC "$tmpdir/q1.tail1.raw" > "$tmpdir/q1.tail1.od"
q1rc=$?
[ "$q1rc" -eq 0 ] || err "$CLR32D final-one-byte od stage failed"
[ -s "$tmpdir/q1.tail1.od" ] || err "$CLR32D final-one-byte od stage produced empty output"
tr -d '[:space:]' < "$tmpdir/q1.tail1.od" > "$tmpdir/q1.tail1.txt"
q1rc=$?
[ "$q1rc" -eq 0 ] || err "$CLR32D final-one-byte normalization stage failed"
q1tail1=$(cat "$tmpdir/q1.tail1.txt"); q1rc=$?
[ "$q1rc" -eq 0 ] || err "$CLR32D final-one-byte read-back stage failed"
case $q1tail1 in ''|*[!0-9]*) err "$CLR32D final-one-byte result is empty or non-numeric" ;; esac
[ "$q1tail1" = 10 ] || err "$CLR32D must end in LF"
tail -c 2 "$CLR32D" > "$tmpdir/q1.tail2.raw"
q1rc=$?
[ "$q1rc" -eq 0 ] || err "$CLR32D final-two-byte tail stage failed"
[ -s "$tmpdir/q1.tail2.raw" ] || err "$CLR32D final-two-byte tail stage produced empty output"
od -An -tuC "$tmpdir/q1.tail2.raw" > "$tmpdir/q1.tail2.od"
q1rc=$?
[ "$q1rc" -eq 0 ] || err "$CLR32D final-two-byte od stage failed"
[ -s "$tmpdir/q1.tail2.od" ] || err "$CLR32D final-two-byte od stage produced empty output"
tr -d '[:space:]' < "$tmpdir/q1.tail2.od" > "$tmpdir/q1.tail2.txt"
q1rc=$?
[ "$q1rc" -eq 0 ] || err "$CLR32D final-two-byte normalization stage failed"
q1tail2=$(cat "$tmpdir/q1.tail2.txt"); q1rc=$?
[ "$q1rc" -eq 0 ] || err "$CLR32D final-two-byte read-back stage failed"
case $q1tail2 in ''|*[!0-9]*) err "$CLR32D final-two-byte result is empty or non-numeric" ;; esac
[ "$q1tail2" != 1010 ] || err "$CLR32D must end in exactly one LF"
# The record may contain exactly its source commit and source packet
# blob as 40-hex tokens; nothing else.
printf '%s\n' b4594210975940df71b0e941841320d11defaa4c e4cdf7771e189fc0f729358334aafd35177048c6 > "$tmpdir/q1.hex.exp" \
  || err "$CLR32D exact-40-hex allowlist generation failed"
awk '{s=$0; while (match(s,/[0-9a-fA-F]+/)) {t=substr(s,RSTART,RLENGTH); if (length(t)==40) print tolower(t); s=substr(s,RSTART+RLENGTH)}}' \
  "$CLR32D" > "$tmpdir/q1.hex.raw"
q1rc=$?
[ "$q1rc" -eq 0 ] || err "$CLR32D exact-40-hex enumeration failed"
LC_ALL=C sort -u "$tmpdir/q1.hex.raw" > "$tmpdir/q1.hex.act"
q1rc=$?
[ "$q1rc" -eq 0 ] || err "$CLR32D exact-40-hex sort failed"
cmp -s "$tmpdir/q1.hex.exp" "$tmpdir/q1.hex.act"; q1rc=$?
[ "$q1rc" -eq 0 ] || err "$CLR32D contains a missing, altered, or extra exact-40-hex token"

# F3.2e PSBT-output TEST-ARCHITECTURE alignment packet: supporting lexical
# and structural evidence only, never self-authentication or independent proof.
PKT32E=docs/f3/F3.2E-PSBT-OUTPUT-TEST-ALIGNMENT-PACKET.md
[ -f "$PKT32E" ] || err "$PKT32E missing"
# This exact Git blob is an audit locator and supporting byte-identity
# invariant only; it is never self-authentication or independent proof.
p32eblob=4ffa20afbedeb0b6cfbbe57298f941bc0537683e
git --no-optional-locks hash-object -- "$PKT32E" > "$tmpdir/p32e.blob.act"; p32erc=$?
[ "$p32erc" -eq 0 ] || err "$PKT32E git hash-object audit-locator scan failed (exit $p32erc)"
[ -s "$tmpdir/p32e.blob.act" ] || err "$PKT32E git hash-object audit-locator scan produced empty output"
grep -cE '^[0-9a-f]{40}$' "$tmpdir/p32e.blob.act" > "$tmpdir/p32e.blob.count"; p32erc=$?
[ "$p32erc" -le 1 ] || err "$PKT32E git hash-object audit-locator format scan failed"
p32eblobfmt=$(cat "$tmpdir/p32e.blob.count"); p32erc=$?
[ "$p32erc" -eq 0 ] || err "$PKT32E git hash-object audit-locator format-count read failed"
[ "$p32eblobfmt" = 1 ] || err "$PKT32E git hash-object audit-locator output is not one lowercase 40-hex OID"
printf '%s\n' "$p32eblob" > "$tmpdir/p32e.blob.exp" \
  || err "$PKT32E expected audit-locator blob generation failed"
cmp -s "$tmpdir/p32e.blob.exp" "$tmpdir/p32e.blob.act"; p32erc=$?
[ "$p32erc" -eq 0 ] || err "$PKT32E audit-locator blob identity differs from the pinned packet blob"
p32etitle='# QK-F3.2e — PSBT-Output TEST-ARCHITECTURE Alignment Packet (Non-Binding)'
p32estatus='STATUS: OWNER-AUTHORIZED ALIGNMENT INPUT ONLY — NON-BINDING — PROPOSED CORRECTION TEXT UNSELECTED — QK-TST-DIFF-002 AND QK-TST-DIFF-004 ARE CORRECTION TARGETS ONLY — QK-TST-REH-004 RETAINED UNCHANGED AS EXTERNAL-FINALIZATION CONTROL — CANONICAL TEST-ARCHITECTURE UNCHANGED — ALL QK-TST STATUSES UNCHANGED — PLANNED — NOT RUN — D-11 NOT SELECTED — F32C-D11-Q-002 THROUGH F32C-D11-Q-012 UNANSWERED — D-09 AND EVERY QK-LIM OPEN — PSBT PROFILE NOT ACCEPTED — NO IMPLEMENTATION, TESTING, VECTORS, OR MEDIA I/O — NO EVIDENCE OR GATE CHANGE — LOCAL AND UNPUBLISHED.'
p32eend='END OF PACKET — F3.2e PSBT-OUTPUT TEST-ARCHITECTURE ALIGNMENT INPUT ONLY — PROPOSED CORRECTION TEXT UNSELECTED — CANONICAL TEST-ARCHITECTURE AND ALL QK-TST STATUSES UNCHANGED — LOCAL AND UNPUBLISHED.'
sed -n '1p' "$PKT32E" > "$tmpdir/p32e.title.act"; p32erc=$?
[ "$p32erc" -eq 0 ] || err "$PKT32E title read failed (exit $p32erc)"
[ -s "$tmpdir/p32e.title.act" ] || err "$PKT32E title read produced empty output"
printf '%s\n' "$p32etitle" > "$tmpdir/p32e.title.exp" \
  || err "$PKT32E title fixture generation failed"
cmp -s "$tmpdir/p32e.title.exp" "$tmpdir/p32e.title.act"; p32erc=$?
[ "$p32erc" -eq 0 ] || err "$PKT32E exact title is not first"
tail -n 1 "$PKT32E" > "$tmpdir/p32e.end.act"; p32erc=$?
[ "$p32erc" -eq 0 ] || err "$PKT32E terminal-line read failed (exit $p32erc)"
[ -s "$tmpdir/p32e.end.act" ] || err "$PKT32E terminal-line read produced empty output"
printf '%s\n' "$p32eend" > "$tmpdir/p32e.end.exp" \
  || err "$PKT32E terminal-line fixture generation failed"
cmp -s "$tmpdir/p32e.end.exp" "$tmpdir/p32e.end.act"; p32erc=$?
[ "$p32erc" -eq 0 ] || err "$PKT32E exact terminal line missing"
# Exact full-line STATUS binding.
grep -c '^STATUS:' "$PKT32E" > "$tmpdir/p32e.status.count"; p32erc=$?
[ "$p32erc" -le 1 ] || err "$PKT32E STATUS count failed"
p32estatuslines=$(cat "$tmpdir/p32e.status.count"); p32erc=$?
[ "$p32erc" -eq 0 ] || err "$PKT32E STATUS count read failed"
[ "$p32estatuslines" = 1 ] || err "$PKT32E must contain exactly one canonical STATUS line"
grep '^STATUS:' "$PKT32E" > "$tmpdir/p32e.status.act"; p32erc=$?
[ "$p32erc" -eq 0 ] || err "$PKT32E STATUS line extraction failed"
printf '%s\n' "$p32estatus" > "$tmpdir/p32e.status.exp" || err "$PKT32E STATUS expected generation failed"
cmp -s "$tmpdir/p32e.status.exp" "$tmpdir/p32e.status.act"; p32erc=$?
[ "$p32erc" -eq 0 ] || err "$PKT32E STATUS line is not exactly the complete required banner"
p32estatusany=$(awk '{s=$0; while (match(s,/STATUS:/)) {c++; s=substr(s,RSTART+RLENGTH)}} END {print c+0}' "$PKT32E"); p32erc=$?
[ "$p32erc" -eq 0 ] || err "$PKT32E global STATUS occurrence scan failed"
case $p32estatusany in ''|*[!0-9]*) err "$PKT32E global STATUS occurrence scan produced non-numeric output" ;; esac
[ "$p32estatusany" = 1 ] || err "$PKT32E must contain exactly one STATUS: occurrence anywhere (found $p32estatusany)"
# Owner words: exact one-paragraph quote present exactly once.
p32eowner='Authorize preparation and independent audit of a non-binding docs-only F3.2e PSBT-output TEST-ARCHITECTURE alignment packet from be4d019e349e15ca575ac64b64f900957283e5e0, with only the mechanically necessary verifier bindings. Limit scope to QK-TST-DIFF-002 and QK-TST-DIFF-004, with QK-TST-REH-004 retained unchanged as the external-finalization control. No canonical TEST-ARCHITECTURE edit, test-status change, Q-002 through Q-012 answer, D-11 or D-09 selection, profile acceptance, implementation, testing, vectors, media I/O, hardware work, settings changes, or publication.'
p32eown=$(grep -cFx -e "$p32eowner" "$PKT32E"); p32erc=$?
[ "$p32erc" -le 1 ] || err "$PKT32E owner-quote exact scan failed"
[ "$p32eown" = 1 ] || err "$PKT32E exact owner quote must occur exactly once"
sed -n '/^## Owner words exactly$/,/^## Canonical source rows (reproduced byte-for-byte from source base)$/p' \
  "$PKT32E" > "$tmpdir/p32e.owner.act"; p32erc=$?
[ "$p32erc" -eq 0 ] || err "$PKT32E owner section extraction failed"
cat > "$tmpdir/p32e.owner.exp" <<'QK_F32E_OWNER_EOF' || err "$PKT32E owner section fixture generation failed"
## Owner words exactly

Authorize preparation and independent audit of a non-binding docs-only F3.2e PSBT-output TEST-ARCHITECTURE alignment packet from be4d019e349e15ca575ac64b64f900957283e5e0, with only the mechanically necessary verifier bindings. Limit scope to QK-TST-DIFF-002 and QK-TST-DIFF-004, with QK-TST-REH-004 retained unchanged as the external-finalization control. No canonical TEST-ARCHITECTURE edit, test-status change, Q-002 through Q-012 answer, D-11 or D-09 selection, profile acceptance, implementation, testing, vectors, media I/O, hardware work, settings changes, or publication.

## Canonical source rows (reproduced byte-for-byte from source base)
QK_F32E_OWNER_EOF
cmp -s "$tmpdir/p32e.owner.exp" "$tmpdir/p32e.owner.act"; p32erc=$?
[ "$p32erc" -eq 0 ] || err "$PKT32E owner section is not the exact closed transcript"
# Source base audit locator present at least once (appears in standing section
# and verbatim in owner words quote).
grep -F -e 'be4d019e349e15ca575ac64b64f900957283e5e0' "$PKT32E" > "$tmpdir/p32e.srcbase.act" 2>/dev/null
p32erc=$?
[ "$p32erc" -le 1 ] || err "$PKT32E source-base 40-hex scan failed"
[ -s "$tmpdir/p32e.srcbase.act" ] || err "$PKT32E source-base must be present at least once"
# Commit A audit locator present exactly once.
p32ecmta=$(grep -cF -e 'e57faff4ead69ddf108cf522cb6c3cbfbef8219a' "$PKT32E"); p32erc=$?
[ "$p32erc" -le 1 ] || err "$PKT32E commit-A 40-hex scan failed"
[ "$p32ecmta" = 1 ] || err "$PKT32E commit A must occur exactly once"
# Six source/protected blob audit locators each present exactly once.
for p32eblk in \
  f4e127a92fc68243274b7d384e335fa4632e5dd2 \
  981b1b497102187da66fb4e82ef0725b32c088f7 \
  b4594210975940df71b0e941841320d11defaa4c \
  a996a6d7c2bfa3a15109085475868410fe354422 \
  838a732ab556b51ca8b0b61bed9ae9d512d47a87 \
  877866e5a3636bdfb7015d715e048ccfad63d939; do
  p32en=$(grep -cF -e "$p32eblk" "$PKT32E"); p32erc=$?
  [ "$p32erc" -le 1 ] || err "$PKT32E audit-locator blob scan failed for $p32eblk"
  [ "$p32en" = 1 ] || err "$PKT32E audit-locator blob must occur exactly once: $p32eblk"
done
# F3.2g intentionally amends the active canonical file, so retain the
# F3.2e predicate against the exact canonical source at the published
# F3.2f base rather than weakening or deleting the historical check.
git --no-optional-locks show 45f2b362994b785d303e91b8e530efc724dc2d81:docs/TEST-ARCHITECTURE.md \
  > "$tmpdir/p32e.testarch.source" 2> "$tmpdir/p32e.testarch.source.err"; p32erc=$?
[ "$p32erc" -eq 0 ] || err "cannot read the historical F3.2e TEST-ARCHITECTURE source"
[ -s "$tmpdir/p32e.testarch.source" ] || err "historical F3.2e TEST-ARCHITECTURE source is empty"
git --no-optional-locks hash-object -- "$tmpdir/p32e.testarch.source" \
  > "$tmpdir/p32e.testarch.source.act"; p32erc=$?
[ "$p32erc" -eq 0 ] || err "historical F3.2e TEST-ARCHITECTURE source blob scan failed"
[ -s "$tmpdir/p32e.testarch.source.act" ] || err "historical F3.2e TEST-ARCHITECTURE source blob scan produced empty output"
printf '%s\n' f4e127a92fc68243274b7d384e335fa4632e5dd2 \
  > "$tmpdir/p32e.testarch.source.exp" || err "historical F3.2e TEST-ARCHITECTURE source blob fixture failed"
cmp -s "$tmpdir/p32e.testarch.source.exp" "$tmpdir/p32e.testarch.source.act"; p32erc=$?
[ "$p32erc" -eq 0 ] || err "historical F3.2e TEST-ARCHITECTURE source differs from the reviewed blob"
# Other source/protected working-tree files themselves must retain their
# reviewed blobs; the packet's printed locators alone are not sufficient.
while IFS=' ' read -r p32esource p32eexpected; do
  git --no-optional-locks rev-parse "45f2b362994b785d303e91b8e530efc724dc2d81:$p32esource" > "$tmpdir/p32e.source.act" 2>/dev/null; p32erc=$?
  [ "$p32erc" -eq 0 ] || err "$p32esource source/protected blob scan failed (exit $p32erc)"
  [ -s "$tmpdir/p32e.source.act" ] || err "$p32esource source/protected blob scan produced empty output"
  printf '%s\n' "$p32eexpected" > "$tmpdir/p32e.source.exp" \
    || err "$p32esource expected source/protected blob generation failed"
  cmp -s "$tmpdir/p32e.source.exp" "$tmpdir/p32e.source.act"; p32erc=$?
  [ "$p32erc" -eq 0 ] || err "$p32esource differs from the F3.2e reviewed source/protected blob"
done <<'QK_F32E_SOURCE_BLOBS_EOF'
docs/REQUIREMENTS.md 981b1b497102187da66fb4e82ef0725b32c088f7
docs/f3/F3.2C-D11-MEDIA-WRITE-LIFECYCLE-CONSTRUCTION-PACKET.md b4594210975940df71b0e941841320d11defaa4c
docs/f3/F3.2D-D11-Q001-OWNER-CLARIFICATION-RECORD.md a996a6d7c2bfa3a15109085475868410fe354422
docs/f3/F3.2B-PSBT-OWNER-RESPONSE-RECORD.md 838a732ab556b51ca8b0b61bed9ae9d512d47a87
docs/f3/PSBT-V0-REVIEW-PROFILE-DRAFT.md 877866e5a3636bdfb7015d715e048ccfad63d939
QK_F32E_SOURCE_BLOBS_EOF
# Canonical source rows reproduced byte-for-byte.
p32ediff002='| QK-TST-DIFF-002 | DIFF | PSBT parsing, validation, signing, and finalized output vs. independent implementations; signature verification and independent parseability. Oracle: verdict/byte agreement on shared corpora. | QK-REQ-PSBT-004, QK-REQ-PSBT-006; QK-THR-006, QK-THR-017 | F9 | Gate C | Cross-implementation agreement record with corpus hashes | PLANNED — NOT RUN |'
p32ediff004='| QK-TST-DIFF-004 | DIFF | Export-route interop: the signed PSBT and raw final transaction exported via QR and via SD are byte-identical to each other and parse/verify identically in independent implementations. Oracle: cross-route byte comparison plus independent-parser agreement. | QK-REQ-TRN-007; QK-THR-006; QK-LIM-PSBT-026, QK-LIM-PSBT-027 | F10 | Gate C | Cross-implementation agreement record with corpus hashes | PLANNED — NOT RUN |'
p32ereh004='| QK-TST-REH-004 | REH | Rescue with commodity reader and open rescue tool; independent transaction finalization outside QuietKey tooling; acceptance by Bitcoin Core. Dependency: rescue evidence is definable only after OD-02 resolves the card interface. Oracle: Bitcoin Core acceptance of the rescued transaction. | QK-REQ-CARD-006, QK-REQ-PSBT-004, QK-REQ-REC-006, QK-REQ-TRN-007; QK-THR-001, QK-THR-006, QK-THR-020 | F12 | Gate B, Gate C, Gate E | Rehearsal transcript + artifact hashes | PLANNED — NOT RUN |'
for p32erow in "$p32ediff002" "$p32ediff004" "$p32ereh004"; do
  p32ern=$(grep -cFx -e "$p32erow" "$PKT32E"); p32erc=$?
  [ "$p32erc" -le 1 ] || err "$PKT32E canonical row scan failed"
  [ "$p32ern" = 1 ] || err "$PKT32E one required canonical source row is missing, altered, or duplicated"
done
# Proposed plan/oracle text present (unselected marker and key phrases).
grep -F 'PSBT v0 parsing and then-selected-profile validation against an independent implementation' "$PKT32E" >/dev/null \
  || err "$PKT32E missing DIFF-002 proposed plan key phrase"
grep -F 'Export-route interoperability for one already frozen, fully serialized, freshly independently reparsed unfinalized signed-PSBT artifact.' "$PKT32E" >/dev/null \
  || err "$PKT32E missing DIFF-004 proposed plan key phrase"
grep -F 'UNCHANGED CONTROL — NO CANDIDATE EDIT' "$PKT32E" >/dev/null \
  || err "$PKT32E missing UNCHANGED CONTROL label for REH-004"
# Conflict statements present.
grep -F '"finalized output" is therefore stale and ambiguous under D-10' "$PKT32E" >/dev/null \
  || err "$PKT32E missing DIFF-002 conflict statement"
grep -F '"raw final transaction" in the DIFF-004 plan directly conflicts with D-10' "$PKT32E" >/dev/null \
  || err "$PKT32E missing DIFF-004 conflict statement"
# Unchanged-control meaning stated.
grep -F 'QK-TST-REH-004 RETAINED UNCHANGED AS EXTERNAL-FINALIZATION CONTROL' "$PKT32E" >/dev/null \
  || err "$PKT32E missing unchanged-control meaning in STATUS"
# QK-LIM-PSBT-027 residual inconsistency flagged.
grep -F 'QK-LIM-PSBT-027' "$PKT32E" >/dev/null \
  || err "$PKT32E missing QK-LIM-PSBT-027 residual inconsistency flag"
grep -F 'residual cross-document inconsistency' "$PKT32E" >/dev/null \
  || err "$PKT32E missing residual cross-document inconsistency statement"
# Dependencies and non-effects.
grep -F 'DIFF-002 cannot run before' "$PKT32E" >/dev/null \
  || err "$PKT32E missing DIFF-002 dependency statement"
grep -F 'DIFF-004 cannot run before' "$PKT32E" >/dev/null \
  || err "$PKT32E missing DIFF-004 dependency statement"
grep -F 'DIFF-002 owns signature' "$PKT32E" >/dev/null \
  || err "$PKT32E missing DIFF-002 vs DIFF-004 scope separation statement"
# No finalization/raw-transaction language leaked into proposed text.
sed -n '/^### QK-TST-DIFF-002 proposed/,/^### QK-TST-DIFF-004 proposed/p' "$PKT32E" > "$tmpdir/p32e.d002prop" \
  || err "$PKT32E DIFF-002 proposed section extraction failed"
[ -s "$tmpdir/p32e.d002prop" ] || err "$PKT32E DIFF-002 proposed section extraction was empty"
forbid "$PKT32E DIFF-002 proposed plan leaks finalization field language" \
  -iE '(FINAL_SCRIPTSIG|FINAL_SCRIPTWITNESS)' "$tmpdir/p32e.d002prop"
forbid "$PKT32E DIFF-002 proposed plan claims QuietKey produces finalized output" \
  -iE 'QuietKey[^.]*finali[sz]ed? output|produces[^.]*finali[sz]ed? output|finali[sz]ed? output[^.]*is released' "$tmpdir/p32e.d002prop"
sed -n '/^### QK-TST-DIFF-004 proposed/,/^## Dependencies/p' "$PKT32E" > "$tmpdir/p32e.d004prop" \
  || err "$PKT32E DIFF-004 proposed section extraction failed"
[ -s "$tmpdir/p32e.d004prop" ] || err "$PKT32E DIFF-004 proposed section extraction was empty"
forbid "$PKT32E DIFF-004 proposed plan claims a raw final transaction" \
  -iE 'raw final transaction' "$tmpdir/p32e.d004prop"
# No canonical TEST-ARCHITECTURE edit claim.
forbid "$PKT32E claims canonical TEST-ARCHITECTURE was edited" \
  -iE '(TEST-ARCHITECTURE|QK-TST)[^.]*((has been|was|is now) (updated|changed|edited|corrected|amended))' "$PKT32E"
# No test-status change claim.
forbid "$PKT32E claims a QK-TST status was changed" \
  -iE 'QK-TST[^.]*(status (changed|updated|is now)|(now|has been) (RUN|PASSED|FAILED|COMPLETE))' "$PKT32E"
grep -F 'No correction is selected by this packet; candidate text requires later owner approval, and canonical correction requires a still-later separate authorization.' "$PKT32E" >/dev/null \
  || err "$PKT32E missing exact correction non-selection and later-authorization boundary"
grep -F 'D-09, D-11, F32C-D11-Q-002 through F32C-D11-Q-012, every QK-LIM, profile acceptance, tests, evidence, gates A through E, and STOP-SHIP all remain open or unchanged.' "$PKT32E" >/dev/null \
  || err "$PKT32E missing exact open-or-unchanged governance boundary"
forbid "$PKT32E claims tests were run or completed" \
  -iE '(test(s|ing)? (was|were|has been|have been) (run|performed|completed)|QK-TST-[^.]* (PASSED|FAILED|COMPLETE))' "$PKT32E"
forbid "$PKT32E claims evidence or a gate was created, changed, or satisfied" \
  -iE '(evidence|gate(s| [A-E])?)[^.]*((has been|was|is) (created|updated|changed|satisfied|passed|closed))' "$PKT32E"
# Exact allowed QK-TST set: only QK-TST-DIFF-002, QK-TST-DIFF-004, QK-TST-REH-004.
grep -E 'QK-TST-[A-Z0-9-]+' "$PKT32E" > "$tmpdir/p32e.tst.raw" 2>/dev/null; p32erc=$?
[ "$p32erc" -le 1 ] || err "$PKT32E QK-TST token scan failed"
awk '{ s = $0
  while (match(s, /QK-TST-[A-Z0-9-]+/)) {
    print substr(s, RSTART, RLENGTH)
    s = substr(s, RSTART + RLENGTH) } }' "$PKT32E" > "$tmpdir/p32e.tst.tokens" \
  || err "$PKT32E QK-TST token extraction failed"
LC_ALL=C sort -u "$tmpdir/p32e.tst.tokens" > "$tmpdir/p32e.tst.found" \
  || err "$PKT32E QK-TST token sort failed"
printf '%s\n' \
  QK-TST-DIFF-002 \
  QK-TST-DIFF-004 \
  QK-TST-REH-004 > "$tmpdir/p32e.tst.exp" \
  || err "$PKT32E QK-TST expected list generation failed"
LC_ALL=C comm -23 "$tmpdir/p32e.tst.found" "$tmpdir/p32e.tst.exp" > "$tmpdir/p32e.tst.extra" \
  || err "$PKT32E QK-TST extra-token comm failed"
[ ! -s "$tmpdir/p32e.tst.extra" ] || err "$PKT32E contains QK-TST tokens outside the exact allowed set: $(cat "$tmpdir/p32e.tst.extra")"
LC_ALL=C comm -23 "$tmpdir/p32e.tst.exp" "$tmpdir/p32e.tst.found" > "$tmpdir/p32e.tst.missing" \
  || err "$PKT32E QK-TST missing-token comm failed"
[ ! -s "$tmpdir/p32e.tst.missing" ] || err "$PKT32E is missing required QK-TST tokens: $(cat "$tmpdir/p32e.tst.missing")"
# Headings transcript.
grep '#' "$PKT32E" > "$tmpdir/p32e.heads.act"; p32erc=$?
[ "$p32erc" -eq 0 ] || err "$PKT32E heading extraction failed"
cat > "$tmpdir/p32e.heads.exp" <<'QK_F32E_HEADS_EOF' || err "$PKT32E heading fixture generation failed"
# QK-F3.2e — PSBT-Output TEST-ARCHITECTURE Alignment Packet (Non-Binding)
## Standing and source boundary
## Audit locators (supporting byte identity only)
## Owner words exactly
## Canonical source rows (reproduced byte-for-byte from source base)
### Differential table (canonical)
### Rehearsal table (canonical, unchanged control)
## Conflict analysis
### DIFF-002 conflict
### DIFF-004 conflict
## Proposed correction text (UNSELECTED — candidate only)
### QK-TST-DIFF-002 proposed plan/oracle (UNSELECTED)
### QK-TST-DIFF-004 proposed plan/oracle (UNSELECTED)
## Dependencies and non-effects
QK_F32E_HEADS_EOF
cmp -s "$tmpdir/p32e.heads.exp" "$tmpdir/p32e.heads.act"; p32erc=$?
[ "$p32erc" -eq 0 ] || err "$PKT32E headings are not the exact closed ordered transcript"
# Table transcript: pipe-carrying lines.
grep '|' "$PKT32E" > "$tmpdir/p32e.pipes.act"; p32erc=$?
[ "$p32erc" -le 1 ] || err "$PKT32E pipe-line scan failed"
cat > "$tmpdir/p32e.pipes.exp" <<'QK_F32E_PIPES_EOF' || err "$PKT32E pipe-line fixture generation failed"
| ID | Method | Plan / oracle | Links | Milestone | Gate | Evidence artifact | Status |
|---|---|---|---|---|---|---|---|
| QK-TST-DIFF-002 | DIFF | PSBT parsing, validation, signing, and finalized output vs. independent implementations; signature verification and independent parseability. Oracle: verdict/byte agreement on shared corpora. | QK-REQ-PSBT-004, QK-REQ-PSBT-006; QK-THR-006, QK-THR-017 | F9 | Gate C | Cross-implementation agreement record with corpus hashes | PLANNED — NOT RUN |
| QK-TST-DIFF-004 | DIFF | Export-route interop: the signed PSBT and raw final transaction exported via QR and via SD are byte-identical to each other and parse/verify identically in independent implementations. Oracle: cross-route byte comparison plus independent-parser agreement. | QK-REQ-TRN-007; QK-THR-006; QK-LIM-PSBT-026, QK-LIM-PSBT-027 | F10 | Gate C | Cross-implementation agreement record with corpus hashes | PLANNED — NOT RUN |
| ID | Method | Plan / oracle | Links | Milestone | Gate | Evidence artifact | Status |
|---|---|---|---|---|---|---|---|
| QK-TST-REH-004 | REH | Rescue with commodity reader and open rescue tool; independent transaction finalization outside QuietKey tooling; acceptance by Bitcoin Core. Dependency: rescue evidence is definable only after OD-02 resolves the card interface. Oracle: Bitcoin Core acceptance of the rescued transaction. | QK-REQ-CARD-006, QK-REQ-PSBT-004, QK-REQ-REC-006, QK-REQ-TRN-007; QK-THR-001, QK-THR-006, QK-THR-020 | F12 | Gate B, Gate C, Gate E | Rehearsal transcript + artifact hashes | PLANNED — NOT RUN |
| ID | Method | Plan / oracle | Links | Milestone | Gate | Evidence artifact | Status |
|---|---|---|---|---|---|---|---|
| QK-TST-DIFF-002 | DIFF | PSBT v0 parsing and then-selected-profile validation against an independent implementation over shared positive and adversarial corpora; for each QuietKey-produced candidate output, independently fully consume and parse the exact serialized bytes, prove that the output is one unfinalized signed PSBT, verify every produced signature, and prove the exact record-level delta: every accepted pre-existing non-signature key/value record remains byte-identical in its original map and original relative order; every input contains exactly the two new authorized selected-pair PSBT_IN_PARTIAL_SIG records; no pre-existing partial-signature record and no missing, foreign, third, duplicate, replaced, or mutated selected-pair partial-signature record is present; and no finalization record is present. No finalization, extraction, raw transaction, or broadcast occurs. Oracle: all then-selected-profile verdicts agree and every independent output-parse, signature, and exact-delta assertion passes; any disagreement or failed assertion fails the row. Whole-output byte agreement between separately signing implementations is not required. | QK-REQ-PSBT-004, QK-REQ-PSBT-006; QK-THR-006, QK-THR-017 | F9 | Gate C | Cross-implementation agreement record with corpus hashes | PLANNED — NOT RUN |
| QK-TST-DIFF-004 | DIFF | Export-route interoperability for one already frozen, fully serialized, freshly independently reparsed unfinalized signed-PSBT artifact. Without re-signing, route-specific cases provide that same byte sequence to uncompressed BBQr file type P output and to a newly created binary .psbt SD output under the then-selected D-11 lifecycle. Independent route receivers/readers recover the payloads; decoded QR payload bytes and completed SD output-file bytes must each equal the frozen artifact byte-for-byte and therefore equal each other, and an independent PSBT implementation must fully consume and parse both recovered byte sequences as the same unfinalized signed PSBT. The cases make no route approval, session, cardinality, completion, finalization, extraction, raw-transaction, broadcast, delivery, receipt, atomicity, or durability claim. Oracle: exact three-way byte equality plus independent full-consumption parse agreement; any wrapper, sidecar, trailing byte, route mismatch, finalization field, raw transaction, or parse disagreement fails the row. | QK-REQ-TRN-007; QK-THR-006; QK-LIM-PSBT-026, QK-LIM-PSBT-027 | F10 | Gate C | Cross-implementation agreement record with corpus hashes | PLANNED — NOT RUN |
QK_F32E_PIPES_EOF
cmp -s "$tmpdir/p32e.pipes.exp" "$tmpdir/p32e.pipes.act"; p32erc=$?
[ "$p32erc" -eq 0 ] || err "$PKT32E pipe-carrying lines are not the exact closed table transcript"
# UTF-8/LF/hidden/material checks.
iconv -f UTF-8 -t UTF-8 "$PKT32E" > "$tmpdir/p32e.utf8" 2> "$tmpdir/p32e.iconv.err"; p32erc=$?
[ "$p32erc" -eq 0 ] || err "$PKT32E is not strict UTF-8 (iconv exit $p32erc)"
[ -s "$tmpdir/p32e.utf8" ] || err "$PKT32E UTF-8 validation produced empty output"
cmp -s "$PKT32E" "$tmpdir/p32e.utf8"; p32erc=$?
[ "$p32erc" -eq 0 ] || err "$PKT32E UTF-8 validation changed bytes"
tail -c 1 "$PKT32E" > "$tmpdir/p32e.tail1.raw"; p32erc=$?
[ "$p32erc" -eq 0 ] || err "$PKT32E final-byte read failed"
[ -s "$tmpdir/p32e.tail1.raw" ] || err "$PKT32E final-byte read produced empty output"
od -An -tuC "$tmpdir/p32e.tail1.raw" > "$tmpdir/p32e.tail1.od"; p32erc=$?
[ "$p32erc" -eq 0 ] || err "$PKT32E final-byte od failed"
tr -d '[:space:]' < "$tmpdir/p32e.tail1.od" > "$tmpdir/p32e.tail1.txt"; p32erc=$?
[ "$p32erc" -eq 0 ] || err "$PKT32E final-byte normalization failed"
p32etail1=$(cat "$tmpdir/p32e.tail1.txt"); p32erc=$?
[ "$p32erc" -eq 0 ] || err "$PKT32E final-byte read-back failed"
case $p32etail1 in ''|*[!0-9]*) err "$PKT32E final-byte result is empty or non-numeric" ;; esac
[ "$p32etail1" = 10 ] || err "$PKT32E must end in LF"
tail -c 2 "$PKT32E" > "$tmpdir/p32e.tail2.raw"; p32erc=$?
[ "$p32erc" -eq 0 ] || err "$PKT32E final-two-byte read failed"
od -An -tuC "$tmpdir/p32e.tail2.raw" > "$tmpdir/p32e.tail2.od"; p32erc=$?
[ "$p32erc" -eq 0 ] || err "$PKT32E final-two-byte od failed"
tr -d '[:space:]' < "$tmpdir/p32e.tail2.od" > "$tmpdir/p32e.tail2.txt"; p32erc=$?
[ "$p32erc" -eq 0 ] || err "$PKT32E final-two-byte normalization failed"
p32etail2=$(cat "$tmpdir/p32e.tail2.txt"); p32erc=$?
[ "$p32erc" -eq 0 ] || err "$PKT32E final-two-byte read-back failed"
case $p32etail2 in ''|*[!0-9]*) err "$PKT32E final-two-byte result is empty or non-numeric" ;; esac
[ "$p32etail2" != 1010 ] || err "$PKT32E must end in exactly one LF"
od -An -tx1 "$PKT32E" > "$tmpdir/p32e.bytes.raw"; p32erc=$?
[ "$p32erc" -eq 0 ] || err "$PKT32E byte scan failed"
[ -s "$tmpdir/p32e.bytes.raw" ] || err "$PKT32E byte scan produced empty output"
tr -d '[:space:]' < "$tmpdir/p32e.bytes.raw" > "$tmpdir/p32e.bytes.hex"; p32erc=$?
[ "$p32erc" -eq 0 ] || err "$PKT32E byte normalization failed"
[ -s "$tmpdir/p32e.bytes.hex" ] || err "$PKT32E normalized byte scan produced empty output"
p32ebad=$(grep -cE '(^efbbbf)|00|0d|e2808[ef]|e280a[a-e]|e281a[6-9]' "$tmpdir/p32e.bytes.hex"); p32erc=$?
[ "$p32erc" -le 1 ] || err "$PKT32E control/bidi byte scan failed"
[ "$p32ebad" = 0 ] || err "$PKT32E contains BOM, NUL, CR, LRM/RLM, or bidi controls"
forbid "$PKT32E contains hidden HTML or a link definition" -E '<!--|-->|^\[[^]]+\]:' "$PKT32E"
forbid "$PKT32E contains a tab or trailing whitespace" -E '	|[[:blank:]]$' "$PKT32E"
forbid "$PKT32E contains a block quote" -E '^[[:space:]]*>' "$PKT32E"
forbid "$PKT32E contains a Setext heading or horizontal-rule line" -E '^[[:space:]]*(=+|-+)[[:space:]]*$' "$PKT32E"
forbid "$PKT32E contains URL/URI/email material" -iE '(https?://|[a-z][a-z0-9+.-]*://|[[:alnum:]_.+-]+@[[:alnum:].-]+)' "$PKT32E"
forbid "$PKT32E contains PSBT magic hex" -E '[7]0736274' "$PKT32E"
forbid "$PKT32E contains PSBT base64 magic" -E '[c]HNidP' "$PKT32E"
forbid "$PKT32E contains xpub-like material" -E '[x]pub[1-9A-HJ-NP-Za-km-z]{20,}' "$PKT32E"
forbid "$PKT32E contains xprv-like material" -E '[x]prv[1-9A-HJ-NP-Za-km-z]{20,}' "$PKT32E"
forbid "$PKT32E contains suspicious 41+ hex run" -E '[0-9a-fA-F]{41,}' "$PKT32E"
awk '{ s=$0
  while (match(s, /[A-Za-z0-9+\/=]+/)) {
    t=substr(s,RSTART,RLENGTH)
    if (length(t) >= 44) { print t; exit }
    s=substr(s,RSTART+RLENGTH)
  }
}' "$PKT32E" > "$tmpdir/p32e.base64"; p32erc=$?
[ "$p32erc" -eq 0 ] || err "$PKT32E base64 material scan failed (awk exit $p32erc)"
[ ! -s "$tmpdir/p32e.base64" ] || err "$PKT32E contains base64-like payload material"
# Exact 40-hex token allowlist for this packet.
printf '%s\n' \
  838a732ab556b51ca8b0b61bed9ae9d512d47a87 \
  877866e5a3636bdfb7015d715e048ccfad63d939 \
  981b1b497102187da66fb4e82ef0725b32c088f7 \
  a996a6d7c2bfa3a15109085475868410fe354422 \
  b4594210975940df71b0e941841320d11defaa4c \
  be4d019e349e15ca575ac64b64f900957283e5e0 \
  e57faff4ead69ddf108cf522cb6c3cbfbef8219a \
  f4e127a92fc68243274b7d384e335fa4632e5dd2 > "$tmpdir/p32e.hex.exp" \
  || err "$PKT32E exact-40-hex allowlist generation failed"
LC_ALL=C sort -c "$tmpdir/p32e.hex.exp" \
  || err "$PKT32E exact-40-hex allowlist is not sorted (fail-closed self-check)"
awk '{s=$0; while (match(s,/[0-9a-fA-F]+/)) {t=substr(s,RSTART,RLENGTH); if (length(t)==40) print tolower(t); s=substr(s,RSTART+RLENGTH)}}' \
  "$PKT32E" > "$tmpdir/p32e.hex.raw"; p32erc=$?
[ "$p32erc" -eq 0 ] || err "$PKT32E exact-40-hex enumeration failed"
LC_ALL=C sort -u "$tmpdir/p32e.hex.raw" > "$tmpdir/p32e.hex.act"; p32erc=$?
[ "$p32erc" -eq 0 ] || err "$PKT32E exact-40-hex sort failed"
cmp -s "$tmpdir/p32e.hex.exp" "$tmpdir/p32e.hex.act"; p32erc=$?
[ "$p32erc" -eq 0 ] || err "$PKT32E contains a missing, altered, or extra exact-40-hex token"

# F3.2f PSBT-output owner-direction record. The whole-record blob is the
# decisive closed-world invariant; the checks below also bind its
# source rows, owner-direction map, encoding, and non-enacting boundary.
REC32F=docs/f3/F3.2F-PSBT-OUTPUT-TEST-OWNER-DIRECTION-RECORD.md
[ -f "$REC32F" ] || err "$REC32F missing"
p32fblob=a066fc9710371f414d158a3deb9c345f2b00821b
git --no-optional-locks hash-object -- "$REC32F" > "$tmpdir/p32f.blob.act"; p32frc=$?
[ "$p32frc" -eq 0 ] || err "$REC32F git hash-object audit-locator scan failed"
[ -s "$tmpdir/p32f.blob.act" ] || err "$REC32F git hash-object audit-locator scan produced empty output"
printf '%s\n' "$p32fblob" > "$tmpdir/p32f.blob.exp" || err "$REC32F blob fixture generation failed"
cmp -s "$tmpdir/p32f.blob.exp" "$tmpdir/p32f.blob.act"; p32frc=$?
[ "$p32frc" -eq 0 ] || err "$REC32F differs from its pinned whole-record blob"
p32ftitle='# QK-F3.2f — PSBT-Output TEST-ARCHITECTURE Owner-Direction Record'
p32fstatus='STATUS: OWNER DIRECTIONS RECORDED — NON-ENACTING — COMPLETE PROPOSED PLAN / ORACLE TEXT FOR QK-TST-DIFF-002 AND QK-TST-DIFF-004 APPROVED EXACTLY AS PRINTED — NO CHANGE TO ANY OTHER CELL APPROVED — QK-TST-REH-004 RETAINED UNCHANGED — CANONICAL TEST-ARCHITECTURE UNCHANGED — ALL QK-TST STATUSES UNCHANGED — PLANNED — NOT RUN — F32C-D11-Q-002 THROUGH Q-012 UNANSWERED — D-11 AND D-09 NOT SELECTED — EVERY QK-LIM OPEN — PSBT PROFILE AND EVERY CLAUSE NOT ACCEPTED — NO IMPLEMENTATION, TESTING, VECTORS, EVIDENCE, OR MEDIA I/O — NO EVIDENCE OR GATE CHANGE — LOCAL AND UNPUBLISHED.'
p32fend='END OF OWNER-DIRECTION RECORD — TWO NON-ENACTING PLAN / ORACLE DIRECTIONS RECORDED — QK-TST-REH-004 UNCHANGED — CANONICAL TEST-ARCHITECTURE AND ALL QK-TST STATUSES UNCHANGED — F32C-D11-Q-002 THROUGH Q-012 UNANSWERED — D-11 AND D-09 NOT SELECTED — LOCAL AND UNPUBLISHED.'
sed -n '1p' "$REC32F" > "$tmpdir/p32f.title.act"; p32frc=$?
[ "$p32frc" -eq 0 ] || err "$REC32F title read failed"
printf '%s\n' "$p32ftitle" > "$tmpdir/p32f.title.exp" || err "$REC32F title fixture generation failed"
cmp -s "$tmpdir/p32f.title.exp" "$tmpdir/p32f.title.act"; p32frc=$?
[ "$p32frc" -eq 0 ] || err "$REC32F exact title differs"
grep '^STATUS:' "$REC32F" > "$tmpdir/p32f.status.act"; p32frc=$?
[ "$p32frc" -eq 0 ] || err "$REC32F STATUS extraction failed"
printf '%s\n' "$p32fstatus" > "$tmpdir/p32f.status.exp" || err "$REC32F STATUS fixture generation failed"
cmp -s "$tmpdir/p32f.status.exp" "$tmpdir/p32f.status.act"; p32frc=$?
[ "$p32frc" -eq 0 ] || err "$REC32F exact STATUS differs"
p32fstatusany=$(awk '{s=$0; while (match(s,/STATUS:/)) {c++; s=substr(s,RSTART+RLENGTH)}} END {print c+0}' "$REC32F"); p32frc=$?
[ "$p32frc" -eq 0 ] || err "$REC32F global STATUS scan failed"
[ "$p32fstatusany" = 1 ] || err "$REC32F must contain exactly one STATUS occurrence"
tail -n 1 "$REC32F" > "$tmpdir/p32f.end.act"; p32frc=$?
[ "$p32frc" -eq 0 ] || err "$REC32F terminal line read failed"
printf '%s\n' "$p32fend" > "$tmpdir/p32f.end.exp" || err "$REC32F terminal fixture generation failed"
cmp -s "$tmpdir/p32f.end.exp" "$tmpdir/p32f.end.act"; p32frc=$?
[ "$p32frc" -eq 0 ] || err "$REC32F exact terminal line differs"
cat > "$tmpdir/p32f.headings.exp" <<'QK_F32F_HEADINGS_EOF' || err "$REC32F heading fixture generation failed"
# QK-F3.2f — PSBT-Output TEST-ARCHITECTURE Owner-Direction Record
## Standing and source boundary
## Owner approval words exactly
## Owner preparation authority words exactly
## Exact direction map
## Source rows containing approved Plan / oracle directions
## Unchanged external-finalization control
## Historical and source honesty
## Dependencies and non-effects
QK_F32F_HEADINGS_EOF
grep '^#' "$REC32F" > "$tmpdir/p32f.headings.act"; p32frc=$?
[ "$p32frc" -eq 0 ] || err "$REC32F heading extraction failed"
cmp -s "$tmpdir/p32f.headings.exp" "$tmpdir/p32f.headings.act"; p32frc=$?
[ "$p32frc" -eq 0 ] || err "$REC32F heading set differs"
for p32fline in \
  '| F32F-TST-DIR-001 | QK-TST-DIFF-002 | Plan / oracle only | COMPLETE PROPOSED PLAN / ORACLE TEXT APPROVED AS OWNER DIRECTION — NON-ENACTING — CANONICAL ROW AND STATUS UNCHANGED. |' \
  '| F32F-TST-DIR-002 | QK-TST-DIFF-004 | Plan / oracle only | COMPLETE PROPOSED PLAN / ORACLE TEXT APPROVED AS OWNER DIRECTION — NON-ENACTING — CANONICAL ROW AND STATUS UNCHANGED. |' \
  'There are exactly two owner directions. QK-TST-REH-004 is a separate unchanged external-finalization control, not a third approval.' \
  'QK-TST-REH-004 receives no candidate edit or owner direction and remains PLANNED — NOT RUN. Its finalization remains external and its existing OD-02 dependency remains unchanged.'; do
  p32fn=$(grep -cFx -e "$p32fline" "$REC32F"); p32frc=$?
  [ "$p32frc" -le 1 ] || err "$REC32F exact direction/control scan failed"
  [ "$p32fn" = 1 ] || err "$REC32F required direction/control line is missing, altered, or duplicated"
done
grep '^| QK-TST-DIFF-' "$PKT32E" > "$tmpdir/p32f.source.diff.all"; p32frc=$?
[ "$p32frc" -eq 0 ] || err "$PKT32E proposed-row source extraction failed"
sed -n '3,4p' "$tmpdir/p32f.source.diff.all" > "$tmpdir/p32f.source.diff"; p32frc=$?
[ "$p32frc" -eq 0 ] || err "$PKT32E proposed-row source selection failed"
grep '^| QK-TST-DIFF-' "$REC32F" > "$tmpdir/p32f.record.diff"; p32frc=$?
[ "$p32frc" -eq 0 ] || err "$REC32F source-row carrying approved Plan / oracle extraction failed"
cmp -s "$tmpdir/p32f.source.diff" "$tmpdir/p32f.record.diff"; p32frc=$?
[ "$p32frc" -eq 0 ] || err "$REC32F DIFF source rows carrying the approved Plan / oracle cells are not byte-exact from F3.2e"
p32freh=$(grep -cFx -e "$p32ereh004" "$REC32F"); p32frc=$?
[ "$p32frc" -le 1 ] || err "$REC32F REH-004 control scan failed"
[ "$p32freh" = 1 ] || err "$REC32F REH-004 control row is missing, altered, or duplicated"
for p32fowner in \
  'Approve, as non-enacting owner directions, the complete proposed Plan / oracle text for QK-TST-DIFF-002 and QK-TST-DIFF-004 exactly as printed in the F3.2e packet at published commit 574e790193d45d3f392c64951d319bb5fde11d20. Approve no change to any other cell. QK-TST-REH-004 remains unchanged.' \
  'This approval does not amend docs/TEST-ARCHITECTURE.md, change any QK-TST status, authorize testing or evidence, answer F32C-D11-Q-002 through Q-012, or select D-11, D-09, any QK-LIM, the PSBT profile, or any clause.' \
  'Authorize preparation and independent audit of a non-enacting docs-only F3.2f PSBT-output test owner-direction record from 574e790193d45d3f392c64951d319bb5fde11d20, recording only my approved directions for QK-TST-DIFF-002 and QK-TST-DIFF-004, with QK-TST-REH-004 retained unchanged and only the mechanically necessary verifier bindings.' \
  'No canonical TEST-ARCHITECTURE edit, test-status change, F32C-D11-Q-002 through Q-012 answer, D-11 or D-09 selection, QK-LIM selection, profile or clause acceptance, implementation, testing, vectors, evidence, media I/O, hardware work, settings changes, or publication.'; do
  p32fn=$(grep -cFx -e "$p32fowner" "$REC32F"); p32frc=$?
  [ "$p32frc" -le 1 ] || err "$REC32F owner transcript scan failed"
  [ "$p32fn" = 1 ] || err "$REC32F owner transcript line is missing, altered, or duplicated"
done
git --no-optional-locks show 45f2b362994b785d303e91b8e530efc724dc2d81:docs/TEST-ARCHITECTURE.md \
  > "$tmpdir/p32f.testarch.source" 2> "$tmpdir/p32f.testarch.source.err"; p32frc=$?
[ "$p32frc" -eq 0 ] || err "cannot read the historical F3.2f TEST-ARCHITECTURE source"
[ -s "$tmpdir/p32f.testarch.source" ] || err "historical F3.2f TEST-ARCHITECTURE source is empty"
for p32fsourcepair in \
  'docs/f3/F3.2E-PSBT-OUTPUT-TEST-ALIGNMENT-PACKET.md 4ffa20afbedeb0b6cfbbe57298f941bc0537683e' \
  "$tmpdir/p32f.testarch.source f4e127a92fc68243274b7d384e335fa4632e5dd2"; do
  p32fsource=${p32fsourcepair%% *}
  p32fexpected=${p32fsourcepair#* }
  git --no-optional-locks hash-object -- "$p32fsource" > "$tmpdir/p32f.source.act"; p32frc=$?
  [ "$p32frc" -eq 0 ] || err "$p32fsource source blob scan failed"
  printf '%s\n' "$p32fexpected" > "$tmpdir/p32f.source.exp" || err "$p32fsource source blob fixture failed"
  cmp -s "$tmpdir/p32f.source.exp" "$tmpdir/p32f.source.act"; p32frc=$?
  [ "$p32frc" -eq 0 ] || err "$p32fsource differs from the F3.2f reviewed source blob"
done
iconv -f UTF-8 -t UTF-8 "$REC32F" > "$tmpdir/p32f.utf8" 2> "$tmpdir/p32f.iconv.err"; p32frc=$?
[ "$p32frc" -eq 0 ] || err "$REC32F is not strict UTF-8"
[ -s "$tmpdir/p32f.utf8" ] || err "$REC32F UTF-8 stage produced empty output"
cmp -s "$REC32F" "$tmpdir/p32f.utf8"; p32frc=$?
[ "$p32frc" -eq 0 ] || err "$REC32F UTF-8 round trip changed bytes"
p32f_final_lf_ok() {
  p32flffile=$1
  p32flftag=$2
  tail -c 1 "$p32flffile" > "$tmpdir/p32f.$p32flftag.last.raw" || return 2
  [ -s "$tmpdir/p32f.$p32flftag.last.raw" ] || return 1
  od -An -tuC "$tmpdir/p32f.$p32flftag.last.raw" > "$tmpdir/p32f.$p32flftag.last.od" || return 2
  tr -d '[:space:]' < "$tmpdir/p32f.$p32flftag.last.od" > "$tmpdir/p32f.$p32flftag.last.norm" || return 2
  [ -s "$tmpdir/p32f.$p32flftag.last.norm" ] || return 1
  p32flflast=$(cat "$tmpdir/p32f.$p32flftag.last.norm") || return 2
  case $p32flflast in ''|*[!0-9]*) return 1 ;; esac
  [ "$p32flflast" = 10 ] || return 1
  tail -c 2 "$p32flffile" > "$tmpdir/p32f.$p32flftag.last2.raw" || return 2
  cmp -s "$tmpdir/p32f.lf.double" "$tmpdir/p32f.$p32flftag.last2.raw"
  p32flfrc=$?
  case $p32flfrc in 0) return 1 ;; 1) : ;; *) return 2 ;; esac
  cmp -s "$tmpdir/p32f.lf.crlf" "$tmpdir/p32f.$p32flftag.last2.raw"
  p32flfrc=$?
  case $p32flfrc in 0) return 1 ;; 1) return 0 ;; *) return 2 ;; esac
}
printf '\n\n' > "$tmpdir/p32f.lf.double" || err "$REC32F double-final-LF fixture generation failed"
printf '\r\n' > "$tmpdir/p32f.lf.crlf" || err "$REC32F CRLF fixture generation failed"
printf 'qk\n' > "$tmpdir/p32f.lf.valid" || err "$REC32F valid-final-LF fixture generation failed"
printf 'qk' > "$tmpdir/p32f.lf.missing" || err "$REC32F missing-final-LF fixture generation failed"
printf 'qk\n\n' > "$tmpdir/p32f.lf.doubled" || err "$REC32F doubled-final-LF fixture generation failed"
printf 'qk\r\n' > "$tmpdir/p32f.lf.crlfinput" || err "$REC32F CRLF input fixture generation failed"
printf 'qkn' > "$tmpdir/p32f.lf.asciin" || err "$REC32F ASCII-n fixture generation failed"
p32f_final_lf_ok "$tmpdir/p32f.lf.valid" valid; p32frc=$?
[ "$p32frc" -eq 0 ] || err "$REC32F final-LF predicate rejected the focused valid-LF control"
for p32flfinvalid in missing doubled crlfinput asciin; do
  p32f_final_lf_ok "$tmpdir/p32f.lf.$p32flfinvalid" "$p32flfinvalid"; p32frc=$?
  [ "$p32frc" -eq 1 ] || err "$REC32F final-LF predicate failed its focused $p32flfinvalid rejection control (exit $p32frc)"
done
p32f_final_lf_ok "$REC32F" record; p32frc=$?
case $p32frc in
  0) : ;;
  1) err "$REC32F must end in exact decimal byte 10, without double final LF or CRLF" ;;
  *) err "$REC32F final-LF evidence producer or normalization failed (exit $p32frc)" ;;
esac
forbid "$REC32F contains a tab, trailing whitespace, HTML comment, hidden link definition, fence, blockquote, URL, or email material" \
  -E '	|[[:blank:]]$|<!--|-->|^\[[^]]+\]:|^```|^[[:space:]]*>|https?://|[[:alnum:]_.+-]+@[[:alnum:].-]+' "$REC32F"
forbid "$REC32F contains PSBT or key payload material" -E '[7]0736274|[c]HNidP|[x]pub|[x]prv' "$REC32F"
printf '%s\n' \
  22114c6741ac653b9c5079b1bfccdb795a88f3df \
  4ffa20afbedeb0b6cfbbe57298f941bc0537683e \
  574e790193d45d3f392c64951d319bb5fde11d20 \
  574e790193d45d3f392c64951d319bb5fde11d20 \
  574e790193d45d3f392c64951d319bb5fde11d20 \
  574e790193d45d3f392c64951d319bb5fde11d20 \
  f4e127a92fc68243274b7d384e335fa4632e5dd2 > "$tmpdir/p32f.hex.exp" \
  || err "$REC32F exact-40-hex multiset fixture generation failed"
awk '{s=$0; while (match(s,/[0-9a-fA-F]+/)) {t=substr(s,RSTART,RLENGTH); if (length(t)==40) print tolower(t); s=substr(s,RSTART+RLENGTH)}}' \
  "$REC32F" > "$tmpdir/p32f.hex.raw"; p32frc=$?
[ "$p32frc" -eq 0 ] || err "$REC32F exact-40-hex multiset enumeration failed"
LC_ALL=C sort "$tmpdir/p32f.hex.raw" > "$tmpdir/p32f.hex.act"; p32frc=$?
[ "$p32frc" -eq 0 ] || err "$REC32F exact-40-hex multiset sort failed"
cmp -s "$tmpdir/p32f.hex.exp" "$tmpdir/p32f.hex.act"; p32frc=$?
[ "$p32frc" -eq 0 ] || err "$REC32F exact-40-hex multiset differs"

# F3.2g canonical TEST-ARCHITECTURE amendment. Reconstruct the expected
# document deterministically from the published F3.2f base by replacing
# exactly one unique complete old row for each target with the complete
# approved row carried by the pinned F3.2f record. The row-cell checks
# independently require every non-Plan cell, including Status, to remain
# byte-identical; the whole-document comparison preserves every other byte.
TESTARCH32G=docs/TEST-ARCHITECTURE.md
p32gbase=45f2b362994b785d303e91b8e530efc724dc2d81
p32gstage=a64399dd35aef8d6daa05171f1da30c8026f6d1f
p32gbaseblob=f4e127a92fc68243274b7d384e335fa4632e5dd2
p32gactiveblob=065e20eed4e916c907a244aa3e5ca2e66cbc5d4e
git --no-optional-locks show "$p32gbase:$TESTARCH32G" \
  > "$tmpdir/p32g.testarch.base" 2> "$tmpdir/p32g.testarch.base.err"; p32grc=$?
[ "$p32grc" -eq 0 ] || err "$TESTARCH32G base read failed"
[ -s "$tmpdir/p32g.testarch.base" ] || err "$TESTARCH32G base read produced empty output"
git --no-optional-locks hash-object -- "$tmpdir/p32g.testarch.base" \
  > "$tmpdir/p32g.base.blob.act"; p32grc=$?
[ "$p32grc" -eq 0 ] || err "$TESTARCH32G base blob scan failed"
[ -s "$tmpdir/p32g.base.blob.act" ] || err "$TESTARCH32G base blob scan produced empty output"
printf '%s\n' "$p32gbaseblob" > "$tmpdir/p32g.base.blob.exp" \
  || err "$TESTARCH32G base blob fixture generation failed"
cmp -s "$tmpdir/p32g.base.blob.exp" "$tmpdir/p32g.base.blob.act"; p32grc=$?
[ "$p32grc" -eq 0 ] || err "$TESTARCH32G base differs from its pinned blob"
git --no-optional-locks show "$p32gstage:$TESTARCH32G" > "$tmpdir/p32g.testarch.frozen" 2> "$tmpdir/p32g.testarch.frozen.err"; p32grc=$?
[ "$p32grc" -eq 0 ] || err "$TESTARCH32G frozen-stage read failed"
[ -s "$tmpdir/p32g.testarch.frozen" ] || err "$TESTARCH32G frozen-stage read produced empty output"
git --no-optional-locks hash-object -- "$tmpdir/p32g.testarch.frozen" \
  > "$tmpdir/p32g.active.blob.act"; p32grc=$?
[ "$p32grc" -eq 0 ] || err "$TESTARCH32G active blob scan failed"
[ -s "$tmpdir/p32g.active.blob.act" ] || err "$TESTARCH32G active blob scan produced empty output"
printf '%s\n' "$p32gactiveblob" > "$tmpdir/p32g.active.blob.exp" \
  || err "$TESTARCH32G active blob fixture generation failed"
cmp -s "$tmpdir/p32g.active.blob.exp" "$tmpdir/p32g.active.blob.act"; p32grc=$?
[ "$p32grc" -eq 0 ] || err "$TESTARCH32G differs from the authorized F3.2g blob"

for p32gid in QK-TST-DIFF-002 QK-TST-DIFF-004; do
  awk -v prefix="| $p32gid |" 'index($0,prefix) == 1 {print}' \
    "$tmpdir/p32g.testarch.base" > "$tmpdir/p32g.$p32gid.old"; p32grc=$?
  [ "$p32grc" -eq 0 ] || err "$p32gid old-row extraction failed"
  [ -s "$tmpdir/p32g.$p32gid.old" ] || err "$p32gid old-row extraction produced empty output"
  p32grows=$(awk 'END {print NR+0}' "$tmpdir/p32g.$p32gid.old"); p32grc=$?
  [ "$p32grc" -eq 0 ] || err "$p32gid old-row count failed"
  [ "$p32grows" = 1 ] || err "$p32gid old row is not unique in the pinned base"
  awk -v prefix="| $p32gid |" 'index($0,prefix) == 1 {print}' \
    "$REC32F" > "$tmpdir/p32g.$p32gid.new"; p32grc=$?
  [ "$p32grc" -eq 0 ] || err "$p32gid approved-row extraction failed"
  [ -s "$tmpdir/p32g.$p32gid.new" ] || err "$p32gid approved-row extraction produced empty output"
  p32grows=$(awk 'END {print NR+0}' "$tmpdir/p32g.$p32gid.new"); p32grc=$?
  [ "$p32grc" -eq 0 ] || err "$p32gid approved-row count failed"
  [ "$p32grows" = 1 ] || err "$p32gid approved row is not unique in the pinned F3.2f record"
  cat "$tmpdir/p32g.$p32gid.old" "$tmpdir/p32g.$p32gid.new" \
    > "$tmpdir/p32g.$p32gid.pair"; p32grc=$?
  [ "$p32grc" -eq 0 ] || err "$p32gid old/new row pair generation failed"
  [ -s "$tmpdir/p32g.$p32gid.pair" ] || err "$p32gid old/new row pair is empty"
  awk -F '|' '
    NR == 1 {
      if (NF != 10) exit 11
      for (i=1; i<=NF; i++) old[i]=$i
      next
    }
    NR == 2 {
      if (NF != 10) exit 12
      if ($4 == old[4]) exit 13
      for (i=1; i<=NF; i++) if (i != 4 && $i != old[i]) exit 14
      compared=1
    }
    END { if (NR != 2 || compared != 1) exit 15 }
  ' "$tmpdir/p32g.$p32gid.pair"; p32grc=$?
  [ "$p32grc" -eq 0 ] || err "$p32gid changed a non-Plan cell or did not change exactly the complete Plan / oracle cell (awk exit $p32grc)"
done

p32gold002=$(cat "$tmpdir/p32g.QK-TST-DIFF-002.old"); p32grc=$?
[ "$p32grc" -eq 0 ] || err "QK-TST-DIFF-002 old-row read failed"
[ -n "$p32gold002" ] || err "QK-TST-DIFF-002 old-row read produced empty output"
p32gnew002=$(cat "$tmpdir/p32g.QK-TST-DIFF-002.new"); p32grc=$?
[ "$p32grc" -eq 0 ] || err "QK-TST-DIFF-002 approved-row read failed"
[ -n "$p32gnew002" ] || err "QK-TST-DIFF-002 approved-row read produced empty output"
p32gold004=$(cat "$tmpdir/p32g.QK-TST-DIFF-004.old"); p32grc=$?
[ "$p32grc" -eq 0 ] || err "QK-TST-DIFF-004 old-row read failed"
[ -n "$p32gold004" ] || err "QK-TST-DIFF-004 old-row read produced empty output"
p32gnew004=$(cat "$tmpdir/p32g.QK-TST-DIFF-004.new"); p32grc=$?
[ "$p32grc" -eq 0 ] || err "QK-TST-DIFF-004 approved-row read failed"
[ -n "$p32gnew004" ] || err "QK-TST-DIFF-004 approved-row read produced empty output"
awk -v old002="$p32gold002" -v new002="$p32gnew002" \
    -v old004="$p32gold004" -v new004="$p32gnew004" '
  $0 == old002 { count002++; print new002; next }
  $0 == old004 { count004++; print new004; next }
  { print }
  END { if (count002 != 1 || count004 != 1) exit 21 }
' "$tmpdir/p32g.testarch.base" > "$tmpdir/p32g.testarch.expected"; p32grc=$?
[ "$p32grc" -eq 0 ] || err "$TESTARCH32G exact two-row reconstruction failed (awk exit $p32grc)"
[ -s "$tmpdir/p32g.testarch.expected" ] || err "$TESTARCH32G exact two-row reconstruction produced empty output"
cmp -s "$tmpdir/p32g.testarch.expected" "$tmpdir/p32g.testarch.frozen"; p32grc=$?
[ "$p32grc" -eq 0 ] || err "$TESTARCH32G is not the exact unique two-Plan-cell transformation of the pinned base"

for p32gsourcepair in \
  'docs/f3/F3.2E-PSBT-OUTPUT-TEST-ALIGNMENT-PACKET.md 4ffa20afbedeb0b6cfbbe57298f941bc0537683e' \
  'docs/f3/F3.2F-PSBT-OUTPUT-TEST-OWNER-DIRECTION-RECORD.md a066fc9710371f414d158a3deb9c345f2b00821b'; do
  p32gsource=${p32gsourcepair%% *}
  p32gsourceblob=${p32gsourcepair#* }
  git --no-optional-locks hash-object -- "$p32gsource" \
    > "$tmpdir/p32g.source.blob.act"; p32grc=$?
  [ "$p32grc" -eq 0 ] || err "$p32gsource protected-blob scan failed"
  [ -s "$tmpdir/p32g.source.blob.act" ] || err "$p32gsource protected-blob scan produced empty output"
  printf '%s\n' "$p32gsourceblob" > "$tmpdir/p32g.source.blob.exp" \
    || err "$p32gsource protected-blob fixture generation failed"
  cmp -s "$tmpdir/p32g.source.blob.exp" "$tmpdir/p32g.source.blob.act"; p32grc=$?
  [ "$p32grc" -eq 0 ] || err "$p32gsource differs from its protected blob"
done

for p32gowner in \
  'Authorize preparation and independent audit of a docs-only F3.2g canonical TEST-ARCHITECTURE amendment from 45f2b362994b785d303e91b8e530efc724dc2d81, replacing only the complete Plan / oracle cells of QK-TST-DIFF-002 and QK-TST-DIFF-004 with the owner-approved text recorded in the published F3.2f owner-direction record, byte-for-byte. Preserve every other cell and row unchanged, retain QK-TST-REH-004 byte-for-byte, and include only the mechanically necessary Decision Log and verifier bindings.' \
  'No QK-TST status change or testing/evidence; no F32C-D11-Q-002 through Q-012 answer; no D-11, D-09, QK-LIM, profile, clause, OD-05/06, dependency, corpus, implementation, vector, fixture, media-I/O, hardware, license, settings, credential, release, or publication change.'; do
  grep -cFx -e "$p32gowner" docs/DECISION-LOG.md > "$tmpdir/p32g.owner.count"; p32grc=$?
  [ "$p32grc" -le 1 ] || err "F3.2g owner-transcript scan failed"
  [ -s "$tmpdir/p32g.owner.count" ] || err "F3.2g owner-transcript count produced empty output"
  p32gownercount=$(cat "$tmpdir/p32g.owner.count"); p32grc=$?
  [ "$p32grc" -eq 0 ] || err "F3.2g owner-transcript count read failed"
  [ "$p32gownercount" = 1 ] || err "F3.2g owner-transcript line is missing, altered, or duplicated"
done

awk -v prefix='| QK-TST-REH-004 |' 'index($0,prefix) == 1 {print}' \
  "$tmpdir/p32g.testarch.base" > "$tmpdir/p32g.reh.base"; p32grc=$?
[ "$p32grc" -eq 0 ] || err "QK-TST-REH-004 base-row extraction failed"
[ -s "$tmpdir/p32g.reh.base" ] || err "QK-TST-REH-004 base-row extraction produced empty output"
awk -v prefix='| QK-TST-REH-004 |' 'index($0,prefix) == 1 {print}' \
  "$tmpdir/p32g.testarch.frozen" > "$tmpdir/p32g.reh.active"; p32grc=$?
[ "$p32grc" -eq 0 ] || err "QK-TST-REH-004 active-row extraction failed"
[ -s "$tmpdir/p32g.reh.active" ] || err "QK-TST-REH-004 active-row extraction produced empty output"
cmp -s "$tmpdir/p32g.reh.base" "$tmpdir/p32g.reh.active"; p32grc=$?
[ "$p32grc" -eq 0 ] || err "QK-TST-REH-004 changed"
awk -F '|' '
  index($0,"| QK-TST-") == 1 {
    rows++
    if (NF != 10 || $9 != " PLANNED — NOT RUN ") exit 31
  }
  END { if (rows == 0) exit 32 }
' "$tmpdir/p32g.testarch.frozen"; p32grc=$?
[ "$p32grc" -eq 0 ] || err "$TESTARCH32G contains a changed or malformed QK-TST status cell (awk exit $p32grc)"

# F3.2h non-binding QK-LIM-PSBT-027 cross-document alignment packet.
# The whole-packet blob is decisive; the checks below independently bind
# the exact source graph, owner transcript, canonical inventory, one
# unanswered question, three ordered unselected options, recommendation
# boundary, source/protected blobs, encoding, and non-enacting scope.
PKT32H=docs/f3/F3.2H-QK-LIM-PSBT-027-CROSS-DOCUMENT-ALIGNMENT-PACKET.md
[ -f "$PKT32H" ] || err "$PKT32H missing"
p32hbase=a64399dd35aef8d6daa05171f1da30c8026f6d1f
p32ha=da55fb4bcd4983140c8fb379cc3322eec99284f0
p32hstage=e36b41e5cd55264b4b745550c96c74968b06eae7
p32hdlogblob=e7b7db5a12ea3c0a32d2b9cc3287e4d67d1da1bc
p32hblob=e18ba6b4a5c2ee5fc5b7d1a464b656c631b526d5
p32hparent=$(git --no-optional-locks rev-parse "$p32ha^" 2>/dev/null); p32hrc=$?
[ "$p32hrc" -eq 0 ] || err "F3.2h commit A parent resolution failed"
[ -n "$p32hparent" ] || err "F3.2h commit A parent resolution produced empty output"
[ "$p32hparent" = "$p32hbase" ] || err "F3.2h commit A parent is $p32hparent, expected $p32hbase"
git --no-optional-locks show -s --format=%B "$p32ha" > "$tmpdir/p32h.a.msg.act"; p32hrc=$?
[ "$p32hrc" -eq 0 ] || err "F3.2h commit A message read failed"
printf '%s\n\n' 'docs: authorize F3.2h QK-LIM-PSBT-027 alignment packet' \
  > "$tmpdir/p32h.a.msg.exp" || err "F3.2h commit A message fixture generation failed"
cmp -s "$tmpdir/p32h.a.msg.exp" "$tmpdir/p32h.a.msg.act"; p32hrc=$?
[ "$p32hrc" -eq 0 ] || err "F3.2h commit A full message differs"
git --no-optional-locks diff-tree --no-commit-id --name-only -r "$p32ha" \
  > "$tmpdir/p32h.a.paths.act"; p32hrc=$?
[ "$p32hrc" -eq 0 ] || err "F3.2h commit A path enumeration failed"
printf '%s\n' docs/DECISION-LOG.md > "$tmpdir/p32h.a.paths.exp" \
  || err "F3.2h commit A path fixture generation failed"
cmp -s "$tmpdir/p32h.a.paths.exp" "$tmpdir/p32h.a.paths.act"; p32hrc=$?
[ "$p32hrc" -eq 0 ] || err "F3.2h commit A changes a path other than docs/DECISION-LOG.md"
git --no-optional-locks ls-tree "$p32ha" -- docs/DECISION-LOG.md \
  > "$tmpdir/p32h.a.tree"; p32hrc=$?
[ "$p32hrc" -eq 0 ] || err "F3.2h commit A Decision Log tree lookup failed"
[ -s "$tmpdir/p32h.a.tree" ] || err "F3.2h commit A Decision Log tree entry is missing"
p32hatreelines=$(awk 'END {print NR+0}' "$tmpdir/p32h.a.tree"); p32hrc=$?
[ "$p32hrc" -eq 0 ] || err "F3.2h commit A Decision Log tree count failed"
[ "$p32hatreelines" = 1 ] || err "F3.2h commit A Decision Log tree entry is not unique"
p32hamode=$(awk 'NR == 1 {print $1}' "$tmpdir/p32h.a.tree"); p32hrc=$?
[ "$p32hrc" -eq 0 ] || err "F3.2h commit A Decision Log mode extraction failed"
p32hablob=$(awk 'NR == 1 {print $3}' "$tmpdir/p32h.a.tree"); p32hrc=$?
[ "$p32hrc" -eq 0 ] || err "F3.2h commit A Decision Log blob extraction failed"
[ "$p32hamode" = 100644 ] || err "F3.2h commit A Decision Log mode is $p32hamode, expected 100644"
[ "$p32hablob" = "$p32hdlogblob" ] || err "F3.2h commit A Decision Log blob differs"

git --no-optional-locks hash-object -- "$PKT32H" > "$tmpdir/p32h.blob.act"; p32hrc=$?
[ "$p32hrc" -eq 0 ] || err "$PKT32H blob scan failed"
[ -s "$tmpdir/p32h.blob.act" ] || err "$PKT32H blob scan produced empty output"
printf '%s\n' "$p32hblob" > "$tmpdir/p32h.blob.exp" \
  || err "$PKT32H blob fixture generation failed"
cmp -s "$tmpdir/p32h.blob.exp" "$tmpdir/p32h.blob.act"; p32hrc=$?
[ "$p32hrc" -eq 0 ] || err "$PKT32H differs from its pinned whole-packet blob"

p32htitle='# QK-F3.2h — QK-LIM-PSBT-027 Cross-Document Alignment Packet (Non-Binding)'
p32hstatus='STATUS: OWNER-AUTHORIZED ALIGNMENT INPUT ONLY — NON-BINDING — NON-NORMATIVE — ONE QUESTION — THREE DISPOSITIONS — ALL UNSELECTED — OPTION 1 RECOMMENDED AS ANALYSIS ONLY, NOT SELECTED — NO OWNER SELECTION — NO CANONICAL EDIT — QK-LIM-PSBT-026 AND QK-LIM-PSBT-027 UNCHANGED — NO QK-LIM VALUE, TITLE, STATUS, LINK, OR ROW CHANGE — NO QK-TST PLAN / ORACLE OR STATUS CHANGE — LOCAL AND UNPUBLISHED.'
p32hend='END OF PACKET — F3.2h QK-LIM-PSBT-027 CROSS-DOCUMENT ALIGNMENT INPUT ONLY — ONE QUESTION — THREE DISPOSITIONS — ALL UNSELECTED — OPTION 1 RECOMMENDED AS ANALYSIS ONLY, NOT SELECTED — NO CANONICAL EDIT — QK-LIM-PSBT-026 AND QK-LIM-PSBT-027 UNCHANGED — LOCAL AND UNPUBLISHED.'
sed -n '1p' "$PKT32H" > "$tmpdir/p32h.title.act"; p32hrc=$?
[ "$p32hrc" -eq 0 ] || err "$PKT32H title read failed"
printf '%s\n' "$p32htitle" > "$tmpdir/p32h.title.exp" || err "$PKT32H title fixture generation failed"
cmp -s "$tmpdir/p32h.title.exp" "$tmpdir/p32h.title.act"; p32hrc=$?
[ "$p32hrc" -eq 0 ] || err "$PKT32H exact title is not first"
grep '^STATUS:' "$PKT32H" > "$tmpdir/p32h.status.act"; p32hrc=$?
[ "$p32hrc" -eq 0 ] || err "$PKT32H STATUS extraction failed"
printf '%s\n' "$p32hstatus" > "$tmpdir/p32h.status.exp" || err "$PKT32H STATUS fixture generation failed"
cmp -s "$tmpdir/p32h.status.exp" "$tmpdir/p32h.status.act"; p32hrc=$?
[ "$p32hrc" -eq 0 ] || err "$PKT32H exact STATUS differs"
p32hstatusany=$(awk '{s=$0; while (match(s,/STATUS:/)) {c++; s=substr(s,RSTART+RLENGTH)}} END {print c+0}' "$PKT32H"); p32hrc=$?
[ "$p32hrc" -eq 0 ] || err "$PKT32H global STATUS scan failed"
[ "$p32hstatusany" = 1 ] || err "$PKT32H must contain exactly one STATUS occurrence"
tail -n 1 "$PKT32H" > "$tmpdir/p32h.end.act"; p32hrc=$?
[ "$p32hrc" -eq 0 ] || err "$PKT32H terminal-line read failed"
printf '%s\n' "$p32hend" > "$tmpdir/p32h.end.exp" || err "$PKT32H terminal fixture generation failed"
cmp -s "$tmpdir/p32h.end.exp" "$tmpdir/p32h.end.act"; p32hrc=$?
[ "$p32hrc" -eq 0 ] || err "$PKT32H exact terminal line differs"

for p32howner in \
  'Authorize preparation and independent audit of a non-binding docs-only F3.2h QK-LIM-PSBT-027 cross-document alignment packet from a64399dd35aef8d6daa05171f1da30c8026f6d1f, with only the mechanically necessary Decision Log and verifier bindings. Limit scope to the stale “Raw final-transaction output bytes” dimension and its live links in docs/RESOURCE-BUDGETS.md, docs/REQUIREMENTS.md, and the QK-TST-DIFF-004 Links cell of docs/TEST-ARCHITECTURE.md.' \
  'Present exactly three unselected dispositions: recommended permanent tombstoning, unlinking, and non-reuse of ID 027; preservation as an inactive future contingency with no current links or value; or deferral with the known inconsistency retained. Reject deletion, renumbering, reuse, or repurposing of ID 027. Keep QK-LIM-PSBT-026 and all historical records unchanged.' \
  'No owner selection or canonical edit; no QK-LIM value, title, status, link, or row change; no QK-TST Plan / oracle or status change; no answer to F32C-D11-Q-002 through Q-012; no D-11, D-09, OD-05/06, profile, clause, implementation, testing, corpus, vector, fixture, evidence, media-I/O, hardware, license, gate, STOP-SHIP, setting, credential, release, publication, or remote change.'; do
  for p32hownerfile in docs/DECISION-LOG.md "$PKT32H"; do
    p32hownerhits=$(grep -cFx -e "$p32howner" "$p32hownerfile"); p32hrc=$?
    [ "$p32hrc" -le 1 ] || err "F3.2h owner transcript scan failed in $p32hownerfile"
    [ "$p32hownerhits" = 1 ] || err "F3.2h owner transcript differs or duplicates in $p32hownerfile"
  done
done
sed -n '/^### QK-AUTH-F3.2H-QK-LIM-PSBT-027-ALIGN-PKT-001 /,/^### QK-AUTH-F3.2I-QK-LIM-PSBT-027-DIR-REC-001 /p' \
  docs/DECISION-LOG.md > "$tmpdir/p32h.dlog.section"; p32hrc=$?
[ "$p32hrc" -eq 0 ] || err "F3.2h Decision Log section extraction failed"
sed -n '/^- \*\*Owner words exactly (literal three-paragraph block follows):\*\*$/,/^- \*\*Published parent and source locators:\*\*/p' \
  "$tmpdir/p32h.dlog.section" > "$tmpdir/p32h.owner.dlog.framed"; p32hrc=$?
[ "$p32hrc" -eq 0 ] || err "F3.2h Decision Log owner block extraction failed"
sed '1d;$d' "$tmpdir/p32h.owner.dlog.framed" > "$tmpdir/p32h.owner.dlog"; p32hrc=$?
[ "$p32hrc" -eq 0 ] || err "F3.2h Decision Log owner block deframing failed"
sed -n '/^## Owner words exactly$/,/^## Exact current canonical inventory$/p' \
  "$PKT32H" > "$tmpdir/p32h.owner.packet.framed"; p32hrc=$?
[ "$p32hrc" -eq 0 ] || err "F3.2h packet owner block extraction failed"
sed '1d;$d' "$tmpdir/p32h.owner.packet.framed" > "$tmpdir/p32h.owner.packet"; p32hrc=$?
[ "$p32hrc" -eq 0 ] || err "F3.2h packet owner block deframing failed"
cmp -s "$tmpdir/p32h.owner.dlog" "$tmpdir/p32h.owner.packet"; p32hrc=$?
[ "$p32hrc" -eq 0 ] || err "F3.2h Decision Log and packet owner transcript blocks differ"

while IFS=' ' read -r p32hsource p32hsourceblob; do
  git --no-optional-locks rev-parse "$p32hstage:$p32hsource" > "$tmpdir/p32h.source.act" 2>/dev/null; p32hrc=$?
  [ "$p32hrc" -eq 0 ] || err "F3.2h source/protected blob scan failed for $p32hsource"
  [ -s "$tmpdir/p32h.source.act" ] || err "F3.2h source/protected blob scan produced empty output for $p32hsource"
  printf '%s\n' "$p32hsourceblob" > "$tmpdir/p32h.source.exp" \
    || err "F3.2h source/protected blob fixture failed for $p32hsource"
  cmp -s "$tmpdir/p32h.source.exp" "$tmpdir/p32h.source.act"; p32hrc=$?
  [ "$p32hrc" -eq 0 ] || err "F3.2h source/protected blob differs for $p32hsource"
done <<'QK_F32H_SOURCE_BLOBS_EOF'
docs/RESOURCE-BUDGETS.md 1ae6494fc24a8e3572464cf45e6d43ea4875e95d
docs/REQUIREMENTS.md 981b1b497102187da66fb4e82ef0725b32c088f7
docs/TEST-ARCHITECTURE.md 065e20eed4e916c907a244aa3e5ca2e66cbc5d4e
docs/f3/F3.2E-PSBT-OUTPUT-TEST-ALIGNMENT-PACKET.md 4ffa20afbedeb0b6cfbbe57298f941bc0537683e
docs/f3/F3.2F-PSBT-OUTPUT-TEST-OWNER-DIRECTION-RECORD.md a066fc9710371f414d158a3deb9c345f2b00821b
QK_F32H_SOURCE_BLOBS_EOF

git --no-optional-locks show "$p32hstage:docs/RESOURCE-BUDGETS.md" > "$tmpdir/p32h.resource.frozen" 2>/dev/null; p32hrc=$?
[ "$p32hrc" -eq 0 ] || err "F3.2h frozen RESOURCE-BUDGETS read failed"
git --no-optional-locks show "$p32hstage:docs/REQUIREMENTS.md" > "$tmpdir/p32h.requirements.frozen" 2>/dev/null; p32hrc=$?
[ "$p32hrc" -eq 0 ] || err "F3.2h frozen REQUIREMENTS read failed"
git --no-optional-locks show "$p32hstage:docs/TEST-ARCHITECTURE.md" > "$tmpdir/p32h.test.frozen" 2>/dev/null; p32hrc=$?
[ "$p32hrc" -eq 0 ] || err "F3.2h frozen TEST-ARCHITECTURE read failed"
p32hrow026='| QK-LIM-PSBT-026 | Signed PSBT output bytes | qk-core output serialization | QK-THR-016 unbounded output | QK-REQ-PSBT-005, QK-REQ-TRN-007; QK-TST-DIFF-004 | Output size distribution; transport ceilings | OPEN — VALUE NOT AUTHORIZED IN F1 | OPEN | OD-05 |'
p32hrow027='| QK-LIM-PSBT-027 | Raw final-transaction output bytes | qk-core output serialization | QK-THR-016 unbounded output | QK-REQ-PSBT-005, QK-REQ-TRN-007; QK-TST-DIFF-004 | Output size distribution; transport ceilings | OPEN — VALUE NOT AUTHORIZED IN F1 | OPEN | OD-05 |'
for p32hrow in "$p32hrow026" "$p32hrow027"; do
  p32hsourcen=$(grep -cFx -e "$p32hrow" "$tmpdir/p32h.resource.frozen"); p32hrc=$?
  [ "$p32hrc" -le 1 ] || err "F3.2h RESOURCE-BUDGETS source-row scan failed"
  [ "$p32hsourcen" = 1 ] || err "F3.2h required RESOURCE-BUDGETS source row is missing, altered, or duplicated"
  p32hpacketn=$(grep -cFx -e "$p32hrow" "$PKT32H"); p32hrc=$?
  [ "$p32hrc" -le 1 ] || err "F3.2h packet source-row scan failed"
  [ "$p32hpacketn" = 1 ] || err "F3.2h required RESOURCE-BUDGETS row reproduction is missing, altered, or duplicated"
done
p32hpsbt005='QK-LIM-PSBT-001, QK-LIM-PSBT-002, QK-LIM-PSBT-003, QK-LIM-PSBT-004, QK-LIM-PSBT-005, QK-LIM-PSBT-006, QK-LIM-PSBT-007, QK-LIM-PSBT-008, QK-LIM-PSBT-009, QK-LIM-PSBT-010, QK-LIM-PSBT-011, QK-LIM-PSBT-012, QK-LIM-PSBT-013, QK-LIM-PSBT-014, QK-LIM-PSBT-015, QK-LIM-PSBT-016, QK-LIM-PSBT-017, QK-LIM-PSBT-018, QK-LIM-PSBT-019, QK-LIM-PSBT-020, QK-LIM-PSBT-021, QK-LIM-PSBT-022, QK-LIM-PSBT-023, QK-LIM-PSBT-024, QK-LIM-PSBT-025, QK-LIM-PSBT-026, QK-LIM-PSBT-027'
p32htrn007='QK-LIM-SD-004, QK-LIM-PSBT-026, QK-LIM-PSBT-027'
p32hdiff004='QK-REQ-TRN-007; QK-THR-006; QK-LIM-PSBT-026, QK-LIM-PSBT-027'
awk -F '|' '$2 == " QK-REQ-PSBT-005 " {x=$6; sub(/^ /,"",x); sub(/ $/,"",x); print x}' \
  "$tmpdir/p32h.requirements.frozen" > "$tmpdir/p32h.psbt005.source"; p32hrc=$?
[ "$p32hrc" -eq 0 ] || err "F3.2h QK-REQ-PSBT-005 Lim extraction failed"
awk -F '|' '$2 == " QK-REQ-TRN-007 " {x=$6; sub(/^ /,"",x); sub(/ $/,"",x); print x}' \
  "$tmpdir/p32h.requirements.frozen" > "$tmpdir/p32h.trn007.source"; p32hrc=$?
[ "$p32hrc" -eq 0 ] || err "F3.2h QK-REQ-TRN-007 Lim extraction failed"
awk -F '|' '$2 == " QK-TST-DIFF-004 " {x=$5; sub(/^ /,"",x); sub(/ $/,"",x); print x}' \
  "$tmpdir/p32h.test.frozen" > "$tmpdir/p32h.diff004.source"; p32hrc=$?
[ "$p32hrc" -eq 0 ] || err "F3.2h QK-TST-DIFF-004 Links extraction failed"
for p32hcellpair in \
  "$tmpdir/p32h.psbt005.source|$p32hpsbt005" \
  "$tmpdir/p32h.trn007.source|$p32htrn007" \
  "$tmpdir/p32h.diff004.source|$p32hdiff004"; do
  p32hcellfile=${p32hcellpair%%|*}
  p32hcellexpected=${p32hcellpair#*|}
  printf '%s\n' "$p32hcellexpected" > "$tmpdir/p32h.cell.exp" \
    || err "F3.2h canonical-cell fixture generation failed"
  cmp -s "$tmpdir/p32h.cell.exp" "$p32hcellfile"; p32hrc=$?
  [ "$p32hrc" -eq 0 ] || err "F3.2h canonical source cell differs: $p32hcellexpected"
  p32hcellcount=$(grep -cFx -e "$p32hcellexpected" "$PKT32H"); p32hrc=$?
  [ "$p32hrc" -le 1 ] || err "F3.2h packet canonical-cell scan failed"
  [ "$p32hcellcount" = 1 ] || err "F3.2h packet canonical-cell reproduction is missing, altered, or duplicated"
done

p32hquestioncount=$(grep -c '^### F32H-LIM-Q-[0-9][0-9][0-9] — ' "$PKT32H"); p32hrc=$?
[ "$p32hrc" -le 1 ] || err "$PKT32H owner-question heading scan failed"
[ "$p32hquestioncount" = 1 ] || err "$PKT32H must contain exactly one owner-question heading"
grep '^| F32H-LIM-OPT-' "$PKT32H" > "$tmpdir/p32h.options.act"; p32hrc=$?
[ "$p32hrc" -eq 0 ] || err "$PKT32H option-row extraction failed"
cat > "$tmpdir/p32h.options.exp" <<'QK_F32H_OPTIONS_EOF' || err "$PKT32H option-row fixture generation failed"
| F32H-LIM-OPT-001 | UNSELECTED | RECOMMENDED — NOT SELECTED | Under separately authorized later canonical work, preserve ID 027 as a permanent non-reusable tombstone and remove its live links. Never delete, renumber, reuse, or repurpose the ID. |
| F32H-LIM-OPT-002 | UNSELECTED | NOT RECOMMENDED | Under separately authorized later canonical work, preserve ID 027 as an inactive same-semantic future contingency for raw final-transaction output bytes, with no current links and no value. Activation would require separate future authority. |
| F32H-LIM-OPT-003 | UNSELECTED | NOT RECOMMENDED | Defer; retain the complete current QK-LIM-PSBT-027 row and all four current canonical locations unchanged, with the known inconsistency still live. |
QK_F32H_OPTIONS_EOF
cmp -s "$tmpdir/p32h.options.exp" "$tmpdir/p32h.options.act"; p32hrc=$?
[ "$p32hrc" -eq 0 ] || err "$PKT32H does not contain exactly the three ordered authorized option rows"
awk -F '|' '
  NR == 1 { if ($2 != " F32H-LIM-OPT-001 " || $3 != " UNSELECTED " || $4 != " RECOMMENDED — NOT SELECTED ") exit 51; next }
  NR == 2 { if ($2 != " F32H-LIM-OPT-002 " || $3 != " UNSELECTED " || $4 != " NOT RECOMMENDED ") exit 52; next }
  NR == 3 { if ($2 != " F32H-LIM-OPT-003 " || $3 != " UNSELECTED " || $4 != " NOT RECOMMENDED ") exit 53; next }
  END { if (NR != 3) exit 54 }
' "$tmpdir/p32h.options.act"; p32hrc=$?
[ "$p32hrc" -eq 0 ] || err "$PKT32H option order, selection, or recommendation grammar differs (awk exit $p32hrc)"
for p32hboundary in \
  'There is exactly one owner question and exactly three ordered dispositions. All three dispositions are UNSELECTED. Option 1 alone is recommended, and that recommendation is analysis only, not an owner selection or canonical direction.' \
  '- “Permanent non-reusable tombstone” and “inactive same-semantic future contingency” describe unselected future disposition concepts only. `TOMBSTONED` and `INACTIVE` are not asserted or invented as current RESOURCE-BUDGETS Status vocabulary.' \
  '- No option deletes, renumbers, reuses, or repurposes ID 027. Under every option, the identifier remains permanently attributable to the “Raw final-transaction output bytes” history and may never identify a different dimension.' \
  '- No option selects or proposes any numeric QK-LIM value, including `0`.' \
  '- QK-LIM-PSBT-026 and QK-LIM-PSBT-027 remain byte-for-byte unchanged, including their titles, boundaries, threats, links, evidence-needed text, values, statuses, and open-decision cells.' \
  '- QK-TST-DIFF-004 remains byte-for-byte unchanged. No Plan / oracle, Links, Milestone, Gate, Evidence artifact, or Status cell changes.'; do
  p32hboundarycount=$(grep -cFx -e "$p32hboundary" "$PKT32H"); p32hrc=$?
  [ "$p32hrc" -le 1 ] || err "$PKT32H boundary statement scan failed"
  [ "$p32hboundarycount" = 1 ] || err "$PKT32H required boundary statement is missing, altered, or duplicated"
done

iconv -f UTF-8 -t UTF-8 "$PKT32H" > "$tmpdir/p32h.utf8" 2> "$tmpdir/p32h.iconv.err"; p32hrc=$?
[ "$p32hrc" -eq 0 ] || err "$PKT32H is not strict UTF-8"
[ -s "$tmpdir/p32h.utf8" ] || err "$PKT32H UTF-8 validation produced empty output"
cmp -s "$PKT32H" "$tmpdir/p32h.utf8"; p32hrc=$?
[ "$p32hrc" -eq 0 ] || err "$PKT32H UTF-8 validation changed bytes"
tail -c 1 "$PKT32H" > "$tmpdir/p32h.last.raw"; p32hrc=$?
[ "$p32hrc" -eq 0 ] || err "$PKT32H final-byte read failed"
[ -s "$tmpdir/p32h.last.raw" ] || err "$PKT32H final-byte read produced empty output"
od -An -tuC "$tmpdir/p32h.last.raw" > "$tmpdir/p32h.last.od"; p32hrc=$?
[ "$p32hrc" -eq 0 ] || err "$PKT32H final-byte scan failed"
tr -d '[:space:]' < "$tmpdir/p32h.last.od" > "$tmpdir/p32h.last.norm"; p32hrc=$?
[ "$p32hrc" -eq 0 ] || err "$PKT32H final-byte normalization failed"
p32hlast=$(cat "$tmpdir/p32h.last.norm"); p32hrc=$?
[ "$p32hrc" -eq 0 ] || err "$PKT32H final-byte read-back failed"
[ "$p32hlast" = 10 ] || err "$PKT32H must end in exact LF"
tail -c 2 "$PKT32H" > "$tmpdir/p32h.last2.raw"; p32hrc=$?
[ "$p32hrc" -eq 0 ] || err "$PKT32H final-two-byte read failed"
printf '\n\n' > "$tmpdir/p32h.double-lf" || err "$PKT32H double-LF fixture generation failed"
cmp -s "$tmpdir/p32h.double-lf" "$tmpdir/p32h.last2.raw"; p32hrc=$?
[ "$p32hrc" -eq 1 ] || err "$PKT32H must not end in double LF or the cmp check failed (exit $p32hrc)"
od -An -tx1 "$PKT32H" > "$tmpdir/p32h.bytes.raw"; p32hrc=$?
[ "$p32hrc" -eq 0 ] || err "$PKT32H byte scan failed"
tr -d '[:space:]' < "$tmpdir/p32h.bytes.raw" > "$tmpdir/p32h.bytes.hex"; p32hrc=$?
[ "$p32hrc" -eq 0 ] || err "$PKT32H byte normalization failed"
p32hbad=$(grep -cE '(^efbbbf)|00|0d|e2808[ef]|e280a[a-e]|e281a[6-9]' "$tmpdir/p32h.bytes.hex"); p32hrc=$?
[ "$p32hrc" -le 1 ] || err "$PKT32H control/bidi byte scan failed"
[ "$p32hbad" = 0 ] || err "$PKT32H contains BOM, NUL, CR, LRM/RLM, or bidi controls"
forbid "$PKT32H contains a tab, trailing whitespace, HTML comment, hidden link definition, fence, blockquote, URL, or email material" \
  -E '	|[[:blank:]]$|<!--|-->|^\[[^]]+\]:|^```|^[[:space:]]*>|https?://|[[:alnum:]_.+-]+@[[:alnum:].-]+' "$PKT32H"
forbid "$PKT32H contains PSBT or key payload material" -E '[7]0736274|[c]HNidP|[x]pub|[x]prv' "$PKT32H"
forbid "$PKT32H contains suspicious 41+ hex material" -E '[0-9a-fA-F]{41,}' "$PKT32H"
printf '%s\n' \
  065e20eed4e916c907a244aa3e5ca2e66cbc5d4e \
  1ae6494fc24a8e3572464cf45e6d43ea4875e95d \
  4ffa20afbedeb0b6cfbbe57298f941bc0537683e \
  981b1b497102187da66fb4e82ef0725b32c088f7 \
  a066fc9710371f414d158a3deb9c345f2b00821b \
  a64399dd35aef8d6daa05171f1da30c8026f6d1f \
  a64399dd35aef8d6daa05171f1da30c8026f6d1f \
  da55fb4bcd4983140c8fb379cc3322eec99284f0 > "$tmpdir/p32h.hex.exp" \
  || err "$PKT32H exact-40-hex multiset fixture generation failed"
awk '{s=$0; while (match(s,/[0-9a-fA-F]+/)) {t=substr(s,RSTART,RLENGTH); if (length(t)==40) print tolower(t); s=substr(s,RSTART+RLENGTH)}}' \
  "$PKT32H" > "$tmpdir/p32h.hex.raw"; p32hrc=$?
[ "$p32hrc" -eq 0 ] || err "$PKT32H exact-40-hex enumeration failed"
LC_ALL=C sort "$tmpdir/p32h.hex.raw" > "$tmpdir/p32h.hex.act"; p32hrc=$?
[ "$p32hrc" -eq 0 ] || err "$PKT32H exact-40-hex sort failed"
cmp -s "$tmpdir/p32h.hex.exp" "$tmpdir/p32h.hex.act"; p32hrc=$?
[ "$p32hrc" -eq 0 ] || err "$PKT32H exact-40-hex multiset differs"

# ---------------- F3.2i QK-LIM-PSBT-027 owner-direction record
# Non-enacting future direction only. Exact bytes, owner transcript,
# source history, canonical blobs, and closed selection grammar are
# fail-closed supporting checks; they enact no canonical amendment.
REC32I=docs/f3/F3.2I-QK-LIM-PSBT-027-OWNER-DIRECTION-RECORD.md
[ -f "$REC32I" ] || err "$REC32I missing"
p32ibase=e36b41e5cd55264b4b745550c96c74968b06eae7
p32ia=c4e1ed94a02fba5d01f5cebfda4d5b1439222625
p32istage=878b23be4690bb778a615bfe1a6ef108e7a94008
p32irecordblob=2f4bc0f5cb8e861b45f515fb7c4c5dbc764784c5
p32ipacketblob=e18ba6b4a5c2ee5fc5b7d1a464b656c631b526d5

git --no-optional-locks rev-parse "$p32ibase^{commit}" > "$tmpdir/p32i.base.act" 2>/dev/null
p32irc=$?
[ "$p32irc" -eq 0 ] || err "F3.2i source base does not resolve as a commit"
printf '%s\n' "$p32ibase" > "$tmpdir/p32i.base.exp" \
  || err "F3.2i source-base fixture generation failed"
cmp -s "$tmpdir/p32i.base.exp" "$tmpdir/p32i.base.act"; p32irc=$?
[ "$p32irc" -eq 0 ] || err "F3.2i source base resolution differs"
git --no-optional-locks rev-parse "$p32ia^{commit}" > "$tmpdir/p32i.a.act" 2>/dev/null
p32irc=$?
[ "$p32irc" -eq 0 ] || err "F3.2i authorization commit A does not resolve"
printf '%s\n' "$p32ia" > "$tmpdir/p32i.a.exp" \
  || err "F3.2i authorization-commit fixture generation failed"
cmp -s "$tmpdir/p32i.a.exp" "$tmpdir/p32i.a.act"; p32irc=$?
[ "$p32irc" -eq 0 ] || err "F3.2i authorization commit resolution differs"

git --no-optional-locks hash-object -- "$REC32I" > "$tmpdir/p32i.record.act"
p32irc=$?
[ "$p32irc" -eq 0 ] || err "$REC32I whole-record blob scan failed"
[ -s "$tmpdir/p32i.record.act" ] || err "$REC32I whole-record blob scan produced empty output"
printf '%s\n' "$p32irecordblob" > "$tmpdir/p32i.record.exp" \
  || err "$REC32I whole-record blob fixture generation failed"
cmp -s "$tmpdir/p32i.record.exp" "$tmpdir/p32i.record.act"; p32irc=$?
[ "$p32irc" -eq 0 ] || err "$REC32I whole-record bytes differ"

for p32iowner in \
  'Approve, as a non-enacting owner direction, F32H-LIM-OPT-001 exactly as printed in the published F3.2h packet at commit e36b41e5cd55264b4b745550c96c74968b06eae7: “Under separately authorized later canonical work, preserve ID 027 as a permanent non-reusable tombstone and remove its live links. Never delete, renumber, reuse, or repurpose the ID.” Approve no other disposition.' \
  'This approval selects only the future disposition direction. It does not declare the current QK-LIM-PSBT-027 row tombstoned or inactive; select any replacement title, Status vocabulary, row syntax, link syntax, or canonical bytes; authorize any value, including zero; or amend any current live link. QK-LIM-PSBT-026 remains unchanged.' \
  'Authorize preparation and independent audit of a non-enacting docs-only F3.2i QK-LIM-PSBT-027 owner-direction record from e36b41e5cd55264b4b745550c96c74968b06eae7, recording only that approved direction, with only the mechanically necessary Decision Log and verifier bindings.' \
  'No canonical RESOURCE-BUDGETS, REQUIREMENTS, or TEST-ARCHITECTURE edit; no QK-LIM value, title, status, link, or row change; no QK-TST Plan / oracle, Links, or status change; no answer to F32C-D11-Q-002 through Q-012; no D-11, D-09, OD-05/06, profile, clause, implementation, testing, corpus, vector, fixture, evidence, media-I/O, hardware, license, gate, STOP-SHIP, setting, credential, other-branch, tag, release, publication, or remote change.'; do
  for p32iownerfile in docs/DECISION-LOG.md "$REC32I"; do
    p32iownerhits=$(grep -cFx -e "$p32iowner" "$p32iownerfile"); p32irc=$?
    [ "$p32irc" -le 1 ] || err "F3.2i owner transcript scan failed in $p32iownerfile"
    [ "$p32iownerhits" = 1 ] || err "F3.2i owner transcript differs or duplicates in $p32iownerfile"
  done
done
sed -n '/^### QK-AUTH-F3.2I-QK-LIM-PSBT-027-DIR-REC-001 /,/^### QK-AUTH-F3.2J-QK-LIM-PSBT-027-CONSTRUCT-001 /p' \
  docs/DECISION-LOG.md > "$tmpdir/p32i.dlog.section"; p32irc=$?
[ "$p32irc" -eq 0 ] || err "F3.2i Decision Log section extraction failed"
sed -n '/^- \*\*Owner words exactly (literal four-paragraph block follows):\*\*$/,/^- \*\*Published parent and source locators:\*\*/p' \
  "$tmpdir/p32i.dlog.section" > "$tmpdir/p32i.owner.dlog.framed"; p32irc=$?
[ "$p32irc" -eq 0 ] || err "F3.2i Decision Log owner block extraction failed"
sed '1d;$d' "$tmpdir/p32i.owner.dlog.framed" > "$tmpdir/p32i.owner.dlog"; p32irc=$?
[ "$p32irc" -eq 0 ] || err "F3.2i Decision Log owner block deframing failed"
sed -n '/^## Owner words exactly$/,/^## Exact direction map$/p' \
  "$REC32I" > "$tmpdir/p32i.owner.record.framed"; p32irc=$?
[ "$p32irc" -eq 0 ] || err "F3.2i record owner block extraction failed"
sed '1d;$d' "$tmpdir/p32i.owner.record.framed" > "$tmpdir/p32i.owner.record"; p32irc=$?
[ "$p32irc" -eq 0 ] || err "F3.2i record owner block deframing failed"
cmp -s "$tmpdir/p32i.owner.dlog" "$tmpdir/p32i.owner.record"; p32irc=$?
[ "$p32irc" -eq 0 ] || err "F3.2i Decision Log and record owner transcript blocks differ"

grep '^| F32H-LIM-OPT-' "$REC32I" > "$tmpdir/p32i.options.act"; p32irc=$?
[ "$p32irc" -eq 0 ] || err "$REC32I option-row extraction failed"
cat > "$tmpdir/p32i.options.exp" <<'QK_F32I_OPTIONS_EOF' || err "$REC32I option-row fixture generation failed"
| F32H-LIM-OPT-001 | UNSELECTED — HISTORICAL SOURCE STATE | OWNER DIRECTION APPROVED — NON-ENACTING | NONE — FUTURE DIRECTION ONLY |
| F32H-LIM-OPT-002 | UNSELECTED — HISTORICAL SOURCE STATE | NOT APPROVED | NONE |
| F32H-LIM-OPT-003 | UNSELECTED — HISTORICAL SOURCE STATE | NOT APPROVED | NONE |
| F32H-LIM-OPT-001 | Under separately authorized later canonical work, preserve ID 027 as a permanent non-reusable tombstone and remove its live links. Never delete, renumber, reuse, or repurpose the ID. |
QK_F32I_OPTIONS_EOF
cmp -s "$tmpdir/p32i.options.exp" "$tmpdir/p32i.options.act"; p32irc=$?
[ "$p32irc" -eq 0 ] || err "$REC32I exact option rows differ"
awk -F '|' '
  NR == 1 { if ($2 != " F32H-LIM-OPT-001 " || $3 != " UNSELECTED — HISTORICAL SOURCE STATE " || $4 != " OWNER DIRECTION APPROVED — NON-ENACTING " || $5 != " NONE — FUTURE DIRECTION ONLY ") exit 61; next }
  NR == 2 { if ($2 != " F32H-LIM-OPT-002 " || $3 != " UNSELECTED — HISTORICAL SOURCE STATE " || $4 != " NOT APPROVED " || $5 != " NONE ") exit 62; next }
  NR == 3 { if ($2 != " F32H-LIM-OPT-003 " || $3 != " UNSELECTED — HISTORICAL SOURCE STATE " || $4 != " NOT APPROVED " || $5 != " NONE ") exit 63; next }
  NR == 4 { if ($2 != " F32H-LIM-OPT-001 ") exit 64; next }
  END { if (NR != 4) exit 65 }
' "$tmpdir/p32i.options.act"; p32irc=$?
[ "$p32irc" -eq 0 ] || err "$REC32I selection grammar differs (awk exit $p32irc)"
for p32iboundary in \
  'There is exactly one approved owner direction: `F32H-LIM-OPT-001`. `F32H-LIM-OPT-002` and `F32H-LIM-OPT-003` are not approved.' \
  '- Its three option rows remain `UNSELECTED` as the historical source state at packet publication. This record does not rewrite, supersede, or misdescribe those historical bytes.' \
  '- This record does not declare `QK-LIM-PSBT-027` currently `TOMBSTONED` or `INACTIVE`; those words describe no current registry status here.' \
  '- No replacement title, Status vocabulary, row syntax, link syntax, canonical bytes, or value is selected. No value, including zero, is authorized.' \
  '- `QK-TST-DIFF-004` remains byte-for-byte unchanged. No Plan / oracle, Links, Milestone, Gate, Evidence artifact, or Status cell changes.'; do
  p32iboundarycount=$(grep -cFx -e "$p32iboundary" "$REC32I"); p32irc=$?
  [ "$p32irc" -le 1 ] || err "$REC32I boundary statement scan failed"
  [ "$p32iboundarycount" = 1 ] || err "$REC32I required boundary statement is missing, altered, or duplicated"
done

while IFS=' ' read -r p32iprotected p32iprotectedblob; do
  git --no-optional-locks rev-parse "$p32istage:$p32iprotected" > "$tmpdir/p32i.protected.act" 2>/dev/null; p32irc=$?
  [ "$p32irc" -eq 0 ] || err "F3.2i protected blob scan failed for $p32iprotected"
  [ -s "$tmpdir/p32i.protected.act" ] || err "F3.2i protected blob scan produced empty output for $p32iprotected"
  printf '%s\n' "$p32iprotectedblob" > "$tmpdir/p32i.protected.exp" \
    || err "F3.2i protected blob fixture failed for $p32iprotected"
  cmp -s "$tmpdir/p32i.protected.exp" "$tmpdir/p32i.protected.act"; p32irc=$?
  [ "$p32irc" -eq 0 ] || err "F3.2i protected blob differs for $p32iprotected"
done <<'QK_F32I_PROTECTED_BLOBS_EOF'
docs/RESOURCE-BUDGETS.md 1ae6494fc24a8e3572464cf45e6d43ea4875e95d
docs/REQUIREMENTS.md 981b1b497102187da66fb4e82ef0725b32c088f7
docs/TEST-ARCHITECTURE.md 065e20eed4e916c907a244aa3e5ca2e66cbc5d4e
docs/f3/F3.2E-PSBT-OUTPUT-TEST-ALIGNMENT-PACKET.md 4ffa20afbedeb0b6cfbbe57298f941bc0537683e
docs/f3/F3.2F-PSBT-OUTPUT-TEST-OWNER-DIRECTION-RECORD.md a066fc9710371f414d158a3deb9c345f2b00821b
docs/f3/F3.2H-QK-LIM-PSBT-027-CROSS-DOCUMENT-ALIGNMENT-PACKET.md e18ba6b4a5c2ee5fc5b7d1a464b656c631b526d5
QK_F32I_PROTECTED_BLOBS_EOF

git --no-optional-locks show "$p32istage:docs/RESOURCE-BUDGETS.md" > "$tmpdir/p32i.resource.frozen" 2>/dev/null; p32irc=$?
[ "$p32irc" -eq 0 ] || err "F3.2i frozen RESOURCE-BUDGETS read failed"
git --no-optional-locks show "$p32istage:docs/REQUIREMENTS.md" > "$tmpdir/p32i.requirements.frozen" 2>/dev/null; p32irc=$?
[ "$p32irc" -eq 0 ] || err "F3.2i frozen REQUIREMENTS read failed"
git --no-optional-locks show "$p32istage:docs/TEST-ARCHITECTURE.md" > "$tmpdir/p32i.test.frozen" 2>/dev/null; p32irc=$?
[ "$p32irc" -eq 0 ] || err "F3.2i frozen TEST-ARCHITECTURE read failed"
for p32irow in "$p32hrow026" "$p32hrow027"; do
  p32irowcount=$(grep -cFx -e "$p32irow" "$tmpdir/p32i.resource.frozen"); p32irc=$?
  [ "$p32irc" -le 1 ] || err "F3.2i canonical source-row scan failed"
  [ "$p32irowcount" = 1 ] || err "F3.2i canonical QK-LIM row is missing, altered, or duplicated"
done
awk -F '|' '$2 == " QK-REQ-PSBT-005 " {x=$6; sub(/^ /,"",x); sub(/ $/,"",x); print x}' \
  "$tmpdir/p32i.requirements.frozen" > "$tmpdir/p32i.psbt005.source"; p32irc=$?
[ "$p32irc" -eq 0 ] || err "F3.2i QK-REQ-PSBT-005 Lim extraction failed"
awk -F '|' '$2 == " QK-REQ-TRN-007 " {x=$6; sub(/^ /,"",x); sub(/ $/,"",x); print x}' \
  "$tmpdir/p32i.requirements.frozen" > "$tmpdir/p32i.trn007.source"; p32irc=$?
[ "$p32irc" -eq 0 ] || err "F3.2i QK-REQ-TRN-007 Lim extraction failed"
awk -F '|' '$2 == " QK-TST-DIFF-004 " {x=$5; sub(/^ /,"",x); sub(/ $/,"",x); print x}' \
  "$tmpdir/p32i.test.frozen" > "$tmpdir/p32i.diff004.source"; p32irc=$?
[ "$p32irc" -eq 0 ] || err "F3.2i QK-TST-DIFF-004 Links extraction failed"
for p32icellpair in \
  "$tmpdir/p32i.psbt005.source|$p32hpsbt005" \
  "$tmpdir/p32i.trn007.source|$p32htrn007" \
  "$tmpdir/p32i.diff004.source|$p32hdiff004"; do
  p32icellfile=${p32icellpair%%|*}
  p32icellexpected=${p32icellpair#*|}
  printf '%s\n' "$p32icellexpected" > "$tmpdir/p32i.cell.exp" \
    || err "F3.2i canonical-cell fixture generation failed"
  cmp -s "$tmpdir/p32i.cell.exp" "$p32icellfile"; p32irc=$?
  [ "$p32irc" -eq 0 ] || err "F3.2i canonical live-link cell differs: $p32icellexpected"
done

iconv -f UTF-8 -t UTF-8 "$REC32I" > "$tmpdir/p32i.utf8" 2> "$tmpdir/p32i.iconv.err"; p32irc=$?
[ "$p32irc" -eq 0 ] || err "$REC32I is not strict UTF-8"
[ -s "$tmpdir/p32i.utf8" ] || err "$REC32I UTF-8 validation produced empty output"
cmp -s "$REC32I" "$tmpdir/p32i.utf8"; p32irc=$?
[ "$p32irc" -eq 0 ] || err "$REC32I UTF-8 validation changed bytes"
tail -c 1 "$REC32I" > "$tmpdir/p32i.last.raw"; p32irc=$?
[ "$p32irc" -eq 0 ] || err "$REC32I final-byte read failed"
[ -s "$tmpdir/p32i.last.raw" ] || err "$REC32I final-byte read produced empty output"
od -An -tuC "$tmpdir/p32i.last.raw" > "$tmpdir/p32i.last.od"; p32irc=$?
[ "$p32irc" -eq 0 ] || err "$REC32I final-byte scan failed"
tr -d '[:space:]' < "$tmpdir/p32i.last.od" > "$tmpdir/p32i.last.norm"; p32irc=$?
[ "$p32irc" -eq 0 ] || err "$REC32I final-byte normalization failed"
p32ilast=$(cat "$tmpdir/p32i.last.norm"); p32irc=$?
[ "$p32irc" -eq 0 ] || err "$REC32I final-byte read-back failed"
[ "$p32ilast" = 10 ] || err "$REC32I must end in exact LF"
tail -c 2 "$REC32I" > "$tmpdir/p32i.last2.raw"; p32irc=$?
[ "$p32irc" -eq 0 ] || err "$REC32I final-two-byte read failed"
printf '\n\n' > "$tmpdir/p32i.double-lf" || err "$REC32I double-LF fixture generation failed"
cmp -s "$tmpdir/p32i.double-lf" "$tmpdir/p32i.last2.raw"; p32irc=$?
[ "$p32irc" -eq 1 ] || err "$REC32I must not end in double LF or the cmp check failed (exit $p32irc)"
od -An -tx1 "$REC32I" > "$tmpdir/p32i.bytes.raw"; p32irc=$?
[ "$p32irc" -eq 0 ] || err "$REC32I byte scan failed"
awk 'BEGIN { bad=0; p2=""; p1="" }
  {
    for (i=1; i<=NF; i++) {
      b=tolower($i)
      if (b == "00" || b == "0d") bad=bad+1
      seq=p2 p1 b
      if (seq == "efbbbf" || seq == "e2808e" || seq == "e2808f" ||
          seq == "e280aa" || seq == "e280ab" || seq == "e280ac" ||
          seq == "e280ad" || seq == "e280ae" || seq == "e281a6" ||
          seq == "e281a7" || seq == "e281a8" || seq == "e281a9") bad=bad+1
      p2=p1
      p1=b
    }
  }
  END { print bad+0 }' "$tmpdir/p32i.bytes.raw" > "$tmpdir/p32i.bytes.bad"; p32irc=$?
[ "$p32irc" -eq 0 ] || err "$REC32I control/bidi byte scan failed"
p32ibad=$(cat "$tmpdir/p32i.bytes.bad"); p32irc=$?
[ "$p32irc" -eq 0 ] || err "$REC32I control/bidi result read failed"
[ "$p32ibad" = 0 ] || err "$REC32I contains BOM, NUL, CR, LRM/RLM, or bidi controls"
forbid "$REC32I contains a tab, trailing whitespace, HTML comment, hidden link definition, fence, blockquote, URL, or email material" \
  -E '	|[[:blank:]]$|<!--|-->|^\[[^]]+\]:|^```|^[[:space:]]*>|https?://|[[:alnum:]_.+-]+@[[:alnum:].-]+' "$REC32I"
forbid "$REC32I contains PSBT or key payload material" -E '[7]0736274|[c]HNidP|[x]pub|[x]prv' "$REC32I"
forbid "$REC32I contains suspicious 41+ hex material" -E '[0-9a-fA-F]{41,}' "$REC32I"
printf '%s\n' \
  065e20eed4e916c907a244aa3e5ca2e66cbc5d4e \
  1ae6494fc24a8e3572464cf45e6d43ea4875e95d \
  981b1b497102187da66fb4e82ef0725b32c088f7 \
  c4e1ed94a02fba5d01f5cebfda4d5b1439222625 \
  e18ba6b4a5c2ee5fc5b7d1a464b656c631b526d5 \
  e18ba6b4a5c2ee5fc5b7d1a464b656c631b526d5 \
  e36b41e5cd55264b4b745550c96c74968b06eae7 \
  e36b41e5cd55264b4b745550c96c74968b06eae7 \
  e36b41e5cd55264b4b745550c96c74968b06eae7 > "$tmpdir/p32i.hex.exp" \
  || err "$REC32I exact-40-hex multiset fixture generation failed"
awk '{s=$0; while (match(s,/[0-9a-fA-F]+/)) {t=substr(s,RSTART,RLENGTH); if (length(t)==40) print tolower(t); s=substr(s,RSTART+RLENGTH)}}' \
  "$REC32I" > "$tmpdir/p32i.hex.raw"; p32irc=$?
[ "$p32irc" -eq 0 ] || err "$REC32I exact-40-hex enumeration failed"
LC_ALL=C sort "$tmpdir/p32i.hex.raw" > "$tmpdir/p32i.hex.act"; p32irc=$?
[ "$p32irc" -eq 0 ] || err "$REC32I exact-40-hex sort failed"
cmp -s "$tmpdir/p32i.hex.exp" "$tmpdir/p32i.hex.act"; p32irc=$?
[ "$p32irc" -eq 0 ] || err "$REC32I exact-40-hex multiset differs"

# ---------------- F3.2j QK-LIM-PSBT-027 exact construction packet
# Non-binding and non-enacting. The exact one-candidate closed world,
# current/proposed transcripts, protected sources, and material boundaries
# are supporting checks only and perform no canonical amendment.
PKT32J=docs/f3/F3.2J-QK-LIM-PSBT-027-EXACT-TOMBSTONE-CONSTRUCTION-PACKET.md
[ -f "$PKT32J" ] || err "$PKT32J missing"
p32jbase=878b23be4690bb778a615bfe1a6ef108e7a94008
p32ja=336956ec866ca3aa93791ffcb76f30e79e17dd31
p32jstage=0d2115de9c322bf221f5a5008d91e7b7b48363e6
p32jdlogblob=0e366c1acc5579e541dfe3f94a099db9b887064b
p32jpacketblob=b1c2153f5f89a0e1d44d62a09921251e225c0d87
git --no-optional-locks show "$p32ja:docs/DECISION-LOG.md" > "$tmpdir/p32j.dlog.a" 2>/dev/null; p32jrc=$?
[ "$p32jrc" -eq 0 ] || err "F3.2j authorization Decision Log read failed"

git --no-optional-locks rev-parse "$p32jbase^{commit}" > "$tmpdir/p32j.base.act" 2>/dev/null
p32jrc=$?
[ "$p32jrc" -eq 0 ] || err "F3.2j source base does not resolve as a commit"
printf '%s\n' "$p32jbase" > "$tmpdir/p32j.base.exp" \
  || err "F3.2j source-base fixture generation failed"
cmp -s "$tmpdir/p32j.base.exp" "$tmpdir/p32j.base.act"; p32jrc=$?
[ "$p32jrc" -eq 0 ] || err "F3.2j source base resolution differs"
git --no-optional-locks rev-parse "$p32ja^{commit}" > "$tmpdir/p32j.a.act" 2>/dev/null
p32jrc=$?
[ "$p32jrc" -eq 0 ] || err "F3.2j authorization commit A does not resolve"
printf '%s\n' "$p32ja" > "$tmpdir/p32j.a.exp" \
  || err "F3.2j authorization-commit fixture generation failed"
cmp -s "$tmpdir/p32j.a.exp" "$tmpdir/p32j.a.act"; p32jrc=$?
[ "$p32jrc" -eq 0 ] || err "F3.2j authorization commit resolution differs"
p32japarent=$(git --no-optional-locks rev-parse "$p32ja^" 2>/dev/null)
p32jrc=$?
[ "$p32jrc" -eq 0 ] || err "F3.2j authorization commit parent cannot be resolved"
[ "$p32japarent" = "$p32jbase" ] || err "F3.2j authorization commit parent differs"
git --no-optional-locks diff-tree --no-commit-id --name-only -r "$p32ja" > "$tmpdir/p32j.a.paths.act"
p32jrc=$?
[ "$p32jrc" -eq 0 ] || err "F3.2j authorization commit path enumeration failed"
printf '%s\n' docs/DECISION-LOG.md > "$tmpdir/p32j.a.paths.exp" \
  || err "F3.2j authorization path fixture generation failed"
cmp -s "$tmpdir/p32j.a.paths.exp" "$tmpdir/p32j.a.paths.act"; p32jrc=$?
[ "$p32jrc" -eq 0 ] || err "F3.2j authorization commit changes a path other than docs/DECISION-LOG.md"

git --no-optional-locks rev-parse "$p32ja:docs/DECISION-LOG.md" > "$tmpdir/p32j.dlog.blob.act" 2>/dev/null
p32jrc=$?
[ "$p32jrc" -eq 0 ] || err "F3.2j historical Decision Log blob lookup failed"
printf '%s\n' "$p32jdlogblob" > "$tmpdir/p32j.dlog.blob.exp" \
  || err "F3.2j historical Decision Log blob fixture generation failed"
cmp -s "$tmpdir/p32j.dlog.blob.exp" "$tmpdir/p32j.dlog.blob.act"; p32jrc=$?
[ "$p32jrc" -eq 0 ] || err "F3.2j historical Decision Log A blob differs"

for p32jblobpair in \
  "$PKT32J|$p32jpacketblob"; do
  p32jblobpath=${p32jblobpair%%|*}
  p32jblobexpected=${p32jblobpair#*|}
  git --no-optional-locks hash-object -- "$p32jblobpath" > "$tmpdir/p32j.blob.act"
  p32jrc=$?
  [ "$p32jrc" -eq 0 ] || err "F3.2j blob scan failed for $p32jblobpath"
  [ -s "$tmpdir/p32j.blob.act" ] || err "F3.2j blob scan produced empty output for $p32jblobpath"
  printf '%s\n' "$p32jblobexpected" > "$tmpdir/p32j.blob.exp" \
    || err "F3.2j blob fixture generation failed for $p32jblobpath"
  cmp -s "$tmpdir/p32j.blob.exp" "$tmpdir/p32j.blob.act"; p32jrc=$?
  [ "$p32jrc" -eq 0 ] || err "F3.2j active blob differs for $p32jblobpath"
done

for p32jowner in \
  'Authorize preparation and independent audit of a non-binding, non-enacting docs-only F3.2j QK-LIM-PSBT-027 exact tombstone-construction packet from published commit 878b23be4690bb778a615bfe1a6ef108e7a94008, with only the mechanically necessary Decision Log and verifier bindings.' \
  'Limit the packet to exactly one recommended, byte-complete candidate, F32J-LIM-CON-001, explicitly PROPOSED — UNSELECTED. Print the exact current and proposed canonical bytes for: the minimum QK-LIM-PSBT-027-specific RESOURCE-BUDGETS preamble, invariant, and append-only-ID-note corrections needed for a permanent no-value tombstone; every cell of row 027; removal of 027 from the QK-REQ-PSBT-005 and QK-REQ-TRN-007 Lim cells; and removal of 027 from the QK-TST-DIFF-004 Links cell. Preserve the historical dimension name and ID, make every former row relationship non-operative, define any proposed Value-cell text as a non-value sentinel rather than zero or an authorized QK-LIM value, and never delete, renumber, reuse, repurpose, or reopen ID 027. Introduce no general tombstone transition for another row. Keep QK-LIM-PSBT-026 and every other canonical and historical byte unchanged.' \
  'No owner selection of F32J-LIM-CON-001 and no canonical edit; no current tombstone or inactive declaration; no actual QK-LIM value, title, status, link, row, vocabulary, or syntax change; no QK-TST Plan / oracle, Links, or status change; no answer to F32C-D11-Q-002 through Q-012; no D-11, D-09, OD-05/06, profile, clause, dependency, implementation, testing, corpus, vector, fixture, evidence, media-I/O, hardware, license, gate, STOP-SHIP, setting, credential, other-branch, tag, release, publication, or remote change.'; do
  for p32jownerfile in "$tmpdir/p32j.dlog.a" "$PKT32J"; do
    p32jownerhits=$(grep -cFx -e "$p32jowner" "$p32jownerfile"); p32jrc=$?
    [ "$p32jrc" -le 1 ] || err "F3.2j owner transcript scan failed in $p32jownerfile"
    [ "$p32jownerhits" = 1 ] || err "F3.2j owner transcript differs or duplicates in $p32jownerfile"
  done
done
sed -n '/^### QK-AUTH-F3.2J-QK-LIM-PSBT-027-CONSTRUCT-001 /,$p' \
  "$tmpdir/p32j.dlog.a" > "$tmpdir/p32j.dlog.section"; p32jrc=$?
[ "$p32jrc" -eq 0 ] || err "F3.2j Decision Log section extraction failed"
sed -n '/^- \*\*Owner words exactly (literal three-paragraph block follows):\*\*$/,/^- \*\*Published parent and source locators:\*\*/p' \
  "$tmpdir/p32j.dlog.section" > "$tmpdir/p32j.owner.dlog.framed"; p32jrc=$?
[ "$p32jrc" -eq 0 ] || err "F3.2j Decision Log owner block extraction failed"
sed '1d;$d' "$tmpdir/p32j.owner.dlog.framed" > "$tmpdir/p32j.owner.dlog"; p32jrc=$?
[ "$p32jrc" -eq 0 ] || err "F3.2j Decision Log owner block deframing failed"
sed -n '/^## Owner words exactly$/,/^## Exact one-candidate closed world$/p' \
  "$PKT32J" > "$tmpdir/p32j.owner.packet.framed"; p32jrc=$?
[ "$p32jrc" -eq 0 ] || err "F3.2j packet owner block extraction failed"
sed '1d;$d' "$tmpdir/p32j.owner.packet.framed" > "$tmpdir/p32j.owner.packet"; p32jrc=$?
[ "$p32jrc" -eq 0 ] || err "F3.2j packet owner block deframing failed"
cmp -s "$tmpdir/p32j.owner.dlog" "$tmpdir/p32j.owner.packet"; p32jrc=$?
[ "$p32jrc" -eq 0 ] || err "F3.2j Decision Log and packet owner transcript blocks differ"

grep '^| F32J-LIM-CON-' "$PKT32J" > "$tmpdir/p32j.candidates.act"; p32jrc=$?
[ "$p32jrc" -eq 0 ] || err "$PKT32J candidate-row extraction failed"
cat > "$tmpdir/p32j.candidates.exp" <<'QK_F32J_CANDIDATES_EOF' || err "$PKT32J candidate fixture generation failed"
| F32J-LIM-CON-001 | PROPOSED — UNSELECTED | RECOMMENDED — NOT SELECTED | NONE — FUTURE CONSTRUCTION ONLY |
QK_F32J_CANDIDATES_EOF
cmp -s "$tmpdir/p32j.candidates.exp" "$tmpdir/p32j.candidates.act"; p32jrc=$?
[ "$p32jrc" -eq 0 ] || err "$PKT32J one-candidate closed world differs"
for p32jboundary in \
  'STATUS: NON-BINDING — NON-ENACTING — ONE RECOMMENDED BYTE-COMPLETE CANDIDATE — PROPOSED — UNSELECTED — NO CANONICAL EDIT — LOCAL AND UNPUBLISHED.' \
  'There is exactly one candidate: `F32J-LIM-CON-001`. It is recommended analysis only and remains `PROPOSED — UNSELECTED`. No owner selection is recorded or inferred.' \
  'The proposed Value cell is a literal non-value sentinel. It is not zero, a numeric value, a candidate value, a default, an approved limit, or authorization to choose any QK-LIM value. Every former row relationship is explicitly non-operative.' \
  '- This packet does not declare `QK-LIM-PSBT-027` currently tombstoned or inactive and does not introduce any current title, Status vocabulary, row syntax, link syntax, value, or canonical byte.' \
  '- The candidate creates no general tombstone vocabulary or transition for another row.'; do
  p32jboundaryhits=$(grep -cFx -e "$p32jboundary" "$PKT32J"); p32jrc=$?
  [ "$p32jrc" -le 1 ] || err "$PKT32J boundary statement scan failed"
  [ "$p32jboundaryhits" = 1 ] || err "$PKT32J required boundary statement is missing, altered, or duplicated"
done

for p32jtranscript in \
  '**OWNER-APPROVED F1 BASELINE — IMPLEMENTATION EVIDENCE NONE — ALL GATES OPEN**' \
  '**OWNER-APPROVED F1 BASELINE — IMPLEMENTATION EVIDENCE NONE — ALL GATES OPEN — QK-LIM-PSBT-027 PERMANENT TOMBSTONE**' \
  'Every row is one atomic limit: one metric, one unit, one scope, one enforcement point, one future value. This registry deliberately contains **no numeric values, no examples, no defaults, no candidate values, and no recommendations**. Every Value cell is exactly `OPEN — VALUE NOT AUTHORIZED IN F1` and every Status cell is exactly `OPEN`. Values may be authorized only by an explicit owner decision that consumes measurement evidence; no single project phase can freeze them by itself, and F2 measurement alone is insufficient. Instrumented, non-production prototypes may run before values are authorized only under explicit conservative temporary caps that appear in no normative document. No provisional number may appear in any normative document.' \
  'Every live row is one atomic limit: one metric, one unit, one scope, one enforcement point, one future value. This registry deliberately contains **no numeric values, no examples, no defaults, no candidate values, and no recommendations**. Every live-row Value cell is exactly `OPEN — VALUE NOT AUTHORIZED IN F1` and every live-row Status cell is exactly `OPEN`. The retained `QK-LIM-PSBT-027` row is the sole permanent tombstone and is not a live limit row: it preserves the historical dimension name and ID, carries no operative metric, unit, scope, enforcement point, future value, threat, link, evidence, or open-decision relationship, and can never be reopened. Its Value cell is exactly `NOT A VALUE — PERMANENT TOMBSTONE SENTINEL` and its Status cell is exactly `TOMBSTONED — PERMANENT — NON-REUSABLE`; neither cell authorizes or represents zero, a numeric value, a candidate value, a default, or an approved QK-LIM value. This row-specific representation creates no general tombstone vocabulary or transition for another row. Values for live rows may be authorized only by an explicit owner decision that consumes measurement evidence; no single project phase can freeze them by itself, and F2 measurement alone is insufficient. Instrumented, non-production prototypes may run before live-row values are authorized only under explicit conservative temporary caps that appear in no normative document. No provisional number may appear in any normative document.' \
  'Append-only ID note: formerly grouped rows were narrowed to a single atomic dimension while keeping their original IDs; the split-out dimensions were appended as new IDs (F1 audit-correction pass and F1 semantic audit-correction pass). No ID was renumbered or reused.' \
  'Append-only ID note: formerly grouped rows were narrowed to a single atomic dimension while keeping their original IDs; the split-out dimensions were appended as new IDs (F1 audit-correction pass and F1 semantic audit-correction pass). No ID was renumbered or reused. QK-LIM-PSBT-027 is retained with its historical dimension name and ID as a permanent non-reusable tombstone; it is never deleted, renumbered, reused, repurposed, or reopened. No other RESOURCE-BUDGETS ID or row is changed by this row-specific tombstone construction.' \
  '| QK-LIM-PSBT-027 | Raw final-transaction output bytes | qk-core output serialization | QK-THR-016 unbounded output | QK-REQ-PSBT-005, QK-REQ-TRN-007; QK-TST-DIFF-004 | Output size distribution; transport ceilings | OPEN — VALUE NOT AUTHORIZED IN F1 | OPEN | OD-05 |' \
  '| QK-LIM-PSBT-027 | Raw final-transaction output bytes | NONE — FORMER BOUNDARY RELATIONSHIP NON-OPERATIVE | HISTORICAL ONLY — FORMER QK-THR-016 RELATIONSHIP NON-OPERATIVE | NONE — FORMER REQUIREMENT AND TEST RELATIONSHIPS REMOVED | NONE — FORMER EVIDENCE RELATIONSHIP NON-OPERATIVE | NOT A VALUE — PERMANENT TOMBSTONE SENTINEL | TOMBSTONED — PERMANENT — NON-REUSABLE | NONE — FORMER OD-05 RELATIONSHIP NON-OPERATIVE |' \
  'QK-LIM-PSBT-001, QK-LIM-PSBT-002, QK-LIM-PSBT-003, QK-LIM-PSBT-004, QK-LIM-PSBT-005, QK-LIM-PSBT-006, QK-LIM-PSBT-007, QK-LIM-PSBT-008, QK-LIM-PSBT-009, QK-LIM-PSBT-010, QK-LIM-PSBT-011, QK-LIM-PSBT-012, QK-LIM-PSBT-013, QK-LIM-PSBT-014, QK-LIM-PSBT-015, QK-LIM-PSBT-016, QK-LIM-PSBT-017, QK-LIM-PSBT-018, QK-LIM-PSBT-019, QK-LIM-PSBT-020, QK-LIM-PSBT-021, QK-LIM-PSBT-022, QK-LIM-PSBT-023, QK-LIM-PSBT-024, QK-LIM-PSBT-025, QK-LIM-PSBT-026, QK-LIM-PSBT-027' \
  'QK-LIM-PSBT-001, QK-LIM-PSBT-002, QK-LIM-PSBT-003, QK-LIM-PSBT-004, QK-LIM-PSBT-005, QK-LIM-PSBT-006, QK-LIM-PSBT-007, QK-LIM-PSBT-008, QK-LIM-PSBT-009, QK-LIM-PSBT-010, QK-LIM-PSBT-011, QK-LIM-PSBT-012, QK-LIM-PSBT-013, QK-LIM-PSBT-014, QK-LIM-PSBT-015, QK-LIM-PSBT-016, QK-LIM-PSBT-017, QK-LIM-PSBT-018, QK-LIM-PSBT-019, QK-LIM-PSBT-020, QK-LIM-PSBT-021, QK-LIM-PSBT-022, QK-LIM-PSBT-023, QK-LIM-PSBT-024, QK-LIM-PSBT-025, QK-LIM-PSBT-026' \
  'QK-LIM-SD-004, QK-LIM-PSBT-026, QK-LIM-PSBT-027' \
  'QK-LIM-SD-004, QK-LIM-PSBT-026' \
  'QK-REQ-TRN-007; QK-THR-006; QK-LIM-PSBT-026, QK-LIM-PSBT-027' \
  'QK-REQ-TRN-007; QK-THR-006; QK-LIM-PSBT-026'; do
  p32jtranscripthits=$(grep -cFx -e "$p32jtranscript" "$PKT32J"); p32jrc=$?
  [ "$p32jrc" -le 1 ] || err "$PKT32J exact transcript scan failed"
  [ "$p32jtranscripthits" = 1 ] || err "$PKT32J exact current/proposed transcript is missing, altered, or duplicated"
done

while IFS=' ' read -r p32jprotected p32jprotectedblob; do
  git --no-optional-locks rev-parse "$p32jstage:$p32jprotected" > "$tmpdir/p32j.protected.act" 2>/dev/null; p32jrc=$?
  [ "$p32jrc" -eq 0 ] || err "F3.2j protected blob scan failed for $p32jprotected"
  printf '%s\n' "$p32jprotectedblob" > "$tmpdir/p32j.protected.exp" \
    || err "F3.2j protected blob fixture generation failed for $p32jprotected"
  cmp -s "$tmpdir/p32j.protected.exp" "$tmpdir/p32j.protected.act"; p32jrc=$?
  [ "$p32jrc" -eq 0 ] || err "F3.2j protected blob differs for $p32jprotected"
done <<'QK_F32J_PROTECTED_BLOBS_EOF'
docs/RESOURCE-BUDGETS.md 1ae6494fc24a8e3572464cf45e6d43ea4875e95d
docs/REQUIREMENTS.md 981b1b497102187da66fb4e82ef0725b32c088f7
docs/TEST-ARCHITECTURE.md 065e20eed4e916c907a244aa3e5ca2e66cbc5d4e
docs/f3/F3.2I-QK-LIM-PSBT-027-OWNER-DIRECTION-RECORD.md 2f4bc0f5cb8e861b45f515fb7c4c5dbc764784c5
QK_F32J_PROTECTED_BLOBS_EOF
git --no-optional-locks show "$p32jstage:docs/RESOURCE-BUDGETS.md" > "$tmpdir/p32j.resource.frozen" 2>/dev/null; p32jrc=$?
[ "$p32jrc" -eq 0 ] || err "F3.2j frozen RESOURCE-BUDGETS read failed"
for p32jrow in "$p32hrow026" "$p32hrow027"; do
  p32jrowhits=$(grep -cFx -e "$p32jrow" "$tmpdir/p32j.resource.frozen"); p32jrc=$?
  [ "$p32jrc" -le 1 ] || err "F3.2j canonical source-row scan failed"
  [ "$p32jrowhits" = 1 ] || err "F3.2j protected canonical row is missing, altered, or duplicated"
done

iconv -f UTF-8 -t UTF-8 "$PKT32J" > "$tmpdir/p32j.utf8" 2> "$tmpdir/p32j.iconv.err"; p32jrc=$?
[ "$p32jrc" -eq 0 ] || err "$PKT32J is not strict UTF-8"
[ -s "$tmpdir/p32j.utf8" ] || err "$PKT32J UTF-8 validation produced empty output"
cmp -s "$PKT32J" "$tmpdir/p32j.utf8"; p32jrc=$?
[ "$p32jrc" -eq 0 ] || err "$PKT32J UTF-8 validation changed bytes"
tail -c 1 "$PKT32J" > "$tmpdir/p32j.last.raw"; p32jrc=$?
[ "$p32jrc" -eq 0 ] || err "$PKT32J final-byte read failed"
od -An -tuC "$tmpdir/p32j.last.raw" > "$tmpdir/p32j.last.od"; p32jrc=$?
[ "$p32jrc" -eq 0 ] || err "$PKT32J final-byte scan failed"
tr -d '[:space:]' < "$tmpdir/p32j.last.od" > "$tmpdir/p32j.last.norm"; p32jrc=$?
[ "$p32jrc" -eq 0 ] || err "$PKT32J final-byte normalization failed"
p32jlast=$(cat "$tmpdir/p32j.last.norm"); p32jrc=$?
[ "$p32jrc" -eq 0 ] || err "$PKT32J final-byte read-back failed"
[ "$p32jlast" = 10 ] || err "$PKT32J must end in exact LF"
tail -c 2 "$PKT32J" > "$tmpdir/p32j.last2.raw"; p32jrc=$?
[ "$p32jrc" -eq 0 ] || err "$PKT32J final-two-byte read failed"
printf '\n\n' > "$tmpdir/p32j.double-lf" || err "$PKT32J double-LF fixture generation failed"
cmp -s "$tmpdir/p32j.double-lf" "$tmpdir/p32j.last2.raw"; p32jrc=$?
[ "$p32jrc" -eq 1 ] || err "$PKT32J must not end in double LF or the cmp check failed (exit $p32jrc)"
od -An -tx1 "$PKT32J" > "$tmpdir/p32j.bytes.raw"; p32jrc=$?
[ "$p32jrc" -eq 0 ] || err "$PKT32J byte scan failed"
awk 'BEGIN { bad=0; p2=""; p1="" }
  {
    for (i=1; i<=NF; i++) {
      b=tolower($i)
      if (b == "00" || b == "0d") bad=bad+1
      seq=p2 p1 b
      if (seq == "efbbbf" || seq == "e2808e" || seq == "e2808f" ||
          seq == "e280aa" || seq == "e280ab" || seq == "e280ac" ||
          seq == "e280ad" || seq == "e280ae" || seq == "e281a6" ||
          seq == "e281a7" || seq == "e281a8" || seq == "e281a9") bad=bad+1
      p2=p1
      p1=b
    }
  }
  END { print bad+0 }' "$tmpdir/p32j.bytes.raw" > "$tmpdir/p32j.bytes.bad"; p32jrc=$?
[ "$p32jrc" -eq 0 ] || err "$PKT32J control/bidi byte scan failed"
p32jbad=$(cat "$tmpdir/p32j.bytes.bad"); p32jrc=$?
[ "$p32jrc" -eq 0 ] || err "$PKT32J control/bidi result read failed"
[ "$p32jbad" = 0 ] || err "$PKT32J contains BOM, NUL, CR, LRM/RLM, or bidi controls"
forbid "$PKT32J contains a tab, trailing whitespace, HTML comment, hidden link definition, fence, blockquote, URL, or email material" \
  -E '	|[[:blank:]]$|<!--|-->|^\[[^]]+\]:|^```|^[[:space:]]*>|https?://|[[:alnum:]_.+-]+@[[:alnum:].-]+' "$PKT32J"
forbid "$PKT32J contains PSBT or key payload material" -E '[7]0736274|[c]HNidP|[x]pub|[x]prv' "$PKT32J"
forbid "$PKT32J contains suspicious 41+ hex material" -E '[0-9a-fA-F]{41,}' "$PKT32J"
forbid "$PKT32J contains a standalone numeric zero that could be mistaken for a value" \
  -E '(^|[^[:alnum:]_])0([^[:alnum:]_]|$)' "$PKT32J"
printf '%s\n' \
  065e20eed4e916c907a244aa3e5ca2e66cbc5d4e \
  1ae6494fc24a8e3572464cf45e6d43ea4875e95d \
  2f4bc0f5cb8e861b45f515fb7c4c5dbc764784c5 \
  336956ec866ca3aa93791ffcb76f30e79e17dd31 \
  878b23be4690bb778a615bfe1a6ef108e7a94008 \
  878b23be4690bb778a615bfe1a6ef108e7a94008 \
  981b1b497102187da66fb4e82ef0725b32c088f7 > "$tmpdir/p32j.hex.exp" \
  || err "$PKT32J exact-40-hex multiset fixture generation failed"
awk '{s=$0; while (match(s,/[0-9a-fA-F]+/)) {t=substr(s,RSTART,RLENGTH); if (length(t)==40) print tolower(t); s=substr(s,RSTART+RLENGTH)}}' \
  "$PKT32J" > "$tmpdir/p32j.hex.raw"; p32jrc=$?
[ "$p32jrc" -eq 0 ] || err "$PKT32J exact-40-hex enumeration failed"
LC_ALL=C sort "$tmpdir/p32j.hex.raw" > "$tmpdir/p32j.hex.act"; p32jrc=$?
[ "$p32jrc" -eq 0 ] || err "$PKT32J exact-40-hex sort failed"
cmp -s "$tmpdir/p32j.hex.exp" "$tmpdir/p32j.hex.act"; p32jrc=$?
[ "$p32jrc" -eq 0 ] || err "$PKT32J exact-40-hex multiset differs"

# ---------------- F3.2k exact-construction owner-direction record
# Later owner direction only: the source packet remains historical and
# present canonical effect remains NONE.
REC32K=docs/f3/F3.2K-QK-LIM-PSBT-027-EXACT-CONSTRUCTION-OWNER-DIRECTION-RECORD.md
[ -f "$REC32K" ] || err "$REC32K missing"
p32kbase=0d2115de9c322bf221f5a5008d91e7b7b48363e6
p32ka=2abf7092adff3b0e27f754c6021c3d852db638f8
p32kstage=49ca0aa4a19ca10ebe8f2866b2d9426720b8ebdf
p32kdlogblob=ac43ddd8a83d5be95e11d8208a0a998925b1027b
p32krecordblob=5b05d62776c65bfaf5ec41ab39108bc0531b7944
p32kpacketblob=b1c2153f5f89a0e1d44d62a09921251e225c0d87
git --no-optional-locks show "$p32ka:docs/DECISION-LOG.md" > "$tmpdir/p32k.dlog.a" 2>/dev/null; p32krc=$?
[ "$p32krc" -eq 0 ] || err "F3.2k authorization Decision Log read failed"

git --no-optional-locks rev-parse "$p32kbase^{commit}" > "$tmpdir/p32k.base.act" 2>/dev/null
p32krc=$?
[ "$p32krc" -eq 0 ] || err "F3.2k source base does not resolve"
printf '%s\n' "$p32kbase" > "$tmpdir/p32k.base.exp" || err "F3.2k source-base fixture failed"
cmp -s "$tmpdir/p32k.base.exp" "$tmpdir/p32k.base.act"; p32krc=$?
[ "$p32krc" -eq 0 ] || err "F3.2k source base differs"
git --no-optional-locks rev-parse "$p32ka^{commit}" > "$tmpdir/p32k.a.act" 2>/dev/null
p32krc=$?
[ "$p32krc" -eq 0 ] || err "F3.2k A does not resolve"
printf '%s\n' "$p32ka" > "$tmpdir/p32k.a.exp" || err "F3.2k A fixture failed"
cmp -s "$tmpdir/p32k.a.exp" "$tmpdir/p32k.a.act"; p32krc=$?
[ "$p32krc" -eq 0 ] || err "F3.2k A differs"
p32kaparent=$(git --no-optional-locks rev-parse "$p32ka^" 2>/dev/null); p32krc=$?
[ "$p32krc" -eq 0 ] || err "F3.2k A parent lookup failed"
[ "$p32kaparent" = "$p32kbase" ] || err "F3.2k A parent differs"
git --no-optional-locks diff-tree --no-commit-id --name-only -r "$p32ka" > "$tmpdir/p32k.a.paths.act"; p32krc=$?
[ "$p32krc" -eq 0 ] || err "F3.2k A path enumeration failed"
printf '%s\n' docs/DECISION-LOG.md > "$tmpdir/p32k.a.paths.exp" || err "F3.2k A path fixture failed"
cmp -s "$tmpdir/p32k.a.paths.exp" "$tmpdir/p32k.a.paths.act"; p32krc=$?
[ "$p32krc" -eq 0 ] || err "F3.2k A path set differs"

for p32kpair in \
  "docs/DECISION-LOG.md|$p32kdlogblob" \
  "$REC32K|$p32krecordblob" \
  "$PKT32J|$p32kpacketblob"; do
  p32kpath=${p32kpair%%|*}
  p32kexpected=${p32kpair#*|}
  git --no-optional-locks rev-parse "$p32kstage:$p32kpath" > "$tmpdir/p32k.blob.act" 2>/dev/null; p32krc=$?
  [ "$p32krc" -eq 0 ] || err "F3.2k blob scan failed for $p32kpath"
  [ -s "$tmpdir/p32k.blob.act" ] || err "F3.2k blob scan empty for $p32kpath"
  printf '%s\n' "$p32kexpected" > "$tmpdir/p32k.blob.exp" || err "F3.2k blob fixture failed"
  cmp -s "$tmpdir/p32k.blob.exp" "$tmpdir/p32k.blob.act"; p32krc=$?
  [ "$p32krc" -eq 0 ] || err "F3.2k active blob differs for $p32kpath"
done

for p32kowner in \
  'Approve, as a non-enacting owner direction for separately authorized later canonical work, the complete, indivisible, byte-for-byte candidate F32J-LIM-CON-001 exactly as printed in the published F3.2j packet at commit 0d2115de9c322bf221f5a5008d91e7b7b48363e6, packet blob b1c2153f5f89a0e1d44d62a09921251e225c0d87. Approve all and only its proposed future canonical bytes. Approve no alternative, subset, paraphrase, normalization, substitution, or additional change.' \
  'This approval selects only the exact future construction. It does not enact those bytes, amend any canonical document, or declare QK-LIM-PSBT-027 currently tombstoned or inactive. The current row remains OPEN with its current live links until separately authorized canonical work. The proposed Value-cell text remains a non-value sentinel, never zero or an authorized QK-LIM value. Preserve the historical ID and dimension name, QK-LIM-PSBT-026, ALL GATES OPEN, and every other canonical and historical byte. OD-05 and QK-THR-016 remain unresolved or unchanged globally; only their future row-027 relationships become non-operative. Introduce no general tombstone vocabulary or transition for another row.' \
  'Authorize preparation and independent audit of a non-enacting docs-only F3.2k QK-LIM-PSBT-027 exact-construction owner-direction record from published commit 0d2115de9c322bf221f5a5008d91e7b7b48363e6, recording only this exact approval and reproducing the selected future bytes byte-for-byte, with only the mechanically necessary Decision Log and verifier bindings.' \
  'No canonical RESOURCE-BUDGETS, REQUIREMENTS, or TEST-ARCHITECTURE edit; no current QK-LIM value, title, Status, link, row, vocabulary, or syntax change; no current QK-TST Plan / oracle, Links, or status change; no answer to F32C-D11-Q-002 through Q-012; no D-11, D-09, OD-05/06, profile, clause, dependency, implementation, testing, corpus, vector, fixture, evidence, media-I/O, hardware, license, gate, STOP-SHIP, setting, credential, other-branch, tag, release, publication, or remote change.'; do
  for p32kownerfile in "$tmpdir/p32k.dlog.a" "$REC32K"; do
    p32kownerhits=$(grep -cFx -e "$p32kowner" "$p32kownerfile"); p32krc=$?
    [ "$p32krc" -le 1 ] || err "F3.2k owner transcript scan failed in $p32kownerfile"
    [ "$p32kownerhits" = 1 ] || err "F3.2k owner transcript differs or duplicates in $p32kownerfile"
  done
done
sed -n '/^### QK-AUTH-F3.2K-QK-LIM-PSBT-027-EXACT-CON-DIR-REC-001 /,$p' "$tmpdir/p32k.dlog.a" > "$tmpdir/p32k.dlog.section"; p32krc=$?
[ "$p32krc" -eq 0 ] || err "F3.2k Decision Log section extraction failed"
sed -n '/^- \*\*Owner words exactly (literal four-paragraph block follows):\*\*$/,/^- \*\*Published parent and source locators:\*\*/p' "$tmpdir/p32k.dlog.section" > "$tmpdir/p32k.owner.dlog.framed"; p32krc=$?
[ "$p32krc" -eq 0 ] || err "F3.2k Decision Log owner framing failed"
sed '1d;$d' "$tmpdir/p32k.owner.dlog.framed" > "$tmpdir/p32k.owner.dlog"; p32krc=$?
[ "$p32krc" -eq 0 ] || err "F3.2k Decision Log owner deframing failed"
sed -n '/^## Owner words exactly$/,/^## Exact direction map$/p' "$REC32K" > "$tmpdir/p32k.owner.record.framed"; p32krc=$?
[ "$p32krc" -eq 0 ] || err "F3.2k record owner framing failed"
sed '1d;$d' "$tmpdir/p32k.owner.record.framed" > "$tmpdir/p32k.owner.record"; p32krc=$?
[ "$p32krc" -eq 0 ] || err "F3.2k record owner deframing failed"
cmp -s "$tmpdir/p32k.owner.dlog" "$tmpdir/p32k.owner.record"; p32krc=$?
[ "$p32krc" -eq 0 ] || err "F3.2k owner transcript blocks differ"

grep '^| F32J-LIM-CON-' "$REC32K" > "$tmpdir/p32k.direction.act"; p32krc=$?
[ "$p32krc" -eq 0 ] || err "F3.2k direction-row extraction failed"
cat > "$tmpdir/p32k.direction.exp" <<'QK_F32K_DIRECTION_EOF' || err "F3.2k direction fixture failed"
| F32J-LIM-CON-001 | PROPOSED — UNSELECTED — HISTORICAL SOURCE STATE | OWNER DIRECTION APPROVED — NON-ENACTING — COMPLETE INDIVISIBLE CONSTRUCTION ONLY | NONE — FUTURE CONSTRUCTION ONLY |
QK_F32K_DIRECTION_EOF
cmp -s "$tmpdir/p32k.direction.exp" "$tmpdir/p32k.direction.act"; p32krc=$?
[ "$p32krc" -eq 0 ] || err "F3.2k one-construction direction map differs"
p32kstatushits=$(grep -cFx -e 'STATUS: OWNER DIRECTION APPROVED — NON-ENACTING — F32J-LIM-CON-001 ONLY — COMPLETE INDIVISIBLE BYTE-FOR-BYTE FUTURE CONSTRUCTION SELECTED — NO ALTERNATIVE, SUBSET, PARAPHRASE, NORMALIZATION, SUBSTITUTION, OR ADDITIONAL CHANGE APPROVED — F3.2J PROPOSED — UNSELECTED STATE PRESERVED AS HISTORICAL — NO CANONICAL EDIT — CURRENT QK-LIM-PSBT-027 REMAINS OPEN WITH CURRENT LIVE LINKS — QK-LIM-PSBT-026 AND ALL CANONICAL SOURCES UNCHANGED — LOCAL AND UNPUBLISHED.' "$REC32K"); p32krc=$?
[ "$p32krc" -le 1 ] || err "F3.2k status scan failed"
[ "$p32kstatushits" = 1 ] || err "F3.2k exact status differs or duplicates"
for p32kboundary in \
  'complete, indivisible, byte-for-byte `F32J-LIM-CON-001` future construction' \
  'No alternative, subset, paraphrase, normalization, substitution, explanatory packet prose, or added change is approved.' \
  'Present canonical effect is exactly `NONE`.' \
  'does not declare current row 027 `TOMBSTONED` or `INACTIVE`' \
  'literal non-value sentinel `NOT A VALUE — PERMANENT TOMBSTONE SENTINEL`' \
  'OD-05 remains unresolved globally and QK-THR-016 remains unchanged globally' \
  'creates no current or general tombstone vocabulary or transition'; do
  p32kboundaryhits=$(grep -cF -e "$p32kboundary" "$REC32K"); p32krc=$?
  [ "$p32krc" -le 1 ] || err "F3.2k semantic-boundary scan failed"
  [ "$p32kboundaryhits" = 1 ] || err "F3.2k semantic boundary missing or duplicated: $p32kboundary"
done

p32knum=1
while [ "$p32knum" -le 7 ]; do
  case $p32knum in
    1)
      sed -n '/^## Exact current and proposed RESOURCE-BUDGETS preamble bytes$/,/^## Exact current and proposed RESOURCE-BUDGETS invariant bytes$/p' "$PKT32J" > "$tmpdir/p32k.region"; p32krc=$?
      [ "$p32krc" -eq 0 ] || err "F3.2k preamble region extraction failed"
      sed -n '/^### Proposed exact future canonical bytes$/,/^The proposed preamble /p' "$tmpdir/p32k.region" > "$tmpdir/p32k.packet.framed" ;;
    2)
      sed -n '/^## Exact current and proposed RESOURCE-BUDGETS invariant bytes$/,/^## Exact current and proposed RESOURCE-BUDGETS append-only-ID-note bytes$/p' "$PKT32J" > "$tmpdir/p32k.region"; p32krc=$?
      [ "$p32krc" -eq 0 ] || err "F3.2k invariant region extraction failed"
      sed -n '/^### Proposed exact future canonical bytes$/,/^The proposed invariant /p' "$tmpdir/p32k.region" > "$tmpdir/p32k.packet.framed" ;;
    3)
      sed -n '/^## Exact current and proposed RESOURCE-BUDGETS append-only-ID-note bytes$/,/^## Exact current and proposed RESOURCE-BUDGETS row bytes$/p' "$PKT32J" > "$tmpdir/p32k.region"; p32krc=$?
      [ "$p32krc" -eq 0 ] || err "F3.2k append-note region extraction failed"
      sed -n '/^### Proposed exact future canonical bytes$/,/^The proposed note /p' "$tmpdir/p32k.region" > "$tmpdir/p32k.packet.framed" ;;
    4)
      sed -n '/^## Exact current and proposed RESOURCE-BUDGETS row bytes$/,/^## Exact current and proposed consumer-cell bytes$/p' "$PKT32J" > "$tmpdir/p32k.region"; p32krc=$?
      [ "$p32krc" -eq 0 ] || err "F3.2k row region extraction failed"
      sed -n '/^### Proposed exact future canonical row$/,/^### Every row cell, current and proposed$/p' "$tmpdir/p32k.region" > "$tmpdir/p32k.packet.framed" ;;
    5)
      sed -n '/^### QK-REQ-PSBT-005 Lim cell$/,/^### QK-REQ-TRN-007 Lim cell$/p' "$PKT32J" > "$tmpdir/p32k.region"; p32krc=$?
      [ "$p32krc" -eq 0 ] || err "F3.2k PSBT-005 region extraction failed"
      sed -n '/^Proposed exact future canonical bytes:$/,/^### QK-REQ-TRN-007 Lim cell$/p' "$tmpdir/p32k.region" > "$tmpdir/p32k.packet.framed" ;;
    6)
      sed -n '/^### QK-REQ-TRN-007 Lim cell$/,/^### QK-TST-DIFF-004 Links cell$/p' "$PKT32J" > "$tmpdir/p32k.region"; p32krc=$?
      [ "$p32krc" -eq 0 ] || err "F3.2k TRN-007 region extraction failed"
      sed -n '/^Proposed exact future canonical bytes:$/,/^### QK-TST-DIFF-004 Links cell$/p' "$tmpdir/p32k.region" > "$tmpdir/p32k.packet.framed" ;;
    7)
      sed -n '/^### QK-TST-DIFF-004 Links cell$/,/^## Protected bytes and non-effects$/p' "$PKT32J" > "$tmpdir/p32k.region"; p32krc=$?
      [ "$p32krc" -eq 0 ] || err "F3.2k DIFF-004 region extraction failed"
      sed -n '/^Proposed exact future canonical bytes:$/,/^These are exactly three /p' "$tmpdir/p32k.region" > "$tmpdir/p32k.packet.framed" ;;
  esac
  p32krc=$?; [ "$p32krc" -eq 0 ] || err "F3.2k packet payload $p32knum framing failed"
  sed '1d;$d' "$tmpdir/p32k.packet.framed" > "$tmpdir/p32k.packet.payload"; p32krc=$?
  [ "$p32krc" -eq 0 ] || err "F3.2k packet payload $p32knum deframing failed"
  sed -n "/^### Exact selected future bytes — $p32knum\$/,/^### End selected future payload $p32knum\$/p" "$REC32K" > "$tmpdir/p32k.record.framed"; p32krc=$?
  [ "$p32krc" -eq 0 ] || err "F3.2k record payload $p32knum framing failed"
  sed '1d;$d' "$tmpdir/p32k.record.framed" > "$tmpdir/p32k.record.payload"; p32krc=$?
  [ "$p32krc" -eq 0 ] || err "F3.2k record payload $p32knum deframing failed"
  [ -s "$tmpdir/p32k.packet.payload" ] || err "F3.2k packet payload $p32knum empty"
  [ -s "$tmpdir/p32k.record.payload" ] || err "F3.2k record payload $p32knum empty"
  p32kplines=$(awk 'END {print NR+0}' "$tmpdir/p32k.packet.payload"); p32krc=$?
  [ "$p32krc" -eq 0 ] || err "F3.2k packet payload line count failed"
  p32krlines=$(awk 'END {print NR+0}' "$tmpdir/p32k.record.payload"); p32krc=$?
  [ "$p32krc" -eq 0 ] || err "F3.2k record payload line count failed"
  [ "$p32kplines" = 3 ] || err "F3.2k packet payload $p32knum cardinality differs"
  [ "$p32krlines" = 3 ] || err "F3.2k record payload $p32knum cardinality differs"
  cmp -s "$tmpdir/p32k.packet.payload" "$tmpdir/p32k.record.payload"; p32krc=$?
  [ "$p32krc" -eq 0 ] || err "F3.2k payload $p32knum differs byte-for-byte from F3.2j"
  p32kpayline=$(sed -n '2p' "$tmpdir/p32k.record.payload"); p32krc=$?
  [ "$p32krc" -eq 0 ] || err "F3.2k payload $p32knum read failed"
  [ -n "$p32kpayline" ] || err "F3.2k payload $p32knum content empty"
  p32kpayhits=$(grep -cFx -e "$p32kpayline" "$REC32K"); p32krc=$?
  [ "$p32krc" -le 1 ] || err "F3.2k payload $p32knum uniqueness scan failed"
  [ "$p32kpayhits" = 1 ] || err "F3.2k payload $p32knum is missing or duplicated"
  p32knum=$((p32knum + 1))
done
for p32kheading in \
  '^## Selected future payload [1-7] — ' \
  '^### Exact selected future bytes — [1-7]$' \
  '^### End selected future payload [1-7]$'; do
  p32kheadinghits=$(grep -c "$p32kheading" "$REC32K"); p32krc=$?
  [ "$p32krc" -le 1 ] || err "F3.2k payload heading count failed"
  [ "$p32kheadinghits" = 7 ] || err "F3.2k payload heading cardinality differs"
done

while IFS=' ' read -r p32kprotected p32kprotectedblob; do
  git --no-optional-locks rev-parse "$p32kstage:$p32kprotected" > "$tmpdir/p32k.protected.act" 2>/dev/null; p32krc=$?
  [ "$p32krc" -eq 0 ] || err "F3.2k protected blob scan failed for $p32kprotected"
  printf '%s\n' "$p32kprotectedblob" > "$tmpdir/p32k.protected.exp" || err "F3.2k protected fixture failed"
  cmp -s "$tmpdir/p32k.protected.exp" "$tmpdir/p32k.protected.act"; p32krc=$?
  [ "$p32krc" -eq 0 ] || err "F3.2k protected blob differs for $p32kprotected"
done <<'QK_F32K_PROTECTED_EOF'
docs/RESOURCE-BUDGETS.md 1ae6494fc24a8e3572464cf45e6d43ea4875e95d
docs/REQUIREMENTS.md 981b1b497102187da66fb4e82ef0725b32c088f7
docs/TEST-ARCHITECTURE.md 065e20eed4e916c907a244aa3e5ca2e66cbc5d4e
docs/f3/F3.2I-QK-LIM-PSBT-027-OWNER-DIRECTION-RECORD.md 2f4bc0f5cb8e861b45f515fb7c4c5dbc764784c5
docs/f3/F3.2J-QK-LIM-PSBT-027-EXACT-TOMBSTONE-CONSTRUCTION-PACKET.md b1c2153f5f89a0e1d44d62a09921251e225c0d87
QK_F32K_PROTECTED_EOF
git --no-optional-locks show "$p32kstage:docs/RESOURCE-BUDGETS.md" > "$tmpdir/p32k.resource.frozen" 2>/dev/null; p32krc=$?
[ "$p32krc" -eq 0 ] || err "F3.2k frozen RESOURCE-BUDGETS read failed"
for p32krow in "$p32hrow026" "$p32hrow027"; do
  p32krowhits=$(grep -cFx -e "$p32krow" "$tmpdir/p32k.resource.frozen"); p32krc=$?
  [ "$p32krc" -le 1 ] || err "F3.2k current-row scan failed"
  [ "$p32krowhits" = 1 ] || err "F3.2k current row missing, altered, or duplicated"
done
p32kcandidatehits=$(grep -cFx -e '| F32J-LIM-CON-001 | PROPOSED — UNSELECTED | RECOMMENDED — NOT SELECTED | NONE — FUTURE CONSTRUCTION ONLY |' "$PKT32J"); p32krc=$?
[ "$p32krc" -le 1 ] || err "F3.2k historical candidate scan failed"
[ "$p32kcandidatehits" = 1 ] || err "F3.2j PROPOSED — UNSELECTED state differs"

iconv -f UTF-8 -t UTF-8 "$REC32K" > "$tmpdir/p32k.utf8" 2> "$tmpdir/p32k.iconv.err"; p32krc=$?
[ "$p32krc" -eq 0 ] || err "$REC32K is not strict UTF-8"
[ -s "$tmpdir/p32k.utf8" ] || err "$REC32K UTF-8 validation empty"
cmp -s "$REC32K" "$tmpdir/p32k.utf8"; p32krc=$?
[ "$p32krc" -eq 0 ] || err "$REC32K UTF-8 validation changed bytes"
tail -c 1 "$REC32K" > "$tmpdir/p32k.last"; p32krc=$?
[ "$p32krc" -eq 0 ] || err "$REC32K final-byte read failed"
od -An -tuC "$tmpdir/p32k.last" > "$tmpdir/p32k.last.od"; p32krc=$?
[ "$p32krc" -eq 0 ] || err "$REC32K final-byte scan failed"
tr -d '[:space:]' < "$tmpdir/p32k.last.od" > "$tmpdir/p32k.last.norm"; p32krc=$?
[ "$p32krc" -eq 0 ] || err "$REC32K final-byte normalization failed"
p32klast=$(cat "$tmpdir/p32k.last.norm"); p32krc=$?
[ "$p32krc" -eq 0 ] || err "$REC32K final-byte result read failed"
[ "$p32klast" = 10 ] || err "$REC32K must end in exact LF"
tail -c 2 "$REC32K" > "$tmpdir/p32k.last2"; p32krc=$?
[ "$p32krc" -eq 0 ] || err "$REC32K final-two-byte read failed"
printf '\n\n' > "$tmpdir/p32k.double" || err "$REC32K double-LF fixture failed"
cmp -s "$tmpdir/p32k.double" "$tmpdir/p32k.last2"; p32krc=$?
[ "$p32krc" -eq 1 ] || err "$REC32K must not end in double LF or cmp failed (exit $p32krc)"
od -An -tx1 "$REC32K" > "$tmpdir/p32k.bytes"; p32krc=$?
[ "$p32krc" -eq 0 ] || err "$REC32K byte scan failed"
awk 'BEGIN {bad=0; p2=""; p1=""} {for(i=1;i<=NF;i++){b=tolower($i); if(b=="00"||b=="0d")bad++; seq=p2 p1 b; if(seq=="efbbbf"||seq=="e2808e"||seq=="e2808f"||seq=="e280aa"||seq=="e280ab"||seq=="e280ac"||seq=="e280ad"||seq=="e280ae"||seq=="e281a6"||seq=="e281a7"||seq=="e281a8"||seq=="e281a9")bad++; p2=p1; p1=b}} END {print bad+0}' "$tmpdir/p32k.bytes" > "$tmpdir/p32k.bad"; p32krc=$?
[ "$p32krc" -eq 0 ] || err "$REC32K control/bidi scan failed"
p32kbad=$(cat "$tmpdir/p32k.bad"); p32krc=$?
[ "$p32krc" -eq 0 ] || err "$REC32K control/bidi result read failed"
[ "$p32kbad" = 0 ] || err "$REC32K contains BOM, NUL, CR, LRM/RLM, or bidi controls"
forbid "$REC32K contains a tab, trailing whitespace, HTML comment, hidden link definition, fence, blockquote, URL, or email material" \
  -E '	|[[:blank:]]$|<!--|-->|^\[[^]]+\]:|^```|^[[:space:]]*>|https?://|[[:alnum:]_.+-]+@[[:alnum:].-]+' "$REC32K"
forbid "$REC32K contains PSBT or key payload material" -E '[7]0736274|[c]HNidP|[x]pub|[x]prv' "$REC32K"
forbid "$REC32K contains suspicious 41+ hex material" -E '[0-9a-fA-F]{41,}' "$REC32K"
forbid "$REC32K contains a standalone numeric zero that could be mistaken for a value" -E '(^|[^[:alnum:]_])0([^[:alnum:]_]|$)' "$REC32K"
printf '%s\n' \
  065e20eed4e916c907a244aa3e5ca2e66cbc5d4e \
  0d2115de9c322bf221f5a5008d91e7b7b48363e6 \
  0d2115de9c322bf221f5a5008d91e7b7b48363e6 \
  0d2115de9c322bf221f5a5008d91e7b7b48363e6 \
  1ae6494fc24a8e3572464cf45e6d43ea4875e95d \
  2abf7092adff3b0e27f754c6021c3d852db638f8 \
  2f4bc0f5cb8e861b45f515fb7c4c5dbc764784c5 \
  981b1b497102187da66fb4e82ef0725b32c088f7 \
  b1c2153f5f89a0e1d44d62a09921251e225c0d87 \
  b1c2153f5f89a0e1d44d62a09921251e225c0d87 \
  b1c2153f5f89a0e1d44d62a09921251e225c0d87 > "$tmpdir/p32k.hex.exp" || err "$REC32K exact-40-hex fixture failed"
awk '{s=$0; while(match(s,/[0-9a-fA-F]+/)){t=substr(s,RSTART,RLENGTH); if(length(t)==40)print tolower(t); s=substr(s,RSTART+RLENGTH)}}' "$REC32K" > "$tmpdir/p32k.hex.raw"; p32krc=$?
[ "$p32krc" -eq 0 ] || err "$REC32K exact-40-hex enumeration failed"
LC_ALL=C sort "$tmpdir/p32k.hex.raw" > "$tmpdir/p32k.hex.act"; p32krc=$?
[ "$p32krc" -eq 0 ] || err "$REC32K exact-40-hex sort failed"
cmp -s "$tmpdir/p32k.hex.exp" "$tmpdir/p32k.hex.act"; p32krc=$?
[ "$p32krc" -eq 0 ] || err "$REC32K exact-40-hex multiset differs"

# ---------------- F3.2l QK-LIM-PSBT-027 canonical tombstone amendment
# The published F3.2k stage is the immutable source. The exact published
# F3.2l snapshot enacts all and only the seven selected canonical payloads.
p32lbase=49ca0aa4a19ca10ebe8f2866b2d9426720b8ebdf
p32la=4af6166dc23eed7285a3d65b339924cda7b07962
p32lc=1408fa98961e62ba6316515b1e277b6952a96e18
p32ldlogblob=7d03656d245786f3a17eb4dbae689ef03b172b75
p32lresourcepost=09815b0a75c26a118f80c5cec008e695d319900b
p32lrequirementspost=2cf8a34aa5621dcea114e2d5ec3dabc2b79aef84
p32ltestpost=ecb3867ca2842f6d011288d3dcd94d2b1997e516
p32lkrecordblob=5b05d62776c65bfaf5ec41ab39108bc0531b7944
p32ljpacketblob=b1c2153f5f89a0e1d44d62a09921251e225c0d87

p32lbranch=$(git --no-optional-locks symbolic-ref --quiet --short HEAD 2>/dev/null); p32lrc=$?
[ "$p32lrc" -eq 0 ] || err "F3.2l checked-out branch cannot be resolved"
[ "$p32lbranch" = main ] || err "F3.2l checked-out branch is $p32lbranch, expected main"
p32lhead=$(git --no-optional-locks rev-parse "$p32lc^{commit}" 2>/dev/null); p32lrc=$?
[ "$p32lrc" -eq 0 ] || err "F3.2l published C cannot be resolved"
[ "$p32lhead" = "$p32lc" ] || err "F3.2l published C resolution differs"
p32lahead=$(git --no-optional-locks rev-list --count "$p32lbase..$p32lhead"); p32lrc=$?
[ "$p32lrc" -eq 0 ] || err "F3.2l base-to-published-C count failed"
p32lbehind=$(git --no-optional-locks rev-list --count "$p32lhead..$p32lbase"); p32lrc=$?
[ "$p32lrc" -eq 0 ] || err "F3.2l published-C-to-base count failed"
[ "$p32lahead" = 3 ] || err "F3.2l published C is $p32lahead commits above its base, expected exactly 3"
[ "$p32lbehind" = 0 ] || err "F3.2l base is $p32lbehind commits above published C, expected exactly 0"
p32lb=$(git --no-optional-locks rev-parse "$p32lc^" 2>/dev/null); p32lrc=$?
[ "$p32lrc" -eq 0 ] || err "F3.2l C parent lookup failed"
p32laact=$(git --no-optional-locks rev-parse "$p32lb^" 2>/dev/null); p32lrc=$?
[ "$p32lrc" -eq 0 ] || err "F3.2l B parent lookup failed"
p32lbaseact=$(git --no-optional-locks rev-parse "$p32laact^" 2>/dev/null); p32lrc=$?
[ "$p32lrc" -eq 0 ] || err "F3.2l A parent lookup failed"
[ "$p32laact" = "$p32la" ] || err "F3.2l derived A differs"
[ "$p32lbaseact" = "$p32lbase" ] || err "F3.2l A parent differs"

while IFS='|' read -r p32lmsgcommit p32lmsglabel p32lmsgexpected; do
  git --no-optional-locks log -1 --format=%B "$p32lmsgcommit" > "$tmpdir/p32l.msg.act"; p32lrc=$?
  [ "$p32lrc" -eq 0 ] || err "F3.2l $p32lmsglabel message read failed"
  printf '%s\n\n' "$p32lmsgexpected" > "$tmpdir/p32l.msg.exp" || err "F3.2l $p32lmsglabel message fixture failed"
  cmp -s "$tmpdir/p32l.msg.exp" "$tmpdir/p32l.msg.act"; p32lrc=$?
  [ "$p32lrc" -eq 0 ] || err "F3.2l $p32lmsglabel message differs or has a body"
done <<QK_F32L_MESSAGES_EOF
$p32la|A|docs: authorize F3.2l QK-LIM-PSBT-027 canonical tombstone amendment
$p32lb|B|docs(limits): enact QK-LIM-PSBT-027 permanent tombstone
$p32lc|C|chore(verify): bind F3.2l QK-LIM-PSBT-027 canonical amendment stage
QK_F32L_MESSAGES_EOF

printf '%s\n' docs/DECISION-LOG.md > "$tmpdir/p32l.a.paths.exp" || err "F3.2l A path fixture failed"
git --no-optional-locks diff-tree --no-commit-id --name-only -r "$p32la" > "$tmpdir/p32l.a.paths.act"; p32lrc=$?
[ "$p32lrc" -eq 0 ] || err "F3.2l A path enumeration failed"
cmp -s "$tmpdir/p32l.a.paths.exp" "$tmpdir/p32l.a.paths.act"; p32lrc=$?
[ "$p32lrc" -eq 0 ] || err "F3.2l A path set differs"
cat > "$tmpdir/p32l.b.paths.exp" <<'QK_F32L_B_PATHS_EOF' || err "F3.2l B path fixture failed"
docs/REQUIREMENTS.md
docs/RESOURCE-BUDGETS.md
docs/TEST-ARCHITECTURE.md
tools/verify-host-boundary.sh
QK_F32L_B_PATHS_EOF
git --no-optional-locks diff-tree --no-commit-id --name-only -r "$p32lb" > "$tmpdir/p32l.b.paths.raw"; p32lrc=$?
[ "$p32lrc" -eq 0 ] || err "F3.2l B path enumeration failed"
LC_ALL=C sort "$tmpdir/p32l.b.paths.raw" > "$tmpdir/p32l.b.paths.act"; p32lrc=$?
[ "$p32lrc" -eq 0 ] || err "F3.2l B path sort failed"
cmp -s "$tmpdir/p32l.b.paths.exp" "$tmpdir/p32l.b.paths.act"; p32lrc=$?
[ "$p32lrc" -eq 0 ] || err "F3.2l B path set differs"
printf '%s\n' tools/verify-current-stage.sh > "$tmpdir/p32l.c.paths.exp" || err "F3.2l C path fixture failed"
git --no-optional-locks diff-tree --no-commit-id --name-only -r "$p32lc" > "$tmpdir/p32l.c.paths.act"; p32lrc=$?
[ "$p32lrc" -eq 0 ] || err "F3.2l C path enumeration failed"
cmp -s "$tmpdir/p32l.c.paths.exp" "$tmpdir/p32l.c.paths.act"; p32lrc=$?
[ "$p32lrc" -eq 0 ] || err "F3.2l C path set differs"
cat > "$tmpdir/p32l.paths.exp" <<'QK_F32L_PATHS_EOF' || err "F3.2l cumulative path fixture failed"
docs/DECISION-LOG.md
docs/REQUIREMENTS.md
docs/RESOURCE-BUDGETS.md
docs/TEST-ARCHITECTURE.md
tools/verify-current-stage.sh
tools/verify-host-boundary.sh
QK_F32L_PATHS_EOF
git --no-optional-locks diff --name-only "$p32lbase" "$p32lc" > "$tmpdir/p32l.paths.raw"; p32lrc=$?
[ "$p32lrc" -eq 0 ] || err "F3.2l cumulative path enumeration failed"
LC_ALL=C sort "$tmpdir/p32l.paths.raw" > "$tmpdir/p32l.paths.act"; p32lrc=$?
[ "$p32lrc" -eq 0 ] || err "F3.2l cumulative path sort failed"
cmp -s "$tmpdir/p32l.paths.exp" "$tmpdir/p32l.paths.act"; p32lrc=$?
[ "$p32lrc" -eq 0 ] || err "F3.2l cumulative path set differs"

while IFS='|' read -r p32ltreecommit p32ltreemode p32ltreeblob p32ltreepath; do
  git --no-optional-locks ls-tree "$p32ltreecommit" -- "$p32ltreepath" > "$tmpdir/p32l.tree.raw"; p32lrc=$?
  [ "$p32lrc" -eq 0 ] || err "F3.2l tree lookup failed for $p32ltreepath"
  [ -s "$tmpdir/p32l.tree.raw" ] || err "F3.2l tree entry missing for $p32ltreepath"
  p32ltreelines=$(awk 'END {print NR+0}' "$tmpdir/p32l.tree.raw"); p32lrc=$?
  [ "$p32lrc" -eq 0 ] || err "F3.2l tree line count failed for $p32ltreepath"
  [ "$p32ltreelines" = 1 ] || err "F3.2l tree entry is not unique for $p32ltreepath"
  p32ltreeactmode=$(awk 'NR == 1 {print $1}' "$tmpdir/p32l.tree.raw"); p32lrc=$?
  [ "$p32lrc" -eq 0 ] || err "F3.2l tree mode read failed for $p32ltreepath"
  p32ltreeactblob=$(awk 'NR == 1 {print $3}' "$tmpdir/p32l.tree.raw"); p32lrc=$?
  [ "$p32lrc" -eq 0 ] || err "F3.2l tree blob read failed for $p32ltreepath"
  [ "$p32ltreeactmode" = "$p32ltreemode" ] || err "F3.2l mode differs for $p32ltreepath"
  if [ "$p32ltreeblob" != "-" ]; then
    [ "$p32ltreeactblob" = "$p32ltreeblob" ] || err "F3.2l tree blob differs for $p32ltreepath"
  fi
done <<QK_F32L_TREE_EOF
$p32la|100644|$p32ldlogblob|docs/DECISION-LOG.md
$p32lb|100644|$p32lresourcepost|docs/RESOURCE-BUDGETS.md
$p32lb|100644|$p32lrequirementspost|docs/REQUIREMENTS.md
$p32lb|100644|$p32ltestpost|docs/TEST-ARCHITECTURE.md
$p32lb|100755|-|tools/verify-host-boundary.sh
$p32lc|100755|-|tools/verify-current-stage.sh
QK_F32L_TREE_EOF

git --no-optional-locks show "$p32lbase:docs/DECISION-LOG.md" > "$tmpdir/p32l.dlog.base" 2>/dev/null; p32lrc=$?
[ "$p32lrc" -eq 0 ] || err "F3.2l base Decision Log read failed"
git --no-optional-locks show "$p32la:docs/DECISION-LOG.md" > "$tmpdir/p32l.dlog.a" 2>/dev/null; p32lrc=$?
[ "$p32lrc" -eq 0 ] || err "F3.2l A Decision Log read failed"
git --no-optional-locks show "$p32lc:docs/DECISION-LOG.md" > "$tmpdir/p32l.dlog.frozen" 2>/dev/null; p32lrc=$?
[ "$p32lrc" -eq 0 ] || err "F3.2l published Decision Log read failed"
cmp -s "$tmpdir/p32l.dlog.a" "$tmpdir/p32l.dlog.frozen"; p32lrc=$?
[ "$p32lrc" -eq 0 ] || err "F3.2l published Decision Log differs from A"
wc -c < "$tmpdir/p32l.dlog.base" > "$tmpdir/p32l.dlog.bytes.raw"; p32lrc=$?
[ "$p32lrc" -eq 0 ] || err "F3.2l Decision Log base byte count failed"
tr -d '[:space:]' < "$tmpdir/p32l.dlog.bytes.raw" > "$tmpdir/p32l.dlog.bytes"; p32lrc=$?
[ "$p32lrc" -eq 0 ] || err "F3.2l Decision Log byte-count normalization failed"
p32lbasebytes=$(cat "$tmpdir/p32l.dlog.bytes"); p32lrc=$?
[ "$p32lrc" -eq 0 ] || err "F3.2l Decision Log byte-count read failed"
case $p32lbasebytes in ''|*[!0-9]*) err "F3.2l Decision Log base byte count is non-numeric" ;; esac
dd if="$tmpdir/p32l.dlog.a" bs=1 count="$p32lbasebytes" > "$tmpdir/p32l.dlog.prefix" 2> "$tmpdir/p32l.dlog.dd.err"; p32lrc=$?
[ "$p32lrc" -eq 0 ] || err "F3.2l Decision Log prefix read failed"
cmp -s "$tmpdir/p32l.dlog.base" "$tmpdir/p32l.dlog.prefix"; p32lrc=$?
[ "$p32lrc" -eq 0 ] || err "F3.2l Decision Log is not an exact append"
p32lauthhits=$(grep -cFx -e '### QK-AUTH-F3.2L-QK-LIM-PSBT-027-CANONICAL-AMEND-001 — F3.2l QK-LIM-PSBT-027 canonical permanent-tombstone amendment authorization' "$tmpdir/p32l.dlog.frozen"); p32lrc=$?
[ "$p32lrc" -le 1 ] || err "F3.2l authorization heading scan failed"
[ "$p32lauthhits" = 1 ] || err "F3.2l authorization heading differs or duplicates"
sed -n '/^### QK-AUTH-F3.2L-QK-LIM-PSBT-027-CANONICAL-AMEND-001 /,$p' "$tmpdir/p32l.dlog.frozen" > "$tmpdir/p32l.dlog.section"; p32lrc=$?
[ "$p32lrc" -eq 0 ] || err "F3.2l Decision Log section extraction failed"
sed -n '/^- \*\*Owner words exactly (literal three-paragraph block follows):\*\*$/,/^- \*\*Published parent and source locators:\*\*/p' "$tmpdir/p32l.dlog.section" > "$tmpdir/p32l.owner.framed"; p32lrc=$?
[ "$p32lrc" -eq 0 ] || err "F3.2l owner block framing failed"
sed '1,2d;$d' "$tmpdir/p32l.owner.framed" > "$tmpdir/p32l.owner.with-tail"; p32lrc=$?
[ "$p32lrc" -eq 0 ] || err "F3.2l owner block first deframing failed"
sed '$d' "$tmpdir/p32l.owner.with-tail" > "$tmpdir/p32l.owner.act"; p32lrc=$?
[ "$p32lrc" -eq 0 ] || err "F3.2l owner block final deframing failed"
cat > "$tmpdir/p32l.owner.exp" <<'QK_F32L_OWNER_EOF' || err "F3.2l owner fixture failed"
Authorize preparation and independent audit of a docs-only F3.2l canonical QK-LIM-PSBT-027 permanent-tombstone amendment from published commit 49ca0aa4a19ca10ebe8f2866b2d9426720b8ebdf. Enact, as one indivisible byte-for-byte construction, all and only the seven owner-approved future canonical payloads for F32J-LIM-CON-001 reproduced in the published F3.2k owner-direction record at blob 5b05d62776c65bfaf5ec41ab39108bc0531b7944 and sourced from the immutable F3.2j packet at blob b1c2153f5f89a0e1d44d62a09921251e225c0d87. Stop on any missing, duplicated, or mismatched source span; permit no alternative, subset, paraphrase, normalization, substitution, reformatting, or additional byte.

Replace exactly once: in docs/RESOURCE-BUDGETS.md, only the approved preamble, invariant, append-only-ID note, and complete QK-LIM-PSBT-027 row; in docs/REQUIREMENTS.md, only the Lim cells of QK-REQ-PSBT-005 and QK-REQ-TRN-007; and in docs/TEST-ARCHITECTURE.md, only the Links cell of QK-TST-DIFF-004. This enactment makes QK-LIM-PSBT-027 the sole permanent, non-reusable canonical tombstone. Preserve its historical ID and dimension name, QK-LIM-PSBT-026, ALL GATES OPEN, and every other canonical and historical byte. Its Value text is a non-value sentinel, never zero or an authorized QK-LIM value. Never delete, renumber, reuse, repurpose, or reopen ID 027. Introduce no general tombstone vocabulary or transition for another row. OD-05 remains unresolved globally and QK-THR-016 remains unchanged globally; only their row-027 relationships become non-operative.

Use exactly three linear single-parent commits: Commit A appends only docs/DECISION-LOG.md; Commit B changes only docs/RESOURCE-BUDGETS.md, docs/REQUIREMENTS.md, docs/TEST-ARCHITECTURE.md, and tools/verify-host-boundary.sh; Commit C changes only tools/verify-current-stage.sh. Include only the mechanically necessary Decision Log and verifier bindings. No other RESOURCE-BUDGETS row or byte, Requirement text or cell, or QK-TST Plan / oracle, Milestone, Gate, Evidence artifact, Status, or other cell change. No answer to F32C-D11-Q-002 through Q-012; no D-11, D-09, OD-05/06, other QK-LIM value, profile, clause, or dependency selection; no implementation, testing, corpus, vector, fixture, evidence, media-I/O, hardware, license, gate, STOP-SHIP, setting, credential, other-branch, tag, release, publication, remote, or other change. Stop locally after independent audit; publication requires separate exact-commit authority.
QK_F32L_OWNER_EOF
cmp -s "$tmpdir/p32l.owner.exp" "$tmpdir/p32l.owner.act"; p32lrc=$?
[ "$p32lrc" -eq 0 ] || err "F3.2l literal owner block differs"
p32lhistoricalhits=$(grep -cFx -e '- **Historical source disposition:** the immutable F3.2j packet remains `PROPOSED — UNSELECTED` as its historical source state, and the immutable F3.2k record remains `OWNER DIRECTION APPROVED — NON-ENACTING` as its historical selection state. Their former `LOCAL AND UNPUBLISHED` text remains byte-identical historical wording; both historical stages are now published.' docs/DECISION-LOG.md); p32lrc=$?
[ "$p32lrc" -le 1 ] || err "F3.2l historical publication statement scan failed"
[ "$p32lhistoricalhits" = 1 ] || err "F3.2l historical publication statement differs or duplicates"

for p32lsourcepair in \
  "$REC32K|$p32lkrecordblob" \
  "$PKT32J|$p32ljpacketblob"; do
  p32lsourcepath=${p32lsourcepair%%|*}
  p32lsourceexpected=${p32lsourcepair#*|}
  git --no-optional-locks rev-parse "$p32lc:$p32lsourcepath" > "$tmpdir/p32l.source.act" 2>/dev/null; p32lrc=$?
  [ "$p32lrc" -eq 0 ] || err "F3.2l source blob scan failed for $p32lsourcepath"
  printf '%s\n' "$p32lsourceexpected" > "$tmpdir/p32l.source.exp" || err "F3.2l source blob fixture failed"
  cmp -s "$tmpdir/p32l.source.exp" "$tmpdir/p32l.source.act"; p32lrc=$?
  [ "$p32lrc" -eq 0 ] || err "F3.2l immutable source blob differs for $p32lsourcepath"
done
awk -v d="$tmpdir" '
  NR == 37 { print > (d "/p32l.1.old") }
  NR == 41 { print > (d "/p32l.1.new") }
  NR == 49 { print > (d "/p32l.2.old") }
  NR == 53 { print > (d "/p32l.2.new") }
  NR == 61 { print > (d "/p32l.3.old") }
  NR == 65 { print > (d "/p32l.3.new") }
  NR == 73 { print > (d "/p32l.4.old") }
  NR == 77 { print > (d "/p32l.4.new") }
  NR == 101 { print > (d "/p32l.5.old") }
  NR == 105 { print > (d "/p32l.5.new") }
  NR == 111 { print > (d "/p32l.6.old") }
  NR == 115 { print > (d "/p32l.6.new") }
  NR == 121 { print > (d "/p32l.7.old") }
  NR == 125 { print > (d "/p32l.7.new") }' "$PKT32J"; p32lrc=$?
[ "$p32lrc" -eq 0 ] || err "F3.2l packet payload extraction failed"
awk -v d="$tmpdir" '
  NR == 44 { print > (d "/p32l.1.record") }
  NR == 52 { print > (d "/p32l.2.record") }
  NR == 60 { print > (d "/p32l.3.record") }
  NR == 68 { print > (d "/p32l.4.record") }
  NR == 76 { print > (d "/p32l.5.record") }
  NR == 84 { print > (d "/p32l.6.record") }
  NR == 92 { print > (d "/p32l.7.record") }' "$REC32K"; p32lrc=$?
[ "$p32lrc" -eq 0 ] || err "F3.2l record payload extraction failed"
p32lnum=1
while [ "$p32lnum" -le 7 ]; do
  [ -s "$tmpdir/p32l.$p32lnum.old" ] || err "F3.2l old payload $p32lnum is empty"
  [ -s "$tmpdir/p32l.$p32lnum.new" ] || err "F3.2l new payload $p32lnum is empty"
  cmp -s "$tmpdir/p32l.$p32lnum.new" "$tmpdir/p32l.$p32lnum.record"; p32lrc=$?
  [ "$p32lrc" -eq 0 ] || err "F3.2l payload $p32lnum differs between packet and record"
  p32lnum=$((p32lnum + 1))
done

git --no-optional-locks show "$p32lbase:docs/RESOURCE-BUDGETS.md" > "$tmpdir/p32l.resource.0" 2>/dev/null; p32lrc=$?
[ "$p32lrc" -eq 0 ] || err "F3.2l base RESOURCE-BUDGETS read failed"
git --no-optional-locks show "$p32lbase:docs/REQUIREMENTS.md" > "$tmpdir/p32l.requirements.0" 2>/dev/null; p32lrc=$?
[ "$p32lrc" -eq 0 ] || err "F3.2l base REQUIREMENTS read failed"
git --no-optional-locks show "$p32lbase:docs/TEST-ARCHITECTURE.md" > "$tmpdir/p32l.test.0" 2>/dev/null; p32lrc=$?
[ "$p32lrc" -eq 0 ] || err "F3.2l base TEST-ARCHITECTURE read failed"
cat > "$tmpdir/p32l.replace.awk" <<'QK_F32L_REPLACE_AWK_EOF' || err "F3.2l replacement program fixture failed"
BEGIN { count = 0 }
{
  pos = index($0, old)
  if (pos > 0) {
    rest = substr($0, pos + length(old))
    if (index(rest, old) > 0) exit 93
    print substr($0, 1, pos - 1) new rest
    count++
    next
  }
  print
}
END { if (count != 1) exit 92 }
QK_F32L_REPLACE_AWK_EOF
p32l_replace_exact() {
  p32lreplacein=$1
  p32lreplaceout=$2
  p32lreplaceoldfile=$3
  p32lreplacenewfile=$4
  p32lreplaceold=$(cat "$p32lreplaceoldfile"); p32lreplacerc=$?
  [ "$p32lreplacerc" -eq 0 ] || err "F3.2l old replacement payload read failed"
  p32lreplacenew=$(cat "$p32lreplacenewfile"); p32lreplacerc=$?
  [ "$p32lreplacerc" -eq 0 ] || err "F3.2l new replacement payload read failed"
  awk -v old="$p32lreplaceold" -v new="$p32lreplacenew" -f "$tmpdir/p32l.replace.awk" "$p32lreplacein" > "$p32lreplaceout"
  p32lreplacerc=$?
  [ "$p32lreplacerc" -eq 0 ] || err "F3.2l exact-once replacement failed for $p32lreplaceoldfile"
}
p32l_replace_exact "$tmpdir/p32l.resource.0" "$tmpdir/p32l.resource.1" "$tmpdir/p32l.1.old" "$tmpdir/p32l.1.new"
p32l_replace_exact "$tmpdir/p32l.resource.1" "$tmpdir/p32l.resource.2" "$tmpdir/p32l.2.old" "$tmpdir/p32l.2.new"
p32l_replace_exact "$tmpdir/p32l.resource.2" "$tmpdir/p32l.resource.3" "$tmpdir/p32l.3.old" "$tmpdir/p32l.3.new"
p32l_replace_exact "$tmpdir/p32l.resource.3" "$tmpdir/p32l.resource.4" "$tmpdir/p32l.4.old" "$tmpdir/p32l.4.new"
p32l_replace_exact "$tmpdir/p32l.requirements.0" "$tmpdir/p32l.requirements.1" "$tmpdir/p32l.5.old" "$tmpdir/p32l.5.new"
p32l_replace_exact "$tmpdir/p32l.requirements.1" "$tmpdir/p32l.requirements.2" "$tmpdir/p32l.6.old" "$tmpdir/p32l.6.new"
p32l_replace_exact "$tmpdir/p32l.test.0" "$tmpdir/p32l.test.1" "$tmpdir/p32l.7.old" "$tmpdir/p32l.7.new"
git --no-optional-locks show "$p32lc:docs/RESOURCE-BUDGETS.md" > "$tmpdir/p32l.resource.frozen" 2>/dev/null; p32lrc=$?
[ "$p32lrc" -eq 0 ] || err "F3.2l published RESOURCE-BUDGETS read failed"
git --no-optional-locks show "$p32lc:docs/REQUIREMENTS.md" > "$tmpdir/p32l.requirements.frozen" 2>/dev/null; p32lrc=$?
[ "$p32lrc" -eq 0 ] || err "F3.2l published REQUIREMENTS read failed"
git --no-optional-locks show "$p32lc:docs/TEST-ARCHITECTURE.md" > "$tmpdir/p32l.test.frozen" 2>/dev/null; p32lrc=$?
[ "$p32lrc" -eq 0 ] || err "F3.2l published TEST-ARCHITECTURE read failed"
cmp -s "$tmpdir/p32l.resource.4" "$tmpdir/p32l.resource.frozen"; p32lrc=$?
[ "$p32lrc" -eq 0 ] || err "F3.2l RESOURCE-BUDGETS is not the exact four-payload reconstruction"
cmp -s "$tmpdir/p32l.requirements.2" "$tmpdir/p32l.requirements.frozen"; p32lrc=$?
[ "$p32lrc" -eq 0 ] || err "F3.2l REQUIREMENTS is not the exact two-payload reconstruction"
cmp -s "$tmpdir/p32l.test.1" "$tmpdir/p32l.test.frozen"; p32lrc=$?
[ "$p32lrc" -eq 0 ] || err "F3.2l TEST-ARCHITECTURE is not the exact one-payload reconstruction"
for p32lpostpair in \
  "docs/RESOURCE-BUDGETS.md|$p32lresourcepost" \
  "docs/REQUIREMENTS.md|$p32lrequirementspost" \
  "docs/TEST-ARCHITECTURE.md|$p32ltestpost"; do
  p32lpostpath=${p32lpostpair%%|*}
  p32lpostexpected=${p32lpostpair#*|}
  git --no-optional-locks rev-parse "$p32lc:$p32lpostpath" > "$tmpdir/p32l.post.act" 2>/dev/null; p32lrc=$?
  [ "$p32lrc" -eq 0 ] || err "F3.2l post-enactment blob scan failed for $p32lpostpath"
  printf '%s\n' "$p32lpostexpected" > "$tmpdir/p32l.post.exp" || err "F3.2l post-enactment blob fixture failed"
  cmp -s "$tmpdir/p32l.post.exp" "$tmpdir/p32l.post.act"; p32lrc=$?
  [ "$p32lrc" -eq 0 ] || err "F3.2l post-enactment blob differs for $p32lpostpath"
done

p32lrow026hits=$(grep -cFx -e "$p32hrow026" "$tmpdir/p32l.resource.frozen"); p32lrc=$?
[ "$p32lrc" -le 1 ] || err "F3.2l QK-LIM-PSBT-026 scan failed"
[ "$p32lrow026hits" = 1 ] || err "F3.2l changed or duplicated QK-LIM-PSBT-026"
p32lgatehits=$(grep -cF -e 'ALL GATES OPEN' "$tmpdir/p32l.resource.frozen"); p32lrc=$?
[ "$p32lrc" -le 1 ] || err "F3.2l ALL GATES OPEN scan failed"
[ "$p32lgatehits" = 1 ] || err "F3.2l ALL GATES OPEN state differs or duplicates"
for p32lglobalpath in docs/OPEN-DECISIONS.md docs/THREAT-MODEL.md; do
  git --no-optional-locks rev-parse "$p32lbase:$p32lglobalpath" > "$tmpdir/p32l.global.exp" 2>/dev/null; p32lrc=$?
  [ "$p32lrc" -eq 0 ] || err "F3.2l base global-state blob lookup failed for $p32lglobalpath"
  git --no-optional-locks rev-parse "$p32lc:$p32lglobalpath" > "$tmpdir/p32l.global.act" 2>/dev/null; p32lrc=$?
  [ "$p32lrc" -eq 0 ] || err "F3.2l published global-state blob scan failed for $p32lglobalpath"
  cmp -s "$tmpdir/p32l.global.exp" "$tmpdir/p32l.global.act"; p32lrc=$?
  [ "$p32lrc" -eq 0 ] || err "F3.2l global OD/threat state differs for $p32lglobalpath"
done
for p32lcfpair in \
  "docs/DECISION-LOG.md|$tmpdir/p32l.dlog.frozen" \
  "docs/RESOURCE-BUDGETS.md|$tmpdir/p32l.resource.frozen" \
  "docs/REQUIREMENTS.md|$tmpdir/p32l.requirements.frozen" \
  "docs/TEST-ARCHITECTURE.md|$tmpdir/p32l.test.frozen"; do
  p32lcfname=${p32lcfpair%%|*}
  p32lcf=${p32lcfpair#*|}
  iconv -f UTF-8 -t UTF-8 "$p32lcf" > "$tmpdir/p32l.utf8" 2> "$tmpdir/p32l.iconv.err"; p32lrc=$?
  [ "$p32lrc" -eq 0 ] || err "F3.2l published document is not strict UTF-8: $p32lcfname"
  cmp -s "$p32lcf" "$tmpdir/p32l.utf8"; p32lrc=$?
  [ "$p32lrc" -eq 0 ] || err "F3.2l UTF-8 round trip changed bytes: $p32lcfname"
  tail -c 1 "$p32lcf" > "$tmpdir/p32l.last"; p32lrc=$?
  [ "$p32lrc" -eq 0 ] || err "F3.2l final-byte read failed: $p32lcfname"
  od -An -tuC "$tmpdir/p32l.last" > "$tmpdir/p32l.last.od"; p32lrc=$?
  [ "$p32lrc" -eq 0 ] || err "F3.2l final-byte scan failed: $p32lcfname"
  p32llast=$(tr -d '[:space:]' < "$tmpdir/p32l.last.od"); p32lrc=$?
  [ "$p32lrc" -eq 0 ] || err "F3.2l final-byte normalization failed: $p32lcfname"
  [ "$p32llast" = 10 ] || err "F3.2l published document lacks exact final LF: $p32lcfname"
  od -An -tx1 "$p32lcf" > "$tmpdir/p32l.bytes"; p32lrc=$?
  [ "$p32lrc" -eq 0 ] || err "F3.2l byte scan failed: $p32lcfname"
  awk 'BEGIN {bad=0; p2=""; p1=""} {for(i=1;i<=NF;i++){b=tolower($i); if(b=="00"||b=="0d")bad++; seq=p2 p1 b; if(seq=="efbbbf"||seq=="e2808e"||seq=="e2808f"||seq=="e280aa"||seq=="e280ab"||seq=="e280ac"||seq=="e280ad"||seq=="e280ae"||seq=="e281a6"||seq=="e281a7"||seq=="e281a8"||seq=="e281a9")bad++; p2=p1; p1=b}} END {print bad+0}' "$tmpdir/p32l.bytes" > "$tmpdir/p32l.bad"; p32lrc=$?
  [ "$p32lrc" -eq 0 ] || err "F3.2l control/bidi scan failed: $p32lcfname"
  p32lbad=$(cat "$tmpdir/p32l.bad"); p32lrc=$?
  [ "$p32lrc" -eq 0 ] || err "F3.2l control/bidi result read failed: $p32lcfname"
  [ "$p32lbad" = 0 ] || err "F3.2l published document contains BOM, NUL, CR, LRM/RLM, or bidi controls: $p32lcfname"
  forbid "F3.2l published document contains a tab or trailing whitespace: $p32lcfname" -E '	|[[:blank:]]$' "$p32lcf"
done

# ---------------- F3.2m D-11 Q-002 SD attachment-epoch decision packet
# The exact F3.2l C snapshot and F3.2m C stage are published and immutable.
# F3.2m remains non-binding and non-enacting; its LOCAL AND UNPUBLISHED
# packet wording is preserved only as historical preparation-time text.
PKT32M=docs/f3/F3.2M-D11-Q002-SD-ATTACHMENT-EPOCH-DECISION-PACKET.md
[ -f "$PKT32M" ] || err "$PKT32M missing"
p32mbase=1408fa98961e62ba6316515b1e277b6952a96e18
p32mbasetree=75c5e69cf5154b1936b86a6f0795f615a4d6ab3d
p32ma=59008528885259ad8b93be1f0ece136930fd445d
p32mdlogbaseblob=7d03656d245786f3a17eb4dbae689ef03b172b75
p32mdlogablob=99384f6cd5eedd37488e0c12d865737217f88b6c
p32mpacketblob=11714544ea89b3475d65a8a5634b7fdab65f5972

git --no-optional-locks rev-parse "$p32mbase^{commit}" > "$tmpdir/p32m.base.act" 2>/dev/null; p32mrc=$?
[ "$p32mrc" -eq 0 ] || err "F3.2m published base does not resolve as a commit"
printf '%s\n' "$p32mbase" > "$tmpdir/p32m.base.exp" || err "F3.2m base fixture generation failed"
cmp -s "$tmpdir/p32m.base.exp" "$tmpdir/p32m.base.act"; p32mrc=$?
[ "$p32mrc" -eq 0 ] || err "F3.2m published base resolution differs"
git --no-optional-locks rev-parse "$p32mbase^{tree}" > "$tmpdir/p32m.tree.act" 2>/dev/null; p32mrc=$?
[ "$p32mrc" -eq 0 ] || err "F3.2m published base tree cannot be resolved"
printf '%s\n' "$p32mbasetree" > "$tmpdir/p32m.tree.exp" || err "F3.2m base-tree fixture generation failed"
cmp -s "$tmpdir/p32m.tree.exp" "$tmpdir/p32m.tree.act"; p32mrc=$?
[ "$p32mrc" -eq 0 ] || err "F3.2m published base tree differs"
git --no-optional-locks rev-parse "$p32ma^{commit}" > "$tmpdir/p32m.a.act" 2>/dev/null; p32mrc=$?
[ "$p32mrc" -eq 0 ] || err "F3.2m authorization commit A does not resolve"
printf '%s\n' "$p32ma" > "$tmpdir/p32m.a.exp" || err "F3.2m A fixture generation failed"
cmp -s "$tmpdir/p32m.a.exp" "$tmpdir/p32m.a.act"; p32mrc=$?
[ "$p32mrc" -eq 0 ] || err "F3.2m authorization commit A resolution differs"
p32maparent=$(git --no-optional-locks rev-parse "$p32ma^" 2>/dev/null); p32mrc=$?
[ "$p32mrc" -eq 0 ] || err "F3.2m authorization commit A parent cannot be resolved"
[ "$p32maparent" = "$p32mbase" ] || err "F3.2m authorization commit A parent differs"
git --no-optional-locks log -1 --format=%B "$p32ma" > "$tmpdir/p32m.a.msg.act"; p32mrc=$?
[ "$p32mrc" -eq 0 ] || err "F3.2m authorization commit A message read failed"
printf '%s\n\n' 'docs: authorize F3.2m D-11 Q-002 SD attachment-epoch decision packet' > "$tmpdir/p32m.a.msg.exp" \
  || err "F3.2m authorization commit A message fixture failed"
cmp -s "$tmpdir/p32m.a.msg.exp" "$tmpdir/p32m.a.msg.act"; p32mrc=$?
[ "$p32mrc" -eq 0 ] || err "F3.2m authorization commit A message differs or has a body"
git --no-optional-locks diff-tree --no-commit-id --name-only -r "$p32ma" > "$tmpdir/p32m.a.paths.act"; p32mrc=$?
[ "$p32mrc" -eq 0 ] || err "F3.2m authorization commit A path enumeration failed"
printf '%s\n' docs/DECISION-LOG.md > "$tmpdir/p32m.a.paths.exp" || err "F3.2m A path fixture failed"
cmp -s "$tmpdir/p32m.a.paths.exp" "$tmpdir/p32m.a.paths.act"; p32mrc=$?
[ "$p32mrc" -eq 0 ] || err "F3.2m authorization commit A changes a path other than docs/DECISION-LOG.md"

# The host verifier is committed in B, so it must verify either its exact
# intermediate B graph or the exact final C graph without self-pinning B/C.
p32mbranch=$(git --no-optional-locks symbolic-ref --quiet --short HEAD 2>/dev/null); p32mrc=$?
[ "$p32mrc" -eq 0 ] || err "F3.2m checked-out branch cannot be resolved"
[ "$p32mbranch" = main ] || err "F3.2m checked-out branch is not main"
p32mhead=$(git --no-optional-locks rev-parse "f41e26799d0c4522b91e1de72d27cf473116b3ab^{commit}" 2>/dev/null); p32mrc=$?
[ "$p32mrc" -eq 0 ] || err "F3.2m published C does not resolve as a commit"
git --no-optional-locks log -1 --format=%B "$p32mhead" > "$tmpdir/p32m.head.msg.act"; p32mrc=$?
[ "$p32mrc" -eq 0 ] || err "F3.2m HEAD message read failed"
printf '%s\n\n' 'docs(f3): add non-binding F3.2m D-11 Q-002 SD attachment-epoch decision packet' \
  > "$tmpdir/p32m.b.msg.exp" || err "F3.2m B message fixture failed"
printf '%s\n\n' 'chore(verify): bind F3.2m D-11 Q-002 decision-packet stage' \
  > "$tmpdir/p32m.c.msg.exp" || err "F3.2m C message fixture failed"
cmp -s "$tmpdir/p32m.b.msg.exp" "$tmpdir/p32m.head.msg.act"; p32mbheadrc=$?
cmp -s "$tmpdir/p32m.c.msg.exp" "$tmpdir/p32m.head.msg.act"; p32mcheadrc=$?
p32mstage=invalid
p32mb=$p32mhead
p32mc=$p32mhead
case "$p32mbheadrc:$p32mcheadrc" in
  0:1)
    p32mstage=b
    p32mb=$p32mhead
    ;;
  1:0)
    p32mstage=c
    p32mc=$p32mhead
    p32mb=$(git --no-optional-locks rev-parse "$p32mc^" 2>/dev/null); p32mrc=$?
    [ "$p32mrc" -eq 0 ] || err "F3.2m final C parent cannot be derived as B"
    ;;
  *)
    err "F3.2m HEAD is neither exact intermediate B nor exact final C by bodyless message"
    ;;
esac

p32m_single_parent() {
  p32mspcommit=$1
  p32msplabel=$2
  git --no-optional-locks rev-list --no-walk --parents "$p32mspcommit" \
    > "$tmpdir/p32m.single-parent"; p32msprc=$?
  [ "$p32msprc" -eq 0 ] || err "F3.2m $p32msplabel parent enumeration failed"
  p32mspfields=$(awk 'NR == 1 {print NF+0} END {if (NR != 1) exit 1}' \
    "$tmpdir/p32m.single-parent"); p32msprc=$?
  [ "$p32msprc" -eq 0 ] || err "F3.2m $p32msplabel parent count failed"
  [ "$p32mspfields" = 2 ] || err "F3.2m $p32msplabel is not a single-parent commit"
}

p32m_single_parent "$p32mb" "B"
p32mbparent=$(git --no-optional-locks rev-parse "$p32mb^" 2>/dev/null); p32mrc=$?
[ "$p32mrc" -eq 0 ] || err "F3.2m B parent cannot be resolved"
[ "$p32mbparent" = "$p32ma" ] || err "F3.2m B parent differs from exact A"
git --no-optional-locks log -1 --format=%B "$p32mb" > "$tmpdir/p32m.b.msg.act"; p32mrc=$?
[ "$p32mrc" -eq 0 ] || err "F3.2m B message read failed"
cmp -s "$tmpdir/p32m.b.msg.exp" "$tmpdir/p32m.b.msg.act"; p32mrc=$?
[ "$p32mrc" -eq 0 ] || err "F3.2m B full message differs or contains a body"

if [ "$p32mstage" = c ]; then
  p32m_single_parent "$p32mc" "C"
  p32mcparent=$(git --no-optional-locks rev-parse "$p32mc^" 2>/dev/null); p32mrc=$?
  [ "$p32mrc" -eq 0 ] || err "F3.2m final C parent cannot be resolved"
  [ "$p32mcparent" = "$p32mb" ] || err "F3.2m final C parent differs from derived B"
  git --no-optional-locks log -1 --format=%B "$p32mc" > "$tmpdir/p32m.c.msg.act"; p32mrc=$?
  [ "$p32mrc" -eq 0 ] || err "F3.2m C message read failed"
  cmp -s "$tmpdir/p32m.c.msg.exp" "$tmpdir/p32m.c.msg.act"; p32mrc=$?
  [ "$p32mrc" -eq 0 ] || err "F3.2m C full message differs or contains a body"
fi

p32mahead=$(git --no-optional-locks rev-list --count "$p32mbase..$p32mhead" 2>/dev/null); p32mrc=$?
[ "$p32mrc" -eq 0 ] || err "F3.2m ahead-count enumeration failed"
case "$p32mahead" in ''|*[!0-9]*) err "F3.2m ahead count is non-numeric" ;; esac
p32mbehind=$(git --no-optional-locks rev-list --count "$p32mhead..$p32mbase" 2>/dev/null); p32mrc=$?
[ "$p32mrc" -eq 0 ] || err "F3.2m behind-count enumeration failed"
case "$p32mbehind" in ''|*[!0-9]*) err "F3.2m behind count is non-numeric" ;; esac
[ "$p32mbehind" = 0 ] || err "F3.2m HEAD is behind or diverged from the exact base"
if [ "$p32mstage" = b ]; then
  [ "$p32mahead" = 2 ] || err "F3.2m intermediate B must be exactly two commits above base"
elif [ "$p32mstage" = c ]; then
  [ "$p32mahead" = 3 ] || err "F3.2m final C must be exactly three commits above base"
fi
p32mmerges=$(git --no-optional-locks rev-list --merges "$p32mbase..$p32mhead" 2>/dev/null); p32mrc=$?
[ "$p32mrc" -eq 0 ] || err "F3.2m merge enumeration failed"
[ -z "$p32mmerges" ] || err "F3.2m graph contains a merge commit"

git --no-optional-locks diff-tree --no-commit-id --name-only -r "$p32mb" \
  > "$tmpdir/p32m.b.paths.raw"; p32mrc=$?
[ "$p32mrc" -eq 0 ] || err "F3.2m B path enumeration failed"
[ -s "$tmpdir/p32m.b.paths.raw" ] || err "F3.2m B path enumeration produced no paths"
LC_ALL=C sort "$tmpdir/p32m.b.paths.raw" > "$tmpdir/p32m.b.paths.act"; p32mrc=$?
[ "$p32mrc" -eq 0 ] || err "F3.2m B path sort failed"
cat > "$tmpdir/p32m.b.paths.exp" <<'QK_F32M_B_PATHS_EOF' || err "F3.2m B path fixture failed"
docs/f3/F3.2M-D11-Q002-SD-ATTACHMENT-EPOCH-DECISION-PACKET.md
tools/verify-host-boundary.sh
QK_F32M_B_PATHS_EOF
cmp -s "$tmpdir/p32m.b.paths.exp" "$tmpdir/p32m.b.paths.act"; p32mrc=$?
[ "$p32mrc" -eq 0 ] || err "F3.2m B path set differs"

if [ "$p32mstage" = c ]; then
  git --no-optional-locks diff-tree --no-commit-id --name-only -r "$p32mc" \
    > "$tmpdir/p32m.c.paths.raw"; p32mrc=$?
  [ "$p32mrc" -eq 0 ] || err "F3.2m C path enumeration failed"
  [ -s "$tmpdir/p32m.c.paths.raw" ] || err "F3.2m C path enumeration produced no paths"
  LC_ALL=C sort "$tmpdir/p32m.c.paths.raw" > "$tmpdir/p32m.c.paths.act"; p32mrc=$?
  [ "$p32mrc" -eq 0 ] || err "F3.2m C path sort failed"
  printf '%s\n' tools/verify-current-stage.sh > "$tmpdir/p32m.c.paths.exp" \
    || err "F3.2m C path fixture failed"
  cmp -s "$tmpdir/p32m.c.paths.exp" "$tmpdir/p32m.c.paths.act"; p32mrc=$?
  [ "$p32mrc" -eq 0 ] || err "F3.2m C path set differs"
fi

git --no-optional-locks diff --name-only "$p32mbase" "$p32mhead" \
  > "$tmpdir/p32m.cumulative.raw"; p32mrc=$?
[ "$p32mrc" -eq 0 ] || err "F3.2m cumulative path enumeration failed"
LC_ALL=C sort "$tmpdir/p32m.cumulative.raw" > "$tmpdir/p32m.cumulative.act"; p32mrc=$?
[ "$p32mrc" -eq 0 ] || err "F3.2m cumulative path sort failed"
if [ "$p32mstage" = b ]; then
  cat > "$tmpdir/p32m.cumulative.exp" <<'QK_F32M_B_CUMULATIVE_EOF' || err "F3.2m B cumulative fixture failed"
docs/DECISION-LOG.md
docs/f3/F3.2M-D11-Q002-SD-ATTACHMENT-EPOCH-DECISION-PACKET.md
tools/verify-host-boundary.sh
QK_F32M_B_CUMULATIVE_EOF
  p32mcumulativeerr="F3.2m intermediate B cumulative path set differs"
elif [ "$p32mstage" = c ]; then
  cat > "$tmpdir/p32m.cumulative.exp" <<'QK_F32M_C_CUMULATIVE_EOF' || err "F3.2m C cumulative fixture failed"
docs/DECISION-LOG.md
docs/f3/F3.2M-D11-Q002-SD-ATTACHMENT-EPOCH-DECISION-PACKET.md
tools/verify-current-stage.sh
tools/verify-host-boundary.sh
QK_F32M_C_CUMULATIVE_EOF
  p32mcumulativeerr="F3.2m final C cumulative path set differs"
else
  : > "$tmpdir/p32m.cumulative.exp" || err "F3.2m invalid-stage cumulative fixture failed"
  p32mcumulativeerr="F3.2m invalid-stage cumulative path set differs"
fi
cmp -s "$tmpdir/p32m.cumulative.exp" "$tmpdir/p32m.cumulative.act"; p32mrc=$?
[ "$p32mrc" -eq 0 ] || err "$p32mcumulativeerr"

while IFS='|' read -r p32mtreecommit p32mtreemode p32mtreeblob p32mtreepath; do
  git --no-optional-locks ls-tree "$p32mtreecommit" -- "$p32mtreepath" > "$tmpdir/p32m.tree.entry"; p32mrc=$?
  [ "$p32mrc" -eq 0 ] || err "F3.2m tree lookup failed for $p32mtreepath"
  [ -s "$tmpdir/p32m.tree.entry" ] || err "F3.2m tree entry missing for $p32mtreepath"
  p32mtreelines=$(awk 'END {print NR+0}' "$tmpdir/p32m.tree.entry"); p32mrc=$?
  [ "$p32mrc" -eq 0 ] || err "F3.2m tree-entry count failed for $p32mtreepath"
  [ "$p32mtreelines" = 1 ] || err "F3.2m tree entry is not unique for $p32mtreepath"
  p32mtreeactmode=$(awk 'NR == 1 {print $1}' "$tmpdir/p32m.tree.entry"); p32mrc=$?
  [ "$p32mrc" -eq 0 ] || err "F3.2m tree mode read failed for $p32mtreepath"
  p32mtreeactblob=$(awk 'NR == 1 {print $3}' "$tmpdir/p32m.tree.entry"); p32mrc=$?
  [ "$p32mrc" -eq 0 ] || err "F3.2m tree blob read failed for $p32mtreepath"
  [ "$p32mtreeactmode" = "$p32mtreemode" ] || err "F3.2m mode differs for $p32mtreepath"
  [ "$p32mtreeactblob" = "$p32mtreeblob" ] || err "F3.2m blob differs for $p32mtreepath"
done <<QK_F32M_TREE_EOF
$p32ma|100644|$p32mdlogablob|docs/DECISION-LOG.md
$p32mb|100644|$p32mpacketblob|$PKT32M
QK_F32M_TREE_EOF
git --no-optional-locks ls-tree "$p32mb" -- tools/verify-host-boundary.sh > "$tmpdir/p32m.host.tree"; p32mrc=$?
[ "$p32mrc" -eq 0 ] || err "F3.2m active host-verifier tree lookup failed"
[ -s "$tmpdir/p32m.host.tree" ] || err "F3.2m active host-verifier tree entry missing"
p32mhostmode=$(awk 'NR == 1 {print $1}' "$tmpdir/p32m.host.tree"); p32mrc=$?
[ "$p32mrc" -eq 0 ] || err "F3.2m active host-verifier mode read failed"
[ "$p32mhostmode" = 100755 ] || err "F3.2m active host-verifier mode differs"
if [ "$p32mstage" = c ]; then
  git --no-optional-locks ls-tree "$p32mc" -- tools/verify-current-stage.sh \
    > "$tmpdir/p32m.current.tree"; p32mrc=$?
  [ "$p32mrc" -eq 0 ] || err "F3.2m current-stage-verifier tree lookup failed"
  [ -s "$tmpdir/p32m.current.tree" ] || err "F3.2m current-stage-verifier tree entry missing"
  p32mcurrentmode=$(awk 'NR == 1 {print $1}' "$tmpdir/p32m.current.tree"); p32mrc=$?
  [ "$p32mrc" -eq 0 ] || err "F3.2m current-stage-verifier mode read failed"
  [ "$p32mcurrentmode" = 100755 ] || err "F3.2m current-stage-verifier mode differs"
fi

git --no-optional-locks rev-parse "$p32mbase:docs/DECISION-LOG.md" > "$tmpdir/p32m.dlog.base.blob.act" 2>/dev/null; p32mrc=$?
[ "$p32mrc" -eq 0 ] || err "F3.2m base Decision Log blob lookup failed"
printf '%s\n' "$p32mdlogbaseblob" > "$tmpdir/p32m.dlog.base.blob.exp" || err "F3.2m base Decision Log blob fixture failed"
cmp -s "$tmpdir/p32m.dlog.base.blob.exp" "$tmpdir/p32m.dlog.base.blob.act"; p32mrc=$?
[ "$p32mrc" -eq 0 ] || err "F3.2m base Decision Log blob differs"
git --no-optional-locks show "$p32mbase:docs/DECISION-LOG.md" > "$tmpdir/p32m.dlog.base" 2>/dev/null; p32mrc=$?
[ "$p32mrc" -eq 0 ] || err "F3.2m base Decision Log read failed"
git --no-optional-locks show "$p32ma:docs/DECISION-LOG.md" > "$tmpdir/p32m.dlog.a" 2>/dev/null; p32mrc=$?
[ "$p32mrc" -eq 0 ] || err "F3.2m A Decision Log read failed"
git --no-optional-locks rev-parse "$p32ma:docs/DECISION-LOG.md" > "$tmpdir/p32m.dlog.active.blob" 2>/dev/null; p32mrc=$?
[ "$p32mrc" -eq 0 ] || err "F3.2m historical A Decision Log blob lookup failed"
printf '%s\n' "$p32mdlogablob" > "$tmpdir/p32m.dlog.a.blob.exp" || err "F3.2m A Decision Log blob fixture failed"
cmp -s "$tmpdir/p32m.dlog.a.blob.exp" "$tmpdir/p32m.dlog.active.blob"; p32mrc=$?
[ "$p32mrc" -eq 0 ] || err "F3.2m historical A Decision Log is not the exact A blob"
wc -c < "$tmpdir/p32m.dlog.base" > "$tmpdir/p32m.dlog.bytes.raw"; p32mrc=$?
[ "$p32mrc" -eq 0 ] || err "F3.2m base Decision Log byte count failed"
tr -d '[:space:]' < "$tmpdir/p32m.dlog.bytes.raw" > "$tmpdir/p32m.dlog.bytes"; p32mrc=$?
[ "$p32mrc" -eq 0 ] || err "F3.2m Decision Log byte-count normalization failed"
p32mbasebytes=$(cat "$tmpdir/p32m.dlog.bytes"); p32mrc=$?
[ "$p32mrc" -eq 0 ] || err "F3.2m Decision Log byte-count read failed"
case $p32mbasebytes in ''|*[!0-9]*) err "F3.2m Decision Log base byte count is non-numeric" ;; esac
dd if="$tmpdir/p32m.dlog.a" bs=1 count="$p32mbasebytes" > "$tmpdir/p32m.dlog.prefix" 2> "$tmpdir/p32m.dlog.dd.err"; p32mrc=$?
[ "$p32mrc" -eq 0 ] || err "F3.2m Decision Log prefix read failed"
cmp -s "$tmpdir/p32m.dlog.base" "$tmpdir/p32m.dlog.prefix"; p32mrc=$?
[ "$p32mrc" -eq 0 ] || err "F3.2m Decision Log is not an exact append"
p32mauthhits=$(grep -cFx -e '### QK-AUTH-F3.2M-D11-Q002-PKT-001 — F3.2m D-11 Q-002 SD attachment-epoch decision-packet preparation authorization' "$tmpdir/p32m.dlog.a"); p32mrc=$?
[ "$p32mrc" -le 1 ] || err "F3.2m authorization heading scan failed"
[ "$p32mauthhits" = 1 ] || err "F3.2m authorization heading differs or duplicates"

git --no-optional-locks hash-object -- "$PKT32M" > "$tmpdir/p32m.packet.blob.act"; p32mrc=$?
[ "$p32mrc" -eq 0 ] || err "F3.2m packet blob scan failed"
printf '%s\n' "$p32mpacketblob" > "$tmpdir/p32m.packet.blob.exp" || err "F3.2m packet blob fixture failed"
cmp -s "$tmpdir/p32m.packet.blob.exp" "$tmpdir/p32m.packet.blob.act"; p32mrc=$?
[ "$p32mrc" -eq 0 ] || err "F3.2m packet whole blob differs"

for p32mowner in \
  'Authorize preparation and independent audit of a non-binding, non-enacting docs-only F3.2m D-11 Q-002 SD attachment-epoch decision packet from published commit 1408fa98961e62ba6316515b1e277b6952a96e18, with only the mechanically necessary Decision Log and verifier bindings.' \
  'Limit the packet to F32C-D11-Q-002 only. Preserve and inventory the exact current QK-REQ-BND-003 requirement, the F3.2c Q-002, analysis-only sd_attachment_epoch, bounded read-only preflight, state-transition, and F32C-D11-F-017 material, the published F3.2d Q-001 clarification, and the published F3.2l canonical state. Present exactly three finite, mutually exclusive dispositions, all explicitly PROPOSED — UNSELECTED: F32M-D11-Q002-OPT-001, recommended conditional physical attachment-epoch binding whenever a later-selected export plan includes SD, with bounded read-only preflight before review and approval, the session-scoped non-authenticating epoch and exact reviewed preflight facts approval-bound, removal or replacement ending the epoch and the active attempt, no continuation or substitute-media output under that approval, and a new medium requiring a new plan and full review and approval while unchanged-epoch retry remains Q-005-open; F32M-D11-Q002-OPT-002, non-recommended logical SD-route binding with deferred physical insertion only after signing, subject to an explicit reconciliation with QK-REQ-BND-003, with any pre-signing media change still invalidating approval, no replacement continuation or silent approval carry-over, and retry remaining Q-005-open; or F32M-D11-Q002-OPT-003, deferral with Q-002 unresolved. State that recommendation is analysis only, not an owner answer or selection. Select no identifier, hash, serialization, authenticator, filename, collision policy, media-identity mechanism, filesystem, commit primitive, or target behavior.' \
  'No owner selection or canonical or historical edit; no answer to F32C-D11-Q-003 through Q-012 and no change to the recorded Q-001 clarification; no route-set or completion rule, retry rule, same-versus-distinct input/output media rule, filename/collision rule, visibility/commit/orphan rule, QR self-check rule, signature-insertion rule, or D-09 semantic-field rule; no D-11, D-09, OD-05/06, profile, clause, dependency, QK-LIM, QK-TST, evidence, gate, or STOP-SHIP change. Preserve QK-LIM-PSBT-027 as the sole permanent non-reusable tombstone, QK-LIM-PSBT-026, ALL GATES OPEN, and every other canonical and historical byte. No implementation, testing, corpus, vector, fixture, evidence, media I/O, hardware, firmware, license, setting, credential, other-branch, tag, release, publication, remote, or other change.'; do
  for p32mownerfile in "$tmpdir/p32m.dlog.a" "$PKT32M"; do
    p32mownerhits=$(grep -cFx -e "$p32mowner" "$p32mownerfile"); p32mrc=$?
    [ "$p32mrc" -le 1 ] || err "F3.2m owner transcript scan failed in $p32mownerfile"
    [ "$p32mownerhits" = 1 ] || err "F3.2m owner transcript differs or duplicates in $p32mownerfile"
  done
done
sed -n '/^### QK-AUTH-F3.2M-D11-Q002-PKT-001 /,$p' "$tmpdir/p32m.dlog.a" > "$tmpdir/p32m.dlog.section"; p32mrc=$?
[ "$p32mrc" -eq 0 ] || err "F3.2m Decision Log section extraction failed"
sed -n '/^- \*\*Owner words exactly (literal three-paragraph block follows):\*\*$/,/^- \*\*Published parent and source locators:\*\*/p' \
  "$tmpdir/p32m.dlog.section" > "$tmpdir/p32m.owner.dlog.framed"; p32mrc=$?
[ "$p32mrc" -eq 0 ] || err "F3.2m Decision Log owner-block extraction failed"
sed '1d;$d' "$tmpdir/p32m.owner.dlog.framed" > "$tmpdir/p32m.owner.dlog"; p32mrc=$?
[ "$p32mrc" -eq 0 ] || err "F3.2m Decision Log owner-block deframing failed"
sed -n '/^## Owner words exactly$/,/^## Exact current source inventory$/p' \
  "$PKT32M" > "$tmpdir/p32m.owner.packet.framed"; p32mrc=$?
[ "$p32mrc" -eq 0 ] || err "F3.2m packet owner-block extraction failed"
sed '1d;$d' "$tmpdir/p32m.owner.packet.framed" > "$tmpdir/p32m.owner.packet"; p32mrc=$?
[ "$p32mrc" -eq 0 ] || err "F3.2m packet owner-block deframing failed"
cmp -s "$tmpdir/p32m.owner.dlog" "$tmpdir/p32m.owner.packet"; p32mrc=$?
[ "$p32mrc" -eq 0 ] || err "F3.2m Decision Log and packet owner transcript blocks differ"

grep '^## ' "$PKT32M" > "$tmpdir/p32m.sections.act"; p32mrc=$?
[ "$p32mrc" -eq 0 ] || err "F3.2m ordered-section extraction failed"
cat > "$tmpdir/p32m.sections.exp" <<'QK_F32M_SECTIONS_EOF' || err "F3.2m ordered-section fixture failed"
## Standing/source boundary
## Supporting audit locators
## Owner words exactly
## Exact current source inventory
## Reconciliation analysis without selection
## F32C-D11-Q-002 owner question — UNANSWERED
## Exactly three dispositions
## Mutual exclusivity and guardrails
## Preserved state/non-effects
## Exact terminal marker
QK_F32M_SECTIONS_EOF
cmp -s "$tmpdir/p32m.sections.exp" "$tmpdir/p32m.sections.act"; p32mrc=$?
[ "$p32mrc" -eq 0 ] || err "F3.2m section order or closed grammar differs"
p32mtitlehits=$(grep -cFx -e '# QK-F3.2m — D-11 Q-002 SD Attachment-Epoch Decision Packet (Non-Binding)' "$PKT32M"); p32mrc=$?
[ "$p32mrc" -le 1 ] || err "F3.2m title scan failed"
[ "$p32mtitlehits" = 1 ] || err "F3.2m title differs or duplicates"
p32mwarninghits=$(grep -cFx -e 'EXPERIMENTAL — NO REAL FUNDS — NOT A WALLET' "$PKT32M"); p32mrc=$?
[ "$p32mrc" -le 1 ] || err "F3.2m safety-warning scan failed"
[ "$p32mwarninghits" = 1 ] || err "F3.2m safety warning differs or duplicates"
p32mquestionheadings=$(grep -cFx -e '## F32C-D11-Q-002 owner question — UNANSWERED' "$PKT32M"); p32mrc=$?
[ "$p32mrc" -le 1 ] || err "F3.2m question-heading scan failed"
[ "$p32mquestionheadings" = 1 ] || err "F3.2m must contain exactly one owner-question heading"
p32moptionheaders=$(grep -cFx -e '| Option ID | Selection | Recommendation | Disposition |' "$PKT32M"); p32mrc=$?
[ "$p32mrc" -le 1 ] || err "F3.2m option-table header scan failed"
[ "$p32moptionheaders" = 1 ] || err "F3.2m must contain exactly one option table"
grep '^| F32M-D11-Q002-OPT-' "$PKT32M" > "$tmpdir/p32m.options.act"; p32mrc=$?
[ "$p32mrc" -eq 0 ] || err "F3.2m option-row extraction failed"
cat > "$tmpdir/p32m.options.exp" <<'QK_F32M_OPTIONS_EOF' || err "F3.2m option fixture generation failed"
| F32M-D11-Q002-OPT-001 | PROPOSED — UNSELECTED | RECOMMENDED — NOT SELECTED | If separately selected later, whenever a later-selected export plan includes SD, require the exact physical SD attachment epoch to be present: perform bounded read-only preflight before review and approval; bind the session-scoped non-authenticating epoch and exact reviewed preflight facts to approval; removal or replacement ends that epoch and, where an active attempt exists, ends that attempt; permit no continuation or substitute-media output under that approval; and require a new medium to receive a new plan and full review and approval. Retry under an unchanged attachment epoch remains F32C-D11-Q-005-open. This disposition selects no media-identity mechanism and does not define the content of any filename or collision fact. |
| F32M-D11-Q002-OPT-002 | PROPOSED — UNSELECTED | NOT RECOMMENDED | If separately selected later, bind only the logical SD route and defer physical insertion until after signing. Any pre-signing media change still invalidates approval under QK-REQ-BND-003. Acquisition of postapproval media or preflight facts remains an explicit unresolved conflict requiring separately authorized QK-REQ-BND-003 reconciliation; temporal sequencing does not reconcile it. On removal or replacement after insertion, the epoch and any active attempt end; no replacement may continue the active attempt, no approval may silently carry over, and retry remains F32C-D11-Q-005-open. This disposition selects no media-identity mechanism, filename, collision policy, filesystem, commit primitive, or target behavior. |
| F32M-D11-Q002-OPT-003 | PROPOSED — UNSELECTED | NOT RECOMMENDED | Defer. F32C-D11-Q-002 remains unresolved; neither attachment-epoch binding nor logical-route binding is selected. |
QK_F32M_OPTIONS_EOF
cmp -s "$tmpdir/p32m.options.exp" "$tmpdir/p32m.options.act"; p32mrc=$?
[ "$p32mrc" -eq 0 ] || err "F3.2m exact three-option content, order, selection, or recommendation differs"
p32moptionrows=$(awk 'END {print NR+0}' "$tmpdir/p32m.options.act"); p32mrc=$?
[ "$p32mrc" -eq 0 ] || err "F3.2m option-row count failed"
[ "$p32moptionrows" = 3 ] || err "F3.2m must contain exactly three option rows"

for p32msource in \
  '| QK-REQ-BND-003 | Any intervening input, card, media, session, or state change after approval SHALL invalidate that approval before signing. | QK-DEC-009, QK-DEC-010 | QK-THR-017, QK-THR-019 | NONE (TOCTOU invariant) | QK-TST-PROP-006, QK-TST-PWR-004 | property, power-cut | Gate C |' \
  '- INHERITED FIXED REQUIREMENT: QK-REQ-BND-003 requires that any intervening input, card, media, session, or state change after approval invalidates approval before signing.' \
  '| F32C-D11-Q-002 | Must exact physical SD attachment epoch be present/approval-bound, or may logical SD route accept later insertion/replacement; reconcile broad media-change invalidation. | OWNER QUESTION — UNANSWERED — NO RESPONSE REQUESTED — NOT READY FOR SELECTION |' \
  '| F32C-D11-F-009 | short write or removal during write | end attempt and attachment epoch; residue may remain; Q-001 remains unresolved | no commit or completion; no continue after reinsertion | PROPOSED — UNSELECTED — TARGET EVIDENCE REQUIRED |' \
  '| F32C-D11-F-017 | media replacement | attachment epoch ends; Q-002 decides attempt-versus-approval invalidation | never treat replacement as the same medium | PROPOSED — UNSELECTED — TARGET EVIDENCE REQUIRED |' \
  '| F32C-D11-F-019 | retry request | same frozen bytes only if later selected; cross-attempt QR accumulation remains evidence-relevant | never re-sign or change plan | PROPOSED — UNSELECTED — TARGET EVIDENCE REQUIRED |' \
  'F32C-D11-Q-001 DISPOSITION: OWNER CLARIFICATION RECORDED — NON-ENACTING — D-11 NOT SELECTED.' \
  '- A later failure permits no automatic fallback, retry, or re-signing.' \
  '- The published F3.2d Q-001 clarification remains current and unchanged. Before route output begins, failure releases nothing; after output begins, a later failure stops further output, permits no complete-artifact, delivery, receipt, finalization, broadcast, atomicity, or durability claim, and permits no automatic fallback, retry, or re-signing. No route-output-begins boundary is selected.' \
  'This clarification defines no route-output-begins boundary and selects no D-11 construction, state, route, or route set.' \
  '- Its Q-001-unanswered wording records its historical status at the source base. This later record supplies the current owner clarification without editing or superseding the source packet.' \
  '- F32C-D11-Q-002 — Must exact physical SD attachment epoch be present/approval-bound, or may logical SD route accept later insertion/replacement; reconcile broad media-change invalidation. — UNANSWERED — NO RESPONSE RECORDED — NOT READY FOR SELECTION' \
  'The Q-001 “no retry” clarification does not answer Q-005 future-new-attempt policy. The Q-001 “no automatic fallback” clarification does not answer Q-003 or Q-004 route cardinality or outcomes.' \
  '| QK-LIM-PSBT-026 | Signed PSBT output bytes | qk-core output serialization | QK-THR-016 unbounded output | QK-REQ-PSBT-005, QK-REQ-TRN-007; QK-TST-DIFF-004 | Output size distribution; transport ceilings | OPEN — VALUE NOT AUTHORIZED IN F1 | OPEN | OD-05 |' \
  '| QK-LIM-PSBT-027 | Raw final-transaction output bytes | NONE — FORMER BOUNDARY RELATIONSHIP NON-OPERATIVE | HISTORICAL ONLY — FORMER QK-THR-016 RELATIONSHIP NON-OPERATIVE | NONE — FORMER REQUIREMENT AND TEST RELATIONSHIPS REMOVED | NONE — FORMER EVIDENCE RELATIONSHIP NON-OPERATIVE | NOT A VALUE — PERMANENT TOMBSTONE SENTINEL | TOMBSTONED — PERMANENT — NON-REUSABLE | NONE — FORMER OD-05 RELATIONSHIP NON-OPERATIVE |'; do
  p32msourcehits=$(grep -cFx -e "$p32msource" "$PKT32M"); p32mrc=$?
  [ "$p32mrc" -le 1 ] || err "F3.2m exact source-inventory scan failed"
  [ "$p32msourcehits" = 1 ] || err "F3.2m exact source-inventory line is missing, altered, or duplicated"
done

for p32mboundary in \
  'STATUS: OWNER-AUTHORIZED DECISION INPUT ONLY — NON-BINDING — NON-ENACTING — F32C-D11-Q-002 ONLY AND UNANSWERED — EXACTLY THREE DISPOSITIONS PROPOSED — UNSELECTED — OPTION 1 RECOMMENDED AS ANALYSIS ONLY — NOT SELECTED — F3.2D Q-001 CLARIFICATION PRESERVED — F32C-D11-Q-003 THROUGH Q-012 UNANSWERED — D-11 EVIDENCE/CONSTRUCTION-BLOCKED AND NOT SELECTED — PSBT PROFILE NOT ACCEPTED — QK-LIM-PSBT-027 SOLE PERMANENT NON-REUSABLE TOMBSTONE — QK-LIM-PSBT-026 LIVE AND OPEN — ALL GATES OPEN — NO IMPLEMENTATION OR MEDIA I/O — LOCAL AND UNPUBLISHED.' \
  'The recommendation is analysis only, not an owner answer or selection.' \
  'The three dispositions are finite and mutually exclusive at approval time: physical attachment epoch bound, no physical attachment epoch bound with first insertion after signing, or no disposition. Recommendation is analysis only. There is no hybrid, fourth option, implicit default, answer, approval, or selection.' \
  'Preflight facts are observations, not selected filenames, collision policy, authentication, authority, or stable physical-media identity. No stable physical-media identity, identifier, hash, serialization, authenticator, filename, collision resolution, media-identity mechanism, filesystem, writer, commit primitive, target behavior, atomicity, durability, receipt, or residue-absence claim is selected or defined.' \
  '`F32M-D11-Q002-OPT-002` does not reconcile, waive, or amend `QK-REQ-BND-003`. Neither option answers unchanged-epoch retry or `F32C-D11-Q-005`, `F32C-D11-Q-003` through `F32C-D11-Q-012`, D-09, or any other excluded item.' \
  'Under F32M-D11-Q002-OPT-001 or F32M-D11-Q002-OPT-002, removal or replacement cannot continue an active attempt, and no replacement medium receives silent approval carry-over. F32M-D11-Q002-OPT-003 selects neither rule because it defers F32C-D11-Q-002. Nothing in this packet selects same-versus-distinct input/output media, route set, completion, retry, filename/collision, visibility/commit/orphan, QR self-check, signature insertion, serialization, hashing, authentication, writer, atomicity, durability, receipt, or residue policy.' \
  'END OF PACKET — F3.2m D-11 Q-002 DECISION INPUT ONLY — NON-BINDING — NON-ENACTING — F32C-D11-Q-002 UNANSWERED — EXACTLY THREE DISPOSITIONS PROPOSED — UNSELECTED — NO OWNER SELECTION — D-11 NOT SELECTED — LOCAL AND UNPUBLISHED.'; do
  p32mboundaryhits=$(grep -cFx -e "$p32mboundary" "$PKT32M"); p32mrc=$?
  [ "$p32mrc" -le 1 ] || err "F3.2m boundary statement scan failed"
  [ "$p32mboundaryhits" = 1 ] || err "F3.2m required boundary statement is missing, altered, or duplicated"
done
forbid "F3.2m packet reintroduces an overbroad all-dispositions attempt rule" \
  -F 'under any disposition' "$PKT32M"
forbid "F3.2m packet conflates prohibited actions with a retry/re-signing claim" \
  -F 'retry, or re-signing claim' "$PKT32M"

while IFS=' ' read -r p32mprotected p32mprotectedblob; do
  git --no-optional-locks rev-parse "$p32mbase:$p32mprotected" > "$tmpdir/p32m.protected.base.act" 2>/dev/null; p32mrc=$?
  [ "$p32mrc" -eq 0 ] || err "F3.2m protected base blob lookup failed for $p32mprotected"
  printf '%s\n' "$p32mprotectedblob" > "$tmpdir/p32m.protected.exp" || err "F3.2m protected blob fixture failed"
  cmp -s "$tmpdir/p32m.protected.exp" "$tmpdir/p32m.protected.base.act"; p32mrc=$?
  [ "$p32mrc" -eq 0 ] || err "F3.2m protected base blob differs for $p32mprotected"
  git --no-optional-locks hash-object -- "$p32mprotected" > "$tmpdir/p32m.protected.active.act"; p32mrc=$?
  [ "$p32mrc" -eq 0 ] || err "F3.2m active protected blob scan failed for $p32mprotected"
  cmp -s "$tmpdir/p32m.protected.exp" "$tmpdir/p32m.protected.active.act"; p32mrc=$?
  [ "$p32mrc" -eq 0 ] || err "F3.2m active protected blob differs for $p32mprotected"
done <<'QK_F32M_PROTECTED_BLOBS_EOF'
ARCHITECTURE.md 71e3f95adf541560ff5d067030f78dfd088d1ec1
docs/MATURITY-GATES.md 5b6b67b7ec44f1460f31a02803e6f6db4f9386d1
docs/OPEN-DECISIONS.md a292d97308ae9a36d5bb5c4c48a83905bb06c073
docs/REQUIREMENTS.md 2cf8a34aa5621dcea114e2d5ec3dabc2b79aef84
docs/RESOURCE-BUDGETS.md 09815b0a75c26a118f80c5cec008e695d319900b
docs/TEST-ARCHITECTURE.md ecb3867ca2842f6d011288d3dcd94d2b1997e516
docs/THREAT-MODEL.md 9bb66dc93d452e04284e13026814ed7322fb25b0
docs/f3/F3.2C-D11-MEDIA-WRITE-LIFECYCLE-CONSTRUCTION-PACKET.md b4594210975940df71b0e941841320d11defaa4c
docs/f3/F3.2D-D11-Q001-OWNER-CLARIFICATION-RECORD.md a996a6d7c2bfa3a15109085475868410fe354422
docs/f3/F3.2J-QK-LIM-PSBT-027-EXACT-TOMBSTONE-CONSTRUCTION-PACKET.md b1c2153f5f89a0e1d44d62a09921251e225c0d87
docs/f3/F3.2K-QK-LIM-PSBT-027-EXACT-CONSTRUCTION-OWNER-DIRECTION-RECORD.md 5b05d62776c65bfaf5ec41ab39108bc0531b7944
docs/f3/PSBT-V0-REVIEW-PROFILE-DRAFT.md 877866e5a3636bdfb7015d715e048ccfad63d939
QK_F32M_PROTECTED_BLOBS_EOF
for p32mbaseverifier in \
  "tools/verify-host-boundary.sh|4d5041591bd28c665c717ddbdfc0dc54ef345680" \
  "tools/verify-current-stage.sh|ee144c20c76283d8565d7d031145be372bae5375"; do
  p32mverifierpath=${p32mbaseverifier%%|*}
  p32mverifierblob=${p32mbaseverifier#*|}
  git --no-optional-locks rev-parse "$p32mbase:$p32mverifierpath" > "$tmpdir/p32m.verifier.base.act" 2>/dev/null; p32mrc=$?
  [ "$p32mrc" -eq 0 ] || err "F3.2m base verifier blob lookup failed for $p32mverifierpath"
  printf '%s\n' "$p32mverifierblob" > "$tmpdir/p32m.verifier.base.exp" || err "F3.2m base verifier fixture failed"
  cmp -s "$tmpdir/p32m.verifier.base.exp" "$tmpdir/p32m.verifier.base.act"; p32mrc=$?
  [ "$p32mrc" -eq 0 ] || err "F3.2m base verifier blob differs for $p32mverifierpath"
done

p32mtombstones=$(grep -cF -e '| TOMBSTONED — PERMANENT — NON-REUSABLE |' docs/RESOURCE-BUDGETS.md); p32mrc=$?
[ "$p32mrc" -le 1 ] || err "F3.2m tombstone-row count failed"
[ "$p32mtombstones" = 1 ] || err "F3.2m must preserve exactly one permanent non-reusable tombstone"
p32mrow026hits=$(grep -cFx -e '| QK-LIM-PSBT-026 | Signed PSBT output bytes | qk-core output serialization | QK-THR-016 unbounded output | QK-REQ-PSBT-005, QK-REQ-TRN-007; QK-TST-DIFF-004 | Output size distribution; transport ceilings | OPEN — VALUE NOT AUTHORIZED IN F1 | OPEN | OD-05 |' docs/RESOURCE-BUDGETS.md); p32mrc=$?
[ "$p32mrc" -le 1 ] || err "F3.2m QK-LIM-PSBT-026 scan failed"
[ "$p32mrow026hits" = 1 ] || err "F3.2m changed or duplicated live OPEN QK-LIM-PSBT-026"
p32mdiffstatus=$(grep -cF -e '| QK-TST-DIFF-004 ' docs/TEST-ARCHITECTURE.md); p32mrc=$?
[ "$p32mrc" -le 1 ] || err "F3.2m QK-TST-DIFF-004 row scan failed"
[ "$p32mdiffstatus" = 1 ] || err "F3.2m changed or duplicated QK-TST-DIFF-004"
p32mplanned=$(grep -F -e '| QK-TST-DIFF-004 ' docs/TEST-ARCHITECTURE.md > "$tmpdir/p32m.diff004"); p32mrc=$?
[ "$p32mrc" -eq 0 ] || err "F3.2m QK-TST-DIFF-004 extraction failed"
p32mplannedhits=$(grep -cF -e '| PLANNED — NOT RUN |' "$tmpdir/p32m.diff004"); p32mrc=$?
[ "$p32mrc" -le 1 ] || err "F3.2m QK-TST-DIFF-004 status scan failed"
[ "$p32mplannedhits" = 1 ] || err "F3.2m QK-TST-DIFF-004 is not PLANNED — NOT RUN"
p32mgatehits=$(grep -cF -e 'ALL GATES OPEN' docs/RESOURCE-BUDGETS.md); p32mrc=$?
[ "$p32mrc" -le 1 ] || err "F3.2m ALL GATES OPEN scan failed"
[ "$p32mgatehits" = 1 ] || err "F3.2m ALL GATES OPEN state differs or duplicates"

iconv -f UTF-8 -t UTF-8 "$PKT32M" > "$tmpdir/p32m.utf8" 2> "$tmpdir/p32m.iconv.err"; p32mrc=$?
[ "$p32mrc" -eq 0 ] || err "$PKT32M is not strict UTF-8"
[ -s "$tmpdir/p32m.utf8" ] || err "$PKT32M UTF-8 validation produced empty output"
cmp -s "$PKT32M" "$tmpdir/p32m.utf8"; p32mrc=$?
[ "$p32mrc" -eq 0 ] || err "$PKT32M UTF-8 validation changed bytes"
tail -c 1 "$PKT32M" > "$tmpdir/p32m.last.raw"; p32mrc=$?
[ "$p32mrc" -eq 0 ] || err "$PKT32M final-byte read failed"
od -An -tuC "$tmpdir/p32m.last.raw" > "$tmpdir/p32m.last.od"; p32mrc=$?
[ "$p32mrc" -eq 0 ] || err "$PKT32M final-byte scan failed"
tr -d '[:space:]' < "$tmpdir/p32m.last.od" > "$tmpdir/p32m.last.norm"; p32mrc=$?
[ "$p32mrc" -eq 0 ] || err "$PKT32M final-byte normalization failed"
p32mlast=$(cat "$tmpdir/p32m.last.norm"); p32mrc=$?
[ "$p32mrc" -eq 0 ] || err "$PKT32M final-byte read-back failed"
[ "$p32mlast" = 10 ] || err "$PKT32M must end in exact LF"
tail -c 2 "$PKT32M" > "$tmpdir/p32m.last2.raw"; p32mrc=$?
[ "$p32mrc" -eq 0 ] || err "$PKT32M final-two-byte read failed"
printf '\n\n' > "$tmpdir/p32m.double-lf" || err "$PKT32M double-LF fixture generation failed"
cmp -s "$tmpdir/p32m.double-lf" "$tmpdir/p32m.last2.raw"; p32mrc=$?
[ "$p32mrc" -eq 1 ] || err "$PKT32M must not end in double LF or cmp failed (exit $p32mrc)"
od -An -tx1 "$PKT32M" > "$tmpdir/p32m.bytes.raw"; p32mrc=$?
[ "$p32mrc" -eq 0 ] || err "$PKT32M byte scan failed"
tr 'A-F' 'a-f' < "$tmpdir/p32m.bytes.raw" > "$tmpdir/p32m.bytes"; p32mrc=$?
[ "$p32mrc" -eq 0 ] || err "$PKT32M byte normalization failed"
p32mbad=$(awk 'BEGIN {bad=0; p2=""; p1=""} {for(i=1;i<=NF;i++){b=$i; if(b=="00"||b=="0d")bad++; seq=p2 p1 b; if(seq=="efbbbf"||seq=="e2808e"||seq=="e2808f"||seq=="e280aa"||seq=="e280ab"||seq=="e280ac"||seq=="e280ad"||seq=="e280ae"||seq=="e281a6"||seq=="e281a7"||seq=="e281a8"||seq=="e281a9")bad++; p2=p1; p1=b}} END {print bad+0}' "$tmpdir/p32m.bytes"); p32mrc=$?
[ "$p32mrc" -eq 0 ] || err "$PKT32M control/bidi byte scan failed"
[ "$p32mbad" = 0 ] || err "$PKT32M contains BOM, NUL, CR, LRM/RLM, or bidi controls"
forbid "$PKT32M contains a tab, trailing whitespace, HTML comment, hidden link definition, fence, blockquote, URL, or email material" \
  -E '	|[[:blank:]]$|<!--|-->|^\[[^]]+\]:|^```|^[[:space:]]*>|https?://|[[:alnum:]_.+-]+@[[:alnum:].-]+' "$PKT32M"
forbid "$PKT32M contains PSBT or key payload material" -E '[7]0736274|[c]HNidP|[x]pub|[x]prv' "$PKT32M"
forbid "$PKT32M contains suspicious 41+ hex material" -E '[0-9a-fA-F]{41,}' "$PKT32M"

# F3.2n D-11 Q-002 physical SD attachment-epoch owner-direction record.
# F3.2m is frozen above at its exact published C. This is the sole
# HEAD-driven stage block and accepts only the exact finite B or C state.
REC32N=docs/f3/F3.2N-D11-Q002-SD-ATTACHMENT-EPOCH-OWNER-DIRECTION-RECORD.md
[ -f "$REC32N" ] || err "$REC32N missing"
p32nbase=f41e26799d0c4522b91e1de72d27cf473116b3ab
p32ntree=9ae24ea3278252b0a0f6703d2cbc381d59859dcf
p32na=d3a4f3bec5902d2e2155647a27ffe34bfa233bee
p32ndlogbaseblob=99384f6cd5eedd37488e0c12d865737217f88b6c
p32ndlogablob=84f8fd26b311fe3e084b01c932ae3ee7469c49a3
p32nrecordblob=01f7fb3140bcf69c31719a996c7a4c7ddd2394ab
p32npacketblob=11714544ea89b3475d65a8a5634b7fdab65f5972

p32nprovenanceblocks=$(awk '
  /^# The exact F3[.]2l C snapshot and F3[.]2m C stage are published and immutable[.]$/ { state=1; next }
  state == 1 && /^# F3[.]2m remains non-binding and non-enacting; its LOCAL AND UNPUBLISHED$/ { state=2; next }
  state == 2 && /^# packet wording is preserved only as historical preparation-time text[.]$/ { found++; state=0; next }
  { state=0 }
  END { print found+0 }' tools/verify-host-boundary.sh); p32nrc=$?
[ "$p32nrc" -eq 0 ] || err "F3.2n F3.2m provenance-block scan failed"
[ "$p32nprovenanceblocks" = 1 ] || err "F3.2n truthful F3.2m provenance block differs, duplicates, or is non-contiguous"
forbid "F3.2n host verifier restores stale F3.2m present-tense provenance wording" \
  -E '^# The exact F3[.]2l C snapshot is published and immutable[.] F3[.]2m is a$' tools/verify-host-boundary.sh
forbid "F3.2n host verifier restores stale F3.2m local/unpublished provenance wording" \
  -E '^# local[/]unpublished, non-binding, non-enacting decision input only[.]$' tools/verify-host-boundary.sh

p32nbranch=$(git --no-optional-locks symbolic-ref --quiet --short HEAD 2>/dev/null); p32nrc=$?
[ "$p32nrc" -eq 0 ] || err "F3.2n checked-out branch cannot be resolved"
[ "$p32nbranch" = main ] || err "F3.2n checked-out branch is not main"
p32nhead=$(git --no-optional-locks rev-parse "HEAD^{commit}" 2>/dev/null); p32nrc=$?
[ "$p32nrc" -eq 0 ] || err "F3.2n HEAD does not resolve as a commit"
git --no-optional-locks log -1 --format=%B "$p32nhead" > "$tmpdir/p32n.head.msg.act"; p32nrc=$?
[ "$p32nrc" -eq 0 ] || err "F3.2n HEAD message read failed"
printf '%s\n\n' 'docs(f3): record non-enacting F3.2n D-11 Q-002 physical SD attachment-epoch direction' \
  > "$tmpdir/p32n.b.msg.exp" || err "F3.2n B message fixture failed"
printf '%s\n\n' 'chore(verify): bind F3.2n D-11 Q-002 physical SD attachment-epoch owner-direction stage' \
  > "$tmpdir/p32n.c.msg.exp" || err "F3.2n C message fixture failed"
cmp -s "$tmpdir/p32n.b.msg.exp" "$tmpdir/p32n.head.msg.act"; p32nbheadrc=$?
cmp -s "$tmpdir/p32n.c.msg.exp" "$tmpdir/p32n.head.msg.act"; p32ncheadrc=$?
p32nstage=invalid
p32nb=$p32nhead
p32nc=$p32nhead
case "$p32nbheadrc:$p32ncheadrc" in
  0:1)
    p32nstage=b
    p32nb=$p32nhead
    ;;
  1:0)
    p32nstage=c
    p32nc=$p32nhead
    p32nb=$(git --no-optional-locks rev-parse "$p32nc^" 2>/dev/null); p32nrc=$?
    [ "$p32nrc" -eq 0 ] || err "F3.2n final C parent cannot be derived as B"
    ;;
  *)
    err "F3.2n HEAD is neither exact intermediate B nor exact final C by bodyless message"
    ;;
esac

p32n_single_parent() {
  p32nspcommit=$1
  p32nsplabel=$2
  git --no-optional-locks rev-list --no-walk --parents "$p32nspcommit" \
    > "$tmpdir/p32n.single-parent"; p32nsprc=$?
  [ "$p32nsprc" -eq 0 ] || err "F3.2n $p32nsplabel parent enumeration failed"
  p32nspfields=$(awk 'NR == 1 {print NF+0} END {if (NR != 1) exit 1}' \
    "$tmpdir/p32n.single-parent"); p32nsprc=$?
  [ "$p32nsprc" -eq 0 ] || err "F3.2n $p32nsplabel parent count failed"
  [ "$p32nspfields" = 2 ] || err "F3.2n $p32nsplabel is not a single-parent commit"
}

p32n_single_parent "$p32na" "A"
p32naparent=$(git --no-optional-locks rev-parse "$p32na^" 2>/dev/null); p32nrc=$?
[ "$p32nrc" -eq 0 ] || err "F3.2n A parent cannot be resolved"
[ "$p32naparent" = "$p32nbase" ] || err "F3.2n A parent differs from exact published base"
git --no-optional-locks log -1 --format=%B "$p32na" > "$tmpdir/p32n.a.msg.act"; p32nrc=$?
[ "$p32nrc" -eq 0 ] || err "F3.2n A message read failed"
printf '%s\n\n' 'docs: authorize F3.2n D-11 Q-002 physical SD attachment-epoch owner direction' \
  > "$tmpdir/p32n.a.msg.exp" || err "F3.2n A message fixture failed"
cmp -s "$tmpdir/p32n.a.msg.exp" "$tmpdir/p32n.a.msg.act"; p32nrc=$?
[ "$p32nrc" -eq 0 ] || err "F3.2n A full message differs or contains a body"
git --no-optional-locks diff-tree --no-commit-id --name-only -r "$p32na" > "$tmpdir/p32n.a.paths.act"; p32nrc=$?
[ "$p32nrc" -eq 0 ] || err "F3.2n A path enumeration failed"
printf '%s\n' docs/DECISION-LOG.md > "$tmpdir/p32n.a.paths.exp" || err "F3.2n A path fixture failed"
cmp -s "$tmpdir/p32n.a.paths.exp" "$tmpdir/p32n.a.paths.act"; p32nrc=$?
[ "$p32nrc" -eq 0 ] || err "F3.2n A changes a path other than docs/DECISION-LOG.md"

p32n_single_parent "$p32nb" "B"
p32nbparent=$(git --no-optional-locks rev-parse "$p32nb^" 2>/dev/null); p32nrc=$?
[ "$p32nrc" -eq 0 ] || err "F3.2n B parent cannot be resolved"
[ "$p32nbparent" = "$p32na" ] || err "F3.2n B parent differs from exact A"
git --no-optional-locks log -1 --format=%B "$p32nb" > "$tmpdir/p32n.b.msg.act"; p32nrc=$?
[ "$p32nrc" -eq 0 ] || err "F3.2n B message read failed"
cmp -s "$tmpdir/p32n.b.msg.exp" "$tmpdir/p32n.b.msg.act"; p32nrc=$?
[ "$p32nrc" -eq 0 ] || err "F3.2n B full message differs or contains a body"
git --no-optional-locks diff-tree --no-commit-id --name-only -r "$p32nb" > "$tmpdir/p32n.b.paths.raw"; p32nrc=$?
[ "$p32nrc" -eq 0 ] || err "F3.2n B path enumeration failed"
LC_ALL=C sort "$tmpdir/p32n.b.paths.raw" > "$tmpdir/p32n.b.paths.act" || err "F3.2n B path sort failed"
cat > "$tmpdir/p32n.b.paths.exp" <<'QK_HOST_F32N_B_PATHS_EOF'
docs/f3/F3.2N-D11-Q002-SD-ATTACHMENT-EPOCH-OWNER-DIRECTION-RECORD.md
tools/verify-host-boundary.sh
QK_HOST_F32N_B_PATHS_EOF
cmp -s "$tmpdir/p32n.b.paths.exp" "$tmpdir/p32n.b.paths.act"; p32nrc=$?
[ "$p32nrc" -eq 0 ] || err "F3.2n B path set differs from exact record/host pair"

if [ "$p32nstage" = c ]; then
  p32n_single_parent "$p32nc" "C"
  p32ncparent=$(git --no-optional-locks rev-parse "$p32nc^" 2>/dev/null); p32nrc=$?
  [ "$p32nrc" -eq 0 ] || err "F3.2n C parent cannot be resolved"
  [ "$p32ncparent" = "$p32nb" ] || err "F3.2n C parent differs from exact B"
  git --no-optional-locks log -1 --format=%B "$p32nc" > "$tmpdir/p32n.c.msg.act"; p32nrc=$?
  [ "$p32nrc" -eq 0 ] || err "F3.2n C message read failed"
  cmp -s "$tmpdir/p32n.c.msg.exp" "$tmpdir/p32n.c.msg.act"; p32nrc=$?
  [ "$p32nrc" -eq 0 ] || err "F3.2n C full message differs or contains a body"
  git --no-optional-locks diff-tree --no-commit-id --name-only -r "$p32nc" > "$tmpdir/p32n.c.paths.act"; p32nrc=$?
  [ "$p32nrc" -eq 0 ] || err "F3.2n C path enumeration failed"
  printf '%s\n' tools/verify-current-stage.sh > "$tmpdir/p32n.c.paths.exp" || err "F3.2n C path fixture failed"
  cmp -s "$tmpdir/p32n.c.paths.exp" "$tmpdir/p32n.c.paths.act"; p32nrc=$?
  [ "$p32nrc" -eq 0 ] || err "F3.2n C changes a path other than tools/verify-current-stage.sh"
fi

p32nahead=$(git --no-optional-locks rev-list --count "$p32nbase..$p32nhead" 2>/dev/null); p32nrc=$?
[ "$p32nrc" -eq 0 ] || err "F3.2n ahead-count failed"
p32nbehind=$(git --no-optional-locks rev-list --count "$p32nhead..$p32nbase" 2>/dev/null); p32nrc=$?
[ "$p32nrc" -eq 0 ] || err "F3.2n behind-count failed"
[ "$p32nbehind" = 0 ] || err "F3.2n HEAD is behind or diverged from exact base"
case "$p32nstage:$p32nahead" in
  b:2|c:3) : ;;
  *) err "F3.2n stage/ahead count differs: stage=$p32nstage ahead=$p32nahead" ;;
esac
p32nmerges=$(git --no-optional-locks rev-list --merges "$p32nbase..$p32nhead" 2>/dev/null); p32nrc=$?
[ "$p32nrc" -eq 0 ] || err "F3.2n merge enumeration failed"
[ -z "$p32nmerges" ] || err "F3.2n chain contains a merge commit"

git --no-optional-locks diff --name-only "$p32nbase" "$p32nhead" > "$tmpdir/p32n.paths.raw"; p32nrc=$?
[ "$p32nrc" -eq 0 ] || err "F3.2n cumulative path enumeration failed"
LC_ALL=C sort "$tmpdir/p32n.paths.raw" > "$tmpdir/p32n.paths.act" || err "F3.2n cumulative path sort failed"
if [ "$p32nstage" = b ]; then
  cat > "$tmpdir/p32n.paths.exp" <<'QK_HOST_F32N_STAGE_B_PATHS_EOF'
docs/DECISION-LOG.md
docs/f3/F3.2N-D11-Q002-SD-ATTACHMENT-EPOCH-OWNER-DIRECTION-RECORD.md
tools/verify-host-boundary.sh
QK_HOST_F32N_STAGE_B_PATHS_EOF
else
  cat > "$tmpdir/p32n.paths.exp" <<'QK_HOST_F32N_STAGE_C_PATHS_EOF'
docs/DECISION-LOG.md
docs/f3/F3.2N-D11-Q002-SD-ATTACHMENT-EPOCH-OWNER-DIRECTION-RECORD.md
tools/verify-current-stage.sh
tools/verify-host-boundary.sh
QK_HOST_F32N_STAGE_C_PATHS_EOF
fi
cmp -s "$tmpdir/p32n.paths.exp" "$tmpdir/p32n.paths.act"; p32nrc=$?
[ "$p32nrc" -eq 0 ] || err "F3.2n cumulative path set differs from exact stage partition"

git --no-optional-locks rev-parse "$p32nbase^{tree}" > "$tmpdir/p32n.base.tree.act" 2>/dev/null; p32nrc=$?
[ "$p32nrc" -eq 0 ] || err "F3.2n base tree lookup failed"
printf '%s\n' "$p32ntree" > "$tmpdir/p32n.base.tree.exp" || err "F3.2n base tree fixture failed"
cmp -s "$tmpdir/p32n.base.tree.exp" "$tmpdir/p32n.base.tree.act"; p32nrc=$?
[ "$p32nrc" -eq 0 ] || err "F3.2n base tree differs"
for p32ntreecheck in \
  "$p32na|100644|$p32ndlogablob|docs/DECISION-LOG.md" \
  "$p32nb|100644|$p32nrecordblob|$REC32N"; do
  p32ntreecommit=${p32ntreecheck%%|*}
  p32ntreerest=${p32ntreecheck#*|}
  p32ntreemode=${p32ntreerest%%|*}
  p32ntreerest=${p32ntreerest#*|}
  p32ntreeblob=${p32ntreerest%%|*}
  p32ntreepath=${p32ntreerest#*|}
  git --no-optional-locks ls-tree "$p32ntreecommit" -- "$p32ntreepath" > "$tmpdir/p32n.tree.act"; p32nrc=$?
  [ "$p32nrc" -eq 0 ] || err "F3.2n tree lookup failed for $p32ntreepath"
  printf '%s blob %s\t%s\n' "$p32ntreemode" "$p32ntreeblob" "$p32ntreepath" > "$tmpdir/p32n.tree.exp" \
    || err "F3.2n tree fixture failed for $p32ntreepath"
  cmp -s "$tmpdir/p32n.tree.exp" "$tmpdir/p32n.tree.act"; p32nrc=$?
  [ "$p32nrc" -eq 0 ] || err "F3.2n tree entry differs for $p32ntreepath"
done
git --no-optional-locks ls-tree "$p32nb" -- tools/verify-host-boundary.sh > "$tmpdir/p32n.host.tree"; p32nrc=$?
[ "$p32nrc" -eq 0 ] || err "F3.2n B host-verifier tree lookup failed"
p32nhostmode=$(awk 'NR == 1 {print $1} END {if (NR != 1) exit 1}' "$tmpdir/p32n.host.tree"); p32nrc=$?
[ "$p32nrc" -eq 0 ] || err "F3.2n B host-verifier mode read failed"
[ "$p32nhostmode" = 100755 ] || err "F3.2n B host-verifier mode differs"
if [ "$p32nstage" = c ]; then
  git --no-optional-locks ls-tree "$p32nc" -- tools/verify-current-stage.sh > "$tmpdir/p32n.current.tree"; p32nrc=$?
  [ "$p32nrc" -eq 0 ] || err "F3.2n C current-stage tree lookup failed"
  p32ncurrentmode=$(awk 'NR == 1 {print $1} END {if (NR != 1) exit 1}' "$tmpdir/p32n.current.tree"); p32nrc=$?
  [ "$p32nrc" -eq 0 ] || err "F3.2n C current-stage mode read failed"
  [ "$p32ncurrentmode" = 100755 ] || err "F3.2n C current-stage mode differs"
fi

git --no-optional-locks rev-parse "$p32nbase:docs/DECISION-LOG.md" > "$tmpdir/p32n.dlog.base.blob.act" 2>/dev/null; p32nrc=$?
[ "$p32nrc" -eq 0 ] || err "F3.2n base Decision Log blob lookup failed"
printf '%s\n' "$p32ndlogbaseblob" > "$tmpdir/p32n.dlog.base.blob.exp" || err "F3.2n base Decision Log blob fixture failed"
cmp -s "$tmpdir/p32n.dlog.base.blob.exp" "$tmpdir/p32n.dlog.base.blob.act"; p32nrc=$?
[ "$p32nrc" -eq 0 ] || err "F3.2n base Decision Log blob differs"
git --no-optional-locks rev-parse "$p32na:docs/DECISION-LOG.md" > "$tmpdir/p32n.dlog.a.blob.act" 2>/dev/null; p32nrc=$?
[ "$p32nrc" -eq 0 ] || err "F3.2n A Decision Log blob lookup failed"
printf '%s\n' "$p32ndlogablob" > "$tmpdir/p32n.dlog.a.blob.exp" || err "F3.2n A Decision Log blob fixture failed"
cmp -s "$tmpdir/p32n.dlog.a.blob.exp" "$tmpdir/p32n.dlog.a.blob.act"; p32nrc=$?
[ "$p32nrc" -eq 0 ] || err "F3.2n A Decision Log blob differs"
git --no-optional-locks rev-parse "$p32nhead:docs/DECISION-LOG.md" > "$tmpdir/p32n.dlog.head.blob.act" 2>/dev/null; p32nrc=$?
[ "$p32nrc" -eq 0 ] || err "F3.2n HEAD Decision Log blob lookup failed"
cmp -s "$tmpdir/p32n.dlog.a.blob.exp" "$tmpdir/p32n.dlog.head.blob.act"; p32nrc=$?
[ "$p32nrc" -eq 0 ] || err "F3.2n Decision Log changed after exact A"
git --no-optional-locks show "$p32nbase:docs/DECISION-LOG.md" > "$tmpdir/p32n.dlog.base" 2>/dev/null; p32nrc=$?
[ "$p32nrc" -eq 0 ] || err "F3.2n base Decision Log read failed"
git --no-optional-locks show "$p32na:docs/DECISION-LOG.md" > "$tmpdir/p32n.dlog.a" 2>/dev/null; p32nrc=$?
[ "$p32nrc" -eq 0 ] || err "F3.2n A Decision Log read failed"
wc -c < "$tmpdir/p32n.dlog.base" > "$tmpdir/p32n.dlog.bytes.raw"; p32nrc=$?
[ "$p32nrc" -eq 0 ] || err "F3.2n base Decision Log byte count failed"
tr -d '[:space:]' < "$tmpdir/p32n.dlog.bytes.raw" > "$tmpdir/p32n.dlog.bytes"; p32nrc=$?
[ "$p32nrc" -eq 0 ] || err "F3.2n Decision Log byte-count normalization failed"
p32nbasebytes=$(cat "$tmpdir/p32n.dlog.bytes"); p32nrc=$?
[ "$p32nrc" -eq 0 ] || err "F3.2n Decision Log byte-count read failed"
case $p32nbasebytes in ''|*[!0-9]*) err "F3.2n Decision Log base byte count is non-numeric" ;; esac
dd if="$tmpdir/p32n.dlog.a" bs=1 count="$p32nbasebytes" > "$tmpdir/p32n.dlog.prefix" 2> "$tmpdir/p32n.dlog.dd.err"; p32nrc=$?
[ "$p32nrc" -eq 0 ] || err "F3.2n Decision Log prefix read failed"
cmp -s "$tmpdir/p32n.dlog.base" "$tmpdir/p32n.dlog.prefix"; p32nrc=$?
[ "$p32nrc" -eq 0 ] || err "F3.2n Decision Log is not an exact append"
p32nauthhits=$(grep -cFx -e '### QK-AUTH-F3.2N-D11-Q002-SD-ATTACHMENT-EPOCH-DIR-REC-001 — F3.2n D-11 Q-002 physical SD attachment-epoch owner-direction record preparation authorization' "$tmpdir/p32n.dlog.a"); p32nrc=$?
[ "$p32nrc" -le 1 ] || err "F3.2n authorization heading scan failed"
[ "$p32nauthhits" = 1 ] || err "F3.2n authorization heading differs or duplicates"

git --no-optional-locks hash-object -- "$REC32N" > "$tmpdir/p32n.record.blob.act"; p32nrc=$?
[ "$p32nrc" -eq 0 ] || err "F3.2n record blob scan failed"
printf '%s\n' "$p32nrecordblob" > "$tmpdir/p32n.record.blob.exp" || err "F3.2n record blob fixture failed"
cmp -s "$tmpdir/p32n.record.blob.exp" "$tmpdir/p32n.record.blob.act"; p32nrc=$?
[ "$p32nrc" -eq 0 ] || err "F3.2n record whole blob differs"
git --no-optional-locks hash-object -- "$PKT32M" > "$tmpdir/p32n.packet.blob.act"; p32nrc=$?
[ "$p32nrc" -eq 0 ] || err "F3.2n source packet blob scan failed"
printf '%s\n' "$p32npacketblob" > "$tmpdir/p32n.packet.blob.exp" || err "F3.2n source packet blob fixture failed"
cmp -s "$tmpdir/p32n.packet.blob.exp" "$tmpdir/p32n.packet.blob.act"; p32nrc=$?
[ "$p32nrc" -eq 0 ] || err "F3.2n immutable F3.2m source packet differs"

sed -n '/^### QK-AUTH-F3\.2N-D11-Q002-SD-ATTACHMENT-EPOCH-DIR-REC-001 /,$p' "$tmpdir/p32n.dlog.a" > "$tmpdir/p32n.dlog.section"; p32nrc=$?
[ "$p32nrc" -eq 0 ] || err "F3.2n Decision Log section extraction failed"
sed -n '/^- \*\*Owner words exactly (literal six-paragraph block follows):\*\*$/,/^- \*\*Published source boundary:\*\*/p' \
  "$tmpdir/p32n.dlog.section" > "$tmpdir/p32n.dlog.owner.framed"; p32nrc=$?
[ "$p32nrc" -eq 0 ] || err "F3.2n Decision Log owner block extraction failed"
sed -n '/^## Owner words exactly$/,/^## Exact direction map$/p' "$REC32N" > "$tmpdir/p32n.record.owner.framed"; p32nrc=$?
[ "$p32nrc" -eq 0 ] || err "F3.2n record owner block extraction failed"
[ "$(awk 'END {print NR+0}' "$tmpdir/p32n.dlog.owner.framed")" = 15 ] \
  || err "F3.2n Decision Log owner block framing or paragraph breaks differ"
[ "$(awk 'END {print NR+0}' "$tmpdir/p32n.record.owner.framed")" = 15 ] \
  || err "F3.2n record owner block framing or paragraph breaks differ"
sed -n '3,13p' "$tmpdir/p32n.dlog.owner.framed" > "$tmpdir/p32n.dlog.owner"; p32nrc=$?
[ "$p32nrc" -eq 0 ] || err "F3.2n Decision Log owner transcript deframing failed"
sed -n '3,13p' "$tmpdir/p32n.record.owner.framed" > "$tmpdir/p32n.record.owner"; p32nrc=$?
[ "$p32nrc" -eq 0 ] || err "F3.2n record owner transcript deframing failed"
cmp -s "$tmpdir/p32n.dlog.owner" "$tmpdir/p32n.record.owner"; p32nrc=$?
[ "$p32nrc" -eq 0 ] || err "F3.2n six-paragraph owner transcript differs between exact A and record"

sed -n 's/^| F32M-D11-Q002-OPT-001 | PROPOSED — UNSELECTED | RECOMMENDED — NOT SELECTED | \(.*\) |$/\1/p' \
  "$PKT32M" > "$tmpdir/p32n.selected.packet"; p32nrc=$?
[ "$p32nrc" -eq 0 ] || err "F3.2n selected source-cell extraction failed"
[ "$(awk 'END {print NR+0}' "$tmpdir/p32n.selected.packet")" = 1 ] \
  || err "F3.2n selected source-cell extraction is not exactly one line"
sed -n '/^## Selected option text exactly$/,/^## Conditional future direction$/p' "$REC32N" \
  > "$tmpdir/p32n.selected.record.framed"; p32nrc=$?
[ "$p32nrc" -eq 0 ] || err "F3.2n selected-text block extraction failed"
[ "$(awk 'END {print NR+0}' "$tmpdir/p32n.selected.record.framed")" = 5 ] \
  || err "F3.2n selected-text block framing differs"
sed -n '3p' "$tmpdir/p32n.selected.record.framed" > "$tmpdir/p32n.selected.record"; p32nrc=$?
[ "$p32nrc" -eq 0 ] || err "F3.2n selected-text deframing failed"
cmp -s "$tmpdir/p32n.selected.packet" "$tmpdir/p32n.selected.record"; p32nrc=$?
[ "$p32nrc" -eq 0 ] || err "F3.2n selected text differs from exact unquoted F3.2m OPT-001 disposition cell"

for p32nrequiredline in \
  '| F32M-D11-Q002-OPT-001 | PROPOSED — UNSELECTED — HISTORICAL SOURCE STATE | OWNER ANSWER AND DIRECTION APPROVED — NON-ENACTING — ALL AND ONLY THIS DISPOSITION | NONE — SEPARATELY AUTHORIZED LATER WORK ONLY |' \
  '| F32M-D11-Q002-OPT-002 | PROPOSED — UNSELECTED — HISTORICAL SOURCE STATE | NOT APPROVED — NO SELECTION | NONE |' \
  '| F32M-D11-Q002-OPT-003 | PROPOSED — UNSELECTED — HISTORICAL SOURCE STATE | NOT APPROVED — NO SELECTION | NONE |' \
  'There is exactly one approved direction: all and only `F32M-D11-Q002-OPT-001`. No alternative, hybrid, subset, paraphrase, normalization, substitution, implied default, packet recommendation, or additional change is approved.' \
  '- No continuation or substitute-media output is permitted under that approval.' \
  '- Unchanged-epoch retry remains open under `F32C-D11-Q-005`; this record selects no unchanged-epoch retry policy. The published F3.2d Q-001 clarification remains byte-identical and unchanged.' \
  '- `F32C-D11-Q-003` through `F32C-D11-Q-012` remain unanswered.' \
  '- Present canonical effect is exactly `NONE`. No canonical source is amended by this record.' \
  '- `QK-REQ-BND-003` remains byte-identical and unchanged.'; do
  p32nlinehits=$(grep -cFx -e "$p32nrequiredline" "$REC32N"); p32nrc=$?
  [ "$p32nrc" -le 1 ] || err "F3.2n exact semantic-line scan failed"
  [ "$p32nlinehits" = 1 ] || err "F3.2n exact semantic line differs or duplicates: $p32nrequiredline"
done
forbid "F3.2n record restores stale substitute-medium wording" \
  -F 'substitute-medium output' "$REC32N"
forbid "F3.2n record restores the overbroad stale retry-policy wording" \
  -F 'selects no retry, continuation, fallback, or re-signing policy.' "$REC32N"

iconv -f UTF-8 -t UTF-8 "$REC32N" > "$tmpdir/p32n.utf8" 2> "$tmpdir/p32n.iconv.err"; p32nrc=$?
[ "$p32nrc" -eq 0 ] || err "$REC32N is not strict UTF-8"
[ -s "$tmpdir/p32n.utf8" ] || err "$REC32N UTF-8 validation produced empty output"
cmp -s "$REC32N" "$tmpdir/p32n.utf8"; p32nrc=$?
[ "$p32nrc" -eq 0 ] || err "$REC32N UTF-8 validation changed bytes"
tail -c 1 "$REC32N" > "$tmpdir/p32n.last.raw"; p32nrc=$?
[ "$p32nrc" -eq 0 ] || err "$REC32N final-byte read failed"
od -An -tuC "$tmpdir/p32n.last.raw" > "$tmpdir/p32n.last.od"; p32nrc=$?
[ "$p32nrc" -eq 0 ] || err "$REC32N final-byte scan failed"
tr -d '[:space:]' < "$tmpdir/p32n.last.od" > "$tmpdir/p32n.last.norm"; p32nrc=$?
[ "$p32nrc" -eq 0 ] || err "$REC32N final-byte normalization failed"
p32nlast=$(cat "$tmpdir/p32n.last.norm"); p32nrc=$?
[ "$p32nrc" -eq 0 ] || err "$REC32N final-byte read-back failed"
[ "$p32nlast" = 10 ] || err "$REC32N must end in exact LF"
tail -c 2 "$REC32N" > "$tmpdir/p32n.last2.raw"; p32nrc=$?
[ "$p32nrc" -eq 0 ] || err "$REC32N final-two-byte read failed"
printf '\n\n' > "$tmpdir/p32n.double-lf" || err "$REC32N double-LF fixture generation failed"
cmp -s "$tmpdir/p32n.double-lf" "$tmpdir/p32n.last2.raw"; p32nrc=$?
[ "$p32nrc" -eq 1 ] || err "$REC32N must not end in double LF or cmp failed (exit $p32nrc)"
od -An -tx1 "$REC32N" > "$tmpdir/p32n.bytes.raw"; p32nrc=$?
[ "$p32nrc" -eq 0 ] || err "$REC32N byte scan failed"
tr 'A-F' 'a-f' < "$tmpdir/p32n.bytes.raw" > "$tmpdir/p32n.bytes"; p32nrc=$?
[ "$p32nrc" -eq 0 ] || err "$REC32N byte normalization failed"
p32nbad=$(awk 'BEGIN {bad=0; p2=""; p1=""} {for(i=1;i<=NF;i++){b=$i; if(b=="00"||b=="0d")bad++; seq=p2 p1 b; if(seq=="efbbbf"||seq=="e2808e"||seq=="e2808f"||seq=="e280aa"||seq=="e280ab"||seq=="e280ac"||seq=="e280ad"||seq=="e280ae"||seq=="e281a6"||seq=="e281a7"||seq=="e281a8"||seq=="e281a9")bad++; p2=p1; p1=b}} END {print bad+0}' "$tmpdir/p32n.bytes"); p32nrc=$?
[ "$p32nrc" -eq 0 ] || err "$REC32N control/bidi byte scan failed"
[ "$p32nbad" = 0 ] || err "$REC32N contains BOM, NUL, CR, LRM/RLM, or bidi controls"
forbid "$REC32N contains a tab, trailing whitespace, HTML comment, hidden link definition, fence, blockquote, URL, or email material" \
  -E '	|[[:blank:]]$|<!--|-->|^\[[^]]+\]:|^```|^[[:space:]]*>|https?://|[[:alnum:]_.+-]+@[[:alnum:].-]+' "$REC32N"
forbid "$REC32N contains PSBT or key payload material" -E '[7]0736274|[c]HNidP|[x]pub|[x]prv' "$REC32N"
forbid "$REC32N contains suspicious 41+ hex material" -E '[0-9a-fA-F]{41,}' "$REC32N"

# G: full changed-content material scan across exactly the sixteen named
# protocol/provenance/checker paths listed in the loop below; replit.md
# is separately bounded elsewhere and is not part of this sixteen-path scan.
# Supporting evidence only, never
# proof of absence. Patterns are
# written self-scan-safe (bracketed first character) so the literals in
# this authorized script do not match themselves.
for cf in "$DRAFT" "$WTS" "$RSP32" "$PKT32C" "$CLR32D" "$PKT32E" "$REC32F" "$PKT32H" "$REC32I" "$PKT32J" "$REC32K" "$PKT32M" "$REC32N" docs/f3/README.md docs/SOURCE-REGISTER.md tools/verify-host-boundary.sh; do
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
# across the same sixteen named scan paths; every token must be deliberately
# classified below; any unclassified token is a blocker.
#   857a7debc6625a3dadbaecee1ee7b2ed5e8ada75  pinned bitcoin/bips commit (BIP 174 / type registry / BIP 370 citations)
#   15a7a4ed7c4d0952ce966087e55a9a3e2f28ec1d  pinned bitcoin/bitcoin commit (doc/psbt.md citation)
#   de71c22328b24e0848bbe1bd12ac8974ca83b5b8  pinned Ian Coleman BIP39 tool commit (SOURCE-REGISTER row)
#   5088588dd4f913a489329d2422b0f925ed281856  pinned SeedSigner commit (SOURCE-REGISTER row)
#   55f93844b56e3637468321e1c68638a8138a3a2b  pinned COLDCARD firmware commit (SOURCE-REGISTER row)
#   1e9dfb9518bd90d4531180d9a3258dd21e54dee3  retired QuietKey laboratory pin (SOURCE-REGISTER row)
#   8f3154d0e7845ed5a4c69b73b9479821fdf06765  governance manifest-ancestry constant required by this authorized script
#   26e075704cdd172fce62b9b7cd38b4035db384d8  published F3.2c parent and packet source base
#   a996a6d7c2bfa3a15109085475868410fe354422  F3.2d Q-001 whole-record reviewed blob
#   2c6d1152f09730661b2cadd86d2374c755191128  reviewed F3.2d Q-001 authorization commit A
#   a9d1f205cfa879a6f54b8838256d36e469cfed97  published base commit (Source-Register bounded-append anchor in this script)
#   b4594210975940df71b0e941841320d11defaa4c  F3.2c packet audit-locator/supporting byte-identity invariant
#   bb6601f3b97528a72c55622251a4b475680ec21b  published F3.2b owner-response source base
#   e4cdf7771e189fc0f729358334aafd35177048c6  published F3.2d Q-001 source base
#   4ffa20afbedeb0b6cfbbe57298f941bc0537683e  F3.2e packet pinned whole-file blob
#   838a732ab556b51ca8b0b61bed9ae9d512d47a87  F3.2b owner-response blob (F3.2e audit locator)
#   877866e5a3636bdfb7015d715e048ccfad63d939  PSBT draft blob (F3.2e audit locator)
#   981b1b497102187da66fb4e82ef0725b32c088f7  REQUIREMENTS blob (F3.2e audit locator)
#   be4d019e349e15ca575ac64b64f900957283e5e0  F3.2e source base
#   e57faff4ead69ddf108cf522cb6c3cbfbef8219a  F3.2e authorization commit A (Decision Log anchor)
#   f4e127a92fc68243274b7d384e335fa4632e5dd2  TEST-ARCHITECTURE blob (F3.2e audit locator)
#   22114c6741ac653b9c5079b1bfccdb795a88f3df  F3.2f authorization commit A (Decision Log anchor)
#   574e790193d45d3f392c64951d319bb5fde11d20  F3.2f source base / published F3.2e C
#   a066fc9710371f414d158a3deb9c345f2b00821b  F3.2f owner-direction whole-record blob
#   45f2b362994b785d303e91b8e530efc724dc2d81  F3.2g source base / published F3.2f C
#   55bd46310606e2df4089d8234a67655c81440bab  F3.2g authorization commit A (Decision Log anchor)
#   065e20eed4e916c907a244aa3e5ca2e66cbc5d4e  F3.2g amended TEST-ARCHITECTURE blob
#   a64399dd35aef8d6daa05171f1da30c8026f6d1f  F3.2h source base / published F3.2g C
#   da55fb4bcd4983140c8fb379cc3322eec99284f0  F3.2h authorization commit A
#   e7b7db5a12ea3c0a32d2b9cc3287e4d67d1da1bc  F3.2h Decision Log A blob
#   1ae6494fc24a8e3572464cf45e6d43ea4875e95d  F3.2h RESOURCE-BUDGETS source blob
#   2f4bc0f5cb8e861b45f515fb7c4c5dbc764784c5  F3.2i owner-direction whole-record blob
#   336956ec866ca3aa93791ffcb76f30e79e17dd31  F3.2j authorization commit A
#   0d2115de9c322bf221f5a5008d91e7b7b48363e6  F3.2k source base / published F3.2j C
#   0e366c1acc5579e541dfe3f94a099db9b887064b  F3.2j Decision Log A blob
#   e18ba6b4a5c2ee5fc5b7d1a464b656c631b526d5  F3.2h packet blob
#   c4e1ed94a02fba5d01f5cebfda4d5b1439222625  F3.2i authorization commit A
#   e36b41e5cd55264b4b745550c96c74968b06eae7  F3.2i source base / published F3.2h C
#   878b23be4690bb778a615bfe1a6ef108e7a94008  F3.2j source base / published F3.2i C
#   b1c2153f5f89a0e1d44d62a09921251e225c0d87  F3.2j packet blob
#   2abf7092adff3b0e27f754c6021c3d852db638f8  F3.2k authorization commit A
#   5b05d62776c65bfaf5ec41ab39108bc0531b7944  F3.2k owner-direction record blob
#   ac43ddd8a83d5be95e11d8208a0a998925b1027b  F3.2k Decision Log A blob
#   49ca0aa4a19ca10ebe8f2866b2d9426720b8ebdf  F3.2l source base / published F3.2k C
#   4af6166dc23eed7285a3d65b339924cda7b07962  F3.2l authorization commit A
#   7d03656d245786f3a17eb4dbae689ef03b172b75  F3.2l Decision Log A blob
#   09815b0a75c26a118f80c5cec008e695d319900b  F3.2l RESOURCE-BUDGETS post-enactment blob
#   2cf8a34aa5621dcea114e2d5ec3dabc2b79aef84  F3.2l REQUIREMENTS post-enactment blob
#   ecb3867ca2842f6d011288d3dcd94d2b1997e516  F3.2l TEST-ARCHITECTURE post-enactment blob
#   1408fa98961e62ba6316515b1e277b6952a96e18  F3.2m published source base / published F3.2l C
#   75c5e69cf5154b1936b86a6f0795f615a4d6ab3d  F3.2m published source-base tree
#   4d5041591bd28c665c717ddbdfc0dc54ef345680  F3.2m base host-verifier blob
#   5b6b67b7ec44f1460f31a02803e6f6db4f9386d1  F3.2m protected MATURITY-GATES blob
#   59008528885259ad8b93be1f0ece136930fd445d  F3.2m authorization commit A
#   99384f6cd5eedd37488e0c12d865737217f88b6c  F3.2m Decision Log A blob
#   a292d97308ae9a36d5bb5c4c48a83905bb06c073  F3.2m protected OPEN-DECISIONS blob
#   11714544ea89b3475d65a8a5634b7fdab65f5972  F3.2m packet whole-file blob
#   ee144c20c76283d8565d7d031145be372bae5375  F3.2m base current-stage-verifier blob
#   9bb66dc93d452e04284e13026814ed7322fb25b0  F3.2m protected THREAT-MODEL blob
#   f41e26799d0c4522b91e1de72d27cf473116b3ab  F3.2n source base / published F3.2m C
#   9ae24ea3278252b0a0f6703d2cbc381d59859dcf  F3.2n published source-base tree
#   d3a4f3bec5902d2e2155647a27ffe34bfa233bee  F3.2n authorization commit A
#   84f8fd26b311fe3e084b01c932ae3ee7469c49a3  F3.2n Decision Log A blob
#   01f7fb3140bcf69c31719a996c7a4c7ddd2394ab  F3.2n owner-direction record blob
{
  printf '%s\n' \
    01f7fb3140bcf69c31719a996c7a4c7ddd2394ab \
    065e20eed4e916c907a244aa3e5ca2e66cbc5d4e \
    09815b0a75c26a118f80c5cec008e695d319900b \
    0d2115de9c322bf221f5a5008d91e7b7b48363e6 \
    0e366c1acc5579e541dfe3f94a099db9b887064b \
    11714544ea89b3475d65a8a5634b7fdab65f5972 \
    1408fa98961e62ba6316515b1e277b6952a96e18 \
    15a7a4ed7c4d0952ce966087e55a9a3e2f28ec1d \
    1ae6494fc24a8e3572464cf45e6d43ea4875e95d \
    1e9dfb9518bd90d4531180d9a3258dd21e54dee3 \
    22114c6741ac653b9c5079b1bfccdb795a88f3df \
    26e075704cdd172fce62b9b7cd38b4035db384d8 \
    2abf7092adff3b0e27f754c6021c3d852db638f8 \
    2c6d1152f09730661b2cadd86d2374c755191128 \
    2cf8a34aa5621dcea114e2d5ec3dabc2b79aef84 \
    2f4bc0f5cb8e861b45f515fb7c4c5dbc764784c5 \
    336956ec866ca3aa93791ffcb76f30e79e17dd31 \
    45f2b362994b785d303e91b8e530efc724dc2d81 \
    49ca0aa4a19ca10ebe8f2866b2d9426720b8ebdf \
    4af6166dc23eed7285a3d65b339924cda7b07962 \
    4d5041591bd28c665c717ddbdfc0dc54ef345680 \
    4ffa20afbedeb0b6cfbbe57298f941bc0537683e \
    5088588dd4f913a489329d2422b0f925ed281856 \
    55bd46310606e2df4089d8234a67655c81440bab \
    55f93844b56e3637468321e1c68638a8138a3a2b \
    574e790193d45d3f392c64951d319bb5fde11d20 \
    59008528885259ad8b93be1f0ece136930fd445d \
    5b05d62776c65bfaf5ec41ab39108bc0531b7944 \
    5b6b67b7ec44f1460f31a02803e6f6db4f9386d1 \
    71e3f95adf541560ff5d067030f78dfd088d1ec1 \
    75c5e69cf5154b1936b86a6f0795f615a4d6ab3d \
    7d03656d245786f3a17eb4dbae689ef03b172b75 \
    838a732ab556b51ca8b0b61bed9ae9d512d47a87 \
    84f8fd26b311fe3e084b01c932ae3ee7469c49a3 \
    857a7debc6625a3dadbaecee1ee7b2ed5e8ada75 \
    877866e5a3636bdfb7015d715e048ccfad63d939 \
    878b23be4690bb778a615bfe1a6ef108e7a94008 \
    8f3154d0e7845ed5a4c69b73b9479821fdf06765 \
    981b1b497102187da66fb4e82ef0725b32c088f7 \
    99384f6cd5eedd37488e0c12d865737217f88b6c \
    9ae24ea3278252b0a0f6703d2cbc381d59859dcf \
    9bb66dc93d452e04284e13026814ed7322fb25b0 \
    a066fc9710371f414d158a3deb9c345f2b00821b \
    a292d97308ae9a36d5bb5c4c48a83905bb06c073 \
    a64399dd35aef8d6daa05171f1da30c8026f6d1f \
    a996a6d7c2bfa3a15109085475868410fe354422 \
    a9d1f205cfa879a6f54b8838256d36e469cfed97 \
    ac43ddd8a83d5be95e11d8208a0a998925b1027b \
    b1c2153f5f89a0e1d44d62a09921251e225c0d87 \
    b4594210975940df71b0e941841320d11defaa4c \
    bb6601f3b97528a72c55622251a4b475680ec21b \
    be4d019e349e15ca575ac64b64f900957283e5e0 \
    c4e1ed94a02fba5d01f5cebfda4d5b1439222625 \
    d3a4f3bec5902d2e2155647a27ffe34bfa233bee \
    da55fb4bcd4983140c8fb379cc3322eec99284f0 \
    de71c22328b24e0848bbe1bd12ac8974ca83b5b8 \
    e18ba6b4a5c2ee5fc5b7d1a464b656c631b526d5 \
    e36b41e5cd55264b4b745550c96c74968b06eae7 \
    e4cdf7771e189fc0f729358334aafd35177048c6 \
    e57faff4ead69ddf108cf522cb6c3cbfbef8219a \
    e7b7db5a12ea3c0a32d2b9cc3287e4d67d1da1bc \
    ecb3867ca2842f6d011288d3dcd94d2b1997e516 \
    ee144c20c76283d8565d7d031145be372bae5375 \
    f41e26799d0c4522b91e1de72d27cf473116b3ab \
    f4e127a92fc68243274b7d384e335fa4632e5dd2
} > "$tmpdir/hexallow" || err "40-hex allowlist generation failed (fail-closed)"
LC_ALL=C sort -c "$tmpdir/hexallow" \
  || err "40-hex allowlist is not sorted (fail-closed self-check)"
: > "$tmpdir/hexfound.raw"
for cf in "$DRAFT" "$WTS" "$RSP32" "$PKT32C" "$CLR32D" "$PKT32E" "$REC32F" "$PKT32H" "$REC32I" "$PKT32J" "$REC32K" "$PKT32M" "$REC32N" docs/f3/README.md docs/SOURCE-REGISTER.md tools/verify-host-boundary.sh; do
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
