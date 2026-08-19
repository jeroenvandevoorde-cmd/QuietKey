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
# docs/DECISION-LOG.md must be byte-identical to the reviewed A commit.
git --no-optional-locks show 9354d4a2924378ddcc20e4ffa26be0602bd913c0:docs/DECISION-LOG.md > "$tmpdir/dlog.a" 2>/dev/null \
  || err "cannot read docs/DECISION-LOG.md from the reviewed A commit"
cmp -s "$tmpdir/dlog.a" docs/DECISION-LOG.md
dlrc=$?
[ "$dlrc" -eq 0 ] || err "docs/DECISION-LOG.md is not byte-identical to the reviewed A commit (cmp exit $dlrc): extra or altered governance text"
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

# G: full changed-content material scan across exactly the seven named
# protocol/provenance/checker paths listed in the loop below; replit.md
# is separately bounded elsewhere and is not part of this seven-path
# scan. Supporting evidence only, never
# proof of absence. Patterns are
# written self-scan-safe (bracketed first character) so the literals in
# this authorized script do not match themselves.
for cf in "$DRAFT" "$WTS" "$RSP32" "$PKT32C" docs/f3/README.md docs/SOURCE-REGISTER.md tools/verify-host-boundary.sh; do
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
# across the same seven named scan paths; every token must be deliberately
# classified below; any unclassified token is a blocker.
#   857a7debc6625a3dadbaecee1ee7b2ed5e8ada75  pinned bitcoin/bips commit (BIP 174 / type registry / BIP 370 citations)
#   15a7a4ed7c4d0952ce966087e55a9a3e2f28ec1d  pinned bitcoin/bitcoin commit (doc/psbt.md citation)
#   de71c22328b24e0848bbe1bd12ac8974ca83b5b8  pinned Ian Coleman BIP39 tool commit (SOURCE-REGISTER row)
#   5088588dd4f913a489329d2422b0f925ed281856  pinned SeedSigner commit (SOURCE-REGISTER row)
#   55f93844b56e3637468321e1c68638a8138a3a2b  pinned COLDCARD firmware commit (SOURCE-REGISTER row)
#   1e9dfb9518bd90d4531180d9a3258dd21e54dee3  retired QuietKey laboratory pin (SOURCE-REGISTER row)
#   8f3154d0e7845ed5a4c69b73b9479821fdf06765  governance manifest-ancestry constant required by this authorized script
#   26e075704cdd172fce62b9b7cd38b4035db384d8  published F3.2c parent and packet source base
#   9354d4a2924378ddcc20e4ffa26be0602bd913c0  reviewed F3.2c construction-packet authorization commit A
#   a9d1f205cfa879a6f54b8838256d36e469cfed97  published base commit (Source-Register bounded-append anchor in this script)
#   b4594210975940df71b0e941841320d11defaa4c  F3.2c packet audit-locator/supporting byte-identity invariant
#   bb6601f3b97528a72c55622251a4b475680ec21b  published F3.2b owner-response source base
{
  printf '%s\n' \
    15a7a4ed7c4d0952ce966087e55a9a3e2f28ec1d \
    1e9dfb9518bd90d4531180d9a3258dd21e54dee3 \
    26e075704cdd172fce62b9b7cd38b4035db384d8 \
    5088588dd4f913a489329d2422b0f925ed281856 \
    55f93844b56e3637468321e1c68638a8138a3a2b \
    857a7debc6625a3dadbaecee1ee7b2ed5e8ada75 \
    8f3154d0e7845ed5a4c69b73b9479821fdf06765 \
    9354d4a2924378ddcc20e4ffa26be0602bd913c0 \
    a9d1f205cfa879a6f54b8838256d36e469cfed97 \
    b4594210975940df71b0e941841320d11defaa4c \
    bb6601f3b97528a72c55622251a4b475680ec21b \
    de71c22328b24e0848bbe1bd12ac8974ca83b5b8
} > "$tmpdir/hexallow" || err "40-hex allowlist generation failed (fail-closed)"
LC_ALL=C sort -c "$tmpdir/hexallow" \
  || err "40-hex allowlist is not sorted (fail-closed self-check)"
: > "$tmpdir/hexfound.raw"
for cf in "$DRAFT" "$WTS" "$RSP32" "$PKT32C" docs/f3/README.md docs/SOURCE-REGISTER.md tools/verify-host-boundary.sh; do
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
