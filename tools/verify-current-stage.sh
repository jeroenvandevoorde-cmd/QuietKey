#!/bin/sh
# QuietKey current-stage consistency checker (host-bootstrap stage).
#
# Designated current-stage consistency checker; its PASS is SUPPORTING
# EVIDENCE ONLY, never authoritative proof. POSIX, offline,
# verify-only, non-mutating, strict-clean-worktree, fail-closed.
# It checks declared still-applicable foundation invariants directly
# and checks canonical-file consistency against the published base,
# while permitting only the documented later-stage additions.
#
# LIMITS:
#   * The grep-based checks are heuristic, not complete semantic proof.
#   * HEAD includes changes to this script itself; a PASS does not
#     authenticate the script and is meaningful only after independent
#     review of the exact commit and bytes. A script cannot
#     authenticate itself. Any digest kept in-repo is an audit locator,
#     not a trust anchor.
#   * No repository-resident script can inspect the Replit Secrets
#     inventory or any other hosting-platform fact. Secret and
#     environment checks below are LEXICAL pattern checks only over
#     tracked content; they never prove semantic secret absence.
#   * tools/verify-foundation.sh (F0) and tools/verify-f2-preparation.sh
#     (F2 preparation) are immutable historical snapshot verifiers,
#     byte-pinned, required to pass only at their documented anchors,
#     and NOT run at HEAD; their known fail-open limitations are not
#     repaired. This checker independently reasserts the enduring
#     controls instead and verifies their bytes are unchanged.

set -u

fail=0
err() { printf 'CURRENT STAGE FAIL: %s\n' "$1" >&2; fail=1; }

# forbid <msg> <grep args...>: the pattern must NOT match. grep exit 1
# (no match) is the ONLY pass; exit 0 (found) and exit >1 (scan error)
# both fail, so a broken scan can never pass silently.
forbid() {
  fmsg=$1; shift
  grep "$@" >/dev/null 2>&1
  frc=$?
  [ "$frc" -eq 1 ] || err "$fmsg (grep exit $frc: 0=found, >1=scan error)"
}

cd "$(dirname "$0")/.." || { echo "CURRENT STAGE FAIL: cannot locate repository root" >&2; exit 1; }

GIT="git --no-optional-locks"

BASE=2442f4e6ddbf950980f6656e7219cc4ff23d3e41   # published base
C1=c622c19832c82b849737b895f41be7657fa8cc54     # docs: authorize host-only F3/F4 bootstrap
C2=f236f4097b87fce8f0ab781ec36d97c9b52cdc79     # build: add dependency-free Rust host state model
C3=8f3154d0e7845ed5a4c69b73b9479821fdf06765     # chore: establish current-stage verification
C4=20dea88b8501e07edb93fd7b8f1aaa4e1ecd2ca1     # feat(host): add transaction authority policy model
C5=5f186d051a1430b4f4a5d43dbfd0efab4661c648     # chore: advance current-stage verification (PUBLISHED BASE)
C6=11991ff6fb0559fd7512d1c0be300300072c0669     # docs(f3): draft PSBT v0 review profile
C7=145f960e659334be55afc11a1e0427c23c0f3b5e     # chore: advance current-stage verification (PUBLISHED BASE)
C8=b4668047aef673eaf67992e00d3a953167547a66     # docs: record F3.1a correction-only authorization
C9=757d41063749603a5fdb13aa73809ddbad098a82     # docs(f3.1a): remediate PSBT review-profile draft
C10=9ffea22a75946a53b7aa4d358cf25844bb3e323a    # chore: advance current-stage consistency checks (PUBLISHED BASE)
C11=b0155f16457f8ee82d2611f38571bf7dd508c147    # docs: record status-accuracy erratum authorization
C12=6640eb7945eaed8c9a5d9c75f4a617ef9b146ac2    # docs: correct current status and CARD-006 evidence family
C13=d9277cd2fcd8d699448a1667624123a3347118d6    # chore: advance status-erratum consistency checks (PUBLISHED BASE)
C14=6de0a4bb5863fc9717d32d8b5d25c88f6133da6f    # docs: record F3.1b Revision 2 policy-direction authorization
C15=1d2bc774a0a0cde445770d48509b901b580c6e97    # docs(f3): clarify remaining Revision 2 status and weight rules (reconstructed B)

tmpdir="${TMPDIR:-/tmp}/qk-current-stage.$$"
umask 077
mkdir "$tmpdir" || { echo "CURRENT STAGE FAIL: cannot create temp dir" >&2; exit 1; }
trap 'rm -rf "$tmpdir"' EXIT INT TERM

# ---------------------------------------------------------------- 0. Clean
# Strict clean worktree: no tracked modification, no untracked file.
# Ignored build caches are acceptable only because they are ignored;
# nothing under an ignored path may ever be tracked (checked below).
dirty=$($GIT status --porcelain -uall) || err "git status failed (enumeration fail-closed)"
[ -z "$dirty" ] || err "worktree is not strictly clean: $dirty"

# Full tracked-file listing, fail-closed: later filename scans read
# this file instead of re-running git in a maskable pipeline.
$GIT ls-files > "$tmpdir/allfiles" || err "git ls-files failed (enumeration fail-closed)"
[ -s "$tmpdir/allfiles" ] || err "git ls-files returned no tracked files (enumeration fail-closed)"

# ----------------------------------------------------------- a. Ancestry
# Exact linear ancestry BASE -> C1 -> ... -> C12 -> C13 -> C14 ->
# C15 -> HEAD, no merges. C13 is the PUBLISHED base of the current
# unpublished work.
head=$($GIT rev-parse HEAD) || err "cannot resolve HEAD"
p_head=$($GIT rev-parse "$head^" 2>/dev/null) || err "HEAD has no parent"
p_c15=$($GIT rev-parse "$C15^" 2>/dev/null) || err "C15 has no parent"
p_c14=$($GIT rev-parse "$C14^" 2>/dev/null) || err "C14 has no parent"
p_c13=$($GIT rev-parse "$C13^" 2>/dev/null) || err "C13 has no parent"
p_c12=$($GIT rev-parse "$C12^" 2>/dev/null) || err "C12 has no parent"
p_c11=$($GIT rev-parse "$C11^" 2>/dev/null) || err "C11 has no parent"
p_c10=$($GIT rev-parse "$C10^" 2>/dev/null) || err "C10 has no parent"
p_c9=$($GIT rev-parse "$C9^" 2>/dev/null) || err "C9 has no parent"
p_c8=$($GIT rev-parse "$C8^" 2>/dev/null) || err "C8 has no parent"
p_c7=$($GIT rev-parse "$C7^" 2>/dev/null) || err "C7 has no parent"
p_c6=$($GIT rev-parse "$C6^" 2>/dev/null) || err "C6 has no parent"
p_c5=$($GIT rev-parse "$C5^" 2>/dev/null) || err "C5 has no parent"
p_c4=$($GIT rev-parse "$C4^" 2>/dev/null) || err "C4 has no parent"
p_c3=$($GIT rev-parse "$C3^" 2>/dev/null) || err "C3 has no parent"
p_c2=$($GIT rev-parse "$C2^" 2>/dev/null) || err "C2 has no parent"
p_c1=$($GIT rev-parse "$C1^" 2>/dev/null) || err "C1 has no parent"
[ "$p_head" = "$C15" ] || err "HEAD parent is $p_head, expected $C15"
[ "$p_c15" = "$C14" ] || err "C15 parent is $p_c15, expected $C14"
[ "$p_c14" = "$C13" ] || err "C14 parent is $p_c14, expected $C13"
[ "$p_c13" = "$C12" ] || err "C13 parent is $p_c13, expected $C12"
[ "$p_c12" = "$C11" ] || err "C12 parent is $p_c12, expected $C11"
[ "$p_c11" = "$C10" ] || err "C11 parent is $p_c11, expected $C10"
[ "$p_c10" = "$C9" ] || err "C10 parent is $p_c10, expected $C9"
[ "$p_c9" = "$C8" ] || err "C9 parent is $p_c9, expected $C8"
[ "$p_c8" = "$C7" ] || err "C8 parent is $p_c8, expected $C7"
[ "$p_c7" = "$C6" ] || err "C7 parent is $p_c7, expected $C6"
[ "$p_c6" = "$C5" ] || err "C6 parent is $p_c6, expected $C5"
[ "$p_c5" = "$C4" ] || err "C5 parent is $p_c5, expected $C4"
[ "$p_c4" = "$C3" ] || err "C4 parent is $p_c4, expected $C3"
[ "$p_c3" = "$C2" ] || err "C3 parent is $p_c3, expected $C2"
[ "$p_c2" = "$C1" ] || err "C2 parent is $p_c2, expected $C1"
[ "$p_c1" = "$BASE" ] || err "C1 parent is $p_c1, expected $BASE"
count=$($GIT rev-list --count "$BASE..$head") || err "git rev-list --count failed (fail-closed)"
[ "$count" = "16" ] || err "expected exactly 16 commits after base, found $count"
merges=$($GIT rev-list --merges "$BASE..$head") || err "git rev-list --merges failed (fail-closed)"
[ -z "$merges" ] || err "merge commit present in $BASE..$head: $merges"
for c in "$head" "$C15" "$C14" "$C13" "$C12" "$C11" "$C10" "$C9" "$C8" "$C7" "$C6" "$C5" "$C4" "$C3" "$C2" "$C1"; do
  $GIT rev-list --no-walk --parents "$c" > "$tmpdir/parents" \
    || err "git rev-list --parents failed for $c (fail-closed)"
  # POSIX portability: wc -w may pad its output with whitespace on some
  # platforms; strip all whitespace, require a nonempty digit string,
  # and compare numerically. Two rc-checked temp-file stages — no
  # pipeline, so a wc failure cannot be masked by tr succeeding.
  # (Verifier portability only; no platform-independent reproducibility
  # is claimed.)
  wc -w < "$tmpdir/parents" > "$tmpdir/np.raw" \
    || err "parent count wc failed for $c (fail-closed)"
  tr -d '[:space:]' < "$tmpdir/np.raw" > "$tmpdir/np.txt" \
    || err "parent count whitespace strip failed for $c (fail-closed)"
  np=$(cat "$tmpdir/np.txt") \
    || err "parent count read-back failed for $c (fail-closed)"
  case "$np" in
    ''|*[!0-9]*) err "parent count for $c is not numeric: '$np' (fail-closed)" ;;
    *) [ "$np" -eq 2 ] || err "commit $c does not have exactly one parent (fields=$np)" ;;
  esac
done

# ------------------------------------------- b/c/d. Per-commit path sets
check_paths() {
  # $1 = commit, $2 = label, remaining lines on stdin = expected paths
  LC_ALL=C sort > "$tmpdir/exp.$2" \
    || err "expected path-set sort failed for $2 (fail-closed)"
  $GIT diff-tree --no-commit-id --name-only -r "$1" > "$tmpdir/raw.$2" \
    || err "git diff-tree failed for $2 (enumeration fail-closed)"
  [ -s "$tmpdir/raw.$2" ] || err "git diff-tree returned no paths for $2 (enumeration fail-closed)"
  LC_ALL=C sort "$tmpdir/raw.$2" > "$tmpdir/act.$2" \
    || err "actual path-set sort failed for $2 (fail-closed)"
  diff "$tmpdir/exp.$2" "$tmpdir/act.$2" > "$tmpdir/d.$2" 2>&1 \
    || err "$2 changes wrong path set: $(cat "$tmpdir/d.$2")"
}

check_paths "$C1" "commit1" <<'EOF'
docs/BUILD-ROADMAP.md
docs/DECISION-LOG.md
docs/HOST-WORK-AUTHORIZATION.md
EOF

check_paths "$C2" "commit2" <<'EOF'
.replit
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

check_paths "$C3" "commit3" <<'EOF'
.replit
replit.md
tools/verify-host-boundary.sh
tools/verify-current-stage.sh
EOF

check_paths "$C4" "commit4" <<'EOF'
docs/f4/README.md
docs/f4/TRANSACTION-AUTHORITY-POLICY.md
host/qk-host-model/src/lib.rs
host/qk-host-model/src/transaction_policy.rs
host/qk-host-sim/src/lib.rs
host/qk-host-sim/tests/transaction_policy.rs
tools/verify-host-boundary.sh
EOF

check_paths "$C5" "commit5" <<'EOF'
tools/verify-current-stage.sh
EOF

check_paths "$C6" "commit6" <<'EOF'
docs/SOURCE-REGISTER.md
docs/f3/PSBT-V0-REVIEW-PROFILE-DRAFT.md
docs/f3/README.md
tools/verify-host-boundary.sh
EOF

check_paths "$C7" "commit7" <<'EOF'
tools/verify-current-stage.sh
EOF

check_paths "$C8" "commit8" <<'EOF'
docs/DECISION-LOG.md
EOF

check_paths "$C9" "commit9" <<'EOF'
docs/SOURCE-REGISTER.md
docs/f3/PSBT-V0-REVIEW-PROFILE-DRAFT.md
docs/f3/README.md
replit.md
tools/verify-host-boundary.sh
EOF

check_paths "$C10" "commit10" <<'EOF'
tools/verify-current-stage.sh
EOF

check_paths "$C11" "commit11" <<'EOF'
docs/DECISION-LOG.md
EOF

check_paths "$C12" "commit12" <<'EOF'
README.md
SECURITY.md
docs/BUILD-ROADMAP.md
docs/HOST-WORK-AUTHORIZATION.md
docs/REQUIREMENTS.md
tools/verify-host-boundary.sh
EOF

check_paths "$C13" "commit13" <<'EOF'
tools/verify-current-stage.sh
EOF

check_paths "$C14" "commit14" <<'EOF'
docs/DECISION-LOG.md
EOF

check_paths "$C15" "commit15" <<'EOF'
docs/SOURCE-REGISTER.md
docs/f3/PSBT-V0-REVIEW-PROFILE-DRAFT.md
docs/f3/README.md
tools/verify-host-boundary.sh
EOF

check_paths "$head" "verifier-advance-commit" <<'EOF'
tools/verify-current-stage.sh
EOF

# ---------------- F3.1a authorization record and revision markers/sets
# Supporting lexical checks only. The exact plan/decision/clause SETS
# (001..034, 001..090, D-00..D-12) are enforced by the strict
# host-boundary run in section g below.
grep -F 'QK-AUTH-F3.1A-001' docs/DECISION-LOG.md >/dev/null \
  || err "docs/DECISION-LOG.md missing the F3.1a authorization record QK-AUTH-F3.1A-001"
grep -F 'Please continue, full authorization sustained.' docs/DECISION-LOG.md >/dev/null \
  || err "docs/DECISION-LOG.md missing the exact F3.1a owner authorization words"
grep -F 'REVISION: F3.1b REVISION 2 — OWNER DIRECTIONS RECORDED — PROFILE NOT ACCEPTED.' docs/f3/PSBT-V0-REVIEW-PROFILE-DRAFT.md >/dev/null \
  || err "PSBT draft missing the exact F3.1b Revision 2 revision marker"
grep -F 'REVIEW DRAFT — F3.1b REVISION 2 OWNER DIRECTIONS RECORDED — NOT ACCEPTED' docs/f3/PSBT-V0-REVIEW-PROFILE-DRAFT.md >/dev/null \
  || err "PSBT draft missing the Revision 2 directions-recorded not-accepted end status"
grep -F 'QK-AUTH-F3.1B-R2-001' docs/DECISION-LOG.md >/dev/null \
  || err "docs/DECISION-LOG.md missing the F3.1b Revision 2 authorization record QK-AUTH-F3.1B-R2-001"
grep -F 'Agreed, I approve this direction.' docs/DECISION-LOG.md >/dev/null \
  || err "docs/DECISION-LOG.md missing the exact F3.1b Revision 2 owner authorization words"
# Static regression: the host checker must itself carry the corrected
# B-final semantics checks (supporting lexical evidence only): the
# COMPLETE-LITERAL-FULL-ROW source helper (POSIX grep -Fxc, exactly
# one whole-line match) plus its resource-uniqueness check, all 19
# invocations, the transaction.h correction, the four row-scoped PLAN
# assertions, and the Revision 2 owner-directed PLAN-056 assertions
# with the retired-language forbids. Old substring (grep -cF) helper
# behavior is NOT accepted.
grep -F "forbid \"\$DRAFT still allows an ESTIMATE fee-rate status\"" tools/verify-host-boundary.sh >/dev/null \
  || err "host checker missing the ESTIMATE fee-rate negative check"
grep -F 'locktime enforcement for that input' tools/verify-host-boundary.sh >/dev/null \
  || err "host checker missing the per-input locktime-disable negative check"
grep -F 'exact_row() {' tools/verify-host-boundary.sh >/dev/null \
  || err "host checker missing the complete-literal-full-row source helper"
grep -F 'rowcount=$(grep -Fxc "$3" docs/SOURCE-REGISTER.md)' tools/verify-host-boundary.sh >/dev/null \
  || err "host checker helper does not perform the exact grep -Fxc complete-full-row check"
grep -F 'selcount=$(grep -cF "$2" docs/SOURCE-REGISTER.md)' tools/verify-host-boundary.sh >/dev/null \
  || err "host checker helper does not perform the resource-uniqueness check"
grep -F 'does not occur on exactly one source-table row' tools/verify-host-boundary.sh >/dev/null \
  || err "host checker helper missing the resource-uniqueness failure branch"
# All 19 exact_row calls must use filename/path-only selectors (a
# backticked token as the entire $2 argument), never selectors bound
# to the mutable leading source-label cell. Fail-closed count check.
fsel=$(grep -c "^  '\`[^\`]*\`' \\\\\$" tools/verify-host-boundary.sh)
fsel_rc=$?
[ "$fsel_rc" -le 1 ] || err "host checker filename-only selector count failed (grep exit $fsel_rc)"
[ "$fsel" = "19" ] || err "host checker does not use filename/path-only selectors for all 19 exact_row calls (found $fsel)"
forbid "host checker still carries a source-label-bound resource selector argument" \
  -F "\` |' \\" tools/verify-host-boundary.sh
grep -F 'does not match the complete literal expected row exactly once' tools/verify-host-boundary.sh >/dev/null \
  || err "host checker helper missing the complete-literal-row failure branch"
forbid "host checker still carries the old substring grep -cF row helper behavior" \
  -F 'ercount=$(grep -cF' tools/verify-host-boundary.sh
srcnt=$(grep -c '^exact_row ' tools/verify-host-boundary.sh)
src_rc=$?
[ "$src_rc" -le 1 ] || err "host checker exact_row invocation count failed (grep exit $src_rc)"
[ "$srcnt" = "19" ] || err "host checker does not carry exactly 19 complete-full-row source checks (found $srcnt)"
grep -F "exact_row 'primitives/transaction.h'" tools/verify-host-boundary.sh >/dev/null \
  || err "host checker missing the primitives/transaction.h full-row assertion"
grep -F "F3.1a citation-only reference for LOCKTIME_THRESHOLD 500,000,000 only." tools/verify-host-boundary.sh >/dev/null \
  || err "host checker missing the narrowed script.h purpose assertion"
grep -F 'LOCKTIME_THRESHOLD 500,000,000 and nSequence constant' tools/verify-host-boundary.sh >/dev/null \
  || err "host checker missing the false script.h nSequence-wording negative check"
grep -F 'for pid in QK-F3-PLAN-056 QK-F3-PLAN-085 QK-F3-PLAN-086 QK-F3-PLAN-087; do' tools/verify-host-boundary.sh >/dev/null \
  || err "host checker missing the four exact row-scoped PLAN D-12 disposition checks"
grep -F 'BIP125 opt-in encoding strictly PRESENT/ABSENT' tools/verify-host-boundary.sh >/dev/null \
  || err "host checker missing the PLAN-056 PRESENT/ABSENT encoding-display assertion"
grep -F 'actual/network replaceability UNKNOWN and never guaranteed' tools/verify-host-boundary.sh >/dev/null \
  || err "host checker missing the PLAN-056 replaceability-UNKNOWN assertion"
grep -F 'still carries retired Alternative A/B phasing' tools/verify-host-boundary.sh >/dev/null \
  || err "host checker missing the retired-Alternative-phasing forbid"
grep -F "still carries the retired 'replacement policy not evaluated' literal" tools/verify-host-boundary.sh >/dev/null \
  || err "host checker missing the retired replacement-policy-label forbid"
grep -F '(nSequence below 0xfffffffe) distinguished' tools/verify-host-boundary.sh >/dev/null \
  || err "host checker missing the PLAN-087 direct-BIP125-encoding assertion"
# Static regression: the host checker must carry the F3.1b Revision 2
# owner-direction checks (supporting lexical evidence only).
grep -F 'QK-AUTH-F3.1B-R2-001' tools/verify-host-boundary.sh >/dev/null \
  || err "host checker missing the F3.1b Revision 2 authorization checks"
grep -F 'UNSUPPORTED TRANSACTION POLICY' tools/verify-host-boundary.sh >/dev/null \
  || err "host checker missing the D-12 unsupported-version rejection check"
grep -F 'CANNOT VERIFY FEE RATE' tools/verify-host-boundary.sh >/dev/null \
  || err "host checker missing the D-08 CANNOT VERIFY FEE RATE check"
grep -F 'REJECTS at import, BEFORE any' tools/verify-host-boundary.sh >/dev/null \
  || err "host checker missing the D-03 import-stage rejection check"
grep -F 'as the EFFECTIVE PREVOUT' tools/verify-host-boundary.sh >/dev/null \
  || err "host checker missing the D-01 effective-prevout check"
forbid "host checker still lists PSBT_IN_PARTIAL_SIG as an allowed import field row" \
  -F 'INPUT: PSBT_IN_PARTIAL_SIG 0x02' tools/verify-host-boundary.sh
grep -F 'PD (per the pinned BIP preamble)' tools/verify-host-boundary.sh >/dev/null \
  || err "host checker missing the corrected BIP license classification checks"
# Static regression: the host checker must carry the reconstructed
# Revision 2 CORRECTION guards (supporting lexical evidence only):
# corrected BIP143 provenance, honest review-total/outflow language,
# complete marker/flag and witness weight accounting, the D-03/D-10
# stage boundary, route availability, the record-level delta
# predicate, qualified produced-signature taxonomy, mixed plan-class
# rows, the D-00 BLOCKED prerequisite list, and P2TR/nonce boundary
# guards — each with its paired stale-phrase forbid.
grep -F 'the 8-byte amount digest field comes from the EFFECTIVE' tools/verify-host-boundary.sh >/dev/null \
  || err "host checker missing the corrected BIP143 amount-provenance check"
grep -F "forbid \"\$DRAFT still claims amount and scriptCode both come from the effective prevout\"" tools/verify-host-boundary.sh >/dev/null \
  || err "host checker missing the stale BIP143 joint-provenance forbid"
grep -F "exact_row 'BIP 143'" tools/verify-host-boundary.sh >/dev/null \
  || err "host checker missing the bip-0143 full-row source assertion"
grep -F 'proven descriptor-owned outputs = not-proven-owned outputs + fee' tools/verify-host-boundary.sh >/dev/null \
  || err "host checker missing the conservative-wallet-debit identity check"
grep -F "forbid \"\$DRAFT still overclaims an exact external-recipient total\"" tools/verify-host-boundary.sh >/dev/null \
  || err "host checker missing the external-recipient-total forbid"
grep -F "forbid \"\$DRAFT still overclaims an exact net outflow\"" tools/verify-host-boundary.sh >/dev/null \
  || err "host checker missing the exact-net-outflow forbid"
grep -F 'they contribute 2 WU and must never be omitted' tools/verify-host-boundary.sh >/dev/null \
  || err "host checker missing the SegWit marker/flag 2-WU check"
grep -F 'item count and every CompactSize/item byte' tools/verify-host-boundary.sh >/dev/null \
  || err "host checker missing the witness-vector CompactSize accounting check"
grep -F 'NO one-signature/intermediate signed PSBT or other incomplete' tools/verify-host-boundary.sh >/dev/null \
  || err "host checker missing the no-incomplete-artifact check"
grep -F "forbid \"\$DRAFT still uses the contradictory 'NO partial PSBT' phrasing\"" tools/verify-host-boundary.sh >/dev/null \
  || err "host checker missing the stale NO-partial-PSBT forbid"
grep -F 'D-10/OD-05 OPEN and is wholly unspecified here' tools/verify-host-boundary.sh >/dev/null \
  || err "host checker missing the open D-10 finalization boundary check"
grep -F 'MUST be AVAILABLE over both' tools/verify-host-boundary.sh >/dev/null \
  || err "host checker missing the route-availability check"
grep -F "forbid \"\$DRAFT still mandates export over each authorized route\"" tools/verify-host-boundary.sh >/dev/null \
  || err "host checker missing the stale per-route-mandate forbid"
grep -F 'POSITION/ORDER of the new records is NOT a security predicate' tools/verify-host-boundary.sh >/dev/null \
  || err "host checker missing the insertion-order non-predicate check"
grep -F 'record encoding remains byte-identical in its original map and' tools/verify-host-boundary.sh >/dev/null \
  || err "host checker missing the record-level byte-preservation check"
grep -F 'produced-signature malformed/non-strict-DER' tools/verify-host-boundary.sh >/dev/null \
  || err "host checker missing the qualified produced-signature taxonomy check"
grep -F 'by PRESENCE and never parses' tools/verify-host-boundary.sh >/dev/null \
  || err "host checker missing the import presence-only taxonomy check"
grep -F 'for mpid in QK-F3-PLAN-034 QK-F3-PLAN-084 QK-F3-PLAN-085 QK-F3-PLAN-088; do' tools/verify-host-boundary.sh >/dev/null \
  || err "host checker missing the four row-scoped mixed plan-class checks"
grep -F 'not rejected solely by QK-F3-PSBT-031 arithmetic/range' tools/verify-host-boundary.sh >/dev/null \
  || err "host checker missing the PLAN-084 not-rejected-solely-by-031 check"
grep -F 'BLOCKED — MUST NOT ACCEPT' tools/verify-host-boundary.sh >/dev/null \
  || err "host checker missing the D-00 BLOCKED readiness check"
grep -F "forbid \"\$DRAFT D-00 row still carries the misleading finite-proposed-candidate readiness\"" tools/verify-host-boundary.sh >/dev/null \
  || err "host checker missing the row-scoped finite-proposed-candidate forbid"
grep -F 'neither RFC6979 nor any card nonce or anti-exfil' tools/verify-host-boundary.sh >/dev/null \
  || err "host checker missing the nonce/anti-exfil boundary check"
grep -F 'requires a separate explicit architecture-owner amendment' tools/verify-host-boundary.sh >/dev/null \
  || err "host checker missing the P2TR separate-amendment boundary check"
grep -F "forbid \"\$DRAFT section 6 still claims nothing was owner-decided\"" tools/verify-host-boundary.sh >/dev/null \
  || err "host checker missing the stale section-6 owner-decided forbid"
grep -F "forbid \"\$DRAFT still misattributes the derivation boundary to a D-08 family\"" tools/verify-host-boundary.sh >/dev/null \
  || err "host checker missing the stale D-08-boundary-family forbid"
grep -F 'not-proven-owned / treated as' tools/verify-host-boundary.sh >/dev/null \
  || err "host checker missing the not-proven-owned class check"
# Final audit wording fixes — DIRECT document checks (supporting
# lexical evidence only): exhaustive README decision-status summary,
# byte-exact honesty sentence, route-availability summaries, and the
# BIP141 weight equation in three scopes.
grep -F "D-00, D-02, D-04, D-06, D-07, D-09, D-10, and D-11 remain owner-open/structurally open as classified in the decision table; D-05's present-profile allowlist remains owner-open while only its FUTURE recipient-only P2TR direction is recorded" docs/f3/README.md >/dev/null \
  || err "docs/f3/README.md missing the exhaustive open-decision status summary"
forbid "docs/f3/README.md still carries the incomplete open-decision summary" \
  -F 'D-00, D-09 and D-11 remain open' docs/f3/README.md
grep -F 'No proposed byte-level rule is normative or frozen; no byte-exact vector or implementation artifact exists.' docs/f3/README.md >/dev/null \
  || err "docs/f3/README.md missing the corrected byte-exact honesty sentence"
forbid "docs/f3/README.md still carries the stale byte-exact sentence" \
  -F 'Nothing here is byte-exact or frozen.' docs/f3/README.md
grep -F 'signed-PSBT artifact availability over both approved capabilities' docs/f3/PSBT-V0-REVIEW-PROFILE-DRAFT.md >/dev/null \
  || err "PSBT draft missing the route-availability summary phrasing"
forbid "PSBT draft still summarizes export over both routes" \
  -F 'signed-PSBT export over both routes' docs/f3/PSBT-V0-REVIEW-PROFILE-DRAFT.md
wecnt=$(grep -cF 'weight_min/max = 4 × stripped_size + 2 (SegWit marker+flag) +' docs/f3/PSBT-V0-REVIEW-PROFILE-DRAFT.md)
we_rc=$?
[ "$we_rc" -le 1 ] || err "weight-equation occurrence count failed (grep exit $we_rc)"
[ "$wecnt" = "3" ] || err "PSBT draft must state the BIP141 weight equation exactly three times; found $wecnt"
# Final audit wording fixes — STATIC host-verifier regression checks.
grep -F 'the exhaustive open-decision status summary' tools/verify-host-boundary.sh >/dev/null \
  || err "host checker missing the exhaustive open-decision summary assertion"
grep -F "forbid \"docs/f3/README.md still carries the incomplete open-decision summary\"" tools/verify-host-boundary.sh >/dev/null \
  || err "host checker missing the stale open-decision summary forbid"
grep -F 'the corrected byte-exact honesty sentence' tools/verify-host-boundary.sh >/dev/null \
  || err "host checker missing the byte-exact honesty assertion"
grep -F "forbid \"docs/f3/README.md still carries the stale byte-exact sentence\"" tools/verify-host-boundary.sh >/dev/null \
  || err "host checker missing the stale byte-exact sentence forbid"
grep -F 'the route-availability summary phrasing' tools/verify-host-boundary.sh >/dev/null \
  || err "host checker missing the route-availability summary assertion"
grep -F "forbid \"\$DRAFT still summarizes export over both routes\"" tools/verify-host-boundary.sh >/dev/null \
  || err "host checker missing the stale export-over-both-routes forbid"
grep -F '[ "$fwcnt" = "3" ]' tools/verify-host-boundary.sh >/dev/null \
  || err "host checker missing the three-occurrence weight-equation count check"
grep -F 'in the checked formula' tools/verify-host-boundary.sh >/dev/null \
  || err "host checker missing the QK-022 scoped weight-equation check"
grep -F 'apply the checked formula' tools/verify-host-boundary.sh >/dev/null \
  || err "host checker missing the section-12 scoped weight-equation check"
grep -F 'the checked formula weight_min/max = 4 × stripped_size + 2 (SegWit marker+flag) + witness_min/max' tools/verify-host-boundary.sh >/dev/null \
  || err "host checker missing the PLAN-088 row-scoped weight-equation check"

# ---------------- F3.1b status-accuracy erratum (QK-AUTH-F3.1B-001)
# Supporting lexical/mechanical checks only, never proof of status.
# Authorization and erratum markers.
grep -F 'QK-AUTH-F3.1B-001' docs/DECISION-LOG.md >/dev/null \
  || err "docs/DECISION-LOG.md missing the F3.1b authorization record QK-AUTH-F3.1B-001"
grep -F '**Owner words exactly:** “Agreed”' docs/DECISION-LOG.md >/dev/null \
  || err "docs/DECISION-LOG.md missing the exact F3.1b owner authorization words"
grep -F 'QK-ERR-REQ-2026-08-18-001 — Effective erratum: QK-REQ-CARD-006 Evidence family (append-only)' docs/REQUIREMENTS.md >/dev/null \
  || err "docs/REQUIREMENTS.md missing the CARD-006 evidence-family erratum"
# Mechanical append-only proof: the file at the given published base
# must be an exact byte prefix of the current file (old length
# extracted, then byte-for-byte compare of the leading segment; every
# step rc-checked).
check_prefix() {
  # $1 = path, $2 = anchor commit
  $GIT show "$2:$1" > "$tmpdir/pfx.old" 2>/dev/null \
    || err "cannot read $1 from anchor $2"
  wc -c < "$tmpdir/pfx.old" > "$tmpdir/pfx.len.raw" \
    || err "prefix length wc failed for $1"
  tr -d '[:space:]' < "$tmpdir/pfx.len.raw" > "$tmpdir/pfx.len" \
    || err "prefix length strip failed for $1"
  oldlen=$(cat "$tmpdir/pfx.len") || err "prefix length read-back failed for $1"
  case "$oldlen" in ''|*[!0-9]*) err "prefix length not numeric for $1: '$oldlen'"; return ;; esac
  dd if="$1" bs=1 count="$oldlen" > "$tmpdir/pfx.new" 2>/dev/null \
    || err "prefix extraction failed for $1"
  cmp -s "$tmpdir/pfx.old" "$tmpdir/pfx.new"
  cprc=$?
  [ "$cprc" -eq 0 ] || err "$1 is not append-only: published-base content is not an exact byte prefix (cmp exit $cprc)"
}
check_prefix docs/DECISION-LOG.md "$C13"
check_prefix docs/REQUIREMENTS.md "$C10"
# Truthful present-state wording present; stale claims gone.
grep -F 'the owner-approved specification baseline, dependency-free payload-free HOST-only non-product state/policy models and tests, and a non-normative PSBT review-profile draft' README.md >/dev/null \
  || err "README.md missing the truthful current-state statement"
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
grep -F 'QK-AUTH-F3F4-001 — Host-only F3/F4 bootstrap authorization' docs/HOST-WORK-AUTHORIZATION.md >/dev/null \
  || err "HOST-WORK-AUTHORIZATION.md original authorization record heading is missing"
grep -F '“Yes, go ahead.”' docs/HOST-WORK-AUTHORIZATION.md >/dev/null \
  || err "HOST-WORK-AUTHORIZATION.md original owner quote is missing"
# Static regression: the host checker must carry the F3.1b truthful-
# status and erratum checks and the stale-claim forbids.
grep -F 'F3.1b status-accuracy erratum (QK-AUTH-F3.1B-001)' tools/verify-host-boundary.sh >/dev/null \
  || err "host checker missing the F3.1b status-accuracy check block"
grep -F 'The effective Evidence cell for QK-REQ-CARD-006 is "recovery-rehearsal, target-bench"; its Tst cell remains "QK-TST-REH-004, QK-TST-BENCH-005".' tools/verify-host-boundary.sh >/dev/null \
  || err "host checker missing the exact CARD-006 effective Evidence/Tst assertion"
grep -F 'QK-TST-BENCH-005 remains conditional on OD-02 and no non-exportable-signer direction is selected.' tools/verify-host-boundary.sh >/dev/null \
  || err "host checker missing the OD-02 conditionality assertion"
grep -F 'historical QK-REQ-CARD-006 row is missing or was edited' tools/verify-host-boundary.sh >/dev/null \
  || err "host checker missing the historical CARD-006 row-preservation assertion"
grep -F -e "-F 'contains an architecture foundation only' README.md" tools/verify-host-boundary.sh >/dev/null \
  || err "host checker missing the stale README claim forbid"
grep -F -e "-F 'without executing any of them' docs/BUILD-ROADMAP.md" tools/verify-host-boundary.sh >/dev/null \
  || err "host checker missing the stale roadmap claim forbid"
grep -F 'missing the corrected unvalidated-specification sentence' tools/verify-host-boundary.sh >/dev/null \
  || err "host checker missing the corrected README-sentence positive assertion"
grep -F -e "-F 'This repository is a development specification only; no implementation evidence exists.' README.md" tools/verify-host-boundary.sh >/dev/null \
  || err "host checker missing the stale README-sentence forbid"

# --------------------------------- e. Historical verifiers byte-identical
for v in tools/verify-foundation.sh tools/verify-f2-preparation.sh; do
  $GIT show "$BASE:$v" > "$tmpdir/hist" 2>/dev/null || err "cannot read $v from base"
  diff "$tmpdir/hist" "$v" >/dev/null 2>&1 || err "$v differs from base $BASE"
done

# ------------------- f. Still-applicable foundation controls, reasserted
# f.1 Stage allowlist and canonical-file immutability: every tracked file
# must either be byte-identical to the base or be one of the documented
# later-stage additions/authorized modifications.
cat > "$tmpdir/allowed-diff" <<'EOF'
.replit
README.md
SECURITY.md
docs/BUILD-ROADMAP.md
docs/DECISION-LOG.md
docs/HOST-WORK-AUTHORIZATION.md
docs/REQUIREMENTS.md
docs/SOURCE-REGISTER.md
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
replit.md
tools/verify-current-stage.sh
tools/verify-host-boundary.sh
EOF
$GIT diff --name-only "$BASE" "$head" > "$tmpdir/actual-diff.raw" \
  || err "git diff --name-only failed (enumeration fail-closed)"
[ -s "$tmpdir/actual-diff.raw" ] || err "git diff returned no changed paths (enumeration fail-closed)"
LC_ALL=C sort "$tmpdir/actual-diff.raw" > "$tmpdir/actual-diff" \
  || err "base-to-head diff path-set sort failed (fail-closed)"
diff "$tmpdir/allowed-diff" "$tmpdir/actual-diff" > "$tmpdir/dd" 2>&1 \
  || err "tracked changes since base differ from the authorized set: $(cat "$tmpdir/dd")"
# Every other tracked file is therefore byte-identical to base, including
# all canonical governance files and both historical verifiers.

# f.2 Required files exist.
for f in \
  README.md ARCHITECTURE.md replit.md AGENTS.md SECURITY.md \
  docs/THREAT-MODEL.md docs/MATURITY-GATES.md docs/OPEN-DECISIONS.md \
  docs/DECISION-LOG.md docs/SOURCE-REGISTER.md docs/BUILD-ROADMAP.md \
  docs/HOST-WORK-AUTHORIZATION.md .gitignore \
  tools/verify-foundation.sh tools/verify-f2-preparation.sh \
  tools/verify-host-boundary.sh tools/verify-current-stage.sh
do
  [ -f "$f" ] || err "missing required file: $f"
done

# f.3 Enduring warnings.
first_line=$(head -n 1 README.md 2>/dev/null)
[ "$first_line" = "EXPERIMENTAL — NO REAL FUNDS — NOT A WALLET" ] \
  || err "README does not begin with the exact no-funds warning"
for f in replit.md SECURITY.md docs/f3/README.md docs/f4/README.md; do
  grep -F 'EXPERIMENTAL — NO REAL FUNDS — NOT A WALLET' "$f" >/dev/null \
    || err "$f missing the no-funds warning"
done

# f.4 Decision and gate state.
i=1
while [ "$i" -le 14 ]; do
  id=$(printf 'QK-DEC-%03d' "$i")
  grep -q "$id" ARCHITECTURE.md || err "ARCHITECTURE.md missing $id"
  i=$((i + 1))
done
for g in A B C D E; do
  grep -E "Gate $g.*OPEN|OPEN.*Gate $g" docs/MATURITY-GATES.md >/dev/null 2>&1 \
    || err "Gate $g OPEN language not found in docs/MATURITY-GATES.md"
done
for od in OD-01 OD-02 OD-03 OD-04 OD-05 OD-06 OD-07 OD-08; do
  grep -F "$od" docs/OPEN-DECISIONS.md >/dev/null || err "$od missing from docs/OPEN-DECISIONS.md"
done

# f.5 No license while OD-08 is open.
# grep exit 0 = matches, 1 = no match (allowed), >1 = error (fail).
grep -iE '(^|/)(LICENSE|LICENCE|COPYING|COPYRIGHT|NOTICE)(\.|$)' "$tmpdir/allfiles" > "$tmpdir/lic"
rc=$?
[ "$rc" -le 1 ] || err "license filename scan grep failed (fail-closed)"
lic=$(cat "$tmpdir/lic")
[ -z "$lic" ] || err "license-like file tracked while OD-08 is open: $lic"

# f.6 No service/deploy/db/workflow/env artifacts; no dependency
# manifests beyond the authorized host workspace.
grep -E '(^|/)(\.env|.*\.(db|sqlite|sqlite3))$|^\.github/|(^|/)(Dockerfile|docker-compose[^/]*)$|(^|/)(package\.json|requirements\.txt|pyproject\.toml|go\.mod)$' "$tmpdir/allfiles" > "$tmpdir/badnames"
rc=$?
[ "$rc" -le 1 ] || err "prohibited filename scan grep failed (fail-closed)"
bad=$(cat "$tmpdir/badnames")
[ -z "$bad" ] || err "service/deploy/db/workflow/env/dependency artifact tracked: $bad"
forbid ".replit contains deployment configuration" \
  -E '^deployment|^\[deployment' .replit

# f.7 Exact current .replit content.
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
diff "$tmpdir/replit.expected" .replit > "$tmpdir/rd" 2>&1 \
  || err ".replit differs from the authorized content: $(cat "$tmpdir/rd")"

# f.8 No secret USE in tracked content. (Platform Secrets inventory is
# unprovable from inside the repository; this is a tracked-content check
# only.) SESSION_SECRET may appear solely in the two documented
# descriptive mentions.
# git grep exits 1 for "no match" (acceptable) and >1 for real errors;
# distinguish the two explicitly so a git failure cannot pass silently.
$GIT grep -l 'SESSION_SECRET' -- . > "$tmpdir/ssrefs"
rc=$?
[ "$rc" -le 1 ] || err "git grep SESSION_SECRET failed (enumeration fail-closed)"
grep -v -e '^docs/f2/README.md$' -e '^tools/verify-f2-preparation.sh$' -e '^tools/verify-current-stage.sh$' "$tmpdir/ssrefs" > "$tmpdir/ssbad"
rc=$?
[ "$rc" -le 1 ] || err "SESSION_SECRET allowlist grep failed (fail-closed)"
refs=$(cat "$tmpdir/ssbad")
[ -z "$refs" ] || err "SESSION_SECRET referenced outside documented descriptive mentions: $refs"
$GIT grep -nE 'std *:: *env|process\.env|os\.environ|getenv *\(' -- ':!tools/' ':!docs/' > "$tmpdir/envuse"
rc=$?
[ "$rc" -le 1 ] || err "git grep env-use failed (enumeration fail-closed)"
envuse=$(cat "$tmpdir/envuse")
[ -z "$envuse" ] || err "environment-variable use found in tracked code: $envuse"

# ------------------------- g. Host boundary, strict publication mode
sh tools/verify-host-boundary.sh > "$tmpdir/hb" 2>&1 \
  || err "verify-host-boundary.sh (publication mode) failed: $(cat "$tmpdir/hb")"
grep -x 'HOST BOOTSTRAP SCOPE PASS' "$tmpdir/hb" >/dev/null \
  || err "verify-host-boundary.sh did not emit the strict publication pass line"

# ----------------------------------------------- h. Lockfile purity
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

# ------------------------------------------------ i. No untracked files
$GIT status --porcelain -uall > "$tmpdir/status" \
  || err "git status failed (enumeration fail-closed)"
grep '^??' "$tmpdir/status" > "$tmpdir/untracked"
rc=$?
[ "$rc" -le 1 ] || err "untracked scan grep failed (fail-closed)"
untracked=$(cat "$tmpdir/untracked")
[ -z "$untracked" ] || err "untracked files present: $untracked"

# -------- j0. Regression: the host-boundary Cargo.lock source/checksum
# scan must use the fail-closed forbid helper (grep 0=violation,
# 1=allowed no-match, >1=hard failure).
awk 'p == 1 { print; p = 0 }
  index($0, "forbid \"host/Cargo.lock contains external source/checksum entries\"") > 0 { print; p = 1 }' \
  tools/verify-host-boundary.sh > "$tmpdir/lockscan" 2>&1
rc=$?
[ "$rc" -eq 0 ] || err "lockfile-scan regression check failed to run (awk exit $rc; exact-empty is caught by the follow-on content check)"
grep -F -- "-E '^(source|checksum) *=' host/Cargo.lock" "$tmpdir/lockscan" >/dev/null 2>&1 \
  || err "verify-host-boundary.sh Cargo.lock source/checksum scan does not use the fail-closed forbid helper"

# ---------------------------- j. Verifier self-check: no masked scans
# Neither verifier may contain an OR-COLON or OR-TRUE construct that
# could mask a failing security-relevant command. The patterns are
# assembled by concatenation so this check does not match itself.
bar='|'
m1="$bar$bar :"; m2="$bar$bar:"; m3="$bar$bar true"; m4="$bar${bar}true"
for vf in tools/verify-current-stage.sh tools/verify-host-boundary.sh; do
  for m in "$m1" "$m2" "$m3" "$m4"; do
    grep -Fn "$m" "$vf" > "$tmpdir/mask" 2>&1
    rc=$?
    [ "$rc" -le 1 ] || err "mask-construct self-scan failed on $vf (fail-closed)"
    [ ! -s "$tmpdir/mask" ] || err "$vf contains a masking construct: $(cat "$tmpdir/mask")"
  done
done
tracked_ignored=$($GIT ls-files -i -c --exclude-standard) \
  || err "git ls-files -i failed (enumeration fail-closed)"
[ -z "$tracked_ignored" ] || err "tracked file matches an ignore rule: $tracked_ignored"

if [ "$fail" -eq 0 ]; then
  echo "CURRENT STAGE PASS"
  exit 0
else
  exit 1
fi
