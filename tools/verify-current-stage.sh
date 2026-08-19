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
C16=a9d1f205cfa879a6f54b8838256d36e469cfed97    # chore: rebind Revision 2 consistency checks (PUBLISHED BASE)
C17=19979a5ec3d141125e7f4471d14846bba44e0e1a    # docs: authorize F3.2a Wallet Trust Spine drafting
C18=a92a4b5dade0abcbcb8ad04a454b2cf4b229a32f    # docs(f3): correct Wallet Trust Spine draft and guards
C19=e81ab9c61dda9be60ac45facbe5db57115578540    # chore: rebind F3.2a consistency checks (PUBLISHED BASE)
C20=8060a57e873eda0a69991fb31b6e53b9b44bf3a4    # docs: authorize OD-08 decision-packet preparation
C21=30a2240945842e6b33b0b492e4ae34212b5858f6    # docs(od08): add decision packet and reanchor host checks
C22=8c18266c6fc6c00831f444f51a6a1f762250a12d    # chore: bind OD-08 decision-packet consistency checks (PUBLISHED OD-08 PARENT)
C23=e29359bd0dac2892f0d3291a9ec4a11b758513f9    # docs: authorize OD-08 owner-response record preparation
C24=e5c887b46eef7fde14cfe667264bb427598be3cb    # docs(od08): add non-enacting owner-response record and reanchor host checks
C25=a9840819eba4d1b98b8346fc0ae0b44f611a45c5    # chore: bind OD-08 owner-response consistency checks (PUBLISHED F3.2B PARENT)
C26=9e30750ebf85a17884624c0697cc0ef14a7bafe3    # docs: authorize F3.2b PSBT decision-packet preparation
C27=85b5356961e5f04f49e7c9e8d835c09e45755e9f    # docs(f3): add non-binding F3.2b PSBT decision packet and reanchor host checks

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
# Exact linear ancestry BASE -> C1 -> ... -> C24 -> C25 -> C26 ->
# C27 -> HEAD, no merges. C25 is the PUBLISHED base of the current
# unpublished work.
head=$($GIT rev-parse HEAD) || err "cannot resolve HEAD"
p_head=$($GIT rev-parse "$head^" 2>/dev/null) || err "HEAD has no parent"
p_c27=$($GIT rev-parse "$C27^" 2>/dev/null) || err "C27 has no parent"
p_c26=$($GIT rev-parse "$C26^" 2>/dev/null) || err "C26 has no parent"
p_c25=$($GIT rev-parse "$C25^" 2>/dev/null) || err "C25 has no parent"
p_c24=$($GIT rev-parse "$C24^" 2>/dev/null) || err "C24 has no parent"
p_c23=$($GIT rev-parse "$C23^" 2>/dev/null) || err "C23 has no parent"
p_c22=$($GIT rev-parse "$C22^" 2>/dev/null) || err "C22 has no parent"
p_c21=$($GIT rev-parse "$C21^" 2>/dev/null) || err "C21 has no parent"
p_c20=$($GIT rev-parse "$C20^" 2>/dev/null) || err "C20 has no parent"
p_c19=$($GIT rev-parse "$C19^" 2>/dev/null) || err "C19 has no parent"
p_c18=$($GIT rev-parse "$C18^" 2>/dev/null) || err "C18 has no parent"
p_c17=$($GIT rev-parse "$C17^" 2>/dev/null) || err "C17 has no parent"
p_c16=$($GIT rev-parse "$C16^" 2>/dev/null) || err "C16 has no parent"
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
[ "$p_head" = "$C27" ] || err "HEAD parent is $p_head, expected $C27"
[ "$p_c27" = "$C26" ] || err "C27 parent is $p_c27, expected $C26"
[ "$p_c26" = "$C25" ] || err "C26 parent is $p_c26, expected $C25"
[ "$p_c25" = "$C24" ] || err "C25 parent is $p_c25, expected $C24"
[ "$p_c24" = "$C23" ] || err "C24 parent is $p_c24, expected $C23"
[ "$p_c23" = "$C22" ] || err "C23 parent is $p_c23, expected $C22"
[ "$p_c22" = "$C21" ] || err "C22 parent is $p_c22, expected $C21"
[ "$p_c21" = "$C20" ] || err "C21 parent is $p_c21, expected $C20"
[ "$p_c20" = "$C19" ] || err "C20 parent is $p_c20, expected $C19"
[ "$p_c19" = "$C18" ] || err "C19 parent is $p_c19, expected $C18"
[ "$p_c18" = "$C17" ] || err "C18 parent is $p_c18, expected $C17"
[ "$p_c17" = "$C16" ] || err "C17 parent is $p_c17, expected $C16"
[ "$p_c16" = "$C15" ] || err "C16 parent is $p_c16, expected $C15"
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
[ "$count" = "28" ] || err "expected exactly 28 commits after base, found $count"
merges=$($GIT rev-list --merges "$BASE..$head") || err "git rev-list --merges failed (fail-closed)"
[ -z "$merges" ] || err "merge commit present in $BASE..$head: $merges"
for c in "$head" "$C27" "$C26" "$C25" "$C24" "$C23" "$C22" "$C21" "$C20" "$C19" "$C18" "$C17" "$C16" "$C15" "$C14" "$C13" "$C12" "$C11" "$C10" "$C9" "$C8" "$C7" "$C6" "$C5" "$C4" "$C3" "$C2" "$C1"; do
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

check_paths "$C16" "commit16" <<'EOF'
tools/verify-current-stage.sh
EOF

check_paths "$C17" "commit17" <<'EOF'
docs/DECISION-LOG.md
EOF

check_paths "$C18" "commit18" <<'EOF'
docs/SOURCE-REGISTER.md
docs/f3/README.md
docs/f3/WALLET-TRUST-SPINE-DRAFT.md
tools/verify-host-boundary.sh
EOF

check_paths "$C19" "commit19" <<'EOF'
tools/verify-current-stage.sh
EOF

check_paths "$C20" "commit20" <<'EOF'
docs/DECISION-LOG.md
EOF

check_paths "$C21" "commit21" <<'EOF'
docs/OD-08-DECISION-PACKET.md
tools/verify-host-boundary.sh
EOF

check_paths "$C22" "commit22" <<'EOF'
tools/verify-current-stage.sh
EOF

check_paths "$C23" "commit23" <<'EOF'
docs/DECISION-LOG.md
EOF

check_paths "$C24" "commit24" <<'EOF'
docs/OD-08-OWNER-RESPONSE-RECORD.md
tools/verify-host-boundary.sh
EOF

check_paths "$C25" "commit25" <<'EOF'
tools/verify-current-stage.sh
EOF

check_paths "$C26" "commit26" <<'EOF'
docs/DECISION-LOG.md
EOF

check_paths "$C27" "commit27" <<'EOF'
docs/f3/F3.2B-PSBT-DECISION-PACKET.md
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
# one whole-line match) plus its resource-uniqueness check, all 26
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
# All 26 exact_row calls must use filename/path-only selectors (a
# backticked token as the entire $2 argument), never selectors bound
# to the mutable leading source-label cell. Fail-closed count check.
fsel=$(grep -c "^  '\`[^\`]*\`' \\\\\$" tools/verify-host-boundary.sh)
fsel_rc=$?
[ "$fsel_rc" -le 1 ] || err "host checker filename-only selector count failed (grep exit $fsel_rc)"
[ "$fsel" = "26" ] || err "host checker does not use filename/path-only selectors for all 26 exact_row calls (found $fsel)"
forbid "host checker still carries a source-label-bound resource selector argument" \
  -F "\` |' \\" tools/verify-host-boundary.sh
grep -F 'does not match the complete literal expected row exactly once' tools/verify-host-boundary.sh >/dev/null \
  || err "host checker helper missing the complete-literal-row failure branch"
forbid "host checker still carries the old substring grep -cF row helper behavior" \
  -F 'ercount=$(grep -cF' tools/verify-host-boundary.sh
srcnt=$(grep -c '^exact_row ' tools/verify-host-boundary.sh)
src_rc=$?
[ "$src_rc" -le 1 ] || err "host checker exact_row invocation count failed (grep exit $src_rc)"
[ "$srcnt" = "26" ] || err "host checker does not carry exactly 26 complete-full-row source checks (found $srcnt)"
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
# ------------------------------ F3.2a Wallet Trust Spine draft stage
# Direct essentials of the new draft, plus static assertions that the
# host checker carries each new F3.2a guard. Lexical evidence only.
WTS=docs/f3/WALLET-TRUST-SPINE-DRAFT.md
[ -f "$WTS" ] || err "$WTS missing"
grep -F 'QK-AUTH-F3.2A-001 — F3.2a Wallet Trust Spine drafting authorization' docs/DECISION-LOG.md >/dev/null \
  || err "docs/DECISION-LOG.md missing the QK-AUTH-F3.2A-001 record"
grep -F 'STATUS: AUTHORIZED — F3.2a HOST-ONLY WALLET TRUST-SPINE DRAFT — PROPOSED/NON-NORMATIVE — INCOMPLETE — NO PROFILE ACCEPTED OR FROZEN — NO TEST VECTORS GENERATED OR RUN — NO IMPLEMENTATION — NO TARGET EVIDENCE.' "$WTS" >/dev/null \
  || err "$WTS missing the exact mandatory status banner"
csstl=$(grep -c '^STATUS:' "$WTS")
csrc=$?
[ "$csrc" -le 1 ] || err "WTS STATUS-line count failed (grep exit $csrc)"
[ "$csstl" = "1" ] || err "$WTS must contain exactly one line beginning 'STATUS:' (found $csstl)"
grep '^STATUS:' "$WTS" > "$tmpdir/cs.wts.status"
csrc=$?
[ "$csrc" -le 1 ] || err "WTS STATUS-line extraction failed (grep exit $csrc)"
printf '%s\n' 'STATUS: AUTHORIZED — F3.2a HOST-ONLY WALLET TRUST-SPINE DRAFT — PROPOSED/NON-NORMATIVE — INCOMPLETE — NO PROFILE ACCEPTED OR FROZEN — NO TEST VECTORS GENERATED OR RUN — NO IMPLEMENTATION — NO TARGET EVIDENCE.' > "$tmpdir/cs.wts.status.expected" \
  || err "WTS expected-status generation failed (fail-closed)"
cmp -s "$tmpdir/cs.wts.status.expected" "$tmpdir/cs.wts.status"
cscmp=$?
[ "$cscmp" -eq 0 ] || err "$WTS STATUS line is not exactly the mandatory banner as a full line (cmp exit $cscmp)"
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
# Robust closed-world WTS ID sets, enforced DIRECTLY here (not only
# via the host checker): extract every row-leading ID with any digit
# count, compare against the exact expected lists, rc-check every
# stage. Duplicates, omissions, malformed IDs and extras all fail.
cwlines=$(grep -c '^\*\*QK-F3-WTS' "$WTS")
cwrc=$?
[ "$cwrc" -le 1 ] || err "WTS clause heading-prefix line count failed (grep exit $cwrc)"
cwvalid=$(grep -cE '^\*\*QK-F3-WTS-[0-9][0-9][0-9] \(PROPOSED/NON-NORMATIVE\)\.\*\*' "$WTS")
cwrc=$?
[ "$cwrc" -le 1 ] || err "WTS valid clause heading count failed (grep exit $cwrc)"
[ "$cwlines" = "$cwvalid" ] || err "$WTS has $cwlines clause heading-prefix lines but only $cwvalid satisfy the complete anchored heading grammar: malformed clause heading grammar"
sed -n 's/^\*\*\(QK-F3-WTS-[0-9][0-9][0-9]\) (PROPOSED\/NON-NORMATIVE)\.\*\*.*/\1/p' "$WTS" > "$tmpdir/cs.wts.clauses.actual"
cwrc=$?
[ "$cwrc" -eq 0 ] || err "WTS clause heading extraction failed (sed exit $cwrc)"
[ -s "$tmpdir/cs.wts.clauses.actual" ] || err "$WTS contains no valid WTS clause headings (fail-closed)"
: > "$tmpdir/cs.wts.clauses.expected" || err "WTS clause expected-list init failed"
wtsi=1
while [ "$wtsi" -le 15 ]; do
  printf 'QK-F3-WTS-%03d\n' "$wtsi" >> "$tmpdir/cs.wts.clauses.expected" \
    || err "WTS clause expected-list generation failed at $wtsi"
  wtsi=$((wtsi + 1))
done
LC_ALL=C sort "$tmpdir/cs.wts.clauses.actual" > "$tmpdir/cs.wts.clauses.sorted" \
  || err "WTS clause sort failed (fail-closed)"
cmp -s "$tmpdir/cs.wts.clauses.expected" "$tmpdir/cs.wts.clauses.sorted"
cwcmp=$?
[ "$cwcmp" -eq 0 ] || err "$WTS clause heading set is not exactly QK-F3-WTS-001..015 (cmp exit $cwcmp)"
cwplines=$(grep -cE '^\|[ ]*QK-F3-WTS-PLAN' "$WTS")
cwrc=$?
[ "$cwrc" -le 1 ] || err "WTS plan row-prefix line count failed (grep exit $cwrc)"
cwpvalid=$(grep -cE '^\| QK-F3-WTS-PLAN-[0-9][0-9][0-9] \|' "$WTS")
cwrc=$?
[ "$cwrc" -le 1 ] || err "WTS valid plan first-cell count failed (grep exit $cwrc)"
[ "$cwplines" = "$cwpvalid" ] || err "$WTS has $cwplines plan-prefix rows but only $cwpvalid satisfy the exact anchored first-cell grammar: malformed plan row grammar"
sed -n 's/^| \(QK-F3-WTS-PLAN-[0-9][0-9][0-9]\) |.*/\1/p' "$WTS" > "$tmpdir/cs.wts.plans.actual"
cwrc=$?
[ "$cwrc" -eq 0 ] || err "WTS plan ID extraction failed (sed exit $cwrc)"
[ -s "$tmpdir/cs.wts.plans.actual" ] || err "$WTS contains no valid WTS plan rows (fail-closed)"
: > "$tmpdir/cs.wts.plans.expected" || err "WTS plan expected-list init failed"
wtsi=1
while [ "$wtsi" -le 20 ]; do
  printf 'QK-F3-WTS-PLAN-%03d\n' "$wtsi" >> "$tmpdir/cs.wts.plans.expected" \
    || err "WTS plan expected-list generation failed at $wtsi"
  wtsi=$((wtsi + 1))
done
LC_ALL=C sort "$tmpdir/cs.wts.plans.actual" > "$tmpdir/cs.wts.plans.sorted" \
  || err "WTS plan sort failed (fail-closed)"
cmp -s "$tmpdir/cs.wts.plans.expected" "$tmpdir/cs.wts.plans.sorted"
cwcmp=$?
[ "$cwcmp" -eq 0 ] || err "$WTS plan row set is not exactly QK-F3-WTS-PLAN-001..020 (cmp exit $cwcmp)"
# Every plan row must END with the exact final status cell.
wtspl=$(grep -cE '^\| QK-F3-WTS-PLAN-[0-9][0-9][0-9] \|.*\| PLANNED — NOT GENERATED — NOT RUN \|$' "$WTS")
cwrc=$?
[ "$cwrc" -le 1 ] || err "WTS plan final-status count failed (grep exit $cwrc)"
[ "$wtspl" = "20" ] || err "$WTS does not have exactly 20 plan rows ending with the exact final status cell (found $wtspl)"
grep -F 'wallet_id = SHA256(canonical_receive_descriptor_ASCII || 0x00 || canonical_change_descriptor_ASCII)' "$WTS" >/dev/null \
  || err "$WTS missing the exact preserved wallet_id formula"
grep -F 'single-interface B+C choreography is BLOCKED' "$WTS" >/dev/null \
  || err "$WTS missing the B+C BLOCKED marker"
grep -F 'END OF DRAFT — PROPOSED/NON-NORMATIVE — NO PROFILE ACCEPTED — NO VECTORS — NO IMPLEMENTATION — NO TARGET EVIDENCE.' "$WTS" >/dev/null \
  || err "$WTS missing the exact end-of-draft status line"
# Corrected semantic/status phrases enforced directly.
grep -F 'a signer and A2 is not a signer role' "$WTS" >/dev/null \
  || err "$WTS missing the corrected A1/A2 role statement"
grep -F 'No single custody object alone satisfies the threshold' "$WTS" >/dev/null \
  || err "$WTS missing the no-single-object-threshold rule"
forbid "$WTS still carries the retired no-role-split wording" \
  -F 'no role is ever split across' "$WTS"
forbid "$WTS still names the unpinned BIP389" \
  -F 'BIP389' "$WTS"
grep -F 'contain the same A2 value' "$WTS" >/dev/null \
  || err "$WTS missing the same-A2 canonical invariant"
grep -F 'cannot be reached without establishing this same-A2 invariant' "$WTS" >/dev/null \
  || err "$WTS missing the FINAL-ACCEPTANCE same-A2 precondition"
grep -F "independently recomputed from each card's D" "$WTS" >/dev/null \
  || err "$WTS missing the recomputed-not-stored wallet_id rule"
grep -F 'wallet_id is never stored on the cards' "$WTS" >/dev/null \
  || err "$WTS missing the wallet_id-never-stored rule"
grep -F 'MUST match its OWN assigned role entry' "$WTS" >/dev/null \
  || err "$WTS missing the per-role public-material agreement rule"
grep -F 'stateless replacement terminal with no prior wallet registration' "$WTS" >/dev/null \
  || err "$WTS missing the stateless-replacement-terminal statement"
grep -F 'traceability is NOT DONE' "$WTS" >/dev/null \
  || err "$WTS missing the honest traceability-NOT-DONE boundary"
grep -F 'an explicit profile-acceptance prerequisite and remains NOT' "$WTS" >/dev/null \
  || err "$WTS missing the traceability acceptance-prerequisite statement"
forbid "$WTS still claims completed traceability to existing QK-TST IDs" \
  -F 'traces only to existing' "$WTS"
# Exact bounded append content enforced directly (checked stages, cmp).
# The current Decision Log must be byte-identical to the reviewed
# owner-response authorization commit A (C23); the published C22
# content must be an exact byte prefix of it; and the appended suffix
# beyond the C22 prefix must be byte-identical to the exact authorized
# QK-AUTH-OD08-RSP-001 record transcript embedded below.
$GIT show "$C26:docs/DECISION-LOG.md" > "$tmpdir/cs.dlog.a" 2>/dev/null \
  || err "cannot read docs/DECISION-LOG.md from C26"
cmp -s "$tmpdir/cs.dlog.a" docs/DECISION-LOG.md
csdl=$?
[ "$csdl" -eq 0 ] || err "docs/DECISION-LOG.md is not byte-identical to the reviewed C26 (F3.2b A) version (cmp exit $csdl)"
$GIT show "$C25:docs/DECISION-LOG.md" > "$tmpdir/cs.dlog.base" 2>/dev/null \
  || err "cannot read docs/DECISION-LOG.md from C25"
wc -c < "$tmpdir/cs.dlog.base" > "$tmpdir/cs.dlog.len.raw" \
  || err "C25 Decision-Log length failed (fail-closed)"
tr -d '[:space:]' < "$tmpdir/cs.dlog.len.raw" > "$tmpdir/cs.dlog.len" \
  || err "C25 Decision-Log length strip failed (fail-closed)"
dlbl=$(cat "$tmpdir/cs.dlog.len") || err "C25 Decision-Log length read-back failed (fail-closed)"
case "$dlbl" in ''|*[!0-9]*) err "C25 Decision-Log length not numeric: '$dlbl'" ;; esac
dd if=docs/DECISION-LOG.md bs=1 count="$dlbl" > "$tmpdir/cs.dlog.head" 2>/dev/null \
  || err "Decision-Log prefix extraction failed (fail-closed)"
cmp -s "$tmpdir/cs.dlog.base" "$tmpdir/cs.dlog.head"
csdl=$?
[ "$csdl" -eq 0 ] || err "published C25 Decision-Log is not an exact byte prefix of the current Decision-Log (cmp exit $csdl)"
# Exact authorized suffix beyond the C25 prefix.
dlskip=$((dlbl + 1)) || err "suffix offset arithmetic failed (fail-closed)"
tail -c "+$dlskip" docs/DECISION-LOG.md > "$tmpdir/cs.dlog.suffix" \
  || err "Decision-Log suffix extraction failed (fail-closed)"
cat > "$tmpdir/cs.dlog.suffix.expected" <<'QK_F32B_SUFFIX_EOF' || err "expected Decision-Log suffix file generation failed (fail-closed)"

### QK-AUTH-F3.2B-PKT-001 — F3.2b non-binding PSBT decision-packet preparation authorization

- **ID:** QK-AUTH-F3.2B-PKT-001
- **Date:** 2026-08-19
- **Approver:** Project owner
- **Owner words exactly:** “Authorize preparation and independent audit of the docs-only F3.2b PSBT decision packet from a9840819. No profile acceptance, implementation, vectors, license application, hardware work, or settings changes.”
- **Context:** given after publication of the audited OD-08 owner-response chain ending at the published parent below. The owner authorized preparation and independent audit of a non-binding F3.2b PSBT decision packet only: decision input, not an answer, selection, adoption, or acceptance of any profile or clause, and not publication or any later implementation or application authority. The prepared chain includes the single mechanically necessary host-verifier file-set addition described below because the packet lives inside the host verifier’s exact tracked host file set scope; this implementation detail does not broaden the owner’s quoted authorization or alter any other host-boundary predicate.
- **Published parent:** `a9840819eba4d1b98b8346fc0ae0b44f611a45c5`.
- **Authorizes only:** local preparation of the non-binding F3.2b PSBT decision packet; local verification of the prepared chain; independent read-only audit of the prepared packet; export of the exact unpushed tree for that audit; Commit B adding exactly `docs/f3/F3.2B-PSBT-DECISION-PACKET.md` and changing exactly `tools/verify-host-boundary.sh` solely to reanchor its Decision-Log byte-identity anchor to this Commit A and to add exactly `docs/f3/F3.2B-PSBT-DECISION-PACKET.md` as one line to its exact authorized tracked host file set, while preserving every other host-boundary predicate; then Commit C changing exactly `tools/verify-current-stage.sh`. Publication is not authorized by this record and requires a later explicit owner instruction after passing independent audits.
- **Packet scope:** exactly four owner questions: D-02, present-profile D-05, D-06, and D-10. D-00 remains blocked; D-04 remains owner-open and is not posed in this four-question packet; representative coordinator-corpus review remains required before any later selection; D-07, D-09, and D-11 remain evidence- or construction-blocked with no response requested; the recorded D-01, D-03, D-08, and D-12 directions remain non-normative and are preserved without reopening; the future-only recipient-P2TR direction remains future-only.
- **Explicit exclusions:** no publication; no owner response or new D-item selection; no profile, bundle, clause, serialization, hash, policy, limit, test, vector, or evidence acceptance; no normative change; no edit to the PSBT draft, F3 README, Source Register, Architecture, Requirements, Traceability, Open Decisions, gates, evidence, OD, QK-LIM, or QK-TST documents; no code, parser, serializer, wallet, crypto, signing, key, address, PSBT specimen, QR, SD, card, or target work; no vector, fixture, corpus, or payload generation or execution; no license, SPDX, or manifest license change; no hardware, Flux, procurement, or fabrication work; no role, channel, repository setting, workflow, deployment, or `.replit` change; no third-party text, import, or source change; no host-boundary predicate change besides the exact Decision-Log anchor advance and the single authorized file-set line addition above.
- **Effect:** local packet preparation only; the PSBT draft remains byte-identical, proposed, non-normative, and not accepted; every status remains unchanged; Gates A–E remain OPEN; F5–F12 remain unauthorized; and this chain remains local and unpublished pending a later explicit owner publication instruction after passing independent audits.
QK_F32B_SUFFIX_EOF
cmp -s "$tmpdir/cs.dlog.suffix.expected" "$tmpdir/cs.dlog.suffix"
csdl=$?
[ "$csdl" -eq 0 ] || err "Decision-Log suffix beyond the published C25 prefix is not the exact authorized QK-AUTH-F3.2B-PKT-001 record (cmp exit $csdl)"
# OD-08 authorization record essentials. Every check below is a
# COMPLETE-literal-line proof: grep -cFx -e against the entire exact
# bullet or heading line from docs/DECISION-LOG.md, each required
# exactly once with rc handling. A duplicated phrase on the same line,
# or any shortened, prefixed, or suffixed variant of a bullet, changes
# the line bytes and therefore fails the corresponding full-line guard.
cat > "$tmpdir/cs.dlog.lines" <<'EOF' || err "expected authorization-line file generation failed (fail-closed)"
### QK-AUTH-OD08-PKT-001 — OD-08 non-binding decision-packet preparation authorization
- **Owner words exactly:** “Perfect, go ahead”
- **Published parent:** `e81ab9c61dda9be60ac45facbe5db57115578540`.
- **Authorizes only:** local preparation of a factual current-state and rights-chain inventory; an informational comparison of unselected standard license families for software, hardware designs, documentation, and ancillary material; separately answerable owner questions covering licensing, contributions, maintainership, review, vulnerability reporting, release signing, supported versions, audit ownership, and trademark/official-build boundaries; independent read-only audit of the prepared packet; and the exact verifier rebind below. Publication is not authorized by this record and requires a later explicit owner instruction after a passing independent audit.
- **Authorized next commits:** Commit B adding exactly `docs/OD-08-DECISION-PACKET.md` and changing exactly `tools/verify-host-boundary.sh` solely to advance its byte-identity Decision-Log anchor to Commit A while preserving all other host-boundary predicates; then Commit C changing exactly `tools/verify-current-stage.sh`.
- **Explicit exclusions:** no license selection, grant, application, modification, or legal conclusion; no `LICENSE`, `LICENCE`, `COPYING`, `COPYRIGHT`, `NOTICE`, `AUTHORS`, `CONTRIBUTING`, `CODEOWNERS`, `REUSE.toml`, SPDX header, manifest license field, DCO/CLA activation, or third-party text/code import; no assertion of copyright ownership or contributor consent; no OD resolution; no architecture, requirement, limit, test, evidence, maturity-gate, milestone, release, or support-status change; no person, organization, handle, email, channel, maintainer, reviewer, key custodian, auditor, or service appointment; no repository/hosting setting, branch rule, private-reporting channel, release-signing mechanism, or supported-version policy activation; no code, vector, fixture, dependency, hardware, Flux, procurement, fabrication, or use-with-funds authorization; no host-boundary scope, acceptance predicate, test expectation, status rule, file allowlist, platform/dependency check, or semantic claim may change except the exact necessary Decision-Log anchor advance.
- **Effect:** OD-08 remains OPEN in full; this chain grants no new rights and does not determine or revoke any rights that may have arisen from historical repository versions; the repository still has no selected project license; no governance role or channel exists by virtue of this record; Gates A–E remain OPEN, STOP-SHIP remains in force, every other status remains unchanged; and this chain remains local and unpublished pending a separate explicit owner publication approval.
EOF
# Independent precondition: the expected-line file must contain exactly
# seven nonempty lines before the loop runs, so an empty, partially
# written, or truncated file cannot silently run zero or fewer checks.
dlexp=$(awk 'BEGIN { n = 0 } /./ { n = n + 1 } END { print n }' "$tmpdir/cs.dlog.lines") \
  || err "expected authorization-line count stage failed (awk fail-closed)"
[ "$dlexp" = "7" ] || err "expected authorization-line file must contain exactly 7 nonempty lines (found $dlexp): generation was partial, empty, or corrupted"
dlproc=0
while IFS= read -r dlline; do
  dlc=$(grep -cFx -e "$dlline" docs/DECISION-LOG.md)
  dlrc=$?
  [ "$dlrc" -le 1 ] || err "OD-08 record full-line check failed (grep exit $dlrc)"
  [ "$dlc" = "1" ] || err "OD-08 record line not present exactly once as a complete line (found $dlc): $dlline"
  dlproc=$((dlproc + 1))
done < "$tmpdir/cs.dlog.lines"
[ "$dlproc" = "7" ] || err "OD-08 packet-record full-line loop processed $dlproc of 7 expected lines (fail-closed)"
# OD-08 owner-response authorization record essentials
# (QK-AUTH-OD08-RSP-001). Same COMPLETE-literal-line mechanism as the
# packet-record block above: rc-checked generation, exact expected
# nonempty line count before the loop, per-line grep -cFx -e exactly
# once, exact processed count after the loop.
cat > "$tmpdir/cs.rsp.lines" <<'QK_RSP_LINES_EOF' || err "expected owner-response authorization-line file generation failed (fail-closed)"
### QK-AUTH-OD08-RSP-001 — OD-08 non-enacting owner-response record preparation authorization
- **Owner words exactly:** “Authorize preparation and independent audit of the OD‑08 owner-response record from 8c18266. No license application or settings changes.”
- **Published parent:** `8c18266c6fc6c00831f444f51a6a1f762250a12d`.
- **Authorizes only:** transcription of the owner-provided responses into a non-enacting owner-response record; local verification of the prepared chain; independent read-only audit of the prepared record; export of the exact unpushed tree for that audit; Commit B; and Commit C. Publication is not authorized by this record and requires a later explicit owner instruction after passing independent audits.
- **Authorized next commits:** Commit B adding exactly `docs/OD-08-OWNER-RESPONSE-RECORD.md` and changing exactly `tools/verify-host-boundary.sh` solely to advance its byte-identity Decision-Log anchor to Commit A while preserving all other host-boundary predicates; then Commit C changing exactly `tools/verify-current-stage.sh`.
- **Explicit exclusions:** no publication; no license or SPDX selection, application, or grant; no legal conclusion; no OD-08 closure; no policy, role, channel, repository or hosting setting, support promise, release, or maturity-gate activation; no protected canonical-document change; no code, vector, fixture, dependency, hardware, Flux, procurement, or fabrication work; no assertion of copyright ownership, contributor consent, or chain-of-title proof; no person, organization, handle, email, channel, maintainer, reviewer, key custodian, auditor, or service appointment takes operational effect by virtue of this record.
- **Effect:** OD-08 remains OPEN in full; this chain enacts nothing, grants no rights, and does not determine or revoke any rights that may have arisen from historical repository versions; the repository still has no selected project license; Gates A–E remain OPEN, STOP-SHIP remains in force, every other status remains unchanged; and this chain remains local and unpublished pending a later explicit owner publication instruction after passing independent audits.
QK_RSP_LINES_EOF
rspexp=$(awk 'BEGIN { n = 0 } /./ { n = n + 1 } END { print n }' "$tmpdir/cs.rsp.lines") \
  || err "expected owner-response authorization-line count stage failed (awk fail-closed)"
[ "$rspexp" = "7" ] || err "expected owner-response authorization-line file must contain exactly 7 nonempty lines (found $rspexp): generation was partial, empty, or corrupted"
rspproc=0
while IFS= read -r rspline; do
  rspc=$(grep -cFx -e "$rspline" docs/DECISION-LOG.md)
  rsprc=$?
  [ "$rsprc" -le 1 ] || err "OD-08 owner-response record full-line check failed (grep exit $rsprc)"
  [ "$rspc" = "1" ] || err "OD-08 owner-response record line not present exactly once as a complete line (found $rspc): $rspline"
  rspproc=$((rspproc + 1))
done < "$tmpdir/cs.rsp.lines"
[ "$rspproc" = "7" ] || err "OD-08 owner-response record full-line loop processed $rspproc of 7 expected lines (fail-closed)"
# F3.2b decision-packet authorization record essentials
# (QK-AUTH-F3.2B-PKT-001). Same COMPLETE-literal-line mechanism:
# rc-checked generation, exact expected nonempty line count before the
# loop, per-line grep -cFx -e exactly once, exact processed count.
cat > "$tmpdir/cs.f32b.lines" <<'QK_F32B_LINES_EOF' || err "expected F3.2b authorization-line file generation failed (fail-closed)"
### QK-AUTH-F3.2B-PKT-001 — F3.2b non-binding PSBT decision-packet preparation authorization
- **Owner words exactly:** “Authorize preparation and independent audit of the docs-only F3.2b PSBT decision packet from a9840819. No profile acceptance, implementation, vectors, license application, hardware work, or settings changes.”
- **Published parent:** `a9840819eba4d1b98b8346fc0ae0b44f611a45c5`.
- **Packet scope:** exactly four owner questions: D-02, present-profile D-05, D-06, and D-10. D-00 remains blocked; D-04 remains owner-open and is not posed in this four-question packet; representative coordinator-corpus review remains required before any later selection; D-07, D-09, and D-11 remain evidence- or construction-blocked with no response requested; the recorded D-01, D-03, D-08, and D-12 directions remain non-normative and are preserved without reopening; the future-only recipient-P2TR direction remains future-only.
- **Effect:** local packet preparation only; the PSBT draft remains byte-identical, proposed, non-normative, and not accepted; every status remains unchanged; Gates A–E remain OPEN; F5–F12 remain unauthorized; and this chain remains local and unpublished pending a later explicit owner publication instruction after passing independent audits.
QK_F32B_LINES_EOF
f32bexp=$(awk 'BEGIN { n = 0 } /./ { n = n + 1 } END { print n }' "$tmpdir/cs.f32b.lines") \
  || err "expected F3.2b authorization-line count stage failed (awk fail-closed)"
[ "$f32bexp" = "5" ] || err "expected F3.2b authorization-line file must contain exactly 5 nonempty lines (found $f32bexp): generation was partial, empty, or corrupted"
f32bproc=0
while IFS= read -r f32bline; do
  f32bc=$(grep -cFx -e "$f32bline" docs/DECISION-LOG.md)
  f32brc=$?
  [ "$f32brc" -le 1 ] || err "F3.2b record full-line check failed (grep exit $f32brc)"
  [ "$f32bc" = "1" ] || err "F3.2b record line not present exactly once as a complete line (found $f32bc): $f32bline"
  f32bproc=$((f32bproc + 1))
done < "$tmpdir/cs.f32b.lines"
[ "$f32bproc" = "5" ] || err "F3.2b record full-line loop processed $f32bproc of 5 expected lines (fail-closed)"

# ---------------- OD-08 decision packet (QK-AUTH-OD08-PKT-001)
# Non-binding decision-input packet: byte-bound to reviewed commit B,
# closed-world question set, unanswered-response proof, and
# license/material/claim guards. Lexical evidence only; nothing here
# proves legal status.
PKT=docs/OD-08-DECISION-PACKET.md
[ -f "$PKT" ] || err "$PKT missing"
$GIT show "$C21:$PKT" > "$tmpdir/cs.pkt.b" 2>/dev/null \
  || err "cannot read $PKT from C21"
cmp -s "$tmpdir/cs.pkt.b" "$PKT"
pkc=$?
[ "$pkc" -eq 0 ] || err "$PKT is not byte-identical to the reviewed C21 (OD-08 B) version (cmp exit $pkc)"
pfirst=$(head -n 1 "$PKT") || err "packet first-line read failed (fail-closed)"
[ "$pfirst" = "EXPERIMENTAL — NO REAL FUNDS — NOT A WALLET" ] \
  || err "$PKT does not begin with the exact no-funds warning"
plast=$(tail -n 1 "$PKT") || err "packet last-line read failed (fail-closed)"
[ "$plast" = "END OF PACKET — OD-08 REMAINS OPEN — OWNER RESPONSES AND A SEPARATE RECORDED APPLICATION AUTHORIZATION ARE REQUIRED." ] \
  || err "$PKT does not end with the exact end-of-packet line"
pst=$(grep -c '^STATUS:' "$PKT")
prc=$?
[ "$prc" -le 1 ] || err "packet STATUS-line count failed (grep exit $prc)"
[ "$pst" = "1" ] || err "$PKT must contain exactly one line beginning 'STATUS:' (found $pst)"
grep '^STATUS:' "$PKT" > "$tmpdir/cs.pkt.status"
prc=$?
[ "$prc" -le 1 ] || err "packet STATUS-line extraction failed (grep exit $prc)"
printf '%s\n' 'STATUS: OWNER-AUTHORIZED DECISION INPUT ONLY — NON-NORMATIVE — OD-08 OPEN — ALL OPTIONS UNSELECTED — THIS PACKET GRANTS NO RIGHTS — NO ROLE APPOINTED OR CHANNEL CONFIGURED — NO RELEASE OR GATE CHANGE.' > "$tmpdir/cs.pkt.status.expected" \
  || err "packet expected-status generation failed (fail-closed)"
cmp -s "$tmpdir/cs.pkt.status.expected" "$tmpdir/cs.pkt.status"
pcmp=$?
[ "$pcmp" -eq 0 ] || err "$PKT STATUS line is not exactly the mandatory banner as a full line (cmp exit $pcmp)"
# Closed-world OD08 question set: every row-leading token must satisfy
# the complete anchored 3-cell row grammar (ID cell, pipe-free subject
# cell, exact unanswered response cell); IDs are derived only from
# fully valid rows and must be exactly 001..015; every OD08-Q-
# occurrence anywhere in the packet is enumerated by an awk substring
# loop and must total exactly 15, so a second token smuggled onto one
# line (which line-based grep -c cannot see) also fails.
qpre=$(grep -c '^| OD08-Q-' "$PKT")
prc=$?
[ "$prc" -le 1 ] || err "packet question row-prefix count failed (grep exit $prc)"
qval=$(grep -cE '^\| OD08-Q-[0-9][0-9][0-9] \| [^|]* \| OWNER RESPONSE REQUIRED — UNSELECTED \|$' "$PKT")
prc=$?
[ "$prc" -le 1 ] || err "packet valid full-row grammar count failed (grep exit $prc)"
[ "$qpre" = "$qval" ] || err "$PKT has $qpre question-prefix rows but only $qval satisfy the exact anchored 3-cell row grammar: malformed question row (extra pipe cell, altered response cell, or bad ID)"
[ "$qval" = "15" ] || err "$PKT must contain exactly 15 fully valid question rows (found $qval)"
awk 'BEGIN { n = 0 }
  { s = $0
    while ((i = index(s, "OD08-Q-")) > 0) { n = n + 1; s = substr(s, i + 7) } }
  END { print n }' "$PKT" > "$tmpdir/cs.q.tok"
prc=$?
[ "$prc" -eq 0 ] || err "packet OD08-Q- occurrence enumeration failed (awk exit $prc)"
qtok=$(cat "$tmpdir/cs.q.tok") || err "packet OD08-Q- occurrence read-back failed (fail-closed)"
[ "$qtok" = "15" ] || err "$PKT contains $qtok OD08-Q- occurrences, expected exactly 15: smuggled, duplicated, or same-line extra question token"
sed -n 's/^| \(OD08-Q-[0-9][0-9][0-9]\) | [^|]* | OWNER RESPONSE REQUIRED — UNSELECTED |$/\1/p' "$PKT" > "$tmpdir/cs.q.actual"
prc=$?
[ "$prc" -eq 0 ] || err "packet question-token extraction failed (sed exit $prc)"
[ -s "$tmpdir/cs.q.actual" ] || err "$PKT contains no valid OD08 question rows (fail-closed)"
: > "$tmpdir/cs.q.expected" || err "packet expected question-list init failed"
qi=1
while [ "$qi" -le 15 ]; do
  printf 'OD08-Q-%03d\n' "$qi" >> "$tmpdir/cs.q.expected" \
    || err "packet expected question-list generation failed at $qi"
  qi=$((qi + 1))
done
LC_ALL=C sort "$tmpdir/cs.q.actual" > "$tmpdir/cs.q.sorted" \
  || err "packet question sort failed (fail-closed)"
cmp -s "$tmpdir/cs.q.expected" "$tmpdir/cs.q.sorted"
pcmp=$?
[ "$pcmp" -eq 0 ] || err "$PKT question set is not exactly OD08-Q-001..015 (cmp exit $pcmp)"
qresp=$(grep -cF ' | OWNER RESPONSE REQUIRED — UNSELECTED |' "$PKT")
prc=$?
[ "$prc" -le 1 ] || err "packet unanswered-response count failed (grep exit $prc)"
[ "$qresp" = "15" ] || err "$PKT does not have exactly 15 lines carrying the exact unanswered response cell (found $qresp): filled, malformed, or extra owner response"
grep -F 'DEFER — REMAINS OPEN' "$PKT" >/dev/null \
  || err "$PKT missing the explicit DEFER — REMAINS OPEN instruction"
grep -F 'An owner answer to any question is direction input only. Partial answers leave' "$PKT" >/dev/null \
  || err "$PKT missing the direction-input-only / partial-answers caveat"
grep -F 'All 15 questions are separately answerable' "$PKT" >/dev/null \
  || err "$PKT missing the separately-answerable statement"
# Key verified facts, candidates and caveats (exact strings).
grep -F 'Publication is not authorized by QK-AUTH-OD08-PKT-001' "$PKT" >/dev/null \
  || err "$PKT missing the publication-not-authorized statement"
grep -F 'Preparation of this packet was authorized by the owner record' "$PKT" >/dev/null \
  || err "$PKT missing the preparation-only authorization statement"
grep -F 'the repository has no selected project license' "$PKT" >/dev/null \
  || err "$PKT missing the no-selected-license fact"
grep -F 'No project-applied `SPDX-License-Identifier` header, manifest license field, or' "$PKT" >/dev/null \
  || err "$PKT missing the project-applied-SPDX-scoped fact"
grep -F 'cite third-party license identifiers for provenance without' "$PKT" >/dev/null \
  || err "$PKT missing the Source-Register third-party-identifier boundary"
grep -F 'zero third-party/registry dependencies' "$PKT" >/dev/null \
  || err "$PKT missing the zero-third-party-dependency fact"
grep -F 'one first-party path dependency on `host/qk-host-model`' "$PKT" >/dev/null \
  || err "$PKT missing the first-party path-dependency fact"
grep -F '`publish = false`' "$PKT" >/dev/null \
  || err "$PKT missing the publish=false fact"
grep -F '1adce1afa1e6cf6cc22287af54c2a7a3a8e2458e' "$PKT" >/dev/null \
  || err "$PKT missing the historical MIT-introduction commit fact"
grep -F '8f7ce227db21299d831636243ab76b110a875f73' "$PKT" >/dev/null \
  || err "$PKT missing the historical MIT-removal commit fact"
grep -F 'removal revoked any rights' "$PKT" >/dev/null \
  || err "$PKT missing the no-revocation-claim caveat"
grep -F 'Git author labels are commit metadata only' "$PKT" >/dev/null \
  || err "$PKT missing the author-labels-not-title caveat"
grep -F 'not legal advice' "$PKT" >/dev/null \
  || err "$PKT missing the not-legal-advice caveat"
grep -F 'Every row below has status UNSELECTED.' "$PKT" >/dev/null \
  || err "$PKT missing the all-rows-UNSELECTED statement"
grep -F 'Apache-2.0, only after rights/legal review' "$PKT" >/dev/null \
  || err "$PKT missing the software starting recommendation"
grep -F 'MIT; MPL-2.0' "$PKT" >/dev/null \
  || err "$PKT missing the software alternatives"
grep -F 'CHOICE of either license; it does not automatically apply both' "$PKT" >/dev/null \
  || err "$PKT missing the MIT-OR-Apache recipient-choice explanation"
grep -F 'CERN-OHL-W-2.0' "$PKT" >/dev/null \
  || err "$PKT missing the hardware starting recommendation"
grep -F 'CERN-OHL-P-2.0; CERN-OHL-S-2.0' "$PKT" >/dev/null \
  || err "$PKT missing the hardware alternatives"
grep -F 'No safety certification exists or is implied' "$PKT" >/dev/null \
  || err "$PKT missing the no-safety-certification caveat"
grep -F 'CC-BY-4.0' "$PKT" >/dev/null \
  || err "$PKT missing the documentation starting recommendation"
grep -F 'CC-BY-SA-4.0' "$PKT" >/dev/null \
  || err "$PKT missing the documentation alternative"
grep -F 'recommends against applying CC licenses to software' "$PKT" >/dev/null \
  || err "$PKT missing the Creative-Commons-recommendation caveat"
grep -F 'software documentation may use CC' "$PKT" >/dev/null \
  || err "$PKT missing the software-documentation-may-use-CC clause"
grep -F 'code snippets mixed into documentation must be handled separately' "$PKT" >/dev/null \
  || err "$PKT missing the mixed-code-snippet caveat"
grep -F 'CC0-1.0 where legally effective' "$PKT" >/dev/null \
  || err "$PKT missing the data starting candidate"
grep -F 'need explicit classification' "$PKT" >/dev/null \
  || err "$PKT missing the ancillary-classification requirement"
grep -F 'A separately enacted inbound=outbound rule, plus DCO 1.1 sign-off' "$PKT" >/dev/null \
  || err "$PKT missing the contributions starting recommendation"
grep -F 'certification of submission authority, not an inbound license' "$PKT" >/dev/null \
  || err "$PKT missing the DCO-is-not-a-license clarification"
grep -F 'CLA only if a specific need justifies it' "$PKT" >/dev/null \
  || err "$PKT missing the CLA-only-if-justified caveat"
grep -F 'the author plus two independent human approvers' "$PKT" >/dev/null \
  || err "$PKT missing the protected-change approval rule"
grep -F 'at least one non-author reviewer' "$PKT" >/dev/null \
  || err "$PKT missing the routine-change reviewer rule"
grep -F 'protected changes remain blocked' "$PKT" >/dev/null \
  || err "$PKT missing the absent-staffing blocked rule"
grep -F 'it is not enabled by this packet' "$PKT" >/dev/null \
  || err "$PKT missing the private-reporting evaluated-not-enabled caveat"
grep -F 'No versions of any kind are supported; no security-support promise or policy is approved.' "$PKT" >/dev/null \
  || err "$PKT missing the exact no-supported-versions fact"
grep -F 'a tag ref is not inherently immutable' "$PKT" >/dev/null \
  || err "$PKT missing the tag-ref-not-immutable qualification"
grep -F 'reproducible-build match' "$PKT" >/dev/null \
  || err "$PKT missing the reproducible-build release element"
grep -F 'both independent of every material artifact preparer or builder' "$PKT" >/dev/null \
  || err "$PKT missing the releaser-independence rule"
grep -F 'JOINTLY binds the exact annotated tag object, the exact commit SHA, every artifact digest, and the provenance/reproducible-build record' "$PKT" >/dev/null \
  || err "$PKT missing the joint-binding release manifest/attestation requirement"
grep -F 'a signed release manifest or attestation' "$PKT" >/dev/null \
  || err "$PKT missing the signed release manifest/attestation element"
grep -F 'never closes a gate or accepts residual risk' "$PKT" >/dev/null \
  || err "$PKT missing the audit-never-closes-gates rule"
grep -F 'an open or CC license alone does not settle mark use' "$PKT" >/dev/null \
  || err "$PKT missing the trademark-separation caveat"
grep -F '(three people)' "$PKT" >/dev/null \
  || err "$PKT missing the three-person protected-review count"
grep -F 'no self-review, no shared account' "$PKT" >/dev/null \
  || err "$PKT missing the independence definition"
grep -F 'non-exclusive and non-exhaustive' "$PKT" >/dev/null \
  || err "$PKT missing the non-exclusive classification note"
grep -F 'mixed-content boundaries' "$PKT" >/dev/null \
  || err "$PKT missing the mixed-content-boundaries note"
grep -F 'moral-right consents or waivers where legally possible' "$PKT" >/dev/null \
  || err "$PKT missing the moral-rights element"
grep -F 'database rights where applicable' "$PKT" >/dev/null \
  || err "$PKT missing the database-rights element"
grep -F 'makes no legal conclusion' "$PKT" >/dev/null \
  || err "$PKT missing the no-legal-conclusion statement"
grep -F 'waiver plus a fallback public license' "$PKT" >/dev/null \
  || err "$PKT missing the CC0 waiver/fallback explanation"
grep -F 'does not settle patent or trademark rights' "$PKT" >/dev/null \
  || err "$PKT missing the CC0 patent/trademark caveat"
grep -F 'No auditor is appointed' "$PKT" >/dev/null \
  || err "$PKT missing the no-auditor-appointed statement"
grep -F 'Closing OD-08 requires a' "$PKT" >/dev/null \
  || err "$PKT missing the later-explicit-owner-record closure rule"
grep -F 'separately authorized application chain' "$PKT" >/dev/null \
  || err "$PKT missing the separate-application-chain rule"
grep -F 'no Source Register row is added' "$PKT" >/dev/null \
  || err "$PKT missing the no-source-register-row statement"
# Informational links: closed-world URL allowlist. Each of the 15
# exact labeled bullets must appear exactly once as a full line; every
# https:// occurrence anywhere in the packet is enumerated by an awk
# substring loop and must total exactly 15, so an unlabeled URL, an
# extra URL, or two URLs on one line all fail.
purl=$(grep -c '^- https://' "$PKT")
prc=$?
[ "$prc" -le 1 ] || err "packet URL-line count failed (grep exit $prc)"
plab=$(grep -c '^- https://.* — UNPINNED / INFORMATIONAL ONLY / NO TEXT IMPORTED$' "$PKT")
prc=$?
[ "$prc" -le 1 ] || err "packet labeled-URL count failed (grep exit $prc)"
[ "$purl" = "15" ] || err "$PKT must list exactly 15 informational URL bullets (found $purl)"
[ "$purl" = "$plab" ] || err "$PKT has $purl URL lines but only $plab carry the exact UNPINNED/INFORMATIONAL/NO-TEXT label"
awk 'BEGIN { n = 0 }
  { s = $0
    while ((i = index(s, "https://")) > 0) { n = n + 1; s = substr(s, i + 8) } }
  END { print n }' "$PKT" > "$tmpdir/cs.url.tok"
prc=$?
[ "$prc" -eq 0 ] || err "packet https:// occurrence enumeration failed (awk exit $prc)"
utok=$(cat "$tmpdir/cs.url.tok") || err "packet https:// occurrence read-back failed (fail-closed)"
[ "$utok" = "15" ] || err "$PKT contains $utok https:// occurrences, expected exactly 15: extra, smuggled, or same-line additional URL"
cat > "$tmpdir/cs.url.exp" <<'EOF'
- https://spdx.org/licenses/ — UNPINNED / INFORMATIONAL ONLY / NO TEXT IMPORTED
- https://www.apache.org/licenses/LICENSE-2.0 — UNPINNED / INFORMATIONAL ONLY / NO TEXT IMPORTED
- https://opensource.org/license/mit — UNPINNED / INFORMATIONAL ONLY / NO TEXT IMPORTED
- https://www.mozilla.org/en-US/MPL/2.0/ — UNPINNED / INFORMATIONAL ONLY / NO TEXT IMPORTED
- https://cern-ohl.web.cern.ch/ — UNPINNED / INFORMATIONAL ONLY / NO TEXT IMPORTED
- https://creativecommons.org/licenses/by/4.0/legalcode.en — UNPINNED / INFORMATIONAL ONLY / NO TEXT IMPORTED
- https://creativecommons.org/licenses/by-sa/4.0/legalcode.en — UNPINNED / INFORMATIONAL ONLY / NO TEXT IMPORTED
- https://creativecommons.org/publicdomain/zero/1.0/legalcode.en — UNPINNED / INFORMATIONAL ONLY / NO TEXT IMPORTED
- https://creativecommons.org/faq/#can-i-apply-a-creative-commons-license-to-software — UNPINNED / INFORMATIONAL ONLY / NO TEXT IMPORTED
- https://developercertificate.org/ — UNPINNED / INFORMATIONAL ONLY / NO TEXT IMPORTED
- https://opensource.org/osd — UNPINNED / INFORMATIONAL ONLY / NO TEXT IMPORTED
- https://docs.github.com/en/code-security/how-tos/report-and-fix-vulnerabilities/configure-vulnerability-reporting — UNPINNED / INFORMATIONAL ONLY / NO TEXT IMPORTED
- https://docs.github.com/en/authentication/managing-commit-signature-verification/signing-tags — UNPINNED / INFORMATIONAL ONLY / NO TEXT IMPORTED
- https://docs.github.com/en/repositories/configuring-branches-and-merges-in-your-repository/managing-rulesets/available-rules-for-rulesets — UNPINNED / INFORMATIONAL ONLY / NO TEXT IMPORTED
- https://doc.rust-lang.org/cargo/reference/manifest.html — UNPINNED / INFORMATIONAL ONLY / NO TEXT IMPORTED
EOF
while IFS= read -r ubl; do
  ucnt=$(grep -cFx -e "$ubl" "$PKT")
  prc=$?
  [ "$prc" -le 1 ] || err "packet URL-bullet check failed (grep exit $prc)"
  [ "$ucnt" = "1" ] || err "$PKT does not contain exactly once (found $ucnt): $ubl"
done < "$tmpdir/cs.url.exp"
# License/claim/material guards over the packet (fail-closed forbid).
# The packet legitimately NAMES the backticked `SPDX-License-Identifier`
# header in its no-project-applied-header fact; only the colon-suffixed
# applied-tag form is forbidden.
forbid "$PKT contains an applied SPDX license identifier tag" \
  -F 'SPDX-License-Identifier:' "$PKT"
forbid "$PKT contains copied MIT license text" \
  -F 'Permission is hereby granted' "$PKT"
forbid "$PKT contains copied Apache license application text" \
  -F 'Licensed under the Apache License' "$PKT"
forbid "$PKT contains a mailto channel" \
  -F 'mailto:' "$PKT"
forbid "$PKT contains an email address" \
  -E '[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z][A-Za-z]' "$PKT"
forbid "$PKT contains a long secret-like hex run (>= 64 hex chars)" \
  -E '[0-9a-fA-F]{64}' "$PKT"
forbid "$PKT contains extended-key-like material" \
  -E '(^|[^A-Za-z0-9])[xt](prv|pub)[A-Za-z0-9]{20,}' "$PKT"
forbid "$PKT contains bech32-address-like material" \
  -E '(^|[^0-9a-z])[b]c1[02-9ac-hj-np-z]{20,}' "$PKT"
forbid "$PKT contains raw PSBT material" \
  -E '[c]HNidP|[7]0736274ff' "$PKT"
# Base64-blob guard: enumerate every base64-alphabet run of 44+ chars
# (awk length test, no interval regex, no pipeline); legitimate prose
# slash-lists (lowercase words joined by /) are tolerated, but any
# such run carrying a digit or '+' is treated as payload material.
awk '{ s = $0
  while (match(s, /[A-Za-z0-9+\/]+/)) {
    t = substr(s, RSTART, RLENGTH)
    if (length(t) >= 44) print t
    s = substr(s, RSTART + RLENGTH) } }' "$PKT" > "$tmpdir/cs.b64runs"
prc=$?
[ "$prc" -eq 0 ] || err "packet base64-run enumeration failed (awk exit $prc; empty output is legitimate and distinguished from error)"
grep '[0-9+]' "$tmpdir/cs.b64runs" > "$tmpdir/cs.b64bad"
prc=$?
[ "$prc" -le 1 ] || err "packet base64-run classification failed (grep exit $prc)"
[ ! -s "$tmpdir/cs.b64bad" ] || err "$PKT contains a base64 payload blob: $(cat "$tmpdir/cs.b64bad")"
forbid "$PKT claims OD-08 is resolved or closed" \
  -iE 'OD-08 (is |was |has been |now )?(resolved|closed)' "$PKT"
forbid "$PKT claims a license was selected, adopted, applied or granted" \
  -iE '(license|licence) (is|was|has been|hereby) (selected|adopted|applied|granted)' "$PKT"
forbid "$PKT performs a hereby-style grant, appointment or activation" \
  -iE 'hereby (grant|license|appoint|configure|enable)' "$PKT"
forbid "$PKT claims production readiness" \
  -iE 'production[- ]ready' "$PKT"
forbid "$PKT claims a validated, secure or audited status" \
  -iE '(is|are) (fully )?(validated|secure|audited)' "$PKT"
forbid "$PKT claims a closed gate" \
  -iE 'Gate [A-E][^.]*CLOSED' "$PKT"
forbid "$PKT contains a checked checkbox" \
  -E '\[[xX]\]' "$PKT"
# Stale or overbroad wording rejected by the independent audit.
forbid "$PKT claims publication was authorized together with preparation" \
  -F 'Preparation and publication' "$PKT"
forbid "$PKT overclaims that no SPDX expression exists anywhere" \
  -F 'no SPDX expression exist anywhere' "$PKT"
forbid "$PKT overclaims no external dependency" \
  -F 'no external dependency' "$PKT"
forbid "$PKT uses the categorical CC-not-suitable-for-software wording" \
  -F 'licenses are not suitable for software' "$PKT"
forbid "$PKT conflates DCO with an inbound=outbound license rule" \
  -F 'DCO 1.1 with inbound=outbound' "$PKT"
forbid "$PKT claims an inherently immutable signed tag" \
  -F 'immutable signed tag' "$PKT"
forbid "$PKT uses the stale sole-artifact-preparer wording" \
  -F 'sole artifact preparer' "$PKT"
forbid "$PKT links the stale signing-commits page instead of signing-tags" \
  -F 'managing-commit-signature-verification/signing-commits' "$PKT"
# ------------- Host verifier: byte identity and reanchor-only proof
# The active host verifier must be byte-identical to reviewed B, and
# its entire e81->B delta must be confined to lines carrying the old
# or new Decision-Log anchor SHA (exactly 3 removed / 3 added lines).
$GIT show "$C21:tools/verify-host-boundary.sh" > "$tmpdir/cs.hb.b" 2>/dev/null \
  || err "cannot read tools/verify-host-boundary.sh from C21"
$GIT show "$C27:tools/verify-host-boundary.sh" > "$tmpdir/cs.hb.b27" 2>/dev/null \
  || err "cannot read tools/verify-host-boundary.sh from C27"
cmp -s "$tmpdir/cs.hb.b27" tools/verify-host-boundary.sh
pkc=$?
[ "$pkc" -eq 0 ] || err "tools/verify-host-boundary.sh is not byte-identical to the reviewed C27 (F3.2b B) version (cmp exit $pkc)"
# Reanchor-plus-single-file-set proof: the delta from the published
# C25 host verifier to the reviewed C27 version must equal the exact
# minimal transcript embedded below — the three Decision-Log-anchor
# advances plus the one owner-authorized tracked-file-set line for the
# F3.2b packet, and nothing else.
$GIT show "$C25:tools/verify-host-boundary.sh" > "$tmpdir/cs.hb.base" 2>/dev/null \
  || err "cannot read tools/verify-host-boundary.sh from C25"
diff "$tmpdir/cs.hb.base" tools/verify-host-boundary.sh > "$tmpdir/cs.hb.d" 2>&1
hbd=$?
[ "$hbd" -eq 1 ] || err "host-verifier C25 delta diff did not report exactly a difference (diff exit $hbd)"
cat > "$tmpdir/cs.hb.d.expected" <<'QK_HB_DIFF_EOF' || err "expected host-verifier delta transcript generation failed (fail-closed)"
71a72
> docs/f3/F3.2B-PSBT-DECISION-PACKET.md
1229c1230
< git --no-optional-locks show e29359bd0dac2892f0d3291a9ec4a11b758513f9:docs/DECISION-LOG.md > "$tmpdir/dlog.a" 2>/dev/null \
---
> git --no-optional-locks show 9e30750ebf85a17884624c0697cc0ef14a7bafe3:docs/DECISION-LOG.md > "$tmpdir/dlog.a" 2>/dev/null \
1374c1375
< #   e29359bd0dac2892f0d3291a9ec4a11b758513f9  reviewed OD-08 owner-response authorization commit A (Decision-Log byte-identity anchor in this script)
---
> #   9e30750ebf85a17884624c0697cc0ef14a7bafe3  reviewed F3.2b decision-packet authorization commit A (Decision-Log byte-identity anchor in this script)
1383a1385
>     9e30750ebf85a17884624c0697cc0ef14a7bafe3 \
1385,1386c1387
<     de71c22328b24e0848bbe1bd12ac8974ca83b5b8 \
<     e29359bd0dac2892f0d3291a9ec4a11b758513f9
---
>     de71c22328b24e0848bbe1bd12ac8974ca83b5b8
QK_HB_DIFF_EOF
cmp -s "$tmpdir/cs.hb.d.expected" "$tmpdir/cs.hb.d"
hbd=$?
[ "$hbd" -eq 0 ] || err "host-verifier C25-to-C27 delta is not the exact minimal anchor-advance-plus-file-set transcript (cmp exit $hbd): $(cat "$tmpdir/cs.hb.d")"
grep -F "show $C26:docs/DECISION-LOG.md" tools/verify-host-boundary.sh >/dev/null \
  || err "host checker Decision-Log anchor is not the F3.2b A commit"
# ------------------------- SOURCE-REGISTER byte-identical to e81/C19
$GIT show "$C19:docs/SOURCE-REGISTER.md" > "$tmpdir/cs.sreg.c19" 2>/dev/null \
  || err "cannot read docs/SOURCE-REGISTER.md from C19"
cmp -s "$tmpdir/cs.sreg.c19" docs/SOURCE-REGISTER.md
pkc=$?
[ "$pkc" -eq 0 ] || err "docs/SOURCE-REGISTER.md is not byte-identical to the published C19 version (cmp exit $pkc)"
# ------------------- Exact e81..HEAD changed path set (exactly five)
cat > "$tmpdir/cs.od08.exp" <<'EOF'
docs/DECISION-LOG.md
docs/OD-08-DECISION-PACKET.md
docs/OD-08-OWNER-RESPONSE-RECORD.md
docs/f3/F3.2B-PSBT-DECISION-PACKET.md
tools/verify-current-stage.sh
tools/verify-host-boundary.sh
EOF
$GIT diff --name-only "$C19" "$head" > "$tmpdir/cs.od08.raw" \
  || err "git diff C19..HEAD failed (enumeration fail-closed)"
[ -s "$tmpdir/cs.od08.raw" ] || err "git diff C19..HEAD returned no paths (enumeration fail-closed)"
LC_ALL=C sort "$tmpdir/cs.od08.raw" > "$tmpdir/cs.od08.act" \
  || err "C19..HEAD path-set sort failed (fail-closed)"
diff "$tmpdir/cs.od08.exp" "$tmpdir/cs.od08.act" > "$tmpdir/cs.od08.dd" 2>&1 \
  || err "changes since published C19 differ from the six authorized OD-08 and F3.2b paths: $(cat "$tmpdir/cs.od08.dd")"
# --------- Exact C22..HEAD changed path set (exactly four, this chain)
cat > "$tmpdir/cs.rspset.exp" <<'EOF'
docs/DECISION-LOG.md
docs/OD-08-OWNER-RESPONSE-RECORD.md
docs/f3/F3.2B-PSBT-DECISION-PACKET.md
tools/verify-current-stage.sh
tools/verify-host-boundary.sh
EOF
$GIT diff --name-only "$C22" "$head" > "$tmpdir/cs.rspset.raw" \
  || err "git diff C22..HEAD failed (enumeration fail-closed)"
[ -s "$tmpdir/cs.rspset.raw" ] || err "git diff C22..HEAD returned no paths (enumeration fail-closed)"
LC_ALL=C sort "$tmpdir/cs.rspset.raw" > "$tmpdir/cs.rspset.act" \
  || err "C22..HEAD path-set sort failed (fail-closed)"
diff "$tmpdir/cs.rspset.exp" "$tmpdir/cs.rspset.act" > "$tmpdir/cs.rspset.dd" 2>&1 \
  || err "changes since published C22 differ from the five authorized owner-response and F3.2b chain paths: $(cat "$tmpdir/cs.rspset.dd")"
# --------- Exact C25..HEAD changed path set (exactly four, this chain)
cat > "$tmpdir/cs.f32bset.exp" <<'EOF'
docs/DECISION-LOG.md
docs/f3/F3.2B-PSBT-DECISION-PACKET.md
tools/verify-current-stage.sh
tools/verify-host-boundary.sh
EOF
$GIT diff --name-only "$C25" "$head" > "$tmpdir/cs.f32bset.raw" \
  || err "git diff C25..HEAD failed (enumeration fail-closed)"
[ -s "$tmpdir/cs.f32bset.raw" ] || err "git diff C25..HEAD returned no paths (enumeration fail-closed)"
LC_ALL=C sort "$tmpdir/cs.f32bset.raw" > "$tmpdir/cs.f32bset.act" \
  || err "C25..HEAD path-set sort failed (fail-closed)"
diff "$tmpdir/cs.f32bset.exp" "$tmpdir/cs.f32bset.act" > "$tmpdir/cs.f32bset.dd" 2>&1 \
  || err "changes since published C25 differ from the four authorized F3.2b chain paths: $(cat "$tmpdir/cs.f32bset.dd")"
# Every other tracked blob — the PSBT draft, F3 README, wallet-trust
# spine, SOURCE-REGISTER, OPEN-DECISIONS, OD-08 docs, architecture,
# requirements, security docs, gates, limits, tests, evidence, code,
# manifests/lock, .replit and all the rest — is therefore
# byte-identical to the published C25 state.
# --------------------------------------- Verifier executable modes
# Fail-closed mode guard: both verifier scripts must be executable in
# the working tree, and their committed modes at HEAD must be exactly
# 100755. Separate rc-checked git ls-tree stages plus checked
# read/extraction stages; missing, duplicate, malformed, or
# non-100755 results are all rejected. Like every other check in this
# script, this is self-referential supporting evidence with the same
# self-authentication limits: a hostile history could carry a guard
# that lies about itself; independent audit remains required.
[ -x tools/verify-current-stage.sh ] || err "working-tree tools/verify-current-stage.sh is not executable"
[ -x tools/verify-host-boundary.sh ] || err "working-tree tools/verify-host-boundary.sh is not executable"
for modepath in tools/verify-current-stage.sh tools/verify-host-boundary.sh; do
  $GIT ls-tree HEAD -- "$modepath" > "$tmpdir/cs.mode.raw" \
    || err "git ls-tree HEAD failed for $modepath (fail-closed)"
  [ -s "$tmpdir/cs.mode.raw" ] || err "committed mode entry missing for $modepath (fail-closed)"
  modelines=$(awk 'BEGIN { n = 0 } { n = n + 1 } END { print n }' "$tmpdir/cs.mode.raw") \
    || err "committed mode line count failed for $modepath (awk fail-closed)"
  [ "$modelines" = "1" ] || err "committed mode entry for $modepath is not exactly one ls-tree line (found $modelines)"
  modeval=$(awk 'NR == 1 { print $1 }' "$tmpdir/cs.mode.raw") \
    || err "committed mode extraction failed for $modepath (awk fail-closed)"
  case "$modeval" in
    100755) : ;;
    '') err "committed mode for $modepath is empty or malformed (fail-closed)" ;;
    *) err "committed mode for $modepath is $modeval, expected exactly 100755" ;;
  esac
done

# ---------------- OD-08 owner-response record (QK-AUTH-OD08-RSP-001)
# Non-enacting direction-input record: byte-bound to reviewed commit
# C24, closed-world question-row set, recorded-state proof, and
# license/material/claim guards. Lexical evidence only; nothing here
# proves legal status, ownership, or enactment.
RSP=docs/OD-08-OWNER-RESPONSE-RECORD.md
[ -f "$RSP" ] || err "$RSP missing"
$GIT show "$C24:$RSP" > "$tmpdir/cs.rsp.b" 2>/dev/null \
  || err "cannot read $RSP from C24"
cmp -s "$tmpdir/cs.rsp.b" "$RSP"
rspk=$?
[ "$rspk" -eq 0 ] || err "$RSP is not byte-identical to the reviewed C24 (OD-08 RSP B) version (cmp exit $rspk)"
rfirst=$(head -n 1 "$RSP") || err "owner-response record first-line read failed (fail-closed)"
[ "$rfirst" = "EXPERIMENTAL — NO REAL FUNDS — NOT A WALLET" ] \
  || err "$RSP does not begin with the exact no-funds warning"
rstc=$(grep -cFx -e 'STATUS: OWNER RESPONSES RECORDED — NON-BINDING DIRECTION INPUT ONLY — OD-08 OPEN — NO PROJECT LICENSE, SPDX EXPRESSION, OR POLICY SELECTED, APPLIED, OR GRANTED — NO RIGHTS GRANTED — NO ROLE, CHANNEL, REPOSITORY SETTING, SUPPORT PROMISE, RELEASE, OR GATE CHANGE ENACTED — BELGIAN/EU LEGAL REVIEW REQUIRED.' "$RSP")
rstrc=$?
[ "$rstrc" -le 1 ] || err "owner-response STATUS full-line count failed (grep exit $rstrc)"
[ "$rstc" = "1" ] || err "$RSP exact STATUS line not present exactly once (found $rstc)"
rstp=$(grep -c '^STATUS:' "$RSP")
rstrc=$?
[ "$rstrc" -le 1 ] || err "owner-response STATUS prefix count failed (grep exit $rstrc)"
[ "$rstp" = "1" ] || err "$RSP must contain exactly one STATUS line (found $rstp)"
rendc=$(grep -cFx -e 'END OF OWNER-RESPONSE RECORD — OD-08 REMAINS OPEN — BELGIAN LEGAL REVIEW AND SEPARATE OWNER AUTHORIZATION ARE REQUIRED BEFORE ANY APPLICATION.' "$RSP")
rstrc=$?
[ "$rstrc" -le 1 ] || err "owner-response terminal-line count failed (grep exit $rstrc)"
[ "$rendc" = "1" ] || err "$RSP exact terminal line not present exactly once (found $rendc)"
rlast=$(tail -n 1 "$RSP") || err "owner-response record last-line read failed (fail-closed)"
[ "$rlast" = "END OF OWNER-RESPONSE RECORD — OD-08 REMAINS OPEN — BELGIAN LEGAL REVIEW AND SEPARATE OWNER AUTHORIZATION ARE REQUIRED BEFORE ANY APPLICATION." ] \
  || err "$RSP does not end with the exact terminal line"
# Closed-world question-ID occurrence enumeration: rc-checked single
# POSIX awk stage counts EVERY substring occurrence of "OD08-Q-"
# anywhere in the record, so a same-line smuggled reference cannot
# hide from line-based greps.
rqocc=$(awk 'BEGIN { n = 0 } { s = $0
  while ((i = index(s, "OD08-Q-")) > 0) { n = n + 1; s = substr(s, i + 7) } }
  END { print n }' "$RSP") \
  || err "owner-response question-token enumeration failed (awk fail-closed)"
[ "$rqocc" = "15" ] || err "$RSP must contain exactly 15 OD08-Q- occurrences anywhere (found $rqocc)"
# Every question row matches the full three-cell grammar with the
# exact recorded state and a pipe-free single-line response cell.
grep '^| OD08-Q-' "$RSP" > "$tmpdir/cs.rsp.rows"
rstrc=$?
[ "$rstrc" -le 1 ] || err "owner-response row extraction failed (grep exit $rstrc)"
rrows=$(grep -c '^| OD08-Q-' "$RSP")
rstrc=$?
[ "$rstrc" -le 1 ] || err "owner-response row count failed (grep exit $rstrc)"
[ "$rrows" = "15" ] || err "$RSP must contain exactly 15 question rows (found $rrows)"
rbad=$(grep -c -v -E '^\| OD08-Q-[0-9][0-9][0-9] \| [^|]+ \| RECORDED — DIRECTION INPUT ONLY — NOT ENACTED \|$' "$tmpdir/cs.rsp.rows")
rstrc=$?
[ "$rstrc" -le 1 ] || err "owner-response row grammar scan failed (grep exit $rstrc)"
[ "$rbad" = "0" ] || err "$RSP contains $rbad question rows that violate the exact three-cell recorded-state grammar"
# IDs exactly 001..015, generated expected list, sorted, cmp.
sed -e 's/^| \(OD08-Q-[0-9][0-9][0-9]\) |.*$/\1/' "$tmpdir/cs.rsp.rows" > "$tmpdir/cs.rsp.ids.raw" \
  || err "owner-response ID extraction failed (fail-closed)"
LC_ALL=C sort "$tmpdir/cs.rsp.ids.raw" > "$tmpdir/cs.rsp.ids" \
  || err "owner-response ID sort failed (fail-closed)"
awk 'BEGIN { for (i = 1; i <= 15; i = i + 1) printf "OD08-Q-%03d\n", i }' > "$tmpdir/cs.rsp.ids.exp" \
  || err "owner-response expected-ID generation failed (awk fail-closed)"
ridexp=$(awk 'BEGIN { n = 0 } /./ { n = n + 1 } END { print n }' "$tmpdir/cs.rsp.ids.exp") \
  || err "owner-response expected-ID count stage failed (awk fail-closed)"
[ "$ridexp" = "15" ] || err "owner-response expected-ID file must contain exactly 15 lines (found $ridexp): generation was partial, empty, or corrupted"
cmp -s "$tmpdir/cs.rsp.ids.exp" "$tmpdir/cs.rsp.ids"
rspk=$?
[ "$rspk" -eq 0 ] || err "$RSP question IDs are not exactly OD08-Q-001..OD08-Q-015 in a duplicate-free set (cmp exit $rspk)"
# Rows appear in declared 001..015 order (unsorted extraction equals
# the generated expected order).
cmp -s "$tmpdir/cs.rsp.ids.exp" "$tmpdir/cs.rsp.ids.raw"
rspk=$?
[ "$rspk" -eq 0 ] || err "$RSP question rows are not in exact OD08-Q-001..015 order (cmp exit $rspk)"
# Each complete literal row exactly once (grep -Fxc), checked against
# an INDEPENDENT embedded expected transcript of all 15 rows — not
# derived from the record under test — with rc-checked heredoc
# creation, an exact-15-nonempty-line precondition, and an exact
# processed count after the loop.
cat > "$tmpdir/cs.rsp.rows.exp" <<'QK_RSP_ROWS_EOF' || err "expected owner-response row-transcript generation failed (fail-closed)"
| OD08-Q-001 | OWNER ATTESTATION ONLY — NOT INDEPENDENTLY VERIFIED — PARTIAL: As of the published parent identified in QK-AUTH-OD08-RSP-001, Jeroen Vande Voorde attests, based on personal knowledge, that he claims to be the sole known and disclosed human rightsholder and reports no other known human contributor or claimant. He reports that he is not aware of incorporated copied or adapted third-party material; cited sources are references only, and citation supplies neither permission nor title. Service, agent, and synthetic Git identities and their terms, employment and contract history, copyright, patent, database, moral-right, trademark, historical-title, and contributor-consent questions remain evidence and Belgian-counsel dependencies. | RECORDED — DIRECTION INPUT ONLY — NOT ENACTED |
| OD08-Q-002 | OWNER CLASSIFICATION PRINCIPLE RECORDED — PARTIAL, NOT A COMMIT-BOUND PATH MAP: software includes Rust, scripts, manifests, and configuration; documentation includes specifications and docs; future CAD, schematics, PCB, and BOM material is hardware-design material; vectors, fixtures, and datasets are data; logos, artwork, fonts, gateware, and manufacturing outputs are separate and deferred. Cited sources remain third-party and outside any future grant unless separately cleared; citations do not import source material or rights. An exact commit-bound nonexclusive per-path map, mixed-content handling, future paths, and exclusions remain required before any separate selection or application. | RECORDED — DIRECTION INPUT ONLY — NOT ENACTED |
| OD08-Q-003 | PREFERRED FUTURE CANDIDATE FOR LATER SEPARATE SELECTION: Apache-2.0 for later enumerated rights-cleared first-party software, subject to rights evidence, an exact path map, and written Belgian counsel review. This record does not select, apply, or grant it. | RECORDED — DIRECTION INPUT ONLY — NOT ENACTED |
| OD08-Q-004 | PREFERRED FUTURE CANDIDATE FOR LATER SEPARATE SELECTION: CERN-OHL-W-2.0 for later enumerated rights-cleared hardware-design sources, subject to rights evidence, an exact path map, and written Belgian counsel review. It is not a safety certification. This record does not select, apply, or grant it. | RECORDED — DIRECTION INPUT ONLY — NOT ENACTED |
| OD08-Q-005 | PREFERRED FUTURE CANDIDATE FOR LATER SEPARATE SELECTION: CC-BY-4.0 for later enumerated rights-cleared first-party documentation, not software, subject to rights evidence, an exact path map, and written Belgian counsel review. This record does not select, apply, or grant it. | RECORDED — DIRECTION INPUT ONLY — NOT ENACTED |
| OD08-Q-006 | PREFERRED FUTURE CANDIDATE FOR LATER SEPARATE SELECTION: unmodified CC0-1.0, including its built-in fallback, for later enumerated rights-cleared public first-party vectors and data. Whether a separately selected alternative is needed where CC0 is unsuitable remains open; fixtures and every other deferred asset class remain open; CC0 does not affect patents or trademarks. This record does not select, apply, or grant it. | RECORDED — DIRECTION INPUT ONLY — NOT ENACTED |
| OD08-Q-007 | CURRENT REPOSITORY FACT AT THE PUBLISHED PARENT: no contribution or inbound policy is enacted, so no external submission can be treated as accepted under one. FUTURE POLICY PREFERENCE: initially decline external code, design, and documentation contributions. If later opened by separate enactment, use verbatim DCO 1.1 plus a separate explicit inbound-equals-outbound rule; the DCO is a certification, not a license, assignment, or grant. No CLA is selected by this response. This record neither opens nor closes contribution intake. | RECORDED — DIRECTION INPUT ONLY — NOT ENACTED |
| OD08-Q-008 | INTENDED FUTURE NOMINEE ONLY: Jeroen Vande Voorde as primary maintainer. This record appoints no operational role. Backup remains unappointed; operating scope, least privilege, succession, removal, and conflict rules remain open. | RECORDED — DIRECTION INPUT ONLY — NOT ENACTED |
| OD08-Q-009 | PREFERRED PROSPECTIVE GOVERNANCE STANDARD FOR LATER SEPARATE ENACTMENT: routine changes require one independent human reviewer; protected security, release, license, and governance changes require the author plus two independent human approvers. Current staffing is not established; under any later-enacted standard, solo routine work and protected work or release without the required independent humans would remain blocked; agents and bots do not count as human approvers; no break-glass route is selected. This supplies no retroactive validation and enacts no setting. | RECORDED — DIRECTION INPUT ONLY — NOT ENACTED |
| OD08-Q-010 | PREFERRED FUTURE MECHANISM: GitHub private vulnerability reporting, which may be separately enabled only after a named human owner and backup plus monitoring, access, retention, acknowledgement, escalation, and disclosure procedures exist. Satisfying those prerequisites does not itself enable it. This record creates or enables no channel or setting; the published repository documentation records none configured, but repository content cannot prove hosting-platform state. | RECORDED — DIRECTION INPUT ONLY — NOT ENACTED |
| OD08-Q-011 | PREFERRED FUTURE RELEASE CONTROL FOR LATER SEPARATE SELECTION AND ENACTMENT: two authorized human releasers, each independent of every material artifact preparer or builder; reproducible-build match; a signed annotated tag plus a signed manifest or attestation jointly binding the exact tag object ID, exact commit SHA, every artifact digest, and the provenance and reproducible-build record; a protected release ref or external transparency anchor; public verification; and separated key custody, backup, rotation, revocation, and compromise procedures. Exact people, reviewer/releaser overlap, signing scheme, and operational details remain open. No control is enabled and no release exists. | RECORDED — DIRECTION INPUT ONLY — NOT ENACTED |
| OD08-Q-012 | VERIFIED REPOSITORY FACT AT THE PUBLISHED PARENT: no tag, release, supported version of any kind, approved support policy, or security-support promise exists. OWNER DIRECTION INPUT: a separately enacted no-support notice should be published and retained until a separately approved supported release exists. Future support window, EOL, backport, and notification rules remain open. This record enacts no notice or support policy. | RECORDED — DIRECTION INPUT ONLY — NOT ENACTED |
| OD08-Q-013 | INTENDED FUTURE COORDINATOR NOMINEE ONLY: Jeroen Vande Voorde. Substantive audits require an independent qualified reviewer. Coordination does not appoint Jeroen, qualify him as the independent reviewer, permit suppression of findings, close a gate, or accept residual risk. Reviewer, conflict-disclosure rules, scope, remediation, retest, and publication process remain open; no auditor or audit process is appointed or activated. | RECORDED — DIRECTION INPUT ONLY — NOT ENACTED |
| OD08-Q-014 | DESIRED FUTURE SEPARATE TRADEMARK AND OFFICIAL-BUILD POLICY: Jeroen Vande Voorde is the intended controller, subject to legal clearance. No present ownership, registration, exclusivity, or enforceability is claimed. Lawful nominative and customary references remain permitted without implied endorsement. No copyright or open-content grant itself conveys trademark, endorsement, or official-build permission except where an applicable license or law requires or permits it. Nothing is applied. | RECORDED — DIRECTION INPUT ONLY — NOT ENACTED |
| OD08-Q-015 | OWNER DIRECTION INPUT: review by counsel qualified in Belgian and EU intellectual-property law. This does not select Belgian governing law, forum, or jurisdiction for any license or policy. No effective date, retroactivity, or historical scope is selected. Written counsel review and sign-off must be tied to the exact evidence and any proposed application. Any later application acts only through an exact, separately authorized commit and path map. This record asserts no revocation, rescission, narrowing, replacement, or alteration of rights recipients may have obtained under historical MIT-published versions. | RECORDED — DIRECTION INPUT ONLY — NOT ENACTED |
QK_RSP_ROWS_EOF
rexp=$(awk 'BEGIN { n = 0 } /./ { n = n + 1 } END { print n }' "$tmpdir/cs.rsp.rows.exp") \
  || err "expected owner-response row-transcript count stage failed (awk fail-closed)"
[ "$rexp" = "15" ] || err "expected owner-response row-transcript file must contain exactly 15 nonempty lines (found $rexp): generation was partial, empty, or corrupted"
rowproc=0
while IFS= read -r rrow; do
  rowc=$(grep -Fxc -e "$rrow" "$RSP")
  rstrc=$?
  [ "$rstrc" -le 1 ] || err "owner-response complete-row check failed (grep exit $rstrc)"
  [ "$rowc" = "1" ] || err "owner-response record does not contain the expected complete literal row exactly once (found $rowc): $rrow"
  rowproc=$((rowproc + 1))
done < "$tmpdir/cs.rsp.rows.exp"
[ "$rowproc" = "15" ] || err "owner-response expected-row loop processed $rowproc of 15 expected rows (fail-closed)"
# Exactly 15 recorded-state cells anywhere (substring enumeration).
rsc=$(awk 'BEGIN { n = 0 } { s = $0
  while ((i = index(s, "| RECORDED — DIRECTION INPUT ONLY — NOT ENACTED |")) > 0) { n = n + 1; s = substr(s, i + 1) } }
  END { print n }' "$RSP") \
  || err "owner-response state-cell enumeration failed (awk fail-closed)"
[ "$rsc" = "15" ] || err "$RSP must contain exactly 15 exact recorded-state cells (found $rsc)"
rsumc=$(grep -cFx -e 'Summary: 15 response rows recorded. Several responses are partial and contain deferred or open matters; 0 questions closed; OD-08 remains OPEN in full.' "$RSP")
rstrc=$?
[ "$rstrc" -le 1 ] || err "owner-response summary-line count failed (grep exit $rstrc)"
[ "$rsumc" = "1" ] || err "$RSP exact summary line not present exactly once (found $rsumc)"
# Positive limitation and open-dependency assertions (full lines).
grep -Fx -e '- This record is not legal advice and contains no legal conclusion.' "$RSP" >/dev/null \
  || err "$RSP missing the exact not-legal-advice line"
grep -Fx -e '- Owner statements and owner choices recorded here are direction input only; they are not independent legal verification of any fact, right, or title.' "$RSP" >/dev/null \
  || err "$RSP missing the exact no-independent-verification line"
grep -Fx -e '- Git metadata, hosting-service metadata, and agent metadata are not chain-of-title proof.' "$RSP" >/dev/null \
  || err "$RSP missing the exact metadata-not-title-proof line"
grep -Fx -e '- No response in this record closes OD-08; OD-08 remains OPEN in full.' "$RSP" >/dev/null \
  || err "$RSP missing the exact no-closure line"
grep -F 'preserved byte-for-byte, including all of its original placeholder cells' "$RSP" >/dev/null \
  || err "$RSP missing the packet byte-preservation statement"
grep -Fx -e '## Remaining open dependencies' "$RSP" >/dev/null \
  || err "$RSP missing the remaining-open-dependencies section heading"
grep -Fx -e '- written review and sign-off by counsel qualified in Belgian and EU intellectual-property law' "$RSP" >/dev/null \
  || err "$RSP missing the Belgian/EU-counsel open dependency"
grep -Fx -e '- later owner closure decision and still-later separately authorized application chain' "$RSP" >/dev/null \
  || err "$RSP missing the closure-and-application-chain open dependency"
grep -Fx -e '- independent chain-of-title and rights evidence' "$RSP" >/dev/null \
  || err "$RSP missing the chain-of-title open dependency"
grep -Fx -e '- a later explicit license and policy selection/closure record before any application' "$RSP" >/dev/null \
  || err "$RSP missing the later-selection-record open dependency"
# Required exact attestation-only prefix (Q001) and no-selection
# sentence (Q015), each present as a substring exactly once.
rq1c=$(grep -cF -e 'OWNER ATTESTATION ONLY — NOT INDEPENDENTLY VERIFIED — PARTIAL:' "$RSP")
rstrc=$?
[ "$rstrc" -le 1 ] || err "Q001 attestation-prefix count failed (grep exit $rstrc)"
[ "$rq1c" = "1" ] || err "$RSP Q001 exact attestation-only prefix not present exactly once (found $rq1c)"
rq15c=$(grep -cF -e 'This does not select Belgian governing law, forum, or jurisdiction for any license or policy.' "$RSP")
rstrc=$?
[ "$rstrc" -le 1 ] || err "Q015 no-selection-sentence count failed (grep exit $rstrc)"
[ "$rq15c" = "1" ] || err "$RSP Q015 exact no-governing-law/forum/jurisdiction sentence not present exactly once (found $rq15c)"
grep -Fx -e 'OD-08 remains OPEN.' "$RSP" >/dev/null \
  || err "$RSP missing the exact OD-08-remains-OPEN line"
# Forbidden content in the record.
forbid "$RSP applies an SPDX expression" -F 'SPDX-License-Identifier:' "$RSP"
forbid "$RSP contains an email-like locator" -E '[A-Za-z0-9._%+-][A-Za-z0-9._%+-]*@[A-Za-z0-9.-][A-Za-z0-9.-]*\.[A-Za-z]' "$RSP"
forbid "$RSP contains a checked task box" -F '[x]' "$RSP"
forbid "$RSP claims OD-08 is closed" -F 'OD-08 is CLOSED' "$RSP"
forbid "$RSP claims OD-08 is resolved" -F 'OD-08 is RESOLVED' "$RSP"
forbid "$RSP imports actual license text" -F 'Apache License, Version 2.0, January 2004' "$RSP"
forbid "$RSP imports actual license text preamble" -F 'TERMS AND CONDITIONS FOR USE, REPRODUCTION, AND DISTRIBUTION' "$RSP"
forbid "$RSP carries the stale sole-artifact-preparer wording" -F 'sole artifact preparer' "$RSP"
forbid "$RSP carries the stale contributions-closed-now phrasing" -F 'External contributions are closed now' "$RSP"
forbid "$RSP carries the stale present-direction-and-fact phrasing" -F 'Present direction and fact' "$RSP"
forbid "$RSP carries the stale supported-versions phrasing" -F 'zero supported production versions' "$RSP"
forbid "$RSP carries the stale summary line" -F 'Summary: 15 recorded, 0 deferred, 0 unanswered.' "$RSP"
forbid "$RSP carries the stale partially-unverified phrasing" -F 'PARTIALLY UNVERIFIED' "$RSP"
forbid "$RSP carries the stale license-direction phrasing" -F 'Future software-license direction is' "$RSP"
forbid "$RSP contains an uppercase checked task box" -F '[X]' "$RSP"
forbid "$RSP claims a role was actually appointed" -F 'is hereby appointed' "$RSP"
forbid "$RSP claims a channel or setting is now enabled" -F 'is now enabled' "$RSP"
forbid "$RSP claims a channel or setting has been enabled" -F 'has been enabled' "$RSP"
# Long-hex payload guard: no 40+ hex run may appear in the record at
# all (the record cites no commit hashes by design). Fail-closed:
# the awk stage writes to a checked temporary file; any awk failure
# is an error, and the file must exist and be empty.
awk '{ s = $0
  while (match(s, /[0-9a-fA-F]+/)) {
    t = substr(s, RSTART, RLENGTH)
    if (length(t) >= 40) print t
    s = substr(s, RSTART + RLENGTH) } }' "$RSP" > "$tmpdir/cs.rsp.hex" \
  || err "owner-response hex-run scan failed (awk fail-closed)"
[ -f "$tmpdir/cs.rsp.hex" ] || err "owner-response hex-run scan produced no output file (fail-closed)"
[ ! -s "$tmpdir/cs.rsp.hex" ] || err "$RSP contains a 40+ character hex run (raw payload guard): $(cat "$tmpdir/cs.rsp.hex")"
# Base64-like payload guard: run-enumeration flagging EVERY run of 44
# or more base64-alphabet characters, including all-letter runs.
# Same fail-closed checked-file pattern.
awk '{ s = $0
  while (match(s, /[A-Za-z0-9+\/=]+/)) {
    t = substr(s, RSTART, RLENGTH)
    if (length(t) >= 44) print t
    s = substr(s, RSTART + RLENGTH) } }' "$RSP" > "$tmpdir/cs.rsp.b64" \
  || err "owner-response base64-run scan failed (awk fail-closed)"
[ -f "$tmpdir/cs.rsp.b64" ] || err "owner-response base64-run scan produced no output file (fail-closed)"
[ ! -s "$tmpdir/cs.rsp.b64" ] || err "$RSP contains a base64-like payload run: $(cat "$tmpdir/cs.rsp.b64")"
# The response record intentionally contains no URL, wallet-material
# token, PSBT payload, or checkbox of either case. Each scan below is
# an rc-checked grep stage (exit 0 or 1 only) writing to a checked
# temporary file that must be empty. Exact coverage: URL schemes and
# bech32-like prefixes are matched case-insensitively; extended-key
# prefixes cover x/y/z/t/u/v pub and prv in any letter case, each
# requiring a 6+ character Base58 tail so ordinary prose cannot
# false-match; WIF-like tokens cover mainnet prefixes 5/K/L and
# testnet prefixes 9/c with Base58 bodies of both applicable total
# lengths (51 and 52); the PSBT guards match the fixed base64 and
# raw-hex magic prefixes only.
rscan() {
  rsmsg=$1; rsopt=$2; rspat=$3; rsout=$4
  grep "$rsopt" -e "$rspat" "$RSP" > "$tmpdir/$rsout"
  rsrc=$?
  [ "$rsrc" -le 1 ] || err "owner-response $rsmsg scan failed (grep exit $rsrc)"
  [ -f "$tmpdir/$rsout" ] || err "owner-response $rsmsg scan produced no output file (fail-closed)"
  [ ! -s "$tmpdir/$rsout" ] || err "$RSP contains forbidden $rsmsg content: $(cat "$tmpdir/$rsout")"
}
rscan "http-URL" -iF 'http://' cs.rsp.urlh
rscan "https-URL" -iF 'https://' cs.rsp.urls
rscan "lowercase-checkbox" -F '[x]' cs.rsp.cbl
rscan "uppercase-checkbox" -F '[X]' cs.rsp.cbu
rscan "extended-key-material" -iE '[xyztuv](pub|prv)[1-9A-HJ-NP-Za-km-z]{6}' cs.rsp.xkey
rscan "WIF-like-material" -E '[5KL9c][1-9A-HJ-NP-Za-km-z]{50,51}' cs.rsp.wif
rscan "bech32-address-material" -iE '(bc1|tb1|bcrt1)[ac-hj-np-z02-9]{8}' cs.rsp.bech
rscan "PSBT-base64-material" -F 'cHNidP' cs.rsp.psbtb
rscan "PSBT-hex-material" -F '70736274' cs.rsp.psbth

# ---------------- F3.2b PSBT decision packet (QK-AUTH-F3.2B-PKT-001)
# Non-binding decision-input packet: byte-bound to reviewed commit
# C27, closed-world 13-row ledger and 4-row question set from
# independent embedded transcripts, boundary-phrase requirements, and
# material/claim guards. Lexical evidence only; nothing here accepts a
# profile or proves any technical property.
FPKT=docs/f3/F3.2B-PSBT-DECISION-PACKET.md
[ -f "$FPKT" ] || err "$FPKT missing"
$GIT show "$C27:$FPKT" > "$tmpdir/cs.fp.b" 2>/dev/null \
  || err "cannot read $FPKT from C27"
cmp -s "$tmpdir/cs.fp.b" "$FPKT"
fpk=$?
[ "$fpk" -eq 0 ] || err "$FPKT is not byte-identical to the reviewed C27 (F3.2b B) version (cmp exit $fpk)"
ffirst=$(head -n 1 "$FPKT") || err "F3.2b packet first-line read failed (fail-closed)"
[ "$ffirst" = "EXPERIMENTAL — NO REAL FUNDS — NOT A WALLET" ] \
  || err "$FPKT does not begin with the exact no-funds warning"
fstc=$(grep -cFx -e 'STATUS: OWNER-AUTHORIZED DECISION INPUT ONLY — NON-NORMATIVE — F3.2b PACKET PREPARATION ONLY — PSBT PROFILE NOT ACCEPTED — NO CLAUSE OR OWNER-OPEN D-ITEM SELECTED — RECORDED D-01, D-03, D-08, AND D-12 DIRECTIONS PRESERVED AS NON-NORMATIVE — D-05 FUTURE-ONLY RECIPIENT-P2TR DIRECTION PRESERVED — ALL FOUR OWNER QUESTIONS UNANSWERED — NO IMPLEMENTATION — NO VECTORS GENERATED OR RUN — NO LICENSE APPLICATION — NO HARDWARE OR SETTINGS CHANGE — GATES A–E OPEN — LOCAL AND UNPUBLISHED.' "$FPKT")
fsrc=$?
[ "$fsrc" -le 1 ] || err "F3.2b STATUS full-line count failed (grep exit $fsrc)"
[ "$fstc" = "1" ] || err "$FPKT exact STATUS line not present exactly once (found $fstc)"
fstp=$(grep -c '^STATUS:' "$FPKT")
fsrc=$?
[ "$fsrc" -le 1 ] || err "F3.2b STATUS prefix count failed (grep exit $fsrc)"
[ "$fstp" = "1" ] || err "$FPKT must contain exactly one STATUS line (found $fstp)"
flast=$(tail -n 1 "$FPKT") || err "F3.2b packet last-line read failed (fail-closed)"
[ "$flast" = "END OF PACKET — F3.2b NON-BINDING DECISION INPUT ONLY — PSBT PROFILE NOT ACCEPTED — FOUR OWNER RESPONSES, ALL BLOCKED PREREQUISITES, AND A SEPARATE PROFILE-ACCEPTANCE ACT REMAIN REQUIRED." ] \
  || err "$FPKT does not end with the exact terminal line"
fendc=$(grep -cFx -e 'END OF PACKET — F3.2b NON-BINDING DECISION INPUT ONLY — PSBT PROFILE NOT ACCEPTED — FOUR OWNER RESPONSES, ALL BLOCKED PREREQUISITES, AND A SEPARATE PROFILE-ACCEPTANCE ACT REMAIN REQUIRED.' "$FPKT")
fsrc=$?
[ "$fsrc" -le 1 ] || err "F3.2b terminal-line count failed (grep exit $fsrc)"
[ "$fendc" = "1" ] || err "$FPKT exact terminal line not present exactly once (found $fendc)"
# Closed-world ledger: every D-token occurrence anywhere counted by an
# rc-checked awk substring loop (same-line smuggling visible), exact
# 13 rows in exact order equal to the independent transcript below.
fdocc=$(awk 'BEGIN { n = 0 } { s = $0
  while ((i = index(s, "F32B-PSBT-D-")) > 0) { n = n + 1; s = substr(s, i + 12) } }
  END { print n }' "$FPKT") \
  || err "F3.2b ledger-token enumeration failed (awk fail-closed)"
[ "$fdocc" = "13" ] || err "$FPKT must contain exactly 13 F32B-PSBT-D- occurrences anywhere (found $fdocc)"
grep '^| F32B-PSBT-D-' "$FPKT" > "$tmpdir/cs.fp.drows"
fsrc=$?
[ "$fsrc" -le 1 ] || err "F3.2b ledger row extraction failed (grep exit $fsrc)"
cat > "$tmpdir/cs.fp.drows.exp" <<'QK_F32B_DROWS_EOF' || err "expected F3.2b ledger-row transcript generation failed (fail-closed)"
| F32B-PSBT-D-00 | D-00 | BLOCKED — MUST NOT ACCEPT — PREREQUISITES OPEN — PROFILE NOT ACCEPTED |
| F32B-PSBT-D-01 | D-01 | OWNER DIRECTION RECORDED — CLAUSE REMAINS PROPOSED — PROFILE NOT ACCEPTED |
| F32B-PSBT-D-02 | D-02 | OWNER RESPONSE REQUIRED — UNSELECTED — PROFILE NOT ACCEPTED |
| F32B-PSBT-D-03 | D-03 | OWNER DIRECTION RECORDED — CLAUSE REMAINS PROPOSED — PROFILE NOT ACCEPTED |
| F32B-PSBT-D-04 | D-04 | OWNER-OPEN — NOT POSED IN THIS PACKET — CORPUS REVIEW REQUIRED BEFORE SELECTION — PROFILE NOT ACCEPTED |
| F32B-PSBT-D-05 | D-05 | OWNER RESPONSE REQUIRED FOR PRESENT PROFILE — FUTURE-ONLY P2TR DIRECTION RECORDED — PROFILE NOT ACCEPTED |
| F32B-PSBT-D-06 | D-06 | OWNER RESPONSE REQUIRED — UNSELECTED — PROFILE NOT ACCEPTED |
| F32B-PSBT-D-07 | D-07 | EVIDENCE/CONSTRUCTION-BLOCKED — NO RESPONSE REQUESTED — PROFILE NOT ACCEPTED |
| F32B-PSBT-D-08 | D-08 | OWNER DIRECTION RECORDED — CLAUSE REMAINS PROPOSED — PROFILE NOT ACCEPTED |
| F32B-PSBT-D-09 | D-09 | EVIDENCE/CONSTRUCTION-BLOCKED — NO RESPONSE REQUESTED — PROFILE NOT ACCEPTED |
| F32B-PSBT-D-10 | D-10 | OWNER RESPONSE REQUIRED — UNSELECTED — PROFILE NOT ACCEPTED |
| F32B-PSBT-D-11 | D-11 | EVIDENCE/CONSTRUCTION-BLOCKED — NO RESPONSE REQUESTED — PROFILE NOT ACCEPTED |
| F32B-PSBT-D-12 | D-12 | OWNER DIRECTION RECORDED — CLAUSE REMAINS PROPOSED — PROFILE NOT ACCEPTED |
QK_F32B_DROWS_EOF
fdexp=$(awk 'BEGIN { n = 0 } /./ { n = n + 1 } END { print n }' "$tmpdir/cs.fp.drows.exp") \
  || err "expected F3.2b ledger-row count stage failed (awk fail-closed)"
[ "$fdexp" = "13" ] || err "expected F3.2b ledger-row transcript must contain exactly 13 nonempty lines (found $fdexp): generation was partial, empty, or corrupted"
cmp -s "$tmpdir/cs.fp.drows.exp" "$tmpdir/cs.fp.drows"
fpk=$?
if [ "$fpk" -ne 0 ]; then
  diff "$tmpdir/cs.fp.drows.exp" "$tmpdir/cs.fp.drows" > "$tmpdir/cs.fp.drows.dd" 2>&1
  fddrc=$?
  [ "$fddrc" -le 1 ] || err "F3.2b ledger-row diagnostic diff stage failed (diff exit $fddrc)"
  head -n 4 "$tmpdir/cs.fp.drows.dd" > "$tmpdir/cs.fp.drows.dd4" \
    || err "F3.2b ledger-row diagnostic head stage failed (fail-closed)"
  err "$FPKT ledger rows are not exactly the 13 expected rows in exact order (cmp exit $fpk): $(cat "$tmpdir/cs.fp.drows.dd4")"
fi
fdproc=0
while IFS= read -r fdrow; do
  fdc=$(grep -Fxc -e "$fdrow" "$FPKT")
  fsrc=$?
  [ "$fsrc" -le 1 ] || err "F3.2b complete-ledger-row check failed (grep exit $fsrc)"
  [ "$fdc" = "1" ] || err "F3.2b packet does not contain the expected complete literal ledger row exactly once (found $fdc): $fdrow"
  fdproc=$((fdproc + 1))
done < "$tmpdir/cs.fp.drows.exp"
[ "$fdproc" = "13" ] || err "F3.2b ledger-row loop processed $fdproc of 13 expected rows (fail-closed)"
# Closed-world question set: token enumeration (4 rows + 4 headings =
# exactly 8 anywhere), exact 4 rows in exact order, exact heading
# lines, exactly 4 placeholder response cells, no other response.
fqocc=$(awk 'BEGIN { n = 0 } { s = $0
  while ((i = index(s, "F32B-PSBT-Q-")) > 0) { n = n + 1; s = substr(s, i + 12) } }
  END { print n }' "$FPKT") \
  || err "F3.2b question-token enumeration failed (awk fail-closed)"
[ "$fqocc" = "8" ] || err "$FPKT must contain exactly 8 F32B-PSBT-Q- occurrences anywhere (4 rows + 4 headings; found $fqocc)"
grep '^| F32B-PSBT-Q-' "$FPKT" > "$tmpdir/cs.fp.qrows"
fsrc=$?
[ "$fsrc" -le 1 ] || err "F3.2b question row extraction failed (grep exit $fsrc)"
cat > "$tmpdir/cs.fp.qrows.exp" <<'QK_F32B_QROWS_EOF' || err "expected F3.2b question-row transcript generation failed (fail-closed)"
| F32B-PSBT-Q-001 | D-02 | OWNER RESPONSE REQUIRED — UNSELECTED |
| F32B-PSBT-Q-002 | present-profile D-05 | OWNER RESPONSE REQUIRED — UNSELECTED |
| F32B-PSBT-Q-003 | D-06 | OWNER RESPONSE REQUIRED — UNSELECTED |
| F32B-PSBT-Q-004 | D-10 | OWNER RESPONSE REQUIRED — UNSELECTED |
QK_F32B_QROWS_EOF
fqexp=$(awk 'BEGIN { n = 0 } /./ { n = n + 1 } END { print n }' "$tmpdir/cs.fp.qrows.exp") \
  || err "expected F3.2b question-row count stage failed (awk fail-closed)"
[ "$fqexp" = "4" ] || err "expected F3.2b question-row transcript must contain exactly 4 nonempty lines (found $fqexp): generation was partial, empty, or corrupted"
cmp -s "$tmpdir/cs.fp.qrows.exp" "$tmpdir/cs.fp.qrows"
fpk=$?
if [ "$fpk" -ne 0 ]; then
  diff "$tmpdir/cs.fp.qrows.exp" "$tmpdir/cs.fp.qrows" > "$tmpdir/cs.fp.qrows.dd" 2>&1
  fddrc=$?
  [ "$fddrc" -le 1 ] || err "F3.2b question-row diagnostic diff stage failed (diff exit $fddrc)"
  head -n 4 "$tmpdir/cs.fp.qrows.dd" > "$tmpdir/cs.fp.qrows.dd4" \
    || err "F3.2b question-row diagnostic head stage failed (fail-closed)"
  err "$FPKT question rows are not exactly the 4 expected rows in exact order (cmp exit $fpk): $(cat "$tmpdir/cs.fp.qrows.dd4")"
fi
fqproc=0
while IFS= read -r fqrow; do
  fqc=$(grep -Fxc -e "$fqrow" "$FPKT")
  fsrc=$?
  [ "$fsrc" -le 1 ] || err "F3.2b complete-question-row check failed (grep exit $fsrc)"
  [ "$fqc" = "1" ] || err "F3.2b packet does not contain the expected complete literal question row exactly once (found $fqc): $fqrow"
  fqproc=$((fqproc + 1))
done < "$tmpdir/cs.fp.qrows.exp"
[ "$fqproc" = "4" ] || err "F3.2b question-row loop processed $fqproc of 4 expected rows (fail-closed)"
fpcell=$(awk 'BEGIN { n = 0 } { s = $0
  while ((i = index(s, "| OWNER RESPONSE REQUIRED — UNSELECTED |")) > 0) { n = n + 1; s = substr(s, i + 1) } }
  END { print n }' "$FPKT") \
  || err "F3.2b placeholder-cell enumeration failed (awk fail-closed)"
[ "$fpcell" = "4" ] || err "$FPKT must contain exactly 4 exact placeholder response cells (found $fpcell)"
grep -Fx -e '### F32B-PSBT-Q-001 — D-02: PSBT_GLOBAL_XPUB policy' "$FPKT" >/dev/null \
  || err "$FPKT missing the exact Q-001 heading"
grep -Fx -e '### F32B-PSBT-Q-002 — present-profile D-05: recipient output classes' "$FPKT" >/dev/null \
  || err "$FPKT missing the exact Q-002 heading"
grep -Fx -e '### F32B-PSBT-Q-003 — D-06: change and self-transfer classification' "$FPKT" >/dev/null \
  || err "$FPKT missing the exact Q-003 heading"
grep -Fx -e '### F32B-PSBT-Q-004 — D-10: signing artifact boundary' "$FPKT" >/dev/null \
  || err "$FPKT missing the exact Q-004 heading"
# Required standing, candidate, and boundary phrases (exact counts).
fcnt() {
  fcmsg=$1; fcexp=$2; fcpat=$3
  fcn=$(grep -cF -e "$fcpat" "$FPKT")
  fcrc=$?
  [ "$fcrc" -le 1 ] || err "F3.2b $fcmsg count failed (grep exit $fcrc)"
  [ "$fcn" = "$fcexp" ] || err "$FPKT $fcmsg: expected exactly $fcexp occurrences, found $fcn"
}
fcnt "recommended-candidate labels" 4 'RECOMMENDED CANDIDATE — UNSELECTED:'
fcnt "later-owner-question labels" 4 'Later owner question (exact):'
fcnt "dependencies-and-stops labels" 4 'Dependencies and stops:'
fcnt "defer-option sentence" 1 'A later owner answer to any single question may also be exactly DEFER — REMAINS OPEN.'
fcnt "no-response-recorded sentence" 1 'This packet records no response of any kind for any question.'
fcnt "no-blocked-question sentence" 1 'There is no question for D-00, D-04, D-07, D-09, or D-11.'
fcnt "parent-binding line" 1 'Bound parent commit: `a9840819eba4d1b98b8346fc0ae0b44f611a45c5`.'
fcnt "no-amendment sentence" 1 'it amends nothing and supersedes nothing.'
fcnt "answers-cannot-accept sentence" 1 'those answers cannot accept the PSBT profile and cannot resolve D-00.'
fcnt "full-comparison boundary" 1 'never fingerprint alone'
fcnt "signer-only boundary" 1 'not a Finalizer or Extractor'
fcnt "exact-witnessScript construction" 1 'sortedmulti(2,A,B,C)'
fcnt "P2TR-not-an-option sentence" 1 'Accepting P2TR as a current recipient class is not an option in this packet.'
fcnt "proof-limits sentence" 1 'not key possession, spendability, freshness, intent, chain state, or non-reuse'
fcnt "PSBT-019/PLAN-028 flag" 1 'the PSBT-019 conservative fallback wording versus the PLAN-028 wording; no draft edit is made now.'
fcnt "D-00 blockers heading" 1 '## D-00 blockers (repeated from the parent draft)'
fcnt "D-00 must-not-accept sentence" 1 'D-00 must not be accepted while any of the following remains open:'
fcnt "deferred-and-blocked section heading" 1 '## Deferred owner-open and blocked items (no response requested)'
fcnt "D-04 not-posed bullet" 1 'D-04 remains owner-open and is deliberately not posed in this packet. Representative coordinator-corpus review must precede any later selection.'
fcnt "D-04 bounded-preservation clause" 1 'Bounded preservation cannot be selected or accepted without exact structural validation and an accepted full-commitment/round-trip design.'
fcnt "D-02 map-absence wording" 1 'Absence of every PSBT_GLOBAL_XPUB entry is valid'
fcnt "D-02 comparison-baseline wording" 1 'D is only the trusted local comparison baseline for metadata consistency, and signing authority still requires the authorized factor ceremony and physical approval.'
fcnt "D-06 witness-script boundary" 1 'PSBT_OUT_WITNESS_SCRIPT is unnecessary. If present, it is accepted only with a complete D-derived candidate and must byte-match the independently derived witnessScript; otherwise the PSBT rejects.'
fcnt "D-06 class-3 fallback wording" 1 'Missing, coherent-but-incomplete, or unrelated structurally valid output BIP32-derivation metadata yields class 3.'
fcnt "D-10 no-additional-artifact-class wording" 1 'No additional artifact class is allowed while inherited transport encodings remain unchanged.'
fcnt "D-10 route-set undecided wording" 1 'does not decide route, route set, naming,'
fcnt "D-07 blocked bullet" 1 'D-07 remains blocked pending target-platform and human-factors QK-LIM evidence'
fcnt "D-09 blocked bullet" 1 'D-09 remains blocked pending the exact commitment construction'
fcnt "D-11 blocked bullet" 1 'D-11 remains blocked pending the media and write lifecycle definition'
fcnt "no-selectable-blocked sentence" 1 'None of these four items is a selectable question in this packet, and this packet requests no owner response for any of them.'
# 40-hex runs: exactly one, and it must be the bound parent SHA.
awk '{ s = $0
  while (match(s, /[0-9a-fA-F]+/)) {
    t = substr(s, RSTART, RLENGTH)
    if (length(t) >= 40) print t
    s = substr(s, RSTART + RLENGTH) } }' "$FPKT" > "$tmpdir/cs.fp.hex" \
  || err "F3.2b hex-run scan failed (awk fail-closed)"
[ -f "$tmpdir/cs.fp.hex" ] || err "F3.2b hex-run scan produced no output file (fail-closed)"
fhexn=$(awk 'BEGIN { n = 0 } /./ { n = n + 1 } END { print n }' "$tmpdir/cs.fp.hex") \
  || err "F3.2b hex-run count stage failed (awk fail-closed)"
[ "$fhexn" = "1" ] || err "$FPKT must contain exactly one 40+ hex run (the bound parent); found $fhexn"
printf '%s\n' 'a9840819eba4d1b98b8346fc0ae0b44f611a45c5' > "$tmpdir/cs.fp.hex.exp" \
  || err "F3.2b expected-hex generation failed (fail-closed)"
cmp -s "$tmpdir/cs.fp.hex.exp" "$tmpdir/cs.fp.hex"
fpk=$?
[ "$fpk" -eq 0 ] || err "$FPKT 40+ hex run is not exactly the bound parent SHA (cmp exit $fpk): $(cat "$tmpdir/cs.fp.hex")"
# Base64-alphabet payload guard: EVERY run of 44 or more characters,
# including all-letter runs, is forbidden (the 40-hex parent SHA is
# shorter than 44 and cannot satisfy this).
awk '{ s = $0
  while (match(s, /[A-Za-z0-9+\/=]+/)) {
    t = substr(s, RSTART, RLENGTH)
    if (length(t) >= 44) print t
    s = substr(s, RSTART + RLENGTH) } }' "$FPKT" > "$tmpdir/cs.fp.b64" \
  || err "F3.2b base64-run scan failed (awk fail-closed)"
[ -f "$tmpdir/cs.fp.b64" ] || err "F3.2b base64-run scan produced no output file (fail-closed)"
[ ! -s "$tmpdir/cs.fp.b64" ] || err "$FPKT contains a base64-like payload run: $(cat "$tmpdir/cs.fp.b64")"
# Zero-content scans over the packet. Same rc-checked checked-file
# mechanics and exact coverage as the owner-response rscan set above,
# plus an email guard and a Base58 address-like guard.
fscan() {
  fsmsg=$1; fsopt=$2; fspat=$3; fsout=$4
  grep "$fsopt" -e "$fspat" "$FPKT" > "$tmpdir/$fsout"
  fsrc2=$?
  [ "$fsrc2" -le 1 ] || err "F3.2b $fsmsg scan failed (grep exit $fsrc2)"
  [ -f "$tmpdir/$fsout" ] || err "F3.2b $fsmsg scan produced no output file (fail-closed)"
  [ ! -s "$tmpdir/$fsout" ] || err "$FPKT contains forbidden $fsmsg content: $(cat "$tmpdir/$fsout")"
}
fscan "http-URL" -iF 'http://' cs.fp.urlh
fscan "https-URL" -iF 'https://' cs.fp.urls
fscan "email-like-locator" -E '[A-Za-z0-9._%+-][A-Za-z0-9._%+-]*@[A-Za-z0-9.-][A-Za-z0-9.-]*\.[A-Za-z]' cs.fp.mail
fscan "lowercase-checkbox" -F '[x]' cs.fp.cbl
fscan "uppercase-checkbox" -F '[X]' cs.fp.cbu
fscan "extended-key-material" -iE '[xyztuv](pub|prv)[1-9A-HJ-NP-Za-km-z]{6}' cs.fp.xkey
fscan "WIF-like-material" -E '[5KL9c][1-9A-HJ-NP-Za-km-z]{50,51}' cs.fp.wif
fscan "bech32-address-material" -iE '(bc1|tb1|bcrt1)[ac-hj-np-z02-9]{8}' cs.fp.bech
fscan "base58-address-material" -E '(^|[^1-9A-HJ-NP-Za-km-z])[13mn2][1-9A-HJ-NP-Za-km-z]{25,34}' cs.fp.b58
fscan "generic-URI-scheme" -E '[A-Za-z][A-Za-z0-9+.-]*://' cs.fp.uri
fscan "PSBT-base64-material" -F 'cHNidP' cs.fp.psbtb
fscan "PSBT-hex-material" -F '70736274' cs.fp.psbth
# Affirmative-claim, promotion, reopening, and status guards. Each is
# a fail-closed forbid over verb phrases so the packet's explicit
# negative statements cannot false-match.
forbid "$FPKT makes an affirmative acceptance/approval/completion claim" \
  -iE '(profile|packet|clause|bundle|candidate|option|question|response|D-0[0-9]|D-1[0-2]) (is|are|now|been|hereby) (accepted|approved|implemented|validated|conformant|complete|production[- ]ready)' "$FPKT"
forbid "$FPKT claims something is normative" -iE '(is|are|now|becomes) normative' "$FPKT"
forbid "$FPKT opens a D-00 acceptance path" -iE 'D-00 (is|now|has been) (accepted|resolved|closed)' "$FPKT"
forbid "$FPKT reopens a recorded direction" -iE '(is|are|now|hereby) reopened' "$FPKT"
forbid "$FPKT poses a question for a blocked item" -E '^\| F32B-PSBT-Q-[0-9][0-9][0-9] \| [^|]*D-(00|04|07|09|11)' "$FPKT"
forbid "$FPKT promotes current P2TR capability" -iE 'P2TR (is|are|now|becomes) (accepted|allowed|supported|permitted)' "$FPKT"
forbid "$FPKT applies an SPDX expression" -F 'SPDX-License-Identifier:' "$FPKT"
forbid "$FPKT selects or applies a license" -iE 'license (is|has been|now) (selected|applied|granted)' "$FPKT"
forbid "$FPKT appoints a role" -F 'is hereby appointed' "$FPKT"
forbid "$FPKT enables a channel or setting" -E '(is now|has been) enabled' "$FPKT"
forbid "$FPKT claims a closed gate" -iE 'Gate [A-E][^.]*CLOSED' "$FPKT"
forbid "$FPKT assigns a QK-LIM value" -E 'QK-LIM[-0-9A-Za-z]* *= *[0-9]' "$FPKT"
forbid "$FPKT claims vectors were generated or run" \
  -iE 'vectors? (were|have been|are) (generated|run)' "$FPKT"
# Remnant guards for owner-corrected wording: none of the superseded
# phrasings may reappear in the packet.
forbid "$FPKT carries the stale new-options STATUS wording" -F 'ALL FOUR NEW OPTIONS UNSELECTED' "$FPKT"
forbid "$FPKT carries the stale sole-authority wording" -F 'remains the sole authority' "$FPKT"
forbid "$FPKT carries the stale map-absence wording" -F 'Absence of the map is valid' "$FPKT"
forbid "$FPKT carries the stale alternative-encoding wording" -F 'no alternative encoding' "$FPKT"
forbid "$FPKT carries the stale record-set wording" -F 'record set' "$FPKT"
forbid "$FPKT carries the stale evidence-blocked-for-response wording" -F 'EVIDENCE-BLOCKED FOR RESPONSE' "$FPKT"
forbid "$FPKT carries the stale response-deferred wording" -F 'response-deferred' "$FPKT"
forbid "$FPKT carries the stale precede-any-response wording" -F 'must precede any response' "$FPKT"
forbid "$FPKT carries the stale consider-preservation wording" -F 'preservation is later considered' "$FPKT"
forbid "docs/DECISION-LOG.md carries the stale response-deferred wording" \
  -F 'response-deferred' docs/DECISION-LOG.md
forbid "docs/DECISION-LOG.md carries the stale precede-any-response wording" \
  -F 'must precede any response' docs/DECISION-LOG.md
# The Decision-Log record must never claim the owner separately or
# explicitly authorized the host file-set addition; the owner rejected
# that claim as false.
forbid "docs/DECISION-LOG.md carries the rejected owner-explicit-authorization claim" \
  -F 'separately and explicitly authorized' docs/DECISION-LOG.md
$GIT show "$C16:docs/SOURCE-REGISTER.md" > "$tmpdir/cs.sreg.base" 2>/dev/null \
  || err "cannot read docs/SOURCE-REGISTER.md from C16"
cat "$tmpdir/cs.sreg.base" > "$tmpdir/cs.sreg.expected" \
  || err "source-register expected reconstruction failed (fail-closed)"
for csbip in bip-0032 bip-0048 bip-0067 bip-0380 bip-0382 bip-0383 bip-0039; do
  grep -F "| bitcoin/bips — \`$csbip.mediawiki\` |" docs/SOURCE-REGISTER.md > "$tmpdir/cs.sreg.row.$csbip"
  csrc=$?
  [ "$csrc" -le 1 ] || err "source-register row extraction failed for $csbip (grep exit $csrc)"
  [ -s "$tmpdir/cs.sreg.row.$csbip" ] || err "docs/SOURCE-REGISTER.md missing the authorized $csbip row"
  cat "$tmpdir/cs.sreg.row.$csbip" >> "$tmpdir/cs.sreg.expected" \
    || err "source-register expected append failed for $csbip (fail-closed)"
done
cmp -s "$tmpdir/cs.sreg.expected" docs/SOURCE-REGISTER.md
cssr=$?
[ "$cssr" -eq 0 ] || err "docs/SOURCE-REGISTER.md is not exactly the C16 baseline plus the seven authorized F3.2a rows in declared order (cmp exit $cssr)"
# Static assertions: host checker carries each F3.2a guard family.
# These greps prove presence of the guard text in the checker only;
# they are lexical, self-referential evidence with the same honesty
# limits as every other static check here.
grep -F 'WTS=docs/f3/WALLET-TRUST-SPINE-DRAFT.md' tools/verify-host-boundary.sh >/dev/null \
  || err "host checker missing the F3.2a draft section"
grep -F 'clause heading set is not exactly QK-F3-WTS-001..015' tools/verify-host-boundary.sh >/dev/null \
  || err "host checker missing the closed-world clause-set comparison"
grep -F 'plan row set is not exactly QK-F3-WTS-PLAN-001..020' tools/verify-host-boundary.sh >/dev/null \
  || err "host checker missing the closed-world plan-set comparison"
grep -F 'malformed clause heading grammar' tools/verify-host-boundary.sh >/dev/null \
  || err "host checker missing the clause heading-prefix/valid-heading count equality check"
grep -F 'malformed plan row grammar' tools/verify-host-boundary.sh >/dev/null \
  || err "host checker missing the plan row-prefix/valid-first-cell count equality check"
grep -F 'satisfy the complete anchored heading grammar' tools/verify-host-boundary.sh >/dev/null \
  || err "host checker missing the complete anchored clause-heading grammar rule"
grep -F 'satisfy the exact anchored first-cell grammar' tools/verify-host-boundary.sh >/dev/null \
  || err "host checker missing the exact anchored plan first-cell grammar rule"
grep -F 'must occur exactly once as a line-anchored PROPOSED/NON-NORMATIVE heading' tools/verify-host-boundary.sh >/dev/null \
  || err "host checker missing the line-anchored per-ID clause heading check"
grep -F 'must occur on exactly one line-anchored table row' tools/verify-host-boundary.sh >/dev/null \
  || err "host checker missing the line-anchored per-ID plan row uniqueness check"
grep -F "must contain exactly one line beginning 'STATUS:'" tools/verify-host-boundary.sh >/dev/null \
  || err "host checker missing the exactly-one-STATUS-line rule"
grep -F 'STATUS line is not exactly the mandatory banner' tools/verify-host-boundary.sh >/dev/null \
  || err "host checker missing the full-line STATUS banner equality rule"
grep -F 'affirmative VALIDATED token' tools/verify-host-boundary.sh >/dev/null \
  || err "host checker missing the global VALIDATED token guard"
grep -F 'affirmative CONFORMANT token' tools/verify-host-boundary.sh >/dev/null \
  || err "host checker missing the global CONFORMANT token guard"
grep -F 'affirmative COMPLETE token' tools/verify-host-boundary.sh >/dev/null \
  || err "host checker missing the global COMPLETE token guard"
grep -F "does not END with the exact final status cell" tools/verify-host-boundary.sh >/dev/null \
  || err "host checker missing the exact final plan-status-cell check"
grep -F 'long secret-like hex run (>= 64 hex chars)' tools/verify-host-boundary.sh >/dev/null \
  || err "host checker missing the 64-hex material guard"
grep -F 'unclassified exact-40-hex token(s) present in content paths' tools/verify-host-boundary.sh >/dev/null \
  || err "host checker missing the closed 40-hex pin-classifier guard"
grep -F 'base64 payload blob' tools/verify-host-boundary.sh >/dev/null \
  || err "host checker missing the base64 payload guard"
grep -F 'raw PSBT material' tools/verify-host-boundary.sh >/dev/null \
  || err "host checker missing the raw-PSBT material guard"
grep -F 'affirmative APPROVED token' tools/verify-host-boundary.sh >/dev/null \
  || err "host checker missing the affirmative-APPROVED guard"
grep -F 'claims production readiness' tools/verify-host-boundary.sh >/dev/null \
  || err "host checker missing the production-ready guard"
grep -F 'claims a closed gate' tools/verify-host-boundary.sh >/dev/null \
  || err "host checker missing the closed-gate guard"
grep -F 'is not byte-identical to the reviewed A commit' tools/verify-host-boundary.sh >/dev/null \
  || err "host checker missing the exact Decision-Log byte-identity check"
grep -F 'plus the seven authorized F3.2a rows in declared order' tools/verify-host-boundary.sh >/dev/null \
  || err "host checker missing the exact Source-Register bounded-append check"
grep -F 'wallet_id is never stored on the cards' tools/verify-host-boundary.sh >/dev/null \
  || err "host checker missing the wallet_id-never-stored check"
grep -F 'contain the same A2 value' tools/verify-host-boundary.sh >/dev/null \
  || err "host checker missing the same-A2 invariant check"
grep -F 'stateless replacement terminal with no prior wallet registration' tools/verify-host-boundary.sh >/dev/null \
  || err "host checker missing the stateless-replacement-terminal check"
grep -F 'traceability is NOT DONE' tools/verify-host-boundary.sh >/dev/null \
  || err "host checker missing the traceability-NOT-DONE check"
grep -F 'A fingerprint alone is NEVER identity' tools/verify-host-boundary.sh >/dev/null \
  || err "host checker missing the fingerprint-not-identity check"
grep -F 'A QuietKey domain prefix MUST NOT be added' tools/verify-host-boundary.sh >/dev/null \
  || err "host checker missing the no-domain-prefix check"
grep -F 'Receive first, then exactly one raw zero byte, then change' tools/verify-host-boundary.sh >/dev/null \
  || err "host checker missing the wallet_id byte-order check"
grep -F 'PERMANENT SEMANTIC ROLE ORDER A,B,C' tools/verify-host-boundary.sh >/dev/null \
  || err "host checker missing the textual role-order check"
grep -F 'NEVER redefines the semantic roles A/B/C' tools/verify-host-boundary.sh >/dev/null \
  || err "host checker missing the slot-never-redefines-role check"
grep -F 'atomically committed as one physical transaction' tools/verify-host-boundary.sh >/dev/null \
  || err "host checker missing the no-atomic-provisioning check"
grep -F 'the requirements currently CONFLICT' tools/verify-host-boundary.sh >/dev/null \
  || err "host checker missing the BND-003/D-03 conflict check"
grep -F 'MUST NOT choose the construction' tools/verify-host-boundary.sh >/dev/null \
  || err "host checker missing the D-09-construction-open check"
grep -F 'INSIDE the authorization trust boundary' tools/verify-host-boundary.sh >/dev/null \
  || err "host checker missing the malicious-terminal limitation check"
grep -F 'contains what looks like a real extended key' tools/verify-host-boundary.sh >/dev/null \
  || err "host checker missing the payload-material lexical scan"
grep -F 'single-interface B+C choreography BLOCKED pending QK-REQ-BND-003 versus D-03 reconciliation plus OD-02 evidence' tools/verify-host-boundary.sh >/dev/null \
  || err "host checker missing the README B+C BLOCKED summary check"

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
check_prefix docs/DECISION-LOG.md "$C16"
check_prefix docs/SOURCE-REGISTER.md "$C16"
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
docs/OD-08-DECISION-PACKET.md
docs/OD-08-OWNER-RESPONSE-RECORD.md
docs/REQUIREMENTS.md
docs/SOURCE-REGISTER.md
docs/f3/F3.2B-PSBT-DECISION-PACKET.md
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
  docs/OD-08-DECISION-PACKET.md docs/OD-08-OWNER-RESPONSE-RECORD.md \
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
