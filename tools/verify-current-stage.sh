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
C28=bb6601f3b97528a72c55622251a4b475680ec21b    # chore: bind F3.2b PSBT decision-packet consistency checks (PUBLISHED RESPONSE PARENT)
C29=3dfda3d6c10d54f92e6c397866e8c630a1249898    # docs: authorize F3.2b PSBT owner-response preparation
C30=363eda2137f6e4e29ba01db9183d9ea72672fb10    # docs(f3): record owner-approved F3.2b PSBT directions and reanchor host checks
C31=26e075704cdd172fce62b9b7cd38b4035db384d8    # published F3.2c parent
C32=9354d4a2924378ddcc20e4ffa26be0602bd913c0    # docs: authorize F3.2c D-11 construction-packet preparation
C33=76839acf30c48e3623c27c68cb7ecdbf5f5cf698    # docs(f3): add non-binding F3.2c D-11 construction packet and reanchor host checks
C34=e4cdf7771e189fc0f729358334aafd35177048c6    # published F3.2d Q-001 source base
C35=2c6d1152f09730661b2cadd86d2374c755191128    # docs: authorize F3.2d Q-001 clarification record
C36=a4f9e328554cdd77b850a1aa41b9cb9f3849d747    # docs(f3): record non-enacting D-11 Q-001 clarification
C37=be4d019e349e15ca575ac64b64f900957283e5e0    # published F3.2e source base / F3.2d commit C
C38=e57faff4ead69ddf108cf522cb6c3cbfbef8219a    # docs: authorize F3.2e PSBT-output test-alignment packet
C39=c66793900f62bce9f2fde67483a22fd3b22fab22    # docs(f3): add non-binding PSBT-output test-alignment packet
C40=574e790193d45d3f392c64951d319bb5fde11d20    # published F3.2f source base / F3.2e commit C
C41=22114c6741ac653b9c5079b1bfccdb795a88f3df    # docs: authorize F3.2f owner-direction record
C42=8cf313ea02af2ebf4b065eef207ea5ea909ef2dd    # docs(f3): record non-enacting F3.2f owner directions
C43=45f2b362994b785d303e91b8e530efc724dc2d81    # published F3.2g source base / F3.2f commit C
C44=55bd46310606e2df4089d8234a67655c81440bab    # docs: authorize F3.2g TEST-ARCHITECTURE amendment
C45=f710ac058dfe6e98c111e4d568ee1731ae288cf3    # docs(test): apply approved F3.2g Plan / oracle corrections
F32G_C=a64399dd35aef8d6daa05171f1da30c8026f6d1f # published F3.2h source base / F3.2g commit C
C46=da55fb4bcd4983140c8fb379cc3322eec99284f0    # docs: authorize F3.2h QK-LIM-PSBT-027 alignment packet
C47=73d315bbb5a57f63db1eaf78bcb92aa18ea3bb74    # docs(f3): add non-binding F3.2h QK-LIM-PSBT-027 alignment packet

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
# Exact linear ancestry BASE -> C1 -> ... -> C34 -> C35 -> C36 ->
# C37 -> C38 -> C39 -> C40 -> C41 -> C42 -> C43 -> C44 -> C45 ->
# F32G_C -> C46 -> C47 -> HEAD, no merges. F32G_C is the published
# base of the exact three-commit local/unpublished F3.2h chain.
head=$($GIT rev-parse HEAD) || err "cannot resolve HEAD"
p_head=$($GIT rev-parse "$head^" 2>/dev/null) || err "HEAD has no parent"
p_c47=$($GIT rev-parse "$C47^" 2>/dev/null) || err "C47 has no parent"
p_c46=$($GIT rev-parse "$C46^" 2>/dev/null) || err "C46 has no parent"
p_f32g_c=$($GIT rev-parse "$F32G_C^" 2>/dev/null) || err "F32G_C has no parent"
p_c45=$($GIT rev-parse "$C45^" 2>/dev/null) || err "C45 has no parent"
p_c44=$($GIT rev-parse "$C44^" 2>/dev/null) || err "C44 has no parent"
p_c43=$($GIT rev-parse "$C43^" 2>/dev/null) || err "C43 has no parent"
p_c42=$($GIT rev-parse "$C42^" 2>/dev/null) || err "C42 has no parent"
p_c41=$($GIT rev-parse "$C41^" 2>/dev/null) || err "C41 has no parent"
p_c40=$($GIT rev-parse "$C40^" 2>/dev/null) || err "C40 has no parent"
p_c39=$($GIT rev-parse "$C39^" 2>/dev/null) || err "C39 has no parent"
p_c38=$($GIT rev-parse "$C38^" 2>/dev/null) || err "C38 has no parent"
p_c37=$($GIT rev-parse "$C37^" 2>/dev/null) || err "C37 has no parent"
p_c36=$($GIT rev-parse "$C36^" 2>/dev/null) || err "C36 has no parent"
p_c35=$($GIT rev-parse "$C35^" 2>/dev/null) || err "C35 has no parent"
p_c34=$($GIT rev-parse "$C34^" 2>/dev/null) || err "C34 has no parent"
p_c33=$($GIT rev-parse "$C33^" 2>/dev/null) || err "C33 has no parent"
p_c32=$($GIT rev-parse "$C32^" 2>/dev/null) || err "C32 has no parent"
p_c31=$($GIT rev-parse "$C31^" 2>/dev/null) || err "C31 has no parent"
p_c30=$($GIT rev-parse "$C30^" 2>/dev/null) || err "C30 has no parent"
p_c29=$($GIT rev-parse "$C29^" 2>/dev/null) || err "C29 has no parent"
p_c28=$($GIT rev-parse "$C28^" 2>/dev/null) || err "C28 has no parent"
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
[ "$p_head" = "$C47" ] || err "HEAD parent is $p_head, expected $C47"
[ "$p_c47" = "$C46" ] || err "C47 parent is $p_c47, expected $C46"
[ "$p_c46" = "$F32G_C" ] || err "C46 parent is $p_c46, expected $F32G_C"
[ "$p_f32g_c" = "$C45" ] || err "F32G_C parent is $p_f32g_c, expected $C45"
[ "$p_c45" = "$C44" ] || err "C45 parent is $p_c45, expected $C44"
[ "$p_c44" = "$C43" ] || err "C44 parent is $p_c44, expected $C43"
[ "$p_c43" = "$C42" ] || err "C43 parent is $p_c43, expected $C42"
[ "$p_c42" = "$C41" ] || err "C42 parent is $p_c42, expected $C41"
[ "$p_c41" = "$C40" ] || err "C41 parent is $p_c41, expected $C40"
[ "$p_c40" = "$C39" ] || err "C40 parent is $p_c40, expected $C39"
[ "$p_c39" = "$C38" ] || err "C39 parent is $p_c39, expected $C38"
[ "$p_c38" = "$C37" ] || err "C38 parent is $p_c38, expected $C37"
[ "$p_c37" = "$C36" ] || err "C37 parent is $p_c37, expected $C36"
[ "$p_c36" = "$C35" ] || err "C36 parent is $p_c36, expected $C35"
[ "$p_c35" = "$C34" ] || err "C35 parent is $p_c35, expected $C34"
[ "$p_c34" = "$C33" ] || err "C34 parent is $p_c34, expected $C33"
[ "$p_c33" = "$C32" ] || err "C33 parent is $p_c33, expected $C32"
[ "$p_c32" = "$C31" ] || err "C32 parent is $p_c32, expected $C31"
[ "$p_c31" = "$C30" ] || err "C31 parent is $p_c31, expected $C30"
[ "$p_c30" = "$C29" ] || err "C30 parent is $p_c30, expected $C29"
[ "$p_c29" = "$C28" ] || err "C29 parent is $p_c29, expected $C28"
[ "$p_c28" = "$C27" ] || err "C28 parent is $p_c28, expected $C27"
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
[ "$count" = "49" ] || err "expected exactly 49 commits after base, found $count"
merges=$($GIT rev-list --merges "$BASE..$head") || err "git rev-list --merges failed (fail-closed)"
[ -z "$merges" ] || err "merge commit present in $BASE..$head: $merges"
for c in "$head" "$C47" "$C46" "$F32G_C" "$C45" "$C44" "$C43" "$C42" "$C41" "$C40" "$C39" "$C38" "$C37" "$C36" "$C35" "$C34" "$C33" "$C32" "$C31" "$C30" "$C29" "$C28" "$C27" "$C26" "$C25" "$C24" "$C23" "$C22" "$C21" "$C20" "$C19" "$C18" "$C17" "$C16" "$C15" "$C14" "$C13" "$C12" "$C11" "$C10" "$C9" "$C8" "$C7" "$C6" "$C5" "$C4" "$C3" "$C2" "$C1"; do
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

# Exact F3.2d commit subjects. Full-line cmp avoids prefix/suffix,
# newline, pretty-format, or multi-line-message ambiguity.
check_subject() {
  $GIT show -s --format=%s "$1" > "$tmpdir/subj.act" \
    || err "cannot read subject for $2"
  printf '%s\n' "$3" > "$tmpdir/subj.exp" \
    || err "cannot generate expected subject for $2"
  cmp -s "$tmpdir/subj.exp" "$tmpdir/subj.act" \
    || err "$2 subject is not exactly: $3"
}
check_subject "$C35" "F3.2d commit A" 'docs: authorize F3.2d Q-001 clarification record'
check_subject "$C36" "F3.2d commit B" 'docs(f3): record non-enacting D-11 Q-001 clarification'
check_subject "$C37" "F3.2d commit C" 'chore(verify): bind F3.2d Q-001 clarification stage'
check_message() {
  $GIT show -s --format=%B "$1" > "$tmpdir/msg.act" \
    || err "cannot read full message for $2"
  printf '%s\n\n' "$3" > "$tmpdir/msg.exp" \
    || err "cannot generate expected full message for $2"
  cmp -s "$tmpdir/msg.exp" "$tmpdir/msg.act" \
    || err "$2 full message differs or contains a body: $3"
}
check_message "$C38" "F3.2e commit A" 'docs: authorize F3.2e PSBT-output test-alignment packet'
check_message "$C39" "F3.2e commit B" 'docs(f3): add non-binding PSBT-output test-alignment packet'
check_message "$C40" "F3.2e commit C" 'chore(verify): bind F3.2e test-alignment packet stage'
check_message "$C41" "F3.2f commit A" 'docs: authorize F3.2f PSBT-output test owner-direction record'
check_message "$C42" "F3.2f commit B" 'docs(f3): record non-enacting PSBT-output test owner directions'
check_message "$C43" "F3.2f commit C" 'chore(verify): bind F3.2f test owner-direction stage'
check_message "$C44" "F3.2g commit A" 'docs: authorize F3.2g PSBT-output TEST-ARCHITECTURE amendment'
check_message "$C45" "F3.2g commit B" 'docs(test): apply approved PSBT-output Plan / oracle corrections'
check_message "$F32G_C" "F3.2g commit C" 'chore(verify): bind F3.2g TEST-ARCHITECTURE amendment stage'
check_message "$C46" "F3.2h commit A" 'docs: authorize F3.2h QK-LIM-PSBT-027 alignment packet'
check_message "$C47" "F3.2h commit B" 'docs(f3): add non-binding F3.2h QK-LIM-PSBT-027 alignment packet'
check_message "$head" "F3.2h commit C" 'chore(verify): bind F3.2h QK-LIM-PSBT-027 alignment packet stage'

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

check_paths "$C28" "commit28" <<'EOF'
tools/verify-current-stage.sh
EOF

check_paths "$C29" "commit29" <<'EOF'
docs/DECISION-LOG.md
EOF

check_paths "$C30" "commit30" <<'EOF'
docs/f3/F3.2B-PSBT-OWNER-RESPONSE-RECORD.md
tools/verify-host-boundary.sh
EOF

check_paths "$C31" "commit31" <<'EOF'
tools/verify-current-stage.sh
EOF

check_paths "$C32" "commit32" <<'EOF'
docs/DECISION-LOG.md
EOF

check_paths "$C33" "commit33" <<'EOF'
docs/f3/F3.2C-D11-MEDIA-WRITE-LIFECYCLE-CONSTRUCTION-PACKET.md
tools/verify-host-boundary.sh
EOF

check_paths "$C34" "commit34" <<'EOF'
tools/verify-current-stage.sh
EOF

check_paths "$C35" "f32d-commit-a" <<'EOF'
docs/DECISION-LOG.md
EOF

check_paths "$C36" "f32d-commit-b" <<'EOF'
docs/f3/F3.2D-D11-Q001-OWNER-CLARIFICATION-RECORD.md
tools/verify-host-boundary.sh
EOF

check_paths "$C37" "f32d-commit-c" <<'EOF'
tools/verify-current-stage.sh
EOF

check_paths "$C38" "f32e-commit-a" <<'EOF'
docs/DECISION-LOG.md
EOF

check_paths "$C39" "f32e-commit-b" <<'EOF'
docs/f3/F3.2E-PSBT-OUTPUT-TEST-ALIGNMENT-PACKET.md
tools/verify-host-boundary.sh
EOF

check_paths "$C40" "f32e-commit-c" <<'EOF'
tools/verify-current-stage.sh
EOF

check_paths "$C41" "f32f-commit-a" <<'EOF'
docs/DECISION-LOG.md
EOF

check_paths "$C42" "f32f-commit-b" <<'EOF'
docs/f3/F3.2F-PSBT-OUTPUT-TEST-OWNER-DIRECTION-RECORD.md
tools/verify-host-boundary.sh
EOF

check_paths "$C43" "f32f-commit-c" <<'EOF'
tools/verify-current-stage.sh
EOF

check_paths "$C44" "f32g-commit-a" <<'EOF'
docs/DECISION-LOG.md
EOF

check_paths "$C45" "f32g-commit-b" <<'EOF'
docs/TEST-ARCHITECTURE.md
tools/verify-host-boundary.sh
EOF

check_paths "$F32G_C" "f32g-commit-c" <<'EOF'
tools/verify-current-stage.sh
EOF

check_paths "$C46" "f32h-commit-a" <<'EOF'
docs/DECISION-LOG.md
EOF

check_paths "$C47" "f32h-commit-b" <<'EOF'
docs/f3/F3.2H-QK-LIM-PSBT-027-CROSS-DOCUMENT-ALIGNMENT-PACKET.md
tools/verify-host-boundary.sh
EOF

check_paths "$head" "f32h-commit-c" <<'EOF'
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
# Historical F3.2b bounded append content enforced directly. C29 is a
# historical Decision-Log prefix; it is not the current active log.
$GIT show "$C29:docs/DECISION-LOG.md" > "$tmpdir/cs.dlog.a" 2>/dev/null \
  || err "cannot read docs/DECISION-LOG.md from C29"
wc -c < "$tmpdir/cs.dlog.a" > "$tmpdir/cs.dlog.a.len.raw" || err "C29 Decision-Log length failed"
tr -d '[:space:]' < "$tmpdir/cs.dlog.a.len.raw" > "$tmpdir/cs.dlog.a.len" || err "C29 Decision-Log length strip failed"
csd29=$(cat "$tmpdir/cs.dlog.a.len") || err "C29 Decision-Log length read failed"
dd if=docs/DECISION-LOG.md bs=1 count="$csd29" > "$tmpdir/cs.dlog.a.prefix" 2>/dev/null || err "C29 Decision-Log prefix extraction failed"
cmp -s "$tmpdir/cs.dlog.a" "$tmpdir/cs.dlog.a.prefix" || err "reviewed C29 Decision Log is not an exact prefix"
$GIT show "$C28:docs/DECISION-LOG.md" > "$tmpdir/cs.dlog.base" 2>/dev/null \
  || err "cannot read docs/DECISION-LOG.md from C28"
wc -c < "$tmpdir/cs.dlog.base" > "$tmpdir/cs.dlog.len.raw" \
  || err "C28 Decision-Log length failed (fail-closed)"
tr -d '[:space:]' < "$tmpdir/cs.dlog.len.raw" > "$tmpdir/cs.dlog.len" \
  || err "C28 Decision-Log length strip failed (fail-closed)"
dlbl=$(cat "$tmpdir/cs.dlog.len") || err "C28 Decision-Log length read-back failed (fail-closed)"
case "$dlbl" in ''|*[!0-9]*) err "C28 Decision-Log length not numeric: '$dlbl'" ;; esac
dd if=docs/DECISION-LOG.md bs=1 count="$dlbl" > "$tmpdir/cs.dlog.head" 2>/dev/null \
  || err "Decision-Log prefix extraction failed (fail-closed)"
cmp -s "$tmpdir/cs.dlog.base" "$tmpdir/cs.dlog.head"
csdl=$?
[ "$csdl" -eq 0 ] || err "published C28 Decision-Log is not an exact byte prefix of the current Decision-Log (cmp exit $csdl)"
# Exact authorized suffix beyond the C28 prefix.
dlskip=$((dlbl + 1)) || err "suffix offset arithmetic failed (fail-closed)"
tail -c "+$dlskip" "$tmpdir/cs.dlog.a" > "$tmpdir/cs.dlog.suffix" \
  || err "Decision-Log suffix extraction failed (fail-closed)"
cat > "$tmpdir/cs.dlog.suffix.expected" <<'QK_F32B_RSP_SUFFIX_EOF' || err "expected Decision-Log suffix file generation failed (fail-closed)"

### QK-AUTH-F3.2B-RSP-001 — F3.2b PSBT owner-response record preparation authorization

- **ID:** QK-AUTH-F3.2B-RSP-001
- **Date:** 2026-08-19
- **Approver:** Project owner
- **Owner words exactly:** “Approve all four F3.2b directions.”
- **Owner preparation authority exactly:** “Authorize preparation and independent audit of the docs-only F3.2b owner-response record from bb6601f3. No profile acceptance, implementation, vectors, license application, hardware work, settings changes, or publication.”
- **Published parent:** `bb6601f3b97528a72c55622251a4b475680ec21b`.
- **Source packet:** `docs/f3/F3.2B-PSBT-DECISION-PACKET.md` at the published parent.
- **Scope:** exactly four non-enacting policy directions only: `F32B-PSBT-Q-001`/D-02, `F32B-PSBT-Q-002`/D-05, `F32B-PSBT-Q-003`/D-06, and `F32B-PSBT-Q-004`/D-10. Preparation and independent audit are authorized; publication and any profile or clause acceptance are not authorized.
- **Authorized next commits:** Commit B adding exactly `docs/f3/F3.2B-PSBT-OWNER-RESPONSE-RECORD.md` and changing exactly `tools/verify-host-boundary.sh` to reanchor this Decision Log state, add the record to its exact host file set, and add strict record checks; then Commit C changing exactly `tools/verify-current-stage.sh`.
- **Explicit exclusions:** D-00 remains blocked; D-04 remains OWNER-OPEN, with representative coordinator-corpus review required before selection; D-07 remains EVIDENCE/CONSTRUCTION-BLOCKED pending target/human QK-LIM evidence; D-09 remains EVIDENCE/CONSTRUCTION-BLOCKED pending the exact commitment construction; D-11 remains EVIDENCE/CONSTRUCTION-BLOCKED pending the media/write lifecycle; no edit to the packet or PSBT profile draft; no architecture/requirements/OD/QK-LIM/QK-TST/evidence/gate status change; no implementation, dependencies, parser/signing/crypto code, fixtures/vectors, conformance or real-funds use; no finalization/extraction/broadcast authorization; no license application; no hardware/firmware/Flux/procurement/fabrication; no other-branch, remote-branch, branch-setting, tag, release, push, publication, settings, or credential change.
- **Effect:** this record records four non-enacting owner-direction dispositions, but enacts no normative profile or clause and changes no OD, QK-LIM, QK-TST, evidence, gate, implementation, release, remote, or publication status; it authorizes no publication.
QK_F32B_RSP_SUFFIX_EOF
cmp -s "$tmpdir/cs.dlog.suffix.expected" "$tmpdir/cs.dlog.suffix"
csdl=$?
[ "$csdl" -eq 0 ] || err "Decision-Log suffix beyond the published C28 prefix is not the exact authorized QK-AUTH-F3.2B-RSP-001 record (cmp exit $csdl)"
# Historical F3.2c authorization append: C31 is the exact prefix, C32
# is the reviewed authorization log, C34 retained those bytes, and the
# suffix is the one exact authorized QK-AUTH-F3.2C-D11-PKT-001
# transcript. Supporting evidence only.
$GIT show "$C31:docs/DECISION-LOG.md" > "$tmpdir/cs.f32c.dlog.c31" 2>/dev/null \
  || err "cannot read C31 published Decision Log"
$GIT show "$C32:docs/DECISION-LOG.md" > "$tmpdir/cs.f32c.dlog.c32" 2>/dev/null \
  || err "cannot read C32 authorization Decision Log"
$GIT show "$C34:docs/DECISION-LOG.md" > "$tmpdir/cs.f32c.dlog.c34" 2>/dev/null \
  || err "cannot read C34 historical Decision Log"
cmp -s "$tmpdir/cs.f32c.dlog.c32" "$tmpdir/cs.f32c.dlog.c34" \
  || err "C34 did not retain the exact historical C32 Decision Log"
wc -c < "$tmpdir/cs.f32c.dlog.c31" > "$tmpdir/cs.f32c.dlog.len.raw" \
  || err "C31 Decision-Log length failed"
tr -d '[:space:]' < "$tmpdir/cs.f32c.dlog.len.raw" > "$tmpdir/cs.f32c.dlog.len" \
  || err "C31 Decision-Log length normalization failed"
f32cdl=$(cat "$tmpdir/cs.f32c.dlog.len") || err "C31 Decision-Log length read failed"
case "$f32cdl" in ''|*[!0-9]*) err "C31 Decision-Log length is not numeric" ;; esac
dd if="$tmpdir/cs.f32c.dlog.c32" bs=1 count="$f32cdl" > "$tmpdir/cs.f32c.dlog.prefix" 2>/dev/null \
  || err "C31/C32 Decision-Log prefix extraction failed"
cmp -s "$tmpdir/cs.f32c.dlog.c31" "$tmpdir/cs.f32c.dlog.prefix" \
  || err "C31 Decision Log is not an exact byte prefix of C32"
f32cskip=$((f32cdl + 1))
tail -c "+$f32cskip" "$tmpdir/cs.f32c.dlog.c32" > "$tmpdir/cs.f32c.dlog.suffix" \
  || err "F3.2c Decision-Log suffix extraction failed"
cat > "$tmpdir/cs.f32c.dlog.suffix.expected" <<'QK_F32C_DLOG_SUFFIX_EOF' || err "F3.2c Decision-Log expected suffix generation failed"

### QK-AUTH-F3.2C-D11-PKT-001 — F3.2c D-11 non-binding media/write lifecycle construction-packet preparation authorization

- **ID:** QK-AUTH-F3.2C-D11-PKT-001
- **Date:** 2026-08-19
- **Approver:** Project owner
- **Owner words exactly:** “Authorize preparation and independent audit of the non-binding docs-only F3.2c D-11 media/write lifecycle construction packet from 26e075704cdd172fce62b9b7cd38b4035db384d8, with only the mechanically necessary host-boundary and current-stage verifier bindings. No D-11 selection, profile or clause acceptance, implementation, dependencies, vectors, fixtures, specimens, media I/O or testing, QK-LIM/QK-TST/evidence/gate change, license application, hardware or firmware work, settings or credential changes, or publication.”
- **Published parent:** `26e075704cdd172fce62b9b7cd38b4035db384d8`.
- **Exact commit/path map:** Commit A changes only `docs/DECISION-LOG.md`; Commit B adds only `docs/f3/F3.2C-D11-MEDIA-WRITE-LIFECYCLE-CONSTRUCTION-PACKET.md` and changes only `tools/verify-host-boundary.sh`; Commit C changes only `tools/verify-current-stage.sh`.
- **Least-authority scope:** only local packet preparation and verification, one credential-safe audit-bundle export, and independent read-only audit are authorized. The mechanically necessary verifier bindings do not broaden this authority.
- **Boundaries:** D-11 remains unanswered and EVIDENCE/CONSTRUCTION-BLOCKED; D-09 remains unresolved; the PSBT profile draft remains not accepted; no normative clause, OD, limit, test, evidence, gate, implementation, product, target, release, remote, publication, license, hardware, firmware, setting, credential, tag, or other-branch transition is authorized.
- **Later publication:** publication requires a separate explicit instruction naming the exact audited 40-hex commit.
- **Effect:** this authorization records no D-11 selection, enacts no profile or clause, changes no protected status, and authorizes no publication.
QK_F32C_DLOG_SUFFIX_EOF
cmp -s "$tmpdir/cs.f32c.dlog.suffix.expected" "$tmpdir/cs.f32c.dlog.suffix" \
  || err "C32 Decision-Log suffix is not the exact QK-AUTH-F3.2C-D11-PKT-001 record"
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

# F3.2b owner-response authorization record essentials
# (QK-AUTH-F3.2B-RSP-001), checked as complete literal lines.
cat > "$tmpdir/cs.f32brsp.lines" <<'QK_F32B_RSP_LINES_EOF' || err "expected F3.2b response authorization-line file generation failed"
### QK-AUTH-F3.2B-RSP-001 — F3.2b PSBT owner-response record preparation authorization
- **Owner words exactly:** “Approve all four F3.2b directions.”
- **Owner preparation authority exactly:** “Authorize preparation and independent audit of the docs-only F3.2b owner-response record from bb6601f3. No profile acceptance, implementation, vectors, license application, hardware work, settings changes, or publication.”
- **Published parent:** `bb6601f3b97528a72c55622251a4b475680ec21b`.
- **Source packet:** `docs/f3/F3.2B-PSBT-DECISION-PACKET.md` at the published parent.
- **Scope:** exactly four non-enacting policy directions only: `F32B-PSBT-Q-001`/D-02, `F32B-PSBT-Q-002`/D-05, `F32B-PSBT-Q-003`/D-06, and `F32B-PSBT-Q-004`/D-10. Preparation and independent audit are authorized; publication and any profile or clause acceptance are not authorized.
- **Authorized next commits:** Commit B adding exactly `docs/f3/F3.2B-PSBT-OWNER-RESPONSE-RECORD.md` and changing exactly `tools/verify-host-boundary.sh` to reanchor this Decision Log state, add the record to its exact host file set, and add strict record checks; then Commit C changing exactly `tools/verify-current-stage.sh`.
- **Explicit exclusions:** D-00 remains blocked; D-04 remains OWNER-OPEN, with representative coordinator-corpus review required before selection; D-07 remains EVIDENCE/CONSTRUCTION-BLOCKED pending target/human QK-LIM evidence; D-09 remains EVIDENCE/CONSTRUCTION-BLOCKED pending the exact commitment construction; D-11 remains EVIDENCE/CONSTRUCTION-BLOCKED pending the media/write lifecycle; no edit to the packet or PSBT profile draft; no architecture/requirements/OD/QK-LIM/QK-TST/evidence/gate status change; no implementation, dependencies, parser/signing/crypto code, fixtures/vectors, conformance or real-funds use; no finalization/extraction/broadcast authorization; no license application; no hardware/firmware/Flux/procurement/fabrication; no other-branch, remote-branch, branch-setting, tag, release, push, publication, settings, or credential change.
- **Effect:** this record records four non-enacting owner-direction dispositions, but enacts no normative profile or clause and changes no OD, QK-LIM, QK-TST, evidence, gate, implementation, release, remote, or publication status; it authorizes no publication.
QK_F32B_RSP_LINES_EOF
f32brspexp=$(awk 'BEGIN { n = 0 } /./ { n = n + 1 } END { print n }' "$tmpdir/cs.f32brsp.lines") \
  || err "F3.2b response expected-line count failed"
[ "$f32brspexp" = "9" ] || err "F3.2b response expected-line transcript must contain exactly 9 lines (found $f32brspexp)"
f32brspproc=0
while IFS= read -r f32brspline; do
  f32brspc=$(grep -cFx -e "$f32brspline" docs/DECISION-LOG.md)
  f32brsprc=$?
  [ "$f32brsprc" -le 1 ] || err "F3.2b response authorization full-line check failed (grep exit $f32brsprc)"
  [ "$f32brspc" = "1" ] || err "F3.2b response authorization line not present exactly once: $f32brspline"
  f32brspproc=$((f32brspproc + 1))
done < "$tmpdir/cs.f32brsp.lines"
[ "$f32brspproc" = "9" ] || err "F3.2b response authorization loop processed $f32brspproc of 9 lines"

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
# ------------- Host verifier: truthful historical and active bindings
# C30, C31, and C32 carry the same historical F3.2b host bytes. C33 is
# the active F3.2c Commit B host and is bound separately below.
$GIT show "$C21:tools/verify-host-boundary.sh" > "$tmpdir/cs.hb.b" 2>/dev/null \
  || err "cannot read tools/verify-host-boundary.sh from C21"
$GIT show "$C27:tools/verify-host-boundary.sh" > "$tmpdir/cs.hb.b27" 2>/dev/null \
  || err "cannot read tools/verify-host-boundary.sh from C27"
$GIT show "$C30:tools/verify-host-boundary.sh" > "$tmpdir/cs.hb.b30" 2>/dev/null \
  || err "cannot read tools/verify-host-boundary.sh from C30"
$GIT show "$C31:tools/verify-host-boundary.sh" > "$tmpdir/cs.hb.c31" 2>/dev/null \
  || err "cannot read historical host verifier from C31"
$GIT show "$C32:tools/verify-host-boundary.sh" > "$tmpdir/cs.hb.c32" 2>/dev/null \
  || err "cannot read historical host verifier from C32"
cmp -s "$tmpdir/cs.hb.b30" "$tmpdir/cs.hb.c31" \
  || err "historical C30 and C31 host verifiers differ"
cmp -s "$tmpdir/cs.hb.c31" "$tmpdir/cs.hb.c32" \
  || err "historical C31 and C32 host verifiers differ"
# Reject any tautological two-file cmp in this checker. Such a line can
# only prove a temporary file equals itself and is not historical evidence.
awk '$1 == "cmp" && $2 == "-s" && $3 == $4 { print }' tools/verify-current-stage.sh > "$tmpdir/cs.selfcmp" \
  || err "current-stage self-comparison scan failed"
[ ! -s "$tmpdir/cs.selfcmp" ] \
  || err "current-stage checker contains a tautological cmp self-comparison: $(cat "$tmpdir/cs.selfcmp")"
# Reanchor-plus-single-file-set proof: the delta from the published
# C25 host verifier to the reviewed C27 version must equal the exact
# minimal transcript embedded below — the three Decision-Log-anchor
# advances plus the one owner-authorized tracked-file-set line for the
# F3.2b packet, and nothing else.
$GIT show "$C25:tools/verify-host-boundary.sh" > "$tmpdir/cs.hb.base" 2>/dev/null \
  || err "cannot read tools/verify-host-boundary.sh from C25"
diff "$tmpdir/cs.hb.base" "$tmpdir/cs.hb.b27" > "$tmpdir/cs.hb.d" 2>&1
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
grep -F "show $C26:docs/DECISION-LOG.md" "$tmpdir/cs.hb.b27" >/dev/null \
  || err "historical C27 host checker Decision-Log anchor is not the F3.2b packet A commit"
$GIT show "$C40:tools/verify-host-boundary.sh" > "$tmpdir/cs.hb.f32e-stage" 2>/dev/null \
  || err "cannot read historical F3.2e host checker from C40"
grep -F "show $C38:docs/DECISION-LOG.md" "$tmpdir/cs.hb.f32e-stage" >/dev/null \
  || err "historical F3.2e host checker Decision-Log anchor is not the F3.2e authorization A commit"
# ------------------------- SOURCE-REGISTER byte-identical to e81/C19
$GIT show "$C19:docs/SOURCE-REGISTER.md" > "$tmpdir/cs.sreg.c19" 2>/dev/null \
  || err "cannot read docs/SOURCE-REGISTER.md from C19"
cmp -s "$tmpdir/cs.sreg.c19" docs/SOURCE-REGISTER.md
pkc=$?
[ "$pkc" -eq 0 ] || err "docs/SOURCE-REGISTER.md is not byte-identical to the published C19 version (cmp exit $pkc)"
# --------------------- Exact historical C19..C40 path set (exactly ten)
cat > "$tmpdir/cs.od08.exp" <<'EOF'
docs/DECISION-LOG.md
docs/OD-08-DECISION-PACKET.md
docs/OD-08-OWNER-RESPONSE-RECORD.md
docs/f3/F3.2B-PSBT-DECISION-PACKET.md
docs/f3/F3.2B-PSBT-OWNER-RESPONSE-RECORD.md
docs/f3/F3.2C-D11-MEDIA-WRITE-LIFECYCLE-CONSTRUCTION-PACKET.md
docs/f3/F3.2D-D11-Q001-OWNER-CLARIFICATION-RECORD.md
docs/f3/F3.2E-PSBT-OUTPUT-TEST-ALIGNMENT-PACKET.md
tools/verify-current-stage.sh
tools/verify-host-boundary.sh
EOF
$GIT diff --name-only "$C19" "$C40" > "$tmpdir/cs.od08.raw" \
  || err "git diff C19..C40 failed (enumeration fail-closed)"
[ -s "$tmpdir/cs.od08.raw" ] || err "git diff C19..C40 returned no paths (enumeration fail-closed)"
LC_ALL=C sort "$tmpdir/cs.od08.raw" > "$tmpdir/cs.od08.act" \
  || err "C19..C40 path-set sort failed (fail-closed)"
diff "$tmpdir/cs.od08.exp" "$tmpdir/cs.od08.act" > "$tmpdir/cs.od08.dd" 2>&1 \
  || err "changes since published C19 differ from the ten authorized OD-08, F3.2b, F3.2c, F3.2d, and F3.2e paths: $(cat "$tmpdir/cs.od08.dd")"
# ---------- Exact historical C22..C40 path set (exactly nine)
cat > "$tmpdir/cs.rspset.exp" <<'EOF'
docs/DECISION-LOG.md
docs/OD-08-OWNER-RESPONSE-RECORD.md
docs/f3/F3.2B-PSBT-DECISION-PACKET.md
docs/f3/F3.2B-PSBT-OWNER-RESPONSE-RECORD.md
docs/f3/F3.2C-D11-MEDIA-WRITE-LIFECYCLE-CONSTRUCTION-PACKET.md
docs/f3/F3.2D-D11-Q001-OWNER-CLARIFICATION-RECORD.md
docs/f3/F3.2E-PSBT-OUTPUT-TEST-ALIGNMENT-PACKET.md
tools/verify-current-stage.sh
tools/verify-host-boundary.sh
EOF
$GIT diff --name-only "$C22" "$C40" > "$tmpdir/cs.rspset.raw" \
  || err "git diff C22..C40 failed (enumeration fail-closed)"
[ -s "$tmpdir/cs.rspset.raw" ] || err "git diff C22..C40 returned no paths (enumeration fail-closed)"
LC_ALL=C sort "$tmpdir/cs.rspset.raw" > "$tmpdir/cs.rspset.act" \
  || err "C22..C40 path-set sort failed (fail-closed)"
diff "$tmpdir/cs.rspset.exp" "$tmpdir/cs.rspset.act" > "$tmpdir/cs.rspset.dd" 2>&1 \
  || err "changes since published C22 differ from the nine authorized owner-response, F3.2b, F3.2c, F3.2d, and F3.2e paths: $(cat "$tmpdir/cs.rspset.dd")"
# --------- Exact historical C25..C40 path set (exactly eight)
cat > "$tmpdir/cs.f32bset.exp" <<'EOF'
docs/DECISION-LOG.md
docs/f3/F3.2B-PSBT-DECISION-PACKET.md
docs/f3/F3.2B-PSBT-OWNER-RESPONSE-RECORD.md
docs/f3/F3.2C-D11-MEDIA-WRITE-LIFECYCLE-CONSTRUCTION-PACKET.md
docs/f3/F3.2D-D11-Q001-OWNER-CLARIFICATION-RECORD.md
docs/f3/F3.2E-PSBT-OUTPUT-TEST-ALIGNMENT-PACKET.md
tools/verify-current-stage.sh
tools/verify-host-boundary.sh
EOF
$GIT diff --name-only "$C25" "$C40" > "$tmpdir/cs.f32bset.raw" \
  || err "git diff C25..C40 failed (enumeration fail-closed)"
[ -s "$tmpdir/cs.f32bset.raw" ] || err "git diff C25..C40 returned no paths (enumeration fail-closed)"
LC_ALL=C sort "$tmpdir/cs.f32bset.raw" > "$tmpdir/cs.f32bset.act" \
  || err "C25..C40 path-set sort failed (fail-closed)"
diff "$tmpdir/cs.f32bset.exp" "$tmpdir/cs.f32bset.act" > "$tmpdir/cs.f32bset.dd" 2>&1 \
  || err "changes since published C25 differ from the eight authorized F3.2b, F3.2c, F3.2d, and F3.2e paths: $(cat "$tmpdir/cs.f32bset.dd")"
# --------- Exact historical C28..C40 path set (exactly seven)
cat > "$tmpdir/cs.f32brspset.exp" <<'EOF'
docs/DECISION-LOG.md
docs/f3/F3.2B-PSBT-OWNER-RESPONSE-RECORD.md
docs/f3/F3.2C-D11-MEDIA-WRITE-LIFECYCLE-CONSTRUCTION-PACKET.md
docs/f3/F3.2D-D11-Q001-OWNER-CLARIFICATION-RECORD.md
docs/f3/F3.2E-PSBT-OUTPUT-TEST-ALIGNMENT-PACKET.md
tools/verify-current-stage.sh
tools/verify-host-boundary.sh
EOF
$GIT diff --name-only "$C28" "$C40" > "$tmpdir/cs.f32brspset.raw" \
  || err "git diff C28..C40 failed (enumeration fail-closed)"
[ -s "$tmpdir/cs.f32brspset.raw" ] || err "git diff C28..C40 returned no paths (enumeration fail-closed)"
LC_ALL=C sort "$tmpdir/cs.f32brspset.raw" > "$tmpdir/cs.f32brspset.act" \
  || err "C28..C40 path-set sort failed (fail-closed)"
diff "$tmpdir/cs.f32brspset.exp" "$tmpdir/cs.f32brspset.act" > "$tmpdir/cs.f32brspset.dd" 2>&1 \
  || err "changes since published C28 differ from the seven authorized F3.2b response, F3.2c, F3.2d, and F3.2e paths: $(cat "$tmpdir/cs.f32brspset.dd")"
# Every tracked blob outside the seven-path historical C28..C40 set above —
# including the F3.2b decision packet, the PSBT draft, F3 README,
# wallet-trust spine, SOURCE-REGISTER, OPEN-DECISIONS, OD-08 docs,
# architecture, requirements, security docs, gates, limits, tests,
# evidence, code, manifests/lock, .replit and all the rest — is
# therefore byte-identical to the published C28 state; executable
# scope is unchanged.
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
# F3.2d exact 1/2/1 path-mode matrix above the published C34 source
# base. Path sets are checked above; this binds every authorized entry
# mode at its introducing commit.
for f32dmodepair in \
  "$C35 100644 docs/DECISION-LOG.md" \
  "$C36 100644 docs/f3/F3.2D-D11-Q001-OWNER-CLARIFICATION-RECORD.md" \
  "$C36 100755 tools/verify-host-boundary.sh" \
  "$C37 100755 tools/verify-current-stage.sh"; do
  f32dmodecommit=${f32dmodepair%% *}
  f32dmoderest=${f32dmodepair#* }
  f32dmodeexp=${f32dmoderest%% *}
  f32dmodepath=${f32dmoderest#* }
  $GIT ls-tree "$f32dmodecommit" -- "$f32dmodepath" > "$tmpdir/cs.f32d.mode.raw" \
    || err "F3.2d ls-tree failed for $f32dmodepath"
  [ -s "$tmpdir/cs.f32d.mode.raw" ] || err "F3.2d mode entry missing for $f32dmodepath"
  f32dmodelines=$(awk 'END {print NR+0}' "$tmpdir/cs.f32d.mode.raw") \
    || err "F3.2d mode line count failed for $f32dmodepath"
  [ "$f32dmodelines" = 1 ] || err "F3.2d mode entry is not unique for $f32dmodepath"
  f32dmodeact=$(awk 'NR == 1 {print $1}' "$tmpdir/cs.f32d.mode.raw") \
    || err "F3.2d mode extraction failed for $f32dmodepath"
  [ "$f32dmodeact" = "$f32dmodeexp" ] \
    || err "F3.2d mode for $f32dmodepath is $f32dmodeact, expected $f32dmodeexp"
done
# F3.2e exact 1/2/1 path-mode matrix above the published C37 source
# base. Path sets are checked above; this binds every authorized entry
# mode at its introducing commit.
for f32emodepair in \
  "$C38 100644 docs/DECISION-LOG.md" \
  "$C39 100644 docs/f3/F3.2E-PSBT-OUTPUT-TEST-ALIGNMENT-PACKET.md" \
  "$C39 100755 tools/verify-host-boundary.sh" \
  "$C40 100755 tools/verify-current-stage.sh"; do
  f32emodecommit=${f32emodepair%% *}
  f32emoderest=${f32emodepair#* }
  f32emodeexp=${f32emoderest%% *}
  f32emodepath=${f32emoderest#* }
  $GIT ls-tree "$f32emodecommit" -- "$f32emodepath" > "$tmpdir/cs.f32e.mode.raw" \
    || err "F3.2e ls-tree failed for $f32emodepath"
  [ -s "$tmpdir/cs.f32e.mode.raw" ] || err "F3.2e mode entry missing for $f32emodepath"
  f32emodelines=$(awk 'END {print NR+0}' "$tmpdir/cs.f32e.mode.raw") \
    || err "F3.2e mode line count failed for $f32emodepath"
  [ "$f32emodelines" = 1 ] || err "F3.2e mode entry is not unique for $f32emodepath"
  f32emodeact=$(awk 'NR == 1 {print $1}' "$tmpdir/cs.f32e.mode.raw") \
    || err "F3.2e mode extraction failed for $f32emodepath"
  [ "$f32emodeact" = "$f32emodeexp" ] \
    || err "F3.2e mode for $f32emodepath is $f32emodeact, expected $f32emodeexp"
done
# F3.2f exact 1/2/1 path-mode matrix above the published C40 source
# base. Historical checks remain fixed at the published F3.2f C.
for f32fmodepair in \
  "$C41 100644 docs/DECISION-LOG.md" \
  "$C42 100644 docs/f3/F3.2F-PSBT-OUTPUT-TEST-OWNER-DIRECTION-RECORD.md" \
  "$C42 100755 tools/verify-host-boundary.sh" \
  "$C43 100755 tools/verify-current-stage.sh"; do
  f32fmodecommit=${f32fmodepair%% *}
  f32fmoderest=${f32fmodepair#* }
  f32fmodeexp=${f32fmoderest%% *}
  f32fmodepath=${f32fmoderest#* }
  $GIT ls-tree "$f32fmodecommit" -- "$f32fmodepath" > "$tmpdir/cs.f32f.mode.raw" \
    || err "F3.2f ls-tree failed for $f32fmodepath"
  [ -s "$tmpdir/cs.f32f.mode.raw" ] || err "F3.2f mode entry missing for $f32fmodepath"
  f32fmodelines=$(awk 'END {print NR+0}' "$tmpdir/cs.f32f.mode.raw") \
    || err "F3.2f mode line count failed for $f32fmodepath"
  [ "$f32fmodelines" = 1 ] || err "F3.2f mode entry is not unique for $f32fmodepath"
  f32fmodeact=$(awk 'NR == 1 {print $1}' "$tmpdir/cs.f32f.mode.raw") \
    || err "F3.2f mode extraction failed for $f32fmodepath"
  [ "$f32fmodeact" = "$f32fmodeexp" ] \
    || err "F3.2f mode for $f32fmodepath is $f32fmodeact, expected $f32fmodeexp"
done
# F3.2g exact 1/2/1 path-mode matrix above the published C43 source
# base. Path sets are checked independently above.
for f32gmodepair in \
  "$C44 100644 docs/DECISION-LOG.md" \
  "$C45 100644 docs/TEST-ARCHITECTURE.md" \
  "$C45 100755 tools/verify-host-boundary.sh" \
  "$F32G_C 100755 tools/verify-current-stage.sh"; do
  f32gmodecommit=${f32gmodepair%% *}
  f32gmoderest=${f32gmodepair#* }
  f32gmodeexp=${f32gmoderest%% *}
  f32gmodepath=${f32gmoderest#* }
  $GIT ls-tree "$f32gmodecommit" -- "$f32gmodepath" > "$tmpdir/cs.f32g.mode.raw" \
    || err "F3.2g ls-tree failed for $f32gmodepath"
  [ -s "$tmpdir/cs.f32g.mode.raw" ] || err "F3.2g mode entry missing for $f32gmodepath"
  f32gmodelines=$(awk 'END {print NR+0}' "$tmpdir/cs.f32g.mode.raw") \
    || err "F3.2g mode line count failed for $f32gmodepath"
  [ "$f32gmodelines" = 1 ] || err "F3.2g mode entry is not unique for $f32gmodepath"
  f32gmodeact=$(awk 'NR == 1 {print $1}' "$tmpdir/cs.f32g.mode.raw") \
    || err "F3.2g mode extraction failed for $f32gmodepath"
  [ "$f32gmodeact" = "$f32gmodeexp" ] \
    || err "F3.2g mode for $f32gmodepath is $f32gmodeact, expected $f32gmodeexp"
done
# F3.2h exact 1/2/1 path-mode matrix above the published F32G_C
# source base. Path sets are checked independently above.
for f32hmodepair in \
  "$C46 100644 docs/DECISION-LOG.md" \
  "$C47 100644 docs/f3/F3.2H-QK-LIM-PSBT-027-CROSS-DOCUMENT-ALIGNMENT-PACKET.md" \
  "$C47 100755 tools/verify-host-boundary.sh" \
  "$head 100755 tools/verify-current-stage.sh"; do
  f32hmodecommit=${f32hmodepair%% *}
  f32hmoderest=${f32hmodepair#* }
  f32hmodeexp=${f32hmoderest%% *}
  f32hmodepath=${f32hmoderest#* }
  $GIT ls-tree "$f32hmodecommit" -- "$f32hmodepath" > "$tmpdir/cs.f32h.mode.raw" \
    || err "F3.2h ls-tree failed for $f32hmodepath"
  [ -s "$tmpdir/cs.f32h.mode.raw" ] || err "F3.2h mode entry missing for $f32hmodepath"
  f32hmodelines=$(awk 'END {print NR+0}' "$tmpdir/cs.f32h.mode.raw") \
    || err "F3.2h mode line count failed for $f32hmodepath"
  [ "$f32hmodelines" = 1 ] || err "F3.2h mode entry is not unique for $f32hmodepath"
  f32hmodeact=$(awk 'NR == 1 {print $1}' "$tmpdir/cs.f32h.mode.raw") \
    || err "F3.2h mode extraction failed for $f32hmodepath"
  [ "$f32hmodeact" = "$f32hmodeexp" ] \
    || err "F3.2h mode for $f32hmodepath is $f32hmodeact, expected $f32hmodeexp"
done
# F3.2c Commit B mode partition: packet exactly 100644 and active host
# verifier exactly 100755, each represented by one unique tree entry.
for bmodepair in \
  '100644 docs/f3/F3.2C-D11-MEDIA-WRITE-LIFECYCLE-CONSTRUCTION-PACKET.md' \
  '100755 tools/verify-host-boundary.sh'; do
  bmodeexp=${bmodepair%% *}
  bmodepath=${bmodepair#* }
  $GIT ls-tree "$C33" -- "$bmodepath" > "$tmpdir/cs.f32c.bmode.raw" \
    || err "git ls-tree C33 failed for $bmodepath"
  [ -s "$tmpdir/cs.f32c.bmode.raw" ] || err "C33 mode entry missing for $bmodepath"
  bmodelines=$(awk 'END { print NR+0 }' "$tmpdir/cs.f32c.bmode.raw") \
    || err "C33 mode line count failed for $bmodepath"
  [ "$bmodelines" = "1" ] || err "C33 mode entry is not unique for $bmodepath"
  bmodeact=$(awk 'NR == 1 { print $1 }' "$tmpdir/cs.f32c.bmode.raw") \
    || err "C33 mode extraction failed for $bmodepath"
  [ "$bmodeact" = "$bmodeexp" ] || err "C33 mode for $bmodepath is $bmodeact, expected $bmodeexp"
done
# Commit B mode partition: the new response record is exactly 100644
# and the host verifier remains exactly 100755.
for bmodepair in \
  '100644 docs/f3/F3.2B-PSBT-OWNER-RESPONSE-RECORD.md' \
  '100755 tools/verify-host-boundary.sh'; do
  bmodeexp=${bmodepair%% *}
  bmodepath=${bmodepair#* }
  $GIT ls-tree "$C30" -- "$bmodepath" > "$tmpdir/cs.bmode.raw" \
    || err "git ls-tree C30 failed for $bmodepath (fail-closed)"
  [ -s "$tmpdir/cs.bmode.raw" ] || err "C30 mode entry missing for $bmodepath"
  bmodelines=$(awk 'BEGIN { n = 0 } { n = n + 1 } END { print n }' "$tmpdir/cs.bmode.raw") \
    || err "C30 mode line count failed for $bmodepath"
  [ "$bmodelines" = "1" ] || err "C30 mode entry is not unique for $bmodepath (found $bmodelines)"
  bmodeact=$(awk 'NR == 1 { print $1 }' "$tmpdir/cs.bmode.raw") \
    || err "C30 mode extraction failed for $bmodepath"
  [ "$bmodeact" = "$bmodeexp" ] \
    || err "C30 mode for $bmodepath is $bmodeact, expected $bmodeexp"
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

# ---------------- F3.2b PSBT owner-response record
# Direct essentials plus static host-guard presence. Supporting
# evidence only; neither verifier can authenticate its own semantics.
F32BRSP=docs/f3/F3.2B-PSBT-OWNER-RESPONSE-RECORD.md
[ -f "$F32BRSP" ] || err "$F32BRSP missing"
$GIT show "$C30:$F32BRSP" > "$tmpdir/cs.f32brsp.b" 2>/dev/null \
  || err "cannot read $F32BRSP from C30"
cmp -s "$tmpdir/cs.f32brsp.b" "$F32BRSP"
f32brc=$?
[ "$f32brc" -eq 0 ] || err "$F32BRSP is not byte-identical to reviewed C30 response Commit B (cmp exit $f32brc)"
$GIT show "$C28:docs/f3/F3.2B-PSBT-DECISION-PACKET.md" > "$tmpdir/cs.f32brsp.packet.base" 2>/dev/null \
  || err "cannot read source packet from C28"
cmp -s "$tmpdir/cs.f32brsp.packet.base" docs/f3/F3.2B-PSBT-DECISION-PACKET.md
f32brc=$?
[ "$f32brc" -eq 0 ] || err "source packet is not byte-identical to published C28 (cmp exit $f32brc)"
$GIT show "$C28:docs/f3/PSBT-V0-REVIEW-PROFILE-DRAFT.md" > "$tmpdir/cs.f32brsp.profile.base" 2>/dev/null \
  || err "cannot read PSBT profile draft from C28"
cmp -s "$tmpdir/cs.f32brsp.profile.base" docs/f3/PSBT-V0-REVIEW-PROFILE-DRAFT.md
f32brc=$?
[ "$f32brc" -eq 0 ] || err "PSBT profile draft is not byte-identical to published C28 (cmp exit $f32brc)"
f32brspstatus='STATUS: OWNER DIRECTION RECORDED — NON-ENACTING — POLICY DIRECTION ONLY — PROFILE NOT ACCEPTED — D-04 OWNER-OPEN — D-07, D-09, AND D-11 EVIDENCE/CONSTRUCTION-BLOCKED — NO IMPLEMENTATION — NO VECTORS GENERATED OR RUN — NO LICENSE APPLICATION — NO HARDWARE OR SETTINGS CHANGE — LOCAL AND UNPUBLISHED.'
f32brspc=$(grep -cFx -e "$f32brspstatus" "$F32BRSP")
f32brc=$?
[ "$f32brc" -le 1 ] || err "F3.2b response STATUS check failed"
[ "$f32brspc" = "1" ] || err "$F32BRSP exact STATUS not present exactly once (found $f32brspc)"
f32brspp=$(grep -c '^STATUS:' "$F32BRSP")
f32brc=$?
[ "$f32brc" -le 1 ] || err "F3.2b response STATUS-prefix check failed"
[ "$f32brspp" = "1" ] || err "$F32BRSP must contain exactly one STATUS line (found $f32brspp)"
f32brspq=$(awk 'BEGIN { n = 0 } { s = $0
  while ((i = index(s, "F32B-PSBT-Q-")) > 0) { n = n + 1; s = substr(s, i + 12) } }
  END { print n }' "$F32BRSP") || err "F3.2b response Q-ID enumeration failed"
[ "$f32brspq" = "8" ] || err "$F32BRSP must contain exactly 8 Q-ID occurrences (found $f32brspq)"
grep '^| F32B-PSBT-Q-' "$F32BRSP" > "$tmpdir/cs.f32brsp.rows"
f32brc=$?
[ "$f32brc" -le 1 ] || err "F3.2b response-row extraction failed"
cat > "$tmpdir/cs.f32brsp.rows.expected" <<'QK_F32B_RESPONSE_ROWS_EOF' || err "F3.2b response expected-row generation failed"
| F32B-PSBT-Q-001 | D-02 | APPROVE RECOMMENDED DIRECTION (NON-ENACTING) |
| F32B-PSBT-Q-002 | present-profile D-05 | APPROVE RECOMMENDED DIRECTION (NON-ENACTING) |
| F32B-PSBT-Q-003 | D-06 | APPROVE RECOMMENDED DIRECTION (NON-ENACTING) |
| F32B-PSBT-Q-004 | D-10 | APPROVE RECOMMENDED DIRECTION (NON-ENACTING) |
QK_F32B_RESPONSE_ROWS_EOF
cmp -s "$tmpdir/cs.f32brsp.rows.expected" "$tmpdir/cs.f32brsp.rows"
f32brc=$?
[ "$f32brc" -eq 0 ] || err "$F32BRSP exact ordered response rows differ (cmp exit $f32brc)"
for f32breq in \
  'bb6601f3b97528a72c55622251a4b475680ec21b' \
  'docs/f3/F3.2B-PSBT-DECISION-PACKET.md' \
  '“Approve all four F3.2b directions.”' \
  'This record is governance provenance, not cryptographic identity proof, audit proof, or profile acceptance.' \
  'D-00 remains blocked.' \
  'D-04 remains OWNER-OPEN, with representative coordinator-corpus review required before selection.' \
  'D-07 remains EVIDENCE/CONSTRUCTION-BLOCKED pending target/human QK-LIM evidence.' \
  'D-09 remains EVIDENCE/CONSTRUCTION-BLOCKED pending the exact commitment construction.' \
  'D-11 remains EVIDENCE/CONSTRUCTION-BLOCKED pending the media/write lifecycle.' \
  'OD-05 remains open.' \
  'Every QK-LIM remains open.' \
  'QK-TST and all evidence statuses remain unchanged.' \
  'complete trio specifically as PSBT_OUT_BIP32_DERIVATION records, one each for A, B, and C' \
  'The class-3 fallback applies only to missing, coherent-but-incomplete, or unrelated, structurally valid output BIP32-derivation metadata' \
  'PSBT_OUT_WITNESS_SCRIPT is unnecessary. If present, it is allowed only with a complete D-derived candidate and must byte-match the independently derived witnessScript; otherwise reject.' \
  'PSBT_GLOBAL_XPUB and external/coordinator labels neither prove ownership nor alone cause rejection.' \
  'Any pre-existing PSBT_IN_PARTIAL_SIG record, selected or non-selected, or any finalization field makes the PSBT ineligible and rejects at import before private-key/card access.' \
  'Such a record or field is never validate-counted, preserved into output, overwritten, or stripped; therefore no pre-existing signature or final field can appear in an eligible output.' \
  'Only accepted pre-existing NON-SIGNATURE key-value encodings are preserved byte-for-byte and in relative order.' \
  'output has exactly the authorized two new selected-pair PSBT_IN_PARTIAL_SIG records' \
  'No publication authority is granted.'; do
  f32breqc=$(grep -cF -e "$f32breq" "$F32BRSP")
  f32brc=$?
  [ "$f32brc" -le 1 ] || err "F3.2b response essential count failed: $f32breq"
  [ "$f32breqc" = "1" ] || err "F3.2b response essential not present exactly once (found $f32breqc): $f32breq"
done
forbid "$F32BRSP carries the stale flattened D-item status" \
  -F 'D-04, D-07, D-09, and D-11 remain open.' "$F32BRSP"
forbid "$F32BRSP carries the stale allowed-non-selected-signature sentence" \
  -F 'Any allowed pre-existing non-selected signature remains pre-existing and byte-preserved' "$F32BRSP"
# Direct actual-byte scan, plus static requirements below that the
# reviewed host verifier performs the same checked od/tr/grep stages.
od -An -tx1 "$F32BRSP" > "$tmpdir/cs.f32brsp.bytes.raw" \
  || err "$F32BRSP byte scan failed (od fail-closed)"
[ -s "$tmpdir/cs.f32brsp.bytes.raw" ] || err "$F32BRSP byte scan produced no output"
tr -d '[:space:]' < "$tmpdir/cs.f32brsp.bytes.raw" > "$tmpdir/cs.f32brsp.bytes.hex" \
  || err "$F32BRSP byte scan normalization failed (tr fail-closed)"
[ -s "$tmpdir/cs.f32brsp.bytes.hex" ] || err "$F32BRSP normalized byte scan is empty"
f32bbidi=$(grep -cE 'e280a[abde]|e281a[6-9]' "$tmpdir/cs.f32brsp.bytes.hex")
f32brc=$?
[ "$f32brc" -le 1 ] || err "$F32BRSP actual-byte bidi scan failed (grep exit $f32brc)"
[ "$f32bbidi" = "0" ] || err "$F32BRSP contains an actual UTF-8 bidirectional control sequence"
# Static requirement that the reviewed host verifier carries the
# corresponding exact/closed-world and policy-widening guard families.
for f32bhguard in \
  'must contain exactly 8 Q-ID occurrences' \
  'rows are missing, duplicated, reordered, malformed, or extra' \
  'GLOBAL_XPUB strict match' \
  'P2TR future-only boundary' \
  'D-06 branch distinction' \
  'D-06 complete output-derivation trio' \
  'D-06 class-3 fallback boundary' \
  'D-06 witnessScript rule' \
  'D-06 label neutrality' \
  'D-06 contradiction rejection' \
  'D-10 incoming-signature import rejection' \
  'D-10 incoming-signature non-output boundary' \
  'D-10 accepted non-signature preservation' \
  'D-10 exactly-two signatures' \
  'D-10 finalization prohibition' \
  'D-11 unresolved boundary' \
  'Q-003 allows witnessScript fall-through' \
  'Q-003 rejects solely on an external/coordinator label' \
  'Q-004 allows incoming non-selected partial signatures' \
  'Q-004 preserves incoming partial signatures' \
  'actual-byte bidi scan' \
  'od -An -tx1' \
  'r32.bytes.raw' \
  'r32.bytes.hex' \
  'e280a[abde]|e281a[6-9]' \
  'gives GLOBAL_XPUB authoritative force' \
  'weakens exactly-two signatures to up-to-two' \
  'claims profile acceptance' \
  'claims publication'; do
  grep -F -e "$f32bhguard" tools/verify-host-boundary.sh >/dev/null \
    || err "active host checker missing F3.2b response guard: $f32bhguard"
done
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

# F3.2c direct bindings. Supporting self-authored evidence only; these
# checks do not authenticate themselves or replace independent audit.
F32CPKT=docs/f3/F3.2C-D11-MEDIA-WRITE-LIFECYCLE-CONSTRUCTION-PACKET.md
$GIT show "$C32:docs/DECISION-LOG.md" > "$tmpdir/cs.f32c.dlog" 2>/dev/null || err "cannot read C32 Decision Log"
$GIT show "$C34:docs/DECISION-LOG.md" > "$tmpdir/cs.f32c.dlog.c34.direct" 2>/dev/null || err "cannot read C34 Decision Log"
cmp -s "$tmpdir/cs.f32c.dlog" "$tmpdir/cs.f32c.dlog.c34.direct" || err "C34 Decision Log did not retain the exact historical C32 bytes"
$GIT show "$C33:$F32CPKT" > "$tmpdir/cs.f32c.packet" 2>/dev/null || err "cannot read C33 packet"
cmp -s "$tmpdir/cs.f32c.packet" "$F32CPKT" || err "F3.2c packet is not byte-identical to C33"
csf32cblob=b4594210975940df71b0e941841320d11defaa4c
csf32ctreeblob=$($GIT ls-tree "$C33" -- "$F32CPKT" | awk '{print $3}'); csf32crc=$?
[ "$csf32crc" -eq 0 ] || err "F3.2c C33 packet tree-blob lookup failed"
[ "$csf32ctreeblob" = "$csf32cblob" ] || err "F3.2c C33 packet tree blob differs from the approved packet blob"
csf32cactblob=$($GIT hash-object -- "$F32CPKT"); csf32crc=$?
[ "$csf32crc" -eq 0 ] || err "F3.2c active packet hash-object scan failed"
[ "$csf32cactblob" = "$csf32cblob" ] || err "F3.2c active packet blob differs from the approved packet blob"
grep -F -e 'git --no-optional-locks hash-object -- "$PKT32C"' tools/verify-host-boundary.sh >/dev/null \
  || err "host verifier is missing the packet hash-object audit-locator mechanism"
grep -F -e 'b4594210975940df71b0e941841320d11defaa4c' tools/verify-host-boundary.sh >/dev/null \
  || err "host verifier is missing the approved packet audit-locator blob"
grep -F -e '[ "$p32blobact" = "$p32blob" ] || err' tools/verify-host-boundary.sh >/dev/null \
  || err "host verifier is missing the active packet blob comparison"
$GIT show "$C33:tools/verify-host-boundary.sh" > "$tmpdir/cs.f32c.host" 2>/dev/null || err "cannot read C33 host verifier"
$GIT show "$C34:tools/verify-host-boundary.sh" > "$tmpdir/cs.f32c.host.c34" 2>/dev/null || err "cannot read C34 host verifier"
cmp -s "$tmpdir/cs.f32c.host" "$tmpdir/cs.f32c.host.c34" || err "C34 host verifier did not retain the exact historical C33 bytes"
for csf32c in \
  '# QK-F3.2c — D-11 Media/Write Lifecycle Construction and Readiness Packet (Non-Binding)' \
  'OWNER QUESTIONS UNANSWERED' \
  'D-11 selection is blocked until owner meaning is resolved.' \
  'p32set F32C-D11-C 8' \
  'p32set F32C-D11-E 10' \
  'p32set F32C-D11-Q 12' \
  'p32set F32C-D11-F 22' \
  'row-leading IDs are not the exact ordered C/E/Q/F union' \
  'expected exactly 52' \
  'failure rows or outcomes are not exact' \
  'pipe-carrying lines are not exactly the four closed tables' \
  'hash-carrying lines are not exactly the one H1 and eleven H2 headings' \
  'contains a contradictory claim' \
  'contains a Setext underline or pipe-free GFM table delimiter run' \
  'od byte scan produced empty output' \
  'UTF-8 validation changed bytes' \
  'e2808[ef]|e280a[a-e]|e281a[6-9]' \
  'never self-authentication or independent proof.'; do
  grep -F -e "$csf32c" tools/verify-host-boundary.sh "$F32CPKT" >/dev/null \
    || err "F3.2c static guard/packet phrase missing: $csf32c"
done
# Independent exact full-line STATUS binding: the packet's sole STATUS:
# line must equal the complete required banner byte-for-byte.
csf32cstatus='STATUS: OWNER-AUTHORIZED CONSTRUCTION/READINESS INPUT ONLY — NON-NORMATIVE — D-11 EVIDENCE/CONSTRUCTION-BLOCKED — D-11 NOT SELECTED — OWNER QUESTIONS UNANSWERED — PSBT PROFILE NOT ACCEPTED — NO IMPLEMENTATION OR DEPENDENCIES — NO VECTORS, FIXTURES, OR SPECIMENS GENERATED OR RUN — NO MEDIA I/O OR TESTING — NO TARGET EVIDENCE — NO QK-LIM VALUE SELECTED — NO QK-TST/EVIDENCE/GATE CHANGE — NO LICENSE APPLICATION — NO HARDWARE, FIRMWARE, SETTINGS, OR CREDENTIAL CHANGE — LOCAL AND UNPUBLISHED.'
[ "$(grep -c '^STATUS:' "$F32CPKT")" = 1 ] || err "F3.2c packet must contain exactly one canonical STATUS line"
csf32cstatusany=$(awk '{s=$0; while (match(s,/STATUS:/)) {c++; s=substr(s,RSTART+RLENGTH)}} END {print c+0}' "$F32CPKT"); csf32crc=$?
[ "$csf32crc" -eq 0 ] || err "F3.2c global STATUS occurrence scan failed"
case $csf32cstatusany in ''|*[!0-9]*) err "F3.2c global STATUS occurrence scan produced empty or non-numeric output" ;; esac
[ "$csf32cstatusany" = 1 ] || err "F3.2c packet must contain exactly one STATUS: occurrence anywhere (found $csf32cstatusany)"
grep -F -e 'awk '\''{s=$0; while (match(s,/STATUS:/)) {c++; s=substr(s,RSTART+RLENGTH)}} END {print c+0}'\'' "$PKT32C"' tools/verify-host-boundary.sh >/dev/null \
  || err "host verifier is missing the literal STATUS occurrence-count mechanism"
grep -F -e 'global STATUS occurrence scan produced empty or non-numeric output' tools/verify-host-boundary.sh >/dev/null \
  || err "host verifier is missing the fail-closed STATUS occurrence output guard"
grep -F -e 'STATUS same-line uniqueness canary generation failed' tools/verify-host-boundary.sh >/dev/null \
  || err "host verifier is missing the corrected same-line STATUS canary"
grep '^STATUS:' "$F32CPKT" > "$tmpdir/cs.f32c.status.act" || err "F3.2c STATUS line extraction failed"
printf '%s\n' "$csf32cstatus" > "$tmpdir/cs.f32c.status.exp" || err "F3.2c STATUS expected generation failed"
cmp -s "$tmpdir/cs.f32c.status.exp" "$tmpdir/cs.f32c.status.act"
csf32crc=$?
[ "$csf32crc" -eq 0 ] || err "F3.2c STATUS line is not exactly the complete required banner"
# Fail-closed suffix canaries: any appended text (including a
# 'D-11 SELECTED' claim) must break the exact full-line binding.
for csf32csfx in ' — D-11 SELECTED' ' EXTRA' '.'; do
  printf '%s%s\n' "$csf32cstatus" "$csf32csfx" > "$tmpdir/cs.f32c.status.bad" || err "F3.2c STATUS suffix canary generation failed"
  cmp -s "$tmpdir/cs.f32c.status.exp" "$tmpdir/cs.f32c.status.bad"
  csf32crc=$?
  [ "$csf32crc" -eq 1 ] || err "F3.2c STATUS suffix canary failed to detect appended text (cmp exit $csf32crc)"
done
# Independent global STATUS-uniqueness canaries cover visible Markdown
# prefixes and a second occurrence on the canonical line.
for csf32cstatusbad in '> STATUS: SECONDARY' '>> STATUS: SECONDARY' ' STATUS: SECONDARY'; do
  printf '%s\n%s\n' "$csf32cstatus" "$csf32cstatusbad" > "$tmpdir/cs.f32c.status.unique.bad" \
    || err "F3.2c STATUS uniqueness canary generation failed"
  csf32cstatusn=$(awk '{s=$0; while (match(s,/STATUS:/)) {c++; s=substr(s,RSTART+RLENGTH)}} END {print c+0}' "$tmpdir/cs.f32c.status.unique.bad"); csf32crc=$?
  [ "$csf32crc" -eq 0 ] || err "F3.2c STATUS uniqueness canary scan failed"
  case $csf32cstatusn in ''|*[!0-9]*) err "F3.2c STATUS uniqueness canary scan produced empty or non-numeric output" ;; esac
  [ "$csf32cstatusn" = 2 ] || err "F3.2c STATUS uniqueness canary did not count exactly two occurrences"
done
printf '%s STATUS: SECONDARY\n' "$csf32cstatus" > "$tmpdir/cs.f32c.status.unique.bad" \
  || err "F3.2c STATUS same-line uniqueness canary generation failed"
csf32cstatusn=$(awk '{s=$0; while (match(s,/STATUS:/)) {c++; s=substr(s,RSTART+RLENGTH)}} END {print c+0}' "$tmpdir/cs.f32c.status.unique.bad"); csf32crc=$?
[ "$csf32crc" -eq 0 ] || err "F3.2c STATUS same-line uniqueness canary scan failed"
case $csf32cstatusn in ''|*[!0-9]*) err "F3.2c STATUS same-line uniqueness canary scan produced empty or non-numeric output" ;; esac
[ "$csf32cstatusn" = 2 ] || err "F3.2c STATUS same-line uniqueness canary did not count exactly two occurrences"
# Independently enumerate the complete packet row union rather than
# relying only on the active host checker. Malformed, unknown-family,
# duplicate, suffixed, smuggled, or reordered row IDs fail.
: > "$tmpdir/cs.f32c.union.exp" || err "F3.2c expected union init failed"
for csf32cspec in 'C 8' 'E 10' 'Q 12' 'F 22'; do
  set -- $csf32cspec; csf32ci=1
  while [ "$csf32ci" -le "$2" ]; do
    printf 'F32C-D11-%s-%03d\n' "$1" "$csf32ci" >> "$tmpdir/cs.f32c.union.exp" \
      || err "F3.2c expected union generation failed"
    csf32ci=$((csf32ci + 1))
  done
done
grep '^| F32C-D11-' "$F32CPKT" > "$tmpdir/cs.f32c.union.rows"
csf32crc=$?
[ "$csf32crc" -eq 0 ] || err "F3.2c row enumeration failed or returned no rows"
csf32craw=$(awk 'END { print NR }' "$tmpdir/cs.f32c.union.rows") || err "F3.2c raw row count failed"
[ "$csf32craw" = 52 ] || err "F3.2c raw F32C-D11 row count is $csf32craw, expected exactly 52"
sed -n 's/^| \(F32C-D11-[CEQF]-[0-9][0-9][0-9]\) |.*$/\1/p' "$tmpdir/cs.f32c.union.rows" > "$tmpdir/cs.f32c.union.rowids" \
  || err "F3.2c row-ID extraction failed"
csf32cids=$(awk 'END { print NR }' "$tmpdir/cs.f32c.union.rowids") || err "F3.2c valid row-ID count failed"
[ "$csf32cids" = "$csf32craw" ] || err "F3.2c only $csf32cids of $csf32craw rows carry exact valid IDs"
cmp -s "$tmpdir/cs.f32c.union.exp" "$tmpdir/cs.f32c.union.rowids" \
  || err "F3.2c row IDs are not the exact ordered C/E/Q/F union"
awk '{s=$0; while (match(s,/F32C-D11-[A-Z]-[0-9][0-9][0-9]/)) {print substr(s,RSTART,RLENGTH); s=substr(s,RSTART+RLENGTH)}}' \
  "$F32CPKT" > "$tmpdir/cs.f32c.union.tokens" || err "F3.2c token enumeration failed"
cmp -s "$tmpdir/cs.f32c.union.exp" "$tmpdir/cs.f32c.union.tokens" \
  || err "F3.2c exact ID tokens are missing, duplicated, unknown, or smuggled"
# Closed-world broad token scan: every maximal F32C-D11-prefixed token
# over letters, digits, underscore, hyphen, and literal asterisk
# (any family width, digit width, suffix, or delimiter residue) must be
# an exact allowed ID or the single permitted exact E-family glob token
# F32C-D11-E-*.
awk '{s=$0; while (match(s,/F32C-D11-[A-Za-z0-9_*-]*/)) {print substr(s,RSTART,RLENGTH); s=substr(s,RSTART+RLENGTH)}}' \
  "$F32CPKT" > "$tmpdir/cs.f32c.union.broad" || err "F3.2c broad F32C-D11 token enumeration failed"
[ -s "$tmpdir/cs.f32c.union.broad" ] || err "F3.2c broad F32C-D11 token enumeration produced no tokens"
sort -u "$tmpdir/cs.f32c.union.broad" > "$tmpdir/cs.f32c.union.broad.sorted" || err "F3.2c broad token sort failed"
sort -u "$tmpdir/cs.f32c.union.exp" > "$tmpdir/cs.f32c.union.allow" || err "F3.2c expected union sort failed"
printf 'F32C-D11-E-*\n' >> "$tmpdir/cs.f32c.union.allow" || err "F3.2c family-glob allowance append failed"
sort -o "$tmpdir/cs.f32c.union.allow" "$tmpdir/cs.f32c.union.allow" || err "F3.2c allowance resort failed"
comm -23 "$tmpdir/cs.f32c.union.broad.sorted" "$tmpdir/cs.f32c.union.allow" > "$tmpdir/cs.f32c.union.stray" \
  || err "F3.2c stray-token comparison failed"
[ ! -s "$tmpdir/cs.f32c.union.stray" ] || err "F3.2c packet contains F32C-D11-prefixed tokens outside the exact allowed IDs"
csf32cglob=$(grep -cF -e 'F32C-D11-E-*' "$F32CPKT"); csf32crc=$?
[ "$csf32crc" -le 1 ] || err "F3.2c family-glob scan failed"
[ "$csf32cglob" = 1 ] || err "F3.2c family-glob mention F32C-D11-E-* must occur exactly once"
csf32cgtok=$(grep -cxF -e 'F32C-D11-E-*' "$tmpdir/cs.f32c.union.broad"); csf32crc=$?
[ "$csf32crc" -le 1 ] || err "F3.2c family-glob token count scan failed"
[ "$csf32cgtok" = 1 ] || err "F3.2c exact glob token F32C-D11-E-* must occur exactly once"
# Fail-closed regression probes: the broad closed-world scan must reject
# unknown and multi-letter families, wrong digit widths, suffixes, and
# malformed delimiters. Supporting self-authored evidence only.
cat > "$tmpdir/cs.f32c.probe.bad" <<'QK_CS_F32C_PROBE_EOF' || err "F3.2c probe sample generation failed"
F32C-D11-XX-001
F32C-D11-F-01
F32C-D11-F-0001
F32C-D11-F-001X
F32C-D11-F_001
F32C-D11-FF-010
F32C-D11-E-***
QK_CS_F32C_PROBE_EOF
awk '{s=$0; while (match(s,/F32C-D11-[A-Za-z0-9_*-]*/)) {print substr(s,RSTART,RLENGTH); s=substr(s,RSTART+RLENGTH)}}' \
  "$tmpdir/cs.f32c.probe.bad" > "$tmpdir/cs.f32c.probe.tok" || err "F3.2c probe tokenization failed"
csf32cptok=$(awk 'END { print NR }' "$tmpdir/cs.f32c.probe.tok") || err "F3.2c probe token count failed"
[ "$csf32cptok" = 7 ] || err "F3.2c probe tokenizer missed malformed IDs ($csf32cptok of 7)"
sort -u "$tmpdir/cs.f32c.probe.tok" > "$tmpdir/cs.f32c.probe.tok.sorted" || err "F3.2c probe token sort failed"
comm -23 "$tmpdir/cs.f32c.probe.tok.sorted" "$tmpdir/cs.f32c.union.allow" > "$tmpdir/cs.f32c.probe.stray" \
  || err "F3.2c probe comparison failed"
csf32cpstray=$(awk 'END { print NR }' "$tmpdir/cs.f32c.probe.stray") || err "F3.2c probe stray count failed"
[ "$csf32cpstray" = 7 ] || err "F3.2c closed-world probe failed to reject malformed IDs ($csf32cpstray of 7)"
cat > "$tmpdir/cs.f32c.failure.expected" <<'QK_CS_F32C_FAILURE_ROWS_EOF' || err "F3.2c expected failure rows generation failed"
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
QK_CS_F32C_FAILURE_ROWS_EOF
grep '^| F32C-D11-F-' "$F32CPKT" > "$tmpdir/cs.f32c.failure.actual" \
  || err "F3.2c failure row enumeration failed"
cmp -s "$tmpdir/cs.f32c.failure.expected" "$tmpdir/cs.f32c.failure.actual" \
  || err "F3.2c failure rows or outcomes differ from the exact closed table"
# Independent closed-world pipe transcript: every '|'-carrying line in
# the packet must be exactly the ordered concatenation of the four
# closed tables below (60 lines, no prose pipes); leading-pipe-omitted,
# indented, extra-cell, appended, dropped, and reordered rows and any
# extra table section all fail. Supporting self-authored evidence only.
grep '|' "$F32CPKT" > "$tmpdir/cs.f32c.pipes.act"
csf32crc=$?
[ "$csf32crc" -eq 0 ] || err "F3.2c pipe-line enumeration failed or found no pipe lines"
csf32cpn=$(awk 'END { print NR }' "$tmpdir/cs.f32c.pipes.act") || err "F3.2c pipe-line count failed"
[ "$csf32cpn" = 60 ] || err "F3.2c pipe-carrying line count is $csf32cpn, expected exactly 60"
cat > "$tmpdir/cs.f32c.pipes.exp" <<'QK_CS_F32C_PIPES_EOF' || err "F3.2c expected pipe transcript generation failed"
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
QK_CS_F32C_PIPES_EOF
cmp -s "$tmpdir/cs.f32c.pipes.exp" "$tmpdir/cs.f32c.pipes.act"
csf32crc=$?
[ "$csf32crc" -eq 0 ] || err "F3.2c pipe-carrying lines are not exactly the four closed tables"
# Fail-closed pipe canaries: appended, dropped, indented, leading-pipe-
# omitted, and extra-cell variants must each break the byte compare.
{ cat "$tmpdir/cs.f32c.pipes.exp"; printf '%s\n' '| F32C-D11-C-001 | smuggled duplicate | EXTRA |'; } > "$tmpdir/cs.f32c.pipes.bad1" || err "F3.2c pipe canary 1 generation failed"
sed '$d' "$tmpdir/cs.f32c.pipes.exp" > "$tmpdir/cs.f32c.pipes.bad2" || err "F3.2c pipe canary 2 generation failed"
sed '1s/^/ /' "$tmpdir/cs.f32c.pipes.exp" > "$tmpdir/cs.f32c.pipes.bad3" || err "F3.2c pipe canary 3 generation failed"
sed '3s/^|//' "$tmpdir/cs.f32c.pipes.exp" > "$tmpdir/cs.f32c.pipes.bad4" || err "F3.2c pipe canary 4 generation failed"
sed '3s/|$/| EXTRA |/' "$tmpdir/cs.f32c.pipes.exp" > "$tmpdir/cs.f32c.pipes.bad5" || err "F3.2c pipe canary 5 generation failed"
for csf32cbadp in "$tmpdir/cs.f32c.pipes.bad1" "$tmpdir/cs.f32c.pipes.bad2" "$tmpdir/cs.f32c.pipes.bad3" "$tmpdir/cs.f32c.pipes.bad4" "$tmpdir/cs.f32c.pipes.bad5"; do
  cmp -s "$tmpdir/cs.f32c.pipes.exp" "$csf32cbadp"
  csf32crc=$?
  [ "$csf32crc" -eq 1 ] || err "F3.2c pipe transcript canary failed to detect a mutated table (cmp exit $csf32crc for $csf32cbadp)"
done
# Independent closed-world heading transcript: every '#'-carrying line
# in the packet must be exactly the one H1 plus the eleven H2 headings
# below, in order (12 lines, no prose hashes); extra, renamed,
# reordered, indented, or deeper ATX headings all fail.
grep '#' "$F32CPKT" > "$tmpdir/cs.f32c.heads.act"
csf32crc=$?
[ "$csf32crc" -eq 0 ] || err "F3.2c heading-line enumeration failed or found no hash lines"
csf32chn=$(awk 'END { print NR }' "$tmpdir/cs.f32c.heads.act") || err "F3.2c heading-line count failed"
[ "$csf32chn" = 12 ] || err "F3.2c hash-carrying line count is $csf32chn, expected exactly 12"
cat > "$tmpdir/cs.f32c.heads.exp" <<'QK_CS_F32C_HEADS_EOF' || err "F3.2c expected heading transcript generation failed"
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
QK_CS_F32C_HEADS_EOF
cmp -s "$tmpdir/cs.f32c.heads.exp" "$tmpdir/cs.f32c.heads.act"
csf32crc=$?
[ "$csf32crc" -eq 0 ] || err "F3.2c hash-carrying lines are not exactly the one H1 and eleven H2 headings"
# Fail-closed heading canaries: appended, dropped, indented, and renamed
# heading variants must each break the byte compare.
{ cat "$tmpdir/cs.f32c.heads.exp"; printf '%s\n' '### Smuggled deeper heading'; } > "$tmpdir/cs.f32c.heads.bad1" || err "F3.2c heading canary 1 generation failed"
sed '$d' "$tmpdir/cs.f32c.heads.exp" > "$tmpdir/cs.f32c.heads.bad2" || err "F3.2c heading canary 2 generation failed"
sed '2s/^/ /' "$tmpdir/cs.f32c.heads.exp" > "$tmpdir/cs.f32c.heads.bad3" || err "F3.2c heading canary 3 generation failed"
sed '2s/labels/labels renamed/' "$tmpdir/cs.f32c.heads.exp" > "$tmpdir/cs.f32c.heads.bad4" || err "F3.2c heading canary 4 generation failed"
for csf32cbadh in "$tmpdir/cs.f32c.heads.bad1" "$tmpdir/cs.f32c.heads.bad2" "$tmpdir/cs.f32c.heads.bad3" "$tmpdir/cs.f32c.heads.bad4"; do
  cmp -s "$tmpdir/cs.f32c.heads.exp" "$csf32cbadh"
  csf32crc=$?
  [ "$csf32crc" -eq 1 ] || err "F3.2c heading transcript canary failed to detect a mutated heading set (cmp exit $csf32crc for $csf32cbadh)"
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
forbid "F3.2c packet contains a Setext underline or pipe-free GFM table delimiter run" -E '^[[:blank:]]*(>[[:blank:]]*)*:?(=+|-+):?[[:blank:]]*$' "$F32CPKT"
for csf32csx in '=' '=====' '-' '-----' '   ---' ':---' '---:' ':---:' '   :---:' '> :---' '>> :---:' '> > ---:'; do
  printf '%s\n' "$csf32csx" > "$tmpdir/cs.f32c.setext.canary" || err "F3.2c Setext/GFM delimiter canary generation failed"
  grep -E '^[[:blank:]]*(>[[:blank:]]*)*:?(=+|-+):?[[:blank:]]*$' "$tmpdir/cs.f32c.setext.canary" >/dev/null
  csf32crc=$?
  [ "$csf32crc" -eq 0 ] || err "F3.2c Setext/GFM delimiter canary pattern failed to match run '$csf32csx' (grep exit $csf32crc)"
done
printf '%s\n' '| :--- | ---: |' > "$tmpdir/cs.f32c.setext.negative" || err "F3.2c Setext/GFM negative canary generation failed"
grep -E '^[[:blank:]]*(>[[:blank:]]*)*:?(=+|-+):?[[:blank:]]*$' "$tmpdir/cs.f32c.setext.negative" >/dev/null
csf32crc=$?
[ "$csf32crc" -eq 1 ] || err "F3.2c Setext/GFM delimiter pattern wrongly matched a legitimate piped separator line (grep exit $csf32crc)"
# Decision-Log tree-mode binding at the authorization commit A (C32),
# alongside the existing Commit-B/HEAD mode partition checks.
csdlmode=$($GIT ls-tree "$C32" -- docs/DECISION-LOG.md | awk '{ print $1 }') \
  || err "F3.2c Decision-Log mode lookup at C32 failed"
[ "$csdlmode" = 100644 ] || err "docs/DECISION-LOG.md tree mode at C32 is not exactly 100644"
for csf32csem in \
  'Interrupted QR cannot retract observed frames' \
  'a receiver may accumulate frames across interrupted or retried cycles' \
  'Conventional SD staging cannot guarantee no residue.' \
  'Neither route may silently assume the weaker interpretation.' \
  'no ARTIFACT-BEARING route output begins before D11-S6' \
  'A bounded read-only SD preflight is an unselected candidate that may precede review' \
  'Any bound preflight fact changing after approval goes to D11-X1.' \
  'QR-Q2 SELF_CHECKED is an explicit candidate branch, not a universal transition' \
  'exact-length write success before sync/close' \
  'successful sync/close return before temp readback while not proving durability' \
  'exact temp-byte equality plus `qk-core` fresh reparse before commit' \
  'successful target-proven no-replace visibility-transition return before the metadata barrier while not proving atomicity' \
  'successful target-specific metadata-barrier return before final readback while not proving durability' \
  'exact final-byte equality plus fresh reparse before local completion indication' \
  'S9 does not prove receipt, finalization, broadcast, or durability.' \
  'QK-F2E-008, QK-F2E-009, and QK-F2E-015 are protocol templates only — NOT RUN — NOT GATE EVIDENCE.' \
  'OD-05 and OD-06 remain OPEN.' \
  'Packet-local F32C-D11-E-* IDs create no canonical QK-TST, run registration, evidence record, or gate input.' \
  'QK-REQ-BND-003 requires that any intervening input, card, media, session, or state change after approval invalidates approval before signing.'; do
  grep -F -e "$csf32csem" "$F32CPKT" >/dev/null \
    || err "F3.2c independently required semantic is missing: $csf32csem"
done
# S9 location binding: the S9 boundary sentence is asserted packet-only
# in the csf32csem list above. Independently, exact full-line fixtures
# bind its one required-phrase entry inside the host p32req list and the
# complete active p32req-to-PKT32C enforcement line. An anywhere match,
# including one relocated to a comment, cannot satisfy either location.
csf32cs9='S9 does not prove receipt, finalization, broadcast, or durability.'
csf32cs9p=$(grep -cF -e "$csf32cs9" "$F32CPKT"); csf32crc=$?
[ "$csf32crc" -le 1 ] || err "F3.2c packet S9 line-count scan failed"
[ "$csf32cs9p" = 1 ] || err "F3.2c packet must contain exactly one S9 boundary line (found $csf32cs9p)"
cat > "$tmpdir/cs.f32c.s9.required-line" <<'QK_F32C_S9_REQUIRED_LINE_EOF'
  'S9 does not prove receipt, finalization, broadcast, or durability.' \
QK_F32C_S9_REQUIRED_LINE_EOF
csf32crc=$?
[ "$csf32crc" -eq 0 ] || err "F3.2c host S9 required-line fixture generation failed"
csf32cs9n=$(grep -cFx -f "$tmpdir/cs.f32c.s9.required-line" tools/verify-host-boundary.sh); csf32crc=$?
[ "$csf32crc" -le 1 ] || err "F3.2c host S9 exact required-line scan failed"
[ "$csf32cs9n" = 1 ] || err "host verifier must contain exactly one exact S9 p32req entry (found $csf32cs9n)"
cat > "$tmpdir/cs.f32c.s9.enforcement-line" <<'QK_F32C_S9_ENFORCEMENT_LINE_EOF'
  grep -F -e "$p32req" "$PKT32C" >/dev/null || err "$PKT32C missing semantic boundary: $p32req"
QK_F32C_S9_ENFORCEMENT_LINE_EOF
csf32crc=$?
[ "$csf32crc" -eq 0 ] || err "F3.2c host S9 enforcement-line fixture generation failed"
csf32cs9e=$(grep -cFx -f "$tmpdir/cs.f32c.s9.enforcement-line" tools/verify-host-boundary.sh); csf32crc=$?
[ "$csf32crc" -le 1 ] || err "F3.2c host S9 exact enforcement-line scan failed"
[ "$csf32cs9e" = 1 ] || err "host verifier must contain exactly one complete active p32req packet enforcement line (found $csf32cs9e)"
# Relocation canary: delete only the exact p32req entry, then append the
# same sentence as a comment. The anywhere count deliberately becomes
# two: one legitimate independently enforced F3.2d closed-section fixture plus the
# relocated comment. The exact historical p32req count must become zero.
grep -Fvx -f "$tmpdir/cs.f32c.s9.required-line" tools/verify-host-boundary.sh > "$tmpdir/cs.f32c.s9.relocated-host"
csf32crc=$?
[ "$csf32crc" -eq 0 ] || err "F3.2c S9 relocation canary host-copy generation failed"
printf '# %s\n' "$csf32cs9" >> "$tmpdir/cs.f32c.s9.relocated-host" \
  || err "F3.2c S9 relocation canary comment append failed"
csf32cs9a=$(grep -cF -e "$csf32cs9" "$tmpdir/cs.f32c.s9.relocated-host"); csf32crc=$?
[ "$csf32crc" -le 1 ] || err "F3.2c S9 relocation canary anywhere scan failed"
[ "$csf32cs9a" = 2 ] || err "F3.2c S9 relocation canary anywhere count is $csf32cs9a, expected 2 (F3.2d semantic plus relocated comment)"
csf32cs9x=$(grep -cFx -f "$tmpdir/cs.f32c.s9.required-line" "$tmpdir/cs.f32c.s9.relocated-host"); csf32crc=$?
[ "$csf32crc" -le 1 ] || err "F3.2c S9 relocation canary exact-line scan failed"
[ "$csf32cs9x" = 0 ] || err "F3.2c S9 relocation canary exact required-line count is $csf32cs9x, expected 0"
# Fail-closed S9 probes: (a) a packet copy with the S9 sentence removed
# must fail the dedicated packet-only grep even though the host verifier
# is unchanged; (b) a host-verifier copy with its S9 literal removed
# must contain no anywhere literal even though the packet
# is unchanged.
grep -Fv -e "$csf32cs9" "$F32CPKT" > "$tmpdir/cs.f32c.s9.pkt" || err "F3.2c S9 packet probe generation failed"
grep -F -e "$csf32cs9" "$tmpdir/cs.f32c.s9.pkt" >/dev/null
csf32crc=$?
[ "$csf32crc" -eq 1 ] || err "F3.2c S9 packet-removal probe was not detected by the packet-only check (grep exit $csf32crc)"
grep -Fv -e "$csf32cs9" tools/verify-host-boundary.sh > "$tmpdir/cs.f32c.s9.host" || err "F3.2c S9 host probe generation failed"
csf32cs9h=$(grep -cF -e "$csf32cs9" "$tmpdir/cs.f32c.s9.host"); csf32crc=$?
[ "$csf32crc" -le 1 ] || err "F3.2c S9 host probe scan failed"
[ "$csf32cs9h" = 0 ] || err "F3.2c S9 host-removal probe still contains the literal (probe ineffective)"
# Independent packet-only case-insensitive fixed contradictory-phrase
# loop (a closed fixed-phrase list, not exhaustive language coverage),
# run here in addition to executing and byte-binding the host verifier.
for csf32cclaim in 'D-11 SELECTED' 'D-11: SELECTED' 'PROFILE ACCEPTED' \
  'OWNER QUESTIONS ANSWERED' 'TARGET EVIDENCE PRESENT' 'GATE CLOSED' \
  'TESTS RUN' 'EVIDENCE RECORDED' 'IMPLEMENTATION ENABLED' \
  'PUBLICATION AUTHORIZED'; do
  csf32ccn=$(LC_ALL=C grep -ciF -e "$csf32cclaim" "$F32CPKT"); csf32crc=$?
  [ "$csf32crc" -le 1 ] || err "F3.2c contradictory-claim scan failed"
  [ "$csf32ccn" = 0 ] || err "F3.2c packet contains a contradictory claim: $csf32cclaim"
done
# Statically require the case-insensitive host claim guard and its
# canaries in the active host verifier.
grep -F -e 'LC_ALL=C grep -ciF -e "$p32claim" "$PKT32C"' tools/verify-host-boundary.sh >/dev/null \
  || err "host verifier is missing the case-insensitive contradictory-claim guard"
grep -F -e 'case-insensitive claim canary missed a mixed-case variant of:' tools/verify-host-boundary.sh >/dev/null \
  || err "host verifier is missing the mixed-case claim canaries"
# Mixed-case claim canaries plus zero-stage and error-stage probes for
# this independent loop: a lowercase variant must be counted, a
# claim-free sample must count zero (grep exit 1 tolerated), and a
# missing-file scan must report an error exit greater than 1.
printf '%s\n' 'D-11 selected' 'Publication authorized' > "$tmpdir/cs.f32c.claim.canary" \
  || err "F3.2c claim canary generation failed"
csf32ccc=$(LC_ALL=C grep -ciF -e 'D-11 SELECTED' "$tmpdir/cs.f32c.claim.canary"); csf32crc=$?
[ "$csf32crc" -eq 0 ] || err "F3.2c claim canary scan failed (grep exit $csf32crc)"
[ "$csf32ccc" = 1 ] || err "F3.2c case-insensitive claim canary missed the lowercase D-11 selected variant"
csf32ccc=$(LC_ALL=C grep -ciF -e 'PUBLICATION AUTHORIZED' "$tmpdir/cs.f32c.claim.canary"); csf32crc=$?
[ "$csf32crc" -eq 0 ] || err "F3.2c claim canary scan failed (grep exit $csf32crc)"
[ "$csf32ccc" = 1 ] || err "F3.2c case-insensitive claim canary missed the mixed-case publication variant"
printf 'no claims here\n' > "$tmpdir/cs.f32c.claim.zero" || err "F3.2c claim zero-sample generation failed"
csf32ccz=$(LC_ALL=C grep -ciF -e 'D-11 SELECTED' "$tmpdir/cs.f32c.claim.zero"); csf32crc=$?
[ "$csf32crc" -eq 1 ] || err "F3.2c claim zero-stage probe returned unexpected grep exit $csf32crc"
[ "$csf32ccz" = 0 ] || err "F3.2c claim zero-stage probe counted a phantom claim"
LC_ALL=C grep -ciF -e 'D-11 SELECTED' "$tmpdir/cs.f32c.claim.does-not-exist" >/dev/null 2>&1
csf32crc=$?
[ "$csf32crc" -gt 1 ] || err "F3.2c claim error-stage probe failed to report a scan error (grep exit $csf32crc)"
forbid "$F32CPKT retains stale preflight wording" -F 'no route I/O occurs before S6' "$F32CPKT"
forbid "$F32CPKT retains stale S9 wording" -F 'S9 proves no receipt' "$F32CPKT"
forbid "$F32CPKT retains stale blanket failure wording" -F 'For every row the proposed fail-closed outcome forbids' "$F32CPKT"
# Independent strict byte pipeline: checked and nonempty raw and
# normalized stages, exact UTF-8 round trip, and actual-byte control scan.
od -An -tx1 "$F32CPKT" > "$tmpdir/cs.f32c.bytes.raw" || err "F3.2c od stage failed"
[ -s "$tmpdir/cs.f32c.bytes.raw" ] || err "F3.2c od stage produced empty output"
tr -d '[:space:]' < "$tmpdir/cs.f32c.bytes.raw" > "$tmpdir/cs.f32c.bytes.hex" \
  || err "F3.2c tr stage failed"
[ -s "$tmpdir/cs.f32c.bytes.hex" ] || err "F3.2c tr stage produced empty output"
csf32cbad=$(grep -cE '(^efbbbf)|00|0d|e2808[ef]|e280a[a-e]|e281a[6-9]' "$tmpdir/cs.f32c.bytes.hex")
csf32crc=$?
[ "$csf32crc" -le 1 ] || err "F3.2c actual-byte control scan failed"
[ "$csf32cbad" = 0 ] || err "F3.2c contains BOM, NUL, CR, LRM/RLM, or bidi controls"
# The frozen historical host contains two pipeline-based terminal-LF
# assertions. Because A and B are immutable, current-stage is the
# authoritative fail-closed enforcement point for this historical
# predicate: every producing and normalizing stage is checked here.
tail -c 1 "$F32CPKT" > "$tmpdir/cs.f32c.final-one.raw"
csf32crc=$?
[ "$csf32crc" -eq 0 ] || err "F3.2c final-one-byte tail stage failed"
[ -s "$tmpdir/cs.f32c.final-one.raw" ] || err "F3.2c final-one-byte tail stage produced empty output"
od -An -tuC "$tmpdir/cs.f32c.final-one.raw" > "$tmpdir/cs.f32c.final-one.od"
csf32crc=$?
[ "$csf32crc" -eq 0 ] || err "F3.2c final-one-byte od stage failed"
[ -s "$tmpdir/cs.f32c.final-one.od" ] || err "F3.2c final-one-byte od stage produced empty output"
tr -d '[:space:]' < "$tmpdir/cs.f32c.final-one.od" > "$tmpdir/cs.f32c.final-one.norm"
csf32crc=$?
[ "$csf32crc" -eq 0 ] || err "F3.2c final-one-byte tr stage failed"
[ -s "$tmpdir/cs.f32c.final-one.norm" ] || err "F3.2c final-one-byte normalized stage produced empty output"
csf32cfinalone=$(cat "$tmpdir/cs.f32c.final-one.norm")
csf32crc=$?
[ "$csf32crc" -eq 0 ] || err "F3.2c final-one-byte normalized read failed"
case $csf32cfinalone in ''|*[!0-9]*) err "F3.2c final-one-byte normalized output is non-numeric" ;; esac
[ "$csf32cfinalone" = 10 ] || err "F3.2c packet must end in LF"
tail -c 2 "$F32CPKT" > "$tmpdir/cs.f32c.final-two.raw"
csf32crc=$?
[ "$csf32crc" -eq 0 ] || err "F3.2c final-two-byte tail stage failed"
[ -s "$tmpdir/cs.f32c.final-two.raw" ] || err "F3.2c final-two-byte tail stage produced empty output"
wc -c < "$tmpdir/cs.f32c.final-two.raw" > "$tmpdir/cs.f32c.final-two.count.raw"
csf32crc=$?
[ "$csf32crc" -eq 0 ] || err "F3.2c final-two-byte count failed"
[ -s "$tmpdir/cs.f32c.final-two.count.raw" ] || err "F3.2c final-two-byte count stage produced empty output"
tr -d '[:space:]' < "$tmpdir/cs.f32c.final-two.count.raw" > "$tmpdir/cs.f32c.final-two.count.norm"
csf32crc=$?
[ "$csf32crc" -eq 0 ] || err "F3.2c final-two-byte count normalization failed"
[ -s "$tmpdir/cs.f32c.final-two.count.norm" ] || err "F3.2c final-two-byte count normalization produced empty output"
csf32cfinaltwobytes=$(cat "$tmpdir/cs.f32c.final-two.count.norm")
csf32crc=$?
[ "$csf32crc" -eq 0 ] || err "F3.2c final-two-byte count normalized read failed"
case $csf32cfinaltwobytes in ''|*[!0-9]*) err "F3.2c final-two-byte count is non-numeric" ;; esac
[ "$csf32cfinaltwobytes" = 2 ] || err "F3.2c final-two-byte tail stage did not produce exactly two bytes"
od -An -tuC "$tmpdir/cs.f32c.final-two.raw" > "$tmpdir/cs.f32c.final-two.od"
csf32crc=$?
[ "$csf32crc" -eq 0 ] || err "F3.2c final-two-byte od stage failed"
[ -s "$tmpdir/cs.f32c.final-two.od" ] || err "F3.2c final-two-byte od stage produced empty output"
tr -d '[:space:]' < "$tmpdir/cs.f32c.final-two.od" > "$tmpdir/cs.f32c.final-two.norm"
csf32crc=$?
[ "$csf32crc" -eq 0 ] || err "F3.2c final-two-byte tr stage failed"
[ -s "$tmpdir/cs.f32c.final-two.norm" ] || err "F3.2c final-two-byte normalized stage produced empty output"
csf32cfinaltwo=$(cat "$tmpdir/cs.f32c.final-two.norm")
csf32crc=$?
[ "$csf32crc" -eq 0 ] || err "F3.2c final-two-byte normalized read failed"
case $csf32cfinaltwo in ''|*[!0-9]*) err "F3.2c final-two-byte normalized output is non-numeric" ;; esac
[ "$csf32cfinaltwo" != 1010 ] || err "F3.2c packet must end in exactly one LF"

# Bind the immutable C33 host snapshot that introduced the historical
# pipelines. These are snapshot-content locators, not active logic
# endorsed by current-stage.
$GIT show "$C33:tools/verify-host-boundary.sh" > "$tmpdir/cs.f32c.host.c33" 2>/dev/null
csf32crc=$?
[ "$csf32crc" -eq 0 ] || err "cannot read frozen F3.2c host snapshot from C33"
[ -s "$tmpdir/cs.f32c.host.c33" ] || err "frozen F3.2c C33 host snapshot is empty"
$GIT hash-object -- "$tmpdir/cs.f32c.host.c33" > "$tmpdir/cs.f32c.host.c33.blob"
csf32crc=$?
[ "$csf32crc" -eq 0 ] || err "frozen F3.2c C33 host snapshot blob scan failed"
printf '%s\n' 649961ef0dc31c59ea6447534e6e04de0dc9284f > "$tmpdir/cs.f32c.host.c33.blob.exp" \
  || err "frozen F3.2c C33 host snapshot blob fixture generation failed"
cmp -s "$tmpdir/cs.f32c.host.c33.blob.exp" "$tmpdir/cs.f32c.host.c33.blob"
csf32crc=$?
[ "$csf32crc" -eq 0 ] || err "frozen F3.2c C33 host snapshot blob differs"
csf32chistone=$(grep -cFx '[ "$(tail -c 1 "$PKT32C" | od -An -tuC | tr -d '\''[:space:]'\'')" = 10 ] || err "$PKT32C must end in LF"' "$tmpdir/cs.f32c.host.c33")
csf32crc=$?
[ "$csf32crc" -eq 0 ] || err "frozen F3.2c C33 host final-one pipeline locator scan failed"
[ "$csf32chistone" = 1 ] || err "frozen F3.2c C33 host final-one pipeline locator differs"
csf32chisttwo=$(grep -cFx '[ "$(tail -c 2 "$PKT32C" | od -An -tuC | tr -d '\''[:space:]'\'')" != 1010 ] || err "$PKT32C must end in exactly one LF"' "$tmpdir/cs.f32c.host.c33")
csf32crc=$?
[ "$csf32crc" -eq 0 ] || err "frozen F3.2c C33 host final-two pipeline locator scan failed"
[ "$csf32chisttwo" = 1 ] || err "frozen F3.2c C33 host final-two pipeline locator differs"
iconv -f UTF-8 -t UTF-8 "$F32CPKT" > "$tmpdir/cs.f32c.utf8" 2> "$tmpdir/cs.f32c.iconv.err"
csf32crc=$?
[ "$csf32crc" -eq 0 ] || err "F3.2c strict UTF-8 validation failed"
[ -s "$tmpdir/cs.f32c.utf8" ] || err "F3.2c UTF-8 stage produced empty output"
cmp -s "$F32CPKT" "$tmpdir/cs.f32c.utf8" || err "F3.2c UTF-8 round trip changed bytes"
for protected in docs/f3/F3.2B-PSBT-DECISION-PACKET.md docs/f3/F3.2B-PSBT-OWNER-RESPONSE-RECORD.md docs/f3/PSBT-V0-REVIEW-PROFILE-DRAFT.md; do
  $GIT show "$C31:$protected" > "$tmpdir/cs.f32c.protected" 2>/dev/null || err "cannot read protected C31 blob $protected"
  cmp -s "$tmpdir/cs.f32c.protected" "$protected" || err "protected file differs from C31: $protected"
done

# ---------------------- F3.2d Q-001 owner-clarification stage bindings
# Supporting evidence only. These repository-resident checks do not
# authenticate themselves, prove an audit, or prove publication.
F32DREC=docs/f3/F3.2D-D11-Q001-OWNER-CLARIFICATION-RECORD.md
[ -f "$F32DREC" ] || err "$F32DREC missing"
# Exact historical four-path union from the published C34 base through
# the frozen F3.2d C37 head.
cat > "$tmpdir/cs.f32d.paths.exp" <<'QK_F32D_PATHS_EOF' || err "F3.2d path fixture generation failed"
docs/DECISION-LOG.md
docs/f3/F3.2D-D11-Q001-OWNER-CLARIFICATION-RECORD.md
tools/verify-current-stage.sh
tools/verify-host-boundary.sh
QK_F32D_PATHS_EOF
$GIT diff --name-only "$C34" "$C37" > "$tmpdir/cs.f32d.paths.raw" \
  || err "F3.2d C34..C37 path enumeration failed"
[ -s "$tmpdir/cs.f32d.paths.raw" ] || err "F3.2d C34..C37 path enumeration is empty"
LC_ALL=C sort "$tmpdir/cs.f32d.paths.raw" > "$tmpdir/cs.f32d.paths.act" \
  || err "F3.2d C34..HEAD path sort failed"
cmp -s "$tmpdir/cs.f32d.paths.exp" "$tmpdir/cs.f32d.paths.act" \
  || err "F3.2d C34..C37 path union is not the exact authorized four-path set"
# At the frozen F3.2d C37 head, Decision Log is exactly A; record and
# host verifier are exactly B.
$GIT show "$C35:docs/DECISION-LOG.md" > "$tmpdir/cs.f32d.dlog.a" 2>/dev/null \
  || err "cannot read F3.2d Decision Log from C35"
$GIT show "$C37:docs/DECISION-LOG.md" > "$tmpdir/cs.f32d.dlog.c37" 2>/dev/null \
  || err "cannot read frozen F3.2d Decision Log from C37"
cmp -s "$tmpdir/cs.f32d.dlog.a" "$tmpdir/cs.f32d.dlog.c37" \
  || err "frozen F3.2d C37 Decision Log is not byte-identical to commit A"
# Direct append-only proof: the e4 Decision Log must be the exact byte
# prefix of C35, and the remaining bytes must be the exact authorized
# F3.2d suffix. The owner block is then independently cross-bound to the
# record transcript below. Supporting evidence only, never authentication.
$GIT show "$C34:docs/DECISION-LOG.md" > "$tmpdir/cs.f32d.dlog.e4" 2>/dev/null \
  || err "cannot read F3.2d Decision Log from C34/e4"
[ -s "$tmpdir/cs.f32d.dlog.e4" ] || err "F3.2d C34/e4 Decision Log is empty"
wc -c < "$tmpdir/cs.f32d.dlog.e4" > "$tmpdir/cs.f32d.dlog.e4.bytes.raw" \
  || err "F3.2d C34/e4 Decision Log byte count failed"
tr -d '[:space:]' < "$tmpdir/cs.f32d.dlog.e4.bytes.raw" > "$tmpdir/cs.f32d.dlog.e4.bytes" \
  || err "F3.2d C34/e4 Decision Log byte-count normalization failed"
[ -s "$tmpdir/cs.f32d.dlog.e4.bytes" ] || err "F3.2d C34/e4 Decision Log byte count is empty"
csq1dlogbasebytes=$(sed -n '1p' "$tmpdir/cs.f32d.dlog.e4.bytes"); csq1rc=$?
[ "$csq1rc" -eq 0 ] || err "F3.2d C34/e4 Decision Log byte-count read failed"
case $csq1dlogbasebytes in ''|*[!0-9]*) err "F3.2d C34/e4 Decision Log byte count is non-numeric" ;; esac
dd if="$tmpdir/cs.f32d.dlog.a" bs=1 count="$csq1dlogbasebytes" \
  > "$tmpdir/cs.f32d.dlog.a.prefix" 2> "$tmpdir/cs.f32d.dlog.a.prefix.dd.err"
csq1rc=$?
[ "$csq1rc" -eq 0 ] || err "F3.2d C35 Decision Log prefix dd read failed"
[ -s "$tmpdir/cs.f32d.dlog.a.prefix" ] || err "F3.2d C35 Decision Log prefix is empty"
cmp -s "$tmpdir/cs.f32d.dlog.e4" "$tmpdir/cs.f32d.dlog.a.prefix" \
  || err "F3.2d C34/e4 Decision Log is not the exact byte prefix of C35"
csq1dlogsuffixstart=$((csq1dlogbasebytes + 1))
tail -c "+$csq1dlogsuffixstart" "$tmpdir/cs.f32d.dlog.a" > "$tmpdir/cs.f32d.dlog.a.suffix" \
  || err "F3.2d C35 Decision Log suffix extraction failed"
[ -s "$tmpdir/cs.f32d.dlog.a.suffix" ] || err "F3.2d C35 Decision Log authorization suffix is empty"
cat > "$tmpdir/cs.f32d.dlog.suffix.exp" <<'QK_CS_F32D_DLOG_SUFFIX_EOF' || err "F3.2d Decision Log suffix fixture generation failed"

### QK-AUTH-F3.2D-D11-Q001-CLR-001 — F3.2d D-11 Q-001 owner-clarification record preparation authorization

- **ID:** QK-AUTH-F3.2D-D11-Q001-CLR-001
- **Date:** 2026-08-19
- **Approver:** Project owner
- **Owner words exactly (literal two-paragraph block follows):**

Approve the recommended F32C-D11-Q-001 clarification: “Failure releases no artifact or partial output” does not claim that already observed QR frames or SD residue can be withdrawn or proven absent. Before route output begins, failure releases nothing; after output begins, a later failure stops further output, permits no complete-artifact, delivery, receipt, finalization, broadcast, atomicity, or durability claim, and permits no automatic fallback, retry, or re-signing.

Authorize preparation and independent audit of a non-enacting docs-only F3.2d Q-001 owner-clarification record from e4cdf7771e189fc0f729358334aafd35177048c6, with only the mechanically necessary verifier bindings. No D-11 selection; no answer to Q-002 through Q-012; no profile acceptance, D-09 or QK-LIM selection, implementation, testing, media I/O, hardware work, settings changes, or publication.

- **Published parent:** `e4cdf7771e189fc0f729358334aafd35177048c6`.
- **Source packet:** `docs/f3/F3.2C-D11-MEDIA-WRITE-LIFECYCLE-CONSTRUCTION-PACKET.md` at the published parent.
- **Exact commit/path map:** Commit A changes only `docs/DECISION-LOG.md`; Commit B adds only `docs/f3/F3.2D-D11-Q001-OWNER-CLARIFICATION-RECORD.md` and changes only `tools/verify-host-boundary.sh`; Commit C changes only `tools/verify-current-stage.sh`.
- **Least-authority scope:** only local preparation and verification of the non-enacting docs-only F3.2d Q-001 owner-clarification record, the mechanically necessary verifier bindings, and independent read-only audit are authorized.
- **Explicit exclusions:** no D-11 selection, closure, construction, state, route, route-set, filesystem, filename, attachment, retry, orphan, QR-preflight, or signature-order selection; no response to F32C-D11-Q-002 through F32C-D11-Q-012; no profile or clause acceptance; no D-09 field, serialization, hash, or domain selection; no QK-LIM selection; no OD, QK-TST, evidence, gate, STOP-SHIP, implementation, dependency, vector, fixture, specimen, test, media-I/O, license, hardware, firmware, setting, credential, remote, tag, release, publication, or other-branch change.
- **Effect:** this authorization records preparation authority for one non-enacting clarification record only; it does not close Q-001 or D-11, select any construction or policy, enact any profile or clause, alter any protected status, authenticate or audit its own output, or authorize publication.
- **Later publication:** publication requires a separate explicit owner instruction naming the exact independently audited 40-hex commit.
QK_CS_F32D_DLOG_SUFFIX_EOF
cmp -s "$tmpdir/cs.f32d.dlog.suffix.exp" "$tmpdir/cs.f32d.dlog.a.suffix" \
  || err "F3.2d C35 Decision Log appended authorization suffix differs"
sed -n '/^- \*\*Owner words exactly (literal two-paragraph block follows):\*\*$/,/^- \*\*Published parent:\*\*/p' \
  "$tmpdir/cs.f32d.dlog.a.suffix" > "$tmpdir/cs.f32d.dlog.owner.framed" \
  || err "F3.2d Decision Log owner block extraction failed"
[ -s "$tmpdir/cs.f32d.dlog.owner.framed" ] || err "F3.2d Decision Log owner block extraction is empty"
csq1dlogownerlines=$(awk 'END {print NR+0}' "$tmpdir/cs.f32d.dlog.owner.framed"); csq1rc=$?
[ "$csq1rc" -eq 0 ] || err "F3.2d Decision Log owner block line count failed"
[ "$csq1dlogownerlines" = 7 ] || err "F3.2d Decision Log owner block framing is not exactly seven lines"
sed '1d;$d' "$tmpdir/cs.f32d.dlog.owner.framed" > "$tmpdir/cs.f32d.dlog.owner" \
  || err "F3.2d Decision Log owner block deframing failed"
sed -n '/^## Owner words exactly$/,/^## Q-001 disposition$/p' "$F32DREC" > "$tmpdir/cs.f32d.record.owner.framed" \
  || err "F3.2d record owner block cross-binding extraction failed"
[ -s "$tmpdir/cs.f32d.record.owner.framed" ] || err "F3.2d record owner block cross-binding extraction is empty"
csq1recordownerlines=$(awk 'END {print NR+0}' "$tmpdir/cs.f32d.record.owner.framed"); csq1rc=$?
[ "$csq1rc" -eq 0 ] || err "F3.2d record owner block line count failed"
[ "$csq1recordownerlines" = 7 ] || err "F3.2d record owner block framing is not exactly seven lines"
sed '1d;$d' "$tmpdir/cs.f32d.record.owner.framed" > "$tmpdir/cs.f32d.record.owner" \
  || err "F3.2d record owner block deframing failed"
cmp -s "$tmpdir/cs.f32d.dlog.owner" "$tmpdir/cs.f32d.record.owner" \
  || err "F3.2d Decision Log owner block differs from the record transcript"
$GIT show "$C36:$F32DREC" > "$tmpdir/cs.f32d.record.b" 2>/dev/null \
  || err "cannot read F3.2d record from C36"
cmp -s "$tmpdir/cs.f32d.record.b" "$F32DREC" \
  || err "active F3.2d record is not byte-identical to commit B"
$GIT show "$C36:tools/verify-host-boundary.sh" > "$tmpdir/cs.f32d.host.b" 2>/dev/null \
  || err "cannot read F3.2d host verifier from C36"
$GIT show "$C37:tools/verify-host-boundary.sh" > "$tmpdir/cs.f32d.host.c37" 2>/dev/null \
  || err "cannot read frozen F3.2d host verifier from C37"
cmp -s "$tmpdir/cs.f32d.host.b" "$tmpdir/cs.f32d.host.c37" \
  || err "frozen F3.2d C37 host verifier is not byte-identical to commit B"
csq1blob=a996a6d7c2bfa3a15109085475868410fe354422
$GIT ls-tree "$C36" -- "$F32DREC" > "$tmpdir/cs.f32d.record.tree" \
  || err "F3.2d C36 record tree lookup failed"
[ -s "$tmpdir/cs.f32d.record.tree" ] || err "F3.2d C36 record tree entry missing"
csq1treelines=$(awk 'END {print NR+0}' "$tmpdir/cs.f32d.record.tree"); csq1rc=$?
[ "$csq1rc" -eq 0 ] || err "F3.2d C36 record tree line-count failed"
[ "$csq1treelines" = 1 ] || err "F3.2d C36 record tree entry is not unique"
csq1tree=$(awk '{print $3}' "$tmpdir/cs.f32d.record.tree"); csq1rc=$?
[ "$csq1rc" -eq 0 ] || err "F3.2d C36 record tree-blob extraction failed"
[ -n "$csq1tree" ] || err "F3.2d C36 record tree-blob extraction is empty"
[ "$csq1tree" = "$csq1blob" ] || err "F3.2d C36 record tree blob differs from the approved whole-record blob"
csq1act=$($GIT hash-object -- "$F32DREC"); csq1rc=$?
[ "$csq1rc" -eq 0 ] || err "F3.2d active record hash-object failed"
[ "$csq1act" = "$csq1blob" ] || err "F3.2d active record differs from the approved whole-record blob"
# The F3.2c source packet is the same approved blob at e4/C34, B/C36,
# and active HEAD. Each lookup and extraction is independently checked.
for csq1srccommit in "$C34" "$C36"; do
  $GIT ls-tree "$csq1srccommit" -- "$F32CPKT" > "$tmpdir/cs.f32d.source.tree" \
    || err "F3.2d source packet tree lookup failed at $csq1srccommit"
  [ -s "$tmpdir/cs.f32d.source.tree" ] || err "F3.2d source packet tree entry missing at $csq1srccommit"
  csq1srclines=$(awk 'END {print NR+0}' "$tmpdir/cs.f32d.source.tree") \
    || err "F3.2d source packet tree count failed at $csq1srccommit"
  [ "$csq1srclines" = 1 ] || err "F3.2d source packet tree entry is not unique at $csq1srccommit"
  csq1srcblob=$(awk 'NR == 1 {print $3}' "$tmpdir/cs.f32d.source.tree") \
    || err "F3.2d source packet blob extraction failed at $csq1srccommit"
  [ "$csq1srcblob" = b4594210975940df71b0e941841320d11defaa4c ] \
    || err "F3.2d source packet blob changed at $csq1srccommit"
done
csq1srcact=$($GIT hash-object -- "$F32CPKT"); csq1rc=$?
[ "$csq1rc" -eq 0 ] || err "F3.2d active source packet hash-object failed"
[ "$csq1srcact" = b4594210975940df71b0e941841320d11defaa4c ] \
  || err "F3.2d active source packet differs from the approved e4 blob"
# Independent exact title, sole STATUS, and terminal-line checks.
csq1title='# F3.2d D-11 Q-001 Owner-Clarification Record (Non-Enacting)'
csq1status='STATUS: OWNER CLARIFICATION RECORDED — NON-ENACTING — F32C-D11-Q-001 FAILURE/COMPLETION MEANING CLARIFIED — D-11 NOT SELECTED — D-11 EVIDENCE/CONSTRUCTION-BLOCKED — F32C-D11-Q-002 THROUGH F32C-D11-Q-012 UNANSWERED — PSBT PROFILE NOT ACCEPTED — D-09 AND EVERY QK-LIM OPEN — NO IMPLEMENTATION — NO TESTING OR MEDIA I/O — NO QK-TST/EVIDENCE/GATE CHANGE — NO LICENSE APPLICATION — NO HARDWARE, FIRMWARE, SETTINGS, OR CREDENTIAL CHANGE — LOCAL AND UNPUBLISHED.'
csq1end='END OF RECORD — F32C-D11-Q-001 OWNER CLARIFICATION RECORDED — NON-ENACTING — D-11 NOT SELECTED — Q-002 THROUGH Q-012 UNANSWERED — TARGET EVIDENCE ABSENT — D-09 AND EVERY QK-LIM OPEN — PSBT PROFILE NOT ACCEPTED — LOCAL AND UNPUBLISHED.'
sed -n '1p' "$F32DREC" > "$tmpdir/cs.f32d.title.act"; csq1rc=$?
[ "$csq1rc" -eq 0 ] || err "F3.2d record title read failed"
[ -s "$tmpdir/cs.f32d.title.act" ] || err "F3.2d record title read is empty"
printf '%s\n' "$csq1title" > "$tmpdir/cs.f32d.title.exp" \
  || err "F3.2d record title fixture generation failed"
cmp -s "$tmpdir/cs.f32d.title.exp" "$tmpdir/cs.f32d.title.act" \
  || err "F3.2d record exact title is not first"
tail -n 1 "$F32DREC" > "$tmpdir/cs.f32d.end.act"; csq1rc=$?
[ "$csq1rc" -eq 0 ] || err "F3.2d record terminal-line read failed"
[ -s "$tmpdir/cs.f32d.end.act" ] || err "F3.2d record terminal-line read is empty"
printf '%s\n' "$csq1end" > "$tmpdir/cs.f32d.end.exp" \
  || err "F3.2d record terminal-line fixture generation failed"
cmp -s "$tmpdir/cs.f32d.end.exp" "$tmpdir/cs.f32d.end.act" \
  || err "F3.2d record exact terminal line missing"
csq1statuslines=$(grep -c '^STATUS:' "$F32DREC"); csq1rc=$?
[ "$csq1rc" -eq 0 ] || err "F3.2d record canonical STATUS scan failed"
[ "$csq1statuslines" = 1 ] || err "F3.2d record must contain exactly one canonical STATUS line"
grep '^STATUS:' "$F32DREC" > "$tmpdir/cs.f32d.status.act" \
  || err "F3.2d record STATUS extraction failed"
printf '%s\n' "$csq1status" > "$tmpdir/cs.f32d.status.exp" \
  || err "F3.2d record STATUS fixture generation failed"
cmp -s "$tmpdir/cs.f32d.status.exp" "$tmpdir/cs.f32d.status.act" \
  || err "F3.2d record STATUS is not the exact complete banner"
csq1statusany=$(awk '{s=toupper($0); while (match(s,/STATUS:/)) {c++; s=substr(s,RSTART+RLENGTH)}} END {print c+0}' "$F32DREC"); csq1rc=$?
[ "$csq1rc" -eq 0 ] || err "F3.2d record case-insensitive STATUS count failed"
case $csq1statusany in ''|*[!0-9]*) err "F3.2d STATUS count is non-numeric" ;; esac
[ "$csq1statusany" = 1 ] || err "F3.2d record must contain exactly one STATUS: occurrence in any letter case"
# Independent exact literal owner quote, including its internal blank
# line and the section boundaries.
sed -n '/^## Owner words exactly$/,/^## Q-001 disposition$/p' "$F32DREC" > "$tmpdir/cs.f32d.owner.act" \
  || err "F3.2d owner transcript extraction failed"
cat > "$tmpdir/cs.f32d.owner.exp" <<'QK_CS_F32D_OWNER_EOF' || err "F3.2d owner transcript fixture generation failed"
## Owner words exactly

Approve the recommended F32C-D11-Q-001 clarification: “Failure releases no artifact or partial output” does not claim that already observed QR frames or SD residue can be withdrawn or proven absent. Before route output begins, failure releases nothing; after output begins, a later failure stops further output, permits no complete-artifact, delivery, receipt, finalization, broadcast, atomicity, or durability claim, and permits no automatic fallback, retry, or re-signing.

Authorize preparation and independent audit of a non-enacting docs-only F3.2d Q-001 owner-clarification record from e4cdf7771e189fc0f729358334aafd35177048c6, with only the mechanically necessary verifier bindings. No D-11 selection; no answer to Q-002 through Q-012; no profile acceptance, D-09 or QK-LIM selection, implementation, testing, media I/O, hardware work, settings changes, or publication.

## Q-001 disposition
QK_CS_F32D_OWNER_EOF
cmp -s "$tmpdir/cs.f32d.owner.exp" "$tmpdir/cs.f32d.owner.act" \
  || err "F3.2d literal owner transcript or required blank line differs"
# Independent exact ordered Q-002..Q-012 closed transcript.
grep '^- F32C-D11-Q-0' "$F32DREC" > "$tmpdir/cs.f32d.questions.act"
csq1rc=$?
[ "$csq1rc" -eq 0 ] || err "F3.2d question transcript extraction failed"
cat > "$tmpdir/cs.f32d.questions.exp" <<'QK_CS_F32D_QUESTIONS_EOF' || err "F3.2d question fixture generation failed"
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
QK_CS_F32D_QUESTIONS_EOF
cmp -s "$tmpdir/cs.f32d.questions.exp" "$tmpdir/cs.f32d.questions.act" \
  || err "F3.2d Q-002 through Q-012 transcript is answered, malformed, duplicated, or reordered"
# Exact provenance, Q-001 meaning, historical boundary, and non-effects.
cat > "$tmpdir/cs.f32d.semantic.exp" <<'QK_CS_F32D_SEMANTIC_EOF' || err "F3.2d semantic fixture generation failed"
- Source base: `e4cdf7771e189fc0f729358334aafd35177048c6`.
- Source packet Git blob: `b4594210975940df71b0e941841320d11defaa4c`.
- The source base and packet blob are audit locators and supporting byte-identity references only. They are not authentication, audit proof, or trust anchors.
F32C-D11-Q-001 DISPOSITION: OWNER CLARIFICATION RECORDED — NON-ENACTING — D-11 NOT SELECTED.
- “Failure releases no artifact or partial output” does not claim that already observed QR frames or SD residue can be withdrawn or proven absent.
- Before route output begins, failure releases nothing.
- After route output begins, a later failure stops further output.
- A later failure permits no complete-artifact, delivery, receipt, finalization, broadcast, atomicity, or durability claim.
- A later failure permits no automatic fallback, retry, or re-signing.
This clarification defines no route-output-begins boundary and selects no D-11 construction, state, route, or route set.
F32C-D11-F-006, F32C-D11-F-009, F32C-D11-F-014, and F32C-D11-F-022 remain PROPOSED — UNSELECTED — TARGET EVIDENCE REQUIRED.
S9 does not prove receipt, finalization, broadcast, or durability.
- The source F3.2c packet remains byte-identical.
- Its LOCAL AND UNPUBLISHED banner records its historical status at preparation. The byte-identical packet was later published as part of the source base named above.
- Its Q-001-unanswered wording records its historical status at the source base. This later record supplies the current owner clarification without editing or superseding the source packet.
The Q-001 “no retry” clarification does not answer Q-005 future-new-attempt policy. The Q-001 “no automatic fallback” clarification does not answer Q-003 or Q-004 route cardinality or outcomes.
- D-11 remains EVIDENCE/CONSTRUCTION-BLOCKED and NOT SELECTED.
- No D-11 construction, state, route, route set, filesystem, filename, attachment, retry, orphan, QR-preflight, or signature-order policy is selected.
- D-09 remains open. No D-09 field, serialization, hash, or domain is selected.
- Every QK-LIM remains open. No QK-LIM value is selected.
- The PSBT profile remains not accepted. No profile or clause is accepted.
- No OD, QK-TST, evidence, gate, or STOP-SHIP status changes.
- OD-05 and OD-06 remain OPEN.
- Tests remain PLANNED — NOT RUN. No test or media I/O was run for this record.
- Gates A–E remain OPEN. STOP-SHIP remains unchanged.
- No code, dependency, vector, fixture, specimen, test, media, hardware, firmware, setting, credential, license, release, remote, publication, or other-branch change is authorized or enacted.
- This record makes no audit, authentication, publication, target-validation, atomicity, or durability claim.
QK_CS_F32D_SEMANTIC_EOF
csq1semexp=$(awk 'END {print NR+0}' "$tmpdir/cs.f32d.semantic.exp") \
  || err "F3.2d semantic fixture count failed"
[ "$csq1semexp" = 27 ] || err "F3.2d semantic fixture is incomplete (found $csq1semexp of 27)"
csq1semproc=0
while IFS= read -r csq1line; do
  csq1n=$(grep -cFx -e "$csq1line" "$F32DREC"); csq1rc=$?
  [ "$csq1rc" -le 1 ] || err "F3.2d semantic line scan failed"
  [ "$csq1n" = 1 ] || err "F3.2d semantic line must occur exactly once: $csq1line"
  csq1semproc=$((csq1semproc + 1))
done < "$tmpdir/cs.f32d.semantic.exp"
[ "$csq1semproc" = 27 ] || err "F3.2d semantic loop processed $csq1semproc of 27 lines"
for csq1claim in 'D-11 IS SELECTED' 'D-11 HAS BEEN SELECTED' \
  'D-11 IS CLOSED' 'Q-001 IS CLOSED' 'PROFILE IS ACCEPTED' \
  'TESTS WERE RUN' 'PUBLICATION IS AUTHORIZED' 'RECORD IS AUDITED' \
  'RECORD IS AUTHENTICATED' 'RECORD IS PUBLISHED'; do
  csq1n=$(LC_ALL=C grep -ciF -e "$csq1claim" "$F32DREC"); csq1rc=$?
  [ "$csq1rc" -le 1 ] || err "F3.2d contradictory-claim scan failed"
  [ "$csq1n" = 0 ] || err "F3.2d record contains a contradictory claim: $csq1claim"
done
# Statically bind the active host verifier's operational F3.2d
# mechanisms. Anchored non-comment source lines prevent comment-only
# satisfaction; the strict host verifier is executed later in section g.
for csq1mechanism in \
  '^q1blob=a996a6d7c2bfa3a15109085475868410fe354422$' \
  '^q1blobact=\$[(]git --no-optional-locks hash-object -- "\$CLR32D"[)]; q1rc=\$\?$' \
  '^\[ "\$q1blobact" = "\$q1blob" \] \|\| err "\$CLR32D differs from the reviewed whole-record blob"$' \
  '^q1statusany=\$[(]awk ' \
  '^cmp -s "\$tmpdir/q1.owner.exp" "\$tmpdir/q1.owner.act"; q1rc=\$\?$' \
  '^cmp -s "\$tmpdir/q1.questions.exp" "\$tmpdir/q1.questions.act"; q1rc=\$\?$' \
  '^cmp -s "\$tmpdir/q1.heads.exp" "\$tmpdir/q1.heads.act"; q1rc=\$\?$' \
  '^cmp -s "\$tmpdir/q1.hex.exp" "\$tmpdir/q1.hex.act"; q1rc=\$\?$'; do
  csq1mn=$(grep -cE -e "$csq1mechanism" tools/verify-host-boundary.sh); csq1rc=$?
  [ "$csq1rc" -eq 0 ] || err "host verifier F3.2d mechanism scan failed: $csq1mechanism"
  [ "$csq1mn" = 1 ] || err "host verifier must contain one operational F3.2d mechanism line: $csq1mechanism"
done
csq1anchor=$(grep -cF 'git --no-optional-locks show 2c6d1152f09730661b2cadd86d2374c755191128:docs/DECISION-LOG.md > "$tmpdir/dlog.a"' "$tmpdir/cs.f32d.host.b"); csq1rc=$?
[ "$csq1rc" -eq 0 ] || err "historical host verifier F3.2d Decision-Log anchor scan failed"
[ "$csq1anchor" = 1 ] || err "historical F3.2d host verifier must contain exactly one operational Decision-Log anchor"
csq1path=$(grep -cFx 'docs/f3/F3.2D-D11-Q001-OWNER-CLARIFICATION-RECORD.md' tools/verify-host-boundary.sh); csq1rc=$?
[ "$csq1rc" -eq 0 ] || err "host verifier F3.2d file-set line scan failed"
[ "$csq1path" = 1 ] || err "host verifier exact file set must contain the F3.2d record exactly once"
csq1scan=$(grep -cFx 'for cf in "$DRAFT" "$WTS" "$RSP32" "$PKT32C" "$CLR32D" docs/f3/README.md docs/SOURCE-REGISTER.md tools/verify-host-boundary.sh; do' "$tmpdir/cs.f32d.host.b"); csq1rc=$?
[ "$csq1rc" -eq 0 ] || err "historical host verifier F3.2d material-scan binding failed"
[ "$csq1scan" = 2 ] || err "historical F3.2d host verifier must include the record in both exact material/token scan loops"

# ---------------- F3.2e PSBT-output TEST-ARCHITECTURE alignment stage
# Supporting evidence only. These repository-resident checks do not
# authenticate themselves, prove an audit, select a correction, amend a
# canonical row, or authorize publication.
F32EPKT=docs/f3/F3.2E-PSBT-OUTPUT-TEST-ALIGNMENT-PACKET.md
[ -f "$F32EPKT" ] || err "$F32EPKT missing"

# Exact four-path union above the published C37 source base. Together
# with the exact A/B/C path and mode checks, every other tracked blob is
# protected from this local chain.
cat > "$tmpdir/cs.f32e.paths.exp" <<'QK_CS_F32E_PATHS_EOF' || err "F3.2e path fixture generation failed"
docs/DECISION-LOG.md
docs/f3/F3.2E-PSBT-OUTPUT-TEST-ALIGNMENT-PACKET.md
tools/verify-current-stage.sh
tools/verify-host-boundary.sh
QK_CS_F32E_PATHS_EOF
$GIT diff --name-only "$C37" "$C40" > "$tmpdir/cs.f32e.paths.raw"
csf32erc=$?
[ "$csf32erc" -eq 0 ] || err "F3.2e C37..C40 path enumeration failed"
[ -s "$tmpdir/cs.f32e.paths.raw" ] || err "F3.2e C37..C40 path enumeration is empty"
LC_ALL=C sort "$tmpdir/cs.f32e.paths.raw" > "$tmpdir/cs.f32e.paths.act"
csf32erc=$?
[ "$csf32erc" -eq 0 ] || err "F3.2e C37..C40 path sort failed"
cmp -s "$tmpdir/cs.f32e.paths.exp" "$tmpdir/cs.f32e.paths.act"
csf32erc=$?
[ "$csf32erc" -eq 0 ] || err "F3.2e C37..C40 path union is not the exact authorized four-path set"

# Decision Log A is the historical C40-stage binding and an exact append
# to the published C37 source base.
$GIT show "$C38:docs/DECISION-LOG.md" > "$tmpdir/cs.f32e.dlog.a" 2>/dev/null
csf32erc=$?
[ "$csf32erc" -eq 0 ] || err "cannot read F3.2e Decision Log from C38/A"
[ -s "$tmpdir/cs.f32e.dlog.a" ] || err "F3.2e C38/A Decision Log is empty"
$GIT show "$C40:docs/DECISION-LOG.md" > "$tmpdir/cs.f32e.dlog.stage" 2>/dev/null
csf32erc=$?
[ "$csf32erc" -eq 0 ] || err "cannot read F3.2e Decision Log from C40 stage"
cmp -s "$tmpdir/cs.f32e.dlog.a" "$tmpdir/cs.f32e.dlog.stage"
csf32erc=$?
[ "$csf32erc" -eq 0 ] || err "F3.2e C40 Decision Log is not byte-identical to F3.2e commit A"
$GIT show "$C37:docs/DECISION-LOG.md" > "$tmpdir/cs.f32e.dlog.base" 2>/dev/null
csf32erc=$?
[ "$csf32erc" -eq 0 ] || err "cannot read F3.2e Decision Log from C37 source base"
[ -s "$tmpdir/cs.f32e.dlog.base" ] || err "F3.2e C37 Decision Log is empty"
wc -c < "$tmpdir/cs.f32e.dlog.base" > "$tmpdir/cs.f32e.dlog.bytes.raw"
csf32erc=$?
[ "$csf32erc" -eq 0 ] || err "F3.2e C37 Decision Log byte count failed"
tr -d '[:space:]' < "$tmpdir/cs.f32e.dlog.bytes.raw" > "$tmpdir/cs.f32e.dlog.bytes"
csf32erc=$?
[ "$csf32erc" -eq 0 ] || err "F3.2e Decision Log byte-count normalization failed"
csf32ebasebytes=$(cat "$tmpdir/cs.f32e.dlog.bytes")
csf32erc=$?
[ "$csf32erc" -eq 0 ] || err "F3.2e Decision Log byte-count read failed"
case $csf32ebasebytes in ''|*[!0-9]*) err "F3.2e Decision Log byte count is non-numeric" ;; esac
dd if="$tmpdir/cs.f32e.dlog.a" bs=1 count="$csf32ebasebytes" \
  > "$tmpdir/cs.f32e.dlog.prefix" 2> "$tmpdir/cs.f32e.dlog.prefix.err"
csf32erc=$?
[ "$csf32erc" -eq 0 ] || err "F3.2e C38/A Decision Log prefix dd read failed"
[ -s "$tmpdir/cs.f32e.dlog.prefix" ] || err "F3.2e C38/A Decision Log prefix is empty"
cmp -s "$tmpdir/cs.f32e.dlog.base" "$tmpdir/cs.f32e.dlog.prefix"
csf32erc=$?
[ "$csf32erc" -eq 0 ] || err "F3.2e C37 Decision Log is not the exact byte prefix of C38/A"
csf32esuffixstart=$((csf32ebasebytes + 1))
tail -c "+$csf32esuffixstart" "$tmpdir/cs.f32e.dlog.a" > "$tmpdir/cs.f32e.dlog.suffix"
csf32erc=$?
[ "$csf32erc" -eq 0 ] || err "F3.2e C38/A Decision Log suffix extraction failed"
[ -s "$tmpdir/cs.f32e.dlog.suffix" ] || err "F3.2e C38/A Decision Log suffix is empty"
cat > "$tmpdir/cs.f32e.dlog.suffix.exp" <<'QK_CS_F32E_DLOG_SUFFIX_EOF' || err "F3.2e Decision Log suffix fixture generation failed"

### QK-AUTH-F3.2E-PSBT-TST-ALIGN-PKT-001 — F3.2e PSBT-output TEST-ARCHITECTURE alignment-packet preparation authorization

- **ID:** QK-AUTH-F3.2E-PSBT-TST-ALIGN-PKT-001
- **Date:** 2026-08-20
- **Approver:** Project owner
- **Owner words exactly:**

Authorize preparation and independent audit of a non-binding docs-only F3.2e PSBT-output TEST-ARCHITECTURE alignment packet from be4d019e349e15ca575ac64b64f900957283e5e0, with only the mechanically necessary verifier bindings. Limit scope to QK-TST-DIFF-002 and QK-TST-DIFF-004, with QK-TST-REH-004 retained unchanged as the external-finalization control. No canonical TEST-ARCHITECTURE edit, test-status change, Q-002 through Q-012 answer, D-11 or D-09 selection, profile acceptance, implementation, testing, vectors, media I/O, hardware work, settings changes, or publication.

- **Published parent:** `be4d019e349e15ca575ac64b64f900957283e5e0`.
- **Scope:** local preparation and independent read-only audit of one non-binding docs-only F3.2e alignment packet limited to proposed, unselected plan/oracle correction text for `QK-TST-DIFF-002` and `QK-TST-DIFF-004`, with `QK-TST-REH-004` reproduced byte-for-byte as the unchanged external-finalization control, plus only the mechanically necessary verifier bindings and one clean complete sole-main audit bundle in `/tmp`.
- **Exact commit/path map:** Commit A changes only `docs/DECISION-LOG.md`; Commit B adds only `docs/f3/F3.2E-PSBT-OUTPUT-TEST-ALIGNMENT-PACKET.md` and changes only `tools/verify-host-boundary.sh`; Commit C changes only `tools/verify-current-stage.sh`. The chain is exactly three linear one-parent commits with no merge and cumulative changes to only those four paths.
- **Explicit exclusions:** no canonical `docs/TEST-ARCHITECTURE.md`, `docs/REQUIREMENTS.md`, `docs/TRACEABILITY.md`, `docs/RESOURCE-BUDGETS.md`, prior F3.2b/c/d record or packet, PSBT profile, `docs/OPEN-DECISIONS.md`, `ARCHITECTURE.md`, `docs/MATURITY-GATES.md`, `docs/SOURCE-REGISTER.md`, `docs/f3/README.md`, `README.md`, `.replit`, code, manifest, dependency, license, hardware, firmware, remote, branch, tag, release, setting, credential, or publication change; no Q-002 through Q-012 answer; no D-09 or D-11 selection; no QK-LIM value or link change; no profile or clause acceptance; no implementation, testing, vector, fixture, specimen, corpus, payload, media I/O, evidence, gate, or STOP-SHIP change.
- **Non-effects:** the packet is alignment input only and selects or enacts no correction. `QK-TST-DIFF-002` and `QK-TST-DIFF-004` remain `PLANNED — NOT RUN`; `QK-TST-REH-004` remains unchanged; every QK-TST status remains unchanged; D-09, D-11, Q-002 through Q-012, every QK-LIM, profile acceptance, tests, evidence, gates, and STOP-SHIP remain open or unchanged exactly as before. Verifier results and independent review are supporting evidence only, never authentication, audit proof, correction selection, canonical amendment, or publication authority.
- **Later publication:** publication requires a separate explicit owner instruction naming the exact independently audited 40-hex commit; this authorization alone does not authorize publication.
QK_CS_F32E_DLOG_SUFFIX_EOF
cmp -s "$tmpdir/cs.f32e.dlog.suffix.exp" "$tmpdir/cs.f32e.dlog.suffix"
csf32erc=$?
[ "$csf32erc" -eq 0 ] || err "F3.2e C38/A Decision Log appended authorization suffix differs"

# Cross-bind the exact one-paragraph owner words between Decision Log A
# and the packet, including their surrounding blank lines.
sed -n '/^- \*\*Owner words exactly:\*\*$/,/^- \*\*Published parent:\*\*/p' \
  "$tmpdir/cs.f32e.dlog.suffix" > "$tmpdir/cs.f32e.dlog.owner.framed"
csf32erc=$?
[ "$csf32erc" -eq 0 ] || err "F3.2e Decision Log owner block extraction failed"
sed '1d;$d' "$tmpdir/cs.f32e.dlog.owner.framed" > "$tmpdir/cs.f32e.dlog.owner"
csf32erc=$?
[ "$csf32erc" -eq 0 ] || err "F3.2e Decision Log owner block deframing failed"
sed -n '/^## Owner words exactly$/,/^## Canonical source rows (reproduced byte-for-byte from source base)$/p' \
  "$F32EPKT" > "$tmpdir/cs.f32e.packet.owner.framed"
csf32erc=$?
[ "$csf32erc" -eq 0 ] || err "F3.2e packet owner block extraction failed"
sed '1d;$d' "$tmpdir/cs.f32e.packet.owner.framed" > "$tmpdir/cs.f32e.packet.owner"
csf32erc=$?
[ "$csf32erc" -eq 0 ] || err "F3.2e packet owner block deframing failed"
cmp -s "$tmpdir/cs.f32e.dlog.owner" "$tmpdir/cs.f32e.packet.owner"
csf32erc=$?
[ "$csf32erc" -eq 0 ] || err "F3.2e Decision Log and packet owner transcripts differ"

# Commit B packet remains active; its historical host bytes remain exact
# through the F3.2e C stage and are rebound only by the later F3.2f B.
$GIT show "$C39:$F32EPKT" > "$tmpdir/cs.f32e.packet.b" 2>/dev/null
csf32erc=$?
[ "$csf32erc" -eq 0 ] || err "cannot read F3.2e packet from C39/B"
cmp -s "$tmpdir/cs.f32e.packet.b" "$F32EPKT"
csf32erc=$?
[ "$csf32erc" -eq 0 ] || err "active F3.2e packet is not byte-identical to C39/B"
$GIT show "$C39:tools/verify-host-boundary.sh" > "$tmpdir/cs.f32e.host.b" 2>/dev/null
csf32erc=$?
[ "$csf32erc" -eq 0 ] || err "cannot read F3.2e host verifier from C39/B"
$GIT show "$C40:tools/verify-host-boundary.sh" > "$tmpdir/cs.f32e.host.stage" 2>/dev/null
csf32erc=$?
[ "$csf32erc" -eq 0 ] || err "cannot read F3.2e host verifier from C40 stage"
cmp -s "$tmpdir/cs.f32e.host.b" "$tmpdir/cs.f32e.host.stage"
csf32erc=$?
[ "$csf32erc" -eq 0 ] || err "F3.2e C40 host verifier is not byte-identical to F3.2e C39/B"

# Exact historical C39/B tree modes/blobs for the C39/C40 preservation
# check.
for csf32etreepair in \
  "100644 4ffa20afbedeb0b6cfbbe57298f941bc0537683e $F32EPKT" \
  '100755 b1cd5dfe71377913ee283fac17352f41fcc48654 tools/verify-host-boundary.sh'; do
  csf32etreemode=${csf32etreepair%% *}
  csf32etreerest=${csf32etreepair#* }
  csf32etreeblob=${csf32etreerest%% *}
  csf32etreepath=${csf32etreerest#* }
  $GIT ls-tree "$C39" -- "$csf32etreepath" > "$tmpdir/cs.f32e.tree.raw"
  csf32erc=$?
  [ "$csf32erc" -eq 0 ] || err "F3.2e C39/B tree lookup failed for $csf32etreepath"
  [ -s "$tmpdir/cs.f32e.tree.raw" ] || err "F3.2e C39/B tree entry missing for $csf32etreepath"
  csf32etreelines=$(awk 'END {print NR+0}' "$tmpdir/cs.f32e.tree.raw")
  csf32erc=$?
  [ "$csf32erc" -eq 0 ] || err "F3.2e C39/B tree line count failed for $csf32etreepath"
  [ "$csf32etreelines" = 1 ] || err "F3.2e C39/B tree entry is not unique for $csf32etreepath"
  csf32etreeactmode=$(awk 'NR == 1 {print $1}' "$tmpdir/cs.f32e.tree.raw")
  csf32erc=$?
  [ "$csf32erc" -eq 0 ] || err "F3.2e C39/B tree mode extraction failed for $csf32etreepath"
  csf32etreeactblob=$(awk 'NR == 1 {print $3}' "$tmpdir/cs.f32e.tree.raw")
  csf32erc=$?
  [ "$csf32erc" -eq 0 ] || err "F3.2e C39/B tree blob extraction failed for $csf32etreepath"
  [ "$csf32etreeactmode" = "$csf32etreemode" ] || err "F3.2e C39/B tree mode differs for $csf32etreepath"
  [ "$csf32etreeactblob" = "$csf32etreeblob" ] || err "F3.2e C39/B tree blob differs for $csf32etreepath"
done

# Source and protected documents retained the exact reviewed blobs through
# the published F3.2f C stage. F3.2g intentionally amends TEST-ARCHITECTURE.
while IFS=' ' read -r csf32eprotected csf32eprotectedblob; do
  $GIT show "$C43:$csf32eprotected" > "$tmpdir/cs.f32e.protected.stage" 2>/dev/null
  csf32erc=$?
  [ "$csf32erc" -eq 0 ] || err "cannot read F3.2e protected stage bytes for $csf32eprotected"
  [ -s "$tmpdir/cs.f32e.protected.stage" ] || err "F3.2e protected stage bytes are empty for $csf32eprotected"
  $GIT hash-object -- "$tmpdir/cs.f32e.protected.stage" > "$tmpdir/cs.f32e.protected.act"
  csf32erc=$?
  [ "$csf32erc" -eq 0 ] || err "F3.2e protected blob scan failed for $csf32eprotected"
  printf '%s\n' "$csf32eprotectedblob" > "$tmpdir/cs.f32e.protected.exp" \
    || err "F3.2e protected blob fixture generation failed for $csf32eprotected"
  cmp -s "$tmpdir/cs.f32e.protected.exp" "$tmpdir/cs.f32e.protected.act"
  csf32erc=$?
  [ "$csf32erc" -eq 0 ] || err "F3.2e protected blob differs for $csf32eprotected"
done <<'QK_CS_F32E_PROTECTED_EOF'
docs/TEST-ARCHITECTURE.md f4e127a92fc68243274b7d384e335fa4632e5dd2
docs/REQUIREMENTS.md 981b1b497102187da66fb4e82ef0725b32c088f7
docs/f3/F3.2C-D11-MEDIA-WRITE-LIFECYCLE-CONSTRUCTION-PACKET.md b4594210975940df71b0e941841320d11defaa4c
docs/f3/F3.2D-D11-Q001-OWNER-CLARIFICATION-RECORD.md a996a6d7c2bfa3a15109085475868410fe354422
docs/f3/F3.2B-PSBT-OWNER-RESPONSE-RECORD.md 838a732ab556b51ca8b0b61bed9ae9d512d47a87
docs/f3/PSBT-V0-REVIEW-PROFILE-DRAFT.md 877866e5a3636bdfb7015d715e048ccfad63d939
QK_CS_F32E_PROTECTED_EOF

# Exact packet title, sole STATUS, terminal line, and all five canonical
# or proposed QK-TST row transcripts.
csf32etitle='# QK-F3.2e — PSBT-Output TEST-ARCHITECTURE Alignment Packet (Non-Binding)'
csf32estatus='STATUS: OWNER-AUTHORIZED ALIGNMENT INPUT ONLY — NON-BINDING — PROPOSED CORRECTION TEXT UNSELECTED — QK-TST-DIFF-002 AND QK-TST-DIFF-004 ARE CORRECTION TARGETS ONLY — QK-TST-REH-004 RETAINED UNCHANGED AS EXTERNAL-FINALIZATION CONTROL — CANONICAL TEST-ARCHITECTURE UNCHANGED — ALL QK-TST STATUSES UNCHANGED — PLANNED — NOT RUN — D-11 NOT SELECTED — F32C-D11-Q-002 THROUGH F32C-D11-Q-012 UNANSWERED — D-09 AND EVERY QK-LIM OPEN — PSBT PROFILE NOT ACCEPTED — NO IMPLEMENTATION, TESTING, VECTORS, OR MEDIA I/O — NO EVIDENCE OR GATE CHANGE — LOCAL AND UNPUBLISHED.'
csf32eend='END OF PACKET — F3.2e PSBT-OUTPUT TEST-ARCHITECTURE ALIGNMENT INPUT ONLY — PROPOSED CORRECTION TEXT UNSELECTED — CANONICAL TEST-ARCHITECTURE AND ALL QK-TST STATUSES UNCHANGED — LOCAL AND UNPUBLISHED.'
sed -n '1p' "$F32EPKT" > "$tmpdir/cs.f32e.title.act"
csf32erc=$?
[ "$csf32erc" -eq 0 ] || err "F3.2e packet title read failed"
printf '%s\n' "$csf32etitle" > "$tmpdir/cs.f32e.title.exp" \
  || err "F3.2e packet title fixture generation failed"
cmp -s "$tmpdir/cs.f32e.title.exp" "$tmpdir/cs.f32e.title.act"
csf32erc=$?
[ "$csf32erc" -eq 0 ] || err "F3.2e exact title is not first"
grep -c '^STATUS:' "$F32EPKT" > "$tmpdir/cs.f32e.status.count"
csf32erc=$?
[ "$csf32erc" -le 1 ] || err "F3.2e packet STATUS count failed"
csf32estatuscount=$(cat "$tmpdir/cs.f32e.status.count")
csf32erc=$?
[ "$csf32erc" -eq 0 ] || err "F3.2e packet STATUS count read failed"
[ "$csf32estatuscount" = 1 ] || err "F3.2e packet must contain exactly one STATUS line"
grep '^STATUS:' "$F32EPKT" > "$tmpdir/cs.f32e.status.act"
csf32erc=$?
[ "$csf32erc" -eq 0 ] || err "F3.2e packet STATUS extraction failed"
printf '%s\n' "$csf32estatus" > "$tmpdir/cs.f32e.status.exp" \
  || err "F3.2e packet STATUS fixture generation failed"
cmp -s "$tmpdir/cs.f32e.status.exp" "$tmpdir/cs.f32e.status.act"
csf32erc=$?
[ "$csf32erc" -eq 0 ] || err "F3.2e packet STATUS differs"
tail -n 1 "$F32EPKT" > "$tmpdir/cs.f32e.end.act"
csf32erc=$?
[ "$csf32erc" -eq 0 ] || err "F3.2e packet terminal-line read failed"
printf '%s\n' "$csf32eend" > "$tmpdir/cs.f32e.end.exp" \
  || err "F3.2e packet terminal-line fixture generation failed"
cmp -s "$tmpdir/cs.f32e.end.exp" "$tmpdir/cs.f32e.end.act"
csf32erc=$?
[ "$csf32erc" -eq 0 ] || err "F3.2e exact terminal line is missing"
grep '^| QK-TST-' "$F32EPKT" > "$tmpdir/cs.f32e.rows.act"
csf32erc=$?
[ "$csf32erc" -eq 0 ] || err "F3.2e QK-TST row transcript extraction failed"
cat > "$tmpdir/cs.f32e.rows.exp" <<'QK_CS_F32E_ROWS_EOF' || err "F3.2e row transcript fixture generation failed"
| QK-TST-DIFF-002 | DIFF | PSBT parsing, validation, signing, and finalized output vs. independent implementations; signature verification and independent parseability. Oracle: verdict/byte agreement on shared corpora. | QK-REQ-PSBT-004, QK-REQ-PSBT-006; QK-THR-006, QK-THR-017 | F9 | Gate C | Cross-implementation agreement record with corpus hashes | PLANNED — NOT RUN |
| QK-TST-DIFF-004 | DIFF | Export-route interop: the signed PSBT and raw final transaction exported via QR and via SD are byte-identical to each other and parse/verify identically in independent implementations. Oracle: cross-route byte comparison plus independent-parser agreement. | QK-REQ-TRN-007; QK-THR-006; QK-LIM-PSBT-026, QK-LIM-PSBT-027 | F10 | Gate C | Cross-implementation agreement record with corpus hashes | PLANNED — NOT RUN |
| QK-TST-REH-004 | REH | Rescue with commodity reader and open rescue tool; independent transaction finalization outside QuietKey tooling; acceptance by Bitcoin Core. Dependency: rescue evidence is definable only after OD-02 resolves the card interface. Oracle: Bitcoin Core acceptance of the rescued transaction. | QK-REQ-CARD-006, QK-REQ-PSBT-004, QK-REQ-REC-006, QK-REQ-TRN-007; QK-THR-001, QK-THR-006, QK-THR-020 | F12 | Gate B, Gate C, Gate E | Rehearsal transcript + artifact hashes | PLANNED — NOT RUN |
| QK-TST-DIFF-002 | DIFF | PSBT v0 parsing and then-selected-profile validation against an independent implementation over shared positive and adversarial corpora; for each QuietKey-produced candidate output, independently fully consume and parse the exact serialized bytes, prove that the output is one unfinalized signed PSBT, verify every produced signature, and prove the exact record-level delta: every accepted pre-existing non-signature key/value record remains byte-identical in its original map and original relative order; every input contains exactly the two new authorized selected-pair PSBT_IN_PARTIAL_SIG records; no pre-existing partial-signature record and no missing, foreign, third, duplicate, replaced, or mutated selected-pair partial-signature record is present; and no finalization record is present. No finalization, extraction, raw transaction, or broadcast occurs. Oracle: all then-selected-profile verdicts agree and every independent output-parse, signature, and exact-delta assertion passes; any disagreement or failed assertion fails the row. Whole-output byte agreement between separately signing implementations is not required. | QK-REQ-PSBT-004, QK-REQ-PSBT-006; QK-THR-006, QK-THR-017 | F9 | Gate C | Cross-implementation agreement record with corpus hashes | PLANNED — NOT RUN |
| QK-TST-DIFF-004 | DIFF | Export-route interoperability for one already frozen, fully serialized, freshly independently reparsed unfinalized signed-PSBT artifact. Without re-signing, route-specific cases provide that same byte sequence to uncompressed BBQr file type P output and to a newly created binary .psbt SD output under the then-selected D-11 lifecycle. Independent route receivers/readers recover the payloads; decoded QR payload bytes and completed SD output-file bytes must each equal the frozen artifact byte-for-byte and therefore equal each other, and an independent PSBT implementation must fully consume and parse both recovered byte sequences as the same unfinalized signed PSBT. The cases make no route approval, session, cardinality, completion, finalization, extraction, raw-transaction, broadcast, delivery, receipt, atomicity, or durability claim. Oracle: exact three-way byte equality plus independent full-consumption parse agreement; any wrapper, sidecar, trailing byte, route mismatch, finalization field, raw transaction, or parse disagreement fails the row. | QK-REQ-TRN-007; QK-THR-006; QK-LIM-PSBT-026, QK-LIM-PSBT-027 | F10 | Gate C | Cross-implementation agreement record with corpus hashes | PLANNED — NOT RUN |
QK_CS_F32E_ROWS_EOF
cmp -s "$tmpdir/cs.f32e.rows.exp" "$tmpdir/cs.f32e.rows.act"
csf32erc=$?
[ "$csf32erc" -eq 0 ] || err "F3.2e canonical/proposed row transcript differs"

# Exact unchanged-control statement and complete dependencies/non-effects
# section preserve the non-binding boundary.
csf32econtrol='QK-TST-REH-004 is the UNCHANGED CONTROL — NO CANDIDATE EDIT. Its finalization is independent and outside QuietKey tooling; this is not QuietKey behavior or current evidence. The row is consistent with D-10 because finalization occurs externally after rescue, not inside QuietKey. This row is not a correction target; its plan/oracle text is not proposed for change.'
grep -cFx -e "$csf32econtrol" "$F32EPKT" > "$tmpdir/cs.f32e.control.count"
csf32erc=$?
[ "$csf32erc" -le 1 ] || err "F3.2e unchanged-control statement scan failed"
csf32econtrolcount=$(cat "$tmpdir/cs.f32e.control.count")
csf32erc=$?
[ "$csf32erc" -eq 0 ] || err "F3.2e unchanged-control count read failed"
[ "$csf32econtrolcount" = 1 ] || err "F3.2e unchanged-control statement is missing, altered, or duplicated"
sed -n '/^## Dependencies and non-effects$/,/^END OF PACKET/p' "$F32EPKT" > "$tmpdir/cs.f32e.effects.act"
csf32erc=$?
[ "$csf32erc" -eq 0 ] || err "F3.2e dependencies/non-effects extraction failed"
cat > "$tmpdir/cs.f32e.effects.exp" <<'QK_CS_F32E_EFFECTS_EOF' || err "F3.2e dependencies/non-effects fixture generation failed"
## Dependencies and non-effects

- QK-TST-DIFF-002 cannot run before: profile selection, relevant policies, a genuinely independent pinned/provenance/license-reviewed implementation, and separately authorized corpora.
- QK-TST-DIFF-004 cannot run before: D-11 selection, OD-05 and OD-06 resolution, route mechanics, applicable QK-LIM values, and independent receiver and parser identities.
- QK-TST-REH-004 cannot run before OD-02 resolves the card interface.
- D-09, D-11, F32C-D11-Q-002 through F32C-D11-Q-012, every QK-LIM, profile acceptance, tests, evidence, gates A through E, and STOP-SHIP all remain open or unchanged.
- No canonical `docs/TEST-ARCHITECTURE.md`, `docs/REQUIREMENTS.md`, `docs/TRACEABILITY.md`, `docs/RESOURCE-BUDGETS.md`, prior F3.2b/c/d record or packet, PSBT profile, `docs/OPEN-DECISIONS.md`, `ARCHITECTURE.md`, `docs/MATURITY-GATES.md`, `docs/SOURCE-REGISTER.md`, `docs/f3/README.md`, `README.md`, `.replit`, code, manifest, dependency, license, hardware, firmware, remote, branch, tag, release, setting, credential, or publication change is authorized or enacted by this packet.
- No QK-LIM value, link, or row change is made. QK-LIM-PSBT-026 and QK-LIM-PSBT-027 remain OPEN — VALUE NOT AUTHORIZED IN F1.
- Candidate text requires later owner approval; canonical correction requires a still-later separate authorization.
- This packet is local and unpublished. Publication requires a separate explicit owner instruction naming the exact independently audited 40-hex commit.

END OF PACKET — F3.2e PSBT-OUTPUT TEST-ARCHITECTURE ALIGNMENT INPUT ONLY — PROPOSED CORRECTION TEXT UNSELECTED — CANONICAL TEST-ARCHITECTURE AND ALL QK-TST STATUSES UNCHANGED — LOCAL AND UNPUBLISHED.
QK_CS_F32E_EFFECTS_EOF
cmp -s "$tmpdir/cs.f32e.effects.exp" "$tmpdir/cs.f32e.effects.act"
csf32erc=$?
[ "$csf32erc" -eq 0 ] || err "F3.2e dependencies/non-effects transcript differs"

# Bind the historical F3.2e host's operational anchor, file-set entry,
# packet blob pin, and scan-loop expansion. The active strict host is
# independently bound below for F3.2f and executed later.
csf32eanchor=$(grep -cF 'git --no-optional-locks show e57faff4ead69ddf108cf522cb6c3cbfbef8219a:docs/DECISION-LOG.md > "$tmpdir/dlog.a"' "$tmpdir/cs.f32e.host.b")
csf32erc=$?
[ "$csf32erc" -eq 0 ] || err "historical F3.2e C39/B host Decision-Log anchor scan failed"
[ "$csf32eanchor" = 1 ] || err "historical F3.2e C39/B host must contain exactly one Decision-Log anchor"
csf32epath=$(grep -cFx 'docs/f3/F3.2E-PSBT-OUTPUT-TEST-ALIGNMENT-PACKET.md' "$tmpdir/cs.f32e.host.b")
csf32erc=$?
[ "$csf32erc" -eq 0 ] || err "historical F3.2e C39/B host file-set scan failed"
[ "$csf32epath" = 1 ] || err "historical F3.2e C39/B host exact file set must contain the packet exactly once"
csf32eblobpin=$(grep -cFx 'p32eblob=4ffa20afbedeb0b6cfbbe57298f941bc0537683e' "$tmpdir/cs.f32e.host.b")
csf32erc=$?
[ "$csf32erc" -eq 0 ] || err "historical F3.2e C39/B host packet-blob pin scan failed"
[ "$csf32eblobpin" = 1 ] || err "historical F3.2e C39/B host must contain exactly one packet-blob pin"
csf32escan=$(grep -cFx 'for cf in "$DRAFT" "$WTS" "$RSP32" "$PKT32C" "$CLR32D" "$PKT32E" docs/f3/README.md docs/SOURCE-REGISTER.md tools/verify-host-boundary.sh; do' "$tmpdir/cs.f32e.host.b")
csf32erc=$?
[ "$csf32erc" -eq 0 ] || err "historical F3.2e C39/B host material-scan binding failed"
[ "$csf32escan" = 2 ] || err "historical F3.2e C39/B host must include the packet in both exact material/token scan loops"

# ----------------------------- F3.2f owner-direction stage exact bindings
F32FREC=docs/f3/F3.2F-PSBT-OUTPUT-TEST-OWNER-DIRECTION-RECORD.md
[ -f "$F32FREC" ] || err "$F32FREC missing"
cat > "$tmpdir/cs.f32f.paths.exp" <<'QK_CS_F32F_PATHS_EOF' || err "F3.2f path fixture generation failed"
docs/DECISION-LOG.md
docs/f3/F3.2F-PSBT-OUTPUT-TEST-OWNER-DIRECTION-RECORD.md
tools/verify-current-stage.sh
tools/verify-host-boundary.sh
QK_CS_F32F_PATHS_EOF
$GIT diff --name-only "$C40" "$C43" > "$tmpdir/cs.f32f.paths.raw"
csf32frc=$?
[ "$csf32frc" -eq 0 ] || err "F3.2f C40..C43 path enumeration failed"
[ -s "$tmpdir/cs.f32f.paths.raw" ] || err "F3.2f C40..C43 path enumeration is empty"
LC_ALL=C sort "$tmpdir/cs.f32f.paths.raw" > "$tmpdir/cs.f32f.paths.act"
csf32frc=$?
[ "$csf32frc" -eq 0 ] || err "F3.2f C40..C43 path sort failed"
cmp -s "$tmpdir/cs.f32f.paths.exp" "$tmpdir/cs.f32f.paths.act"
csf32frc=$?
[ "$csf32frc" -eq 0 ] || err "F3.2f C40..C43 path union is not the exact authorized four-path set"

# A is an append-only Decision Log update and remained exact through C43.
$GIT show "$C40:docs/DECISION-LOG.md" > "$tmpdir/cs.f32f.dlog.base" 2>/dev/null
csf32frc=$?
[ "$csf32frc" -eq 0 ] || err "cannot read F3.2f base Decision Log"
$GIT show "$C41:docs/DECISION-LOG.md" > "$tmpdir/cs.f32f.dlog.a" 2>/dev/null
csf32frc=$?
[ "$csf32frc" -eq 0 ] || err "cannot read F3.2f A Decision Log"
$GIT show "$C43:docs/DECISION-LOG.md" > "$tmpdir/cs.f32f.dlog.stage" 2>/dev/null
csf32frc=$?
[ "$csf32frc" -eq 0 ] || err "cannot read F3.2f C43 Decision Log"
cmp -s "$tmpdir/cs.f32f.dlog.a" "$tmpdir/cs.f32f.dlog.stage"
csf32frc=$?
[ "$csf32frc" -eq 0 ] || err "F3.2f C43 Decision Log is not byte-identical to F3.2f A"
wc -c < "$tmpdir/cs.f32f.dlog.base" > "$tmpdir/cs.f32f.dlog.bytes.raw"
csf32frc=$?
[ "$csf32frc" -eq 0 ] || err "F3.2f base Decision Log byte count failed"
tr -d '[:space:]' < "$tmpdir/cs.f32f.dlog.bytes.raw" > "$tmpdir/cs.f32f.dlog.bytes"
csf32frc=$?
[ "$csf32frc" -eq 0 ] || err "F3.2f Decision Log byte-count normalization failed"
csf32fbasebytes=$(cat "$tmpdir/cs.f32f.dlog.bytes")
csf32frc=$?
[ "$csf32frc" -eq 0 ] || err "F3.2f Decision Log byte-count read failed"
case $csf32fbasebytes in ''|*[!0-9]*) err "F3.2f Decision Log byte count is non-numeric" ;; esac
dd if="$tmpdir/cs.f32f.dlog.a" bs=1 count="$csf32fbasebytes" \
  > "$tmpdir/cs.f32f.dlog.prefix" 2> "$tmpdir/cs.f32f.dlog.prefix.err"
csf32frc=$?
[ "$csf32frc" -eq 0 ] || err "F3.2f Decision Log prefix read failed"
cmp -s "$tmpdir/cs.f32f.dlog.base" "$tmpdir/cs.f32f.dlog.prefix"
csf32frc=$?
[ "$csf32frc" -eq 0 ] || err "F3.2f base Decision Log is not the exact prefix of A"

# Exact A/B modes and blobs, plus the preserved C43 stage bytes.
for csf32ftreepair in \
  '100644 ffc140296400b9d3d4e892085cf8ca598674e113 docs/DECISION-LOG.md' \
  '100644 a066fc9710371f414d158a3deb9c345f2b00821b docs/f3/F3.2F-PSBT-OUTPUT-TEST-OWNER-DIRECTION-RECORD.md' \
  '100755 a8e71a5879c8dbb1773ace2b7bf8565554bb16f4 tools/verify-host-boundary.sh'; do
  csf32fmode=${csf32ftreepair%% *}
  csf32frest=${csf32ftreepair#* }
  csf32fblob=${csf32frest%% *}
  csf32fpath=${csf32frest#* }
  case $csf32fpath in docs/DECISION-LOG.md) csf32fcommit=$C41 ;; *) csf32fcommit=$C42 ;; esac
  $GIT ls-tree "$csf32fcommit" -- "$csf32fpath" > "$tmpdir/cs.f32f.tree.raw"
  csf32frc=$?
  [ "$csf32frc" -eq 0 ] || err "F3.2f tree lookup failed for $csf32fpath"
  [ -s "$tmpdir/cs.f32f.tree.raw" ] || err "F3.2f tree entry missing for $csf32fpath"
  csf32factmode=$(awk 'NR == 1 {print $1}' "$tmpdir/cs.f32f.tree.raw")
  csf32frc=$?
  [ "$csf32frc" -eq 0 ] || err "F3.2f tree mode extraction failed for $csf32fpath"
  csf32factblob=$(awk 'NR == 1 {print $3}' "$tmpdir/cs.f32f.tree.raw")
  csf32frc=$?
  [ "$csf32frc" -eq 0 ] || err "F3.2f tree blob extraction failed for $csf32fpath"
  [ "$csf32factmode" = "$csf32fmode" ] || err "F3.2f mode differs for $csf32fpath"
  [ "$csf32factblob" = "$csf32fblob" ] || err "F3.2f blob differs for $csf32fpath"
  $GIT show "$C43:$csf32fpath" > "$tmpdir/cs.f32f.stage.file" 2>/dev/null
  csf32frc=$?
  [ "$csf32frc" -eq 0 ] || err "cannot read F3.2f C43 stage bytes for $csf32fpath"
  $GIT hash-object -- "$tmpdir/cs.f32f.stage.file" > "$tmpdir/cs.f32f.stage.blob"
  csf32frc=$?
  [ "$csf32frc" -eq 0 ] || err "F3.2f C43 stage blob scan failed for $csf32fpath"
  printf '%s\n' "$csf32fblob" > "$tmpdir/cs.f32f.stage.exp" || err "F3.2f C43 stage blob fixture failed"
  cmp -s "$tmpdir/cs.f32f.stage.exp" "$tmpdir/cs.f32f.stage.blob"
  csf32frc=$?
  [ "$csf32frc" -eq 0 ] || err "F3.2f C43 stage blob differs for $csf32fpath"
done
for csf32frecordfixture in \
  '## Source rows containing approved Plan / oracle directions' \
  '- `docs/TEST-ARCHITECTURE.md` remains unchanged. Both rows containing the approved Plan / oracle direction cells and the unchanged control remain `PLANNED — NOT RUN`.'; do
  csf32ffixturecount=$(grep -cFx -e "$csf32frecordfixture" "$F32FREC")
  csf32frc=$?
  [ "$csf32frc" -le 1 ] || err "F3.2f changed heading/semantic fixture scan failed"
  [ "$csf32ffixturecount" = 1 ] || err "F3.2f changed heading/semantic fixture is missing, altered, or duplicated"
done
for csf32fprotectedpair in \
  'docs/TEST-ARCHITECTURE.md f4e127a92fc68243274b7d384e335fa4632e5dd2' \
  'docs/f3/F3.2E-PSBT-OUTPUT-TEST-ALIGNMENT-PACKET.md 4ffa20afbedeb0b6cfbbe57298f941bc0537683e'; do
  csf32fprotected=${csf32fprotectedpair%% *}
  csf32fprotectedblob=${csf32fprotectedpair#* }
  $GIT show "$C43:$csf32fprotected" > "$tmpdir/cs.f32f.protected.stage" 2>/dev/null
  csf32frc=$?
  [ "$csf32frc" -eq 0 ] || err "cannot read F3.2f C43 protected bytes for $csf32fprotected"
  $GIT hash-object -- "$tmpdir/cs.f32f.protected.stage" > "$tmpdir/cs.f32f.protected.act"
  csf32frc=$?
  [ "$csf32frc" -eq 0 ] || err "F3.2f C43 protected blob scan failed for $csf32fprotected"
  printf '%s\n' "$csf32fprotectedblob" > "$tmpdir/cs.f32f.protected.exp" || err "F3.2f protected blob fixture failed"
  cmp -s "$tmpdir/cs.f32f.protected.exp" "$tmpdir/cs.f32f.protected.act"
  csf32frc=$?
  [ "$csf32frc" -eq 0 ] || err "F3.2f protected blob differs for $csf32fprotected"
done
for csf32fowner in \
  'Approve, as non-enacting owner directions, the complete proposed Plan / oracle text for QK-TST-DIFF-002 and QK-TST-DIFF-004 exactly as printed in the F3.2e packet at published commit 574e790193d45d3f392c64951d319bb5fde11d20. Approve no change to any other cell. QK-TST-REH-004 remains unchanged.' \
  'This approval does not amend docs/TEST-ARCHITECTURE.md, change any QK-TST status, authorize testing or evidence, answer F32C-D11-Q-002 through Q-012, or select D-11, D-09, any QK-LIM, the PSBT profile, or any clause.' \
  'Authorize preparation and independent audit of a non-enacting docs-only F3.2f PSBT-output test owner-direction record from 574e790193d45d3f392c64951d319bb5fde11d20, recording only my approved directions for QK-TST-DIFF-002 and QK-TST-DIFF-004, with QK-TST-REH-004 retained unchanged and only the mechanically necessary verifier bindings.' \
  'No canonical TEST-ARCHITECTURE edit, test-status change, F32C-D11-Q-002 through Q-012 answer, D-11 or D-09 selection, QK-LIM selection, profile or clause acceptance, implementation, testing, vectors, evidence, media I/O, hardware work, settings changes, or publication.'; do
  for csf32fownerfile in docs/DECISION-LOG.md "$F32FREC"; do
    csf32fownercount=$(grep -cFx -e "$csf32fowner" "$csf32fownerfile")
    csf32frc=$?
    [ "$csf32frc" -le 1 ] || err "F3.2f owner transcript scan failed in $csf32fownerfile"
    [ "$csf32fownercount" = 1 ] || err "F3.2f owner transcript differs or duplicates in $csf32fownerfile"
  done
done
$GIT show "$C43:tools/verify-host-boundary.sh" > "$tmpdir/cs.f32f.host.c43" 2>/dev/null
csf32frc=$?
[ "$csf32frc" -eq 0 ] || err "cannot read historical F3.2f C43 host verifier"
csf32fanchor=$(grep -cF 'git --no-optional-locks show 22114c6741ac653b9c5079b1bfccdb795a88f3df:docs/DECISION-LOG.md > "$tmpdir/dlog.a"' "$tmpdir/cs.f32f.host.c43")
csf32frc=$?
[ "$csf32frc" -eq 0 ] || err "historical F3.2f C43 host Decision-Log anchor scan failed"
[ "$csf32fanchor" = 1 ] || err "historical F3.2f C43 host must contain exactly one F3.2f Decision-Log anchor"
csf32fblobpin=$(grep -cFx 'p32fblob=a066fc9710371f414d158a3deb9c345f2b00821b' "$tmpdir/cs.f32f.host.c43")
csf32frc=$?
[ "$csf32frc" -eq 0 ] || err "historical F3.2f C43 host record-blob pin scan failed"
[ "$csf32fblobpin" = 1 ] || err "historical F3.2f C43 host must contain exactly one F3.2f record-blob pin"

# ------------------- F3.2g canonical TEST-ARCHITECTURE amendment bindings
F32GTEST=docs/TEST-ARCHITECTURE.md
[ -f "$F32GTEST" ] || err "$F32GTEST missing"
cat > "$tmpdir/cs.f32g.paths.exp" <<'QK_CS_F32G_PATHS_EOF' || err "F3.2g path fixture generation failed"
docs/DECISION-LOG.md
docs/TEST-ARCHITECTURE.md
tools/verify-current-stage.sh
tools/verify-host-boundary.sh
QK_CS_F32G_PATHS_EOF
$GIT diff --name-only "$C43" "$F32G_C" > "$tmpdir/cs.f32g.paths.raw"
csf32grc=$?
[ "$csf32grc" -eq 0 ] || err "F3.2g C43..F32G_C path enumeration failed"
[ -s "$tmpdir/cs.f32g.paths.raw" ] || err "F3.2g C43..F32G_C path enumeration is empty"
LC_ALL=C sort "$tmpdir/cs.f32g.paths.raw" > "$tmpdir/cs.f32g.paths.act"
csf32grc=$?
[ "$csf32grc" -eq 0 ] || err "F3.2g C43..F32G_C path sort failed"
cmp -s "$tmpdir/cs.f32g.paths.exp" "$tmpdir/cs.f32g.paths.act"
csf32grc=$?
[ "$csf32grc" -eq 0 ] || err "F3.2g C43..F32G_C path union is not the exact authorized four-path set"

# A is an append-only Decision Log update preserved exactly at the
# published F3.2g C stage. The active log has a later authorized append.
$GIT show "$C43:docs/DECISION-LOG.md" > "$tmpdir/cs.f32g.dlog.base" 2>/dev/null
csf32grc=$?
[ "$csf32grc" -eq 0 ] || err "cannot read F3.2g base Decision Log"
$GIT show "$C44:docs/DECISION-LOG.md" > "$tmpdir/cs.f32g.dlog.a" 2>/dev/null
csf32grc=$?
[ "$csf32grc" -eq 0 ] || err "cannot read F3.2g A Decision Log"
$GIT show "$F32G_C:docs/DECISION-LOG.md" > "$tmpdir/cs.f32g.dlog.stage" 2>/dev/null
csf32grc=$?
[ "$csf32grc" -eq 0 ] || err "cannot read F3.2g C Decision Log"
cmp -s "$tmpdir/cs.f32g.dlog.a" "$tmpdir/cs.f32g.dlog.stage"
csf32grc=$?
[ "$csf32grc" -eq 0 ] || err "F3.2g C Decision Log is not byte-identical to F3.2g A"
wc -c < "$tmpdir/cs.f32g.dlog.base" > "$tmpdir/cs.f32g.dlog.bytes.raw"
csf32grc=$?
[ "$csf32grc" -eq 0 ] || err "F3.2g base Decision Log byte count failed"
tr -d '[:space:]' < "$tmpdir/cs.f32g.dlog.bytes.raw" > "$tmpdir/cs.f32g.dlog.bytes"
csf32grc=$?
[ "$csf32grc" -eq 0 ] || err "F3.2g Decision Log byte-count normalization failed"
csf32gbasebytes=$(cat "$tmpdir/cs.f32g.dlog.bytes")
csf32grc=$?
[ "$csf32grc" -eq 0 ] || err "F3.2g Decision Log byte-count read failed"
case $csf32gbasebytes in ''|*[!0-9]*) err "F3.2g Decision Log byte count is non-numeric" ;; esac
dd if="$tmpdir/cs.f32g.dlog.a" bs=1 count="$csf32gbasebytes" \
  > "$tmpdir/cs.f32g.dlog.prefix" 2> "$tmpdir/cs.f32g.dlog.prefix.err"
csf32grc=$?
[ "$csf32grc" -eq 0 ] || err "F3.2g Decision Log prefix read failed"
cmp -s "$tmpdir/cs.f32g.dlog.base" "$tmpdir/cs.f32g.dlog.prefix"
csf32grc=$?
[ "$csf32grc" -eq 0 ] || err "F3.2g base Decision Log is not the exact prefix of A"

# Exact A/B modes and blobs plus frozen-stage byte identity.
$GIT show "$F32G_C:tools/verify-host-boundary.sh" > "$tmpdir/cs.f32g.host.stage" 2>/dev/null
csf32grc=$?
[ "$csf32grc" -eq 0 ] || err "cannot read F3.2g C host verifier"
for csf32gtreepair in \
  '100644 48df71d4144b0b2469f711d5c21b2084f964b58f docs/DECISION-LOG.md' \
  '100644 065e20eed4e916c907a244aa3e5ca2e66cbc5d4e docs/TEST-ARCHITECTURE.md' \
  '100755 31947996491fb98a208c98d8f210813d68e70dba tools/verify-host-boundary.sh'; do
  csf32gmode=${csf32gtreepair%% *}
  csf32grest=${csf32gtreepair#* }
  csf32gblob=${csf32grest%% *}
  csf32gpath=${csf32grest#* }
  case $csf32gpath in docs/DECISION-LOG.md) csf32gcommit=$C44 ;; *) csf32gcommit=$C45 ;; esac
  $GIT ls-tree "$csf32gcommit" -- "$csf32gpath" > "$tmpdir/cs.f32g.tree.raw"
  csf32grc=$?
  [ "$csf32grc" -eq 0 ] || err "F3.2g tree lookup failed for $csf32gpath"
  [ -s "$tmpdir/cs.f32g.tree.raw" ] || err "F3.2g tree entry missing for $csf32gpath"
  csf32glines=$(awk 'END {print NR+0}' "$tmpdir/cs.f32g.tree.raw")
  csf32grc=$?
  [ "$csf32grc" -eq 0 ] || err "F3.2g tree line count failed for $csf32gpath"
  [ "$csf32glines" = 1 ] || err "F3.2g tree entry is not unique for $csf32gpath"
  csf32gactmode=$(awk 'NR == 1 {print $1}' "$tmpdir/cs.f32g.tree.raw")
  csf32grc=$?
  [ "$csf32grc" -eq 0 ] || err "F3.2g tree mode extraction failed for $csf32gpath"
  csf32gactblob=$(awk 'NR == 1 {print $3}' "$tmpdir/cs.f32g.tree.raw")
  csf32grc=$?
  [ "$csf32grc" -eq 0 ] || err "F3.2g tree blob extraction failed for $csf32gpath"
  [ "$csf32gactmode" = "$csf32gmode" ] || err "F3.2g mode differs for $csf32gpath"
  [ "$csf32gactblob" = "$csf32gblob" ] || err "F3.2g blob differs for $csf32gpath"
  case $csf32gpath in
    docs/DECISION-LOG.md) csf32gstagefile="$tmpdir/cs.f32g.dlog.stage" ;;
    docs/TEST-ARCHITECTURE.md) csf32gstagefile="$F32GTEST" ;;
    tools/verify-host-boundary.sh) csf32gstagefile="$tmpdir/cs.f32g.host.stage" ;;
  esac
  $GIT hash-object -- "$csf32gstagefile" > "$tmpdir/cs.f32g.stage.blob"
  csf32grc=$?
  [ "$csf32grc" -eq 0 ] || err "F3.2g frozen-stage blob scan failed for $csf32gpath"
  printf '%s\n' "$csf32gblob" > "$tmpdir/cs.f32g.stage.exp" || err "F3.2g frozen-stage blob fixture failed"
  cmp -s "$tmpdir/cs.f32g.stage.exp" "$tmpdir/cs.f32g.stage.blob"
  csf32grc=$?
  [ "$csf32grc" -eq 0 ] || err "F3.2g frozen-stage blob differs for $csf32gpath"
done

# Bind the immutable base/B documents and reconstruct the exact authorized
# old-row-to-approved-row transformation independently of the host verifier.
$GIT show "$C43:$F32GTEST" > "$tmpdir/cs.f32g.test.base" 2>/dev/null
csf32grc=$?
[ "$csf32grc" -eq 0 ] || err "cannot read F3.2g base TEST-ARCHITECTURE"
[ -s "$tmpdir/cs.f32g.test.base" ] || err "F3.2g base TEST-ARCHITECTURE is empty"
$GIT show "$C45:$F32GTEST" > "$tmpdir/cs.f32g.test.b" 2>/dev/null
csf32grc=$?
[ "$csf32grc" -eq 0 ] || err "cannot read F3.2g B TEST-ARCHITECTURE"
[ -s "$tmpdir/cs.f32g.test.b" ] || err "F3.2g B TEST-ARCHITECTURE is empty"
cmp -s "$tmpdir/cs.f32g.test.b" "$F32GTEST"
csf32grc=$?
[ "$csf32grc" -eq 0 ] || err "active TEST-ARCHITECTURE is not byte-identical to F3.2g B"
for csf32gblobpair in \
  "$tmpdir/cs.f32g.test.base f4e127a92fc68243274b7d384e335fa4632e5dd2" \
  "$tmpdir/cs.f32g.test.b 065e20eed4e916c907a244aa3e5ca2e66cbc5d4e"; do
  csf32gblobfile=${csf32gblobpair%% *}
  csf32gblobexp=${csf32gblobpair#* }
  $GIT hash-object -- "$csf32gblobfile" > "$tmpdir/cs.f32g.test.blob.act"
  csf32grc=$?
  [ "$csf32grc" -eq 0 ] || err "F3.2g TEST-ARCHITECTURE blob scan failed"
  printf '%s\n' "$csf32gblobexp" > "$tmpdir/cs.f32g.test.blob.exp" \
    || err "F3.2g TEST-ARCHITECTURE blob fixture failed"
  cmp -s "$tmpdir/cs.f32g.test.blob.exp" "$tmpdir/cs.f32g.test.blob.act"
  csf32grc=$?
  [ "$csf32grc" -eq 0 ] || err "F3.2g TEST-ARCHITECTURE blob differs"
done
for csf32gid in QK-TST-DIFF-002 QK-TST-DIFF-004; do
  awk -v id="$csf32gid" 'index($0, "| " id " |") == 1 {print}' \
    "$tmpdir/cs.f32g.test.base" > "$tmpdir/cs.f32g.old.$csf32gid"
  csf32grc=$?
  [ "$csf32grc" -eq 0 ] || err "F3.2g old-row extraction failed for $csf32gid"
  csf32goldn=$(awk 'END {print NR+0}' "$tmpdir/cs.f32g.old.$csf32gid")
  csf32grc=$?
  [ "$csf32grc" -eq 0 ] || err "F3.2g old-row count failed for $csf32gid"
  [ "$csf32goldn" = 1 ] || err "F3.2g base must contain exactly one $csf32gid row"
  awk -v id="$csf32gid" 'index($0, "| " id " |") == 1 {print}' \
    "$F32FREC" > "$tmpdir/cs.f32g.approved.$csf32gid"
  csf32grc=$?
  [ "$csf32grc" -eq 0 ] || err "F3.2g approved-row extraction failed for $csf32gid"
  csf32gapprovedn=$(awk 'END {print NR+0}' "$tmpdir/cs.f32g.approved.$csf32gid")
  csf32grc=$?
  [ "$csf32grc" -eq 0 ] || err "F3.2g approved-row count failed for $csf32gid"
  [ "$csf32gapprovedn" = 1 ] || err "F3.2f record must contain exactly one approved $csf32gid row"
  csf32gnew=$(cat "$tmpdir/cs.f32g.approved.$csf32gid")
  csf32grc=$?
  [ "$csf32grc" -eq 0 ] || err "F3.2g approved-row read failed for $csf32gid"
  [ -n "$csf32gnew" ] || err "F3.2g approved row is empty for $csf32gid"
  csf32gnewn=$(grep -Fxc -e "$csf32gnew" "$F32GTEST")
  csf32grc=$?
  [ "$csf32grc" -le 1 ] || err "F3.2g active approved-row scan failed for $csf32gid"
  [ "$csf32gnewn" = 1 ] || err "F3.2g active document must contain the approved $csf32gid row exactly once"
  awk -F '|' -v id="$csf32gid" '$2 == " " id " " {print $2 "|" $3 "|" $5 "|" $6 "|" $7 "|" $8 "|" $9}' \
    "$tmpdir/cs.f32g.old.$csf32gid" > "$tmpdir/cs.f32g.old.nonplan.$csf32gid"
  csf32grc=$?
  [ "$csf32grc" -eq 0 ] || err "F3.2g old non-Plan cell extraction failed for $csf32gid"
  awk -F '|' -v id="$csf32gid" '$2 == " " id " " {print $2 "|" $3 "|" $5 "|" $6 "|" $7 "|" $8 "|" $9}' \
    "$tmpdir/cs.f32g.approved.$csf32gid" > "$tmpdir/cs.f32g.new.nonplan.$csf32gid"
  csf32grc=$?
  [ "$csf32grc" -eq 0 ] || err "F3.2g new non-Plan cell extraction failed for $csf32gid"
  cmp -s "$tmpdir/cs.f32g.old.nonplan.$csf32gid" "$tmpdir/cs.f32g.new.nonplan.$csf32gid"
  csf32grc=$?
  [ "$csf32grc" -eq 0 ] || err "F3.2g changed a non-Plan cell for $csf32gid"
done
csf32gold002=$(cat "$tmpdir/cs.f32g.old.QK-TST-DIFF-002") || err "F3.2g old DIFF-002 row read failed"
csf32gnew002=$(cat "$tmpdir/cs.f32g.approved.QK-TST-DIFF-002") || err "F3.2g new DIFF-002 row read failed"
csf32gold004=$(cat "$tmpdir/cs.f32g.old.QK-TST-DIFF-004") || err "F3.2g old DIFF-004 row read failed"
csf32gnew004=$(cat "$tmpdir/cs.f32g.approved.QK-TST-DIFF-004") || err "F3.2g new DIFF-004 row read failed"
awk -v old002="$csf32gold002" -v new002="$csf32gnew002" \
    -v old004="$csf32gold004" -v new004="$csf32gnew004" '
  $0 == old002 { print new002; n002++; next }
  $0 == old004 { print new004; n004++; next }
  { print }
  END { if (n002 != 1 || n004 != 1) exit 42 }
' "$tmpdir/cs.f32g.test.base" > "$tmpdir/cs.f32g.test.expected"
csf32grc=$?
[ "$csf32grc" -eq 0 ] || err "F3.2g whole-document reconstruction failed"
cmp -s "$tmpdir/cs.f32g.test.expected" "$F32GTEST"
csf32grc=$?
[ "$csf32grc" -eq 0 ] || err "F3.2g active TEST-ARCHITECTURE is not the exact authorized transformation"

# REH-004, all statuses, and the two historical source records are protected.
for csf32grehsource in "$tmpdir/cs.f32g.test.base" "$F32GTEST"; do
  awk 'index($0, "| QK-TST-REH-004 |") == 1 {print}' "$csf32grehsource" \
    > "$tmpdir/cs.f32g.reh.$(basename "$csf32grehsource")"
  csf32grc=$?
  [ "$csf32grc" -eq 0 ] || err "F3.2g REH-004 extraction failed"
done
cmp -s "$tmpdir/cs.f32g.reh.cs.f32g.test.base" "$tmpdir/cs.f32g.reh.TEST-ARCHITECTURE.md"
csf32grc=$?
[ "$csf32grc" -eq 0 ] || err "QK-TST-REH-004 changed during F3.2g"
awk -F '|' '
  index($0, "| QK-TST-") == 1 {
    n++
    if ($9 != " PLANNED — NOT RUN ") bad=1
  }
  END { if (n == 0 || bad) exit 43 }
' "$F32GTEST"
csf32grc=$?
[ "$csf32grc" -eq 0 ] || err "not all QK-TST statuses are exactly PLANNED — NOT RUN"
for csf32gprotectedpair in \
  'docs/f3/F3.2E-PSBT-OUTPUT-TEST-ALIGNMENT-PACKET.md 4ffa20afbedeb0b6cfbbe57298f941bc0537683e' \
  'docs/f3/F3.2F-PSBT-OUTPUT-TEST-OWNER-DIRECTION-RECORD.md a066fc9710371f414d158a3deb9c345f2b00821b'; do
  csf32gprotected=${csf32gprotectedpair%% *}
  csf32gprotectedblob=${csf32gprotectedpair#* }
  $GIT hash-object -- "$csf32gprotected" > "$tmpdir/cs.f32g.protected.act"
  csf32grc=$?
  [ "$csf32grc" -eq 0 ] || err "F3.2g protected blob scan failed for $csf32gprotected"
  printf '%s\n' "$csf32gprotectedblob" > "$tmpdir/cs.f32g.protected.exp" \
    || err "F3.2g protected blob fixture failed"
  cmp -s "$tmpdir/cs.f32g.protected.exp" "$tmpdir/cs.f32g.protected.act"
  csf32grc=$?
  [ "$csf32grc" -eq 0 ] || err "F3.2g protected blob differs for $csf32gprotected"
done
for csf32gowner in \
  'Authorize preparation and independent audit of a docs-only F3.2g canonical TEST-ARCHITECTURE amendment from 45f2b362994b785d303e91b8e530efc724dc2d81, replacing only the complete Plan / oracle cells of QK-TST-DIFF-002 and QK-TST-DIFF-004 with the owner-approved text recorded in the published F3.2f owner-direction record, byte-for-byte. Preserve every other cell and row unchanged, retain QK-TST-REH-004 byte-for-byte, and include only the mechanically necessary Decision Log and verifier bindings.' \
  'No QK-TST status change or testing/evidence; no F32C-D11-Q-002 through Q-012 answer; no D-11, D-09, QK-LIM, profile, clause, OD-05/06, dependency, corpus, implementation, vector, fixture, media-I/O, hardware, license, settings, credential, release, or publication change.'; do
  csf32gownercount=$(grep -cFx -e "$csf32gowner" docs/DECISION-LOG.md)
  csf32grc=$?
  [ "$csf32grc" -le 1 ] || err "F3.2g owner transcript scan failed"
  [ "$csf32gownercount" = 1 ] || err "F3.2g owner transcript differs or duplicates"
done

# Bind the exact historical F3.2g C host mechanisms independently. The
# active host has a later authorized Decision-Log anchor and F3.2h guards.
for csf32ghostfixture in \
  '55bd46310606e2df4089d8234a67655c81440bab:docs/DECISION-LOG.md' \
  'p32gbase=45f2b362994b785d303e91b8e530efc724dc2d81' \
  'p32gbaseblob=f4e127a92fc68243274b7d384e335fa4632e5dd2' \
  'p32gactiveblob=065e20eed4e916c907a244aa3e5ca2e66cbc5d4e' \
  'cmp -s "$tmpdir/p32g.testarch.expected" "$TESTARCH32G"' \
  'err "QK-TST-REH-004 changed"' \
  'contains a changed or malformed QK-TST status cell'; do
  csf32ghostcount=$(grep -cF -e "$csf32ghostfixture" "$tmpdir/cs.f32g.host.stage")
  csf32grc=$?
  [ "$csf32grc" -le 1 ] || err "historical F3.2g C host mechanism scan failed"
  [ "$csf32ghostcount" = 1 ] || err "historical F3.2g C host mechanism is missing or duplicated: $csf32ghostfixture"
done

# ---------------- F3.2h QK-LIM-PSBT-027 cross-document alignment packet
# This stage is local, non-binding, non-normative, and unpublished.
# The exact graph/path/mode checks above and the bindings below preserve
# the complete F3.2g C source stage while adding only the authorized
# Decision Log append, packet, and verifier changes.
F32HPKT=docs/f3/F3.2H-QK-LIM-PSBT-027-CROSS-DOCUMENT-ALIGNMENT-PACKET.md
[ -f "$F32HPKT" ] || err "$F32HPKT missing"
cat > "$tmpdir/cs.f32h.paths.exp" <<'QK_CS_F32H_PATHS_EOF' || err "F3.2h path fixture generation failed"
docs/DECISION-LOG.md
docs/f3/F3.2H-QK-LIM-PSBT-027-CROSS-DOCUMENT-ALIGNMENT-PACKET.md
tools/verify-current-stage.sh
tools/verify-host-boundary.sh
QK_CS_F32H_PATHS_EOF
$GIT diff --name-only "$F32G_C" "$head" > "$tmpdir/cs.f32h.paths.raw"
csf32hrc=$?
[ "$csf32hrc" -eq 0 ] || err "F3.2h F32G_C..HEAD path enumeration failed"
[ -s "$tmpdir/cs.f32h.paths.raw" ] || err "F3.2h F32G_C..HEAD path enumeration is empty"
LC_ALL=C sort "$tmpdir/cs.f32h.paths.raw" > "$tmpdir/cs.f32h.paths.act"
csf32hrc=$?
[ "$csf32hrc" -eq 0 ] || err "F3.2h F32G_C..HEAD path sort failed"
cmp -s "$tmpdir/cs.f32h.paths.exp" "$tmpdir/cs.f32h.paths.act"
csf32hrc=$?
[ "$csf32hrc" -eq 0 ] || err "F3.2h F32G_C..HEAD path union is not the exact authorized four-path set"

# Commit A is one append-only Decision Log update and remains the exact
# active log. Commit B packet and host bytes remain exactly active.
$GIT show "$F32G_C:docs/DECISION-LOG.md" > "$tmpdir/cs.f32h.dlog.base" 2>/dev/null
csf32hrc=$?
[ "$csf32hrc" -eq 0 ] || err "cannot read F3.2h base Decision Log"
$GIT show "$C46:docs/DECISION-LOG.md" > "$tmpdir/cs.f32h.dlog.a" 2>/dev/null
csf32hrc=$?
[ "$csf32hrc" -eq 0 ] || err "cannot read F3.2h A Decision Log"
cmp -s "$tmpdir/cs.f32h.dlog.a" docs/DECISION-LOG.md
csf32hrc=$?
[ "$csf32hrc" -eq 0 ] || err "active Decision Log is not byte-identical to F3.2h A"
wc -c < "$tmpdir/cs.f32h.dlog.base" > "$tmpdir/cs.f32h.dlog.bytes.raw"
csf32hrc=$?
[ "$csf32hrc" -eq 0 ] || err "F3.2h base Decision Log byte count failed"
tr -d '[:space:]' < "$tmpdir/cs.f32h.dlog.bytes.raw" > "$tmpdir/cs.f32h.dlog.bytes"
csf32hrc=$?
[ "$csf32hrc" -eq 0 ] || err "F3.2h Decision Log byte-count normalization failed"
csf32hbasebytes=$(cat "$tmpdir/cs.f32h.dlog.bytes")
csf32hrc=$?
[ "$csf32hrc" -eq 0 ] || err "F3.2h Decision Log byte-count read failed"
case $csf32hbasebytes in ''|*[!0-9]*) err "F3.2h Decision Log byte count is non-numeric" ;; esac
dd if="$tmpdir/cs.f32h.dlog.a" bs=1 count="$csf32hbasebytes" \
  > "$tmpdir/cs.f32h.dlog.prefix" 2> "$tmpdir/cs.f32h.dlog.prefix.err"
csf32hrc=$?
[ "$csf32hrc" -eq 0 ] || err "F3.2h Decision Log prefix read failed"
cmp -s "$tmpdir/cs.f32h.dlog.base" "$tmpdir/cs.f32h.dlog.prefix"
csf32hrc=$?
[ "$csf32hrc" -eq 0 ] || err "F3.2h base Decision Log is not the exact prefix of A"

for csf32htreepair in \
  "$C46 100644 e7b7db5a12ea3c0a32d2b9cc3287e4d67d1da1bc docs/DECISION-LOG.md" \
  "$C47 100644 e18ba6b4a5c2ee5fc5b7d1a464b656c631b526d5 $F32HPKT" \
  "$C47 100755 854ef60c2e95eed4751499ecbd197e934f5f1be6 tools/verify-host-boundary.sh"; do
  csf32htreecommit=${csf32htreepair%% *}
  csf32htreerest=${csf32htreepair#* }
  csf32htreemode=${csf32htreerest%% *}
  csf32htreerest=${csf32htreerest#* }
  csf32htreeblob=${csf32htreerest%% *}
  csf32htreepath=${csf32htreerest#* }
  $GIT ls-tree "$csf32htreecommit" -- "$csf32htreepath" > "$tmpdir/cs.f32h.tree.raw"
  csf32hrc=$?
  [ "$csf32hrc" -eq 0 ] || err "F3.2h tree lookup failed for $csf32htreepath"
  [ -s "$tmpdir/cs.f32h.tree.raw" ] || err "F3.2h tree entry missing for $csf32htreepath"
  csf32htreelines=$(awk 'END {print NR+0}' "$tmpdir/cs.f32h.tree.raw")
  csf32hrc=$?
  [ "$csf32hrc" -eq 0 ] || err "F3.2h tree line count failed for $csf32htreepath"
  [ "$csf32htreelines" = 1 ] || err "F3.2h tree entry is not unique for $csf32htreepath"
  csf32htreeactmode=$(awk 'NR == 1 {print $1}' "$tmpdir/cs.f32h.tree.raw")
  csf32hrc=$?
  [ "$csf32hrc" -eq 0 ] || err "F3.2h tree mode extraction failed for $csf32htreepath"
  csf32htreeactblob=$(awk 'NR == 1 {print $3}' "$tmpdir/cs.f32h.tree.raw")
  csf32hrc=$?
  [ "$csf32hrc" -eq 0 ] || err "F3.2h tree blob extraction failed for $csf32htreepath"
  [ "$csf32htreeactmode" = "$csf32htreemode" ] || err "F3.2h mode differs for $csf32htreepath"
  [ "$csf32htreeactblob" = "$csf32htreeblob" ] || err "F3.2h tree blob differs for $csf32htreepath"
  $GIT hash-object -- "$csf32htreepath" > "$tmpdir/cs.f32h.active.blob"
  csf32hrc=$?
  [ "$csf32hrc" -eq 0 ] || err "F3.2h active blob scan failed for $csf32htreepath"
  printf '%s\n' "$csf32htreeblob" > "$tmpdir/cs.f32h.active.exp" \
    || err "F3.2h active blob fixture failed"
  cmp -s "$tmpdir/cs.f32h.active.exp" "$tmpdir/cs.f32h.active.blob"
  csf32hrc=$?
  [ "$csf32hrc" -eq 0 ] || err "F3.2h active blob differs for $csf32htreepath"
done
$GIT show "$C47:$F32HPKT" > "$tmpdir/cs.f32h.packet.b" 2>/dev/null
csf32hrc=$?
[ "$csf32hrc" -eq 0 ] || err "cannot read F3.2h packet from C47/B"
cmp -s "$tmpdir/cs.f32h.packet.b" "$F32HPKT"
csf32hrc=$?
[ "$csf32hrc" -eq 0 ] || err "active F3.2h packet is not byte-identical to C47/B"
$GIT show "$C47:tools/verify-host-boundary.sh" > "$tmpdir/cs.f32h.host.b" 2>/dev/null
csf32hrc=$?
[ "$csf32hrc" -eq 0 ] || err "cannot read F3.2h host verifier from C47/B"
cmp -s "$tmpdir/cs.f32h.host.b" tools/verify-host-boundary.sh
csf32hrc=$?
[ "$csf32hrc" -eq 0 ] || err "active host verifier is not byte-identical to C47/B"

# Canonical sources and historical F3.2e/F3.2f records are protected.
while IFS=' ' read -r csf32hprotected csf32hprotectedblob; do
  $GIT hash-object -- "$csf32hprotected" > "$tmpdir/cs.f32h.protected.act"
  csf32hrc=$?
  [ "$csf32hrc" -eq 0 ] || err "F3.2h protected blob scan failed for $csf32hprotected"
  printf '%s\n' "$csf32hprotectedblob" > "$tmpdir/cs.f32h.protected.exp" \
    || err "F3.2h protected blob fixture failed for $csf32hprotected"
  cmp -s "$tmpdir/cs.f32h.protected.exp" "$tmpdir/cs.f32h.protected.act"
  csf32hrc=$?
  [ "$csf32hrc" -eq 0 ] || err "F3.2h protected blob differs for $csf32hprotected"
done <<'QK_CS_F32H_PROTECTED_EOF'
docs/RESOURCE-BUDGETS.md 1ae6494fc24a8e3572464cf45e6d43ea4875e95d
docs/REQUIREMENTS.md 981b1b497102187da66fb4e82ef0725b32c088f7
docs/TEST-ARCHITECTURE.md 065e20eed4e916c907a244aa3e5ca2e66cbc5d4e
docs/f3/F3.2E-PSBT-OUTPUT-TEST-ALIGNMENT-PACKET.md 4ffa20afbedeb0b6cfbbe57298f941bc0537683e
docs/f3/F3.2F-PSBT-OUTPUT-TEST-OWNER-DIRECTION-RECORD.md a066fc9710371f414d158a3deb9c345f2b00821b
QK_CS_F32H_PROTECTED_EOF

# Cross-bind all three exact owner paragraphs between the active Decision
# Log and packet. Paragraph breaks are compared as bytes below.
for csf32howner in \
  'Authorize preparation and independent audit of a non-binding docs-only F3.2h QK-LIM-PSBT-027 cross-document alignment packet from a64399dd35aef8d6daa05171f1da30c8026f6d1f, with only the mechanically necessary Decision Log and verifier bindings. Limit scope to the stale “Raw final-transaction output bytes” dimension and its live links in docs/RESOURCE-BUDGETS.md, docs/REQUIREMENTS.md, and the QK-TST-DIFF-004 Links cell of docs/TEST-ARCHITECTURE.md.' \
  'Present exactly three unselected dispositions: recommended permanent tombstoning, unlinking, and non-reuse of ID 027; preservation as an inactive future contingency with no current links or value; or deferral with the known inconsistency retained. Reject deletion, renumbering, reuse, or repurposing of ID 027. Keep QK-LIM-PSBT-026 and all historical records unchanged.' \
  'No owner selection or canonical edit; no QK-LIM value, title, status, link, or row change; no QK-TST Plan / oracle or status change; no answer to F32C-D11-Q-002 through Q-012; no D-11, D-09, OD-05/06, profile, clause, implementation, testing, corpus, vector, fixture, evidence, media-I/O, hardware, license, gate, STOP-SHIP, setting, credential, release, publication, or remote change.'; do
  for csf32hownerfile in docs/DECISION-LOG.md "$F32HPKT"; do
    csf32hownercount=$(grep -cFx -e "$csf32howner" "$csf32hownerfile")
    csf32hrc=$?
    [ "$csf32hrc" -le 1 ] || err "F3.2h owner transcript scan failed in $csf32hownerfile"
    [ "$csf32hownercount" = 1 ] || err "F3.2h owner transcript differs or duplicates in $csf32hownerfile"
  done
done
sed -n '/^- \*\*Owner words exactly (literal three-paragraph block follows):\*\*$/,/^- \*\*Published parent and source locators:\*\*/p' \
  docs/DECISION-LOG.md > "$tmpdir/cs.f32h.owner.dlog.framed"
csf32hrc=$?
[ "$csf32hrc" -eq 0 ] || err "F3.2h Decision Log owner block extraction failed"
sed '1d;$d' "$tmpdir/cs.f32h.owner.dlog.framed" > "$tmpdir/cs.f32h.owner.dlog"
csf32hrc=$?
[ "$csf32hrc" -eq 0 ] || err "F3.2h Decision Log owner block deframing failed"
sed -n '/^## Owner words exactly$/,/^## Exact current canonical inventory$/p' \
  "$F32HPKT" > "$tmpdir/cs.f32h.owner.packet.framed"
csf32hrc=$?
[ "$csf32hrc" -eq 0 ] || err "F3.2h packet owner block extraction failed"
sed '1d;$d' "$tmpdir/cs.f32h.owner.packet.framed" > "$tmpdir/cs.f32h.owner.packet"
csf32hrc=$?
[ "$csf32hrc" -eq 0 ] || err "F3.2h packet owner block deframing failed"
cmp -s "$tmpdir/cs.f32h.owner.dlog" "$tmpdir/cs.f32h.owner.packet"
csf32hrc=$?
[ "$csf32hrc" -eq 0 ] || err "F3.2h Decision Log and packet owner transcript blocks differ"

# The active host blob is pinned above. Bind the operative F3.2h guards
# independently before invoking the host verifier in strict mode below.
for csf32hhostfixture in \
  'da55fb4bcd4983140c8fb379cc3322eec99284f0:docs/DECISION-LOG.md' \
  'p32hbase=a64399dd35aef8d6daa05171f1da30c8026f6d1f' \
  'p32ha=da55fb4bcd4983140c8fb379cc3322eec99284f0' \
  'p32hblob=e18ba6b4a5c2ee5fc5b7d1a464b656c631b526d5' \
  'docs/RESOURCE-BUDGETS.md 1ae6494fc24a8e3572464cf45e6d43ea4875e95d' \
  'cmp -s "$tmpdir/p32h.options.exp" "$tmpdir/p32h.options.act"' \
  'must contain exactly one owner-question heading' \
  'option order, selection, or recommendation grammar differs' \
  'No option selects or proposes any numeric QK-LIM value, including `0`.' \
  'must not end in double LF' \
  'source/protected blob differs'; do
  csf32hhostcount=$(grep -cF -e "$csf32hhostfixture" tools/verify-host-boundary.sh)
  csf32hrc=$?
  [ "$csf32hrc" -le 1 ] || err "active host F3.2h mechanism scan failed"
  [ "$csf32hhostcount" = 1 ] || err "active host F3.2h mechanism is missing or duplicated: $csf32hhostfixture"
done

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
docs/TEST-ARCHITECTURE.md
docs/f3/F3.2B-PSBT-DECISION-PACKET.md
docs/f3/F3.2B-PSBT-OWNER-RESPONSE-RECORD.md
docs/f3/F3.2C-D11-MEDIA-WRITE-LIFECYCLE-CONSTRUCTION-PACKET.md
docs/f3/F3.2D-D11-Q001-OWNER-CLARIFICATION-RECORD.md
docs/f3/F3.2E-PSBT-OUTPUT-TEST-ALIGNMENT-PACKET.md
docs/f3/F3.2F-PSBT-OUTPUT-TEST-OWNER-DIRECTION-RECORD.md
docs/f3/F3.2H-QK-LIM-PSBT-027-CROSS-DOCUMENT-ALIGNMENT-PACKET.md
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
  docs/f3/F3.2B-PSBT-DECISION-PACKET.md docs/f3/F3.2B-PSBT-OWNER-RESPONSE-RECORD.md \
  docs/f3/F3.2C-D11-MEDIA-WRITE-LIFECYCLE-CONSTRUCTION-PACKET.md \
  docs/f3/F3.2D-D11-Q001-OWNER-CLARIFICATION-RECORD.md \
  docs/f3/F3.2E-PSBT-OUTPUT-TEST-ALIGNMENT-PACKET.md \
  docs/f3/F3.2F-PSBT-OUTPUT-TEST-OWNER-DIRECTION-RECORD.md \
  docs/f3/F3.2H-QK-LIM-PSBT-027-CROSS-DOCUMENT-ALIGNMENT-PACKET.md \
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
