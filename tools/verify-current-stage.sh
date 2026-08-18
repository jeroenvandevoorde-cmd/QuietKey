#!/bin/sh
# QuietKey current-stage verifier (host-bootstrap stage).
#
# Authoritative verifier for the CURRENT stage. POSIX, offline,
# verify-only, non-mutating, strict-clean-worktree, fail-closed.
# It reasserts every still-applicable foundation control directly and
# proves canonical-file immutability against the published base, while
# permitting only the documented later-stage additions.
#
# LIMITS:
#   * The grep-based checks are heuristic, not complete semantic proof.
#   * No repository-resident script can inspect the Replit Secrets
#     inventory or any other hosting-platform fact. This script only
#     proves that no tracked code or configuration USES SESSION_SECRET
#     or any environment secret.
#   * tools/verify-foundation.sh (F0) and tools/verify-f2-preparation.sh
#     (F2 preparation) are immutable historical snapshot verifiers,
#     required to pass only at their documented anchors. This script
#     verifies their bytes are unchanged; it does not run them at HEAD.

set -u

fail=0
err() { printf 'CURRENT STAGE FAIL: %s\n' "$1" >&2; fail=1; }

cd "$(dirname "$0")/.." || { echo "CURRENT STAGE FAIL: cannot locate repository root" >&2; exit 1; }

GIT="git --no-optional-locks"

BASE=2442f4e6ddbf950980f6656e7219cc4ff23d3e41   # published base (origin/main)
C1=c622c19832c82b849737b895f41be7657fa8cc54     # docs: authorize host-only F3/F4 bootstrap
C2=f236f4097b87fce8f0ab781ec36d97c9b52cdc79     # build: add dependency-free Rust host state model

tmpdir="${TMPDIR:-/tmp}/qk-current-stage.$$"
umask 077
mkdir "$tmpdir" || { echo "CURRENT STAGE FAIL: cannot create temp dir" >&2; exit 1; }
trap 'rm -rf "$tmpdir"' EXIT INT TERM

# ---------------------------------------------------------------- 0. Clean
# Strict clean worktree: no tracked modification, no untracked file.
# Ignored build caches are acceptable only because they are ignored;
# nothing under an ignored path may ever be tracked (checked below).
dirty=$($GIT status --porcelain -uall)
[ -z "$dirty" ] || err "worktree is not strictly clean: $dirty"

# ----------------------------------------------------------- a. Ancestry
# Exact linear ancestry BASE -> C1 -> C2 -> HEAD, no merges.
head=$($GIT rev-parse HEAD) || err "cannot resolve HEAD"
p_head=$($GIT rev-parse "$head^" 2>/dev/null) || err "HEAD has no parent"
p_c2=$($GIT rev-parse "$C2^" 2>/dev/null) || err "C2 has no parent"
p_c1=$($GIT rev-parse "$C1^" 2>/dev/null) || err "C1 has no parent"
[ "$p_head" = "$C2" ] || err "HEAD parent is $p_head, expected $C2"
[ "$p_c1" = "$BASE" ] || err "C1 parent is $p_c1, expected $BASE"
[ "$p_c2" = "$C1" ] || err "C2 parent is $p_c2, expected $C1"
count=$($GIT rev-list --count "$BASE..$head")
[ "$count" = "3" ] || err "expected exactly 3 commits after base, found $count"
merges=$($GIT rev-list --merges "$BASE..$head")
[ -z "$merges" ] || err "merge commit present in $BASE..$head: $merges"
for c in "$head" "$C2" "$C1"; do
  np=$($GIT rev-list --no-walk --parents "$c" | wc -w)
  [ "$np" = "2" ] || err "commit $c does not have exactly one parent"
done

# ------------------------------------------- b/c/d. Per-commit path sets
check_paths() {
  # $1 = commit, $2 = label, remaining lines on stdin = expected paths
  LC_ALL=C sort > "$tmpdir/exp.$2"
  $GIT diff-tree --no-commit-id --name-only -r "$1" | LC_ALL=C sort > "$tmpdir/act.$2"
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

check_paths "$head" "governance-commit" <<'EOF'
.replit
replit.md
tools/verify-host-boundary.sh
tools/verify-current-stage.sh
EOF

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
docs/BUILD-ROADMAP.md
docs/DECISION-LOG.md
docs/HOST-WORK-AUTHORIZATION.md
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
replit.md
tools/verify-current-stage.sh
tools/verify-host-boundary.sh
EOF
$GIT diff --name-only "$BASE" "$head" | LC_ALL=C sort > "$tmpdir/actual-diff"
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
lic=$($GIT ls-files | grep -iE '(^|/)(LICENSE|LICENCE|COPYING|COPYRIGHT|NOTICE)(\.|$)' || :)
[ -z "$lic" ] || err "license-like file tracked while OD-08 is open: $lic"

# f.6 No service/deploy/db/workflow/env artifacts; no dependency
# manifests beyond the authorized host workspace.
bad=$($GIT ls-files | grep -E '(^|/)(\.env|.*\.(db|sqlite|sqlite3))$|^\.github/|(^|/)(Dockerfile|docker-compose[^/]*)$|(^|/)(package\.json|requirements\.txt|pyproject\.toml|go\.mod)$' || :)
[ -z "$bad" ] || err "service/deploy/db/workflow/env/dependency artifact tracked: $bad"
grep -E '^deployment|^\[deployment' .replit >/dev/null 2>&1 && err ".replit contains deployment configuration"

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
refs=$($GIT grep -l 'SESSION_SECRET' -- . | grep -v -e '^docs/f2/README.md$' -e '^tools/verify-f2-preparation.sh$' -e '^tools/verify-current-stage.sh$' || :)
[ -z "$refs" ] || err "SESSION_SECRET referenced outside documented descriptive mentions: $refs"
envuse=$($GIT grep -nE 'std *:: *env|process\.env|os\.environ|getenv *\(' -- ':!tools/' ':!docs/' || :)
[ -z "$envuse" ] || err "environment-variable use found in tracked code: $envuse"

# ------------------------- g. Host boundary, strict publication mode
sh tools/verify-host-boundary.sh > "$tmpdir/hb" 2>&1 \
  || err "verify-host-boundary.sh (publication mode) failed: $(cat "$tmpdir/hb")"
grep -x 'HOST BOOTSTRAP SCOPE PASS' "$tmpdir/hb" >/dev/null \
  || err "verify-host-boundary.sh did not emit the strict publication pass line"

# ----------------------------------------------- h. Lockfile purity
grep -E '^(source|checksum) *=' host/Cargo.lock >/dev/null 2>&1 \
  && err "host/Cargo.lock contains external source/checksum entries"
names=$(grep -c '^name = ' host/Cargo.lock)
[ "$names" = "2" ] || err "host/Cargo.lock does not contain exactly two packages (found $names)"
grep '^name = "qk-host-model"$' host/Cargo.lock >/dev/null || err "qk-host-model missing from lockfile"
grep '^name = "qk-host-sim"$' host/Cargo.lock >/dev/null || err "qk-host-sim missing from lockfile"

# ------------------------------------------------ i. No untracked files
untracked=$($GIT status --porcelain -uall | grep '^??' || :)
[ -z "$untracked" ] || err "untracked files present: $untracked"
tracked_ignored=$($GIT ls-files -i -c --exclude-standard || :)
[ -z "$tracked_ignored" ] || err "tracked file matches an ignore rule: $tracked_ignored"

if [ "$fail" -eq 0 ]; then
  echo "CURRENT STAGE PASS"
  exit 0
else
  exit 1
fi
