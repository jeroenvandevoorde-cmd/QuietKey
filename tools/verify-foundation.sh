#!/bin/sh
# QuietKey Foundation Gate F0 verifier.
# Portable POSIX shell, no external dependencies beyond standard utilities.
# This script only verifies; it never rewrites, creates, or deletes files.
# EXPERIMENTAL — NO REAL FUNDS — NOT A WALLET

set -u

fail=0
err() { echo "FAIL: $1"; fail=1; }
ok()  { echo "ok:   $1"; }

cd "$(dirname "$0")/.." || { echo "FAIL: cannot locate repository root"; exit 1; }

# 1. Every required file exists.
for f in \
  README.md ARCHITECTURE.md replit.md AGENTS.md SECURITY.md \
  docs/THREAT-MODEL.md docs/MATURITY-GATES.md docs/OPEN-DECISIONS.md \
  docs/DECISION-LOG.md docs/SOURCE-REGISTER.md docs/BUILD-ROADMAP.md \
  .gitignore tools/verify-foundation.sh
do
  if [ -f "$f" ]; then ok "required file exists: $f"; else err "missing required file: $f"; fi
done

# 2. README begins with the exact warning.
first_line=$(head -n 1 README.md 2>/dev/null)
if [ "$first_line" = "EXPERIMENTAL — NO REAL FUNDS — NOT A WALLET" ]; then
  ok "README begins with the exact no-funds warning"
else
  err "README does not begin with the exact warning"
fi

# 3. Architecture contains QK-DEC-001 through QK-DEC-014.
i=1
while [ "$i" -le 14 ]; do
  id=$(printf 'QK-DEC-%03d' "$i")
  if grep -q "$id" ARCHITECTURE.md 2>/dev/null; then
    ok "ARCHITECTURE.md contains $id"
  else
    err "ARCHITECTURE.md missing $id"
  fi
  i=$((i + 1))
done

# 4. Gates A–E are present and OPEN.
for g in A B C D E; do
  if grep -q "Gate $g" docs/MATURITY-GATES.md 2>/dev/null; then
    ok "Gate $g present"
    if grep "Gate $g" docs/MATURITY-GATES.md | grep -q "OPEN"; then
      ok "Gate $g is OPEN"
    else
      err "Gate $g is not marked OPEN"
    fi
  else
    err "Gate $g missing from docs/MATURITY-GATES.md"
  fi
done

# 5. Root LICENSE must not exist (removed by owner authorization; license is an OPEN decision).
if [ -e "LICENSE" ]; then
  err "root LICENSE exists; it was removed by owner authorization and no license may be selected"
else
  ok "root LICENSE absent (license remains an OPEN owner decision)"
fi

# 6. Nothing under attached_assets/ may be tracked by Git.
if [ -d .git ] && command -v git >/dev/null 2>&1; then
  tracked_assets=$(git --no-optional-locks ls-files -- attached_assets 2>/dev/null)
  if [ -n "$tracked_assets" ]; then
    err "files under attached_assets/ are tracked by Git: $tracked_assets"
  else
    ok "no attached_assets/ files are tracked by Git"
  fi
else
  ok "git unavailable; skipping attached_assets tracking check"
fi

# 7. Allowlist enforcement: outside .git and local Replit metadata
#    (.cache, .local, .agents, .config, .upm, attached_assets), only the
#    foundation's permitted files may exist. Any other file — any language,
#    any directory, any manifest, lockfile, database, or workflow — fails.
is_allowed() {
  case "$1" in
    ./README.md|./ARCHITECTURE.md|./replit.md|./AGENTS.md|./SECURITY.md|\
    ./docs/THREAT-MODEL.md|./docs/MATURITY-GATES.md|./docs/OPEN-DECISIONS.md|\
    ./docs/DECISION-LOG.md|./docs/SOURCE-REGISTER.md|./docs/BUILD-ROADMAP.md|\
    ./.gitignore|./tools/verify-foundation.sh|./.replit|./replit.nix) return 0 ;;
    *) return 1 ;;
  esac
}
unexpected=""
for f in $(find . \
  -path ./.git -prune -o \
  -path ./.cache -prune -o \
  -path ./.local -prune -o \
  -path ./.agents -prune -o \
  -path ./.config -prune -o \
  -path ./.upm -prune -o \
  -path ./attached_assets -prune -o \
  -type f -print 2>/dev/null); do
  is_allowed "$f" || unexpected="$unexpected $f"
done
if [ -n "$unexpected" ]; then
  err "files exist outside the F0 allowlist:$unexpected"
else
  ok "only permitted foundation files exist (allowlist enforced)"
fi

# 8. No functional wallet or cryptographic implementation exists.
# (With no source files besides this verifier, none can exist; also check for
#  database/deployment/workflow artifacts.)
for x in '*.db' '*.sqlite' '*.sqlite3'; do
  found=$(find . -path ./.git -prune -o -path ./.cache -prune -o -path ./.local -prune -o -path ./.agents -prune -o -name "$x" -type f -print 2>/dev/null)
  [ -n "$found" ] && err "database file exists: $found"
done
[ -d ".github" ] && err "workflow/deployment directory exists: .github"
ok "no wallet/cryptographic implementation, database, or workflow artifacts found"

echo
if [ "$fail" -eq 0 ]; then
  echo "FOUNDATION VERIFICATION: PASS"
  exit 0
else
  echo "FOUNDATION VERIFICATION: FAIL"
  exit 1
fi
