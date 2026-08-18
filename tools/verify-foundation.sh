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
  err "git or .git unavailable — tracking checks cannot run (fail closed)"
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
    ./docs/REQUIREMENTS.md|./docs/TRACEABILITY.md|./docs/LIFECYCLE-STATES.md|\
    ./docs/RESOURCE-BUDGETS.md|./docs/TEST-ARCHITECTURE.md|\
    ./.gitignore|./tools/verify-foundation.sh|./.replit) return 0 ;;
    *) return 1 ;;
  esac
}
unexpected=""
unexpected=$(find . \
  -path ./.git -prune -o \
  -path ./.cache -prune -o \
  -path ./.local -prune -o \
  -path ./.agents -prune -o \
  -path ./.config -prune -o \
  -path ./.upm -prune -o \
  -path ./attached_assets -prune -o \
  -type f -print 2>/dev/null | while IFS= read -r f; do
  is_allowed "$f" || printf ' %s' "$f"
done)
if [ -n "$unexpected" ]; then
  err "files exist outside the F0 allowlist:$unexpected"
else
  ok "only permitted foundation files exist (allowlist enforced)"
fi

# 7a2. Environment config: replit.nix must not exist, and .replit must contain
#      exactly the authorized content (in particular, no auto-added modules line).
if [ -e replit.nix ]; then
  err "replit.nix exists; the foundation authorizes no Nix package file"
else
  ok "replit.nix absent"
fi
expected_replit='run = "bash tools/verify-foundation.sh"

[nix]
channel = "stable-25_05"

[agent]
expertMode = true

[packager.features]
guessImports = false
packageSearch = false
enabledForHosting = false'
actual_replit=$(cat .replit 2>/dev/null)
if [ "$actual_replit" = "$expected_replit" ]; then
  ok ".replit contains exactly the authorized content"
else
  err ".replit differs from the authorized content (auto-added modules line or other drift?)"
fi

# 7b. F1 documents: present and visibly DRAFT / non-authoritative.
F1_BANNER='DRAFT — PENDING PROJECT-OWNER APPROVAL — NON-AUTHORITATIVE UNTIL CORRECTED F0 ARCHITECTURE IS APPROVED'
for f in docs/REQUIREMENTS.md docs/TRACEABILITY.md docs/LIFECYCLE-STATES.md \
         docs/RESOURCE-BUDGETS.md docs/TEST-ARCHITECTURE.md; do
  if [ -f "$f" ]; then
    ok "required F1 file exists: $f"
    if grep -q "$F1_BANNER" "$f" 2>/dev/null; then
      ok "F1 DRAFT banner present: $f"
    else
      err "F1 DRAFT banner missing: $f"
    fi
  else
    err "missing required F1 file: $f"
  fi
done

# 7c. F1 structural checks: requirements table integrity, ID discipline,
#     traceability coverage, and budget placeholders.
#     Portable POSIX shell + awk/sed/tr/sort/comm/diff only (no grep -o).
REQ=docs/REQUIREMENTS.md
BUD=docs/RESOURCE-BUDGETS.md
TST=docs/TEST-ARCHITECTURE.md
TRC=docs/TRACEABILITY.md
THRM=docs/THREAT-MODEL.md

tmpdir=$(mktemp -d "${TMPDIR:-/tmp}/qk-verify.XXXXXX") || { echo "FAIL: cannot create temp dir"; exit 1; }
trap 'rm -rf "$tmpdir"' EXIT INT TERM

# tokens FILE PATTERN — one matching ID token per line (POSIX: tr + grep, no -o).
tokens() { tr -c 'A-Za-z0-9_-' '\n' < "$1" | grep "$2" ; }

# Every requirement data row has exactly 8 fields (10 awk fields with leading/
# trailing empties) — an unescaped pipe in any cell changes the count.
bad_fields=$(awk -F'|' '/^\| QK-REQ-/ { if (NF != 10) print $2 }' "$REQ")
if [ -n "$bad_fields" ]; then
  err "requirement rows with wrong Markdown field count (unescaped table separator?):$bad_fields"
else
  ok "every requirement row has the expected Markdown field count"
fi

# Exactly one SHALL or SHALL NOT per requirement row.
bad_shall=$(awk -F'|' '/^\| QK-REQ-/ {
  t=$3; n=gsub(/SHALL NOT/,"",t); m=gsub(/SHALL/,"",t);
  if (n+m != 1) print $2 }' "$REQ")
if [ -n "$bad_shall" ]; then
  err "requirement rows without exactly one SHALL/SHALL NOT:$bad_shall"
else
  ok "every requirement row contains exactly one SHALL or SHALL NOT"
fi

# Required Src/Thr/Lim/Tst/Gate fields present and well-formed per row.
bad_cells=$(awk -F'|' '/^\| QK-REQ-/ {
  id=$2; src=$4; thr=$5; lim=$6; tst=$7; gate=$9;
  if (src !~ /QK-DEC-[0-9][0-9][0-9]/) print id " (Src)";
  if (thr !~ /QK-THR-[0-9][0-9][0-9]/) print id " (Thr)";
  if (lim !~ /QK-LIM-/ && lim !~ /NONE/) print id " (Lim)";
  if (tst !~ /QK-TST-/) print id " (Tst)";
  if (gate !~ /Gate [A-E]/ && gate !~ /FOUNDATION/) print id " (Gate)" }' "$REQ")
if [ -n "$bad_cells" ]; then
  err "requirement rows with missing/malformed source, threat, limit, test, or gate fields:$bad_cells"
else
  ok "every requirement row has well-formed Src/Thr/Lim/Tst/Gate fields"
fi

# ID uniqueness within each defining register (first-column / definition IDs).
dup=""
d=$(awk -F'|' '/^\| QK-REQ-/{gsub(/ /,"",$2); print $2}' "$REQ" | sort | uniq -d)
[ -n "$d" ] && dup="$dup REQ:$d"
d=$(awk -F'|' '/^\| QK-LIM-/{gsub(/ /,"",$2); print $2}' "$BUD" | sort | uniq -d)
[ -n "$d" ] && dup="$dup LIM:$d"
d=$(awk -F'|' '/^\| QK-TST-/{gsub(/ /,"",$2); print $2}' "$TST" | sort | uniq -d)
[ -n "$d" ] && dup="$dup TST:$d"
d=$(sed -n 's/.*\*\*\(QK-THR-[0-9][0-9][0-9]\) —.*/\1/p' "$THRM" | sort | uniq -d)
[ -n "$d" ] && dup="$dup THR:$d"
if [ -n "$dup" ]; then err "duplicate IDs:$dup"; else ok "all QK-REQ/QK-LIM/QK-TST/QK-THR IDs unique"; fi

# Defining registers -> defined-ID lists.
awk -F'|' '/^\| QK-LIM-/{gsub(/ /,"",$2); print $2}' "$BUD" | sort -u > "$tmpdir/lim_def"
awk -F'|' '/^\| QK-TST-/{gsub(/ /,"",$2); print $2}' "$TST" | sort -u > "$tmpdir/tst_def"
awk -F'|' '/^\| QK-REQ-/{gsub(/ /,"",$2); print $2}' "$REQ" | sort -u > "$tmpdir/req_def"
sed -n 's/.*\*\*\(QK-THR-[0-9][0-9][0-9]\) —.*/\1/p' "$THRM" | sort -u > "$tmpdir/thr_def"
tokens ARCHITECTURE.md '^QK-DEC-[0-9][0-9][0-9]$' | sort -u > "$tmpdir/dec_def"

# Requirements register -> cited-ID lists.
tokens "$REQ" "^QK-LIM-[A-Z0-9]*-[0-9][0-9][0-9]$" | sort -u > "$tmpdir/lim_cited"
tokens "$REQ" "^QK-TST-[A-Z]*-[0-9][0-9][0-9]$" | sort -u > "$tmpdir/tst_cited"
tokens "$REQ" "^QK-THR-[0-9][0-9][0-9]$" | sort -u > "$tmpdir/thr_cited"
tokens "$REQ" "^QK-DEC-[0-9][0-9][0-9]$" | sort -u > "$tmpdir/dec_cited"

# Every cited ID must exist in its defining register (catches QK-DEC-999 etc.).
m=$(comm -23 "$tmpdir/lim_cited" "$tmpdir/lim_def"); [ -n "$m" ] && err "cited QK-LIM IDs not defined in $BUD: $m"
m=$(comm -23 "$tmpdir/tst_cited" "$tmpdir/tst_def"); [ -n "$m" ] && err "cited QK-TST IDs not defined in $TST: $m"
m=$(comm -23 "$tmpdir/thr_cited" "$tmpdir/thr_def"); [ -n "$m" ] && err "cited QK-THR IDs not defined in $THRM: $m"
m=$(comm -23 "$tmpdir/dec_cited" "$tmpdir/dec_def"); [ -n "$m" ] && err "cited QK-DEC IDs not defined in ARCHITECTURE.md: $m"

# Every defined limit/test/decision must be cited by at least one requirement.
m=$(comm -13 "$tmpdir/lim_cited" "$tmpdir/lim_def"); [ -n "$m" ] && err "QK-LIM rows never cited by any requirement: $m"
m=$(comm -13 "$tmpdir/tst_cited" "$tmpdir/tst_def"); [ -n "$m" ] && err "QK-TST IDs never cited by any requirement: $m"
m=$(comm -13 "$tmpdir/dec_cited" "$tmpdir/dec_def"); [ -n "$m" ] && err "QK-DEC decisions cited by no requirement: $m"

# Every defined threat must be cited by a requirement or explicitly excluded.
while IFS= read -r id; do
  if ! grep "$id" "$tmpdir/thr_cited" >/dev/null 2>&1; then
    n=$(printf '%s' "$id" | sed 's/QK-THR-//')
    if ! awk -F'|' -v n="$n" 'BEGIN{found=1} $2 ~ n && $0 ~ /[Ee]xclusion/ {found=0} END{exit found}' "$TRC"; then
      err "threat $id neither cited by a requirement nor explicitly excluded in $TRC"
    fi
  fi
done < "$tmpdir/thr_def"

# Canonical forward matrix derived from the requirements register, and the
# same canonical form parsed from TRACEABILITY.md; the two must be identical
# field-by-field (IDs abbreviated per the documented prefix convention).
awk -F'|' '/^\| QK-REQ-/ {
  id=$2; gsub(/ /,"",id); sub(/^QK-REQ-/,"",id);
  out=id;
  n=split($4, a, /QK-DEC-/); s="";
  for (i=2; i<=n; i++) { v=substr(a[i],1,3); s = s (s=="" ? "" : ",") v }
  out = out "|" s;
  n=split($5, a, /QK-THR-/); s="";
  for (i=2; i<=n; i++) { v=substr(a[i],1,3); s = s (s=="" ? "" : ",") v }
  out = out "|" s;
  n=split($6, a, /QK-LIM-/); s="";
  for (i=2; i<=n; i++) { v=a[i]; sub(/[^A-Z0-9-].*$/,"",v); s = s (s=="" ? "" : ",") v }
  out = out "|" (s=="" ? "NONE" : s);
  n=split($7, a, /QK-TST-/); s="";
  for (i=2; i<=n; i++) { v=a[i]; sub(/[^A-Z0-9-].*$/,"",v); s = s (s=="" ? "" : ",") v }
  out = out "|" s;
  g=$9; gsub(/Gate /,"",g); gsub(/ /,"",g);
  print out "|" g }' "$REQ" | sort > "$tmpdir/fwd_from_req"
awk '/## Forward matrix/{inm=1; next} /## Reverse coverage/{inm=0} inm' "$TRC" | \
awk -F'|' '/^\| [A-Z0-9]+-[0-9][0-9][0-9] / {
  id=$2; gsub(/ /,"",id); out=id;
  for (col=3; col<=7; col++) { v=$col; gsub(/ /,"",v); out = out "|" v }
  print out }' | sort > "$tmpdir/fwd_from_trc"
if diff "$tmpdir/fwd_from_req" "$tmpdir/fwd_from_trc" > "$tmpdir/fwd_diff" 2>&1; then
  ok "forward matrix matches the requirements register field-by-field"
else
  err "forward matrix disagrees with requirements register: $(head -5 "$tmpdir/fwd_diff")"
fi

# Reverse decision/threat coverage tables must equal pairs derived from the register.
awk -F'|' '/^\| QK-REQ-/ {
  id=$2; gsub(/ /,"",id); sub(/^QK-REQ-/,"",id);
  n=split($4, a, /QK-DEC-/);
  for (i=2; i<=n; i++) print substr(a[i],1,3) " " id }' "$REQ" | sort -u > "$tmpdir/decpairs_req"
awk '/## Reverse coverage — decisions/{inm=1; next} /## Reverse coverage — threats/{inm=0} inm' "$TRC" | \
awk -F'|' '/^\| [0-9][0-9][0-9] /{
  d=$2; gsub(/ /,"",d);
  n=split($3, a, /[ ,]+/);
  for (i=1; i<=n; i++) if (a[i] ~ /^[A-Z0-9]+-[0-9][0-9][0-9]$/) print d " " a[i] }' | sort -u > "$tmpdir/decpairs_trc"
if diff "$tmpdir/decpairs_req" "$tmpdir/decpairs_trc" > "$tmpdir/dec_diff" 2>&1; then
  ok "reverse decision-coverage table matches the requirements register"
else
  err "reverse decision table disagrees with register: $(head -5 "$tmpdir/dec_diff")"
fi
awk -F'|' '/^\| QK-REQ-/ {
  id=$2; gsub(/ /,"",id); sub(/^QK-REQ-/,"",id);
  n=split($5, a, /QK-THR-/);
  for (i=2; i<=n; i++) print substr(a[i],1,3) " " id }' "$REQ" | sort -u > "$tmpdir/thrpairs_req"
awk '/## Reverse coverage — threats/{inm=1; next} /^QK-THR-015/{inm=0} /## Reverse coverage — limits/{inm=0} inm' "$TRC" | \
awk -F'|' '/^\| [0-9][0-9][0-9] /{
  t=$2; gsub(/ /,"",t);
  n=split($3, a, /[ ,().;:]+/);
  for (i=1; i<=n; i++) if (a[i] ~ /^[A-Z0-9]+-[0-9][0-9][0-9]$/ && a[i] !~ /^(QK|THR|DEC|LIM|TST)/) print t " " a[i] }' | sort -u > "$tmpdir/thrpairs_trc"
if diff "$tmpdir/thrpairs_req" "$tmpdir/thrpairs_trc" > "$tmpdir/thr_diff" 2>&1; then
  ok "reverse threat-coverage table matches the requirements register"
else
  err "reverse threat table disagrees with register: $(head -5 "$tmpdir/thr_diff")"
fi
ok "cross-register citation and coverage checks completed"

# No free-standing normative SHALL/SHALL NOT outside the requirements register.
# In the other F1 documents, a line containing SHALL is permitted only when it
# is a reference to register phrasing ("SHALL/SHALL NOT", "SHALL or SHALL NOT",
# "SHALL / SHALL NOT"); any other occurrence is an orphan normative claim.
orphan=""
for f in "$TRC" docs/LIFECYCLE-STATES.md "$BUD" "$TST"; do
  hits=$(awk '/SHALL/ {
    t=$0
    gsub(/SHALL\/SHALL NOT/,"",t)
    gsub(/SHALL or SHALL NOT/,"",t)
    gsub(/SHALL \/ SHALL NOT/,"",t)
    if (t ~ /SHALL/) print FILENAME ":" FNR }' "$f")
  [ -n "$hits" ] && orphan="$orphan $hits"
done
if [ -n "$orphan" ]; then
  err "free-standing SHALL/SHALL NOT outside the requirements register:$orphan"
else
  ok "no free-standing normative SHALL/SHALL NOT outside the requirements register"
fi

# Budget row schema: exactly 9 columns (11 awk fields); Value cell is exactly
# the placeholder; Status cell is exactly OPEN. No numbers, examples, defaults,
# candidates, or recommendations may appear in any Value cell.
bad_bud=$(awk -F'|' '/^\| QK-LIM-/ {
  if (NF != 11) { print $2 " (fields)"; next }
  v=$8; gsub(/^ +| +$/,"",v);
  s=$9; gsub(/^ +| +$/,"",s);
  if (v != "OPEN — VALUE NOT AUTHORIZED IN F1") print $2 " (Value)";
  if (s != "OPEN") print $2 " (Status)" }' "$BUD")
if [ -n "$bad_bud" ]; then
  err "budget rows violating the row schema (9 columns, exact placeholder Value, Status OPEN):$bad_bud"
else
  ok "every budget row has 9 columns, the exact OPEN placeholder Value, and Status OPEN"
fi

# Planned-test row schema: exactly 8 columns (10 awk fields); Status cell is
# exactly PLANNED — NOT RUN; Milestone is F3–F12; Gate well-formed.
bad_tst=$(awk -F'|' '/^\| QK-TST-/ {
  if (NF != 10) { print $2 " (fields)"; next }
  s=$9; gsub(/^ +| +$/,"",s);
  if (s != "PLANNED — NOT RUN") print $2 " (Status)";
  m=$6; gsub(/^ +| +$/,"",m);
  if (m !~ /^F([3-9]|1[0-2])$/) print $2 " (Milestone)";
  g=$7;
  if (g !~ /Gate [A-E]/ && g !~ /FOUNDATION/) print $2 " (Gate)" }' "$TST")
if [ -n "$bad_tst" ]; then
  err "planned-test rows violating the row schema (8 columns, Status PLANNED — NOT RUN, Milestone F3–F12, Gate):$bad_tst"
else
  ok "every planned-test row has 8 columns, Status exactly PLANNED — NOT RUN, and a valid milestone/gate"
fi

# Threat-register row schema: exactly 9 columns (11 awk fields); Status is one
# of OPEN, PLANNED CONTROL, ACCEPTED LIMITATION, OUT OF SCOPE; and every
# defined threat appears in the register exactly once.
bad_thr=$(awk -F'|' '/^\| QK-THR-/ {
  if (NF != 11) { print $2 " (fields)"; next }
  s=$9; gsub(/^ +| +$/,"",s);
  if (s != "OPEN" && s != "PLANNED CONTROL" && s != "ACCEPTED LIMITATION" && s != "OUT OF SCOPE") print $2 " (Status)" }' "$THRM")
if [ -n "$bad_thr" ]; then
  err "threat-register rows violating the row schema:$bad_thr"
else
  ok "every threat-register row has 9 columns and an allowed status"
fi
awk -F'|' '/^\| QK-THR-/{gsub(/ /,"",$2); print $2}' "$THRM" | sort -u > "$tmpdir/thr_reg"
m=$(comm -3 "$tmpdir/thr_def" "$tmpdir/thr_reg")
if [ -n "$m" ]; then
  err "threat register rows do not match the defined threat set: $m"
else
  ok "threat register covers exactly the defined threat set"
fi

# Single authoritative status definitions: each gate heading appears exactly
# once in MATURITY-GATES, and the ARCHITECTURE DRAFT status line appears
# exactly once in ARCHITECTURE.md.
for g in A B C D E; do
  n=$(grep -c "^### Gate $g " docs/MATURITY-GATES.md 2>/dev/null)
  if [ "$n" = "1" ]; then
    ok "exactly one authoritative status heading for Gate $g"
  else
    err "Gate $g has $n status headings in docs/MATURITY-GATES.md (must be exactly 1)"
  fi
done
n=$(grep -c 'DRAFT — PENDING PROJECT-OWNER APPROVAL' ARCHITECTURE.md 2>/dev/null)
if [ "$n" = "1" ]; then
  ok "exactly one authoritative DRAFT status line in ARCHITECTURE.md"
else
  err "ARCHITECTURE.md has $n DRAFT status lines (must be exactly 1)"
fi

# ARCHITECTURE remains pending owner approval.
if grep 'DRAFT — PENDING PROJECT-OWNER APPROVAL' ARCHITECTURE.md >/dev/null 2>&1; then
  ok "ARCHITECTURE.md remains DRAFT pending owner approval"
else
  err "ARCHITECTURE.md no longer marked DRAFT pending owner approval"
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
echo "NOTE: this verifier checks the working tree only. It cannot prove the absence"
echo "NOTE: of Replit platform state outside the tree (Secrets, Deployments, object"
echo "NOTE: storage, databases, scheduled jobs). Platform cleanliness requires manual"
echo "NOTE: inspection of the workspace configuration."
if [ "$fail" -eq 0 ]; then
  echo "FOUNDATION VERIFICATION: PASS"
  exit 0
else
  echo "FOUNDATION VERIFICATION: FAIL"
  exit 1
fi
