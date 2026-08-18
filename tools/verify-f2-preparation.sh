#!/bin/sh
# tools/verify-f2-preparation.sh
#
# QuietKey F2.0 structural preparation verifier.
#
# This script is a stage-specific structural aid, never authoritative
# evidence. It is bound to the approved F2 entry revision: the supplied H1
# must equal EXPECTED_H1 below, and the full H1 hash must appear in
# docs/f2/README.md and docs/f2/ENTRY-REVIEW.md.
#
# Modes (identical content rules in both):
#   --worktree <full-40-hex-H1-hash>
#       HEAD must equal the supplied H1 hash. The union of the tracked/staged
#       diff against HEAD (including deletions, renames, mode and type
#       changes) and the full untracked set must be exactly the eleven
#       allowlisted F2 preparation additions.
#   --commit <full-40-hex-H1-hash> <full-40-hex-H2-hash>
#       The worktree must be clean, HEAD must equal the supplied H2, H2's
#       sole parent must be exactly H1, and the exact H1..H2 diff (including
#       modes and types) must be exactly the eleven allowlisted additions.
#
# Hash arguments must be full 40-character lowercase hexadecimal object
# names. This script never resolves, abbreviates, or infers a hash and
# rejects missing, extra, shortened, or non-hex arguments.
#
# STATED LIMITATIONS (not waivable):
#   * This is a STRUCTURAL check only. It cannot prove scientific
#     completeness, absence of bias, safety, experimental quality, or the
#     semantic correctness of any document it inspects.
#   * This script is self-authored in the same revision it checks (H2), so
#     its success line is supporting evidence only, never primary evidence.
#   * NOTE: the absence of a SESSION_SECRET (or any other platform secret)
#     is a manually observed platform fact; no repository-resident verifier
#     can prove facts about the hosting platform.
#   * Running tools/verify-foundation.sh against the expanded F2 tree
#     reports an allowlist mismatch. That is the EXPECTED STAGE MISMATCH
#     between the F0/F1 foundation allowlist and the F2 preparation
#     additions, not a real defect. The foundation verifier is only required
#     to succeed at the clean H1 revision. A real defect is any change to
#     the BYTES of tools/verify-foundation.sh or of any other pre-existing
#     H1 file, which this script checks directly.
#
# Numeric-check scope: numeric prohibitions target the designated
# threshold/value fields of the experiment register only (enforced below by
# exact-string matching of those fields). Dates, commit hashes, identifiers,
# and repetition counts in prose are exempt by design.
#
# Status-change scope: OD, gate, test, and limit statuses live exclusively
# in pre-existing H1 files. The requirement that every pre-existing tracked
# file be byte-identical to H1 therefore structurally rejects any changed
# OD, gate, test, or limit status.
#
# Tooling: POSIX sh, awk, sed, tr, sort, comm, diff, and git only.
# On success this script prints exactly one line on stdout:
#   F2 STRUCTURAL PREPARATION CHECK: PASS

set -u
LC_ALL=C
export LC_ALL

GIT="git --no-optional-locks"

TMP="${TMPDIR:-/tmp}/qk-f2-verify.$$"
mkdir "$TMP" || { echo "cannot create temp dir" >&2; exit 2; }
trap 'rm -rf "$TMP"' 0

fail() {
    printf 'F2 STRUCTURAL PREPARATION CHECK: FAIL\n' >&2
    printf 'reason: %s\n' "$1" >&2
    exit 1
}

usage_fail() {
    printf 'usage:\n' >&2
    printf '  %s --worktree <full-40-hex-H1-hash>\n' "$0" >&2
    printf '  %s --commit <full-40-hex-H1-hash> <full-40-hex-H2-hash>\n' "$0" >&2
    printf 'hashes must be full 40-character lowercase hex; this script never resolves or abbreviates refs\n' >&2
    exit 2
}

is_full_hash() {
    h="$1"
    [ "${#h}" -eq 40 ] || return 1
    rest=$(printf '%s' "$h" | tr -d '0123456789abcdef')
    [ -z "$rest" ]
}

EXPECTED_H1='d24cf39269eca79f6e471d16eeda2d7736334dd3'
BANNER='F2 PREPARATION ONLY — TARGET WORK NOT RUN — NO GATE CLOSED'
VERIFIER='tools/verify-f2-preparation.sh'
REGISTER='docs/f2/EXPERIMENT-REGISTER.md'
EVIDENCE='docs/f2/EVIDENCE-REGISTER.md'
DECINPUT='docs/f2/DECISION-INPUTS.md'

# Allowlist, LC_ALL=C sorted. Exactly these eleven paths may be added.
cat > "$TMP/allow" <<'EOF'
docs/f2/CARD-PROTOCOL.md
docs/f2/DECISION-INPUTS.md
docs/f2/ENTRY-REVIEW.md
docs/f2/EVIDENCE-REGISTER.md
docs/f2/EXIT-REVIEW.md
docs/f2/EXPERIMENT-REGISTER.md
docs/f2/QR-PROTOCOL.md
docs/f2/README.md
docs/f2/SD-POWER-PROTOCOL.md
docs/f2/TARGET-CORE-PROTOCOL.md
tools/verify-f2-preparation.sh
EOF

# ---- argument handling ------------------------------------------------------

MODE=''
H1=''
H2=''
case "${1-}" in
    --worktree)
        [ "$#" -eq 2 ] || usage_fail
        H1="$2"
        is_full_hash "$H1" || usage_fail
        MODE=worktree
        ;;
    --commit)
        [ "$#" -eq 3 ] || usage_fail
        H1="$2"
        H2="$3"
        is_full_hash "$H1" || usage_fail
        is_full_hash "$H2" || usage_fail
        MODE=commit
        ;;
    *)
        usage_fail
        ;;
esac

$GIT rev-parse --is-inside-work-tree >/dev/null 2>&1 || fail "not inside a git work tree"
[ "$H1" = "$EXPECTED_H1" ] || fail "supplied H1 ($H1) does not equal the approved F2 entry revision ($EXPECTED_H1)"
t=$($GIT cat-file -t "$H1" 2>/dev/null) || fail "H1 object not found: $H1"
[ "$t" = commit ] || fail "H1 is not a commit: $H1"

# readf <path> <outfile> : materialize the checked revision's file content
readf() {
    if [ "$MODE" = worktree ]; then
        cat "$1" > "$2" 2>/dev/null || fail "cannot read worktree file: $1"
    else
        $GIT show "$H2:$1" > "$2" 2>/dev/null || fail "cannot read $1 from H2"
    fi
}

# ---- mode-specific structure checks ----------------------------------------

if [ "$MODE" = worktree ]; then
    head=$($GIT rev-parse HEAD 2>/dev/null) || fail "cannot read HEAD"
    [ "$head" = "$H1" ] || fail "HEAD ($head) does not equal supplied H1 ($H1)"

    # Tracked/staged diff against HEAD union untracked set.
    $GIT status --porcelain -uall > "$TMP/porc" || fail "git status failed"
    : > "$TMP/added"
    while IFS= read -r line; do
        [ -n "$line" ] || continue
        xy=$(printf '%s' "$line" | sed -n 's/^\(..\).*$/\1/p')
        p=$(printf '%s' "$line" | sed 's/^...//')
        case "$xy" in
            '??'|'A '|'AM')
                printf '%s\n' "$p" >> "$TMP/added"
                ;;
            *)
                fail "disallowed worktree change (status '$xy'): $p"
                ;;
        esac
        case "$p" in
            '"'*) fail "path requiring quoting is prohibited: $p" ;;
        esac
    done < "$TMP/porc"

    sort -u "$TMP/added" > "$TMP/added.sorted"
    diff "$TMP/allow" "$TMP/added.sorted" >/dev/null 2>&1 \
        || fail "addition set is not exactly the eleven allowlisted paths (see: diff of allowlist vs observed)"

    # Disk-level type and mode rules.
    while IFS= read -r p; do
        [ -e "$p" ] || fail "allowlisted file missing: $p"
        [ -h "$p" ] && fail "symlink prohibited: $p"
        [ -f "$p" ] || fail "not a regular file: $p"
        if [ "$p" = "$VERIFIER" ]; then
            [ -x "$p" ] || fail "verifier must be executable: $p"
        else
            [ -x "$p" ] && fail "executable mode prohibited for addition: $p"
        fi
    done < "$TMP/allow"

    # Foundation verifier byte-identical to H1.
    $GIT show "$H1:tools/verify-foundation.sh" > "$TMP/fv.h1" 2>/dev/null \
        || fail "cannot read tools/verify-foundation.sh from H1"
    diff "$TMP/fv.h1" tools/verify-foundation.sh >/dev/null 2>&1 \
        || fail "tools/verify-foundation.sh differs from H1"
    # All other pre-existing tracked files are byte-identical to H1 because
    # the porcelain scan above rejects every non-addition status.
else
    t=$($GIT cat-file -t "$H2" 2>/dev/null) || fail "H2 object not found: $H2"
    [ "$t" = commit ] || fail "H2 is not a commit: $H2"

    porc=$($GIT status --porcelain) || fail "git status failed"
    [ -z "$porc" ] || fail "worktree is not clean in --commit mode"

    head=$($GIT rev-parse HEAD 2>/dev/null) || fail "cannot read HEAD"
    [ "$head" = "$H2" ] || fail "HEAD ($head) does not equal supplied H2 ($H2)"

    parents=$($GIT rev-list --parents -n 1 "$H2") || fail "cannot read H2 parents"
    set -- $parents
    [ "$#" -eq 2 ] || fail "H2 must have exactly one parent"
    [ "$1" = "$H2" ] || fail "internal: rev-list mismatch"
    [ "$2" = "$H1" ] || fail "H2 sole parent ($2) is not H1 ($H1)"

    $GIT diff --raw --no-renames "$H1" "$H2" > "$TMP/raw" || fail "git diff failed"
    : > "$TMP/added"
    while IFS= read -r line; do
        [ -n "$line" ] || continue
        meta=$(printf '%s' "$line" | sed 's/\t.*$//')
        p=$(printf '%s' "$line" | sed 's/^[^\t]*\t//')
        st=$(printf '%s' "$meta" | awk '{print $5}')
        newmode=$(printf '%s' "$meta" | awk '{print $2}')
        [ "$st" = A ] || fail "H1..H2 contains a non-addition change ($st): $p"
        case "$newmode" in
            100644)
                [ "$p" = "$VERIFIER" ] && fail "verifier must be mode 100755: $p"
                ;;
            100755)
                [ "$p" = "$VERIFIER" ] || fail "executable mode prohibited for addition: $p"
                ;;
            120000) fail "symlink prohibited: $p" ;;
            160000) fail "submodule prohibited: $p" ;;
            *) fail "prohibited mode/type $newmode: $p" ;;
        esac
        printf '%s\n' "$p" >> "$TMP/added"
    done < "$TMP/raw"

    sort -u "$TMP/added" > "$TMP/added.sorted"
    diff "$TMP/allow" "$TMP/added.sorted" >/dev/null 2>&1 \
        || fail "H1..H2 addition set is not exactly the eleven allowlisted paths"

    # Foundation verifier byte-identical between H1 and H2.
    $GIT show "$H1:tools/verify-foundation.sh" > "$TMP/fv.h1" 2>/dev/null \
        || fail "cannot read tools/verify-foundation.sh from H1"
    $GIT show "$H2:tools/verify-foundation.sh" > "$TMP/fv.h2" 2>/dev/null \
        || fail "cannot read tools/verify-foundation.sh from H2"
    diff "$TMP/fv.h1" "$TMP/fv.h2" >/dev/null 2>&1 \
        || fail "tools/verify-foundation.sh differs between H1 and H2"
    # All other pre-existing tracked files are byte-identical to H1 because
    # the raw diff scan above rejects every non-addition status.
fi

# ---- addition hygiene (both modes) ------------------------------------------

while IFS= read -r p; do
    # Hidden path components, archives, manifests, lockfiles, workflows.
    printf '%s\n' "$p" | tr '/' '\n' | while IFS= read -r comp; do
        case "$comp" in
            .*) fail "hidden path component prohibited: $p" ;;
        esac
    done || exit 1
    case "$p" in
        *.zip|*.tar|*.tar.*|*.tgz|*.gz|*.bz2|*.xz|*.7z|*.rar|*.jar) fail "archive prohibited: $p" ;;
        *.lock|*lock.json|*lock.yaml|*lock.yml|yarn.lock) fail "lockfile prohibited: $p" ;;
        *.toml|*.nix|package.json|Cargo.toml|pyproject.toml) fail "platform/config addition prohibited: $p" ;;
        .github/*|*/workflows/*) fail "workflow addition prohibited: $p" ;;
    esac

    readf "$p" "$TMP/f"

    # NUL / binary prohibition.
    nul=$(tr -cd '\000' < "$TMP/f" | tr '\000' x)
    [ -z "$nul" ] || fail "NUL/binary content prohibited: $p"

    # LFS pointer prohibition.
    first=$(sed -n '1p' "$TMP/f")
    case "$first" in
        'version https://git-lfs'*) fail "LFS pointer prohibited: $p" ;;
    esac
done < "$TMP/allow"

# ---- content rules for the ten governance documents (both modes) -----------

: > "$TMP/f2all"
for p in \
    docs/f2/CARD-PROTOCOL.md \
    docs/f2/DECISION-INPUTS.md \
    docs/f2/ENTRY-REVIEW.md \
    docs/f2/EVIDENCE-REGISTER.md \
    docs/f2/EXIT-REVIEW.md \
    docs/f2/EXPERIMENT-REGISTER.md \
    docs/f2/QR-PROTOCOL.md \
    docs/f2/README.md \
    docs/f2/SD-POWER-PROTOCOL.md \
    docs/f2/TARGET-CORE-PROTOCOL.md
do
    readf "$p" "$TMP/doc"

    cat "$TMP/doc" >> "$TMP/f2all"

    # Exact banner line required.
    awk -v b="$BANNER" '$0 == b { found = 1 } END { exit found ? 0 : 1 }' "$TMP/doc" \
        || fail "missing exact preparation banner: $p"

    # Execution interlock: evidence-inflation words, free-standing
    # normative language, run/result/operator record labels, execution
    # authorization, and embedded script sources are structural failures.
    # Word tokens and phrases are matched CASE-INSENSITIVELY; word tokens
    # use non-letter boundaries so that e.g. "provenance" never matches
    # a prohibited word.
    awk -v path="$p" '
        BEGIN {
            nw = 0
            word[++nw] = "SHALL"
            word[++nw] = "VALIDATED"
            word[++nw] = "PROVEN"
            word[++nw] = "PASSED"
            word[++nw] = "RECOMMENDED"
            np = 0
            phr[++np] = "EXECUTION IS AUTHORIZED"
            phr[++np] = "EXECUTION AUTHORIZED"
            phr[++np] = "RUNS ARE AUTHORIZED"
            phr[++np] = "RUN IS AUTHORIZED"
            phr[++np] = "AUTHORIZED TO PROCEED"
            phr[++np] = "AUTHORIZED TO RUN"
            phr[++np] = "AUTHORIZED TO BEGIN"
            phr[++np] = "MAY NOW RUN"
            phr[++np] = "MAY NOW BEGIN"
            phr[++np] = "MAY NOW PROCEED"
            phr[++np] = "CLEARED TO RUN"
            phr[++np] = "BYTE EQUALITY WITH A REFERENCE SIGNATURE"
            phr[++np] = "BYTE-IDENTICAL TO A REFERENCE SIGNATURE"
            phr[++np] = "BYTE-FOR-BYTE AGAINST A REFERENCE SIGNATURE"
            phr[++np] = "MATCHES A REFERENCE SIGNATURE"
            phr[++np] = "MATCHES THE REFERENCE SIGNATURE"
            phr[++np] = "COMPARE SIGNATURE BYTES"
            phr[++np] = "COMPARE THE SIGNATURE BYTES"
            phr[++np] = "SIGNATURE BYTES TO THE REFERENCE"
            phr[++np] = "SIGNATURE BYTES AGAINST THE REFERENCE"
            nl = 0
            lab[++nl] = "- RESULT:"
            lab[++nl] = "- RESULTS:"
            lab[++nl] = "- OUTCOME:"
            lab[++nl] = "- OPERATOR:"
            lab[++nl] = "- TESTER:"
            lab[++nl] = "- RUN TIMESTAMP:"
            lab[++nl] = "- RUN DATE:"
            lab[++nl] = "- OBSERVED:"
            lab[++nl] = "- OBSERVATION:"
            lab[++nl] = "- OBSERVATIONS:"
            lab[++nl] = "- MEASURED:"
            lab[++nl] = "- MEASUREMENT:"
            lab[++nl] = "- MEASUREMENTS:"
            lab[++nl] = "- RECOMMENDATION:"
            lab[++nl] = "- RECOMMENDATIONS:"
            status = 0
        }
        {
            up = toupper($0)
            for (i = 1; i <= nw; i++) {
                pat = "(^|[^A-Z])" word[i] "([^A-Z]|$)"
                if (up ~ pat) {
                    printf "forbidden word %s in %s line %d\n", word[i], path, NR > "/dev/stderr"
                    status = 1
                }
            }
            for (i = 1; i <= np; i++) {
                if (index(up, phr[i]) > 0) {
                    printf "forbidden phrase \"%s\" in %s line %d\n", phr[i], path, NR > "/dev/stderr"
                    status = 1
                }
            }
            for (i = 1; i <= nl; i++) {
                if (index(up, lab[i]) == 1) {
                    printf "forbidden record label \"%s\" in %s line %d\n", lab[i], path, NR > "/dev/stderr"
                    status = 1
                }
            }
            if (index($0, "#!/") > 0) {
                printf "embedded script source in %s line %d\n", path, NR > "/dev/stderr"
                status = 1
            }
        }
        END { exit status }
    ' "$TMP/doc" || fail "execution-interlock token violation: $p"
done

# ---- reference legitimacy (both modes) --------------------------------------
# Every QK-REQ / QK-THR / QK-LIM / QK-TST / QK-APR / QK-DEC identifier
# referenced by an F2 document must be a member of the exact token set
# extracted from the H1 corpus with the same tokenizer — set membership,
# never a substring test, so an invented prefix such as QK-REQ-CARD-00
# can never ride on QK-REQ-CARD-001. F2 preparation may reference, never
# invent, requirements, threats, limits, tests, approvals, or decisions.
# The only permitted register-family notation is the exact schema
# placeholders QK-F2E-NNN and QK-F2V-NNN plus registered numeric
# experiment IDs within the register range; any other QK-F2E-* / QK-F2V-*
# token is a structural failure.

$GIT ls-tree -r --name-only "$H1" > "$TMP/h1files" || fail "cannot list H1 tree"
: > "$TMP/corpus"
while IFS= read -r f; do
    $GIT show "$H1:$f" >> "$TMP/corpus" 2>/dev/null || fail "cannot read H1 file: $f"
done < "$TMP/h1files"

tokenize() {
    awk '{
        s = $0
        while (match(s, /QK-[A-Z0-9][A-Z0-9-]*/)) {
            print substr(s, RSTART, RLENGTH)
            s = substr(s, RSTART + RLENGTH)
        }
    }' "$1" | sort -u
}

tokenize "$TMP/f2all"  > "$TMP/toks"
tokenize "$TMP/corpus" > "$TMP/corpustoks"

: > "$TMP/need"
while IFS= read -r t; do
    case "$t" in
        QK-F2E-[0-9][0-9][0-9])
            n=$(printf '%s' "$t" | sed 's/^QK-F2E-0*//')
            [ -n "$n" ] || fail "experiment reference out of range: $t"
            [ "$n" -ge 1 ] 2>/dev/null || fail "experiment reference out of range: $t"
            [ "$n" -le 15 ] 2>/dev/null || fail "experiment reference out of range: $t"
            ;;
        QK-F2E-NNN|QK-F2V-NNN)
            : # exact schema placeholders only
            ;;
        QK-F2E-*|QK-F2V-*)
            fail "bogus F2 register-family token (only QK-F2E-NNN, QK-F2V-NNN, and registered numeric IDs are permitted): $t"
            ;;
        QK|QK-REQ|QK-THR|QK-LIM|QK-TST|QK-F2E|QK-F2V|QK-APR|QK-DEC|QK-LIM-QR|QK-LIM-SD|QK-LIM-APDU)
            : # closed list of bare family/subfamily mentions in prose
            ;;
        QK-REQ-*|QK-THR-*|QK-LIM-*|QK-TST-*|QK-APR-*|QK-DEC-*)
            printf '%s\n' "$t" >> "$TMP/need"
            ;;
        *)
            fail "unrecognized QK identifier family in F2 documents: $t"
            ;;
    esac
done < "$TMP/toks"

invented=$(comm -23 "$TMP/need" "$TMP/corpustoks")
[ -z "$invented" ] || fail "identifier(s) not in the H1 token set (invented reference): $(printf '%s' "$invented" | tr '\n' ' ')"

# ---- entry-revision binding in the documents (both modes) --------------------
for p in docs/f2/README.md docs/f2/ENTRY-REVIEW.md; do
    readf "$p" "$TMP/hb"
    awk -v h="$EXPECTED_H1" 'index($0, h) { found = 1; exit } END { exit found ? 0 : 1 }' "$TMP/hb" \
        || fail "full approved H1 hash missing from $p"
done

# ---- experiment register discipline (both modes) ----------------------------

# The register parser is SECTION-AWARE: the register must contain exactly
# the sections QK-F2E-001 through QK-F2E-015 in ascending order, each
# containing every required field exactly once. Inside a section, every
# bulleted field label must come from the closed label set below —
# unrecognized record-like fields (run dates, testers, results, and so on)
# are structural failures, whatever they are called. Designated open/value
# fields are matched against their exact template strings, which also
# enforces the numeric prohibition on those fields.
readf "$REGISTER" "$TMP/reg"
awk '
    function setexact(l, v) { allowed[l] = 1; exact[l] = v; req[++nreq] = l }
    function setfree(l)     { allowed[l] = 1; exact[l] = "";  req[++nreq] = l }
    function checksec(   i, l) {
        for (i = 1; i <= nreq; i++) {
            l = req[i]
            if (cnt[l] != 1) {
                printf "field \"%s\" appears %d times in section %s (need exactly once)\n", l, cnt[l] + 0, curid > "/dev/stderr"
                ok = 0
            }
        }
    }
    BEGIN {
        ok = 1; secs = 0; insec = 0; nreq = 0
        S  = "OPEN — SPECIMEN NOT IDENTIFIED"
        F  = "OPEN — NOT DEFINED UNTIL RUN REGISTRATION"
        N  = "NONE — NOT RUN"
        ST = "PROTOCOL TEMPLATE — RUN REGISTRATION PENDING — NOT RUN"
        H3 = "run registration requires a future owner-authorized commit (H3); NOT GRANTED."
        setfree("Question")
        setfree("Links")
        setfree("Owner decision this may inform (never resolve)")
        setexact("Specimen", S)
        setexact("Apparatus", S)
        setfree("Procedure outline")
        setexact("Repetition plan", F)
        setexact("Calibration plan", F)
        setexact("Exclusion criteria", F)
        setexact("Stopping rule", F)
        setexact("Analysis plan", F)
        setfree("Raw-evidence and hashing plan")
        setfree("Known confounders")
        setfree("Controls")
        setfree("Inconclusive handling")
        setexact("H3 prerequisite", H3)
        setfree("Claim (potential subject only)")
        setexact("Fact", N)
        setexact("Inference", N)
        setexact("Decision input", N)
        setexact("Status", ST)
    }
    /^### / {
        if (insec) checksec()
        if ($0 !~ /^### QK-F2E-[0-9][0-9][0-9] /) {
            print "malformed experiment heading line " NR > "/dev/stderr"; ok = 0
        }
        secs++
        curid = substr($0, 5, 10)
        n = substr($0, 12, 3) + 0
        if (n != secs) {
            printf "section %s out of order or duplicated (expected number %d)\n", curid, secs > "/dev/stderr"
            ok = 0
        }
        for (l in allowed) cnt[l] = 0
        insec = 1
        next
    }
    insec && /^- / {
        i = index($0, ":")
        if (i == 0) {
            print "unlabeled bullet inside experiment section, line " NR > "/dev/stderr"; ok = 0; next
        }
        l = substr($0, 3, i - 3)
        if (!(l in allowed)) {
            printf "unrecognized field label \"%s\" line %d\n", l, NR > "/dev/stderr"; ok = 0; next
        }
        cnt[l]++
        if (exact[l] != "" && $0 != "- " l ": " exact[l]) {
            printf "non-template value for \"%s\" line %d\n", l, NR > "/dev/stderr"; ok = 0
        }
    }
    END {
        if (insec) checksec()
        if (secs != 15) {
            print "expected exactly fifteen experiment sections QK-F2E-001..015, found " secs > "/dev/stderr"
            ok = 0
        }
        exit ok ? 0 : 1
    }
' "$TMP/reg" || fail "experiment register discipline violation: $REGISTER"

# ---- evidence register: schema only, zero rows (both modes) -----------------

readf "$EVIDENCE" "$TMP/ev"
awk '
    BEGIN {
        ok = 1; empty = 0; feas = 0; rows = 0; assocempty = 0
        # closed table grammar: every "|" line must be one of these exact
        # header/separator lines or a schema-definition row whose first cell
        # is a known field label; exact expected occurrence counts.
        expct["|---|---|"] = 2
        expct["| Field | Notes for F2 use |"] = 1
        expct["| Evidence ID | Experiment ID |"] = 1
        nf = 0
        fld[++nf] = "Evidence ID";   fld[++nf] = "Claim"
        fld[++nf] = "Evidence level"; fld[++nf] = "Source commit"
        fld[++nf] = "Specification version"; fld[++nf] = "Planned test ID"
        fld[++nf] = "Environment";   fld[++nf] = "Toolchain/dependency identity"
        fld[++nf] = "Procedure";     fld[++nf] = "Raw artifacts"
        fld[++nf] = "Result";        fld[++nf] = "Reviewer"
        fld[++nf] = "Date";          fld[++nf] = "Limitations"
        fld[++nf] = "Affected gate"; fld[++nf] = "Gate-decision reference"
        for (i = 1; i <= nf; i++) isfld[fld[i]] = 1
    }
    /^\| QK-F2V-/ { print "populated evidence row line " NR > "/dev/stderr"; ok = 0 }
    /^\|/ {
        if ($0 in expct) { seen[$0]++ }
        else {
            cell = $0
            sub(/^\| */, "", cell); sub(/ *\|.*$/, "", cell)
            if (cell in isfld) { fseen[cell]++ }
            else { print "table row outside the closed evidence grammar, line " NR > "/dev/stderr"; ok = 0 }
        }
    }
    $0 == "NONE — no evidence exists; this association table is intentionally empty." { assocempty = NR }
    { if (index($0, "PASS") > 0 || index($0, "FAIL") > 0) { print "verdict vocabulary line " NR > "/dev/stderr"; ok = 0 } }
    /^## Rows$/ { if (rows) { print "duplicate ## Rows section line " NR > "/dev/stderr"; ok = 0 }; rows = NR; next }
    rows && $0 == "NONE — no experiment has been run; this register is intentionally empty." {
        if (empty) { print "duplicate empty-state line " NR > "/dev/stderr"; ok = 0 }
        empty = NR; next
    }
    rows && $0 != "" {
        # after ## Rows, ONLY blank lines and the exact empty-state line may exist
        print "unexpected content after ## Rows, line " NR > "/dev/stderr"
        ok = 0
    }
    index($0, "| Planned test ID |") == 1 {
        if (index($0, "NONE — F2 FEASIBILITY ONLY") > 0) feas = 1
        if (index($0, "QK-F2E") > 0) {
            print "Planned test ID field must never carry F2 experiment identifiers, line " NR > "/dev/stderr"
            ok = 0
        }
    }
    END {
        if (!rows)  { print "missing ## Rows section" > "/dev/stderr"; ok = 0 }
        if (!empty || empty < rows) { print "missing exact empty-state line under ## Rows" > "/dev/stderr"; ok = 0 }
        if (!feas)  { print "Planned test ID schema row must define the exact NONE — F2 FEASIBILITY ONLY marker" > "/dev/stderr"; ok = 0 }
        if (!assocempty || assocempty > rows) { print "missing exact association-table empty-state line before ## Rows" > "/dev/stderr"; ok = 0 }
        for (l in expct) if (seen[l] != expct[l]) { print "expected " expct[l] " occurrence(s) of table line: " l > "/dev/stderr"; ok = 0 }
        for (i = 1; i <= nf; i++) if (fseen[fld[i]] != 1) { print "schema field row must appear exactly once: " fld[i] > "/dev/stderr"; ok = 0 }
        exit ok ? 0 : 1
    }
' "$TMP/ev" || fail "evidence register must be schema-only with the exact empty state: $EVIDENCE"

# ---- decision inputs: placeholders only (both modes) ------------------------

readf "$DECINPUT" "$TMP/di"
awk '
    BEGIN {
        ok = 1; man = 0; sec = ""
        # exact required experiment-row set per decision section
        want["OD-01"] = "001 002"
        want["OD-02"] = "003 004 005 011 012 013 014"
        want["OD-05"] = "006 007 009 015"
        want["OD-06"] = "008"
    }
    { if (index($0, "Measurement authorizes nothing") > 0) man = 1 }
    /^## OD-0[0-9] / {
        sec = substr($0, 4, 5)
        seen[sec] = ""
        next
    }
    /^## / { sec = "" }
    /^\|/ {
        # the ONLY table lines permitted anywhere in this document:
        if ($0 == "| Experiment | Input placeholder |") next
        if ($0 == "|---|---|") next
        if ($0 ~ /^\| QK-F2E-0(0[1-9]|1[0-5]) \| OPEN — NO EVIDENCE EXISTS \|$/) {
            if (sec == "" || !(sec in want)) {
                print "experiment row outside a mapped OD section, line " NR > "/dev/stderr"
                ok = 0
            } else {
                seen[sec] = seen[sec] (seen[sec] == "" ? "" : " ") substr($0, 10, 3)
            }
            next
        }
        print "populated or malformed table row line " NR > "/dev/stderr"
        ok = 0
    }
    END {
        for (s in want) {
            if (!(s in seen)) { print "missing section " s > "/dev/stderr"; ok = 0 }
            else if (seen[s] != want[s]) {
                print "section " s " row set is [" seen[s] "], required exactly [" want[s] "]" > "/dev/stderr"
                ok = 0
            }
        }
        exit (man && ok) ? 0 : 1
    }
' "$TMP/di" || fail "decision-inputs document must carry exactly the required OD-01/OD-02/OD-05/OD-06 open-placeholder row sets and state that measurement authorizes nothing: $DECINPUT"

# QK-F2E-004 must retain the mathematical-verification condition verbatim.
readf "$REGISTER" "$TMP/reg004"
awk '
    BEGIN { insec = 0; found = 0 }
    /^### QK-F2E-004/ { insec = 1 }
    insec && /^### QK-F2E-005/ { insec = 0 }
    insec && index($0, "verify each returned signature mathematically — ECDSA verification against the expected public key and message") > 0 { found = 1 }
    END { exit found ? 0 : 1 }
' "$TMP/reg004" || fail "QK-F2E-004 must state mathematical ECDSA verification as the correctness method: $REGISTER"

# ---- success -----------------------------------------------------------------

printf 'F2 STRUCTURAL PREPARATION CHECK: PASS\n'
exit 0
