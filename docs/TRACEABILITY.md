# QuietKey Traceability Matrix

**OWNER-APPROVED F1 BASELINE — IMPLEMENTATION EVIDENCE NONE — ALL GATES OPEN**

EXPERIMENTAL — NO REAL FUNDS — NOT A WALLET

This matrix links every requirement (`docs/REQUIREMENTS.md`) to its source decision (`ARCHITECTURE.md`), threats (`docs/THREAT-MODEL.md`), resource limits (`docs/RESOURCE-BUDGETS.md`), planned tests (`docs/TEST-ARCHITECTURE.md`), and gate. It records traceability of DRAFT plans only — no threat is mitigated, resolved, or validated, and no evidence exists. The matrix below was regenerated mechanically from the register tables during the F1 semantic audit-correction pass. Regeneration is a derivation step, not validation, and constitutes no evidence of anything; consistency between this file and the registers is re-checkable at any time with the procedure at the end (structural parts automated by `tools/verify-foundation.sh`).

**Prefix convention (applies to every table in this document):** cell entries are full IDs with the family prefix removed for legibility. Reconstruct full IDs as follows: forward-matrix column 1 and all requirement references → prepend `QK-REQ-`; decision cells → prepend `QK-DEC-`; threat cells → prepend `QK-THR-`; limit cells → prepend `QK-LIM-`; test cells → prepend `QK-TST-`. Numeric-only entries (e.g. `009`) take the prefix directly (`QK-THR-009`); entries with a domain (e.g. `PSBT-005`) likewise (`QK-LIM-PSBT-005` in a limit cell). Checks must reconstruct full IDs this way before comparing against the defining registers.

## Forward matrix (100 requirements)

| QK-REQ | QK-DEC | QK-THR | QK-LIM | QK-TST | Gate |
|---|---|---|---|---|---|
| CUS-001 | 002, 003 | 005 | NONE | DIFF-003, REH-001 | C |
| CUS-002 | 002, 007 | 003, 004, 015 | NONE | PROP-004, AUD-004 | B |
| CUS-003 | 002 | 002, 003, 008 | NONE | PROP-003, AUD-001 | C |
| CUS-004 | 003 | 003, 020 | NONE | UNIT-002 | FOUNDATION |
| CUS-005 | 003 | 012 | NONE | DIFF-003, UNIT-003 | C |
| CUS-006 | 003 | 006, 017 | NONE | UNIT-002, DIFF-003 | C |
| CUS-007 | 011 | 012, 020 | NONE | DIFF-003, AUD-001 | FOUNDATION |
| CUS-008 | 005 | 005 | NONE | AUD-008 | FOUNDATION |
| CUS-009 | 005 | 005 | NONE | AUD-008, HF-003 | FOUNDATION |
| ENT-001 | 007 | 004, 015 | NONE | PROP-004, AUD-004 | B |
| ENT-002 | 007 | 004, 015 | NONE | PROP-004 | C |
| ENT-003 | 007 | 012, 015 | NONE | UNIT-004, HF-003 | C |
| ENT-004 | 007 | 009, 015 | NONE | AUD-004 | C |
| ENT-005 | 007 | 012, 015 | NONE | AUD-004 | FOUNDATION |
| ENT-006 | 007 | 015 | NONE | PROP-004, AUD-004 | C |
| ENT-007 | 007 | 015 | NONE | AUD-004 | C |
| ENT-008 | 007 | 015 | NONE | AUD-004, DIFF-001 | C |
| ENT-009 | 007 | 015 | NONE | AUD-004 | C |
| ENT-010 | 007 | 015 | NONE | UNIT-004, AUD-009 | C |
| ENT-011 | 007 | 015 | NONE | AUD-009 | FOUNDATION |
| ENT-012 | 007 | 015, 018 | NONE | AUD-009, HF-003 | E |
| A1-001 | 008 | 002, 021 | NONE | UNIT-001, DIFF-001 | A |
| A1-002 | 008 | 002, 015 | NONE | UNIT-001, AUD-001 | A |
| A1-003 | 008 | 002, 006 | NONE | PROP-001, CORP-004 | A |
| A1-004 | 008 | 006, 017 | NONE | UNIT-001, CORP-004 | A |
| A1-005 | 008 | 011 | NONE | CORP-004, BENCH-004 | A |
| A1-006 | 008, 009 | 006, 016 | A1-001, A1-002, A1-003, A1-004, A1-005, A1-006, A1-007, A1-008, A1-009, A1-010, A1-011, A1-012, A1-013, A1-014 | FUZZ-005, BENCH-003 | A |
| A1-007 | 004, 008 | 014 | NONE | AUD-006, HF-001 | A |
| A1-008 | 004 | 014 | NONE | AUD-006 | FOUNDATION |
| A1-009 | 008 | 011, 012, 019 | NONE | REH-006, PWR-001 | A |
| A1-010 | 004, 008 | 002, 018 | NONE | AUD-006, CORP-004 | A |
| A1-011 | 004, 008 | 018 | NONE | AUD-006 | FOUNDATION |
| CARD-001 | 006 | 003, 008, 018, 021 | NONE | BENCH-002, AUD-003 | B |
| CARD-002 | 006 | 001, 014 | NONE | REH-001, AUD-003 | B |
| CARD-003 | 006 | 003, 017 | NONE | UNIT-007, BENCH-002 | B |
| CARD-004 | 009 | 006, 016 | APDU-001, APDU-002, APDU-003, APDU-004, APDU-005, APDU-006, APDU-007, APDU-008, APDU-009, APDU-010, APDU-011 | FUZZ-004, CORP-005 | B |
| CARD-005 | 006 | 001, 011, 019 | NONE | PWR-002, BENCH-002 | B |
| CARD-006 | 006 | 001 | NONE | REH-004, BENCH-005 | B |
| CARD-007 | 004, 006 | 014 | NONE | AUD-006, BENCH-002 | B |
| CARD-008 | 006 | 019 | NONE | UNIT-007, BENCH-002 | B |
| CARD-009 | 006 | 017, 019 | NONE | UNIT-007, CORP-005 | B |
| CARD-010 | 006 | 019 | NONE | PWR-002 | B |
| PSBT-001 | 009 | 006, 016 | PSBT-001 | UNIT-005, CORP-001 | C |
| PSBT-002 | 009, 010 | 006, 016 | PSBT-001, PSBT-002, PSBT-003, PSBT-004, PSBT-009, PSBT-010, PSBT-012, PSBT-013 | PROP-002, FUZZ-001 | C |
| PSBT-003 | 009 | 006, 007 | NONE | PROP-002, REH-001 | C |
| PSBT-004 | 009 | 006 | NONE | DIFF-002, REH-004 | C |
| PSBT-005 | 009 | 006, 016 | PSBT-001, PSBT-002, PSBT-003, PSBT-004, PSBT-005, PSBT-006, PSBT-007, PSBT-008, PSBT-009, PSBT-010, PSBT-011, PSBT-012, PSBT-013, PSBT-014, PSBT-015, PSBT-016, PSBT-017, PSBT-018, PSBT-019, PSBT-020, PSBT-021, PSBT-022, PSBT-023, PSBT-024, PSBT-025, PSBT-026, PSBT-027 | FUZZ-001, BENCH-003 | C |
| PSBT-006 | 009 | 006, 017 | PSBT-001 | CORP-001, DIFF-002 | C |
| PSBT-007 | 009 | 016 | NONE | PROP-007, FUZZ-001 | C |
| PSBT-008 | 003, 009 | 016 | NONE | PROP-007, CORP-001 | C |
| TRN-001 | 009 | 006, 016 | SD-001, SD-002 | UNIT-009, CORP-003 | C |
| TRN-002 | 009 | 011, 019 | NONE | UNIT-009, PWR-003 | D |
| TRN-003 | 009 | 006, 016 | QR-001, QR-003, QR-006 | UNIT-006, BENCH-001 | A |
| TRN-004 | 009, 010 | 006 | NONE | SAN-003, AUD-001 | C |
| TRN-005 | 009 | 006, 016 | QR-001, QR-002, QR-003, QR-004, QR-005, QR-006, QR-007, QR-008, QR-009, QR-010, QR-011, QR-012, QR-013, QR-014 | FUZZ-002, CORP-002 | A |
| TRN-006 | 009 | 006, 016 | SD-001, SD-002, SD-003, SD-005, SD-006, SD-007, SD-008, SD-009, SD-010 | FUZZ-003, BENCH-003 | C |
| TRN-007 | 009 | 006 | SD-004, PSBT-026, PSBT-027 | DIFF-004, REH-004 | C |
| TRN-008 | 009 | 019 | SD-011, SD-012, SD-013 | PWR-005, CORP-003 | D |
| TRN-009 | 009, 010 | 016 | NONE | SAN-004, AUD-001 | D |
| TRN-010 | 009, 010 | 016 | SD-003, SD-008, SD-009 | SAN-004, FUZZ-003 | D |
| TUI-001 | 010 | 007 | NONE | UNIT-013, AUD-001 | C |
| TUI-002 | 009, 010 | 006, 017 | NONE | PROP-002, HF-002 | C |
| TUI-003 | 009 | 012, 016 | TUI-001, TUI-002, TUI-003, TUI-004, TUI-005, TUI-006, TUI-007, TUI-008, TUI-009 | HF-002, BENCH-003 | C |
| TUI-004 | 006 | 007 | NONE | AUD-001 | FOUNDATION |
| PLT-001 | 004, 006 | 001, 014, 018 | NONE | PROP-005, SAN-003, PWR-004 | C |
| PLT-002 | 010 | 007 | NONE | UNIT-013 | C |
| PLT-003 | 010 | 006, 018 | NONE | SAN-003, AUD-001 | C |
| PLT-004 | 010 | 006, 008, 018 | EXE-002 | UNIT-010, SAN-003 | C |
| PLT-005 | 010 | 006, 014, 018 | NONE | SAN-003, CORP-006 | C |
| PLT-006 | 009, 010 | 006, 016 | MEM-001, MEM-002, MEM-003, MEM-004, MEM-005, MEM-006, MEM-007, MEM-008, MEM-009, MEM-010, MEM-011, MEM-012, MEM-013, MEM-014, MEM-015, MEM-016, MEM-017, MEM-018, IPC-001, IPC-002, IPC-003, IPC-004, IPC-005, IPC-006, EXE-001, EXE-002, EXE-003, EXE-004, EXE-005, EXE-006, EXE-007 | BENCH-003, SAN-001 | C |
| PLT-007 | 004, 010 | 014 | NONE | AUD-006, UNIT-007 | C |
| PLT-008 | 004, 006 | 009, 018 | NONE | AUD-007 | C |
| PLT-009 | 010 | 006, 016 | NONE | SAN-003, AUD-001 | C |
| PLT-010 | 009, 010 | 006, 017 | DSC-001, DSC-002 | PROP-002, FUZZ-001 | C |
| PLT-011 | 010 | 016 | NONE | FUZZ-004, AUD-001 | C |
| PLT-012 | 010 | 009 | NONE | AUD-001 | FOUNDATION |
| BND-001 | 002, 003 | 017 | NONE | UNIT-011, CORP-006 | C |
| BND-002 | 009, 010 | 017 | NONE | PROP-006, PROP-002 | C |
| BND-003 | 009, 010 | 017, 019 | NONE | PROP-006, PWR-004 | C |
| REC-001 | 005 | 001, 020 | NONE | REH-001 | E |
| REC-002 | 005 | 003, 004 | NONE | REH-003 | E |
| REC-003 | 005 | 004 | NONE | REH-003, UNIT-008 | E |
| REC-004 | 005, 006 | 001 | NONE | REH-002 | E |
| REC-005 | 006, 009 | 011, 012, 019 | NONE | PWR-001, CORP-006 | D |
| REC-006 | 003, 005 | 001, 020 | NONE | REH-001, REH-004 | E |
| REC-007 | 005 | 021 | NONE | REH-003 | E |
| HF-001 | 001, 007 | 012 | NONE | UNIT-004, HF-003 | E |
| HF-002 | 001 | 012, 020 | NONE | HF-001 | A |
| HF-003 | 001, 009 | 006, 012, 016 | PSBT-001, QR-001, SD-001, A1-001, APDU-001 | CORP-001, HF-002 | C |
| HF-004 | 001 | 012 | NONE | AUD-001 | FOUNDATION |
| ASR-001 | 014, 012 | 013, 014 | NONE | AUD-001 | FOUNDATION |
| ASR-002 | 014 | 009 | NONE | AUD-002, SAN-002, REH-001 | FOUNDATION |
| ASR-003 | 014 | 012 | NONE | AUD-002 | FOUNDATION |
| ASR-004 | 013 | 009 | NONE | AUD-002 | FOUNDATION |
| ASR-005 | 014 | 006, 016 | PSBT-001, QR-001, SD-001, A1-001, APDU-001 | FUZZ-001, FUZZ-002, FUZZ-003, FUZZ-004, FUZZ-005 | C |
| ASR-006 | 012 | 013 | NONE | AUD-001 | FOUNDATION |
| ASR-007 | 014 | 009 | NONE | AUD-002 | FOUNDATION |
| ASR-008 | 014 | 009, 012 | NONE | AUD-005 | FOUNDATION |
| ASR-009 | 004, 014 | 014 | NONE | AUD-001, AUD-006 | FOUNDATION |
| ASR-010 | 012 | 013 | NONE | REH-005, AUD-002 | FOUNDATION |

## Reverse coverage — decisions (14/14 cited by at least one requirement)

| QK-DEC | Covered by (QK-REQ-) |
|---|---|
| 001 | HF-001, HF-002, HF-003, HF-004 |
| 002 | CUS-001, CUS-002, CUS-003, BND-001 |
| 003 | CUS-001, CUS-004, CUS-005, CUS-006, PSBT-008, BND-001, REC-006 |
| 004 | A1-007, A1-008, A1-010, A1-011, CARD-007, PLT-001, PLT-007, PLT-008, ASR-009 |
| 005 | CUS-008, CUS-009, REC-001, REC-002, REC-003, REC-004, REC-006, REC-007 |
| 006 | CARD-001, CARD-002, CARD-003, CARD-005, CARD-006, CARD-007, CARD-008, CARD-009, CARD-010, TUI-004, PLT-001, PLT-008, REC-004, REC-005 |
| 007 | CUS-002, ENT-001, ENT-002, ENT-003, ENT-004, ENT-005, ENT-006, ENT-007, ENT-008, ENT-009, ENT-010, ENT-011, ENT-012, HF-001 |
| 008 | A1-001, A1-002, A1-003, A1-004, A1-005, A1-006, A1-007, A1-009, A1-010, A1-011 |
| 009 | A1-006, CARD-004, PSBT-001, PSBT-002, PSBT-003, PSBT-004, PSBT-005, PSBT-006, PSBT-007, PSBT-008, TRN-001, TRN-002, TRN-003, TRN-004, TRN-005, TRN-006, TRN-007, TRN-008, TRN-009, TRN-010, TUI-002, TUI-003, PLT-006, PLT-010, BND-002, BND-003, REC-005, HF-003 |
| 010 | PSBT-002, TRN-004, TRN-009, TRN-010, TUI-001, TUI-002, PLT-002, PLT-003, PLT-004, PLT-005, PLT-006, PLT-007, PLT-009, PLT-010, PLT-011, PLT-012, BND-002, BND-003 |
| 011 | CUS-007 |
| 012 | ASR-001, ASR-006, ASR-010 |
| 013 | ASR-004 |
| 014 | ASR-001, ASR-002, ASR-003, ASR-005, ASR-007, ASR-008, ASR-009 |

Note: QK-DEC-011's packaging-invariance obligation is carried normatively by QK-REQ-CUS-007.

## Reverse coverage — threats (20 of 21 covered; QK-THR-010 explicitly excluded)

| QK-THR | Covered by (QK-REQ-) or explicit exclusion |
|---|---|
| 001 | CARD-002, CARD-005, CARD-006, PLT-001, REC-001, REC-004, REC-006 |
| 002 | CUS-003, A1-001, A1-002, A1-003, A1-010 |
| 003 | CUS-002, CUS-003, CUS-004, CARD-001, CARD-003, REC-002 |
| 004 | CUS-002, ENT-001, ENT-002, REC-002, REC-003 |
| 005 | CUS-001, CUS-008, CUS-009. Residual: theft of a valid pair remains the accepted 2-of-3 design boundary (THREAT-MODEL Non-goals); the cited requirements govern storage separation and ceremony co-presence, not pair theft itself. |
| 006 | CUS-006, A1-003, A1-004, A1-006, CARD-004, PSBT-001, PSBT-002, PSBT-003, PSBT-004, PSBT-005, PSBT-006, TRN-001, TRN-003, TRN-004, TRN-005, TRN-006, TRN-007, TUI-002, PLT-003, PLT-004, PLT-005, PLT-006, PLT-009, PLT-010, HF-003, ASR-005 |
| 007 | PSBT-003, TUI-001, TUI-004, PLT-002 |
| 008 | CUS-003, CARD-001, PLT-004 |
| 009 | ENT-004, PLT-008, PLT-012, ASR-002, ASR-004, ASR-007, ASR-008 |
| 010 | **Explicit exclusion**: coercion with access to a valid pair is a stated non-goal (THREAT-MODEL Non-goals); the cloak may reduce targeting but no requirement claims protection once coercion begins. No normative control exists or is planned. |
| 011 | A1-005, A1-009, CARD-005, TRN-002, REC-005 |
| 012 | CUS-005, CUS-007, ENT-003, ENT-005, A1-009, TUI-003, REC-005, HF-001, HF-002, HF-003, HF-004, ASR-003, ASR-008 |
| 013 | ASR-001, ASR-006, ASR-010 |
| 014 | A1-007, A1-008, CARD-002, CARD-007, PLT-001, PLT-005, PLT-007, ASR-001, ASR-009 |
| 015 | CUS-002, ENT-001, ENT-002, ENT-003, ENT-004, ENT-005, ENT-006, ENT-007, ENT-008, ENT-009, ENT-010, ENT-011, ENT-012, A1-002 |
| 016 | A1-006, CARD-004, PSBT-001, PSBT-002, PSBT-005, PSBT-007, PSBT-008, TRN-001, TRN-003, TRN-005, TRN-006, TRN-009, TRN-010, TUI-003, PLT-006, PLT-009, PLT-011, HF-003, ASR-005 |
| 017 | CUS-006, A1-004, CARD-003, CARD-009, PSBT-006, TUI-002, PLT-010, BND-001, BND-002, BND-003 |
| 018 | ENT-012, A1-010, A1-011, CARD-001, PLT-001, PLT-003, PLT-004, PLT-005, PLT-008 |
| 019 | A1-009, CARD-005, CARD-008, CARD-009, CARD-010, TRN-002, TRN-008, BND-003, REC-005 |
| 020 | CUS-004, CUS-007, REC-001, REC-006, HF-002 |
| 021 | A1-001, CARD-001, REC-007 |

QK-THR-015…020 are append-only precision refinements added in the F1 audit-correction pass, and QK-THR-021 was appended in the F1 semantic audit-correction pass; their coverage restates or extends coverage of the broad threats they refine.

## Reverse coverage — limits and planned tests (mechanically derived)

- All 121 QK-LIM rows defined in `docs/RESOURCE-BUDGETS.md` are cited by at least one requirement (121/121 as derived; re-check with the procedure below).
- All 66 QK-TST IDs defined in `docs/TEST-ARCHITECTURE.md` are cited by at least one requirement (66/66 as derived; re-check with the procedure below).
- Every limit and test ID cited by a requirement exists in its defining register (no dangling citations as derived; re-check with the procedure below).

## Orphan check

As derived at regeneration (re-checkable, not evidence): every SHALL/SHALL NOT normative statement in the F1 document set lives in exactly one `docs/REQUIREMENTS.md` row with a QK-DEC source, threat citation, limit citation (or NONE with rationale), planned tests, and gate; the other F1 documents (this file, LIFECYCLE-STATES, RESOURCE-BUDGETS, TEST-ARCHITECTURE) contain no free-standing SHALL/SHALL NOT claims, only non-normative restatements by requirement ID.

Check procedure (repeatable; `tools/verify-foundation.sh` automates the structural parts):

1. Extract all `QK-REQ-` IDs from `docs/REQUIREMENTS.md`; confirm the same set appears in the forward matrix (no additions, no omissions), reconstructing full IDs per the prefix convention above.
2. Confirm each requirement row contains exactly one SHALL or SHALL NOT, and grep the other four F1 documents for the whole words SHALL / SHALL NOT — every hit must be either absent or a quoted reference to register phrasing, never a free-standing normative claim.
3. Confirm every `QK-DEC-001…014` appears in the decision reverse table; every `QK-THR-001…021` appears in the threat reverse table as covered or explicitly excluded.
4. Confirm every `QK-LIM-` and `QK-TST-` ID defined in its register is cited by at least one requirement, and every cited ID exists in its register.
5. Confirm ID uniqueness across all families (sort/uniq, zero duplicates), that every requirement row has the expected Markdown field count with no unescaped table separators, that every resource-budget Value cell is exactly `OPEN — VALUE NOT AUTHORIZED IN F1` with Status exactly `OPEN`, and that every planned-test Status cell is exactly `PLANNED — NOT RUN`.
