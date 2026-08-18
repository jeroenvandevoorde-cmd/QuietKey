# QuietKey Traceability Matrix

**DRAFT — PENDING PROJECT-OWNER APPROVAL — NON-AUTHORITATIVE UNTIL CORRECTED F0 ARCHITECTURE IS APPROVED**

EXPERIMENTAL — NO REAL FUNDS — NOT A WALLET

This matrix links every requirement (`docs/REQUIREMENTS.md`) to its source decision (`ARCHITECTURE.md`), threats (`docs/THREAT-MODEL.md`), resource limits (`docs/RESOURCE-BUDGETS.md`), planned tests (`docs/TEST-ARCHITECTURE.md`), and gate. It records traceability of DRAFT plans only — no threat is mitigated, resolved, or validated, and no evidence exists.

## Forward matrix

| QK-REQ | QK-DEC | QK-THR | QK-LIM | QK-TST | Gate |
|---|---|---|---|---|---|
| CUS-001 | 002, 003 | 005 | NONE | DIFF-003, REH-001 | C |
| CUS-002 | 002, 007 | 003, 004 | NONE | PROP-004, AUD-004 | B |
| CUS-003 | 002 | 002, 003, 008 | NONE | PROP-003, AUD-001 | C |
| CUS-004 | 003 | 003 | NONE | UNIT-002 | FOUNDATION |
| CUS-005 | 003 | 012 | NONE | DIFF-003, UNIT-003 | C |
| CUS-006 | 003 | 006 | NONE | UNIT-002, DIFF-003 | C |
| ENT-001 | 007 | 004 | NONE | PROP-004, AUD-004 | B |
| ENT-002 | 007 | 004 | NONE | PROP-004 | C |
| ENT-003 | 007 | 012 | NONE | UNIT-004, HF-003 | C |
| ENT-004 | 007 | 009 | NONE | AUD-004 | C |
| ENT-005 | 007 | 012 | NONE | AUD-004 | FOUNDATION |
| A1-001 | 008 | 002 | NONE | UNIT-001, DIFF-001 | A |
| A1-002 | 008 | 002 | NONE | UNIT-001, AUD-001 | A |
| A1-003 | 008 | 002, 006 | NONE | PROP-001, CORP-004 | A |
| A1-004 | 008 | 006 | NONE | UNIT-001, CORP-004 | A |
| A1-005 | 008 | 011 | NONE | CORP-004, BENCH-004 | A |
| A1-006 | 008, 009 | 006 | A1-001…003 | FUZZ-005, BENCH-003 | A |
| CARD-001 | 006 | 003, 008 | NONE | BENCH-002, AUD-003 | B |
| CARD-002 | 006 | 001, 014 | NONE | REH-001, AUD-003 | B |
| CARD-003 | 006 | 003 | NONE | UNIT-007, BENCH-002 | B |
| CARD-004 | 009 | 006 | APDU-001…003 | FUZZ-004, CORP-005 | B |
| CARD-005 | 006 | 001, 011 | NONE | PWR-002, BENCH-002 | B |
| CARD-006 | 006 | 001 | NONE | REH-004 | B |
| PSBT-001 | 009 | 006 | PSBT-001 | UNIT-005, CORP-001 | C |
| PSBT-002 | 009, 010 | 006 | PSBT-001…004 | PROP-002, FUZZ-001 | C |
| PSBT-003 | 009 | 006, 007 | NONE | PROP-002, REH-001 | C |
| PSBT-004 | 009 | 006 | NONE | DIFF-002, REH-004 | C |
| PSBT-005 | 009 | 006 | PSBT-001…006 | FUZZ-001, BENCH-003 | C |
| PSBT-006 | 009 | 006 | PSBT-001 | CORP-001, DIFF-002 | C |
| TRN-001 | 009 | 006 | SD-001, SD-002 | UNIT-009, CORP-003 | C |
| TRN-002 | 009 | 011 | NONE | UNIT-009, PWR-003 | D |
| TRN-003 | 009 | 006 | QR-001, QR-003 | UNIT-006, BENCH-001 | A |
| TRN-004 | 009, 010 | 006 | NONE | SAN-003, AUD-001 | C |
| TRN-005 | 009 | 006 | QR-001…005 | FUZZ-002, CORP-002 | A |
| TRN-006 | 009 | 006 | SD-001…003 | FUZZ-003, BENCH-003 | C |
| TUI-001 | 010 | 007 | NONE | UNIT-007, AUD-001 | C |
| TUI-002 | 009, 010 | 006 | NONE | PROP-002, HF-002 | C |
| TUI-003 | 009 | 012 | TUI-001…003 | HF-002, BENCH-003 | C |
| TUI-004 | 006 | 007 | NONE | AUD-001 | FOUNDATION |
| PLT-001 | 004, 006 | 001, 014 | NONE | PROP-005, SAN-003, PWR-004 | C |
| PLT-002 | 010 | 007 | NONE | UNIT-007 | C |
| PLT-003 | 010 | 006 | NONE | SAN-003, AUD-001 | C |
| PLT-004 | 010 | 006, 008 | EXE-002 | UNIT-010, SAN-003 | C |
| PLT-005 | 010 | 006, 014 | NONE | SAN-003, CORP-006 | C |
| PLT-006 | 009, 010 | 006 | MEM-001…004, IPC-001…002, EXE-001…002 | BENCH-003, SAN-001 | C |
| REC-001 | 005 | 001 | NONE | REH-001 | E |
| REC-002 | 005 | 003, 004 | NONE | REH-003 | E |
| REC-003 | 005 | 004 | NONE | REH-003, UNIT-008 | E |
| REC-004 | 005, 006 | 001 | NONE | REH-002 | E |
| REC-005 | 006, 009 | 011, 012 | NONE | PWR-001, CORP-006 | D |
| REC-006 | 003, 005 | 001 | NONE | REH-001, REH-004 | E |
| HF-001 | 001, 007 | 012 | NONE | UNIT-004, HF-003 | E |
| HF-002 | 001 | 012 | NONE | HF-001 | A |
| HF-003 | 001, 009 | 006, 012 | PSBT-001, QR-001, SD-001, A1-001, APDU-001 (representative) | CORP-001, HF-002 | C |
| HF-004 | 001 | 012 | NONE | AUD-001 | FOUNDATION |
| ASR-001 | 014, 012 | 013, 014 | NONE | AUD-001 | FOUNDATION |
| ASR-002 | 014 | 009 | NONE | AUD-002, SAN-002, REH-001 | FOUNDATION |
| ASR-003 | 014 | 012 | NONE | AUD-002 | FOUNDATION |
| ASR-004 | 013 | 009 | NONE | AUD-002 | FOUNDATION |
| ASR-005 | 014 | 006 | PSBT-001, QR-001, SD-001, A1-001, APDU-001 (representative) | FUZZ-001…005 | C |
| ASR-006 | 012 | 013 | NONE | AUD-001 | FOUNDATION |
| ASR-007 | 014 | 009 | NONE | AUD-002 | FOUNDATION |
| ASR-008 | 014 | 009, 012 | NONE | AUD-005 | FOUNDATION |

(Prefixes `QK-REQ-`, `QK-DEC-0`, `QK-THR-0`, `QK-LIM-`, `QK-TST-` omitted from cells for legibility; full IDs appear in the source registers.)

## Reverse coverage — decisions

| QK-DEC | Covered by (QK-REQ-) |
|---|---|
| 001 | HF-001, HF-002, HF-003, HF-004 |
| 002 | CUS-001, CUS-002, CUS-003 |
| 003 | CUS-001, CUS-004, CUS-005, CUS-006, REC-006 |
| 004 | PLT-001 |
| 005 | CUS-001 (via 002/003 chain), REC-001, REC-002, REC-003, REC-004, REC-006 |
| 006 | CARD-001, CARD-002, CARD-003, CARD-005, CARD-006, TUI-004, PLT-001, REC-004, REC-005 |
| 007 | CUS-002, ENT-001, ENT-002, ENT-003, ENT-004, ENT-005, HF-001 |
| 008 | A1-001, A1-002, A1-003, A1-004, A1-005, A1-006 |
| 009 | A1-006, CARD-004, PSBT-001…006, TRN-001…006, TUI-002, TUI-003, PLT-006, REC-005, HF-003 |
| 010 | PSBT-002, TRN-004, TUI-001, TUI-002, PLT-002…006 |
| 011 | Constrains packaging only; normative content carried by CUS-001, CUS-002, CUS-005 (kits must not change threshold, keys, derivation, protocol, or recovery mathematics) |
| 012 | ASR-001, ASR-006 |
| 013 | ASR-004 |
| 014 | ASR-001, ASR-002, ASR-003, ASR-005, ASR-007, ASR-008 |

Coverage: 14/14.

## Reverse coverage — threats

| QK-THR | Covered by (QK-REQ-) or explicit exclusion |
|---|---|
| 001 | CARD-002, CARD-005, CARD-006, PLT-001, REC-001, REC-004, REC-006 |
| 002 | CUS-003, A1-001, A1-002, A1-003 |
| 003 | CUS-002, CUS-003, CUS-004, CARD-001, CARD-003, REC-002 |
| 004 | CUS-002, ENT-001, ENT-002, REC-002, REC-003 |
| 005 | CUS-001. Residual: theft of a valid pair is the accepted 2-of-3 design boundary (THREAT-MODEL Non-goals); storage separation per QK-DEC-005 is the selected posture, not a normative control. |
| 006 | CUS-006, A1-003, A1-004, A1-006, CARD-004, PSBT-001…006, TRN-001, TRN-003…006, TUI-002, PLT-003…006, HF-003, ASR-005 |
| 007 | PSBT-003, TUI-001, TUI-004, PLT-002 |
| 008 | CUS-003, CARD-001, PLT-004 |
| 009 | ENT-004, ASR-002, ASR-004, ASR-007, ASR-008 |
| 010 | **Explicit exclusion**: coercion with access to a valid pair is a stated non-goal (THREAT-MODEL Non-goals); the cloak may reduce targeting but no requirement claims protection once coercion begins. No normative control exists or is planned. |
| 011 | A1-005, CARD-005, TRN-002, REC-005 |
| 012 | CUS-005, ENT-003, ENT-005, TUI-003, REC-005, HF-001…004, ASR-003, ASR-008 |
| 013 | ASR-001, ASR-006 |
| 014 | CARD-002, PLT-001, PLT-005, ASR-001 |

Coverage: 13 threats covered by requirements; 1 (QK-THR-010) explicitly excluded with documented rationale. No unaddressed threat.

## Reverse coverage — limits and planned tests

- Every QK-LIM row (31 rows: PSBT-001…006, QR-001…005, SD-001…003, A1-001…003, APDU-001…003, TUI-001…003, IPC-001…002, MEM-001…004, EXE-001…002) is referenced by at least one requirement (see forward matrix rows A1-006, CARD-004, PSBT-001/002/005/006, TRN-001/003/005/006, TUI-003, PLT-004/006, HF-003, ASR-005).
- Every QK-TST ID (52 planned tests: UNIT-001…010, PROP-001…005, DIFF-001…003, FUZZ-001…005, SAN-001…003, CORP-001…006, BENCH-001…004, PWR-001…004, HF-001…003, REH-001…004, AUD-001…005) is referenced by at least one requirement in the forward matrix.

## Orphan check

Zero orphan normative statements: every SHALL/SHALL NOT in `docs/REQUIREMENTS.md` appears in the forward matrix with a QK-DEC source, threat citation, limit citation (or NONE with rationale), planned tests, and gate; no normative SHALL/SHALL NOT statement exists in any other F1 document (TRACEABILITY, LIFECYCLE-STATES, RESOURCE-BUDGETS, TEST-ARCHITECTURE restate register requirements by ID, using non-normative language, rather than introducing new normative claims).

Check procedure (repeatable):

1. Extract all `QK-REQ-` IDs from `docs/REQUIREMENTS.md`; confirm the same set appears in the forward matrix (no additions, no omissions).
2. Confirm each requirement row contains exactly one SHALL or SHALL NOT, and grep the other four F1 documents for the whole words SHALL / SHALL NOT — every hit must be either absent or a quoted reference to register phrasing, never a free-standing normative claim.
3. Confirm every `QK-DEC-001…014` appears in the decision reverse table; every `QK-THR-001…014` appears in the threat reverse table as covered or explicitly excluded.
4. Confirm every `QK-LIM-` and `QK-TST-` ID defined in its register is cited by at least one requirement, and every cited ID exists in its register.
5. Confirm ID uniqueness across all four families (sort/uniq, zero duplicates).
