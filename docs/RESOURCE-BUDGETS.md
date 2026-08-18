# QuietKey Resource-Budget Registry

**DRAFT — PENDING PROJECT-OWNER APPROVAL — NON-AUTHORITATIVE UNTIL CORRECTED F0 ARCHITECTURE IS APPROVED**

EXPERIMENTAL — NO REAL FUNDS — NOT A WALLET

Rule (non-normative restatement): every hostile-input path must have a hard approved bound before its parser is implemented. The normative statements of this rule are the uniquely identified bound requirements in `docs/REQUIREMENTS.md`: QK-REQ-A1-006, QK-REQ-CARD-004, QK-REQ-PSBT-005, QK-REQ-TRN-005, QK-REQ-TRN-006, QK-REQ-TUI-003, QK-REQ-PLT-006, and QK-REQ-ASR-005. This registry defines the dimensions those requirements bind; it introduces no normative language of its own.

This registry defines the dimensions that require limits. It deliberately contains **no numeric values, no examples, no defaults, no candidate values, and no recommendations**. Every value cell is exactly `OPEN — TBD AFTER F2 TARGET MEASUREMENT`. Device-dependent rows cite the governing open decision (OD-02 exact card, OD-04 A1 physical codec, OD-05 transport ceilings and review layout, OD-06 boot/update).

Freeze evidence required for **every** row before its value may be approved: representative and adversarial corpora; measured peak RAM and stack on the exact target; worst-case CPU/time; camera/display usability where applicable; documented safety margin; defined rejection UX; versioning of the limit; explicit owner review and decision-log entry. Values are frozen only by owner decision — never by measurement alone.

## PSBT

| ID | Dimension | Value | Open decision |
|---|---|---|---|
| QK-LIM-PSBT-001 | Total serialized PSBT size | OPEN — TBD AFTER F2 TARGET MEASUREMENT | OD-05 |
| QK-LIM-PSBT-002 | Global map: key/value lengths and entry count | OPEN — TBD AFTER F2 TARGET MEASUREMENT | OD-05 |
| QK-LIM-PSBT-003 | Input count and per-input map key/value lengths and entry counts | OPEN — TBD AFTER F2 TARGET MEASUREMENT | OD-05 |
| QK-LIM-PSBT-004 | Output count and per-output map key/value lengths and entry counts | OPEN — TBD AFTER F2 TARGET MEASUREMENT | OD-05 |
| QK-LIM-PSBT-005 | Script lengths (witness scripts, scriptPubKeys) | OPEN — TBD AFTER F2 TARGET MEASUREMENT | OD-05 |
| QK-LIM-PSBT-006 | Derivation path depth and origin entry count | OPEN — TBD AFTER F2 TARGET MEASUREMENT | OD-05 |

## QR

| ID | Dimension | Value | Open decision |
|---|---|---|---|
| QK-LIM-QR-001 | Total decoded payload bytes per transfer | OPEN — TBD AFTER F2 TARGET MEASUREMENT | OD-05 |
| QK-LIM-QR-002 | Frame count per BBQr transfer | OPEN — TBD AFTER F2 TARGET MEASUREMENT | OD-05 |
| QK-LIM-QR-003 | Per-frame payload size | OPEN — TBD AFTER F2 TARGET MEASUREMENT | OD-05 |
| QK-LIM-QR-004 | Scan session time and per-frame decode time | OPEN — TBD AFTER F2 TARGET MEASUREMENT | OD-05 |
| QK-LIM-QR-005 | Duplicate-frame handling and reassembly buffer occupancy | OPEN — TBD AFTER F2 TARGET MEASUREMENT | OD-05 |

## SD

| ID | Dimension | Value | Open decision |
|---|---|---|---|
| QK-LIM-SD-001 | Accepted `.psbt` file size | OPEN — TBD AFTER F2 TARGET MEASUREMENT | OD-05 |
| QK-LIM-SD-002 | File/directory entries examined during intake | OPEN — TBD AFTER F2 TARGET MEASUREMENT | OD-05 |
| QK-LIM-SD-003 | Filesystem metadata parsing work (reads, traversal depth, time) | OPEN — TBD AFTER F2 TARGET MEASUREMENT | OD-05 |

## A1 / OCR

| ID | Dimension | Value | Open decision |
|---|---|---|---|
| QK-LIM-A1-001 | OCR candidate count per capture and per session | OPEN — TBD AFTER F2 TARGET MEASUREMENT | OD-04 |
| QK-LIM-A1-002 | Error-correction work per candidate (symbols corrected, iterations, time) | OPEN — TBD AFTER F2 TARGET MEASUREMENT | OD-04 |
| QK-LIM-A1-003 | Decode/authentication attempts per session | OPEN — TBD AFTER F2 TARGET MEASUREMENT | OD-04 |

## APDU / card

| ID | Dimension | Value | Open decision |
|---|---|---|---|
| QK-LIM-APDU-001 | Command and response sizes | OPEN — TBD AFTER F2 TARGET MEASUREMENT | OD-02 |
| QK-LIM-APDU-002 | Exchange sequence length per operation and per session | OPEN — TBD AFTER F2 TARGET MEASUREMENT | OD-02 |
| QK-LIM-APDU-003 | Session count, retries, and inter-exchange timeouts | OPEN — TBD AFTER F2 TARGET MEASUREMENT | OD-02 |

## Trusted review UI

| ID | Dimension | Value | Open decision |
|---|---|---|---|
| QK-LIM-TUI-001 | Review page count per transaction | OPEN — TBD AFTER F2 TARGET MEASUREMENT | OD-05 |
| QK-LIM-TUI-002 | Items and rendered content per review page | OPEN — TBD AFTER F2 TARGET MEASUREMENT | OD-05 |
| QK-LIM-TUI-003 | Review and confirmation timeouts | OPEN — TBD AFTER F2 TARGET MEASUREMENT | OD-05 |

## Core IPC

| ID | Dimension | Value | Open decision |
|---|---|---|---|
| QK-LIM-IPC-001 | Message size between `qk-io` and `qk-core` | OPEN — TBD AFTER F2 TARGET MEASUREMENT | OD-05 |
| QK-LIM-IPC-002 | Message rate and queue depth | OPEN — TBD AFTER F2 TARGET MEASUREMENT | OD-05 |

## Memory

| ID | Dimension | Value | Open decision |
|---|---|---|---|
| QK-LIM-MEM-001 | Heap ceiling per process (`qk-core`, `qk-io`) | OPEN — TBD AFTER F2 TARGET MEASUREMENT | OD-06 |
| QK-LIM-MEM-002 | Stack ceiling per process and per parsing stage | OPEN — TBD AFTER F2 TARGET MEASUREMENT | OD-06 |
| QK-LIM-MEM-003 | Secret arena size and residency | OPEN — TBD AFTER F2 TARGET MEASUREMENT | OD-06 |
| QK-LIM-MEM-004 | Parser arena size per hostile-input path | OPEN — TBD AFTER F2 TARGET MEASUREMENT | OD-06 |

## Execution and cleanup

| ID | Dimension | Value | Open decision |
|---|---|---|---|
| QK-LIM-EXE-001 | Per-stage execution time for each hostile-input path (parse, validate, review construction) | OPEN — TBD AFTER F2 TARGET MEASUREMENT | OD-05 |
| QK-LIM-EXE-002 | Cleanup/zeroization completion time at session end, cancellation, failure, and shutdown | OPEN — TBD AFTER F2 TARGET MEASUREMENT | OD-06 |

## Registry rules (non-normative summary)

- 31 rows. No row may be implemented against until its value is owner-approved.
- A frozen value change requires a new version of the row, fresh freeze evidence, and a new owner decision.
- Rejection of over-limit input must be fail-closed and user-visible (QK-REQ-HF-003).
