# QuietKey Resource-Budget Registry

**DRAFT — PENDING PROJECT-OWNER APPROVAL — NON-AUTHORITATIVE UNTIL CORRECTED F0 ARCHITECTURE IS APPROVED**

EXPERIMENTAL — NO REAL FUNDS — NOT A WALLET

Rule (non-normative restatement): every hostile-input path must have a hard approved bound before its parser is implemented. The normative statements of this rule are the uniquely identified bound requirements in `docs/REQUIREMENTS.md`: QK-REQ-A1-006, QK-REQ-CARD-004, QK-REQ-PSBT-005, QK-REQ-TRN-005, QK-REQ-TRN-006, QK-REQ-TUI-003, QK-REQ-PLT-006, and QK-REQ-ASR-005. This registry defines the dimensions those requirements bind; it introduces no normative language of its own.

Every row is one atomic, individually auditable limit dimension. This registry deliberately contains **no numeric values, no examples, no defaults, no candidate values, and no recommendations**. Every Value cell is exactly `OPEN — TBD AFTER F2 TARGET MEASUREMENT` and every Status cell is exactly `OPEN`. Device-dependent rows cite the governing open decision (OD-02 exact card, OD-04 A1 physical codec, OD-05 transport ceilings and review layout, OD-06 boot/update and platform).

Column meanings: **Boundary** — the component that must enforce the limit. **Threat / rationale** — the refined threat the bound addresses. **Links** — the requirement(s) binding this row and the planned test(s) that will exercise it. **Evidence needed** — measurement evidence required before the owner may freeze a value (in addition to the common freeze pack below).

Common freeze pack required for **every** row before its value may be approved: representative and adversarial corpora; measured peak RAM and stack on the exact target; worst-case CPU/time; camera/display usability where applicable; documented safety margin; defined rejection UX; versioning of the limit; explicit owner review and decision-log entry. Values are frozen only by owner decision — never by measurement alone.

Append-only ID note (F1 audit-correction pass): formerly grouped rows were narrowed to a single atomic dimension while keeping their original IDs; the split-out dimensions were appended as new IDs. No ID was renumbered or reused.

## PSBT

| ID | Dimension | Boundary | Threat / rationale | Links | Evidence needed | Value | Status | Open decision |
|---|---|---|---|---|---|---|---|---|
| QK-LIM-PSBT-001 | Total serialized PSBT bytes | qk-io pre-parse and qk-core reparse | QK-THR-016 oversized input | QK-REQ-PSBT-005; QK-TST-FUZZ-001, QK-TST-BENCH-003 | Corpus size distribution; target RAM/time at ceiling | OPEN — TBD AFTER F2 TARGET MEASUREMENT | OPEN | OD-05 |
| QK-LIM-PSBT-002 | Global-map entry count | qk-core reparse | QK-THR-016 map flooding | QK-REQ-PSBT-002, QK-REQ-PSBT-005; QK-TST-FUZZ-001 | Adversarial map corpora; parse work at ceiling | OPEN — TBD AFTER F2 TARGET MEASUREMENT | OPEN | OD-05 |
| QK-LIM-PSBT-003 | Input count | qk-core reparse | QK-THR-016 count explosion | QK-REQ-PSBT-002, QK-REQ-PSBT-005; QK-TST-FUZZ-001 | Worst-case validation work per input at ceiling | OPEN — TBD AFTER F2 TARGET MEASUREMENT | OPEN | OD-05 |
| QK-LIM-PSBT-004 | Output count | qk-core reparse | QK-THR-016 count explosion | QK-REQ-PSBT-002, QK-REQ-PSBT-005; QK-TST-FUZZ-001 | Worst-case validation and review work at ceiling | OPEN — TBD AFTER F2 TARGET MEASUREMENT | OPEN | OD-05 |
| QK-LIM-PSBT-005 | Script length (witness script, scriptPubKey) | qk-core reparse | QK-THR-016 oversized script | QK-REQ-PSBT-005; QK-TST-FUZZ-001 | Policy-relevant script corpus; parse work at ceiling | OPEN — TBD AFTER F2 TARGET MEASUREMENT | OPEN | OD-05 |
| QK-LIM-PSBT-006 | Derivation path depth | qk-core reparse | QK-THR-016 pathological depth | QK-REQ-PSBT-005; QK-TST-FUZZ-001 | Derivation work at ceiling on target | OPEN — TBD AFTER F2 TARGET MEASUREMENT | OPEN | OD-05 |
| QK-LIM-PSBT-007 | Key length per map entry | qk-core reparse | QK-THR-016 oversized key | QK-REQ-PSBT-005; QK-TST-FUZZ-001 | Adversarial key-length corpora | OPEN — TBD AFTER F2 TARGET MEASUREMENT | OPEN | OD-05 |
| QK-LIM-PSBT-008 | Value length per map entry | qk-core reparse | QK-THR-016 oversized value | QK-REQ-PSBT-005; QK-TST-FUZZ-001 | Adversarial value-length corpora | OPEN — TBD AFTER F2 TARGET MEASUREMENT | OPEN | OD-05 |
| QK-LIM-PSBT-009 | Per-input map entry count | qk-core reparse | QK-THR-016 map flooding | QK-REQ-PSBT-002, QK-REQ-PSBT-005; QK-TST-FUZZ-001 | Parse work and memory at ceiling | OPEN — TBD AFTER F2 TARGET MEASUREMENT | OPEN | OD-05 |
| QK-LIM-PSBT-010 | Per-output map entry count | qk-core reparse | QK-THR-016 map flooding | QK-REQ-PSBT-002, QK-REQ-PSBT-005; QK-TST-FUZZ-001 | Parse work and memory at ceiling | OPEN — TBD AFTER F2 TARGET MEASUREMENT | OPEN | OD-05 |
| QK-LIM-PSBT-011 | Child index ceiling | qk-core reparse | QK-THR-016 pathological index | QK-REQ-PSBT-005; QK-TST-FUZZ-001 | Derivation behavior across index range on target | OPEN — TBD AFTER F2 TARGET MEASUREMENT | OPEN | OD-05 |
| QK-LIM-PSBT-012 | Unknown-field budget (count and bytes) | qk-core reparse | QK-THR-016 unknown-field flooding | QK-REQ-PSBT-002, QK-REQ-PSBT-005; QK-TST-FUZZ-001 | Adversarial unknown-field corpora | OPEN — TBD AFTER F2 TARGET MEASUREMENT | OPEN | OD-05 |
| QK-LIM-PSBT-013 | Parsing work/time per PSBT | qk-core reparse | QK-THR-016 CPU exhaustion | QK-REQ-PSBT-002, QK-REQ-PSBT-005; QK-TST-FUZZ-001, QK-TST-BENCH-003 | Worst-case CPU/time on exact target | OPEN — TBD AFTER F2 TARGET MEASUREMENT | OPEN | OD-05 |
| QK-LIM-PSBT-014 | Reviewable recipient/change output count | qk-core review construction | QK-THR-016/012 unreviewable transaction | QK-REQ-PSBT-005, QK-REQ-TUI-003; QK-TST-HF-002 | Human-factors review data at ceiling | OPEN — TBD AFTER F2 TARGET MEASUREMENT | OPEN | OD-05 |

## QR

| ID | Dimension | Boundary | Threat / rationale | Links | Evidence needed | Value | Status | Open decision |
|---|---|---|---|---|---|---|---|---|
| QK-LIM-QR-001 | Total decoded payload bytes per transfer | qk-io QR reassembly | QK-THR-016 oversized transfer | QK-REQ-TRN-003, QK-REQ-TRN-005; QK-TST-FUZZ-002 | Camera throughput and memory at ceiling | OPEN — TBD AFTER F2 TARGET MEASUREMENT | OPEN | OD-05 |
| QK-LIM-QR-002 | Frame count per BBQr transfer | qk-io QR reassembly | QK-THR-016 frame flooding | QK-REQ-TRN-005; QK-TST-FUZZ-002 | Scan duration and reassembly state at ceiling | OPEN — TBD AFTER F2 TARGET MEASUREMENT | OPEN | OD-05 |
| QK-LIM-QR-003 | Per-frame payload size | qk-io QR decode | QK-THR-016 oversized frame | QK-REQ-TRN-003, QK-REQ-TRN-005; QK-TST-FUZZ-002 | Camera/display usability; decode work per frame | OPEN — TBD AFTER F2 TARGET MEASUREMENT | OPEN | OD-05 |
| QK-LIM-QR-004 | Scan session duration | qk-io QR session | QK-THR-016 unbounded session | QK-REQ-TRN-005; QK-TST-CORP-002 | Usability data for legitimate transfers | OPEN — TBD AFTER F2 TARGET MEASUREMENT | OPEN | OD-05 |
| QK-LIM-QR-005 | Reassembly work per transfer | qk-io QR reassembly | QK-THR-016 CPU exhaustion | QK-REQ-TRN-005; QK-TST-FUZZ-002 | Worst-case reassembly CPU on target | OPEN — TBD AFTER F2 TARGET MEASUREMENT | OPEN | OD-05 |
| QK-LIM-QR-006 | Accepted frame size/version set | qk-io QR decode | QK-THR-016 parser ambiguity | QK-REQ-TRN-003, QK-REQ-TRN-005; QK-TST-UNIT-006 | Decode reliability per version on target camera | OPEN — TBD AFTER F2 TARGET MEASUREMENT | OPEN | OD-05 |
| QK-LIM-QR-007 | Per-frame decode time | qk-io QR decode | QK-THR-016 CPU exhaustion | QK-REQ-TRN-005; QK-TST-BENCH-001 | Worst-case per-frame decode CPU on target | OPEN — TBD AFTER F2 TARGET MEASUREMENT | OPEN | OD-05 |
| QK-LIM-QR-008 | Duplicate/conflicting candidate frame count | qk-io QR reassembly | QK-THR-016/017 conflicting frames | QK-REQ-TRN-005; QK-TST-CORP-002 | Adversarial conflicting-frame corpora | OPEN — TBD AFTER F2 TARGET MEASUREMENT | OPEN | OD-05 |
| QK-LIM-QR-009 | Reassembly memory ceiling | qk-io QR reassembly | QK-THR-016 memory exhaustion | QK-REQ-TRN-005; QK-TST-FUZZ-002, QK-TST-BENCH-003 | Peak RAM at ceiling on exact target | OPEN — TBD AFTER F2 TARGET MEASUREMENT | OPEN | OD-05 |

## SD

| ID | Dimension | Boundary | Threat / rationale | Links | Evidence needed | Value | Status | Open decision |
|---|---|---|---|---|---|---|---|---|
| QK-LIM-SD-001 | Accepted `.psbt` input file bytes | qk-io SD intake | QK-THR-016 oversized file | QK-REQ-TRN-001, QK-REQ-TRN-006; QK-TST-FUZZ-003 | Intake RAM/time at ceiling | OPEN — TBD AFTER F2 TARGET MEASUREMENT | OPEN | OD-05 |
| QK-LIM-SD-002 | File/directory entries examined during intake | qk-io SD intake | QK-THR-016 directory flooding | QK-REQ-TRN-001, QK-REQ-TRN-006; QK-TST-FUZZ-003 | Hostile-filesystem corpora; traversal work | OPEN — TBD AFTER F2 TARGET MEASUREMENT | OPEN | OD-05 |
| QK-LIM-SD-003 | Filesystem metadata parsing work (reads, traversal depth, time) | qk-io SD intake | QK-THR-016 hostile filesystem | QK-REQ-TRN-006; QK-TST-FUZZ-003 | Worst-case metadata parse CPU on target | OPEN — TBD AFTER F2 TARGET MEASUREMENT | OPEN | OD-05 |
| QK-LIM-SD-004 | Output file bytes | qk-io SD output | QK-THR-016/019 unbounded write | QK-REQ-TRN-006; QK-TST-CORP-003 | Write duration and media behavior at ceiling | OPEN — TBD AFTER F2 TARGET MEASUREMENT | OPEN | OD-05 |
| QK-LIM-SD-005 | Filename/path length | qk-io SD intake | QK-THR-016 pathological names | QK-REQ-TRN-006; QK-TST-FUZZ-003 | Adversarial name corpora | OPEN — TBD AFTER F2 TARGET MEASUREMENT | OPEN | OD-05 |
| QK-LIM-SD-006 | Output write attempts per operation | qk-io SD output | QK-THR-019 retry storms, input overwrite pressure | QK-REQ-TRN-002, QK-REQ-TRN-006; QK-TST-PWR-003 | Interruption/retry behavior on target media | OPEN — TBD AFTER F2 TARGET MEASUREMENT | OPEN | OD-05 |
| QK-LIM-SD-007 | I/O operation duration | qk-io SD intake/output | QK-THR-016 stalled media DoS | QK-REQ-TRN-006; QK-TST-CORP-003 | Media latency distribution incl. degraded cards | OPEN — TBD AFTER F2 TARGET MEASUREMENT | OPEN | OD-05 |

## A1 / OCR

| ID | Dimension | Boundary | Threat / rationale | Links | Evidence needed | Value | Status | Open decision |
|---|---|---|---|---|---|---|---|---|
| QK-LIM-A1-001 | OCR candidate count per capture and per session | qk-core A1 capture pipeline | QK-THR-016 candidate explosion | QK-REQ-A1-006, QK-REQ-HF-003; QK-TST-FUZZ-005 | Candidate statistics on real prints; work at ceiling | OPEN — TBD AFTER F2 TARGET MEASUREMENT | OPEN | OD-04 |
| QK-LIM-A1-002 | Error-correction work per candidate (symbols corrected, iterations, time) | qk-core A1 decode | QK-THR-016 correction-work DoS | QK-REQ-A1-006; QK-TST-FUZZ-005 | Correction CPU at ceiling on exact target | OPEN — TBD AFTER F2 TARGET MEASUREMENT | OPEN | OD-04 |
| QK-LIM-A1-003 | Decode/authentication attempts per session | qk-core A1 decode | QK-THR-016 attempt flooding | QK-REQ-A1-006; QK-TST-FUZZ-005 | Legitimate-recovery attempt statistics | OPEN — TBD AFTER F2 TARGET MEASUREMENT | OPEN | OD-04 |
| QK-LIM-A1-004 | Scanned/footer symbol count per document | qk-core A1 capture | QK-THR-016 oversized symbol field | QK-REQ-A1-006; QK-TST-FUZZ-005 | Codec geometry vs. camera resolution on target | OPEN — TBD AFTER F2 TARGET MEASUREMENT | OPEN | OD-04 |
| QK-LIM-A1-005 | OCR confidence acceptance threshold | qk-core A1 capture | QK-THR-016/012 low-confidence garbage input | QK-REQ-A1-006; QK-TST-BENCH-004 | Confidence/success curves from print/capture trials | OPEN — TBD AFTER F2 TARGET MEASUREMENT | OPEN | OD-04 |
| QK-LIM-A1-006 | Capture session duration | qk-core A1 capture | QK-THR-016 unbounded session | QK-REQ-A1-006; QK-TST-HF-001 | Human-trial capture duration data | OPEN — TBD AFTER F2 TARGET MEASUREMENT | OPEN | OD-04 |
| QK-LIM-A1-007 | Capture pipeline memory ceiling | qk-core A1 capture | QK-THR-016 memory exhaustion | QK-REQ-A1-006; QK-TST-BENCH-003 | Peak RAM at ceiling on exact target | OPEN — TBD AFTER F2 TARGET MEASUREMENT | OPEN | OD-04 |

## APDU / card

| ID | Dimension | Boundary | Threat / rationale | Links | Evidence needed | Value | Status | Open decision |
|---|---|---|---|---|---|---|---|---|
| QK-LIM-APDU-001 | Command bytes per APDU | qk-core card session | QK-THR-016 oversized command | QK-REQ-CARD-004, QK-REQ-HF-003; QK-TST-FUZZ-004 | Exact-card protocol behavior at ceiling | OPEN — TBD AFTER F2 TARGET MEASUREMENT | OPEN | OD-02 |
| QK-LIM-APDU-002 | Commands per operation and per session | qk-core card session | QK-THR-016 sequence flooding | QK-REQ-CARD-004; QK-TST-FUZZ-004 | Legitimate-operation exchange counts on exact card | OPEN — TBD AFTER F2 TARGET MEASUREMENT | OPEN | OD-02 |
| QK-LIM-APDU-003 | Card session duration | qk-core card session | QK-THR-016 unbounded session | QK-REQ-CARD-004; QK-TST-CORP-005 | Operation timing on exact card | OPEN — TBD AFTER F2 TARGET MEASUREMENT | OPEN | OD-02 |
| QK-LIM-APDU-004 | Response bytes per APDU | qk-core card-response parse | QK-THR-016 oversized/hostile response | QK-REQ-CARD-004; QK-TST-FUZZ-004 | Hostile-response corpora; parse work at ceiling | OPEN — TBD AFTER F2 TARGET MEASUREMENT | OPEN | OD-02 |
| QK-LIM-APDU-005 | Provisioning payload size | qk-core provisioning | QK-THR-016/019 oversized/partial write | QK-REQ-CARD-004; QK-TST-PWR-002 | Exact-card storage geometry; write timing | OPEN — TBD AFTER F2 TARGET MEASUREMENT | OPEN | OD-02 |
| QK-LIM-APDU-006 | Derivation index ceiling per card operation | qk-core card session | QK-THR-016 pathological index | QK-REQ-CARD-004; QK-TST-FUZZ-004 | Card derivation timing across index range | OPEN — TBD AFTER F2 TARGET MEASUREMENT | OPEN | OD-02 |
| QK-LIM-APDU-007 | Per-operation time and retry count | qk-core card session | QK-THR-016/019 stall and retry storms | QK-REQ-CARD-004; QK-TST-CORP-005, QK-TST-PWR-002 | Exact-card latency and failure statistics | OPEN — TBD AFTER F2 TARGET MEASUREMENT | OPEN | OD-02 |

## Trusted review UI

| ID | Dimension | Boundary | Threat / rationale | Links | Evidence needed | Value | Status | Open decision |
|---|---|---|---|---|---|---|---|---|
| QK-LIM-TUI-001 | Review page count per transaction | qk-core review | QK-THR-012/016 unreviewable pagination | QK-REQ-TUI-003; QK-TST-HF-002 | Human-factors review accuracy at ceiling | OPEN — TBD AFTER F2 TARGET MEASUREMENT | OPEN | OD-05 |
| QK-LIM-TUI-002 | Items and rendered content per review page | qk-core review | QK-THR-012 overload, misread risk | QK-REQ-TUI-003; QK-TST-HF-002 | Display geometry; human-trial accuracy | OPEN — TBD AFTER F2 TARGET MEASUREMENT | OPEN | OD-05 |
| QK-LIM-TUI-003 | Idle timeout during review | qk-core review | QK-THR-019 stale approval/session | QK-REQ-TUI-003; QK-TST-CORP-006 | Legitimate review duration data | OPEN — TBD AFTER F2 TARGET MEASUREMENT | OPEN | OD-05 |
| QK-LIM-TUI-004 | Recipient output count presented for review | qk-core review | QK-THR-012 unreviewable recipient list | QK-REQ-TUI-003; QK-TST-HF-002 | Human-trial accuracy at ceiling | OPEN — TBD AFTER F2 TARGET MEASUREMENT | OPEN | OD-05 |
| QK-LIM-TUI-005 | Change output count presented for review | qk-core review | QK-THR-012/017 hidden-change risk | QK-REQ-TUI-003; QK-TST-HF-002 | Human-trial accuracy at ceiling | OPEN — TBD AFTER F2 TARGET MEASUREMENT | OPEN | OD-05 |
| QK-LIM-TUI-006 | Approval-hold duration | qk-core approval | QK-THR-012 accidental approval | QK-REQ-TUI-003; QK-TST-HF-002 | Human-trial approval-error data | OPEN — TBD AFTER F2 TARGET MEASUREMENT | OPEN | OD-05 |
| QK-LIM-TUI-007 | Error-message length | qk-core review/errors | QK-THR-016/018 unbounded or leaking messages | QK-REQ-TUI-003, QK-REQ-HF-003; QK-TST-CORP-006 | Display geometry; message audit | OPEN — TBD AFTER F2 TARGET MEASUREMENT | OPEN | OD-05 |

## Core IPC

| ID | Dimension | Boundary | Threat / rationale | Links | Evidence needed | Value | Status | Open decision |
|---|---|---|---|---|---|---|---|---|
| QK-LIM-IPC-001 | Message size between `qk-io` and `qk-core` | qk-core IPC receive | QK-THR-016 oversized message | QK-REQ-PLT-006; QK-TST-SAN-001 | Transfer-size distribution; RAM at ceiling | OPEN — TBD AFTER F2 TARGET MEASUREMENT | OPEN | OD-05 |
| QK-LIM-IPC-002 | Message rate | qk-core IPC receive | QK-THR-016 flooding | QK-REQ-PLT-006; QK-TST-SAN-001 | Legitimate-rate measurement; CPU at ceiling | OPEN — TBD AFTER F2 TARGET MEASUREMENT | OPEN | OD-05 |
| QK-LIM-IPC-003 | Queue depth | qk-core IPC receive | QK-THR-016 memory exhaustion via backlog | QK-REQ-PLT-006; QK-TST-SAN-001, QK-TST-BENCH-003 | Peak RAM at ceiling on exact target | OPEN — TBD AFTER F2 TARGET MEASUREMENT | OPEN | OD-05 |

## Memory

| ID | Dimension | Boundary | Threat / rationale | Links | Evidence needed | Value | Status | Open decision |
|---|---|---|---|---|---|---|---|---|
| QK-LIM-MEM-001 | Heap ceiling per process (`qk-core`, `qk-io`) | process runtime | QK-THR-016 memory exhaustion | QK-REQ-PLT-006; QK-TST-BENCH-003 | Peak heap on exact target across worst cases | OPEN — TBD AFTER F2 TARGET MEASUREMENT | OPEN | OD-06 |
| QK-LIM-MEM-002 | Stack ceiling per process and per parsing stage | process runtime | QK-THR-016 stack exhaustion | QK-REQ-PLT-006; QK-TST-BENCH-003, QK-TST-SAN-001 | Peak stack per stage on exact target | OPEN — TBD AFTER F2 TARGET MEASUREMENT | OPEN | OD-06 |
| QK-LIM-MEM-003 | Secret arena size and residency | qk-core secret arena | QK-THR-018 remanence surface | QK-REQ-PLT-006, QK-REQ-PLT-004; QK-TST-SAN-001 | Secret-lifetime analysis on exact target | OPEN — TBD AFTER F2 TARGET MEASUREMENT | OPEN | OD-06 |
| QK-LIM-MEM-004 | Parser arena size per hostile-input path | qk-core/qk-io parsers | QK-THR-016 memory exhaustion | QK-REQ-PLT-006; QK-TST-BENCH-003 | Peak arena use per path at input ceilings | OPEN — TBD AFTER F2 TARGET MEASUREMENT | OPEN | OD-06 |

## Execution and cleanup

| ID | Dimension | Boundary | Threat / rationale | Links | Evidence needed | Value | Status | Open decision |
|---|---|---|---|---|---|---|---|---|
| QK-LIM-EXE-001 | Per-stage execution time for each hostile-input path (parse, validate, review construction) | qk-core/qk-io stage watchdog | QK-THR-016 CPU exhaustion | QK-REQ-PLT-006; QK-TST-BENCH-003 | Worst-case stage CPU on exact target | OPEN — TBD AFTER F2 TARGET MEASUREMENT | OPEN | OD-05 |
| QK-LIM-EXE-002 | Cleanup/zeroization completion time at session end, cancellation, failure, and shutdown | qk-core cleanup | QK-THR-018 remanence window | QK-REQ-PLT-004, QK-REQ-PLT-006; QK-TST-SAN-001, QK-TST-PWR-004 | Zeroization timing on exact target incl. failure paths | OPEN — TBD AFTER F2 TARGET MEASUREMENT | OPEN | OD-06 |

## Registry rules (non-normative summary)

- 60 rows. No row may be implemented against until its value is owner-approved.
- A frozen value change requires a new version of the row, fresh freeze evidence, and a new owner decision.
- Rejection of over-limit input must be fail-closed and user-visible (QK-REQ-HF-003).
