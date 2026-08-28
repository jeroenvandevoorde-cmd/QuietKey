# QuietKey Resource-Budget Registry

**OWNER-APPROVED F1 BASELINE — IMPLEMENTATION EVIDENCE NONE — ALL GATES OPEN — QK-LIM-PSBT-027 PERMANENT TOMBSTONE**

EXPERIMENTAL — NO REAL FUNDS — NOT A WALLET

Rule (non-normative restatement): every hostile-input path must have a hard approved bound before production acceptance of its parser. The normative statements of this rule are the uniquely identified bound requirements in `docs/REQUIREMENTS.md`: QK-REQ-A1-006, QK-REQ-CARD-004, QK-REQ-PSBT-005, QK-REQ-TRN-005, QK-REQ-TRN-006, QK-REQ-TUI-003, QK-REQ-PLT-006, QK-REQ-PLT-010, QK-REQ-ASR-005, and the v2 QK-REQ-KIT rows. This registry defines the dimensions those requirements bind; it introduces no normative language of its own.

Every live row is one atomic resource limit: one metric, one unit, one scope, one enforcement point, and one future value. Every live-row Value cell remains exactly `OPEN — VALUE NOT AUTHORIZED IN F1` and every live-row Status cell remains exactly `OPEN`. Exact ratified protocol shapes may appear outside those cells; a shape is not a parser-resource authorization. The retained `QK-LIM-PSBT-027` row is the sole permanent tombstone and is not a live limit row: it preserves the historical dimension name and ID, carries no operative metric, unit, scope, enforcement point, future value, threat, link, evidence, or open-decision relationship, and can never be reopened. Its Value cell is exactly `NOT A VALUE — PERMANENT TOMBSTONE SENTINEL` and its Status cell is exactly `TOMBSTONED — PERMANENT — NON-REUSABLE`; neither cell authorizes or represents zero, a numeric value, a candidate value, a default, or an approved QK-LIM value. This row-specific representation creates no general tombstone vocabulary or transition for another row. Values for live rows may be authorized only by an explicit Owner decision that consumes measurement evidence. Instrumented, non-production prototypes may run before live-row values are authorized only under the separately recorded HOST candidate caps. No provisional number may appear in a live Value cell.

Column meanings: **Boundary** — the component that must enforce the limit. **Threat / rationale** — the refined threat the bound addresses. **Links** — the requirement(s) binding this row and the planned test(s) that will exercise it. **Evidence needed** — measurement evidence required before the owner may authorize a value (in addition to the common freeze pack below).

Common freeze pack required for **every** row before its value may be authorized: representative and adversarial corpora; measured peak RAM and stack on the exact target; worst-case CPU/time; camera/display usability where applicable; documented safety margin; defined rejection UX; versioning of the limit; explicit owner review and decision-log entry. Values are authorized only by owner decision — never by measurement alone.

Append-only ID note: formerly grouped rows were narrowed to a single atomic dimension while keeping their original IDs; the split-out dimensions were appended as new IDs. No ID was renumbered or reused. QK-LIM-PSBT-027 is retained with its historical dimension name and ID as a permanent non-reusable tombstone; it is never deleted, renumbered, reused, repurposed, or reopened. The v2 kit path receives the fresh QK-LIM-KIT namespace; no A1, general QR, SD, or PSBT ID is reused for a kit-specific bound.

## Ratified v2 shapes — not resource-value authorizations

- The native P2WSH 2-of-2 witness script is exactly 71 bytes, superseding the 105-byte v1 shape. The fixed fee-estimation witness is exactly `1 + 1 + 2 × (1 + 72) + (1 + 71) = 220` bytes, superseding the 254-byte v1 shape: item count, empty dummy, two maximum 72-byte signatures including sighash flags, and the actual witness script.
- Each descriptor route performs exactly four inherited 165-byte child derivations. At the existing 132-route HOST structural cap this is 528 derivations and 87,120 cumulative requested bytes, with one 165-byte derivation buffer logically live. This supersedes the 792-derivation v1 HOST candidate for v2 paths; QK-LIM-PSBT-025 remains OPEN.
- A kit share frame is exactly 142 bytes. Its printed fallback is exactly 228 M18 symbols in four presentation lines of 57, carrying 1,136 data bits followed by exactly four zero pad bits. Its printed QR is fixed version 10, error correction Q, byte mode, no ECI, deterministic lowest-penalty mask with lowest-number tie, and a four-module quiet zone. A disagreement with any exact shape is malformed input, not an over-limit allowance; the resource rows below remain OPEN.

## PSBT

| ID | Dimension | Boundary | Threat / rationale | Links | Evidence needed | Value | Status | Open decision |
|---|---|---|---|---|---|---|---|---|
| QK-LIM-PSBT-001 | Total serialized PSBT bytes | qk-io pre-parse and qk-core reparse | QK-THR-016 oversized input | QK-REQ-PSBT-005; QK-TST-FUZZ-001, QK-TST-BENCH-003 | Corpus size distribution; target RAM/time at ceiling | OPEN — VALUE NOT AUTHORIZED IN F1 | OPEN | OD-05 |
| QK-LIM-PSBT-002 | Global-map entry count | qk-core reparse | QK-THR-016 map flooding | QK-REQ-PSBT-002, QK-REQ-PSBT-005; QK-TST-FUZZ-001 | Adversarial map corpora; parse work at ceiling | OPEN — VALUE NOT AUTHORIZED IN F1 | OPEN | OD-05 |
| QK-LIM-PSBT-003 | Input count | qk-core reparse | QK-THR-016 count explosion | QK-REQ-PSBT-002, QK-REQ-PSBT-005; QK-TST-FUZZ-001 | Worst-case validation work per input at ceiling | OPEN — VALUE NOT AUTHORIZED IN F1 | OPEN | OD-05 |
| QK-LIM-PSBT-004 | Output count | qk-core reparse | QK-THR-016 count explosion | QK-REQ-PSBT-002, QK-REQ-PSBT-005; QK-TST-FUZZ-001 | Worst-case validation and review work at ceiling | OPEN — VALUE NOT AUTHORIZED IN F1 | OPEN | OD-05 |
| QK-LIM-PSBT-005 | Witness script length | qk-core reparse | QK-THR-016 oversized script | QK-REQ-PSBT-005; QK-TST-FUZZ-001 | Policy-relevant witness-script corpus; parse work at ceiling | OPEN — VALUE NOT AUTHORIZED IN F1 | OPEN | OD-05 |
| QK-LIM-PSBT-006 | Derivation path depth | qk-core reparse | QK-THR-016 pathological depth | QK-REQ-PSBT-005; QK-TST-FUZZ-001 | Derivation work at ceiling on target | OPEN — VALUE NOT AUTHORIZED IN F1 | OPEN | OD-05 |
| QK-LIM-PSBT-007 | Key length per map entry | qk-core reparse | QK-THR-016 oversized key | QK-REQ-PSBT-005; QK-TST-FUZZ-001 | Adversarial key-length corpora | OPEN — VALUE NOT AUTHORIZED IN F1 | OPEN | OD-05 |
| QK-LIM-PSBT-008 | Value length per map entry | qk-core reparse | QK-THR-016 oversized value | QK-REQ-PSBT-005; QK-TST-FUZZ-001 | Adversarial value-length corpora | OPEN — VALUE NOT AUTHORIZED IN F1 | OPEN | OD-05 |
| QK-LIM-PSBT-009 | Per-input map entry count | qk-core reparse | QK-THR-016 map flooding | QK-REQ-PSBT-002, QK-REQ-PSBT-005; QK-TST-FUZZ-001 | Parse work and memory at ceiling | OPEN — VALUE NOT AUTHORIZED IN F1 | OPEN | OD-05 |
| QK-LIM-PSBT-010 | Per-output map entry count | qk-core reparse | QK-THR-016 map flooding | QK-REQ-PSBT-002, QK-REQ-PSBT-005; QK-TST-FUZZ-001 | Parse work and memory at ceiling | OPEN — VALUE NOT AUTHORIZED IN F1 | OPEN | OD-05 |
| QK-LIM-PSBT-011 | Child index ceiling (canonical wallet ceiling; QK-LIM-APDU-006 is bound to this row) | qk-core reparse | QK-THR-016 pathological index | QK-REQ-PSBT-005; QK-TST-FUZZ-001 | Derivation behavior across index range on target | OPEN — VALUE NOT AUTHORIZED IN F1 | OPEN | OD-05 |
| QK-LIM-PSBT-012 | Unknown-field count | qk-core reparse | QK-THR-016 unknown-field flooding | QK-REQ-PSBT-002, QK-REQ-PSBT-005; QK-TST-FUZZ-001 | Adversarial unknown-field corpora | OPEN — VALUE NOT AUTHORIZED IN F1 | OPEN | OD-05 |
| QK-LIM-PSBT-013 | Parsing work (operations) per PSBT | qk-core reparse | QK-THR-016 CPU exhaustion | QK-REQ-PSBT-002, QK-REQ-PSBT-005; QK-TST-FUZZ-001, QK-TST-BENCH-003 | Worst-case parse operation counts on exact target | OPEN — VALUE NOT AUTHORIZED IN F1 | OPEN | OD-05 |
| QK-LIM-PSBT-014 | Total reviewable output count | qk-core review construction | QK-THR-016/012 unreviewable transaction | QK-REQ-PSBT-005, QK-REQ-TUI-003; QK-TST-HF-002 | Human-factors review data at ceiling | OPEN — VALUE NOT AUTHORIZED IN F1 | OPEN | OD-05 |
| QK-LIM-PSBT-015 | scriptPubKey length | qk-core reparse | QK-THR-016 oversized script | QK-REQ-PSBT-005; QK-TST-FUZZ-001 | Policy-relevant scriptPubKey corpus; parse work at ceiling | OPEN — VALUE NOT AUTHORIZED IN F1 | OPEN | OD-05 |
| QK-LIM-PSBT-016 | Unknown-field aggregate bytes | qk-core reparse | QK-THR-016 unknown-field flooding | QK-REQ-PSBT-005; QK-TST-FUZZ-001 | Adversarial unknown-field corpora | OPEN — VALUE NOT AUTHORIZED IN F1 | OPEN | OD-05 |
| QK-LIM-PSBT-017 | Parsing elapsed time per PSBT | qk-core reparse | QK-THR-016 CPU exhaustion | QK-REQ-PSBT-005; QK-TST-BENCH-003 | Worst-case elapsed parse time on exact target | OPEN — VALUE NOT AUTHORIZED IN F1 | OPEN | OD-05 |
| QK-LIM-PSBT-018 | Reviewable recipient-output sublimit (QK-LIM-TUI-004 is bound to this row) | qk-core review construction | QK-THR-012 unreviewable recipient list | QK-REQ-PSBT-005; QK-TST-HF-002 | Human-trial accuracy at ceiling | OPEN — VALUE NOT AUTHORIZED IN F1 | OPEN | OD-05 |
| QK-LIM-PSBT-019 | Reviewable change-output sublimit (QK-LIM-TUI-005 is bound to this row) | qk-core review construction | QK-THR-012/017 hidden-change risk | QK-REQ-PSBT-005; QK-TST-HF-002 | Human-trial accuracy at ceiling | OPEN — VALUE NOT AUTHORIZED IN F1 | OPEN | OD-05 |
| QK-LIM-PSBT-020 | Aggregate map entries across all maps | qk-core reparse | QK-THR-016 aggregate flooding below per-map ceilings | QK-REQ-PSBT-005; QK-TST-FUZZ-001 | Aggregate parse work and memory at ceiling | OPEN — VALUE NOT AUTHORIZED IN F1 | OPEN | OD-05 |
| QK-LIM-PSBT-021 | Nested previous-transaction input count | qk-core prevtx validation | QK-THR-016 nested explosion | QK-REQ-PSBT-005; QK-TST-FUZZ-001 | Prevtx validation work at ceiling | OPEN — VALUE NOT AUTHORIZED IN F1 | OPEN | OD-05 |
| QK-LIM-PSBT-022 | Nested previous-transaction output count | qk-core prevtx validation | QK-THR-016 nested explosion | QK-REQ-PSBT-005; QK-TST-FUZZ-001 | Prevtx validation work at ceiling | OPEN — VALUE NOT AUTHORIZED IN F1 | OPEN | OD-05 |
| QK-LIM-PSBT-023 | Nested previous-transaction bytes | qk-core prevtx validation | QK-THR-016 oversized prevtx | QK-REQ-PSBT-005; QK-TST-FUZZ-001 | Prevtx size distribution; RAM at ceiling | OPEN — VALUE NOT AUTHORIZED IN F1 | OPEN | OD-05 |
| QK-LIM-PSBT-024 | Existing-signature verifications per PSBT | qk-core validation | QK-THR-016 verification-work DoS | QK-REQ-PSBT-005; QK-TST-FUZZ-001 | Signature-verification CPU at ceiling on target | OPEN — VALUE NOT AUTHORIZED IN F1 | OPEN | OD-05 |
| QK-LIM-PSBT-025 | Child derivations per PSBT | qk-core validation | QK-THR-016 derivation-work DoS | QK-REQ-PSBT-005; QK-TST-FUZZ-001 | Derivation CPU at ceiling on target | OPEN — VALUE NOT AUTHORIZED IN F1 | OPEN | OD-05 |
| QK-LIM-PSBT-026 | Signed PSBT output bytes | qk-core output serialization | QK-THR-016 unbounded output | QK-REQ-PSBT-005, QK-REQ-TRN-007; QK-TST-DIFF-004 | Output size distribution; transport ceilings | OPEN — VALUE NOT AUTHORIZED IN F1 | OPEN | OD-05 |
| QK-LIM-PSBT-027 | Raw final-transaction output bytes | NONE — FORMER BOUNDARY RELATIONSHIP NON-OPERATIVE | HISTORICAL ONLY — FORMER QK-THR-016 RELATIONSHIP NON-OPERATIVE | NONE — FORMER REQUIREMENT AND TEST RELATIONSHIPS REMOVED | NONE — FORMER EVIDENCE RELATIONSHIP NON-OPERATIVE | NOT A VALUE — PERMANENT TOMBSTONE SENTINEL | TOMBSTONED — PERMANENT — NON-REUSABLE | NONE — FORMER OD-05 RELATIONSHIP NON-OPERATIVE |

## Descriptor

| ID | Dimension | Boundary | Threat / rationale | Links | Evidence needed | Value | Status | Open decision |
|---|---|---|---|---|---|---|---|---|
| QK-LIM-DSC-001 | Descriptor bytes | qk-core descriptor parse | QK-THR-016 oversized descriptor | QK-REQ-PLT-010; QK-TST-FUZZ-001 | Descriptor size distribution; parse RAM at ceiling | OPEN — VALUE NOT AUTHORIZED IN F1 | OPEN | OD-05 |
| QK-LIM-DSC-002 | Descriptor parse work | qk-core descriptor parse | QK-THR-016 CPU exhaustion | QK-REQ-PLT-010; QK-TST-FUZZ-001 | Worst-case descriptor parse CPU on target | OPEN — VALUE NOT AUTHORIZED IN F1 | OPEN | OD-05 |

## QR

| ID | Dimension | Boundary | Threat / rationale | Links | Evidence needed | Value | Status | Open decision |
|---|---|---|---|---|---|---|---|---|
| QK-LIM-QR-001 | Total decoded payload bytes per transfer | qk-io QR reassembly | QK-THR-016 oversized transfer | QK-REQ-TRN-003, QK-REQ-TRN-005; QK-TST-FUZZ-002 | Camera throughput and memory at ceiling | OPEN — VALUE NOT AUTHORIZED IN F1 | OPEN | OD-05 |
| QK-LIM-QR-002 | Unique QR parts per BBQr transfer | qk-io QR reassembly | QK-THR-016 part flooding | QK-REQ-TRN-005; QK-TST-FUZZ-002 | Scan duration and reassembly state at ceiling | OPEN — VALUE NOT AUTHORIZED IN F1 | OPEN | OD-05 |
| QK-LIM-QR-003 | Per-frame payload size | qk-io QR decode | QK-THR-016 oversized frame | QK-REQ-TRN-003, QK-REQ-TRN-005; QK-TST-FUZZ-002 | Camera/display usability; decode work per frame | OPEN — VALUE NOT AUTHORIZED IN F1 | OPEN | OD-05 |
| QK-LIM-QR-004 | Scan session duration | qk-io QR session | QK-THR-016 unbounded session | QK-REQ-TRN-005; QK-TST-CORP-002 | Usability data for legitimate transfers | OPEN — VALUE NOT AUTHORIZED IN F1 | OPEN | OD-05 |
| QK-LIM-QR-005 | Reassembly work per transfer | qk-io QR reassembly | QK-THR-016 CPU exhaustion | QK-REQ-TRN-005; QK-TST-FUZZ-002 | Worst-case reassembly CPU on target | OPEN — VALUE NOT AUTHORIZED IN F1 | OPEN | OD-05 |
| QK-LIM-QR-006 | Maximum accepted QR symbol version | qk-io QR decode | QK-THR-016 parser ambiguity | QK-REQ-TRN-003, QK-REQ-TRN-005; QK-TST-UNIT-006 | Decode reliability per version on target camera | OPEN — VALUE NOT AUTHORIZED IN F1 | OPEN | OD-05 |
| QK-LIM-QR-007 | Per-frame decode time | qk-io QR decode | QK-THR-016 CPU exhaustion | QK-REQ-TRN-005; QK-TST-BENCH-001 | Worst-case per-frame decode CPU on target | OPEN — VALUE NOT AUTHORIZED IN F1 | OPEN | OD-05 |
| QK-LIM-QR-008 | Duplicate frame count per transfer (conflicting content fails immediately — no allowance; see invariants) | qk-io QR reassembly | QK-THR-016 duplicate flooding | QK-REQ-TRN-005; QK-TST-CORP-002 | Adversarial duplicate-frame corpora | OPEN — VALUE NOT AUTHORIZED IN F1 | OPEN | OD-05 |
| QK-LIM-QR-009 | Reassembly memory ceiling | qk-io QR reassembly | QK-THR-016 memory exhaustion | QK-REQ-TRN-005; QK-TST-FUZZ-002, QK-TST-BENCH-003 | Peak RAM at ceiling on exact target | OPEN — VALUE NOT AUTHORIZED IN F1 | OPEN | OD-05 |
| QK-LIM-QR-010 | Total frames processed per transfer (including duplicates and rejects) | qk-io QR session | QK-THR-016 processing flood below unique-part ceiling | QK-REQ-TRN-005; QK-TST-FUZZ-002 | Frame-processing CPU at ceiling | OPEN — VALUE NOT AUTHORIZED IN F1 | OPEN | OD-05 |
| QK-LIM-QR-011 | Accepted BBQr protocol mode set | qk-io QR decode | QK-THR-016 parser ambiguity | QK-REQ-TRN-003, QK-REQ-TRN-005; QK-TST-UNIT-006 | Mode-handling decode reliability on target | OPEN — VALUE NOT AUTHORIZED IN F1 | OPEN | OD-05 |
| QK-LIM-QR-012 | Concurrent candidate reassembly streams | qk-io QR reassembly | QK-THR-016 state explosion | QK-REQ-TRN-005; QK-TST-FUZZ-002 | Reassembly state memory at ceiling | OPEN — VALUE NOT AUTHORIZED IN F1 | OPEN | OD-05 |
| QK-LIM-QR-013 | Raw camera image bytes per frame | qk-io camera capture | QK-THR-016 oversized capture | QK-REQ-TRN-005; QK-TST-BENCH-001 | Camera buffer geometry on exact target | OPEN — VALUE NOT AUTHORIZED IN F1 | OPEN | OD-05 |
| QK-LIM-QR-014 | Stream restarts per scan session | qk-io QR session | QK-THR-016 restart thrashing | QK-REQ-TRN-005; QK-TST-CORP-002 | Legitimate restart statistics | OPEN — VALUE NOT AUTHORIZED IN F1 | OPEN | OD-05 |

## SD

| ID | Dimension | Boundary | Threat / rationale | Links | Evidence needed | Value | Status | Open decision |
|---|---|---|---|---|---|---|---|---|
| QK-LIM-SD-001 | Accepted `.psbt` input file bytes | qk-io SD intake | QK-THR-016 oversized file | QK-REQ-TRN-001, QK-REQ-TRN-006; QK-TST-FUZZ-003 | Intake RAM/time at ceiling | OPEN — VALUE NOT AUTHORIZED IN F1 | OPEN | OD-05 |
| QK-LIM-SD-002 | File/directory entries examined during intake | qk-io SD intake | QK-THR-016 directory flooding | QK-REQ-TRN-001, QK-REQ-TRN-006; QK-TST-FUZZ-003 | Hostile-filesystem corpora; traversal work | OPEN — VALUE NOT AUTHORIZED IN F1 | OPEN | OD-05 |
| QK-LIM-SD-003 | Filesystem metadata read operations | qk-io SD intake (userspace) | QK-THR-016 hostile filesystem | QK-REQ-TRN-006, QK-REQ-TRN-010; QK-TST-FUZZ-003 | Worst-case metadata read counts on target | OPEN — VALUE NOT AUTHORIZED IN F1 | OPEN | OD-06 |
| QK-LIM-SD-004 | Output file bytes | qk-io SD output writer | QK-THR-016/019 unbounded write | QK-REQ-TRN-006, QK-REQ-TRN-007; QK-TST-CORP-003 | Write duration and media behavior at ceiling | OPEN — VALUE NOT AUTHORIZED IN F1 | OPEN | OD-05 |
| QK-LIM-SD-005 | Filename bytes | qk-io SD intake | QK-THR-016 pathological names | QK-REQ-TRN-006; QK-TST-FUZZ-003 | Adversarial name corpora | OPEN — VALUE NOT AUTHORIZED IN F1 | OPEN | OD-05 |
| QK-LIM-SD-006 | Output write attempts per operation | qk-io SD output writer | QK-THR-019 retry storms, input overwrite pressure | QK-REQ-TRN-002, QK-REQ-TRN-006; QK-TST-PWR-003 | Interruption/retry behavior on target media | OPEN — VALUE NOT AUTHORIZED IN F1 | OPEN | OD-05 |
| QK-LIM-SD-007 | Input-read deadline | qk-io SD intake | QK-THR-016 stalled media DoS | QK-REQ-TRN-006; QK-TST-CORP-003 | Media read-latency distribution incl. degraded cards | OPEN — VALUE NOT AUTHORIZED IN F1 | OPEN | OD-05 |
| QK-LIM-SD-008 | Directory traversal depth | qk-io SD intake (userspace) | QK-THR-016 hostile filesystem | QK-REQ-TRN-006, QK-REQ-TRN-010; QK-TST-FUZZ-003 | Hostile-filesystem traversal corpora | OPEN — VALUE NOT AUTHORIZED IN F1 | OPEN | OD-06 |
| QK-LIM-SD-009 | Filesystem metadata parse time | qk-io SD intake (userspace) | QK-THR-016 hostile filesystem | QK-REQ-TRN-006, QK-REQ-TRN-010; QK-TST-FUZZ-003 | Worst-case metadata parse CPU on target | OPEN — VALUE NOT AUTHORIZED IN F1 | OPEN | OD-06 |
| QK-LIM-SD-010 | Full-path bytes | qk-io SD intake | QK-THR-016 pathological paths | QK-REQ-TRN-006; QK-TST-FUZZ-003 | Adversarial path corpora | OPEN — VALUE NOT AUTHORIZED IN F1 | OPEN | OD-05 |
| QK-LIM-SD-011 | Output-write deadline | qk-io SD output writer | QK-THR-016/019 stalled write | QK-REQ-TRN-008; QK-TST-PWR-005 | Media write-latency distribution | OPEN — VALUE NOT AUTHORIZED IN F1 | OPEN | OD-05 |
| QK-LIM-SD-012 | Output sync deadline | qk-io SD output writer | QK-THR-019 unsynced output presented complete | QK-REQ-TRN-008; QK-TST-PWR-005 | Sync-latency distribution on target media | OPEN — VALUE NOT AUTHORIZED IN F1 | OPEN | OD-05 |
| QK-LIM-SD-013 | Output read-back verification deadline | qk-io SD output writer | QK-THR-019 unverified output presented complete | QK-REQ-TRN-008; QK-TST-PWR-005 | Read-back latency distribution on target media | OPEN — VALUE NOT AUTHORIZED IN F1 | OPEN | OD-05 |

## A1 / OCR

| ID | Dimension | Boundary | Threat / rationale | Links | Evidence needed | Value | Status | Open decision |
|---|---|---|---|---|---|---|---|---|
| QK-LIM-A1-001 | OCR candidate count per capture | qk-io A1 capture pipeline | QK-THR-016 candidate explosion | QK-REQ-A1-006, QK-REQ-HF-003; QK-TST-FUZZ-005 | Candidate statistics on real prints; work at ceiling | OPEN — VALUE NOT AUTHORIZED IN F1 | OPEN | OD-04 |
| QK-LIM-A1-002 | Error-correction symbols corrected per candidate | qk-io A1 decode | QK-THR-016 correction-work DoS | QK-REQ-A1-006; QK-TST-FUZZ-005 | Correction statistics on damaged prints | OPEN — VALUE NOT AUTHORIZED IN F1 | OPEN | OD-04 |
| QK-LIM-A1-003 | Capsule decode attempts per session | qk-core A1 capsule intake | QK-THR-016 attempt flooding | QK-REQ-A1-006; QK-TST-FUZZ-005 | Legitimate-recovery attempt statistics | OPEN — VALUE NOT AUTHORIZED IN F1 | OPEN | OD-04 |
| QK-LIM-A1-004 | Raw scanned symbol count per document | qk-io A1 capture | QK-THR-016 oversized symbol field | QK-REQ-A1-006; QK-TST-FUZZ-005 | Codec geometry vs. camera resolution on target | OPEN — VALUE NOT AUTHORIZED IN F1 | OPEN | OD-04 |
| QK-LIM-A1-005 | OCR confidence acceptance threshold | qk-io A1 capture | QK-THR-016/012 low-confidence garbage input | QK-REQ-A1-006; QK-TST-BENCH-004 | Confidence/success curves from print/capture trials | OPEN — VALUE NOT AUTHORIZED IN F1 | OPEN | OD-04 |
| QK-LIM-A1-006 | Capture session duration | qk-io A1 capture | QK-THR-016 unbounded session | QK-REQ-A1-006; QK-TST-HF-001 | Human-trial capture duration data | OPEN — VALUE NOT AUTHORIZED IN F1 | OPEN | OD-04 |
| QK-LIM-A1-007 | Capture pipeline memory ceiling | qk-io A1 capture | QK-THR-016 memory exhaustion | QK-REQ-A1-006; QK-TST-BENCH-003 | Peak RAM at ceiling on exact target | OPEN — VALUE NOT AUTHORIZED IN F1 | OPEN | OD-04 |
| QK-LIM-A1-008 | OCR candidate count per session | qk-io A1 capture pipeline | QK-THR-016 candidate explosion across captures | QK-REQ-A1-006; QK-TST-FUZZ-005 | Session-level candidate statistics | OPEN — VALUE NOT AUTHORIZED IN F1 | OPEN | OD-04 |
| QK-LIM-A1-009 | Error-correction iterations per candidate | qk-io A1 decode | QK-THR-016 correction-work DoS | QK-REQ-A1-006; QK-TST-FUZZ-005 | Iteration counts at ceiling on target | OPEN — VALUE NOT AUTHORIZED IN F1 | OPEN | OD-04 |
| QK-LIM-A1-010 | Error-correction time per candidate | qk-io A1 decode | QK-THR-016 CPU exhaustion | QK-REQ-A1-006; QK-TST-BENCH-003 | Correction CPU at ceiling on exact target | OPEN — VALUE NOT AUTHORIZED IN F1 | OPEN | OD-04 |
| QK-LIM-A1-011 | Footer symbol count per document | qk-io A1 capture | QK-THR-016 oversized footer | QK-REQ-A1-006; QK-TST-FUZZ-005 | Codec footer geometry on target | OPEN — VALUE NOT AUTHORIZED IN F1 | OPEN | OD-04 |
| QK-LIM-A1-012 | Raw image bytes per capture | qk-io A1 capture | QK-THR-016 oversized capture | QK-REQ-A1-006; QK-TST-BENCH-004 | Camera buffer geometry on exact target | OPEN — VALUE NOT AUTHORIZED IN F1 | OPEN | OD-04 |
| QK-LIM-A1-013 | Erasure positions per candidate | qk-io A1 decode | QK-THR-016 pathological erasure patterns | QK-REQ-A1-006; QK-TST-FUZZ-005 | Erasure statistics on damaged prints | OPEN — VALUE NOT AUTHORIZED IN F1 | OPEN | OD-04 |
| QK-LIM-A1-014 | AEAD authentication attempts per session | qk-core A1 capsule intake | QK-THR-016 attempt flooding | QK-REQ-A1-006; QK-TST-FUZZ-005 | Legitimate-recovery authentication statistics | OPEN — VALUE NOT AUTHORIZED IN F1 | OPEN | OD-04 |

## V2 recovery kit

| ID | Dimension | Boundary | Threat / rationale | Links | Evidence needed | Value | Status | Open decision |
|---|---|---|---|---|---|---|---|---|
| QK-LIM-KIT-001 | Kit-share frame bytes accepted per submission | qk-core kit-frame parser | QK-THR-016 oversized or shape-confused share | QK-REQ-KIT-001; QK-TST-UNIT-014, QK-TST-FUZZ-002 | Hostile frame corpus; target parse RAM/time | OPEN — VALUE NOT AUTHORIZED IN F1 | OPEN | OD-05 |
| QK-LIM-KIT-002 | M18 fallback symbols accepted per share | qk-io fallback decode and qk-core frame validation | QK-THR-016 oversized or ambiguous transcription | QK-REQ-KIT-015; QK-TST-DIFF-005, QK-TST-FUZZ-002 | Transcription corpus; target input and decode work | OPEN — VALUE NOT AUTHORIZED IN F1 | OPEN | OD-07 |
| QK-LIM-KIT-003 | Kit-share QR decode attempts per session | qk-core mode-locked scanner | QK-THR-016 attempt flooding | QK-REQ-KIT-007, QK-REQ-KIT-015; QK-TST-PROP-008, QK-TST-FUZZ-002 | Legitimate and hostile retry statistics on fixed camera | OPEN — VALUE NOT AUTHORIZED IN F1 | OPEN | OD-05 |
| QK-LIM-KIT-004 | Fallback submissions per session | qk-core mode-locked scanner | QK-THR-016 retry and transcription flooding | QK-REQ-KIT-007, QK-REQ-KIT-015; QK-TST-PROP-008, QK-TST-FUZZ-002 | Human-entry retry data under the later ratified input method | OPEN — VALUE NOT AUTHORIZED IN F1 | OPEN | OD-07 |
| QK-LIM-KIT-005 | Kit scan-session duration | qk-core/qk-io scanner session | QK-THR-016/019 unbounded or stale recovery session | QK-REQ-KIT-007; QK-TST-PROP-008 | Legitimate scan duration and timeout behavior on exact target | OPEN — VALUE NOT AUTHORIZED IN F1 | OPEN | OD-05 |
| QK-LIM-KIT-006 | Raw image bytes per kit-share capture | qk-io camera capture | QK-THR-016 oversized capture | QK-REQ-KIT-015; QK-TST-DIFF-005, QK-TST-FUZZ-002 | Camera buffer geometry on exact target | OPEN — VALUE NOT AUTHORIZED IN F1 | OPEN | OD-05 |
| QK-LIM-KIT-007 | QR candidates per kit-share capture | qk-io QR candidate pipeline | QK-THR-016 candidate explosion | QK-REQ-KIT-007, QK-REQ-KIT-015; QK-TST-DIFF-005, QK-TST-FUZZ-002 | Candidate statistics on real kit prints | OPEN — VALUE NOT AUTHORIZED IN F1 | OPEN | OD-05 |
| QK-LIM-KIT-008 | Decode work per kit-share QR candidate | qk-io QR decode | QK-THR-016 CPU exhaustion | QK-REQ-KIT-015; QK-TST-DIFF-005, QK-TST-FUZZ-002 | Worst-case decode work on exact target | OPEN — VALUE NOT AUTHORIZED IN F1 | OPEN | OD-05 |
| QK-LIM-KIT-009 | Print-artifact bytes per share page | qk-core artifact construction and qk-io print broker | QK-THR-016/019 oversized or incomplete page | QK-REQ-KIT-006; QK-TST-REH-007 | Exact renderer output and printer-spool behavior | OPEN — VALUE NOT AUTHORIZED IN F1 | OPEN | OD-07 |
| QK-LIM-KIT-010 | Print attempts per setup copy | qk-core kit-generation lifecycle | QK-THR-019 retry ambiguity or unintended extra copies | QK-REQ-KIT-005, QK-REQ-KIT-006; QK-TST-REH-007 | Printer failure/retry and custody rehearsal data | OPEN — VALUE NOT AUTHORIZED IN F1 | OPEN | OD-07 |
| QK-LIM-KIT-011 | Share-combine attempts per session | qk-core kit secret owner | QK-THR-016 attempt flooding and cross-wallet probing | QK-REQ-KIT-002, QK-REQ-KIT-007; QK-TST-UNIT-014, QK-TST-PROP-008, QK-TST-FUZZ-002 | Wrong-index, wrong-wallet, checksum, and legitimate retry corpus | OPEN — VALUE NOT AUTHORIZED IN F1 | OPEN | OD-05 |
| QK-LIM-KIT-012 | Mode-locked kit-scanner arena bytes | qk-core kit scanner | QK-THR-016 memory exhaustion and stale-share retention | QK-REQ-KIT-007, QK-REQ-KIT-015; QK-TST-PROP-008, QK-TST-FUZZ-002 | Peak arena and cleanup behavior at all scanner bounds | OPEN — VALUE NOT AUTHORIZED IN F1 | OPEN | OD-06 |

## APDU / card

| ID | Dimension | Boundary | Threat / rationale | Links | Evidence needed | Value | Status | Open decision |
|---|---|---|---|---|---|---|---|---|
| QK-LIM-APDU-001 | Command bytes per APDU | qk-core card session | QK-THR-016 oversized command | QK-REQ-CARD-004, QK-REQ-HF-003; QK-TST-FUZZ-004 | Exact-card protocol behavior at ceiling | OPEN — VALUE NOT AUTHORIZED IN F1 | OPEN | OD-02 |
| QK-LIM-APDU-002 | Commands per operation | qk-core card session | QK-THR-016 sequence flooding | QK-REQ-CARD-004; QK-TST-FUZZ-004 | Legitimate-operation exchange counts on exact card | OPEN — VALUE NOT AUTHORIZED IN F1 | OPEN | OD-02 |
| QK-LIM-APDU-003 | Card session duration | qk-core card session | QK-THR-016 unbounded session | QK-REQ-CARD-004; QK-TST-CORP-005 | Operation timing on exact card | OPEN — VALUE NOT AUTHORIZED IN F1 | OPEN | OD-02 |
| QK-LIM-APDU-004 | Response bytes per APDU | qk-core card-response parse | QK-THR-016 oversized/hostile response | QK-REQ-CARD-004; QK-TST-FUZZ-004 | Hostile-response corpora; parse work at ceiling | OPEN — VALUE NOT AUTHORIZED IN F1 | OPEN | OD-02 |
| QK-LIM-APDU-005 | Provisioning payload size | qk-core provisioning | QK-THR-016/019 oversized/partial write | QK-REQ-CARD-004; QK-TST-PWR-002 | Exact-card storage geometry; write timing | OPEN — VALUE NOT AUTHORIZED IN F1 | OPEN | OD-02 |
| QK-LIM-APDU-006 | Derivation index ceiling per card operation (bound to the canonical wallet ceiling QK-LIM-PSBT-011; see invariants) | qk-core card session | QK-THR-016 pathological index | QK-REQ-CARD-004; QK-TST-FUZZ-004 | Card derivation timing across index range | OPEN — VALUE NOT AUTHORIZED IN F1 | OPEN | OD-02 |
| QK-LIM-APDU-007 | Per-operation time | qk-core card session | QK-THR-016/019 stall | QK-REQ-CARD-004; QK-TST-CORP-005 | Exact-card latency statistics | OPEN — VALUE NOT AUTHORIZED IN F1 | OPEN | OD-02 |
| QK-LIM-APDU-008 | Commands per session | qk-core card session | QK-THR-016 sequence flooding | QK-REQ-CARD-004; QK-TST-FUZZ-004 | Legitimate-session exchange counts on exact card | OPEN — VALUE NOT AUTHORIZED IN F1 | OPEN | OD-02 |
| QK-LIM-APDU-009 | Retry count per operation | qk-core card session | QK-THR-019 retry storms | QK-REQ-CARD-004; QK-TST-PWR-002 | Exact-card failure/retry statistics | OPEN — VALUE NOT AUTHORIZED IN F1 | OPEN | OD-02 |
| QK-LIM-APDU-010 | Aggregate APDU bytes per session | qk-core card session | QK-THR-016 aggregate flooding below per-APDU ceilings | QK-REQ-CARD-004; QK-TST-FUZZ-004 | Session-level exchange volume on exact card | OPEN — VALUE NOT AUTHORIZED IN F1 | OPEN | OD-02 |
| QK-LIM-APDU-011 | Signing requests per session | qk-core card session | QK-THR-016/017 signing-request flooding | QK-REQ-CARD-004; QK-TST-FUZZ-004 | Legitimate signing-request counts | OPEN — VALUE NOT AUTHORIZED IN F1 | OPEN | OD-02 |

## Trusted review UI

| ID | Dimension | Boundary | Threat / rationale | Links | Evidence needed | Value | Status | Open decision |
|---|---|---|---|---|---|---|---|---|
| QK-LIM-TUI-001 | Review page count per transaction | qk-core review | QK-THR-012/016 unreviewable pagination | QK-REQ-TUI-003; QK-TST-HF-002 | Human-factors review accuracy at ceiling | OPEN — VALUE NOT AUTHORIZED IN F1 | OPEN | OD-05 |
| QK-LIM-TUI-002 | Items per review page | qk-core review | QK-THR-012 overload, misread risk | QK-REQ-TUI-003; QK-TST-HF-002 | Display geometry; human-trial accuracy | OPEN — VALUE NOT AUTHORIZED IN F1 | OPEN | OD-05 |
| QK-LIM-TUI-003 | Per-page idle timeout during review | qk-core review | QK-THR-019 stale approval/session | QK-REQ-TUI-003; QK-TST-CORP-006 | Legitimate review duration data | OPEN — VALUE NOT AUTHORIZED IN F1 | OPEN | OD-05 |
| QK-LIM-TUI-004 | Recipient output count presented for review (bound to QK-LIM-PSBT-018; see invariants) | qk-core review | QK-THR-012 unreviewable recipient list | QK-REQ-TUI-003; QK-TST-HF-002 | Human-trial accuracy at ceiling | OPEN — VALUE NOT AUTHORIZED IN F1 | OPEN | OD-05 |
| QK-LIM-TUI-005 | Change output count presented for review (bound to QK-LIM-PSBT-019; see invariants) | qk-core review | QK-THR-012/017 hidden-change risk | QK-REQ-TUI-003; QK-TST-HF-002 | Human-trial accuracy at ceiling | OPEN — VALUE NOT AUTHORIZED IN F1 | OPEN | OD-05 |
| QK-LIM-TUI-006 | Approval-hold duration | qk-core approval | QK-THR-012 accidental approval | QK-REQ-TUI-003; QK-TST-HF-002 | Human-trial approval-error data | OPEN — VALUE NOT AUTHORIZED IN F1 | OPEN | OD-05 |
| QK-LIM-TUI-007 | Error-message length | qk-core review/errors | QK-THR-016/018 unbounded or leaking messages | QK-REQ-TUI-003, QK-REQ-HF-003; QK-TST-CORP-006 | Display geometry; message audit | OPEN — VALUE NOT AUTHORIZED IN F1 | OPEN | OD-05 |
| QK-LIM-TUI-008 | Rendered glyph/cell count per review page | qk-core review | QK-THR-012/016 render overload | QK-REQ-TUI-003; QK-TST-HF-002 | Display geometry; render work at ceiling | OPEN — VALUE NOT AUTHORIZED IN F1 | OPEN | OD-05 |
| QK-LIM-TUI-009 | Total review duration per transaction | qk-core review | QK-THR-019 indefinitely open review | QK-REQ-TUI-003; QK-TST-CORP-006 | Legitimate end-to-end review duration data | OPEN — VALUE NOT AUTHORIZED IN F1 | OPEN | OD-05 |

## Core IPC

| ID | Dimension | Boundary | Threat / rationale | Links | Evidence needed | Value | Status | Open decision |
|---|---|---|---|---|---|---|---|---|
| QK-LIM-IPC-001 | Message size between `qk-io` and `qk-core` | qk-core IPC receive | QK-THR-016 oversized message | QK-REQ-PLT-006; QK-TST-SAN-001 | Transfer-size distribution; RAM at ceiling | OPEN — VALUE NOT AUTHORIZED IN F1 | OPEN | OD-05 |
| QK-LIM-IPC-002 | Message rate | qk-core IPC receive | QK-THR-016 flooding | QK-REQ-PLT-006; QK-TST-SAN-001 | Legitimate-rate measurement; CPU at ceiling | OPEN — VALUE NOT AUTHORIZED IN F1 | OPEN | OD-05 |
| QK-LIM-IPC-003 | Queue depth | qk-core IPC receive | QK-THR-016 memory exhaustion via backlog | QK-REQ-PLT-006; QK-TST-SAN-001, QK-TST-BENCH-003 | Peak RAM at ceiling on exact target | OPEN — VALUE NOT AUTHORIZED IN F1 | OPEN | OD-05 |
| QK-LIM-IPC-004 | Messages per session | qk-core IPC receive | QK-THR-016 aggregate flooding below rate ceiling | QK-REQ-PLT-006; QK-TST-SAN-001 | Legitimate-session message counts | OPEN — VALUE NOT AUTHORIZED IN F1 | OPEN | OD-05 |
| QK-LIM-IPC-005 | Aggregate IPC bytes per session | qk-core IPC receive | QK-THR-016 aggregate volume flooding | QK-REQ-PLT-006; QK-TST-SAN-001 | Session-level transfer volume | OPEN — VALUE NOT AUTHORIZED IN F1 | OPEN | OD-05 |
| QK-LIM-IPC-006 | Per-exchange IPC deadline | qk-core IPC receive | QK-THR-016 stalled-peer DoS | QK-REQ-PLT-006; QK-TST-SAN-001 | Exchange latency distribution on target | OPEN — VALUE NOT AUTHORIZED IN F1 | OPEN | OD-05 |

## Memory

| ID | Dimension | Boundary | Threat / rationale | Links | Evidence needed | Value | Status | Open decision |
|---|---|---|---|---|---|---|---|---|
| QK-LIM-MEM-001 | `qk-core` heap ceiling | qk-core runtime | QK-THR-016 memory exhaustion | QK-REQ-PLT-006; QK-TST-BENCH-003 | Peak heap on exact target across worst cases | OPEN — VALUE NOT AUTHORIZED IN F1 | OPEN | OD-06 |
| QK-LIM-MEM-002 | `qk-core` stack ceiling | qk-core runtime | QK-THR-016 stack exhaustion | QK-REQ-PLT-006; QK-TST-BENCH-003, QK-TST-SAN-001 | Peak stack on exact target | OPEN — VALUE NOT AUTHORIZED IN F1 | OPEN | OD-06 |
| QK-LIM-MEM-003 | Secret arena size (bytes) | qk-core secret arena | QK-THR-018 remanence surface | QK-REQ-PLT-006, QK-REQ-PLT-004; QK-TST-SAN-001 | Secret footprint analysis on exact target | OPEN — VALUE NOT AUTHORIZED IN F1 | OPEN | OD-06 |
| QK-LIM-MEM-004 | PSBT parser arena size | qk-core PSBT parser | QK-THR-016 memory exhaustion | QK-REQ-PLT-006; QK-TST-BENCH-003 | Peak arena use at PSBT input ceilings | OPEN — VALUE NOT AUTHORIZED IN F1 | OPEN | OD-06 |
| QK-LIM-MEM-005 | `qk-io` heap ceiling | qk-io runtime | QK-THR-016 memory exhaustion | QK-REQ-PLT-006; QK-TST-BENCH-003 | Peak heap on exact target across worst cases | OPEN — VALUE NOT AUTHORIZED IN F1 | OPEN | OD-06 |
| QK-LIM-MEM-006 | `qk-decoy` heap ceiling | qk-decoy runtime | QK-THR-016 memory exhaustion | QK-REQ-PLT-006; QK-TST-BENCH-003 | Peak heap on exact target | OPEN — VALUE NOT AUTHORIZED IN F1 | OPEN | OD-06 |
| QK-LIM-MEM-007 | `qk-io` stack ceiling | qk-io runtime | QK-THR-016 stack exhaustion | QK-REQ-PLT-006; QK-TST-BENCH-003, QK-TST-SAN-001 | Peak stack on exact target | OPEN — VALUE NOT AUTHORIZED IN F1 | OPEN | OD-06 |
| QK-LIM-MEM-008 | `qk-decoy` stack ceiling | qk-decoy runtime | QK-THR-016 stack exhaustion | QK-REQ-PLT-006; QK-TST-BENCH-003 | Peak stack on exact target | OPEN — VALUE NOT AUTHORIZED IN F1 | OPEN | OD-06 |
| QK-LIM-MEM-009 | Secret arena residency duration | qk-core secret arena | QK-THR-018 remanence window | QK-REQ-PLT-006, QK-REQ-PLT-004; QK-TST-SAN-001 | Secret-lifetime analysis on exact target | OPEN — VALUE NOT AUTHORIZED IN F1 | OPEN | OD-06 |
| QK-LIM-MEM-010 | QR parser arena size | qk-io QR parser | QK-THR-016 memory exhaustion | QK-REQ-PLT-006; QK-TST-BENCH-003 | Peak arena use at QR input ceilings | OPEN — VALUE NOT AUTHORIZED IN F1 | OPEN | OD-06 |
| QK-LIM-MEM-011 | SD parser arena size | qk-io SD parser | QK-THR-016 memory exhaustion | QK-REQ-PLT-006; QK-TST-BENCH-003 | Peak arena use at SD input ceilings | OPEN — VALUE NOT AUTHORIZED IN F1 | OPEN | OD-06 |
| QK-LIM-MEM-012 | A1 parser arena size | qk-io A1 pipeline | QK-THR-016 memory exhaustion | QK-REQ-PLT-006; QK-TST-BENCH-003 | Peak arena use at A1 input ceilings | OPEN — VALUE NOT AUTHORIZED IN F1 | OPEN | OD-06 |
| QK-LIM-MEM-013 | APDU-response parser arena size | qk-core card-response parser | QK-THR-016 memory exhaustion | QK-REQ-PLT-006; QK-TST-BENCH-003 | Peak arena use at APDU response ceilings | OPEN — VALUE NOT AUTHORIZED IN F1 | OPEN | OD-06 |
| QK-LIM-MEM-014 | `qk-core` process RSS ceiling | qk-core runtime | QK-THR-016 memory exhaustion | QK-REQ-PLT-006; QK-TST-BENCH-003 | Peak RSS on exact target | OPEN — VALUE NOT AUTHORIZED IN F1 | OPEN | OD-06 |
| QK-LIM-MEM-015 | `qk-io` process RSS ceiling | qk-io runtime | QK-THR-016 memory exhaustion | QK-REQ-PLT-006; QK-TST-BENCH-003 | Peak RSS on exact target | OPEN — VALUE NOT AUTHORIZED IN F1 | OPEN | OD-06 |
| QK-LIM-MEM-016 | `qk-decoy` process RSS ceiling | qk-decoy runtime | QK-THR-016 memory exhaustion | QK-REQ-PLT-006; QK-TST-BENCH-003 | Peak RSS on exact target | OPEN — VALUE NOT AUTHORIZED IN F1 | OPEN | OD-06 |
| QK-LIM-MEM-017 | Camera/DMA buffer bytes | qk-io camera path | QK-THR-016/018 buffer exhaustion, remanence surface | QK-REQ-PLT-006; QK-TST-BENCH-003, QK-TST-SAN-001 | Camera buffer geometry and clearing on target | OPEN — VALUE NOT AUTHORIZED IN F1 | OPEN | OD-06 |
| QK-LIM-MEM-018 | Framebuffer buffer bytes | qk-core display path | QK-THR-016/018 buffer exhaustion, remanence surface | QK-REQ-PLT-006; QK-TST-SAN-001 | Framebuffer geometry and clearing on target | OPEN — VALUE NOT AUTHORIZED IN F1 | OPEN | OD-06 |

## Execution and cleanup

| ID | Dimension | Boundary | Threat / rationale | Links | Evidence needed | Value | Status | Open decision |
|---|---|---|---|---|---|---|---|---|
| QK-LIM-EXE-001 | Parse-stage time per hostile-input path | qk-core/qk-io stage watchdog | QK-THR-016 CPU exhaustion | QK-REQ-PLT-006; QK-TST-BENCH-003 | Worst-case parse-stage CPU on exact target | OPEN — VALUE NOT AUTHORIZED IN F1 | OPEN | OD-05 |
| QK-LIM-EXE-002 | Cleanup/zeroization completion time at session end, cancellation, failure, and shutdown | qk-core cleanup | QK-THR-018 remanence window | QK-REQ-PLT-004, QK-REQ-PLT-006; QK-TST-SAN-001, QK-TST-PWR-004 | Zeroization timing on exact target incl. failure paths | OPEN — VALUE NOT AUTHORIZED IN F1 | OPEN | OD-06 |
| QK-LIM-EXE-003 | Validation-stage time per hostile-input path | qk-core stage watchdog | QK-THR-016 CPU exhaustion | QK-REQ-PLT-006; QK-TST-BENCH-003 | Worst-case validation-stage CPU on exact target | OPEN — VALUE NOT AUTHORIZED IN F1 | OPEN | OD-05 |
| QK-LIM-EXE-004 | Review-construction/render-stage time | qk-core stage watchdog | QK-THR-016 CPU exhaustion | QK-REQ-PLT-006; QK-TST-BENCH-003 | Worst-case review/render CPU on exact target | OPEN — VALUE NOT AUTHORIZED IN F1 | OPEN | OD-05 |
| QK-LIM-EXE-005 | Total core-request deadline | qk-core request watchdog | QK-THR-016 aggregate stall below stage ceilings | QK-REQ-PLT-006; QK-TST-BENCH-003 | End-to-end request latency on exact target | OPEN — VALUE NOT AUTHORIZED IN F1 | OPEN | OD-05 |
| QK-LIM-EXE-006 | Finalization/serialization-stage time | qk-core output stage | QK-THR-016 CPU exhaustion | QK-REQ-PLT-006; QK-TST-BENCH-003 | Worst-case output-stage CPU on exact target | OPEN — VALUE NOT AUTHORIZED IN F1 | OPEN | OD-05 |
| QK-LIM-EXE-007 | Signature-verification-stage time | qk-core output stage | QK-THR-016 verification-work DoS | QK-REQ-PLT-006; QK-TST-BENCH-003 | Worst-case verification CPU on exact target | OPEN — VALUE NOT AUTHORIZED IN F1 | OPEN | OD-05 |

## Cross-limit invariants (checked arithmetic; non-normative restatement of QK-REQ-PSBT-007)

Individually safe limits can multiply into unsafe totals. When values are authorized, each product below must be recomputed with checked arithmetic and independently shown safe on the exact target; overflow anywhere fails closed:

- PSBT: input count × per-input map entries, output count × per-output map entries, and their sum vs. aggregate map entries (QK-LIM-PSBT-003 × 009, 004 × 010 vs. 020); map entries × max key/value length vs. total PSBT bytes and parser arena (007/008 × 020 vs. 001, MEM-004); prevtx inputs/outputs × prevtx bytes vs. validation work (021/022/023 vs. 013/017).
- QR: unique parts × per-frame payload vs. total decoded bytes (QK-LIM-QR-002 × 003 vs. 001); total frames processed × per-frame decode time vs. scan session duration (010 × 007 vs. 004); concurrent streams × reassembly memory vs. arena (012 × 009 vs. MEM-010).
- SD: entries examined × metadata reads per entry vs. metadata read ceiling and parse time (QK-LIM-SD-002 vs. 003/009).
- A1: candidates per session × correction time per candidate vs. capture session duration (QK-LIM-A1-008 × 010 vs. 006); candidates × iterations vs. pipeline memory (008 × 009 vs. 007, MEM-012).
- Kit: QR attempts × candidates per capture × work per candidate vs. scan-session duration (QK-LIM-KIT-003 × 007 × 008 vs. 005); fallback submissions × exact symbols vs. session work (004 × 002); combine attempts × exact frame bytes vs. scanner arena and cleanup work (011 × 001 vs. 012); print attempts × artifact bytes vs. bounded setup output work (010 × 009); raw image bytes and candidate state vs. camera and scanner arenas (006/007 vs. MEM-010, KIT-012).
- APDU: commands per session × command/response bytes vs. aggregate session bytes (QK-LIM-APDU-008 × 001/004 vs. 010).
- TUI: pages × items per page and items × glyphs vs. total reviewable outputs and render budgets (QK-LIM-TUI-001 × 002, 002 × 008 vs. PSBT-014).
- IPC: message rate × message size × session duration vs. aggregate session bytes (QK-LIM-IPC-002 × 001 vs. 005).
- EXE: sum of stage times (parse + validation + review/render + finalization/serialization + signature verification) vs. the total core-request deadline (QK-LIM-EXE-001+003+004+006+007 vs. 005).

## Bound duplicate concepts (anti-drift)

- QK-LIM-APDU-006 (card derivation index ceiling) is bound to QK-LIM-PSBT-011 (canonical wallet child-index ceiling): one owner-authorized value governs both rows; they may never diverge.
- QK-LIM-TUI-004/005 (review recipient/change capacities) are bound to QK-LIM-PSBT-018/019 (accepted PSBT review sublimits): the review UI may never advertise capacity the PSBT acceptance path does not enforce, or vice versa.

## Registry rules (non-normative summary)

- 133 rows. No row may be relied on in production until its value is Owner-authorized.
- An authorized value change requires a new version of the row, fresh freeze evidence, and a new owner decision.
- Conflicting QR frame content fails the transfer immediately; no limit row grants an allowance for accepting conflicting content.
- Rejection of over-limit input must be fail-closed and user-visible (QK-REQ-HF-003).
