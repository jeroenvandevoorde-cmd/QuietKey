# QuietKey Test Architecture

**DRAFT — PENDING PROJECT-OWNER APPROVAL — NON-AUTHORITATIVE UNTIL CORRECTED F0 ARCHITECTURE IS APPROVED**

EXPERIMENTAL — NO REAL FUNDS — NOT A WALLET

This document records **verification plans only**. No test exists, no fixture exists, no corpus exists, and **no evidence exists or is claimed**. Planned test IDs `QK-TST-<METHOD>-NNN` are stable and never renumbered. Mapping rule: every SHALL/SHALL NOT requirement in `docs/REQUIREMENTS.md` maps to at least one planned test below or to a named physical/audit gate. Negative tests are required for every hostile-input path.

**Evidence never closes a gate automatically. Only an explicit owner gate decision, recorded in `docs/DECISION-LOG.md`, closes a gate.**

## Method families

| Family | Prefix | Character |
|---|---|---|
| Unit | QK-TST-UNIT | Deterministic behavior of one component |
| Property | QK-TST-PROP | Invariants over generated input spaces |
| Differential | QK-TST-DIFF | Agreement with independent implementations |
| Fuzz | QK-TST-FUZZ | Coverage-guided hostile input generation |
| Sanitizer/static | QK-TST-SAN | Memory/UB sanitizers, static analysis, code review tooling |
| Hostile corpus | QK-TST-CORP | Curated adversarial corpora with expected rejections |
| Target bench | QK-TST-BENCH | Measurement on the exact production hardware |
| Power cut | QK-TST-PWR | Interruption injection |
| Human factors | QK-TST-HF | Representative-user trials |
| Recovery rehearsal | QK-TST-REH | End-to-end recovery on production kit contents |
| Independent audit | QK-TST-AUD | External qualified review |

## Planned tests

### Unit

| ID | Plan |
|---|---|
| QK-TST-UNIT-001 | A1 capsule vectors: encrypt/decrypt round-trips, AAD binding (magic, versions, network, `wallet_id`), tag failure on any modification, fresh-nonce behavior. Negative: truncated/mutated capsule, wrong-wallet AAD, reused inputs. |
| QK-TST-UNIT-002 | Descriptor canonicalization and `wallet_id` computation; D-as-metadata classification. Negative: reordered/malformed descriptors. |
| QK-TST-UNIT-003 | 256-bit entropy → 24-word BIP39 mapping with empty passphrase against published vectors. Negative: bad checksum, wrong word count. |
| QK-TST-UNIT-004 | Dice transcript validation: exactly 100 d6 rolls per value, fail-closed on invalid characters, wrong counts, transcript reuse. |
| QK-TST-UNIT-005 | PSBT v0 accept/reject units: version gating, structural rules. Negative: v2, base64/hex input, empty/duplicate maps. |
| QK-TST-UNIT-006 | BBQr type-P reassembly units: framing, ordering, completion detection. Negative: wrong file type, compressed payloads. |
| QK-TST-UNIT-007 | Card role/lifecycle/session state machine and wallet-mode transitions (decoy termination, exclusive display/keypad ownership). Negative: role confusion (B presented as C), stale sessions. |
| QK-TST-UNIT-008 | Lifecycle guards: wrong card, wrong document (A1 of another wallet), wrong wallet, substituted or duplicate factors rejected; no missing-signer reissue path exists. |
| QK-TST-UNIT-009 | SD intake units: binary `.psbt` only, no autodetection, no input overwrite under retry. Negative: base64/hex/renamed files, name collisions. |
| QK-TST-UNIT-010 | Secret cleanup units: zeroization at session end, cancellation, failure, shutdown; nothing secret written to logs or persistent state. |

### Property

| ID | Plan |
|---|---|
| QK-TST-PROP-001 | Invariant: no A1 plaintext observable before successful authentication, across generated failure paths (corruption, truncation, wrong key, wrong AAD, interruption). |
| QK-TST-PROP-002 | Invariant: signing occurs only after trusted-core reparse, review construction from the core's own parse, and physical approval; the reviewed transaction equals the signed transaction. |
| QK-TST-PROP-003 | Invariant: no single custody object (or terminal state alone) yields material satisfying the 2-of-3 threshold. |
| QK-TST-PROP-004 | Invariant: A, B, C, A2 generation draws four independent values; no derivation of one from another or from a common master. |
| QK-TST-PROP-005 | Invariant: no wallet secret survives a session across restart, in any storage location, for generated session histories. |

### Differential

| ID | Plan |
|---|---|
| QK-TST-DIFF-001 | A1 capsule cross-checked by an independent implementation not derived from the reference (Gate A evidence input). |
| QK-TST-DIFF-002 | PSBT parsing, validation, signing, and finalized output vs. independent implementations; signature verification and independent parseability. |
| QK-TST-DIFF-003 | Descriptor, derivation (`m/48'/0'/0'/2'/{0,1}/*`), sortedmulti ordering, and address derivation vs. independent implementations. |

### Fuzz

| ID | Plan |
|---|---|
| QK-TST-FUZZ-001 | PSBT parser fuzzing (structure-aware), recorded corpora and results; enforced against QK-LIM-PSBT rows. |
| QK-TST-FUZZ-002 | QR/BBQr reassembly fuzzing including flooding, duplicates, out-of-order and mutated frames; enforced against QK-LIM-QR rows. |
| QK-TST-FUZZ-003 | SD filesystem/file intake fuzzing (hostile filesystem images); enforced against QK-LIM-SD rows. |
| QK-TST-FUZZ-004 | APDU response parser fuzzing (hostile card); enforced against QK-LIM-APDU rows. |
| QK-TST-FUZZ-005 | A1/OCR candidate and error-correction pipeline fuzzing; enforced against QK-LIM-A1 rows. |

### Sanitizer / static analysis

| ID | Plan |
|---|---|
| QK-TST-SAN-001 | Memory and undefined-behavior sanitizer runs across core and parsers under fuzz corpora; triaged findings. |
| QK-TST-SAN-002 | Static analysis with triaged findings, tracked to closure. |
| QK-TST-SAN-003 | Secret-memory handling review: allocation discipline, zeroization, no swap/leak paths, no secret logging, `qk-io` capability restriction — verified with tooling and code review on target. |

### Hostile corpus

| ID | Plan |
|---|---|
| QK-TST-CORP-001 | PSBT rejection corpus: malformed, oversized, truncated, duplicated, mutated, ambiguous inputs; policy, prevout, derivation, change, sighash, fee, and signature failures. Expected result: rejection with fail-closed UX, no partial processing. |
| QK-TST-CORP-002 | QR corpus: flooding, duplicate/conflicting frames, reassembly ambiguity, over-limit transfers. |
| QK-TST-CORP-003 | SD corpus: corrupt, full, read-only, mid-operation removal images; overwrite-attempt scenarios. |
| QK-TST-CORP-004 | A1 corpus: print corruption, multiple OCR candidates, authentication failures, OCR uncertainty, wrong-wallet capsules, error-correction-vs-authenticity separation. |
| QK-TST-CORP-005 | Card/APDU corpus: role/lifecycle/session violations, sequencing faults, malformed responses, counterfeit-card behavior. |
| QK-TST-CORP-006 | Cross-wallet and substitution corpus: wrong/missing/duplicate/substituted factors across two provisioned wallets; half-provisioned artifacts; prohibited persistence/logging probes. |

### Target bench

| ID | Plan |
|---|---|
| QK-TST-BENCH-001 | Actual-camera BBQr type-P limits and decode performance on the exact fixed hardware (Gate A evidence input). |
| QK-TST-BENCH-002 | Exact-card secp256k1 correctness/performance, derivation, RNG characterization, APDU behavior, write atomicity, endurance, independent B/C keys with same A2/D (Gate B evidence input). |
| QK-TST-BENCH-003 | Peak RAM/stack and worst-case CPU/time per hostile-input path on target — the measurement input for freezing every QK-LIM row (values remain OPEN until owner approval). |
| QK-TST-BENCH-004 | A1 print/capture decode trials on fixed mechanics across damage and aging conditions (Gate A evidence input). |

### Power cut

| ID | Plan |
|---|---|
| QK-TST-PWR-001 | Interruption injection during provisioning; no half-provisioned wallet, card, or A1 accepted in any state. |
| QK-TST-PWR-002 | Power-cut during card operations; consistent card state at every interruption point. |
| QK-TST-PWR-003 | Power-cut/removal during SD reads and writes; no input overwrite; recovery from corrupt/full/read-only/removed media. |
| QK-TST-PWR-004 | Restart and stale-session behavior after interruption: no secret residue, no resumed half-completed approval. |

### Human factors

| ID | Plan |
|---|---|
| QK-TST-HF-001 | A1 production and recovery trials with representative users against predefined thresholds (thresholds OPEN per OD-07). |
| QK-TST-HF-002 | Transaction review comprehension and over-limit/malformed rejection UX trials. |
| QK-TST-HF-003 | Ceremony error-rate trials (dice transcripts, provisioning) confirming fail-closed behavior with real users. |

### Recovery rehearsal

| ID | Plan |
|---|---|
| QK-TST-REH-001 | End-to-end rehearsals of A1+B, A1+C, and B+C on production kit contents by representative users. |
| QK-TST-REH-002 | Recovery on a replacement terminal. |
| QK-TST-REH-003 | Complete lost-factor rotation: one-time surviving-pair use, fresh A′/B′/C′/A2′/D′ wallet, full sweep; confirmation that no reissue path exists. |
| QK-TST-REH-004 | Rescue with commodity reader and open rescue tool; independent transaction finalization outside QuietKey tooling; acceptance by Bitcoin Core. |
| QK-TST-REH-005 | Quantum-threat migration rehearsal: review the versioned sweep/migration plan and rehearse it end-to-end with rehearsal wallets holding no real funds, verifying trigger criteria, ownership, plan versioning, sweep completeness, and that no post-quantum security or proprietary post-quantum script claim is made. |

### Independent audit

| ID | Plan |
|---|---|
| QK-TST-AUD-001 | Independent cryptographic and protocol review of the implemented core, trust boundaries, and prohibited-claims discipline. |
| QK-TST-AUD-002 | Supply-chain, reproducible-build, release-signing, update-substitution, and third-party-code-intake audit; governance rule that evidence never closes a gate. |
| QK-TST-AUD-003 | Exact-card applet lifecycle and extraction-resistance characterization (Gate B evidence input). |
| QK-TST-AUD-004 | Entropy source review: independence, conditioner specification and vectors, proof the release binary reaches intended sources, per-source failure testing. |
| QK-TST-AUD-005 | Evidence-record schema completeness audit: verify every recorded evidence item contains all schema fields (evidence ID, claim, level, source commit, spec version, planned test ID, environment, exact target identity where applicable — including the audit judging whether the "where applicable" condition was correctly applied — toolchain/dependency identity, procedure, raw-artifact location and cryptographic hashes, result, reviewer, date, limitations, affected gate, gate-decision reference), and that no gate status changed without an owner decision consuming the record. |
| QK-TST-AUD-006 | Camouflage presentation audit: verify A1 presents as an ordinary webpage printout, that no project component, tool, or documented procedure resolves, contacts, registers, or follows the apparent source URL, that cards present as ordinary bus-pass-style cards, that the terminal outside wallet mode presents only calculator behavior, and that no project material treats camouflage as authentication or a cryptographic guarantee. |

## Adversarial coverage checklist (all planned above)

Wrong/missing/duplicate/substituted factors (UNIT-007/008, CORP-006); cross-wallet combinations (CORP-006); malformed/oversized/ambiguous/truncated/duplicated/mutated inputs (CORP-001…005, FUZZ-001…005); PSBT policy/prevout/derivation/change/sighash/fee/signature failures (CORP-001, DIFF-002); QR flooding/reassembly (CORP-002, FUZZ-002); A1 corruption/multiple candidates/authentication/OCR uncertainty (CORP-004, FUZZ-005); card role/lifecycle/session/APDU faults (CORP-005, FUZZ-004, UNIT-007); entropy failure/reuse/correlation (PROP-004, UNIT-004, AUD-004); cancel/timeout/removal/restart/stale-session/power-cut (PWR-001…004, UNIT-007/010); SD corrupt/full/read-only/removal/no-overwrite (CORP-003, PWR-003, UNIT-009); secret cleanup and prohibited logging (UNIT-010, SAN-003, PROP-005, CORP-006); build/update/supply-chain substitution (AUD-002).

## Future evidence-record schema

Every future evidence record must contain the fields below (normative statement: QK-REQ-ASR-008 in `docs/REQUIREMENTS.md`; this section is its schema definition, not an independent normative claim):

| Field | Content |
|---|---|
| Evidence ID | Stable unique identifier |
| Claim | Exact claim the evidence supports |
| Evidence level | SPEC / REFERENCE-TESTED / HOST-TESTED / TARGET-TESTED / INDEPENDENTLY-AUDITED (per `docs/MATURITY-GATES.md`) |
| Source commit | Commit hash of the software under test |
| Specification version | Version of the requirement/spec verified |
| Planned test ID | The QK-TST identifier executed |
| Environment | Execution environment; **exact target hardware identity where applicable** |
| Toolchain/dependency identity | Compiler, tool, and dependency versions |
| Procedure | Steps performed |
| Raw artifacts | Location of raw artifacts and their cryptographic hashes |
| Result | Expected vs. actual outcome |
| Reviewer | Named reviewer |
| Date | Absolute date |
| Limitations | What the evidence does not show |
| Affected gate | Gate A–E or release blocker |
| Gate-decision reference | The owner decision-log entry (if any) that consumed this evidence |

An evidence record is an input to an owner gate decision — it never changes gate status by itself.
