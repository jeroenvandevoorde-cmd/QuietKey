# QuietKey Requirements Register

**DRAFT — PENDING PROJECT-OWNER APPROVAL — NON-AUTHORITATIVE UNTIL CORRECTED F0 ARCHITECTURE IS APPROVED**

EXPERIMENTAL — NO REAL FUNDS — NOT A WALLET

This register turns the selected, unvalidated architecture (`ARCHITECTURE.md`, QK-DEC-001…014, DRAFT) and threat model (`docs/THREAT-MODEL.md`, QK-THR-001…020) into numbered, testable requirements. Every requirement is DRAFT. Nothing here is implemented, validated, or evidence-backed. No requirement claims any threat is mitigated, resolved, or validated — requirements state what the future implementation SHALL satisfy and how satisfaction will one day be verified.

Conventions:

- IDs are `QK-REQ-<DOMAIN>-NNN`, stable, never renumbered; corrections are append-only.
- Each requirement contains exactly one SHALL or SHALL NOT.
- **Src** — source decision (`QK-DEC-…`). **Thr** — applicable threats (`QK-THR-…`). **Lim** — applicable resource-limit rows (`QK-LIM-…`, see `docs/RESOURCE-BUDGETS.md`) or `NONE` with rationale. **Tst** — planned verification (`QK-TST-…`, see `docs/TEST-ARCHITECTURE.md`). **Evidence** — evidence method family. **Gate** — Gate A–E or FOUNDATION (governance/release blocker).
- Security properties only; no implementation mechanisms or wire formats are specified here.
- Requirement text never contains an unescaped Markdown table separator; formulas use function notation (e.g., CONCAT) instead of raw concatenation operators.

## CUS — Custody

| ID | Requirement | Src | Thr | Lim | Tst | Evidence | Gate |
|---|---|---|---|---|---|---|---|
| QK-REQ-CUS-001 | The wallet policy SHALL be native SegWit P2WSH `wsh(sortedmulti(2,A,B,C))` on Bitcoin mainnet only. | QK-DEC-002, QK-DEC-003 | QK-THR-005 | NONE (policy definition, not a bounded input path) | QK-TST-DIFF-003, QK-TST-REH-001 | differential, recovery-rehearsal | Gate C |
| QK-REQ-CUS-002 | Signing authorities A, B, and C SHALL be independently generated, with C never a clone of B. | QK-DEC-002, QK-DEC-007 | QK-THR-003, QK-THR-004, QK-THR-015 | NONE (generation property, not an input path) | QK-TST-PROP-004, QK-TST-AUD-004 | property, independent-audit | Gate B |
| QK-REQ-CUS-003 | Possession of one custody object, or of the terminal alone, SHALL NOT satisfy the 2-of-3 spending threshold. | QK-DEC-002 | QK-THR-002, QK-THR-003, QK-THR-008 | NONE (threshold property, not an input path) | QK-TST-PROP-003, QK-TST-AUD-001 | property, independent-audit | Gate C |
| QK-REQ-CUS-004 | Descriptor metadata D SHALL be treated as recovery metadata and never as a signing factor. | QK-DEC-003 | QK-THR-003, QK-THR-020 | NONE (classification rule) | QK-TST-UNIT-002 | unit | FOUNDATION |
| QK-REQ-CUS-005 | Key derivation SHALL use `m/48'/0'/0'/2'/{0,1}/*` from 24-word English BIP39 mnemonics with a fixed empty passphrase. | QK-DEC-003 | QK-THR-012 | NONE (fixed profile, not an input path) | QK-TST-DIFF-003, QK-TST-UNIT-003 | differential, unit | Gate C |
| QK-REQ-CUS-006 | `wallet_id` SHALL be computed as `SHA256(CONCAT(canonical_receive_descriptor, 0x00, canonical_change_descriptor))`, the SHA-256 of the canonical receive descriptor, a single 0x00 separator byte, and the canonical change descriptor in that order. | QK-DEC-003 | QK-THR-006, QK-THR-017 | NONE (deterministic computation on already-parsed descriptor data) | QK-TST-UNIT-002, QK-TST-DIFF-003 | unit, differential | Gate C |
| QK-REQ-CUS-007 | Kit variants SHALL NOT change the 2-of-3 threshold, key material, derivation profile, card protocol, or recovery mathematics; variants may differ only in packaging, instructions, and descriptor-backup separation. | QK-DEC-011 | QK-THR-012, QK-THR-020 | NONE (packaging invariance rule, not an input path) | QK-TST-DIFF-003, QK-TST-AUD-001 | differential, independent-audit | FOUNDATION |

## ENT — Entropy

| ID | Requirement | Src | Thr | Lim | Tst | Evidence | Gate |
|---|---|---|---|---|---|---|---|
| QK-REQ-ENT-001 | A, B, C, and A2 SHALL each originate from an independently generated 256-bit entropy value. | QK-DEC-007 | QK-THR-004, QK-THR-015 | NONE (generation property) | QK-TST-PROP-004, QK-TST-AUD-004 | property, independent-audit | Gate B |
| QK-REQ-ENT-002 | The system SHALL NOT expand one common master secret into A, B, C, or A2. | QK-DEC-007 | QK-THR-004, QK-THR-015 | NONE (prohibition) | QK-TST-PROP-004 | property | Gate C |
| QK-REQ-ENT-003 | Advanced Physical mode SHALL fail closed on invalid characters, incorrect roll counts, or transcript reuse, requiring exactly 100 private d6 rolls per value across four new transcripts. | QK-DEC-007 | QK-THR-012, QK-THR-015 | NONE (fail-closed ceremony rule; transcript length fixed by decision) | QK-TST-UNIT-004, QK-TST-HF-003 | unit, human-factors | Gate C |
| QK-REQ-ENT-004 | Release evidence SHALL trace the actual linked binary to the intended hardware entropy sources and demonstrate detection of failure of each source. | QK-DEC-007 | QK-THR-009, QK-THR-015 | NONE (evidence obligation) | QK-TST-AUD-004 | independent-audit | Gate C |
| QK-REQ-ENT-005 | The project SHALL NOT claim entropy quality on the basis of runtime health checks. | QK-DEC-007 | QK-THR-012, QK-THR-015 | NONE (claims prohibition) | QK-TST-AUD-004 | independent-audit | FOUNDATION |

## A1 — Recovery Document capsule

| ID | Requirement | Src | Thr | Lim | Tst | Evidence | Gate |
|---|---|---|---|---|---|---|---|
| QK-REQ-A1-001 | The A1 capsule SHALL use IETF ChaCha20-Poly1305 with keys derived via HKDF-SHA256 (`IKM=A2`, `salt=wallet_id`, info `QuietKey/A1/v1`) over exactly the 32-byte Seed-A entropy. | QK-DEC-008 | QK-THR-002 | NONE (fixed cryptographic profile) | QK-TST-UNIT-001, QK-TST-DIFF-001 | unit, differential | Gate A |
| QK-REQ-A1-002 | Every new A1 encryption SHALL use a fresh random stored 96-bit nonce. | QK-DEC-008 | QK-THR-002, QK-THR-015 | NONE (cryptographic rule) | QK-TST-UNIT-001, QK-TST-AUD-001 | unit, independent-audit | Gate A |
| QK-REQ-A1-003 | The system SHALL NOT release A1 plaintext before successful authentication of the full 128-bit tag, under any failure path. | QK-DEC-008 | QK-THR-002, QK-THR-006 | NONE (invariant; bounded work is QK-REQ-A1-006) | QK-TST-PROP-001, QK-TST-CORP-004 | property, hostile-corpus | Gate A |
| QK-REQ-A1-004 | A1 AAD SHALL bind fixed magic, coding version, crypto version, Bitcoin network, and the full `wallet_id`. | QK-DEC-008 | QK-THR-006, QK-THR-017 | NONE (fixed AAD profile) | QK-TST-UNIT-001, QK-TST-CORP-004 | unit, hostile-corpus | Gate A |
| QK-REQ-A1-005 | A1 error correction SHALL NOT substitute for AEAD authenticity in any acceptance decision. | QK-DEC-008 | QK-THR-011 | NONE (separation-of-roles rule) | QK-TST-CORP-004, QK-TST-BENCH-004 | hostile-corpus, target-bench | Gate A |
| QK-REQ-A1-006 | A1 capture, OCR, candidate, and correction work SHALL be bounded by approved limits before any such parser is implemented. | QK-DEC-008, QK-DEC-009 | QK-THR-006, QK-THR-016 | QK-LIM-A1-001, QK-LIM-A1-002, QK-LIM-A1-003, QK-LIM-A1-004, QK-LIM-A1-005, QK-LIM-A1-006, QK-LIM-A1-007 | QK-TST-FUZZ-005, QK-TST-BENCH-003 | fuzz, target-bench | Gate A |
| QK-REQ-A1-007 | The printed A1 SHALL present as an ordinary webpage printout with plausible page content and an apparent source URL, carrying no wallet branding or key-related markings. | QK-DEC-004, QK-DEC-008 | QK-THR-014 | NONE (presentation property, not an input path) | QK-TST-AUD-006, QK-TST-HF-001 | independent-audit, human-factors | Gate A |
| QK-REQ-A1-008 | The apparent source URL printed on A1 SHALL NOT be resolved, contacted, registered, or followed by any project component, tool, or documented procedure. | QK-DEC-004 | QK-THR-014 | NONE (prohibition) | QK-TST-AUD-006 | independent-audit | FOUNDATION |

## CARD — Bearer cards

| ID | Requirement | Src | Thr | Lim | Tst | Evidence | Gate |
|---|---|---|---|---|---|---|---|
| QK-REQ-CARD-001 | Cards B and C SHALL store only the least-authority payload: BIP48 account xprv, chain code, origin data, role, A2, and D. | QK-DEC-006 | QK-THR-003, QK-THR-008, QK-THR-018 | NONE (payload definition; feasibility gated) | QK-TST-BENCH-002, QK-TST-AUD-003 | target-bench, independent-audit | Gate B |
| QK-REQ-CARD-002 | Cards SHALL NOT depend on a PIN, remembered password, terminal pairing, vendor account, phone-home, or online authentication; physical possession is authorization. | QK-DEC-006 | QK-THR-001, QK-THR-014 | NONE (dependency prohibition) | QK-TST-REH-001, QK-TST-AUD-003 | recovery-rehearsal, independent-audit | Gate B |
| QK-REQ-CARD-003 | B and C SHALL use the same applet with fixed, different roles and unique, independent signing keys. | QK-DEC-006 | QK-THR-003, QK-THR-017 | NONE (role/key property) | QK-TST-UNIT-007, QK-TST-BENCH-002 | unit, target-bench | Gate B |
| QK-REQ-CARD-004 | All APDU exchange sizes, sequencing, and session behavior SHALL be bounded by approved limits before card protocol implementation. | QK-DEC-009 | QK-THR-006, QK-THR-016 | QK-LIM-APDU-001, QK-LIM-APDU-002, QK-LIM-APDU-003, QK-LIM-APDU-004, QK-LIM-APDU-005, QK-LIM-APDU-006, QK-LIM-APDU-007 | QK-TST-FUZZ-004, QK-TST-CORP-005 | fuzz, hostile-corpus | Gate B |
| QK-REQ-CARD-005 | Card write operations SHALL preserve a consistent card state under power interruption at any point. | QK-DEC-006 | QK-THR-001, QK-THR-011, QK-THR-019 | NONE (atomicity property; mechanism OPEN per OD-02) | QK-TST-PWR-002, QK-TST-BENCH-002 | power-cut, target-bench | Gate B |
| QK-REQ-CARD-006 | Card content rescue SHALL be possible with a commodity reader and the open rescue tool. | QK-DEC-006 | QK-THR-001 | NONE (availability property; implementation OPEN per OD-02) | QK-TST-REH-004 | recovery-rehearsal | Gate B |
| QK-REQ-CARD-007 | Cards B and C SHALL present externally as ordinary bus-pass-style cards with no wallet branding or key-related markings. | QK-DEC-004, QK-DEC-006 | QK-THR-014 | NONE (presentation property, not an input path) | QK-TST-AUD-006, QK-TST-BENCH-002 | independent-audit, target-bench | Gate B |

## PSBT — Transaction processing

| ID | Requirement | Src | Thr | Lim | Tst | Evidence | Gate |
|---|---|---|---|---|---|---|---|
| QK-REQ-PSBT-001 | The system SHALL accept PSBT version 0 only. | QK-DEC-009 | QK-THR-006, QK-THR-016 | QK-LIM-PSBT-001 | QK-TST-UNIT-005, QK-TST-CORP-001 | unit, hostile-corpus | Gate C |
| QK-REQ-PSBT-002 | The trusted core SHALL reparse and revalidate all hostile transport bytes before any use in review or signing. | QK-DEC-009, QK-DEC-010 | QK-THR-006, QK-THR-016 | QK-LIM-PSBT-001, QK-LIM-PSBT-002, QK-LIM-PSBT-003, QK-LIM-PSBT-004, QK-LIM-PSBT-009, QK-LIM-PSBT-010, QK-LIM-PSBT-012, QK-LIM-PSBT-013 | QK-TST-PROP-002, QK-TST-FUZZ-001 | property, fuzz | Gate C |
| QK-REQ-PSBT-003 | The system SHALL sign only after trusted-core reparse, exact transaction review, and physical approval in the trusted core. | QK-DEC-009 | QK-THR-006, QK-THR-007 | NONE (ordering invariant; input bounds are QK-REQ-PSBT-005) | QK-TST-PROP-002, QK-TST-REH-001 | property, recovery-rehearsal | Gate C |
| QK-REQ-PSBT-004 | The system SHALL verify every produced signature and return independently parseable output. | QK-DEC-009 | QK-THR-006 | NONE (output correctness property) | QK-TST-DIFF-002, QK-TST-REH-004 | differential, recovery-rehearsal | Gate C |
| QK-REQ-PSBT-005 | All PSBT sizes, counts, lengths, depths, indexes, unknown-field budgets, parsing work, and reviewable output counts SHALL be bounded by approved limits before parser implementation. | QK-DEC-009 | QK-THR-006, QK-THR-016 | QK-LIM-PSBT-001, QK-LIM-PSBT-002, QK-LIM-PSBT-003, QK-LIM-PSBT-004, QK-LIM-PSBT-005, QK-LIM-PSBT-006, QK-LIM-PSBT-007, QK-LIM-PSBT-008, QK-LIM-PSBT-009, QK-LIM-PSBT-010, QK-LIM-PSBT-011, QK-LIM-PSBT-012, QK-LIM-PSBT-013, QK-LIM-PSBT-014 | QK-TST-FUZZ-001, QK-TST-BENCH-003 | fuzz, target-bench | Gate C |
| QK-REQ-PSBT-006 | The trusted core SHALL reject transactions with policy, prevout, derivation, change, sighash, fee, or signature inconsistencies. | QK-DEC-009 | QK-THR-006, QK-THR-017 | QK-LIM-PSBT-001 | QK-TST-CORP-001, QK-TST-DIFF-002 | hostile-corpus, differential | Gate C |

## TRN — Transport (QR / SD)

| ID | Requirement | Src | Thr | Lim | Tst | Evidence | Gate |
|---|---|---|---|---|---|---|---|
| QK-REQ-TRN-001 | microSD input SHALL be binary `.psbt` only, with no base64 or hex autodetection. | QK-DEC-009 | QK-THR-006, QK-THR-016 | QK-LIM-SD-001, QK-LIM-SD-002 | QK-TST-UNIT-009, QK-TST-CORP-003 | unit, hostile-corpus | Gate C |
| QK-REQ-TRN-002 | The system SHALL NOT overwrite any input file under any interruption, retry, or failure. | QK-DEC-009 | QK-THR-011, QK-THR-019 | NONE (prohibition; write behavior gated at Gate D) | QK-TST-UNIT-009, QK-TST-PWR-003 | unit, power-cut | Gate D |
| QK-REQ-TRN-003 | Animated QR input SHALL be uncompressed BBQr file type `P` only. | QK-DEC-009 | QK-THR-006, QK-THR-016 | QK-LIM-QR-001, QK-LIM-QR-003, QK-LIM-QR-006 | QK-TST-UNIT-006, QK-TST-BENCH-001 | unit, target-bench | Gate A |
| QK-REQ-TRN-004 | Transport parsing SHALL run unprivileged in `qk-io`, separate from the secret-owning core. | QK-DEC-009, QK-DEC-010 | QK-THR-006 | NONE (privilege-separation property; per-path bounds carried by the path requirements) | QK-TST-SAN-003, QK-TST-AUD-001 | sanitizer/static-analysis, independent-audit | Gate C |
| QK-REQ-TRN-005 | QR reassembly SHALL bound decoded bytes, frame counts, frame versions, decode time, candidate and conflict handling, reassembly work, and memory by approved limits before implementation. | QK-DEC-009 | QK-THR-006, QK-THR-016 | QK-LIM-QR-001, QK-LIM-QR-002, QK-LIM-QR-003, QK-LIM-QR-004, QK-LIM-QR-005, QK-LIM-QR-006, QK-LIM-QR-007, QK-LIM-QR-008, QK-LIM-QR-009 | QK-TST-FUZZ-002, QK-TST-CORP-002 | fuzz, hostile-corpus | Gate A |
| QK-REQ-TRN-006 | SD filesystem and file intake work SHALL be bounded by approved limits before implementation. | QK-DEC-009 | QK-THR-006, QK-THR-016 | QK-LIM-SD-001, QK-LIM-SD-002, QK-LIM-SD-003, QK-LIM-SD-004, QK-LIM-SD-005, QK-LIM-SD-006, QK-LIM-SD-007 | QK-TST-FUZZ-003, QK-TST-BENCH-003 | fuzz, target-bench | Gate C |

## TUI — Trusted review UI

| ID | Requirement | Src | Thr | Lim | Tst | Evidence | Gate |
|---|---|---|---|---|---|---|---|
| QK-REQ-TUI-001 | In wallet mode, the trusted display and keypad path SHALL be owned exclusively by `qk-core`. | QK-DEC-010 | QK-THR-007 | NONE (exclusive-ownership property) | QK-TST-UNIT-007, QK-TST-AUD-001 | unit, independent-audit | Gate C |
| QK-REQ-TUI-002 | The transaction review SHALL present exactly the transaction constructed by the trusted core's own reparse of the hostile bytes. | QK-DEC-009, QK-DEC-010 | QK-THR-006, QK-THR-017 | NONE (review-fidelity invariant) | QK-TST-PROP-002, QK-TST-HF-002 | property, human-factors | Gate C |
| QK-REQ-TUI-003 | Review pagination, per-page content, recipient and change counts, approval-hold and idle timeouts, and error-message length SHALL be bounded by approved limits before review implementation. | QK-DEC-009 | QK-THR-012, QK-THR-016 | QK-LIM-TUI-001, QK-LIM-TUI-002, QK-LIM-TUI-003, QK-LIM-TUI-004, QK-LIM-TUI-005, QK-LIM-TUI-006, QK-LIM-TUI-007 | QK-TST-HF-002, QK-TST-BENCH-003 | human-factors, target-bench | Gate C |
| QK-REQ-TUI-004 | The project SHALL NOT claim protection against a malicious terminal that obtains a threshold during an authorized two-factor session. | QK-DEC-006 | QK-THR-007 | NONE (claims prohibition) | QK-TST-AUD-001 | independent-audit | FOUNDATION |

## PLT — Platform and process separation

| ID | Requirement | Src | Thr | Lim | Tst | Evidence | Gate |
|---|---|---|---|---|---|---|---|
| QK-REQ-PLT-001 | The terminal SHALL retain no wallet secret between sessions. | QK-DEC-004, QK-DEC-006 | QK-THR-001, QK-THR-014, QK-THR-018 | NONE (persistence prohibition) | QK-TST-PROP-005, QK-TST-SAN-003, QK-TST-PWR-004 | property, sanitizer/static-analysis, power-cut | Gate C |
| QK-REQ-PLT-002 | `qk-decoy` SHALL be terminated before wallet mode takes exclusive control of the terminal. | QK-DEC-010 | QK-THR-007 | NONE (mode-transition property) | QK-TST-UNIT-007 | unit | Gate C |
| QK-REQ-PLT-003 | `qk-io` SHALL NOT access secret memory, cards, or the approval path. | QK-DEC-010 | QK-THR-006, QK-THR-018 | NONE (capability prohibition) | QK-TST-SAN-003, QK-TST-AUD-001 | sanitizer/static-analysis, independent-audit | Gate C |
| QK-REQ-PLT-004 | Secret memory SHALL be zeroized at session end, cancellation, failure, and shutdown. | QK-DEC-010 | QK-THR-006, QK-THR-008, QK-THR-018 | QK-LIM-EXE-002 | QK-TST-UNIT-010, QK-TST-SAN-003 | unit, sanitizer/static-analysis | Gate C |
| QK-REQ-PLT-005 | The system SHALL NOT log or persist secret material or wallet metadata outside the persistent state permitted by the lifecycle model. | QK-DEC-010 | QK-THR-006, QK-THR-014, QK-THR-018 | NONE (logging/persistence prohibition) | QK-TST-SAN-003, QK-TST-CORP-006 | sanitizer/static-analysis, hostile-corpus | Gate C |
| QK-REQ-PLT-006 | Heap, stack, secret-arena, parser-arena, core-IPC, execution-time, and cleanup budgets SHALL be bounded by approved limits before implementation. | QK-DEC-009, QK-DEC-010 | QK-THR-006, QK-THR-016 | QK-LIM-MEM-001, QK-LIM-MEM-002, QK-LIM-MEM-003, QK-LIM-MEM-004, QK-LIM-IPC-001, QK-LIM-IPC-002, QK-LIM-IPC-003, QK-LIM-EXE-001, QK-LIM-EXE-002 | QK-TST-BENCH-003, QK-TST-SAN-001 | target-bench, sanitizer/static-analysis | Gate C |
| QK-REQ-PLT-007 | Outside wallet mode, the terminal SHALL present only the calculator behavior of `qk-decoy`, with no wallet-revealing output, prompt, or artifact. | QK-DEC-004, QK-DEC-010 | QK-THR-014 | NONE (presentation property, not an input path) | QK-TST-AUD-006, QK-TST-UNIT-007 | independent-audit, unit | Gate C |

## REC — Recovery

| ID | Requirement | Src | Thr | Lim | Tst | Evidence | Gate |
|---|---|---|---|---|---|---|---|
| QK-REQ-REC-001 | The system SHALL support all three recovery paths: A1+B (normal), A1+C, and B+C (bypassing A). | QK-DEC-005 | QK-THR-001, QK-THR-020 | NONE (path availability property) | QK-TST-REH-001 | recovery-rehearsal | Gate E |
| QK-REQ-REC-002 | After any loss or suspected compromise of A1, B, or C, the procedure SHALL be one-time use of a surviving pair, creation of a completely fresh A′/B′/C′/A2′/D′ wallet, and a sweep of all funds. | QK-DEC-005 | QK-THR-003, QK-THR-004 | NONE (procedural mandate) | QK-TST-REH-003 | recovery-rehearsal | Gate E |
| QK-REQ-REC-003 | The system SHALL NOT reissue a missing signer into the existing descriptor. | QK-DEC-005 | QK-THR-004 | NONE (prohibition) | QK-TST-REH-003, QK-TST-UNIT-008 | recovery-rehearsal, unit | Gate E |
| QK-REQ-REC-004 | Recovery SHALL be possible on a replacement terminal with any valid pair. | QK-DEC-005, QK-DEC-006 | QK-THR-001 | NONE (availability property) | QK-TST-REH-002 | recovery-rehearsal | Gate E |
| QK-REQ-REC-005 | The system SHALL NOT accept a half-provisioned wallet, card, or A1 in any state. | QK-DEC-006, QK-DEC-009 | QK-THR-011, QK-THR-012, QK-THR-019 | NONE (acceptance prohibition; interruption behavior gated at Gate D) | QK-TST-PWR-001, QK-TST-CORP-006 | power-cut, hostile-corpus | Gate D |
| QK-REQ-REC-006 | Descriptor metadata D SHALL be recoverable whenever a valid recovery pair is available. | QK-DEC-003, QK-DEC-005 | QK-THR-001, QK-THR-020 | NONE (availability property) | QK-TST-REH-001, QK-TST-REH-004 | recovery-rehearsal | Gate E |

## HF — Human factors

| ID | Requirement | Src | Thr | Lim | Tst | Evidence | Gate |
|---|---|---|---|---|---|---|---|
| QK-REQ-HF-001 | Provisioning and recovery ceremonies SHALL fail closed on user error rather than proceeding with degraded input. | QK-DEC-001, QK-DEC-007 | QK-THR-012 | NONE (fail-closed principle) | QK-TST-UNIT-004, QK-TST-HF-003 | unit, human-factors | Gate E |
| QK-REQ-HF-002 | A1 production and recovery SHALL meet predefined human-trial thresholds with representative users (thresholds OPEN per OD-07). | QK-DEC-001 | QK-THR-012, QK-THR-020 | NONE (thresholds OPEN per OD-07) | QK-TST-HF-001 | human-factors | Gate A |
| QK-REQ-HF-003 | Rejection of over-limit or malformed input SHALL present a clear fail-closed outcome without partial processing. | QK-DEC-001, QK-DEC-009 | QK-THR-006, QK-THR-012, QK-THR-016 | QK-LIM-PSBT-001, QK-LIM-QR-001, QK-LIM-SD-001, QK-LIM-A1-001, QK-LIM-APDU-001 (representative rows; applies to every registry row) | QK-TST-CORP-001, QK-TST-HF-002 | hostile-corpus, human-factors | Gate C |
| QK-REQ-HF-004 | Project materials SHALL NOT describe QuietKey as fool-proof. | QK-DEC-001 | QK-THR-012 | NONE (claims prohibition) | QK-TST-AUD-001 | independent-audit | FOUNDATION |

## ASR — Assurance and governance

| ID | Requirement | Src | Thr | Lim | Tst | Evidence | Gate |
|---|---|---|---|---|---|---|---|
| QK-REQ-ASR-001 | The project SHALL NOT describe QuietKey as secure, production-ready, validated, audited, or quantum-proof while any required gate is OPEN. | QK-DEC-014, QK-DEC-012 | QK-THR-013, QK-THR-014 | NONE (claims prohibition) | QK-TST-AUD-001 | independent-audit | FOUNDATION |
| QK-REQ-ASR-002 | Production releases SHALL require exact-target evidence, reproducible builds on controlled builders, external review, and complete recovery rehearsals. | QK-DEC-014 | QK-THR-009 | NONE (release precondition) | QK-TST-AUD-002, QK-TST-SAN-002, QK-TST-REH-001 | independent-audit, sanitizer/static-analysis, recovery-rehearsal | FOUNDATION |
| QK-REQ-ASR-003 | Evidence SHALL NOT close a gate automatically; only an explicit owner gate decision recorded in the decision log closes a gate. | QK-DEC-014 | QK-THR-012 | NONE (governance rule) | QK-TST-AUD-002 | independent-audit | FOUNDATION |
| QK-REQ-ASR-004 | Third-party code SHALL NOT enter the repository without a recorded exact commit, license, provenance, purpose, and review status. | QK-DEC-013 | QK-THR-009 | NONE (intake rule) | QK-TST-AUD-002 | independent-audit | FOUNDATION |
| QK-REQ-ASR-005 | Every hostile-input parser SHALL be fuzzed with recorded corpora and results before release. | QK-DEC-014 | QK-THR-006, QK-THR-016 | QK-LIM-PSBT-001, QK-LIM-QR-001, QK-LIM-SD-001, QK-LIM-A1-001, QK-LIM-APDU-001 (one representative row per parser family) | QK-TST-FUZZ-001, QK-TST-FUZZ-002, QK-TST-FUZZ-003, QK-TST-FUZZ-004, QK-TST-FUZZ-005 | fuzz | Gate C |
| QK-REQ-ASR-006 | The project SHALL NOT claim post-quantum security before Bitcoin supports an appropriate consensus spend condition. | QK-DEC-012 | QK-THR-013 | NONE (claims prohibition) | QK-TST-AUD-001 | independent-audit | FOUNDATION |
| QK-REQ-ASR-007 | Update and build integrity SHALL be verifiable against supply-chain substitution before release (boot/update/rollback properties themselves remain OPEN per OD-06). | QK-DEC-014 | QK-THR-009 | NONE (properties OPEN per OD-06) | QK-TST-AUD-002 | independent-audit | FOUNDATION |
| QK-REQ-ASR-008 | Every evidence record SHALL contain all fields of the evidence-record schema in `docs/TEST-ARCHITECTURE.md`, including exact target identity where applicable, raw-artifact cryptographic hashes, limitations, and the gate-decision reference. | QK-DEC-014 | QK-THR-009, QK-THR-012 | NONE (record-keeping rule, not an input path) | QK-TST-AUD-005 | independent-audit | FOUNDATION |
| QK-REQ-ASR-009 | The project SHALL treat camouflage solely as discovery resistance, never as authentication, access control, or a cryptographic guarantee. | QK-DEC-004, QK-DEC-014 | QK-THR-014 | NONE (claims/classification rule) | QK-TST-AUD-001, QK-TST-AUD-006 | independent-audit | FOUNDATION |
| QK-REQ-ASR-010 | The project SHALL maintain a versioned, owner-reviewed, rehearsal-tested sweep/migration plan for execution upon a material change in Bitcoin's quantum threat model, without claiming any proprietary post-quantum script. | QK-DEC-012 | QK-THR-013 | NONE (governance/plan obligation) | QK-TST-REH-005, QK-TST-AUD-002 | recovery-rehearsal, independent-audit | FOUNDATION |

## Coverage notes (non-normative)

- QK-THR-005 (theft of a valid pair) and QK-THR-010 (coercion) are accepted design boundaries per `docs/THREAT-MODEL.md` Non-goals; the traceability matrix records them as explicit exclusions with the storage-separation guidance of QK-DEC-005 as the selected (non-normative) mitigation posture.
- QK-THR-015…020 are append-only precision refinements of QK-THR-001…014 added in the F1 audit-correction pass; they introduce no new claims.
- Every requirement above is DRAFT and unimplemented; no verification has been run and no evidence exists.
