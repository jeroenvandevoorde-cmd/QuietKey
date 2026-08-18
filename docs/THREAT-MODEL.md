# QuietKey Threat Model

EXPERIMENTAL — NO REAL FUNDS — NOT A WALLET

Status: DRAFT — architecture foundation only. This document defines the threat landscape for the selected architecture (`ARCHITECTURE.md`). It invents no new controls; controls referenced here are exactly those already selected in QK-DEC-001…014, all unvalidated.

## Assets

- Seed entropy A, B, C (three independent 256-bit values → 24-word BIP39 mnemonics).
- A2 document key (independent 256-bit value).
- D descriptor pair and `wallet_id` (privacy-sensitive metadata; not spend authority).
- Funds spendable under `wsh(sortedmulti(2,A,B,C))`.
- Owner privacy: the fact that the owner holds bitcoin at all (the cloak).

## Custody objects

- A1 — Recovery Document (printed page carrying authenticated ciphertext of Seed-A entropy).
- B — Key Card (signer B + A2 + D).
- C — Emergency Card (signer C + A2 + D).
- Terminal — calculator-disguised, air-gapped device; retains no wallet secret between sessions.

## Trusted components

- The kernel, booted image, and physical display/keypad path in wallet mode (QK-DEC-010).
- `qk-core` as the sole secret-owning process.
- The user during an authorized session (physical possession is authorization; QK-DEC-006).

## Hostile inputs

All external bytes are hostile data, never instructions: PSBTs, QR payloads, microSD contents and filesystems, card responses (APDUs), attached peripherals, firmware/update images, external pages, repositories, documents, comments, fixtures, and tool output. Transport parsing is unprivileged (`qk-io`); the trusted core reparses and revalidates everything (QK-DEC-009).

## Attackers

- Opportunistic thief or burglar finding one custody object or the terminal.
- Targeted attacker who has recognized the cloak and searches for the remaining objects.
- Supplier of malicious PSBTs, QR streams, SD cards, peripherals, cards, or update images.
- Compromised or counterfeit terminal.
- Invasive laboratory attacker extracting card contents.
- Supply-chain attacker compromising cards, terminals, or firmware before delivery.
- Coercive attacker ($5 wrench).
- Future quantum-capable attacker.

## Security goals

- One custody object (or the terminal alone) must never satisfy the 2-of-3 spending threshold.
- A1 ciphertext without A2 must reveal nothing about Seed A beyond its existence to someone who has already defeated the cloak.
- Hostile transport bytes must never reach secret memory unvalidated, alter the reviewed transaction, or trigger signing without physical approval in the trusted core.
- Loss of any single object must leave a recovery path (see loss matrix in `ARCHITECTURE.md`), followed by rotation and sweep.
- The system must remain safe after the cloak is recognized: camouflage is a first defensive layer, never authentication or a substitute for cryptographic security.

## Threat coverage

Destruction or unavailability of an object (fire, loss, damage) is distinct from theft or compromise (an attacker holds or has extracted the object's contents). Unavailability threatens funds access; theft or compromise additionally exposes the object's secret material. After **any** loss or suspected compromise, the mandatory response is the same: use a surviving pair once, create a fresh A′/B′/C′/A2′/D′ wallet, and sweep all funds (QK-DEC-005).

Each threat below carries a stable identifier `QK-THR-NNN` for traceability (QK-THR-001…014 added in F1 with semantics unchanged from F0; QK-THR-015…020 appended in the F1 audit-correction pass; QK-THR-021 appended in the F1 semantic audit-correction pass).

- **QK-THR-001 — Destruction or unavailability of a single object (A1, B, C, or terminal)** — no secret exposure; funds remain recoverable via the surviving pair (see loss matrix in `ARCHITECTURE.md`), followed by mandatory rotation and sweep. The terminal holds no wallet secret between sessions.
- **QK-THR-002 — Theft of A1 alone** — exposes only authenticated ciphertext of Seed-A entropy (plus the cloaked document itself). Without A2 it yields no key material and cannot satisfy the spending threshold.
- **QK-THR-003 — Theft or extraction of B or C alone** — exposes that card's signing authority, A2, and D. This deanonymizes the wallet (D reveals all xpubs and `wallet_id`) and yields one signer, but not a spending threshold unless the attacker also obtains A1 or the other card. Because A2 is exposed, any A1 the attacker later obtains or has captured becomes decryptable — rotation and sweep are mandatory immediately.
- **QK-THR-004 — Theft of B or C plus A1 (or a captured copy of A1)** — full compromise: A2 from the stolen card decrypts A1 to Seed A; A plus the stolen B or C is a valid 2-of-3 spending threshold. The attacker can spend.
- **QK-THR-005 — Theft of a valid pair (B+C, or a card plus A1)** — the thief can spend. This is the accepted 2-of-3 design boundary; storage separation of B and C in different geographic/security domains is the selected mitigation.
- **QK-THR-006 — Malicious PSBT, QR, SD, card, peripheral, firmware, or update** — bounded unprivileged parsing in `qk-io`; trusted core reparses hostile bytes, constructs the exact review, owns physical approval, signs only after revalidation, and verifies signatures (QK-DEC-009/010). Boot/update properties are an OPEN decision.
- **QK-THR-007 — Malicious terminal during an authorized two-factor session** — inside the authorization trust boundary. 2-of-3 is not claimed to protect against such a terminal obtaining a threshold during that session (QK-DEC-006).
- **QK-THR-008 — Invasive card extraction** — a laboratory attacker who extracts one card obtains that card's signing authority, A2, and D: enough to deanonymize the wallet, and — if the attacker also obtains or has captured A1 — enough to decrypt Seed A and form a valid spending threshold (A plus the extracted signer), fully compromising the wallet. Extraction of one card with no access to A1 or the other card yields one signer and A2 but no threshold. Exact card extraction resistance is unvalidated and gated (Gate B). Rotation and sweep are mandatory on any suspected extraction.
- **QK-THR-009 — Supply-chain compromise** — of cards, terminal, or firmware; mitigations (attestation, reproducible builds, controlled builders) are selected directions requiring gate evidence, not achieved properties.
- **QK-THR-010 — Coercion** — an attacker coercing the owner with access to a valid pair can spend; the cloak may reduce the chance of being targeted but provides no protection once coercion begins.
- **QK-THR-011 — Print damage and media degradation** — error correction on A1 provides availability only, never authenticity; storage/power failure behavior is gated (Gate D).
- **QK-THR-012 — User error** — mistake resistance is a design principle; fail-closed ceremonies (e.g., dice transcripts) and mandatory rehearsals (Gate E) address it; no fool-proof claim is permitted.
- **QK-THR-013 — Future quantum risk** — 24 words are not quantum-proof. Posture is exposure reduction and a reviewed sweep/migration plan, with no post-quantum security claim before Bitcoin consensus support (QK-DEC-012).
- **QK-THR-014 — Camouflage vs. cryptographic security** — the cloak (benign-looking document, bus-pass cards, calculator terminal) counters discovery and casual search only. All confidentiality and spend-authority guarantees rest on the cryptography and the 2-of-3 threshold, which must hold after full cloak recognition.

### Precision refinements (append-only, added in the F1 audit-correction pass)

QK-THR-015…020 are precision refinements of the broad F0 threats above (chiefly QK-THR-001, 006, 009, 011, 012). They restate existing threat surface at requirement granularity for traceability; they introduce no new claims and no new controls, and remain DRAFT and unvalidated like everything else in this document.

- **QK-THR-015 — Entropy failure** — entropy-source failure, correlation between supposedly independent values, source substitution, dice-transcript reuse, or capture of a dice transcript before its destruction; a stateless terminal cannot prove non-reuse of a transcript across prior wallets or sessions, so cross-session duplicate detection cannot be claimed (refines QK-THR-009/012 for generation ceremonies).
- **QK-THR-016 — Parser and resource abuse** — parser ambiguity, oversized or pathological inputs, resource exhaustion, or denial of service on any hostile-input path (refines QK-THR-006).
- **QK-THR-017 — Substitution and binding failure** — substitution of descriptors, documents, card roles, wallets, or transactions, or failure of the bindings (AAD, `wallet_id`, roles, review fidelity) meant to prevent it (refines QK-THR-006).
- **QK-THR-018 — Secret remanence and leakage** — secret material remaining or leaking through memory, framebuffer, camera/DMA paths, IPC, logs, swap, or crash data (refines QK-THR-006/008).
- **QK-THR-019 — Interruption inconsistency** — interruption causing partial persistent state, stale approval or session reuse, media inconsistency, or input overwrite (refines QK-THR-001/011).
- **QK-THR-020 — Recovery-knowledge loss** — loss of D or descriptor metadata, or heirs/owner misunderstanding the recovery procedure (refines QK-THR-001/012).
- **QK-THR-021 — A2 disclosure independent of card theft** — A2 becomes known to an attacker without any card being stolen (e.g., leakage during provisioning or printing, later card compromise that is not noticed, or disclosure through the rescue environment). Any captured, photographed, or publicly exposed A1 — past or future — then becomes decryptable signer-A material. Consequences span privacy (wallet deanonymization when combined with D), availability (the owner must retire A1 as a safe factor), and spend risk (a disclosed A2 plus any A1 copy plus one card forms a threshold). The mandatory posture is rotation and sweep on any suspected A2 disclosure; no requirement claims this threat is mitigated.


## Structured threat register

The register below restates each threat in auditable form. It is DRAFT like everything in this document; a status of PLANNED CONTROL means only that controls are planned and unvalidated — no threat is mitigated, resolved, or validated. Allowed statuses: OPEN, PLANNED CONTROL, ACCEPTED LIMITATION, OUT OF SCOPE. Linked requirements and planned tests are derived mechanically from `docs/REQUIREMENTS.md`.

| ID | Scenario / prerequisites / capability | Assets and boundary | Impact (C/I/A/Privacy) | Linked requirements | Planned tests | Gate(s) | Status | Residual risk |
|---|---|---|---|---|---|---|---|---|
| QK-THR-001 | Fire, loss, damage, or unavailability of a single custody object or the terminal; no attacker capability required | Availability of funds access; no secret exposure | A | QK-REQ-CARD-002, QK-REQ-CARD-005, QK-REQ-CARD-006, QK-REQ-PLT-001, QK-REQ-REC-001, QK-REQ-REC-004, QK-REQ-REC-006 | QK-TST-AUD-003, QK-TST-BENCH-002, QK-TST-BENCH-005, QK-TST-PROP-005, QK-TST-PWR-002, QK-TST-PWR-004, QK-TST-REH-001, QK-TST-REH-002, QK-TST-REH-004, QK-TST-SAN-003 | Gate B, Gate C, Gate E | PLANNED CONTROL | Surviving-pair recovery is itself a one-time, unrehearsed-until-Gate-E path; loss of a second object before rotation removes recovery |
| QK-THR-002 | Thief or finder holds the printed A1 alone; no A2 | A1 ciphertext; cloak boundary | C (ciphertext existence), P | QK-REQ-CUS-003, QK-REQ-A1-001, QK-REQ-A1-002, QK-REQ-A1-003, QK-REQ-A1-010 | QK-TST-AUD-001, QK-TST-AUD-006, QK-TST-CORP-004, QK-TST-DIFF-001, QK-TST-PROP-001, QK-TST-PROP-003, QK-TST-UNIT-001 | Gate A, Gate C | PLANNED CONTROL | Holder learns a cloaked document exists; if A2 is ever disclosed later (QK-THR-021), this capture becomes signer-A material |
| QK-THR-003 | Thief or lab attacker holds/extracts one card; obtains one signer, A2, and D | One signing authority; A2; D; privacy boundary | C, P (deanonymization); spend only with another factor | QK-REQ-CUS-002, QK-REQ-CUS-003, QK-REQ-CUS-004, QK-REQ-CARD-001, QK-REQ-CARD-003, QK-REQ-REC-002 | QK-TST-AUD-001, QK-TST-AUD-003, QK-TST-AUD-004, QK-TST-BENCH-002, QK-TST-PROP-003, QK-TST-PROP-004, QK-TST-REH-003, QK-TST-UNIT-002, QK-TST-UNIT-007 | FOUNDATION, Gate B, Gate C, Gate E | PLANNED CONTROL | One signer plus A2 is permanently exposed; safety then rests entirely on timely rotation and sweep |
| QK-THR-004 | Attacker holds one card plus A1 (or captured copy); decrypts Seed A and forms a threshold | Seed A; spending threshold | C, I, A — full compromise; attacker can spend | QK-REQ-CUS-002, QK-REQ-ENT-001, QK-REQ-ENT-002, QK-REQ-REC-002, QK-REQ-REC-003 | QK-TST-AUD-004, QK-TST-PROP-004, QK-TST-REH-003, QK-TST-UNIT-008 | Gate B, Gate C, Gate E | PLANNED CONTROL | None once the pair is held: this is full compromise; only prior storage separation and rotation speed matter |
| QK-THR-005 | Attacker obtains any valid pair (B+C, or a card plus A1) | Spending threshold | C, I, A — attacker can spend | QK-REQ-CUS-001, QK-REQ-CUS-008, QK-REQ-CUS-009 | QK-TST-AUD-008, QK-TST-DIFF-003, QK-TST-HF-003, QK-TST-REH-001 | FOUNDATION, Gate C | ACCEPTED LIMITATION | Accepted 2-of-3 design boundary; storage-separation instructions reduce likelihood only |
| QK-THR-006 | Supplier of hostile PSBT/QR/SD/card/peripheral/firmware bytes reaches a parser | All hostile-input paths; qk-io/qk-core boundary | I (transaction substitution), A (DoS), C (exfil via outputs) | QK-REQ-CUS-006, QK-REQ-A1-003, QK-REQ-A1-004, QK-REQ-A1-006, QK-REQ-CARD-004, QK-REQ-PSBT-001, QK-REQ-PSBT-002, QK-REQ-PSBT-003, QK-REQ-PSBT-004, QK-REQ-PSBT-005, QK-REQ-PSBT-006, QK-REQ-TRN-001, QK-REQ-TRN-003, QK-REQ-TRN-004, QK-REQ-TRN-005, QK-REQ-TRN-006, QK-REQ-TRN-007, QK-REQ-TUI-002, QK-REQ-PLT-003, QK-REQ-PLT-004, QK-REQ-PLT-005, QK-REQ-PLT-006, QK-REQ-PLT-009, QK-REQ-PLT-010, QK-REQ-HF-003, QK-REQ-ASR-005 | QK-TST-AUD-001, QK-TST-BENCH-001, QK-TST-BENCH-003, QK-TST-CORP-001, QK-TST-CORP-002, QK-TST-CORP-003, QK-TST-CORP-004, QK-TST-CORP-005, QK-TST-CORP-006, QK-TST-DIFF-002, QK-TST-DIFF-003, QK-TST-DIFF-004, QK-TST-FUZZ-001, QK-TST-FUZZ-002, QK-TST-FUZZ-003, QK-TST-FUZZ-004, QK-TST-FUZZ-005, QK-TST-HF-002, QK-TST-PROP-001, QK-TST-PROP-002, QK-TST-REH-001, QK-TST-REH-004, QK-TST-SAN-001, QK-TST-SAN-003, QK-TST-UNIT-001, QK-TST-UNIT-002, QK-TST-UNIT-005, QK-TST-UNIT-006, QK-TST-UNIT-009, QK-TST-UNIT-010 | Gate A, Gate B, Gate C | PLANNED CONTROL | Parser correctness is unproven until Gate C evidence; boot/update parsing ownership remains OPEN (OD-06) |
| QK-THR-007 | Malicious or compromised terminal during an authorized two-factor session | Session secrets; review/approval channel | C, I — forged review/approval within the session | QK-REQ-PSBT-003, QK-REQ-TUI-001, QK-REQ-TUI-004, QK-REQ-PLT-002 | QK-TST-AUD-001, QK-TST-PROP-002, QK-TST-REH-001, QK-TST-UNIT-013 | FOUNDATION, Gate C | ACCEPTED LIMITATION | Explicit non-claim (QK-REQ-TUI-004); nothing protects the session once the terminal is malicious |
| QK-THR-008 | Invasive laboratory extraction of card contents | Card payload (signer, A2, D) | C, P; spend only with another factor | QK-REQ-CUS-003, QK-REQ-CARD-001, QK-REQ-PLT-004 | QK-TST-AUD-001, QK-TST-AUD-003, QK-TST-BENCH-002, QK-TST-PROP-003, QK-TST-SAN-003, QK-TST-UNIT-010 | Gate B, Gate C | PLANNED CONTROL | Extraction resistance is unvalidated until Gate B; detection may never occur, delaying rotation |
| QK-THR-009 | Supply-chain compromise of cards, terminal, firmware, toolchain, or build environment | Entire trust base | C, I, A — arbitrary | QK-REQ-ENT-004, QK-REQ-PLT-008, QK-REQ-PLT-012, QK-REQ-ASR-002, QK-REQ-ASR-004, QK-REQ-ASR-007, QK-REQ-ASR-008 | QK-TST-AUD-001, QK-TST-AUD-002, QK-TST-AUD-004, QK-TST-AUD-005, QK-TST-AUD-007, QK-TST-REH-001, QK-TST-SAN-002 | FOUNDATION, Gate C | PLANNED CONTROL | Reproducible-build/attestation directions are unvalidated; a compromised builder defeats them |
| QK-THR-010 | Coercive attacker with access to the owner and a valid pair | Owner; spending threshold | C, I, A — attacker can spend | NONE — explicit exclusion (see Non-goals and docs/TRACEABILITY.md) | NONE | NONE | OUT OF SCOPE | Stated non-goal; cloak may reduce targeting but no control exists once coercion begins |
| QK-THR-011 | Print damage, media degradation, aging, corruption of A1/SD/cards | Availability of recovery artifacts | A | QK-REQ-A1-005, QK-REQ-A1-009, QK-REQ-CARD-005, QK-REQ-TRN-002, QK-REQ-REC-005 | QK-TST-BENCH-002, QK-TST-BENCH-004, QK-TST-CORP-004, QK-TST-CORP-006, QK-TST-PWR-001, QK-TST-PWR-002, QK-TST-PWR-003, QK-TST-REH-006, QK-TST-UNIT-009 | Gate A, Gate B, Gate D | PLANNED CONTROL | Error correction is availability-only; severe damage still destroys the artifact |
| QK-THR-012 | Owner or heir mistakes during ceremonies, review, or recovery | All ceremonies and review decisions | C, I, A depending on the error | QK-REQ-CUS-005, QK-REQ-CUS-007, QK-REQ-ENT-003, QK-REQ-ENT-005, QK-REQ-A1-009, QK-REQ-TUI-003, QK-REQ-REC-005, QK-REQ-HF-001, QK-REQ-HF-002, QK-REQ-HF-003, QK-REQ-HF-004, QK-REQ-ASR-003, QK-REQ-ASR-008 | QK-TST-AUD-001, QK-TST-AUD-002, QK-TST-AUD-004, QK-TST-AUD-005, QK-TST-BENCH-003, QK-TST-CORP-001, QK-TST-CORP-006, QK-TST-DIFF-003, QK-TST-HF-001, QK-TST-HF-002, QK-TST-HF-003, QK-TST-PWR-001, QK-TST-REH-006, QK-TST-UNIT-003, QK-TST-UNIT-004 | FOUNDATION, Gate A, Gate C, Gate D, Gate E | PLANNED CONTROL | No fool-proof claim permitted; human-trial thresholds remain OPEN (OD-07) |
| QK-THR-013 | Future quantum-capable attacker against exposed public keys | Long-term spendability | C (key exposure), A/I (theft at quantum break) | QK-REQ-ASR-001, QK-REQ-ASR-006, QK-REQ-ASR-010 | QK-TST-AUD-001, QK-TST-AUD-002, QK-TST-REH-005 | FOUNDATION | PLANNED CONTROL | 24-word ECC keys are not quantum-safe; posture is exposure reduction plus a rehearsed sweep plan, nothing stronger |
| QK-THR-014 | Observer evaluates whether objects look like wallet artifacts | The cloak (privacy layer) | P | QK-REQ-A1-007, QK-REQ-A1-008, QK-REQ-CARD-002, QK-REQ-CARD-007, QK-REQ-PLT-001, QK-REQ-PLT-005, QK-REQ-PLT-007, QK-REQ-ASR-001, QK-REQ-ASR-009 | QK-TST-AUD-001, QK-TST-AUD-003, QK-TST-AUD-006, QK-TST-BENCH-002, QK-TST-CORP-006, QK-TST-HF-001, QK-TST-PROP-005, QK-TST-PWR-004, QK-TST-REH-001, QK-TST-SAN-003, QK-TST-UNIT-007 | FOUNDATION, Gate A, Gate B, Gate C | PLANNED CONTROL | Camouflage is discovery resistance only; all guarantees must survive full cloak recognition |
| QK-THR-015 | Entropy-source failure, correlation, substitution, transcript reuse or capture | Generation ceremonies; seed independence | C — predictable or correlated keys | QK-REQ-CUS-002, QK-REQ-ENT-001, QK-REQ-ENT-002, QK-REQ-ENT-003, QK-REQ-ENT-004, QK-REQ-ENT-005, QK-REQ-ENT-006, QK-REQ-ENT-007, QK-REQ-ENT-008, QK-REQ-ENT-009, QK-REQ-ENT-010, QK-REQ-ENT-011, QK-REQ-ENT-012, QK-REQ-A1-002 | QK-TST-AUD-001, QK-TST-AUD-004, QK-TST-AUD-009, QK-TST-DIFF-001, QK-TST-HF-003, QK-TST-PROP-004, QK-TST-UNIT-001, QK-TST-UNIT-004 | FOUNDATION, Gate A, Gate B, Gate C, Gate E | PLANNED CONTROL | Stateless terminal cannot prove cross-session transcript non-reuse; conditioner construction OPEN (OD-03) |
| QK-THR-016 | Pathological or oversized hostile inputs targeting parser resources | Every bounded input path | A (DoS), I (parser confusion) | QK-REQ-A1-006, QK-REQ-CARD-004, QK-REQ-PSBT-001, QK-REQ-PSBT-002, QK-REQ-PSBT-005, QK-REQ-PSBT-007, QK-REQ-PSBT-008, QK-REQ-TRN-001, QK-REQ-TRN-003, QK-REQ-TRN-005, QK-REQ-TRN-006, QK-REQ-TRN-009, QK-REQ-TRN-010, QK-REQ-TUI-003, QK-REQ-PLT-006, QK-REQ-PLT-009, QK-REQ-PLT-011, QK-REQ-HF-003, QK-REQ-ASR-005 | QK-TST-AUD-001, QK-TST-BENCH-001, QK-TST-BENCH-003, QK-TST-CORP-001, QK-TST-CORP-002, QK-TST-CORP-003, QK-TST-CORP-005, QK-TST-FUZZ-001, QK-TST-FUZZ-002, QK-TST-FUZZ-003, QK-TST-FUZZ-004, QK-TST-FUZZ-005, QK-TST-HF-002, QK-TST-PROP-002, QK-TST-PROP-007, QK-TST-SAN-001, QK-TST-SAN-003, QK-TST-SAN-004, QK-TST-UNIT-005, QK-TST-UNIT-006, QK-TST-UNIT-009 | Gate A, Gate B, Gate C, Gate D | PLANNED CONTROL | All limit values remain unauthorized; bounds are unproven until target measurement and owner approval |
| QK-THR-017 | Substitution of descriptors, documents, roles, wallets, transactions, or approval targets | Binding chain: AAD, wallet_id, roles, review, approval digest | I — signing the wrong thing | QK-REQ-CUS-006, QK-REQ-A1-004, QK-REQ-CARD-003, QK-REQ-CARD-009, QK-REQ-PSBT-006, QK-REQ-TUI-002, QK-REQ-PLT-010, QK-REQ-BND-001, QK-REQ-BND-002, QK-REQ-BND-003 | QK-TST-BENCH-002, QK-TST-CORP-001, QK-TST-CORP-004, QK-TST-CORP-005, QK-TST-CORP-006, QK-TST-DIFF-002, QK-TST-DIFF-003, QK-TST-FUZZ-001, QK-TST-HF-002, QK-TST-PROP-002, QK-TST-PROP-006, QK-TST-PWR-004, QK-TST-UNIT-001, QK-TST-UNIT-002, QK-TST-UNIT-007, QK-TST-UNIT-011 | Gate A, Gate B, Gate C | PLANNED CONTROL | Binding designs are unimplemented; TOCTOU windows unproven until Gate C evidence |
| QK-THR-018 | Secret remanence/leakage via memory, framebuffer, DMA, IPC, logs, swap, spool, crash data | Secret arenas; display path; print path | C | QK-REQ-ENT-012, QK-REQ-A1-010, QK-REQ-A1-011, QK-REQ-CARD-001, QK-REQ-PLT-001, QK-REQ-PLT-003, QK-REQ-PLT-004, QK-REQ-PLT-005, QK-REQ-PLT-008 | QK-TST-AUD-001, QK-TST-AUD-003, QK-TST-AUD-006, QK-TST-AUD-007, QK-TST-AUD-009, QK-TST-BENCH-002, QK-TST-CORP-004, QK-TST-CORP-006, QK-TST-HF-003, QK-TST-PROP-005, QK-TST-PWR-004, QK-TST-SAN-003, QK-TST-UNIT-010 | FOUNDATION, Gate A, Gate B, Gate C, Gate E | PLANNED CONTROL | Zeroization and remanence behavior are physical claims requiring exact-target evidence |
| QK-THR-019 | Interruption creating partial state, stale approvals, media inconsistency, or overwrite | Cards, media, sessions, approvals | I, A | QK-REQ-A1-009, QK-REQ-CARD-005, QK-REQ-CARD-008, QK-REQ-CARD-009, QK-REQ-CARD-010, QK-REQ-TRN-002, QK-REQ-TRN-008, QK-REQ-BND-003, QK-REQ-REC-005 | QK-TST-BENCH-002, QK-TST-CORP-003, QK-TST-CORP-005, QK-TST-CORP-006, QK-TST-PROP-006, QK-TST-PWR-001, QK-TST-PWR-002, QK-TST-PWR-003, QK-TST-PWR-004, QK-TST-PWR-005, QK-TST-REH-006, QK-TST-UNIT-007, QK-TST-UNIT-009 | Gate A, Gate B, Gate C, Gate D | PLANNED CONTROL | Card commit mechanism OPEN (OD-02); atomicity unproven until Gates B/D |
| QK-THR-020 | Loss of D/descriptor knowledge or heir misunderstanding | Recovery capability | A | QK-REQ-CUS-004, QK-REQ-CUS-007, QK-REQ-REC-001, QK-REQ-REC-006, QK-REQ-HF-002 | QK-TST-AUD-001, QK-TST-DIFF-003, QK-TST-HF-001, QK-TST-REH-001, QK-TST-REH-004, QK-TST-UNIT-002 | FOUNDATION, Gate A, Gate E | PLANNED CONTROL | Kit wording and executor instructions remain OPEN (OD-07) |
| QK-THR-021 | A2 disclosed without card theft (leak, unnoticed compromise, rescue exposure); any A1 copy becomes signer-A material | A2; every past/future A1 copy; privacy; spend threshold | C, P (deanonymization with D), A (A1 retired), spend with one card + any A1 copy | QK-REQ-A1-001, QK-REQ-CARD-001, QK-REQ-REC-007 | QK-TST-AUD-003, QK-TST-BENCH-002, QK-TST-DIFF-001, QK-TST-REH-003, QK-TST-UNIT-001 | Gate A, Gate B, Gate E | PLANNED CONTROL | Disclosure may never be detected; rotation depends on the owner suspecting it; captured A1 copies are irrevocable |

## Non-goals

- Protecting against theft of a valid pair, or against a compromised kernel/booted image.
- Protecting against a malicious terminal within an authorized session.
- Post-quantum security claims, anti-exfil, timelocks, or duress wallets (not in v1 profile).
- Availability under destruction of two or more custody objects.
