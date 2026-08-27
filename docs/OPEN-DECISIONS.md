# QuietKey Open Decisions

EXPERIMENTAL — NO REAL FUNDS — NOT A WALLET

This file records only genuinely open decisions. The fixed profiles are **not** reopened here: custody topology, Bitcoin/mainnet profile, derivation, 24-word mnemonic model, PSBT v0, BBQr type `P` QR format, and binary `.psbt` SD encoding are settled in `ARCHITECTURE.md` (owner-approved at baseline H0 `c618407a3900657d8ce4c479c4056f859f86bec6`, QK-APR-2026-08-18-001 in `docs/DECISION-LOG.md`). Every decision below remains unresolved; CANDIDATE labels remain hypotheses.

Recommendations below are labeled `CANDIDATE`. A CANDIDATE is a hypothesis: never implemented, never validated. Only explicit owner approval plus a `docs/DECISION-LOG.md` entry resolves an open decision.

## OD-01 — Production toolchain

Contingent on ARMv6/target evidence. `CANDIDATE`: Rust plus a narrow pinned `libsecp256k1` C boundary, with a measured all-C fallback only if necessary. No production language has been selected.

## OD-02 — Exact card — **STOP-BEFORE-F3**

Card model, capabilities, applet lifecycle, APDU byte layouts, optional offline attestation, and rescue implementation. No card has been selected; feasibility is Gate B. `CANDIDATE` (hypothesis only, never validated): signer material non-exportable from the card in normal operation, with signing performed on-card — which would make QK-TST-BENCH-005 runnable and would constrain the rescue path (Gate B rescue evidence cannot even be defined until this resolves). Note: the architecture deliberately uses **no PIN or pairing secret** (QK-REQ-CARD-002), so card possession alone yields whatever the card exposes — the export model is therefore the single most consequential open property of the card. Also open: the commit mechanism realizing the abstract lifecycle states of QK-REQ-CARD-008/009/010, and how D and A2 are read by the rescue tool. This decision must resolve before any F3 profile work depends on card behavior.

## OD-03 — Production entropy sources — **STOP-BEFORE-F3**

Exact hardware sources, health-check implementation, independence evidence, and proof that the release binary actually reaches the intended sources. Runtime health checks cannot prove entropy. QK-DEC-113 closes only the byte-exact QKEC-1 conditioner mathematics and HOST dice-transcript parser: source selection and independence, per-source failure semantics, what "source degraded" means operationally, real transcript secrecy/destruction, terminal cross-run nonce generation and freshness, and all source-reachability or target evidence remain open.

## OD-04 — A1 physical codec parameters

Reed–Solomon parameters, base32 alphabet, checksum, URL-like format details, font, OCR pipeline, and print/scan trial thresholds. The visual codec is explicitly not frozen (custom URL-like format, not Bech32).

## OD-05 — Transport resource ceilings, review layout, and PSBT authorization profile — **STOP-BEFORE-F9** (PSBT policy)

Exact values for every `OPEN — VALUE NOT AUTHORIZED IN F1` row in `docs/RESOURCE-BUDGETS.md` tagged OD-05, plus filesystem choice and transaction review layout. The v1 fee-warning policy is fixed by QK-DEC-110, and the M25 final filenames and temporary suffix are fixed by QK-DEC-112; their physical-target evidence obligations and any future policy/version change remain governed by those rows. Authorization profile per value (all required before any value freezes): representative and adversarial corpora; peak RAM/stack and worst-case CPU/time on the exact target (QK-TST-BENCH-003); camera/display usability where applicable; human-trial review-accuracy data for review-facing limits (QK-TST-HF-002); documented safety margin; rejection UX definition; cross-limit checked-arithmetic invariants recomputed (see the invariants section of the budget registry); bound rows (APDU-006↔PSBT-011, TUI-004/005↔PSBT-018/019) frozen together; owner decision recorded in `docs/DECISION-LOG.md`. Measurement alone — including everything F2 produces — authorizes nothing.

**Unresolved PSBT v0 authorization profile — STOP-BEFORE-F9.** QK-REQ-PSBT-006 deliberately names the rejection classes generically; the exact PSBT v0 authorization policy behind them is an open, owner-reviewed decision that must be specified — and recorded in `docs/DECISION-LOG.md` — before any F9 signing work begins. No answer below is selected in F1; this list only enumerates what must be decided:

- required UTXO data per input, and the `witness_utxo` versus `non_witness_utxo`/full-previous-transaction rules;
- outpoint/prevout reconstruction and script/value consistency checks;
- descriptor, `wallet_id`, origin fingerprint, derivation path/index, signer-role, `witnessScript`, and `sortedmulti`/pubkey-order checks;
- accepted input/output/script profiles and network;
- permitted sighash types;
- existing partial-signature acceptance, uniqueness, validation, and expected-cosigner policy;
- unknown/proprietary PSBT field rejection/preservation/round-trip policy;
- recipient versus change classification and the change derivation proof;
- absolute fee, fee rate/weight computation, warnings, and hard-reject policy;
- the canonical trusted review object and every mandatory user-visible field;
- whether QuietKey returns a partially signed PSBT, a finalized PSBT, a raw transaction, or an explicitly defined subset, including witness/finalization ownership;
- the QR and SD signed-output lifecycle and cross-route equivalence;
- negative/cross-implementation vectors, corpora, and the owner acceptance record.

This STOP-BEFORE-F9 policy decision is additional to — and does not weaken — the limit-authorization rules above: no `OPEN — VALUE NOT AUTHORIZED IN F1` row is freezable through this policy, and this policy is not resolvable through value measurement.

## OD-06 — Boot, update, and rollback

Which boot, update, and rollback properties are achievable without mechanical redesign. Nothing about secure boot or update resilience may be assumed. Also open: which component parses boot/update artifacts — explicitly **not** `qk-io` (QK-REQ-PLT-012's ownership note leaves this open); the containment design for the bounded **userspace** SD filesystem parser (the kernel never mounts removable media — QK-REQ-TRN-009/010), whose containment evidence is QK-TST-SAN-004; and the procedure producing exact-target **air-gap verification** evidence (radio absence/permanent disablement — QK-REQ-PLT-008, QK-TST-AUD-007).

## OD-07 — Human factors and kits

Human-test thresholds, kit packaging, executor wording for inheritance, and descriptor-backup placement across kit tiers.

## OD-08 — Licensing and governance

Project licensing (the prior root MIT LICENSE was removed by owner authorization on 2026-08-18; **no license is currently selected** — software, hardware, and documentation licenses all await owner approval), maintainers, two-person review policy, vulnerability-reporting ownership and channel, release signing, supported-version policy, and audit ownership. None of these identities, emails, or policies may be invented by an agent.

## OD-09 — Quantum Shelter raw-transaction BBQr framing

Quantum Shelter returns only the final raw transaction. Whether its future QR return path uses BBQr file type `T`, and the exact type-`T` profile, framing and interoperability evidence if selected, require a future Owner-ratified decision. Until then Quantum Shelter export is SD-only: the ratified type-`P` profile remains PSBT-only, raw transactions must never be encoded or labeled as type `P`, and M25 pre-commits no type-`T` wire semantics.
