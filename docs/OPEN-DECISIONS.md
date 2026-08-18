# QuietKey Open Decisions

EXPERIMENTAL — NO REAL FUNDS — NOT A WALLET

This file records only genuinely open decisions. The fixed profiles are **not** reopened here: custody topology, Bitcoin/mainnet profile, derivation, 24-word mnemonic model, PSBT v0, BBQr type `P` QR format, and binary `.psbt` SD encoding are settled in `ARCHITECTURE.md` (pending owner approval as a whole).

Recommendations below are labeled `CANDIDATE`. A CANDIDATE is a hypothesis: never implemented, never validated. Only explicit owner approval plus a `docs/DECISION-LOG.md` entry resolves an open decision.

## OD-01 — Production toolchain

Contingent on ARMv6/target evidence. `CANDIDATE`: Rust plus a narrow pinned `libsecp256k1` C boundary, with a measured all-C fallback only if necessary. No production language has been selected.

## OD-02 — Exact card — **STOP-BEFORE-F3**

Card model, capabilities, applet lifecycle, APDU byte layouts, optional offline attestation, and rescue implementation. No card has been selected; feasibility is Gate B. `CANDIDATE` (hypothesis only, never validated): signer material non-exportable from the card in normal operation, with signing performed on-card — which would make QK-TST-BENCH-005 runnable and would constrain the rescue path (Gate B rescue evidence cannot even be defined until this resolves). Note: the architecture deliberately uses **no PIN or pairing secret** (QK-REQ-CARD-002), so card possession alone yields whatever the card exposes — the export model is therefore the single most consequential open property of the card. Also open: the commit mechanism realizing the abstract lifecycle states of QK-REQ-CARD-008/009/010, and how D and A2 are read by the rescue tool. This decision must resolve before any F3 profile work depends on card behavior.

## OD-03 — Production entropy sources — **STOP-BEFORE-F3**

Exact hardware sources, health-check implementation, independence evidence, and proof that the release binary actually reaches the intended sources. Runtime health checks cannot prove entropy. Also open: the **byte-exact conditioner construction** (inputs, domain-separation labels per purpose A/B/C/A2, output derivation) required by QK-REQ-ENT-006/007 — independent test vectors (F3) cannot be written until it is fixed; per-source failure semantics and what "source degraded" means operationally; and the dice-transcript handling procedure that satisfies QK-REQ-ENT-011/012 (secrecy, destruction, no cross-session claim).

## OD-04 — A1 physical codec parameters

Reed–Solomon parameters, base32 alphabet, checksum, URL-like format details, font, OCR pipeline, and print/scan trial thresholds. The visual codec is explicitly not frozen (custom URL-like format, not Bech32).

## OD-05 — Transport resource ceilings and review layout

Exact values for every `OPEN — VALUE NOT AUTHORIZED IN F1` row in `docs/RESOURCE-BUDGETS.md` tagged OD-05, plus fee warnings, filenames, filesystem choice, and transaction review layout. Authorization profile per value (all required before any value freezes): representative and adversarial corpora; peak RAM/stack and worst-case CPU/time on the exact target (QK-TST-BENCH-003); camera/display usability where applicable; human-trial review-accuracy data for review-facing limits (QK-TST-HF-002); documented safety margin; rejection UX definition; cross-limit checked-arithmetic invariants recomputed (see the invariants section of the budget registry); bound rows (APDU-006↔PSBT-011, TUI-004/005↔PSBT-018/019) frozen together; owner decision recorded in `docs/DECISION-LOG.md`. Measurement alone — including everything F2 produces — authorizes nothing.

## OD-06 — Boot, update, and rollback

Which boot, update, and rollback properties are achievable without mechanical redesign. Nothing about secure boot or update resilience may be assumed. Also open: which component parses boot/update artifacts — explicitly **not** `qk-io` (QK-REQ-PLT-012's ownership note leaves this open); the containment design for the bounded **userspace** SD filesystem parser (the kernel never mounts removable media — QK-REQ-TRN-009/010), whose containment evidence is QK-TST-SAN-004; and the procedure producing exact-target **air-gap verification** evidence (radio absence/permanent disablement — QK-REQ-PLT-008, QK-TST-AUD-007).

## OD-07 — Human factors and kits

Human-test thresholds, kit packaging, executor wording for inheritance, and descriptor-backup placement across kit tiers.

## OD-08 — Licensing and governance

Project licensing (the prior root MIT LICENSE was removed by owner authorization on 2026-08-18; **no license is currently selected** — software, hardware, and documentation licenses all await owner approval), maintainers, two-person review policy, vulnerability-reporting ownership and channel, release signing, supported-version policy, and audit ownership. None of these identities, emails, or policies may be invented by an agent.
