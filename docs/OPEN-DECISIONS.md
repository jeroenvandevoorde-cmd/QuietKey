# QuietKey Open Decisions

EXPERIMENTAL — NO REAL FUNDS — NOT A WALLET

This file records only genuinely open decisions. QK-DEC-121 and Core Architecture v2 settle the Single Card plus Two-Envelope Kit topology, native P2WSH `wsh(sortedmulti(2,A,B))`, Bitcoin mainnet, the unchanged derivation and 24-word mnemonic profile, PSBT v0, BBQr transaction transport, the exact kit-share frame and print encodings, the two kit doors, `QK-FEE-POLICY-V2`, and review schema v3. Those decisions are not reopened here. Every decision below remains unresolved; CANDIDATE labels remain hypotheses.

Recommendations below are labeled `CANDIDATE`. A CANDIDATE is a hypothesis: never implemented, never validated. Only explicit owner approval plus a `docs/DECISION-LOG.md` entry resolves an open decision.

## OD-01 — Production toolchain

Contingent on ARMv6/target evidence. `CANDIDATE`: Rust plus a narrow pinned `libsecp256k1` C boundary, with a measured all-C fallback only if necessary. No production language has been selected.

## OD-02 — Exact production card — **PHYSICAL TRIGGER BEFORE CARD INTEGRATION**

Card model, capabilities, applet lifecycle, APDU byte layouts, optional offline attestation, and rescue implementation. No card has been selected; feasibility is Gate B. `CANDIDATE` (hypothesis only, never validated): signer-B material is non-exportable from the card in normal operation, with signing performed on-card. The same candidate must be tested for an optional setup-only spare and for a replacement card provisioned only through the ratified `Kit-Restore` preconditions; no second live card may be added later. The architecture deliberately uses **no PIN or pairing secret** (QK-REQ-CARD-002), so possession yields whatever the card exposes and the export model remains the most consequential open property. Also open are the lifecycle commit mechanism and how D and A2 are read by the rescue tool. The missing-card outcome is not open: it is `Kit-Spend` and a full sweep, never card restoration.

## OD-03 — Production dice evidence and nonce sources

V2 seed generation is dice-only. Manual keypad entry remains exactly 100 values per secret; the intended-primary grid remains exactly five 25-die shakes per secret and cannot ship until fixed-camera read accuracy, measured inter-shake face independence, batch die-bias testing, and settle mechanics guaranteeing one die per cell meet ratified evidence thresholds. Also open are real transcript secrecy/destruction evidence and terminal cross-run nonce generation and freshness. QKEC-1 remains verified library mathematics with no v2 multi-source product entry point. Runtime health checks and displayed scores cannot prove entropy.

## OD-04 — A1 physical codec parameters

The M18 alphabet, Reed–Solomon candidates, MSB-first erasure geometry, and authenticated A1 capsule chain are fixed. Still open are final profile selection, font/footer geometry, product retry order and bound, reader thresholds, damage margin, and exact-target print/scan acceptance. The new kit fallback reuses the M18 alphabet but not the A1 Reed–Solomon container; its exact 228-symbol form is fixed, while its terminal input method is deliberately deferred to the kit-scanner slice.

## OD-05 — Transport resource ceilings and review layout

Exact values for every `OPEN — VALUE NOT AUTHORIZED IN F1` row in `docs/RESOURCE-BUDGETS.md` tagged OD-05, plus filesystem choice and transaction review layout. The PSBT authorization profile, full-previous-transaction proof, SIGHASH_ALL rule, output allowlist, finalization/export lifecycle, `QK-FEE-POLICY-V2`, review schema v3, 71-byte witness script, and 220-byte fixed witness estimate are settled and are not open here. Authorization of a resource value still requires representative and adversarial corpora; peak RAM/stack and worst-case CPU/time on the exact target; camera/display usability where applicable; human-trial accuracy for review-facing limits; safety margin; rejection UX; recomputed cross-limit arithmetic; jointly frozen bound rows; and an Owner decision. Measurement alone authorizes nothing.

## OD-06 — Boot, update, and rollback

Which boot, update, and rollback properties are achievable without mechanical redesign. Nothing about secure boot or update resilience may be assumed. Also open: which component parses boot/update artifacts — explicitly **not** `qk-io` (QK-REQ-PLT-012's ownership note leaves this open); the containment design for the bounded **userspace** SD filesystem parser (the kernel never mounts removable media — QK-REQ-TRN-009/010), whose containment evidence is QK-TST-SAN-004; and the procedure producing exact-target **air-gap verification** evidence (radio absence/permanent disablement — QK-REQ-PLT-008, QK-TST-AUD-007).

## OD-07 — Human factors and kit materials

The universal two-envelope recovery architecture, exactly two complete default copies, identical setup pad across copies, cross-copy pairing, one share per page and envelope, separate-versus-together posture, both preselected doors, sweep-only missing-card/seal-doubt response, periodic seal checks, and optional setup-only spare are fixed. Open items are human-test thresholds; physical envelope, seal, and packaging selections; final printed executor wording; placement within each packaging tier; seal-inspection cadence and usability; and the kit fallback's terminal entry method. Software cannot establish UTXO completeness, continuing possession of the original card, physical destruction, or envelope integrity; those remain external coordinator or human facts and require explicit ceremony confirmation where consumed.

## OD-08 — Licensing and governance

Project licensing (the prior root MIT LICENSE was removed by owner authorization on 2026-08-18; **no license is currently selected** — software, hardware, and documentation licenses all await owner approval), maintainers, two-person review policy, vulnerability-reporting ownership and channel, release signing, supported-version policy, and audit ownership. None of these identities, emails, or policies may be invented by an agent.
