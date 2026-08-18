# QuietKey Decision Log

EXPERIMENTAL — NO REAL FUNDS — NOT A WALLET

All entries below are `DRAFT — PENDING OWNER APPROVAL`. No approvers, evidence, or audit results exist. Only an explicit owner-approval entry added here may change any decision's status.

| Date | ID | Title | Status | Rationale | Architecture link |
|---|---|---|---|---|---|
| 2026-08-18 | QK-DEC-001 | Product philosophy | DRAFT — PENDING OWNER APPROVAL | Stealth and robustness principles anchor every later choice; camouflage explicitly subordinated to cryptography. | [ARCHITECTURE.md § QK-DEC-001](../ARCHITECTURE.md#qk-dec-001--product-philosophy) |
| 2026-08-18 | QK-DEC-002 | Custody topology | DRAFT — PENDING OWNER APPROVAL | Standard P2WSH sortedmulti 2-of-3 gives single-loss tolerance with well-understood, widely reviewable script semantics. | [ARCHITECTURE.md § QK-DEC-002](../ARCHITECTURE.md#qk-dec-002--custody-topology) |
| 2026-08-18 | QK-DEC-003 | Fixed v1 Bitcoin profile | DRAFT — PENDING OWNER APPROVAL | One fixed mainnet/BIP48 profile with no passphrase or 12-word variants minimizes recovery ambiguity and mistake surface. | [ARCHITECTURE.md § QK-DEC-003](../ARCHITECTURE.md#qk-dec-003--fixed-v1-bitcoin-profile) |
| 2026-08-18 | QK-DEC-004 | Physical elements and cloak | DRAFT — PENDING OWNER APPROVAL | Everyday-looking objects (document, cards, calculator) hide custody in plain sight while remaining safe after recognition. | [ARCHITECTURE.md § QK-DEC-004](../ARCHITECTURE.md#qk-dec-004--physical-elements-and-cloak) |
| 2026-08-18 | QK-DEC-005 | Use and recovery hierarchy | DRAFT — PENDING OWNER APPROVAL | Every single-object loss leaves a defined pair path; mandatory rotate-and-sweep prevents reuse of a degraded wallet. | [ARCHITECTURE.md § QK-DEC-005](../ARCHITECTURE.md#qk-dec-005--use-and-recovery-hierarchy) |
| 2026-08-18 | QK-DEC-006 | Bearer-card and terminal model | DRAFT — PENDING OWNER APPROVAL | Possession-is-authorization avoids PIN/vendor dependencies; least-authority card payload limits blast radius, pending exact-card feasibility. | [ARCHITECTURE.md § QK-DEC-006](../ARCHITECTURE.md#qk-dec-006--bearer-card-and-terminal-model) |
| 2026-08-18 | QK-DEC-007 | Entropy product profile | DRAFT — PENDING OWNER APPROVAL | Four independent 256-bit values prevent common-master failure; fail-closed dice mode gives an auditable physical alternative. | [ARCHITECTURE.md § QK-DEC-007](../ARCHITECTURE.md#qk-dec-007--entropy-product-profile) |
| 2026-08-18 | QK-DEC-008 | A1 digital-cryptography baseline | DRAFT — PENDING OWNER APPROVAL | Standard AEAD (ChaCha20-Poly1305) with HKDF domain separation and AAD context binding; no plaintext before authentication. | [ARCHITECTURE.md § QK-DEC-008](../ARCHITECTURE.md#qk-dec-008--a1-digital-cryptography-baseline) |
| 2026-08-18 | QK-DEC-009 | PSBT and transport profile | DRAFT — PENDING OWNER APPROVAL | Single strict input formats (PSBT v0, binary .psbt, BBQr P) shrink the hostile parsing surface; trusted core revalidates everything. | [ARCHITECTURE.md § QK-DEC-009](../ARCHITECTURE.md#qk-dec-009--psbt-and-transport-profile) |
| 2026-08-18 | QK-DEC-010 | Software trust boundary | DRAFT — PENDING OWNER APPROVAL | Separating secret-owning core from unprivileged transport and decoy bounds compromise, without overclaiming against a hostile kernel. | [ARCHITECTURE.md § QK-DEC-010](../ARCHITECTURE.md#qk-dec-010--software-trust-boundary) |
| 2026-08-18 | QK-DEC-011 | Kit tiers | DRAFT — PENDING OWNER APPROVAL | Packaging and instructions may vary by audience while the cryptographic core stays identical across all kits. | [ARCHITECTURE.md § QK-DEC-011](../ARCHITECTURE.md#qk-dec-011--kit-tiers) |
| 2026-08-18 | QK-DEC-012 | Quantum posture | DRAFT — PENDING OWNER APPROVAL | Honest posture: exposure reduction and a reviewed migration plan; no post-quantum claims before Bitcoin consensus support. | [ARCHITECTURE.md § QK-DEC-012](../ARCHITECTURE.md#qk-dec-012--quantum-posture) |
| 2026-08-18 | QK-DEC-013 | Source and licensing boundary | DRAFT — PENDING OWNER APPROVAL | Clean-room discipline: no third-party or legacy code without recorded commit, license, provenance, purpose, and review status. | [ARCHITECTURE.md § QK-DEC-013](../ARCHITECTURE.md#qk-dec-013--source-and-licensing-boundary) |
| 2026-08-18 | QK-DEC-014 | Maturity and release claims | DRAFT — PENDING OWNER APPROVAL | Host simulation cannot prove physical properties; STOP-SHIP holds until exact-target evidence, reproducible builds, review, and rehearsals exist. | [ARCHITECTURE.md § QK-DEC-014](../ARCHITECTURE.md#qk-dec-014--maturity-and-release-claims) |

## Administrative entries

| Date | Entry | Status | Notes |
|---|---|---|---|
| 2026-08-18 | Root MIT LICENSE removed by explicit owner authorization; repository license is now an OPEN owner decision (see docs/OPEN-DECISIONS.md OD-08). No replacement selected. | RECORDED | Sole authorized deletion during F0. |
