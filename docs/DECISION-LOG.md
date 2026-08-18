# QuietKey Decision Log

EXPERIMENTAL — NO REAL FUNDS — NOT A WALLET

Design entries below were recorded as `DRAFT — PENDING OWNER APPROVAL` at creation. The explicit owner approval covering QK-DEC-001…014 as part of baseline H0 is recorded under Owner approval records below (QK-APR-2026-08-18-001). No implementation evidence or audit results exist. Only an explicit owner-approval entry added here may change any decision's status.

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


## Owner approval records

Entries in this section are immutable once checkpointed; corrections require a superseding approval record. Never edit an existing record.

### QK-APR-2026-08-18-001 — Corrected F0/F1 baseline approval

- **ID:** QK-APR-2026-08-18-001
- **Date:** 2026-08-18
- **Approver:** Project owner
- **Approved substantive baseline H0:** `c618407a3900657d8ce4c479c4056f859f86bec6`
- **Scope:** the corrected F0/F1 documents at H0, including QK-DEC-001…014 and the corrected requirements, threat, traceability, lifecycle, resource-budget, and planned-test baselines.
- **Authorized next scope:** F2 feasibility only.
- **Not approved:** implementation or use with funds; Bitcoin/wallet/cryptographic code; production language/toolchain/dependency selection; card/hardware selection; the entropy conditioner; A1 codec parameters; PSBT authorization choices; numeric limits; boot/update design; human-factors thresholds; kit wording; license or governance appointments; closure of any gate; F3 and beyond.
- **Effect:** the architecture-owner-approval release blocker is satisfied; Gates A–E remain OPEN; implementation evidence remains none; OD-01…08 remain unresolved.

### QK-AUTH-F3F4-001 — Host-only F3/F4 bootstrap authorization

- **ID:** QK-AUTH-F3F4-001
- **Date:** 2026-08-18
- **Approver:** Project owner
- **Owner words:** “Yes, go ahead.” (approving a software-first, bounded F3/F4 host bootstrap before hardware purchase, in the immediately preceding explicit scope; see docs/HOST-WORK-AUTHORIZATION.md)
- **Scope:** host-only F3 profile and public test-vector preparation; host-only F4 interface and state-machine scaffold; the reversible rust-stable Replit module as a HOST bootstrap toolchain only.
- **Not approved:** any production toolchain selection (OD-01 remains open); any license/SPDX choice (OD-08 remains open); F5–F12; gate closure; any QK-LIM/QK-TST/evidence/specimen/hardware transition; physical or exact-target work.
- **Effect:** F2 remains AUTHORIZED — PREPARATION COMPLETE — PHYSICAL/EXACT-TARGET WORK BLOCKED — OVERALL INCOMPLETE; F3/F4 become AUTHORIZED host-only as recorded in docs/HOST-WORK-AUTHORIZATION.md; Gates A–E remain OPEN; OD-01…08 remain unresolved; host results are HOST evidence only, never TARGET evidence.

### QK-AUTH-F3.1A-001 — F3.1a correction-only remediation authorization

- **ID:** QK-AUTH-F3.1A-001
- **Date:** 2026-08-18
- **Approver:** Project owner
- **Owner words exactly:** “Please continue, full authorization sustained.”
- **Context:** this immediately approved continuing the explicitly proposed F3.1a correction-only PSBT draft remediation, independent audit, and owner-decision-packet preparation.
- **Published parent:** `145f960e659334be55afc11a1e0427c23c0f3b5e`.
- **Authorized next commits:** Commit B changing exactly `docs/SOURCE-REGISTER.md`, `docs/f3/PSBT-V0-REVIEW-PROFILE-DRAFT.md`, `docs/f3/README.md`, `replit.md`, and `tools/verify-host-boundary.sh`; then Commit C changing exactly the current-stage consistency-checker path `tools/verify-current-stage.sh`.
- **Explicit exclusions:** no profile acceptance; no D item selected; no parser/code/vectors/fixtures/crypto/signing; no gate/OD/QK-LIM/QK-TST/evidence change; no hardware/Flux/procurement/fabrication; no license/governance-role selection; no claim that a repository script authenticates itself.
- **Effect:** F3 remains authorized host-only drafting, incomplete, no profile accepted, no target evidence; all other existing statuses unchanged.

### Effective-status clarification (append-only; alters no prior row or record)

QK-DEC-001…014 are owner-approved as part of baseline H0 by the existing record QK-APR-2026-08-18-001; implementation remains unvalidated and all Gates remain OPEN. The original table cells above remain the historical status-at-creation and are intentionally unedited. No in-repo digest is a trust anchor.

### QK-AUTH-F3.1B-001 — Status-accuracy erratum authorization

- **ID:** QK-AUTH-F3.1B-001
- **Date:** 2026-08-18
- **Approver:** Project owner
- **Owner words exactly:** “Agreed”
- **Context:** the owner approved the immediately preceding explicit two-stage proposal to (1) correct stale present-state wording and the CARD-006 Evidence-family omission, then (2) prepare a separate non-binding PSBT owner-decision evidence packet. This record authorizes ONLY stage (1), the status-accuracy erratum chain below; the later owner-decision evidence packet remains a separate checkpoint and is not begun by this authorization.
- **Published parent:** `9ffea22a75946a53b7aa4d358cf25844bb3e323a`.
- **Authorized next commits:** Commit B changing exactly `README.md`, `SECURITY.md`, `docs/BUILD-ROADMAP.md`, `docs/HOST-WORK-AUTHORIZATION.md`, `docs/REQUIREMENTS.md` (append-only), and `tools/verify-host-boundary.sh`; then Commit C changing exactly the current-stage consistency-checker path `tools/verify-current-stage.sh`.
- **Explicit exclusions:** no architecture/profile/D-item acceptance; no vectors, fixtures, corpora, parser, crypto, seed, signing, QR/SD/card/target code; no gate, OD, QK-LIM, QK-TST status, evidence, toolchain, dependency, license, hardware, Flux, procurement, or fabrication change.
- **Effect:** wording accuracy and one append-only requirements erratum only; every substantive status remains exactly as previously recorded.

### QK-AUTH-F3.1B-R2-001 — F3.1b Revision 2 policy-direction authorization

- **ID:** QK-AUTH-F3.1B-R2-001
- **Date:** 2026-08-18
- **Approver:** Project owner
- **Owner words exactly:** “Agreed, I approve this direction.”
- **Context:** given immediately after the consolidated Revision 2 direction. It approves RECORDING owner-selected policy directions for D-01 (prevout), D-03 (ceremony-pair signatures), D-08 (review/fee-rate), and D-12 (transaction version/temporal policy), a future-only D-05 recipient-P2TR direction, and bounded citation-only source additions. It is direction approval only — NOT retroactive approval, NOT profile acceptance, NOT implementation authorization, NOT evidence, and NOT a trust anchor.
- **Published parent:** `d9277cd2fcd8d699448a1667624123a3347118d6`.
- **Authorized next commits:** Commit B changing exactly `docs/SOURCE-REGISTER.md`, `docs/f3/PSBT-V0-REVIEW-PROFILE-DRAFT.md`, `docs/f3/README.md`, and `tools/verify-host-boundary.sh`; then Commit C changing exactly the current-stage consistency-checker path `tools/verify-current-stage.sh`.
- **Explicit limits and exclusions:** does NOT accept the PSBT profile or any clause as normative; does NOT amend canonical architecture; resolves NO OD; chooses NO numeric QK-LIM value; generates/runs NO vector; changes NO QK-TST or evidence status; closes NO gate; authorizes NO parser/crypto/signing/QR/SD/card/target code; approves NO procurement/fabrication; makes NO production/security/funds claim. All clauses remain PROPOSED/NON-NORMATIVE until separate profile acceptance. Gates A–E remain OPEN; OD-01..08 and every QK-LIM remain OPEN; QK-TST remains PLANNED — NOT RUN; F2 remains physically blocked/incomplete; F3/F4 remain host-only/incomplete; F5–F12 remain unauthorized.

### QK-AUTH-F3.2A-001 — F3.2a Wallet Trust Spine drafting authorization

- **ID:** QK-AUTH-F3.2A-001
- **Date:** 2026-08-19
- **Approver:** Project owner
- **Owner words exactly:** “Agreed, please continue”
- **Context:** given immediately after the explicit recommendation for a docs-only Wallet Trust Spine candidate and exercised under QK-AUTH-F3F4-001. These words authorize preparation of a proposed/non-normative F3.2a draft only; they do not accept a clause/profile, resolve an OD, select a limit, authorize implementation, or change canonical architecture/requirements.
- **Published parent:** `a9d1f205cfa879a6f54b8838256d36e469cfed97`.
- **Authorizes only:** proposed canonical receive/change descriptor and wallet_id byte candidates already bounded by QK-DEC-003; A/B/C role-to-key mapping; provisioning/recovery trust-establishment invariants; A1+B, A1+C and B+C card-independent ceremony requirements; analysis of sequential-card/single-interface prerequisites and conflicts; explicit card-independent versus OD-02/APDU-blocked boundaries.
- **Authorized next commits:** Commit B changing exactly `docs/SOURCE-REGISTER.md`, `docs/f3/WALLET-TRUST-SPINE-DRAFT.md` (new), `docs/f3/README.md`, and `tools/verify-host-boundary.sh`; then Commit C changing exactly the current-stage consistency-checker path `tools/verify-current-stage.sh`.
- **Explicit exclusions:** no architecture/requirements/open-decision amendment; no owner-decision resolution; no QK-LIM/QK-TST/evidence/gate transition; no vectors, fixtures, corpus or payload; no parser, crypto, signing, seed, QR, SD, card or target code; no real keys/descriptors/addresses/funds; no APDU, nonce, anti-exfil, attestation, terminal-pairing or exact-target mechanism; no license/governance/hardware/Flux/procurement/fabrication transition; F5–F12 remain unauthorized.
- **Effect:** F3 remains host-only drafting, incomplete, with no profile accepted and no target evidence. OD-08 and Flux intake are separate future checkpoints outside this chain.
