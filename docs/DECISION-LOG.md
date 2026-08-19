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

### QK-AUTH-OD08-PKT-001 — OD-08 non-binding decision-packet preparation authorization

- **ID:** QK-AUTH-OD08-PKT-001
- **Date:** 2026-08-19
- **Approver:** Project owner
- **Owner words exactly:** “Perfect, go ahead”
- **Context:** given immediately after the recommendation to prepare the separate OD-08 licensing-and-governance decision packet, followed later by separately authorized F3.2b decisions. The owner authorized decision-packet preparation only; no packet option or policy was selected; this record does not claim that the prior recommendation explicitly mentioned independent audit or publication.
- **Published parent:** `e81ab9c61dda9be60ac45facbe5db57115578540`.
- **Authorizes only:** local preparation of a factual current-state and rights-chain inventory; an informational comparison of unselected standard license families for software, hardware designs, documentation, and ancillary material; separately answerable owner questions covering licensing, contributions, maintainership, review, vulnerability reporting, release signing, supported versions, audit ownership, and trademark/official-build boundaries; independent read-only audit of the prepared packet; and the exact verifier rebind below. Publication is not authorized by this record and requires a later explicit owner instruction after a passing independent audit.
- **Authorized next commits:** Commit B adding exactly `docs/OD-08-DECISION-PACKET.md` and changing exactly `tools/verify-host-boundary.sh` solely to advance its byte-identity Decision-Log anchor to Commit A while preserving all other host-boundary predicates; then Commit C changing exactly `tools/verify-current-stage.sh`.
- **Explicit exclusions:** no license selection, grant, application, modification, or legal conclusion; no `LICENSE`, `LICENCE`, `COPYING`, `COPYRIGHT`, `NOTICE`, `AUTHORS`, `CONTRIBUTING`, `CODEOWNERS`, `REUSE.toml`, SPDX header, manifest license field, DCO/CLA activation, or third-party text/code import; no assertion of copyright ownership or contributor consent; no OD resolution; no architecture, requirement, limit, test, evidence, maturity-gate, milestone, release, or support-status change; no person, organization, handle, email, channel, maintainer, reviewer, key custodian, auditor, or service appointment; no repository/hosting setting, branch rule, private-reporting channel, release-signing mechanism, or supported-version policy activation; no code, vector, fixture, dependency, hardware, Flux, procurement, fabrication, or use-with-funds authorization; no host-boundary scope, acceptance predicate, test expectation, status rule, file allowlist, platform/dependency check, or semantic claim may change except the exact necessary Decision-Log anchor advance.
- **Effect:** OD-08 remains OPEN in full; this chain grants no new rights and does not determine or revoke any rights that may have arisen from historical repository versions; the repository still has no selected project license; no governance role or channel exists by virtue of this record; Gates A–E remain OPEN, STOP-SHIP remains in force, every other status remains unchanged; and this chain remains local and unpublished pending a separate explicit owner publication approval.

### QK-AUTH-OD08-RSP-001 — OD-08 non-enacting owner-response record preparation authorization

- **ID:** QK-AUTH-OD08-RSP-001
- **Date:** 2026-08-19
- **Approver:** Project owner
- **Owner words exactly:** “Authorize preparation and independent audit of the OD‑08 owner-response record from 8c18266. No license application or settings changes.”
- **Context:** given after publication of the audited OD-08 decision-packet chain ending at the published parent below. The owner authorized preparation and independent audit of a non-enacting owner-response record only; no license application, settings change, or policy enactment was authorized; the owner responses recorded under this authorization are direction input only and are not independently verified legal facts.
- **Published parent:** `8c18266c6fc6c00831f444f51a6a1f762250a12d`.
- **Authorizes only:** transcription of the owner-provided responses into a non-enacting owner-response record; local verification of the prepared chain; independent read-only audit of the prepared record; export of the exact unpushed tree for that audit; Commit B; and Commit C. Publication is not authorized by this record and requires a later explicit owner instruction after passing independent audits.
- **Authorized next commits:** Commit B adding exactly `docs/OD-08-OWNER-RESPONSE-RECORD.md` and changing exactly `tools/verify-host-boundary.sh` solely to advance its byte-identity Decision-Log anchor to Commit A while preserving all other host-boundary predicates; then Commit C changing exactly `tools/verify-current-stage.sh`.
- **Explicit exclusions:** no publication; no license or SPDX selection, application, or grant; no legal conclusion; no OD-08 closure; no policy, role, channel, repository or hosting setting, support promise, release, or maturity-gate activation; no protected canonical-document change; no code, vector, fixture, dependency, hardware, Flux, procurement, or fabrication work; no assertion of copyright ownership, contributor consent, or chain-of-title proof; no person, organization, handle, email, channel, maintainer, reviewer, key custodian, auditor, or service appointment takes operational effect by virtue of this record.
- **Effect:** OD-08 remains OPEN in full; this chain enacts nothing, grants no rights, and does not determine or revoke any rights that may have arisen from historical repository versions; the repository still has no selected project license; Gates A–E remain OPEN, STOP-SHIP remains in force, every other status remains unchanged; and this chain remains local and unpublished pending a later explicit owner publication instruction after passing independent audits.

### QK-AUTH-F3.2B-PKT-001 — F3.2b non-binding PSBT decision-packet preparation authorization

- **ID:** QK-AUTH-F3.2B-PKT-001
- **Date:** 2026-08-19
- **Approver:** Project owner
- **Owner words exactly:** “Authorize preparation and independent audit of the docs-only F3.2b PSBT decision packet from a9840819. No profile acceptance, implementation, vectors, license application, hardware work, or settings changes.”
- **Context:** given after publication of the audited OD-08 owner-response chain ending at the published parent below. The owner authorized preparation and independent audit of a non-binding F3.2b PSBT decision packet only: decision input, not an answer, selection, adoption, or acceptance of any profile or clause, and not publication or any later implementation or application authority. The prepared chain includes the single mechanically necessary host-verifier file-set addition described below because the packet lives inside the host verifier’s exact tracked host file set scope; this implementation detail does not broaden the owner’s quoted authorization or alter any other host-boundary predicate.
- **Published parent:** `a9840819eba4d1b98b8346fc0ae0b44f611a45c5`.
- **Authorizes only:** local preparation of the non-binding F3.2b PSBT decision packet; local verification of the prepared chain; independent read-only audit of the prepared packet; export of the exact unpushed tree for that audit; Commit B adding exactly `docs/f3/F3.2B-PSBT-DECISION-PACKET.md` and changing exactly `tools/verify-host-boundary.sh` solely to reanchor its Decision-Log byte-identity anchor to this Commit A and to add exactly `docs/f3/F3.2B-PSBT-DECISION-PACKET.md` as one line to its exact authorized tracked host file set, while preserving every other host-boundary predicate; then Commit C changing exactly `tools/verify-current-stage.sh`. Publication is not authorized by this record and requires a later explicit owner instruction after passing independent audits.
- **Packet scope:** exactly four owner questions: D-02, present-profile D-05, D-06, and D-10. D-00 remains blocked; D-04 remains owner-open and is not posed in this four-question packet; representative coordinator-corpus review remains required before any later selection; D-07, D-09, and D-11 remain evidence- or construction-blocked with no response requested; the recorded D-01, D-03, D-08, and D-12 directions remain non-normative and are preserved without reopening; the future-only recipient-P2TR direction remains future-only.
- **Explicit exclusions:** no publication; no owner response or new D-item selection; no profile, bundle, clause, serialization, hash, policy, limit, test, vector, or evidence acceptance; no normative change; no edit to the PSBT draft, F3 README, Source Register, Architecture, Requirements, Traceability, Open Decisions, gates, evidence, OD, QK-LIM, or QK-TST documents; no code, parser, serializer, wallet, crypto, signing, key, address, PSBT specimen, QR, SD, card, or target work; no vector, fixture, corpus, or payload generation or execution; no license, SPDX, or manifest license change; no hardware, Flux, procurement, or fabrication work; no role, channel, repository setting, workflow, deployment, or `.replit` change; no third-party text, import, or source change; no host-boundary predicate change besides the exact Decision-Log anchor advance and the single authorized file-set line addition above.
- **Effect:** local packet preparation only; the PSBT draft remains byte-identical, proposed, non-normative, and not accepted; every status remains unchanged; Gates A–E remain OPEN; F5–F12 remain unauthorized; and this chain remains local and unpublished pending a later explicit owner publication instruction after passing independent audits.

### QK-AUTH-F3.2B-RSP-001 — F3.2b PSBT owner-response record preparation authorization

- **ID:** QK-AUTH-F3.2B-RSP-001
- **Date:** 2026-08-19
- **Approver:** Project owner
- **Owner words exactly:** “Approve all four F3.2b directions.”
- **Owner preparation authority exactly:** “Authorize preparation and independent audit of the docs-only F3.2b owner-response record from bb6601f3. No profile acceptance, implementation, vectors, license application, hardware work, settings changes, or publication.”
- **Published parent:** `bb6601f3b97528a72c55622251a4b475680ec21b`.
- **Source packet:** `docs/f3/F3.2B-PSBT-DECISION-PACKET.md` at the published parent.
- **Scope:** exactly four non-enacting policy directions only: `F32B-PSBT-Q-001`/D-02, `F32B-PSBT-Q-002`/D-05, `F32B-PSBT-Q-003`/D-06, and `F32B-PSBT-Q-004`/D-10. Preparation and independent audit are authorized; publication and any profile or clause acceptance are not authorized.
- **Authorized next commits:** Commit B adding exactly `docs/f3/F3.2B-PSBT-OWNER-RESPONSE-RECORD.md` and changing exactly `tools/verify-host-boundary.sh` to reanchor this Decision Log state, add the record to its exact host file set, and add strict record checks; then Commit C changing exactly `tools/verify-current-stage.sh`.
- **Explicit exclusions:** D-00 remains blocked; D-04 remains OWNER-OPEN, with representative coordinator-corpus review required before selection; D-07 remains EVIDENCE/CONSTRUCTION-BLOCKED pending target/human QK-LIM evidence; D-09 remains EVIDENCE/CONSTRUCTION-BLOCKED pending the exact commitment construction; D-11 remains EVIDENCE/CONSTRUCTION-BLOCKED pending the media/write lifecycle; no edit to the packet or PSBT profile draft; no architecture/requirements/OD/QK-LIM/QK-TST/evidence/gate status change; no implementation, dependencies, parser/signing/crypto code, fixtures/vectors, conformance or real-funds use; no finalization/extraction/broadcast authorization; no license application; no hardware/firmware/Flux/procurement/fabrication; no other-branch, remote-branch, branch-setting, tag, release, push, publication, settings, or credential change.
- **Effect:** this record records four non-enacting owner-direction dispositions, but enacts no normative profile or clause and changes no OD, QK-LIM, QK-TST, evidence, gate, implementation, release, remote, or publication status; it authorizes no publication.

### QK-AUTH-F3.2C-D11-PKT-001 — F3.2c D-11 non-binding media/write lifecycle construction-packet preparation authorization

- **ID:** QK-AUTH-F3.2C-D11-PKT-001
- **Date:** 2026-08-19
- **Approver:** Project owner
- **Owner words exactly:** “Authorize preparation and independent audit of the non-binding docs-only F3.2c D-11 media/write lifecycle construction packet from 26e075704cdd172fce62b9b7cd38b4035db384d8, with only the mechanically necessary host-boundary and current-stage verifier bindings. No D-11 selection, profile or clause acceptance, implementation, dependencies, vectors, fixtures, specimens, media I/O or testing, QK-LIM/QK-TST/evidence/gate change, license application, hardware or firmware work, settings or credential changes, or publication.”
- **Published parent:** `26e075704cdd172fce62b9b7cd38b4035db384d8`.
- **Exact commit/path map:** Commit A changes only `docs/DECISION-LOG.md`; Commit B adds only `docs/f3/F3.2C-D11-MEDIA-WRITE-LIFECYCLE-CONSTRUCTION-PACKET.md` and changes only `tools/verify-host-boundary.sh`; Commit C changes only `tools/verify-current-stage.sh`.
- **Least-authority scope:** only local packet preparation and verification, one credential-safe audit-bundle export, and independent read-only audit are authorized. The mechanically necessary verifier bindings do not broaden this authority.
- **Boundaries:** D-11 remains unanswered and EVIDENCE/CONSTRUCTION-BLOCKED; D-09 remains unresolved; the PSBT profile draft remains not accepted; no normative clause, OD, limit, test, evidence, gate, implementation, product, target, release, remote, publication, license, hardware, firmware, setting, credential, tag, or other-branch transition is authorized.
- **Later publication:** publication requires a separate explicit instruction naming the exact audited 40-hex commit.
- **Effect:** this authorization records no D-11 selection, enacts no profile or clause, changes no protected status, and authorizes no publication.

### QK-AUTH-F3.2D-D11-Q001-CLR-001 — F3.2d D-11 Q-001 owner-clarification record preparation authorization

- **ID:** QK-AUTH-F3.2D-D11-Q001-CLR-001
- **Date:** 2026-08-19
- **Approver:** Project owner
- **Owner words exactly (literal two-paragraph block follows):**

Approve the recommended F32C-D11-Q-001 clarification: “Failure releases no artifact or partial output” does not claim that already observed QR frames or SD residue can be withdrawn or proven absent. Before route output begins, failure releases nothing; after output begins, a later failure stops further output, permits no complete-artifact, delivery, receipt, finalization, broadcast, atomicity, or durability claim, and permits no automatic fallback, retry, or re-signing.

Authorize preparation and independent audit of a non-enacting docs-only F3.2d Q-001 owner-clarification record from e4cdf7771e189fc0f729358334aafd35177048c6, with only the mechanically necessary verifier bindings. No D-11 selection; no answer to Q-002 through Q-012; no profile acceptance, D-09 or QK-LIM selection, implementation, testing, media I/O, hardware work, settings changes, or publication.

- **Published parent:** `e4cdf7771e189fc0f729358334aafd35177048c6`.
- **Source packet:** `docs/f3/F3.2C-D11-MEDIA-WRITE-LIFECYCLE-CONSTRUCTION-PACKET.md` at the published parent.
- **Exact commit/path map:** Commit A changes only `docs/DECISION-LOG.md`; Commit B adds only `docs/f3/F3.2D-D11-Q001-OWNER-CLARIFICATION-RECORD.md` and changes only `tools/verify-host-boundary.sh`; Commit C changes only `tools/verify-current-stage.sh`.
- **Least-authority scope:** only local preparation and verification of the non-enacting docs-only F3.2d Q-001 owner-clarification record, the mechanically necessary verifier bindings, and independent read-only audit are authorized.
- **Explicit exclusions:** no D-11 selection, closure, construction, state, route, route-set, filesystem, filename, attachment, retry, orphan, QR-preflight, or signature-order selection; no response to F32C-D11-Q-002 through F32C-D11-Q-012; no profile or clause acceptance; no D-09 field, serialization, hash, or domain selection; no QK-LIM selection; no OD, QK-TST, evidence, gate, STOP-SHIP, implementation, dependency, vector, fixture, specimen, test, media-I/O, license, hardware, firmware, setting, credential, remote, tag, release, publication, or other-branch change.
- **Effect:** this authorization records preparation authority for one non-enacting clarification record only; it does not close Q-001 or D-11, select any construction or policy, enact any profile or clause, alter any protected status, authenticate or audit its own output, or authorize publication.
- **Later publication:** publication requires a separate explicit owner instruction naming the exact independently audited 40-hex commit.

### QK-AUTH-F3.2E-PSBT-TST-ALIGN-PKT-001 — F3.2e PSBT-output TEST-ARCHITECTURE alignment-packet preparation authorization

- **ID:** QK-AUTH-F3.2E-PSBT-TST-ALIGN-PKT-001
- **Date:** 2026-08-20
- **Approver:** Project owner
- **Owner words exactly:**

Authorize preparation and independent audit of a non-binding docs-only F3.2e PSBT-output TEST-ARCHITECTURE alignment packet from be4d019e349e15ca575ac64b64f900957283e5e0, with only the mechanically necessary verifier bindings. Limit scope to QK-TST-DIFF-002 and QK-TST-DIFF-004, with QK-TST-REH-004 retained unchanged as the external-finalization control. No canonical TEST-ARCHITECTURE edit, test-status change, Q-002 through Q-012 answer, D-11 or D-09 selection, profile acceptance, implementation, testing, vectors, media I/O, hardware work, settings changes, or publication.

- **Published parent:** `be4d019e349e15ca575ac64b64f900957283e5e0`.
- **Scope:** local preparation and independent read-only audit of one non-binding docs-only F3.2e alignment packet limited to proposed, unselected plan/oracle correction text for `QK-TST-DIFF-002` and `QK-TST-DIFF-004`, with `QK-TST-REH-004` reproduced byte-for-byte as the unchanged external-finalization control, plus only the mechanically necessary verifier bindings and one clean complete sole-main audit bundle in `/tmp`.
- **Exact commit/path map:** Commit A changes only `docs/DECISION-LOG.md`; Commit B adds only `docs/f3/F3.2E-PSBT-OUTPUT-TEST-ALIGNMENT-PACKET.md` and changes only `tools/verify-host-boundary.sh`; Commit C changes only `tools/verify-current-stage.sh`. The chain is exactly three linear one-parent commits with no merge and cumulative changes to only those four paths.
- **Explicit exclusions:** no canonical `docs/TEST-ARCHITECTURE.md`, `docs/REQUIREMENTS.md`, `docs/TRACEABILITY.md`, `docs/RESOURCE-BUDGETS.md`, prior F3.2b/c/d record or packet, PSBT profile, `docs/OPEN-DECISIONS.md`, `ARCHITECTURE.md`, `docs/MATURITY-GATES.md`, `docs/SOURCE-REGISTER.md`, `docs/f3/README.md`, `README.md`, `.replit`, code, manifest, dependency, license, hardware, firmware, remote, branch, tag, release, setting, credential, or publication change; no Q-002 through Q-012 answer; no D-09 or D-11 selection; no QK-LIM value or link change; no profile or clause acceptance; no implementation, testing, vector, fixture, specimen, corpus, payload, media I/O, evidence, gate, or STOP-SHIP change.
- **Non-effects:** the packet is alignment input only and selects or enacts no correction. `QK-TST-DIFF-002` and `QK-TST-DIFF-004` remain `PLANNED — NOT RUN`; `QK-TST-REH-004` remains unchanged; every QK-TST status remains unchanged; D-09, D-11, Q-002 through Q-012, every QK-LIM, profile acceptance, tests, evidence, gates, and STOP-SHIP remain open or unchanged exactly as before. Verifier results and independent review are supporting evidence only, never authentication, audit proof, correction selection, canonical amendment, or publication authority.
- **Later publication:** publication requires a separate explicit owner instruction naming the exact independently audited 40-hex commit; this authorization alone does not authorize publication.
