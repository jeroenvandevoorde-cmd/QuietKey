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

### QK-AUTH-F3.2F-PSBT-TST-DIR-REC-001 — F3.2f PSBT-output test owner-direction record preparation authorization

- **ID:** QK-AUTH-F3.2F-PSBT-TST-DIR-REC-001
- **Date:** 2026-08-20
- **Approver:** Project owner
- **Owner approval words exactly:**

Approve, as non-enacting owner directions, the complete proposed Plan / oracle text for QK-TST-DIFF-002 and QK-TST-DIFF-004 exactly as printed in the F3.2e packet at published commit 574e790193d45d3f392c64951d319bb5fde11d20. Approve no change to any other cell. QK-TST-REH-004 remains unchanged.

This approval does not amend docs/TEST-ARCHITECTURE.md, change any QK-TST status, authorize testing or evidence, answer F32C-D11-Q-002 through Q-012, or select D-11, D-09, any QK-LIM, the PSBT profile, or any clause.

- **Owner preparation authority words exactly:**

Authorize preparation and independent audit of a non-enacting docs-only F3.2f PSBT-output test owner-direction record from 574e790193d45d3f392c64951d319bb5fde11d20, recording only my approved directions for QK-TST-DIFF-002 and QK-TST-DIFF-004, with QK-TST-REH-004 retained unchanged and only the mechanically necessary verifier bindings.

No canonical TEST-ARCHITECTURE edit, test-status change, F32C-D11-Q-002 through Q-012 answer, D-11 or D-09 selection, QK-LIM selection, profile or clause acceptance, implementation, testing, vectors, evidence, media I/O, hardware work, settings changes, or publication.

- **Published parent and source locators:** `574e790193d45d3f392c64951d319bb5fde11d20`; `docs/f3/F3.2E-PSBT-OUTPUT-TEST-ALIGNMENT-PACKET.md` blob `4ffa20afbedeb0b6cfbbe57298f941bc0537683e`; `docs/TEST-ARCHITECTURE.md` blob `f4e127a92fc68243274b7d384e335fa4632e5dd2`. These are supporting byte-identity audit locators only, not authentication or proof.
- **Exact commit/path map:** Commit A changes only `docs/DECISION-LOG.md`; Commit B adds only `docs/f3/F3.2F-PSBT-OUTPUT-TEST-OWNER-DIRECTION-RECORD.md` and changes only `tools/verify-host-boundary.sh`; Commit C changes only `tools/verify-current-stage.sh`. The chain is exactly three linear one-parent commits with no merge and cumulative changes to only those four paths.
- **Scope:** records only the two non-enacting owner directions attached to the complete proposed Plan / oracle cells for `QK-TST-DIFF-002` and `QK-TST-DIFF-004` as printed in the F3.2e source packet. `QK-TST-REH-004` remains the unchanged external-finalization control and receives no direction.
- **Explicit exclusions and non-effects:** no canonical document or other cell change; no QK-TST status, test, vector, evidence, gate, STOP-SHIP, implementation, media-I/O, hardware, firmware, setting, credential, remote, branch, tag, release, or publication change; no answer to F32C-D11-Q-002 through F32C-D11-Q-012; no D-11, D-09, QK-LIM, profile, or clause selection or acceptance. Every dependency, open question, QK-LIM title/link, and existing `PLANNED — NOT RUN` status remains unchanged.
- **Later canonical amendment:** this record is non-enacting. Canonical amendment requires a separate explicit owner authorization after this direction record; this authorization does not amend `docs/TEST-ARCHITECTURE.md`.
- **Later publication:** publication requires a separate explicit owner instruction naming the exact independently audited 40-hex commit; this authorization alone does not authorize publication.

### QK-AUTH-F3.2G-PSBT-TST-ARCH-AMD-001 — F3.2g canonical TEST-ARCHITECTURE amendment authorization

- **ID:** QK-AUTH-F3.2G-PSBT-TST-ARCH-AMD-001
- **Date:** 2026-08-20
- **Approver:** Project owner
- **Owner words exactly:**

Authorize preparation and independent audit of a docs-only F3.2g canonical TEST-ARCHITECTURE amendment from 45f2b362994b785d303e91b8e530efc724dc2d81, replacing only the complete Plan / oracle cells of QK-TST-DIFF-002 and QK-TST-DIFF-004 with the owner-approved text recorded in the published F3.2f owner-direction record, byte-for-byte. Preserve every other cell and row unchanged, retain QK-TST-REH-004 byte-for-byte, and include only the mechanically necessary Decision Log and verifier bindings.

No QK-TST status change or testing/evidence; no F32C-D11-Q-002 through Q-012 answer; no D-11, D-09, QK-LIM, profile, clause, OD-05/06, dependency, corpus, implementation, vector, fixture, media-I/O, hardware, license, settings, credential, release, or publication change.

- **Published parent and source locators:** `45f2b362994b785d303e91b8e530efc724dc2d81`; published F3.2f owner-direction record blob `a066fc9710371f414d158a3deb9c345f2b00821b`; F3.2e alignment-packet blob `4ffa20afbedeb0b6cfbbe57298f941bc0537683e`; canonical `docs/TEST-ARCHITECTURE.md` base blob `f4e127a92fc68243274b7d384e335fa4632e5dd2`. These hashes are supporting byte-identity audit locators only, not authentication or proof.
- **Exact commit/path map:** Commit A changes only `docs/DECISION-LOG.md`; Commit B changes only `docs/TEST-ARCHITECTURE.md` and `tools/verify-host-boundary.sh`; Commit C changes only `tools/verify-current-stage.sh`. The chain is exactly three linear one-parent commits with no merge and cumulative changes to only those four paths; documentation modes remain `100644` and verifier modes remain `100755`.
- **Least-authority scope:** locally enact exactly the two owner-approved complete Plan / oracle cells for `QK-TST-DIFF-002` and `QK-TST-DIFF-004`, byte-for-byte from the published F3.2f record, plus only the mechanically necessary Decision Log and verifier bindings and independent read-only audit.
- **Preserved cells, rows, and sources:** each target row's ID, Method, Links, Milestone, Gate, Evidence artifact, and Status cells remain byte-for-byte unchanged; every other `docs/TEST-ARCHITECTURE.md` byte and row remains unchanged; `QK-TST-REH-004` remains byte-for-byte unchanged; the published F3.2e packet and F3.2f record remain unchanged.
- **Explicit exclusions and non-effects:** no QK-TST status, testing, evidence, gate, STOP-SHIP, F32C-D11-Q-002 through F32C-D11-Q-012 answer, D-11 or D-09 selection, QK-LIM value/title/link, profile or clause acceptance, OD-05/06 resolution, dependency, corpus, implementation, vector, fixture, media-I/O, hardware, license, setting, credential, remote, other branch, tag, release, or publication change. The known `QK-LIM-PSBT-027` title/link inconsistency remains untouched. All QK-TST statuses remain `PLANNED — NOT RUN`.
- **Effect:** this authorization canonically enacts exactly the two approved complete Plan / oracle cells and nothing else. It does not authenticate or audit its own output, establish test evidence, or authorize publication.
- **Later publication:** publication requires a separate explicit owner instruction naming the exact independently audited 40-hex commit; this authorization alone does not authorize publication.

### QK-AUTH-F3.2H-QK-LIM-PSBT-027-ALIGN-PKT-001 — F3.2h QK-LIM-PSBT-027 cross-document alignment-packet preparation authorization

- **ID:** QK-AUTH-F3.2H-QK-LIM-PSBT-027-ALIGN-PKT-001
- **Date:** 2026-08-20
- **Approver:** Project owner
- **Owner words exactly (literal three-paragraph block follows):**

Authorize preparation and independent audit of a non-binding docs-only F3.2h QK-LIM-PSBT-027 cross-document alignment packet from a64399dd35aef8d6daa05171f1da30c8026f6d1f, with only the mechanically necessary Decision Log and verifier bindings. Limit scope to the stale “Raw final-transaction output bytes” dimension and its live links in docs/RESOURCE-BUDGETS.md, docs/REQUIREMENTS.md, and the QK-TST-DIFF-004 Links cell of docs/TEST-ARCHITECTURE.md.

Present exactly three unselected dispositions: recommended permanent tombstoning, unlinking, and non-reuse of ID 027; preservation as an inactive future contingency with no current links or value; or deferral with the known inconsistency retained. Reject deletion, renumbering, reuse, or repurposing of ID 027. Keep QK-LIM-PSBT-026 and all historical records unchanged.

No owner selection or canonical edit; no QK-LIM value, title, status, link, or row change; no QK-TST Plan / oracle or status change; no answer to F32C-D11-Q-002 through Q-012; no D-11, D-09, OD-05/06, profile, clause, implementation, testing, corpus, vector, fixture, evidence, media-I/O, hardware, license, gate, STOP-SHIP, setting, credential, release, publication, or remote change.

- **Published parent and source locators:** `a64399dd35aef8d6daa05171f1da30c8026f6d1f`; canonical `docs/RESOURCE-BUDGETS.md` blob `1ae6494fc24a8e3572464cf45e6d43ea4875e95d`; canonical `docs/REQUIREMENTS.md` blob `981b1b497102187da66fb4e82ef0725b32c088f7`; canonical `docs/TEST-ARCHITECTURE.md` blob `065e20eed4e916c907a244aa3e5ca2e66cbc5d4e`. These hashes are supporting byte-identity audit locators only, not authentication or proof.
- **Exact commit/path map:** Commit A appends only `docs/DECISION-LOG.md`; Commit B adds only `docs/f3/F3.2H-QK-LIM-PSBT-027-CROSS-DOCUMENT-ALIGNMENT-PACKET.md` and changes only `tools/verify-host-boundary.sh`; Commit C changes only `tools/verify-current-stage.sh`. The chain is exactly three linear one-parent commits with no merge and cumulative changes to only those four paths; documentation modes remain `100644` and verifier modes remain `100755`.
- **Least-authority scope:** local preparation and independent read-only audit of one non-binding, non-normative packet that inventories the current `QK-LIM-PSBT-027` cross-document inconsistency and presents exactly three ordered, unselected dispositions. A recommendation is analysis only and is not an owner selection.
- **Preserved sources and state:** `QK-LIM-PSBT-026`, `QK-LIM-PSBT-027`, `QK-REQ-PSBT-005`, `QK-REQ-TRN-007`, `QK-TST-DIFF-004`, all historical records, and every other canonical byte remain unchanged. The current registry vocabulary is not expanded by this packet.
- **Explicit exclusions and non-effects:** no owner response or disposition selection; no deletion, renumbering, reuse, or repurposing of ID 027; no numeric QK-LIM value, including zero; no QK-LIM value, title, status, link, or row change; no QK-TST Plan / oracle, Links, or status change; no answer to F32C-D11-Q-002 through F32C-D11-Q-012; no D-11, D-09, OD-05/06, profile, clause, implementation, test, corpus, vector, fixture, evidence, media-I/O, hardware, license, gate, STOP-SHIP, setting, credential, remote, other-branch, tag, release, or publication change.
- **Effect:** packet-preparation authority only. `QK-LIM-PSBT-026` and `QK-LIM-PSBT-027` remain byte-for-byte unchanged and `OPEN — VALUE NOT AUTHORIZED IN F1`; all QK-TST statuses remain `PLANNED — NOT RUN`; the known inconsistency remains live unless and until a later owner-selected disposition receives separate canonical-amendment authority.
- **Later canonical amendment and publication:** any disposition selection, canonical edit, or publication requires a separate explicit owner instruction after independent audit; this authorization alone authorizes none of them.

### QK-AUTH-F3.2I-QK-LIM-PSBT-027-DIR-REC-001 — F3.2i QK-LIM-PSBT-027 owner-direction record preparation authorization

- **ID:** QK-AUTH-F3.2I-QK-LIM-PSBT-027-DIR-REC-001
- **Date:** 2026-08-20
- **Approver:** Project owner
- **Owner words exactly (literal four-paragraph block follows):**

Approve, as a non-enacting owner direction, F32H-LIM-OPT-001 exactly as printed in the published F3.2h packet at commit e36b41e5cd55264b4b745550c96c74968b06eae7: “Under separately authorized later canonical work, preserve ID 027 as a permanent non-reusable tombstone and remove its live links. Never delete, renumber, reuse, or repurpose the ID.” Approve no other disposition.

This approval selects only the future disposition direction. It does not declare the current QK-LIM-PSBT-027 row tombstoned or inactive; select any replacement title, Status vocabulary, row syntax, link syntax, or canonical bytes; authorize any value, including zero; or amend any current live link. QK-LIM-PSBT-026 remains unchanged.

Authorize preparation and independent audit of a non-enacting docs-only F3.2i QK-LIM-PSBT-027 owner-direction record from e36b41e5cd55264b4b745550c96c74968b06eae7, recording only that approved direction, with only the mechanically necessary Decision Log and verifier bindings.

No canonical RESOURCE-BUDGETS, REQUIREMENTS, or TEST-ARCHITECTURE edit; no QK-LIM value, title, status, link, or row change; no QK-TST Plan / oracle, Links, or status change; no answer to F32C-D11-Q-002 through Q-012; no D-11, D-09, OD-05/06, profile, clause, implementation, testing, corpus, vector, fixture, evidence, media-I/O, hardware, license, gate, STOP-SHIP, setting, credential, other-branch, tag, release, publication, or remote change.

- **Published parent and source locators:** `e36b41e5cd55264b4b745550c96c74968b06eae7`; F3.2h packet `docs/f3/F3.2H-QK-LIM-PSBT-027-CROSS-DOCUMENT-ALIGNMENT-PACKET.md` blob `e18ba6b4a5c2ee5fc5b7d1a464b656c631b526d5`; canonical `docs/RESOURCE-BUDGETS.md` blob `1ae6494fc24a8e3572464cf45e6d43ea4875e95d`; canonical `docs/REQUIREMENTS.md` blob `981b1b497102187da66fb4e82ef0725b32c088f7`; canonical `docs/TEST-ARCHITECTURE.md` blob `065e20eed4e916c907a244aa3e5ca2e66cbc5d4e`. These hashes are supporting byte-identity audit locators only, not authentication or proof.
- **Exact commit/path map:** Commit A appends only `docs/DECISION-LOG.md`; Commit B adds only `docs/f3/F3.2I-QK-LIM-PSBT-027-OWNER-DIRECTION-RECORD.md` and changes only `tools/verify-host-boundary.sh`; Commit C changes only `tools/verify-current-stage.sh`. The chain is exactly three linear one-parent commits with no merge and cumulative changes to only those four paths; documentation modes remain `100644` and verifier modes remain `100755`.
- **Least-authority scope:** local preparation and independent read-only audit of one non-enacting owner-direction record. It records only the selected future direction for `F32H-LIM-OPT-001`; it does not enact a canonical amendment or change the packet’s historical all-UNSELECTED state.
- **Preserved sources and state:** `QK-LIM-PSBT-026`, `QK-LIM-PSBT-027`, `QK-REQ-PSBT-005`, `QK-REQ-TRN-007`, `QK-TST-DIFF-004`, the F3.2h packet, all historical records, and every other canonical byte remain unchanged. No current `TOMBSTONED` or `INACTIVE` status is recorded or introduced.
- **Explicit exclusions and non-effects:** no present tombstone or inactive declaration; no replacement title, Status vocabulary, row syntax, link syntax, canonical bytes, value including zero, or live-link change; no deletion, renumbering, reuse, or repurposing of ID 027; no QK-TST Plan / oracle, Links, or status change; no answer to F32C-D11-Q-002 through F32C-D11-Q-012; no D-11, D-09, OD-05/06, profile, clause, implementation, test, corpus, vector, fixture, evidence, media-I/O, hardware, license, gate, STOP-SHIP, setting, credential, remote, other-branch, tag, release, or publication change.
- **Effect:** records F32H-LIM-OPT-001 as the sole owner-approved non-enacting future direction and authorizes preparation and independent audit of its record only. F32H-LIM-OPT-002 and F32H-LIM-OPT-003 remain not approved. No canonical change is enacted; later exact construction, canonical work, and publication each require a separate explicit owner instruction after independent audit.

### QK-AUTH-F3.2J-QK-LIM-PSBT-027-CONSTRUCT-001 — F3.2j QK-LIM-PSBT-027 exact tombstone-construction packet preparation authorization

- **ID:** QK-AUTH-F3.2J-QK-LIM-PSBT-027-CONSTRUCT-001
- **Date:** 2026-08-20
- **Approver:** Project owner
- **Owner words exactly (literal three-paragraph block follows):**

Authorize preparation and independent audit of a non-binding, non-enacting docs-only F3.2j QK-LIM-PSBT-027 exact tombstone-construction packet from published commit 878b23be4690bb778a615bfe1a6ef108e7a94008, with only the mechanically necessary Decision Log and verifier bindings.

Limit the packet to exactly one recommended, byte-complete candidate, F32J-LIM-CON-001, explicitly PROPOSED — UNSELECTED. Print the exact current and proposed canonical bytes for: the minimum QK-LIM-PSBT-027-specific RESOURCE-BUDGETS preamble, invariant, and append-only-ID-note corrections needed for a permanent no-value tombstone; every cell of row 027; removal of 027 from the QK-REQ-PSBT-005 and QK-REQ-TRN-007 Lim cells; and removal of 027 from the QK-TST-DIFF-004 Links cell. Preserve the historical dimension name and ID, make every former row relationship non-operative, define any proposed Value-cell text as a non-value sentinel rather than zero or an authorized QK-LIM value, and never delete, renumber, reuse, repurpose, or reopen ID 027. Introduce no general tombstone transition for another row. Keep QK-LIM-PSBT-026 and every other canonical and historical byte unchanged.

No owner selection of F32J-LIM-CON-001 and no canonical edit; no current tombstone or inactive declaration; no actual QK-LIM value, title, status, link, row, vocabulary, or syntax change; no QK-TST Plan / oracle, Links, or status change; no answer to F32C-D11-Q-002 through Q-012; no D-11, D-09, OD-05/06, profile, clause, dependency, implementation, testing, corpus, vector, fixture, evidence, media-I/O, hardware, license, gate, STOP-SHIP, setting, credential, other-branch, tag, release, publication, or remote change.

- **Published parent and source locators:** `878b23be4690bb778a615bfe1a6ef108e7a94008`; F3.2i record `docs/f3/F3.2I-QK-LIM-PSBT-027-OWNER-DIRECTION-RECORD.md` blob `2f4bc0f5cb8e861b45f515fb7c4c5dbc764784c5`; canonical `docs/RESOURCE-BUDGETS.md` blob `1ae6494fc24a8e3572464cf45e6d43ea4875e95d`; canonical `docs/REQUIREMENTS.md` blob `981b1b497102187da66fb4e82ef0725b32c088f7`; canonical `docs/TEST-ARCHITECTURE.md` blob `065e20eed4e916c907a244aa3e5ca2e66cbc5d4e`. These hashes are supporting byte-identity audit locators only, not authentication or proof.
- **Exact commit/path map:** Commit A appends only `docs/DECISION-LOG.md`; Commit B adds only `docs/f3/F3.2J-QK-LIM-PSBT-027-EXACT-TOMBSTONE-CONSTRUCTION-PACKET.md` and changes only `tools/verify-host-boundary.sh`; Commit C changes only `tools/verify-current-stage.sh`. The chain is exactly three linear one-parent bodyless commits with no merge and cumulative changes to only those four paths; documentation modes remain `100644` and verifier modes remain `100755`.
- **Least-authority scope:** local preparation and independent audit of one non-binding, non-enacting packet containing exactly one recommended, byte-complete, proposed-but-unselected future construction. Recommendation is not selection; the packet neither enacts nor publishes any canonical change.
- **Preserved current and historical state:** `QK-LIM-PSBT-026`, `QK-LIM-PSBT-027`, `QK-REQ-PSBT-005`, `QK-REQ-TRN-007`, `QK-TST-DIFF-004`, every canonical source, the F3.2i record, and every historical byte remain unchanged. No current tombstone, inactive state, value, title, status, link, row, vocabulary, or syntax is introduced.
- **Candidate boundary:** `F32J-LIM-CON-001` is the sole candidate and remains `PROPOSED — UNSELECTED`. It may print only the exact future bytes needed for the permanent, non-reusable, no-value tombstone construction and the three specified consumer-link removals. Any proposed Value text is a non-value sentinel, never zero or an authorized QK-LIM value; no general tombstone transition is created for another row.
- **Explicit exclusions and non-effects:** no owner candidate selection or canonical edit; no deletion, renumbering, reuse, repurposing, or reopening of ID 027; no actual QK-LIM value, title, status, link, row, vocabulary, or syntax change; no QK-TST Plan / oracle, Links, or status change; no answer to F32C-D11-Q-002 through F32C-D11-Q-012; no D-11, D-09, OD-05/06, profile, clause, dependency, implementation, test, corpus, vector, fixture, evidence, media-I/O, hardware, license, gate, STOP-SHIP, setting, credential, remote, other-branch, tag, release, or publication change.
- **Effect:** packet-preparation and independent-audit authority only. Canonical enactment, candidate selection, and publication each require separate later explicit owner authority after independent audit.

### QK-AUTH-F3.2K-QK-LIM-PSBT-027-EXACT-CON-DIR-REC-001 — F3.2k QK-LIM-PSBT-027 exact-construction owner-direction record preparation authorization

- **ID:** QK-AUTH-F3.2K-QK-LIM-PSBT-027-EXACT-CON-DIR-REC-001
- **Date:** 2026-08-20
- **Approver:** Project owner
- **Owner words exactly (literal four-paragraph block follows):**

Approve, as a non-enacting owner direction for separately authorized later canonical work, the complete, indivisible, byte-for-byte candidate F32J-LIM-CON-001 exactly as printed in the published F3.2j packet at commit 0d2115de9c322bf221f5a5008d91e7b7b48363e6, packet blob b1c2153f5f89a0e1d44d62a09921251e225c0d87. Approve all and only its proposed future canonical bytes. Approve no alternative, subset, paraphrase, normalization, substitution, or additional change.

This approval selects only the exact future construction. It does not enact those bytes, amend any canonical document, or declare QK-LIM-PSBT-027 currently tombstoned or inactive. The current row remains OPEN with its current live links until separately authorized canonical work. The proposed Value-cell text remains a non-value sentinel, never zero or an authorized QK-LIM value. Preserve the historical ID and dimension name, QK-LIM-PSBT-026, ALL GATES OPEN, and every other canonical and historical byte. OD-05 and QK-THR-016 remain unresolved or unchanged globally; only their future row-027 relationships become non-operative. Introduce no general tombstone vocabulary or transition for another row.

Authorize preparation and independent audit of a non-enacting docs-only F3.2k QK-LIM-PSBT-027 exact-construction owner-direction record from published commit 0d2115de9c322bf221f5a5008d91e7b7b48363e6, recording only this exact approval and reproducing the selected future bytes byte-for-byte, with only the mechanically necessary Decision Log and verifier bindings.

No canonical RESOURCE-BUDGETS, REQUIREMENTS, or TEST-ARCHITECTURE edit; no current QK-LIM value, title, Status, link, row, vocabulary, or syntax change; no current QK-TST Plan / oracle, Links, or status change; no answer to F32C-D11-Q-002 through Q-012; no D-11, D-09, OD-05/06, profile, clause, dependency, implementation, testing, corpus, vector, fixture, evidence, media-I/O, hardware, license, gate, STOP-SHIP, setting, credential, other-branch, tag, release, publication, or remote change.

- **Published parent and source locators:** `0d2115de9c322bf221f5a5008d91e7b7b48363e6`; immutable F3.2j packet `docs/f3/F3.2J-QK-LIM-PSBT-027-EXACT-TOMBSTONE-CONSTRUCTION-PACKET.md` blob `b1c2153f5f89a0e1d44d62a09921251e225c0d87`; F3.2i record blob `2f4bc0f5cb8e861b45f515fb7c4c5dbc764784c5`; canonical RESOURCE-BUDGETS blob `1ae6494fc24a8e3572464cf45e6d43ea4875e95d`; canonical REQUIREMENTS blob `981b1b497102187da66fb4e82ef0725b32c088f7`; canonical TEST-ARCHITECTURE blob `065e20eed4e916c907a244aa3e5ca2e66cbc5d4e`. These hashes are supporting byte-identity audit locators only, not authentication, audit proof, enactment, or publication authority.
- **Exact commit/path map:** Commit A appends only `docs/DECISION-LOG.md`; Commit B adds only `docs/f3/F3.2K-QK-LIM-PSBT-027-EXACT-CONSTRUCTION-OWNER-DIRECTION-RECORD.md` and changes only `tools/verify-host-boundary.sh`; Commit C changes only `tools/verify-current-stage.sh`. The chain is exactly three linear single-parent bodyless commits with no merge or fourth commit and cumulative changes to only those four paths; documentation modes remain `100644` and verifier modes remain `100755`.
- **Least-authority scope:** local preparation, verification, and independent read-only audit of one non-enacting owner-direction record selecting all and only the complete, indivisible, byte-for-byte `F32J-LIM-CON-001` future construction. The mechanically necessary verifier bindings do not broaden this authority.
- **Historical and current disposition:** the immutable F3.2j packet remains `PROPOSED — UNSELECTED` as its historical source state. This later record marks only the complete exact future construction `OWNER DIRECTION APPROVED — NON-ENACTING`, with present canonical effect `NONE`.
- **Exact payload boundary:** approval attaches only to the seven proposed future payloads printed in the packet: the RESOURCE-BUDGETS preamble, invariant, append-only note, complete nine-cell row 027, two Requirement Lim cells, and QK-TST-DIFF-004 Links cell. They are one indivisible construction; no alternative, subset, paraphrase, normalization, substitution, explanatory packet prose, or additional change is approved.
- **Preserved current and historical state:** the packet, F3.2i record, `QK-LIM-PSBT-026`, current `QK-LIM-PSBT-027` OPEN row and live links, canonical RESOURCE-BUDGETS, REQUIREMENTS, and TEST-ARCHITECTURE sources, `ALL GATES OPEN`, and every other canonical and historical byte remain unchanged. The packet’s `LOCAL AND UNPUBLISHED` wording remains historical and unchanged.
- **Mandatory semantic boundary:** the proposed Value text is exactly `NOT A VALUE — PERMANENT TOMBSTONE SENTINEL`, never zero, a value, default, candidate, or approved limit. Future `TOMBSTONED` syntax is row-027-specific and creates no current or general vocabulary or transition. ID and historical dimension are preserved; ID 027 is never deleted, renumbered, reused, repurposed, or reopened. OD-05 and QK-THR-016 remain globally unresolved or unchanged; only their future row-027 relationships become non-operative. The only future consumer changes are the two named Requirement Lim cells and the DIFF-004 Links cell.
- **Explicit exclusions and non-effects:** no canonical edit; no current tombstone or inactive declaration; no current QK-LIM value, title, Status, link, row, vocabulary, or syntax change; no current QK-TST Plan / oracle, Links, or status change; no answer to F32C-D11-Q-002 through Q-012; no D-11, D-09, OD-05/06, profile, clause, dependency, implementation, testing, corpus, vector, fixture, evidence, media-I/O, hardware, license, gate, STOP-SHIP, setting, credential, remote, other-branch, tag, release, or publication change.
- **Effect:** records one exact owner-approved non-enacting future construction only and authorizes local record preparation and independent audit. It enacts no canonical byte and grants no publication or remote authority.
- **Later canonical amendment and publication:** canonical work and publication each require a separate explicit owner instruction naming the exact independently audited 40-hex commit.

### QK-AUTH-F3.2L-QK-LIM-PSBT-027-CANONICAL-AMEND-001 — F3.2l QK-LIM-PSBT-027 canonical permanent-tombstone amendment authorization

- **ID:** QK-AUTH-F3.2L-QK-LIM-PSBT-027-CANONICAL-AMEND-001
- **Date:** 2026-08-21
- **Approver:** Project owner
- **Owner words exactly (literal three-paragraph block follows):**

Authorize preparation and independent audit of a docs-only F3.2l canonical QK-LIM-PSBT-027 permanent-tombstone amendment from published commit 49ca0aa4a19ca10ebe8f2866b2d9426720b8ebdf. Enact, as one indivisible byte-for-byte construction, all and only the seven owner-approved future canonical payloads for F32J-LIM-CON-001 reproduced in the published F3.2k owner-direction record at blob 5b05d62776c65bfaf5ec41ab39108bc0531b7944 and sourced from the immutable F3.2j packet at blob b1c2153f5f89a0e1d44d62a09921251e225c0d87. Stop on any missing, duplicated, or mismatched source span; permit no alternative, subset, paraphrase, normalization, substitution, reformatting, or additional byte.

Replace exactly once: in docs/RESOURCE-BUDGETS.md, only the approved preamble, invariant, append-only-ID note, and complete QK-LIM-PSBT-027 row; in docs/REQUIREMENTS.md, only the Lim cells of QK-REQ-PSBT-005 and QK-REQ-TRN-007; and in docs/TEST-ARCHITECTURE.md, only the Links cell of QK-TST-DIFF-004. This enactment makes QK-LIM-PSBT-027 the sole permanent, non-reusable canonical tombstone. Preserve its historical ID and dimension name, QK-LIM-PSBT-026, ALL GATES OPEN, and every other canonical and historical byte. Its Value text is a non-value sentinel, never zero or an authorized QK-LIM value. Never delete, renumber, reuse, repurpose, or reopen ID 027. Introduce no general tombstone vocabulary or transition for another row. OD-05 remains unresolved globally and QK-THR-016 remains unchanged globally; only their row-027 relationships become non-operative.

Use exactly three linear single-parent commits: Commit A appends only docs/DECISION-LOG.md; Commit B changes only docs/RESOURCE-BUDGETS.md, docs/REQUIREMENTS.md, docs/TEST-ARCHITECTURE.md, and tools/verify-host-boundary.sh; Commit C changes only tools/verify-current-stage.sh. Include only the mechanically necessary Decision Log and verifier bindings. No other RESOURCE-BUDGETS row or byte, Requirement text or cell, or QK-TST Plan / oracle, Milestone, Gate, Evidence artifact, Status, or other cell change. No answer to F32C-D11-Q-002 through Q-012; no D-11, D-09, OD-05/06, other QK-LIM value, profile, clause, or dependency selection; no implementation, testing, corpus, vector, fixture, evidence, media-I/O, hardware, license, gate, STOP-SHIP, setting, credential, other-branch, tag, release, publication, remote, or other change. Stop locally after independent audit; publication requires separate exact-commit authority.

- **Published parent and source locators:** `49ca0aa4a19ca10ebe8f2866b2d9426720b8ebdf`; immutable F3.2k owner-direction record `docs/f3/F3.2K-QK-LIM-PSBT-027-EXACT-CONSTRUCTION-OWNER-DIRECTION-RECORD.md` blob `5b05d62776c65bfaf5ec41ab39108bc0531b7944`; immutable F3.2j packet `docs/f3/F3.2J-QK-LIM-PSBT-027-EXACT-TOMBSTONE-CONSTRUCTION-PACKET.md` blob `b1c2153f5f89a0e1d44d62a09921251e225c0d87`; canonical RESOURCE-BUDGETS source blob `1ae6494fc24a8e3572464cf45e6d43ea4875e95d`; canonical REQUIREMENTS source blob `981b1b497102187da66fb4e82ef0725b32c088f7`; canonical TEST-ARCHITECTURE source blob `065e20eed4e916c907a244aa3e5ca2e66cbc5d4e`. These hashes are supporting byte-identity audit locators only, not authentication, audit proof, or publication authority.
- **Expected post-enactment byte identities:** canonical RESOURCE-BUDGETS blob `09815b0a75c26a118f80c5cec008e695d319900b`; canonical REQUIREMENTS blob `2cf8a34aa5621dcea114e2d5ec3dabc2b79aef84`; canonical TEST-ARCHITECTURE blob `ecb3867ca2842f6d011288d3dcd94d2b1997e516`. Independent deterministic reconstruction from the seven approved payloads must produce all three identities before enactment.
- **Exact commit/path map:** Commit A appends only `docs/DECISION-LOG.md`; Commit B changes only `docs/RESOURCE-BUDGETS.md`, `docs/REQUIREMENTS.md`, `docs/TEST-ARCHITECTURE.md`, and `tools/verify-host-boundary.sh`; Commit C changes only `tools/verify-current-stage.sh`. The chain is exactly three linear single-parent bodyless commits with no merge or fourth commit and cumulative changes to only those six paths; documentation modes remain `100644` and verifier modes remain `100755`.
- **Least-authority scope:** local canonical enactment, verification, and independent read-only audit of all and only the seven complete, indivisible, byte-for-byte `F32J-LIM-CON-001` payloads. The mechanically necessary Decision Log and verifier bindings do not broaden this authority; no remote or publication authority is granted.
- **Historical source disposition:** the immutable F3.2j packet remains `PROPOSED — UNSELECTED` as its historical source state, and the immutable F3.2k record remains `OWNER DIRECTION APPROVED — NON-ENACTING` as its historical selection state. Their former `LOCAL AND UNPUBLISHED` text remains byte-identical historical wording; both historical stages are now published.
- **Exact payload boundary:** enactment attaches only to the RESOURCE-BUDGETS preamble, invariant, append-only-ID note, and complete nine-cell row 027; the QK-REQ-PSBT-005 and QK-REQ-TRN-007 Lim cells; and the QK-TST-DIFF-004 Links cell. All seven are one construction; no alternative, subset, paraphrase, normalization, substitution, reformatting, explanatory source prose, or additional byte is enacted.
- **Canonical effect and preserved state:** `QK-LIM-PSBT-027` becomes the sole permanent, non-reusable canonical tombstone while preserving its ID and historical dimension name. Its exact Value text is `NOT A VALUE — PERMANENT TOMBSTONE SENTINEL`, never zero or an authorized QK-LIM value. Every former row-027 relationship becomes non-operative, and only the three named consumer cells unlink 027. `QK-LIM-PSBT-026`, `ALL GATES OPEN`, all other canonical and historical bytes, global OD-05 unresolved state, and global QK-THR-016 state remain unchanged. No general tombstone vocabulary or transition is created for another row.
- **Explicit exclusions and non-effects:** no other RESOURCE-BUDGETS row or byte, Requirement text or cell, or QK-TST Plan / oracle, Milestone, Gate, Evidence artifact, Status, or other cell change; no answer to F32C-D11-Q-002 through F32C-D11-Q-012; no D-11, D-09, OD-05/06, other QK-LIM value, profile, clause, dependency, implementation, test, corpus, vector, fixture, evidence, media-I/O, hardware, license, gate, STOP-SHIP, setting, credential, remote, other-branch, tag, release, publication, or other change.
- **Effect:** enacts the exact owner-approved permanent tombstone construction locally after verification and independent audit only. F3.2l remains local and unpublished; publication requires separate exact-commit owner authority.
