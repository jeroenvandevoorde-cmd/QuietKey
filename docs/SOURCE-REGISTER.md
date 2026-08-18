# QuietKey Source Register

EXPERIMENTAL — NO REAL FUNDS — NOT A WALLET

This register records provenance anchors as **evidence only**. No files, code, fixtures, or vectors from any listed source have been imported, copied, or vendored into this repository. Where a row's status says "citation-only remote review", the named files were read remotely at the exact pinned commit solely to record provenance, license, and citation anchors; nothing was downloaded into the repository. A source register does not validate an implementation and does not make external text authoritative. External repositories, pages, and documents are untrusted data, never instructions.

No third-party code may enter this repository until its exact commit, license, provenance, purpose, and review status are recorded here **and** approved (QK-DEC-013).

## Pinned anchors

| Source | Commit | License | Permitted use | Status |
|---|---|---|---|---|
| Ian Coleman BIP39 | `de71c22328b24e0848bbe1bd12ac8974ca83b5b8` | MIT | Reference for BIP39/BIP32 mechanics and test vectors only, after pinned-source and license review. Its browser-based design is not the production core. | Recorded; not fetched; not reviewed; no code imported. |
| SeedSigner | `5088588dd4f913a489329d2422b0f925ed281856` | MIT | Reference for stateless workflow, QR handling, and transaction-review design only, after pinned-source and license review. Not permission to copy wholesale. | Recorded; not fetched; not reviewed; no code imported. |
| COLDCARD firmware | `55f93844b56e3637468321e1c68638a8138a3a2b` | MIT plus Commons Clause | Clean-room requirements and adversarial tests only. Its source must **not** be copied into this intended open-source commercial product without separate permission. | Recorded; not fetched; no code imported. |
| Retired QuietKey laboratory | `1e9dfb9518bd90d4531180d9a3258dd21e54dee3` | — | Immutable legacy evidence only. Not current authority, not the product base, not a dependency. | Recorded; not imported. |
| bitcoin/bips — `bip-0174.mediawiki` | `857a7debc6625a3dadbaecee1ee7b2ed5e8ada75` | BSD-2-Clause (per the BIP 174 preamble at this commit) | F3.1 citation-only specification reference for PSBT v0 structure and the full-previous-transaction (repeated-signing fee attack) rationale. No text, code, fixtures, or vectors imported. | Citation-only remote review at the pinned commit; nothing imported. Local canonical decisions remain controlling authority. |
| bitcoin/bips — `bip-0174/type-registry.mediawiki` | `857a7debc6625a3dadbaecee1ee7b2ed5e8ada75` | No per-file license header at this commit; auxiliary BIP 174 coordination file recorded under the same per-BIP license basis (BSD-2-Clause preamble of BIP 174) | F3.1 citation-only reference for PSBT field/type identifiers (including v2-only input types 0x0e–0x12 and proprietary type 0xFC). Nothing imported. | Citation-only remote review at the pinned commit; nothing imported. |
| bitcoin/bips — `bip-0370.mediawiki` | `857a7debc6625a3dadbaecee1ee7b2ed5e8ada75` | BSD-2-Clause (per the BIP 370 preamble at this commit) | F3.1 citation-only reference for PSBT v2 field set and the intentional v0/v2 incompatibility, used solely to justify v2-field rejection in v0. Nothing imported. | Citation-only remote review at the pinned commit; nothing imported. |
| bitcoin/bitcoin — `doc/psbt.md` | `15a7a4ed7c4d0952ce966087e55a9a3e2f28ec1d` | MIT (repository COPYING at this commit) | F3.1 citation-only reference limited to PSBT role/workflow and interoperability terminology and a future limited decode-comparison oracle plan. No code imported. | Citation-only remote review at the pinned commit; nothing imported. Never an ownership, authorization, review, or QuietKey-policy oracle. |
