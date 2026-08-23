# QK2 Document Import Set — Manifest

Owner-provided normative reference set for docs/qk2/. Import all twelve PDFs
with these exact filenames, plus docs/qk2/00-core-architecture-v1.md from the
LEA-local Core Architecture v1 markdown (not packaged here; its SHA-256 is
reported by the LEA at import and byte-verified by the LOA after the push).
Verify every hash against SHA256SUMS before committing; any mismatch stops the
import.

Authority ordering (Owner-ratified):
1. 00-core-architecture-v1.md — SUPREME authority for system and security
   architecture. Where any other document disagrees, it is correct.
2. Files 01-10 — the Dossier, Decision Register, and eight working drafts:
   subordinate elaborations of v1. 06 (PSBT Checklist) governs the signing
   pipeline.
3. 12 (QK2-HW-P0.1) — authoritative for prototype hardware, EXCEPT its
   superseded residue: the "2-of-2 remains binding" basis line, the bech32
   footer-token target, the 99-digit dice test, and KMAC-related Gate B rows.
4. 11 (QK2-04) and the CloakVault v3 protocol — SUPERSEDED, historical record
   only. Carve-out: QK2-04 section 3.2 Gate A1/A2 test methodology is retained
   as the Gate A test plan.

| # | File | Role |
|---|---|---|
| 00 | core-architecture-v1.md (LEA-local) | Supreme system/security authority |
| 01 | 01-qk2-dossier.pdf | Index to the document set |
| 02 | 02-qk2-decision-register.pdf | Consistency matrix, subordinate to 00 |
| 03 | 03-qk2-blueprint.pdf | Layered design, threat matrix |
| 04 | 04-qkec-1-specification.pdf | Entropy conditioner |
| 05 | 05-qk2-standards-register.pdf | BIP/SLIP/RFC adoption register |
| 06 | 06-qk2-psbt-checklist.pdf | Governing PSBT signing profile |
| 07 | 07-qk2-recovery-decision.pdf | Recovery architecture and kit tiers |
| 08 | 08-qk2-card-protocol.pdf | Bearer-card APDU surface |
| 09 | 09-qk2-recovery-document.pdf | A1 capsule and print codec |
| 10 | 10-qk2-component-map.pdf | Implementation component map |
| 11 | 11-qk2-04-system-device-blueprint.pdf | SUPERSEDED historical; Gate A methodology retained |
| 12 | 12-qk2-hw-p0-1-hardware-blueprint.pdf | Prototype hardware authority minus listed residue |
