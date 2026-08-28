# F3 — Host-Only Profile and Public Test-Vector Preparation

EXPERIMENTAL — NO REAL FUNDS — NOT A WALLET

## V2 migration disposition

QK-DEC-121 makes Core Architecture v2 the active authority. The legacy documents listed below remain historical v1 preparation records and do not supply active three-role, Card-C, selected-pair, 2-of-3, review-schema-v1/v2, or signer-only output behavior. V2 work proceeds only through the eleven ordered slices: descriptor/GOLDEN facts in slice 1, review schema v3 and QK-FEE-POLICY-V2 in slice 2, two-key signing/finalization/Core vectors in slice 3, and later Kit profiles in their assigned slices. No old draft clause is a compatibility path.

STATUS: AUTHORIZED — HOST-ONLY PROFILE AND PUBLIC TEST-VECTOR PREPARATION — INCOMPLETE — NO PROFILE ACCEPTED — NO TARGET EVIDENCE.

Authorization: QK-AUTH-F3F4-001 (docs/HOST-WORK-AUTHORIZATION.md), 2026-08-18.

## Inventory

- [PSBT-V0-REVIEW-PROFILE-DRAFT.md](PSBT-V0-REVIEW-PROFILE-DRAFT.md) — F3.1 PSBT v0 review-profile DRAFT, revised by F3.1a (CORRECTION-ONLY) and F3.1b REVISION 2 (OWNER DIRECTIONS RECORDED — PROFILE NOT ACCEPTED, per QK-AUTH-F3.1B-R2-001): 34 clauses (QK-F3-PSBT-001–034), plans QK-F3-PLAN-001–090 (every plan PLANNED — NOT GENERATED — NOT RUN), decisions D-00–D-12; D-01, D-03, D-08 and D-12 are OWNER-DIRECTED while every clause remains PROPOSED/NON-NORMATIVE until separate profile acceptance; D-05 records a FUTURE recipient-only P2TR direction only (current draft still rejects P2TR everywhere); D-00, D-02, D-04, D-06, D-07, D-09, D-10, and D-11 remain owner-open/structurally open as classified in the decision table; D-05's present-profile allowlist remains owner-open while only its FUTURE recipient-only P2TR direction is recorded; zero vectors generated or run, NO IMPLEMENTATION authorized.
- [WALLET-TRUST-SPINE-DRAFT.md](WALLET-TRUST-SPINE-DRAFT.md) — F3.2a Wallet Trust Spine DRAFT (per QK-AUTH-F3.2A-001): PROPOSED/NON-NORMATIVE — INCOMPLETE — NO PROFILE ACCEPTED OR FROZEN — NO TEST VECTORS GENERATED OR RUN — NO IMPLEMENTATION — NO TARGET EVIDENCE; clauses QK-F3-WTS-001–015, plans QK-F3-WTS-PLAN-001–020 (every plan PLANNED — NOT GENERATED — NOT RUN); proposed canonical receive/change descriptor and wallet_id candidates bounded by QK-DEC-003; single-interface B+C choreography BLOCKED pending QK-REQ-BND-003 versus D-03 reconciliation plus OD-02 evidence.

## Drafting boundary (the only authorized F3 activity)

- This directory may hold host-only **drafting** work toward future normative profiles and public test-vector preparation.
- No normative profile has been accepted. No test vectors have been generated. No proposed byte-level rule is normative or frozen; no byte-exact vector or implementation artifact exists.
- Hardware-dependent profiles (card, QR/camera, SD/power, target performance) are blocked pending exact-target evidence; F2 physical work remains blocked and OVERALL INCOMPLETE.
- No cryptographic, wallet, parsing, signing, or transport implementation is authorized by this boundary.
- Gates A–E remain OPEN; OD-01…08 remain unresolved; host results are HOST evidence only and never TARGET evidence.
