# H3-A — Specimen Enrollment Intake (H3-A.1 Design-Reference Record)

F2 PREPARATION ONLY — TARGET WORK NOT RUN — NO GATE CLOSED

- Base: c46024a4c3c82659cae71211eaac4ba3e1095466
- Prior H3-A checkpoint: 231836284bf78261563dc96fd144513b87154d09
- Document status: DRAFT — OWNER DESIGN INPUT RECORDED — NO PHYSICAL PROTOTYPE IDENTIFIED — NO EXECUTION AUTHORITY
- Enrollment status: INCOMPLETE — NO PHYSICAL SPECIMEN IDENTIFIED

## What H3-A is and is not

H3-A is an F2.1 administrative intake checkpoint; H3-A.1 adds one
owner-supplied design-reference record to it. It is not roadmap milestone
F3, not the H3-B run-registration commit, and not H3-C execution
authorization. H3-A authorizes intake preparation only. A template is not a
run; a registered run is not an authorized run; an authorized run is not an
accepted result; evidence never changes a gate or decision automatically.

This repository contains no actual P0/RV3 BOM, CAD, schematic, PCB,
enclosure, board, camera, display, keypad, SD/card-reader, power-path, or
exact-card specification. A single owner-supplied design-reference PDF was
reviewed outside the repository and is recorded below; its binary is NOT
COMMITTED. All other materials remain NOT PROVIDED to this repository; this
document makes no claim about whether they exist elsewhere.

H3-A physical identity, custody, availability, revision, and permission
fields may be populated only from explicit owner-supplied inventory or a
later separately authorized inspection. Independent research may inform a
design-reference review, but it cannot establish or fill physical specimen
identity, custody, availability, revision, target equivalence, capability,
or permissions. Concept renders, photos, filenames, product listings,
vendor claims, AI-generated artifacts, earlier recommendations, and
plausible defaults cannot populate specimen facts.

## Controlled design input — QK-HWREF-001

This is a controlled design-input record, deliberately separate from the
specimen ledger. A document is not a specimen.

- Reference ID: QK-HWREF-001
- Classification: OWNER-SUPPLIED HISTORICAL PHYSICAL DESIGN REFERENCE —
  PARTIALLY SUPERSEDED — NOT TARGET EVIDENCE
- Received basename (owner-supplied on 2026-08-18, outside the repository):
  `QuietKey_QK2-HW-P0.1_Revised_Prototype_Hardware_Blueprint.pdf`
- Internal document identifier/title: QK2-HW-P0.1 — Revised Prototype
  Hardware Blueprint; issued 2026-08-16.
- Received-file SHA-256, independently computed by the reviewing
  controller:
  `93126505453236103cd8f730a128efc6018cecd0ad06649408c6770f77cea2e0`
- Bounded read-only inspection of those exact bytes: 92,154 bytes; PDF 1.4;
  22 A4 landscape pages; unencrypted; no AcroForm; no document JavaScript,
  OpenAction, additional actions, Names tree/embedded-file entry, or page
  annotations were found. All 22 pages were text-extracted and visually
  reviewed. This is a bounded format/content inspection, not proof of
  safety, authenticity, correctness, feasibility, or approval.
- Repository status: NOT COMMITTED — PUBLICATION/LICENSE/REDACTION REVIEW
  PENDING (OD-08). The PDF must not be copied, uploaded, encoded, or
  committed, and no extracted PDF text or media may be committed. No URL
  inside it is followed or fetched.
- Content status: READ-ONLY REVIEW COMPLETE — APPLICABILITY/SUPERSESSION
  BOUNDARY RECORDED.

A content hash binds only the reviewed bytes. It does not authenticate the
document's origin, and it does not approve, validate, or adopt any of its
content.

## Applicability boundary of QK-HWREF-001

QK-HWREF-001 may inform only unverified physical-design hypotheses:
calculator-disguised form; the 112 × 74 × 20 mm document envelope;
enclosure/board placement; the fixed camera/lens/window path; 320 × 240
display and keypad placement; the top ISO-7816 card entrance; the
battery-door microSD path; the four-AAA power arrangement; document-listed
candidate parts; and the later R01/R02 proposal design.

Every such item is DOCUMENT-DECLARED — UNVERIFIED. It is not selected,
ordered, received, inspected, available, compatible, manufacturable,
mechanically validated, air-gap evidence, BOM approval, production
approval, or gate evidence. The PDF is not CAD, STEP, schematic, PCB,
Gerber, netlist, pin-map, as-built BOM, or a physical specimen. No source
package or RV3-controlled artifact has been supplied to the repository.

## Supersession overlay (canonical architecture controls)

| # | Historical QK-HWREF-001 statement | Current canonical treatment |
|---|---|---|
| 1 | Native P2WSH 2-of-2 | SUPERSEDED by QK-DEC-002 and QK-DEC-005: `wsh(sortedmulti(2,A,B,C))`; A, B, and C are independent and C is not a B clone. |
| 2 | Blanket no-wallet-secret-at-rest wording | SUPERSEDED AS WRITTEN / NARROWED by QK-DEC-004 and QK-DEC-006: the replaceable terminal retains no wallet secret between sessions; B and C intentionally contain their distinct signer material plus A2 and D, subject to OD-02 feasibility. |
| 3 | QR withdrawn or microSD-only | SUPERSEDED by QK-DEC-009: PSBT v0 binary microSD and uncompressed animated BBQr type P are both required; fixed-mechanics QR feasibility remains unproven. |
| 4 | Exactly 142 Bech32 characters and the stated RS/footer construction | REJECTED/SUPERSEDED by QK-DEC-008: the physical codec remains OD-04 and will be custom URL-like, not Bech32; error correction never replaces AEAD authentication. |
| 5 | 99-digit dice-entry acceptance row | HISTORICAL/INSUFFICIENT for the current ceremony: QK-DEC-007 requires exactly 100 private d6 rolls separately for each of A, B, C, and A2; mapping/conditioning remains OD-03. |
| 6 | Historical P0 release and Gate A–C labels | NON-OPERATIVE in this repository. Current Gates A–E remain OPEN and H3-A.1 is inside F2 preparation. |
| 7 | Any P0.1 permission for dimensional deviation, including a 20.8 mm local rear bulge | NOT AUTHORIZED by this intake. The current no-mechanical-redesign constraint remains in force. A failed fit is a blocker or a separately governed redesign request. |

Current canonical architecture (`ARCHITECTURE.md` and the decision log)
controls all conflicts. None of these historical statements may re-enter a
later test criterion or fixture.

## QK-DEC-121 v2 supersession overlay

The preceding table records the v1 disposition that followed
QK-HWREF-001; it is itself superseded where it names the former three-key
topology. Core Architecture v2 now fixes native P2WSH
`wsh(sortedmulti(2,A,B))`: A is terminal-held, B is the one required Key
Card, and Card C and all A+C/B+C routes are removed. The B card stores its
role-B BIP48 account material, A2 and D. An optional byte-equivalent spare B
may be created only during the original setup; no later second live card may
be added.

Kit-Spend is the only missing-card route and performs the constrained sweep.
Kit-Restore may provision a replacement B only after the user confirms that
the original card remains physically in hand, or may reprint A1 with a fresh
nonce; it never signs. Specimen enrollment and card traces cannot establish
card possession or destruction, absence of another live card, Kit-envelope
integrity, or coordinator UTXO completeness. Those are external human or
coordinator facts. Candidate labels C1/C2/C3 remain platform bookkeeping and
do not reinstate a signer role C.

## Owner declaration

OWNER DECLARES NO PHYSICAL PROTOTYPE EXISTS AS OF 2026-08-18 — NOT
INDEPENDENTLY PHYSICALLY VERIFIED.

## Combined intake and empty specimen ledger

The slot names below are bookkeeping categories only. They are not a
component recommendation, suggestion, or selection, and they name no
manufacturer, product, SKU, protocol, candidate, proxy, supplier, reader,
camera, board, card, or apparatus. `NOT MAPPED` means a document input
(QK-HWREF-001) now exists but has not been mapped to any physical asset;
`NOT PROVIDED` means no input of any kind exists for the slot.

| Slot | Identity | Design-reference mapping |
|---|---|---|
| Integrated P0/RV3 assembly | NOT IDENTIFIED | NOT MAPPED |
| Mechanical/enclosure revision | NOT IDENTIFIED | NOT MAPPED |
| Compute target | NOT IDENTIFIED | NOT MAPPED |
| Camera path (sensor/lens/focus/mount/window/cable) | NOT IDENTIFIED | NOT MAPPED |
| Display path | NOT IDENTIFIED | NOT MAPPED |
| Keypad path | NOT IDENTIFIED | NOT MAPPED |
| Boot-storage path | NOT IDENTIFIED | NOT MAPPED |
| Transport-SD path | NOT IDENTIFIED | NOT MAPPED |
| Card electrical/interface path | NOT IDENTIFIED | NOT MAPPED |
| Candidate card batch | NOT IDENTIFIED | NOT MAPPED |
| Power/battery/brownout path | NOT IDENTIFIED | NOT MAPPED |
| Candidate bench readers and measurement apparatus | NOT IDENTIFIED | NOT PROVIDED |

No classification (TARGET, PROXY, APPARATUS, or SACRIFICIAL) is assigned to
any planned component. No serial, lot, custody, availability, revision, or
apparatus is invented or recorded.

R01/R02 target-validation registration remains blocked until an immutable
controlled mechanical source baseline and an exact physical assembly exist
and are enrolled. R03 remains blocked until exact sacrificial cards,
readers, and apparatus are enrolled.

## Enrollment record fields (defined for later owner input; none populated)

When the owner later supplies inventory, each enrollment record will carry
only these fields:

- Privacy-safe public asset alias.
- Classification: TARGET, PROXY, APPARATUS, or SACRIFICIAL.
- Private exact identity — the serial/asset/custody mapping — held under a
  publication/redaction policy that is OWNER INPUT REQUIRED; no offline,
  private, or public storage policy is selected by this document.
- Manufacturer / model / part / hardware revision (owner-supplied); these
  must eventually remain audit-visible for reproducibility.
- Lot or batch, where safe to publish.
- Quantity.
- Provenance.
- Custody / availability.
- Owner-supplied physical-label or document reference.
- Relationship to P0/RV3.
- Firmware / applet / ATR, only if already owner-supplied without
  interrogating any asset.
- Explicit mutable/destructive permission.
- Physical operator: OWNER INPUT REQUIRED.
- Evidence custodian: OWNER INPUT REQUIRED.
- Publication/redaction policy: OWNER INPUT REQUIRED.

No such field is populated in this document. Defaults for every future
record are exactly:

- Identity: NOT IDENTIFIED
- Classification: NOT ASSIGNED
- Capability: UNVERIFIED
- Custody: NOT DECLARED
- Destructive testing: NOT AUTHORIZED
- Run assignment: NONE
- Evidence status: NONE

Enrollment, when later completed, proves only declared identity, custody,
and permissions. It does not establish suitability, capability, safety,
air-gap status, target equivalence, approval, validation, or any gate
closure. No serial numbers, precise storage locations, photographs,
management material, private evidence, or other sensitive inventory may be
committed until an owner-approved publication/redaction policy exists.

## Execution lock

H3-A (including H3-A.1) does not authorize procurement, ordering,
energizing, connecting, opening, inserting a card or SD, reading ATR/APDUs,
scanning QR, camera/display/keypad trials, applet loading or deletion,
lifecycle or management-key changes, compilation, source fetching, network
access, physical probing, soldering, power interruption, destructive
testing, or experiment execution.

The existing no-mechanical-redesign decision remains in force and is
neither revisited nor waived here. A later failure is a blocker or a
separately governed redesign request, never permission to alter mechanics
or silently drop QR/SD requirements.

Only a later, separately reviewed H3-B commit may register an exact run
against identified specimens, apparatus, procedure, repetitions,
calibration, exclusions, analysis, thresholds, abort conditions, and a
safe-command allowlist. Only a still later H3-C owner record naming the
exact H3-B commit and exact run IDs may authorize execution. General
permission to continue is not destructive or physical-execution consent.

## Standing state (unchanged by this document)

- Gates A–E remain OPEN; owner decisions OD-01 through OD-08 remain
  unresolved; all `QK-LIM` values remain open; all `QK-TST` rows remain
  `PLANNED — NOT RUN`; every F2 experiment remains
  `PROTOCOL TEMPLATE — RUN REGISTRATION PENDING — NOT RUN`; the evidence
  register remains empty. This document changes none of them.
- F2.0 PREPARATION COMPLETE — EXPERIMENTS NOT AUTHORIZED OR RUN
- F2 overall INCOMPLETE
