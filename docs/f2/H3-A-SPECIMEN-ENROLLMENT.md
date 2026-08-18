# H3-A — Specimen Enrollment Intake Scaffold

F2 PREPARATION ONLY — TARGET WORK NOT RUN — NO GATE CLOSED

- Base: c46024a4c3c82659cae71211eaac4ba3e1095466
- Document status: DRAFT — OWNER INPUT REQUIRED — NO HARDWARE SELECTED — NO EXECUTION AUTHORITY
- Enrollment status: INCOMPLETE — NO SPECIMEN IDENTIFIED

## What H3-A is and is not

H3-A is an F2.1 administrative intake checkpoint. It is not roadmap
milestone F3, not the H3-B run-registration commit, and not H3-C execution
authorization. H3-A authorizes intake preparation only. A template is not a
run; a registered run is not an authorized run; an authorized run is not an
accepted result; evidence never changes a gate or decision automatically.

This repository contains no actual P0/RV3 BOM, CAD, schematic, PCB,
enclosure, board, camera, display, keypad, SD/card-reader, power-path, or
exact-card specification. These materials were NOT PROVIDED to this
repository; this document makes no claim about whether they exist elsewhere.

Facts may later come only from explicit project-owner-supplied inventory.
They may not be inferred, researched, normalized, or filled in from concept
renders, photos, filenames, product listings, vendor claims, AI-generated
artifacts, earlier recommendations, or plausible defaults.

## Combined intake and empty ledger

The slot names below are bookkeeping categories only. They are not a
component recommendation, suggestion, or selection, and they name no
manufacturer, product, SKU, protocol, candidate, proxy, supplier, reader,
camera, board, card, or apparatus.

| Slot | Identity | BOM/CAD/mechanical reference |
|---|---|---|
| Integrated P0/RV3 assembly | NOT IDENTIFIED | NOT PROVIDED |
| Mechanical/enclosure revision | NOT IDENTIFIED | NOT PROVIDED |
| Compute target | NOT IDENTIFIED | NOT PROVIDED |
| Camera path (sensor/lens/focus/mount/window/cable) | NOT IDENTIFIED | NOT PROVIDED |
| Display path | NOT IDENTIFIED | NOT PROVIDED |
| Keypad path | NOT IDENTIFIED | NOT PROVIDED |
| Boot-storage path | NOT IDENTIFIED | NOT PROVIDED |
| Transport-SD path | NOT IDENTIFIED | NOT PROVIDED |
| Card electrical/interface path | NOT IDENTIFIED | NOT PROVIDED |
| Candidate card batch | NOT IDENTIFIED | NOT PROVIDED |
| Power/battery/brownout path | NOT IDENTIFIED | NOT PROVIDED |
| Candidate bench readers and measurement apparatus | NOT IDENTIFIED | NOT PROVIDED |

## Enrollment record fields (defined for later owner input; none populated)

When the owner later supplies inventory, each enrollment record will carry
only these fields:

- Privacy-safe public asset alias.
- Classification: TARGET, PROXY, APPARATUS, or SACRIFICIAL.
- Exact identity held in a separately approved offline/private inventory,
  not committed to this public repository.
- Manufacturer / model / part / hardware revision (owner-supplied).
- Lot or batch, where safe to publish.
- Quantity.
- Provenance.
- Custody / availability.
- Owner-supplied physical-label or document reference.
- Relationship to P0/RV3.
- Firmware / applet / ATR, only if already owner-supplied without
  interrogating any asset.
- Explicit mutable/destructive permission.

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

H3-A does not authorize procurement, ordering, energizing, connecting,
opening, inserting a card or SD, reading ATR/APDUs, scanning QR,
camera/display/keypad trials, applet loading or deletion, lifecycle or
management-key changes, compilation, source fetching, network access,
physical probing, soldering, power interruption, destructive testing, or
experiment execution.

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
