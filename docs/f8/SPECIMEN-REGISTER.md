# F8-G0 J3R180 Specimen Register

EXPERIMENTAL - EMPTY INTAKE LEDGER - NO CARD COMMAND AUTHORIZED

## Current inventory

NONE - no physical specimen is enrolled in this repository. No supplier,
order, packaging, marking, quantity, batch, serial, custody or assignment
fact has been supplied for entry. The arriving-card statement in QK-DEC-105
does not populate any of those fields.

## Required enrollment record

Each delivered card receives one privacy-safe public alias and one record
with every field below before any card command. A batch-level fact may be
referenced by individual cards, but it never replaces their assignments.

| Field | Required content |
|---|---|
| Public specimen alias | Stable ASCII identifier used in every committed record and artifact name. |
| Claimed catalog path | `J3R180` plus supplier listing/order reference exactly as supplied; not a verified identity. |
| Supplier and order | Supplier, order reference, order date, received date and quantity. |
| Packaging | Observed packaging text, labels, seals and condition; unknown fields remain `NOT OBSERVED`. |
| Card markings | Exact visible front/back/contact markings without interpretation. |
| Visible lot or serial | Privacy-safe committed value or private-map reference under the Owner-approved publication treatment. |
| Photographs | Outside-Git location, deterministic names, byte counts and SHA-256 values for all intake images. |
| Custody | Custodian, custody location or privacy-safe location alias, and transfer log reference. |
| Assignment | Exactly `NON-SACRIFICIAL`, `SACRIFICIAL-APPLET`, `SACRIFICIAL-POWER`, `SACRIFICIAL-ENDURANCE`, or another later Owner-ratified assignment. |
| Mutable permission | Exactly `NONE` for F8-G0; later authority must name the permitted mutation and specimen. |
| Contactless condition | `PRESENT - UNCHARACTERIZED` for a delivered dual-interface J3R180 unless physical identity proves otherwise; no bearer operation is authorized. |
| Source commit | Full commit that first records the completed enrollment. |
| Recorder and timestamp | Owner-supplied or observed recorder identity and UTC timestamp. |

The private exact serial/custody mapping and raw photographs remain outside
Git. The committed aliases and hashes must still permit the Owner-held map to
bind every later observation to one physical specimen.

## Stop conditions

A quantity mismatch, unrecorded substitute, conflicting marking, opened or
unexpected package state, unreadable required identity, duplicate alias,
missing photograph/hash, missing custody declaration, or missing assignment
stops intake. It is recorded as observed; it is never repaired by assuming
the paper shortlist identity. No J3R180 observation transfers to J2R180.

## Ledger

| Alias | Claimed path | Quantity link | Packaging/marking record | Photo manifest | Custody | Assignment | Contactless condition | Source commit | Status |
|---|---|---|---|---|---|---|---|---|---|

NONE - NO SPECIMENS ENROLLED.
