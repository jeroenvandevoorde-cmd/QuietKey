# F8 J3R180 Specimen Register

EXPERIMENTAL - SUPPLIED INTAKE FACTS REGISTERED - NO CARD CONTACT RECORDED

## Batch record

- Supplier: Cardomatic.
- Order reference: `09957`.
- Ordered: 2026-08-25.
- Received: 2026-08-31.
- Quantity: three cards.
- Packaging condition: perfect.
- Printed markings: none.
- Appearance before labeling: all three were physically indistinguishable,
  fully white on front and back.
- Labels: `01`, `02` and `03`, assigned arbitrarily because all three shared an
  identical history at labeling time.
- Recorder: Owner.
- Custody: locked storage at the Owner's premises.
- Photographs: labeled cards and packaging photographed at labeling time on
  the Owner's iPhone; stored on that iPhone and in the Owner's iCloud account.
  Exact filenames, UTC timestamps, byte counts and SHA-256 values are pending
  registration in the private custody bundle.

The claimed `J3R180` catalog path is an Owner-supplied procurement fact, not a
card capability result. No ATR, protocol, serial, CPLC value, APDU response or
physical-card identity has yet been observed through this lane.

## Assignment and contact order

`J3R180-01` is the non-sacrificial reference, `J3R180-02` is the power-cut
specimen, and `J3R180-03` is the endurance specimen. These assignments authorize
no mutation. Contact order is exact:

1. `J3R180-02` alone.
2. `J3R180-03` only after specimen 02's complete transcript is registered and
   reviewed.
3. Protected reference `J3R180-01` only after the procedure has succeeded
   twice.

The applied physical labels and the committed ledger rows are the complete
precondition for specimen contact and are complete. The photograph set is an
optional private-custody fact: no contact or later step waits on its hashes.
Any unexpected response stops the procedure for Owner disposition; it is not
explored ad hoc.

## Publication and custody boundary

Verbatim photographs and specimen serials, plus any future CPLC bytes and raw
capture bundles, remain in durable private Owner custody and must be hash-bound
when their manifests are completed. The repository records aliases, exact byte
counts, SHA-256 values, timestamps, tool and source commits, and privacy-safe
custody paths. Each specimen ATR is published verbatim in
`ENROLLMENT-MANIFEST.md` after enrollment. Every future APDU byte remains
verbatim inside its registered private bundle.

## Ledger

| Alias | Claimed path | Batch link | Packaging/marking record | Photo manifest | Custody | Assignment | Mutable permission | Source commit | Status |
|---|---|---|---|---|---|---|---|---|---|
| `J3R180-01` | Owner-supplied J3R180 | Cardomatic `09957`, 1 of 3 | Perfect packaging; no printed markings; fully white front/back before arbitrary label `01` | `OPTIONAL - UNHASHED` | Locked Owner-premises storage | NON-SACRIFICIAL REFERENCE; contacted last | `NONE` | `PENDING - this register's commit` | INTAKE FACTS REGISTERED; PHOTO HASH OPTIONAL; NO CONTACT |
| `J3R180-02` | Owner-supplied J3R180 | Cardomatic `09957`, 1 of 3 | Perfect packaging; no printed markings; fully white front/back before arbitrary label `02` | `OPTIONAL - UNHASHED` | Locked Owner-premises storage | POWER-CUT SPECIMEN; contacted first | `NONE` | `PENDING - this register's commit` | INTAKE FACTS REGISTERED; CONTACT AUTHORIZED; NOT YET CONTACTED |
| `J3R180-03` | Owner-supplied J3R180 | Cardomatic `09957`, 1 of 3 | Perfect packaging; no printed markings; fully white front/back before arbitrary label `03` | `OPTIONAL - UNHASHED` | Locked Owner-premises storage | ENDURANCE SPECIMEN; contacted second | `NONE` | `PENDING - this register's commit` | INTAKE FACTS REGISTERED; PHOTO HASH OPTIONAL; NO CONTACT |

Contactless condition remains uncharacterized and no contactless bearer
operation is authorized. Quantity mismatch, substitute, conflicting marking,
custody ambiguity or assignment ambiguity stops intake rather than being
repaired by assumption.
