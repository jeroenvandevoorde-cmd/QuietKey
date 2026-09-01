# F8 Card-Bench Preparation and Enrollment

EXPERIMENTAL - HOST BENCH OBSERVATION - FIXED READ-ONLY IDENTITY SEQUENCE

## Status and authority

QK-DEC-105 established the non-mutating F8 groundwork. QK-DEC-147 opened the
ring-fenced `bench/card-enrollment/` preparation lane for the delivered reader
and three Owner-supplied J3R180 specimens; enrollment is complete and frozen.
QK-DEC-153-SUP-002 registers only the fixed read-only `QK-F8-IDENT-V2`
sequence. The lane creates no card secret, key or applet, authorizes no
mutation, changes no Gate, and makes no target or card-capability claim.
Protocol-Lab retains its separate capture and Reader scope; no source moves
between the repositories.

The controlling card behavior is Core Architecture v2 under QK-DEC-121,
QK-REQ-CARD-001 through QK-REQ-CARD-010, QK-REQ-KIT-010,
QK-REQ-KIT-012, QK-REQ-KIT-013, and QK-TST-BENCH-002. The required card is
role B. An optional byte-equivalent spare may be created only during original
setup; no Card-C role or general two-card path exists, and no later second live
card may be added. M20's C1/C2/C3 labels identify candidate platforms, never
signer roles. Every physical observation binds only to the delivered specimen,
apparatus and recorded run; nothing transfers silently to another revision,
batch, reader path or host.

Kit-Spend is the missing-card path. A future Kit-Restore replacement-card run
requires an external confirmation that the original card remains physically in
hand and never converts that statement into machine proof. F8 records can
establish exercised card bytes and behavior, not card possession or
destruction, absence of another live card, Kit-envelope integrity, or
coordinator UTXO completeness.

## Current registration and ordered locks

The completed enrollment registration `QK-F8-ENROLL-EMPTY-V1` permits bounded
reader enumeration, exclusive connection to the exact registered reader, one
explicit reset, exact ATR and negotiated-protocol capture, and disconnect. It
permits zero APDU commands. Its three specimen transcripts and public ATRs are
registered in `ENROLLMENT-MANIFEST.md`.

The stopped `QK-F8-IDENT-V1` registration authorizes no further session. Its
single J3R180-02 attempt returned `69 85` to `80 CA 00 66 00`, sent no later
command and disconnected cleanly; its exact private artifact identity is
registered in `IDENTITY-MANIFEST.md`. The registered replacement
`QK-F8-IDENT-V2` permits one fixed private adapter to issue exactly
`00 A4 04 00 00`, then only after validation exactly
`80 CA 00 66 00`, then only after validation exactly `80 CA 9F 7F 00`.
Generic transmit remains mechanically refused as
`ApduTransmitNotAuthorized`; no caller supplies an APDU.

Fresh V2 contact order is `J3R180-02`, then `J3R180-03` only after 02 passes,
then protected reference `J3R180-01` only after both prior sessions pass. Any
non-PASS identity outcome stops the sequence for Owner disposition. The
J3R180-02 and J3R180-03 V2 PASS artifacts are registered. J3R180-01 remains
stopped until the J3R180-03 evidence commit is checked by the LOA. The Owner
records that J3R180-03 ran after the LOA check of row 1 but before row 1 was
registered on `main`; that observation stands, and no further identity session
may run ahead of its ledger. The labeling photographs remain an optional,
unhashed private-custody fact under QK-DEC-148; no present or future step
depends on them.

## Enrollment evidence boundary

The canonical enrollment transcript is `QK-CARD-ENROLLMENT-V1`, LF-terminated
ASCII. It binds the allowlist and tool versions; the supplied 40-lowercase-hex
source commit; UTC timestamp; host, reader and specimen aliases; every
enumerated reader-name byte and the selected name as complete lowercase hex;
the exact operation order and outcomes; negotiated protocol; ATR bytes as
complete lowercase hex; zero APDU request and response counts; disconnect
outcome; and one named result. Byte fields encode one octet per pair with no
redaction or normalization. The tool never persists automatically; the Owner
redirects output into the private bundle, and `ENROLLMENT-MANIFEST.md` registers
the later exact byte counts and SHA-256 values.

Serials and all identity CPLC, Card Data, FCI, raw-transcript and APDU bytes
remain verbatim in durable private Owner custody and are hash-bound when the
identity manifest is completed. The repository publishes aliases, exact byte
counts, SHA-256 values, timestamps, tool and source commits, custody paths,
counts and each specimen ATR verbatim, but never publishes the FCI, CPLC or
Card Data bytes.
The absence of raw private evidence from Git is deliberate, not a license to
normalize it.

## Existing mock trace checker

`host/qk-card-trace` remains the earlier offline mock-trace checker. It opens no
file or device and has no PC/SC, card, network, cryptographic, provisioning,
applet or mutation interface. Its invocation bounds are HOST mock-ingestion
controls only and select no QK-LIM-APDU, card, session or product value. The new
ring-fenced enrollment boundary neither converts the mock format into a live
format nor changes any existing F8 run packet.

## Committed records

- `APPARATUS-REGISTER.md`: supplied host, reader, hub and topology facts.
- `SPECIMEN-REGISTER.md`: supplied order, physical appearance, assignments,
  custody and completed enrollment order.
- `NONMUTATING-ALLOWLIST.md`: frozen zero-APDU enrollment registration,
  stopped V1 identity registration, and exact V2 operation bounds.
- `ARRIVAL-ALLOWLIST-DRAFT.md`: retained activation record for the stopped V1
  sequence and the three-command V2 replacement.
- `ENROLLMENT-MANIFEST.md`: completed enrollment evidence ledger.
- `IDENTITY-MANIFEST.md`: registered stopped V1 artifact and the V2 transcript
  ledger, with rows 1 and 2 registered and row 3 stopped.
- `RUN-REGISTER.md` and `EXECUTION-PACKETS.md`: the existing seven future bench
  packets, still blocked until their own Owner rows.

## Exclusions

Applet loading or deletion, management authentication, key or storage
mutation, provisioning, signing, RNG sampling, power interruption, endurance
execution, contactless bearer operations, secret-bearing fixtures, APDU or
session-limit freezing, OD-02 resolution, production-card selection and every
Gate conclusion require later Owner authority.
