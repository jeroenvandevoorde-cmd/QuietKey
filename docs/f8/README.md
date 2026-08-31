# F8 Card-Bench Preparation and Enrollment

EXPERIMENTAL - HOST BENCH PREPARATION - ZERO APDU COMMANDS AUTHORIZED

## Status and authority

QK-DEC-105 established the non-mutating F8 groundwork. QK-DEC-147 opens the
ring-fenced `bench/card-enrollment/` preparation lane for the delivered reader
and three Owner-supplied J3R180 specimens. The lane creates no card secret, key
or applet, authorizes no mutation, changes no Gate, and makes no target or card-
capability claim. Protocol-Lab retains its separate capture and Reader scope;
no source moves between the repositories.

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

The sole active enrollment registration is `QK-F8-ENROLL-EMPTY-V1`. It permits,
once all evidence prerequisites are complete, bounded reader enumeration,
exclusive connection to the exact registered reader, one explicit reset, exact
ATR and negotiated-protocol capture, and disconnect. It permits zero APDU
commands. The enrollment tool has no transmit surface and names every attempted
transmit `ApduTransmitNotAuthorized`.

Preparation has two parallel prerequisites before first card contact:

- complete the private-bundle manifest for the supplied labeling and package
   photographs, including exact byte counts, SHA-256 values and timestamps.
- build and register the exact enrollment tool and source commit, then bind the
   apparatus aliases and selected reader-name bytes for the invocation.

After both prerequisites are complete, contact order is locked:

1. Contact `J3R180-02` alone and register its complete canonical transcript and
   public ATR for review.
2. Only after that review, contact `J3R180-03` and register its evidence.
3. Contact protected reference `J3R180-01` last, only after the same procedure
   has succeeded twice.

Any unexpected identity, state, status, response or evidence gap stops the
procedure for Owner disposition. No specimen contact, reset, ATR capture,
protocol negotiation or enrollment success is claimed by the records currently
in this directory. Empty-reader USB identification is permitted now.

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

Photographs, serials, and any future CPLC, raw-transcript or APDU bytes remain
verbatim in durable private Owner custody and must be hash-bound when their
manifests are completed. The repository then publishes aliases, exact byte
counts, SHA-256 values, timestamps, tool and source commits, custody paths, and
each specimen ATR verbatim. The absence of raw private evidence from Git is
deliberate, not a license to normalize it.

## Existing mock trace checker

`host/qk-card-trace` remains the earlier offline mock-trace checker. It opens no
file or device and has no PC/SC, card, network, cryptographic, provisioning,
applet or mutation interface. Its invocation bounds are HOST mock-ingestion
controls only and select no QK-LIM-APDU, card, session or product value. The new
ring-fenced enrollment boundary neither converts the mock format into a live
format nor changes any existing F8 run packet.

## Committed records

- `APPARATUS-REGISTER.md`: supplied host, reader, hub and topology facts;
  private serial and evidence hashes remain pending.
- `SPECIMEN-REGISTER.md`: supplied order, physical appearance, assignments,
  custody and contact order; photograph hashes and timestamps remain pending.
- `NONMUTATING-ALLOWLIST.md`: active zero-APDU enrollment registration and
  exact non-APDU operation bounds.
- `ARRIVAL-ALLOWLIST-DRAFT.md`: registered inactive two-command candidate;
  its required source pair is absent and it grants no execution authority.
- `ENROLLMENT-MANIFEST.md`: public/private evidence boundary and pending
  enrollment ledger.
- `RUN-REGISTER.md` and `EXECUTION-PACKETS.md`: the existing seven future bench
  packets, still blocked until their own Owner rows.

## Exclusions

Applet loading or deletion, management authentication, key or storage
mutation, provisioning, signing, RNG sampling, power interruption, endurance
execution, contactless bearer operations, secret-bearing fixtures, APDU or
session-limit freezing, OD-02 resolution, production-card selection and every
Gate conclusion require later Owner authority.
