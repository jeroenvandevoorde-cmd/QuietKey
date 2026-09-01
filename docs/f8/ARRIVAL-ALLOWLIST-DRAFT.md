# F8 Arrival Allowlist Activation Record

QK-F8-IDENT-V1 STOPPED; QK-F8-IDENT-V2 PREPARED

The earlier state marker `DRAFT - NOT ACTIVE - ZERO APDU COMMANDS AUTHORIZED`
is retained as a historical G0 comparison fact only and is superseded for the
separate identity adapter by QK-DEC-153. QK-DEC-153-SUP-002 supersedes the
unfilled V1 schedule after its first session stopped and registers V2.

## Authority boundary

The mock registration `QK-F8-G0-EMPTY-V1` and enrollment registration
`QK-F8-ENROLL-EMPTY-V1` remain empty. QK-DEC-153-SUP-002 registers the exact
candidate below as `QK-F8-IDENT-V2` only through the private fixed-sequence
identity adapter. Sessions remain stopped until its row and final tool source
receive the required review.

No command byte, AID, response, status word, size, timeout, repetition or
sequence may be inferred from generic J3R180, JCOP, GlobalPlatform, Java Card
or ISO-7816 knowledge. QK-DEC-153-SUP-002 pins section 11.9 of the already
registered Owner-archived GlobalPlatform v2.4 reference for exact SELECT
construction; QK-DEC-153 pins GET DATA and object `00 66`, and exact JCAlgTest commits and blobs
for the command constants and one exact-ATR J3R180 behavioral record. The
legacy VISA Open Platform `9F 7F` CPLC object is outside the GlobalPlatform tag
table; its source boundary is solely the pinned JCAlgTest evidence.

## Retained empty G0 table

This retained table remains empty so the existing mock checker registration
cannot acquire a command merely because the separate identity path is active.

| Order | Exact command bytes or bounded mask | Command/data length rule | Purpose | Allowed lifecycle/session position | Exact expected response shape | Allowed status words | Per-command repetitions | Timing capture | Stop condition | Source ID/hash | Status |
|---|---|---|---|---|---|---|---|---|---|---|---|

NONE - ZERO DRAFT APDU COMMANDS; ZERO ACTIVE APDU COMMANDS.

That retained marker applies only to the empty G0 mock table above. It does not
describe or authorize the separately fixed `QK-F8-IDENT-V2` adapter.

## Activated fixed sequence

The stopped V1 session on specimen `J3R180-02` reached its first command once,
received `69 85`, sent no second command and disconnected cleanly. Its source
commit and supplied timestamp are `800da1a2b6158e08195237c2523cb560a957571a`
and `2026-09-01T14:00:40Z`; exact private transcript byte count and SHA-256 are
still owed before evidence registration. The result is compatible with the
absence of an application context, while both pinned behavioral sources SELECT
before GET DATA; it proves neither the internal cause nor any capability.

The V2 identity sequence is exact:

1. `00 A4 04 00 00` (5 bytes), at most once and first. It is SELECT by name
   with empty data, selecting the default application. Success is
   `body || 90 00`, at most 258 total bytes, with `body` exactly one canonical
   definite-length BER-TLV whose outer tag is `6F`; its contents are
   uninterpreted and may have zero length.
2. `80 CA 00 66 00` (5 bytes), at most once and second, only after the SELECT
   response meets its exact grammar. Its purpose is
   Card Recognition Data. Success is `body || 90 00`, at most 258 total bytes,
   with `body` one complete canonical definite-length BER-TLV whose outer tag
   is `66`, whose value is nonempty, and whose first nested tag byte is `73`.
3. `80 CA 9F 7F 00` (5 bytes), at most once and third, only after the second
   response meets that exact grammar. Its purpose is CPLC data.
   Success is exactly `9F 7F 2A` followed by 42 bytes and then status `9000`.

For the first two commands, canonical definite length is short form for value
lengths 0 through 127 or `81` followed by lengths 128 through 253; indefinite,
`82`, nonminimal, truncated and trailing encodings reject. For every command,
every other status is captured verbatim and stops the run for Owner
disposition. There is no other `SELECT`, retry, `61xx` follow-up, `6Cxx`
correction, chaining, alternate CLA or other command. No command may be added,
reordered, repeated, corrected or explored during execution.

## Activation checklist

- [x] Owner-archived official specification exact-byte identity registered.
- [x] JCAlgTest command and result commits and blobs registered.
- [x] Exact V1 grammars frozen by QK-DEC-153 and V2 SELECT grammar by its supplement.
- [x] Specimen and apparatus evidence complete and aliases bound.
- [x] QK-DEC-153-SUP-002 registers the exact V2 sequence and fresh three-session order.
- [x] Code table and tests change in the same bounded V2 range.

No V2 identity session may run before the final tool source commit is published
and reviewed.
Any unlisted behavior stops and returns to Owner disposition rather than being
explored ad hoc.
