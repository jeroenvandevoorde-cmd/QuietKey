# F8 Arrival Allowlist Activation Record

ACTIVATED AS QK-F8-IDENT-V1

## Authority boundary

The mock registration `QK-F8-G0-EMPTY-V1` and enrollment registration
`QK-F8-ENROLL-EMPTY-V1` remain empty. QK-DEC-153 separately activates the exact
candidate below as `QK-F8-IDENT-V1` only through the private fixed-sequence
identity adapter.

No command byte, AID, response, status word, size, timeout, repetition or
sequence may be inferred from generic J3R180, JCOP, GlobalPlatform, Java Card
or ISO-7816 knowledge. QK-DEC-153 pins the Owner-archived GlobalPlatform v2.4
reference for GET DATA and object `00 66`, and exact JCAlgTest commits and blobs
for the command constants and one exact-ATR J3R180 behavioral record. The
legacy VISA Open Platform `9F 7F` CPLC object is outside the GlobalPlatform tag
table; its source boundary is solely the pinned JCAlgTest evidence.

## Retained empty G0 table

This retained table remains empty so the existing mock checker registration
cannot acquire a command merely because the separate identity path is active.

| Order | Exact command bytes or bounded mask | Command/data length rule | Purpose | Allowed lifecycle/session position | Exact expected response shape | Allowed status words | Per-command repetitions | Timing capture | Stop condition | Source ID/hash | Status |
|---|---|---|---|---|---|---|---|---|---|---|---|

NONE - ZERO QK-F8-G0-EMPTY-V1 MOCK APDU COMMANDS.

## Activated fixed sequence

The identity sequence is exact:

1. `80 CA 00 66 00` (5 bytes), at most once and first. Its purpose is
   Card Recognition Data. Success is `body || 90 00`, at most 258 total bytes,
   with `body` one complete canonical definite-length BER-TLV whose outer tag
   is `66`, whose value is nonempty, and whose first nested tag byte is `73`.
2. `80 CA 9F 7F 00` (5 bytes), at most once and second, only after the first
   response meets that exact grammar. Its purpose is CPLC data.
   Success is exactly `9F 7F 2A` followed by 42 bytes and then status `9000`.

For either command, every other status is captured verbatim and stops the run
for Owner disposition. There is no `SELECT`, retry, `61xx` follow-up, `6Cxx`
correction, chaining, alternate CLA or other command. No command may be added,
reordered, repeated, corrected or explored during execution.

## Activation checklist

- [x] Owner-archived official specification exact-byte identity registered.
- [x] JCAlgTest command and result commits and blobs registered.
- [x] Exact success grammars frozen by QK-DEC-153.
- [x] Specimen and apparatus evidence complete and aliases bound.
- [x] QK-DEC-153 activates the exact registration and three-session order.
- [x] Fixed adapter, transcript and tests land in the same activation range.

No identity session may run before the final tool source commit is published.
Any unlisted behavior stops and returns to Owner disposition rather than being
explored ad hoc.
