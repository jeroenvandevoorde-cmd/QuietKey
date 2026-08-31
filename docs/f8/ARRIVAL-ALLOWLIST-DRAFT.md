# F8 Arrival Allowlist Inactive Candidate

DRAFT - NOT ACTIVE - ZERO APDU COMMANDS AUTHORIZED

## Authority boundary

The active mock registration remains `QK-F8-G0-EMPTY-V1`, and the enrollment
registration is `QK-F8-ENROLL-EMPTY-V1`; both are defined in
`NONMUTATING-ALLOWLIST.md` and both authorize zero APDUs. The exact candidate
below is registered but inactive, absent from both code tables, and grants no
execution authority.

No command byte, AID, response, status word, size, timeout, repetition or
sequence may be inferred from generic J3R180, JCOP, GlobalPlatform, Java Card
or ISO-7816 knowledge. Activation requires a later Owner row carrying both an
official specification reference and a source tying the data objects to the
delivered J3R180 profile. Neither source is registered.

## Existing empty-draft table

This retained table remains empty so the existing mock checker registration
cannot acquire a command merely because the separate candidate is documented.

| Order | Exact command bytes or bounded mask | Command/data length rule | Purpose | Allowed lifecycle/session position | Exact expected response shape | Allowed status words | Per-command repetitions | Timing capture | Stop condition | Source ID/hash | Status |
|---|---|---|---|---|---|---|---|---|---|---|---|

NONE - ZERO DRAFT APDU COMMANDS; ZERO ACTIVE APDU COMMANDS.

## Registered inactive candidate

The candidate sequence is exact and may be activated only as one later bounded
registration:

1. `80 CA 00 66 00` (5 bytes), at most once and first. Its purpose is candidate
   arrival identity data. Success requires status `9000` plus an exact response
   grammar supplied by the missing pinned sources; no grammar is inferred.
2. `80 CA 9F 7F 00` (5 bytes), at most once and second, only after the first
   response meets that later grammar. Its purpose is candidate CPLC data.
   Success is exactly `9F 7F 2A` followed by 42 bytes and then status `9000`.

For either command, every other status is captured verbatim and stops the run
for Owner disposition. There is no `SELECT`, retry, `61xx` follow-up, `6Cxx`
correction, chaining, alternate CLA or other command. No command may be added,
reordered, repeated, corrected or explored during execution.

## Activation checklist

- [ ] Official specification reference registered and blob-pinned.
- [ ] Source tying both objects to the delivered J3R180 profile registered and
      blob-pinned.
- [ ] Exact success grammar for `80 CA 00 66 00` fixed by those sources.
- [ ] Specimen and apparatus evidence complete and aliases bound.
- [ ] Later Owner decision activates an exact registration and execution row.
- [ ] Code table and tests change in the same bounded activation range.

Until every prerequisite is complete, no APDU may reach a specimen. Any
unlisted behavior stops and returns to Owner disposition rather than being
explored ad hoc.
