# F8-G0 Card-Bench Groundwork

EXPERIMENTAL - HOST SCAFFOLD AND EMPTY REGISTERS - NOT A WALLET

## Status and authority

QK-DEC-105 authorizes only non-mutating groundwork for Owner-supplied,
arriving J3R180 specimens. This directory and `host/qk-card-trace/` do not
select a card, freeze an APDU protocol, resolve OD-02, execute
QK-TST-BENCH-002, or change any Gate. Protocol-Lab retains its separate
capture and Reader scope; no source moves between the repositories.

The controlling card behavior remains Core Architecture v1 sections 4.5 and
6.1 through 6.5, QK-REQ-CARD-001 through QK-REQ-CARD-010, and
QK-TST-BENCH-002. The M20 paper matrix is sourcing and planning input only.
Every physical observation will bind only to the delivered, enrolled J3R180
revision and batch. Nothing transfers to J2R180 or another variant.

## Ordered execution locks

The following sequence is mandatory:

1. The Owner supplies the physical facts required by
   `SPECIMEN-REGISTER.md`; an agent may not infer or populate them.
2. Every reader, host stack, tool and planned power-cut apparatus is entered
   in `APPARATUS-REGISTER.md` from observed or Owner-supplied facts.
3. A later Owner-ratified registration replaces the empty live APDU list in
   `NONMUTATING-ALLOWLIST.md` with exact command bytes or masks.
4. A separately authorized run binds exact enrolled aliases, apparatus,
   repetitions, procedures and raw-artifact locations to one registration in
   `RUN-REGISTER.md`.
5. Only that run may operate the named specimens. Any unexpected identity,
   state, status or response stops it.

Until step 3, no live APDU is approved. Reset, ATR capture and transport
protocol negotiation are not APDU commands, but this distinction is not
physical-run authorization. No card is connected or reset merely because
the offline checker exists.

## Offline trace checker

`qk-card-trace` reads one complete canonical mock trace from standard input.
It opens no file or device and has no PC/SC, card, network, cryptographic,
provisioning, applet or mutation interface. The caller must provide five
positive HOST-harness controls on every invocation: maximum input bytes,
maximum record count, maximum decoded bytes in one record and maximum
identifier bytes, plus maximum bytes in the mock ATR record. There is no
default. These are mock-fixture ingestion controls for that invocation only
and never select or imply a QK-LIM-APDU, card, session or product value;
every QK-LIM-APDU row stays open. Nonempty lowercase-even hex is structural
mock-envelope syntax rather than a physical-card minimum.

The mock envelope carries a deterministic filename identity and a
lowercase 64-hex `raw_sha256` value. The checker validates that field but
does not calculate it. A future registered evidence procedure computes
SHA-256 for raw media and trace artifacts with its recorded toolchain. The
checker reports only counts, the canonical filename and the supplied hash;
it never echoes ATR, protocol or APDU payload bytes.

The currently registered allowlist identifier is
`QK-F8-G0-EMPTY-V1`. Mock traces require `MOCK-` run, specimen and reader
aliases and forbid APDU records. `mode=LIVE` is rejected, and live APDU
commands are default-denied by an empty code table. A nonempty table and a
live envelope require a new decision and source change; generic Java Card
knowledge is never enough. The mock filename/envelope is not a silently
selected future live-evidence format.

## Committed records

- `SPECIMEN-REGISTER.md`: empty enrollment ledger and exact intake schema.
- `APPARATUS-REGISTER.md`: empty apparatus ledger and exact identity schema.
- `NONMUTATING-ALLOWLIST.md`: empty live APDU registration.
- `ARRIVAL-ALLOWLIST-DRAFT.md`: fillable, explicitly inactive paperwork for
  the later delivered-card non-mutating command registration; it contains
  zero command bytes and does not alter the active empty list.
- `RUN-REGISTER.md`: seven complete future-design packets, all blocked and
  `NOT RUN` until exact physical bindings and later execution authority exist.
- `EXECUTION-PACKETS.md`: seven execution-ready fillable run-instance forms;
  every physical, count, command and authority field remains inactive.

Raw photographs, private serial-to-alias mappings, card traces, PC/SC logs,
power traces and other media remain outside Git. Committed manifests later
carry only approved aliases, deterministic artifact names, byte counts,
SHA-256 values, custody locations and the source commit.

## F8-G0 exclusions

Applet loading or deletion, management authentication, key or storage
mutation, provisioning, signing, RNG sampling, power interruption, endurance
execution, contactless bearer operations, secret-bearing fixtures, APDU or
session-limit freezing, OD-02 resolution, production-card selection and all
Gate conclusions require later Owner authorization.
