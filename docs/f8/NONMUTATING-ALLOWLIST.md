# F8-G0 Non-Mutating Intake Allowlist

EXPERIMENTAL - EMPTY LIVE APDU LIST - DEFAULT DENY

## Registration QK-F8-G0-EMPTY-V1

This is the complete live APDU allowlist registered by F8-G0:

| Order | Command bytes or exact mask | Purpose | Permitted response |
|---|---|---|---|

NONE - ZERO LIVE APDU COMMANDS ARE APPROVED.

The matching code table in `host/qk-card-trace/src/allowlist.rs` has length
zero. The F8-G0 checker rejects `mode=LIVE` entirely and returns
`ApduRecordNotAuthorized` for either APDU record type in its mock envelope.
It therefore accepts no live command or response and makes no live-trace
format decision.

Cold/warm reset, ATR capture and reader/PCSC T=1 negotiation are transport
observations rather than APDU commands. They are not added to the table, and
this classification does not authorize a physical run. An enrolled
specimen/apparatus set and a separately authorized run remain prerequisites.

`SELECT`, `GET DATA`, `GET STATUS`, GlobalPlatform management commands,
application commands and every undocumented command are unapproved. A later
nonempty revision must state exact command bytes or masks, allowed lengths,
expected status/response classes, sequence position, stop conditions,
delivered-card documentation source, and the Owner decision. It must update
this document, the code table, the separately reviewed live envelope and
tests in one bounded change. Generic
J3R180, JCOP, Java Card, GlobalPlatform or ISO-7816 knowledge is never an
allowlist entry.

The offline parser's caller-supplied trace, record, record-byte, identifier
and mock-ATR-byte controls are HOST ingestion controls only. They are not
card, APDU, session or product ceilings; all QK-LIM-APDU values remain open.
