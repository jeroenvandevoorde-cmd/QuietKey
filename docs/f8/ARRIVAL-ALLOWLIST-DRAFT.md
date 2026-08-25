# F8-G0 Arrival Allowlist Registration Draft

DRAFT - NOT ACTIVE - ZERO APDU COMMANDS AUTHORIZED

## Purpose and activation boundary

This is fillable paperwork for the later Owner-ratified, non-mutating
J3R180-arrival allowlist required by QK-DEC-105. It is not the active list.
The active registration remains `QK-F8-G0-EMPTY-V1` in
`NONMUTATING-ALLOWLIST.md`, and the live/APDU checker path remains closed.

No command byte, AID, response, status word, size, timeout, repetition or
sequence may be inferred from generic J3R180, JCOP, GlobalPlatform,
Java Card or ISO-7816 knowledge. Every populated value needs a registered
source tied to the delivered revision/batch and explicit Owner ratification.

## Registration identity - all fields required before Owner review

| Field | Value |
|---|---|
| Draft registration ID | `OWNER INPUT REQUIRED - NOT ACTIVE` |
| Supersedes active registration | `QK-F8-G0-EMPTY-V1` only after ratification |
| Owner decision row | `OWNER INPUT REQUIRED - NOT ACTIVE` |
| QuietKey source commit | `OWNER INPUT REQUIRED - NOT ACTIVE` |
| Delivered batch record | `OWNER INPUT REQUIRED - NOT ACTIVE` |
| Included specimen aliases | `OWNER INPUT REQUIRED - NOT ACTIVE` |
| Included apparatus aliases | `OWNER INPUT REQUIRED - NOT ACTIVE` |
| Card-document source IDs/hashes | `OWNER INPUT REQUIRED - NOT ACTIVE` |
| Capture-tool source/version/hash | `OWNER INPUT REQUIRED - NOT ACTIVE` |
| Operator and evidence custodian | `OWNER INPUT REQUIRED - NOT ACTIVE` |
| Planned UTC window | `OWNER INPUT REQUIRED - NOT ACTIVE` |

Any unbound field keeps this draft inactive.

## Non-APDU observations

These rows classify candidate intake observations; they do not authorize
execution and contain no rig value or expected card fact.

| Order | Observation | Exact apparatus/config binding | Expected record shape | Stop condition | Status |
|---|---|---|---|---|---|
| 1 | Reset and ATR capture | `OWNER INPUT REQUIRED - NOT ACTIVE` | `OWNER INPUT REQUIRED - NOT ACTIVE` | Any identity, transport or record-shape mismatch | `DRAFT - NOT ACTIVE` |
| 2 | Protocol negotiation capture | `OWNER INPUT REQUIRED - NOT ACTIVE` | `OWNER INPUT REQUIRED - NOT ACTIVE` | Any unregistered negotiation or state | `DRAFT - NOT ACTIVE` |

## Candidate APDU rows

Exactly zero candidate command rows exist. Before ratification, every proposed
row must be added with all columns populated from registered delivered-card
sources. Placeholder, partial and wildcard-only rows are prohibited.

| Order | Exact command bytes or bounded mask | Command/data length rule | Purpose | Allowed lifecycle/session position | Exact expected response shape | Allowed status words | Per-command repetitions | Timing capture | Stop condition | Source ID/hash | Status |
|---|---|---|---|---|---|---|---|---|---|---|---|

NONE - ZERO DRAFT APDU COMMANDS; ZERO ACTIVE APDU COMMANDS.

## Required response and sequence closure

Before this draft can be presented for ratification, it must state without
defaults or omissions:

- the exact first command and total ordered command count;
- whether every command is exact bytes or which byte positions a bounded
  mask permits to vary, with the source of each variation;
- the exact data and response length rules for every command;
- every allowed status word and its meaning at that exact sequence point;
- reset, removal, reinsertion and retry behavior, including a finite
  run-specific repetition count;
- run-specific timing capture and stop rules without selecting a product
  timeout or any QK-LIM-APDU value;
- the rejection/stop action for an extra response, missing response,
  unregistered status, changed ATR/negotiation, changed specimen/apparatus,
  state ambiguity or capture-tool error; and
- raw-artifact naming, outside-Git custody, byte-count and SHA-256 manifest
  procedure.

Any behavior not expressly listed is denied and stops the run. A discovery
cannot be added during execution; it returns to the planning loop.

## Ratification checklist

All boxes remain unchecked until an Owner review:

- [ ] Every specimen and apparatus alias resolves in the active ledgers.
- [ ] Delivered revision/batch facts and source hashes are recorded.
- [ ] Command table is nonempty only if every row is complete.
- [ ] Every command is demonstrated non-mutating from the registered source;
      absence of an obvious write opcode is insufficient.
- [ ] No management authentication, applet loading/deletion, key/storage
      mutation, provisioning, signing, RNG sampling, contactless bearer
      operation, power cut or endurance operation is present.
- [ ] Run-specific ingestion controls are supplied without changing any open
      QK-LIM-APDU or product value.
- [ ] Unexpected-state and deviation handling is explicit and fail-closed.
- [ ] Owner decision row and exact activation commit are named.
- [ ] Code table and tests change in the same bounded activation range.

Until every item is checked and the Owner row lands, this file remains
paperwork only and `QK-F8-G0-EMPTY-V1` remains the sole active registration.
