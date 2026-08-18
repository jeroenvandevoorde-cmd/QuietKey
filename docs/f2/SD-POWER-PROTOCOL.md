# F2 SD and Power Protocol Context — Electrical and Interruption Feasibility

F2 PREPARATION ONLY — TARGET WORK NOT RUN — NO GATE CLOSED

This document gives protocol context for the SD electrical and power
interruption feasibility experiments. The single canonical definition of
each experiment lives in `docs/f2/EXPERIMENT-REGISTER.md`; this document
references register IDs only and duplicates no row.

## Experiments covered

- QK-F2E-008 — SD interface electrical and removal behavior probe
- QK-F2E-009 — SD output write, sync, and read-back interruption probe
- QK-F2E-010 — Provisioning-interruption feasibility probe

## Context

The transport requirement family requires that inputs are never overwritten
under interruption (QK-REQ-TRN-002), that incomplete outputs are never
presented as complete (QK-REQ-TRN-008), that hostile SD metadata is never
mounted or parsed by a trusted kernel (QK-REQ-TRN-009), and that SD access
is a bounded userspace design (QK-REQ-TRN-010). The related planned tests
QK-TST-PWR-001, QK-TST-PWR-003, and QK-TST-PWR-005
(`docs/TEST-ARCHITECTURE.md`) remain `PLANNED — NOT RUN` and are defined
against the production design, which does not exist. The three F2
experiments above are earlier feasibility probes on candidate hardware.
QK-F2E-008 informs OD-06, which governs the QK-REQ-TRN-009/QK-REQ-TRN-010
mechanism selection. QK-F2E-009 informs OD-05, which governs the
`QK-LIM-SD` output-completion rows it cites. QK-F2E-010 prepares the
interruption-injection method only: a mock non-product sequence on candidate
hardware cannot execute QK-TST-PWR-001 and yields no Gate A or Gate D
evidence. All three also inform a future owner hardware selection for which
no numbered decision exists yet, and all are Gate D (and, for QK-F2E-010,
Gate A) preparation only.

## Boundaries specific to this protocol area

- Sacrificial media only. Media interrupted under QK-F2E-009 are treated as
  consumed and are never reused for any custody-relevant purpose.
- Power interruption uses a controlled power-cut apparatus only, so every
  interruption point is recorded; ad-hoc unplugging is excluded.
- The mock provisioning sequence in QK-F2E-010 contains no secret material
  and no seed-like fixture of any kind.
- Bench observation runs from a bounded userspace position; no trusted
  kernel mounts hostile media at any point.
- Data gathered here may inform, never set, the open `QK-LIM-SD` rows; every
  limit value remains `OPEN — VALUE NOT AUTHORIZED IN F1` until owner
  authorization.
- No fixture, probe, or bench source code enters this repository in F2.0.
  The location of any future bench tooling remains OPEN until run
  registration under H3; any future harness must be separately
  owner-authorized, source-reviewable, license-recorded, pinned by a
  content-addressed revision or hash, and identified inside the evidence
  records it produces.
- Any future media fixture is public synthetic, no-funds, non-mnemonic,
  non-custody material created solely for the registered bench run; no
  fixture or artifact enters the F2.0 preparation commit.

## Execution status

All three experiments are protocol templates. No run registration exists;
run registration requires a future owner-authorized commit (H3). No specimen
or apparatus is identified.
