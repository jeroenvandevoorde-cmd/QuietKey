# F2 QR Protocol Context — Camera and BBQr Type-P Feasibility

F2 PREPARATION ONLY — TARGET WORK NOT RUN — NO GATE CLOSED

This document gives protocol context for the camera and BBQr type-P
feasibility experiments. The single canonical definition of each experiment
lives in `docs/f2/EXPERIMENT-REGISTER.md`; this document references register
IDs only and duplicates no row.

## Experiments covered

- QK-F2E-006 — Actual-camera BBQr type-P frame-rate and decode feasibility
- QK-F2E-007 — QR reassembly resource observation on candidate target
- QK-F2E-015 — Animated signed-PSBT QR egress feasibility

## Context

The transport requirement family fixes animated QR ingest to uncompressed
BBQr type P only (QK-REQ-TRN-003) and requires bounded reassembly
(QK-REQ-TRN-005). The related planned tests QK-TST-BENCH-001 and parts of
QK-TST-BENCH-003 (`docs/TEST-ARCHITECTURE.md`) remain `PLANNED — NOT RUN`
and are defined against the exact production hardware, which does not exist
yet. The F2 experiments above are earlier, coarser feasibility probes on
candidate hardware. QK-F2E-006 covers ingest (camera side) and QK-F2E-015
covers egress (animated signed-PSBT display side, checked against an
independent receiver); QK-F2E-015 complements, and does not replace, the
ingress experiment. Their canonical planned-test mapping is: QK-F2E-006
prepares and may inform QK-TST-BENCH-001; QK-F2E-007 prepares and may
inform QK-TST-BENCH-003; QK-F2E-015 prepares and may inform QK-TST-DIFF-004.
None of them executes or changes any of those tests, which remain
`PLANNED — NOT RUN` and are defined against the exact production target: a
candidate target cannot execute an exact-target test. All three are Gate A
preparation only, not Gate A evidence, and inform OD-05 (which governs the
open `QK-LIM-QR` rows) plus a future owner hardware selection for which no
numbered decision exists yet.

## Boundaries specific to this protocol area

- No camera, lens, sensor, display, or target board is selected by this
  document; every specimen field is open until run registration.
- Data gathered under QK-F2E-007 may inform, never set, the open `QK-LIM-QR`
  rows; every limit value remains `OPEN — VALUE NOT AUTHORIZED IN F1` until
  owner authorization, and those rows are governed by OD-05.
- Hostile frame streams and any egress payloads used in any future run are
  public synthetic, no-funds, non-mnemonic, non-custody bench inputs created
  solely for the registered bench run; no fixture enters this repository.
- Decoder, reassembly, and receiver implementations used on the bench are
  reference implementations identified in the evidence record; they are not
  product code. The location of any future bench source remains OPEN until
  run registration under H3; any future harness must be separately
  owner-authorized, source-reviewable, license-recorded, and pinned by a
  content-addressed revision or hash.
- Findings on candidate hardware do not transfer to the eventual fixed
  mechanics; that distinction is recorded as a limitation in every evidence
  record produced under these experiments.

## Execution status

All three experiments are protocol templates. No run registration exists; run
registration requires a future owner-authorized commit (H3). No specimen or
apparatus is identified.
