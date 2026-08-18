# F2 Target-Core Protocol Context — Toolchain and ARMv6

F2 PREPARATION ONLY — TARGET WORK NOT RUN — NO GATE CLOSED

This document gives protocol context for the toolchain and ARMv6 feasibility
experiments. The single canonical definition of each experiment lives in
`docs/f2/EXPERIMENT-REGISTER.md`; this document references register IDs only
and duplicates no row.

## Experiments covered

- QK-F2E-001 — ARMv6 candidate toolchain reproducible-build feasibility
- QK-F2E-002 — ARMv6 secp256k1 reference-operation timing envelope

## Context

OD-01 (`docs/OPEN-DECISIONS.md`) holds the production-toolchain decision
open. Its candidate direction is Rust plus a narrow pinned `libsecp256k1` C
boundary, with a measured all-C fallback only if necessary. No production
language, compiler, or target has been selected, and this document selects
none.

The roadmap purpose of F2 is to gather real-hardware decision inputs for
OD-01 and OD-02 before committing (`docs/BUILD-ROADMAP.md`). The two
experiments above prepare the toolchain half of that input. Their outputs,
if ever produced, become evidence records under the schema referenced in
`docs/f2/EVIDENCE-REGISTER.md` and decision-input placeholders in
`docs/f2/DECISION-INPUTS.md`. They resolve nothing: OD-01 can be resolved
only by an explicit owner decision in `docs/DECISION-LOG.md`.

## Boundaries specific to this protocol area

- No probe artifact built under QK-F2E-001 or QK-F2E-002 is product code,
  and none may ever be promoted to product code. The location of any future
  bench or probe source remains OPEN until run registration under H3; any
  future harness must be separately owner-authorized, source-reviewable,
  license-recorded, and pinned by a content-addressed revision or hash. No
  probe or harness source enters this repository in F2.0.
- No compiler, interpreter, or build toolchain probe is ever exercised on
  the hosting platform of this repository. Toolchain probing happens only on
  identified, registered bench builders under a future H3 run registration;
  the hosting environment of this governance repository is never a builder,
  bench, or measurement apparatus.
- Any provenance recorded under QK-F2E-001 follows the third-party-source
  discipline referenced by QK-REQ-ASR-004; nothing here adds a source to
  `docs/SOURCE-REGISTER.md`.
- Timing observations under QK-F2E-002 are raw decision inputs only. They do
  not set, suggest, or pre-commit any `QK-LIM` value; every limit value
  remains `OPEN — VALUE NOT AUTHORIZED IN F1` until owner authorization.
- Supply-chain exposure during any future run (component download, builder
  provisioning) is itself in scope of QK-THR-009 and is recorded as a
  limitation in the corresponding evidence record.

## Execution status

Both experiments are protocol templates. No run registration exists; run
registration requires a future owner-authorized commit (H3). No specimen or
apparatus is identified.
