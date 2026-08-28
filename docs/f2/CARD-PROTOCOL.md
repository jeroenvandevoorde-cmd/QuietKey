# F2 Card Protocol Context — Exact-Card Feasibility

F2 PREPARATION ONLY — TARGET WORK NOT RUN — NO GATE CLOSED

## QK-DEC-121 v2 supersession overlay

The experiment list below is retained as the historical F2.0 set.
QK-F2E-013's B/C-role procedure is superseded and must not run. Current card
work has one required role-B card, permits a byte-equivalent spare only during
the original setup, has no Card-C role or general two-card path, and routes a
missing card to Kit-Spend. A replacement B may be provisioned only through a
separately bound Kit-Restore run after the user's external confirmation that
the original card remains physically in hand. A future v2 registration must
bind these constraints before QK-TST-BENCH-002(g) execution.

This document gives protocol context for the exact-card feasibility
experiments. The single canonical definition of each experiment lives in
`docs/f2/EXPERIMENT-REGISTER.md`; this document references register IDs only
and duplicates no row.

## Experiments covered

- QK-F2E-003 — Exact-card APDU behavior and byte-layout survey
- QK-F2E-004 — Exact-card signing correctness and performance probe
- QK-F2E-005 — Exact-card write atomicity under controlled power interruption
- QK-F2E-011 — Exact-card derivation and key-origin boundary survey
- QK-F2E-012 — Exact-card signing nonce and RNG capability characterization
- QK-F2E-013 — historical v1 A2/B/C payload experiment; superseded by
  QK-DEC-121 and not executable for v2
- QK-F2E-014 — Exact-card lifecycle and storage-endurance probe

## Context

OD-02 (`docs/OPEN-DECISIONS.md`, STOP-BEFORE-F3) holds the exact-card
decision open: card model, capabilities, applet lifecycle, APDU byte
layouts, optional offline attestation, and rescue implementation. No card
has been selected, and this document selects none. The CANDIDATE
non-exportable-signer hypothesis remains a hypothesis; the experiments above
gather feasibility inputs that the owner may consume when resolving OD-02,
and nothing more. All of them use candidate card specimens and are Gate B
preparation and OD-02 input only: Gate B itself requires the exact
production card selected after OD-02.

These experiments prepare inputs related to the planned tests
QK-TST-BENCH-002 and QK-TST-PWR-002 (`docs/TEST-ARCHITECTURE.md`), which
remain `PLANNED — NOT RUN` and belong to later milestones. An F2 experiment
is not a planned test; it may prepare or inform a planned test but never
executes one and never changes any test status — only a separately accepted
canonical test run can do that.

## Boundaries specific to this protocol area

- Sacrificial specimens only. No card used in any future run may ever hold,
  or later be used for, custody-relevant material. Specimens interrupted
  under QK-F2E-005 are treated as consumed.
- No PIN, password, pairing secret, vendor account, or online authentication
  is introduced at any point, consistent with QK-REQ-CARD-002.
- Power interruption under QK-F2E-005 uses a controlled power-cut apparatus
  only; ad-hoc interruption is excluded because interruption points would be
  unrecorded.
- No applet, firmware, or host-side card tooling source code enters this
  repository in F2.0. The location of any future bench tooling remains OPEN
  until run registration under H3; any future harness must be separately
  owner-authorized, source-reviewable, license-recorded, pinned by a
  content-addressed revision or hash, and identified inside the evidence
  records it produces.
- Any hardware execution on a card happens only within a future H3
  owner-approved safe command allowlist; destructive and lifecycle commands
  belong in separately controlled sacrificial-card runs.
- Any future signing or card fixture is public synthetic, no-funds,
  non-custody material created solely for the registered bench run; no
  fixture or artifact enters the F2.0 preparation commit. Where signer-state
  testing requires it, a future v2-registered run may use
  owner-authorized, public, synthetic, openly disclosed, no-funds,
  non-custody raw-key or seed fixtures: these are test vectors, not
  secrets, and never custody-relevant material. Black-box interface
  observations made with such fixtures can never prove internal physical
  separation, entropy quality, or absence of hidden coupling beyond the
  surveyed interface behavior.
- Card traces can establish only the exercised byte and lifecycle behavior.
  Original-card possession or destruction, absence of another live card,
  Kit-envelope integrity, and coordinator UTXO completeness are external
  facts and cannot be inferred from a successful run.
- Non-exportability probing (planned as QK-TST-BENCH-005, conditional on
  OD-02) is out of scope for these F2 experiments.

## Execution status

Six current-compatible experiments and one superseded v1 experiment remain
historical protocol templates. No v2 run registration exists;
run registration requires a future owner-authorized commit (H3). No specimen
or apparatus is identified.
