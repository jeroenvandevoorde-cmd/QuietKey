# F2 Preparation — Overview

F2 PREPARATION ONLY — TARGET WORK NOT RUN — NO GATE CLOSED

## QK-DEC-121 v2 supersession overlay

This directory preserves the F2.0 preparation record at its historical
revision. QK-DEC-121 now controls every future card run: there is one required
role-B card, an optional byte-equivalent spare may be created only during the
original setup, and no Card-C role or general two-card path exists. References
below to B/C roles or QK-F2E-013 describe superseded v1 preparation and do not
authorize execution. A future v2 registration must bind the current
QK-TST-BENCH-002(g) oracle, including the setup-spare and Kit-Restore
lifecycle boundaries, before that work can run.

The terminal and card can establish byte and protocol facts only. Original
card possession or destruction, absence of another live card, Kit-envelope
integrity, and coordinator UTXO completeness remain external human or
coordinator facts. The C1/C2/C3 names in M20 remain candidate-platform labels;
they never name a Card-C signer role.

## Purpose

This directory contains the F2.0 preparation set for the QuietKey milestone
`F2 — Toolchain plus early exact-target card, QR, SD, and power feasibility`
(`docs/BUILD-ROADMAP.md`). It prepares protocol templates for future
experiments. It authorizes nothing, selects nothing, runs nothing, and
records no measurement.

The approved F2 entry revision (H1) is commit
`d24cf39269eca79f6e471d16eeda2d7736334dd3`; see `docs/f2/ENTRY-REVIEW.md`.

Status of this preparation: F2.0 PREPARATION COMPLETE — EXPERIMENTS NOT AUTHORIZED OR RUN.
Status of the F2 milestone overall: F2 overall INCOMPLETE.

## What exists and what does not

- Ten governance documents in `docs/f2/` and one structural verifier in
  `tools/verify-f2-preparation.sh`. Nothing else was added.
- No experiment has been run under this register. No F2 specimen (board, SoC,
  camera, card, reader, SD interface, power apparatus, OS, kernel, compiler,
  or language) is identified or assigned in this repository. Every specimen
  and apparatus field is `OPEN — SPECIMEN NOT IDENTIFIED`. This states the
  repository's own record only; it makes no claim about what exists outside
  the repository.
- No F2 evidence row or artifact is recorded in this repository.
  `docs/f2/EVIDENCE-REGISTER.md` is schema-only with zero rows.
- At the preserved F2.0 revision, all maturity gates (A through E), owner
  decisions OD-01 through OD-08, 121 `QK-LIM` values, and 66 planned tests
  had the open statuses recorded below. Current statuses and successor rows
  live in the root registers and are not silently back-projected into this
  historical preparation record.

## File map

| File | Role |
|---|---|
| `README.md` | This overview. |
| `ENTRY-REVIEW.md` | Policy-fixed, content-addressed record of the F2 entry revision and entry conditions. |
| `EXPERIMENT-REGISTER.md` | Single canonical source of experiment rows (`QK-F2E-NNN`, append-only). |
| `TARGET-CORE-PROTOCOL.md` | Protocol context for toolchain / ARMv6 experiments (references register IDs only). |
| `CARD-PROTOCOL.md` | Protocol context for exact-card experiments (references register IDs only). |
| `QR-PROTOCOL.md` | Protocol context for camera / BBQr experiments (references register IDs only). |
| `SD-POWER-PROTOCOL.md` | Protocol context for SD electrical and power-interruption experiments (references register IDs only). |
| `EVIDENCE-REGISTER.md` | Evidence schema header only; zero rows. |
| `DECISION-INPUTS.md` | Placeholder mapping from experiments to owner decisions; no recommendations. |
| `EXIT-REVIEW.md` | Template for the future F2 exit review; all fields open. |

## Execution interlock

Experiment execution is a separately authorized future activity:

- Run registration requires a future owner-authorized commit (referred to as
  H3 in the register). No such authorization exists.
- All linked canonical `QK-TST` rows remain `PLANNED — NOT RUN` and belong to
  later milestones; an F2 experiment run may prepare or inform them but never
  executes one and never changes any `QK-TST` status.
- `tools/verify-f2-preparation.sh` is a stage-specific structural aid, never
  authoritative evidence. It structurally rejects, among other things:
  any non-open specimen assignment, any populated evidence row, any run
  timestamp, operator, result, observation, inference, or recommendation,
  any hardware/bench/fixture/probe/applet/firmware/parser source or script,
  any changed OD, gate, test, or limit status, and any
  execution-authorization language inside `docs/f2/`.

## Verifier usage

```
sh tools/verify-f2-preparation.sh --worktree <full-40-hex-H1-hash>
sh tools/verify-f2-preparation.sh --commit <full-40-hex-H1-hash> <full-40-hex-H2-hash>
```

Both modes apply identical content rules. Arguments must be full 40-character
lowercase hexadecimal commit hashes; the verifier never resolves, abbreviates,
or infers a hash. On success it prints exactly one line:
`F2 STRUCTURAL PREPARATION CHECK: PASS`.

## Verifier limitations (stated, not waivable)

- The verifier checks structure only. It cannot prove scientific
  completeness, absence of bias, safety, experimental quality, or the
  semantic correctness of any document.
- The verifier is self-authored in the same revision it checks (H2), so its
  success line is supporting evidence only, never primary evidence.
- The absence of a `SESSION_SECRET` (or any platform secret) is a manually
  observed platform fact; no repository-resident verifier can prove facts
  about the hosting platform.
- Running `tools/verify-foundation.sh` against the expanded tree reports an
  allowlist mismatch. That is the expected stage mismatch between the F0/F1
  foundation allowlist and the F2 preparation additions, not a defect; the
  foundation verifier is only required to succeed at the clean H1 revision,
  where it was confirmed before this preparation began.

## Non-authorization statement

Nothing in this directory changes any gate, owner decision, requirement,
limit, or test status. Measurement authorizes nothing; only explicit owner
decisions recorded in `docs/DECISION-LOG.md` can consume evidence.
