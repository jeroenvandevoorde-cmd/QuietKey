# F2 Entry Review

F2 PREPARATION ONLY — TARGET WORK NOT RUN — NO GATE CLOSED

## Entry revision (policy-fixed record)

- F2 entry revision (H1): `d24cf39269eca79f6e471d16eeda2d7736334dd3`
- H1 is the owner-approval commit that recorded owner approval
  `QK-APR-2026-08-18-001` over the audited baseline
  `c618407a3900657d8ce4c479c4056f859f86bec6` (H0).
- This entry review records H1 as the fixed F2 entry revision. The record is
  policy-fixed and content-addressed by the commit that carries it; any later
  correction is a new record or revision, never a silent edit.

## Entry conditions observed at H1

The following conditions were observed at the clean H1 revision, before any
F2 preparation file existed:

- Worktree clean; `HEAD`, local `main`, and `origin/main` all at H1.
- `tools/verify-foundation.sh` succeeded at H1 (its success at H1 is the only
  stage at which it is required to succeed; see the stage-mismatch note in
  `docs/f2/README.md`).
- Maturity gates A, B, C, D, and E: all OPEN (`docs/MATURITY-GATES.md`).
- Owner decisions OD-01 through OD-08: all unresolved (`docs/OPEN-DECISIONS.md`).
- All 121 `QK-LIM` rows carry Value exactly
  `OPEN — VALUE NOT AUTHORIZED IN F1` and Status exactly `OPEN`
  (`docs/RESOURCE-BUDGETS.md`).
- All 66 `QK-TST` rows carry Status exactly `PLANNED — NOT RUN`
  (`docs/TEST-ARCHITECTURE.md`).
- No product code and no F2 evidence are recorded in this repository, and
  no F2 specimen or hardware is identified or assigned in this repository.
  This entry makes no claim about the world outside this repository.

## Scope of F2.0 (this preparation step)

F2.0 prepares protocol templates and a structural verifier only. It is the
first sub-step of the F2 milestone. F2 as a whole remains INCOMPLETE until
its roadmap deliverables exist and the owner has logged the corresponding
decisions; none of that occurs in F2.0.

Explicitly out of scope for F2.0:

- Running, scheduling, or authorizing any experiment.
- Identifying, acquiring, or naming any specimen or apparatus.
- Producing, recording, or referencing any measurement or evidence.
- Changing any gate, owner decision, requirement, limit, or test status.
- Writing any product, bench, fixture, probe, applet, firmware, or parser
  code.

## Exit from F2.0

F2.0 ends with the preparation commit (H2, sole parent H1) containing exactly
the eleven allowlisted files and a structural verifier success in both
verifier modes. The end state is:

- F2.0 PREPARATION COMPLETE — EXPERIMENTS NOT AUTHORIZED OR RUN
- F2 overall INCOMPLETE
