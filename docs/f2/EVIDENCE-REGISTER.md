# F2 Evidence Register

F2 PREPARATION ONLY — TARGET WORK NOT RUN — NO GATE CLOSED

This register holds evidence records produced by future, separately
authorized F2 experiment runs. It currently contains ZERO rows, because no
experiment has been run and no evidence exists.

## Schema

Every future row uses the evidence-record schema defined in
`docs/TEST-ARCHITECTURE.md`, whose completeness requirement is
QK-REQ-ASR-008. The schema fields, reused here without alteration, are:

| Field | Notes for F2 use |
|---|---|
| Evidence ID | `QK-F2V-NNN`, append-only, assigned at recording time. |
| Claim | The single claim the record speaks to; one claim per record. |
| Evidence level | One of the levels enumerated in `docs/TEST-ARCHITECTURE.md`. |
| Source commit | Full hash of the run-registration commit (H3 or later). |
| Specification version | Governance revision the run was registered against. |
| Planned test ID | Related `QK-TST` row if any; otherwise exactly `NONE — F2 FEASIBILITY ONLY`. Experiment identifiers from the F2 experiment register never appear in this field; the record-to-experiment association is carried by the separate companion association table below, outside this schema. |
| Environment | Exact specimen and apparatus identity where applicable. |
| Toolchain/dependency identity | Exact bench-tooling identity used in the run. |
| Procedure | What was done, as registered, including deviations. |
| Raw artifacts | Location plus cryptographic hash of every raw artifact. |
| Result | Recorded verbatim; inconclusive outcomes are recorded as inconclusive. |
| Reviewer | Who reviewed the record. |
| Date | Date of the run. |
| Limitations | What the record cannot show, always populated. |
| Affected gate | Gate context only; a record never changes gate status. |
| Gate-decision reference | Owner decision-log entry that consumed the record, if any. |

## Legend

- A record is an observation container. It closes no gate, resolves no owner
  decision, changes no requirement, limit, or test status, and authorizes
  nothing.
- The Result field carries the raw recorded outcome in the run's own terms.
  This register defines no verdict vocabulary of any kind.
- Records are policy-fixed and content-addressed by the commit that carries
  them. A superseded record is marked superseded by a later record; any
  correction is a new record or revision, never a silent edit.

## Experiment association (companion table)

The canonical evidence-row schema from `docs/TEST-ARCHITECTURE.md` is used
unaltered above and is not redefined here. The association between a future
evidence record and the F2 experiment it was produced under is carried by
this separate companion table — a mapping from Evidence ID to Experiment
ID — which sits outside the canonical schema and adds no field to it. This
definition is structure only; an empty association table is not evidence
and asserts nothing.

| Evidence ID | Experiment ID |
|---|---|

NONE — no evidence exists; this association table is intentionally empty.

## Rows

NONE — no experiment has been run; this register is intentionally empty.
