# F4 — Host-Only Transaction Authority Policy Model

EXPERIMENTAL — NO REAL FUNDS — NOT A WALLET

HOST-ONLY — PAYLOAD-FREE — NOT PRODUCT CODE — NOT TARGET EVIDENCE — INCOMPLETE

STATUS: HOST-ONLY POLICY-ORDER SCAFFOLD — SYMBOLIC ASSERTIONS ONLY — NO
VALIDATION, REVIEW, APPROVAL, REVALIDATION, SIGNING, SIGNATURE
VERIFICATION, OR OUTPUT PARSING IS PERFORMED OR PROVEN.

## What this is

`host/qk-host-model/src/transaction_policy.rs` (exercised by
`host/qk-host-sim` and its tests) is a dependency-free, library-only,
payload-free Rust policy model of the mandatory transaction
authorization ORDER established by QK-DEC-009 and QK-DEC-010:

validate -> construct review -> physical approval -> revalidate ->
permit signature -> verify signature -> reparse output

It models ONLY the ordering policy. It does NOT implement QK-DEC-009 or
QK-DEC-010 and makes no claim that either decision is implemented,
partially implemented, or implementable; the mapping below is a
correspondence of ordering steps to decision language only.

## Symbolic assertion limitations

Every input event is an UNAUTHENTICATED symbolic assertion from a
hypothetical future component. `ValidationPassed`, `ReviewConstructed`,
`Approve`, `RevalidationPassed`, `SignatureProduced`,
`SignatureVerified`, and `OutputReparsed` are assertions the policy
model consumes without verifying. The model does not claim that
validation, review correctness, physical approval, revalidation,
signature production or verification, or output parsing actually
occurred, and it cannot detect a false assertion. `Restart`,
`PowerLoss`, and `MediaRemoved` remain symbolic HOST policy events, as
below.

Transaction/intent binding is MANDATORY. In this model it is
REPRESENTED by `RevalidationPassed` as an UNAUTHENTICATED symbolic
assertion — the binding is not carried by, and is not proven by, the
payload-free event itself. The represented assertion is precisely
that the future trusted component reparsed and revalidated
the candidate transaction and proved byte-exact/canonical commitment
equality to the exact review object and policy context that were
physically approved in that same workflow. This payload-free model
cannot perform or prove that binding; a future implementation MUST
enforce it before emitting `RevalidationPassed`. It is forbidden to
treat a review/approval of candidate T1 followed by revalidation or
signing of a different candidate T2 as valid. The model proves only
the ordering (no path to `SignPermitted` skips the
binding-representing `RevalidationPassed`); payload equality is never
tested here, because the payload-free model cannot check equality.

The only TRANSACTION workflow runner exported by the normal library is
`run_transaction_workflow(events)`: it accepts events only and always
begins at `Locked` — no public arbitrary-start TRANSACTION
workflow/scenario API exists in a non-test build. (The older generic
5-state runner `run_scenario(start, events)` remains public and
unchanged; no claim is made about it here.) The public pure transition
function
`transaction_transition(state, event)` does accept caller-supplied
states, strictly for model/table use; consequently no cross-call
replay or path-provenance guarantee exists anywhere. Neither function
is an authorization boundary. The exact approval claim — single-use
per authorization cycle, not per function invocation — is: within one
correctly outcome-threaded invocation of `run_transaction_workflow`
that begins `Locked`, `Approve` continues only from `Confirming`; an
immediate duplicate `Approve`, or any stale `Approve` before a fresh
symbolic `BeginValidation` → `ValidationPassed` → `ReviewConstructed`
→ `RequestApproval` sequence reaches `Confirming`, rejects locked and
stops the remaining suffix; after a completed cycle returns to `Ready`
through the signed completion path, an `Approve` following a new full
validation/review/request sequence begins a NEW authorization cycle in
the same invocation and is not replay. This is symbolic order only; no
payload, freshness, or identity fact is proven by the model.
Interruption naming: `Restart`,
`PowerLoss`, and `MediaRemoved` are symbolic HOST policy events only:
no target runtime, persistence, boot-recovery, removable-media,
signing, parser, physical-button, or power-loss evidence is claimed.

## Transition table

States (11): `Locked`, `Ready`, `Validating`, `ConstructingReview`,
`ReviewReady`, `Confirming`, `Approved`, `Revalidating`,
`SignPermitted`, `VerifyingSignature`, `ReparsingOutput`.

Events (23): 11 continuing-order events, `Sleep`, 5 interruptions
(`Cancel`, `Timeout`, `MediaRemoved`, `Restart`, `PowerLoss`), and 6
explicit failures (`ValidationFailed`, `ReviewConstructionFailed`,
`ApprovalRejected`, `RevalidationFailed`, `SignatureInvalid`,
`OutputInvalid`).

The ONLY continuing transitions (11 cells):

| State | Event | Next state |
|---|---|---|
| Locked | Wake | Ready |
| Ready | BeginValidation | Validating |
| Validating | ValidationPassed | ConstructingReview |
| ConstructingReview | ReviewConstructed | ReviewReady |
| ReviewReady | RequestApproval | Confirming |
| Confirming | Approve | Approved |
| Approved | BeginRevalidation | Revalidating |
| Revalidating | RevalidationPassed | SignPermitted |
| SignPermitted | SignatureProduced | VerifyingSignature |
| VerifyingSignature | SignatureVerified | ReparsingOutput |
| ReparsingOutput | OutputReparsed | Ready |

`Sleep`, every interruption, and every explicit failure return
`HaltLocked` from EVERY state (11 x 12 = 132 cells). Every other
state/event pair returns `RejectLocked` with a structured error naming
the pair (110 cells) and never preserves `Ready`, `Validating`,
`ReviewReady`, `Confirming`, `Approved`, `Revalidating`,
`SignPermitted`, `VerifyingSignature`, or `ReparsingOutput`. Total:
11 x 23 = 253 cells = 11 Continue + 132 HaltLocked + 110 RejectLocked.
Both terminal outcomes always resolve to `Locked`.

"Exhaustive" here means exhaustive over the current explicitly
enumerated 11-state and 23-event constants only. ONE Rust test
iterates all 253 declared pairs (they are not 253 tests). These tests
prove table consistency and the declared ordering, not independent
protocol correctness or future enum completeness. All fail-closed
claims are fail-closed over the declared state/event semantics,
assuming successful host execution: allocation exhaustion, panic or
abort, process termination, persistence, boot recovery, and target
behavior are outside this model, and the runner's step vector is
host-test plumbing, not a bounded production mechanism.

Modeled security-order properties (of the symbolic model only, and
ALL scoped to a single correctly outcome-threaded invocation of
`run_transaction_workflow` beginning at `Locked` — no cross-call
guarantee exists, and the public pure transition function accepts
caller-supplied states for model/table use): within one such
invocation, `SignatureProduced` continues only from `SignPermitted`;
`SignPermitted` is entered only after `Approve` followed by the
binding-representing `RevalidationPassed` in that same uninterrupted
invocation; `Approve` continues only from `Confirming` — approval is single-use
per authorization cycle, not per function invocation: an immediate
duplicate `Approve`, or a stale `Approve` before a fresh
validation/review/request sequence reaches `Confirming`, rejects
locked and stops the suffix, while an `Approve` after a completed
cycle and a new full sequence begins a new authorization cycle; after
`SignatureVerified`, the signed-completion path can return to `Ready`
only through `ReparsingOutput` + `OutputReparsed` (the `Locked` +
`Wake` entry into `Ready` is a separate path); any failure or
interruption ends the invocation locked, and a later `Wake` can only
begin a completely new invocation starting from `Locked`.

## Excluded capabilities and data

No transaction bytes, PSBT, amounts, fees, addresses, scripts,
descriptors, networks, change labels, seeds, entropy, words, dice
transcripts, keys, A1/A2/B/C payloads, hashes, signatures, QR, SD,
APDU, card data, files, paths, or fixtures. No text or byte payload
fields of any kind, no byte buffers or wallet-byte arrays, no
serialization, parsing, cryptography, randomness, clocks, threads,
processes, environment access, filesystem, standard input/output,
network, FFI, persistence, target runtime or target-runtime
integration, binary, server, or UI. No external
code or dependencies were added or copied.

## Status preservation

No canonical test status, gate, open decision, limit, or evidence
status changes. Canonical QK-TST rows are unchanged and remain PLANNED
— NOT RUN; no QK-TST row was executed and nothing here is Gate C
evidence. Gates A–E remain OPEN; OD-01…OD-08 remain unresolved; all
QK-LIM values remain open; F2 remains OVERALL INCOMPLETE / physically
blocked; F3/F4 host work remains AUTHORIZED — INCOMPLETE; F5–F12 remain
NOT AUTHORIZED; there is no target evidence and no selected project
license.

## Normative status

This policy model is a NON-NORMATIVE scaffold until the corresponding
F3 interface and workflow profiles are separately accepted. Acceptance
of those profiles is a distinct future decision; nothing in this
document or model pre-commits it.
