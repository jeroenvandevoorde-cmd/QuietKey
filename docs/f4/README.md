# F4 — Host-Only Interface and State-Machine Scaffold

EXPERIMENTAL — NO REAL FUNDS — NOT A WALLET

STATUS: AUTHORIZED — HOST-ONLY INTERFACE AND STATE-MACHINE SCAFFOLD — INCOMPLETE — NO TARGET CLAIM.

Authorization: QK-AUTH-F3F4-001 (docs/HOST-WORK-AUTHORIZATION.md), 2026-08-18.

## What exists

- `host/qk-host-model`: a HOST policy model only — opaque, payload-free workflow states (including an explicit `Approved` state distinct from pre-confirmation `Working`), deterministic public events, structured transition errors, and a total fail-closed transition function whose outcome type always exposes the security result (`Continue`, `HaltLocked`, or `RejectLocked`). The only continuing transitions are the exact workflow Locked→Ready→Working→Confirming→Approved→Ready; `Sleep` and every interruption (cancellation, timeout, removable-media removal, restart, power loss) halt locked from every state; every other state/event pair rejects locked and never preserves `Working`, `Confirming`, or `Approved`.
- `host/qk-host-sim`: a library-only deterministic scenario runner over the model, with tests. On any halt or rejection the runner sets `Locked` and stops consuming queued events; a later `Wake` is only a new scenario beginning from `Locked`, never a stale suffix of an interrupted scenario.
- `tools/verify-host-boundary.sh`: an additive, offline, verify-only host-boundary check.

## Non-goals and evidence limits

- This is a disposable host scaffold, not `qk-core` production logic and not a wallet simulator.
- `Restart`, `PowerLoss`, and `MediaRemoved` are symbolic HOST policy events only. They provide no evidence about runtime behavior, persistence, boot recovery, removable-media handling, target hardware, or real power loss.
- It contains no secret bytes, wallet data, cryptography, parsing, file/device access, clocks, randomness, logging, network, environment access, threads, processes, FFI, persistence, or hardware code.
- No binary, server, UI, REPL, stdin, service, port, preview, deployment, database, or background process exists.
- Results are HOST evidence only — never TARGET evidence; they establish no production compatibility, memory safety, security, air-gap behavior, target performance, or fitness for funds.
- Functional F4 modules remain contingent on accepted corresponding F3 profiles. Gates A–E remain OPEN; OD-01…08 remain unresolved; F2 remains OVERALL INCOMPLETE; H3-A enrollment remains incomplete; all physical work remains blocked.
