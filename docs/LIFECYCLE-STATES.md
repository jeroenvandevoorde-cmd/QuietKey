# QuietKey Lifecycle and Trust-Boundary Model

**DRAFT — PENDING PROJECT-OWNER APPROVAL — NON-AUTHORITATIVE UNTIL CORRECTED F0 ARCHITECTURE IS APPROVED**

EXPERIMENTAL — NO REAL FUNDS — NOT A WALLET

This document specifies security properties of lifecycle states and transitions — never implementation mechanisms or wire formats. All content is DRAFT and unimplemented. Column meanings:

- **Trigger** — event starting the transition. **Guard** — prerequisites that must hold. **Owner** — trusted component owning the transition. **Secrets present** — wallet secrets that may exist in memory during the transition. **Persist** — persistent state permitted to result. **Success** — postcondition on success. **Failure/Cancel/Power-loss** — postcondition on any failure, cancellation, or power interruption. **Links** — QK-REQ / QK-TST IDs.

Global rules: every failure, cancellation, timeout, or power-loss postcondition ends with secret zeroization (QK-REQ-PLT-004) and no half-provisioned artifact accepted (QK-REQ-REC-005). No transition may persist secret material or unpermitted metadata (QK-REQ-PLT-005). The terminal retains no wallet secret between sessions (QK-REQ-PLT-001).

## Provisioning

| Transition | Trigger | Guard | Owner | Secrets present | Persist | Success | Failure/Cancel/Power-loss | Links |
|---|---|---|---|---|---|---|---|---|
| Enter provisioning | Owner starts ceremony | Wallet mode active; qk-decoy terminated; no prior session residue | qk-core | none yet | none | Ceremony context ready | Return to idle; nothing persisted | QK-REQ-PLT-002; QK-TST-UNIT-007 |
| Generate entropy | Ceremony step | Four independent 256-bit values (device mode) or four valid 100-roll d6 transcripts | qk-core | A, B, C, A2 | none | Entropy accepted | Fail closed; zeroize; no partial acceptance | QK-REQ-ENT-001/002/003, QK-REQ-HF-001; QK-TST-UNIT-004, QK-TST-PROP-004 |
| Provision cards B and C | Entropy accepted | Exact-card least-authority payload write; C independent of B | qk-core | A, B, C, A2, D | card contents (B: signer B+A2+D; C: signer C+A2+D) | Both cards complete and verified | No half-provisioned card accepted; card state consistent; zeroize | QK-REQ-CARD-001/003/005, QK-REQ-REC-005; QK-TST-PWR-001/002, QK-TST-BENCH-002 |
| Produce A1 | Cards complete | Capsule per fixed A1 profile; fresh nonce; AAD bound | qk-core | Seed A, A2 | printed A1 (ciphertext only) | A1 produced and verified by re-decode | No half-produced A1 accepted; zeroize | QK-REQ-A1-001…005, QK-REQ-REC-005; QK-TST-UNIT-001, QK-TST-PWR-001 |
| Finish provisioning | All artifacts verified | A2 not retained on terminal; root mnemonics not retained | qk-core | none after cleanup | none on terminal | Wallet usable; terminal clean | Zeroize; ceremony void; no artifact accepted | QK-REQ-PLT-001/004; QK-TST-UNIT-010, QK-TST-PROP-005 |

## Signing — normal path A1+B

| Transition | Trigger | Guard | Owner | Secrets present | Persist | Success | Failure/Cancel/Power-loss | Links |
|---|---|---|---|---|---|---|---|---|
| Start session | Owner enters wallet mode | qk-decoy terminated; exclusive display/keypad | qk-core | none | none | Session open | Return to idle; zeroize | QK-REQ-TUI-001, QK-REQ-PLT-002; QK-TST-UNIT-007 |
| Intake PSBT (QR/SD) | Transport input | Bounds per QK-LIM rows; unprivileged parse in qk-io | qk-io (parse) → qk-core (reparse) | none in qk-io | none; no input overwrite | Trusted-core reparse complete | Reject fail-closed; no partial state | QK-REQ-TRN-001/003/004/005/006, QK-REQ-PSBT-002; QK-TST-FUZZ-001/002/003, QK-TST-CORP-001/002/003 |
| Decrypt Seed A | A1 presented, B present | A2 read from B; capsule authenticates for this `wallet_id` | qk-core | A2, Seed A | none | Seed A available in secret arena | Fail closed on auth failure; zeroize | QK-REQ-A1-003/004; QK-TST-PROP-001, QK-TST-CORP-004 |
| Review and approve | Reparse complete | Review built solely from trusted-core parse; policy/prevout/derivation/change/sighash/fee checks pass | qk-core | Seed A; card session B | none | Physical approval recorded for exactly the reviewed transaction | Cancel/timeout: discard, zeroize, no signature exists | QK-REQ-PSBT-003/006, QK-REQ-TUI-002/003; QK-TST-PROP-002, QK-TST-HF-002 |
| Sign and output | Approval | Revalidation immediately before signing; signatures verified | qk-core | Seed A; card session B | signed output only | Independently parseable signed result | Power-loss: no partial signature released; zeroize | QK-REQ-PSBT-003/004; QK-TST-DIFF-002, QK-TST-PWR-004 |
| End session | Output delivered or aborted | — | qk-core | none after cleanup | none | Terminal clean | Same as success (cleanup is unconditional) | QK-REQ-PLT-001/004; QK-TST-UNIT-010 |

## Recovery paths

| Transition | Trigger | Guard | Owner | Secrets present | Persist | Success | Failure/Cancel/Power-loss | Links |
|---|---|---|---|---|---|---|---|---|
| A1+C recovery | B unavailable | Same guards as A1+B with card C; role checked (C is not B) | qk-core | A2, Seed A; card session C | signed output only | Spend/recovery completed; rotation mandated | Fail closed; zeroize | QK-REQ-REC-001/002, QK-REQ-CARD-003; QK-TST-REH-001, QK-TST-UNIT-008 |
| B+C recovery | A1 unavailable | Both cards present; A bypassed entirely | qk-core | card sessions B and C | signed output only | Spend/recovery completed; rotation mandated | Fail closed; zeroize | QK-REQ-REC-001/002; QK-TST-REH-001 |
| Lost-factor rotation | Any loss or suspected compromise | One-time use of a surviving pair only | qk-core | per path used | fresh A1′ + cards B′/C′ | Completely fresh A′/B′/C′/A2′/D′ wallet provisioned; all funds swept; old wallet abandoned | Rotation ceremony fails closed like provisioning; no reissue into old descriptor | QK-REQ-REC-002/003; QK-TST-REH-003 |
| Terminal replacement | Terminal lost/failed | Replacement terminal has no prior wallet state; any valid pair | qk-core (new terminal) | per path used | none beyond signed output | Recovery completes on replacement terminal | Fail closed; zeroize | QK-REQ-REC-004, QK-REQ-PLT-001; QK-TST-REH-002 |

## Exceptional transitions

| Transition | Trigger | Guard | Owner | Secrets present | Persist | Success | Failure/Cancel/Power-loss | Links |
|---|---|---|---|---|---|---|---|---|
| Cancellation | Owner cancels | Any state | qk-core | whatever the state held | none | State discarded; zeroized; session ends or returns to safe idle | Identical (cancellation is the failure path) | QK-REQ-PLT-004; QK-TST-UNIT-010, QK-TST-PWR-004 |
| Timeout | Review/confirmation timer expires (limit OPEN, QK-LIM-TUI-003) | Any interactive state | qk-core | as held | none | Same as cancellation | Identical | QK-REQ-TUI-003; QK-TST-CORP-006 |
| Wrong card / document / wallet | Factor fails role, AAD, or `wallet_id` check | Guards reject before any secret use | qk-core | none released | none | Rejection with fail-closed message | Identical | QK-REQ-A1-004, QK-REQ-CARD-003, QK-REQ-HF-003; QK-TST-UNIT-008, QK-TST-CORP-006 |
| Card/media removal | Card or SD removed mid-operation | Any state | qk-core | as held | none; no input overwrite | Operation aborted; consistent card/media state | Identical | QK-REQ-CARD-005, QK-REQ-TRN-002; QK-TST-PWR-002/003 |
| Power loss | Power interruption | Any state | qk-core (on restart) | none after restart | none beyond already-committed consistent artifacts | Restart into clean idle; no secret residue; no resumed approval | Identical by definition | QK-REQ-PLT-001, QK-REQ-REC-005; QK-TST-PWR-001…004, QK-TST-PROP-005 |
| Failure (any internal error) | Error detected | Any state | owning component | as held | none | Fail closed; zeroize; user-visible outcome | Identical | QK-REQ-HF-003, QK-REQ-PLT-004; QK-TST-UNIT-010 |
| Shutdown and secret cleanup | Session end or power-off request | — | qk-core | none after cleanup | none | All secret memory zeroized within the approved cleanup budget (QK-LIM-EXE-002) | Power-loss during shutdown: covered by power-loss row | QK-REQ-PLT-001/004; QK-TST-UNIT-010, QK-TST-SAN-003 |

## Trust boundaries

### qk-core

- **Responsibilities:** sole owner of secret memory, secret arena, card sessions, trusted display/keypad in wallet mode, PSBT reparse/validation, review construction, physical approval, signing, signature verification, zeroization.
- **Forbidden:** persisting any wallet secret; releasing plaintext before authentication; signing without reparse, review, and physical approval; accepting transport bytes it did not reparse; retaining A2 or root mnemonic material after ceremonies.

### qk-io

- **Responsibilities:** bounded camera/QR and SD transport only, within approved QK-LIM budgets; delivering raw hostile bytes to qk-core.
- **Forbidden:** access to secret memory, cards, approval path, or trusted display/keypad; persistence of payloads; exceeding any approved bound; interpreting external bytes as instructions.

### qk-decoy

- **Responsibilities:** calculator behavior only.
- **Forbidden:** any wallet capability, secret access, card access, or presence after wallet mode takes exclusive control (terminated first).

The kernel, booted image, and physical display/keypad path remain trusted (QK-DEC-010); process separation is not claimed to defend against a compromised kernel, and a malicious terminal within an authorized two-factor session remains inside the authorization trust boundary (QK-DEC-006, QK-REQ-TUI-004).
