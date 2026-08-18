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
| Generate entropy | Ceremony step | Recommended mode: four separately generated per-purpose 256-bit outputs (A, B, C, A2), each using fresh device and card contributions, explicit domain separation, and fail-closed source handling — byte-exact conditioner unresolved under OD-03. Advanced Physical mode: four separate, private, exactly-100-roll d6 transcripts with active-ceremony-only duplicate detection and post-provisioning destruction | qk-core | A, B, C, A2 | none | Four per-purpose outputs accepted; no common master expansion, and no claim that combining sources sums entropy | Fail closed; zeroize; no partial acceptance | QK-REQ-ENT-001/002/003, QK-REQ-HF-001; QK-TST-UNIT-004, QK-TST-PROP-004 |
| Provision cards B and C | Entropy accepted | Exact-card least-authority payload write; C independent of B | qk-core | A, B, C, A2, D | card contents (B: signer B+A2+D; C: signer C+A2+D) | Both cards complete and verified | No half-provisioned card accepted; card state consistent; zeroize | QK-REQ-CARD-001/003/005, QK-REQ-REC-005; QK-TST-PWR-001/002, QK-TST-BENCH-002 |
| Produce A1 | Cards complete | Capsule per fixed A1 profile; fresh nonce; AAD bound; local printing only — network/cloud printing prohibited; print spool/cache disposal required | qk-core (capsule), qk-io (print/capture transport) | Seed A, A2 | printed A1 paper artifact carrying only the cloak body plus ciphertext/footer | The actual printed paper artifact — not an in-memory render or pre-print payload — scanned back on the production terminal (qk-io: capture/OCR/transport only) and cryptographically authenticated and semantically bound to the intended `wallet_id` and D by qk-core; provisioning cannot finish and funding cannot be recommended until this print-back verification passes | Failure, cancel, or power-loss voids acceptance and zeroizes; no half-produced A1 accepted | QK-REQ-A1-001…005, QK-REQ-REC-005; QK-TST-UNIT-001, QK-TST-PWR-001 |
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
| Quantum-threat migration | Owner determines a material change in Bitcoin's quantum threat model has occurred | Versioned, owner-reviewed sweep/migration plan in force (QK-REQ-ASR-010); no post-quantum security claim made | owner + qk-core (sweep executes as ordinary signing/rotation) | per path used | per rotation row | Funds swept per the plan's current version; destination policy is the plan's owner-approved choice, not a proprietary post-quantum script | Fails closed like rotation; plan remains in force; partial sweeps re-attempted per plan | QK-REQ-ASR-010, QK-REQ-ASR-006, QK-REQ-REC-002; QK-TST-REH-005 |
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

## Custody truth table

Non-normative analysis of which object combinations decrypt Seed A, hold independent signers, and can spend **in principle** (before any implementation exists; nothing here is validated). Counting rules: the terminal is never a signer and holds no wallet secret between sessions (QK-REQ-PLT-001). D is watch-only metadata — never a signer. A2 is a decryption key — never a signer. A duplicate of an already-counted factor never adds a signer (QK-REQ-CUS-004). "A decrypts" asks whether Seed A plaintext is obtainable from the held objects alone (A1 needs A2, which lives only on cards in normal custody).

| Held combination | A decrypts? | Independent signers held | Spend possible in principle? | Intended / emergency role | Required response on this exposure | Residual risk |
|---|---|---|---|---|---|---|
| none | No | 0 | No | — | — | — |
| A1 only | No (no A2) | 0 | No | Backup at rest | If theft or capture is known or suspected: rotation and sweep (QK-REQ-REC-002) — any later A2 disclosure converts the capture into signer-A material (QK-THR-021) | Ciphertext existence disclosed; capture is irrevocable if photographed |
| B only | No | 1 (signer B; A2 and D also present on-card) | No | Daily-carry factor | If stolen: rotation and sweep (QK-REQ-REC-002) | A2+D exposed; any A1 copy anywhere becomes decryptable |
| C only | No | 1 (signer C; A2 and D also present on-card) | No | Vault factor | If stolen: rotation and sweep | Same as B only |
| A1+B | Yes (A2 from B) | 2 (A, B) | Yes | Intended daily spend path | If held by an attacker: full compromise — immediate sweep race | None — this is a valid pair |
| A1+C | Yes (A2 from C) | 2 (A, C) | Yes | Emergency spend path (B unavailable); rotation mandated after use | Same as A1+B | None — valid pair |
| B+C | No (A bypassed) | 2 (B, C) | Yes | Emergency path (A1 unavailable); rotation mandated after use | Same as A1+B | None — valid pair |
| A1+B+C | Yes | 3 | Yes | Full collection (ceremonies only; storage separation forbids at rest — QK-REQ-CUS-008/009) | If held by an attacker: full compromise | Co-presence window during ceremonies (QK-THR-005) |

Additional exposures (same counting rules):

| Event | A decrypts? | Signers gained by attacker | Spend possible for attacker? | Required response | Residual risk |
|---|---|---|---|---|---|
| Terminal alone (loss, theft, or compromise, between sessions) | No | 0 | No | Replace terminal (QK-REQ-REC-004); no rotation forced by the object itself | A compromised terminal used in a **later** authorized session can forge that session (QK-REQ-TUI-004) |
| D disclosure (descriptor leaks) | No | 0 | No | Privacy response only; consider rotation for privacy | Full wallet deanonymization; watch-only surveillance (QK-THR-003) |
| D loss (standalone copies) | No | 0 | Owner spend hindered | Restore D from any surviving card (cards carry D) or coordinator backup | Recovery blocked until D restored (QK-THR-020) |
| D loss (every object carrying D lost) | No | 0 | No — descriptor knowledge gone | None available; prevention only | With no card and no D copy surviving, at most one custody object remains — funds unrecoverable regardless (QK-THR-020) |
| A2 disclosure without any card theft | Only combined with any A1 copy | 0 by itself | Only with any A1 copy **plus** one card | Rotation and sweep on suspicion (QK-REQ-REC-007) | Every past/future A1 copy becomes signer-A material; disclosure may never be detected (QK-THR-021) |
| A1 + A2 (attacker holds both) | Yes | 1 (A) | No (needs one more signer) | Rotation and sweep | One card theft away from full compromise |
| Theft of any valid pair | Per pair | 2 | Yes | Immediate sweep race with surviving objects if any | Total loss possible (QK-THR-005 — accepted design boundary) |
| Loss (not theft) of any single object | No | 0 | No | One-time surviving-pair rotation (QK-REQ-REC-002/003) | Recovery path itself unrehearsed until Gate E; second loss before rotation is fatal |
| Theft of any single object | No | 0 or 1 (see rows above) | No | Rotation and sweep | Attacker holds one object while owner races rotation |
| Destruction of any two objects | No | 0 | No — funds unrecoverable (only one object survives) | None available; prevention only (storage separation, geography) | Permanent loss — 2-of-3 requires two objects |

### Card lifecycle states (non-normative note)

Cards move through the abstract states defined by QK-REQ-CARD-008 (uninitialized → provisioning → committed → retired, with a single atomic commit), may sign only in the committed state (QK-REQ-CARD-009), and must land in a consistent state under any interruption (QK-REQ-CARD-010). Mechanisms are OPEN per OD-02.

## Trust boundaries

### qk-core

- **Responsibilities:** sole owner of secret memory, secret arena, card sessions, trusted display/keypad in wallet mode, PSBT reparse/validation, review construction, physical approval, signing, signature verification, zeroization; A1 capsule authentication and decryption and independent semantic validation of parsed input (QK-REQ-PLT-010); card APDU response parsing as documented owner (QK-REQ-PLT-011). Boot/update parsing ownership remains OPEN (QK-REQ-PLT-012, OD-06).
- **Forbidden:** persisting any wallet secret; releasing plaintext before authentication; signing without reparse, review, and physical approval; accepting transport bytes it did not reparse; retaining A2 or root mnemonic material after ceremonies.

### qk-io

- **Responsibilities:** bounded camera/QR and SD transport, and the A1 image-capture/OCR candidate pipeline up to (but excluding) capsule authentication (QK-REQ-PLT-009), within approved QK-LIM budgets; delivering raw hostile bytes and OCR candidates to qk-core.
- **Forbidden:** access to secret memory, cards, APDU response parsing (owned by qk-core per QK-REQ-PLT-011), approval path, or trusted display/keypad; boot/update parsing (ownership OPEN per OD-06, never assignable to qk-io — QK-REQ-PLT-012); capsule authentication or decryption; persistence of payloads; exceeding any approved bound; interpreting external bytes as instructions.

### qk-decoy

- **Responsibilities:** calculator behavior only.
- **Forbidden:** any wallet capability, secret access, card access, or presence after wallet mode takes exclusive control (terminated first).

### Kernel and booted image

- **Intended trust:** trusted computing base in wallet mode (QK-DEC-010); process separation is not claimed to defend against its compromise.
- **Permitted data:** all process memory by definition of a kernel; scheduling and device mediation.
- **Forbidden access/capabilities:** persistence of wallet secrets or metadata beyond the lifecycle model; any network capability (air-gapped device).
- **Compromise consequence:** total — secrets and approvals in that session cannot be protected; no requirement claims otherwise.
- **Evidence needed:** boot/update integrity evidence per OD-06 (OPEN); reproducible-build and supply-chain evidence (QK-REQ-ASR-002/007).

### Physical display/keypad path

- **Intended trust:** trusted in wallet mode as the exclusive review/approval channel of qk-core (QK-REQ-TUI-001).
- **Permitted data:** review content constructed by qk-core; keypad input.
- **Forbidden access/capabilities:** access by qk-io or qk-decoy in wallet mode; retention of displayed secrets (framebuffer remanence — QK-THR-018).
- **Compromise consequence:** review and approval can be forged for that session (within QK-REQ-TUI-004's stated non-claim).
- **Evidence needed:** exclusive-ownership verification (QK-TST-UNIT-007); remanence checks (QK-TST-SAN-001/003).

### Cards B and C

- **Intended trust:** bearer signing elements; trusted to hold the least-authority payload and perform role-fixed signing (QK-REQ-CARD-001/003).
- **Permitted data:** BIP48 account xprv, chain code, origin data, role, A2, D — nothing else.
- **Forbidden access/capabilities:** PIN/pairing/online dependencies (QK-REQ-CARD-002); exporting secrets except via the defined rescue path; any state change that survives interruption inconsistently (QK-REQ-CARD-005).
- **Compromise consequence:** per QK-THR-003/008 — one signer plus A2 and D exposed; threshold only with another factor; rotation and sweep mandatory.
- **Evidence needed:** exact-card feasibility and extraction-resistance evidence (Gate B; OD-02 OPEN); QK-TST-BENCH-002, QK-TST-AUD-003.

### Print computer and printer (A1 production)

- **Intended trust:** untrusted beyond the single A1 production ceremony; sees ciphertext only.
- **Permitted data:** A1 ciphertext, cloak page content, apparent URL text — never plaintext seed material, A2, or D.
- **Forbidden access/capabilities:** receiving any plaintext secret; retaining spooler/cache copies per the ceremony's disposal procedure; network transmission of the capsule.
- **Compromise consequence:** attacker gains authenticated ciphertext only (QK-THR-002); capture of A1 becomes dangerous only combined with A2 (QK-THR-004).
- **Evidence needed:** ceremony procedure audit (QK-TST-AUD-006, QK-TST-HF-001); documented spooler/cache handling before Gate A closes.

### Online coordinator (watch-only)

- **Intended trust:** untrusted; composes PSBTs and broadcasts; holds descriptors (privacy-sensitive) but no spend authority.
- **Permitted data:** descriptor pair D, `wallet_id`, unsigned/signed PSBTs.
- **Forbidden access/capabilities:** any key material, A2, or approval capability; its bytes are always hostile input (QK-DEC-009).
- **Compromise consequence:** privacy loss (deanonymization) and malicious PSBT supply (QK-THR-006/017); funds safe if the trusted core's review holds.
- **Evidence needed:** hostile-input coverage of everything it produces (QK-TST-FUZZ-001/002/003, QK-TST-CORP-001/002/003).

### Commodity-reader rescue environment

- **Intended trust:** untrusted general-purpose computer used only when the terminal is lost (QK-REQ-CARD-006); the user accepts exposure knowingly during rescue.
- **Permitted data:** card contents surfaced by the open rescue tool during a rescue the owner initiated.
- **Forbidden access/capabilities:** no role in normal operation; never a signing environment endorsed as safe; rescue documentation must state the exposure.
- **Compromise consequence:** secrets read during rescue are exposed to that machine; rotation and sweep are mandatory after rescue (QK-REQ-REC-002).
- **Evidence needed:** rescue rehearsal on a clean machine (QK-TST-REH-004); documented post-rescue rotation requirement.

### Replit / build and development environment

- **Intended trust:** outside the production trust boundary entirely. Nothing produced here is trusted for production; it hosts DRAFT documents and, later, source whose production trust derives only from reproducible builds on controlled builders (QK-REQ-ASR-002).
- **Permitted data:** public repository content only — never key material, secrets, or real-fund artifacts.
- **Forbidden access/capabilities:** producing release binaries; holding secrets; closing gates; any claim that CI/verifier passage constitutes security evidence.
- **Compromise consequence:** supply-chain threat (QK-THR-009) — addressed only by the reproducible-build, review, and provenance requirements (QK-REQ-ASR-002/004/007), all unvalidated.
- **Evidence needed:** reproducible-build and provenance evidence at release time (QK-TST-AUD-002).

The kernel, booted image, and physical display/keypad path remain trusted (QK-DEC-010); process separation is not claimed to defend against a compromised kernel, and a malicious terminal within an authorized two-factor session remains inside the authorization trust boundary (QK-DEC-006, QK-REQ-TUI-004).
