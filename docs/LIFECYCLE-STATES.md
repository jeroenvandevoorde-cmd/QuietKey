# QuietKey v2 Lifecycle and Trust-Boundary Model

**OWNER-APPROVED V2 BASELINE — PRODUCTION EVIDENCE INCOMPLETE — ALL GATES OPEN**

EXPERIMENTAL — NO REAL FUNDS — NOT A WALLET

This document specifies security properties of lifecycle states and transitions, never implementation mechanisms beyond the Owner-fixed profiles. **Trigger** starts a transition; **Guard** is its prerequisite; **Owner** is the trusted component; **Secrets present** lists transient secret state; **Persist** lists permitted durable artifacts; **Success** and **Failure/Cancel/Power-loss** are postconditions; **Links** name requirements and planned tests.

Global rules: every failure, cancellation, timeout, card/media removal, restart, or power loss ends with secret zeroization and no half-provisioned artifact accepted. The terminal retains no wallet secret between sessions. The two-envelope Kit is deliberately a complete spare wallet; its secrecy while split is computational and capped by the Kit-R transcript. Its non-regeneration property is a terminal lifecycle rule after setup, not a physical non-copyability claim. UTXO completeness, possession of destroyed-card remains, envelope integrity, artifact destruction, and custody separation are external human or coordinator facts.

## Provisioning

| Transition | Trigger | Guard | Owner | Secrets present | Persist | Success | Failure/Cancel/Power-loss | Links |
|---|---|---|---|---|---|---|---|---|
| Enter provisioning | Owner starts ceremony | Wallet mode exclusive; no prior residue | qk-core | none | none | Four-purpose context ready | Return to clean idle | QK-REQ-PLT-001/002/004; QK-TST-UNIT-013 |
| Acquire dice transcripts | Ceremony step | Fixed purpose order Seed-A, Signer-B, Kit-R, A2; ManualKeypad exactly 100 or gated DiceGrid exactly 125 face values per purpose; echo, confirm, commit; pairwise reuse rejection | qk-core | four fixed transcript buffers | none | Four accepted transcripts retained together | Wipe all four; accept nothing | QK-REQ-ENT-001/003/006/007/009/010/012; QK-TST-UNIT-004, QK-TST-HF-003 |
| Derive wallet facts | Four transcripts accepted | Literal SHA-256; fixed BIP39/BIP32 and descriptor profiles; 2-of-2 A/B only | qk-core | Seed-A entropy, Seed-B entropy, A2, Kit-R transcript, transient mnemonic/derivation state | none | D, `wallet_id`, first addresses, and B payload agree | Wipe; no partial facts accepted | QK-REQ-CUS-001/002/005/006; QK-TST-DIFF-003, QK-TST-UNIT-002/003 |
| Provision B | Wallet facts ready | Exact-card atomic write of signer B, A2 and D | qk-core | B account secret, A2, D | one committed B card | Card payload and public facts verified | No ambiguous or partially committed card; wipe | QK-REQ-CARD-001/003/005/008/009/010; QK-TST-BENCH-002, QK-TST-PWR-002 |
| Provision optional spare | Owner elects spare during original setup | Same signer-B/A2/D payload; no post-setup path | qk-core | B account secret, A2, D | at most one setup-time spare B | Spare matches D and is committed | No spare accepted; primary B remains consistent | QK-REQ-KIT-013, QK-REQ-CARD-003/005; QK-TST-BENCH-002, QK-TST-REH-007 |
| Produce A1 | B committed | Frozen A1 capsule; caller-supplied fresh nonce; local print; actual page scans back and authenticates against `wallet_id` and D | qk-core, qk-io transport | Seed-A entropy, A2 | verified printed A1 | Printed artifact accepted | Void page; wipe; provisioning incomplete | QK-REQ-A1-001…011, QK-REQ-REC-005; QK-TST-REH-006, QK-TST-PWR-001 |
| Construct Kit shares | A1 and wallet facts ready | QK-REQ-KIT-003 KDF; one pad for every setup copy; exact payload order Seed-A, Seed-B, A2 | qk-core | both seeds, A2, Kit-R transcript, T, salt, PRK, R, shares | none yet | Opposite-index frames bind full `wallet_id`; equal indices cannot combine | Wipe all Kit-R intermediates and shares; no output accepted | QK-REQ-KIT-001…005; QK-TST-UNIT-014, QK-TST-PROP-008, QK-TST-DIFF-005 |
| Print two complete Kits | Frames constructed | Default count two; each share page has exact QR and fallback; labels/instructions state complete-wallet, separation/co-storage posture, restore rules, and seal response | qk-core, qk-io transport | transient frames and payload during verification | four sealed share envelopes forming two cross-compatible complete Kits | Every page/frame/checksum/index/wallet binding and envelope assignment verified | Tombstone defective output; wipe; provisioning incomplete | QK-REQ-KIT-006/014/015/016, QK-REQ-REC-005; QK-TST-DIFF-005, QK-TST-BENCH-006, QK-TST-REH-007 |
| Finish provisioning | B, A1, two complete Kits, and any optional spare verified | No terminal secret persistence; Kit-R regeneration path closes permanently | qk-core | none after cleanup | only authorized physical/coordinator artifacts | Wallet usable; terminal clean | Wipe; ceremony void; no half-wallet accepted | QK-REQ-KIT-005/006/013, QK-REQ-PLT-001/004/005; QK-TST-PROP-005/008, QK-TST-UNIT-010 |

## Normal signing — A1+B

| Transition | Trigger | Guard | Owner | Secrets present | Persist | Success | Failure/Cancel/Power-loss | Links |
|---|---|---|---|---|---|---|---|---|
| Start session | Owner enters wallet mode | qk-decoy terminated; display/keypad exclusive | qk-core | none | none | Session open | Clean idle | QK-REQ-TUI-001, QK-REQ-PLT-002; QK-TST-UNIT-013 |
| Intake transaction | QR/SD supplied | Bounded qk-io parse, immutable copy, trusted-core reparse | qk-io then qk-core | none in qk-io | no input overwrite | Schema-v3 review facts ready | Named rejection; no partial state | QK-REQ-TRN-001/003/004/005/006, QK-REQ-PSBT-001/002/005; QK-TST-FUZZ-001/002/003 |
| Decrypt Seed A | A1 and B presented | A2 from B; A1 authenticates to this `wallet_id` | qk-core | A2, Seed-A entropy | none | Signer A available transiently | Named rejection; wipe | QK-REQ-A1-003/004, QK-REQ-BND-001; QK-TST-PROP-001, QK-TST-CORP-004 |
| Review and approve | Schema-v3 review ready | QK-FEE-POLICY-V2, ownership/change/prevout/sighash checks, complete fixed-order review | qk-core | signer A; B session | none | Hold bound to exact review identity | Wipe; no signature exists | QK-REQ-PSBT-003/006, QK-REQ-BND-002/003, QK-REQ-TUI-002/003; QK-TST-PROP-002/006 |
| Sign, finalize, export | Bound approval | Reparse and revalidation; A and B signatures verified; canonical 2-of-2 witness | qk-core | signer A; B session | verified signed artifacts only | Freshly parsed finalized transaction exported | No partial valid output; wipe | QK-REQ-PSBT-003/004, QK-REQ-TRN-007/008; QK-TST-DIFF-002/004, QK-TST-PWR-004/005 |
| End session | Output delivered or aborted | unconditional cleanup | qk-core | none after cleanup | none on terminal | Terminal clean | Same cleanup | QK-REQ-PLT-001/004; QK-TST-UNIT-010 |

## Kit session common prefix

| Transition | Trigger | Guard | Owner | Secrets present | Persist | Success | Failure/Cancel/Power-loss | Links |
|---|---|---|---|---|---|---|---|---|
| Select Kit door | Owner starts Kit session | Choose exactly one of Kit-Spend or Kit-Restore before scanning | qk-core | none | none | Door fixed for session | Wipe and terminate | QK-REQ-KIT-007; QK-TST-PROP-008, QK-TST-REH-007 |
| Scan share 1 | Door fixed | Scanner accepts Kit-share QR only; fallback input unavailable pending its own decision | qk-io then qk-core | first share after core acceptance | none | Canonical frame retained | Named rejection; wipe and terminate | QK-REQ-PLT-009/010, QK-REQ-KIT-001/007/015/016; QK-TST-BENCH-006, QK-TST-CORP-002 |
| Scan share 2 and combine | First share accepted | Opposite index, same version and full `wallet_id`, valid checksums; frames canonical | qk-core | both shares, recovered Seed-A entropy, Seed-B entropy, A2 | none | Recovered public facts reproduce D and `wallet_id` | Same-index, mismatch, corruption, or derivation failure wipes and terminates | QK-REQ-BND-001, QK-REQ-KIT-001/002/007; QK-TST-UNIT-014, QK-TST-PROP-008 |

## Kit-Spend — sweep only

| Transition | Trigger | Guard | Owner | Secrets present | Persist | Success | Failure/Cancel/Power-loss | Links |
|---|---|---|---|---|---|---|---|---|
| Intake sweep transaction | Shares combined under Kit-Spend | Every presented input proves owned; exactly one output; output is a new address of a newly supplied replacement descriptor; no change | qk-core | recovered A/B/A2 | none | Sweep review object ready | Reject; wipe; no signing | QK-REQ-KIT-008, QK-REQ-PSBT-002/006; QK-TST-PROP-002, QK-TST-REH-007 |
| Confirm external completeness | Sweep review ready | Product states coordinator supplied UTXO set is external and not terminal-proven | user/coordinator fact consumed by qk-core UI | recovered A/B/A2 | none | User proceeds with bounded factual warning | Cancel wipes and ends | QK-REQ-KIT-009, QK-REQ-TUI-002; QK-TST-REH-007 |
| Review, sign, export | Sweep constraints hold | Complete review; approval/revalidation; exact A/B signatures; one new-wallet output | qk-core | recovered A/B/A2 | signed sweep artifact only | Sweep result released; old wallet marked for abandonment by procedure | No partial output; wipe | QK-REQ-KIT-008, QK-REQ-PSBT-003/004, QK-REQ-BND-002/003; QK-TST-DIFF-002, QK-TST-REH-007 |

## Kit-Restore — no signing

| Transition | Trigger | Guard | Owner | Secrets present | Persist | Success | Failure/Cancel/Power-loss | Links |
|---|---|---|---|---|---|---|---|---|
| Choose restore artifact | Shares combined under Kit-Restore | Exactly replacement B or A1 reprint; no signing or transaction intake state exists | qk-core | recovered Seed-A entropy, Seed-B entropy, A2 | none | One restore branch fixed | Wipe and terminate | QK-REQ-REC-001, QK-REQ-KIT-007/010/011; QK-TST-PROP-008, QK-TST-REH-007 |
| Replace destroyed B | Owner selects card | User confirms physical remains are in hand; new card matches B in D; atomic write | qk-core | Seed-B entropy/account secret, A2, D | one replacement B | Replacement verified; remains disposition is external | Missing-card answer routes to sweep; interruption leaves no ambiguous card | QK-REQ-REC-003, QK-REQ-KIT-010/012; QK-TST-BENCH-002, QK-TST-PWR-002, QK-TST-REH-007 |
| Reprint A1 | Owner selects A1 | Frozen capsule with fresh caller-provided nonce; actual print scans back and authenticates | qk-core, qk-io transport | Seed-A entropy, A2 | replacement A1 | New A1 verified; no signature exists | Void print; wipe; no output accepted | QK-REQ-A1-002/009, QK-REQ-KIT-011; QK-TST-UNIT-001, QK-TST-REH-006/007 |
| Finish restoration | Replacement verified | No second live B created; no Kit regeneration; no signing artifact | qk-core | none after cleanup | restored artifact only | Terminal clean; restored A1+B exists only to complete the mandatory fresh-wallet sweep after Kit opening | Same cleanup | QK-REQ-REC-002, QK-REQ-KIT-005/010/011/013, QK-REQ-PLT-001/004; QK-TST-PROP-008, QK-TST-REH-007 |

## Mandatory sweep triggers

| Trigger | Required route | Why terminal cannot prove the fact | Links |
|---|---|---|---|
| B cannot be found | Kit-Spend to fresh wallet | Absence does not prove destruction; restoring could create two live B cards | QK-REQ-REC-003, QK-REQ-KIT-012/013; QK-TST-REH-007 |
| Kit envelope intentionally opened, seal found broken, or any doubt of opening/photography | Kit-Spend directly, or Kit-Restore followed by an A1+B sweep, to a fresh wallet | Seal state and custody history are human observations | QK-REQ-REC-002, QK-REQ-KIT-014; QK-TST-HF-003, QK-TST-REH-007 |
| A2, A1+B, or complete Kit suspected exposed | Any still-controlled authorized sweep path | Exposure and copy destruction are external facts | QK-REQ-REC-002/007, QK-REQ-KIT-014; QK-TST-REH-003/007 |
| Material quantum-threat change | Versioned Owner-reviewed sweep plan | Threat determination is external policy input | QK-REQ-ASR-006/010; QK-TST-REH-005 |

Periodic rehearsal includes an envelope-seal check. A damaged share with intact trusted custody is an availability event; any doubt that it was viewed or copied is a compromise event and uses the sweep row.

## Exceptional transitions

| Transition | Trigger | Postcondition | Links |
|---|---|---|---|
| Cancellation or timeout | Owner cancel or timer expiry | Wipe every transient secret, approval, share, door and parsed fact; terminate | QK-REQ-PLT-004, QK-REQ-TUI-003; QK-TST-UNIT-010 |
| Card/media removal | Removal during any nonterminal state | Abort, wipe, preserve only already-committed consistent artifacts | QK-REQ-CARD-005, QK-REQ-TRN-002; QK-TST-PWR-002/003 |
| Power loss or restart | Any state | Restart at clean idle; no resumed door, share, review, approval, or signing state | QK-REQ-PLT-001/004, QK-REQ-REC-005; QK-TST-PWR-001…005 |
| Internal failure | Any named error | Fail closed, show bounded factual result, wipe, terminate | QK-REQ-HF-003, QK-REQ-PLT-004; QK-TST-UNIT-010 |
| Drop/cleanup | Session owner leaves scope | Optimization-resistant wipe of transcript, seeds, A2, Kit-R intermediates, shares, and recovered payload | QK-REQ-ENT-012, QK-REQ-KIT-005, QK-REQ-PLT-004; QK-TST-SAN-003 |

## Custody truth table

The terminal is never a signer and retains no wallet secret between sessions. D is metadata, A2 is a decryption key, and neither is a signing factor. “Spend possible” describes possession in principle, not the restricted terminal route.

| Held combination | A available? | B available? | Spend possible? | Intended posture | Required response |
|---|---:|---:|---:|---|---|
| none or terminal alone | No | No | No | replaceable terminal | none from possession alone |
| A1 only | No, without A2 | No | No | normal factor at rest | sweep on known capture because later A2 disclosure converts it |
| B only | No | Yes | No | normal card | sweep on theft/extraction; A2 makes any captured A1 decryptable |
| A1+B | Yes | Yes | Yes | normal signing pair | attacker possession is full compromise |
| either Kit share alone | No | No | No | separated envelope | sweep if seal/copy doubt; computational secrecy is capped by Kit-R entropy |
| any share 1 + any share 2 from setup copies | Yes | Yes | Yes | complete break-glass Kit | only Kit-Spend or Kit-Restore is exposed by product flow |
| two same-index shares | No | No | No | invalid combination | reject before reconstruction |
| optional setup spare B alone | No | Yes | No | pre-created spare | same exposure rules as B |
| A1 + either B copy | Yes | Yes | Yes | normal path | attacker possession is full compromise |

Two complete Kits are printed by default. Cross-copy opposite indices deliberately combine because every setup copy uses the same pad. Co-storing both envelopes chooses faster use over separation safety; the Kit page must say so.

## Trust boundaries

### qk-core

- Sole owner of transcripts, secret derivation, A1 authentication, Kit frame validation and combination, door state, PSBT semantics, trusted review/approval, signing, card writes, and zeroization.
- Must never expose a general Kit signing session, regenerate Kit shares after setup, restore a missing B, accept same-index shares, or persist wallet secrets.

### qk-io

- Owns bounded camera/QR, A1 image/OCR, Kit-share image/string transport, and microSD transport; outputs remain hostile.
- Has no secret, card, approval, Kit-combination, capsule-authentication, or door-selection authority. Every Kit scanner screen is mode-locked to Kit shares. The fallback-string terminal input method remains unavailable until separately ratified.

### Key Card B and setup-time spare

- Hold only signer-B least-authority account material, A2, D, fixed role and lifecycle state.
- A spare may be created only at original setup. Later restoration requires the old card's physical remains; the terminal cannot establish that fact.

### Kit envelopes and print path

- Each envelope holds one framed 96-byte share page. Either share alone depends on Kit-R computational secrecy; both reveal the complete wallet.
- The printer sees share bytes and is therefore within the setup ceremony's temporary confidentiality boundary. Copies, spool/cache disposal, sealing, geography, periodic seal checks, and destruction are physical procedures rather than terminal-proven facts.

### Online coordinator

- Holds D and constructs hostile PSBTs. It is responsible for discovering the complete UTXO set used by Kit-Spend; the terminal proves ownership of presented inputs but not omission of unpresented UTXOs.

### User

- Supplies the external facts: selected Kit posture, custody separation, seal history, physical card remains, destruction, and coordinator completeness confirmation.
- A false or mistaken fact can defeat the corresponding physical procedure; no screen or cryptographic check is described as proving it.

### Kernel, booted image, display/keypad, qk-decoy, build environment, and rescue computer

Their prior trust boundaries remain: kernel and physical UI are trusted in wallet mode; qk-decoy is terminated first; the development environment holds public test material only; commodity-reader rescue is an exposure event followed by migration. Process separation does not protect a session from a compromised kernel or authorized malicious terminal.
