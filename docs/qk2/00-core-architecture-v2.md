# QuietKey Core Architecture v2

Status: Owner-ratified normative architecture under QK-DEC-121  
Profile: Single Card plus Two-Envelope Kit  
System status: experimental, no real funds

## 1. Authority and scope

This document is the supreme product architecture for QuietKey v2. It supersedes Core Architecture v1 for all active product, implementation, test, bench, and Gate work. Core Architecture v1 and its subordinate documents remain immutable historical material.

Where another document conflicts with this one, this document prevails. Durable changes require an Owner-ratified Decision Log row. Implementations, tests, fixtures, diagrams, and product text must not silently restore a v1 assumption.

V2 retains these frozen foundations:

- mainnet-only Bitcoin;
- native P2WSH;
- BIP48 path `m/48'/0'/0'/2'`;
- BIP39 English 24-word derivation with fixed empty passphrase;
- PSBT v0;
- the M17 A1 capsule;
- the M18 OCR-safe alphabet and frozen A1 codec;
- the M21 ring-fenced fuzz framework;
- the M22/M30 uncompressed-Base32 BBQr P/T profile;
- the P0.1 logical keypad vocabulary;
- dice-only v1 entropy input; and
- normal A1 plus Key Card signing.

V2 removes Card C, three-account descriptors, every A1+C or B+C recovery route, and every general two-card signing ceremony.

## 2. Core decision

### 2.1 Wallet topology

Each wallet has exactly two signing authorities:

- **A** — terminal-held signing authority derived from Seed-A; and
- **B** — the one required Key Card authority derived from Signer-B.

The wallet descriptor is native mainnet P2WSH:

```text
wsh(sortedmulti(2,A,B))
```

Both signatures are required. Descriptor origins for A and B are exactly `[fingerprint/48'/0'/0'/2']`; receive descriptors end `/0/*`, change descriptors end `/1/*`, and the two full checksummed descriptors are byte-identical except for that branch byte.

The terminal may offer one optional spare B card during initial setup. A spare is byte-equivalent wallet authority, not a third signer. It is never required, cannot be added after setup, and changes neither threshold nor descriptor.

### 2.2 Normal operation

Normal signing requires:

1. the unchanged A1 capsule;
2. the terminal authority A;
3. the one required Key Card B;
4. the authenticated descriptor pair D; and
5. the complete validate, review, approve, revalidate, sign, finalize, and export sequence.

The normal route remains A1+B. The Kit is not a convenience signing path.

### 2.3 Recovery Kit

The Recovery Kit contains exactly two sealed tamper-evident envelopes. Each envelope carries one framed XOR share. Either envelope alone is insufficient. Together they reconstruct a complete 96-byte wallet payload:

```text
Seed-A entropy[32] || Seed-B entropy[32] || A2[32]
```

The Kit is therefore a complete wallet when both envelopes are combined. Outside the Kit, the no-single-object principle remains: no ordinary single object is sufficient to spend.

Two complete Kits are printed by default during setup. All copies use the same two share values, so any copy of share 1 combines with any copy of share 2. Product instructions encourage geographically and administratively separate custody. The capsule's cryptographic security does not depend on copy scarcity, but public posting works against the discretion layer and is not recommended.

The Kit cannot generate a new Kit after setup. This is a terminal lifecycle invariant: share-generation state is wiped after setup and no regeneration API exists. It is not a claim that a person cannot photograph or copy a printed page.

## 3. Custody and loss model

### 3.1 Ordinary objects

The ordinary custody objects are:

- terminal;
- required Key Card B;
- optional setup-time spare B;
- A1 printed kit copy and any private identical digital copies;
- authenticated descriptor pair D/watch-only coordinator material;
- Kit envelope share 1; and
- Kit envelope share 2.

### 3.2 Expected outcomes

| Situation | Required response |
|---|---|
| A1 and B available | Normal A1+B signing. |
| Card missing, both Kit envelopes intact | Kit-Spend sweep only. |
| Card damaged but remains physically in hand, both Kit envelopes intact | Kit-Restore may provision one replacement B, after which A1+B performs the required fresh-wallet sweep. |
| A1 unavailable, B remains in hand, both Kit envelopes intact | Kit-Restore may reprint A1 with a fresh nonce, after which A1+B performs the required fresh-wallet sweep. |
| Any Kit seal is doubtful, opened unexpectedly, photographed, or custody-ambiguous | Sweep immediately; do not restore in place. |
| Only one Kit envelope available | No payload and no spending route. |
| Watch-only coordinator lacks complete UTXO knowledge | Do not claim a complete sweep; resolve coordinator state first. |

Periodic seal checks are a product requirement. The expected interval and physical wording remain implementation/bench decisions until separately ratified.

### 3.3 External facts

Software cannot prove:

- that the watch-only side has found every wallet UTXO;
- that a claimed card remains physically in hand;
- that a discarded card was destroyed;
- that no second live card exists;
- that an envelope was never photographed or copied; or
- that a seal is physically intact.

These are explicit human or coordinator facts. The terminal may request factual confirmation and bind the response to a flow, but it must not present the response as machine verification.

## 4. Entropy and secret derivation

### 4.1 Dice-only policy

V2 has two dice transcript profiles:

- **ManualKeypad** — exactly 100 literal ASCII digits `1` through `6` per purpose; and
- **DiceGrid** — exactly 125 literal ASCII digits `1` through `6` per purpose, representing five confirmed shakes of 25 dice.

There are exactly four fresh purposes in this order:

1. Seed-A;
2. Signer-B;
3. Kit-R; and
4. A2.

Invalid bytes reject immediately and are never filtered. Exact transcript reuse across any pair of the four purposes is a hard error. A complete transcript hashes once with SHA-256. The transcript is seed-equivalent secret material, is retained only as long as the ceremony requires simultaneous reuse checking and derivation, is never exported, and is wiped on completion, cancellation, interruption, failure, or drop.

ManualKeypad remains exactly 100 values. DiceGrid remains gated on fixed-camera read accuracy, measured inter-shake face independence, batch die-bias testing, and settle mechanics guaranteeing one die per cell.

### 4.2 Seed-A and Signer-B

The SHA-256 transcript output is 256-bit BIP39 entropy. It maps to 24 English words using the BIP39 checksum rule. The words use NFKD normalization, PBKDF2-HMAC-SHA512 with exactly 2048 rounds, and fixed empty passphrase. Mnemonic material is transient and provisioning-internal; no public API exposes it.

Private BIP32 derives account nodes at `m/48'/0'/0'/2'`. Invalid presented derivations reject without skip-to-next-index behavior. Only account xpubs, descriptors, wallet ID, scripts, and addresses leave the secret boundary.

### 4.3 A2

A2 is the literal SHA-256 output of its transcript. It remains the 32-byte A1 document secret and the final 32 bytes of the Kit payload.

### 4.4 Kit-R

Let `wallet_id` be the SHA-256 of the full checksummed receive descriptor, one zero byte, and the full checksummed change descriptor.

For the Kit-R transcript:

```text
T     = SHA256(literal transcript)
salt  = SHA256(ASCII "QuietKey/QKEC-1" || ASCII "Kit-R" || wallet_id[0..16])
PRK   = HKDF-SHA256-Extract(salt, T)
R     = HKDF-SHA256-Expand(
          PRK,
          ASCII "QuietKey/Kit-R/pad/v1" || 0x00 || wallet_id,
          96 bytes
        )
```

The first 16 bytes of `wallet_id` are the ceremony identifier. No separate random or persistent ceremony identifier exists.

Share construction is exact:

```text
P      = Seed-A entropy || Seed-B entropy || A2
share1 = R
share2 = P XOR R
```

Share secrecy is computational and capped by Kit-R transcript entropy. It is not a 768-bit information-theoretic one-time-pad claim. The same R is used only to emit all setup copies of this wallet's two shares; it is then wiped with every payload and derivation scratch value.

## 5. Descriptor and public wallet identity

The two-account descriptor body is exactly 297 ASCII bytes and the full checksummed descriptor is exactly 306 bytes. The wallet-ID transcript is exactly 613 bytes.

The fixed offsets are:

- origin starts `[18,157]`;
- xpub starts `[41,180]`; and
- branch positions `[153,292]`.

Account xpubs must be distinct. Derived route keys must be distinct. The 2-of-2 witnessScript is exactly 71 bytes:

```text
OP_2 PUSH33(sorted key 0) PUSH33(sorted key 1) OP_2 OP_CHECKMULTISIG
```

Each route performs exactly four bounded public derivations: branch and index for A, then branch and index for B. Hardened indices, invalid tweaks, infinity, depth overflow, malformed account metadata, duplicate xpubs, duplicate derived keys, pair mismatch, noncanonical descriptor text, or checksum mismatch are named rejections.

The public v2 GOLDEN fixture lineage uses four obvious public manual transcripts: the first 100 bytes of infinite repetitions `123456`, `234561`, `345612`, and `456123` for Seed-A, Signer-B, Kit-R, and A2. It is permanently valueless public private material, never production input.

## 6. A1 capsule

The M17 capsule remains byte-frozen:

```text
magic[4] || coding_version[1] || crypto_version[1] || network[1] ||
nonce[12] || ciphertext[32] || tag[16]
```

It is exactly 67 bytes. AAD remains the seven-byte header followed by the full 32-byte wallet ID. The document key remains HKDF-SHA256 with IKM A2, salt wallet ID, and info `QuietKey/A1/v1`. Decryption releases no plaintext before authentication.

Kit-Restore may reprint A1 only with a fresh caller-supplied 96-bit nonce. The old capsule is not reproduced byte-for-byte.

## 7. Kit share storage formats

### 7.1 Canonical frame

Each share frame is exactly 142 bytes:

| Field | Bytes | Value |
|---|---:|---|
| magic | 4 | ASCII `QKKS` |
| version | 1 | `01` |
| share index | 1 | `01` or `02` |
| wallet binding | 32 | full `wallet_id` |
| share | 96 | share 1 or share 2 |
| checksum | 8 | first 8 bytes of the hash below |

Checksum construction:

```text
SHA256(ASCII "QuietKey/KitShare/v1" || 0x00 || preceding 134 frame bytes)[0..8]
```

Checksum verification precedes field use. Version, index, wallet mismatch, same-index combination, length, checksum, and canonicality failures are distinct named rejections. A candidate payload is not released until both valid, different-index, same-wallet frames combine and all downstream wallet facts reproduce the bound wallet ID.

### 7.2 QR

The printed QR is exact:

- QR version 10;
- error correction Q;
- byte mode;
- no ECI;
- mask with the lowest ISO penalty score, lowest-number mask on a tie; and
- four-module quiet zone.

There is exactly one share QR per envelope page.

### 7.3 Character fallback

The exact 142 frame bytes pack MSB-first in the M18 alphabet. The result is exactly 228 symbols with four required zero pad bits. It is presented as four lines of 57 symbols. Line wrapping is presentation only; there are no separators.

The terminal input method for this fallback is not yet ratified. It belongs to the mode-locked kit-scanner slice and must not be inferred from the A1 reader.

## 8. Card model

There is one required Key Card role B. A setup-time spare, if chosen, carries the same B authority and wallet binding. The card protocol must bind version, lifecycle, card identity, wallet ID, account fingerprint, account xpub, descriptor commitment, and allowed operations.

No v2 command, role, slot, fixture, or screen may retain a Card C semantic. Procurement labels such as candidate C1/C2/C3 are not card roles.

Provisioning, replacement, power-cut behavior, atomicity, endurance, timing, and target cleanup remain Gate-B/C physical obligations. A replacement card may be written through Kit-Restore only when the user confirms the old card remains physically in hand. A missing card requires sweep, not replacement.

## 9. Transaction intake, review, and fee policy

The immutable-input and previous-transaction proof rules remain. Every input must be descriptor-owned with no skip path. Change is reconstructed from D. Every non-change output is classified under the ratified six-template destination policy. SIGHASH_ALL remains mandatory.

Review schema v3 uses exact domain:

```text
QuietKey/D-09/review/v3
```

It rejects schema v1 and v2 without translation. It binds QK-FEE-POLICY-V2 and all approval-relevant input, output, recipient, change, amount, fee, warning, locktime, sequence/RBF, sighash, network, source-identity, descriptor, and wallet facts.

The maximum 2-of-2 input witness is:

```text
1 + 1 + 2 * (1 + 72) + (1 + 71) = 220
```

QK-FEE-POLICY-V2 retains the v1 thresholds:

- `W-FEERATE-LOW` below 1000 milli-sat/vB;
- `W-FEERATE-HIGH` at or above 200000 milli-sat/vB;
- `W-FEESHARE-HIGH` when fee times 20 is at or above total input value;
- `W-FEEABS-HIGH` at or above 1000000 sats; and
- fatal emergency rejection strictly above 5000000 sats.

All arithmetic is checked. Estimated vsize uses BIP141 and the 220-byte witness template. The 182-byte reference transaction is 238 vB; the 100-input maximum is 11,036 vB.

## 10. Signing and finalization

Normal signing verifies every existing partial signature against the descriptor-derived A/B key and exact transaction digest. Terminal A signatures use the pinned libsecp256k1 boundary, RFC6979, low-S normalization, and immediate verification. Card B signatures are verified before insertion.

The final witness is exactly:

1. one zero-length CHECKMULTISIG dummy;
2. the A and B signatures ordered by their public keys' positions in the sorted witnessScript; and
3. the exact 71-byte witnessScript.

After every insertion, the immutable review identity and all unchanged facts are rebound. Finalization reparses the raw transaction from bytes, reconstructs every digest, and verifies both signatures. No Kit-Restore flow reaches signing.

## 11. Kit session doors

The user selects a Kit door before any share scan. Scanner state is then locked to Kit-share frames and cannot accept PSBT, A1, BBQr transaction, coordinator, or other QR types.

### 11.1 Kit-Spend

Kit-Spend is sweep-only. It may sign only when:

- both valid shares combine and reproduce the bound old wallet;
- the watch-only side supplies the complete candidate UTXO set;
- every transaction input is proven owned by the old descriptor;
- the transaction has exactly one output;
- that output is proven to the newly generated descriptor; and
- there is no change output, OP_RETURN output, second recipient, or unowned input.

The terminal cannot prove coordinator UTXO completeness. Product text states that responsibility plainly. Any close profile race, ambiguous ownership, or incomplete source state rejects rather than relaxing sweep shape.

### 11.2 Kit-Restore

Kit-Restore signs nothing. It permits exactly one of:

- provision one replacement B card after explicit physical-remains confirmation; or
- reprint A1 with a fresh nonce.

It emits no transaction signature, general wallet export, new Kit, or second live card. If the card is missing, the restore door is unavailable.

Intentional Kit opening is itself a seal-breaking event. A restored A1+B path exists only to perform the subsequent migration to a fresh wallet; it does not return the opened Kit wallet to indefinite normal operation.

## 12. Exports

Finalized PSBT and raw-transaction SD artifacts retain the M25 atomic create, write, sync, close, reopen, hash/parse verify, and no-replace rename lifecycle. Transaction QR retains BBQr file types P and T under the frozen profile.

Watch-only coordinator export remains SD-only and uses the v2 two-key BSMS/BIP389 successor after its migration slice. QR remains transaction-only. Quantum Shelter descriptor export and address packs remain excluded.

The Kit's QR is a setup/recovery share format, not a transaction or coordinator export.

## 13. Screen and ceremony principles

Every shake or manual transcript is echoed exactly for confirmation before acceptance. Each complete transcript receives a displayed commitment. The fixed derivation explanation renders no mnemonic, seed byte, transcript, A2, Kit-R material, or private key. The final wallet fingerprint is displayed.

All displayed claims are factual. There is no randomness meter or statistical score. Review and result screens select only bound fact objects and do not recompute, normalize, or invent facts.

Card removal, media removal, timeout, shutdown, restart, power loss, cancellation, failure, invalid transition, or dropped state wipes and terminates. After approval, no transport, camera, or intake yield is allowed before the bound signing outcome.

Kit screens additionally bind the preselected door, both frame identities, same-wallet/different-index result, and permitted terminal action. Human confirmations remain labeled as human statements.

## 14. Resource and allocation boundaries

The descriptor layer remains direct-allocation-free. A route inherits exactly four bounded 165-byte BIP32 allocations, eight for receive plus change. Transaction-wide derivation caps and review encoding maxima use new non-reused v2 limit identifiers.

Kit frame, fallback, QR, print artifact, frame input, two-share combination, scanner session, and Kit-Spend/Restore resources receive separate non-reused limit IDs. Exact 142-byte frame, 228-symbol fallback, four lines of 57, QR v10-Q, 96-byte share, and two-frame combination are protocol constants. Larger implementation-buffer and target-resource values remain candidates until their slice and registry freeze.

HOST allocation facts do not discharge production-core allocation-free or target-remanence obligations.

## 15. Threat boundaries

The v2 design explicitly covers:

- theft or compromise of one ordinary non-Kit object;
- one-envelope disclosure;
- cross-wallet and same-index share confusion;
- malformed or type-confused scanner input;
- Card B loss versus Card B damage while retained;
- Kit seal doubt and photographed/copied shares;
- incomplete coordinator UTXO knowledge;
- attempts to turn Kit-Restore into signing;
- attempts to add a late second live card;
- A1 nonce reuse during reprint; and
- stale v1 review, descriptor, witness, fixture, or card-role objects.

The design does not claim that software senses physical copying, proves destruction, proves sole possession, discovers all UTXOs without coordinator input, or supplies target constant-time/remanence evidence before the relevant Gates.

## 16. Maturity gates

- **Gate A** — fixed-camera readability, kit QR/fallback morphology, print geometry, dice-grid evidence, and physical user flows.
- **Gate B** — required-card capability, optional setup spare, atomic provisioning, replacement constraints, endurance, timing, power-cut behavior, and CCID reachability.
- **Gate C** — production-core allocation, cleanup, constant-time boundaries, complete protocol/resource registry, and hardware integration.
- **Gate D** — real storage, print/export lifecycle, interruption, power-cut, and artifact-custody evidence.
- **Gate E** — end-to-end normal A1+B, Kit-Spend, Kit-Restore, seal response, replacement discipline, and product ceremony behavior on the target stack.

No HOST milestone closes a physical Gate.

## 17. Migration order

Implementation proceeds only in this dependency order:

1. descriptor core and public v2 GOLDEN lineage;
2. review schema v3 and QK-FEE-POLICY-V2;
3. signing, finalization, and Bitcoin Core differential suite;
4. provisioning and Kit-R secret ownership;
5. screen-flow topology;
6. two-key coordinator export;
7. Kit frame and combination codec;
8. setup-only Kit generation and print export;
9. mode-locked Kit scanner and fallback input decision;
10. Kit-Restore; and
11. Kit-Spend enforcement.

Each slice requires its own exact scope, source/test evidence, hostile-input coverage, Owner approval, and LOA verification before its successor begins. Until a slice lands, downstream v1 code may remain present only as frozen migration residue and receives no new feature work.

## 18. Final invariant

QuietKey v2 has one normal signing route and one sealed complete-wallet recovery mechanism:

```text
Normal:      A1 + B -> reviewed 2-of-2 signing
Recovery:    envelope 1 + envelope 2 -> preselected Kit-Spend or Kit-Restore
Kit-Spend:   complete owned-input sweep -> one new-descriptor output, no change
Kit-Restore: replacement B while old B remains, or fresh-nonce A1; no signing
```

No active v2 behavior depends on Card C, a 2-of-3 descriptor, a general Kit signing session, silent UTXO-completeness inference, or a post-setup Kit regeneration path.
