# QuietKey Maturity Gates

EXPERIMENTAL — NO REAL FUNDS — NOT A WALLET

Status is kept strictly separate from evidence: a gate's status changes only when the listed evidence exists and is accepted by the project owner. No gate closes because a document, plan, or reference implementation exists. Documentation cannot close a technical or physical gate. QuietKey is STOP-SHIP until every required gate closes.

## Maturity levels

- `SPEC` — a written, reviewed specification exists. No implementation claim.
- `REFERENCE-TESTED` — a reference implementation passes independent test vectors in a development environment.
- `HOST-TESTED` — behavior verified in host simulation (e.g., Replit). Proves logic only; proves nothing physical.
- `TARGET-TESTED` — verified on the exact production hardware target with recorded evidence.
- `INDEPENDENTLY-AUDITED` — externally reviewed by independent qualified parties with a published report.

## Technical gates

### Gate A — printed recovery media and QR on fixed mechanics — **OPEN**

Required evidence:

- Independent A1 capsule test vectors, cross-checked by an implementation not derived from the reference.
- Demonstration that no plaintext is ever released before successful authentication (no unauthenticated plaintext under any failure path).
- Realistic print/capture trials of the A1 physical codec on the fixed terminal mechanics (camera, optics, lighting) across damage and aging conditions, meeting predefined decode thresholds.
- Realistic print/capture trials of each 142-byte kit-share QR on the fixed mechanics and physical-readability/recovery trials of its exact 228-symbol M18 fallback after that fallback's terminal input method is separately ratified, including one-page-per-share production, scanner-mode lock, same-index rejection, full `wallet_id` binding, checksum failure, damaged print, and bounded retry behavior.
- Exact-target proof that kit scanning accepts only the preselected `Kit-Spend` or `Kit-Restore` door for the complete session and cannot yield to transaction intake, transport, or another recovery door.
- Human trials of A1 and kit-page production, custody instructions, scanning, fallback recovery, and error handling with representative users meeting predefined thresholds.
- Actual-camera and display-path BBQr type `P` and type `T` limits and performance measured on the exact fixed hardware (frame rates, payload ceilings), recorded as trial data, not projections.
- Fuzzing of the A1/OCR candidate and error-correction pipeline (QK-TST-FUZZ-005) with recorded corpora and results, and measured resource bounds for the A1 capture path on the exact target (inputs to the QK-LIM-A1 rows).

### Gate B — exact-card feasibility — **OPEN**

Required evidence, all on the exact production card model:

- secp256k1 signing correctness and performance on-card.
- Derivation behavior for the least-authority payload (BIP48 account xprv, chain code, origin, role, A2, D).
- On-card RNG characterization.
- APDU protocol behavior including exact byte layouts.
- Write atomicity, storage endurance, and power-cut behavior during card operations.
- Confirmed signer-B key generation and least-authority payload behavior, including A2, D, role, and `wallet_id` binding.
- Setup-only spare-card provisioning from the same signer-B authority, plus a proof that no spare can be added after setup and that a replacement-card restore is unavailable unless the original card remains physically in hand.
- Rescue path demonstrated with a commodity reader (the definition of this evidence depends on OD-02: what a rescue reads, and how, cannot be specified until the card and its export model are selected).
- Applet lifecycle and extraction-resistance characterization recorded.

### Gate C — production core — **OPEN**

Required evidence:

- Target-language/toolchain decision recorded with ARMv6/target evidence (resolves OD-01).
- Reproducible builds from controlled builders with traceable binaries.
- Differential testing against independent implementations.
- Fuzzing of all hostile-input parsers (PSBT, descriptor, QR, SD, APDU responses, A1 candidate pipeline, kit frame/fallback, and mode-locked kit scanner) with recorded corpora and results.
- Semantic-validation evidence for descriptors, A1 capsules, card payloads, and QR/SD-delivered PSBTs performed independently in `qk-core` (QK-REQ-PLT-010), and APDU response parsing owned by `qk-core` (QK-REQ-PLT-011).
- Exact-target air-gap verification: every radio absent or permanently disabled, with no software re-enable path (QK-REQ-PLT-008, QK-TST-AUD-007).
- Exact-target enforcement of the v2 `wsh(sortedmulti(2,A,B))` descriptor, 71-byte witness script, 220-byte fixed witness estimate, review schema v3, and `QK-FEE-POLICY-V2`, with v1/v2 review objects rejected rather than translated.
- Exact-target enforcement of both kit doors: `Kit-Spend` accepts only all-owned inputs and exactly one new-descriptor output with no change; `Kit-Restore` performs no signing and provisions only a permitted replacement card or a fresh-nonce A1.
- Property-based tests for core invariants.
- Sanitizer runs (memory, undefined behavior) and static analysis with triaged findings.
- Secret-memory handling review (allocation, zeroization between sessions, no swap/leak paths) verified on target.
- Independent cryptographic and protocol review of the implemented core.
- `qk-core`/`qk-io`/`qk-decoy` separation implemented on target; signing occurs only after trusted-core reparse, review, and physical approval.

### Gate D — storage and power failure — **OPEN**

Required evidence:

- Interruption/power-cut injection during provisioning, SD writes, and updates, with no secret leakage or corruption.
- Interruption/power-cut injection during kit-share creation and printing; a page or kit copy is never accepted until its complete printed share has passed the required verification flow.
- No acceptance of a half-provisioned wallet, card, A1, setup-only spare, share page, or two-envelope kit in any state.
- No input overwrite under any interruption or retry.
- Demonstrated recovery from corrupt, full, removed, or interrupted media.
- microSD electrical/removal fault behavior on target; media aging and error-correction limits characterized with recorded results.
- Userspace SD filesystem-parser containment demonstrated (kernel never mounts removable media — QK-REQ-TRN-009/010, QK-TST-SAN-004).
- SD output atomicity: an output interrupted during write, sync, or read-back verification is never presented as complete (QK-REQ-TRN-008, QK-TST-PWR-005).

### Gate E — complete recovery rehearsal — **OPEN**

Required evidence, performed by representative users on production kit contents, meeting predefined human-factors thresholds:

- End-to-end rehearsal of the normal A1+B path, `Kit-Spend`, replacement-card `Kit-Restore`, and fresh-nonce A1 `Kit-Restore`.
- Rehearsal of same-index, wrong-wallet, malformed-frame, checksum, seal-doubt, missing-card, and interrupted-session failures, each reaching the specified sweep or stop outcome without another door becoming available.
- Rehearsal that A1 alone, B alone, or either single envelope alone cannot spend, while the complete Kit deliberately can and is governed by its physical custody instructions.
- Cross-copy rehearsal showing that share 1 from one setup copy and share 2 from another reconstruct the same payload, while all copies contain the same setup pad and no post-setup regeneration path exists.
- Recovery on a replacement terminal.
- Complete lost-factor rotation: one-time use of an authorized surviving route, fresh Seed-A′/Signer-B′/A2′/Kit-R′/D′ material, a fresh A1′, two fresh complete kit copies, and a full sweep.
- Periodic seal inspection, separate-versus-together envelope handling, setup-time spare choice, and the rule that a missing card or seal doubt requires a sweep rather than restoration.
- Rescue using the open rescue tool with commodity hardware.
- Independent transaction finalization outside QuietKey tooling.
- Resulting transactions accepted by Bitcoin Core.

## Release blockers (in addition to Gates A–E)

- Architecture-owner approval of the v2 migration and Core Architecture v2 — **SATISFIED** by QK-DEC-121. This is the only satisfied blocker.

All other blockers remain **OPEN**:
- P0/RV3 hardware conclusions.
- Reproducible releases from controlled builders with traceable binaries.
- Configured private vulnerability reporting with designated ownership.
- External independent audit.

Replit and host simulation cannot validate physical claims. For each physical claim — the air gap, exact-card behavior, dice-grid read accuracy and mechanics, camera/optics performance, printer behavior, envelope seals, microSD electrical behavior, memory erasure, secure boot, update resilience, and power-loss behavior — only evidence recorded on the exact production target and materials counts toward the gate listing that claim. UTXO completeness, possession of the original card, destruction of superseded material, and envelope integrity remain external human or coordinator facts; software must not claim to prove them. Non-physical logic claims (parser verdicts, state-machine behavior, protocol correctness) may accumulate `HOST-TESTED` evidence earlier, but every gate above still requires its listed target-level evidence before the owner may close it.
