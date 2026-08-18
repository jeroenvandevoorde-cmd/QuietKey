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

### Gate A — A1 and QR on fixed mechanics — **OPEN**

Required evidence:

- Independent A1 capsule test vectors, cross-checked by an implementation not derived from the reference.
- Demonstration that no plaintext is ever released before successful authentication (no unauthenticated plaintext under any failure path).
- Realistic print/capture trials of the A1 physical codec on the fixed terminal mechanics (camera, optics, lighting) across damage and aging conditions, meeting predefined decode thresholds.
- Human trials of A1 production and recovery with representative users meeting predefined thresholds.
- Actual-camera BBQr type `P` limits and performance measured on the exact fixed hardware (frame rates, payload ceilings), recorded as trial data, not projections.
- Fuzzing of the A1/OCR candidate and error-correction pipeline (QK-TST-FUZZ-005) with recorded corpora and results, and measured resource bounds for the A1 capture path on the exact target (inputs to the QK-LIM-A1 rows).

### Gate B — exact-card feasibility — **OPEN**

Required evidence, all on the exact production card model:

- secp256k1 signing correctness and performance on-card.
- Derivation behavior for the least-authority payload (BIP48 account xprv, chain code, origin, role, A2, D).
- On-card RNG characterization.
- APDU protocol behavior including exact byte layouts.
- Write atomicity, storage endurance, and power-cut behavior during card operations.
- Confirmed independent B/C signing keys with the same A2 and D payloads (C never a clone of B).
- Rescue path demonstrated with a commodity reader (the definition of this evidence depends on OD-02: what a rescue reads, and how, cannot be specified until the card and its export model are selected).
- Applet lifecycle and extraction-resistance characterization recorded.

### Gate C — production core — **OPEN**

Required evidence:

- Target-language/toolchain decision recorded with ARMv6/target evidence (resolves OD-01).
- Reproducible builds from controlled builders with traceable binaries.
- Differential testing against independent implementations.
- Fuzzing of all hostile-input parsers (PSBT, descriptor, QR, SD, APDU responses, A1 candidate pipeline) with recorded corpora and results.
- Semantic-validation evidence for descriptors, A1 capsules, card payloads, and QR/SD-delivered PSBTs performed independently in `qk-core` (QK-REQ-PLT-010), and APDU response parsing owned by `qk-core` (QK-REQ-PLT-011).
- Exact-target air-gap verification: every radio absent or permanently disabled, with no software re-enable path (QK-REQ-PLT-008, QK-TST-AUD-007).
- Property-based tests for core invariants.
- Sanitizer runs (memory, undefined behavior) and static analysis with triaged findings.
- Secret-memory handling review (allocation, zeroization between sessions, no swap/leak paths) verified on target.
- Independent cryptographic and protocol review of the implemented core.
- `qk-core`/`qk-io`/`qk-decoy` separation implemented on target; signing occurs only after trusted-core reparse, review, and physical approval.

### Gate D — storage and power failure — **OPEN**

Required evidence:

- Interruption/power-cut injection during provisioning, SD writes, and updates, with no secret leakage or corruption.
- No acceptance of a half-provisioned wallet, card, or A1 in any state.
- No input overwrite under any interruption or retry.
- Demonstrated recovery from corrupt, full, removed, or interrupted media.
- microSD electrical/removal fault behavior on target; media aging and error-correction limits characterized with recorded results.
- Userspace SD filesystem-parser containment demonstrated (kernel never mounts removable media — QK-REQ-TRN-009/010, QK-TST-SAN-004).
- SD output atomicity: an output interrupted during write, sync, or read-back verification is never presented as complete (QK-REQ-TRN-008, QK-TST-PWR-005).

### Gate E — complete recovery rehearsal — **OPEN**

Required evidence, performed by representative users on production kit contents, meeting predefined human-factors thresholds:

- End-to-end rehearsal of every recovery path: A1+B, A1+C, and B+C.
- Recovery on a replacement terminal.
- Complete lost-factor rotation: one-time use of a surviving pair, fresh A′/B′/C′/A2′/D′ wallet, and full sweep.
- Rescue using the open rescue tool with commodity hardware.
- Independent transaction finalization outside QuietKey tooling.
- Resulting transactions accepted by Bitcoin Core.

## Release blockers (in addition to Gates A–E)

- Architecture-owner approval of `ARCHITECTURE.md` — **SATISFIED** at baseline H0 `c618407a3900657d8ce4c479c4056f859f86bec6` (QK-APR-2026-08-18-001 in `docs/DECISION-LOG.md`). This is the only satisfied blocker.

All other blockers remain **OPEN**:
- P0/RV3 hardware conclusions.
- Reproducible releases from controlled builders with traceable binaries.
- Configured private vulnerability reporting with designated ownership.
- External independent audit.

Replit and host simulation cannot validate physical claims. For each physical claim — the air gap, exact-card behavior, RNG characteristics, camera/optics performance, microSD electrical behavior, memory erasure, secure boot, update resilience, and power-loss behavior — only evidence recorded on the exact production target counts toward the gate listing that claim. Non-physical logic claims (parser verdicts, state-machine behavior, protocol correctness) may accumulate `HOST-TESTED` evidence earlier, but every gate above still requires its listed target-level evidence before the owner may close it.
