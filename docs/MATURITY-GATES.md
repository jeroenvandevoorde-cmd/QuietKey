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

### Gate B — exact-card feasibility — **OPEN**

Required evidence, all on the exact production card model:

- secp256k1 signing correctness and performance on-card.
- Derivation behavior for the least-authority payload (BIP48 account xprv, chain code, origin, role, A2, D).
- On-card RNG characterization.
- APDU protocol behavior including exact byte layouts.
- Write atomicity, storage endurance, and power-cut behavior during card operations.
- Confirmed independent B/C signing keys with the same A2 and D payloads (C never a clone of B).
- Rescue path demonstrated with a commodity reader.
- Applet lifecycle and extraction-resistance characterization recorded.

### Gate C — production core — **OPEN**

Required evidence:

- Target-language/toolchain decision recorded with ARMv6/target evidence (resolves OD-01).
- Reproducible builds from controlled builders with traceable binaries.
- Differential testing against independent implementations.
- Fuzzing of all hostile-input parsers (PSBT, QR, SD, APDU responses) with recorded corpora and results.
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

### Gate E — complete recovery rehearsal — **OPEN**

Required evidence, performed by representative users on production kit contents, meeting predefined human-factors thresholds:

- End-to-end rehearsal of every recovery path: A1+B, A1+C, and B+C.
- Recovery on a replacement terminal.
- Complete lost-factor rotation: one-time use of a surviving pair, fresh A′/B′/C′/A2′/D′ wallet, and full sweep.
- Rescue using the open rescue tool with commodity hardware.
- Independent transaction finalization outside QuietKey tooling.
- Resulting transactions accepted by Bitcoin Core.

## Release blockers (in addition to Gates A–E)

All **OPEN**:

- Architecture-owner approval of `ARCHITECTURE.md` (currently DRAFT).
- P0/RV3 hardware conclusions.
- Reproducible releases from controlled builders with traceable binaries.
- Configured private vulnerability reporting with designated ownership.
- External independent audit.

Replit and host simulation cannot validate the air gap, exact card, RNG, camera/optics, microSD electrical behavior, memory erasure, secure boot, update resilience, or power-loss behavior. Only exact-target evidence counts toward Gates A–E.
