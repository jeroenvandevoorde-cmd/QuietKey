# Campaign 038 - Normal SEC1210 signing qualification

Status: PLANNED — NOT EXECUTED.

QK-DEC-172, published at
`a740e65b903560420ef43445d96855b686ced154`, authorizes this M21
preregistration before implementation. This file records a recipe and planned
coverage, not an implemented target or a qualifying result. No starting corpus
has been constructed or measured for this campaign, and no executed-input
count, post-run inventory, minimization result or artifact count is claimed.

## Boundary and fixed recipe

The sole new target is `qk_core_normal_sec1210`. It will drive the actual
integrated Normal A1+B owner through an in-memory descriptor and deterministic
clock, not a second signing controller. Public fixtures supply the signing
material. Arbitrary input bytes select a public profile/fixture and bounded
operation/fault schedule; they are hostile data, never new signing material.
No subprocess, device, real descriptor, PTY, UART, GPIO, card or secret enters
fuzz execution. Linux PTY qualification is separate software evidence and is
not performed by this target.

| Target | Public seed | Qualifying inputs | Maximum input bytes | Feature, defaults disabled |
|---|---:|---:|---:|---|
| `qk_core_normal_sec1210` | 172001 | 100,000 | 65,536 | `normal-sec1210` |

Re-adopt Campaign 037's pinned cargo-fuzz 0.13.2 and
`nightly-2026-08-25` (`rustc 1.100.0-nightly (e7769602a 2026-08-24)`),
AddressSanitizer, release overflow checks and debug assertions, and offline
dependency resolution. The run uses a two-second per-input timeout, 2,048 MiB
RSS limit, reload disabled, final statistics and an empty target artifact
directory. The planned invocation, available only after commit D adds this
target's runner dispatch, is:

```text
fuzz/run-bounded.sh qk_core_normal_sec1210 100000
```

The runner must select `--no-default-features --features normal-sec1210` and
use `-runs=100000 -seed=172001 -max_len=65536 -reload=0 -timeout=2
-rss_limit_mb=2048 -print_final_stats=1` under the pinned AddressSanitizer
build. These are the qualifying recipe, not evidence that it has run.

The feature enables only the already declared `qk-core`, `qk-card-protocol`
and `qk-ipc` dependencies plus `qk-core/sec1210-production`,
`qk-core/normal-process`, `qk-core/fuzzing` and `qk-ipc/fuzzing`, never
`host-runtime` or a new package. The planned internal path closure is exactly
these fifteen crates: qk-a1, qk-bbqr, qk-bip32, qk-card-protocol, qk-core,
qk-descriptor, qk-device-wire, qk-ipc, qk-kit, qk-provisioning, qk-psbt,
qk-secp, qk-sec1210-wire, qk-t1 and qk-wallet-v2. Existing fuzzing enables Kit
instrumentation too; this fuzz-only closure is not the integrated shipping
configuration's runtime-exclusion symbol proof.

## Planned oracle and hostile-input coverage

The target will exercise the shared application session and existing Normal
owner with registered public, permanently NEVER-FUND fixtures. Valid fixture
paths anchor positive traversal for Simple Recovery, Inheritance and Quantum
Shelter, zero/one/100 missing B signatures and mixed existing/missing
signatures. The program mutates event ordering, approval, application replies,
frame fragmentation and timing around those paths. Independent state
assertions will cover:

- No SIGN before approval; single-use approval/revalidation; only the pending
  card reply may be serviced after approval; a non-card event cannot be
  serviced, ignored as success or queued for resumption during that window.
- Binding and response-envelope failures before SIGN, including wrong wallet,
  profile, lifecycle, account fingerprint/xpub, descriptor commitment/bytes,
  session identity, counter and instruction.
- Malformed DER, invalid signatures, wrong key/review hash/input index,
  high-S normalization and repeated r; duplicate, reordered, missing, late and
  earlier-operation replies do not bypass the existing verifier.
- Bounded request dispatch and the 100/101 SIGN-attempt boundary; already
  valid B signatures require no new SIGN. The successful zero-WTX trace has
  eight binding APDUs plus 100 SIGN APDUs, 108 application APDUs and 113
  controller commands. The focused signing-count rejection must be
  `SigningRejected` with `OperationFailed` before transport, not transport-cap
  exhaustion or rejection of an already completed operation.
- Descriptor short/failed writes, end-of-stream/removal, absent, truncated or
  coalesced replies, malformed card/controller frames, clock failure or
  regression, exact deadlines and one step beyond, WTX and reader-extension
  limits, using the existing production limits and fieldless error names.
- Failure before any SIGN and at first, middle or last pending SIGN, including
  after accepted partial signatures: sticky first terminal outcome, consumed
  approval, bounded state, wiping, no partial export, no further write or
  export, no retry and no revival by a well-formed late reply. An attempted
  SIGN retains the unknown-card-outcome fact rather than claiming the card
  never signed.

Deterministic exact-boundary, transition and targeted allocation-failure
tests remain required by QK-DEC-172 independently of mutation coverage. Fuzz
input does not trigger real OOM or introduce a production allocator-control
API. A clean bounded campaign does not prove exhaustive coverage or independent
correctness of shared parsers and cryptography.

## Source, starting inventory and working-directory provenance

The qualifying source will be the published commit D, after the integrated
implementation and mandatory LOA Linux handoffs. This preregistration's commit
is not that source. Commit D adds the target and its sole new starting root,
`fuzz/corpus/qk_core_normal_sec1210/`, records the actual constructed files,
byte counts and SHA-256 inventories, and keeps this campaign planned with a
checked starting inventory and no completed manifest. It cannot self-pin an
unknowable future commit SHA. Do not rewrite this recipe to match later results.

Before qualification, seed the external working corpus only from that
published D commit's starting root, not a prior smoke-run, stopped-run or
post-run directory. Record its exact source SHA, the source and destination
paths, the seeding command and matching inventories, then the exact run
command, tool identities and execution platform. The persisted filesystem
counts are distinct from libFuzzer's live-unit counts.

All pre-existing 55 targets, target-to-feature mappings, corpus roots and
manifests remain byte-frozen and replay-only. No existing corpus is minimized,
promoted or re-registered by Campaign 038. No new dependency, lockfile change
or pin-semantics change is authorized by this preregistration.

## Minimization, registration and stopping rule

Retain the unmodified post-run root and make two independent copies. Minimize
each copy through the pinned `fuzz/minimize-corpus.sh` path until their content
inventories agree at a fixed point, then require a further unchanged
confirmation pass. Record every pass's command, exit, file/byte counts and
SHA-256 identity. Inventory listings use the existing sorted
`SHA-256<TAB>bytes<LF>` convention; manifest entries use the existing
`corpus<TAB>target<TAB>bytes<TAB>SHA-256<TAB>path<LF>` grammar and filename
ordering. Commit E promotes only this new root's independently agreeing bytes.

Only after qualification, commit E creates
`fuzz/CORPUS-MANIFEST-NORMAL-SEC1210-V1.tsv`, naming the actual published D
source. The completion record will state actual executed inputs;
starting/post-run/final file counts, byte counts and SHA-256 inventories;
manifest bytes, LF count and SHA-256; all minimization identities and exits;
artifact counts and identities; stopped evidence; and replay outcomes.
Remeasure any artifact identity recorded in prose against the retained bytes
during review; the existing manifest gate does not automatically check such
narrative values.

Replay all 55 historical corpora unchanged and the new root through the pinned
replay path. `tools/check-fuzz-corpora.sh` verifies inventories; it is not
itself corpus execution. Record replay counts and exits separately from the
inventory gate and `tools/check.sh`. Final LOA Linux CHECK PASS and corpus
replay remain closure gates; macOS measurements are labeled as such and do not
substitute for Linux runtime qualification.

A finding stops qualification with evidence retained. No unapproved oracle
change, retry, source change or scope widening can turn that finding into a
pass. Smoke runs, if any, are nonqualifying and separately identified; neither
they nor later success erase a stopped attempt.

This campaign authorizes no apparatus or card operation. It produces no Gate B
or Gate C evidence and makes no target timing, power-cut, endurance, remanence
or constant-time claim. A green qualification run means the software contract
holds against a model of the card, and nothing about a card.
