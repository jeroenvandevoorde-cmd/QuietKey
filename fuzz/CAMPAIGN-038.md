# Campaign 038 - Normal SEC1210 signing qualification

Status: EXECUTED — QUALIFYING RUN COMPLETE.

QK-DEC-172, published at
`a740e65b903560420ef43445d96855b686ced154`, authorizes this M21
preregistration before implementation. Commit D at
`3b1a7a7d93e4fe513b853ef90fa29a3cbda4dbb1` constructed the target and
starting corpus recorded below. Commit E records the completed qualification,
independent minimization and registered replay without rewriting the
preregistered recipe.

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

The qualifying source was published commit D at
`3b1a7a7d93e4fe513b853ef90fa29a3cbda4dbb1`, after the integrated
implementation and mandatory LOA Linux handoffs. This preregistration's commit
was not that source. Commit D added the target and its sole new starting root,
`fuzz/corpus/qk_core_normal_sec1210/`, records the actual constructed files,
byte counts and SHA-256 inventories, and keeps this campaign planned with a
checked starting inventory and no completed manifest. It cannot self-pin an
unknowable future commit SHA. Do not rewrite this recipe to match later results.

The constructed root contains exactly 68 regular public seed files. Each file
is 25 bytes, for 1,700 bytes in total. No qualifying execution is recorded by
this measurement. The canonical listing is sorted
`SHA-256<TAB>bytes<LF>`. The entries inventory is ordered by filename and uses
`corpus<TAB>target<TAB>bytes<TAB>SHA-256<TAB>path<LF>`.

| Target | Start files / bytes | Listing bytes | Listing SHA-256 | Entries bytes | Entries SHA-256 |
|---|---:|---:|---|---:|---|
| `qk_core_normal_sec1210` | 68 / 1,700 | 4,624 | `339631dead4a6db702f305ed50ddaf2041de01f1933bf5eae2204fe161ef2ec8` | 10,206 | `7818e075a5eaf4cd4979df682123feee7ecc8775996db65ea5feafd73bb1946d` |

The 68 public seeds make the named positive, binding, signing, I/O, framing,
clock, WTX, reader-extension and preapproval paths reachable without relying
on long mutation chains. Their exact bytes are:

| Filename | Bytes | Hex |
|---|---:|---|
| `binding-counter` | 25 | `3130313930403053303030303030303030313230303030780a` |
| `binding-descriptor` | 25 | `3130313b30403053303030303030303030313430303030780a` |
| `binding-fingerprint` | 25 | `3130313630403053303030303030303030303930303030780a` |
| `binding-instruction` | 25 | `3130313a30403053303030303030303030313330303030780a` |
| `binding-lifecycle` | 25 | `3130313430403053303030303030303030303730303030780a` |
| `binding-lifecycle-shape` | 25 | `3130313330403053303030303030303030303630303030780a` |
| `binding-profile` | 25 | `3130313230403053303030303030303030303530303030780a` |
| `binding-session` | 25 | `3130313830403053303030303030303030313130303030780a` |
| `binding-wallet` | 25 | `3130313530403053303030303030303030303830303030780a` |
| `binding-xpub` | 25 | `3130313730403053303030303030303030313030303030780a` |
| `boundary-hundred` | 25 | `39303130303f3053303030303030303030363030303030780a` |
| `clock-deadline` | 25 | `3d30313230403053303030303030303030363630303030780a` |
| `clock-failed` | 25 | `3d30313030403053303030303030303030363430303030780a` |
| `clock-regressed` | 25 | `3d30313130403053303030303030303030363530303030780a` |
| `coalesced-slot-event` | 25 | `3c30313030403053303030303030303030363330303030780a` |
| `frame-checksum` | 25 | `3430313230403053303030303030303030333530303030780a` |
| `frame-nack` | 25 | `3430313730403053303030303030303030343030303030780a` |
| `frame-sequence` | 25 | `3430313430403053303030303030303030333730303030780a` |
| `frame-status` | 25 | `3430313630403053303030303030303030333930303030780a` |
| `frame-t1-chaining` | 25 | `3430313b30403053303030303030303030343430303030780a` |
| `frame-t1-checksum` | 25 | `3430313830403053303030303030303030343130303030780a` |
| `frame-t1-nad` | 25 | `3430313930403053303030303030303030343230303030780a` |
| `frame-t1-r-block` | 25 | `3430313a30403053303030303030303030343330303030780a` |
| `frame-truncated` | 25 | `3430313330403053303030303030303030333630303030780a` |
| `frame-type` | 25 | `3430313530403053303030303030303030333830303030780a` |
| `high-s-accepted` | 25 | `3a30313030403053303030303030303030363130303030780a` |
| `hostile-qkip` | 25 | `3830313030403053303030303030303030353930303030510a` |
| `invalid-signature-late-reply` | 25 | `3e30313030403053303030303030303030363730303030780a` |
| `io-closed` | 25 | `3330313230403053303030303030303030323930303030780a` |
| `io-overreported-read` | 25 | `3330313030403053303030303030303030333430303030780a` |
| `io-read-failed` | 25 | `3330313130403053303030303030303030323830303030780a` |
| `io-read-timeout` | 25 | `3330313330403053303030303030303030333030303030780a` |
| `io-short-write` | 25 | `3330313630403053303030303030303030333330303030780a` |
| `io-write-failed` | 25 | `3330313430403053303030303030303030333130303030780a` |
| `io-write-timeout` | 25 | `3330313530403053303030303030303030333230303030780a` |
| `preapproval-hold` | 25 | `3730313030403053303030303030303030353530303030300a` |
| `preapproval-invalid-event` | 25 | `3730313030403053303030303030303030353830303030330a` |
| `preapproval-removed` | 25 | `3730313030403053303030303030303030353630303030310a` |
| `preapproval-timeout` | 25 | `3730313030403053303030303030303030353730303030320a` |
| `reader-extension-eight` | 25 | `3630313130403053303030303030303030353230303030780a` |
| `reader-extension-malformed` | 25 | `3630313330403053303030303030303030353430303030780a` |
| `reader-extension-nine` | 25 | `3630313230403053303030303030303030353330303030780a` |
| `reader-extension-one` | 25 | `3630313030403053303030303030303030353130303030780a` |
| `repeated-r-rejected` | 25 | `3b303130303f3053303030303030303030363230303030780a` |
| `session-counter-exhausted` | 25 | `3f30313030403053303030303030303030363830303030780a` |
| `sign-earlier-binding` | 25 | `3230313f30403053303030303030303030323630303030780a` |
| `sign-earlier-session` | 25 | `3230314030403053303030303030303030323730303030780a` |
| `sign-future-counter` | 25 | `3230313e30403053303030303030303030323530303030780a` |
| `sign-high-s` | 25 | `3230313930403053303030303030303030323030303030780a` |
| `sign-invalid` | 25 | `3230313830403053303030303030303030313930303030780a` |
| `sign-malformed-der` | 25 | `3230313730403053303030303030303030313830303030780a` |
| `sign-repeated-r` | 25 | `3230323a313f3053303030303030303030323130303030780a` |
| `sign-replay-previous` | 25 | `3230323d313f3053303030303030303030323430303030780a` |
| `sign-wrong-counter` | 25 | `3230313c30403053303030303030303030323330303030780a` |
| `sign-wrong-index` | 25 | `3230313530403053303030303030303030313630303030780a` |
| `sign-wrong-key` | 25 | `3230313630403053303030303030303030313730303030780a` |
| `sign-wrong-review` | 25 | `3230313430403053303030303030303030313530303030780a` |
| `sign-wrong-session` | 25 | `3230313b30403053303030303030303030323230303030780a` |
| `success-hundred` | 25 | `30323230303f3053303030303030303030303330303030780a` |
| `success-mixed` | 25 | `3030333030403053303030303030303030303430303030780a` |
| `success-one` | 25 | `3031313030403053303030303030303030303230303030780a` |
| `success-zero` | 25 | `3030303030403053303030303030303030303130303030780a` |
| `wtx-eight` | 25 | `3530313130403053303030303030303030343630303030780a` |
| `wtx-large-multiplier` | 25 | `3530313430403053303030303030303030343930303030780a` |
| `wtx-nine` | 25 | `3530313230403053303030303030303030343730303030780a` |
| `wtx-one` | 25 | `3530313030403053303030303030303030343530303030780a` |
| `wtx-two-max` | 25 | `3530313530403053303030303030303030353030303030780a` |
| `wtx-zero-multiplier` | 25 | `3530313330403053303030303030303030343830303030780a` |

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

After qualification, commit E creates
`fuzz/CORPUS-MANIFEST-NORMAL-SEC1210-V1.tsv`, naming the actual published D
source. The completion record below states actual executed inputs;
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

## Execution and retained post-run root

Qualification ran once on 2026-09-19 from published commit D
`3b1a7a7d93e4fe513b853ef90fa29a3cbda4dbb1`. HEAD, origin/main and the clean
source tree matched that SHA before execution. The committed 68-file starting
root was copied into a fresh external qualification checkout with the exact
command and matching start inventories retained in external evidence. No
smoke run, stopped attempt, retry, source edit or parameter change occurred.

The platform was macOS 15.8 build 24H23, x86_64, kernel 24.6.0. Linux-only
descriptor and UART paths were not exercised by this pure in-memory target.
The measured tools were cargo-fuzz 0.13.2 and
`rustc 1.100.0-nightly (e7769602a 2026-08-24)` under
nightly-2026-08-25. The run wrapper SHA-256 was
`62041dc8f2b07aed847777132fcd41b380f51d062930d403ead35ba1aa975a20`;
the minimization wrapper SHA-256 was
`6bb3bbf653156108b6fbec666883b6257c00921e00ace86bc1665a508831bfe7`;
and the replay wrapper SHA-256 was
`2550e6a614f23452c24f733f768a649795160cf9229d9b5c5c059a8069c8d541`.

The exact preregistered invocation began at 05:41:40Z and ended at 08:24:48Z.
It executed exactly 100,000 inputs with seed 172001, exit 0, 380 new engine
units, slowest-unit time zero seconds, peak RSS 697 MiB and zero artifacts.
Measured process wall time was 9,787.51 seconds. The engine's final live corpus
was 187 units / 4,466 bytes; that internal quantity is not substituted for the
persisted post-run root. The retained run log is 56,441 bytes with SHA-256
`d4ed1da1708a00443dee44d903867b3795403b100a541083238f879efdc9e952`.

| Root | Files / bytes | Listing bytes | Listing SHA-256 | Entries bytes | Entries SHA-256 |
|---|---:|---:|---|---:|---|
| Starting | 68 / 1,700 | 4,624 | `339631dead4a6db702f305ed50ddaf2041de01f1933bf5eae2204fe161ef2ec8` | 10,206 | `7818e075a5eaf4cd4979df682123feee7ecc8775996db65ea5feafd73bb1946d` |
| Retained post-run | 280 / 6,763 | 19,039 | `cd3b6d31581ed7d4dabaf9986836479c898702c8ad06b2818fe3069033c7f875` | 47,093 | `86aa13e2e8c0cdcad1ac57ab7309aae1842c0dfb3634c1613e8d9e7327fec762` |
| Promoted fixed point | 134 / 3,233 | 9,111 | `0b54e1875647400fddf6d92fb574f1eadf62fb21768f57571b626ea32873e254` | 23,315 | `27c2a376c0f5cd814c8af7964d596a1b795204ed09a48b3a9b5a7391a9c68ddf` |

## Two-copy minimization and promotion

The exact post-run root was retained before two independent copies A and B
were made. The existing minimization wrapper ran five sequential passes on
each copy: ten invocations total, all at the same published source, all shell
exit 0, all carrying `MERGE-OUTER: successful`, all without the wrapper's
masked-child-failure text, all artifact-free and all with clean tracked source.
A and B agreed byte-for-byte after every corresponding pass. Pass four was
the first agreeing stable fixed point; pass five was the required additional
unchanged confirmation. Before/after snapshots, inventories, logs and exact
commands remain in external evidence.

| Pass on A and B | Files | Bytes | Listing bytes | Listing SHA-256 | Entries bytes | Entries SHA-256 | Stable |
|---|---:|---:|---:|---|---:|---|---|
| 1 | 142 | 3,417 | 9,655 | `ffbcca020e4dd1ec1c1684b90cd0e9c03b5e9da5c936ab44752af552629061a0` | 24,707 | `31d8502c76c0062f5a1bce6af2116af665e21350bdd95f41f8fb04788595d99d` | no |
| 2 | 135 | 3,256 | 9,179 | `b5e5a5f91d05f66fcf836b0d6a5556eb8166bf169e88a4e30a2fc21aee818068` | 23,489 | `5e882bed46e18ca1ab95bef2d0a8e764db65e2c281acb45c4988fa747da61a4e` | no |
| 3 | 134 | 3,233 | 9,111 | `0b54e1875647400fddf6d92fb574f1eadf62fb21768f57571b626ea32873e254` | 23,315 | `27c2a376c0f5cd814c8af7964d596a1b795204ed09a48b3a9b5a7391a9c68ddf` | no |
| 4 | 134 | 3,233 | 9,111 | `0b54e1875647400fddf6d92fb574f1eadf62fb21768f57571b626ea32873e254` | 23,315 | `27c2a376c0f5cd814c8af7964d596a1b795204ed09a48b3a9b5a7391a9c68ddf` | yes |
| 5 | 134 | 3,233 | 9,111 | `0b54e1875647400fddf6d92fb574f1eadf62fb21768f57571b626ea32873e254` | 23,315 | `27c2a376c0f5cd814c8af7964d596a1b795204ed09a48b3a9b5a7391a9c68ddf` | yes |

The A/B log SHA-256 pairs for passes one through five were respectively
`b488b2de64425ba7197f2758573421fceaa1fc0a9487e0c7bf36ffedd97283fb` /
`cc3fcb98e12861f5024737087b66c09b43cb702279d8ab809355420c39f870d1`,
`705605cb1c708643fb888ae3251219ec268b9df9e44d3ca2e77032c5a3b1dcb6` /
`90146ec2884c70d2bb6fb2144e81f50ed895b2d8a52e4e1494fc03bc29c2d306`,
`83c7df91e64c65db1cce21f27619d99b4070129625f2eb7f5881bdf258b6bb7b` /
`88c6ac70ca47b5a994e156a732b772c10c64e3a69ef5a80627ac4e5c1133ef76`,
`b50cae7d340af0a34f4400481841d6829d87d43701a6006a4c5af853c59d864b` /
`bc121cdae200cd8691a47558140bd6c0e1922d79a3685cbf913af22ea517a32d`,
and `71ce32a5c7b32f4be9fcb67b883a2f90111b901d78b1acd1ac281d22c8ff587c` /
`9afd18469a18a63c9cffa19e0956215a2e9ff15b14201110c4bf980acdbde7c7`.
Only the independently agreeing fixed-point bytes were promoted.

## Complete registered replay

All 56 registered corpus roots replayed in sorted target order through
`fuzz/replay-corpus.sh TARGET` at the qualification source on macOS 15.8 build
24H23, x86_64. The retained replay records span filesystem timestamps from
08:36:00Z to 08:41:30Z on 2026-09-19. A terminal-only timer reported 329.69
seconds, but no replay-driver timing log was retained, so that fractional wall
time is contextual rather than independently reconstructible from the retained
files. Registered roots totaled 10,027 files / 675,281 bytes; engine executed
units totaled 10,092. These quantities are not interchangeable. Every target
exited 0 and produced zero artifacts.
The promoted `qk_core_normal_sec1210` root contributed 134 files / 3,233 bytes
and 135 executed units. Its inventory remained byte-identical before and after
replay. All 55 historical roots remained byte-identical to commit D. The
retained per-target replay summary is 5,996 bytes with SHA-256
`cdeb0aa1d2bfdb0a2e801d78011772e5444a4e0bb2b99ba25233e02e73d9ed5e`;
individual logs and exact exits remain in external evidence.

## Manifest registration

`fuzz/CORPUS-MANIFEST-NORMAL-SEC1210-V1.tsv` was rendered from the promoted
root at qualification source
`3b1a7a7d93e4fe513b853ef90fa29a3cbda4dbb1`. Rendered and installed bytes
compare equal.

| Manifest | Entries | Bytes | LF | SHA-256 |
|---|---:|---:|---:|---|
| `fuzz/CORPUS-MANIFEST-NORMAL-SEC1210-V1.tsv` | 134 | 23,735 | 141 | `7bfaa9d4ee37f17741222e7759fbc6c10e6df4e182a47faa90045070e0cb443c` |

## Completion boundary

The one required 100,000-input run completed at the published Commit D source;
all ten minimization invocations passed their explicit success and artifact
guards; both independent copies reached the same fixed point and repeated it
unchanged; all 56 registered roots replayed with exit 0 and no artifact; and no
stopped or smoke attempt occurred. Campaign 038 therefore registers the
promoted corpus and manifest above. This is pure software hostile-input
qualification. It makes no device, physical transport, card-operation,
production-readiness, timing or Gate claim.
