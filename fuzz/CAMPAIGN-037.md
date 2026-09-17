# Campaign 037 - production SEC1210 transport qualification

Status: EXECUTED — QUALIFYING RUN COMPLETE.

The fixed recipe and measured starting roots below were preregistered at
`cfce367fa7385bb541b5641034e57dbf2724e066`. The first qualifying attempt
stopped on a fuzz-oracle mismatch, retained all evidence and changed no
tracked source. The LOA-authorized oracle correction was published as
`fcf0a2c2e62e6d5031c9c43cc81ccfca7a0ad887`; both qualifying runs and every
minimization pass were then executed once from the registered starts at that
published source. The preregistration language is preserved below, and the
measured completion record follows the coverage section.

## Boundary and fixed recipe

QK-DEC-169 commit 5 qualifies only the changed `qk_sec1210_wire` target and
the new `qk_core_sec1210_transport` target. The other 53 target corpus roots,
every prior manifest entry and every byte outside
`fuzz/corpus/qk_sec1210_wire` and
`fuzz/corpus/qk_core_sec1210_transport` remain frozen and replay-only. Inputs
are public synthetic ATRs, T=1 blocks, SEC1210/CCID frames, descriptor
outcomes, clock steps and bounded state-machine programs. No device, product
process, UART, GPIO, card operation, signing operation, key, secret or private
material enters either closure.

The published commit containing this preregistration defines the only eligible
source for both qualifying runs and every minimization pass; the completed
record will name that commit as the qualification source. Until qualification
completes, no executed-input count, post-run inventory, result, minimization
identity or artifact finding is claimed. Earlier smoke runs against unpublished
source are nonqualifying and excluded from Campaign 037 evidence.

| Target | Public seed | Inputs | Maximum input bytes | Feature, defaults disabled |
|---|---:|---:|---:|---|
| `qk_sec1210_wire` | 169001 | 100,000 | 4,096 | `sec1210-wire` |
| `qk_core_sec1210_transport` | 169002 | 100,000 | 65,536 | `sec1210-production` |

Pinned tools and limits are Campaign 036's: cargo-fuzz 0.13.2;
nightly-2026-08-25; rustc `1.100.0-nightly (e7769602a 2026-08-24)`;
AddressSanitizer; release overflow checks and debug assertions; offline
dependency resolution; two-second per-input timeout; 2,048 MiB RSS ceiling;
reload disabled; final statistics; and empty target artifact directories before
the runs.

```text
fuzz/run-bounded.sh qk_sec1210_wire 100000
fuzz/run-bounded.sh qk_core_sec1210_transport 100000
```

Each exact post-run root is retained and copied independently twice. Both
copies are minimized with `fuzz/minimize-corpus.sh`; every pass, exit and
inventory identity is recorded. Promotion requires the two copies to reach the
same fixed point and one further unchanged confirmation pass. Campaign 037
never deletes, renames or changes a pre-Campaign-037 corpus file: the promoted
root is the frozen prior root plus any novel independently agreeing minimized
bytes. Failures and artifacts are preserved and are not erased by a later
pass. Corpus figures are measured file counts and bytes, not libFuzzer live-unit
counts. The completed record reports the actual platform, source, executed
inputs, starting and persisted post-run inventories, canonical listing and
entries identities, complete minimization histories, exits, artifact counts
and replay of all 55 registered roots.

## Measured starting roots

The existing Campaign 036 `qk_sec1210_wire` root and the new public
`qk_core_sec1210_transport` seeds were copied into fresh external start
directories and measured before qualification. No qualifying run is recorded
by this measurement. The wire root is byte-identical to its promoted Campaign
036 fixed point; no wire seed is added, removed or changed at preregistration.
The production-transport root contains 25 new public seed files totaling 76
bytes.

The canonical listing is sorted `SHA-256<TAB>bytes<LF>`. Entries are ordered by
filename and use the manifest grammar
`corpus<TAB>target<TAB>bytes<TAB>SHA-256<TAB>fuzz/corpus/target/filename<LF>`.

| Target | Start files/bytes | Listing bytes | Listing SHA-256 | Entries SHA-256 |
|---|---:|---:|---|---|
| `qk_sec1210_wire` | 565 / 43,252 | 38,374 | `d457d789a42609c98566e0d5699ac72971635662f11d195be611a587bc47a873` | `37e77b5c3de454a819ee1e4acb999be21630e8543d9b1b06f6aef02b4689df92` |
| `qk_core_sec1210_transport` | 25 / 76 | 1,675 | `8cf5fbde3299c8679d36384c21bc3ffad7d5ce65200411737559f1fb6995f1b9` | `2ec8f2e35801ed1f2f0216c8caf8ffc9033a4a50754dbf2d7e62f96afe33ee1a` |
| Aggregate | 590 / 43,328 | - | - | `b4e0e226fb47ee3a8c1b6e37561b8767926e59ccfb76f82c823f2c1641fa90eb` |

## Oracle and hostile-input coverage

The changed wire target preserves all Campaign 036 decoder, exchange,
readback, IFS, Fi/Di and raw-response oracles. It additionally compares the
fixed-storage production decoder with the existing decoder after every input
byte, including decoded facts, pending-byte counts, completion and sticky
failure. It independently checks the production GetSlotStatus, PowerOn-at-3-V,
GetParameters, SetParameters and XfrBlock request constructors for exact
framing, slot zero, sequence, payload length and XOR; drives structural
production ATR validation with arbitrary bytes; and retains the raw-session
boundaries for 512 commands, 32,768 received bytes, 64 events, WTX, reader time
extension, deadlines, partial/coalesced frames and terminal failure.

The new joint target drives the production qk-core SEC1210 transport only
through an injected in-memory descriptor and deterministic clock. It checks the
five-command initialization and exact emitted request grammar; fragmented and
coalesced input; descriptor short-write, failure, timeout and end states; clock
failure, regression and exact deadline edges; application command lengths
through 221/222 bytes; responses through 218/219 bytes; 108/109 APDUs; the
derived 977-command boundary; 64/65 events; eight/nine WTX requests; eight/nine
reader time extensions; controller sequence wrap; T=1 send and receive sequence
state; malformed framing, checksum, length, status, error, NAD and PCB; chaining
and R-block rejection; and received-byte accounting below the conservative
session envelope. The product unit test supplies the exact 52,815-byte and
one-byte-over boundary proof because the envelope's four-byte allowance for
each event is intentionally unreachable on a continuing public path: the only
continuing event is the two-byte SlotChange, while a four-byte HardwareError is
terminal. Its deterministic-clock oracle groups descriptor waits by controller
command and asserts the ordinary base allowance, the IFS transition, accepted
WTX allowances, reader extensions without another write and clipping at the
original absolute APDU deadline. Every operation asserts bounded counters,
fieldless production error names, sticky first failure, reset behavior and no
write after terminal failure.

The 25 public production-transport seeds make each of the eight top-level lanes
and the important near-boundary selectors reachable without relying on long
mutation chains. Filenames are SHA-1 of the bytes solely for libFuzzer naming;
evidence identities use SHA-256.

| Filename | Bytes | Hex |
|---|---:|---|
| `09d2af8dd22201dd8d48e5dcfcaed281ff9422c7` | 2 | `300a` |
| `e5fa44f2b31c1fb553b6021e7360d07d5d91ff5e` | 2 | `310a` |
| `7448d8798a4380162d4b56f9b452e2f6f9e24e7a` | 2 | `320a` |
| `a3db5c13ff90a36963278c6a39e4ee3c22e2a436` | 2 | `330a` |
| `9c6b057a2b9d96a4067a749ee3b3b0158d390cf1` | 2 | `340a` |
| `5d9474c0309b7ca09a182d888f73b37a8fe1362c` | 2 | `350a` |
| `ccf271b7830882da1791852baeca1737fcbe4b90` | 2 | `360a` |
| `d3964f9dad9f60363c81b688324d95b4ec7c8038` | 2 | `370a` |
| `4143d3a341877154d6e95211464e1df1015b74bd` | 3 | `31300a` |
| `ad552e6dc057d1d825bf49df79d6b98eba846ebe` | 3 | `31320a` |
| `d0758565fd06c37aa66b071160d156f5628cd518` | 3 | `32300a` |
| `aec46dc0de48f39f98f9572b6560ca3f0916b715` | 3 | `32330a` |
| `97ea7ec8a6bb8ab9049d86bc39b5be2b0800b14b` | 3 | `33300a` |
| `ee91be46f117cd84e7924a54fe5a7923129b0681` | 6 | `33213a3a310a` |
| `54a95c085e4c3a37d3077d8f32c3fc2423d7398a` | 4 | `3430400a` |
| `ee526b046da020a8fe8930dba8105730f57907df` | 4 | `3430410a` |
| `1fb45e0b8e830ad89189049dd3ff03d36347f17f` | 3 | `35300a` |
| `b4297d8ba77b0d208f3c3537a2592fd239d9008e` | 3 | `36300a` |
| `d514562e9d3e1580287834c5d5bf78615326daab` | 3 | `36310a` |
| `f87ea1a24729bffa68b314534c8e378653e6cfd2` | 4 | `3734300a` |
| `cc2722f0c58d14a9327124c22c17f71c56a7635e` | 4 | `3735300a` |
| `8e0383f1dbd567d8f1aabe67bc2a0fea56a5e99c` | 4 | `3736300a` |
| `26d6f45a1358f378c32d6cac925c0882125adf0c` | 4 | `3737300a` |
| `dd07df21629278e2e5da4251c4d2d0fbd8b46c0e` | 3 | `37300a` |
| `4a4bc0a954aacaf16e27b9cf9a4a14ba09c25036` | 3 | `37310a` |

## Preserved stopped attempt and oracle correction

The first attempt used published source
`cfce367fa7385bb541b5641034e57dbf2724e066`. Its wire target completed
100,000 inputs with exit 0 and no artifact, but the core target stopped after
584 inputs with one three-byte artifact, hex `35c670`, SHA-256
`879d17bdf5b41584067e5e027b42f831020bf1432e8d26e0a82a0c177d875d5a`.
That input exposed an oracle error: the product returned
`T1DeadlineExceeded` for the IFS absolute deadline while the oracle expected
`Sec1210DeadlineExceeded`. The exact stopped wire and core corpus roots, both
logs and the artifact remain retained externally. The repository's tracked
starts were restored byte-for-byte; the artifact was replayed against the
correction and was not promoted into either corpus.

The LOA found the matching read-side IFS classification error before the
campaign resumed. Its independent sweep of all one-, two- and three-byte
inputs plus 200,000 pseudo-random inputs of four through 24 bytes executed
17,043,008 inputs: correcting only the write-side oracle left 397 mismatches,
while correcting both sites left none. The published correction changes only
the fuzz oracle; no product byte changed. Both 100,000-input targets were
rerun at the corrected source rather than carrying forward the earlier wire
result.

## Execution and retained post-run roots

Qualification ran on 2026-09-17 using published source
`fcf0a2c2e62e6d5031c9c43cc81ccfca7a0ad887`. GitHub main, HEAD and the clean
source tree were checked before execution. The platform was macOS 15.8,
build 24H23, x86_64 (`macOS-15.8-x86_64-i386-64bit` in the qualification
context). Linux-only descriptor and UART paths were not exercised by these
pure fuzz closures.

The measured tools were cargo-fuzz 0.13.2 and
`rustc 1.100.0-nightly (e7769602a 2026-08-24)` using
nightly-2026-08-25. The run wrapper SHA-256 was
`a4919beb5650046675cdc6313fcbceaa5debdb93e9dc8cf0bcab9b592e951c1c`;
the minimization wrapper SHA-256 was
`01f1124b86985a5a49ab43c78fa97b68b48c86fe674ae1f4a087cebe8a501d5d`.
Qualification context recording began at 10:20:39.036561Z and completed at
10:26:12.912135Z. These times are host observations, not product timing
evidence.

| Target | Seed | Start files/bytes | Inputs executed | Exit | Persisted post-run files/bytes | New engine units | Peak RSS MiB | Artifacts |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| `qk_sec1210_wire` | 169001 | 565 / 43,252 | 100,000 | 0 | 825 / 61,694 | 334 | 586 | 0 |
| `qk_core_sec1210_transport` | 169002 | 25 / 76 | 100,000 | 0 | 471 / 5,963 | 674 | 528 | 0 |

Wire ran from 10:20:40.689823Z to 10:24:05.297640Z, with a measured process
wall time of 204.616008435 seconds. Core ran from 10:24:06.988543Z to
10:24:39.414376Z, with a measured process wall time of 32.424907837 seconds.
Both wrappers reported exactly 100,000 executed inputs, slowest-input time
zero seconds, exit 0 and no artifact. Engine-reported live units and elapsed
time are not substituted for measured persisted files or process wall time.

| Retained run log | Bytes | SHA-256 |
|---|---:|---|
| `run-qk_sec1210_wire.log` | 44,794 | `00f725ace871bf20d15612f4ac2be54f53f9392566a94d5d32e4140555fe08b0` |
| `run-qk_core_sec1210_transport.log` | 87,101 | `43ad481806f1e787e2de434cf98bc951639ee5aee46724fcb437bd23ce869542` |

| Post-run root | Files/bytes | Listing bytes | Listing SHA-256 | Entries SHA-256 |
|---|---:|---:|---|---|
| `qk_sec1210_wire` | 825 / 61,694 | 56,062 | `2e8d2fb088f0a8488a53ce0feff809af3ca48a213343991b83ea8c84dbebc62e` | `c24c70e376650e9b2908f1998a0b6f76040230cc6ac5228edcde7594c16605dc` |
| `qk_core_sec1210_transport` | 471 / 5,963 | 31,691 | `da49125dd0723fd221e0ac76baada993173789e824314e02e53179c230262c46` | `18acdcc61411c9f6e7eeb106e25562d75414feb1676596ca408e85fda08da64a` |

## Two-copy minimization and promotion

Each exact post-run root was retained and copied independently to A and B.
The existing minimization wrapper ran five passes on each wire copy and eight
passes on each core copy: 26 invocations in total, all at the same published
source, all exit 0, all artifact-free and with no masked child failure. The A
and B identities agreed after every corresponding pass. Wire passes four and
five and core passes seven and eight were the two consecutive unchanged
confirmations of their respective fixed points. Per-pass logs, exits,
identities and retained before/after copies remain in external evidence.

### qk_sec1210_wire

| Pass on A and B | Files | Bytes | Listing bytes | Listing SHA-256 | Entries SHA-256 | Unchanged from preceding pass |
|---|---:|---:|---:|---|---|---|
| 1 | 677 | 49,598 | 45,971 | `7f77a74844655f11d9c726fc91f7183836f948bfa7f7e9feb34205e935ac1eb3` | `7aae9615bb502bfc8693260ec81859aed817754edd3b5ce94354f626caf47622` | no |
| 2 | 667 | 49,409 | 45,295 | `ff1e17833e7bac95a63a9b1f3ce27104dc52364dc9a8b09aa3a4ffc0c456e12f` | `9584ef27b244c6f9212d1fe22da45d2755700461ab698c44754ffc2c9501a28a` | no |
| 3 | 663 | 49,341 | 45,024 | `d36d35e0d06b14336f37319a9b59f6f1993d83eb89538d6121ff511f09f747bd` | `66e5f34551de162b963d4a1a7ae8465acf67576e5fe00775ac1a3fcd4f9bf08c` | no |
| 4 | 663 | 49,341 | 45,024 | `d36d35e0d06b14336f37319a9b59f6f1993d83eb89538d6121ff511f09f747bd` | `66e5f34551de162b963d4a1a7ae8465acf67576e5fe00775ac1a3fcd4f9bf08c` | yes |
| 5 | 663 | 49,341 | 45,024 | `d36d35e0d06b14336f37319a9b59f6f1993d83eb89538d6121ff511f09f747bd` | `66e5f34551de162b963d4a1a7ae8465acf67576e5fe00775ac1a3fcd4f9bf08c` | yes |

### qk_core_sec1210_transport

| Pass on A and B | Files | Bytes | Listing bytes | Listing SHA-256 | Entries SHA-256 | Unchanged from preceding pass |
|---|---:|---:|---:|---|---|---|
| 1 | 411 | 5,349 | 27,660 | `c3ee2876655c60dc606ce5a576740e7d3b4c12811eddd6b348116b55d25e07be` | `6d8f8e051133608118ee415e64fb7875c25c3c2709c7a0af50bbaffb2fdb7b6c` | no |
| 2 | 397 | 5,259 | 26,720 | `e0e23037afc86a8809073c29cece888c08efdd4e28c5d854f5c99075af9d77ef` | `055755298ede40a355487141347ef9d4439bb5bbf9e5785cd32fa3da9a2ac70d` | no |
| 3 | 394 | 5,241 | 26,518 | `7aedf3b43c2b06d5530cc4ab362499834df192525768bd724dc47ebcb5a7f673` | `5e5b823fa911f1afd5b985f3944d1b69824d05f4a6e2abfdec90fd75c748d600` | no |
| 4 | 391 | 5,221 | 26,317 | `d590f782ac1b2158f5bc5d98a0447df2834d8c62624422a78470f174a3e3ca7b` | `1181c90c88bd7d45e9ef9a8d93775add6c55489012e2e5b59a062b8878e62806` | no |
| 5 | 387 | 5,208 | 26,049 | `54b1555ddf9efead7df78bba118a9f311fe3266498624c38349fa5852afbc445` | `54c4f24f1b698bb1e6d481eb3766cfb28e4e90b889c9ff214d6be9171a886cbf` | no |
| 6 | 386 | 5,204 | 25,982 | `5c735e8920725c9dd07348dba65b90aba53c5287bf976100f0c68c39539d8d35` | `aaba38e932633ecc35ed140191e5a6b1a1f4514c9a80f307377b39736e424d16` | no |
| 7 | 386 | 5,204 | 25,982 | `5c735e8920725c9dd07348dba65b90aba53c5287bf976100f0c68c39539d8d35` | `aaba38e932633ecc35ed140191e5a6b1a1f4514c9a80f307377b39736e424d16` | yes |
| 8 | 386 | 5,204 | 25,982 | `5c735e8920725c9dd07348dba65b90aba53c5287bf976100f0c68c39539d8d35` | `aaba38e932633ecc35ed140191e5a6b1a1f4514c9a80f307377b39736e424d16` | yes |

The promoted wire root is the complete frozen 565-file Campaign 036 root plus
the 210 novel byte strings retained by both fixed-point copies. Those novel
files total 15,039 bytes. All historical wire files remain byte-identical;
112 that minimization did not retain were restored by the union. The new core
root is Campaign 037 material: 12 of its 25 preregistered seeds remain, 13
were minimized away, and 374 new agreeing files were promoted. This does not
delete or alter any pre-Campaign-037 corpus byte.

The first external promotion-helper invocation stopped before changing the
repository because it compared tuple-backed and JSON-list-backed versions of
the same starting identity directly. The helper-only comparison was normalized
and promotion then completed; neither fuzz target was rerun. That stop and its
zero-change disposition remain recorded externally. The exact post-run roots,
both independent minimization histories and the displaced repository post-run
roots remain retained rather than erased. The other 53 corpus roots remained
byte-frozen.

| Promoted target | Files/bytes | Listing bytes | Listing SHA-256 | Entries SHA-256 |
|---|---:|---:|---|---|
| `qk_sec1210_wire` | 775 / 58,291 | 52,651 | `983eaf557ee13ada9c2fb0695d34b9d6808663fcdaf77a78f1c17fa277a0bad2` | `7a93bf940f199008b9525a8ec4ca8ab835d79551fd27ecd98058e906a9d54bf9` |
| `qk_core_sec1210_transport` | 386 / 5,204 | 25,982 | `5c735e8920725c9dd07348dba65b90aba53c5287bf976100f0c68c39539d8d35` | `aaba38e932633ecc35ed140191e5a6b1a1f4514c9a80f307377b39736e424d16` |
| Aggregate | 1,161 / 63,495 | - | - | `3de064d2458de981523e1223a75dbd889cc1561370326124ef591e638b14ed33` |

## Complete registered replay

All 55 registered corpus roots replayed in sorted target order with
`fuzz/replay-corpus.sh TARGET` at the qualification source. The platform was
macOS 15.8 build 24H23, x86_64. Registered corpus files totaled 9,893 /
672,048 bytes; engine executed units totaled 9,957. These quantities are not
interchangeable. Every target exited 0 and produced zero artifacts.

| Replay | Corpus files | Corpus bytes | Executed units | Exit | Artifacts |
|---|---:|---:|---:|---:|---:|
| `qk_sec1210_wire` | 775 | 58,291 | 776 | 0 | 0 |
| `qk_core_sec1210_transport` | 386 | 5,204 | 387 | 0 | 0 |
| All 55 registered targets | 9,893 | 672,048 | 9,957 | all 0 | 0 |

Replay ran from 10:28:25.163805Z to 10:32:58.758580Z on 2026-09-17; replay
processes totaled 270.761135115 seconds. All 55 inventories matched the
promoted snapshot before and after, the other 53 matched the preregistered
baseline, and source-file fingerprints and HEAD remained unchanged. The
replay wrapper SHA-256 was
`97e1ad96aebe85351bc109c57650d512a35e8ddc48121d6fff2a537d83c866f3`.
The retained baseline snapshot SHA-256 is
`d76783084cc5daac148be6796d49d010ddaa2e1ea30af02fe209d12d3635d60a`;
the promoted snapshot SHA-256 is
`1fe4a3568ad79d0035e2b559a5800c1d42d8223f3d4c7d56389fa255c829cc84`.
Individual logs, per-target exits and statistics, source fingerprints and
before/after inventories remain in external custody.

## Manifest registration

`fuzz/CORPUS-MANIFEST-SEC1210-PRODUCTION-V1.tsv` was rendered from the
promoted roots at qualification source
`fcf0a2c2e62e6d5031c9c43cc81ccfca7a0ad887`. Its 1,161 entries bind the
775-file wire root and 386-file core root above. Rendered and installed bytes
compare equal.

| Manifest | Bytes | LF | SHA-256 |
|---|---:|---:|---|
| `fuzz/CORPUS-MANIFEST-SEC1210-PRODUCTION-V1.tsv` | 193,738 | 1,169 | `45d6ebf5de1f0c31428f7c186462da2d2c80292d30afe049441be172d548981f` |

## Completion boundary

Both required 100,000-input runs completed at one published source; all 26
minimization invocations exited 0 without artifacts; each A/B pair reached an
identical fixed point followed by two unchanged confirmations; the historical
wire root was preserved; and all 55 registered roots replayed unchanged.
Campaign 037 therefore registers the promoted corpora and manifest above.
This is pure software hostile-input qualification. It makes no device,
physical transport, card-operation, production-readiness, timing or Gate
claim.
