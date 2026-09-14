# Campaign 036 - bounded raw-response T=1 and SEC1210 transport

Status: EXECUTED — QUALIFYING RUN COMPLETE.

The recipe, exact seed table and measured starting unions were preregistered
in `986ed309f8dcc8725d20ea81550b85e7b65611af` before either qualifying run.
The execution and minimization record below is the subsequent qualification
record; statements about the preregistration boundary preserve that earlier
state. The completed registered replay is recorded separately below.

## Boundary and fixed recipe

QK-DEC-167-SUP-013 requalifies only `qk_t1` and
`qk_sec1210_wire`. The other 52 registered corpus roots remain byte-frozen
and replay-only. Inputs are public synthetic T=1 blocks, SEC1210/CCID frames
and bounded state-machine programs; no bench code, UART, GPIO, native
transport, host clock, card, signing operation, key or private material enters
either closure. Both targets retain every Campaign 035
ordinary/readback/IFS/Fi/Di oracle. The wire target remains wire-only; the T=1
target additionally exercises independently modeled joint raw T=1/SEC1210
layers. Production crate source is unchanged by this qualification.

Both 100,000-input runs and every minimization pass use one published code
commit, recorded afterwards as the qualification source in the completed
record and both final manifests. Until qualification completes, the active
manifests and checker registrations retain Campaign 035 unchanged. The public
seed candidates below are materialized in retained external start copies for
measurement before this preregistration is published; their measured union
identities are registered before either qualifying run. Only subsequently
qualified, independently agreeing fixed points replace the selected roots and
registrations together. At publication, this preregistration reported no
execution source, executed-input count, post-run inventory, result or artifact
finding; those later measurements are recorded below.

| Target | Public seed | Maximum input bytes | Feature, defaults disabled |
|---|---:|---:|---|
| `qk_t1` | 167011 | 8,192 | `t1-readback` |
| `qk_sec1210_wire` | 167012 | 4,096 | `sec1210-wire` |

Pinned tools and limits remain Campaign 035's: cargo-fuzz 0.13.2;
nightly-2026-08-25; rustc `1.100.0-nightly (e7769602a 2026-08-24)`;
AddressSanitizer; release overflow checks and debug assertions; offline
dependency resolution; two-second per-input timeout; 2,048 MiB RSS ceiling;
reload disabled; final statistics; empty target artifact directories before
the runs.

```text
fuzz/run-bounded.sh qk_t1 100000
fuzz/run-bounded.sh qk_sec1210_wire 100000
```

Every exact post-run root is retained and copied independently twice. Both
copies are minimized with unchanged `fuzz/minimize-corpus.sh`; each pass,
exit and identity is recorded. Promotion requires agreeing fixed points and
one unchanged confirmation pass. No unselected root is promoted or modified.
Corpus figures are measured file counts and bytes, not libFuzzer live-unit
counts. Failures and artifacts remain preserved and are not erased by a later
pass. The completed record names the actual verification platform, source,
executed inputs, starting and persisted post-run inventories, canonical
listing and entries identities, complete minimization histories, exits and
artifact counts. All 54 registered roots are replayed after promotion.

## Measured starting unions

The retained Campaign 035 roots and every exact candidate byte below were
copied into external start directories before qualification. The candidate
count, byte count and any exact-content de-duplication against the baselines
are recorded below. Every filename and byte count was checked against its
candidate bytes. The resulting inventories were measured from those external
copies, not inferred from sums. At that measurement, repository corpus roots
remained unchanged; no qualification run is recorded by the starting-union
measurement itself.

The canonical listing is sorted `SHA-256<TAB>bytes<LF>`. Entries are ordered
by filename and use the manifest grammar
`corpus<TAB>target<TAB>bytes<TAB>SHA-256<TAB>fuzz/corpus/target/filename<LF>`.
Baseline, candidate and external-union records remain retained outside Git.

The table specifies 47 T=1 candidates / 201 bytes and 31 wire candidates /
69 bytes before de-duplication. Five T=1 candidate byte strings already had
the same SHA-1 filename and exact bytes in the retained root, so T=1 added 42
files / 179 bytes; every wire filename was new, so wire added 31 files /
69 bytes. No existing filename carried different bytes.

| Target | Start files/bytes | Listing bytes | Listing SHA-256 | Entries SHA-256 |
|---|---:|---:|---|---|
| `qk_t1` | 775 / 27,599 | 52,564 | `ed41d16ae58a0621e200b0bb4f05ed6e4806f753618f46f1a7162276e0a2d4b2` | `4327309dd4ffebc0684d158bb0bf364e473509e34e1b232470e560beca9a03c7` |
| `qk_sec1210_wire` | 378 / 26,192 | 25,675 | `f1b35a5dfd7344e9ec337df902ad7485fae4844b9ad1bbbe54184185b28f4c69` | `0d13831a1fb053f94ac0a44fbb23b45ba40cf6b5dbd089c6b3f6f91c8d4c3d85` |

## Retained prior identities

Campaign 035 and its evidence remain unchanged. Both prior manifests bind
`a210126d6be075dc3320cdec73d71dfd1b1fddac`.

| Target | Prior corpus files/bytes | Prior listing bytes/SHA-256 | Prior manifest bytes/LF | Manifest SHA-256 | Prior entries SHA-256 |
|---|---:|---|---:|---|---|
| `qk_t1` | 733 / 27,420 | 49,750 / `3627952c9c37e057dcffbaec3eb48a791325c0c19a53874343f7121c6a76820b` | 102,902 / 740 | `e54700c7768d4bddcd31f4a56c0c4b8a9114cbd45c3694dbbf88656e6fb24e6d` | `2644609fd42b16717a0bb3a089a75a5bab940354284b07fa4d230834eaeeb672` |
| `qk_sec1210_wire` | 347 / 26,123 | 23,598 / `b91c0f6780b7e1fc5b05e66daf5a474862d4b6eb2758368717b9caf8b62c9424` | 55,924 / 354 | `129bfcf1b5f5f583c6ab90322d54c10b62fe33d62a99cb8ef911a8a3e48782ca` | `4af91fa4801a76ec7dba7c11ea2b9ff72ae49687a221d0cc37338eaa72d41d94` |

## Oracle and candidate-seed coverage

Both targets preserve all previous oracles and append independent reference
state machines for SUP-013's raw-response path. Reference bytes and bounds are
separately expressed rather than imported from implementation constants;
framing length is treated only as an untrusted bound, XOR/LRC is verified
before semantic fields drive state, and first failures remain sticky.
Acceptance, phase, counters, sequence state, pending command, deadlines and
retained observations are compared after every operation.

The T=1 target independently models mandatory IFS-to-254 before the first
APDU; 1/254/255-byte command INF and 254/255-byte response INF;
258/259-byte blocks; 128/129 APDUs; 16-exchange bounds; independent
send/receive bits and wrap; one final nonchained I-block; and named rejection
of chaining, R-blocks, retransmission, resynchronization and unsolicited
control replies. Its WTX model covers multipliers 1, 2 and 24, rejection of 0
and 25, the eighth/ninth boundary, exact same-multiplier E3 response and bBWI,
no APDU completion or sequence-bit advance, per-command allowance clipped by
the original 30,000 ms APDU deadline, a response after the base five-second
wait when validly extended, and rejection when the requested interval cannot
fit the remaining APDU budget. Multiple WTX requests do not accumulate
multiplicatively.

The wire target independently models the fixed
GetSlotStatus/PowerOn/GetParameters/SetParameters/IFS initialization and the
raw outer SEC1210 session through 512 commands, including CCID sequence wrap
255/0/1, 512/513 boundaries, 32,768 received bytes, event demultiplexing,
partial/coalesced frames, request bytes, bBWI and retained spans. Reader
time-extension DataBlocks remain nonfinal observations on the outstanding
command: the model covers retained multipliers, eight/nine occurrences across
WTX traffic, unchanged sequence and pending command, no reset of the
command/APDU deadline, exact empty shape, status/type/slot/sequence precedence
and extension-plus-final-response coalescing. The wire oracle does not invent
upper-layer APDU, WTX-count or T=1 semantic policy; those limits are asserted
by the independent T=1 and joint models.

The joint `qk_t1` path pairs both independent models, carrying exact IFS
state, raw T=1 blocks, CCID requests/responses and deadlines through normal
completion, WTX response exchanges and reader extensions. It checks that
neither extension mechanism completes an APDU or advances T=1 sequence bits,
that only the final accepted I-block completes the APDU, and that a terminal
error prevents a later send. Candidate seeds cover successful and rejecting
boundaries above plus partial writes, clock regression, exact deadline edges,
malformed checksums/lengths/NAD/PCB, wrong slot/sequence/status/error and
trailing or unsolicited bytes.

The table specifies 47 T=1 candidates / 201 bytes and 31 wire candidates /
69 bytes before de-duplication. Filenames are
SHA-1 of the bytes solely for libFuzzer naming; evidence identities use
SHA-256. Every candidate is listed in full. The table records intended
coverage, not execution results. Baselines and candidates are retained
independently before qualification or promotion.

| Target | Filename | Bytes | Hex |
|---|---|---:|---|
| `qk_sec1210_wire` | `efe43def97eb295fe99c3753f2d740d7b36df689` | 1 | `f0` |
| `qk_sec1210_wire` | `07b7255eacbc81c051445ebe4f8c74fc8892dd3e` | 1 | `f1` |
| `qk_sec1210_wire` | `986b212420e3b977068244e6bd916575bb0c15e5` | 1 | `f2` |
| `qk_sec1210_wire` | `26b27149d109852d7b775d600e0aaffaea0b6249` | 2 | `f201` |
| `qk_sec1210_wire` | `0a80baa1797615faddb0ccfaa6d46382a6b3e0e2` | 1 | `f3` |
| `qk_sec1210_wire` | `9010b855a709ff98c9e491fd6b658415e12ba55c` | 2 | `f301` |
| `qk_sec1210_wire` | `b48f491783e98de10682f2d4455dfce5bdc3c233` | 1 | `f4` |
| `qk_sec1210_wire` | `6cdef40d27f99c0414b096f175ea860d05b4dfbf` | 2 | `f40e` |
| `qk_sec1210_wire` | `e851623533e16393d2e47f5081ec4ef6e33e38bf` | 2 | `f41d` |
| `qk_sec1210_wire` | `c66be7210915f39e91456fc2eac9441012a0a3ea` | 1 | `f5` |
| `qk_sec1210_wire` | `b0d5527a3abfadf66faa2db7df561b44202d8d07` | 2 | `f501` |
| `qk_sec1210_wire` | `2792f0ee8a34e97bf1f60ad9bd978ebb77fd177a` | 2 | `f502` |
| `qk_sec1210_wire` | `8906a863b9e577347fbf04bb6d6af1f7b79c7aef` | 2 | `f503` |
| `qk_sec1210_wire` | `75f75ac5209b4e45f3f4dab7a90a32b04f85a345` | 2 | `f504` |
| `qk_sec1210_wire` | `10bd5732e67ed60b277dbe8eb0be0f3eea6b5dd2` | 2 | `f505` |
| `qk_sec1210_wire` | `1d52acb31495abb2e0ce67ee6f8291a3e2f711f9` | 3 | `f50101` |
| `qk_sec1210_wire` | `426cd5d47be6c58504e3e4a83a4ae46cc48020c4` | 3 | `f50102` |
| `qk_sec1210_wire` | `d3b46e5104773ea73d5ccb5dd8ae3ec66a53974f` | 3 | `f50103` |
| `qk_sec1210_wire` | `4b2d6877636fb4bf4d148d1c11140216e2f79cb5` | 3 | `f50104` |
| `qk_sec1210_wire` | `9b16668f4e16c0e9932661855b7bcb5bad8b0f72` | 1 | `f6` |
| `qk_sec1210_wire` | `3c10bca138644fcd76784dd4f5fc4713c2a7d7eb` | 2 | `f601` |
| `qk_sec1210_wire` | `73b74736664ad85828ce1be2e29fb4a68d24402b` | 1 | `f7` |
| `qk_sec1210_wire` | `0169b5bcd219b137eb1266459ee18004e73babad` | 2 | `f701` |
| `qk_sec1210_wire` | `6abb16b581cbd447cd5ab3af4117b107eac10f9b` | 3 | `f70001` |
| `qk_sec1210_wire` | `1ac3e04ce6bed668aa565efa7a02caf65830351e` | 3 | `000900` |
| `qk_sec1210_wire` | `6c81bb09efa69a4dd376f0ec41bd71ac5e9c8d60` | 3 | `040900` |
| `qk_sec1210_wire` | `c9b29861b1c883fc3dd7e5e7068b0f1cdd5f4d77` | 3 | `050900` |
| `qk_sec1210_wire` | `2aa15f2c6f1666fe85d700a03c203013aa9d6b05` | 5 | `0502010001` |
| `qk_sec1210_wire` | `e1e57fbcedf0ed04a2fad11979c266aa5d54ffa2` | 3 | `0504ff` |
| `qk_sec1210_wire` | `b66c39f99c9c5cae4038b86e7b672073c8749ea8` | 3 | `050306` |
| `qk_sec1210_wire` | `b1e8862fa90c53d366a8b3009e631db298d9ccab` | 4 | `05080801` |
| `qk_t1` | `ea2ad1f4757f997e1611d679919b8a140014ff7a` | 5 | `00e101fe1e` |
| `qk_t1` | `9069ca78e7450a285173431b3e52c5c25299e473` | 4 | `00000000` |
| `qk_t1` | `1bb9f568d66d1ca62e36c1ddf588d7e8f4378438` | 4 | `00400040` |
| `qk_t1` | `43d1b6363769af9504536fd705a787b333150c8d` | 4 | `00200020` |
| `qk_t1` | `871d4633ab51af629c02b4baf1c5497d2dc92bc6` | 4 | `00800080` |
| `qk_t1` | `a6704cf76abf1734f4e597113f79c011f998b8b5` | 4 | `00810081` |
| `qk_t1` | `3e92e278ae235e15ad884e1346d62a47dbb6f356` | 4 | `00c000c0` |
| `qk_t1` | `363eb7bf07a99b9fd708cbf37cf3dce330e74ce9` | 4 | `00c200c2` |
| `qk_t1` | `097cc96792703a4563719ae293b502649c4b9efe` | 5 | `00c30101c3` |
| `qk_t1` | `33fd4e7b1d47f8e095473b2b5f9f1656189ace5e` | 5 | `00c30102c0` |
| `qk_t1` | `e6fb7c481033be9478b8369234028800ba3b78c8` | 5 | `00c30118da` |
| `qk_t1` | `e412706b5526151e60b2381f2aff07e2bb473612` | 5 | `00c30100c2` |
| `qk_t1` | `bb2dd9e835e910073ccf991a1c1cdd178b26aeb9` | 5 | `00c30119db` |
| `qk_t1` | `c1dabe16aa8274daf0618bf60ef35960d53ca621` | 5 | `00c301ff3d` |
| `qk_t1` | `aa387b5ed9268dfd3699d61131056eef463cf7bb` | 5 | `00e30101e3` |
| `qk_t1` | `c229c017a61c497a7c086ad28f8c9de72dfadece` | 4 | `00c300c3` |
| `qk_t1` | `68d048ed096737025b20e54d3a122f460f735ad6` | 5 | `01c30101c2` |
| `qk_t1` | `873b256d201e637d31ebb67e0ab2bb7392ee80a2` | 5 | `00c30101c2` |
| `qk_t1` | `a3d2e23cf89b4eb696b1383072a74494e9ab2f0a` | 4 | `f6000000` |
| `qk_t1` | `29812dafb5ec9261b4a04db63c163a5a43253a9b` | 4 | `f6000101` |
| `qk_t1` | `d2242451a0043da02274c6e04d32303a9fb3f6bb` | 4 | `f6000202` |
| `qk_t1` | `3b2b8b1ba3318a3a3e44111fd7f9ef73d448f200` | 4 | `f6010103` |
| `qk_t1` | `defa848f7d9f96abacc7c3aa3020f4b7df56f6c9` | 4 | `f6010202` |
| `qk_t1` | `3a881fc949f03ca1908280332d75565e1a5cef11` | 4 | `f6010000` |
| `qk_t1` | `6c291883267d5743645d20a66eb6c266dbc456bf` | 4 | `f6010004` |
| `qk_t1` | `b1ac5a6af2d637251edd7c5987b8befced13ff81` | 4 | `f6020000` |
| `qk_t1` | `11c5219a792e2e5294e33962b882ab9337c89cb9` | 4 | `f6020002` |
| `qk_t1` | `3d2c2a3469a5672f82e5a3eef6fecf770a585873` | 4 | `f6020003` |
| `qk_t1` | `4e8c6a6166ed9aa5a19cfc17ddd3ada3a79277fd` | 4 | `f6020100` |
| `qk_t1` | `db4399aab3fa708dc3bea4b539898ecc84b36bec` | 4 | `f6030300` |
| `qk_t1` | `2255c853823123a70fc1b371e0f25bc7e402e26d` | 4 | `f6030500` |
| `qk_t1` | `fa39855ed496e6a0435722668dc4a4472fba5de7` | 4 | `f6030600` |
| `qk_t1` | `aaae456a793ab3222ca42ea7a282923ca1052394` | 4 | `01000107` |
| `qk_t1` | `59634d90a9d8df2e17a09e0a3e839bb81639955c` | 4 | `02000107` |
| `qk_t1` | `6ab75f3a58f8c4696122bc62e5a0a1644c563df8` | 4 | `03000107` |
| `qk_t1` | `7f73cae822dbc65f59e4cb1f8c7061de98c301f1` | 4 | `04000107` |
| `qk_t1` | `675751f8aa4b7d1ca66d96645db4598a1e801393` | 4 | `05000107` |
| `qk_t1` | `3e78105684ffdf8af62b49e174d0e8afe91450c7` | 6 | `0600010700ff` |
| `qk_t1` | `75870d5ae6cc506bcf87eb9983a6f1aa7a9db73a` | 6 | `0600011f0100` |
| `qk_t1` | `ca4cdef5923a705c314028cbd9997963af724f26` | 6 | `070001070001` |
| `qk_t1` | `4aa481c70615617dea90edc828e8fd2f2f1ef0d7` | 4 | `08000007` |
| `qk_t1` | `f8f660af9a116fdd91b8efad44909bfef861610e` | 4 | `09000007` |
| `qk_t1` | `1fb37ed80503c500b4c05158588ffbbd723a2d65` | 4 | `0a000107` |
| `qk_t1` | `f7bebe939f955bc2bf3412944688960489b0fbd6` | 4 | `0b000107` |
| `qk_t1` | `cafba6d7fdc76e7efa28d28d54f82a807e7183d9` | 4 | `0c000107` |
| `qk_t1` | `4211e1095cb2a92c784a72a3dfb5cc9f8a6fbbfd` | 4 | `0d000007` |
| `qk_t1` | `73b74736664ad85828ce1be2e29fb4a68d24402b` | 1 | `f7` |

## Execution and results

Both qualifying runs and all 26 minimization calls used published source
`986ed309f8dcc8725d20ea81550b85e7b65611af` on 2026-09-14. The source
was confirmed on GitHub main before the runs and remained unchanged throughout
qualification. It is the source registered for both promoted corpora.
The platform was macOS 15.7.9, x86_64
(`macOS-15.7.9-x86_64-i386-64bit` in the recorder). Linux-only UART paths
are outside these pure closures and were not exercised.

The measured tool context was cargo-fuzz 0.13.2 and
`rustc 1.100.0-nightly (e7769602a 2026-08-24)`, using the preregistered
nightly-2026-08-25 recipe and limits above. The executed run wrapper SHA-256
was `6e4f8fe48d00ffe36b1dff4f3789d9bc8c25ff65ddaa4a980db5e056e4daea27`;
the unchanged minimization wrapper SHA-256 was
`579455c0eb169a632c581b24c011338f486cbf832d35c89acae1e1cc25e50045`.
Qualification context recording began at 00:45:03.566570Z and completed at
00:53:25.195518Z. These are HOST execution observations, not physical timing
evidence.

| Target | Seed | Start files/bytes | Inputs executed | Exit | Persisted post-run files/bytes | New engine units | Peak RSS MiB | Artifacts |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| `qk_t1` | 167011 | 775 / 27,599 | 100,000 | 0 | 1,121 / 47,534 | 553 | 591 | 0 |
| `qk_sec1210_wire` | 167012 | 378 / 26,192 | 100,000 | 0 | 688 / 52,929 | 669 | 569 | 0 |

T=1 ran from 00:45:05.552502Z to 00:49:18.491397Z; its recorded process wall
time was 252.929089350 seconds. The engine reported 252 seconds, 396 inputs/s,
coverage 3,488, features 12,876 and a live corpus of 938/38Kb. Wire ran from
00:49:20.289671Z to 00:51:07.392129Z; its process wall time was 107.092852251
seconds. The engine reported 106 seconds, 943 inputs/s, coverage 3,002,
features 8,903 and a live corpus of 607/46Kb. Both reported slowest-input
time zero seconds. Live corpus units and engine duration are quoted engine
statistics, not persisted file counts or the separately measured process
wall time. Both wrapper invocations exited zero and produced no artifact.

| Retained run log | Bytes | SHA-256 |
|---|---:|---|
| `run-qk_t1.log` | 73,984 | `d2a2339664da87021ab461cd154546153eca028c4f5efb7f787c8b2d712ae644` |
| `run-qk_sec1210_wire.log` | 90,174 | `b3c78f9a0853dd138db236b4596eb2fa014b14e0335423049271c15e18d371bd` |

| Post-run root | Files/bytes | Listing bytes | Listing SHA-256 | Entries SHA-256 |
|---|---:|---:|---|---|
| `qk_t1` | 1,121 / 47,534 | 76,071 | `0fba2a077209712599901a5b9a2c87f9c919b2d4cba4db0507a3756eb94f5bf6` | `8843b8bd5a8cc0580cf41750e3fe3b5528f800a8a3a1b6c78361c527c3d6f926` |
| `qk_sec1210_wire` | 688 / 52,929 | 46,746 | `154a65b3b780386af0224a955cf365e2769c6a331f192491751aaa59ce11d9f3` | `eb26f7e460321d585450ca10cd11a578fbdc85f98f3333429f3b3294cad30992` |

## Two-copy minimization and promotion

Each exact post-run root was retained and independently copied to A and B.
The existing `fuzz/minimize-corpus.sh TARGET <absolute-copy>` wrapper ran
seven passes on each T=1 copy and six on each wire copy, all at the same
published source. All 26 calls exited zero and produced zero artifacts.
The copies agreed after every corresponding pass, including file names and
bytes, so each A/B row below records the identical measured result of both
independent calls, not one unexecuted inferred copy.

T=1 passes 6 and 7 were unchanged confirmations of pass 5. Wire passes 5 and
6 were unchanged confirmations of pass 4. No copy disagreement occurred.
Per-pass logs, log identities, exits, source bindings, before/after
inventories and retained post-pass roots remain in external evidence.

### qk_t1

| Pass on A and B | Files | Bytes | Listing bytes | Listing SHA-256 | Entries SHA-256 | Unchanged from preceding pass |
|---|---:|---:|---:|---|---|---|
| 1 | 918 | 37012 | 62267 | `5616093271c73e187e4b99a0ed61f5a18ee57be21915655fec347f88bebf1e58` | `289d2d220dc777f8b979d92b265e1cc170d50629819d21cbd1ba2d223491e728` | no |
| 2 | 895 | 36619 | 60713 | `14ab8980740b58628ed7e58809d4a09152331e9ad1c18ed42e7d2924ec26ee1d` | `583554cde5c30da5f2c6727b088a24e68c01e0e0e2a20ee9b8f34af1b7001884` | no |
| 3 | 885 | 36284 | 60038 | `22fcc09b1c2bde41d8e49081d1ad2c819be33f64fa7b991ac9c5a96c3e9a10bd` | `7d89d7137e0e0660f440fc4822db6750d6c7acc3f275fad9c1022bba31c27a2b` | no |
| 4 | 881 | 36089 | 59767 | `a9b5ca382e47bd2a9ea5c0bb0ee6af694cd6dd6cf5aea28f28b6824ff6b1cfe3` | `db1bcfec98b9b62a0829ba4f7c1727cd60f47aba62981cce9dd7ce07e3400e5d` | no |
| 5 | 879 | 36052 | 59631 | `4f62e9d058ceb94eb5a8f385f9d781cb3fd490228f24ee48b58b9ad6a0fbb490` | `2703fa7c4900da3c8d2a6eb8b40ece9b4c3f494cfd47a7a6f6d9632b2114a657` | no |
| 6 | 879 | 36052 | 59631 | `4f62e9d058ceb94eb5a8f385f9d781cb3fd490228f24ee48b58b9ad6a0fbb490` | `2703fa7c4900da3c8d2a6eb8b40ece9b4c3f494cfd47a7a6f6d9632b2114a657` | yes |
| 7 | 879 | 36052 | 59631 | `4f62e9d058ceb94eb5a8f385f9d781cb3fd490228f24ee48b58b9ad6a0fbb490` | `2703fa7c4900da3c8d2a6eb8b40ece9b4c3f494cfd47a7a6f6d9632b2114a657` | yes |

### qk_sec1210_wire

| Pass on A and B | Files | Bytes | Listing bytes | Listing SHA-256 | Entries SHA-256 | Unchanged from preceding pass |
|---|---:|---:|---:|---|---|---|
| 1 | 582 | 44154 | 39524 | `351f4d51b5db9c93d6d1c32cfa0223e0ec4ad37c2e27f650e4585b6679368a5c` | `dbcf51d39b85d9c0a244ab4c4b5c0263e48c9b16bf97976ce812c68fc3946ca6` | no |
| 2 | 570 | 43290 | 38711 | `0a13cf13697e457eb705b391566359296eb66a6cea54e7bdaf49360de06c4d5d` | `debf9049e0cf7d848523d149b93d854bcee7f5a143054f78889cc2dc399ec4d9` | no |
| 3 | 567 | 43268 | 38509 | `b5b10657ded066f9ddbd04afd4499be7dc3905120651520528a615292249de90` | `53bbd7520a04493a2d66ca27d32812b8181a0a66bd72f48c42b0175da486a613` | no |
| 4 | 565 | 43252 | 38374 | `d457d789a42609c98566e0d5699ac72971635662f11d195be611a587bc47a873` | `37e77b5c3de454a819ee1e4acb999be21630e8543d9b1b06f6aef02b4689df92` | no |
| 5 | 565 | 43252 | 38374 | `d457d789a42609c98566e0d5699ac72971635662f11d195be611a587bc47a873` | `37e77b5c3de454a819ee1e4acb999be21630e8543d9b1b06f6aef02b4689df92` | yes |
| 6 | 565 | 43252 | 38374 | `d457d789a42609c98566e0d5699ac72971635662f11d195be611a587bc47a873` | `37e77b5c3de454a819ee1e4acb999be21630e8543d9b1b06f6aef02b4689df92` | yes |

Only the two agreeing fixed points were promoted. The baseline and seeded
starts, exact post-run roots, both independent copy histories, every log and
the execution context remain retained outside Git. The displaced repository
post-run roots were retained rather than deleted. The other 52 registered
roots matched the pre-campaign baseline and remained byte-frozen.

| Promoted target | Files/bytes | Listing bytes | Listing SHA-256 | Entries SHA-256 |
|---|---:|---:|---|---|
| `qk_t1` | 879 / 36,052 | 59,631 | `4f62e9d058ceb94eb5a8f385f9d781cb3fd490228f24ee48b58b9ad6a0fbb490` | `2703fa7c4900da3c8d2a6eb8b40ece9b4c3f494cfd47a7a6f6d9632b2114a657` |
| `qk_sec1210_wire` | 565 / 43,252 | 38,374 | `d457d789a42609c98566e0d5699ac72971635662f11d195be611a587bc47a873` | `37e77b5c3de454a819ee1e4acb999be21630e8543d9b1b06f6aef02b4689df92` |

## Complete registered replay

All 54 registered roots replayed with the existing
`fuzz/replay-corpus.sh TARGET` wrapper, in sorted target order, at published
source `986ed309f8dcc8725d20ea81550b85e7b65611af`. The platform was
macOS 15.7.9 build 24G830, x86_64. Actual registered corpus files total
9,297 / 651,805 bytes; executed engine units total 9,360. Those quantities
are not interchangeable. Every target exited zero and produced zero artifacts.

| Replay | Corpus files | Corpus bytes | Executed units | Exit | Artifacts |
|---|---:|---:|---:|---:|---:|
| `qk_t1` | 879 | 36,052 | 880 | 0 | 0 |
| `qk_sec1210_wire` | 565 | 43,252 | 566 | 0 | 0 |
| All 54 registered targets | 9,297 | 651,805 | 9,360 | all 0 | 0 |

Replay ran on 2026-09-14 from 00:57:02.523274Z to 01:00:16.507466Z;
the replay processes totaled 191.229355797 seconds. All 54 corpus inventories
matched the promoted snapshot before and after, the other 52 matched the
pre-campaign baseline, and source-file fingerprints and HEAD were unchanged
throughout. The replay wrapper SHA-256 was
`f6030a7c1137c2fe2b967ecde68b59ad3cc2667f1c1d7436a08c3ae0fab8738b`.
The retained baseline snapshot SHA-256 is
`b21a5f050f7839cd1173ac73fb08ec411a4cd5d91ca0a3253f12924513785265`;
the promoted snapshot SHA-256 is
`ade66b83c8bf49d7aa308ac3fbdaddcfcf05c3e4d1679dac1ae54ad6fcf076d6`.
Individual stdout/stderr logs and identities, per-target exits and statistics,
source fingerprints and before/after inventories remain in external custody.
No physical sitting, transport operation or Gate claim is part of this pure
qualification.

## Manifest registration

Both existing manifests were rendered at
`986ed309f8dcc8725d20ea81550b85e7b65611af` with their registered renderers;
rendered and installed bytes compare equal. Their campaign_source is that
same published qualification source. Only their two active campaign paths in
`tools/check-fuzz-corpora.sh` move from Campaign 035 to Campaign 036;
historical Campaign 035 evidence and every other registration remain
unchanged.

| Manifest | Bytes | LF | SHA-256 |
|---|---:|---:|---|
| `fuzz/CORPUS-MANIFEST-T1-R2.tsv` | 123,295 | 886 | `d31c0e7fba3c90500d6d5fdec78a0b88e7f3910a1bb070c6eacfea21069df0cc` |
| `fuzz/CORPUS-MANIFEST-SEC1210-R2A.tsv` | 90,756 | 572 | `8d8e71600d792de1a94e1c619f0795c69b056124bc58eb64b69b0421d1ca6538` |
