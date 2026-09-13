# Campaign 035 - fixed Fi/Di parameters before IFSD-254 readback

Status: EXECUTED — QUALIFYING RUN COMPLETE.

The recipe, exact seed table and measured starting unions were preregistered
in `a210126d6be075dc3320cdec73d71dfd1b1fddac` before either qualifying run.
The execution and minimization record below is the subsequent qualification
record; statements about the preregistration boundary preserve that earlier
state. The completed registered replay is recorded separately below.

## Boundary and fixed recipe

QK-DEC-167-SUP-010 requalifies only `qk_t1` and `qk_sec1210_wire`.
The other 52 registered corpus roots remain byte-frozen and replay-only.
Inputs are public synthetic wire frames and state-machine programs; no card,
UART, GPIO, bench code, host clock, signing operation or private material enters
either closure. The existing default codec/exchange, T=1 and IFS paths remain
exercised alongside the opt-in fixed SetParameters path. No `qk-t1` production
source changes as part of this qualification.

Both 100,000-input runs and every minimization pass use one published code
commit, recorded afterwards as the qualification source in the completed
record and both final manifests. Until qualification completes, the active
manifests and checker registrations retain Campaign 034 unchanged. The public
seed candidates below are materialized in retained external start copies for
measurement before this preregistration is published; their measured union
identities are registered before either qualifying run. Only subsequently
qualified, independently agreeing fixed points replace the selected roots and
registrations together. At publication, this preregistration reported no
execution source, executed-input count, post-run inventory, result or artifact
finding; those later measurements are recorded below.

| Target | Public seed | Maximum input bytes | Feature, defaults disabled |
|---|---:|---:|---|
| `qk_t1` | 167009 | 8,192 | `t1-readback` |
| `qk_sec1210_wire` | 167010 | 4,096 | `sec1210-wire` |

Pinned tools and limits remain Campaign 034's: cargo-fuzz 0.13.2;
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
copies are minimized with the existing `fuzz/minimize-corpus.sh`; each pass,
exit and identity is recorded. Promotion requires agreeing fixed points and
one unchanged confirmation pass. No unselected root is promoted or modified.
Corpus figures are measured file counts and bytes, not libFuzzer's live-unit
count. All failures and artifacts remain preserved and are not erased by a
later passing run. The completed record names the verification platform and
records actual executed inputs, starting and persisted post-run inventories,
SHA-256 listings and entries, minimization histories, exits and artifacts.
All 54 registered roots are replayed after promotion.

## Measured starting unions

The retained Campaign 034 roots and all exact candidate bytes below were
copied into external start directories before qualification. All 67 candidate
filenames were new: T=1 added 36 files / 849 bytes and wire added 31 files /
605 bytes, with no de-duplication against either baseline. Every filename and
byte count was checked against its candidate bytes. The resulting inventories
below were measured from those external copies, not inferred from sums.
At that measurement, repository corpus roots remained unchanged; no
qualification run is recorded by the starting-union measurement itself.

The canonical listing is sorted `SHA-256<TAB>bytes<LF>`, as in Campaign 034.
Entries are ordered by filename and use the manifest grammar
`corpus<TAB>target<TAB>bytes<TAB>SHA-256<TAB>fuzz/corpus/target/filename<LF>`.
The baseline, external start inventories and exact added-seed records remain
retained outside Git.

| Target | Start files/bytes | Listing bytes | Listing SHA-256 | Entries SHA-256 |
|---|---:|---:|---|---|
| `qk_t1` | 637 / 18,914 | 43,209 | `872340795eeabedef147c3f063fca222260b743327f5ebb2e96d9b3b5c37aa56` | `96e9d02298c1cd0360d7a414c04f282e133e651963ca4bf1047aa4d1a4d8fd83` |
| `qk_sec1210_wire` | 338 / 27,465 | 23,003 | `3d09f56634d2b2cf682995af4d50fe270bc880ade530a45f7d0f8945fc6b985d` | `a9b9c2bb85fc6f6f5cb6b5a43ddf4c071dd0a1463b48e19171926aa787e86c87` |

## Retained prior identities

Campaign 034 and its evidence remain unchanged. Both prior manifests bind
`999ccdf4b2db07e04681e455b4c84495e08a4038`.

| Target | Prior corpus files/bytes | Prior manifest bytes/LF | Manifest SHA-256 | Prior entries SHA-256 |
|---|---:|---:|---|---|
| `qk_t1` | 601 / 18,065 | 84,410 / 608 | `aa6f40832b1adaa3103ae9f9db932b02ee348f35b87fe9ea6f70dd9b3c7c6342` | `d9fa64ffb1fa2c94cf063b1a471cd3df0e851058e4ea54142d67a68dcf8ccf15` |
| `qk_sec1210_wire` | 307 / 26,860 | 49,542 / 314 | `b94983f3497a3574a0bf94c5b015430d96388b6b50318da3f60ccc6ff0b6c124` | `093ee1c346e2d7a0a5b2a692740a334dcb0ec5dee28f17971b7e62096f540e97` |

## Oracle and candidate-seed coverage

Both targets independently place the complete fuzz input at the sequence-4
SetParameters response boundary and also repair the XOR of field mutations to
reach semantic precedence. Their reference payload is a separately written
constant, not imported from the implementation. Reference decoders expose
fields only after bounded framing and XOR validation. Every completed decoded
SetParameters reply is compared as retained diagnostic evidence, including
raw status, bError, protocol and payload when acceptance fails. Acceptance,
observations, request/response counts, phase, sequence and first-failure
retention are compared independently; an evidence reply is not an accepted
response. Common status failures outrank wrong type or payload; wrong length
and protocol keep their names; an otherwise successful nonexact seven-byte
echo gets `Sec1210SetParametersEchoRejected`.

The wire target preserves the default probe and opaque IFS-transfer oracles
and adds the fixed Parameters oracle, fragmented and coalesced events and
replies, exact/short/long/oversize lengths, every parameter-byte mutation,
failed status with bError, time extension, checksum failure, partial frames
and deadline/clock boundaries. The T=1 target retains its default and IFS
models and adds opt-in wire operation programs starting before activation,
before SetParameters and after its acceptance. These cover premature IFS,
partial writes, repeated/late SetParameters, diagnostics and sticky failures.
Its third joint path accepts fixed parameters, performs IFS at sequence 5,
then exercises up to eight synthetic APDUs with persistent sequence bits,
valid chaining, fragmented CCID responses and hostile T=1 continuations.

The table specifies 31 wire candidates / 605 bytes and 36 T=1 candidates /
849 bytes before de-duplication against retained roots. No starting-union
count is inferred by addition. Filenames are SHA-1 of bytes solely for
libFuzzer naming; evidence identities use SHA-256. Every candidate is supplied
in full to the pending-SetParameters response path, while
the state programs additionally drive the independent operation oracle.
The initialization program consists of four-byte operations: 0 begins the
next initialization command, 2 records its exact write, and 3 supplies the
independent expected reply; after four such triples, operation 1 claims the
IFS transfer. Starting the same program from multiple registered phases also
tests premature and repeated operations. The table registers intended
coverage, not execution results. Baselines and candidates are retained
independently before qualification or promotion.

| Target | Filename | Bytes | Hex |
|---|---|---:|---|
| `qk_sec1210_wire` | `f7b9e047f4b901a719a2a2d07a807640169fb851` | 20 | `0306610700000000040100001810ff4d00fe0022` |
| `qk_sec1210_wire` | `7416f9fc26fdfe90c2331c5849d8ba956a602762` | 20 | `0306820700000000040000011810ff4d00fe00c1` |
| `qk_sec1210_wire` | `dba62ee379ffbdab4f2b48cabebb207f22651b5a` | 18 | `03066f05000000000500000000c101fe3e6a` |
| `qk_sec1210_wire` | `6f300e07e86c85cf7ba3ea8deaacfd24470d9645` | 18 | `03068005000000000500000000e101fe1e85` |
| `qk_sec1210_wire` | `c3e25bb312ac592c6504909344b2fee68fae8129` | 20 | `0306820700000000040000011910ff4d00fe00c0` |
| `qk_sec1210_wire` | `9dc312f00eacd811b43185c8543b0b5ae18eb9ce` | 20 | `0306820700000000040000011811ff4d00fe00c0` |
| `qk_sec1210_wire` | `a126f2c070da5ac094196b407478b8038eb81fed` | 20 | `0306820700000000040000011810fe4d00fe00c0` |
| `qk_sec1210_wire` | `e615472b3407a233f17f3baa175a299e4cb12769` | 20 | `0306820700000000040000011810ff4c00fe00c0` |
| `qk_sec1210_wire` | `739def69db148c696e31f5723af02a060e550b0b` | 20 | `0306820700000000040000011810ff4d01fe00c0` |
| `qk_sec1210_wire` | `e2882354a8542a49514b3789af8e739091c7aa8d` | 20 | `0306820700000000040000011810ff4d00ff00c0` |
| `qk_sec1210_wire` | `0dec676d811f815d36e1a1470a377420a84fa105` | 20 | `0306820700000000040000011810ff4d00fe01c0` |
| `qk_sec1210_wire` | `483be17df2351138aac35b2697eec9817aad3d4b` | 13 | `03068200000000000400000182` |
| `qk_sec1210_wire` | `0a5137c58dc3c0f52a21d9ef39c311f6ecf61d68` | 19 | `0306820600000000040000011810ff4d00fec0` |
| `qk_sec1210_wire` | `50c663782780373c9dd74ff85419de26f06211ea` | 21 | `0306820800000000040000011810ff4d00fe0000ce` |
| `qk_sec1210_wire` | `d0fff2e50cfd378d1d2c0ad1960739f030ac4edd` | 20 | `0306820700000000040000001810ff4d00fe00c0` |
| `qk_sec1210_wire` | `eced005580721c1d7e315e004f7926665834491e` | 20 | `0306800700000000040000011810ff4d00fe00c3` |
| `qk_sec1210_wire` | `61efee63bf272c5382ab65fa956aacde4eab5a74` | 20 | `0306820700000001040000011810ff4d00fe00c0` |
| `qk_sec1210_wire` | `e108fd8f42fbe858665cd666f554a9724cc01055` | 20 | `0306820700000000050000011810ff4d00fe00c0` |
| `qk_sec1210_wire` | `74f88fb47269dc136f3bc2eb339fd5a42f5c01af` | 20 | `0306820700000000040400011810ff4d00fe00c5` |
| `qk_sec1210_wire` | `e94c752f4400619f51a2cf4662b101ebb8d88950` | 20 | `0306820700000000040100011810ff4d00fe00c0` |
| `qk_sec1210_wire` | `c9a2de688e6de492cfe441a12dc82a6ec08e743b` | 20 | `0306820700000000040200011810ff4d00fe00c3` |
| `qk_sec1210_wire` | `bb2088d16d34263b7abbcc49738c53e8d50a9b76` | 20 | `030682070000000004000c011810ff4d00fe00cd` |
| `qk_sec1210_wire` | `4377cd343dc28352768766ba11119f51d5e1fc77` | 13 | `030682000000000004400c01ce` |
| `qk_sec1210_wire` | `4a9c64d26780d0285f193513e02f2ab184ef41d9` | 20 | `030682070000000004400c011110ff4d00fe0084` |
| `qk_sec1210_wire` | `d5b06624d580c9d3d8e8a803746c7bdbea59f1a2` | 13 | `03068100000000000480ff01fe` |
| `qk_sec1210_wire` | `573ae93175871692fe91dd082540cb7885f797cc` | 20 | `0306820700000000040000011810ff4d00fe00c0` |
| `qk_sec1210_wire` | `65ae0a3649c9a65e6bdb60c166f8886c936998ab` | 22 | `500f0306820700000000040000011810ff4d00fe00c1` |
| `qk_sec1210_wire` | `62dfbf3972ad94c36991871e303fac41ea049425` | 22 | `0306820700000000040000011810ff4d00fe00c15003` |
| `qk_sec1210_wire` | `0dc7b8c7dabf835fe7b437e2558623ced9083966` | 40 | `0306820700000000040000011810ff4d00fe00c10306820700000000040000011810ff4d00fe00c1` |
| `qk_sec1210_wire` | `c66978c07f1321021be642bdcf09223f812550ec` | 19 | `0306820700000000040000011810ff4d00fe00` |
| `qk_sec1210_wire` | `7405c1043e4dd92ef1790f3fd5fbe26926160019` | 7 | `03068206010000` |
| `qk_t1` | `f7b9e047f4b901a719a2a2d07a807640169fb851` | 20 | `0306610700000000040100001810ff4d00fe0022` |
| `qk_t1` | `7416f9fc26fdfe90c2331c5849d8ba956a602762` | 20 | `0306820700000000040000011810ff4d00fe00c1` |
| `qk_t1` | `dba62ee379ffbdab4f2b48cabebb207f22651b5a` | 18 | `03066f05000000000500000000c101fe3e6a` |
| `qk_t1` | `6f300e07e86c85cf7ba3ea8deaacfd24470d9645` | 18 | `03068005000000000500000000e101fe1e85` |
| `qk_t1` | `c3e25bb312ac592c6504909344b2fee68fae8129` | 20 | `0306820700000000040000011910ff4d00fe00c0` |
| `qk_t1` | `9dc312f00eacd811b43185c8543b0b5ae18eb9ce` | 20 | `0306820700000000040000011811ff4d00fe00c0` |
| `qk_t1` | `a126f2c070da5ac094196b407478b8038eb81fed` | 20 | `0306820700000000040000011810fe4d00fe00c0` |
| `qk_t1` | `e615472b3407a233f17f3baa175a299e4cb12769` | 20 | `0306820700000000040000011810ff4c00fe00c0` |
| `qk_t1` | `739def69db148c696e31f5723af02a060e550b0b` | 20 | `0306820700000000040000011810ff4d01fe00c0` |
| `qk_t1` | `e2882354a8542a49514b3789af8e739091c7aa8d` | 20 | `0306820700000000040000011810ff4d00ff00c0` |
| `qk_t1` | `0dec676d811f815d36e1a1470a377420a84fa105` | 20 | `0306820700000000040000011810ff4d00fe01c0` |
| `qk_t1` | `483be17df2351138aac35b2697eec9817aad3d4b` | 13 | `03068200000000000400000182` |
| `qk_t1` | `0a5137c58dc3c0f52a21d9ef39c311f6ecf61d68` | 19 | `0306820600000000040000011810ff4d00fec0` |
| `qk_t1` | `50c663782780373c9dd74ff85419de26f06211ea` | 21 | `0306820800000000040000011810ff4d00fe0000ce` |
| `qk_t1` | `d0fff2e50cfd378d1d2c0ad1960739f030ac4edd` | 20 | `0306820700000000040000001810ff4d00fe00c0` |
| `qk_t1` | `eced005580721c1d7e315e004f7926665834491e` | 20 | `0306800700000000040000011810ff4d00fe00c3` |
| `qk_t1` | `61efee63bf272c5382ab65fa956aacde4eab5a74` | 20 | `0306820700000001040000011810ff4d00fe00c0` |
| `qk_t1` | `e108fd8f42fbe858665cd666f554a9724cc01055` | 20 | `0306820700000000050000011810ff4d00fe00c0` |
| `qk_t1` | `74f88fb47269dc136f3bc2eb339fd5a42f5c01af` | 20 | `0306820700000000040400011810ff4d00fe00c5` |
| `qk_t1` | `e94c752f4400619f51a2cf4662b101ebb8d88950` | 20 | `0306820700000000040100011810ff4d00fe00c0` |
| `qk_t1` | `c9a2de688e6de492cfe441a12dc82a6ec08e743b` | 20 | `0306820700000000040200011810ff4d00fe00c3` |
| `qk_t1` | `bb2088d16d34263b7abbcc49738c53e8d50a9b76` | 20 | `030682070000000004000c011810ff4d00fe00cd` |
| `qk_t1` | `4377cd343dc28352768766ba11119f51d5e1fc77` | 13 | `030682000000000004400c01ce` |
| `qk_t1` | `4a9c64d26780d0285f193513e02f2ab184ef41d9` | 20 | `030682070000000004400c011110ff4d00fe0084` |
| `qk_t1` | `d5b06624d580c9d3d8e8a803746c7bdbea59f1a2` | 13 | `03068100000000000480ff01fe` |
| `qk_t1` | `573ae93175871692fe91dd082540cb7885f797cc` | 20 | `0306820700000000040000011810ff4d00fe00c0` |
| `qk_t1` | `65ae0a3649c9a65e6bdb60c166f8886c936998ab` | 22 | `500f0306820700000000040000011810ff4d00fe00c1` |
| `qk_t1` | `62dfbf3972ad94c36991871e303fac41ea049425` | 22 | `0306820700000000040000011810ff4d00fe00c15003` |
| `qk_t1` | `0dc7b8c7dabf835fe7b437e2558623ced9083966` | 40 | `0306820700000000040000011810ff4d00fe00c10306820700000000040000011810ff4d00fe00c1` |
| `qk_t1` | `c66978c07f1321021be642bdcf09223f812550ec` | 19 | `0306820700000000040000011810ff4d00fe00` |
| `qk_t1` | `7405c1043e4dd92ef1790f3fd5fbe26926160019` | 7 | `03068206010000` |
| `qk_t1` | `74c01b48c0bffc252f2d9da55011598a7b747491` | 60 | `000000000200000003000000000000000200000003000000000000000200000003000000000000000200000003000000010000000200000003000000` |
| `qk_t1` | `e202ec73c44a88ced467be9a6d21f548c59bd2dc` | 40 | `00000000020000000300000000000000020000000300000000000000020000000300000001000000` |
| `qk_t1` | `2d77b2b80cf5870008e75aefe4a5db4bcf34dcd3` | 52 | `00000000020000000300000000000000020000000300000000000000020000000300000000000000020000000300000000000000` |
| `qk_t1` | `e90a2f17b418d3e81b062f7c5f2c4d6d331c9511` | 44 | `0000000002000000030000000000000002000000030000000000000002000000030000000000000002010000` |
| `qk_t1` | `b182c94d998229c58104032ecc27e04bf8d36c1b` | 48 | `000000000200000003000000000000000200000003000000000000000200000003000000000000000200000006030000` |

## Execution and results

Both qualifying runs and all 34 minimization calls used published source
`a210126d6be075dc3320cdec73d71dfd1b1fddac` on 2026-09-13. The source
was confirmed on GitHub main before the runs and remained unchanged throughout
qualification. It is the source registered for both promoted corpora.
The platform was macOS 15.7.9, x86_64
(`macOS-15.7.9-x86_64-i386-64bit` in the recorder). Linux-only UART paths
are outside these pure closures and were not exercised.

The measured tool context was cargo-fuzz 0.13.2 and
`rustc 1.100.0-nightly (e7769602a 2026-08-24)`, using the preregistered
nightly-2026-08-25 recipe and limits above. The executed run wrapper SHA-256
was `b90611d17542c9e9a03dd62bed0b64aa5dd9fb36880ef7204a7ef58e39d87d44`;
the unchanged minimization wrapper SHA-256 was
`579455c0eb169a632c581b24c011338f486cbf832d35c89acae1e1cc25e50045`.
Qualification context recording began at 15:53:07.013575Z and completed at
15:59:58.613685Z. These are HOST execution observations, not physical timing
evidence.

| Target | Seed | Start files/bytes | Inputs executed | Exit | Persisted post-run files/bytes | New engine units | Peak RSS MiB | Artifacts |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| `qk_t1` | 167009 | 637 / 18,914 | 100,000 | 0 | 1,054 / 42,605 | 677 | 594 | 0 |
| `qk_sec1210_wire` | 167010 | 338 / 27,465 | 100,000 | 0 | 485 / 38,249 | 322 | 478 | 0 |

T=1 ran from 15:53:08.678358Z to 15:57:10.234381Z; its recorded process wall
time was 241.478856026 seconds. The engine reported 240 seconds, 416 inputs/s,
coverage 2,191, features 8,971 and a live corpus of 844/32Kb. Wire ran from
15:57:11.874178Z to 15:57:43.821058Z; its process wall time was 31.939619238
seconds. The engine reported 31 seconds, 3,225 inputs/s, coverage 1,445,
features 3,871 and a live corpus of 370/26Kb. Both reported slowest-input
time zero seconds. Live corpus units and engine duration are quoted engine
statistics, not persisted file counts or the separately measured process
wall time. Both wrapper invocations exited zero and produced no artifact.

| Retained run log | Bytes | SHA-256 |
|---|---:|---|
| `run-qk_t1.log` | 92,223 | `a5aec30349aa2aa40462e5ef39f34d4924f7923ab8876c0d3dfe2a91043424a0` |
| `run-qk_sec1210_wire.log` | 44,019 | `8a62a1de2e1b390c8e91b7c7fe3f936a70a85bd0a4d0a81041a2dbfc6867e904` |

| Post-run root | Files/bytes | Listing bytes | Listing SHA-256 | Entries SHA-256 |
|---|---:|---:|---|---|
| `qk_t1` | 1,054 / 42,605 | 71,601 | `18d6222eeaab2dd9165c5c670428757a39448809bb834c9c147cf2276c84cdfd` | `6408d14e530269097139719a02a01564e27b73abaeeff7844669bf63c6dc885e` |
| `qk_sec1210_wire` | 485 / 38,249 | 33,013 | `04bd3d36c04ae890a025db0e70a8ccfae28b472756e067bcc543261d36e39c82` | `3dd9a2f85b561d7941a72a9e3a88f3fd817b8d76db7f3f6763fdd7c5eb11728b` |

## Two-copy minimization and promotion

Each exact post-run root was retained and independently copied to A and B.
The existing `fuzz/minimize-corpus.sh TARGET <absolute-copy>` wrapper ran
nine passes on each T=1 copy and eight on each wire copy, all at the same
published source. All 34 calls exited zero and produced zero artifacts.
The copies agreed after every corresponding pass, including file names and
bytes, so each A/B row below records the identical measured result of both
independent calls, not one unexecuted inferred copy.

T=1 passes 8 and 9 were unchanged confirmations of pass 7. Wire passes 7 and
8 were unchanged confirmations of pass 6. No copy disagreement occurred.
Per-pass logs, log identities, exits, source bindings, before/after
inventories and retained post-pass roots remain in external evidence.

### qk_t1

| Pass on A and B | Files | Bytes | Listing bytes | Listing SHA-256 | Entries SHA-256 | Unchanged from preceding pass |
|---|---:|---:|---:|---|---|---|
| 1 | 772 | 28282 | 52395 | `ae924b72d48001593db917e9bdefd4dd9abed4377ce4176c16b8dad2c28a8723` | `4fe9b29f1988650ae7ba7f301444f2a885279c6fd0c9a3e1a7c2507518397aef` | no |
| 2 | 748 | 27611 | 50763 | `b60fe4426aa41e8c00932198c51399083566fb63827e1ee0b9baa78819a68950` | `87346051f505fbef95d7911f3c43048b1e286ba869dedc9bf7e49c433417c15b` | no |
| 3 | 741 | 27506 | 50290 | `92aada4a6658513093cb69e60b0d1af90c5ff4a8fb26854434ac5a5f7de3826a` | `26dd471adf3188e44a7e68e1847763042244f38af238c1b5ac33ddf60c505698` | no |
| 4 | 736 | 27453 | 49953 | `f9179e9c85fa6e99f6ec1adb989c3f177fa7babce665ee01c63a05c1d50493f0` | `422eb33be5cd12f8866ebed5f514181d886207e3729cf7357693e960fb938a05` | no |
| 5 | 735 | 27447 | 49886 | `deececa812f8873efc22d7537d0d7975132c42b003f9d8a77343b5eb8f377df5` | `4f2cb1926d958295c49919d1ed32e089ab67439173e14a9c0ecd51f03cf2baf2` | no |
| 6 | 734 | 27436 | 49818 | `251505aa6163f5537321d01862d9fc7f35c43e44d9299a5c8265c1fff6db93ce` | `d2656555246582bee6a4c7db03efa0dd46ed6a6b5c380f80751d93db11986fef` | no |
| 7 | 733 | 27420 | 49750 | `3627952c9c37e057dcffbaec3eb48a791325c0c19a53874343f7121c6a76820b` | `2644609fd42b16717a0bb3a089a75a5bab940354284b07fa4d230834eaeeb672` | no |
| 8 | 733 | 27420 | 49750 | `3627952c9c37e057dcffbaec3eb48a791325c0c19a53874343f7121c6a76820b` | `2644609fd42b16717a0bb3a089a75a5bab940354284b07fa4d230834eaeeb672` | yes |
| 9 | 733 | 27420 | 49750 | `3627952c9c37e057dcffbaec3eb48a791325c0c19a53874343f7121c6a76820b` | `2644609fd42b16717a0bb3a089a75a5bab940354284b07fa4d230834eaeeb672` | yes |

### qk_sec1210_wire

| Pass on A and B | Files | Bytes | Listing bytes | Listing SHA-256 | Entries SHA-256 | Unchanged from preceding pass |
|---|---:|---:|---:|---|---|---|
| 1 | 358 | 26338 | 24341 | `f4c697def197031cca8c58a13b49bafa1268b25fa2bd577398f219e159b7c1a8` | `67632baed11870c56f3cf25015fe7f37fd7f27db590b40db5feea150b8044cb0` | no |
| 2 | 353 | 26180 | 24003 | `0d5f30b4b9e5f38164f86661035adc8e2803a72458b2e9544e7c6e1184720b14` | `ed3dcd844d4f58cf5e310fdb44306aeca9920fb21361e0e289476d7f6f438aad` | no |
| 3 | 352 | 26171 | 23936 | `bc5501c5f1cadc6783e8360fd657fcef7694eb7354983e2dddb2b6853d5b3244` | `5c487d9c11f83d61daa67117d4f78a12622b6b8ae4f11cb91ada0b0438317106` | no |
| 4 | 351 | 26166 | 23869 | `5c578326d4dc6db098f1e69850b350d0933c0b814d52b5e390cc5e723f63f01d` | `e8a8822b13f55379ac9eb2e08e6f36d38a5ec8040bed0b54b68008c0a0f0ecc2` | no |
| 5 | 350 | 26156 | 23801 | `93f13a3991d945cc1e18081f797528a471707012bab8590ec78c30bd9a1b9543` | `d5aec3aaf325addd6ae6321a2ffee7404249cfd018f82d7f8ee96391ebb7f54f` | no |
| 6 | 347 | 26123 | 23598 | `b91c0f6780b7e1fc5b05e66daf5a474862d4b6eb2758368717b9caf8b62c9424` | `4af91fa4801a76ec7dba7c11ea2b9ff72ae49687a221d0cc37338eaa72d41d94` | no |
| 7 | 347 | 26123 | 23598 | `b91c0f6780b7e1fc5b05e66daf5a474862d4b6eb2758368717b9caf8b62c9424` | `4af91fa4801a76ec7dba7c11ea2b9ff72ae49687a221d0cc37338eaa72d41d94` | yes |
| 8 | 347 | 26123 | 23598 | `b91c0f6780b7e1fc5b05e66daf5a474862d4b6eb2758368717b9caf8b62c9424` | `4af91fa4801a76ec7dba7c11ea2b9ff72ae49687a221d0cc37338eaa72d41d94` | yes |

Only the two agreeing fixed points were promoted. The baseline and seeded
starts, exact post-run roots, both independent copy histories, every log and
the execution context remain retained outside Git. The displaced repository
post-run roots were retained rather than deleted. The other 52 registered
roots matched the pre-campaign baseline and remained byte-frozen.

| Promoted target | Files/bytes | Listing bytes | Listing SHA-256 | Entries SHA-256 |
|---|---:|---:|---|---|
| `qk_t1` | 733 / 27,420 | 49,750 | `3627952c9c37e057dcffbaec3eb48a791325c0c19a53874343f7121c6a76820b` | `2644609fd42b16717a0bb3a089a75a5bab940354284b07fa4d230834eaeeb672` |
| `qk_sec1210_wire` | 347 / 26,123 | 23,598 | `b91c0f6780b7e1fc5b05e66daf5a474862d4b6eb2758368717b9caf8b62c9424` | `4af91fa4801a76ec7dba7c11ea2b9ff72ae49687a221d0cc37338eaa72d41d94` |

## Complete registered replay

All 54 registered roots replayed with the existing
`fuzz/replay-corpus.sh TARGET` wrapper, in sorted target order, at published
source `a210126d6be075dc3320cdec73d71dfd1b1fddac`. The platform was
macOS 15.7.9 build 24G830, x86_64. Actual registered corpus files total
8,933 / 626,044 bytes; executed engine units total 8,996. Those quantities
are not interchangeable. Every target exited zero and produced zero artifacts.

| Replay | Corpus files | Corpus bytes | Executed units | Exit | Artifacts |
|---|---:|---:|---:|---:|---:|
| `qk_t1` | 733 | 27,420 | 734 | 0 | 0 |
| `qk_sec1210_wire` | 347 | 26,123 | 348 | 0 | 0 |
| All 54 registered targets | 8,933 | 626,044 | 8,996 | all 0 | 0 |

Replay ran on 2026-09-13 from 16:00:13.536589Z to 16:03:26.110104Z;
the replay processes totaled 189.975980492 seconds. All 54 corpus inventories
matched the promoted snapshot before and after, the other 52 matched the
pre-campaign baseline, and source-file fingerprints and HEAD were unchanged
throughout. The replay wrapper SHA-256 was
`4722543ff936598e2904478eb5950996d3f46550cfe5021f00b9140063028413`.
The retained baseline snapshot SHA-256 is
`36646c72ea88c6b8daca5eef442612055001a0d087e3f3cc69620a27f17ec3f4`;
the promoted snapshot SHA-256 is
`b21a5f050f7839cd1173ac73fb08ec411a4cd5d91ca0a3253f12924513785265`.
Individual stdout/stderr logs and identities, per-target exits and statistics,
source fingerprints and before/after inventories remain in external custody.
No physical sitting, transport operation or Gate claim is part of this pure
qualification.

## Manifest registration

Both existing manifests were rendered at
`a210126d6be075dc3320cdec73d71dfd1b1fddac` with their registered renderers;
rendered and installed bytes compare equal. Their campaign_source is that
same published qualification source. Only their two active campaign paths in
`tools/check-fuzz-corpora.sh` move from Campaign 034 to Campaign 035; historical
Campaign 034 evidence and every other registration remain unchanged.

| Manifest | Bytes | LF | SHA-256 |
|---|---:|---:|---|
| `fuzz/CORPUS-MANIFEST-T1-R2.tsv` | 102,902 | 740 | `e54700c7768d4bddcd31f4a56c0c4b8a9114cbd45c3694dbbf88656e6fb24e6d` |
| `fuzz/CORPUS-MANIFEST-SEC1210-R2A.tsv` | 55,924 | 354 | `129bfcf1b5f5f583c6ab90322d54c10b62fe33d62a99cb8ef911a8a3e48782ca` |
