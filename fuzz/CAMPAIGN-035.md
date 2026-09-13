# Campaign 035 - fixed Fi/Di parameters before IFSD-254 readback

Status: PREREGISTRATION - NOT EXECUTED.

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
registrations together. This preregistration reports no execution source,
executed-input count, post-run inventory, result or artifact finding.

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
Repository corpus roots remain unchanged; no qualification run is recorded
by this measurement.

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
