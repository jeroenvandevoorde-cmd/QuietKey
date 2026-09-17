# Campaign 037 - production SEC1210 transport qualification

Status: PLANNED — NOT EXECUTED.

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

## Completion boundary

Only after both 100,000-input runs complete at the published source, both
independent minimization copies agree, an unchanged confirmation pass succeeds
and every prior corpus replays unchanged may the selected roots be promoted
and `fuzz/CORPUS-MANIFEST-SEC1210-PRODUCTION-V1.tsv` be registered. The
completed Campaign 037 record will replace this planned status with measured
execution, minimization, manifest and replay evidence. Until then, Campaign
037 makes no qualification, artifact-free, production-runtime, device or
physical claim.
