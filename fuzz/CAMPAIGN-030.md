# Card applet slice 1 corpus hygiene campaign 030

Status: EXECUTED — REQUALIFICATION COMPLETE.

## Requalification boundary

This owner-directed run requalified only `qk_card_model` at source
`05c640da25902398c04117ee0cf430f149f7f8e4`. The other 51 registered targets
were replayed but were not fuzzed or minimized. The fixed tool identities were
cargo-fuzz 0.13.2; `nightly-2026-08-25`; rustc
`1.100.0-nightly (e7769602a 2026-08-24)`; AddressSanitizer; release-profile
overflow checks and debug assertions enabled; and offline dependency
resolution.

The exact bounded-run command was:

```text
fuzz/run-bounded.sh qk_card_model 100000
```

It fixed public campaign seed 161002, maximum fuzzer input length 65,536, a
two-second per-input timeout, a 2,048 MiB RSS ceiling, disabled corpus reload,
final statistics, and an empty target artifact directory. It executed exactly
100,000 inputs and exited zero.

## Fixed public committed-state seed

Before the new seed was added, the registered `qk_card_model` fixed point was
56 files/45,446 bytes. Its canonical sorted `SHA-256<TAB>bytes` listing was
3,828 bytes/56 LF with SHA-256
`bf30b0bcff3d6f98b1f8a1ba51fca1842669cf75564ce1aafc3a05aca0c400e6`.
Its manifest entries SHA-256 was
`c5bdfb8a51f74f5f6505758a73b946bddf34916cea4d9a6d937468b39accedcf`.

The new seed uses only the already-registered public fixture
`host/qk-card-protocol/tests/fixtures/card_protocol_v1.txt`, 17,919 bytes,
SHA-256
`5019c642ec61c1042043c0b325658e06d54bbcd3648c2e168b742e9af139bbe4`.
The fixture is marked `PERMANENTLY NEVER-FUND PUBLIC PRIVATE MATERIAL`; this
campaign created no key or signature authority.

The target's fixed public committed-state path constructs a committed model
only by replaying the fixture's nine `setup_*_request_hex` requests. No fuzzer
byte enters that construction or COMMIT. The new 370-byte seed then encodes the
fixture's nine `normal_*_request_hex` requests in fixture order. Each request is
framed as a control byte, a two-byte big-endian request length, and the exact
request bytes. The first control byte is `0x80`, selecting the public
pre-committed start and contact T=1; the remaining eight control bytes are
`0x00`, retaining contact T=1 without reselecting the start.

| Bytes | SHA-1 / corpus filename | SHA-256 | Corpus path |
|---:|---|---|---|
| 370 | `ebfcba758a0f3a3767a699933522d6a08dabcebc` | `2949903952cb66a3b0a5af333316b0438391877eb7caf4f0f140d484e7829bef` | `fuzz/corpus/qk_card_model/ebfcba758a0f3a3767a699933522d6a08dabcebc` |

The bounded run therefore started from 57 files/45,816 bytes. Its canonical
listing was 3,897 bytes/57 LF with SHA-256
`f91841dd18bac66957093388ce0ff90534cd9f2e356b81646a69662f8c4dcfcd`.

## Bounded-run result

| Start files/bytes | Engine seconds; rate/s | Coverage/features | Live corpus reported by libFuzzer | New units | Peak RSS MiB | Persisted post-run files/bytes | Artifacts |
|---:|---:|---:|---:|---:|---:|---:|---:|
| 57/45,816 | 22; 4,545 | 1,180/2,369 | 144/92Kb | 378 | 460 | 180/133,280 | 0 |

The slowest input was reported as zero seconds. The live-corpus byte field
preserves libFuzzer's printed unit; the persisted value is the exact filesystem
count. The post-run canonical listing was 12,382 bytes/180 LF with SHA-256
`3d3105d4681474023a5b5d9062068680d305a05a5cdbb72b290451c2ec4e8f04`.

## Two-copy minimization

Two separately copied post-run roots were each minimized three times. The exact
commands were:

```text
fuzz/minimize-corpus.sh qk_card_model /tmp/qk-hygiene-030.nkeN6p/copy-a
fuzz/minimize-corpus.sh qk_card_model /tmp/qk-hygiene-030.nkeN6p/copy-a
fuzz/minimize-corpus.sh qk_card_model /tmp/qk-hygiene-030.nkeN6p/copy-a
fuzz/minimize-corpus.sh qk_card_model /tmp/qk-hygiene-030.nkeN6p/copy-b
fuzz/minimize-corpus.sh qk_card_model /tmp/qk-hygiene-030.nkeN6p/copy-b
fuzz/minimize-corpus.sh qk_card_model /tmp/qk-hygiene-030.nkeN6p/copy-b
```

Each copy followed the same sequence: 180 files/133,280 bytes -> 134
files/82,873 bytes -> unchanged -> unchanged confirmation. A and B agreed byte
for byte after every pass. All six invocations exited zero and the target
artifact directory remained empty.

The agreed fixed point is 134 files/82,873 bytes. Its canonical listing is
9,198 bytes/134 LF with SHA-256
`f2092594ee4080fed99adebed3507e945c564ebcdd5aca6259492da8c62a8d25`;
its manifest entries SHA-256 is
`df72fd6f414b055430f37fd187726c0d8fde678bc605158aeffbab4c9a39da4e`.
The 370-byte fixed public seed remains present byte for byte.

## Registration and source semantics

Before this hygiene run, `QK-CARD-S1-CORPUS-MANIFEST-V1` was 91,182 bytes/572
LF with SHA-256
`41f8e02e118117331332c350e90ada6790a39832a095e11dcd48ff813ac2081c`.
It bound 562 files/72,038 bytes with aggregate entries SHA-256
`84d734bf7c0a7207c4ed2f83ebab2c8a73a54e2255b7de9ac561dd7449416b68`.
The prior `qk_card_model` identity was the 56-file fixed point recorded above.

The exact render command was:

```text
tools/check-fuzz-corpora.sh --render-card-s1 05c640da25902398c04117ee0cf430f149f7f8e4
```

The rendered manifest remains version `QK-CARD-S1-CORPUS-MANIFEST-V1` and
retains `campaign_source`
`8d2e4ff9443b7b050348c19b0df8229ede17ea9a` for the unchanged
`qk_card_protocol`, `qk_device_wire`, and `qk_core_normal_process` roots. Its
new row
`target_source<TAB>qk_card_model<TAB>05c640da25902398c04117ee0cf430f149f7f8e4`
binds only the replaced `qk_card_model` root to the source that produced it.
The renderer validates both commits and requires the target named by
`target_source` to belong to the partition; normal checking reproduces the
same split-source manifest rather than relabeling the three unchanged roots.
The source-object guard now applies its Git existence and commit-object checks
equally to `campaign_source` and `target_source`. For each label, a valid commit
was accepted while a missing 40-character value, a blob object, and a tree
object were rejected by name: six fail-closed negative probes in total.

The final CARD manifest is 103,487 bytes/651 LF with SHA-256
`1fe74925fb0da15e19946e9c97415fa3d312fbfddfb3d38cbf2f5440c3771461`.
It binds 640 files/109,465 bytes with aggregate entries SHA-256
`80f4e978165f3f78f4381984d1cf1de5e0ec45648eda86e93b57d48e5dcdcff0`.
The other three CARD target counts, byte totals, and entries hashes are
unchanged from Campaign 029.

## Complete retained-corpus replay

The exact replay commands were:

```text
fuzz/replay-corpus.sh qk_card_model
python3 /tmp/qk-hygiene-030.nkeN6p/replay_remaining.py
```

The final `qk_card_model` root replayed 134 files/82,873 bytes, executed 135
units, retained coverage/features 1,180/2,369, added zero units, reached 40 MiB
peak RSS, exited zero, and produced zero artifacts. The other 51 registered
roots contained 7,717 files/489,466 bytes and replayed 7,777 units. All 51
exited zero with zero timeouts, failures, or artifacts. Their complete
before-and-after filename, byte-length, and SHA-256 inventories were
byte-identical at 1,659,319 bytes/38,893 LF and SHA-256
`3a38751575bb95fec96557c165828af9c76afa0946cf5a54632ff14d48079ce6`.

The complete retained set was therefore 52 roots and 7,851 files totaling
572,339 bytes. It executed 7,912 units with zero failures and zero artifacts.
The model's zero-new-unit replay plus the identical 51-root inventories left
every retained corpus at its registered bytes.

The complete canonical filesystem listing contains one line per corpus file,
sorted by path, as `path-with-fuzz/corpus-prefix-removed<TAB>byte-count<TAB>SHA-256<LF>`.
It is 1,007,619 bytes/7,851 LF with SHA-256
`a4a97d30b123474c95a825b10371e54d73ba5a410df8a6892a4fdf0e4f5037a0`.

The workspace test command was:

```text
cargo test --manifest-path host/Cargo.toml --workspace --locked --offline
```

It exited zero. The 197 test binaries reported 1,385 passed tests, zero
failures and no ignored or filtered tests.

The applet-build wrapper regression suite reported 75 passed tests. Its real
wrapper probes imported a module in a clean temporary checkout and found no
`__pycache__`, `.pyc`, or `.pyo` output; both wrappers require `python3 -I -B`,
and removing `-B` from either wrapper is a named build-contract rejection.

## Claim boundary

This was pure HOST evidence. No physical card, converter, CAP, GlobalPlatform,
Java Card, delivered platform, RNG, contactless-enforcement,
performance, production, or Gate claim is made. No process, socket, operating
system descriptor, device, card, or hardware operation occurred. The
test-only `qk-card-model` closure remained absent from every product closure.
