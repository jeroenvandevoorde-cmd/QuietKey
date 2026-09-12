# Campaign 033 — bounded T=1 and SEC1210 readback

Status: EXECUTED — QUALIFYING RUN COMPLETE.

## Qualification boundary

This QK-DEC-167-SUP-003 campaign qualified the new joint pure `qk_t1`
target and requalified the existing `qk_sec1210_wire` target because its
selected crate closure changed. Both qualifying runs and all 22 minimization
calls used published source
`8664809b7968d63c5f227492e7aa2984a3b1c604`. The other 52 registered corpus
roots were replay-only and remained byte-frozen.

The fixed tool identities were cargo-fuzz 0.13.2;
`nightly-2026-08-25`; rustc `1.100.0-nightly (e7769602a 2026-08-24)`;
AddressSanitizer; release-profile overflow checks and debug assertions enabled;
and offline dependency resolution. The runs were made on macOS 15.7.9,
Darwin 24.6.0, x86_64. Linux-only UART code is outside both fuzz closures and
was not exercised by this campaign.

The joint target selected only the nondefault `t1-readback` feature with
default features off. Its complete product-code closure is the dependency-free
`qk-t1` and `qk-sec1210-wire` crates. The requalified target retained its
unchanged `sec1210-wire` feature and sole `qk-sec1210-wire` dependency. The
UART adapter, processes, wall clocks, GPIO, cards and bench tool were outside
both closures. The exact commands were:

```text
fuzz/run-bounded.sh qk_t1 100000
fuzz/run-bounded.sh qk_sec1210_wire 100000
```

The commands pinned public seeds 167003 and 167001 and maximum input lengths
8,192 and 4,096 respectively. Both used a two-second per-input timeout, a
2,048 MiB RSS ceiling, disabled corpus reload, final statistics and an empty
target artifact directory.

## Starting points and bounded-run results

The preregistered `qk_t1` starting corpus contained two files / 28 bytes. Its
canonical sorted `SHA-256<TAB>bytes<LF>` listing was 136 bytes / two LF with
SHA-256
`0eefd30ea23f7cc5e44f82d27231085cfcc2971d1c280337df628faab66b7980`;
its manifest entries SHA-256 was
`3276696359db695227aeaefb9406cd79dfefe9186332ee7fc3fab1f882d03de8`.
The retained SEC1210 root began at Campaign 032's registered 229 files /
12,921 bytes. Its canonical listing was 15,557 bytes / 229 LF with SHA-256
`e1729b983283f027516fdd35f093a1ae74fafc0c0237586793b98849351d32e8`,
and its manifest entries SHA-256 was
`2a5950de303437a3cdfd45b143862575980ca9bb766a9279000b7513874f611b`.

| Target | Start files/bytes | Engine seconds; rate/s | Coverage/features | Live corpus reported by libFuzzer | New units | Peak RSS MiB | Persisted post-run files/bytes | Artifacts |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| `qk_t1` | 2/28 | 48; 2,083 | 1,656/6,261 | 632/13,066b | 1,030 | 563 | 630/13,059 | 0 |
| `qk_sec1210_wire` | 229/12,921 | 10; 10,000 | 704/2,499 | 291/26Kb | 206 | 461 | 376/31,652 | 0 |

Each command executed exactly 100,000 inputs and exited zero. Both reported a
slowest input of zero seconds. The live-corpus fields preserve libFuzzer's
printed values; the persisted values are exact filesystem measurements. The
T=1 post-run canonical listing was 42,707 bytes / 630 LF with SHA-256
`89535b33fa9791bbfd32bceac0e5a09a55b4badcf25f7a3e7f99d82ec6d4fad0`.
The SEC1210 post-run listing was 25,598 bytes / 376 LF with SHA-256
`d1b1ff60998c271172d504d6ad91dafed41c1cb927906ea05316030d4b5c8b9a`.
No finding, timeout or artifact occurred.

## Two-copy minimization

Each exact post-run root was copied independently twice. Every pass ran the
corresponding command below once on each copy and exited zero:

```text
fuzz/minimize-corpus.sh qk_t1 <absolute-copy>
fuzz/minimize-corpus.sh qk_sec1210_wire <absolute-copy>
```

The copies agreed byte for byte after every pass. T=1 pass eight and SEC1210
pass three were unchanged confirmations of the preceding fixed points.

| T=1 stage | Files | Bytes | Canonical listing bytes | Canonical listing SHA-256 |
|---|---:|---:|---:|---|
| Post-run copy | 630 | 13,059 | 42,707 | `89535b33fa9791bbfd32bceac0e5a09a55b4badcf25f7a3e7f99d82ec6d4fad0` |
| Pass 1 | 495 | 10,445 | 33,547 | `30109d41d90589025d29352f0bd8c455a8707e196103b7bda11869ac2ed2270b` |
| Pass 2 | 473 | 10,007 | 32,055 | `8c69ffe0f657108075ff6685eae0f00ef0298ba96d43a40c283041a5069e9e83` |
| Pass 3 | 467 | 9,928 | 31,648 | `7d81920b2798b8c9de511db73b12ef4204f5527473eea52a115a9736adaccd26` |
| Pass 4 | 461 | 9,868 | 31,243 | `2b83f29476f0a8b7fd76b1639915d9b613afbed52b4ecb221f77c71afe3d54f7` |
| Pass 5 | 456 | 9,805 | 30,904 | `951f3d222043ea99851ae2a783f95165712a69e1dd233fef10db448ca19b1683` |
| Pass 6 | 452 | 9,753 | 30,633 | `e2d0f79648794ad1b4148d15f2d60c3e559566970415e7bc7b5bb5493d831725` |
| Pass 7 | 449 | 9,626 | 30,429 | `2a607d7ce06dd45b370d37b3b126459599ba1f39a62b38e2dde0d0b3f2074f2c` |
| Pass 8 | 449 | 9,626 | 30,429 | `2a607d7ce06dd45b370d37b3b126459599ba1f39a62b38e2dde0d0b3f2074f2c` |

| SEC1210 stage | Files | Bytes | Canonical listing bytes | Canonical listing SHA-256 |
|---|---:|---:|---:|---|
| Post-run copy | 376 | 31,652 | 25,598 | `d1b1ff60998c271172d504d6ad91dafed41c1cb927906ea05316030d4b5c8b9a` |
| Pass 1 | 287 | 25,939 | 19,539 | `8e89ec8d0440805c4aac59dfe50c5c26c8eff26048500ce44ec9448729f36a67` |
| Pass 2 | 283 | 25,884 | 19,269 | `0b75da8e94ede451ece21fe24586431258cde82904c535d450e0a2be092a2779` |
| Pass 3 | 283 | 25,884 | 19,269 | `0b75da8e94ede451ece21fe24586431258cde82904c535d450e0a2be092a2779` |

All 22 minimization calls passed, both target artifact directories stayed
empty and only the two selected roots were promoted. Initial roots, exact
post-run roots and both minimized-copy histories remain retained outside Git.

The promoted T=1 fixed point's manifest entries SHA-256 is
`106558d28ca7402958fa0cd09a9b9ec5f267b17b904ae9568ab292f29aa04b97`.
`fuzz/CORPUS-MANIFEST-T1-R2.tsv` is 63,131 bytes, 456 LF, SHA-256
`6ab48898389737cb95af244a631dda12e63a4e72f0066235aada8625791c1e24`.
The promoted SEC1210 fixed point's entries SHA-256 is
`2e2d17e146946d08c2b1007e807159ee521a91b17de09f7cdc01ea21230ae6fc`.
The re-rendered `fuzz/CORPUS-MANIFEST-SEC1210-R2A.tsv` is 45,707 bytes,
290 LF, SHA-256
`749cd341d7833f27e227cfa1aae620d453736516bda14610d18cf4493c259cc1`.
Both manifests bind the same published campaign source.

## Complete retained-corpus replay

All 54 registered roots replayed under the pinned toolchain. They contained
8,585 files totaling 608,011 bytes and executed 8,648 units. Every root exited
zero, every replay reported zero new units, and there were zero failures,
timeouts, findings or artifacts.

Before and after the replay, the 52 roots outside this campaign contained
7,853 files totaling 572,501 bytes. Their complete sorted
`path<TAB>byte-count<TAB>SHA-256<LF>` inventory was 1,102,119 bytes / 7,853 LF
with SHA-256
`f0dcd00b9431131070e3d7cacb9b139ec124ea196a0a92f4c5486194104fe2da`.
The complete 54-root inventory in that format is 1,197,835 bytes / 8,585 LF
with SHA-256
`b82866329c1ed126ab74304d7777d63b652e3278386e5e200b444f2a18daca01`.

## Claim boundary

This is pure HOST evidence. The joint target compares independently expressed
T=1 and SEC1210 batch/state models against the implementation, including
checksum and frame grammars, prefix and length binding, persistent sequence
bits, response chaining, parameter gates, time-extension rejection, event and
receive caps, and sticky named failures. No signing or secret material is
supplied. No physical card, UART, GPIO, converter, CAP, GlobalPlatform, Java
Card, hardware-readiness, physical T=1, APDU-device, performance, production
or Gate claim is made. No card or hardware operation occurred.
