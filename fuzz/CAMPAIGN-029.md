# Card applet slice 1 campaign 029

Status: EXECUTED — QUALIFYING RUN COMPLETE.

## Qualification boundary

Qualification source: `8d2e4ff9443b7b050348c19b0df8229ede17ea9a`.
All four final-source runs, both copies of each minimization, both rendered
manifests, and the final replay bind that source. The fixed tool identities
were cargo-fuzz 0.13.2; `nightly-2026-08-25`; rustc
`1.100.0-nightly (e7769602a 2026-08-24)`; AddressSanitizer; release-profile
overflow checks and debug assertions enabled; and offline dependency
resolution.

The exact qualifying commands were:

```text
fuzz/run-bounded.sh qk_card_protocol 100000
fuzz/run-bounded.sh qk_card_model 100000
fuzz/run-bounded.sh qk_device_wire 100000
fuzz/run-bounded.sh qk_core_normal_process 100000
```

The public seeds and maximum fuzzer input lengths were 161001 and 65,536 for
`qk_card_protocol`, 161002 and 65,536 for `qk_card_model`, 156001 and 65,536
for `qk_device_wire`, and 156002 and 4,096 for
`qk_core_normal_process`. Each run used a two-second per-input timeout, a
2,048 MiB RSS ceiling, disabled corpus reload, final statistics, and an empty
artifact directory. Each run executed exactly 100,000 inputs and exited zero.

## Superseded pre-repair execution

An earlier execution at unpublished source
`e5d183af38c44a6157eed42c101879cc37759b71` produced an interim
`qk_device_wire` fixed point of 329 files/19,862 bytes. Its two copies agreed
at that source. QK-DEC-161-SUP-001 superseded that result after the plain path
dependency repair changed the qualification source; it is not retained and is
not a registered qualification fact. All four runs and both minimizations were
performed again at the qualification source above.

## Starting corpus registration

The new targets were seeded only from the shared public fixture
`host/qk-card-protocol/tests/fixtures/card_protocol_v1.txt`, 17,919 bytes,
SHA-256
`5019c642ec61c1042043c0b325658e06d54bbcd3648c2e168b742e9af139bbe4`.
That fixture is marked `PERMANENTLY NEVER-FUND PUBLIC PRIVATE MATERIAL` and
its body funding status is `PERMANENTLY NEVER-FUND TEST MATERIAL`. It uses
the already-registered card fixture authority; Campaign 029 created no key
authority.

| Target | Fixture-derived seed | Bytes | SHA-256 | Corpus path |
|---|---|---:|---|---|
| `qk_card_protocol` | `setup_select_request_hex` line | 51 | `e3129642c35ca44edd9607bb05efe83699fdf925d72601b326c74dd02180bc41` | `fuzz/corpus/qk_card_protocol/a92c489aad28b8a5d326785e7f66e1af9ff1fad5` |
| `qk_card_protocol` | `normal_sign_0_request_hex` line | 292 | `87d9806f3792a6c8df0174b9b8b3b508f533bbe227cfc417230a52f68e33410f` | `fuzz/corpus/qk_card_protocol/e32b21f1a161b1848892507a259d54a83b130ab7` |
| `qk_card_protocol` | `record_profile_01_hex` line | 1,586 | `e4c54755fc3583e5296432fc274d26893af4dfebbf4cab7f261cffe58cd85365` | `fuzz/corpus/qk_card_protocol/486cadc4c2cb906dad2e09c3bdad3d59f9ec1151` |
| `qk_card_protocol` | `normal_info_response_hex` line | 347 | `fe55ecca06cd7918f3080d78b5cc3c7c9ae29bb50d51c5a56713d05a6fbf9e6a` | `fuzz/corpus/qk_card_protocol/b186595696c4139444494a04738f33e6127eda9b` |
| `qk_card_protocol` | `normal_read_1_0_response_hex` line | 467 | `c82a1dc0119a9a4798d222279113dcda8e959d40c5ee2b47f57f075c4dcc66c1` | `fuzz/corpus/qk_card_protocol/95b91c27d201adca0c644c5fbd432a52db3c18ad` |
| `qk_card_protocol` | `normal_sign_0_response_hex` line | 357 | `0790a69b3490ac9cb23ac842e74afa8155482635242cbd240e700593ed0c965e` | `fuzz/corpus/qk_card_protocol/d2b06efee2df13bb7f0933d86857648c6031eaa5` |
| `qk_card_model` | all 18 request lines, in fixture order | 3,253 | `6514a708a320900d2a044cf2394254735716c72acc4ccee4e2134f5ab4ea5465` | `fuzz/corpus/qk_card_model/1a6d4c56ba843fef6ad7f9691da36efc7da359ae` |

The two new target roots contained seven files totaling 6,353 bytes. Together
with the registered `qk_device_wire` fixed point of 302 files/18,899 bytes and
`qk_core_normal_process` fixed point of 84 files/1,089 bytes, the Campaign 029
starting point was 393 files/26,341 bytes. Its canonical sorted
`class<TAB>target<TAB>bytes<TAB>sha256<TAB>path` block had SHA-256
`4213ac2a6bb1bbd22cd01bd3fdffb3cda9089c3d3f0ce0f9e025c8d6fd18fce9`.
`tools/check-fuzz-corpora.sh` reproduced that fixed point before execution.

## Qualification results

| Target | Start files/bytes | Engine seconds; rate/s | Coverage/features | Live corpus reported by libFuzzer | New units | Peak RSS MiB | Persisted post-run files/bytes | Wall seconds | Artifacts |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| `qk_card_protocol` | 6/3,100 | 1; 100,000 | 531/664 | 125/6,922b | 347 | 80 | 122/6,915 | 3.05 | 0 |
| `qk_card_model` | 1/3,253 | 4; 25,000 | 972/1,430 | 76/57Kb | 406 | 449 | 76/58,500 | 5.14 | 0 |
| `qk_device_wire` | 302/18,899 | 7; 14,285 | 1,453/2,733 | 331/19Kb | 120 | 327 | 398/23,764 | 7.64 | 0 |
| `qk_core_normal_process` | 84/1,089 | 271; 369 | 5,119/7,781 | 86/1,586b | 45 | 463 | 101/2,036 | 271.64 | 0 |

Every target reported a zero-second slowest input. The live-corpus byte fields
preserve libFuzzer's printed units; persisted values are exact filesystem
counts. The post-run canonical sorted `SHA-256<TAB>bytes` listings were:

| Target | Listing bytes/LF | SHA-256 |
|---|---:|---|
| `qk_card_protocol` | 8,214/122 | `77d8766ab7d79cf8298cdd6a84b60976a1a1520efc3d88c498a3b0d8f9bdf17a` |
| `qk_card_model` | 5,204/76 | `cf95af43414aa412c5e385f433d25941334655ee7fcf1f4702f07c53f2bbf418` |
| `qk_device_wire` | 27,072/398 | `8103e1ea0c93966b9cd0b38dd31fbec371525b2af05de4c81801dbcc707fc124` |
| `qk_core_normal_process` | 6,808/101 | `6778c7bcdc7435e3065789c3b24b5cf19bc3f6caa914f23bff98fc734cad79de` |

## Two-copy minimization and registration

Two separately copied post-run roots for every target were minimized through
an unchanged confirmation pass. The A and B copies agreed byte for byte after
every pass; all 26 minimization invocations exited zero with empty target
artifact directories:

- `qk_card_protocol`: 122/6,915 -> 98/5,261 -> 97/5,260 -> 96/5,257 ->
  unchanged. The changed-pass listing SHA-256 values were
  `f12a34d2eec37fdf677b30189b6b8118af4f2be0226311978d65bea8e21db21e`,
  `592d5ae549cece6e3784d7827b0b88d6d7f170c4ce6093f07337a301d4c8e125`,
  and `c45d6534b5516f3b7ffb629001d8c93f62292cafd43b2303028dc1ab86c09349`.
- `qk_card_model`: 76/58,500 -> 57/45,454 -> 56/45,446 -> unchanged.
  The changed-pass listing SHA-256 values were
  `bd1d36440c52f353395d1119152ba0aff2e8b67770ee8469cc3a7a7004d3bfae`
  and `bf30b0bcff3d6f98b1f8a1ba51fca1842669cf75564ce1aafc3a05aca0c400e6`.
- `qk_device_wire`: 398/23,764 -> 326/19,807 -> 324/19,738 -> unchanged.
  The changed-pass listing SHA-256 values were
  `0ef13fb1a94c15398347ddbb6f1941d39d6c0a6dfd638fddcdbf5965ec782c39`
  and `24293c873c589576c3da41df8b900f1aeba3edd36c383a4efe012968a86c1c01`.
- `qk_core_normal_process`: 101/2,036 -> 88/1,621 -> 86/1,597 ->
  unchanged. The changed-pass listing SHA-256 values were
  `21e1e1ee4550839c5f5a928920b201b41c934a9ad2e5ac810118b6431cbc9763`
  and `3c95894ff36ab11e1007f6588c0d3e1ee9e37f7674ca508626ed9436eae6905d`.

The two new targets had no prior registered campaign fixed point. The agreed
roots were promoted under QK-DEC-146. The requalified roots replaced the
QK-PROCESS-S9-CORPUS-MANIFEST-V1 entries registered at source
`157ab863707b8f074e8b2f906f2c84af45ccb8e7`. That predecessor manifest was
62,831 bytes/394 LF with SHA-256
`4f11a8a6ca3974c78aa0777021d7e8afab616e66bbbc90c3986ba0d7fa5ca016`
and bound 386 files/19,988 bytes with aggregate entries SHA-256
`5c394f3fb9b68f7151929dd89dfbafafa66e859b1f7531f42a676d9fafcb5c59`.
Its prior `qk_device_wire` entries SHA-256 was
`124bb69d74bc3f82b46d3aa7fb4389458baaaf5241b61be988030dc41f4064c1`;
its prior `qk_core_normal_process` entries SHA-256 was
`d6d465b3da4f75e3220a92934118294eec1f511f2e4a38a55a35b077438e4597`.

The final target fixed points are:

| Target | Files/bytes | Entries SHA-256 | Canonical listing bytes/LF | Canonical listing SHA-256 |
|---|---:|---|---:|---|
| `qk_card_protocol` | 96/5,257 | `cbef07df897fd2cec5c3da7ee6788d5b3d68eccd3db755c448ce820188dc8cbd` | 6,469/96 | `c45d6534b5516f3b7ffb629001d8c93f62292cafd43b2303028dc1ab86c09349` |
| `qk_card_model` | 56/45,446 | `c5bdfb8a51f74f5f6505758a73b946bddf34916cea4d9a6d937468b39accedcf` | 3,828/56 | `bf30b0bcff3d6f98b1f8a1ba51fca1842669cf75564ce1aafc3a05aca0c400e6` |
| `qk_device_wire` | 324/19,738 | `8338da8fe2231dbb6052b1fcc1c2db9a8d7567aabcb7307bc80185145ae12697` | 22,036/324 | `24293c873c589576c3da41df8b900f1aeba3edd36c383a4efe012968a86c1c01` |
| `qk_core_normal_process` | 86/1,597 | `5b354d648a32a2d74d2f9a0d9620447bb3b2d5d1b82d6b97744427aa5db48c7d` | 5,795/86 | `3c95894ff36ab11e1007f6588c0d3e1ee9e37f7674ca508626ed9436eae6905d` |

The rendered `QK-CARD-S1-CORPUS-MANIFEST-V1` is 91,182 bytes/572 LF with
SHA-256
`41f8e02e118117331332c350e90ada6790a39832a095e11dcd48ff813ac2081c`.
It binds 562 files/72,038 bytes with aggregate entries SHA-256
`84d734bf7c0a7207c4ed2f83ebab2c8a73a54e2255b7de9ac561dd7449416b68`.

The re-rendered `QK-PROCESS-S9-CORPUS-MANIFEST-V1` is 66,659 bytes/418 LF
with SHA-256
`053d25ec94a3d1ede0c35f3a018af06d90f7443ca704363fb3f624451539b1f8`.
It binds 410 files/21,335 bytes with aggregate entries SHA-256
`615a3c9b08c3f1b4bfd7d949d75ad3e4bcc34026c77336ac85c37e4f61439237`.

## Final retained-corpus replay

The retained Campaign 029 roots replayed at the qualification source with no
new units and no artifacts:

| Target | Retained files/bytes | Executed units | Coverage/features | Peak RSS MiB |
|---|---:|---:|---:|---:|
| `qk_card_protocol` | 96/5,257 | 97 | 531/664 | 36 |
| `qk_card_model` | 56/45,446 | 57 | 972/1,430 | 37 |
| `qk_device_wire` | 324/19,738 | 325 | 1,453/2,733 | 56 |
| `qk_core_normal_process` | 86/1,597 | 87 | 5,119/7,781 | 57 |

The complete registered set contained 52 roots and 7,773 files totaling
534,912 bytes. All 52 roots replayed, executing 7,834 units with zero
failures and zero artifacts. The canonical before-and-after filesystem
listings were byte-identical at 997,959 bytes/7,773 LF and SHA-256
`cf6bfd396938efe10b6bb22ece677c429cc567d7e0d18e92837c1c2727cd7351`.

These were pure HOST targets: no process, socket, descriptor, device, card,
or hardware operation occurred. The test-only `qk-card-model` closure remained
absent from every product closure. Campaign 029 makes no converter, CAP,
GlobalPlatform, Java Card, delivered-platform, RNG, contactless-enforcement,
performance, production, or Gate claim.
