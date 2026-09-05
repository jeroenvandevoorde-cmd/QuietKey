# Card applet slice 1 campaign 029

Status: PLANNED — NOT EXECUTED.

## Qualification boundary

QK-DEC-161 requires four pure-target campaigns against one final source
commit: new targets `qk_card_protocol` and `qk_card_model`, plus
requalification of `qk_device_wire` and `qk_core_normal_process`. The fixed
tool identities are cargo-fuzz 0.13.2; `nightly-2026-08-25`; rustc
`1.100.0-nightly (e7769602a 2026-08-24)`; AddressSanitizer; release-profile
overflow checks and debug assertions enabled; and offline dependency
resolution. No qualifying campaign has run under this record.

The qualifying commands, after the final source commit exists, are:

```text
fuzz/run-bounded.sh qk_card_protocol 100000
fuzz/run-bounded.sh qk_card_model 100000
fuzz/run-bounded.sh qk_device_wire 100000
fuzz/run-bounded.sh qk_core_normal_process 100000
```

The public seeds and maximum fuzzer input lengths are 161001 and 65,536 for
`qk_card_protocol`, 161002 and 65,536 for `qk_card_model`, 156001 and 65,536
for `qk_device_wire`, and 156002 and 4,096 for
`qk_core_normal_process`. Each run uses a two-second per-input timeout, a
2,048 MiB RSS ceiling, disabled corpus reload, final statistics, and an empty
artifact directory.

## Starting corpus registration

The new targets are seeded only from the shared public fixture
`host/qk-card-protocol/tests/fixtures/card_protocol_v1.txt`, 17,919 bytes,
SHA-256
`5019c642ec61c1042043c0b325658e06d54bbcd3648c2e168b742e9af139bbe4`.
That fixture is marked `PERMANENTLY NEVER-FUND PUBLIC PRIVATE MATERIAL` and
uses the already-registered card fixture authority; Campaign 029 creates no
key authority.

| Target | Fixture-derived seed | Bytes | SHA-256 | Corpus path |
|---|---|---:|---|---|
| `qk_card_protocol` | `setup_select_request_hex` line | 51 | `e3129642c35ca44edd9607bb05efe83699fdf925d72601b326c74dd02180bc41` | `fuzz/corpus/qk_card_protocol/a92c489aad28b8a5d326785e7f66e1af9ff1fad5` |
| `qk_card_protocol` | `normal_sign_0_request_hex` line | 292 | `87d9806f3792a6c8df0174b9b8b3b508f533bbe227cfc417230a52f68e33410f` | `fuzz/corpus/qk_card_protocol/e32b21f1a161b1848892507a259d54a83b130ab7` |
| `qk_card_protocol` | `record_profile_01_hex` line | 1,586 | `e4c54755fc3583e5296432fc274d26893af4dfebbf4cab7f261cffe58cd85365` | `fuzz/corpus/qk_card_protocol/486cadc4c2cb906dad2e09c3bdad3d59f9ec1151` |
| `qk_card_protocol` | `normal_info_response_hex` line | 347 | `fe55ecca06cd7918f3080d78b5cc3c7c9ae29bb50d51c5a56713d05a6fbf9e6a` | `fuzz/corpus/qk_card_protocol/b186595696c4139444494a04738f33e6127eda9b` |
| `qk_card_protocol` | `normal_read_1_0_response_hex` line | 467 | `c82a1dc0119a9a4798d222279113dcda8e959d40c5ee2b47f57f075c4dcc66c1` | `fuzz/corpus/qk_card_protocol/95b91c27d201adca0c644c5fbd432a52db3c18ad` |
| `qk_card_protocol` | `normal_sign_0_response_hex` line | 357 | `0790a69b3490ac9cb23ac842e74afa8155482635242cbd240e700593ed0c965e` | `fuzz/corpus/qk_card_protocol/d2b06efee2df13bb7f0933d86857648c6031eaa5` |
| `qk_card_model` | all 18 request lines, in fixture order | 3,253 | `6514a708a320900d2a044cf2394254735716c72acc4ccee4e2134f5ab4ea5465` | `fuzz/corpus/qk_card_model/1a6d4c56ba843fef6ad7f9691da36efc7da359ae` |

The two new target roots contain seven files totaling 6,353 bytes. Together
with the registered `qk_device_wire` fixed point of 302 files/18,899 bytes and
`qk_core_normal_process` fixed point of 84 files/1,089 bytes, the Campaign 029
starting point is 393 files/26,341 bytes. Its canonical sorted
`class<TAB>target<TAB>bytes<TAB>sha256<TAB>path` block has SHA-256
`4213ac2a6bb1bbd22cd01bd3fdffb3cda9089c3d3f0ce0f9e025c8d6fd18fce9`.
`tools/check-fuzz-corpora.sh` recomputes this exact fixed point before a
qualifying run.

## Completion conditions

Both separately copied minimizations for each target must agree byte for byte.
Under QK-DEC-146, an agreed changed fixed point replaces the registered target
root and records its prior entries hash; disagreement stops for Owner
disposition. If either requalified root changes, the owning
`CORPUS-MANIFEST-PROCESS-S9.tsv` is re-rendered with its prior manifest and
entry hashes recorded. The final `QK-CARD-S1-CORPUS-MANIFEST-V1` binds all four roots.
Every registered corpus then replays on the final tree with zero failures and
zero artifacts. These are pure HOST targets: no process, socket, descriptor,
device, card, or hardware operation occurs. The test-only `qk-card-model`
closure remains absent from every product closure.
