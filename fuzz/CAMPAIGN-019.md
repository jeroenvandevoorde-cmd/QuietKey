# Reused-module cleanup campaign 019

Status: EXECUTED — QUALIFYING RUN COMPLETE.

The common product-code source for eight targets was
`1cb2508da103c26a246fb9a1f7acf72eb50aa0b6`. The M24 target source was
`fb9a04c01e219c7508d17fef3403f86120e89b7b`, whose only source change after
the product-code commit is the QK-DEC-138 exhaustive named-error match arm in
`fuzz/fuzz_targets/qk_host_sim_m24.rs`.

The fixed tool identities were cargo-fuzz 0.13.2;
`nightly-2026-08-25`; rustc
`1.100.0-nightly (e7769602a 2026-08-24)`; AddressSanitizer; release-profile
overflow checks and debug assertions enabled; and offline dependency
resolution. Each qualifying command was `fuzz/run-bounded.sh TARGET 100000`.
The scripts fixed a 2-second timeout, 2,048 MiB RSS limit, corpus reload off,
and final-stat reporting. Target-specific seeds and maximum lengths were:

| Target | Seed | Maximum input |
| --- | ---: | ---: |
| `qk_psbt` | 21001 | 4,096 bytes |
| `qk_psbt_m23` | 23001 | 4,096 bytes |
| `qk_host_sim_m23` | 23002 | 4,096 bytes |
| `qk_host_sim_m24` | 24001 | 4,096 bytes |
| `qk_host_sim_m25` | 25001 | 4,096 bytes |
| `qk_host_sim_m27` | 27001 | 1,024 bytes |
| `qk_host_sim_m30` | 30002 | 4,096 bytes |
| `qk_host_sim_v2_s5_screen` | 125001 | 2,048 bytes |
| `qk_host_sim_v2_s11_kit_spend` | 131001 | 512 bytes |

## Pre-run M24 compilation stop

The first prescribed M24 command stopped during Rust compilation with E0004:
`assert_signing_error_named` omitted the already-existing
`SigningV2Error::InvalidRecoveredSignature` variant. The libFuzzer engine did
not start: executed inputs, reached target arms, findings, panics, timeouts,
sanitizer reports, and artifacts were all zero. Its registered corpus remained
268 files/7,157 bytes with sorted `SHA-256<TAB>bytes` listing SHA-256
`4e8135bd6ee7e447a17238a14c1c8501659abdd56ef9673fb0b04de626bd3ba3`.
QK-DEC-138 records the stop and the one-arm target-only repair. The successful
M24 qualification below is the sole engine run for that target.

## Qualifying executions

Every successful target executed exactly 100,000 inputs and created zero
artifact files.

| Target | Seconds | Exec/s | Coverage/features | New units | Slowest | Peak RSS |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| `qk_psbt` | 8 | 12,500 | 460/712 | 251 | 0 s | 431 MiB |
| `qk_psbt_m23` | 20 | 5,000 | 2,114/3,387 | 140 | 0 s | 430 MiB |
| `qk_host_sim_m23` | 47 | 2,127 | 2,337/4,184 | 175 | 0 s | 428 MiB |
| `qk_host_sim_m24` | 241 | 414 | 3,487/6,640 | 137 | 0 s | 462 MiB |
| `qk_host_sim_m25` | 960 | 104 | 3,137/3,588 | 0 | 0 s | 439 MiB |
| `qk_host_sim_m27` | 4 | 25,000 | 4,311/6,190 | 230 | 0 s | 269 MiB |
| `qk_host_sim_m30` | 980 | 102 | 2,772/2,975 | 0 | 0 s | 442 MiB |
| `qk_host_sim_v2_s5_screen` | 8 | 12,500 | 694/1,126 | 32 | 0 s | 409 MiB |
| `qk_host_sim_v2_s11_kit_spend` | 230 | 434 | 4,571/7,961 | 38 | 0 s | 169 MiB |

The sorted listing digest in the next table hashes lines of
`SHA-256<TAB>byte-count`, without paths.

| Target | Starting corpus | Starting listing SHA-256 | Post-run corpus | Post-run listing SHA-256 | Retained corpus | Retained listing SHA-256 |
| --- | ---: | --- | ---: | --- | ---: | --- |
| `qk_psbt` | 79 / 4,664 B | `d6d0d094ed318a59680fe6cf3a827bf4cd8c19224f5d8eb4b5bcef4d330a3119` | 264 / 68,572 B | `52259fd03ceabfe67bb20f36784839fa1ca71e8ea478faa259625fce7309a9f3` | 164 / 42,417 B | `17899290a3effedfe1b8ce979e757b7c39c867f1585444cef27cb4b281f92093` |
| `qk_psbt_m23` | 235 / 5,100 B | `d39a6b462be7a78a80161a870c9ed2130cf69f31d0d4fe29da60a0522ce3d0b1` | 355 / 7,842 B | `4c7cd00b557467498ce249c6fb32ce13a43a003a5a5abba02af0772c965b0079` | 246 / 5,109 B | `388d2fa55bd679f009126f2ddb3f04c7519b5b894305b035c97e23d0524f8e17` |
| `qk_host_sim_m23` | 239 / 5,537 B | `bacdfb381caa0f28262e3e6174b585eecd99b3cb3ff63b5aff27ae70c5777cc6` | 384 / 9,189 B | `85a6c548c2f925dbde96a3805a381e393aee3db1a3cb47ce33845c81a1fb5d1d` | 260 / 5,844 B | `6a3f8cd5abbeb52b0f41a605a16bbf45497b25071e898fd3c66addd1ca928b82` |
| `qk_host_sim_m24` | 268 / 7,157 B | `4e8135bd6ee7e447a17238a14c1c8501659abdd56ef9673fb0b04de626bd3ba3` | 398 / 12,324 B | `ff6dafa16cd8016db3ea81f4638bb5161271dd477a9d1a675ab9a5a04ac36e45` | 273 / 7,363 B | `28899e69a0a3a7b43521a88de49889c653848a2a58259c38a78810487009ebd2` |
| `qk_host_sim_m25` | 20 / 78 B | `9d3b7603d044e682772b4aca71591fe5604886124c50c87d549270f7b6d19992` | 20 / 78 B | `9d3b7603d044e682772b4aca71591fe5604886124c50c87d549270f7b6d19992` | 19 / 74 B | `44c7a591ac6196330ec807f0b90a66c8f6990e8a6db9c1bd2d7f531af207811b` |
| `qk_host_sim_m27` | 273 / 3,490 B | `1e599c5fa1f0517810bd7979eac04c05cf4160830c0148830044f66f310e7f1b` | 427 / 8,070 B | `a4f3d3bdd185f56c793951385be596df4b57bdd7e6df58ee89b28abb44aa60e8` | 321 / 5,425 B | `7732ef807ac32719fc09cd3800bfa44735d89bd509cdc98e89a46f041f7f1729` |
| `qk_host_sim_m30` | 18 / 49 B | `c58b4d10012e029e1221097d54334ea010488e0b2011e1524ae55d5150a5184b` | 18 / 49 B | `c58b4d10012e029e1221097d54334ea010488e0b2011e1524ae55d5150a5184b` | 18 / 49 B | `c58b4d10012e029e1221097d54334ea010488e0b2011e1524ae55d5150a5184b` |
| `qk_host_sim_v2_s5_screen` | 132 / 6,409 B | `4377a89be905b7f28786ce91c2650ac690fc393374e5b4ad990e6d23df7bf7b5` | 163 / 8,864 B | `c931fdbfe428332a0334d3a301b5a81158b854e77e5b19044a40e5119863c2ca` | 132 / 6,912 B | `1f04391ea7950a0f8b6deba5e26b7ce273b618acf8826bee01230f5fe4002caf` |
| `qk_host_sim_v2_s11_kit_spend` | 115 / 7,640 B | `b81c162a3507cfd67fc187f02a6d4e1e1a1058de2c3bdc776d6a4fb6168debd2` | 152 / 9,632 B | `49af00cd5df954902cb5f70160e7b01aab19085f652737240e27d108edfbdd67` | 115 / 7,682 B | `59644a6a23862ae0bed858d92c93e124b4dfc00dd506f3219d0be2a943d86f16` |

Two separate copies of every post-run corpus were minimized serially until an
additional pass made no change. The two final listings for every target were
byte-identical. Their complete count/byte progressions were:

- `qk_psbt`: 264/68,572, 171/45,400, 170/44,939, 167/44,009,
  166/43,542, 164/42,417, unchanged.
- `qk_psbt_m23`: 355/7,842, 255/5,254, 247/5,125, 246/5,109,
  unchanged.
- `qk_host_sim_m23`: 384/9,189, 266/5,894, 262/5,862, 260/5,844,
  unchanged.
- `qk_host_sim_m24`: 398/12,324, 280/7,516, 278/7,434, 276/7,394,
  275/7,386, 273/7,363, unchanged.
- `qk_host_sim_m25`: 20/78, 19/74, unchanged.
- `qk_host_sim_m27`: 427/8,070, 323/5,442, 321/5,425, unchanged.
- `qk_host_sim_m30`: 18/49, unchanged.
- `qk_host_sim_v2_s5_screen`: 163/8,864, 132/6,912, unchanged.
- `qk_host_sim_v2_s11_kit_spend`: 152/9,632, 117/7,740,
  115/7,682, unchanged.

The nine retained corpora total 1,548 files/80,875 bytes. The unchanged M30
fixed point required no corpus or manifest change. The other eight fixed
points were promoted and registered in the seven permitted partitions:

| Manifest | Bytes | File SHA-256 | Relevant retained entry SHA-256 |
| --- | ---: | --- | --- |
| `CORPUS-MANIFEST.tsv` | 142,696 | `9d5e54666a51fc4093cf4dad70761df529c3b01758f3fc07fd9da062c170835c` | `qk_psbt` `325caf0b3c1b2172542cfafd7e18639d006a9397b3c81f3669c3c1d72f2be9b9` |
| `CORPUS-MANIFEST-M23.tsv` | 79,303 | `9d5447e57b928e3401a7c3299491b3096cc0c26091b7273273f1f96f51849152` | aggregate `f2cbb0c4a51763b5d64732b372f8354cd5acd1cc4b6fb41e829fc4f4beab6903` |
| `CORPUS-MANIFEST-M24.tsv` | 43,949 | `950f590ae44e2559a9d58d342eef625301858ec39c873342f44a9bc062565da5` | `25b6426e291cfb4917dc2fe1d17300f2d95f9edf0c7dad92c088c6929aca1a4b` |
| `CORPUS-MANIFEST-M25.tsv` | 3,408 | `390145f045262ca9833c4b0806fb5bf79323196a9d14f0520a577a7e0d9792c4` | `f5593d178767f377f123a47bed17c98053736c8a995a1d3339838ecd19aab239` |
| `CORPUS-MANIFEST-M27.tsv` | 51,561 | `2f02d2e66c32d361feaf1f95a655c65ceabf78534aa460ec126cf187ca01d32c` | `4d9f55aa8ff752354c464052398e26f0fc11715a28900b24379a1869c6770671` |
| `CORPUS-MANIFEST-V2-S5.tsv` | 61,969 | `2f2242f85aef9aa89e8329a84afc6b6624d2ddf5bff626bf322daffc0c388fba` | `qk_host_sim_v2_s5_screen` `1c392197bba9352436c99a7ad7315cf3b60f42220eca854c9c373c91f507fac9` |
| `CORPUS-MANIFEST-V2-S11.tsv` | 21,828 | `3779dae0bafee446009994722e2aaeea9866be01b110c9b4d661d86e93947251` | `b1019d959ba4d10afdb7e4f77606b6c82942b097966290ec9425ef76666b6b7f` |

## Final-tree retained-corpus replay

All 31 registered corpora replayed sequentially within three disjoint process
groups against executable tree `fb9a04c01e219c7508d17fef3403f86120e89b7b`.
Each run exited zero with `new_units_added=0` and zero artifacts. The exact
executed-unit counts were:

```text
qk_psbt                              165 PASS
qk_descriptor                        122 PASS
qk_a1                                 39 PASS
qk_a1_codec                          468 PASS
qk_card_trace                        147 PASS
qk_bbqr_codec                         80 PASS
qk_bbqr_reassembly                   187 PASS
qk_psbt_m23                          248 PASS
qk_host_sim_m23                      262 PASS
qk_host_sim_m24                      274 PASS
qk_host_sim_m25                       20 PASS
qk_provisioning_inputs_m26           127 PASS
qk_provisioning_chain_m26            115 PASS
qk_host_sim_m27                      323 PASS
qk_host_sim_m28                       73 PASS
qk_host_sim_m29                      186 PASS
qk_bbqr_m30                          120 PASS
qk_host_sim_m30                       19 PASS
qk_provisioning_v2_inputs             82 PASS
qk_provisioning_v2_chain             111 PASS
qk_host_sim_v2_s5_screen             133 PASS
qk_host_sim_v2_s5_manual_keypad      199 PASS
qk_host_sim_v2_s6_watch_only          90 PASS
qk_kit_v2_s7_codec                   234 PASS
qk_kit_v2_s7_combine                  90 PASS
qk_provisioning_v2_s8_kit_setup      143 PASS
qk_host_sim_v2_s9_kit_intake         133 PASS
qk_host_sim_v2_s10_kit_restore        70 PASS
qk_host_sim_v2_s11_kit_spend         116 PASS
qk_update_package                    155 PASS
qk_update_lifecycle                   35 PASS
```

The final replay executed 4,566 units. Across qualification, minimization,
registration and retained replay, artifact, panic, timeout, sanitizer report,
wrong acceptance, unnamed rejection and behavior-difference counts were zero.
No fixture file changed.
