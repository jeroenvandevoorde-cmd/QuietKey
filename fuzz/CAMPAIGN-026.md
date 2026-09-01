# Process slice 7 campaign 026

Status: EXECUTED — QUALIFYING RUN COMPLETE.

Opening qualification source: `435990f2105b71d334b190de4e8247e396ab75ef`.
Final-source qualification source:
`3cc194c7f278193cad8148360bb43c7974cae6de`.

## Common method

All nine qualifying campaigns used source
`435990f2105b71d334b190de4e8247e396ab75ef`. The fixed tool identities were
cargo-fuzz 0.13.2; `nightly-2026-08-25`; rustc
`1.100.0-nightly (e7769602a 2026-08-24)`; AddressSanitizer; release-profile
overflow checks and debug assertions enabled; and offline dependency
resolution. Every run used corpus reload disabled, a two-second input timeout,
a 2,048 MiB RSS ceiling, final-stat reporting and an empty artifact directory.
The exact commands were:

```text
fuzz/run-bounded.sh qk_core_io_peer 100000
fuzz/run-bounded.sh qk_core_session 100000
fuzz/run-bounded.sh qk_core_provisioning_entry 100000
fuzz/run-bounded.sh qk_core_provisioning_run 100000
fuzz/run-bounded.sh qk_core_normal_entry 100000
fuzz/run-bounded.sh qk_core_normal_run 100000
fuzz/run-bounded.sh qk_core_kit_intake 100000
fuzz/run-bounded.sh qk_core_kit_restore 100000
fuzz/run-bounded.sh qk_core_kit_spend 100000
```

Target seeds and maximum input lengths in bytes were respectively 144001/16,384,
144002/4,096, 145001/1,024, 145002/512, 149001/4,096, 149002/4,096,
151001/512, 151002/512 and 151003/512.

## Opening qualification

| Target | Start files/bytes | Engine seconds; rate/s | Coverage/features | Live files/bytes | New units | Peak RSS MiB | Persisted post-run files/bytes | Artifacts |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| `qk_core_io_peer` | 36/232 | 9; 11,111 | 776/923 | 34/225 | 0 | 438 | 36/232 | 0 |
| `qk_core_session` | 114/9,723 | 12; 8,333 | 919/2,536 | 114/9,657 | 9 | 491 | 123/10,510 | 0 |
| `qk_core_provisioning_entry` | 246/10,763 | 2,015; 49 | 2,310/3,591 | 246/10,734 | 6 | 475 | 252/11,047 | 0 |
| `qk_core_provisioning_run` | 192/9,650 | 626; 159 | 2,975/4,998 | 193/9,776 | 3 | 349 | 195/9,968 | 0 |
| `qk_core_normal_entry` | 53/762 | 4; 25,000 | 949/1,392 | 53/762 | 0 | 84 | 53/762 | 0 |
| `qk_core_normal_run` | 148/2,441 | 326; 306 | 4,926/15,188 | 153/2,581 | 19 | 432 | 162/2,945 | 0 |
| `qk_core_kit_intake` | 0/0 | 13; 7,692 | 1,653/2,541 | 31/46 | 40 | 162 | 30/45 | 0 |
| `qk_core_kit_restore` | 0/0 | 11,075; 9 | 3,100/4,131 | 58/79 | 95 | 472 | 57/78 | 0 |
| `qk_core_kit_spend` | 0/0 | 10,486; 9 | 4,928/7,918 | 58/211 | 77 | 473 | 57/210 | 0 |

Every target executed exactly 100,000 inputs, exited zero and reported a
zero-second slowest unit. Kit-Restore used 11,076.42 real seconds and
Kit-Spend used 10,486.85 real seconds. For both targets the runtime live count
includes libFuzzer's one-byte in-memory seed; the persisted corpus facts are
the filesystem counts in the table.

The post-run canonical sorted `SHA-256<TAB>bytes` listing facts were:

| Target | Listing bytes/LF | SHA-256 |
|---|---:|---|
| `qk_core_io_peer` | 2,416/36 | `5a6b22681a307e8e7a0478d111e314e92800dbfbc009c04b2d3403a509a3c1db` |
| `qk_core_session` | 8,354/123 | `db225ff0bc67dbbd0bc09f8125eb20f26f79c93f73e65e53afe50e56c5385e84` |
| `qk_core_provisioning_entry` | 17,146/252 | `2b1f0fab1f4a26ed241db900cdd3369e515b0fc03b6ff500f1f2a30f69b615bd` |
| `qk_core_provisioning_run` | 13,268/195 | `b29670b24b2c95a8424e2522bc1c193316a903d000469f850062182b4b57a58a` |
| `qk_core_normal_entry` | 3,581/53 | `58e75e005aed7d908f79cc276045587a7ea6e2d0c853eba1a1b146fcdff3e4e2` |
| `qk_core_normal_run` | 10,942/162 | `75090aa1509a6b836124ff47db55eba9de5a21333f11f818182c4137665a98fd` |
| `qk_core_kit_intake` | 2,010/30 | `0942eab2fdeed7fb1e5e835ac56f5f8807767b99c102eb0180f3b748e139a8a7` |
| `qk_core_kit_restore` | 3,819/57 | `9bd7f9dc3e112405d2e0e79c97fb762756b457cd50f6050ea3b42863e53809ce` |
| `qk_core_kit_spend` | 3,819/57 | `ded3f1232103cebaba30c0f60364f342fd5189941ddfbc97ede43f796c9e8033` |

## Two-copy minimization and promotion

Two separately copied post-run corpora for every target were minimized to an
unchanged confirmation pass. The two copies reached the same progression and
agreed byte for byte at their final fixed point:

- `qk_core_io_peer`: 36 files/232 bytes remained unchanged; final canonical
  listing 2,416 bytes/36 LF, SHA-256
  `5a6b22681a307e8e7a0478d111e314e92800dbfbc009c04b2d3403a509a3c1db`.
- `qk_core_session`: 123/10,510 → 114/9,653 → unchanged; final listing
  7,739 bytes/114 LF, SHA-256
  `8cf4c246541effd739abe5e505ae2e249f84e6573d4d66ce5c75aa2cab67e99d`.
- `qk_core_provisioning_entry`: 252/11,047 → 246/10,639 → 245/10,611 →
  unchanged; final listing 16,668 bytes/245 LF, SHA-256
  `2f7f09f8e937917086651641ce9694bdcd197f8afa06a2519614098d83bbb355`.
- `qk_core_provisioning_run`: 195/9,968 → 193/9,776 → unchanged; final
  listing 13,131 bytes/193 LF, SHA-256
  `95f7d2df2564f8fa31a3193d7ab524917ac465f90895a4c3a1bc1f5c6b124bb2`.
- `qk_core_normal_entry`: 53/762 remained unchanged; final listing 3,581
  bytes/53 LF, SHA-256
  `58e75e005aed7d908f79cc276045587a7ea6e2d0c853eba1a1b146fcdff3e4e2`.
- `qk_core_normal_run`: 162/2,945 → 150/2,485 → unchanged; final listing
  10,130 bytes/150 LF, SHA-256
  `24861f62fad1eee97bde001d83e2461b12a6ffd7132890bb3e2068e9f9cce794`.
- `qk_core_kit_intake`: 30/45 → 29/37 → unchanged; final listing 1,943
  bytes/29 LF, SHA-256
  `e1fa88104dd2b222f1a73344d29652afee74ff88d07ecb6670165ad224ef96be`.
- `qk_core_kit_restore`: 57/78 → 56/77 → 56/77 → unchanged; final listing
  3,752 bytes/56 LF, SHA-256
  `c60be81f754a57d325d047c05b545642f2679a731dfb6d2b243852462f6235a7`.
- `qk_core_kit_spend`: 57/210 → 53/189 → 52/186 → 51/182 → unchanged;
  final listing 3,417 bytes/51 LF, SHA-256
  `4a59a96012259480d715b7ffa674b527ecac1eac530a5c31f5167bf5f35bfd4c`.

Every minimization pass exited zero and every target artifact directory stayed
empty. The retained directories were promoted only after both copies agreed.

The three pre-promotion manifests below shared campaign source
`d172318a0dcd00db4e7141fff60a33679872d46a`. Before promotion, PROCESS-S4
was 24,493 bytes/158 LF with SHA-256
`915d78e60ee273e89070bd4d511b9b9fa07fff45e44125373025f7b49a4d7a31`;
its target entry hashes were
`a9ce239a7d67870d797d69b92ebcba48b03d26899457e9f607f6e5af5e422d73`
and `2af011337602a31698475d223376b8705049cff56679d4501afd7f9cfefa3302`,
and its aggregate was 150/9,955/
`fb3d6e36d0be0eb23cac4da14762acf7bf89b14677268ca97eebe1406a5edd17`.
PROCESS-S5 was 79,544 bytes/446 LF with SHA-256
`3fc750910c738dfe9a4e916b13d40d759861e59df5738e356431e17fab374eb9`;
its target entry hashes were
`4359ace5bb5040c11cea17c5d99aa069512d3ba15af3fb07a3170cc1e40ddf4b`
and `fb04fc537eab667654cad919ce7237da4e146b981a9ef1b845b641fb8602f285`,
and its aggregate was 438/20,413/
`5cdf1ef17d92a709c7a1bc1d767c7c51b7b786d19b367f5ae4619f72d48a97a5`.
PROCESS-S6 was 34,038 bytes/209 LF with SHA-256
`385bf4b17f5f79867a38bb18c15275dbdf68065431af97aaad8ded70d9d27c2e`;
its target entry hashes were
`f3de20565da23312914b73801e4bfbe4230a5e7644d2ea1d452fab3851bcb02c`
and `295621c8ef6308ddcb4558731a152099552a65bdcfc541a19b84fb22beb44dde`,
and its aggregate was 201/3,203/
`b98c3c8c1feda4783e5d7200d939451fd0626a3806ced9e2e502ebbc94ff649f`.

The agreed promotions changed `qk_core_session`,
`qk_core_provisioning_entry`, `qk_core_provisioning_run` and
`qk_core_normal_run`. `qk_core_io_peer` and `qk_core_normal_entry` retained
their prior fixed points. The three Kit targets were new partition roots.

All final manifests bind campaign source
`435990f2105b71d334b190de4e8247e396ab75ef`:

| Partition | Target or aggregate facts | Manifest bytes/LF/SHA-256 |
|---|---|---|
| PROCESS-S4 | aggregate 150/9,885/`cb3ffb26deee88598290158f3362b301bd8fae903906d38de41c662c14dffc41` | 24,492/158/`42d1a30ba04edd6879ccae4f7f2341d546fd476002aca12d71e2f01cd1d7c9d0` |
| PROCESS-S5 | aggregate 438/20,387/`26232d950a3bf3846242cb331a94f46fd4c72f440cbb75d57beaaeaca69e23a5` | 79,540/446/`f34e8d14c08fa4e5bf5c9522e3dfd09eaa55b165f344889634fda2145ff7a8b2` |
| PROCESS-S6 | aggregate 203/3,247/`4b08173d4a64fc4dbed5a2f17c52d63931918584c38e7502fb0e5047cbe2d72a` | 34,370/211/`470bca2b1d154506f2374f08444d3fb7078281a7c2c37a3f1ee9083724ac452f` |
| PROCESS-S7 | aggregate 927/33,815/`884fdf31f40d0a1e9db110ac742482e6ccc10ba0d2a3b1c4451fd93d16aaa5fa` | 160,764/942/`399a62797536c17fead1f1f302326e98c5427ba3c38df3269d543310df5da86d` |

The per-target counts, byte totals and entry hashes are the registered rows in
the four manifests; the listing hashes above intentionally use the separate
canonical-listing serialization.

## Opening-tree retained-corpus replay

The nine requalified corpora loaded 927 files/33,815 bytes and executed 936
units. The 38 replay-only corpora loaded 6,123 files/413,108 bytes and executed
6,170 units. Across all 47 retained corpus roots, 7,050 files/446,923 bytes
executed 7,106 units. Every pre/post filename-size-hash listing was identical;
every target added zero units, created zero artifacts and exited zero under the
pinned nightly and AddressSanitizer.

The replay-only set was exactly `qk_psbt`, `qk_descriptor`, `qk_a1`,
`qk_a1_codec`, `qk_card_trace`, `qk_bbqr_codec`, `qk_bbqr_reassembly`,
`qk_psbt_m23`, `qk_host_sim_m23`, `qk_host_sim_m24`, `qk_host_sim_m25`,
`qk_provisioning_inputs_m26`, `qk_provisioning_chain_m26`, `qk_host_sim_m27`,
`qk_host_sim_m28`, `qk_host_sim_m29`, `qk_bbqr_m30`, `qk_host_sim_m30`,
`qk_provisioning_v2_inputs`, `qk_provisioning_v2_chain`,
`qk_host_sim_v2_s5_screen`, `qk_host_sim_v2_s5_manual_keypad`,
`qk_host_sim_v2_s6_watch_only`, `qk_kit_v2_s7_codec`,
`qk_kit_v2_s7_combine`, `qk_provisioning_v2_s8_kit_setup`,
`qk_host_sim_v2_s9_kit_intake`, `qk_host_sim_v2_s10_kit_restore`,
`qk_host_sim_v2_s11_kit_spend`, `qk_update_package`,
`qk_update_lifecycle`, `qk_ipc_wire`, `qk_ipc_endpoint_state`,
`qk_supervisor_lifecycle`, `qk_decoy_calculator`, `qk_io_ingress`,
`qk_io_egress` and `qk_io_session`.

The three new total oracles cover mode-locked scanner and fallback intake,
frame and pair precedence, old and replacement descriptor rebinding, both
restore branches, exact A1 print and scan-back bytes, review visitation,
assertion identity and no-yield ordering, every sweep-shape condition, all
profile and route combinations, exact SD and type-T delivery bytes,
interruption absorption, deterministic repetition and wipe accounting. The
six inherited qk-core oracles continue to cover QKIP peer/session state,
provisioning and normal-wallet flows while compiling the expanded direct
qk-kit edge. No product source or target oracle changed during qualification
at `435990f2105b71d334b190de4e8247e396ab75ef`.

## Final-source transition

The full check after the opening qualification found that
`host/qk-core/Cargo.toml` declared `qk-kit` optional even though the approved
default and process-s7 closures require that direct product edge
unconditionally. Commit `3cc194c7f278193cad8148360bb43c7974cae6de`
removed only `optional = true` from that path dependency. It changed no Rust
product logic or target oracle, but all nine campaigns were repeated because
the registered qualification source must be the final fuzz-relevant source.
Commit `4baf9a2b09870ff66095154f3add004c6edf08cf` then changed only the matching
surface expectation and the qk-core allowlist checksum. The final campaigns
and manifests therefore bind `3cc194c7f278193cad8148360bb43c7974cae6de`,
while publication-tree replay and checks include the later pin-only commit.

## Final-source qualification

The nine final-source campaigns had these exact results:

| Target | Start files/bytes | Engine seconds; rate/s | Coverage/features | Live files/bytes | New units | Peak RSS MiB | Persisted post-run files/bytes | Real seconds | Artifacts |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| `qk_core_io_peer` | 36/232 | 9; 11,111 | 776/923 | 34/225 | 0 | 439 | 36/232 | 10.52 | 0 |
| `qk_core_session` | 114/9,653 | 11; 9,090 | 919/2,536 | 114/9,607 | 6 | 490 | 120/10,482 | 13.29 | 0 |
| `qk_core_provisioning_entry` | 245/10,611 | 1,992; 50 | 2,310/3,591 | 245/10,584 | 13 | 475 | 258/11,308 | 1,994.88 | 0 |
| `qk_core_provisioning_run` | 193/9,776 | 640; 156 | 2,975/5,015 | 199/10,874 | 9 | 346 | 202/11,200 | 643.44 | 0 |
| `qk_core_normal_entry` | 53/762 | 4; 25,000 | 949/1,392 | 53/762 | 0 | 84 | 53/762 | 5.84 | 0 |
| `qk_core_normal_run` | 150/2,485 | 350; 285 | 4,926/15,194 | 151/2,545 | 14 | 429 | 160/3,015 | 353.55 | 0 |
| `qk_core_kit_intake` | 29/37 | 13; 7,692 | 1,653/2,541 | 30/38 | 4 | 161 | 30/38 | 15.36 | 0 |
| `qk_core_kit_restore` | 56/77 | 11,143; 8 | 3,100/4,131 | 56/76 | 1 | 474 | 57/78 | 11,151.64 | 0 |
| `qk_core_kit_spend` | 51/182 | 10,815; 9 | 4,928/7,918 | 52/183 | 6 | 442 | 52/183 | 10,827.90 | 0 |

Every row executed exactly 100,000 inputs, exited zero and reported a
zero-second slowest input.

The corresponding final-source post-run canonical listing facts were:

| Target | Listing bytes/LF | SHA-256 |
|---|---:|---|
| `qk_core_io_peer` | 2,416/36 | `5a6b22681a307e8e7a0478d111e314e92800dbfbc009c04b2d3403a509a3c1db` |
| `qk_core_session` | 8,151/120 | `746bd06e82ff2ef9c6e2135416902fd0e2d0f9b39b8a476651dad78e412d34e2` |
| `qk_core_provisioning_entry` | 17,553/258 | `5c06120d7273cc0795f6a6553be8adb0c6c0679ace64886c12f375afe520b6a5` |
| `qk_core_provisioning_run` | 13,751/202 | `7f7622a27faf4b6dbf4b3fc6f71fff1ef5f1e2ca1dc1a94dc0d612932fe929a4` |
| `qk_core_normal_entry` | 3,581/53 | `58e75e005aed7d908f79cc276045587a7ea6e2d0c853eba1a1b146fcdff3e4e2` |
| `qk_core_normal_run` | 10,809/160 | `3140a1863241168d1778e275cd2d5a16cba163bb369d0d02e7b4f2cfde5faf4d` |
| `qk_core_kit_intake` | 2,010/30 | `f2f903cc8e8b70c4a661ebd6585482f44b0f7d73e3cca3aa396d3d542848b575` |
| `qk_core_kit_restore` | 3,819/57 | `6e74969eec067eac3f0df5d1b09a0f94901ff4e649cd0c9890a05035edae6c36` |
| `qk_core_kit_spend` | 3,484/52 | `721b9172e69c96e0ccffaa216217cff68c48194141a11d743432b4513aeb418c` |

Two separately copied post-run corpora for each completed target were minimized
through an unchanged confirmation pass and agreed byte for byte. The retained
fixed points and their immediately prior registered entry hashes were:

| Target | Final-source progression | Final canonical listing bytes/LF/SHA-256 | Prior registered entry hash | Final entry hash |
|---|---|---|---|---|
| `qk_core_io_peer` | 36/232 unchanged | 2,416/36/`5a6b22681a307e8e7a0478d111e314e92800dbfbc009c04b2d3403a509a3c1db` | `a9ce239a7d67870d797d69b92ebcba48b03d26899457e9f607f6e5af5e422d73` | unchanged |
| `qk_core_session` | 120/10,482 → 114/9,607 → unchanged | 7,739/114/`8efc540b28afbfb37322ed5a44ff1f1cdf4d147f14b8e043edaa2825451118d9` | `8c1e719da5be1babfd58bf51334a2ce64a660160e2b3a530f37788a459155181` | `4518069234644e038d07cca1ab537a3446598f4bc61eeaf1f596c60586487c5e` |
| `qk_core_provisioning_entry` | 258/11,308 → 244/10,471 → unchanged | 16,599/244/`864f48662dbc25ca1491bb22822b6c4c9233cdcfea186626e909afffe1adf464` | `502c9762fea566fa8e23ab0c1ec2ce2088fe194a9294b7fc684da72132956f3f` | `6d770478d241f3521a9f0ae450159a6ec0906a2a50aadc9596acabd5f1120916` |
| `qk_core_provisioning_run` | 202/11,200 → 200/11,006 → unchanged | 13,614/200/`29b4ee945ea4d6d6b9c28259e6d52411c8a6cd3f98db51e7ef916a23646a098c` | `e0e3228f11b236370ae5ee506c778e732a989176723c914a46ebfe48af5bd784` | `9cfd9c0955dd55ec8b2de6251de40415ed3b675aff2569a18a7ef5ec37baa2ec` |
| `qk_core_normal_entry` | 53/762 unchanged | 3,581/53/`58e75e005aed7d908f79cc276045587a7ea6e2d0c853eba1a1b146fcdff3e4e2` | `f3de20565da23312914b73801e4bfbe4230a5e7644d2ea1d452fab3851bcb02c` | unchanged |
| `qk_core_normal_run` | 160/3,015 → 151/2,517 → 150/2,511 → unchanged | 10,131/150/`45e3c8c0cc8e7a7435bc372ac77048dc5d90f8c5cec0d97959837f46fca59149` | `0a84aecb9425f4ea61e133c67d426424b8c3368f87829a701dc329786d33e39d` | `c36240604c659902cd3e0b5d923029717a6d73afc94962c1c8a65b559046a390` |
| `qk_core_kit_intake` | 30/38 unchanged | 2,010/30/`f2f903cc8e8b70c4a661ebd6585482f44b0f7d73e3cca3aa396d3d542848b575` | `a52a11e19e9796cfc64c5c4cff4477c1cfd91108fd1d08cf224268aa02670a87` | `f6c8456d4f759f351b01ae29c2ed74bb631da4b923b1b2da90dc2d3b154bb3d8` |
| `qk_core_kit_restore` | 57/78 → 56/76 → unchanged | 3,752/56/`b2c81ab6be7132b89f085eeff03234b0f7c229e99e131340dcac448f7ebe03ad` | `da4f78111481366042e842892875d9523798980570e613ebe34302f679ae3ada` | `7cbed5dfb16b9b4702710375aea9ab28aa6403532342fe6986a9c5899dc43ae5` |
| `qk_core_kit_spend` | 52/183 unchanged | 3,484/52/`721b9172e69c96e0ccffaa216217cff68c48194141a11d743432b4513aeb418c` | `41e0133903747b3bc85bf9606f86616591b08b051ff5a9598f9eb607bc5632fa` | `c26d0163a409da8f00ecc75ec87a466b04a9416d85041db78670330842657fc2` |

Every minimization pass exited zero and every target artifact directory stayed
empty. Each retained directory was promoted only after both copies agreed.

## Final manifests

All four final manifests bind campaign source
`3cc194c7f278193cad8148360bb43c7974cae6de`:

| Partition | Aggregate count/bytes/entries SHA-256 | Manifest bytes/LF/SHA-256 |
|---|---|---|
| PROCESS-S4 | 150/9,839/`8193a94323b7b800a1ad85e078e95cdcab86e94ded0d9b32c0ec4ddec0a3e643` | 24,492/158/`8b2656b77a0179c7dc29eee37a3e474631909908b9e7e3bc1f99f69bf2b2690f` |
| PROCESS-S5 | 444/21,477/`dc53e72dab3139cc406f0693e71131348408ccf14eb9536b45727903356d5cb0` | 80,611/452/`44739bf75bbe0de3584273f48905c71729ed2fbdcf5b5a894591b428207c643c` |
| PROCESS-S6 | 203/3,273/`3154f2b99719f332280c577ac9b74bb97525068673f86c96db071189f5ce9ff3` | 34,371/211/`da25490623e41762f190915cb13d7cd8f2d2a3ce1f1f0b718fc34c314e82eb61` |
| PROCESS-S7 | 935/34,886/`ee8856edc0a73373d1d22a1f891ea15272ab4e3b17408db3597ace1e1b2eafbd` | 162,164/950/`bcf444134678faeefa40c53233cf72ea69229995a477c520403814bd81bfffe4` |

The per-target counts, byte totals and entry hashes are the registered rows in
those manifests; the canonical-listing hashes use the distinct serialization
defined below.

## Publication-tree retained-corpus replay

The nine requalified corpora loaded 935 files/34,886 bytes and executed 944
units. The same 38 replay-only roots enumerated in the opening replay loaded
6,123 files/413,108 bytes and executed 6,170 units. Across all 47 retained
corpus roots, 7,058 files/447,994 bytes executed 7,114 units. Every pre/post
filename-size-hash listing was identical; every target added zero units,
created zero artifacts and exited zero under the pinned nightly and
AddressSanitizer. The final replay included the pin-only
`4baf9a2b09870ff66095154f3add004c6edf08cf` state.

## Hash domains

- A corpus-file SHA-256 is over the exact payload bytes.
- A canonical listing hash is SHA-256 over the complete LF-terminated,
  bytewise-sorted ASCII sequence
  `lowercase_payload_sha256<TAB>decimal_payload_bytes<LF>`; filenames and
  paths are excluded.
- A manifest target `entries_sha256` is SHA-256 over that target's exact
  LF-terminated rows
  `class<TAB>target<TAB>bytes<TAB>sha256<TAB>path<LF>`, emitted in target order
  and C-locale path order.
- A manifest aggregate hash uses the same entry rows concatenated for all
  targets in their declared order.
- A manifest-file SHA-256 is over the exact complete manifest bytes.
- Replay identity compares C-locale-sorted
  `basename<TAB>bytes<TAB>payload_sha256<LF>` listings before and after replay.
