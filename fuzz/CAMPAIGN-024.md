# Process slice 5 campaign 024

Status: EXECUTED — QUALIFYING RUN COMPLETE.

The initial common product-and-fuzz source commit was
`0e505e213e280ac0510d023146ed6864b8bcf4a6`. The byte-frozen
`qk_core_io_peer` and `qk_core_session` target sources remained at
`e416080d8867fc381bdcc6aa1a26382f4767b6b8`, but both requalified against the
common source's expanded qk-core product and fuzz closure. The fixed tool
identities were cargo-fuzz 0.13.2; `nightly-2026-08-25`; rustc
`1.100.0-nightly (e7769602a 2026-08-24)`; AddressSanitizer; release-profile
overflow checks and debug assertions enabled; and offline dependency
resolution. The exact qualifying commands were:

```text
fuzz/run-bounded.sh qk_core_io_peer 100000
fuzz/run-bounded.sh qk_core_session 100000
fuzz/run-bounded.sh qk_core_provisioning_entry 100000
fuzz/run-bounded.sh qk_core_provisioning_run 100000
```

All runs used corpus reload disabled, a two-second input timeout, 2,048 MiB
RSS ceiling and final-stat reporting. Target seeds and maximum inputs were
respectively 144001/16,384, 144002/4,096, 145001/1,024 and 145002/512.

`qk_core_io_peer` started from its 32-file/243-byte PROCESS-S4 set. It
executed exactly 100,000 inputs in 6 seconds at 16,666 executions per second,
finished at coverage/features 681/820, added 22 engine units, had a
zero-second slowest unit, peaked at 460 MiB RSS, and created zero artifact
files. The final live engine statistic was 37 units/251 bytes; the post-run
filesystem corpus contained 54 files/417 bytes. That filesystem corpus's
3,633-byte sorted `SHA-256<TAB>bytes` listing had SHA-256
`b314354c637c9b04114544150ae878d0c3e4a578576ef56783a2d6b047c3b251`.

`qk_core_session` started from its 102-file/5,996-byte PROCESS-S4 set. It
executed exactly 100,000 inputs in 8 seconds at 12,500 executions per second,
finished at coverage/features 845/2,142, added 66 engine units, had a
zero-second slowest unit, peaked at 501 MiB RSS, and created zero artifact
files. The final live engine statistic was 113 units/9,363 bytes; the
post-run filesystem corpus contained 154 files/13,878 bytes. That filesystem
corpus's 10,463-byte sorted `SHA-256<TAB>bytes` listing had SHA-256
`a557c6b10a3780723a709729efc875d9377cf925be5c7817a1b1ce37b7b1d1a7`.

The QK-DEC-145 fixed-point stop condition fired because both expressly
requalified PROCESS-S4 sets changed. QK-DEC-146 authorized promotion and
Campaign 023 remains immutable. The predecessor target entry-block hashes
were `1b4f7b437dee3d89c7d454b91eb1ccc8cfe2cf05a8440c5b2e2a316863a4c2e0`
and `115a5840d3453b3d9b2118ed2da6e671a8353d438a98ff0ca2e0ad0bca541d2d`;
their predecessor 134-file/6,239-byte aggregate entry-block hash was
`449a0b8dc0ef4f499c1bd6d262aadaffbd4602b7b591e3edeeaa41cf4ba5bc69`.
The predecessor PROCESS-S4 manifest was 21,929 bytes/142 LF with SHA-256
`478d2f18cf56e897855c9225bf0e3422415a2b1b75ad8e4ece97f8d3cf22aa5f`.

Two copies of each requalified corpus were minimized serially. Both peer
copies followed the same progression:

- 54 files/417 bytes, 3,633-byte listing SHA-256
  `b314354c637c9b04114544150ae878d0c3e4a578576ef56783a2d6b047c3b251`;
- 35 files/240 bytes, 2,350-byte listing SHA-256
  `eb01a039aab1de18c63592c3efe7712d40cf04d248337c18b5c3bf3e2d22b4d4`;
- a further pass left that 35-file set unchanged.

Both session copies followed the same progression:

- 154 files/13,878 bytes, 10,463-byte listing SHA-256
  `a557c6b10a3780723a709729efc875d9377cf925be5c7817a1b1ce37b7b1d1a7`;
- 108 files/8,520 bytes, 7,325-byte listing SHA-256
  `fc0803e63a64c1278769a4a32f5b71e223ef53f76ffb1c229c2c92961948566d`;
- 107 files/8,515 bytes, 7,258-byte listing SHA-256
  `6401bb5cac3f941d4714facb05a5137354b76ab05f1b831ab272400351cd5f1d`;
- a further pass left that 107-file set unchanged.

The two fixed-point listings and directories agreed byte for byte for each
requalified target. The promoted `qk_core_io_peer` entry block has SHA-256
`9404c28e278846f7bc6fa3d6e7d87d29aac642652e66bb3eec014ae9505f448c`;
the promoted `qk_core_session` entry block has SHA-256
`b8f208afeed6941173cc575cdb98f7714db7746237df9a3a9acf96c75cc4b2d0`.
Their replacement aggregate is 142 files/8,755 bytes with entry-block
SHA-256
`735d937398c928bac2e45e692d9075e1f366263f34d2e8d28c78b23d8f973c42`.
`CORPUS-MANIFEST-PROCESS-S4.tsv` is 23,209 bytes/150 LF with SHA-256
`0c2fbd5def18d29ce844f616e3c9b7fae68280cbfb6dc780840931b79c793845`.

`qk_core_provisioning_entry` started from 225 public units totaling 6,525
bytes: the full nineteen-key by five-count matrix, the full nineteen-key by
six-stage matrix, all six reuse pairs and all ten interruption positions. It
executed exactly 100,000 inputs in 1,405 seconds at 71 executions per second,
finished at coverage/features 2,256/3,495, added 205 engine units, had a
zero-second slowest unit, peaked at 467 MiB RSS, and created zero artifact
files. The final live engine statistic was 271 units/12,314 bytes; the
post-run filesystem corpus contained 389 files/15,735 bytes. That filesystem
corpus's 26,464-byte sorted listing had SHA-256
`db85ba4a9e92e6104023f9448dfe310e3a59c84339aa6e98fcb2cbd1acfec0e5`.

Two entry-corpus copies were minimized serially. Both followed the same
progression:

- 389 files/15,735 bytes, 26,464-byte listing SHA-256
  `db85ba4a9e92e6104023f9448dfe310e3a59c84339aa6e98fcb2cbd1acfec0e5`;
- 259 files/11,388 bytes, 17,622-byte listing SHA-256
  `304a1072b270cda9d321224943e2fc19adb9f9a353987aada7b06718e16e4b4e`;
- 251 files/11,069 bytes, 17,078-byte listing SHA-256
  `9c76bf5c9a8d466fb584ec805b758b59451a589ba24259ed453e9409d5dd7d07`;
- 249 files/11,011 bytes, 16,942-byte listing SHA-256
  `7ff6b88c1a3af1ca86fcbcf04504faf9020daa4c39b3ec2ccfedb3e48c0bcc98`;
- a further pass left that 249-file set unchanged.

`qk_core_provisioning_run` started from 22 public units totaling 660 bytes,
covering complete no-spare and spare flows, scenarios 2 through 5, all four
Kit receipt positions, all ten interruptions, the invalid-card action and card
removal. It executed exactly 100,000 target inputs in 442 seconds at 226
executions per second, finished at coverage/features 2,828/4,678, added 192
engine units, had a zero-second slowest unit, peaked at 272 MiB RSS, and
created zero artifact files. The final live engine statistic was 196
units/9,480 bytes; the post-run filesystem corpus contained 202 files/9,660
bytes. That filesystem corpus's 13,740-byte sorted listing had SHA-256
`5d140e61a53f159ef462aa95cd9976968a914d18896a66d117b28861fd6398d8`.
The total is target inputs, not 100,000 complete provisioning flows; inputs
outside the deterministic one-in-256 admission fold take bounded named
pre-provisioning paths.

Two run-corpus copies were minimized serially. Both followed the same
progression:

- 202 files/9,660 bytes, 13,740-byte listing SHA-256
  `5d140e61a53f159ef462aa95cd9976968a914d18896a66d117b28861fd6398d8`;
- 171 files/7,870 bytes, 11,628-byte listing SHA-256
  `ff70884eaad26271a0eaf4212c10399b48a9e4bc1f31fd4e5d9cc0de2c405752`;
- 170 files/7,838 bytes, 11,560-byte listing SHA-256
  `31e5a9977e29043e2deaf0dccac40ca5c82da5dfad3eae6736638607a0e8e0c0`;
- a further pass left that 170-file set unchanged.

The two fixed-point listings and directories agreed byte for byte for each
new target. `qk_core_provisioning_entry` retained 249 files/11,011 bytes with
manifest entry-block SHA-256
`17d8e2065acc3048ac14f5cb140d76780fac2309056326be03e08914661e4edc`;
`qk_core_provisioning_run` retained 170 files/7,838 bytes with entry-block
SHA-256
`2039ce682cc3a074027a14f0b1a807c4d2ef396d727dd8d193247897050f29fb`.
The PROCESS-S5 aggregate is 419 files/18,849 bytes with entry-block SHA-256
`e4a43417fc6daaaa8f4751f2c56f790caab16f055754a987842f8fd9debc7070`.
`CORPUS-MANIFEST-PROCESS-S5.tsv` is 76,169 bytes/427 LF with SHA-256
`88a01a5fe6e0cad774aa139446e224f8792395a6f8fd7e31c6737707ce26d976`.

Retained-corpus replay for `qk_core_provisioning_entry` loaded all 249 files
totaling 11,011 bytes and executed 250 units. It finished at
coverage/features 2,256/3,495, added zero units, had a zero-second slowest
unit, peaked at 44 MiB RSS, created zero artifact files, and exited zero.
`qk_core_provisioning_run` loaded all 170 files totaling 7,838 bytes and
executed 171 units. It finished at coverage/features 2,828/4,678, added zero
units, had a zero-second slowest unit, peaked at 47 MiB RSS, created zero
artifact files, and exited zero.

The other 40 registered corpora loaded 6,265 files/421,863 bytes and executed
6,314 replay units in total. They added zero units, created zero artifact
files, and exited zero. Across all 42 retained corpora, 6,684 files/440,712
bytes executed 6,735 replay units.

## Post-format requalification

The first full `tools/check.sh` run after the initial evidence registration
rejected two formatter-only line wraps in `host/qk-core/src/capability.rs`.
Commit `c32eeba2be9dd6294dd98569f7cddef0b4d3d496` applied only those `rustfmt`
changes (two insertions and eight deletions); it changed no type, signature,
branch, value or comment. Because the file is fuzz-relevant, all four Campaign
024 targets were restarted from zero against that source with the same
commands, seeds, bounds, toolchain and AddressSanitizer settings recorded
above.

`qk_core_io_peer` started from the promoted 35-file/240-byte set, executed
exactly 100,000 inputs in 7 seconds at 14,285 executions per second, finished
at coverage/features 681/820 with a live engine statistic of 35 units/232
bytes, added 8 engine units, had a zero-second slowest unit, peaked at 438 MiB
RSS, and created zero artifact files. Its post-run filesystem corpus contained
43 files/286 bytes; the canonical 2,887-byte sorted listing had SHA-256
`9108bad1ed7bbb5aacafd41c2c2126e254d8ffd6a00b9afed4ef27ac2c788b42`.

`qk_core_session` started from the promoted 107-file/8,515-byte set, executed
exactly 100,000 inputs in 9 seconds at 11,111 executions per second, finished
at coverage/features 845/2,392 with a live engine statistic of 116 units/9,833
bytes, added 42 engine units, had a zero-second slowest unit, peaked at 505 MiB
RSS, and created zero artifact files. Its post-run filesystem corpus contained
140 files/15,256 bytes; the canonical 9,519-byte sorted listing had SHA-256
`92907628451ec802ea9796017aa29161d29bcfc3e7495b9e698b5c91e45c8d3d`.

`qk_core_provisioning_entry` started from the promoted 249-file/11,011-byte
filesystem set; libFuzzer initialized 247 live units/10,953 bytes. It executed
exactly 100,000 inputs in 1,827 seconds at 54 executions per second, finished
at coverage/features 2,256/3,505 with a live engine statistic of 251
units/11,346 bytes, added 40 engine units, had a zero-second slowest unit,
peaked at 474 MiB RSS, and created zero artifact files. Its post-run filesystem
corpus contained 286 files/13,763 bytes; the canonical 19,468-byte sorted
listing had SHA-256
`9415e15a58fe8beb6b8a12fadd64e5d27ce3a9ababb73ec9af88258cd5194e0f`.

`qk_core_provisioning_run` started from the promoted 170-file/7,838-byte
filesystem set; libFuzzer initialized 169 live units/7,837 bytes. It executed
exactly 100,000 inputs in 757 seconds at 132 executions per second, finished
at coverage/features 2,829/4,719 with a live engine statistic of 192
units/9,765 bytes, added 29 engine units, had a zero-second slowest unit,
peaked at 381 MiB RSS, and created zero artifact files. Its post-run filesystem
corpus contained 194 files/9,825 bytes; the canonical 13,200-byte sorted
listing had SHA-256
`a740807576204a0e2b9e3adb51514643e22fb625f984ea65539d5dfd0409a7ca`.

Two fresh copies of every post-format filesystem corpus were minimized
serially. The two copies followed identical progressions for each target and
their final listings and directories agreed byte for byte:

- `qk_core_io_peer`: 43 files/286 bytes, 2,887-byte listing SHA-256
  `9108bad1ed7bbb5aacafd41c2c2126e254d8ffd6a00b9afed4ef27ac2c788b42`;
  36 files/230 bytes, 2,416-byte listing SHA-256
  `efcffe301a74e507fe00c4df7e1749c59255b12705d4c12d0b7d972351eb1045`;
  35 files/228 bytes, 2,349-byte listing SHA-256
  `19c3fa67416335e7507390275fe1af246b1f47ff51f3e74f16ff8da45317cb8f`;
  and one further unchanged pass.
- `qk_core_session`: 140 files/15,256 bytes, 9,519-byte listing SHA-256
  `92907628451ec802ea9796017aa29161d29bcfc3e7495b9e698b5c91e45c8d3d`;
  114 files/9,217 bytes, 7,739-byte listing SHA-256
  `5b30428c4e864d0954befb0dd57fd15af5774352ff10cbc85267257953c9cc3c`;
  and one further unchanged pass.
- `qk_core_provisioning_entry`: 286 files/13,763 bytes, 19,468-byte listing
  SHA-256
  `9415e15a58fe8beb6b8a12fadd64e5d27ce3a9ababb73ec9af88258cd5194e0f`;
  247 files/11,155 bytes, 16,808-byte listing SHA-256
  `b05340b75f6b1d375207c592ffa0ab8caf62340ad1c745720879084d50b849d8`;
  and one further unchanged pass.
- `qk_core_provisioning_run`: 194 files/9,825 bytes, 13,200-byte listing
  SHA-256
  `a740807576204a0e2b9e3adb51514643e22fb625f984ea65539d5dfd0409a7ca`;
  190 files/9,520 bytes, 12,927-byte listing SHA-256
  `365af43ce85ab222ee94e5b888ddb8f5bfd203c9dc5d1671a669534f75d2e119`;
  and one further unchanged pass.

Before this second promotion, the target entry-block hashes were
`9404c28e278846f7bc6fa3d6e7d87d29aac642652e66bb3eec014ae9505f448c`,
`b8f208afeed6941173cc575cdb98f7714db7746237df9a3a9acf96c75cc4b2d0`,
`17d8e2065acc3048ac14f5cb140d76780fac2309056326be03e08914661e4edc`
and `2039ce682cc3a074027a14f0b1a807c4d2ef396d727dd8d193247897050f29fb`
in target order. The predecessor PROCESS-S4 aggregate entry-block hash was
`735d937398c928bac2e45e692d9075e1f366263f34d2e8d28c78b23d8f973c42`;
its 23,209-byte/150-LF manifest had SHA-256
`0c2fbd5def18d29ce844f616e3c9b7fae68280cbfb6dc780840931b79c793845`.
The predecessor PROCESS-S5 aggregate entry-block hash was
`e4a43417fc6daaaa8f4751f2c56f790caab16f055754a987842f8fd9debc7070`;
its 76,169-byte/427-LF manifest had SHA-256
`88a01a5fe6e0cad774aa139446e224f8792395a6f8fd7e31c6737707ce26d976`.

The replacement PROCESS-S4 target entry-block hashes are
`322481cfab35c36da25d81bbf0a98272bf51bf8735c786aec6d8eb006eba9434`
and `706bab5fbe927cdf66f5439ab27ff701578d5369f5d7c53cb1ad99cf7c49166f`.
Its aggregate is 149 files/9,445 bytes with entry-block SHA-256
`8cc5887300434b9f42250bfbe7b32d4f8caf9e3dbcb6a6b9e00ad690cac4b6e0`;
the 24,333-byte/157-LF manifest has SHA-256
`e24047c32e582c3631e4ff3e249787096b5b8ac266ebb985185de5e36389d96f`.
The replacement PROCESS-S5 target entry-block hashes are
`9182722863e5b8cd9c68cc4f5b6f24af4ff2e77708c62ec7d896726db2dd2081`
and `0e89c276922177a5ccb4c7351acd5d2779492707afa6ebfc467a5a1a22650bfc`.
Its aggregate is 437 files/20,675 bytes with entry-block SHA-256
`5c5c2823fcca36bc7508c2183c496be0a3ee71b7b6f7d82df2fe69a6795afd94`;
the 79,374-byte/445-LF manifest has SHA-256
`36953ec4112ae9bf01f8aba6b47d389757de9ef1d37443ed327b3c4ffc8fe6c8`.
Both manifests bind campaign source
`c32eeba2be9dd6294dd98569f7cddef0b4d3d496`.

Final-tree replay loaded all 42 registered corpora: 6,709 files/443,228
bytes executed 6,760 units, added zero units, created zero artifact files and
exited zero. The four requalified targets respectively loaded 35/228,
114/9,217, 247/11,155 and 190/9,520 files/bytes and executed 36, 115, 248 and
191 units; their final coverage/features were 681/820, 845/2,392,
2,256/3,505 and 2,829/4,719. The other 38 corpora loaded 6,123 files/413,108
bytes and executed 6,170 units, with zero additions and zero artifact files.

The entry oracle covered every entry key, count and stage, exact echo,
commitment and order, all six reuse pairs, every interruption, terminal
absorption, repeat consistency and wipe accounting. The run oracle covered
card and spare choices, hostile A1 scan-back, exact A1 and four-page Kit
egress and receipts, page ordering, every interruption, terminal absorption,
repeat consistency and wipe accounting. Across qualification, minimization,
registration and every retained-corpus replay, the observed panic, timeout,
sanitizer-report, wrong-acceptance, unnamed-rejection, repeat-mismatch,
wipe-mismatch and artifact-file counts were zero. No product source or target
oracle changed after the post-format qualification began at
`c32eeba2be9dd6294dd98569f7cddef0b4d3d496`.
