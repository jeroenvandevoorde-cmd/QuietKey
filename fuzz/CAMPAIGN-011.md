# V2 slice-5 campaign 011

Status: EXECUTED — QUALIFYING RUN COMPLETE.

Fuzz-target source commit:
`e0582e6c2d4f5873a9a8324a40cc512b307e270c`.
Qualifying-run tree and committed-seed source:
`e33a85fdee5b472dbcc41fcd23931ceaee339ddb`.

The fixed tool identities were cargo-fuzz 0.13.2;
`nightly-2026-08-25`; rustc
`1.100.0-nightly (e7769602a 2026-08-24)`; AddressSanitizer;
release-profile overflow checks and debug assertions enabled; dependency
resolution offline. The qualifying runs started from exactly three committed
`qk_host_sim_v2_s5_screen` seeds totaling 6 bytes and five committed
`qk_host_sim_v2_s5_manual_keypad` seeds totaling 10 bytes. Their initial
manifest entry-block SHA-256 values were respectively
`22de820d4740b0b11538fe020e921c4d1a64866dfff0daaff41f62e0f5eb00bb`
and `ad3177d76ef29fb3332f2dc45608adec385fa5d27c53ed252ec1ba331e10423a`;
the eight-entry/16-byte aggregate entry-block SHA-256 was
`7441720e50ed938ce6aa0d1cedbbe30d9b63522e9f11fd6385a6b24fda81dcab`.

The exact qualifying commands were:

```text
fuzz/run-bounded.sh qk_host_sim_v2_s5_screen 100000
fuzz/run-bounded.sh qk_host_sim_v2_s5_manual_keypad 100000
```

The commands fixed seeds 125001 and 125002, maximum lengths 2,048 and 1,024,
timeout 2 seconds, RSS limit 2,048 MiB, corpus reload off, AddressSanitizer,
and final-stat reporting. The screen run executed exactly 100,000 inputs in
8 engine seconds at 12,500 executions per second. It finished at
coverage/features 693/1,118 with an engine corpus of 160 files/6,740 bytes,
added 346 engine units, had a zero-second slowest unit, peaked at 502 MiB RSS,
and produced zero artifact files. The manual-keypad run executed exactly
100,000 inputs in 543 engine seconds at 184 executions per second. It finished
at coverage/features 1,281/2,054 with an engine corpus of 227 files/6,461
bytes, added 451 engine units, had a zero-second slowest unit, peaked at 499
MiB RSS, and produced zero artifact files. The two qualifying runs therefore
executed exactly 200,000 libFuzzer inputs.

For every presented input, the screen target constructed the registered
schema-v3 review and v2 descriptor facts, ran the selected event sequence
twice, and required byte-equal typed snapshots and outcomes. Its oracles
enforced route and Kit-door immutability, the complete review visitation
ledger, approval identity, no post-hold yield, named transition and mode
rejections, no Kit capability release, and wipe or typed deferred termination.
For every presented input, the manual-keypad target ran the selected P0.1 key
sequence twice and required byte-equal snapshots and outcomes. Its oracles
locked every state-preserving key rejection, exact echo-confirm-commit order,
the four simultaneously retained 100-byte secret buffers, all six pairwise
reuse cases, completion through `HostProvisioningRunV2`, and wipe on every
closed termination path. Neither target releases a retained secret value.

After both writers exited, two stable inventories and empty artifact checks
were recorded before any corpus copy or minimization. The screen filesystem
held 160 files/6,740 bytes; its 10,808-byte sorted
`SHA-256<TAB>bytes` listing had SHA-256
`421ec681441529d44a9f59cd8608d8d1f59f872c0b15df0b65d4da5e9a0ceac4`.
The manual-keypad filesystem held 228 files/6,463 bytes; its 15,405-byte
listing had SHA-256
`c3ac62ef7371780cfb97522b4ccefbf6b7410766cb20dac0c579caa74e5b6f50`.
The one-file/two-byte difference from the manual run's engine inventory is a
committed starting unit retained by the filesystem. Both post-run sets had
zero duplicate content hashes and zero non-regular entries.

Two copies of each stable post-run set were minimized serially. The screen
copies progressed identically from 136 files/6,501 bytes with 9,194-byte
listing SHA-256
`0e84c492438abfdd21f88e02e964c3d0cb2341f9dad049c3b84b68b8c080fad1`
to 132 files/6,409 bytes with 8,925-byte listing SHA-256
`4377a89be905b7f28786ce91c2650ac690fc393374e5b4ad990e6d23df7bf7b5`,
then remained byte-identical on the next pass. Both screen merge paths
preserved coverage/features 2,060/2,486. Fresh proof copies also preserved
that exact set.

The manual-keypad copies progressed identically through 205 files/6,099 bytes
with 13,856-byte listing SHA-256
`e400058d5720ae56fc3308e1e07dacae442af02f247f6f061a0585434c8ee78d`,
200 files/6,033 bytes with 13,518-byte listing SHA-256
`dff2dca5b9683a4ae9301797e3138502d34fc81ea1cecce9ba6468cbf2905b68`,
and 198 files/6,007 bytes with 13,383-byte listing SHA-256
`350f0f02f5fb48fe1769ffa1b10ce57bcd7bf51953600e502b9add26d5658a39`,
then remained byte-identical on the next pass. Both manual merge paths
preserved coverage/features 1,292/2,065. Fresh proof copies also preserved
that exact set. No concurrent process wrote any snapshot, minimization, proof,
or artifact directory.

Before import, AddressSanitizer replay preserved both proof sets exactly. The
screen set loaded 132 files/6,409 bytes, executed 133 units at
coverage/features 693/1,118, peaked at 41 MiB RSS, and added zero units. The
manual-keypad set loaded 198 files/6,007 bytes, executed 199 units at
coverage/features 1,281/2,054, peaked at 44 MiB RSS, and added zero units.
Both had zero slow units and zero artifact files.

Those two proven sets became the persistent corpora. Their manifest entry
blocks have SHA-256
`959d81f50982c34a9d5f0102f85537da57618041447d556c0adc125bcd7c4025`
and `e9f4f5b41858e6bfa3fa8cbb2f87c29aa02173798a100ca9879ca0c91ee4fe6e`.
`CORPUS-MANIFEST-V2-S5.tsv` is 61,965 bytes/338 LF with SHA-256
`4ec63e3d529ed01b48149f23896c44bfc2aae08e8ad24a88e03f7f41c7472b13`;
its aggregate is 330 files/12,416 bytes with entry-block SHA-256
`3834a8d4731a2d49d4d23893475dd78665c8a71c1526f461732f44967f800101`.
The complete cross-partition path and hash check passed.

Retained-corpus replay reproduced the pre-import results: the screen set
executed 133 units at coverage/features 693/1,118 with 41 MiB peak RSS, and
the manual-keypad set executed 199 units at 1,281/2,054 with 44 MiB peak RSS.
Both retained replays added zero units, had zero-second slowest units, created
zero artifact files, and exited zero.

Across both qualifying campaigns, minimization, proof replay, import, and
retained replay, panic, timeout, sanitizer report, wrong acceptance, wrong
named rejection, review skip, post-hold yield, Kit capability release,
secret-output escape, partial artifact, and residual fuzz artifact counts were
all zero. No product source or target oracle changed after qualification began.
