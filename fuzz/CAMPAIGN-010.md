# V2 slice-4 campaign 010

Status: EXECUTED — QUALIFYING RUN COMPLETE.

Fuzz-target source commit:
`8322b9b982662bb7d9637fdba699c2d318440f7a`.
Qualifying-run tree and committed-seed source:
`ae8f4084c799bfbb394f8a55896f93dec63b84b8`.

The fixed tool identities were cargo-fuzz 0.13.2;
`nightly-2026-08-25`; rustc
`1.100.0-nightly (e7769602a 2026-08-24)`; AddressSanitizer;
release-profile overflow checks and debug assertions enabled; dependency
resolution offline. The qualifying run started from exactly five committed
`qk_provisioning_v2_inputs` seeds totaling 13 bytes and one committed
`qk_provisioning_v2_chain` seed totaling 6 bytes. Their initial manifest
entry-block SHA-256 values were respectively
`832aed531c274a6ec5e067b6a38993599e1674873c14b1cce1acf2dede58f5a8`
and `7566cde0a0c818eea9d3be773f439ba5a792f2b258a742e0e0ce72a534f2d15c`;
the six-entry/19-byte aggregate entry-block SHA-256 was
`0b02b6430cb3b33a5ed32b03af074a7619308489d22c36c1e51f53b0d289ea5f`.
Preflight replay loaded those exact sets and executed 6 and 2 units at
coverage/features 1,145/2,138 and 1,237/1,237, with peak RSS 44 and 41 MiB,
zero new units, zero slow units and zero artifacts.

Commit `030e271fe9955e39347c0475261aa7456bf9007c` introduced the two targets.
Before any qualifying execution, commit
`8322b9b982662bb7d9637fdba699c2d318440f7a` replaced a coarse transcript
oracle with exact input-category classification, added a test/fuzz-only
production/reference Kit-R equality check, and added an explicit test/fuzz-only
owner-drop zero assertion. No non-test/fuzz behavior changed, no campaign
finding caused that correction, and no earlier generated corpus unit was
retained. Commit `ae8f4084c799bfbb394f8a55896f93dec63b84b8`
then registered the six exact starting seeds before qualification.

Both campaigns used six deterministic, isolated shards. The fixed arithmetic
was `16,666 * 5 + 16,670 = 100,000` executions per target. Input-state shards
used seeds 124001, 124003, 124005, 124007, 124009 and 124011 with maximum
length 1,024; chain-state shards used seeds 124002, 124004, 124006, 124008,
124010 and 124012 with maximum length 512. Every shard fixed timeout 2 s, RSS
limit 2,048 MiB, corpus reload off, its own temporary copy of the committed
seed set, its own empty artifact directory, and AddressSanitizer. The exact
command shape was:

```text
CARGO_NET_OFFLINE=true PATH=/private/tmp/qk-cargo-fuzz/bin:$PATH cargo +nightly-2026-08-25 fuzz run TARGET TEMP_CORPUS --fuzz-dir fuzz --sanitizer address -- -runs=RUNS -seed=SEED -max_len=MAX_LEN -reload=0 -timeout=2 -rss_limit_mb=2048 -print_final_stats=1 -artifact_prefix=TEMP_ARTIFACT/
```

The six input-state shards ran from 2026-08-29T02:55:45Z through
2026-08-29T03:12:57Z. They executed 16,666, 16,666, 16,666, 16,666, 16,666
and 16,670 units in 924, 1,030, 997, 901, 971 and 1,030 engine seconds at
18, 16, 16, 18, 17 and 16 executions per second. They added 116, 94, 102,
110, 118 and 109 engine units. Final coverage/features were 1,242/2,356,
1,242/2,345, 1,242/2,357, 1,242/2,342, 1,242/2,356 and 1,242/2,360;
engine corpus files/bytes were 81/728, 74/482, 76/522, 75/479, 82/605 and
79/641. Post-run filesystem files/bytes were 84/737, 77/491, 79/531, 78/488,
85/614 and 82/650, totaling 485 files/3,511 bytes before deduplication. Peak
RSS was 422 MiB for every shard; every shard exited zero with zero slow units
and zero artifacts.

The six chain-state shards ran from 2026-08-29T03:13:11Z through
2026-08-29T03:53:00Z. They executed 16,666, 16,666, 16,666, 16,666, 16,666
and 16,670 units in 2,384, 2,382, 2,387, 2,381, 2,383 and 2,384 engine
seconds, all at 6 executions per second. They added 134, 143, 154, 131, 134
and 140 engine units. Final coverage/features were 1,377/2,014, 1,378/2,020,
1,379/2,027, 1,379/2,023, 1,378/2,019 and 1,378/2,019; engine corpus
files/bytes were 118/862, 129/877, 135/881, 122/949, 126/859 and 129/916.
Post-run filesystem files/bytes were 118/862, 128/875, 135/881, 121/947,
126/859 and 129/916, totaling 757 files/5,340 bytes before deduplication.
Peak RSS was 421 MiB for every shard; every shard exited zero with zero slow
units and zero artifacts. All twelve shards together executed exactly 200,000
units.

For every presented input, the input-state target executed its selected raw
transcript, exact precedence scenario or nonce-state path twice and required
byte-equal typed outcomes. Its exact classifier enforced `DiceCount` for a
101st byte before inspecting that byte, `InvalidDiceSymbol` for an in-range
non-face byte, all six pairwise `TranscriptReuse` cases, and representative
multiple-reuse shapes: one triple, one disjoint pair and all-four reuse,
valid-transcript construction, `NonceReuse` for a repeated nonce,
`AlreadyEncrypted` for a later different nonce, fresh-run reproducibility,
exhaustive named errors and no partial artifact.

For every presented input, the chain-state target built four deterministic
public transcripts twice and required byte-equal public artifacts. It strictly
reparsed both v2 descriptors, tied wallet ID, reconstructed receive-0 and
change-0 scripts, decoded both Bech32 addresses back to the script programs,
authenticated the A1 capsule, compared the opened public Seed-A value, tied
the production Kit-R result to the separate reference path, exercised explicit
owner drop and zero assertion, and required a repeated same-run encryption to
return `NonceReuse` without an artifact.

The six post-run input directories produced a serial, content-addressed
436-file/3,402-byte union. Its 29,378-byte sorted `SHA-256<TAB>bytes` listing
has SHA-256
`5d6a66a5b59af211c3f821f49d3a94231c698244156f0903d4f2dc5e0bd7043b`.
Repeated SHA-256-ascending minimization progressed through 86/652, 85/642,
82/611, 81/601 and unchanged 81/601 file/byte sets. The respective listing
SHA-256 values were
`d4fd2d7d48a72bc459cde6d85fdabe35f04c922d04c420e7716808928da4c8f6`,
`6dd3059b5d941da61eb23ced8c272a3f88e975edd344705f945670f12298ec74`,
`f80df5aa9280bdafa8d7c2bd36db8396a3ac0261c88611149757e8702d016cf1`,
and twice
`d17d64b01d1ad9f414ab5d50d222d6cae036a7c2ae1dc0cd5fe30f00a90abdb3`.
Fresh ascending and descending minimizations both preserved that exact
81-file/601-byte set and its 5,454-byte listing.

The six post-run chain directories produced a serial, content-addressed
744-file/5,280-byte union. Its 49,941-byte listing has SHA-256
`a9fc8767ec31361e35c9c9df6837d06bf6557a143ff66d66a9b254070b1d1289`.
Repeated SHA-256-ascending minimization progressed through 129/694, 118/621,
114/612, 112/562, 110/556 and unchanged 110/556 file/byte sets. The respective
listing SHA-256 values were
`03576c8a971a5d9e00f121ea5e01b9431a914cd47462f22a6abaca44e75710b4`,
`1e77e0a8feb4011b147ba36c9e51a4aa95c1e3a36efa260267c38298b66b6def`,
`a3d7149f90c43fd3019457d6bbbb4fcec80c8ffa4b0195edfce15a42e1d4c34c`,
`e467ae2bd2d004a26772c59c02b63691913a3d9fbc9a37847320c3e615e64b57`,
and twice
`134cb9f0204c6f550a7ca86192cc84252ee2aff5df34cfbfff40a0d2df8c2ed1`.
Fresh ascending and descending minimizations both preserved that exact
110-file/556-byte set and its 7,381-byte listing. No concurrent process wrote
either union or minimization directory.

Before import, AddressSanitizer replay preserved both proven listings exactly.
The input set executed 82 units in 1 second at coverage/features 1,242/2,360
and peak RSS 74 MiB. The chain set executed 111 units in 13 seconds at
coverage/features 1,379/2,034 and peak RSS 301 MiB. Both had zero new units,
zero slow units and zero artifacts.

Those two proven sets became the persistent corpora. Their manifest entry
blocks have SHA-256
`3f77b4af50af1d8c425844d8ab7aa15b87e6f97d6729ba76bffa5167b74bb873`
and `60d7880c5c09c9bd9ba06ac812ef431bb17792f33017d6d61da4365a9dd5a529`.
`CORPUS-MANIFEST-V2-S4.tsv` is 39,160 bytes/199 LF with SHA-256
`30162a3ebe34ccc300ce05c2b71e5c33472e00f7c27e968fa664e1e7f152e783`;
its aggregate is 191 files/1,157 bytes with entry-block SHA-256
`483d68403d80e007d062e930642e07de2ca1ee687e8527d1cc67b89d3faa7764`.
The complete cross-partition path and hash check passed.

Retained-corpus replay loaded 81 input files/601 bytes and executed 82 units
in 1 second at coverage/features 1,242/2,360, then loaded 110 chain files/556
bytes and executed 111 units in 13 seconds at 1,379/2,034. Peak RSS was 74 and
301 MiB; new units, slow units and artifact files were zero. Both replays
exited zero.

Across both qualifying campaigns, minimization, pre-import replay, import and
retained replay, panic, timeout, sanitizer finding, wrong acceptance, wrong
named rejection, partial artifact and residual fuzz artifact counts were all
zero. No product source or target oracle changed after qualification began.
