# M26 campaign 006

Status: EXECUTED — QUALIFYING RUN COMPLETE.

Fuzz-target source commit:
`e64b7a5e4d594e903c88a76cd85fa399044433a8`.
Qualifying-run tree and committed-seed source:
`23325f58d71d1ad1832c64e7fffcb637ce976e00`.

The fixed tool identities were cargo-fuzz 0.13.2;
`nightly-2026-08-25`; rustc
`1.100.0-nightly (e7769602a 2026-08-24)`; AddressSanitizer;
release-profile overflow checks and debug assertions enabled; dependency
resolution offline. The qualifying run started from exactly 26 committed
`qk_provisioning_inputs_m26` seeds totaling 76 bytes and three committed
`qk_provisioning_chain_m26` seeds totaling 53 bytes.

The bounded campaigns used six deterministic, isolated shards per target
because complete-chain execution measured about five inputs per second. The
approved arithmetic was `16,666 * 5 + 16,670 = 100,000` executions per target.
Input-state shards used seeds 26001, 26003, 26005, 26007, 26009 and 26011 with
maximum length 1,024; full-chain shards used seeds 26002, 26004, 26006, 26008,
26010 and 26012 with maximum length 512. Every shard fixed timeout 2 s, RSS
limit 2,048 MiB, corpus reload off, its own temporary corpus and artifact
directory, and AddressSanitizer. The exact command shape was:

```text
CARGO_NET_OFFLINE=true PATH=/private/tmp/qk-cargo-fuzz/bin:$PATH cargo +nightly-2026-08-25 fuzz run TARGET TEMP_CORPUS --fuzz-dir fuzz --sanitizer address -- -runs=RUNS -seed=SEED -max_len=MAX_LEN -reload=0 -timeout=2 -rss_limit_mb=2048 -print_final_stats=1 -artifact_prefix=TEMP_ARTIFACT/
```

The six input-state shards executed 16,666, 16,666, 16,666, 16,666, 16,666
and 16,670 inputs in 1,499, 1,593, 1,604, 1,478, 1,664 and 1,639 engine
seconds. They added 163, 177, 158, 151, 156 and 169 engine units; final
coverage/features were 1,353/2,739, 1,352/2,750, 1,353/2,740, 1,352/2,720,
1,353/2,715 and 1,353/2,741. Peak RSS was 424 MiB for every shard.

The six full-chain shards executed 16,666, 16,666, 16,666, 16,666, 16,666
and 16,670 inputs in 3,066, 3,062, 3,062, 3,064, 3,062 and 3,064 engine
seconds. They added 154, 142, 170, 161, 154 and 149 engine units; final
coverage/features were 1,308/1,933, 1,308/1,940, 1,308/1,936, 1,308/1,940,
1,308/1,938 and 1,308/1,937. Peak RSS was 421 MiB except shard four at
422 MiB. All 12 shards exited zero and together executed exactly 200,000
inputs. Slowest-unit seconds, timeouts, artifact files, sanitizer findings and
product-code findings were zero.

For every presented input, the input-state target executed each selected
canonical-record, dice-transcript or nonce-state path twice and required
byte-equal typed outcomes, an exhaustive named `ProvisioningError`, no partial
artifact, same-run nonce rejection, and fresh-run reproducibility. The
full-chain target executed the deterministic public dice path twice, required
byte-equal public artifacts, reparsed both descriptors, rederived both scripts,
validated both Bech32 addresses, authenticated the capsule, and required a
second same-run encryption to reject without returning an artifact.

The six post-run input-state directories contained 968 files/12,427 bytes in
sum and produced a content-deduplicated 733-file/11,849-byte union. Its sorted
`SHA-256<TAB>bytes` set was 49,645 bytes with SHA-256
`bc9e6c1379e1ee94f79ca7e96938d8d284d4d26313802a02f3883cea0373a32c`.
The six full-chain directories contained 825 files/18,766 bytes in sum and
produced an 805-file/18,495-byte union. Its 54,607-byte set had SHA-256
`9f1c8cf9c2f097e6b56bfc32b029ee1ca5f45aeadc4fafda17753943a8a544eb`.

Two identical union-builder processes were detected writing the same temporary
paths. Both had exited at the explicit process check. Before minimization, all
six generated union and cmin directories were emptied and rebuilt once,
serially, from the immutable shard directories. No output from the concurrently
written directories was accepted.

The first opposite-order minimizations reached the same coverage/features but
selected different content. Input-state ascending and descending outputs were
141 files/1,857 bytes with set SHA-256 `a50a34685f9dfd1db8dbaf0f713c54adb4506a99751a0c78810445881aa8931f`
and 141 files/1,852 bytes with `f7393a19cfc0701a4020153ed231368407c9b903ccb0a4620e7f95a8fe1d2ace`.
Full-chain outputs were 127 files/1,229 bytes with
`7d1c21fc58b156d239b0d575a8126bf980fe2f6da168686180b25b12e4252205`
and 127 files/1,249 bytes with
`6da478d93ca7076f9a233623d6ab52f66a18c37b100346c2e98eac5cb6d4b9d4`.
Neither pair was accepted.

Fresh self-minimizations also differed: input-state outputs were 132
files/1,735 bytes with `0c099d0476921949b6fa07c0eb9e53449733cce3823014a9fdb1ade92b4466a6`
and 132 files/1,714 bytes with `cc494b368c9371104c899eae8897dc4f2a7f2b71bce6ef894da5dedd6aa8d9d0`;
full-chain outputs were 117 files/1,158 bytes with
`2950ad821bf90b43eb808b00c31b946fad4ac43707159c7c2eaea3ac931397b1`
and 118 files/1,160 bytes with `692e0e3f2eccbf0dae94df5e3c9db01d5d9a2861541084ecc7a42b2a01a61f93`.
Neither pair was accepted.

The canonical rule then repeatedly minimized the SHA-256-ascending output
until its exact set stopped changing. Input-state counts progressed 132 to 129
to 128 to 126 to 126; full-chain progressed 117 to 115 to 115. Fresh
ascending and descending proofs preserved the exact 126-file/1,626-byte
input-state set, whose 8,521-byte listing has SHA-256
`367ef441e1affd13775ff72a3391f004fd211ff12f331cbd24a342fe9d4e82da`.
The first full-chain proof reduced only its descending copy from 115 to 114,
so that pair was rejected. A second fresh pair from the strict subset preserved
the exact 114-file/1,126-byte set in both orders; its 7,684-byte listing has
SHA-256 `0b38a91176fc15e0e6685b2e76e3958bd7f73ce24deff3b8921f74bc17dcf2a4`.

Those two proven sets became the persistent corpora. Their manifest entry
blocks have SHA-256
`139bac58e340d7e6640c532b0abefa56dcb2d13570920109e3f1a630b7325384`
and `4edb8dc567d3c66821d771cc19dd8f7999b66f1d7209b045aa2f4973c27b03f2`.
`CORPUS-MANIFEST-M26.tsv` is 43,911 bytes/248 LF with SHA-256
`0dbb8c82515f34e48b96ed9c90a10832bc727a7d68c58590001db6f39f22b028`;
its aggregate is 240 files/2,752 bytes with entry-block SHA-256
`4b2211d8efaad6c6094215813d4ab191f9d7f9ae59e4ffe862c9a2200a5fc7e0`.

Pinned retained-corpus replay under AddressSanitizer loaded 126 input-state
files/1,626 bytes and executed 127 units in 13 seconds at coverage/features
1,353/2,768, then loaded 114 full-chain files/1,126 bytes and executed 115
units in 17 seconds at 1,308/1,944. Peak RSS was 356 and 417 MiB; new units,
slowest-unit seconds and artifact files were zero. Both replays exited zero.

`CAMPAIGN-006-TRANSCRIPT.tsv` preserves the exact shard parameters, result
fields, post-run inventories, duplicate-union correction, every rejected
minimization set, the canonical iterations, both fixed-point proofs, retained
facts and replay results. It is 8,114 bytes/82 LF with SHA-256
`a3fec83e235a1915f47133eee5ea02c819070a2b23fbaaa476e5e4f99c32f91f`.

Three earlier starts were excluded before qualification. At source `0e95be3`,
input-state and full-chain generation stopped at counters 934 and 354 after
the BIP32 zero-tweak rejection was reproduced; their untracked additions were
discarded. At `1336f4a`, they stopped at 2,503 and 759 because the exact
SHA-256/HMAC-SHA256/HKDF-SHA256 vectors were not directly executed; their
untracked additions were discarded. At `36867ba`, six isolated full-chain
shards stopped at counters 50, 50, 49, 48, 50 and 49 because imported fixture
file hashes were not asserted. Their temporary results were discarded. No
result from those starts is part of campaign 006, and no product source file
changed during the qualifying generation, minimization, registration or
replay.
