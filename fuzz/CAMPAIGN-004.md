# M24 campaign 004

Fuzz-target source commit:
`709fa87fb33534deed92627c219f1c7e3473e78d`.
Executed tree and committed-seed source:
`babd5d87e083eaadaabb8eed1fdd73e07ad72a67`.

Tool identities were cargo-fuzz 0.13.2; `nightly-2026-08-25`; rustc
`1.100.0-nightly (e7769602a 2026-08-24)`; AddressSanitizer; release-profile
overflow checks and debug assertions enabled; dependency resolution offline.

The campaign started from the exact preregistered inventory of 18 committed
public seeds totaling 77 bytes for `qk_host_sim_m24`. It contained the exact
A+B/A+C fixture completions, both accepted input-source values, each stable
terminal/mock control rejection, and bounded mutate/truncate/append PSBT
shapes. All key material was the public, permanently NEVER-FUND M24 fixture
lineage and was imported only through qk-secp with caller-source wiping
asserted on every signing execution.

The executed command was:

```text
PATH=/private/tmp/qk-cargo-fuzz/bin:$PATH fuzz/run-bounded.sh qk_host_sim_m24 100000
```

The runner fixed seed 24001, maximum input length 4,096 bytes, timeout 2 s,
RSS limit 2,048 MiB, corpus reload disabled, and required an empty artifact
directory before starting. The run executed exactly 100,000 inputs in 224
seconds, averaged 446 executions per second, added 449 units, and ended at
coverage/features 3,251/5,337 with engine corpus 295 files/5,389 bytes. The
post-run filesystem inventory was 316 files/5,465 bytes. Peak RSS was 496 MiB;
slowest-unit seconds, timeout count, artifact-file count, sanitizer findings,
and product-code findings were all zero.

For every presented input, the target ran the complete owned-S0 review and
M24 signing/finalization path twice with freshly imported keys. The two typed
outcomes remained byte-equal. Every rejection stayed on the exhaustively
enumerated named-error surface and the exact public controls retained their
rejection precedence. No error exposed a partial PSBT, raw transaction,
signature, key, or hostile input. Every acceptance was an M5 fixed-point
finalized PSBT, and the exact A+B/A+C controls matched all fixture PSBT,
transaction, txid, and wtxid bytes.

The post-run directory was copied twice and each copy was processed by
`PATH=/private/tmp/qk-cargo-fuzz/bin:$PATH fuzz/minimize-corpus.sh
qk_host_sim_m24 COPY`. Both copies produced the same 267-file/4,812-byte
sorted `SHA-256<TAB>bytes` content set, SHA-256
`9940d800eb0531fa06203facfe1a89022e17d35a2717a620f8bf3d9b2bf450a5`.
One copy became the persistent corpus.

The retained manifest entry block is SHA-256
`f9c93bd09aab39bbfd4d9c2641d7f4ffaab1f9b3b52499d7e55caaf1642cc3e1`.
`CORPUS-MANIFEST-M24.tsv` is 42,969 bytes/274 LF, SHA-256
`6b57592878a0579a886b984caa0bd09a2c6bd95e69a29cecbcf935447e4331bc`.

`PATH=/private/tmp/qk-cargo-fuzz/bin:$PATH fuzz/replay-corpus.sh
qk_host_sim_m24` loaded 267 retained files and executed 268 units. It reported
engine corpus 264 files/4,788 bytes, coverage/features 3,251/5,337, peak RSS
49 MiB, zero new units, zero slowest-unit seconds, and zero artifact files.
No product source file changed during campaign execution, minimization,
registration, or replay.
