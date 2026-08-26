# M24 campaign 004 preregistration

Fuzz-target source commit:
`709fa87fb33534deed92627c219f1c7e3473e78d`.

Status: **NOT EXECUTED**. This file preregisters the bounded campaign and
records no campaign execution count, coverage, finding, timeout, or outcome.

Tool identities are cargo-fuzz 0.13.2; `nightly-2026-08-25`; rustc
`1.100.0-nightly (e7769602a 2026-08-24)`; AddressSanitizer; release-profile
overflow checks and debug assertions enabled; dependency resolution offline.

The starting corpus is the exact `CORPUS-MANIFEST-M24.tsv` inventory: 18
committed public seeds totaling 77 bytes for `qk_host_sim_m24`. It contains
the two exact A+B/A+C fixture completions, both accepted input-source values,
each stable terminal/mock control rejection, and bounded mutate/truncate/append
PSBT shapes. All key material is the public, permanently NEVER-FUND M24
fixture lineage; the target imports it only through qk-secp and checks that the
caller source is wiped immediately.

The one planned command is:

```text
PATH=/private/tmp/qk-cargo-fuzz/bin:$PATH fuzz/run-bounded.sh qk_host_sim_m24 100000
```

The runner fixes seed 24001, maximum input length 4,096 bytes, timeout 2 s,
RSS limit 2,048 MiB, corpus reload disabled, and requires an empty artifact
directory before starting. No other target is part of campaign 004.

For every presented input, the target runs the complete owned-S0 review and
M24 signing/finalization path twice with freshly imported keys. The two typed
outcomes must be byte-equal. Every M23 and M24 rejection must remain on the
exhaustively enumerated named-error surface; exact public control inputs must
also retain their ratified rejection precedence. An error exposes no partial
PSBT, raw transaction, signature, key, or hostile input. Acceptance must yield
an M5 fixed-point finalized PSBT, and the exact A+B/A+C controls must match all
fixture PSBT, transaction, txid, and wtxid bytes. Any panic, wrong acceptance,
wrong rejection, nondeterminism, sanitizer finding, timeout, or artifact stops
the campaign and enters the registered finding procedure before product code
changes.

After the bounded run, two copies of the resulting corpus are minimized
separately through `fuzz/minimize-corpus.sh qk_host_sim_m24 COPY`. Their sorted
content sets must agree byte-for-byte. One matching copy may replace the
persistent corpus; the manifest is then regenerated against the same source
commit. The retained corpus is replayed once through
`fuzz/replay-corpus.sh qk_host_sim_m24`, and the execution record adds only the
measured counts, hashes, coverage, resource figures, and outcomes.
