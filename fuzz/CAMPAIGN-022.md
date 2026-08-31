# Process slice 3 campaign 022

Status: PLANNED — NOT EXECUTED.

The common source will be the commit that first registers all three
QK-DEC-143 targets, their separate non-default dependency feature, exact
runner routing, dependency-closure proofs, and these public starting corpora.
No product source or target oracle may change after that source commit without
restarting all three qualifying runs against the later commit.

The exact qualifying commands are:

```text
fuzz/run-bounded.sh qk_io_ingress 100000
fuzz/run-bounded.sh qk_io_egress 100000
fuzz/run-bounded.sh qk_io_session 100000
```

All runs use cargo-fuzz 0.13.2, `nightly-2026-08-25` with rustc
`1.100.0-nightly (e7769602a 2026-08-24)`, AddressSanitizer, release-profile
overflow checks and debug assertions, corpus reload disabled, two-second input
timeout, 2,048 MiB RSS ceiling, and final-stat reporting. Ingress uses public
seed 143001 and maximum input length 16,384; egress uses public seed 143002 and
maximum input length 16,384; session uses public seed 143003 and maximum input
length 4,096.

After each run, two copied corpora are minimized serially until each reaches a
fixed point. Their sorted `SHA-256<TAB>bytes` listings must agree byte for byte
before one set replaces the persistent corpus. The resulting three partitions
are registered in `CORPUS-MANIFEST-PROCESS-S3.tsv`. The 35 earlier partitions
are replay-only because their sources remain unchanged; all 38 retained
corpora are replayed on the final tree before publication.

The ingress and egress oracles compare every presented byte, tag, body,
boundary, transfer offset and response with separately written transport
models and tie accepted P/T frames to the unchanged qk-bbqr implementation.
The session oracle compares full operation sequences with a separate terminal
state model. All three require named deterministic rejection, no wrong
acceptance, no partial transfer, one-use boundary behavior, and cleanup counts.
