# Process slice 4 campaign 023

Status: PLANNED — NOT EXECUTED.

The common source will be the commit that first registers both QK-DEC-144
targets, their separate non-default dependency feature, exact runner routing,
dependency-closure proofs, corpus-registration guard, and these public starting
corpora. No product source or target oracle may change after that source commit
without restarting both qualifying runs against the later commit.

The exact qualifying commands are:

```text
fuzz/run-bounded.sh qk_core_io_peer 100000
fuzz/run-bounded.sh qk_core_session 100000
```

Both runs use cargo-fuzz 0.13.2, `nightly-2026-08-25` with rustc
`1.100.0-nightly (e7769602a 2026-08-24)`, AddressSanitizer, release-profile
overflow checks and debug assertions, corpus reload disabled, two-second input
timeout, 2,048 MiB RSS ceiling, and final-stat reporting. The peer target uses
public seed 144001 and maximum input length 16,384; the session target uses
public seed 144002 and maximum input length 4,096.

After each run, two copied corpora are minimized serially until each reaches a
fixed point. Their sorted `SHA-256<TAB>bytes` listings must agree byte for byte
before one set replaces the persistent corpus. The resulting two partitions
are registered in `CORPUS-MANIFEST-PROCESS-S4.tsv`. The 38 earlier partitions
are replay-only because their sources remain unchanged; all 40 retained
corpora are replayed on the final tree before publication.

The peer oracle exercises the complete inner grammar, accepted qk-io status
mapping, exact valid ingress transfer, outer fragmentation and coalescing,
ancillary rejection, session identity and exchange order. The session oracle
drives typed capabilities, all logical keys and interruptions, the complete
shell lifecycle, deterministic session-id facts, terminal absorption and wipe
counts. Both require stable named outcomes and exact repeat consistency.
