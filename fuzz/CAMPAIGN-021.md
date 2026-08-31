# Process slice 2 campaign 021

Status: PLANNED — NOT EXECUTED.

The common source will be the commit that first registers both QK-DEC-142
targets, their separate non-default dependency features, exact runner routing,
dependency-closure proofs, and these public starting corpora. No product source
or target oracle may change after that source commit without restarting both
qualifying runs against the later commit.

The exact qualifying commands are:

```text
fuzz/run-bounded.sh qk_supervisor_lifecycle 100000
fuzz/run-bounded.sh qk_decoy_calculator 100000
```

Both runs use cargo-fuzz 0.13.2, `nightly-2026-08-25` with rustc
`1.100.0-nightly (e7769602a 2026-08-24)`, AddressSanitizer, release-profile
overflow checks and debug assertions, corpus reload disabled, two-second input
timeout, 2,048 MiB RSS ceiling, and final-stat reporting. The supervisor target
uses public seed 142001 and maximum input length 4,096. The calculator target
uses public seed 142002 and maximum input length 2,048.

After each run, two copied corpora are minimized serially until each reaches a
fixed point. Their sorted `SHA-256<TAB>bytes` listings must agree byte for byte
before one set replaces the persistent corpus. The resulting two partitions
are registered in `CORPUS-MANIFEST-PROCESS-S2.tsv`. The 33 earlier partitions
are replay-only because their sources remain unchanged; all 35 retained
corpora are replayed on the final tree before publication.

The calculator oracle compares the implementation after every key with a
separately written total fixed-decimal transition, arithmetic, rounding, and
display model. The supervisor oracle compares every lifecycle event with a
separately written grant and termination model. Actual `recvmsg`, SCM_RIGHTS,
fragmentation, coalescing, and EOF behavior remain covered by deterministic
HOST integration tests and are not executed as syscalls by libFuzzer.
