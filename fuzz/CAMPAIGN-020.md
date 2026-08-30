# Process slice 1 campaign 020

Status: PLANNED — NOT EXECUTED.

The common source commit, exact execution statistics, two-copy minimization
progressions, retained-corpus facts, and replay results are recorded only after
both qualifying campaigns complete. The fixed tool identities are cargo-fuzz
0.13.2; `nightly-2026-08-25`; rustc
`1.100.0-nightly (e7769602a 2026-08-24)`; AddressSanitizer; release-profile
overflow checks and debug assertions enabled; and dependency resolution
offline. The exact qualifying commands are:

```text
fuzz/run-bounded.sh qk_ipc_wire 100000
fuzz/run-bounded.sh qk_ipc_endpoint_state 100000
```

`qk_ipc_wire` uses public seed 140001, maximum input length 4,096, timeout 2
seconds, RSS limit 2,048 MiB, corpus reload off, and final-stat reporting. It
drives raw and constructed frame parsing, exact re-encoding, arbitrary stream
fragmentation and coalescing, ancillary-first termination, declared-size
bounds, stable named rejections, and repeat consistency.

`qk_ipc_endpoint_state` uses public seed 140002 with the same bounds. It drives
the complete core and I/O endpoint lifecycles, valid and hostile initiations
and replies, session binding, monotonic exchange identifiers, one-outstanding
work, peer loss, terminal stability, stable named rejections, and repeat
consistency.

After each 100,000-input run, two copies of its filesystem corpus are minimized
separately to unchanged fixed points. Only byte-identical sorted
`SHA-256<TAB>bytes` listings may become the persistent corpus. The two retained
corpora then replay under the same pinned toolchain before
`CORPUS-MANIFEST-PROCESS-S1.tsv` is registered. Existing target corpora are
replay-only because `qk-ipc` is a new dependency-free leaf absent from their
dependency closures.
