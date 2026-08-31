# Process slice 1 campaign 020

Status: EXECUTED — QUALIFYING RUN COMPLETE.

The common fuzz-target source commit was
`68b61e6be83bb5ee09890ff5e3b98c5ecfaf2183`. The fixed tool identities were
cargo-fuzz 0.13.2; `nightly-2026-08-25`; rustc
`1.100.0-nightly (e7769602a 2026-08-24)`; AddressSanitizer; release-profile
overflow checks and debug assertions enabled; and offline dependency
resolution. The exact qualifying commands were:

```text
fuzz/run-bounded.sh qk_ipc_wire 100000
fuzz/run-bounded.sh qk_ipc_endpoint_state 100000
```

`qk_ipc_wire` used public seed 140001, maximum input length 4,096, timeout 2
seconds, RSS limit 2,048 MiB, corpus reload off, and final-stat reporting. It
started from three public seed files totaling 29 bytes. It executed exactly
100,000 inputs in 7 seconds at 14,285 executions per second, finished at
coverage/features 669/1,306, added 244 engine units, had a zero-second slowest
unit, peaked at 582 MiB RSS, and created zero artifact files. The post-run
filesystem corpus contained 127 files/9,382 bytes. Its 8,641-byte sorted
`SHA-256<TAB>bytes` listing had SHA-256
`8614507a4d8dd06f36f02b20f12b0f61310d5b892db754265478ed4a539f014e`.

Two copies of that wire corpus were minimized serially. Both copies followed
the same complete progression:

- 127 files/9,382 bytes, 8,641-byte listing SHA-256
  `8614507a4d8dd06f36f02b20f12b0f61310d5b892db754265478ed4a539f014e`;
- 110 files/8,410 bytes, 7,485-byte listing SHA-256
  `bbebb501f5671331844dc1f0c75e194be13e11a30fea722526a0711670b89526`;
- 106 files/8,325 bytes, 7,214-byte listing SHA-256
  `0efe72bc40a7bfd2181e3b5b14af4f0ac1fb55b465f1865fcea28826d62ea1af`;
- 103 files/8,021 bytes, 7,008-byte listing SHA-256
  `c495f9ee0ea11178f39e98157b45080acacc6a76ce4494ffe37e79246a1ac13a`;
- a further pass left that 103-file set unchanged.

`qk_ipc_endpoint_state` used public seed 140002 with the same maximum input,
timeout, RSS, reload, sanitizer, assertion, overflow, and reporting settings.
It started from two public seed files totaling 28 bytes. It executed exactly
100,000 inputs in 4 seconds at 25,000 executions per second, finished at
coverage/features 635/2,234, added 739 engine units, had a zero-second slowest
unit, peaked at 225 MiB RSS, and created zero artifact files. The post-run
filesystem corpus contained 311 files/12,811 bytes. Its 21,132-byte sorted
`SHA-256<TAB>bytes` listing had SHA-256
`2f263f6b5ef590a38af2884b53c7dc4cf87ab0dfbcd10a677b7497eca91925a6`.

Two copies of that endpoint-state corpus were minimized serially. Both copies
followed the same complete progression:

- 311 files/12,811 bytes, 21,132-byte listing SHA-256
  `2f263f6b5ef590a38af2884b53c7dc4cf87ab0dfbcd10a677b7497eca91925a6`;
- 269 files/11,288 bytes, 18,278-byte listing SHA-256
  `f12211af245d8c418c163e7a7c3f61e37504efe67434180434a7f4f96ee828b7`;
- 268 files/11,270 bytes, 18,210-byte listing SHA-256
  `9d70799c22238dd024e7f7e4f62bb20b64c3f206a05182edb414e767c1e6ca62`;
- 265 files/11,163 bytes, 18,006-byte listing SHA-256
  `6ab653460ef0975d95a8c44287df9e1418b0eb96f1265c03b09a000361b1fb98`;
- a further pass left that 265-file set unchanged.

For each target, the two fixed-point listings were byte-identical. No
concurrent process wrote either minimization or artifact directory. The
matching fixed-point sets became the persistent corpora. `qk_ipc_wire`
retained 103 files/8,021 bytes with manifest entry-block SHA-256
`5d9ee8b4501d0546eed5864c3b8e1c678607a38194423635d5cc0a29a681e78d`;
`qk_ipc_endpoint_state` retained 265 files/11,163 bytes with manifest
entry-block SHA-256
`6af33b1cce72ddfeff324a90923cbf479e31dd5388ab13f7bd21e72f7f672fb1`.
The aggregate is 368 files/19,184 bytes with entry-block SHA-256
`ffa9dd883e350789425b67d2cae885ebebd92e9d30ce233263a2523e55aad6d9`.
`CORPUS-MANIFEST-PROCESS-S1.tsv` is 61,771 bytes/376 LF with SHA-256
`4a6749620ba1716fc61305acbea8fb9af25aec1bd347e79064eb857bd15ceeca`.

Retained-corpus replay for `qk_ipc_wire` loaded all 103 files totaling 8,021
bytes and executed 104 units. It finished at coverage/features 669/1,306 with
an engine corpus of 103 files/8,021 bytes, added zero units, had a zero-second
slowest unit, peaked at 38 MiB RSS, created zero artifact files, and exited
zero. Retained-corpus replay for `qk_ipc_endpoint_state` loaded all 265 files
totaling 11,163 bytes and executed 266 units. It finished at
coverage/features 635/2,234 with an engine corpus of 265 files/11,163 bytes,
added zero units, had a zero-second slowest unit, peaked at 39 MiB RSS, created
zero artifact files, and exited zero.

The wire target exercised raw and constructed frame parsing, byte-exact
re-encoding, arbitrary fragmentation and coalescing, ancillary-first
termination, hostile declared lengths, payload-shape rules, exact consumed
counts, stable named rejections, repeat consistency, and decoder cleanup. The
endpoint-state target exercised the complete core and I/O lifecycles, valid
and hostile initiations and replies, core-minted session binding, strictly
monotonic exchange identifiers, one-outstanding work, exhaustion, peer loss,
terminal stability, stable named rejections, and repeat consistency.

The 31 previously registered targets and corpora were classified replay-only:
none invokes `qk-ipc`, so none required a qualifying campaign, corpus
minimization, or manifest change. All 33 registered corpora replayed to exit
zero on the final source tree, executing 4,936 replay units in total and
creating zero artifact files. Across qualification, minimization,
registration, and all retained-corpus replays, the observed panic, timeout,
sanitizer-report, wrong-acceptance, unnamed-rejection, parse/encode
disagreement, session/order disagreement, terminal-instability,
repeat-mismatch, and observable-wipe-mismatch counts were zero. No product
source or target oracle changed after qualification began.
