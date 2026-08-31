# Process slice 4 campaign 023

Status: EXECUTED — QUALIFYING RUN COMPLETE.

The common product-and-fuzz source commit was
`e416080d8867fc381bdcc6aa1a26382f4767b6b8`. The fixed tool identities were
cargo-fuzz 0.13.2; `nightly-2026-08-25`; rustc
`1.100.0-nightly (e7769602a 2026-08-24)`; AddressSanitizer; release-profile
overflow checks and debug assertions enabled; and offline dependency
resolution. The exact qualifying commands were:

```text
fuzz/run-bounded.sh qk_core_io_peer 100000
fuzz/run-bounded.sh qk_core_session 100000
```

`qk_core_io_peer` used public seed 144001, maximum input length 16,384,
timeout 2 seconds, RSS limit 2,048 MiB, corpus reload off, and final-stat
reporting. It started from six public seed files totaling 91 bytes. It
executed exactly 100,000 inputs in 6 seconds at 16,666 executions per second,
finished at coverage/features 646/777, added 120 engine units, had a
zero-second slowest unit, peaked at 424 MiB RSS, and created zero artifact
files. The final live engine statistic was 34 units/241 bytes; the post-run
filesystem corpus contained 49 files/394 bytes. That filesystem corpus's
3,300-byte sorted `SHA-256<TAB>bytes` listing had SHA-256
`971a7edbfa88be13c5bee6511cb62250f681e3b0974a797aae90bb4a404fb339`.

Two copies of that peer corpus were minimized serially. Both copies followed
the same complete progression:

- 49 files/394 bytes, 3,300-byte listing SHA-256
  `971a7edbfa88be13c5bee6511cb62250f681e3b0974a797aae90bb4a404fb339`;
- 32 files/243 bytes, 2,152-byte listing SHA-256
  `c83994083a2c27fa2968fdf74798e624069a403e06bef616327c11a5c6321605`;
- a further pass left that 32-file set unchanged.

`qk_core_session` used public seed 144002, maximum input length 4,096, and the
same timeout, RSS, reload, sanitizer, assertion, overflow, and reporting
settings. It started from eleven public seed files totaling 91 bytes. It
executed exactly 100,000 inputs in 7 seconds at 14,285 executions per second,
finished at coverage/features 835/2,078, added 283 engine units, had a
zero-second slowest unit, peaked at 518 MiB RSS, and created zero artifact
files. The final live engine statistic was 123 units/6,630 bytes; the post-run
filesystem corpus contained 146 files/6,776 bytes. That filesystem corpus's
9,876-byte sorted `SHA-256<TAB>bytes` listing had SHA-256
`fea6d06edf541ca34421382b66a83e868730c300d94a33f812b8f826ac41a249`.

Two copies of that session corpus were minimized serially. Both copies
followed the same complete progression:

- 146 files/6,776 bytes, 9,876-byte listing SHA-256
  `fea6d06edf541ca34421382b66a83e868730c300d94a33f812b8f826ac41a249`;
- 106 files/6,048 bytes, 7,181-byte listing SHA-256
  `fb828bd0738a736d88ee28cd7f61c7b23006af7fd2ada16940f55fa7551bc35f`;
- 103 files/6,025 bytes, 6,980-byte listing SHA-256
  `99a77bb1286118e95042ed5cc68884cde0b58dbf689b5856cc585bead1cfca1c`;
- 102 files/5,996 bytes, 6,912-byte listing SHA-256
  `2875d97b7c84b949f84f4e8ff20fca09eb1e93fe2a849e2eb1ab7fe22abd7de1`;
- a further pass left that 102-file set unchanged.

For both targets, the two fixed-point listings were byte-identical. No
concurrent process wrote either copy or either artifact directory. One agreed
fixed-point set replaced each persistent corpus. `qk_core_io_peer` retained
32 files/243 bytes with manifest entry-block SHA-256
`1b4f7b437dee3d89c7d454b91eb1ccc8cfe2cf05a8440c5b2e2a316863a4c2e0`;
`qk_core_session` retained 102 files/5,996 bytes with manifest entry-block
SHA-256
`115a5840d3453b3d9b2118ed2da6e671a8353d438a98ff0ca2e0ad0bca541d2d`.
The aggregate is 134 files/6,239 bytes with entry-block SHA-256
`449a0b8dc0ef4f499c1bd6d262aadaffbd4602b7b591e3edeeaa41cf4ba5bc69`.
`CORPUS-MANIFEST-PROCESS-S4.tsv` is 21,929 bytes/142 LF with SHA-256
`478d2f18cf56e897855c9225bf0e3422415a2b1b75ad8e4ece97f8d3cf22aa5f`.

Retained-corpus replay for `qk_core_io_peer` loaded all 32 files totaling 243
bytes and executed 33 units. It finished at coverage/features 646/777, added
zero units, had a zero-second slowest unit, peaked at 35 MiB RSS, created zero
artifact files, and exited zero. `qk_core_session` loaded all 102 files
totaling 5,996 bytes and executed 103 units. It finished at coverage/features
835/2,078, added zero units, had a zero-second slowest unit, peaked at 38 MiB
RSS, created zero artifact files, and exited zero.

The 38 previously registered targets and corpora were replay-only: none
compiled or invoked `qk-core`, so none required a qualifying campaign, corpus
minimization, or manifest change. All 38 replayed to exit zero on the frozen
source tree, executing 6,170 replay units in total, adding zero units and
creating zero artifact files. Including the two new partitions, all 40
retained corpora executed 6,306 replay units.

The peer oracle exercised the complete inner grammar, all 71 accepted qk-io
status mappings, exact valid ingress transfer, outer fragmentation and
coalescing, ancillary rejection, session identity and exchange ordering. The
session oracle drove typed capabilities, all nineteen logical keys, all ten
interruptions, the complete shell lifecycle, deterministic session-id facts,
terminal absorption and wipe counts. Across qualification, minimization,
registration and every retained-corpus replay, the observed panic, timeout,
sanitizer-report, wrong-acceptance, unnamed-rejection, repeat-mismatch and
artifact-file counts were zero. No product source or target oracle changed
after qualification began.
