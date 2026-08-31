# Process slice 3 campaign 022

Status: EXECUTED — QUALIFYING RUN COMPLETE.

The common product-and-fuzz source commit was
`beac2e8fad07b7fe600704509ccd913396343d2d`. The fixed tool identities were
cargo-fuzz 0.13.2; `nightly-2026-08-25`; rustc
`1.100.0-nightly (e7769602a 2026-08-24)`; AddressSanitizer; release-profile
overflow checks and debug assertions enabled; and offline dependency
resolution. The exact qualifying commands were:

```text
fuzz/run-bounded.sh qk_io_ingress 100000
fuzz/run-bounded.sh qk_io_egress 100000
fuzz/run-bounded.sh qk_io_session 100000
```

`qk_io_ingress` used public seed 143001, maximum input length 16,384,
timeout 2 seconds, RSS limit 2,048 MiB, corpus reload off, and final-stat
reporting. It started from eight public seed files totaling 118 bytes. It
executed exactly 100,000 inputs in 389 seconds at 257 executions per second,
finished at coverage/features 1,207/2,806, added 279 engine units, had a
zero-second slowest unit, peaked at 349 MiB RSS, and created zero artifact
files. The final live engine statistic was 159 units/11,184 bytes; the
post-run filesystem corpus contained 164 files/11,268 bytes. That filesystem
corpus's 11,139-byte sorted `SHA-256<TAB>bytes` listing had SHA-256
`2893b4e8e9dd62830c6a32deaefd20ef1fb790a9443c068e2e1f6ed124bb89da`.

Two copies of that ingress corpus were minimized serially. Both copies
followed the same complete progression:

- 164 files/11,268 bytes, 11,139-byte listing SHA-256
  `2893b4e8e9dd62830c6a32deaefd20ef1fb790a9443c068e2e1f6ed124bb89da`;
- 145 files/10,702 bytes, 9,852-byte listing SHA-256
  `7c5884e363af4f2fa6ffbd796c9475e1e99304466421399c5a21073d422a585f`;
- 142 files/10,682 bytes, 9,651-byte listing SHA-256
  `42220740d3894b4b0a287b9cd32ced1c279a66e4114f5dd3da9d69e7d301ef72`;
- a further pass left that 142-file set unchanged.

`qk_io_egress` used public seed 143002, maximum input length 16,384, and the
same timeout, RSS, reload, sanitizer, assertion, overflow, and reporting
settings. It started from seven public seed files totaling 235 bytes. It
executed exactly 100,000 inputs in 56 seconds at 1,785 executions per second,
finished at coverage/features 1,681/3,449, added 681 engine units, had a
zero-second slowest unit, peaked at 411 MiB RSS, and created zero artifact
files. The final live engine statistic was 189 units/2,324 bytes; the
post-run filesystem corpus contained 201 files/2,627 bytes. That filesystem
corpus's sorted `SHA-256<TAB>bytes` listing had SHA-256
`f28c910d0581d36df93e7d3f4986bdc9513abd65a1732fe9498e5c39dcbb661d`.

Two copies of that egress corpus were minimized serially. Both copies
followed the same complete progression:

- 201 files/2,627 bytes, listing SHA-256
  `f28c910d0581d36df93e7d3f4986bdc9513abd65a1732fe9498e5c39dcbb661d`;
- 149 files/1,615 bytes, listing SHA-256
  `23aed64f4a8df6fbf19cf30508b39df585f5aaa80faba8a86974471dfeb8b07f`;
- 144 files/1,571 bytes, listing SHA-256
  `6431ac44aa250fdd15fecca3c49b5d56b7d918fa286e25d02c2ce99b6f84236f`;
- 142 files/1,552 bytes, listing SHA-256
  `0b57a4ae50d984027ea0f89b038f9b0f6f9603689b1f8f5ef2694fcf9c7efc42`;
- a further pass left that 142-file set unchanged.

`qk_io_session` used public seed 143003, maximum input length 4,096, and the
same timeout, RSS, reload, sanitizer, assertion, overflow, and reporting
settings. It started from five public seed files totaling 245 bytes. It
executed exactly 100,000 inputs in 50 seconds at 2,000 executions per second,
finished at coverage/features 1,373/2,923, added 1,234 engine units, had a
zero-second slowest unit, peaked at 481 MiB RSS, and created zero artifact
files. The final live engine statistic was 531 units/26 KiB; the post-run
filesystem corpus contained 532 files/27,034 bytes. That filesystem corpus's
sorted `SHA-256<TAB>bytes` listing had SHA-256
`c63c13c444cbb0b84fe8fc45d5e9afa337e50803fa6ae40c79d3da65196c3222`.

Two copies of that session corpus were minimized serially. Both copies
followed the same complete progression:

- 532 files/27,034 bytes, listing SHA-256
  `c63c13c444cbb0b84fe8fc45d5e9afa337e50803fa6ae40c79d3da65196c3222`;
- 409 files/20,460 bytes, listing SHA-256
  `5db08dd58f3660ab12047894ff22a4823d60cf17c5797ac3d273a589eea562c7`;
- 403 files/20,159 bytes, listing SHA-256
  `5552c4ede4707c2a129b2044b4313e8ecfae81f748a7598d10eba2673c258d94`;
- 399 files/19,921 bytes, listing SHA-256
  `0171ed29e82c091c60d51836db1adf0775d4207bda7d1210ae821deb9b7e4013`;
- a further pass left that 399-file set unchanged.

For every target, the two fixed-point listings were byte-identical. No
concurrent process wrote either copy or that target's artifact directory. One
agreed fixed-point set replaced each persistent corpus. `qk_io_ingress`
retained 142 files/10,682 bytes with manifest entry-block SHA-256
`a9b08685dee4f0ae2193a35af798bdad396fce8e55aa811e7123ff7fb56d5c63`;
`qk_io_egress` retained 142 files/1,552 bytes with entry-block SHA-256
`a7b19d14577135fb95e175a8736a792617e18d6f5be48edcdcef8db10b6f6985`;
`qk_io_session` retained 399 files/19,921 bytes with entry-block SHA-256
`b934b6c5bb6e1c07dca07dbcd7e8608082260aeb4c95cdad7f00eb7479410de2`.
The aggregate is 683 files/32,155 bytes with entry-block SHA-256
`599571a0c752323b9af4da31ba1394a69acbccef43246c751e57edae72812cfa`.
`CORPUS-MANIFEST-PROCESS-S3.tsv` is 106,872 bytes/692 LF with SHA-256
`c44c5c29fc08597a82a3f6bfb9eb3caab9030229f9ccf13c6dfd29bf28e12a16`.

Retained-corpus replay for `qk_io_ingress` loaded all 142 files totaling
10,682 bytes and executed 143 units. It finished at coverage/features
1,207/2,806, added zero units, had a zero-second slowest unit, peaked at
220 MiB RSS, created zero artifact files, and exited zero. `qk_io_egress`
loaded all 142 files totaling 1,552 bytes and executed 143 units. It finished
at coverage/features 1,681/3,449, added zero units, peaked at 81 MiB RSS,
created zero artifact files, and exited zero. `qk_io_session` loaded all 399
files totaling 19,921 bytes and executed 400 units. It finished at
coverage/features 1,373/2,923, added zero units, peaked at 61 MiB RSS, created
zero artifact files, and exited zero.

The 35 previously registered targets and corpora were replay-only: none
compiled or invoked `qk-io`, so none required a qualifying campaign, corpus
minimization, or manifest change. All 35 replayed to exit zero on the frozen
source tree, executing 5,484 replay units in total, adding zero units and
creating zero artifact files. Including the three new partitions, all 38
retained corpora contained 6,123 files and executed 6,170 replay units.

The ingress oracle compared the complete inner grammar, source tags, media
record grammar, exact candidates, chunk offsets and contents, and separately
generated canonical P frames; arbitrary wrapper-valid P streams were tied to
the unchanged qk-bbqr reassembler for exact payload or error. The egress
oracle compared the complete inner grammar, sink/artifact allowlist, transfer
state, writer faults and complete responses with a separately written model;
its P/T frames also decoded and reassembled through unchanged qk-bbqr. The
session oracle compared complete action sequences, full QKIP responses,
one-use boundary facts, all 32 receive-failure categories and terminal states
with a separate model. Fixed target paths isolated active ingress and egress
owner cleanup from mock-boundary cleanup. Across qualification, minimization,
registration and every retained-corpus replay, the observed panic, timeout,
sanitizer-report, wrong-acceptance, unnamed-rejection, model-disagreement,
terminal-instability, repeat-mismatch and artifact-file counts were zero. No
product source or target oracle changed after qualification began.
