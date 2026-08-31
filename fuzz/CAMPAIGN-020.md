# Process slice 1 campaign 020

Status: EXECUTED — QUALIFYING RUN COMPLETE.

The common fuzz-target source commit was
`e7378a7f501361a468c2131e5df7220e4c1ee2c6`. The fixed tool identities were
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
100,000 inputs in 2 seconds at 50,000 executions per second, finished at
coverage/features 340/589, added 146 engine units, had a zero-second slowest
unit, peaked at 231 MiB RSS, and created zero artifact files. The post-run
filesystem corpus contained 68
files/4,503 bytes. Its 4,612-byte sorted `SHA-256<TAB>bytes` listing had
SHA-256
`5bf6c54c286948478ab5931f2da7d98100fb8c35de11a04c00a3baca9404f729`.

Two copies of that wire corpus were minimized serially. Both copies followed
the same complete progression:

- 68 files/4,503 bytes, 4,612-byte listing SHA-256
  `5bf6c54c286948478ab5931f2da7d98100fb8c35de11a04c00a3baca9404f729`;
- 59 files/4,264 bytes, 4,004-byte listing SHA-256
  `c3707c65943d1b7b92aadb0ede242fafe9e920fe441624b7a84a96b6e0c9ac8d`;
- a further pass left that 59-file set unchanged.

`qk_ipc_endpoint_state` used public seed 140002 with the same maximum input,
timeout, RSS, reload, sanitizer, assertion, overflow and reporting settings.
It started from two public seed files totaling 28 bytes. It executed exactly
100,000 inputs in 4 seconds at 25,000 executions per second, finished at
coverage/features 331/1,192, added 679 engine units, had a zero-second slowest
unit, peaked at 284 MiB RSS, and created zero artifact files. The post-run
filesystem corpus contained 271
files/12,940 bytes. Its 18,421-byte sorted `SHA-256<TAB>bytes` listing had
SHA-256
`564f95bb5090be01a10bbdd2fd6afeee3aab9893f9f8614b3ad768396671d2c4`.

Two copies of that endpoint-state corpus were minimized serially. Both copies
followed the same complete progression:

- 271 files/12,940 bytes, 18,421-byte listing SHA-256
  `564f95bb5090be01a10bbdd2fd6afeee3aab9893f9f8614b3ad768396671d2c4`;
- 246 files/11,748 bytes, 16,722-byte listing SHA-256
  `aa57f88537923e22388f97fb993c0c1d76962c72afce922bfe673c1405a6103c`;
- 244 files/11,705 bytes, 16,586-byte listing SHA-256
  `34d2e668905591f1e44af8c88511d9a44b5b930aa3c6a438cf114a9748176504`;
- 242 files/11,657 bytes, 16,450-byte listing SHA-256
  `e0469fe1a947255f7b41c8d92bba06484a727cfba6662d606183827c86f60623`;
- 241 files/11,580 bytes, 16,382-byte listing SHA-256
  `004a52a5d92e63276f3e4cdbc2c9b42a521540849abb8a417ae9a4ece7b7c286`;
- a further pass left that 241-file set unchanged.

For each target, the two fixed-point listings were byte-identical. No
concurrent process wrote either minimization or artifact directory. The
matching fixed-point sets became the persistent corpora. `qk_ipc_wire`
retained 59 files/4,264 bytes with manifest entry-block SHA-256
`067e68c6448475c9125639e6470cfdea943c03c9c03d29db766e613bbcb04ac5`;
`qk_ipc_endpoint_state` retained 241 files/11,580 bytes with manifest
entry-block SHA-256
`dc6dc16cacb258a2190a499423b0144b2f52c39ecacf46deb02bee93d71a0a19`.
The aggregate is 300 files/15,844 bytes with entry-block SHA-256
`ddad2cf3b80807e3014dd06d7ab1f473e2f4f8b8090e6205930ec3bbf60799e6`.
`CORPUS-MANIFEST-PROCESS-S1.tsv` is 50,950 bytes/308 LF with SHA-256
`d9d749a1427ce4eecbf5e9c7e65107b2f90fe47ceaa9b89dc4b23d43a8a47c6d`.

Retained-corpus replay for `qk_ipc_wire` loaded all 59 files totaling 4,264
bytes and executed 60 units. It finished at coverage/features 340/589 with an
engine corpus of 58 files/4,259 bytes, added zero units, had a zero-second
slowest unit, peaked at 35 MiB RSS, created zero artifact files, and exited
zero. Retained-corpus replay for `qk_ipc_endpoint_state` loaded all 241 files
totaling 11,580 bytes and executed 242 units. It finished at coverage/features
331/1,192 with an engine corpus of 241 files/11,580 bytes, added zero units,
had a zero-second slowest unit, peaked at 38 MiB RSS, created zero artifact
files, and exited zero.

The wire target exercised raw and constructed frame parsing, byte-exact
re-encoding, arbitrary fragmentation and coalescing, ancillary-first
termination, hostile declared lengths, payload-shape rules, exact consumed
counts, stable named rejections, repeat consistency, and decoder cleanup. The
endpoint-state target exercised the complete core and I/O lifecycles, valid
and hostile initiations and replies, core-minted session binding, strictly
monotonic exchange identifiers, one-outstanding work, exhaustion, peer loss,
terminal stability, stable named rejections, and repeat consistency.

The 31 previously registered targets and corpora were classified replay-only:
none compiles or exercises the new dependency-free `qk-ipc` leaf, so none
required a qualifying campaign, corpus minimization or manifest change. All 31
replayed to exit zero on the final source tree and created zero artifact files.
Across qualification, minimization, registration and all retained-corpus
replays, artifact, panic, timeout, sanitizer report, wrong acceptance, unnamed
rejection, parse/encode disagreement, session/order disagreement, terminal
instability, repeat mismatch and observable wipe mismatch counts were zero. No
product source or target oracle changed after qualification began.
