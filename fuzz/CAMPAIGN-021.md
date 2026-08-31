# Process slice 2 campaign 021

Status: EXECUTED — QUALIFYING RUN COMPLETE.

The common fuzz-target source commit was
`532aed2675ca1625454e374cc118d377c9b77fcc`. The fixed tool identities were
cargo-fuzz 0.13.2; `nightly-2026-08-25`; rustc
`1.100.0-nightly (e7769602a 2026-08-24)`; AddressSanitizer; release-profile
overflow checks and debug assertions enabled; and offline dependency
resolution. The exact qualifying commands were:

```text
fuzz/run-bounded.sh qk_supervisor_lifecycle 100000
fuzz/run-bounded.sh qk_decoy_calculator 100000
```

`qk_supervisor_lifecycle` used public seed 142001, maximum input length 4,096,
timeout 2 seconds, RSS limit 2,048 MiB, corpus reload off, and final-stat
reporting. It started from three public seed files totaling 44 bytes. It
executed exactly 100,000 inputs in 1 second at 100,000 executions per second,
finished at coverage/features 195/539, added 291 engine units, had a zero-second
slowest unit, peaked at 169 MiB RSS, and created zero artifact files. The final
in-memory engine statistic was 108 units/4,425 bytes; the post-run filesystem
corpus contained 107 files/4,424 bytes. That filesystem corpus's 7,252-byte
sorted `SHA-256<TAB>bytes` listing had SHA-256
`e182f3af1c81bfa560c043e07fe2ddb926bb0e0fce9b2348bf01e74cd3e7fbb1`.

Two copies of that supervisor corpus were minimized serially. Both copies
followed the same complete progression:

- 107 files/4,424 bytes, 7,252-byte listing SHA-256
  `e182f3af1c81bfa560c043e07fe2ddb926bb0e0fce9b2348bf01e74cd3e7fbb1`;
- 102 files/3,946 bytes, 6,911-byte listing SHA-256
  `88169d617151af8a39274022b14522882f324857df4b974a084408ec14006eca`;
- 100 files/3,896 bytes, 6,775-byte listing SHA-256
  `8605c57fef4ddd490a1b1abd25a7a7767f473f4683b6210437bb25dcc5236c88`;
- a further pass left that 100-file set unchanged.

`qk_decoy_calculator` used public seed 142002, maximum input length 2,048, and
the same timeout, RSS, reload, sanitizer, assertion, overflow, and reporting
settings. It started from three public seed files totaling 56 bytes. It
executed exactly 100,000 inputs in 4 seconds at 25,000 executions per second,
finished at coverage/features 741/3,368, added 1,223 engine units, had a
zero-second slowest unit, peaked at 110 MiB RSS, and created zero artifact
files. The post-run corpus contained 553 files/13,799 bytes. Its 37,528-byte
sorted `SHA-256<TAB>bytes` listing had SHA-256
`1c34e7ef7e49f98e0d5a7ec48adab4082df1cb3f10bdf11fcdb54fc646430774`.

Two copies of that calculator corpus were minimized serially. Both copies
followed the same complete progression:

- 553 files/13,799 bytes, 37,528-byte listing SHA-256
  `1c34e7ef7e49f98e0d5a7ec48adab4082df1cb3f10bdf11fcdb54fc646430774`;
- 462 files/11,453 bytes, 31,341-byte listing SHA-256
  `81c880d78047ae1a88043ec4719800fa22dd289b2c1d65d0c1f32f6a16193c53`;
- 454 files/11,228 bytes, 30,798-byte listing SHA-256
  `740c2a5ec2da1ea54a2a09d8823ff0e1141c616e25b427dfb5cf746d83e34374`;
- 450 files/11,151 bytes, 30,526-byte listing SHA-256
  `4a374ddea2e3cd1c6d22e7edd6176cedfa08256bcb8f7427116763d180f02242`;
- 447 files/11,066 bytes, 30,322-byte listing SHA-256
  `bf949b7f54b287a2327a20cfcaf5b67174aadaca09912e152b8d55a34c54cfd5`;
- 446 files/11,004 bytes, 30,254-byte listing SHA-256
  `c6c15a15f9d659f89e37e7e49347dd6f5cfadda94bfd3b5e25bb19d93de83bc9`;
- a further pass left that 446-file set unchanged.

For each target, the two fixed-point listings were byte-identical. No
concurrent process wrote either target's two minimization copies or artifact
directory. The matching fixed-point sets became the persistent corpora.
`qk_supervisor_lifecycle` retained 100 files/3,896 bytes with manifest
entry-block SHA-256
`c38b76e5b17aaf38ce19d1fb62598bd20220be535da42830b5eac6c9d4d18067`;
`qk_decoy_calculator` retained 446 files/11,004 bytes with manifest entry-block
SHA-256
`03fb5a4bfd84506f796bfd34c750f674f93839ef9c0eea804e60a7a160805cb5`.
The aggregate is 546 files/14,900 bytes with entry-block SHA-256
`8595ce60827158244819029e31bb62e5304a54469bbca53be6cd98af961d1771`.
`CORPUS-MANIFEST-PROCESS-S2.tsv` is 92,994 bytes/554 LF with SHA-256
`a546263a4f2f7599768eb0960aeb4c10b4ca5982b9e6bbd5d9d96469fdf03251`.

Retained-corpus replay for `qk_supervisor_lifecycle` loaded all 100 files
totaling 3,896 bytes and executed 101 units. It finished at coverage/features
195/539 with an engine corpus of 100 files/3,896 bytes, added zero units, had a
zero-second slowest unit, peaked at 36 MiB RSS, created zero artifact files,
and exited zero. Retained-corpus replay for `qk_decoy_calculator` loaded all
446 files totaling 11,004 bytes and executed 447 units. It finished at
coverage/features 741/3,368 with an engine corpus of 446 files/11,004 bytes,
added zero units, had a zero-second slowest unit, peaked at 40 MiB RSS, created
zero artifact files, and exited zero.

The 33 previously registered targets and corpora were classified replay-only:
none invokes the new calculator or supervisor target models, so none required
a qualifying campaign, corpus minimization, or manifest change. All 35
registered corpora replayed to exit zero on the final source tree, executing
5,484 replay units in total and creating zero artifact files. The calculator
oracle covered total fixed-decimal transition, arithmetic, rounding, display,
named-rejection, repeated-outcome, and no-silent-key behavior. The supervisor
oracle covered grant order, decoy-before-product sequencing, loss and failure
termination, no restart, named outcomes, and absorbing terminal behavior. Real
`recvmsg`, `SCM_RIGHTS`, fragmentation, coalescing, and EOF remained covered by
the deterministic HOST integration tests rather than fuzzer syscalls. Across
qualification, minimization, registration, and all retained-corpus replays,
the observed panic, timeout, sanitizer-report, wrong-acceptance,
unnamed-rejection, model-disagreement, terminal-instability, repeat-mismatch,
and artifact-file counts were zero. No product source or target oracle changed
after qualification began.
