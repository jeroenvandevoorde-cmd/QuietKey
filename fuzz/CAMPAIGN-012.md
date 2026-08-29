# V2 slice-6 campaign 012

Status: EXECUTED — QUALIFYING RUN COMPLETE.

Fuzz-target source commit:
`ecf9a46d4c4068045003366643571eb0b8ea90db`.
Qualifying-run tree and committed-seed source:
`3d432255ebb516fc91824c0c98f970f8aacb8fc4`.

The fixed tool identities were cargo-fuzz 0.13.2;
`nightly-2026-08-25`; rustc
`1.100.0-nightly (e7769602a 2026-08-24)`; AddressSanitizer;
release-profile overflow checks and debug assertions enabled; dependency
resolution offline. The qualifying run started from exactly five committed
`qk_host_sim_v2_s6_watch_only` seeds totaling 10 bytes. Their initial manifest
entry-block SHA-256 was
`9dd5aa599c2a70ec271ac5d1ea8c3cf5ecfc0448332162ce6c7b5e5c8ae6a4f1`.

The exact qualifying command was:

```text
fuzz/run-bounded.sh qk_host_sim_v2_s6_watch_only 100000
```

The command fixed seed 126001, maximum length 4,096, timeout 2 seconds, RSS
limit 2,048 MiB, corpus reload off, AddressSanitizer, and final-stat reporting.
It executed exactly 100,000 inputs in 225 engine seconds at 444 executions per
second. It finished at coverage/features 1,211/2,298 with an engine corpus of
101 files/1,791 bytes, added 199 engine units, had a zero-second slowest unit,
peaked at 456 MiB RSS, and produced zero artifact files.

For every presented input, the target selected a coordinator tier, mutated the
registered immutable provisioning facts, exercised the exact BSMS reopen path,
and selected every mock-SD lifecycle failure. It ran the same input twice and
required byte-equal typed outcomes. Its oracles locked the Quantum Shelter
SD-only rejection, all named construction and reopen rejections, the golden
408-byte record and bound metadata, filename construction, immutable input,
complete-only final names, unchanged destination namespace on failure, and the
expected typed result for every injected fault.

After the writer exited, two copies of the 104-file post-run set were minimized
serially. Both copies progressed identically through 94, 93, and 89 files,
then remained unchanged on the next pass. Both merge paths preserved
coverage/features 1,222/2,309. Their final sorted
`SHA-256<TAB>bytes` listings were byte-identical: 89 entries, 1,573 corpus
bytes, a 6,005-byte listing, and listing SHA-256
`be4ab1aab6e0dbeb551934b031e33695b7e6dd324c05fedae42ebe39d3507332`.
No concurrent process wrote either minimization or artifact directory.

That fixed-point set became the persistent corpus. Its manifest entry block
has SHA-256
`d9f1992935d139e317b0f575139ecb9ba3e05038a065d7355993e8c30156bd58`.
`CORPUS-MANIFEST-V2-S6.tsv` is 16,925 bytes/96 LF with SHA-256
`f3038487c04d8bf051b668e5fe0a453430fc704dfed3349f73a27d8d2ee98d77`;
its aggregate is 89 files/1,573 bytes with the same entry-block SHA-256. The
complete path, byte-count, and content-hash check passed.

Retained-corpus replay loaded 89 files totaling 1,573 bytes with minimum length
1 and maximum length 153. It executed 90 units at coverage/features
1,211/2,298, added zero units, had a zero-second slowest unit, peaked at 40 MiB
RSS, created zero artifact files, and exited zero.

Across qualification, minimization, import, and retained replay, panic,
timeout, sanitizer report, wrong acceptance, wrong named rejection, partial
artifact, residual fuzz artifact, input mutation, final-name exposure before
verification, and destination-namespace mutation outside the registered
temporary-file allowance counts were all zero. No product source or target
oracle changed after qualification began.
