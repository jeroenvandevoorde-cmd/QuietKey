# V2 slice-3 campaign 009

Status: EXECUTED — BOTH QUALIFYING RUNS COMPLETE.

The `qk_host_sim_m23` target source was
`8f8106c0f0d1be5ca5a57617723d7181dc9041ef`. The corrected
`qk_host_sim_m24` target source was
`e5f2152f2f2b059d80195b188a1312b59f3056bf`. The fixed tool identities were
cargo-fuzz 0.13.2; `nightly-2026-08-25`; rustc
`1.100.0-nightly (e7769602a 2026-08-24)`; AddressSanitizer; release-profile
overflow checks and debug assertions enabled; dependency resolution offline.

The two qualifying commands were exactly:

```text
PATH=/private/tmp/qk-cargo-fuzz/bin:$PATH fuzz/run-bounded.sh qk_host_sim_m23 100000
PATH=/private/tmp/qk-cargo-fuzz/bin:$PATH fuzz/run-bounded.sh qk_host_sim_m24 100000
```

The runners fixed seeds 23002 and 24001 respectively, maximum input length
4,096 bytes, timeout 2 s, RSS limit 2,048 MiB, corpus reload disabled, and an
empty target artifact directory at each qualifying start. Each target executed
the selected hostile input twice and required exact typed outcome equality.

The M23 run started from 246 files/4,769 bytes. Its initial engine corpus was
130 files/3,311 bytes. It executed exactly 100,000 inputs in 42 seconds,
averaged 2,380 executions per second, added 419 engine units, and ended at
coverage/features 2,074/3,450 with engine corpus 273 files/6,174 bytes. Peak
RSS was 429 MiB and slowest-unit seconds were zero. Its post-run filesystem
corpus held 430 files/9,744 bytes.

Two M23 post-run copies were minimized separately and produced the same set at
each recorded stage. Their file-count sequence was
430 -> 254 -> 243 -> 241 -> 239 -> 239. The 254-file stage held 5,747 bytes
with sorted `SHA-256<TAB>bytes` set SHA-256
`eb44a995f20e747121137ea72e3a77351ca0447fe9807b2dbf392a0d4d5271bb`;
the 243-file stage held 5,600 bytes with
`6a45b9483f59be1a29d79e01d2f7c4b62616718d0f9022c431c45bf8c22b6fe5`.
The matching stable M23 set contains 239 files/5,537 bytes. Its 239-line,
16,133-byte sorted listing has SHA-256
`bacdfb381caa0f28262e3e6174b585eecd99b3cb3ff63b5aff27ae70c5777cc6`.

The M24 run started from 267 files/4,812 bytes. Its initial engine corpus was
136 files/3,165 bytes at coverage/features 2,880/4,811. It executed exactly
100,000 inputs in 202 seconds, averaged 495 executions per second, added 393
engine units, and ended at coverage/features 3,104/5,371 with engine corpus
297 files/7,680 bytes. Peak RSS was 459 MiB and slowest-unit seconds were
zero. Its post-run filesystem corpus held 461 files/11,442 bytes.

Two M24 post-run copies were minimized separately and produced the same set.
Their file-count sequence was 461 -> 281 -> 272 -> 268 -> 268. The matching
stable set contains 268 files/7,157 bytes. Its 268-line, 18,108-byte sorted
listing has SHA-256
`4e8135bd6ee7e447a17238a14c1c8501659abdd56ef9673fb0b04de626bd3ba3`.
One matching copy of each corpus became persistent.

`CORPUS-MANIFEST-M23.tsv` retains the earlier `qk_psbt_m23` source pin and
records campaign source `8f8106c0f0d1be5ca5a57617723d7181dc9041ef` for the migrated host target.
Its host-target entry block has SHA-256
`e0d303f30d813b0d14b54af443f2287f6da42d0bedf3ac4fa494aa94d8f1e5be`;
the 474-file/10,637-byte partition aggregate has SHA-256
`b80cf2875ef11028076b5ac7cfcab47a4d89896de85f66af37b14376de0b1c8e`.
The manifest is 74,301 bytes/483 LF with SHA-256
`d273219f0916d2f4427e99821d72039470bf5745b4c296b6cdb54ea9e1d283b1`.

`CORPUS-MANIFEST-M24.tsv` advances to generation V2 and records campaign
source `e5f2152f2f2b059d80195b188a1312b59f3056bf`. Its 268-file/7,157-byte
entry block and aggregate each have SHA-256
`32b854525bca9b38573cc46b6b58832f6dbb607ea4cd0099b2dc5ca8dd596ea4`.
The manifest is 43,156 bytes/275 LF with SHA-256
`edc072ada221038bff8f7adb9e3005966303ade851d6b1d197ab75605a86d604`.

Pinned retained-corpus replay under AddressSanitizer executed 241 M23 units
from 239 files/5,537 bytes and reported engine corpus 239 files/5,537 bytes,
coverage/features 2,074/3,450, peak RSS 43 MiB, and zero new units,
slowest-unit seconds, or artifact files. M24 replay executed 269 units from
268 files/7,157 bytes and reported engine corpus 268 files/7,157 bytes,
coverage/features 3,104/5,371, peak RSS 52 MiB, and the same zero counts. Both
replays exited zero.

Two M24 prequalification stops exposed target-control precedence mistakes,
not product defects. At source `8f8106c0f0d1be5ca5a57617723d7181dc9041ef`,
tracked input `40 41 68` stopped after 16 executions because the target
expected `InvalidMockSignature` after the already-planned identical terminal
signature; the product returned the ordered `DuplicateSignature`. The raw
3-byte unit is registered at
`fuzz/corpus/qk_host_sim_m24/40e1cf098e73adb245671281894fcb36c0f6a0c0`
with SHA-256
`02c8404fd928e1ceb815a777ba2b0961d6ee6866dbb2bfcd8949153520373f76`.
A pinned minimization attempt reproduced it, then libFuzzer itself asserted in
`SetMaxInputLen`, emitted a zero-byte non-finding, and was interrupted; the
original tracked 3-byte unit is the regression control.

At source `bfbdeee4e5436ac0d8d7afd713d6d3664a7ae6c9`, tracked input
`ff 5e 5e` stopped after 21 executions because the target expected
`DuplicateSignature` after a wrong terminal key; the lower-sorted terminal
role returned `TerminalKeyMismatch` first. Its raw 3-byte artifact had SHA-256
`d1608daab918075328a6a8dfa33d914157c921b1d62185e92955319643619bfd`.
It is registered here as the exact bytes formerly at
`fuzz/corpus/qk_host_sim_m24/00415145c0a1a93709b9b9304948099630dccaee`
in source `bfbdeee4e5436ac0d8d7afd713d6d3664a7ae6c9`; the qualifying minimizer
removed it from the current set. The two source corrections changed only exact
target expectations. Raw artifact-directory copies stayed outside Git for the
session. Every qualifying generation, minimization, registration, and replay
artifact count was zero.

Across both qualifying campaigns, panic, timeout, sanitizer finding, wrong
named outcome, wrong acceptance, partial-output release, and artifact-file
counts were zero. No product source changed during qualifying generation,
minimization, registration, or replay.
