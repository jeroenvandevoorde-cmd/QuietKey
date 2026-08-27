# M27 campaign 007

Status: EXECUTED — QUALIFYING RUN COMPLETE.

Fuzz-target source commit:
`e74fdac0122539a59d9fd10a6956c6763f070f34`.

The fixed tool identities were cargo-fuzz 0.13.2;
`nightly-2026-08-25`; rustc
`1.100.0-nightly (e7769602a 2026-08-24)`; AddressSanitizer;
release-profile overflow checks and debug assertions enabled; dependency
resolution offline. The qualifying run started from exactly 28 public seeds
totaling 116 bytes for `qk_host_sim_m27`.

The executed command was exactly:

```text
PATH=/private/tmp/qk-cargo-fuzz/bin:$PATH fuzz/run-bounded.sh qk_host_sim_m27 100000
```

The runner fixed seed 27001, maximum input length 1,024 bytes, timeout 2 s,
RSS limit 2,048 MiB, corpus reload disabled, and required an empty artifact
directory before starting. The target executes each selected transition trace
twice and requires byte-equal typed outcomes. It checks the exhaustive named
error surface, fixed review and factor order, approval identity binding,
post-approval no-yield behavior, wiping interruption outcomes, stable terminal
behavior, and exact selection of facts from public frozen fixture objects.

The qualifying run executed exactly 100,000 inputs in 3 engine seconds,
averaged 33,333 executions per second, added 557 engine units, and ended at
coverage/features 4,018/5,407 with engine corpus 305 files/3,736 bytes. Peak
RSS was 250 MiB and slowest-unit seconds were zero. Panic, timeout, sanitizer
finding, wrong named outcome, and artifact-file counts were zero. The post-run
filesystem corpus held 327 files totaling 3,832 bytes.

Two copies of that post-run corpus were minimized separately through the
pinned runner. Both copies followed the same sequence: 327 files/3,832 bytes;
280/3,539 with sorted `SHA-256<TAB>bytes` set SHA-256
`2ceefbccf7849edd3ebc729f78f32599662069ffce691b34db8d04c5d79f77d9`;
275/3,510 with `a72f6100062e8577523e3a2f861412d6feaccd6cfe4a908b3a3609323ef90d51`;
and 273/3,490 with
`1e599c5fa1f0517810bd7979eac04c05cf4160830c0148830044f66f310e7f1b`.
A further fresh minimization of each copy preserved that exact final set. Its
273-line, 18,387-byte sorted listing has the same final SHA-256. One proven
copy became the persistent corpus.

The persistent manifest entry block and aggregate each have SHA-256
`eae399b129db95842c312b9a5042e7a9dc819936c6602b790a6c873b7e165566`.
`CORPUS-MANIFEST-M27.tsv` is 43,895 bytes/280 LF with SHA-256
`65fa97df6a9b1c29810dcda2b8dccc9c017904f920ecbbd36bf414a48367e7d4`.

Pinned retained-corpus replay under AddressSanitizer found 273 files/3,490
bytes and executed 275 units. It reported engine corpus 272 files/3,485 bytes,
coverage/features 4,017/5,420, peak RSS 45 MiB, and zero new units,
slowest-unit seconds, or artifact files. The replay exited zero.

A prequalification 10,000-input smoke run preceded the final factor-order
snapshot. It added 161 engine units, ended at coverage/features 3,790/4,749,
used 59 MiB peak RSS, and produced no artifact. Its generated corpus was
discarded before the qualifying run and none of it is registered. No product
source file changed during qualifying generation, minimization, registration,
or replay.
