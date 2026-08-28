# M28 campaign 008

Status: EXECUTED — QUALIFYING RUN COMPLETE.

Fuzz-target source commit:
`d9f23e12ddc3bba4e8dcfa65827c8405759c0557`.

The fixed tool identities were cargo-fuzz 0.13.2;
`nightly-2026-08-25`; rustc
`1.100.0-nightly (e7769602a 2026-08-24)`; AddressSanitizer;
release-profile overflow checks and debug assertions enabled; dependency
resolution offline. The qualifying run started with an empty
`qk_host_sim_m28` corpus.

The executed command was exactly:

```text
PATH=/private/tmp/qk-cargo-fuzz/bin:$PATH fuzz/run-bounded.sh qk_host_sim_m28 100000
```

The runner fixed seed 28001, maximum input length 4,096 bytes, timeout 2 s,
RSS limit 2,048 MiB, corpus reload disabled, and required an empty artifact
directory before starting. The target executes each selected input twice and
requires exact typed outcome equality. It checks the served-tier boundary,
Quantum Shelter rejection, provisioning-fact rejection categories, exact
four-line artifact and metadata facts, hostile reopened-record mutations,
all mock-SD lifecycle faults, final-name atomicity, and immutable input bytes.

The qualifying run executed exactly 100,000 inputs in 400 seconds, averaged
250 executions per second, added 157 engine units, and ended at
coverage/features 1,242/2,445 with engine corpus 82 files/1,841 bytes. Peak
RSS was 462 MiB and slowest-unit seconds were zero. Panic, timeout, sanitizer
finding, wrong named outcome, and artifact-file counts were zero. The
post-run filesystem corpus held 81 files totaling 1,840 bytes.

Two copies of that post-run corpus were minimized separately through the
pinned runner. Both copies followed the same sequence: 81 files/1,840 bytes;
76/1,732 with sorted `SHA-256<TAB>bytes` set SHA-256
`0758f0cb0359265c06317622abc4f5ce0bc44ec56af8069cf826489e79295ff0`;
and 72/1,680 with
`cd8239422ec5f82f4b3a757d547e6b6bda60b91ad2e96126cf65e8d1ea911f1e`.
A further fresh minimization of each copy preserved that exact final set. Its
72-line, 4,873-byte sorted listing has the same final SHA-256. One proven copy
became the persistent corpus.

The persistent manifest entry block and aggregate each have SHA-256
`9a81e1f156c921e0757ea489e4c64b9205df9951298a2105ef98363c7e699966`.
`CORPUS-MANIFEST-M28.tsv` is 11,887 bytes/79 LF with SHA-256
`8a776422823a1f4580e51edbe276a459584a121d5f305fa6484498bfdbca743c`.

Pinned retained-corpus replay under AddressSanitizer found 72 files/1,680
bytes and executed 73 units. It reported engine corpus 70 files/1,618 bytes,
coverage/features 1,241/2,444, peak RSS 40 MiB, and zero new units,
slowest-unit seconds, or artifact files. The replay exited zero.

A prequalification 10,000-input smoke run preceded the source commit. Its
generated corpus was discarded before the qualifying run and none of it is
registered. No product source file changed during qualifying generation,
minimization, registration, or replay.
