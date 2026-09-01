# Process slice 8 campaign 027

Status: EXECUTED — QUALIFYING RUN COMPLETE.

Qualification source: `1c98359cd8f9105c4280a2ca035eb8acbfca5efc`.

## Common method

Both targets ran from the preserved pre-repair minimization fixed points through
`fuzz/run-bounded.sh` for exactly 100,000 inputs. The fixed tool identities
were cargo-fuzz 0.13.2; `nightly-2026-08-25`; rustc
`1.100.0-nightly (e7769602a 2026-08-24)`; AddressSanitizer; release-profile
overflow checks and debug assertions enabled; and offline dependency
resolution. Corpus reload was disabled, the input timeout was two seconds, the
RSS ceiling was 2,048 MiB, final statistics were enabled, and both artifact
directories began and remained empty. The exact commands were:

```text
fuzz/run-bounded.sh qk_supervisor_lifecycle 100000
fuzz/run-bounded.sh qk_supervisor_process_lifecycle 100000
```

The targets used seed/max_len pairs 142001/4,096 and 154001/4,096.

## Qualification results

| Target | Start files/bytes | Engine seconds; rate/s | Coverage/features | Live files/bytes | New units | Peak RSS MiB | Persisted post-run files/bytes | Real seconds | Artifacts |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| `qk_supervisor_lifecycle` | 103/5,732 | 3; 33,333 | 187/566 | 108/7,900 | 48 | 355 | 137/12,840 | 4.43 | 0 |
| `qk_supervisor_process_lifecycle` | 134/5,789 | 4; 25,000 | 221/722 | 146/11,137 | 119 | 311 | 222/17,781 | 4.91 | 0 |

Both targets executed exactly 100,000 inputs, exited zero and reported a
zero-second slowest input. The live corpus facts are libFuzzer's in-memory
facts; the persisted facts are the complete post-run filesystem roots.

The post-run canonical sorted `SHA-256<TAB>bytes` listings were:

| Target | Listing bytes/LF | SHA-256 |
|---|---:|---|
| `qk_supervisor_lifecycle` | 9,315/137 | `c579137bf648ee8c459754e3a280a618ce17b362bc5f62d9545111edad399c80` |
| `qk_supervisor_process_lifecycle` | 15,087/222 | `0e4df230676e616b1ce7f162c457618bd1fed392ae486fb5f9bf1107cbb7f267` |

## Two-copy minimization and promotion

Two separately copied post-run roots for each target were minimized through
an unchanged confirmation pass. Each pair agreed byte for byte at its fixed
point and every pass exited zero:

- `qk_supervisor_lifecycle`: 137/12,840 → 110/7,953 → 108/7,900 →
  unchanged. Its final canonical listing is 7,331 bytes/108 LF with SHA-256
  `4d26ca0be75e543f25118fa2415677082c2481843e85ce368139b2a4e2d4f473`.
- `qk_supervisor_process_lifecycle`: 222/17,781 → 145/10,876 → unchanged.
  Its final canonical listing is 9,837 bytes/145 LF with SHA-256
  `0ff3e70f8c011c88d7d0abecdf8d4707c345b41b32416410583629fddbc07cbe`.

The agreed fixed points replaced the working corpus roots. Before this slice,
the registered PROCESS-S2 `qk_supervisor_lifecycle` entry hash was
`c38b76e5b17aaf38ce19d1fb62598bd20220be535da42830b5eac6c9d4d18067`;
its 100-file/3,896-byte canonical listing was 6,775 bytes/100 LF with SHA-256
`8605c57fef4ddd490a1b1abd25a7a7767f473f4683b6210437bb25dcc5236c88`.
The new process-lifecycle target had no prior registered campaign fixed point.

The final PROCESS-S8 manifest binds the qualification source and registers:

| Target or aggregate | Files/bytes | Entries SHA-256 |
|---|---:|---|
| `qk_supervisor_lifecycle` | 108/7,900 | `63e9422d842f49ca48277039362206ccd023e34c3bfe0e0be753db92e732979e` |
| `qk_supervisor_process_lifecycle` | 145/10,876 | `0c997aecc85a3f30aac8077fb8bf08c78e295d7c5dcc3d5e5aad7ac3968e623e` |
| aggregate | 253/18,776 | `648890a93eea5216a6deeadd47dd328fca4eac083a03cfb65e79eadf023e858d` |

The entries hashes use the manifest's canonical
`class<TAB>target<TAB>bytes<TAB>sha256<TAB>path` serialization. The separate
listing hashes above intentionally omit class, target and path.

QK-DEC-146 promotion also re-rendered PROCESS-S2. Its prior manifest bound
source `532aed2675ca1625454e374cc118d377c9b77fcc`, was 92,994 bytes/554 LF
with SHA-256
`a546263a4f2f7599768eb0960aeb4c10b4ca5982b9e6bbd5d9d96469fdf03251`,
and registered aggregate 546/14,900 with entries SHA-256
`8595ce60827158244819029e31bb62e5304a54469bbca53be6cd98af961d1771`.
The re-rendered manifest binds the qualification source, is 94,414 bytes/562
LF with SHA-256
`2d2af30d1beb69fb4bdb73790e77d42355bba16e1c4f927aec2acb885cfb6a14`,
and registers aggregate 554/18,904 with entries SHA-256
`bd843e50f8a1436fa896d54180415dd3e1f3ea4cda9747e9ce31232ba4e8a6ae`;
the `qk_decoy_calculator` entry remains byte-identical.

## Superseded pre-repair execution

Both targets previously completed 100,000-input runs and two-copy
minimizations at `f31b0d03fda87627d206f8ff4d4ef7d7685d6a1f`. No finding was produced,
but review then found an EOF handoff defect and the resulting 103/5,732 and
134/5,789 fixed points were retained only as the starting corpora for the
post-repair qualification. They are not the registered qualification facts.

## Final retained-corpus replay

`qk_supervisor_lifecycle` loaded 108 files/7,900 bytes and executed 109 units;
coverage/features were 187/566, peak RSS was 36 MiB and zero units were added.
`qk_supervisor_process_lifecycle` loaded 145 files/10,876 bytes and executed
146 units; coverage/features were 221/722, peak RSS was 36 MiB and zero units
were added. Both replays exited zero, created zero artifacts and left their
complete filesystem corpus roots unchanged.
