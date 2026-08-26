# M21 campaign 001

Source commit: `f4ce49644c0bbc0b703296e316488e9f7e4c82d7`

Tool identities: cargo-fuzz 0.13.2; `nightly-2026-08-25`; rustc
`1.100.0-nightly (e7769602a 2026-08-24)`; AddressSanitizer; release-profile
overflow checks and debug assertions enabled; dependency resolution offline.

Each target started from the one committed seed at the source commit. The
executed campaign command was
`PATH=/private/tmp/qk-cargo-fuzz/bin:$PATH fuzz/run-bounded.sh TARGET 100000`.
The runner supplied the fixed seed and maximum length shown below, timeout 2 s,
RSS limit 2,048 MiB, corpus reload disabled, and an empty per-target artifact
directory.

| Target | Seed | Max bytes | Executed | Final cov/ft | Engine corpus | Post-run files/bytes | New units | Peak RSS MiB | Artifact files |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| `qk_psbt` | 21001 | 4,096 | 100,000 | 318/400 | 88/5,269 B | 88/5,269 | 216 | 194 | 0 |
| `qk_descriptor` | 21002 | 891 | 100,000 | 543/1,029 | 169/2,366 B | 170/2,385 | 563 | 163 | 0 |
| `qk_a1` | 21003 | 96 | 100,000 | 243/311 | 40/1,533 B | 40/1,533 | 52 | 43 | 0 |
| `qk_a1_codec` | 21004 | 512 | 100,000 | 667/2,071 | 546/27 KiB | 546/28,294 | 682 | 67 | 0 |
| `qk_card_trace` | 21005 | 4,096 | 100,000 | 391/642 | 170/33 KiB | 167/34,427 | 535 | 131 | 0 |

Total executed inputs: 500,000. Post-run filesystem inventory: 1,011 files,
71,908 bytes. Finding artifacts: 0. Timeouts: 0. Product findings: 0.

For each target, the post-run directory was copied twice and each copy was
processed by `PATH=/private/tmp/qk-cargo-fuzz/bin:$PATH
fuzz/minimize-corpus.sh TARGET COPY`. Both copies produced the same sorted
`SHA-256<TAB>bytes` content set. One copy became the persistent corpus.

| Target | Minimized files | Bytes | Minimized content-set SHA-256 | Manifest entry-block SHA-256 |
|---|---:|---:|---|---|
| `qk_psbt` | 79 | 4,664 | `d6d0d094ed318a59680fe6cf3a827bf4cd8c19224f5d8eb4b5bcef4d330a3119` | `a80230c71332bd61440000f982f18857079a7250638672221cf1e37ec0a8616c` |
| `qk_descriptor` | 136 | 1,896 | `25f98ad5ca96bc5369be089646d52737b306cc295be1f0ad556b94dc1c249591` | `2b35aa0475206af885e3d91852748b07c4337fef56e8b34968a8eb53754d27b6` |
| `qk_a1` | 38 | 1,438 | `5460deb6a3b203caeae2f50ec6e74d92aae71c7f21689e356b048049cd9d9ea2` | `3af1a44e395278c9c856ef181a3b33a8cea4b8d8fb172fe876fac2aa7176300d` |
| `qk_a1_codec` | 467 | 24,985 | `f1c551eb5d1bac9f7fe59bcc03c0f0c7a3f76fb5d70d716a5646dd06abf9bc5c` | `1557711fc21747afefaa59bb4dec80ef53e4fb9bdcf15a0005236c8a252f7cff` |
| `qk_card_trace` | 146 | 30,405 | `c4cf6de861f35ee63c6e0edbfb62e305d870d43b2035becdd14134d3f2d2ab4c` | `13291310a1dd04f1bfedf644721b63d4b28b503f529a457b4b3da7579f88440b` |

The retained inventory is 866 files and 63,388 bytes. Its exact entry block is
SHA-256 `0e3e633b291f5f5015923085ae0d43e91658302b514d2af09480cb9428b67ce8`.
`CORPUS-MANIFEST.tsv` is 132,516 bytes/877 LF, SHA-256
`e8374e4197c02cfd0f5b4728c74706936c968c25279df0244470afd467747692`.

`PATH=/private/tmp/qk-cargo-fuzz/bin:$PATH fuzz/replay-corpus.sh TARGET`
then loaded 79/136/38/467/146 retained files for
`qk_psbt`/`qk_descriptor`/`qk_a1`/`qk_a1_codec`/`qk_card_trace` and executed
80/137/39/468/147 units respectively, including libFuzzer's one empty input per
target. All five replays exited zero and left zero artifact files.

Before the source commit, an exploratory codec run stopped on a target-only
assertion that treated noncanonical terminal padding as a correctable symbol
error. The generator was restricted to data-symbol positions, the raw artifact
was excluded, 829 exploratory corpus units were moved outside the worktree, and
all five source corpora were reset to their single committed seeds. No `host/`
file changed.
