# M22 campaign 002

Fuzz-target source commit: `e6bb7656ae782cd2aa321efa6489853a9c92c756`.
Executed tree and committed-seed source:
`17ed5ea06ca45062c2c04203518bec8832009abf`.

Tool identities: cargo-fuzz 0.13.2; `nightly-2026-08-25`; rustc
`1.100.0-nightly (e7769602a 2026-08-24)`; AddressSanitizer; release-profile
overflow checks and debug assertions enabled; dependency resolution offline.

The campaign started from 15 committed public seeds totaling 113 bytes: three
for `qk_bbqr_codec` and twelve for `qk_bbqr_reassembly`. The executed command
for each target was
`PATH=/private/tmp/qk-cargo-fuzz/bin:$PATH fuzz/run-bounded.sh TARGET 100000`.
The runner supplied the fixed seed and maximum length shown below, timeout 2 s,
RSS limit 2,048 MiB, corpus reload disabled, and an empty per-target artifact
directory.

| Target | Seed | Max bytes | Executed | Final cov/ft | Engine corpus | Post-run files/bytes | New units | Peak RSS MiB | Artifact files | Timeouts |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| `qk_bbqr_codec` | 22001 | 4,297 | 100,000 | 242/496 | 92/3,215 B | 94/3,246 B | 212 | 47 | 0 | 0 |
| `qk_bbqr_reassembly` | 22002 | 16,384 | 100,000 | 508/1,101 | 198/13,070 B | 206/13,086 B | 361 | 499 | 0 | 0 |

Total executed inputs: 200,000. Post-run filesystem inventory: 300 files,
16,332 bytes. Finding artifacts: 0. Timeouts: 0. Product-code findings: 0.

For each target, the post-run directory was copied twice and each copy was
processed by `PATH=/private/tmp/qk-cargo-fuzz/bin:$PATH
fuzz/minimize-corpus.sh TARGET COPY`. Both copies produced the same sorted
`SHA-256<TAB>bytes` content set. One copy became the persistent corpus.

| Target | Minimized files | Bytes | Minimized content-set SHA-256 | Manifest entry-block SHA-256 |
|---|---:|---:|---|---|
| `qk_bbqr_codec` | 79 | 2,908 | `a333d7f16d8dd43a8005b6a56f7737000272a41a9e10414700295850b84a06ec` | `dabe5c51c4c3906f5f4b91ec18951debf24d07ea1f6a3b9168bed91b5f7faae2` |
| `qk_bbqr_reassembly` | 186 | 12,570 | `58287ce746579f37ababe7ec479ae779fc79fadb244cfcf2eee123a73920b889` | `b6e831d382727db9f394b9c89c557a1c00f792dd21b3b459fae60d4399f63d3b` |

The retained inventory is 265 files and 15,478 bytes. Its exact entry block is
SHA-256 `d5d385fee9a8e105d2d4c662ba032ce36b1cf15c08038f8a1897598c9954eb8d`.
`CORPUS-MANIFEST-M22.tsv` is 43,707 bytes/273 LF, SHA-256
`c5477ee7ced132979d8ee04249ec7f1e6fde5feed611e8ca26c19c4c1a941654`.
The exact-cap sentinel from the committed starting corpus remains retained as
23 bytes with content SHA-256
`06f2a006cc71b60535e20b57b9545e85fddfb4c49e33785f61b2edfbc24feeb0`.

`PATH=/private/tmp/qk-cargo-fuzz/bin:$PATH fuzz/replay-corpus.sh TARGET`
then loaded 79 and 186 retained files for `qk_bbqr_codec` and
`qk_bbqr_reassembly` and executed 80 and 187 units, respectively, including
libFuzzer's one empty input per target. The codec replay reported engine corpus
77/2,904 B, cov/ft 242/496, and peak RSS 35 MiB. The reassembly replay reported
engine corpus 178/12,130 B, cov/ft 508/1,101, and peak RSS 39 MiB. Both replays
exited zero and left zero artifact files.

No product source file changed during campaign execution, minimization,
registration, or replay.
