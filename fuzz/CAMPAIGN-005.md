# M25 campaign 005

Status: EXECUTED — QUALIFYING RUN COMPLETE.

Fuzz-target source commit:
`33fdd062828306a20f69660a09f782efc6363aa5`.
Qualifying-run tree and committed-seed source:
`e454c66d15c9d4a37647afd677a975eda8dc6882`.

The fixed tool identities are cargo-fuzz 0.13.2; `nightly-2026-08-25`;
rustc `1.100.0-nightly (e7769602a 2026-08-24)`; AddressSanitizer; release-profile
overflow checks and debug assertions enabled; dependency resolution offline.

The qualifying run started from exactly 30 committed seeds totaling 166
bytes for `qk_host_sim_m25`. It covers all three tiers, both artifact selectors,
Quantum Shelter's unavailable finalized-PSBT branch, all nine named mock-SD
failures plus success for both artifact kinds, successful single- and
multi-frame finalized-PSBT BBQr, invalid part geometry, and a full 16-byte
caller nonce override. All workflow
facts come only from the dedicated public, permanently NEVER-FUND M25 fixture;
the target imports no private key or nonce.

The executed command was exactly:

```text
PATH=/private/tmp/qk-cargo-fuzz/bin:$PATH fuzz/run-bounded.sh qk_host_sim_m25 100000
```

The runner fixes seed 25001, maximum input length 4,096 bytes, timeout 2 s,
RSS limit 2,048 MiB, corpus reload disabled, and requires an empty artifact
directory before starting. Success required exactly 100,000 executed inputs,
zero artifact files, and no panic, sanitizer finding, timeout, or wrong named
outcome.

For every presented input, the target reconstructs the exact threshold-complete
M25 fixture through the M23/M24 capability path without signing material, binds
the M25 export owner, and runs the selected tier, artifact, BBQr geometry, nonce,
and SD edge twice. Both typed outcomes must be byte-equal. Every rejection must
remain on the exhaustive named `BbqrError` or `SdExportError` surface; every
failed SD call must preserve the input and never create or replace a final file;
every successful final must contain the exact bound artifact. Raw transactions
have no BBQr route, and Quantum Shelter exposes no finalized PSBT.

The qualifying run executed exactly 100,000 inputs in 836 seconds, averaged 119
executions per second, added 51 engine units and ended at coverage/features
2,857/3,235 with engine corpus 21 files/82 bytes. The post-run filesystem held
58 files. Peak RSS was 441 MiB; slowest-unit seconds, timeout count,
artifact-file count, sanitizer findings and product-code findings were all zero.

Two copies of that 58-file post-run corpus were processed separately with the
pinned `fuzz/minimize-corpus.sh` path. Both produced the same 20-file/78-byte
sorted `SHA-256<TAB>bytes` content set: 1,341 bytes/20 LF with SHA-256
`9d3b7603d044e682772b4aca71591fe5604886124c50c87d549270f7b6d19992`.
One copy became the persistent corpus. Its manifest entry block is SHA-256
`b2ebc25575baa637dbf1724392599c8c06baa12e0de46ade18974790446bf654`;
`CORPUS-MANIFEST-M25.tsv` is 3,567 bytes/27 LF with SHA-256
`807a3121f744d253db566ac1cb5f822d7b297874a576e26c8bd0c3ae7e418a8e`.

The retained-corpus replay loaded 20 files and executed 21 units. It reported
engine corpus 18 files/71 bytes, coverage/features 2,856/3,235, peak RSS 42 MiB,
zero new units, zero slowest-unit seconds and zero artifact files. Before that
replay, commit `46080ff75a5465dde503f1392bc69875d124fdab` clarified the
fixture's construction comments without changing any parsed field or constructed
transaction fact. No product source file changed during campaign execution,
minimization, registration or replay.

Before a qualifying run, an initial invocation was interrupted after exactly
54,082 inputs when inspection found that `simple_psbt_part_four` selected the
7-byte geometry instead of its named 4-byte geometry. That partial invocation
reported 39 new engine units, zero slowest-unit seconds, peak RSS 440 MiB and
zero artifact files; its 26 untracked corpus additions were discarded. The
seed control byte was corrected and the manifest regenerated before restart.
The campaign source was then rebound to the commit that completed the fixture's
recorded entropy-generation procedure; no constructed transaction fact changed.
No result from the interrupted invocation is part of campaign 005.
