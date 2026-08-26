# M25 campaign 005

Status: PREREGISTERED — QUALIFYING RUN NOT EXECUTED.

Fuzz-target source commit:
`716e216e84d5a693ac8aa1abe07e3e0ca1f4f31e`.

The fixed tool identities are cargo-fuzz 0.13.2; `nightly-2026-08-25`;
rustc `1.100.0-nightly (e7769602a 2026-08-24)`; AddressSanitizer; release-profile
overflow checks and debug assertions enabled; dependency resolution offline.

The preregistered public inventory is exactly 30 committed seeds totaling 166
bytes for `qk_host_sim_m25`. It covers all three tiers, both artifact selectors,
Quantum Shelter's unavailable finalized-PSBT branch, all nine named mock-SD
failures plus success for both artifact kinds, successful single- and
multi-frame finalized-PSBT BBQr, invalid part geometry, and a full 16-byte
caller nonce override. All workflow
facts come only from the dedicated public, permanently NEVER-FUND M25 fixture;
the target imports no private key or nonce.

The command to execute is exactly:

```text
PATH=/private/tmp/qk-cargo-fuzz/bin:$PATH fuzz/run-bounded.sh qk_host_sim_m25 100000
```

The runner fixes seed 25001, maximum input length 4,096 bytes, timeout 2 s,
RSS limit 2,048 MiB, corpus reload disabled, and requires an empty artifact
directory before starting. Success requires exactly 100,000 executed inputs,
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

After execution, two copies of the post-run corpus will be minimized separately
with the pinned `fuzz/minimize-corpus.sh` path. Their sorted
`SHA-256<TAB>bytes` content sets must agree before one copy replaces the
persistent corpus. The retained manifest is then rendered against the unchanged
source commit above and replayed once with `fuzz/replay-corpus.sh`.

No campaign result is recorded by this preregistration.

Before a qualifying run, an initial invocation was interrupted after exactly
54,082 inputs when inspection found that `simple_psbt_part_four` selected the
7-byte geometry instead of its named 4-byte geometry. That partial invocation
reported 39 new engine units, zero slowest-unit seconds, peak RSS 440 MiB and
zero artifact files; its 26 untracked corpus additions were discarded. The
seed control byte was corrected and the manifest regenerated before restart.
No result from the interrupted invocation is part of campaign 005.
