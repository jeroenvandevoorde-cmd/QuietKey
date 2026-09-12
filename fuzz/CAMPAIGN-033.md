# Campaign 033 — bounded T=1 and SEC1210 readback

Status: PLANNED — NOT EXECUTED.

## Scope and fixed commands

QK-DEC-167-SUP-003 authorizes one joint pure `qk_t1` target and requalification
of the existing `qk_sec1210_wire` target because its selected crate closure
changed. The joint target selects only the nondefault `t1-readback` feature
with default features off: `qk-t1` and `qk-sec1210-wire`, both dependency-free.
The prior target retains its `sec1210-wire` feature and unchanged target bytes.
No UART adapter, operating-system process, wall clock, GPIO, card or bench tool
enters either selected closure. All other 52 corpus roots are replay-only and
remain byte-frozen.

The qualifying runs will be:

```text
fuzz/run-bounded.sh qk_t1 100000
fuzz/run-bounded.sh qk_sec1210_wire 100000
```

The new target pins public seed 167003 and maximum input length 8,192 bytes;
the existing target retains seed 167001 and maximum length 4,096 bytes.
Both retain cargo-fuzz 0.13.2, `nightly-2026-08-25`, rustc
`1.100.0-nightly (e7769602a 2026-08-24)`, AddressSanitizer, release overflow
checks and debug assertions, offline resolution, a two-second per-input
timeout, 2,048 MiB RSS ceiling, disabled corpus reload and final statistics.
Both artifact directories must be empty before the bounded runs.

## Preregistered starting identities

The new root `fuzz/corpus/qk_t1/` contains two public mutation seeds, not wire
frame fixtures: `seed-ccid` is the ASCII string `CCID-parameters` plus LF
(16 bytes, SHA-256
`6523847a6ef12d8dcc2a9ffe4d7dafd5cedd3a3360b0504d7d6405cbdfe54dfa`);
`seed-t1` is `T1-readback` plus LF (12 bytes, SHA-256
`cad5a72512d18453d403a70db27a1edd0ffbedcde5f9e91cde5228b599cb6c2b`).
The starting corpus is 2 files / 28 bytes, manifest entries SHA-256
`3276696359db695227aeaefb9406cd79dfefe9186332ee7fc3fab1f882d03de8`.
The checker pins that exact identity while this campaign is planned and the
new manifest is absent; an altered or untracked seed fails closed.

The retained SEC1210 root starts at Campaign 032's 229 files / 12,921 bytes,
entries SHA-256
`2a5950de303437a3cdfd45b143862575980ca9bb766a9279000b7513874f611b`.
Its prior manifest `fuzz/CORPUS-MANIFEST-SEC1210-R2A.tsv` is 37,027 bytes,
236 LF, SHA-256
`6d4ca0d9dda4b7a4da553fdd3101ae38a92a90b491fbf88c6bc2ac617f7320ef`.
Campaign 032 and that registration remain historical evidence until the
selected root is requalified and its manifest is re-rendered. No previous
qualification is relabeled as this campaign's result.

## Publication, minimization and evidence requirements

Both runs and every minimization must use one future published ancestor
commit containing the final target, model, closure and routing code. No
qualification source is claimed by this planned record. Retain the initial
and post-run roots privately, copy each post-run root independently twice,
and minimize both copies to an agreeing fixed point with the existing
`fuzz/minimize-corpus.sh` routing. Only the two selected roots may change.

The completed record will report each actual platform, every run's executed
input count, start and post-run file counts and bytes, minimization passes,
fixed-point counts and identities, artifacts and retained-corpus replay.
`fuzz/CORPUS-MANIFEST-T1-R2.tsv` and the re-rendered SEC1210 manifest will
bind the same published source. The render modes are `--render-t1-r2` and
`--render-sec1210-r2a` on `tools/check-fuzz-corpora.sh`.

No campaign has run under this record. This is a pure HOST qualification
plan, not a card operation or a physical T=1, timing, endurance, power-cut,
atomicity, hardware-readiness or Gate claim.
