# Process slice 9 campaign 028

Status: PLANNED — NOT EXECUTED.

## Qualification boundary

The qualification source is not fixed yet. It must be the final source commit
containing the complete QK-DEC-156 implementation, and neither target nor any
selected dependency may change after that commit and before both campaigns,
both two-copy minimizations, registration, and final replay complete. The
fixed tool identities are cargo-fuzz 0.13.2; `nightly-2026-08-25`; rustc
`1.100.0-nightly (e7769602a 2026-08-24)`; AddressSanitizer; release-profile
overflow checks and debug assertions enabled; and offline dependency
resolution.

The exact qualifying commands will be:

```text
fuzz/run-bounded.sh qk_device_wire 100000
fuzz/run-bounded.sh qk_core_normal_process 100000
```

`qk_device_wire` uses public campaign seed 156001 and maximum fuzzer input
length 65,536. Its 16 control bytes are separate from the candidate frame; one
registered selector synthesizes the exact 262,169-byte maximum QKDV chunk
presentation without raising the fuzzer-input limit. `qk_core_normal_process`
uses public campaign seed 156002 and maximum input length 4,096. Both use a
two-second per-input timeout, 2,048 MiB RSS
ceiling, disabled corpus reload, final statistics, and an empty artifact
directory. Each run must execute exactly 100,000 inputs, exit zero, and retain
zero artifacts.

## Starting corpus registration

The canonical `qk_device_wire` seeds are registered byte for byte:

| Capability/body seed | Bytes | SHA-256 | Corpus path |
|---|---:|---|---|
| Display Stage | 33 | `ca70ad8631f185fc479da14639164f47cffe5bb14b7f9a49f5cd88da08ea6f3a` | `fuzz/corpus/qk_device_wire/e06bf9680cd4b55a35ab0efbe0e21f02a1d0c28d` |
| Keypad Key | 34 | `830b1f3f0636c541e704621db9b545e80c4de31c7326f9a827eedae9653ede39` | `fuzz/corpus/qk_device_wire/87525ea6177bc75b0bac24ef378adc779986b592` |
| CardResponse Profile | 33 | `cc49e539eb0f93cfe9cb2afc02fc61c82bdd3403414af2670c441e59d12da64e` | `fuzz/corpus/qk_device_wire/484730dada1bbe3f1a4b9b4cc40db6527e473c2c` |
| CardRequest ReadProfile | 32 | `1b82867efe853641a336f688492de742415d548f560c46b645665d03ce91d4a5` | `fuzz/corpus/qk_device_wire/747edf069ea18aefe0a09016ad03696a808709ef` |
| CameraInput Kit Begin and maximum-chunk selector | 37 | `3c77d87b51f9c8e2935ddd499aaad8bca8387e02341e5a336dd5bc8160f2a011` | `fuzz/corpus/qk_device_wire/378f905a795c7e13265db779835221b2ec939766` |
| MediaInput ReadBegin | 45 | `b338408625aec411d35765a95f8dbcd2ec44864e0f5e3a423c618cf82a01cf8a` | `fuzz/corpus/qk_device_wire/ba9dbe6c3ed965fc79ca227f212a9a297063bb62` |
| PrintOutput A1 Begin and oversized-direct-chunk selector | 39 | `b56819bc3a01d280a904e6b3319ed09142ff2742636534ae0ae46ad73e2379f8` | `fuzz/corpus/qk_device_wire/865fd762f6f8fa9abda119f8517ecae42e20c3a8` |
| MediaOutput RawTransaction Begin | 83 | `67daa505e06aa170911fd2273c77e69423246d5d83c38a40fbcce64154d95b08` | `fuzz/corpus/qk_device_wire/207fedf7b8be9ce628f29355def79764b99f9cb2` |
| Display coalesced sequences 1 and 2 | 50 | `8123392a9cbfdb0cf44e25d77f3c33cb6c1d4d4af51ce080d27f71ebbcab5e99` | `fuzz/corpus/qk_device_wire/4ce6c8458141102f5695a538c7ff9505d81dea58` |

Before qualification, `qk_device_wire` has nine public seeds totaling 386
bytes: one canonical frame for each of the eight capabilities plus one
canonical two-frame coalesced Display stream. `qk_core_normal_process` has five
public seeds totaling 23 bytes. The fourteen starting files total 409 bytes.
Their canonical `class<TAB>target<TAB>bytes<TAB>sha256<TAB>path` entry block is
2,287 bytes and
has SHA-256
`40a72ec84daa6a86b0064d623ca5683817a520ca6204ebc259897a0c32910147`.
`tools/check-fuzz-corpora.sh` recomputes and fails closed on this exact starting
fixed point while this campaign remains planned.

## Required execution and registration

Each post-run corpus is copied twice and the copies are minimized separately
through unchanged confirmation passes. The two canonical fixed-point listings
for a target must agree byte for byte; disagreement stops for Owner
disposition. An agreed changed fixed point is promoted under QK-DEC-146. The
prior registered entry hash is recorded for every requalified partition whose
fixed point changes.

Only after both campaigns and minimizations complete may
`CORPUS-MANIFEST-PROCESS-S9.tsv` be rendered with the final source commit and
this status be changed to `EXECUTED — QUALIFYING RUN COMPLETE.` The completed
record must contain the exact run counts, timings, rates, coverage/features,
live and persisted corpus facts, RSS, artifact count, every two-copy
minimization progression, retained listing and manifest-entry hashes, promoted
prior hashes, and final replay facts. Every other registered corpus replays
unchanged on the final tree. No process, socket, descriptor, device, card, or
hardware operation occurs in either pure target.
