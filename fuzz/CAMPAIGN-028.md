# Process slice 9 campaign 028

Status: EXECUTED — QUALIFYING RUN COMPLETE.

## Qualification boundary

Qualification source: `157ab863707b8f074e8b2f906f2c84af45ccb8e7`.
Neither target nor any selected dependency changed after that commit and before
both campaigns, both two-copy minimizations, registration, and final replay.
The fixed tool identities were cargo-fuzz 0.13.2; `nightly-2026-08-25`; rustc
`1.100.0-nightly (e7769602a 2026-08-24)`; AddressSanitizer; release-profile
overflow checks and debug assertions enabled; and offline dependency
resolution.

The exact qualifying commands were:

```text
fuzz/run-bounded.sh qk_device_wire 100000
fuzz/run-bounded.sh qk_core_normal_process 100000
```

`qk_device_wire` used public campaign seed 156001 and maximum fuzzer input
length 65,536. Its 16 control bytes are separate from the candidate frame; one
registered selector synthesizes the exact 262,169-byte maximum QKDV chunk
presentation without raising the fuzzer-input limit. `qk_core_normal_process`
used public campaign seed 156002 and maximum input length 4,096. Both used a
two-second per-input timeout, 2,048 MiB RSS
ceiling, disabled corpus reload, final statistics, and an empty artifact
directory. Each run executed exactly 100,000 inputs, exited zero, and retained
zero artifacts.

## Starting corpus record

The canonical `qk_device_wire` seeds were registered byte for byte before the
campaign:

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

Before qualification, `qk_device_wire` had nine public seeds totaling 386
bytes: one canonical frame for each of the eight capabilities plus one
canonical two-frame coalesced Display stream. `qk_core_normal_process` had five
public seeds totaling 23 bytes. The fourteen starting files totaled 409 bytes.
Their canonical `class<TAB>target<TAB>bytes<TAB>sha256<TAB>path` entry block is
2,287 bytes and
has SHA-256
`40a72ec84daa6a86b0064d623ca5683817a520ca6204ebc259897a0c32910147`.
`tools/check-fuzz-corpora.sh` recomputed and failed closed on this exact
starting fixed point before execution.

## Qualification results

| Target | Start files/bytes | Engine seconds; rate/s | Coverage/features | Live corpus reported by libFuzzer | New units | Peak RSS MiB | Persisted post-run files/bytes | Artifacts |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| `qk_device_wire` | 9/386 | 8; 12,500 | 1,404/2,648 | 337/20Kb | 518 | 332 | 337/21,164 | 0 |
| `qk_core_normal_process` | 5/23 | 209; 478 | 4,937/7,815 | 91/1,161b | 126 | 453 | 91/1,161 | 0 |

Both targets reported a zero-second slowest input. The live-corpus byte fields
above preserve libFuzzer's own printed units; the persisted facts are exact
filesystem byte counts. Their post-run canonical sorted
`SHA-256<TAB>bytes` listings were:

| Target | Listing bytes/LF | SHA-256 |
|---|---:|---|
| `qk_device_wire` | 22,919/337 | `ca35e72790aa96ddc35c06de950bc5a55a2b1a863c3d28e330774fea6f9e3505` |
| `qk_core_normal_process` | 6,128/91 | `0bac7e7748142db32e8070d6cd86708fb77bed56730afe5971f64e3a9bbb66ca` |

## Two-copy minimization and registration

Two separately copied post-run roots for each target were minimized through an
unchanged confirmation pass. Each pair agreed byte for byte after every pass,
and every pass exited zero:

- `qk_device_wire`: 337/21,164 -> 305/19,050 -> 303/18,944 ->
  302/18,899 -> unchanged. Its final canonical listing is 20,539 bytes/302 LF
  with SHA-256
  `bf504c68a22d49c27dcc97f93310945b86558ba6bd588fcb428fe09e0e9819b9`.
- `qk_core_normal_process`: 91/1,161 -> 84/1,089 -> unchanged. Its final
  canonical listing is 5,656 bytes/84 LF with SHA-256
  `15d9aef82bc6ac3e74683c2695f10b9ce545b93bb306b24db3ca17f3bc25d5ae`.

These are new targets, so neither replaced a prior registered campaign fixed
point. The agreed roots were promoted under QK-DEC-146. The final
`CORPUS-MANIFEST-PROCESS-S9.tsv` is 62,831 bytes/394 LF with SHA-256
`4f11a8a6ca3974c78aa0777021d7e8afab616e66bbbc90c3986ba0d7fa5ca016`
and binds:

| Target or aggregate | Files/bytes | Entries SHA-256 |
|---|---:|---|
| `qk_device_wire` | 302/18,899 | `124bb69d74bc3f82b46d3aa7fb4389458baaaf5241b61be988030dc41f4064c1` |
| `qk_core_normal_process` | 84/1,089 | `d6d465b3da4f75e3220a92934118294eec1f511f2e4a38a55a35b077438e4597` |
| aggregate | 386/19,988 | `5c394f3fb9b68f7151929dd89dfbafafa66e859b1f7531f42a676d9fafcb5c59` |

## Final retained-corpus replay

`qk_device_wire` loaded 302 files/18,899 bytes and executed 303 units;
coverage/features were 1,404/2,648, peak RSS was 55 MiB and zero units were
added. `qk_core_normal_process` loaded 84 files/1,089 bytes and executed 85
units; coverage/features were 4,937/7,815, peak RSS was 57 MiB and zero units
were added. Both replays exited zero, created zero artifacts and left their
filesystem corpus roots unchanged.

The complete registered corpus set contained 50 target roots and 7,597 files
totaling 26,660 bytes. All 50 targets replayed against the qualification source
and reported 7,656 executed units, zero failures and zero artifact files. No
process, socket, descriptor, device, card, or hardware operation occurred in
either pure target.
