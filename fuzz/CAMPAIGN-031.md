# Card signature repeated-r campaign 031

Status: EXECUTED — REQUALIFICATION COMPLETE.

## Requalification boundary

This QK-DEC-164 run requalified only `qk_core_normal_process` at source
`180e5e9578f8b6fabccdfb5d9199d9b3c7b2d79d`. The other 51 registered
targets were replay-only because their target source and selected closure were
byte-frozen. The fixed tool identities were cargo-fuzz 0.13.2;
`nightly-2026-08-25`; rustc `1.100.0-nightly (e7769602a 2026-08-24)`;
AddressSanitizer; release-profile overflow checks and debug assertions enabled;
and offline dependency resolution.

The exact bounded-run command was:

```text
fuzz/run-bounded.sh qk_core_normal_process 100000
```

It fixed public campaign seed 156002, maximum fuzzer input length 4,096, a
two-second per-input timeout, a 2,048 MiB RSS ceiling, disabled corpus reload,
final statistics, and an empty target artifact directory. It executed exactly
100,000 inputs and exited zero.

## Starting point and bounded-run result

The registered starting fixed point was 86 files/1,597 bytes. Its canonical
sorted `SHA-256<TAB>bytes` listing was 5,795 bytes/86 LF with SHA-256
`3c95894ff36ab11e1007f6588c0d3e1ee9e37f7674ca508626ed9436eae6905d`;
its manifest entries SHA-256 was
`5b354d648a32a2d74d2f9a0d9620447bb3b2d5d1b82d6b97744427aa5db48c7d`.

| Start files/bytes | Engine seconds; rate/s | Coverage/features | Live corpus reported by libFuzzer | New units | Peak RSS MiB | Persisted post-run files/bytes | Artifacts |
|---:|---:|---:|---:|---:|---:|---:|---:|
| 86/1,597 | 262; 381 | 5,178/7,900 | 89/1,769b | 11 | 464 | 96/2,468 | 0 |

The slowest input was reported as zero seconds. The live-corpus byte field
preserves libFuzzer's printed value; the persisted value is the exact
filesystem count. The post-run canonical listing was 6,475 bytes/96 LF with
SHA-256
`eec19267d06b840419c3c6b7e95756c81ebb662289307382d5af19a4d0b64e3e`.
No finding, timeout or artifact occurred.

## Two-copy minimization

Two separately copied post-run roots were each minimized three times:

```text
fuzz/minimize-corpus.sh qk_core_normal_process /tmp/qk-card-hardening.UQPV1B/campaign031-copy-a
fuzz/minimize-corpus.sh qk_core_normal_process /tmp/qk-card-hardening.UQPV1B/campaign031-copy-a
fuzz/minimize-corpus.sh qk_core_normal_process /tmp/qk-card-hardening.UQPV1B/campaign031-copy-a
fuzz/minimize-corpus.sh qk_core_normal_process /tmp/qk-card-hardening.UQPV1B/campaign031-copy-b
fuzz/minimize-corpus.sh qk_core_normal_process /tmp/qk-card-hardening.UQPV1B/campaign031-copy-b
fuzz/minimize-corpus.sh qk_core_normal_process /tmp/qk-card-hardening.UQPV1B/campaign031-copy-b
```

Each copy followed 96 files/2,468 bytes -> 89 files -> 88 files -> unchanged
confirmation. The two final directories agreed byte for byte, all six commands
exited zero, and the target artifact directory stayed empty. The promoted
fixed point is 88 files/1,759 bytes. Its canonical listing is 5,931 bytes/88 LF
with SHA-256
`0ead940712ca3291c3cf616abd8260ce544f0455886c82fd0c6f6898cb79d0a1`;
its manifest entries SHA-256 is
`9b51c25718229494e8343e2b59fd441d2b9788a658c4bce666f8c7ee7accf83b`.

## Registration and source semantics

Before Campaign 031, `QK-PROCESS-S9-CORPUS-MANIFEST-V1` was 66,659 bytes/418
LF with SHA-256
`053d25ec94a3d1ede0c35f3a018af06d90f7443ca704363fb3f624451539b1f8`.
It bound 410 files/21,335 bytes with aggregate entries SHA-256
`615a3c9b08c3f1b4bfd7d949d75ad3e4bcc34026c77336ac85c37e4f61439237`.
The prior core target identity was the 86-file fixed point above.

The exact render commands were:

```text
tools/check-fuzz-corpora.sh --render-process-s9 8d2e4ff9443b7b050348c19b0df8229ede17ea9a
tools/check-fuzz-corpora.sh --render-card-s1 05c640da25902398c04117ee0cf430f149f7f8e4
```

The renderer keeps each partition's historical `campaign_source` and emits
one exact `target_source` row for each target whose fixed point was produced by
a later source. PROCESS-S9 therefore binds only `qk_core_normal_process` to
`180e5e9578f8b6fabccdfb5d9199d9b3c7b2d79d`. CARD-S1 binds
`qk_card_model` to `05c640da25902398c04117ee0cf430f149f7f8e4` and
`qk_core_normal_process` to `180e5e9578f8b6fabccdfb5d9199d9b3c7b2d79d`.
Every configured target requires exactly one row; missing, duplicate, unknown
and malformed target-source rows each failed closed with exit 1. Short,
uppercase, nonexistent, blob and tree source values also retain the existing
named source-object rejections.

The final PROCESS-S9 manifest is 67,085 bytes/421 LF with SHA-256
`f5205a837815cb41cbd7704bd5bc0bfd06e5a172cd39ef23f220fed494f402d6`.
It binds 412 files/21,497 bytes with aggregate entries SHA-256
`570d456b3c7e2e23e1e1079d927784366ceb19951ba04b3aef6d7667d21e91f7`.

Before Campaign 031, `QK-CARD-S1-CORPUS-MANIFEST-V1` was 103,487 bytes/651
LF with SHA-256
`1fe74925fb0da15e19946e9c97415fa3d312fbfddfb3d38cbf2f5440c3771461`.
The final CARD-S1 manifest is 103,913 bytes/654 LF with SHA-256
`aee4851c16a14f6bf89ed3dc8ce48488a5cd57cb0ef9554b256f569c4502d521`.
It binds 642 files/109,627 bytes with aggregate entries SHA-256
`0f4ee2eaab293f21700bc30216ac0bd88db55be0ae9fb213a2fe648540853fb0`.
All target identities except `qk_core_normal_process` remain unchanged.

## Complete retained-corpus replay

All 52 registered roots replayed under the pinned toolchain. The requalified
root contained 88 files/1,759 bytes, executed 89 units, added zero units,
exited zero and produced no artifact. The complete retained set contained
7,853 files totaling 572,501 bytes and executed 7,914 units. Every root exited
zero, every replay reported zero new units, and there were zero failures,
timeouts, findings or artifacts.

The complete canonical filesystem listing contains one line per corpus file,
sorted by path, as
`path-with-fuzz/corpus-prefix-removed<TAB>byte-count<TAB>SHA-256<LF>`. It is
1,007,883 bytes/7,853 LF with SHA-256
`c73f0d494685b9cce0b097180f5a8ded801eca54e53911543d15511cbd49473c`.
Replay began before the checker-only target-source failure-propagation commit
and ended after it; that intervening commit changed only
`tools/check-fuzz-corpora.sh`, so no compiled target, replay script, corpus byte
or dependency closure changed during replay.

## Claim boundary

This is pure HOST evidence. No physical card, converter, CAP, GlobalPlatform,
Java Card, delivered-platform, RNG, contactless-enforcement, performance,
production or Gate claim is made. No process, socket, descriptor, device, card
or hardware operation occurred. The future DEV-card commit-capacity
measurement and 1,000-signature repeated-r run remain separately gated, and no
`Scalar256` source was changed.
