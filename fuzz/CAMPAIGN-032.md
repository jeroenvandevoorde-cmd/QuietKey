# Campaign 032 — bounded SEC1210 R2a codec and exchange

Status: EXECUTED — QUALIFYING RUN COMPLETE.

## Qualification boundary

This QK-DEC-167 campaign qualified only `qk_sec1210_wire` at published source
`f61fc557e4b9da329edf7c0686d842bd44f09534`. The other 52 registered targets
were replay-only because their target source and selected closure were
byte-frozen. The fixed tool identities were cargo-fuzz 0.13.2;
`nightly-2026-08-25`; rustc `1.100.0-nightly (e7769602a 2026-08-24)`;
AddressSanitizer; release-profile overflow checks and debug assertions enabled;
and offline dependency resolution.

The target uses only the `sec1210-wire` feature with default features off. Its
sole product-code dependency is the dependency-free `qk-sec1210-wire` crate.
The UART adapter, processes, wall clocks, GPIO and physical devices are outside
the closure. The exact bounded-run command was:

```text
fuzz/run-bounded.sh qk_sec1210_wire 100000
```

It fixed public campaign seed 167001, maximum fuzzer input length 4,096, a
two-second per-input timeout, a 2,048 MiB RSS ceiling, disabled corpus reload,
final statistics, and an empty target artifact directory. It executed exactly
100,000 inputs and exited zero.

## Starting point and bounded-run result

The preregistered starting corpus contained two files/33 bytes. Its canonical
sorted `SHA-256<TAB>bytes<LF>` listing was 135 bytes/two LF with SHA-256
`7bdbd037784bed810a7aba6bc5ca1862cf7b240285b0d7f0032de42e6dc5c4be`;
its preregistered identity was
`2:33:f75773d19797a686d46d217bc95744ada528ee750dec708b76fd7313267024c3`
(files:bytes:manifest entries SHA-256).

| Start files/bytes | Engine seconds; rate/s | Coverage/features | Live corpus reported by libFuzzer | New units | Peak RSS MiB | Persisted post-run files/bytes | Artifacts |
|---:|---:|---:|---:|---:|---:|---:|---:|
| 2/33 | 11; 9,090 | 690/2,293 | 282/14,322b | 673 | 462 | 277/14,312 | 0 |

The slowest input was reported as zero seconds. The live-corpus byte field
preserves libFuzzer's printed value; the persisted value is the exact
filesystem count. The post-run canonical listing was 18,805 bytes/277 LF with
SHA-256
`31ba95d551fe1d389ca422835486c302920a3c33a67310e2f3e2252e09d9317f`.
No finding, timeout or artifact occurred.

## Two-copy minimization

Two separately copied post-run roots were each minimized five times with:

```text
fuzz/minimize-corpus.sh qk_sec1210_wire <absolute-copy-a>
fuzz/minimize-corpus.sh qk_sec1210_wire <absolute-copy-b>
```

Each invocation exited zero. The corresponding copies agreed byte for byte
after every pass. Pass five was an unchanged fixed-point confirmation:

| Stage | Files | Bytes | Canonical listing bytes | Canonical listing SHA-256 |
|---|---:|---:|---:|---|
| Post-run copy | 277 | 14,312 | 18,805 | `31ba95d551fe1d389ca422835486c302920a3c33a67310e2f3e2252e09d9317f` |
| Pass 1 | 239 | 13,237 | 16,235 | `2af23d65cba72a67bd6bb8dd5ef1a84f588bddc8a35eb3b4e979f0d0a1dcf785` |
| Pass 2 | 233 | 13,082 | 15,829 | `5670b89187219018c63f15c898317d1a15b91f5bba9c5628b8d6b673649403ae` |
| Pass 3 | 230 | 13,050 | 15,626 | `97db27644a89ef616a90b540b0856415f469185d266dfac65cdea00515838098` |
| Pass 4 | 229 | 12,921 | 15,557 | `e1729b983283f027516fdd35f093a1ae74fafc0c0237586793b98849351d32e8` |
| Pass 5 | 229 | 12,921 | 15,557 | `e1729b983283f027516fdd35f093a1ae74fafc0c0237586793b98849351d32e8` |

All ten minimization calls passed, the target artifact directory stayed empty,
and only the new target root was replaced. The two starting files, the exact
post-run root and both minimized copies remain retained outside the repository.

The promoted fixed point's manifest entries SHA-256 is
`2a5950de303437a3cdfd45b143862575980ca9bb766a9279000b7513874f611b`.
The registered manifest `fuzz/CORPUS-MANIFEST-SEC1210-R2A.tsv` is 37,027 bytes,
236 LF, SHA-256
`6d4ca0d9dda4b7a4da553fdd3101ae38a92a90b491fbf88c6bc2ac617f7320ef`.
It binds one target, 229 files/12,921 bytes, at campaign source
`f61fc557e4b9da329edf7c0686d842bd44f09534`.

## Complete retained-corpus replay

All 53 registered roots replayed under the pinned toolchain. The new root
contained 229 files/12,921 bytes, executed 230 units, added zero units, exited
zero and produced no artifact. The complete retained set contained 8,082 files
totaling 585,422 bytes and executed 8,144 units. Every root exited zero, every
replay reported zero new units, and there were zero failures, timeouts,
findings or artifacts.

Before the new target was promoted, the 52 older roots contained 7,853 files
totaling 572,501 bytes. Their complete sorted
`path<TAB>byte-count<TAB>SHA-256<LF>` inventory was 1,102,119 bytes/7,853 LF
with SHA-256
`f0dcd00b9431131070e3d7cacb9b139ec124ea196a0a92f4c5486194104fe2da`.
The same identity after the replay proves every older corpus byte was retained.

The complete 53-root inventory in that format is 1,133,477 bytes/8,082 LF with
SHA-256
`4748a4c9244ace73569de1c42a3e279046faf02de914191cd74ea4328116cefe`.
No selected target closure, replay script or previously registered corpus byte
changed between the published qualification source and this evidence
registration; the new target changed only through the documented qualification
and promotion above.

## Claim boundary

This is pure HOST evidence. The reference target checks stream framing,
checksum-repaired semantic mutations, both command phases, operation ordering,
global event limits, absolute receive deadlines and sticky named failure
outcomes. No signing or secret material is supplied. No physical card, UART,
GPIO, converter, CAP, GlobalPlatform, Java Card, hardware-readiness, T=1, APDU,
performance, production or Gate claim is made. No card or hardware operation
occurred.
