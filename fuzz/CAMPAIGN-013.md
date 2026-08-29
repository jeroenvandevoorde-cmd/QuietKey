# V2 slice-7 campaign 013

Status: EXECUTED — QUALIFYING RUN COMPLETE.

Fuzz-target source commit and qualifying-run tree:
`b9982853ed4d5d01c032bee77682db9b38466e31`.

The fixed tool identities were cargo-fuzz 0.13.2;
`nightly-2026-08-25`; rustc
`1.100.0-nightly (e7769602a 2026-08-24)`; AddressSanitizer;
release-profile overflow checks and debug assertions enabled; dependency
resolution offline. The qualifying runs started from exactly five committed
`qk_kit_v2_s7_codec` seeds totaling 15 bytes and five committed
`qk_kit_v2_s7_combine` seeds totaling 15 bytes. Their initial manifest
entry-block SHA-256 values were respectively
`f59426270d545d902cb3f0bac19fb2d34b0f2d9cba34ef67e1137445ac3f0438`
and `e9926e0882d6c0d484bb5677e5917e726d3f8eca2dfb5a7555966dc7cb4160ad`;
the ten-entry/30-byte aggregate entry-block SHA-256 was
`3958eac4a3ba8305203e7a0882a6521e118b10dbdf5fc759cefc123e97db4613`.

The exact qualifying commands were:

```text
fuzz/run-bounded.sh qk_kit_v2_s7_codec 100000
fuzz/run-bounded.sh qk_kit_v2_s7_combine 100000
```

The commands fixed seeds 127001 and 127002, maximum length 512, timeout 2
seconds, RSS limit 2,048 MiB, corpus reload off, AddressSanitizer, and
final-stat reporting. The codec run executed exactly 100,000 inputs in 352
engine seconds at 284 executions per second, added 291 engine units, peaked
at 117 MiB RSS, and produced zero artifact files. The combination run executed
exactly 100,000 inputs in 37 engine seconds at 2,702 executions per second,
added 102 engine units, peaked at 198 MiB RSS, and produced zero artifact
files. The two qualifying runs therefore executed exactly 200,000 libFuzzer
inputs.

For every presented input, the codec target used a local reference classifier
to predict exact frame and fallback acceptance or the named rejection, then
required the qk-kit result to agree. Accepted frames had to round-trip through
the exact 142-byte frame, 228-symbol fallback, and fixed QR-v10-Q paths without
changing their wallet, share, or checksum bytes. The target also exercised
deterministic semantic and malformed-fallback cases and bounded its consumed
input to 505 bytes.

For every presented input, the combination target used a local frame
classifier, derived the second wallet and share from the first, and required
the qk-kit result to agree with the exact expected named outcome. Every
accepted pair had to produce the same 64-byte owned payload in both caller
orders. The target exercised wallet mismatch, duplicate share index, unknown
share index, malformed frame, and exact-share cases while consuming at most
512 bytes.

After both writers exited, the codec filesystem held 273 files/101,387 bytes
and the combination filesystem held 93 files/22,281 bytes. Both artifact
directories were empty. Two copies of each post-run set were minimized
serially. The codec copies progressed identically through 240, 237, 234, and
233 files, then remained unchanged on the next pass. The combination copies
progressed identically to 89 files and remained unchanged on the next pass.
The final sorted byte-and-hash inventories of each pair of copies were
byte-identical. No concurrent process wrote a minimization or artifact
directory.

Those fixed-point sets became the persistent corpora. The codec corpus is 233
files/86,106 bytes with manifest entry-block SHA-256
`cb754bc10860f115d80d1a346b71724513b8da0f31d2f42a8543193618960d21`.
The combination corpus is 89 files/22,269 bytes with manifest entry-block
SHA-256
`e505c8bd12467e6cee595935c360fbc9e5ecd740bc937ea3346ac98f19c1a45d`.
Their registered aggregate is 322 files/108,375 bytes with entry-block SHA-256
`42ec4970cfdca0c7eddf5fae8f5ee263c36605de5cb3bd9d3b4a46a4cc308816`.
The complete cross-partition path, byte-count, and content-hash check passed.

Retained-corpus replay loaded all 233 codec files totaling 86,106 bytes,
executed 234 units at coverage/features 621/1,196, added zero units, peaked at
38 MiB RSS, and created zero artifact files. The combination replay loaded all
89 files totaling 22,269 bytes, executed 90 units at coverage/features
306/457, added zero units, peaked at 36 MiB RSS, and created zero artifact
files. Both replays had zero-second slowest units and exited zero.

Across qualification, minimization, import, and retained replay, panic,
timeout, sanitizer report, wrong acceptance, wrong named rejection, caller-order
disagreement, payload mismatch, input over-consumption, and residual fuzz
artifact counts were all zero. The QR work-buffer clearing defect was fixed in
`b04f009`; the target acceptance-oracle defects were fixed in `b998285`.
Neither change occurred after the qualifying runs began.
