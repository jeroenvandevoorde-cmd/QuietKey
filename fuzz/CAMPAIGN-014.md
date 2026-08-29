# V2 slice-8 campaign 014

Status: EXECUTED — QUALIFYING RUN COMPLETE.

Fuzz-target source commit and qualifying-run tree:
`2e897a8938aa1cc78ff985bbe619c16cf0496e00`.

The fixed tool identities were cargo-fuzz 0.13.2;
`nightly-2026-08-25`; rustc
`1.100.0-nightly (e7769602a 2026-08-24)`; AddressSanitizer;
release-profile overflow checks and debug assertions enabled; dependency
resolution offline. The qualifying run started from exactly six committed
`qk_provisioning_v2_s8_kit_setup` seeds totaling 22 bytes. They selected the
missing-A1 gate, first rejection at each of the four page positions, and full
four-page completion. Their six-entry initial entry-block SHA-256 was
`08a1fffc514bdf164da54cd8f96c10e124429a5b6711f8594102b23c7bb24f3f`.

The exact qualifying command was:

```text
fuzz/run-bounded.sh qk_provisioning_v2_s8_kit_setup 100000
```

The command fixed seed 128001, maximum length 512, timeout 2 seconds, RSS
limit 2,048 MiB, corpus reload off, AddressSanitizer, and final-stat reporting.
It executed exactly 100,000 inputs in 526 engine seconds at 190 executions per
second. It finished at coverage/features 1,777/3,512 with an engine corpus of
179 files/4,831 bytes, added 181 engine units, had a zero-second slowest unit,
peaked at 424 MiB RSS, and produced zero artifact files.

Every input longer than 512 bytes was excluded by the fixed target bound. A
rolling one-byte selector made the full provisioning and four-page QR path
sparse while the other inputs exercised a deterministic 99-symbol
`DiceCount` rejection twice. Every selected setup scenario ran twice and
required the same typed result. The full path constructed four pairwise-
distinct 100-symbol public ManualKeypad transcripts, created A1 except in the
named pre-A1 scenario, and then exercised one consuming setup run.

For every delivered page, the target required the fixed copy/index order,
exact four-by-57 fallback line geometry, canonical alphabet and pad bits,
frame magic/version/index/full-wallet binding, and the exact domain-separated
frame checksum through the separately retained qk-psbt SHA-256 source. It
re-encoded the logical QR and required byte-equal 529-byte output, mask facts,
quiet-zone geometry, and zero final padding bits. Same-index copies had to
carry equal 96-byte shares, and the index-one/index-two XOR had to reproduce
the exact Seed-A, Signer-B, and A2 literal-transcript hashes. Local reference
frames, shares, fallback copies, and QR copies were volatile-wiped after use;
the in-crate fuzzing assertions required every reusable 899-byte generation
buffer wipe. Rejection had to stop at its selected page without a later
callback or receipt, while success required all four callbacks before the
fixed two-copy/four-page receipt.

After the writer exited, the filesystem held 179 files/4,831 bytes and the
artifact directory was empty. Two copies of the post-run corpus were minimized
serially. Both copies progressed identically through 151 files, 144 files, and
142 files, then remained byte-unchanged on the next pass. Their final sorted
`SHA-256<TAB>bytes` inventories were byte-identical: 142 entries, 3,846 corpus
bytes, and listing SHA-256
`8b4884dfcb6a0c6fd017e282fccafe362ad6b9f4ca95b3512f117db9bfa5e1e6`.
No concurrent process wrote either minimization or artifact directory.

That fixed-point set became the persistent corpus. Its manifest entry block
has SHA-256
`48d17a0df15d117ae2aa0ff48c363f7a923ea9afeaf0480940cdbb30c0ec0949`.
`CORPUS-MANIFEST-V2-S8.tsv` is 27,638 bytes/149 LF with SHA-256
`57468fdbb845a0161d73f71ff128e7631a57c08ebc84c80429fe313178129f92`;
its aggregate is 142 files/3,846 bytes with the same entry-block SHA-256. The
complete cross-partition path, byte-count, and content-hash check passed.

Retained-corpus replay loaded all 142 files totaling 3,846 bytes and executed
143 units. It finished at coverage/features 1,777/3,512 with a deduplicated
engine corpus of 141 files/3,845 bytes, added zero units, had a zero-second
slowest unit, peaked at 365 MiB RSS, created zero artifact files, and exited
zero.

Across qualification, minimization, import, and retained replay, panic,
timeout, sanitizer report, wrong acceptance, wrong named rejection, page-order
disagreement, same-index copy mismatch, payload mismatch, callback after
rejection, premature receipt, caller-buffer wipe assertion, input
over-consumption, and residual fuzz artifact counts were all zero. No product
source or target oracle changed after qualification began.
