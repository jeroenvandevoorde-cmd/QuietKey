# Firmware campaign 018

Status: EXECUTED — QUALIFYING RUN COMPLETE.

The common fuzz-target source commit was
`350415d53a88d7928a9ced3078d3b9fc38a1838b`. The fixed tool identities were
cargo-fuzz 0.13.2; `nightly-2026-08-25`; rustc
`1.100.0-nightly (e7769602a 2026-08-24)`; AddressSanitizer; release-profile
overflow checks and debug assertions enabled; and dependency resolution
offline. The exact qualifying commands were:

```text
fuzz/run-bounded.sh qk_update_package 100000
fuzz/run-bounded.sh qk_update_lifecycle 100000
```

`qk_update_package` used public seed 136001, maximum input length 4,096,
timeout 2 seconds, RSS limit 2,048 MiB, corpus reload off, and final-stat
reporting. It started from 18 public seed files totaling 138 bytes. It executed
exactly 100,000 inputs in 6 seconds at 16,666 executions per second, finished
at coverage/features 798/1,067 with an engine corpus of 178 files/4,817 bytes,
added 396 engine units, had a zero-second slowest unit, peaked at 394 MiB RSS,
and created zero artifact files. The post-run filesystem corpus contained 208
files/4,988 bytes. Its 14,045-byte sorted `SHA-256<TAB>bytes` listing had
SHA-256
`629004a8756fa67192c34764372fd4a90431b9894eb544d3b8ee83fe9d427435`.

Two copies of that package corpus were minimized serially. Both copies followed
the same complete progression:

- 208 files/4,988 bytes, listing SHA-256
  `629004a8756fa67192c34764372fd4a90431b9894eb544d3b8ee83fe9d427435`;
- 158 files/4,080 bytes, listing SHA-256
  `8875bc7a0892d003326f52dd24741b8dd413785b0940885e4f383416257ec546`;
- 153 files/4,055 bytes, listing SHA-256
  `11e34be2f55784a73294c7afa50bdf1f0ee1f33c8bc726f29dff894d05159445`;
- 151 files/3,947 bytes, listing SHA-256
  `49eac828c5510fddbe04c94ebcb72fa6b219a61a16e9cb61f970d0b624a6c24f`;
- 150 files/3,942 bytes, listing SHA-256
  `cc69ea4bfb1b0a7fe3ba45bb0b9235964217886078ad41e8164d101c2fb586ec`;
- 149 files/3,939 bytes, listing SHA-256
  `8c71096722f015535771ffb3ea7c18cf147a77d5993205f2498a9f47cfb0a74f`;
- a further pass left that 149-file set unchanged.

The two fixed-point listings were byte-identical and each was 10,073 bytes.

`qk_update_lifecycle` used public seed 136002, maximum input length 512,
timeout 2 seconds, RSS limit 2,048 MiB, corpus reload off, and final-stat
reporting. It started from 20 public seed files totaling 140 bytes. It executed
exactly 100,000 inputs in 22 seconds at 4,545 executions per second, finished
at coverage/features 716/806 with an engine corpus of 43 files/182 bytes,
added 89 engine units, had a zero-second slowest unit, peaked at 462 MiB RSS,
and created zero artifact files. The post-run filesystem corpus contained 62
files/332 bytes. Its 4,154-byte sorted `SHA-256<TAB>bytes` listing had SHA-256
`5196befce18597dfca4c64bfe5be36c60cef32a8406b893ba208802de8ab6bb4`.

Two copies of that lifecycle corpus were minimized serially. Both copies
followed the same complete progression: 62 files/332 bytes with listing
SHA-256
`5196befce18597dfca4c64bfe5be36c60cef32a8406b893ba208802de8ab6bb4`;
33 files/143 bytes with listing SHA-256
`29c6ad5350bcccd9446b3219e104ef9f857033d44923b100b8d207fbcf9c9b1e`;
and a further pass left that 33-file set unchanged. The two fixed-point listings
were byte-identical and each was 2,211 bytes.

The matching fixed-point sets became the persistent corpora.
`qk_update_package` retained 149 files/3,939 bytes with manifest entry-block
SHA-256
`569d9e786e7b057525688de1deb7302f988f620c5b5177e01a435331159b1b09`;
`qk_update_lifecycle` retained 33 files/143 bytes with manifest entry-block
SHA-256
`b3c27bfd827c00c6948b76b896c5ec0e970257987cddff59a778b3052d239278`.
The aggregate is 182 files/4,082 bytes with entry-block SHA-256
`4ac0411eb3cfeb964b2e3ad26d482517194b61406a45fa74b6c8e557e96cf2c2`.
`CORPUS-MANIFEST-FIRMWARE-V1.tsv` is 30,438 bytes/190 LF with SHA-256
`ffbd69ff925a492ad7a34c69ff9fd39390c732b99883a47b3542e9b29480cebe`.

Retained-corpus replay for `qk_update_package` loaded all 149 files totaling
3,939 bytes and executed 155 units. It finished at coverage/features 798/1,068
with an engine corpus of 148 files/3,935 bytes, added zero units, had a
zero-second slowest unit, peaked at 38 MiB RSS, created zero artifact files,
and exited zero. Retained-corpus replay for `qk_update_lifecycle` loaded all 33
files totaling 143 bytes and executed 35 units. It finished at
coverage/features 716/806 with an engine corpus of 31 files/130 bytes, added
zero units, had a zero-second slowest unit, peaked at 36 MiB RSS, created zero
artifact files, and exited zero.

The package target exercised hostile package bytes, single-candidate read-only
media, one-read private staging, wallet/card preconditions, compiled-anchor
policies, strict parsing, public-key-only verification, version floors,
signature-role variants, exact accepted public facts, stable named rejection
text, and repeat consistency. The lifecycle target exercised preparation,
inactive-slot selection, fallback, first-boot reports, single-use boot attempts,
delayed floor/key-set commit, boot display, wallet/card preconditions, and all
12 successful-preparation branches under a closed expected model for operation
tags, committed state, trial presence, boot count, and final display. Neither
target contains a signing operation or private key, accesses real media, or
makes target, flash, boot, power-cut, or Gate claims.
