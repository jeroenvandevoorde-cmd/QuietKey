# Process slice 5 campaign 024

Status: PLANNED — NOT EXECUTED.

The common product-and-new-target source will be the commit that first brings
together the final QK-DEC-145 product tree, both new target oracles, the
`process-s5-core` feature and exact closure proof, runner routing, registration
guard, this plan and the public starting corpora. The byte-frozen
`qk_core_io_peer` and `qk_core_session` target source remains
`e416080d8867fc381bdcc6aa1a26382f4767b6b8`, but both requalify against that
common product tree because they compile the expanded `qk-core` closure. No
product source, target oracle, runner routing or starting corpus may change
after the source commit without restarting the affected run against the later
commit.

The exact qualifying commands are:

```text
fuzz/run-bounded.sh qk_core_io_peer 100000
fuzz/run-bounded.sh qk_core_session 100000
fuzz/run-bounded.sh qk_core_provisioning_entry 100000
fuzz/run-bounded.sh qk_core_provisioning_run 100000
```

All runs use cargo-fuzz 0.13.2, `nightly-2026-08-25` with rustc
`1.100.0-nightly (e7769602a 2026-08-24)`, AddressSanitizer, release-profile
overflow checks and debug assertions, corpus reload disabled, two-second input
timeout, 2,048 MiB RSS ceiling and final-stat reporting. Target seeds and
maximum inputs are respectively 144001/16,384, 144002/4,096, 145001/1,024 and
145002/512.

The entry target starts from 225 public units totaling 6,525 bytes: the full
nineteen-key by five-count matrix, the full nineteen-key by six-stage matrix,
all six reuse pairs and all ten interruption positions. The run target starts
from 22 public units totaling 660 bytes, all satisfying its deterministic
one-in-256 admission fold and covering complete no-spare and spare flows,
scenarios 2 through 5, all four Kit receipt positions, all ten interruptions,
the invalid-card action and card removal. Every other run-target input follows
the bounded pre-provisioning named-rejection path; 100,000 target inputs are
not described as 100,000 complete provisioning flows.
The entry and run starting-corpus entry blocks have SHA-256
`0a42d22e1a9109feddc6cc1d8bfcbf2a3f56660a046b898bfefd59f49a62b9d8` and
`edf606ea6c97a489a3d4aefa83cc42e58ff42593b166c0415e3130972f9da4c4`;
their 247-unit/7,185-byte aggregate entry block has SHA-256
`79dd9570b0f4e8f2cc1f0839852de5cc81ef2a32f2d234af7e7c9f56801172e4`.

After each run, two copied corpora are minimized serially to fixed point and
their sorted `SHA-256<TAB>bytes` listings must agree byte for byte. The two new
fixed points are registered in `CORPUS-MANIFEST-PROCESS-S5.tsv`. The two
requalified slice-4 fixed points must remain byte-identical to their registered
sets; any change stops for scope direction because QK-DEC-145 freezes the prior
manifest and campaign. The other 38 partitions are replay-only, and all 42
retained corpora replay on the final tree.

The entry oracle covers every entry key, count and stage, exact echo,
commitment and order, all six reuse pairs, every interruption, terminal
absorption, repeat consistency and wipe accounting. The run oracle covers
card and spare choices, hostile A1 scan-back, exact A1 and four-page Kit
egress and receipts, page ordering, every interruption, terminal absorption,
repeat consistency and wipe accounting. Both require named outcomes and
reject any wrong acceptance or unstable repeat.
