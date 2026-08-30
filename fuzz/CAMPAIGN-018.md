# Firmware campaign 018

Status: PLANNED — NOT EXECUTED.

This file preregisters the QK-DEC-136 firmware package and lifecycle campaigns.
It records no campaign source, execution result, retained-corpus count, corpus
digest, coverage, or sanitizer outcome. The complete target-scaffold commit will
become the common campaign source only after it is committed; both qualifying
runs and every retained corpus unit will then be registered in a later evidence
commit.

The fixed tool identities are cargo-fuzz 0.13.2; `nightly-2026-08-25`; rustc
`1.100.0-nightly (e7769602a 2026-08-24)`; AddressSanitizer; release-profile
overflow checks and debug assertions enabled; and dependency resolution
offline. The exact planned commands are:

```text
fuzz/run-bounded.sh qk_update_package 100000
fuzz/run-bounded.sh qk_update_lifecycle 100000
```

`qk_update_package` uses public seed 136001 and maximum input length 4,096.
It drives hostile package bytes, the single-candidate read-only media boundary,
one-read private staging, wallet/card preconditions, compiled-anchor policies,
strict parsing, public-key-only verification, version floors, signature-role
variants, exact accepted public facts, stable named rejection text, and repeat
consistency. `qk_update_lifecycle` uses public seed 136002 and maximum input
length 512. It drives preparation, inactive-slot selection, fallback, first-boot
reports, single-use boot attempts, delayed floor/key-set commit, boot display,
wallet/card preconditions, exact lifecycle state, stable named rejection text,
and repeat consistency. Neither target contains a signing operation or private
key, accesses real media, or makes target, flash, boot, power-cut, or Gate
claims.

Each run must execute exactly 100,000 inputs. After each run, two copies of its
post-run corpus are minimized serially through `fuzz/minimize-corpus.sh` until a
further pass changes neither copy. Their sorted `SHA-256<TAB>bytes` inventories
must agree byte-for-byte before one set replaces the persistent corpus. The
retained sets must replay clean through `fuzz/replay-corpus.sh`, produce no fuzz
artifact, and be registered together in `CORPUS-MANIFEST-FIRMWARE-V1.tsv` with
the common committed campaign source. A reproduced finding stops this plan and
follows the ordinary fix, minimized regression, and decision-row procedure.
