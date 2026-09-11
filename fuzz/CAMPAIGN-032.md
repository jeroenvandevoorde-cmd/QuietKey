# Campaign 032 — bounded SEC1210 R2a codec and exchange

Status: PLANNED — NOT EXECUTED.

Authority: QK-DEC-167. HOST/mock transport only; no card operation.

Target `qk_sec1210_wire` uses only the `sec1210-wire` feature (default features off).
Its sole product-code dependency is the dependency-free `qk-sec1210-wire` crate.
The UART adapter, processes, wall clocks, GPIO and physical devices are outside this closure.

Qualification: one published source commit, 100,000 inputs, seed 167001,
max_len 4096, AddressSanitizer, timeout 2 seconds, RSS limit 2048 MB,
reload disabled, with the existing pinned nightly and cargo-fuzz framework.
Two independent copies of the post-run corpus must minimize to an identical
fixed point before registration; all older corpora are replayed unchanged.

The starting corpus identity is `2:33:f75773d19797a686d46d217bc95744ada528ee750dec708b76fd7313267024c3` (files:bytes:entries SHA-256).
The reference target separately checks stream framing, checksum-repaired
semantic mutations, both command phases, operation ordering, global event limits,
absolute receive deadlines and sticky named failure outcomes. No signing or
secret material is supplied. No hardware-readiness, T=1, APDU or Gate claim.
