# V2 slice-3 campaign 009

Status: PREREGISTERED — NOT YET EXECUTED.

This paired campaign migrates exactly `qk_host_sim_m23` and
`qk_host_sim_m24` under QK-DEC-123. The target-source commit, exact execution
facts, minimized corpus facts, manifest identities, and replay results remain
blank until the final target sources and provenance-complete v2 signing
fixture are committed. No result is claimed by this preregistration.

The fixed tool identities remain cargo-fuzz 0.13.2;
`nightly-2026-08-25`; rustc
`1.100.0-nightly (e7769602a 2026-08-24)`; AddressSanitizer;
release-profile overflow checks and debug assertions enabled; dependency
resolution offline after the registered one-time fetch.

The two qualifying commands are exactly:

```text
PATH=/private/tmp/qk-cargo-fuzz/bin:$PATH fuzz/run-bounded.sh qk_host_sim_m23 100000
PATH=/private/tmp/qk-cargo-fuzz/bin:$PATH fuzz/run-bounded.sh qk_host_sim_m24 100000
```

The existing runner pins seed 23002 for `qk_host_sim_m23`, seed 24001 for
`qk_host_sim_m24`, maximum input length 4,096 bytes for each, timeout 2 s,
RSS limit 2,048 MiB, corpus reload disabled, and an empty artifact directory
at start. Each target executes the selected hostile input twice and requires
exact typed outcome equality.

The v2 M23 target preserves the owned-S0 hostile generator and stable
parse/intake/workflow named-error oracles. Acceptance requires an exact
`DescriptorPairV2`, schema byte 03, `QK-FEE-POLICY-V2`, the registered A/B
fingerprints and wallet identity, exact canonical review-v3 bytes and hash,
reparse/rebuild equality, and no partial review output. After each accepted
review, fixed comparator probes that present schema identity v1 and v2 must
reject as `UnsupportedReviewSchemaVersion` before canonical mismatch; the
hostile-input path and every probe release no partial review object.

The v2 M24 target preserves hostile S0, terminal-key, and mock-signature
generation. It requires pre-signing review-v3 rebind, stable named errors,
pre-insertion verification of every A/B signature, exact one-record deltas,
no role C path, no partial PSBT/signature/witness/transaction on failure,
strict 71-byte 2-of-2 witness construction, canonical finalized PSBT, exact
raw extraction, witness stripping, txid/wtxid identity, and freshly reparsed
final signature verification. Exact public controls must reproduce the
registered v2 fixture bytes.

Each campaign starts from its current registered public corpus copied to a
fresh working directory. The qualifying run's post-run corpus is copied
twice. Both copies are minimized through the pinned runner until a further
fresh minimization preserves the exact sorted `SHA-256<TAB>bytes` set; any
disagreement stops registration. One matching copy becomes persistent.

`CORPUS-MANIFEST-M23.tsv` retains the separately pinned `qk_psbt_m23`
schema-v3 source and records the new `qk_host_sim_m23` campaign source.
`CORPUS-MANIFEST-M24.tsv` advances to its v2 generation and records the new
`qk_host_sim_m24` source. `tools/check-fuzz-corpora.sh` must reproduce every
entry, count, byte total, per-target digest, and aggregate digest before the
campaign report changes to executed.

After registration, each retained corpus is replayed under the same pinned
nightly and AddressSanitizer. The report records exact unit counts, engine
corpus, coverage/features, elapsed seconds, executions per second, peak RSS,
slowest unit, added units, artifact count, minimization sequence, sorted-set
digests, manifest byte/LF/SHA-256 identities, and replay exit. Panic, timeout,
sanitizer finding, wrong named outcome, wrong acceptance, partial-output
release, and artifact-file counts must all be zero.

Any reproduced finding follows QK-DEC-106 and QK-DEC-123: minimize and hash
register it, add an ordinary defect fix and regression fixture, and record the
frozen-crate change without treating frozen status as a reason to defer it.
No product source changes during qualifying generation, minimization,
registration, or replay.
