# QuietKey ring-fenced parser campaigns

EXPERIMENTAL — PUBLIC TEST INPUTS ONLY — NOT PRODUCT CODE

## V2 migration disposition

QK-DEC-121 preserves this ring fence and its dependency controls. Each target and registered corpus remains tied to the implementation generation it actually exercises: slice 1 replaces only `qk_descriptor`; later review, signing, provisioning, screen, export, Kit-frame, scanner, restore, and spend targets change only in their assigned slices. Until migrated, a v1 target is frozen historical coverage and supplies no v2 Card-C, three-role, selected-pair, 2-of-3, schema-v1/v2, or general-recovery capability. Corpus registration, minimization, named-error, no-panic, and sanitizer rules remain mandatory for every successor target.

This independent Cargo workspace is outside `host/Cargo.toml`. It contains
eighteen libFuzzer targets for the `qk-psbt`, `qk-descriptor`, `qk-a1`,
`qk-a1-codec`, `qk-card-trace`, M22 `qk-bbqr` codec and reassembly, and M23
`qk-psbt` semantic/review and `qk-host-sim` owned-workflow boundaries, plus
the M24 `qk-host-sim` signing/finalization continuation. Under QK-DEC-123 the
two host-simulator targets migrate together to the parallel v2 slice: the M23
target owns exact hostile S0 into schema-v3 review readiness, and the M24
target continues that exact identity through A/B signing, strict 2-of-2
finalization, and raw-transaction reparse. Neither target accepts a v1 or v2
review object as a v3 object, and both keep the earlier public entrypoints
outside the fuzzed acceptance path. The M24 target uses only the public,
permanently NEVER-FUND QK-DEC-121 GOLDEN fixture lineage and asserts secret
import-source wiping, stable named rejection, exact golden completion,
absence of partial output, and repeat consistency over hostile PSBT and mock
controls. It
also includes the M25 `qk-host-sim` export boundary: that target reconstructs
the dedicated public threshold-complete NEVER-FUND fixture without any secret,
then drives tier/artifact selection, every mock-SD edge, nonce-derived names,
and finalized-PSBT-only BBQr framing twice while asserting exact golden facts,
stable named outcomes, input preservation, and per-artifact failure atomicity. It
also includes two M26 `qk-provisioning` targets: one drives canonical QKEC-1,
dice, and same-run nonce state through hostile boundary inputs; the other drives
the deterministic public full chain and reparses every descriptor, address, and
capsule result. Both assert repeat consistency, named rejection, and the absence
of partial artifacts. The M27 `qk-host-sim` target drives the typed
provisioning, signing, and recovery screen-flow transition machine through
bounded event streams. It checks deterministic typed outcomes, the closed named
error surface, fixed-order review visitation, approval identity binding,
post-approval no-yield behavior, interruption wiping, terminal stability, and
exact fact forwarding from public frozen fixture objects. This area changes no
product behavior and reaches no card, camera, network, filesystem parser, real
signing authority, or production target.

The exact runner is cargo-fuzz 0.13.2 and the exact compiler channel is
`nightly-2026-08-25` (`rustc 1.100.0-nightly (e7769602a 2026-08-24)`). The
runtime dependency and runner are recorded in `docs/SOURCE-REGISTER.md`.
`DEPENDENCY-ALLOWLIST.tsv` records every package in the active normal/build
closure with an exact version, checksum, provenance, license, and purpose.
`Cargo.lock` also contains Cargo's inactive cross-target resolutions; the
checker derives the actual build-target closure offline and rejects any active
package outside the allowlist or any inactive allowlist row. `tools/check.sh`
exempts only `fuzz/**/Cargo.toml` from the general dependency ban and fails
closed on non-top-level dependency tables, patches, replacements, or any
manifest/allowlist/closure mismatch.
A fresh clone must run `cargo fetch --manifest-path fuzz/Cargo.toml --locked`
once with network access before `tools/check.sh` can pass offline.

Every optimized fuzz build has overflow checks and debug assertions enabled by
both the workspace profile and cargo-fuzz's default build mode. The targets
bound presented input length, enumerate every named parser rejection, and
assert deterministic reparse or round-trip invariants after acceptance.

From the repository root, with the exact `cargo-fuzz` executable on `PATH`:

```text
fuzz/run-bounded.sh qk_psbt 100000
fuzz/run-bounded.sh qk_descriptor 100000
fuzz/run-bounded.sh qk_a1 100000
fuzz/run-bounded.sh qk_a1_codec 100000
fuzz/run-bounded.sh qk_card_trace 100000
fuzz/run-bounded.sh qk_bbqr_codec 100000
fuzz/run-bounded.sh qk_bbqr_reassembly 100000
fuzz/run-bounded.sh qk_psbt_m23 100000
fuzz/run-bounded.sh qk_host_sim_m23 100000
fuzz/run-bounded.sh qk_host_sim_m24 100000
fuzz/run-bounded.sh qk_host_sim_m25 100000
fuzz/run-bounded.sh qk_provisioning_inputs_m26 100000
fuzz/run-bounded.sh qk_provisioning_chain_m26 100000
fuzz/run-bounded.sh qk_host_sim_m27 100000
fuzz/run-bounded.sh qk_host_sim_m28 100000
fuzz/run-bounded.sh qk_host_sim_m29 100000
fuzz/run-bounded.sh qk_bbqr_m30 100000
fuzz/run-bounded.sh qk_host_sim_m30 100000
```

Each target has a fixed public campaign seed in `run-bounded.sh`. After a
bounded run, minimize a copied corpus in place through the same pinned runner
and compiler checks with:

```text
fuzz/minimize-corpus.sh TARGET CORPUS_DIRECTORY
```

Two copies of a post-run corpus are minimized separately and their sorted
content hashes must agree before one becomes persistent. Build products, raw
crash artifacts, coverage output, and transient logs stay ignored. A raw
artifact is reproduced with `reproduce.sh`, minimized with
`minimize-finding.sh`, then copied under `fuzz/findings/TARGET/` using its
SHA-256 as its filename and registered before any fix. The applicable campaign
manifest registers every retained seed or finding by target, byte count, and
SHA-256.
A reproduced parser finding follows QK-DEC-106: ordinary fix commit, minimized
regression fixture, and a decision row when the affected crate is frozen.
Every retained unit can be replayed once under the pinned build with
`fuzz/replay-corpus.sh TARGET`.

The two v2 slice-3 campaigns are preregistered together in
`CAMPAIGN-009.md`. Each executes exactly 100,000 inputs under AddressSanitizer
and starts from its separately retained public corpus. Two copied corpora are
minimized separately until a further pass changes neither set; only matching
sorted `SHA-256<TAB>bytes` sets may replace the persistent directories. M23
and M24 manifests move to their v2 generations only after both targets build,
both qualifying campaigns finish, minimization agrees, and retained replay is
clean.
