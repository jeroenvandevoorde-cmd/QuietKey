# QuietKey ring-fenced parser campaigns

EXPERIMENTAL — PUBLIC TEST INPUTS ONLY — NOT PRODUCT CODE

This independent Cargo workspace is outside `host/Cargo.toml`. It contains
nine libFuzzer targets for the `qk-psbt`, `qk-descriptor`, `qk-a1`,
`qk-a1-codec`, `qk-card-trace`, M22 `qk-bbqr` codec and reassembly, and M23
`qk-psbt` semantic/review and `qk-host-sim` owned-workflow boundaries. It
changes no product behavior and reaches no card, camera, network, filesystem
parser, signing authority, or production target.

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
