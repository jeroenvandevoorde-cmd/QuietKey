# QuietKey ring-fenced parser campaigns

EXPERIMENTAL — PUBLIC TEST INPUTS ONLY — NOT PRODUCT CODE

## V2 migration disposition

QK-DEC-121 preserves this ring fence and its dependency controls. Each target and registered corpus remains tied to the implementation generation it actually exercises: slice 1 replaces only `qk_descriptor`; later review, signing, provisioning, screen, export, Kit-frame, scanner, restore, and spend targets change only in their assigned slices. Until migrated, a v1 target is frozen historical coverage and supplies no v2 Card-C, three-role, selected-pair, 2-of-3, schema-v1/v2, or general-recovery capability. Corpus registration, minimization, named-error, no-panic, and sanitizer rules remain mandatory for every successor target.

This independent Cargo workspace is outside `host/Cargo.toml`. It contains
forty libFuzzer targets for the `qk-psbt`, `qk-descriptor`, `qk-a1`,
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
of partial artifacts. Those M26 targets and their corpus partition remain
byte-frozen v1 migration residue. The separate v2 slice-4 inputs target drives
only `HostProvisioningRunV2::from_manual_dice` and nonce state across hostile
shape, symbol, all-six-pair reuse, and precedence cases. Its chain target drives
valid pairwise-distinct transcripts through the public A/B wallet and A1 facts,
then strictly reparses the v2 descriptors, scripts, addresses, and capsule.
Both demand stable named outcomes, exact repeat consistency, no partial
artifact, and public-artifact-only observations while the setup payload and
Kit-R pad remain opaque run-owned values. The two v2 slice-5 targets drive the
parallel screen topology and manual-keypad owner without consuming the v1 M27
or M29 fixtures. They require deterministic transitions, the complete
interruption wipe set, immutable Kit-door and approval identities, honest
slice-10/slice-11 deferred terminals, state-preserving keypad rejections,
four-buffer retention through reuse detection, and no C-role or Kit capability
release. M25 reuse is limited to its unchanged export-artifact types and
metadata semantics over v2 slice-3 finalized facts. The v2 slice-6 target
drives only the two-key watch-only construction and mock-SD publication path.
It locks both descriptor round trips, exact GOLDEN facts, the tier fence,
every record-line rejection and precedence, nonce-derived names, all mock-SD
faults and collisions, namespace preservation, deterministic repeat outcomes,
and the absence of any partial valid artifact or residual fuzz artifact. The
two v2 slice-7 `qk-kit` targets drive only the canonical Kit frame, M18
fallback, deterministic logical QR, and opaque pair-combination boundaries.
Dependency-free reference classifiers use the separately implemented,
NIST-vector-locked qk-psbt SHA-256 source and no qk-kit parser. The codec
target locks exact frame and fallback parsing precedence, canonical bytes,
fixed QR metadata, and unchanged caller output on rejection. The
combine target locks left-then-right frame validation, duplicate/same-index/
wallet-mismatch precedence, caller-order outcome invariance, deterministic
outcomes, and the absence of premature payload release; the qk-kit unit suite
separately locks exact caller-order payload identity. Neither target creates a Kit,
releases a combined payload, or reaches a scanner, camera, display, card,
restore, spend, persistence, rendering, target, performance, or Gate path. The
v2 slice-8 `qk_provisioning_v2_s8_kit_setup` target drives the sole consuming
setup-generation seam. It makes valid work deliberately sparse while retaining
all six fixed scenarios: missing A1, rejection at each of four page callbacks,
and success. Every delivered page is checked for exact callback order,
canonical frame/checksum/fallback, repeat QR equality and quiet-zone geometry,
same-index copy identity, full wallet binding, and XOR payload identity from
the four literal transcript hashes. The target repeats every selected
scenario, requires the closed named result and exact callback count, and uses
the in-crate fuzzing assertions that require every reusable 899-byte caller
output-buffer wipe. It creates no persistent Kit, renderer, scanner, retry,
card, camera, display, physical print, production, target-resource,
performance, or Gate path. The v2 slice-9
`qk_host_sim_v2_s9_kit_intake` target drives the mode-locked scanner-frame and
two-key fallback-entry boundary over both typed Kit doors. Every selected
scenario runs twice and requires deterministic exact ready facts, stable named
rejections, or bounded drop behavior,
exact door/mode binding, caller-frame clearing, terminal stability, no
post-rejection work, and no premature payload surface. Generated frame, share,
and fallback scratch is cleared before return. The target accepts no image or
camera fact and makes no scanner-performance, target, restore, spend,
production, or Gate claim. The v2 slice-10
`qk_host_sim_v2_s10_kit_restore` target consumes only a public slice-9 ready
owner reconstructed from the registered NEVER-FUND fixtures, rebinds it to
exact D, and drives both fixed restore actions across both intake modes and
frame orders. Its closed scenarios cover preparation and surviving-factor
rejection, every decimal assertion digit, missing-card routing, accepted and
rejected mock sinks, scan-back mismatch, every interruption across all six
reachable stage/action owners, and every distinct foreign operation. A
rolling byte selector keeps the full fixture rebind sparse; every other
selector deterministically checks the named invalid-digit rejection
twice. Each selected scenario runs twice and requires the same
named result, exact public receipt, sink count, mandatory-migration posture,
or bounded drop summary. It exposes no recovered payload or signer secret and
makes no signing, transaction, second-card, real card/APDU, physical-print,
freshness-generation, target, production, or Gate claim. The v2 slice-11
`qk_host_sim_v2_s11_kit_spend` target consumes only a public Kit-Spend ready
owner, rebinds it to exact old D, and admits one sweep to a distinct
replacement-wallet destination. Its 28 closed scenarios cover both intake
modes and frame orders, old-descriptor branches, hostile transaction shapes,
foreign-input positions, destination classes, assertion digits,
interruptions, foreign operations, partial-owner drops, and second-call
attempts. Every selected scenario runs twice and locks the exact result,
terminal state, callback/sign/finalize counts, caller-buffer clearing, and
complete-success facts. It exposes no generic signing operation and accepts
no restore, regeneration, second sweep, callback signer, ordinary-wallet
continuation, export, approval, or post-terminal work. The M27
`qk-host-sim` target drives
the typed provisioning, signing, and recovery screen-flow transition machine
through bounded event streams. It checks deterministic typed outcomes, the closed named
error surface, fixed-order review visitation, approval identity binding,
post-approval no-yield behavior, interruption wiping, terminal stability, and
exact fact forwarding from public frozen fixture objects. This area changes no
product behavior and reaches no card, camera, network, filesystem parser, real
signing authority, or production target.

The QK-DEC-136 `qk_update_package` and `qk_update_lifecycle` targets are the
HOST-only firmware-update partition. The package target bounds hostile package
and mock-media inputs, asserts single-read staging, stable named rejections,
production refusal of the registered test anchors, exact accepted public facts,
and deterministic results. The lifecycle target drives inactive-slot trial
preparation, fallback, single-use first-boot reporting, delayed floor/key-set
commit, version display, and all wallet/card preconditions while locking exact
state and rejection outcomes. Both use public, permanently NEVER-USE fixture
material, expose no signing or private-key operation, and make no real-media,
installer, flash, boot, target, power-cut, or Gate claim. Campaign 018 remains
preregistered but unexecuted until the complete target scaffold is committed.

The QK-DEC-140 `qk_ipc_wire` and `qk_ipc_endpoint_state` targets are the
HOST-only process-slice-1 partition. The wire target drives raw and constructed
frame parsing, exact re-encoding, arbitrary fragmentation and coalescing,
ancillary-first termination, size bounds, stable named rejections, and repeat
consistency. The endpoint target drives the complete core and I/O lifecycle,
hostile session and exchange facts, one-outstanding work, peer loss, terminal
stability, stable named rejections, and repeat consistency. Neither target
opens a socket or reaches a process, wallet, card, device, target, privilege,
performance, production, or Gate boundary. Campaign 020 is complete and its
two-copy-minimized corpora are registered in
`CORPUS-MANIFEST-PROCESS-S1.tsv`.

The QK-DEC-142 `qk_supervisor_lifecycle` and `qk_decoy_calculator` targets are
the HOST-only process-slice-2 partition. The supervisor target drives the
closed child, grant, connection-loss, termination, and no-restart transitions
while requiring stable named outcomes and repeat consistency. The calculator
target drives every P0.1 key through the complete
entry, pending-operation, result, overflow, and divide-by-zero states while
requiring deterministic display bytes, fixed twelve-digit bounds, immediate
left-to-right arithmetic, and a total key/state oracle. Neither target reaches
a wallet, card, real device, target privilege, production, performance, or Gate
boundary. Campaign 021 is complete and its retained corpora are hash-registered.

The QK-DEC-144 `qk_core_io_peer` and `qk_core_session` targets are the HOST-only
process-slice-4 partition. The peer target drives qk-core's separately
implemented inner response parser, one complete valid ingress transfer, outer
fragmentation and coalescing, ancillary rejection, session identity and
exchange ordering. The session target drives the typed capability seams, all
logical keys and interruptions, the complete non-signing shell lifecycle,
deterministic session-id facts, terminal absorption and exact wipe accounting.
Both require stable named outcomes and repeat consistency. Neither target
creates a wallet fact, signs, derives from live entropy, approves, exports,
opens a process or socket, or reaches a real display, keypad, card, target,
production, performance or Gate boundary. Campaign 023 is preregistered but
unexecuted until the complete target and registration scaffold is committed.

The exact runner is cargo-fuzz 0.13.2 and the exact compiler channel is
`nightly-2026-08-25` (`rustc 1.100.0-nightly (e7769602a 2026-08-24)`). The
runtime dependency and runner are recorded in `docs/SOURCE-REGISTER.md`.
`DEPENDENCY-ALLOWLIST.tsv` records every package in the union of the default,
`ipc`, `process-s2-decoy`, `process-s2-supervisor`, `process-s3-io`, and
`process-s4-core`
normal/build closures
with an exact version, checksum, provenance, license, and purpose. `qk-ipc`,
`qk-decoy`, `qk-supervisor`, `qk-io`, and `qk-core` are optional and absent from the default
closure; each target selects only its named non-default feature. `Cargo.lock`
also contains Cargo's inactive cross-target resolutions. The dependency guard
proves the six closures remain isolated, qk-decoy's host closure is
dependency-free, qk-supervisor's host closure is exactly qk-supervisor plus
qk-ipc, qk-io's host and fuzz closures are exactly qk-io plus qk-ipc and
qk-bbqr, qk-core's host and fuzz closures are exactly qk-core plus qk-ipc, and
the normalized union validates against the allowlist.
`tools/check.sh` exempts only
`fuzz/**/Cargo.toml` from the general dependency ban and fails closed on
non-top-level dependency tables, patches, replacements, closure isolation, or
any manifest/allowlist mismatch.
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
fuzz/run-bounded.sh qk_provisioning_v2_inputs 100000
fuzz/run-bounded.sh qk_provisioning_v2_chain 100000
fuzz/run-bounded.sh qk_host_sim_v2_s5_screen 100000
fuzz/run-bounded.sh qk_host_sim_v2_s5_manual_keypad 100000
fuzz/run-bounded.sh qk_host_sim_v2_s6_watch_only 100000
fuzz/run-bounded.sh qk_kit_v2_s7_codec 100000
fuzz/run-bounded.sh qk_kit_v2_s7_combine 100000
fuzz/run-bounded.sh qk_provisioning_v2_s8_kit_setup 100000
fuzz/run-bounded.sh qk_host_sim_v2_s9_kit_intake 100000
fuzz/run-bounded.sh qk_host_sim_v2_s10_kit_restore 100000
fuzz/run-bounded.sh qk_host_sim_v2_s11_kit_spend 100000
fuzz/run-bounded.sh qk_update_package 100000
fuzz/run-bounded.sh qk_update_lifecycle 100000
fuzz/run-bounded.sh qk_ipc_wire 100000
fuzz/run-bounded.sh qk_ipc_endpoint_state 100000
fuzz/run-bounded.sh qk_supervisor_lifecycle 100000
fuzz/run-bounded.sh qk_decoy_calculator 100000
fuzz/run-bounded.sh qk_io_ingress 100000
fuzz/run-bounded.sh qk_io_egress 100000
fuzz/run-bounded.sh qk_io_session 100000
fuzz/run-bounded.sh qk_core_io_peer 100000
fuzz/run-bounded.sh qk_core_session 100000
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

The two v2 slice-3 campaigns are recorded together in `CAMPAIGN-009.md`.
Each executed exactly 100,000 inputs under AddressSanitizer from its retained
public corpus. Two copied corpora were minimized separately until a further
pass changed neither set; only matching sorted `SHA-256<TAB>bytes` sets
replaced the persistent directories. The M23 registry retained its separate
`qk_psbt_m23` source pin, the M24 registry advanced to generation V2, and both
retained corpora replayed clean under the pinned toolchain.

The two v2 slice-4 campaigns are registered separately in
`CORPUS-MANIFEST-V2-S4.tsv` and recorded together in `CAMPAIGN-010.md`. The
two completed v2 slice-5 campaigns are registered separately in
`CORPUS-MANIFEST-V2-S5.tsv` and recorded together in `CAMPAIGN-011.md`. Both
slice-5 targets executed 100,000 inputs, reached exact two-copy minimization
fixed points, and replayed their hash-registered corpora under the pinned
toolchain. The v2 slice-6 corpus will be registered separately in
`CORPUS-MANIFEST-V2-S6.tsv` and its completed run recorded in
`CAMPAIGN-012.md`. The two completed v2 slice-7 campaigns are registered in
`CORPUS-MANIFEST-V2-S7.tsv` and recorded in `CAMPAIGN-013.md`. The v2 slice-8
setup-generation campaign is registered separately in
`CORPUS-MANIFEST-V2-S8.tsv` and recorded in `CAMPAIGN-014.md`.
The v2 slice-9 intake corpus will be registered separately in
`CORPUS-MANIFEST-V2-S9.tsv` and its completed run recorded in
`CAMPAIGN-015.md`.
The completed v2 slice-10 Kit-Restore campaign is registered in
`CORPUS-MANIFEST-V2-S10.tsv` and recorded in `CAMPAIGN-016.md`. The completed
v2 slice-11 Kit-Spend campaign is registered in
`CORPUS-MANIFEST-V2-S11.tsv` and recorded in `CAMPAIGN-017.md`.
The two planned firmware campaigns are preregistered in `CAMPAIGN-018.md`.
Their retained two-copy-minimized corpora will be registered together in
`CORPUS-MANIFEST-FIRMWARE-V1.tsv` only after the target-scaffold commit becomes
their common campaign source and both 100,000-input runs complete.
The two completed process-slice-1 campaigns are recorded in `CAMPAIGN-020.md`;
their matching retained corpora are registered together in
`CORPUS-MANIFEST-PROCESS-S1.tsv` under the source-before-execution rule.
The two completed process-slice-2 campaigns are recorded in `CAMPAIGN-021.md`;
their matching two-copy-minimized corpora are registered together in
`CORPUS-MANIFEST-PROCESS-S2.tsv` under the source-before-execution rule.
The three completed process-slice-3 campaigns are recorded in
`CAMPAIGN-022.md`; their matching two-copy-minimized corpora are registered
together in `CORPUS-MANIFEST-PROCESS-S3.tsv` under the source-before-execution
rule.
The two planned process-slice-4 campaigns are preregistered in
`CAMPAIGN-023.md`. Their retained two-copy-minimized corpora will be registered
together in `CORPUS-MANIFEST-PROCESS-S4.tsv` only after the
campaign-registration commit becomes their common campaign source and both
runs complete.
