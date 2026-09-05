# QuietKey ring-fenced parser campaigns

EXPERIMENTAL — PUBLIC TEST INPUTS ONLY — NOT PRODUCT CODE

## V2 migration disposition

QK-DEC-121 preserves this ring fence and its dependency controls. Each target and registered corpus remains tied to the implementation generation it actually exercises: slice 1 replaces only `qk_descriptor`; later review, signing, provisioning, screen, export, Kit-frame, scanner, restore, and spend targets change only in their assigned slices. Until migrated, a v1 target is frozen historical coverage and supplies no v2 Card-C, three-role, selected-pair, 2-of-3, schema-v1/v2, or general-recovery capability. Corpus registration, minimization, named-error, no-panic, and sanitizer rules remain mandatory for every successor target.

This independent Cargo workspace is outside `host/Cargo.toml`. It contains
fifty-two libFuzzer targets for the `qk-psbt`, `qk-descriptor`, `qk-a1`,
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

QK-DEC-154 requalifies the pure `qk_supervisor_lifecycle` transition model and
adds the pure `qk_supervisor_process_lifecycle` model for the fixed bootstrap,
single-connection, parent-endpoint-close, normal-completion, bounded-reap,
cleanup, child-loss, connection-loss, no-restart, and absorbing named-outcome
rules. Neither target creates a process, socket, descriptor, wallet fact, or
device operation. Live process and syscall behavior remains bounded integration
test evidence. Campaign 027 and `CORPUS-MANIFEST-PROCESS-S8.tsv` are created
only after the final source commit is fixed and both qualifying campaigns and
two-copy minimizations complete.

QK-DEC-156 adds the dependency-free pure `qk_device_wire` target for the exact
QKDV header, all eight capability-bound body families, parser precedence,
fragmentation, coalescing, sequence, input/output-transfer, outstanding-
exchange, terminal-state, short-output, and volatile-cleanup rules. Its
control bytes are separate from candidate bytes, and a registered control
selector synthesizes the exact 262,169-byte maximum chunk presentation.
The pure `qk_core_normal_process` target drives the process-only Normal owner
through hostile card, keypad, QKIP, route, and interruption inputs and through
the complete registered public A1+B success and card-rejection cases. It locks
stable named outcomes, terminal absorption, deterministic repetition, exact
QKDV and QKIP adapters, and the absence of premature signature use. Neither
target creates a process, socket, descriptor, real device, card operation, or
hardware claim. Campaign 028 records fourteen byte-registered public starting
seeds, including one frame for every QKDV capability and a two-frame coalesced
stream. Both 100,000-input campaigns completed against the fixed final source;
their agreeing two-copy minimizations are registered in
`CORPUS-MANIFEST-PROCESS-S9.tsv`.

QK-DEC-161 adds the pure `qk_card_protocol` and `qk_card_model` targets and
requalifies `qk_device_wire` and `qk_core_normal_process`. The protocol target
drives hostile command, response, persistent-record, rejection-encoding,
lifecycle-table, output-bound, and volatile-wipe paths while requiring the
complete named error surface and deterministic canonical encodings. The model
target sends bounded arbitrary raw APDUs only through `CardModel::process_apdu`
and requires canonical responses, exact named rejections, deterministic state
transitions, and matching cleanup counts. Their initial accepted seeds are
exact lines copied from the shared public, permanently NEVER-FUND
`card_protocol_v1.txt` fixture; they create no new key authority. The test-only
model permits COMMIT in the exact registered fixture flow only, so arbitrary
structured mutations cannot introduce or exercise unregistered signing key
material; malformed and pre-commit state remain hostile inputs. The model is
absent from every product closure. The requalified core target parses
the registered INFO, descriptor, A2, and signature response facts through
`qk-card-protocol`, enters through one doc-hidden fuzz-only bound-card seam,
and requires the default decoder to reject the retired NormalFactor kind.
Campaign 029 remains planned until
the final source is fixed; no card, device, process, socket, descriptor, or
hardware action occurs in these pure targets.

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
production, performance or Gate boundary. Campaign 023 is complete and its
retained two-copy-minimized corpora are hash-registered.

The QK-DEC-145 `qk_core_provisioning_entry` and
`qk_core_provisioning_run` targets are the HOST-only process-slice-5
partition. The entry target drives the fixed manual-dice entry, echo,
confirmation and commitment sequence, including every state-preserving input
rejection, all reuse pairs and terminating interruptions. The run target drives
the public card-binding choices, hostile A1 scan-back, exact A1 and four-page
Kit print exchanges, receipt ordering, terminal absorption and cleanup
accounting. Its deterministic one-in-256 admission fold keeps the complete
provisioning path campaign-feasible; 22 public admitted seeds cover every
named semantic arm, while every other input drives a bounded named-rejection
path. Campaign 024 is complete; its two new two-copy-minimized corpora are
registered in `CORPUS-MANIFEST-PROCESS-S5.tsv`, and its two requalified
PROCESS-S4 corpora were promoted under QK-DEC-146.

The QK-DEC-149 `qk_core_normal_entry` and `qk_core_normal_run` targets are
the HOST-only process-slice-6 partition. The entry target drives the three
explicit recovery-profile bytes, both hostile PSBT ingress sources, framing,
state ordering and all terminating interruptions. The run target drives a
valid public NEVER-FUND flow through purpose-bound A1 and mock-card-B facts,
exact descriptor and wallet rebinding, schema-v3 review identity, every review
position, hold approval, reparse, purpose-bound A signing, checked mock-B
insertion, two-key finalization and exactly one explicit profile-permitted SD
or BBQr route. It locks exact finalized bytes, raw bytes, txid, wtxid, SD
filenames and receipts, BBQr geometry and reassembly, route delivery order,
partial two-artifact completion, deterministic repetition, named terminal
outcomes and cleanup accounting. Neither target reaches a real card, media
device, camera, display, keypad, process containment, target, performance,
production or Gate boundary. Campaign 025 is complete at final source
`d172318a0dcd00db4e7141fff60a33679872d46a`; both new corpora and the four
requalified qk-core corpora reached matching two-copy fixed points, were
promoted under QK-DEC-146 and are registered in the PROCESS-S4, S5 and S6
manifests bound to that source.

The exact runner is cargo-fuzz 0.13.2 and the exact compiler channel is
`nightly-2026-08-25` (`rustc 1.100.0-nightly (e7769602a 2026-08-24)`). The
runtime dependency and runner are recorded in `docs/SOURCE-REGISTER.md`.
`DEPENDENCY-ALLOWLIST.tsv` records every package in the union of the default,
`ipc`, `process-s2-decoy`, `process-s2-supervisor`, `process-s8-supervisor`,
`process-s3-io`, `process-s4-core`, `process-s5-core`, `process-s6-core`, and
`process-s7-core`, `process-s9-wire`, `process-s9-core`, `card-s1-protocol`,
and `card-s1-model`
normal/build closures
with an exact version, checksum, provenance, license, and purpose. `qk-ipc`,
`qk-decoy`, `qk-supervisor`, `qk-io`, `qk-core`, `qk-device-wire`,
`qk-card-protocol`, and `qk-card-model` are
optional and absent from the default closure; each target selects only its
named non-default feature. `process-s9-wire` reaches only qk-device-wire;
`process-s9-core` adds qk-device-wire to the existing qk-core closure.
`Cargo.lock`
also contains Cargo's inactive cross-target resolutions. The dependency guard
proves the fourteen fuzz closures remain isolated, qk-decoy's host closure is
dependency-free, qk-supervisor's host closure is exactly qk-supervisor plus
qk-ipc, and qk-io's default fuzz closure is exactly qk-io plus qk-ipc and
qk-bbqr while its HOST runtime closure adds only qk-device-wire. The
process-s4 through process-s7 closures are exactly qk-a1,
qk-bbqr, qk-bip32, qk-core, qk-descriptor, qk-ipc, qk-kit, qk-provisioning,
qk-psbt, qk-secp and qk-wallet-v2. The qk-core HOST runtime and
`process-s9-core` closure add only qk-device-wire to that set; direct qk-ipc
fuzzing support is selected only inside the core feature. qk-host-sim and qk-io are absent from
all core product and fuzz closures. The normalized union validates against the
allowlist; `card-s1-protocol` reaches only qk-card-protocol,
`card-s1-model` reaches only qk-card-model, qk-card-protocol and qk-secp, and
qk-card-model is absent from every product closure. The legacy default and
other named closures remain unchanged except for the ratified qk-core and
qk-device-wire edges.
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
fuzz/run-bounded.sh qk_supervisor_process_lifecycle 100000
fuzz/run-bounded.sh qk_decoy_calculator 100000
fuzz/run-bounded.sh qk_io_ingress 100000
fuzz/run-bounded.sh qk_io_egress 100000
fuzz/run-bounded.sh qk_io_session 100000
fuzz/run-bounded.sh qk_core_io_peer 100000
fuzz/run-bounded.sh qk_core_session 100000
fuzz/run-bounded.sh qk_core_provisioning_entry 100000
fuzz/run-bounded.sh qk_core_provisioning_run 100000
fuzz/run-bounded.sh qk_core_normal_entry 100000
fuzz/run-bounded.sh qk_core_normal_run 100000
fuzz/run-bounded.sh qk_core_kit_intake 100000
fuzz/run-bounded.sh qk_core_kit_restore 100000
fuzz/run-bounded.sh qk_core_kit_spend 100000
fuzz/run-bounded.sh qk_device_wire 100000
fuzz/run-bounded.sh qk_card_protocol 100000
fuzz/run-bounded.sh qk_card_model 100000
fuzz/run-bounded.sh qk_core_normal_process 100000
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
The two completed process-slice-4 campaigns are recorded in
`CAMPAIGN-023.md`; their matching two-copy-minimized corpora are registered
together in `CORPUS-MANIFEST-PROCESS-S4.tsv` under the source-before-execution
rule.
The three QK-DEC-151 process-slice-7 targets use the isolated
`process-s7-core` feature closure. Campaign 026 records the completed
requalification of all six earlier qk-core targets and the completed 100,000-
input campaigns for Kit intake, restore and spend. Their agreed retained
corpora are registered together in `CORPUS-MANIFEST-PROCESS-S7.tsv`; the
promoted earlier-target fixed points are also reflected in the S4, S5 and S6
partition manifests under QK-DEC-146.
The QK-DEC-154 process-slice-8 targets use the isolated pure supervisor
features. Campaign 027 records the two 100,000-input qualifying runs and their
agreed minimizations once the final source commit exists; the resulting
partition is rendered as `CORPUS-MANIFEST-PROCESS-S8.tsv`, with any changed
requalified slice-2 fixed point promoted under QK-DEC-146.
The QK-DEC-156 process-slice-9 targets use the isolated `process-s9-wire` and
`process-s9-core` features.
Campaign 028 records their public seed bytes, campaign parameters, exact
execution order, two-copy minimization, promotion, registration, and replay
results. The resulting `CORPUS-MANIFEST-PROCESS-S9.tsv` registers 386 units
containing 19,988 bytes against the fixed final source.
