# F2 Experiment Register

F2 PREPARATION ONLY — TARGET WORK NOT RUN — NO GATE CLOSED

This register is the single canonical source of F2 experiment definitions.
Experiment IDs use the family `QK-F2E-NNN` and are append-only: an ID, once
assigned, is never reused, renumbered, or deleted. Protocol documents in this
directory reference these IDs and never duplicate the rows.

Field discipline for every experiment:

- Specimen and Apparatus are exactly `OPEN — SPECIMEN NOT IDENTIFIED` until a
  future owner-authorized run registration.
- Repetition plan, Calibration plan, Exclusion criteria, Stopping rule, and
  Analysis plan are exactly `OPEN — NOT DEFINED UNTIL RUN REGISTRATION`.
  Repetition counts, the number of builders or specimens, and sweep points
  are part of the repetition plan and therefore remain OPEN; no procedure
  outline below selects any of them.
- Fact, Inference, and Decision input are exactly `NONE — NOT RUN`. The Claim
  field states only what a future run could in principle speak to; it asserts
  nothing.
- Status is exactly `PROTOCOL TEMPLATE — RUN REGISTRATION PENDING — NOT RUN`.
- Run registration for any experiment requires a future owner-authorized
  commit (H3). No such authorization exists.
- An experiment may inform, but can never resolve, an owner decision.
  Measurement authorizes nothing.
- Finite trials speak only to the registered tested points and recorded
  coverage. The absence of a failure at tested points is never treated as
  showing that failure is impossible.
- All linked canonical `QK-TST` rows remain `PLANNED — NOT RUN` and belong to
  later milestones. An F2 experiment run may prepare or inform a planned
  test, but it never executes one and never changes any `QK-TST` status;
  only a separately accepted canonical test run can do that.
- Inconclusive outcomes are recorded verbatim as inconclusive; they are never
  re-run, trimmed, or reinterpreted without a new registered run entry.

---

### QK-F2E-001 — ARMv6 candidate toolchain reproducible-build feasibility

- Question: Can the OD-01 candidate toolchain (Rust plus a narrow pinned `libsecp256k1` C boundary) produce byte-reproducible ARMv6 artifacts from a controlled builder, and what provenance record does that require?
- Links: QK-THR-009; QK-REQ-ASR-002; QK-REQ-ASR-004; QK-REQ-ASR-007; broad later audit context only (not tested by this experiment): QK-TST-AUD-002; gate context: no gate closes; OD-01 resolution is a Gate C closure input per `docs/MATURITY-GATES.md`.
- Owner decision this may inform (never resolve): OD-01
- Specimen: OPEN — SPECIMEN NOT IDENTIFIED
- Apparatus: OPEN — SPECIMEN NOT IDENTIFIED
- Procedure outline: pin exact toolchain component identities; build a minimal non-product probe artifact on independent controlled builders (the number of builders and builds is part of the repetition plan and remains OPEN); compare artifacts byte-for-byte; record complete provenance (source identity, component identity, build inputs) for every component.
- Repetition plan: OPEN — NOT DEFINED UNTIL RUN REGISTRATION
- Calibration plan: OPEN — NOT DEFINED UNTIL RUN REGISTRATION
- Exclusion criteria: OPEN — NOT DEFINED UNTIL RUN REGISTRATION
- Stopping rule: OPEN — NOT DEFINED UNTIL RUN REGISTRATION
- Analysis plan: OPEN — NOT DEFINED UNTIL RUN REGISTRATION
- Raw-evidence and hashing plan: every raw artifact (build logs, artifact binaries, provenance manifests) is stored at a recorded location with a cryptographic hash, in a record carrying every field of the evidence schema in `docs/TEST-ARCHITECTURE.md` as required by QK-REQ-ASR-008.
- Known confounders: builder environment drift; non-pinned transitive components; timestamp or path embedding in artifacts; toolchain component substitution between builds.
- Controls: independent builder comparison as reproduction control; no sacrificial hardware involved; no power-cut apparatus involved.
- Inconclusive handling: recorded verbatim as inconclusive; any repeat requires a new registered run entry.
- H3 prerequisite: run registration requires a future owner-authorized commit (H3); NOT GRANTED.
- Claim (potential subject only): whether the candidate toolchain direction is buildable and reproducible for ARMv6.
- Fact: NONE — NOT RUN
- Inference: NONE — NOT RUN
- Decision input: NONE — NOT RUN
- Status: PROTOCOL TEMPLATE — RUN REGISTRATION PENDING — NOT RUN

---

### QK-F2E-002 — ARMv6 secp256k1 reference-operation timing envelope

- Question: What order-of-magnitude timing envelope do representative secp256k1 reference operations exhibit on an ARMv6-class target under the OD-01 candidate boundary?
- Links: QK-REQ-ASR-002; gate context: no gate closes; this experiment is OD-01 feasibility input only — no canonical timing test is mapped to it unless one is later added to `docs/TEST-ARCHITECTURE.md`.
- Owner decision this may inform (never resolve): OD-01
- Specimen: OPEN — SPECIMEN NOT IDENTIFIED
- Apparatus: OPEN — SPECIMEN NOT IDENTIFIED
- Procedure outline: on an identified ARMv6-class specimen, time representative reference operations built from the pinned candidate boundary; record raw timing series without aggregation; note operating conditions alongside each series.
- Repetition plan: OPEN — NOT DEFINED UNTIL RUN REGISTRATION
- Calibration plan: OPEN — NOT DEFINED UNTIL RUN REGISTRATION
- Exclusion criteria: OPEN — NOT DEFINED UNTIL RUN REGISTRATION
- Stopping rule: OPEN — NOT DEFINED UNTIL RUN REGISTRATION
- Analysis plan: OPEN — NOT DEFINED UNTIL RUN REGISTRATION
- Raw-evidence and hashing plan: raw timing series and environment descriptions stored at a recorded location with cryptographic hashes, per the evidence schema in `docs/TEST-ARCHITECTURE.md` (QK-REQ-ASR-008).
- Known confounders: clock scaling; thermal state; background activity of any host OS; measurement-harness overhead; compiler option drift.
- Controls: harness-overhead baseline measurement as control; no sacrificial hardware involved; no power-cut apparatus involved.
- Inconclusive handling: recorded verbatim as inconclusive; any repeat requires a new registered run entry.
- H3 prerequisite: run registration requires a future owner-authorized commit (H3); NOT GRANTED.
- Claim (potential subject only): whether ARMv6-class timing is within a range worth continuing to evaluate under OD-01.
- Fact: NONE — NOT RUN
- Inference: NONE — NOT RUN
- Decision input: NONE — NOT RUN
- Status: PROTOCOL TEMPLATE — RUN REGISTRATION PENDING — NOT RUN

---

### QK-F2E-003 — Exact-card APDU behavior and byte-layout survey

- Question: What documented and observed APDU behaviors and byte layouts does a candidate exact card expose, and do the surveyed behaviors admit the least-authority payload model?
- Links: QK-THR-001; QK-THR-003; QK-THR-008; QK-REQ-CARD-001; contextual only (this survey covers part of the interface, not the full hostile-response scope): QK-REQ-CARD-004; QK-LIM-APDU-001; related planned context: QK-TST-BENCH-002; gate context: candidate-card specimen; Gate B preparation and OD-02 input only — Gate B itself requires the exact production card selected after OD-02; no gate closes.
- Owner decision this may inform (never resolve): OD-02
- Specimen: OPEN — SPECIMEN NOT IDENTIFIED
- Apparatus: OPEN — SPECIMEN NOT IDENTIFIED
- Procedure outline: enumerate the candidate card's documented command set (the documentation survey may be exhaustive); on a sacrificial specimen, exercise only commands on a future H3 owner-approved safe command allowlist — destructive and lifecycle commands belong in separately controlled sacrificial-card runs; record raw command/response byte traces; compare observed behavior against vendor documentation and against the least-authority payload model.
- Repetition plan: OPEN — NOT DEFINED UNTIL RUN REGISTRATION
- Calibration plan: OPEN — NOT DEFINED UNTIL RUN REGISTRATION
- Exclusion criteria: OPEN — NOT DEFINED UNTIL RUN REGISTRATION
- Stopping rule: OPEN — NOT DEFINED UNTIL RUN REGISTRATION
- Analysis plan: OPEN — NOT DEFINED UNTIL RUN REGISTRATION
- Raw-evidence and hashing plan: raw APDU traces and documentation excerpts stored at a recorded location with cryptographic hashes, per the evidence schema in `docs/TEST-ARCHITECTURE.md` (QK-REQ-ASR-008).
- Known confounders: card firmware revision differences between specimens; reader-side behavior; undocumented vendor state carried between sessions.
- Controls: sacrificial card specimens only — never a custody-relevant card; specimen-consistency controls are part of the repetition plan and remain OPEN; no power-cut apparatus in this experiment.
- Inconclusive handling: recorded verbatim as inconclusive; any repeat requires a new registered run entry.
- H3 prerequisite: run registration requires a future owner-authorized commit (H3); NOT GRANTED.
- Claim (potential subject only): whether a candidate card's surveyed interface is compatible with the OD-02 feasibility questions, at the surveyed coverage only.
- Fact: NONE — NOT RUN
- Inference: NONE — NOT RUN
- Decision input: NONE — NOT RUN
- Status: PROTOCOL TEMPLATE — RUN REGISTRATION PENDING — NOT RUN

---

### QK-F2E-004 — Exact-card signing correctness and performance probe

- Question: Does a candidate exact card produce mathematically valid secp256k1 ECDSA signatures for reference inputs, and within what raw timing envelope?
- Links: QK-REQ-CARD-001; related planned context: QK-TST-BENCH-002 (signing correctness); weak threat context only: QK-THR-001; gate context: candidate-card specimen; Gate B preparation and OD-02 input only — Gate B itself requires the exact production card selected after OD-02; no gate closes.
- Owner decision this may inform (never resolve): OD-02
- Specimen: OPEN — SPECIMEN NOT IDENTIFIED
- Apparatus: OPEN — SPECIMEN NOT IDENTIFIED
- Procedure outline: load reference inputs onto a sacrificial specimen; request signing operations; verify each returned signature mathematically — ECDSA verification against the expected public key and message; byte comparison against a stored reference signature is registered only if the exact card explicitly documents a deterministic nonce construction and that separate documented claim is itself under test; record raw timing per operation.
- Repetition plan: OPEN — NOT DEFINED UNTIL RUN REGISTRATION
- Calibration plan: OPEN — NOT DEFINED UNTIL RUN REGISTRATION
- Exclusion criteria: OPEN — NOT DEFINED UNTIL RUN REGISTRATION
- Stopping rule: OPEN — NOT DEFINED UNTIL RUN REGISTRATION
- Analysis plan: OPEN — NOT DEFINED UNTIL RUN REGISTRATION
- Raw-evidence and hashing plan: raw request/response traces, reference-input files, and timing series stored at a recorded location with cryptographic hashes, per the evidence schema in `docs/TEST-ARCHITECTURE.md` (QK-REQ-ASR-008).
- Known confounders: reader latency folded into timing; card-internal state effects; specimen-to-specimen variation.
- Controls: sacrificial card specimens only; independent mathematical signature verification as correctness control; no power-cut apparatus in this experiment.
- Inconclusive handling: recorded verbatim as inconclusive; any repeat requires a new registered run entry.
- H3 prerequisite: run registration requires a future owner-authorized commit (H3); NOT GRANTED.
- Claim (potential subject only): whether candidate-card signing behavior is worth continuing to evaluate under OD-02.
- Fact: NONE — NOT RUN
- Inference: NONE — NOT RUN
- Decision input: NONE — NOT RUN
- Status: PROTOCOL TEMPLATE — RUN REGISTRATION PENDING — NOT RUN

---

### QK-F2E-005 — Exact-card write atomicity under controlled power interruption

- Question: At the registered tested interruption points during write and lifecycle operations, does a candidate exact card ever exhibit an inconsistent third state, and what coverage of interruption points was actually tested?
- Links: QK-THR-011; QK-THR-019; QK-REQ-CARD-005; QK-REQ-CARD-010; QK-LIM-APDU-005; QK-LIM-APDU-009; related planned context: QK-TST-PWR-002; gate context: candidate-card specimen; Gate B preparation and OD-02 input only — Gate B itself requires the exact production card selected after OD-02; no gate closes.
- Owner decision this may inform (never resolve): OD-02
- Specimen: OPEN — SPECIMEN NOT IDENTIFIED
- Apparatus: OPEN — SPECIMEN NOT IDENTIFIED
- Procedure outline: drive write and lifecycle operations on a sacrificial specimen through a controlled power-cut apparatus; interrupt at registered, systematically varied points; on restart, read back state through the documented interface; record per tested point whether observed state is one of the two committed states or an inconsistent third state; record the tested-point coverage explicitly — untested points support no claim.
- Repetition plan: OPEN — NOT DEFINED UNTIL RUN REGISTRATION
- Calibration plan: OPEN — NOT DEFINED UNTIL RUN REGISTRATION
- Exclusion criteria: OPEN — NOT DEFINED UNTIL RUN REGISTRATION
- Stopping rule: OPEN — NOT DEFINED UNTIL RUN REGISTRATION
- Analysis plan: OPEN — NOT DEFINED UNTIL RUN REGISTRATION
- Raw-evidence and hashing plan: interruption-point logs, restart read-back traces, and apparatus configuration records stored at a recorded location with cryptographic hashes, per the evidence schema in `docs/TEST-ARCHITECTURE.md` (QK-REQ-ASR-008).
- Known confounders: apparatus switching characteristics; residual card capacitance; specimen wear accumulated across interruptions; reader power behavior.
- Controls: sacrificial card specimens only — specimens are expected to be consumed; controlled power-cut apparatus only (never ad-hoc unplugging); uninterrupted operation on a matched specimen as baseline control.
- Inconclusive handling: recorded verbatim as inconclusive; any repeat requires a new registered run entry.
- H3 prerequisite: run registration requires a future owner-authorized commit (H3); NOT GRANTED.
- Claim (potential subject only): candidate-card interruption behavior at the tested points only; absence of an inconsistent state at tested points never shows such a state is impossible.
- Fact: NONE — NOT RUN
- Inference: NONE — NOT RUN
- Decision input: NONE — NOT RUN
- Status: PROTOCOL TEMPLATE — RUN REGISTRATION PENDING — NOT RUN

---

### QK-F2E-006 — Actual-camera BBQr type-P frame-rate and decode feasibility

- Question: At what raw frame rates and frame sizes does a candidate camera assembly decode uncompressed BBQr type-P sequences, before any product mechanics exist?
- Links: QK-THR-006; QK-THR-016; QK-REQ-TRN-003; QK-LIM-QR-007; QK-LIM-QR-013 (these `QK-LIM-QR` rows are governed by OD-05); related planned context: QK-TST-BENCH-001; gate context: QK-TST-BENCH-001 and Gate A preparation only, not Gate A evidence — Gate A evidence requires the exact fixed production hardware; no gate closes.
- Owner decision this may inform (never resolve): OD-05; also a future owner hardware selection for which no numbered decision exists yet.
- Specimen: OPEN — SPECIMEN NOT IDENTIFIED
- Apparatus: OPEN — SPECIMEN NOT IDENTIFIED
- Procedure outline: present generated BBQr type-P sequences on a controlled display to a candidate camera assembly; sweep presentation rate and module density (sweep points are part of the repetition plan and remain OPEN); record raw capture streams and per-frame decode outcomes without aggregation.
- Repetition plan: OPEN — NOT DEFINED UNTIL RUN REGISTRATION
- Calibration plan: OPEN — NOT DEFINED UNTIL RUN REGISTRATION
- Exclusion criteria: OPEN — NOT DEFINED UNTIL RUN REGISTRATION
- Stopping rule: OPEN — NOT DEFINED UNTIL RUN REGISTRATION
- Analysis plan: OPEN — NOT DEFINED UNTIL RUN REGISTRATION
- Raw-evidence and hashing plan: raw capture streams, generated source sequences, and per-frame outcome logs stored at a recorded location with cryptographic hashes, per the evidence schema in `docs/TEST-ARCHITECTURE.md` (QK-REQ-ASR-008).
- Known confounders: display refresh interaction; ambient lighting; lens focus drift; decoder software identity on the bench host; camera auto-exposure behavior.
- Controls: fixed-geometry bench arrangement as repeatability control; static single-frame decode as baseline control; sacrificial media not applicable; no power-cut apparatus in this experiment.
- Inconclusive handling: recorded verbatim as inconclusive; any repeat requires a new registered run entry.
- H3 prerequisite: run registration requires a future owner-authorized commit (H3); NOT GRANTED.
- Claim (potential subject only): whether a candidate camera assembly is worth continuing to evaluate for BBQr type-P ingest.
- Fact: NONE — NOT RUN
- Inference: NONE — NOT RUN
- Decision input: NONE — NOT RUN
- Status: PROTOCOL TEMPLATE — RUN REGISTRATION PENDING — NOT RUN

---

### QK-F2E-007 — QR reassembly resource observation on candidate target

- Question: What raw memory and work profile does reference BBQr type-P reassembly exhibit on a candidate target class under hostile and benign frame streams?
- Links: QK-THR-016; QK-REQ-TRN-005; QK-LIM-QR-001; QK-LIM-QR-009 (these `QK-LIM-QR` rows are governed by OD-05); planned-test preparation only — a candidate target cannot execute the exact-target test QK-TST-BENCH-003; gate context: Gate A preparation only, not Gate A evidence; no gate closes.
- Owner decision this may inform (never resolve): OD-05; also a future owner hardware selection for which no numbered decision exists yet.
- Specimen: OPEN — SPECIMEN NOT IDENTIFIED
- Apparatus: OPEN — SPECIMEN NOT IDENTIFIED
- Procedure outline: replay recorded benign and hostile frame streams into a reference reassembly implementation on a candidate target class; record raw peak-memory and work observations per stream; keep streams and observations paired.
- Repetition plan: OPEN — NOT DEFINED UNTIL RUN REGISTRATION
- Calibration plan: OPEN — NOT DEFINED UNTIL RUN REGISTRATION
- Exclusion criteria: OPEN — NOT DEFINED UNTIL RUN REGISTRATION
- Stopping rule: OPEN — NOT DEFINED UNTIL RUN REGISTRATION
- Analysis plan: OPEN — NOT DEFINED UNTIL RUN REGISTRATION
- Raw-evidence and hashing plan: input stream files and raw observation logs stored at a recorded location with cryptographic hashes, per the evidence schema in `docs/TEST-ARCHITECTURE.md` (QK-REQ-ASR-008).
- Known confounders: reference-implementation identity (not the production implementation, which does not exist); allocator behavior; measurement instrumentation overhead.
- Controls: benign stream as baseline control; instrumentation-only idle run as overhead control; sacrificial media not applicable; no power-cut apparatus in this experiment.
- Inconclusive handling: recorded verbatim as inconclusive; any repeat requires a new registered run entry.
- H3 prerequisite: run registration requires a future owner-authorized commit (H3); NOT GRANTED.
- Claim (potential subject only): the observed resource envelope of reference reassembly; it can inform, never set, any `QK-LIM` value.
- Fact: NONE — NOT RUN
- Inference: NONE — NOT RUN
- Decision input: NONE — NOT RUN
- Status: PROTOCOL TEMPLATE — RUN REGISTRATION PENDING — NOT RUN

---

### QK-F2E-008 — SD interface electrical and removal behavior probe

- Question: How does a candidate SD interface behave electrically under insertion, removal, and hostile-media presentation, observed from a bounded userspace position?
- Links: QK-THR-006; QK-THR-011; QK-THR-019; QK-REQ-TRN-002; QK-REQ-TRN-009; QK-REQ-TRN-010 (the TRN-009/TRN-010 mechanism selection is governed by OD-06); related planned context: QK-TST-PWR-003; gate context: Gate D preparation only; no gate closes.
- Owner decision this may inform (never resolve): OD-06; also a future owner hardware selection for which no numbered decision exists yet.
- Specimen: OPEN — SPECIMEN NOT IDENTIFIED
- Apparatus: OPEN — SPECIMEN NOT IDENTIFIED
- Procedure outline: exercise insertion, removal during idle, removal during read, and presentation of corrupt, full, and read-only sacrificial media on a candidate SD interface; observe from a bounded userspace reader without trusted-kernel mounting; record raw electrical and behavioral observations.
- Repetition plan: OPEN — NOT DEFINED UNTIL RUN REGISTRATION
- Calibration plan: OPEN — NOT DEFINED UNTIL RUN REGISTRATION
- Exclusion criteria: OPEN — NOT DEFINED UNTIL RUN REGISTRATION
- Stopping rule: OPEN — NOT DEFINED UNTIL RUN REGISTRATION
- Analysis plan: OPEN — NOT DEFINED UNTIL RUN REGISTRATION
- Raw-evidence and hashing plan: raw observation logs, media images before and after each trial, and apparatus configuration records stored at a recorded location with cryptographic hashes, per the evidence schema in `docs/TEST-ARCHITECTURE.md` (QK-REQ-ASR-008).
- Known confounders: media brand and wear variation; connector wear across trials; host controller quirks; ambient temperature.
- Controls: sacrificial media only — never custody-relevant media; a known-good untouched medium as baseline control; controlled removal fixture rather than hand timing where interruption points matter.
- Inconclusive handling: recorded verbatim as inconclusive; any repeat requires a new registered run entry.
- H3 prerequisite: run registration requires a future owner-authorized commit (H3); NOT GRANTED.
- Claim (potential subject only): whether a candidate SD interface direction is worth continuing to evaluate for Gate D preparation.
- Fact: NONE — NOT RUN
- Inference: NONE — NOT RUN
- Decision input: NONE — NOT RUN
- Status: PROTOCOL TEMPLATE — RUN REGISTRATION PENDING — NOT RUN

---

### QK-F2E-009 — SD output write, sync, and read-back interruption probe

- Question: At the registered tested interruption points across write, sync, and read-back of an output file on sacrificial media, is an incomplete output observed as complete at any tested point, and what coverage was actually tested?
- Links: QK-THR-019; QK-REQ-TRN-008; QK-LIM-SD-011; QK-LIM-SD-012; QK-LIM-SD-013 (these `QK-LIM-SD` rows are governed by OD-05); related planned context: QK-TST-PWR-005; gate context: Gate D preparation only; no gate closes.
- Owner decision this may inform (never resolve): OD-05; also a future owner hardware selection for which no numbered decision exists yet.
- Specimen: OPEN — SPECIMEN NOT IDENTIFIED
- Apparatus: OPEN — SPECIMEN NOT IDENTIFIED
- Procedure outline: write a known output pattern to sacrificial media through a controlled power-cut apparatus; interrupt at registered, systematically varied points across write, sync, and read-back phases; after restart, image the media and record exactly what a bounded reader would observe; record the tested-point coverage explicitly — untested points support no claim.
- Repetition plan: OPEN — NOT DEFINED UNTIL RUN REGISTRATION
- Calibration plan: OPEN — NOT DEFINED UNTIL RUN REGISTRATION
- Exclusion criteria: OPEN — NOT DEFINED UNTIL RUN REGISTRATION
- Stopping rule: OPEN — NOT DEFINED UNTIL RUN REGISTRATION
- Analysis plan: OPEN — NOT DEFINED UNTIL RUN REGISTRATION
- Raw-evidence and hashing plan: pre- and post-interruption media images, interruption-point logs, and apparatus records stored at a recorded location with cryptographic hashes, per the evidence schema in `docs/TEST-ARCHITECTURE.md` (QK-REQ-ASR-008).
- Known confounders: media-internal write caching invisible to the host; controller-level wear management; apparatus switching characteristics; filesystem identity on the sacrificial media.
- Controls: sacrificial media only — media are expected to be consumed; controlled power-cut apparatus only; uninterrupted write/sync/read-back cycle as baseline control.
- Inconclusive handling: recorded verbatim as inconclusive; any repeat requires a new registered run entry.
- H3 prerequisite: run registration requires a future owner-authorized commit (H3); NOT GRANTED.
- Claim (potential subject only): whether the candidate storage direction distinguishes complete from incomplete outputs at the tested points; absence of a false-complete observation at tested points never shows impossibility.
- Fact: NONE — NOT RUN
- Inference: NONE — NOT RUN
- Decision input: NONE — NOT RUN
- Status: PROTOCOL TEMPLATE — RUN REGISTRATION PENDING — NOT RUN

---

### QK-F2E-010 — Provisioning-interruption feasibility probe

- Question: Can an interruption-injection method be built around candidate hardware such that, at the registered tested interruption points of a mock provisioning sequence, every observed post-restart state is unambiguously classifiable, and what coverage was actually tested?
- Links: QK-THR-011; QK-THR-012; QK-THR-019; QK-REQ-A1-009; QK-REQ-REC-005; method preparation only — a mock non-product sequence on candidate hardware cannot execute QK-TST-PWR-001 and yields no Gate A or Gate D evidence; gate context: Gate A and Gate D preparation only; no gate closes.
- Owner decision this may inform (never resolve): a future owner hardware selection decision; no existing OD is resolved by this experiment.
- Specimen: OPEN — SPECIMEN NOT IDENTIFIED
- Apparatus: OPEN — SPECIMEN NOT IDENTIFIED
- Procedure outline: define a mock provisioning sequence with no secret material; drive it on candidate hardware through a controlled power-cut apparatus; interrupt at registered, systematically varied points; record the observable state after each restart and whether the state is unambiguously classifiable; record the tested-point coverage explicitly — untested points support no claim.
- Repetition plan: OPEN — NOT DEFINED UNTIL RUN REGISTRATION
- Calibration plan: OPEN — NOT DEFINED UNTIL RUN REGISTRATION
- Exclusion criteria: OPEN — NOT DEFINED UNTIL RUN REGISTRATION
- Stopping rule: OPEN — NOT DEFINED UNTIL RUN REGISTRATION
- Analysis plan: OPEN — NOT DEFINED UNTIL RUN REGISTRATION
- Raw-evidence and hashing plan: interruption-point logs, post-restart state records, and mock-sequence definitions stored at a recorded location with cryptographic hashes, per the evidence schema in `docs/TEST-ARCHITECTURE.md` (QK-REQ-ASR-008).
- Known confounders: mock sequence fidelity (no product provisioning logic exists); apparatus timing granularity; specimen state carried across trials.
- Controls: sacrificial card and sacrificial media only; controlled power-cut apparatus only; uninterrupted mock sequence as baseline control; the mock sequence contains no secret and no seed-like fixture.
- Inconclusive handling: recorded verbatim as inconclusive; any repeat requires a new registered run entry.
- H3 prerequisite: run registration requires a future owner-authorized commit (H3); NOT GRANTED.
- Claim (potential subject only): whether interruption injection around candidate hardware is a workable method for later gate-relevant testing, at the tested coverage only.
- Fact: NONE — NOT RUN
- Inference: NONE — NOT RUN
- Decision input: NONE — NOT RUN
- Status: PROTOCOL TEMPLATE — RUN REGISTRATION PENDING — NOT RUN

---

### QK-F2E-011 — Exact-card derivation and key-origin boundary survey

- Question: What key-derivation and key-origin behavior does a candidate exact card expose for the least-authority payload model, and where is its supported derivation boundary?
- Links: QK-THR-003; QK-REQ-CARD-001; QK-REQ-CARD-003; related planned context: QK-TST-BENCH-002 (derivation behavior); gate context: candidate-card specimen; Gate B preparation and OD-02 input only — Gate B itself requires the exact production card selected after OD-02; no gate closes.
- Owner decision this may inform (never resolve): OD-02
- Specimen: OPEN — SPECIMEN NOT IDENTIFIED
- Apparatus: OPEN — SPECIMEN NOT IDENTIFIED
- Procedure outline: on a sacrificial specimen, survey documented derivation capabilities within a future H3 owner-approved safe command allowlist; probe where on-card derivation is supported, refused, or undefined; verify key-origin correctness of derived material by independent recomputation from documented inputs; record raw traces and the exact boundary observed.
- Repetition plan: OPEN — NOT DEFINED UNTIL RUN REGISTRATION
- Calibration plan: OPEN — NOT DEFINED UNTIL RUN REGISTRATION
- Exclusion criteria: OPEN — NOT DEFINED UNTIL RUN REGISTRATION
- Stopping rule: OPEN — NOT DEFINED UNTIL RUN REGISTRATION
- Analysis plan: OPEN — NOT DEFINED UNTIL RUN REGISTRATION
- Raw-evidence and hashing plan: raw command/response traces, recomputation inputs and outputs, and boundary notes stored at a recorded location with cryptographic hashes, per the evidence schema in `docs/TEST-ARCHITECTURE.md` (QK-REQ-ASR-008).
- Known confounders: card firmware revision differences; vendor-documented versus observed behavior divergence; reader-side transformation of traffic.
- Controls: sacrificial card specimens only; independent recomputation from documented inputs as correctness control; no power-cut apparatus in this experiment.
- Inconclusive handling: recorded verbatim as inconclusive; any repeat requires a new registered run entry.
- H3 prerequisite: run registration requires a future owner-authorized commit (H3); NOT GRANTED.
- Claim (potential subject only): whether a candidate card's derivation and key-origin behavior is compatible with the least-authority payload model under OD-02, at the surveyed boundary only.
- Fact: NONE — NOT RUN
- Inference: NONE — NOT RUN
- Decision input: NONE — NOT RUN
- Status: PROTOCOL TEMPLATE — RUN REGISTRATION PENDING — NOT RUN

---

### QK-F2E-012 — Exact-card signing nonce and RNG capability characterization

- Question: What signing-nonce construction and random-number capability does a candidate exact card document and observably exhibit, within the limits of what external observation can show?
- Links: QK-THR-015; QK-REQ-CARD-007; related planned context: QK-TST-BENCH-002 (on-card RNG characterization); gate context: candidate-card specimen; Gate B preparation and OD-02 input only — Gate B itself requires the exact production card selected after OD-02; no gate closes.
- Owner decision this may inform (never resolve): OD-02
- Specimen: OPEN — SPECIMEN NOT IDENTIFIED
- Apparatus: OPEN — SPECIMEN NOT IDENTIFIED
- Procedure outline: collect the candidate card's documented claims about signing-nonce construction and RNG; on a sacrificial specimen, within a future H3 owner-approved safe command allowlist, collect signature and RNG output samples; apply statistical characterization to the samples, recording explicitly that statistical testing can reject some defects but can never establish entropy or nonce quality; the run design is conditional on the selected card's documented signing model.
- Repetition plan: OPEN — NOT DEFINED UNTIL RUN REGISTRATION
- Calibration plan: OPEN — NOT DEFINED UNTIL RUN REGISTRATION
- Exclusion criteria: OPEN — NOT DEFINED UNTIL RUN REGISTRATION
- Stopping rule: OPEN — NOT DEFINED UNTIL RUN REGISTRATION
- Analysis plan: OPEN — NOT DEFINED UNTIL RUN REGISTRATION
- Raw-evidence and hashing plan: raw sample sets, documentation excerpts, and characterization outputs stored at a recorded location with cryptographic hashes, per the evidence schema in `docs/TEST-ARCHITECTURE.md` (QK-REQ-ASR-008).
- Known confounders: sample volume obtainable through the interface; card-internal post-processing masking source behavior; documented behavior differing from observed behavior; firmware revision differences.
- Controls: sacrificial card specimens only; documented-claim versus observed-sample comparison as the framing control; no power-cut apparatus in this experiment.
- Inconclusive handling: recorded verbatim as inconclusive; any repeat requires a new registered run entry.
- H3 prerequisite: run registration requires a future owner-authorized commit (H3); NOT GRANTED.
- Claim (potential subject only): what the candidate card documents and observably exhibits about nonce and RNG capability; statistical observation can never establish entropy.
- Fact: NONE — NOT RUN
- Inference: NONE — NOT RUN
- Decision input: NONE — NOT RUN
- Status: PROTOCOL TEMPLATE — RUN REGISTRATION PENDING — NOT RUN

---

### QK-F2E-013 — A2 payload storage, separation, and export-model characterization

- Question: At the probed black-box interface of a candidate exact card, can two specimens provisioned with deliberately distinct fixtures present distinct signer identities, both store and return the same A2 payload exactly, and keep A2 write/read operations from changing those observed identities or exposing seed or private-key bytes — and what export model governs the payload?
- Links: QK-THR-003; QK-REQ-CARD-003 (kept solely because this procedure probes its distinct-role/unique-key interface aspects; no compliance claim and no test execution); QK-REQ-CUS-002; related planned context: QK-TST-BENCH-002 (least-authority payload and independent B/C keys); gate context: candidate-card specimen; Gate B preparation and OD-02 input only — Gate B itself requires the exact production card selected after OD-02; no gate closes.
- Owner decision this may inform (never resolve): OD-02
- Specimen: OPEN — SPECIMEN NOT IDENTIFIED
- Apparatus: OPEN — SPECIMEN NOT IDENTIFIED
- Procedure outline: on sacrificial specimens, within a future H3 owner-approved safe command allowlist: provision the B-role and C-role specimens with deliberately distinct, independently specified, owner-authorized public synthetic fixtures (openly disclosed, no-funds, non-custody raw-key or seed test vectors — test vectors, not secrets); verify each specimen's returned public identity against its independent expected value and verify the B and C identities are distinct; place the same public synthetic A2 payload on both specimens; verify either card returns the exact A2 payload; verify A2 write and read operations do not change the observed B/C signer identities and do not expose seed or private-key bytes through the probed interface; characterize the card's export model for the payload (specimen counts are part of the repetition plan and remain OPEN).
- Repetition plan: OPEN — NOT DEFINED UNTIL RUN REGISTRATION
- Calibration plan: OPEN — NOT DEFINED UNTIL RUN REGISTRATION
- Exclusion criteria: OPEN — NOT DEFINED UNTIL RUN REGISTRATION
- Stopping rule: OPEN — NOT DEFINED UNTIL RUN REGISTRATION
- Analysis plan: OPEN — NOT DEFINED UNTIL RUN REGISTRATION
- Raw-evidence and hashing plan: raw traces, payload fixtures (non-secret bench payloads only), and separation-probe records stored at a recorded location with cryptographic hashes, per the evidence schema in `docs/TEST-ARCHITECTURE.md` (QK-REQ-ASR-008).
- Known confounders: vendor storage abstractions hiding physical layout; firmware revision differences; interface-level access control masking the underlying export model.
- Controls: sacrificial card specimens only; fixtures restricted to owner-authorized, public, synthetic, openly disclosed, no-funds, non-custody test vectors created solely for the registered bench run — never custody-relevant material; independent expected public identities computed outside the card under test; no power-cut apparatus in this experiment.
- Inconclusive handling: recorded verbatim as inconclusive; any repeat requires a new registered run entry.
- H3 prerequisite: run registration requires a future owner-authorized commit (H3); NOT GRANTED.
- Claim (potential subject only): whether, at the probed black-box interface coverage only, the candidate card presents distinct B/C signer identities from distinct fixtures and supports the A2-on-either-bearer-card arrangement without observed identity change or seed/private-key exposure. This can never prove internal physical separation, entropy quality, or absence of hidden coupling beyond surveyed interface behavior.
- Fact: NONE — NOT RUN
- Inference: NONE — NOT RUN
- Decision input: NONE — NOT RUN
- Status: PROTOCOL TEMPLATE — RUN REGISTRATION PENDING — NOT RUN

---

### QK-F2E-014 — Exact-card lifecycle and storage-endurance probe

- Question: How does a candidate exact card behave across repeated lifecycle transitions and storage rewrites over time, distinct from the single interruption-atomicity probe QK-F2E-005?
- Links: QK-THR-011; QK-REQ-CARD-008; related planned context: QK-TST-BENCH-002 (storage endurance); gate context: candidate-card specimen; Gate B preparation and OD-02 input only — Gate B itself requires the exact production card selected after OD-02; no gate closes.
- Owner decision this may inform (never resolve): OD-02
- Specimen: OPEN — SPECIMEN NOT IDENTIFIED
- Apparatus: OPEN — SPECIMEN NOT IDENTIFIED
- Procedure outline: on sacrificial specimens, within a future H3 owner-approved safe command allowlist, drive repeated lifecycle transitions and storage rewrites without power interruption; record per-cycle observations of state consistency, refusal behavior, and any degradation the interface exposes; destructive and irreversible lifecycle commands belong in separately controlled sacrificial-card runs and consume their specimens.
- Repetition plan: OPEN — NOT DEFINED UNTIL RUN REGISTRATION
- Calibration plan: OPEN — NOT DEFINED UNTIL RUN REGISTRATION
- Exclusion criteria: OPEN — NOT DEFINED UNTIL RUN REGISTRATION
- Stopping rule: OPEN — NOT DEFINED UNTIL RUN REGISTRATION
- Analysis plan: OPEN — NOT DEFINED UNTIL RUN REGISTRATION
- Raw-evidence and hashing plan: per-cycle logs and state read-back traces stored at a recorded location with cryptographic hashes, per the evidence schema in `docs/TEST-ARCHITECTURE.md` (QK-REQ-ASR-008).
- Known confounders: specimen-to-specimen variation; wear effects confounded with firmware behavior; interface-visible state not reflecting internal storage condition.
- Controls: sacrificial card specimens only — specimens driven to end of life are consumed; an unexercised matched specimen as baseline control; no power-cut apparatus in this experiment (interruption behavior is QK-F2E-005).
- Inconclusive handling: recorded verbatim as inconclusive; any repeat requires a new registered run entry.
- H3 prerequisite: run registration requires a future owner-authorized commit (H3); NOT GRANTED.
- Claim (potential subject only): candidate-card lifecycle and endurance behavior over the exercised cycles only; exercised-cycle behavior never bounds unexercised lifetimes.
- Fact: NONE — NOT RUN
- Inference: NONE — NOT RUN
- Decision input: NONE — NOT RUN
- Status: PROTOCOL TEMPLATE — RUN REGISTRATION PENDING — NOT RUN

---

### QK-F2E-015 — Animated signed-PSBT QR egress feasibility

- Question: Can a candidate display and rendering path present an animated BBQr sequence carrying a signed PSBT such that an independent receiver reassembles it, using only future owner-authorized public synthetic no-funds data?
- Links: QK-THR-006; QK-REQ-TRN-007; related planned context: QK-TST-DIFF-004 (export-route interop); the applicable `QK-LIM-QR` rows are governed by OD-05; gate context: egress complement to the ingress experiment QK-F2E-006; Gate A preparation only, not Gate A evidence; no gate closes.
- Owner decision this may inform (never resolve): OD-05; also a future owner hardware selection for which no numbered decision exists yet.
- Specimen: OPEN — SPECIMEN NOT IDENTIFIED
- Apparatus: OPEN — SPECIMEN NOT IDENTIFIED
- Procedure outline: render animated BBQr sequences carrying public synthetic no-funds signed-PSBT data on a candidate display path; capture with an independent receiver implementation not derived from the renderer; record per-frame readability and end-to-end reassembly outcomes; encoding parameters, frame counts and rates, payload ceilings, display identity, receiver identity, and acceptance thresholds all remain OPEN until run registration under H3.
- Repetition plan: OPEN — NOT DEFINED UNTIL RUN REGISTRATION
- Calibration plan: OPEN — NOT DEFINED UNTIL RUN REGISTRATION
- Exclusion criteria: OPEN — NOT DEFINED UNTIL RUN REGISTRATION
- Stopping rule: OPEN — NOT DEFINED UNTIL RUN REGISTRATION
- Analysis plan: OPEN — NOT DEFINED UNTIL RUN REGISTRATION
- Raw-evidence and hashing plan: rendered source sequences, capture streams, receiver outputs, and per-frame logs stored at a recorded location with cryptographic hashes, per the evidence schema in `docs/TEST-ARCHITECTURE.md` (QK-REQ-ASR-008).
- Known confounders: display refresh and persistence characteristics; receiver camera quality independent of the rendering under test; encoder/receiver implementation identity; ambient conditions.
- Controls: public synthetic no-funds, non-mnemonic, non-custody data only, created solely for the registered bench run; independent receiver implementation as the interoperability control; static single-frame render as baseline control; no power-cut apparatus in this experiment.
- Inconclusive handling: recorded verbatim as inconclusive; any repeat requires a new registered run entry.
- H3 prerequisite: run registration requires a future owner-authorized commit (H3); NOT GRANTED.
- Claim (potential subject only): whether a candidate display/rendering direction is worth continuing to evaluate for animated signed-PSBT egress, at the tested configurations only.
- Fact: NONE — NOT RUN
- Inference: NONE — NOT RUN
- Decision input: NONE — NOT RUN
- Status: PROTOCOL TEMPLATE — RUN REGISTRATION PENDING — NOT RUN
