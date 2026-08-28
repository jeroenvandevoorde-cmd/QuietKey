# F8-G0 Seven-Assertion Future Run Register

EXPERIMENTAL - REGISTRATION DESIGNS ONLY - ALL RUNS BLOCKED AND NOT RUN

## Common binding and evidence contract

The seven packets below map exactly one-to-one to QK-TST-BENCH-002 `(a)`
through `(g)`. They are complete future-design packets, not executable run
instances. Exact specimen aliases, apparatus aliases, repetitions,
calibration values, fixture-generation transcript hashes, dates, operators,
raw locations and execution authority remain `OWNER INPUT REQUIRED`; no
agent may invent them. A later row must bind every such value before a run.

Every packet has these common controls:

- only enrolled J3R180 specimens and registered apparatus; results bind to
  that delivered revision/batch and never transfer to J2R180;
- raw photographs, APDU/media traces, timing series and power traces outside
  Git, with committed manifests carrying deterministic names, byte counts,
  lowercase SHA-256 values, aliases, source commit and custody;
- public, synthetic, permanently NEVER-FUND fixtures only; signing/provisioning
  authorities are generated outside Git under a later QK-DEC-047-compliant
  procedure, and management material and secret bytes never enter Git or
  traces;
- exact deviations and inconclusive results recorded without trimming or
  adaptive repetition; unexpected identity, state, status, command or
  response stops the run;
- one claim per evidence record under the existing evidence schema; no run
  selects a card, resolves OD-02, changes QK-TST status or changes a Gate.
- one required role-B card only; an optional byte-equivalent spare is a
  setup-only case, Card C and general two-card flows are prohibited, and a
  replacement card belongs to a separately bound Kit-Restore run;
- card traces do not establish original-card possession or destruction,
  absence of another live card, Kit-envelope integrity, or coordinator UTXO
  completeness; those remain external human or coordinator facts.

Deterministic raw names use
`f8-<run-id>__<specimen-alias>__<utc>__<artifact-kind>.<ext>`. The committed
mock checker uses
`qk-card-trace-v1__<run-id>__<specimen-alias>__<utc>.txt` only for `MOCK-`
aliases. The later live-run registration must freeze its own envelope and
allowed artifact-kind vocabulary and record the hash toolchain; F8-G0
chooses no live format or evidence-tool default.

## QK-F8R-A-001 - assertion (a), signing correctness and performance

- Alignment: QK-TST-BENCH-002(a); QK-F2E-004; Core Architecture v2.
- Question: on the delivered card/applet, are raw 32-byte-digest secp256k1
  ECDSA results mathematically valid, strict DER and low-S, and what complete
  latency series is observed?
- Procedure design: externally create registered public expected keys and
  digests; exercise private-key import and separately capability-only native
  key generation if supported; request signatures; verify every result with
  the pinned HOST verification boundary; record DER/low-S classification,
  public-key match, nonce observations and raw per-operation timing. Byte
  equality is not an oracle unless a separately documented deterministic
  nonce construction is under test.
- Calibration/control: reader/host overhead series; independent signature
  verification; cold/warm state recorded separately.
- Required later bindings: specimen/apparatus aliases, applet binary/source
  hashes, fixture procedure, operation/repetition counts, timing method,
  exclusion and stopping rules, analysis and raw custody.
- Acceptance record: one result per signature plus complete timing series;
  unsupported curve/import/keygen/digest/DER behavior is recorded, not
  substituted.
- Status: `BLOCKED - APPLET/MUTATION/RUN AUTHORITY REQUIRED - NOT RUN`.

## QK-F8R-B-001 - assertion (b), least-authority derivation

- Alignment: QK-TST-BENCH-002(b); QK-F2E-011; Core Architecture v2.
- Question: does the delivered implementation store only the BIP48 account
  xprv/chain/origin boundary, return the matching account xpub, derive only
  non-hardened branch `{0,1}` and bounded index children, and refuse every
  presented out-of-profile route?
- Procedure design: provision an externally generated run-only account
  authority; compare account xpub and child public keys to frozen HOST
  recomputation; include branches 0 and 1, indices 0, 1 and 65535, hardened
  and above-boundary requests, wrong origin/network/wallet bindings and raw
  timing. No BIP39, PBKDF2 or root-key operation is credited.
- Calibration/control: independently computed public oracles; unchanged
  request replay; reader-overhead series.
- Required later bindings: exact fixtures kept outside Git, specimen/apparatus
  aliases, repetition counts, route matrix, APDU registration, analysis,
  stops and raw custody.
- Acceptance record: exact public-key/origin verdict and timing for every
  registered route, including named rejections.
- Status: `BLOCKED - APPLET/PROVISIONING/RUN AUTHORITY REQUIRED - NOT RUN`.

## QK-F8R-C-001 - assertion (c), on-card RNG characterization

- Alignment: QK-TST-BENCH-002(c); QK-F2E-012; Core Architecture v2.
- Question: what RNG primitive/API, sample behavior, throughput, health
  indications and signing-nonce relationship are documented and observed on
  the delivered card/applet?
- Procedure design: record delivered documentation claims separately from
  observation; acquire the preregistered raw sample and signature sets;
  record throughput, errors and health indications; run frozen
  characterization procedures; compare repeated-message signatures without
  claiming that statistical testing proves entropy or nonce quality.
- Calibration/control: capture-path baseline and frozen deterministic
  characterization fixtures; card-internal post-processing remains a stated
  limitation.
- Required later bindings: APIs, sample/repetition counts, tools and versions,
  statistical procedures/thresholds, specimen/apparatus, stops and custody.
- Acceptance record: raw-hash-linked samples, exact tool outputs and bounded
  observations; API presence alone earns no positive result.
- Status: `BLOCKED - APPLET/RNG/RUN AUTHORITY REQUIRED - NOT RUN`.

## QK-F8R-D-001 - assertion (d), APDU and transport behavior

- Alignment: QK-TST-BENCH-002(d); QK-F2E-003; Core Architecture v2.
- Question: what ATR, ISO-7816/T=1 negotiation, voltage, frame/APDU behavior,
  reset/session behavior, byte layouts, timing and commodity-CCID
  reachability are observed on the delivered specimen?
- Procedure design: enroll card and apparatus; first capture reset/ATR and
  negotiation; only after a later nonempty allowlist registration issue each
  exact approved identity/status command in order; record request/response
  bytes outside Git, statuses and raw timing. Any unlisted command or
  unexpected identity/state/status stops. J3R180's contactless interface
  remains a condition; no contactless bearer operation is performed.
- Calibration/control: known reader baseline, repeated reset baseline,
  second registered commodity reader if later bound, and checker validation
  of canonical trace envelopes.
- Required later bindings: exact allowlist, reader/host/PCSC/tool identities,
  voltage and timing apparatus, repetitions, expected statuses, stops,
  analysis and custody.
- Acceptance record: complete raw-hash-linked trace inventory and bounded
  observations only; no APDU/product ceiling is selected.
- Status: `BLOCKED - EMPTY APDU ALLOWLIST AND RUN AUTHORITY REQUIRED - NOT RUN`.

## QK-F8R-E-001 - assertion (e), write atomicity and power cuts

- Alignment: QK-TST-BENCH-002(e); QK-F2E-005; QK-TST-PWR-002; Core
  Architecture v2.
- Question: at every registered interruption point, is post-restart state
  exactly an allowed pre-commit or committed state rather than an ambiguous
  third state?
- Procedure design: on assigned sacrificial specimens, exercise the later
  ratified `BEGIN/DATA/COMMIT/ABORT` lifecycle and interrupt through a frozen
  systematic grid; after each restart read state only through registered
  commands; retain complete trigger, voltage and response traces. Untested
  points support no claim.
- Calibration/control: uninterrupted matched-specimen baseline; switching
  latency/residual-power characterization; fixed pre/post state oracles.
- Required later bindings: sacrificial aliases, exact applet/protocol,
  injection points/repetitions, apparatus/calibration, state oracle,
  consumption rules, stops, analysis and custody.
- Acceptance record: one exact post-state record per injection with coverage
  enumerated; any third/unclear state stops and remains recorded.
- Status: `BLOCKED - MUTATION/POWER-CUT/RUN AUTHORITY REQUIRED - NOT RUN`.

## QK-F8R-F-001 - assertion (f), storage endurance

- Alignment: QK-TST-BENCH-002(f); QK-F2E-014; Core Architecture v2.
- Question: across the registered cycles, what NVM/write amplification,
  transaction-buffer wear, retention basis, degradation indicators and
  irreversible behavior are observed for the delivered revision/app?
- Procedure design: preserve one matched baseline; drive registered repeated
  lifecycle/storage operations on assigned sacrificial cards; record every
  cycle, interface-visible state, timing, errors and wear indication; never
  extrapolate exercised cycles to an untested lifetime.
- Calibration/control: unexercised matched specimen, initial full readback,
  fixed per-cycle operation definition and apparatus baseline.
- Required later bindings: destructive specimen allocation, exact writes,
  cycle/repetition/stopping counts, write-amplification method, environment,
  manufacturer retention source, analysis and custody.
- Acceptance record: full per-cycle series and final state for every
  specimen, including consumed or inconclusive outcomes.
- Status: `BLOCKED - ENDURANCE/MUTATION/RUN AUTHORITY REQUIRED - NOT RUN`.

## QK-F8R-G-001 - assertion (g), B payload and setup-spare lifecycle

- Alignment: QK-TST-BENCH-002(g); QK-F2E-013 as a superseded historical
  predecessor only; Core Architecture v2 and QK-DEC-121.
- Question: does the required role-B card carry only the ratified signer-B,
  A2, D and binding payload; does any optional spare created during original
  setup carry the same payload byte-for-byte; and are Card-C and post-setup
  second-card paths absent or rejected?
- Procedure design: generate one run-only B account authority outside Git,
  one patterned public A2, and one exact descriptor pair/wallet ID; provision
  the required B; if the bound run includes a setup spare, provision it only
  in that setup and compare complete public readback and behavior for byte
  equivalence; exercise valid routes and rejected wrong-role, mixed-wallet,
  wrong-path/policy, precommit and post-setup second-card requests; probe
  every documented normal-operation read path for signer-private bytes.
  Exhaustive hidden-interface extraction remains QK-TST-BENCH-005.
- Calibration/control: separately computed public values, byte equality for
  any setup spare, two-wallet substitution matrix and pre/post readback.
- Required later bindings: exact primary and, if exercised, setup-spare
  specimens; applet/protocol; QK-DEC-047 fixture procedure; case/repetition
  matrix; expected named results; stops; analysis; and raw custody. A
  replacement-card test requires a separate Kit-Restore registration and
  the user's external possession confirmation.
- Acceptance record: case-by-case B payload, optional-spare equivalence,
  binding, path, lifecycle and prohibited-interface results with trace
  hashes and no secret-bearing committed bytes.
- Status: `BLOCKED - APPLET/PROVISIONING/MUTATION/RUN AUTHORITY REQUIRED - NOT RUN`.

## Completeness statement

The registered assertion keys are exactly `(a),(b),(c),(d),(e),(f),(g)` once
each. Every run is `NOT RUN`; the specimen and apparatus ledgers are empty;
the live APDU allowlist is empty; and no evidence row exists from F8-G0.
