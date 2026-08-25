# F8-G0 Execution-Ready Future Run Packets

DRAFT PAPERWORK - NOT ACTIVE - ALL SEVEN RUNS NOT RUN

## How these packets are used

This file turns the seven future-design registrations in `RUN-REGISTER.md`
into fillable run-instance paperwork. It does not supply physical facts,
limits, APDU bytes, fixture secrets, counts or authority. Every
`OWNER INPUT REQUIRED - NOT ACTIVE` cell must be replaced by observed,
registered or expressly Owner-ratified content in a later row and commit.

A packet is executable only when all common fields and every packet-specific
field are populated, its prerequisite decisions have landed, its exact
registration commit is named, and the Owner separately authorizes that run.
No packet executes QK-TST-BENCH-002 merely by being filled; its evidence may
later feed the canonical seven-assertion record.

## Common run-instance cover sheet - required for A through G

| Field | Required value |
|---|---|
| Run ID and assertion | Exact unique run ID and one key `(a)` through `(g)` |
| Owner execution authority | Decision row plus exact authorized commit |
| Governing versions | Core/requirements/test rows and F8 registration commit |
| Date/operator/custodian | Names or approved aliases and planned UTC window |
| Specimens | Enrolled public aliases, delivered batch/revision, assignment and pre-state |
| Apparatus | Exact reader, host, PC/SC, tool, timing and other apparatus aliases |
| Software | Applet/protocol/tool source, build and binary hashes where applicable |
| Fixtures | Public facts committed; secret-bearing generation/destruction procedure and public-result hashes outside Git |
| Case matrix | Every positive/negative case, ordering and finite repetition count |
| Run-only controls | Explicit byte/count/time ingestion controls; never product defaults or QK-LIM values |
| Calibration | Procedure, artifacts, validity window and pass/stop rule |
| Exclusions | Predeclared exclusion reasons; excluded raw artifacts remain retained and hashed |
| Stop rules | Identity/state/status/tool/deviation/inconclusive and apparatus-change stops |
| Analysis | Exact per-case computation, aggregation and no-adaptive-repeat rule |
| Raw custody | Outside-Git location, deterministic names, byte counts, SHA-256 and manifest toolchain |
| Expected outputs | Exact record schemas and category vocabulary, not an expected favorable result |
| Limitations | Delivered-batch scope and every claim the run cannot support |
| Status | Must remain `NOT RUN` until execution, then recorded without silent edits |

For every packet below, the complete common cover sheet value is currently
`OWNER INPUT REQUIRED - NOT ACTIVE`.

## Packet A - QK-F8R-A-001 / QK-TST-BENCH-002(a)

| Execution field | Required entry before activation |
|---|---|
| Exact operation surface | Imported-key ECDSA path and separately identified capability-only native-keygen path, if present; unsupported paths remain explicit |
| Digest/public oracle set | Exact public digest and expected-public-key records plus hashes |
| Secret fixture handling | Later ratified outside-Git authority generation, card loading and destruction transcript; no secret in logs/Git |
| Signature checks | Strict DER parse, mathematical verification, low-S classification and returned-public-key binding per result |
| Nonce observations | Exact observation procedure and limitation; no deterministic-byte oracle unless separately documented |
| Timing matrix | Cold/warm state, operation classes, finite repetitions, clock point and overhead calibration |
| Failure categories | Unsupported curve/import/digest/keygen, malformed/invalid/high-S result, public-key mismatch, card/tool/status/timing failure |
| Packet state | `OWNER INPUT REQUIRED - NOT ACTIVE - NOT RUN` |

## Packet B - QK-F8R-B-001 / QK-TST-BENCH-002(b)

| Execution field | Required entry before activation |
|---|---|
| Provisioned boundary | Exact run-only BIP48 account xprv/chain/origin handling outside Git and expected account xpub hash |
| Positive routes | Exact branch/index matrix including both branches and registered boundary points |
| Negative routes | Hardened, above-boundary, wrong branch/origin/network/wallet and malformed request matrix |
| Public oracle | Frozen HOST recomputation version/input/output hashes without modifying frozen qk-bip32 |
| State checks | Pre/post account identity, lifecycle and policy binding records |
| Timing matrix | Route classes, finite repetitions, capture point and overhead calibration |
| Failure categories | Import/origin/xpub/child mismatch, unsupported route, unexpected acceptance/status/state, tool/timing failure |
| Packet state | `OWNER INPUT REQUIRED - NOT ACTIVE - NOT RUN` |

## Packet C - QK-F8R-C-001 / QK-TST-BENCH-002(c)

| Execution field | Required entry before activation |
|---|---|
| Documented primitive/API | Delivered-card source IDs/hashes and exact claim text location |
| Sample routes | Exact RNG/signature API paths, sample framing and capture method |
| Sample counts | Finite preregistered counts per route/specimen/state |
| Characterization tools | Exact source/version/binary hashes, parameters and deterministic control inputs |
| Throughput/health record | Clock point, raw status/error capture and aggregation |
| Nonce relation | Exact repeated-message/input matrix and bounded observable questions |
| Limitation statement | Statistical results may reject defects but never establish entropy or hidden construction quality |
| Failure categories | Unsupported/unavailable API, malformed/repeated/failed sample, status/tool/custody deviation, inconclusive |
| Packet state | `OWNER INPUT REQUIRED - NOT ACTIVE - NOT RUN` |

## Packet D - QK-F8R-D-001 / QK-TST-BENCH-002(d)

| Execution field | Required entry before activation |
|---|---|
| Active allowlist | Later Owner-ratified nonempty registration ID/commit; current empty list cannot activate this packet |
| Transport observations | Exact reset/ATR/negotiation apparatus, order, repetitions and expected record shapes |
| APDU sequence | Exact ordered rows, byte/mask rules, data/response lengths and statuses copied from the active allowlist |
| Reader matrix | Exact commodity CCID aliases and any separately authorized target-reader alias; no implicit pooling |
| Electrical/timing record | Voltage/timing apparatus, capture points, calibration and finite repetitions |
| Contactless condition | Delivered J3R180 radio identity recorded; zero contactless bearer operations in this packet |
| Failure categories | Identity/ATR/negotiation/sequence/length/status/state/timing/tool mismatch and any unregistered behavior |
| Packet state | `OWNER INPUT REQUIRED - EMPTY ALLOWLIST - NOT ACTIVE - NOT RUN` |

## Packet E - QK-F8R-E-001 / QK-TST-BENCH-002(e)

| Execution field | Required entry before activation |
|---|---|
| Sacrificial assignment | Exact enrolled cards authorized for mutation and consumption |
| Lifecycle protocol | Owner-ratified applet/protocol and exact pre/committed state oracles |
| Injection grid | Every operation boundary, within-operation point, ordering and finite repetitions |
| Power apparatus | Supply/switch/trigger/measurement aliases, residual-power treatment and calibration |
| Baseline | Matched uninterrupted specimen/operation matrix |
| Restart/readback | Exact delay, reset and registered read-only state-query sequence |
| Failure categories | Allowed pre-state, allowed committed state, ambiguous third state, unreadable/consumed, apparatus/tool deviation |
| Packet state | `OWNER INPUT REQUIRED - MUTATION/POWER AUTHORITY ABSENT - NOT RUN` |

## Packet F - QK-F8R-F-001 / QK-TST-BENCH-002(f)

| Execution field | Required entry before activation |
|---|---|
| Sacrificial/control set | Exact endurance specimens and unexercised matched controls |
| Write operation | Byte-exact lifecycle/storage transaction and verified write-amplification method |
| Cycle schedule | Finite cycle points, inspections, rest/environment schedule and stop count |
| Environment | Temperature/power/reader/apparatus identities and recording method |
| Retention basis | Delivered revision source IDs/hashes; no extrapolation from generic family claims |
| Per-cycle record | State, timing, error/status, degradation indication and artifact hash schema |
| Failure categories | State/data mismatch, refusal/error, timing/degradation change, unreadable/consumed, apparatus/tool deviation |
| Packet state | `OWNER INPUT REQUIRED - ENDURANCE AUTHORITY ABSENT - NOT RUN` |

## Packet G - QK-F8R-G-001 / QK-TST-BENCH-002(g)

| Execution field | Required entry before activation |
|---|---|
| Card pair/set | Exact enrolled B-role and C-role specimens running the same applet binary |
| Distinct authorities | Later ratified outside-Git generation/destruction records and expected distinct account xpub hashes |
| Shared fields | Exact patterned public A2, canonical descriptor pair D and wallet_id public hashes/bytes authorized for the run |
| Positive matrix | B/C info/readback, A2/D/wallet binding, valid branch/path and committed signing-state cases |
| Negative matrix | Duplicate/wrong role or key, mixed wallet/D/A2, wrong path/policy, precommit/retired state and prohibited export cases |
| Pre/post identity | Role/account xpub/fingerprint/D/wallet_id readback before and after every state-changing phase |
| Non-exportability scope | Every documented normal-operation read route only; hidden-interface characterization remains QK-TST-BENCH-005 |
| Failure categories | Shared/distinct/binding/path/policy/lifecycle/export/status/state/tool mismatch and inconclusive |
| Packet state | `OWNER INPUT REQUIRED - PROVISIONING/MUTATION AUTHORITY ABSENT - NOT RUN` |

## Completeness and non-activation

There are exactly seven packets, A through G, each mapped once to
QK-TST-BENCH-002. Every common cover-sheet field and packet state still
requires Owner input. The specimen/apparatus ledgers and active APDU list are
empty, so no packet is active or executable and no result exists.
