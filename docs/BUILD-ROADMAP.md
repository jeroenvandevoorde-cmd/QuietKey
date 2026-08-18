# QuietKey Build Roadmap

EXPERIMENTAL — NO REAL FUNDS — NOT A WALLET

This roadmap summarizes milestones F0–F12 without executing any of them. Each milestone lists purpose, deliverables, exclusions, exit evidence, and affected gate(s). Replit and host simulation cannot close physical gates (A, B, D, E and the physical parts of C); only exact-target evidence can. Nothing here closes a gate.

Baseline status: the F0 and F1 baselines are owner-approved at H0 `c618407a3900657d8ce4c479c4056f859f86bec6` (QK-APR-2026-08-18-001). F2 remains AUTHORIZED — PREPARATION COMPLETE — PHYSICAL/EXACT-TARGET WORK BLOCKED — OVERALL INCOMPLETE. Under QK-AUTH-F3F4-001 (2026-08-18, docs/HOST-WORK-AUTHORIZATION.md): F3 is AUTHORIZED — HOST-ONLY PROFILE AND PUBLIC TEST-VECTOR PREPARATION — INCOMPLETE — NO PROFILE ACCEPTED — NO TARGET EVIDENCE; F4 is AUTHORIZED — HOST-ONLY INTERFACE AND STATE-MACHINE SCAFFOLD — INCOMPLETE — NO TARGET CLAIM; functional F4 modules remain contingent on accepted corresponding F3 profiles. F5–F12 remain NOT AUTHORIZED. Gates A–E remain OPEN; OD-01…08 remain unresolved; host work is HOST evidence only and never TARGET evidence.

## F0 — Foundation and governance

- **Purpose:** One clean, reviewable source of truth before any code exists.
- **Deliverables:** Governance/architecture documents, guardrails, verification script.
- **Exclusions:** Any application, cryptographic, simulator, or fixture code; dependencies; language selection.
- **Exit evidence:** `tools/verify-foundation.sh` passes; owner review of the foundation.
- **Affected gate:** None closed; establishes the gate framework.

## F1 — Requirements, threat model, limits, and test traceability

- **Purpose:** Turn the architecture into numbered, testable requirements.
- **Deliverables:** Requirement register with IDs, refined threat model mapping, explicit limits, requirement→test traceability skeleton.
- **Exclusions:** Implementation of any kind.
- **Exit evidence:** Owner-reviewed requirement set; every requirement traceable to a planned test.
- **Affected gate:** Precondition for all gates; closes none.

## F2 — Toolchain plus early exact-target card, QR, SD, and power feasibility

- **Purpose:** Resolve OD-01/OD-02 inputs with real hardware evidence before committing.
- **Deliverables:** Toolchain decision proposal (ARMv6 evidence), exact-card feasibility trials, camera/QR frame-rate trials, SD electrical and power-loss probes.
- **Exclusions:** Wallet logic; production code.
- **Exit evidence:** Recorded target measurements; owner decisions logged in the decision log.
- **Affected gate:** Feeds Gates A, B, D (none close).

## F3 — Normative profiles and independent vectors

- **Purpose:** Freeze byte-exact normative specifications.
- **Deliverables:** Normative profiles for A1 capsule, descriptors, `wallet_id`, transport; independently generated test vectors.
- **Exclusions:** Production implementation.
- **Exit evidence:** Vectors cross-checked by an independent implementation/tool; owner approval.
- **Affected gate:** SPEC level for Gates A, B, C inputs.

## F4 — Host simulator and trusted state-machine skeleton

- **Purpose:** Executable model of `qk-core`/`qk-io`/`qk-decoy` states on host.
- **Deliverables:** Host simulator, state-machine skeleton, proportional tests.
- **Exclusions:** Real secrets; target hardware claims.
- **Exit evidence:** HOST-TESTED state transitions against F1 requirements.
- **Affected gate:** Gate C groundwork (does not close it).

## F5 — Wallet identity, derivation, and descriptor core

- **Purpose:** Implement BIP32/BIP48 derivation, descriptor pair D, and `wallet_id` per the frozen profile.
- **Deliverables:** Reference core passing F3 vectors.
- **Exclusions:** Signing; entropy; card I/O.
- **Exit evidence:** REFERENCE-TESTED then HOST-TESTED against independent vectors.
- **Affected gate:** Gate C progress.

## F6 — Entropy and provisioning

- **Purpose:** Implement the conditioner, dice-transcript mode, and provisioning ceremony per QK-DEC-007.
- **Deliverables:** Entropy pipeline with fail-closed validation; ceremony flows.
- **Exclusions:** Claims that health checks prove entropy; production RNG conclusions.
- **Exit evidence:** Reviewed conditioner spec and vectors; HOST-TESTED ceremonies; target entropy-source evidence remains gated.
- **Affected gate:** Gate C progress; entropy release evidence stays open (OD-03).

## F7 — A1 capsule, rescue tool, and physical-codec trials

- **Purpose:** Implement the A1 AEAD capsule (QK-DEC-008) and run physical print/scan/OCR trials.
- **Deliverables:** Capsule implementation with vectors; standalone rescue tool; codec parameter trial data (OD-04).
- **Exclusions:** Freezing the visual codec without trial evidence.
- **Exit evidence:** REFERENCE/HOST-TESTED capsule; recorded target trial data.
- **Affected gate:** Gate A evidence gathering.

## F8 — Card applet, provisioning, and rescue

- **Purpose:** Implement the card applet and least-authority provisioning per QK-DEC-006 on the selected card.
- **Deliverables:** Applet, APDU layouts (OD-02 resolved), provisioning and rescue paths.
- **Exclusions:** Claims of extraction resistance without characterization.
- **Exit evidence:** TARGET-TESTED on production cards.
- **Affected gate:** Gate B.

## F9 — Bounded PSBT validation, review, and signing

- **Purpose:** Implement the trusted-core PSBT pipeline per QK-DEC-009.
- **Deliverables:** Reparse/revalidate pipeline, exact review construction, physical approval, sign-after-revalidation, signature verification.
- **Exclusions:** PSBT v2, Taproot, autodetection.
- **Exit evidence:** Adversarial corpus results; HOST-TESTED then TARGET-TESTED.
- **Affected gate:** Gate C.

## F10 — QR and SD brokers plus target trials

- **Purpose:** Implement unprivileged `qk-io` transport and prove it on fixed mechanics.
- **Deliverables:** Camera/BBQr broker, SD broker, resource ceilings (OD-05 resolved), target trials.
- **Exclusions:** Any secret or approval access in `qk-io`.
- **Exit evidence:** TARGET-TESTED capture/transfer meeting thresholds.
- **Affected gate:** Gate A.

## F11 — Appliance integration, secret lifecycle, boot/update, and reproducible builds

- **Purpose:** Integrate the appliance, verify secret erasure and power-loss behavior, establish boot/update posture (OD-06) and reproducible builds.
- **Deliverables:** Integrated image, memory-lifecycle evidence, power-loss injection results, reproducible-build pipeline on controlled builders.
- **Exclusions:** Secure-boot claims beyond measured properties.
- **Exit evidence:** TARGET-TESTED lifecycle and failure behavior; reproducible-release evidence.
- **Affected gate:** Gates C, D; release blockers.

## F12 — Complete recovery, inheritance, human factors, external audit, and release qualification

- **Purpose:** Prove the whole system with people, not just machines.
- **Deliverables:** Full recovery/inheritance rehearsals, human-factors studies against thresholds (OD-07), external audit, release qualification package.
- **Exclusions:** Closing any gate by documentation; shipping before all gates and blockers close.
- **Exit evidence:** INDEPENDENTLY-AUDITED; complete rehearsal records; owner release approval.
- **Affected gate:** Gate E and all remaining release blockers.
