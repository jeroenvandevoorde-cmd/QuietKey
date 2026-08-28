# QuietKey Build Roadmap

EXPERIMENTAL — NO REAL FUNDS — NOT A WALLET

This roadmap summarizes milestones F0–F12 and the ordered v2 migration slices. Each milestone lists purpose, deliverables, exclusions, exit evidence, and affected gate(s). Replit and host simulation cannot close physical gates (A, B, D, E and the physical parts of C); only exact-target evidence can. Nothing here closes a gate.

Baseline status: QK-DEC-121 supersedes the v1 A/B/C migration basis with the v2 Single Card plus Two-Envelope Kit architecture and authorizes v2 slice 1. Completed v1 HOST milestones remain historical inputs; they do not establish v2 behavior merely because reusable primitives are retained. F2 physical work remains triggered by the camera-rig and card arrivals. Gates A–E remain OPEN; the genuinely open items are listed in `docs/OPEN-DECISIONS.md`; host work is HOST evidence only and never TARGET evidence.

## Ordered v2 migration — one reviewed slice at a time

1. Descriptor core and the public, permanently NEVER-FUND v2 GOLDEN lineage.
2. Review schema v3 and `QK-FEE-POLICY-V2`, including the 71-byte witness script and 220-byte fixed witness estimate.
3. Signing, finalization, and Bitcoin Core differential fixtures for native P2WSH 2-of-2.
4. Provisioning and Kit-R secret ownership, with no public plaintext secret surface.
5. Screen-flow topology for normal A1+B, setup, `Kit-Spend`, and `Kit-Restore`.
6. Two-key watch-only coordinator export.
7. Kit frame, XOR combine, QR, and M18 fallback codec.
8. Setup-only kit generation and two-copy print export.
9. Mode-locked kit scanner; this slice separately ratifies the terminal input method for the 228-symbol fallback.
10. `Kit-Restore` for a permitted replacement card or a fresh-nonce A1, with no signing.
11. Enforced `Kit-Spend`: all inputs owned, exactly one output to a new descriptor address, and no change.

Every slice has an exact file scope and receives Owner plus LOA verification before its successor begins. A later slice may consume only the typed facts and invariants frozen by earlier slices. No new 2-of-3 work, compatibility translation, or parallel implementation of a later slice is permitted.

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

## F2 — Toolchain plus early exact-target card, QR, print, SD, and power feasibility

- **Purpose:** Resolve OD-01/OD-02 inputs with real hardware evidence before committing.
- **Deliverables:** Toolchain decision proposal (ARMv6 evidence), exact-card feasibility trials for signer B/setup spare/replacement, camera trials for A1 and kit-share QR/fallback media, printer interruption probes, SD electrical and power-loss probes.
- **Exclusions:** Wallet logic; production code.
- **Exit evidence:** Recorded target measurements; owner decisions logged in the decision log.
- **Affected gate:** Feeds Gates A, B, D (none close).

## F3 — Normative profiles and independent vectors

- **Purpose:** Freeze byte-exact normative specifications.
- **Deliverables:** Normative profiles for the frozen A1 capsule, 2-of-2 descriptors, `wallet_id`, review schema v3, kit shares, and transports; separately generated public test vectors.
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

- **Purpose:** Implement BIP32/BIP48 derivation, the native P2WSH `wsh(sortedmulti(2,A,B))` descriptor pair D, and `wallet_id` per the frozen profile.
- **Deliverables:** Reference core passing F3 vectors.
- **Exclusions:** Signing; entropy; card I/O.
- **Exit evidence:** REFERENCE-TESTED then HOST-TESTED against independent vectors.
- **Affected gate:** Gate C progress.

## F6 — Dice input, provisioning, and kit generation

- **Purpose:** Implement the manual and gated dice-grid transcript profiles, Seed-A/Signer-B/A2 derivation, deterministic Kit-R expansion, card/A1 provisioning, and setup-only kit generation.
- **Deliverables:** Fail-closed dice validation; ceremony flows; exactly two complete kit copies by default; no post-setup share regeneration path.
- **Exclusions:** Claims that a score proves entropy, that Kit-R provides 768 bits of information-theoretic secrecy, or that software proves physical destruction, card possession, or seal integrity.
- **Exit evidence:** HOST-TESTED mathematics and ceremonies; fixed-camera dice-grid evidence, exact-target secret cleanup, print, and card behavior remain gated.
- **Affected gate:** Gate C progress; feeds Gates A, B, D, and E without closing them.

## F7 — A1 capsule, kit media, rescue tool, and physical-codec trials

- **Purpose:** Implement the A1 AEAD capsule (QK-DEC-008) and run physical print/scan/OCR trials.
- **Deliverables:** Capsule implementation with vectors; exact kit-share QR/fallback implementation; standalone rescue tool; A1 and kit-media trial data.
- **Exclusions:** Freezing the visual codec without trial evidence.
- **Exit evidence:** REFERENCE/HOST-TESTED capsule; recorded target trial data.
- **Affected gate:** Gate A evidence gathering.

## F8 — Single-card applet, provisioning, spare, and restore

- **Purpose:** Implement signer-B card behavior and least-authority provisioning on the selected card.
- **Deliverables:** Applet, APDU layouts, setup-only spare provisioning, commodity-reader rescue, and replacement-card `Kit-Restore` with original-card-possession enforcement.
- **Exclusions:** Claims of extraction resistance without characterization.
- **Exit evidence:** TARGET-TESTED on production cards.
- **Affected gate:** Gate B.

## F9 — Bounded PSBT validation, review, signing, and Kit-Spend

- **Purpose:** Implement the trusted-core PSBT pipeline per QK-DEC-009.
- **Deliverables:** Reparse/revalidate pipeline, schema-v3 review construction, physical approval, sign-after-revalidation, signature verification, and the all-inputs-owned/one-new-output/no-change `Kit-Spend` path.
- **Exclusions:** PSBT v2, Taproot, autodetection.
- **Exit evidence:** Adversarial corpus results; HOST-TESTED then TARGET-TESTED.
- **Affected gate:** Gate C.

## F10 — QR, kit scanner, print, and SD brokers plus target trials

- **Purpose:** Implement unprivileged `qk-io` transport and prove it on fixed mechanics.
- **Deliverables:** Camera/BBQr broker, mode-locked kit scanner, kit print broker, SD broker, resource ceilings, and target trials.
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
- **Deliverables:** Normal A1+B, both kit doors, sweep-only loss response, seal-check, setup-spare, cross-copy share, recovery/inheritance, and human-factors rehearsals against thresholds; external review and release qualification package.
- **Exclusions:** Closing any gate by documentation; shipping before all gates and blockers close.
- **Exit evidence:** INDEPENDENTLY-AUDITED; complete rehearsal records; owner release approval.
- **Affected gate:** Gate E and all remaining release blockers.
