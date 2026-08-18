# QuietKey Architecture

**Status: DRAFT — PENDING PROJECT-OWNER APPROVAL**

EXPERIMENTAL — NO REAL FUNDS — NOT A WALLET

## Scope

This document is the single source of truth for QuietKey's selected architecture. It records decisions QK-DEC-001 through QK-DEC-014 as selected but **unvalidated**: nothing here has been validated on production hardware. Selected architecture is kept separate from evidence; evidence lives in `docs/MATURITY-GATES.md` and future gate records. Replit is a cloud development and host-testing environment, not QuietKey's production security boundary.

## Canonical product decisions

### QK-DEC-001 — Product philosophy

QuietKey's principles are stealth, simplicity, minimalism, authenticated encryption, hiding in plain sight, mistake resistance, and uncompromising robustness. Camouflage is a first defensive layer, not authentication or a substitute for cryptographic security. "Fool-proof" is not an acceptable security claim.

### QK-DEC-002 — Custody topology

QuietKey has three independently generated Bitcoin signing authorities A, B, and C. C must never be a clone of B.

The wallet policy is standard native SegWit P2WSH 2-of-3:

`wsh(sortedmulti(2,A,B,C))`

Possession of one custody object is insufficient to spend. Possession of any valid pair is sufficient.

### QK-DEC-003 — Fixed v1 Bitcoin profile

- Production network: Bitcoin mainnet only.
- Derivation: `m/48'/0'/0'/2'/{0,1}/*`.
- A, B, and C originate from separate 256-bit entropy values and map to 24-word English BIP39 mnemonics.
- The BIP39 passphrase is fixed empty. There is no passphrase feature or 12-word mode.
- D is the checksummed receive/change descriptor pair containing all three account xpubs and origin information.
- `wallet_id = SHA256(canonical_receive_descriptor || 0x00 || canonical_change_descriptor)`.
- D is stored on B and C. An additional A2-encrypted D backup may exist in the recovery kit as redundant metadata, never as another signing factor.

### QK-DEC-004 — Physical elements and cloak

- A1 — Recovery Document: an ordinary-looking printed webpage. Its visible body may be a recipe, guitar tab, travel page, or similar benign content. A source-URL-looking footer contains error-corrected, authenticated ciphertext of Seed-A entropy. The apparent URL is never followed, contacted, or resolved.
- A2 — Document key: a fresh independent 256-bit value generated during that wallet's provisioning ceremony. It decrypts A1, is copied to B and C, is never pre-installed on the terminal, and must not remain on the terminal afterward.
- B — Key Card: a bus-pass-like bearer card containing independent signer B, A2, and D.
- C — Emergency Card: a separate bearer card containing independent signer C, the same A2, and the same D. It belongs in a geographically separate recovery or inheritance kit.
- Terminal: a calculator-disguised, air-gapped, replaceable device retaining no wallet secret between sessions.

The cloak applies to all visible elements, but the security model must remain safe after the cloak is recognized.

### QK-DEC-005 — Use and recovery hierarchy

- Normal path: A1+B.
- B unavailable: A1+C.
- A1 unavailable: B+C, bypassing A.
- C unavailable: A1+B remains available.
- B and C must be stored separately, preferably in different geographic and security domains.
- After loss or suspected compromise of A1, B, or C, use a surviving pair once, create a completely fresh A′/B′/C′/A2′/D′ wallet, and sweep all funds. A missing signer cannot simply be reissued into the existing descriptor.

### QK-DEC-006 — Bearer-card and terminal model

- B and C have no PIN, remembered recovery password, terminal pairing, vendor account, phone-home requirement, or online authentication dependency. Physical possession is authorization.
- The cards use the same applet but fixed, different roles and unique signing keys.
- The logical B/C seeds are independent. The selected least-authority provisioning model stores only each BIP48 account xprv, chain code, origin data, role, A2, and D, subject to exact-card feasibility testing.
- Root mnemonic material is not retained on the terminal.
- A malicious terminal during a valid two-factor session is within the authorization trust boundary. Do not claim 2-of-3 protects against such a terminal obtaining a threshold during that session.
- The no-mechanical-redesign decision remains in force. Do not invent dimensions, components, secure-element capabilities, camera performance, card features, or boot guarantees.

### QK-DEC-007 — Entropy product profile

- A, B, C, and A2 are four independently generated 256-bit values. Never expand one common master secret into them.
- Recommended mode combines independently sampled device/card sources through a fixed, domain-separated conditioner whose exact specification and vectors must be reviewed before implementation.
- Advanced Physical mode uses exactly 100 private d6 rolls for each of A, B, C, and A2: four new transcripts, 400 rolls total. Invalid characters, incorrect counts, and transcript reuse fail closed.
- Runtime health checks cannot prove entropy. Release evidence must trace the actual linked binary to the intended hardware sources and test failure of each source.
- CloakGrid or another novel ceremony remains research until it has an entropy argument, independent verifier, human study, and attack review.

### QK-DEC-008 — A1 digital-cryptography baseline

The selected but unvalidated A1 capsule design is:

- IETF ChaCha20-Poly1305 from a reviewed implementation;
- HKDF-SHA256 with `IKM=A2`, `salt=wallet_id`, and info `QuietKey/A1/v1`;
- a fresh random stored 96-bit nonce for every new encryption;
- plaintext exactly the 32-byte Seed-A entropy;
- AAD binding fixed magic, coding version, crypto version, Bitcoin network, and full `wallet_id`;
- a full 128-bit authentication tag;
- no plaintext release before successful authentication.

The visual/OCR codec is not frozen. It will be a custom URL-like format, not Bech32. Error correction provides availability and never replaces AEAD authenticity.

### QK-DEC-009 — PSBT and transport profile

- PSBT v0 only.
- microSD input is binary `.psbt` only, with no base64/hex autodetection and no input overwrite.
- Animated QR uses uncompressed BBQr file type `P` only, subject to fixed-hardware performance testing.
- QR and SD transport parsing is unprivileged and separate from the secret-owning core.
- The trusted core reparses and validates hostile bytes, constructs the exact transaction review, owns final physical approval, signs only after revalidation, verifies signatures, and returns independently parseable output.

### QK-DEC-010 — Software trust boundary

The intended appliance has:

- `qk-core`: secret memory, cards, trusted display/keypad in wallet mode, PSBT validation, review, approval, and signing;
- `qk-io`: bounded camera/QR and SD transport only, with no secrets or card/approval access;
- `qk-decoy`: calculator only, terminated before wallet mode takes exclusive control.

The kernel, booted image, and physical display/keypad path remain trusted. Process separation does not make a compromised kernel safe.

### QK-DEC-011 — Kit tiers

Simple Recovery, Inheritance, and higher-privacy or "Quantum Shelter" kits may vary packaging, instructions, descriptor-backup separation, rehearsal material, and coordinator privacy. They must not change the wallet threshold, signing keys, derivation, card protocol, or recovery mathematics.

### QK-DEC-012 — Quantum posture

Twenty-four words do not make Bitcoin quantum-proof. QuietKey may reduce public-key exposure, offer privacy-conscious coordinator options, and maintain a tested migration plan. It must not claim post-quantum security before Bitcoin supports an appropriate consensus spend condition. A future threat change triggers a reviewed sweep/migration—not a proprietary "quantum-safe" script.

### QK-DEC-013 — Source and licensing boundary

- The previous QuietKey repository is a retired protocol laboratory, not the product base.
- Ian Coleman and SeedSigner may inform standards and workflow after pinned-source and license review.
- COLDCARD may inform clean-room requirements and adversarial tests, but its source must not be copied into this intended open-source commercial product without separate permission.
- No third-party code enters the repository until its exact commit, license, provenance, purpose, and review status are recorded.

### QK-DEC-014 — Maturity and release claims

Replit and host simulation cannot validate the air gap, exact card, RNG, camera/optics, microSD electrical behavior, memory erasure, secure boot, update resilience, or power-loss behavior.

Production releases require exact-target evidence, reproducible builds on controlled builders, external review, and complete recovery rehearsals. QuietKey remains STOP-SHIP until every required gate closes.

## A1/A2/B/C loss matrix

Per QK-DEC-005. "Spend/recover" means a valid pair remains usable; every loss row ends with one-time use of a surviving pair, creation of a fresh A′/B′/C′/A2′/D′ wallet, and a sweep of all funds.

| Lost/compromised | Spend/recover with | Notes |
|---|---|---|
| Nothing | A1+B (normal path) | A2 (on B or C) decrypts A1 to obtain Seed A |
| A1 | B+C | Bypasses A entirely; then rotate and sweep |
| A2 only (both card copies unreadable) | B+C | A1 becomes undecryptable; equivalent to losing A1; rotate and sweep |
| B | A1+C | Then rotate and sweep |
| C | A1+B | Then rotate and sweep |
| Terminal | Any valid pair on a replacement terminal | Terminal retains no wallet secret between sessions |
| Any single custody object stolen | Remaining valid pair | One object is insufficient to spend; rotate and sweep after suspected compromise |
| Any valid pair stolen | — | Thief can spend. 2-of-3 threshold is the design boundary |
| Any two of A1/B/C lost (no theft) | — | Funds unrecoverable; a missing signer cannot be reissued into the existing descriptor |

## Trust limitations

- A malicious terminal during a valid two-factor session is within the authorization trust boundary (QK-DEC-006).
- The kernel, booted image, and physical display/keypad path remain trusted; process separation does not make a compromised kernel safe (QK-DEC-010).
- Camouflage is a defensive layer only; the security model must remain safe after the cloak is recognized (QK-DEC-001, QK-DEC-004).
- Runtime health checks cannot prove entropy (QK-DEC-007).
- Replit and host simulation cannot validate physical properties (QK-DEC-014).

## Non-goals

- No PINs, passphrases, or 12-word mode.
- No PSBT v2, Taproot, UR, SeedQR, anti-exfil, or timelocks.
- No proprietary post-quantum scripts or post-quantum security claims.
- No vendor accounts, terminal pairing, phone-home, or online authentication dependency.
- No protection against a malicious terminal that obtains a threshold during an authorized two-factor session.
- No reuse of the Vault-Key, fixed-nonce, 2-of-2, XOR-share, or `0x02` protocol.

## Prohibited claims

QuietKey must never be described as secure, production-ready, validated, audited, fool-proof, or quantum-proof while any required gate is OPEN. "Fool-proof" is never an acceptable security claim. Documentation, this file included, cannot close a technical or physical gate.

## Open items

Genuinely open decisions are tracked exclusively in `docs/OPEN-DECISIONS.md` (toolchain, exact card, entropy sources, A1 physical codec parameters, transport resource ceilings, boot/update properties, human-test thresholds, licensing and governance). The fixed custody, Bitcoin, derivation, mnemonic, PSBT, QR-format, and SD-encoding profiles above are not open.

## Stop-ship gates

QuietKey is STOP-SHIP until every gate in `docs/MATURITY-GATES.md` closes: Gates A–E plus architecture-owner approval, P0/RV3 hardware conclusions, reproducible releases, vulnerability reporting, and external audit. All gates are currently OPEN. No gate closes because a document or reference implementation exists.

## Change control

- This document is authoritative over `replit.md` and any other mutable working notes.
- An agent may propose a change by recording it in `docs/OPEN-DECISIONS.md`.
- Only explicit project-owner approval **and** a new entry in `docs/DECISION-LOG.md` may change this architecture.
- No agent may mark this document owner-approved or close any technical gate.
