# QuietKey Threat Model

EXPERIMENTAL — NO REAL FUNDS — NOT A WALLET

Status: DRAFT — architecture foundation only. This document defines the threat landscape for the selected architecture (`ARCHITECTURE.md`). It invents no new controls; controls referenced here are exactly those already selected in QK-DEC-001…014, all unvalidated.

## Assets

- Seed entropy A, B, C (three independent 256-bit values → 24-word BIP39 mnemonics).
- A2 document key (independent 256-bit value).
- D descriptor pair and `wallet_id` (privacy-sensitive metadata; not spend authority).
- Funds spendable under `wsh(sortedmulti(2,A,B,C))`.
- Owner privacy: the fact that the owner holds bitcoin at all (the cloak).

## Custody objects

- A1 — Recovery Document (printed page carrying authenticated ciphertext of Seed-A entropy).
- B — Key Card (signer B + A2 + D).
- C — Emergency Card (signer C + A2 + D).
- Terminal — calculator-disguised, air-gapped device; retains no wallet secret between sessions.

## Trusted components

- The kernel, booted image, and physical display/keypad path in wallet mode (QK-DEC-010).
- `qk-core` as the sole secret-owning process.
- The user during an authorized session (physical possession is authorization; QK-DEC-006).

## Hostile inputs

All external bytes are hostile data, never instructions: PSBTs, QR payloads, microSD contents and filesystems, card responses (APDUs), attached peripherals, firmware/update images, external pages, repositories, documents, comments, fixtures, and tool output. Transport parsing is unprivileged (`qk-io`); the trusted core reparses and revalidates everything (QK-DEC-009).

## Attackers

- Opportunistic thief or burglar finding one custody object or the terminal.
- Targeted attacker who has recognized the cloak and searches for the remaining objects.
- Supplier of malicious PSBTs, QR streams, SD cards, peripherals, cards, or update images.
- Compromised or counterfeit terminal.
- Invasive laboratory attacker extracting card contents.
- Supply-chain attacker compromising cards, terminals, or firmware before delivery.
- Coercive attacker ($5 wrench).
- Future quantum-capable attacker.

## Security goals

- One custody object (or the terminal alone) must never satisfy the 2-of-3 spending threshold.
- A1 ciphertext without A2 must reveal nothing about Seed A beyond its existence to someone who has already defeated the cloak.
- Hostile transport bytes must never reach secret memory unvalidated, alter the reviewed transaction, or trigger signing without physical approval in the trusted core.
- Loss of any single object must leave a recovery path (see loss matrix in `ARCHITECTURE.md`), followed by rotation and sweep.
- The system must remain safe after the cloak is recognized: camouflage is a first defensive layer, never authentication or a substitute for cryptographic security.

## Threat coverage

Destruction or unavailability of an object (fire, loss, damage) is distinct from theft or compromise (an attacker holds or has extracted the object's contents). Unavailability threatens funds access; theft or compromise additionally exposes the object's secret material. After **any** loss or suspected compromise, the mandatory response is the same: use a surviving pair once, create a fresh A′/B′/C′/A2′/D′ wallet, and sweep all funds (QK-DEC-005).

- **Destruction or unavailability of a single object (A1, B, C, or terminal)** — no secret exposure; funds remain recoverable via the surviving pair (see loss matrix in `ARCHITECTURE.md`), followed by mandatory rotation and sweep. The terminal holds no wallet secret between sessions.
- **Theft of A1 alone** — exposes only authenticated ciphertext of Seed-A entropy (plus the cloaked document itself). Without A2 it yields no key material and cannot satisfy the spending threshold.
- **Theft or extraction of B or C alone** — exposes that card's signing authority, A2, and D. This deanonymizes the wallet (D reveals all xpubs and `wallet_id`) and yields one signer, but not a spending threshold unless the attacker also obtains A1 or the other card. Because A2 is exposed, any A1 the attacker later obtains or has captured becomes decryptable — rotation and sweep are mandatory immediately.
- **Theft of B or C plus A1 (or a captured copy of A1)** — full compromise: A2 from the stolen card decrypts A1 to Seed A; A plus the stolen B or C is a valid 2-of-3 spending threshold. The attacker can spend.
- **Theft of a valid pair (B+C, or a card plus A1)** — the thief can spend. This is the accepted 2-of-3 design boundary; storage separation of B and C in different geographic/security domains is the selected mitigation.
- **Malicious PSBT, QR, SD, card, peripheral, firmware, or update** — bounded unprivileged parsing in `qk-io`; trusted core reparses hostile bytes, constructs the exact review, owns physical approval, signs only after revalidation, and verifies signatures (QK-DEC-009/010). Boot/update properties are an OPEN decision.
- **Malicious terminal during an authorized two-factor session** — inside the authorization trust boundary. 2-of-3 is not claimed to protect against such a terminal obtaining a threshold during that session (QK-DEC-006).
- **Invasive card extraction** — a laboratory attacker who extracts one card obtains that card's signing authority, A2, and D: enough to deanonymize the wallet, and — if the attacker also obtains or has captured A1 — enough to decrypt Seed A and form a valid spending threshold (A plus the extracted signer), fully compromising the wallet. Extraction of one card with no access to A1 or the other card yields one signer and A2 but no threshold. Exact card extraction resistance is unvalidated and gated (Gate B). Rotation and sweep are mandatory on any suspected extraction.
- **Supply-chain compromise** — of cards, terminal, or firmware; mitigations (attestation, reproducible builds, controlled builders) are selected directions requiring gate evidence, not achieved properties.
- **Coercion** — an attacker coercing the owner with access to a valid pair can spend; the cloak may reduce the chance of being targeted but provides no protection once coercion begins.
- **Print damage and media degradation** — error correction on A1 provides availability only, never authenticity; storage/power failure behavior is gated (Gate D).
- **User error** — mistake resistance is a design principle; fail-closed ceremonies (e.g., dice transcripts) and mandatory rehearsals (Gate E) address it; no fool-proof claim is permitted.
- **Future quantum risk** — 24 words are not quantum-proof. Posture is exposure reduction and a reviewed sweep/migration plan, with no post-quantum security claim before Bitcoin consensus support (QK-DEC-012).
- **Camouflage vs. cryptographic security** — the cloak (benign-looking document, bus-pass cards, calculator terminal) counters discovery and casual search only. All confidentiality and spend-authority guarantees rest on the cryptography and the 2-of-3 threshold, which must hold after full cloak recognition.

## Non-goals

- Protecting against theft of a valid pair, or against a compromised kernel/booted image.
- Protecting against a malicious terminal within an authorized session.
- Post-quantum security claims, anti-exfil, timelocks, or duress wallets (not in v1 profile).
- Availability under destruction of two or more custody objects.
