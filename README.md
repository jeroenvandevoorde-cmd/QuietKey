EXPERIMENTAL — NO REAL FUNDS — NOT A WALLET

# QuietKey

QuietKey is an in-design Bitcoin cold-custody system built around stealth, simplicity, and authenticated encryption: a 2-of-3 multisignature wallet whose custody objects are disguised as ordinary items — a printed webpage (A1 Recovery Document), two bus-pass-like bearer cards (B Key Card, C Emergency Card), and a calculator-disguised, air-gapped terminal.

**This repository contains the owner-approved specification baseline and bounded HOST-only evidence from structural PSBT-v0 parsing and M5 canonical serialization through M8 existing-signature verification, M9/M10 public BIP32 and strict mainnet-xpub decoding, M11 paired descriptor validation, M12 descriptor ownership/change proof, M13 recipient-script classification, M14 D-09 review binding, M15 final-only canonical PSBT emission by inserting externally produced signatures, and M16 capability-only native-P2WSH witness finalization and raw-transaction extraction.** The verification boundary remains the five-call qk-secp wrapper over pinned libsecp256k1; no Rust signing function or private-key input exists. qk-descriptor itself performs zero direct allocations, while each complete route inherits six bounded 165-byte allocations from the frozen qk-bip32 boundary; allocation-free production derivation remains a Gate C obligation. The separately invoked M16 Bitcoin Core v28.0 harness is outside the Cargo workspace and exercises committed public transactions only.

This is not a wallet product and is unsafe for funds. It contains no signature generation, seed/xprv handling, private derivation, arbitrary descriptor language, address rendering, arbitrary or non-native-P2WSH finalizer, broadcast, media I/O, target UI/runtime, or production evidence. M16 can consume only M15's threshold-complete capability, reparses and rechecks it, and returns one opaque finalized PSBT/raw-transaction result; it provides no signing, finalization, extraction, persistence, media-export, network, or broadcast entry from arbitrary caller bytes.

## Status

- Replit is a cloud development and host-testing environment. It is **not** QuietKey's production security boundary.
- No real seed words, A2 values, private keys, xprvs, production card secrets, funded PSBTs, recovery documents, manufacturer keys, or release-signing keys may ever enter Replit, Replit Secrets, Agent chat, logs, previews, screenshots, databases, or fixtures.
- Documentation cannot close a technical or physical gate.
- Nothing is secure, production-ready, validated, audited, fool-proof, or quantum-proof merely because this foundation exists.
- `ARCHITECTURE.md` is `OWNER-APPROVED SPECIFICATION BASELINE — IMPLEMENTATION UNVALIDATED — ALL GATES OPEN` — owner approval QK-APR-2026-08-18-001 at baseline H0 `c618407a3900657d8ce4c479c4056f859f86bec6`. QuietKey remains an unvalidated development specification; the tracked Rust is HOST-only non-product scaffold, and no product or target implementation evidence exists. Every technical gate is OPEN. QuietKey is STOP-SHIP.

## Governance documents

- [ARCHITECTURE.md](ARCHITECTURE.md) — canonical product decisions (QK-DEC-001…014), trust limitations, stop-ship gates, change control
- [AGENTS.md](AGENTS.md) — portable agent guardrails
- [SECURITY.md](SECURITY.md) — security policy and reporting status
- [replit.md](replit.md) — non-authoritative Replit working notes
- [docs/THREAT-MODEL.md](docs/THREAT-MODEL.md) — assets, attackers, goals, non-goals
- [docs/MATURITY-GATES.md](docs/MATURITY-GATES.md) — maturity levels and Gates A–E (all OPEN)
- [docs/OPEN-DECISIONS.md](docs/OPEN-DECISIONS.md) — genuinely open decisions (CANDIDATE only)
- [docs/DECISION-LOG.md](docs/DECISION-LOG.md) — decision record (historical status-at-creation rows preserved unedited; effective status is set by the appended owner-approval records, e.g. QK-APR-2026-08-18-001)
- [docs/SOURCE-REGISTER.md](docs/SOURCE-REGISTER.md) — pinned external anchors, evidence only
- [docs/BUILD-ROADMAP.md](docs/BUILD-ROADMAP.md) — milestones F0–F12

## Provenance

The retired QuietKey protocol laboratory is **not** imported here and is **not** a dependency. It is recorded in the source register as immutable legacy evidence only.

## Licensing

The intended project is open source, but its exact software, hardware, and documentation licenses await explicit project-owner approval. No license has been selected; see `docs/OPEN-DECISIONS.md`.
