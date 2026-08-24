# Security Policy

EXPERIMENTAL — NO REAL FUNDS — NOT A WALLET

This repository is **pre-production** and **unsafe for funds**. Its bounded HOST-only Rust evidence now covers structural PSBT-v0 parsing and M5 canonical serialization, M8 existing-signature verification, public BIP32/xpub and paired-descriptor foundations, descriptor ownership/change proof, recipient-script facts, D-09 review binding, M15 final-only canonical PSBT emission by inserting externally produced signatures, and M16 capability-only native-P2WSH witness finalization plus raw-transaction extraction. The only secp256k1 production calls remain the five verification/public-derivation functions exposed by qk-secp; no Rust signing function or private-key input exists.

M15 requires the retained approved review hash and current cycle token, inserts one authenticated descriptor-role signature record at a time, reparses and revalidates after each insertion, and returns bytes only when every input is threshold-complete. M16 consumes only that capability, reconstructs the native-P2WSH witnesses, reparses the finalized PSBT and extracted transaction through EOF, and computes txid/wtxid from the exact bytes. It does not generate signatures, accept arbitrary transaction bytes, broadcast, or perform media output. There is still no wallet product, seed/xprv handling, private derivation, arbitrary descriptor language, address renderer, target UI/runtime, or production evidence. Do not use anything here to store, receive, or move real bitcoin.

## Never submit real secrets

Never submit real mnemonics, seed words, private keys, xprvs, A2 values, funded PSBTs, recovery pages/documents, or sensitive captures (photos, screenshots, scans of custody objects) in issues, pull requests, prompts, chat, logs, or test fixtures. Reports containing real secret material will be treated as compromised: the affected wallet must be rotated and swept.

## Vulnerability reporting

A private vulnerability-reporting channel **must be configured before any public release**. It is **not yet configured**. No reporting email or platform setting is claimed to exist or be enabled at this time.

## Open governance blockers

- Vulnerability-reporting ownership: **OPEN** — no owner or channel has been designated.
- Supported-version policy: **OPEN** — no versions exist and no support policy has been approved.

These blockers are tracked in `docs/OPEN-DECISIONS.md` and `docs/MATURITY-GATES.md`. Nothing in this repository is secure, production-ready, validated, or audited.
