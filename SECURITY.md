# Security Policy

EXPERIMENTAL — NO REAL FUNDS — NOT A WALLET

This repository is **pre-production** and **unsafe for funds**. It contains the owner-approved specification baseline, dependency-free payload-free HOST-only non-product state/policy models and tests, a non-normative PSBT review-profile draft, a dependency-free HOST-only bounded structural PSBT-v0 parser, canonical structural serializer, and bounded semantic-subset analyzer scaffold (structural signature candidates only — the analyzer performs no cryptographic verification), and a HOST-only verification-only libsecp256k1 v0.8.0 FFI boundary (five functions over a vendored pinned tree; not integrated into PSBT analysis) — no wallet product, no QuietKey signing wrapper, no callable Rust signing API, no PSBT-integrated signing path, no product signing behavior (the vendored libsecp256k1 tree and its compiled native archive contain dormant upstream signing code and symbols that qk-secp neither declares nor calls), no PSBT-integrated signature verification, no validity/signability/completeness decisions, no seed generation, no QR/SD/card integration, no target UI/runtime, and no production evidence. Do not use anything here to store, receive, or move real bitcoin.

## Never submit real secrets

Never submit real mnemonics, seed words, private keys, xprvs, A2 values, funded PSBTs, recovery pages/documents, or sensitive captures (photos, screenshots, scans of custody objects) in issues, pull requests, prompts, chat, logs, or test fixtures. Reports containing real secret material will be treated as compromised: the affected wallet must be rotated and swept.

## Vulnerability reporting

A private vulnerability-reporting channel **must be configured before any public release**. It is **not yet configured**. No reporting email or platform setting is claimed to exist or be enabled at this time.

## Open governance blockers

- Vulnerability-reporting ownership: **OPEN** — no owner or channel has been designated.
- Supported-version policy: **OPEN** — no versions exist and no support policy has been approved.

These blockers are tracked in `docs/OPEN-DECISIONS.md` and `docs/MATURITY-GATES.md`. Nothing in this repository is secure, production-ready, validated, or audited.
