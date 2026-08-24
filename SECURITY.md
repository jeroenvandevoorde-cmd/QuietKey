# Security Policy

EXPERIMENTAL — NO REAL FUNDS — NOT A WALLET

This repository is **pre-production** and **unsafe for funds**. It contains the owner-approved specification baseline, dependency-free payload-free HOST-only non-product state/policy models and tests, a non-normative PSBT review-profile draft, a dependency-free HOST-only bounded structural PSBT-v0 parser, canonical structural serializer, and bounded semantic-subset analyzer scaffold (structural signature candidates only — the analyzer performs no cryptographic verification), a HOST-only verification-only libsecp256k1 v0.8.0 FFI boundary (five functions over a vendored pinned tree), and a HOST-only M8 read-only existing-signature verification layer that integrates that boundary into PSBT analysis (a bounded BIP143 SIGHASH_ALL digest engine anchored to official public test vectors, plus a read-only analyzer entrypoint that cryptographically verifies existing partial signatures on native P2WSH canonical-multisig inputs and reports per-input verified counts and a VERIFY_AND_EXPORT_ONLY disposition as returned facts only), and a HOST-only bounded public (nonhardened) BIP32 CKDpub child-derivation foundation (private clean-room FIPS 180-4 SHA-512 and FIPS 198-1 HMAC-SHA512 modules exercised against byte-verbatim pinned NIST CAVP vectors — no FIPS or CAVP validation claim — plus a frozen three-item public surface that derives exactly one presented-index nonhardened child per call through the unchanged five-function qk-secp boundary, never incrementing, scanning, or retrying indexes — no BIP32 conformance claim) — no wallet product, no QuietKey signing wrapper, no callable Rust signing API, no PSBT-integrated signing path, no product signing behavior (the vendored libsecp256k1 tree and its compiled native archive contain dormant upstream signing code and symbols that qk-secp neither declares nor calls), no signature creation or insertion, no finalization or export, no validity/signability/exportability decisions (M8 verified statuses are reported verification facts only — no export is performed or authorized, and no S4/S7 authorization, ownership, or change check is bypassed), no seed generation, no private derivation or xprv/seed/extended-key handling, no Base58 or xpub text API, no HASH160 or key fingerprints, no derivation-path policy, no PSBT key-origin or ownership integration, no QR/SD/card integration, no target UI/runtime, and no production evidence. Do not use anything here to store, receive, or move real bitcoin.

## Never submit real secrets

Never submit real mnemonics, seed words, private keys, xprvs, A2 values, funded PSBTs, recovery pages/documents, or sensitive captures (photos, screenshots, scans of custody objects) in issues, pull requests, prompts, chat, logs, or test fixtures. Reports containing real secret material will be treated as compromised: the affected wallet must be rotated and swept.

## Vulnerability reporting

A private vulnerability-reporting channel **must be configured before any public release**. It is **not yet configured**. No reporting email or platform setting is claimed to exist or be enabled at this time.

## Open governance blockers

- Vulnerability-reporting ownership: **OPEN** — no owner or channel has been designated.
- Supported-version policy: **OPEN** — no versions exist and no support policy has been approved.

These blockers are tracked in `docs/OPEN-DECISIONS.md` and `docs/MATURITY-GATES.md`. Nothing in this repository is secure, production-ready, validated, or audited.
