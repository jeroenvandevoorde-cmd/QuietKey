# Security Policy

EXPERIMENTAL — NO REAL FUNDS — NOT A WALLET

QuietKey is pre-production and unsafe for funds. Core Architecture v2 is ratified, but the repository is still migrating from a historical v1 HOST reference and every physical or target Gate remains open. Do not use any code, fixture, document, or generated artifact here to receive, store, approve, or move real bitcoin.

## Never submit real secrets

Never submit real mnemonics, dice transcripts, seed bytes, private keys, xprvs, A2 or Kit-R material, Kit shares, funded PSBTs, recovery pages, card secrets, manufacturer keys, release keys, or sensitive photos/screenshots/scans in issues, pull requests, prompts, chat, logs, test fixtures, or source control. Treat accidental exposure as compromise and rotate the affected wallet.

Public fixture material is allowed only under an explicit decision row. It must be reproducible, permanently NEVER-FUND, purpose-bound, screened against registered KAT and NUMS sets when required, and accompanied by complete first-commit provenance. Public known-private material is never production input.

## Active security boundary

- The v2 wallet requires terminal authority A and Key Card authority B.
- The two Recovery Kit envelopes together reconstruct a complete wallet. Either share alone is insufficient, but share secrecy is limited by Kit-R transcript entropy.
- Kit-Spend and Kit-Restore are separate, mode-locked doors. Restore signs nothing.
- Software cannot establish physical custody, copy history, card destruction, sole-card existence, seal integrity, or coordinator UTXO completeness.
- HOST results do not establish target constant-time behavior, remanence, secure boot, card atomicity, camera performance, storage power-loss safety, print durability, or ceremony usability.
- Historical v1 Card-C and 2-of-3 behavior is migration residue only and is not an active security promise.

## Vulnerability reporting

A private vulnerability-reporting channel must be configured before any public release. It is not yet configured. Do not include secret material or funded artifacts in a report.

## Open governance blockers

- Vulnerability-reporting ownership and channel: OPEN.
- Supported-version policy: OPEN; no production version exists.
- Production license and disclosure policy: OPEN.

These items remain tracked in [`docs/OPEN-DECISIONS.md`](docs/OPEN-DECISIONS.md) and [`docs/MATURITY-GATES.md`](docs/MATURITY-GATES.md). No document or HOST implementation closes them.
