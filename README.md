EXPERIMENTAL — NO REAL FUNDS — NOT A WALLET

# QuietKey

QuietKey is an in-design Bitcoin cold-custody system. The active Owner-ratified v2 profile uses a native mainnet P2WSH 2-of-2 wallet with terminal authority A, one required Key Card authority B, an A1 encrypted recovery document, and a two-envelope Recovery Kit that reconstructs the complete wallet only when both shares are combined.

The repository is migrating from the historical v1 three-authority HOST reference to Core Architecture v2 under QK-DEC-121. Downstream v1 code may remain temporarily only as frozen migration residue. It is not active product authority and receives no feature work. The eleven ordered migration slices and their exact claim boundaries are recorded in [`docs/qk2/00-core-architecture-v2.md`](docs/qk2/00-core-architecture-v2.md).

## Status

- The supreme architecture is [Core Architecture v2](docs/qk2/00-core-architecture-v2.md); [ARCHITECTURE.md](ARCHITECTURE.md) is its root authority index.
- Current Rust is bounded HOST reference and simulation work. It is not a production wallet or target implementation.
- All target and physical Gates remain open. No HOST result validates cards, camera/optics, dice-grid behavior, printing, storage power loss, secure boot, memory remanence, or complete target ceremonies.
- No real or confidential mnemonic, transcript, A2 value, private key, xprv, funded transaction, recovery page, card secret, or sensitive capture may enter this repository, prompts, logs, or fixtures.
- Narrow public fixture exceptions are permanently NEVER-FUND material whose exact provenance is recorded before use.

## V2 at a glance

- Normal route: A1+B reviewed 2-of-2 signing.
- Recovery Kit: two different-index, same-wallet shares reconstruct Seed-A entropy, Seed-B entropy, and A2.
- Kit-Spend: fully owned-input sweep to exactly one new-wallet output, with no change.
- Kit-Restore: replacement B while the old card remains physically held, or fresh-nonce A1 reprint; it signs nothing.
- Card C and every v1 A1+C or B+C route are removed.

## Governance

- [Core Architecture v2](docs/qk2/00-core-architecture-v2.md) — supreme active architecture
- [Decision Log](docs/DECISION-LOG.md) — append-only Owner decisions and migration scopes
- [Threat Model](docs/THREAT-MODEL.md) — active assets, adversaries, goals, and exclusions
- [Requirements](docs/REQUIREMENTS.md) and [Traceability](docs/TRACEABILITY.md) — normative behavior and evidence mapping
- [Maturity Gates](docs/MATURITY-GATES.md) and [Resource Budgets](docs/RESOURCE-BUDGETS.md) — open production obligations and limits
- [Source Register](docs/SOURCE-REGISTER.md) — pinned external authorities and fixture provenance
- [Agent Guardrails](AGENTS.md) — repository working rules

## Security and licensing

See [SECURITY.md](SECURITY.md) before reporting a defect or handling any test material. No public vulnerability-reporting channel or supported-version policy is configured yet. The intended project is open source, but its exact software, hardware, and documentation licenses remain Owner decisions.
