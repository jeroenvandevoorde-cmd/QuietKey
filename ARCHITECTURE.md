# QuietKey Architecture

**Status: OWNER-RATIFIED V2 SPECIFICATION — IMPLEMENTATION MIGRATION IN PROGRESS — ALL PHYSICAL GATES OPEN**

EXPERIMENTAL — NO REAL FUNDS — NOT A WALLET

## Supreme authority

[`docs/qk2/00-core-architecture-v2.md`](docs/qk2/00-core-architecture-v2.md) is the supreme product and security architecture under QK-DEC-121. It supersedes Core Architecture v1 for every active product, implementation, test, bench, and Gate decision. Core Architecture v1 and its subordinate records remain immutable historical material.

Where any other document, fixture, test, or implementation conflicts with Core Architecture v2, Core Architecture v2 prevails. Only an explicit Owner decision recorded in [`docs/DECISION-LOG.md`](docs/DECISION-LOG.md) may change it. [`docs/OPEN-DECISIONS.md`](docs/OPEN-DECISIONS.md) records candidates and unresolved work; it has no authority to change the architecture.

## Active product topology

- The wallet is mainnet native P2WSH `wsh(sortedmulti(2,A,B))` at `m/48'/0'/0'/2'/{0,1}/*`.
- A is the terminal-held authority and B is the one required Key Card authority. An optional setup-time spare is byte-equivalent B authority, not a third signer.
- Normal signing is A1+B and must complete intake, proof, review, approval, revalidation, signing, finalization, and export.
- Card C, three-account descriptors, A1+C, B+C, and general two-card signing are removed from active v2 behavior.
- The universal Recovery Kit has two sealed envelopes. Together their framed shares reconstruct `Seed-A entropy[32] || Seed-B entropy[32] || A2[32]`; either envelope alone is insufficient.
- Kit-Spend is a one-output, no-change sweep from fully proven old-wallet inputs to a newly generated descriptor. Kit-Restore signs nothing and permits only a replacement B while the old card remains physically held, or an A1 reprint with a fresh nonce.
- Intentional or doubtful Kit opening requires migration to a fresh wallet. No post-setup Kit regeneration path exists.

## Retained foundations

V2 retains mainnet, BIP39 English 24-word derivation with empty passphrase, PSBT v0, the M17 A1 capsule, M18 alphabet and codec, M21 ring-fenced fuzzing, M22/M30 BBQr P/T profile, P0.1 logical keys, dice-only entropy input, and SD-only watch-only coordinator export. Exact retained behavior and every v2 change are defined by Core Architecture v2 and its ratifying rows.

## Trust and claim boundaries

- Share secrecy is computational and capped by Kit-R transcript entropy.
- Non-regeneration is a terminal lifecycle property, not a physical anti-copying claim.
- Software cannot prove complete coordinator UTXO discovery, physical card possession or destruction, absence of another live card, or envelope integrity.
- The kernel, booted image, display/keypad path, production cryptographic implementation, cards, camera, storage hardware, printing, and physical custody remain outside HOST evidence unless their exact Gate closes.
- Camouflage is a discretion layer, not authentication. A malicious terminal during an authorized threshold session remains within the authorization boundary.

## Migration control

QK-DEC-121 fixes eleven dependency-ordered migration slices. Until its slice lands, downstream v1 code may remain only as frozen migration residue and receives no new feature work. Each slice has an exact file scope and requires Owner authorization plus external verification before its successor begins. No implementation may silently restore a Card-C, 2-of-3, general-Kit-signing, or post-setup-regeneration assumption.

## Maturity

Replit and HOST simulation cannot close physical Gates. QuietKey remains STOP-SHIP until every required condition in [`docs/MATURITY-GATES.md`](docs/MATURITY-GATES.md) is met on the exact production stack. Documentation and reference code do not make QuietKey secure, production-ready, validated, fool-proof, or quantum-proof.

## Change control

- Changes require explicit Owner approval and an appended decision row.
- Historical decision rows are never rewritten; later rows supersede them explicitly.
- Sources and evidence are registered in [`docs/SOURCE-REGISTER.md`](docs/SOURCE-REGISTER.md).
- Requirements, tests, limits, and roadmap entries must trace to the active v2 authority and preserve every open physical obligation.
