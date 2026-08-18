# QuietKey Open Decisions

EXPERIMENTAL — NO REAL FUNDS — NOT A WALLET

This file records only genuinely open decisions. The fixed profiles are **not** reopened here: custody topology, Bitcoin/mainnet profile, derivation, 24-word mnemonic model, PSBT v0, BBQr type `P` QR format, and binary `.psbt` SD encoding are settled in `ARCHITECTURE.md` (pending owner approval as a whole).

Recommendations below are labeled `CANDIDATE`. A CANDIDATE is a hypothesis: never implemented, never validated. Only explicit owner approval plus a `docs/DECISION-LOG.md` entry resolves an open decision.

## OD-01 — Production toolchain

Contingent on ARMv6/target evidence. `CANDIDATE`: Rust plus a narrow pinned `libsecp256k1` C boundary, with a measured all-C fallback only if necessary. No production language has been selected.

## OD-02 — Exact card

Card model, capabilities, applet lifecycle, APDU byte layouts, optional offline attestation, and rescue implementation. No card has been selected; feasibility is Gate B.

## OD-03 — Production entropy sources

Exact hardware sources, health-check implementation, independence evidence, and proof that the release binary actually reaches the intended sources. Runtime health checks cannot prove entropy.

## OD-04 — A1 physical codec parameters

Reed–Solomon parameters, base32 alphabet, checksum, URL-like format details, font, OCR pipeline, and print/scan trial thresholds. The visual codec is explicitly not frozen (custom URL-like format, not Bech32).

## OD-05 — Transport resource ceilings and review layout

Exact PSBT, QR, and SD resource ceilings, fee warnings, filenames, filesystem choice, and transaction review layout.

## OD-06 — Boot, update, and rollback

Which boot, update, and rollback properties are achievable without mechanical redesign. Nothing about secure boot or update resilience may be assumed.

## OD-07 — Human factors and kits

Human-test thresholds, kit packaging, executor wording for inheritance, and descriptor-backup placement across kit tiers.

## OD-08 — Licensing and governance

Project licensing (the prior root MIT LICENSE was removed by owner authorization on 2026-08-18; **no license is currently selected** — software, hardware, and documentation licenses all await owner approval), maintainers, two-person review policy, vulnerability-reporting ownership and channel, release signing, supported-version policy, and audit ownership. None of these identities, emails, or policies may be invented by an agent.
