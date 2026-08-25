# QuietKey Host Bootstrap Toolchain

EXPERIMENTAL — NO REAL FUNDS — NOT A WALLET

STATUS: HOST BOOTSTRAP TOOLCHAIN ONLY — NOT THE PRODUCTION TOOLCHAIN — OD-01 OPEN — NO TARGET CLAIM — NO ARM/TARGET SUPPORT CLAIMED.

## Installed host toolchain (Replit module, reversible)

- Replit module: `rust-stable` under Nix channel `stable-25_05` (the only tracked effect is the `modules = ["rust-stable"]` line in `.replit`).
- `rustc --version --verbose`:

```
rustc 1.88.0 (6b00bc388 2025-06-23)
binary: rustc
commit-hash: 6b00bc3880198600130e1cf62b8f8a93494488cc
commit-date: 2025-06-23
host: x86_64-unknown-linux-gnu
release: 1.88.0
LLVM version: 20.1.5
```

- `cargo --version`: `cargo 1.88.0 (873a06493 2025-05-10)`

## Boundaries

- HOST evidence only (x86_64 Linux container). Never TARGET evidence. Establishes no production compatibility, memory safety, security, air-gap behavior, target performance, or fitness for funds.
- This module/channel combination is a reversible host bootstrap toolchain only; it does not select the production toolchain and does not resolve OD-01.
- Workspace: `host/` only; stable Rust, edition 2021, resolver 2; all eight current workspace crates set `publish = false`; no license fields while OD-08 remains open; zero external dependencies; release overflow checks enabled and release panic strategy abort; first-party unsafe code forbidden at crate roots.
- Authorization: QK-AUTH-F3F4-001 (docs/HOST-WORK-AUTHORIZATION.md).
