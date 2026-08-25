# QuietKey Host Bootstrap Toolchain

EXPERIMENTAL — NO REAL FUNDS — NOT A WALLET

STATUS: HOST BOOTSTRAP TOOLCHAIN ONLY — NOT THE PRODUCTION TOOLCHAIN — OD-01 OPEN — NO TARGET CLAIM — NO ARM/TARGET SUPPORT CLAIMED.

## Tracked Replit bootstrap selection (reversible)

- Replit module: `rust-stable` under Nix channel `stable-25_05` (the only tracked effect is the `modules = ["rust-stable"]` line in `.replit`).
- This floating selector is not a Rust version pin. The canonical checker requires Clippy 1.98 or newer; an environment resolving the module below that floor cannot produce passing HOST evidence.

## Executed HOST toolchain snapshot (2026-08-25)

- `rustc --version --verbose`:

```
rustc 1.98.0 (88d9e12ae 2026-08-18)
binary: rustc
commit-hash: 88d9e12ae178fab0fb5cc050a94da85685d449ea
commit-date: 2026-08-18
host: x86_64-apple-darwin
release: 1.98.0
LLVM version: 22.1.8
```

- `cargo --version`: `cargo 1.98.0 (797e8a9bc 2026-08-05)`
- `rustfmt --version`: `rustfmt 1.9.0-stable (88d9e12ae1 2026-08-18)`
- `cargo clippy --version`: `clippy 0.1.98 (88d9e12ae1 2026-08-18)`
- `rustup show active-toolchain`: `stable-x86_64-apple-darwin (default)`
- This executed snapshot records the current HOST environment only; it is not a toolchain pin and does not resolve OD-01.

## Boundaries

- HOST evidence only (the executed snapshot above is x86_64 macOS; the tracked Replit selector is a separate host bootstrap). Never TARGET evidence. Establishes no production compatibility, memory safety, security, air-gap behavior, target performance, or fitness for funds.
- This module/channel combination is a reversible host bootstrap toolchain only; it does not select the production toolchain and does not resolve OD-01.
- Workspace: `host/` only; stable Rust, edition 2021, resolver 2; all nine current workspace crates set `publish = false`; no license fields while OD-08 remains open; zero external dependencies; release overflow checks enabled and release panic strategy abort; first-party unsafe code forbidden at crate roots.
- Authorization: QK-AUTH-F3F4-001 (docs/HOST-WORK-AUTHORIZATION.md).
