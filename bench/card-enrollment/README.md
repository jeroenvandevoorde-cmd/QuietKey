# QuietKey F8 card-enrollment tool

HOST BENCH PREPARATION ONLY - ZERO APDU COMMANDS - NO GATE CLAIM

This ring-fenced tool implements QK-DEC-147. It can enumerate PC/SC reader
names and, only after the F8 manifest prerequisites and a later execution
authorization are complete, connect to one exactly selected reader in
exclusive mode, explicitly reset one inserted specimen, capture its exact ATR
and negotiated protocol, and disconnect. It has no APDU transmit or control
surface. `QK-F8-ENROLL-EMPTY-V1` is the complete active allowlist.

The tool writes one canonical `QK-CARD-ENROLLMENT-V1` transcript to standard
output and never opens an output file. The Owner redirects that output into
the durable private custody bundle. A later repository manifest records the
transcript's exact byte count and SHA-256, source commit, timestamp, aliases,
and custody path; ATR bytes are additionally published verbatim only when the
ordered specimen enrollment is authorized and completed.

## Locked build

A fresh machine first fetches the locked registry packages with network access:

```sh
cargo fetch --manifest-path bench/card-enrollment/Cargo.toml --locked
```

Subsequent builds and tests use `--locked --offline`. They run without
`PCSC_LIB_DIR`, `PCSC_LIB_NAME`, `LIBPCSCLITE_*`, `PKG_CONFIG*`, or related
native-library override variables. On the registered macOS apparatus, the
transitive binding links the operating system's built-in PC/SC framework;
that OS component is outside the pinned four-package registry closure.

```sh
cargo build --manifest-path bench/card-enrollment/Cargo.toml --locked --offline
cargo test --manifest-path bench/card-enrollment/Cargo.toml --locked --offline
```

## Preparation-only invocations

Empty-reader enumeration is the only currently permitted physical use:

```sh
cargo run --manifest-path bench/card-enrollment/Cargo.toml --locked --offline -- \
  enumerate <40-lowercase-hex-source-commit> <YYYY-MM-DDTHH:MM:SSZ> iMac SCR3310-01
```

The enrollment form is documented for the later Owner-run procedure and must
not be invoked until the photo and private-serial manifests are complete and
the run is authorized. The selected PC/SC reader name is supplied as complete
lowercase hex so every name byte is preserved:

```sh
cargo run --manifest-path bench/card-enrollment/Cargo.toml --locked --offline -- \
  enroll <40-lowercase-hex-source-commit> <YYYY-MM-DDTHH:MM:SSZ> iMac SCR3310-01 \
  J3R180-02 <selected-reader-name-lowerhex>
```

The physical order remains `J3R180-02`, then `J3R180-03` only after the first
record is registered and reviewed, then `J3R180-01` only after two successful
procedures. No invocation changes card state beyond the expressly ratified
exclusive connection and reset observations, and no APDU can be supplied.
