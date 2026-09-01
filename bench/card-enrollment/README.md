# QuietKey F8 card-observation tool

HOST BENCH OBSERVATION ONLY - FIXED READ-ONLY IDENTITY SEQUENCE - NO GATE CLAIM

This ring-fenced tool implements QK-DEC-147 and QK-DEC-153. The completed
`QK-F8-ENROLL-EMPTY-V1` path can enumerate PC/SC reader names, connect to one
exactly selected reader in exclusive mode, explicitly reset one inserted
specimen, capture its exact ATR and negotiated protocol, and disconnect without
an APDU. The separate `QK-F8-IDENT-V1` path checks the registered ATR and T=1,
then performs only two private literal reads in fixed order. It has no caller-
supplied APDU, raw card, passthrough or control surface.

The tool writes a canonical `QK-CARD-ENROLLMENT-V1` or
`QK-CARD-IDENTITY-V1` transcript to standard output and never opens an output
file. The Owner redirects output into the durable private custody bundle. The
identity manifest later records each transcript's exact byte count and SHA-256,
source commit, timestamp, aliases, custody path and counts; ATR bytes are public
while Card Data, CPLC and complete raw transcripts remain private.

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

## Invocations

The completed enumeration form remains:

```sh
cargo run --manifest-path bench/card-enrollment/Cargo.toml --locked --offline -- \
  enumerate <40-lowercase-hex-source-commit> <YYYY-MM-DDTHH:MM:SSZ> iMac SCR3310-01
```

The completed zero-APDU enrollment form remains byte-frozen. The selected
PC/SC reader name is complete lowercase hex so every name byte is preserved:

```sh
cargo run --manifest-path bench/card-enrollment/Cargo.toml --locked --offline -- \
  enroll <40-lowercase-hex-source-commit> <YYYY-MM-DDTHH:MM:SSZ> iMac SCR3310-01 \
  J3R180-02 <selected-reader-name-lowerhex>
```

After the final identity-tool source commit is published, the Owner uses only:

```sh
cargo run --manifest-path bench/card-enrollment/Cargo.toml --locked --offline -- \
  identity <40-lowercase-hex-source-commit> <YYYY-MM-DDTHH:MM:SSZ> iMac SCR3310-01 \
  J3R180-02 <selected-reader-name-lowerhex>
```

The required order is `J3R180-02`, `J3R180-03` only after 02 passes, then
protected `J3R180-01` only after both prior sessions pass. A non-PASS outcome
stops the sequence. The command accepts no APDU bytes; its only transmissions
are fixed `80 CA 00 66 00` and, after exact validation, `80 CA 9F 7F 00`.
