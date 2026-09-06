# QuietKey F8 card-observation tool

HOST BENCH ONLY - FIXED ROW-GATED IDENTITY AND APPLET SITTINGS - NO GATE CLAIM

This ring-fenced tool implements QK-DEC-147, QK-DEC-153-SUP-002 and the
software-only preparation authorized by QK-DEC-165 and QK-DEC-165-SUP-001. The completed
`QK-F8-ENROLL-EMPTY-V1` path can enumerate PC/SC reader names, connect to one
exactly selected reader in exclusive mode, explicitly reset one inserted
specimen, capture its exact ATR and negotiated protocol, and disconnect without
an APDU. The separate `QK-F8-IDENT-V2` path checks the registered ATR and T=1,
then performs only one private literal SELECT and two private literal reads in
fixed order. It has no caller-supplied APDU, raw card, passthrough or control
surface. The sitting path contains the two compiled, registered B4/B5 plans
and the separate four-command management observation below; it does not add
a generic card-command surface.

The historical modes write a canonical `QK-CARD-ENROLLMENT-V1` or
`QK-CARD-IDENTITY-V2` transcript to standard output and never open an output
file. The identity transcript retains its frozen tool-version value `0.0.3`
and the existing sitting transcripts retain `0.0.4`, even though the package
is now `0.0.5`. The Owner redirects historical-mode
output into the durable private custody bundle.
`docs/f8/IDENTITY-MANIFEST.md` later records each transcript's exact byte count
and SHA-256, source commit, timestamp, aliases, custody path and counts; ATR
bytes are public while FCI, Card Data, CPLC and complete raw transcripts remain
private.

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

The new-session order is `J3R180-02`, `J3R180-03` only after 02 passes, then
protected `J3R180-01` only after both prior sessions pass. A non-PASS outcome
stops the sequence. The command accepts no APDU bytes; its only transmissions
are fixed `00 A4 04 00 00`, then after exact validation `80 CA 00 66 00`, then
after exact validation `80 CA 9F 7F 00`. All sessions remain stopped until the
V2 row, code, and checks receive the required review.

## Fixed sitting modes

The package contains two version-1 plans registered as
`tests/fixtures/sitting_install_v1.tsv` and
`tests/fixtures/sitting_provision_v1.tsv`. Their indexed command/response pairs
were produced by two separately implemented constructors and agree
byte-for-byte. Both derive only from the permanently-never-fund public GOLDEN
fixture at `host/qk-card-protocol/tests/fixtures/card_protocol_v1.txt` (17,919
bytes, 94 LF, SHA-256
`5019c642ec61c1042043c0b325658e06d54bbcd3648c2e168b742e9af139bbe4`, Git
blob `a43001772504ca62180893958d6c23a28be51430`).

The exact command form is:

```sh
cargo run --manifest-path bench/card-enrollment/Cargo.toml --locked --offline -- \
  sitting <install-info|provision-golden> \
  17f3b26acc97930d94d5acec9d3b4dd83dcda31a \
  <YYYY-MM-DDTHH:MM:SSZ> iMac SCR3310-01 J3R180-02 \
  4964656e7469766520534352333378782076322e302055534220534320526561646572 \
  <absolute-new-output>
```

The 40-hex argument is the fixed CAP campaign source: Row A helper commit
`17f3b26acc97930d94d5acec9d3b4dd83dcda31a`. It is not a claim about the
sitting-tool executable's source; the physical sitting record separately binds
the published Lane B tool revision. The plans also bind the canonical
49,313-byte CAP with SHA-256
`b20ba762d4c5b6c92f8f121980b425b295dcb2c2d3e4cad2a3b405be4efbb52f` and
the nine applet sources at
`7e3407f8607f580f5f9df29ae28428d894b483f2`.

The output must be an absent absolute path whose basename is exactly
`qk-card-sitting-v1__<mode>__J3R180-02__<utc>.txt`. The tool creates it with
mode 0600 before any PC/SC action and never overwrites an existing path. It
flushes the `QK-CARD-SITTING-V1` header, each event, every request before its
single transmission, every received response before comparison, and each PASS
before the next exchange. The transcript preserves the first failure, records
disconnect separately, and is capped at 32,768 bytes.

`install-info` performs exactly three exchanges: applet SELECT, Setup OPEN with
the fixed `a1` session, and unprovisioned INFO. `provision-golden` performs the
nine fixed GOLDEN provisioning exchanges through COMMIT, then eight fixed
Setup readback exchanges under the `b2` session. Neither plan contains SIGN.
Requests are capped at 221 bytes, responses are captured in 258 bytes, and a
returned response above 218 bytes is recorded before rejection. The command
accepts no caller-provided command bytes, fixture path, CAP, profile, record,
session identifier, or retry choice.

The model and transcript tests are offline and do not contact a card. Running
either sitting mode against hardware remains subject to its own Owner sitting
row.

## Management observation (Lane 3)

QK-DEC-165-SUP-001 fixes the third sitting mode, `management-observe`. Its
implementation and tests contact no card. One J3R180-02 observation sitting
becomes available only after publication and Owner/LOA approval of this code;
no other specimen or later operation is authorized by that sitting.

```sh
cargo run --manifest-path bench/card-enrollment/Cargo.toml --locked --offline -- \
  sitting management-observe <40-lowercase-hex-published-tool-source-commit> \
  <YYYY-MM-DDTHH:MM:SSZ> iMac SCR3310-01 J3R180-02 \
  4964656e7469766520534352333378782076322e302055534220534320526561646572 \
  <absolute-new-output>
```

The required basename is
`qk-card-sitting-v1__management-observe__J3R180-02__<utc>.txt`. The supplied
source is the published **tool** revision, recorded separately from the fixed
CAP campaign source. It is Owner-asserted provenance, not binary attestation.
The tool creates its private output with create-new/no-overwrite and mode 0600
before context establishment; the existing exclusive-connect, reset, exact
reader/ATR/T=1 gates and LeaveCard cleanup remain.

The only APDUs are, once each and in this order:

1. SelectIsd: `00a4040008a00000015100000000`.
2. CardRecognition: `80ca006600`.
3. InitializeUpdate: `8050000008514b46384233563100`.
4. KeyInformation: `80ca00e000`.

The fixed public challenge is ASCII `QKF8B3V1`. No key, cryptogram verification,
session-key derivation, EXTERNAL AUTHENTICATE or gp.jar operation is used.
`66` precedes INITIALIZE UPDATE and E0 because it is the only GET DATA already
observed unauthenticated on this specimen; the SCP observation is retained even
if E0 is refused. PASS means exactly four transmit calls and four returned
responses, plus LeaveCard. The first failure stops all remaining APDUs; there
is no continuation, correction, resize/resend, reconnect or retry.

Responses are captured in 258 bytes, recorded and flushed before validation.
The precedence is capture/length availability, `9000`, then the row's shape
gate: canonical outer `6F`, outer `66` with first nested `73`, the fixed SCP
response layouts, and canonical outer `E0`. E0 contents are deliberately
opaque to the engine and must be interpreted from the private retained bytes
before any rotation proposal. No captured specimen response is a comparison
fixture. The old applet sitting plans retain their 218-byte response bound.

`QK-CARD-MANAGEMENT-OBSERVATION-V1` is an ASCII/LF, 32,768-byte capped private
transcript. Every line flushes; a write/flush failure latches the writer closed
and terminates the sitting. It records the named phase, raw request/response,
counts, first failure, disconnect, and result. INIT fields are card-reported
selection, not completed authentication. SCP01/02 have no response i field;
only SCP03 supplies one. The earlier SCP02 i=55 is advertised recognition data,
not a reason to assume SCP03 or AES.

Negotiated SCP version and key type/length may be published with the permitted
evidence identity. Key version numbers, identifiers, E0, FCI, recognition data
and the INITIALIZE UPDATE body remain private. The live command returns only
status/named errors to the console, never raw observations. No rotation,
provisioning, load, further build or Gate claim follows from PASS.
