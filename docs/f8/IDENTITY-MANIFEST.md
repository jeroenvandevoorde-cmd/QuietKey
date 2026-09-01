# F8 Identity-Read Evidence Manifest

EXPERIMENTAL - QK-F8-IDENT-V1 - NO IDENTITY SESSION RECORDED

## Registration boundary

QK-DEC-153 authorizes one fixed read-only identity session per enrolled
specimen, after the final tool source commit is published, in order
`J3R180-02`, `J3R180-03`, `J3R180-01`. A non-PASS result stops the sequence for
Owner disposition. This file registers no execution outcome yet and authorizes
no APDU beyond the exact `QK-F8-IDENT-V1` sequence.

The complete raw transcripts, reader and specimen serials, and every Card Data,
CPLC, request and response byte stay in durable private Owner custody. One
later Owner-directed evidence commit fills all three rows together with exact
artifact identity. The repository continues to publish ATRs verbatim but never
publishes Card Data or CPLC bytes.

## Canonical private transcript

`QK-CARD-IDENTITY-V1` is LF-terminated ASCII, at most 16,384 bytes, and carries
these fields in order:

1. transcript identifier, allowlist identifier and tool version;
2. final 40-lowercase-hex source commit and UTC timestamp;
3. host, reader and specimen aliases, then literal mode `IDENTITY`;
4. reader count, every complete reader-name byte as lowercase hex, and the
   selected reader name as lowercase hex;
5. ordered event count and every named operation/outcome;
6. negotiated protocol and complete ATR hex;
7. exact APDU request and response counts;
8. fixed exchange slots 0 and 1, each complete request and response hex or
   literal `NONE`;
9. disconnect outcome and final named result, followed by one final LF.

Every request is recorded before its transmission. A failed transmission has a
request but no invented response. Returned responses include their status bytes
without redaction, normalization or interpretation beyond the registered
grammar checks.

## Pending evidence ledger

| Required order | Specimen alias | Public ATR | Protocol | Private transcript alias | Exact byte count | SHA-256 | Tool/source commit | UTC timestamp | Private custody path | tx/rx counts | Result |
|---:|---|---|---|---|---:|---|---|---|---|---|---|
| 1 | `J3R180-02` | `3bd518ff8191fe1fc38073c821100a` | `T1` | PENDING | PENDING | PENDING | `qk-card-enrollment 0.0.2` / PENDING | PENDING | Private F8 bundle in locked storage at Owner premises | PENDING | PENDING |
| 2 | `J3R180-03` | `3bd518ff8191fe1fc38073c821100a` | `T1` | PENDING | PENDING | PENDING | `qk-card-enrollment 0.0.2` / PENDING | PENDING | Private F8 bundle in locked storage at Owner premises | PENDING | PENDING |
| 3 | `J3R180-01` | `3bd518ff8191fe1fc38073c821100a` | `T1` | PENDING | PENDING | PENDING | `qk-card-enrollment 0.0.2` / PENDING | PENDING | Private F8 bundle in locked storage at Owner premises | PENDING | PENDING |

No row may be filled from terminal recollection or normalized output. Each row
is tied to the exact retained private artifact bytes supplied by the Owner.

## Claim boundary

The observations identify only the delivered specimen, registered apparatus,
tool source and session. Matching ATR or response shape establishes no internal
revision equivalence, capability, production suitability, timing property,
mutation resistance or Gate result. No identity-read outcome becomes an applet
authority or a substitute for its separately ratified capability runs.
