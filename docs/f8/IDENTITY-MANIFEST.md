# F8 Identity-Read Evidence Manifest

EXPERIMENTAL - V1 ARTIFACT IDENTITY PENDING - V2 SESSIONS STOPPED

## Registration boundary

QK-DEC-153 authorized `QK-F8-IDENT-V1`. Its first and only session, on
`J3R180-02`, stopped on a named rejection, so V1 authorizes no further session.
QK-DEC-153-SUP-002 supersedes the unfilled V1 schedule with one fresh fixed
read-only `QK-F8-IDENT-V2` session per enrolled specimen, in order
`J3R180-02`, `J3R180-03`, `J3R180-01`. A non-PASS result stops the sequence for
Owner disposition. V2 sessions remain stopped until the row and final tool
source receive the required review. This file authorizes no command beyond the
exact V2 sequence.

The frozen `ENROLLMENT-MANIFEST.md` statement that no further card contact is
authorized closes only `QK-F8-ENROLL-EMPTY-V1`; QK-DEC-153 and its V2
supplement are the later narrow authorities for identity contacts and create
no further enrollment session.

The complete raw transcripts, reader and specimen serials, and every Card Data,
CPLC, request and response byte stay in durable private Owner custody. The V1
artifact identity is registered when its owed count and hash arrive; one later
Owner-directed V2 evidence commit fills all three V2 rows together with exact
artifact identities. The repository continues to publish ATRs verbatim but
never publishes FCI, Card Data or CPLC bytes.

## V1 stopped-session fact pending exact artifact registration

The Owner reports that at source commit
`800da1a2b6158e08195237c2523cb560a957571a`, supplied timestamp
`2026-09-01T14:00:40Z`, J3R180-02 enumeration, exclusive connection, reset,
registered ATR and T=1 capture passed; `80 CA 00 66 00` returned status `69 85`;
the tool rejected as `CardRecognitionStatusRejected`, transmitted nothing
further and disconnected cleanly. The exact retained private transcript byte
count and SHA-256 remain owed. Until supplied, this is a pending Owner fact,
not a hash-registered artifact row. It neither fills nor preserves the former
three-row V1 schedule.

## Canonical V2 private transcript

`QK-CARD-IDENTITY-V2` is LF-terminated ASCII, at most 16,384 bytes, and carries
these fields in order:

1. transcript identifier, allowlist identifier and tool version;
2. final 40-lowercase-hex source commit and UTC timestamp;
3. host, reader and specimen aliases, then literal mode `IDENTITY`;
4. reader count, every complete reader-name byte as lowercase hex, and the
   selected reader name as lowercase hex;
5. ordered event count and every named operation/outcome;
6. negotiated protocol and complete ATR hex;
7. exact APDU request and response counts;
8. fixed exchange slots 0, 1 and 2, each complete request and response hex or
   literal `NONE`;
9. disconnect outcome and final named result, followed by one final LF.

Every request is recorded before its transmission. A failed transmission has a
request but no invented response. Returned responses include their status bytes
without redaction, normalization or interpretation beyond the registered
grammar checks.

## Pending V2 evidence ledger

| Required order | Specimen alias | Public ATR | Protocol | Private transcript alias | Exact byte count | SHA-256 | Tool/source commit | UTC timestamp | Private custody path | tx/rx counts | Result |
|---:|---|---|---|---|---:|---|---|---|---|---|---|
| 1 | `J3R180-02` | `3bd518ff8191fe1fc38073c821100a` | `T1` | PENDING | PENDING | PENDING | `qk-card-enrollment 0.0.3` / PENDING | PENDING | Private F8 bundle in locked storage at Owner premises | PENDING | PENDING |
| 2 | `J3R180-03` | `3bd518ff8191fe1fc38073c821100a` | `T1` | PENDING | PENDING | PENDING | `qk-card-enrollment 0.0.3` / PENDING | PENDING | Private F8 bundle in locked storage at Owner premises | PENDING | PENDING |
| 3 | `J3R180-01` | `3bd518ff8191fe1fc38073c821100a` | `T1` | PENDING | PENDING | PENDING | `qk-card-enrollment 0.0.3` / PENDING | PENDING | Private F8 bundle in locked storage at Owner premises | PENDING | PENDING |

No row may be filled from terminal recollection or normalized output. Each row
is tied to the exact retained private artifact bytes supplied by the Owner.

## Claim boundary

The observations identify only the delivered specimen, registered apparatus,
tool source and session. Matching ATR or response shape establishes no internal
revision equivalence, capability, production suitability, timing property,
mutation resistance or Gate result. No identity-read outcome becomes an applet
authority or a substitute for its separately ratified capability runs.
