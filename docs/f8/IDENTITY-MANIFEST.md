# F8 Identity-Read Evidence Manifest

EXPERIMENTAL - V1 ARTIFACT REGISTERED - V2 SEQUENCE COMPLETE

## Registration boundary

QK-DEC-153 authorized `QK-F8-IDENT-V1`. Its first and only session, on
`J3R180-02`, stopped on a named rejection, so V1 authorizes no further session.
QK-DEC-153-SUP-002 supersedes the unfilled V1 schedule with one fresh fixed
read-only `QK-F8-IDENT-V2` session per enrolled specimen, in order
`J3R180-02`, `J3R180-03`, `J3R180-01`. A non-PASS result stops the sequence for
Owner disposition. All three V2 sessions are registered below and the fixed
sequence is complete. QK-DEC-153-SUP-002 authorizes no further identity
session. This file authorizes no command beyond the exact V2 sequence.

The frozen `ENROLLMENT-MANIFEST.md` statement that no further card contact is
authorized closes only `QK-F8-ENROLL-EMPTY-V1`; QK-DEC-153 and its V2
supplement are the later narrow authorities for identity contacts and create
no further enrollment session.

The complete raw transcripts, reader and specimen serials, and every Card Data,
CPLC, request and response byte stay in durable private Owner custody. The V1
artifact identity and all three V2 artifact identities are registered below.
Each V2 row was filled by its own Owner-directed evidence commit after its
session. The repository continues to publish ATRs verbatim but never publishes
FCI, Card Data or CPLC bytes.

## Registered V1 stopped-session artifact

The Owner reports that at source commit
`800da1a2b6158e08195237c2523cb560a957571a`, supplied timestamp
`2026-09-01T14:00:40Z`, J3R180-02 enumeration, exclusive connection, reset,
registered ATR and T=1 capture passed; `80 CA 00 66 00` returned status `69 85`;
the tool rejected as `CardRecognitionStatusRejected`, transmitted nothing
further and disconnected cleanly. Private transcript `identity-J3R180-02.txt`,
produced by `qk-card-enrollment 0.0.2`, is 919 bytes with SHA-256
`5b5b08b339fc813462dde6a0080de60d98e9e07d4333cfd5d1fe3b4e3a3cf599`
and remains in the private F8 bundle in locked storage at the Owner's premises.
This registers the stopped artifact identity; it neither fills nor preserves
the former three-row V1 schedule.

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

## V2 invocation and ordering accounting

Before the registered PASS run, one invocation of the V2 tool at source
`f4cd9e73afb5993eb3427bb8558dfd853988a7ff` found no card in the reader and
stopped at `ExclusiveConnect` before any card contact. Its refusal transcript
was overwritten because both invocations used the same output path. The PASS
run below is therefore exactly one V2 contact session on J3R180-02. Beginning
with the J3R180-03 session, the output filename carries the timestamp.

The J3R180-03 V2 procedure used exactly one invocation and one timestamped
output name. The Owner ran it after the LOA review of row 1 but before row 1 was
registered on `main`, departing from the QK-DEC-153-SUP-002 ordering. The
observation stands and is registered below. No further identity session may run
ahead of its preceding ledger registration and review.

The protected J3R180-01 V2 procedure used exactly one invocation and one
timestamped output name after the required LOA check of the row-2 evidence
commit. The retained artifact check reproduced its hash and exact schema, and
all three responses matched the registered grammars. Its FCI and Card
Recognition Data bytes were byte-identical to specimens 02 and 03; its CPLC
differed in the IC serial and pre-personalization fields. Those bytes remain in
Owner custody. This third registered row completes the fixed V2 sequence.

## V2 evidence ledger

| Required order | Specimen alias | Public ATR | Protocol | Private transcript alias | Exact byte count | SHA-256 | Tool/source commit | UTC timestamp | Private custody path | tx/rx counts | Result |
|---:|---|---|---|---|---:|---|---|---|---|---|---|
| 1 | `J3R180-02` | `3bd518ff8191fe1fc38073c821100a` | `T1` | `identity-v2-J3R180-02.txt` | 1312 | `d35b5bca64ae16d160ddc5de969a71b9eb8caf83334d84010f1f6698506631c7` | `qk-card-enrollment 0.0.3` / source `f4cd9e73afb5993eb3427bb8558dfd853988a7ff` | `2026-09-01T18:28:54Z` | Private F8 bundle in locked storage at Owner premises | `3/3` | PASS; 12 events all PASS; all three responses matched the registered grammars; disconnect PASS |
| 2 | `J3R180-03` | `3bd518ff8191fe1fc38073c821100a` | `T1` | `identity-v2-J3R180-03-2026-09-01T18:55:05Z.txt` | 1312 | `f9146888489e53a1f8ddecab022cc34fb1ea24921278ac8a6f87211d46356493` | `qk-card-enrollment 0.0.3` / source `f4cd9e73afb5993eb3427bb8558dfd853988a7ff` | `2026-09-01T18:55:05Z` | Private F8 bundle in locked storage at Owner premises | `3/3` | PASS; 12 events all PASS; all three responses matched the registered grammars; disconnect PASS; exactly one invocation |
| 3 | `J3R180-01` | `3bd518ff8191fe1fc38073c821100a` | `T1` | `identity-v2-J3R180-01-2026-09-01T21:21:10Z.txt` | 1312 | `22a3dc9c69cfed0eb3f25314b4bda16ef65b373e77499979978628f6f4415600` | `qk-card-enrollment 0.0.3` / source `edd4bb18754cb3498aa11423bdac33244552a5fc` | `2026-09-01T21:21:10Z` | Private F8 bundle in locked storage at Owner premises | `3/3` | PASS; 12 events all PASS; all three responses matched the registered grammars; disconnect PASS; exactly one invocation |

No row may be filled from terminal recollection or normalized output. Each row
is tied to the exact retained private artifact bytes supplied by the Owner.

## Claim boundary

The observations identify only the delivered specimen, registered apparatus,
tool source and session. Matching ATR or response shape establishes no internal
revision equivalence, capability, production suitability, timing property,
mutation resistance or Gate result. No identity-read outcome becomes an applet
authority or a substitute for its separately ratified capability runs.
