# QK-F3.2a — Wallet Trust Spine DRAFT

EXPERIMENTAL — NO REAL FUNDS — NOT A WALLET

STATUS: AUTHORIZED — F3.2a HOST-ONLY WALLET TRUST-SPINE DRAFT — PROPOSED/NON-NORMATIVE — INCOMPLETE — NO PROFILE ACCEPTED OR FROZEN — NO TEST VECTORS GENERATED OR RUN — NO IMPLEMENTATION — NO TARGET EVIDENCE.

AUTHORIZATION: QK-AUTH-F3F4-001 — DRAFTING ONLY; QK-AUTH-F3.2A-001 authorizes preparation of this draft only. Every rule remains PROPOSED/NON-NORMATIVE until separate explicit profile acceptance.

RFC 2119/8174 keywords (MUST, MUST NOT, SHOULD, MAY), stable clause/plan IDs, and
exact-looking candidate strings in this document carry NO normative force: this
draft changes no architecture, resolves no open decision (OD), selects no QK-LIM
value, changes no QK-TST or evidence status, closes no gate, and authorizes no
F5–F12 work, no code, no vectors, no target work, no procurement, no
fabrication, and no real-funds use.

Clause IDs are exactly QK-F3-WTS-001 through QK-F3-WTS-015, contiguous and
unique. Plan IDs are exactly QK-F3-WTS-PLAN-001 through QK-F3-WTS-PLAN-020,
contiguous and unique. Every clause is PROPOSED/NON-NORMATIVE. Every plan
status is exactly PLANNED — NOT GENERATED — NOT RUN. This draft adds no
canonical requirement, no QK-TST row, and no evidence.

## 1. Definitions and authority

**QK-F3-WTS-001 (PROPOSED/NON-NORMATIVE).** Custody OBJECTS are distinguished
from signer ROLES. A1 is a custody object (the printed/scanned artifact under
the inherited A1/A2 profile); B and C are custody objects (cards) that each
carry exactly one fixed signer role. Signer roles are A, B, and C. A1 is not
a signer and A2 is not a signer role: role A becomes usable only when the
authenticated A1 is combined with the same wallet's card-held A2 under the
inherited authentication rules. B and C each carry exactly one fixed signer
role. No single custody object alone satisfies the threshold.

**QK-F3-WTS-002 (PROPOSED/NON-NORMATIVE).** The descriptor pair D, the BIP380
descriptor checksums, the wallet_id, and all BIP32 fingerprints are METADATA
AND IDENTIFIERS ONLY: they are not factors, not authentication, and not proof
of ownership. A fingerprint alone is NEVER identity, because 4-byte
fingerprint collisions are possible. Coordinator-supplied data and any global
xpub NEVER grant authority. There is NO persistent wallet registration and NO
terminal pairing: the terminal remains stateless between sessions and holds no
enrolled-wallet list.

## 2. Canonical D candidate (bounded by QK-DEC-003)

**QK-F3-WTS-003 (PROPOSED/NON-NORMATIVE).** The proposed canonical D is a pair
of TWO distinct checksummed ASCII BIP380 descriptors — one receive, one change
— and MUST NOT be silently replaced by a single or multipath descriptor
representation. Template
form (placeholders only, never real key material):

```
receive: wsh(sortedmulti(2,[aaaaaaaa/48h/0h/0h/2h]XPUB_A/0/*,[bbbbbbbb/48h/0h/0h/2h]XPUB_B/0/*,[cccccccc/48h/0h/0h/2h]XPUB_C/0/*))#________
change:  wsh(sortedmulti(2,[aaaaaaaa/48h/0h/0h/2h]XPUB_A/1/*,[bbbbbbbb/48h/0h/0h/2h]XPUB_B/1/*,[cccccccc/48h/0h/0h/2h]XPUB_C/1/*))#________
```

Constraints, each REQUIRED in the candidate: no whitespace, newline, or NUL
byte anywhere in either descriptor; origin fingerprints represented as exactly
eight lowercase hex characters; the canonical hardened marker is `h` (never
`'`); the three keys are mainnet BIP32 account extended public keys at
`m/48h/0h/0h/2h` in ordinary xpub serialization only — never ypub/zpub and
never any private (xprv) form; the receive descriptor uses key suffix `/0/*`
for all three keys and the change descriptor uses `/1/*` for all three keys;
the outer template is `wsh(sortedmulti(2,...))` with the required BIP380
checksum appended. The full checksummed ASCII strings are the proposed
canonical descriptor bytes.

**QK-F3-WTS-004 (PROPOSED/NON-NORMATIVE).** Textual descriptor key-expression
order is the PERMANENT SEMANTIC ROLE ORDER A,B,C: the first key expression is
role A, the second role B, the third role C, identically in both descriptors.
This textual order is a role map, never a script-order claim (see
QK-F3-WTS-006).

## 3. wallet_id candidate (bounded by QK-DEC-003)

**QK-F3-WTS-005 (PROPOSED/NON-NORMATIVE).** The existing canonical formula is
preserved exactly:

```
wallet_id = SHA256(canonical_receive_descriptor_ASCII || 0x00 || canonical_change_descriptor_ASCII)
```

Receive first, then exactly one raw zero byte, then change. The hash input is
the full checksummed ASCII descriptor strings (checksums included). There is
NO domain tag or prefix, NO length fields, NO whitespace, NO newline, NO
terminator, NO displayed-hex input, and NO other byte of any kind. The raw
output is 32 bytes; lowercase 64-hex is DISPLAY ONLY and never a hash input.
A QuietKey domain prefix MUST NOT be added: adding one would amend QK-DEC-003
and is outside this draft's authority.

## 4. Role map versus sortedmulti script order

**QK-F3-WTS-006 (PROPOSED/NON-NORMATIVE).** `sortedmulti` separately sorts the
three COMPRESSED DERIVED CHILD public keys lexicographically after derivation
at every branch/index. The witnessScript slot/order can therefore change with
child/index and NEVER redefines the semantic roles A/B/C, which are fixed by
textual key-expression order alone (QK-F3-WTS-004).

**QK-F3-WTS-007 (PROPOSED/NON-NORMATIVE).** Signer identity comparison uses
role PLUS full origin path PLUS full account public material PLUS the selected
derived child public key — never script slot and never fingerprint alone.
Duplicate account public material across roles, or a duplicate derived child
key across roles, REJECTS fail-closed. Equal fingerprints alone do NOT prove
duplicate identity (collisions are possible) and equally do not excuse the
full-material comparison.

## 5. Agreement predicate

**QK-F3-WTS-008 (PROPOSED/NON-NORMATIVE).** Before any approval or signing,
EVERY available copy of D, the recomputed wallet_id, the logical role
assignment, the full account public material, the origin information, and the
selected derived child key MUST all agree. Any mismatch, and any MISSING
required comparison, fails closed. D itself is not an authenticator: agreement
of D copies establishes consistency of metadata, never authority.

## 6. Provisioning (card-independent semantic states only)

**QK-F3-WTS-009 (PROPOSED/NON-NORMATIVE).** Provisioning is described here
ONLY as card-independent semantic states and invariants. This draft does NOT
define entropy sourcing, conditioning, RNG, APDUs, commit bytes, or rollback.
The proposed state sequence: derive the A/B/C account public records;
construct D and wallet_id; stage and cross-check B and C as distinct fixed
roles with independent signer material and byte-identical D; produce A1 under
the inherited profile; scan back the ACTUAL print; authenticate under the
inherited A1/A2 rules; rederive A and match D/wallet_id; then reach exactly
one wallet-level FINAL ACCEPTANCE point. Canonical semantic invariant: B and
C contain the same A2 value. HOW that value is written, read back, or
verified is OD-02/APDU-blocked and is NOT selected here. Wallet-level FINAL
ACCEPTANCE cannot be reached without establishing this same-A2 invariant by
the future approved mechanism.

**QK-F3-WTS-010 (PROPOSED/NON-NORMATIVE).** It is NEVER claimed that B, C, and
the printed A1 are atomically committed as one physical transaction. Partial
physical artifacts may exist after interruption; they remain NOT ACCEPTED and
require a future OD-02/Gate-B retirement/reset/destruction procedure, which
this draft deliberately does NOT invent. Failure, cancellation, or shutdown
zeroizes terminal-held secret state — an intent whose realization is subject
to target evidence, which is still absent.

## 7. Recovery and pair trust establishment

**QK-F3-WTS-011 (PROPOSED/NON-NORMATIVE).** Pair trust establishment:
- A1+B: verify fixed role B and B's full origin/account public material
  against role B's entry in the same D; then authenticate A1 with the B-held
  A2 and REQUIRE the derived A to match role A's entry in that D before pair
  A+B can be selected.
- A1+C: the exact role-C analogue.
- B+C: REQUIRES byte-identical canonical D on both cards; wallet_id is
  independently recomputed from each card's D and the two recomputed values
  MUST be equal; roles B and C MUST be distinct fixed roles; and each card's
  full origin/account public material MUST match its OWN assigned role entry
  in D. wallet_id is never stored on the cards: the canonical card payload
  stores D and A2, not a persistent wallet_id.
All three paths establish trust from the presented custody objects alone, on
a stateless replacement terminal with no prior wallet registration.
Wrong wallet, role mismatch, duplicate/clone material, a missing required
comparison, or any disagreement ABORTS. The inherited rotate-and-sweep
obligation after recovery is preserved unchanged; storage/backup placement is
not changed by this draft.

## 8. Transaction ceremony invariants

**QK-F3-WTS-012 (PROPOSED/NON-NORMATIVE).** The exact custody-object pair and
signer-role pair are BOUND BEFORE REVIEW. A1+B and A1+C ceremonies use only
their selected pair; no third or out-of-pair signer ever participates. The
approval inventory is SEMANTIC ONLY and includes: profile/version; the exact D
pair and wallet_id; the selected custody/signing roles; the A1 authenticated
result where used; the card role, full public material, and committed-state
result; the exact imported bytes or their digest; transport/media/session
context; review facts; and policy context. The D-09 commitment hash, domain
tags, field order, length encoding, and serialization remain OPEN: this draft
may require the future construction to be typed, length-delimited, and
unambiguous in its domains, but MUST NOT choose the construction. Any
exact-card identifier, terminal boot identity, or session primitive exists
only if later proven under OD-02/OD-06 — none is invented here. Accepted
limitation, repeated: a malicious terminal during an authorized threshold
session is INSIDE the authorization trust boundary; this is not
independent-device review security.

## 9. B+C sequencing conflict — BLOCKED, NOT SOLVED

**QK-F3-WTS-013 (PROPOSED/NON-NORMATIVE).** QK-REQ-BND-003 requires that any
intervening card/session/state change after approval INVALIDATES approval
before signing. The recorded F3.1 D-03 direction requires exactly the selected
pair's two signatures after ONE physical approval. A single-interface,
one-reader B+C implementation would need a card change after approval to
obtain two on-card signatures — so the requirements currently CONFLICT. This
draft does NOT invent an exception, preauthorization token, persistent card
session, second approval, exported signer, dual-reader hardware, card
attestation, or APDU mechanism. Only card-independent invariants are stated:
both roles, D, wallet_id, and full public material are bound before approval;
no signing before approval; any post-approval card change invalidates under
QK-REQ-BND-003; no partial output; no blind retry. Executable
single-interface B+C choreography is BLOCKED pending separately authorized
reconciliation of QK-REQ-BND-003 versus the D-03 direction plus OD-02
exact-card and hardware evidence. Candidate resolution classes (for example:
dual-reader hardware, revised approval semantics, on-card session
continuation) are listed ONLY as unselected analysis and change no
architecture or requirement.

## 10. Card-independent versus blocked boundary

**QK-F3-WTS-014 (PROPOSED/NON-NORMATIVE).**

| Card-independent proposed contract | Explicitly OD-02/Gate-B or evidence BLOCKED |
| --- | --- |
| role uniqueness; agreement predicate; exact selected pair; failure state; no blind retry; all-or-nothing output; zeroization intent; stateless terminal boundary | card model; number of interfaces; APDU bytes/sequencing/limits; lifecycle commit/rollback; reading D/A2; account-public derivation/export; unique card ID/attestation; secure channel; counters; nonce/RNG; anti-exfil; non-exportability/rescue; state persistence across swaps; power-cut behavior |

## 11. Traceability and status

**QK-F3-WTS-015 (PROPOSED/NON-NORMATIVE).** Honest acceptance boundary —
traceability is NOT DONE. This draft carries individual controlling
QK-DEC/QK-REQ/OD references inline, but it does NOT yet provide
clause-by-clause requirement coverage and does NOT map any WTS plan to a
canonical QK-TST ID. Complete clause-to-requirement and plan-to-test
traceability is an explicit profile-acceptance prerequisite and remains NOT
DONE. No canonical ID, status, or evidence is added or modified; every
existing QK-TST remains PLANNED — NOT RUN and evidence is absent. A future
separately authorized mapping proves nothing, runs nothing, and creates no
evidence. Coverage listing NEVER proves correctness. D-00, D-02, D-04, the
D-05 current allowlist, D-06, D-07, D-09, D-10,
and D-11 remain owner-open as already recorded; the F3.1 directions remain
proposed; nothing here accepts the PSBT profile.

## 12. Test plans (symbolic only; no vector generated or run)

| Plan ID | Covers | Focus (symbolic only) | Status |
| --- | --- | --- | --- |
| QK-F3-WTS-PLAN-001 | QK-F3-WTS-003 | exact receive descriptor form (template, `h` marker, `/0/*` suffixes, checksum present) | PLANNED — NOT GENERATED — NOT RUN |
| QK-F3-WTS-PLAN-002 | QK-F3-WTS-003 | exact change descriptor form (`/1/*` suffixes for all three keys) | PLANNED — NOT GENERATED — NOT RUN |
| QK-F3-WTS-PLAN-003 | QK-F3-WTS-003 | checksum/whitespace/NUL/encoding rejection (bad checksum, embedded space, newline, NUL, non-ASCII, uppercase-hex fingerprint, `'` marker, ypub/zpub/xprv) | PLANNED — NOT GENERATED — NOT RUN |
| QK-F3-WTS-PLAN-004 | QK-F3-WTS-005 | wallet_id byte order (receive first), single 0x00 separator, checksum inclusion in hash input | PLANNED — NOT GENERATED — NOT RUN |
| QK-F3-WTS-PLAN-005 | QK-F3-WTS-005 | swapped receive/change, extra prefix/domain tag, appended newline each produce a DIFFERENT wallet_id and reject as mismatch | PLANNED — NOT GENERATED — NOT RUN |
| QK-F3-WTS-PLAN-006 | QK-F3-WTS-004, QK-F3-WTS-006 | textual role order A,B,C versus lexicographic derived-key sorting across multiple child indices (slot changes, roles fixed) | PLANNED — NOT GENERATED — NOT RUN |
| QK-F3-WTS-PLAN-007 | QK-F3-WTS-007 | duplicate account public material across roles rejects | PLANNED — NOT GENERATED — NOT RUN |
| QK-F3-WTS-PLAN-008 | QK-F3-WTS-007 | duplicate derived child key across roles rejects; equal fingerprints alone neither prove nor excuse | PLANNED — NOT GENERATED — NOT RUN |
| QK-F3-WTS-PLAN-009 | QK-F3-WTS-008 | D copy disagreement, wallet_id recomputation mismatch, role/public-material mismatch each fail closed | PLANNED — NOT GENERATED — NOT RUN |
| QK-F3-WTS-PLAN-010 | QK-F3-WTS-008 | missing required comparison fails closed (absence is failure, never a skip) | PLANNED — NOT GENERATED — NOT RUN |
| QK-F3-WTS-PLAN-011 | QK-F3-WTS-009 | B and C provisioning as distinct fixed roles with independent signer material, byte-identical D, and the same-A2 invariant (mechanism OD-02/APDU-blocked, not selected) | PLANNED — NOT GENERATED — NOT RUN |
| QK-F3-WTS-PLAN-012 | QK-F3-WTS-009 | A1 print-back scan mismatch rejects before FINAL ACCEPTANCE | PLANNED — NOT GENERATED — NOT RUN |
| QK-F3-WTS-PLAN-013 | QK-F3-WTS-011 | A1+B recovery: role-B material verified against role B in D, A1 authenticated with B-held A2, derived A matches role A in D | PLANNED — NOT GENERATED — NOT RUN |
| QK-F3-WTS-PLAN-014 | QK-F3-WTS-011 | A1+C recovery: exact role-C analogue | PLANNED — NOT GENERATED — NOT RUN |
| QK-F3-WTS-PLAN-015 | QK-F3-WTS-011 | B+C agreement: byte-identical canonical D, wallet_id independently recomputed from each card's D and equal, distinct fixed roles, per-role public-material match; wrong-wallet abort | PLANNED — NOT GENERATED — NOT RUN |
| QK-F3-WTS-PLAN-016 | QK-F3-WTS-013 | the QK-REQ-BND-003 versus D-03 single-interface conflict is BLOCKED — asserted as a blocked outcome, never a passing flow | PLANNED — NOT GENERATED — NOT RUN |
| QK-F3-WTS-PLAN-017 | QK-F3-WTS-001, QK-F3-WTS-007, QK-F3-WTS-008, QK-F3-WTS-011, QK-F3-WTS-012, QK-F3-WTS-013 | wrong-role, duplicate role/signer material, and post-approval context-change rejection (post-approval invalidation included) | PLANNED — NOT GENERATED — NOT RUN |
| QK-F3-WTS-PLAN-018 | QK-F3-WTS-010, QK-F3-WTS-013, QK-F3-WTS-014 | failure/interruption behavior: no partial output, no blind retry, zeroization intent | PLANNED — NOT GENERATED — NOT RUN |
| QK-F3-WTS-PLAN-019 | QK-F3-WTS-002 | terminal statelessness: no persistent wallet registration, no terminal pairing | PLANNED — NOT GENERATED — NOT RUN |
| QK-F3-WTS-PLAN-020 | QK-F3-WTS-012, QK-F3-WTS-014 | APDU/mechanism unknowns remain blocked; malicious-terminal limitation stated, never mitigated by claim | PLANNED — NOT GENERATED — NOT RUN |

END OF DRAFT — PROPOSED/NON-NORMATIVE — NO PROFILE ACCEPTED — NO VECTORS — NO IMPLEMENTATION — NO TARGET EVIDENCE.
