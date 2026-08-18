# QK-F3.1 — PSBT v0 Review Profile DRAFT

EXPERIMENTAL — NO REAL FUNDS — NOT A WALLET

STATUS: AUTHORIZED — F3.1 HOST-ONLY PSBT v0 REVIEW-PROFILE DRAFT — NON-NORMATIVE — INCOMPLETE — NO PROFILE ACCEPTED — NO TEST VECTORS GENERATED — NO TARGET EVIDENCE.

REVISION: F3.1a — CORRECTION-ONLY REVIEW DRAFT — NO OWNER ITEM DECIDED.

AUTHORIZATION: QK-AUTH-F3F4-001 — DRAFTING ONLY; F3.1a remediation recorded as QK-AUTH-F3.1A-001. No profile clause becomes accepted merely because it was corrected.

Any RFC 2119/RFC 8174 terms in this document describe PROPOSED
requirements only and have no normative force until separately
owner-approved. PSBT v0 is already selected by QK-DEC-009; this draft
inherits but does not modify or expand that architecture decision. It
accepts no profile, closes no gate, resolves no open decision (OD) or
QK-LIM, changes no QK-TST or evidence status, and authorizes no F9
implementation. Every clause below carries a stable proposed-clause ID
(QK-F3-PSBT-001 through QK-F3-PSBT-034, contiguous; 031–034 were
appended without renumbering 001–030; F3.1a corrects clause text
without adding, removing, renumbering, or accepting any clause); an ID
is a stable reference handle and never implies acceptance. This document contains no parser,
no serializer, no cryptography, no fixtures, and no byte-level test
data of any kind.

## 1. Scope and hard exclusions

**QK-F3-PSBT-001** — Inherited scope (citation of existing decisions,
not new authority): mainnet only; PSBT version 0 only; binary `.psbt`
file via SD card transport; uncompressed BBQr type P as a TRANSPORT
encoding only; native SegWit P2WSH `wsh(sortedmulti(2,A,B,C))` only;
derivation family `m/48'/0'/0'/2'/{0,1}/*`; signed-PSBT export over
both approved routes (BBQr type P and a newly created microSD output
file) is an inherited minimum from QK-REQ-TRN-007. By contrast, the
narrower rule "partially signed only, never finalized, no raw
transaction" is a RECOMMENDED CANDIDATE under OD-05 in this draft
(QK-F3-PSBT-016) — it is not inherited and not settled. All bytes and
metadata arriving through future `qk-io` are hostile and
non-authoritative.

**QK-F3-PSBT-002** — Hard exclusions. This draft excludes and proposes
to reject or defer: PSBT v2 (BIP 370), Taproot wallet and PSBT fields,
P2TR recipient outputs (see QK-F3-PSBT-020), any format autodetection,
UR and SeedQR transports, any parser/serializer implementation, key
derivation, cryptography, signing, finalization, QR/SD driver
implementation, target-device behavior, every OWNER-SELECTED
project/resource/workload/admission/UI ceiling (each such ceiling
remains symbolic and belongs to the applicable OPEN QK-LIM family;
fixed BIP174/Bitcoin wire widths, structural constants, and Bitcoin
validity/money ranges are pinned protocol/validity invariants, not
owner-selected QK-LIM values), real funds, fixtures and test vectors,
and any interoperability, production, or security claim.

## 2. Primary sources (pinned, citation only)

Cited by reference only, at exact pinned commits recorded in
docs/SOURCE-REGISTER.md. No third-party code, fixtures, vectors, or
specification text is copied into this repository. The pinned BIP 174
text is itself the primary source for the full-previous-transaction
rationale cited in QK-F3-PSBT-011.

- BIP 174 (License: BSD-2-Clause), repository bitcoin/bips at commit
  `857a7debc6625a3dadbaecee1ee7b2ed5e8ada75`:
  https://github.com/bitcoin/bips/blob/857a7debc6625a3dadbaecee1ee7b2ed5e8ada75/bip-0174.mediawiki
- PSBT type registry (auxiliary BIP 174 coordination file, same
  pinned commit):
  https://github.com/bitcoin/bips/blob/857a7debc6625a3dadbaecee1ee7b2ed5e8ada75/bip-0174/type-registry.mediawiki
- BIP 370, PSBT version 2 and the intentional v0/v2 incompatibility
  (License: BSD-2-Clause), same pinned commit:
  https://github.com/bitcoin/bips/blob/857a7debc6625a3dadbaecee1ee7b2ed5e8ada75/bip-0370.mediawiki
- Bitcoin Core PSBT role/workflow documentation (repository MIT
  license), bitcoin/bitcoin at commit
  `15a7a4ed7c4d0952ce966087e55a9a3e2f28ec1d`:
  https://github.com/bitcoin/bitcoin/blob/15a7a4ed7c4d0952ce966087e55a9a3e2f28ec1d/doc/psbt.md
- Canonical local governance (controlling authority for descriptor,
  BIP48 derivation, sortedmulti policy, and mainnet-only scope; no
  external text becomes normative): QK-DEC-002, QK-DEC-003,
  QK-DEC-009, QK-DEC-010; QK-REQ-PSBT-001..008; QK-REQ-TRN-001..010;
  QK-REQ-TUI-001..004; QK-REQ-BND-001..003; QK-REQ-CUS-001,
  QK-REQ-CUS-006.

## 3. Threat and trust contract

**QK-F3-PSBT-003** — Future `qk-io`, in its unprivileged role, MAY
parse bounded QR/BBQr framing and SD/filesystem transport structure
only. It MUST never interpret PSBT transaction semantics and MUST
never supply an authoritative transaction fact. Future `qk-core`
independently reparses the delivered PSBT bytes and derives every
authoritative fact itself.

**QK-F3-PSBT-004** — Future `qk-core` MUST independently parse and
derive every authoritative fact. It MUST never trust a transport, UI,
or coordinator claim of amount, address, change label, fee, network,
wallet, derivation, sighash, signature validity, or completion. Every
review field MUST have future trusted-core origin, derived by `qk-core`
itself from independently parsed data plus the loaded descriptor
context. This draft supplies requirements only — no algorithms and no
evidence.

## 4. Proposed validation order (dependency-correct)

**QK-F3-PSBT-005** — Proposed order, each step depending only on
earlier steps: bounded intake → magic/version/map framing, minimal
CompactSize, full consumption → unique full keys and map counts →
unsigned-transaction structural rules → input prevout validation
(full-prevtx txid/vout commitment; QK-F3-PSBT-011) →
wallet/descriptor/origin/derivation/witness-script ownership,
concluding with the final authenticated-prevout-to-derived-script
binding (the supplied-prevtx-committed scriptPubKey MUST equal the
descriptor-derived P2WSH program; QK-F3-PSBT-012) →
existing-signature encoding/policy checks (strict DER per BIP 66,
trailing sighash byte, proposed low-S policy; QK-F3-PSBT-015) and
per-input sighash checks → output/change/
self-transfer/recipient classification → checked amounts, sums, and
fee (QK-F3-PSBT-031) → locktime and raw sequences (replacement policy
not evaluated; QK-F3-PSBT-033) → factor/card agreement precondition
(QK-F3-PSBT-032) → canonical review facts → review commitment (its serialization remains
OPEN) → physical approval bound per QK-F3-PSBT-032 → immediate full
reparse — of the trusted core's retained exact imported byte
sequence, never a reread of QR, SD, or any other mutable transport
source — and equality to the approved commitment → future signature
production → produced-signature verification → output reparse and
exact-delta proof (QK-F3-PSBT-025, -033). Between the equality proof
and signature production no new untrusted transaction/media input and
no review-relevant mutation is permitted; the already-bound active
signer/card APDU exchange is explicitly allowed. F4.1
models the SYMBOLIC order of the tail of this pipeline only; this
document does not implement any step.

## 5. Field-disposition matrices

Dispositions used: PROPOSED REQUIRED, PROPOSED OPTIONAL-VALIDATE,
PROPOSED REJECT, OPEN. No other value is used anywhere in this draft.
Each matrix below is an explicit CLOSED-WORLD ALLOWLIST with this
exact default rule, restated as the final row of every scope:
"Every key type not explicitly allowed by this profile, whether
registered/known or unrecognized — PROPOSED REJECT." A registry-aware
parser can therefore never treat a registered-but-unlisted field as
silently allowed or undisposed. The registered-but-unsupported fields
named below (exact names and type values from the pinned type
registry) can be registered/valid PSBT generally; they are
profile-ineligible under this profile, not malformed in the standard.
In the v1 RECOMMENDED CANDIDATE, fields not explicitly allowed and
proprietary fields are policy-rejected during bounded map framing/key
parsing, before semantic, ownership, fee, review, or signing
processing, in every scope (QK-F3-PSBT-018), so QuietKey never accepts
and then silently drops or strips a field. The four categories stay
distinct: registered-but-profile-ineligible; unregistered/unrecognized;
structurally valid proprietary; malformed proprietary.

**QK-F3-PSBT-006** — Global map:

| Global field | Disposition |
|---|---|
| Unsigned transaction | PROPOSED REQUIRED (exactly one) |
| Global xpub | PROPOSED OPTIONAL-VALIDATE (candidate/owner decision D-02; if accepted it is an untrusted hint that must exactly agree with D and confers no authority) |
| PSBT version field | PROPOSED OPTIONAL-VALIDATE (omitted, or present and exactly zero) |
| Registered-but-unsupported: PSBT_GLOBAL_SP_ECDH_SHARE 0x07 | PROPOSED REJECT (registered/valid generally; profile-ineligible) |
| Registered-but-unsupported: PSBT_GLOBAL_SP_DLEQ 0x08 | PROPOSED REJECT (registered/valid generally; profile-ineligible) |
| Registered-but-unsupported: PSBT_GLOBAL_GENERIC_SIGNED_MESSAGE 0x09 | PROPOSED REJECT (registered/valid generally; profile-ineligible) |
| Unregistered/unrecognized key types (global scope) | PROPOSED REJECT (v1 candidate; D-04 NOT ACCEPTED) |
| Proprietary type PSBT_GLOBAL_PROPRIETARY 0xFC (global scope) | PROPOSED REJECT (v1 candidate; malformed 0xFC is never called valid) |
| All v2-only global fields (BIP 370) | PROPOSED REJECT |
| Every key type not explicitly allowed by this profile, whether registered/known or unrecognized (closed-world default) | PROPOSED REJECT |

**QK-F3-PSBT-007** — Per-input map:

| Input field | Disposition |
|---|---|
| non_witness_utxo | PROPOSED REQUIRED (both-UTXO candidate; validated per QK-F3-PSBT-011) |
| witness_utxo | PROPOSED REQUIRED |
| Partial signature | PROPOSED OPTIONAL-VALIDATE (expected script keys only, per input and per pubkey; see QK-F3-PSBT-015) |
| Sighash type | PROPOSED OPTIONAL-VALIDATE (per input; SIGHASH_ALL only; see QK-F3-PSBT-014) |
| Redeem script | PROPOSED REJECT |
| Witness script | PROPOSED REQUIRED (must equal descriptor-derived script) |
| BIP32 derivation | PROPOSED REQUIRED (for the relevant script keys) |
| Final scriptSig / final witness | PROPOSED REJECT |
| Hash preimage fields | PROPOSED REJECT |
| Taproot fields | PROPOSED REJECT |
| PSBT_IN_PREVIOUS_TXID 0x0e (v2-only) | PROPOSED REJECT |
| PSBT_IN_OUTPUT_INDEX 0x0f (v2-only) | PROPOSED REJECT |
| PSBT_IN_SEQUENCE 0x10 (v2-only) | PROPOSED REJECT |
| PSBT_IN_REQUIRED_TIME_LOCKTIME 0x11 (v2-only) | PROPOSED REJECT |
| PSBT_IN_REQUIRED_HEIGHT_LOCKTIME 0x12 (v2-only) | PROPOSED REJECT |
| Registered-but-unsupported: PSBT_IN_POR_COMMITMENT 0x09 | PROPOSED REJECT (registered/valid generally; profile-ineligible) |
| Registered-but-unsupported: PSBT_IN_MUSIG2_PARTICIPANT_PUBKEYS 0x1a | PROPOSED REJECT (registered/valid generally; profile-ineligible) |
| Registered-but-unsupported: PSBT_IN_MUSIG2_PUB_NONCE 0x1b | PROPOSED REJECT (registered/valid generally; profile-ineligible) |
| Registered-but-unsupported: PSBT_IN_MUSIG2_PARTIAL_SIG 0x1c | PROPOSED REJECT (registered/valid generally; profile-ineligible) |
| Registered-but-unsupported: PSBT_IN_SP_ECDH_SHARE 0x1d | PROPOSED REJECT (registered/valid generally; profile-ineligible) |
| Registered-but-unsupported: PSBT_IN_SP_DLEQ 0x1e | PROPOSED REJECT (registered/valid generally; profile-ineligible) |
| Registered-but-unsupported: PSBT_IN_SP_SPEND_BIP32_DERIVATION 0x1f | PROPOSED REJECT (registered/valid generally; profile-ineligible) |
| Registered-but-unsupported: PSBT_IN_SP_TWEAK 0x20 | PROPOSED REJECT (registered/valid generally; profile-ineligible) |
| Unregistered/unrecognized key types (input scope) | PROPOSED REJECT (v1 candidate; D-04 NOT ACCEPTED) |
| Proprietary type 0xFC (input scope) | PROPOSED REJECT (v1 candidate) |
| Every key type not explicitly allowed by this profile, whether registered/known or unrecognized (closed-world default) | PROPOSED REJECT |

**QK-F3-PSBT-008** — Per-output map:

| Output field | Disposition |
|---|---|
| Redeem script | PROPOSED REJECT |
| Witness script | PROPOSED OPTIONAL-VALIDATE (own outputs only; must match descriptor derivation) |
| BIP32 derivation | PROPOSED OPTIONAL-VALIDATE (required to prove change/self-transfer; see QK-F3-PSBT-019) |
| Amount / script v2-only fields (BIP 370) | PROPOSED REJECT |
| Taproot fields | PROPOSED REJECT |
| Registered-but-unsupported: PSBT_OUT_MUSIG2_PARTICIPANT_PUBKEYS 0x08 | PROPOSED REJECT (registered/valid generally; profile-ineligible) |
| Registered-but-unsupported: PSBT_OUT_SP_V0_INFO 0x09 | PROPOSED REJECT (registered/valid generally; profile-ineligible) |
| Registered-but-unsupported: PSBT_OUT_SP_V0_LABEL 0x0a | PROPOSED REJECT (registered/valid generally; profile-ineligible) |
| Registered-but-unsupported: PSBT_OUT_DNSSEC_PROOF 0x35 | PROPOSED REJECT (registered/valid generally; profile-ineligible) |
| Unregistered/unrecognized key types (output scope) | PROPOSED REJECT (v1 candidate; D-04 NOT ACCEPTED) |
| Proprietary type 0xFC (output scope) | PROPOSED REJECT (v1 candidate) |
| Every key type not explicitly allowed by this profile, whether registered/known or unrecognized (closed-world default) | PROPOSED REJECT |

**QK-F3-PSBT-009** — Structural rules (all PROPOSED REQUIRED):
exact PSBT magic; v0 version field omitted or exactly zero; exactly
one unsigned transaction; unsigned transaction in legacy serialization
with no witness data; every unsigned-transaction input scriptSig
empty; every CompactSize minimally encoded; unique FULL keys within
each map — uniqueness applies to the full key (key type plus keydata),
not merely the key type, so multiple entries with the same key type
but different keydata can be valid while a duplicate full key is
always invalid; input and output map counts exactly matching the
unsigned transaction; no truncation and no trailing bytes; every
length/count product checked before use (QK-F3-PSBT-031); every
OWNER-SELECTED project/resource/workload/admission/UI ceiling remains
symbolic and belongs to the applicable OPEN QK-LIM family, while
fixed BIP174/Bitcoin wire widths, structural constants, and the
Bitcoin validity/money ranges required by QK-REQ-PSBT-008 are pinned
protocol/validity invariants, not owner-selected QK-LIM values; no
open product ceiling is selected here, and every QK-LIM remains OPEN.

Minimum unsigned-transaction admissibility (all PROPOSED REQUIRED;
these are proposed QuietKey v1 profile checks and are NOT a claim of
exhaustive Bitcoin transaction or consensus validation): the full
inner legacy/non-witness transaction serialization MUST be consumed
exactly, with no unconsumed and no missing bytes; the unsigned
transaction MUST have at least one input and at least one output;
every input outpoint MUST be non-null; coinbase-form unsigned
transactions are profile-rejected — QuietKey signs spends and does not
construct coinbase transactions; and no two inputs may spend the same
outpoint (duplicate input outpoints are rejected).

## 6. Candidate policy bundle — RECOMMENDED CANDIDATE — NOT ACCEPTED

Every clause in this section is a RECOMMENDED CANDIDATE only. Nothing
in this section has been owner-decided.

**QK-F3-PSBT-010** — All inputs MUST be owned by the exact loaded
descriptor D and match native P2WSH `sortedmulti(2,A,B,C)` 2-of-3.
Mixed or foreign inputs: reject.

**QK-F3-PSBT-011** — Prevout authentication, both-UTXO RECOMMENDED
CANDIDATE: require BOTH `witness_utxo` AND `non_witness_utxo` (the
full previous transaction) for every native-SegWit input. Rationale
from the pinned BIP 174 text: full previous transactions are
defense-in-depth against the SegWit/BIP143 repeated-signing fee
attack, in which a signer shown a false input value can be induced to
sign twice and leak the difference as fee; the explicit tradeoff is
QR transport size. Exact proposed validation: compute the standard
Bitcoin txid of the supplied `non_witness_utxo` transaction — the
double-SHA256 of its non-witness (stripped) serialization as defined
by Bitcoin transaction semantics; never the wtxid and never a hash of
any witness-inclusive serialization — and compare it to
the unsigned transaction input's prevout txid; bounds-check the
prevout vout index against that transaction's output count; then
compare that indexed output's amount and scriptPubKey with
`witness_utxo`. Explicit limitation on the word "authenticated"
anywhere in this draft: full-prevtx txid/vout validation proves only
that the supplied value and scriptPubKey are committed by the supplied
full transaction and referenced txid. It does NOT prove that the
transaction exists in the best chain, is confirmed, that the outpoint
is unspent, or any other online chain-state fact; an offline signer
has no chain state. Where this draft says "authenticated prevout" it
means exactly "prevout committed by the supplied full transaction and
referenced txid" and nothing more. D-01 stays NOT ACCEPTED. If the owner later chooses a
witness-only policy, the accepted profile MUST explicitly downgrade
its prevout and fee provenance claims and explicitly address the
repeated-signing attack; this draft never calls witness-only values
independently authenticated.

**QK-F3-PSBT-012** — `witness_script` REQUIRED for every input and
MUST equal the script independently derived from D. `redeem_script` on
any input: reject. The prevtx-committed (per QK-F3-PSBT-011)
`witness_utxo` scriptPubKey MUST be exactly native P2WSH: the 34-byte
script `0x00 0x20 <32-byte SHA256(witnessScript)>`, where `0x00` is
the `OP_0` version opcode, `0x20` is the one-byte direct-push opcode
pushing exactly 32 bytes, and the pushed 32-byte witness program
equals the SHA256 of the exact `witness_script` independently
derived from the trusted descriptor D. Ownership is established ONLY
by the full chain D → all three derived keys at one common
branch/index coordinate → exact `sortedmulti(2,A,B,C)` witness_script
→ SHA256 → prevtx-committed prevout scriptPubKey. A supplied
`witness_script` and supplied BIP32 derivation records alone NEVER
establish ownership.

**QK-F3-PSBT-013** — BIP32 derivations REQUIRED for the three relevant
script keys of every input and MUST match the exact master
fingerprints, account origins, branches, and indexes computed from D.
All three A/B/C input derivation entries MUST share one common
descriptor branch/index coordinate and match D at that coordinate;
supplied paths merely PROPOSE the coordinate — the derivation and
comparison against D decide it.
A global xpub, if present and if D-02 accepts it, is an untrusted hint
that MUST exactly agree with D and confers no authority.

**QK-F3-PSBT-014** — Effective sighash is determined PER INPUT.
SIGHASH_ALL only. An absent per-input sighash field means a proposed
default of ALL for v0 ECDSA only if that default is separately
accepted (packet item D-03). Any other effective sighash on any input:
reject.

**QK-F3-PSBT-015** — Existing-signature status is tracked PER INPUT
and PER PUBKEY. Existing partial signatures are allowed only for
expected script keys and only after future cryptographic verification
against that input's exact effective sighash, including the trailing
sighash byte. Encoding rule: every partial-signature value MUST be a
strict-DER ECDSA signature per BIP 66 followed by exactly one trailing
sighash byte; non-DER, padded, or otherwise non-strict encodings:
reject. High-S handling is a PROPOSED v1 relay-policy alignment
choice: low-S is a Bitcoin Core standardness/relay policy, not a
consensus rule, and BIP 146 is never cited here as a deployed
consensus rule; the proposed v1 candidate rejects high-S existing
signatures as a policy choice, subject to the same owner decision
family as D-03. Multiple partial signatures under distinct expected full
keys on one input are structurally valid; a duplicate full key is
invalid (QK-F3-PSBT-009). Invalid, foreign, or conflicting signatures:
reject. A PSBT is never rejected merely because the expected other
cosigner's signature is present. Handling of an already
threshold-signed PSBT is D-03 OPEN unless otherwise decided.

**QK-F3-PSBT-016** — RECOMMENDED CANDIDATE under OD-05 (not inherited,
not settled): QuietKey exports a signed PSBT only, never finalizes,
and never emits a raw transaction; a final scriptSig or final witness
on any input is rejected. Signed-PSBT export over both approved routes
remains the inherited minimum (QK-REQ-TRN-007, QK-F3-PSBT-001).

**QK-F3-PSBT-017** — Known-irrelevant hash-preimage fields and all
Taproot fields: reject.

**QK-F3-PSBT-018** — Closed-world allowlist default and proprietary
key-value pairs, v1 RECOMMENDED CANDIDATE: every key type not
explicitly allowed by this profile, whether registered/known or
unrecognized, is PROPOSED REJECT in every scope (global, input,
output), as a policy rejection during bounded map framing/key parsing,
before semantic, ownership, fee, review, or signing processing, so
QuietKey never accepts a field it would then drop, strip, or pass
through unreviewed.
Registered-but-unsupported fields (the named registry rows in
section 5) can be registered/valid PSBT generally; they are
profile-ineligible here, not malformed in the standard.
Unregistered/unrecognized key types are a separate rejected category,
distinguished from the known proprietary type
0xFC: 0xFC is a defined type whose internal structure
(identifier-length, identifier, subtype, subkeydata) can be malformed,
and malformed 0xFC is never called valid. D-04 stays NOT ACCEPTED and
may later choose bounded preservation only if an accepted
commitment/round-trip design exists; any such preservation alternative
REQUIRES structural validation of the field and an exact
scope/index/full-key/value commitment before acceptance
(QK-F3-PSBT-026). Because the v1 candidate rejects these fields, no
accepted opaque field can sit outside the review commitment.

**QK-F3-PSBT-019** — Change classification only if independently
proven from D's change branch and derivation. An own receive-branch
output is displayed separately as a self-transfer. Anything not proven
change is a recipient. Coordinator labels are never authoritative.
Ambiguous or conflicting ownership: reject.

**QK-F3-PSBT-020** — Multiple inputs and multiple recipient outputs
are permitted only within future OPEN limits. No one-recipient
assumption anywhere. The architecture's v1 non-goal "No Taproot"
controls: P2TR recipient outputs are EXCLUDED in this v1 draft.
D-05 may decide the remaining non-Taproot recipient allowlist only;
the PROPOSED (NOT ACCEPTED) D-05 recipient script allowlist is exactly
P2PKH, P2SH, P2WPKH, and P2WSH; every other recipient script class is
an explicit reject. Enabling P2TR recipients requires a separate
architecture-owner amendment, and OD-05 cannot silently reopen it. No
silent unsupported output — every unsupported output script is an
explicit reject.

**QK-F3-PSBT-021** — Mainnet rendering only. Scripts themselves do not
encode a network; address and network rendering derives from the
canonical mainnet context, never from coordinator metadata.

**QK-F3-PSBT-022** — Absolute fee is exact ONLY when computed from
full-previous-transaction values committed by the supplied full
transactions and referenced txids (QK-F3-PSBT-011; this proves
commitment, never chain existence, confirmation, or unspentness)
as verified input sums minus output sums, using
checked arithmetic (QK-F3-PSBT-031). Fee-rate before final signatures
is UNAVAILABLE while D-08 remains open; if the D-08 candidate is later
owner-selected and every bound is proven, the status is RANGE,
otherwise it stays UNAVAILABLE. It is never an estimate,
it is never called exact, and it MUST never rely
on a coordinator-supplied fee or fee rate. Warning and hard thresholds
remain OD-05/QK-LIM OPEN.

**QK-F3-PSBT-023** — The review display MUST show: all recipient,
self-transfer, and change outputs; per-output amounts; total input and
total output sums; the exact absolute fee (per QK-F3-PSBT-022);
the fee-rate status and method state; the raw transaction version and
raw nLockTime, displayed exactly; every RAW nSequence
value per input, displayed exactly and accompanied by the literal
status "replacement policy not evaluated" while no pinned
owner-approved replacement policy exists (QK-F3-PSBT-033, D-12 OPEN),
with no opt-in signaling implication and no replaceability inference
derived or shown. Version, nLockTime, and nSequence are treated
together as one time/lock semantics family (QK-F3-PSBT-023, -026,
-033) under one combined owner decision, D-12 under OD-05; input
count; output count; per-input
effective sighash; wallet_id; and all policy warnings. Exact
pagination, layout, and timeouts remain OPEN (QK-LIM-TUI families).

**QK-F3-PSBT-024** — A review commitment field inventory is REQUIRED
(section 8). Its byte serialization, hash choice, and domain
separation remain OPEN (D-09). Revalidation MUST prove exact equality
to the approved future commitment and MUST forbid substituting
T1-review facts for T2-sign facts in either direction. Revalidation
operates on the trusted core's retained exact imported byte sequence
only; it MUST NOT reread QR, SD, or any other mutable media or
transport source, because a media reread would reintroduce the
substitution window the commitment exists to close.

**QK-F3-PSBT-025** — Future signer output, exact allowed-delta rule:
the signer MAY add only missing partial-signature key/value records
for the explicitly authorized active signer-role set; it MUST NOT
replace, remove, semantically reorder, or mutate any pre-existing
accepted record or any unsigned-transaction fact. Same-signer rule:
when an accepted valid partial signature for an active signer pubkey
is already present, QuietKey adds NO replacement or duplicate record
for that full key; it may sign only genuinely missing authorized-role
records. Distinct expected cosigner signatures remain normal
(QK-F3-PSBT-015). Every signature record the signer inserts MUST
itself satisfy the strict-DER-plus-one-trailing-sighash-byte encoding
rule of QK-F3-PSBT-015, and produced signatures MUST be emitted low-S
under the same proposed v1 relay/interoperability policy. The
independent reparse MUST additionally prove that the
produced-signature record bytes in the reparsed export are exactly the
records already verified (or verify them directly from the reparsed
output); a produced-signature-record mismatch is its own fatal class. Byte-preservation rule for export: the
exported object MUST preserve every pre-existing accepted byte and the
original map/record order exactly, with the ONLY permitted difference
being the insertion of the authorized new partial-signature records;
no re-serialization, reordering, CompactSize re-encoding, or
normalization of pre-existing content is permitted. It MUST verify
every signature it produces, MUST independently reparse the exact
exported object and prove the exact allowed delta, and MUST export a
newly named signed PSBT over each authorized route.
Produced-signature verification failure, output-reparse failure, and
export-delta violation are separate, independently fatal failure
classes. Exact naming and atomic-write policy remain OD-05/OD-06 OPEN.

## 7. Appended clauses (031–034; appended without renumbering)

**QK-F3-PSBT-031** — Checked arithmetic and monetary range. ALL
arithmetic over sizes, counts, lengths, depths, indices, values, sums,
fees, weights, and derived resource products MUST be checked, failing
closed on overflow or underflow, at every computation and comparison.
ALL monetary amounts MUST be enforced within the valid Bitcoin
monetary range at every computation and comparison. The valid Bitcoin
monetary range (Bitcoin Core MoneyRange) is exactly 0 to
2,100,000,000,000,000 satoshis inclusive, applied to every individual
amount and every intermediate and final sum. This clause maps
QK-REQ-PSBT-007 and QK-REQ-PSBT-008 into this profile.

**QK-F3-PSBT-032** — Approval binding and invalidation. Physical
approval MUST be bound, via the canonical review commitment
(section 8), to the exact imported input bytes, the exact factor
combination and factor/card session identities, all available D and
wallet_id copies and card roles and signer-derived public keys, the
active signer-role set, the media/session identity, the profile
identifier/version and selected candidate-policy context, and the
loaded descriptor pair. ANY input, card, media, factor, session,
state, descriptor, wallet_id, profile, or policy-context change after
approval INVALIDATES that approval and forces a full reparse and
review.

Agreement precondition (QK-REQ-BND-001, enforced, not merely cited):
BEFORE review-object construction/approval and again BEFORE signing,
for each permitted active factor combination A1+B, A1+C, and B+C,
every available D copy, wallet_id value, card role, signer-derived
public key, and the selected descriptor/wallet-policy context MUST
mutually agree with the selected descriptor. Missing required
comparison material or ANY mismatch MUST fail closed before
approval/signing: no review approval and no signing authority is
produced. Only the agreed values may then be placed in the approval
commitment. A stable mismatch is still fatal; invalidation-on-change
is not a substitute for this precondition. This clause maps
QK-REQ-BND-001, QK-REQ-BND-002, and QK-REQ-BND-003 into this profile.

**QK-F3-PSBT-033** — Output mutation and replacement-policy semantics.
The only permitted output delta is the allowed-delta rule of
QK-F3-PSBT-025. Sequence handling while no pinned owner-approved
replacement policy exists (D-12 OPEN): the review MUST display each
raw nSequence value exactly, MUST display the literal status
"replacement policy not evaluated", and MUST NOT derive or show any
opt-in signaling implication or any replaceability inference. Only
after a separate pinned owner-approved policy exists MAY a derived
signal be shown, and it MUST never be presented as a guarantee of
network replaceability. Encoded relative-lock (BIP 68) meaning, stated
for D-12 exactly: relative lock-time is consensus-active only when the
transaction version is 2 or greater AND the per-input disable bit
(bit 31) is clear; when active, the masked low 16 bits of nSequence
encode the relative lock value, interpreted as blocks when the
type flag (bit 22) is 0 and as 512-second units when bit 22 is 1.
This is the encoded meaning only — an offline signer evaluates no
chain state and reports chain-state satisfaction as UNKNOWN.
Absolute-lock (nLockTime) meaning, stated for D-12 exactly: nLockTime
is a TRANSACTION-LEVEL field, never per-input. nLockTime=0 means no
absolute lock. For nonzero nLockTime, values below 500,000,000 are
height-class and values at or above 500,000,000 are time-class;
finality uses a strict less-than comparison of nLockTime against the
applicable chain context, and per BIP 113 the time-class context is
the prior-block median time past. An otherwise-unsatisfied nonzero
nLockTime is ignored ONLY when EVERY input has nSequence=0xffffffff;
with any non-final input present, the transaction-level absolute lock
remains active until satisfied. The offline signer has no trustworthy
current height, median time past, mempool, or chain-state fact, so
lock satisfaction is always reported UNKNOWN. BIP 68 relative-lock
interpretation applies ONLY when the transaction version is 2 or
greater and disable bit 31 is clear, as stated above — encoded
semantics only, satisfaction UNKNOWN. BIP 125 DIRECT opt-in signaling
is interpreted separately: an input signals when its nSequence is
below 0xfffffffe; this is mempool policy, never consensus, and
inherited signaling, ancestry, full-RBF/peer policy, and actual
replaceability are unavailable/UNKNOWN — network replaceability is
never promised. The same
raw nSequence value MUST be evaluated separately for each of its three
distinct roles — transaction-level nLockTime finality (via the
all-inputs-final exception above), BIP 68 relative lock encoding,
and BIP 125 replacement signaling — which overlap in encoding but are
never interchangeable. Produced-signature
verification failure and output-reparse failure are distinct failure
classes, each independently fatal (see also QK-F3-PSBT-025's
export-delta violation class).

**QK-F3-PSBT-034** — Accepted typed-field encoding validation. Before
any semantic use, every explicitly allowed BIP174 typed field — in the
global, input, and output scopes alike — MUST satisfy the exact
keydata and value serialization rules of the pinned BIP 174 text and
pinned type registry for that field: required or forbidden keydata,
exact/fixed-width or structurally constrained value forms, minimally
encoded CompactSize wherever applicable, and full value consumption
with no unconsumed bytes. A malformed accepted-type field REJECTS
before any ownership, fee, review, or signing logic runs. This
obligation applies only to fields the closed-world allowlist accepts;
profile-rejected key types remain rejected by that allowlist and are
not thereby accepted or validated.

Allowed-field schema matrix (every field the v1 closed-world matrices
mark PROPOSED REQUIRED or PROPOSED OPTIONAL-VALIDATE; keydata and
value categories are stated by reference to the pinned BIP 174 text
and pinned type registry; numeric widths below were verified against
the pinned primary source; no third-party prose or bytes are copied):

| Allowed field (scope, type) | Keydata rule | Value rule | Consumption | Semantic follow-on | Planned negative coverage |
|---|---|---|---|---|---|
| GLOBAL: PSBT_GLOBAL_UNSIGNED_TX 0x00 | keydata FORBIDDEN (no key data) | network-serialized transaction in the old format without witnesses, every scriptSig empty | exact full consumption of the inner serialization | QK-F3-PSBT-009 admissibility | QK-F3-PLAN-071, -074 |
| GLOBAL: PSBT_GLOBAL_XPUB 0x01 (only if D-02 accepts) | keydata REQUIRED: 78-byte serialized extended public key (BIP 32) | 4-byte fingerprint then 32-bit little-endian path elements; element count MUST match the xpub depth | full value consumption | QK-F3-PSBT-013 (D-02) | QK-F3-PLAN-071 |
| GLOBAL: version field 0xFB | keydata FORBIDDEN (no key data) | 32-bit little-endian unsigned integer; exactly zero if present | exact fixed width | QK-F3-PSBT-006 | QK-F3-PLAN-071 (with -008, -035, -036) |
| INPUT: PSBT_IN_NON_WITNESS_UTXO 0x00 | keydata FORBIDDEN (no key data) | full previous transaction in network serialization | exact full consumption | QK-F3-PSBT-011 | QK-F3-PLAN-072 |
| INPUT: PSBT_IN_WITNESS_UTXO 0x01 | keydata FORBIDDEN (no key data) | 64-bit little-endian amount, CompactSize scriptPubKey length, scriptPubKey bytes | full value consumption; minimal CompactSize | QK-F3-PSBT-011 | QK-F3-PLAN-072 |
| INPUT: PSBT_IN_PARTIAL_SIG 0x02 | keydata REQUIRED: the corresponding public key | signature bytes as they would be pushed to the stack: strict-DER ECDSA per BIP 66 plus exactly one trailing sighash byte (proposed low-S policy per QK-F3-PSBT-015) | full value consumption | QK-F3-PSBT-015, -025 | QK-F3-PLAN-072, -078, -079 |
| INPUT: PSBT_IN_SIGHASH_TYPE 0x03 | keydata FORBIDDEN (no key data) | 32-bit little-endian unsigned integer | exact fixed width | QK-F3-PSBT-014 | QK-F3-PLAN-072 |
| INPUT: PSBT_IN_WITNESS_SCRIPT 0x05 | keydata FORBIDDEN (no key data) | witnessScript bytes | full value consumption | QK-F3-PSBT-012 | QK-F3-PLAN-072 |
| INPUT: PSBT_IN_BIP32_DERIVATION 0x06 | keydata REQUIRED: the public key | 4-byte fingerprint then 32-bit little-endian path elements (value length an exact multiple of 4 bytes after the fingerprint) | full value consumption | QK-F3-PSBT-013 | QK-F3-PLAN-072 |
| OUTPUT: PSBT_OUT_WITNESS_SCRIPT 0x01 | keydata FORBIDDEN (no key data) | witnessScript bytes | full value consumption | QK-F3-PSBT-012, -019 | QK-F3-PLAN-073 |
| OUTPUT: PSBT_OUT_BIP32_DERIVATION 0x02 | keydata REQUIRED: the public key | 4-byte fingerprint then zero or more 32-bit little-endian path elements (value length an exact multiple of 4 bytes after the fingerprint, per the pinned BIP 174 text) | full value consumption | QK-F3-PSBT-013, -019 | QK-F3-PLAN-073 |

## 8. Canonical review-object field inventory (not a struct)

**QK-F3-PSBT-026** — Field inventory with future-core origin. This is
an inventory, not a struct and not a serialization. Serialization and
hash remain OPEN (D-09). Because the v1 candidate rejects unknown and
proprietary fields (QK-F3-PSBT-018), no accepted opaque field exists
outside this commitment.

| Review/commitment field | Sole permitted future source |
|---|---|
| profile identifier/version and selected candidate-policy context | future qk-core profile registry |
| immutable digest of the exact original imported PSBT byte sequence, computed BEFORE any parsing re-encoding, map reordering, CompactSize normalization, or serialization — a digest of a reserialized equivalent object is not the imported-bytes digest (hash algorithm and domain separation remain D-09 OPEN) | future qk-core digest of the bytes as imported |
| canonical descriptor pair commitment and wallet_id (QK-REQ-CUS-006) | loaded descriptor context in future qk-core |
| factor combination and factor/card session identities | future qk-core session state (QK-REQ-BND-001) |
| all available D/wallet_id copies, card roles, signer-derived public keys | future qk-core factor verification (QK-REQ-BND-001) |
| active signer-role set | future qk-core session policy |
| media/session identity | future qk-core transport session state |
| network | canonical mainnet context in future qk-core |
| unsigned tx version and raw nLockTime, plus whether absolute locktime is active or disabled by all-final sequences, and the height-versus-time locktime class | future qk-core parse (encoded meaning only; chain-state satisfaction never claimed) |
| per-input deterministic BIP 68 interpretation where applicable (version threshold, disable bit 31, type bit 22, masked relative value; blocks vs 512-second units), chain-state status UNKNOWN; BIP 125 signaling as mempool signaling only, presentation per D-12 | future qk-core parse and encoding interpretation (QK-F3-PSBT-033, D-12) |
| explicit positions: global scope plus each input map index and each output map index, binding every input's and output's index alongside its facts (explicit, not merely implied by original order; encoding remains D-09 OPEN) | future qk-core parse (order- and index-preserving) |
| per-input outpoint, full-prevtx-committed prevout value and script (commitment only; no chain-state claim) | future qk-core parse + full-prevtx commitment validation (QK-F3-PSBT-011) |
| per-input ownership evidence | future qk-core descriptor/derivation computation |
| per-input raw sequence, displayed exactly with the literal status "replacement policy not evaluated" while D-12 remains OPEN | future qk-core parse |
| per-input effective sighash | future qk-core parse and policy check (QK-F3-PSBT-014) |
| per-input, per-pubkey existing-signature state | future qk-core cryptographic verification (future) |
| per-output value, script, rendered destination | future qk-core parse + script interpretation under mainnet context |
| per-output classification and proof | future qk-core change/self-transfer proof from D |
| total input / total output sums | future qk-core checked arithmetic (QK-F3-PSBT-031) |
| exact absolute fee | future qk-core checked subtraction of authenticated sums |
| fee-rate status and method | future qk-core; method itself OPEN (D-08) |
| policy verdict and warnings | future qk-core policy evaluation |

Factor, card, media, and session identities included in the approval
commitment are NON-SECRET identifiers or domain-separated
commitments/digests only. They MUST never contain, serialize, log, or
expose seed material, private keys, A2, card secret state, session
secrets, or any other secret value. Exact privacy-preserving encoding
remains D-09 OPEN.

Any change to any bound identity or fact after approval invalidates
approval per QK-F3-PSBT-032.

## 9. Proposed reject-reason taxonomy (stable, no numeric codes yet)

**QK-F3-PSBT-027** — Proposed reject-reason classes: bad envelope,
bad magic, bad version; nonminimal CompactSize; duplicate full key;
malformed, truncated, or trailing bytes; map-count mismatch;
unsigned-transaction script/witness violation; missing prevout;
prevout txid mismatch; prevout index out of range; prevout
output/witness_utxo mismatch; unsupported or mismatched script;
foreign wallet, descriptor, origin, or derivation mismatch;
unsupported sighash; invalid or foreign existing signature;
finalized-field conflict; unknown field; proprietary field (including
malformed 0xFC); v2-only field in v0; ambiguous or spoofed change;
unsupported output; amount range, overflow, or underflow; fee
inconsistency; over-limit symbolic class; inadmissible unsigned
transaction (zero inputs; zero outputs; null or coinbase-form
outpoint; duplicate input outpoint); malformed accepted-type field
(QK-F3-PSBT-034); factor/card agreement precondition failure
(QK-F3-PSBT-032); commitment/revalidation
mismatch; approval-binding invalidation; full-prevtx-committed
prevout/P2WSH commitment mismatch (QK-F3-PSBT-012), meaning the
prevout committed by the supplied full transaction and referenced
txid, never chain existence, confirmation, or unspentness; common
branch/index mismatch
(QK-F3-PSBT-013); malformed/non-strict DER signature encoding;
high-S proposed-policy rejection (QK-F3-PSBT-015);
registered-but-profile-ineligible field; forbidden output
mutation/removal/reorder (QK-F3-PSBT-025); produced-signature-record
mismatch; produced-signature
verification failure; output-reparse failure. This taxonomy is
proposed only and carries no numeric codes yet.

Acceptance-time obligation: The profile MUST NOT be accepted until
every QK-F3-PLAN-001..090 maps to one or more approved canonical
QK-TST IDs through separately authorized canonical edits. Mapping
alone neither runs tests nor creates evidence; no canonical register
is edited now.

## 10. Traceability matrix

**QK-F3-PSBT-028** — Every canonical ID below maps to exact proposed
clause(s) or an explicit OUT OF THIS PROFILE / OPEN status, from the
canonical text of docs/REQUIREMENTS.md. Canonical status is not
modified here.

| Canonical ID | Proposed clause(s) / status |
|---|---|
| QK-REQ-PSBT-001 (v0 only) | QK-F3-PSBT-001, -006, -009 |
| QK-REQ-PSBT-002 (trusted-core reparse of hostile bytes) | QK-F3-PSBT-004, -005 |
| QK-REQ-PSBT-003 (sign only after reparse, review, physical approval) | QK-F3-PSBT-005, -024, -032 |
| QK-REQ-PSBT-004 (verify every produced signature; independently parseable output) | QK-F3-PSBT-025, -033 |
| QK-REQ-PSBT-005 (all sizes/counts/budgets bounded by approved limits) | QK-F3-PSBT-009; every bound QK-LIM OPEN |
| QK-REQ-PSBT-006 (reject policy/prevout/derivation/change/sighash/fee/signature inconsistencies) | QK-F3-PSBT-010, -011, -012, -013, -014, -015, -019, -022 |
| QK-REQ-PSBT-007 (checked arithmetic, fail closed) | QK-F3-PSBT-031 |
| QK-REQ-PSBT-008 (valid Bitcoin monetary range everywhere) | QK-F3-PSBT-031 |
| QK-REQ-TRN-001 (binary `.psbt` only, no autodetection) | QK-F3-PSBT-001, -002 |
| QK-REQ-TRN-002 (never overwrite any input file) | QK-F3-PSBT-025; write lifecycle OD-05/OD-06 OPEN |
| QK-REQ-TRN-003 (uncompressed BBQr type P only) | QK-F3-PSBT-001; transport bounds OUT OF THIS PROFILE |
| QK-REQ-TRN-004 (transport parsing unprivileged in qk-io) | QK-F3-PSBT-003 |
| QK-REQ-TRN-005 (QR reassembly bounds) | OUT OF THIS PROFILE (transport limits; QK-LIM-QR OPEN) |
| QK-REQ-TRN-006 (SD intake bounds) | OUT OF THIS PROFILE (transport limits; QK-LIM-SD OPEN) |
| QK-REQ-TRN-007 (signed-PSBT export over both routes) | QK-F3-PSBT-001, -016, -025 (inherited minimum) |
| QK-REQ-TRN-008 (incomplete output never presented complete) | QK-F3-PSBT-025, -033; OD-05/OD-06 OPEN |
| QK-REQ-TRN-009 (no trusted-kernel mount of hostile SD metadata) | OUT OF THIS PROFILE (OD-06 transport design) |
| QK-REQ-TRN-010 (bounded read-only SD design) | OUT OF THIS PROFILE (OD-06 OPEN) |
| QK-REQ-TUI-001 (trusted display/keypad owned by qk-core) | OUT OF THIS PROFILE (trusted-UI ownership, cited context only) |
| QK-REQ-TUI-002 (review presents exactly the core's own reparse) | QK-F3-PSBT-004, -023, -024 |
| QK-REQ-TUI-003 (review pagination/timeouts bounded) | QK-F3-PSBT-023; QK-LIM-TUI OPEN |
| QK-REQ-TUI-004 (no malicious-terminal protection claim) | QK-F3-PSBT-002 (claims prohibition respected) |
| QK-REQ-BND-001 (factor/wallet_id/card-role/public-key agreement) | QK-F3-PSBT-032 (agreement precondition, fail-closed before approval/signing), -026 |
| QK-REQ-BND-002 (approval bound to exact input bytes and sessions) | QK-F3-PSBT-024, -026, -032 |
| QK-REQ-BND-003 (any post-approval change invalidates approval) | QK-F3-PSBT-032 |
| QK-REQ-CUS-001 (P2WSH sortedmulti(2,A,B,C) mainnet only) | QK-F3-PSBT-001, -010 |
| QK-REQ-CUS-006 (wallet_id computation) | QK-F3-PSBT-026 (commitment row; computation cited, not restated) |
| QK-THR (transport/coordinator deception family) | QK-F3-PSBT-003, -004, -011, -019, -021 |
| QK-THR (substitution/replay family) | QK-F3-PSBT-024, -032; F4.1 symbolic model |
| QK-THR (malformed-input family) | QK-F3-PSBT-009, -018, -027, -034 |
| OD-05 | QK-F3-PSBT-016, -022, -023, -025; remains OPEN |
| OD-06 | QK-F3-PSBT-025; remains OPEN |
| QK-LIM (size/count/value families) | QK-F3-PSBT-009, -020, -022, -031; every family remains OPEN |

## 11. Future test-plan matrix (metadata only — no bytes, no vectors)

**QK-F3-PSBT-029** — Metadata-only plan. Every entry is symbolic; no
hex, base64, binary, address, mnemonic, xpub, fingerprint, real or
funded data, generated vector, or run result exists anywhere in this
repository for this plan. Plan IDs are contiguous QK-F3-PLAN-001
through QK-F3-PLAN-090 (075–090 appended by F3.1a without
renumbering). Every status is exactly
PLANNED — NOT GENERATED — NOT RUN. Bitcoin Core `decodepsbt` appears
below strictly as a limited decode/interoperability oracle only —
never an ownership, descriptor, authorization, review, or
QuietKey-policy oracle.

| Plan ID | Clause | Class | Symbolic construction recipe | Expected proposed disposition | Independent oracle plan | Status |
|---|---|---|---|---|---|---|
| QK-F3-PLAN-001 | QK-F3-PSBT-010 | positive | base native P2WSH 2-of-3 spend, one recipient, one change | accept for review | future independent parser + Bitcoin Core decodepsbt as limited decode/interoperability oracle only | PLANNED — NOT GENERATED — NOT RUN |
| QK-F3-PLAN-002 | QK-F3-PSBT-019 | positive | valid spend with no change output | accept; all non-self outputs classified recipient | same oracle plan as QK-F3-PLAN-001 | PLANNED — NOT GENERATED — NOT RUN |
| QK-F3-PLAN-003 | QK-F3-PSBT-020 | positive | valid spend with multiple recipient outputs | accept within OPEN limits | same oracle plan as QK-F3-PLAN-001 | PLANNED — NOT GENERATED — NOT RUN |
| QK-F3-PLAN-004 | QK-F3-PSBT-015 | positive | valid spend carrying the expected other cosigner's partial signature | accept; never rejected for its presence | future signature verification oracle | PLANNED — NOT GENERATED — NOT RUN |
| QK-F3-PLAN-005 | QK-F3-PSBT-009 | positive | valid spend with shuffled key-value order within maps | accept; order-independent parse | future independent parser | PLANNED — NOT GENERATED — NOT RUN |
| QK-F3-PLAN-006 | QK-F3-PSBT-018 | adversarial | valid spend plus unknown/proprietary fields (v1 candidate) | reject: unknown/proprietary field | future independent parser | PLANNED — NOT GENERATED — NOT RUN |
| QK-F3-PLAN-007 | QK-F3-PSBT-009 | adversarial | wrong magic prefix | reject: bad magic | future independent parser | PLANNED — NOT GENERATED — NOT RUN |
| QK-F3-PLAN-008 | QK-F3-PSBT-006 | adversarial | version field present and nonzero | reject: bad version | future independent parser | PLANNED — NOT GENERATED — NOT RUN |
| QK-F3-PLAN-009 | QK-F3-PSBT-009 | adversarial | truncated map section | reject: truncated | future independent parser | PLANNED — NOT GENERATED — NOT RUN |
| QK-F3-PLAN-010 | QK-F3-PSBT-009 | adversarial | valid body plus trailing bytes | reject: trailing bytes | future independent parser | PLANNED — NOT GENERATED — NOT RUN |
| QK-F3-PLAN-011 | QK-F3-PSBT-009 | adversarial | malformed CompactSize length | reject: malformed | future independent parser | PLANNED — NOT GENERATED — NOT RUN |
| QK-F3-PLAN-012 | QK-F3-PSBT-009 | adversarial | nonminimally encoded CompactSize | reject: nonminimal CompactSize | future independent parser | PLANNED — NOT GENERATED — NOT RUN |
| QK-F3-PLAN-013 | QK-F3-PSBT-009 | adversarial | duplicate full key within one map | reject: duplicate full key | future independent parser | PLANNED — NOT GENERATED — NOT RUN |
| QK-F3-PLAN-014 | QK-F3-PSBT-009 | adversarial | input/output map count differing from unsigned tx | reject: map-count mismatch | future independent parser | PLANNED — NOT GENERATED — NOT RUN |
| QK-F3-PLAN-015 | QK-F3-PSBT-009 | adversarial | unsigned tx with nonempty input scriptSig | reject: unsigned-tx violation | future independent parser | PLANNED — NOT GENERATED — NOT RUN |
| QK-F3-PLAN-016 | QK-F3-PSBT-009 | adversarial | unsigned tx serialized with witness data | reject: unsigned-tx violation | future independent parser | PLANNED — NOT GENERATED — NOT RUN |
| QK-F3-PLAN-017 | QK-F3-PSBT-011 | adversarial | input missing witness_utxo | reject: missing prevout | future independent parser | PLANNED — NOT GENERATED — NOT RUN |
| QK-F3-PLAN-018 | QK-F3-PSBT-011 | adversarial | non_witness_utxo indexed output conflicting with witness_utxo | reject: prevout output/witness_utxo mismatch | future independent parser | PLANNED — NOT GENERATED — NOT RUN |
| QK-F3-PLAN-019 | QK-F3-PSBT-012 | adversarial | witness_script differing from descriptor derivation | reject: mismatched script | future descriptor-derivation oracle | PLANNED — NOT GENERATED — NOT RUN |
| QK-F3-PLAN-020 | QK-F3-PSBT-013 | adversarial | derivation path/fingerprint mismatch against D | reject: derivation mismatch | future descriptor-derivation oracle | PLANNED — NOT GENERATED — NOT RUN |
| QK-F3-PLAN-021 | QK-F3-PSBT-013 | adversarial | global xpub not matching D | reject: wallet mismatch | future descriptor-derivation oracle | PLANNED — NOT GENERATED — NOT RUN |
| QK-F3-PLAN-022 | QK-F3-PSBT-010 | adversarial | one foreign (non-D) input mixed into an owned spend | reject: foreign input | future descriptor-derivation oracle | PLANNED — NOT GENERATED — NOT RUN |
| QK-F3-PLAN-023 | QK-F3-PSBT-014 | adversarial | sighash other than ALL | reject: unsupported sighash | future independent parser | PLANNED — NOT GENERATED — NOT RUN |
| QK-F3-PLAN-024 | QK-F3-PSBT-012 | adversarial | redeem_script present (nested/legacy form) | reject: unsupported script | future independent parser | PLANNED — NOT GENERATED — NOT RUN |
| QK-F3-PLAN-025 | QK-F3-PSBT-020 | adversarial | recipient output with unsupported script class | reject: unsupported output | future independent parser | PLANNED — NOT GENERATED — NOT RUN |
| QK-F3-PLAN-026 | QK-F3-PSBT-015 | adversarial | structurally invalid or foreign partial signature | reject: invalid existing signature | future signature verification oracle | PLANNED — NOT GENERATED — NOT RUN |
| QK-F3-PLAN-027 | QK-F3-PSBT-016 | adversarial | final scriptSig/final witness present on an input | reject: finalized-field conflict | future independent parser | PLANNED — NOT GENERATED — NOT RUN |
| QK-F3-PLAN-028 | QK-F3-PSBT-019 | adversarial | coordinator-labeled change not proven from D change branch | reject: spoofed change | future descriptor-derivation oracle | PLANNED — NOT GENERATED — NOT RUN |
| QK-F3-PLAN-029 | QK-F3-PSBT-019 | adversarial | conflicting ownership evidence on one output | reject: ambiguous change | future descriptor-derivation oracle | PLANNED — NOT GENERATED — NOT RUN |
| QK-F3-PLAN-030 | QK-F3-PSBT-031 | adversarial | symbolic amount-sum overflow/underflow construction | reject: amount overflow/underflow | future checked-arithmetic oracle | PLANNED — NOT GENERATED — NOT RUN |
| QK-F3-PLAN-031 | QK-F3-PSBT-022 | adversarial | output sum exceeding authenticated input sum | reject: fee inconsistency | future checked-arithmetic oracle | PLANNED — NOT GENERATED — NOT RUN |
| QK-F3-PLAN-032 | QK-F3-PSBT-024 | adversarial | symbolic commitment substitution between review and sign | reject: commitment/revalidation mismatch | F4.1 symbolic model plus future commitment oracle | PLANNED — NOT GENERATED — NOT RUN |
| QK-F3-PLAN-033 | QK-F3-PSBT-033 | adversarial | symbolic produced-signature verification failure | reject: produced-signature verification failure | future signature verification oracle | PLANNED — NOT GENERATED — NOT RUN |
| QK-F3-PLAN-034 | QK-F3-PSBT-009 | adversarial | every future limit-boundary class, symbolically (at, below, above each future QK-LIM bound) | reject above bound; at/below a bound means not rejected solely by that limit, never blanket acceptance | future limit-matrix oracle; every bound remains OPEN | PLANNED — NOT GENERATED — NOT RUN |
| QK-F3-PLAN-035 | QK-F3-PSBT-006 | positive | version field omitted entirely | accept (v0 by omission) | future independent parser | PLANNED — NOT GENERATED — NOT RUN |
| QK-F3-PLAN-036 | QK-F3-PSBT-006 | positive | version field present and explicitly zero | accept | future independent parser | PLANNED — NOT GENERATED — NOT RUN |
| QK-F3-PLAN-037 | QK-F3-PSBT-009 | positive | same key type with distinct full keys (distinct keydata) in one map | accept; full-key uniqueness satisfied | future independent parser | PLANNED — NOT GENERATED — NOT RUN |
| QK-F3-PLAN-038 | QK-F3-PSBT-007 | adversarial | each v2-only input field 0x0e, 0x0f, 0x10, 0x11, 0x12 present in a v0 PSBT, one case per field | reject: v2-only field in v0 | future independent parser | PLANNED — NOT GENERATED — NOT RUN |
| QK-F3-PLAN-039 | QK-F3-PSBT-006 | adversarial | known v2-only global and output fields present in a v0 PSBT | reject: v2-only field in v0 | future independent parser | PLANNED — NOT GENERATED — NOT RUN |
| QK-F3-PLAN-040 | QK-F3-PSBT-011 | adversarial | input missing the full previous transaction (non_witness_utxo absent under both-UTXO candidate) | reject: missing prevout | future independent parser | PLANNED — NOT GENERATED — NOT RUN |
| QK-F3-PLAN-041 | QK-F3-PSBT-011 | adversarial | non_witness_utxo whose txid differs from the unsigned tx input prevout txid | reject: prevout txid mismatch | future independent parser | PLANNED — NOT GENERATED — NOT RUN |
| QK-F3-PLAN-042 | QK-F3-PSBT-011 | adversarial | prevout vout index out of range of the supplied previous transaction | reject: prevout index out of range | future independent parser | PLANNED — NOT GENERATED — NOT RUN |
| QK-F3-PLAN-043 | QK-F3-PSBT-011 | adversarial | indexed previous output amount or scriptPubKey differing from witness_utxo | reject: prevout output/witness_utxo mismatch | future independent parser | PLANNED — NOT GENERATED — NOT RUN |
| QK-F3-PLAN-044 | QK-F3-PSBT-011 | adversarial | repeated-signing/value-spoofing construction: witness-only value lie with no authenticating full prevtx | reject under both-UTXO candidate: missing/unauthenticated prevout | future independent parser + threat-model review | PLANNED — NOT GENERATED — NOT RUN |
| QK-F3-PLAN-045 | QK-F3-PSBT-018 | adversarial | unknown key type present, one case per scope (global, input, output) | reject: unknown field | future independent parser | PLANNED — NOT GENERATED — NOT RUN |
| QK-F3-PLAN-046 | QK-F3-PSBT-018 | adversarial | proprietary 0xFC present, one case per scope, including a malformed 0xFC internal structure | reject: proprietary field | future independent parser | PLANNED — NOT GENERATED — NOT RUN |
| QK-F3-PLAN-047 | QK-F3-PSBT-014 | positive | per-input sighash absent under the candidate absent=>ALL default | accept only if the D-03 default is separately accepted; otherwise disposition follows D-03 | future independent parser | PLANNED — NOT GENERATED — NOT RUN |
| QK-F3-PLAN-048 | QK-F3-PSBT-014 | adversarial | wrong sighash on one input among several valid inputs | reject: unsupported sighash | future independent parser | PLANNED — NOT GENERATED — NOT RUN |
| QK-F3-PLAN-049 | QK-F3-PSBT-015 | adversarial | existing signature whose trailing sighash byte mismatches that input's effective sighash | reject: invalid existing signature | future signature verification oracle | PLANNED — NOT GENERATED — NOT RUN |
| QK-F3-PLAN-050 | QK-F3-PSBT-015 | positive | multiple partial signatures under distinct expected full keys on one input | accept; structurally valid | future signature verification oracle | PLANNED — NOT GENERATED — NOT RUN |
| QK-F3-PLAN-051 | QK-F3-PSBT-015 | adversarial | already threshold-signed PSBT presented for signing | disposition D-03 OPEN; never silently signed | future signature verification oracle | PLANNED — NOT GENERATED — NOT RUN |
| QK-F3-PLAN-052 | QK-F3-PSBT-032 | adversarial | T1/T2 exact imported-input-byte mutation between review and sign | approval invalidated; reject: approval-binding invalidation | F4.1 symbolic model plus future commitment oracle | PLANNED — NOT GENERATED — NOT RUN |
| QK-F3-PLAN-053 | QK-F3-PSBT-032 | adversarial | factor, card, media, session, or state change after approval | approval invalidated; full reparse/review forced | F4.1 symbolic model plus future commitment oracle | PLANNED — NOT GENERATED — NOT RUN |
| QK-F3-PLAN-054 | QK-F3-PSBT-032 | adversarial | descriptor, wallet_id, profile, or policy-context change after approval | approval invalidated; full reparse/review forced | F4.1 symbolic model plus future commitment oracle | PLANNED — NOT GENERATED — NOT RUN |
| QK-F3-PLAN-055 | QK-F3-PSBT-031 | adversarial | symbolic checked-arithmetic and Bitcoin monetary-range boundary constructions (value above maximum money; negative; sum overflow) | reject: amount range/overflow/underflow | future checked-arithmetic oracle | PLANNED — NOT GENERATED — NOT RUN |
| QK-F3-PLAN-056 | QK-F3-PSBT-033 | positive | inputs with varying raw nSequence values | disposition follows unresolved D-12 in explicit phases: while D-12 remains OPEN, no transaction disposition and no accept path exists, each raw nSequence is represented exactly with the literal status "replacement policy not evaluated", and no derived replacement inference is made; if Alternative A is later owner-accepted and every other rule passes, review/display each raw nSequence exactly plus only the approved derived temporal/policy facts authorized by the accepted D-12 policy, the "replacement policy not evaluated" label is retired unconditionally for that phase, and actual/network replaceability remains UNKNOWN and is never guaranteed; if Alternative B is later accepted, reject the owner-selected active temporal/policy patterns (including direct BIP125 signaling); currently no outcome is selected; raw-value fidelity always required | future independent parser | PLANNED — NOT GENERATED — NOT RUN |
| QK-F3-PLAN-057 | QK-F3-PSBT-033 | adversarial | symbolic output-reparse failure of the exact exported object | reject: output-reparse failure | future independent parser | PLANNED — NOT GENERATED — NOT RUN |
| QK-F3-PLAN-058 | QK-F3-PSBT-018 | adversarial | registered-but-unsupported global field PSBT_GLOBAL_GENERIC_SIGNED_MESSAGE 0x09 present (registered/valid generally; profile-ineligible) | reject: field not explicitly allowed by this profile | future independent parser | PLANNED — NOT GENERATED — NOT RUN |
| QK-F3-PLAN-059 | QK-F3-PSBT-018 | adversarial | registered-but-unsupported input field PSBT_IN_POR_COMMITMENT 0x09 present (registered/valid generally; profile-ineligible) | reject: field not explicitly allowed by this profile | future independent parser | PLANNED — NOT GENERATED — NOT RUN |
| QK-F3-PLAN-060 | QK-F3-PSBT-018 | adversarial | registered-but-unsupported output field PSBT_OUT_DNSSEC_PROOF 0x35 present (registered/valid generally; profile-ineligible) | reject: field not explicitly allowed by this profile | future independent parser | PLANNED — NOT GENERATED — NOT RUN |
| QK-F3-PLAN-061 | QK-F3-PSBT-018 | adversarial | exhaustive sweep of EVERY matrix-enumerated registered MuSig2 field, one case each: PSBT_IN_MUSIG2_PARTICIPANT_PUBKEYS 0x1a, PSBT_IN_MUSIG2_PUB_NONCE 0x1b, PSBT_IN_MUSIG2_PARTIAL_SIG 0x1c, PSBT_OUT_MUSIG2_PARTICIPANT_PUBKEYS 0x08 (registered/valid generally; profile-ineligible) | reject each: field not explicitly allowed by this profile (profile-reject; not a claim of malformed standard PSBT) | future independent parser | PLANNED — NOT GENERATED — NOT RUN |
| QK-F3-PLAN-062 | QK-F3-PSBT-018 | adversarial | exhaustive sweep of EVERY matrix-enumerated registered Silent Payments field, one case each: PSBT_GLOBAL_SP_ECDH_SHARE 0x07, PSBT_GLOBAL_SP_DLEQ 0x08, PSBT_IN_SP_ECDH_SHARE 0x1d, PSBT_IN_SP_DLEQ 0x1e, PSBT_IN_SP_SPEND_BIP32_DERIVATION 0x1f, PSBT_IN_SP_TWEAK 0x20, PSBT_OUT_SP_V0_INFO 0x09, PSBT_OUT_SP_V0_LABEL 0x0a (registered/valid generally; profile-ineligible) | reject each: field not explicitly allowed by this profile (profile-reject; not a claim of malformed standard PSBT) | future independent parser | PLANNED — NOT GENERATED — NOT RUN |
| QK-F3-PLAN-063 | QK-F3-PSBT-018 | adversarial | unregistered/unrecognized key type present, one case per scope (separate category from registered-but-unsupported) | reject: unregistered/unrecognized key type | future independent parser | PLANNED — NOT GENERATED — NOT RUN |
| QK-F3-PLAN-064 | QK-F3-PSBT-025 | adversarial | attempted replacement or duplicate partial-signature record for an active signer full key that already carries an accepted valid signature | no delta added; replacement/duplicate rejected per the same-signer rule | F4.1 symbolic model plus future independent parser | PLANNED — NOT GENERATED — NOT RUN |
| QK-F3-PLAN-065 | QK-F3-PSBT-011 | adversarial | txid/wtxid confusion: symbolic construction whose outpoint comparison would only succeed against the wtxid or a witness-inclusive hash | reject: prevout txid mismatch (standard txid only) | future independent parser | PLANNED — NOT GENERATED — NOT RUN |
| QK-F3-PLAN-066 | QK-F3-PSBT-032 | adversarial | for each permitted factor combination A1+B, A1+C, and B+C: mismatch or missing comparison material across available D copies, wallet_id values, card roles, signer-derived public keys, or descriptor/wallet-policy context | reject: factor/card agreement precondition failure, fail closed BEFORE review approval and BEFORE signing; no approval or signing authority produced | F4.1 symbolic model plus future factor-verification oracle | PLANNED — NOT GENERATED — NOT RUN |
| QK-F3-PLAN-067 | QK-F3-PSBT-009 | adversarial | unsigned transaction with zero inputs | reject: inadmissible unsigned transaction (zero inputs) | future independent parser | PLANNED — NOT GENERATED — NOT RUN |
| QK-F3-PLAN-068 | QK-F3-PSBT-009 | adversarial | unsigned transaction with zero outputs | reject: inadmissible unsigned transaction (zero outputs) | future independent parser | PLANNED — NOT GENERATED — NOT RUN |
| QK-F3-PLAN-069 | QK-F3-PSBT-009 | adversarial | unsigned transaction containing a null outpoint / coinbase-form input | reject: inadmissible unsigned transaction (null or coinbase-form outpoint) | future independent parser | PLANNED — NOT GENERATED — NOT RUN |
| QK-F3-PLAN-070 | QK-F3-PSBT-009 | adversarial | two unsigned-transaction inputs spending the same outpoint | reject: inadmissible unsigned transaction (duplicate input outpoint) | future independent parser | PLANNED — NOT GENERATED — NOT RUN |
| QK-F3-PLAN-071 | QK-F3-PSBT-034 | adversarial | table-driven exhaustive plan over the QK-F3-PSBT-034 allowed-field schema, GLOBAL scope: for EVERY allowed global field row (unsigned transaction; global xpub; version field) future vector construction MUST include at least one malformed-keydata case and every applicable malformed-value, malformed-length, and incomplete-consumption case — not merely representatives | reject: malformed accepted-type field, before ownership/fee/review/signing logic | future independent parser | PLANNED — NOT GENERATED — NOT RUN |
| QK-F3-PLAN-072 | QK-F3-PSBT-034 | adversarial | table-driven exhaustive plan over the QK-F3-PSBT-034 allowed-field schema, INPUT scope: for EVERY allowed input field row (non_witness_utxo; witness_utxo; partial signature; sighash type; witness script; BIP32 derivation) future vector construction MUST include at least one malformed-keydata case and every applicable malformed-value, malformed-length, and incomplete-consumption case — not merely representatives | reject: malformed accepted-type field, before ownership/fee/review/signing logic | future independent parser | PLANNED — NOT GENERATED — NOT RUN |
| QK-F3-PLAN-073 | QK-F3-PSBT-034 | adversarial | table-driven exhaustive plan over the QK-F3-PSBT-034 allowed-field schema, OUTPUT scope: for EVERY allowed output field row (witness script; BIP32 derivation) future vector construction MUST include at least one malformed-keydata case and every applicable malformed-value, malformed-length, and incomplete-consumption case — not merely representatives | reject: malformed accepted-type field, before ownership/fee/review/signing logic | future independent parser | PLANNED — NOT GENERATED — NOT RUN |
| QK-F3-PLAN-074 | QK-F3-PSBT-009 | adversarial | malformed, truncated, or not-fully-consumed INNER unsigned-transaction value, distinct from outer PSBT truncation or trailing bytes | reject: inadmissible unsigned transaction (inner-transaction malformation), before map-count, ownership, fee, review, or signing logic | future independent parser | PLANNED — NOT GENERATED — NOT RUN |
| QK-F3-PLAN-075 | QK-F3-PSBT-012 | adversarial | full-prevtx-committed prevout P2WSH witness program vs supplied/derived witnessScript hash mismatch (commitment by the supplied full transaction and referenced txid only; chain existence, confirmation, and unspentness never implied) | reject: full-prevtx-committed prevout/P2WSH commitment mismatch | future descriptor-derivation oracle | PLANNED — NOT GENERATED — NOT RUN |
| QK-F3-PLAN-076 | QK-F3-PSBT-012 | adversarial | full-prevtx-committed prevout commits to a different D branch/index than the supplied derivations propose (commitment wording as in PLAN-075; no chain-state claim) | reject: full-prevtx-committed prevout/P2WSH commitment mismatch | future descriptor-derivation oracle | PLANNED — NOT GENERATED — NOT RUN |
| QK-F3-PLAN-077 | QK-F3-PSBT-013 | adversarial | A/B/C input derivation entries lacking one common descriptor branch/index coordinate | reject: common branch/index mismatch | future descriptor-derivation oracle | PLANNED — NOT GENERATED — NOT RUN |
| QK-F3-PLAN-078 | QK-F3-PSBT-015 | adversarial | BER/non-strict-DER existing partial signature | reject: malformed/non-strict DER signature encoding | future signature verification oracle | PLANNED — NOT GENERATED — NOT RUN |
| QK-F3-PLAN-079 | QK-F3-PSBT-015 | adversarial | strict-DER but high-S existing partial signature | reject: high-S proposed-policy rejection (proposed low-S policy; not consensus) | future signature verification oracle | PLANNED — NOT GENERATED — NOT RUN |
| QK-F3-PLAN-080 | QK-F3-PSBT-025 | adversarial | produced signature non-DER, high-S, or with wrong trailing sighash byte | fatal: produced-signature verification failure; no export | future signature verification oracle | PLANNED — NOT GENERATED — NOT RUN |
| QK-F3-PLAN-081 | QK-F3-PSBT-025 | adversarial | export mutates, removes, or reorders a pre-existing accepted record outside the allowed delta | fatal: forbidden output mutation/removal/reorder, proven by output reparse | future independent parser | PLANNED — NOT GENERATED — NOT RUN |
| QK-F3-PLAN-082 | QK-F3-PSBT-025 | adversarial | reparsed produced-signature record bytes differing from the already verified records | fatal: produced-signature-record mismatch | future independent parser + signature verification oracle | PLANNED — NOT GENERATED — NOT RUN |
| QK-F3-PLAN-083 | QK-F3-PSBT-024 | adversarial | attempted post-approval mutable-media reread/substitution instead of the retained exact imported bytes | reject: approval-binding invalidation / commitment revalidation failure | F4.1 symbolic model plus future commitment oracle | PLANNED — NOT GENERATED — NOT RUN |
| QK-F3-PLAN-084 | QK-F3-PSBT-031 | adversarial | monetary matrix: 0, MAX_MONEY, MAX_MONEY+1, negative amount, running-sum overflow or sum above MAX_MONEY, and negative fee | accept only in-range constructions; reject: amount range/overflow/underflow or fee inconsistency | future checked-arithmetic oracle | PLANNED — NOT GENERATED — NOT RUN |
| QK-F3-PLAN-085 | QK-F3-PSBT-033 | positive | transaction version/nLockTime activation matrix: zero/nonzero nLockTime, height-class vs time-class (500,000,000 threshold), mixed final/non-final input sequences, and the all-inputs-final transaction-level exception | disposition follows unresolved D-12: if Alternative A is later accepted and all other rules pass, interpret/display the exact encoded facts; if Alternative B is later accepted, reject the selected active temporal/policy patterns (including direct BIP125 signaling); currently no outcome is selected; chain-state satisfaction never claimed | future independent parser | PLANNED — NOT GENERATED — NOT RUN |
| QK-F3-PLAN-086 | QK-F3-PSBT-033 | positive | BIP68 matrix: version below/at least 2 threshold, disable bit 31 set/clear, type bit 22 both values (blocks vs 512-second units), masked low-16-bit relative value | disposition follows unresolved D-12: if Alternative A is later accepted and all other rules pass, interpret/display the exact encoded facts; if Alternative B is later accepted, reject the selected active temporal/policy patterns (including direct BIP125 signaling); currently no outcome is selected; never claim chain-state satisfaction | future independent parser | PLANNED — NOT GENERATED — NOT RUN |
| QK-F3-PLAN-087 | QK-F3-PSBT-033 | positive | BIP125 direct opt-in signal (nSequence below 0xfffffffe) distinguished from unavailable inherited-signaling/full-RBF/actual-replaceability state | disposition follows unresolved D-12: if Alternative A is later accepted and all other rules pass, interpret/display the exact encoded facts as mempool signaling only, never a network guarantee; if Alternative B is later accepted, reject the selected active temporal/policy patterns (including direct BIP125 signaling); currently no outcome is selected | future independent parser + threat-model review | PLANNED — NOT GENERATED — NOT RUN |
| QK-F3-PLAN-088 | QK-F3-PSBT-022 | positive | D-08 range: known existing signature lengths plus each missing signature at 9 and 72 bytes including sighash; exact checked min/max weight and vsize | fee-rate reported as RANGE or UNAVAILABLE, never exact before final witnesses | future checked-arithmetic oracle | PLANNED — NOT GENERATED — NOT RUN |
| QK-F3-PLAN-089 | QK-F3-PSBT-020 | positive | one symbolic positive case for each proposed D-05 recipient class: P2PKH, P2SH, P2WPKH, P2WSH | profile-eligible only if D-05 is later accepted and every other check passes; no acceptance implied now | future independent parser | PLANNED — NOT GENERATED — NOT RUN |
| QK-F3-PLAN-090 | QK-F3-PSBT-020 | adversarial | P2TR, OP_RETURN, bare/nonstandard, unknown witness version, or other unsupported recipient output | reject: unsupported output (explicit) | future independent parser | PLANNED — NOT GENERATED — NOT RUN |

## 12. Owner decision packet

### D-08 correction (F3.1a)

The BIP 66 serialized ECDSA signature vector INCLUDING the trailing
sighash byte is 9–73 bytes; strict low-S reduces the MAXIMUM to
72 bytes — it does not change the minimum. RECOMMENDED but NOT
ACCEPTED RANGE candidate for pre-final fee rate: start from the exact
base transaction bytes and the exact descriptor-derived native-P2WSH
final-witness template; use actual accepted existing-signature lengths
and the interval [9, 72] bytes (including sighash) for each missing
eventual low-S signature; if more than threshold valid signatures
exist, range over every valid two-signature finalizer selection;
compute checked min/max weight, vsize = ceil(weight/4), and the exact
rational fee-rate interval [fee/max_vsize, fee/min_vsize]; any decimal
display rounds the lower bound down and the upper bound up at a
separately selected precision; if any bound cannot be proven, the
status is UNAVAILABLE. D-08 asks the owner to select or revise RANGE
versus UNAVAILABLE and remains NOT ACCEPTED. Fee rate is never called
exact before final witnesses.

### Decision table

**QK-F3-PSBT-030** — Finite decision packet. Inherited decisions
(mainnet-only, PSBT v0, P2WSH sortedmulti 2-of-3, SD/BBQr transports,
signed-PSBT export over both routes; QK-DEC-002/003/009/010,
QK-REQ-TRN-007) are cited, not reopened. Every item below is
unresolved and stays NOT ACCEPTED and, where noted, OD-05 or OD-06
OPEN until an explicit owner decision. No claim is made that the
candidate bundle as a whole is already the default recommendation;
each item is decided individually. Until D-12 is selected, the profile
cannot be accepted and there is no runtime accept path. No owner item
is selected here.

| Item | Decision required (accept or revise) | Candidate reference | Readiness/Status |
|---|---|---|---|
| D-00 | Base clause bundle acceptance: accept or revise every clause obligation not otherwise covered by D-01..D-12 | sections 1–11 | finite proposed candidate; owner-open; NOT ACCEPTED |
| D-01 | Prevout policy: both-UTXO (recommended) vs witness_utxo-only with explicit provenance downgrade | QK-F3-PSBT-011 | finite proposed candidate; owner-open; NOT ACCEPTED |
| D-02 | Global xpub handling (untrusted hint, exact agreement with D). If D-02 is not selected and no replacement exists, GLOBAL_XPUB rejects under the closed-world default; no prevalence claim is made | QK-F3-PSBT-013 | finite proposed candidate; owner-open; NOT ACCEPTED |
| D-03 | Partial-signature, absent-sighash default, high-S policy family, and already-threshold-signed policy | QK-F3-PSBT-014, -015 | finite proposed candidate; owner-open; NOT ACCEPTED |
| D-04 | Unknown/proprietary policy: v1 rejection (recommended) vs future bounded preservation with structural validation and full commitment. v1 rejection rejects the WHOLE PSBT, an explicit interoperability cost; selection requires representative coordinator-corpus review | QK-F3-PSBT-018 | finite proposed candidate; owner-open; NOT ACCEPTED |
| D-05 | Recipient script allowlist: proposed exactly P2PKH, P2SH, P2WPKH, P2WSH; P2TR recipients stay excluded absent a separate architecture-owner amendment | QK-F3-PSBT-020 | finite proposed candidate; owner-open; NOT ACCEPTED |
| D-06 | Change/self-transfer proof requirements | QK-F3-PSBT-019 | finite proposed candidate; owner-open; NOT ACCEPTED |
| D-07 | Multiple-output policy and limits (QK-LIM, OPEN) | QK-F3-PSBT-020 | structurally/evidence-open (limits are OPEN QK-LIM values) |
| D-08 | Fee-rate method before final signatures: RANGE candidate (per the D-08 correction above) vs UNAVAILABLE; never exact | QK-F3-PSBT-022 | finite proposed candidate; owner-open; NOT ACCEPTED |
| D-09 | Review commitment serialization, hash, domain separation | QK-F3-PSBT-024, -026 | structurally/evidence-open (construction undefined) |
| D-10 | Finalization/export boundary (signed PSBT only vs any finalization) under OD-05 | QK-F3-PSBT-016, -025 | finite proposed candidate; owner-open; NOT ACCEPTED |
| D-11 | Output filenames, media, and atomic write lifecycle (OD-05/OD-06, OPEN) | QK-F3-PSBT-025, -033 | structurally/evidence-open (media/write design undefined) |
| D-12 | Combined version/nLockTime/nSequence/BIP68/BIP125 interpretation under existing OD-05. Alternative A, recommended but NOT ACCEPTED: INTERPRET-AND-DISPLAY the consensus temporal semantics plus separately identified mempool-policy signaling, plus raw values, with literal chain-state/network status UNKNOWN. Alternative B, restrictive candidate, NOT ACCEPTED: reject any active absolute-lock (nLockTime) pattern, any active BIP68 relative-lock pattern, OR any direct BIP125 signal (nSequence below 0xfffffffe), only after owner selection and representative coordinator-corpus review. Resolves no canonical OD; no D-13 and no new OD is added | QK-F3-PSBT-023, -026, -033 | finite proposed candidates; owner-open; NOT ACCEPTED |

REVIEW DRAFT CORRECTED (F3.1a) — NOT ACCEPTED
No profile accepted. No vectors generated or run. No implementation
authorized. Gates A–E remain OPEN; OD-01..08 and every QK-LIM remain
unresolved/open; D-00..D-12 remain owner-open; QK-TST/evidence
unchanged; F2 incomplete; F3/F4 authorized-incomplete; F5-F12
unauthorized.
