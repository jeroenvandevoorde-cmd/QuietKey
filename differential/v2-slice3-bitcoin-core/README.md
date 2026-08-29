# QuietKey v2 slice-3 Bitcoin Core v28.0 differential harness

This suite is a parallel v2 A/B continuation. It does not alter or import the
frozen `differential/m16-bitcoin-core/` v1 evidence tree. It is invoked
separately from the Cargo workspace and `tools/check.sh`, reaches only an
isolated regtest daemon, and contains no broadcast, wallet RPC, product Core
dependency, or production claim.

## Current state

The checked-in fixture is `READY`: the complete v2 corpus was produced outside
Git by the two-constructor QK-DEC-047 procedure, every closed field is present,
and its complete provenance is registered with the first fixture commit. The
runner still fails closed on any other state before extracting or starting
Bitcoin Core. No evidence transcript exists until the final slice-3 HOST
implementation and the separately pinned Core inputs are both ready to run.

The final invocation is:

```sh
python3 differential/v2-slice3-bitcoin-core/run.py \
  --repo-root . \
  --fixture differential/v2-slice3-bitcoin-core/fixtures/v2_core_vectors.txt \
  --procedure differential/v2-slice3-bitcoin-core/README.md \
  --sha256sums /outside/repository/SHA256SUMS \
  --archive /outside/repository/bitcoin-28.0-x86_64-apple-darwin.tar.gz \
  --transcript differential/v2-slice3-bitcoin-core/evidence/run-YYYYMMDDTHHMMSSZ-HEAD.txt
```

The repository must be clean. The runner requires its own, procedure, and
fixture working bytes to match their HEAD blobs. It creates a new transcript
and refuses to overwrite an existing path. The external archive, checksum
list, extracted binaries, daemon data directory, logs, and RPC cookie never
enter Git.

## Pinned executable boundary

QK-DEC-123 reuses the already registered Bitcoin Core release without a new
pin:

- release: Bitcoin Core 28.0; executable banners v28.0.0;
- archive: `bitcoin-28.0-x86_64-apple-darwin.tar.gz`, 37,680,963 bytes;
- archive SHA-256:
  `77e931bbaaf47771a10c376230bf53223f5380864bad3568efc7f4d02e40a0f7`;
- `SHA256SUMS`: 2,620 bytes, 25 LF, SHA-256
  `d1384c7cbb9027bc5642943d675d25f2edd88e34207e0aaa307babf097d6d023`;
- `bitcoind` SHA-256:
  `55afd04193715ef76bb445a8aec7c18f1af780b9df8b8e5028c1b78baa15b4ee`;
- `bitcoin-cli` SHA-256:
  `2b53751345cdc0f326fa82e721c1f33b29db75d39f9125cb212d2e38524e4c1c`.

The caller retrieves the checksum list and archive outside the repository.
The runner verifies every byte/count/hash pin, extracts into a temporary
directory with traversal checks, verifies both binaries, and starts a fresh
loopback-only regtest daemon with wallet, peer, DNS-seed, and fixed-seed
behavior disabled.

## Registered v2 identity

Every positive case is tied to the QK-DEC-121 GOLDEN lineage:

- wallet_id
  `d5b7e52f569ae51e7c66af14240d8e4459c6246785ce5c441773995614f60e9e`;
- origin fingerprints A/B `2fae9711`, `72a14ab8`;
- exact receive/change descriptors of 306 bytes each;
- strict receive-0 witnessScript of 71 bytes;
- exactly two type-06 derivations, roles A and B;
- exactly two valid type-02 partial signatures at threshold;
- schema byte `03`, domain `QuietKey/D-09/review/v3`, and policy identifier
  `QK-FEE-POLICY-V2`;
- exact pre-signing S0 SHA-256, canonical review-v3 bytes, and review-v3 hash.

The fixture records each literal, byte length, and SHA-256. The runner
recomputes descriptor/script commitments, map inventories, S0 identity,
canonical review identity, and raw transaction identifiers rather than
trusting case labels.

The header also carries the exact two public transcript strings and route
scalars. It pins `host/qk-psbt/tests/fixtures/signing_finalization_v2.txt` by
path, 16,075 bytes, 74 LF, SHA-256
`0c1b55c4928cc05d3db3b4d9fa5310ec4011727ad3d2f133f151ec1f4d40ef25`,
and Git blob `bff025faa873a37c20ea40ec96397cf1b39258dd`. Before Core starts,
the runner requires that HEAD blob and byte-compares all six transcript,
transcript-hash, and scalar fields with the Core fixture header.

## Static regtest state

The final fixture embeds one exact height-1 regtest block whose coinbase pays
the registered receive-0 P2WSH program. It records complete block and coinbase
bytes, hashes, value, output index, header time, and scriptPubKey. The runner
sets mock time to the header time, submits the exact block, asserts the exact
height-one state, generates exactly 100 maturity blocks to `raw(51)`, and
asserts the seed UTXO remains unspent with 101 confirmations. No transaction
is submitted to the chain.

Raw Bitcoin transactions carry no network tag. Exercising a mainnet-profile
object against isolated regtest policy changes no product network rule.

## Positive differential cases

The final corpus contains exactly two positives:

1. `V2-S3-CORE-UNKNOWN-FREE`;
2. `V2-S3-CORE-UNKNOWN-ORDER`.

Before Core runs, the runner pins all PSBT map type sequences. The expected
pre-finalization maps are:

- unknown-free: global `(0)`, input `(0,1,2,2,3,5,6,6)`, output `()`;
- unknown-order: global `(0,255,256)`, input
  `(0,1,2,2,3,5,6,6,255,256)`, output `(255,256)`.

The expected finalized maps are global `(0)`, input `(0,1,8)`, output `()`
for unknown-free, with the same 255/256 records added in each unknown-bearing
map. There is no role C, third derivation, third partial signature, or 105-byte
script in any v2 case.

For each positive, `finalizepsbt(psbt,false)` must report complete. The
unknown-free Core PSBT must be byte-equal to QuietKey's finalized PSBT. For
the unknown-bearing case, decoded values and complete record multisets must
match; the sole permitted byte delta is the registered ordering difference
for numeric types 255 and 256 in every map. Swapping exactly those pairs in
the QuietKey encoding must reproduce Core's bytes exactly.

`finalizepsbt(psbt,true)` must reproduce the exact raw transaction. The runner
then requires exact txid, wtxid, version, locktime, outpoint, sequence, output
amounts/scripts, empty scriptSig, and four witness items: empty dummy, the two
DER-plus-`01` signatures ordered by their positions in the BIP67 script, and
the exact 71-byte witnessScript. Witness stripping must reproduce the exact
unsigned transaction.

`testmempoolaccept` must return one result with `allowed=true`, exact txid and
wtxid, exact base fee, no package error, and no reject reason. Its reported
actual vsize is recorded. It need not equal the schema-v3 estimated vsize
because the policy estimate always uses two maximum 72-byte stored
signatures, while exact fixture DER lengths may be shorter.

## Negative Core controls

Three exact one-change controls derive from the unknown-free positive:

- swap the two signature witness items;
- flip one bit in a DER integer while retaining strict DER structure;
- flip one bit in the serialized base transaction's named output amount.

The runner reconstructs each mutation and requires exact fixture-byte
equality before invoking Core. Witness mutations preserve stripped bytes and
txid. The base mutation preserves every field except the named amount byte.
Each `testmempoolaccept` result must be `allowed=false` with exact mutated
txid/wtxid, a nonempty Core reject reason, and no package error. Core wording
is evidence output, not a QuietKey named-error category.

## Evidence transcript

The transcript shape is frozen in `evidence/TRANSCRIPT-SCHEMA.txt`. A run
records repository and input identities, Core identities, normalized RPC
arguments/results, seed/maturity state, each schema-v3/policy-v2 identity,
all positive and negative case results, assertion/RPC counts, daemon exit,
and PASS or FAIL. RPC triples appear at their exact execution positions; the
schema freezes their method order and the intervening summary blocks while
allowing only the bounded startup-readiness error prefix. Temporary paths,
ports, cookie contents, environment values, and process listings are never
recorded.

Every invocation writes one new transcript, including failed runs. It is
committed without rewriting any prior transcript.

## Fixture-production boundary

The fixture is generated outside Git by two separately written constructors
that extend the public QK-DEC-121 GOLDEN lineage. Every fixture carries the
exact marking `PERMANENTLY NEVER-FUND PUBLIC PRIVATE MATERIAL`. The companion
HOST fixture and this Core header both record the public manual transcript
construction and deliberately exposed route scalars, so all signatures are
reproducible and the two fixture families are byte-tied.
Constructors agree byte-for-byte on keys, derivations, scripts, digests,
signatures, PSBT stages, witnesses, transactions, txids/wtxids, review-v3
facts, Core vectors, mutations, and seed-block facts in one normalized semantic
transcript. The registered fixture is a closed rendering of those agreed facts.

Route keys and signature r values are screened against every registered KAT,
NUMS, and fixture set, all standing encodings, and the small-multiple range;
same-lineage GOLDEN matches are called out. Generators and all intermediates
are destroyed before commit. No new entropy, secret authority, wallet, or
fundable lineage is created.

The first generation workspace was destroyed before the closed Core fixture
text was framed. The exact constructor sources were then recovered from the
local task record, their original hashes were rechecked, and both regenerated
the registered normalized semantic transcript byte-for-byte. After framing,
the recovered workspace was destroyed. The fixture records both destruction
times, file/directory/symlink counts, byte totals, and root-absence results.
It also records the byte count, deletion time, and absence of the temporary
text artifact used only to locate those task records.
