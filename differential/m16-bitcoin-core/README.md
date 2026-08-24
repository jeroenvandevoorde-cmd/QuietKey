# QuietKey M16 Bitcoin Core v28.0 differential harness

This suite is invoked separately from the Cargo workspace and
`tools/check.sh`. It consumes committed public fixture bytes. It contains no
signer, key generator, private scalar, nonce, wallet, broadcast path, or
product RPC dependency.

## Current state

The committed fixture is a complete public corpus with `corpus_state: READY`.
It contains the exact closed header and five exact closed case schemas
implemented by the runner. Unknown, missing, duplicate, noncanonical,
bracketed, or placeholder fields reject before Bitcoin Core starts. The
transcript schema documents the output shape; it is not run evidence.

Invoke the suite explicitly; it is never reached by Cargo or `tools/check.sh`:

```sh
python3 differential/m16-bitcoin-core/run.py \
  --repo-root . \
  --fixture differential/m16-bitcoin-core/fixtures/m16_core_vectors.txt \
  --procedure differential/m16-bitcoin-core/README.md \
  --sha256sums /outside/repository/SHA256SUMS \
  --archive /outside/repository/bitcoin-28.0-x86_64-apple-darwin.tar.gz \
  --transcript differential/m16-bitcoin-core/evidence/run-20260824T220000Z-abcdef0.txt
```

The runner requires itself, the procedure, and the fixture at these canonical
repository paths, tracked with working bytes equal to their HEAD blobs. The
repository must be clean when the run begins. The transcript must be a new
`evidence/run-YYYYMMDDTHHMMSSZ-<HEAD>.txt` path and is never overwritten. The
caller removes the external checksum file and archive after the run.

## Pinned executable

- Release: Bitcoin Core v28.0 (`bitcoind` and `bitcoin-cli` report v28.0.0).
- Platform archive: `bitcoin-28.0-x86_64-apple-darwin.tar.gz`.
- Archive bytes: 37,680,963.
- Archive SHA-256:
  `77e931bbaaf47771a10c376230bf53223f5380864bad3568efc7f4d02e40a0f7`.
- Official checksum URL:
  `https://bitcoincore.org/bin/bitcoin-core-28.0/SHA256SUMS`.
- `SHA256SUMS` bytes/lines/SHA-256: 2,620 / 25 LF /
  `d1384c7cbb9027bc5642943d675d25f2edd88e34207e0aaa307babf097d6d023`.
- Selected official line:
  `77e931bbaaf47771a10c376230bf53223f5380864bad3568efc7f4d02e40a0f7  bitcoin-28.0-x86_64-apple-darwin.tar.gz`.
- Extracted executable SHA-256 values:
  `bitcoind=55afd04193715ef76bb445a8aec7c18f1af780b9df8b8e5028c1b78baa15b4ee`;
  `bitcoin-cli=2b53751345cdc0f326fa82e721c1f33b29db75d39f9125cb212d2e38524e4c1c`.

Retrieve the checksum list and archive outside the repository. Verify the
checksum-list byte pin, select exactly one filename-matching line, verify the
archive with that line, verify archive size, extract into a temporary
directory, verify both executable hashes, and assert both version banners.
Neither the archive, extracted binary, data directory, log, nor RPC cookie is
copied into Git.

## Static regtest state

The fixture embeds one exact height-1 regtest block whose sole coinbase pays
a native P2WSH output used by the committed positive cases. That block was
created outside Git from the public witness-program descriptor; creating it
required no wallet or private key. Its complete block bytes, block hash,
coinbase transaction bytes, txid, output index, amount, and scriptPubKey are
all present in the fixture.
The header time is exactly `1800000000`. Before submission, the isolated
regtest node's mock time is set to that exact public header value so the
deterministic block remains rerunnable regardless of the host wall clock; the
typed `setmocktime` call and result are recorded in the transcript.

For each run:

1. Start the pinned daemon with a new temporary data directory and only the
   `regtest` chain, loopback RPC, `listen=0`, `connect=0`, `dnsseed=0`,
   `fixedseeds=0`, and `disablewallet=1`.
2. Assert chain `regtest`, height zero, and the pinned genesis hash.
3. Set regtest mock time to the exact fixture header time, then submit the
   exact fixture block; assert RPC success, its exact block hash, height one,
   and the exact coinbase UTXO.
4. Run `generatetodescriptor 100 "raw(51)"`; assert exactly 100 returned
   hashes, final height 101, and that the seed UTXO remains unspent and
   mature for the next-block mempool context.
5. Never call `sendrawtransaction`, `submitpackage`, or a wallet RPC.

Raw transaction serialization contains no network tag. Feeding a transaction
produced from a mainnet-profile review object to the isolated regtest policy
engine therefore widens neither product parsing nor product network policy.
Regtest is harness state only.

## Positive cases

For each positive case, the fixture supplies exact M15 PSBT bytes, QuietKey
finalized PSBT bytes, raw witness transaction bytes, witness-stripped bytes,
txid, wtxid, four witness items, and every SHA-256/length.
The runner pins the complete decoded type sequence of every map before any
Core call. Unknown-free M15 maps are `[0]`,
`[0,1,2,2,3,5,6,6,6]`, `[]`, and their finalized maps are `[0]`,
`[0,1,8]`, `[]`. Unknown-bearing M15 maps are `[0,255,256]`,
`[0,1,2,2,2,3,5,6,6,6,255,256]`, `[255,256]`, and their finalized maps
are `[0,255,256]`, `[0,1,8,255,256]`, `[255,256]`. Thus the fixture labels
cannot hide an extra record, and the intended two-signature versus
three-signature coverage is exact.

Run `finalizepsbt(M15_PSBT, false)` and require `complete=true`. For an
unknown-free case, base64-decode the Core PSBT and require byte equality with
the fixture's QuietKey finalized PSBT. For an unknown-bearing case, byte
equality is neither required nor treated as a failure: run `decodepsbt` on
both finalized PSBTs, compare normalized complete JSON values, and compare
complete per-map `(decoded type, full key bytes, value bytes)` multisets.

The unknown-bearing case deliberately carries unknown numeric types 255 and
256 in every global, input, and output map. QuietKey M5 orders by decoded
numeric type, yielding `[255,256]`; Core v28.0 stores unknown complete keys in
a raw-byte ordered map, yielding `[256,255]` because the minimal type encodings
are `fdff00` and `fd0001`. The exact complete keys and order-only byte delta in
all three maps are recorded as expected. Every present unknown key and value,
scope, record count, known field, UTXO, and final witness is equal after
decoding. The runner swaps exactly those two records in each QuietKey map,
reserializes every map, and requires exact Core byte equality; an additional
reordered or changed byte fails.

Run `finalizepsbt(M15_PSBT, true)` and require `complete=true` plus exact raw
transaction hex for every case, including unknown-bearing cases. Run
`decoderawtransaction`; require exact txid, wtxid (`hash`), version, locktime,
input sequences/outpoints, output amounts/scripts, empty scriptSig, and the
four-item witness `[empty, signature in first selected pubkey position,
signature in second selected pubkey position, 105-byte witnessScript]`.
The runner independently parses and canonically reserializes the witness and
stripped transactions, requires the stripped bytes in both PSBTs, reconstructs
the P2WSH commitment, parses the strict BIP67 script, ties each selected
signature value and pubkey to the M15 partial-signature map, and asserts the
two strictly increasing script positions.

Run `testmempoolaccept '[RAW_TX]' 0` separately per positive raw transaction.
Require one result with `allowed=true`, exact txid/wtxid, nonzero vsize, the
expected base fee converted exactly to satoshis, the expected effective fee
member, no reject reason, and no package error. Every version, locktime,
outpoint, sequence, output amount, output script, witness item, fee, and
descriptor wallet_id expectation is carried as a literal fixture field or is
recomputed from those literal bytes. The RPC is read-only and does not insert
the transaction.

## Negative Core controls

The fixture embeds exact raw bytes for three one-change controls derived from
the unknown-free accepted raw transaction:

- swap the two signature witness items while leaving all other bytes fixed;
- flip one value bit inside one DER integer while retaining strict DER form;
- flip bit zero of serialized byte 49, changing output zero by exactly one
  satoshi while freezing the input, witness, script, version, and locktime.

Before invoking Core, the runner reconstructs each mutation from the parent
transaction and requires byte equality. The two witness mutations retain the
same witness-stripped bytes and txid. The base mutation must change the txid
and wtxid to the exact fixture values while retaining every base field except
the named output amount byte. The signature mutation names its witness index,
byte offset, and one-bit XOR mask; the offset must lie inside a DER integer
value and both before/after encodings must remain strict DER plus SIGHASH_ALL.
Invoke `testmempoolaccept` separately for each. Require `allowed=false`, exact
mutated txid/wtxid, a nonempty reject reason, no package error, and no daemon
or harness failure. Record the complete returned JSON; do not pin
reject-reason wording as a product category.

## Evidence transcript

The runner writes a new transcript path supplied by the caller and refuses to
overwrite it. The transcript records UTC run time, repository commit/tree and
clean status, host OS/architecture, harness/procedure/fixture hashes, every
pinned Core artifact fact, version banners, chain/genesis/seed/maturity facts,
the typed normalized JSON arguments and complete normalized JSON results for every RPC,
the expected unknown-order delta, per-case assertion totals, aggregate totals,
daemon clean stop, and final PASS/FAIL. It never records temporary paths,
ports, cookie contents, environment variables, or process listings.

Every invocation writes one new transcript with `result=PASS` or `result=FAIL`.
Commit that transcript as its own evidence file before any repair or rerun. A
later run writes a new file; no previous transcript is rewritten.

## Fixture creation boundary

The positive corpus is generated outside Git only after its decision rows
exist. Its closed header records two implementation and runtime hashes, the
external-generation-transcript hash and exact byte/line counts, agreement
scope, authority/signature/nonce counts, the screening report and its native
repository/target counts, every destruction count and result, completion
time, and permanent lineage status. It uses new high-entropy ephemeral
signing authorities and a unique high-entropy nonce for each signature. Two
separately written implementations must agree byte-for-byte on public keys,
descriptors,
derivations, scripts, digests, signatures, PSBTs, witnesses, raw
transactions, txid/wtxid, mutations, and fixture output. New public keys and
signature `r` values are screened against the committed KAT, known-key,
NUMS, M15, raw/decoded, contiguous-hex, and small-multiple sets. The fixture
header records implementation/runtime hashes, public transcript facts, native
scan counts, seed-block facts, and deletion completion. Every scalar, nonce,
entropy buffer, signer, generator, temporary wallet, and intermediate is
destroyed before commit. Only complete public byte payloads remain. The
mainnet descriptor lineage is permanently NEVER-FUND; temporary regtest coins
have no value outside the isolated chain.
