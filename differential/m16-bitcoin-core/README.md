# QuietKey M16 Bitcoin Core v28.0 differential harness

This suite is invoked separately from the Cargo workspace and
`tools/check.sh`. It consumes committed public fixture bytes. It contains no
signer, key generator, private scalar, nonce, wallet, broadcast path, or
product RPC dependency.

## Current state

The committed fixture is deliberately a non-executable schema placeholder.
Its header says `corpus_state: PLACEHOLDER-FAIL-CLOSED`, every not-yet-created
payload is visibly bracketed, and the runner requires the exact value
`corpus_state: READY` before it will parse a block, PSBT, or transaction or
start Bitcoin Core. Replacing that state and every placeholder is permitted
only after the externally generated public corpus meets QK-DEC-084. The
transcript schema is likewise labelled as a placeholder and is not run
evidence.

After the corpus exists, invoke the suite explicitly; it is never reached by
Cargo or `tools/check.sh`:

```sh
python3 differential/m16-bitcoin-core/run.py \
  --repo-root . \
  --fixture differential/m16-bitcoin-core/fixtures/m16_core_vectors.txt \
  --procedure differential/m16-bitcoin-core/README.md \
  --sha256sums /outside/repository/SHA256SUMS \
  --archive /outside/repository/bitcoin-28.0-x86_64-apple-darwin.tar.gz \
  --transcript /new/evidence/transcript.txt
```

The caller removes the external checksum file and archive after the run. The
runner refuses to overwrite an existing transcript.

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

For each run:

1. Start the pinned daemon with a new temporary data directory and only the
   `regtest` chain, loopback RPC, `listen=0`, `connect=0`, `dnsseed=0`,
   `fixedseeds=0`, and `disablewallet=1`.
2. Assert chain `regtest`, height zero, and the pinned genesis hash.
3. Submit the exact fixture block; assert RPC success, its exact block hash,
   height one, and the exact coinbase UTXO.
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

Run `finalizepsbt(M15_PSBT, false)` and require `complete=true`. For an
unknown-free case, base64-decode the Core PSBT and require byte equality with
the fixture's QuietKey finalized PSBT. For an unknown-bearing case, byte
equality is neither required nor treated as a failure: run `decodepsbt` on
both finalized PSBTs, compare normalized complete JSON values, and compare
complete per-map `(decoded type, full key bytes, value bytes)` multisets.

The unknown-bearing case deliberately carries unknown numeric types 255 and
256 in the same map. QuietKey M5 orders by decoded numeric type, yielding
`[255,256]`; Core v28.0 stores unknown complete keys in a raw-byte ordered map,
yielding `[256,255]` because the minimal type encodings are `fdff00` and
`fd0001`. The exact order-only byte delta is recorded as expected. Every key,
value, scope, record count, known field, proprietary record, UTXO, and final
witness is equal after decoding.

Run `finalizepsbt(M15_PSBT, true)` and require `complete=true` plus exact raw
transaction hex for every case, including unknown-bearing cases. Run
`decoderawtransaction`; require exact txid, wtxid (`hash`), version, locktime,
input sequences/outpoints, output amounts/scripts, empty scriptSig, and the
four-item witness `[empty, signature in first selected pubkey position,
signature in second selected pubkey position, 105-byte witnessScript]`.

Run `testmempoolaccept '[RAW_TX]' 0` separately per positive raw transaction.
Require one result with `allowed=true`, exact txid/wtxid, nonzero vsize, the
expected fee, no reject reason, and no package error. The RPC is read-only and
does not insert the transaction.

## Negative Core controls

The fixture embeds exact raw bytes for three one-change controls derived from
the accepted raw transaction:

- replace the zero-length CHECKMULTISIG dummy with the one-byte item `01`;
- swap the two signature witness items while leaving all other bytes fixed;
- flip a value bit inside one DER integer while retaining strict DER form.

Invoke `testmempoolaccept` separately for each. Require `allowed=false`, exact
mutated txid/wtxid as applicable, a nonempty reject reason, and no daemon or
harness failure. Record the complete returned JSON; do not pin reject-reason
wording as a product category.

## Evidence transcript

The runner writes a new transcript path supplied by the caller and refuses to
overwrite it. The transcript records UTC run time, repository commit/tree and
clean status, host OS/architecture, harness/procedure/fixture hashes, every
pinned Core artifact fact, version banners, chain/genesis/seed/maturity facts,
the normalized arguments and complete normalized JSON results for every RPC,
the expected unknown-order delta, per-case assertion totals, aggregate totals,
daemon clean stop, and final PASS/FAIL. It never records temporary paths,
ports, cookie contents, environment variables, or process listings.

Commit the transcript as its own evidence file after a passing run. A later
run writes a new file; no previous transcript is rewritten.

## Fixture creation boundary

The positive corpus is generated outside Git only after its decision rows
exist. It uses new high-entropy ephemeral signing authorities and a
unique high-entropy nonce for each signature. Two separately written
implementations must agree byte-for-byte on public keys, descriptors,
derivations, scripts, digests, signatures, PSBTs, witnesses, raw
transactions, txid/wtxid, mutations, and fixture output. New public keys and
signature `r` values are screened against the committed KAT, known-key,
NUMS, M15, raw/decoded, contiguous-hex, and small-multiple sets. The fixture
header records implementation/runtime hashes, consumed public facts, scan
counts, seed-block facts, and deletion completion. Every scalar, nonce,
entropy buffer, signer, generator, temporary wallet, and intermediate is
destroyed before commit. Only complete public byte payloads remain. The
mainnet descriptor lineage is permanently NEVER-FUND; temporary regtest coins
have no value outside the isolated chain.
