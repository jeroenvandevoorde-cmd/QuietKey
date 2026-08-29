# V2 slice-3 HOST-cap derivations

All arithmetic below is checked before allocation or conversion. These are
QK-DEC-034 HOST scaffold candidates only. They do not freeze a registry or
target-hardware limit, and none reuses a v1 M16 identifier.

## Maximum witness bytes per input: 220

The native v2 wallet is strict P2WSH `sortedmulti(2,A,B)`. Its maximum input
witness serialization is:

- stack-item count: `1` byte (`04`);
- zero-length CHECKMULTISIG dummy: `1` byte (`00`);
- two maximum stored signatures, including `SIGHASH_ALL`:
  `2 * (1-byte length + 72 bytes) = 146`;
- exact 71-byte witnessScript: `1-byte length + 71 = 72`.

Total: `1 + 1 + 146 + 72 = 220` bytes.

## Maximum type-08 record: 223

The final-script-witness PSBT record has one-byte key length, one-byte type-08
key, one-byte CompactSize value length because 220 is below 253, and the
220-byte witness value:

`1 + 1 + 1 + 220 = 223` bytes.

## Maximum raw witness transaction: 27,537

The ratified maximum witness-stripped unsigned transaction is 5,535 bytes.
Witness serialization adds the BIP141 marker/flag and at most 100 input
witnesses:

`5,535 + 2 + 100 * 220 = 27,537` bytes.

## Minimum finalized-PSBT shrink: 121 bytes per input

At completion there are exactly two type-02 partial signatures. At the
maximum stored-signature length each record occupies:

`1 key length + 34 key + 1 value length + 72 value = 108` bytes.

There are exactly two type-06 derivation records. Each contains the 33-byte
pubkey in its key and a 28-byte fingerprint plus six-child path value:

`1 key length + 34 key + 1 value length + 28 value = 64` bytes.

Finalization replaces those mandatory records with at most one 223-byte
type-08 record, so the mandatory shrink is:

`2 * 108 + 2 * 64 - 223 = 121` bytes per input.

Signature bytes cancel between removed type-02 values and the witness. Any
removed type-03, type-04, or byte-equal type-05 record increases the shrink.
