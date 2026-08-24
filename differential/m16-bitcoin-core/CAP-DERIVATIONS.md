# M16 ratified HOST-cap derivations

All arithmetic is checked before conversion/reservation and is suitable for
compile-time assertions. These are QK-DEC-034 HOST candidates only.

## Witness bytes per input: 254

The exact maximum witness serialization is:

- stack item count: `1` byte (`04`);
- zero-length CHECKMULTISIG dummy: `1` byte (`00`);
- two maximum stored signatures: `2 * (1-byte length + 72 bytes) = 146`;
- 105-byte witnessScript: `1-byte length + 105 = 106`.

Total: `1 + 1 + 146 + 106 = 254`.

## Raw witness transaction: 30,937

The previously ratified maximum witness-stripped unsigned transaction is
5,535 bytes. Witness serialization adds the two marker/flag bytes and at most
100 input witnesses:

`5,535 + 2 + 100 * 254 = 30,937`.

## Finalized PSBT shrink: at least 149 bytes per input

At threshold there are at least two type-02 partial-signature records. At
maximum stored signature length, each is
`1 key-length + 34 key + 1 value-length + 72 value = 108`, so two occupy 216
bytes. M12 proof requires exactly three type-06 derivation records. Each
contains the 33-byte pubkey in its key and the exact 28-byte fingerprint plus
six-child path in its value:

`1 key-length + 34 key + 1 value-length + 28 value = 64`; three occupy 192.

The maximum type-08 final-script-witness record is
`1 key-length + 1 key + 3 value-length + 254 value = 259` bytes. Thus the
mandatory replacement alone shrinks by:

`2 * 108 + 3 * 64 - 259 = 149`.

For shorter signatures, the signature bytes cancel between removed type-02
records and the type-08 witness; when the witness value drops below 253 its
CompactSize prefix also contracts from three bytes to one. Removal of any
present type-03, type-04, or type-05 field increases the shrink. A third
partial signature likewise increases it.
