#![no_main]

use libfuzzer_sys::fuzz_target;
use qk_a1::{decrypt, encrypt, A1Error};

const CAPSULE_LEN: usize = 67;
const MAX_PRESENTED_CAPSULE_LEN: usize = CAPSULE_LEN + 1;
const SENTINEL: [u8; 32] = [0xa5; 32];
const PUBLIC_A2: [u8; 32] = [0xa2; 32];
const PUBLIC_SEED_A: [u8; 32] = [0xa1; 32];
const PUBLIC_WALLET_ID: [u8; 32] = [0x57; 32];

struct Cursor<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> Cursor<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    fn byte(&mut self) -> u8 {
        let byte = self.bytes.get(self.offset).copied().unwrap_or(0);
        self.offset = self.offset.saturating_add(1);
        byte
    }

    fn array<const N: usize>(&mut self) -> [u8; N] {
        core::array::from_fn(|_| self.byte())
    }
}

fn structural_error(capsule: &[u8]) -> Option<A1Error> {
    if capsule.len() != CAPSULE_LEN {
        return Some(A1Error::InvalidCapsuleLength);
    }
    if capsule[..4] != *b"QKA1" {
        return Some(A1Error::InvalidMagic);
    }
    if capsule[4] != 1 {
        return Some(A1Error::UnsupportedCodingVersion);
    }
    if capsule[5] != 1 {
        return Some(A1Error::UnsupportedCryptoVersion);
    }
    if capsule[6] != 1 {
        return Some(A1Error::UnsupportedNetwork);
    }
    None
}

fn assert_named_error(error: A1Error) {
    match error {
        A1Error::InvalidCapsuleLength
        | A1Error::InvalidMagic
        | A1Error::UnsupportedCodingVersion
        | A1Error::UnsupportedCryptoVersion
        | A1Error::UnsupportedNetwork
        | A1Error::AuthenticationFailed => {}
    }
}

fn exercise_decrypt(a2: &[u8; 32], wallet_id: &[u8; 32], capsule: &[u8]) {
    let mut plaintext = SENTINEL;
    let result = decrypt(a2, wallet_id, capsule, &mut plaintext);

    if let Some(expected) = structural_error(capsule) {
        assert_eq!(result, Err(expected));
        assert_eq!(plaintext, SENTINEL);
        let mut repeated_plaintext = SENTINEL;
        assert_eq!(
            decrypt(a2, wallet_id, capsule, &mut repeated_plaintext),
            Err(expected)
        );
        assert_eq!(repeated_plaintext, SENTINEL);
        return;
    }

    match result {
        Err(error) => {
            assert_named_error(error);
            assert_eq!(error, A1Error::AuthenticationFailed);
            assert_eq!(plaintext, SENTINEL);
            let mut repeated_plaintext = SENTINEL;
            assert_eq!(
                decrypt(a2, wallet_id, capsule, &mut repeated_plaintext),
                Err(error)
            );
            assert_eq!(repeated_plaintext, SENTINEL);
        }
        Ok(()) => {
            let mut nonce = [0u8; 12];
            nonce.copy_from_slice(&capsule[7..19]);
            assert_eq!(
                encrypt(a2, wallet_id, &nonce, &plaintext).as_slice(),
                capsule
            );
            let mut repeated_plaintext = SENTINEL;
            assert_eq!(
                decrypt(a2, wallet_id, capsule, &mut repeated_plaintext),
                Ok(())
            );
            assert_eq!(repeated_plaintext, plaintext);
        }
    }
}

fuzz_target!(|data: &[u8]| {
    let mut cursor = Cursor::new(data);
    let nonce = cursor.array::<12>();

    // Raw hostile capsules cover every presented length from empty through one
    // byte over the fixed wire size while keeping work independent of input size.
    let raw_len = usize::from(cursor.byte()) % (MAX_PRESENTED_CAPSULE_LEN + 1);
    let raw_capsule = cursor.array::<MAX_PRESENTED_CAPSULE_LEN>();
    exercise_decrypt(&PUBLIC_A2, &PUBLIC_WALLET_ID, &raw_capsule[..raw_len]);

    // Every input also reaches a valid capsule and a deterministic one-byte
    // mutation, making acceptance and rejection behavior continuously checked.
    let capsule = encrypt(&PUBLIC_A2, &PUBLIC_WALLET_ID, &nonce, &PUBLIC_SEED_A);
    exercise_decrypt(&PUBLIC_A2, &PUBLIC_WALLET_ID, &capsule);

    let mut changed = capsule;
    let changed_index = usize::from(cursor.byte()) % CAPSULE_LEN;
    changed[changed_index] ^= cursor.byte() | 1;
    exercise_decrypt(&PUBLIC_A2, &PUBLIC_WALLET_ID, &changed);
});
