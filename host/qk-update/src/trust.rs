//! Compiled public-anchor validation for QK-DEC-136.

use crate::{
    sha256, UpdateError, FINGERPRINT_DOMAIN, KEYSET_DOMAIN, REGISTERED_TEST_ANCHORS,
    REGISTERED_TEST_FINGERPRINTS, REGISTERED_TEST_KEYSET_ID,
};
use qk_secp::PublicKey;

const ZERO_SEPARATOR: [u8; 1] = [0];

/// Three validated, distinct, compiled public verification anchors.
///
/// The native parsed keys remain private to the crate and no secret or
/// signing surface is reachable through this owner.
pub struct CompiledTrust {
    anchor_bytes: [[u8; 33]; 3],
    parsed: [PublicKey; 3],
    fingerprints: [[u8; 32]; 3],
    keyset_id: [u8; 32],
}

impl CompiledTrust {
    /// Construct the production policy boundary. Any exact registered test
    /// key, its row-defined fingerprint, or its ordered key-set identifier
    /// fails mechanically.
    pub fn production(anchor_bytes: [[u8; 33]; 3]) -> Result<Self, UpdateError> {
        let trust = Self::validate(anchor_bytes)?;
        if trust.contains_registered_test_material() {
            return Err(UpdateError::TestAnchorInProduction);
        }
        Ok(trust)
    }

    /// Fixture-anchor acceptance does not exist in ordinary production
    /// builds. It is compiled solely for unit tests and the ring-fenced fuzz
    /// profile.
    #[cfg(any(test, feature = "fuzzing"))]
    pub fn fixture(anchor_bytes: [[u8; 33]; 3]) -> Result<Self, UpdateError> {
        Self::validate(anchor_bytes)
    }

    pub const fn keyset_id(&self) -> [u8; 32] {
        self.keyset_id
    }

    pub const fn fingerprints(&self) -> [[u8; 32]; 3] {
        self.fingerprints
    }

    pub const fn anchor_bytes(&self) -> [[u8; 33]; 3] {
        self.anchor_bytes
    }

    pub(crate) fn role_key(&self, role: u8) -> Result<&PublicKey, UpdateError> {
        match role {
            1 => self
                .parsed
                .first()
                .ok_or(UpdateError::CompiledAnchorMalformed),
            2 => self
                .parsed
                .get(1)
                .ok_or(UpdateError::CompiledAnchorMalformed),
            3 => self
                .parsed
                .get(2)
                .ok_or(UpdateError::CompiledAnchorMalformed),
            _ => Err(UpdateError::SignatureRoleOutOfRange),
        }
    }

    fn validate(anchor_bytes: [[u8; 33]; 3]) -> Result<Self, UpdateError> {
        let [role1, role2, role3] = anchor_bytes;
        if role1 == role2 || role1 == role3 || role2 == role3 {
            return Err(UpdateError::DuplicateCompiledAnchor);
        }

        let parsed1 = qk_secp::pubkey_parse_compressed(&role1)
            .map_err(|_| UpdateError::CompiledAnchorMalformed)?;
        let parsed2 = qk_secp::pubkey_parse_compressed(&role2)
            .map_err(|_| UpdateError::CompiledAnchorMalformed)?;
        let parsed3 = qk_secp::pubkey_parse_compressed(&role3)
            .map_err(|_| UpdateError::CompiledAnchorMalformed)?;

        let fingerprint1 = anchor_fingerprint(&role1)?;
        let fingerprint2 = anchor_fingerprint(&role2)?;
        let fingerprint3 = anchor_fingerprint(&role3)?;
        let keyset_id = keyset_id(&[role1, role2, role3])?;

        Ok(Self {
            anchor_bytes: [role1, role2, role3],
            parsed: [parsed1, parsed2, parsed3],
            fingerprints: [fingerprint1, fingerprint2, fingerprint3],
            keyset_id,
        })
    }

    fn contains_registered_test_material(&self) -> bool {
        self.keyset_id == REGISTERED_TEST_KEYSET_ID
            || self.anchor_bytes.iter().any(|candidate| {
                REGISTERED_TEST_ANCHORS
                    .iter()
                    .any(|registered| candidate == registered)
            })
            || self.fingerprints.iter().any(|candidate| {
                REGISTERED_TEST_FINGERPRINTS
                    .iter()
                    .any(|registered| candidate == registered)
            })
    }
}

pub(crate) fn keyset_id(anchor_bytes: &[[u8; 33]; 3]) -> Result<[u8; 32], UpdateError> {
    let [role1, role2, role3] = anchor_bytes;
    sha256::sha256(&[KEYSET_DOMAIN, &ZERO_SEPARATOR, role1, role2, role3])
        .map_err(|_| UpdateError::CompiledAnchorMalformed)
}

pub(crate) fn anchor_fingerprint(anchor: &[u8; 33]) -> Result<[u8; 32], UpdateError> {
    sha256::sha256(&[FINGERPRINT_DOMAIN, &ZERO_SEPARATOR, anchor])
        .map_err(|_| UpdateError::CompiledAnchorMalformed)
}

#[cfg(test)]
mod tests {
    use super::{anchor_fingerprint, keyset_id, CompiledTrust};
    use crate::{
        UpdateError, REGISTERED_TEST_ANCHORS, REGISTERED_TEST_FINGERPRINTS,
        REGISTERED_TEST_KEYSET_ID,
    };

    #[test]
    fn registered_facts_recompute_exactly() {
        assert_eq!(
            keyset_id(&REGISTERED_TEST_ANCHORS),
            Ok(REGISTERED_TEST_KEYSET_ID)
        );
        for (anchor, expected) in REGISTERED_TEST_ANCHORS
            .iter()
            .zip(REGISTERED_TEST_FINGERPRINTS)
        {
            assert_eq!(anchor_fingerprint(anchor), Ok(expected));
        }
    }

    #[test]
    fn production_rejects_registered_test_material() {
        assert!(matches!(
            CompiledTrust::production(REGISTERED_TEST_ANCHORS),
            Err(UpdateError::TestAnchorInProduction)
        ));
        let [role1, role2, role3] = REGISTERED_TEST_ANCHORS;
        assert!(matches!(
            CompiledTrust::production([role2, role1, role3]),
            Err(UpdateError::TestAnchorInProduction)
        ));
        assert!(CompiledTrust::fixture(REGISTERED_TEST_ANCHORS).is_ok());
    }

    #[test]
    fn malformed_and_duplicate_anchors_are_distinct() {
        let [role1, role2, role3] = REGISTERED_TEST_ANCHORS;
        assert!(matches!(
            CompiledTrust::fixture([role1, role1, role3]),
            Err(UpdateError::DuplicateCompiledAnchor)
        ));
        let mut malformed = role2;
        if let Some(prefix) = malformed.first_mut() {
            *prefix = 0x04;
        }
        assert!(matches!(
            CompiledTrust::fixture([role1, malformed, role3]),
            Err(UpdateError::CompiledAnchorMalformed)
        ));
    }
}
