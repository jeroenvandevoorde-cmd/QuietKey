//! Canonical QKEC-1 source records and per-purpose conditioning.

use crate::hkdf_sha256::{expand, extract};
use crate::secret::{wipe, Secret};
use crate::sha256::Sha256;
use crate::ProvisioningError;

const VERSION: u8 = 1;
const REQUIRED_RECORD_BYTES: usize = 106;
const OPTIONAL_RECORD_BYTES: usize = 141;
const SOURCE_BYTES: usize = 32;
const TLV_BYTES: usize = 1 + 2 + SOURCE_BYTES;
const PURPOSE_PREFIX: &[u8] = b"QuietKey/QKEC-1";
const OUTPUT_INFO: &[u8] = b"QuietKey/256-bit-output";

pub(crate) const PURPOSES: [&[u8]; 4] = [b"Seed-A", b"Signer-B", b"Signer-C", b"A2"];

fn validate_record(record: &[u8]) -> Result<(), ProvisioningError> {
    if !matches!(record.len(), REQUIRED_RECORD_BYTES | OPTIONAL_RECORD_BYTES) {
        return Err(ProvisioningError::InvalidRecordLength);
    }
    if record[0] != VERSION {
        return Err(ProvisioningError::UnsupportedRecordVersion);
    }

    let expected_count = (record.len() - 1) / TLV_BYTES;
    let mut seen = [false; 4];
    let mut previous = 0u8;
    for position in 0..expected_count {
        let offset = 1 + position * TLV_BYTES;
        let tag = record[offset];
        if !(1..=4).contains(&tag) {
            return Err(ProvisioningError::UnknownSource);
        }
        if position != 0 {
            if tag == previous {
                return Err(ProvisioningError::DuplicateSource);
            }
            if tag < previous {
                return Err(ProvisioningError::SourceOutOfOrder);
            }
        }
        let length = u16::from_be_bytes([record[offset + 1], record[offset + 2]]);
        if usize::from(length) != SOURCE_BYTES {
            return Err(ProvisioningError::InvalidSourceLength);
        }
        seen[usize::from(tag - 1)] = true;
        previous = tag;
    }
    if !seen[0] || !seen[1] || !seen[2] {
        return Err(ProvisioningError::MissingRequiredSource);
    }
    if expected_count == 3 && seen[3] {
        return Err(ProvisioningError::InvalidRecordLength);
    }
    if expected_count == 4 && !seen[3] {
        return Err(ProvisioningError::MissingRequiredSource);
    }
    Ok(())
}

fn condition_one(
    record: &[u8],
    purpose: &[u8],
    ceremony_id: &[u8; 16],
) -> Result<Secret<32>, ProvisioningError> {
    validate_record(record)?;
    let mut salt_hash = Sha256::new();
    salt_hash.update(PURPOSE_PREFIX);
    salt_hash.update(purpose);
    salt_hash.update(ceremony_id);
    let mut salt = salt_hash.finish();
    let mut prk = extract(&salt, record);
    let mut output = [0u8; 32];
    if !expand(&prk, OUTPUT_INFO, &mut output) {
        wipe(&mut salt);
        wipe(&mut prk);
        wipe(&mut output);
        return Err(ProvisioningError::CryptographicInvariant);
    }
    wipe(&mut salt);
    wipe(&mut prk);
    Ok(Secret::take(&mut output))
}

pub(crate) fn condition_four(
    records: [&[u8]; 4],
    ceremony_id: &[u8; 16],
) -> Result<[Secret<32>; 4], ProvisioningError> {
    for record in records {
        validate_record(record)?;
    }
    for left in 0..records.len() {
        for right in left + 1..records.len() {
            if records[left] == records[right] {
                return Err(ProvisioningError::SourceSetReuse);
            }
        }
    }
    Ok([
        condition_one(records[0], PURPOSES[0], ceremony_id)?,
        condition_one(records[1], PURPOSES[1], ceremony_id)?,
        condition_one(records[2], PURPOSES[2], ceremony_id)?,
        condition_one(records[3], PURPOSES[3], ceremony_id)?,
    ])
}

#[cfg(test)]
mod tests {
    use super::{condition_four, validate_record};
    use crate::ProvisioningError;

    fn record(seed: u8, optional: bool) -> Vec<u8> {
        let mut out = vec![1];
        let count = if optional { 4 } else { 3 };
        for tag in 1..=count {
            out.push(tag);
            out.extend_from_slice(&32u16.to_be_bytes());
            out.extend(core::iter::repeat_n(seed.wrapping_add(tag), 32));
        }
        out
    }

    #[test]
    fn exact_record_shapes_and_purpose_separation() {
        let records = [
            record(1, false),
            record(2, true),
            record(3, false),
            record(4, true),
        ];
        assert_eq!((records[0].len(), records[1].len()), (106, 141));
        let outputs = condition_four(
            [&records[0], &records[1], &records[2], &records[3]],
            &[0x55; 16],
        )
        .expect("valid public test records");
        for left in 0..4 {
            for right in left + 1..4 {
                assert_ne!(outputs[left].as_bytes(), outputs[right].as_bytes());
            }
        }
    }

    #[test]
    fn record_failures_are_named() {
        assert_eq!(
            validate_record(&[]),
            Err(ProvisioningError::InvalidRecordLength)
        );
        let mut value = record(1, false);
        value[0] = 2;
        assert_eq!(
            validate_record(&value),
            Err(ProvisioningError::UnsupportedRecordVersion)
        );
        value = record(1, false);
        value[1] = 5;
        assert_eq!(
            validate_record(&value),
            Err(ProvisioningError::UnknownSource)
        );
        value = record(1, false);
        value[36] = 1;
        assert_eq!(
            validate_record(&value),
            Err(ProvisioningError::DuplicateSource)
        );
        value = record(1, false);
        value[1] = 2;
        value[36] = 1;
        assert_eq!(
            validate_record(&value),
            Err(ProvisioningError::SourceOutOfOrder)
        );
        value = record(1, false);
        value[2] = 0;
        value[3] = 31;
        assert_eq!(
            validate_record(&value),
            Err(ProvisioningError::InvalidSourceLength)
        );
        value = record(1, false);
        value[71] = 4;
        assert_eq!(
            validate_record(&value),
            Err(ProvisioningError::MissingRequiredSource)
        );
    }

    #[test]
    fn all_six_cross_purpose_equalities_reject() {
        for left in 0..4 {
            for right in left + 1..4 {
                let mut records = [
                    record(1, false),
                    record(2, false),
                    record(3, false),
                    record(4, false),
                ];
                records[right] = records[left].clone();
                assert!(matches!(
                    condition_four(
                        [&records[0], &records[1], &records[2], &records[3]],
                        &[0u8; 16]
                    ),
                    Err(ProvisioningError::SourceSetReuse)
                ));
            }
        }
    }
}
