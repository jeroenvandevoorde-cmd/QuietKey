use qk_sec1210_wire::{Command, Decoder, Error, Message, MAX_WIRE_BYTES};

fn frame(payload: &[u8]) -> Vec<u8> {
    let mut bytes = vec![3, 6, 0x80];
    bytes.extend_from_slice(&(payload.len() as u32).to_le_bytes());
    bytes.extend_from_slice(&[0, 2, 0, 0, 0]);
    bytes.extend_from_slice(payload);
    bytes.push(bytes.iter().fold(0, |sum, byte| sum ^ byte));
    bytes
}
fn decode(bytes: &[u8]) -> Result<Vec<Message>, Error> {
    let mut decoder = Decoder::default();
    let mut messages = Vec::new();
    for byte in bytes {
        if let Some(message) = decoder.push(*byte)? {
            messages.push(message);
        }
    }
    decoder.finish()?;
    Ok(messages)
}

#[test]
fn exact_requests_have_independently_derived_xor_and_fields() {
    assert_eq!(
        Command::GetSlotStatus.encode(),
        [3, 6, 0x65, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0x61]
    );
    assert_eq!(
        Command::PowerOn.encode(),
        [3, 6, 0x62, 0, 0, 0, 0, 0, 2, 2, 0, 0, 0x67]
    );
}
#[test]
fn maximum_frame_storage_is_fixed_and_payload_is_preserved() {
    let bytes = frame(&[0xa5; 261]);
    assert_eq!(bytes.len(), MAX_WIRE_BYTES);
    let Message::Response(response) = &decode(&bytes).unwrap()[0] else {
        panic!()
    };
    assert_eq!(response.payload(), [0xa5; 261]);
}
#[test]
fn every_prefix_of_frame_is_incomplete_and_fragmentation_has_no_semantics() {
    let bytes = frame(&[1, 2, 3, 4, 5]);
    for cut in 1..bytes.len() {
        assert_eq!(decode(&bytes[..cut]), Err(Error::Truncated));
        let mut decoder = Decoder::default();
        for byte in &bytes[..cut] {
            assert_eq!(decoder.push(*byte).unwrap(), None);
        }
        let mut result = None;
        for byte in &bytes[cut..] {
            result = decoder.push(*byte).unwrap().or(result);
        }
        assert!(matches!(result, Some(Message::Response(_))));
        assert_eq!(decoder.finish(), Ok(()));
    }
}
#[test]
fn each_single_bit_corruption_is_rejected_or_structurally_incomplete() {
    let bytes = frame(&[7; 15]);
    for index in 0..bytes.len() {
        for bit in 0..8 {
            let mut changed = bytes.clone();
            changed[index] ^= 1 << bit;
            assert!(decode(&changed).is_err(), "{index}/{bit}");
        }
    }
}
#[test]
fn untrusted_lengths_reject_before_payload_copy() {
    for length in [262u32, 0xffff, u32::MAX] {
        let mut bytes = vec![3, 6, 0x80];
        bytes.extend_from_slice(&length.to_le_bytes());
        assert_eq!(decode(&bytes), Err(Error::LengthExceeded));
    }
}
#[test]
fn checksum_precedes_slot_sequence_and_status_visibility() {
    let mut bytes = frame(&[]);
    bytes[7] = 1;
    bytes[8] = 99;
    bytes[9] = 0xff;
    assert_eq!(decode(&bytes), Err(Error::ChecksumRejected));
}
#[test]
fn nack_is_three_bytes_checksummed_and_terminal() {
    assert_eq!(decode(&[3, 0x15]), Err(Error::Truncated));
    assert_eq!(decode(&[3, 0x15, 0]), Err(Error::ChecksumRejected));
    let mut decoder = Decoder::default();
    assert_eq!(decoder.push(3), Ok(None));
    assert_eq!(decoder.push(0x15), Ok(None));
    assert_eq!(decoder.push(0x16), Err(Error::Nack));
    assert_eq!(decoder.push(3), Err(Error::Nack));
}
#[test]
fn events_are_exact_non_checksummed_grammars_and_coalesce() {
    let mut bytes = vec![0x50, 0x0f, 0x51, 0, 1, 1];
    bytes.extend(frame(&[]));
    let messages = decode(&bytes).unwrap();
    assert_eq!(messages.len(), 3);
    assert_eq!(messages[0], Message::SlotChange { bitmap: 0x0f });
    assert_eq!(
        messages[1],
        Message::HardwareError {
            slot: 0,
            sequence: 1,
            code: 1
        }
    );
    for bytes in [&[0x50][..], &[0x51, 0, 1][..]] {
        assert_eq!(decode(bytes), Err(Error::Truncated));
    }
}
#[test]
fn unknown_prefix_never_resynchronizes() {
    let mut bytes = vec![0];
    bytes.extend(frame(&[]));
    assert_eq!(decode(&bytes), Err(Error::PrefixRejected));
}
