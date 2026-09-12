use qk_t1::{decode, encode_ack, encode_command, Error as E, Received, MAX_BLOCK_BYTES};

fn frame(nad: u8, pcb: u8, inf: &[u8]) -> Vec<u8> {
    let mut bytes = vec![nad, pcb, inf.len() as u8];
    bytes.extend_from_slice(inf);
    bytes.push(bytes.iter().fold(0, |sum, byte| sum ^ byte));
    bytes
}

#[test]
fn literal_commands_and_acknowledgements() {
    assert_eq!(
        encode_command(&[0x00, 0xa4], 0).unwrap().as_bytes(),
        &[0, 0, 2, 0, 0xa4, 0xa6]
    );
    assert_eq!(
        encode_command(&[0x00, 0xa4], 1).unwrap().as_bytes(),
        &[0, 0x40, 2, 0, 0xa4, 0xe6]
    );
    assert_eq!(encode_ack(0).unwrap().as_bytes(), &[0, 0x80, 0, 0x80]);
    assert_eq!(encode_ack(1).unwrap().as_bytes(), &[0, 0x90, 0, 0x90]);
}

#[test]
fn command_and_sequence_bounds_are_checked_before_copying() {
    assert_eq!(encode_command(&[], 0), Err(E::CommandLengthRejected));
    assert!(encode_command(&[7; 30], 1).is_ok());
    assert_eq!(encode_command(&[7; 31], 0), Err(E::CommandLengthRejected));
    assert_eq!(encode_command(&[7], 2), Err(E::SequenceRejected));
    assert_eq!(encode_ack(255), Err(E::SequenceRejected));
}

#[test]
fn i_block_sequence_more_and_payload_are_exact() {
    for sequence in 0..=1 {
        for more in [false, true] {
            for len in 0..=32 {
                let inf = vec![0x55; len];
                let bytes = frame(0, sequence << 6 | if more { 0x20 } else { 0 }, &inf);
                assert_eq!(
                    decode(&bytes),
                    Ok(Received::I {
                        sequence,
                        more,
                        inf: &inf
                    })
                );
            }
        }
    }
}

#[test]
fn every_i_block_reserved_bit_is_rejected() {
    for pcb in 0u8..128 {
        let bytes = frame(0, pcb, &[1]);
        if pcb & 0x1f == 0 {
            assert!(decode(&bytes).is_ok());
        } else {
            assert_eq!(decode(&bytes), Err(E::PcbRejected));
        }
    }
}

#[test]
fn r_blocks_are_exact_and_never_enable_a_retry() {
    for pcb in 0x80..0xc0 {
        let bytes = frame(0, pcb, &[]);
        let expected = match pcb {
            0x80 => Ok(Received::R { sequence: 0 }),
            0x90 => Ok(Received::R { sequence: 1 }),
            0x81 | 0x82 | 0x91 | 0x92 => Err(E::RetransmissionRejected),
            _ => Err(E::PcbRejected),
        };
        assert_eq!(decode(&bytes), expected, "PCB {pcb:02x}");
    }
    assert_eq!(decode(&frame(0, 0x80, &[0])), Err(E::ControlLengthRejected));
}

#[test]
fn every_s_function_and_response_is_terminal_by_name() {
    for response in [0, 0x20] {
        for (function, inf, error) in [
            (0, &[][..], E::ResynchRejected),
            (1, &[0xfe][..], E::IfsRejected),
            (2, &[][..], E::AbortRejected),
            (3, &[1][..], E::WtxRejected),
        ] {
            assert_eq!(
                decode(&frame(0, 0xc0 | response | function, inf)),
                Err(error)
            );
        }
    }
    assert_eq!(decode(&frame(0, 0xc3, &[])), Err(E::ControlLengthRejected));
    assert_eq!(decode(&frame(0, 0xe2, &[0])), Err(E::ControlLengthRejected));
    assert_eq!(decode(&frame(0, 0xc4, &[])), Err(E::PcbRejected));
}

#[test]
fn exact_length_and_ifsd_precede_checksum_and_fields() {
    for len in 0..4 {
        assert_eq!(decode(&vec![0xff; len]), Err(E::BlockLengthRejected));
    }
    assert_eq!(MAX_BLOCK_BYTES, 36);
    assert_eq!(decode(&frame(0, 0, &[1; 33])), Err(E::BlockLengthRejected));
    let mut bytes = frame(0, 0, &[1]);
    bytes[2] = 2;
    assert_eq!(decode(&bytes), Err(E::BlockLengthRejected));
    bytes[2] = 1;
    bytes.push(0);
    assert_eq!(decode(&bytes), Err(E::BlockLengthRejected));
}

#[test]
fn checksum_precedes_nad_and_control_semantics() {
    let mut bytes = frame(1, 0xc3, &[2]);
    bytes[4] ^= 1;
    assert_eq!(decode(&bytes), Err(E::ChecksumRejected));
    bytes[4] ^= 1;
    assert_eq!(decode(&bytes), Err(E::NadRejected));
}

#[test]
fn every_single_bit_corruption_is_detected() {
    let bytes = frame(0, 0x20, &[0x99; 32]);
    for index in 0..bytes.len() {
        for bit in 0..8 {
            let mut changed = bytes.clone();
            changed[index] ^= 1 << bit;
            assert!(decode(&changed).is_err());
        }
    }
}
