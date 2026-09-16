use qk_sec1210_wire::{
    validate_production_atr, Error, ProductionDecoder, ProductionMessageKind, ProductionRequest,
    Sec1210AtrProfileRejected, MAX_PRODUCTION_ATR_BYTES, REGISTERED_ATR,
};

const ATR_SOURCE: &str = include_str!("../src/atr_v2.rs");
const STRUCTURAL_ALTERNATIVE: [u8; 9] = [0x3b, 0x90, 0x18, 0x81, 0x91, 0xdd, 0x1f, 0x02, 0x58];
const TA2_IFSC_SPOOF: [u8; 9] = [0x3b, 0x90, 0x18, 0xd1, 0xdd, 0x00, 0x1f, 0x02, 0x99];

fn changed(index: usize, value: u8) -> Vec<u8> {
    let mut atr = REGISTERED_ATR.to_vec();
    atr[index] = value;
    let last = atr.len() - 1;
    atr[last] = atr[1..last].iter().fold(0u8, |sum, byte| sum ^ byte);
    atr
}

fn with_tck<const N: usize>(mut atr: [u8; N]) -> [u8; N] {
    let last = atr.len() - 1;
    atr[last] = atr[1..last].iter().fold(0u8, |sum, byte| sum ^ byte);
    atr
}

#[test]
fn registered_and_distinct_structural_profiles_pass() {
    assert_eq!(validate_production_atr(&REGISTERED_ATR), Ok(()));
    assert_ne!(STRUCTURAL_ALTERNATIVE.as_slice(), REGISTERED_ATR);
    assert_eq!(validate_production_atr(&STRUCTURAL_ALTERNATIVE), Ok(()));
    assert_eq!(
        validate_production_atr(&TA2_IFSC_SPOOF),
        Err(Sec1210AtrProfileRejected)
    );
}

#[test]
fn iso_maximum_is_structural_and_not_the_registered_atr_length() {
    let registered_plus_historical = with_tck([
        0x3b, 0xd6, 0x18, 0xff, 0x81, 0x91, 0xfe, 0x1f, 0xc3, 0x80, 0x73, 0xc8, 0x21, 0x10, 0x42,
        0x00,
    ]);
    assert_eq!(validate_production_atr(&REGISTERED_ATR), Ok(()));
    assert_eq!(validate_production_atr(&registered_plus_historical), Ok(()));

    let explicit_lrc_tc3 = with_tck([
        0x3b, 0x96, 0x18, 0x81, 0xd1, 0xfe, 0x00, 0x1f, 0x02, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06,
        0x00,
    ]);
    let mut explicit_crc_tc3 = explicit_lrc_tc3;
    explicit_crc_tc3[6] = 0x01;
    explicit_crc_tc3 = with_tck(explicit_crc_tc3);
    assert_eq!(validate_production_atr(&explicit_lrc_tc3), Ok(()));
    assert_eq!(
        validate_production_atr(&explicit_crc_tc3),
        Err(Sec1210AtrProfileRejected)
    );

    let maximum = with_tck([
        0x3b, 0xff, 0x18, 0x00, 0xff, 0x81, 0xf1, 0xfe, 0x00, 0x00, 0xd1, 0x00, 0x00, 0x7f, 0x02,
        0x00, 0x00, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c,
        0x0d, 0x0e, 0x00,
    ]);
    assert_eq!(maximum.len(), MAX_PRODUCTION_ATR_BYTES);
    assert_eq!(validate_production_atr(&maximum), Ok(()));

    let mut maximum_plus_one = [0u8; MAX_PRODUCTION_ATR_BYTES + 1];
    maximum_plus_one[..MAX_PRODUCTION_ATR_BYTES].copy_from_slice(&maximum);
    assert_eq!(
        validate_production_atr(&maximum_plus_one),
        Err(Sec1210AtrProfileRejected)
    );
}

#[test]
fn all_public_failures_are_the_same_fieldless_rejection() {
    let mut too_long = [0u8; MAX_PRODUCTION_ATR_BYTES + 1];
    too_long[0] = 0x3b;
    let no_class_b = changed(8, 0xc1);
    let wrong_fidi = changed(2, 0x11);
    let short_ifsc = changed(6, 0xdc);
    for atr in [
        &[][..],
        &[0x3f, 0x00],
        &[0x3b, 0x10],
        &REGISTERED_ATR[..14],
        &[0x3b, 0x10, 0x18],
        no_class_b.as_slice(),
        wrong_fidi.as_slice(),
        short_ifsc.as_slice(),
        &too_long,
    ] {
        assert_eq!(validate_production_atr(atr), Err(Sec1210AtrProfileRejected));
    }
    assert_eq!(
        Sec1210AtrProfileRejected.name(),
        "Sec1210AtrProfileRejected"
    );
}

fn response(payload: &[u8]) -> Vec<u8> {
    let mut bytes = vec![0x03, 0x06, 0x80];
    bytes.extend_from_slice(&(payload.len() as u32).to_le_bytes());
    bytes.extend_from_slice(&[0x00, 0x07, 0x00, 0x00, 0x00]);
    bytes.extend_from_slice(payload);
    bytes.push(bytes.iter().fold(0u8, |sum, byte| sum ^ byte));
    bytes
}

#[test]
fn production_decoder_returns_owned_fixed_response_without_boxed_api() {
    let mut decoder = ProductionDecoder::default();
    let mut decoded = None;
    for byte in response(&[1, 2, 3]) {
        decoded = decoder.push(byte).unwrap().or(decoded);
    }
    let message = decoded.unwrap();
    assert_eq!(message.kind(), ProductionMessageKind::Response);
    let decoded_response = message.response().unwrap();
    assert_eq!(decoded_response.message_type(), 0x80);
    assert_eq!(decoded_response.slot(), 0);
    assert_eq!(decoded_response.sequence(), 7);
    assert_eq!(decoded_response.status(), 0);
    assert_eq!(decoded_response.error(), 0);
    assert_eq!(decoded_response.parameter(), 0);
    assert_eq!(decoded_response.payload(), [1, 2, 3]);
    assert_eq!(decoder.pending_bytes(), 0);
    assert_eq!(decoder.finish(), Ok(()));

    let mut decoder = ProductionDecoder::default();
    let mut decoded = None;
    for byte in response(&[4, 5, 6]) {
        decoded = decoder.push(byte).unwrap().or(decoded);
    }
    let response = decoded.unwrap().into_response().unwrap();
    assert_eq!(response.payload(), [4, 5, 6]);
}

#[test]
fn production_request_constructors_pin_the_five_wire_shapes() {
    assert_eq!(
        ProductionRequest::get_slot_status(1).as_bytes(),
        [3, 6, 0x65, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0x61]
    );
    assert_eq!(
        ProductionRequest::power_on_3v(2).as_bytes(),
        [3, 6, 0x62, 0, 0, 0, 0, 0, 2, 2, 0, 0, 0x67]
    );
    assert_eq!(
        ProductionRequest::get_parameters(3).as_bytes(),
        [3, 6, 0x6c, 0, 0, 0, 0, 0, 3, 0, 0, 0, 0x6a]
    );
    assert_eq!(
        ProductionRequest::set_fidi_parameters(4).as_bytes(),
        [3, 6, 0x61, 7, 0, 0, 0, 0, 4, 1, 0, 0, 0x18, 0x10, 0xff, 0x4d, 0, 0xfe, 0, 0x22,]
    );
    let ifs = [0x00, 0xc1, 0x01, 0xfe, 0x3e];
    assert_eq!(
        ProductionRequest::xfr_block(5, 0, &ifs).unwrap().as_bytes(),
        [3, 6, 0x6f, 5, 0, 0, 0, 0, 5, 0, 0, 0, 0x00, 0xc1, 0x01, 0xfe, 0x3e, 0x6a,]
    );
}

#[test]
fn xfr_block_rejects_bad_length_shape_and_lrc_before_encoding() {
    for bytes in [&[][..], &[0, 0, 0], &[0, 0, 1, 0], &[0, 0, 0, 1]] {
        assert!(matches!(
            ProductionRequest::xfr_block(6, 0, bytes),
            Err(Error::PayloadRejected)
        ));
    }
}

#[test]
fn interface_chain_and_checksum_are_complete_and_exact() {
    let mut trailing = STRUCTURAL_ALTERNATIVE.to_vec();
    trailing.push(0);
    let mut corrupt = STRUCTURAL_ALTERNATIVE;
    corrupt[8] ^= 1;
    for atr in [&trailing[..], &corrupt] {
        assert_eq!(validate_production_atr(atr), Err(Sec1210AtrProfileRejected));
    }
    for atr in [&[
        0x3b, 0x90, 0x18, 0x81, 0x91, 0xfe, 0x9f, 0xc1, 0x1f, 0xc3, 0xe4,
    ][..]]
    {
        assert_eq!(validate_production_atr(atr), Err(Sec1210AtrProfileRejected));
    }
}

#[test]
fn complete_protocol_profile_handles_late_parameters_and_rejects_rfu_shapes() {
    let late_ifsc = [0x3b, 0x90, 0x18, 0x81, 0x81, 0x91, 0xfe, 0x1f, 0x02, 0xfa];
    let edc_rfu = [0x3b, 0x90, 0x18, 0x81, 0xd1, 0xdd, 0x02, 0x1f, 0xc3, 0xdb];
    let late_crc = [
        0x3b, 0x90, 0x18, 0x81, 0x91, 0xdd, 0xc1, 0x01, 0x1f, 0x02, 0x98,
    ];
    let descending = [0x3b, 0x90, 0x18, 0x81, 0x91, 0xdd, 0x80, 0x1f, 0x02, 0xd8];
    let global_before_t1 = [0x3b, 0x90, 0x18, 0x8f, 0x91, 0xdd, 0x1f, 0x02, 0x56];
    let reserved_voltage = [0x3b, 0x90, 0x18, 0x81, 0x91, 0xdd, 0x1f, 0x0a, 0x50];
    assert_eq!(validate_production_atr(&late_ifsc), Ok(()));
    for atr in [
        edc_rfu.as_slice(),
        late_crc.as_slice(),
        descending.as_slice(),
        global_before_t1.as_slice(),
        reserved_voltage.as_slice(),
    ] {
        assert_eq!(validate_production_atr(atr), Err(Sec1210AtrProfileRejected));
    }
}

#[test]
fn production_facade_is_fixed_storage_and_uses_the_allocation_free_decoder_path() {
    assert!(!ATR_SOURCE.contains("Vec<"));
    assert!(!ATR_SOURCE.contains("Box<"));
    assert!(!ATR_SOURCE.contains("unsafe"));
    assert_eq!(
        ATR_SOURCE.matches("self.inner.push_fixed(byte)?").count(),
        1
    );
}
