//! Wipe-path accounting hooks are available only to qualification builds.

#[cfg(feature = "fuzzing")]
const FIXTURE: &str = include_str!("../../qk-card-protocol/tests/fixtures/card_protocol_v1.txt");
#[cfg(feature = "fuzzing")]
const FIXTURE_NONCE: [u8; 12] = *b"QKV2S4NONCE1";
#[cfg(feature = "fuzzing")]
static WIPE_TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

#[cfg(feature = "fuzzing")]
fn fixture_record(profile: qk_card_model::ModelProfile) -> [u8; qk_card_model::RECORD_BYTES] {
    let prefix = match profile {
        qk_card_model::ModelProfile::SimpleRecovery => "record_profile_01_hex: ",
        qk_card_model::ModelProfile::Inheritance => "record_profile_02_hex: ",
        qk_card_model::ModelProfile::QuantumShelter => "record_profile_03_hex: ",
    };
    let value = FIXTURE
        .lines()
        .find_map(|line| line.strip_prefix(prefix))
        .expect("registered record");
    let mut record = [0u8; qk_card_model::RECORD_BYTES];
    assert_eq!(value.len(), record.len() * 2);
    for (output, pair) in record.iter_mut().zip(value.as_bytes().as_chunks::<2>().0) {
        *output = u8::from_str_radix(core::str::from_utf8(pair).expect("ASCII hex"), 16)
            .expect("fixture hex");
    }
    record
}

#[cfg(feature = "fuzzing")]
#[test]
fn staging_and_session_owners_are_wiped_on_abort() {
    use qk_card_model::{CardModel, ModelMode, ModelProfile};
    let _guard = WIPE_TEST_LOCK.lock().expect("wipe test lock");
    let id = [0x31; 16];
    let nonce = FIXTURE_NONCE;
    let record = fixture_record(ModelProfile::SimpleRecovery);
    qk_card_model::reset_wipe_counter();
    let mut model = CardModel::new();
    model.select(true).expect("select");
    model.open(1, ModelMode::Setup, id).expect("open");
    model.begin_provision(&id, 1, 1, nonce).expect("begin");
    model.write_chunk(&id, 2, 0, &record[..192]).expect("write");
    model.abort(&id, 3).expect("abort");
    assert!(qk_card_model::wipe_counter() >= 781 + 16 + 12);
}

#[cfg(feature = "fuzzing")]
#[test]
fn aggregate_cap_is_accepted_exactly_and_rejected_one_byte_over() {
    use qk_card_model::{CardModel, RESPONSE_BYTES};
    use qk_card_protocol::{
        encode_get_info, encode_open_session, encode_select, EnvelopeRef, Media, Mode,
        ProtocolError, MAX_AGGREGATE_BYTES,
    };
    const SESSION: [u8; 16] = [0x71; 16];
    const WRONG_SESSION: [u8; 16] = [0x72; 16];
    fn opened(request: &mut [u8; 221], response: &mut [u8; RESPONSE_BYTES]) -> CardModel {
        let mut model = CardModel::new();
        let len = encode_select(request).expect("select");
        model
            .process_apdu(Media::ContactT1, &request[..len], response)
            .expect("select");
        let len = encode_open_session(Mode::Setup, &SESSION, request).expect("open");
        model
            .process_apdu(Media::ContactT1, &request[..len], response)
            .expect("open");
        model
    }
    let mut request = [0u8; 221];
    let mut response = [0u8; RESPONSE_BYTES];
    let info_response_len = 21 + 137 + 2;

    let mut exact = opened(&mut request, &mut response);
    let info_len = encode_get_info(EnvelopeRef::new(&SESSION, 1), &mut request).expect("info");
    exact.set_aggregate_bytes_for_test(MAX_AGGREGATE_BYTES - info_len - info_response_len);
    assert_eq!(
        exact.process_apdu(Media::ContactT1, &request[..info_len], &mut response),
        Ok(info_response_len)
    );
    assert_eq!(exact.aggregate_bytes_for_test(), Some(MAX_AGGREGATE_BYTES));

    let mut over = opened(&mut request, &mut response);
    let info_len =
        encode_get_info(EnvelopeRef::new(&WRONG_SESSION, 99), &mut request).expect("info");
    over.set_aggregate_bytes_for_test(MAX_AGGREGATE_BYTES - info_len - info_response_len + 1);
    assert_eq!(
        over.process_apdu(Media::ContactT1, &request[..info_len], &mut response),
        Err(ProtocolError::SessionStateRejected)
    );
    assert_eq!(&response[..2], &[0x6f, 0x03]);
    assert!(response[2..].iter().all(|byte| *byte == 0));
    assert_eq!(over.aggregate_bytes_for_test(), None);
}

#[cfg(feature = "fuzzing")]
#[test]
fn signature_response_cap_precedes_later_semantic_rejections() {
    use qk_card_model::{CardModel, ModelMode, ModelProfile, RESPONSE_BYTES};
    use qk_card_protocol::{
        encode_open_session, encode_read_d_chunk, encode_select, encode_sign_digest,
        DescriptorSelector, EnvelopeRef, Media, Mode, ProtocolError, SignRequest,
        MAX_AGGREGATE_BYTES,
    };
    const SETUP: [u8; 16] = [0x73; 16];
    const NORMAL: [u8; 16] = [0x74; 16];
    let record = fixture_record(ModelProfile::SimpleRecovery);
    fn opened(record: &[u8; qk_card_model::RECORD_BYTES], mode: Mode) -> CardModel {
        let mut model = CardModel::new();
        model.select(true).expect("select");
        model.open(1, ModelMode::Setup, SETUP).expect("open");
        model
            .begin_provision(&SETUP, 1, 1, FIXTURE_NONCE)
            .expect("begin");
        for (index, (offset, width)) in [(0, 192), (192, 192), (384, 192), (576, 192), (768, 13)]
            .into_iter()
            .enumerate()
        {
            model
                .write_chunk(
                    &SETUP,
                    2 + index as u32,
                    offset as u16,
                    &record[offset..offset + width],
                )
                .expect("write");
        }
        model.commit(&SETUP, 7).expect("commit");
        let mut request = [0u8; 221];
        let mut response = [0u8; RESPONSE_BYTES];
        let len = encode_select(&mut request).expect("select");
        model
            .process_apdu(Media::ContactT1, &request[..len], &mut response)
            .expect("select");
        let len = encode_open_session(mode, &NORMAL, &mut request).expect("open");
        model
            .process_apdu(Media::ContactT1, &request[..len], &mut response)
            .expect("open");
        model
    }

    let wallet_id: [u8; 32] = record[23..55].try_into().expect("wallet id");
    let mut valid = [0u8; 221];
    let len = encode_sign_digest(
        EnvelopeRef::new(&NORMAL, 1),
        SignRequest {
            wallet_id: &wallet_id,
            review_hash: &[0x75; 32],
            input_index: 0,
            branch: 0,
            child_index: 0,
            digest: &[0x76; 32],
        },
        &mut valid,
    )
    .expect("sign request");
    assert_eq!(len, 132);
    const MAXIMUM_RESPONSE_BYTES: usize = 165;
    for mut invalid in [
        {
            let mut bytes = valid;
            bytes[26] ^= 1;
            bytes
        },
        {
            let mut bytes = valid;
            bytes[94] = 2;
            bytes[95..99].copy_from_slice(&65_536u32.to_be_bytes());
            bytes
        },
    ] {
        let mut model = opened(&record, Mode::Normal);
        let mut response = [0u8; RESPONSE_BYTES];
        model.set_aggregate_bytes_for_test(MAX_AGGREGATE_BYTES - len - MAXIMUM_RESPONSE_BYTES + 1);
        assert_eq!(
            model.process_apdu(Media::ContactT1, &invalid[..len], &mut response),
            Err(ProtocolError::SessionStateRejected)
        );
        assert_eq!(&response[..2], &[0x6f, 0x03]);
        assert!(response[2..].iter().all(|byte| *byte == 0));
        invalid.fill(0);
    }

    let mut exact = opened(&record, Mode::Normal);
    let mut response = [0u8; RESPONSE_BYTES];
    exact.set_aggregate_bytes_for_test(MAX_AGGREGATE_BYTES - len - MAXIMUM_RESPONSE_BYTES);
    assert!(exact
        .process_apdu(Media::ContactT1, &valid[..len], &mut response)
        .is_ok());

    let mut invalid_read = [0u8; 221];
    let read_len = encode_read_d_chunk(
        EnvelopeRef::new(&NORMAL, 1),
        DescriptorSelector::Receive,
        0,
        &mut invalid_read,
    )
    .expect("read request");
    invalid_read[27..29].copy_from_slice(&1u16.to_be_bytes());
    let mut invalid_offset = opened(&record, Mode::Setup);
    let mut response = [0u8; RESPONSE_BYTES];
    invalid_offset.set_aggregate_bytes_for_test(MAX_AGGREGATE_BYTES - read_len - 218 + 1);
    assert_eq!(
        invalid_offset.process_apdu(Media::ContactT1, &invalid_read[..read_len], &mut response,),
        Err(ProtocolError::SessionStateRejected)
    );
    assert_eq!(&response[..2], &[0x6f, 0x03]);

    let mut final_chunk = opened(&record, Mode::Setup);
    let mut request = [0u8; 221];
    let first_len = encode_read_d_chunk(
        EnvelopeRef::new(&NORMAL, 1),
        DescriptorSelector::Receive,
        0,
        &mut request,
    )
    .expect("first read");
    final_chunk
        .process_apdu(Media::ContactT1, &request[..first_len], &mut response)
        .expect("first read response");
    let final_len = encode_read_d_chunk(
        EnvelopeRef::new(&NORMAL, 2),
        DescriptorSelector::Receive,
        192,
        &mut request,
    )
    .expect("final read");
    final_chunk.set_aggregate_bytes_for_test(MAX_AGGREGATE_BYTES - final_len - 140);
    assert_eq!(
        final_chunk.process_apdu(Media::ContactT1, &request[..final_len], &mut response),
        Ok(140)
    );
}

#[cfg(feature = "fuzzing")]
#[test]
fn caught_unwind_wipes_volatile_session_and_response() {
    use qk_card_model::{CardModel, FaultPoint, RESPONSE_BYTES};
    use qk_card_protocol::{
        encode_get_info, encode_open_session, encode_select, EnvelopeRef, Media, Mode,
        ProtocolError,
    };
    const SESSION: [u8; 16] = [0x81; 16];
    let _guard = WIPE_TEST_LOCK.lock().expect("wipe test lock");
    let mut model = CardModel::new();
    let mut request = [0u8; 221];
    let mut response = [0xa5u8; RESPONSE_BYTES];
    let len = encode_select(&mut request).expect("select");
    model
        .process_apdu(Media::ContactT1, &request[..len], &mut response)
        .expect("select");
    let len = encode_open_session(Mode::Setup, &SESSION, &mut request).expect("open");
    model
        .process_apdu(Media::ContactT1, &request[..len], &mut response)
        .expect("open");
    let len = encode_get_info(EnvelopeRef::new(&SESSION, 1), &mut request).expect("info");
    model.inject_fault(FaultPoint::CaughtUnwind);
    qk_card_model::reset_wipe_counter();
    let caught = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _ = model.process_apdu(Media::ContactT1, &request[..len], &mut response);
    }));
    assert!(caught.is_err());
    assert!(
        qk_card_model::wipe_counter() >= 16,
        "session id was not wiped"
    );
    assert!(response.iter().all(|byte| *byte == 0));
    assert_eq!(
        model.process_apdu(Media::ContactT1, &request[..len], &mut response),
        Err(ProtocolError::SessionStateRejected)
    );
    assert_eq!(&response[..2], &[0x6f, 0x03]);
}

#[cfg(feature = "fuzzing")]
#[test]
fn provisioning_response_cap_is_preflighted_before_every_persistent_mutation() {
    use qk_card_model::{CardModel, ModelLifecycle, ModelMode, ModelProfile, RESPONSE_BYTES};
    use qk_card_protocol::{
        encode_abort, encode_begin_provision, encode_commit, encode_write_chunk, EnvelopeRef,
        Media, ProtocolError, MAX_AGGREGATE_BYTES,
    };
    const SESSION: [u8; 16] = [0x91; 16];
    const NONCE: [u8; 12] = FIXTURE_NONCE;
    fn reject_over_cap(model: &mut CardModel, request: &[u8], response_size: usize) {
        let mut response = [0xa5u8; RESPONSE_BYTES];
        model.set_aggregate_bytes_for_test(MAX_AGGREGATE_BYTES - request.len() - response_size + 1);
        assert_eq!(
            model.process_apdu(Media::ContactT1, request, &mut response),
            Err(ProtocolError::SessionStateRejected)
        );
        assert_eq!(&response[..2], &[0x6f, 0x03]);
        assert!(response[2..].iter().all(|byte| *byte == 0));
    }
    fn open_setup(model: &mut CardModel) {
        model.select(true).expect("select");
        model.open(1, ModelMode::Setup, SESSION).expect("open");
    }
    let record = fixture_record(ModelProfile::SimpleRecovery);
    let mut request = [0u8; 221];

    let mut begin = CardModel::new();
    open_setup(&mut begin);
    let len = encode_begin_provision(EnvelopeRef::new(&SESSION, 1), 1, &NONCE, &mut request)
        .expect("begin");
    reject_over_cap(&mut begin, &request[..len], 23);
    assert_eq!(begin.lifecycle(), ModelLifecycle::Unprovisioned);

    let mut write = CardModel::new();
    open_setup(&mut write);
    write.begin_provision(&SESSION, 1, 1, NONCE).expect("begin");
    let len = encode_write_chunk(
        EnvelopeRef::new(&SESSION, 2),
        0,
        &record[..192],
        &mut request,
    )
    .expect("write");
    reject_over_cap(&mut write, &request[..len], 25);
    assert_eq!(write.lifecycle(), ModelLifecycle::Staging);
    open_setup(&mut write);
    assert_eq!(write.write_chunk(&SESSION, 1, 0, &record[..192]), Ok(192));

    let mut commit = CardModel::new();
    open_setup(&mut commit);
    commit
        .begin_provision(&SESSION, 1, 1, NONCE)
        .expect("begin");
    for (index, (offset, width)) in [
        (0usize, 192usize),
        (192, 192),
        (384, 192),
        (576, 192),
        (768, 13),
    ]
    .iter()
    .copied()
    .enumerate()
    {
        commit
            .write_chunk(
                &SESSION,
                2 + index as u32,
                offset as u16,
                &record[offset..offset + width],
            )
            .expect("write");
    }
    let len = encode_commit(EnvelopeRef::new(&SESSION, 7), &mut request).expect("commit");
    reject_over_cap(&mut commit, &request[..len], 23);
    assert_eq!(commit.lifecycle(), ModelLifecycle::Staging);
    open_setup(&mut commit);
    commit.commit(&SESSION, 1).expect("commit remains possible");

    let mut abort = CardModel::new();
    open_setup(&mut abort);
    abort.begin_provision(&SESSION, 1, 1, NONCE).expect("begin");
    let len = encode_abort(EnvelopeRef::new(&SESSION, 2), &mut request).expect("abort");
    reject_over_cap(&mut abort, &request[..len], 23);
    assert_eq!(abort.lifecycle(), ModelLifecycle::Staging);
    open_setup(&mut abort);
    abort.abort(&SESSION, 1).expect("abort remains possible");
    assert_eq!(abort.lifecycle(), ModelLifecycle::Unprovisioned);
}

#[cfg(feature = "fuzzing")]
#[test]
fn interior_crypto_unwind_wipes_all_scratch_and_session_state() {
    use qk_card_model::{CardModel, FaultPoint, ModelMode, ModelProfile, RESPONSE_BYTES};
    use qk_card_protocol::{
        encode_open_session, encode_select, encode_sign_digest, EnvelopeRef, Media, Mode,
        ProtocolError, SignRequest,
    };
    const SETUP: [u8; 16] = [0xa1; 16];
    let _guard = WIPE_TEST_LOCK.lock().expect("wipe test lock");
    const NORMAL: [u8; 16] = [0xa2; 16];
    const NONCE: [u8; 12] = FIXTURE_NONCE;
    let record = fixture_record(ModelProfile::SimpleRecovery);
    let mut model = CardModel::new();
    model.select(true).expect("select");
    model.open(1, ModelMode::Setup, SETUP).expect("open");
    model.begin_provision(&SETUP, 1, 1, NONCE).expect("begin");
    for (index, (offset, width)) in [
        (0usize, 192usize),
        (192, 192),
        (384, 192),
        (576, 192),
        (768, 13),
    ]
    .iter()
    .copied()
    .enumerate()
    {
        model
            .write_chunk(
                &SETUP,
                2 + index as u32,
                offset as u16,
                &record[offset..offset + width],
            )
            .expect("write");
    }
    model.commit(&SETUP, 7).expect("commit");
    let mut request = [0u8; 221];
    let mut response = [0xa5u8; RESPONSE_BYTES];
    let len = encode_select(&mut request).expect("select");
    model
        .process_apdu(Media::ContactT1, &request[..len], &mut response)
        .expect("select");
    let len = encode_open_session(Mode::Normal, &NORMAL, &mut request).expect("open");
    model
        .process_apdu(Media::ContactT1, &request[..len], &mut response)
        .expect("open");
    let mut wallet = [0u8; 32];
    wallet.copy_from_slice(&record[23..55]);
    let len = encode_sign_digest(
        EnvelopeRef::new(&NORMAL, 1),
        SignRequest {
            wallet_id: &wallet,
            review_hash: &[0xa4; 32],
            input_index: 0,
            branch: 1,
            child_index: 7,
            digest: &[0xa5; 32],
        },
        &mut request,
    )
    .expect("sign");
    model.inject_fault(FaultPoint::InteriorCryptoUnwind);
    qk_card_model::reset_wipe_counter();
    let caught = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _ = model.process_apdu(Media::ContactT1, &request[..len], &mut response);
    }));
    assert!(caught.is_err());
    assert!(
        qk_card_model::wipe_counter() >= 512,
        "crypto scratch was not drop-wiped"
    );
    assert!(response.iter().all(|byte| *byte == 0));
    assert_eq!(
        model.process_apdu(Media::ContactT1, &request[..len], &mut response),
        Err(ProtocolError::SessionStateRejected)
    );
}

#[cfg(not(feature = "fuzzing"))]
#[test]
fn wipe_instrumentation_is_not_in_the_default_surface() {
    assert!(!cfg!(feature = "fuzzing"));
}
