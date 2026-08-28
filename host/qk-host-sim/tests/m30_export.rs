//! M30 Quantum Shelter file-type-T export boundary over the public M25 fixture.

use qk_bbqr::{
    BbqrError, BbqrFileType, Reassembler, MAX_FRAME_TEXT_BYTES, MAX_TOTAL_DECODED_BYTES,
};
use qk_descriptor::parse_descriptor_pair;
use qk_host_sim::{
    ExportArtifactKind, ExportArtifacts, ExportNonce, KitTier, MockFileKind, MockSdFilesystem,
    ReviewReadyWorkflow, TierArtifacts,
};
use qk_psbt::InputSource;

const FIXTURE: &str = include_str!("fixtures/m25_export.txt");
const NONCE: ExportNonce = ExportNonce::from_bytes([
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
]);

// M25 `raw_tx_hex`, split at the ratified 60-byte geometry and encoded with
// standard uppercase unpadded Base32, prefixed by the pinned `B$2T` wire fields.
const EXACT_TYPE_T_FRAMES: [&str; 6] = [
    "B$2T0600AIAAAAAAAEAXGNYOXGTJ2QZVHBFAG767DS2AW3V6CKTYDL7TIV22DE6TWWDN4MQAAAAAAAH577776ANIZQBQAAAAAAABMAAU",
    "B$2T0601ZT62NJEBW36L6F4Q6HBQU2NRTLLQ66TWAQAEOMCEAIQAW36FQW5QQRHYF2HOAV44QSFSTFBHXIY56EEP3YZG6EXH2XYQGJIC",
    "B$2T0602EBRKOLAZUE7P5U3YWUKW5RY6PDA5KGCRDN5COYNYIYOMNJVS7LZZUAKIGBCQEIIA35HXTE7DP3OHAPJN6X2EMEWZJGH2UHVW",
    "B$2T0603PCEAMKB2WYP5UNNIZQUQEICRU2SHX3INBKMFEEKIKMVZWKXMVDT2CLKJDWDAEHDQR3KRB5ZFQEAWSURBAIN5J5HYKV375F6Q",
    "B$2T0604LC67ERUWF534KAB5H3DME7SYVBS4V35COD75QIIDBNG4BGTEJFDO4QZQC7HBM6XJ46JPYC7XFBNCOJ5J4GMN2WGCB5MSCA4K",
    "B$2T0605W4VFZ5K6ZYEVLNVISNIPOF5CPPIIL6UXQES6MNVZC5FWXPSVJ5J255ABAAAA",
];

fn global(name: &str) -> &str {
    FIXTURE
        .lines()
        .find_map(|line| line.strip_prefix(&format!("{name}: ")))
        .expect("fixture field")
}

fn hex(value: &str) -> Vec<u8> {
    assert!(value.len().is_multiple_of(2));
    value
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            u8::from_str_radix(core::str::from_utf8(pair).expect("ASCII"), 16).expect("hex")
        })
        .collect()
}

fn hex_32(value: &str) -> [u8; 32] {
    hex(value).try_into().expect("32-byte field")
}

fn finalized() -> qk_host_sim::FinalizedTransaction {
    let descriptor = parse_descriptor_pair(
        global("receive_descriptor").as_bytes(),
        global("change_descriptor").as_bytes(),
    )
    .expect("descriptor pair");
    let s0 = hex(global("initial_psbt_hex"));
    let mut workflow = ReviewReadyWorkflow::new(descriptor).expect("workflow");
    workflow.intake(&s0, InputSource::MicroSd).expect("intake");
    workflow.wake().expect("wake");
    workflow.begin_validation().expect("begin validation");
    workflow.validate().expect("validation");
    workflow.construct_review().expect("review");
    workflow
        .sign_and_finalize_m24(Vec::new(), &[])
        .expect("threshold-complete fixture")
}

fn export(tier: KitTier) -> ExportArtifacts {
    ExportArtifacts::from_finalized(finalized(), tier).expect("bound export")
}

#[test]
fn quantum_shelter_frames_only_its_bound_raw_transaction_as_type_t() {
    let owner = export(KitTier::QuantumShelter);
    let raw = owner
        .quantum_shelter_qr()
        .expect("Quantum Shelter type-T capability");
    let expected = hex(global("raw_tx_hex"));
    let metadata = raw.metadata();
    assert_eq!(raw.bytes(), expected);
    assert_eq!(metadata.kind(), ExportArtifactKind::RawTransaction);
    assert_eq!(metadata.serialized_len(), expected.len());
    assert_eq!(metadata.sha256(), hex_32(global("raw_tx_sha256")));
    assert_eq!(metadata.txid(), hex_32(global("txid_raw_hex")));
    assert_eq!(metadata.wtxid(), hex_32(global("wtxid_raw_hex")));

    let mut encoder = raw.bbqr(60).expect("M22 geometry");
    let declared = encoder.declared_parts();
    assert_eq!(usize::from(declared), EXACT_TYPE_T_FRAMES.len());
    let mut storage = [0u8; MAX_TOTAL_DECODED_BYTES];
    let mut reassembler = Reassembler::new_typed(BbqrFileType::Transaction, &mut storage);
    let mut emitted = 0u16;
    while emitted < declared {
        let mut frame = [0xa5u8; MAX_FRAME_TEXT_BYTES];
        let facts = encoder
            .next_frame(&mut frame)
            .expect("type-T encoding")
            .expect("declared frame");
        assert_eq!(facts.declared_parts(), declared);
        assert_eq!(facts.part_index(), emitted);
        assert_eq!(&frame[..4], b"B$2T");
        let expected_frame = EXACT_TYPE_T_FRAMES[usize::from(emitted)].as_bytes();
        assert_eq!(facts.frame_len(), expected_frame.len());
        assert_eq!(&frame[..facts.frame_len()], expected_frame);
        assert!(frame[facts.frame_len()..].iter().all(|byte| *byte == 0xa5));
        let progress = reassembler
            .submit(&frame[..facts.frame_len()])
            .expect("type-T reassembly");
        assert_eq!(progress.received_parts, emitted + 1);
        emitted += 1;
    }
    assert_eq!(reassembler.payload().expect("complete"), expected);
    let mut untouched = [0x5au8; MAX_FRAME_TEXT_BYTES];
    assert_eq!(encoder.next_frame(&mut untouched), Ok(None));
    assert!(untouched.iter().all(|byte| *byte == 0x5a));
}

#[test]
fn simple_and_inheritance_keep_p_framing_and_no_raw_qr_capability() {
    for tier in [KitTier::SimpleRecovery, KitTier::Inheritance] {
        let owner = export(tier);
        let (psbt, raw) = match owner.artifacts() {
            TierArtifacts::SimpleRecovery {
                finalized_psbt,
                raw_transaction,
            }
            | TierArtifacts::Inheritance {
                finalized_psbt,
                raw_transaction,
            } => (finalized_psbt, raw_transaction),
            _ => panic!("non-Quantum artifact shape"),
        };
        let mut encoder = psbt.bbqr(60).expect("unchanged type-P geometry");
        let mut frame = [0u8; MAX_FRAME_TEXT_BYTES];
        let facts = encoder
            .next_frame(&mut frame)
            .expect("type-P encoding")
            .expect("first frame");
        assert_eq!(&frame[..4], b"B$2P");
        assert_eq!(raw.bytes(), hex(global("raw_tx_hex")));
        assert_eq!(raw.metadata().kind(), ExportArtifactKind::RawTransaction);
        assert!(facts.frame_len() > 8);
    }

    let source = include_str!("../src/export.rs");
    let raw_impl = source
        .split("impl<'a> RawTransactionArtifact<'a> {")
        .nth(1)
        .expect("raw artifact implementation")
        .split("/// Tier-closed artifact exposure")
        .next()
        .expect("bounded implementation section");
    assert!(!raw_impl.contains("pub fn bbqr"));
}

#[test]
fn quantum_shelter_sd_lifecycle_and_metadata_are_unchanged() {
    let owner = export(KitTier::QuantumShelter);
    let raw = owner
        .quantum_shelter_qr()
        .expect("Quantum Shelter type-T capability");
    let metadata = raw.metadata();
    let mut filesystem = MockSdFilesystem::new();
    let published = raw
        .write_mock_sd(NONCE, &mut filesystem, None)
        .expect("M25 SD lifecycle");
    assert_eq!(published.metadata(), metadata);
    assert_eq!(filesystem.events().len(), 7);
    assert_eq!(
        filesystem.file_kind(published.names().final_name()),
        Some(MockFileKind::Final)
    );
    assert_eq!(
        filesystem.file_bytes(published.names().final_name()),
        Some(raw.bytes())
    );
}

#[test]
fn transaction_geometry_rejects_before_any_frame_state_exists() {
    let owner = export(KitTier::QuantumShelter);
    let raw = owner
        .quantum_shelter_qr()
        .expect("Quantum Shelter type-T capability");
    assert!(matches!(
        raw.bbqr(4),
        Err(BbqrError::InvalidNonFinalPartLength)
    ));

    for tier in [KitTier::SimpleRecovery, KitTier::Inheritance] {
        assert!(export(tier).quantum_shelter_qr().is_none());
    }
}
