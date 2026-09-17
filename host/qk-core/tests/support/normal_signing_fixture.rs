//! Public never-fund card/reader fixture; no device or production dependency.

use qk_card_protocol::{parse_command, CommandRef, DescriptorSelector, Instruction, Media, Mode};
use qk_core::{
    CoreOutbound, KeypadKey, NormalProcessEventV2, NormalProcessStageV2, NormalSec1210V2,
    NormalStageV2, Sec1210ClockErrorV2, Sec1210DescriptorErrorV2, Sec1210DescriptorReadV2,
    Sec1210DescriptorV2, Sec1210DescriptorWriteV2, Sec1210MonotonicClockV2, Source,
};
use qk_io::{BrokerReply, BrokerSession, MockInput, MockOutputWriter, Source as IoSource};
use qk_ipc::{ReceivedFrame, StreamDecoder};
use std::cell::RefCell;
use std::collections::VecDeque;
use std::rc::Rc;

pub const CARD: &str =
    include_str!("../../../qk-card-protocol/tests/fixtures/card_protocol_v1.txt");
pub const SIGNING: &str =
    include_str!("../../../qk-psbt/tests/fixtures/signing_finalization_v2.txt");
pub const PROVISIONING: &str =
    include_str!("../../../qk-provisioning/tests/fixtures/provisioning_v2.txt");
pub type Owner = NormalSec1210V2<FixtureDescriptor, FixtureClock>;

pub fn receive(owner: &mut Owner, reply: &BrokerReply) -> Option<CoreOutbound> {
    let mut bytes = reply.frame_bytes().to_vec();
    let result = owner
        .receive_qkip(&mut bytes, false)
        .expect("accepted broker reply");
    assert!(bytes.iter().all(|byte| *byte == 0));
    result
}

pub fn ingress(
    owner: &mut Owner,
    broker: &mut BrokerSession,
    begin: CoreOutbound,
    source: IoSource,
    bytes: &[u8],
) {
    let mut input = MockInput::try_new(source, bytes).expect("public input");
    let began = reply(broker, &begin, Some(&mut input), None);
    let mut next = receive(owner, &began);
    while let Some(outbound) = next {
        let reply = reply(broker, &outbound, None, None);
        next = receive(owner, &reply);
    }
}

pub fn approval(profile: u8, psbt: &[u8]) -> (Owner, BrokerSession, Trace) {
    let (descriptor, clock, trace) = rig(profile);
    let ascii = [b'0', b'0' + profile];
    let (mut owner, opening) = Owner::start(&ascii, descriptor, clock).expect("bound card");
    assert_eq!(trace.apdus().len(), 8);
    assert_eq!(trace.sign_count(), 0);
    let mut broker = BrokerSession::new();
    let ready = reply(&mut broker, &opening, None, None);
    assert!(receive(&mut owner, &ready).is_none());
    owner
        .handle_event(NormalProcessEventV2::LogicalKey(
            KeypadKey::EqualsConfirmEnter,
        ))
        .expect("confirm profile");
    let begin = owner
        .handle_event(NormalProcessEventV2::SelectPsbtSource(Source::MediaPsbt))
        .expect("source")
        .expect("PSBT begin");
    ingress(
        &mut owner,
        &mut broker,
        begin,
        IoSource::MediaPsbt,
        &media_record(psbt),
    );
    let begin = owner
        .advance_automatic()
        .expect("factor B")
        .expect("A1 begin");
    ingress(
        &mut owner,
        &mut broker,
        begin,
        IoSource::CameraA1Candidate,
        &a1(),
    );
    assert!(owner.advance_automatic().expect("validate A1").is_none());
    for _ in 0..400 {
        if owner.stage() == NormalProcessStageV2::Normal(NormalStageV2::FinalApproval) {
            break;
        }
        owner
            .handle_event(NormalProcessEventV2::LogicalKey(
                KeypadKey::EqualsConfirmEnter,
            ))
            .expect("review next");
    }
    assert_eq!(
        owner.stage(),
        NormalProcessStageV2::Normal(NormalStageV2::FinalApproval)
    );
    assert!(owner.screen().is_some());
    assert_eq!(trace.sign_count(), 0, "no SIGN before approval");
    (owner, broker, trace)
}

pub fn field<'a>(source: &'a str, name: &str) -> &'a str {
    source
        .lines()
        .find_map(|line| line.strip_prefix(name)?.strip_prefix(": "))
        .expect("registered public fixture field")
}

pub fn hex(text: &str) -> Vec<u8> {
    assert!(text.len().is_multiple_of(2));
    text.as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            u8::from_str_radix(std::str::from_utf8(pair).expect("ASCII hex"), 16)
                .expect("fixture hex")
        })
        .collect()
}

pub fn psbt() -> Vec<u8> {
    hex(field(SIGNING, "s0_hex"))
}

pub fn a1() -> Vec<u8> {
    hex(field(PROVISIONING, "a1_capsule_hex"))
}

/// Derive many public inputs from the registered S0 without adding key material.
/// Each prior transaction differs in its public input nonce; all owned outputs
/// remain the registered receive-0 script. The fee stays 100,000 satoshis.
pub fn psbt_with_inputs(count: usize) -> Vec<u8> {
    assert!((1..=100).contains(&count));
    if count == 1 {
        return psbt();
    }
    let original = psbt();
    let mut cursor = 5;
    let mut global = read_map(&original, &mut cursor);
    let input = read_map(&original, &mut cursor);
    let mut outputs = Vec::new();
    while cursor < original.len() {
        outputs.push(read_map(&original, &mut cursor));
    }
    let unsigned = global
        .iter_mut()
        .find(|(key, _)| key == &[0])
        .expect("unsigned fixture transaction");
    let old_tx = unsigned.1.clone();
    assert_eq!(old_tx[4], 1);
    let mut tx = old_tx[..4].to_vec();
    tx.push(u8::try_from(count).expect("bounded input count"));
    let mut inputs = Vec::new();
    for position in 0..count {
        let mut records = input.clone();
        let previous = records
            .iter_mut()
            .find(|(key, _)| key == &[0])
            .expect("non-witness fixture prevtx");
        previous.1[5] = u8::try_from(position).expect("bounded public nonce");
        tx.extend_from_slice(&sha256(&sha256(&previous.1)));
        tx.extend_from_slice(&old_tx[37..46]);
        inputs.push(records);
    }
    let output_offset = tx.len();
    tx.extend_from_slice(&old_tx[46..]);
    let change = 1_000_000u64 * u64::try_from(count).expect("bounded count") - 600_000;
    tx[output_offset + 1..output_offset + 9].copy_from_slice(&change.to_le_bytes());
    unsigned.1 = tx;
    let mut rebuilt = b"psbt\xff".to_vec();
    write_map(&mut rebuilt, &global);
    for records in inputs {
        write_map(&mut rebuilt, &records);
    }
    for records in outputs {
        write_map(&mut rebuilt, &records);
    }
    rebuilt
}

pub fn proof(bytes: &[u8]) -> qk_psbt::ValidatedNormalV3 {
    qk_psbt::build_validated_normal_v3(
        qk_psbt::OwnedS0::new(bytes, qk_psbt::InputSource::MicroSd).expect("bounded public S0"),
        qk_descriptor::parse_descriptor_pair_v2(
            field(CARD, "receive_descriptor").as_bytes(),
            field(CARD, "change_descriptor").as_bytes(),
        )
        .expect("registered descriptor pair"),
    )
    .expect("valid public fixture proof")
}

/// Add already-valid B signatures without changing the unsigned transaction.
pub fn psbt_with_existing_b(count: usize, present: &[usize]) -> Vec<u8> {
    let bytes = psbt_with_inputs(count);
    let validated = proof(&bytes);
    let mut cursor = 5;
    let global = read_map(&bytes, &mut cursor);
    let mut output = b"psbt\xff".to_vec();
    write_map(&mut output, &global);
    for index in 0..count {
        let mut input = read_map(&bytes, &mut cursor);
        if present.contains(&index) {
            let mut key = vec![2];
            key.extend_from_slice(&hex(field(CARD, "route_public_key_hex")));
            let mut signature = sign(validated.input_signing_plans()[index].digest());
            signature.push(1);
            input.push((key, signature));
            input.sort_by(|left, right| left.0.cmp(&right.0));
        }
        write_map(&mut output, &input);
    }
    output.extend_from_slice(&bytes[cursor..]);
    output
}

type Map = Vec<(Vec<u8>, Vec<u8>)>;

fn compact_size(input: &[u8], cursor: &mut usize) -> usize {
    let prefix = input[*cursor];
    *cursor += 1;
    match prefix {
        0..=252 => usize::from(prefix),
        253 => {
            let value = u16::from_le_bytes(input[*cursor..*cursor + 2].try_into().expect("u16"));
            *cursor += 2;
            usize::from(value)
        }
        _ => panic!("bounded fixture CompactSize"),
    }
}

fn put_size(output: &mut Vec<u8>, size: usize) {
    if size <= 252 {
        output.push(u8::try_from(size).expect("small size"));
    } else {
        output.push(253);
        output.extend_from_slice(
            &u16::try_from(size)
                .expect("bounded fixture size")
                .to_le_bytes(),
        );
    }
}

fn read_map(input: &[u8], cursor: &mut usize) -> Map {
    let mut records = Vec::new();
    loop {
        let length = compact_size(input, cursor);
        if length == 0 {
            return records;
        }
        let key = input[*cursor..*cursor + length].to_vec();
        *cursor += length;
        let length = compact_size(input, cursor);
        let value = input[*cursor..*cursor + length].to_vec();
        *cursor += length;
        records.push((key, value));
    }
}

fn write_map(output: &mut Vec<u8>, records: &Map) {
    for (key, value) in records {
        put_size(output, key.len());
        output.extend_from_slice(key);
        put_size(output, value.len());
        output.extend_from_slice(value);
    }
    output.push(0);
}

// Same public fixture constructor as qk-psbt's descriptor_ownership test.
fn sha256(bytes: &[u8]) -> [u8; 32] {
    const K: [u32; 64] = [
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4,
        0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe,
        0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f,
        0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
        0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc,
        0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
        0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116,
        0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7,
        0xc67178f2,
    ];

    let mut padded = Vec::with_capacity(bytes.len() + 72);
    padded.extend_from_slice(bytes);
    let bit_len = (bytes.len() as u64) * 8;
    padded.push(0x80);
    while padded.len() % 64 != 56 {
        padded.push(0);
    }
    padded.extend_from_slice(&bit_len.to_be_bytes());

    let mut state = [
        0x6a09e667u32,
        0xbb67ae85,
        0x3c6ef372,
        0xa54ff53a,
        0x510e527f,
        0x9b05688c,
        0x1f83d9ab,
        0x5be0cd19,
    ];
    for block in padded.chunks_exact(64) {
        let mut words = [0u32; 64];
        for index in 0..16 {
            words[index] = u32::from_be_bytes(block[index * 4..index * 4 + 4].try_into().unwrap());
        }
        for index in 16..64 {
            let s0 = words[index - 15].rotate_right(7)
                ^ words[index - 15].rotate_right(18)
                ^ (words[index - 15] >> 3);
            let s1 = words[index - 2].rotate_right(17)
                ^ words[index - 2].rotate_right(19)
                ^ (words[index - 2] >> 10);
            words[index] = words[index - 16]
                .wrapping_add(s0)
                .wrapping_add(words[index - 7])
                .wrapping_add(s1);
        }

        let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h] = state;
        for index in 0..64 {
            let sigma1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let choose = (e & f) ^ (!e & g);
            let first = h
                .wrapping_add(sigma1)
                .wrapping_add(choose)
                .wrapping_add(K[index])
                .wrapping_add(words[index]);
            let sigma0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let majority = (a & b) ^ (a & c) ^ (b & c);
            let second = sigma0.wrapping_add(majority);
            h = g;
            g = f;
            f = e;
            e = d.wrapping_add(first);
            d = c;
            c = b;
            b = a;
            a = first.wrapping_add(second);
        }
        state = [
            state[0].wrapping_add(a),
            state[1].wrapping_add(b),
            state[2].wrapping_add(c),
            state[3].wrapping_add(d),
            state[4].wrapping_add(e),
            state[5].wrapping_add(f),
            state[6].wrapping_add(g),
            state[7].wrapping_add(h),
        ];
    }

    let mut digest = [0u8; 32];
    for (index, word) in state.iter().enumerate() {
        digest[index * 4..index * 4 + 4].copy_from_slice(&word.to_be_bytes());
    }
    digest
}

pub fn media_record(payload: &[u8]) -> Vec<u8> {
    let name = b"normal-v2.psbt";
    let mut record = vec![u8::try_from(name.len()).expect("fixture filename length")];
    record.extend_from_slice(name);
    record.extend_from_slice(
        &u32::try_from(payload.len())
            .expect("fixture size")
            .to_le_bytes(),
    );
    record.extend_from_slice(payload);
    record
}

pub fn decode_one(bytes: &[u8]) -> ReceivedFrame {
    let mut decoder = StreamDecoder::new();
    let outcome = decoder.ingest(bytes, false).expect("complete QKIP frame");
    assert_eq!(outcome.consumed(), bytes.len());
    assert!(outcome.frame_ready());
    decoder.take_frame().expect("owned QKIP frame")
}

pub fn reply(
    broker: &mut BrokerSession,
    outbound: &CoreOutbound,
    input: Option<&mut MockInput>,
    writer: Option<&mut MockOutputWriter>,
) -> BrokerReply {
    broker
        .accept(&decode_one(outbound.frame_bytes()), input, writer)
        .expect("purpose-bound public fixture broker reply")
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SignFault {
    WrongReview,
    WrongIndex,
    WrongKey,
    MalformedDer,
    Invalid,
    HighS,
    Repeated,
    Removed,
    ReadFailure,
    ShortWrite,
    WriteFailure,
    TimedOut,
    BadChecksum,
    WrongSession,
    WrongCounter,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum Fault {
    #[default]
    None,
    InfoProfile,
    InfoLifecycle,
    InfoWallet,
    InfoFingerprint,
    InfoXpub,
    Descriptor,
    Sign {
        ordinal: usize,
        kind: SignFault,
    },
}

#[derive(Default)]
struct TraceState {
    writes: Vec<Vec<u8>>,
    apdus: Vec<Vec<u8>>,
    signs: usize,
    fault: Fault,
    fragment_bytes: usize,
    now_ms: u64,
    clock_script: VecDeque<Result<u64, Sec1210ClockErrorV2>>,
    descriptor_dropped: bool,
}

#[derive(Clone)]
pub struct Trace(Rc<RefCell<TraceState>>);

impl Trace {
    pub fn set_fault(&self, fault: Fault) {
        self.0.borrow_mut().fault = fault;
    }

    pub fn set_fragment_bytes(&self, bytes: usize) {
        assert!(bytes > 0);
        self.0.borrow_mut().fragment_bytes = bytes;
    }

    pub fn set_clock_script(
        &self,
        values: impl IntoIterator<Item = Result<u64, Sec1210ClockErrorV2>>,
    ) {
        self.0.borrow_mut().clock_script = values.into_iter().collect();
    }

    pub fn writes(&self) -> Vec<Vec<u8>> {
        self.0.borrow().writes.clone()
    }

    pub fn apdus(&self) -> Vec<Vec<u8>> {
        self.0.borrow().apdus.clone()
    }

    pub fn sign_count(&self) -> usize {
        self.0.borrow().signs
    }

    pub fn descriptor_dropped(&self) -> bool {
        self.0.borrow().descriptor_dropped
    }

    pub fn last_valid_sign_reply(&self) -> Option<Vec<u8>> {
        let state = self.0.borrow();
        let request = state
            .apdus
            .iter()
            .rev()
            .find(|request| request.get(1) == Some(&0x15))?;
        let CommandRef::SignDigest {
            envelope,
            review_hash,
            input_index,
            digest,
            ..
        } = parse_command(Media::ContactT1, request).expect("recorded valid SIGN request")
        else {
            panic!("recorded SIGN instruction must parse as SIGN");
        };
        let der = sign(digest);
        let mut tail = review_hash.to_vec();
        tail.extend_from_slice(&input_index.to_be_bytes());
        tail.extend_from_slice(&hex(field(CARD, "route_public_key_hex")));
        tail.push(u8::try_from(der.len()).expect("bounded valid DER"));
        tail.extend_from_slice(&der);
        Some(success(Some(envelope), &tail))
    }
}

pub struct FixtureClock(Trace);

impl Sec1210MonotonicClockV2 for FixtureClock {
    fn now_ms(&mut self) -> Result<u64, Sec1210ClockErrorV2> {
        let mut state = self.0 .0.borrow_mut();
        if let Some(value) = state.clock_script.pop_front() {
            if let Ok(now) = value {
                state.now_ms = now;
            }
            return value;
        }
        let now = state.now_ms;
        state.now_ms = now.saturating_add(1);
        Ok(now)
    }
}

enum Read {
    Bytes(Vec<u8>),
    Removed,
    Failed,
    TimedOut,
}

pub struct FixtureDescriptor {
    trace: Trace,
    profile: u8,
    reads: VecDeque<Read>,
    last_der: Option<Vec<u8>>,
    session_id: Option<[u8; 16]>,
    next_envelope: u32,
}

pub fn rig(profile: u8) -> (FixtureDescriptor, FixtureClock, Trace) {
    assert!((1..=3).contains(&profile));
    let trace = Trace(Rc::new(RefCell::new(TraceState::default())));
    (
        FixtureDescriptor {
            trace: trace.clone(),
            profile,
            reads: VecDeque::new(),
            last_der: None,
            session_id: None,
            next_envelope: 1,
        },
        FixtureClock(trace.clone()),
        trace,
    )
}

fn controller_response(kind: u8, sequence: u8, status: u8, parameter: u8, body: &[u8]) -> Vec<u8> {
    let mut frame = vec![0x03, 0x06, kind];
    frame.extend_from_slice(
        &u32::try_from(body.len())
            .expect("bounded fixture reply")
            .to_le_bytes(),
    );
    frame.extend_from_slice(&[0, sequence, status, 0, parameter]);
    frame.extend_from_slice(body);
    frame.push(frame.iter().fold(0, |checksum, byte| checksum ^ byte));
    frame
}

fn success(envelope: Option<qk_card_protocol::EnvelopeRef<'_>>, tail: &[u8]) -> Vec<u8> {
    let mut response = Vec::new();
    if let Some(envelope) = envelope {
        response.push(1);
        response.extend_from_slice(envelope.session_id());
        response.extend_from_slice(&envelope.sequence().to_be_bytes());
    }
    response.extend_from_slice(tail);
    response.extend_from_slice(&[0x90, 0]);
    response
}

fn sign(digest: &[u8; 32]) -> Vec<u8> {
    let mut scalar: [u8; 32] = hex(field(CARD, "route_private_scalar_hex"))
        .try_into()
        .expect("registered public route scalar");
    let secret = qk_secp::secret_key_import(&mut scalar).expect("public test scalar");
    assert_eq!(scalar, [0; 32]);
    let key = qk_secp::pubkey_parse_compressed(
        &hex(field(CARD, "route_public_key_hex"))
            .try_into()
            .expect("registered route public key"),
    )
    .expect("public route key");
    let signature =
        qk_secp::ecdsa_sign_rfc6979(&secret, digest, &key).expect("public fixture SIGN");
    let mut der = [0; 72];
    let length = qk_secp::signature_serialize_der(&signature, &mut der).expect("public DER");
    der[..length].to_vec()
}

fn high_s(der: &[u8]) -> Vec<u8> {
    // Public signature transformation only; retain R and replace S by n-S.
    let r_length = usize::from(der[3]);
    let s_tag = 4 + r_length;
    assert_eq!(der[s_tag], 2);
    let s_length = usize::from(der[s_tag + 1]);
    let s = &der[s_tag + 2..s_tag + 2 + s_length];
    assert!(s.len() <= 32);
    let mut padded = [0; 32];
    padded[32 - s.len()..].copy_from_slice(s);
    let mut high = hex("fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141");
    let mut borrow = 0i16;
    for index in (0..32).rev() {
        let value = i16::from(high[index]) - i16::from(padded[index]) - borrow;
        high[index] = (value & 255) as u8;
        borrow = i16::from(value < 0);
    }
    assert_eq!(borrow, 0);
    let first = high.iter().position(|byte| *byte != 0).expect("nonzero S");
    let mut encoded = high[first..].to_vec();
    if encoded[0] & 0x80 != 0 {
        encoded.insert(0, 0);
    }
    let mut output = vec![
        0x30,
        u8::try_from(r_length + encoded.len() + 4).expect("DER size"),
        2,
        u8::try_from(r_length).expect("R size"),
    ];
    output.extend_from_slice(&der[4..s_tag]);
    output.extend_from_slice(&[2, u8::try_from(encoded.len()).expect("S size")]);
    output.extend_from_slice(&encoded);
    output
}

impl FixtureDescriptor {
    fn application_response(&mut self, apdu: &[u8], fault: Fault) -> Vec<u8> {
        let command = parse_command(Media::ContactT1, apdu).expect("encoded application command");
        let ordinal = self.trace.0.borrow().apdus.len();
        let binding = [
            Instruction::Select,
            Instruction::OpenSession,
            Instruction::GetInfo,
            Instruction::ReadDChunk,
            Instruction::ReadDChunk,
            Instruction::ReadDChunk,
            Instruction::ReadDChunk,
            Instruction::ExportA2,
        ];
        assert_eq!(
            command.instruction(),
            binding
                .get(ordinal - 1)
                .copied()
                .unwrap_or(Instruction::SignDigest)
        );
        if let Some(envelope) = command.envelope() {
            assert_eq!(Some(*envelope.session_id()), self.session_id);
            assert_eq!(envelope.sequence(), self.next_envelope);
            self.next_envelope += 1;
        }
        match command {
            CommandRef::Select => success(None, &[]),
            CommandRef::OpenSession { mode, session_id } => {
                assert_eq!(mode, Mode::Normal);
                assert!(self.session_id.is_none());
                self.session_id = Some(*session_id);
                success(Some(qk_card_protocol::EnvelopeRef::new(session_id, 0)), &[])
            }
            CommandRef::GetInfo { envelope } => {
                let reference = hex(field(CARD, "normal_info_response_hex"));
                let mut info = reference[21..reference.len() - 2].to_vec();
                info[3] = self.profile;
                match fault {
                    Fault::InfoProfile => info[3] = if self.profile == 1 { 2 } else { 1 },
                    Fault::InfoLifecycle => info[2] = 0,
                    Fault::InfoWallet => info[21] ^= 1,
                    Fault::InfoFingerprint => info[53] ^= 1,
                    Fault::InfoXpub => info[70] ^= 1,
                    _ => {}
                }
                success(Some(envelope), &info)
            }
            CommandRef::ReadDChunk {
                envelope,
                selector,
                offset,
            } => {
                assert_eq!(
                    (selector, offset),
                    [
                        (DescriptorSelector::Receive, 0),
                        (DescriptorSelector::Receive, 192),
                        (DescriptorSelector::Change, 0),
                        (DescriptorSelector::Change, 192),
                    ][ordinal - 4]
                );
                let descriptor = field(
                    CARD,
                    match selector {
                        DescriptorSelector::Receive => "receive_descriptor",
                        DescriptorSelector::Change => "change_descriptor",
                    },
                )
                .as_bytes();
                let start = usize::from(offset);
                let end = descriptor.len().min(start + 192);
                let mut tail = vec![selector.byte()];
                tail.extend_from_slice(&offset.to_be_bytes());
                tail.extend_from_slice(&descriptor[start..end]);
                if fault == Fault::Descriptor {
                    tail[3] ^= 1;
                }
                success(Some(envelope), &tail)
            }
            CommandRef::ExportA2 { envelope, purpose } => {
                let mut tail = vec![purpose.byte()];
                tail.extend_from_slice(&hex(field(CARD, "a2_hex")));
                success(Some(envelope), &tail)
            }
            CommandRef::SignDigest {
                envelope,
                wallet_id,
                review_hash,
                input_index,
                branch,
                child_index,
                digest,
            } => {
                assert_eq!(wallet_id.as_slice(), hex(field(CARD, "wallet_id_hex")));
                assert_eq!((branch, child_index), (0, 0));
                let mut review = *review_hash;
                let mut index = input_index;
                let mut key = hex(field(CARD, "route_public_key_hex"));
                let mut der = sign(digest);
                let kind = match fault {
                    Fault::Sign { kind, .. } => Some(kind),
                    _ => None,
                };
                match kind {
                    Some(SignFault::WrongReview) => review[0] ^= 1,
                    Some(SignFault::WrongIndex) => index = index.saturating_add(1),
                    Some(SignFault::WrongKey) => key[1] ^= 1,
                    Some(SignFault::MalformedDer) => der = vec![0; 8],
                    Some(SignFault::Invalid) => *der.last_mut().expect("DER end") ^= 1,
                    Some(SignFault::HighS) => {
                        der = high_s(&der);
                    }
                    Some(SignFault::Repeated) => {
                        der = self.last_der.clone().expect("prior public signature");
                    }
                    _ => {}
                }
                self.last_der = Some(der.clone());
                let mut tail = review.to_vec();
                tail.extend_from_slice(&index.to_be_bytes());
                tail.extend_from_slice(&key);
                tail.push(u8::try_from(der.len()).expect("bounded DER"));
                tail.extend_from_slice(&der);
                let mut response = success(Some(envelope), &tail);
                match kind {
                    Some(SignFault::WrongSession) => response[1] ^= 1,
                    Some(SignFault::WrongCounter) => response[20] ^= 1,
                    _ => {}
                }
                response
            }
            _ => panic!("unregistered application command"),
        }
    }
}

impl Sec1210DescriptorV2 for FixtureDescriptor {
    fn write(
        &mut self,
        bytes: &[u8],
        _maximum_wait_ms: u64,
    ) -> Result<Sec1210DescriptorWriteV2, Sec1210DescriptorErrorV2> {
        self.trace.0.borrow_mut().writes.push(bytes.to_vec());
        assert!(bytes.len() >= 13);
        assert_eq!(&bytes[..2], &[3, 6]);
        assert_eq!(bytes.iter().fold(0, |checksum, byte| checksum ^ byte), 0);
        assert_eq!(bytes[7], 0);
        let length = u32::from_le_bytes(bytes[3..7].try_into().expect("CCID length")) as usize;
        assert_eq!(bytes.len(), length + 13);
        let sequence = bytes[8];
        let payload = &bytes[12..bytes.len() - 1];
        let configured_fault = self.trace.0.borrow().fault;
        let mut active_fault = match configured_fault {
            Fault::Sign { .. } => Fault::None,
            other => other,
        };
        let mut frame = match bytes[2] {
            0x65 => {
                assert!(payload.is_empty());
                controller_response(0x81, sequence, 1, 1, &[])
            }
            0x62 => {
                assert_eq!(bytes[9], 2);
                controller_response(0x80, sequence, 0, 0, &hex("3bd518ff8191fe1fc38073c821100a"))
            }
            0x6c => controller_response(0x82, sequence, 0, 1, &hex("1110ff4d00fe00")),
            0x61 => {
                assert_eq!(bytes[9], 1);
                assert_eq!(payload, hex("1810ff4d00fe00"));
                controller_response(0x82, sequence, 0, 1, payload)
            }
            0x6f if payload == hex("00c101fe3e") => {
                controller_response(0x80, sequence, 0, 0, &hex("00e101fe1e"))
            }
            0x6f => {
                assert!(payload.len() >= 4);
                assert_eq!(payload[0], 0);
                assert_eq!(payload[1] & !0x40, 0);
                assert_eq!(payload.len(), usize::from(payload[2]) + 4);
                assert_eq!(payload.iter().fold(0, |checksum, byte| checksum ^ byte), 0);
                let apdu = &payload[3..payload.len() - 1];
                let is_sign = apdu.get(1) == Some(&0x15);
                {
                    let mut trace = self.trace.0.borrow_mut();
                    trace.apdus.push(apdu.to_vec());
                    if is_sign {
                        trace.signs += 1;
                    }
                    active_fault = configured_fault;
                    if let Fault::Sign { ordinal, .. } = active_fault {
                        if !is_sign || trace.signs != ordinal {
                            active_fault = Fault::None;
                        }
                    }
                }
                match active_fault {
                    Fault::Sign {
                        kind: SignFault::ShortWrite,
                        ..
                    } => return Ok(Sec1210DescriptorWriteV2::Bytes(bytes.len() - 1)),
                    Fault::Sign {
                        kind: SignFault::WriteFailure,
                        ..
                    } => return Err(Sec1210DescriptorErrorV2),
                    Fault::Sign {
                        kind: SignFault::Removed,
                        ..
                    } => {
                        self.reads.push_back(Read::Removed);
                        return Ok(Sec1210DescriptorWriteV2::Bytes(bytes.len()));
                    }
                    Fault::Sign {
                        kind: SignFault::ReadFailure,
                        ..
                    } => {
                        self.reads.push_back(Read::Failed);
                        return Ok(Sec1210DescriptorWriteV2::Bytes(bytes.len()));
                    }
                    Fault::Sign {
                        kind: SignFault::TimedOut,
                        ..
                    } => {
                        self.reads.push_back(Read::TimedOut);
                        return Ok(Sec1210DescriptorWriteV2::Bytes(bytes.len()));
                    }
                    _ => {}
                }
                let response = self.application_response(apdu, active_fault);
                let mut block = vec![
                    0,
                    payload[1],
                    u8::try_from(response.len()).expect("unchained response"),
                ];
                block.extend_from_slice(&response);
                block.push(block.iter().fold(0, |checksum, byte| checksum ^ byte));
                controller_response(0x80, sequence, 0, 0, &block)
            }
            _ => panic!("unregistered reader command"),
        };
        if matches!(
            active_fault,
            Fault::Sign {
                kind: SignFault::BadChecksum,
                ..
            }
        ) {
            *frame.last_mut().expect("CCID checksum") ^= 1;
        }
        self.reads.push_back(Read::Bytes(frame));
        Ok(Sec1210DescriptorWriteV2::Bytes(bytes.len()))
    }

    fn read(
        &mut self,
        output: &mut [u8],
        maximum_wait_ms: u64,
    ) -> Result<Sec1210DescriptorReadV2, Sec1210DescriptorErrorV2> {
        match self.reads.pop_front().unwrap_or(Read::Removed) {
            Read::Removed => Ok(Sec1210DescriptorReadV2::EndOfStream),
            Read::Failed => Err(Sec1210DescriptorErrorV2),
            Read::TimedOut => {
                let mut trace = self.trace.0.borrow_mut();
                trace.now_ms = trace.now_ms.saturating_add(maximum_wait_ms);
                Ok(Sec1210DescriptorReadV2::TimedOut)
            }
            Read::Bytes(bytes) => {
                let limit = self.trace.0.borrow().fragment_bytes;
                let length =
                    output
                        .len()
                        .min(bytes.len())
                        .min(if limit == 0 { usize::MAX } else { limit });
                output[..length].copy_from_slice(&bytes[..length]);
                if length < bytes.len() {
                    self.reads.push_front(Read::Bytes(bytes[length..].to_vec()));
                }
                Ok(Sec1210DescriptorReadV2::Bytes(length))
            }
        }
    }
}

impl Drop for FixtureDescriptor {
    fn drop(&mut self) {
        self.trace.0.borrow_mut().descriptor_dropped = true;
    }
}

#[test]
fn public_fixture_construction_preserves_lineage_and_input_bounds() {
    assert_eq!(psbt_with_inputs(1), psbt());
    for count in [1, 3, 100] {
        let bytes = psbt_with_inputs(count);
        let validated = proof(&bytes);
        validated
            .revalidate()
            .expect("derived public proof revalidates");
        assert_eq!(validated.input_signing_plans().len(), count);
        assert!(validated.input_signing_plans().iter().all(|plan| {
            plan.branch() == 0 && plan.child_index() == 0 && !plan.existing_role_signatures()[1]
        }));
    }
    for (count, present) in [(1, vec![0]), (3, vec![0, 2])] {
        let validated = proof(&psbt_with_existing_b(count, &present));
        for (index, plan) in validated.input_signing_plans().iter().enumerate() {
            assert_eq!(plan.existing_role_signatures()[1], present.contains(&index));
        }
    }
}
