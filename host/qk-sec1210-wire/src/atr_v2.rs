//! Bounded structural ATR validation for the production SEC1210 profile.

use crate::codec::{FixedMessage, Response};
use crate::wipe;
use crate::{Decoder, Error, MAX_WIRE_BYTES};

/// ISO/IEC 7816-3 maximum: TS plus at most 32 following ATR bytes.
pub const MAX_PRODUCTION_ATR_BYTES: usize = 33;

const DIRECT_CONVENTION: u8 = 0x3b;
const REQUIRED_FIDI: u8 = 0x18;
const MINIMUM_IFSC: u8 = 221;
const MAXIMUM_IFSC: u8 = 254;
const PROTOCOL_T1: u8 = 1;
const PROTOCOL_GLOBAL: u8 = 15;
const CLASS_B_SUPPORTED: u8 = 0x02;
const FIDI_PARAMETERS: [u8; 7] = [0x18, 0x10, 0xff, 0x4d, 0x00, 0xfe, 0x00];

/// Largest complete T=1 block accepted by the production frame encoder.
pub const MAX_PRODUCTION_TPDU_BYTES: usize = 258;

/// The sole public rejection emitted by production ATR validation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Sec1210AtrProfileRejected;

impl Sec1210AtrProfileRejected {
    pub const fn name(self) -> &'static str {
        "Sec1210AtrProfileRejected"
    }
}

/// The checksum-verified message kind returned by the production decoder.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProductionMessageKind {
    Response,
    SlotChange { bitmap: u8 },
    HardwareError { slot: u8, sequence: u8, code: u8 },
}

/// A checksum-verified allocation-free message from the SEC1210 stream.
///
/// Response storage is present in every value so no message kind introduces
/// heap indirection or a large enum variant.
pub struct ProductionMessage {
    kind: ProductionMessageKind,
    response: ProductionResponse,
}

impl ProductionMessage {
    pub fn kind(&self) -> ProductionMessageKind {
        self.kind
    }

    pub fn response(&self) -> Option<&ProductionResponse> {
        (self.kind == ProductionMessageKind::Response).then_some(&self.response)
    }

    pub fn into_response(self) -> Option<ProductionResponse> {
        let Self { kind, response } = self;
        (kind == ProductionMessageKind::Response).then_some(response)
    }
}

/// One checksum-verified response held in fixed storage.
pub struct ProductionResponse {
    inner: Response,
}

impl ProductionResponse {
    pub fn message_type(&self) -> u8 {
        self.inner.message_type
    }

    pub fn slot(&self) -> u8 {
        self.inner.slot
    }

    pub fn sequence(&self) -> u8 {
        self.inner.sequence
    }

    pub fn status(&self) -> u8 {
        self.inner.status
    }

    pub fn error(&self) -> u8 {
        self.inner.error
    }

    pub fn parameter(&self) -> u8 {
        self.inner.parameter
    }

    pub fn payload(&self) -> &[u8] {
        self.inner.payload()
    }
}

/// Allocation-free facade over the shared SEC1210 incremental decoder.
#[derive(Default)]
pub struct ProductionDecoder {
    inner: Decoder,
}

impl ProductionDecoder {
    pub fn pending_bytes(&self) -> usize {
        self.inner.pending_bytes()
    }

    pub fn finish(&mut self) -> Result<(), Error> {
        self.inner.finish()
    }

    pub fn push(&mut self, byte: u8) -> Result<Option<ProductionMessage>, Error> {
        let message = self.inner.push_fixed(byte)?;
        Ok(message.map(|message| match message {
            FixedMessage::Response => {
                let mut response = Response::zeroed();
                self.inner.take_fixed_response_into(&mut response);
                ProductionMessage {
                    kind: ProductionMessageKind::Response,
                    response: ProductionResponse { inner: response },
                }
            }
            FixedMessage::SlotChange { bitmap } => ProductionMessage {
                kind: ProductionMessageKind::SlotChange { bitmap },
                response: ProductionResponse {
                    inner: Response::zeroed(),
                },
            },
            FixedMessage::HardwareError {
                slot,
                sequence,
                code,
            } => ProductionMessage {
                kind: ProductionMessageKind::HardwareError {
                    slot,
                    sequence,
                    code,
                },
                response: ProductionResponse {
                    inner: Response::zeroed(),
                },
            },
        }))
    }
}

/// One fixed-storage SEC1210 request frame.
pub struct ProductionRequest {
    bytes: [u8; MAX_WIRE_BYTES],
    len: usize,
}

impl ProductionRequest {
    pub fn get_slot_status(sequence: u8) -> Self {
        Self::encode(0x65, sequence, 0, &[])
    }

    pub fn power_on_3v(sequence: u8) -> Self {
        Self::encode(0x62, sequence, 2, &[])
    }

    pub fn get_parameters(sequence: u8) -> Self {
        Self::encode(0x6c, sequence, 0, &[])
    }

    pub fn set_fidi_parameters(sequence: u8) -> Self {
        Self::encode(0x61, sequence, 1, &FIDI_PARAMETERS)
    }

    pub fn xfr_block(sequence: u8, bwi: u8, tpdu: &[u8]) -> Result<Self, Error> {
        if !(4..=MAX_PRODUCTION_TPDU_BYTES).contains(&tpdu.len())
            || usize::from(tpdu[2]) + 4 != tpdu.len()
            || tpdu.iter().fold(0u8, |sum, byte| sum ^ byte) != 0
        {
            return Err(Error::PayloadRejected);
        }
        Ok(Self::encode(0x6f, sequence, bwi, tpdu))
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes[..self.len]
    }

    fn encode(message_type: u8, sequence: u8, parameter: u8, payload: &[u8]) -> Self {
        let mut request = Self {
            bytes: [0; MAX_WIRE_BYTES],
            len: 13 + payload.len(),
        };
        request.bytes[..3].copy_from_slice(&[0x03, 0x06, message_type]);
        request.bytes[3..7].copy_from_slice(&(payload.len() as u32).to_le_bytes());
        request.bytes[8] = sequence;
        request.bytes[9] = parameter;
        request.bytes[12..12 + payload.len()].copy_from_slice(payload);
        request.bytes[request.len - 1] = request.bytes[..request.len - 1]
            .iter()
            .fold(0u8, |sum, byte| sum ^ byte);
        request
    }
}

impl Drop for ProductionRequest {
    fn drop(&mut self) {
        wipe::bytes(&mut self.bytes);
        wipe::values(core::slice::from_mut(&mut self.len), 0);
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum AtrProfileReason {
    Length,
    Convention,
    InterfaceChain,
    Checksum,
    Protocol,
    VoltageClass,
    Edc,
    FiDi,
    Ifsc,
}

#[derive(Clone, Copy)]
struct AtrFacts {
    fidi: Option<u8>,
    ifsc: Option<u8>,
    t1_available: bool,
    class_b_available: bool,
    lrc_only: bool,
}

/// Validate a complete ATR against the production SEC1210 card profile.
///
/// This is structural validation, not comparison with a registered specimen.
/// Every parse and profile failure deliberately collapses to one fieldless
/// public rejection.
pub fn validate_production_atr(atr: &[u8]) -> Result<(), Sec1210AtrProfileRejected> {
    validate_with_reason(atr).map_err(|_| Sec1210AtrProfileRejected)
}

fn validate_with_reason(atr: &[u8]) -> Result<(), AtrProfileReason> {
    let facts = parse(atr)?;
    if !facts.t1_available {
        return Err(AtrProfileReason::Protocol);
    }
    if !facts.class_b_available {
        return Err(AtrProfileReason::VoltageClass);
    }
    if !facts.lrc_only {
        return Err(AtrProfileReason::Edc);
    }
    if facts.fidi != Some(REQUIRED_FIDI) {
        return Err(AtrProfileReason::FiDi);
    }
    if !matches!(facts.ifsc, Some(MINIMUM_IFSC..=MAXIMUM_IFSC)) {
        return Err(AtrProfileReason::Ifsc);
    }
    Ok(())
}

fn parse(atr: &[u8]) -> Result<AtrFacts, AtrProfileReason> {
    if atr.len() < 2 || atr.len() > MAX_PRODUCTION_ATR_BYTES {
        return Err(AtrProfileReason::Length);
    }
    if atr[0] != DIRECT_CONVENTION {
        return Err(AtrProfileReason::Convention);
    }

    let t0 = atr[1];
    let historical_len = usize::from(t0 & 0x0f);
    let mut presence = t0 >> 4;
    let mut offset = 2usize;
    let mut group = 1u8;
    let mut group_protocol = None;
    let mut facts = AtrFacts {
        fidi: None,
        ifsc: None,
        t1_available: false,
        class_b_available: false,
        lrc_only: true,
    };
    let mut tck_required = false;
    let mut global_ta_seen = false;
    let mut t1_tc_seen = false;
    let mut last_protocol = None;

    loop {
        let ta = take_if(atr, &mut offset, presence & 0x01 != 0)?;
        let _tb = take_if(atr, &mut offset, presence & 0x02 != 0)?;
        let tc = take_if(atr, &mut offset, presence & 0x04 != 0)?;
        let td = take_if(atr, &mut offset, presence & 0x08 != 0)?;

        if group == 1 {
            facts.fidi = ta;
        }
        // TA2 selects specific mode rather than carrying a T=1 IFSC. This
        // profile relies on reader-owned negotiable-mode PPS, so TA2 is not
        // compatible with the fixed initialization sequence.
        if group == 2 && ta.is_some() {
            return Err(AtrProfileReason::Protocol);
        }
        if group >= 3 && group_protocol == Some(PROTOCOL_T1) {
            if facts.ifsc.is_none() {
                facts.ifsc = ta;
            }
            if !t1_tc_seen {
                if let Some(value) = tc {
                    t1_tc_seen = true;
                    // Only 00 (LRC) and 01 (CRC) are defined. Any higher
                    // value carries reserved bits and is not an LRC profile.
                    facts.lrc_only = value == 0;
                }
            }
        }
        if group_protocol == Some(PROTOCOL_GLOBAL) && !global_ta_seen {
            if let Some(value) = ta {
                global_ta_seen = true;
                let classes = value & 0x07;
                let class_mask_defined = matches!(classes, 1 | 2 | 3 | 4 | 6 | 7);
                let reserved_clear = value & 0x38 == 0;
                facts.class_b_available =
                    class_mask_defined && reserved_clear && classes & CLASS_B_SUPPORTED != 0;
            }
        }

        let Some(td) = td else {
            break;
        };
        // Global interface bytes are terminal in the offered-protocol chain.
        if group_protocol == Some(PROTOCOL_GLOBAL) {
            return Err(AtrProfileReason::Protocol);
        }
        let protocol = td & 0x0f;
        if protocol != PROTOCOL_GLOBAL {
            if last_protocol.is_some_and(|last| protocol < last) {
                return Err(AtrProfileReason::Protocol);
            }
            last_protocol = Some(protocol);
        }
        facts.t1_available |= protocol == PROTOCOL_T1;
        tck_required |= protocol != 0;
        group_protocol = Some(protocol);
        presence = td >> 4;
        group = group
            .checked_add(1)
            .ok_or(AtrProfileReason::InterfaceChain)?;
    }

    offset = offset
        .checked_add(historical_len)
        .ok_or(AtrProfileReason::InterfaceChain)?;
    if offset > atr.len() {
        return Err(AtrProfileReason::InterfaceChain);
    }

    if tck_required {
        if offset >= atr.len() {
            return Err(AtrProfileReason::Checksum);
        }
        offset = offset
            .checked_add(1)
            .ok_or(AtrProfileReason::InterfaceChain)?;
        if atr[1..offset].iter().fold(0u8, |sum, byte| sum ^ byte) != 0 {
            return Err(AtrProfileReason::Checksum);
        }
    }
    if offset != atr.len() {
        return Err(AtrProfileReason::InterfaceChain);
    }
    Ok(facts)
}

fn take_if(atr: &[u8], offset: &mut usize, present: bool) -> Result<Option<u8>, AtrProfileReason> {
    if !present {
        return Ok(None);
    }
    let value = *atr.get(*offset).ok_or(AtrProfileReason::InterfaceChain)?;
    *offset = offset
        .checked_add(1)
        .ok_or(AtrProfileReason::InterfaceChain)?;
    Ok(Some(value))
}

#[cfg(test)]
mod tests {
    use super::{validate_with_reason, AtrProfileReason};

    const REGISTERED: [u8; 15] = [
        0x3b, 0xd5, 0x18, 0xff, 0x81, 0x91, 0xfe, 0x1f, 0xc3, 0x80, 0x73, 0xc8, 0x21, 0x10, 0x0a,
    ];

    fn changed(index: usize, value: u8) -> [u8; 15] {
        let mut atr = REGISTERED;
        atr[index] = value;
        let last = atr.len() - 1;
        atr[last] = atr[1..last].iter().fold(0u8, |sum, byte| sum ^ byte);
        atr
    }

    #[test]
    fn every_private_reason_is_reachable() {
        let edc_rfu = [0x3b, 0x90, 0x18, 0x81, 0xd1, 0xdd, 0x02, 0x1f, 0xc3, 0xdb];
        let cases: [(&[u8], AtrProfileReason); 9] = [
            (&[], AtrProfileReason::Length),
            (&[0x3f, 0x00], AtrProfileReason::Convention),
            (&[0x3b, 0x10], AtrProfileReason::InterfaceChain),
            (&REGISTERED[..14], AtrProfileReason::Checksum),
            (&[0x3b, 0x10, 0x18], AtrProfileReason::Protocol),
            (&changed(8, 0xc1), AtrProfileReason::VoltageClass),
            (&edc_rfu, AtrProfileReason::Edc),
            (&changed(2, 0x11), AtrProfileReason::FiDi),
            (&changed(6, 0xdc), AtrProfileReason::Ifsc),
        ];
        for (atr, reason) in cases {
            assert_eq!(validate_with_reason(atr), Err(reason), "{reason:?}");
        }
    }

    #[test]
    fn ta2_specific_mode_cannot_spoof_the_t1_ifsc() {
        let ta2_spoof = [0x3b, 0x90, 0x18, 0xd1, 0xdd, 0x00, 0x1f, 0x02, 0x99];
        assert_eq!(
            validate_with_reason(&ta2_spoof),
            Err(AtrProfileReason::Protocol)
        );
    }

    #[test]
    fn first_t1_parameters_may_appear_in_a_later_protocol_group() {
        let late_ifsc = [0x3b, 0x90, 0x18, 0x81, 0x81, 0x91, 0xfe, 0x1f, 0x02, 0xfa];
        assert_eq!(validate_with_reason(&late_ifsc), Ok(()));
    }

    #[test]
    fn protocol_order_late_crc_and_reserved_voltage_bits_are_rejected() {
        let late_crc = [
            0x3b, 0x90, 0x18, 0x81, 0x91, 0xdd, 0xc1, 0x01, 0x1f, 0x02, 0x98,
        ];
        let descending = [0x3b, 0x90, 0x18, 0x81, 0x91, 0xdd, 0x80, 0x1f, 0x02, 0xd8];
        let global_before_t1 = [0x3b, 0x90, 0x18, 0x8f, 0x91, 0xdd, 0x1f, 0x02, 0x56];
        let reserved_voltage = [0x3b, 0x90, 0x18, 0x81, 0x91, 0xdd, 0x1f, 0x0a, 0x50];
        assert_eq!(validate_with_reason(&late_crc), Err(AtrProfileReason::Edc));
        assert_eq!(
            validate_with_reason(&descending),
            Err(AtrProfileReason::Protocol)
        );
        assert_eq!(
            validate_with_reason(&global_before_t1),
            Err(AtrProfileReason::Protocol)
        );
        assert_eq!(
            validate_with_reason(&reserved_voltage),
            Err(AtrProfileReason::VoltageClass)
        );
    }
}
