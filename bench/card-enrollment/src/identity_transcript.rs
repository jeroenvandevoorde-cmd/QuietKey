use core::fmt::Write;

use crate::{
    identity::validate_identity_record, IdentityError, IdentityOperation, IdentityRecord,
    IDENTITY_ALLOWLIST_ID, IDENTITY_TOOL_VERSION, IDENTITY_TRANSCRIPT_VERSION,
    MAX_TRANSCRIPT_BYTES,
};

pub fn encode_identity_transcript(record: &IdentityRecord) -> Result<Vec<u8>, IdentityError> {
    validate_identity_record(record)?;
    let metadata = record.metadata.inner();
    let mut text = String::with_capacity(2_048);
    writeln!(text, "{IDENTITY_TRANSCRIPT_VERSION}").expect("String writes cannot fail");
    writeln!(text, "allowlist={IDENTITY_ALLOWLIST_ID}").expect("String writes cannot fail");
    writeln!(text, "tool_version={IDENTITY_TOOL_VERSION}").expect("String writes cannot fail");
    writeln!(text, "source_commit={}", metadata.source_commit).expect("String writes cannot fail");
    writeln!(text, "timestamp_utc={}", metadata.timestamp_utc).expect("String writes cannot fail");
    writeln!(text, "host_alias={}", metadata.host_alias).expect("String writes cannot fail");
    writeln!(text, "reader_alias={}", metadata.reader_alias).expect("String writes cannot fail");
    writeln!(
        text,
        "specimen_alias={}",
        metadata.specimen_alias.as_deref().unwrap_or("NONE")
    )
    .expect("String writes cannot fail");
    text.push_str("mode=IDENTITY\n");
    writeln!(text, "reader_count={}", record.readers.len()).expect("String writes cannot fail");
    for (index, reader) in record.readers.iter().enumerate() {
        write!(text, "reader.{index}.name_hex=").expect("String writes cannot fail");
        write_hex(&mut text, reader);
        text.push('\n');
    }
    text.push_str("selected_reader_name_hex=");
    if let Some(reader) = metadata.selected_reader_name.as_deref() {
        write_hex(&mut text, reader);
    } else {
        text.push_str("NONE");
    }
    text.push('\n');
    writeln!(text, "event_count={}", record.events.len()).expect("String writes cannot fail");
    for (index, event) in record.events.iter().enumerate() {
        writeln!(
            text,
            "event.{index}={}:{}",
            event.operation.as_str(),
            event.outcome.as_str()
        )
        .expect("String writes cannot fail");
    }
    match record.observed_protocol {
        Some(protocol) => {
            writeln!(text, "protocol={}", protocol.as_str()).expect("String writes cannot fail");
        }
        None => text.push_str("protocol=NONE\n"),
    }
    match record.observed_atr.as_deref() {
        Some(atr) => {
            text.push_str("atr_hex=");
            write_hex(&mut text, atr);
            text.push('\n');
        }
        None => text.push_str("atr_hex=NONE\n"),
    }
    writeln!(
        text,
        "apdu_tx_count={}",
        record
            .exchanges
            .iter()
            .filter(|exchange| exchange.request.is_some())
            .count()
    )
    .expect("String writes cannot fail");
    writeln!(
        text,
        "apdu_rx_count={}",
        record
            .exchanges
            .iter()
            .filter(|exchange| exchange.response.is_some())
            .count()
    )
    .expect("String writes cannot fail");
    for (index, exchange) in record.exchanges.iter().enumerate() {
        write!(text, "apdu.{index}.tx_hex=").expect("String writes cannot fail");
        write_hex_or_none(&mut text, exchange.request.as_deref());
        text.push('\n');
        write!(text, "apdu.{index}.rx_hex=").expect("String writes cannot fail");
        write_hex_or_none(&mut text, exchange.response.as_deref());
        text.push('\n');
    }
    text.push_str("disconnect=");
    match record
        .events
        .iter()
        .rev()
        .find(|event| event.operation == IdentityOperation::Disconnect)
    {
        Some(event) => text.push_str(event.outcome.as_str()),
        None => text.push_str("NONE"),
    }
    text.push('\n');
    writeln!(text, "result={}", record.outcome.as_str()).expect("String writes cannot fail");
    if text.len() > MAX_TRANSCRIPT_BYTES {
        return Err(IdentityError::TranscriptTooLarge);
    }
    debug_assert!(text.is_ascii());
    Ok(text.into_bytes())
}

fn write_hex_or_none(output: &mut String, input: Option<&[u8]>) {
    match input {
        Some(bytes) => write_hex(output, bytes),
        None => output.push_str("NONE"),
    }
}

fn write_hex(output: &mut String, input: &[u8]) {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    for byte in input {
        output.push(char::from(HEX[usize::from(byte >> 4)]));
        output.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
}
