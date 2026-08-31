use core::fmt::Write;

use crate::{
    EnrollmentError, EnrollmentRecord, ACTIVE_ALLOWLIST_ID, MAX_TRANSCRIPT_BYTES, TOOL_VERSION,
    TRANSCRIPT_VERSION,
};

pub fn encode_transcript(record: &EnrollmentRecord) -> Result<Vec<u8>, EnrollmentError> {
    let metadata = record.metadata.inner();
    let mut text = String::with_capacity(1_024);
    writeln!(text, "{TRANSCRIPT_VERSION}").expect("String writes cannot fail");
    writeln!(text, "allowlist={ACTIVE_ALLOWLIST_ID}").expect("String writes cannot fail");
    writeln!(text, "tool_version={TOOL_VERSION}").expect("String writes cannot fail");
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
    writeln!(text, "mode={}", metadata.mode.as_str()).expect("String writes cannot fail");
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
    match record.capture.as_ref() {
        Some(capture) => {
            writeln!(text, "protocol={}", capture.protocol.as_str())
                .expect("String writes cannot fail");
            text.push_str("atr_hex=");
            write_hex(&mut text, &capture.atr);
            text.push('\n');
        }
        None => text.push_str("protocol=NONE\natr_hex=NONE\n"),
    }
    text.push_str("apdu_tx_count=0\napdu_rx_count=0\n");
    writeln!(text, "result={}", record.outcome.as_str()).expect("String writes cannot fail");
    if text.len() > MAX_TRANSCRIPT_BYTES {
        return Err(EnrollmentError::TranscriptTooLarge);
    }
    debug_assert!(text.is_ascii());
    Ok(text.into_bytes())
}

fn write_hex(output: &mut String, input: &[u8]) {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    for byte in input {
        output.push(char::from(HEX[usize::from(byte >> 4)]));
        output.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        encode_transcript, CardCapture, EnrollmentEvent, EnrollmentMetadata, EnrollmentMode,
        EnrollmentOperation, EnrollmentOutcome, NegotiatedProtocol,
    };

    #[test]
    fn transcript_is_ascii_complete_and_lf_terminated() {
        let metadata = EnrollmentMetadata {
            mode: EnrollmentMode::Enroll,
            source_commit: "0123456789abcdef0123456789abcdef01234567".to_owned(),
            timestamp_utc: "2026-08-31T12:34:56Z".to_owned(),
            host_alias: "iMac".to_owned(),
            reader_alias: "SCR3310-01".to_owned(),
            specimen_alias: Some("J3R180-02".to_owned()),
            selected_reader_name: Some(vec![0x41, 0x80]),
        }
        .validate()
        .expect("valid metadata");
        let record = crate::EnrollmentRecord {
            metadata,
            readers: vec![vec![0x41, 0x80]],
            events: vec![EnrollmentEvent {
                operation: EnrollmentOperation::EnumerateReaders,
                outcome: EnrollmentOutcome::Pass,
            }],
            capture: Some(CardCapture {
                atr: vec![0x3b, 0x00],
                protocol: NegotiatedProtocol::T1,
            }),
            outcome: EnrollmentOutcome::Pass,
        };
        let bytes = encode_transcript(&record).expect("transcript");
        assert!(bytes.is_ascii());
        assert!(bytes.ends_with(b"\n"));
        let text = String::from_utf8(bytes).expect("ASCII");
        assert!(text.contains("reader.0.name_hex=4180\n"));
        assert!(text.contains("selected_reader_name_hex=4180\n"));
        assert!(text.contains("atr_hex=3b00\n"));
        assert!(text.contains("apdu_tx_count=0\napdu_rx_count=0\n"));
    }
}
