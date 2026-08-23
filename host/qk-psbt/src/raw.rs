//! Low-level offset/length views and record decoding over one
//! immutable borrowed buffer. No copying, no allocation, no panics.

use crate::error::{ParseError, RejectCategory};

/// A bounded byte-range view into the parsed input buffer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Span {
    /// Inclusive start offset in the input buffer.
    pub start: usize,
    /// Exclusive end offset in the input buffer.
    pub end: usize,
}

impl Span {
    /// Length of the range in bytes.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.end.saturating_sub(self.start)
    }

    /// Whether the range is empty.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.end <= self.start
    }

    /// Resolve the range against a buffer; `None` if out of bounds.
    #[must_use]
    pub fn slice<'a>(&self, buf: &'a [u8]) -> Option<&'a [u8]> {
        buf.get(self.start..self.end)
    }
}

/// Decode one minimally encoded CompactSize at `pos`.
/// Returns `(value, encoded_length)`.
pub(crate) fn decode_compact_size(buf: &[u8], pos: usize) -> Result<(u64, usize), ParseError> {
    let trunc = ParseError::new(RejectCategory::Truncated, pos);
    let nonmin = ParseError::new(RejectCategory::NonMinimalCompactSize, pos);
    let first = *buf.get(pos).ok_or(trunc)?;
    let tail = |n: usize| -> Result<&[u8], ParseError> {
        let s = pos.checked_add(1).ok_or(trunc)?;
        let e = s.checked_add(n).ok_or(trunc)?;
        buf.get(s..e).ok_or(trunc)
    };
    match first {
        0xfd => {
            let b: [u8; 2] = tail(2)?.try_into().map_err(|_| trunc)?;
            let v = u64::from(u16::from_le_bytes(b));
            if v < 0xfd {
                return Err(nonmin);
            }
            Ok((v, 3))
        }
        0xfe => {
            let b: [u8; 4] = tail(4)?.try_into().map_err(|_| trunc)?;
            let v = u64::from(u32::from_le_bytes(b));
            if v <= 0xffff {
                return Err(nonmin);
            }
            Ok((v, 5))
        }
        0xff => {
            let b: [u8; 8] = tail(8)?.try_into().map_err(|_| trunc)?;
            let v = u64::from_le_bytes(b);
            if v <= 0xffff_ffff {
                return Err(nonmin);
            }
            Ok((v, 9))
        }
        _ => Ok((u64::from(first), 1)),
    }
}

/// A decoded key-value record (borrowed spans only).
#[derive(Debug, Clone, Copy)]
pub(crate) struct RawRecord {
    pub key_type: u64,
    /// Complete raw key: key type bytes plus key data (no length prefix).
    pub full_key: Span,
    /// Key data after the CompactSize key type.
    pub key_data: Span,
    /// Value bytes.
    pub value: Span,
    /// Offset one past the end of this record.
    pub end: usize,
}

pub(crate) enum Item {
    /// A `0x00` map separator; `end` is one past it.
    Separator {
        end: usize,
    },
    Record(RawRecord),
}

/// Decode one record or separator at `pos`. Every CompactSize must be
/// minimal, including the key type inside each non-empty key, and the
/// key type must lie entirely within the key bytes.
pub(crate) fn decode_record(buf: &[u8], pos: usize) -> Result<Item, ParseError> {
    let trunc = |o: usize| ParseError::new(RejectCategory::Truncated, o);
    let (key_len, kl_sz) = decode_compact_size(buf, pos)?;
    let key_start = pos.checked_add(kl_sz).ok_or(trunc(pos))?;
    if key_len == 0 {
        return Ok(Item::Separator { end: key_start });
    }
    let key_len = usize::try_from(key_len).map_err(|_| trunc(pos))?;
    let key_end = key_start.checked_add(key_len).ok_or(trunc(pos))?;
    let key_bytes = buf.get(key_start..key_end).ok_or(trunc(key_start))?;
    let (key_type, kt_sz) = decode_compact_size(key_bytes, 0).map_err(|e| match e.category {
        RejectCategory::Truncated => {
            ParseError::new(RejectCategory::InvalidKeyStructure, key_start)
        }
        _ => ParseError::new(e.category, key_start),
    })?;
    let key_data_start = key_start.checked_add(kt_sz).ok_or(trunc(key_start))?;
    let (value_len, vl_sz) = decode_compact_size(buf, key_end)?;
    let value_len = usize::try_from(value_len).map_err(|_| trunc(key_end))?;
    let value_start = key_end.checked_add(vl_sz).ok_or(trunc(key_end))?;
    let value_end = value_start.checked_add(value_len).ok_or(trunc(key_end))?;
    if buf.get(value_start..value_end).is_none() {
        return Err(trunc(value_start.min(buf.len())));
    }
    Ok(Item::Record(RawRecord {
        key_type,
        full_key: Span {
            start: key_start,
            end: key_end,
        },
        key_data: Span {
            start: key_data_start,
            end: key_end,
        },
        value: Span {
            start: value_start,
            end: value_end,
        },
        end: value_end,
    }))
}

/// One preserved record yielded by [`Records`]: resolved borrowed byte
/// slices plus the offset/length spans they came from.
#[derive(Debug, Clone, Copy)]
pub struct Record<'a> {
    /// Decoded CompactSize key type.
    pub key_type: u64,
    /// Complete raw key bytes (type bytes plus key data).
    pub full_key: &'a [u8],
    /// Key data bytes after the key type.
    pub key_data: &'a [u8],
    /// Value bytes, verbatim.
    pub value: &'a [u8],
    /// Span of `full_key` in the input buffer.
    pub full_key_span: Span,
    /// Span of `key_data` in the input buffer.
    pub key_data_span: Span,
    /// Span of `value` in the input buffer.
    pub value_span: Span,
}

/// Iterator over the records of one already-validated map. Yields every
/// record verbatim, including preserved unknown and proprietary
/// records, in on-wire order. Never panics; stops at the separator.
#[derive(Debug, Clone)]
pub struct Records<'a> {
    buf: &'a [u8],
    pos: usize,
    end: usize,
}

impl<'a> Records<'a> {
    pub(crate) const fn new(buf: &'a [u8], span: Span) -> Self {
        Self {
            buf,
            pos: span.start,
            end: span.end,
        }
    }
}

impl<'a> Iterator for Records<'a> {
    type Item = Record<'a>;

    fn next(&mut self) -> Option<Record<'a>> {
        if self.pos >= self.end {
            return None;
        }
        match decode_record(self.buf, self.pos) {
            Ok(Item::Record(r)) if r.end <= self.end => {
                self.pos = r.end;
                Some(Record {
                    key_type: r.key_type,
                    full_key: r.full_key.slice(self.buf)?,
                    key_data: r.key_data.slice(self.buf)?,
                    value: r.value.slice(self.buf)?,
                    full_key_span: r.full_key,
                    key_data_span: r.key_data,
                    value_span: r.value,
                })
            }
            _ => {
                // Separator, decode failure, or overrun: end iteration.
                self.pos = self.end;
                None
            }
        }
    }
}
