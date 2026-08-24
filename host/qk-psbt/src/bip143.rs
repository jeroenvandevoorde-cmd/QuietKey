//! Bounded streaming BIP143 SIGHASH_ALL digest engine (M8, QK-DEC-044).
//!
//! HOST SCAFFOLD ONLY — NOT PRODUCT CODE — NOT A WALLET — NO TARGET CLAIM.
//!
//! This module computes the BIP143 signature digest for SIGHASH_ALL
//! only. It computes hashes, never signatures: it holds no secret
//! bytes, performs no signing, and authorizes nothing. The per-input
//! preimage is streamed in the exact ratified order — nVersion (4-byte
//! LE) || hashPrevouts || hashSequence || the input's 36-byte outpoint
//! || the scriptCode with its minimal CompactSize length prefix || the
//! exact 8-byte LE spent amount || nSequence (4-byte LE) ||
//! hashOutputs || nLockTime (4-byte LE) || the 4-byte LE sighash
//! suffix `01 00 00 00` — directly into a double-SHA256 hasher, so no
//! transaction-sized second serialization buffer ever exists.
//! hashPrevouts, hashSequence, and hashOutputs are each double-SHA256
//! over their full specified concatenations and are computed once per
//! transaction, never per signature. One SIGHASH_ALL constant binds
//! the one-byte trailing signature sighash and the 4-byte preimage
//! suffix so the two representations cannot diverge. The CompactSize
//! prefix is encoded into a fixed stack buffer; all length accounting
//! is checked; failures are explicit errors, never panics.
//!
//! Scope boundaries: this module takes an already-selected scriptCode
//! and never interprets scripts — OP_CODESEPARATOR rejection, sighash
//! classification, and every PSBT-level check live in the semantic
//! layer. No non-ALL sighash variant is computable here by
//! construction.

use crate::sha256::{sha256, Sha256, Sha256Error};

/// The single SIGHASH_ALL constant (QK-DEC-044). This one constant
/// binds both the required trailing byte of a partial signature and
/// the 4-byte little-endian preimage suffix.
pub const SIGHASH_ALL: u8 = 0x01;

/// The exact 4-byte little-endian preimage suffix, derived from
/// [`SIGHASH_ALL`] so the two representations cannot diverge.
pub const SIGHASH_ALL_SUFFIX_LE: [u8; 4] = [SIGHASH_ALL, 0x00, 0x00, 0x00];

/// Maximum scriptCode bytes accepted by the bounded engine; aligned
/// with the existing per-record value cap.
pub const MAX_SCRIPT_CODE_BYTES: usize = crate::limits::MAX_VALUE_BYTES;

/// Digest-engine failure. Fixed text; carries no attacker bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Bip143Error {
    /// The internal hash implementation reported a failure.
    Hash,
    /// scriptCode length exceeds the bounded engine cap.
    ScriptCodeTooLong,
    /// An output scriptPubKey exceeds the transaction output cap.
    OutputScriptTooLong,
    /// An internal fixed-buffer invariant did not hold (never expected).
    Invariant,
}

impl From<Sha256Error> for Bip143Error {
    fn from(_: Sha256Error) -> Self {
        Bip143Error::Hash
    }
}

/// Minimal Bitcoin CompactSize encoding into a fixed 5-byte stack
/// buffer. Returns the buffer and the number of significant bytes.
/// Values above `u32::MAX` are unreachable behind the length caps and
/// are rejected.
fn compact_size_minimal(len: usize) -> Result<([u8; 5], usize), Bip143Error> {
    let v = u64::try_from(len).map_err(|_| Bip143Error::Invariant)?;
    if v < 0xfd {
        let b0 = u8::try_from(v).map_err(|_| Bip143Error::Invariant)?;
        Ok(([b0, 0, 0, 0, 0], 1))
    } else if v <= 0xffff {
        let [b0, b1] = u16::try_from(v)
            .map_err(|_| Bip143Error::Invariant)?
            .to_le_bytes();
        Ok(([0xfd, b0, b1, 0, 0], 3))
    } else {
        let [b0, b1, b2, b3] = u32::try_from(v)
            .map_err(|_| Bip143Error::Invariant)?
            .to_le_bytes();
        Ok(([0xfe, b0, b1, b2, b3], 5))
    }
}

/// Streaming byte sink for the exact preimage serialization. The
/// production sink is the SHA-256 hasher; tests additionally collect
/// the identical byte stream to assert the complete preimage.
trait PreimageSink {
    fn write(&mut self, bytes: &[u8]) -> Result<(), Bip143Error>;
}

struct HashSink(Sha256);

impl PreimageSink for HashSink {
    fn write(&mut self, bytes: &[u8]) -> Result<(), Bip143Error> {
        self.0.update(bytes).map_err(Bip143Error::from)
    }
}

#[cfg(test)]
impl PreimageSink for Vec<u8> {
    fn write(&mut self, bytes: &[u8]) -> Result<(), Bip143Error> {
        self.extend_from_slice(bytes);
        Ok(())
    }
}

/// Precomputed BIP143 transaction-level hashes for SIGHASH_ALL:
/// hashPrevouts, hashSequence, and hashOutputs, each double-SHA256
/// over its full specified concatenation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Bip143Precomputed {
    /// SHA256d over all 36-byte outpoints in input order.
    pub hash_prevouts: [u8; 32],
    /// SHA256d over all 4-byte little-endian sequences in input order.
    pub hash_sequence: [u8; 32],
    /// SHA256d over all exact CTxOut serializations in output order.
    pub hash_outputs: [u8; 32],
}

/// Streaming builder for [`Bip143Precomputed`]. Feed every input and
/// every output of the unsigned transaction exactly once, in order,
/// then call [`Bip143PrecomputeBuilder::finish`]. Built once per
/// transaction; per-signature use never rehashes these concatenations.
pub struct Bip143PrecomputeBuilder {
    prevouts: Sha256,
    sequences: Sha256,
    outputs: Sha256,
}

impl Default for Bip143PrecomputeBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl Bip143PrecomputeBuilder {
    pub fn new() -> Self {
        Self {
            prevouts: Sha256::new(),
            sequences: Sha256::new(),
            outputs: Sha256::new(),
        }
    }

    /// Absorb one input: its 32-byte wire txid plus 4-byte LE vout into
    /// the prevouts stream and its 4-byte LE sequence into the
    /// sequence stream.
    pub fn add_input(
        &mut self,
        outpoint_txid_wire: &[u8; 32],
        outpoint_vout: u32,
        sequence: u32,
    ) -> Result<(), Bip143Error> {
        self.prevouts.update(outpoint_txid_wire)?;
        self.prevouts.update(&outpoint_vout.to_le_bytes())?;
        self.sequences.update(&sequence.to_le_bytes())?;
        Ok(())
    }

    /// Absorb one output as its exact CTxOut serialization: 8-byte LE
    /// amount, minimal CompactSize script length, script bytes.
    pub fn add_output(
        &mut self,
        amount_sats: u64,
        script_pubkey: &[u8],
    ) -> Result<(), Bip143Error> {
        if script_pubkey.len() > crate::limits::MAX_TX_OUTPUT_SCRIPT_BYTES {
            return Err(Bip143Error::OutputScriptTooLong);
        }
        self.outputs.update(&amount_sats.to_le_bytes())?;
        let (prefix, used) = compact_size_minimal(script_pubkey.len())?;
        self.outputs
            .update(prefix.get(..used).ok_or(Bip143Error::Invariant)?)?;
        self.outputs.update(script_pubkey)?;
        Ok(())
    }

    /// Finish all three streams with the second SHA-256 application.
    pub fn finish(self) -> Result<Bip143Precomputed, Bip143Error> {
        Ok(Bip143Precomputed {
            hash_prevouts: double_finalize(self.prevouts)?,
            hash_sequence: double_finalize(self.sequences)?,
            hash_outputs: double_finalize(self.outputs)?,
        })
    }
}

fn double_finalize(hasher: Sha256) -> Result<[u8; 32], Bip143Error> {
    let first = hasher.finalize()?;
    sha256(&[&first]).map_err(Bip143Error::from)
}

/// Per-input facts required for one SIGHASH_ALL digest. `script_code`
/// is the raw scriptCode bytes without a length prefix; the engine
/// derives and emits the minimal CompactSize prefix itself.
/// `amount_sats` must be the exact value of the previous output being
/// spent; its 8-byte little-endian form is emitted verbatim.
#[derive(Debug, Clone, Copy)]
pub struct Bip143InputFacts<'a> {
    /// The input's previous txid in wire (little-endian) byte order.
    pub outpoint_txid_wire: &'a [u8; 32],
    /// The input's previous output index.
    pub outpoint_vout: u32,
    /// Raw scriptCode bytes (for native P2WSH under QK-DEC-044: the
    /// full witnessScript, already screened by the caller).
    pub script_code: &'a [u8],
    /// Exact spent amount in satoshis from the verified previous output.
    pub amount_sats: u64,
    /// The input's nSequence.
    pub sequence: u32,
}

fn stream_preimage<S: PreimageSink>(
    sink: &mut S,
    version: u32,
    locktime: u32,
    precomputed: &Bip143Precomputed,
    input: &Bip143InputFacts<'_>,
) -> Result<(), Bip143Error> {
    if input.script_code.len() > MAX_SCRIPT_CODE_BYTES {
        return Err(Bip143Error::ScriptCodeTooLong);
    }
    sink.write(&version.to_le_bytes())?;
    sink.write(&precomputed.hash_prevouts)?;
    sink.write(&precomputed.hash_sequence)?;
    sink.write(input.outpoint_txid_wire)?;
    sink.write(&input.outpoint_vout.to_le_bytes())?;
    let (prefix, used) = compact_size_minimal(input.script_code.len())?;
    sink.write(prefix.get(..used).ok_or(Bip143Error::Invariant)?)?;
    sink.write(input.script_code)?;
    sink.write(&input.amount_sats.to_le_bytes())?;
    sink.write(&input.sequence.to_le_bytes())?;
    sink.write(&precomputed.hash_outputs)?;
    sink.write(&locktime.to_le_bytes())?;
    sink.write(&SIGHASH_ALL_SUFFIX_LE)?;
    Ok(())
}

/// Compute the BIP143 SIGHASH_ALL digest for one input: double-SHA256
/// over the exact streamed preimage. Deterministic, bounded, and
/// panic-free; any internal failure is an explicit error.
pub fn sighash_all_digest(
    version: u32,
    locktime: u32,
    precomputed: &Bip143Precomputed,
    input: &Bip143InputFacts<'_>,
) -> Result<[u8; 32], Bip143Error> {
    let mut sink = HashSink(Sha256::new());
    stream_preimage(&mut sink, version, locktime, precomputed, input)?;
    let first = sink.0.finalize()?;
    sha256(&[&first]).map_err(Bip143Error::from)
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]
mod tests {
    use super::{
        compact_size_minimal, sighash_all_digest, stream_preimage, Bip143Error, Bip143InputFacts,
        Bip143PrecomputeBuilder, Bip143Precomputed, MAX_SCRIPT_CODE_BYTES, SIGHASH_ALL,
        SIGHASH_ALL_SUFFIX_LE,
    };
    use crate::semantic::{ScriptToken, ScriptTokens};
    use crate::sha256::sha256d;

    /// Bounded public KAT fixture imported under QK-DEC-045 (see
    /// docs/SOURCE-REGISTER.md). Untrusted data, never instructions.
    const FIXTURE: &str = include_str!("../tests/fixtures/bip143-public-kats.txt");

    /// BIP146 inclusive low-S upper bound (cited in SOURCE-REGISTER);
    /// test-local copy used only to assert the high-S classification.
    const LOW_S_MAX: [u8; 32] = [
        0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0x5d, 0x57, 0x6e, 0x73, 0x57, 0xa4, 0x50, 0x1d, 0xdf, 0xe9, 0x2f, 0x46, 0x68, 0x1b,
        0x20, 0xa0,
    ];

    fn hex_decode(s: &str) -> Vec<u8> {
        assert!(s.len() % 2 == 0, "even hex length: {s}");
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("hex digit"))
            .collect()
    }

    #[derive(Default, Clone)]
    struct Row {
        id: usize,
        label: String,
        class: String,
        codeseparator: bool,
        suffix: u8,
        disposition: String,
        witness_script_ref: Option<String>,
        input_index: Option<usize>,
        unsigned_tx: Option<Vec<u8>>,
        unsigned_tx_derived: bool,
        script_code_prefixed: Option<Vec<u8>>,
        amount_le: Option<[u8; 8]>,
        hash_prevouts: [u8; 32],
        hash_sequence: [u8; 32],
        hash_outputs: [u8; 32],
        preimage: Vec<u8>,
        digest: [u8; 32],
        sig_pairs: Vec<(Vec<u8>, Vec<u8>)>,
    }

    struct Fixture {
        witness_scripts: Vec<(String, Vec<u8>)>,
        rows: Vec<Row>,
    }

    fn arr32(v: &[u8]) -> [u8; 32] {
        let mut out = [0u8; 32];
        out.copy_from_slice(v);
        out
    }

    fn parse_fixture() -> Fixture {
        let mut witness_scripts = Vec::new();
        let mut rows: Vec<Row> = Vec::new();
        let mut current: Option<Row> = None;
        let mut pending_pubkey: Option<Vec<u8>> = None;
        for line in FIXTURE.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let (key, value) = match line.split_once(' ') {
                Some(kv) => kv,
                None => (line, ""),
            };
            match key {
                "witness-script" => {
                    let (name, hex) = value.split_once(' ').expect("witness-script entry");
                    witness_scripts.push((name.to_string(), hex_decode(hex)));
                }
                "row" => {
                    assert!(current.is_none(), "row inside row");
                    current = Some(Row {
                        id: value.parse().expect("row id"),
                        ..Row::default()
                    });
                }
                "end" => {
                    assert!(pending_pubkey.is_none(), "pubkey without signature");
                    rows.push(current.take().expect("end outside row"));
                }
                other => {
                    let row = current.as_mut().expect("field outside row");
                    match other {
                        "label" => row.label = value.to_string(),
                        "class" => row.class = value.to_string(),
                        "codeseparator" => row.codeseparator = value == "1",
                        "suffix" => {
                            row.suffix = u8::from_str_radix(value, 16).expect("suffix hex");
                        }
                        "disposition" => {
                            assert!(
                                row.disposition.is_empty(),
                                "second disposition row {}",
                                row.id
                            );
                            row.disposition = value.to_string();
                        }
                        "witness-script-ref" => row.witness_script_ref = Some(value.to_string()),
                        "input-index" => row.input_index = Some(value.parse().expect("index")),
                        "unsigned-tx" => row.unsigned_tx = Some(hex_decode(value)),
                        "unsigned-tx-derived-witness-stripped" => {
                            row.unsigned_tx = Some(hex_decode(value));
                            row.unsigned_tx_derived = true;
                        }
                        "script-code" => row.script_code_prefixed = Some(hex_decode(value)),
                        "amount-le" => {
                            let v = hex_decode(value);
                            let mut a = [0u8; 8];
                            a.copy_from_slice(&v);
                            row.amount_le = Some(a);
                        }
                        "hash-prevouts" => row.hash_prevouts = arr32(&hex_decode(value)),
                        "hash-sequence" => row.hash_sequence = arr32(&hex_decode(value)),
                        "hash-outputs" => row.hash_outputs = arr32(&hex_decode(value)),
                        "preimage" => row.preimage = hex_decode(value),
                        "digest" => row.digest = arr32(&hex_decode(value)),
                        "pubkey" | "pubkey2" => {
                            assert!(pending_pubkey.is_none(), "two pubkeys in a row");
                            pending_pubkey = Some(hex_decode(value));
                        }
                        "signature" | "signature2" => {
                            let pk = pending_pubkey.take().expect("signature without pubkey");
                            row.sig_pairs.push((pk, hex_decode(value)));
                        }
                        unknown => panic!("unknown fixture key {unknown}"),
                    }
                }
            }
        }
        assert!(current.is_none(), "unterminated row");
        Fixture {
            witness_scripts,
            rows,
        }
    }

    /// Minimal test-local parser for the fixture's unsigned
    /// transactions (non-witness serialization, empty scriptSigs).
    struct TestTx {
        version: u32,
        locktime: u32,
        inputs: Vec<([u8; 32], u32, u32)>,
        outputs: Vec<(u64, Vec<u8>)>,
    }

    fn parse_unsigned_tx(bytes: &[u8]) -> TestTx {
        let mut pos = 0usize;
        let take = |pos: &mut usize, n: usize| -> &[u8] {
            let out = &bytes[*pos..*pos + n];
            *pos += n;
            out
        };
        let csz = |pos: &mut usize| -> u64 {
            let first = bytes[*pos];
            *pos += 1;
            match first {
                0xfd => {
                    let v = u16::from_le_bytes([bytes[*pos], bytes[*pos + 1]]);
                    *pos += 2;
                    u64::from(v)
                }
                0xfe | 0xff => panic!("oversized count in fixture tx"),
                small => u64::from(small),
            }
        };
        let version = u32::from_le_bytes(take(&mut pos, 4).try_into().unwrap());
        let n_in = csz(&mut pos);
        let mut inputs = Vec::new();
        for _ in 0..n_in {
            let txid: [u8; 32] = take(&mut pos, 32).try_into().unwrap();
            let vout = u32::from_le_bytes(take(&mut pos, 4).try_into().unwrap());
            let script_len = csz(&mut pos);
            assert_eq!(
                script_len, 0,
                "unsigned tx input must carry empty scriptSig"
            );
            let sequence = u32::from_le_bytes(take(&mut pos, 4).try_into().unwrap());
            inputs.push((txid, vout, sequence));
        }
        let n_out = csz(&mut pos);
        let mut outputs = Vec::new();
        for _ in 0..n_out {
            let amount = u64::from_le_bytes(take(&mut pos, 8).try_into().unwrap());
            let script_len = usize::try_from(csz(&mut pos)).unwrap();
            outputs.push((amount, take(&mut pos, script_len).to_vec()));
        }
        let locktime = u32::from_le_bytes(take(&mut pos, 4).try_into().unwrap());
        assert_eq!(pos, bytes.len(), "trailing bytes in fixture tx");
        TestTx {
            version,
            locktime,
            inputs,
            outputs,
        }
    }

    fn ws_by_ref<'a>(fx: &'a Fixture, name: &str) -> &'a [u8] {
        &fx.witness_scripts
            .iter()
            .find(|(n, _)| n == name)
            .expect("witness-script ref")
            .1
    }

    /// Extract the normalized 32-byte big-endian S value from a bare
    /// DER ECDSA signature (sighash byte already stripped).
    fn der_s_32(der: &[u8]) -> [u8; 32] {
        assert_eq!(der[0], 0x30, "DER sequence");
        assert_eq!(usize::from(der[1]) + 2, der.len(), "DER length");
        assert_eq!(der[2], 0x02, "R integer tag");
        let r_len = usize::from(der[3]);
        let s_tag = 4 + r_len;
        assert_eq!(der[s_tag], 0x02, "S integer tag");
        let s_len = usize::from(der[s_tag + 1]);
        let s = &der[s_tag + 2..s_tag + 2 + s_len];
        let trimmed = match s.split_first() {
            Some((0, rest)) if !rest.is_empty() => rest,
            _ => s,
        };
        assert!(trimmed.len() <= 32, "S wider than 32 bytes");
        let mut out = [0u8; 32];
        out[32 - trimmed.len()..].copy_from_slice(trimmed);
        out
    }

    /// Anti-skip inventory: all 14 official digest rows are present
    /// with contiguous IDs, the exact ratified classification sets,
    /// the exact suffix distribution, and exactly one recorded
    /// disposition per row that matches the frozen precedence
    /// (CodeSeparator before UnsupportedSighash).
    #[test]
    fn fixture_inventory_counts_sets_and_dispositions() {
        let fx = parse_fixture();
        assert_eq!(fx.rows.len(), 14, "official digest row count");
        assert_eq!(fx.witness_scripts.len(), 3, "unique witnessScripts");
        for (i, row) in fx.rows.iter().enumerate() {
            assert_eq!(row.id, i + 1, "contiguous row ids");
            assert!(!row.label.is_empty(), "label row {}", row.id);
        }
        let ids = |pred: &dyn Fn(&Row) -> bool| -> Vec<usize> {
            fx.rows.iter().filter(|r| pred(r)).map(|r| r.id).collect()
        };
        assert_eq!(ids(&|r| r.class == "all"), vec![1, 2, 7, 13, 14]);
        assert_eq!(
            ids(&|r| r.class == "non-all"),
            vec![3, 4, 5, 6, 8, 9, 10, 11, 12]
        );
        assert_eq!(ids(&|r| r.codeseparator), vec![3, 4, 5, 6]);
        let mut dist: Vec<(u8, usize)> = Vec::new();
        for row in &fx.rows {
            match dist.iter_mut().find(|(s, _)| *s == row.suffix) {
                Some((_, n)) => *n += 1,
                None => dist.push((row.suffix, 1)),
            }
        }
        dist.sort_unstable();
        assert_eq!(
            dist,
            vec![
                (0x01, 5),
                (0x02, 1),
                (0x03, 3),
                (0x81, 1),
                (0x82, 1),
                (0x83, 3)
            ],
            "suffix distribution"
        );
        for row in &fx.rows {
            let expected = if row.codeseparator {
                "unsupported-code-separator"
            } else if row.class == "non-all" {
                "unsupported-sighash"
            } else if row.id == 13 || row.id == 14 {
                "digest-high-s"
            } else {
                "digest-verify"
            };
            assert_eq!(row.disposition, expected, "disposition row {}", row.id);
        }
        assert_eq!(
            ids(&|r| r.disposition == "digest-verify"),
            vec![1, 2, 7],
            "positive verification rows"
        );
        assert_eq!(
            ids(&|r| r.disposition == "digest-high-s"),
            vec![13, 14],
            "high-S rows"
        );
        let pair_count: usize = fx.rows.iter().map(|r| r.sig_pairs.len()).sum();
        assert_eq!(pair_count, 6, "imported signature pairs");
        assert_eq!(
            fx.rows[12].sig_pairs.len() + fx.rows[13].sig_pairs.len(),
            3,
            "high-S signature pairs"
        );
        assert!(fx.rows[13].unsigned_tx_derived, "row 14 tx labeled derived");
        for row in &fx.rows {
            if row.id != 14 {
                assert!(!row.unsigned_tx_derived, "only row 14 is derived");
            }
        }
    }

    /// Every official preimage double-SHA256s to its official digest,
    /// for all 14 rows — never filtered by class.
    #[test]
    fn all_fourteen_preimages_reproduce_official_digests() {
        let fx = parse_fixture();
        for row in &fx.rows {
            let digest = sha256d(&[&row.preimage]).unwrap();
            assert_eq!(digest, row.digest, "row {}", row.id);
        }
    }

    /// The recorded intermediates sit at the exact ratified preimage
    /// positions in every row: hashPrevouts at [4..36], hashSequence
    /// at [36..68], hashOutputs at [len-40..len-8], and the 4-byte
    /// little-endian sighash suffix at the end.
    #[test]
    fn preimage_positions_match_recorded_intermediates_and_suffix() {
        let fx = parse_fixture();
        for row in &fx.rows {
            let p = &row.preimage;
            let n = p.len();
            assert!(n > 156, "minimum preimage length row {}", row.id);
            assert_eq!(&p[4..36], &row.hash_prevouts, "hashPrevouts row {}", row.id);
            assert_eq!(
                &p[36..68],
                &row.hash_sequence,
                "hashSequence row {}",
                row.id
            );
            assert_eq!(
                &p[n - 40..n - 8],
                &row.hash_outputs,
                "hashOutputs row {}",
                row.id
            );
            assert_eq!(
                &p[n - 4..],
                &[row.suffix, 0x00, 0x00, 0x00],
                "suffix row {}",
                row.id
            );
            if let Some(amount) = &row.amount_le {
                assert_eq!(&p[n - 52..n - 44], amount, "amount row {}", row.id);
            }
            if let Some(sc) = &row.script_code_prefixed {
                assert_eq!(
                    &p[104..104 + sc.len()],
                    &sc[..],
                    "scriptCode row {}",
                    row.id
                );
            }
        }
    }

    /// The five SIGHASH_ALL rows exercise the raw engine end to end:
    /// the precompute builder reproduces all recorded intermediate
    /// hashes from the unsigned transaction, the streamed preimage is
    /// byte-identical to the official preimage, the emitted CompactSize
    /// prefix is the official minimal prefix, and the final digest is
    /// the official digest.
    #[test]
    fn five_all_rows_builder_reproduces_intermediates_preimage_digest() {
        let fx = parse_fixture();
        let mut exercised = 0usize;
        for row in fx.rows.iter().filter(|r| r.class == "all") {
            let tx = parse_unsigned_tx(row.unsigned_tx.as_ref().expect("ALL row tx"));
            let mut builder = Bip143PrecomputeBuilder::new();
            for (txid, vout, sequence) in &tx.inputs {
                builder.add_input(txid, *vout, *sequence).unwrap();
            }
            for (amount, script) in &tx.outputs {
                builder.add_output(*amount, script).unwrap();
            }
            let pre = builder.finish().unwrap();
            assert_eq!(
                pre.hash_prevouts, row.hash_prevouts,
                "hashPrevouts row {}",
                row.id
            );
            assert_eq!(
                pre.hash_sequence, row.hash_sequence,
                "hashSequence row {}",
                row.id
            );
            assert_eq!(
                pre.hash_outputs, row.hash_outputs,
                "hashOutputs row {}",
                row.id
            );
            let prefixed = row.script_code_prefixed.as_ref().expect("ALL scriptCode");
            let (script_code, used) = {
                let (buf, used) = compact_size_minimal(0).unwrap();
                let _ = (buf, used);
                // Decode the official prefix, then require minimality.
                let first = prefixed[0];
                let (len, consumed): (usize, usize) = match first {
                    0xfd => (
                        usize::from(u16::from_le_bytes([prefixed[1], prefixed[2]])),
                        3,
                    ),
                    0xfe | 0xff => panic!("oversized scriptCode prefix in fixture"),
                    small => (usize::from(small), 1),
                };
                assert_eq!(prefixed.len(), consumed + len, "prefix row {}", row.id);
                let (minimal, minimal_used) = compact_size_minimal(len).unwrap();
                assert_eq!(
                    &minimal[..minimal_used],
                    &prefixed[..consumed],
                    "minimal prefix row {}",
                    row.id
                );
                (&prefixed[consumed..], consumed)
            };
            let _ = used;
            let (txid, vout, sequence) = &tx.inputs[row.input_index.expect("index")];
            let amount = u64::from_le_bytes(*row.amount_le.as_ref().expect("amount"));
            let facts = Bip143InputFacts {
                outpoint_txid_wire: txid,
                outpoint_vout: *vout,
                script_code,
                amount_sats: amount,
                sequence: *sequence,
            };
            let mut streamed: Vec<u8> = Vec::new();
            stream_preimage(&mut streamed, tx.version, tx.locktime, &pre, &facts).unwrap();
            assert_eq!(streamed, row.preimage, "complete preimage row {}", row.id);
            let digest = sighash_all_digest(tx.version, tx.locktime, &pre, &facts).unwrap();
            assert_eq!(digest, row.digest, "final digest row {}", row.id);
            exercised += 1;
        }
        assert_eq!(exercised, 5, "all five ALL rows exercised");
    }

    /// Rows 1, 2, and 7: the imported low-S signatures verify over the
    /// official digest and public key through qk-secp. The trailing
    /// sighash byte must equal the single SIGHASH_ALL constant and is
    /// stripped before DER parsing; DER-only bytes reach qk-secp.
    #[test]
    fn low_s_all_rows_verify_through_qk_secp() {
        let fx = parse_fixture();
        let mut verified = 0usize;
        for row in fx.rows.iter().filter(|r| r.disposition == "digest-verify") {
            assert_eq!(row.sig_pairs.len(), 1, "one pair row {}", row.id);
            let (pubkey, signature) = &row.sig_pairs[0];
            let (last, der) = signature.split_last().expect("signature bytes");
            assert_eq!(*last, SIGHASH_ALL, "trailing sighash byte row {}", row.id);
            assert!(der_s_32(der) <= LOW_S_MAX, "low-S row {}", row.id);
            let key: [u8; 33] = pubkey.as_slice().try_into().expect("compressed key");
            let key = qk_secp::pubkey_parse_compressed(&key).expect("pubkey parse");
            let sig = qk_secp::signature_parse_der(der).expect("DER parse");
            qk_secp::ecdsa_verify(&sig, &row.digest, &key).expect("verification");
            verified += 1;
        }
        assert_eq!(verified, 3, "exactly three positive verification rows");
    }

    /// Rows 13 and 14: all three imported signature pairs are high-S.
    /// Each S exceeds the BIP146 bound, qk-secp verification fails
    /// closed, and nothing is normalized — the assertion is HighS,
    /// never a rewrite.
    #[test]
    fn high_s_rows_fail_verification_and_are_never_normalized() {
        let fx = parse_fixture();
        let mut pairs = 0usize;
        for row in fx.rows.iter().filter(|r| r.disposition == "digest-high-s") {
            assert!(!row.sig_pairs.is_empty(), "pairs row {}", row.id);
            for (pubkey, signature) in &row.sig_pairs {
                let (last, der) = signature.split_last().expect("signature bytes");
                assert_eq!(*last, SIGHASH_ALL, "trailing sighash byte row {}", row.id);
                let s = der_s_32(der);
                assert!(s > LOW_S_MAX, "high-S required row {}", row.id);
                let key: [u8; 33] = pubkey.as_slice().try_into().expect("compressed key");
                let key = qk_secp::pubkey_parse_compressed(&key).expect("pubkey parse");
                let sig = qk_secp::signature_parse_der(der).expect("high-S DER still parses");
                assert_eq!(
                    qk_secp::ecdsa_verify(&sig, &row.digest, &key),
                    Err(qk_secp::SecpError::VerificationFailed),
                    "high-S must fail verification row {}",
                    row.id
                );
                pairs += 1;
            }
        }
        assert_eq!(pairs, 3, "exactly three high-S signature pairs");
    }

    /// All nine non-ALL rows carry a non-ALL suffix and are recorded
    /// as expected fail-closed classifications; the four CodeSeparator
    /// rows among them keep the CodeSeparator-first precedence while
    /// this test independently asserts the sighash axis for every one.
    #[test]
    fn nine_non_all_rows_assert_unsupported_sighash_axis() {
        let fx = parse_fixture();
        let mut checked = 0usize;
        for row in fx.rows.iter().filter(|r| r.class == "non-all") {
            assert_ne!(row.suffix, SIGHASH_ALL, "non-ALL suffix row {}", row.id);
            assert_ne!(
                &row.preimage[row.preimage.len() - 4..],
                &SIGHASH_ALL_SUFFIX_LE,
                "non-ALL preimage suffix row {}",
                row.id
            );
            if row.codeseparator {
                assert_eq!(
                    row.disposition, "unsupported-code-separator",
                    "precedence row {}",
                    row.id
                );
            } else {
                assert_eq!(
                    row.disposition, "unsupported-sighash",
                    "disposition row {}",
                    row.id
                );
            }
            checked += 1;
        }
        assert_eq!(checked, 9, "all nine non-ALL rows checked");
    }

    /// The four CodeSeparator rows associate with the three imported
    /// witnessScripts, and the OP_CODESEPARATOR determination uses
    /// parsed opcode semantics — a pushed 0xAB byte does not count,
    /// only an actual `Opcode(0xAB)` token does.
    #[test]
    fn four_codesep_rows_reject_via_parsed_opcodes_not_byte_scans() {
        let fx = parse_fixture();
        let has_codesep_opcode = |script: &[u8]| -> bool {
            ScriptTokens::new(script)
                .map(|t| t.expect("well-formed fixture script"))
                .any(|t| matches!(t, ScriptToken::Opcode(0xab)))
        };
        let mut checked = 0usize;
        for row in fx.rows.iter().filter(|r| r.codeseparator) {
            let name = row.witness_script_ref.as_ref().expect("ws ref");
            let script = ws_by_ref(&fx, name);
            assert!(
                has_codesep_opcode(script),
                "parsed OP_CODESEPARATOR row {}",
                row.id
            );
            checked += 1;
        }
        assert_eq!(checked, 4, "all four CodeSeparator rows checked");
        // Rows 5/6 witnessScripts push a public key whose bytes contain
        // a raw 0xAB — the parsed-opcode walk must still attribute the
        // rejection to the real opcode, and a script whose only 0xAB
        // lives inside pushed data must NOT count as CodeSeparator.
        let ws_b = ws_by_ref(&fx, "ws-b");
        let pushed_key: Vec<u8> = ScriptTokens::new(ws_b)
            .map(|t| t.expect("well-formed"))
            .find_map(|t| match t {
                ScriptToken::Push(data) if data.len() == 33 => Some(data.to_vec()),
                _ => None,
            })
            .expect("pushed 33-byte key");
        assert!(
            pushed_key.contains(&0xab),
            "chosen pushed key contains a raw 0xAB byte"
        );
        let mut push_only = vec![0x21];
        push_only.extend_from_slice(&pushed_key);
        push_only.push(0xac);
        assert!(
            !has_codesep_opcode(&push_only),
            "pushed 0xAB must not classify as OP_CODESEPARATOR"
        );
        // Row 7's official scriptCode payload (a 6-of-6 witnessScript)
        // contains no OP_CODESEPARATOR opcode.
        let row7 = &fx.rows[6];
        let sc = row7
            .script_code_prefixed
            .as_ref()
            .expect("row 7 scriptCode");
        assert!(!has_codesep_opcode(&sc[1..]), "row 7 has no CodeSeparator");
    }

    /// Minimal CompactSize prefix boundaries: 252 stays one byte, 253
    /// switches to the 0xFD three-byte form, 65536 switches to the
    /// 0xFE five-byte form, and an over-cap scriptCode fails closed.
    #[test]
    fn compact_size_prefix_boundaries_and_cap() {
        assert_eq!(compact_size_minimal(0).unwrap(), ([0, 0, 0, 0, 0], 1));
        assert_eq!(compact_size_minimal(252).unwrap(), ([0xfc, 0, 0, 0, 0], 1));
        assert_eq!(
            compact_size_minimal(253).unwrap(),
            ([0xfd, 0xfd, 0x00, 0, 0], 3)
        );
        assert_eq!(
            compact_size_minimal(65535).unwrap(),
            ([0xfd, 0xff, 0xff, 0, 0], 3)
        );
        assert_eq!(
            compact_size_minimal(65536).unwrap(),
            ([0xfe, 0x00, 0x00, 0x01, 0x00], 5)
        );
        let pre = Bip143Precomputed {
            hash_prevouts: [0u8; 32],
            hash_sequence: [0u8; 32],
            hash_outputs: [0u8; 32],
        };
        for len in [252usize, 253] {
            let script = vec![0x51u8; len];
            let facts = Bip143InputFacts {
                outpoint_txid_wire: &[0u8; 32],
                outpoint_vout: 0,
                script_code: &script,
                amount_sats: 1,
                sequence: 0xffff_ffff,
            };
            let mut streamed: Vec<u8> = Vec::new();
            stream_preimage(&mut streamed, 1, 0, &pre, &facts).unwrap();
            let (prefix, used) = compact_size_minimal(len).unwrap();
            assert_eq!(
                &streamed[104..104 + used],
                &prefix[..used],
                "prefix len {len}"
            );
            assert_eq!(
                sighash_all_digest(1, 0, &pre, &facts).unwrap(),
                sha256d(&[&streamed]).unwrap(),
                "streamed digest equals preimage digest len {len}"
            );
        }
        let oversized = vec![0u8; MAX_SCRIPT_CODE_BYTES + 1];
        let facts = Bip143InputFacts {
            outpoint_txid_wire: &[0u8; 32],
            outpoint_vout: 0,
            script_code: &oversized,
            amount_sats: 0,
            sequence: 0,
        };
        assert_eq!(
            sighash_all_digest(1, 0, &pre, &facts),
            Err(Bip143Error::ScriptCodeTooLong)
        );
    }

    /// Digest mutation sensitivity: flipping any single preimage
    /// component of official row 1 changes the digest.
    #[test]
    fn digest_is_sensitive_to_every_preimage_component() {
        let fx = parse_fixture();
        let row = &fx.rows[0];
        let tx = parse_unsigned_tx(row.unsigned_tx.as_ref().unwrap());
        let mut builder = Bip143PrecomputeBuilder::new();
        for (txid, vout, sequence) in &tx.inputs {
            builder.add_input(txid, *vout, *sequence).unwrap();
        }
        for (amount, script) in &tx.outputs {
            builder.add_output(*amount, script).unwrap();
        }
        let pre = builder.finish().unwrap();
        let prefixed = row.script_code_prefixed.as_ref().unwrap();
        let script_code = &prefixed[1..];
        let (txid, vout, sequence) = &tx.inputs[row.input_index.unwrap()];
        let amount = u64::from_le_bytes(row.amount_le.unwrap());
        let base = Bip143InputFacts {
            outpoint_txid_wire: txid,
            outpoint_vout: *vout,
            script_code,
            amount_sats: amount,
            sequence: *sequence,
        };
        let official = sighash_all_digest(tx.version, tx.locktime, &pre, &base).unwrap();
        assert_eq!(official, row.digest, "baseline equals official digest");
        let mut flipped_txid = *txid;
        flipped_txid[0] ^= 0x01;
        let truncated = &script_code[..script_code.len() - 1];
        type Variant<'a> = (
            [u8; 32],
            u32,
            &'a [u8],
            u64,
            u32,
            u32,
            u32,
            Bip143Precomputed,
        );
        let variants: Vec<Variant<'_>> = vec![
            // (txid, vout, script, amount, sequence, version, locktime, precomputed)
            (
                flipped_txid,
                *vout,
                script_code,
                amount,
                *sequence,
                tx.version,
                tx.locktime,
                pre,
            ),
            (
                *txid,
                vout ^ 1,
                script_code,
                amount,
                *sequence,
                tx.version,
                tx.locktime,
                pre,
            ),
            (
                *txid,
                *vout,
                truncated,
                amount,
                *sequence,
                tx.version,
                tx.locktime,
                pre,
            ),
            (
                *txid,
                *vout,
                script_code,
                amount ^ 1,
                *sequence,
                tx.version,
                tx.locktime,
                pre,
            ),
            (
                *txid,
                *vout,
                script_code,
                amount,
                sequence ^ 1,
                tx.version,
                tx.locktime,
                pre,
            ),
            (
                *txid,
                *vout,
                script_code,
                amount,
                *sequence,
                tx.version ^ 1,
                tx.locktime,
                pre,
            ),
            (
                *txid,
                *vout,
                script_code,
                amount,
                *sequence,
                tx.version,
                tx.locktime ^ 1,
                pre,
            ),
            (
                *txid,
                *vout,
                script_code,
                amount,
                *sequence,
                tx.version,
                tx.locktime,
                Bip143Precomputed {
                    hash_prevouts: flip(pre.hash_prevouts),
                    ..pre
                },
            ),
            (
                *txid,
                *vout,
                script_code,
                amount,
                *sequence,
                tx.version,
                tx.locktime,
                Bip143Precomputed {
                    hash_sequence: flip(pre.hash_sequence),
                    ..pre
                },
            ),
            (
                *txid,
                *vout,
                script_code,
                amount,
                *sequence,
                tx.version,
                tx.locktime,
                Bip143Precomputed {
                    hash_outputs: flip(pre.hash_outputs),
                    ..pre
                },
            ),
        ];
        for (i, (t, v, sc, a, sq, ver, lt, p)) in variants.iter().enumerate() {
            let facts = Bip143InputFacts {
                outpoint_txid_wire: t,
                outpoint_vout: *v,
                script_code: sc,
                amount_sats: *a,
                sequence: *sq,
            };
            let digest = sighash_all_digest(*ver, *lt, &p.clone(), &facts).unwrap();
            assert_ne!(digest, official, "variant {i} must change the digest");
        }
        // Suffix sensitivity: the same preimage with a non-ALL suffix
        // yields a different digest (the engine cannot emit one by
        // construction; assert over the raw bytes).
        let mut mutated = row.preimage.clone();
        let last = mutated.len() - 4;
        mutated[last] = 0x02;
        assert_ne!(
            sha256d(&[&mutated]).unwrap(),
            row.digest,
            "suffix byte must change the digest"
        );
    }

    fn flip(mut h: [u8; 32]) -> [u8; 32] {
        h[0] ^= 0xff;
        h
    }

    /// The one SIGHASH_ALL constant binds the trailing byte and the
    /// 4-byte little-endian suffix.
    #[test]
    fn sighash_all_constant_binds_byte_and_suffix() {
        assert_eq!(SIGHASH_ALL, 0x01);
        assert_eq!(SIGHASH_ALL_SUFFIX_LE, [SIGHASH_ALL, 0x00, 0x00, 0x00]);
    }
}
