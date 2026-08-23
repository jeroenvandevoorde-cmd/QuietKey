//! Pinned upstream BIP-174 test vectors as expected-verdict fixtures.
//!
//! Source: the base64 test-vector strings embedded in bitcoin/bips
//! `bip-0174.mediawiki` at commit
//! `857a7debc6625a3dadbaecee1ee7b2ed5e8ada75`, license BSD-2-Clause per
//! the BIP 174 preamble at that commit; provenance recorded in
//! `docs/SOURCE-REGISTER.md`. These 36 vector strings and the
//! corresponding 34 Case labels are the only imported material; their
//! source bytes/text are verbatim. Upstream vectors that carry fields
//! or shapes outside the ratified v0 structural profile are labeled
//! expected rejections with their exact category; the profile is never
//! loosened to make an upstream vector pass. The two upstream "valid" vectors with
//! zero-input unsigned transactions reject under the local profile.
//! The canonical-serializer goldens below are locally derived from
//! these imported vectors and first-party synthetic fixtures; no
//! upstream expected-output material is imported. HOST evidence only;
//! no conformance claim.
//!
//! Breakdown of the 36 imported strings (34 carry upstream "Case"
//! labels; the two unknown-KV strings are introduced by prose and are
//! label-free): 20 structural rejects, 8 ordinary upstream-valid
//! accepts, 2 upstream-valid vectors rejected locally for zero-input
//! unsigned transactions, 4 upstream signer-check cases (Cases 31-34)
//! that are signer-failure (structurally valid; post-M3 rejection
//! pending), and 2 unknown-KV preservation cases.

use qk_psbt::{canonical_serialize, parse, InputSource, PsbtView, Records, RejectCategory};

#[derive(Clone, Copy)]
enum Verdict {
    Accept,
    /// Signer-failure case: structurally valid, so M3 must accept it;
    /// the upstream-expected rejection belongs to post-M3 signer
    /// validation, which does not exist yet (rejection pending).
    SignerRejectLater,
    Reject(RejectCategory),
}
use Verdict::{Accept, Reject, SignerRejectLater};

/// Strict base64 decoder for the fixture strings (test-only).
fn b64(s: &str) -> Vec<u8> {
    const ABC: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let bytes: Vec<u8> = s.bytes().filter(|b| !b.is_ascii_whitespace()).collect();
    assert!(
        bytes.len() % 4 == 0,
        "base64 length must be a multiple of 4"
    );
    let mut out = Vec::new();
    for chunk in bytes.chunks(4) {
        let mut vals = [0u8; 4];
        let mut pad = 0usize;
        for (i, &c) in chunk.iter().enumerate() {
            if c == b'=' {
                pad += 1;
                vals[i] = 0;
            } else {
                assert_eq!(pad, 0, "padding only at end");
                let v = ABC.iter().position(|&a| a == c).expect("valid base64 char");
                vals[i] = v as u8;
            }
        }
        let n = (u32::from(vals[0]) << 18)
            | (u32::from(vals[1]) << 12)
            | (u32::from(vals[2]) << 6)
            | u32::from(vals[3]);
        out.push((n >> 16) as u8);
        if pad < 2 {
            out.push((n >> 8) as u8);
        }
        if pad < 1 {
            out.push(n as u8);
        }
    }
    out
}

const VECTORS: &[(&str, &str, Verdict)] = &[
    (
        "invalid: Network transaction, not PSBT format",
        "AgAAAAEmgXE3Ht/yhek3re6ks3t4AAwFZsuzrWRkFxPKQhcb9gAAAABqRzBEAiBwsiRRI+a/R01gxbUMBD1MaRpdJDXwmjSnZiqdwlF5CgIgATKcqdrPKAvfMHQOwDkEIkIsgctFg5RXrrdvwS7dlbMBIQJlfRGNM1e44PTCzUbbezn22cONmnCry5st5dyNv+TOMf7///8C09/1BQAAAAAZdqkU0MWZA8W6woaHYOkP1SGkZlqnZSCIrADh9QUAAAAAF6kUNUXm4zuDLEcFDyTT7rk8nAOUi8eHsy4TAA==",
        Reject(RejectCategory::InvalidMagic),
    ),
    (
        "invalid: PSBT missing outputs",
        "cHNidP8BAHUCAAAAASaBcTce3/KF6Tet7qSze3gADAVmy7OtZGQXE8pCFxv2AAAAAAD+////AtPf9QUAAAAAGXapFNDFmQPFusKGh2DpD9UhpGZap2UgiKwA4fUFAAAAABepFDVF5uM7gyxHBQ8k0+65PJwDlIvHh7MuEwAAAQD9pQEBAAAAAAECiaPHHqtNIOA3G7ukzGmPopXJRjr6Ljl/hTPMti+VZ+UBAAAAFxYAFL4Y0VKpsBIDna89p95PUzSe7LmF/////4b4qkOnHf8USIk6UwpyN+9rRgi7st0tAXHmOuxqSJC0AQAAABcWABT+Pp7xp0XpdNkCxDVZQ6vLNL1TU/////8CAMLrCwAAAAAZdqkUhc/xCX/Z4Ai7NK9wnGIZeziXikiIrHL++E4sAAAAF6kUM5cluiHv1irHU6m80GfWx6ajnQWHAkcwRAIgJxK+IuAnDzlPVoMR3HyppolwuAJf3TskAinwf4pfOiQCIAGLONfc0xTnNMkna9b7QPZzMlvEuqFEyADS8vAtsnZcASED0uFWdJQbrUqZY3LLh+GFbTZSYG2YVi/jnF6efkE/IQUCSDBFAiEA0SuFLYXc2WHS9fSrZgZU327tzHlMDDPOXMMJ/7X85Y0CIGczio4OFyXBl/saiK9Z9R5E5CVbIBZ8hoQDHAXR8lkqASECI7cr7vCWXRC+B3jv7NYfysb3mk6haTkzgHNEZPhPKrMAAAAAAA==",
        Reject(RejectCategory::InvalidMapCount),
    ),
    (
        "invalid: PSBT where one input has a filled scriptSig in the unsigned tx",
        "cHNidP8BAP0KAQIAAAACqwlJoIxa98SbghL0F+LxWrP1wz3PFTghqBOfh3pbe+QAAAAAakcwRAIgR1lmF5fAGwNrJZKJSGhiGDR9iYZLcZ4ff89X0eURZYcCIFMJ6r9Wqk2Ikf/REf3xM286KdqGbX+EhtdVRs7tr5MZASEDXNxh/HupccC1AaZGoqg7ECy0OIEhfKaC3Ibi1z+ogpL+////qwlJoIxa98SbghL0F+LxWrP1wz3PFTghqBOfh3pbe+QBAAAAAP7///8CYDvqCwAAAAAZdqkUdopAu9dAy+gdmI5x3ipNXHE5ax2IrI4kAAAAAAAAGXapFG9GILVT+glechue4O/p+gOcykWXiKwAAAAAAAABASAA4fUFAAAAABepFDVF5uM7gyxHBQ8k0+65PJwDlIvHhwEEFgAUhdE1N/LiZUBaNNuvqePdoB+4IwgAAAA=",
        Reject(RejectCategory::UnsignedTxScriptSigNotEmpty),
    ),
    (
        "invalid: PSBT where inputs and outputs are provided but without an unsigned tx",
        "cHNidP8AAQD9pQEBAAAAAAECiaPHHqtNIOA3G7ukzGmPopXJRjr6Ljl/hTPMti+VZ+UBAAAAFxYAFL4Y0VKpsBIDna89p95PUzSe7LmF/////4b4qkOnHf8USIk6UwpyN+9rRgi7st0tAXHmOuxqSJC0AQAAABcWABT+Pp7xp0XpdNkCxDVZQ6vLNL1TU/////8CAMLrCwAAAAAZdqkUhc/xCX/Z4Ai7NK9wnGIZeziXikiIrHL++E4sAAAAF6kUM5cluiHv1irHU6m80GfWx6ajnQWHAkcwRAIgJxK+IuAnDzlPVoMR3HyppolwuAJf3TskAinwf4pfOiQCIAGLONfc0xTnNMkna9b7QPZzMlvEuqFEyADS8vAtsnZcASED0uFWdJQbrUqZY3LLh+GFbTZSYG2YVi/jnF6efkE/IQUCSDBFAiEA0SuFLYXc2WHS9fSrZgZU327tzHlMDDPOXMMJ/7X85Y0CIGczio4OFyXBl/saiK9Z9R5E5CVbIBZ8hoQDHAXR8lkqASECI7cr7vCWXRC+B3jv7NYfysb3mk6haTkzgHNEZPhPKrMAAAAAAA==",
        Reject(RejectCategory::MissingUnsignedTx),
    ),
    (
        "invalid: PSBT with duplicate keys in an input",
        "cHNidP8BAHUCAAAAASaBcTce3/KF6Tet7qSze3gADAVmy7OtZGQXE8pCFxv2AAAAAAD+////AtPf9QUAAAAAGXapFNDFmQPFusKGh2DpD9UhpGZap2UgiKwA4fUFAAAAABepFDVF5uM7gyxHBQ8k0+65PJwDlIvHh7MuEwAAAQD9pQEBAAAAAAECiaPHHqtNIOA3G7ukzGmPopXJRjr6Ljl/hTPMti+VZ+UBAAAAFxYAFL4Y0VKpsBIDna89p95PUzSe7LmF/////4b4qkOnHf8USIk6UwpyN+9rRgi7st0tAXHmOuxqSJC0AQAAABcWABT+Pp7xp0XpdNkCxDVZQ6vLNL1TU/////8CAMLrCwAAAAAZdqkUhc/xCX/Z4Ai7NK9wnGIZeziXikiIrHL++E4sAAAAF6kUM5cluiHv1irHU6m80GfWx6ajnQWHAkcwRAIgJxK+IuAnDzlPVoMR3HyppolwuAJf3TskAinwf4pfOiQCIAGLONfc0xTnNMkna9b7QPZzMlvEuqFEyADS8vAtsnZcASED0uFWdJQbrUqZY3LLh+GFbTZSYG2YVi/jnF6efkE/IQUCSDBFAiEA0SuFLYXc2WHS9fSrZgZU327tzHlMDDPOXMMJ/7X85Y0CIGczio4OFyXBl/saiK9Z9R5E5CVbIBZ8hoQDHAXR8lkqASECI7cr7vCWXRC+B3jv7NYfysb3mk6haTkzgHNEZPhPKrMAAAAAAQA/AgAAAAH//////////////////////////////////////////wAAAAAA/////wEAAAAAAAAAAANqAQAAAAAAAAAA",
        Reject(RejectCategory::DuplicateKey),
    ),
    (
        "invalid: PSBT with invalid global transaction typed key",
        "cHNidP8CAAFVAgAAAAEnmiMjpd+1H8RfIg+liw/BPh4zQnkqhdfjbNYzO1y8OQAAAAAA/////wGgWuoLAAAAABl2qRT/6cAGEJfMO2NvLLBGD6T8Qn0rRYisAAAAAAABASCVXuoLAAAAABepFGNFIA9o0YnhrcDfHE0W6o8UwNvrhyICA7E0HMunaDtq9PEjjNbpfnFn1Wn6xH8eSNR1QYRDVb1GRjBDAiAEJLWO/6qmlOFVnqXJO7/UqJBkIkBVzfBwtncUaUQtBwIfXI6w/qZRbWC4rLM61k7eYOh4W/s6qUuZvfhhUduamgEBBCIAIHcf0YrUWWZt1J89Vk49vEL0yEd042CtoWgWqO1IjVaBAQVHUiEDsTQcy6doO2r08SOM1ul+cWfVafrEfx5I1HVBhENVvUYhA95V0eHayAXj+KWMH7+blMAvPbqv4Sf+/KSZXyb4IIO9Uq4iBgOxNBzLp2g7avTxI4zW6X5xZ9Vp+sR/HkjUdUGEQ1W9RhC0prpnAAAAgAAAAIAEAACAIgYD3lXR4drIBeP4pYwfv5uUwC89uq/hJ/78pJlfJvggg70QtKa6ZwAAAIAAAACABQAAgAAA",
        Reject(RejectCategory::InvalidKeyStructure),
    ),
    (
        "invalid: PSBT with invalid input witness utxo typed key",
        "cHNidP8BAFUCAAAAASeaIyOl37UfxF8iD6WLD8E+HjNCeSqF1+Ns1jM7XLw5AAAAAAD/////AaBa6gsAAAAAGXapFP/pwAYQl8w7Y28ssEYPpPxCfStFiKwAAAAAAAIBACCVXuoLAAAAABepFGNFIA9o0YnhrcDfHE0W6o8UwNvrhyICA7E0HMunaDtq9PEjjNbpfnFn1Wn6xH8eSNR1QYRDVb1GRjBDAiAEJLWO/6qmlOFVnqXJO7/UqJBkIkBVzfBwtncUaUQtBwIfXI6w/qZRbWC4rLM61k7eYOh4W/s6qUuZvfhhUduamgEBBCIAIHcf0YrUWWZt1J89Vk49vEL0yEd042CtoWgWqO1IjVaBAQVHUiEDsTQcy6doO2r08SOM1ul+cWfVafrEfx5I1HVBhENVvUYhA95V0eHayAXj+KWMH7+blMAvPbqv4Sf+/KSZXyb4IIO9Uq4iBgOxNBzLp2g7avTxI4zW6X5xZ9Vp+sR/HkjUdUGEQ1W9RhC0prpnAAAAgAAAAIAEAACAIgYD3lXR4drIBeP4pYwfv5uUwC89uq/hJ/78pJlfJvggg70QtKa6ZwAAAIAAAACABQAAgAAA",
        Reject(RejectCategory::InvalidKeyStructure),
    ),
    (
        "invalid: PSBT with invalid pubkey length for input partial signature typed key",
        "cHNidP8BAFUCAAAAASeaIyOl37UfxF8iD6WLD8E+HjNCeSqF1+Ns1jM7XLw5AAAAAAD/////AaBa6gsAAAAAGXapFP/pwAYQl8w7Y28ssEYPpPxCfStFiKwAAAAAAAEBIJVe6gsAAAAAF6kUY0UgD2jRieGtwN8cTRbqjxTA2+uHIQIDsTQcy6doO2r08SOM1ul+cWfVafrEfx5I1HVBhENVvUYwQwIgBCS1jv+qppThVZ6lyTu/1KiQZCJAVc3wcLZ3FGlELQcCH1yOsP6mUW1guKyzOtZO3mDoeFv7OqlLmb34YVHbmpoBAQQiACB3H9GK1FlmbdSfPVZOPbxC9MhHdONgraFoFqjtSI1WgQEFR1IhA7E0HMunaDtq9PEjjNbpfnFn1Wn6xH8eSNR1QYRDVb1GIQPeVdHh2sgF4/iljB+/m5TALz26r+En/vykmV8m+CCDvVKuIgYDsTQcy6doO2r08SOM1ul+cWfVafrEfx5I1HVBhENVvUYQtKa6ZwAAAIAAAACABAAAgCIGA95V0eHayAXj+KWMH7+blMAvPbqv4Sf+/KSZXyb4IIO9ELSmumcAAACAAAAAgAUAAIAAAA==",
        Reject(RejectCategory::InvalidKeyStructure),
    ),
    (
        "invalid: PSBT with invalid redeemscript typed key",
        "cHNidP8BAFUCAAAAASeaIyOl37UfxF8iD6WLD8E+HjNCeSqF1+Ns1jM7XLw5AAAAAAD/////AaBa6gsAAAAAGXapFP/pwAYQl8w7Y28ssEYPpPxCfStFiKwAAAAAAAEBIJVe6gsAAAAAF6kUY0UgD2jRieGtwN8cTRbqjxTA2+uHIgIDsTQcy6doO2r08SOM1ul+cWfVafrEfx5I1HVBhENVvUZGMEMCIAQktY7/qqaU4VWepck7v9SokGQiQFXN8HC2dxRpRC0HAh9cjrD+plFtYLisszrWTt5g6Hhb+zqpS5m9+GFR25qaAQIEACIAIHcf0YrUWWZt1J89Vk49vEL0yEd042CtoWgWqO1IjVaBAQVHUiEDsTQcy6doO2r08SOM1ul+cWfVafrEfx5I1HVBhENVvUYhA95V0eHayAXj+KWMH7+blMAvPbqv4Sf+/KSZXyb4IIO9Uq4iBgOxNBzLp2g7avTxI4zW6X5xZ9Vp+sR/HkjUdUGEQ1W9RhC0prpnAAAAgAAAAIAEAACAIgYD3lXR4drIBeP4pYwfv5uUwC89uq/hJ/78pJlfJvggg70QtKa6ZwAAAIAAAACABQAAgAAA",
        Reject(RejectCategory::InvalidKeyStructure),
    ),
    (
        "invalid: PSBT with invalid witnessscript typed key",
        "cHNidP8BAFUCAAAAASeaIyOl37UfxF8iD6WLD8E+HjNCeSqF1+Ns1jM7XLw5AAAAAAD/////AaBa6gsAAAAAGXapFP/pwAYQl8w7Y28ssEYPpPxCfStFiKwAAAAAAAEBIJVe6gsAAAAAF6kUY0UgD2jRieGtwN8cTRbqjxTA2+uHIgIDsTQcy6doO2r08SOM1ul+cWfVafrEfx5I1HVBhENVvUZGMEMCIAQktY7/qqaU4VWepck7v9SokGQiQFXN8HC2dxRpRC0HAh9cjrD+plFtYLisszrWTt5g6Hhb+zqpS5m9+GFR25qaAQEEIgAgdx/RitRZZm3Unz1WTj28QvTIR3TjYK2haBao7UiNVoECBQBHUiEDsTQcy6doO2r08SOM1ul+cWfVafrEfx5I1HVBhENVvUYhA95V0eHayAXj+KWMH7+blMAvPbqv4Sf+/KSZXyb4IIO9Uq4iBgOxNBzLp2g7avTxI4zW6X5xZ9Vp+sR/HkjUdUGEQ1W9RhC0prpnAAAAgAAAAIAEAACAIgYD3lXR4drIBeP4pYwfv5uUwC89uq/hJ/78pJlfJvggg70QtKa6ZwAAAIAAAACABQAAgAAA",
        Reject(RejectCategory::InvalidKeyStructure),
    ),
    (
        "invalid: PSBT with invalid pubkey in input BIP 32 derivation paths typed key",
        "cHNidP8BAFUCAAAAASeaIyOl37UfxF8iD6WLD8E+HjNCeSqF1+Ns1jM7XLw5AAAAAAD/////AaBa6gsAAAAAGXapFP/pwAYQl8w7Y28ssEYPpPxCfStFiKwAAAAAAAEBIJVe6gsAAAAAF6kUY0UgD2jRieGtwN8cTRbqjxTA2+uHIgIDsTQcy6doO2r08SOM1ul+cWfVafrEfx5I1HVBhENVvUZGMEMCIAQktY7/qqaU4VWepck7v9SokGQiQFXN8HC2dxRpRC0HAh9cjrD+plFtYLisszrWTt5g6Hhb+zqpS5m9+GFR25qaAQEEIgAgdx/RitRZZm3Unz1WTj28QvTIR3TjYK2haBao7UiNVoEBBUdSIQOxNBzLp2g7avTxI4zW6X5xZ9Vp+sR/HkjUdUGEQ1W9RiED3lXR4drIBeP4pYwfv5uUwC89uq/hJ/78pJlfJvggg71SriEGA7E0HMunaDtq9PEjjNbpfnFn1Wn6xH8eSNR1QYRDVb0QtKa6ZwAAAIAAAACABAAAgCIGA95V0eHayAXj+KWMH7+blMAvPbqv4Sf+/KSZXyb4IIO9ELSmumcAAACAAAAAgAUAAIAAAA==",
        Reject(RejectCategory::InvalidKeyStructure),
    ),
    (
        "invalid: PSBT with invalid non-witness utxo typed key",
        "cHNidP8BAJoCAAAAAljoeiG1ba8MI76OcHBFbDNvfLqlyHV5JPVFiHuyq911AAAAAAD/////g40EJ9DsZQpoqka7CwmK6kQiwHGyyng1Kgd5WdB86h0BAAAAAP////8CcKrwCAAAAAAWABTYXCtx0AYLCcmIauuBXlCZHdoSTQDh9QUAAAAAFgAUAK6pouXw+HaliN9VRuh0LR2HAI8AAAAAAAIAALsCAAAAAarXOTEBi9JfhK5AC2iEi+CdtwbqwqwYKYur7nGrZW+LAAAAAEhHMEQCIFj2/HxqM+GzFUjUgcgmwBW9MBNarULNZ3kNq2bSrSQ7AiBKHO0mBMZzW2OT5bQWkd14sA8MWUL7n3UYVvqpOBV9ugH+////AoDw+gIAAAAAF6kUD7lGNCFpa4LIM68kHHjBfdveSTSH0PIKJwEAAAAXqRQpynT4oI+BmZQoGFyXtdhS5AY/YYdlAAAAAQfaAEcwRAIgdAGK1BgAl7hzMjwAFXILNoTMgSOJEEjn282bVa1nnJkCIHPTabdA4+tT3O+jOCPIBwUUylWn3ZVE8VfBZ5EyYRGMAUgwRQIhAPYQOLMI3B2oZaNIUnRvAVdyk0IIxtJEVDk82ZvfIhd3AiAFbmdaZ1ptCgK4WxTl4pB02KJam1dgvqKBb2YZEKAG6gFHUiEClYO/Oa4KYJdHrRma3dY0+mEIVZ1sXNObTCGD8auW4H8hAtq2H/SaFNtqfQKwzR+7ePxLGDErW05U2uTbovv+9TbXUq4AAQEgAMLrCwAAAAAXqRS39fr0Dj1ApaRZsds1NfK3L6kh6IcBByMiACCMI1MXN0O1ld+0oHtyuo5C43l9p06H/n2ddJfjsgKJAwEI2gQARzBEAiBi63pVYQenxz9FrEq1od3fb3B1+xJ1lpp/OD7/94S8sgIgDAXbt0cNvy8IVX3TVscyXB7TCRPpls04QJRdsSIo2l8BRzBEAiBl9FulmYtZon/+GnvtAWrx8fkNVLOqj3RQql9WolEDvQIgf3JHA60e25ZoCyhLVtT/y4j3+3Weq74IqjDym4UTg9IBR1IhAwidwQx6xttU+RMpr2FzM9s4jOrQwjH3IzedG5kDCwLcIQI63ZBPPW3PWd25BrDe4jUpt/+57VDl6GFRkmhgIh8Oc1KuACICA6mkw39ZltOqJdusa1cK8GUDlEkpQkYLNUdT7Z7spYdxENkMak8AAACAAAAAgAQAAIAAIgICf2OZdX0u/1WhNq0CxoSxg4tlVuXxtrNCgqlLa1AFEJYQ2QxqTwAAAIAAAACABQAAgAA=",
        Reject(RejectCategory::InvalidKeyStructure),
    ),
    (
        "invalid: PSBT with invalid final scriptsig typed key",
        "cHNidP8BAJoCAAAAAljoeiG1ba8MI76OcHBFbDNvfLqlyHV5JPVFiHuyq911AAAAAAD/////g40EJ9DsZQpoqka7CwmK6kQiwHGyyng1Kgd5WdB86h0BAAAAAP////8CcKrwCAAAAAAWABTYXCtx0AYLCcmIauuBXlCZHdoSTQDh9QUAAAAAFgAUAK6pouXw+HaliN9VRuh0LR2HAI8AAAAAAAEAuwIAAAABqtc5MQGL0l+ErkALaISL4J23BurCrBgpi6vucatlb4sAAAAASEcwRAIgWPb8fGoz4bMVSNSByCbAFb0wE1qtQs1neQ2rZtKtJDsCIEoc7SYExnNbY5PltBaR3XiwDwxZQvufdRhW+qk4FX26Af7///8CgPD6AgAAAAAXqRQPuUY0IWlrgsgzryQceMF9295JNIfQ8gonAQAAABepFCnKdPigj4GZlCgYXJe12FLkBj9hh2UAAAACBwDaAEcwRAIgdAGK1BgAl7hzMjwAFXILNoTMgSOJEEjn282bVa1nnJkCIHPTabdA4+tT3O+jOCPIBwUUylWn3ZVE8VfBZ5EyYRGMAUgwRQIhAPYQOLMI3B2oZaNIUnRvAVdyk0IIxtJEVDk82ZvfIhd3AiAFbmdaZ1ptCgK4WxTl4pB02KJam1dgvqKBb2YZEKAG6gFHUiEClYO/Oa4KYJdHrRma3dY0+mEIVZ1sXNObTCGD8auW4H8hAtq2H/SaFNtqfQKwzR+7ePxLGDErW05U2uTbovv+9TbXUq4AAQEgAMLrCwAAAAAXqRS39fr0Dj1ApaRZsds1NfK3L6kh6IcBByMiACCMI1MXN0O1ld+0oHtyuo5C43l9p06H/n2ddJfjsgKJAwEI2gQARzBEAiBi63pVYQenxz9FrEq1od3fb3B1+xJ1lpp/OD7/94S8sgIgDAXbt0cNvy8IVX3TVscyXB7TCRPpls04QJRdsSIo2l8BRzBEAiBl9FulmYtZon/+GnvtAWrx8fkNVLOqj3RQql9WolEDvQIgf3JHA60e25ZoCyhLVtT/y4j3+3Weq74IqjDym4UTg9IBR1IhAwidwQx6xttU+RMpr2FzM9s4jOrQwjH3IzedG5kDCwLcIQI63ZBPPW3PWd25BrDe4jUpt/+57VDl6GFRkmhgIh8Oc1KuACICA6mkw39ZltOqJdusa1cK8GUDlEkpQkYLNUdT7Z7spYdxENkMak8AAACAAAAAgAQAAIAAIgICf2OZdX0u/1WhNq0CxoSxg4tlVuXxtrNCgqlLa1AFEJYQ2QxqTwAAAIAAAACABQAAgAA=",
        Reject(RejectCategory::InvalidKeyStructure),
    ),
    (
        "invalid: PSBT with invalid final script witness typed key",
        "cHNidP8BAJoCAAAAAljoeiG1ba8MI76OcHBFbDNvfLqlyHV5JPVFiHuyq911AAAAAAD/////g40EJ9DsZQpoqka7CwmK6kQiwHGyyng1Kgd5WdB86h0BAAAAAP////8CcKrwCAAAAAAWABTYXCtx0AYLCcmIauuBXlCZHdoSTQDh9QUAAAAAFgAUAK6pouXw+HaliN9VRuh0LR2HAI8AAAAAAAEAuwIAAAABqtc5MQGL0l+ErkALaISL4J23BurCrBgpi6vucatlb4sAAAAASEcwRAIgWPb8fGoz4bMVSNSByCbAFb0wE1qtQs1neQ2rZtKtJDsCIEoc7SYExnNbY5PltBaR3XiwDwxZQvufdRhW+qk4FX26Af7///8CgPD6AgAAAAAXqRQPuUY0IWlrgsgzryQceMF9295JNIfQ8gonAQAAABepFCnKdPigj4GZlCgYXJe12FLkBj9hh2UAAAABB9oARzBEAiB0AYrUGACXuHMyPAAVcgs2hMyBI4kQSOfbzZtVrWecmQIgc9Npt0Dj61Pc76M4I8gHBRTKVafdlUTxV8FnkTJhEYwBSDBFAiEA9hA4swjcHahlo0hSdG8BV3KTQgjG0kRUOTzZm98iF3cCIAVuZ1pnWm0KArhbFOXikHTYolqbV2C+ooFvZhkQoAbqAUdSIQKVg785rgpgl0etGZrd1jT6YQhVnWxc05tMIYPxq5bgfyEC2rYf9JoU22p9ArDNH7t4/EsYMStbTlTa5Nui+/71NtdSrgABASAAwusLAAAAABepFLf1+vQOPUClpFmx2zU18rcvqSHohwEHIyIAIIwjUxc3Q7WV37Sge3K6jkLjeX2nTof+fZ10l+OyAokDAggA2gQARzBEAiBi63pVYQenxz9FrEq1od3fb3B1+xJ1lpp/OD7/94S8sgIgDAXbt0cNvy8IVX3TVscyXB7TCRPpls04QJRdsSIo2l8BRzBEAiBl9FulmYtZon/+GnvtAWrx8fkNVLOqj3RQql9WolEDvQIgf3JHA60e25ZoCyhLVtT/y4j3+3Weq74IqjDym4UTg9IBR1IhAwidwQx6xttU+RMpr2FzM9s4jOrQwjH3IzedG5kDCwLcIQI63ZBPPW3PWd25BrDe4jUpt/+57VDl6GFRkmhgIh8Oc1KuACICA6mkw39ZltOqJdusa1cK8GUDlEkpQkYLNUdT7Z7spYdxENkMak8AAACAAAAAgAQAAIAAIgICf2OZdX0u/1WhNq0CxoSxg4tlVuXxtrNCgqlLa1AFEJYQ2QxqTwAAAIAAAACABQAAgAA=",
        Reject(RejectCategory::InvalidKeyStructure),
    ),
    (
        "invalid: PSBT with invalid pubkey in output BIP 32 derivation paths typed key",
        "cHNidP8BAJoCAAAAAljoeiG1ba8MI76OcHBFbDNvfLqlyHV5JPVFiHuyq911AAAAAAD/////g40EJ9DsZQpoqka7CwmK6kQiwHGyyng1Kgd5WdB86h0BAAAAAP////8CcKrwCAAAAAAWABTYXCtx0AYLCcmIauuBXlCZHdoSTQDh9QUAAAAAFgAUAK6pouXw+HaliN9VRuh0LR2HAI8AAAAAAAEAuwIAAAABqtc5MQGL0l+ErkALaISL4J23BurCrBgpi6vucatlb4sAAAAASEcwRAIgWPb8fGoz4bMVSNSByCbAFb0wE1qtQs1neQ2rZtKtJDsCIEoc7SYExnNbY5PltBaR3XiwDwxZQvufdRhW+qk4FX26Af7///8CgPD6AgAAAAAXqRQPuUY0IWlrgsgzryQceMF9295JNIfQ8gonAQAAABepFCnKdPigj4GZlCgYXJe12FLkBj9hh2UAAAABB9oARzBEAiB0AYrUGACXuHMyPAAVcgs2hMyBI4kQSOfbzZtVrWecmQIgc9Npt0Dj61Pc76M4I8gHBRTKVafdlUTxV8FnkTJhEYwBSDBFAiEA9hA4swjcHahlo0hSdG8BV3KTQgjG0kRUOTzZm98iF3cCIAVuZ1pnWm0KArhbFOXikHTYolqbV2C+ooFvZhkQoAbqAUdSIQKVg785rgpgl0etGZrd1jT6YQhVnWxc05tMIYPxq5bgfyEC2rYf9JoU22p9ArDNH7t4/EsYMStbTlTa5Nui+/71NtdSrgABASAAwusLAAAAABepFLf1+vQOPUClpFmx2zU18rcvqSHohwEHIyIAIIwjUxc3Q7WV37Sge3K6jkLjeX2nTof+fZ10l+OyAokDAQjaBABHMEQCIGLrelVhB6fHP0WsSrWh3d9vcHX7EnWWmn84Pv/3hLyyAiAMBdu3Rw2/LwhVfdNWxzJcHtMJE+mWzThAlF2xIijaXwFHMEQCIGX0W6WZi1mif/4ae+0BavHx+Q1Us6qPdFCqX1aiUQO9AiB/ckcDrR7blmgLKEtW1P/LiPf7dZ6rvgiqMPKbhROD0gFHUiEDCJ3BDHrG21T5EymvYXMz2ziM6tDCMfcjN50bmQMLAtwhAjrdkE89bc9Z3bkGsN7iNSm3/7ntUOXoYVGSaGAiHw5zUq4AIQIDqaTDf1mW06ol26xrVwrwZQOUSSlCRgs1R1PtnuylhxDZDGpPAAAAgAAAAIAEAACAACICAn9jmXV9Lv9VoTatAsaEsYOLZVbl8bazQoKpS2tQBRCWENkMak8AAACAAAAAgAUAAIAA",
        Reject(RejectCategory::InvalidKeyStructure),
    ),
    (
        "invalid: PSBT with invalid input sighash type typed key",
        "cHNidP8BAHMCAAAAATAa6YblFqHsisW0vGVz0y+DtGXiOtdhZ9aLOOcwtNvbAAAAAAD/////AnR7AQAAAAAAF6kUA6oXrogrXQ1Usl1jEE5P/s57nqKHYEOZOwAAAAAXqRS5IbG6b3IuS/qDtlV6MTmYakLsg4cAAAAAAAEBHwDKmjsAAAAAFgAU0tlLZK4IWH7vyO6xh8YB6Tn5A3wCAwABAAAAAAEAFgAUYunpgv/zTdgjlhAxawkM0qO3R8sAAQAiACCHa62DLx0WgBXtQSMqnqZaGBXZ7xPA74dZ9ktbKyeKZQEBJVEhA7fOI6AcW0vwCmQlN836uzFbZoMyhnR471EwnSvVf4qHUa4A",
        Reject(RejectCategory::InvalidKeyStructure),
    ),
    (
        "invalid: PSBT with invalid output redeemScript typed key",
        "cHNidP8BAHMCAAAAATAa6YblFqHsisW0vGVz0y+DtGXiOtdhZ9aLOOcwtNvbAAAAAAD/////AnR7AQAAAAAAF6kUA6oXrogrXQ1Usl1jEE5P/s57nqKHYEOZOwAAAAAXqRS5IbG6b3IuS/qDtlV6MTmYakLsg4cAAAAAAAEBHwDKmjsAAAAAFgAU0tlLZK4IWH7vyO6xh8YB6Tn5A3wAAgAAFgAUYunpgv/zTdgjlhAxawkM0qO3R8sAAQAiACCHa62DLx0WgBXtQSMqnqZaGBXZ7xPA74dZ9ktbKyeKZQEBJVEhA7fOI6AcW0vwCmQlN836uzFbZoMyhnR471EwnSvVf4qHUa4A",
        Reject(RejectCategory::InvalidKeyStructure),
    ),
    (
        "invalid: PSBT with invalid output witnessScript typed key",
        "cHNidP8BAHMCAAAAATAa6YblFqHsisW0vGVz0y+DtGXiOtdhZ9aLOOcwtNvbAAAAAAD/////AnR7AQAAAAAAF6kUA6oXrogrXQ1Usl1jEE5P/s57nqKHYEOZOwAAAAAXqRS5IbG6b3IuS/qDtlV6MTmYakLsg4cAAAAAAAEBHwDKmjsAAAAAFgAU0tlLZK4IWH7vyO6xh8YB6Tn5A3wAAQAWABRi6emC//NN2COWEDFrCQzSo7dHywABACIAIIdrrYMvHRaAFe1BIyqeploYFdnvE8Dvh1n2S1srJ4plIQEAJVEhA7fOI6AcW0vwCmQlN836uzFbZoMyhnR471EwnQbVf4qHUa4A",
        Reject(RejectCategory::InvalidKeyStructure),
    ),
    (
        "invalid: PSBT with unsigned tx serialized with witness serialization format",
        "cHNidP8BAHgCAAAAAAEBJoFxNx7f8oXpN63upLN7eAAMBWbLs61kZBcTykIXG/YAAAAAAP7///8C09/1BQAAAAAZdqkU0MWZA8W6woaHYOkP1SGkZlqnZSCIrADh9QUAAAAAF6kUNUXm4zuDLEcFDyTT7rk8nAOUi8eHALMuEwAAAQD9pQEBAAAAAAECiaPHHqtNIOA3G7ukzGmPopXJRjr6Ljl/hTPMti+VZ+UBAAAAFxYAFL4Y0VKpsBIDna89p95PUzSe7LmF/////4b4qkOnHf8USIk6UwpyN+9rRgi7st0tAXHmOuxqSJC0AQAAABcWABT+Pp7xp0XpdNkCxDVZQ6vLNL1TU/////8CAMLrCwAAAAAZdqkUhc/xCX/Z4Ai7NK9wnGIZeziXikiIrHL++E4sAAAAF6kUM5cluiHv1irHU6m80GfWx6ajnQWHAkcwRAIgJxK+IuAnDzlPVoMR3HyppolwuAJf3TskAinwf4pfOiQCIAGLONfc0xTnNMkna9b7QPZzMlvEuqFEyADS8vAtsnZcASED0uFWdJQbrUqZY3LLh+GFbTZSYG2YVi/jnF6efkE/IQUCSDBFAiEA0SuFLYXc2WHS9fSrZgZU327tzHlMDDPOXMMJ/7X85Y0CIGczio4OFyXBl/saiK9Z9R5E5CVbIBZ8hoQDHAXR8lkqASECI7cr7vCWXRC+B3jv7NYfysb3mk6haTkzgHNEZPhPKrMAAAAAAAAA",
        Reject(RejectCategory::UnsignedTxWitnessFormat),
    ),
    (
        // Upstream intent is a misstated value size; under the local
        // structural walk the garbled unsigned-tx bytes read as a
        // zero-input transaction followed by the witness flag byte, so
        // the profile deterministically rejects it there.
        "invalid: PSBT with an invalid value data due to its size being not the stated size",
        "cHNidP8BADN0Af8HAAEAAAABAP8BAApzMXQo/wAAAAAB/wEDAQAAAQAAAAAAAAAAdgEAAABBAAkAAAAAAA==",
        Reject(RejectCategory::UnsignedTxWitnessFormat),
    ),
    (
        "valid: PSBT with one P2PKH input. Outputs are empty",
        "cHNidP8BAHUCAAAAASaBcTce3/KF6Tet7qSze3gADAVmy7OtZGQXE8pCFxv2AAAAAAD+////AtPf9QUAAAAAGXapFNDFmQPFusKGh2DpD9UhpGZap2UgiKwA4fUFAAAAABepFDVF5uM7gyxHBQ8k0+65PJwDlIvHh7MuEwAAAQD9pQEBAAAAAAECiaPHHqtNIOA3G7ukzGmPopXJRjr6Ljl/hTPMti+VZ+UBAAAAFxYAFL4Y0VKpsBIDna89p95PUzSe7LmF/////4b4qkOnHf8USIk6UwpyN+9rRgi7st0tAXHmOuxqSJC0AQAAABcWABT+Pp7xp0XpdNkCxDVZQ6vLNL1TU/////8CAMLrCwAAAAAZdqkUhc/xCX/Z4Ai7NK9wnGIZeziXikiIrHL++E4sAAAAF6kUM5cluiHv1irHU6m80GfWx6ajnQWHAkcwRAIgJxK+IuAnDzlPVoMR3HyppolwuAJf3TskAinwf4pfOiQCIAGLONfc0xTnNMkna9b7QPZzMlvEuqFEyADS8vAtsnZcASED0uFWdJQbrUqZY3LLh+GFbTZSYG2YVi/jnF6efkE/IQUCSDBFAiEA0SuFLYXc2WHS9fSrZgZU327tzHlMDDPOXMMJ/7X85Y0CIGczio4OFyXBl/saiK9Z9R5E5CVbIBZ8hoQDHAXR8lkqASECI7cr7vCWXRC+B3jv7NYfysb3mk6haTkzgHNEZPhPKrMAAAAAAAAA",
        Accept,
    ),
    (
        "valid: PSBT with one P2PKH input and one P2SH-P2WPKH input. First input is signed and finalized. Outputs are empty",
        "cHNidP8BAKACAAAAAqsJSaCMWvfEm4IS9Bfi8Vqz9cM9zxU4IagTn4d6W3vkAAAAAAD+////qwlJoIxa98SbghL0F+LxWrP1wz3PFTghqBOfh3pbe+QBAAAAAP7///8CYDvqCwAAAAAZdqkUdopAu9dAy+gdmI5x3ipNXHE5ax2IrI4kAAAAAAAAGXapFG9GILVT+glechue4O/p+gOcykWXiKwAAAAAAAEHakcwRAIgR1lmF5fAGwNrJZKJSGhiGDR9iYZLcZ4ff89X0eURZYcCIFMJ6r9Wqk2Ikf/REf3xM286KdqGbX+EhtdVRs7tr5MZASEDXNxh/HupccC1AaZGoqg7ECy0OIEhfKaC3Ibi1z+ogpIAAQEgAOH1BQAAAAAXqRQ1RebjO4MsRwUPJNPuuTycA5SLx4cBBBYAFIXRNTfy4mVAWjTbr6nj3aAfuCMIAAAA",
        Accept,
    ),
    (
        "valid: PSBT with one P2PKH input which has a non-final scriptSig and has a sighash type specified. Outputs are empty",
        "cHNidP8BAHUCAAAAASaBcTce3/KF6Tet7qSze3gADAVmy7OtZGQXE8pCFxv2AAAAAAD+////AtPf9QUAAAAAGXapFNDFmQPFusKGh2DpD9UhpGZap2UgiKwA4fUFAAAAABepFDVF5uM7gyxHBQ8k0+65PJwDlIvHh7MuEwAAAQD9pQEBAAAAAAECiaPHHqtNIOA3G7ukzGmPopXJRjr6Ljl/hTPMti+VZ+UBAAAAFxYAFL4Y0VKpsBIDna89p95PUzSe7LmF/////4b4qkOnHf8USIk6UwpyN+9rRgi7st0tAXHmOuxqSJC0AQAAABcWABT+Pp7xp0XpdNkCxDVZQ6vLNL1TU/////8CAMLrCwAAAAAZdqkUhc/xCX/Z4Ai7NK9wnGIZeziXikiIrHL++E4sAAAAF6kUM5cluiHv1irHU6m80GfWx6ajnQWHAkcwRAIgJxK+IuAnDzlPVoMR3HyppolwuAJf3TskAinwf4pfOiQCIAGLONfc0xTnNMkna9b7QPZzMlvEuqFEyADS8vAtsnZcASED0uFWdJQbrUqZY3LLh+GFbTZSYG2YVi/jnF6efkE/IQUCSDBFAiEA0SuFLYXc2WHS9fSrZgZU327tzHlMDDPOXMMJ/7X85Y0CIGczio4OFyXBl/saiK9Z9R5E5CVbIBZ8hoQDHAXR8lkqASECI7cr7vCWXRC+B3jv7NYfysb3mk6haTkzgHNEZPhPKrMAAAAAAQMEAQAAAAAAAA==",
        Accept,
    ),
    (
        "valid: PSBT with one P2PKH input and one P2SH-P2WPKH input both with non-final scriptSigs. P2SH-P2WPKH input's redeemScript is available. Outputs filled.",
        "cHNidP8BAKACAAAAAqsJSaCMWvfEm4IS9Bfi8Vqz9cM9zxU4IagTn4d6W3vkAAAAAAD+////qwlJoIxa98SbghL0F+LxWrP1wz3PFTghqBOfh3pbe+QBAAAAAP7///8CYDvqCwAAAAAZdqkUdopAu9dAy+gdmI5x3ipNXHE5ax2IrI4kAAAAAAAAGXapFG9GILVT+glechue4O/p+gOcykWXiKwAAAAAAAEA3wIAAAABJoFxNx7f8oXpN63upLN7eAAMBWbLs61kZBcTykIXG/YAAAAAakcwRAIgcLIkUSPmv0dNYMW1DAQ9TGkaXSQ18Jo0p2YqncJReQoCIAEynKnazygL3zB0DsA5BCJCLIHLRYOUV663b8Eu3ZWzASECZX0RjTNXuOD0ws1G23s59tnDjZpwq8ubLeXcjb/kzjH+////AtPf9QUAAAAAGXapFNDFmQPFusKGh2DpD9UhpGZap2UgiKwA4fUFAAAAABepFDVF5uM7gyxHBQ8k0+65PJwDlIvHh7MuEwAAAQEgAOH1BQAAAAAXqRQ1RebjO4MsRwUPJNPuuTycA5SLx4cBBBYAFIXRNTfy4mVAWjTbr6nj3aAfuCMIACICAurVlmh8qAYEPtw94RbN8p1eklfBls0FXPaYyNAr8k6ZELSmumcAAACAAAAAgAIAAIAAIgIDlPYr6d8ZlSxVh3aK63aYBhrSxKJciU9H2MFitNchPQUQtKa6ZwAAAIABAACAAgAAgAA=",
        Accept,
    ),
    (
        "valid: PSBT with one P2SH-P2WSH input of a 2-of-2 multisig, redeemScript, witnessScript, and keypaths are available. Contains one signature.",
        "cHNidP8BAFUCAAAAASeaIyOl37UfxF8iD6WLD8E+HjNCeSqF1+Ns1jM7XLw5AAAAAAD/////AaBa6gsAAAAAGXapFP/pwAYQl8w7Y28ssEYPpPxCfStFiKwAAAAAAAEBIJVe6gsAAAAAF6kUY0UgD2jRieGtwN8cTRbqjxTA2+uHIgIDsTQcy6doO2r08SOM1ul+cWfVafrEfx5I1HVBhENVvUZGMEMCIAQktY7/qqaU4VWepck7v9SokGQiQFXN8HC2dxRpRC0HAh9cjrD+plFtYLisszrWTt5g6Hhb+zqpS5m9+GFR25qaAQEEIgAgdx/RitRZZm3Unz1WTj28QvTIR3TjYK2haBao7UiNVoEBBUdSIQOxNBzLp2g7avTxI4zW6X5xZ9Vp+sR/HkjUdUGEQ1W9RiED3lXR4drIBeP4pYwfv5uUwC89uq/hJ/78pJlfJvggg71SriIGA7E0HMunaDtq9PEjjNbpfnFn1Wn6xH8eSNR1QYRDVb1GELSmumcAAACAAAAAgAQAAIAiBgPeVdHh2sgF4/iljB+/m5TALz26r+En/vykmV8m+CCDvRC0prpnAAAAgAAAAIAFAACAAAA=",
        Accept,
    ),
    (
        "valid: PSBT with one P2WSH input of a 2-of-2 multisig. witnessScript, keypaths, and global xpubs are available. Contains no signatures. Outputs filled.",
        "cHNidP8BAFICAAAAAZ38ZijCbFiZ/hvT3DOGZb/VXXraEPYiCXPfLTht7BJ2AQAAAAD/////AfA9zR0AAAAAFgAUezoAv9wU0neVwrdJAdCdpu8TNXkAAAAATwEENYfPAto/0AiAAAAAlwSLGtBEWx7IJ1UXcnyHtOTrwYogP/oPlMAVZr046QADUbdDiH7h1A3DKmBDck8tZFmztaTXPa7I+64EcvO8Q+IM2QxqT64AAIAAAACATwEENYfPAto/0AiAAAABuQRSQnE5zXjCz/JES+NTzVhgXj5RMoXlKLQH+uP2FzUD0wpel8itvFV9rCrZp+OcFyLrrGnmaLbyZnzB1nHIPKsM2QxqT64AAIABAACAAAEBKwBlzR0AAAAAIgAgLFSGEmxJeAeagU4TcV1l82RZ5NbMre0mbQUIZFuvpjIBBUdSIQKdoSzbWyNWkrkVNq/v5ckcOrlHPY5DtTODarRWKZyIcSEDNys0I07Xz5wf6l0F1EFVeSe+lUKxYusC4ass6AIkwAtSriIGAp2hLNtbI1aSuRU2r+/lyRw6uUc9jkO1M4NqtFYpnIhxENkMak+uAACAAAAAgAAAAAAiBgM3KzQjTtfPnB/qXQXUQVV5J76VQrFi6wLhqyzoAiTACxDZDGpPrgAAgAEAAIAAAAAAACICA57/H1R6HV+S36K6evaslxpL0DukpzSwMVaiVritOh75EO3kXMUAAACAAAAAgAEAAIAA",
        Accept,
    ),
    (
        "valid: PSBT with unknown types in the inputs.",
        "cHNidP8BAD8CAAAAAf//////////////////////////////////////////AAAAAAD/////AQAAAAAAAAAAA2oBAAAAAAAACvABAgMEBQYHCAkPAQIDBAUGBwgJCgsMDQ4PAAA=",
        Accept,
    ),
    (
        "valid: PSBT with `PSBT_GLOBAL_XPUB`.",
        "cHNidP8BAJ0BAAAAAnEOp2q0XFy2Q45gflnMA3YmmBgFrp4N/ZCJASq7C+U1AQAAAAD/////GQmU1qizyMgsy8+y+6QQaqBmObhyqNRHRlwNQliNbWcAAAAAAP////8CAOH1BQAAAAAZdqkUtrwsDuVlWoQ9ea/t0MzD991kNAmIrGBa9AUAAAAAFgAUEYjvjkzgRJ6qyPsUHL9aEXbmoIgAAAAATwEEiLIeA55TDKyAAAAAPbyKXJdp8DGxfnf+oVGGAyIaGP0Y8rmlTGyMGsdcvDUC8jBYSxVdHH8c1FEgplPEjWULQxtnxbLBPyfXFCA3wWkQJ1acUDEAAIAAAACAAAAAgAABAR8A4fUFAAAAABYAFDO5gvkbKPFgySC0q5XljOUN2jpKIgIDMJaA8zx9446mpHzU7NZvH1pJdHxv+4gI7QkDkkPjrVxHMEQCIC1wTO2DDFapCTRL10K2hS3M0QPpY7rpLTjnUlTSu0JFAiAthsQ3GV30bAztoITyopHD2i1kBw92v5uQsZXn7yj3cgEiBgMwloDzPH3jjqakfNTs1m8fWkl0fG/7iAjtCQOSQ+OtXBgnVpxQMQAAgAAAAIAAAACAAAAAAAEAAAAAAQEfAOH1BQAAAAAWABQ4j7lEMH63fvRRl9CwskXgefAR3iICAsd3Fh9z0LfHK57nveZQKT0T8JW8dlatH1Jdpf0uELEQRzBEAiBMsftfhpyULg4mEAV2ElQ5F5rojcqKncO6CPeVOYj6pgIgUh9JynkcJ9cOJzybFGFphZCTYeJb4nTqIA1+CIJ+UU0BIgYCx3cWH3PQt8crnue95lApPRPwlbx2Vq0fUl2l/S4QsRAYJ1acUDEAAIAAAACAAAAAgAAAAAAAAAAAAAAiAgLSDKUC7iiWhtIYFb1DqAY3sGmOH7zb5MrtRF9sGgqQ7xgnVpxQMQAAgAAAAIAAAACAAAAAAAQAAAAA",
        Accept,
    ),
    (
        "valid: PSBT with global unsigned tx that has 0 inputs and 0 outputs",
        "cHNidP8BAAoAAAAAAAAAAAAAAA==",
        Reject(RejectCategory::UnsignedTxZeroInputs),
    ),
    (
        "valid: PSBT with 0 inputs",
        "cHNidP8BAEwCAAAAAALT3/UFAAAAABl2qRTQxZkDxbrChodg6Q/VIaRmWqdlIIisAOH1BQAAAAAXqRQ1RebjO4MsRwUPJNPuuTycA5SLx4ezLhMAAAAA",
        Reject(RejectCategory::UnsignedTxZeroInputs),
    ),
    (
        "signer-failure (structurally valid; post-M3 rejection pending): A Witness UTXO is provided for a non-witness input",
        "cHNidP8BAKACAAAAAqsJSaCMWvfEm4IS9Bfi8Vqz9cM9zxU4IagTn4d6W3vkAAAAAAD+////qwlJoIxa98SbghL0F+LxWrP1wz3PFTghqBOfh3pbe+QBAAAAAP7///8CYDvqCwAAAAAZdqkUdopAu9dAy+gdmI5x3ipNXHE5ax2IrI4kAAAAAAAAGXapFG9GILVT+glechue4O/p+gOcykWXiKwAAAAAAAEBItPf9QUAAAAAGXapFNSO0xELlAFMsRS9Mtb00GbcdCVriKwAAQEgAOH1BQAAAAAXqRQ1RebjO4MsRwUPJNPuuTycA5SLx4cBBBYAFIXRNTfy4mVAWjTbr6nj3aAfuCMIACICAurVlmh8qAYEPtw94RbN8p1eklfBls0FXPaYyNAr8k6ZELSmumcAAACAAAAAgAIAAIAAIgIDlPYr6d8ZlSxVh3aK63aYBhrSxKJciU9H2MFitNchPQUQtKa6ZwAAAIABAACAAgAAgAA=",
        SignerRejectLater,
    ),
    (
        "signer-failure (structurally valid; post-M3 rejection pending): redeemScript with non-witness UTXO does not match the scriptPubKey",
        "cHNidP8BAJoCAAAAAljoeiG1ba8MI76OcHBFbDNvfLqlyHV5JPVFiHuyq911AAAAAAD/////g40EJ9DsZQpoqka7CwmK6kQiwHGyyng1Kgd5WdB86h0BAAAAAP////8CcKrwCAAAAAAWABTYXCtx0AYLCcmIauuBXlCZHdoSTQDh9QUAAAAAFgAUAK6pouXw+HaliN9VRuh0LR2HAI8AAAAAAAEAuwIAAAABqtc5MQGL0l+ErkALaISL4J23BurCrBgpi6vucatlb4sAAAAASEcwRAIgWPb8fGoz4bMVSNSByCbAFb0wE1qtQs1neQ2rZtKtJDsCIEoc7SYExnNbY5PltBaR3XiwDwxZQvufdRhW+qk4FX26Af7///8CgPD6AgAAAAAXqRQPuUY0IWlrgsgzryQceMF9295JNIfQ8gonAQAAABepFCnKdPigj4GZlCgYXJe12FLkBj9hh2UAAAAiAgLath/0mhTban0CsM0fu3j8SxgxK1tOVNrk26L7/vU210gwRQIhAPYQOLMI3B2oZaNIUnRvAVdyk0IIxtJEVDk82ZvfIhd3AiAFbmdaZ1ptCgK4WxTl4pB02KJam1dgvqKBb2YZEKAG6gEBAwQBAAAAAQRHUiEClYO/Oa4KYJdHrRma3dY0+mEIVZ1sXNObTCGD8auW4H8hAtq2H/SaFNtqfQKwzR+7ePxLGDErW05U2uTbovv+9TbXUq8iBgKVg785rgpgl0etGZrd1jT6YQhVnWxc05tMIYPxq5bgfxDZDGpPAAAAgAAAAIAAAACAIgYC2rYf9JoU22p9ArDNH7t4/EsYMStbTlTa5Nui+/71NtcQ2QxqTwAAAIAAAACAAQAAgAABASAAwusLAAAAABepFLf1+vQOPUClpFmx2zU18rcvqSHohyICAjrdkE89bc9Z3bkGsN7iNSm3/7ntUOXoYVGSaGAiHw5zRzBEAiBl9FulmYtZon/+GnvtAWrx8fkNVLOqj3RQql9WolEDvQIgf3JHA60e25ZoCyhLVtT/y4j3+3Weq74IqjDym4UTg9IBAQMEAQAAAAEEIgAgjCNTFzdDtZXftKB7crqOQuN5fadOh/59nXSX47ICiQMBBUdSIQMIncEMesbbVPkTKa9hczPbOIzq0MIx9yM3nRuZAwsC3CECOt2QTz1tz1nduQaw3uI1Kbf/ue1Q5ehhUZJoYCIfDnNSriIGAjrdkE89bc9Z3bkGsN7iNSm3/7ntUOXoYVGSaGAiHw5zENkMak8AAACAAAAAgAMAAIAiBgMIncEMesbbVPkTKa9hczPbOIzq0MIx9yM3nRuZAwsC3BDZDGpPAAAAgAAAAIACAACAACICA6mkw39ZltOqJdusa1cK8GUDlEkpQkYLNUdT7Z7spYdxENkMak8AAACAAAAAgAQAAIAAIgICf2OZdX0u/1WhNq0CxoSxg4tlVuXxtrNCgqlLa1AFEJYQ2QxqTwAAAIAAAACABQAAgAA=",
        SignerRejectLater,
    ),
    (
        "signer-failure (structurally valid; post-M3 rejection pending): redeemScript with witness UTXO does not match the scriptPubKey",
        "cHNidP8BAJoCAAAAAljoeiG1ba8MI76OcHBFbDNvfLqlyHV5JPVFiHuyq911AAAAAAD/////g40EJ9DsZQpoqka7CwmK6kQiwHGyyng1Kgd5WdB86h0BAAAAAP////8CcKrwCAAAAAAWABTYXCtx0AYLCcmIauuBXlCZHdoSTQDh9QUAAAAAFgAUAK6pouXw+HaliN9VRuh0LR2HAI8AAAAAAAEAuwIAAAABqtc5MQGL0l+ErkALaISL4J23BurCrBgpi6vucatlb4sAAAAASEcwRAIgWPb8fGoz4bMVSNSByCbAFb0wE1qtQs1neQ2rZtKtJDsCIEoc7SYExnNbY5PltBaR3XiwDwxZQvufdRhW+qk4FX26Af7///8CgPD6AgAAAAAXqRQPuUY0IWlrgsgzryQceMF9295JNIfQ8gonAQAAABepFCnKdPigj4GZlCgYXJe12FLkBj9hh2UAAAAiAgLath/0mhTban0CsM0fu3j8SxgxK1tOVNrk26L7/vU210gwRQIhAPYQOLMI3B2oZaNIUnRvAVdyk0IIxtJEVDk82ZvfIhd3AiAFbmdaZ1ptCgK4WxTl4pB02KJam1dgvqKBb2YZEKAG6gEBAwQBAAAAAQRHUiEClYO/Oa4KYJdHrRma3dY0+mEIVZ1sXNObTCGD8auW4H8hAtq2H/SaFNtqfQKwzR+7ePxLGDErW05U2uTbovv+9TbXUq4iBgKVg785rgpgl0etGZrd1jT6YQhVnWxc05tMIYPxq5bgfxDZDGpPAAAAgAAAAIAAAACAIgYC2rYf9JoU22p9ArDNH7t4/EsYMStbTlTa5Nui+/71NtcQ2QxqTwAAAIAAAACAAQAAgAABASAAwusLAAAAABepFLf1+vQOPUClpFmx2zU18rcvqSHohyICAjrdkE89bc9Z3bkGsN7iNSm3/7ntUOXoYVGSaGAiHw5zRzBEAiBl9FulmYtZon/+GnvtAWrx8fkNVLOqj3RQql9WolEDvQIgf3JHA60e25ZoCyhLVtT/y4j3+3Weq74IqjDym4UTg9IBAQMEAQAAAAEEIgAgjCNTFzdDtZXftKB7crqOQuN5fadOh/59nXSX47ICiQABBUdSIQMIncEMesbbVPkTKa9hczPbOIzq0MIx9yM3nRuZAwsC3CECOt2QTz1tz1nduQaw3uI1Kbf/ue1Q5ehhUZJoYCIfDnNSriIGAjrdkE89bc9Z3bkGsN7iNSm3/7ntUOXoYVGSaGAiHw5zENkMak8AAACAAAAAgAMAAIAiBgMIncEMesbbVPkTKa9hczPbOIzq0MIx9yM3nRuZAwsC3BDZDGpPAAAAgAAAAIACAACAACICA6mkw39ZltOqJdusa1cK8GUDlEkpQkYLNUdT7Z7spYdxENkMak8AAACAAAAAgAQAAIAAIgICf2OZdX0u/1WhNq0CxoSxg4tlVuXxtrNCgqlLa1AFEJYQ2QxqTwAAAIAAAACABQAAgAA=",
        SignerRejectLater,
    ),
    (
        "signer-failure (structurally valid; post-M3 rejection pending): witnessScript with witness UTXO does not match the redeemScript",
        "cHNidP8BAJoCAAAAAljoeiG1ba8MI76OcHBFbDNvfLqlyHV5JPVFiHuyq911AAAAAAD/////g40EJ9DsZQpoqka7CwmK6kQiwHGyyng1Kgd5WdB86h0BAAAAAP////8CcKrwCAAAAAAWABTYXCtx0AYLCcmIauuBXlCZHdoSTQDh9QUAAAAAFgAUAK6pouXw+HaliN9VRuh0LR2HAI8AAAAAAAEAuwIAAAABqtc5MQGL0l+ErkALaISL4J23BurCrBgpi6vucatlb4sAAAAASEcwRAIgWPb8fGoz4bMVSNSByCbAFb0wE1qtQs1neQ2rZtKtJDsCIEoc7SYExnNbY5PltBaR3XiwDwxZQvufdRhW+qk4FX26Af7///8CgPD6AgAAAAAXqRQPuUY0IWlrgsgzryQceMF9295JNIfQ8gonAQAAABepFCnKdPigj4GZlCgYXJe12FLkBj9hh2UAAAAiAgLath/0mhTban0CsM0fu3j8SxgxK1tOVNrk26L7/vU210gwRQIhAPYQOLMI3B2oZaNIUnRvAVdyk0IIxtJEVDk82ZvfIhd3AiAFbmdaZ1ptCgK4WxTl4pB02KJam1dgvqKBb2YZEKAG6gEBAwQBAAAAAQRHUiEClYO/Oa4KYJdHrRma3dY0+mEIVZ1sXNObTCGD8auW4H8hAtq2H/SaFNtqfQKwzR+7ePxLGDErW05U2uTbovv+9TbXUq4iBgKVg785rgpgl0etGZrd1jT6YQhVnWxc05tMIYPxq5bgfxDZDGpPAAAAgAAAAIAAAACAIgYC2rYf9JoU22p9ArDNH7t4/EsYMStbTlTa5Nui+/71NtcQ2QxqTwAAAIAAAACAAQAAgAABASAAwusLAAAAABepFLf1+vQOPUClpFmx2zU18rcvqSHohyICAjrdkE89bc9Z3bkGsN7iNSm3/7ntUOXoYVGSaGAiHw5zRzBEAiBl9FulmYtZon/+GnvtAWrx8fkNVLOqj3RQql9WolEDvQIgf3JHA60e25ZoCyhLVtT/y4j3+3Weq74IqjDym4UTg9IBAQMEAQAAAAEEIgAgjCNTFzdDtZXftKB7crqOQuN5fadOh/59nXSX47ICiQMBBUdSIQMIncEMesbbVPkTKa9hczPbOIzq0MIx9yM3nRuZAwsC3CECOt2QTz1tz1nduQaw3uI1Kbf/ue1Q5ehhUZJoYCIfDnNSrSIGAjrdkE89bc9Z3bkGsN7iNSm3/7ntUOXoYVGSaGAiHw5zENkMak8AAACAAAAAgAMAAIAiBgMIncEMesbbVPkTKa9hczPbOIzq0MIx9yM3nRuZAwsC3BDZDGpPAAAAgAAAAIACAACAACICA6mkw39ZltOqJdusa1cK8GUDlEkpQkYLNUdT7Z7spYdxENkMak8AAACAAAAAgAQAAIAAIgICf2OZdX0u/1WhNq0CxoSxg4tlVuXxtrNCgqlLa1AFEJYQ2QxqTwAAAIAAAACABQAAgAA=",
        SignerRejectLater,
    ),
    (
        "unknown_kv: unknown key-value pairs input 1",
        "cHNidP8BAD8CAAAAAf//////////////////////////////////////////AAAAAAD/////AQAAAAAAAAAAA2oBAAAAAAAK8AECAwQFBgcICQ8BAgMEBQYHCAkKCwwNDg8ACvABAgMEBQYHCAkPAQIDBAUGBwgJCgsMDQ4PAArwAQIDBAUGBwgJDwECAwQFBgcICQoLDA0ODwA=",
        Accept,
    ),
    (
        "unknown_kv: unknown key-value pairs input 2",
        "cHNidP8BAD8CAAAAAf//////////////////////////////////////////AAAAAAD/////AQAAAAAAAAAAA2oBAAAAAAAK8AECAwQFBgcIEA8BAgMEBQYHCAkKCwwNDg8ACvABAgMEBQYHCBAPAQIDBAUGBwgJCgsMDQ4PAArwAQIDBAUGBwgQDwECAwQFBgcICQoLDA0ODwA=",
        Accept,
    ),
];

#[test]
fn every_pinned_upstream_vector_gets_its_expected_verdict() {
    for (name, b64s, verdict) in VECTORS {
        let bytes = b64(b64s);
        let result = parse(&bytes, InputSource::MicroSd);
        match verdict {
            Verdict::Accept => {
                assert!(result.is_ok(), "{name}: expected accept, got {result:?}");
            }
            Verdict::SignerRejectLater => {
                assert!(
                    name.starts_with(
                        "signer-failure (structurally valid; post-M3 rejection pending)"
                    ),
                    "{name}: signer-failure case must be labeled as deferred"
                );
                assert!(
                    result.is_ok(),
                    "{name}: signer-failure (structurally valid; post-M3 rejection pending) — M3 structural parse must accept, got {result:?}"
                );
            }
            Verdict::Reject(cat) => {
                let err = result
                    .err()
                    .unwrap_or_else(|| panic!("{name}: expected rejection {cat:?}, got accept"));
                assert_eq!(err.category, *cat, "{name}: wrong category");
            }
        }
    }
}

#[test]
fn upstream_unknown_key_value_vectors_preserve_records_verbatim() {
    let expected_value: Vec<u8> = (1u8..=15).collect();
    for (name, b64s, _) in VECTORS
        .iter()
        .filter(|(n, _, _)| n.starts_with("unknown_kv"))
    {
        let bytes = b64(b64s);
        let view = parse(&bytes, InputSource::MicroSd).expect("unknown_kv vectors accept");
        let scopes = [
            view.global_records(),
            view.input_records(0).expect("one input map"),
            view.output_records(0).expect("one output map"),
        ];
        for (i, records) in scopes.into_iter().enumerate() {
            let unknowns: Vec<_> = records.filter(|r| r.key_type == 0xf0).collect();
            assert_eq!(unknowns.len(), 1, "{name}: scope {i} unknown count");
            let r = unknowns[0];
            assert_eq!(r.key_data.len(), 9, "{name}: scope {i} key data length");
            assert_eq!(
                &r.key_data[..8],
                &[1, 2, 3, 4, 5, 6, 7, 8],
                "{name}: scope {i} key data"
            );
            assert_eq!(
                r.value,
                &expected_value[..],
                "{name}: scope {i} value bytes"
            );
            assert_eq!(
                r.value_span.slice(&bytes).unwrap(),
                r.value,
                "{name}: scope {i} span mismatch"
            );
        }
    }
}

// ---------------------------------------------------------------------------
// M5 canonical structural serializer tests (QK-DEC-036).
//
// The canonical-identity goldens below are locally derived, not imported:
// for every accepted upstream fixture the test first proves, independently
// of the serializer, that each map is already adjacent-ordered by (decoded
// numeric key type, raw key data). Given verbatim record copying and the
// parser's minimal-CompactSize guarantee, byte identity is then the only
// canonical outcome, so the input bytes themselves serve as the expected
// output. The scrambled synthetic fixture's expected canonical bytes were
// derived independently by a temporary local script implementing the
// QK-DEC-036 ordering; neither the script nor any intermediate artifact is
// committed.
// ---------------------------------------------------------------------------

type RecordTriple = (u64, Vec<u8>, Vec<u8>);
type MapMultiset = Vec<RecordTriple>;
type EncodedRecords = Vec<Vec<u8>>;

/// First-party synthetic PSBT with deliberately scrambled record order in
/// the global, input, and output maps. Contains unknown records (0xf0,
/// 0xf1), valid proprietary records (0xfc), an input SIGHASH_ALL record
/// (type 0x03, four-byte value 1), same-type records with differing key
/// data ([0x01] vs [0x01, 0x00]), and global key types 255 and 256 whose
/// numeric order differs from raw encoded-key order (encoded 255 =
/// fd ff 00 sorts after encoded 256 = fd 00 01). The unsigned transaction
/// is the never-fundable one-input/one-OP_RETURN-output synthetic.
const SCRAMBLED_SYNTHETIC_PSBT: &[u8] = &[
    0x70, 0x73, 0x62, 0x74, 0xff, 0x04, 0xfd, 0x00, 0x01, 0x01, 0x01, 0x33, 0x02, 0xf0, 0x01, 0x01,
    0x11, 0x01, 0x00, 0x3d, 0x02, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0x00, 0xfe, 0xff,
    0xff, 0xff, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x6a, 0x00, 0x00, 0x00,
    0x00, 0x04, 0xfd, 0xff, 0x00, 0x01, 0x01, 0x22, 0x07, 0xfc, 0x04, 0x74, 0x65, 0x73, 0x74, 0x00,
    0x02, 0xaa, 0xbb, 0x00, 0x03, 0xf0, 0x01, 0x00, 0x01, 0x55, 0x05, 0xfc, 0x02, 0x71, 0x6b, 0x00,
    0x01, 0x66, 0x01, 0x03, 0x04, 0x01, 0x00, 0x00, 0x00, 0x02, 0xf0, 0x01, 0x01, 0x44, 0x00, 0x01,
    0xf1, 0x01, 0x77, 0x01, 0x04, 0x01, 0x88, 0x00,
];

/// Expected canonical bytes for `SCRAMBLED_SYNTHETIC_PSBT`, hard-coded from
/// the independent temporary-script derivation described above.
const SCRAMBLED_EXPECTED_CANONICAL: &[u8] = &[
    0x70, 0x73, 0x62, 0x74, 0xff, 0x01, 0x00, 0x3d, 0x02, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff,
    0xff, 0x00, 0xfe, 0xff, 0xff, 0xff, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
    0x6a, 0x00, 0x00, 0x00, 0x00, 0x02, 0xf0, 0x01, 0x01, 0x11, 0x07, 0xfc, 0x04, 0x74, 0x65, 0x73,
    0x74, 0x00, 0x02, 0xaa, 0xbb, 0x04, 0xfd, 0xff, 0x00, 0x01, 0x01, 0x22, 0x04, 0xfd, 0x00, 0x01,
    0x01, 0x01, 0x33, 0x00, 0x01, 0x03, 0x04, 0x01, 0x00, 0x00, 0x00, 0x02, 0xf0, 0x01, 0x01, 0x44,
    0x03, 0xf0, 0x01, 0x00, 0x01, 0x55, 0x05, 0xfc, 0x02, 0x71, 0x6b, 0x00, 0x01, 0x66, 0x00, 0x01,
    0x04, 0x01, 0x88, 0x01, 0xf1, 0x01, 0x77, 0x00,
];

/// Minimal CompactSize encoding (test-local, independent of the crate).
fn compact_size(n: usize) -> Vec<u8> {
    if n < 0xfd {
        vec![n as u8]
    } else if n <= 0xffff {
        let mut v = vec![0xfd];
        v.extend_from_slice(&(n as u16).to_le_bytes());
        v
    } else {
        let mut v = vec![0xfe];
        v.extend_from_slice(&(n as u32).to_le_bytes());
        v
    }
}

/// Encode one record: key length, key-type CompactSize, key data,
/// value length, value.
fn record(key_type: u64, key_data: &[u8], value: &[u8]) -> Vec<u8> {
    let mut key = compact_size(key_type as usize);
    key.extend_from_slice(key_data);
    let mut out = compact_size(key.len());
    out.extend_from_slice(&key);
    out.extend_from_slice(&compact_size(value.len()));
    out.extend_from_slice(value);
    out
}

/// Never-fundable synthetic unsigned transaction: one null-prevout input,
/// one zero-value OP_RETURN output.
fn synthetic_tx() -> Vec<u8> {
    let mut tx = vec![0x02, 0x00, 0x00, 0x00, 0x01];
    tx.extend_from_slice(&[0u8; 32]);
    tx.extend_from_slice(&[0xff, 0xff, 0xff, 0xff, 0x00, 0xfe, 0xff, 0xff, 0xff]);
    tx.push(0x01);
    tx.extend_from_slice(&[0u8; 8]);
    tx.extend_from_slice(&[0x01, 0x6a, 0x00, 0x00, 0x00, 0x00]);
    tx
}

/// Assemble a full PSBT from encoded per-map record lists.
fn build_psbt(global: &[Vec<u8>], inputs: &[&[Vec<u8>]], outputs: &[&[Vec<u8>]]) -> Vec<u8> {
    let mut psbt = vec![0x70, 0x73, 0x62, 0x74, 0xff];
    for r in global {
        psbt.extend_from_slice(r);
    }
    psbt.push(0x00);
    for map in inputs {
        for r in *map {
            psbt.extend_from_slice(r);
        }
        psbt.push(0x00);
    }
    for map in outputs {
        for r in *map {
            psbt.extend_from_slice(r);
        }
        psbt.push(0x00);
    }
    psbt
}

/// Independent adjacent-order check for one map: every neighbouring pair
/// must be strictly ascending by (decoded numeric key type, raw key data).
fn scope_adjacent_ordered(records: Records<'_>) -> bool {
    let mut prev: Option<(u64, &[u8])> = None;
    for r in records {
        let cur = (r.key_type, r.key_data);
        if let Some(p) = prev {
            if p >= cur {
                return false;
            }
        }
        prev = Some(cur);
    }
    true
}

/// Adjacent-order proof over every map of a view.
fn all_maps_adjacent_ordered(view: &PsbtView<'_>) -> bool {
    if !scope_adjacent_ordered(view.global_records()) {
        return false;
    }
    for i in 0..view.input_map_count() {
        if !scope_adjacent_ordered(view.input_records(i).expect("input map")) {
            return false;
        }
    }
    for i in 0..view.output_map_count() {
        if !scope_adjacent_ordered(view.output_records(i).expect("output map")) {
            return false;
        }
    }
    true
}

/// Per-map multisets of (key type, complete key bytes, value bytes) in map
/// order: global, then inputs by index, then outputs by index.
fn map_multisets(view: &PsbtView<'_>) -> Vec<MapMultiset> {
    fn collect(records: Records<'_>) -> MapMultiset {
        let mut v: MapMultiset = records
            .map(|r| (r.key_type, r.full_key.to_vec(), r.value.to_vec()))
            .collect();
        v.sort();
        v
    }
    let mut maps = vec![collect(view.global_records())];
    for i in 0..view.input_map_count() {
        maps.push(collect(view.input_records(i).expect("input map")));
    }
    for i in 0..view.output_map_count() {
        maps.push(collect(view.output_records(i).expect("output map")));
    }
    maps
}

/// The 14 structurally accepted imported fixtures (10 Accept plus 4
/// SignerRejectLater).
fn accepted_fixtures() -> Vec<(&'static str, Vec<u8>)> {
    VECTORS
        .iter()
        .filter(|(_, _, v)| matches!(v, Accept | SignerRejectLater))
        .map(|(n, s, _)| (*n, b64(s)))
        .collect()
}

/// All permutations of the given encoded records.
fn permutations(items: &[Vec<u8>]) -> Vec<EncodedRecords> {
    if items.len() <= 1 {
        return vec![items.to_vec()];
    }
    let mut out = Vec::new();
    for i in 0..items.len() {
        let mut rest = items.to_vec();
        let head = rest.remove(i);
        for mut p in permutations(&rest) {
            let mut v = vec![head.clone()];
            v.append(&mut p);
            out.push(v);
        }
    }
    out
}

/// Property-test corpus: all 5! = 120 permutations of a small valid
/// synthetic record set in the input map, plus the 14 accepted fixtures.
fn property_corpus() -> Vec<Vec<u8>> {
    let tx = synthetic_tx();
    let global = vec![record(0x00, &[], &tx)];
    let out_map = vec![record(0xf1, &[], &[0x77])];
    let five = vec![
        record(0x03, &[], &[0x01, 0x00, 0x00, 0x00]),
        record(0xf0, &[0x01], &[0xaa]),
        record(0xf0, &[0x02], &[0xbb]),
        record(0xfc, &[0x02, 0x71, 0x6b, 0x00], &[0xcc]),
        record(255, &[0x01], &[0xdd]),
    ];
    let perms = permutations(&five);
    assert_eq!(perms.len(), 120, "5! permutations");
    let mut corpus: Vec<Vec<u8>> = perms
        .into_iter()
        .map(|perm| build_psbt(&global, &[&perm], &[&out_map]))
        .collect();
    corpus.extend(accepted_fixtures().into_iter().map(|(_, b)| b));
    corpus
}

#[test]
fn accepted_upstream_fixtures_are_canonical_identity_goldens() {
    let fixtures = accepted_fixtures();
    assert_eq!(fixtures.len(), 14, "10 Accept + 4 SignerRejectLater");
    for (name, bytes) in &fixtures {
        let view = parse(bytes, InputSource::MicroSd).expect("accepted fixture parses");
        assert!(
            all_maps_adjacent_ordered(&view),
            "{name}: every map must already be adjacent-ordered by (key type, key data); the identity golden is derived from this independently proven fact"
        );
        let out = canonical_serialize(&view).expect("accepted fixture serializes");
        assert_eq!(
            &out, bytes,
            "{name}: canonical serialization must reproduce the input bytes"
        );
    }
}

#[test]
fn scrambled_synthetic_psbt_serializes_to_hardcoded_canonical_bytes() {
    let view =
        parse(SCRAMBLED_SYNTHETIC_PSBT, InputSource::MicroSd).expect("scrambled fixture parses");
    // Real reordering is required in every map: none is adjacent-ordered.
    assert!(!scope_adjacent_ordered(view.global_records()));
    assert!(!scope_adjacent_ordered(
        view.input_records(0).expect("input map")
    ));
    assert!(!scope_adjacent_ordered(
        view.output_records(0).expect("output map")
    ));

    let out = canonical_serialize(&view).expect("scrambled fixture serializes");
    assert_eq!(
        out.as_slice(),
        SCRAMBLED_EXPECTED_CANONICAL,
        "canonical bytes must match the independently derived expectation"
    );
    assert_ne!(
        out.as_slice(),
        SCRAMBLED_SYNTHETIC_PSBT,
        "serialization really reordered records"
    );

    let reparsed = parse(&out, InputSource::MicroSd).expect("canonical output reparses");
    // The SIGHASH_ALL record stays byte-identical.
    let sighash: Vec<_> = reparsed
        .input_records(0)
        .expect("input map")
        .filter(|r| r.key_type == 0x03)
        .collect();
    assert_eq!(sighash.len(), 1);
    assert_eq!(sighash[0].full_key, &[0x03]);
    assert_eq!(sighash[0].value, &[0x01, 0x00, 0x00, 0x00]);
    // Numeric key-type order governs: 255 sorts before 256 even though raw
    // encoded keys would order 256 (fd 00 01) before 255 (fd ff 00).
    let global_types: Vec<u64> = reparsed.global_records().map(|r| r.key_type).collect();
    assert_eq!(global_types, vec![0x00, 0xf0, 0xfc, 255, 256]);
    // Same-type records order by key data; the shorter prefix sorts first.
    let unknown_key_data: Vec<Vec<u8>> = reparsed
        .input_records(0)
        .expect("input map")
        .filter(|r| r.key_type == 0xf0)
        .map(|r| r.key_data.to_vec())
        .collect();
    assert_eq!(unknown_key_data, vec![vec![0x01], vec![0x01, 0x00]]);
}

#[test]
fn canonical_serialization_preserves_records_maps_and_unsigned_tx() {
    fn of_type(m: &MapMultiset, key_type: u64) -> MapMultiset {
        m.iter()
            .filter(|(t, _, _)| *t == key_type)
            .cloned()
            .collect()
    }
    fn high_unknowns(m: &MapMultiset) -> MapMultiset {
        m.iter()
            .filter(|(t, _, _)| *t >= 0xf0 && *t != 0xfc)
            .cloned()
            .collect()
    }
    let mut corpus: Vec<(String, Vec<u8>)> = accepted_fixtures()
        .into_iter()
        .map(|(n, b)| (n.to_string(), b))
        .collect();
    corpus.push((
        "scrambled synthetic".to_string(),
        SCRAMBLED_SYNTHETIC_PSBT.to_vec(),
    ));
    for (name, bytes) in &corpus {
        let before = parse(bytes, InputSource::MicroSd).expect("corpus member parses");
        let out = canonical_serialize(&before).expect("corpus member serializes");
        let after = parse(&out, InputSource::MicroSd).expect("canonical output reparses");
        assert_eq!(
            before.input_map_count(),
            after.input_map_count(),
            "{name}: input map count"
        );
        assert_eq!(
            before.output_map_count(),
            after.output_map_count(),
            "{name}: output map count"
        );
        assert_eq!(
            before.unsigned_tx_bytes(),
            after.unsigned_tx_bytes(),
            "{name}: exact unsigned-tx bytes"
        );
        let (m_before, m_after) = (map_multisets(&before), map_multisets(&after));
        assert_eq!(m_before.len(), m_after.len(), "{name}: map list length");
        for (i, (a, b)) in m_before.iter().zip(m_after.iter()).enumerate() {
            assert_eq!(a.len(), b.len(), "{name}: map {i} record count");
            assert_eq!(a, b, "{name}: map {i} complete-key/value multiset");
            // Explicit unchanged-byte assertions for proprietary, SIGHASH,
            // and high-numbered unknown records (subsumed by the multiset
            // equality, asserted separately as required).
            assert_eq!(
                of_type(a, 0xfc),
                of_type(b, 0xfc),
                "{name}: map {i} proprietary bytes"
            );
            assert_eq!(
                of_type(a, 0x03),
                of_type(b, 0x03),
                "{name}: map {i} SIGHASH bytes"
            );
            assert_eq!(
                high_unknowns(a),
                high_unknowns(b),
                "{name}: map {i} unknown bytes"
            );
        }
    }
}

#[test]
fn canonical_output_length_always_equals_input_length() {
    for bytes in property_corpus() {
        let view = parse(&bytes, InputSource::MicroSd).expect("corpus member parses");
        let out = canonical_serialize(&view).expect("corpus member serializes");
        assert_eq!(out.len(), bytes.len(), "output length equals input length");
    }
}

#[test]
fn canonical_output_is_a_fixed_point_of_parse_then_serialize() {
    for bytes in property_corpus() {
        let view = parse(&bytes, InputSource::MicroSd).expect("corpus member parses");
        let once = canonical_serialize(&view).expect("first serialization");
        let reparsed = parse(&once, InputSource::MicroSd).expect("canonical output reparses");
        let twice = canonical_serialize(&reparsed).expect("second serialization");
        assert_eq!(
            once, twice,
            "parse -> serialize is a fixed point on canonical bytes"
        );
    }
}

#[test]
fn compact_size_boundaries_empty_maps_and_full_descending_map() {
    let tx = synthetic_tx();
    let global = vec![record(0x00, &[], &tx)];
    let out_map = vec![record(0xf1, &[], &[0x77])];

    // Accepted length boundaries, built already canonical so identity is
    // the expected outcome: value lengths 252 (largest one-byte
    // CompactSize), 253 (smallest fd form), and 65536 (smallest fe form),
    // plus a complete key of exactly 128 bytes (one-byte length 0x80).
    let long_key_data = [0x42u8; 127];
    let boundary_map = vec![
        record(0xf0, &[0x01], &[0x11; 252]),
        record(0xf0, &[0x02], &[0x22; 253]),
        record(0xf0, &[0x03], &[0x33; 65536]),
        record(0xf5, &long_key_data, &[0x44]),
    ];
    let bytes = build_psbt(&global, &[&boundary_map], &[&out_map]);
    let view = parse(&bytes, InputSource::MicroSd).expect("boundary fixture parses");
    let out = canonical_serialize(&view).expect("boundary fixture serializes");
    assert_eq!(
        out, bytes,
        "already-canonical boundary fixture round-trips to identity"
    );

    // Empty input and output maps: separators only.
    let empty: Vec<Vec<u8>> = Vec::new();
    let bytes = build_psbt(&global, &[&empty], &[&empty]);
    let view = parse(&bytes, InputSource::MicroSd).expect("empty-maps fixture parses");
    let out = canonical_serialize(&view).expect("empty-maps fixture serializes");
    assert_eq!(out, bytes, "empty maps round-trip to identity");

    // A completely full input map (MAX_RECORDS_PER_MAP records) inserted in
    // strictly descending key-type order must reorder to ascending.
    let descending: Vec<Vec<u8>> = (0..qk_psbt::limits::MAX_RECORDS_PER_MAP)
        .rev()
        .map(|i| record(0x19 + i as u64, &[], &[0x55]))
        .collect();
    let bytes = build_psbt(&global, &[&descending], &[&out_map]);
    let view = parse(&bytes, InputSource::MicroSd).expect("descending fixture parses");
    assert!(
        !scope_adjacent_ordered(view.input_records(0).expect("input map")),
        "descending map starts unordered"
    );
    let out = canonical_serialize(&view).expect("descending fixture serializes");
    assert_eq!(
        out.len(),
        bytes.len(),
        "length preserved under full-map reordering"
    );
    let reparsed = parse(&out, InputSource::MicroSd).expect("reordered output reparses");
    let types: Vec<u64> = reparsed
        .input_records(0)
        .expect("input map")
        .map(|r| r.key_type)
        .collect();
    let ascending: Vec<u64> = (0..qk_psbt::limits::MAX_RECORDS_PER_MAP)
        .map(|i| 0x19 + i as u64)
        .collect();
    assert_eq!(
        types, ascending,
        "all records ascending after canonicalization"
    );
}
