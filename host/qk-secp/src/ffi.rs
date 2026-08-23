//! The single FFI boundary module (QK-DEC-042).
//!
//! HOST SCAFFOLD ONLY — NOT PRODUCT CODE — NOT A WALLET — NO TARGET CLAIM.
//!
//! This is the only module in the crate that may contain the unsafe
//! keyword. It declares the immutable static context object and
//! exactly five upstream functions — the ratified Rust-declared and
//! callable wrapper surface. The unmodified native archive contains
//! other dormant base symbols; none are declared or callable here.
//! Upstream default abort callbacks are retained as defense in depth;
//! the fixed-size inputs and prechecks below make illegal-argument
//! callbacks unreachable. Opaque C objects never escape this crate.
//! Return codes are passed through raw to the caller, which maps every
//! 0/1 and fails closed on any other code.

#![allow(unsafe_code)]
#![deny(unsafe_op_in_unsafe_fn)]

use core::ffi::{c_int, c_uchar, c_uint};
use core::mem::MaybeUninit;

/// Byte size of the opaque public-key object.
pub(crate) const PUBKEY_OBJ_BYTES: usize = 64;
/// Byte size of the opaque signature object.
pub(crate) const SIG_OBJ_BYTES: usize = 64;
/// Compressed public-key serialization length.
pub(crate) const COMPRESSED_PUBKEY_BYTES: usize = 33;
/// Message digest and tweak length.
pub(crate) const SCALAR_BYTES: usize = 32;
/// Upstream compressed-serialization flag value (258).
const FLAG_COMPRESSED: c_uint = 258;

/// Opaque upstream context type; never instantiated from Rust.
#[repr(C)]
pub(crate) struct RawContext {
    _opaque: [u8; 0],
}

/// Opaque 64-byte upstream public-key object.
#[repr(C)]
pub(crate) struct RawPubkey {
    pub(crate) data: [u8; PUBKEY_OBJ_BYTES],
}

/// Opaque 64-byte upstream signature object.
#[repr(C)]
pub(crate) struct RawSignature {
    pub(crate) data: [u8; SIG_OBJ_BYTES],
}

extern "C" {
    static secp256k1_context_static: *const RawContext;
    fn secp256k1_ec_pubkey_parse(
        ctx: *const RawContext,
        pubkey: *mut RawPubkey,
        input: *const c_uchar,
        inputlen: usize,
    ) -> c_int;
    fn secp256k1_ec_pubkey_serialize(
        ctx: *const RawContext,
        output: *mut c_uchar,
        outputlen: *mut usize,
        pubkey: *const RawPubkey,
        flags: c_uint,
    ) -> c_int;
    fn secp256k1_ec_pubkey_tweak_add(
        ctx: *const RawContext,
        pubkey: *mut RawPubkey,
        tweak32: *const c_uchar,
    ) -> c_int;
    fn secp256k1_ecdsa_signature_parse_der(
        ctx: *const RawContext,
        sig: *mut RawSignature,
        input: *const c_uchar,
        inputlen: usize,
    ) -> c_int;
    fn secp256k1_ecdsa_verify(
        ctx: *const RawContext,
        sig: *const RawSignature,
        msghash32: *const c_uchar,
        pubkey: *const RawPubkey,
    ) -> c_int;
}

/// The one static verification-only context.
fn context() -> *const RawContext {
    // SAFETY: reading an immutable extern static pointer installed by
    // the linked archive; it is never written from Rust.
    unsafe { secp256k1_context_static }
}

/// Parse a fixed 33-byte compressed public key. Returns the raw code
/// and, on code 1, the initialized opaque object; zeroed otherwise.
pub(crate) fn pubkey_parse(
    input: &[u8; COMPRESSED_PUBKEY_BYTES],
) -> (c_int, [u8; PUBKEY_OBJ_BYTES]) {
    let mut obj = MaybeUninit::<RawPubkey>::uninit();
    // SAFETY: context is the immutable static; obj is a valid
    // uniquely-owned out-pointer; input is a valid fixed-size buffer
    // whose exact length is passed.
    let code = unsafe {
        secp256k1_ec_pubkey_parse(context(), obj.as_mut_ptr(), input.as_ptr(), input.len())
    };
    if code == 1 {
        // SAFETY: upstream initializes the object exactly when it
        // returns 1.
        (code, unsafe { obj.assume_init() }.data)
    } else {
        (code, [0u8; PUBKEY_OBJ_BYTES])
    }
}

/// Serialize an opaque public-key object with the compressed flag
/// (258) and out-length 33. Returns the raw code, the written length,
/// and the buffer.
pub(crate) fn pubkey_serialize_compressed(
    obj: &[u8; PUBKEY_OBJ_BYTES],
) -> (c_int, usize, [u8; COMPRESSED_PUBKEY_BYTES]) {
    let raw = RawPubkey { data: *obj };
    let mut out = [0u8; COMPRESSED_PUBKEY_BYTES];
    let mut outlen: usize = COMPRESSED_PUBKEY_BYTES;
    // SAFETY: context is the immutable static; out/outlen are valid
    // uniquely-owned pointers with outlen preset to the buffer size;
    // raw is a valid object copy.
    let code = unsafe {
        secp256k1_ec_pubkey_serialize(
            context(),
            out.as_mut_ptr(),
            &mut outlen,
            &raw,
            FLAG_COMPRESSED,
        )
    };
    (code, outlen, out)
}

/// Tweak-add an opaque public-key object by a fixed 32-byte tweak.
/// Returns the raw code and, on code 1, the resulting object; zeroed
/// otherwise (fail closed, never the upstream-invalidated buffer).
pub(crate) fn pubkey_tweak_add(
    obj: &[u8; PUBKEY_OBJ_BYTES],
    tweak: &[u8; SCALAR_BYTES],
) -> (c_int, [u8; PUBKEY_OBJ_BYTES]) {
    let mut raw = RawPubkey { data: *obj };
    // SAFETY: context is the immutable static; raw is a valid
    // uniquely-owned in/out object copy; tweak is a valid fixed-size
    // buffer.
    let code = unsafe { secp256k1_ec_pubkey_tweak_add(context(), &mut raw, tweak.as_ptr()) };
    if code == 1 {
        (code, raw.data)
    } else {
        (code, [0u8; PUBKEY_OBJ_BYTES])
    }
}

/// Parse a bounded DER signature slice (caller enforces 8..=72 bytes).
/// Returns the raw code and, on code 1, the opaque object; zeroed
/// otherwise.
pub(crate) fn signature_parse_der(input: &[u8]) -> (c_int, [u8; SIG_OBJ_BYTES]) {
    let mut obj = MaybeUninit::<RawSignature>::uninit();
    // SAFETY: context is the immutable static; obj is a valid
    // uniquely-owned out-pointer; input pointer and exact length come
    // from one live slice.
    let code = unsafe {
        secp256k1_ecdsa_signature_parse_der(
            context(),
            obj.as_mut_ptr(),
            input.as_ptr(),
            input.len(),
        )
    };
    if code == 1 {
        // SAFETY: upstream initializes the object exactly when it
        // returns 1.
        (code, unsafe { obj.assume_init() }.data)
    } else {
        (code, [0u8; SIG_OBJ_BYTES])
    }
}

/// Verify an opaque signature object over a 32-byte digest against an
/// opaque public-key object. Returns the raw code.
pub(crate) fn ecdsa_verify(
    sig: &[u8; SIG_OBJ_BYTES],
    digest: &[u8; SCALAR_BYTES],
    key: &[u8; PUBKEY_OBJ_BYTES],
) -> c_int {
    let raw_sig = RawSignature { data: *sig };
    let raw_key = RawPubkey { data: *key };
    // SAFETY: context is the immutable static; all three arguments are
    // valid fixed-size objects owned by this frame.
    unsafe { secp256k1_ecdsa_verify(context(), &raw_sig, digest.as_ptr(), &raw_key) }
}

#[cfg(test)]
mod tests {
    use super::{context, RawContext, RawPubkey, RawSignature};
    use core::ffi::c_int;
    use core::mem::{align_of, size_of};

    #[test]
    fn abi_sizes_and_alignments() {
        assert_eq!(size_of::<RawPubkey>(), 64);
        assert_eq!(size_of::<RawSignature>(), 64);
        assert_eq!(align_of::<RawPubkey>(), 1);
        assert_eq!(align_of::<RawSignature>(), 1);
        assert_eq!(size_of::<c_int>(), 4);
        assert_eq!(size_of::<*const RawContext>(), size_of::<usize>());
    }

    #[test]
    fn static_context_is_present() {
        assert!(!context().is_null());
    }
}
