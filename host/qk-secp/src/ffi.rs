//! The single FFI boundary module (QK-DEC-042).
//!
//! HOST SCAFFOLD ONLY — NOT PRODUCT CODE — NOT A WALLET — NO TARGET CLAIM.
//!
//! This is the only module in the crate that may contain the unsafe
//! keyword. It declares the immutable static context object and the
//! original five verification functions, QK-DEC-111's exact six
//! signing additions and explicit RFC6979 nonce pointer, plus
//! QK-DEC-113's exact two provisioning-derivation calls. The
//! unmodified native archive contains
//! other dormant base symbols; none are declared or callable here.
//! Upstream default abort callbacks are retained as defense in depth;
//! the fixed-size inputs and prechecks below make illegal-argument
//! callbacks unreachable. Opaque C objects never escape this crate.
//! Return codes are passed through raw to the caller, which maps every
//! 0/1 and fails closed on any other code.

#![allow(unsafe_code)]
#![deny(unsafe_op_in_unsafe_fn)]

use core::ffi::{c_int, c_uchar, c_uint, c_void};
use core::mem::MaybeUninit;
use core::ptr;
use core::sync::atomic::{compiler_fence, Ordering};

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
/// Upstream `SECP256K1_CONTEXT_NONE` flag value.
const CONTEXT_NONE: c_uint = 1;

/// Exact upstream RFC6979 nonce callback ABI.
type NonceFunction = unsafe extern "C" fn(
    nonce32: *mut c_uchar,
    msg32: *const c_uchar,
    key32: *const c_uchar,
    algo16: *const c_uchar,
    data: *mut c_void,
    attempt: c_uint,
) -> c_int;

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
    static secp256k1_nonce_function_rfc6979: NonceFunction;
    fn secp256k1_context_create(flags: c_uint) -> *mut RawContext;
    fn secp256k1_context_destroy(ctx: *mut RawContext);
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
    fn secp256k1_ec_pubkey_create(
        ctx: *const RawContext,
        pubkey: *mut RawPubkey,
        seckey: *const c_uchar,
    ) -> c_int;
    fn secp256k1_ec_seckey_tweak_add(
        ctx: *const RawContext,
        seckey: *mut c_uchar,
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
    fn secp256k1_ec_seckey_verify(ctx: *const RawContext, seckey: *const c_uchar) -> c_int;
    fn secp256k1_ecdsa_sign(
        ctx: *const RawContext,
        sig: *mut RawSignature,
        msghash32: *const c_uchar,
        seckey: *const c_uchar,
        noncefp: NonceFunction,
        ndata: *const c_void,
    ) -> c_int;
    fn secp256k1_ecdsa_signature_normalize(
        ctx: *const RawContext,
        sigout: *mut RawSignature,
        sigin: *const RawSignature,
    ) -> c_int;
    fn secp256k1_ecdsa_signature_serialize_der(
        ctx: *const RawContext,
        output: *mut c_uchar,
        outputlen: *mut usize,
        sig: *const RawSignature,
    ) -> c_int;
}

/// RAII owner for one non-static native signing or provisioning context.
struct OwnedContext {
    raw: *mut RawContext,
}

impl OwnedContext {
    fn create() -> Option<Self> {
        // SAFETY: CONTEXT_NONE is the exact valid upstream flag. A
        // non-null result is uniquely owned until Drop.
        let raw = unsafe { secp256k1_context_create(CONTEXT_NONE) };
        if raw.is_null() {
            None
        } else {
            Some(Self { raw })
        }
    }
}

impl Drop for OwnedContext {
    fn drop(&mut self) {
        // SAFETY: raw is non-null and came from exactly one successful
        // context_create call; this owner is non-Clone and drops once.
        unsafe { secp256k1_context_destroy(self.raw) };
    }
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

/// Create one public key from a fixed provisioning scalar through a
/// freshly created non-static context. Returns `None` only when the
/// context cannot be obtained, otherwise the raw status and an opaque
/// object that is zeroed on ordinary rejection.
pub(crate) fn provisioning_pubkey_create(
    secret: &[u8; SCALAR_BYTES],
) -> Option<(c_int, [u8; PUBKEY_OBJ_BYTES])> {
    let owned_context = OwnedContext::create()?;
    let mut obj = MaybeUninit::<RawPubkey>::uninit();
    // SAFETY: the context is non-static and uniquely live; obj is a
    // valid out-pointer; secret is one live fixed-size scalar buffer;
    // the native call does not retain either pointer.
    let code =
        unsafe { secp256k1_ec_pubkey_create(owned_context.raw, obj.as_mut_ptr(), secret.as_ptr()) };
    if code == 1 {
        // SAFETY: upstream initializes the public key exactly on code 1.
        Some((code, unsafe { obj.assume_init() }.data))
    } else {
        Some((code, [0u8; PUBKEY_OBJ_BYTES]))
    }
}

/// Add one tweak to a fixed provisioning scalar using a private scratch
/// copy. `candidate` receives bytes only on ordinary success. The scratch
/// buffer is volatile-wiped after every native return, including success.
pub(crate) fn provisioning_secret_tweak_add(
    parent: &[u8; SCALAR_BYTES],
    tweak: &[u8; SCALAR_BYTES],
    candidate: &mut [u8; SCALAR_BYTES],
) -> Option<c_int> {
    let owned_context = OwnedContext::create()?;
    let mut scratch = *parent;
    // SAFETY: the context is non-static and uniquely live; scratch is one uniquely owned live
    // fixed-size in/out buffer; tweak is a live fixed-size input; the
    // native call retains neither pointer. Upstream may invalidate scratch
    // on rejection, so it is never copied unless the status is exactly 1.
    let code = unsafe {
        secp256k1_ec_seckey_tweak_add(owned_context.raw, scratch.as_mut_ptr(), tweak.as_ptr())
    };
    if code == 1 {
        candidate.copy_from_slice(&scratch);
    }
    wipe_secret(&mut scratch);
    Some(code)
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

/// Validate one fixed secret scalar through the static context.
pub(crate) fn secret_key_verify(secret: &[u8; SCALAR_BYTES]) -> c_int {
    // SAFETY: context is immutable and secret is one live fixed-size
    // buffer. Upstream permits secret-key validation on the static
    // context and does not retain the input pointer.
    unsafe { secp256k1_ec_seckey_verify(context(), secret.as_ptr()) }
}

/// Sign through one freshly created non-static context using the
/// explicit pinned RFC6979 function and null additional data.
pub(crate) fn ecdsa_sign_rfc6979(
    secret: &[u8; SCALAR_BYTES],
    digest: &[u8; SCALAR_BYTES],
) -> Option<(c_int, [u8; SIG_OBJ_BYTES])> {
    let signing_context = OwnedContext::create()?;
    let mut obj = MaybeUninit::<RawSignature>::uninit();
    // SAFETY: the context is non-static and uniquely live; obj is a
    // valid out-pointer; digest and secret are fixed-size live
    // buffers; the nonce callback is the pinned upstream function;
    // additional nonce data is deliberately null.
    let code = unsafe {
        secp256k1_ecdsa_sign(
            signing_context.raw,
            obj.as_mut_ptr(),
            digest.as_ptr(),
            secret.as_ptr(),
            secp256k1_nonce_function_rfc6979,
            ptr::null(),
        )
    };
    if code == 1 {
        // SAFETY: upstream initializes the signature exactly on code 1.
        Some((code, unsafe { obj.assume_init() }.data))
    } else {
        Some((code, [0u8; SIG_OBJ_BYTES]))
    }
}

/// Normalize an opaque signature. Return zero means it was already
/// low-S; one means the output was changed to low-S.
pub(crate) fn signature_normalize(obj: &[u8; SIG_OBJ_BYTES]) -> (c_int, [u8; SIG_OBJ_BYTES]) {
    let input = RawSignature { data: *obj };
    let mut output = RawSignature {
        data: [0u8; SIG_OBJ_BYTES],
    };
    // SAFETY: context is immutable and both opaque objects are valid
    // fixed-size signature representations.
    let code = unsafe { secp256k1_ecdsa_signature_normalize(context(), &mut output, &input) };
    (code, output.data)
}

/// Serialize an opaque signature into a fixed 72-byte DER container.
pub(crate) fn signature_serialize_der(obj: &[u8; SIG_OBJ_BYTES]) -> (c_int, usize, [u8; 72]) {
    let signature = RawSignature { data: *obj };
    let mut output = [0u8; 72];
    let mut outputlen = output.len();
    // SAFETY: context is immutable; output/outputlen form one valid
    // bounded destination; signature is a valid opaque object copy.
    let code = unsafe {
        secp256k1_ecdsa_signature_serialize_der(
            context(),
            output.as_mut_ptr(),
            &mut outputlen,
            &signature,
        )
    };
    (code, outputlen, output)
}

/// Volatile wipe for the sole safe-wrapper secret owner and its import
/// source. The fence prevents reordering across the completed wipe.
pub(crate) fn wipe_secret(secret: &mut [u8; SCALAR_BYTES]) {
    for byte in secret {
        // SAFETY: byte is a uniquely borrowed live byte. Volatile
        // writes make the clearing operation observable to the
        // abstract machine and prevent dead-store elimination.
        unsafe { ptr::write_volatile(byte, 0) };
    }
    compiler_fence(Ordering::SeqCst);
}

#[cfg(test)]
mod tests {
    use super::{context, wipe_secret, RawContext, RawPubkey, RawSignature};
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

    #[test]
    fn volatile_wipe_clears_every_byte() {
        let mut secret = [0xa5u8; 32];
        wipe_secret(&mut secret);
        assert_eq!(secret, [0u8; 32]);
    }
}
