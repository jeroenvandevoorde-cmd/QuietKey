//! Volatile protocol owners and encoder scratch clear on every exit path.

#[cfg(feature = "fuzzing")]
mod qualification {
    use std::panic::{catch_unwind, AssertUnwindSafe};

    use qk_card_protocol::{
        encode_open_session, encode_sign_digest, reset_wiped_bytes, wiped_bytes, CommandRef,
        EnvelopeRef, Mode, ProtocolError, ResponseRef, SessionTracker, SignRequest,
        MAX_REQUEST_BYTES,
    };

    const SESSION: [u8; 16] = [0x11; 16];
    const WALLET: [u8; 32] = [0x22; 32];
    const REVIEW: [u8; 32] = [0x33; 32];
    const DIGEST: [u8; 32] = [0x44; 32];
    const PUBLIC_KEY: [u8; 33] = [0x02; 33];
    const DER: [u8; 8] = [0x30, 6, 2, 1, 1, 2, 1, 1];

    fn sign(
        sequence: u32,
        wallet_id: &'static [u8; 32],
        review_hash: &'static [u8; 32],
    ) -> CommandRef<'static> {
        CommandRef::SignDigest {
            envelope: EnvelopeRef::new(&SESSION, sequence),
            wallet_id,
            review_hash,
            input_index: sequence,
            branch: 0,
            child_index: 0,
            digest: &DIGEST,
        }
    }

    #[test]
    fn encoder_scratch_wipes_on_success_and_error() {
        let mut output = [0u8; MAX_REQUEST_BYTES];
        reset_wiped_bytes();
        encode_open_session(Mode::Normal, &SESSION, &mut output).expect("OPEN encoding");
        assert_eq!(wiped_bytes(), 18);

        reset_wiped_bytes();
        encode_sign_digest(
            EnvelopeRef::new(&SESSION, 1),
            SignRequest {
                wallet_id: &WALLET,
                review_hash: &REVIEW,
                input_index: 0,
                branch: 0,
                child_index: 0,
                digest: &DIGEST,
            },
            &mut output,
        )
        .expect("SIGN encoding");
        assert_eq!(wiped_bytes(), 105 + 215);

        reset_wiped_bytes();
        let mut short = [0u8; 1];
        assert!(encode_sign_digest(
            EnvelopeRef::new(&SESSION, 1),
            SignRequest {
                wallet_id: &WALLET,
                review_hash: &REVIEW,
                input_index: 0,
                branch: 0,
                child_index: 0,
                digest: &DIGEST,
            },
            &mut short,
        )
        .is_err());
        assert_eq!(wiped_bytes(), 105 + 215);
    }

    #[test]
    fn session_material_wipes_on_named_rejection_drop_and_unwind() {
        static OTHER_WALLET: [u8; 32] = [0x99; 32];
        reset_wiped_bytes();
        let mut tracker = SessionTracker::new(Mode::Normal, &SESSION, 24, 23).expect("session");
        tracker
            .begin_exchange(sign(1, &WALLET, &REVIEW), 132)
            .expect("first SIGN");
        tracker
            .finish_success(
                ResponseRef::SignDigest {
                    envelope: EnvelopeRef::new(&SESSION, 1),
                    review_hash: &REVIEW,
                    input_index: 1,
                    public_key: &PUBLIC_KEY,
                    signature_der: &DER,
                },
                101,
            )
            .expect("SIGN response");
        assert_eq!(
            tracker.begin_exchange(sign(2, &OTHER_WALLET, &REVIEW), 132),
            Err(ProtocolError::SigningBindingRejected)
        );
        assert_eq!(wiped_bytes(), 16 + 32 + 32);
        drop(tracker);
        assert_eq!(wiped_bytes(), 16 + 32 + 32);

        reset_wiped_bytes();
        let outcome = catch_unwind(AssertUnwindSafe(|| {
            let _tracker = SessionTracker::new(Mode::Normal, &SESSION, 24, 23).expect("session");
            panic!("qualification unwind");
        }));
        assert!(outcome.is_err());
        assert_eq!(wiped_bytes(), 16 + 32 + 32);
    }
}

#[cfg(not(feature = "fuzzing"))]
#[test]
fn wipe_instrumentation_is_not_in_the_default_surface() {
    assert!(!cfg!(feature = "fuzzing"));
}
