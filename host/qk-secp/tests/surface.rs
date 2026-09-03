//! Surface pin for the purpose-bound card-signature normalization seam.

const CARGO_SRC: &str = include_str!("../Cargo.toml");
const LIB_SRC: &str = include_str!("../src/lib.rs");

#[test]
fn card_signature_normalization_feature_is_non_default_and_dependency_free() {
    assert!(CARGO_SRC.contains("[features]\ndefault = []\ncard-signature-normalization = []"));
    assert!(!CARGO_SRC.contains("[dependencies]"));
}

#[test]
fn card_signature_normalization_surface_is_exactly_feature_gated() {
    let marker =
        "#[cfg(feature = \"card-signature-normalization\")]\npub fn normalize_card_signature_der(";
    assert_eq!(LIB_SRC.matches(marker).count(), 1);
    assert_eq!(
        LIB_SRC
            .matches("pub fn normalize_card_signature_der")
            .count(),
        1
    );
    assert!(LIB_SRC
        .contains("input: &[u8],\n    output: &mut [u8; 72],\n) -> Result<usize, SecpError>"));
}

#[cfg(feature = "card-signature-normalization")]
#[test]
fn enabled_surface_has_the_pinned_external_type() {
    let _: fn(&[u8], &mut [u8; 72]) -> Result<usize, qk_secp::SecpError> =
        qk_secp::normalize_card_signature_der;
}
