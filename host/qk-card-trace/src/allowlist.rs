//! Closed live APDU allowlist for F8-G0.

/// No live APDU command is ratified by QK-DEC-105.
///
/// ATR capture and protocol negotiation are transport observations, not
/// APDU commands. A later nonempty list requires a separate Owner-ratified
/// registration and an explicit source change.
const LIVE_APDU_ALLOWLIST: [&[u8]; 0] = [];

pub(crate) fn live_mode_registered() -> bool {
    !LIVE_APDU_ALLOWLIST.is_empty()
}

#[cfg(test)]
mod tests {
    use super::live_mode_registered;

    #[test]
    fn live_allowlist_is_empty_and_default_deny() {
        assert!(!live_mode_registered());
    }
}
