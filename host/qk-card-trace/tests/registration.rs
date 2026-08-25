use qk_card_trace::{assert_complete_assertion_set, Assertion};

const REGISTER: &str = include_str!("../../../docs/f8/RUN-REGISTER.md");

#[test]
fn register_contains_exactly_one_packet_for_each_assertion() {
    assert_eq!(assert_complete_assertion_set(&Assertion::ALL), Ok(()));
    for (letter, key) in [
        ('A', 'a'),
        ('B', 'b'),
        ('C', 'c'),
        ('D', 'd'),
        ('E', 'e'),
        ('F', 'f'),
        ('G', 'g'),
    ] {
        let heading = format!("## QK-F8R-{letter}-001 - assertion ({key})");
        assert_eq!(REGISTER.matches(&heading).count(), 1, "{heading}");
    }
    assert_eq!(REGISTER.matches("## QK-F8R-").count(), 7);
}

#[test]
fn every_packet_is_explicitly_not_run() {
    assert_eq!(REGISTER.matches("- Status: `BLOCKED -").count(), 7);
    assert_eq!(REGISTER.matches("- NOT RUN`.").count(), 7);
    assert!(REGISTER.contains("the specimen and apparatus ledgers are empty"));
    assert!(REGISTER.contains("the live APDU allowlist is empty"));
}

#[test]
fn one_to_one_f2_alignment_is_pinned() {
    for expected in [
        "QK-TST-BENCH-002(a); QK-F2E-004",
        "QK-TST-BENCH-002(b); QK-F2E-011",
        "QK-TST-BENCH-002(c); QK-F2E-012",
        "QK-TST-BENCH-002(d); QK-F2E-003",
        "QK-TST-BENCH-002(e); QK-F2E-005",
        "QK-TST-BENCH-002(f); QK-F2E-014",
        "QK-TST-BENCH-002(g); QK-F2E-013",
    ] {
        assert_eq!(REGISTER.matches(expected).count(), 1, "{expected}");
    }
}

#[test]
fn g_packet_contains_the_ratified_expansion() {
    for required in [
        "distinct\n  externally derived account signing authorities",
        "fixed B/C roles",
        "byte-identical A2 and D",
        "D/`wallet_id`, path, policy",
        "lifecycle and normal-operation private-key non-exportability",
        "QK-TST-BENCH-005",
    ] {
        assert!(REGISTER.contains(required), "{required}");
    }
}

#[test]
fn raw_artifact_names_and_hash_custody_are_pinned_without_a_hash_tool_default() {
    assert!(REGISTER.contains("f8-<run-id>__<specimen-alias>__<utc>__<artifact-kind>.<ext>"));
    assert!(REGISTER.contains("qk-card-trace-v1__<run-id>__<specimen-alias>__<utc>.txt"));
    assert!(REGISTER.contains("chooses no live format or evidence-tool default"));
}
