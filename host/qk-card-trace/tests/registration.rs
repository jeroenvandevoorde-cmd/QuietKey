use qk_card_trace::{assert_complete_assertion_set, Assertion};

const REGISTER: &str = include_str!("../../../docs/f8/RUN-REGISTER.md");
const EXECUTION_PACKETS: &str = include_str!("../../../docs/f8/EXECUTION-PACKETS.md");
const ARRIVAL_ALLOWLIST_DRAFT: &str = include_str!("../../../docs/f8/ARRIVAL-ALLOWLIST-DRAFT.md");
const ACTIVE_ALLOWLIST: &str = include_str!("../../../docs/f8/NONMUTATING-ALLOWLIST.md");
const ACTIVE_ALLOWLIST_SOURCE: &str = include_str!("../src/allowlist.rs");

fn assert_markdown_table_has_no_data_rows(source: &str, header: &str, terminator: &str) {
    assert_eq!(
        source.matches(header).count(),
        1,
        "table header is not unique"
    );
    assert_eq!(
        source.matches(terminator).count(),
        1,
        "table terminator is not unique"
    );
    let (_, after_header) = source
        .split_once(header)
        .unwrap_or_else(|| panic!("missing table header: {header}"));
    let (table, _) = after_header
        .split_once(terminator)
        .unwrap_or_else(|| panic!("missing table terminator: {terminator}"));
    let rows: Vec<_> = table
        .lines()
        .map(str::trim)
        .filter(|line| line.starts_with('|'))
        .collect();
    assert_eq!(
        rows.len(),
        1,
        "table contains a candidate data row: {rows:?}"
    );
    assert!(
        rows[0].starts_with("|---"),
        "table separator is malformed: {}",
        rows[0]
    );
}

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
        "required role-B card carry only the ratified signer-B,\n  A2, D and binding payload; does any optional spare created during original\n  setup carry the same payload byte-for-byte; and are Card-C and post-setup\n  second-card paths absent or rejected?",
        "rejected wrong-role, mixed-wallet,\n  wrong-path/policy, precommit and post-setup second-card requests",
        "normal-operation read path for signer-private bytes",
        "optional-spare equivalence,\n  binding, path, lifecycle and prohibited-interface results",
        "replacement-card test requires a separate Kit-Restore registration and\n  the user's external possession confirmation",
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

#[test]
fn execution_packets_cover_the_seven_registered_assertions_once() {
    for (letter, key) in [
        ('A', 'a'),
        ('B', 'b'),
        ('C', 'c'),
        ('D', 'd'),
        ('E', 'e'),
        ('F', 'f'),
        ('G', 'g'),
    ] {
        let heading = format!("## Packet {letter} - QK-F8R-{letter}-001 / QK-TST-BENCH-002({key})");
        assert_eq!(EXECUTION_PACKETS.matches(&heading).count(), 1, "{heading}");
    }
    assert_eq!(EXECUTION_PACKETS.matches("## Packet ").count(), 7);
    assert_eq!(EXECUTION_PACKETS.matches("| Packet state |").count(), 7);
    assert_eq!(EXECUTION_PACKETS.matches("- NOT RUN`").count(), 7);
    assert!(EXECUTION_PACKETS.contains("OWNER INPUT REQUIRED - NOT ACTIVE"));
}

#[test]
fn arrival_allowlist_draft_cannot_activate_or_authorize_a_command() {
    for required in [
        "DRAFT - NOT ACTIVE - ZERO APDU COMMANDS AUTHORIZED",
        "QK-F8-G0-EMPTY-V1",
        "NONE - ZERO DRAFT APDU COMMANDS; ZERO ACTIVE APDU COMMANDS.",
        "No command byte, AID, response, status word, size, timeout, repetition or",
        "Code table and tests change in the same bounded activation range.",
    ] {
        assert!(ARRIVAL_ALLOWLIST_DRAFT.contains(required), "{required}");
    }
    assert_markdown_table_has_no_data_rows(
        ARRIVAL_ALLOWLIST_DRAFT,
        "| Order | Exact command bytes or bounded mask | Command/data length rule | Purpose | Allowed lifecycle/session position | Exact expected response shape | Allowed status words | Per-command repetitions | Timing capture | Stop condition | Source ID/hash | Status |",
        "NONE - ZERO DRAFT APDU COMMANDS; ZERO ACTIVE APDU COMMANDS.",
    );
    assert_markdown_table_has_no_data_rows(
        ACTIVE_ALLOWLIST,
        "| Order | Command bytes or exact mask | Purpose | Permitted response |",
        "NONE - ZERO LIVE APDU COMMANDS ARE APPROVED.",
    );
    assert!(ACTIVE_ALLOWLIST.contains("## Registration QK-F8-G0-EMPTY-V1"));
    assert!(ACTIVE_ALLOWLIST.contains("NONE - ZERO LIVE APDU COMMANDS ARE APPROVED."));
    assert!(ACTIVE_ALLOWLIST_SOURCE.contains("const LIVE_APDU_ALLOWLIST: [&[u8]; 0] = [];"));
}
