//! HOST-only synthetic structural integration of the `qk-psbt`
//! structural parser with the `qk-host-sim` transaction workflow
//! runner.
//!
//! HOST SCAFFOLD ONLY — NOT PRODUCT CODE — NOT A WALLET — NO TARGET
//! CLAIM. Scope: see the canonical scope disclaimer in
//! `qk_host_model::transaction_policy`. This is synthetic structural
//! integration, not product validation: it proves parser-to-model
//! WIRING plus cycle/order provenance only. Parse success maps only
//! to the existing symbolic `ValidationPassed` assertion; the
//! test-local review is built from parser-proven STRUCTURAL facts
//! only — never amounts, prevouts, addresses, ownership, change,
//! fees, sighash, signatures, witness equality, or any other
//! semantics. Review equality here is structural and test-local; the
//! runner-minted cycle token binds symbolic order only — it does NOT
//! bind transaction bytes and does NOT constitute D-09/canonical
//! review equality, which remains open (changed-but-still-parseable
//! bytes are deliberately not rejected here). `SignatureProduced`,
//! `SignatureVerified`, and `OutputReparsed` are never emitted.

use qk_host_model::transaction_policy::{TransactionEvent, TransactionState};
use qk_host_sim::{ApplyOutcome, TransactionWorkflow, WorkflowEvent, WorkflowRejection};
use qk_psbt::{parse, InputSource, PsbtView, RejectCategory, Span};

/// Inline first-party 72-byte PSBT: one null-outpoint /
/// empty-scriptSig input, one zero-value OP_RETURN output, no
/// UTXO/key/signature material — deliberately never-fundable
/// synthetic test material.
const FIXTURE: [u8; 72] = [
    0x70, 0x73, 0x62, 0x74, 0xff, // magic "psbt\xff"
    0x01, 0x00, 0x3d, // global record: key len 1, type 0x00, value len 61
    0x02, 0x00, 0x00, 0x00, // tx version 2
    0x01, // one input
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // null prevout txid
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, //
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, //
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, //
    0xff, 0xff, 0xff, 0xff, // null prevout index
    0x00, // empty scriptSig
    0xfe, 0xff, 0xff, 0xff, // sequence
    0x01, // one output
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // zero amount
    0x01, 0x6a, // one-byte OP_RETURN scriptPubKey
    0x00, 0x00, 0x00, 0x00, // locktime
    0x00, // global map separator
    0x00, // empty input map
    0x00, // empty output map
];

/// Test-local bounded review built ONLY from parser-proven structural
/// facts. Its equality is structural and test-local; it is NOT the
/// open D-09/canonical review-binding equality.
#[derive(Debug, Clone, PartialEq, Eq)]
struct SyntheticStructuralReview {
    source: InputSource,
    total_bytes: usize,
    unsigned_tx_span: Span,
    unsigned_tx_len: usize,
    input_count: usize,
    output_count: usize,
    global_map_span: Span,
    global_record_count: usize,
    input_maps: Vec<(Span, usize)>,
    output_maps: Vec<(Span, usize)>,
}

/// Build the bounded structural review from a parsed view.
/// `inject_failure` forces the review-construction failure path.
fn build_review(
    bytes: &[u8],
    view: &PsbtView<'_>,
    source: InputSource,
    inject_failure: bool,
) -> Result<SyntheticStructuralReview, ()> {
    if inject_failure {
        return Err(());
    }
    let tx = view.unsigned_tx();
    let mut input_maps = Vec::new();
    for i in 0..view.input_map_count() {
        input_maps.push((
            view.input_map_span(i).ok_or(())?,
            view.input_records(i).ok_or(())?.count(),
        ));
    }
    let mut output_maps = Vec::new();
    for i in 0..view.output_map_count() {
        output_maps.push((
            view.output_map_span(i).ok_or(())?,
            view.output_records(i).ok_or(())?.count(),
        ));
    }
    Ok(SyntheticStructuralReview {
        source,
        total_bytes: bytes.len(),
        unsigned_tx_span: tx.span,
        unsigned_tx_len: tx.span.len(),
        input_count: tx.input_count,
        output_count: tx.output_count,
        global_map_span: view.global_map_span(),
        global_record_count: view.global_records().count(),
        input_maps,
        output_maps,
    })
}

fn plain(event: TransactionEvent) -> WorkflowEvent {
    WorkflowEvent::Plain(event)
}

fn expect_continue(wf: &mut TransactionWorkflow, event: WorkflowEvent, expected: TransactionState) {
    let outcome = wf.apply(event).expect("workflow must still be live");
    assert_eq!(outcome, ApplyOutcome::Continue(expected));
    assert_eq!(wf.state(), expected);
}

fn assert_locked(wf: &TransactionWorkflow) {
    assert_eq!(wf.state(), TransactionState::Locked);
    assert!(wf.is_finished());
    assert_eq!(wf.minted_token(), None);
}

fn expect_halt(wf: &mut TransactionWorkflow, event: TransactionEvent) {
    let outcome = wf.apply(plain(event)).expect("workflow must still be live");
    assert_eq!(outcome, ApplyOutcome::HaltLocked);
    assert_locked(wf);
}

/// Drive a fresh workflow from Locked to `target`, performing the
/// parser-mapped step at validation and (when reached) the
/// same-bytes/same-source reparse plus structural review equality
/// before the token-carrying revalidation assertion.
fn reach(target: TransactionState) -> TransactionWorkflow {
    let source = InputSource::MicroSd;
    let mut wf = TransactionWorkflow::new();
    expect_continue(
        &mut wf,
        plain(TransactionEvent::Wake),
        TransactionState::Ready,
    );
    expect_continue(
        &mut wf,
        plain(TransactionEvent::BeginValidation),
        TransactionState::Validating,
    );
    if wf.state() == target {
        return wf;
    }
    let view = parse(&FIXTURE, source).expect("fixture must parse structurally");
    let review = build_review(&FIXTURE, &view, source, false).expect("review must build");
    expect_continue(
        &mut wf,
        plain(TransactionEvent::ValidationPassed),
        TransactionState::ConstructingReview,
    );
    if wf.state() == target {
        return wf;
    }
    expect_continue(
        &mut wf,
        plain(TransactionEvent::ReviewConstructed),
        TransactionState::ReviewReady,
    );
    if wf.state() == target {
        return wf;
    }
    expect_continue(
        &mut wf,
        plain(TransactionEvent::RequestApproval),
        TransactionState::Confirming,
    );
    if wf.state() == target {
        return wf;
    }
    expect_continue(
        &mut wf,
        plain(TransactionEvent::Approve),
        TransactionState::Approved,
    );
    if wf.state() == target {
        return wf;
    }
    expect_continue(
        &mut wf,
        plain(TransactionEvent::BeginRevalidation),
        TransactionState::Revalidating,
    );
    if wf.state() == target {
        return wf;
    }
    // Reparse the exact same immutable bytes with the same source and
    // require test-local structural review equality, then and only
    // then assert revalidation with the current cycle token.
    let reparsed = parse(&FIXTURE, source).expect("same-bytes reparse must succeed");
    let rebuilt = build_review(&FIXTURE, &reparsed, source, false).expect("review must rebuild");
    assert_eq!(rebuilt, review);
    let token = wf
        .minted_token()
        .expect("accepted Approve must mint a token");
    expect_continue(
        &mut wf,
        WorkflowEvent::RevalidationPassed(token),
        TransactionState::SignPermitted,
    );
    assert_eq!(wf.state(), target, "target stage must be reachable");
    wf
}

#[test]
fn valid_fixture_reaches_review_ready_for_both_sources() {
    for source in [InputSource::MicroSd, InputSource::Qr] {
        let mut wf = TransactionWorkflow::new();
        expect_continue(
            &mut wf,
            plain(TransactionEvent::Wake),
            TransactionState::Ready,
        );
        expect_continue(
            &mut wf,
            plain(TransactionEvent::BeginValidation),
            TransactionState::Validating,
        );
        let view = parse(&FIXTURE, source).expect("fixture must parse structurally");
        expect_continue(
            &mut wf,
            plain(TransactionEvent::ValidationPassed),
            TransactionState::ConstructingReview,
        );
        let review = build_review(&FIXTURE, &view, source, false).expect("review must build");
        expect_continue(
            &mut wf,
            plain(TransactionEvent::ReviewConstructed),
            TransactionState::ReviewReady,
        );
        assert_eq!(review.source, source);
        assert_eq!(review.total_bytes, 72);
        assert_eq!(review.unsigned_tx_span, Span { start: 8, end: 69 });
        assert_eq!(review.unsigned_tx_len, 61);
        assert_eq!(view.unsigned_tx_bytes(), &FIXTURE[8..69]);
        assert_eq!(review.input_count, 1);
        assert_eq!(review.output_count, 1);
        assert_eq!(review.global_record_count, 1);
        assert_eq!(review.input_maps.len(), 1);
        assert_eq!(review.output_maps.len(), 1);
        assert_eq!(review.input_maps[0].1, 0, "input map must be empty");
        assert_eq!(review.output_maps[0].1, 0, "output map must be empty");
        assert_eq!(wf.minted_token(), None);
        assert!(!wf.is_finished());
    }
}

#[test]
fn parse_failures_map_to_validation_failed_and_lock() {
    let mut bad_magic = FIXTURE;
    bad_magic[0] = 0x71;
    let truncated = &FIXTURE[..20];
    let cases: [(&[u8], RejectCategory); 2] = [
        (&bad_magic, RejectCategory::InvalidMagic),
        (truncated, RejectCategory::Truncated),
    ];
    for (bytes, category) in cases {
        let mut wf = TransactionWorkflow::new();
        expect_continue(
            &mut wf,
            plain(TransactionEvent::Wake),
            TransactionState::Ready,
        );
        expect_continue(
            &mut wf,
            plain(TransactionEvent::BeginValidation),
            TransactionState::Validating,
        );
        let err = parse(bytes, InputSource::MicroSd).expect_err("corrupt bytes must reject");
        assert_eq!(err.category, category);
        // Parse failure maps to ValidationFailed: no review is built
        // and no token is ever minted.
        expect_halt(&mut wf, TransactionEvent::ValidationFailed);
    }
}

#[test]
fn review_construction_failure_locks() {
    let mut wf = TransactionWorkflow::new();
    expect_continue(
        &mut wf,
        plain(TransactionEvent::Wake),
        TransactionState::Ready,
    );
    expect_continue(
        &mut wf,
        plain(TransactionEvent::BeginValidation),
        TransactionState::Validating,
    );
    let view = parse(&FIXTURE, InputSource::MicroSd).expect("fixture must parse structurally");
    expect_continue(
        &mut wf,
        plain(TransactionEvent::ValidationPassed),
        TransactionState::ConstructingReview,
    );
    let injected = build_review(&FIXTURE, &view, InputSource::MicroSd, true);
    assert!(injected.is_err(), "injected build failure must surface");
    expect_halt(&mut wf, TransactionEvent::ReviewConstructionFailed);
}

#[test]
fn approval_rejected_locks_and_mints_no_token() {
    let mut wf = reach(TransactionState::Confirming);
    assert_eq!(wf.minted_token(), None);
    expect_halt(&mut wf, TransactionEvent::ApprovalRejected);
}

#[test]
fn same_bytes_reparse_with_current_token_reaches_sign_permitted() {
    let source = InputSource::MicroSd;
    let mut wf = TransactionWorkflow::new();
    expect_continue(
        &mut wf,
        plain(TransactionEvent::Wake),
        TransactionState::Ready,
    );
    expect_continue(
        &mut wf,
        plain(TransactionEvent::BeginValidation),
        TransactionState::Validating,
    );
    let view = parse(&FIXTURE, source).expect("fixture must parse structurally");
    let review = build_review(&FIXTURE, &view, source, false).expect("review must build");
    expect_continue(
        &mut wf,
        plain(TransactionEvent::ValidationPassed),
        TransactionState::ConstructingReview,
    );
    expect_continue(
        &mut wf,
        plain(TransactionEvent::ReviewConstructed),
        TransactionState::ReviewReady,
    );
    expect_continue(
        &mut wf,
        plain(TransactionEvent::RequestApproval),
        TransactionState::Confirming,
    );
    assert_eq!(wf.minted_token(), None);
    expect_continue(
        &mut wf,
        plain(TransactionEvent::Approve),
        TransactionState::Approved,
    );
    let token = wf
        .minted_token()
        .expect("accepted Approve must mint the cycle token");
    expect_continue(
        &mut wf,
        plain(TransactionEvent::BeginRevalidation),
        TransactionState::Revalidating,
    );
    // Reparse the exact same immutable bytes with the same source,
    // rebuild the same structural review, and check equality; then
    // and only then emit the token-carrying revalidation assertion.
    let reparsed = parse(&FIXTURE, source).expect("same-bytes reparse must succeed");
    let rebuilt = build_review(&FIXTURE, &reparsed, source, false).expect("review must rebuild");
    assert_eq!(rebuilt, review);
    expect_continue(
        &mut wf,
        WorkflowEvent::RevalidationPassed(token),
        TransactionState::SignPermitted,
    );
    // Stop at SignPermitted: this proves parser-to-model wiring plus
    // cycle/order provenance only. SignatureProduced is never emitted.
    assert!(!wf.is_finished());
    assert_eq!(wf.minted_token(), Some(token));
}

#[test]
fn corrupted_reparse_after_approval_locks_and_clears_token() {
    let mut wf = reach(TransactionState::Revalidating);
    assert!(wf.minted_token().is_some(), "cycle token must be active");
    // Corrupt one byte of a copy; the post-approval reparse fails.
    let mut corrupted = FIXTURE;
    corrupted[7] = 0x3c; // shrink the declared unsigned-tx value length
    assert!(parse(&corrupted, InputSource::MicroSd).is_err());
    // Reparse failure maps to RevalidationFailed: locked, token
    // cleared, SignPermitted never reached.
    expect_halt(&mut wf, TransactionEvent::RevalidationFailed);
}

#[test]
fn interruptions_lock_and_clear_token_at_every_stage() {
    // Every interruption event actually declared by the model —
    // Sleep plus the five `is_interruption` events, six total.
    let interruptions = [
        TransactionEvent::Sleep,
        TransactionEvent::Cancel,
        TransactionEvent::Timeout,
        TransactionEvent::MediaRemoved,
        TransactionEvent::Restart,
        TransactionEvent::PowerLoss,
    ];
    assert!(interruptions.iter().all(|e| e.is_terminal()));
    assert_eq!(
        interruptions.iter().filter(|e| e.is_interruption()).count(),
        5
    );
    let stages = [
        TransactionState::Validating,
        TransactionState::ConstructingReview,
        TransactionState::ReviewReady,
        TransactionState::Confirming,
        TransactionState::Approved,
        TransactionState::Revalidating,
        TransactionState::SignPermitted,
    ];
    for stage in stages {
        for event in interruptions {
            let mut wf = reach(stage);
            let token_expected = matches!(
                stage,
                TransactionState::Approved
                    | TransactionState::Revalidating
                    | TransactionState::SignPermitted
            );
            assert_eq!(wf.minted_token().is_some(), token_expected);
            expect_halt(&mut wf, event);
        }
    }
}

#[test]
fn reparse_cannot_bypass_missing_or_foreign_token() {
    let source = InputSource::MicroSd;
    // Missing token: a successful same-bytes reparse with an equal
    // structural review does not substitute for the cycle token.
    let mut wf = reach(TransactionState::Revalidating);
    let first_view = parse(&FIXTURE, source).expect("reparse must succeed");
    let first = build_review(&FIXTURE, &first_view, source, false).expect("review must build");
    let second_view = parse(&FIXTURE, source).expect("reparse must succeed");
    let second = build_review(&FIXTURE, &second_view, source, false).expect("review must build");
    assert_eq!(first, second);
    let outcome = wf
        .apply(plain(TransactionEvent::RevalidationPassed))
        .expect("workflow must still be live");
    assert!(matches!(
        outcome,
        ApplyOutcome::RejectLocked(WorkflowRejection::MissingToken { .. })
    ));
    assert_locked(&wf);
    // Foreign-runner token: minted by a different runner instance,
    // rejected even after the same successful reparse and equality.
    let mut wf = reach(TransactionState::Revalidating);
    let reparse_view = parse(&FIXTURE, source).expect("reparse must succeed");
    let reparsed = build_review(&FIXTURE, &reparse_view, source, false).expect("review must build");
    assert_eq!(reparsed, first);
    let foreign_runner = reach(TransactionState::Approved);
    let foreign = foreign_runner
        .minted_token()
        .expect("foreign runner must mint its own token");
    let outcome = wf
        .apply(WorkflowEvent::RevalidationPassed(foreign))
        .expect("workflow must still be live");
    assert!(matches!(
        outcome,
        ApplyOutcome::RejectLocked(WorkflowRejection::TokenMismatch { .. })
    ));
    assert_locked(&wf);
}
