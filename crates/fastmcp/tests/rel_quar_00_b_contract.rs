//! Public-surface REL-QUAR-00 B contract checks (bd-mcp-rel-quar-00-b-9931).
//!
//! External consumer of the published facade: every symbol below is reached
//! through `fastmcp_rust::release_quarantine_reachability`, never through a
//! `#[cfg(test)]` module, so what this proves is the packaged public surface
//! (PL-3).
//!
//! The positive derives the denial record from A's shipped inventory,
//! accepts it through the shipped B evaluator, and cross-checks the cell
//! count against an INDEPENDENT ORACLE that shares no code with the
//! evaluator: 12 ordered contexts times 6 ordered sinks, counted from the
//! public arrays. The planted negative plants SIX independent one-variable
//! mutations in fresh clones, proves the stable typed refusal and its exact
//! code for each, and proves the pristine record is unchanged and
//! re-acceptable afterwards.
//!
//! NO PROVIDER ACTION OCCURS HERE. Nothing in this file reaches the network,
//! reads provider state, or touches a credential. The provider observation
//! and the unresolved historical-run count are values carried out of A's
//! recorded inventory, and the `REL-02` receipt state is the recorded
//! quarantined state, not an observation.

use fastmcp_rust::release_quarantine::{
    ORDERED_CONTEXTS, ORDERED_SINKS, ProviderObservation, SinkReachability,
};
use fastmcp_rust::release_quarantine_reachability::{
    RESTORATION_RECEIPT_IDENTIFIER, Rel02ReceiptState, canonical_cell_bytes,
    frozen_mutation_reachability, rel_quar_00_b_reachability_denial,
};

/// Independent oracle for the cell count. Shares no code with the evaluator:
/// it multiplies the two published ordered arrays rather than asking the
/// evaluator how many cells it expects.
fn oracle_cell_count() -> usize {
    ORDERED_CONTEXTS.len() * ORDERED_SINKS.len()
}

#[test]
fn rel_quar_00_b_positive() {
    let record = frozen_mutation_reachability().expect("A's frozen inventory yields a B record");

    // Independent oracle first: if this disagrees with the evaluator the
    // evaluator's own count is not evidence.
    assert_eq!(
        oracle_cell_count(),
        72,
        "the published ordered arrays must still be 12 contexts by 6 sinks"
    );
    assert_eq!(
        record.cells.len(),
        oracle_cell_count(),
        "the derived record must carry exactly the oracle's cell count"
    );

    let receipt = rel_quar_00_b_reachability_denial(&record)
        .expect("the frozen quarantined record is accepted");

    assert_eq!(receipt.denial_cells, 72);
    assert_eq!(
        receipt.rel_02_receipt,
        Rel02ReceiptState::Absent,
        "quarantine stands only while the {RESTORATION_RECEIPT_IDENTIFIER} receipt is absent"
    );

    // Every cell is externally inert, in context-major order.
    for (index, cell) in record.cells.iter().enumerate() {
        assert_eq!(cell.context, ORDERED_CONTEXTS[index / ORDERED_SINKS.len()]);
        assert_eq!(cell.sink, ORDERED_SINKS[index % ORDERED_SINKS.len()]);
        assert_eq!(
            cell.result,
            SinkReachability::ExternallyInert,
            "cell {index} must terminate externally inert"
        );
    }

    // Every zero-authority counter is zero.
    assert_eq!(record.counters.first_non_zero(), None);

    // The record is deterministic: an independent derivation must produce a
    // byte-identical digest. A digest that varied between constructions
    // would bind nothing.
    let again = frozen_mutation_reachability().expect("second derivation succeeds");
    let receipt_again =
        rel_quar_00_b_reachability_denial(&again).expect("second derivation is accepted");
    assert_eq!(
        receipt.canonical_digest, receipt_again.canonical_digest,
        "the canonical B digest must be stable across independent derivations"
    );

    // The B digest must NOT equal the A digest it binds: a B digest that
    // collided with its own input would prove nothing about B.
    assert_ne!(
        receipt.canonical_digest.as_bytes(),
        record.a_digest.as_bytes(),
        "the B digest must be distinct from the A digest it length-prefixes"
    );

    // The recorded provider observation is carried, never resolved here.
    assert_ne!(
        record.provider_disabled,
        ProviderObservation::VerifiedBySeparateAuthority,
        "B must never record provider state as verified; that is a separate authority"
    );
}

#[test]
fn rel_quar_00_b_planted_negative() {
    let pristine = frozen_mutation_reachability().expect("A's frozen inventory yields a B record");
    let accepted = rel_quar_00_b_reachability_denial(&pristine).expect("baseline is accepted");

    // Captured BEFORE any mutation. Comparing the record against a clone of
    // itself taken afterwards would be `observed == observed`; this snapshot
    // is the only operand a mutation could move.
    let baseline_cell_zero_bytes = canonical_cell_bytes(&pristine.cells[0]);

    // (1) One cell's terminal result flipped. Nothing else changes.
    let mut planted = pristine.clone();
    planted.cells[0].result = SinkReachability::MutationReachable;
    let refusal = rel_quar_00_b_reachability_denial(&planted)
        .expect_err("a reachable sink must be refused");
    assert_eq!(refusal.code, "E_MUTATION_REACHABLE");
    assert!(refusal.to_string().starts_with("RELQUAR00B|Error|"));

    // (2) The restoration boundary opened. This is the whole point of the
    // slice: only an exact REL-02 receipt may lift quarantine, and its
    // presence must be evaluated deliberately rather than silently accepted.
    let mut planted = pristine.clone();
    planted.rel_02_receipt = Rel02ReceiptState::Present;
    let refusal = rel_quar_00_b_reachability_denial(&planted)
        .expect_err("a present restoration receipt must not be auto-accepted");
    assert_eq!(refusal.code, "E_RESTORATION_BOUNDARY");

    // (3) One zero-authority counter raised.
    let mut planted = pristine.clone();
    planted.counters.registry_requests = 1;
    let refusal = rel_quar_00_b_reachability_denial(&planted)
        .expect_err("a non-zero registry-request counter must be refused");
    assert_eq!(refusal.code, "E_NONZERO_AUTHORITY");
    assert_eq!(refusal.field, "registry_requests");

    // (4) Two cells transposed: same set, wrong order.
    let mut planted = pristine.clone();
    planted.cells.swap(0, 1);
    let refusal =
        rel_quar_00_b_reachability_denial(&planted).expect_err("cell order must be exact");
    assert_eq!(refusal.code, "E_CELL_ORDER");

    // (5) One cell's recorded state digest corrupted while its fields stay
    // valid. Catches a record whose per-cell digests were never recomputed.
    let mut planted = pristine.clone();
    planted.cells[5].state_digest = pristine.a_digest;
    let refusal = rel_quar_00_b_reachability_denial(&planted)
        .expect_err("a stale per-cell digest must be refused");
    assert_eq!(refusal.code, "E_CELL_DIGEST");

    // (6) Provider state asserted as verified by this slice, which it may
    // never do.
    let mut planted = pristine.clone();
    planted.provider_disabled = ProviderObservation::VerifiedBySeparateAuthority;
    let refusal = rel_quar_00_b_reachability_denial(&planted)
        .expect_err("B must refuse to record provider verification");
    assert_eq!(refusal.code, "E_PROVIDER_INFERENCE");

    // Every refusal above borrowed the record. The pristine value must be
    // unchanged and still acceptable, with the identical receipt.
    let reaccepted =
        rel_quar_00_b_reachability_denial(&pristine).expect("pristine remains acceptable");
    assert_eq!(reaccepted, accepted, "refusal must not mutate the record");
    assert_eq!(
        canonical_cell_bytes(&pristine.cells[0]),
        baseline_cell_zero_bytes,
        "the baseline cell bytes are unchanged after six refusals"
    );
}
