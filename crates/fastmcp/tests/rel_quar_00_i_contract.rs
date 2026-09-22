//! Public-surface REL-QUAR-00 INTEGRATION contract checks
//! (bd-mcp-rel-quar-00-integration-qiyn).
//!
//! External consumer of the published facade: every symbol below is reached
//! through `fastmcp_rust::release_quarantine_integration`, never through a
//! `#[cfg(test)]` module, so what this proves is the packaged public surface
//! (PL-3).
//!
//! FOUR TESTS, TWO PAIRS, ONE PER NAMED SYMBOL. The bead names two symbols --
//! the public evidence entrypoint `quarantine_release_surface` and the
//! evaluator `rel_quar_00_integration_quarantine_closure` -- and two test
//! pairs. The `_i_*` pair exercises the ENTRYPOINT and the `_integration_*`
//! pair exercises the EVALUATOR, so each pair has a distinct subject rather
//! than duplicating one. This is the shape `crates/fastmcp/tests/fnd_03_i.rs`
//! already uses for a FND-03 integration bead: four tests in one file under
//! both naming schemes, with the bar's `count = 2` naming the required pair.
//!
//! NO PROVIDER ACTION OCCURS HERE. Nothing in this file reaches the network,
//! reads provider state, or touches a credential. The provider observation,
//! the unresolved counts and the `REL-02` state are values carried out of the
//! two slices' recorded inputs, never observations.

use fastmcp_rust::release_quarantine::{
    ORDERED_CONTEXTS, ORDERED_SINKS, quarantine_workflow_inventory,
};
use fastmcp_rust::release_quarantine_integration::{
    REQUIRED_WORKFLOW_IDENTITIES, quarantine_release_surface,
    rel_quar_00_integration_quarantine_closure,
};
use fastmcp_rust::release_quarantine_reachability::{
    MutationReachabilityRecord, Rel02ReceiptState, frozen_mutation_reachability,
};

/// Independent oracle for the cell count. Shares no code with either
/// evaluator: it multiplies the two published ordered arrays rather than
/// asking a receipt how many cells it expects.
fn oracle_cell_count() -> usize {
    ORDERED_CONTEXTS.len() * ORDERED_SINKS.len()
}

fn frozen_pair() -> (
    fastmcp_rust::release_quarantine::QuarantineWorkflowInventory,
    MutationReachabilityRecord,
) {
    let inventory = quarantine_workflow_inventory();
    let record = frozen_mutation_reachability().expect("A's frozen inventory yields a B record");
    (inventory, record)
}

// --- the ENTRYPOINT pair -----------------------------------------------

#[test]
fn rel_quar_00_i_positive() {
    let (inventory, record) = frozen_pair();

    // Oracle first: if it disagrees with the receipt, the receipt's own count
    // is not evidence of anything.
    assert_eq!(
        oracle_cell_count(),
        72,
        "the published ordered arrays must still be 12 contexts by 6 sinks"
    );

    let receipt = quarantine_release_surface(&inventory, &record)
        .expect("the frozen quarantined closure is accepted through the public entrypoint");

    assert_eq!(receipt.workflow_identities, REQUIRED_WORKFLOW_IDENTITIES);
    assert_eq!(receipt.contexts, ORDERED_CONTEXTS.len());
    assert_eq!(receipt.sinks, ORDERED_SINKS.len());
    assert_eq!(
        receipt.externally_inert_cells,
        oracle_cell_count(),
        "the closure must replay exactly the oracle's cell count"
    );
    assert_eq!(
        receipt.rel_02_receipt,
        Rel02ReceiptState::Absent,
        "only the absent REL-02 state admits; quarantine stands"
    );
    assert!(
        receipt.unresolved_provider_observations > 0,
        "the standing provider-side observations must remain UNRESOLVED: this role \
         has no authority to observe the provider, so a zero here means inference"
    );
    assert_ne!(
        receipt.a_digest, receipt.b_digest,
        "the two slice digests are domain-separated and must never coincide"
    );
    assert_ne!(
        receipt.canonical_digest, receipt.a_digest,
        "the integration digest is domain-separated from A's"
    );
    assert_ne!(
        receipt.canonical_digest, receipt.b_digest,
        "the integration digest is domain-separated from B's"
    );
}

#[test]
fn rel_quar_00_i_planted_negative() {
    let (inventory, pristine) = frozen_pair();
    let accepted = quarantine_release_surface(&inventory, &pristine).expect(
        "ARM 0: the pristine closure must be accepted, or every refusal below is unattributable",
    );

    // ARM 1 -- THE FORBIDDEN DIMENSION THIS ROLE UNIQUELY OWNS: the B record
    // is rebound to an A digest that is not the one A's replay produced.
    //
    // This is the integration property. Neither slice can check it: A never
    // sees the B record, and B STORES `a_digest` and encodes it but never
    // validates it against A (release_quarantine_reachability.rs -- it is set
    // at construction, :436, and read only by the encoder, :267). So a record
    // bound to a foreign inventory is accepted by both slices individually and
    // refused only here.
    //
    // The mutation uses a digest already present in the record rather than
    // inventing one, so it cannot fail for a malformed-value reason.
    let mut planted = pristine.clone();
    planted.a_digest = pristine.cells[0].state_digest;
    let refusal = quarantine_release_surface(&inventory, &planted)
        .expect_err("a record bound to a foreign A digest must be refused");
    assert_eq!(
        refusal.code, "E_SLICE_BINDING",
        "the cross-slice binding is the dimension this evaluator uniquely owns"
    );
    assert_eq!(refusal.field, "record.a_digest");

    // ARM 2 -- GUARD PRECEDENCE, ASSERTED RATHER THAN ASSUMED.
    //
    // The first version of this test planted a present REL-02 receipt and
    // expected `E_REL_02_PRESENT`. It got `E_B_SLICE`, because the shipped B
    // evaluator refuses that itself at :496 with `E_RESTORATION_BOUNDARY`,
    // BEFORE this evaluator's own REL-02 check is ever reached. The integration
    // guard for that dimension is defence-in-depth and is unreachable through
    // the shipped replay -- so a negative cannot target it, and pretending
    // otherwise would assert a guard that cannot fire.
    //
    // Asserting the precedence instead turns that into a checked property: if a
    // future change ever made the integration guard fire first, or dropped B's,
    // this arm fails and says which.
    let mut planted = pristine.clone();
    planted.rel_02_receipt = Rel02ReceiptState::Present;
    let refusal = quarantine_release_surface(&inventory, &planted)
        .expect_err("a present REL-02 receipt must be refused by SOMETHING");
    assert_eq!(
        refusal.code, "E_B_SLICE",
        "B owns the restoration boundary and must refuse it before the integration guard"
    );
    assert_eq!(
        refusal.field, "E_RESTORATION_BOUNDARY",
        "the integration refusal must carry B's own code, so a reader learns WHICH slice refused"
    );

    // The pristine record is unchanged and still acceptable, with the identical
    // receipt. Without this a refusal above could be an artefact of a mutation
    // that leaked into the shared input.
    let reaccepted = quarantine_release_surface(&inventory, &pristine)
        .expect("the pristine closure is still accepted after two planted arms");
    assert_eq!(
        reaccepted, accepted,
        "planting must not mutate the pristine closure or its digests"
    );
}

// --- the EVALUATOR pair ------------------------------------------------

#[test]
fn rel_quar_00_integration_positive() {
    let (inventory, record) = frozen_pair();

    let receipt = rel_quar_00_integration_quarantine_closure(&inventory, &record)
        .expect("the frozen quarantined closure is accepted by the evaluator");

    // The evaluator and the entrypoint must agree exactly. If they diverge,
    // one of the two named symbols is not the surface the bead describes.
    let through_surface = quarantine_release_surface(&inventory, &record)
        .expect("the entrypoint accepts what the evaluator accepts");
    assert_eq!(
        receipt, through_surface,
        "the public entrypoint and the evaluator must produce the identical receipt"
    );

    assert_eq!(receipt.externally_inert_cells, oracle_cell_count());
    assert_eq!(receipt.workflow_identities, 2);
}

#[test]
fn rel_quar_00_integration_planted_negative() {
    let (inventory, pristine) = frozen_pair();
    let accepted = rel_quar_00_integration_quarantine_closure(&inventory, &pristine)
        .expect("ARM 0: the pristine closure must be accepted by the evaluator");

    // One variable, on the dimension the evaluator uniquely owns, through the
    // EVALUATOR rather than the entrypoint so this pair's refusal path is
    // exercised on its own subject.
    //
    // The first version planted a non-zero counter and expected
    // `E_COUNTER_NON_ZERO`. B refuses non-zero counters itself at :493, so that
    // guard is shadowed exactly as the REL-02 one is, and the negative was
    // targeting a guard that cannot fire through the shipped replay.
    let mut planted = pristine.clone();
    planted.a_digest = pristine.cells[0].state_digest;
    let refusal = rel_quar_00_integration_quarantine_closure(&inventory, &planted)
        .expect_err("a record bound to a foreign A digest must be refused");
    assert_eq!(refusal.code, "E_SLICE_BINDING");
    assert_eq!(refusal.field, "record.a_digest");

    let reaccepted = rel_quar_00_integration_quarantine_closure(&inventory, &pristine)
        .expect("the pristine closure is still accepted");
    assert_eq!(
        reaccepted, accepted,
        "planting must not mutate the pristine closure or its digests"
    );
}
