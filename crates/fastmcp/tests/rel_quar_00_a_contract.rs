//! Public-surface REL-QUAR-00 A contract checks (bd-mcp-rel-quar-00-a-jbcf).
//!
//! The positive binds the frozen quarantine identity to the actual
//! checked-in workflow bytes, cross-checks the source with an independent
//! textual oracle that shares no code with the shipped evaluator, and
//! accepts the inventory through the shipped public surface. The planted
//! negative flips exactly one reachability cell in a clone, proves the
//! stable typed refusal, and proves the accepted pristine state is
//! byte-for-byte unchanged and re-acceptable.

use std::fs;
use std::path::{Path, PathBuf};

use fastmcp_rust::release_quarantine::{
    CANONICAL_INPUT_LIMIT_BYTES, MutationSink, QuarantineContext, SinkReachability, WORKFLOW_PATH,
    canonical_inventory_bytes, quarantine_workflow_inventory,
    rel_quar_00_a_ambient_authority_inventory, sha256_bounded,
};

fn checked_in_workflow_path() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(2)
        .expect("workspace root exists above crates/fastmcp")
        .join(WORKFLOW_PATH)
}

fn lowercase_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for &byte in bytes {
        out.push(HEX[usize::from(byte >> 4)] as char);
        out.push(HEX[usize::from(byte & 0x0f)] as char);
    }
    out
}

#[test]
fn rel_quar_00_a_positive() {
    let inventory = quarantine_workflow_inventory();

    // Bind the frozen quarantine identity to the actual checked-in bytes.
    let workflow_bytes =
        fs::read(checked_in_workflow_path()).expect("checked-in quarantine workflow is readable");
    let workflow_digest = sha256_bounded(&workflow_bytes, CANONICAL_INPUT_LIMIT_BYTES)
        .expect("workflow definition fits the audited canonical bound");
    assert_eq!(
        lowercase_hex(workflow_digest.as_bytes()),
        inventory.quarantine.definition_sha256_hex,
        "frozen quarantine identity must match the checked-in workflow bytes; \
         a workflow edit requires a conscious inventory re-freeze"
    );

    // Independent textual oracle over the checked-in source. Deliberately
    // disjoint from the shipped evaluator: it observes raw workflow text.
    let workflow_text =
        String::from_utf8(workflow_bytes).expect("workflow definition is valid UTF-8");
    assert!(
        workflow_text.contains("workflow_dispatch:"),
        "quarantine keeps only the manual diagnostic trigger"
    );
    assert!(
        workflow_text.contains("contents: read"),
        "quarantine declares read-only permissions"
    );
    for forbidden in [
        "\n  push:",
        "tags:",
        "pull_request:",
        "cargo publish",
        "secrets.",
        "contents: write",
        "packages: write",
        "id-token: write",
        "action-gh-release",
        "environment:",
    ] {
        assert!(
            !workflow_text.contains(forbidden),
            "quarantined workflow source must not contain {forbidden:?}"
        );
    }

    // Accept through the shipped public surface.
    let receipt = rel_quar_00_a_ambient_authority_inventory(&inventory)
        .expect("frozen inventory satisfies the ambient-authority predicate");
    assert_eq!(receipt.reachability_cells, 72);
    assert_eq!(receipt.ambient_publish_triggers, 0);
    assert_eq!(receipt.mutation_capable_permissions, 0);
    assert_eq!(receipt.secret_references, 0);
    assert_eq!(receipt.publication_capable_processes, 0);
    assert_eq!(
        receipt.unresolved_provider_observations, 3,
        "provider disablement, token rotation, and historical-run disposition \
         remain unresolved provider-side observations in the A slice"
    );

    // Deterministic acceptance: the receipt (including the canonical digest)
    // reproduces exactly.
    let second =
        rel_quar_00_a_ambient_authority_inventory(&inventory).expect("acceptance is deterministic");
    assert_eq!(receipt, second);
}

#[test]
fn rel_quar_00_a_planted_negative() {
    let pristine = quarantine_workflow_inventory();
    let pristine_bytes = canonical_inventory_bytes(&pristine);
    let accepted = rel_quar_00_a_ambient_authority_inventory(&pristine)
        .expect("pristine inventory is accepted before planting");

    // Plant exactly one forbidden change: a single reachability cell flips
    // from externally inert to mutation-reachable.
    let mut planted = pristine.clone();
    let cell = planted
        .reachability_cells
        .iter_mut()
        .find(|cell| {
            cell.context == QuarantineContext::ManualDispatch
                && cell.sink == MutationSink::RegistryUpload
        })
        .expect("manual-dispatch/registry-upload cell exists");
    cell.result = SinkReachability::MutationReachable;

    let diagnostic = rel_quar_00_a_ambient_authority_inventory(&planted)
        .expect_err("a mutation-reachable cell is refused");
    assert_eq!(diagnostic.code, "E_MUTATION_REACHABLE");
    assert_eq!(
        diagnostic.to_string(),
        "RELQUAR00A|Error|E_MUTATION_REACHABLE|ambient-authority-inventory|\
         cell[context=manual-dispatch,sink=registry-upload]"
    );

    // The accepted pristine state is byte-for-byte unchanged and still
    // accepted with an identical receipt and canonical digest.
    assert_eq!(
        canonical_inventory_bytes(&pristine),
        pristine_bytes,
        "rejection must not disturb the accepted canonical encoding"
    );
    let reaccepted = rel_quar_00_a_ambient_authority_inventory(&pristine)
        .expect("pristine inventory re-accepts after the refused plant");
    assert_eq!(accepted, reaccepted);
}
