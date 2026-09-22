//! REL-QUAR-00 INTEGRATION: join the A inventory and B denial slices through
//! their shipped public entrypoints (`bd-mcp-rel-quar-00-integration-qiyn`).
//!
//! DISJOINT BY CONSTRUCTION, for exactly the reason the B slice states about
//! A: this module defines its own canonical encoders, its own diagnostic type
//! and its own digest domain, and it reaches A and B ONLY through their
//! shipped public entrypoints. Sharing either slice's private encoders would
//! produce an integration digest that agrees with its inputs by construction
//! rather than by evidence. A's helpers are `push_*` and private, B's are
//! `put_*` and private; this module's are `append_*` and private, so the three
//! encodings cannot silently converge.
//!
//! WHAT THIS PROVES. It replays A through
//! [`crate::release_quarantine::rel_quar_00_a_ambient_authority_inventory`]
//! and B through
//! [`crate::release_quarantine_reachability::rel_quar_00_b_reachability_denial`],
//! binds the two receipts to each other by A's canonical digest, and admits
//! the pair only when two workflow identities, twelve ordered contexts, six
//! ordered sinks and seventy-two externally inert ordered cells all replay,
//! every zero-authority counter is exactly zero, the recorded provider
//! disablement agrees between the slices, the standing unresolved
//! provider-side observations remain unresolved, and no `REL-02` receipt is
//! present.
//!
//! WHAT IT DOES NOT PROVE. It observes no provider state and performs no
//! provider action. The provider-disablement observation and the unresolved
//! historical-run count are carried as RECORDED inputs from the slices, never
//! inferred, exactly as A and B carry theirs. No function here reads the
//! network, and none may.
//!
//! WHICH GUARDS ARE THIS ROLE'S OWN, AND WHICH ARE SHADOWED. Established by
//! running the planted negatives, not by reading:
//!
//!   OWN, and reachable -- neither slice can make these, because each is a
//!   relation BETWEEN the two:
//!     E_SLICE_BINDING   the B record is bound to the A digest A's replay
//!                       actually produced. B STORES `a_digest` and encodes it
//!                       but never validates it, so a record bound to a foreign
//!                       inventory passes both slices individually.
//!
//!   DEFENCE IN DEPTH, and UNREACHABLE through the shipped replays -- the B
//!   evaluator refuses each of these first, so the checks below cannot fire and
//!   no planted negative can target them:
//!     E_REL_02_PRESENT    shadowed by B's `E_RESTORATION_BOUNDARY`
//!     E_COUNTER_NON_ZERO  shadowed by B's own zero-counter check
//!     E_PROVIDER_STATE    shadowed by B's `E_PROVIDER_INFERENCE`
//!
//! They are kept rather than deleted because they state this closure's own
//! requirements in one place, and because they would become load-bearing if the
//! B replay were ever removed from the entrypoint. They are documented as
//! shadowed so a reader does not mistake them for live protection, and the
//! contract test asserts the PRECEDENCE -- a change that made one of them fire
//! first, or that dropped B's, fails that arm and names which.
//!
//! NO-CLAIM BOUNDARY. This role alone does not establish parent completion,
//! aggregate MCP 2026-07-28 support, MCP 2024-11-05 preservation, automatic
//! negotiation, profile maturity, conformance, publication, or release
//! readiness. It carries zero protocol capability and zero authority to
//! publish, disable, cancel, delete, rerun, or signal a provider workflow.

use core::fmt;

use crate::release_quarantine::{
    ORDERED_CONTEXTS, ORDERED_SINKS, QuarantineWorkflowInventory, Sha256Digest, WorkflowIdentity,
    rel_quar_00_a_ambient_authority_inventory, sha256_bounded,
};
use crate::release_quarantine_reachability::{
    MutationReachabilityRecord, Rel02ReceiptState, rel_quar_00_b_reachability_denial,
};

/// Domain separator for the integration canonical digest. Distinct from both
/// slice domains so an integration digest can never be mistaken for, or
/// collide with, an A or B digest.
pub const CANONICAL_DIGEST_DOMAIN: &[u8] = b"fastmcp-rel-quar-00-integration-v1\0";

/// Exact upper bound on canonical integration input accepted by the digest.
pub const CANONICAL_INPUT_LIMIT_BYTES: usize = 65_536;

/// The public evidence entrypoint's own identity, bound into the digest so a
/// receipt cannot be replayed as having come from a different surface.
pub const PUBLIC_ENTRYPOINT_IDENTITY: &str = "quarantine_release_surface";

/// The integration revision bound into the digest.
pub const INTEGRATION_REVISION: &str = "rel-quar-00-integration-v1";

/// The exact number of workflow identities the closure replays.
pub const REQUIRED_WORKFLOW_IDENTITIES: usize = 2;

/// Stable typed refusal produced by the integration evaluator.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClosureDiagnostic {
    /// Stable machine-readable code, e.g. `E_COUNTER_NON_ZERO`.
    pub code: &'static str,
    /// The first failing field, named.
    pub field: String,
}

impl fmt::Display for ClosureDiagnostic {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.code, self.field)
    }
}

fn reject(code: &'static str, field: impl Into<String>) -> ClosureDiagnostic {
    ClosureDiagnostic {
        code,
        field: field.into(),
    }
}

/// Accepted closure receipt: the joined evidence of both slices.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QuarantineClosureReceipt {
    /// Workflow identities replayed (exactly two).
    pub workflow_identities: usize,
    /// Ordered contexts replayed (exactly twelve).
    pub contexts: usize,
    /// Ordered mutation sinks replayed (exactly six).
    pub sinks: usize,
    /// Externally inert ordered cells replayed (exactly seventy-two).
    pub externally_inert_cells: usize,
    /// Standing unresolved provider-side observations, carried through.
    pub unresolved_provider_observations: usize,
    /// The `REL-02` receipt state that was accepted. Only `Absent` admits.
    pub rel_02_receipt: Rel02ReceiptState,
    /// A's canonical digest, as replayed here.
    pub a_digest: Sha256Digest,
    /// B's canonical digest, as replayed here.
    pub b_digest: Sha256Digest,
    /// Canonical integration digest under [`CANONICAL_DIGEST_DOMAIN`].
    pub canonical_digest: Sha256Digest,
}

// --- canonical encoding, private and distinct from both slices' ---

fn append_usize(buffer: &mut Vec<u8>, value: usize) {
    buffer.extend_from_slice(&(value as u64).to_be_bytes());
}

fn append_bytes(buffer: &mut Vec<u8>, bytes: &[u8]) {
    append_usize(buffer, bytes.len());
    buffer.extend_from_slice(bytes);
}

fn append_str(buffer: &mut Vec<u8>, value: &str) {
    append_bytes(buffer, value.as_bytes());
}

fn append_identity(buffer: &mut Vec<u8>, identity: &WorkflowIdentity) {
    append_str(buffer, identity.workflow_name);
    append_str(buffer, identity.path);
    append_str(buffer, identity.revision);
    append_str(buffer, identity.definition_sha256_hex);
    append_usize(buffer, identity.actions.len());
    for action in identity.actions {
        append_str(buffer, action.name);
        append_str(buffer, action.commit_sha);
    }
    append_str(buffer, identity.provider_disablement.tag());
}

/// Deterministic length-prefixed canonical encoding of the closure. This exact
/// sequence, prefixed by [`CANONICAL_DIGEST_DOMAIN`], is the digest input:
/// A digest, B digest, the workflow and action identities, all seventy-two
/// cell digests, the provider state, the unresolved counts, the seven
/// zero-authority counters, the public-entrypoint identity, and the
/// integration revision.
#[must_use]
pub fn canonical_closure_bytes(
    inventory: &QuarantineWorkflowInventory,
    record: &MutationReachabilityRecord,
    a_digest: &Sha256Digest,
    b_digest: &Sha256Digest,
) -> Vec<u8> {
    let mut buffer = Vec::with_capacity(16_384);
    buffer.extend_from_slice(CANONICAL_DIGEST_DOMAIN);
    append_bytes(&mut buffer, a_digest.as_bytes());
    append_bytes(&mut buffer, b_digest.as_bytes());
    append_usize(&mut buffer, REQUIRED_WORKFLOW_IDENTITIES);
    append_identity(&mut buffer, &inventory.historical);
    append_identity(&mut buffer, &inventory.quarantine);
    append_usize(&mut buffer, record.cells.len());
    for cell in &record.cells {
        append_bytes(&mut buffer, cell.state_digest.as_bytes());
    }
    append_str(&mut buffer, record.provider_disabled.tag());
    append_usize(&mut buffer, record.unresolved_historical_runs);
    append_usize(
        &mut buffer,
        inventory.unresolved_provider_observations.len(),
    );
    append_usize(&mut buffer, record.counters.ambient_publish_triggers);
    append_usize(&mut buffer, record.counters.mutation_permissions);
    append_usize(&mut buffer, record.counters.secret_access);
    append_usize(&mut buffer, record.counters.publication_processes);
    append_usize(&mut buffer, record.counters.registry_requests);
    append_usize(&mut buffer, record.counters.release_tag_asset_mutations);
    append_usize(&mut buffer, record.counters.provider_grants);
    append_str(&mut buffer, PUBLIC_ENTRYPOINT_IDENTITY);
    append_str(&mut buffer, INTEGRATION_REVISION);
    buffer
}

fn is_immutable_pin(sha: &str) -> bool {
    sha.len() == 40
        && sha
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// Replays both slices and admits the closure.
///
/// Replays exactly two workflow identities, the twelve ordered contexts, the
/// six ordered sinks and the seventy-two externally inert ordered cells.
///
/// # Errors
///
/// Returns the stable [`ClosureDiagnostic`] naming the first failing field.
/// Rejection never mutates the borrowed inputs and performs no provider
/// action of any kind.
pub fn rel_quar_00_integration_quarantine_closure(
    inventory: &QuarantineWorkflowInventory,
    record: &MutationReachabilityRecord,
) -> Result<QuarantineClosureReceipt, ClosureDiagnostic> {
    // Both slices are replayed through their SHIPPED entrypoints. A failure in
    // either is surfaced with that slice's own code, so a refusal names which
    // slice refused rather than collapsing to one integration code.
    let a_receipt = rel_quar_00_a_ambient_authority_inventory(inventory)
        .map_err(|diagnostic| reject("E_A_SLICE", diagnostic.code))?;
    let b_receipt = rel_quar_00_b_reachability_denial(record)
        .map_err(|diagnostic| reject("E_B_SLICE", diagnostic.code))?;

    // The two receipts must be about the same A inventory. Without this the
    // closure would join a B record derived from a DIFFERENT inventory and the
    // integration digest would bind two unrelated objects.
    if record.a_digest != a_receipt.canonical_digest {
        return Err(reject("E_SLICE_BINDING", "record.a_digest"));
    }

    // Shape: two identities, twelve contexts, six sinks, seventy-two cells.
    if inventory.ordered_contexts.len() != ORDERED_CONTEXTS.len() {
        return Err(reject("E_CONTEXT_COUNT", "inventory.ordered_contexts"));
    }
    if inventory.ordered_sinks.len() != ORDERED_SINKS.len() {
        return Err(reject("E_SINK_COUNT", "inventory.ordered_sinks"));
    }
    let expected_cells = ORDERED_CONTEXTS.len() * ORDERED_SINKS.len();
    if a_receipt.reachability_cells != expected_cells {
        return Err(reject("E_CELL_COUNT", "a_receipt.reachability_cells"));
    }
    if b_receipt.denial_cells != expected_cells {
        return Err(reject("E_CELL_COUNT", "b_receipt.denial_cells"));
    }

    // Action identities match their immutable pins, on both identities.
    for identity in [&inventory.historical, &inventory.quarantine] {
        for action in identity.actions {
            if !is_immutable_pin(action.commit_sha) {
                return Err(reject(
                    "E_ACTION_PIN",
                    format!("{}:{}", identity.path, action.name),
                ));
            }
        }
    }

    // Every zero-authority counter is exactly zero. B names the first
    // offender, so the field is the counter rather than a generic label.
    if let Some(field) = record.counters.first_non_zero() {
        return Err(reject("E_COUNTER_NON_ZERO", field));
    }

    // Provider-disabled state agrees between the slices. B carries the
    // recorded observation; A carries it per identity. A disagreement means
    // one slice is describing a different provider state than the other.
    if record.provider_disabled != inventory.quarantine.provider_disablement {
        return Err(reject("E_PROVIDER_STATE", "record.provider_disabled"));
    }

    // The standing unresolved provider-side observations must REMAIN
    // unresolved. Resolving them is provider observation, which this role has
    // no authority to perform, so a zero here means someone inferred it.
    if a_receipt.unresolved_provider_observations == 0 {
        return Err(reject(
            "E_UNRESOLVED_CLEARED",
            "a_receipt.unresolved_provider_observations",
        ));
    }

    // No REL-02 receipt is present. `Absent` is the only admitting state; the
    // quarantine stands until a separately authorized receipt exists.
    if record.rel_02_receipt != Rel02ReceiptState::Absent {
        return Err(reject("E_REL_02_PRESENT", "record.rel_02_receipt"));
    }

    let bytes = canonical_closure_bytes(
        inventory,
        record,
        &a_receipt.canonical_digest,
        &b_receipt.canonical_digest,
    );
    let canonical_digest = sha256_bounded(&bytes, CANONICAL_INPUT_LIMIT_BYTES)
        .map_err(|_| reject("E_CANONICAL_INPUT", "canonical_closure_bytes"))?;

    Ok(QuarantineClosureReceipt {
        workflow_identities: REQUIRED_WORKFLOW_IDENTITIES,
        contexts: ORDERED_CONTEXTS.len(),
        sinks: ORDERED_SINKS.len(),
        externally_inert_cells: expected_cells,
        unresolved_provider_observations: a_receipt.unresolved_provider_observations,
        rel_02_receipt: record.rel_02_receipt,
        a_digest: a_receipt.canonical_digest,
        b_digest: b_receipt.canonical_digest,
        canonical_digest,
    })
}

/// The integration public evidence entrypoint.
///
/// Consumes only A's shipped workflow/action inventory and B's shipped
/// reachability-denial surface, and delegates to
/// [`rel_quar_00_integration_quarantine_closure`]. It exists as its own named
/// symbol because the closure is the REPLAY and this is the SURFACE: the
/// entrypoint's identity is bound into the canonical digest, so a receipt
/// carries which public surface produced it.
///
/// # Errors
///
/// Returns the stable [`ClosureDiagnostic`] naming the first failing field.
pub fn quarantine_release_surface(
    inventory: &QuarantineWorkflowInventory,
    record: &MutationReachabilityRecord,
) -> Result<QuarantineClosureReceipt, ClosureDiagnostic> {
    rel_quar_00_integration_quarantine_closure(inventory, record)
}
