//! REL-QUAR-00 B: mutation-reachability denial and the REL-02-only
//! restoration boundary (`bd-mcp-rel-quar-00-b-9931`).
//!
//! This module is the B slice and is deliberately DISJOINT from the A
//! inventory module: it defines its own canonical encoding helpers, its own
//! diagnostic type, and its own digest domain, and it reaches A only through
//! A's shipped public surface. Sharing A's private encoders would make a B
//! digest that agrees with A by construction rather than by evidence.
//!
//! WHAT THIS PROVES, AND WHAT IT DOES NOT. It evaluates the twelve ordered
//! contexts by six ordered sinks for exactly seventy-two cells and denies
//! every external mutation path through the quarantined definition. It does
//! NOT observe provider state: the provider-disabled observation and the
//! unresolved historical-run count are carried as RECORDED inputs, never
//! inferred from source, exactly as A carries its unresolved provider
//! observations. No function here reads the network, and none may.
//!
//! NO-CLAIM BOUNDARY. This role alone does not establish parent completion,
//! aggregate MCP 2026-07-28 support, MCP 2024-11-05 preservation, automatic
//! negotiation, profile maturity, conformance, publication, or release
//! readiness. It carries zero protocol capability and no publication
//! authority, and its bead earns zero capability credit by design. Its named
//! consumer is the public REL-QUAR-00 surface named in the canonical package
//! contract, and nothing else may cite it.
//!
//! THE RESTORATION BOUNDARY. Quarantine may be lifted only by an exact
//! `REL-02` authorization receipt. Its ABSENCE is the quarantined state, so
//! [`Rel02ReceiptState::Absent`] is what a passing evaluation records — not a
//! missing input. No version-like tag, branch or ref, actor, token, prior
//! run, or already-published response substitutes for it, and the evaluator
//! refuses every such substitution by construction: the only value that can
//! open the boundary is the receipt variant itself.

use core::fmt;

use crate::release_quarantine::{
    CANONICAL_INPUT_LIMIT_BYTES as A_CANONICAL_INPUT_LIMIT_BYTES, MutationSink, ORDERED_CONTEXTS,
    ORDERED_SINKS, ProviderObservation, QuarantineContext, QuarantineWorkflowInventory,
    Sha256Digest, SinkReachability, WorkflowIdentity, canonical_inventory_bytes,
    event_is_ambient_publish_trigger, permission_is_mutation_capable,
    process_is_publication_capable, quarantine_workflow_inventory, sha256_bounded,
};

/// Domain separator for the B canonical digest. Distinct from A's domain so a
/// B digest can never be mistaken for, or collide with, an A digest.
pub const CANONICAL_DIGEST_DOMAIN: &[u8] = b"fastmcp-rel-quar-00-b-v1\0";

/// Exact upper bound on canonical B input accepted by the digest.
pub const CANONICAL_INPUT_LIMIT_BYTES: usize = 65_536;

/// Stable diagnostic slug for the B evaluator.
pub const DIAGNOSTIC_SLUG: &str = "mutation-reachability-denial";

/// The exact authorization receipt identifier that may restore release
/// capability. Nothing else may.
pub const RESTORATION_RECEIPT_IDENTIFIER: &str = "REL-02";

/// State of the `REL-02` authorization receipt.
///
/// `Absent` is the quarantined state and the only state this evaluator
/// accepts. `Present` is recorded so that a future authorized restoration is
/// representable and must be evaluated deliberately rather than by editing
/// this enum away.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Rel02ReceiptState {
    /// No `REL-02` authorization receipt exists. Quarantine stands.
    Absent,
    /// A `REL-02` authorization receipt exists.
    Present,
}

impl Rel02ReceiptState {
    /// Stable canonical-encoding tag.
    #[must_use]
    pub const fn tag(self) -> &'static str {
        match self {
            Self::Absent => "rel-02-absent",
            Self::Present => "rel-02-present",
        }
    }
}

/// Provenance of the ref or dispatch input that produced a context.
///
/// Recorded per cell so that a substituted ref shape is a one-variable change
/// the planted negative can make, rather than something the encoding hides.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RefInputProvenance {
    /// A ref or input supplied by the provider for this context.
    ProviderSupplied,
    /// No ref or input participates in this context.
    NotApplicable,
}

impl RefInputProvenance {
    /// Stable canonical-encoding tag.
    #[must_use]
    pub const fn tag(self) -> &'static str {
        match self {
            Self::ProviderSupplied => "provider-supplied",
            Self::NotApplicable => "not-applicable",
        }
    }
}

/// One evaluated reachability-denial cell.
///
/// Carries the item-1 field set: workflow/action identity, ref/input
/// provenance, the permission, secret and process set sizes taken from the
/// quarantine identity, the sink, the terminal result, and a per-cell state
/// digest over that cell's own canonical bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReachabilityDenialCell {
    /// The closed-context input.
    pub context: QuarantineContext,
    /// The external mutation sink.
    pub sink: MutationSink,
    /// Terminal result for runs created from the quarantined definition.
    pub result: SinkReachability,
    /// Workflow identity role the cell was evaluated against.
    pub workflow_identity: &'static str,
    /// Count of pinned action identities on that workflow identity.
    pub action_identities: usize,
    /// Ref or dispatch-input provenance for this context.
    pub ref_input_provenance: RefInputProvenance,
    /// Declared permission-set size on the evaluated identity.
    pub permission_set: usize,
    /// Secret-reference-set size on the evaluated identity.
    pub secret_set: usize,
    /// Process-invocation-set size on the evaluated identity.
    pub process_set: usize,
    /// Digest over this cell's canonical bytes.
    pub state_digest: Sha256Digest,
}

/// Counters that must each be exactly zero for the denial to hold.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ZeroAuthorityCounters {
    /// Ambient publish triggers on the quarantine identity.
    pub ambient_publish_triggers: usize,
    /// Mutation-capable declared permissions.
    pub mutation_permissions: usize,
    /// Secret accesses.
    pub secret_access: usize,
    /// Publication-capable processes.
    pub publication_processes: usize,
    /// Registry requests reachable from the definition.
    pub registry_requests: usize,
    /// Release, tag or asset mutations reachable from the definition.
    pub release_tag_asset_mutations: usize,
    /// Provider grants held by the definition.
    pub provider_grants: usize,
}

impl ZeroAuthorityCounters {
    /// The first non-zero counter, by canonical order, if any.
    #[must_use]
    pub const fn first_non_zero(&self) -> Option<&'static str> {
        if self.ambient_publish_triggers != 0 {
            return Some("ambient_publish_triggers");
        }
        if self.mutation_permissions != 0 {
            return Some("mutation_permissions");
        }
        if self.secret_access != 0 {
            return Some("secret_access");
        }
        if self.publication_processes != 0 {
            return Some("publication_processes");
        }
        if self.registry_requests != 0 {
            return Some("registry_requests");
        }
        if self.release_tag_asset_mutations != 0 {
            return Some("release_tag_asset_mutations");
        }
        if self.provider_grants != 0 {
            return Some("provider_grants");
        }
        None
    }
}

/// The B evidence record: everything the canonical B digest binds.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MutationReachabilityRecord {
    /// The A canonical inventory digest this record is bound to.
    pub a_digest: Sha256Digest,
    /// The seventy-two ordered denial cells, context-major.
    pub cells: Vec<ReachabilityDenialCell>,
    /// State of the `REL-02` authorization receipt.
    pub rel_02_receipt: Rel02ReceiptState,
    /// Recorded provider-side disablement observation. Never inferred.
    pub provider_disabled: ProviderObservation,
    /// Recorded count of unresolved historical runs. Never inferred.
    pub unresolved_historical_runs: usize,
    /// The zero-authority counters.
    pub counters: ZeroAuthorityCounters,
}

/// Stable typed refusal produced by the B evaluator.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReachabilityDiagnostic {
    /// Stable machine-readable code.
    pub code: &'static str,
    /// The exact field that failed.
    pub field: String,
}

impl fmt::Display for ReachabilityDiagnostic {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "RELQUAR00B|Error|{}|{}|{}",
            self.code, DIAGNOSTIC_SLUG, self.field
        )
    }
}

impl core::error::Error for ReachabilityDiagnostic {}

fn reject(code: &'static str, field: impl Into<String>) -> ReachabilityDiagnostic {
    ReachabilityDiagnostic {
        code,
        field: field.into(),
    }
}

// --- canonical encoding, B's own. Deliberately not A's private helpers. ---

fn put_bytes(buffer: &mut Vec<u8>, bytes: &[u8]) {
    buffer.extend_from_slice(&(bytes.len() as u64).to_be_bytes());
    buffer.extend_from_slice(bytes);
}

fn put_str(buffer: &mut Vec<u8>, value: &str) {
    put_bytes(buffer, value.as_bytes());
}

fn put_usize(buffer: &mut Vec<u8>, value: usize) {
    put_bytes(buffer, &(value as u64).to_be_bytes());
}

/// Canonical bytes for one cell, excluding its own state digest.
#[must_use]
pub fn canonical_cell_bytes(cell: &ReachabilityDenialCell) -> Vec<u8> {
    let mut buffer = Vec::with_capacity(256);
    put_str(&mut buffer, cell.context.tag());
    put_str(&mut buffer, cell.sink.tag());
    put_str(&mut buffer, cell.result.tag());
    put_str(&mut buffer, cell.workflow_identity);
    put_usize(&mut buffer, cell.action_identities);
    put_str(&mut buffer, cell.ref_input_provenance.tag());
    put_usize(&mut buffer, cell.permission_set);
    put_usize(&mut buffer, cell.secret_set);
    put_usize(&mut buffer, cell.process_set);
    buffer
}

/// Deterministic length-prefixed canonical encoding of the B record. This
/// exact sequence, prefixed by [`CANONICAL_DIGEST_DOMAIN`], is the digest
/// input.
#[must_use]
pub fn canonical_reachability_bytes(record: &MutationReachabilityRecord) -> Vec<u8> {
    let mut buffer = Vec::with_capacity(16_384);
    buffer.extend_from_slice(CANONICAL_DIGEST_DOMAIN);
    put_bytes(&mut buffer, record.a_digest.as_bytes());
    put_usize(&mut buffer, record.cells.len());
    for cell in &record.cells {
        let cell_bytes = canonical_cell_bytes(cell);
        put_bytes(&mut buffer, &cell_bytes);
        put_bytes(&mut buffer, cell.state_digest.as_bytes());
    }
    put_str(&mut buffer, record.rel_02_receipt.tag());
    put_str(&mut buffer, record.provider_disabled.tag());
    put_usize(&mut buffer, record.unresolved_historical_runs);
    put_usize(&mut buffer, record.counters.ambient_publish_triggers);
    put_usize(&mut buffer, record.counters.mutation_permissions);
    put_usize(&mut buffer, record.counters.secret_access);
    put_usize(&mut buffer, record.counters.publication_processes);
    put_usize(&mut buffer, record.counters.registry_requests);
    put_usize(&mut buffer, record.counters.release_tag_asset_mutations);
    put_usize(&mut buffer, record.counters.provider_grants);
    buffer
}

/// Accepted-denial receipt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReachabilityDenialReceipt {
    /// Number of evaluated denial cells (exactly seventy-two).
    pub denial_cells: usize,
    /// The `REL-02` receipt state that was accepted.
    pub rel_02_receipt: Rel02ReceiptState,
    /// Recorded unresolved historical-run count carried through.
    pub unresolved_historical_runs: usize,
    /// Canonical B digest under [`CANONICAL_DIGEST_DOMAIN`].
    pub canonical_digest: Sha256Digest,
}

// --- derivation from A's shipped surface ---

fn digest_of(bytes: &[u8], field: &'static str) -> Result<Sha256Digest, ReachabilityDiagnostic> {
    sha256_bounded(bytes, CANONICAL_INPUT_LIMIT_BYTES).map_err(|_| reject("E_CANONICAL_INPUT", field))
}

/// A registry request is any process invocation that reaches a package
/// registry. Fail-closed: the classifier names the reaching forms rather
/// than trying to enumerate the safe ones.
#[must_use]
pub fn process_is_registry_request(process: &str) -> bool {
    process.contains("cargo publish") || process.contains("crates.io") || process.contains("registry")
}

/// A release, tag or asset mutation is any process invocation that creates or
/// moves a release, a tag, or a public asset. Fail-closed in the same sense.
#[must_use]
pub fn process_is_release_tag_or_asset_mutation(process: &str) -> bool {
    process.contains("gh release")
        || process.contains("git tag")
        || process.contains("git push --tags")
        || process.contains("upload-release-asset")
        || process.contains("softprops/action-gh-release")
}

/// A provider grant is any declared permission that is not explicitly
/// read-only. Fail-closed: an unrecognised permission counts as a grant.
#[must_use]
pub fn permission_is_provider_grant(permission: &str) -> bool {
    !permission.ends_with(": read") && !permission.ends_with(":read") && !permission.ends_with("none")
}

fn counters_for(identity: &WorkflowIdentity) -> ZeroAuthorityCounters {
    ZeroAuthorityCounters {
        ambient_publish_triggers: identity
            .events
            .iter()
            .filter(|event| event_is_ambient_publish_trigger(event))
            .count(),
        mutation_permissions: identity
            .declared_permissions
            .iter()
            .filter(|permission| permission_is_mutation_capable(permission))
            .count(),
        secret_access: identity.secret_references.len(),
        publication_processes: identity
            .process_invocations
            .iter()
            .filter(|process| process_is_publication_capable(process))
            .count(),
        registry_requests: identity
            .process_invocations
            .iter()
            .filter(|process| process_is_registry_request(process))
            .count(),
        release_tag_asset_mutations: identity
            .process_invocations
            .iter()
            .filter(|process| process_is_release_tag_or_asset_mutation(process))
            .count(),
        provider_grants: identity
            .declared_permissions
            .iter()
            .filter(|permission| permission_is_provider_grant(permission))
            .count(),
    }
}

const fn provenance_for(context: QuarantineContext) -> RefInputProvenance {
    match context {
        QuarantineContext::TokenPresent | QuarantineContext::TokenAbsent => {
            RefInputProvenance::NotApplicable
        }
        _ => RefInputProvenance::ProviderSupplied,
    }
}

/// The B public evidence entrypoint.
///
/// Consumes A's shipped workflow/action inventory and derives the
/// seventy-two ordered denial cells, the zero-authority counters, and the
/// recorded provider and `REL-02` states. Every value is taken from A's
/// public surface or from this module's recorded constants; nothing is
/// observed from the network and nothing is inferred about provider state.
///
/// # Errors
///
/// Returns a [`ReachabilityDiagnostic`] if A's inventory does not present the
/// closed context and sink sets, or if a digest input exceeds its bound.
pub fn quarantine_mutation_reachability(
    inventory: &QuarantineWorkflowInventory,
) -> Result<MutationReachabilityRecord, ReachabilityDiagnostic> {
    if inventory.ordered_contexts != ORDERED_CONTEXTS {
        return Err(reject("E_CONTEXT_SET", "ordered_contexts"));
    }
    if inventory.ordered_sinks != ORDERED_SINKS {
        return Err(reject("E_SINK_SET", "ordered_sinks"));
    }
    let expected = ORDERED_CONTEXTS.len() * ORDERED_SINKS.len();
    if inventory.reachability_cells.len() != expected {
        return Err(reject("E_CONTEXT_SET", "reachability_cells.len"));
    }

    let identity = &inventory.quarantine;
    let a_bytes = canonical_inventory_bytes(inventory);
    let a_digest = sha256_bounded(&a_bytes, A_CANONICAL_INPUT_LIMIT_BYTES)
        .map_err(|_| reject("E_CANONICAL_INPUT", "canonical_inventory_bytes"))?;

    let mut cells = Vec::with_capacity(expected);
    for (index, source) in inventory.reachability_cells.iter().enumerate() {
        let context = ORDERED_CONTEXTS[index / ORDERED_SINKS.len()];
        let sink = ORDERED_SINKS[index % ORDERED_SINKS.len()];
        if source.context != context || source.sink != sink {
            return Err(reject(
                "E_CONTEXT_SET",
                format!("cell[context={},sink={}].order", context.tag(), sink.tag()),
            ));
        }
        let mut cell = ReachabilityDenialCell {
            context,
            sink,
            result: source.result,
            workflow_identity: identity.role.tag(),
            action_identities: identity.actions.len(),
            ref_input_provenance: provenance_for(context),
            permission_set: identity.declared_permissions.len(),
            secret_set: identity.secret_references.len(),
            process_set: identity.process_invocations.len(),
            state_digest: a_digest,
        };
        let cell_bytes = canonical_cell_bytes(&cell);
        cell.state_digest = digest_of(&cell_bytes, "cell.state_digest")?;
        cells.push(cell);
    }

    Ok(MutationReachabilityRecord {
        a_digest,
        cells,
        rel_02_receipt: Rel02ReceiptState::Absent,
        provider_disabled: identity.provider_disablement,
        unresolved_historical_runs: inventory.unresolved_provider_observations.len(),
        counters: counters_for(identity),
    })
}

/// Builds the B record from A's frozen shipped inventory.
///
/// # Errors
///
/// Propagates [`quarantine_mutation_reachability`].
pub fn frozen_mutation_reachability() -> Result<MutationReachabilityRecord, ReachabilityDiagnostic>
{
    quarantine_mutation_reachability(&quarantine_workflow_inventory())
}

/// The REL-QUAR-00 B evaluator.
///
/// Requires all seventy-two ordered cells present in context-major order and
/// terminating externally inert, each cell's recorded state digest to
/// recompute from its own canonical bytes, every zero-authority counter to be
/// exactly zero, and the `REL-02` authorization receipt to be ABSENT. Binds
/// the whole record into the canonical B digest.
///
/// # Errors
///
/// Returns the stable [`ReachabilityDiagnostic`] naming the first failing
/// field. Rejection never mutates the borrowed record, and the evaluator
/// performs no provider action of any kind.
pub fn rel_quar_00_b_reachability_denial(
    record: &MutationReachabilityRecord,
) -> Result<ReachabilityDenialReceipt, ReachabilityDiagnostic> {
    let expected = ORDERED_CONTEXTS.len() * ORDERED_SINKS.len();
    if record.cells.len() != expected {
        return Err(reject("E_CELL_COUNT", "cells.len"));
    }
    for (index, cell) in record.cells.iter().enumerate() {
        let context = ORDERED_CONTEXTS[index / ORDERED_SINKS.len()];
        let sink = ORDERED_SINKS[index % ORDERED_SINKS.len()];
        let field = format!("cell[context={},sink={}]", context.tag(), sink.tag());
        if cell.context != context || cell.sink != sink {
            return Err(reject("E_CELL_ORDER", field));
        }
        if cell.result != SinkReachability::ExternallyInert {
            return Err(reject("E_MUTATION_REACHABLE", field));
        }
        if cell.ref_input_provenance != provenance_for(context) {
            return Err(reject("E_REF_PROVENANCE", field));
        }
        let recomputed = digest_of(&canonical_cell_bytes(cell), "cell.state_digest")?;
        if recomputed != cell.state_digest {
            return Err(reject("E_CELL_DIGEST", field));
        }
    }
    if let Some(counter) = record.counters.first_non_zero() {
        return Err(reject("E_NONZERO_AUTHORITY", counter));
    }
    if record.rel_02_receipt != Rel02ReceiptState::Absent {
        return Err(reject("E_RESTORATION_BOUNDARY", "rel_02_receipt"));
    }
    if record.provider_disabled == ProviderObservation::VerifiedBySeparateAuthority {
        return Err(reject("E_PROVIDER_INFERENCE", "provider_disabled"));
    }

    let canonical_digest = digest_of(
        &canonical_reachability_bytes(record),
        "canonical_reachability_bytes",
    )?;

    Ok(ReachabilityDenialReceipt {
        denial_cells: record.cells.len(),
        rel_02_receipt: record.rel_02_receipt,
        unresolved_historical_runs: record.unresolved_historical_runs,
        canonical_digest,
    })
}
