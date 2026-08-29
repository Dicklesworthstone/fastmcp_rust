//! REL-QUAR-00 A: ambient publisher discovery and authority-removal evidence.
//!
//! This module is the shipped, non-`cfg(test)` public surface for the
//! REL-QUAR-00 A capability slice. It freezes the release-workflow quarantine
//! inventory — the immutable historical `release.yml` publisher identity and
//! the checked-in quarantine-verification identity — and evaluates that
//! inventory against the ambient-authority predicate: zero ambient publish
//! triggers, zero mutation-capable permissions, zero secret references, zero
//! publication-capable processes, and seventy-two externally inert
//! context-by-sink reachability cells. Supplied identities are
//! equality-bound to the frozen expectations field by field, so a
//! substituted-but-well-formed revision, digest, or action commit identity
//! is refused, not merely shape-checked.
//!
//! Scope boundaries (REL-QUAR-00):
//!
//! - This surface is safety evidence only. It grants zero protocol capability
//!   and asserts no authority to mutate provider state, cancel runs, disable
//!   workflows, or rotate credentials.
//! - Provider-side facts — historical workflow-ID disablement, ambient
//!   registry-token removal/rotation, and pre-quarantine queued/in-progress
//!   run disposition — are recorded here strictly as unresolved provider-side
//!   observations. They are never inferred safe from source state; the B
//!   slice owns their separately authorized resolution.
//! - The canonical digest binds the whole inventory under the domain
//!   separator `fastmcp-rel-quar-00-a-v1\0` using length-prefixed framing and
//!   the bounded SHA-256 primitive from `fastmcp-core`.

use core::fmt;

pub use fastmcp_core::crypto::{CryptoInputTooLongError, Sha256Digest, sha256_bounded};

/// Domain separator for the REL-QUAR-00 A canonical digest, including the
/// terminal NUL byte required by the package contract.
pub const CANONICAL_DIGEST_DOMAIN: &[u8] = b"fastmcp-rel-quar-00-a-v1\0";

/// Fixed audited bound for the canonical inventory encoding handed to
/// [`sha256_bounded`]. The frozen inventory encodes to a few kilobytes; an
/// encoding that exceeds this bound is an inventory defect, not a reason to
/// raise the limit silently.
pub const CANONICAL_INPUT_LIMIT_BYTES: usize = 65_536;

/// Repository path shared by both frozen workflow identities.
pub const WORKFLOW_PATH: &str = ".github/workflows/release.yml";

/// Stable diagnostic slug used by every [`QuarantineDiagnostic`].
pub const DIAGNOSTIC_SLUG: &str = "ambient-authority-inventory";

/// The frozen standing unresolved provider-side observations. The evaluator
/// equality-binds the inventory's list to exactly these entries; dropping,
/// rewording, or resolving one from source state is refused.
pub const UNRESOLVED_PROVIDER_OBSERVATIONS: [&str; 3] = [
    "historical release.yml provider workflow-ID disablement unverified",
    "ambient crates.io registry token removal/rotation unverified",
    "pre-quarantine queued/in-progress run inventory and disposition unverified",
];

/// Role of a frozen workflow identity within the quarantine inventory.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WorkflowRole {
    /// The immutable historical `release.yml` provider identity whose
    /// ambient publication authority this package discovers and records.
    HistoricalPublisher,
    /// The checked-in quarantine verification definition that replaced the
    /// historical publisher at the same path.
    QuarantineVerification,
}

impl WorkflowRole {
    /// Stable canonical-encoding tag.
    #[must_use]
    pub const fn tag(self) -> &'static str {
        match self {
            Self::HistoricalPublisher => "historical-publisher",
            Self::QuarantineVerification => "quarantine-verification",
        }
    }
}

/// Provider-side disablement/credential observation for a workflow identity.
///
/// The A slice holds no provider credential and performs no provider read,
/// so the only state it may record is unresolved. The verified variant exists
/// for the downstream integration receipt, which binds separately authorized
/// provider read-backs; the A evaluator rejects it fail-closed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProviderObservation {
    /// No provider-side evidence exists in this slice; the fact remains an
    /// unresolved stop-the-line observation under separate authority.
    UnresolvedPendingSeparateAuthority,
    /// A separately authorized provider read-back exists. Never constructible
    /// as truth inside the A slice.
    VerifiedBySeparateAuthority,
}

impl ProviderObservation {
    /// Stable canonical-encoding tag.
    #[must_use]
    pub const fn tag(self) -> &'static str {
        match self {
            Self::UnresolvedPendingSeparateAuthority => "unresolved-pending-separate-authority",
            Self::VerifiedBySeparateAuthority => "verified-by-separate-authority",
        }
    }
}

/// One of the twelve ordered closed-context inputs required by the package
/// contract.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QuarantineContext {
    /// A version-shaped or arbitrary tag push.
    TagPush,
    /// A branch push, including the default branch.
    BranchPush,
    /// A pull request from any source.
    PullRequest,
    /// A manual `workflow_dispatch` invocation.
    ManualDispatch,
    /// A rerun of a previously created run.
    WorkflowRerun,
    /// Invocation as or of a reusable workflow.
    ReusableWorkflowInvocation,
    /// An environment-approval gate resolving.
    EnvironmentApproval,
    /// Execution in a fork context.
    ForkContext,
    /// A registry or repository token being present in provider state.
    TokenPresent,
    /// No token present in provider state.
    TokenAbsent,
    /// Adversarially shaped refs or dispatch inputs.
    AdversarialRefOrInput,
    /// A queued or in-progress run created before the quarantine landed.
    HistoricalQueuedRun,
}

impl QuarantineContext {
    /// Stable canonical-encoding tag.
    #[must_use]
    pub const fn tag(self) -> &'static str {
        match self {
            Self::TagPush => "tag-push",
            Self::BranchPush => "branch-push",
            Self::PullRequest => "pull-request",
            Self::ManualDispatch => "manual-dispatch",
            Self::WorkflowRerun => "workflow-rerun",
            Self::ReusableWorkflowInvocation => "reusable-workflow-invocation",
            Self::EnvironmentApproval => "environment-approval",
            Self::ForkContext => "fork-context",
            Self::TokenPresent => "token-present",
            Self::TokenAbsent => "token-absent",
            Self::AdversarialRefOrInput => "adversarial-ref-or-input",
            Self::HistoricalQueuedRun => "historical-queued-run",
        }
    }
}

/// The canonical ordered closed set of twelve contexts.
pub const ORDERED_CONTEXTS: [QuarantineContext; 12] = [
    QuarantineContext::TagPush,
    QuarantineContext::BranchPush,
    QuarantineContext::PullRequest,
    QuarantineContext::ManualDispatch,
    QuarantineContext::WorkflowRerun,
    QuarantineContext::ReusableWorkflowInvocation,
    QuarantineContext::EnvironmentApproval,
    QuarantineContext::ForkContext,
    QuarantineContext::TokenPresent,
    QuarantineContext::TokenAbsent,
    QuarantineContext::AdversarialRefOrInput,
    QuarantineContext::HistoricalQueuedRun,
];

/// One of the six external mutation sinks required by the package contract.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MutationSink {
    /// Any mutation-capable workflow or job permission.
    WritePermission,
    /// Any repository, organization, or environment secret access.
    SecretAccess,
    /// Public GitHub release creation.
    ReleaseCreation,
    /// Registry (crates.io) upload.
    RegistryUpload,
    /// Tag creation or movement.
    TagMutation,
    /// Public asset upload.
    PublicAssetUpload,
}

impl MutationSink {
    /// Stable canonical-encoding tag.
    #[must_use]
    pub const fn tag(self) -> &'static str {
        match self {
            Self::WritePermission => "write-permission",
            Self::SecretAccess => "secret-access",
            Self::ReleaseCreation => "release-creation",
            Self::RegistryUpload => "registry-upload",
            Self::TagMutation => "tag-mutation",
            Self::PublicAssetUpload => "public-asset-upload",
        }
    }
}

/// The canonical ordered closed set of six mutation sinks.
pub const ORDERED_SINKS: [MutationSink; 6] = [
    MutationSink::WritePermission,
    MutationSink::SecretAccess,
    MutationSink::ReleaseCreation,
    MutationSink::RegistryUpload,
    MutationSink::TagMutation,
    MutationSink::PublicAssetUpload,
];

/// Terminal result of one context-by-sink reachability cell for runs created
/// from the quarantined workflow definition.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SinkReachability {
    /// The context terminates with zero external mutation through this sink.
    ExternallyInert,
    /// The sink is reachable; the inventory must be rejected.
    MutationReachable,
}

impl SinkReachability {
    /// Stable canonical-encoding tag.
    #[must_use]
    pub const fn tag(self) -> &'static str {
        match self {
            Self::ExternallyInert => "externally-inert",
            Self::MutationReachable => "mutation-reachable",
        }
    }
}

/// One context-by-sink reachability cell.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReachabilityCell {
    /// The closed-context input.
    pub context: QuarantineContext,
    /// The external mutation sink.
    pub sink: MutationSink,
    /// The terminal result for runs created from the quarantined definition.
    pub result: SinkReachability,
}

/// An action referenced by a workflow identity, pinned to an immutable
/// commit identity.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ActionIdentity {
    /// Fully qualified action name, e.g. `actions/checkout`.
    pub name: &'static str,
    /// The exact 40-hex-character pinned commit identity.
    pub commit_sha: &'static str,
}

/// A frozen workflow identity: path/revision plus its complete event, job,
/// permission, secret-reference, process-invocation, and action sets.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkflowIdentity {
    /// Role of this identity within the inventory.
    pub role: WorkflowRole,
    /// The workflow `name:` field.
    pub workflow_name: &'static str,
    /// Repository path of the definition.
    pub path: &'static str,
    /// Git revision (40-hex commit) that fixed the recorded bytes.
    pub revision: &'static str,
    /// SHA-256 (lowercase hex) of the workflow definition bytes at
    /// [`Self::revision`].
    pub definition_sha256_hex: &'static str,
    /// Complete trigger/event set.
    pub events: &'static [&'static str],
    /// Complete job set.
    pub jobs: &'static [&'static str],
    /// Complete declared permission set, qualified by scope.
    pub declared_permissions: &'static [&'static str],
    /// Complete secret-reference set.
    pub secret_references: &'static [&'static str],
    /// Complete process-invocation set (commands and mutation-relevant
    /// action behaviors).
    pub process_invocations: &'static [&'static str],
    /// Complete action set with immutable commit identities.
    pub actions: &'static [ActionIdentity],
    /// Provider-side disablement/credential observation for this identity.
    pub provider_disablement: ProviderObservation,
}

/// The complete frozen REL-QUAR-00 A inventory.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QuarantineWorkflowInventory {
    /// The immutable historical publisher identity.
    pub historical: WorkflowIdentity,
    /// The checked-in quarantine verification identity.
    pub quarantine: WorkflowIdentity,
    /// The ordered closed set of twelve contexts.
    pub ordered_contexts: Vec<QuarantineContext>,
    /// The ordered closed set of six mutation sinks.
    pub ordered_sinks: Vec<MutationSink>,
    /// The seventy-two context-major reachability cells.
    pub reachability_cells: Vec<ReachabilityCell>,
    /// Standing unresolved provider-side observations. Recorded verbatim;
    /// never inferred resolved from source state.
    pub unresolved_provider_observations: Vec<&'static str>,
}

/// Stable typed refusal produced by the evaluator.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QuarantineDiagnostic {
    /// Stable machine-readable code, e.g. `E_MUTATION_REACHABLE`.
    pub code: &'static str,
    /// The exact field that failed, e.g.
    /// `cell[context=manual-dispatch,sink=registry-upload]`.
    pub field: String,
}

impl fmt::Display for QuarantineDiagnostic {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "RELQUAR00A|Error|{}|{}|{}",
            self.code, DIAGNOSTIC_SLUG, self.field
        )
    }
}

impl core::error::Error for QuarantineDiagnostic {}

/// Accepted-inventory receipt with the counts and canonical digest required
/// by the package contract.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QuarantineReceipt {
    /// Number of evaluated reachability cells (exactly seventy-two).
    pub reachability_cells: usize,
    /// Ambient publish triggers on the quarantine identity (exactly zero).
    pub ambient_publish_triggers: usize,
    /// Mutation-capable permissions on the quarantine identity (exactly
    /// zero).
    pub mutation_capable_permissions: usize,
    /// Secret references on the quarantine identity (exactly zero).
    pub secret_references: usize,
    /// Publication-capable processes on the quarantine identity (exactly
    /// zero).
    pub publication_capable_processes: usize,
    /// Count of standing unresolved provider-side observations. Non-zero
    /// until the separately authorized B slice supplies provider evidence;
    /// this receipt therefore never claims the repository externally safe.
    pub unresolved_provider_observations: usize,
    /// Canonical inventory digest under [`CANONICAL_DIGEST_DOMAIN`].
    pub canonical_digest: Sha256Digest,
}

/// Classifies an event as an ambient publish trigger. Fail-closed: every
/// event other than a manual `workflow_dispatch` invocation is ambient.
#[must_use]
pub fn event_is_ambient_publish_trigger(event: &str) -> bool {
    !event.starts_with("workflow_dispatch")
}

/// Classifies a declared permission as mutation-capable. Fail-closed: every
/// permission whose grant is not exactly `read` is mutation-capable.
#[must_use]
pub fn permission_is_mutation_capable(permission: &str) -> bool {
    !permission.ends_with(": read")
}

/// Classifies a process invocation as publication-capable. The denylist
/// covers registry upload, public release creation, tag mutation, and public
/// asset upload surfaces observed in the historical publisher.
#[must_use]
pub fn process_is_publication_capable(process: &str) -> bool {
    const DENYLIST: [&str; 6] = [
        "cargo publish",
        "gh release",
        "action-gh-release",
        "git tag",
        "git push",
        "crates.io upload",
    ];
    DENYLIST.iter().any(|needle| process.contains(needle))
}

fn historical_identity() -> WorkflowIdentity {
    const ACTIONS: [ActionIdentity; 6] = [
        ActionIdentity {
            name: "actions/checkout",
            commit_sha: "3d3c42e5aac5ba805825da76410c181273ba90b1",
        },
        ActionIdentity {
            name: "dtolnay/rust-toolchain",
            commit_sha: "2c7215f132e9ebf062739d9130488b56d53c060c",
        },
        ActionIdentity {
            name: "Swatinem/rust-cache",
            commit_sha: "e18b497796c12c097a38f9edb9d0641fb99eee32",
        },
        ActionIdentity {
            name: "actions/upload-artifact",
            commit_sha: "043fb46d1a93c77aae656e7c1c64a875d1fc6a0a",
        },
        ActionIdentity {
            name: "actions/download-artifact",
            commit_sha: "3e5f45b2cfb9172054b4087a40e8e0b5a5461e7c",
        },
        ActionIdentity {
            name: "softprops/action-gh-release",
            commit_sha: "3bb12739c298aeb8a4eeaf626c5b8d85266b0e65",
        },
    ];

    WorkflowIdentity {
        role: WorkflowRole::HistoricalPublisher,
        workflow_name: "Release",
        path: WORKFLOW_PATH,
        revision: "7c02d8e0e2b09d3bbe2d4f40ad89efa20c619b8d",
        definition_sha256_hex: "dad6d55939a1b49e221169e6c42f66fe0bc1721a6fcb2eeea10ad80159a15bf5",
        events: &["push.tags: v*", "workflow_dispatch: tag input"],
        jobs: &["build", "release", "publish-crates"],
        declared_permissions: &[
            "workflow.contents: write",
            "job.release.contents: write",
            "job.publish-crates.contents: read",
        ],
        secret_references: &["secrets.CARGO_REGISTRY_TOKEN"],
        process_invocations: &[
            "cargo publish -p <crate> --locked (twelve-attempt retry loop)",
            "softprops/action-gh-release public release creation and asset upload",
            "cargo build --release (binary matrix)",
            "tar/shasum release packaging",
        ],
        actions: &ACTIONS,
        provider_disablement: ProviderObservation::UnresolvedPendingSeparateAuthority,
    }
}

fn quarantine_identity() -> WorkflowIdentity {
    const ACTIONS: [ActionIdentity; 5] = [
        ActionIdentity {
            name: "actions/checkout",
            commit_sha: "3d3c42e5aac5ba805825da76410c181273ba90b1",
        },
        ActionIdentity {
            name: "dtolnay/rust-toolchain",
            commit_sha: "6c977a6ca4077a0ceb28ffbe03f59d46e9ac8772",
        },
        ActionIdentity {
            name: "Swatinem/rust-cache",
            commit_sha: "6323deb102c322ba6fcbdcafc7e3dddab59af2b6",
        },
        ActionIdentity {
            name: "taiki-e/install-action",
            commit_sha: "ba47c86ac325773530516bb756137ac718732518",
        },
        ActionIdentity {
            name: "actions/upload-artifact",
            commit_sha: "043fb46d1a93c77aae656e7c1c64a875d1fc6a0a",
        },
    ];

    WorkflowIdentity {
        role: WorkflowRole::QuarantineVerification,
        workflow_name: "Release Quarantine Verification",
        path: WORKFLOW_PATH,
        revision: "3332da3e036fb4c0a778aaec24cb17720b37c08c",
        definition_sha256_hex: "23ea1534d4ee97a60506d2efc48c27e67dc4acbcd98c1818fb46f23e744b5684",
        events: &["workflow_dispatch"],
        jobs: &["preflight", "build"],
        declared_permissions: &[
            "workflow.contents: read",
            "job.preflight.contents: read",
            "job.build.contents: read",
        ],
        secret_references: &[],
        process_invocations: &[
            "cargo metadata/fmt/check/clippy/test verification",
            "cargo audit --deny warnings",
            "cargo package --locked --no-verify (runner-local diagnostic)",
            "cargo build --release --locked -p fastmcp-cli (diagnostic)",
            "tar/shasum/Compress-Archive diagnostic packaging",
            "actions/upload-artifact expiring private diagnostic (3-day retention)",
        ],
        actions: &ACTIONS,
        provider_disablement: ProviderObservation::UnresolvedPendingSeparateAuthority,
    }
}

/// The public evidence entrypoint: the frozen REL-QUAR-00 A inventory.
///
/// Freezes exactly two workflow identities — the immutable historical
/// `release.yml` publisher (revision `7c02d8e0`, the last pre-quarantine
/// bytes) and the checked-in quarantine verification definition (revision
/// `3332da3e`, re-frozen over action-pin and dated-toolchain updates) — plus the ordered
/// twelve-context/six-sink closed sets, the seventy-two reachability cells,
/// and the standing unresolved provider-side observations.
#[must_use]
pub fn quarantine_workflow_inventory() -> QuarantineWorkflowInventory {
    let mut reachability_cells = Vec::with_capacity(ORDERED_CONTEXTS.len() * ORDERED_SINKS.len());
    for context in ORDERED_CONTEXTS {
        for sink in ORDERED_SINKS {
            reachability_cells.push(ReachabilityCell {
                context,
                sink,
                result: SinkReachability::ExternallyInert,
            });
        }
    }

    QuarantineWorkflowInventory {
        historical: historical_identity(),
        quarantine: quarantine_identity(),
        ordered_contexts: ORDERED_CONTEXTS.to_vec(),
        ordered_sinks: ORDERED_SINKS.to_vec(),
        reachability_cells,
        unresolved_provider_observations: UNRESOLVED_PROVIDER_OBSERVATIONS.to_vec(),
    }
}

fn push_length_prefixed(buffer: &mut Vec<u8>, bytes: &[u8]) {
    buffer.extend_from_slice(&(bytes.len() as u64).to_be_bytes());
    buffer.extend_from_slice(bytes);
}

fn push_str(buffer: &mut Vec<u8>, value: &str) {
    push_length_prefixed(buffer, value.as_bytes());
}

fn push_u64(buffer: &mut Vec<u8>, value: u64) {
    push_length_prefixed(buffer, &value.to_be_bytes());
}

fn push_str_list(buffer: &mut Vec<u8>, values: &[&str]) {
    push_u64(buffer, values.len() as u64);
    for value in values {
        push_str(buffer, value);
    }
}

fn encode_identity(buffer: &mut Vec<u8>, identity: &WorkflowIdentity) {
    push_str(buffer, identity.role.tag());
    push_str(buffer, identity.workflow_name);
    push_str(buffer, identity.path);
    push_str(buffer, identity.revision);
    push_str(buffer, identity.definition_sha256_hex);
    push_str_list(buffer, identity.events);
    push_str_list(buffer, identity.jobs);
    push_str_list(buffer, identity.declared_permissions);
    push_str_list(buffer, identity.secret_references);
    push_str_list(buffer, identity.process_invocations);
    push_u64(buffer, identity.actions.len() as u64);
    for action in identity.actions {
        push_str(buffer, action.name);
        push_str(buffer, action.commit_sha);
    }
    push_str(buffer, identity.provider_disablement.tag());
}

/// Predicate counts derived from the quarantine identity by the fixed
/// fail-closed classifiers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct AmbientAuthorityCounts {
    ambient_publish_triggers: usize,
    mutation_capable_permissions: usize,
    secret_references: usize,
    publication_capable_processes: usize,
}

fn ambient_authority_counts(identity: &WorkflowIdentity) -> AmbientAuthorityCounts {
    AmbientAuthorityCounts {
        ambient_publish_triggers: identity
            .events
            .iter()
            .filter(|event| event_is_ambient_publish_trigger(event))
            .count(),
        mutation_capable_permissions: identity
            .declared_permissions
            .iter()
            .filter(|permission| permission_is_mutation_capable(permission))
            .count(),
        secret_references: identity.secret_references.len(),
        publication_capable_processes: identity
            .process_invocations
            .iter()
            .filter(|process| process_is_publication_capable(process))
            .count(),
    }
}

/// Deterministic length-prefixed canonical encoding of the inventory. This
/// exact byte sequence, prefixed by [`CANONICAL_DIGEST_DOMAIN`], is the input
/// to the canonical digest.
#[must_use]
pub fn canonical_inventory_bytes(inventory: &QuarantineWorkflowInventory) -> Vec<u8> {
    let mut buffer = Vec::with_capacity(8_192);
    buffer.extend_from_slice(CANONICAL_DIGEST_DOMAIN);
    encode_identity(&mut buffer, &inventory.historical);
    encode_identity(&mut buffer, &inventory.quarantine);
    push_u64(&mut buffer, inventory.ordered_contexts.len() as u64);
    for context in &inventory.ordered_contexts {
        push_str(&mut buffer, context.tag());
    }
    push_u64(&mut buffer, inventory.ordered_sinks.len() as u64);
    for sink in &inventory.ordered_sinks {
        push_str(&mut buffer, sink.tag());
    }
    push_u64(&mut buffer, inventory.reachability_cells.len() as u64);
    for cell in &inventory.reachability_cells {
        push_str(&mut buffer, cell.context.tag());
        push_str(&mut buffer, cell.sink.tag());
        push_str(&mut buffer, cell.result.tag());
    }
    let counts = ambient_authority_counts(&inventory.quarantine);
    push_u64(&mut buffer, counts.ambient_publish_triggers as u64);
    push_u64(&mut buffer, counts.mutation_capable_permissions as u64);
    push_u64(&mut buffer, counts.secret_references as u64);
    push_u64(&mut buffer, counts.publication_capable_processes as u64);
    push_str(&mut buffer, inventory.historical.provider_disablement.tag());
    push_str(&mut buffer, inventory.quarantine.provider_disablement.tag());
    push_u64(
        &mut buffer,
        inventory.unresolved_provider_observations.len() as u64,
    );
    for observation in &inventory.unresolved_provider_observations {
        push_str(&mut buffer, observation);
    }
    push_str(&mut buffer, inventory.quarantine.definition_sha256_hex);
    buffer
}

fn is_lower_hex(value: &str, expected_len: usize) -> bool {
    value.len() == expected_len
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn reject(code: &'static str, field: impl Into<String>) -> QuarantineDiagnostic {
    QuarantineDiagnostic {
        code,
        field: field.into(),
    }
}

fn check_identity_shape(identity: &WorkflowIdentity) -> Result<(), QuarantineDiagnostic> {
    let role = identity.role.tag();
    if identity.path != WORKFLOW_PATH {
        return Err(reject("E_IDENTITY_SET", format!("identity[{role}].path")));
    }
    if identity.workflow_name.is_empty() || identity.events.is_empty() {
        return Err(reject("E_IDENTITY_SET", format!("identity[{role}].shape")));
    }
    if !is_lower_hex(identity.revision, 40) {
        return Err(reject(
            "E_IDENTITY_SET",
            format!("identity[{role}].revision"),
        ));
    }
    if !is_lower_hex(identity.definition_sha256_hex, 64) {
        return Err(reject(
            "E_IDENTITY_SET",
            format!("identity[{role}].definition_sha256_hex"),
        ));
    }
    for action in identity.actions {
        if action.name.is_empty() || !is_lower_hex(action.commit_sha, 40) {
            return Err(reject(
                "E_ACTION_IDENTITY",
                format!("identity[{role}].action[{}]", action.name),
            ));
        }
    }
    if identity.provider_disablement != ProviderObservation::UnresolvedPendingSeparateAuthority {
        return Err(reject(
            "E_PROVIDER_INFERENCE",
            format!("identity[{role}].provider_disablement"),
        ));
    }
    Ok(())
}

/// Equality-binds a supplied identity to its frozen expectation, field by
/// field. Shape checks alone admit a one-variable substitution with another
/// well-formed identity (for example a different valid lowercase-hex action
/// commit); the frozen-identity predicate requires exact equality on every
/// recorded field.
fn check_identity_binding(
    actual: &WorkflowIdentity,
    frozen: &WorkflowIdentity,
) -> Result<(), QuarantineDiagnostic> {
    let role = frozen.role.tag();
    let mismatch: Option<&'static str> = if actual.role != frozen.role {
        Some("role")
    } else if actual.workflow_name != frozen.workflow_name {
        Some("workflow_name")
    } else if actual.path != frozen.path {
        Some("path")
    } else if actual.revision != frozen.revision {
        Some("revision")
    } else if actual.definition_sha256_hex != frozen.definition_sha256_hex {
        Some("definition_sha256_hex")
    } else if actual.events != frozen.events {
        Some("events")
    } else if actual.jobs != frozen.jobs {
        Some("jobs")
    } else if actual.declared_permissions != frozen.declared_permissions {
        Some("declared_permissions")
    } else if actual.secret_references != frozen.secret_references {
        Some("secret_references")
    } else if actual.process_invocations != frozen.process_invocations {
        Some("process_invocations")
    } else if actual.actions != frozen.actions {
        Some("actions")
    } else {
        None
    };
    if let Some(field) = mismatch {
        return Err(reject(
            "E_IDENTITY_BINDING",
            format!("identity[{role}].{field}"),
        ));
    }
    if actual.provider_disablement != frozen.provider_disablement {
        return Err(reject(
            "E_PROVIDER_INFERENCE",
            format!("identity[{role}].provider_disablement"),
        ));
    }
    Ok(())
}

fn check_quarantine_predicate(counts: AmbientAuthorityCounts) -> Result<(), QuarantineDiagnostic> {
    if counts.ambient_publish_triggers != 0 {
        return Err(reject("E_AMBIENT_TRIGGER", "quarantine.events"));
    }
    if counts.mutation_capable_permissions != 0 {
        return Err(reject(
            "E_MUTATION_PERMISSION",
            "quarantine.declared_permissions",
        ));
    }
    if counts.secret_references != 0 {
        return Err(reject("E_SECRET_REFERENCE", "quarantine.secret_references"));
    }
    if counts.publication_capable_processes != 0 {
        return Err(reject(
            "E_PUBLICATION_PROCESS",
            "quarantine.process_invocations",
        ));
    }
    Ok(())
}

fn check_historical_discovery(identity: &WorkflowIdentity) -> Result<(), QuarantineDiagnostic> {
    let counts = ambient_authority_counts(identity);
    let discovery_complete = counts.ambient_publish_triggers > 0
        && counts.mutation_capable_permissions > 0
        && counts.secret_references > 0
        && counts.publication_capable_processes > 0;
    if discovery_complete {
        Ok(())
    } else {
        Err(reject("E_HISTORICAL_DISCOVERY", "historical"))
    }
}

fn check_reachability_cells(
    inventory: &QuarantineWorkflowInventory,
) -> Result<usize, QuarantineDiagnostic> {
    if inventory.ordered_contexts != ORDERED_CONTEXTS {
        return Err(reject("E_CONTEXT_SET", "ordered_contexts"));
    }
    if inventory.ordered_sinks != ORDERED_SINKS {
        return Err(reject("E_SINK_SET", "ordered_sinks"));
    }
    let expected_cells = ORDERED_CONTEXTS.len() * ORDERED_SINKS.len();
    if inventory.reachability_cells.len() != expected_cells {
        return Err(reject("E_CONTEXT_SET", "reachability_cells.len"));
    }
    for (index, cell) in inventory.reachability_cells.iter().enumerate() {
        let context = ORDERED_CONTEXTS[index / ORDERED_SINKS.len()];
        let sink = ORDERED_SINKS[index % ORDERED_SINKS.len()];
        if cell.context != context || cell.sink != sink {
            return Err(reject(
                "E_CONTEXT_SET",
                format!("cell[context={},sink={}].order", context.tag(), sink.tag()),
            ));
        }
        if cell.result != SinkReachability::ExternallyInert {
            return Err(reject(
                "E_MUTATION_REACHABLE",
                format!(
                    "cell[context={},sink={}]",
                    cell.context.tag(),
                    cell.sink.tag()
                ),
            ));
        }
    }
    Ok(expected_cells)
}

/// The REL-QUAR-00 A evaluator.
///
/// Equality-binds both supplied identities to the frozen expectations field
/// by field (revision, definition digest, events, jobs, permissions,
/// secrets, processes, pinned action names/SHAs, provider observation),
/// enforces the ambient-authority predicate on the quarantine identity (zero
/// ambient publish triggers, zero mutation-capable permissions, zero secret
/// references, zero publication-capable processes), requires all seventy-two
/// ordered reachability cells to terminate externally inert, requires the
/// historical identity to actually record the discovered ambient authority,
/// refuses any provider-side safety inference, and binds everything into the
/// canonical digest.
///
/// # Errors
///
/// Returns the stable [`QuarantineDiagnostic`] naming the first failing
/// field. Rejection never mutates the borrowed inventory.
pub fn rel_quar_00_a_ambient_authority_inventory(
    inventory: &QuarantineWorkflowInventory,
) -> Result<QuarantineReceipt, QuarantineDiagnostic> {
    // Self-integrity of the frozen expectations: a defective re-freeze
    // (truncated digest, malformed action pin) must fail before it can bind
    // anything.
    let frozen_historical = historical_identity();
    let frozen_quarantine = quarantine_identity();
    check_identity_shape(&frozen_historical)?;
    check_identity_shape(&frozen_quarantine)?;

    // Frozen-identity predicate: every recorded field of the supplied
    // identities must equal the frozen expectation exactly. Shape checks
    // alone would admit a one-variable substitution with another well-formed
    // revision, digest, or action commit identity.
    check_identity_binding(&inventory.historical, &frozen_historical)?;
    check_identity_binding(&inventory.quarantine, &frozen_quarantine)?;

    // The predicate checks below are intentionally kept even though equality
    // binding subsumes them for the current constants: they refuse a future
    // re-freeze that would reintroduce ambient authority into the quarantine
    // identity or erase the historical discovery record.
    let counts = ambient_authority_counts(&inventory.quarantine);
    check_quarantine_predicate(counts)?;
    check_historical_discovery(&inventory.historical)?;

    if inventory.unresolved_provider_observations != UNRESOLVED_PROVIDER_OBSERVATIONS {
        return Err(reject(
            "E_PROVIDER_INFERENCE",
            "unresolved_provider_observations",
        ));
    }

    let reachability_cells = check_reachability_cells(inventory)?;

    let canonical_bytes = canonical_inventory_bytes(inventory);
    let canonical_digest = sha256_bounded(&canonical_bytes, CANONICAL_INPUT_LIMIT_BYTES)
        .map_err(|_| reject("E_CANONICAL_INPUT", "canonical_inventory_bytes"))?;

    Ok(QuarantineReceipt {
        reachability_cells,
        ambient_publish_triggers: counts.ambient_publish_triggers,
        mutation_capable_permissions: counts.mutation_capable_permissions,
        secret_references: counts.secret_references,
        publication_capable_processes: counts.publication_capable_processes,
        unresolved_provider_observations: inventory.unresolved_provider_observations.len(),
        canonical_digest,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ambient_trigger_classifier_admits_only_manual_dispatch() {
        assert!(!event_is_ambient_publish_trigger("workflow_dispatch"));
        assert!(event_is_ambient_publish_trigger("push.tags: v*"));
        assert!(event_is_ambient_publish_trigger("pull_request"));
    }

    #[test]
    fn permission_classifier_is_fail_closed() {
        assert!(!permission_is_mutation_capable("workflow.contents: read"));
        assert!(permission_is_mutation_capable("workflow.contents: write"));
        assert!(permission_is_mutation_capable("job.x.id-token: none"));
    }

    #[test]
    fn process_classifier_flags_publication_surfaces() {
        assert!(process_is_publication_capable(
            "cargo publish -p fastmcp-core --locked"
        ));
        assert!(process_is_publication_capable(
            "softprops/action-gh-release public release creation and asset upload"
        ));
        assert!(!process_is_publication_capable(
            "cargo package --locked --no-verify (runner-local diagnostic)"
        ));
    }

    #[test]
    fn canonical_encoding_is_deterministic() {
        let inventory = quarantine_workflow_inventory();
        assert_eq!(
            canonical_inventory_bytes(&inventory),
            canonical_inventory_bytes(&inventory)
        );
    }
}
