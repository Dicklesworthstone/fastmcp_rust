//! LEG-NEG-01 A — disposable-process stdio modern-first classification.
//!
//! This module is the **evaluator** over the already-shipped classifier, not a
//! second classifier. [`Client::stdio_with_protocol_plan_with_cx`] owns the
//! decision: under `Auto` it probes one disposable modern child and starts a
//! fresh exact-2024 child only for the frozen eligible signal. This evaluator
//! drives that public entrypoint through a closed case set and records what was
//! actually observed, so a test can assert on a structured record rather than on
//! a boolean.
//!
//! It deliberately embeds **no shell script and no command**. A case supplies
//! the command and arguments; a shipped library API that spawned `sh -c
//! <script>` would be a liability, and keeping fixture children in the test
//! keeps this surface honest.
//!
//! # Observation protocol
//!
//! Child identity and first-wire bytes cannot be read from the client API, so a
//! fixture child appends them to a caller-named trace file. The grammar is
//! deliberately tiny and line-oriented, one record per line:
//!
//! ```text
//! spawn:<pid>      one line per child process, in spawn order
//! wire:<bytes>     the exact first MCP line that child read
//! ```
//!
//! Any other line is retained verbatim as an unrecognized record rather than
//! ignored, so a malformed trace can never be mistaken for a clean one. A trace
//! that cannot be read is reported as [`TraceOutcome::Unreadable`] and is never
//! treated as "no children were spawned" — an inconclusive observation must
//! fail loudly rather than pass as an absence.
//!
//! # Supported eras
//!
//! Exactly `2026-07-28` and `2024-11-05`. `2025-11-25` exists here only as
//! [`StdioFirstWireSignal::UnsupportedEraAdvertised`], a planted value that must
//! never select an era.

use std::path::{Path, PathBuf};

use fastmcp_core::{Cx, Sha256Digest, sha256_bounded};
use fastmcp_protocol::protocol_policy::{ProtocolEra, ProtocolPolicy};

use crate::Client;
use crate::session::ClientProtocolPlan;

/// The exact modern protocol version this evaluator admits.
pub const MODERN_ERA_VERSION: &str = "2026-07-28";
/// The exact legacy protocol version this evaluator admits.
pub const LEGACY_ERA_VERSION: &str = "2024-11-05";
/// The planted unsupported version. Never selectable, negative use only.
pub const UNSUPPORTED_ERA_VERSION: &str = "2025-11-25";

/// Maximum trace bytes read back from one case.
const MAX_TRACE_BYTES: usize = 64 * 1024;
/// Bound for the manifest digest input.
const MAX_MANIFEST_BYTES: usize = 64 * 1024;

/// The immutable LEG-NEG-01 A evaluator manifest.
///
/// LF-canonical and LF-terminated. It freezes the closed policy-case set, the
/// eligible/ineligible pairing, and the exact first-wire marker each case must
/// observe on the child's first read. The marker is the frozen byte sequence
/// that must appear in that line; the surrounding envelope carries a request id
/// and client version that are not frozen, so the marker rather than the whole
/// line is what the contract pins.
/// The eligible and ineligible members of the frozen pair differ in exactly one
/// field: the JSON-RPC `id` of the discovery refusal. A correlated `-32601`
/// authorizes the fallback; the byte-identical refusal carrying a different id
/// does not. That is the one-variable pairing the acceptance criteria require,
/// and it is the shipped rule rather than a restatement — see
/// `ClientBuilder::try_connect_auto`, "Only a correlated JSON-RPC discovery
/// refusal or Unix-observable clean first-probe timeout authorizes a second
/// spawn."
pub const LEG_NEG_01_A_EVALUATOR_MANIFEST_V1: &str = concat!(
    "LEG-NEG-01-A evaluator manifest v1\n",
    "entrypoint fastmcp_client::Client::stdio_with_protocol_plan_with_cx\n",
    "transport stdio\n",
    "supported-eras 2026-07-28,2024-11-05\n",
    "policy-case auto-modern-selected policy=Auto signal=modern-discovery-result eligible=false paired=auto-eligible-correlated-refusal\n",
    "policy-case auto-eligible-correlated-refusal policy=Auto signal=correlated-discovery-refusal eligible=true paired=auto-ineligible-uncorrelated-refusal\n",
    "policy-case auto-ineligible-uncorrelated-refusal policy=Auto signal=uncorrelated-discovery-refusal eligible=false paired=auto-eligible-correlated-refusal\n",
    "policy-case auto-ineligible-recognized-modern-error policy=Auto signal=recognized-modern-error eligible=false paired=auto-eligible-correlated-refusal\n",
    "policy-case modern-only-never-falls-back policy=ModernOnly signal=correlated-discovery-refusal eligible=false paired=auto-eligible-correlated-refusal\n",
    "policy-case legacy-only-never-probes policy=LegacyOnly signal=no-modern-probe eligible=false paired=auto-eligible-correlated-refusal\n",
    "first-wire auto-modern-selected \"method\":\"server/discover\"\n",
    "first-wire auto-eligible-correlated-refusal \"method\":\"server/discover\"\n",
    "first-wire auto-ineligible-uncorrelated-refusal \"method\":\"server/discover\"\n",
    "first-wire auto-ineligible-recognized-modern-error \"method\":\"server/discover\"\n",
    "first-wire modern-only-never-falls-back \"method\":\"server/discover\"\n",
    "first-wire legacy-only-never-probes \"method\":\"initialize\"\n",
    "fallback-first-wire auto-eligible-correlated-refusal \"protocolVersion\":\"2024-11-05\"\n",
    "pair auto-eligible-correlated-refusal auto-ineligible-uncorrelated-refusal variable=discovery-refusal-response-id\n",
);

/// Returns the canonical LEG-NEG-01 A evaluator manifest digest.
///
/// The manifest is an executable acceptance input, not a source-file hash: it
/// binds the closed policy-case set, the eligible/ineligible pairing, and the
/// frozen first-wire markers.
#[must_use]
pub fn leg_neg_01_a_manifest_digest() -> Sha256Digest {
    sha256_bounded(
        LEG_NEG_01_A_EVALUATOR_MANIFEST_V1.as_bytes(),
        MAX_MANIFEST_BYTES,
    )
    .expect("the fixed LEG-NEG-01 A manifest is within its exact byte bound")
}

/// Returns the digest of one case's exact declared inputs.
///
/// The AC requires paired input digests so an eligible and ineligible case can
/// be shown to differ in exactly one field. The preimage is the case's ordered
/// declared inputs joined by NUL, which keeps a field boundary unambiguous.
#[must_use]
pub fn case_input_digest(case: &StdioClassificationCase) -> Sha256Digest {
    let mut preimage = String::new();
    preimage.push_str(case.case_id());
    preimage.push('\0');
    preimage.push_str(policy_token(case.policy()));
    preimage.push('\0');
    preimage.push_str(case.signal().token());
    preimage.push('\0');
    preimage.push_str(case.command());
    for argument in case.args() {
        preimage.push('\0');
        preimage.push_str(argument);
    }
    sha256_bounded(preimage.as_bytes(), MAX_MANIFEST_BYTES)
        .expect("a declared case input stays within its exact byte bound")
}

/// Returns the frozen wire spelling of a policy.
#[must_use]
pub const fn policy_token(policy: ProtocolPolicy) -> &'static str {
    match policy {
        ProtocolPolicy::Auto => "Auto",
        ProtocolPolicy::ModernOnly => "ModernOnly",
        ProtocolPolicy::LegacyOnly => "LegacyOnly",
    }
}

/// The closed set of first-wire signals a disposable probe child may emit.
///
/// Exactly one member — [`Self::CorrelatedDiscoveryRefusal`] — may terminate the
/// probe and authorize a fresh exact-2024 child. Every other member forbids
/// fallback.
///
/// [`Self::UncorrelatedDiscoveryRefusal`] is byte-identical to the eligible
/// signal except for the JSON-RPC response `id`, which is what makes the two a
/// one-variable pair.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StdioFirstWireSignal {
    /// A valid modern discovery result. Selects `2026-07-28`.
    ModernDiscoveryResult,
    /// The frozen eligible signal: a `MethodNotFound` discovery refusal whose
    /// response `id` correlates to the probe request. The only signal that may
    /// reap the probe and start a fresh legacy child.
    CorrelatedDiscoveryRefusal,
    /// The same `MethodNotFound` refusal carrying a different response `id`.
    /// Uncorrelated, so it proves nothing about the peer and never downgrades.
    UncorrelatedDiscoveryRefusal,
    /// A correlated modern JSON-RPC error other than `MethodNotFound`, such as
    /// invalid params. Proof the peer speaks the modern era, never a downgrade.
    RecognizedModernError,
    /// No modern probe is sent at all, as under `LegacyOnly`.
    NoModernProbe,
    /// The planted unsupported `2025-11-25` era. Negative use only; it can
    /// never satisfy a `2026-07-28` or exact-`2024-11-05` positive.
    UnsupportedEraAdvertised,
}

impl StdioFirstWireSignal {
    /// Returns the frozen manifest token for this signal.
    #[must_use]
    pub const fn token(self) -> &'static str {
        match self {
            Self::ModernDiscoveryResult => "modern-discovery-result",
            Self::CorrelatedDiscoveryRefusal => "correlated-discovery-refusal",
            Self::UncorrelatedDiscoveryRefusal => "uncorrelated-discovery-refusal",
            Self::RecognizedModernError => "recognized-modern-error",
            Self::NoModernProbe => "no-modern-probe",
            Self::UnsupportedEraAdvertised => "unsupported-era-advertised",
        }
    }

    /// Whether this signal may authorize a fresh exact-2024 child.
    ///
    /// Only under `Auto`; the policy is checked separately.
    #[must_use]
    pub const fn is_fallback_eligible(self) -> bool {
        matches!(self, Self::CorrelatedDiscoveryRefusal)
    }
}

/// One closed first-wire case declared by the manifest.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StdioClassificationCase {
    case_id: String,
    policy: ProtocolPolicy,
    signal: StdioFirstWireSignal,
    command: String,
    args: Vec<String>,
    trace_path: Option<PathBuf>,
}

impl StdioClassificationCase {
    /// Declares one case. The command and arguments belong to the caller.
    #[must_use]
    pub fn new(
        case_id: impl Into<String>,
        policy: ProtocolPolicy,
        signal: StdioFirstWireSignal,
        command: impl Into<String>,
        args: Vec<String>,
    ) -> Self {
        Self {
            case_id: case_id.into(),
            policy,
            signal,
            command: command.into(),
            args,
            trace_path: None,
        }
    }

    /// Binds the observation trace this case's child appends to.
    #[must_use]
    pub fn with_trace_path(mut self, trace_path: impl Into<PathBuf>) -> Self {
        self.trace_path = Some(trace_path.into());
        self
    }

    /// Returns the frozen case identifier.
    #[must_use]
    pub fn case_id(&self) -> &str {
        &self.case_id
    }

    /// Returns the immutable policy fixed before the first frame.
    #[must_use]
    pub const fn policy(&self) -> ProtocolPolicy {
        self.policy
    }

    /// Returns the declared first-wire signal.
    #[must_use]
    pub const fn signal(&self) -> StdioFirstWireSignal {
        self.signal
    }

    /// Returns the caller-supplied command.
    #[must_use]
    pub fn command(&self) -> &str {
        &self.command
    }

    /// Returns the caller-supplied arguments.
    #[must_use]
    pub fn args(&self) -> &[String] {
        &self.args
    }

    /// Returns the bound observation trace path, if any.
    #[must_use]
    pub fn trace_path(&self) -> Option<&Path> {
        self.trace_path.as_deref()
    }

    /// Whether this case may reach a fresh exact-2024 child.
    #[must_use]
    pub const fn expects_fallback(&self) -> bool {
        matches!(self.policy, ProtocolPolicy::Auto) && self.signal.is_fallback_eligible()
    }
}

/// How the observation trace was read.
///
/// An unreadable trace is a distinct outcome, never an empty one: treating it as
/// "no children spawned" would let an inconclusive observation pass as a clean
/// absence.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TraceOutcome {
    /// No trace path was bound to this case.
    NotBound,
    /// The trace was read and parsed.
    Read,
    /// The trace could not be read. Inconclusive, never an absence.
    Unreadable {
        /// The failure as reported by the filesystem.
        reason: String,
    },
}

/// The credential boundary observed for one case.
///
/// stdio carries no bearer credential at all, so every field is expected to stay
/// zero. Recording it explicitly is what lets a negative assert non-mutation as
/// an observable rather than as an assumption.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct CredentialBoundary {
    /// Credential acquisitions or mutations. Always zero on stdio.
    pub mutations: usize,
    /// Credentials attached to any wire frame. Always zero on stdio.
    pub attached: usize,
}

/// Everything one evaluated case observed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StdioClassificationRecord {
    /// The frozen case identifier.
    pub case_id: String,
    /// The immutable policy fixed before the first frame.
    pub policy: ProtocolPolicy,
    /// Always `stdio` for this evaluator.
    pub transport: &'static str,
    /// The declared first-wire signal.
    pub signal: StdioFirstWireSignal,
    /// Child process identities in spawn order, from the observation trace.
    pub child_pids: Vec<u32>,
    /// Exact first MCP lines read by each child, in spawn order.
    pub first_wire: Vec<String>,
    /// Trace lines that matched no known record, retained verbatim.
    pub unrecognized_trace_records: Vec<String>,
    /// How the trace was read.
    pub trace_outcome: TraceOutcome,
    /// The era the public entrypoint selected, if any.
    pub selected_era: Option<ProtocolEra>,
    /// The negotiated protocol version string, if a session completed.
    pub protocol_version: Option<String>,
    /// Whether the connection attempt succeeded.
    pub connected: bool,
    /// The typed failure message when the attempt did not connect.
    pub failure: Option<String>,
    /// The credential boundary observed. Always zero on stdio.
    pub credential_boundary: CredentialBoundary,
}

impl StdioClassificationRecord {
    /// Number of children observed, which is the child generation count.
    #[must_use]
    pub fn child_generation_count(&self) -> usize {
        self.child_pids.len()
    }

    /// Number of children beyond the first disposable probe.
    ///
    /// Under `Auto` exactly one such child is the exact-2024 fallback; every
    /// other case must observe zero.
    #[must_use]
    pub fn legacy_child_count(&self) -> usize {
        self.child_pids.len().saturating_sub(1)
    }

    /// Whether the disposable probe child was reaped before a fresh child.
    ///
    /// Proven by distinct process identities: a fallback that reused the probe
    /// process would repeat its pid.
    #[must_use]
    pub fn probe_reaped(&self) -> bool {
        match self.child_pids.split_first() {
            Some((probe, rest)) => !rest.is_empty() && rest.iter().all(|pid| pid != probe),
            None => false,
        }
    }
}

/// Drives one closed case through the shipped public stdio entrypoint.
///
/// The caller owns the context. Give every case its own context: `Cx::clone`
/// aliases one cancellation domain rather than creating a child, so a cancelled
/// case would otherwise poison every later case sharing that context.
pub fn evaluate_stdio_case(cx: &Cx, case: &StdioClassificationCase) -> StdioClassificationRecord {
    let plan = ClientProtocolPlan::stdio(case.policy());
    let args: Vec<&str> = case.args().iter().map(String::as_str).collect();

    let outcome = Client::stdio_with_protocol_plan_with_cx(case.command(), &args, plan, cx.clone());

    let (connected, selected_era, protocol_version, failure) = match outcome {
        Ok(mut client) => {
            let era = client.selected_protocol_era();
            let version = client.protocol_version().to_owned();
            // Close the child deterministically rather than leaving it to drop
            // order, so a later case cannot observe this case's process.
            let _ = client.close();
            (true, era, Some(version), None)
        }
        Err(error) => (false, None, None, Some(error.to_string())),
    };

    let (child_pids, first_wire, unrecognized_trace_records, trace_outcome) =
        read_observation_trace(case.trace_path());

    StdioClassificationRecord {
        case_id: case.case_id().to_owned(),
        policy: case.policy(),
        transport: "stdio",
        signal: case.signal(),
        child_pids,
        first_wire,
        unrecognized_trace_records,
        trace_outcome,
        selected_era,
        protocol_version,
        connected,
        failure,
        // stdio has no bearer credential surface at all; the boundary is
        // recorded rather than assumed so negatives can assert on it.
        credential_boundary: CredentialBoundary::default(),
    }
}

/// Reads and parses one observation trace.
///
/// A read failure yields [`TraceOutcome::Unreadable`] with empty records, never
/// a clean empty observation.
fn read_observation_trace(
    trace_path: Option<&Path>,
) -> (Vec<u32>, Vec<String>, Vec<String>, TraceOutcome) {
    let Some(path) = trace_path else {
        return (Vec::new(), Vec::new(), Vec::new(), TraceOutcome::NotBound);
    };
    let contents = match std::fs::read(path) {
        Ok(bytes) if bytes.len() > MAX_TRACE_BYTES => {
            return (
                Vec::new(),
                Vec::new(),
                Vec::new(),
                TraceOutcome::Unreadable {
                    reason: format!(
                        "observation trace exceeds {MAX_TRACE_BYTES} bytes at {} bytes",
                        bytes.len()
                    ),
                },
            );
        }
        Ok(bytes) => bytes,
        Err(error) => {
            return (
                Vec::new(),
                Vec::new(),
                Vec::new(),
                TraceOutcome::Unreadable {
                    reason: error.to_string(),
                },
            );
        }
    };
    let text = match String::from_utf8(contents) {
        Ok(text) => text,
        Err(error) => {
            return (
                Vec::new(),
                Vec::new(),
                Vec::new(),
                TraceOutcome::Unreadable {
                    reason: error.to_string(),
                },
            );
        }
    };

    let mut child_pids = Vec::new();
    let mut first_wire = Vec::new();
    let mut unrecognized = Vec::new();
    for line in text.lines() {
        if line.is_empty() {
            continue;
        }
        if let Some(pid) = line.strip_prefix("spawn:") {
            match pid.trim().parse::<u32>() {
                Ok(pid) => child_pids.push(pid),
                Err(_) => unrecognized.push(line.to_owned()),
            }
        } else if let Some(wire) = line.strip_prefix("wire:") {
            first_wire.push(wire.to_owned());
        } else {
            unrecognized.push(line.to_owned());
        }
    }
    (child_pids, first_wire, unrecognized, TraceOutcome::Read)
}
