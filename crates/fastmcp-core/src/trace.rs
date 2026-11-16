//! Bounded W3C trace metadata admission and independent-field recovery.
//!
//! The grammars follow [Trace Context, sections 3.2–3.3](https://www.w3.org/TR/2021/REC-trace-context-1-20211123/)
//! and [Baggage, section 3.3](https://www.w3.org/TR/2024/CR-baggage-20240530/).
//! The limits are the default OBS-01/LIMIT-01 admission profile. Valid values
//! retain their exact spelling. Admission neither decodes baggage nor grants
//! authority to forward it. [`OutboundTracePolicy`] separately authorizes a
//! bounded projection for one explicitly configured source/destination hop.
//!
//! Incoming optional telemetry uses [`TraceContext::recover`]: malformed trace
//! metadata never becomes an application-protocol error. Local producers use
//! [`TraceContext::try_from_fields`] to reject malformed field combinations.

use std::fmt;

use serde_json::Value;

/// Maximum encoded bytes retained for a traceparent, including a future suffix.
pub const MAX_TRACEPARENT_BYTES: usize = 4 * 1024;
/// Maximum encoded bytes retained for the complete tracestate field.
pub const MAX_TRACESTATE_BYTES: usize = 512;
/// Maximum tracestate list members, including permitted empty members.
pub const MAX_TRACESTATE_MEMBERS: usize = 32;
/// Maximum encoded bytes retained for the complete baggage field.
pub const MAX_BAGGAGE_BYTES: usize = 8 * 1024;
/// Maximum baggage members, including repeated keys.
pub const MAX_BAGGAGE_MEMBERS: usize = 64;

/// Fixed diagnostics for locally constructed trace metadata. No peer data is
/// retained in an error, its display text, or its debug representation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TraceContextError {
    /// A traceparent violates the known-field or version grammar.
    InvalidTraceparent,
    /// A tracestate violates its key/value grammar or repeats a key.
    InvalidTracestate,
    /// A baggage member or property violates the baggage grammar.
    InvalidBaggage,
    /// A tracestate has no valid companion traceparent.
    OrphanedTracestate,
    /// A traceparent exceeds the local encoded-byte bound.
    TraceparentLimitExceeded,
    /// A tracestate exceeds the local encoded-byte or member bound.
    TracestateLimitExceeded,
    /// Baggage exceeds the local encoded-byte or member bound.
    BaggageLimitExceeded,
}

impl fmt::Display for TraceContextError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidTraceparent => "invalid traceparent",
            Self::InvalidTracestate => "invalid tracestate",
            Self::InvalidBaggage => "invalid baggage",
            Self::OrphanedTracestate => "tracestate requires a valid traceparent",
            Self::TraceparentLimitExceeded => "traceparent exceeds its admission limit",
            Self::TracestateLimitExceeded => "tracestate exceeds its admission limit",
            Self::BaggageLimitExceeded => "baggage exceeds its admission limit",
        })
    }
}

impl std::error::Error for TraceContextError {}

/// A bounded report of fields removed during receiver recovery.
///
/// Counts describe discarded fields, never attacker-controlled member counts.
/// An invalid traceparent also removes a present tracestate, but baggage is
/// independent. No rejected value or peer-controlled diagnostic is retained.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct TraceContextRecovery {
    rejected: u8,
}

impl TraceContextRecovery {
    const TRACEPARENT: u8 = 1;
    const TRACESTATE: u8 = 2;
    const BAGGAGE: u8 = 4;

    /// Whether a present traceparent was discarded.
    pub const fn traceparent_rejected(self) -> bool {
        self.rejected & Self::TRACEPARENT != 0
    }

    /// Whether a present tracestate was discarded, including orphaned state.
    pub const fn tracestate_rejected(self) -> bool {
        self.rejected & Self::TRACESTATE != 0
    }

    /// Whether a present baggage field was discarded in its entirety.
    pub const fn baggage_rejected(self) -> bool {
        self.rejected & Self::BAGGAGE != 0
    }

    /// Number of discarded fields, always between zero and three.
    pub const fn rejected_count(self) -> u8 {
        self.rejected.count_ones() as u8
    }

    /// Whether recovery discarded no fields.
    pub const fn is_empty(self) -> bool {
        self.rejected == 0
    }
}

/// Immutable, syntactically admitted W3C trace metadata.
///
/// Baggage may contain sensitive application data. Debug output therefore
/// reveals field presence only; values are available solely through explicit
/// accessors. Syntax admission is neither authentication nor forwarding consent.
#[derive(Clone, Default, Eq, PartialEq)]
pub struct TraceContext {
    traceparent: Option<String>,
    tracestate: Option<String>,
    baggage: Option<String>,
}

impl fmt::Debug for TraceContext {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("TraceContext")
            .field("has_traceparent", &self.traceparent.is_some())
            .field("has_tracestate", &self.tracestate.is_some())
            .field("has_baggage", &self.baggage.is_some())
            .finish()
    }
}

impl TraceContext {
    /// Admits locally supplied fields without normalizing their spelling.
    ///
    /// Tracestate requires a valid traceparent; baggage does not. All validation
    /// and local admission limits are checked before any field is copied.
    pub fn try_from_fields(
        traceparent: Option<&str>,
        tracestate: Option<&str>,
        baggage: Option<&str>,
    ) -> Result<Self, TraceContextError> {
        if let Some(value) = traceparent {
            validate_traceparent(value)?;
        }
        if let Some(value) = tracestate {
            if traceparent.is_none() {
                return Err(TraceContextError::OrphanedTracestate);
            }
            validate_tracestate(value)?;
        }
        if let Some(value) = baggage {
            validate_baggage(value)?;
        }
        Ok(Self {
            traceparent: traceparent.map(str::to_owned),
            tracestate: tracestate.map(str::to_owned),
            baggage: baggage.map(str::to_owned),
        })
    }

    /// Recovers optional peer metadata using the OBS-01 receiver policy.
    ///
    /// Invalid or non-string traceparent removes itself and its tracestate.
    /// Invalid/orphaned tracestate does not invalidate a valid traceparent.
    /// Baggage is independent and is discarded in full on any malformed member
    /// or local limit failure. The caller can use the bounded report to remove
    /// rejected fields from its effective metadata without changing the MCP
    /// request, notification, result, or error.
    pub fn recover(
        traceparent: Option<&Value>,
        tracestate: Option<&Value>,
        baggage: Option<&Value>,
    ) -> (Self, TraceContextRecovery) {
        let mut report = TraceContextRecovery::default();
        let traceparent = recover_field(
            traceparent,
            validate_traceparent,
            TraceContextRecovery::TRACEPARENT,
            &mut report,
        );
        let tracestate = if traceparent.is_some() {
            recover_field(
                tracestate,
                validate_tracestate,
                TraceContextRecovery::TRACESTATE,
                &mut report,
            )
        } else {
            // Do not inspect orphaned vendor state, even if its grammar is valid.
            if tracestate.is_some() {
                report.rejected |= TraceContextRecovery::TRACESTATE;
            }
            None
        };
        let baggage = recover_field(
            baggage,
            validate_baggage,
            TraceContextRecovery::BAGGAGE,
            &mut report,
        );
        (
            Self {
                traceparent: traceparent.map(str::to_owned),
                tracestate: tracestate.map(str::to_owned),
                baggage: baggage.map(str::to_owned),
            },
            report,
        )
    }

    /// Returns the exact admitted traceparent, including opaque future fields.
    pub fn traceparent(&self) -> Option<&str> {
        self.traceparent.as_deref()
    }

    /// Returns the exact admitted tracestate, including permitted whitespace.
    pub fn tracestate(&self) -> Option<&str> {
        self.tracestate.as_deref()
    }

    /// Returns admitted baggage without decoding, sorting, or merging keys.
    pub fn baggage(&self) -> Option<&str> {
        self.baggage.as_deref()
    }

    /// Whether none of the three fields is present.
    pub const fn is_empty(&self) -> bool {
        self.traceparent.is_none() && self.tracestate.is_none() && self.baggage.is_none()
    }
}

/// Maximum exact source/destination rules in one outbound trace policy.
pub const MAX_TRACE_POLICY_RULES: usize = 32;
/// Maximum configured baggage allowlist or additional sensitive-key entries.
pub const MAX_TRACE_POLICY_KEYS: usize = 64;
/// Maximum encoded bytes in a configured baggage or tracestate key.
pub const MAX_TRACE_POLICY_KEY_BYTES: usize = 256;
/// Maximum encoded bytes in a tenant, security-domain, or local peer identity.
pub const MAX_TRACE_SCOPE_BYTES: usize = 256;
/// Maximum input and canonical-output bytes for a network origin identity.
pub const MAX_TRACE_ORIGIN_BYTES: usize = 4 * 1024;

/// Transport identity owned by the connection, never by trace metadata.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TraceTransport {
    /// HTTP requests to the configured MCP endpoint.
    Http,
    /// One already-owned standard-input/output peer.
    Stdio,
    /// One already-owned in-process transport peer.
    Memory,
    /// A WebSocket endpoint or explicitly identified pre-upgraded peer.
    WebSocket,
}

/// A redacted configuration error. Peer values are never retained.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TracePolicyError {
    /// Enabled policies require a nonzero, host-assigned revision.
    InvalidRevision,
    /// The network scheme, transport, origin, or local peer identity is invalid.
    InvalidEndpoint,
    /// A tenant or security-domain identity is empty or outside its bounds.
    InvalidScope,
    /// A configured key does not satisfy its field's grammar or byte bound.
    InvalidKey,
    /// A configured key list exceeds its bounded input cardinality.
    TooManyKeys,
    /// The policy has too many exact hop rules.
    TooManyRules,
    /// Two rules claim the same exact source and destination.
    DuplicateRule,
    /// Per-hop baggage budgets exceed admission bounds or are inconsistent.
    InvalidBaggageLimits,
    /// Vendor state cannot cross a tenant or security-domain boundary.
    TracestateBoundary,
}

impl fmt::Display for TracePolicyError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidRevision => "outbound trace policy requires a nonzero revision",
            Self::InvalidEndpoint => "invalid outbound trace endpoint identity",
            Self::InvalidScope => "invalid outbound trace tenant or security domain",
            Self::InvalidKey => "invalid outbound trace policy key",
            Self::TooManyKeys => "outbound trace policy key limit exceeded",
            Self::TooManyRules => "outbound trace policy rule limit exceeded",
            Self::DuplicateRule => "duplicate outbound trace policy hop",
            Self::InvalidBaggageLimits => "invalid outbound baggage budgets",
            Self::TracestateBoundary => "tracestate cannot cross a tenant or security domain",
        })
    }
}

impl std::error::Error for TracePolicyError {}

/// Host-supplied identity of one side of a trace propagation hop.
///
/// The transport owner must bind this identity to its actual connection. In
/// particular, HTTP clients compare the canonical origin against their selected
/// endpoint; local transports bind an explicit peer identity to the already
/// owned connection. Tenant and security-domain labels come from trusted host
/// configuration or independently verified authority, never caller trace fields.
/// This type describes a policy partition; it grants no authentication authority.
#[derive(Clone, Eq, PartialEq)]
pub struct TraceEndpoint {
    transport: TraceTransport,
    origin: String,
    network: bool,
    tenant: String,
    security_domain: String,
}

impl fmt::Debug for TraceEndpoint {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("TraceEndpoint")
            .field("transport", &self.transport)
            .field("network_origin", &self.network)
            .finish_non_exhaustive()
    }
}

impl TraceEndpoint {
    /// Canonicalizes the origin of an HTTP(S) or WS(S) endpoint. Paths, queries,
    /// and fragments do not become policy identities; credentials and raw
    /// ASCII controls/whitespace are refused before URL normalization.
    pub fn network(
        transport: TraceTransport,
        endpoint: &str,
        tenant: &str,
        security_domain: &str,
    ) -> Result<Self, TracePolicyError> {
        validate_trace_scope(tenant)?;
        validate_trace_scope(security_domain)?;
        if endpoint.is_empty()
            || endpoint.len() > MAX_TRACE_ORIGIN_BYTES
            || endpoint
                .bytes()
                .any(|byte| byte.is_ascii_control() || byte.is_ascii_whitespace())
        {
            return Err(TracePolicyError::InvalidEndpoint);
        }
        let url = url::Url::parse(endpoint).map_err(|_| TracePolicyError::InvalidEndpoint)?;
        let scheme_allowed = match transport {
            TraceTransport::Http => matches!(url.scheme(), "http" | "https"),
            TraceTransport::WebSocket => matches!(url.scheme(), "ws" | "wss"),
            TraceTransport::Stdio | TraceTransport::Memory => false,
        };
        if !scheme_allowed
            || url.host().is_none()
            || !url.username().is_empty()
            || url.password().is_some()
        {
            return Err(TracePolicyError::InvalidEndpoint);
        }
        let origin = url.origin().ascii_serialization();
        if origin.len() > MAX_TRACE_ORIGIN_BYTES || origin == "null" {
            return Err(TracePolicyError::InvalidEndpoint);
        }
        Ok(Self {
            transport,
            origin,
            network: true,
            tenant: tenant.to_owned(),
            security_domain: security_domain.to_owned(),
        })
    }

    /// Binds a bounded, opaque host-assigned identity to a local or
    /// pre-upgraded peer. This does not attest to a WebSocket's network origin.
    pub fn local(
        transport: TraceTransport,
        peer_id: &str,
        tenant: &str,
        security_domain: &str,
    ) -> Result<Self, TracePolicyError> {
        validate_trace_scope(tenant)?;
        validate_trace_scope(security_domain)?;
        if transport == TraceTransport::Http || validate_trace_scope(peer_id).is_err() {
            return Err(TracePolicyError::InvalidEndpoint);
        }
        Ok(Self {
            transport,
            origin: peer_id.to_owned(),
            network: false,
            tenant: tenant.to_owned(),
            security_domain: security_domain.to_owned(),
        })
    }

    /// The independently selected transport.
    pub const fn transport(&self) -> TraceTransport {
        self.transport
    }
    /// Canonical network origin or opaque local peer identity.
    pub fn origin(&self) -> &str {
        &self.origin
    }
    /// The canonical origin, only when a network URL established this identity.
    pub fn network_origin(&self) -> Option<&str> {
        self.network.then_some(self.origin.as_str())
    }
    /// Host-owned tenant partition.
    pub fn tenant(&self) -> &str {
        &self.tenant
    }
    /// Host-owned security-domain partition.
    pub fn security_domain(&self) -> &str {
        &self.security_domain
    }
}

fn validate_trace_scope(value: &str) -> Result<(), TracePolicyError> {
    if value.is_empty()
        || value.len() > MAX_TRACE_SCOPE_BYTES
        || !value.bytes().all(|byte| byte.is_ascii_graphic())
    {
        return Err(TracePolicyError::InvalidScope);
    }
    Ok(())
}

/// Fresh limits applied after allowlist and sensitive-key filtering on each hop.
/// Repeated keys consume member budget, but share one distinct-key slot.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BaggageForwardingLimits {
    bytes: usize,
    members: usize,
    distinct_keys: usize,
}

impl Default for BaggageForwardingLimits {
    fn default() -> Self {
        Self {
            bytes: MAX_BAGGAGE_BYTES,
            members: MAX_BAGGAGE_MEMBERS,
            distinct_keys: MAX_BAGGAGE_MEMBERS,
        }
    }
}

impl BaggageForwardingLimits {
    /// Constructs positive limits no larger than the inbound admission profile.
    pub fn new(
        max_bytes: usize,
        max_members: usize,
        max_distinct_keys: usize,
    ) -> Result<Self, TracePolicyError> {
        if max_bytes == 0
            || max_bytes > MAX_BAGGAGE_BYTES
            || max_members == 0
            || max_members > MAX_BAGGAGE_MEMBERS
            || max_distinct_keys == 0
            || max_distinct_keys > max_members
        {
            return Err(TracePolicyError::InvalidBaggageLimits);
        }
        Ok(Self {
            bytes: max_bytes,
            members: max_members,
            distinct_keys: max_distinct_keys,
        })
    }
}

/// One explicit, exact source/destination forwarding rule. New rules drop every
/// field until its forwarding method is called. No wildcard hop matching exists.
#[derive(Clone, Eq, PartialEq)]
pub struct TracePropagationRule {
    source: TraceEndpoint,
    destination: TraceEndpoint,
    traceparent: bool,
    tracestate_keys: Vec<String>,
    baggage_keys: Vec<String>,
    baggage_limits: BaggageForwardingLimits,
}

impl fmt::Debug for TracePropagationRule {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("TracePropagationRule")
            .field("continue_traceparent", &self.traceparent)
            .field("tracestate_key_count", &self.tracestate_keys.len())
            .field("baggage_key_count", &self.baggage_keys.len())
            .field("baggage_limits", &self.baggage_limits)
            .finish_non_exhaustive()
    }
}

impl TracePropagationRule {
    /// Starts with an exact host-approved hop and no forwarded fields.
    pub fn new(source: TraceEndpoint, destination: TraceEndpoint) -> Self {
        Self {
            source,
            destination,
            traceparent: false,
            tracestate_keys: Vec::new(),
            baggage_keys: Vec::new(),
            baggage_limits: BaggageForwardingLimits::default(),
        }
    }

    /// Permits continuation of the admitted traceparent, including opaque
    /// future-version fields. This rule does not generate or mutate trace IDs.
    #[must_use]
    pub fn with_traceparent(mut self) -> Self {
        self.traceparent = true;
        self
    }

    /// Permits only named vendors' state within the same tenant and security
    /// domain. A different origin still requires this explicit vendor allowlist.
    /// Tracestate is emitted only alongside a forwarded valid traceparent.
    pub fn with_tracestate_keys<I, S>(mut self, keys: I) -> Result<Self, TracePolicyError>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        if self.source.tenant != self.destination.tenant
            || self.source.security_domain != self.destination.security_domain
        {
            return Err(TracePolicyError::TracestateBoundary);
        }
        self.tracestate_keys =
            collect_policy_keys(keys, valid_tracestate_key, MAX_TRACESTATE_MEMBERS)?;
        Ok(self)
    }

    /// Allows specific baggage keys, subject to the policy's sensitive denylist
    /// and fresh per-hop budgets. No baggage is allowed merely by valid syntax.
    pub fn with_baggage_keys<I, S>(
        mut self,
        keys: I,
        limits: BaggageForwardingLimits,
    ) -> Result<Self, TracePolicyError>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        self.baggage_keys = collect_policy_keys(keys, valid_baggage_key, MAX_TRACE_POLICY_KEYS)?;
        self.baggage_limits = limits;
        Ok(self)
    }
}

fn collect_policy_keys<I, S>(
    keys: I,
    valid: fn(&str) -> bool,
    max_keys: usize,
) -> Result<Vec<String>, TracePolicyError>
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    let mut admitted = Vec::new();
    for (index, key) in keys.into_iter().enumerate() {
        if index >= max_keys {
            return Err(TracePolicyError::TooManyKeys);
        }
        let key = key.as_ref();
        if key.len() > MAX_TRACE_POLICY_KEY_BYTES || !valid(key) {
            return Err(TracePolicyError::InvalidKey);
        }
        admitted.push(key.to_owned());
    }
    admitted.sort();
    admitted.dedup();
    Ok(admitted)
}

/// Immutable versioned outbound policy. The default is disabled; an enabled
/// policy has a nonzero host-managed revision and an explicit list of hops.
/// Policy revisions must change whenever a deployed policy changes. Trace
/// policy decisions cannot grant authorization, select credentials, or change
/// application routing, protocol versions, or transport selection.
#[derive(Clone, Default, Eq, PartialEq)]
pub struct OutboundTracePolicy {
    revision: u64,
    rules: Vec<TracePropagationRule>,
    sensitive_baggage_keys: Vec<String>,
}

impl fmt::Debug for OutboundTracePolicy {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("OutboundTracePolicy")
            .field("revision", &self.revision)
            .field("rule_count", &self.rules.len())
            .field("sensitive_key_count", &self.sensitive_baggage_keys.len())
            .finish_non_exhaustive()
    }
}

impl OutboundTracePolicy {
    /// Creates a policy with no permitted hops under an explicit nonzero revision.
    pub fn new(revision: u64) -> Result<Self, TracePolicyError> {
        if revision == 0 {
            return Err(TracePolicyError::InvalidRevision);
        }
        Ok(Self {
            revision,
            ..Self::default()
        })
    }

    /// Adds one exact hop; duplicate hops are refused instead of depending on
    /// rule order. Source and destination transports may differ explicitly.
    pub fn with_rule(mut self, rule: TracePropagationRule) -> Result<Self, TracePolicyError> {
        if self.revision == 0 {
            return Err(TracePolicyError::InvalidRevision);
        }
        if self.rules.len() == MAX_TRACE_POLICY_RULES {
            return Err(TracePolicyError::TooManyRules);
        }
        if self.rules.iter().any(|existing| {
            existing.source == rule.source && existing.destination == rule.destination
        }) {
            return Err(TracePolicyError::DuplicateRule);
        }
        self.rules.push(rule);
        Ok(self)
    }

    /// Adds configured sensitive keys. Denial is case-insensitive and runs
    /// after the case-sensitive allowlist. A sensitive entry or property key
    /// drops its entire member. Common credential keys are always denied;
    /// this configuration cannot override that protection.
    pub fn with_sensitive_baggage_keys<I, S>(mut self, keys: I) -> Result<Self, TracePolicyError>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        let additional = collect_policy_keys(keys, valid_baggage_key, MAX_TRACE_POLICY_KEYS)?;
        for key in additional {
            let key = key.to_ascii_lowercase();
            if !self.sensitive_baggage_keys.contains(&key) {
                if self.sensitive_baggage_keys.len() == MAX_TRACE_POLICY_KEYS {
                    return Err(TracePolicyError::TooManyKeys);
                }
                self.sensitive_baggage_keys.push(key);
            }
        }
        self.sensitive_baggage_keys.sort();
        Ok(self)
    }

    /// The immutable host-assigned policy revision; zero denotes disabled.
    pub const fn revision(&self) -> u64 {
        self.revision
    }

    /// Evaluates a host-bound hop for the exact final MCP revision. Unknown or
    /// legacy revisions, disabled policies, and unmatched hops emit no tracing;
    /// none can change the application operation's success or failure.
    ///
    /// Every output re-enters the common W3C constructor. Baggage and vendor
    /// state are filtered without decoding values, merging duplicate baggage
    /// keys, or discarding permitted properties. Exceeding a fresh baggage
    /// budget drops the entire selected baggage field. Any emitted context
    /// requires the caller to bypass reusable result caches for that operation.
    pub fn evaluate(
        &self,
        source: &TraceEndpoint,
        destination: &TraceEndpoint,
        context: &TraceContext,
        protocol_version: &str,
    ) -> OutboundTraceDecision {
        let mut outcome = TracePolicyOutcome::Applied;
        let mut output = TraceContext::default();
        let mut baggage_budget_exceeded = false;
        if self.revision == 0 {
            outcome = TracePolicyOutcome::Disabled;
        } else if protocol_version != "2026-07-28" {
            outcome = TracePolicyOutcome::UnsupportedProtocol;
        } else if let Some(rule) = self
            .rules
            .iter()
            .find(|rule| &rule.source == source && &rule.destination == destination)
        {
            let parent = if rule.traceparent {
                context.traceparent()
            } else {
                None
            };
            let state = if parent.is_some() {
                context
                    .tracestate()
                    .and_then(|state| filter_tracestate(state, &rule.tracestate_keys))
            } else {
                None
            };
            let baggage = context.baggage().and_then(|baggage| {
                let (filtered, exceeded) =
                    filter_baggage(baggage, rule, &self.sensitive_baggage_keys);
                baggage_budget_exceeded = exceeded;
                filtered
            });
            match TraceContext::try_from_fields(parent, state.as_deref(), baggage.as_deref()) {
                Ok(admitted) => output = admitted,
                Err(_) => outcome = TracePolicyOutcome::InvalidProjection,
            }
        } else {
            outcome = TracePolicyOutcome::UnmatchedHop;
        }
        let input_state = state_member_count(context.tracestate());
        let output_state = state_member_count(output.tracestate());
        let input_baggage = baggage_member_count(context.baggage());
        let output_baggage = baggage_member_count(output.baggage());
        let input_fields = trace_field_count(context);
        let output_fields = trace_field_count(&output);
        OutboundTraceDecision {
            source: source.clone(),
            destination: destination.clone(),
            context: output,
            diagnostic: TracePolicyDiagnostic {
                revision: self.revision,
                outcome,
                forwarded_fields: output_fields,
                dropped_fields: input_fields.saturating_sub(output_fields),
                tracestate_members_forwarded: output_state,
                tracestate_members_dropped: input_state.saturating_sub(output_state),
                baggage_members_forwarded: output_baggage,
                baggage_members_dropped: input_baggage.saturating_sub(output_baggage),
                baggage_budget_exceeded,
            },
        }
    }
}

/// Fixed, redacted outcome category for one outbound propagation decision.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TracePolicyOutcome {
    /// No enabled policy was installed.
    Disabled,
    /// Trace propagation is not defined by this policy for the selected revision.
    UnsupportedProtocol,
    /// No exact source/destination rule approved this hop.
    UnmatchedHop,
    /// An exact rule was applied, including its explicit field drops.
    Applied,
    /// A local projection failed final W3C validation and was discarded in full.
    InvalidProjection,
}

/// Bounded policy revision and keep/drop counts, without trace values, vendor
/// keys, baggage keys, tenant identities, or origin strings.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TracePolicyDiagnostic {
    revision: u64,
    outcome: TracePolicyOutcome,
    forwarded_fields: u8,
    dropped_fields: u8,
    tracestate_members_forwarded: u8,
    tracestate_members_dropped: u8,
    baggage_members_forwarded: u8,
    baggage_members_dropped: u8,
    baggage_budget_exceeded: bool,
}

impl TracePolicyDiagnostic {
    /// Host-assigned policy revision used for this decision.
    pub const fn revision(&self) -> u64 {
        self.revision
    }
    /// Fixed policy outcome, never a peer-supplied diagnostic.
    pub const fn outcome(&self) -> TracePolicyOutcome {
        self.outcome
    }
    /// Number of complete trace fields emitted, between zero and three.
    pub const fn forwarded_fields(&self) -> u8 {
        self.forwarded_fields
    }
    /// Number of input fields wholly omitted from this hop.
    pub const fn dropped_fields(&self) -> u8 {
        self.dropped_fields
    }
    /// Number of nonempty vendor entries forwarded.
    pub const fn tracestate_members_forwarded(&self) -> u8 {
        self.tracestate_members_forwarded
    }
    /// Number of nonempty vendor entries omitted.
    pub const fn tracestate_members_dropped(&self) -> u8 {
        self.tracestate_members_dropped
    }
    /// Number of baggage members forwarded, counting duplicate keys.
    pub const fn baggage_members_forwarded(&self) -> u8 {
        self.baggage_members_forwarded
    }
    /// Number of baggage members omitted, counting duplicate keys.
    pub const fn baggage_members_dropped(&self) -> u8 {
        self.baggage_members_dropped
    }
    /// Whether a fresh per-hop byte, member, or distinct-key budget was exceeded.
    pub const fn baggage_budget_exceeded(&self) -> bool {
        self.baggage_budget_exceeded
    }
}

/// A policy-approved, endpoint-bound trace projection. Only policy evaluation
/// can construct it; raw metadata cannot become an outbound decision.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OutboundTraceDecision {
    source: TraceEndpoint,
    destination: TraceEndpoint,
    context: TraceContext,
    diagnostic: TracePolicyDiagnostic,
}

impl OutboundTraceDecision {
    /// Validated fields approved for this exact hop.
    pub fn context(&self) -> &TraceContext {
        &self.context
    }
    /// Source identity to which the decision was bound.
    pub fn source(&self) -> &TraceEndpoint {
        &self.source
    }
    /// Destination identity the transport must verify before sending.
    pub fn destination(&self) -> &TraceEndpoint {
        &self.destination
    }
    /// The applied host-assigned policy revision.
    pub const fn revision(&self) -> u64 {
        self.diagnostic.revision
    }
    /// Redacted keep/drop evidence suitable for diagnostics.
    pub const fn diagnostic(&self) -> &TracePolicyDiagnostic {
        &self.diagnostic
    }
    /// All emitted context may affect the peer's result. Until a caller supplies
    /// a safe policy-specific cache projection, traced results are uncacheable.
    pub const fn requires_uncacheable_response(&self) -> bool {
        !self.context.is_empty()
    }
}

fn key_is_allowed(keys: &[String], key: &str) -> bool {
    keys.binary_search_by(|configured| configured.as_str().cmp(key))
        .is_ok()
}

fn filter_tracestate(value: &str, allowed: &[String]) -> Option<String> {
    let retained: Vec<_> = value
        .split(',')
        .map(trim_ows)
        .filter(|member| {
            member
                .split_once('=')
                .is_some_and(|(key, _)| key_is_allowed(allowed, key))
        })
        .collect();
    (!retained.is_empty()).then(|| retained.join(","))
}

fn sensitive_baggage_key(key: &str, configured: &[String]) -> bool {
    const CREDENTIAL_KEYS: &[&str] = &[
        "authorization",
        "proxy-authorization",
        "cookie",
        "set-cookie",
        "password",
        "passwd",
        "secret",
        "client_secret",
        "client-secret",
        "token",
        "access_token",
        "access-token",
        "refresh_token",
        "refresh-token",
        "id_token",
        "id-token",
        "api_key",
        "api-key",
        "apikey",
        "credential",
        "credentials",
        "session",
        "session_id",
        "session-id",
    ];
    CREDENTIAL_KEYS
        .iter()
        .any(|denied| key.eq_ignore_ascii_case(denied))
        || configured
            .iter()
            .any(|denied| key.eq_ignore_ascii_case(denied))
}

fn filter_baggage(
    value: &str,
    rule: &TracePropagationRule,
    denied: &[String],
) -> (Option<String>, bool) {
    let mut retained = Vec::new();
    let mut distinct = Vec::new();
    let mut bytes = 0;
    for member in value.split(',').map(trim_ows) {
        let Some((key, _)) = member.split_once('=') else {
            return (None, true);
        };
        let key = trim_ows(key);
        if !key_is_allowed(&rule.baggage_keys, key)
            || sensitive_baggage_key(key, denied)
            || member.split(';').skip(1).any(|property| {
                let property = trim_ows(property);
                let key = property
                    .split_once('=')
                    .map_or(property, |(key, _)| trim_ows(key));
                sensitive_baggage_key(key, denied)
            })
        {
            continue;
        }
        let new_key = !distinct.contains(&key);
        let additional_bytes = member.len() + usize::from(!retained.is_empty());
        if retained.len() == rule.baggage_limits.members
            || bytes + additional_bytes > rule.baggage_limits.bytes
            || (new_key && distinct.len() == rule.baggage_limits.distinct_keys)
        {
            return (None, true);
        }
        bytes += additional_bytes;
        if new_key {
            distinct.push(key);
        }
        retained.push(member);
    }
    ((!retained.is_empty()).then(|| retained.join(",")), false)
}

fn state_member_count(value: Option<&str>) -> u8 {
    value.map_or(0, |value| {
        value
            .split(',')
            .filter(|member| !trim_ows(member).is_empty())
            .count() as u8
    })
}

fn baggage_member_count(value: Option<&str>) -> u8 {
    value.map_or(0, |value| value.split(',').count() as u8)
}

fn trace_field_count(context: &TraceContext) -> u8 {
    u8::from(context.traceparent.is_some())
        + u8::from(context.tracestate.is_some())
        + u8::from(context.baggage.is_some())
}

fn recover_field<'a>(
    value: Option<&'a Value>,
    validate: fn(&str) -> Result<(), TraceContextError>,
    rejected_bit: u8,
    report: &mut TraceContextRecovery,
) -> Option<&'a str> {
    let value = value?;
    match value.as_str() {
        Some(value) if validate(value).is_ok() => Some(value),
        _ => {
            report.rejected |= rejected_bit;
            None
        }
    }
}

fn validate_traceparent(value: &str) -> Result<(), TraceContextError> {
    if value.len() > MAX_TRACEPARENT_BYTES {
        return Err(TraceContextError::TraceparentLimitExceeded);
    }
    let bytes = value.as_bytes();
    if bytes.len() < 55
        || !bytes[..2].iter().copied().all(is_lower_hex)
        || &bytes[..2] == b"ff"
        || bytes[2] != b'-'
        || bytes[35] != b'-'
        || bytes[52] != b'-'
        || !bytes[3..35].iter().copied().all(is_lower_hex)
        || bytes[3..35].iter().all(|byte| *byte == b'0')
        || !bytes[36..52].iter().copied().all(is_lower_hex)
        || bytes[36..52].iter().all(|byte| *byte == b'0')
        || !bytes[53..55].iter().copied().all(is_lower_hex)
    {
        return Err(TraceContextError::InvalidTraceparent);
    }
    if &bytes[..2] == b"00" {
        if bytes.len() != 55 {
            return Err(TraceContextError::InvalidTraceparent);
        }
    } else if bytes.len() > 55 && bytes[55] != b'-' {
        return Err(TraceContextError::InvalidTraceparent);
    }
    // An unknown version's suffix is opaque: do not invent a field grammar or
    // require hexadecimal extensions. Keep only the US-ASCII HTTP field-value
    // boundary (visible characters, space, and horizontal tab). Other control
    // characters and non-ASCII text cannot be part of this representation.
    if !bytes
        .iter()
        .all(|byte| matches!(*byte, b'\t' | 0x20..=0x7e))
    {
        return Err(TraceContextError::InvalidTraceparent);
    }
    Ok(())
}

fn is_lower_hex(byte: u8) -> bool {
    byte.is_ascii_digit() || matches!(byte, b'a'..=b'f')
}

fn trim_ows(value: &str) -> &str {
    value.trim_matches([' ', '\t'])
}

fn validate_tracestate(value: &str) -> Result<(), TraceContextError> {
    if value.len() > MAX_TRACESTATE_BYTES {
        return Err(TraceContextError::TracestateLimitExceeded);
    }
    let mut keys = [""; MAX_TRACESTATE_MEMBERS];
    for (index, member) in value.split(',').enumerate() {
        if index >= MAX_TRACESTATE_MEMBERS {
            return Err(TraceContextError::TracestateLimitExceeded);
        }
        let member = trim_ows(member);
        if member.is_empty() {
            continue;
        }
        let (key, value) = member
            .split_once('=')
            .ok_or(TraceContextError::InvalidTracestate)?;
        if !valid_tracestate_key(key)
            || keys.contains(&key)
            || value.is_empty()
            || value.len() > 256
            || !value
                .bytes()
                .all(|byte| matches!(byte, 0x20..=0x2b | 0x2d..=0x3c | 0x3e..=0x7e))
        {
            return Err(TraceContextError::InvalidTracestate);
        }
        keys[index] = key;
    }
    Ok(())
}

fn valid_tracestate_key(value: &str) -> bool {
    let permitted = |byte: u8| {
        byte.is_ascii_lowercase()
            || byte.is_ascii_digit()
            || matches!(byte, b'_' | b'-' | b'*' | b'/')
    };
    if let Some((tenant, system)) = value.split_once('@') {
        !tenant.is_empty()
            && tenant.len() <= 241
            && (tenant.as_bytes()[0].is_ascii_lowercase() || tenant.as_bytes()[0].is_ascii_digit())
            && tenant.bytes().all(permitted)
            && !system.is_empty()
            && system.len() <= 14
            && system.as_bytes()[0].is_ascii_lowercase()
            && system.bytes().all(permitted)
    } else {
        !value.is_empty()
            && value.len() <= 256
            && value.as_bytes()[0].is_ascii_lowercase()
            && value.bytes().all(permitted)
    }
}

fn validate_baggage(value: &str) -> Result<(), TraceContextError> {
    if value.len() > MAX_BAGGAGE_BYTES {
        return Err(TraceContextError::BaggageLimitExceeded);
    }
    for (index, member) in value.split(',').enumerate() {
        if index >= MAX_BAGGAGE_MEMBERS {
            return Err(TraceContextError::BaggageLimitExceeded);
        }
        let mut parts = member.split(';');
        let (key, value) = parts
            .next()
            .and_then(|part| part.split_once('='))
            .ok_or(TraceContextError::InvalidBaggage)?;
        if !valid_baggage_key(trim_ows(key)) || !valid_baggage_value(trim_ows(value)) {
            return Err(TraceContextError::InvalidBaggage);
        }
        for property in parts {
            let property = trim_ows(property);
            let valid = match property.split_once('=') {
                Some((key, value)) => {
                    valid_baggage_key(trim_ows(key)) && valid_baggage_value(trim_ows(value))
                }
                None => valid_baggage_key(property),
            };
            if !valid {
                return Err(TraceContextError::InvalidBaggage);
            }
        }
    }
    Ok(())
}

fn valid_baggage_key(value: &str) -> bool {
    !value.is_empty()
        && value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric()
                || matches!(
                    byte,
                    b'!' | b'#'
                        | b'$'
                        | b'%'
                        | b'&'
                        | b'\''
                        | b'*'
                        | b'+'
                        | b'-'
                        | b'.'
                        | b'^'
                        | b'_'
                        | b'`'
                        | b'|'
                        | b'~'
                )
        })
}

fn valid_baggage_value(value: &str) -> bool {
    let bytes = value.as_bytes();
    let mut index = 0;
    while let Some(&byte) = bytes.get(index) {
        if byte == b'%' {
            // The value grammar permits encoded octets, including invalid UTF-8
            // octets. We preserve them; a decoder must apply W3C replacement.
            if !bytes.get(index + 1).is_some_and(u8::is_ascii_hexdigit)
                || !bytes.get(index + 2).is_some_and(u8::is_ascii_hexdigit)
            {
                return false;
            }
            index += 3;
        } else {
            if !matches!(byte, 0x21 | 0x23..=0x2b | 0x2d..=0x3a | 0x3c..=0x5b | 0x5d..=0x7e) {
                return false;
            }
            index += 1;
        }
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    const PARENT: &str = "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01";

    #[test]
    fn obs_01_traceparent_known_fields_and_future_suffix_corpus() {
        for parent in [
            PARENT,
            "00-00000000000000000000000000000001-0000000000000001-00",
            "00-ffffffffffffffffffffffffffffffff-ffffffffffffffff-ff",
            "cc-12345678901234567890123456789012-1234567890123456-01",
            "cc-12345678901234567890123456789012-1234567890123456-09-opaque=Future.Value",
            "01-12345678901234567890123456789012-1234567890123456-01-",
            "fe-12345678901234567890123456789012-1234567890123456-ff-a--b;value with space",
            "01-12345678901234567890123456789012-1234567890123456-01-future\tfield",
        ] {
            let context = TraceContext::try_from_fields(Some(parent), None, None).unwrap();
            assert_eq!(context.traceparent(), Some(parent));
        }
    }

    #[test]
    fn obs_01_traceparent_rejects_one_invalid_known_dimension() {
        for parent in [
            "",
            "ff-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01",
            "FF-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01",
            "0g-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01",
            "0-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01",
            "000-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01",
            "00-00000000000000000000000000000000-00f067aa0ba902b7-01",
            "00-4bf92f3577b34da6a3ce929d0e0e4736-0000000000000000-01",
            "00-4BF92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01",
            "00-4bf92f3577b34da6a3ce929d0e0e4736-00F067aa0ba902b7-01",
            "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-0A",
            "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-0",
            "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01-future",
            "cc-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01.future",
            "cc-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01-\r\nsecret",
            "cc-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01-\0secret",
            "cc-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01-\x7fsecret",
            "cc-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01-é",
        ] {
            assert_eq!(
                TraceContext::try_from_fields(Some(parent), None, None),
                Err(TraceContextError::InvalidTraceparent)
            );
        }
    }

    #[test]
    fn obs_01_traceparent_byte_limit_is_exact() {
        let prefix = "01-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01-";
        let parent = format!(
            "{prefix}{}",
            "x".repeat(MAX_TRACEPARENT_BYTES - prefix.len())
        );
        assert!(TraceContext::try_from_fields(Some(&parent), None, None).is_ok());
        assert_eq!(
            TraceContext::try_from_fields(Some(&(parent + "x")), None, None),
            Err(TraceContextError::TraceparentLimitExceeded)
        );
    }

    #[test]
    fn obs_01_tracestate_accepts_ows_empty_members_and_tenant_keys() {
        for state in [
            "",
            " \t ",
            ",",
            " \t,rojo=00f067aa0ba902b7, \t,congo=t61rcWkgMzE,",
            "\trojo=leading and interior spaces \t",
            "rojo= leading space",
            "123tenant@vendor=value",
            "a_1-*/=b",
            "a=!*+:/@[]\\?^`{|}~",
        ] {
            let context = TraceContext::try_from_fields(Some(PARENT), Some(state), None).unwrap();
            assert_eq!(context.tracestate(), Some(state));
        }
        assert!(
            TraceContext::try_from_fields(
                Some(PARENT),
                Some(&format!("{}=v", "a".repeat(256))),
                None
            )
            .is_ok()
        );
        assert!(
            TraceContext::try_from_fields(
                Some(PARENT),
                Some(&format!("{}@{}=v", "1".repeat(241), "a".repeat(14))),
                None
            )
            .is_ok()
        );
    }

    #[test]
    fn obs_01_tracestate_rejects_duplicates_and_invalid_member_grammar() {
        for state in [
            "a=1,a=2",
            "a=1, \ta=2",
            "a",
            "a=",
            "a= \t ",
            "a =b",
            "a\t=b",
            "a=b=c",
            "a=b\tc",
            "a=b\nc",
            "a=é",
            "=b",
            "A=b",
            "1=b",
            "_a=b",
            "a.b=c",
            "a@b@c=d",
            "a@1=b",
            "@b=c",
            "a@=b",
            "a=b,broken",
        ] {
            assert_eq!(
                TraceContext::try_from_fields(Some(PARENT), Some(state), None),
                Err(TraceContextError::InvalidTracestate)
            );
        }
        for state in [
            format!("{}=b", "a".repeat(257)),
            format!("{}@b=c", "a".repeat(242)),
            format!("a@{}=b", "a".repeat(15)),
            format!("a={}", "b".repeat(257)),
        ] {
            assert_eq!(
                TraceContext::try_from_fields(Some(PARENT), Some(&state), None),
                Err(TraceContextError::InvalidTracestate)
            );
        }
    }

    #[test]
    fn obs_01_tracestate_member_and_byte_limits_are_exact() {
        let members = (0..MAX_TRACESTATE_MEMBERS)
            .map(|index| format!("k{index}=v"))
            .collect::<Vec<_>>()
            .join(",");
        assert!(TraceContext::try_from_fields(Some(PARENT), Some(&members), None).is_ok());
        assert_eq!(
            TraceContext::try_from_fields(Some(PARENT), Some(&(members + ",extra=v")), None),
            Err(TraceContextError::TracestateLimitExceeded)
        );
        let empty = ",".repeat(MAX_TRACESTATE_MEMBERS - 1);
        assert!(TraceContext::try_from_fields(Some(PARENT), Some(&empty), None).is_ok());
        assert_eq!(
            TraceContext::try_from_fields(Some(PARENT), Some(&(empty + ",")), None),
            Err(TraceContextError::TracestateLimitExceeded)
        );
        let state = format!("a={},b={}", "x".repeat(256), "y".repeat(251));
        assert_eq!(state.len(), MAX_TRACESTATE_BYTES);
        assert!(TraceContext::try_from_fields(Some(PARENT), Some(&state), None).is_ok());
        assert_eq!(
            TraceContext::try_from_fields(Some(PARENT), Some(&(state + "y")), None),
            Err(TraceContextError::TracestateLimitExceeded)
        );
    }

    #[test]
    fn obs_01_baggage_accepts_duplicates_properties_and_encoded_octets() {
        for baggage in [
            "key=value",
            "key=",
            "key=value,key=other",
            "key1=value1;property1;property2, key2 = value2, key3=value3; propertyKey=propertyValue",
            " \tKEY = value\t ; flag \t ; key = a=b== \t ",
            "key=;empty=;flag;flag;empty=next",
            "key=Am%C3%A9lie,percent=%25,binary=%ff,lower=%c3%a9",
            "!#$%&'*+-.^_`|~=!#$&'()*+-./0123456789:<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[]^_`{|}~",
        ] {
            let context = TraceContext::try_from_fields(None, None, Some(baggage)).unwrap();
            assert_eq!(context.baggage(), Some(baggage));
            assert!(context.traceparent().is_none());
        }
    }

    #[test]
    fn obs_01_baggage_rejects_one_malformed_member_or_property() {
        for baggage in [
            "",
            " \t ",
            "key",
            "=value",
            ",key=value",
            "key=value,",
            "key=value,,other=value",
            "key=has space",
            "key=has\ttab",
            "key=\"quoted\"",
            "key=back\\slash",
            "key=é",
            "key=\n",
            "key=%",
            "key=%0",
            "key=%xy",
            "key=%2g",
            "key=value;",
            "key=value;;flag",
            "key=value;=bad",
            "key=value;bad key",
            "key=value;prop=has space",
            "key=value;prop=%",
            "bad:key=value",
            "key=value,otherwise=good;bad=\"quoted\"",
        ] {
            assert_eq!(
                TraceContext::try_from_fields(None, None, Some(baggage)),
                Err(TraceContextError::InvalidBaggage)
            );
        }
    }

    #[test]
    fn obs_01_baggage_member_and_byte_limits_are_exact() {
        let members = vec!["key=value"; MAX_BAGGAGE_MEMBERS].join(",");
        assert!(TraceContext::try_from_fields(None, None, Some(&members)).is_ok());
        assert_eq!(
            TraceContext::try_from_fields(None, None, Some(&(members + ",key=value"))),
            Err(TraceContextError::BaggageLimitExceeded)
        );
        let baggage = format!("k={}", "x".repeat(MAX_BAGGAGE_BYTES - 2));
        assert!(TraceContext::try_from_fields(None, None, Some(&baggage)).is_ok());
        assert_eq!(
            TraceContext::try_from_fields(None, None, Some(&(baggage + "x"))),
            Err(TraceContextError::BaggageLimitExceeded)
        );
    }

    #[test]
    fn obs_01_recovery_retains_only_independently_valid_fields() {
        let parent = json!(PARENT);
        let state = json!("a=1");
        let baggage = json!("key=value;property");
        let invalid = json!("secret-invalid-field");
        let (context, report) = TraceContext::recover(Some(&invalid), Some(&state), Some(&baggage));
        assert_eq!(context.traceparent(), None);
        assert_eq!(context.tracestate(), None);
        assert_eq!(context.baggage(), baggage.as_str());
        assert!(report.traceparent_rejected());
        assert!(report.tracestate_rejected());
        assert!(!report.baggage_rejected());
        assert_eq!(report.rejected_count(), 2);

        let (context, report) =
            TraceContext::recover(Some(&parent), Some(&invalid), Some(&baggage));
        assert_eq!(context.traceparent(), Some(PARENT));
        assert_eq!(context.tracestate(), None);
        assert_eq!(context.baggage(), baggage.as_str());
        assert_eq!(report.rejected_count(), 1);
        assert!(report.tracestate_rejected());

        let (context, report) = TraceContext::recover(Some(&parent), Some(&state), Some(&invalid));
        assert_eq!(context.traceparent(), Some(PARENT));
        assert_eq!(context.tracestate(), state.as_str());
        assert_eq!(context.baggage(), None);
        assert_eq!(report.rejected_count(), 1);
        assert!(report.baggage_rejected());
    }

    #[test]
    fn obs_01_recovery_rejects_non_strings_without_retaining_them() {
        for invalid in [
            Value::Null,
            json!(true),
            json!(17),
            json!([]),
            json!({"secret": 1}),
        ] {
            let (context, report) =
                TraceContext::recover(Some(&invalid), Some(&invalid), Some(&invalid));
            assert!(context.is_empty());
            assert_eq!(report.rejected_count(), 3);
            assert!(report.traceparent_rejected());
            assert!(report.tracestate_rejected());
            assert!(report.baggage_rejected());
            assert!(!format!("{report:?}").contains("secret"));
        }
        let (context, report) = TraceContext::recover(None, None, None);
        assert_eq!(context, TraceContext::default());
        assert!(report.is_empty());
        let (context, report) = TraceContext::recover(None, Some(&json!("")), None);
        assert!(context.is_empty());
        assert!(report.tracestate_rejected());
        assert_eq!(report.rejected_count(), 1);
        assert_eq!(
            TraceContext::try_from_fields(None, Some(""), None),
            Err(TraceContextError::OrphanedTracestate)
        );
    }

    #[test]
    fn obs_01_recovery_discards_the_entire_baggage_field() {
        for invalid in [
            json!("valid=retained-only-if-all-valid,invalid"),
            json!(format!("k={}", "x".repeat(MAX_BAGGAGE_BYTES))),
            json!(vec!["k=v"; MAX_BAGGAGE_MEMBERS + 1].join(",")),
        ] {
            let (context, report) =
                TraceContext::recover(Some(&json!(PARENT)), None, Some(&invalid));
            assert_eq!(context.traceparent(), Some(PARENT));
            assert_eq!(context.baggage(), None);
            assert_eq!(report.rejected_count(), 1);
            assert!(report.baggage_rejected());
        }
    }

    #[test]
    fn obs_01_admitted_values_round_trip_and_debug_is_redacted() {
        let state = " \ta=private-vendor-value, ";
        let baggage = "sensitive=secret-value;sensitive-property";
        let context =
            TraceContext::try_from_fields(Some(PARENT), Some(state), Some(baggage)).unwrap();
        let (recovered, report) = TraceContext::recover(
            Some(&json!(context.traceparent().unwrap())),
            Some(&json!(context.tracestate().unwrap())),
            Some(&json!(context.baggage().unwrap())),
        );
        assert_eq!(recovered, context);
        assert!(report.is_empty());
        let debug = format!("{context:?}");
        assert!(!debug.contains(PARENT));
        assert!(!debug.contains("private-vendor-value"));
        assert!(!debug.contains("secret-value"));
        assert!(!debug.contains("sensitive-property"));
        assert!(debug.contains("has_traceparent: true"));
    }

    fn outbound_endpoints() -> (TraceEndpoint, TraceEndpoint) {
        (
            TraceEndpoint::network(
                TraceTransport::Http,
                "https://source.example/mcp",
                "tenant-a",
                "domain-a",
            )
            .unwrap(),
            TraceEndpoint::network(
                TraceTransport::Http,
                "https://destination.example/mcp",
                "tenant-a",
                "domain-a",
            )
            .unwrap(),
        )
    }

    #[test]
    fn obs_01_outbound_endpoint_identity_is_canonical_bounded_and_transport_owned() {
        let canonical = TraceEndpoint::network(
            TraceTransport::Http,
            "https://example.test/mcp",
            "tenant",
            "domain",
        )
        .unwrap();
        let alias = TraceEndpoint::network(
            TraceTransport::Http,
            "HTTPS://EXAMPLE.TEST:443/other?query=opaque#fragment",
            "tenant",
            "domain",
        )
        .unwrap();
        assert_eq!(canonical, alias);
        assert_eq!(canonical.origin(), "https://example.test");
        assert_eq!(canonical.network_origin(), Some("https://example.test"));
        assert_eq!(canonical.transport(), TraceTransport::Http);
        assert_eq!(
            TraceEndpoint::network(
                TraceTransport::Http,
                "https://b\u{00fc}cher.example/mcp",
                "tenant",
                "domain"
            )
            .unwrap()
            .origin(),
            "https://xn--bcher-kva.example"
        );
        assert_ne!(
            canonical,
            TraceEndpoint::network(
                TraceTransport::Http,
                "https://example.test:444/mcp",
                "tenant",
                "domain"
            )
            .unwrap()
        );
        for endpoint in [
            "file:///tmp/mcp",
            "https://user:secret@example.test/mcp",
            "ws://example.test/mcp",
            "invalid",
            "https://example.test/\rpath",
            "https://exam\nple.test/mcp",
            "https://exam\tple.test/mcp",
            " https://example.test/mcp",
            "https://example.test/mcp ",
            "https://example.test/\0path",
        ] {
            assert_eq!(
                TraceEndpoint::network(TraceTransport::Http, endpoint, "tenant", "domain"),
                Err(TracePolicyError::InvalidEndpoint)
            );
        }
        assert!(
            TraceEndpoint::network(
                TraceTransport::WebSocket,
                "wss://example.test/socket",
                "tenant",
                "domain"
            )
            .is_ok()
        );
        assert_eq!(
            TraceEndpoint::local(TraceTransport::Http, "peer", "tenant", "domain"),
            Err(TracePolicyError::InvalidEndpoint)
        );
        let local = TraceEndpoint::local(
            TraceTransport::WebSocket,
            "already-upgraded-peer",
            "tenant",
            "domain",
        )
        .unwrap();
        assert_eq!(local.network_origin(), None);
        assert_eq!(local.origin(), "already-upgraded-peer");
        for tenant in ["", "tenant with space", "tenant\nsecret"] {
            assert_eq!(
                TraceEndpoint::local(TraceTransport::Memory, "peer", tenant, "domain"),
                Err(TracePolicyError::InvalidScope)
            );
        }
        assert!(
            TraceEndpoint::local(
                TraceTransport::Memory,
                &"p".repeat(MAX_TRACE_SCOPE_BYTES),
                "tenant",
                "domain"
            )
            .is_ok()
        );
        assert_eq!(
            TraceEndpoint::local(
                TraceTransport::Memory,
                &"p".repeat(MAX_TRACE_SCOPE_BYTES + 1),
                "tenant",
                "domain"
            ),
            Err(TracePolicyError::InvalidEndpoint)
        );
    }

    #[test]
    fn obs_01_outbound_disabled_unknown_hop_and_other_versions_emit_nothing() {
        let (source, destination) = outbound_endpoints();
        let context = TraceContext::try_from_fields(
            Some(PARENT),
            Some("vendor=private-state"),
            Some("safe=private-value"),
        )
        .unwrap();
        let disabled =
            OutboundTracePolicy::default().evaluate(&source, &destination, &context, "2026-07-28");
        assert!(disabled.context().is_empty());
        assert_eq!(disabled.revision(), 0);
        assert_eq!(
            disabled.diagnostic().outcome(),
            TracePolicyOutcome::Disabled
        );
        assert_eq!(disabled.diagnostic().dropped_fields(), 3);
        assert!(!disabled.requires_uncacheable_response());
        assert_eq!(
            OutboundTracePolicy::new(0),
            Err(TracePolicyError::InvalidRevision)
        );
        assert_eq!(
            OutboundTracePolicy::default().with_rule(TracePropagationRule::new(
                source.clone(),
                destination.clone()
            )),
            Err(TracePolicyError::InvalidRevision)
        );

        let no_hops = OutboundTracePolicy::new(7).unwrap().evaluate(
            &source,
            &destination,
            &context,
            "2026-07-28",
        );
        assert!(no_hops.context().is_empty());
        assert_eq!(
            no_hops.diagnostic().outcome(),
            TracePolicyOutcome::UnmatchedHop
        );
        let policy = OutboundTracePolicy::new(7)
            .unwrap()
            .with_rule(
                TracePropagationRule::new(source.clone(), destination.clone()).with_traceparent(),
            )
            .unwrap();
        for version in ["2024-11-05", "2025-11-25", "2026-07-28 ", "", "future"] {
            let decision = policy.evaluate(&source, &destination, &context, version);
            assert!(decision.context().is_empty());
            assert_eq!(
                decision.diagnostic().outcome(),
                TracePolicyOutcome::UnsupportedProtocol
            );
            assert!(!decision.requires_uncacheable_response());
        }
        let decision = policy.evaluate(&source, &destination, &context, "2026-07-28");
        assert_eq!(decision.context().traceparent(), Some(PARENT));
        assert_eq!(decision.context().tracestate(), None);
        assert_eq!(decision.context().baggage(), None);
        assert_eq!(decision.diagnostic().forwarded_fields(), 1);
        assert_eq!(decision.diagnostic().dropped_fields(), 2);
        assert!(decision.requires_uncacheable_response());
        assert_eq!(decision.source(), &source);
        assert_eq!(decision.destination(), &destination);
    }

    #[test]
    fn obs_01_outbound_rules_bind_each_identity_dimension_and_allow_explicit_transport_hops() {
        let source =
            TraceEndpoint::local(TraceTransport::Memory, "source", "tenant", "domain").unwrap();
        let destination =
            TraceEndpoint::local(TraceTransport::Stdio, "destination", "tenant", "domain").unwrap();
        let context = TraceContext::try_from_fields(Some(PARENT), None, None).unwrap();
        let policy = OutboundTracePolicy::new(9)
            .unwrap()
            .with_rule(
                TracePropagationRule::new(source.clone(), destination.clone()).with_traceparent(),
            )
            .unwrap();
        let baseline = policy.evaluate(&source, &destination, &context, "2026-07-28");
        assert_eq!(
            baseline.context(),
            &context,
            "an explicitly configured memory-to-stdio hop works"
        );
        for changed_source in [
            TraceEndpoint::local(TraceTransport::Memory, "other-source", "tenant", "domain")
                .unwrap(),
            TraceEndpoint::local(TraceTransport::Memory, "source", "other-tenant", "domain")
                .unwrap(),
            TraceEndpoint::local(TraceTransport::Memory, "source", "tenant", "other-domain")
                .unwrap(),
            TraceEndpoint::local(TraceTransport::WebSocket, "source", "tenant", "domain").unwrap(),
        ] {
            let decision = policy.evaluate(&changed_source, &destination, &context, "2026-07-28");
            assert!(decision.context().is_empty());
            assert_eq!(
                decision.diagnostic().outcome(),
                TracePolicyOutcome::UnmatchedHop
            );
        }
        for changed_destination in [
            TraceEndpoint::local(
                TraceTransport::Stdio,
                "other-destination",
                "tenant",
                "domain",
            )
            .unwrap(),
            TraceEndpoint::local(
                TraceTransport::Stdio,
                "destination",
                "other-tenant",
                "domain",
            )
            .unwrap(),
            TraceEndpoint::local(
                TraceTransport::Stdio,
                "destination",
                "tenant",
                "other-domain",
            )
            .unwrap(),
            TraceEndpoint::local(TraceTransport::WebSocket, "destination", "tenant", "domain")
                .unwrap(),
        ] {
            assert!(
                policy
                    .evaluate(&source, &changed_destination, &context, "2026-07-28")
                    .context()
                    .is_empty()
            );
        }
        assert_eq!(
            policy.evaluate(&source, &destination, &context, "2026-07-28"),
            baseline,
            "a refused hop cannot mutate policy or an earlier decision"
        );
    }

    #[test]
    fn obs_01_outbound_vendor_state_requires_an_explicit_related_domain_allowlist() {
        let (source, destination) = outbound_endpoints();
        let rule = TracePropagationRule::new(source.clone(), destination.clone())
            .with_traceparent()
            .with_tracestate_keys(["allowed", "tenant@vendor"])
            .unwrap();
        let policy = OutboundTracePolicy::new(11)
            .unwrap()
            .with_rule(rule)
            .unwrap();
        let context = TraceContext::try_from_fields(
            Some(PARENT),
            Some(" \t,unrelated=private,allowed=keep,tenant@vendor=opaque, "),
            None,
        )
        .unwrap();
        let decision = policy.evaluate(&source, &destination, &context, "2026-07-28");
        assert_eq!(
            decision.context().tracestate(),
            Some("allowed=keep,tenant@vendor=opaque")
        );
        assert_eq!(decision.diagnostic().tracestate_members_forwarded(), 2);
        assert_eq!(decision.diagnostic().tracestate_members_dropped(), 1);
        assert_eq!(decision.context().traceparent(), Some(PARENT));
        for unrelated in [
            TraceEndpoint::network(
                TraceTransport::Http,
                "https://destination.example",
                "tenant-b",
                "domain-a",
            )
            .unwrap(),
            TraceEndpoint::network(
                TraceTransport::Http,
                "https://destination.example",
                "tenant-a",
                "domain-b",
            )
            .unwrap(),
        ] {
            assert_eq!(
                TracePropagationRule::new(source.clone(), unrelated)
                    .with_traceparent()
                    .with_tracestate_keys(["allowed"]),
                Err(TracePolicyError::TracestateBoundary)
            );
        }
        let no_parent = OutboundTracePolicy::new(12)
            .unwrap()
            .with_rule(
                TracePropagationRule::new(source.clone(), destination.clone())
                    .with_tracestate_keys(["allowed"])
                    .unwrap(),
            )
            .unwrap();
        assert!(
            no_parent
                .evaluate(&source, &destination, &context, "2026-07-28")
                .context()
                .is_empty(),
            "vendor state cannot be emitted without a continued parent"
        );
    }

    #[test]
    fn obs_01_outbound_baggage_allowlist_then_sensitive_denylist_preserves_safe_members() {
        let (source, _) = outbound_endpoints();
        let destination = TraceEndpoint::network(
            TraceTransport::Http,
            "https://other.example",
            "tenant-b",
            "domain-b",
        )
        .unwrap();
        let policy = OutboundTracePolicy::new(13)
            .unwrap()
            .with_sensitive_baggage_keys(["private"])
            .unwrap()
            .with_rule(
                TracePropagationRule::new(source.clone(), destination.clone())
                    .with_baggage_keys(
                        ["safe", "Authorization", "secret", "private", "PRIVATE"],
                        BaggageForwardingLimits::default(),
                    )
                    .unwrap(),
            )
            .unwrap();
        let context = TraceContext::try_from_fields(None, None, Some("safe=one;flag;prop=%ff,safe=two,Authorization=opaque,secret=hidden,PRIVATE=customer,unlisted=no,safe=three;password=hidden")).unwrap();
        let decision = policy.evaluate(&source, &destination, &context, "2026-07-28");
        assert_eq!(
            decision.context().baggage(),
            Some("safe=one;flag;prop=%ff,safe=two")
        );
        assert_eq!(
            decision.context().traceparent(),
            None,
            "baggage remains independent of a parent"
        );
        assert_eq!(decision.diagnostic().baggage_members_forwarded(), 2);
        assert_eq!(decision.diagnostic().baggage_members_dropped(), 5);
        assert!(!decision.diagnostic().baggage_budget_exceeded());
        assert!(decision.requires_uncacheable_response());
        let context = TraceContext::try_from_fields(
            None,
            None,
            Some("private=opaque,safe=one;PRIVATE=opaque"),
        )
        .unwrap();
        assert!(
            policy
                .evaluate(&source, &destination, &context, "2026-07-28")
                .context()
                .is_empty(),
            "configured denial also covers case aliases and property keys"
        );
    }

    #[test]
    fn obs_01_outbound_baggage_budgets_are_fresh_and_count_duplicates_and_distinct_keys() {
        let (source, destination) = outbound_endpoints();
        let selected = "safe=one;flag,safe=two";
        let context = TraceContext::try_from_fields(
            None,
            None,
            Some("secret=discard-before-budget,safe=one;flag,safe=two"),
        )
        .unwrap();
        let policy_for = |limits| {
            OutboundTracePolicy::new(15)
                .unwrap()
                .with_rule(
                    TracePropagationRule::new(source.clone(), destination.clone())
                        .with_baggage_keys(["safe", "other", "secret"], limits)
                        .unwrap(),
                )
                .unwrap()
        };
        let exact = policy_for(BaggageForwardingLimits::new(selected.len(), 2, 1).unwrap());
        let decision = exact.evaluate(&source, &destination, &context, "2026-07-28");
        assert_eq!(decision.context().baggage(), Some(selected));
        assert_eq!(decision.diagnostic().baggage_members_forwarded(), 2);
        assert_eq!(decision.diagnostic().baggage_members_dropped(), 1);
        for limits in [
            BaggageForwardingLimits::new(selected.len() - 1, 2, 1).unwrap(),
            BaggageForwardingLimits::new(selected.len(), 1, 1).unwrap(),
        ] {
            let decision =
                policy_for(limits).evaluate(&source, &destination, &context, "2026-07-28");
            assert!(decision.context().is_empty());
            assert!(decision.diagnostic().baggage_budget_exceeded());
            assert_eq!(decision.diagnostic().baggage_members_dropped(), 3);
            assert!(!decision.requires_uncacheable_response());
        }
        let distinct =
            TraceContext::try_from_fields(None, None, Some("safe=one,other=two")).unwrap();
        let decision = policy_for(BaggageForwardingLimits::new(128, 2, 1).unwrap()).evaluate(
            &source,
            &destination,
            &distinct,
            "2026-07-28",
        );
        assert!(decision.context().is_empty());
        assert!(decision.diagnostic().baggage_budget_exceeded());
        assert_eq!(
            exact
                .evaluate(&source, &destination, &context, "2026-07-28")
                .context()
                .baggage(),
            Some(selected),
            "each hop starts with a fresh budget"
        );
    }

    #[test]
    fn obs_01_outbound_policy_configuration_rejects_invalid_and_unbounded_rules() {
        let (source, destination) = outbound_endpoints();
        let rule =
            TracePropagationRule::new(source.clone(), destination.clone()).with_traceparent();
        let policy = OutboundTracePolicy::new(17)
            .unwrap()
            .with_rule(rule.clone())
            .unwrap();
        assert_eq!(
            policy.clone().with_rule(rule.clone()),
            Err(TracePolicyError::DuplicateRule)
        );
        for key in [
            "has space".to_owned(),
            "a".repeat(MAX_TRACE_POLICY_KEY_BYTES + 1),
        ] {
            assert_eq!(
                rule.clone()
                    .with_baggage_keys([key], BaggageForwardingLimits::default()),
                Err(TracePolicyError::InvalidKey)
            );
        }
        assert!(
            rule.clone()
                .with_baggage_keys(
                    ["a".repeat(MAX_TRACE_POLICY_KEY_BYTES)],
                    BaggageForwardingLimits::default()
                )
                .is_ok()
        );
        assert_eq!(
            rule.clone().with_baggage_keys(
                vec!["safe"; MAX_TRACE_POLICY_KEYS + 1],
                BaggageForwardingLimits::default()
            ),
            Err(TracePolicyError::TooManyKeys)
        );
        assert_eq!(
            rule.clone().with_tracestate_keys(["Uppercase"]),
            Err(TracePolicyError::InvalidKey)
        );
        for (bytes, members, distinct) in [
            (0, 1, 1),
            (MAX_BAGGAGE_BYTES + 1, 1, 1),
            (1, 0, 0),
            (1, MAX_BAGGAGE_MEMBERS + 1, 1),
            (1, 1, 0),
            (1, 1, 2),
        ] {
            assert_eq!(
                BaggageForwardingLimits::new(bytes, members, distinct),
                Err(TracePolicyError::InvalidBaggageLimits)
            );
        }
        let mut bounded = OutboundTracePolicy::new(18).unwrap();
        for index in 0..MAX_TRACE_POLICY_RULES {
            let destination = TraceEndpoint::local(
                TraceTransport::Stdio,
                &format!("peer-{index}"),
                "tenant-a",
                "domain-a",
            )
            .unwrap();
            bounded = bounded
                .with_rule(TracePropagationRule::new(source.clone(), destination))
                .unwrap();
        }
        assert_eq!(bounded.with_rule(rule), Err(TracePolicyError::TooManyRules));
        let sensitive = (0..MAX_TRACE_POLICY_KEYS).map(|index| format!("key{index}"));
        let bounded = policy.with_sensitive_baggage_keys(sensitive).unwrap();
        assert_eq!(
            bounded.with_sensitive_baggage_keys(["one-more"]),
            Err(TracePolicyError::TooManyKeys)
        );
    }

    #[test]
    fn obs_01_outbound_every_emitted_combination_readmits_and_diagnostics_are_redacted() {
        let (source, destination) = outbound_endpoints();
        let policy = OutboundTracePolicy::new(21)
            .unwrap()
            .with_rule(
                TracePropagationRule::new(source.clone(), destination.clone())
                    .with_traceparent()
                    .with_tracestate_keys(["a"])
                    .unwrap()
                    .with_baggage_keys(["safe", "secret"], BaggageForwardingLimits::default())
                    .unwrap(),
            )
            .unwrap();
        let future = "cc-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-ff-future\tfield";
        for parent in [None, Some(PARENT), Some(future)] {
            for state in [None, Some(""), Some(" ,a=vendor-private,b=other, ")] {
                if parent.is_none() && state.is_some() {
                    continue;
                }
                for baggage in [
                    None,
                    Some("safe=private-value;flag;prop=%ff"),
                    Some("safe=one,safe=two,secret=private-credential"),
                ] {
                    let input = TraceContext::try_from_fields(parent, state, baggage).unwrap();
                    let decision = policy.evaluate(&source, &destination, &input, "2026-07-28");
                    let output = decision.context();
                    assert_eq!(
                        &TraceContext::try_from_fields(
                            output.traceparent(),
                            output.tracestate(),
                            output.baggage()
                        )
                        .unwrap(),
                        output
                    );
                    assert_eq!(decision.requires_uncacheable_response(), !output.is_empty());
                    assert_eq!(decision.diagnostic().revision(), 21);
                    let debug = format!("{policy:?} {decision:?}");
                    for sensitive in [
                        PARENT,
                        "vendor-private",
                        "private-value",
                        "private-credential",
                        "source.example",
                        "destination.example",
                        "tenant-a",
                        "domain-a",
                    ] {
                        assert!(!debug.contains(sensitive));
                    }
                }
            }
        }
    }
}
