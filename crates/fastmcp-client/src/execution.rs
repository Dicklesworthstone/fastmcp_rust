//! Transport-neutral request execution and response correlation.
//!
//! This module owns the correlation rules that are independent of a concrete
//! MCP transport. A transport supplies typed JSON-RPC frames; the executor
//! commits requests, preserves out-of-order final responses for their exact
//! owners, retains bounded tombstones for retired owners, and never turns
//! malformed peer ingress into a peer-directed JSON-RPC response.

use std::borrow::Cow;
use std::collections::{HashMap, VecDeque};
use std::sync::atomic::{AtomicBool, AtomicU8, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, Instant};

use asupersync::Cx;
use fastmcp_core::{McpError, McpErrorCode, McpResult, Sha256Digest, sha256_bounded};
use fastmcp_protocol::methods::{INITIALIZE, SUBSCRIPTIONS_LISTEN, TOOLS_CALL};
use fastmcp_protocol::protocol_policy::ProtocolEra;
use fastmcp_protocol::tasks_extension::{
    CancelTaskParams, CancelTaskResult, GetTaskParams, GetTaskResult, TASK_STATUS_NOTIFICATION,
    Task, TaskId, TaskInputLedger, TaskMethodRequest, TaskStatusNotification, UpdateTaskParams,
    UpdateTaskResult, task_subscription_ids,
};
use fastmcp_protocol::{
    CancellationSender, CancellationWireMessage, CancelledParams, CoreRequest, CoreResult,
    CoreResultDiscriminatorPolicy, CorrelationKey, DecodedResult, FINAL_SUBSCRIPTION_ID_META_KEY,
    FinalCancelledNotificationParams, FinalCoreResult,
    FinalSubscriptionsAcknowledgedNotificationParams, FinalSubscriptionsListenParams,
    JsonRpcMessage, JsonRpcRequest, JsonRpcResponse, RequestId, ResultPeerDiagnostic,
    ResultPeerEra, SubscriptionFilter, decode_peer_result,
};
use fastmcp_transport::{Transport, TransportError};
use serde_json::Value;

use crate::{RequestTimeoutPolicy, transport_error_to_mcp};

/// Bounded compatibility diagnostic for a peer's final cache TTL.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FinalCacheTtlDiagnostic {
    /// A cacheable final complete result omitted its required `ttlMs` member.
    Missing,
    /// A cacheable final complete result supplied a negative `ttlMs`.
    Negative,
}

/// Default maximum number of active request owners.
pub const DEFAULT_MAX_IN_FLIGHT_EXECUTIONS: usize = 1_024;
/// Absolute ceiling for active request owners.
pub const MAX_IN_FLIGHT_EXECUTIONS: usize = 16_384;
/// Default maximum number of retained response correlations.
pub const DEFAULT_MAX_RESPONSE_CORRELATIONS: usize = 4_096;
/// Absolute ceiling for retained response correlations.
pub const MAX_RESPONSE_CORRELATIONS: usize = 65_536;
/// Default period for retaining a retired execution's exact response ID.
pub const DEFAULT_TOMBSTONE_RETENTION: Duration = Duration::from_mins(10);
/// Longest admitted period for retaining a retired response ID.
pub const MAX_TOMBSTONE_RETENTION: Duration = Duration::from_hours(1);

const MAX_RETAINED_PEER_ACTIVITY: usize = 1_024;
/// Minimum automatic-pagination page bound admitted by CLT-01 B.
pub const MIN_AUTOMATIC_PAGINATION_PAGES: usize = 1_000;
/// Minimum automatic-pagination item bound admitted by CLT-01 B.
pub const MIN_AUTOMATIC_PAGINATION_ITEMS: usize = 100_000;
/// Minimum automatic-pagination decoded-byte bound admitted by CLT-01 B.
pub const MIN_AUTOMATIC_PAGINATION_DECODED_BYTES: usize = 256 * 1024 * 1024;
/// Minimum automatic-pagination deadline admitted by CLT-01 B.
pub const MIN_AUTOMATIC_PAGINATION_DEADLINE: Duration = Duration::from_mins(5);
/// Hard automatic-pagination page ceiling.
pub const MAX_AUTOMATIC_PAGINATION_PAGES: usize = 10_000;
/// Hard automatic-pagination item ceiling.
pub const MAX_AUTOMATIC_PAGINATION_ITEMS: usize = 1_000_000;
/// Hard automatic-pagination decoded-byte ceiling.
pub const MAX_AUTOMATIC_PAGINATION_DECODED_BYTES: usize = 2 * 1024 * 1024 * 1024;
/// Hard automatic-pagination deadline ceiling.
pub const MAX_AUTOMATIC_PAGINATION_DEADLINE: Duration = Duration::from_mins(30);
const CLT_01_A_MANIFEST_ROWS: &str = concat!(
    "CLT-01-A\n",
    "01 reordered correlated finals\n",
    "02 duplicate response ID\n",
    "03 unknown late tombstoned ID\n",
    "04 notification interleaving\n",
    "05 malformed peer ingress without reverse response\n",
    "06 typed complete input-required result siblings\n",
    "07 send queue backpressure\n",
    "08 connection-loss waiter fanout\n",
    "pending correlation_key request_id execution_generation request_state send_committed idle_deadline absolute_deadline terminal_state cancellation_committed tombstone_generation\n",
);
const CLT_01_B_MANIFEST_ROWS: &str = concat!(
    "CLT-01-B\n",
    "09 explicit caller cancellation/drop\n",
    "10 idle expiry and exact matching-progress reset\n",
    "11 non-resettable absolute expiry under progress/log/keepalive flood\n",
    "12 final-response/caller-cancel/timeout/connection-loss same-tick race\n",
    "13 reverse request and streaming notification ordering\n",
    "14 opaque pagination empty/repeated/absent cursors plus page/item/byte/deadline bounds\n",
    "15 shutdown/connection-close cleanup\n",
    "terminal_state terminal_reason final_delivered cancellation_committed cancellation_transport_attempts local_cancellation_event waiter_release tombstone\n",
);

/// Bounds for one multi-round model-request tool retry (MRTR) operation.
///
/// The caller chooses the operation's absolute deadline separately. These
/// bounds limit only how many input-required continuations and total supplied
/// input values that operation may admit before it sends another request.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct MrtrDriverLimits {
    max_continuation_rounds: usize,
    max_total_input_responses: usize,
}

impl MrtrDriverLimits {
    /// Creates validated MRTR continuation bounds.
    ///
    /// Both bounds must be nonzero. A continuation round is one peer
    /// `input_required` result followed by one possible caller retry.
    pub(crate) fn new(
        max_continuation_rounds: usize,
        max_total_input_responses: usize,
    ) -> McpResult<Self> {
        if max_continuation_rounds == 0 {
            return Err(McpError::invalid_params(
                "MRTR continuation-round limit must be at least one",
            ));
        }
        if max_total_input_responses == 0 {
            return Err(McpError::invalid_params(
                "MRTR total input-response limit must be at least one",
            ));
        }
        Ok(Self {
            max_continuation_rounds,
            max_total_input_responses,
        })
    }
}

/// Caller-owned state for one bounded multi-round MRTR operation.
///
/// This type deliberately does not own transport state or spawn work. The
/// stdio client keeps transport ownership while this driver makes the caller's
/// cancellation context, one absolute deadline, and the continuation/input
/// counters explicit at every retry boundary.
#[derive(Debug)]
pub(crate) struct MrtrDriver<'cx> {
    cx: &'cx Cx,
    deadline: Instant,
    limits: MrtrDriverLimits,
    continuation_rounds: usize,
    total_input_responses: usize,
}

impl<'cx> MrtrDriver<'cx> {
    /// Starts one MRTR operation using exactly the supplied caller context and
    /// absolute deadline.
    pub(crate) fn new(cx: &'cx Cx, deadline: Instant, limits: MrtrDriverLimits) -> McpResult<Self> {
        let driver = Self {
            cx,
            deadline,
            limits,
            continuation_rounds: 0,
            total_input_responses: 0,
        };
        driver.before_request()?;
        Ok(driver)
    }

    /// Returns the operation-wide absolute deadline.
    #[must_use]
    pub(crate) const fn deadline(&self) -> Instant {
        self.deadline
    }

    /// Checks caller cancellation and the operation-wide deadline before a
    /// request can be committed.
    pub(crate) fn before_request(&self) -> McpResult<()> {
        if self.cx.checkpoint().is_err() {
            return Err(McpError::request_cancelled());
        }
        if Instant::now() >= self.deadline {
            return Err(McpError::internal_error(
                "MRTR operation absolute deadline elapsed",
            ));
        }
        Ok(())
    }

    /// Admits one peer `input_required` continuation before the callback is
    /// invoked. This prevents a callback effect or another wire request after
    /// the configured round bound has been reached.
    pub(crate) fn begin_continuation(&mut self) -> McpResult<()> {
        self.before_request()?;
        let continuation_rounds = self.continuation_rounds.checked_add(1).ok_or_else(|| {
            McpError::internal_error("MRTR continuation-round counter overflowed")
        })?;
        if continuation_rounds > self.limits.max_continuation_rounds {
            return Err(McpError::invalid_params(
                "MRTR continuation-round limit exceeded",
            ));
        }
        self.continuation_rounds = continuation_rounds;
        Ok(())
    }

    /// Admits the response entries selected for the current continuation.
    ///
    /// A state-only continuation supplies zero entries and is therefore
    /// admitted as long as the caller has not exceeded the round limit.
    pub(crate) fn admit_input_responses(&mut self, input_response_count: usize) -> McpResult<()> {
        self.before_request()?;
        let total_input_responses = self
            .total_input_responses
            .checked_add(input_response_count)
            .ok_or_else(|| {
                McpError::internal_error("MRTR total input-response counter overflowed")
            })?;
        if total_input_responses > self.limits.max_total_input_responses {
            return Err(McpError::invalid_params(
                "MRTR total input-response limit exceeded",
            ));
        }
        self.total_input_responses = total_input_responses;
        self.before_request()
    }
}

/// A client-authored JSON-RPC request that expects one final response.
pub type Request = JsonRpcRequest;

/// Returns the canonical CLT-01 A case-and-pending-record manifest digest.
///
/// The manifest is an executable acceptance input, not a source-file hash: it
/// binds the public executor's ordered groups 01–08 and every observable
/// pending-map field exercised by the public-surface tests.
#[must_use]
pub fn clt_01_a_manifest_digest() -> Sha256Digest {
    sha256_bounded(
        CLT_01_A_MANIFEST_ROWS.as_bytes(),
        CLT_01_A_MANIFEST_ROWS.len(),
    )
    .expect("the fixed CLT-01 A manifest is within its exact byte bound")
}

/// Returns the canonical CLT-01 B lifecycle-and-pagination manifest digest.
///
/// The digest binds ordered groups 09–15 and the terminal predicate; it is
/// deliberately a fixed acceptance input rather than a hash of this source.
#[must_use]
pub fn clt_01_b_manifest_digest() -> Sha256Digest {
    sha256_bounded(
        CLT_01_B_MANIFEST_ROWS.as_bytes(),
        CLT_01_B_MANIFEST_ROWS.len(),
    )
    .expect("the fixed CLT-01 B manifest is within its exact byte bound")
}

/// Decodes a core response through the exact request and negotiated-era type.
///
/// The request owns the method-specific result shape, so this cannot conflate a
/// final `tools/call` response with a legacy result or with another core
/// method's complete payload. The caller owns connection policy after a peer
/// violates this contract.
pub(crate) fn decode_core_result(request: &CoreRequest, result: &Value) -> McpResult<CoreResult> {
    decode_core_result_from_source(request, result, None)
}

pub(crate) fn decode_core_result_from_source(
    request: &CoreRequest,
    result: &Value,
    result_source: Option<&str>,
) -> McpResult<CoreResult> {
    let encoded = match result_source {
        Some(source) => {
            let admitted: Value = serde_json::from_str(source).map_err(|_| {
                McpError::invalid_request("Peer core result source is not valid JSON")
            })?;
            if &admitted != result {
                return Err(McpError::invalid_request(
                    "Peer core result source differs from its typed response",
                ));
            }
            Cow::Borrowed(source)
        }
        None => Cow::Owned(serde_json::to_string(result).map_err(|_| {
            McpError::invalid_request(
                "Peer core result could not be encoded for protocol admission",
            )
        })?),
    };
    request
        .decode_result(&encoded)
        .map_err(|_| McpError::invalid_request("Peer core result failed protocol decoding"))
}

/// Decodes a core result while applying the final cache-TTL compatibility rule
/// at the client ingress boundary. Missing or negative peer TTLs are
/// normalized to zero freshness and reported through a bounded local
/// diagnostic. All other malformed shapes continue through strict protocol
/// decoding unchanged.
pub(crate) fn decode_core_result_with_cache_ttl(
    request: &CoreRequest,
    result: &Value,
) -> McpResult<(CoreResult, Option<FinalCacheTtlDiagnostic>)> {
    decode_core_result_with_cache_ttl_from_source(request, result, None)
}

pub(crate) fn decode_core_result_with_cache_ttl_from_source(
    request: &CoreRequest,
    result: &Value,
    result_source: Option<&str>,
) -> McpResult<(CoreResult, Option<FinalCacheTtlDiagnostic>)> {
    let mut normalized = result.clone();
    let diagnostic = tolerant_final_cache_ttl(request, &mut normalized);
    let normalized_source = result_source
        .map(|source| normalize_final_cache_ttl_source(source, diagnostic))
        .transpose()?;
    decode_core_result_from_source(request, &normalized, normalized_source.as_deref())
        .map(|result| (result, diagnostic))
}

fn normalize_final_cache_ttl_source(
    source: &str,
    diagnostic: Option<FinalCacheTtlDiagnostic>,
) -> McpResult<Cow<'_, str>> {
    match diagnostic {
        None => Ok(Cow::Borrowed(source)),
        Some(FinalCacheTtlDiagnostic::Missing) => {
            let end = source.trim_end().len();
            let Some(close) = end
                .checked_sub(1)
                .filter(|index| source.as_bytes()[*index] == b'}')
            else {
                return Err(McpError::invalid_request(
                    "Peer cacheable result source is not an object",
                ));
            };
            let open = source.find('{').ok_or_else(|| {
                McpError::invalid_request("Peer cacheable result is not an object")
            })?;
            let separator = if source[open + 1..close].trim().is_empty() {
                ""
            } else {
                ","
            };
            Ok(Cow::Owned(format!(
                "{}{}\"ttlMs\":0{}",
                &source[..close],
                separator,
                &source[close..]
            )))
        }
        Some(FinalCacheTtlDiagnostic::Negative) => {
            let range = top_level_json_member_value_range(source, "ttlMs").ok_or_else(|| {
                McpError::invalid_request("Peer cache TTL source member could not be located")
            })?;
            let mut normalized = String::with_capacity(source.len());
            normalized.push_str(&source[..range.start]);
            normalized.push('0');
            normalized.push_str(&source[range.end..]);
            Ok(Cow::Owned(normalized))
        }
    }
}

fn top_level_json_member_value_range(
    source: &str,
    expected_name: &str,
) -> Option<std::ops::Range<usize>> {
    let bytes = source.as_bytes();
    let mut cursor = bytes.iter().position(|byte| !byte.is_ascii_whitespace())?;
    if bytes.get(cursor) != Some(&b'{') {
        return None;
    }
    cursor += 1;
    loop {
        while bytes.get(cursor).is_some_and(u8::is_ascii_whitespace) {
            cursor += 1;
        }
        if bytes.get(cursor) == Some(&b'}') {
            return None;
        }
        let key_start = cursor;
        let key_end = json_string_end(bytes, cursor)?;
        let key: String = serde_json::from_str(&source[key_start..key_end]).ok()?;
        cursor = key_end;
        while bytes.get(cursor).is_some_and(u8::is_ascii_whitespace) {
            cursor += 1;
        }
        if bytes.get(cursor) != Some(&b':') {
            return None;
        }
        cursor += 1;
        while bytes.get(cursor).is_some_and(u8::is_ascii_whitespace) {
            cursor += 1;
        }
        let value_start = cursor;
        let value_end = json_value_end(bytes, cursor)?;
        if key == expected_name {
            return Some(value_start..value_end);
        }
        cursor = value_end;
        while bytes.get(cursor).is_some_and(u8::is_ascii_whitespace) {
            cursor += 1;
        }
        match bytes.get(cursor) {
            Some(b',') => cursor += 1,
            Some(b'}') => return None,
            _ => return None,
        }
    }
}

fn json_string_end(bytes: &[u8], start: usize) -> Option<usize> {
    if bytes.get(start) != Some(&b'"') {
        return None;
    }
    let mut cursor = start + 1;
    while let Some(byte) = bytes.get(cursor) {
        match byte {
            b'"' => return Some(cursor + 1),
            b'\\' => cursor = cursor.checked_add(2)?,
            _ => cursor += 1,
        }
    }
    None
}

fn json_value_end(bytes: &[u8], start: usize) -> Option<usize> {
    if bytes.get(start) == Some(&b'"') {
        return json_string_end(bytes, start);
    }
    if matches!(bytes.get(start), Some(b'{') | Some(b'[')) {
        let mut stack = vec![*bytes.get(start)?];
        let mut cursor = start + 1;
        while let Some(byte) = bytes.get(cursor) {
            match byte {
                b'"' => cursor = json_string_end(bytes, cursor)?,
                b'{' | b'[' => {
                    stack.push(*byte);
                    cursor += 1;
                }
                b'}' if stack.last() == Some(&b'{') => {
                    stack.pop();
                    cursor += 1;
                    if stack.is_empty() {
                        return Some(cursor);
                    }
                }
                b']' if stack.last() == Some(&b'[') => {
                    stack.pop();
                    cursor += 1;
                    if stack.is_empty() {
                        return Some(cursor);
                    }
                }
                _ => cursor += 1,
            }
        }
        return None;
    }
    let mut cursor = start;
    while !matches!(bytes.get(cursor), None | Some(b',') | Some(b'}')) {
        cursor += 1;
    }
    let mut end = cursor;
    while end > start && bytes[end - 1].is_ascii_whitespace() {
        end -= 1;
    }
    (end > start).then_some(end)
}

fn tolerant_final_cache_ttl(
    request: &CoreRequest,
    result: &mut Value,
) -> Option<FinalCacheTtlDiagnostic> {
    let CoreRequest::Final(request) = request else {
        return None;
    };
    if !matches!(
        request,
        fastmcp_protocol::FinalCoreRequest::ToolsList(_)
            | fastmcp_protocol::FinalCoreRequest::ResourcesList(_)
            | fastmcp_protocol::FinalCoreRequest::ResourceTemplatesList(_)
            | fastmcp_protocol::FinalCoreRequest::ResourcesRead(_)
            | fastmcp_protocol::FinalCoreRequest::PromptsList(_)
    ) {
        return None;
    }
    let Some(members) = result.as_object_mut() else {
        return None;
    };
    if members
        .get("resultType")
        .is_some_and(|result_type| result_type.as_str() != Some("complete"))
    {
        return None;
    }

    match members.get("ttlMs") {
        None => {
            members.insert("ttlMs".to_owned(), Value::Number(0_u64.into()));
            Some(FinalCacheTtlDiagnostic::Missing)
        }
        Some(Value::Number(ttl)) if ttl.to_string().starts_with('-') => {
            members.insert("ttlMs".to_owned(), Value::Number(0_u64.into()));
            Some(FinalCacheTtlDiagnostic::Negative)
        }
        _ => None,
    }
}

/// Public snapshot of one active correlation record.
///
/// The executor exposes these records so callers can audit exactly which
/// request owns a response slot without access to the concrete transport.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PendingRequestRecord {
    /// Canonical key for this correlation; numeric wire aliases share one key.
    pub correlation_key: CorrelationKey,
    /// Exact JSON-RPC request ID sent to the peer.
    pub request_id: RequestId,
    /// Monotonic generation for a request ID that may later be tombstoned.
    pub execution_generation: u64,
    /// Whether the request has entered the response-wait phase.
    pub request_state: ExecutionTerminalState,
    /// Whether the request bytes were committed to the transport.
    pub send_committed: bool,
    /// Post-send idle deadline recorded for the execution owner.
    pub idle_deadline: Instant,
    /// Non-resettable post-send absolute deadline recorded for the owner.
    pub absolute_deadline: Instant,
    /// Current terminal state; active entries are always [`Self::request_state`].
    pub terminal_state: ExecutionTerminalState,
    /// Whether a cancellation transition has been selected for this owner.
    pub cancellation_committed: bool,
    /// Generation retained by a later tombstone, if this record has retired.
    pub tombstone_generation: Option<u64>,
}

/// Exactly-once execution state visible to callers.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ExecutionTerminalState {
    /// The execution remains eligible to receive one final response.
    Pending,
    /// A final JSON-RPC response was accepted for the exact owner.
    Response,
    /// The transport or peer protocol failed the owner.
    Failed,
    /// The owner was abandoned and a cancellation request was selected.
    Cancelled,
}

/// The one local cause that won an execution's terminal transition.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ExecutionTerminalReason {
    /// The peer final response won the terminal transition.
    FinalResponse,
    /// The caller explicitly cancelled the execution.
    CallerCancelled,
    /// The request-owned handle was dropped before its final response.
    CallerDropped,
    /// A valid, accepted peer subscription teardown selected cancellation.
    PeerSubscriptionTeardown,
    /// The committed request made no qualifying progress before idle expiry.
    IdleTimeout,
    /// The non-resettable committed request lifetime elapsed.
    AbsoluteTimeout,
    /// The shared connection or peer ingress failed.
    ConnectionLost,
    /// The exact owner received an invalid final MCP result envelope.
    PeerProtocol,
    /// Local executor shutdown selected the terminal transition.
    Shutdown,
}

/// Typed, local-only cancellation indication for an execution owner.
///
/// This intentionally exposes a classifier rather than peer-provided text;
/// raw cancellation reasons are never copied into an observer event.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CancellationRequested {
    /// Exact request ID whose cancellation was selected.
    pub request_id: RequestId,
    /// Local classifier for the selected cancellation source.
    pub reason: ExecutionTerminalReason,
}

/// Cooperative cancellation handle owned by one exact-2024 reverse request.
///
/// The executor cancels this handle only after accepting an ID-free legacy
/// `notifications/cancelled` notification that names this request's live
/// owner. A callback must use its own checkpoints before producing effects.
const REVERSE_CALLBACK_OPEN: u8 = 0;
const REVERSE_CALLBACK_CANCELLED: u8 = 1;
const REVERSE_CALLBACK_RESPONSE_SENT: u8 = 2;

#[derive(Clone, Debug)]
pub struct ReverseRequestCancellation(Arc<AtomicU8>);

impl ReverseRequestCancellation {
    pub(crate) fn new() -> Self {
        Self(Arc::new(AtomicU8::new(REVERSE_CALLBACK_OPEN)))
    }

    pub(crate) fn cancel(&self) {
        let _ = self.0.compare_exchange(
            REVERSE_CALLBACK_OPEN,
            REVERSE_CALLBACK_CANCELLED,
            Ordering::AcqRel,
            Ordering::Acquire,
        );
    }

    pub(crate) fn is_open(&self) -> bool {
        self.0.load(Ordering::Acquire) == REVERSE_CALLBACK_OPEN
    }

    pub(crate) fn record_response_sent(&self) {
        let previous = self.0.compare_exchange(
            REVERSE_CALLBACK_OPEN,
            REVERSE_CALLBACK_RESPONSE_SENT,
            Ordering::AcqRel,
            Ordering::Acquire,
        );
        debug_assert!(
            previous.is_ok(),
            "only an elected open callback can record a response write"
        );
    }

    pub(crate) fn belongs_to_same_request(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.0, &other.0)
    }

    /// Returns whether the server or owning connection cancelled this request.
    #[must_use]
    pub fn is_cancel_requested(&self) -> bool {
        self.0.load(Ordering::Acquire) == REVERSE_CALLBACK_CANCELLED
    }

    /// Returns `RequestCancelled` when this reverse request is no longer live.
    pub fn checkpoint(&self) -> McpResult<()> {
        if self.is_cancel_requested() {
            return Err(McpError::request_cancelled());
        }
        Ok(())
    }
}

/// One exact-2024 server-authored reverse request together with its response
/// capability.
///
/// The capability is local to both this request incarnation and this executor
/// connection. It cannot answer a later request that happens to reuse the
/// same JSON-RPC ID, including after a matching cancellation.
#[derive(Clone, Debug)]
pub struct ReverseRequest {
    request: JsonRpcRequest,
    cancellation: ReverseRequestCancellation,
    owner: Arc<()>,
}

impl ReverseRequest {
    /// Returns the exact server-authored request frame.
    #[must_use]
    pub fn request(&self) -> &JsonRpcRequest {
        &self.request
    }

    /// Returns the exact response ID carried by this request.
    #[must_use]
    pub fn request_id(&self) -> &RequestId {
        self.request
            .id
            .as_ref()
            .expect("reverse request owners always retain a request ID")
    }

    /// Returns the cooperative cancellation handle for this request owner.
    #[must_use]
    pub fn cancellation(&self) -> &ReverseRequestCancellation {
        &self.cancellation
    }
}

#[derive(Clone, Debug)]
struct ActiveReverseRequest {
    request_id: RequestId,
    cancellation: ReverseRequestCancellation,
    owner: Arc<()>,
}

/// Immutable receipt for the terminal CAS of one execution.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExecutionTerminalRecord {
    /// State selected by the single terminal transition.
    pub terminal_state: ExecutionTerminalState,
    /// Cause selected by the single terminal transition.
    pub terminal_reason: ExecutionTerminalReason,
    /// Whether a peer final response, rather than a local error, was delivered.
    pub final_delivered: bool,
    /// Whether this terminal path selected cancellation.
    pub cancellation_committed: bool,
    /// Number of cancellation transport sends attempted for this execution.
    pub cancellation_transport_attempts: u8,
    /// Whether the one typed local cancellation event was published.
    pub local_cancellation_event: bool,
    /// Whether the response waiter was released.
    pub waiter_release: bool,
    /// Whether the canonical request ID is retained to discard a late final response.
    pub tombstone: bool,
}

/// Bounds for an automatic opaque-cursor pagination sequence.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PaginationBounds {
    max_pages: usize,
    max_items: usize,
    max_decoded_bytes: usize,
    deadline: Duration,
}

impl PaginationBounds {
    /// Creates bounds within the frozen CLT-01 B admission interval.
    pub fn new(
        max_pages: usize,
        max_items: usize,
        max_decoded_bytes: usize,
        deadline: Duration,
    ) -> McpResult<Self> {
        if !(MIN_AUTOMATIC_PAGINATION_PAGES..=MAX_AUTOMATIC_PAGINATION_PAGES).contains(&max_pages)
            || !(MIN_AUTOMATIC_PAGINATION_ITEMS..=MAX_AUTOMATIC_PAGINATION_ITEMS)
                .contains(&max_items)
            || !(MIN_AUTOMATIC_PAGINATION_DECODED_BYTES..=MAX_AUTOMATIC_PAGINATION_DECODED_BYTES)
                .contains(&max_decoded_bytes)
            || !(MIN_AUTOMATIC_PAGINATION_DEADLINE..=MAX_AUTOMATIC_PAGINATION_DEADLINE)
                .contains(&deadline)
        {
            return Err(McpError::invalid_params(
                "Automatic pagination bounds fall outside the CLT-01 B admission interval",
            ));
        }
        Ok(Self {
            max_pages,
            max_items,
            max_decoded_bytes,
            deadline,
        })
    }
}

impl Default for PaginationBounds {
    fn default() -> Self {
        Self {
            max_pages: MIN_AUTOMATIC_PAGINATION_PAGES,
            max_items: MIN_AUTOMATIC_PAGINATION_ITEMS,
            max_decoded_bytes: MIN_AUTOMATIC_PAGINATION_DECODED_BYTES,
            deadline: MIN_AUTOMATIC_PAGINATION_DEADLINE,
        }
    }
}

/// State machine for opaque pagination cursors.
///
/// A present cursor, including the empty string and a repeated value, always
/// means another page. Only an absent field finishes the sequence.
#[derive(Clone, Debug)]
pub struct OpaquePagination {
    bounds: PaginationBounds,
    started_at: Instant,
    pages: usize,
    items: usize,
    decoded_bytes: usize,
    next_cursor: Option<String>,
    complete: bool,
}

impl OpaquePagination {
    /// Starts a bounded pagination sequence at `started_at`.
    #[must_use]
    pub fn new(bounds: PaginationBounds, started_at: Instant) -> Self {
        Self {
            bounds,
            started_at,
            pages: 0,
            items: 0,
            decoded_bytes: 0,
            next_cursor: None,
            complete: false,
        }
    }

    /// Admits one decoded page and records its next cursor verbatim.
    ///
    /// Returns `true` when the next cursor field is present, independently of
    /// its contents; callers must issue another request in that case.
    pub fn accept_page(
        &mut self,
        next_cursor: Option<String>,
        item_count: usize,
        decoded_bytes: usize,
        observed_at: Instant,
    ) -> McpResult<bool> {
        if self.complete {
            return Err(McpError::invalid_request(
                "Automatic pagination received a page after cursor absence completed it",
            ));
        }
        if observed_at.duration_since(self.started_at) > self.bounds.deadline {
            return Err(McpError::internal_error(
                "Automatic pagination deadline elapsed",
            ));
        }
        self.pages = self.pages.checked_add(1).ok_or_else(|| {
            McpError::internal_error("Automatic pagination page counter overflowed")
        })?;
        self.items = self.items.checked_add(item_count).ok_or_else(|| {
            McpError::internal_error("Automatic pagination item counter overflowed")
        })?;
        self.decoded_bytes = self
            .decoded_bytes
            .checked_add(decoded_bytes)
            .ok_or_else(|| {
                McpError::internal_error("Automatic pagination byte counter overflowed")
            })?;
        if self.pages > self.bounds.max_pages
            || self.items > self.bounds.max_items
            || self.decoded_bytes > self.bounds.max_decoded_bytes
        {
            return Err(McpError::internal_error(
                "Automatic pagination exceeded a local bound",
            ));
        }
        self.complete = next_cursor.is_none();
        self.next_cursor = next_cursor;
        Ok(!self.complete)
    }

    /// Returns the opaque next cursor without normalization or interpretation.
    #[must_use]
    pub fn next_cursor(&self) -> Option<&str> {
        self.next_cursor.as_deref()
    }
}

#[derive(Debug)]
struct PendingExecution {
    record: PendingRequestRecord,
    owner_dropped: OwnerDropped,
    timeout_policy: RequestTimeoutPolicy,
    last_progress: Option<f64>,
    method: String,
}

/// Shared dropped-owner marker. This replaces the executor's local
/// `Rc<Cell<bool>>` ownership so cloned execution handles can cross the
/// negotiated stdio boundary without relying on thread-local state.
#[derive(Clone, Debug)]
struct OwnerDropped(Arc<AtomicBool>);

impl OwnerDropped {
    fn new() -> Self {
        Self(Arc::new(AtomicBool::new(false)))
    }

    fn get(&self) -> bool {
        self.0.load(Ordering::Acquire)
    }

    fn set(&self, value: bool) {
        self.0.store(value, Ordering::Release);
    }
}

/// Mutex-backed executor state ownership.
///
/// The transport-neutral adapter retains its historical synchronous API. The
/// negotiated stdio client uses its own sole ingress arbiter and shared
/// response registry; this wrapper removes the old `Rc<RefCell<_>>` ownership
/// from public request handles.
#[derive(Debug)]
struct SharedExecutorState<T>(Arc<Mutex<ExecutorState<T>>>);

impl<T> Clone for SharedExecutorState<T> {
    fn clone(&self) -> Self {
        Self(Arc::clone(&self.0))
    }
}

impl<T> SharedExecutorState<T> {
    fn new(state: ExecutorState<T>) -> Self {
        Self(Arc::new(Mutex::new(state)))
    }

    fn borrow(&self) -> MutexGuard<'_, ExecutorState<T>> {
        self.0
            .lock()
            .expect("request executor state mutex poisoned")
    }

    fn borrow_mut(&self) -> MutexGuard<'_, ExecutorState<T>> {
        self.borrow()
    }

    fn try_borrow_mut(&self) -> Result<MutexGuard<'_, ExecutorState<T>>, ()> {
        self.0.try_lock().map_err(|_| ())
    }

    fn ptr_eq(left: &Self, right: &Self) -> bool {
        Arc::ptr_eq(&left.0, &right.0)
    }
}

#[derive(Clone, Debug)]
enum TaskExecutionOperation {
    ToolCall,
    Get(TaskId),
    Update(TaskId),
    Cancel(TaskId),
    Subscription,
}

#[derive(Debug)]
struct TaskSubscription {
    requested_filter: SubscriptionFilter,
    accepted_filter: Option<SubscriptionFilter>,
    notifications: VecDeque<TaskStatusNotification>,
}

#[derive(Debug)]
enum ExecutionOutcome {
    Response(DecodedFinalResponse),
    Failure(McpError),
}

/// One admitted JSON-RPC final response and its lossless result envelope.
///
/// JSON-RPC error responses have no result envelope, so their `decoded` field
/// is absent and the caller receives the peer's typed JSON-RPC error instead.
#[derive(Debug)]
struct DecodedFinalResponse {
    response: JsonRpcResponse,
    raw_result: Option<String>,
    decoded: Option<AdmittedFinalResult>,
}

#[derive(Debug)]
enum AdmittedFinalResult {
    Core(DecodedResult, Option<ResultPeerDiagnostic>),
    Task,
}

impl DecodedFinalResponse {
    fn admit(
        response: JsonRpcResponse,
        raw_result: Option<String>,
        peer_era: ResultPeerEra,
        accepts_task_result: bool,
    ) -> McpResult<Self> {
        if raw_result.is_some() != response.result.is_some() {
            return Err(McpError::invalid_request(
                "Peer final result source does not match the response kind",
            ));
        }
        if let Some(source) = raw_result.as_deref() {
            let admitted: Value = serde_json::from_str(source).map_err(|_| {
                McpError::invalid_request("Peer final result source is not valid JSON")
            })?;
            if response.result.as_ref() != Some(&admitted) {
                return Err(McpError::invalid_request(
                    "Peer final result source differs from its typed response",
                ));
            }
        }
        let decoded = response
            .result
            .as_ref()
            .map(|result| {
                if accepts_task_result
                    && result.get("resultType").and_then(Value::as_str) == Some("task")
                {
                    return Ok(AdmittedFinalResult::Task);
                }
                let encoded = raw_result.as_deref().map_or_else(
                    || {
                        serde_json::to_string(result).map_err(|_| {
                            McpError::invalid_request(
                                "Peer final result could not be encoded for protocol admission",
                            )
                        })
                    },
                    |source| Ok(source.to_owned()),
                )?;
                decode_peer_result(&encoded, peer_era, &CoreResultDiscriminatorPolicy)
                    .map_err(|_| {
                        McpError::invalid_request("Peer final result failed protocol decoding")
                    })
                    .map(|(result, diagnostic)| AdmittedFinalResult::Core(result, diagnostic))
            })
            .transpose()?;
        Ok(Self {
            response,
            raw_result,
            decoded,
        })
    }

    fn into_decoded(self) -> McpResult<(DecodedResult, Option<ResultPeerDiagnostic>)> {
        match self.decoded {
            Some(AdmittedFinalResult::Core(decoded, diagnostic)) => Ok((decoded, diagnostic)),
            Some(AdmittedFinalResult::Task) => Err(McpError::invalid_request(
                "Tasks result requires its typed Tasks execution surface",
            )),
            None => {
                let error = self
                    .response
                    .error
                    .expect("validated JSON-RPC final responses have either result or error");
                match error.data {
                    Some(data) => Err(McpError::with_data(
                        error
                            .code
                            .as_i32()
                            .map(McpErrorCode::from)
                            .unwrap_or(McpErrorCode::InternalError),
                        error.message,
                        data,
                    )),
                    None => Err(McpError::new(
                        error
                            .code
                            .as_i32()
                            .map(McpErrorCode::from)
                            .unwrap_or(McpErrorCode::InternalError),
                        error.message,
                    )),
                }
            }
        }
    }
}

#[derive(Debug)]
struct Tombstone {
    generation: u64,
    expires_at: Instant,
    /// Peer-produced terminal outcomes remain observable as duplicate
    /// diagnostics; abandoned-owner finals are silently discarded instead.
    retain_late_response_diagnostic: bool,
}

#[derive(Debug)]
struct DeferredDropCancellation {
    request_id: RequestId,
    generation: u64,
    message: JsonRpcMessage,
}

#[derive(Debug)]
struct ExecutorState<T> {
    transport: T,
    pending: HashMap<CorrelationKey, PendingExecution>,
    completed: HashMap<(RequestId, u64), ExecutionOutcome>,
    tombstones: HashMap<CorrelationKey, Tombstone>,
    notifications: VecDeque<JsonRpcRequest>,
    reverse_requests: VecDeque<ReverseRequest>,
    pending_reverse_requests: HashMap<CorrelationKey, ActiveReverseRequest>,
    stream_notifications: HashMap<(RequestId, u64), VecDeque<JsonRpcRequest>>,
    uncorrelated_responses: VecDeque<JsonRpcResponse>,
    terminal_records: HashMap<(RequestId, u64), ExecutionTerminalRecord>,
    terminal_expirations: HashMap<(RequestId, u64), Instant>,
    cancellation_events: VecDeque<CancellationRequested>,
    deferred_drop_cancellations: VecDeque<DeferredDropCancellation>,
    task_subscriptions: HashMap<(RequestId, u64), TaskSubscription>,
    next_generation: u64,
    result_peer_era: ResultPeerEra,
    terminal_error: Option<McpError>,
    shutdown: bool,
}

impl<T> ExecutorState<T> {
    fn retain_notification(&mut self, request: JsonRpcRequest) -> bool {
        if self.notifications.len() >= MAX_RETAINED_PEER_ACTIVITY {
            return false;
        }
        self.notifications.push_back(request);
        true
    }

    fn retain_uncorrelated_response(&mut self, response: JsonRpcResponse) -> bool {
        if self.uncorrelated_responses.len() >= MAX_RETAINED_PEER_ACTIVITY {
            return false;
        }
        self.uncorrelated_responses.push_back(response);
        true
    }

    fn retain_reverse_request(&mut self, request: JsonRpcRequest) -> McpResult<()> {
        let request_id = request.id.clone().ok_or_else(|| {
            McpError::invalid_request("Client reverse request omitted a JSON-RPC request ID")
        })?;
        let key = request_id.correlation_key().map_err(|_| {
            McpError::invalid_request("Client reverse request has an invalid JSON-RPC request ID")
        })?;
        if self.pending_reverse_requests.contains_key(&key) {
            return Err(McpError::invalid_request(
                "Client reverse request ID is already active",
            ));
        }
        if self.reverse_requests.len() >= MAX_RETAINED_PEER_ACTIVITY {
            return Err(McpError::internal_error(
                "Client reverse-request queue is full",
            ));
        }
        let cancellation = ReverseRequestCancellation::new();
        let owner = Arc::new(());
        self.pending_reverse_requests.insert(
            key,
            ActiveReverseRequest {
                request_id: request_id.clone(),
                cancellation: cancellation.clone(),
                owner: Arc::clone(&owner),
            },
        );
        self.reverse_requests.push_back(ReverseRequest {
            request,
            cancellation,
            owner,
        });
        Ok(())
    }

    fn prune_tombstones(&mut self, now: Instant) {
        self.tombstones
            .retain(|_, tombstone| tombstone.expires_at > now);
    }

    fn retain_terminal(
        &mut self,
        key: (RequestId, u64),
        record: ExecutionTerminalRecord,
        outcome: ExecutionOutcome,
    ) {
        let now = Instant::now();
        let expires_at = now.checked_add(DEFAULT_TOMBSTONE_RETENTION).unwrap_or(now);
        self.terminal_records.insert(key.clone(), record);
        self.terminal_expirations.insert(key.clone(), expires_at);
        self.completed.insert(key, outcome);
    }

    fn release_terminal(&mut self, key: &(RequestId, u64)) {
        self.completed.remove(key);
        self.terminal_records.remove(key);
        self.terminal_expirations.remove(key);
    }

    fn prune_retained_terminals(&mut self, now: Instant) {
        let expired = self
            .terminal_expirations
            .iter()
            .filter_map(|(key, expires_at)| (*expires_at <= now).then_some(key.clone()))
            .collect::<Vec<_>>();
        for key in expired {
            self.release_terminal(&key);
            self.stream_notifications.remove(&key);
            self.task_subscriptions.remove(&key);
        }
    }

    fn cancel_reverse_requests(&mut self) {
        for reverse_request in self.pending_reverse_requests.values() {
            reverse_request.cancellation.cancel();
        }
        self.pending_reverse_requests.clear();
        self.reverse_requests.clear();
    }

    fn fail_all(&mut self, error: McpError, reason: ExecutionTerminalReason) {
        if self.terminal_error.is_some() {
            return;
        }
        self.terminal_error = Some(error.clone());
        self.tombstones.clear();
        self.cancel_reverse_requests();
        self.task_subscriptions.clear();
        self.deferred_drop_cancellations.clear();
        let pending = std::mem::take(&mut self.pending);
        for (_, pending) in pending {
            let request_id = pending.record.request_id.clone();
            self.stream_notifications
                .remove(&(request_id.clone(), pending.record.execution_generation));
            self.retain_terminal(
                (request_id.clone(), pending.record.execution_generation),
                ExecutionTerminalRecord {
                    terminal_state: ExecutionTerminalState::Failed,
                    terminal_reason: reason,
                    final_delivered: false,
                    cancellation_committed: false,
                    cancellation_transport_attempts: 0,
                    local_cancellation_event: false,
                    waiter_release: true,
                    tombstone: false,
                },
                ExecutionOutcome::Failure(error.clone()),
            );
        }
    }
}

/// A transport-neutral request executor.
///
/// Multiple executions may be started before either is waited. The one
/// transport reader routes each final response by its exact request ID, so a
/// reordered final response becomes available to its owner rather than being
/// consumed by the request currently driving the reader.
#[derive(Debug)]
pub struct RequestExecutor<T> {
    state: SharedExecutorState<T>,
    tombstone_retention: Duration,
    max_in_flight: usize,
    max_correlations: usize,
}

impl<T> Clone for RequestExecutor<T> {
    fn clone(&self) -> Self {
        Self {
            state: self.state.clone(),
            tombstone_retention: self.tombstone_retention,
            max_in_flight: self.max_in_flight,
            max_correlations: self.max_correlations,
        }
    }
}

impl<T> RequestExecutor<T>
where
    T: Transport,
{
    /// Creates an executor with the frozen CLT-01 A correlation bounds.
    #[must_use]
    pub fn new(transport: T) -> Self {
        Self::with_result_peer_era(transport, ResultPeerEra::Legacy)
    }

    /// Creates an executor bound to the negotiated peer era.
    ///
    /// The caller must select this from the completed initialize handshake and
    /// keep it immutable for the connection. The era controls exact result
    /// decoding and whether legacy server-to-client requests reach the
    /// handler boundary. [`Self::new`] retains the legacy-era default for
    /// callers that have not yet integrated negotiation.
    #[must_use]
    pub fn with_result_peer_era(transport: T, result_peer_era: ResultPeerEra) -> Self {
        Self {
            state: SharedExecutorState::new(ExecutorState {
                transport,
                pending: HashMap::new(),
                completed: HashMap::new(),
                tombstones: HashMap::new(),
                notifications: VecDeque::new(),
                reverse_requests: VecDeque::new(),
                pending_reverse_requests: HashMap::new(),
                stream_notifications: HashMap::new(),
                uncorrelated_responses: VecDeque::new(),
                terminal_records: HashMap::new(),
                terminal_expirations: HashMap::new(),
                cancellation_events: VecDeque::new(),
                deferred_drop_cancellations: VecDeque::new(),
                task_subscriptions: HashMap::new(),
                next_generation: 0,
                result_peer_era,
                terminal_error: None,
                shutdown: false,
            }),
            tombstone_retention: DEFAULT_TOMBSTONE_RETENTION,
            max_in_flight: DEFAULT_MAX_IN_FLIGHT_EXECUTIONS,
            max_correlations: DEFAULT_MAX_RESPONSE_CORRELATIONS,
        }
    }

    /// Returns the immutable peer era governing this multiplexed connection.
    #[must_use]
    pub fn result_peer_era(&self) -> ResultPeerEra {
        self.state.borrow().result_peer_era
    }

    /// Starts one request-owned execution after its request is committed.
    ///
    /// `request` must be a JSON-RPC request with an ID. Notifications have no
    /// final result slot and are intentionally rejected by this surface.
    pub fn execute(&self, cx: &Cx, request: Request) -> McpResult<RequestExecution<T>> {
        self.execute_with_timeout_policy(cx, request, RequestTimeoutPolicy::default())
    }

    /// Starts an execution with a per-request bounded timeout policy.
    pub fn execute_with_timeout_policy(
        &self,
        cx: &Cx,
        request: Request,
        timeout_policy: RequestTimeoutPolicy,
    ) -> McpResult<RequestExecution<T>> {
        if cx.checkpoint().is_err() {
            return Err(McpError::request_cancelled());
        }
        let request_id = request.id.clone().ok_or_else(|| {
            McpError::invalid_params("Request execution requires a JSON-RPC request ID")
        })?;
        let correlation_key = request_id.correlation_key().map_err(|_| {
            McpError::invalid_params("Request execution requires a valid JSON-RPC request ID")
        })?;

        let mut state = self.state.borrow_mut();
        self.drain_abandoned_locked(cx, &mut state)?;
        state.prune_tombstones(Instant::now());
        state.prune_retained_terminals(Instant::now());
        if state.shutdown {
            return Err(McpError::internal_error(
                "Client request executor is shut down",
            ));
        }
        if let Some(error) = &state.terminal_error {
            return Err(error.clone());
        }
        if state.pending.contains_key(&correlation_key) {
            return Err(McpError::invalid_request("Duplicate in-flight request ID"));
        }
        if state.tombstones.contains_key(&correlation_key) {
            return Err(McpError::invalid_request(
                "Tombstoned request ID cannot be reused",
            ));
        }
        if state.pending.len() >= self.max_in_flight {
            return Err(McpError::internal_error(
                "Client in-flight execution limit reached",
            ));
        }
        let retained_terminals = state.completed.len().max(state.terminal_records.len());
        if state
            .pending
            .len()
            .saturating_add(state.tombstones.len())
            .saturating_add(retained_terminals)
            >= self.max_correlations
        {
            return Err(McpError::internal_error(
                "Client response correlation limit reached",
            ));
        }
        let generation = state
            .next_generation
            .checked_add(1)
            .ok_or_else(|| McpError::internal_error("Client execution generation exhausted"))?;
        state.next_generation = generation;

        state
            .transport
            .send(cx, &JsonRpcMessage::Request(request.clone()))
            .map_err(|error| self.handle_send_error_locked(&mut state, error))?;

        let committed_at = Instant::now();
        let idle_deadline = committed_at
            .checked_add(timeout_policy.idle_timeout())
            .ok_or_else(|| {
                McpError::internal_error("Client execution idle deadline exceeds the clock range")
            })?;
        let absolute_deadline = committed_at
            .checked_add(timeout_policy.absolute_timeout())
            .ok_or_else(|| {
                McpError::internal_error(
                    "Client execution absolute deadline exceeds the clock range",
                )
            })?;
        let owner_dropped = OwnerDropped::new();
        state.pending.insert(
            correlation_key.clone(),
            PendingExecution {
                record: PendingRequestRecord {
                    correlation_key,
                    request_id: request_id.clone(),
                    execution_generation: generation,
                    request_state: ExecutionTerminalState::Pending,
                    send_committed: true,
                    idle_deadline,
                    absolute_deadline,
                    terminal_state: ExecutionTerminalState::Pending,
                    cancellation_committed: false,
                    tombstone_generation: None,
                },
                owner_dropped: owner_dropped.clone(),
                timeout_policy,
                last_progress: None,
                method: request.method.clone(),
            },
        );

        Ok(RequestExecution {
            request_id,
            generation,
            owner_dropped,
            state: self.state.clone(),
            method: request.method,
            params: request.params,
            task_operation: None,
            tombstone_retention: self.tombstone_retention,
            completed: false,
        })
    }

    pub fn execute_task_tool_call(
        &self,
        cx: &Cx,
        request: Request,
    ) -> McpResult<RequestExecution<T>> {
        self.require_modern_tasks_era()?;
        let core_request = self.decode_final_core_request(&request)?;
        if core_request.method() != TOOLS_CALL {
            return Err(McpError::invalid_params(
                "Tasks tool execution requires a final tools/call request",
            ));
        }
        let mut execution = self.execute(cx, request)?;
        execution.task_operation = Some(TaskExecutionOperation::ToolCall);
        Ok(execution)
    }

    pub fn execute_tasks_get(&self, cx: &Cx, request: Request) -> McpResult<RequestExecution<T>> {
        self.require_modern_tasks_era()?;
        let task = self.decode_tasks_get_request(&request)?;
        let mut execution = self.execute(cx, request)?;
        execution.task_operation = Some(TaskExecutionOperation::Get(task.task_id));
        Ok(execution)
    }

    pub fn execute_tasks_update(
        &self,
        cx: &Cx,
        request: Request,
        task: &Task,
    ) -> McpResult<RequestExecution<T>> {
        self.require_modern_tasks_era()?;
        let Task::InputRequired {
            base,
            input_requests,
        } = task
        else {
            return Err(McpError::invalid_params(
                "tasks/update requires an input_required final task",
            ));
        };
        let ledger = TaskInputLedger::from_requests(input_requests).map_err(|_| {
            McpError::invalid_params("Task input requests are not an admitted ledger")
        })?;
        let update = self.decode_tasks_update_request(&request, &ledger)?;
        if update.task_id != base.task_id {
            return Err(McpError::invalid_params(
                "tasks/update request taskId does not match the retained task",
            ));
        }
        let mut execution = self.execute(cx, request)?;
        execution.task_operation = Some(TaskExecutionOperation::Update(update.task_id));
        Ok(execution)
    }

    pub fn execute_tasks_cancel(
        &self,
        cx: &Cx,
        request: Request,
    ) -> McpResult<RequestExecution<T>> {
        self.require_modern_tasks_era()?;
        let task = self.decode_tasks_cancel_request(&request)?;
        let mut execution = self.execute(cx, request)?;
        execution.task_operation = Some(TaskExecutionOperation::Cancel(task.task_id));
        Ok(execution)
    }

    pub fn execute_tasks_subscription(
        &self,
        cx: &Cx,
        request: Request,
    ) -> McpResult<RequestExecution<T>> {
        self.require_modern_tasks_era()?;
        let requested_filter = self.decode_tasks_subscription_request(&request)?;
        let mut execution = self.execute(cx, request)?;
        execution.task_operation = Some(TaskExecutionOperation::Subscription);
        self.state.borrow_mut().task_subscriptions.insert(
            (execution.request_id.clone(), execution.generation),
            TaskSubscription {
                requested_filter,
                accepted_filter: None,
                notifications: VecDeque::new(),
            },
        );
        Ok(execution)
    }

    /// Drives exactly one peer frame through the correlation registry.
    ///
    /// A malformed or closed transport fails all known owners with the same
    /// typed local outcome and never sends a JSON-RPC response back to the
    /// peer. Notifications are retained separately and never consume a final
    /// response slot.
    pub fn drive(&self, cx: &Cx) -> McpResult<()> {
        let mut state = self.state.borrow_mut();
        self.drain_abandoned_locked(cx, &mut state)?;
        self.expire_timeouts_locked(cx, &mut state, Instant::now())?;
        if let Some(error) = &state.terminal_error {
            return Err(error.clone());
        }
        let message = match state.transport.recv(cx) {
            Ok(message) => message,
            Err(error) => {
                let error = transport_error_to_mcp(error);
                state.fail_all(error.clone(), ExecutionTerminalReason::ConnectionLost);
                return Err(error);
            }
        };
        if message.validate().is_err() {
            let error = McpError::invalid_request("Peer sent an invalid JSON-RPC message");
            state.fail_all(error.clone(), ExecutionTerminalReason::ConnectionLost);
            return Err(error);
        }
        match message {
            // `Transport::recv` has already decoded this typed frame, so it
            // cannot honestly supply the peer's exact result-member source.
            // Do not manufacture one by serializing the `Value` again: raw
            // admissions must use `route_response_with_raw_result` instead.
            JsonRpcMessage::Response(response) => {
                self.route_response_with_raw_result_locked(&mut state, response, None)?;
            }
            JsonRpcMessage::Request(request) => {
                if request.method == "notifications/cancelled" {
                    self.route_cancellation_notification_locked(cx, &mut state, &request)?;
                } else if request.id.is_some() {
                    if state.result_peer_era == ResultPeerEra::Modern {
                        self.reject_modern_reverse_request_locked(cx, &mut state, request)?;
                    } else if let Err(error) = state.retain_reverse_request(request) {
                        state.fail_all(error.clone(), ExecutionTerminalReason::ConnectionLost);
                        return Err(error);
                    }
                } else if self
                    .route_task_subscription_acknowledgement_locked(&mut state, &request)?
                {
                } else if self.route_task_subscription_notification_locked(&mut state, &request)? {
                } else if self.route_stream_notification_locked(&mut state, &request)? {
                } else if !state.retain_notification(request) {
                    let error = McpError::internal_error("Client peer-activity queue is full");
                    state.fail_all(error.clone(), ExecutionTerminalReason::ConnectionLost);
                    return Err(error);
                }
            }
        }
        Ok(())
    }

    /// Routes one already-admitted final response while retaining its exact
    /// result-member source for request-owned decoding.
    ///
    /// This is the exact-source ingress companion to [`Self::drive`]. The
    /// typed transport path does not fabricate a source after decoding; a raw
    /// transport admission supplies the peer's original result source here.
    pub fn route_response_with_raw_result(
        &self,
        cx: &Cx,
        response: JsonRpcResponse,
        raw_result: Option<String>,
    ) -> McpResult<()> {
        let mut state = self.state.borrow_mut();
        self.drain_abandoned_locked(cx, &mut state)?;
        self.expire_timeouts_locked(cx, &mut state, Instant::now())?;
        if state.shutdown {
            return Err(McpError::internal_error(
                "Client request executor is shut down",
            ));
        }
        if let Some(error) = &state.terminal_error {
            return Err(error.clone());
        }
        if response.validate().is_err() {
            let error = McpError::invalid_request("Peer sent an invalid JSON-RPC response");
            state.fail_all(error.clone(), ExecutionTerminalReason::ConnectionLost);
            return Err(error);
        }
        self.route_response_with_raw_result_locked(&mut state, response, raw_result)?;
        Ok(())
    }

    /// Waits for one execution's exact final response while routing peer
    /// traffic for every other live execution.
    pub fn wait(&self, cx: &Cx, execution: &mut RequestExecution<T>) -> McpResult<JsonRpcResponse> {
        let (outcome, _) = self.wait_for_terminal(cx, execution)?;
        match outcome {
            ExecutionOutcome::Response(response) => Ok(response.response),
            ExecutionOutcome::Failure(error) => Err(error),
        }
    }

    /// Waits for a final response and returns preceding request-owned progress.
    ///
    /// The returned stream preserves peer arrival order and is drained exactly
    /// once with the terminal outcome, so a caller cannot accidentally reuse
    /// stale progress after consuming the final response.
    pub fn wait_with_stream(
        &self,
        cx: &Cx,
        execution: &mut RequestExecution<T>,
    ) -> McpResult<(JsonRpcResponse, Vec<JsonRpcRequest>)> {
        let (outcome, stream) = self.wait_for_terminal(cx, execution)?;
        match outcome {
            ExecutionOutcome::Response(response) => Ok((response.response, stream)),
            ExecutionOutcome::Failure(error) => Err(error),
        }
    }

    /// Waits for a final response and returns its exact admitted result source.
    ///
    /// The source is absent for a JSON-RPC error response and for typed
    /// transport ingress that could not retain raw JSON.
    pub fn wait_with_raw_result(
        &self,
        cx: &Cx,
        execution: &mut RequestExecution<T>,
    ) -> McpResult<(JsonRpcResponse, Option<String>)> {
        let (outcome, _) = self.wait_for_terminal(cx, execution)?;
        match outcome {
            ExecutionOutcome::Response(response) => Ok((response.response, response.raw_result)),
            ExecutionOutcome::Failure(error) => Err(error),
        }
    }

    /// Waits for and decodes a final MCP result envelope.
    ///
    /// JSON-RPC errors become their local [`McpError`] equivalent. Successful
    /// result envelopes are decoded through the negotiated peer era, retaining
    /// inert unknown members and exact JSON-number lexemes.
    pub fn wait_decoded(
        &self,
        cx: &Cx,
        execution: &mut RequestExecution<T>,
    ) -> McpResult<(DecodedResult, Option<ResultPeerDiagnostic>)> {
        let (outcome, _) = self.wait_for_terminal(cx, execution)?;
        match outcome {
            ExecutionOutcome::Response(response) => response.into_decoded(),
            ExecutionOutcome::Failure(error) => Err(error),
        }
    }

    /// Waits for a decoded final result and all preceding request-owned progress.
    pub fn wait_decoded_with_stream(
        &self,
        cx: &Cx,
        execution: &mut RequestExecution<T>,
    ) -> McpResult<(
        DecodedResult,
        Option<ResultPeerDiagnostic>,
        Vec<JsonRpcRequest>,
    )> {
        let (outcome, stream) = self.wait_for_terminal(cx, execution)?;
        match outcome {
            ExecutionOutcome::Response(response) => {
                let (decoded, diagnostic) = response.into_decoded()?;
                Ok((decoded, diagnostic, stream))
            }
            ExecutionOutcome::Failure(error) => Err(error),
        }
    }

    pub fn wait_task_tool_call(
        &self,
        cx: &Cx,
        execution: &mut RequestExecution<T>,
    ) -> McpResult<fastmcp_protocol::CreateTaskResult> {
        self.require_modern_tasks_era()?;
        execution.ensure_task_operation(|operation| {
            matches!(operation, TaskExecutionOperation::ToolCall)
        })?;
        let core_request = self.decode_final_core_request_from_execution(execution)?;
        let response = self.wait(cx, execution)?;
        match core_request.decode_response(&response) {
            Ok(CoreResult::Final(FinalCoreResult::ToolsCallTask { result })) => Ok(result),
            Ok(_) | Err(_) => Err(McpError::invalid_request(
                "Peer tools/call result is not a final Tasks creation result",
            )),
        }
    }

    pub fn wait_tasks_get(
        &self,
        cx: &Cx,
        execution: &mut RequestExecution<T>,
    ) -> McpResult<GetTaskResult> {
        self.require_modern_tasks_era()?;
        let expected = execution.task_id_for(|operation| match operation {
            TaskExecutionOperation::Get(task_id) => Some(task_id),
            TaskExecutionOperation::ToolCall
            | TaskExecutionOperation::Update(_)
            | TaskExecutionOperation::Cancel(_)
            | TaskExecutionOperation::Subscription => None,
        })?;
        let response = self.wait(cx, execution)?;
        let result = decode_task_response::<GetTaskResult>(&response, "tasks/get")?;
        if result.task.base().task_id != expected {
            return Err(McpError::invalid_request(
                "tasks/get response taskId does not match its request",
            ));
        }
        Ok(result)
    }

    pub fn wait_tasks_update(
        &self,
        cx: &Cx,
        execution: &mut RequestExecution<T>,
    ) -> McpResult<UpdateTaskResult> {
        self.require_modern_tasks_era()?;
        execution.ensure_task_operation(|operation| {
            matches!(operation, TaskExecutionOperation::Update(_))
        })?;
        let response = self.wait(cx, execution)?;
        decode_task_response(&response, "tasks/update")
    }

    pub fn wait_tasks_cancel(
        &self,
        cx: &Cx,
        execution: &mut RequestExecution<T>,
    ) -> McpResult<CancelTaskResult> {
        self.require_modern_tasks_era()?;
        execution.ensure_task_operation(|operation| {
            matches!(operation, TaskExecutionOperation::Cancel(_))
        })?;
        let response = self.wait(cx, execution)?;
        decode_task_response(&response, "tasks/cancel")
    }

    pub fn take_tasks_subscription_notifications(
        &self,
        execution: &RequestExecution<T>,
    ) -> McpResult<Vec<TaskStatusNotification>> {
        execution.ensure_task_operation(|operation| {
            matches!(operation, TaskExecutionOperation::Subscription)
        })?;
        let mut state = self.state.borrow_mut();
        let subscription = state
            .task_subscriptions
            .get_mut(&(execution.request_id.clone(), execution.generation))
            .ok_or_else(|| McpError::invalid_request("Tasks subscription is no longer active"))?;
        Ok(subscription.notifications.drain(..).collect())
    }

    pub fn wait_tasks_subscription(
        &self,
        cx: &Cx,
        execution: &mut RequestExecution<T>,
    ) -> McpResult<(SubscriptionFilter, Vec<TaskStatusNotification>)> {
        self.require_modern_tasks_era()?;
        execution.ensure_task_operation(|operation| {
            matches!(operation, TaskExecutionOperation::Subscription)
        })?;
        let core_request = self.decode_final_core_request_from_execution(execution)?;
        let key = (execution.request_id.clone(), execution.generation);
        let response = match self.wait(cx, execution) {
            Ok(response) => response,
            Err(error) => {
                self.state.borrow_mut().task_subscriptions.remove(&key);
                return Err(error);
            }
        };
        let terminal = match core_request.decode_response(&response) {
            Ok(CoreResult::Final(FinalCoreResult::SubscriptionsListen { .. })) => Ok(()),
            Ok(_) | Err(_) => Err(McpError::invalid_request(
                "Tasks subscription terminal result is not a matching subscriptions/listen completion",
            )),
        };
        let subscription = self
            .state
            .borrow_mut()
            .task_subscriptions
            .remove(&key)
            .ok_or_else(|| McpError::invalid_request("Tasks subscription state is unavailable"))?;
        terminal?;
        let accepted_filter = subscription.accepted_filter.ok_or_else(|| {
            McpError::invalid_request("Tasks subscription terminated before acknowledgement")
        })?;
        Ok((
            accepted_filter,
            subscription.notifications.into_iter().collect(),
        ))
    }

    /// Returns snapshots of every active request correlation.
    #[must_use]
    pub fn pending_records(&self) -> Vec<PendingRequestRecord> {
        self.state
            .borrow()
            .pending
            .values()
            .map(|pending| pending.record.clone())
            .collect()
    }

    /// Removes and returns retained peer notifications in arrival order.
    pub fn take_notifications(&self) -> Vec<JsonRpcRequest> {
        self.state.borrow_mut().notifications.drain(..).collect()
    }

    /// Removes and returns exact-legacy peer requests that require a client response.
    ///
    /// Each returned request retains its own response capability and
    /// cancellation handle. Pass the same value to
    /// [`Self::respond_to_reverse_request`] so an old callback cannot respond
    /// to a later peer request that reuses its JSON-RPC ID.
    pub fn take_reverse_requests(&self) -> Vec<ReverseRequest> {
        self.state.borrow_mut().reverse_requests.drain(..).collect()
    }

    /// Sends one final result for an exact-legacy peer-authored reverse request.
    pub fn respond_to_reverse_request(
        &self,
        cx: &Cx,
        request: &ReverseRequest,
        result: Value,
    ) -> McpResult<()> {
        let mut state = self.state.borrow_mut();
        if state.shutdown {
            return Err(McpError::internal_error(
                "Client request executor is shut down",
            ));
        }
        if state.terminal_error.is_some() {
            return Err(McpError::internal_error(
                "Client request executor connection is no longer usable",
            ));
        }
        let request_id = request.request_id();
        let key = request_id.correlation_key().map_err(|_| {
            McpError::invalid_request("Client reverse response has an invalid JSON-RPC request ID")
        })?;
        let Some(active) = state.pending_reverse_requests.get(&key) else {
            return Err(McpError::invalid_request(
                "Client reverse response does not own a live peer request ID",
            ));
        };
        if !Arc::ptr_eq(&active.owner, &request.owner)
            || !active
                .cancellation
                .belongs_to_same_request(&request.cancellation)
            || !active.request_id.correlates_with(request_id)
            || !request.cancellation.is_open()
        {
            return Err(McpError::invalid_request(
                "Client reverse response does not own a live peer request ID",
            ));
        }
        let owned_request_id = active.request_id.clone();
        state
            .transport
            .send(
                cx,
                &JsonRpcMessage::Response(JsonRpcResponse::success(
                    owned_request_id.clone(),
                    result,
                )),
            )
            .map_err(|error| self.handle_send_error_locked(&mut state, error))?;
        request.cancellation.record_response_sent();
        let removed = state.pending_reverse_requests.remove(&key);
        debug_assert!(removed.is_some());
        state.reverse_requests.retain(|request| {
            !request.request_id().correlates_with(&owned_request_id)
        });
        Ok(())
    }

    /// Removes and returns bounded, typed local cancellation indications.
    pub fn take_cancellation_events(&self) -> Vec<CancellationRequested> {
        self.state
            .borrow_mut()
            .cancellation_events
            .drain(..)
            .collect()
    }

    /// Returns terminal receipts retained for unconsumed request executions.
    #[must_use]
    pub fn terminal_records(&self) -> Vec<ExecutionTerminalRecord> {
        let mut state = self.state.borrow_mut();
        state.prune_retained_terminals(Instant::now());
        state.terminal_records.values().cloned().collect()
    }

    /// Selects explicit caller cancellation for one live execution.
    pub fn cancel(&self, cx: &Cx, execution: &mut RequestExecution<T>) -> McpResult<()> {
        execution.ensure_owner(&self.state)?;
        let mut state = self.state.borrow_mut();
        self.cancel_pending_locked(
            cx,
            &mut state,
            &execution.request_id,
            ExecutionTerminalReason::CallerCancelled,
        )
    }

    /// Accepts a peer subscription teardown for one request-owned execution.
    ///
    /// The peer's raw reason is intentionally not retained. Callers invoke
    /// this only after their subscription policy accepts the teardown frame.
    pub fn accept_subscription_teardown(
        &self,
        cx: &Cx,
        execution: &mut RequestExecution<T>,
    ) -> McpResult<()> {
        execution.ensure_owner(&self.state)?;
        let mut state = self.state.borrow_mut();
        let is_active_modern_subscription = state.result_peer_era == ResultPeerEra::Modern
            && state
                .pending
                .get(&execution.request_id.correlation_key().map_err(|_| {
                    McpError::invalid_params(
                        "Request execution owns an invalid JSON-RPC request ID",
                    )
                })?)
                .is_some_and(|pending| pending.method == SUBSCRIPTIONS_LISTEN);
        if !is_active_modern_subscription {
            return Err(McpError::invalid_request(
                "Peer cancellation is only valid for an active modern subscriptions/listen request",
            ));
        }
        self.cancel_pending_without_notification_locked(
            cx,
            &mut state,
            &execution.request_id,
            ExecutionTerminalReason::PeerSubscriptionTeardown,
        )
    }

    /// Expires committed request deadlines at a runtime-supplied monotonic instant.
    pub fn poll_timeouts_at(&self, cx: &Cx, observed_at: Instant) -> McpResult<()> {
        let mut state = self.state.borrow_mut();
        self.drain_abandoned_locked(cx, &mut state)?;
        self.expire_timeouts_locked(cx, &mut state, observed_at)
    }

    /// Cancels live owners, releases their waiters, and closes the transport.
    pub fn shutdown(&self, cx: &Cx) -> McpResult<()> {
        let mut state = self.state.borrow_mut();
        if state.shutdown {
            return Ok(());
        }
        let mut cleanup_error = self
            .flush_deferred_drop_cancellations_locked(cx, &mut state)
            .err();
        state.shutdown = true;
        let request_ids = state
            .pending
            .values()
            .map(|pending| pending.record.request_id.clone())
            .collect::<Vec<_>>();
        for request_id in request_ids {
            if let Err(error) = self.cancel_pending_locked(
                cx,
                &mut state,
                &request_id,
                ExecutionTerminalReason::Shutdown,
            ) {
                cleanup_error.get_or_insert(error);
            }
        }
        state.cancel_reverse_requests();
        if let Err(error) = state.transport.close() {
            let error = transport_error_to_mcp(error);
            state.fail_all(error.clone(), ExecutionTerminalReason::ConnectionLost);
            cleanup_error.get_or_insert(error);
        }
        if let Some(error) = cleanup_error {
            return Err(error);
        }
        state.terminal_error.get_or_insert_with(|| {
            McpError::internal_error("Client request executor is shut down")
        });
        Ok(())
    }

    /// Removes and returns unmatched final responses in arrival order.
    ///
    /// Unknown, duplicate, and expired-owner response IDs are retained as
    /// bounded diagnostics instead of being guessed as another owner's result.
    pub fn take_uncorrelated_responses(&self) -> Vec<JsonRpcResponse> {
        self.state
            .borrow_mut()
            .uncorrelated_responses
            .drain(..)
            .collect()
    }

    fn handle_send_error_locked(
        &self,
        state: &mut ExecutorState<T>,
        transport_error: TransportError,
    ) -> McpError {
        if matches!(&transport_error, TransportError::Codec(_))
            || matches!(&transport_error, TransportError::Io(error) if error.kind() == std::io::ErrorKind::WouldBlock)
        {
            return transport_error_to_mcp(transport_error);
        }
        let error = transport_error_to_mcp(transport_error);
        state.fail_all(error.clone(), ExecutionTerminalReason::ConnectionLost);
        error
    }

    fn reject_modern_reverse_request_locked(
        &self,
        cx: &Cx,
        state: &mut ExecutorState<T>,
        request: JsonRpcRequest,
    ) -> McpResult<()> {
        let request_id = request.id.expect("modern reverse request has an ID");
        let rejection = JsonRpcMessage::Response(JsonRpcResponse::error(
            Some(request_id),
            McpError::method_not_found(&request.method).into(),
        ));
        state
            .transport
            .send(cx, &rejection)
            .map_err(|error| self.handle_send_error_locked(state, error))
    }

    fn wait_for_terminal(
        &self,
        cx: &Cx,
        execution: &mut RequestExecution<T>,
    ) -> McpResult<(ExecutionOutcome, Vec<JsonRpcRequest>)> {
        execution.ensure_owner(&self.state)?;
        loop {
            if let Some(outcome) = execution.take_terminal_outcome()? {
                return Ok(outcome);
            }
            if cx.checkpoint().is_err() {
                self.cancel(cx, execution)?;
                return Ok(execution
                    .take_terminal_outcome()?
                    .expect("caller cancellation selects a terminal execution outcome"));
            }
            self.drive(cx)?;
        }
    }

    fn route_response_with_raw_result_locked(
        &self,
        state: &mut ExecutorState<T>,
        response: JsonRpcResponse,
        raw_result: Option<String>,
    ) -> McpResult<()> {
        let Some(response_id) = response.id.clone() else {
            let error = McpError::invalid_request("Peer response omitted a request ID");
            state.fail_all(error, ExecutionTerminalReason::ConnectionLost);
            return Ok(());
        };
        let Ok(correlation_key) = response_id.correlation_key() else {
            let error = McpError::invalid_request("Peer response used an invalid request ID");
            state.fail_all(error, ExecutionTerminalReason::ConnectionLost);
            return Ok(());
        };
        let retain_late_response_diagnostic =
            state.tombstones.get(&correlation_key).map(|tombstone| {
                debug_assert!(tombstone.generation > 0);
                tombstone.retain_late_response_diagnostic
            });
        if let Some(retain_late_response_diagnostic) = retain_late_response_diagnostic {
            if retain_late_response_diagnostic && !state.retain_uncorrelated_response(response) {
                state.fail_all(
                    McpError::internal_error("Client uncorrelated-response queue is full"),
                    ExecutionTerminalReason::ConnectionLost,
                );
            }
            return Ok(());
        }
        let Some(pending) = state.pending.get(&correlation_key) else {
            if !state.retain_uncorrelated_response(response) {
                state.fail_all(
                    McpError::internal_error("Client uncorrelated-response queue is full"),
                    ExecutionTerminalReason::ConnectionLost,
                );
            }
            return Ok(());
        };
        let generation = pending.record.execution_generation;
        let expires_at = Instant::now()
            .checked_add(self.tombstone_retention)
            .ok_or_else(|| {
                McpError::internal_error("Tombstone retention exceeds the clock range")
            })?;
        let pending = state
            .pending
            .remove(&correlation_key)
            .expect("the exact pending owner remains live until its terminal transition");
        let owned_request_id = pending.record.request_id.clone();
        state.tombstones.insert(
            correlation_key,
            Tombstone {
                generation,
                expires_at,
                retain_late_response_diagnostic: true,
            },
        );
        let accepts_task_result =
            state.result_peer_era == ResultPeerEra::Modern && pending.method == TOOLS_CALL;
        let decoded = match DecodedFinalResponse::admit(
            response,
            raw_result,
            state.result_peer_era,
            accepts_task_result,
        ) {
            Ok(decoded) => decoded,
            Err(error) => {
                state
                    .stream_notifications
                    .remove(&(owned_request_id.clone(), generation));
                state.retain_terminal(
                    (owned_request_id.clone(), generation),
                    ExecutionTerminalRecord {
                        terminal_state: ExecutionTerminalState::Failed,
                        terminal_reason: ExecutionTerminalReason::PeerProtocol,
                        final_delivered: false,
                        cancellation_committed: false,
                        cancellation_transport_attempts: 0,
                        local_cancellation_event: false,
                        waiter_release: true,
                        tombstone: true,
                    },
                    ExecutionOutcome::Failure(error),
                );
                return Ok(());
            }
        };
        state.retain_terminal(
            (owned_request_id.clone(), generation),
            ExecutionTerminalRecord {
                terminal_state: ExecutionTerminalState::Response,
                terminal_reason: ExecutionTerminalReason::FinalResponse,
                final_delivered: true,
                cancellation_committed: false,
                cancellation_transport_attempts: 0,
                local_cancellation_event: false,
                waiter_release: true,
                tombstone: true,
            },
            ExecutionOutcome::Response(decoded),
        );
        Ok(())
    }

    fn drain_abandoned_locked(&self, cx: &Cx, state: &mut ExecutorState<T>) -> McpResult<()> {
        let now = Instant::now();
        state.prune_tombstones(now);
        state.prune_retained_terminals(now);
        self.flush_deferred_drop_cancellations_locked(cx, state)?;
        let abandoned = state
            .pending
            .iter()
            .filter(|(_, pending)| pending.owner_dropped.get())
            .map(|(_, pending)| {
                (
                    pending.record.request_id.clone(),
                    pending.record.execution_generation,
                )
            })
            .collect::<Vec<_>>();
        for (request_id, generation) in abandoned {
            let cancellation = self.cancel_pending_locked(
                cx,
                state,
                &request_id,
                ExecutionTerminalReason::CallerDropped,
            );
            // A dropped owner has no waiter that can consume the local
            // outcome, so retain only its correlation tombstone.
            state.release_terminal(&(request_id, generation));
            cancellation?;
        }
        Ok(())
    }

    fn flush_deferred_drop_cancellations_locked(
        &self,
        cx: &Cx,
        state: &mut ExecutorState<T>,
    ) -> McpResult<()> {
        while let Some(cancellation) = state.deferred_drop_cancellations.pop_front() {
            if let Some(record) = state
                .terminal_records
                .get_mut(&(cancellation.request_id.clone(), cancellation.generation))
            {
                record.cancellation_transport_attempts =
                    record.cancellation_transport_attempts.saturating_add(1);
            }
            if let Err(error) = state.transport.send(cx, &cancellation.message) {
                let error = transport_error_to_mcp(error);
                state.fail_all(error.clone(), ExecutionTerminalReason::ConnectionLost);
                return Err(error);
            }
        }
        Ok(())
    }

    fn cancel_pending_locked(
        &self,
        cx: &Cx,
        state: &mut ExecutorState<T>,
        request_id: &RequestId,
        reason: ExecutionTerminalReason,
    ) -> McpResult<()> {
        self.cancel_pending_with_notification_locked(cx, state, request_id, reason, true)
    }

    fn cancel_pending_without_notification_locked(
        &self,
        cx: &Cx,
        state: &mut ExecutorState<T>,
        request_id: &RequestId,
        reason: ExecutionTerminalReason,
    ) -> McpResult<()> {
        self.cancel_pending_with_notification_locked(cx, state, request_id, reason, false)
    }

    fn cancel_pending_with_notification_locked(
        &self,
        cx: &Cx,
        state: &mut ExecutorState<T>,
        request_id: &RequestId,
        reason: ExecutionTerminalReason,
        notify_peer: bool,
    ) -> McpResult<()> {
        let correlation_key = request_id.correlation_key().map_err(|_| {
            McpError::invalid_params("Request cancellation requires a valid JSON-RPC request ID")
        })?;
        let Some(pending) = state.pending.get(&correlation_key) else {
            return Ok(());
        };
        // MCP forbids client cancellation of initialize. A local owner still
        // transitions to cancellation, but no peer notification is emitted.
        let notify_peer = notify_peer && pending.method != INITIALIZE;
        // Assemble the selected-era notification before the terminal CAS so a
        // local encoding failure leaves the still-live owner unchanged.
        let cancellation = if notify_peer {
            Some(self.cancellation_control_message(state, request_id)?)
        } else {
            None
        };
        let Some(mut pending) = state.pending.remove(&correlation_key) else {
            return Ok(());
        };
        let owned_request_id = pending.record.request_id.clone();
        pending.record.cancellation_committed = true;
        pending.record.terminal_state = ExecutionTerminalState::Cancelled;
        let generation = pending.record.execution_generation;
        state
            .task_subscriptions
            .remove(&(owned_request_id.clone(), generation));
        let expires_at = Instant::now()
            .checked_add(self.tombstone_retention)
            .ok_or_else(|| {
                McpError::internal_error("Tombstone retention exceeds the clock range")
            })?;
        state.tombstones.insert(
            correlation_key,
            Tombstone {
                generation,
                expires_at,
                retain_late_response_diagnostic: false,
            },
        );
        state
            .stream_notifications
            .remove(&(owned_request_id.clone(), generation));
        state.retain_terminal(
            (owned_request_id.clone(), generation),
            ExecutionTerminalRecord {
                terminal_state: ExecutionTerminalState::Cancelled,
                terminal_reason: reason,
                final_delivered: false,
                cancellation_committed: true,
                cancellation_transport_attempts: u8::from(notify_peer),
                local_cancellation_event: true,
                waiter_release: true,
                tombstone: true,
            },
            ExecutionOutcome::Failure(McpError::request_cancelled()),
        );
        if state.cancellation_events.len() >= MAX_RETAINED_PEER_ACTIVITY {
            // Cancellation is never held behind observer backpressure. The
            // bounded observer queue evicts its oldest already-observed event
            // so the current terminal transition retains its typed signal.
            let _ = state.cancellation_events.pop_front();
        }
        state.cancellation_events.push_back(CancellationRequested {
            request_id: owned_request_id,
            reason,
        });
        if !notify_peer {
            return Ok(());
        }
        let Some(cancellation) = cancellation else {
            return Ok(());
        };
        if let Err(error) = state.transport.send(cx, &cancellation) {
            let error = transport_error_to_mcp(error);
            state.fail_all(error.clone(), ExecutionTerminalReason::ConnectionLost);
            return Err(error);
        }
        Ok(())
    }

    fn route_cancellation_notification_locked(
        &self,
        cx: &Cx,
        state: &mut ExecutorState<T>,
        notification: &JsonRpcRequest,
    ) -> McpResult<bool> {
        if notification.method != "notifications/cancelled" {
            return Ok(false);
        }
        let era = match state.result_peer_era {
            ResultPeerEra::Legacy => ProtocolEra::Legacy2024,
            ResultPeerEra::Modern => ProtocolEra::Modern2026,
        };
        let Ok(cancellation) =
            CancellationWireMessage::decode(era, CancellationSender::Server, notification)
        else {
            return Ok(true);
        };
        match cancellation {
            CancellationWireMessage::Legacy2024 { params, .. } => {
                let key = params.request_id.correlation_key().ok();
                if let Some(active) = key
                    .as_ref()
                    .and_then(|key| state.pending_reverse_requests.remove(key))
                {
                    active.cancellation.cancel();
                    state.reverse_requests.retain(|request| {
                        !Arc::ptr_eq(&request.owner, &active.owner)
                    });
                }
            }
            CancellationWireMessage::Modern2026 { params, .. } => {
                if let Some(metadata_subscription_id) = params
                    .meta
                    .as_ref()
                    .and_then(|metadata| metadata.get(FINAL_SUBSCRIPTION_ID_META_KEY))
                    .and_then(|value| serde_json::from_value::<RequestId>(value.clone()).ok())
                    && !metadata_subscription_id.correlates_with(&params.request_id)
                {
                    return Ok(true);
                }
                let active_subscription_id = state.pending.values().find_map(|pending| {
                    (pending.method == SUBSCRIPTIONS_LISTEN
                        && pending
                            .record
                            .request_id
                            .correlates_with(&params.request_id))
                    .then(|| pending.record.request_id.clone())
                });
                if let Some(active_subscription_id) = active_subscription_id {
                    self.cancel_pending_without_notification_locked(
                        cx,
                        state,
                        &active_subscription_id,
                        ExecutionTerminalReason::PeerSubscriptionTeardown,
                    )?;
                }
            }
        }
        Ok(true)
    }

    fn cancellation_control_message(
        &self,
        state: &ExecutorState<T>,
        request_id: &RequestId,
    ) -> McpResult<JsonRpcMessage> {
        cancellation_control_message_for_era(state.result_peer_era, request_id)
    }

    fn route_task_subscription_acknowledgement_locked(
        &self,
        state: &mut ExecutorState<T>,
        notification: &JsonRpcRequest,
    ) -> McpResult<bool> {
        if notification.id.is_some()
            || notification.method != "notifications/subscriptions/acknowledged"
            || state.task_subscriptions.is_empty()
        {
            return Ok(false);
        }
        let Some(params) = notification.params.clone() else {
            return Ok(false);
        };
        let acknowledgement: FinalSubscriptionsAcknowledgedNotificationParams =
            serde_json::from_value(params).map_err(|_| {
                McpError::invalid_request("Tasks subscription acknowledgement is invalid")
            })?;
        let Some(subscription_id) = acknowledgement
            .meta
            .as_ref()
            .and_then(|metadata| metadata.get(FINAL_SUBSCRIPTION_ID_META_KEY))
            .and_then(|value| serde_json::from_value::<RequestId>(value.clone()).ok())
        else {
            return Ok(false);
        };
        let Some((owned_subscription_id, generation)) = state
            .pending
            .values()
            .find(|pending| pending.record.request_id.correlates_with(&subscription_id))
            .map(|pending| {
                (
                    pending.record.request_id.clone(),
                    pending.record.execution_generation,
                )
            })
        else {
            return Ok(false);
        };
        let key = (owned_subscription_id, generation);
        let Some(subscription) = state.task_subscriptions.get(&key) else {
            return Ok(false);
        };
        if subscription.accepted_filter.is_some() {
            return Err(McpError::invalid_request(
                "Tasks subscription received a duplicate acknowledgement",
            ));
        }
        validate_task_subscription_filter(
            &subscription.requested_filter,
            &acknowledgement.notifications,
        )?;
        let subscription = state.task_subscriptions.get_mut(&key).ok_or_else(|| {
            McpError::internal_error("Tasks subscription disappeared during acknowledgement")
        })?;
        subscription.accepted_filter = Some(acknowledgement.notifications);
        Ok(true)
    }

    fn route_task_subscription_notification_locked(
        &self,
        state: &mut ExecutorState<T>,
        notification: &JsonRpcRequest,
    ) -> McpResult<bool> {
        if notification.id.is_some()
            || notification.method != TASK_STATUS_NOTIFICATION
            || state.task_subscriptions.is_empty()
        {
            return Ok(false);
        }
        let Some(params) = notification.params.clone() else {
            return Ok(false);
        };
        let task_notification: TaskStatusNotification = serde_json::from_value(serde_json::json!({
            "jsonrpc": fastmcp_protocol::JSONRPC_VERSION,
            "method": TASK_STATUS_NOTIFICATION,
            "params": params,
        }))
        .map_err(|_| McpError::invalid_request("Tasks subscription event is invalid"))?;
        let Some(subscription_id) = task_notification
            .params
            .meta
            .as_ref()
            .and_then(|metadata| metadata.get(FINAL_SUBSCRIPTION_ID_META_KEY))
            .and_then(|value| serde_json::from_value::<RequestId>(value.clone()).ok())
        else {
            return Ok(false);
        };
        let Some((owned_subscription_id, generation)) = state
            .pending
            .values()
            .find(|pending| pending.record.request_id.correlates_with(&subscription_id))
            .map(|pending| {
                (
                    pending.record.request_id.clone(),
                    pending.record.execution_generation,
                )
            })
        else {
            return Ok(false);
        };
        let key = (owned_subscription_id, generation);
        let Some(subscription) = state.task_subscriptions.get(&key) else {
            return Ok(false);
        };
        let Some(accepted_filter) = subscription.accepted_filter.as_ref() else {
            return Err(McpError::invalid_request(
                "Tasks subscription event arrived before acknowledgement",
            ));
        };
        let accepted_task_ids = task_subscription_ids(accepted_filter).map_err(|_| {
            McpError::internal_error("Tasks subscription retained an invalid acknowledgement")
        })?;
        if !accepted_task_ids.as_ref().is_some_and(|task_ids| {
            task_ids
                .iter()
                .any(|task_id| task_id == &task_notification.params.task.base().task_id)
        }) {
            return Err(McpError::invalid_request(
                "Tasks subscription event taskId is outside the acknowledged filter",
            ));
        }
        if subscription.notifications.len() >= MAX_RETAINED_PEER_ACTIVITY {
            return Err(McpError::internal_error(
                "Tasks subscription event queue is full",
            ));
        }
        state
            .task_subscriptions
            .get_mut(&key)
            .ok_or_else(|| {
                McpError::internal_error("Tasks subscription disappeared during event routing")
            })?
            .notifications
            .push_back(task_notification);
        Ok(true)
    }

    fn require_modern_tasks_era(&self) -> McpResult<()> {
        if self.state.borrow().result_peer_era != ResultPeerEra::Modern {
            return Err(McpError::invalid_request(
                "The final Tasks extension requires a modern peer era",
            ));
        }
        Ok(())
    }

    fn decode_final_core_request(&self, request: &Request) -> McpResult<CoreRequest> {
        CoreRequest::decode(
            ProtocolEra::Modern2026,
            &request.method,
            request.params.as_ref(),
        )
        .map_err(|_| McpError::invalid_params("Invalid final core request for Tasks execution"))
    }

    fn decode_final_core_request_from_execution(
        &self,
        execution: &RequestExecution<T>,
    ) -> McpResult<CoreRequest> {
        CoreRequest::decode(
            ProtocolEra::Modern2026,
            &execution.method,
            execution.params.as_ref(),
        )
        .map_err(|_| McpError::invalid_params("Invalid final core request for Tasks execution"))
    }

    fn task_request_wire(&self, request: &Request) -> McpResult<Value> {
        let request_id = request.id.clone().ok_or_else(|| {
            McpError::invalid_params("Tasks execution requires a JSON-RPC request ID")
        })?;
        Ok(serde_json::json!({
            "jsonrpc": fastmcp_protocol::JSONRPC_VERSION,
            "id": request_id,
            "method": request.method,
            "params": request.params,
        }))
    }

    fn decode_tasks_get_request(&self, request: &Request) -> McpResult<GetTaskParams> {
        TaskMethodRequest::<GetTaskParams>::decode(self.task_request_wire(request)?)
            .map(|request| request.params)
            .map_err(|_| McpError::invalid_params("Invalid final tasks/get request"))
    }

    fn decode_tasks_update_request(
        &self,
        request: &Request,
        ledger: &TaskInputLedger,
    ) -> McpResult<UpdateTaskParams> {
        TaskMethodRequest::<UpdateTaskParams>::decode_update(
            self.task_request_wire(request)?,
            ledger,
        )
        .map(|request| request.params)
        .map_err(|_| McpError::invalid_params("Invalid final tasks/update request"))
    }

    fn decode_tasks_cancel_request(&self, request: &Request) -> McpResult<CancelTaskParams> {
        TaskMethodRequest::<CancelTaskParams>::decode_cancel(self.task_request_wire(request)?)
            .map(|request| request.params)
            .map_err(|_| McpError::invalid_params("Invalid final tasks/cancel request"))
    }

    fn decode_tasks_subscription_request(
        &self,
        request: &Request,
    ) -> McpResult<SubscriptionFilter> {
        if request.method != SUBSCRIPTIONS_LISTEN {
            return Err(McpError::invalid_params(
                "Tasks subscription execution requires subscriptions/listen",
            ));
        }
        self.decode_final_core_request(request)?;
        let params: FinalSubscriptionsListenParams = request
            .params
            .clone()
            .ok_or_else(|| McpError::invalid_params("Tasks subscription requires parameters"))
            .and_then(|params| {
                serde_json::from_value(params).map_err(|_| {
                    McpError::invalid_params("Tasks subscription parameters are invalid")
                })
            })?;
        if task_subscription_ids(&params.notifications)
            .map_err(|_| McpError::invalid_params("Tasks subscription filter is invalid"))?
            .is_none()
        {
            return Err(McpError::invalid_params(
                "Tasks subscription requires a taskIds filter",
            ));
        }
        Ok(params.notifications)
    }

    fn expire_timeouts_locked(
        &self,
        cx: &Cx,
        state: &mut ExecutorState<T>,
        observed_at: Instant,
    ) -> McpResult<()> {
        let expired = state
            .pending
            .iter()
            .filter_map(|(_, pending)| {
                let reason = if observed_at >= pending.record.absolute_deadline {
                    Some(ExecutionTerminalReason::AbsoluteTimeout)
                } else if observed_at >= pending.record.idle_deadline {
                    Some(ExecutionTerminalReason::IdleTimeout)
                } else {
                    None
                }?;
                Some((pending.record.request_id.clone(), reason))
            })
            .collect::<Vec<_>>();
        for (request_id, reason) in expired {
            self.cancel_pending_locked(cx, state, &request_id, reason)?;
        }
        Ok(())
    }

    fn route_stream_notification_locked(
        &self,
        state: &mut ExecutorState<T>,
        notification: &JsonRpcRequest,
    ) -> McpResult<bool> {
        if notification.method != "notifications/progress" {
            return Ok(false);
        }
        let Some(params) = notification.params.as_ref().and_then(Value::as_object) else {
            return Ok(false);
        };
        let Some(token) = params.get("progressToken") else {
            return Ok(false);
        };
        let Ok(request_id) = serde_json::from_value::<RequestId>(token.clone()) else {
            return Ok(false);
        };
        let Some(progress) = params.get("progress").and_then(Value::as_f64) else {
            return Ok(false);
        };
        if !progress.is_finite() {
            return Ok(false);
        }
        let Ok(correlation_key) = request_id.correlation_key() else {
            return Ok(false);
        };
        let Some(pending) = state.pending.get_mut(&correlation_key) else {
            return Ok(false);
        };
        if pending.last_progress.is_some_and(|prior| progress <= prior) {
            return Ok(false);
        }
        pending.last_progress = Some(progress);
        if pending.timeout_policy.resets_idle_on_matching_progress() {
            let reset_at = Instant::now();
            let next_idle = reset_at
                .checked_add(pending.timeout_policy.idle_timeout())
                .ok_or_else(|| {
                    McpError::internal_error("Client idle deadline exceeds the clock range")
                })?;
            pending.record.idle_deadline = next_idle.min(pending.record.absolute_deadline);
        }
        let generation = pending.record.execution_generation;
        let owned_request_id = pending.record.request_id.clone();
        let stream = state
            .stream_notifications
            .entry((owned_request_id, generation))
            .or_default();
        if stream.len() >= MAX_RETAINED_PEER_ACTIVITY {
            return Err(McpError::internal_error(
                "Client request stream queue is full",
            ));
        }
        stream.push_back(notification.clone());
        Ok(true)
    }
}

fn cancellation_control_message_for_era(
    peer_era: ResultPeerEra,
    request_id: &RequestId,
) -> McpResult<JsonRpcMessage> {
    let cancellation = match peer_era {
        ResultPeerEra::Legacy => CancellationWireMessage::Legacy2024 {
            sender: CancellationSender::Client,
            params: CancelledParams {
                request_id: request_id.clone(),
                reason: None,
            },
        },
        ResultPeerEra::Modern => CancellationWireMessage::Modern2026 {
            sender: CancellationSender::Client,
            params: FinalCancelledNotificationParams {
                request_id: request_id.clone(),
                reason: None,
                meta: None,
                additional: Default::default(),
            },
        },
    };
    cancellation
        .encode()
        .map(JsonRpcMessage::Request)
        .map_err(|error| {
            McpError::invalid_params(format!("Invalid cancellation control parameters: {error}"))
        })
}

fn decode_task_response<R>(response: &JsonRpcResponse, method: &'static str) -> McpResult<R>
where
    R: serde::de::DeserializeOwned,
{
    let result = response.result.clone().ok_or_else(|| {
        McpError::invalid_request(format!("Peer {method} response did not contain a result"))
    })?;
    serde_json::from_value(result)
        .map_err(|_| McpError::invalid_request(format!("Peer {method} result is invalid")))
}

fn validate_task_subscription_filter(
    requested_filter: &SubscriptionFilter,
    accepted_filter: &SubscriptionFilter,
) -> McpResult<()> {
    let requested_task_ids = task_subscription_ids(requested_filter)
        .map_err(|_| McpError::internal_error("Tasks subscription request filter is invalid"))?
        .ok_or_else(|| McpError::internal_error("Tasks subscription omitted its taskIds filter"))?;
    let accepted_task_ids = task_subscription_ids(accepted_filter).map_err(|_| {
        McpError::invalid_request("Tasks subscription acknowledgement filter is invalid")
    })?;
    if let Some(accepted_task_ids) = accepted_task_ids {
        for (index, task_id) in accepted_task_ids.iter().enumerate() {
            if !requested_task_ids
                .iter()
                .any(|requested| requested == task_id)
                || accepted_task_ids[..index]
                    .iter()
                    .any(|previous| previous == task_id)
            {
                return Err(McpError::invalid_request(
                    "Tasks subscription acknowledgement contains an unrequested taskId",
                ));
            }
        }
    }
    Ok(())
}

/// One request-owned response stream handle.
///
/// Dropping a live handle promptly selects its local terminal transition and
/// queues its one bounded cancellation notification. The next executor
/// operation owns the transport send, so `Drop` never performs I/O while it
/// holds the shared executor state.
#[derive(Debug)]
pub struct RequestExecution<T> {
    request_id: RequestId,
    generation: u64,
    owner_dropped: OwnerDropped,
    state: SharedExecutorState<T>,
    method: String,
    params: Option<Value>,
    task_operation: Option<TaskExecutionOperation>,
    tombstone_retention: Duration,
    completed: bool,
}

impl<T> RequestExecution<T> {
    /// Returns the exact request ID committed for this execution.
    #[must_use]
    pub fn request_id(&self) -> &RequestId {
        &self.request_id
    }

    /// Returns this request ID's monotonic local execution generation.
    #[must_use]
    pub const fn generation(&self) -> u64 {
        self.generation
    }

    /// Removes request-owned streaming notifications in peer arrival order.
    ///
    /// Only structurally valid progress with this execution's exact token can
    /// enter this queue; generic notifications remain executor-level activity.
    pub fn take_stream_notifications(&mut self) -> McpResult<Vec<JsonRpcRequest>> {
        if self.completed {
            return Err(McpError::invalid_request(
                "Request execution result was already consumed",
            ));
        }
        Ok(self
            .state
            .borrow_mut()
            .stream_notifications
            .remove(&(self.request_id.clone(), self.generation))
            .map_or_else(Vec::new, |events| events.into_iter().collect()))
    }

    fn ensure_owner(&self, state: &SharedExecutorState<T>) -> McpResult<()> {
        if !SharedExecutorState::ptr_eq(&self.state, state) {
            return Err(McpError::invalid_params(
                "Request execution belongs to a different executor",
            ));
        }
        if self.completed {
            return Err(McpError::invalid_request(
                "Request execution result was already consumed",
            ));
        }
        Ok(())
    }

    fn ensure_task_operation(
        &self,
        accepts: impl FnOnce(&TaskExecutionOperation) -> bool,
    ) -> McpResult<()> {
        self.ensure_owner(&self.state)?;
        if self
            .task_operation
            .as_ref()
            .is_none_or(|operation| !accepts(operation))
        {
            return Err(McpError::invalid_params(
                "Request execution does not own the required Tasks operation",
            ));
        }
        Ok(())
    }

    fn task_id_for(
        &self,
        select: impl FnOnce(&TaskExecutionOperation) -> Option<&TaskId>,
    ) -> McpResult<TaskId> {
        self.ensure_owner(&self.state)?;
        self.task_operation
            .as_ref()
            .and_then(select)
            .cloned()
            .ok_or_else(|| {
                McpError::invalid_params(
                    "Request execution does not own the required Tasks operation",
                )
            })
    }

    fn take_terminal_outcome(
        &mut self,
    ) -> McpResult<Option<(ExecutionOutcome, Vec<JsonRpcRequest>)>> {
        if self.completed {
            return Err(McpError::invalid_request(
                "Request execution result was already consumed",
            ));
        }
        let mut state = self.state.borrow_mut();
        let now = Instant::now();
        state.prune_retained_terminals(now);
        let key = (self.request_id.clone(), self.generation);
        let outcome = state.completed.remove(&key);
        let Some(outcome) = outcome else {
            let correlation_key = self.request_id.correlation_key().map_err(|_| {
                McpError::invalid_params("Request execution owns an invalid JSON-RPC request ID")
            })?;
            if state
                .pending
                .get(&correlation_key)
                .is_some_and(|pending| pending.record.execution_generation == self.generation)
            {
                return Ok(None);
            }
            return Err(McpError::internal_error(
                "Request execution terminal result expired before it was consumed",
            ));
        };
        state.terminal_records.remove(&key);
        state.terminal_expirations.remove(&key);
        let stream = state
            .stream_notifications
            .remove(&key)
            .map_or_else(Vec::new, |events| events.into_iter().collect());
        self.completed = true;
        Ok(Some((outcome, stream)))
    }
}

impl<T> Drop for RequestExecution<T> {
    fn drop(&mut self) {
        let key = (self.request_id.clone(), self.generation);
        if self.completed {
            if let Ok(mut state) = self.state.try_borrow_mut() {
                state.release_terminal(&key);
                state.task_subscriptions.remove(&key);
            }
            return;
        }

        self.owner_dropped.set(true);
        let Ok(mut state) = self.state.try_borrow_mut() else {
            return;
        };
        let Ok(correlation_key) = self.request_id.correlation_key() else {
            return;
        };
        let Some(pending) = state.pending.get(&correlation_key) else {
            state.release_terminal(&key);
            state.task_subscriptions.remove(&key);
            state.stream_notifications.remove(&key);
            return;
        };
        if pending.record.execution_generation != self.generation {
            state.release_terminal(&key);
            state.task_subscriptions.remove(&key);
            state.stream_notifications.remove(&key);
            return;
        }
        let Some(pending) = state.pending.remove(&correlation_key) else {
            return;
        };
        state
            .task_subscriptions
            .remove(&(self.request_id.clone(), self.generation));
        state
            .stream_notifications
            .remove(&(self.request_id.clone(), self.generation));
        let now = Instant::now();
        let expires_at = now.checked_add(self.tombstone_retention).unwrap_or(now);
        state.tombstones.insert(
            correlation_key,
            Tombstone {
                generation: self.generation,
                expires_at,
                retain_late_response_diagnostic: false,
            },
        );
        let cancellation = (pending.method != INITIALIZE)
            .then(|| cancellation_control_message_for_era(state.result_peer_era, &self.request_id))
            .transpose()
            .ok()
            .flatten();
        state.retain_terminal(
            key.clone(),
            ExecutionTerminalRecord {
                terminal_state: ExecutionTerminalState::Cancelled,
                terminal_reason: ExecutionTerminalReason::CallerDropped,
                final_delivered: false,
                cancellation_committed: true,
                cancellation_transport_attempts: 0,
                local_cancellation_event: true,
                waiter_release: true,
                tombstone: true,
            },
            ExecutionOutcome::Failure(McpError::request_cancelled()),
        );
        if state.cancellation_events.len() >= MAX_RETAINED_PEER_ACTIVITY {
            let _ = state.cancellation_events.pop_front();
        }
        state.cancellation_events.push_back(CancellationRequested {
            request_id: self.request_id.clone(),
            reason: ExecutionTerminalReason::CallerDropped,
        });
        if let Some(message) = cancellation {
            state
                .deferred_drop_cancellations
                .push_back(DeferredDropCancellation {
                    request_id: self.request_id.clone(),
                    generation: self.generation,
                    message,
                });
        }
        state.release_terminal(&key);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use fastmcp_protocol::ExactJsonValue;
    use fastmcp_transport::CodecError;

    #[derive(Debug)]
    struct ScriptedTransport {
        received: VecDeque<Result<JsonRpcMessage, TransportError>>,
        sent: Vec<JsonRpcMessage>,
        send_error: Option<std::io::ErrorKind>,
    }

    impl ScriptedTransport {
        fn new(received: impl IntoIterator<Item = Result<JsonRpcMessage, TransportError>>) -> Self {
            Self {
                received: received.into_iter().collect(),
                sent: Vec::new(),
                send_error: None,
            }
        }
    }

    impl Transport for ScriptedTransport {
        fn send(&mut self, _cx: &Cx, message: &JsonRpcMessage) -> Result<(), TransportError> {
            if let Some(kind) = self.send_error {
                return Err(TransportError::Io(std::io::Error::from(kind)));
            }
            self.sent.push(message.clone());
            Ok(())
        }

        fn recv(&mut self, _cx: &Cx) -> Result<JsonRpcMessage, TransportError> {
            self.received
                .pop_front()
                .unwrap_or(Err(TransportError::Closed))
        }

        fn close(&mut self) -> Result<(), TransportError> {
            Ok(())
        }
    }

    fn request(id: i64) -> JsonRpcRequest {
        JsonRpcRequest::new("tools/call", Some(serde_json::json!({"id": id})), id)
    }

    fn response(id: i64, result: serde_json::Value) -> JsonRpcMessage {
        JsonRpcMessage::Response(JsonRpcResponse::success(RequestId::Number(id), result))
    }

    fn legacy_reverse_request(id: i64) -> JsonRpcMessage {
        JsonRpcMessage::Request(JsonRpcRequest::new(
            "sampling/createMessage",
            Some(serde_json::json!({"messages": [], "maxTokens": 9})),
            id,
        ))
    }

    fn tasks_subscription_request(id: i64, task_id: &TaskId) -> JsonRpcRequest {
        let mut notifications = SubscriptionFilter::default();
        fastmcp_protocol::set_task_subscription_ids(&mut notifications, vec![task_id.clone()])
            .expect("compose a bounded Tasks subscription filter");
        JsonRpcRequest::new(
            SUBSCRIPTIONS_LISTEN,
            Some(serde_json::json!({
                "_meta": fastmcp_protocol::FinalRequestMeta::new(fastmcp_protocol::ClientCapabilities::default()),
                "notifications": notifications,
            })),
            id,
        )
    }

    fn task_tool_call_request(id: i64) -> JsonRpcRequest {
        JsonRpcRequest::new(
            TOOLS_CALL,
            Some(serde_json::json!({
                "name": "long-running-tool",
                "arguments": {},
                "_meta": fastmcp_protocol::FinalRequestMeta::new(fastmcp_protocol::ClientCapabilities::default()),
            })),
            id,
        )
    }

    fn tasks_subscription_acknowledgement(id: i64, task_id: &TaskId) -> JsonRpcMessage {
        JsonRpcMessage::Request(JsonRpcRequest::notification(
            "notifications/subscriptions/acknowledged",
            Some(serde_json::json!({
                "_meta": {"io.modelcontextprotocol/subscriptionId": id},
                "notifications": {"taskIds": [task_id]},
            })),
        ))
    }

    fn tasks_status_notification(id: i64, task_id: &TaskId) -> JsonRpcMessage {
        JsonRpcMessage::Request(JsonRpcRequest::notification(
            TASK_STATUS_NOTIFICATION,
            Some(serde_json::json!({
                "_meta": {"io.modelcontextprotocol/subscriptionId": id},
                "taskId": task_id,
                "status": "working",
                "createdAt": "2026-07-28T12:00:00.000Z",
                "lastUpdatedAt": "2026-07-28T12:00:00.000Z",
                "ttlMs": null,
            })),
        ))
    }

    #[test]
    fn unit_clt_01_a_positive() {
        assert_eq!(
            clt_01_a_manifest_digest().as_bytes(),
            &[
                0x52, 0x7c, 0x4b, 0xdb, 0x5b, 0xdd, 0xff, 0x10, 0x95, 0xb3, 0x27, 0xf7, 0x92, 0x5b,
                0xcf, 0x73, 0xba, 0x6e, 0xd0, 0x05, 0x22, 0x5b, 0x8b, 0x59, 0x91, 0x6b, 0x0b, 0x7e,
                0xe3, 0x88, 0x62, 0xb7,
            ],
        );
        let executor = RequestExecutor::new(ScriptedTransport::new([
            Ok(response(999, serde_json::json!({"unknown": true}))),
            Ok(response(
                2,
                serde_json::json!({"kind": "input-required", "x": [1, 2]}),
            )),
            Ok(JsonRpcMessage::Request(JsonRpcRequest::notification(
                "notifications/message",
                Some(serde_json::json!({"level": "info"})),
            ))),
            Ok(response(
                1,
                serde_json::json!({"kind": "complete", "extra": {"n": 9007199254740993u64}}),
            )),
        ]));
        let cx = Cx::for_testing();
        let mut first = executor
            .execute(&cx, request(1))
            .expect("first request commits");
        let mut second = executor
            .execute(&cx, request(2))
            .expect("second request commits");

        let records = executor.pending_records();
        assert_eq!(records.len(), 2);
        assert!(records.iter().all(|record| {
            record.correlation_key
                == record
                    .request_id
                    .correlation_key()
                    .expect("committed request IDs remain canonicalizable")
                && record.send_committed
                && record.request_state == ExecutionTerminalState::Pending
                && record.terminal_state == ExecutionTerminalState::Pending
                && !record.cancellation_committed
                && record.tombstone_generation.is_none()
                && record.idle_deadline <= record.absolute_deadline
        }));

        let first_response = executor
            .wait(&cx, &mut first)
            .expect("reordered first response");
        assert_eq!(first_response.id, Some(RequestId::Number(1)));
        assert_eq!(
            first_response.result,
            Some(serde_json::json!({"kind": "complete", "extra": {"n": 9007199254740993u64}}))
        );
        let second_response = executor
            .wait(&cx, &mut second)
            .expect("stored second response");
        assert_eq!(second_response.id, Some(RequestId::Number(2)));
        assert_eq!(
            second_response.result,
            Some(serde_json::json!({"kind": "input-required", "x": [1, 2]}))
        );
        let notifications = executor.take_notifications();
        assert_eq!(notifications.len(), 1);
        assert!(executor.pending_records().is_empty());
        let uncorrelated = executor.take_uncorrelated_responses();
        assert_eq!(uncorrelated.len(), 1);
        assert_eq!(uncorrelated[0].id, Some(RequestId::Number(999)));

        let malformed = RequestExecutor::new(ScriptedTransport::new([Err(TransportError::Codec(
            CodecError::Json(
                serde_json::from_str::<serde_json::Value>("{").expect_err("invalid JSON"),
            ),
        ))]));
        let mut malformed_first = malformed
            .execute(&cx, request(11))
            .expect("first malformed-owner request commits");
        let mut malformed_second = malformed
            .execute(&cx, request(12))
            .expect("second malformed-owner request commits");
        let error = malformed
            .drive(&cx)
            .expect_err("malformed peer ingress fails locally without a peer response");
        assert_eq!(error.code, fastmcp_core::McpErrorCode::InternalError);
        assert_eq!(
            malformed
                .wait(&cx, &mut malformed_first)
                .expect_err("first owner receives the fanout failure")
                .code,
            fastmcp_core::McpErrorCode::InternalError,
        );
        assert_eq!(
            malformed
                .wait(&cx, &mut malformed_second)
                .expect_err("second owner receives the same fanout failure")
                .code,
            fastmcp_core::McpErrorCode::InternalError,
        );
        assert_eq!(malformed.state.borrow().transport.sent.len(), 2);

        let closed = RequestExecutor::new(ScriptedTransport::new([Err(TransportError::Closed)]));
        let mut closed_first = closed
            .execute(&cx, request(13))
            .expect("first connection-loss owner request commits");
        let mut closed_second = closed
            .execute(&cx, request(14))
            .expect("second connection-loss owner request commits");
        assert!(closed.drive(&cx).is_err());
        assert_eq!(
            closed
                .wait(&cx, &mut closed_first)
                .expect_err("first owner receives connection loss")
                .code,
            fastmcp_core::McpErrorCode::InternalError,
        );
        assert_eq!(
            closed
                .wait(&cx, &mut closed_second)
                .expect_err("second owner receives connection loss")
                .code,
            fastmcp_core::McpErrorCode::InternalError,
        );

        let abandoned = RequestExecutor::new(ScriptedTransport::new([
            Ok(response(31, serde_json::json!({"late": true}))),
            Ok(response(32, serde_json::json!({"current": true}))),
        ]));
        let dropped = abandoned
            .execute(&cx, request(31))
            .expect("abandoned request commits");
        drop(dropped);
        let mut current = abandoned
            .execute(&cx, request(32))
            .expect("next request drains the cancelled owner first");
        let current_response = abandoned
            .wait(&cx, &mut current)
            .expect("late tombstone response cannot poison the next generation");
        assert_eq!(current_response.id, Some(RequestId::Number(32)));
        assert_eq!(abandoned.state.borrow().transport.sent.len(), 3);

        let backpressured = RequestExecutor::new(ScriptedTransport {
            received: VecDeque::new(),
            sent: Vec::new(),
            send_error: Some(std::io::ErrorKind::WouldBlock),
        });
        assert!(backpressured.execute(&cx, request(21)).is_err());
        assert!(backpressured.pending_records().is_empty());
        assert!(backpressured.execute(&cx, request(22)).is_err());
    }

    #[test]
    fn modern_reverse_request_is_rejected_without_mutating_legacy_handler_state() {
        let cx = Cx::for_testing();
        let executor = RequestExecutor::with_result_peer_era(
            ScriptedTransport::new([Ok(legacy_reverse_request(700))]),
            ResultPeerEra::Modern,
        );
        let _execution = executor
            .execute(&cx, request(42))
            .expect("outer request commits before modern peer ingress");
        let pending_before = executor.pending_records();

        executor
            .drive(&cx)
            .expect("modern legacy-shaped reverse request is rejected locally");

        assert!(executor.take_reverse_requests().is_empty());
        assert_eq!(executor.pending_records(), pending_before);
        let state = executor.state.borrow();
        assert!(state.pending_reverse_requests.is_empty());
        assert_eq!(state.reverse_requests.len(), 0);
        assert_eq!(state.transport.sent.len(), 2);
        let JsonRpcMessage::Response(rejection) = &state.transport.sent[1] else {
            panic!("modern reverse request receives one JSON-RPC error response");
        };
        assert_eq!(rejection.id, Some(RequestId::Number(700)));
        let error = rejection
            .error
            .as_ref()
            .expect("rejection carries an error");
        assert_eq!(error.code, i32::from(McpErrorCode::MethodNotFound));
        assert_eq!(error.message, "Method not found");
    }

    #[test]
    fn legacy_reverse_request_remains_available_to_the_handler_boundary() {
        let cx = Cx::for_testing();
        let executor = RequestExecutor::with_result_peer_era(
            ScriptedTransport::new([Ok(legacy_reverse_request(700))]),
            ResultPeerEra::Legacy,
        );
        let _execution = executor
            .execute(&cx, request(42))
            .expect("outer request commits before legacy peer ingress");
        let pending_before = executor.pending_records();

        executor
            .drive(&cx)
            .expect("legacy reverse request reaches the handler boundary");

        let reverse_requests = executor.take_reverse_requests();
        assert_eq!(reverse_requests.len(), 1);
        assert_eq!(reverse_requests[0].request_id(), &RequestId::Number(700));
        assert_eq!(reverse_requests[0].request().method, "sampling/createMessage");
        assert_eq!(executor.pending_records(), pending_before);
        executor
            .respond_to_reverse_request(
                &cx,
                &reverse_requests[0],
                serde_json::json!({"ok": true}),
            )
            .expect("legacy handler result is sent for its exact request ID");

        let state = executor.state.borrow();
        assert!(state.pending_reverse_requests.is_empty());
        assert!(state.reverse_requests.is_empty());
        assert_eq!(state.transport.sent.len(), 2);
        let JsonRpcMessage::Response(response) = &state.transport.sent[1] else {
            panic!("legacy handler result is a JSON-RPC response");
        };
        assert_eq!(response.id, Some(RequestId::Number(700)));
        assert_eq!(response.result, Some(serde_json::json!({"ok": true})));
    }

    #[test]
    fn unit_clt_01_a_planted_negative() {
        let executor = RequestExecutor::new(ScriptedTransport::new(std::iter::empty()));
        let cx = Cx::for_testing();
        let _first = executor
            .execute(&cx, request(7))
            .expect("baseline request commits");
        let before = executor.pending_records();
        let error = executor
            .execute(&cx, request(7))
            .expect_err("changing only the correlation ID to a duplicate must fail");
        assert_eq!(error.code, fastmcp_core::McpErrorCode::InvalidRequest);
        assert_eq!(executor.pending_records(), before);
        assert_eq!(executor.state.borrow().transport.sent.len(), 1);
        assert!(executor.take_notifications().is_empty());
        assert!(executor.take_uncorrelated_responses().is_empty());
    }

    #[test]
    fn unit_clt_01_b_positive() {
        assert_eq!(
            clt_01_b_manifest_digest().as_bytes(),
            &[
                0x8f, 0xae, 0x58, 0xf3, 0x7a, 0xe8, 0x54, 0xb1, 0x89, 0xc7, 0x42, 0x9a, 0x75, 0xd8,
                0xf7, 0x4b, 0x4b, 0x88, 0xda, 0x1e, 0x1d, 0xd7, 0xd5, 0x9a, 0x8d, 0x88, 0x0e, 0xd1,
                0x97, 0xa5, 0x78, 0xc6,
            ],
        );
        let cx = Cx::for_testing();
        let executor = RequestExecutor::new(ScriptedTransport::new([
            Ok(JsonRpcMessage::Request(JsonRpcRequest::new(
                "sampling/createMessage",
                Some(serde_json::json!({"messages": []})),
                700,
            ))),
            Ok(JsonRpcMessage::Request(JsonRpcRequest::notification(
                "notifications/progress",
                Some(serde_json::json!({"progressToken": 42, "progress": 0.5})),
            ))),
            Ok(response(42, serde_json::json!({"kind": "complete"}))),
        ]));
        let mut execution = executor
            .execute(&cx, request(42))
            .expect("public executor commits the request");

        executor.drive(&cx).expect("reverse request is retained");
        let reverse = executor.take_reverse_requests();
        assert_eq!(reverse.len(), 1);
        assert_eq!(reverse[0].request_id(), &RequestId::Number(700));
        executor
            .respond_to_reverse_request(
                &cx,
                &reverse[0],
                serde_json::json!({"ok": true}),
            )
            .expect("reverse request receives a JSON-RPC result");

        let idle_before_progress = executor.pending_records()[0].idle_deadline;
        executor
            .drive(&cx)
            .expect("exact valid progress enters the request-owned stream");
        let stream = execution
            .take_stream_notifications()
            .expect("live execution owns its stream");
        assert_eq!(stream.len(), 1);
        assert_eq!(stream[0].method, "notifications/progress");
        assert!(executor.pending_records()[0].idle_deadline >= idle_before_progress);
        let final_response = executor
            .wait(&cx, &mut execution)
            .expect("stream notification precedes exact final response");
        assert_eq!(final_response.id, Some(RequestId::Number(42)));

        let explicit = RequestExecutor::new(ScriptedTransport::new(std::iter::empty()));
        let mut explicitly_cancelled = explicit
            .execute(&cx, request(43))
            .expect("explicit-cancellation request commits");
        let caller_cancelled = Cx::for_testing();
        caller_cancelled.set_cancel_requested(true);
        assert_eq!(
            explicit
                .wait(&caller_cancelled, &mut explicitly_cancelled)
                .expect_err("caller cancellation selects and releases its exact waiter")
                .code,
            fastmcp_core::McpErrorCode::RequestCancelled,
        );
        assert!(explicit.terminal_records().is_empty());
        assert_eq!(
            explicit.take_cancellation_events(),
            vec![CancellationRequested {
                request_id: RequestId::Number(43),
                reason: ExecutionTerminalReason::CallerCancelled,
            }],
        );

        let timed = RequestExecutor::new(ScriptedTransport::new(std::iter::empty()));
        let short = RequestTimeoutPolicy::new(Duration::from_millis(1), Duration::from_millis(2))
            .expect("bounded timeout policy");
        let mut idle_execution = timed
            .execute_with_timeout_policy(&cx, request(44), short)
            .expect("idle timeout request commits");
        let idle_deadline = timed.pending_records()[0].idle_deadline;
        timed
            .poll_timeouts_at(&cx, idle_deadline)
            .expect("idle deadline selects cancellation");
        assert!(timed.wait(&cx, &mut idle_execution).is_err());
        assert_eq!(
            timed.take_cancellation_events()[0].reason,
            ExecutionTerminalReason::IdleTimeout,
        );

        let absolute = RequestExecutor::new(ScriptedTransport::new(std::iter::empty()));
        let flood_policy =
            RequestTimeoutPolicy::new(Duration::from_secs(1), Duration::from_millis(2))
                .expect("bounded absolute timeout policy");
        let mut absolute_execution = absolute
            .execute_with_timeout_policy(&cx, request(45), flood_policy)
            .expect("absolute timeout request commits");
        let absolute_deadline = absolute.pending_records()[0].absolute_deadline;
        absolute
            .poll_timeouts_at(&cx, absolute_deadline)
            .expect("absolute deadline cannot be reset by peer activity");
        assert!(absolute.wait(&cx, &mut absolute_execution).is_err());
        assert_eq!(
            absolute.take_cancellation_events()[0].reason,
            ExecutionTerminalReason::AbsoluteTimeout,
        );

        let subscription = RequestExecutor::with_result_peer_era(
            ScriptedTransport::new(std::iter::empty()),
            ResultPeerEra::Modern,
        );
        let mut subscribed = subscription
            .execute(
                &cx,
                JsonRpcRequest::new(SUBSCRIPTIONS_LISTEN, Some(serde_json::json!({})), 46),
            )
            .expect("subscription-owned request commits");
        subscription
            .accept_subscription_teardown(&cx, &mut subscribed)
            .expect("accepted teardown selects local cancellation");
        assert!(subscription.wait(&cx, &mut subscribed).is_err());
        assert_eq!(
            subscription.take_cancellation_events()[0].reason,
            ExecutionTerminalReason::PeerSubscriptionTeardown,
        );

        let mut pagination = OpaquePagination::new(PaginationBounds::default(), Instant::now());
        assert!(
            pagination
                .accept_page(Some(String::new()), 0, 0, Instant::now())
                .expect("empty opaque cursor remains present")
        );
        assert_eq!(pagination.next_cursor(), Some(""));
        assert!(
            pagination
                .accept_page(Some(String::new()), 0, 0, Instant::now())
                .expect("repeated opaque cursor remains present")
        );
        assert!(
            !pagination
                .accept_page(None, 0, 0, Instant::now())
                .expect("only cursor absence completes pagination")
        );

        let shutdown = RequestExecutor::new(ScriptedTransport::new(std::iter::empty()));
        let mut closing = shutdown
            .execute(&cx, request(47))
            .expect("shutdown-owned request commits");
        shutdown
            .shutdown(&cx)
            .expect("bounded shutdown closes transport");
        assert!(shutdown.wait(&cx, &mut closing).is_err());
        assert!(shutdown.terminal_records().is_empty());
    }

    #[test]
    fn unit_clt_01_b_planted_negative() {
        let cx = Cx::for_testing();
        let executor = RequestExecutor::new(ScriptedTransport::new([Ok(JsonRpcMessage::Request(
            JsonRpcRequest::notification(
                "notifications/progress",
                Some(serde_json::json!({"progressToken": 101, "progress": 0.5})),
            ),
        ))]));
        let mut execution = executor
            .execute(&cx, request(100))
            .expect("baseline request commits");
        let before = executor.pending_records();
        executor
            .drive(&cx)
            .expect("changing only the progress token leaves the owner untouched");
        assert_eq!(executor.pending_records(), before);
        assert!(
            execution
                .take_stream_notifications()
                .expect("unrelated progress has no stream owner")
                .is_empty()
        );
        assert_eq!(executor.take_notifications().len(), 1);
        assert!(executor.terminal_records().is_empty());
        assert!(executor.take_cancellation_events().is_empty());
    }

    #[test]
    fn request_executor_clone_preserves_raw_results_and_prompt_drop_cancellation() {
        let cx = Cx::for_testing();
        let executor = RequestExecutor::with_result_peer_era(
            ScriptedTransport::new(std::iter::empty()),
            ResultPeerEra::Modern,
        );
        let clone = executor.clone();
        assert_eq!(clone.result_peer_era(), ResultPeerEra::Modern);

        let mut completed = executor
            .execute(&cx, request(80))
            .expect("primary clone commits its request");
        let dropped = clone
            .execute(&cx, request(81))
            .expect("secondary clone shares the same multiplexed core");
        let raw_result = r#"{"resultType":"complete","opaque":{"decimal":1.20e+4}}"#;
        let typed_result: Value = serde_json::from_str(raw_result).expect("raw result is JSON");
        clone
            .route_response_with_raw_result(
                &cx,
                JsonRpcResponse::success(RequestId::Number(80), typed_result),
                Some(raw_result.to_owned()),
            )
            .expect("raw routing admits the completed owner's matching source");
        let (_, preserved_raw_result) = executor
            .wait_with_raw_result(&cx, &mut completed)
            .expect("a response routed by one clone belongs to the exact owner");
        assert_eq!(preserved_raw_result.as_deref(), Some(raw_result));

        drop(dropped);
        assert!(executor.pending_records().is_empty());
        assert!(executor.terminal_records().is_empty());
        assert_eq!(
            executor.take_cancellation_events(),
            vec![CancellationRequested {
                request_id: RequestId::Number(81),
                reason: ExecutionTerminalReason::CallerDropped,
            }],
        );

        assert_eq!(executor.state.borrow().transport.sent.len(), 2);
        clone
            .route_response_with_raw_result(
                &cx,
                JsonRpcResponse::success(
                    RequestId::Number(81),
                    serde_json::json!({"resultType":"complete"}),
                ),
                Some(r#"{"resultType":"complete"}"#.to_owned()),
            )
            .expect("the raw ingress drains cancellation before discarding the tombstoned final");
        let state = executor.state.borrow();
        assert_eq!(state.transport.sent.len(), 3);
        let JsonRpcMessage::Request(cancellation) = &state.transport.sent[2] else {
            panic!("the dropped owner emits a cancellation notification");
        };
        assert_eq!(
            cancellation
                .params
                .as_ref()
                .and_then(|params| params.get("requestId")),
            Some(&Value::from(81)),
        );
    }

    #[test]
    fn request_executor_raw_result_mismatch_rejects_only_its_owner() {
        let cx = Cx::for_testing();
        let executor = RequestExecutor::with_result_peer_era(
            ScriptedTransport::new(std::iter::empty()),
            ResultPeerEra::Modern,
        );
        let mut rejected = executor
            .execute(&cx, request(82))
            .expect("first owner commits");
        let mut admitted = executor
            .execute(&cx, request(83))
            .expect("second owner commits");
        let raw_result = r#"{"resultType":"complete","opaque":{"decimal":1.20e+4}}"#;
        let admitted_result: Value = serde_json::from_str(raw_result).expect("raw result is JSON");
        executor
            .route_response_with_raw_result(
                &cx,
                JsonRpcResponse::success(
                    RequestId::Number(82),
                    serde_json::json!({"resultType":"complete","opaque":{"decimal":12001}}),
                ),
                Some(raw_result.to_owned()),
            )
            .expect("mismatched raw source is routed to its exact owner");
        executor
            .route_response_with_raw_result(
                &cx,
                JsonRpcResponse::success(RequestId::Number(83), admitted_result),
                Some(raw_result.to_owned()),
            )
            .expect("matching raw source is routed to its exact owner");

        assert_eq!(
            executor
                .wait_with_raw_result(&cx, &mut rejected)
                .expect_err("changing only the typed result rejects its owner")
                .code,
            McpErrorCode::InvalidRequest,
        );
        let (_, preserved_raw_result) = executor
            .wait_with_raw_result(&cx, &mut admitted)
            .expect("the exact sibling result remains admitted");
        assert_eq!(preserved_raw_result.as_deref(), Some(raw_result));
        assert_eq!(
            executor
                .execute(&cx, request(82))
                .expect_err("a peer-protocol terminal outcome also retires its canonical ID")
                .code,
            McpErrorCode::InvalidRequest,
        );
    }

    #[test]
    fn normal_drive_never_fabricates_a_raw_result_source() {
        let cx = Cx::for_testing();
        let raw_result = r#"{"resultType":"complete","opaque":{"decimal":1.20e+4}}"#;
        let typed_result: Value = serde_json::from_str(raw_result).expect("raw result is JSON");
        let executor = RequestExecutor::with_result_peer_era(
            ScriptedTransport::new([Ok(JsonRpcMessage::Response(JsonRpcResponse::success(
                RequestId::Number(84),
                typed_result,
            )))]),
            ResultPeerEra::Modern,
        );
        let mut execution = executor
            .execute(&cx, request(84))
            .expect("normal transport request commits");

        let (_, retained_source) = executor
            .wait_with_raw_result(&cx, &mut execution)
            .expect("normal drive preserves the typed response for the waiter");
        assert!(retained_source.is_none());
    }

    #[test]
    fn completed_canonical_id_blocks_alias_reuse_until_tombstone_expiry() {
        let cx = Cx::for_testing();
        let executor = RequestExecutor::with_result_peer_era(
            ScriptedTransport::new(std::iter::empty()),
            ResultPeerEra::Modern,
        );
        let mut completed = executor
            .execute(&cx, request(85))
            .expect("baseline request commits");
        executor
            .route_response_with_raw_result(
                &cx,
                JsonRpcResponse::success(
                    RequestId::Integer("85e0".to_owned()),
                    serde_json::json!({"resultType":"complete"}),
                ),
                Some(r#"{"resultType":"complete"}"#.to_owned()),
            )
            .expect("a numeric response alias completes the baseline owner");

        let alias = || {
            JsonRpcRequest::new(
                "tools/call",
                Some(serde_json::json!({"id": "same-canonical-id"})),
                RequestId::Integer("85e0".to_owned()),
            )
        };
        assert_eq!(
            executor
                .execute(&cx, alias())
                .expect_err("an unconsumed terminal outcome retains its canonical ID")
                .code,
            McpErrorCode::InvalidRequest,
        );
        assert_eq!(
            executor
                .wait(&cx, &mut completed)
                .expect("baseline owner consumes its exact final response")
                .id,
            Some(RequestId::Integer("85e0".to_owned())),
        );
        assert_eq!(
            executor
                .execute(&cx, alias())
                .expect_err("consuming the terminal outcome cannot reopen its canonical ID")
                .code,
            McpErrorCode::InvalidRequest,
        );

        let key = RequestId::Number(85)
            .correlation_key()
            .expect("numeric test ID is canonical");
        executor
            .state
            .borrow_mut()
            .tombstones
            .get_mut(&key)
            .expect("normal terminal outcome retains a canonical tombstone")
            .expires_at = Instant::now();
        let mut replacement = executor
            .execute(&cx, alias())
            .expect("only tombstone expiry permits the canonical replacement");
        executor
            .route_response_with_raw_result(
                &cx,
                JsonRpcResponse::success(
                    RequestId::Number(85),
                    serde_json::json!({"resultType":"complete"}),
                ),
                Some(r#"{"resultType":"complete"}"#.to_owned()),
            )
            .expect("the post-expiry final belongs to the replacement owner");
        assert_eq!(
            executor
                .wait(&cx, &mut replacement)
                .expect("the canonical replacement receives its own final")
                .id,
            Some(RequestId::Number(85)),
        );
    }

    #[test]
    fn normal_terminal_late_duplicate_negative_cannot_complete_an_adjacent_owner() {
        let cx = Cx::for_testing();
        let executor = RequestExecutor::with_result_peer_era(
            ScriptedTransport::new(std::iter::empty()),
            ResultPeerEra::Modern,
        );
        let mut completed = executor
            .execute(&cx, request(86))
            .expect("baseline request commits");
        let raw_result = r#"{"resultType":"complete"}"#;
        executor
            .route_response_with_raw_result(
                &cx,
                JsonRpcResponse::success(
                    RequestId::Number(86),
                    serde_json::json!({"resultType":"complete"}),
                ),
                Some(raw_result.to_owned()),
            )
            .expect("baseline owner receives its terminal response");
        executor
            .wait(&cx, &mut completed)
            .expect("baseline owner consumes its terminal response");
        let mut adjacent = executor
            .execute(&cx, request(87))
            .expect("an unrelated owner remains admissible");
        let pending_before_late_duplicate = executor.pending_records();

        executor
            .route_response_with_raw_result(
                &cx,
                JsonRpcResponse::success(
                    RequestId::Number(86),
                    serde_json::json!({"resultType":"complete"}),
                ),
                Some(raw_result.to_owned()),
            )
            .expect("changing only the late final ID targets the retired owner");
        assert_eq!(executor.pending_records(), pending_before_late_duplicate);
        executor
            .route_response_with_raw_result(
                &cx,
                JsonRpcResponse::success(
                    RequestId::Number(87),
                    serde_json::json!({"resultType":"complete"}),
                ),
                Some(raw_result.to_owned()),
            )
            .expect("only the adjacent owner's final may complete it");
        assert_eq!(
            executor
                .wait(&cx, &mut adjacent)
                .expect("the late duplicate cannot poison the adjacent owner")
                .id,
            Some(RequestId::Number(87)),
        );
        let late_duplicates = executor.take_uncorrelated_responses();
        assert_eq!(late_duplicates.len(), 1);
        assert_eq!(late_duplicates[0].id, Some(RequestId::Number(86)));
    }

    #[test]
    fn numeric_aliases_share_admission_response_and_tombstone_ownership() {
        let cx = Cx::for_testing();
        let executor = RequestExecutor::with_result_peer_era(
            ScriptedTransport::new(std::iter::empty()),
            ResultPeerEra::Modern,
        );
        let mut owner = executor
            .execute(&cx, request(86))
            .expect("baseline numeric owner commits");

        let alias = JsonRpcRequest::new(
            "tools/call",
            Some(serde_json::json!({"id": "alias"})),
            RequestId::Integer("86e0".to_owned()),
        );
        let error = executor
            .execute(&cx, alias)
            .expect_err("a numeric alias cannot create a second pending owner");
        assert_eq!(error.code, McpErrorCode::InvalidRequest);
        assert_eq!(executor.pending_records().len(), 1);
        assert_eq!(executor.state.borrow().transport.sent.len(), 1);

        executor
            .route_response_with_raw_result(
                &cx,
                JsonRpcResponse::success(
                    RequestId::Integer("86e0".to_owned()),
                    serde_json::json!({"resultType":"complete"}),
                ),
                Some(r#"{"resultType":"complete"}"#.to_owned()),
            )
            .expect("a numeric response alias completes the original owner");
        let response = executor
            .wait(&cx, &mut owner)
            .expect("the original owner receives its aliased final response");
        assert_eq!(response.id, Some(RequestId::Integer("86e0".to_owned())));

        let tombstoned = executor
            .execute(&cx, request(87))
            .expect("second owner commits before caller drop");
        drop(tombstoned);
        let alias = JsonRpcRequest::new(
            "tools/call",
            Some(serde_json::json!({"id": "tombstone-alias"})),
            RequestId::Integer("87e0".to_owned()),
        );
        let error = executor
            .execute(&cx, alias)
            .expect_err("a numeric alias cannot reuse a tombstoned owner");
        assert_eq!(error.code, McpErrorCode::InvalidRequest);
        executor
            .route_response_with_raw_result(
                &cx,
                JsonRpcResponse::success(
                    RequestId::Integer("87e0".to_owned()),
                    serde_json::json!({"resultType":"complete"}),
                ),
                Some(r#"{"resultType":"complete"}"#.to_owned()),
            )
            .expect("a numeric alias is discarded by its matching tombstone");
        executor
            .route_response_with_raw_result(
                &cx,
                JsonRpcResponse::success(
                    RequestId::Number(87),
                    serde_json::json!({"resultType":"complete"}),
                ),
                Some(r#"{"resultType":"complete"}"#.to_owned()),
            )
            .expect("a second late numeric alias remains owned by the tombstone");
        let alias = JsonRpcRequest::new(
            "tools/call",
            Some(serde_json::json!({"id": "tombstone-second-late-alias"})),
            RequestId::Number(87),
        );
        let error = executor
            .execute(&cx, alias)
            .expect_err("a late response never consumes the tombstone before its expiry");
        assert_eq!(error.code, McpErrorCode::InvalidRequest);
        assert!(executor.pending_records().is_empty());
        assert!(executor.take_uncorrelated_responses().is_empty());
    }

    #[test]
    fn numeric_alias_tombstone_expiry_allows_a_new_owner() {
        let cx = Cx::for_testing();
        let executor = RequestExecutor::with_result_peer_era(
            ScriptedTransport::new(std::iter::empty()),
            ResultPeerEra::Modern,
        );
        let dropped = executor
            .execute(&cx, request(89))
            .expect("baseline numeric owner commits before drop");
        drop(dropped);
        let key = RequestId::Number(89)
            .correlation_key()
            .expect("numeric test ID is canonical");
        executor
            .state
            .borrow_mut()
            .tombstones
            .get_mut(&key)
            .expect("dropped owner installs its tombstone")
            .expires_at = Instant::now();

        let mut replacement = executor
            .execute(
                &cx,
                JsonRpcRequest::new(
                    "tools/call",
                    Some(serde_json::json!({"id": "replacement-alias"})),
                    RequestId::Integer("89e0".to_owned()),
                ),
            )
            .expect("changing only tombstone expiry permits the canonical replacement");
        executor
            .route_response_with_raw_result(
                &cx,
                JsonRpcResponse::success(
                    RequestId::Number(89),
                    serde_json::json!({"resultType":"complete"}),
                ),
                Some(r#"{"resultType":"complete"}"#.to_owned()),
            )
            .expect("the expired canonical tombstone no longer suppresses its replacement");
        assert_eq!(
            executor
                .wait(&cx, &mut replacement)
                .expect("the replacement owns the post-expiry final")
                .id,
            Some(RequestId::Number(89)),
        );
    }

    #[test]
    fn shutdown_propagates_deferred_drop_cancellation_send_failure() {
        let cx = Cx::for_testing();
        let executor = RequestExecutor::new(ScriptedTransport::new(std::iter::empty()));
        let dropped = executor
            .execute(&cx, request(88))
            .expect("owner commits before its prompt drop");
        drop(dropped);
        executor.state.borrow_mut().transport.send_error = Some(std::io::ErrorKind::BrokenPipe);

        let error = executor
            .shutdown(&cx)
            .expect_err("shutdown must expose deferred cancellation cleanup failure");
        assert_ne!(error.code, McpErrorCode::RequestCancelled);
        let state = executor.state.borrow();
        assert!(state.shutdown);
        assert!(state.terminal_error.is_some());
        assert!(state.deferred_drop_cancellations.is_empty());
        assert!(state.pending.is_empty());
    }

    #[test]
    fn shutdown_propagates_active_owner_cancellation_send_failure() {
        let cx = Cx::for_testing();
        let executor = RequestExecutor::new(ScriptedTransport::new(std::iter::empty()));
        let active = executor
            .execute(&cx, request(90))
            .expect("owner commits before shutdown cancellation");
        executor.state.borrow_mut().transport.send_error = Some(std::io::ErrorKind::BrokenPipe);

        let error = executor
            .shutdown(&cx)
            .expect_err("shutdown must expose active-owner cancellation send failure");
        assert_ne!(error.code, McpErrorCode::RequestCancelled);
        let state = executor.state.borrow();
        assert!(state.shutdown);
        assert!(state.terminal_error.is_some());
        assert!(state.pending.is_empty());
        assert_eq!(state.terminal_records.len(), 1);
        drop(state);
        drop(active);
        assert!(executor.terminal_records().is_empty());
    }

    #[test]
    fn completed_terminal_state_is_released_on_consumption_but_correlation_retires_until_expiry() {
        let cx = Cx::for_testing();
        let mut executor = RequestExecutor::with_result_peer_era(
            ScriptedTransport::new(std::iter::empty()),
            ResultPeerEra::Modern,
        );
        executor.max_correlations = 1;
        let mut first = executor
            .execute(&cx, request(91))
            .expect("first owner fits the bounded retained-correlation budget");
        executor
            .route_response_with_raw_result(
                &cx,
                JsonRpcResponse::success(
                    RequestId::Number(91),
                    serde_json::json!({"resultType":"complete"}),
                ),
                Some(r#"{"resultType":"complete"}"#.to_owned()),
            )
            .expect("first owner receives its terminal result");
        assert_eq!(executor.state.borrow().completed.len(), 1);
        assert_eq!(executor.terminal_records().len(), 1);
        assert_eq!(
            executor
                .execute(&cx, request(92))
                .expect_err("an unconsumed completed result occupies the bounded budget")
                .code,
            McpErrorCode::InternalError,
        );

        executor
            .wait(&cx, &mut first)
            .expect("consuming the terminal result releases its retained state");
        assert!(executor.state.borrow().completed.is_empty());
        assert!(executor.terminal_records().is_empty());
        assert_eq!(
            executor
                .execute(&cx, request(92))
                .expect_err("the retained tombstone occupies correlation capacity before expiry")
                .code,
            McpErrorCode::InternalError,
        );
        let first_key = RequestId::Number(91)
            .correlation_key()
            .expect("numeric test ID is canonical");
        executor
            .state
            .borrow_mut()
            .tombstones
            .get_mut(&first_key)
            .expect("normal terminal result retires its canonical correlation")
            .expires_at = Instant::now();
        let replacement = executor
            .execute(&cx, request(92))
            .expect("tombstone expiry releases capacity for the near-identical owner");
        drop(replacement);
    }

    #[test]
    fn completed_terminal_retention_is_released_on_handle_drop_and_expiry() {
        let cx = Cx::for_testing();
        let mut executor = RequestExecutor::with_result_peer_era(
            ScriptedTransport::new(std::iter::empty()),
            ResultPeerEra::Modern,
        );
        executor.max_correlations = 1;
        let completed = executor
            .execute(&cx, request(93))
            .expect("first owner fits the bounded retained-correlation budget");
        executor
            .route_response_with_raw_result(
                &cx,
                JsonRpcResponse::success(
                    RequestId::Number(93),
                    serde_json::json!({"resultType":"complete"}),
                ),
                Some(r#"{"resultType":"complete"}"#.to_owned()),
            )
            .expect("first owner receives its terminal result");
        drop(completed);
        assert!(executor.state.borrow().completed.is_empty());
        assert!(executor.terminal_records().is_empty());
        let completed_key = RequestId::Number(93)
            .correlation_key()
            .expect("numeric test ID is canonical");
        executor
            .state
            .borrow_mut()
            .tombstones
            .get_mut(&completed_key)
            .expect("dropping the completed handle preserves its response tombstone")
            .expires_at = Instant::now();

        let mut expired = executor
            .execute(&cx, request(94))
            .expect("the completed correlation releases capacity only after tombstone expiry");
        executor
            .route_response_with_raw_result(
                &cx,
                JsonRpcResponse::success(
                    RequestId::Number(94),
                    serde_json::json!({"resultType":"complete"}),
                ),
                Some(r#"{"resultType":"complete"}"#.to_owned()),
            )
            .expect("sibling owner receives its terminal result");
        let key = (RequestId::Number(94), expired.generation());
        executor
            .state
            .borrow_mut()
            .terminal_expirations
            .insert(key, Instant::now());
        assert!(executor.terminal_records().is_empty());
        assert_eq!(
            executor
                .wait(&cx, &mut expired)
                .expect_err("changing only terminal retention to expired releases the outcome")
                .code,
            McpErrorCode::InternalError,
        );
        assert!(executor.state.borrow().completed.is_empty());
    }

    #[test]
    fn raw_routing_expired_owner_negative_discards_final_after_lifecycle_gates() {
        let cx = Cx::for_testing();
        let executor = RequestExecutor::with_result_peer_era(
            ScriptedTransport::new(std::iter::empty()),
            ResultPeerEra::Modern,
        );
        let mut expired = executor
            .execute(&cx, request(85))
            .expect("request commits before raw ingress");
        {
            let mut state = executor.state.borrow_mut();
            let pending = state
                .pending
                .get_mut(
                    &RequestId::Number(85)
                        .correlation_key()
                        .expect("numeric test ID is a valid correlation key"),
                )
                .expect("request remains pending before the planted deadline");
            pending.record.absolute_deadline = Instant::now();
        }

        executor
            .route_response_with_raw_result(
                &cx,
                JsonRpcResponse::success(
                    RequestId::Number(85),
                    serde_json::json!({"resultType":"complete"}),
                ),
                Some(r#"{"resultType":"complete"}"#.to_owned()),
            )
            .expect("raw ingress gates expiry before it considers the final response");

        assert_eq!(
            executor
                .wait(&cx, &mut expired)
                .expect_err("changing only the lifetime to expired rejects the final")
                .code,
            McpErrorCode::RequestCancelled,
        );
        assert!(executor.terminal_records().is_empty());
        assert!(executor.take_uncorrelated_responses().is_empty());
        assert_eq!(executor.state.borrow().transport.sent.len(), 2);
    }

    #[test]
    fn raw_routing_late_dropped_response_negative_cannot_complete_adjacent_owner() {
        let cx = Cx::for_testing();
        let executor = RequestExecutor::with_result_peer_era(
            ScriptedTransport::new(std::iter::empty()),
            ResultPeerEra::Modern,
        );
        let dropped = executor
            .execute(&cx, request(86))
            .expect("first owner commits");
        drop(dropped);
        let mut adjacent = executor
            .execute(&cx, request(87))
            .expect("the next owner flushes the dropped owner's cancellation");
        let raw_result = r#"{"resultType":"complete"}"#;

        executor
            .route_response_with_raw_result(
                &cx,
                JsonRpcResponse::success(
                    RequestId::Number(86),
                    serde_json::json!({"resultType":"complete"}),
                ),
                Some(raw_result.to_owned()),
            )
            .expect("the tombstone consumes only its late raw final");
        assert_eq!(executor.pending_records().len(), 1);
        assert_eq!(
            executor.pending_records()[0].request_id,
            RequestId::Number(87)
        );

        executor
            .route_response_with_raw_result(
                &cx,
                JsonRpcResponse::success(
                    RequestId::Number(87),
                    serde_json::json!({"resultType":"complete"}),
                ),
                Some(raw_result.to_owned()),
            )
            .expect("only the adjacent owner's exact raw final completes it");
        let response = executor
            .wait(&cx, &mut adjacent)
            .expect("late dropped response must not poison the adjacent owner");
        assert_eq!(response.id, Some(RequestId::Number(87)));
        assert!(executor.take_uncorrelated_responses().is_empty());
    }

    #[test]
    fn modern_executor_cancellation_omits_optional_final_metadata() {
        let cx = Cx::for_testing();
        let executor = RequestExecutor::with_result_peer_era(
            ScriptedTransport::new(std::iter::empty()),
            ResultPeerEra::Modern,
        );
        let mut execution = executor
            .execute(&cx, request(47))
            .expect("modern request commits before cancellation");

        executor
            .cancel(&cx, &mut execution)
            .expect("final cancellation needs no synthesized metadata");

        let state = executor.state.borrow();
        assert_eq!(state.transport.sent.len(), 2);
        let JsonRpcMessage::Request(cancellation) = &state.transport.sent[1] else {
            panic!("cancellation is a JSON-RPC notification");
        };
        assert!(cancellation.is_notification());
        assert_eq!(cancellation.method, "notifications/cancelled");
        let params = cancellation
            .params
            .as_ref()
            .expect("final cancellation carries parameters");
        assert_eq!(params.get("requestId"), Some(&serde_json::json!(47)));
        assert!(params.get("_meta").is_none());
        assert!(params.get("awaitCleanup").is_none());
    }

    #[test]
    fn malformed_modern_peer_cancellation_leaves_owner_state_unchanged() {
        let cx = Cx::for_testing();
        let executor = RequestExecutor::with_result_peer_era(
            ScriptedTransport::new([Ok(JsonRpcMessage::Request(JsonRpcRequest::notification(
                "notifications/cancelled",
                Some(serde_json::json!({"reason": "missing request ID"})),
            )))]),
            ResultPeerEra::Modern,
        );
        let mut execution = executor
            .execute(&cx, request(48))
            .expect("baseline modern request commits");
        let pending_before = executor.pending_records();

        executor
            .drive(&cx)
            .expect("invalid peer cancellation is ignored without terminating the client");
        assert_eq!(executor.pending_records(), pending_before);
        assert!(executor.terminal_records().is_empty());
        assert!(executor.take_cancellation_events().is_empty());
        assert_eq!(executor.state.borrow().transport.sent.len(), 1);
        executor
            .cancel(&cx, &mut execution)
            .expect("the still-live owner remains locally cancellable");
    }

    #[test]
    fn unit_clt_01_final_result_stream_reverse_and_peer_cancellation_positive() {
        let cx = Cx::for_testing();
        let complete =
            serde_json::from_str(r#"{"resultType":"complete","opaque":{"decimal":1.20e+4}}"#)
                .expect("exact-number result is valid JSON");
        let executor = RequestExecutor::with_result_peer_era(
            ScriptedTransport::new([
                Ok(JsonRpcMessage::Request(JsonRpcRequest::new(
                    "sampling/createMessage",
                    Some(serde_json::json!({"messages": []})),
                    700,
                ))),
                Ok(JsonRpcMessage::Request(JsonRpcRequest::notification(
                    "notifications/progress",
                    Some(serde_json::json!({"progressToken": 42, "progress": 0.5})),
                ))),
                Ok(response(42, complete)),
            ]),
            ResultPeerEra::Modern,
        );
        let mut execution = executor
            .execute(&cx, request(42))
            .expect("request commits before peer traffic arrives");

        executor
            .drive(&cx)
            .expect("modern legacy-shaped reverse request is rejected");
        assert!(executor.take_reverse_requests().is_empty());
        {
            let state = executor.state.borrow();
            let sent = &state.transport.sent;
            assert_eq!(sent.len(), 2);
            let JsonRpcMessage::Response(rejection) = &sent[1] else {
                panic!("modern reverse request receives an error response");
            };
            assert_eq!(rejection.id, Some(RequestId::Number(700)));
            assert_eq!(
                rejection.error.as_ref().map(|error| error.code.clone()),
                Some(i32::from(McpErrorCode::MethodNotFound))
            );
        }

        let (decoded, diagnostic, stream) = executor
            .wait_decoded_with_stream(&cx, &mut execution)
            .expect("progress precedes a complete final result");
        assert!(diagnostic.is_none());
        assert_eq!(stream.len(), 1);
        assert_eq!(stream[0].method, "notifications/progress");
        assert!(matches!(decoded, DecodedResult::Complete(_)));
        let complete = match decoded {
            DecodedResult::Complete(complete) => complete,
            DecodedResult::InputRequired(_) | DecodedResult::Deferred(_) => return,
        };
        let opaque = complete
            .extras
            .members()
            .iter()
            .find(|member| member.name == "opaque")
            .expect("unknown result member is retained inertly");
        assert!(matches!(opaque.value, ExactJsonValue::Object(_)));
        let opaque = match &opaque.value {
            ExactJsonValue::Object(opaque) => opaque,
            ExactJsonValue::Null
            | ExactJsonValue::Bool(_)
            | ExactJsonValue::String(_)
            | ExactJsonValue::Number(_)
            | ExactJsonValue::Array(_) => return,
        };
        assert_eq!(
            opaque.get("decimal"),
            Some(&ExactJsonValue::Number("1.20e+4".to_owned()))
        );
        assert_eq!(executor.state.borrow().transport.sent.len(), 2);

        let cancelled = RequestExecutor::with_result_peer_era(
            ScriptedTransport::new([
                Ok(JsonRpcMessage::Request(JsonRpcRequest::notification(
                    "notifications/cancelled",
                    Some(serde_json::json!({"requestId": 43, "reason": "peer text"})),
                ))),
                Ok(response(43, serde_json::json!({}))),
            ]),
            ResultPeerEra::Modern,
        );
        let mut cancelled_execution = cancelled
            .execute(&cx, request(43))
            .expect("request commits before peer cancellation");
        let pending_before = cancelled.pending_records();
        cancelled
            .drive(&cx)
            .expect("server cancellation for a non-subscription is ignored");
        assert_eq!(cancelled.pending_records(), pending_before);
        cancelled
            .wait(&cx, &mut cancelled_execution)
            .expect("the ordinary request remains owned by its terminal response");
        assert_eq!(cancelled.state.borrow().transport.sent.len(), 1);
        assert!(cancelled.take_cancellation_events().is_empty());
        assert!(cancelled.take_notifications().is_empty());
    }

    #[test]
    fn unit_clt_01_final_result_planted_negative_is_owner_scoped() {
        let cx = Cx::for_testing();
        let rejected = serde_json::from_str(r#"{"resultType":null,"opaque":{"decimal":1.20e+4}}"#)
            .expect("planted negative remains structurally valid JSON");
        let accepted =
            serde_json::from_str(r#"{"resultType":"complete","opaque":{"decimal":1.20e+4}}"#)
                .expect("near-identical positive remains valid JSON");
        let executor = RequestExecutor::with_result_peer_era(
            ScriptedTransport::new([Ok(response(60, rejected)), Ok(response(61, accepted))]),
            ResultPeerEra::Modern,
        );
        let mut rejected_execution = executor
            .execute(&cx, request(60))
            .expect("first request commits");
        let mut accepted_execution = executor
            .execute(&cx, request(61))
            .expect("second request commits");

        assert_eq!(
            executor
                .wait_decoded(&cx, &mut rejected_execution)
                .expect_err("only explicit null instead of complete is rejected")
                .code,
            McpErrorCode::InvalidRequest,
        );
        let (accepted, diagnostic) = executor
            .wait_decoded(&cx, &mut accepted_execution)
            .expect("the other owner remains eligible for its final result");
        assert!(diagnostic.is_none());
        assert!(matches!(accepted, DecodedResult::Complete(_)));
        assert!(executor.terminal_records().is_empty());
        assert_eq!(executor.state.borrow().transport.sent.len(), 2);
        assert!(executor.take_uncorrelated_responses().is_empty());
    }

    #[test]
    fn unit_task_01_executor_subscription_lifecycle_positive() {
        let cx = Cx::for_testing();
        let task_id = TaskId::parse("task-73").expect("bounded task id");
        let executor = RequestExecutor::with_result_peer_era(
            ScriptedTransport::new([
                Ok(response(
                    72,
                    serde_json::json!({
                        "resultType": "task",
                        "taskId": task_id,
                        "status": "working",
                        "createdAt": "2026-07-28T12:00:00.000Z",
                        "lastUpdatedAt": "2026-07-28T12:00:00.000Z",
                        "ttlMs": null,
                    }),
                )),
                Ok(tasks_subscription_acknowledgement(73, &task_id)),
                Ok(tasks_status_notification(73, &task_id)),
                Ok(response(
                    73,
                    serde_json::json!({
                        "resultType": "complete",
                        "_meta": {"io.modelcontextprotocol/subscriptionId": 73},
                    }),
                )),
            ]),
            ResultPeerEra::Modern,
        );
        let mut task_execution = executor
            .execute_task_tool_call(&cx, task_tool_call_request(72))
            .expect("final tools/call commits before the peer creates its Task");
        let created = executor
            .wait_task_tool_call(&cx, &mut task_execution)
            .expect("final tools/call returns the typed durable Task handle");
        assert_eq!(created.task.base().task_id, task_id);
        let mut subscription = executor
            .execute_tasks_subscription(&cx, tasks_subscription_request(73, &task_id))
            .expect("final Tasks subscription commits after exact local admission");

        let (accepted_filter, notifications) = executor
            .wait_tasks_subscription(&cx, &mut subscription)
            .expect("acknowledged exact Tasks stream terminates through its owner");
        assert_eq!(
            task_subscription_ids(&accepted_filter).expect("accepted filter remains typed"),
            Some(vec![task_id.clone()]),
        );
        assert_eq!(notifications.len(), 1);
        assert_eq!(notifications[0].params.task.base().task_id, task_id);
        assert!(executor.state.borrow().task_subscriptions.is_empty());
        assert!(executor.pending_records().is_empty());
        assert_eq!(executor.state.borrow().transport.sent.len(), 2);
        assert!(executor.terminal_records().is_empty());
        assert!(executor.take_cancellation_events().is_empty());
    }

    #[test]
    fn unit_task_01_executor_subscription_wrong_task_negative_unchanged_state() {
        let cx = Cx::for_testing();
        let requested_task = TaskId::parse("task-73").expect("bounded requested task id");
        let foreign_task = TaskId::parse("task-74").expect("bounded foreign task id");
        let executor = RequestExecutor::with_result_peer_era(
            ScriptedTransport::new([
                Ok(tasks_subscription_acknowledgement(73, &requested_task)),
                Ok(tasks_status_notification(73, &foreign_task)),
            ]),
            ResultPeerEra::Modern,
        );
        let subscription = executor
            .execute_tasks_subscription(&cx, tasks_subscription_request(73, &requested_task))
            .expect("baseline exact Tasks subscription commits");
        executor
            .drive(&cx)
            .expect("baseline acknowledgement is admitted");
        let before_pending = executor.pending_records();
        let before_accepted = executor
            .state
            .borrow()
            .task_subscriptions
            .get(&(RequestId::Number(73), subscription.generation()))
            .and_then(|subscription| subscription.accepted_filter.clone());
        let before_accepted_snapshot =
            serde_json::to_value(&before_accepted).expect("accepted filter snapshot serializes");

        let error = executor
            .drive(&cx)
            .expect_err("changing only taskId to an unacknowledged task must reject the event");
        assert_eq!(error.code, McpErrorCode::InvalidRequest);
        assert_eq!(executor.pending_records(), before_pending);
        let after_accepted = executor
            .state
            .borrow()
            .task_subscriptions
            .get(&(RequestId::Number(73), subscription.generation()))
            .and_then(|subscription| subscription.accepted_filter.clone());
        assert_eq!(
            serde_json::to_value(after_accepted).expect("accepted filter snapshot serializes"),
            before_accepted_snapshot,
        );
        assert!(
            executor
                .take_tasks_subscription_notifications(&subscription)
                .expect("rejected event leaves the listener queue unchanged")
                .is_empty()
        );
        assert_eq!(executor.state.borrow().transport.sent.len(), 1);
        assert!(executor.terminal_records().is_empty());
        assert!(executor.take_cancellation_events().is_empty());
        assert!(executor.take_notifications().is_empty());
    }

    #[test]
    fn cache_03_tolerates_missing_and_negative_cache_ttl_as_immediately_stale() {
        let request = CoreRequest::Final(fastmcp_protocol::FinalCoreRequest::ToolsList(
            fastmcp_protocol::FinalListParams {
                meta: fastmcp_protocol::common_types::OpenMetadata::default(),
                cursor: None,
                include_tags: None,
                exclude_tags: None,
            },
        ));

        let (missing, missing_diagnostic) = decode_core_result_with_cache_ttl(
            &request,
            &serde_json::json!({
                "resultType": "complete",
                "tools": [],
                "cacheScope": "private",
            }),
        )
        .expect("a missing peer TTL is normalized to zero freshness");
        assert_eq!(missing_diagnostic, Some(FinalCacheTtlDiagnostic::Missing));
        assert!(matches!(
            missing,
            CoreResult::Final(FinalCoreResult::ToolsList { result, .. })
                if result.payload.ttl_ms.try_as_millis() == Ok(0)
                    && result.payload.ttl_ms.as_str() == "0"
        ));

        let (negative, negative_diagnostic) = decode_core_result_with_cache_ttl(
            &request,
            &serde_json::json!({
                "resultType": "complete",
                "tools": [],
                "ttlMs": -1.5,
                "cacheScope": "private",
            }),
        )
        .expect("a negative peer TTL is normalized to zero freshness");
        assert_eq!(negative_diagnostic, Some(FinalCacheTtlDiagnostic::Negative));
        assert!(matches!(
            negative,
            CoreResult::Final(FinalCoreResult::ToolsList { result, .. })
                if result.payload.ttl_ms.try_as_millis() == Ok(0)
                    && result.payload.ttl_ms.as_str() == "0"
        ));

        let exact_source = r#"{"resultType":"complete","tools":[],"zeta":{"second":2,"first":1},"ttlMs":-1,"cacheScope":"private","alpha":1.20e+4}"#;
        let exact_value = serde_json::from_str(exact_source).expect("exact TTL source is JSON");
        let (exact, diagnostic) = decode_core_result_with_cache_ttl_from_source(
            &request,
            &exact_value,
            Some(exact_source),
        )
        .expect("negative TTL compatibility retains every other source lexeme");
        assert_eq!(diagnostic, Some(FinalCacheTtlDiagnostic::Negative));
        let CoreResult::Final(FinalCoreResult::ToolsList { result, .. }) = exact else {
            panic!("exact TTL source selects tools/list");
        };
        assert_eq!(result.payload.ttl_ms.as_str(), "0");
        assert_eq!(
            result
                .payload
                .ttl_ms
                .try_as_millis()
                .expect("normalized TTL fits the local duration domain"),
            0
        );
        assert_eq!(
            result
                .extras
                .members()
                .iter()
                .map(|member| member.name.as_str())
                .collect::<Vec<_>>(),
            vec!["zeta", "alpha"],
        );
        assert_eq!(
            result.extras.members()[1].value,
            fastmcp_protocol::ExactJsonValue::Number("1.20e+4".to_owned()),
        );

        assert!(
            decode_core_result_with_cache_ttl(
                &request,
                &serde_json::json!({
                    "resultType": "complete",
                    "tools": [],
                    "ttlMs": 1.5,
                    "cacheScope": "private",
                }),
            )
            .is_err()
        );
    }
}
