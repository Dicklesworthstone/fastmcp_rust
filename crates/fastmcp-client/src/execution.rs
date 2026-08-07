//! Transport-neutral request execution and response correlation.
//!
//! This module owns the correlation rules that are independent of a concrete
//! MCP transport. A transport supplies typed JSON-RPC frames; the executor
//! commits requests, preserves out-of-order final responses for their exact
//! owners, retains bounded tombstones for abandoned owners, and never turns
//! malformed peer ingress into a peer-directed JSON-RPC response.

use std::cell::{Cell, RefCell};
use std::collections::{HashMap, VecDeque};
use std::rc::Rc;
use std::time::{Duration, Instant};

use asupersync::Cx;
use fastmcp_core::{McpError, McpResult, Sha256Digest, sha256_bounded};
use fastmcp_protocol::{
    CancelledParams, JsonRpcMessage, JsonRpcRequest, JsonRpcResponse, RequestId,
};
use fastmcp_transport::{Transport, TransportError};
use serde_json::Value;

use crate::{RequestTimeoutPolicy, transport_error_to_mcp};

/// Default maximum number of active request owners.
pub const DEFAULT_MAX_IN_FLIGHT_EXECUTIONS: usize = 1_024;
/// Absolute ceiling for active request owners.
pub const MAX_IN_FLIGHT_EXECUTIONS: usize = 16_384;
/// Default maximum number of retained response correlations.
pub const DEFAULT_MAX_RESPONSE_CORRELATIONS: usize = 4_096;
/// Absolute ceiling for retained response correlations.
pub const MAX_RESPONSE_CORRELATIONS: usize = 65_536;
/// Default period for retaining an abandoned execution's exact response ID.
pub const DEFAULT_TOMBSTONE_RETENTION: Duration = Duration::from_mins(10);
/// Longest admitted period for retaining an abandoned response ID.
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

/// Public snapshot of one active correlation record.
///
/// The executor exposes these records so callers can audit exactly which
/// request owns a response slot without access to the concrete transport.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PendingRequestRecord {
    /// Stable key for this correlation; equal to the exact JSON-RPC request ID.
    pub correlation_key: RequestId,
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
    /// Whether the exact request ID is retained to discard a late final response.
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
    owner_dropped: Rc<Cell<bool>>,
    timeout_policy: RequestTimeoutPolicy,
    last_progress: Option<f64>,
}

#[derive(Debug)]
enum ExecutionOutcome {
    Response(JsonRpcResponse),
    Failure(McpError),
}

#[derive(Debug)]
struct Tombstone {
    generation: u64,
    expires_at: Instant,
}

#[derive(Debug)]
struct ExecutorState<T> {
    transport: T,
    pending: HashMap<RequestId, PendingExecution>,
    completed: HashMap<(RequestId, u64), ExecutionOutcome>,
    tombstones: HashMap<RequestId, Tombstone>,
    notifications: VecDeque<JsonRpcRequest>,
    reverse_requests: VecDeque<JsonRpcRequest>,
    stream_notifications: HashMap<(RequestId, u64), VecDeque<JsonRpcRequest>>,
    uncorrelated_responses: VecDeque<JsonRpcResponse>,
    terminal_records: HashMap<(RequestId, u64), ExecutionTerminalRecord>,
    cancellation_events: VecDeque<CancellationRequested>,
    next_generation: u64,
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

    fn retain_reverse_request(&mut self, request: JsonRpcRequest) -> bool {
        if self.reverse_requests.len() >= MAX_RETAINED_PEER_ACTIVITY {
            return false;
        }
        self.reverse_requests.push_back(request);
        true
    }

    fn prune_tombstones(&mut self, now: Instant) {
        self.tombstones
            .retain(|_, tombstone| tombstone.expires_at > now);
    }

    fn fail_all(&mut self, error: McpError, reason: ExecutionTerminalReason) {
        if self.terminal_error.is_some() {
            return;
        }
        self.terminal_error = Some(error.clone());
        self.tombstones.clear();
        for (request_id, pending) in self.pending.drain() {
            self.terminal_records.insert(
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
            );
            self.completed.insert(
                (request_id, pending.record.execution_generation),
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
    state: Rc<RefCell<ExecutorState<T>>>,
    tombstone_retention: Duration,
    max_in_flight: usize,
    max_correlations: usize,
}

impl<T> RequestExecutor<T>
where
    T: Transport,
{
    /// Creates an executor with the frozen CLT-01 A correlation bounds.
    #[must_use]
    pub fn new(transport: T) -> Self {
        Self {
            state: Rc::new(RefCell::new(ExecutorState {
                transport,
                pending: HashMap::new(),
                completed: HashMap::new(),
                tombstones: HashMap::new(),
                notifications: VecDeque::new(),
                reverse_requests: VecDeque::new(),
                stream_notifications: HashMap::new(),
                uncorrelated_responses: VecDeque::new(),
                terminal_records: HashMap::new(),
                cancellation_events: VecDeque::new(),
                next_generation: 0,
                terminal_error: None,
                shutdown: false,
            })),
            tombstone_retention: DEFAULT_TOMBSTONE_RETENTION,
            max_in_flight: DEFAULT_MAX_IN_FLIGHT_EXECUTIONS,
            max_correlations: DEFAULT_MAX_RESPONSE_CORRELATIONS,
        }
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

        let mut state = self.state.borrow_mut();
        self.drain_abandoned_locked(cx, &mut state)?;
        state.prune_tombstones(Instant::now());
        if state.shutdown {
            return Err(McpError::internal_error(
                "Client request executor is shut down",
            ));
        }
        if let Some(error) = &state.terminal_error {
            return Err(error.clone());
        }
        if state.pending.contains_key(&request_id) {
            return Err(McpError::invalid_request("Duplicate in-flight request ID"));
        }
        if state.tombstones.contains_key(&request_id) {
            return Err(McpError::invalid_request(
                "Tombstoned request ID cannot be reused",
            ));
        }
        if state.pending.len() >= self.max_in_flight {
            return Err(McpError::internal_error(
                "Client in-flight execution limit reached",
            ));
        }
        if state.pending.len().saturating_add(state.tombstones.len()) >= self.max_correlations {
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
            .send(cx, &JsonRpcMessage::Request(request))
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
        let owner_dropped = Rc::new(Cell::new(false));
        state.pending.insert(
            request_id.clone(),
            PendingExecution {
                record: PendingRequestRecord {
                    correlation_key: request_id.clone(),
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
            },
        );

        Ok(RequestExecution {
            request_id,
            generation,
            owner_dropped,
            state: self.state.clone(),
            completed: false,
        })
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
            JsonRpcMessage::Response(response) => self.route_response_locked(&mut state, response),
            JsonRpcMessage::Request(request) => {
                if request.id.is_some() {
                    if !state.retain_reverse_request(request) {
                        let error =
                            McpError::internal_error("Client reverse-request queue is full");
                        state.fail_all(error.clone(), ExecutionTerminalReason::ConnectionLost);
                        return Err(error);
                    }
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

    /// Waits for one execution's exact final response while routing peer
    /// traffic for every other live execution.
    pub fn wait(&self, cx: &Cx, execution: &mut RequestExecution<T>) -> McpResult<JsonRpcResponse> {
        execution.ensure_owner(&self.state)?;
        loop {
            if let Some(outcome) = execution.take_outcome()? {
                return outcome;
            }
            self.drive(cx)?;
        }
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

    /// Removes and returns peer requests that require a client response.
    pub fn take_reverse_requests(&self) -> Vec<JsonRpcRequest> {
        self.state.borrow_mut().reverse_requests.drain(..).collect()
    }

    /// Sends one final result for a peer-authored reverse request.
    pub fn respond_to_reverse_request(
        &self,
        cx: &Cx,
        request_id: RequestId,
        result: Value,
    ) -> McpResult<()> {
        let mut state = self.state.borrow_mut();
        if state.shutdown {
            return Err(McpError::internal_error(
                "Client request executor is shut down",
            ));
        }
        state
            .transport
            .send(
                cx,
                &JsonRpcMessage::Response(JsonRpcResponse::success(request_id, result)),
            )
            .map_err(|error| self.handle_send_error_locked(&mut state, error))
    }

    /// Removes and returns bounded, typed local cancellation indications.
    pub fn take_cancellation_events(&self) -> Vec<CancellationRequested> {
        self.state
            .borrow_mut()
            .cancellation_events
            .drain(..)
            .collect()
    }

    /// Returns terminal receipts selected by completed request executions.
    #[must_use]
    pub fn terminal_records(&self) -> Vec<ExecutionTerminalRecord> {
        self.state
            .borrow()
            .terminal_records
            .values()
            .cloned()
            .collect()
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
        self.cancel_pending_locked(
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
        state.shutdown = true;
        let request_ids = state.pending.keys().cloned().collect::<Vec<_>>();
        for request_id in request_ids {
            self.cancel_pending_locked(
                cx,
                &mut state,
                &request_id,
                ExecutionTerminalReason::Shutdown,
            )?;
        }
        if let Err(error) = state.transport.close() {
            let error = transport_error_to_mcp(error);
            state.fail_all(error.clone(), ExecutionTerminalReason::ConnectionLost);
            return Err(error);
        }
        state.terminal_error = Some(McpError::internal_error(
            "Client request executor is shut down",
        ));
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

    fn route_response_locked(&self, state: &mut ExecutorState<T>, response: JsonRpcResponse) {
        let Some(request_id) = response.id.clone() else {
            let error = McpError::invalid_request("Peer response omitted a request ID");
            state.fail_all(error, ExecutionTerminalReason::ConnectionLost);
            return;
        };
        if let Some(tombstone) = state.tombstones.remove(&request_id) {
            debug_assert!(tombstone.generation > 0);
            return;
        }
        let Some(pending) = state.pending.remove(&request_id) else {
            if !state.retain_uncorrelated_response(response) {
                state.fail_all(
                    McpError::internal_error("Client uncorrelated-response queue is full"),
                    ExecutionTerminalReason::ConnectionLost,
                );
            }
            return;
        };
        state.terminal_records.insert(
            (request_id.clone(), pending.record.execution_generation),
            ExecutionTerminalRecord {
                terminal_state: ExecutionTerminalState::Response,
                terminal_reason: ExecutionTerminalReason::FinalResponse,
                final_delivered: true,
                cancellation_committed: false,
                cancellation_transport_attempts: 0,
                local_cancellation_event: false,
                waiter_release: true,
                tombstone: false,
            },
        );
        state.completed.insert(
            (request_id, pending.record.execution_generation),
            ExecutionOutcome::Response(response),
        );
    }

    fn drain_abandoned_locked(&self, cx: &Cx, state: &mut ExecutorState<T>) -> McpResult<()> {
        state.prune_tombstones(Instant::now());
        let abandoned = state
            .pending
            .iter()
            .filter(|(_, pending)| pending.owner_dropped.get())
            .map(|(request_id, _)| request_id.clone())
            .collect::<Vec<_>>();
        for request_id in abandoned {
            self.cancel_pending_locked(
                cx,
                state,
                &request_id,
                ExecutionTerminalReason::CallerDropped,
            )?;
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
        let Some(mut pending) = state.pending.remove(request_id) else {
            return Ok(());
        };
        pending.record.cancellation_committed = true;
        pending.record.terminal_state = ExecutionTerminalState::Cancelled;
        let generation = pending.record.execution_generation;
        let expires_at = Instant::now()
            .checked_add(self.tombstone_retention)
            .ok_or_else(|| {
                McpError::internal_error("Tombstone retention exceeds the clock range")
            })?;
        state.tombstones.insert(
            request_id.clone(),
            Tombstone {
                generation,
                expires_at,
            },
        );
        state.completed.insert(
            (request_id.clone(), generation),
            ExecutionOutcome::Failure(McpError::request_cancelled()),
        );
        state.terminal_records.insert(
            (request_id.clone(), generation),
            ExecutionTerminalRecord {
                terminal_state: ExecutionTerminalState::Cancelled,
                terminal_reason: reason,
                final_delivered: false,
                cancellation_committed: true,
                cancellation_transport_attempts: 1,
                local_cancellation_event: true,
                waiter_release: true,
                tombstone: true,
            },
        );
        if state.cancellation_events.len() >= MAX_RETAINED_PEER_ACTIVITY {
            // Cancellation is never held behind observer backpressure. The
            // bounded observer queue evicts its oldest already-observed event
            // so the current terminal transition retains its typed signal.
            let _ = state.cancellation_events.pop_front();
        }
        state.cancellation_events.push_back(CancellationRequested {
            request_id: request_id.clone(),
            reason,
        });
        let params = serde_json::to_value(CancelledParams {
            request_id: request_id.clone(),
            reason: None,
            await_cleanup: None,
        })
        .map_err(|_| McpError::internal_error("Failed to encode cancellation request"))?;
        let cancellation = JsonRpcMessage::Request(JsonRpcRequest::notification(
            "notifications/cancelled",
            Some(params),
        ));
        if let Err(error) = state.transport.send(cx, &cancellation) {
            let error = transport_error_to_mcp(error);
            state.fail_all(error.clone(), ExecutionTerminalReason::ConnectionLost);
            return Err(error);
        }
        Ok(())
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
            .filter_map(|(request_id, pending)| {
                let reason = if observed_at >= pending.record.absolute_deadline {
                    Some(ExecutionTerminalReason::AbsoluteTimeout)
                } else if observed_at >= pending.record.idle_deadline {
                    Some(ExecutionTerminalReason::IdleTimeout)
                } else {
                    None
                }?;
                Some((request_id.clone(), reason))
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
        let Some(pending) = state.pending.get_mut(&request_id) else {
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
        let stream = state
            .stream_notifications
            .entry((request_id, generation))
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

/// One request-owned response stream handle.
///
/// Dropping a live handle selects its local cancellation transition. The next
/// executor operation sends the one bounded cancellation notification and
/// keeps only the exact-ID tombstone required to discard a late response.
#[derive(Debug)]
pub struct RequestExecution<T> {
    request_id: RequestId,
    generation: u64,
    owner_dropped: Rc<Cell<bool>>,
    state: Rc<RefCell<ExecutorState<T>>>,
    completed: bool,
}

impl<T> RequestExecution<T>
where
    T: Transport,
{
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

    fn ensure_owner(&self, state: &Rc<RefCell<ExecutorState<T>>>) -> McpResult<()> {
        if !Rc::ptr_eq(&self.state, state) {
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

    fn take_outcome(&mut self) -> McpResult<Option<McpResult<JsonRpcResponse>>> {
        if self.completed {
            return Err(McpError::invalid_request(
                "Request execution result was already consumed",
            ));
        }
        let outcome = self
            .state
            .borrow_mut()
            .completed
            .remove(&(self.request_id.clone(), self.generation));
        let Some(outcome) = outcome else {
            return Ok(None);
        };
        self.completed = true;
        Ok(Some(match outcome {
            ExecutionOutcome::Response(response) => Ok(response),
            ExecutionOutcome::Failure(error) => Err(error),
        }))
    }
}

impl<T> Drop for RequestExecution<T> {
    fn drop(&mut self) {
        if !self.completed {
            self.owner_dropped.set(true);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
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

    #[test]
    fn clt_01_a_positive() {
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
            record.correlation_key == record.request_id
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
    fn clt_01_a_planted_negative() {
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
    fn clt_01_b_positive() {
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
        assert_eq!(reverse[0].id, Some(RequestId::Number(700)));
        executor
            .respond_to_reverse_request(
                &cx,
                RequestId::Number(700),
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
        explicit
            .cancel(&cx, &mut explicitly_cancelled)
            .expect("explicit caller cancellation selects one terminal transition");
        assert_eq!(
            explicit
                .wait(&cx, &mut explicitly_cancelled)
                .expect_err("cancelled execution releases its waiter")
                .code,
            fastmcp_core::McpErrorCode::RequestCancelled,
        );
        let explicit_terminal = explicit.terminal_records();
        assert_eq!(explicit_terminal.len(), 1);
        assert_eq!(
            explicit_terminal[0],
            ExecutionTerminalRecord {
                terminal_state: ExecutionTerminalState::Cancelled,
                terminal_reason: ExecutionTerminalReason::CallerCancelled,
                final_delivered: false,
                cancellation_committed: true,
                cancellation_transport_attempts: 1,
                local_cancellation_event: true,
                waiter_release: true,
                tombstone: true,
            },
        );
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

        let subscription = RequestExecutor::new(ScriptedTransport::new(std::iter::empty()));
        let mut subscribed = subscription
            .execute(&cx, request(46))
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
        assert_eq!(
            shutdown.terminal_records()[0].terminal_reason,
            ExecutionTerminalReason::Shutdown
        );
    }

    #[test]
    fn clt_01_b_planted_negative() {
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
}
