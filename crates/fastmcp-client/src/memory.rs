//! Modern, caller-driven request execution over a bounded memory connection.
//!
//! This is in-process integration infrastructure. It owns no runtime, reader
//! thread, background pump or network connector. Callers may start several
//! executions, then drive any handle; the one reader routes other owners'
//! responses and progress without consuming their results.

use std::collections::{BTreeMap, VecDeque};
use std::future::{Future, poll_fn};
use std::pin::{Pin, pin};
use std::sync::Arc;
use std::task::Poll;
use std::time::{Duration, Instant};

use asupersync::Cx;
use fastmcp_core::{McpError, McpErrorCode, McpRequestCancellation, McpResult};
use fastmcp_protocol::protocol_policy::{MODERN_PROTOCOL_VERSION, ProtocolEra};
use fastmcp_protocol::{
    ClientCapabilities, ClientInfo, CoreRequest, CoreResult, FinalCoreResult, FinalRequestMeta,
    JsonRpcMessage, JsonRpcRequest, JsonRpcResponse, RequestId, ServerCapabilities,
    ServerDiscoverResult,
};
use fastmcp_transport::memory::asynchronous::MemorySendPermit;
use fastmcp_transport::memory::{MemoryRecvHalf, MemorySendHalf, MemoryTransport};
use fastmcp_transport::{
    ReceivedTransportFrame, Transport, TransportError, TransportRecvHalf, TransportSendHalf,
};
use serde_json::Value;

use crate::execution::{
    CancellationRequested, FinalCacheTtlDiagnostic, RequestExecution, RequestExecutor,
    decode_core_result_with_cache_ttl_from_source,
};
use crate::session::ClientSession;
use crate::{RequestTimeoutPolicy, transport_error_to_mcp};

const CHECKPOINT_INTERVAL: Duration = Duration::from_millis(20);
const SEND_ADMISSION_TIMEOUT: Duration = Duration::from_secs(30);
const MAX_DIAGNOSTICS: usize = 1_024;

/// The executor owns correlation, never the memory channel's actual I/O.
#[derive(Debug)]
struct ExternalMemoryTransport;

impl Transport for ExternalMemoryTransport {
    fn send(&mut self, _: &Cx, _: &JsonRpcMessage) -> Result<(), TransportError> {
        Err(TransportError::Io(std::io::Error::other(
            "memory executor writes require an owned channel permit",
        )))
    }

    fn recv(&mut self, _: &Cx) -> Result<JsonRpcMessage, TransportError> {
        Err(TransportError::Io(std::io::Error::other(
            "memory executor ingress belongs to its asynchronous driver",
        )))
    }

    fn close(&mut self, _: &Cx) -> Result<(), TransportError> {
        Ok(())
    }
}

type MemoryExecutor = RequestExecutor<ExternalMemoryTransport>;

/// One independently owned ordinary modern request on a [`MemoryClient`].
///
/// Dropping an unfinished handle elects local cancellation immediately. Its
/// bounded cancellation control is committed on the next client drive before
/// new application work; Drop itself never waits for capacity. The exact late
/// response remains owned by a tombstone and cannot complete a sibling.
#[derive(Debug)]
pub struct MemoryRequestExecution {
    owner: Arc<()>,
    inner: RequestExecution<ExternalMemoryTransport>,
    request: CoreRequest,
    notifications: VecDeque<JsonRpcRequest>,
    finished: bool,
}

impl MemoryRequestExecution {
    /// The exact monotonically allocated ID actually published to the peer.
    #[must_use]
    pub fn request_id(&self) -> &RequestId {
        self.inner.request_id()
    }
}

/// A request-owned notification or the one typed final outcome.
#[derive(Debug)]
pub enum MemoryRequestEvent {
    /// Valid progress carrying this exact execution's advertised token.
    Notification(JsonRpcRequest),
    /// The method-specific final result, including any input-required branch
    /// and admitted open result members. No continuation is retried implicitly.
    Result(Box<CoreResult>),
}

/// A modern-only asynchronous client for an existing bounded memory endpoint.
///
/// Ordinary core methods share the same typed protocol admission and request
/// executor as other clients. Long-lived subscriptions and extension methods
/// require their distinct owning APIs and are not opened by this adapter.
/// Client metadata is frozen at connect and stamped on every request.
///
/// A caller timer driver is required when an operation must wait: response
/// deadlines and the 30-second send-admission bound remain observable even if
/// the peer is silent. There is no blocking-pool or reactor requirement.
pub struct MemoryClient {
    receiver: MemoryRecvHalf,
    sender: MemorySendHalf,
    executor: MemoryExecutor,
    owner: Arc<()>,
    session: ClientSession,
    next_id: i64,
    timeout_policy: RequestTimeoutPolicy,
    cache_diagnostics: VecDeque<FinalCacheTtlDiagnostic>,
    closed: bool,
}

impl std::fmt::Debug for MemoryClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MemoryClient")
            .field("next_id", &self.next_id)
            .field("closed", &self.closed)
            .finish_non_exhaustive()
    }
}

impl MemoryClient {
    /// Discovers the exact modern peer using only the supplied runtime context.
    pub async fn connect(
        cx: &Cx,
        transport: MemoryTransport,
        client_info: ClientInfo,
        capabilities: ClientCapabilities,
    ) -> McpResult<Self> {
        Self::connect_with_cancellation(
            cx,
            &McpRequestCancellation::new(),
            transport,
            client_info,
            capabilities,
        )
        .await
    }

    /// Connects with an explicit request-cancellation token. Failed discovery
    /// closes both owned halves and never retries on this or a fresh endpoint.
    pub async fn connect_with_cancellation(
        cx: &Cx,
        cancellation: &McpRequestCancellation,
        transport: MemoryTransport,
        client_info: ClientInfo,
        capabilities: ClientCapabilities,
    ) -> McpResult<Self> {
        checkpoint(cx, cancellation)?;
        if capabilities
            .extensions
            .as_ref()
            .is_some_and(|extensions| !extensions.is_empty())
        {
            return Err(McpError::invalid_params(
                "Memory core client does not negotiate extension execution",
            ));
        }
        let session = ClientSession::try_new(
            client_info,
            capabilities,
            None,
            ServerCapabilities::default(),
            MODERN_PROTOCOL_VERSION.to_owned(),
        )
        .map_err(|_| McpError::internal_error("Modern memory protocol version is unavailable"))?;
        let (receiver, sender) = transport.into_split();
        let mut client = Self {
            receiver,
            sender,
            executor: RequestExecutor::with_external_driver(
                ExternalMemoryTransport,
                ProtocolEra::Modern2026,
            ),
            owner: Arc::new(()),
            session,
            next_id: 1,
            timeout_policy: RequestTimeoutPolicy::default(),
            cache_diagnostics: VecDeque::new(),
            closed: false,
        };
        let result = client
            .request_core(cx, cancellation, "server/discover", serde_json::json!({}))
            .await?;
        let CoreResult::Final(FinalCoreResult::Discover(discovery)) = result else {
            return Err(McpError::invalid_request(
                "Memory discovery returned another method's result",
            ));
        };
        if !discovery
            .supported_versions()
            .iter()
            .any(|version| version == MODERN_PROTOCOL_VERSION)
        {
            return Err(McpError::invalid_request(
                "Memory peer does not support MCP 2026-07-28",
            ));
        }
        let server_info = discovery
            .server_info()
            .cloned()
            .or_else(|| discovery.compatibility_server_info());
        client.session = ClientSession::try_new(
            client.session.client_info().clone(),
            client.session.client_capabilities().clone(),
            server_info,
            ServerCapabilities::default(),
            MODERN_PROTOCOL_VERSION.to_owned(),
        )
        .map_err(|_| McpError::internal_error("Modern memory session could not be established"))?
        .with_server_discovery(discovery);
        Ok(client)
    }

    /// The successfully admitted discovery snapshot retained at connection time.
    #[must_use]
    pub fn server_discovery(&self) -> &ServerDiscoverResult {
        self.session
            .server_discovery()
            .expect("public memory clients completed discovery")
    }

    /// Starts one ordinary typed core operation. The returned handle owns an
    /// actual committed request; a pending/dropped send owns no request ID,
    /// response waiter, deadline or cancellation control.
    pub async fn execute_core(
        &mut self,
        cx: &Cx,
        cancellation: &McpRequestCancellation,
        method: &str,
        parameters: Value,
    ) -> McpResult<MemoryRequestExecution> {
        self.execute_core_with_timeout_policy(
            cx,
            cancellation,
            method,
            parameters,
            self.timeout_policy,
        )
        .await
    }

    /// Uses stricter bounded idle and absolute response deadlines for one call.
    /// Both start at actual channel publication, never at capacity reservation.
    pub async fn execute_core_with_timeout_policy(
        &mut self,
        cx: &Cx,
        cancellation: &McpRequestCancellation,
        method: &str,
        parameters: Value,
        timeout_policy: RequestTimeoutPolicy,
    ) -> McpResult<MemoryRequestExecution> {
        self.ensure_open()?;
        checkpoint(cx, cancellation)?;
        RequestTimeoutPolicy::new(
            timeout_policy.idle_timeout(),
            timeout_policy.absolute_timeout(),
        )?;
        if timeout_policy.idle_timeout() > self.timeout_policy.idle_timeout()
            || timeout_policy.absolute_timeout() > self.timeout_policy.absolute_timeout()
        {
            return Err(McpError::invalid_params(
                "Memory execution timeout exceeds the client policy",
            ));
        }
        if method == "subscriptions/listen" {
            return Err(McpError::invalid_params(
                "Ordinary memory execution cannot open a subscription",
            ));
        }
        let parameters = self.parameters(parameters)?;
        let request = CoreRequest::decode(ProtocolEra::Modern2026, method, Some(&parameters))
            .map_err(|_| McpError::invalid_params("Invalid modern memory core request"))?;
        let next_id = self
            .next_id
            .checked_add(1)
            .ok_or_else(|| McpError::internal_error("Memory request IDs exhausted"))?;
        let wire = JsonRpcRequest::new(method, Some(parameters), self.next_id);
        // Admission/serialization errors must be observable even behind a full
        // queue. The commit permit repeats the transport's exact same check.
        fastmcp_transport::Codec::new()
            .encode_request(&wire)
            .map_err(transport_error_from_codec)?;
        let deadline = Instant::now() + SEND_ADMISSION_TIMEOUT;
        loop {
            self.flush_controls(cx, cancellation, deadline).await?;
            let permit = reserve_capacity(
                &mut self.sender,
                &mut self.receiver,
                &self.executor,
                cx,
                cancellation,
                deadline,
            )
            .await?;
            let committed = self.executor.execute_external(
                cx,
                cancellation,
                wire.clone(),
                timeout_policy,
                |message| permit.send(message),
            )?;
            if let Some(inner) = committed {
                self.next_id = next_id;
                return Ok(MemoryRequestExecution {
                    owner: Arc::clone(&self.owner),
                    inner,
                    request,
                    notifications: VecDeque::new(),
                    finished: false,
                });
            }
            // A sibling dropped while capacity was pending. Its control is
            // now authoritative; the unused permit aborts before retrying.
        }
    }

    /// Drives this connection until one event for the selected handle is ready.
    /// Other handles retain their correlated outcomes. Dropping this *wait*
    /// preserves the execution; dropping the execution itself cancels it.
    pub async fn next_event(
        &mut self,
        cx: &Cx,
        cancellation: &McpRequestCancellation,
        execution: &mut MemoryRequestExecution,
    ) -> McpResult<Option<MemoryRequestEvent>> {
        self.ensure_owner(execution)?;
        if execution.finished {
            return Ok(None);
        }
        loop {
            let maintenance = self.executor.poll_timeouts_at(cx, Instant::now());
            if let Some(error) = execution.inner.terminal_error() {
                execution.notifications.clear();
                execution.finished = true;
                // Consume the selected terminal receipt exactly once.
                let _ = self.executor.try_take_response(&mut execution.inner);
                return Err(error);
            }
            if let Some(notification) = execution.notifications.pop_front() {
                return Ok(Some(MemoryRequestEvent::Notification(notification)));
            }
            execution
                .notifications
                .extend(execution.inner.take_stream_notifications()?);
            if let Some(notification) = execution.notifications.pop_front() {
                return Ok(Some(MemoryRequestEvent::Notification(notification)));
            }
            if let Some((response, source)) = self
                .executor
                .try_take_response_with_raw_result(&mut execution.inner)?
            {
                execution.finished = true;
                let result = decode_response(&execution.request, response, source.as_deref())?;
                if let Some(diagnostic) = result.1 {
                    if self.cache_diagnostics.len() == MAX_DIAGNOSTICS {
                        self.cache_diagnostics.pop_front();
                    }
                    self.cache_diagnostics.push_back(diagnostic);
                }
                return Ok(Some(MemoryRequestEvent::Result(Box::new(result.0))));
            }
            maintenance?;
            if checkpoint(cx, cancellation).is_err() {
                let cancelled = self.executor.cancel(cx, &mut execution.inner);
                if execution.inner.terminal_error().is_none() {
                    cancelled?;
                }
                continue;
            }
            self.ensure_open()?;
            // One drive turn always returns after a frame or maintenance
            // tick. Even a blocked cancellation write cannot hide a result
            // or timeout already elected for this selected owner.
            if let Err(error) = self.drive_once(cx, cancellation).await {
                // A failed read/write retires owners before returning its
                // driver error. Consume this owner's elected failure above,
                // preserving an earlier cancellation and exactly-once events.
                if execution.inner.terminal_error().is_some() {
                    continue;
                }
                if error.code == McpErrorCode::RequestCancelled {
                    let cancelled = self.executor.cancel(cx, &mut execution.inner);
                    if execution.inner.terminal_error().is_none() {
                        cancelled?;
                    }
                } else {
                    return Err(error);
                }
            }
        }
    }

    /// Completes one core call, retaining valid progress in its owned handle
    /// until consumed. Use execute/next_event to observe progress incrementally.
    pub async fn request_core(
        &mut self,
        cx: &Cx,
        cancellation: &McpRequestCancellation,
        method: &str,
        parameters: Value,
    ) -> McpResult<CoreResult> {
        let mut execution = self
            .execute_core(cx, cancellation, method, parameters)
            .await?;
        loop {
            match self.next_event(cx, cancellation, &mut execution).await? {
                Some(MemoryRequestEvent::Result(result)) => return Ok(*result),
                Some(MemoryRequestEvent::Notification(_)) => {}
                None => {
                    return Err(McpError::internal_error(
                        "Memory execution ended without its result",
                    ));
                }
            }
        }
    }

    /// Lists one tools page without projecting away modern result metadata.
    pub async fn list_tools(
        &mut self,
        cx: &Cx,
        cancellation: &McpRequestCancellation,
        cursor: Option<&str>,
    ) -> McpResult<CoreResult> {
        let parameters = cursor.map_or_else(
            || serde_json::json!({}),
            |cursor| serde_json::json!({"cursor": cursor}),
        );
        self.request_core(cx, cancellation, "tools/list", parameters)
            .await
    }

    /// Calls a tool, retaining complete or input-required typed outcomes.
    pub async fn call_tool(
        &mut self,
        cx: &Cx,
        cancellation: &McpRequestCancellation,
        name: &str,
        arguments: Value,
    ) -> McpResult<CoreResult> {
        self.request_core(
            cx,
            cancellation,
            "tools/call",
            serde_json::json!({"name": name, "arguments": arguments}),
        )
        .await
    }

    /// Elects local cancellation without waiting for observer/peer capacity.
    /// Its control remains bounded and owned until the next drive commits it.
    pub fn cancel(&mut self, cx: &Cx, execution: &mut MemoryRequestExecution) -> McpResult<()> {
        self.ensure_owner(execution)?;
        if !execution.finished {
            self.executor.cancel(cx, &mut execution.inner)?;
        }
        Ok(())
    }

    /// Returns connection-level notifications without guessing a request owner.
    /// In particular, identifier-free logs and unmatched progress do not become
    /// another request's callback or extend any response deadline.
    pub fn take_server_notifications(&mut self) -> Vec<JsonRpcRequest> {
        self.executor.take_notifications()
    }

    /// Takes bounded local cancellation indications; these are not wire logs.
    pub fn take_cancellation_events(&mut self) -> Vec<CancellationRequested> {
        self.executor.take_cancellation_events()
    }

    /// Reports missing/negative peer cache TTLs normalized to zero freshness.
    pub fn take_cache_ttl_diagnostics(&mut self) -> Vec<FinalCacheTtlDiagnostic> {
        self.cache_diagnostics.drain(..).collect()
    }

    /// Closes both channel directions and retires every request immediately.
    /// Channel closure is the cancellation boundary; queued controls are not
    /// misreported as wire sends, and a full peer queue cannot delay teardown.
    pub fn close(&mut self, cx: &Cx) -> McpResult<()> {
        if self.closed {
            return Ok(());
        }
        self.closed = true;
        let result = self.executor.shutdown(cx);
        let receive = self.receiver.close(cx).map_err(transport_error_to_mcp);
        let send = self.sender.close(cx).map_err(transport_error_to_mcp);
        result.and(receive).and(send)
    }

    fn ensure_open(&self) -> McpResult<()> {
        if self.closed {
            return Err(McpError::internal_error("Memory client is closed"));
        }
        self.executor.terminal_error().map_or(Ok(()), Err)
    }

    fn ensure_owner(&self, execution: &MemoryRequestExecution) -> McpResult<()> {
        if !Arc::ptr_eq(&self.owner, &execution.owner) {
            return Err(McpError::invalid_params(
                "Memory execution belongs to another client",
            ));
        }
        Ok(())
    }

    fn parameters(&self, mut parameters: Value) -> McpResult<Value> {
        let object = parameters
            .as_object_mut()
            .ok_or_else(|| McpError::invalid_params("Memory core parameters must be an object"))?;
        let mut metadata = serde_json::to_value(FinalRequestMeta {
            protocol_version: MODERN_PROTOCOL_VERSION.to_owned(),
            client_capabilities: self.session.client_capabilities().clone(),
            client_info: Some(self.session.modern_client_implementation()),
            additional_metadata: BTreeMap::new(),
        })
        .map_err(|_| McpError::invalid_params("Memory client metadata is invalid"))?;
        if let Some(existing) = object.remove("_meta") {
            let existing = existing.as_object().ok_or_else(|| {
                McpError::invalid_params("Memory request metadata must be an object")
            })?;
            let generated = metadata
                .as_object_mut()
                .expect("typed metadata is an object");
            for (key, value) in existing {
                generated
                    .entry(key.clone())
                    .or_insert_with(|| value.clone());
            }
        }
        object.insert("_meta".to_owned(), metadata);
        Ok(parameters)
    }

    async fn flush_controls(
        &mut self,
        cx: &Cx,
        cancellation: &McpRequestCancellation,
        deadline: Instant,
    ) -> McpResult<()> {
        while self.executor.has_external_controls(cx)? {
            let permit = reserve_capacity(
                &mut self.sender,
                &mut self.receiver,
                &self.executor,
                cx,
                cancellation,
                deadline,
            )
            .await?;
            if let Err(error) = self
                .executor
                .commit_external_control(|message| permit.send(message))
            {
                // A successfully reserved slot's control is fixed/validated.
                // The only remaining memory commit failure is disconnection.
                self.executor.fail_connection(error.clone());
                return Err(error);
            }
        }
        Ok(())
    }

    async fn drive_once(
        &mut self,
        cx: &Cx,
        cancellation: &McpRequestCancellation,
    ) -> McpResult<()> {
        if self.executor.has_external_controls(cx)? {
            let mut sending = pin!(self.sender.reserve_send_async(cx));
            let mut receiving = pin!(self.receiver.recv_with_source_async(cx));
            let mut progress = pin!(poll_fn(|task| {
                if let Poll::Ready(result) = sending.as_mut().poll(task) {
                    return Poll::Ready(Ok(result));
                }
                receiving.as_mut().poll(task).map(Err)
            }));
            match wait_turn(cx, cancellation, None, progress.as_mut()).await? {
                Some(Ok(Ok(permit))) => {
                    if let Err(error) = self
                        .executor
                        .commit_external_control(|message| permit.send(message))
                    {
                        self.executor.fail_connection(error.clone());
                        return Err(error);
                    }
                }
                Some(Ok(Err(TransportError::Cancelled)))
                | Some(Err(Err(TransportError::Cancelled))) => {
                    return Err(McpError::request_cancelled());
                }
                Some(Ok(Err(error))) | Some(Err(Err(error))) => {
                    return Err(fail_transport(&self.executor, error));
                }
                Some(Err(Ok(frame))) => admit_frame(&self.executor, cx, frame)?,
                None => {}
            }
        } else {
            let mut receiving = pin!(self.receiver.recv_with_source_async(cx));
            match wait_turn(cx, cancellation, None, receiving.as_mut()).await? {
                Some(Ok(frame)) => admit_frame(&self.executor, cx, frame)?,
                Some(Err(TransportError::Cancelled)) => return Err(McpError::request_cancelled()),
                Some(Err(error)) => return Err(fail_transport(&self.executor, error)),
                None => {}
            }
        }
        Ok(())
    }
}

impl Drop for MemoryClient {
    fn drop(&mut self) {
        if !self.closed {
            self.executor.fail_connection(McpError::request_cancelled());
        }
        // Dropping the two actual halves releases both channel directions.
        // Request handles retain only the bounded executor state, never I/O.
    }
}

fn checkpoint(cx: &Cx, cancellation: &McpRequestCancellation) -> McpResult<()> {
    if cancellation.is_cancel_requested()
        || cx
            .budget()
            .deadline
            .is_some_and(|deadline| cx.now() >= deadline)
        || cx.checkpoint().is_err()
    {
        return Err(McpError::request_cancelled());
    }
    Ok(())
}

fn transport_error_from_codec(error: fastmcp_transport::CodecError) -> McpError {
    transport_error_to_mcp(TransportError::Codec(error))
}

fn fail_transport(executor: &MemoryExecutor, error: TransportError) -> McpError {
    let error = transport_error_to_mcp(error);
    executor.fail_connection(error.clone());
    error
}

fn admit_frame(executor: &MemoryExecutor, cx: &Cx, frame: ReceivedTransportFrame) -> McpResult<()> {
    if let Err(error) = executor.drive_frame(cx, frame) {
        executor.fail_connection(error.clone());
        return Err(error);
    }
    Ok(())
}

/// Capacity waits keep ingress live, including when both capacity-one queues
/// are full and the peer must finish sending before it can consume our write.
async fn reserve_capacity<'a>(
    sender: &'a mut MemorySendHalf,
    receiver: &mut MemoryRecvHalf,
    executor: &MemoryExecutor,
    cx: &'a Cx,
    cancellation: &McpRequestCancellation,
    deadline: Instant,
) -> McpResult<MemorySendPermit<'a>> {
    let mut sending = pin!(sender.reserve_send_async(cx));
    loop {
        executor.poll_timeouts_at(cx, Instant::now())?;
        if let Some(error) = executor.terminal_error() {
            return Err(error);
        }
        let mut receiving = pin!(receiver.recv_with_source_async(cx));
        let mut progress = pin!(poll_fn(|task| {
            if let Poll::Ready(result) = sending.as_mut().poll(task) {
                return Poll::Ready(Ok(result));
            }
            receiving.as_mut().poll(task).map(Err)
        }));
        match wait_turn(cx, cancellation, Some(deadline), progress.as_mut()).await? {
            Some(Ok(Ok(permit))) => return Ok(permit),
            Some(Ok(Err(TransportError::Cancelled)))
            | Some(Err(Err(TransportError::Cancelled))) => {
                return Err(McpError::request_cancelled());
            }
            Some(Ok(Err(error))) | Some(Err(Err(error))) => {
                return Err(fail_transport(executor, error));
            }
            Some(Err(Ok(frame))) => admit_frame(executor, cx, frame)?,
            None => {}
        }
    }
}

/// Returns after one operation or a bounded maintenance tick. The operation
/// remains pinned by its caller across ticks, preserving channel waiter order.
async fn wait_turn<F: Future>(
    cx: &Cx,
    cancellation: &McpRequestCancellation,
    deadline: Option<Instant>,
    mut operation: Pin<&mut F>,
) -> McpResult<Option<F::Output>> {
    let mut cancelled = pin!(cancellation.cancelled());
    let mut timer = None;
    poll_fn(|task| {
        if let Err(error) = checkpoint(cx, cancellation) {
            return Poll::Ready(Err(error));
        }
        if cancelled.as_mut().poll(task).is_ready() {
            return Poll::Ready(Err(McpError::request_cancelled()));
        }
        if deadline.is_some_and(|deadline| Instant::now() >= deadline) {
            return Poll::Ready(Err(McpError::request_cancelled()));
        }
        // Ready is an atomic channel commitment. Never turn it into a local
        // cancellation after publication or after consuming an ingress frame.
        if let Poll::Ready(result) = operation.as_mut().poll(task) {
            return Poll::Ready(Ok(Some(result)));
        }
        if cx.timer_driver().is_none()
            || !cx.capabilities().time
            || Cx::current().is_some_and(|ambient| !ambient.capabilities().time)
        {
            return Poll::Ready(Err(McpError::invalid_params(
                "Pending memory client execution requires caller time capability and timer driver",
            )));
        }
        let delay = deadline.map_or(CHECKPOINT_INTERVAL, |deadline| {
            CHECKPOINT_INTERVAL.min(deadline.saturating_duration_since(Instant::now()))
        });
        let delay = cx.budget().deadline.map_or(delay, |deadline| {
            delay.min(Duration::from_nanos(deadline.duration_since(cx.now())))
        });
        let _current = Cx::set_current(Some(cx.clone()));
        let timer = timer.get_or_insert_with(|| asupersync::time::sleep(cx.now(), delay));
        if Pin::new(timer).poll(task).is_ready() {
            return Poll::Ready(Ok(None));
        }
        Poll::Pending
    })
    .await
}

fn decode_response(
    request: &CoreRequest,
    response: JsonRpcResponse,
    source: Option<&str>,
) -> McpResult<(CoreResult, Option<FinalCacheTtlDiagnostic>)> {
    if let Some(error) = response.error {
        let code = error
            .code
            .as_i32()
            .map(McpErrorCode::from)
            .unwrap_or(McpErrorCode::InternalError);
        return Err(match error.data {
            Some(data) => McpError::with_data(code, error.message, data),
            None => McpError::new(code, error.message),
        });
    }
    let result = response
        .result
        .ok_or_else(|| McpError::invalid_request("Memory response omitted its result"))?;
    decode_core_result_with_cache_ttl_from_source(request, &result, source)
}

#[cfg(test)]
mod tests {
    use super::*;
    use asupersync::runtime::RuntimeBuilder;
    use fastmcp_protocol::ExactJsonValue;
    use fastmcp_transport::memory::create_memory_transport_pair_with_capacity;
    use serde_json::json;

    fn run<F: Future<Output = ()>>(test: impl FnOnce(Cx) -> F) {
        let runtime = RuntimeBuilder::current_thread()
            .blocking_threads(0, 0)
            .build()
            .unwrap();
        runtime.block_on(async {
            let cx = Cx::current().unwrap();
            assert!(cx.blocking_pool_handle().is_none());
            asupersync::time::timeout(cx.now(), Duration::from_secs(5), test(cx))
                .await
                .expect("memory client must progress on its caller runtime");
        });
        assert!(runtime.shutdown_timeout(Duration::from_secs(1)));
    }

    fn info() -> ClientInfo {
        ClientInfo {
            name: "typed-memory-client".to_owned(),
            version: "1".to_owned(),
        }
    }

    fn discovery() -> Value {
        json!({"resultType":"complete", "supportedVersions":["2026-07-28"],
            "capabilities":{}, "ttlMs":0, "cacheScope":"private"})
    }

    fn tools() -> Value {
        json!({"resultType":"complete", "tools":[], "ttlMs":0, "cacheScope":"private"})
    }

    fn complete() -> Value {
        json!({"resultType":"complete", "content":[]})
    }

    fn response(id: i64, result: Value) -> JsonRpcMessage {
        JsonRpcMessage::Response(JsonRpcResponse::success(RequestId::Number(id), result))
    }

    async fn receive(
        cx: &Cx,
        peer: &mut MemoryTransport,
        method: &str,
        id: Option<i64>,
    ) -> JsonRpcRequest {
        let JsonRpcMessage::Request(request) = peer.recv_async(cx).await.unwrap() else {
            panic!("expected a client request");
        };
        assert_eq!(request.method, method);
        assert_eq!(request.id, id.map(RequestId::Number));
        request
    }

    async fn connected(cx: &Cx) -> (MemoryClient, MemoryTransport) {
        let (transport, mut peer) = create_memory_transport_pair_with_capacity(1);
        peer.send_async(cx, &response(1, discovery()))
            .await
            .unwrap();
        let client = MemoryClient::connect(cx, transport, info(), ClientCapabilities::default())
            .await
            .unwrap();
        let request = receive(cx, &mut peer, "server/discover", Some(1)).await;
        assert_eq!(
            request.params.unwrap()["_meta"]["io.modelcontextprotocol/clientInfo"]["name"],
            "typed-memory-client"
        );
        assert!(
            client
                .server_discovery()
                .supported_versions()
                .iter()
                .any(|version| version == "2026-07-28")
        );
        (client, peer)
    }

    async fn result(
        cx: &Cx,
        client: &mut MemoryClient,
        execution: &mut MemoryRequestExecution,
    ) -> CoreResult {
        loop {
            match client
                .next_event(cx, &McpRequestCancellation::new(), execution)
                .await
                .unwrap()
            {
                Some(MemoryRequestEvent::Result(result)) => return *result,
                Some(MemoryRequestEvent::Notification(_)) => {}
                None => panic!("execution lost its result"),
            }
        }
    }

    #[test]
    fn memory_client_correlates_reordered_results_and_exact_request_progress() {
        run(|cx| async move {
            let (mut client, mut peer) = connected(&cx).await;
            let mut server = cx
                .spawn(move |peer_cx| async move {
                    let call = receive(&peer_cx, &mut peer, "tools/call", Some(2)).await;
                    assert_eq!(
                        call.params.unwrap()["_meta"]["io.modelcontextprotocol/clientInfo"]["name"],
                        "typed-memory-client"
                    );
                    receive(&peer_cx, &mut peer, "tools/list", Some(3)).await;
                    peer.send_async(&peer_cx, &response(3, tools()))
                        .await
                        .unwrap();
                    for token in ["foreign", "owned"] {
                        peer.send_async(
                            &peer_cx,
                            &JsonRpcMessage::Request(JsonRpcRequest::notification(
                                "notifications/progress",
                                Some(json!({"progressToken":token,"progress":1})),
                            )),
                        )
                        .await
                        .unwrap();
                    }
                    let mut payload = complete();
                    for (name, exact) in [
                        ("x-number", "1.20e+4"),
                        ("x-zero", "-0"),
                        ("x-large", "123456789012345678901234567890"),
                    ] {
                        payload[name] = Value::Number(serde_json::Number::from_string_unchecked(
                            exact.to_owned(),
                        ));
                    }
                    peer.send_async(&peer_cx, &response(2, payload))
                        .await
                        .unwrap();
                    peer
                })
                .unwrap();
            let cancellation = McpRequestCancellation::new();
            let mut call = client.execute_core(&cx, &cancellation, "tools/call", json!({
                "name":"echo", "arguments":{}, "_meta":{"progressToken":"owned", "io.modelcontextprotocol/clientInfo":{"name":"spoof","version":"9"}}
            })).await.unwrap();
            let mut list = client
                .execute_core(&cx, &cancellation, "tools/list", json!({}))
                .await
                .unwrap();
            let Some(MemoryRequestEvent::Notification(progress)) = client
                .next_event(&cx, &cancellation, &mut call)
                .await
                .unwrap()
            else {
                panic!("matching progress precedes its final result");
            };
            assert_eq!(progress.params.unwrap()["progressToken"], "owned");
            assert!(matches!(
                result(&cx, &mut client, &mut list).await,
                CoreResult::Final(FinalCoreResult::ToolsList { .. })
            ));
            let CoreResult::Final(FinalCoreResult::ToolsCall {
                result: call_result,
                ..
            }) = result(&cx, &mut client, &mut call).await
            else {
                panic!("typed tool result");
            };
            for (name, exact) in [
                ("x-number", "1.20e+4"),
                ("x-zero", "-0"),
                ("x-large", "123456789012345678901234567890"),
            ] {
                assert_eq!(
                    call_result
                        .extras
                        .members()
                        .iter()
                        .find(|member| member.name == name)
                        .unwrap()
                        .value,
                    ExactJsonValue::Number(exact.to_owned())
                );
            }
            let unmatched = client.take_server_notifications();
            assert_eq!(unmatched.len(), 1);
            assert_eq!(
                unmatched[0].params.as_ref().unwrap()["progressToken"],
                "foreign"
            );
            assert!(
                client
                    .next_event(&cx, &cancellation, &mut call)
                    .await
                    .unwrap()
                    .is_none()
            );
            let _peer = server.join(&cx).await.unwrap();
            client.close(&cx).unwrap();
        });
    }

    #[test]
    fn memory_client_drains_ingress_while_both_capacity_one_directions_are_full() {
        run(|cx| async move {
            let (mut client, mut peer) = connected(&cx).await;
            let cancellation = McpRequestCancellation::new();
            let mut first = client
                .execute_core(&cx, &cancellation, "tools/list", json!({}))
                .await
                .unwrap();
            // Client-to-peer now holds request 2; peer-to-client holds a log.
            peer.send_async(
                &cx,
                &JsonRpcMessage::Request(JsonRpcRequest::notification(
                    "notifications/message",
                    Some(json!({"level":"info","data":"before read"})),
                )),
            )
            .await
            .unwrap();
            let mut server = cx
                .spawn(move |peer_cx| async move {
                    // Deliberately finish writing before reading another request.
                    // A send-only capacity waiter deadlocks this exact peer.
                    peer.send_async(&peer_cx, &response(2, tools()))
                        .await
                        .unwrap();
                    receive(&peer_cx, &mut peer, "tools/list", Some(2)).await;
                    receive(&peer_cx, &mut peer, "tools/list", Some(3)).await;
                    peer.send_async(&peer_cx, &response(3, tools()))
                        .await
                        .unwrap();
                    peer
                })
                .unwrap();
            let mut second = client
                .execute_core(&cx, &cancellation, "tools/list", json!({}))
                .await
                .unwrap();
            assert!(matches!(
                result(&cx, &mut client, &mut second).await,
                CoreResult::Final(FinalCoreResult::ToolsList { .. })
            ));
            assert!(matches!(
                result(&cx, &mut client, &mut first).await,
                CoreResult::Final(FinalCoreResult::ToolsList { .. })
            ));
            assert_eq!(client.take_server_notifications().len(), 1);
            let _peer = server.join(&cx).await.unwrap();
            client.close(&cx).unwrap();
        });
    }

    #[test]
    fn memory_client_rejects_reverse_requests_after_real_capacity_without_losing_owners() {
        run(|cx| async move {
            let (mut client, mut peer) = connected(&cx).await;
            let live = McpRequestCancellation::new();
            let mut first = client
                .execute_core(&cx, &live, "tools/list", json!({}))
                .await
                .unwrap();
            let original = client.executor.pending_records();
            // The peer's opposite-direction ID has the same mathematical
            // value as our active ID, but its exact spelling must be echoed.
            let reverse_id = RequestId::Integer("2.00".to_owned());
            peer.send_async(
                &cx,
                &JsonRpcMessage::Request(JsonRpcRequest::new(
                    "roots/list",
                    Some(json!({})),
                    reverse_id.clone(),
                )),
            )
            .await
            .unwrap();
            {
                // The actual outbound slot still holds request 2. Dropping
                // this capacity-blocked wait must preserve the queued reply.
                let mut waiting = pin!(client.next_event(&cx, &live, &mut first));
                poll_fn(|task| {
                    assert!(waiting.as_mut().poll(task).is_pending());
                    Poll::Ready(())
                })
                .await;
            }
            assert_eq!(client.executor.pending_records(), original);
            assert!(client.executor.has_external_controls(&cx).unwrap());
            assert!(client.executor.terminal_error().is_none());
            assert_eq!(client.next_id, 3);
            assert!(client.take_cancellation_events().is_empty());

            let mut server = cx
                .spawn(move |peer_cx| async move {
                    receive(&peer_cx, &mut peer, "tools/list", Some(2)).await;
                    let JsonRpcMessage::Response(rejection) =
                        peer.recv_async(&peer_cx).await.unwrap()
                    else {
                        panic!("the reverse request receives an error response before new work");
                    };
                    assert_eq!(rejection.id, Some(reverse_id));
                    assert!(rejection.result.is_none());
                    assert_eq!(
                        rejection.error.as_ref().unwrap().code.as_i32(),
                        Some(-32601)
                    );
                    // A duplicate rejection or cancellation would fail this read.
                    receive(&peer_cx, &mut peer, "tools/list", Some(3)).await;
                    peer.send_async(&peer_cx, &response(3, tools()))
                        .await
                        .unwrap();
                    peer.send_async(&peer_cx, &response(2, tools()))
                        .await
                        .unwrap();
                    peer
                })
                .unwrap();
            let mut sibling = client
                .execute_core(&cx, &live, "tools/list", json!({}))
                .await
                .unwrap();
            assert_eq!(sibling.request_id(), &RequestId::Number(3));
            assert!(matches!(
                result(&cx, &mut client, &mut first).await,
                CoreResult::Final(FinalCoreResult::ToolsList { .. })
            ));
            assert!(matches!(
                result(&cx, &mut client, &mut sibling).await,
                CoreResult::Final(FinalCoreResult::ToolsList { .. })
            ));
            assert!(!client.executor.has_external_controls(&cx).unwrap());
            assert!(client.executor.terminal_error().is_none());
            assert!(client.take_cancellation_events().is_empty());
            let _peer = server.join(&cx).await.unwrap();
            client.close(&cx).unwrap();
        });
    }

    #[test]
    fn memory_client_unsent_cancellation_drop_and_invalid_input_spend_no_ids() {
        run(|cx| async move {
            let (mut client, mut peer) = connected(&cx).await;
            let live = McpRequestCancellation::new();
            let mut first = client
                .execute_core(&cx, &live, "tools/list", json!({}))
                .await
                .unwrap();
            let original = client.executor.pending_records();
            for (method, parameters) in [
                ("initialize", json!({})),
                ("tools/list", json!({"_meta":[]})),
            ] {
                assert_eq!(
                    client
                        .execute_core(&cx, &live, method, parameters)
                        .await
                        .unwrap_err()
                        .code,
                    McpErrorCode::InvalidParams
                );
                assert_eq!(client.next_id, 3);
                assert_eq!(client.executor.pending_records(), original);
            }
            for drop_wait in [false, true] {
                let cancellation = McpRequestCancellation::new();
                {
                    let mut sending =
                        pin!(client.execute_core(&cx, &cancellation, "tools/list", json!({})));
                    poll_fn(|task| {
                        assert!(sending.as_mut().poll(task).is_pending());
                        Poll::Ready(())
                    })
                    .await;
                    if !drop_wait {
                        cancellation.cancel();
                        assert_eq!(
                            sending.await.unwrap_err().code,
                            McpErrorCode::RequestCancelled
                        );
                    }
                }
                assert_eq!(client.next_id, 3);
                assert_eq!(client.executor.pending_records(), original);
                assert!(!client.executor.has_external_controls(&cx).unwrap());
            }
            receive(&cx, &mut peer, "tools/list", Some(2)).await;
            peer.send_async(&cx, &response(2, tools())).await.unwrap();
            assert!(matches!(
                result(&cx, &mut client, &mut first).await,
                CoreResult::Final(FinalCoreResult::ToolsList { .. })
            ));
            let mut next = client
                .execute_core(&cx, &live, "tools/list", json!({}))
                .await
                .unwrap();
            receive(&cx, &mut peer, "tools/list", Some(3)).await;
            peer.send_async(&cx, &response(3, tools())).await.unwrap();
            result(&cx, &mut client, &mut next).await;
            client.close(&cx).unwrap();
        });
    }

    #[test]
    fn memory_client_dropped_and_original_token_cancelled_owners_do_not_poison_siblings() {
        run(|cx| async move {
            for mode in ["drop", "token", "explicit"] {
                let (mut client, mut peer) = connected(&cx).await;
                let first_token = McpRequestCancellation::new();
                let mut first = Some(
                    client
                        .execute_core(&cx, &first_token, "tools/list", json!({}))
                        .await
                        .unwrap(),
                );
                match mode {
                    "drop" => {
                        drop(first.take());
                    }
                    "token" => {
                        first_token.cancel();
                    }
                    _ => {
                        client.cancel(&cx, first.as_mut().unwrap()).unwrap();
                    }
                }
                // Attempting a new send must retain the unsent cancellation
                // control when the real outbound queue is still full.
                let live = McpRequestCancellation::new();
                {
                    let mut sending =
                        pin!(client.execute_core(&cx, &live, "tools/list", json!({})));
                    poll_fn(|task| {
                        assert!(sending.as_mut().poll(task).is_pending());
                        Poll::Ready(())
                    })
                    .await;
                }
                assert_eq!(client.next_id, 3);
                assert!(client.executor.has_external_controls(&cx).unwrap());
                let mut server = cx
                    .spawn(move |peer_cx| async move {
                        receive(&peer_cx, &mut peer, "tools/list", Some(2)).await;
                        let cancel =
                            receive(&peer_cx, &mut peer, "notifications/cancelled", None).await;
                        assert_eq!(cancel.params.unwrap()["requestId"], 2);
                        receive(&peer_cx, &mut peer, "tools/list", Some(3)).await;
                        peer.send_async(&peer_cx, &response(2, tools()))
                            .await
                            .unwrap();
                        peer.send_async(&peer_cx, &response(3, tools()))
                            .await
                            .unwrap();
                        peer
                    })
                    .unwrap();
                let mut sibling = client
                    .execute_core(&cx, &live, "tools/list", json!({}))
                    .await
                    .unwrap();
                result(&cx, &mut client, &mut sibling).await;
                if let Some(first) = first.as_mut() {
                    // A new wait token cannot revive the old creating token.
                    assert_eq!(
                        client.next_event(&cx, &live, first).await.unwrap_err().code,
                        McpErrorCode::RequestCancelled
                    );
                }
                assert_eq!(client.take_cancellation_events().len(), 1);
                assert!(!client.executor.has_external_controls(&cx).unwrap());
                let _peer = server.join(&cx).await.unwrap();
                client.close(&cx).unwrap();
            }
        });
    }

    #[test]
    fn memory_client_response_timeout_is_observable_without_peer_or_watchdog_wake() {
        run(|cx| async move {
            let (mut client, mut peer) = connected(&cx).await;
            let live = McpRequestCancellation::new();
            let mut silent = client
                .execute_core_with_timeout_policy(
                    &cx,
                    &live,
                    "tools/list",
                    json!({}),
                    RequestTimeoutPolicy::new(
                        Duration::from_millis(40),
                        Duration::from_millis(100),
                    )
                    .unwrap(),
                )
                .await
                .unwrap();
            receive(&cx, &mut peer, "tools/list", Some(2)).await;
            let started = Instant::now();
            assert_eq!(
                client
                    .next_event(&cx, &live, &mut silent)
                    .await
                    .unwrap_err()
                    .code,
                McpErrorCode::RequestCancelled
            );
            assert!(
                started.elapsed() < Duration::from_secs(1),
                "outer watchdog cannot supply the missing wake"
            );
            assert!(!live.is_cancel_requested());
            assert_eq!(
                client.take_cancellation_events()[0].reason,
                crate::ExecutionTerminalReason::IdleTimeout
            );
            client.close(&cx).unwrap();
        });
    }

    #[test]
    fn memory_client_original_token_cancels_while_an_already_committed_sibling_is_driven() {
        run(|cx| async move {
            let (mut client, mut peer) = connected(&cx).await;
            let original = McpRequestCancellation::new();
            let live = McpRequestCancellation::new();
            let mut first = client
                .execute_core(&cx, &original, "tools/list", json!({}))
                .await
                .unwrap();
            receive(&cx, &mut peer, "tools/list", Some(2)).await;
            let mut sibling = client
                .execute_core(&cx, &live, "tools/list", json!({}))
                .await
                .unwrap();
            receive(&cx, &mut peer, "tools/list", Some(3)).await;
            original.cancel();
            let mut server = cx
                .spawn(move |peer_cx| async move {
                    // The late response races cancellation while a different
                    // handle, with a different token, owns the read operation.
                    peer.send_async(&peer_cx, &response(2, tools()))
                        .await
                        .unwrap();
                    peer.send_async(&peer_cx, &response(3, tools()))
                        .await
                        .unwrap();
                    let cancelled =
                        receive(&peer_cx, &mut peer, "notifications/cancelled", None).await;
                    assert_eq!(cancelled.params.unwrap()["requestId"], 2);
                    peer
                })
                .unwrap();
            result(&cx, &mut client, &mut sibling).await;
            assert_eq!(
                client
                    .next_event(&cx, &live, &mut first)
                    .await
                    .unwrap_err()
                    .code,
                McpErrorCode::RequestCancelled
            );
            assert!(!live.is_cancel_requested());
            let _peer = server.join(&cx).await.unwrap();
            client.close(&cx).unwrap();
        });
    }

    #[test]
    fn memory_client_returns_input_required_and_only_sends_an_explicit_continuation() {
        run(|cx| async move {
            let (transport, mut peer) = create_memory_transport_pair_with_capacity(1);
            peer.send_async(&cx, &response(1, discovery()))
                .await
                .unwrap();
            let capabilities: ClientCapabilities =
                serde_json::from_value(json!({"roots":{}})).unwrap();
            let mut client = MemoryClient::connect(&cx, transport, info(), capabilities)
                .await
                .unwrap();
            receive(&cx, &mut peer, "server/discover", Some(1)).await;
            let live = McpRequestCancellation::new();
            let mut call = client
                .execute_core(
                    &cx,
                    &live,
                    "tools/call",
                    json!({"name":"interactive","arguments":{}}),
                )
                .await
                .unwrap();
            receive(&cx, &mut peer, "tools/call", Some(2)).await;
            peer.send_async(&cx, &response(2, json!({"resultType":"input_required", "inputRequests":{"roots":{"method":"roots/list"}}, "requestState":"round-1"}))).await.unwrap();
            let CoreResult::Final(FinalCoreResult::ToolsCallInputRequired {
                result: required, ..
            }) = result(&cx, &mut client, &mut call).await
            else {
                panic!("caller receives the typed continuation branch");
            };
            assert_eq!(required.request_state(), Some("round-1"));
            assert_eq!(
                client.next_id, 3,
                "input-required does not cause an implicit retry"
            );
            assert!(client.executor.pending_records().is_empty());
            let mut continuation = client.execute_core(&cx, &live, "tools/call", json!({
                "name":"interactive", "arguments":{}, "requestState":"round-1", "inputResponses":{"roots":{"roots":[]}}
            })).await.unwrap();
            let retry = receive(&cx, &mut peer, "tools/call", Some(3)).await;
            assert_eq!(
                retry.params.unwrap()["inputResponses"],
                json!({"roots":{"roots":[]}})
            );
            peer.send_async(&cx, &response(3, complete()))
                .await
                .unwrap();
            assert!(matches!(
                result(&cx, &mut client, &mut continuation).await,
                CoreResult::Final(FinalCoreResult::ToolsCall { .. })
            ));
            client.close(&cx).unwrap();
        });
    }

    #[test]
    fn memory_client_caller_deadline_interrupts_full_queue_before_publication() {
        let runtime = RuntimeBuilder::current_thread()
            .blocking_threads(0, 0)
            .build()
            .unwrap();
        let healthy = runtime.request_cx_with_budget(asupersync::Budget::INFINITE);
        runtime.block_on(async {
            asupersync::time::timeout(healthy.now(), Duration::from_secs(3), async {
                let (mut client, mut peer) = connected(&healthy).await;
                let live = McpRequestCancellation::new();
                let first = client
                    .execute_core(&healthy, &live, "tools/list", json!({}))
                    .await
                    .unwrap();
                let before = client.executor.pending_records();
                let limited = runtime.request_cx_with_budget(
                    asupersync::Budget::INFINITE
                        .with_deadline(healthy.now().saturating_add_nanos(40_000_000)),
                );
                let started = Instant::now();
                assert_eq!(
                    client
                        .execute_core(&limited, &live, "tools/list", json!({}))
                        .await
                        .unwrap_err()
                        .code,
                    McpErrorCode::RequestCancelled
                );
                assert!(started.elapsed() < Duration::from_secs(1));
                assert!(!live.is_cancel_requested());
                assert_eq!(client.next_id, 3);
                assert_eq!(client.executor.pending_records(), before);
                receive(&healthy, &mut peer, "tools/list", Some(2)).await;
                client.close(&healthy).unwrap();
                drop(first);
            })
            .await
            .unwrap();
        });
        assert!(runtime.shutdown_timeout(Duration::from_secs(1)));
    }

    #[test]
    fn memory_client_bad_typed_result_and_foreign_handle_leave_healthy_owner_usable() {
        run(|cx| async move {
            let (mut client, mut peer) = connected(&cx).await;
            let (mut other, _other_peer) = connected(&cx).await;
            let live = McpRequestCancellation::new();
            let mut bad = client
                .execute_core(&cx, &live, "tools/list", json!({}))
                .await
                .unwrap();
            receive(&cx, &mut peer, "tools/list", Some(2)).await;
            assert_eq!(
                other
                    .next_event(&cx, &live, &mut bad)
                    .await
                    .unwrap_err()
                    .code,
                McpErrorCode::InvalidParams
            );
            assert_eq!(
                other.cancel(&cx, &mut bad).unwrap_err().code,
                McpErrorCode::InvalidParams
            );
            assert_eq!(client.executor.pending_records().len(), 1);
            peer.send_async(&cx, &response(2, json!({"resultType":"complete","tools":"wrong","ttlMs":0,"cacheScope":"private"}))).await.unwrap();
            assert_eq!(
                client
                    .next_event(&cx, &live, &mut bad)
                    .await
                    .unwrap_err()
                    .code,
                McpErrorCode::InvalidRequest
            );
            let mut good = client
                .execute_core(&cx, &live, "tools/list", json!({}))
                .await
                .unwrap();
            receive(&cx, &mut peer, "tools/list", Some(3)).await;
            peer.send_async(&cx, &response(3, tools())).await.unwrap();
            result(&cx, &mut client, &mut good).await;
            client.close(&cx).unwrap();
            other.close(&cx).unwrap();
        });
    }

    #[test]
    fn memory_client_closed_peer_releases_all_handles_and_close_never_waits_for_capacity() {
        run(|cx| async move {
            for local_close in [false, true] {
                let (mut client, mut peer) = connected(&cx).await;
                let live = McpRequestCancellation::new();
                let mut first = client
                    .execute_core(&cx, &live, "tools/list", json!({}))
                    .await
                    .unwrap();
                receive(&cx, &mut peer, "tools/list", Some(2)).await;
                let mut second = client
                    .execute_core(&cx, &live, "tools/list", json!({}))
                    .await
                    .unwrap();
                let started = Instant::now();
                if local_close {
                    client.close(&cx).unwrap();
                    assert!(started.elapsed() < Duration::from_millis(100));
                } else {
                    peer.close(&cx).unwrap();
                }
                assert!(client.next_event(&cx, &live, &mut first).await.is_err());
                assert!(
                    client
                        .next_event(&cx, &live, &mut first)
                        .await
                        .unwrap()
                        .is_none()
                );
                assert!(client.next_event(&cx, &live, &mut second).await.is_err());
                assert!(
                    client
                        .next_event(&cx, &live, &mut second)
                        .await
                        .unwrap()
                        .is_none()
                );
                assert!(client.executor.pending_records().is_empty());
                let next = client.next_id;
                assert!(
                    client
                        .execute_core(&cx, &live, "tools/list", json!({}))
                        .await
                        .is_err()
                );
                assert_eq!(client.next_id, next);
            }
        });
    }

    #[test]
    fn memory_client_original_cancellation_wins_peer_loss_and_is_consumed_once() {
        run(|cx| async move {
            let (mut client, mut peer) = connected(&cx).await;
            let original = McpRequestCancellation::new();
            let live = McpRequestCancellation::new();
            let mut execution = client
                .execute_core(&cx, &original, "tools/list", json!({}))
                .await
                .unwrap();
            receive(&cx, &mut peer, "tools/list", Some(2)).await;
            {
                let mut waiting = pin!(client.next_event(&cx, &live, &mut execution));
                poll_fn(|task| {
                    assert!(waiting.as_mut().poll(task).is_pending());
                    Poll::Ready(())
                })
                .await;
                // The live observer is already inside the read operation.
                // Connection failure must inspect the original owner's token,
                // then report its cancellation instead of the raw read error.
                original.cancel();
                peer.close(&cx).unwrap();
                assert_eq!(
                    waiting.await.unwrap_err().code,
                    McpErrorCode::RequestCancelled
                );
            }
            assert!(!live.is_cancel_requested());
            assert!(execution.inner.terminal_error().is_none());
            assert!(client.executor.terminal_error().is_some());
            assert!(client.executor.pending_records().is_empty());
            for _ in 0..2 {
                assert!(
                    client
                        .next_event(&cx, &live, &mut execution)
                        .await
                        .unwrap()
                        .is_none()
                );
            }
            client.close(&cx).unwrap();
        });
    }

    #[test]
    fn memory_client_control_saturation_preserves_and_consumes_elected_cancellation() {
        run(|cx| async move {
            for mode in ["original", "observer-before-wait", "observer-after-pending"] {
                let (mut client, _peer) = connected(&cx).await;
                let original = McpRequestCancellation::new();
                let observer = McpRequestCancellation::new();
                let mut execution = client
                    .execute_core(&cx, &original, "tools/list", json!({}))
                    .await
                    .unwrap();
                let source = serde_json::to_vec(&JsonRpcMessage::Request(JsonRpcRequest::new(
                    "roots/list",
                    Some(json!({})),
                    2,
                )))
                .unwrap();
                // Fill only the bounded external rejection allowance, leaving
                // the ordinary owner active and the actual send queue untouched.
                for _ in 0..crate::execution::DEFAULT_MAX_IN_FLIGHT_EXECUTIONS {
                    client
                        .executor
                        .drive_frame(&cx, ReceivedTransportFrame::admit(source.clone()).unwrap())
                        .unwrap();
                }
                assert!(client.executor.terminal_error().is_none());
                assert_eq!(client.executor.pending_records().len(), 1);
                let error = if mode == "observer-after-pending" {
                    let mut waiting = pin!(client.next_event(&cx, &observer, &mut execution));
                    poll_fn(|task| {
                        assert!(waiting.as_mut().poll(task).is_pending());
                        Poll::Ready(())
                    })
                    .await;
                    observer.cancel();
                    waiting.await.unwrap_err()
                } else {
                    if mode == "original" {
                        original.cancel();
                    } else {
                        observer.cancel();
                    }
                    client
                        .next_event(&cx, &observer, &mut execution)
                        .await
                        .unwrap_err()
                };
                // Each cancellation path elects the owner's outcome before
                // its additional control overflows the shared queue.
                assert_eq!(error.code, McpErrorCode::RequestCancelled, "{mode}");
                assert_eq!(original.is_cancel_requested(), mode == "original");
                assert!(client.executor.terminal_error().is_some());
                assert!(execution.inner.terminal_error().is_none());
                assert!(
                    client
                        .next_event(&cx, &observer, &mut execution)
                        .await
                        .unwrap()
                        .is_none()
                );
                assert!(!client.executor.has_external_controls(&cx).unwrap());
                client.close(&cx).unwrap();
            }
        });
    }

    #[test]
    fn memory_client_retained_success_wins_sibling_cancellation_control_overflow() {
        run(|cx| async move {
            let (mut client, mut peer) = connected(&cx).await;
            let live = McpRequestCancellation::new();
            let stopped = McpRequestCancellation::new();
            let mut completed = client
                .execute_core(&cx, &live, "tools/list", json!({}))
                .await
                .unwrap();
            receive(&cx, &mut peer, "tools/list", Some(2)).await;
            let mut sibling = client
                .execute_core(&cx, &stopped, "tools/list", json!({}))
                .await
                .unwrap();
            // Model a successful response already routed while a sibling
            // drove ingress, but not yet consumed by its selected owner.
            let completed_source = serde_json::to_vec(&response(2, tools())).unwrap();
            client
                .executor
                .drive_frame(
                    &cx,
                    ReceivedTransportFrame::admit(completed_source).unwrap(),
                )
                .unwrap();
            let rejection_source = serde_json::to_vec(&JsonRpcMessage::Request(
                JsonRpcRequest::new("roots/list", Some(json!({})), 2),
            ))
            .unwrap();
            for _ in 0..crate::execution::DEFAULT_MAX_IN_FLIGHT_EXECUTIONS {
                client
                    .executor
                    .drive_frame(
                        &cx,
                        ReceivedTransportFrame::admit(rejection_source.clone()).unwrap(),
                    )
                    .unwrap();
            }
            stopped.cancel();
            assert!(matches!(
                result(&cx, &mut client, &mut completed).await,
                CoreResult::Final(FinalCoreResult::ToolsList { .. })
            ));
            assert!(
                client
                    .next_event(&cx, &live, &mut completed)
                    .await
                    .unwrap()
                    .is_none()
            );
            assert!(client.executor.terminal_error().is_some());
            assert_eq!(
                client
                    .next_event(&cx, &live, &mut sibling)
                    .await
                    .unwrap_err()
                    .code,
                McpErrorCode::RequestCancelled
            );
            assert!(
                client
                    .next_event(&cx, &live, &mut sibling)
                    .await
                    .unwrap()
                    .is_none()
            );
            assert!(client.executor.pending_records().is_empty());
            assert!(!client.executor.has_external_controls(&cx).unwrap());
            client.close(&cx).unwrap();
        });
    }

    #[test]
    fn memory_client_discovery_rejects_legacy_without_sending_initialize() {
        run(|cx| async move {
            let (transport, mut peer) = create_memory_transport_pair_with_capacity(1);
            let mut peer_discovery = discovery();
            peer_discovery["supportedVersions"] = json!(["2024-11-05"]);
            peer.send_async(&cx, &response(1, peer_discovery))
                .await
                .unwrap();
            assert!(
                MemoryClient::connect(&cx, transport, info(), ClientCapabilities::default())
                    .await
                    .is_err()
            );
            receive(&cx, &mut peer, "server/discover", Some(1)).await;
            assert!(matches!(
                peer.recv_async(&cx).await,
                Err(TransportError::Closed)
            ));
        });
    }
}
