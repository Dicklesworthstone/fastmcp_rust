//! Explicit, one-shot resolution of a fresh Task input snapshot.
//!
//! This is not a retry loop: one get, one admitted callback batch, one update.
//! Managed and ordinary clients share the same admission and callback engine.
//! Their transport adapters retain the original operation's lifetime and IDs.

use std::collections::BTreeMap;
use std::future::{Future, poll_fn};
use std::io::{self, Write};
use std::task::Poll;
use std::time::Instant;

use asupersync::Cx;
#[cfg(feature = "websocket-experimental")]
use asupersync::io::{AsyncRead, AsyncWrite};
use asupersync::time::Sleep;
use asupersync::types::Time;
use fastmcp_core::{McpError, McpRequestCancellation, McpResult};
use fastmcp_protocol::tasks_extension::{
    MAX_TASK_INPUT_MAP_ENTRIES, TaskInputLedger, TaskInputRequests,
};
use fastmcp_protocol::{FinalEmbeddedInputRequest, FinalEmbeddedInputResponse, RequestId};
use serde::Serialize;
use serde_json::Value;

use super::{
    MAX_TASK_RESPONSE_BYTES, ManagedHttpClient, ManagedHttpClientError, TaskCall, TaskResult,
};
#[cfg(unix)]
use crate::Client;
#[cfg(feature = "websocket-experimental")]
use crate::WebSocketClient;
use crate::http_auth::rpc::interaction::{admit_embedded_input, normalize_embedded_input_context};
use crate::{
    FinalTask, FinalTaskId, FinalTaskInputResponses, FinalUpdateTaskResult, HttpClient,
    HttpClientError, MrtrCallbackOwner, ReverseRequestHandlers, catch_client_callback_unwind,
};
// `#[cfg(test)]`, not unconditional and not absent. Its only remaining users
// are in this file's test module (`owners: &Arc<Mutex<Vec<..>>>` at :934 and
// `cancellation: ..` at :971); the production use went away when resolve_one
// stopped making its own token, because
// invoke_embedded_input_request_async now creates one internally and returns
// the owner.
//
// `warning: unused import` is computed PER TARGET. It is genuinely unused in
// `--lib`, which is what emitted the warning, and genuinely required in
// `--lib --test`. Deleting it silenced the warning and produced two E0425s;
// gating it to `cfg(test)` satisfies both targets, which is the only form that
// does.
#[cfg(test)]
use crate::ReverseRequestCancellation;

fn invalid(message: &'static str) -> McpError {
    McpError::invalid_params(message)
}

fn checkpoint(cx: &Cx, cancellation: &McpRequestCancellation) -> McpResult<()> {
    if cancellation.is_cancel_requested() || cx.checkpoint().is_err() {
        return Err(McpError::request_cancelled());
    }
    Ok(())
}

fn expired_input() -> McpError {
    McpError::invalid_request("Final Task input snapshot has expired")
}

// The retained snapshot, not a callback or a later credential renewal, fixes
// this disclosure's lifetime. Wall time is checked at every effect boundary;
// the caller's runtime timer also caps the original remaining duration so a
// silent callback wakes and a clock adjustment cannot extend the operation.
struct InputRetention<'task> {
    task: &'task FinalTask,
    deadline: Option<Time>,
}

impl<'task> InputRetention<'task> {
    fn new(cx: &Cx, task: &'task FinalTask) -> McpResult<Self> {
        let remaining = crate::task_wait::input_retention_remaining(task)?;
        if remaining.is_some() && cx.timer_driver().is_none() {
            return Err(McpError::internal_error(
                "Task input retention requires a caller timer driver",
            ));
        }
        let deadline = remaining.map(|remaining| {
            cx.now()
                .saturating_add_nanos(u64::try_from(remaining.as_nanos()).unwrap_or(u64::MAX))
        });
        Ok(Self { task, deadline })
    }

    fn check(&self, cx: &Cx) -> McpResult<()> {
        crate::task_wait::admit_input_retention(self.task)?;
        if self.deadline.is_some_and(|deadline| cx.now() >= deadline) {
            return Err(expired_input());
        }
        Ok(())
    }
}

fn admit_limits(max_inputs: usize, max_payload_bytes: usize) -> Result<(), ManagedHttpClientError> {
    admit_input_limits(max_inputs, max_payload_bytes)
        .map_err(|_| ManagedHttpClientError::InvalidPolicy)
}

fn admit_input_limits(max_inputs: usize, max_payload_bytes: usize) -> McpResult<()> {
    if !(1..=MAX_TASK_INPUT_MAP_ENTRIES).contains(&max_inputs)
        || !(1..=MAX_TASK_RESPONSE_BYTES).contains(&max_payload_bytes)
    {
        return Err(invalid("Invalid Task input resolution limits"));
    }
    Ok(())
}

// Count encoded descriptors and keyed answers without another response buffer.
// Counts bound container overhead; bytes are a serialization budget, not RSS.
struct PayloadBudget(usize);

impl PayloadBudget {
    fn charge(&mut self, value: &impl Serialize) -> McpResult<()> {
        let mut counter = Self(self.0);
        serde_json::to_writer(&mut counter, value)
            .map_err(|_| invalid("Task input payload limit exceeded"))?;
        self.0 = counter.0;
        Ok(())
    }
}

impl Write for PayloadBudget {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.0 = self
            .0
            .checked_sub(bytes.len())
            .ok_or_else(|| io::Error::other("Task input payload limit"))?;
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

struct PreparedInputs {
    ledger: TaskInputLedger,
    effective: TaskInputRequests,
    budget: PayloadBudget,
    omitted_contexts: usize,
}

fn prepare_inputs(
    task: &FinalTask,
    handlers: &ReverseRequestHandlers,
    capabilities: &Value,
    max_inputs: usize,
    max_payload_bytes: usize,
) -> McpResult<PreparedInputs> {
    let FinalTask::InputRequired { input_requests, .. } = task else {
        return Err(invalid("Task is not awaiting input"));
    };
    crate::task_wait::admit_input_retention(task)?;
    if input_requests.is_empty() || input_requests.len() > max_inputs {
        return Err(invalid("Task input count is outside its bounds"));
    }
    let ledger = TaskInputLedger::from_requests(input_requests)
        .map_err(|_| invalid("Invalid Task input descriptors"))?;
    let mut budget = PayloadBudget(max_payload_bytes);
    budget.charge(input_requests)?;
    let mut effective = BTreeMap::new();
    let mut omitted_contexts = 0;
    for (key, request) in input_requests {
        let installed = match request {
            FinalEmbeddedInputRequest::Roots(_) => handlers.modern_roots_list.is_some(),
            FinalEmbeddedInputRequest::Sampling(_) => {
                handlers.modern_sampling_create_message.is_some()
            }
            FinalEmbeddedInputRequest::Elicitation(_) => {
                handlers.modern_elicitation_create.is_some()
            }
        };
        if !installed {
            return Err(invalid(
                "Task input requires an unconfigured reverse handler",
            ));
        }
        let encoded = serde_json::to_value(request)
            .map_err(|_| invalid("Task input descriptor could not be encoded"))?;
        let mut admitted = admit_embedded_input(capabilities, encoded)
            .map_err(|_| invalid("Task input requires an unadvertised capability"))?;
        if normalize_embedded_input_context(capabilities, &mut admitted) {
            omitted_contexts += 1;
        }
        effective.insert(key.clone(), admitted);
    }
    Ok(PreparedInputs {
        ledger,
        effective,
        budget,
        omitted_contexts,
    })
}

async fn resolve_one(
    cx: &Cx,
    cancellation: &McpRequestCancellation,
    retention: &InputRetention<'_>,
    handlers: &ReverseRequestHandlers,
    key: &str,
    request: FinalEmbeddedInputRequest,
) -> McpResult<(FinalEmbeddedInputResponse, MrtrCallbackOwner)> {
    checkpoint(cx, cancellation)?;
    retention.check(cx)?;
    let kind = request.response_kind();
    // `invoke_embedded_input_request_async` takes the caller's CHECKPOINT and
    // creates its own `ReverseRequestCancellation` internally, returning the
    // `MrtrCallbackOwner` it made -- the shape of the canonical call in
    // `Client::respond_to_input_required_async`. This site still passed a
    // caller-made cancellation and built its own owner, which is the signature
    // that existed before 5f60e8de moved ownership transfer inside the method
    // ("Transfer successful ownership explicitly"); that commit updated lib.rs
    // and left this call behind. The owner is forwarded to this function's
    // caller, which is what records RESPONSE_SENT, so the "live until ACK"
    // invariant the previous comment described is preserved -- it is now the
    // method's and the caller's, not this frame's.
    let guard = || {
        checkpoint(cx, cancellation)?;
        retention.check(cx)
    };
    let mut callback =
        std::pin::pin!(handlers.invoke_embedded_input_request_async(cx, key, request, &guard));
    let (value, owner) = poll_fn(|task| {
        if let Err(error) = checkpoint(cx, cancellation) {
            return Poll::Ready(Err(error));
        }
        if let Err(error) = retention.check(cx) {
            return Poll::Ready(Err(error));
        }
        let result =
            catch_client_callback_unwind(|| callback.as_mut().poll(task)).unwrap_or_else(|_| {
                Poll::Ready(Err(McpError::internal_error(
                    "Client Task input handler failed",
                )))
            });
        if let Err(error) = checkpoint(cx, cancellation) {
            return Poll::Ready(Err(error));
        }
        if let Err(error) = retention.check(cx) {
            return Poll::Ready(Err(error));
        }
        result
    })
    .await?;
    let response: FinalEmbeddedInputResponse = serde_json::from_value(value)
        .map_err(|_| invalid("Invalid Task input response"))?;
    if !response.matches_kind(kind) {
        return Err(invalid(
            "Task input response does not match its descriptor",
        ));
    }
    Ok((response, owner))
}

// Poll every admitted input before waiting. A host input can itself wait for
// another input in the same batch; awaiting them serially never starts that
// sibling. These futures remain owned by this operation, not spawned tasks.
async fn resolve_batch(
    cx: &Cx,
    cancellation: &McpRequestCancellation,
    retention: &InputRetention<'_>,
    handlers: &ReverseRequestHandlers,
    effective: TaskInputRequests,
    budget: &mut PayloadBudget,
) -> McpResult<(FinalTaskInputResponses, Vec<MrtrCallbackOwner>)> {
    if effective.is_empty() || effective.len() > MAX_TASK_INPUT_MAP_ENTRIES {
        return Err(invalid("Task input count is outside its bounds"));
    }
    let mut timer = std::pin::pin!(retention.deadline.map(Sleep::new));
    let mut pending: Vec<_> = effective
        .into_iter()
        .map(|(key, request)| {
            Some(Box::pin(async move {
                let (response, owner) =
                    resolve_one(cx, cancellation, retention, handlers, &key, request).await?;
                Ok::<_, McpError>((key, response, owner))
            }))
        })
        .collect();
    let mut responses = FinalTaskInputResponses::new();
    let mut owners = Vec::with_capacity(pending.len());
    poll_fn(|task| {
        checkpoint(cx, cancellation)?;
        retention.check(cx)?;
        if let Some(timer) = timer.as_mut().as_pin_mut()
            && timer.poll(task).is_ready()
        {
            return Poll::Ready(Err(expired_input()));
        }
        for slot in &mut pending {
            checkpoint(cx, cancellation)?;
            retention.check(cx)?;
            let Some(future) = slot else {
                continue;
            };
            let Poll::Ready(result) = future.as_mut().poll(task) else {
                continue;
            };
            // A completed child must never be polled again. On any subsequent
            // failure, dropping this batch cancels both completed owners and
            // still-pending callbacks before dispatch can submit an update.
            *slot = None;
            let (key, response, owner) = result?;
            budget.charge(&(&key, &response))?;
            responses.insert(key, response);
            owners.push(owner);
        }
        checkpoint(cx, cancellation)?;
        retention.check(cx)?;
        if owners.len() == pending.len() {
            Poll::Ready(Ok((
                std::mem::take(&mut responses),
                std::mem::take(&mut owners),
            )))
        } else {
            Poll::Pending
        }
    })
    .await
}

// Only these adapters own wire admission. The engine below cannot create a
// Task, reconstruct an authentication context, or repeat an uncertain update.
trait TaskInputTransport {
    type Error: From<McpError>;

    async fn read(
        &mut self,
        cx: &Cx,
        cancellation: &McpRequestCancellation,
        task_id: FinalTaskId,
    ) -> Result<FinalTask, Self::Error>;

    fn input_context(&self) -> McpResult<(ReverseRequestHandlers, Value)>;

    async fn update(
        &mut self,
        cx: &Cx,
        cancellation: &McpRequestCancellation,
        task: &FinalTask,
        responses: FinalTaskInputResponses,
    ) -> Result<FinalUpdateTaskResult, Self::Error>;
}

struct HttpTaskInputTransport<'client> {
    client: &'client mut HttpClient,
    // Managed admission reserves the first ID before entering this operation.
    // Ordinary HTTP resolves it from the same allocator at its first read.
    request_id: Option<RequestId>,
}

impl TaskInputTransport for HttpTaskInputTransport<'_> {
    type Error = HttpClientError;

    async fn read(
        &mut self,
        cx: &Cx,
        cancellation: &McpRequestCancellation,
        task_id: FinalTaskId,
    ) -> Result<FinalTask, Self::Error> {
        checkpoint(cx, cancellation)?;
        let request_id = match self.request_id.take() {
            Some(request_id) => request_id,
            None => self.client.next_request_id()?,
        };
        self.client
            .connection
            .get_task_final(cx, request_id, task_id, MAX_TASK_RESPONSE_BYTES)
            .await
            .map(|result| result.task)
            .map_err(HttpClientError::Connection)
    }

    fn input_context(&self) -> McpResult<(ReverseRequestHandlers, Value)> {
        // In the managed path these are the operation-local wrapped handlers
        // installed by CallbackBoundary. Never recover unguarded builder copies.
        let handlers = self
            .client
            .connection
            .modern_reverse_request_handlers()
            .cloned()
            .ok_or_else(|| invalid("No Task input handlers are configured"))?;
        let capabilities = serde_json::to_value(&self.client.client_capabilities)
            .map_err(|_| invalid("Invalid client capabilities"))?;
        Ok((handlers, capabilities))
    }

    async fn update(
        &mut self,
        cx: &Cx,
        cancellation: &McpRequestCancellation,
        task: &FinalTask,
        responses: FinalTaskInputResponses,
    ) -> Result<FinalUpdateTaskResult, Self::Error> {
        checkpoint(cx, cancellation)?;
        let update_id = self.client.next_request_id()?;
        self.client
            .connection
            .update_task_final(cx, update_id, task, responses, MAX_TASK_RESPONSE_BYTES)
            .await
            .map_err(HttpClientError::Connection)
    }
}

#[cfg(unix)]
impl TaskInputTransport for Client {
    type Error = McpError;

    async fn read(
        &mut self,
        cx: &Cx,
        cancellation: &McpRequestCancellation,
        task_id: FinalTaskId,
    ) -> McpResult<FinalTask> {
        self.get_task_final_with_cx(cx, cancellation, task_id)
            .await
            .map(|result| result.task)
    }

    fn input_context(&self) -> McpResult<(ReverseRequestHandlers, Value)> {
        let capabilities = serde_json::to_value(self.session.client_capabilities())
            .map_err(|_| invalid("Invalid client capabilities"))?;
        Ok((self.reverse_request_handlers.clone(), capabilities))
    }

    async fn update(
        &mut self,
        cx: &Cx,
        cancellation: &McpRequestCancellation,
        task: &FinalTask,
        responses: FinalTaskInputResponses,
    ) -> McpResult<FinalUpdateTaskResult> {
        self.update_task_final_with_cx(cx, cancellation, task, responses)
            .await
    }
}

#[cfg(feature = "websocket-experimental")]
impl<IO> TaskInputTransport for WebSocketClient<IO>
where
    IO: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    type Error = McpError;

    async fn read(
        &mut self,
        cx: &Cx,
        cancellation: &McpRequestCancellation,
        task_id: FinalTaskId,
    ) -> McpResult<FinalTask> {
        checkpoint(cx, cancellation)?;
        self.get_task_final(cx, task_id).await.map(|result| result.task)
    }

    fn input_context(&self) -> McpResult<(ReverseRequestHandlers, Value)> {
        let capabilities = serde_json::to_value(self.session.client_capabilities())
            .map_err(|_| invalid("Invalid client capabilities"))?;
        Ok((self.reverse_request_handlers.clone(), capabilities))
    }

    async fn update(
        &mut self,
        cx: &Cx,
        cancellation: &McpRequestCancellation,
        task: &FinalTask,
        responses: FinalTaskInputResponses,
    ) -> McpResult<FinalUpdateTaskResult> {
        checkpoint(cx, cancellation)?;
        self.update_task_final(cx, task, responses).await
    }
}

async fn resolve_with_transport<T: TaskInputTransport>(
    cx: &Cx,
    cancellation: &McpRequestCancellation,
    transport: &mut T,
    task_id: FinalTaskId,
    max_inputs: usize,
    max_payload_bytes: usize,
) -> Result<FinalUpdateTaskResult, T::Error> {
    admit_input_limits(max_inputs, max_payload_bytes)?;
    // Let both managed lifetime guards check before each new network boundary,
    // including immediately ready cached discovery and ready host callbacks.
    asupersync::runtime::yield_now().await;
    checkpoint(cx, cancellation)?;
    let snapshot = transport.read(cx, cancellation, task_id).await?;
    asupersync::runtime::yield_now().await;
    checkpoint(cx, cancellation)?;
    let retention = InputRetention::new(cx, &snapshot)?;
    let (handlers, capabilities) = transport.input_context()?;
    let PreparedInputs {
        ledger,
        effective,
        mut budget,
        omitted_contexts,
    } = prepare_inputs(
        &snapshot,
        &handlers,
        &capabilities,
        max_inputs,
        max_payload_bytes,
    )?;
    // Emit no peer-controlled keys or values. The diagnostic precedes host
    // effects, and only after the entire batch passed capability admission.
    if omitted_contexts != 0 {
        log::debug!("Unadvertised sampling context omitted from Task inputs");
    }
    let (responses, owners) = resolve_batch(
        cx,
        cancellation,
        &retention,
        &handlers,
        effective,
        &mut budget,
    )
    .await?;
    ledger
        .validate_responses(&responses)
        .map_err(|_| invalid("Invalid Task input response batch"))?;
    asupersync::runtime::yield_now().await;
    checkpoint(cx, cancellation)?;
    retention.check(cx)?;
    let acknowledged = transport
        .update(cx, cancellation, &snapshot, responses)
        .await?;
    asupersync::runtime::yield_now().await;
    checkpoint(cx, cancellation)?;
    for owner in &owners {
        owner.0.record_response_sent();
    }
    Ok(acknowledged)
}

pub(super) async fn dispatch(
    cx: &Cx,
    cancellation: &McpRequestCancellation,
    client: &mut HttpClient,
    request_id: RequestId,
    task_id: FinalTaskId,
    max_inputs: usize,
    max_payload_bytes: usize,
) -> Result<TaskResult, HttpClientError> {
    resolve_with_transport(
        cx,
        cancellation,
        &mut HttpTaskInputTransport {
            client,
            request_id: Some(request_id),
        },
        task_id,
        max_inputs,
        max_payload_bytes,
    )
    .await
    .map(TaskResult::Update)
}

fn native_deadline(
    cx: &Cx,
    cancellation: &McpRequestCancellation,
    policy: crate::RequestTimeoutPolicy,
    max_inputs: usize,
    max_payload_bytes: usize,
) -> McpResult<Instant> {
    admit_input_limits(max_inputs, max_payload_bytes)?;
    checkpoint(cx, cancellation)?;
    if cx.timer_driver().is_none() {
        return Err(McpError::internal_error(
            "Task input resolution requires a caller timer driver",
        ));
    }
    crate::mrtr_operation_deadline(cx, policy)
}

impl HttpClient {
    /// Reads one fresh Task, resolves its inputs with this client's installed
    /// modern roots, sampling and elicitation handlers, and submits one update.
    ///
    /// This call explicitly authorizes those host effects. The entire input
    /// batch must satisfy the capabilities actually advertised by this client
    /// and have installed handlers before any callback starts. Callbacks run
    /// concurrently within finite count and payload bounds, without spawning
    /// tasks. Unadvertised sampling context is omitted from callback inputs.
    ///
    /// The configured request absolute timeout and caller `Cx` deadline cover
    /// the read, callbacks and update together. A caller timer driver is
    /// required. Finite Task retention also bounds callback execution and
    /// admission of the update. Dropping or cancelling the operation cancels
    /// local callback owners; it never sends `tasks/cancel`.
    ///
    /// No failed or uncertain update is retried, and no Task is created. An
    /// acknowledgement does not imply completion or change an existing handle:
    /// explicitly poll or attach the Task afterward to reconcile its state.
    /// Calling this API again is a new disclosure decision and may repeat host
    /// effects. It does not provide crash recovery or exactly-once execution.
    ///
    /// `max_inputs` is 1..=MAX_TASK_INPUT_MAP_ENTRIES; `max_payload_bytes` is
    /// 1..=8 MiB and covers the encoded descriptors plus keyed answers.
    /// Invalid bounds and pre-cancellation refuse before allocating an ID.
    pub async fn resolve_task_inputs_final(
        &mut self,
        cx: &Cx,
        task_id: FinalTaskId,
        max_inputs: usize,
        max_payload_bytes: usize,
    ) -> Result<FinalUpdateTaskResult, HttpClientError> {
        self.resolve_task_inputs_final_with_cancellation(
            cx,
            &McpRequestCancellation::new(),
            task_id,
            max_inputs,
            max_payload_bytes,
        )
        .await
    }

    /// One-shot Task input resolution with caller-owned cancellation. An
    /// interrupted update may already have reached the server; reconcile it
    /// explicitly instead of invoking host callbacks again automatically.
    pub async fn resolve_task_inputs_final_with_cancellation(
        &mut self,
        cx: &Cx,
        cancellation: &McpRequestCancellation,
        task_id: FinalTaskId,
        max_inputs: usize,
        max_payload_bytes: usize,
    ) -> Result<FinalUpdateTaskResult, HttpClientError> {
        let deadline = native_deadline(
            cx,
            cancellation,
            self.request_timeout_policy,
            max_inputs,
            max_payload_bytes,
        )?;
        crate::wait_for_mrtr_operation(
            cx,
            Some(cancellation),
            deadline,
            resolve_with_transport(
                cx,
                cancellation,
                &mut HttpTaskInputTransport {
                    client: self,
                    request_id: None,
                },
                task_id,
                max_inputs,
                max_payload_bytes,
            ),
        )
        .await
    }
}

#[cfg(unix)]
impl Client {
    /// Resolves one fresh Task input batch through the yielding Unix stdio
    /// request owner. This has the same bounded host-effect admission and
    /// single-update semantics as [`HttpClient::resolve_task_inputs_final`].
    /// The original timeout also covers any deferred initialization. Dropping
    /// a request retires only its owner; deferred wire cancellation is flushed
    /// when this client next drives ingress or closes.
    pub async fn resolve_task_inputs_final(
        &mut self,
        cx: &Cx,
        task_id: FinalTaskId,
        max_inputs: usize,
        max_payload_bytes: usize,
    ) -> McpResult<FinalUpdateTaskResult> {
        self.resolve_task_inputs_final_with_cancellation(
            cx,
            &McpRequestCancellation::new(),
            task_id,
            max_inputs,
            max_payload_bytes,
        )
        .await
    }

    /// Resolves one admitted batch with caller cancellation. No callback or
    /// uncertain update is automatically replayed. Read the Task again after
    /// acknowledgement or interruption before deciding on another disclosure.
    pub async fn resolve_task_inputs_final_with_cancellation(
        &mut self,
        cx: &Cx,
        cancellation: &McpRequestCancellation,
        task_id: FinalTaskId,
        max_inputs: usize,
        max_payload_bytes: usize,
    ) -> McpResult<FinalUpdateTaskResult> {
        let deadline = native_deadline(
            cx,
            cancellation,
            self.timeout_policy,
            max_inputs,
            max_payload_bytes,
        )?;
        crate::wait_for_mrtr_operation(
            cx,
            Some(cancellation),
            deadline,
            resolve_with_transport(
                cx,
                cancellation,
                self,
                task_id,
                max_inputs,
                max_payload_bytes,
            ),
        )
        .await
    }
}

#[cfg(feature = "websocket-experimental")]
impl<IO> WebSocketClient<IO>
where
    IO: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    /// Resolves one fresh Task input batch over this negotiated WebSocket.
    /// Admission, concurrent callbacks and bounds match
    /// [`HttpClient::resolve_task_inputs_final`]. The operation retains the
    /// same connection and request-ID allocator throughout; it never reconnects
    /// or repeats an uncertain update. A successful ACK requires an explicit
    /// later Task read to learn the resulting state.
    pub async fn resolve_task_inputs_final(
        &mut self,
        cx: &Cx,
        task_id: FinalTaskId,
        max_inputs: usize,
        max_payload_bytes: usize,
    ) -> McpResult<FinalUpdateTaskResult> {
        self.resolve_task_inputs_final_with_cancellation(
            cx,
            &McpRequestCancellation::new(),
            task_id,
            max_inputs,
            max_payload_bytes,
        )
        .await
    }

    /// One-shot Task input resolution with caller cancellation. The native
    /// request owner handles abandonment; an interrupted partial frame makes
    /// the connection unusable instead of replaying the update.
    pub async fn resolve_task_inputs_final_with_cancellation(
        &mut self,
        cx: &Cx,
        cancellation: &McpRequestCancellation,
        task_id: FinalTaskId,
        max_inputs: usize,
        max_payload_bytes: usize,
    ) -> McpResult<FinalUpdateTaskResult> {
        let deadline = native_deadline(
            cx,
            cancellation,
            self.request_timeout_policy,
            max_inputs,
            max_payload_bytes,
        )?;
        crate::wait_for_mrtr_operation(
            cx,
            Some(cancellation),
            deadline,
            resolve_with_transport(
                cx,
                cancellation,
                self,
                task_id,
                max_inputs,
                max_payload_bytes,
            ),
        )
        .await
    }
}

impl ManagedHttpClient {
    /// Fetches one fresh input-required Task, resolves its inputs using the
    /// configured modern reverse handlers, and submits exactly one update.
    ///
    /// Requires `with_tasks` and live bilateral Tasks admission. Every input's
    /// descriptor, advertised capability and installed handler is checked before
    /// any callback runs. Sampling tools and URL elicitation need their specific
    /// capability leaves; unsupported sampling context is omitted with a fixed
    /// diagnostic before host effects. The original snapshot is not rewritten.
    ///
    /// Admitted callbacks progress concurrently within this operation, up to
    /// `max_inputs` live futures; no runtime tasks or threads are spawned. A
    /// pending input does not prevent an independent input from starting.
    /// Replies retain their original keys regardless of completion order. All
    /// replies must pass the shared payload budget and input ledger before the
    /// single update is sent. Failure disposes the entire local batch.
    ///
    /// This is an explicit disclosure operation, not part of get/wait/watch.
    /// The caller must authorize use of its configured roots, sampling and
    /// elicitation handlers for this task. Callbacks may perform side effects;
    /// those cannot be undone if a later callback or the update fails.
    ///
    /// One credential and one managed deadline cover discovery, snapshot, host
    /// input and update. The Task's finite retention is checked before callbacks
    /// and update, and a caller-runtime timer interrupts pending callbacks at
    /// that earlier deadline. Null retention adds no Task deadline. Cancellation,
    /// logout, revocation, expiry and abandonment dispose local callback owners
    /// and prevent further updates. No uncertain
    /// update is retried; no task is created, polled, watched or cancelled. An
    /// acknowledgement is not evidence that the task subsequently completed.
    /// Invoking this API again is a new disclosure decision, not exactly-once
    /// recovery. The server still authorizes current task state at update time.
    ///
    /// `max_inputs` is 1..=MAX_TASK_INPUT_MAP_ENTRIES. `max_payload_bytes` is
    /// 1..=8 MiB and counts the encoded descriptor map plus each encoded
    /// `(input_key, answer)` pair. Native response/envelope limits are separate.
    /// Invalid local bounds refuse before acquisition or network contact.
    pub async fn resolve_task_inputs_final(
        &mut self,
        cx: &Cx,
        task_id: FinalTaskId,
        max_inputs: usize,
        max_payload_bytes: usize,
    ) -> Result<FinalUpdateTaskResult, ManagedHttpClientError> {
        self.resolve_task_inputs_final_with_cancellation(
            cx,
            &McpRequestCancellation::new(),
            task_id,
            max_inputs,
            max_payload_bytes,
        )
        .await
    }

    /// One-shot Task input resolution with caller-owned cancellation. Cancelling
    /// this operation never closes a sibling client or the shared OAuth login.
    pub async fn resolve_task_inputs_final_with_cancellation(
        &mut self,
        cx: &Cx,
        cancellation: &McpRequestCancellation,
        task_id: FinalTaskId,
        max_inputs: usize,
        max_payload_bytes: usize,
    ) -> Result<FinalUpdateTaskResult, ManagedHttpClientError> {
        self.admit_tasks(cx, cancellation)?;
        admit_limits(max_inputs, max_payload_bytes)?;
        match self
            .perform_task(
                cx,
                cancellation,
                TaskCall::Resolve {
                    task_id,
                    max_inputs,
                    max_payload_bytes,
                },
            )
            .await?
        {
            TaskResult::Update(result) => Ok(result),
            _ => Err(ManagedHttpClientError::InvalidPolicy),
        }
    }
}

#[cfg(all(test, any(unix, feature = "websocket-experimental")))]
mod native_tests {
    use super::*;
    use crate::{ClientBuilder, ClientProtocolPlan, ProtocolPolicy, RequestTimeoutPolicy};
    use fastmcp_core::McpErrorCode;
    use serde_json::json;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex};
    use std::time::Duration;

    const INPUT_BYTES: usize = 64 * 1024;

    fn id() -> FinalTaskId {
        FinalTaskId::parse("task-1").unwrap()
    }

    fn discovery() -> Value {
        json!({
            "resultType":"complete", "supportedVersions":["2026-07-28"],
            "capabilities":{"tools":{}, "extensions":{"io.modelcontextprotocol/tasks":{}}},
            "ttlMs":0, "cacheScope":"private",
            "_meta":{"io.modelcontextprotocol/serverInfo":{"name":"task-input-peer","version":"1"}}
        })
    }

    fn inputs() -> Value {
        json!({
            "a-roots":{"method":"roots/list"},
            "b-sampling":{"method":"sampling/createMessage","params":{
                "messages":[{"role":"user","content":{"type":"text","text":"hello"}}],
                "maxTokens":16, "includeContext":"allServers"
            }},
            "c-form":{"method":"elicitation/create","params":{
                "mode":"form", "message":"approve",
                "requestedSchema":{"type":"object",
                    "properties":{"answer":{"type":"string"}}, "required":["answer"]}
            }}
        })
    }

    fn answers() -> Value {
        json!({
            "a-roots":{"roots":[]},
            "b-sampling":{"role":"assistant","model":"fixture",
                "content":{"type":"text","text":"sampled"}},
            "c-form":{"action":"accept","content":{"answer":"approved"}}
        })
    }

    fn snapshot(input_requests: Value) -> Value {
        json!({
            "resultType":"complete", "taskId":"task-1", "status":"input_required",
            "createdAt":"2026-07-28T12:00:00Z", "lastUpdatedAt":"2026-07-28T12:00:00Z",
            "ttlMs":null, "inputRequests":input_requests
        })
    }

    fn completed() -> Value {
        json!({
            "resultType":"complete", "taskId":"task-1", "status":"completed",
            "createdAt":"2026-07-28T12:00:00Z", "lastUpdatedAt":"2026-07-28T12:00:01Z",
            "ttlMs":null, "result":{"content":[], "futureResult":{"kept":true}}
        })
    }

    fn catalog() -> Value {
        json!({"resultType":"complete", "tools":[], "ttlMs":0, "cacheScope":"private"})
    }

    fn handlers(
        calls: &Arc<AtomicUsize>,
        owners: &Arc<Mutex<Vec<ReverseRequestCancellation>>>,
    ) -> ReverseRequestHandlers {
        let roots_called = Arc::clone(calls);
        let roots_owned = Arc::clone(owners);
        let sampling_called = Arc::clone(calls);
        let sampling_owned = Arc::clone(owners);
        let form_called = Arc::clone(calls);
        let form_owned = Arc::clone(owners);
        ReverseRequestHandlers::new()
            .with_modern_roots_list(move |_, local, _| {
                roots_called.fetch_add(1, Ordering::SeqCst);
                roots_owned.lock().unwrap().push(local);
                Box::pin(async { Ok(crate::FinalEmbeddedRootsListResult { roots: vec![] }) })
            })
            .with_modern_sampling_create_message(move |_, local, parameters| {
                assert!(parameters.include_context.is_none());
                sampling_called.fetch_add(1, Ordering::SeqCst);
                sampling_owned.lock().unwrap().push(local);
                let answer: crate::FinalCreateMessageResult = serde_json::from_value(json!({
                    "role":"assistant", "model":"fixture",
                    "content":{"type":"text","text":"sampled"}
                }))
                .unwrap();
                Box::pin(async move { Ok(answer) })
            })
            .with_modern_elicitation_create(move |_, local, _| {
                form_called.fetch_add(1, Ordering::SeqCst);
                form_owned.lock().unwrap().push(local);
                let answer: crate::ElicitResult = serde_json::from_value(json!({
                    "action":"accept", "content":{"answer":"approved"}
                }))
                .unwrap();
                Box::pin(async move { Ok(answer) })
            })
    }

    struct PendingRoots {
        cancellation: ReverseRequestCancellation,
        drops: Arc<AtomicUsize>,
    }

    impl Future for PendingRoots {
        type Output = McpResult<crate::FinalEmbeddedRootsListResult>;

        fn poll(self: std::pin::Pin<&mut Self>, _: &mut std::task::Context<'_>) -> Poll<Self::Output> {
            Poll::Pending
        }
    }

    impl Drop for PendingRoots {
        fn drop(&mut self) {
            assert!(self.cancellation.is_cancel_requested());
            self.drops.fetch_add(1, Ordering::SeqCst);
        }
    }

    fn pending_roots(calls: &Arc<AtomicUsize>, drops: &Arc<AtomicUsize>) -> ReverseRequestHandlers {
        let calls = Arc::clone(calls);
        let drops = Arc::clone(drops);
        ReverseRequestHandlers::new().with_modern_roots_list(move |_, cancellation, _| {
            calls.fetch_add(1, Ordering::SeqCst);
            Box::pin(PendingRoots {
                cancellation,
                drops: Arc::clone(&drops),
            })
        })
    }

    #[cfg(unix)]
    mod http {
        use super::*;
        use asupersync::runtime::{RuntimeBuilder, reactor::create_reactor};
        use std::io::{Read, Write};
        use std::net::{TcpListener, TcpStream};

        fn run(operation: impl Future<Output = ()>) {
            RuntimeBuilder::current_thread()
                .with_reactor(create_reactor().unwrap())
                .build()
                .unwrap()
                .block_on(operation);
        }

        fn accept(listener: &TcpListener) -> TcpStream {
            let deadline = Instant::now() + Duration::from_secs(5);
            loop {
                match listener.accept() {
                    Ok((stream, _)) => {
                        stream.set_nonblocking(false).unwrap();
                        stream.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
                        stream.set_write_timeout(Some(Duration::from_secs(3))).unwrap();
                        return stream;
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        assert!(Instant::now() < deadline, "missing expected Task request");
                        std::thread::sleep(Duration::from_millis(1));
                    }
                    Err(error) => panic!("Task peer accept: {error}"),
                }
            }
        }

        fn read(stream: &mut TcpStream) -> Value {
            let mut bytes = Vec::new();
            let mut buffer = [0_u8; 4096];
            let end = loop {
                let count = stream.read(&mut buffer).unwrap();
                assert!(count > 0, "request ended before its headers");
                bytes.extend_from_slice(&buffer[..count]);
                assert!(bytes.len() <= 128 * 1024);
                if let Some(index) = bytes.windows(4).position(|part| part == b"\r\n\r\n") {
                    break index + 4;
                }
            };
            let length = std::str::from_utf8(&bytes[..end])
                .unwrap()
                .lines()
                .find_map(|line| {
                    let (name, value) = line.split_once(':')?;
                    name.eq_ignore_ascii_case("content-length")
                        .then(|| value.trim().parse::<usize>().unwrap())
                })
                .unwrap();
            assert!(length <= 64 * 1024);
            while bytes.len() < end + length {
                let count = stream.read(&mut buffer).unwrap();
                assert!(count > 0, "request ended before its body");
                bytes.extend_from_slice(&buffer[..count]);
            }
            serde_json::from_slice(&bytes[end..end + length]).unwrap()
        }

        fn peer(
            replies: Vec<(&'static str, Option<Value>)>,
        ) -> (String, std::thread::JoinHandle<Vec<Value>>) {
            peer_with_update_cancellation(replies, None)
        }

        fn peer_with_update_cancellation(
            replies: Vec<(&'static str, Option<Value>)>,
            cancellation: Option<McpRequestCancellation>,
        ) -> (String, std::thread::JoinHandle<Vec<Value>>) {
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            listener.set_nonblocking(true).unwrap();
            let target = format!("http://{}/mcp", listener.local_addr().unwrap());
            let peer = std::thread::spawn(move || {
                let mut requests = Vec::new();
                for (index, (method, result)) in
                    std::iter::once(("server/discover", Some(discovery())))
                        .chain(replies)
                        .enumerate()
                {
                    let mut stream = accept(&listener);
                    let request = read(&mut stream);
                    assert_eq!(request["id"], index + 1);
                    assert_eq!(request["method"], method, "no implicit retry or Task cancellation");
                    if method.starts_with("tasks/") {
                        assert_eq!(request["params"]["taskId"], "task-1");
                    }
                    if method == "tasks/update" && result.is_none()
                        && let Some(cancellation) = &cancellation
                    {
                        cancellation.cancel();
                    }
                    if let Some(result) = result {
                        let body = serde_json::to_vec(&json!({
                            "jsonrpc":"2.0", "id":index + 1, "result":result
                        }))
                        .unwrap();
                        write!(stream,
                            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                            body.len(),
                        ).unwrap();
                        stream.write_all(&body).unwrap();
                        stream.flush().unwrap();
                    }
                    requests.push(request);
                    // None deliberately loses the ACK after a complete update.
                }
                requests
            });
            (target, peer)
        }

        async fn connect(cx: &Cx, target: &str, callbacks: ReverseRequestHandlers) -> HttpClient {
            ClientBuilder::new()
                .protocol_plan(ClientProtocolPlan::http(
                    ProtocolPolicy::ModernOnly,
                    Some(crate::CanonicalHttpUrl::parse(target).unwrap()),
                    None, None, "task-input-owner".into(), "task-input-trust".into(),
                    "native-http".into(), 0, 0, 0,
                ).unwrap())
                .reverse_request_handlers(callbacks)
                .request_timeout_policy(
                    RequestTimeoutPolicy::new(Duration::from_secs(2), Duration::from_secs(2)).unwrap(),
                )
                .connect_http_client_with_cx(cx)
                .await
                .unwrap()
        }

        #[test]
        fn public_http_task_inputs_resolve_all_kinds_then_reconcile_authoritatively() {
            let (target, peer) = peer(vec![
                ("tasks/get", Some(snapshot(inputs()))),
                ("tasks/update", Some(json!({"resultType":"complete"}))),
                ("tasks/get", Some(completed())),
                ("tools/list", Some(catalog())),
            ]);
            let calls = Arc::new(AtomicUsize::new(0));
            let owners = Arc::new(Mutex::new(Vec::new()));
            run(async {
                let cx = Cx::current().unwrap();
                let mut client = connect(&cx, &target, handlers(&calls, &owners)).await;
                client.resolve_task_inputs_final(&cx, id(), 3, INPUT_BYTES).await.unwrap();
                assert_eq!(calls.load(Ordering::SeqCst), 3);
                assert!(owners.lock().unwrap().iter().all(|owner| !owner.is_cancel_requested()));
                let handle = client.attach_final_task(&cx, id()).await.unwrap();
                assert!(matches!(handle.task(), FinalTask::Completed { .. }));
                assert_eq!(serde_json::to_value(handle.task()).unwrap()["result"]["futureResult"], json!({"kept":true}));
                client.list_tools(&cx, None).await.unwrap();
                assert!(cx.checkpoint().is_ok());
            });
            let requests = peer.join().unwrap();
            assert_eq!(requests[2]["params"]["inputResponses"], answers());
            assert_eq!(calls.load(Ordering::SeqCst), 3);
        }

        #[test]
        fn public_http_task_inputs_admit_entire_batch_before_host_effects() {
            for case in ["missing-handler", "sampling-tools", "count", "bytes", "expired", "terminal"] {
                let mut initial = snapshot(inputs());
                if case == "sampling-tools" {
                    initial["inputRequests"]["b-sampling"]["params"]["toolChoice"] = json!({"mode":"auto"});
                } else if case == "expired" {
                    initial["createdAt"] = json!("1970-01-01T00:00:00Z");
                    initial["ttlMs"] = json!(1);
                } else if case == "terminal" {
                    initial = completed();
                }
                let (target, peer) = peer(vec![
                    ("tasks/get", Some(initial)), ("tools/list", Some(catalog())),
                ]);
                let calls = Arc::new(AtomicUsize::new(0));
                let owners = Arc::new(Mutex::new(Vec::new()));
                run(async {
                    let cx = Cx::current().unwrap();
                    let mut callbacks = handlers(&calls, &owners);
                    if case == "missing-handler" {
                        callbacks.modern_elicitation_create = None;
                    }
                    let mut client = connect(&cx, &target, callbacks).await;
                    let result = client.resolve_task_inputs_final(
                        &cx, id(), if case == "count" { 2 } else { 3 },
                        if case == "bytes" { 1 } else { INPUT_BYTES },
                    ).await;
                    assert!(result.is_err(), "{case}");
                    assert_eq!(calls.load(Ordering::SeqCst), 0, "{case}");
                    assert!(owners.lock().unwrap().is_empty());
                    client.list_tools(&cx, None).await.unwrap();
                });
                assert_eq!(peer.join().unwrap().len(), 3);
            }
        }

        #[test]
        fn public_http_task_input_limits_and_precancellation_spend_no_request_id() {
            let (target, peer) = peer(vec![("tools/list", Some(catalog()))]);
            run(async {
                let cx = Cx::current().unwrap();
                let mut client = connect(&cx, &target, ReverseRequestHandlers::new()).await;
                for (count, bytes) in [(0, 1), (1, 0), (MAX_TASK_INPUT_MAP_ENTRIES + 1, 1), (1, MAX_TASK_RESPONSE_BYTES + 1)] {
                    let error = client.resolve_task_inputs_final(&cx, id(), count, bytes).await.unwrap_err();
                    assert!(matches!(error, HttpClientError::CoreResult(error) if error.code == McpErrorCode::InvalidParams));
                }
                let cancellation = McpRequestCancellation::new();
                cancellation.cancel();
                let error = client.resolve_task_inputs_final_with_cancellation(&cx, &cancellation, id(), 1, INPUT_BYTES).await.unwrap_err();
                assert!(matches!(error, HttpClientError::CoreResult(error) if error.code == McpErrorCode::RequestCancelled));
                client.list_tools(&cx, None).await.unwrap();
            });
            assert_eq!(peer.join().unwrap().len(), 2);
        }

        #[test]
        fn public_http_task_input_abandonment_cancels_pending_callbacks_before_drop() {
            for finish in ["cancel", "drop", "deadline"] {
                let (target, peer) = peer(vec![
                    ("tasks/get", Some(snapshot(json!({"roots":{"method":"roots/list"}})))),
                    ("tools/list", Some(catalog())),
                ]);
                let calls = Arc::new(AtomicUsize::new(0));
                let drops = Arc::new(AtomicUsize::new(0));
                run(async {
                    let cx = Cx::current().unwrap();
                    let mut client = connect(&cx, &target, pending_roots(&calls, &drops)).await;
                    if finish == "deadline" {
                        client.request_timeout_policy = RequestTimeoutPolicy::new(Duration::from_millis(200), Duration::from_millis(200)).unwrap();
                    }
                    let cancellation = McpRequestCancellation::new();
                    let mut operation = Box::pin(client.resolve_task_inputs_final_with_cancellation(&cx, &cancellation, id(), 1, INPUT_BYTES));
                    let started_by = Instant::now() + Duration::from_secs(2);
                    poll_fn(|task| {
                        assert!(Instant::now() < started_by);
                        assert!(operation.as_mut().poll(task).is_pending());
                        if calls.load(Ordering::SeqCst) == 1 { Poll::Ready(()) } else { Poll::Pending }
                    }).await;
                    if finish == "cancel" {
                        cancellation.cancel();
                        assert!(operation.as_mut().await.is_err());
                    } else if finish == "deadline" {
                        assert!(operation.as_mut().await.is_err());
                    }
                    drop(operation);
                    assert_eq!(calls.load(Ordering::SeqCst), 1);
                    assert_eq!(drops.load(Ordering::SeqCst), 1);
                    assert!(cx.checkpoint().is_ok());
                    client.list_tools(&cx, None).await.unwrap();
                });
                assert_eq!(peer.join().unwrap().len(), 3);
            }
        }

        #[test]
        fn public_http_task_input_unknown_update_is_never_replayed() {
            for cancelled in [false, true] {
                let cancellation = McpRequestCancellation::new();
                let (target, peer) = peer_with_update_cancellation(vec![
                    ("tasks/get", Some(snapshot(inputs()))),
                    ("tasks/update", None),
                    ("tasks/get", Some(completed())),
                    ("tools/list", Some(catalog())),
                ], cancelled.then(|| cancellation.clone()));
                let calls = Arc::new(AtomicUsize::new(0));
                let owners = Arc::new(Mutex::new(Vec::new()));
                run(async {
                    let cx = Cx::current().unwrap();
                    let mut client = connect(&cx, &target, handlers(&calls, &owners)).await;
                    assert!(client.resolve_task_inputs_final_with_cancellation(&cx, &cancellation, id(), 3, INPUT_BYTES).await.is_err());
                    assert_eq!(calls.load(Ordering::SeqCst), 3);
                    assert!(owners.lock().unwrap().iter().all(ReverseRequestCancellation::is_cancel_requested));
                    assert!(cx.checkpoint().is_ok());
                    let handle = client.attach_final_task(&cx, id()).await.unwrap();
                    assert!(matches!(handle.task(), FinalTask::Completed { .. }));
                    assert_eq!(calls.load(Ordering::SeqCst), 3);
                    client.list_tools(&cx, None).await.unwrap();
                });
                let requests = peer.join().unwrap();
                assert_eq!(requests[2]["params"]["inputResponses"], answers());
                assert_eq!(requests.len(), 5);
            }
        }
    }

    #[cfg(unix)]
    mod stdio {
        use super::*;

        fn exchange(id: u64, method: &str, result: Value) -> String {
            let response = json!({"jsonrpc":"2.0", "id":id, "result":result});
            format!(r#"
IFS= read -r request || exit 81
case "$request" in *'"id":{id}'*) ;; *) exit 82 ;; esac
case "$request" in *'"method":"{method}"'*) ;; *) exit 83 ;; esac
printf '%s\n' '{response}'
"#)
        }

        async fn connect(cx: &Cx, script: &str, callbacks: ReverseRequestHandlers) -> Client {
            ClientBuilder::new()
                .protocol_plan(ClientProtocolPlan::stdio(ProtocolPolicy::ModernOnly))
                .reverse_request_handlers(callbacks)
                .request_timeout_policy(RequestTimeoutPolicy::new(Duration::from_secs(2), Duration::from_secs(2)).unwrap())
                .connect_stdio_with_cx(cx, "sh", &["-c", script])
                .await
                .unwrap()
        }

        #[test]
        fn public_stdio_task_inputs_resolve_all_kinds_then_reconcile_authoritatively() {
            asupersync::runtime::RuntimeBuilder::current_thread().build().unwrap().block_on(async {
                let cx = Cx::current().unwrap();
                let mut script = exchange(1, "server/discover", discovery());
                script.push_str(&exchange(2, "tasks/get", snapshot(inputs())));
                script.push_str(&exchange(3, "tasks/update", json!({"resultType":"complete"})));
                script.push_str(&format!(r#"
case "$request" in *'"taskId":"task-1"'*) ;; *) exit 84 ;; esac
case "$request" in *'"inputResponses":{}'*) ;; *) exit 85 ;; esac
"#, answers()));
                script.push_str(&exchange(4, "tasks/get", completed()));
                script.push_str(&exchange(5, "tasks/get", completed()));
                script.push_str("exec sleep 10\n");
                let calls = Arc::new(AtomicUsize::new(0));
                let owners = Arc::new(Mutex::new(Vec::new()));
                let mut client = connect(&cx, &script, handlers(&calls, &owners)).await;
                client.resolve_task_inputs_final(&cx, id(), 3, INPUT_BYTES).await.unwrap();
                assert_eq!(calls.load(Ordering::SeqCst), 3);
                assert!(owners.lock().unwrap().iter().all(|owner| !owner.is_cancel_requested()));
                let current = client.get_task_final_with_cx(&cx, &McpRequestCancellation::new(), id()).await.unwrap();
                assert!(matches!(current.task, FinalTask::Completed { .. }));
                assert_eq!(serde_json::to_value(current.task).unwrap()["result"]["futureResult"], json!({"kept":true}));
                client.get_task_final_with_cx(&cx, &McpRequestCancellation::new(), id()).await.unwrap();
                client.close_with_cx(&cx).await.unwrap();
                assert_eq!(calls.load(Ordering::SeqCst), 3);
                assert!(cx.checkpoint().is_ok());
            });
        }

        #[test]
        fn public_stdio_task_input_rejection_and_callback_cancellation_send_no_update() {
            for cancel_callback in [false, true] {
                asupersync::runtime::RuntimeBuilder::current_thread().build().unwrap().block_on(async {
                    let cx = Cx::current().unwrap();
                    let cancellation = McpRequestCancellation::new();
                    let signal = cancellation.clone();
                    let calls = Arc::new(AtomicUsize::new(0));
                    let counted = Arc::clone(&calls);
                    let owners = Arc::new(Mutex::new(Vec::new()));
                    let retained = Arc::clone(&owners);
                    let callbacks = ReverseRequestHandlers::new().with_modern_roots_list(move |_, local, _| {
                        counted.fetch_add(1, Ordering::SeqCst);
                        retained.lock().unwrap().push(local);
                        signal.cancel();
                        Box::pin(async { Ok(crate::FinalEmbeddedRootsListResult { roots: vec![] }) })
                    });
                    let input = if cancel_callback {
                        json!({"roots":{"method":"roots/list"}})
                    } else {
                        inputs()
                    };
                    let script = format!("{}{}{}exec sleep 10\n",
                        exchange(1, "server/discover", discovery()),
                        exchange(2, "tasks/get", snapshot(input)),
                        exchange(3, "tasks/get", completed()),
                    );
                    let mut client = connect(&cx, &script, callbacks).await;
                    let error = client.resolve_task_inputs_final_with_cancellation(&cx, &cancellation, id(), 3, INPUT_BYTES).await.unwrap_err();
                    assert_eq!(calls.load(Ordering::SeqCst), usize::from(cancel_callback));
                    if cancel_callback {
                        assert_eq!(error.code, McpErrorCode::RequestCancelled);
                        assert!(owners.lock().unwrap().iter().all(ReverseRequestCancellation::is_cancel_requested));
                    }
                    client.get_task_final_with_cx(&cx, &McpRequestCancellation::new(), id()).await.unwrap();
                    client.close_with_cx(&cx).await.unwrap();
                    assert!(cx.checkpoint().is_ok());
                });
            }
        }
    }

    #[cfg(feature = "websocket-experimental")]
    mod websocket {
        use super::*;
        use asupersync::io::AsyncWriteExt;
        use asupersync::net::tcp::VirtualTcpStream;
        use asupersync::test_utils::run_test;
        use fastmcp_protocol::JsonRpcMessage;
        use fastmcp_transport::TransportError;
        use fastmcp_transport::websocket::AsyncWsServerTransport;

        async fn frame(peer: &mut VirtualTcpStream, id: u64, result: Value) {
            let source = json!({"jsonrpc":"2.0", "id":id, "result":result}).to_string();
            let payload = source.as_bytes();
            let mut encoded = vec![0x81];
            if payload.len() <= 125 {
                encoded.push(u8::try_from(payload.len()).unwrap());
            } else {
                encoded.push(126);
                encoded.extend_from_slice(&u16::try_from(payload.len()).unwrap().to_be_bytes());
            }
            encoded.extend_from_slice(payload);
            peer.write_all(&encoded).await.unwrap();
        }

        async fn connect(
            cx: &Cx,
            initial: Value,
            callbacks: ReverseRequestHandlers,
        ) -> (WebSocketClient<VirtualTcpStream>, VirtualTcpStream) {
            let (client, mut peer) = VirtualTcpStream::pair(
                "127.0.0.1:45141".parse().unwrap(),
                "127.0.0.1:45142".parse().unwrap(),
            );
            frame(&mut peer, 1, discovery()).await;
            frame(&mut peer, 2, initial).await;
            let client = ClientBuilder::new()
                .protocol_plan(ClientProtocolPlan::websocket(ProtocolPolicy::ModernOnly))
                .reverse_request_handlers(callbacks)
                .request_timeout_policy(RequestTimeoutPolicy::new(Duration::from_secs(2), Duration::from_secs(2)).unwrap())
                .connect_websocket_with_cx(cx, crate::AsyncWsClientTransport::from_upgraded(client))
                .await
                .unwrap();
            (client, peer)
        }

        async fn trace(cx: &Cx, peer: VirtualTcpStream, methods: &[&str]) -> Vec<Value> {
            let mut server = AsyncWsServerTransport::from_upgraded(peer);
            let mut requests = Vec::new();
            for (index, method) in methods.iter().enumerate() {
                let JsonRpcMessage::Request(request) = server.recv(cx).await.unwrap() else {
                    panic!("expected only Task requests and the catalog sentinel");
                };
                assert_eq!(request.method.as_str(), *method);
                assert_eq!(request.id, Some(RequestId::Number(i64::try_from(index + 1).unwrap())));
                requests.push(serde_json::to_value(request).unwrap());
            }
            assert!(matches!(server.recv(cx).await, Err(TransportError::Closed)), "no update replay or remote Task cancellation");
            requests
        }

        #[test]
        fn public_websocket_task_inputs_resolve_all_kinds_then_reconcile_authoritatively() {
            run_test(|| async {
                let cx = Cx::current().unwrap();
                let calls = Arc::new(AtomicUsize::new(0));
                let owners = Arc::new(Mutex::new(Vec::new()));
                let (mut client, mut peer) = connect(&cx, snapshot(inputs()), handlers(&calls, &owners)).await;
                frame(&mut peer, 3, json!({"resultType":"complete"})).await;
                frame(&mut peer, 4, completed()).await;
                frame(&mut peer, 5, catalog()).await;
                client.resolve_task_inputs_final(&cx, id(), 3, INPUT_BYTES).await.unwrap();
                assert_eq!(calls.load(Ordering::SeqCst), 3);
                assert!(owners.lock().unwrap().iter().all(|owner| !owner.is_cancel_requested()));
                let current = client.get_task_final(&cx, id()).await.unwrap();
                assert!(matches!(current.task, FinalTask::Completed { .. }));
                client.list_tools(&cx, None).await.unwrap();
                client.close(&cx).await.unwrap();
                let requests = trace(&cx, peer, &["server/discover", "tasks/get", "tasks/update", "tasks/get", "tools/list"]).await;
                assert_eq!(requests[2]["params"]["inputResponses"], answers());
                assert_eq!(calls.load(Ordering::SeqCst), 3);
            });
        }

        #[test]
        fn public_websocket_task_inputs_refuse_unadvertised_later_input_before_callbacks() {
            run_test(|| async {
                let cx = Cx::current().unwrap();
                let calls = Arc::new(AtomicUsize::new(0));
                let owners = Arc::new(Mutex::new(Vec::new()));
                let mut input = inputs();
                input["b-sampling"]["params"]["toolChoice"] = json!({"mode":"auto"});
                let (mut client, mut peer) = connect(&cx, snapshot(input), handlers(&calls, &owners)).await;
                frame(&mut peer, 3, catalog()).await;
                assert!(client.resolve_task_inputs_final(&cx, id(), 3, INPUT_BYTES).await.is_err());
                assert_eq!(calls.load(Ordering::SeqCst), 0);
                client.list_tools(&cx, None).await.unwrap();
                client.close(&cx).await.unwrap();
                trace(&cx, peer, &["server/discover", "tasks/get", "tools/list"]).await;
            });
        }

        #[test]
        fn public_websocket_task_input_cancellation_and_drop_dispose_local_callbacks() {
            for cancelled in [false, true] {
                run_test(|| async move {
                    let cx = Cx::current().unwrap();
                    let calls = Arc::new(AtomicUsize::new(0));
                    let drops = Arc::new(AtomicUsize::new(0));
                    let (mut client, mut peer) = connect(
                        &cx, snapshot(json!({"roots":{"method":"roots/list"}})), pending_roots(&calls, &drops),
                    ).await;
                    frame(&mut peer, 3, catalog()).await;
                    let cancellation = McpRequestCancellation::new();
                    let mut operation = Box::pin(client.resolve_task_inputs_final_with_cancellation(&cx, &cancellation, id(), 1, INPUT_BYTES));
                    poll_fn(|task| {
                        assert!(operation.as_mut().poll(task).is_pending());
                        if calls.load(Ordering::SeqCst) == 1 { Poll::Ready(()) } else { Poll::Pending }
                    }).await;
                    if cancelled {
                        cancellation.cancel();
                        let error = operation.as_mut().await.unwrap_err();
                        assert_eq!(error.code, McpErrorCode::RequestCancelled);
                    }
                    drop(operation);
                    assert_eq!(calls.load(Ordering::SeqCst), 1);
                    assert_eq!(drops.load(Ordering::SeqCst), 1);
                    assert!(cx.checkpoint().is_ok());
                    client.list_tools(&cx, None).await.unwrap();
                    client.close(&cx).await.unwrap();
                    trace(&cx, peer, &["server/discover", "tasks/get", "tools/list"]).await;
                });
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::task::{Context, Waker};

    use crate::{FinalEmbeddedRootsListResult, FinalGetTaskResult};
    use serde_json::json;

    fn task(inputs: Value) -> FinalTask {
        serde_json::from_str::<FinalGetTaskResult>(&json!({
            "resultType":"complete", "taskId":"task-1", "status":"input_required",
            "createdAt":"2026-07-28T12:00:00Z", "lastUpdatedAt":"2026-07-28T12:00:00Z",
            "ttlMs":null, "inputRequests":inputs
        }).to_string())
        .unwrap()
        .task
    }

    fn roots() -> ReverseRequestHandlers {
        ReverseRequestHandlers::new().with_modern_roots_list(|_, _, _| {
            Box::pin(async { Ok(FinalEmbeddedRootsListResult { roots: vec![] }) })
        })
    }

    #[test]
    fn local_limits_are_finite_and_not_clamped() {
        assert!(admit_limits(1, 1).is_ok());
        assert!(admit_limits(MAX_TASK_INPUT_MAP_ENTRIES, MAX_TASK_RESPONSE_BYTES).is_ok());
        for (count, bytes) in [
            (0, 1),
            (1, 0),
            (MAX_TASK_INPUT_MAP_ENTRIES + 1, 1),
            (1, MAX_TASK_RESPONSE_BYTES + 1),
            (usize::MAX, usize::MAX),
        ] {
            assert!(matches!(
                admit_limits(count, bytes),
                Err(ManagedHttpClientError::InvalidPolicy)
            ));
        }
    }

    #[test]
    fn entire_input_batch_requires_both_handler_and_advertised_capability() {
        let task = task(json!({"roots":{"method":"roots/list"}}));
        let original = serde_json::to_value(&task).unwrap();
        assert!(prepare_inputs(&task, &roots(), &json!({"roots":{}}), 1, 4096).is_ok());
        assert!(prepare_inputs(&task, &roots(), &json!({}), 1, 4096).is_err());
        assert!(prepare_inputs(
            &task,
            &ReverseRequestHandlers::new(),
            &json!({"roots":{}}),
            1,
            4096,
        )
        .is_err());
        assert_eq!(serde_json::to_value(&task).unwrap(), original);
    }

    #[test]
    fn mixed_batch_cannot_admit_an_unsupported_later_input() {
        let task = task(json!({
            "a-roots":{"method":"roots/list"},
            "z-form":{"method":"elicitation/create","params":{
                "mode":"form", "message":"approve", "requestedSchema":{"type":"object"}
            }}
        }));
        assert!(prepare_inputs(
            &task,
            &roots(),
            &json!({"roots":{}, "elicitation":{"form":{}}}),
            2,
            4096,
        )
        .is_err());
    }

    #[test]
    fn descriptor_limit_is_checked_before_any_answer_is_retained() {
        let task = task(json!({"one":{"method":"roots/list"},"two":{"method":"roots/list"}}));
        assert!(prepare_inputs(&task, &roots(), &json!({"roots":{}}), 1, 4096).is_err());
        assert!(prepare_inputs(&task, &roots(), &json!({"roots":{}}), 2, 1).is_err());
        assert!(prepare_inputs(&task, &roots(), &json!({"roots":{}}), 2, 4096).is_ok());
    }

    #[test]
    fn keyed_answer_bytes_include_escaping_and_failed_charge_is_atomic() {
        let value = ("key-\"-雪", json!({"roots":[]}));
        let bytes = serde_json::to_vec(&value).unwrap().len();
        let mut exact = PayloadBudget(bytes);
        exact.charge(&value).unwrap();
        assert_eq!(exact.0, 0);
        let mut short = PayloadBudget(bytes - 1);
        assert!(short.charge(&value).is_err());
        assert_eq!(short.0, bytes - 1);
    }

    #[test]
    fn ready_callback_cancellation_withholds_the_answer() {
        let cx = Cx::for_testing();
        let cancellation = McpRequestCancellation::new();
        let signal = cancellation.clone();
        let calls = Arc::new(AtomicUsize::new(0));
        let counted = Arc::clone(&calls);
        let handlers = ReverseRequestHandlers::new().with_modern_roots_list(move |_, _, _| {
            counted.fetch_add(1, Ordering::SeqCst);
            signal.cancel();
            Box::pin(async { Ok(FinalEmbeddedRootsListResult { roots: vec![] }) })
        });
        let request = serde_json::from_value(json!({"method":"roots/list"})).unwrap();
        let snapshot = task(json!({"one":{"method":"roots/list"}}));
        let retention = InputRetention::new(&cx, &snapshot).unwrap();
        let mut future = Box::pin(resolve_one(
            &cx,
            &cancellation,
            &retention,
            &handlers,
            "one",
            request,
        ));
        assert!(matches!(
            future
                .as_mut()
                .poll(&mut Context::from_waker(Waker::noop())),
            Poll::Ready(Err(_))
        ));
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        assert!(cx.checkpoint().is_ok());
    }

    #[test]
    fn callback_panic_is_a_sanitized_failure_not_an_update_answer() {
        let cx = Cx::for_testing();
        let cancellation = McpRequestCancellation::new();
        let handlers = ReverseRequestHandlers::new()
            .with_modern_roots_list(|_, _, _| panic!("private-handler-payload"));
        let request = serde_json::from_value(json!({"method":"roots/list"})).unwrap();
        let snapshot = task(json!({"one":{"method":"roots/list"}}));
        let retention = InputRetention::new(&cx, &snapshot).unwrap();
        let mut future = Box::pin(resolve_one(
            &cx,
            &cancellation,
            &retention,
            &handlers,
            "one",
            request,
        ));
        let Poll::Ready(Err(error)) = future
            .as_mut()
            .poll(&mut Context::from_waker(Waker::noop()))
        else {
            panic!("callback panic must settle as an error");
        };
        assert!(!error.message.contains("private-handler-payload"));
        assert!(cx.checkpoint().is_ok());
    }

    fn root_inputs(keys: &[&str]) -> TaskInputRequests {
        keys.iter()
            .map(|key| {
                (
                    (*key).to_owned(),
                    serde_json::from_value(json!({"method":"roots/list"})).unwrap(),
                )
            })
            .collect()
    }

    struct WakeCount(AtomicUsize);

    impl std::task::Wake for WakeCount {
        fn wake(self: Arc<Self>) {
            self.wake_by_ref();
        }

        fn wake_by_ref(self: &Arc<Self>) {
            self.0.fetch_add(1, Ordering::SeqCst);
        }
    }

    struct PendingInput {
        cancellation: ReverseRequestCancellation,
        drops: Arc<AtomicUsize>,
    }

    impl Future for PendingInput {
        type Output = McpResult<FinalEmbeddedRootsListResult>;

        fn poll(self: std::pin::Pin<&mut Self>, _: &mut Context<'_>) -> Poll<Self::Output> {
            Poll::Pending
        }
    }

    impl Drop for PendingInput {
        fn drop(&mut self) {
            assert!(
                self.cancellation.is_cancel_requested(),
                "the callback owner must cancel before dropping its pending future"
            );
            self.drops.fetch_add(1, Ordering::SeqCst);
        }
    }

    #[test]
    fn pending_input_cannot_borrow_an_unrelated_ambient_timer() {
        let runtime = asupersync::runtime::RuntimeBuilder::current_thread()
            .blocking_threads(0, 0)
            .build()
            .unwrap();
        let ambient = runtime.request_cx_with_budget(asupersync::Budget::INFINITE);
        let cx = Cx::for_testing();
        assert!(ambient.timer_driver().is_some());
        assert!(cx.timer_driver().is_none());
        let cancellation = McpRequestCancellation::new();
        let drops = Arc::new(AtomicUsize::new(0));
        let disposed = Arc::clone(&drops);
        let handlers = ReverseRequestHandlers::new().with_modern_roots_list(move |_, local, _| {
            Box::pin(PendingInput {
                cancellation: local,
                drops: Arc::clone(&disposed),
            })
        });
        let snapshot = task(json!({"one":{"method":"roots/list"}}));
        let retention = InputRetention::new(&cx, &snapshot).unwrap();
        let request = serde_json::from_value(json!({"method":"roots/list"})).unwrap();
        let mut future = Box::pin(resolve_one(
            &cx,
            &cancellation,
            &retention,
            &handlers,
            "one",
            request,
        ));
        let installed = Cx::set_current(Some(ambient.clone()));
        let Poll::Ready(Err(error)) = future
            .as_mut()
            .poll(&mut Context::from_waker(Waker::noop()))
        else {
            panic!("a pending callback must retain its own caller's timer authority");
        };
        assert_eq!(error.code, fastmcp_core::McpErrorCode::InternalError);
        assert_eq!(
            error.message,
            "MRTR callback wait requires caller timer driver"
        );
        drop(future);
        assert_eq!(drops.load(Ordering::SeqCst), 1);
        assert!(!cancellation.is_cancel_requested());
        assert!(cx.checkpoint().is_ok());
        assert!(ambient.checkpoint().is_ok());
        assert_eq!(Cx::current().unwrap().task_id(), ambient.task_id());
        drop(installed);
        drop(ambient);
        assert!(runtime.shutdown_timeout(std::time::Duration::from_secs(1)));
    }

    #[test]
    fn pending_first_input_does_not_block_its_sibling_and_replies_keep_their_keys() {
        use asupersync::channel::oneshot;
        use std::sync::Mutex;

        let runtime = asupersync::runtime::RuntimeBuilder::current_thread()
            .blocking_threads(0, 0)
            .build()
            .unwrap();
        let cx = runtime.request_cx_with_budget(asupersync::Budget::INFINITE);
        let cancellation = McpRequestCancellation::new();
        let (sender, receiver) = oneshot::channel::<()>();
        let sender = Mutex::new(Some(sender));
        let receiver = Mutex::new(Some(receiver));
        let calls = Arc::new(AtomicUsize::new(0));
        let called = Arc::clone(&calls);
        let handlers = ReverseRequestHandlers::new().with_modern_roots_list(move |cx, _, _| {
            let index = called.fetch_add(1, Ordering::SeqCst);
            assert!(index < 2, "a completed callback must not run twice");
            if index == 0 {
                let mut receiver = receiver.lock().unwrap().take().unwrap();
                Box::pin(async move {
                    receiver.recv(cx).await.unwrap();
                    Ok(serde_json::from_value(json!({
                        "roots":[{"uri":"file:///first"}]
                    }))
                    .unwrap())
                })
            } else {
                sender
                    .lock()
                    .unwrap()
                    .take()
                    .unwrap()
                    .send_blocking(())
                    .unwrap();
                Box::pin(async {
                    Ok(serde_json::from_value(json!({
                        "roots":[{"uri":"file:///second"}]
                    }))
                    .unwrap())
                })
            }
        });
        let mut budget = PayloadBudget(4096);
        let snapshot = task(serde_json::to_value(root_inputs(&["a", "b"])).unwrap());
        let retention = InputRetention::new(&cx, &snapshot).unwrap();
        let mut batch = Box::pin(resolve_batch(
            &cx,
            &cancellation,
            &retention,
            &handlers,
            root_inputs(&["a", "b"]),
            &mut budget,
        ));
        let wakes = Arc::new(WakeCount(AtomicUsize::new(0)));
        let waker = Waker::from(Arc::clone(&wakes));
        let mut context = Context::from_waker(&waker);
        assert!(batch.as_mut().poll(&mut context).is_pending());
        assert_eq!(calls.load(Ordering::SeqCst), 2);
        assert!(wakes.0.load(Ordering::SeqCst) > 0);
        let Poll::Ready(Ok((responses, owners))) = batch.as_mut().poll(&mut context) else {
            panic!("the later sibling must release the earlier input without external polling");
        };
        assert_eq!(
            serde_json::to_value(responses).unwrap(),
            json!({
                "a":{"roots":[{"uri":"file:///first"}]},
                "b":{"roots":[{"uri":"file:///second"}]}
            })
        );
        assert_eq!(owners.len(), 2);
        for owner in &owners {
            assert!(!owner.0.is_cancel_requested());
            owner.0.record_response_sent();
        }
        assert_eq!(calls.load(Ordering::SeqCst), 2);
        assert!(cx.checkpoint().is_ok());
        drop(batch);
        drop(cx);
        assert!(runtime.shutdown_timeout(std::time::Duration::from_secs(1)));
    }

    #[test]
    fn batch_failure_disposes_pending_and_completed_owners_without_starting_later_inputs() {
        use std::sync::Mutex;

        for failure in 0..3 {
            let runtime = asupersync::runtime::RuntimeBuilder::current_thread()
                .blocking_threads(0, 0)
                .build()
                .unwrap();
            let cx = runtime.request_cx_with_budget(asupersync::Budget::INFINITE);
            let cancellation = McpRequestCancellation::new();
            let tokens = Arc::new(Mutex::new(Vec::new()));
            let observed = Arc::clone(&tokens);
            let drops = Arc::new(AtomicUsize::new(0));
            let disposed = Arc::clone(&drops);
            let calls = Arc::new(AtomicUsize::new(0));
            let called = Arc::clone(&calls);
            let handlers =
                ReverseRequestHandlers::new().with_modern_roots_list(move |_, local, _| {
                    observed.lock().unwrap().push(local.clone());
                    match called.fetch_add(1, Ordering::SeqCst) {
                        0 => Box::pin(async { Ok(FinalEmbeddedRootsListResult { roots: vec![] }) }),
                        1 => Box::pin(PendingInput {
                            cancellation: local,
                            drops: Arc::clone(&disposed),
                        }),
                        2 => match failure {
                            0 => Box::pin(async { Err(McpError::invalid_params("host declined")) }),
                            1 => panic!("private-batch-panic"),
                            _ => Box::pin(async {
                                Ok(serde_json::from_value(json!({
                                    "roots":[{"uri":format!("file:///{}", "x".repeat(4096))}]
                                }))
                                .unwrap())
                            }),
                        },
                        _ => panic!("later callback ran after a terminal batch failure"),
                    }
                });
            let mut budget = PayloadBudget(1024);
            let snapshot = task(serde_json::to_value(root_inputs(&["a", "b", "c", "d"])).unwrap());
            let retention = InputRetention::new(&cx, &snapshot).unwrap();
            let mut batch = Box::pin(resolve_batch(
                &cx,
                &cancellation,
                &retention,
                &handlers,
                root_inputs(&["a", "b", "c", "d"]),
                &mut budget,
            ));
            let Poll::Ready(Err(error)) =
                batch.as_mut().poll(&mut Context::from_waker(Waker::noop()))
            else {
                panic!("one rejected input must terminate the whole batch");
            };
            assert!(!error.message.contains("private-batch-panic"));
            drop(batch);
            assert_eq!(calls.load(Ordering::SeqCst), 3);
            assert_eq!(drops.load(Ordering::SeqCst), 1);
            assert!(
                tokens
                    .lock()
                    .unwrap()
                    .iter()
                    .all(ReverseRequestCancellation::is_cancel_requested)
            );
            assert!(!cancellation.is_cancel_requested());
            assert!(cx.checkpoint().is_ok());
            drop(cx);
            assert!(runtime.shutdown_timeout(std::time::Duration::from_secs(1)));
        }
    }

    #[test]
    fn abandoning_a_parallel_batch_cancels_every_started_callback_before_disposal() {
        use std::sync::Mutex;

        let runtime = asupersync::runtime::RuntimeBuilder::current_thread()
            .blocking_threads(0, 0)
            .build()
            .unwrap();
        let cx = runtime.request_cx_with_budget(asupersync::Budget::INFINITE);
        let cancellation = McpRequestCancellation::new();
        let tokens = Arc::new(Mutex::new(Vec::new()));
        let observed = Arc::clone(&tokens);
        let drops = Arc::new(AtomicUsize::new(0));
        let disposed = Arc::clone(&drops);
        let handlers = ReverseRequestHandlers::new().with_modern_roots_list(move |_, local, _| {
            observed.lock().unwrap().push(local.clone());
            Box::pin(PendingInput {
                cancellation: local,
                drops: Arc::clone(&disposed),
            })
        });
        let mut budget = PayloadBudget(4096);
        let snapshot = task(serde_json::to_value(root_inputs(&["a", "b", "c"])).unwrap());
        let retention = InputRetention::new(&cx, &snapshot).unwrap();
        let mut batch = Box::pin(resolve_batch(
            &cx,
            &cancellation,
            &retention,
            &handlers,
            root_inputs(&["a", "b", "c"]),
            &mut budget,
        ));
        assert!(
            batch
                .as_mut()
                .poll(&mut Context::from_waker(Waker::noop()))
                .is_pending()
        );
        assert_eq!(tokens.lock().unwrap().len(), 3);
        assert_eq!(drops.load(Ordering::SeqCst), 0);
        drop(batch);
        assert_eq!(drops.load(Ordering::SeqCst), 3);
        assert!(
            tokens
                .lock()
                .unwrap()
                .iter()
                .all(ReverseRequestCancellation::is_cancel_requested)
        );
        assert!(!cancellation.is_cancel_requested());
        assert_eq!(budget.0, 4096);
        assert!(cx.checkpoint().is_ok());
        drop(cx);
        assert!(runtime.shutdown_timeout(std::time::Duration::from_secs(1)));
    }

    #[test]
    fn ready_sibling_cancellation_stops_other_inputs_in_the_same_poll() {
        use std::sync::Mutex;

        let runtime = asupersync::runtime::RuntimeBuilder::current_thread()
            .blocking_threads(0, 0)
            .build()
            .unwrap();
        let cx = runtime.request_cx_with_budget(asupersync::Budget::INFINITE);
        let cancellation = McpRequestCancellation::new();
        let cancel = cancellation.clone();
        let calls = Arc::new(AtomicUsize::new(0));
        let called = Arc::clone(&calls);
        let drops = Arc::new(AtomicUsize::new(0));
        let disposed = Arc::clone(&drops);
        let tokens = Arc::new(Mutex::new(Vec::new()));
        let observed = Arc::clone(&tokens);
        let handlers = ReverseRequestHandlers::new().with_modern_roots_list(move |_, local, _| {
            observed.lock().unwrap().push(local.clone());
            match called.fetch_add(1, Ordering::SeqCst) {
                0 => Box::pin(PendingInput {
                    cancellation: local,
                    drops: Arc::clone(&disposed),
                }),
                1 => {
                    cancel.cancel();
                    Box::pin(async { Ok(FinalEmbeddedRootsListResult { roots: vec![] }) })
                }
                _ => panic!("a cancelled batch must not construct another host callback"),
            }
        });
        let mut budget = PayloadBudget(4096);
        let snapshot = task(serde_json::to_value(root_inputs(&["a", "b", "c"])).unwrap());
        let retention = InputRetention::new(&cx, &snapshot).unwrap();
        let mut batch = Box::pin(resolve_batch(
            &cx,
            &cancellation,
            &retention,
            &handlers,
            root_inputs(&["a", "b", "c"]),
            &mut budget,
        ));
        assert!(matches!(
            batch.as_mut().poll(&mut Context::from_waker(Waker::noop())),
            Poll::Ready(Err(error))
                if error.code == fastmcp_core::McpErrorCode::RequestCancelled
        ));
        drop(batch);
        assert_eq!(calls.load(Ordering::SeqCst), 2);
        assert_eq!(drops.load(Ordering::SeqCst), 1);
        assert!(
            tokens
                .lock()
                .unwrap()
                .iter()
                .all(ReverseRequestCancellation::is_cancel_requested)
        );
        assert_eq!(budget.0, 4096);
        assert!(cx.checkpoint().is_ok());
        drop(cx);
        assert!(runtime.shutdown_timeout(std::time::Duration::from_secs(1)));
    }

    #[test]
    fn parallel_answers_share_one_exact_byte_budget() {
        let cx = Cx::for_testing();
        let cancellation = McpRequestCancellation::new();
        let response: FinalEmbeddedInputResponse =
            serde_json::from_value(json!({"roots":[]})).unwrap();
        let bytes: usize = ["a", "b", "c"]
            .iter()
            .map(|key| serde_json::to_vec(&(key, &response)).unwrap().len())
            .sum();
        let handlers = roots();
        let snapshot = task(serde_json::to_value(root_inputs(&["a", "b", "c"])).unwrap());
        let retention = InputRetention::new(&cx, &snapshot).unwrap();
        for exact in [false, true] {
            let mut budget = PayloadBudget(bytes - usize::from(!exact));
            let mut batch = Box::pin(resolve_batch(
                &cx,
                &cancellation,
                &retention,
                &handlers,
                root_inputs(&["a", "b", "c"]),
                &mut budget,
            ));
            let Poll::Ready(result) = batch.as_mut().poll(&mut Context::from_waker(Waker::noop()))
            else {
                panic!("all-ready inputs must settle in one poll");
            };
            assert_eq!(result.is_ok(), exact);
            if let Ok((responses, owners)) = result {
                assert_eq!(responses.len(), 3);
                assert_eq!(owners.len(), 3);
            }
            drop(batch);
            if exact {
                assert_eq!(budget.0, 0);
            }
        }
    }

    #[test]
    fn precancelled_batch_does_not_invoke_any_host_handler() {
        let cx = Cx::for_testing();
        let cancellation = McpRequestCancellation::new();
        cancellation.cancel();
        let handlers = ReverseRequestHandlers::new().with_modern_roots_list(|_, _, _| {
            panic!("precancelled input handler must never be invoked")
        });
        let mut budget = PayloadBudget(4096);
        let snapshot = task(serde_json::to_value(root_inputs(&["a", "b"])).unwrap());
        let retention = InputRetention::new(&cx, &snapshot).unwrap();
        let mut batch = Box::pin(resolve_batch(
            &cx,
            &cancellation,
            &retention,
            &handlers,
            root_inputs(&["a", "b"]),
            &mut budget,
        ));
        assert!(matches!(
            batch.as_mut().poll(&mut Context::from_waker(Waker::noop())),
            Poll::Ready(Err(_))
        ));
        drop(batch);
        assert_eq!(budget.0, 4096);
        assert!(cx.checkpoint().is_ok());
    }
}
