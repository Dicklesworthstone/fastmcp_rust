//! Explicit, negotiated Tasks operations over the existing memory executor.
//!
//! The official descriptor and local empty settings are frozen before discovery.
//! Ordinary core calls withhold Tasks; only an eligible tool execution retains
//! permission to return a Task. Lifecycle methods use the same immutable
//! extension receipt and exact response source as other extension requests.
//! These APIs do not create a runtime, persist handles, or retry creation.

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Instant;

use asupersync::Cx;
use fastmcp_core::{McpError, McpRequestCancellation, McpResult};
use fastmcp_protocol::extensions::{
    ClientExtensionDiscovery, ExtensionDescriptor, ExtensionDescriptorRegistry,
    ExtensionNegotiationError, ExtensionSettings, NegotiatedExtensionSet,
    official_tasks_empty_settings, register_official_tasks_extension,
};
use fastmcp_protocol::tasks_extension::{TASK_CANCEL, TASK_GET, TASK_UPDATE};
use fastmcp_protocol::{
    CoreResult, ExtensionId, FinalCoreResult, InputRequiredResult, ServerDiscoverResult,
};
use serde_json::Value;

use super::{
    MemoryClient, MemoryClientBuilder, MemoryExtensionEvent, MemoryRequestEvent,
    MemoryRequestExecution, checkpoint,
};
use crate::session::{ClientExtensionResultAdmission, ClientExtensionRuntime};
use crate::{
    FinalCancelTaskResult, FinalGetTaskResult, FinalTask, FinalTaskId, FinalTaskInputResponses,
    FinalToolCallOutcome, FinalUpdateTaskResult, MrtrInputResponses, MrtrResponderFuture,
    OperationMrtrResponder, RequestTimeoutPolicy, ReverseRequestHandlers, SyncMrtrResponderFn,
    mrtr_operation_deadline,
};

#[derive(Debug)]
pub(super) struct MemoryTaskRuntime {
    runtime: Arc<ClientExtensionRuntime>,
    extension_id: ExtensionId,
    negotiated: Option<NegotiatedExtensionSet>,
}

impl MemoryTaskRuntime {
    pub(super) fn new() -> McpResult<Self> {
        let mut descriptors = ExtensionDescriptorRegistry::new();
        let extension_id = register_official_tasks_extension(&mut descriptors).map_err(|_| {
            McpError::internal_error("Official memory Tasks descriptor could not be registered")
        })?;
        let discovery = ClientExtensionDiscovery {
            extensions: BTreeMap::from([(extension_id.clone(), official_tasks_empty_settings())]),
        };
        Ok(Self {
            runtime: Arc::new(ClientExtensionRuntime::new(descriptors, discovery, || {
                compatible_tasks_settings
            })?),
            extension_id,
            negotiated: None,
        })
    }

    pub(super) fn negotiate(&mut self, discovery: &ServerDiscoverResult) -> McpResult<()> {
        // The official descriptor checks both advertisements and the resolver's
        // effective settings are exactly empty objects, and rejects one-sided
        // support. A generic caller-supplied resolver cannot widen this policy.
        let negotiated = self.runtime.negotiate(discovery)?;
        self.runtime
            .admit_method(&negotiated, &self.extension_id, TASK_GET)?;
        self.negotiated = Some(negotiated);
        Ok(())
    }

    fn admit_request(&self, method: &str) -> McpResult<ClientExtensionResultAdmission> {
        let negotiated = self.negotiated.as_ref().ok_or_else(tasks_not_active)?;
        self.runtime
            .admit_request(negotiated, &self.extension_id, method)
    }
}

fn compatible_tasks_settings(
    descriptor: &ExtensionDescriptor,
    client: &ExtensionSettings,
    server: &ExtensionSettings,
) -> Result<ExtensionSettings, ExtensionNegotiationError> {
    if !client.as_object().is_empty() || !server.as_object().is_empty() {
        return Err(ExtensionNegotiationError::SettingsCompatibilityRejected(
            descriptor.id.to_string(),
        ));
    }
    Ok(official_tasks_empty_settings())
}

fn tasks_not_active() -> McpError {
    McpError::invalid_params("Memory Tasks requires explicit opt-in and successful negotiation")
}

fn tool_outcome(result: CoreResult) -> McpResult<FinalToolCallOutcome> {
    match result {
        CoreResult::Final(FinalCoreResult::ToolsCall { result, .. }) => {
            Ok(FinalToolCallOutcome::Complete(result))
        }
        CoreResult::Final(FinalCoreResult::ToolsCallTask { result }) => {
            Ok(FinalToolCallOutcome::Task(result))
        }
        CoreResult::Final(FinalCoreResult::ToolsCallInputRequired { result, .. }) => {
            Ok(FinalToolCallOutcome::InputRequired(result))
        }
        _ => Err(McpError::invalid_request(
            "Memory Tasks tool execution returned another method's result",
        )),
    }
}

impl MemoryClientBuilder {
    /// Selects the official Tasks extension before the first discovery request.
    ///
    /// Connection requires the peer's matching empty-settings advertisement.
    /// Custom extension registries remain independent and compose with this
    /// policy. Raw capabilities or a generic registration cannot replace it.
    /// Ordinary tool calls still withhold Tasks; use the explicit Tasks tool
    /// call surface to permit a Task outcome.
    #[must_use]
    pub fn with_tasks(mut self) -> Self {
        self.tasks_enabled = true;
        self
    }
}

impl MemoryClient {
    pub(crate) const fn task_input_timeout_policy(&self) -> RequestTimeoutPolicy {
        self.timeout_policy
    }

    pub(crate) fn task_input_context(&self) -> McpResult<(ReverseRequestHandlers, Value)> {
        self.ensure_open()?;
        self.require_tasks()?;
        let capabilities = serde_json::to_value(self.session.client_capabilities())
            .map_err(|_| McpError::invalid_params("Invalid Memory client capabilities"))?;
        Ok((self.reverse_request_handlers.clone(), capabilities))
    }

    /// Whether this open connection admitted the explicitly selected Tasks profile.
    #[must_use]
    pub fn tasks_active(&self) -> bool {
        !self.closed
            && self.executor.terminal_error().is_none()
            && self
                .tasks
                .as_ref()
                .is_some_and(|tasks| tasks.negotiated.is_some())
    }

    /// Starts one Task-capable tool call and returns its independently owned execution.
    ///
    /// The server may return an ordinary complete result, an input-required
    /// result, or a Task. No Task-preference parameter is sent. Use the ordinary
    /// `next_event` method to receive progress and the full typed result.
    /// Dropping the handle cancels this request; it does not imply cancellation
    /// of a Task already created by the server or authorize repeating the call.
    pub async fn execute_task_tool_call(
        &mut self,
        cx: &Cx,
        cancellation: &McpRequestCancellation,
        name: &str,
        arguments: Value,
    ) -> McpResult<MemoryRequestExecution> {
        self.execute_task_tool_call_with_timeout_policy(
            cx,
            cancellation,
            name,
            arguments,
            self.timeout_policy,
        )
        .await
    }

    /// Starts an eligible tool call with stricter bounded response deadlines.
    ///
    /// Both timers begin at committed publication. Rejection or cancellation
    /// while waiting for channel capacity publishes nothing and consumes no ID.
    pub async fn execute_task_tool_call_with_timeout_policy(
        &mut self,
        cx: &Cx,
        cancellation: &McpRequestCancellation,
        name: &str,
        arguments: Value,
        timeout_policy: RequestTimeoutPolicy,
    ) -> McpResult<MemoryRequestExecution> {
        self.ensure_open()?;
        checkpoint(cx, cancellation)?;
        self.require_tasks()?;
        self.execute_core_admitted(
            cx,
            cancellation,
            "tools/call",
            serde_json::json!({"name": name, "arguments": arguments}),
            timeout_policy,
            true,
        )
        .await
    }

    /// Completes one eligible call without projecting away its result family.
    ///
    /// A created Task is returned in full, including admitted metadata and
    /// nested result extras. This method performs no implicit polling, resume
    /// persistence, MRTR continuation, or retry after uncertain delivery.
    pub async fn call_tool_final_outcome(
        &mut self,
        cx: &Cx,
        cancellation: &McpRequestCancellation,
        name: &str,
        arguments: Value,
    ) -> McpResult<FinalToolCallOutcome> {
        let mut execution = self
            .execute_task_tool_call(cx, cancellation, name, arguments)
            .await?;
        loop {
            match self.next_event(cx, cancellation, &mut execution).await? {
                Some(MemoryRequestEvent::Notification(_)) => {}
                Some(MemoryRequestEvent::Result(result)) => {
                    return tool_outcome(*result);
                }
                None => {
                    return Err(McpError::internal_error(
                        "Memory Tasks tool execution ended without its result",
                    ));
                }
            }
        }
    }

    /// Calls a Tasks-capable tool and fulfills MRTR inputs with installed handlers.
    ///
    /// Unlike [`Self::call_tool_final_outcome`], this explicitly opts into the
    /// connection's modern sampling, roots, and elicitation handlers. Every
    /// continuation retains the original name, arguments, capabilities, Tasks
    /// negotiation, caller cancellation domain, and absolute operation deadline.
    /// Input batches and cumulative response/round limits are checked before
    /// host effects. Without installed handlers, input-required is returned.
    ///
    /// The server may complete normally or create a Task on any round. An
    /// admitted Task receipt wins simultaneous cancellation so accepted work
    /// remains identifiable; this method never polls, persists, or cancels that
    /// Task. A transport failure or uncertain send never repeats the call.
    pub async fn call_tool_final_outcome_with_handlers(
        &mut self,
        cx: &Cx,
        cancellation: &McpRequestCancellation,
        name: &str,
        arguments: Value,
    ) -> McpResult<FinalToolCallOutcome> {
        self.ensure_open()?;
        checkpoint(cx, cancellation)?;
        self.require_tasks()?;
        let responder: OperationMrtrResponder =
            OperationMrtrResponder::Installed(self.reverse_request_handlers.clone());
        if !responder.has_handler() {
            return self
                .call_tool_final_outcome(cx, cancellation, name, arguments)
                .await;
        }
        let deadline = mrtr_operation_deadline(cx, self.timeout_policy)?;
        self.follow_mrtr(
            cx,
            cancellation,
            deadline,
            "tools/call",
            serde_json::json!({"name": name, "arguments": arguments}),
            responder,
            true,
        )
        .await
        .and_then(tool_outcome)
    }

    /// Calls a Tasks-capable tool with a responder scoped to this MRTR operation.
    ///
    /// The explicit Tasks policy and successful bilateral negotiation are
    /// required before publication. Advertise the responder's capabilities in
    /// [`MemoryClientBuilder::capabilities`] before connecting. The complete
    /// input batch must be supported before `respond` runs, and its map must
    /// answer every requested key. State-only continuations use an empty map.
    /// Installed reverse handlers are not invoked by this method.
    ///
    /// The synchronous callback must return promptly. Cancellation and the
    /// earlier of `deadline` and the client's absolute timeout are checked
    /// before and after callbacks. Each continuation receives a fresh ID and
    /// preserves the original tool, arguments, and Tasks capability. Errors
    /// never cause retries. Complete results and Task receipts retain metadata
    /// and open members; the Task lifecycle remains under the caller's control.
    pub async fn call_tool_final_outcome_with_mrtr_retry<F>(
        &mut self,
        cx: &Cx,
        cancellation: &McpRequestCancellation,
        deadline: Instant,
        name: &str,
        arguments: Value,
        respond: F,
    ) -> McpResult<FinalToolCallOutcome>
    where
        F: FnMut(&InputRequiredResult) -> McpResult<MrtrInputResponses>,
    {
        self.ensure_open()?;
        checkpoint(cx, cancellation)?;
        self.require_tasks()?;
        self.follow_mrtr(
            cx,
            cancellation,
            deadline,
            "tools/call",
            serde_json::json!({"name": name, "arguments": arguments}),
            OperationMrtrResponder::<F>::Caller(respond),
            true,
        )
        .await
        .and_then(tool_outcome)
    }

    /// Calls a Tasks-capable tool with a caller-owned asynchronous input responder.
    ///
    /// This preserves the bilateral Tasks negotiation and complete result
    /// contract of [`Self::call_tool_final_outcome_with_mrtr_retry`]. The
    /// responder may borrow its caller context and input result across awaits.
    /// Its future is bounded by the original cancellation domain and the earlier
    /// of `deadline` and the configured absolute timeout. Cancelling, expiring,
    /// or dropping a pending responder cannot publish a continuation.
    ///
    /// A Task receipt already admitted by the receive owner survives a same-poll
    /// cancellation. The caller owns that Task's later lifecycle; this method
    /// neither polls the Task nor retries an uncertain creating request.
    pub async fn call_tool_final_outcome_with_async_mrtr_retry<F>(
        &mut self,
        cx: &Cx,
        cancellation: &McpRequestCancellation,
        deadline: Instant,
        name: &str,
        arguments: Value,
        respond: F,
    ) -> McpResult<FinalToolCallOutcome>
    where
        F: for<'a> FnMut(&'a Cx, &'a InputRequiredResult) -> MrtrResponderFuture<'a>,
    {
        self.ensure_open()?;
        checkpoint(cx, cancellation)?;
        self.require_tasks()?;
        self.follow_mrtr(
            cx,
            cancellation,
            deadline,
            "tools/call",
            serde_json::json!({"name": name, "arguments": arguments}),
            OperationMrtrResponder::<SyncMrtrResponderFn, F>::Async(respond),
            true,
        )
        .await
        .and_then(tool_outcome)
    }

    /// Reads one exact Task ID through the negotiated official extension.
    ///
    /// A foreign returned ID or malformed snapshot fails this operation without
    /// disclosing it as the requested Task or consuming a sibling's response.
    pub async fn get_task_final(
        &mut self,
        cx: &Cx,
        cancellation: &McpRequestCancellation,
        task_id: FinalTaskId,
    ) -> McpResult<FinalGetTaskResult> {
        let result: FinalGetTaskResult = self
            .request_task(
                cx,
                cancellation,
                TASK_GET,
                serde_json::json!({"taskId": task_id.as_str()}),
            )
            .await?;
        if result.task.base().task_id != task_id {
            return Err(McpError::invalid_request(
                "Memory tasks/get response taskId does not match its request",
            ));
        }
        Ok(result)
    }

    /// Supplies typed responses for an input-required Task.
    ///
    /// Phase, response kinds, and locally observed finite retention are checked
    /// against the retained snapshot before allocating an ID or publishing bytes.
    /// Partial updates retain the official Tasks semantics; the server owns
    /// which outstanding keys remain live. Acknowledgement does not establish
    /// the resulting state or authorize replay after uncertain delivery.
    pub async fn update_task_final(
        &mut self,
        cx: &Cx,
        cancellation: &McpRequestCancellation,
        task: &FinalTask,
        input_responses: FinalTaskInputResponses,
    ) -> McpResult<FinalUpdateTaskResult> {
        self.ensure_open()?;
        checkpoint(cx, cancellation)?;
        self.require_tasks()?;
        crate::task_wait::admit_task_input(task, &input_responses)?;
        let responses = serde_json::to_value(input_responses).map_err(|_| {
            McpError::invalid_params("Memory Tasks input responses could not be encoded")
        })?;
        self.request_task_checked(
            cx,
            cancellation,
            TASK_UPDATE,
            serde_json::json!({"taskId": task.base().task_id.as_str(), "inputResponses": responses}),
            || crate::task_wait::admit_input_retention(task),
        )
        .await
    }

    /// Requests cancellation of one Task without cancelling this client or its siblings.
    ///
    /// The acknowledgement is retained as a complete Tasks result. Cancellation
    /// of this request itself is distinct from the server's Task lifecycle.
    pub async fn cancel_task_final(
        &mut self,
        cx: &Cx,
        cancellation: &McpRequestCancellation,
        task_id: FinalTaskId,
    ) -> McpResult<FinalCancelTaskResult> {
        self.request_task(
            cx,
            cancellation,
            TASK_CANCEL,
            serde_json::json!({"taskId": task_id.as_str()}),
        )
        .await
    }

    fn require_tasks(&self) -> McpResult<&MemoryTaskRuntime> {
        self.tasks
            .as_ref()
            .filter(|tasks| tasks.negotiated.is_some())
            .ok_or_else(tasks_not_active)
    }

    async fn request_task<R: serde::de::DeserializeOwned>(
        &mut self,
        cx: &Cx,
        cancellation: &McpRequestCancellation,
        method: &str,
        parameters: Value,
    ) -> McpResult<R> {
        self.request_task_checked(cx, cancellation, method, parameters, || Ok(()))
            .await
    }

    async fn request_task_checked<R: serde::de::DeserializeOwned, F: FnMut() -> McpResult<()>>(
        &mut self,
        cx: &Cx,
        cancellation: &McpRequestCancellation,
        method: &str,
        parameters: Value,
        before_send: F,
    ) -> McpResult<R> {
        self.ensure_open()?;
        checkpoint(cx, cancellation)?;
        let admission = self.require_tasks()?.admit_request(method)?;
        let parameters = self.parameters_with_tasks(parameters, true)?;
        let mut execution = self
            .execute_admitted_extension_checked(
                cx,
                cancellation,
                method,
                parameters,
                self.timeout_policy,
                admission,
                before_send,
            )
            .await?;
        loop {
            match self
                .next_extension_event(cx, cancellation, &mut execution)
                .await?
            {
                Some(MemoryExtensionEvent::Notification(_)) => {}
                Some(MemoryExtensionEvent::Result(_)) => {
                    let source = execution.raw_result_source().ok_or_else(|| {
                        McpError::invalid_request("Memory Tasks response omitted its result source")
                    })?;
                    let result = serde_json::from_str(source).map_err(|_| {
                        McpError::invalid_request(
                            "Memory Tasks response has an invalid result shape",
                        )
                    })?;
                    checkpoint(cx, cancellation)?;
                    return Ok(result);
                }
                None => {
                    return Err(McpError::internal_error(
                        "Memory Tasks execution ended without its result",
                    ));
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::future::{Future, poll_fn};
    use std::pin::pin;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::task::Poll;
    use std::time::Duration;

    use asupersync::runtime::RuntimeBuilder;
    use fastmcp_core::McpErrorCode;
    use fastmcp_protocol::{
        ClientInfo, JsonRpcMessage, JsonRpcRequest, JsonRpcResponse, RequestId,
    };
    use fastmcp_transport::memory::{MemoryTransport, create_memory_transport_pair_with_capacity};
    use serde_json::json;

    use super::*;

    const TASKS: &str = "io.modelcontextprotocol/tasks";

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
                .expect("memory Tasks must progress on the caller runtime");
        });
        assert!(runtime.shutdown_timeout(Duration::from_secs(1)));
    }

    fn info() -> ClientInfo {
        ClientInfo {
            name: "tasks-memory-client".to_owned(),
            version: "1".to_owned(),
        }
    }

    fn discovery(extensions: Value) -> Value {
        json!({
            "resultType": "complete",
            "supportedVersions": ["2026-07-28"],
            "capabilities": {"extensions": extensions},
            "ttlMs": 0,
            "cacheScope": "private",
        })
    }

    fn response(id: i64, result: Value) -> JsonRpcMessage {
        JsonRpcMessage::Response(JsonRpcResponse::success(RequestId::Number(id), result))
    }

    fn tools() -> Value {
        json!({"resultType":"complete", "tools":[], "ttlMs":0, "cacheScope":"private"})
    }

    fn snapshot(task_id: &str) -> Value {
        json!({
            "resultType": "complete",
            "taskId": task_id,
            "status": "working",
            "createdAt": "2026-07-28T12:00:00.000Z",
            "lastUpdatedAt": "2026-07-28T12:00:00.000Z",
            "ttlMs": 60_000,
        })
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

    fn assert_tasks_metadata(request: &JsonRpcRequest) {
        let meta = &request.params.as_ref().unwrap()["_meta"];
        assert_eq!(
            meta["io.modelcontextprotocol/protocolVersion"],
            "2026-07-28",
        );
        assert_eq!(
            meta["io.modelcontextprotocol/clientInfo"]["name"],
            "tasks-memory-client",
        );
        assert_eq!(
            meta["io.modelcontextprotocol/clientCapabilities"]["extensions"],
            json!({(TASKS): {}}),
        );
    }

    async fn connected(cx: &Cx) -> (MemoryClient, MemoryTransport) {
        connected_with(cx, MemoryClient::builder(info()).with_tasks()).await
    }

    async fn connected_with(
        cx: &Cx,
        builder: MemoryClientBuilder,
    ) -> (MemoryClient, MemoryTransport) {
        let (transport, mut peer) = create_memory_transport_pair_with_capacity(1);
        peer.send_async(cx, &response(1, discovery(json!({(TASKS): {}}))))
            .await
            .unwrap();
        let client = builder.connect(cx, transport).await.unwrap();
        let request = receive(cx, &mut peer, "server/discover", Some(1)).await;
        assert_tasks_metadata(&request);
        assert!(client.tasks_active());
        (client, peer)
    }

    fn input_required() -> Value {
        json!({
            "resultType": "input_required", "requestState": "opaque-first-state",
            "inputRequests": {"roots": {"method": "roots/list"}},
        })
    }

    fn roots_answers(input: &InputRequiredResult) -> MrtrInputResponses {
        input
            .input_requests()
            .into_iter()
            .flat_map(|requests| requests.members())
            .map(|member| (member.name.clone(), json!({"roots": []})))
            .collect()
    }

    fn task_receipt() -> Value {
        let mut value = snapshot("memory-created-after-input");
        value["resultType"] = json!("task");
        value["ttlMs"] = Value::Null;
        value["_meta"] = json!({"com.example/receipt": "résumé 東京"});
        value["com.example/exact"] = Value::Number(serde_json::Number::from_string_unchecked(
            "7.30e-2".to_owned(),
        ));
        value
    }

    #[test]
    fn memory_tasks_mrtr_preserves_authority_and_exact_results_across_rounds() {
        run(|cx| async move {
            for installed in [false, true] {
                for create_task in [false, true] {
                    let handler_calls = Arc::new(AtomicUsize::new(0));
                    let observed = Arc::clone(&handler_calls);
                    let handlers = ReverseRequestHandlers::new().with_modern_roots_list(
                        move |caller, _, _| {
                            assert!(caller.blocking_pool_handle().is_none());
                            observed.fetch_add(1, Ordering::AcqRel);
                            Box::pin(async {
                                Ok(crate::FinalEmbeddedRootsListResult { roots: Vec::new() })
                            })
                        },
                    );
                    let (mut client, mut peer) = connected_with(
                        &cx,
                        MemoryClient::builder(info())
                            .with_tasks()
                            .reverse_request_handlers(handlers),
                    )
                    .await;
                    let cancellation = McpRequestCancellation::new();
                    let mut sibling = client
                        .execute_core(&cx, &cancellation, "tools/list", json!({}))
                        .await
                        .unwrap();
                    receive(&cx, &mut peer, "tools/list", Some(2)).await;
                    let mut server = cx.spawn(move |peer_cx| async move {
                        let request = receive(&peer_cx, &mut peer, "tools/call", Some(3)).await;
                        assert_tasks_metadata(&request);
                        let original = request.params.unwrap();
                        assert_eq!(original["name"], "interactive");
                        assert_eq!(original["arguments"], json!({"value": "résumé 東京"}));
                        for (id, challenge) in [
                            (3, input_required()),
                            (4, json!({"resultType": "input_required", "requestState": "opaque-second-state"})),
                        ] {
                            peer.send_async(&peer_cx, &response(id, challenge.clone())).await.unwrap();
                            let retry = receive(&peer_cx, &mut peer, "tools/call", Some(id + 1)).await;
                            assert_tasks_metadata(&retry);
                            let mut parameters = retry.params.unwrap();
                            assert_eq!(parameters.get("requestState"), challenge.get("requestState"));
                            let answers = parameters.as_object_mut().unwrap().remove("inputResponses");
                            if id == 3 {
                                assert_eq!(answers, Some(json!({"roots": {"roots": []}})));
                            } else {
                                assert!(answers.is_none(), "state-only round must not reuse an earlier answer");
                            }
                            parameters.as_object_mut().unwrap().remove("requestState");
                            assert_eq!(parameters, original, "continuation must retain the original request and authority");
                        }
                        peer.send_async(&peer_cx, &response(2, tools())).await.unwrap();
                        let terminal = if create_task {
                            task_receipt()
                        } else {
                            let mut value = task_receipt();
                            value["resultType"] = json!("complete");
                            value["content"] = json!([]);
                            for key in ["taskId", "status", "createdAt", "lastUpdatedAt", "ttlMs"] {
                                value.as_object_mut().unwrap().remove(key);
                            }
                            value
                        };
                        peer.send_async(&peer_cx, &response(5, terminal)).await.unwrap();
                        peer
                    }).unwrap();
                    let mut responder_calls = 0;
                    let outcome = if installed {
                        client
                            .call_tool_final_outcome_with_handlers(
                                &cx,
                                &cancellation,
                                "interactive",
                                json!({"value": "résumé 東京"}),
                            )
                            .await
                    } else {
                        client
                            .call_tool_final_outcome_with_mrtr_retry(
                                &cx,
                                &cancellation,
                                Instant::now() + Duration::from_secs(3),
                                "interactive",
                                json!({"value": "résumé 東京"}),
                                |input| {
                                    responder_calls += 1;
                                    Ok(roots_answers(input))
                                },
                            )
                            .await
                    }
                    .unwrap();
                    let source = match outcome {
                        FinalToolCallOutcome::Task(created) if create_task => {
                            assert_eq!(
                                created.task.base().task_id.as_str(),
                                "memory-created-after-input"
                            );
                            serde_json::to_string(&created).unwrap()
                        }
                        FinalToolCallOutcome::Complete(complete) if !create_task => {
                            fastmcp_protocol::encode_complete_result(
                                &complete.meta,
                                Vec::new(),
                                &[],
                                &complete.extras,
                            )
                            .unwrap()
                        }
                        outcome => panic!("unexpected MRTR final outcome: {outcome:?}"),
                    };
                    assert!(
                        source.contains("7.30e-2"),
                        "exact numeric result spelling survives"
                    );
                    assert!(source.contains("résumé 東京"));
                    assert_eq!(
                        handler_calls.load(Ordering::Acquire),
                        usize::from(installed)
                    );
                    assert_eq!(responder_calls, if installed { 0 } else { 2 });
                    assert!(matches!(
                        client.next_event(&cx, &cancellation, &mut sibling).await.unwrap(),
                        Some(MemoryRequestEvent::Result(result))
                            if matches!(*result, CoreResult::Final(FinalCoreResult::ToolsList { .. })),
                    ));
                    assert_eq!(
                        client.next_id, 6,
                        "one request per admitted round and no implicit task polling"
                    );
                    assert!(client.take_cancellation_events().is_empty());
                    let _peer = server.join(&cx).await.unwrap();
                    client.close(&cx).unwrap();
                }
            }
        });
    }

    #[test]
    fn memory_tasks_mrtr_rejects_unadvertised_input_before_host_effects() {
        run(|cx| async move {
            let (mut client, mut peer) = connected(&cx).await;
            let mut server = cx.spawn(move |peer_cx| async move {
                let request = receive(&peer_cx, &mut peer, "tools/call", Some(2)).await;
                assert_tasks_metadata(&request);
                assert!(request.params.unwrap()["_meta"]["io.modelcontextprotocol/clientCapabilities"]
                    .get("roots").is_none());
                peer.send_async(&peer_cx, &response(2, input_required())).await.unwrap();
                // The next ID belongs to a fresh ordinary request, never a
                // continuation authorized by unadvertised host capability.
                receive(&peer_cx, &mut peer, "tools/list", Some(3)).await;
                peer.send_async(&peer_cx, &response(3, tools())).await.unwrap();
                peer
            }).unwrap();
            let mut calls = 0;
            let cancellation = McpRequestCancellation::new();
            let error = client
                .call_tool_final_outcome_with_mrtr_retry(
                    &cx,
                    &cancellation,
                    Instant::now() + Duration::from_secs(3),
                    "interactive",
                    json!({}),
                    |input| {
                        calls += 1;
                        Ok(roots_answers(input))
                    },
                )
                .await
                .unwrap_err();
            assert_eq!(error.code, McpErrorCode::InvalidRequest);
            assert_eq!(calls, 0);
            assert_eq!(client.next_id, 3);
            assert!(client.tasks_active());
            assert!(client.take_cancellation_events().is_empty());
            client.list_tools(&cx, &cancellation, None).await.unwrap();
            let _peer = server.join(&cx).await.unwrap();
            client.close(&cx).unwrap();
        });
    }

    #[test]
    fn memory_tasks_mrtr_cancelled_or_invalid_answers_publish_no_continuation() {
        run(|cx| async move {
            for cancel in [false, true] {
                let (mut client, mut peer) = connected_with(
                    &cx,
                    MemoryClient::builder(info())
                        .with_tasks()
                        .capabilities(serde_json::from_value(json!({"roots": {}})).unwrap()),
                )
                .await;
                let mut server = cx
                    .spawn(move |peer_cx| async move {
                        receive(&peer_cx, &mut peer, "tools/call", Some(2)).await;
                        peer.send_async(&peer_cx, &response(2, input_required()))
                            .await
                            .unwrap();
                        receive(&peer_cx, &mut peer, "tools/list", Some(3)).await;
                        peer.send_async(&peer_cx, &response(3, tools()))
                            .await
                            .unwrap();
                        peer
                    })
                    .unwrap();
                let cancellation = McpRequestCancellation::new();
                let mut calls = 0;
                let error = client
                    .call_tool_final_outcome_with_mrtr_retry(
                        &cx,
                        &cancellation,
                        Instant::now() + Duration::from_secs(3),
                        "interactive",
                        json!({}),
                        |input| {
                            calls += 1;
                            if cancel {
                                cancellation.cancel();
                                Ok(roots_answers(input))
                            } else {
                                Ok(MrtrInputResponses::new())
                            }
                        },
                    )
                    .await
                    .unwrap_err();
                assert_eq!(
                    error.code,
                    if cancel {
                        McpErrorCode::RequestCancelled
                    } else {
                        McpErrorCode::InvalidParams
                    }
                );
                assert_eq!(calls, 1);
                assert_eq!(client.next_id, 3);
                assert!(client.tasks_active());
                assert!(client.take_cancellation_events().is_empty());
                client
                    .list_tools(&cx, &McpRequestCancellation::new(), None)
                    .await
                    .unwrap();
                let _peer = server.join(&cx).await.unwrap();
                client.close(&cx).unwrap();
            }
        });
    }

    #[test]
    fn memory_tasks_mrtr_does_not_activate_tasks_for_ordinary_calls() {
        run(|cx| async move {
            let (mut client, mut peer) = connected_with(
                &cx,
                MemoryClient::builder(info())
                    .with_tasks()
                    .capabilities(serde_json::from_value(json!({"roots": {}})).unwrap()),
            )
            .await;
            let mut server = cx.spawn(move |peer_cx| async move {
                for id in [2, 3] {
                    let request = receive(&peer_cx, &mut peer, "tools/call", Some(id)).await;
                    assert!(request.params.unwrap()["_meta"]["io.modelcontextprotocol/clientCapabilities"]
                        ["extensions"].get(TASKS).is_none());
                    peer.send_async(&peer_cx, &response(id, if id == 2 { input_required() } else { task_receipt() }))
                        .await.unwrap();
                }
                receive(&peer_cx, &mut peer, "tools/list", Some(4)).await;
                peer.send_async(&peer_cx, &response(4, tools())).await.unwrap();
                peer
            }).unwrap();
            let cancellation = McpRequestCancellation::new();
            let error = client
                .call_tool_with_mrtr_retry(
                    &cx,
                    &cancellation,
                    Instant::now() + Duration::from_secs(3),
                    "interactive",
                    json!({}),
                    |input| Ok(roots_answers(input)),
                )
                .await
                .unwrap_err();
            assert_eq!(error.code, McpErrorCode::InvalidRequest);
            assert_eq!(client.next_id, 4);
            client.list_tools(&cx, &cancellation, None).await.unwrap();
            let _peer = server.join(&cx).await.unwrap();
            client.close(&cx).unwrap();
        });
    }

    #[test]
    fn memory_tasks_mrtr_deadline_retires_only_the_pending_continuation() {
        run(|cx| async move {
            let (mut client, mut peer) = connected_with(
                &cx,
                MemoryClient::builder(info())
                    .with_tasks()
                    .capabilities(serde_json::from_value(json!({"roots": {}})).unwrap()),
            )
            .await;
            let mut server = cx
                .spawn(move |peer_cx| async move {
                    receive(&peer_cx, &mut peer, "tools/call", Some(2)).await;
                    peer.send_async(&peer_cx, &response(2, input_required()))
                        .await
                        .unwrap();
                    let retry = receive(&peer_cx, &mut peer, "tools/call", Some(3)).await;
                    assert_tasks_metadata(&retry);
                    assert_eq!(retry.params.unwrap()["requestState"], "opaque-first-state");
                    // No result: the originating operation bound must retire this
                    // owner even while the ordinary response timer is still live.
                    let cancel =
                        receive(&peer_cx, &mut peer, "notifications/cancelled", None).await;
                    assert_eq!(cancel.params.unwrap()["requestId"], 3);
                    peer.send_async(&peer_cx, &response(3, task_receipt()))
                        .await
                        .unwrap();
                    receive(&peer_cx, &mut peer, "tools/list", Some(4)).await;
                    peer.send_async(&peer_cx, &response(4, tools()))
                        .await
                        .unwrap();
                    peer
                })
                .unwrap();
            let cancellation = McpRequestCancellation::new();
            let error = client
                .call_tool_final_outcome_with_mrtr_retry(
                    &cx,
                    &cancellation,
                    Instant::now() + Duration::from_millis(300),
                    "interactive",
                    json!({}),
                    |input| Ok(roots_answers(input)),
                )
                .await
                .unwrap_err();
            assert_eq!(error.data.unwrap()["timeoutSource"], "absolute");
            assert_eq!(client.next_id, 4, "a timeout cannot replay a creating call");
            assert!(client.tasks_active());
            client.list_tools(&cx, &cancellation, None).await.unwrap();
            assert_eq!(client.take_cancellation_events().len(), 1);
            let _peer = server.join(&cx).await.unwrap();
            client.close(&cx).unwrap();
        });
    }

    #[test]
    fn memory_tasks_requires_bilateral_empty_settings_before_application_requests() {
        run(|cx| async move {
            for extensions in [
                json!({}),
                json!({(TASKS): null}),
                json!({(TASKS): []}),
                json!({(TASKS): {"mode": "unrecognized"}}),
            ] {
                let (transport, mut peer) = create_memory_transport_pair_with_capacity(1);
                peer.send_async(&cx, &response(1, discovery(extensions.clone())))
                    .await
                    .unwrap();
                assert!(
                    MemoryClient::builder(info())
                        .with_tasks()
                        .connect(&cx, transport)
                        .await
                        .is_err(),
                    "Tasks must reject missing or malformed peer settings: {extensions}",
                );
                let request = receive(&cx, &mut peer, "server/discover", Some(1)).await;
                assert_tasks_metadata(&request);
                assert!(
                    peer.recv_async(&cx).await.is_err(),
                    "failed negotiation closes without an application request",
                );
            }

            let (mut client, mut peer) = connected(&cx).await;
            client.close(&cx).unwrap();
            assert!(!client.tasks_active());
            assert!(peer.recv_async(&cx).await.is_err());
        });
    }

    #[test]
    fn memory_tasks_get_binds_exact_id_and_preserves_typed_results_and_siblings() {
        run(|cx| async move {
            let (mut client, mut peer) = connected(&cx).await;
            let cancellation = McpRequestCancellation::new();
            let mut sibling = client
                .execute_core(&cx, &cancellation, "tools/list", json!({}))
                .await
                .unwrap();
            receive(&cx, &mut peer, "tools/list", Some(2)).await;
            let mut server = cx
                .spawn(move |peer_cx| async move {
                    let request = receive(&peer_cx, &mut peer, TASK_GET, Some(3)).await;
                    assert_tasks_metadata(&request);
                    assert_eq!(request.params.unwrap()["taskId"], "task-requested");
                    peer.send_async(&peer_cx, &response(2, tools()))
                        .await
                        .unwrap();
                    peer.send_async(&peer_cx, &response(3, snapshot("task-foreign")))
                        .await
                        .unwrap();

                    let request = receive(&peer_cx, &mut peer, TASK_GET, Some(4)).await;
                    assert_tasks_metadata(&request);
                    assert_eq!(request.params.unwrap()["taskId"], "task-requested");
                    let mut complete = snapshot("task-requested");
                    complete["status"] = json!("completed");
                    complete["result"] = json!({"content": [], "receipt": "résumé 東京"});
                    complete["result"]["exact"] = Value::Number(
                        serde_json::Number::from_string_unchecked("7.30e-2".to_owned()),
                    );
                    complete["_meta"] = json!({"com.example/source": "memory"});
                    complete["applicationReceipt"] = json!({"accepted": true});
                    peer.send_async(&peer_cx, &response(4, complete))
                        .await
                        .unwrap();
                    peer
                })
                .unwrap();

            let task_id = FinalTaskId::parse("task-requested").unwrap();
            assert_eq!(
                client
                    .get_task_final(&cx, &cancellation, task_id.clone())
                    .await
                    .unwrap_err()
                    .code,
                McpErrorCode::InvalidRequest,
            );
            assert!(matches!(
                client
                    .next_event(&cx, &cancellation, &mut sibling)
                    .await
                    .unwrap(),
                Some(MemoryRequestEvent::Result(result))
                    if matches!(*result, CoreResult::Final(FinalCoreResult::ToolsList { .. })),
            ));

            let result = client
                .get_task_final(&cx, &cancellation, task_id.clone())
                .await
                .unwrap();
            assert_eq!(result.task.base().task_id, task_id);
            assert!(matches!(&result.task, FinalTask::Completed { .. }));
            let retained = serde_json::to_value(&result).unwrap();
            assert_eq!(retained["result"]["receipt"], "résumé 東京");
            assert_eq!(retained["_meta"]["com.example/source"], "memory");
            assert_eq!(retained["applicationReceipt"], json!({"accepted": true}));
            assert!(serde_json::to_string(&result).unwrap().contains("7.30e-2"));
            assert_eq!(client.next_id, 5);
            assert!(client.tasks_active());
            let _peer = server.join(&cx).await.unwrap();
            client.close(&cx).unwrap();
        });
    }

    #[test]
    fn memory_tasks_cancelled_or_dropped_get_never_retries_or_consumes_siblings() {
        run(|cx| async move {
            for drop_wait in [false, true] {
                let (mut client, mut peer) = connected(&cx).await;
                let original = McpRequestCancellation::new();
                {
                    let mut waiting = pin!(client.get_task_final(
                        &cx,
                        &original,
                        FinalTaskId::parse("task-requested").unwrap(),
                    ));
                    poll_fn(|task| {
                        assert!(waiting.as_mut().poll(task).is_pending());
                        Poll::Ready(())
                    })
                    .await;
                    let request = receive(&cx, &mut peer, TASK_GET, Some(2)).await;
                    assert_tasks_metadata(&request);
                    if !drop_wait {
                        original.cancel();
                        assert_eq!(
                            waiting.await.unwrap_err().code,
                            McpErrorCode::RequestCancelled,
                        );
                    }
                }
                assert_eq!(client.next_id, 3);
                let mut server = cx
                    .spawn(move |peer_cx| async move {
                        let cancel =
                            receive(&peer_cx, &mut peer, "notifications/cancelled", None).await;
                        assert_eq!(cancel.params.unwrap()["requestId"], 2);
                        // This invalid late reply belongs only to the retired
                        // get request; it must never become a sibling's result.
                        peer.send_async(
                            &peer_cx,
                            &response(2, json!({"resultType": "task", "taskId": "foreign"})),
                        )
                        .await
                        .unwrap();
                        receive(&peer_cx, &mut peer, "tools/list", Some(3)).await;
                        peer.send_async(&peer_cx, &response(3, tools()))
                            .await
                            .unwrap();
                        let request = receive(&peer_cx, &mut peer, TASK_GET, Some(4)).await;
                        assert_eq!(request.params.unwrap()["taskId"], "task-requested");
                        peer.send_async(&peer_cx, &response(4, snapshot("task-requested")))
                            .await
                            .unwrap();
                        peer
                    })
                    .unwrap();
                let live = McpRequestCancellation::new();
                assert!(matches!(
                    client
                        .request_core(&cx, &live, "tools/list", json!({}))
                        .await
                        .unwrap(),
                    CoreResult::Final(FinalCoreResult::ToolsList { .. }),
                ));
                assert!(matches!(
                    client
                        .get_task_final(&cx, &live, FinalTaskId::parse("task-requested").unwrap())
                        .await
                        .unwrap()
                        .task,
                    FinalTask::Working(_),
                ));
                assert_eq!(client.next_id, 5);
                assert_eq!(client.take_cancellation_events().len(), 1);
                assert!(client.tasks_active());
                let _peer = server.join(&cx).await.unwrap();
                client.close(&cx).unwrap();
            }
        });
    }

    #[test]
    fn memory_tasks_async_mrtr_preserves_negotiation_and_exact_receipt() {
        run(|cx| async move {
            for create_task in [false, true] {
                let installed_calls = Arc::new(AtomicUsize::new(0));
                let observed_installed = Arc::clone(&installed_calls);
                let handlers = ReverseRequestHandlers::new().with_modern_roots_list(
                    move |_, _, _| {
                        observed_installed.fetch_add(1, Ordering::AcqRel);
                        Box::pin(async {
                            Ok(crate::FinalEmbeddedRootsListResult { roots: Vec::new() })
                        })
                    },
                );
                let (mut client, mut peer) = connected_with(
                    &cx,
                    MemoryClient::builder(info())
                        .with_tasks()
                        .reverse_request_handlers(handlers),
                )
                .await;
                let cancellation = McpRequestCancellation::new();
                let mut sibling = client
                    .execute_core(&cx, &cancellation, "tools/list", json!({}))
                    .await
                    .unwrap();
                receive(&cx, &mut peer, "tools/list", Some(2)).await;
                let mut server = cx
                    .spawn(move |peer_cx| async move {
                        let initial = receive(&peer_cx, &mut peer, "tools/call", Some(3)).await;
                        assert_tasks_metadata(&initial);
                        let original = initial.params.unwrap();
                        assert_eq!(original["name"], "interactive");
                        assert_eq!(original["arguments"], json!({"value":"résumé 東京"}));
                        for (id, challenge) in [
                            (3, input_required()),
                            (
                                4,
                                json!({
                                    "resultType":"input_required",
                                    "requestState":"async-state-only",
                                }),
                            ),
                        ] {
                            peer.send_async(&peer_cx, &response(id, challenge.clone()))
                                .await
                                .unwrap();
                            let retry =
                                receive(&peer_cx, &mut peer, "tools/call", Some(id + 1)).await;
                            assert_tasks_metadata(&retry);
                            let mut parameters = retry.params.unwrap();
                            assert_eq!(
                                parameters.get("requestState"),
                                challenge.get("requestState"),
                            );
                            let answers =
                                parameters.as_object_mut().unwrap().remove("inputResponses");
                            if id == 3 {
                                assert_eq!(answers, Some(json!({"roots":{"roots":[]}})));
                            } else {
                                assert!(answers.is_none());
                            }
                            parameters.as_object_mut().unwrap().remove("requestState");
                            assert_eq!(parameters, original);
                        }
                        peer.send_async(&peer_cx, &response(2, tools()))
                            .await
                            .unwrap();
                        let terminal = if create_task {
                            task_receipt()
                        } else {
                            let mut value = task_receipt();
                            value["resultType"] = json!("complete");
                            value["content"] = json!([]);
                            for key in [
                                "taskId",
                                "status",
                                "createdAt",
                                "lastUpdatedAt",
                                "ttlMs",
                            ] {
                                value.as_object_mut().unwrap().remove(key);
                            }
                            value
                        };
                        peer.send_async(&peer_cx, &response(5, terminal))
                            .await
                            .unwrap();
                        peer
                    })
                    .unwrap();
                let calls = Arc::new(AtomicUsize::new(0));
                let pending_polls = Arc::new(AtomicUsize::new(0));
                let observed_calls = Arc::clone(&calls);
                let observed_pending = Arc::clone(&pending_polls);
                let expected_task = cx.task_id();
                let outcome = client
                    .call_tool_final_outcome_with_async_mrtr_retry(
                        &cx,
                        &cancellation,
                        Instant::now() + Duration::from_secs(3),
                        "interactive",
                        json!({"value":"résumé 東京"}),
                        move |caller, input| {
                            let calls = Arc::clone(&observed_calls);
                            let pending = Arc::clone(&observed_pending);
                            Box::pin(async move {
                                assert_eq!(caller.task_id(), expected_task);
                                assert!(caller.blocking_pool_handle().is_none());
                                calls.fetch_add(1, Ordering::AcqRel);
                                let mut yielded = false;
                                poll_fn(|task| {
                                    assert_eq!(Cx::current().unwrap().task_id(), expected_task);
                                    if yielded {
                                        Poll::Ready(())
                                    } else {
                                        yielded = true;
                                        pending.fetch_add(1, Ordering::AcqRel);
                                        task.waker().wake_by_ref();
                                        Poll::Pending
                                    }
                                })
                                .await;
                                assert_eq!(caller.task_id(), expected_task);
                                Ok(roots_answers(input))
                            })
                        },
                    )
                    .await
                    .unwrap();
                let source = match outcome {
                    FinalToolCallOutcome::Task(created) if create_task => {
                        assert_eq!(
                            created.task.base().task_id.as_str(),
                            "memory-created-after-input",
                        );
                        serde_json::to_string(&created).unwrap()
                    }
                    FinalToolCallOutcome::Complete(complete) if !create_task => {
                        fastmcp_protocol::encode_complete_result(
                            &complete.meta,
                            Vec::new(),
                            &[],
                            &complete.extras,
                        )
                        .unwrap()
                    }
                    outcome => panic!("unexpected async Tasks outcome: {outcome:?}"),
                };
                assert!(source.contains("7.30e-2"));
                assert!(source.contains("résumé 東京"));
                assert_eq!(calls.load(Ordering::Acquire), 2);
                assert_eq!(pending_polls.load(Ordering::Acquire), 2);
                assert_eq!(installed_calls.load(Ordering::Acquire), 0);
                assert!(matches!(
                    client
                        .next_event(&cx, &cancellation, &mut sibling)
                        .await
                        .unwrap(),
                    Some(MemoryRequestEvent::Result(result))
                        if matches!(*result, CoreResult::Final(FinalCoreResult::ToolsList { .. })),
                ));
                assert_eq!(client.next_id, 6);
                assert!(client.tasks_active());
                assert!(client.take_cancellation_events().is_empty());
                let _peer = server.join(&cx).await.unwrap();
                client.close(&cx).unwrap();
            }
        });
    }

    #[test]
    fn memory_tasks_async_mrtr_pending_cancellation_publishes_no_continuation() {
        struct ResponderDrop(Arc<AtomicUsize>);

        impl Drop for ResponderDrop {
            fn drop(&mut self) {
                self.0.fetch_add(1, Ordering::AcqRel);
            }
        }

        run(|cx| async move {
            let (mut client, mut peer) = connected_with(
                &cx,
                MemoryClient::builder(info())
                    .with_tasks()
                    .capabilities(serde_json::from_value(json!({"roots":{}})).unwrap()),
            )
            .await;
            peer.send_async(&cx, &response(2, input_required()))
                .await
                .unwrap();
            let cancellation = McpRequestCancellation::new();
            let started = Arc::new(AtomicUsize::new(0));
            let dropped = Arc::new(AtomicUsize::new(0));
            let observed_started = Arc::clone(&started);
            let observed_dropped = Arc::clone(&dropped);
            {
                let mut waiting = pin!(client.call_tool_final_outcome_with_async_mrtr_retry(
                    &cx,
                    &cancellation,
                    Instant::now() + Duration::from_secs(3),
                    "interactive",
                    json!({}),
                    move |caller, _| {
                        let started = Arc::clone(&observed_started);
                        let guard = ResponderDrop(Arc::clone(&observed_dropped));
                        Box::pin(async move {
                            let _guard = guard;
                            assert!(caller.blocking_pool_handle().is_none());
                            started.fetch_add(1, Ordering::AcqRel);
                            std::future::pending::<McpResult<MrtrInputResponses>>().await
                        })
                    },
                ));
                poll_fn(|task| {
                    assert!(waiting.as_mut().poll(task).is_pending());
                    if started.load(Ordering::Acquire) == 1 {
                        Poll::Ready(())
                    } else {
                        task.waker().wake_by_ref();
                        Poll::Pending
                    }
                })
                .await;
                let original = receive(&cx, &mut peer, "tools/call", Some(2)).await;
                assert_tasks_metadata(&original);
                cancellation.cancel();
                assert_eq!(
                    waiting.await.unwrap_err().code,
                    McpErrorCode::RequestCancelled,
                );
            }
            assert_eq!(started.load(Ordering::Acquire), 1);
            assert_eq!(dropped.load(Ordering::Acquire), 1);
            assert_eq!(client.next_id, 3);
            assert!(client.tasks_active());
            assert!(client.take_cancellation_events().is_empty());
            peer.send_async(&cx, &response(3, tools())).await.unwrap();
            client
                .list_tools(&cx, &McpRequestCancellation::new(), None)
                .await
                .unwrap();
            receive(&cx, &mut peer, "tools/list", Some(3)).await;
            assert!(cx.checkpoint().is_ok());
            client.close(&cx).unwrap();
        });
    }
}
