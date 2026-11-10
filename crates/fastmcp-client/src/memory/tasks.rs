//! Explicit, negotiated Tasks operations over the existing memory executor.
//!
//! The official descriptor and local empty settings are frozen before discovery.
//! Ordinary core calls withhold Tasks; only an eligible tool execution retains
//! permission to return a Task. Lifecycle methods use the same immutable
//! extension receipt and exact response source as other extension requests.
//! These APIs do not create a runtime, persist handles, or retry creation.

use std::collections::BTreeMap;
use std::sync::Arc;

use asupersync::Cx;
use fastmcp_core::{McpError, McpRequestCancellation, McpResult};
use fastmcp_protocol::extensions::{
    ClientExtensionDiscovery, ExtensionDescriptor, ExtensionDescriptorRegistry,
    ExtensionNegotiationError, ExtensionSettings, NegotiatedExtensionSet,
    official_tasks_empty_settings, register_official_tasks_extension,
};
use fastmcp_protocol::tasks_extension::{TASK_CANCEL, TASK_GET, TASK_UPDATE};
use fastmcp_protocol::{CoreResult, ExtensionId, FinalCoreResult, ServerDiscoverResult};
use serde_json::Value;

use super::{
    MemoryClient, MemoryClientBuilder, MemoryExtensionEvent, MemoryRequestEvent,
    MemoryRequestExecution, checkpoint,
};
use crate::session::{ClientExtensionResultAdmission, ClientExtensionRuntime};
use crate::{
    FinalCancelTaskResult, FinalGetTaskResult, FinalTask, FinalTaskId, FinalTaskInputResponses,
    FinalToolCallOutcome, FinalUpdateTaskResult, RequestTimeoutPolicy, ReverseRequestHandlers,
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
                    return match *result {
                        CoreResult::Final(FinalCoreResult::ToolsCall { result, .. }) => {
                            Ok(FinalToolCallOutcome::Complete(result))
                        }
                        CoreResult::Final(FinalCoreResult::ToolsCallTask { result }) => {
                            Ok(FinalToolCallOutcome::Task(result))
                        }
                        CoreResult::Final(FinalCoreResult::ToolsCallInputRequired {
                            result,
                            ..
                        }) => Ok(FinalToolCallOutcome::InputRequired(result)),
                        _ => Err(McpError::invalid_request(
                            "Memory Tasks tool execution returned another method's result",
                        )),
                    };
                }
                None => {
                    return Err(McpError::internal_error(
                        "Memory Tasks tool execution ended without its result",
                    ));
                }
            }
        }
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
        let (transport, mut peer) = create_memory_transport_pair_with_capacity(1);
        peer.send_async(cx, &response(1, discovery(json!({(TASKS): {}}))))
            .await
            .unwrap();
        let client = MemoryClient::builder(info())
            .with_tasks()
            .connect(cx, transport)
            .await
            .unwrap();
        let request = receive(cx, &mut peer, "server/discover", Some(1)).await;
        assert_tasks_metadata(&request);
        assert!(client.tasks_active());
        (client, peer)
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
}
