//! Apps forwarding on the caller-owned bounded memory connection.
//!
//! The separate View bridge owns Host consent and the shared MRTR/Tasks
//! composition. Its reused core requests retain memory execution's independent
//! correlation, exact result admission, and deferred cancellation controls.

use std::time::Instant;

use asupersync::Cx;
use fastmcp_core::{McpError, McpRequestCancellation, McpResult};
use fastmcp_protocol::{CoreResult, McpAppsRoutedMethod};
use serde_json::Value;

use super::{
    MemoryClient, MemoryClientBuilder, MemoryRequestEvent, SEND_ADMISSION_TIMEOUT, checkpoint,
};
use crate::mcp_apps::{
    McpAppsActivationProof, McpAppsBridgeTransport, McpAppsHost, McpAppsHostConfiguration,
    McpAppsHostError, McpAppsHostPolicy, McpAppsServerInputClient,
    McpAppsWireBridgeTransport, McpAppsWireHost, McpAppsWireHostCleanup,
    McpAppsWireHostConfiguration, McpAppsWireHostEffects, McpAppsWireHostPolicy,
    dispatch_apps_server_input, project_reused_core_result,
};
use crate::McpAppsClientSettings;

/// Forwards one negotiated Apps View through an existing memory client.
///
/// The policy borrows the client without creating a runtime or background
/// reader. View cancellation retires only its current core request. Deferred
/// cancellation controls use the caller-supplied cleanup context and a fixed
/// bounded deadline; interrupted cleanup remains available to a later drive.
pub struct McpAppsMemoryClientWirePolicy<'client> {
    client: &'client mut MemoryClient,
    cleanup_cx: Cx,
    cleanup_deadline: Option<Instant>,
}

impl MemoryClientBuilder {
    /// Configures Apps MIME support before the first discovery request.
    ///
    /// A Host can be created only after compatible bilateral activation. If
    /// the generic extension registry configures Apps, that registry owns its
    /// settings and activation receipt instead of this dedicated configuration.
    #[must_use]
    pub fn mcp_apps(mut self, settings: McpAppsClientSettings) -> Self {
        self.mcp_apps_settings = Some(settings);
        self
    }
}

impl MemoryClient {
    /// Reports live bilateral Apps activation on this exact connection.
    #[must_use]
    pub fn mcp_apps_active(&self) -> bool {
        !self.closed
            && self.executor.terminal_error().is_none()
            && self.session.mcp_apps_active()
    }

    fn apps_activation_proof(&self) -> Result<McpAppsActivationProof, McpAppsHostError> {
        if !self.mcp_apps_active() {
            return Err(McpAppsHostError::NotNegotiated);
        }
        McpAppsActivationProof::from_activation_receipt(
            self.session.mcp_apps_activation_receipt(),
        )
    }

    /// Starts a typed Apps Host with explicit embedder forwarding and consent.
    pub fn mcp_apps_host<T, P>(
        &self,
        transport: T,
        configuration: McpAppsHostConfiguration,
        policy: P,
    ) -> Result<McpAppsHost<T, P>, McpAppsHostError>
    where
        T: McpAppsBridgeTransport,
        P: McpAppsHostPolicy,
    {
        Ok(McpAppsHost::new_negotiated(
            transport,
            configuration,
            policy,
            self.apps_activation_proof()?,
        ))
    }

    /// Starts a closed-wire Apps Host with an embedder-owned forwarding policy.
    /// Constructing the Host does not authorize a server request or effect.
    pub fn mcp_apps_wire_host_with_policy<T, P>(
        &self,
        transport: T,
        configuration: McpAppsWireHostConfiguration,
        policy: P,
    ) -> Result<McpAppsWireHost<T, P>, McpAppsHostError>
    where
        T: McpAppsWireBridgeTransport,
        P: McpAppsWireHostPolicy,
    {
        Ok(McpAppsWireHost::new_negotiated(
            transport,
            configuration,
            policy,
            self.apps_activation_proof()?,
        ))
    }

    /// Starts one Apps Host using this caller-driven memory connection.
    ///
    /// Reused methods allocate fresh core IDs; View IDs never cross the server
    /// transport. Server input and Task creation require explicit per-View
    /// consent installed with the returned Host's with_effects method.
    ///
    /// The supplied Cx owns bounded transport cleanup after View cancellation.
    /// If it stops, unsent cancellation controls remain queued for a later
    /// client drive under a live context. Dropping the Host releases its borrow.
    pub fn mcp_apps_wire_host<T>(
        &mut self,
        cx: &Cx,
        transport: T,
        configuration: McpAppsWireHostConfiguration,
    ) -> Result<McpAppsWireHost<T, McpAppsMemoryClientWirePolicy<'_>>, McpAppsHostError>
    where
        T: McpAppsWireBridgeTransport,
    {
        let activation_proof = self.apps_activation_proof()?;
        checkpoint(cx, &McpRequestCancellation::new())?;
        Ok(McpAppsWireHost::new_negotiated(
            transport,
            configuration,
            McpAppsMemoryClientWirePolicy {
                client: self,
                cleanup_cx: cx.clone(),
                cleanup_deadline: None,
            },
            activation_proof,
        ))
    }

    async fn request_apps_core_prepared(
        &mut self,
        cx: &Cx,
        cancellation: &McpRequestCancellation,
        deadline: Instant,
        method: &str,
        parameters: Value,
        allow_tasks: bool,
    ) -> McpResult<CoreResult> {
        crate::check_mrtr_operation(cx, Some(cancellation), deadline)?;
        if !self.mcp_apps_active() {
            return Err(McpError::invalid_request("Apps memory connection is inactive"));
        }
        // Keep single-request execution here. The Apps Host, rather than the
        // client's installed general MRTR handlers, owns this View's consent.
        // Redecoration freezes local capabilities and preserves requestState
        // and inputResponses while exposing Tasks only after Host approval.
        let mut execution = self
            .execute_core_admitted(
                cx,
                cancellation,
                method,
                parameters,
                self.timeout_policy,
                allow_tasks,
            )
            .await?;
        loop {
            crate::check_mrtr_operation(cx, Some(cancellation), deadline)?;
            match self.next_event(cx, cancellation, &mut execution).await? {
                Some(MemoryRequestEvent::Notification(_)) => {}
                Some(MemoryRequestEvent::Result(result)) => {
                    crate::check_mrtr_operation(cx, Some(cancellation), deadline)?;
                    return Ok(*result);
                }
                None => {
                    return Err(McpError::internal_error(
                        "Apps memory execution ended without its core result",
                    ));
                }
            }
        }
    }
}

impl McpAppsServerInputClient for MemoryClient {
    fn prepare_apps_server_input(
        &self,
        cx: &Cx,
        parameters: Value,
    ) -> McpResult<(Instant, Value)> {
        if !self.mcp_apps_active() {
            return Err(McpError::invalid_request(
                "MCP Apps reused methods require the current bilateral activation receipt",
            ));
        }
        Ok((
            crate::mrtr_operation_deadline(cx, self.timeout_policy)?,
            self.parameters_with_tasks(parameters, false)?,
        ))
    }

    async fn request_apps_server_input(
        &mut self,
        cx: &Cx,
        cancellation: &McpRequestCancellation,
        deadline: Instant,
        method: &str,
        parameters: Value,
        allow_tasks: bool,
    ) -> McpResult<CoreResult> {
        if allow_tasks {
            #[cfg(feature = "tasks")]
            self.admit_apps_tasks()?;
            #[cfg(not(feature = "tasks"))]
            return Err(McpError::invalid_params("Apps Tasks support is not enabled"));
        }
        self.request_apps_core_prepared(
            cx,
            cancellation,
            deadline,
            method,
            parameters,
            allow_tasks,
        )
        .await
    }

    #[cfg(feature = "tasks")]
    fn admit_apps_tasks(&self) -> McpResult<()> {
        if !self.tasks_active() {
            return Err(McpError::invalid_request(
                "Apps Tasks requires explicit memory Tasks opt-in and negotiation",
            ));
        }
        crate::mcp_apps::admit_apps_task_discovery(
            self.session.server_discovery().ok_or_else(|| {
                McpError::invalid_request("Apps server Tasks require current discovery")
            })?,
        )
    }

    #[cfg(feature = "tasks")]
    async fn get_apps_task(
        &mut self,
        cx: &Cx,
        cancellation: &McpRequestCancellation,
        deadline: Instant,
        task_id: crate::FinalTaskId,
    ) -> McpResult<crate::FinalTask> {
        crate::check_mrtr_operation(cx, Some(cancellation), deadline)?;
        let result = self.get_task_final(cx, cancellation, task_id).await?;
        crate::check_mrtr_operation(cx, Some(cancellation), deadline)?;
        Ok(result.task)
    }

    #[cfg(feature = "tasks")]
    async fn update_apps_task(
        &mut self,
        cx: &Cx,
        cancellation: &McpRequestCancellation,
        deadline: Instant,
        task: &crate::FinalTask,
        responses: crate::FinalTaskInputResponses,
    ) -> McpResult<()> {
        crate::check_mrtr_operation(cx, Some(cancellation), deadline)?;
        self.update_task_final(cx, cancellation, task, responses).await?;
        crate::check_mrtr_operation(cx, Some(cancellation), deadline)
    }
}

impl McpAppsMemoryClientWirePolicy<'_> {
    async fn settle_apps_transport(&mut self) -> Result<(), McpAppsHostError> {
        let deadline = match self.cleanup_deadline {
            Some(deadline) => deadline,
            None => {
                let timeout = self
                    .client
                    .timeout_policy
                    .absolute_timeout()
                    .min(SEND_ADMISSION_TIMEOUT);
                let deadline = Instant::now().checked_add(timeout).ok_or_else(|| {
                    McpError::internal_error("Apps memory cleanup deadline exceeds the clock range")
                })?;
                // Retain this election across a dropped cleanup future. The
                // next Host drive may resume it but cannot restart its budget.
                self.cleanup_deadline = Some(deadline);
                deadline
            }
        };
        let cx = self.cleanup_cx.clone();
        let cancellation = McpRequestCancellation::new();
        let result = crate::wait_for_mrtr_operation(
            &cx,
            Some(&cancellation),
            deadline,
            self.client.flush_controls(&cx, &cancellation, deadline),
        )
        .await;
        if result.is_ok() {
            self.cleanup_deadline = None;
        }
        // A stopped context or full queue never removes an uncommitted control.
        // It remains owned by the memory executor after this Host is dropped.
        result.map_err(McpAppsHostError::Core)
    }
}

impl McpAppsWireHostPolicy for McpAppsMemoryClientWirePolicy<'_> {
    fn transport_cleanup(&mut self) -> McpAppsWireHostCleanup<'_> {
        McpAppsWireHostCleanup::native(self.settle_apps_transport())
    }

    async fn dispatch_reused_request(
        &mut self,
        cx: &Cx,
        cancellation: &McpRequestCancellation,
        method: McpAppsRoutedMethod,
        parameters: Option<Value>,
    ) -> Result<Value, McpAppsHostError> {
        self.dispatch_reused_request_with_effects(
            cx,
            cancellation,
            method,
            parameters,
            &mut (),
        )
        .await
    }

    async fn dispatch_reused_request_with_effects<E: McpAppsWireHostEffects>(
        &mut self,
        cx: &Cx,
        cancellation: &McpRequestCancellation,
        method: McpAppsRoutedMethod,
        parameters: Option<Value>,
        effects: &mut E,
    ) -> Result<Value, McpAppsHostError> {
        checkpoint(cx, cancellation)?;
        if matches!(
            method,
            McpAppsRoutedMethod::ToolsCall | McpAppsRoutedMethod::ResourcesRead
        ) {
            return dispatch_apps_server_input(
                self.client, cx, cancellation, method, parameters, effects,
            )
            .await;
        }
        let core_method = match method {
            McpAppsRoutedMethod::ResourcesList => "resources/list",
            McpAppsRoutedMethod::ResourceTemplatesList => "resources/templates/list",
            McpAppsRoutedMethod::PromptsList => "prompts/list",
            _ => return Err(McpError::invalid_params("Unsupported Apps reused method").into()),
        };
        let (deadline, parameters) = self.client.prepare_apps_server_input(
            cx,
            parameters.unwrap_or_else(|| serde_json::json!({})),
        )?;
        let result = crate::wait_for_mrtr_operation(
            cx,
            Some(cancellation),
            deadline,
            self.client.request_apps_core_prepared(
                cx,
                cancellation,
                deadline,
                core_method,
                parameters,
                false,
            ),
        )
        .await?;
        project_reused_core_result(method, result).map_err(McpAppsHostError::Core)
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::future::{Future, poll_fn};
    use std::pin::Pin;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex};
    use std::task::Poll;
    use std::time::Duration;

    use asupersync::runtime::RuntimeBuilder;
    use fastmcp_protocol::extensions::{
        ClientExtensionDiscovery, ExtensionDescriptorRegistry,
        official_mcp_apps_negotiation_resolver, register_official_mcp_apps_extension,
    };
    use fastmcp_protocol::{
        ClientCapabilities, ClientInfo, FinalCoreResult, JsonRpcMessage, JsonRpcRequest,
        JsonRpcResponse, MCP_APPS_HOST_VIEW_PROTOCOL_VERSION, McpAppsBridgeImplementation,
        McpAppsBridgeLifecycle, McpAppsPinnedHostCapabilities, McpAppsPinnedHostContext,
        RequestId, SamplingCapability,
    };
    use fastmcp_transport::memory::{MemoryTransport, create_memory_transport_pair_with_capacity};
    use serde_json::json;

    use super::*;
    use crate::mcp_apps::{
        McpAppsCatalogBinding, McpAppsInMemoryWireViewTransport, mcp_apps_in_memory_wire_pair,
    };
    use crate::ReverseRequestHandlers;

    const APPS: &str = fastmcp_protocol::extensions::OFFICIAL_MCP_APPS_EXTENSION_ID;
    const CAPS: &str = crate::FINAL_CLIENT_CAPABILITIES_META_KEY;

    fn run<F: Future<Output = ()>>(test: impl FnOnce(Cx) -> F) {
        let runtime = RuntimeBuilder::current_thread()
            .blocking_threads(0, 0)
            .build()
            .unwrap();
        runtime.block_on(async {
            let cx = Cx::current().unwrap();
            assert!(cx.blocking_pool_handle().is_none());
            asupersync::time::timeout(cx.now(), Duration::from_secs(8), test(cx))
                .await
                .expect("memory Apps must progress on the caller runtime");
        });
        assert!(runtime.shutdown_timeout(Duration::from_secs(1)));
    }

    fn settings(mime: &str) -> McpAppsClientSettings {
        McpAppsClientSettings::new(vec![mime.to_owned()]).unwrap()
    }

    fn builder() -> MemoryClientBuilder {
        MemoryClient::builder(ClientInfo {
            name: "apps-memory-client".to_owned(),
            version: "1".to_owned(),
        })
        .mcp_apps(settings(fastmcp_protocol::MCP_APPS_HTML_MIME_TYPE))
        .capabilities(ClientCapabilities {
            sampling: Some(SamplingCapability::default()),
            ..ClientCapabilities::default()
        })
    }

    async fn respond(peer: &mut MemoryTransport, cx: &Cx, id: i64, result: Value) {
        peer.send_async(
            cx,
            &JsonRpcMessage::Response(JsonRpcResponse::success(RequestId::Number(id), result)),
        )
        .await
        .unwrap();
    }

    async fn next_request(peer: &mut MemoryTransport, cx: &Cx) -> JsonRpcRequest {
        let JsonRpcMessage::Request(request) = peer.recv_async(cx).await.unwrap() else {
            panic!("expected a client request or cancellation notification");
        };
        request
    }

    async fn connect(
        cx: &Cx,
        builder: MemoryClientBuilder,
        extensions: Value,
        capacity: usize,
    ) -> (MemoryClient, MemoryTransport, JsonRpcRequest) {
        let (transport, mut peer) = create_memory_transport_pair_with_capacity(capacity);
        respond(&mut peer, cx, 1, json!({
            "resultType": "complete", "supportedVersions": ["2026-07-28"],
            "capabilities": {"tools": {}, "resources": {}, "prompts": {}, "extensions": extensions},
            "ttlMs": 0, "cacheScope": "private"
        }))
        .await;
        let client = builder.connect(cx, transport).await.unwrap();
        let discovery = next_request(&mut peer, cx).await;
        assert_eq!(discovery.method, "server/discover");
        assert_eq!(discovery.id, Some(RequestId::Number(1)));
        (client, peer, discovery)
    }

    fn configuration() -> McpAppsWireHostConfiguration {
        McpAppsWireHostConfiguration {
            host_info: McpAppsBridgeImplementation {
                name: "memory-apps-host".to_owned(),
                version: "1".to_owned(),
            },
            host_capabilities: McpAppsPinnedHostCapabilities {
                server_tools: Some(Default::default()),
                server_resources: Some(Default::default()),
                ..McpAppsPinnedHostCapabilities::default()
            },
            host_context: McpAppsPinnedHostContext::default(),
        }
    }

    async fn enqueue(
        view: &mut McpAppsInMemoryWireViewTransport,
        cx: &Cx,
        id: &str,
        method: &str,
        params: Value,
    ) {
        view.send_to_host(cx, json!({
            "jsonrpc": "2.0", "id": id, "method": method, "params": params,
        }).to_string())
        .await
        .unwrap();
    }

    async fn view_response(view: &mut McpAppsInMemoryWireViewTransport, cx: &Cx) -> Value {
        serde_json::from_str(&view.receive_from_host(cx).await.unwrap()).unwrap()
    }

    async fn activate<T: McpAppsWireBridgeTransport, P: McpAppsWireHostPolicy>(
        host: &mut McpAppsWireHost<T, P>,
        view: &mut McpAppsInMemoryWireViewTransport,
        cx: &Cx,
    ) {
        enqueue(view, cx, "initialize", "ui/initialize", json!({
            "appInfo": {"name": "view", "version": "1"}, "appCapabilities": {},
            "protocolVersion": MCP_APPS_HOST_VIEW_PROTOCOL_VERSION,
        }))
        .await;
        host.process_next(cx).await.unwrap();
        assert!(view_response(view, cx).await.get("result").is_some());
        view.send_to_host(cx, json!({
            "jsonrpc": "2.0", "method": "ui/notifications/initialized",
        }).to_string())
        .await
        .unwrap();
        host.process_next(cx).await.unwrap();
        assert_eq!(host.lifecycle(), McpAppsBridgeLifecycle::Active);
    }

    async fn request<T: McpAppsWireBridgeTransport, P: McpAppsWireHostPolicy>(
        host: &mut McpAppsWireHost<T, P>,
        view: &mut McpAppsInMemoryWireViewTransport,
        cx: &Cx,
        id: &str,
        method: &str,
        params: Value,
    ) -> Value {
        enqueue(view, cx, id, method, params).await;
        host.process_next(cx).await.unwrap();
        let response = view_response(view, cx).await;
        assert_eq!(response["id"], id);
        response
    }

    async fn cancel_view(view: &mut McpAppsInMemoryWireViewTransport, cx: &Cx, id: &str) {
        view.send_to_host(cx, json!({
            "jsonrpc": "2.0", "method": "notifications/cancelled",
            "params": {"requestId": id},
        }).to_string())
        .await
        .unwrap();
    }

    async fn poll_pending<F: Future>(operation: &mut Pin<Box<F>>) {
        poll_fn(|task| {
            assert!(operation.as_mut().poll(task).is_pending());
            Poll::Ready(())
        })
        .await;
    }

    fn complete(text: &str) -> Value {
        json!({"resultType": "complete", "content": [{"type": "text", "text": text}]})
    }

    fn tools() -> Value {
        json!({"resultType": "complete", "tools": [], "ttlMs": 0, "cacheScope": "private"})
    }

    fn callable_tools(names: &[&str]) -> Value {
        json!({"resultType": "complete", "tools": names.iter().map(|name| json!({
            "name": name, "inputSchema": {"type": "object"}
        })).collect::<Vec<_>>(), "ttlMs": 0, "cacheScope": "private"})
    }

    fn input_required(state: &str) -> Value {
        json!({
            "resultType": "input_required", "requestState": state,
            "inputRequests": {"sample": {"method": "sampling/createMessage", "params": {
                "messages": [{"role": "user", "content": {"type": "text", "text": "Review this View"}}],
                "maxTokens": 32,
            }}},
        })
    }

    fn input_response() -> Value {
        json!({"sample": {
            "role": "assistant", "model": "host-approved",
            "content": {"type": "text", "text": "approved answer"}, "stopReason": "endTurn",
        }})
    }

    struct InputEffects {
        allowed: bool,
        calls: Arc<Mutex<Vec<Value>>>,
    }

    #[allow(clippy::unused_async_trait_impl, reason = "public async Host consent callback")]
    impl McpAppsWireHostEffects for InputEffects {
        async fn resolve_server_input(
            &mut self,
            cx: &Cx,
            cancellation: &McpRequestCancellation,
            method: McpAppsRoutedMethod,
            params: &Value,
            required: &fastmcp_protocol::InputRequiredResult,
        ) -> Result<fastmcp_protocol::FinalInputResponses, McpAppsHostError> {
            checkpoint(cx, cancellation)?;
            assert!(matches!(method, McpAppsRoutedMethod::ToolsCall | McpAppsRoutedMethod::ResourcesRead));
            self.calls.lock().unwrap().push(json!({"params": params, "state": required.request_state()}));
            if !self.allowed {
                return Err(McpError::invalid_request("This View did not grant input consent").into());
            }
            Ok(serde_json::from_value(input_response()).unwrap())
        }
    }

    #[test]
    fn memory_apps_requires_bilateral_receipt_and_keeps_incompatible_peer_core_usable() {
        run(|cx| async move {
            for (mime, extensions, active) in [
                (fastmcp_protocol::MCP_APPS_HTML_MIME_TYPE, json!({(APPS): {}}), true),
                (fastmcp_protocol::MCP_APPS_HTML_MIME_TYPE, json!({}), false),
                ("application/json", json!({(APPS): {}}), false),
                (fastmcp_protocol::MCP_APPS_HTML_MIME_TYPE, json!({(APPS): {"unexpected": true}}), false),
            ] {
                let (mut client, mut peer, discovery) = connect(
                    &cx, builder().mcp_apps(settings(mime)), extensions, 1,
                ).await;
                assert_eq!(discovery.params.unwrap()["_meta"][CAPS]["extensions"][APPS],
                    json!({"mimeTypes": [mime]}));
                assert_eq!(client.mcp_apps_active(), active);
                let (transport, _view) = mcp_apps_in_memory_wire_pair(1);
                assert_eq!(client.mcp_apps_wire_host(&cx, transport, configuration()).is_ok(), active);
                respond(&mut peer, &cx, 2, tools()).await;
                assert!(matches!(
                    client.list_tools(&cx, &McpRequestCancellation::new(), None).await.unwrap(),
                    CoreResult::Final(FinalCoreResult::ToolsList { .. }),
                ));
                let ordinary = next_request(&mut peer, &cx).await;
                assert_eq!(ordinary.id, Some(RequestId::Number(2)));
                assert_eq!(ordinary.params.unwrap()["_meta"][CAPS]["extensions"].get(APPS).is_some(), active);
                client.close(&cx).unwrap();
                assert!(!client.mcp_apps_active());
                let (transport, _view) = mcp_apps_in_memory_wire_pair(1);
                assert!(matches!(
                    client.mcp_apps_wire_host(&cx, transport, configuration()),
                    Err(McpAppsHostError::NotNegotiated),
                ));
            }
            let (transport, mut peer) = create_memory_transport_pair_with_capacity(1);
            let raw = ClientCapabilities {
                extensions: Some(BTreeMap::from([(APPS.to_owned(), json!({
                    "mimeTypes": [fastmcp_protocol::MCP_APPS_HTML_MIME_TYPE],
                }))])),
                ..ClientCapabilities::default()
            };
            assert!(MemoryClient::builder(ClientInfo { name: "raw".into(), version: "1".into() })
                .capabilities(raw).connect(&cx, transport).await.is_err());
            assert!(peer.recv_async(&cx).await.is_err(), "raw advertisement cannot publish discovery or mint authority");
        });
    }

    #[test]
    fn memory_apps_generic_registry_owns_settings_and_cannot_fall_back_to_dedicated_html() {
        run(|cx| async move {
            for (generic_mime, dedicated_mime, active) in [
                (fastmcp_protocol::MCP_APPS_HTML_MIME_TYPE, "application/json", true),
                ("application/json", fastmcp_protocol::MCP_APPS_HTML_MIME_TYPE, false),
            ] {
                let mut descriptors = ExtensionDescriptorRegistry::new();
                let id = register_official_mcp_apps_extension(&mut descriptors).unwrap();
                let configured = builder().mcp_apps(settings(dedicated_mime)).extension_registry(
                    descriptors,
                    ClientExtensionDiscovery {
                        extensions: BTreeMap::from([(id, settings(generic_mime).to_extension_settings())]),
                    },
                    official_mcp_apps_negotiation_resolver,
                ).unwrap();
                let (mut client, mut peer, discovery) = connect(&cx, configured, json!({(APPS): {}}), 1).await;
                assert_eq!(discovery.params.unwrap()["_meta"][CAPS]["extensions"][APPS],
                    json!({"mimeTypes": [generic_mime]}));
                assert_eq!(client.mcp_apps_active(), active);
                let (transport, _view) = mcp_apps_in_memory_wire_pair(1);
                assert_eq!(client.mcp_apps_wire_host(&cx, transport, configuration()).is_ok(), active);
                respond(&mut peer, &cx, 2, tools()).await;
                client.list_tools(&cx, &McpRequestCancellation::new(), None).await.unwrap();
                assert_eq!(next_request(&mut peer, &cx).await.params.unwrap()["_meta"][CAPS]["extensions"][APPS],
                    json!({"mimeTypes": [generic_mime]}));
                client.close(&cx).unwrap();
            }
        });
    }

    #[test]
    fn memory_apps_public_host_forwards_reused_methods_with_fresh_core_ids() {
        run(|cx| async move {
            let (mut client, mut peer, _) = connect(&cx, builder(), json!({(APPS): {}}), 2).await;
            let (transport, mut view) = mcp_apps_in_memory_wire_pair(8);
            let mut host = client.mcp_apps_wire_host(&cx, transport, configuration()).unwrap();
            host.bind_server_catalogs(McpAppsCatalogBinding {
                view_id: "view".into(), resource_uri: "ui://view".into(),
                origin: "https://view.example".into(), principal_id: "owner".into(),
                server_id: "memory-peer".into(), revision: "one".into(),
            }, true).unwrap();
            activate(&mut host, &mut view, &cx).await;
            for (offset, (method, params, payload)) in [
                ("tools/call", json!({"name": "ordinary"}), json!({"content": [{"type": "text", "text": "ordinary"}]})),
                ("resources/read", json!({"uri": "test://entry"}), json!({"contents": [{"uri": "test://entry", "text": "resource"}], "ttlMs": 0, "cacheScope": "private"})),
                ("resources/list", json!({}), json!({"resources": [], "ttlMs": 0, "cacheScope": "private"})),
                ("resources/templates/list", json!({}), json!({"resourceTemplates": [], "ttlMs": 0, "cacheScope": "private"})),
                ("prompts/list", json!({}), json!({"prompts": [], "ttlMs": 0, "cacheScope": "private"})),
            ].into_iter().enumerate() {
                let id = i64::try_from(offset).unwrap() + 3;
                if method == "tools/call" {
                    respond(&mut peer, &cx, 2, callable_tools(&["ordinary"])).await;
                }
                let mut result = payload.clone();
                result["resultType"] = json!("complete");
                respond(&mut peer, &cx, id, result).await;
                let response = request(&mut host, &mut view, &cx, "reusable-view-id", method, params.clone()).await;
                if method == "resources/read" {
                    assert_eq!(response["result"]["contents"], payload["contents"]);
                } else {
                    assert_eq!(response["result"], payload);
                }
                assert!(response["result"].get("resultType").is_none());
                if method == "tools/call" {
                    let catalog = next_request(&mut peer, &cx).await;
                    assert_eq!(catalog.id, Some(RequestId::Number(2)));
                    assert_eq!(catalog.method, "tools/list");
                }
                let forwarded = next_request(&mut peer, &cx).await;
                assert_eq!(forwarded.id, Some(RequestId::Number(id)));
                assert_eq!(forwarded.method, method);
                let forwarded = forwarded.params.unwrap();
                assert!(!forwarded.to_string().contains("reusable-view-id"));
                assert_eq!(forwarded["_meta"]["io.modelcontextprotocol/clientInfo"]["name"], "apps-memory-client");
                for (key, value) in params.as_object().unwrap() {
                    assert_eq!(&forwarded[key], value);
                }
            }
            drop(host);
            client.close(&cx).unwrap();
            assert!(peer.recv_async(&cx).await.is_err(), "no Apps envelope or extra core request");
        });
    }

    #[test]
    fn memory_apps_tool_visibility_rechecks_before_every_call() {
        run(|cx| async move {
            let (mut client, mut peer, _) = connect(&cx, builder(), json!({(APPS): {}}), 4).await;
            let (transport, mut view) = mcp_apps_in_memory_wire_pair(8);
            let mut host = client
                .mcp_apps_wire_host(&cx, transport, configuration())
                .unwrap();
            activate(&mut host, &mut view, &cx).await;
            let mut page = callable_tools(&["selected"]);
            page["ttlMs"] = json!(60_000);
            page["tools"][0]["_meta"] = json!({"ui": {"visibility": ["app"]}});
            respond(&mut peer, &cx, 2, page.clone()).await;
            respond(&mut peer, &cx, 3, complete("visible")).await;
            assert_eq!(
                request(
                    &mut host,
                    &mut view,
                    &cx,
                    "same-view",
                    "tools/call",
                    json!({"name":"selected"})
                )
                .await["result"]["content"][0]["text"],
                "visible"
            );
            let catalog = next_request(&mut peer, &cx).await;
            assert_eq!(catalog.method, "tools/list");
            assert_eq!(catalog.id, Some(RequestId::Number(2)));
            let invoked = next_request(&mut peer, &cx).await;
            assert_eq!(invoked.method, "tools/call");
            assert_eq!(invoked.id, Some(RequestId::Number(3)));

            page["tools"][0]["_meta"]["ui"]["visibility"] = json!(["model"]);
            respond(&mut peer, &cx, 4, page).await;
            let denied = request(
                &mut host,
                &mut view,
                &cx,
                "same-view",
                "tools/call",
                json!({"name":"selected"}),
            )
            .await;
            assert!(denied.get("error").is_some());
            assert!(denied.get("result").is_none());
            assert_eq!(host.lifecycle(), McpAppsBridgeLifecycle::Active);
            let fresh = next_request(&mut peer, &cx).await;
            assert_eq!(fresh.method, "tools/list");
            assert_eq!(fresh.id, Some(RequestId::Number(4)));
            drop(host);
            client.close(&cx).unwrap();
            assert!(
                peer.recv_async(&cx).await.is_err(),
                "revoked visibility sends no tools/call"
            );
        });
    }

    #[test]
    fn memory_apps_mrtr_uses_view_consent_and_never_installed_connection_handlers() {
        run(|cx| async move {
            for allowed in [true, false] {
                let connection_calls = Arc::new(AtomicUsize::new(0));
                let observed = Arc::clone(&connection_calls);
                let handlers = ReverseRequestHandlers::new().with_modern_sampling_create_message(
                    move |_, _, _| {
                        observed.fetch_add(1, Ordering::AcqRel);
                        Box::pin(async { Err(McpError::internal_error("connection consent cannot authorize this View")) })
                    },
                );
                let (mut client, mut peer, _) = connect(
                    &cx, builder().reverse_request_handlers(handlers), json!({(APPS): {}}), 4,
                ).await;
                let calls = Arc::new(Mutex::new(Vec::new()));
                let (transport, mut view) = mcp_apps_in_memory_wire_pair(8);
                let mut host = client.mcp_apps_wire_host(&cx, transport, configuration()).unwrap()
                    .with_effects(InputEffects { allowed, calls: Arc::clone(&calls) });
                activate(&mut host, &mut view, &cx).await;
                respond(&mut peer, &cx, 2, callable_tools(&["interactive"])).await;
                respond(&mut peer, &cx, 3, input_required("private-server-state")).await;
                if allowed {
                    respond(&mut peer, &cx, 4, complete("Host approved")).await;
                }
                let original = json!({"name": "interactive", "arguments": {"value": "résumé 東京"}});
                let response = request(&mut host, &mut view, &cx, "view-input", "tools/call", original.clone()).await;
                assert_eq!(response.get("result").is_some(), allowed);
                assert_eq!(response.get("error").is_some(), !allowed);
                assert!(!response.to_string().contains("private-server-state"));
                assert_eq!(calls.lock().unwrap().as_slice(), &[json!({
                    "params": original, "state": "private-server-state",
                })]);
                assert_eq!(next_request(&mut peer, &cx).await.method, "tools/list");
                assert_eq!(next_request(&mut peer, &cx).await.id, Some(RequestId::Number(3)));
                if allowed {
                    let continuation = next_request(&mut peer, &cx).await;
                    assert_eq!(continuation.id, Some(RequestId::Number(4)));
                    let params = continuation.params.unwrap();
                    assert_eq!(params["name"], original["name"]);
                    assert_eq!(params["arguments"], original["arguments"]);
                    assert_eq!(params["requestState"], "private-server-state");
                    assert_eq!(params["inputResponses"], input_response());
                }
                // Replacing effects removes the earlier Host approval too.
                let mut host = host.with_effects(());
                let refused_id = if allowed { 6 } else { 5 };
                respond(&mut peer, &cx, refused_id - 1, callable_tools(&["interactive"])).await;
                respond(&mut peer, &cx, refused_id, input_required("default-refuses")).await;
                assert!(request(&mut host, &mut view, &cx, "view-input", "tools/call", original)
                    .await.get("error").is_some());
                assert_eq!(next_request(&mut peer, &cx).await.method, "tools/list");
                assert_eq!(next_request(&mut peer, &cx).await.id, Some(RequestId::Number(refused_id)));
                let healthy_id = refused_id + 2;
                respond(&mut peer, &cx, healthy_id - 1, callable_tools(&["healthy"])).await;
                respond(&mut peer, &cx, healthy_id, complete("healthy")).await;
                assert_eq!(request(&mut host, &mut view, &cx, "healthy", "tools/call", json!({"name": "healthy"}))
                    .await["result"]["content"][0]["text"], "healthy");
                assert_eq!(next_request(&mut peer, &cx).await.method, "tools/list");
                let healthy = next_request(&mut peer, &cx).await;
                assert_eq!(healthy.id, Some(RequestId::Number(healthy_id)));
                assert!(healthy.params.unwrap().get("inputResponses").is_none());
                assert_eq!(connection_calls.load(Ordering::Acquire), 0);
                drop(host);
                client.close(&cx).unwrap();
                assert!(peer.recv_async(&cx).await.is_err(), "refusal never queues an unauthorized continuation");
            }
        });
    }

    #[test]
    fn memory_apps_dropped_backpressured_cleanup_resumes_without_losing_sibling_result() {
        run(|cx| async move {
            for cancel_tool_call in [false, true] {
                let (mut client, mut peer, _) =
                    connect(&cx, builder(), json!({(APPS): {}}), 1).await;
                let token = McpRequestCancellation::new();
                let mut sibling = client
                    .execute_core(&cx, &token, "tools/list", json!({}))
                    .await
                    .unwrap();
                assert_eq!(
                    next_request(&mut peer, &cx).await.id,
                    Some(RequestId::Number(2))
                );
                let executor = client.executor.clone();
                let (transport, mut view) = mcp_apps_in_memory_wire_pair(8);
                let mut host = client
                    .mcp_apps_wire_host(&cx, transport, configuration())
                    .unwrap();
                activate(&mut host, &mut view, &cx).await;
                enqueue(
                    &mut view,
                    &cx,
                    "cancelled-view",
                    "tools/call",
                    json!({"name": "slow"}),
                )
                .await;
                let cancelled_id = if cancel_tool_call { 4 } else { 3 };
                let mut drive = Box::pin(host.process_next(&cx));
                for pending_id in 3..=cancelled_id {
                    asupersync::time::timeout(
                        cx.now(),
                        Duration::from_secs(2),
                        poll_fn(|task| {
                            assert!(drive.as_mut().poll(task).is_pending());
                            if executor.pending_records().iter().any(|record| {
                                record.request_id == RequestId::Number(pending_id)
                                    && record.send_committed
                            }) {
                                Poll::Ready(())
                            } else {
                                task.waker().wake_by_ref();
                                Poll::Pending
                            }
                        }),
                    )
                    .await
                    .expect("the exact Apps request is published before cancellation");
                    if pending_id != cancelled_id {
                        let catalog = next_request(&mut peer, &cx).await;
                        assert_eq!(catalog.id, Some(RequestId::Number(3)));
                        assert_eq!(catalog.method, "tools/list");
                        respond(&mut peer, &cx, 3, callable_tools(&["slow"])).await;
                    }
                }
                // Leave either the catalog or the real tool call in the only
                // outbound slot so its exact cancellation cannot commit yet.
                cancel_view(&mut view, &cx, "cancelled-view").await;
                poll_pending(&mut drive).await;
                drop(drive);
                let slow = next_request(&mut peer, &cx).await;
                assert_eq!(slow.id, Some(RequestId::Number(cancelled_id)));
                if cancel_tool_call {
                    assert_eq!(slow.method, "tools/call");
                    assert_eq!(slow.params.unwrap()["name"], "slow");
                } else {
                    assert_eq!(slow.method, "tools/list");
                    assert!(slow.params.unwrap().get("name").is_none());
                }
                respond(&mut peer, &cx, 2, tools()).await;
                let mut serving = cx
                    .spawn(move |peer_cx| async move {
                        let cancellation = next_request(&mut peer, &peer_cx).await;
                        assert_eq!(cancellation.method, "notifications/cancelled");
                        assert!(cancellation.id.is_none());
                        assert_eq!(
                            cancellation.params.unwrap(),
                            json!({"requestId": cancelled_id})
                        );
                        let catalog = next_request(&mut peer, &peer_cx).await;
                        assert_eq!(catalog.id, Some(RequestId::Number(cancelled_id + 1)));
                        assert_eq!(catalog.method, "tools/list");
                        let late = if cancel_tool_call {
                            complete("late cancelled response")
                        } else {
                            tools()
                        };
                        respond(&mut peer, &peer_cx, cancelled_id, late).await;
                        respond(
                            &mut peer,
                            &peer_cx,
                            cancelled_id + 1,
                            callable_tools(&["healthy"]),
                        )
                        .await;
                        let healthy = next_request(&mut peer, &peer_cx).await;
                        assert_eq!(healthy.id, Some(RequestId::Number(cancelled_id + 2)));
                        assert_eq!(healthy.method, "tools/call");
                        assert_eq!(healthy.params.unwrap()["name"], "healthy");
                        respond(&mut peer, &peer_cx, cancelled_id + 2, complete("healthy")).await;
                        peer
                    })
                    .unwrap();
                let response = request(
                    &mut host,
                    &mut view,
                    &cx,
                    "healthy-view",
                    "tools/call",
                    json!({"name": "healthy"}),
                )
                .await;
                assert_eq!(response["result"]["content"][0]["text"], "healthy");
                assert_eq!(host.lifecycle(), McpAppsBridgeLifecycle::Active);
                drop(host);
                assert!(
                    matches!(client.next_event(&cx, &token, &mut sibling).await.unwrap(),
                Some(MemoryRequestEvent::Result(result)) if matches!(*result, CoreResult::Final(FinalCoreResult::ToolsList { .. })))
                );
                assert!(!token.is_cancel_requested());
                assert!(cx.checkpoint().is_ok());
                let mut peer = serving.join(&cx).await.unwrap();
                client.close(&cx).unwrap();
                assert!(
                    peer.recv_async(&cx).await.is_err(),
                    "exactly one cancellation and no replay"
                );
            }
        });
    }

    #[test]
    fn memory_apps_stopped_cleanup_context_retains_control_for_later_healthy_client_drive() {
        run(|cx| async move {
            for cancel_tool_call in [false, true] {
                let (mut client, mut peer, _) =
                    connect(&cx, builder(), json!({(APPS): {}}), 1).await;
                let executor = client.executor.clone();
                let cleanup_cx = Cx::for_request();
                let (transport, mut view) = mcp_apps_in_memory_wire_pair(8);
                let mut host = client
                    .mcp_apps_wire_host(&cleanup_cx, transport, configuration())
                    .unwrap();
                activate(&mut host, &mut view, &cx).await;
                enqueue(
                    &mut view,
                    &cx,
                    "stopped-cleanup",
                    "tools/call",
                    json!({"name": "slow"}),
                )
                .await;
                let cancelled_id = if cancel_tool_call { 3 } else { 2 };
                let mut drive = Box::pin(host.process_next(&cx));
                for pending_id in 2..=cancelled_id {
                    asupersync::time::timeout(
                        cx.now(),
                        Duration::from_secs(2),
                        poll_fn(|task| {
                            assert!(drive.as_mut().poll(task).is_pending());
                            if executor.pending_records().iter().any(|record| {
                                record.request_id == RequestId::Number(pending_id)
                                    && record.send_committed
                            }) {
                                Poll::Ready(())
                            } else {
                                task.waker().wake_by_ref();
                                Poll::Pending
                            }
                        }),
                    )
                    .await
                    .expect("the exact Apps request is published before its cleanup owner stops");
                    if pending_id != cancelled_id {
                        let catalog = next_request(&mut peer, &cx).await;
                        assert_eq!(catalog.id, Some(RequestId::Number(2)));
                        assert_eq!(catalog.method, "tools/list");
                        respond(&mut peer, &cx, 2, callable_tools(&["slow"])).await;
                    }
                }
                cleanup_cx.set_cancel_requested(true);
                cancel_view(&mut view, &cx, "stopped-cleanup").await;
                assert!(matches!(drive.await, Err(McpAppsHostError::Core(_))));
                assert_eq!(host.lifecycle(), McpAppsBridgeLifecycle::Closed);
                drop(host);
                let abandoned = next_request(&mut peer, &cx).await;
                assert_eq!(abandoned.id, Some(RequestId::Number(cancelled_id)));
                if cancel_tool_call {
                    assert_eq!(abandoned.method, "tools/call");
                    assert_eq!(abandoned.params.unwrap()["name"], "slow");
                } else {
                    assert_eq!(abandoned.method, "tools/list");
                    assert!(abandoned.params.unwrap().get("name").is_none());
                }
                assert!(
                    client.mcp_apps_active(),
                    "a stopped cleanup owner does not retire the shared client"
                );
                let mut serving = cx
                    .spawn(move |peer_cx| async move {
                        let control = next_request(&mut peer, &peer_cx).await;
                        assert_eq!(control.method, "notifications/cancelled");
                        assert!(control.id.is_none());
                        assert_eq!(control.params.unwrap(), json!({"requestId": cancelled_id}));
                        let ordinary = next_request(&mut peer, &peer_cx).await;
                        assert_eq!(ordinary.id, Some(RequestId::Number(cancelled_id + 1)));
                        assert_eq!(ordinary.method, "tools/list");
                        let late = if cancel_tool_call {
                            complete("late cancelled response")
                        } else {
                            tools()
                        };
                        respond(&mut peer, &peer_cx, cancelled_id, late).await;
                        respond(&mut peer, &peer_cx, cancelled_id + 1, tools()).await;
                        peer
                    })
                    .unwrap();
                assert!(matches!(
                    client
                        .list_tools(&cx, &McpRequestCancellation::new(), None)
                        .await
                        .unwrap(),
                    CoreResult::Final(FinalCoreResult::ToolsList { .. })
                ));
                let mut peer = serving.join(&cx).await.unwrap();
                client.close(&cx).unwrap();
                assert!(
                    peer.recv_async(&cx).await.is_err(),
                    "deferred cancellation is sent exactly once without replay"
                );
            }
        });
    }

    #[cfg(feature = "tasks")]
    mod tasks {
        use super::*;
        use crate::McpAppsServerTaskPolicy;

        const TASKS: &str = fastmcp_protocol::OFFICIAL_TASKS_EXTENSION_ID;

        fn snapshot(status: &str, creation: bool) -> Value {
            let mut value = json!({
                "resultType": if creation { "task" } else { "complete" },
                "taskId": "private-server-task", "status": status,
                "createdAt": "2026-07-28T12:00:00.000Z",
                "lastUpdatedAt": "2026-07-28T12:00:01.000Z",
                "ttlMs": null, "pollIntervalMs": 1, "statusMessage": "Host-private status",
            });
            match status {
                "input_required" => {
                    value["inputRequests"] = input_required("unused")["inputRequests"].clone();
                }
                "completed" => {
                    value["result"] = json!({"content": [{"type": "text", "text": "Task completed"}]});
                }
                _ => {}
            }
            value
        }

        struct TaskEffects {
            creation: bool,
            input: InputEffects,
            snapshots: Arc<AtomicUsize>,
        }

        #[allow(clippy::unused_async_trait_impl, reason = "public async Host consent callbacks")]
        impl McpAppsWireHostEffects for TaskEffects {
            async fn server_task_policy(
                &mut self,
                cx: &Cx,
                cancellation: &McpRequestCancellation,
                params: &Value,
            ) -> Result<Option<McpAppsServerTaskPolicy>, McpAppsHostError> {
                checkpoint(cx, cancellation)?;
                if !self.creation || params["name"] != "job" {
                    return Ok(None);
                }
                Ok(Some(McpAppsServerTaskPolicy::new(
                    Duration::from_millis(1), 8, 64 * 1024,
                )?))
            }

            async fn approve_server_task(
                &mut self,
                cx: &Cx,
                cancellation: &McpRequestCancellation,
                params: &Value,
                task: &crate::FinalTask,
            ) -> Result<(), McpAppsHostError> {
                checkpoint(cx, cancellation)?;
                assert_eq!(params["name"], "job");
                assert_eq!(task.base().task_id.as_str(), "private-server-task");
                self.snapshots.fetch_add(1, Ordering::AcqRel);
                Ok(())
            }

            async fn resolve_server_input(
                &mut self,
                cx: &Cx,
                cancellation: &McpRequestCancellation,
                method: McpAppsRoutedMethod,
                params: &Value,
                required: &fastmcp_protocol::InputRequiredResult,
            ) -> Result<fastmcp_protocol::FinalInputResponses, McpAppsHostError> {
                self.input.resolve_server_input(cx, cancellation, method, params, required).await
            }
        }

        #[test]
        fn memory_apps_composes_mrtr_task_input_update_and_private_terminal_projection() {
            run(|cx| async move {
                let (mut client, mut peer, _) = connect(
                    &cx, builder().with_tasks(), json!({(APPS): {}, (TASKS): {}}), 8,
                ).await;
                let calls = Arc::new(Mutex::new(Vec::new()));
                let snapshots = Arc::new(AtomicUsize::new(0));
                let effects = TaskEffects {
                    creation: true,
                    input: InputEffects { allowed: true, calls: Arc::clone(&calls) },
                    snapshots: Arc::clone(&snapshots),
                };
                let (transport, mut view) = mcp_apps_in_memory_wire_pair(8);
                let mut host = client.mcp_apps_wire_host(&cx, transport, configuration()).unwrap()
                    .with_effects(effects);
                activate(&mut host, &mut view, &cx).await;
                for (id, result) in [
                    (2, callable_tools(&["job"])),
                    (3, input_required("before-task-private-state")),
                    (4, snapshot("working", true)),
                    (5, snapshot("input_required", false)),
                    (6, json!({"resultType": "complete"})),
                    (7, snapshot("completed", false)),
                ] {
                    respond(&mut peer, &cx, id, result).await;
                }
                let original = json!({"name": "job", "arguments": {"value": 7}});
                let response = request(&mut host, &mut view, &cx, "view-task", "tools/call", original.clone()).await;
                assert_eq!(response["result"],
                    json!({"content": [{"type": "text", "text": "Task completed"}]}));
                for private in [
                    "private-server-task", "before-task-private-state", "inputResponses", "Host-private",
                ] {
                    assert!(!response.to_string().contains(private));
                }
                assert_eq!(calls.lock().unwrap().len(), 2, "one ordinary MRTR round and one Task input round");
                assert!(calls.lock().unwrap().iter().all(|call| call["params"] == original));
                assert!(snapshots.load(Ordering::Acquire) > 0);
                let catalog = next_request(&mut peer, &cx).await;
                assert_eq!(catalog.id, Some(RequestId::Number(2)));
                assert_eq!(catalog.method, "tools/list");
                assert!(catalog.params.unwrap()["_meta"][CAPS]["extensions"].get(TASKS).is_none());
                for (id, method) in [
                    (3, "tools/call"), (4, "tools/call"), (5, "tasks/get"),
                    (6, "tasks/update"), (7, "tasks/get"),
                ] {
                    let forwarded = next_request(&mut peer, &cx).await;
                    assert_eq!(forwarded.id, Some(RequestId::Number(id)));
                    assert_eq!(forwarded.method, method);
                    let params = forwarded.params.unwrap();
                    assert_eq!(params["_meta"][CAPS]["extensions"][TASKS], json!({}));
                    assert!(!params.to_string().contains("view-task"));
                    if id == 4 {
                        assert_eq!(params["requestState"], "before-task-private-state");
                        assert_eq!(params["inputResponses"], input_response());
                        assert_eq!(params["arguments"], original["arguments"]);
                    }
                    if method.starts_with("tasks/") {
                        assert_eq!(params["taskId"], "private-server-task");
                    }
                    if id == 6 {
                        assert_eq!(params["inputResponses"], input_response());
                    }
                }
                let mut host = host.with_effects(());
                respond(&mut peer, &cx, 8, callable_tools(&["job"])).await;
                respond(&mut peer, &cx, 9, complete("ordinary")).await;
                assert_eq!(request(&mut host, &mut view, &cx, "view-task", "tools/call", original)
                    .await["result"]["content"][0]["text"], "ordinary");
                assert_eq!(next_request(&mut peer, &cx).await.method, "tools/list");
                let ordinary = next_request(&mut peer, &cx).await;
                assert_eq!(ordinary.id, Some(RequestId::Number(9)));
                assert!(ordinary.params.unwrap()["_meta"][CAPS]["extensions"].get(TASKS).is_none(),
                    "new effects ownership cannot retain prior Task creation consent");
                drop(host);
                client.close(&cx).unwrap();
                assert!(peer.recv_async(&cx).await.is_err(), "observation never implies remote Task cancellation");
            });
        }

        #[test]
        fn memory_apps_tasks_require_both_client_opt_in_and_per_view_creation_consent() {
            run(|cx| async move {
                for (configured, creation) in [(false, true), (true, false)] {
                    let selected = if configured { builder().with_tasks() } else { builder() };
                    let (mut client, mut peer, _) = connect(
                        &cx, selected, json!({(APPS): {}, (TASKS): {}}), 4,
                    ).await;
                    let calls = Arc::new(Mutex::new(Vec::new()));
                    let snapshots = Arc::new(AtomicUsize::new(0));
                    let effects = TaskEffects {
                        creation,
                        input: InputEffects { allowed: true, calls: Arc::clone(&calls) },
                        snapshots: Arc::clone(&snapshots),
                    };
                    let (transport, mut view) = mcp_apps_in_memory_wire_pair(8);
                    let mut host = client.mcp_apps_wire_host(&cx, transport, configuration()).unwrap()
                        .with_effects(effects);
                    activate(&mut host, &mut view, &cx).await;
                    respond(&mut peer, &cx, 2, callable_tools(&["job"])).await;
                    if configured {
                        respond(&mut peer, &cx, 3, snapshot("working", true)).await;
                    }
                    assert!(request(&mut host, &mut view, &cx, "refused-task", "tools/call", json!({"name": "job"}))
                        .await.get("error").is_some());
                    assert_eq!(snapshots.load(Ordering::Acquire), 0);
                    assert!(calls.lock().unwrap().is_empty());
                    assert_eq!(next_request(&mut peer, &cx).await.method, "tools/list");
                    let healthy_id = if configured {
                        let unapproved = next_request(&mut peer, &cx).await;
                        assert_eq!(unapproved.id, Some(RequestId::Number(3)));
                        assert!(unapproved.params.unwrap()["_meta"][CAPS]["extensions"].get(TASKS).is_none());
                        5
                    } else {
                        4
                    };
                    respond(&mut peer, &cx, healthy_id - 1, callable_tools(&["healthy"])).await;
                    respond(&mut peer, &cx, healthy_id, complete("healthy")).await;
                    assert_eq!(request(&mut host, &mut view, &cx, "healthy", "tools/call", json!({"name": "healthy"}))
                        .await["result"]["content"][0]["text"], "healthy");
                    assert_eq!(next_request(&mut peer, &cx).await.method, "tools/list");
                    let healthy = next_request(&mut peer, &cx).await;
                    assert_eq!(healthy.id, Some(RequestId::Number(healthy_id)));
                    assert_eq!(healthy.method, "tools/call", "no unapproved Task lifecycle request");
                    drop(host);
                    client.close(&cx).unwrap();
                    assert!(peer.recv_async(&cx).await.is_err());
                }
            });
        }
    }
}
