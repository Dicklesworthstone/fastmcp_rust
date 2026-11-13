use super::*;
use crate::http_admission::security::scope_policy::request::ScopeRequestPolicy;
use crate::http_admission::security::scope_policy::request::operation::{
    OperationScopePolicy, ScopedOperation,
};
use crate::http_admission::security::scope_policy::{RequiredScopes, ScopeImplicationPolicy};
use crate::{FinalTaskOperation, TaskAccessAction, TaskAccessAuthorizer};
use fastmcp_core::{AuthContext, McpError, McpResult};
use fastmcp_protocol::{FinalTaskId, JsonRpcRequest, JsonRpcResponse};
use std::sync::atomic::{AtomicUsize, Ordering};

fn operation_policy() -> OperationScopePolicy {
    let required = |scope: &str| RequiredScopes::new(vec![scope.to_owned()]).unwrap();
    let methods = ScopeRequestPolicy::new(
        1,
        ScopeImplicationPolicy::new(1, vec![]).unwrap(),
        vec![
            ("tools/call".to_owned(), required("invoke")),
            ("tasks/get".to_owned(), required("manage")),
            ("tasks/update".to_owned(), required("manage")),
            ("tasks/cancel".to_owned(), required("manage")),
            ("subscriptions/listen".to_owned(), required("manage")),
        ],
    ).unwrap();
    OperationScopePolicy::new(
        1,
        methods,
        vec![(ScopedOperation::ToolCall("weather".to_owned()), required("sensitive"))],
    ).unwrap()
}

fn facts(scopes: &[&str]) -> AuthContext {
    let mut auth = relay_test_auth();
    auth.scopes = scopes.iter().map(|scope| (*scope).to_owned()).collect();
    auth.with_verification_valid_until(Instant::now() + Duration::from_secs(120))
}

struct CurrentAuth(Arc<Mutex<AuthContext>>);

impl crate::auth::AuthProvider for CurrentAuth {
    fn authenticate(
        &self,
        _ctx: &McpContext,
        _request: crate::auth::AuthRequest<'_>,
    ) -> McpResult<AuthContext> {
        Ok(self.0.lock().unwrap().clone())
    }
}

fn raw_route() -> BrokerRouteFixture {
    let calls = Arc::new(Mutex::new(Vec::new()));
    let creation = final_task_relay_result();
    let client = ProxyClient::from_backend_with_upstream_binding(
        FinalTaskRelayBackend {
            calls: Arc::clone(&calls),
            task: creation.clone(),
            listener_events: None,
            cancel_after_task_commit: None,
            final_progress: None,
        },
        final_task_relay_binding(ProtocolEra::Modern2026),
        "2026-07-28",
    ).unwrap();
    let client = with_relay_test_retention(client);
    let relay = client.final_tasks_relay().unwrap().unwrap();
    BrokerRouteFixture { client, relay, calls, creation }
}

fn catalog(with_tool: bool) -> ProxyCatalog {
    ProxyCatalog {
        tool_catalog_era: Some(ProtocolEra::Modern2026),
        final_tools: if with_tool { vec![final_catalog_tool()] } else { Vec::new() },
        ..ProxyCatalog::default()
    }
}

async fn dispatch(
    server: &Arc<crate::Server>,
    cx: &Cx,
    connection: &crate::ModernConnection,
    method: &str,
    mut params: serde_json::Value,
) -> JsonRpcResponse {
    params["_meta"] = serde_json::json!({
        "io.modelcontextprotocol/protocolVersion": "2026-07-28",
        "io.modelcontextprotocol/clientCapabilities": {
            "extensions": {fastmcp_protocol::TASKS_EXTENSION: {}}
        }
    });
    let request = JsonRpcRequest::new(method, Some(params), 7311_i64);
    let inbound = crate::InboundRequestContext::with_modern_connection(
        cx.clone(), 7311, crate::InboundRequestTransport::Memory, connection,
    );
    Arc::clone(server).dispatch_with_protocol_policy_owned(
        ProtocolPolicy::ModernOnly, &inbound, request,
        None, None, None, None, McpRequestCancellation::new(), None, Arc::new(|_| {}),
    ).await.expect("correlated proxy response")
}

#[test]
fn proxy_task_router_binding_survives_refresh_and_requires_original_grants() {
    let runtime = asupersync::runtime::RuntimeBuilder::current_thread()
        .with_reactor(asupersync::runtime::reactor::create_reactor().unwrap())
        .build().unwrap();
    let cx = runtime.request_cx_with_budget(asupersync::Budget::default());
    runtime.block_on(async {
        for install in ["builder", "scope", "operation"] {
            let route = raw_route();
            let current_auth = Arc::new(Mutex::new(facts(&["invoke", "sensitive", "manage"])));
            let mut builder = crate::ServerBuilder::new("proxy-operation-grants", "1")
                .auth_provider(CurrentAuth(Arc::clone(&current_auth)))
                .proxy(route.client.clone(), catalog(true)).unwrap();
            let policy = operation_policy();
            if install == "builder" {
                builder = builder.task_access_authorizer(Arc::new(policy.clone()));
            }
            let server = match install {
                "scope" => builder.build().with_scope_authorization(
                    ScopeRequestPolicy::for_operations(policy).unwrap(),
                ).unwrap(),
                "operation" => builder.build().with_operation_scope_authorization(policy).unwrap(),
                _ => builder.build(),
            };
            let server = Arc::new(server);
            let connection = crate::ModernConnection::new();
            let created = dispatch(
                &server, &cx, &connection, "tools/call",
                serde_json::json!({"name": "weather", "arguments": {}}),
            ).await;
            assert!(created.error.is_none(), "{install}: {:?}", created.error);
            let value = created.result.unwrap();
            assert_eq!(value["resultType"], "task");
            let handle: FinalTaskId = serde_json::from_value(value["taskId"].clone()).unwrap();
            let retained = route.relay.tasks.lock().unwrap().tasks[&handle].clone();
            assert_eq!(retained.original_operation.as_ref().unwrap().tool_name(), "weather");

            // New verified facts retain the stable owner, not the old token.
            *current_auth.lock().unwrap() = facts(&["manage", "sensitive", "invoke"]);
            for method in ["tasks/get", "tasks/update", "tasks/cancel"] {
                let mut params = serde_json::json!({"taskId": handle});
                if method == "tasks/update" { params["inputResponses"] = serde_json::json!({}); }
                let response = dispatch(&server, &cx, &connection, method, params).await;
                assert!(response.error.is_none(), "{install} {method}: {:?}", response.error);
            }
            let listener_ctx = McpContext::new(cx.clone(), 7312)
                .with_auth(current_auth.lock().unwrap().clone());
            let mut listener = route.relay.open_listener_async(
                &listener_ctx, relay_test_filter(vec![handle.clone()]),
            ).await.unwrap();
            assert!(matches!(
                listener.next_async(&cx, &McpRequestCancellation::new()).await.unwrap(),
                ProxyFinalTaskListenerEvent::Acknowledged(_)
            ));
            drop(listener);
            let before = route.calls.lock().unwrap().clone();

            // The management method remains allowed; only the original tool
            // permission disappears. Every path must stop before upstream I/O.
            *current_auth.lock().unwrap() = facts(&["invoke", "manage"]);
            for method in ["tasks/get", "tasks/update", "tasks/cancel"] {
                let mut params = serde_json::json!({"taskId": handle});
                if method == "tasks/update" { params["inputResponses"] = serde_json::json!({}); }
                let denied = dispatch(&server, &cx, &connection, method, params.clone()).await;
                params["taskId"] = serde_json::json!("unknown-task-handle");
                let unknown = dispatch(&server, &cx, &connection, method, params).await;
                let denied = denied.error.expect("original-operation scope loss must deny");
                let unknown = unknown.error.unwrap();
                assert_eq!(denied.code, unknown.code);
                assert_eq!(denied.message, unknown.message);
                assert_eq!(denied.data, unknown.data);
            }
            let reduced_ctx = McpContext::new(cx.clone(), 7313)
                .with_auth(current_auth.lock().unwrap().clone());
            assert!(route.relay.open_listener_async(
                &reduced_ctx, relay_test_filter(vec![handle.clone()]),
            ).await.is_err());
            assert_eq!(*route.calls.lock().unwrap(), before);
            *current_auth.lock().unwrap() = facts(&["invoke", "sensitive", "manage"]);
            assert!(dispatch(&server, &cx, &connection, "tasks/get",
                serde_json::json!({"taskId": handle})).await.error.is_none());
        }
    });
    assert!(runtime.shutdown_timeout(Duration::from_secs(2)));
}

#[test]
fn proxy_task_missing_policy_refuses_public_creation_before_upstream_effects() {
    let runtime = asupersync::runtime::RuntimeBuilder::current_thread()
        .with_reactor(asupersync::runtime::reactor::create_reactor().unwrap())
        .build().unwrap();
    let cx = runtime.request_cx_with_budget(asupersync::Budget::default());
    let route = raw_route();
    let server = Arc::new(crate::ServerBuilder::new("unconfigured-proxy", "1")
        .auth_provider(CurrentAuth(Arc::new(Mutex::new(facts(&["invoke", "sensitive", "manage"])))))
        .proxy(route.client.clone(), catalog(true)).unwrap().build());
    let response = runtime.block_on(dispatch(
        &server, &cx, &crate::ModernConnection::new(), "tools/call",
        serde_json::json!({"name": "weather", "arguments": {}}),
    ));
    assert!(response.error.is_some());
    assert!(route.calls.lock().unwrap().is_empty());
    let registry = route.relay.tasks.lock().unwrap();
    assert!(registry.tasks.is_empty());
    assert!(registry.pending_creations.is_empty());
    drop(registry);
    assert!(runtime.shutdown_timeout(Duration::from_secs(2)));
}

fn issue_bound(
    route: &BrokerRouteFixture,
    ctx: &McpContext,
    original: FinalTaskOperation,
) -> FinalTaskId {
    let reservation = route.relay.reserve_task_creation(ctx).unwrap();
    let carrier = route.relay.encode_task_carrier(reservation, route.creation.clone()).unwrap();
    route.relay.admit_carried_task_for_operation(ctx, &carrier, original)
        .unwrap().unwrap().task.base().task_id.clone()
}

#[test]
fn proxy_task_carriers_require_exact_binding_and_cannot_be_rebound() {
    let route = raw_route();
    route.relay.install_access_authorizers(vec![Arc::new(RelayTestAccessAuthorizer)]).unwrap();
    let ctx = relay_test_context(Cx::for_testing(), 7315);
    let reservation = route.relay.reserve_task_creation(&ctx).unwrap();
    let carrier = route.relay.encode_task_carrier(reservation, route.creation.clone()).unwrap();
    let handle = route.relay.admit_carried_task(&ctx, &carrier)
        .unwrap().unwrap().task.base().task_id.clone();
    assert!(block_on(route.relay.dispatch_get(&ctx, serde_json::json!({"taskId": handle}))).is_err(),
        "an internal carrier is not a router-authorized Task handle");
    assert!(route.calls.lock().unwrap().is_empty());
    let original_registration = Arc::new(());
    route.relay.admit_carried_task_for_operation(
        &ctx, &carrier, FinalTaskOperation::for_tool("weather", &original_registration).unwrap(),
    ).unwrap().unwrap();
    assert!(block_on(route.relay.dispatch_get(&ctx, serde_json::json!({"taskId": handle}))).is_ok());
    let replacement_registration = Arc::new(());
    assert!(route.relay.admit_carried_task_for_operation(
        &ctx, &carrier, FinalTaskOperation::for_tool("weather", &replacement_registration).unwrap(),
    ).is_err(), "a same-name replacement cannot acquire an issued carrier");
    drop(original_registration);
    assert!(block_on(route.relay.dispatch_get(&ctx, serde_json::json!({"taskId": handle}))).is_err());
    assert_eq!(route.calls.lock().unwrap().as_slice(), ["tasks/get"]);
}

struct RevocableOperation {
    denied: Mutex<Option<String>>,
}

impl TaskAccessAuthorizer for RevocableOperation {
    fn authorize(&self, _ctx: &McpContext, _action: TaskAccessAction, original: &FinalTaskOperation) -> McpResult<()> {
        if self.denied.lock().unwrap().as_deref() == Some(original.tool_name()) {
            Err(McpError::with_data(McpErrorCode::InvalidParams,
                "private-proxy-policy-canary", serde_json::json!({"secret": "never forward"})))
        } else { Ok(()) }
    }
}

#[test]
fn proxy_task_mixed_selection_denial_opens_no_upstream_and_registration_cannot_retarget() {
    let first = raw_route();
    let second = raw_route();
    let policy = Arc::new(RevocableOperation { denied: Mutex::new(None) });
    first.relay.attach_route(Arc::clone(&second.relay)).unwrap();
    first.relay.install_access_authorizers(vec![policy.clone()]).unwrap();
    let ctx = relay_test_context(Cx::for_testing(), 7320);
    let first_registration = Arc::new(());
    let second_registration = Arc::new(());
    let allowed = issue_bound(&first, &ctx, FinalTaskOperation::for_tool("allowed", &first_registration).unwrap());
    let restricted = issue_bound(&second, &ctx, FinalTaskOperation::for_tool("restricted", &second_registration).unwrap());
    *policy.denied.lock().unwrap() = Some("restricted".to_owned());
    assert!(block_on(first.relay.open_listener_async(&ctx, relay_test_filter(vec![
        allowed.clone(), restricted,
    ]))).is_err());
    assert!(first.calls.lock().unwrap().is_empty());
    assert!(second.calls.lock().unwrap().is_empty());

    let disabled = ctx.clone();
    assert!(disabled.disable_tool("allowed"));
    assert!(block_on(first.relay.dispatch_get(&disabled, serde_json::json!({"taskId": allowed}))).is_err());
    let fresh = relay_test_context(Cx::for_testing(), 7321);
    let original = first.relay.tasks.lock().unwrap().tasks[&allowed].original_operation.clone().unwrap();
    drop(first_registration);
    let replacement_registration = Arc::new(());
    let replacement = FinalTaskOperation::for_tool("allowed", &replacement_registration).unwrap();
    assert_ne!(original, replacement);
    assert!(block_on(first.relay.dispatch_get(&fresh, serde_json::json!({"taskId": allowed}))).is_err());
    assert!(first.calls.lock().unwrap().is_empty());
}

struct CountedListener {
    events: VecDeque<ProxyFinalTaskListenerEvent>,
    reads: Arc<AtomicUsize>,
    drops: Arc<AtomicUsize>,
}

impl Drop for CountedListener {
    fn drop(&mut self) { self.drops.fetch_add(1, Ordering::SeqCst); }
}

impl ProxyFinalTaskListener for CountedListener {
    fn next(&mut self, _cx: &Cx, _cancellation: &McpRequestCancellation) -> McpResult<ProxyFinalTaskListenerEvent> {
        self.reads.fetch_add(1, Ordering::SeqCst);
        self.events.pop_front().ok_or_else(|| McpError::internal_error("unexpected extra read"))
    }
}

#[test]
fn proxy_task_queued_alias_rechecks_original_policy_and_drops_stream_on_revocation() {
    let route = raw_route();
    let policy = Arc::new(RevocableOperation { denied: Mutex::new(None) });
    route.relay.install_access_authorizers(vec![policy.clone()]).unwrap();
    let ctx = relay_test_context(Cx::for_testing(), 7330);
    let registration = Arc::new(());
    let first = issue_bound(&route, &ctx, FinalTaskOperation::for_tool("first", &registration).unwrap());
    let second = issue_bound(&route, &ctx, FinalTaskOperation::for_tool("second", &registration).unwrap());
    let upstream = route.creation.task.base().task_id.clone();
    let upstream_filter = relay_test_filter(vec![upstream.clone()]);
    let reads = Arc::new(AtomicUsize::new(0));
    let drops = Arc::new(AtomicUsize::new(0));
    let inner = CountedListener {
        events: VecDeque::from([
            ProxyFinalTaskListenerEvent::Acknowledged(upstream_filter.clone()),
            ProxyFinalTaskListenerEvent::Notification(relay_test_notification(route.creation.task.clone())),
        ]),
        reads: Arc::clone(&reads), drops: Arc::clone(&drops),
    };
    let mut listener = super::super::AdmittedProxyFinalTaskListener::new(
        Box::new(inner), Arc::clone(&route.relay), super::super::proxy_task_owner(&ctx).unwrap(), ctx.clone(),
        vec![(first.clone(), upstream.clone()), (second.clone(), upstream)],
        upstream_filter, relay_test_filter(vec![first.clone(), second]),
    );
    let cancellation = McpRequestCancellation::new();
    assert!(matches!(block_on(listener.next_async(ctx.cx(), &cancellation)).unwrap(),
        ProxyFinalTaskListenerEvent::Acknowledged(_)));
    let ProxyFinalTaskListenerEvent::Notification(event) =
        block_on(listener.next_async(ctx.cx(), &cancellation)).unwrap() else { panic!("first alias") };
    assert_eq!(event.params.task.base().task_id, first);
    *policy.denied.lock().unwrap() = Some("second".to_owned());
    let denied = block_on(listener.next_async(ctx.cx(), &cancellation)).unwrap_err();
    let unknown = super::super::unknown_proxy_task();
    assert_eq!(denied.code, unknown.code);
    assert_eq!(denied.message, unknown.message);
    assert!(denied.data.is_none());
    assert_eq!(reads.load(Ordering::SeqCst), 2, "queued alias must not read another upstream frame");
    assert_eq!(drops.load(Ordering::SeqCst), 1, "denial releases upstream ownership immediately");
    assert!(listener.pending.is_none());
    assert!(listener.pending_handles.is_empty());
}

#[test]
fn proxy_task_missing_policy_blocks_management_and_reconciliation_without_upstream_reads() {
    let route = raw_route();
    let ctx = relay_test_context(Cx::for_testing(), 7340);
    route.relay.install_access_authorizers(vec![Arc::new(RelayTestAccessAuthorizer)]).unwrap();
    let registration = Arc::new(());
    let handle = issue_bound(&route, &ctx, FinalTaskOperation::for_tool("weather", &registration).unwrap());
    route.relay.tasks.lock().unwrap().access_authorizers.clear();
    let before = route.client.final_task_registry_snapshot_for_test().unwrap();
    assert!(block_on(route.relay.dispatch_get(&ctx, serde_json::json!({"taskId": handle}))).is_err());
    assert!(block_on(route.relay.dispatch_update(&ctx, serde_json::json!({"taskId": handle, "inputResponses": {}}))).is_err());
    assert!(block_on(route.relay.dispatch_cancel(&ctx, serde_json::json!({"taskId": handle}))).is_err());
    assert!(block_on(route.relay.open_listener_async(&ctx, relay_test_filter(vec![handle.clone()]))).is_err());
    assert!(block_on(route.relay.reconcile_task(
        &ctx, super::super::proxy_task_owner(&ctx).unwrap(), &handle,
        route.creation.task.clone(), None, TaskAccessAction::Listen,
    )).is_err());
    assert!(route.calls.lock().unwrap().is_empty());
    assert_eq!(route.client.final_task_registry_snapshot_for_test().unwrap(), before);
}

struct AllowExecution;
impl crate::TaskExecutionAuthorizer for AllowExecution {
    fn authorize(&self, _: &crate::FinalTaskAccessMetadata) -> McpResult<()> { Ok(()) }
}

#[test]
fn proxy_task_policy_batches_are_atomic_across_routes_and_duplicate_client_registries() {
    let first = raw_route();
    let full = raw_route();
    full.relay.install_access_authorizers((0..16).map(|_| {
        Arc::new(RelayTestAccessAuthorizer) as Arc<dyn TaskAccessAuthorizer>
    }).collect()).unwrap();
    let refused = crate::ServerBuilder::new("full-proxy-policy", "1")
        .proxy(first.client.clone(), catalog(false)).unwrap()
        .proxy(full.client.clone(), catalog(false)).unwrap()
        .task_access_authorizer(Arc::new(RelayTestAccessAuthorizer)).try_build();
    assert!(refused.is_err());
    assert!(first.relay.access_authorizers().unwrap().is_empty());
    assert_eq!(full.relay.access_authorizers().unwrap().len(), 16);

    let refused_execution = crate::ServerBuilder::new("invalid-proxy-execution", "1")
        .proxy(first.client.clone(), catalog(false)).unwrap()
        .task_access_authorizer(Arc::new(RelayTestAccessAuthorizer))
        .task_execution_authorizer(Arc::new(AllowExecution)).try_build();
    assert!(refused_execution.is_err());
    assert!(first.relay.access_authorizers().unwrap().is_empty());

    let duplicated = raw_route();
    let _server = crate::ServerBuilder::new("duplicate-proxy-client", "1")
        .proxy(duplicated.client.clone(), catalog(false)).unwrap()
        .proxy(duplicated.client.clone(), catalog(false)).unwrap()
        .task_access_authorizer(Arc::new(RelayTestAccessAuthorizer)).try_build().unwrap();
    assert_eq!(duplicated.relay.access_authorizers().unwrap().len(), 1);
    assert!(first.calls.lock().unwrap().is_empty());
    assert!(full.calls.lock().unwrap().is_empty());
    assert!(duplicated.calls.lock().unwrap().is_empty());
}
