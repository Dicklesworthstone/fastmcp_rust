use super::*;
use crate::http_admission::security::scope_policy::request::ScopeRequestPolicy;
use crate::http_admission::security::scope_policy::request::operation::{
    OperationScopePolicy, ScopedOperation,
};
use crate::http_admission::security::scope_policy::{RequiredScopes, ScopeImplicationPolicy};
use crate::{FinalTaskOperation, ProxyTaskLimits, TaskAccessAction, TaskAccessAuthorizer};
use fastmcp_core::{AuthContext, McpError, McpResult};
use fastmcp_protocol::{FinalTaskId, JsonRpcRequest, JsonRpcResponse, Task};

const OWNER: &str = "renewal-owner";
const TOOL: &str = "renewing-operation";

struct RenewalRoute {
    client: ProxyClient,
    relay: Arc<super::super::ProxyFinalTaskRelay>,
    creation: CreateTaskResult,
    calls: Arc<Mutex<Vec<&'static str>>>,
    replies: Arc<Mutex<VecDeque<TaskReconciliationReply>>>,
    updates: Arc<Mutex<Vec<Task>>>,
}

fn policy() -> ProxyTaskRetentionPolicy {
    ProxyTaskRetentionPolicy::new(Duration::from_secs(120), Duration::from_secs(300))
        .unwrap()
        .with_renewal_margin(Duration::from_secs(10))
        .unwrap()
}

fn route(generation: u64) -> RenewalRoute {
    route_with_notifications(
        final_task_relay_result_with_ttl("renewal-upstream-task", Some(60_000)),
        Vec::new(),
        generation,
    )
}

fn route_with_notifications(
    creation: CreateTaskResult,
    notifications: Vec<Task>,
    generation: u64,
) -> RenewalRoute {
    let calls = Arc::new(Mutex::new(Vec::new()));
    let replies = Arc::new(Mutex::new(VecDeque::new()));
    let updates = Arc::new(Mutex::new(Vec::new()));
    let mut events = VecDeque::from([ProxyFinalTaskListenerEvent::Acknowledged(
        relay_test_filter(vec![creation.task.base().task_id.clone()]),
    )]);
    events.extend(
        notifications
            .into_iter()
            .map(|task| ProxyFinalTaskListenerEvent::Notification(relay_test_notification(task))),
    );
    events.push_back(ProxyFinalTaskListenerEvent::Terminal);
    let mut binding = final_task_relay_binding(ProtocolEra::Modern2026);
    binding.configuration_generation = generation;
    let client = ProxyClient::from_backend_with_upstream_binding(
        TaskReconciliationBackend {
            backend: FinalTaskRelayBackend {
                calls: Arc::clone(&calls),
                task: creation.clone(),
                listener_events: Some(events),
                cancel_after_task_commit: None,
                final_progress: None,
            },
            replies: Arc::clone(&replies),
            observed_updates: Some(Arc::clone(&updates)),
        },
        binding,
        "2026-07-28",
    )
    .unwrap()
    .with_task_retention_policy(policy())
    .unwrap()
    .with_task_limits(ProxyTaskLimits::new(1, 1).unwrap())
    .unwrap();
    let relay = client.final_tasks_relay().unwrap().unwrap();
    RenewalRoute {
        client,
        relay,
        creation,
        calls,
        replies,
        updates,
    }
}

fn facts(subject: &str) -> AuthContext {
    let mut auth = AuthContext::with_subject(subject);
    auth.scopes = ["invoke", "operation", "get", "update", "cancel", "listen"]
        .into_iter()
        .map(str::to_owned)
        .collect();
    auth.with_verification_valid_until(Instant::now() + Duration::from_secs(120))
}

struct CurrentFacts(Arc<Mutex<AuthContext>>);

impl crate::auth::AuthProvider for CurrentFacts {
    fn authenticate(
        &self,
        _ctx: &McpContext,
        _request: crate::auth::AuthRequest<'_>,
    ) -> McpResult<AuthContext> {
        Ok(self.0.lock().unwrap().clone())
    }
}

#[derive(Default)]
struct Revocations(Mutex<Vec<(String, TaskAccessAction)>>);

impl Revocations {
    fn revoke(&self, name: &str, action: TaskAccessAction) {
        self.0.lock().unwrap().push((name.to_owned(), action));
    }
}

impl TaskAccessAuthorizer for Revocations {
    fn authorize(
        &self,
        _ctx: &McpContext,
        action: TaskAccessAction,
        original: &FinalTaskOperation,
    ) -> McpResult<()> {
        if self
            .0
            .lock()
            .unwrap()
            .iter()
            .any(|(name, denied)| name == original.tool_name() && *denied == action)
        {
            return Err(McpError::invalid_request(
                "current application grant was revoked",
            ));
        }
        Ok(())
    }
}

fn scope_policy(names: &[&str]) -> OperationScopePolicy {
    let required = |scope: &str| RequiredScopes::new(vec![scope.to_owned()]).unwrap();
    let methods = ScopeRequestPolicy::new(
        1,
        ScopeImplicationPolicy::new(1, vec![]).unwrap(),
        vec![
            ("tools/call".to_owned(), required("invoke")),
            ("tasks/get".to_owned(), required("get")),
            ("tasks/update".to_owned(), required("update")),
            ("tasks/cancel".to_owned(), required("cancel")),
            ("subscriptions/listen".to_owned(), required("listen")),
        ],
    )
    .unwrap();
    OperationScopePolicy::new(
        1,
        methods,
        names
            .iter()
            .map(|name| {
                (
                    ScopedOperation::ToolCall((*name).to_owned()),
                    required("operation"),
                )
            })
            .collect(),
    )
    .unwrap()
}

fn gateway(
    routes: &[(&str, &RenewalRoute)],
    auth: Arc<Mutex<AuthContext>>,
    revocations: Arc<Revocations>,
) -> Arc<crate::Server> {
    let mut builder =
        crate::ServerBuilder::new("renewal-gateway", "1").auth_provider(CurrentFacts(auth));
    for (name, route) in routes {
        let mut tool = final_catalog_tool();
        tool.name = (*name).to_owned();
        builder = builder
            .proxy(
                route.client.clone(),
                ProxyCatalog {
                    tool_catalog_era: Some(ProtocolEra::Modern2026),
                    final_tools: vec![tool],
                    ..ProxyCatalog::default()
                },
            )
            .unwrap();
    }
    let names: Vec<_> = routes.iter().map(|(name, _)| *name).collect();
    Arc::new(
        builder
            .task_access_authorizer(Arc::new(scope_policy(&names)))
            .task_access_authorizer(revocations)
            .build(),
    )
}

struct Reply {
    response: Option<JsonRpcResponse>,
    frames: Vec<JsonRpcMessage>,
}

async fn dispatch(
    server: &Arc<crate::Server>,
    cx: &Cx,
    method: &str,
    mut params: serde_json::Value,
) -> Reply {
    params["_meta"] = serde_json::json!({
        "io.modelcontextprotocol/protocolVersion": "2026-07-28",
        "io.modelcontextprotocol/clientCapabilities": {
            "extensions": {fastmcp_protocol::TASKS_EXTENSION: {}}
        }
    });
    let connection = crate::ModernConnection::new();
    let inbound = crate::InboundRequestContext::with_modern_connection(
        cx.clone(),
        7601,
        crate::InboundRequestTransport::Memory,
        &connection,
    );
    let frames = Arc::new(Mutex::new(Vec::new()));
    let captured = Arc::clone(&frames);
    let response = asupersync::time::timeout_at(
        cx.now().saturating_add_nanos(2_000_000_000),
        Arc::clone(server).dispatch_with_protocol_policy_owned(
            ProtocolPolicy::ModernOnly,
            &inbound,
            JsonRpcRequest::new(method, Some(params), 7601_i64),
            None,
            None,
            None,
            None,
            McpRequestCancellation::new(),
            None,
            Arc::new(move |frame| captured.lock().unwrap().push(frame)),
        ),
    )
    .await
    .expect("the scripted gateway operation has a bounded terminal response");
    let frames = frames.lock().unwrap().clone();
    Reply { response, frames }
}

async fn create(server: &Arc<crate::Server>, cx: &Cx, tool: &str) -> FinalTaskId {
    let reply = dispatch(
        server,
        cx,
        "tools/call",
        serde_json::json!({"name": tool, "arguments": {}}),
    )
    .await;
    let response = reply
        .response
        .expect("public creation returns a correlated result");
    assert!(response.error.is_none(), "{:?}", response.error);
    let result = response.result.unwrap();
    assert_eq!(result["resultType"], "task");
    serde_json::from_value(result["taskId"].clone()).unwrap()
}

#[derive(Clone, Copy, Debug)]
enum Control {
    Update,
    Cancel,
    Listen,
}

impl Control {
    fn method(self) -> &'static str {
        match self {
            Self::Update => "tasks/update",
            Self::Cancel => "tasks/cancel",
            Self::Listen => "subscriptions/listen",
        }
    }
    fn scope(self) -> &'static str {
        match self {
            Self::Update => "update",
            Self::Cancel => "cancel",
            Self::Listen => "listen",
        }
    }
    fn action(self) -> TaskAccessAction {
        match self {
            Self::Update => TaskAccessAction::Update,
            Self::Cancel => TaskAccessAction::Cancel,
            Self::Listen => TaskAccessAction::Listen,
        }
    }
    fn parameters(self, handle: &FinalTaskId) -> serde_json::Value {
        match self {
            Self::Update => serde_json::json!({"taskId": handle, "inputResponses": {}}),
            Self::Cancel => serde_json::json!({"taskId": handle}),
            Self::Listen => {
                serde_json::json!({"notifications": relay_test_filter(vec![handle.clone()])})
            }
        }
    }
}

const CONTROLS: [Control; 3] = [Control::Update, Control::Cancel, Control::Listen];

fn acknowledged(reply: &Reply) -> usize {
    reply.frames.iter().filter(|frame| {
        matches!(frame, JsonRpcMessage::Request(request) if matches!(ServerNotification::decode(request), Ok(ServerNotification::SubscriptionsAcknowledged(_))))
    }).count()
}

fn task_events(reply: &Reply) -> usize {
    reply
        .frames
        .iter()
        .filter(|frame| {
            matches!(frame, JsonRpcMessage::Request(request)
        if request.method == fastmcp_protocol::tasks_extension::TASK_STATUS_NOTIFICATION)
        })
        .count()
}

fn assert_succeeded(control: Control, reply: &Reply) {
    if matches!(control, Control::Listen) {
        assert!(reply.response.is_none(), "{:?}", reply.response);
        assert_eq!(acknowledged(reply), 1);
    } else {
        let response = reply
            .response
            .as_ref()
            .expect("correlated control response");
        assert!(response.error.is_none(), "{:?}", response.error);
        assert_eq!(response.result.as_ref().unwrap()["resultType"], "complete");
        assert!(reply.frames.is_empty());
    }
}

fn assert_refused(reply: &Reply, code: McpErrorCode) {
    let response = reply
        .response
        .as_ref()
        .expect("refusal is correlated before stream acknowledgment");
    assert!(response.result.is_none());
    let error = response.error.as_ref().unwrap();
    assert_eq!(error.code.as_i32(), Some(i32::from(code)));
    assert!(error.data.is_none());
    assert_eq!(acknowledged(reply), 0);
}

fn checkpoint(
    route: &RenewalRoute,
    handle: &FinalTaskId,
) -> (serde_json::Value, Option<Instant>, Option<Instant>, u64) {
    let snapshot = route
        .client
        .final_task_registry_snapshot_for_test()
        .unwrap();
    let registry = route.relay.tasks.lock().unwrap();
    let retained = &registry.tasks[handle];
    (
        snapshot,
        retained.expires_at,
        retained.recovery_until,
        retained.snapshot_revision,
    )
}

fn queue(route: &RenewalRoute, ttl: u64) {
    route
        .replies
        .lock()
        .unwrap()
        .push_back(TaskReconciliationReply {
            result: Ok(relay_task_with_ttl(&route.creation.task, Some(ttl))),
            before_reply: None,
        });
}

fn assert_charge_retained(route: &RenewalRoute, cx: &Cx, auth: &AuthContext) {
    let owner = McpContext::new(cx.clone(), 7602).with_auth(auth.clone());
    let error = match route.relay.reserve_task_creation(&owner) {
        Ok(_) => panic!("an uncertain renewal cannot free committed upstream capacity"),
        Err(error) => error,
    };
    assert!(error.message.contains("capacity exhausted"));
    assert!(route.relay.tasks.lock().unwrap().orphans.is_empty());
    assert!(route.client.task_orphan_audit().unwrap().is_empty());
}

#[test]
fn proxy_task_renewal_margin_is_explicit_bounded_and_defaults_to_the_upstream_maximum() {
    let short =
        ProxyTaskRetentionPolicy::new(Duration::from_secs(5), Duration::from_secs(60)).unwrap();
    assert_eq!(short.renewal_margin(), Duration::from_secs(5));
    let ordinary =
        ProxyTaskRetentionPolicy::new(Duration::from_secs(120), Duration::from_secs(300)).unwrap();
    assert_eq!(ordinary.renewal_margin(), Duration::from_secs(30));
    assert_eq!(
        ordinary
            .with_renewal_margin(Duration::from_secs(120))
            .unwrap()
            .renewal_margin(),
        Duration::from_secs(120)
    );
    for margin in [Duration::ZERO, Duration::from_secs(121)] {
        assert_eq!(
            ordinary.with_renewal_margin(margin).unwrap_err().code,
            McpErrorCode::InvalidParams
        );
    }
    assert_eq!(policy().renewal_margin(), Duration::from_secs(10));
}

#[test]
fn proxy_task_renewal_public_controls_and_listener_use_fresh_extensions_and_shortening() {
    let runtime = asupersync::runtime::RuntimeBuilder::current_thread()
        .with_reactor(asupersync::runtime::reactor::create_reactor().unwrap())
        .build()
        .unwrap();
    let cx = runtime.request_cx_with_budget(asupersync::Budget::default());
    runtime.block_on(async {
        for control in CONTROLS {
            for (elapsed, renewed_ttl) in [(55, 90_000), (55, 57_000), (65, 90_000)] {
                let route = route(801);
                let auth = Arc::new(Mutex::new(facts(OWNER)));
                let server = gateway(
                    &[(TOOL, &route)],
                    Arc::clone(&auth),
                    Arc::new(Revocations::default()),
                );
                let handle = create(&server, &cx, TOOL).await;
                age_relay_task_mappings(
                    &route.relay,
                    &[handle.clone()],
                    Duration::from_secs(elapsed),
                );
                let before = checkpoint(&route, &handle);
                queue(&route, renewed_ttl);
                let reply =
                    dispatch(&server, &cx, control.method(), control.parameters(&handle)).await;
                assert_succeeded(control, &reply);
                assert_eq!(
                    route.calls.lock().unwrap().as_slice(),
                    ["tools/call", "tasks/get", control.method()]
                );
                let retained = route.relay.tasks.lock().unwrap().tasks[&handle].clone();
                assert_eq!(
                    serde_json::to_value(&retained.task).unwrap()["ttlMs"],
                    renewed_ttl
                );
                assert_eq!(
                    retained.recovery_until, before.2,
                    "a fresh read never resets the hard ceiling"
                );
                assert_eq!(
                    retained.expires_at.unwrap(),
                    before.1.unwrap() + Duration::from_millis(renewed_ttl.saturating_sub(60_000))
                        - Duration::from_millis(60_000_u64.saturating_sub(renewed_ttl))
                );
                if matches!(control, Control::Update) {
                    assert_eq!(route.updates.lock().unwrap().len(), 1);
                    assert_eq!(
                        serde_json::to_value(&route.updates.lock().unwrap()[0]).unwrap()["ttlMs"],
                        renewed_ttl,
                        "tasks/update receives the newly admitted authoritative snapshot"
                    );
                }
                assert_charge_retained(&route, &cx, &auth.lock().unwrap());
            }
        }
    });
}

#[test]
fn proxy_task_renewal_public_controls_outside_margin_need_no_get_grant_or_extra_read() {
    let runtime = asupersync::runtime::RuntimeBuilder::current_thread()
        .with_reactor(asupersync::runtime::reactor::create_reactor().unwrap())
        .build()
        .unwrap();
    let cx = runtime.request_cx_with_budget(asupersync::Budget::default());
    runtime.block_on(async {
        for control in CONTROLS {
            let route = route(802);
            let auth = Arc::new(Mutex::new(facts(OWNER)));
            let server = gateway(
                &[(TOOL, &route)],
                Arc::clone(&auth),
                Arc::new(Revocations::default()),
            );
            let handle = create(&server, &cx, TOOL).await;
            age_relay_task_mappings(&route.relay, &[handle.clone()], Duration::from_secs(20));
            auth.lock().unwrap().scopes.retain(|scope| scope != "get");
            let before = checkpoint(&route, &handle);
            let reply = dispatch(&server, &cx, control.method(), control.parameters(&handle)).await;
            assert_succeeded(control, &reply);
            assert_eq!(
                route.calls.lock().unwrap().as_slice(),
                ["tools/call", control.method()]
            );
            assert_eq!(checkpoint(&route, &handle), before);
        }
    });
}

#[test]
fn proxy_task_renewal_public_missing_get_or_requested_grant_refuses_before_contact() {
    let runtime = asupersync::runtime::RuntimeBuilder::current_thread()
        .with_reactor(asupersync::runtime::reactor::create_reactor().unwrap())
        .build()
        .unwrap();
    let cx = runtime.request_cx_with_budget(asupersync::Budget::default());
    runtime.block_on(async {
        for control in CONTROLS {
            for elapsed in [55, 65] {
                for missing in ["get", control.scope()] {
                    let route = route(803);
                    let auth = Arc::new(Mutex::new(facts(OWNER)));
                    let server = gateway(
                        &[(TOOL, &route)],
                        Arc::clone(&auth),
                        Arc::new(Revocations::default()),
                    );
                    let handle = create(&server, &cx, TOOL).await;
                    age_relay_task_mappings(
                        &route.relay,
                        &[handle.clone()],
                        Duration::from_secs(elapsed),
                    );
                    auth.lock().unwrap().scopes.retain(|scope| scope != missing);
                    let before = checkpoint(&route, &handle);
                    let reply =
                        dispatch(&server, &cx, control.method(), control.parameters(&handle)).await;
                    assert_refused(&reply, McpErrorCode::InvalidParams);
                    assert_eq!(route.calls.lock().unwrap().as_slice(), ["tools/call"]);
                    assert_eq!(checkpoint(&route, &handle), before);
                    assert_charge_retained(&route, &cx, &auth.lock().unwrap());
                }
            }
        }
    });
}

#[test]
fn proxy_task_renewal_public_outage_retains_quota_and_a_later_read_can_recover() {
    let runtime = asupersync::runtime::RuntimeBuilder::current_thread()
        .with_reactor(asupersync::runtime::reactor::create_reactor().unwrap())
        .build()
        .unwrap();
    let cx = runtime.request_cx_with_budget(asupersync::Budget::default());
    runtime.block_on(async {
        for control in CONTROLS {
            let route = route(804);
            let auth = Arc::new(Mutex::new(facts(OWNER)));
            let server = gateway(
                &[(TOOL, &route)],
                Arc::clone(&auth),
                Arc::new(Revocations::default()),
            );
            let handle = create(&server, &cx, TOOL).await;
            age_relay_task_mappings(&route.relay, &[handle.clone()], Duration::from_secs(65));
            let before = checkpoint(&route, &handle);
            route
                .replies
                .lock()
                .unwrap()
                .push_back(TaskReconciliationReply {
                    result: Err(McpError::internal_error("renewal upstream unavailable")),
                    before_reply: None,
                });
            let failed =
                dispatch(&server, &cx, control.method(), control.parameters(&handle)).await;
            assert_refused(&failed, McpErrorCode::InternalError);
            assert_eq!(
                route.calls.lock().unwrap().as_slice(),
                ["tools/call", "tasks/get"]
            );
            assert_eq!(checkpoint(&route, &handle), before);
            assert_charge_retained(&route, &cx, &auth.lock().unwrap());
            queue(&route, 90_000);
            let recovered =
                dispatch(&server, &cx, control.method(), control.parameters(&handle)).await;
            assert_succeeded(control, &recovered);
            assert_eq!(
                route.calls.lock().unwrap().as_slice(),
                ["tools/call", "tasks/get", "tasks/get", control.method()]
            );
            assert_eq!(checkpoint(&route, &handle).2, before.2);
        }
    });
}

#[test]
fn proxy_task_renewal_authoritative_shortening_past_now_refuses_control_and_releases_charge() {
    let runtime = asupersync::runtime::RuntimeBuilder::current_thread()
        .with_reactor(asupersync::runtime::reactor::create_reactor().unwrap())
        .build()
        .unwrap();
    let cx = runtime.request_cx_with_budget(asupersync::Budget::default());
    runtime.block_on(async {
        for control in CONTROLS {
            let route = route(805);
            let auth = Arc::new(Mutex::new(facts(OWNER)));
            let server = gateway(
                &[(TOOL, &route)],
                Arc::clone(&auth),
                Arc::new(Revocations::default()),
            );
            let handle = create(&server, &cx, TOOL).await;
            age_relay_task_mappings(&route.relay, &[handle.clone()], Duration::from_secs(55));
            queue(&route, 50_000);
            let reply = dispatch(&server, &cx, control.method(), control.parameters(&handle)).await;
            assert_refused(&reply, McpErrorCode::InvalidParams);
            assert_eq!(
                route.calls.lock().unwrap().as_slice(),
                ["tools/call", "tasks/get"]
            );
            let registry = route.relay.tasks.lock().unwrap();
            assert!(registry.tasks.is_empty());
            assert!(registry.orphans.is_empty());
            drop(registry);
            let owner = McpContext::new(cx.clone(), 7603).with_auth(auth.lock().unwrap().clone());
            drop(route.relay.reserve_task_creation(&owner).unwrap());
            assert!(route.client.task_orphan_audit().unwrap().is_empty());
        }
    });
}

#[test]
fn proxy_task_renewal_get_revocation_during_read_prevents_state_changes_cleanup_and_control() {
    let runtime = asupersync::runtime::RuntimeBuilder::current_thread()
        .with_reactor(asupersync::runtime::reactor::create_reactor().unwrap())
        .build()
        .unwrap();
    let cx = runtime.request_cx_with_budget(asupersync::Budget::default());
    runtime.block_on(async {
        for control in CONTROLS {
            for ttl in [Some(90_000), None] {
                let route = route(806);
                let auth = Arc::new(Mutex::new(facts(OWNER)));
                let revocations = Arc::new(Revocations::default());
                let server = gateway(
                    &[(TOOL, &route)],
                    Arc::clone(&auth),
                    Arc::clone(&revocations),
                );
                let handle = create(&server, &cx, TOOL).await;
                age_relay_task_mappings(&route.relay, &[handle.clone()], Duration::from_secs(55));
                let before = checkpoint(&route, &handle);
                route
                    .replies
                    .lock()
                    .unwrap()
                    .push_back(TaskReconciliationReply {
                        result: Ok(relay_task_with_ttl(&route.creation.task, ttl)),
                        before_reply: Some(Box::new(move || {
                            revocations.revoke(TOOL, TaskAccessAction::Get)
                        })),
                    });
                let reply =
                    dispatch(&server, &cx, control.method(), control.parameters(&handle)).await;
                assert_refused(&reply, McpErrorCode::InvalidParams);
                assert_eq!(
                    route.calls.lock().unwrap().as_slice(),
                    ["tools/call", "tasks/get"]
                );
                assert_eq!(checkpoint(&route, &handle), before);
                assert_charge_retained(&route, &cx, &auth.lock().unwrap());
                let again =
                    dispatch(&server, &cx, control.method(), control.parameters(&handle)).await;
                assert_refused(&again, McpErrorCode::InvalidParams);
                assert_eq!(
                    route.calls.lock().unwrap().as_slice(),
                    ["tools/call", "tasks/get"]
                );
            }
        }
    });
}

#[test]
fn proxy_task_renewal_requested_action_is_rechecked_after_the_get() {
    let runtime = asupersync::runtime::RuntimeBuilder::current_thread()
        .with_reactor(asupersync::runtime::reactor::create_reactor().unwrap())
        .build()
        .unwrap();
    let cx = runtime.request_cx_with_budget(asupersync::Budget::default());
    runtime.block_on(async {
        for control in CONTROLS {
            let route = route(807);
            let auth = Arc::new(Mutex::new(facts(OWNER)));
            let revocations = Arc::new(Revocations::default());
            let server = gateway(
                &[(TOOL, &route)],
                Arc::clone(&auth),
                Arc::clone(&revocations),
            );
            let handle = create(&server, &cx, TOOL).await;
            age_relay_task_mappings(&route.relay, &[handle.clone()], Duration::from_secs(55));
            let ceiling = checkpoint(&route, &handle).2;
            route
                .replies
                .lock()
                .unwrap()
                .push_back(TaskReconciliationReply {
                    result: Ok(relay_task_with_ttl(&route.creation.task, Some(90_000))),
                    before_reply: Some(Box::new(move || {
                        revocations.revoke(TOOL, control.action())
                    })),
                });
            let reply = dispatch(&server, &cx, control.method(), control.parameters(&handle)).await;
            assert_refused(&reply, McpErrorCode::InvalidParams);
            assert_eq!(
                route.calls.lock().unwrap().as_slice(),
                ["tools/call", "tasks/get"]
            );
            assert_eq!(checkpoint(&route, &handle).2, ceiling);
            assert_charge_retained(&route, &cx, &auth.lock().unwrap());
            assert!(route.updates.lock().unwrap().is_empty());
        }
    });
}

#[test]
fn proxy_task_renewal_listener_preflights_every_route_and_needed_get_before_any_contact() {
    let runtime = asupersync::runtime::RuntimeBuilder::current_thread()
        .with_reactor(asupersync::runtime::reactor::create_reactor().unwrap())
        .build()
        .unwrap();
    let cx = runtime.request_cx_with_budget(asupersync::Budget::default());
    runtime.block_on(async {
        for denied in ["unknown", "foreign", "listen", "get"] {
            let first = route(808);
            let second = route(809);
            let auth = Arc::new(Mutex::new(facts(OWNER)));
            let revocations = Arc::new(Revocations::default());
            let server = gateway(
                &[("first", &first), ("second", &second)],
                Arc::clone(&auth),
                Arc::clone(&revocations),
            );
            let first_handle = create(&server, &cx, "first").await;
            if denied == "foreign" {
                *auth.lock().unwrap() = facts("foreign-renewal-owner");
            }
            let second_handle = create(&server, &cx, "second").await;
            *auth.lock().unwrap() = facts(OWNER);
            age_relay_task_mappings(
                &first.relay,
                &[first_handle.clone()],
                Duration::from_secs(55),
            );
            age_relay_task_mappings(
                &second.relay,
                &[second_handle.clone()],
                Duration::from_secs(55),
            );
            if denied == "listen" {
                revocations.revoke("second", TaskAccessAction::Listen);
            }
            if denied == "get" {
                revocations.revoke("second", TaskAccessAction::Get);
            }
            let first_before = checkpoint(&first, &first_handle);
            let second_before = checkpoint(&second, &second_handle);
            let selected_second = if denied == "unknown" {
                FinalTaskId::parse("unissued-renewal-handle").unwrap()
            } else {
                second_handle.clone()
            };
            let reply = dispatch(
                &server,
                &cx,
                "subscriptions/listen",
                serde_json::json!({
                    "notifications": relay_test_filter(vec![first_handle.clone(), selected_second])
                }),
            )
            .await;
            assert_refused(&reply, McpErrorCode::InvalidParams);
            assert_eq!(
                first.calls.lock().unwrap().as_slice(),
                ["tools/call"],
                "the first route cannot renew before later selections pass"
            );
            assert_eq!(second.calls.lock().unwrap().as_slice(), ["tools/call"]);
            assert_eq!(checkpoint(&first, &first_handle), first_before);
            assert_eq!(checkpoint(&second, &second_handle), second_before);
        }
    });
}

#[test]
fn proxy_task_renewal_listen_reconciliation_requires_its_own_current_get_grant() {
    let runtime = asupersync::runtime::RuntimeBuilder::current_thread()
        .with_reactor(asupersync::runtime::reactor::create_reactor().unwrap())
        .build()
        .unwrap();
    let cx = runtime.request_cx_with_budget(asupersync::Budget::default());
    runtime.block_on(async {
        for grant in ["allowed", "missing", "revoked-during-read"] {
            let initial =
                final_task_relay_result_with_ttl("listener-renewal-authority", Some(60_000));
            let changed = relay_task_with_ttl(&initial.task, Some(90_000));
            let route = route_with_notifications(initial, vec![changed.clone()], 810);
            let auth = Arc::new(Mutex::new(facts(OWNER)));
            let revocations = Arc::new(Revocations::default());
            let server = gateway(
                &[(TOOL, &route)],
                Arc::clone(&auth),
                Arc::clone(&revocations),
            );
            let handle = create(&server, &cx, TOOL).await;
            let before = checkpoint(&route, &handle);
            if grant == "missing" {
                auth.lock().unwrap().scopes.retain(|scope| scope != "get");
            } else {
                let before_reply: Option<Box<dyn FnOnce() + Send>> =
                    if grant == "revoked-during-read" {
                        Some(Box::new(move || {
                            revocations.revoke(TOOL, TaskAccessAction::Get)
                        }))
                    } else {
                        None
                    };
                route
                    .replies
                    .lock()
                    .unwrap()
                    .push_back(TaskReconciliationReply {
                        result: Ok(changed),
                        before_reply,
                    });
            }
            let reply = dispatch(
                &server,
                &cx,
                "subscriptions/listen",
                Control::Listen.parameters(&handle),
            )
            .await;
            assert_succeeded(Control::Listen, &reply);
            assert_eq!(task_events(&reply), usize::from(grant == "allowed"));
            if grant == "missing" {
                assert_eq!(
                    route.calls.lock().unwrap().as_slice(),
                    ["tools/call", "subscriptions/listen"]
                );
            } else {
                assert_eq!(
                    route.calls.lock().unwrap().as_slice(),
                    ["tools/call", "subscriptions/listen", "tasks/get"]
                );
            }
            if grant != "allowed" {
                assert_eq!(checkpoint(&route, &handle), before);
            }
            assert_charge_retained(&route, &cx, &auth.lock().unwrap());
        }
    });
}
