use super::super::{ProxyTaskCleanupOutcome, ProxyTaskOrphanReason};
use super::*;
use crate::ProxyTaskLimits;
use crate::http_admission::security::scope_policy::request::ScopeRequestPolicy;
use crate::http_admission::security::scope_policy::request::operation::{
    OperationScopePolicy, ScopedOperation,
};
use crate::http_admission::security::scope_policy::{RequiredScopes, ScopeImplicationPolicy};
use fastmcp_core::{AuthContext, McpError, McpResult};
use fastmcp_protocol::{FinalCancelTaskResult, FinalTaskId, JsonRpcRequest, JsonRpcResponse};
use std::sync::Barrier;

const TOOL: &str = "retained-operation";
const PRIVATE_TASK_ID: &str = "upstream-private-task-identifier";
const PRIVATE_OWNER: &str = "retention-private-owner";
const PRIVATE_PAYLOAD: &str = "private-upstream-state-and-credential";

#[derive(Clone, Copy)]
enum CleanupReply {
    Acknowledged,
    Failed,
    Interrupted,
}

struct RetentionBackend {
    backend: FinalTaskRelayBackend,
    cleanup: CleanupReply,
    following_creation: Option<CreateTaskResult>,
}

impl ProxyBackend for RetentionBackend {
    fn list_tools(&mut self) -> McpResult<Vec<Tool>> {
        self.backend.list_tools()
    }
    fn list_resources(&mut self) -> McpResult<Vec<Resource>> {
        self.backend.list_resources()
    }
    fn list_resource_templates(&mut self) -> McpResult<Vec<fastmcp_protocol::ResourceTemplate>> {
        self.backend.list_resource_templates()
    }
    fn list_prompts(&mut self) -> McpResult<Vec<Prompt>> {
        self.backend.list_prompts()
    }
    fn call_tool(&mut self, name: &str, arguments: serde_json::Value) -> McpResult<Vec<Content>> {
        self.backend.call_tool(name, arguments)
    }
    fn call_tool_with_progress(
        &mut self,
        name: &str,
        arguments: serde_json::Value,
        progress: super::super::ProgressCallback<'_>,
    ) -> McpResult<Vec<Content>> {
        self.backend
            .call_tool_with_progress(name, arguments, progress)
    }
    fn read_resource(&mut self, uri: &str) -> McpResult<Vec<ResourceContent>> {
        self.backend.read_resource(uri)
    }
    fn get_prompt(
        &mut self,
        name: &str,
        arguments: HashMap<String, String>,
    ) -> McpResult<Vec<PromptMessage>> {
        self.backend.get_prompt(name, arguments)
    }
    fn supports_final_tasks_relay(&mut self) -> McpResult<bool> {
        Ok(true)
    }
    fn call_tool_final_outcome(
        &mut self,
        name: &str,
        arguments: serde_json::Value,
    ) -> McpResult<FinalToolCallOutcome> {
        let outcome = self.backend.call_tool_final_outcome(name, arguments)?;
        if let Some(following) = self.following_creation.take() {
            self.backend.task = following;
        }
        Ok(outcome)
    }
    fn get_final_task(&mut self, task_id: FinalTaskId) -> McpResult<FinalGetTaskResult> {
        self.backend.get_final_task(task_id)
    }
    fn update_final_task(
        &mut self,
        task: &fastmcp_protocol::Task,
        inputs: fastmcp_protocol::TaskInputResponses,
    ) -> McpResult<fastmcp_protocol::UpdateTaskResult> {
        self.backend.update_final_task(task, inputs)
    }
    fn cancel_final_task_with_context(
        &mut self,
        ctx: &McpContext,
        task_id: FinalTaskId,
    ) -> McpResult<FinalCancelTaskResult> {
        ctx.ensure_live()?;
        let response = self.backend.cancel_final_task(task_id)?;
        match self.cleanup {
            CleanupReply::Acknowledged => Ok(response),
            CleanupReply::Failed => Err(McpError::internal_error(PRIVATE_PAYLOAD)),
            CleanupReply::Interrupted => {
                assert!(ctx.request_cancellation().cancel());
                Err(McpError::request_cancelled())
            }
        }
    }
    fn open_final_task_listener(
        &mut self,
        notifications: SubscriptionFilter,
    ) -> McpResult<Box<dyn ProxyFinalTaskListener>> {
        self.backend.open_final_task_listener(notifications)
    }
}

fn raw_client(
    creation: CreateTaskResult,
    cleanup: CleanupReply,
) -> (ProxyClient, Arc<Mutex<Vec<&'static str>>>) {
    raw_scripted_client(creation, None, cleanup)
}

fn raw_scripted_client(
    creation: CreateTaskResult,
    following_creation: Option<CreateTaskResult>,
    cleanup: CleanupReply,
) -> (ProxyClient, Arc<Mutex<Vec<&'static str>>>) {
    let calls = Arc::new(Mutex::new(Vec::new()));
    let client = ProxyClient::from_backend_with_upstream_binding(
        RetentionBackend {
            backend: FinalTaskRelayBackend {
                calls: Arc::clone(&calls),
                task: creation,
                listener_events: None,
                cancel_after_task_commit: None,
                final_progress: None,
            },
            cleanup,
            following_creation,
        },
        final_task_relay_binding(ProtocolEra::Modern2026),
        "2026-07-28",
    )
    .unwrap();
    (client, calls)
}

fn finite_policy() -> ProxyTaskRetentionPolicy {
    ProxyTaskRetentionPolicy::new(Duration::from_secs(60), Duration::from_secs(120)).unwrap()
}

fn route(creation: CreateTaskResult, cleanup: CleanupReply) -> BrokerRouteFixture {
    let (client, calls) = raw_client(creation.clone(), cleanup);
    let client = client
        .with_task_retention_policy(finite_policy())
        .unwrap()
        .with_task_limits(ProxyTaskLimits::new(1, 1).unwrap())
        .unwrap();
    let relay = client.final_tasks_relay().unwrap().unwrap();
    BrokerRouteFixture {
        client,
        relay,
        calls,
        creation,
    }
}

fn catalog() -> ProxyCatalog {
    let mut tool = final_catalog_tool();
    tool.name = TOOL.to_owned();
    ProxyCatalog {
        tool_catalog_era: Some(ProtocolEra::Modern2026),
        final_tools: vec![tool],
        ..ProxyCatalog::default()
    }
}

fn facts(can_cancel: bool) -> AuthContext {
    let mut auth = AuthContext::with_subject(PRIVATE_OWNER);
    auth.scopes = vec![
        "invoke".to_owned(),
        "sensitive".to_owned(),
        "inspect".to_owned(),
    ];
    if can_cancel {
        auth.scopes.push("cancel".to_owned());
    }
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

fn access_policy() -> OperationScopePolicy {
    let required = |scope: &str| RequiredScopes::new(vec![scope.to_owned()]).unwrap();
    let methods = ScopeRequestPolicy::new(
        1,
        ScopeImplicationPolicy::new(1, vec![]).unwrap(),
        vec![
            ("tools/call".to_owned(), required("invoke")),
            ("tasks/get".to_owned(), required("inspect")),
            ("tasks/cancel".to_owned(), required("cancel")),
        ],
    )
    .unwrap();
    OperationScopePolicy::new(
        1,
        methods,
        vec![(
            ScopedOperation::ToolCall(TOOL.to_owned()),
            required("sensitive"),
        )],
    )
    .unwrap()
}

fn gateway(route: &BrokerRouteFixture, auth: Arc<Mutex<AuthContext>>) -> Arc<crate::Server> {
    Arc::new(
        crate::ServerBuilder::new("retention-gateway", "1")
            .auth_provider(CurrentFacts(auth))
            .proxy(route.client.clone(), catalog())
            .unwrap()
            .task_access_authorizer(Arc::new(access_policy()))
            .build(),
    )
}

async fn dispatch(
    server: &Arc<crate::Server>,
    cx: &Cx,
    method: &str,
    mut params: serde_json::Value,
) -> JsonRpcResponse {
    params["_meta"] = serde_json::json!({
        "io.modelcontextprotocol/protocolVersion": "2026-07-28",
        "io.modelcontextprotocol/clientCapabilities": {
            "extensions": {fastmcp_protocol::TASKS_EXTENSION: {}}
        }
    });
    let connection = crate::ModernConnection::new();
    let inbound = crate::InboundRequestContext::with_modern_connection(
        cx.clone(),
        7501,
        crate::InboundRequestTransport::Memory,
        &connection,
    );
    Arc::clone(server)
        .dispatch_with_protocol_policy_owned(
            ProtocolPolicy::ModernOnly,
            &inbound,
            JsonRpcRequest::new(method, Some(params), 7501_i64),
            None,
            None,
            None,
            None,
            McpRequestCancellation::new(),
            None,
            Arc::new(|_| {}),
        )
        .await
        .expect("the public gateway returns a correlated response")
}

async fn create(server: &Arc<crate::Server>, cx: &Cx) -> JsonRpcResponse {
    dispatch(
        server,
        cx,
        "tools/call",
        serde_json::json!({"name": TOOL, "arguments": {}}),
    )
    .await
}

fn assert_state_unknown(response: &JsonRpcResponse) {
    assert!(response.result.is_none());
    let error = response
        .error
        .as_ref()
        .expect("a quarantined Task is not a successful Task result");
    assert_eq!(
        error.code.as_i32(),
        Some(i32::from(McpErrorCode::InvalidRequest))
    );
    assert_eq!(
        error.data,
        Some(serde_json::json!({"reason": "UpstreamStateUnknown"}))
    );
    let encoded = serde_json::to_string(response).unwrap();
    for secret in [PRIVATE_TASK_ID, PRIVATE_OWNER, PRIVATE_PAYLOAD] {
        assert!(
            !encoded.contains(secret),
            "quarantine errors must not disclose remote state"
        );
    }
}

fn assert_quota_refused(response: &JsonRpcResponse) {
    assert!(response.error.is_none(), "{:?}", response.error);
    let result = response.result.as_ref().unwrap();
    assert_eq!(result["resultType"], "complete");
    assert_eq!(result["isError"], true);
    assert!(
        result["content"][0]["text"]
            .as_str()
            .unwrap()
            .contains("capacity exhausted")
    );
    assert!(result.get("taskId").is_none());
}

fn private_creation(ttl: Option<u64>) -> CreateTaskResult {
    let mut value =
        serde_json::to_value(final_task_relay_result_with_ttl(PRIVATE_TASK_ID, ttl)).unwrap();
    value["statusMessage"] = serde_json::json!(PRIVATE_PAYLOAD);
    serde_json::from_value(value).unwrap()
}

#[test]
fn proxy_task_retention_requires_explicit_bounded_policy_before_route_admission() {
    let (client, calls) = raw_client(private_creation(Some(60_000)), CleanupReply::Acknowledged);
    let before = client.final_task_registry_snapshot_for_test().unwrap();
    assert_eq!(client.task_retention_policy().unwrap(), None);
    assert!(client.final_tasks_relay().is_err());
    assert!(
        crate::ServerBuilder::new("unconfigured-retention", "1")
            .proxy(client.clone(), catalog())
            .is_err()
    );
    assert_eq!(
        client.final_task_registry_snapshot_for_test().unwrap(),
        before
    );
    assert!(
        client
            .final_task_registry
            .lock()
            .unwrap()
            .orphans
            .is_empty()
    );
    assert!(!client.final_task_registry.lock().unwrap().limits_frozen);
    assert!(client.task_orphan_audit().unwrap().is_empty());
    assert!(
        calls.lock().unwrap().is_empty(),
        "refusal must precede Task-producing contact"
    );

    for (maximum, mapping) in [
        (Duration::ZERO, Duration::from_secs(1)),
        (Duration::from_secs(1), Duration::ZERO),
        (Duration::from_secs(2), Duration::from_secs(1)),
        (
            Duration::from_secs(1),
            Duration::from_secs(365 * 24 * 60 * 60 + 1),
        ),
    ] {
        assert_eq!(
            ProxyTaskRetentionPolicy::new(maximum, mapping)
                .unwrap_err()
                .code,
            McpErrorCode::InvalidParams
        );
    }
    let observer = client.clone();
    let configured = client.with_task_retention_policy(finite_policy()).unwrap();
    assert_eq!(
        observer.task_retention_policy().unwrap(),
        Some(finite_policy())
    );
    assert_eq!(
        finite_policy().maximum_upstream_ttl(),
        Duration::from_secs(60)
    );
    assert_eq!(finite_policy().mapping_lifetime(), Duration::from_secs(120));
    let _relay = configured.final_tasks_relay().unwrap().unwrap();
    assert!(
        observer
            .clone()
            .with_task_retention_policy(relay_test_retention_policy())
            .is_err()
    );
    assert_eq!(
        observer.task_retention_policy().unwrap(),
        Some(finite_policy())
    );
    assert_eq!(
        observer.final_task_registry_snapshot_for_test().unwrap(),
        before
    );
    assert!(calls.lock().unwrap().is_empty());
}

#[test]
fn proxy_task_retention_public_gateway_admits_the_finite_contract_boundary() {
    let runtime = asupersync::runtime::RuntimeBuilder::current_thread()
        .with_reactor(asupersync::runtime::reactor::create_reactor().unwrap())
        .build()
        .unwrap();
    let cx = runtime.request_cx_with_budget(asupersync::Budget::default());
    runtime.block_on(async {
        let route = route(private_creation(Some(60_000)), CleanupReply::Acknowledged);
        let server = gateway(&route, Arc::new(Mutex::new(facts(true))));
        let response = create(&server, &cx).await;
        assert!(response.error.is_none(), "{:?}", response.error);
        let result = response.result.unwrap();
        assert_eq!(result["resultType"], "task");
        assert_eq!(result["ttlMs"], 60_000);
        assert_ne!(result["taskId"], PRIVATE_TASK_ID);
        let handle = result["taskId"].clone();
        let fetched = dispatch(
            &server,
            &cx,
            "tasks/get",
            serde_json::json!({"taskId": handle}),
        )
        .await;
        assert!(fetched.error.is_none(), "{:?}", fetched.error);
        assert_eq!(fetched.result.unwrap()["taskId"], handle);
        assert_eq!(
            route.calls.lock().unwrap().as_slice(),
            ["tools/call", "tasks/get"]
        );
        assert!(route.client.task_orphan_audit().unwrap().is_empty());
        assert!(route.relay.tasks.lock().unwrap().orphans.is_empty());
        assert_eq!(route.relay.tasks.lock().unwrap().tasks.len(), 1);
    });
}

#[test]
fn proxy_task_retention_public_violations_keep_quota_and_only_cancel_with_current_grants() {
    let runtime = asupersync::runtime::RuntimeBuilder::current_thread()
        .with_reactor(asupersync::runtime::reactor::create_reactor().unwrap())
        .build()
        .unwrap();
    let cx = runtime.request_cx_with_budget(asupersync::Budget::default());
    runtime.block_on(async {
        for ttl in [None, Some(60_001)] {
            for (can_cancel, reply, expected_cleanup) in [
                (
                    true,
                    CleanupReply::Acknowledged,
                    ProxyTaskCleanupOutcome::CancelRequested,
                ),
                (
                    false,
                    CleanupReply::Acknowledged,
                    ProxyTaskCleanupOutcome::NotAuthorized,
                ),
                (true, CleanupReply::Failed, ProxyTaskCleanupOutcome::Failed),
                (
                    true,
                    CleanupReply::Interrupted,
                    ProxyTaskCleanupOutcome::Interrupted,
                ),
            ] {
                let route = route(private_creation(ttl), reply);
                let auth = Arc::new(Mutex::new(facts(can_cancel)));
                let server = gateway(&route, Arc::clone(&auth));
                assert_state_unknown(&create(&server, &cx).await);
                let expected_calls = if can_cancel {
                    vec!["tools/call", "tasks/cancel"]
                } else {
                    vec!["tools/call"]
                };
                assert_eq!(*route.calls.lock().unwrap(), expected_calls);
                {
                    let registry = route.relay.tasks.lock().unwrap();
                    assert!(registry.tasks.is_empty());
                    assert!(registry.pending_creations.is_empty());
                    assert_eq!(registry.orphans.len(), 1);
                }
                let audit = route.client.task_orphan_audit().unwrap();
                assert_eq!(audit.len(), 1);
                assert_eq!(
                    audit[0].reason(),
                    if ttl.is_none() {
                        ProxyTaskOrphanReason::NullTtl
                    } else {
                        ProxyTaskOrphanReason::ExcessiveTtl
                    }
                );
                assert_eq!(audit[0].cleanup(), expected_cleanup);
                assert!(
                    !audit[0].quota_released(),
                    "cancel acknowledgement proves neither termination nor retention deletion"
                );
                let diagnostic = format!("{audit:?}");
                for secret in [PRIVATE_TASK_ID, PRIVATE_OWNER, PRIVATE_PAYLOAD] {
                    assert!(!diagnostic.contains(secret));
                }
                assert_quota_refused(&create(&server, &cx).await);
                assert_eq!(
                    *route.calls.lock().unwrap(),
                    expected_calls,
                    "quarantine consumes capacity before the next side effect"
                );

                // The original immutable hard ceiling is the only local release
                // mechanism. A subsequent reservation cannot release it twice.
                let past = Instant::now() - Duration::from_millis(1);
                route
                    .relay
                    .tasks
                    .lock()
                    .unwrap()
                    .orphans
                    .values_mut()
                    .next()
                    .unwrap()
                    .recovery_until = past;
                let owner =
                    McpContext::new(cx.clone(), 7502).with_auth(auth.lock().unwrap().clone());
                let replacement = route.relay.reserve_task_creation(&owner).unwrap();
                assert!(route.relay.tasks.lock().unwrap().orphans.is_empty());
                assert!(route.relay.reserve_task_creation(&owner).is_err());
                let released = route.client.task_orphan_audit().unwrap();
                assert_eq!(released.len(), 1);
                assert_eq!(released[0].sequence(), audit[0].sequence());
                assert!(released[0].quota_released());
                assert_eq!(released[0].cleanup(), expected_cleanup);
                drop(replacement);
                drop(route.relay.reserve_task_creation(&owner).unwrap());
                assert_eq!(route.client.task_orphan_audit().unwrap(), released);
                assert_eq!(*route.calls.lock().unwrap(), expected_calls);
            }
        }
    });
}

#[test]
fn proxy_task_retention_public_orphan_audit_is_bounded_and_redacted() {
    let runtime = asupersync::runtime::RuntimeBuilder::current_thread()
        .with_reactor(asupersync::runtime::reactor::create_reactor().unwrap())
        .build()
        .unwrap();
    let cx = runtime.request_cx_with_budget(asupersync::Budget::default());
    runtime.block_on(async {
        let route = route(private_creation(None), CleanupReply::Acknowledged);
        let server = gateway(&route, Arc::new(Mutex::new(facts(true))));
        let count = super::super::MAX_PROXY_TASK_ORPHAN_AUDITS + 3;
        for _ in 0..count {
            assert_state_unknown(&create(&server, &cx).await);
            let mut registry = route.relay.tasks.lock().unwrap();
            assert_eq!(registry.orphans.len(), 1);
            registry.orphans.values_mut().next().unwrap().recovery_until =
                Instant::now() - Duration::from_millis(1);
            super::super::ProxyFinalTaskRelay::reclaim_expired_tasks(&mut registry, Instant::now());
            assert!(registry.orphans.is_empty());
        }
        let audit = route.client.task_orphan_audit().unwrap();
        assert_eq!(audit.len(), super::super::MAX_PROXY_TASK_ORPHAN_AUDITS);
        assert!(
            audit
                .windows(2)
                .all(|pair| pair[0].sequence() < pair[1].sequence())
        );
        assert!(
            audit
                .iter()
                .all(|entry| entry.reason() == ProxyTaskOrphanReason::NullTtl
                    && entry.cleanup() == ProxyTaskCleanupOutcome::CancelRequested
                    && entry.quota_released())
        );
        let diagnostic = format!("{audit:?}");
        for secret in [PRIVATE_TASK_ID, PRIVATE_OWNER, PRIVATE_PAYLOAD] {
            assert!(!diagnostic.contains(secret));
        }
        assert_eq!(route.calls.lock().unwrap().len(), 2 * count);
    });
}

#[test]
fn proxy_task_retention_racing_cleanup_capabilities_allow_only_one_cancel() {
    let route = route(private_creation(None), CleanupReply::Acknowledged);
    prepare_relay_test_access(&route.relay);
    let context = relay_test_context(Cx::for_testing(), 7510);
    let reservation = route.relay.reserve_task_creation(&context).unwrap();
    let carrier = route
        .relay
        .encode_task_carrier(reservation, route.creation.clone())
        .unwrap();
    let barrier = Arc::new(Barrier::new(8));
    let mut workers = Vec::new();
    for _ in 0..8 {
        let relay = Arc::clone(&route.relay);
        let barrier = Arc::clone(&barrier);
        let context = context.clone();
        let carrier = carrier.clone();
        workers.push(thread::spawn(move || {
            barrier.wait();
            relay.prepare_orphan_cleanup(&context, &carrier, relay_test_operation())
        }));
    }
    let mut admitted = Vec::new();
    for worker in workers {
        match worker.join().unwrap() {
            Ok(Some(cleanup)) => admitted.push(cleanup),
            Ok(None) => {}
            Err(error) => assert_eq!(
                error.data,
                Some(serde_json::json!({"reason": "UpstreamStateUnknown"}))
            ),
        }
    }
    assert_eq!(admitted.len(), 1);
    let error = block_on(admitted.pop().unwrap().run(&context));
    assert_eq!(
        error.data,
        Some(serde_json::json!({"reason": "UpstreamStateUnknown"}))
    );
    assert_eq!(route.calls.lock().unwrap().as_slice(), ["tasks/cancel"]);
    assert_eq!(route.relay.tasks.lock().unwrap().orphans.len(), 1);
    assert!(route.relay.reserve_task_creation(&context).is_err());
    let audit = route.client.task_orphan_audit().unwrap();
    assert_eq!(audit.len(), 1);
    assert_eq!(audit[0].cleanup(), ProxyTaskCleanupOutcome::CancelRequested);
    assert!(!audit[0].quota_released());
}

#[test]
fn proxy_task_retention_abandoned_admitted_cleanup_retains_ambiguity_without_retry() {
    let route = route(private_creation(None), CleanupReply::Acknowledged);
    prepare_relay_test_access(&route.relay);
    let context = relay_test_context(Cx::for_testing(), 7520);
    let reservation = route.relay.reserve_task_creation(&context).unwrap();
    let carrier = route
        .relay
        .encode_task_carrier(reservation, route.creation.clone())
        .unwrap();
    let mut cleanup = route
        .relay
        .prepare_orphan_cleanup(&context, &carrier, relay_test_operation())
        .unwrap()
        .unwrap();
    assert_eq!(
        cleanup.admit_cancel(&context).unwrap(),
        route.creation.task.base().task_id
    );
    drop(cleanup);
    let repeated = route
        .relay
        .prepare_orphan_cleanup(&context, &carrier, relay_test_operation());
    assert!(
        !matches!(repeated, Ok(Some(_))),
        "an abandoned cleanup cannot start a retry"
    );
    let audit = route.client.task_orphan_audit().unwrap();
    assert_eq!(audit.len(), 1);
    assert_eq!(audit[0].cleanup(), ProxyTaskCleanupOutcome::Interrupted);
    assert!(!audit[0].quota_released());
    assert_eq!(route.relay.tasks.lock().unwrap().orphans.len(), 1);
    assert!(route.relay.reserve_task_creation(&context).is_err());
    assert!(route.calls.lock().unwrap().is_empty());
}

#[test]
fn proxy_task_retention_unpolled_cleanup_can_resume_without_releasing_quota() {
    let route = route(private_creation(None), CleanupReply::Acknowledged);
    prepare_relay_test_access(&route.relay);
    let context = relay_test_context(Cx::for_testing(), 7521);
    let reservation = route.relay.reserve_task_creation(&context).unwrap();
    let carrier = route
        .relay
        .encode_task_carrier(reservation, route.creation.clone())
        .unwrap();
    let cleanup = route
        .relay
        .prepare_orphan_cleanup(&context, &carrier, relay_test_operation())
        .unwrap()
        .unwrap();
    drop(cleanup.run(&context));
    assert!(route.relay.reserve_task_creation(&context).is_err());
    assert!(route.calls.lock().unwrap().is_empty());
    let replacement = route
        .relay
        .prepare_orphan_cleanup(&context, &carrier, relay_test_operation())
        .unwrap()
        .unwrap();
    let error = block_on(replacement.run(&context));
    assert_eq!(
        error.data,
        Some(serde_json::json!({"reason": "UpstreamStateUnknown"}))
    );
    assert_eq!(route.calls.lock().unwrap().as_slice(), ["tasks/cancel"]);
    let audit = route.client.task_orphan_audit().unwrap();
    assert_eq!(audit.len(), 1);
    assert_eq!(audit[0].cleanup(), ProxyTaskCleanupOutcome::CancelRequested);
    assert!(!audit[0].quota_released());
}

#[test]
fn proxy_task_retention_public_repeated_identity_cannot_escape_quarantine() {
    let runtime = asupersync::runtime::RuntimeBuilder::current_thread()
        .with_reactor(asupersync::runtime::reactor::create_reactor().unwrap())
        .build()
        .unwrap();
    let cx = runtime.request_cx_with_budget(asupersync::Budget::default());
    runtime.block_on(async {
        let creation = private_creation(None);
        let finite = CreateTaskResult {
            task: relay_task_with_ttl(&creation.task, Some(60_000)),
            ..creation.clone()
        };
        let (client, calls) =
            raw_scripted_client(creation.clone(), Some(finite), CleanupReply::Acknowledged);
        let client = client
            .with_task_retention_policy(finite_policy())
            .unwrap()
            .with_task_limits(ProxyTaskLimits::new(2, 2).unwrap())
            .unwrap();
        let relay = client.final_tasks_relay().unwrap().unwrap();
        let route = BrokerRouteFixture {
            client,
            relay,
            calls,
            creation,
        };
        let server = gateway(&route, Arc::new(Mutex::new(facts(true))));
        assert_state_unknown(&create(&server, &cx).await);
        let ceiling = route
            .relay
            .tasks
            .lock()
            .unwrap()
            .orphans
            .values()
            .next()
            .unwrap()
            .recovery_until;
        assert_state_unknown(&create(&server, &cx).await);
        {
            let registry = route.relay.tasks.lock().unwrap();
            assert!(
                registry.tasks.is_empty(),
                "a valid-looking replay cannot become an ordinary handle"
            );
            assert!(registry.pending_creations.is_empty());
            assert_eq!(
                registry.orphans.len(),
                2,
                "each returned alias retains its reserved charge"
            );
            assert!(
                registry
                    .orphans
                    .values()
                    .all(|orphan| orphan.recovery_until == ceiling)
            );
        }
        assert_eq!(
            route.calls.lock().unwrap().as_slice(),
            ["tools/call", "tasks/cancel", "tools/call"]
        );
        let audit = route.client.task_orphan_audit().unwrap();
        assert_eq!(audit.len(), 2);
        assert!(
            audit
                .iter()
                .all(|entry| entry.reason() == ProxyTaskOrphanReason::NullTtl
                    && entry.cleanup() == ProxyTaskCleanupOutcome::CancelRequested
                    && !entry.quota_released())
        );
        assert_quota_refused(&create(&server, &cx).await);
        assert_eq!(
            route.calls.lock().unwrap().as_slice(),
            ["tools/call", "tasks/cancel", "tools/call"]
        );
    });
}

#[test]
fn proxy_task_retention_stale_invalid_reply_cannot_quarantine_a_newer_valid_snapshot() {
    for invalid_ttl in [None, Some(31 * 24 * 60 * 60 * 1_000)] {
        let initial =
            final_task_relay_result_with_ttl("retention-revision-race", Some(60_000)).task;
        let renewed = relay_task_with_ttl(&initial, Some(120_000));
        let invalid = relay_task_with_ttl(&initial, invalid_ttl);
        let fixture = task_reconciliation_fixture(initial, Vec::new());
        let route = Arc::downgrade(&fixture.relay);
        let owner = super::super::proxy_task_owner(&fixture.context).unwrap();
        let handle = fixture.handle.clone();
        let concurrent = renewed.clone();
        fixture.replies.lock().unwrap().extend([
            TaskReconciliationReply {
                result: Ok(invalid),
                before_reply: Some(Box::new(move || {
                    let route = route.upgrade().unwrap();
                    let revision = route
                        .known_locator(owner, &handle)
                        .unwrap()
                        .snapshot_revision;
                    assert!(
                        route
                            .record_task(owner, &handle, &concurrent, Some(revision))
                            .unwrap()
                            .is_some()
                    );
                })),
            },
            TaskReconciliationReply {
                result: Ok(renewed),
                before_reply: None,
            },
        ]);
        assert_eq!(task_reconciliation_get(&fixture).unwrap()["ttlMs"], 120_000);
        assert_eq!(
            fixture.calls.lock().unwrap().as_slice(),
            ["tasks/get", "tasks/get"]
        );
        assert!(fixture.relay.tasks.lock().unwrap().orphans.is_empty());
        assert!(fixture.proxy.task_orphan_audit().unwrap().is_empty());
        assert_eq!(fixture.relay.tasks.lock().unwrap().tasks.len(), 1);
    }
}

#[test]
fn proxy_task_retention_invalid_notification_requires_authoritative_confirmation() {
    for invalid_ttl in [None, Some(31 * 24 * 60 * 60 * 1_000)] {
        let initial = final_task_relay_result_with_ttl("retention-event-hint", Some(60_000)).task;
        let renewed = relay_task_with_ttl(&initial, Some(120_000));
        let invalid = relay_task_with_ttl(&initial, invalid_ttl);
        let fixture = task_reconciliation_fixture(initial, vec![invalid]);
        fixture
            .replies
            .lock()
            .unwrap()
            .push_back(TaskReconciliationReply {
                result: Ok(renewed),
                before_reply: None,
            });
        let mut listener = block_on(fixture.relay.open_listener_async(
            &fixture.context,
            relay_test_filter(vec![fixture.handle.clone()]),
        ))
        .unwrap();
        let cancellation = McpRequestCancellation::new();
        assert!(matches!(
            listener.next(fixture.context.cx(), &cancellation).unwrap(),
            ProxyFinalTaskListenerEvent::Acknowledged(_)
        ));
        let ProxyFinalTaskListenerEvent::Notification(notification) =
            block_on(listener.next_async(fixture.context.cx(), &cancellation)).unwrap()
        else {
            panic!("only the authoritative valid snapshot may be delivered");
        };
        assert_eq!(
            serde_json::to_value(notification).unwrap()["params"]["ttlMs"],
            120_000
        );
        assert_eq!(
            fixture.calls.lock().unwrap().as_slice(),
            ["subscriptions/listen", "tasks/get"]
        );
        assert!(fixture.relay.tasks.lock().unwrap().orphans.is_empty());
        assert!(fixture.proxy.task_orphan_audit().unwrap().is_empty());
    }
}

#[test]
fn proxy_task_retention_pending_http_cleanup_obeys_the_callers_tighter_deadline() {
    use std::sync::atomic::{AtomicUsize, Ordering};

    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let address = listener.local_addr().unwrap();
    let received = Arc::new(AtomicUsize::new(0));
    let peer_received = Arc::clone(&received);
    let (release, released) = std::sync::mpsc::sync_channel::<()>(1);
    let peer = thread::spawn(move || {
        let accept = || {
            let deadline = Instant::now() + Duration::from_secs(2);
            loop {
                match listener.accept() {
                    Ok((stream, _)) => {
                        stream
                            .set_read_timeout(Some(Duration::from_secs(2)))
                            .unwrap();
                        stream
                            .set_write_timeout(Some(Duration::from_secs(2)))
                            .unwrap();
                        return stream;
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        assert!(
                            Instant::now() < deadline,
                            "the native cleanup peer receives its bounded request"
                        );
                        thread::sleep(Duration::from_millis(1));
                    }
                    Err(error) => panic!("native cleanup peer: {error}"),
                }
            }
        };
        let mut discovery = accept();
        let request: serde_json::Value =
            serde_json::from_slice(&read_http_request(&mut discovery).body).unwrap();
        assert_eq!(request["method"], "server/discover");
        write_http_discovery_response(
            &mut discovery,
            &serde_json::to_vec(&serde_json::json!({
                "jsonrpc": "2.0", "id": request["id"], "result": {
                    "supportedVersions": ["2026-07-28"],
                    "capabilities": {"extensions": {fastmcp_protocol::TASKS_EXTENSION: {}}},
                    "ttlMs": 0, "cacheScope": "private"
                }
            }))
            .unwrap(),
        );
        drop(discovery);
        let mut cancel = accept();
        let request: serde_json::Value =
            serde_json::from_slice(&read_http_request(&mut cancel).body).unwrap();
        assert_eq!(request["method"], "tasks/cancel");
        assert_eq!(request["params"]["taskId"], PRIVATE_TASK_ID);
        peer_received.fetch_add(1, Ordering::AcqRel);
        released
            .recv_timeout(Duration::from_secs(2))
            .expect("deadline completion releases the held peer");
        // The reply is deliberately later than the caller's deadline. Whether
        // the closed socket accepts these bytes cannot prove Task termination.
        let body = serde_json::to_vec(&serde_json::json!({
            "jsonrpc": "2.0", "id": request["id"], "result": {"resultType": "complete"}
        }))
        .unwrap();
        let head = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            body.len()
        );
        let _late_reply = cancel
            .write_all(head.as_bytes())
            .and_then(|()| cancel.write_all(&body));
        assert!(
            matches!(listener.accept(), Err(error) if error.kind() == std::io::ErrorKind::WouldBlock),
            "cleanup never opens a retry connection"
        );
    });
    let runtime = asupersync::runtime::RuntimeBuilder::current_thread()
        .with_reactor(asupersync::runtime::reactor::create_reactor().unwrap())
        .build()
        .unwrap();
    let cx = runtime.request_cx_with_budget(asupersync::Budget::default());
    runtime.block_on(async {
        let plan = ClientProtocolPlan::http(
            ProtocolPolicy::ModernOnly,
            Some(CanonicalHttpUrl::parse(&format!("http://{address}/mcp")).unwrap()),
            None,
            None,
            "cleanup-credential".to_owned(),
            "cleanup-owner".to_owned(),
            "retention-cleanup-http".to_owned(),
            1,
            1,
            0,
        )
        .unwrap();
        let capabilities = ClientCapabilities::default();
        let connection = ClientHttpConnection::connect(
            &cx,
            plan,
            proxy_http_client_info(),
            capabilities.clone(),
        )
        .await
        .unwrap();
        let binding = final_task_relay_binding(ProtocolEra::Modern2026);
        let client = ProxyClient::from_backend_with_upstream_binding(
            ProxyHttpClient::new(
                binding,
                connection,
                cx.clone(),
                proxy_http_client_info(),
                capabilities,
            ),
            binding,
            "2026-07-28",
        )
        .unwrap()
        .with_task_retention_policy(finite_policy())
        .unwrap()
        .with_task_limits(ProxyTaskLimits::new(1, 1).unwrap())
        .unwrap();
        let relay = client.final_tasks_relay().unwrap().unwrap();
        prepare_relay_test_access(&relay);
        let owner = relay_test_context(cx.clone(), 7530);
        let reservation = relay.reserve_task_creation(&owner).unwrap();
        let carrier = relay
            .encode_task_carrier(reservation, private_creation(None))
            .unwrap();
        let cleanup = relay
            .prepare_orphan_cleanup(&owner, &carrier, relay_test_operation())
            .unwrap()
            .unwrap();
        let deadline_context = owner
            .clone()
            .with_operation_deadline(Some(cx.now().saturating_add_nanos(250_000_000)));
        let error = asupersync::time::timeout_at(
            cx.now().saturating_add_nanos(2_000_000_000),
            cleanup.run(&deadline_context),
        )
        .await
        .expect("the caller's 250 ms deadline must beat the 5 s cleanup ceiling");
        assert_eq!(
            error.data,
            Some(serde_json::json!({"reason": "UpstreamStateUnknown"}))
        );
        assert_eq!(received.load(Ordering::Acquire), 1);
        let audit = client.task_orphan_audit().unwrap();
        assert_eq!(audit.len(), 1);
        assert_eq!(audit[0].cleanup(), ProxyTaskCleanupOutcome::Interrupted);
        assert!(!audit[0].quota_released());
        assert_eq!(relay.tasks.lock().unwrap().orphans.len(), 1);
        assert!(relay.reserve_task_creation(&owner).is_err());
        assert!(!matches!(
            relay.prepare_orphan_cleanup(&owner, &carrier, relay_test_operation()),
            Ok(Some(_))
        ));
        release.send(()).unwrap();
        peer.join().expect("the bounded cleanup peer quiesces");
        assert_eq!(
            client.task_orphan_audit().unwrap(),
            audit,
            "a late network reply cannot release the orphan charge"
        );
        assert!(relay.reserve_task_creation(&owner).is_err());
    });
}
