use super::*;
use crate::ProxyTaskLimits;
use fastmcp_core::{AuthContext, McpResult, Outcome};
use fastmcp_protocol::{FinalTaskId, JsonRpcRequest, JsonRpcResponse};
use std::sync::Barrier;
use std::sync::atomic::{AtomicUsize, Ordering};

fn configured_client(
    cancellation: Option<McpRequestCancellation>,
) -> (ProxyClient, Arc<Mutex<Vec<&'static str>>>, CreateTaskResult) {
    let calls = Arc::new(Mutex::new(Vec::new()));
    let creation = final_task_relay_result();
    let client = ProxyClient::from_backend_with_upstream_binding(
        FinalTaskRelayBackend {
            calls: Arc::clone(&calls),
            task: creation.clone(),
            listener_events: None,
            cancel_after_task_commit: cancellation,
            final_progress: None,
        },
        final_task_relay_binding(ProtocolEra::Modern2026),
        "2026-07-28",
    )
    .unwrap();
    let client = with_relay_test_retention(client);
    (client, calls, creation)
}

fn route(maximum_tasks: usize, maximum_tasks_per_owner: usize) -> BrokerRouteFixture {
    let (client, calls, creation) = configured_client(None);
    let client = client
        .with_task_limits(ProxyTaskLimits::new(maximum_tasks, maximum_tasks_per_owner).unwrap())
        .unwrap();
    let relay = client.final_tasks_relay().unwrap().unwrap();
    prepare_relay_test_access(&relay);
    BrokerRouteFixture {
        client,
        relay,
        calls,
        creation,
    }
}

fn owner(subject: &str, request_id: u64) -> McpContext {
    McpContext::new(Cx::for_testing(), request_id).with_auth(AuthContext::with_subject(subject))
}

fn catalog(name: &str) -> ProxyCatalog {
    let mut tool = final_catalog_tool();
    tool.name = name.to_owned();
    ProxyCatalog {
        tool_catalog_era: Some(ProtocolEra::Modern2026),
        final_tools: vec![tool],
        ..ProxyCatalog::default()
    }
}

struct CurrentOwner(Arc<Mutex<AuthContext>>);

impl crate::auth::AuthProvider for CurrentOwner {
    fn authenticate(
        &self,
        _ctx: &McpContext,
        _request: crate::auth::AuthRequest<'_>,
    ) -> McpResult<AuthContext> {
        Ok(self.0.lock().unwrap().clone())
    }
}

async fn call(server: &Arc<crate::Server>, cx: &Cx, name: &str) -> JsonRpcResponse {
    // Each request uses a fresh connection. The quota belongs to the verified
    // principal and route, not a connection or transient request context.
    let connection = crate::ModernConnection::new();
    let inbound = crate::InboundRequestContext::with_modern_connection(
        cx.clone(),
        7401,
        crate::InboundRequestTransport::Memory,
        &connection,
    );
    let request = JsonRpcRequest::new(
        "tools/call",
        Some(serde_json::json!({
            "name": name,
            "arguments": {},
            "_meta": {
                "io.modelcontextprotocol/protocolVersion": "2026-07-28",
                "io.modelcontextprotocol/clientCapabilities": {
                    "extensions": {fastmcp_protocol::TASKS_EXTENSION: {}}
                }
            }
        })),
        7401_i64,
    );
    Arc::clone(server)
        .dispatch_with_protocol_policy_owned(
            ProtocolPolicy::ModernOnly,
            &inbound,
            request,
            None,
            None,
            None,
            None,
            McpRequestCancellation::new(),
            None,
            Arc::new(|_| {}),
        )
        .await
        .expect("correlated proxy response")
}

fn task_handle(response: JsonRpcResponse) -> FinalTaskId {
    assert!(response.error.is_none(), "{:?}", response.error);
    let result = response.result.expect("Task result");
    assert_eq!(result["resultType"], "task");
    serde_json::from_value(result["taskId"].clone()).unwrap()
}

fn assert_quota_refusal(response: JsonRpcResponse) {
    assert!(response.error.is_none(), "{:?}", response.error);
    let result = response.result.expect("ordinary tool error result");
    assert_eq!(result["resultType"], "complete");
    assert_eq!(result["isError"], true);
    assert!(
        result["content"][0]["text"]
            .as_str()
            .unwrap()
            .contains("capacity exhausted"),
        "{result}"
    );
    assert!(result.get("taskId").is_none());
}

#[test]
fn proxy_task_quota_configuration_is_bounded_shared_and_frozen_before_dispatch() {
    let defaults = ProxyTaskLimits::default();
    assert_eq!(defaults.maximum_tasks(), 128);
    assert_eq!(defaults.maximum_tasks_per_owner(), 128);
    assert_eq!(ProxyTaskLimits::new(128, 128).unwrap(), defaults);
    for (total, per_owner) in [(0, 1), (1, 0), (1, 2), (129, 1), (usize::MAX, 1)] {
        assert_eq!(
            ProxyTaskLimits::new(total, per_owner).unwrap_err().code,
            McpErrorCode::InvalidParams,
        );
    }

    let (client, calls, _) = configured_client(None);
    let observer = client.clone();
    let limits = ProxyTaskLimits::new(2, 1).unwrap();
    let configured = client.with_task_limits(limits).unwrap();
    assert_eq!(observer.task_limits().unwrap(), limits);
    assert_eq!(configured.task_limits().unwrap(), limits);
    let _relay = observer.final_tasks_relay().unwrap().unwrap();
    assert!(
        configured
            .with_task_limits(ProxyTaskLimits::new(3, 2).unwrap())
            .is_err(),
        "an admitted route cannot be widened through a previously cloned client"
    );
    assert_eq!(observer.task_limits().unwrap(), limits);
    assert!(calls.lock().unwrap().is_empty());
    assert_eq!(
        observer.final_task_registry_snapshot_for_test().unwrap(),
        serde_json::json!({"pendingCreations": 0, "tasks": {}}),
    );
}

#[test]
fn proxy_task_quota_public_dispatch_isolates_owners_and_routes_before_upstream_effects() {
    let runtime = asupersync::runtime::RuntimeBuilder::current_thread()
        .with_reactor(asupersync::runtime::reactor::create_reactor().unwrap())
        .build()
        .unwrap();
    let cx = runtime.request_cx_with_budget(asupersync::Budget::default());
    runtime.block_on(async {
        let shared = route(2, 1);
        let independent = route(1, 1);
        let current_owner = Arc::new(Mutex::new(AuthContext::with_subject("quota-alice")));
        let server = Arc::new(
            crate::ServerBuilder::new("quota-gateway", "1")
                .auth_provider(CurrentOwner(Arc::clone(&current_owner)))
                .proxy(shared.client.clone(), catalog("weather"))
                .unwrap()
                .proxy(independent.client.clone(), catalog("forecast"))
                .unwrap()
                .task_access_authorizer(Arc::new(RelayTestAccessAuthorizer))
                .build(),
        );

        let alice = task_handle(call(&server, &cx, "weather").await);
        let before = shared
            .client
            .final_task_registry_snapshot_for_test()
            .unwrap();
        current_owner.lock().unwrap().scopes = vec!["refreshed-grant".to_owned()];
        assert_quota_refusal(call(&server, &cx, "weather").await);
        assert_eq!(shared.calls.lock().unwrap().as_slice(), ["tools/call"]);
        assert_eq!(
            shared
                .client
                .final_task_registry_snapshot_for_test()
                .unwrap(),
            before
        );

        // The same principal retains independent capacity on another route.
        let other_route = task_handle(call(&server, &cx, "forecast").await);
        assert_ne!(alice, other_route);
        assert_eq!(independent.calls.lock().unwrap().as_slice(), ["tools/call"]);

        // Changing only the verified principal admits the remaining route slot.
        *current_owner.lock().unwrap() = AuthContext::with_subject("quota-bob");
        let bob = task_handle(call(&server, &cx, "weather").await);
        assert_ne!(alice, bob);
        assert_eq!(
            shared.calls.lock().unwrap().as_slice(),
            ["tools/call", "tools/call"]
        );
        let full = shared
            .client
            .final_task_registry_snapshot_for_test()
            .unwrap();
        assert_eq!(full["pendingCreations"], 0);
        assert_eq!(full["tasks"].as_object().unwrap().len(), 2);

        *current_owner.lock().unwrap() = AuthContext::with_subject("quota-charlie");
        assert_quota_refusal(call(&server, &cx, "weather").await);
        assert_quota_refusal(call(&server, &cx, "forecast").await);
        assert_eq!(
            shared
                .client
                .final_task_registry_snapshot_for_test()
                .unwrap(),
            full
        );
        assert_eq!(shared.calls.lock().unwrap().len(), 2);
        assert_eq!(independent.calls.lock().unwrap().len(), 1);
    });
    assert!(runtime.shutdown_timeout(Duration::from_secs(2)));
}

#[test]
fn proxy_task_quota_pending_reservations_charge_the_owner_and_drop_releases_capacity() {
    let route = route(2, 1);
    let sibling = route.client.clone().final_tasks_relay().unwrap().unwrap();
    let alice = owner("quota-alice", 7410);
    let bob = owner("quota-bob", 7411);
    let charlie = owner("quota-charlie", 7412);
    let first = route.relay.reserve_task_creation(&alice).unwrap();
    let before = route
        .client
        .final_task_registry_snapshot_for_test()
        .unwrap();
    assert_eq!(before["pendingCreations"], 1);
    assert!(sibling.reserve_task_creation(&alice).is_err());
    assert_eq!(
        route
            .client
            .final_task_registry_snapshot_for_test()
            .unwrap(),
        before
    );
    let second = sibling.reserve_task_creation(&bob).unwrap();
    assert!(route.relay.reserve_task_creation(&charlie).is_err());

    drop(first);
    let replacement = sibling.reserve_task_creation(&charlie).unwrap();
    assert!(route.relay.reserve_task_creation(&charlie).is_err());
    assert!(route.relay.reserve_task_creation(&alice).is_err());
    drop(second);
    let alice_again = route.relay.reserve_task_creation(&alice).unwrap();
    drop(replacement);
    drop(alice_again);
    assert_eq!(
        route
            .client
            .final_task_registry_snapshot_for_test()
            .unwrap(),
        serde_json::json!({"pendingCreations": 0, "tasks": {}}),
    );
    assert!(route.calls.lock().unwrap().is_empty());
}

#[test]
fn proxy_task_quota_concurrent_reservations_cannot_overbook_one_owner() {
    let route = route(8, 1);
    let start = Barrier::new(9);
    let admitted = Barrier::new(9);
    let release = Barrier::new(9);
    let winners = AtomicUsize::new(0);
    let (winner_count, pending_count) = thread::scope(|scope| {
        let mut workers = Vec::new();
        for request_id in 0..8 {
            let relay = Arc::clone(&route.relay);
            let (start, admitted, release, winners) = (&start, &admitted, &release, &winners);
            workers.push(scope.spawn(move || {
                let ctx = owner("one-concurrent-owner", 7420 + request_id);
                start.wait();
                let reservation = relay.reserve_task_creation(&ctx);
                if reservation.is_ok() {
                    winners.fetch_add(1, Ordering::SeqCst);
                }
                admitted.wait();
                release.wait();
                drop(reservation);
            }));
        }
        start.wait();
        admitted.wait();
        let winner_count = winners.load(Ordering::SeqCst);
        let pending_count = route.relay.tasks.lock().unwrap().pending_creations.len();
        release.wait();
        for worker in workers {
            worker.join().unwrap();
        }
        (winner_count, pending_count)
    });
    assert_eq!(winner_count, 1);
    assert_eq!(pending_count, 1);
    assert!(
        route
            .relay
            .tasks
            .lock()
            .unwrap()
            .pending_creations
            .is_empty()
    );
    assert!(
        route
            .relay
            .reserve_task_creation(&owner("one-concurrent-owner", 7430))
            .is_ok()
    );
    assert!(route.calls.lock().unwrap().is_empty());
}

#[test]
fn proxy_task_quota_counts_aliases_and_recovery_locators_until_retention_ends() {
    let route = route(3, 2);
    let alice = owner("quota-alice", 7440);
    let upstream = final_task_relay_result_with_ttl("shared-upstream-task", Some(60_000));
    let first = issue_relay_test_task(&route.relay, &alice, upstream.task.clone());
    let second = issue_relay_test_task(&route.relay, &alice, upstream.task);
    assert_ne!(first.task.base().task_id, second.task.base().task_id);
    assert!(route.relay.reserve_task_creation(&alice).is_err());

    let now = Instant::now();
    {
        let mut registry = route.relay.tasks.lock().unwrap();
        for retained in registry.tasks.values_mut() {
            retained.expires_at = Some(now - Duration::from_secs(1));
            retained.recovery_until = Some(now + Duration::from_secs(60));
        }
    }
    let before = route
        .client
        .final_task_registry_snapshot_for_test()
        .unwrap();
    assert!(route.relay.reserve_task_creation(&alice).is_err());
    assert_eq!(
        route
            .client
            .final_task_registry_snapshot_for_test()
            .unwrap(),
        before
    );
    let bob = route
        .relay
        .reserve_task_creation(&owner("quota-bob", 7441))
        .unwrap();
    drop(bob);

    {
        let mut registry = route.relay.tasks.lock().unwrap();
        for retained in registry.tasks.values_mut() {
            retained.recovery_until = Some(now - Duration::from_secs(1));
        }
    }
    let replacement = route.relay.reserve_task_creation(&alice).unwrap();
    assert!(route.relay.tasks.lock().unwrap().tasks.is_empty());
    drop(replacement);
    assert!(route.calls.lock().unwrap().is_empty());
}

#[test]
fn proxy_task_quota_expired_remote_creation_retains_its_committed_owner_slot() {
    let route = route(1, 1);
    let alice = owner("quota-alice", 7450);
    let reservation = route.relay.reserve_task_creation(&alice).unwrap();
    let expired = (chrono::Utc::now() - chrono::Duration::minutes(5))
        .to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
    let creation = serde_json::from_value(serde_json::json!({
        "resultType": "task",
        "taskId": "expired-upstream-task",
        "status": "input_required",
        "createdAt": expired,
        "lastUpdatedAt": expired,
        "ttlMs": 1,
        "inputRequests": {},
    }))
    .unwrap();
    let carrier = route
        .relay
        .encode_task_carrier(reservation, creation)
        .expect("a committed Task outside the contract retains a private cleanup carrier");
    assert_eq!(
        route
            .client
            .final_task_registry_snapshot_for_test()
            .unwrap(),
        serde_json::json!({"pendingCreations": 0, "tasks": {}}),
    );
    assert_eq!(route.relay.tasks.lock().unwrap().orphans.len(), 1);
    assert!(route.relay.reserve_task_creation(&alice).is_err());
    assert!(
        route
            .relay
            .reserve_task_creation(&owner("quota-bob", 7451))
            .is_err()
    );
    let audit = route.client.task_orphan_audit().unwrap();
    assert_eq!(audit.len(), 1);
    assert_eq!(
        audit[0].reason(),
        super::super::ProxyTaskOrphanReason::InvalidDeadline
    );
    assert!(!audit[0].quota_released());
    assert!(route.calls.lock().unwrap().is_empty());
    drop(carrier);
    assert!(route.relay.reserve_task_creation(&alice).is_err());
}

#[test]
fn proxy_task_quota_cancellation_after_remote_commit_retains_the_issued_mapping() {
    let cancellation = McpRequestCancellation::new();
    let (client, calls, _) = configured_client(Some(cancellation.clone()));
    let client = client
        .with_task_limits(ProxyTaskLimits::new(1, 1).unwrap())
        .unwrap();
    let relay = client.final_tasks_relay().unwrap().unwrap();
    prepare_relay_test_access(&relay);
    let handler = ProxyToolHandler::from_final_with_task_relay(
        final_catalog_tool(),
        client.clone(),
        Arc::clone(&relay),
    )
    .unwrap();
    let ctx = owner("quota-alice", 7460)
        .with_request_cancellation(cancellation.clone())
        .with_client_capabilities(fastmcp_core::ClientCapabilityInfo::new().with_tasks());
    let outcome = block_on(handler.call_final_outcome_async(&ctx, serde_json::json!({})));
    let Outcome::Ok(FinalToolOutcome::CreateTask { .. }) = outcome else {
        panic!("an upstream Task that committed before cancellation must remain retained");
    };
    assert!(cancellation.is_cancel_requested());
    let retained = client.final_task_registry_snapshot_for_test().unwrap();
    assert_eq!(retained["pendingCreations"], 0);
    assert_eq!(retained["tasks"].as_object().unwrap().len(), 1);
    assert!(
        relay
            .reserve_task_creation(&owner("quota-alice", 7461))
            .is_err()
    );
    assert!(
        relay
            .reserve_task_creation(&owner("quota-bob", 7462))
            .is_err()
    );
    assert_eq!(
        client.final_task_registry_snapshot_for_test().unwrap(),
        retained
    );
    assert_eq!(calls.lock().unwrap().as_slice(), ["tools/call"]);
}
