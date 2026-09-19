use super::*;
use std::sync::Arc;
use std::sync::atomic::AtomicUsize;
use std::time::Instant;
use fastmcp_core::CanonicalHttpUrl;
use fastmcp_protocol::{ClientCapabilities, FinalRequestMeta, FINAL_CLIENT_CAPABILITIES_META_KEY};
use crate::http_auth::BoundBearerCredential;
use crate::http_auth::discovery::client_credentials::{
    ClientCredentialsClient, ClientInner, ClientSecret, MachineAuthentication, TokenState,
};
use super::super::super::ClientCredentialsTasksLimits;

fn id(value: &str) -> TaskId { TaskId::parse(value).unwrap() }
fn task(id: &str, status: &str) -> Task {
    let mut value = json!({"taskId":id,"status":status,"createdAt":"2026-09-19T00:00:00Z",
        "lastUpdatedAt":"2026-09-19T00:00:00Z","ttlMs":60000});
    match status {
        "input_required" => value["inputRequests"] = json!({"roots":{"method":"roots/list"}}),
        "completed" => value["result"] = json!({"content":[]}),
        "failed" => value["error"] = json!({"code":-32603,"message":"fixture"}),
        _ => {},
    }
    serde_json::from_value(value).unwrap()
}
fn filter(value: serde_json::Value) -> SubscriptionFilter { serde_json::from_value(value).unwrap() }
pub(super) fn runtime() -> asupersync::runtime::Runtime {
    asupersync::runtime::RuntimeBuilder::current_thread()
        .with_reactor(asupersync::runtime::reactor::create_reactor().unwrap())
        .blocking_threads(0, 2).build().unwrap()
}
// No grant is installed: the public preflight/cancellation cases must not
// reach the deliberately unroutable token endpoint. This is not a TLS fixture.
pub(super) fn consumer() -> ClientCredentialsTasksClient {
    let client = ClientCredentialsClient { inner: Arc::new(ClientInner {
        resource: CanonicalHttpUrl::parse("https://machine.example/mcp").unwrap(),
        token_endpoint: CanonicalHttpUrl::parse("https://issuer.example/token").unwrap(),
        client_id: "watch-fixture".to_owned(), scopes: vec![],
        authentication: MachineAuthentication::Basic(Arc::new(ClientSecret("fixture-secret".to_owned()))),
        issuer_roots: vec![], timeout: Duration::from_secs(5), maximum_lifetime: Duration::from_secs(600),
        leeway: Duration::from_secs(30), closed: McpRequestCancellation::new(),
        pending: AtomicUsize::new(0), state: Arc::new(asupersync::sync::Mutex::new(TokenState::default())),
    }) };
    let mut metadata = FinalRequestMeta::new(ClientCapabilities::default());
    metadata.additional_metadata.insert("com.example/tenant".to_owned(), json!("retained"));
    ClientCredentialsTasksClient::new(client, metadata, ClientCredentialsTasksLimits::default()).unwrap()
}
fn binding(client: &ClientCredentialsTasksClient) -> ClientCredentialsSnapshot {
    let expires_at = Instant::now() + Duration::from_secs(600);
    let bearer = BoundBearerCredential::bind_with_expiry(client.client.resource().clone(), "test-access", expires_at)
        .unwrap().for_owner(&client.client.inner.closed).unwrap();
    ClientCredentialsSnapshot { bearer, scopes: vec![], expires_at, generation: 7 }
}

#[test]
fn machine_watch_selection_is_nonempty_unique_and_fits_the_initial_budget() {
    assert!(WatchState::new(vec![id("one"),id("two")],2).is_ok());
    for (ids, maximum) in [(vec![],2),(vec![id("one"),id("one")],2),(vec![id("one"),id("two")],1),
        ((0..129).map(|n| id(&format!("task-{n}"))).collect(),129)]
    { assert!(matches!(WatchState::new(ids,maximum),Err(ClientCredentialsTaskWatchError::InvalidSelection))); }
}
#[test]
fn machine_watch_acknowledgement_covers_the_exact_selection_before_gets() {
    let state = WatchState::new(vec![id("one"),id("two")],8).unwrap();
    assert!(state.admit_acknowledgement(&filter(json!({"taskIds":["two","one"]}))).is_ok());
    for value in [json!({}),json!({"taskIds":[]}),json!({"taskIds":["one"]}),
        json!({"taskIds":["one","one"]}),json!({"taskIds":["one","other"]})]
    {
        assert!(matches!(state.admit_acknowledgement(&filter(value)),Err(ClientCredentialsTaskWatchError::IncompleteAcknowledgement)));
        assert_eq!(state.snapshots,0);
        assert_eq!(state.initial.len(),2);
    }
}
#[test]
fn machine_watch_notifications_do_not_publish_or_regress_terminals() {
    let mut state = WatchState::new(vec![id("one"),id("two")],8).unwrap();
    let notification = task("one","cancelled");
    assert!(state.needs_snapshot(&notification.base().task_id).unwrap());
    assert_eq!(state.terminal,[false,false]);
    assert!(!state.record_snapshot(&task("one","working")).unwrap());
    assert!(!state.record_snapshot(&task("one","completed")).unwrap());
    assert!(!state.needs_snapshot(&id("one")).unwrap());
    assert!(state.needs_snapshot(&id("other")).is_err());
    assert!(state.record_snapshot(&task("one","working")).is_err());
    assert_eq!(state.terminal,[true,false]);
    assert!(state.record_snapshot(&task("two","failed")).unwrap());
}
#[test]
fn machine_watch_preserves_all_terminal_kinds_and_keeps_input_required_live() {
    for status in ["completed","failed","cancelled"] {
        let mut state = WatchState::new(vec![id("one")],8).unwrap();
        assert!(!state.record_snapshot(&task("one","input_required")).unwrap());
        let terminal = task("one",status);
        assert!(state.record_snapshot(&terminal).unwrap());
        assert_eq!(serde_json::to_value(terminal).unwrap()["status"],status);
    }
}
#[test]
fn machine_watch_snapshot_and_id_budgets_fail_without_consuming_more_capacity() {
    let mut state = WatchState::new(vec![id("one")],1).unwrap();
    state.reserve_snapshot().unwrap();
    assert!(matches!(state.reserve_snapshot(),Err(ClientCredentialsTaskWatchError::SnapshotLimit)));
    assert_eq!(state.snapshots,1);
    let mut ids = WatchIds::new("watch".to_owned()).unwrap();
    let first = ids.next_pair().unwrap();
    let second = ids.next_pair().unwrap();
    assert_eq!(first,(RequestId::String("watch:0".to_owned()),RequestId::String("watch:1".to_owned())));
    assert_eq!(second,(RequestId::String("watch:2".to_owned()),RequestId::String("watch:3".to_owned())));
    ids.next=u64::MAX-1;
    assert!(matches!(ids.next_pair(),Err(ClientCredentialsTaskWatchError::IdentityExhausted)));
    assert_eq!(ids.next,u64::MAX-1);
}
#[test]
fn machine_watch_policy_and_prefix_have_finite_admission_bounds() {
    let second=Duration::from_secs(1);
    assert!(ClientCredentialsTaskWatchPolicy::new(second,1,2).is_ok());
    for (time,snapshots,records) in [(Duration::ZERO,1,2),(Duration::from_secs(3601),1,2),
        (second,0,2),(second,4097,2),(second,1,1),(second,1,4097)]
    { assert!(ClientCredentialsTaskWatchPolicy::new(time,snapshots,records).is_err()); }
    for prefix in ["".to_owned(),"x".repeat(129),"bad\nprefix".to_owned(),"other:0".to_owned(),"é".to_owned()] {
        assert!(WatchIds::new(prefix).is_err());
    }
    assert!(WatchIds::new("safe-_.42".to_owned()).is_ok());
}
#[test]
fn machine_watch_filter_and_get_use_the_existing_composed_metadata() {
    let client=consumer();
    let state=WatchState::new(vec![id("one"),id("two")],8).unwrap();
    assert_eq!(serde_json::to_value(state.filter().unwrap()).unwrap(),json!({"taskIds":["one","two"]}));
    let ids=(RequestId::Number(10),RequestId::Number(11));
    let (prepared,_,discovery)=prepare_pinned(&client,&ids,ManagedTaskRequest::Get(id("one"))).unwrap();
    for (wire,id) in [(&discovery,10),(&prepared.wire,11)] {
        let body:serde_json::Value=serde_json::from_slice(wire.body()).unwrap();
        assert_eq!(body["id"],id);
        assert_eq!(body["params"]["_meta"],client.metadata);
        assert_eq!(body["params"]["_meta"]["com.example/tenant"],"retained");
        assert!(body["params"]["_meta"][FINAL_CLIENT_CAPABILITIES_META_KEY]["extensions"].is_object());
        assert!(!wire.headers().iter().any(|(name,_)|name.eq_ignore_ascii_case("authorization")));
    }
    assert_eq!(serde_json::from_slice::<serde_json::Value>(prepared.wire.body()).unwrap()["params"]["taskId"],"one");
}
#[test]
fn machine_watch_pinned_preflight_refuses_replayable_creation_and_id_aliases() {
    let client=consumer();
    let ids=(RequestId::Number(1),RequestId::Number(2));
    assert!(prepare_pinned(&client,&ids,ManagedTaskRequest::CallTool{name:"effect".to_owned(),arguments:None}).is_err());
    let alias=serde_json::from_str::<RequestId>("1e0").unwrap();
    assert!(prepare_pinned(&client,&(RequestId::Number(1),alias),ManagedTaskRequest::Get(id("one"))).is_err());
    assert!(prepare_pinned(&client,&(RequestId::Number(1),RequestId::String("1".to_owned())),ManagedTaskRequest::Get(id("one"))).is_ok());
}
#[test]
fn machine_watch_binding_copy_preserves_expiry_generation_and_revocation() {
    let client=consumer();
    let original=binding(&client);
    let copied=copy_binding(&original);
    assert_eq!(copied.generation(),7);
    assert_eq!(copied.expires_at(),original.expires_at());
    original.bearer.revoke();
    assert!(check_token(&copied.bearer,copied.expires_at).is_err());
}
#[test]
fn machine_watch_public_precancellation_and_owner_close_never_acquire_a_grant() {
    runtime().block_on(async {
        let cx=Cx::current().unwrap();
        for closed in [false,true] {
            let client=consumer();
            let cancel=McpRequestCancellation::new();
            if closed { client.client.close(); } else { cancel.cancel(); }
            let result=client.watch_tasks_with_cancellation(&cx,&cancel,vec![id("one")],"test".to_owned(),
                ClientCredentialsTaskWatchPolicy::default()).await;
            if closed {
                assert!(matches!(result,Err(ClientCredentialsTaskWatchError::Task(ClientCredentialsTasksError::Authentication(ClientCredentialsError::Closed)))));
            } else {
                assert!(matches!(result,Err(ClientCredentialsTaskWatchError::Task(ClientCredentialsTasksError::Authentication(ClientCredentialsError::Discovery(OAuthDiscoveryError::Cancelled))))));
            }
            assert!(client.client.inner.state.try_lock_owned().unwrap().current.is_none());
        }
    });
}
#[test]
fn machine_watch_public_invalid_selection_is_rejected_before_network_work() {
    runtime().block_on(async {
        let cx=Cx::current().unwrap();
        let client=consumer();
        assert!(matches!(client.watch_tasks(&cx,vec![],"test".to_owned(),ClientCredentialsTaskWatchPolicy::default()).await,
            Err(ClientCredentialsTaskWatchError::InvalidSelection)));
        assert!(matches!(client.watch_tasks(&cx,vec![id("one")],"bad:prefix".to_owned(),ClientCredentialsTaskWatchPolicy::default()).await,
            Err(ClientCredentialsTaskWatchError::InvalidIdPrefix)));
        assert!(client.client.inner.state.try_lock_owned().unwrap().current.is_none());
    });
}
#[test]
fn machine_watch_expired_pinned_requests_fail_before_an_attempted_reacquisition() {
    runtime().block_on(async {
        let cx=Cx::current().unwrap();
        let client=consumer();
        let mut binding=binding(&client);
        binding.expires_at=Instant::now();
        let result=request_pinned(&client,&cx,&McpRequestCancellation::new(),&binding,
            cx.now().saturating_add_nanos(1_000_000_000),(RequestId::Number(1),RequestId::Number(2)),
            ManagedTaskRequest::Get(id("one"))).await;
        assert!(matches!(result,Err(ClientCredentialsTaskWatchError::Task(ClientCredentialsTasksError::Authentication(ClientCredentialsError::Expired)))));
        assert!(client.client.inner.state.try_lock_owned().unwrap().current.is_none());
    });
}
