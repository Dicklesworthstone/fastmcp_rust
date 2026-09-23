use super::*;
use std::cell::Cell;
use std::sync::Arc;
use std::sync::atomic::AtomicUsize;
use std::task::{Context, Poll, Waker};
use std::time::Duration;
use fastmcp_core::CanonicalHttpUrl;
use fastmcp_core::partition::{DurableOwnerKey, PartitionDescriptor};
use fastmcp_protocol::{ClientCapabilities, FinalRequestMeta};
use serde_json::json;
use crate::http_auth::discovery::client_credentials::{
    ClientCredentialsClient, ClientInner, ClientSecret, MachineAuthentication, TokenState,
};
use super::super::{ClientCredentialsTasksLimits, decode_result};

fn client() -> ClientCredentialsTasksClient {
    let client = ClientCredentialsClient { inner: Arc::new(ClientInner {
        resource: CanonicalHttpUrl::parse("https://machine.example/mcp").unwrap(),
        token_endpoint: CanonicalHttpUrl::parse("https://issuer.example/token").unwrap(),
        client_id: "creation-fixture".to_owned(), scopes: vec![],
        authentication: MachineAuthentication::Basic(Arc::new(ClientSecret("fixture-secret".to_owned()))),
        issuer_roots: vec![], timeout: Duration::from_secs(5), maximum_lifetime: Duration::from_secs(600),
        leeway: Duration::from_secs(30), closed: McpRequestCancellation::new(),
        pending: AtomicUsize::new(0), state: Arc::new(asupersync::sync::Mutex::new(TokenState::default())),
    }) };
    ClientCredentialsTasksClient::new(client, FinalRequestMeta::new(ClientCapabilities::default()),
        ClientCredentialsTasksLimits::default()).unwrap()
}
fn binding(resource: &str) -> TaskResumeBinding {
    let facts = PartitionDescriptor::from_verified_facts("fixture", 1, "issuer", resource,
        "tenant", "machine-owner", "client", 1, 1, &[b"fixture".as_slice()]).unwrap();
    TaskResumeBinding::from_verified_owner(CanonicalHttpUrl::parse(resource).unwrap(), "creation",
        &DurableOwnerKey::derive(&facts, 1).unwrap(), [1; 32], [2; 32], [3; 32]).unwrap()
}
fn current() -> TaskResumeBinding { binding("https://machine.example/mcp") }
fn policy() -> TaskResumeCapturePolicy { TaskResumeCapturePolicy::new(Duration::from_secs(60)).unwrap() }
fn created(status: &str) -> Value {
    let mut task = json!({"resultType":"task", "taskId":"PRIVATE / exact ID", "status":status,
        "createdAt":"2000-01-01T00:00:00Z", "lastUpdatedAt":"2000-01-01T00:00:01Z",
        "ttlMs":null, "statusMessage":"PRIVATE-STATUS"});
    match status {
        "input_required" => task["inputRequests"] = json!({"PRIVATE-INPUT":{"method":"roots/list"}}),
        "completed" => task["result"] = json!({"content":[{"type":"text","text":"PRIVATE-RESULT"}]}),
        "failed" => task["error"] = json!({"code":-32603,"message":"PRIVATE-ERROR"}),
        _ => {},
    }
    task
}
fn pending(result: Value) -> PendingClientCredentialsTaskResult {
    let client = client();
    let round = client.prepare_round(RequestId::Number(1), RequestId::Number(2),
        ManagedTaskRequest::CallTool { name:"work".to_owned(), arguments:None }).unwrap();
    let bytes = json!({"jsonrpc":"2.0","id":2,"result":result}).to_string();
    let ManagedTaskEvent::ToolResult(result) = decode_result(&round.prepared.decoder,
        bytes.as_bytes(), &RequestId::Number(2), 65536).unwrap() else { panic!("tool result required") };
    PendingClientCredentialsTaskResult { result, insert: None, persistence: TaskResumePersistenceState::NotAttempted }
}
fn insert() -> TaskResumeInsert {
    let mut result = pending(created("working"));
    result.capture(&Cx::for_testing(), &current(), policy()).unwrap();
    result.insert.unwrap()
}
fn ready<F: Future>(future: F) -> F::Output {
    let mut future = Box::pin(future);
    match future.as_mut().poll(&mut Context::from_waker(Waker::noop())) {
        Poll::Ready(result) => result,
        Poll::Pending => panic!("fixture must complete in one poll"),
    }
}

#[test]
fn preparation_validates_whole_round_and_binding_without_effects() {
    let mut client = client();
    let saves = Cell::new(0);
    let save = |_| { saves.set(saves.get() + 1); std::future::ready(Ok::<_, ()>(())) };
    let opened = client.prepare_tool_submission_persisted(RequestId::Number(1), RequestId::Number(2),
        "work".to_owned(), Some(json!({"idempotency":"unchanged"})), current(), policy(), save).unwrap();
    assert_eq!(opened.submission_state(), ClientCredentialsTaskCreationState::Prepared);
    let round = opened.round.as_ref().unwrap();
    let body: Value = serde_json::from_slice(round.prepared.wire.body()).unwrap();
    assert_eq!(body["params"]["arguments"], json!({"idempotency":"unchanged"}));
    assert!(body["params"].get("task").is_none());
    assert!(body["params"].get("requestState").is_none());
    assert!(!round.prepared.wire.headers().iter().any(|(key, _)| key.eq_ignore_ascii_case("authorization")));
    assert!(client.prepare_tool_submission_persisted(RequestId::Number(1), RequestId::Number(2),
        "work".to_owned(), None, binding("https://other.example/mcp"), policy(), save).is_err());
    assert!(client.prepare_tool_submission_persisted(RequestId::Number(2), RequestId::Number(2),
        "work".to_owned(), None, current(), policy(), save).is_err());
    client.limits.request_bytes = 1;
    assert!(client.prepare_tool_submission_persisted(RequestId::Number(1), RequestId::Number(2),
        "work".to_owned(), None, current(), policy(), save).is_err());
    assert_eq!(saves.get(), 0);
    assert!(client.client.inner.state.try_lock_owned().unwrap().current.is_none());
}

#[test]
fn unpolled_send_is_inert_and_cancelled_entry_cannot_be_retried() {
    let runtime = asupersync::runtime::RuntimeBuilder::current_thread()
        .with_reactor(asupersync::runtime::reactor::create_reactor().unwrap()).build().unwrap();
    runtime.block_on(async {
        let cx = Cx::current().unwrap();
        let client = client();
        let saves = Cell::new(0);
        let mut owner = client.prepare_tool_submission_persisted(RequestId::Number(1), RequestId::Number(2),
            "work".to_owned(), None, current(), policy(), |_| {
                saves.set(saves.get() + 1); std::future::ready(Ok::<_, ()>(()))
            }).unwrap();
        assert!(matches!(owner.next_event(&cx).await, Err(ClientCredentialsTaskCreationError::NotSent)));
        drop(owner.send(&cx));
        assert_eq!(owner.submission_state(), ClientCredentialsTaskCreationState::Prepared);
        assert!(!owner.is_closed());
        let cancellation = McpRequestCancellation::new(); cancellation.cancel();
        assert!(owner.send_with_cancellation(&cx, &cancellation).await.is_err());
        assert_eq!(owner.submission_state(), ClientCredentialsTaskCreationState::Unconfirmed);
        assert!(owner.is_closed());
        assert!(matches!(owner.send(&cx).await, Err(ClientCredentialsTaskCreationError::AlreadyAttempted)));
        assert!(owner.pending().is_none());
        assert_eq!(saves.get(), 0);
        assert!(client.client.inner.state.try_lock_owned().unwrap().current.is_none());
    });
}

#[test]
fn ordinary_core_input_and_all_terminal_results_bypass_checkpoint_capture() {
    let cx = Cx::for_testing();
    for result in [json!({"resultType":"complete","content":[],"isError":true}),
        json!({"resultType":"input_required","requestState":"PRIVATE-STATE"}),
        created("completed"), created("failed"), created("cancelled")]
    {
        let mut pending = pending(result);
        assert!(!pending.capture(&cx, &current(), policy()).unwrap());
        assert!(pending.record().is_none());
        assert_eq!(pending.persistence(), TaskResumePersistenceState::NotAttempted);
    }
}

#[test]
fn active_capture_uses_shared_insert_and_excludes_inputs_and_status_payloads() {
    for status in ["working", "input_required"] {
        let mut pending = pending(created(status));
        assert!(pending.capture(&Cx::for_testing(), &current(), policy()).unwrap());
        let record = pending.record().unwrap();
        assert_eq!(record.task_id().as_str(), "PRIVATE / exact ID");
        let bytes = record.encode().unwrap();
        for forbidden in [b"PRIVATE-INPUT".as_slice(), b"PRIVATE-STATUS", b"roots/list"] {
            assert!(!bytes.windows(forbidden.len()).any(|part| part == forbidden));
        }
        assert!(matches!(pending.result(), FinalCoreResult::ToolsCallTask { result, .. }
            if result.task.base().status_message.as_deref() == Some("PRIVATE-STATUS")));
        let (result, command, state) = pending.into_parts();
        assert!(matches!(*result, FinalCoreResult::ToolsCallTask { .. }));
        assert_eq!(command.unwrap().record().encode().unwrap(), bytes);
        assert_eq!(state, TaskResumePersistenceState::NotAttempted);
    }
}

#[test]
fn capture_failure_keeps_the_actual_task_and_does_not_claim_a_save() {
    let mut value = created("working");
    value["ttlMs"] = json!(1); value["lastUpdatedAt"] = value["createdAt"].clone();
    let mut pending = pending(value);
    assert!(pending.capture(&Cx::for_testing(), &current(), policy()).is_err());
    assert!(pending.record().is_none());
    assert!(matches!(pending.result(), FinalCoreResult::ToolsCallTask { .. }));
    assert_eq!(pending.persistence(), TaskResumePersistenceState::NotAttempted);
}

#[test]
fn save_entry_and_ack_survive_host_failure_and_same_poll_cancellation() {
    for success in [false, true] {
        let cancellation = McpRequestCancellation::new();
        let calls = Cell::new(0);
        let mut state = TaskResumePersistenceState::NotAttempted;
        let mut save = |command: TaskResumeInsert| {
            calls.set(calls.get() + 1);
            assert_eq!(command.record().task_id().as_str(), "PRIVATE / exact ID");
            cancellation.cancel();
            std::future::ready(if success { Ok(()) } else { Err("PRIVATE-PATH") })
        };
        assert_eq!(ready(persist_insert(&mut state, &mut save, insert())).is_ok(), success);
        assert_eq!(calls.get(), 1);
        assert_eq!(state, if success { TaskResumePersistenceState::Acknowledged } else { TaskResumePersistenceState::Unconfirmed });
    }
}

#[test]
fn abandoned_save_drops_provider_but_retains_result_and_write_uncertainty() {
    struct Pending<'a>(&'a Cell<bool>);
    impl Future for Pending<'_> {
        type Output = Result<(), ()>;
        fn poll(self: std::pin::Pin<&mut Self>, _: &mut Context<'_>) -> Poll<Self::Output> { Poll::Pending }
    }
    impl Drop for Pending<'_> { fn drop(&mut self) { self.0.set(true); } }
    let dropped = Cell::new(false);
    let mut pending = pending(created("working"));
    pending.capture(&Cx::for_testing(), &current(), policy()).unwrap();
    let command = pending.insert.clone().unwrap();
    let mut save = |_| Pending(&dropped);
    let mut future = Box::pin(persist_insert(&mut pending.persistence, &mut save, command));
    assert!(future.as_mut().poll(&mut Context::from_waker(Waker::noop())).is_pending());
    drop(future);
    assert!(dropped.get());
    assert_eq!(pending.persistence(), TaskResumePersistenceState::Unconfirmed);
    assert!(matches!(pending.result(), FinalCoreResult::ToolsCallTask { .. }));
    assert!(pending.record().is_some());
}

#[test]
fn diagnostics_do_not_expose_host_or_result_payloads() {
    let warning = ClientCredentialsTaskPersistenceWarning::Persistence("PRIVATE-PATH");
    assert!(!format!("{warning:?} {warning}").contains("PRIVATE"));
    let result = PersistedClientCredentialsTaskResult { pending: pending(created("working")), warning: Some(warning) };
    assert!(!format!("{result:?}").contains("PRIVATE"));
    assert!(!format!("{:?}", result.pending).contains("PRIVATE"));
}
