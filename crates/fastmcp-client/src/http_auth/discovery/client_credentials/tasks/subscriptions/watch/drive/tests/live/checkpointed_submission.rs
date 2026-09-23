//! Multi-round core input -> actual Task -> initial checkpoint -> fresh restart.
//! The native TLS peer and token come from the existing parent fixture. Only
//! conditional storage and its faults are fixtures; no protocol/driver is mocked.

use super::*;
use std::pin::Pin;
use std::sync::atomic::AtomicBool;
use std::task::{Context, Waker};
use asupersync::types::Time;
use asupersync::time::Sleep;
use fastmcp_core::partition::{DurableOwnerKey, PartitionDescriptor};
use fastmcp_protocol::{FinalCoreResult, FinalInputResponses, RequestId};
use crate::http_auth::discovery::client_credentials::tasks::ClientCredentialsTasksError;
use crate::http_auth::discovery::client_credentials::tasks::creation::{
    TaskResumeBinding, TaskResumeCapturePolicy, TaskResumeInsert, TaskResumePersistenceState,
    TaskResumeRecord, ClientCredentialsTaskPersistenceWarning,
};
use crate::http_auth::discovery::client_credentials::tasks::submission::{
    ClientCredentialsTaskSubmissionPolicy, ClientCredentialsTaskSubmissionError,
    ClientCredentialsTaskSubmissionCause, TaskSubmissionState,
};
use crate::http_auth::discovery::client_credentials::tasks::submission::persisted::{
    CheckpointedTaskSubmissionError, CheckpointedTaskSubmissionEvent,
};
use crate::http_auth::discovery::client_credentials::tasks::subscriptions::watch::resume::{
    ClientCredentialsTaskResumeReconciliation, ClientCredentialsTaskResumeError, TaskResumeError,
};

#[derive(Clone, Copy, Debug)]
enum Case {
    Complete, Partial, StateOnly, Ordinary, Terminal, Stream, Correctable, NoPartialState,
    MissingExtension, RefusedContinuation, LostContinuation, ForeignResult,
    GatedSave, FailedSave, LostSave, DropSave, CancelSave, AcknowledgedCancel,
    ExpirySave, DeadlineSave, DropRead, CancelRead, RecordLimit, Restart, RestartConflict,
}
impl Case {
    fn partial(self) -> bool { matches!(self, Self::Partial | Self::RecordLimit) }
    fn bypass(self) -> bool { matches!(self, Self::Ordinary | Self::Terminal) }
    fn refuses(self) -> bool { matches!(self, Self::MissingExtension | Self::RefusedContinuation) }
    fn uncertain_reply(self) -> bool { matches!(self, Self::LostContinuation | Self::ForeignResult) }
    fn read_wait(self) -> bool { matches!(self, Self::DropRead | Self::CancelRead) }
    fn gated(self) -> bool { matches!(self, Self::GatedSave | Self::DropSave | Self::CancelSave) }
    fn timed(self) -> bool { matches!(self, Self::ExpirySave | Self::DeadlineSave) }
    fn restart(self) -> bool { matches!(self, Self::Restart | Self::RestartConflict) }
    fn requests(self) -> usize {
        if self.refuses() { 3 }
        else if matches!(self, Self::Partial) || self.restart() { 6 }
        else { 4 }
    }
    fn saves(self) -> usize {
        usize::from(!self.bypass() && !self.refuses() && !self.uncertain_reply()
            && !self.read_wait() && !matches!(self, Self::RecordLimit))
    }
    fn commits(self) -> bool {
        self.saves() == 1 && !matches!(self, Self::FailedSave | Self::DropSave | Self::CancelSave)
            && !self.timed()
    }
}
fn id(n: usize) -> RequestId { RequestId::String(format!("checkpoint:{n}")) }
fn answers(value: serde_json::Value) -> FinalInputResponses { serde_json::from_value(value).unwrap() }
fn binding(client: &ClientCredentialsTasksClient) -> TaskResumeBinding {
    let resource = client.client.resource();
    let facts = PartitionDescriptor::from_verified_facts("fixture", 1, "https://issuer.example",
        resource.as_str(), "tenant", "machine", "client", 1, 1, &[b"bound-resource".as_slice()]).unwrap();
    TaskResumeBinding::from_verified_owner(resource.clone(), "checkpointed-machine",
        &DurableOwnerKey::derive(&facts, 1).unwrap(), [1; 32], [2; 32], [3; 32]).unwrap()
}
fn arguments() -> serde_json::Value { json!({"PRIVATE-ARGUMENT":7,"idempotency":"host-key"}) }
fn input(case: Case) -> serde_json::Value {
    if matches!(case, Case::StateOnly) { return json!({"resultType":"input_required","requestState":""}); }
    let mut value = json!({"resultType":"input_required","inputRequests":{"one":{"method":"roots/list"}}});
    if case.partial() || matches!(case, Case::NoPartialState) {
        value["inputRequests"]["two"] = json!({"method":"roots/list"});
    }
    if case.partial() { value["requestState"] = json!("  PRIVATE-STATE\u{0} +/%  "); }
    value
}
fn task_result(case: Case) -> serde_json::Value {
    if matches!(case, Case::Ordinary) {
        return json!({"resultType":"complete","content":[{"type":"text","text":"PRIVATE-RESULT"}],"isError":true});
    }
    let mut task = json!({"resultType":"task","taskId":"created / task-é","status":"working",
        "createdAt":"2020-01-01T00:00:00Z","lastUpdatedAt":"2020-01-01T00:00:01Z",
        "ttlMs":null,"statusMessage":"PRIVATE-STATUS"});
    if matches!(case, Case::Partial) {
        task["status"] = json!("input_required");
        task["inputRequests"] = json!({"PRIVATE-TASK-INPUT":{"method":"roots/list"}});
    }
    if matches!(case, Case::Terminal) { task["status"] = json!("cancelled"); }
    task
}

struct Store {
    case: Case,
    calls: AtomicUsize,
    dropped: AtomicUsize,
    tool_posts: AtomicUsize,
    released: AtomicBool,
    waiting: Mutex<Option<Waker>>,
    record: Mutex<Option<Vec<u8>>>,
    cancel: McpRequestCancellation,
    release_at: Option<Time>,
}
struct Saving { store: Arc<Store>, insert: Option<TaskResumeInsert>, timer: Option<Pin<Box<Sleep>>> }
impl Future for Saving {
    type Output = Result<(), &'static str>;
    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.get_mut();
        if this.store.case.gated() && !this.store.released.load(Ordering::SeqCst) {
            *this.store.waiting.lock().unwrap() = Some(cx.waker().clone());
            return Poll::Pending;
        }
        if let Some(timer) = this.timer.as_mut() {
            if timer.as_mut().poll(cx).is_pending() { return Poll::Pending; }
        }
        if matches!(this.store.case, Case::FailedSave) { return Poll::Ready(Err("PRIVATE-STORE")); }
        let insert = this.insert.take().expect("one persistence attempt");
        let mut stored = this.store.record.lock().unwrap();
        assert!(stored.is_none(), "insertion cannot replace an existing checkpoint");
        *stored = Some(insert.record().encode().unwrap());
        drop(stored);
        if matches!(this.store.case, Case::LostSave) { return Poll::Ready(Err("PRIVATE-STORE")); }
        if matches!(this.store.case, Case::AcknowledgedCancel) { this.store.cancel.cancel(); }
        Poll::Ready(Ok(()))
    }
}
impl Drop for Saving { fn drop(&mut self) { self.store.dropped.fetch_add(1, Ordering::SeqCst); } }
impl Store {
    fn start(self: &Arc<Self>, insert: TaskResumeInsert) -> Saving {
        assert_eq!(self.calls.fetch_add(1, Ordering::SeqCst), 0);
        assert_eq!(self.tool_posts.load(Ordering::SeqCst), if self.case.partial() { 3 } else { 2 });
        assert_eq!(insert.record().task_id().as_str(), "created / task-é");
        let bytes = insert.record().encode().unwrap();
        assert!(!bytes.windows(7).any(|part| part == b"PRIVATE"));
        Saving { store: Arc::clone(self), insert: Some(insert), timer: self.release_at.map(|at| Box::pin(Sleep::new(at))) }
    }
    fn release(&self) {
        self.released.store(true, Ordering::SeqCst);
        if let Some(waker) = self.waiting.lock().unwrap().take() { waker.wake(); }
    }
}
async fn tool(peer: &Peer, store: &Store, metadata: &serde_json::Value,
    round: usize, responses: Option<serde_json::Value>, state: Option<&str>,
) -> (TlsStream<TcpStream>, serde_json::Value) {
    let (socket, request) = peer.rpc("tools/call").await;
    assert_eq!(request["id"], format!("checkpoint:{}", 2 * round + 1));
    assert_eq!(request["params"]["arguments"], arguments());
    assert_eq!(request["params"]["name"], "compute");
    assert_eq!(&request["params"]["_meta"], metadata);
    assert!(request["params"].get("task").is_none());
    assert_eq!(request["params"].get("inputResponses"), responses.as_ref());
    assert_eq!(request["params"].get("requestState"), state.map(|value| json!(value)).as_ref());
    assert_eq!(store.calls.load(Ordering::SeqCst), 0, "core challenges must not be checkpointed");
    assert_eq!(store.tool_posts.fetch_add(1, Ordering::SeqCst), round);
    (socket, request)
}
async fn result_reply(socket: &mut TlsStream<TcpStream>, request: &serde_json::Value, result: serde_json::Value) {
    reply(socket, json!({"jsonrpc":"2.0","id":request["id"],"result":result})).await;
    closed(socket).await;
}
async fn server(peer: &Peer, store: &Store, metadata: &serde_json::Value, case: Case) {
    peer.discover().await;
    let (mut socket, request) = tool(peer, store, metadata, 0, None, None).await;
    if matches!(case, Case::Stream) {
        socket.write_all(b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nTransfer-Encoding: chunked\r\n\r\n").await.unwrap();
        event(&mut socket, json!({"jsonrpc":"2.0","method":"notifications/progress",
            "params":{"progressToken":"checkpoint-progress","progress":1}})).await;
        event(&mut socket, json!({"jsonrpc":"2.0","id":request["id"],"result":input(case)})).await;
        closed(&mut socket).await;
    } else { result_reply(&mut socket, &request, input(case)).await; }
    if case.refuses() {
        let (mut socket, request) = peer.rpc("server/discover").await;
        if matches!(case, Case::RefusedContinuation) {
            socket.write_all(b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\nConnection: close\r\n\r\n").await.unwrap();
            socket.shutdown().await.unwrap(); closed(&mut socket).await;
        } else {
            result_reply(&mut socket, &request, json!({"resultType":"complete","supportedVersions":["2026-07-28"],
                "ttlMs":0,"cacheScope":"private","capabilities":{"extensions":{CLIENT_CREDENTIALS_EXTENSION:{}}}})).await;
        }
        return;
    }
    peer.discover().await;
    let responses = if matches!(case, Case::StateOnly) { None }
        else if matches!(case, Case::NoPartialState) { Some(json!({"one":{"roots":[]},"two":{"roots":[]}})) }
        else { Some(json!({"one":{"roots":[]}})) };
    let state = if matches!(case, Case::StateOnly) { Some("") }
        else if case.partial() { Some("  PRIVATE-STATE\u{0} +/%  ") } else { None };
    let (mut socket, request) = tool(peer, store, metadata, 1, responses, state).await;
    if case.read_wait() || matches!(case, Case::LostContinuation) {
        socket.write_all(b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 512\r\nConnection: close\r\n\r\n{\"jsonrpc\":").await.unwrap();
        socket.flush().await.unwrap();
        if matches!(case, Case::LostContinuation) { socket.shutdown().await.unwrap(); }
        closed(&mut socket).await; return;
    }
    if matches!(case, Case::ForeignResult) {
        reply(&mut socket, json!({"jsonrpc":"2.0","id":"foreign:3","result":task_result(case)})).await;
        closed(&mut socket).await; return;
    }
    if case.partial() {
        result_reply(&mut socket, &request, json!({"resultType":"input_required","inputRequests":{"two":{"method":"roots/list"}}})).await;
        if matches!(case, Case::RecordLimit) { return; }
        peer.discover().await;
        let (mut socket, request) = tool(peer, store, metadata, 2, Some(json!({"two":{"roots":[]}})), None).await;
        result_reply(&mut socket, &request, task_result(case)).await;
    } else { result_reply(&mut socket, &request, task_result(case)).await; }
    if case.restart() {
        peer.discover().await;
        let (mut socket, request) = peer.rpc("tasks/get").await;
        assert_eq!(request["params"]["taskId"], "created / task-é");
        let mut value = task_result(case);
        value["resultType"] = json!("complete"); value["status"] = json!("cancelled");
        value["lastUpdatedAt"] = json!("2020-01-01T00:00:02Z");
        if matches!(case, Case::RestartConflict) { value["createdAt"] = json!("2019-01-01T00:00:00Z"); }
        result_reply(&mut socket, &request, value).await;
    }
}

fn run(case: Case) {
    runtime().block_on(async {
        let cx = Cx::current().unwrap();
        let scenario = async {
            let peer = Peer::new().await;
            let mut machine = peer.client();
            if matches!(case, Case::Stream) { machine.metadata["progressToken"] = json!("checkpoint-progress"); }
            let anchor = cx.now();
            let cancel = McpRequestCancellation::new();
            let release_at = if case.timed() { Some(anchor.saturating_add_nanos(4_000_000_000)) } else { None };
            if matches!(case, Case::ExpirySave) {
                let inner = Arc::get_mut(&mut machine.client.inner).unwrap();
                inner.timeout = Duration::from_secs(10);
                let expires_at = Instant::now() + Duration::from_secs(3);
                let mut state = inner.state.try_lock_owned().unwrap();
                let token = state.current.as_mut().unwrap();
                token.expires_at = expires_at; token.renew_after = expires_at;
                token.bearer = BoundBearerCredential::bind_with_expiry(inner.resource.clone(), "watched-access", expires_at)
                    .unwrap().for_owner(&inner.closed).unwrap();
            }
            if matches!(case, Case::DeadlineSave) {
                Arc::get_mut(&mut machine.client.inner).unwrap().timeout = Duration::from_secs(3);
            }
            let store = Arc::new(Store { case, calls: AtomicUsize::new(0), dropped: AtomicUsize::new(0),
                tool_posts: AtomicUsize::new(0), released: AtomicBool::new(false), waiting: Mutex::new(None),
                record: Mutex::new(None), cancel: cancel.clone(), release_at });
            let current = binding(&machine);
            let policy = ClientCredentialsTaskSubmissionPolicy::new(2,
                if matches!(case, Case::StateOnly) { 0 } else { 2 },
                if matches!(case, Case::RecordLimit) { 2 } else { 8 }).unwrap();
            let saving = Arc::clone(&store);
            let mut owner = machine.prepare_tool_submission(id(0), id(1), "compute".to_owned(), Some(arguments()), policy).unwrap()
                .with_initial_checkpoint(current.clone(), TaskResumeCapturePolicy::new(Duration::from_secs(60)).unwrap(),
                    move |insert| saving.start(insert)).unwrap();
            let serving = server(&peer, &store, &machine.metadata, case);
            let application = async {
                owner.send_with_cancellation(&cx, &cancel).await.unwrap();
                if matches!(case, Case::Stream) {
                    assert!(matches!(owner.next_event(&cx).await.unwrap(), Some(CheckpointedTaskSubmissionEvent::Notification(_))));
                    assert_eq!(owner.submission_state(), TaskSubmissionState::AwaitingResponse);
                    assert_eq!(store.calls.load(Ordering::SeqCst), 0);
                }
                let first = owner.next_event(&cx).await.unwrap().unwrap();
                assert!(matches!(first, CheckpointedTaskSubmissionEvent::InputRequired(_)));
                assert_eq!(owner.submission_state(), TaskSubmissionState::AwaitingInput);
                assert!(matches!(owner.next_event(&cx).await,
                    Err(CheckpointedTaskSubmissionError::Submission(ClientCredentialsTaskSubmissionError::InputPending))));
                assert_eq!(store.calls.load(Ordering::SeqCst), 0);
                assert!(store.record.lock().unwrap().is_none());
                // A fresh credential lookup would contact the unserved issuer.
                machine.client.inner.state.try_lock_owned().unwrap().current.as_mut().unwrap().renew_after = Instant::now();
                if matches!(case, Case::Correctable) {
                    for value in [json!({}), json!({"wrong":{"roots":[]}}), json!({"one":{"action":"decline"}})] {
                        assert!(matches!(owner.resume(&cx, id(2), id(3), Some(answers(value))).await,
                            Err(CheckpointedTaskSubmissionError::Submission(ClientCredentialsTaskSubmissionError::NotDispatched(_)))));
                        assert_eq!(owner.submission_state(), TaskSubmissionState::AwaitingInput);
                        assert!(owner.pending_input().is_some());
                        assert_eq!(peer.seen.lock().unwrap().len(), 2);
                        assert_eq!(store.calls.load(Ordering::SeqCst), 0);
                    }
                    assert!(owner.resume(&cx, id(2), id(1), Some(answers(json!({"one":{"roots":[]}})))).await.is_err());
                }
                if matches!(case, Case::NoPartialState) {
                    assert!(owner.resume_partial(&cx, id(2), id(3), answers(json!({"one":{"roots":[]}}))).await.is_err());
                    assert_eq!(owner.submission_state(), TaskSubmissionState::AwaitingInput);
                    assert!(owner.pending_input().unwrap().request_state().is_none());
                    assert_eq!(peer.seen.lock().unwrap().len(), 2);
                }
                if matches!(case, Case::DeadlineSave) {
                    // Consumes the original deadline before the final round. A
                    // wrong timeout reset would let the t+4s storage receipt win.
                    Sleep::new(anchor.saturating_add_nanos(1_500_000_000)).await;
                }
                let resumed = if case.partial() {
                    owner.resume_partial(&cx, id(2), id(3), answers(json!({"one":{"roots":[]}}))).await
                } else {
                    let responses = if matches!(case, Case::StateOnly) { None }
                        else if matches!(case, Case::NoPartialState) { Some(answers(json!({"one":{"roots":[]},"two":{"roots":[]}}))) }
                        else { Some(answers(json!({"one":{"roots":[]}}))) };
                    owner.resume(&cx, id(2), id(3), responses).await
                };
                if case.refuses() {
                    let Err(CheckpointedTaskSubmissionError::Submission(error)) = resumed else { panic!("continuation admission must fail"); };
                    assert!(matches!(&error, ClientCredentialsTaskSubmissionError::NotDispatched(_)));
                    if matches!(case, Case::RefusedContinuation) {
                        assert!(matches!(error.cause(), Some(ClientCredentialsTaskSubmissionCause::Task(
                            ClientCredentialsTasksError::Protocol(ManagedTasksError::HttpStatus { status: 403 })))));
                    } else {
                        assert!(matches!(error.cause(), Some(ClientCredentialsTaskSubmissionCause::Task(
                            ClientCredentialsTasksError::Protocol(ManagedTasksError::Negotiation)))));
                    }
                    assert_eq!(owner.submission_state(), TaskSubmissionState::NotDispatched);
                    assert!(owner.pending_input().is_none() && owner.pending().is_none());
                    assert!(owner.send(&cx).await.is_err()); return;
                }
                resumed.unwrap();
                if case.partial() {
                    let next = owner.next_event(&cx).await;
                    if matches!(case, Case::RecordLimit) {
                        assert!(matches!(next, Err(CheckpointedTaskSubmissionError::Submission(
                            ClientCredentialsTaskSubmissionError::TaskCreationDeliveryUnknown(cause)))
                            if matches!(*cause, ClientCredentialsTaskSubmissionCause::RecordLimit)));
                        assert!(owner.pending().is_none());
                        assert!(owner.send(&cx).await.is_err()); return;
                    }
                    assert!(matches!(next.unwrap(), Some(CheckpointedTaskSubmissionEvent::InputRequired(_))));
                    let pending = owner.pending_input().unwrap().input_requests().unwrap();
                    assert_eq!(pending.members().iter().map(|member| member.name.as_str()).collect::<Vec<_>>(), ["two"]);
                    assert_eq!(store.calls.load(Ordering::SeqCst), 0);
                    owner.resume(&cx, id(4), id(5), Some(answers(json!({"two":{"roots":[]}})))).await.unwrap();
                }
                if case.read_wait() {
                    let mut next = Box::pin(owner.next_event(&cx));
                    poll_fn(|task| { assert!(next.as_mut().poll(task).is_pending()); Poll::Ready(()) }).await;
                    if matches!(case, Case::CancelRead) {
                        cancel.cancel();
                        assert!(matches!(next.await, Err(CheckpointedTaskSubmissionError::Submission(
                            ClientCredentialsTaskSubmissionError::TaskCreationDeliveryUnknown(_)))));
                    } else { drop(next); }
                    assert_eq!(owner.submission_state(), TaskSubmissionState::DeliveryUnknown);
                    assert!(owner.pending().is_none());
                    assert!(owner.send(&cx).await.is_err()); return;
                }
                let result = if case.gated() {
                    let mut next = Box::pin(owner.next_event(&cx));
                    poll_fn(|task| {
                        assert!(next.as_mut().poll(task).is_pending());
                        if store.calls.load(Ordering::SeqCst) == 1 { Poll::Ready(()) }
                        else { task.waker().wake_by_ref(); Poll::Pending }
                    }).await;
                    assert!(store.record.lock().unwrap().is_none());
                    if matches!(case, Case::DropSave) {
                        drop(next);
                        assert_eq!(owner.submission_state(), TaskSubmissionState::Resolved);
                        let pending = owner.pending().unwrap();
                        assert_eq!(pending.persistence(), TaskResumePersistenceState::Unconfirmed);
                        assert_eq!(pending.record().unwrap().task_id().as_str(), "created / task-é");
                        assert!(!owner.is_finished());
                        assert!(owner.next_event(&cx).await.is_err());
                        assert!(owner.send(&cx).await.is_err());
                        assert!(owner.take_pending().is_some()); return;
                    }
                    if matches!(case, Case::CancelSave) { cancel.cancel(); } else { store.release(); }
                    next.await
                } else { owner.next_event(&cx).await };
                if case.uncertain_reply() {
                    let Err(CheckpointedTaskSubmissionError::Submission(error)) = result else { panic!("unknown final delivery must fail"); };
                    assert!(matches!(&error, ClientCredentialsTaskSubmissionError::TaskCreationDeliveryUnknown(_)));
                    if matches!(case, Case::ForeignResult) {
                        assert!(matches!(error.cause(), Some(ClientCredentialsTaskSubmissionCause::Task(
                            ClientCredentialsTasksError::Protocol(ManagedTasksError::ResponseIdMismatch)))));
                    } else {
                        assert!(matches!(error.cause(), Some(ClientCredentialsTaskSubmissionCause::Task(
                            ClientCredentialsTasksError::Protocol(ManagedTasksError::InvalidResponse)))));
                    }
                    assert_eq!(owner.submission_state(), TaskSubmissionState::DeliveryUnknown);
                    assert!(owner.pending().is_none());
                    assert!(owner.send(&cx).await.is_err()); return;
                }
                let Some(CheckpointedTaskSubmissionEvent::Result(result)) = result.unwrap() else { panic!("final result required"); };
                assert_eq!(owner.submission_state(), TaskSubmissionState::Resolved);
                assert!(owner.is_finished() && owner.pending_input().is_none() && owner.pending().is_none());
                assert!(owner.next_event(&cx).await.unwrap().is_none());
                assert!(owner.send(&cx).await.is_err());
                assert!(owner.resume(&cx, id(20), id(21), None).await.is_err());
                if case.bypass() {
                    if matches!(case, Case::Ordinary) {
                        assert!(matches!(result.result(), FinalCoreResult::ToolsCall { .. }));
                    } else {
                        assert!(matches!(result.result(), FinalCoreResult::ToolsCallTask { result, .. }
                            if matches!(&result.task, Task::Cancelled(_))));
                    }
                    assert!(result.record().is_none());
                    assert_eq!(result.persistence(), TaskResumePersistenceState::NotAttempted);
                    assert!(result.warning().is_none());
                } else {
                    assert!(matches!(result.result(), FinalCoreResult::ToolsCallTask { result, .. }
                        if result.task.base().task_id.as_str() == "created / task-é"));
                    if matches!(case, Case::Partial) {
                        assert!(matches!(result.result(), FinalCoreResult::ToolsCallTask { result, .. }
                            if matches!(&result.task, Task::InputRequired { .. })));
                    }
                    assert_eq!(result.record().unwrap().task_id().as_str(), "created / task-é");
                    let acknowledged = case.commits() && !matches!(case, Case::LostSave);
                    assert_eq!(result.persistence(), if acknowledged { TaskResumePersistenceState::Acknowledged }
                        else { TaskResumePersistenceState::Unconfirmed });
                    match case {
                        Case::FailedSave | Case::LostSave => assert!(matches!(result.warning(), Some(ClientCredentialsTaskPersistenceWarning::Persistence(_)))),
                        Case::CancelSave | Case::AcknowledgedCancel | Case::ExpirySave | Case::DeadlineSave =>
                            assert!(matches!(result.warning(), Some(ClientCredentialsTaskPersistenceWarning::Authentication(_)))),
                        _ => assert!(result.warning().is_none()),
                    }
                    assert!(!format!("{result:?}").contains("PRIVATE"));
                    if let Some(warning) = result.warning() { assert!(!format!("{warning:?} {warning}").contains("PRIVATE")); }
                }
                if case.restart() {
                    let bytes = store.record.lock().unwrap().as_ref().unwrap().clone();
                    let record = TaskResumeRecord::decode(&bytes).unwrap();
                    // A separate owner and freshly decoded record must use GET,
                    // not a creating call, saved input challenge, or old token.
                    let reader = peer.client();
                    let observed = reader.reconcile_task_resume(&cx, &current, &record, id(4), id(5)).await;
                    if matches!(case, Case::RestartConflict) {
                        assert!(matches!(observed, Err(ClientCredentialsTaskResumeError::Resume(TaskResumeError::ConflictingSnapshot))));
                    } else {
                        assert!(matches!(observed.unwrap(), ClientCredentialsTaskResumeReconciliation::Terminal(task)
                            if matches!(*task, Task::Cancelled(_))));
                    }
                    assert_eq!(store.record.lock().unwrap().as_ref().unwrap(), &bytes);
                    assert_eq!(record.encode().unwrap(), bytes);
                }
            };
            Box::pin(pair(serving, application)).await;
            assert_eq!(peer.seen.lock().unwrap().clone(), (0..case.requests()).map(|n| format!("checkpoint:{n}")).collect());
            assert_eq!(store.calls.load(Ordering::SeqCst), case.saves());
            assert_eq!(store.dropped.load(Ordering::SeqCst), case.saves());
            assert_eq!(store.record.lock().unwrap().is_some(), case.commits());
            assert_eq!(peer.updates.load(Ordering::SeqCst), 0);
            peer.quiet();
            assert!(cx.checkpoint().is_ok());
        };
        asupersync::time::timeout_at(cx.now().saturating_add_nanos(15_000_000_000), Box::pin(scenario)).await.unwrap();
    });
}
fn isolated(name: &str, case: Case) { isolated_run(&format!("checkpointed_submission::{name}"), || run(case)); }

#[test]
fn complete_input_creates_and_checkpoints_once() { isolated("complete_input_creates_and_checkpoints_once", Case::Complete); }
#[test]
fn partial_inputs_checkpoint_only_the_final_task_not_core_challenges() { isolated("partial_inputs_checkpoint_only_the_final_task_not_core_challenges", Case::Partial); }
#[test]
fn state_only_round_preserves_empty_state_and_absent_answers() { isolated("state_only_round_preserves_empty_state_and_absent_answers", Case::StateOnly); }
#[test]
fn ordinary_result_after_input_bypasses_storage() { isolated("ordinary_result_after_input_bypasses_storage", Case::Ordinary); }
#[test]
fn terminal_task_after_input_bypasses_storage() { isolated("terminal_task_after_input_bypasses_storage", Case::Terminal); }
#[test]
fn streaming_notifications_precede_input_without_triggering_storage() { isolated("streaming_notifications_precede_input_without_triggering_storage", Case::Stream); }
#[test]
fn invalid_answers_and_reused_ids_can_be_corrected_without_extra_posts() { isolated("invalid_answers_and_reused_ids_can_be_corrected_without_extra_posts", Case::Correctable); }
#[test]
fn partial_without_server_state_is_refused_then_complete_input_succeeds() { isolated("partial_without_server_state_is_refused_then_complete_input_succeeds", Case::NoPartialState); }
#[test]
fn lost_tasks_negotiation_prevents_continuation_and_checkpoint() { isolated("lost_tasks_negotiation_prevents_continuation_and_checkpoint", Case::MissingExtension); }
#[test]
fn refused_continuation_discovery_cannot_retry_or_save() { isolated("refused_continuation_discovery_cannot_retry_or_save", Case::RefusedContinuation); }
#[test]
fn lost_final_reply_preserves_unknown_creation_and_saves_nothing() { isolated("lost_final_reply_preserves_unknown_creation_and_saves_nothing", Case::LostContinuation); }
#[test]
fn foreign_final_reply_cannot_supply_a_checkpoint_identity() { isolated("foreign_final_reply_cannot_supply_a_checkpoint_identity", Case::ForeignResult); }
#[test]
fn active_result_waits_for_checkpoint_acknowledgement() { isolated("active_result_waits_for_checkpoint_acknowledgement", Case::GatedSave); }
#[test]
fn failed_insert_returns_actual_task_with_storage_warning() { isolated("failed_insert_returns_actual_task_with_storage_warning", Case::FailedSave); }
#[test]
fn committed_insert_with_lost_reply_is_never_repeated() { isolated("committed_insert_with_lost_reply_is_never_repeated", Case::LostSave); }
#[test]
fn abandoned_save_retains_task_and_uncertain_insert() { isolated("abandoned_save_retains_task_and_uncertain_insert", Case::DropSave); }
#[test]
fn cancellation_during_save_returns_the_already_known_task() { isolated("cancellation_during_save_returns_the_already_known_task", Case::CancelSave); }
#[test]
fn acknowledged_insert_racing_cancel_retains_its_receipt() { isolated("acknowledged_insert_racing_cancel_retains_its_receipt", Case::AcknowledgedCancel); }
#[test]
fn original_token_expiry_bounds_persistence_after_input() { isolated("original_token_expiry_bounds_persistence_after_input", Case::ExpirySave); }
#[test]
fn input_pause_cannot_reset_the_final_persistence_deadline() { isolated("input_pause_cannot_reset_the_final_persistence_deadline", Case::DeadlineSave); }
#[test]
fn abandoned_final_read_releases_transport_without_saving() { isolated("abandoned_final_read_releases_transport_without_saving", Case::DropRead); }
#[test]
fn cancelled_final_read_does_not_invent_a_known_task() { isolated("cancelled_final_read_does_not_invent_a_known_task", Case::CancelRead); }
#[test]
fn cumulative_record_limit_survives_checkpoint_attachment() { isolated("cumulative_record_limit_survives_checkpoint_attachment", Case::RecordLimit); }
#[test]
fn saved_final_task_reopens_with_fresh_get_and_no_creation_replay() { isolated("saved_final_task_reopens_with_fresh_get_and_no_creation_replay", Case::Restart); }
#[test]
fn reopened_task_identity_conflict_leaves_the_checkpoint_unchanged() { isolated("reopened_task_identity_conflict_leaves_the_checkpoint_unchanged", Case::RestartConflict); }
