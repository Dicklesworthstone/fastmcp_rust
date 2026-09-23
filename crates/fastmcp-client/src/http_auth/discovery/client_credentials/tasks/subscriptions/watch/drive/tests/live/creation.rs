//! Real native HTTPS creation and initial-checkpoint composition. The parent
//! provides a pre-acquired machine token and TLS peer. Storage below is an
//! insert-only in-memory fault fixture, not physical or cryptographic evidence.
use super::*;
use std::pin::Pin;
use std::sync::atomic::AtomicBool;
use std::task::Context;
use fastmcp_core::partition::{DurableOwnerKey, PartitionDescriptor};
use fastmcp_protocol::FinalCoreResult;
use crate::http_auth::discovery::client_credentials::tasks::creation::{
    ClientCredentialsTaskCreationError as Error, ClientCredentialsTaskCreationState as State,
    ClientCredentialsTaskPersistenceWarning as Warning, PersistedClientCredentialsTaskSubmissionEvent as Event,
    TaskResumeBinding, TaskResumeCapturePolicy, TaskResumeInsert, TaskResumePersistenceState as Saved,
    TaskResumeRecord,
};

#[derive(Clone, Copy)]
enum Case {
    Working, TaskInput, Ordinary, CoreInput, Completed, Failed, Cancelled,
    GatedSave, FailedSave, LostSave, AbandonSave, CancelSave, CloseSave,
    ExpireSave, DeadlineSave, AckCancel, ExpiredTask, LostReply, ForeignReply,
    MissingTasks, Progress, AbandonRead,
}
impl Case {
    fn gated(self) -> bool {
        matches!(self, Self::GatedSave | Self::AbandonSave | Self::CancelSave | Self::CloseSave
            | Self::ExpireSave | Self::DeadlineSave)
    }
    fn bypasses_save(self) -> bool {
        matches!(self, Self::Ordinary | Self::CoreInput | Self::Completed | Self::Failed | Self::Cancelled
            | Self::ExpiredTask | Self::LostReply | Self::ForeignReply | Self::MissingTasks | Self::AbandonRead)
    }
}
const TASK_ID: &str = "  PRIVATE / machine-é  ";
fn binding(client: &ClientCredentialsTasksClient) -> TaskResumeBinding {
    let resource = client.client.resource();
    let facts = PartitionDescriptor::from_verified_facts("fixture", 1, "issuer", resource.as_str(),
        "tenant", "machine-owner", "client", 1, 1, &[b"fixture".as_slice()]).unwrap();
    TaskResumeBinding::from_verified_owner(resource.clone(), "machine-creation",
        &DurableOwnerKey::derive(&facts, 1).unwrap(), [1; 32], [2; 32], [3; 32]).unwrap()
}
fn result(case: Case) -> serde_json::Value {
    if matches!(case, Case::Ordinary) { return json!({"resultType":"complete","content":[],"isError":true}); }
    if matches!(case, Case::CoreInput) { return json!({"resultType":"input_required","requestState":"PRIVATE-STATE"}); }
    let status = match case { Case::TaskInput => "input_required", Case::Completed => "completed",
        Case::Failed => "failed", Case::Cancelled => "cancelled", _ => "working" };
    let mut value = json!({"resultType":"task","taskId":TASK_ID,"status":status,
        "createdAt":"2000-01-01T00:00:00Z","lastUpdatedAt":"2000-01-01T00:00:00Z",
        "ttlMs":null,"statusMessage":"PRIVATE-STATUS"});
    match case {
        Case::TaskInput => value["inputRequests"] = json!({"PRIVATE-INPUT":{"method":"roots/list"}}),
        Case::Completed => value["result"] = json!({"content":[{"type":"text","text":"PRIVATE-RESULT"}]}),
        Case::Failed => value["error"] = json!({"code":-32603,"message":"PRIVATE-ERROR"}),
        Case::ExpiredTask => value["ttlMs"] = json!(1),
        _ => {},
    }
    value
}

#[derive(Default)]
struct Storage { record: Option<TaskResumeRecord> }
struct DropProbe(Arc<AtomicUsize>);
impl Drop for DropProbe { fn drop(&mut self) { self.0.fetch_add(1, Ordering::SeqCst); } }

fn run_creation(case: Case) {
    runtime().block_on(async {
        let cx = Cx::current().unwrap();
        let scenario = async {
            let peer = Peer::new().await;
            let mut client = peer.client();
            client.metadata["progressToken"] = json!("creation-progress");
            if matches!(case, Case::ExpireSave) {
                let expires_at = Instant::now() + Duration::from_secs(1);
                let bearer = BoundBearerCredential::bind_with_expiry(client.client.resource().clone(),
                    "watched-access", expires_at).unwrap().for_owner(&client.client.inner.closed).unwrap();
                let mut state = client.client.inner.state.try_lock_owned().unwrap();
                state.current = Some(ServiceToken { bearer, scopes:vec![], expires_at, renew_after:expires_at });
            }
            if matches!(case, Case::DeadlineSave) {
                client.limits = crate::http_auth::discovery::client_credentials::tasks::ClientCredentialsTasksLimits::new(
                    65536, 65536, 16, Duration::from_secs(1)).unwrap();
            }
            let current = binding(&client);
            let cancellation = McpRequestCancellation::new();
            let storage = Arc::new(Mutex::new(Storage::default()));
            let entered = Arc::new(AtomicUsize::new(0));
            let dropped = Arc::new(AtomicUsize::new(0));
            let release = Arc::new(AtomicBool::new(false));
            let created_count = AtomicUsize::new(0);
            let server = async {
                if matches!(case, Case::MissingTasks) {
                    let (mut socket, request) = peer.rpc("server/discover").await;
                    reply(&mut socket, json!({"jsonrpc":"2.0","id":request["id"],"result":{
                        "resultType":"complete","supportedVersions":["2026-07-28"],"ttlMs":0,"cacheScope":"private",
                        "capabilities":{"extensions":{CLIENT_CREDENTIALS_EXTENSION:{}}}
                    }})).await;
                    return;
                }
                peer.discover().await;
                let (mut socket, request) = peer.rpc("tools/call").await;
                created_count.fetch_add(1, Ordering::SeqCst);
                assert_eq!(request["id"], "creation:1");
                assert_eq!(request["params"]["name"], "compute");
                assert_eq!(request["params"]["arguments"], json!({"idempotency":"application-owned"}));
                assert!(request["params"].get("task").is_none());
                assert!(request["params"].get("requestState").is_none());
                assert_eq!(entered.load(Ordering::SeqCst), 0, "no speculative checkpoint before the Task result");
                let id = if matches!(case, Case::ForeignReply) { json!("not-the-creating-request") } else { request["id"].clone() };
                let envelope = json!({"jsonrpc":"2.0","id":id,"result":result(case)});
                if matches!(case, Case::LostReply | Case::AbandonRead) {
                    let body = envelope.to_string();
                    socket.write_all(format!("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n", body.len()).as_bytes()).await.unwrap();
                    socket.flush().await.unwrap();
                    if matches!(case, Case::LostReply) { socket.shutdown().await.unwrap(); }
                    else { closed(&mut socket).await; }
                } else if matches!(case, Case::Progress) {
                    socket.write_all(b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nTransfer-Encoding: chunked\r\n\r\n").await.unwrap();
                    event(&mut socket, json!({"jsonrpc":"2.0","method":"notifications/progress",
                        "params":{"progressToken":"creation-progress","progress":1}})).await;
                    event(&mut socket, envelope).await;
                    // Do not emit EOF: the correlated terminal must release this
                    // response instead of waiting for an unrelated later event.
                    closed(&mut socket).await;
                } else { reply(&mut socket, envelope).await; }
            };
            let application = async {
                let store = storage.clone();
                let saves = entered.clone();
                let releases = release.clone();
                let probes = dropped.clone();
                let cancel_on_ack = cancellation.clone();
                let persist = move |command: TaskResumeInsert| -> Pin<Box<dyn Future<Output = Result<(), &'static str>>>> {
                    assert_eq!(saves.fetch_add(1, Ordering::SeqCst), 0, "initial insert is one attempt");
                    let store = store.clone();
                    let releases = releases.clone();
                    let cancel_on_ack = cancel_on_ack.clone();
                    let probe = DropProbe(probes.clone());
                    Box::pin(async move {
                        let _probe = probe;
                        assert_eq!(command.record().task_id().as_str(), TASK_ID);
                        let bytes = command.record().encode().unwrap();
                        for forbidden in [b"PRIVATE-STATUS".as_slice(), b"PRIVATE-INPUT", b"PRIVATE-RESULT", b"application-owned"] {
                            assert!(!bytes.windows(forbidden.len()).any(|part| part == forbidden));
                        }
                        if case.gated() {
                            poll_fn(|_| if releases.load(Ordering::SeqCst) { Poll::Ready(()) } else { Poll::Pending }).await;
                        }
                        if matches!(case, Case::FailedSave) { return Err("PRIVATE-STORE-FAILURE"); }
                        {
                            let mut store = store.lock().unwrap();
                            assert!(store.record.is_none(), "insert must never overwrite an existing checkpoint");
                            store.record = Some(command.record().clone());
                        }
                        if matches!(case, Case::LostSave) { return Err("PRIVATE-LOST-RECEIPT"); }
                        if matches!(case, Case::AckCancel) { cancel_on_ack.cancel(); }
                        Ok(())
                    })
                };
                let mut owner = client.prepare_tool_submission_persisted(
                    RequestId::String("creation:0".to_owned()), RequestId::String("creation:1".to_owned()),
                    "compute".to_owned(), Some(json!({"idempotency":"application-owned"})), current.clone(),
                    TaskResumeCapturePolicy::new(Duration::from_secs(60)).unwrap(), persist,
                ).unwrap();
                assert_eq!(owner.submission_state(), State::Prepared);
                assert!(matches!(owner.next_event(&cx).await, Err(Error::NotSent)));
                drop(owner.send(&cx));
                assert!(!owner.is_closed());
                assert_eq!(owner.submission_state(), State::Prepared);
                let sent = owner.send_with_cancellation(&cx, &cancellation).await;
                if matches!(case, Case::MissingTasks) {
                    assert!(sent.is_err());
                    assert_eq!(owner.submission_state(), State::Unconfirmed);
                    assert!(owner.pending().is_none());
                    assert!(matches!(owner.send(&cx).await, Err(Error::AlreadyAttempted)));
                    return;
                }
                sent.unwrap();
                assert_eq!(owner.submission_state(), State::AwaitingResponse);
                // Any accidental ordinary acquisition from now on would renew.
                // Response parsing and persistence must keep the original token.
                client.client.inner.state.try_lock_owned().unwrap().current.as_mut().unwrap().renew_after = Instant::now();
                assert!(matches!(owner.send(&cx).await, Err(Error::AlreadyAttempted)));
                if matches!(case, Case::AbandonRead) {
                    let mut reading = Box::pin(owner.next_event(&cx));
                    poll_fn(|cx| { assert!(reading.as_mut().poll(cx).is_pending()); Poll::Ready(()) }).await;
                    drop(reading);
                    assert!(owner.is_closed());
                    assert!(owner.pending().is_none());
                    assert_eq!(owner.submission_state(), State::AwaitingResponse);
                    assert!(matches!(owner.next_event(&cx).await, Err(Error::Closed)));
                    return;
                }
                if matches!(case, Case::Progress) {
                    assert!(matches!(owner.next_event(&cx).await.unwrap(), Some(Event::Notification(_))));
                    assert_eq!(entered.load(Ordering::SeqCst), 0);
                    assert_eq!(owner.submission_state(), State::AwaitingResponse);
                }
                let event = if case.gated() {
                    let mut reading = Box::pin(owner.next_event(&cx));
                    let mut controlled = false;
                    let event = poll_fn(|task: &mut Context<'_>| {
                        let result = reading.as_mut().poll(task);
                        if !controlled && entered.load(Ordering::SeqCst) == 1 {
                            assert!(result.is_pending(), "active Task cannot publish before save completion");
                            assert!(storage.lock().unwrap().record.is_none());
                            controlled = true;
                            match case {
                                Case::GatedSave => release.store(true, Ordering::SeqCst),
                                Case::CancelSave => cancellation.cancel(),
                                Case::CloseSave => client.client.inner.closed.cancel(),
                                Case::AbandonSave => return Poll::Ready(None),
                                _ => {},
                            }
                            task.waker().wake_by_ref();
                        }
                        match result { Poll::Ready(result) => Poll::Ready(Some(result)), Poll::Pending => Poll::Pending }
                    }).await;
                    drop(reading);
                    assert!(controlled, "the forbidden dimension must occur after actual provider entry");
                    if matches!(case, Case::AbandonSave) {
                        assert!(event.is_none());
                        assert!(owner.is_closed());
                        assert_eq!(owner.submission_state(), State::Resolved);
                        let pending = owner.pending().expect("accepted result must survive abandoned storage");
                        assert!(matches!(pending.result(), FinalCoreResult::ToolsCallTask { result, .. }
                            if result.task.base().task_id.as_str() == TASK_ID));
                        assert_eq!(pending.persistence(), Saved::Unconfirmed);
                        assert!(pending.record().is_some());
                        assert!(matches!(owner.next_event(&cx).await, Err(Error::Closed)));
                        let pending = owner.take_pending().unwrap();
                        assert_eq!(pending.persistence(), Saved::Unconfirmed);
                        assert!(matches!(owner.send(&cx).await, Err(Error::AlreadyAttempted)));
                        return;
                    }
                    event.unwrap()
                } else { owner.next_event(&cx).await };
                if matches!(case, Case::LostReply | Case::ForeignReply) {
                    let error = event.err().expect("unadmitted reply must fail, not invent a Task");
                    if matches!(case, Case::ForeignReply) {
                        assert!(matches!(error, Error::Task(ClientCredentialsTasksError::Protocol(ManagedTasksError::ResponseIdMismatch))));
                    }
                    assert_eq!(owner.submission_state(), State::AwaitingResponse);
                    assert!(owner.pending().is_none());
                    assert!(matches!(owner.next_event(&cx).await, Err(Error::Closed)));
                    assert!(matches!(owner.send(&cx).await, Err(Error::AlreadyAttempted)));
                    return;
                }
                let Some(Event::Result(delivered)) = event.unwrap() else { panic!("one real protocol result required") };
                assert_eq!(owner.submission_state(), State::Resolved);
                assert!(owner.is_finished());
                assert!(owner.next_event(&cx).await.unwrap().is_none());
                assert!(matches!(owner.send(&cx).await, Err(Error::AlreadyAttempted)));
                assert!(owner.pending().is_none());
                assert!(!format!("{owner:?} {delivered:?}").contains("PRIVATE"));
                match case {
                    Case::Ordinary => assert!(matches!(delivered.result(), FinalCoreResult::ToolsCall { .. })),
                    Case::CoreInput => assert!(matches!(delivered.result(), FinalCoreResult::ToolsCallInputRequired { .. })),
                    _ => assert!(matches!(delivered.result(), FinalCoreResult::ToolsCallTask { result, .. }
                        if result.task.base().task_id.as_str() == TASK_ID)),
                }
                let expected = match case {
                    Case::Ordinary | Case::CoreInput | Case::Completed | Case::Failed | Case::Cancelled | Case::ExpiredTask => Saved::NotAttempted,
                    Case::FailedSave | Case::LostSave | Case::CancelSave | Case::CloseSave | Case::ExpireSave | Case::DeadlineSave => Saved::Unconfirmed,
                    _ => Saved::Acknowledged,
                };
                assert_eq!(delivered.persistence(), expected);
                match case {
                    Case::FailedSave | Case::LostSave => assert!(matches!(delivered.warning(), Some(Warning::Persistence(_)))),
                    Case::CancelSave | Case::CloseSave | Case::ExpireSave | Case::DeadlineSave | Case::AckCancel =>
                        assert!(matches!(delivered.warning(), Some(Warning::Authentication(_)))),
                    Case::ExpiredTask => assert!(matches!(delivered.warning(), Some(Warning::Record(_)))),
                    _ => assert!(delivered.warning().is_none()),
                }
                if let Some(warning) = delivered.warning() { assert!(!format!("{warning:?} {warning}").contains("PRIVATE")); }
                assert_eq!(delivered.record().is_none(), case.bypasses_save());
                if let Some(stored) = &storage.lock().unwrap().record {
                    assert_eq!(stored.encode().unwrap(), delivered.record().unwrap().encode().unwrap());
                }
                assert!(cx.checkpoint().is_ok(), "request-local cancellation must not cancel the ambient caller");
            };
            Box::pin(pair(server, application)).await;
            let attempts = usize::from(!case.bypasses_save());
            assert_eq!(entered.load(Ordering::SeqCst), attempts);
            assert_eq!(dropped.load(Ordering::SeqCst), attempts);
            assert_eq!(created_count.load(Ordering::SeqCst), usize::from(!matches!(case, Case::MissingTasks)));
            let saved = matches!(case, Case::Working | Case::TaskInput | Case::GatedSave | Case::LostSave | Case::AckCancel | Case::Progress);
            assert_eq!(storage.lock().unwrap().record.is_some(), saved);
            let expected: BTreeSet<String> = if matches!(case, Case::MissingTasks) { ["creation:0"].into_iter().map(str::to_owned).collect() }
                else { ["creation:0", "creation:1"].into_iter().map(str::to_owned).collect() };
            assert_eq!(*peer.seen.lock().unwrap(), expected, "no implicit polling, continuation, cancellation or creation replay");
            assert_eq!(peer.updates.load(Ordering::SeqCst), 0);
            peer.quiet();
        };
        asupersync::time::timeout_at(cx.now().saturating_add_nanos(15_000_000_000), Box::pin(scenario)).await.unwrap();
    });
}

macro_rules! creation_case {
    ($name:ident, $case:ident) => {
        #[test]
        fn $name() { isolated_run(concat!("creation::", stringify!($name)), || run_creation(Case::$case)); }
    };
}
creation_case!(tls_created_working_task_is_inserted_before_publication, Working);
creation_case!(tls_created_input_task_is_saved_without_resolving_its_inputs, TaskInput);
creation_case!(tls_ordinary_tool_result_never_invokes_storage, Ordinary);
creation_case!(tls_core_input_result_is_neither_persisted_nor_replayed, CoreInput);
creation_case!(tls_completed_task_result_needs_no_resume_insert, Completed);
creation_case!(tls_failed_task_result_needs_no_resume_insert, Failed);
creation_case!(tls_cancelled_task_result_needs_no_resume_insert, Cancelled);
creation_case!(tls_pending_initial_save_withholds_publication_until_ack, GatedSave);
creation_case!(tls_failed_initial_save_returns_real_task_with_warning, FailedSave);
creation_case!(tls_committed_initial_save_with_lost_reply_is_not_retried, LostSave);
creation_case!(tls_abandoned_initial_save_keeps_accepted_task_custody, AbandonSave);
creation_case!(tls_local_cancellation_of_initial_save_returns_known_task, CancelSave);
creation_case!(tls_machine_close_during_initial_save_returns_known_task, CloseSave);
creation_case!(tls_opening_credential_expiry_bounds_initial_save, ExpireSave);
creation_case!(tls_original_creating_deadline_bounds_initial_save, DeadlineSave);
creation_case!(tls_save_ack_racing_cancellation_survives_with_real_task, AckCancel);
creation_case!(tls_expired_created_task_survives_failed_control_capture, ExpiredTask);
creation_case!(tls_lost_creating_reply_never_invents_or_replays_task, LostReply);
creation_case!(tls_foreign_creating_reply_never_reaches_checkpoint_store, ForeignReply);
creation_case!(tls_unnegotiated_tasks_profile_prevents_creating_call, MissingTasks);
creation_case!(tls_creation_progress_stays_incremental_and_finishes_once, Progress);
creation_case!(tls_abandoned_creating_read_releases_socket_without_replay, AbandonRead);
