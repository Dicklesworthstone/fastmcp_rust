//! Public creation-to-persistence ownership over the existing OAuth/TLS peer.
//! The save callback is an explicit test acknowledgement/failure fixture, NOT
//! evidence of disk durability or encryption. The real insert-only file adapter
//! is covered separately by task_resume_store. Run this complete target with
//! tasks,native-tls-roots; a filtered/feature-disabled run is not qualification.
use super::*;
use std::cell::{Cell, RefCell};
use fastmcp_core::partition::{DurableOwnerKey, PartitionDescriptor};
use fastmcp_client::http_auth::managed::OAuthSessionError;
use fastmcp_client::http_auth::managed::tasks::{ManagedTaskRequestIds, ManagedTasksClient, ManagedTasksLimits};
use fastmcp_client::http_auth::managed::tasks::interaction::ManagedTaskInteractionPolicy;
use fastmcp_client::http_auth::managed::tasks::interaction::submission::{ManagedTaskSubmissionError, TaskSubmissionState};
use fastmcp_client::http_auth::managed::tasks::watch::checkpoint::resume::{TaskResumeBinding, TaskResumeError};
use fastmcp_client::http_auth::managed::tasks::watch::checkpoint::resume::client::creation::{
    TaskResumeCapturePolicy, TaskResumeInsert,
};
use fastmcp_client::http_auth::managed::tasks::watch::checkpoint::resume::client::creation::submission::{
    PersistedTaskSubmissionError, PersistedTaskSubmissionEvent, ResumePersistenceWarning,
};
use fastmcp_client::http_auth::managed::tasks::watch::checkpoint::resume::client::lifecycle::TaskResumePersistenceState;
use fastmcp_protocol::{ClientCapabilities, FinalCoreResult, FinalRequestMeta};

const CASE_ENV: &str = "FASTMCP_TEST_TASK_CREATION_PERSISTENCE";
const DISCOVER: &str = r#"{"resultType":"complete","supportedVersions":["2026-07-28"],"capabilities":{"tools":{"listChanged":true},"extensions":{"io.modelcontextprotocol/tasks":{}}},"ttlMs":0,"cacheScope":"private"}"#;
const NO_TASKS: &str = r#"{"resultType":"complete","supportedVersions":["2026-07-28"],"capabilities":{"tools":{}},"ttlMs":0,"cacheScope":"private"}"#;
const TASK: &str = r#"{"resultType":"task","taskId":"  actual / peer Task  ","status":"working","createdAt":"2020-01-01T00:00:00Z","lastUpdatedAt":"2020-01-01T00:00:00Z","ttlMs":null,"statusMessage":"PRIVATE-STATUS"}"#;
const COMPLETE: &str = r#"{"resultType":"complete","content":[],"isError":true,"x-exact":1.20e+4}"#;

#[derive(Clone, Copy)]
enum Case {
    Persist, Fail, Cancel, DropSave, Timeout, CloseReady, CancelReady,
    Ordinary, Continue, Unknown, Trailing, Expired, WrongResource, Refused, PreCancelled,
}

fn isolated(name: &str, case: Case) {
    let exact = format!("driver::task_creation_persistence::{name}");
    if let Ok(selected) = std::env::var(CASE_ENV) {
        assert_eq!(selected, exact);
        run(case);
        return;
    }
    let roots = RootFile::create();
    struct Child(std::process::Child);
    impl Drop for Child {
        fn drop(&mut self) { let _ = self.0.kill(); let _ = self.0.wait(); }
    }
    let mut child = Child(Command::new(std::env::current_exe().unwrap())
        .args(["--exact", &exact, "--nocapture", "--test-threads=1"])
        .env(CASE_ENV, &exact).env("SSL_CERT_FILE", &roots.0).env_remove("SSL_CERT_DIR")
        .stdin(Stdio::null()).stdout(Stdio::inherit()).stderr(Stdio::inherit()).spawn().unwrap());
    let end = Instant::now() + Duration::from_secs(30);
    loop {
        if let Some(status) = child.0.try_wait().unwrap() {
            assert!(status.success(), "Task creation persistence HTTPS case failed");
            return;
        }
        assert!(Instant::now() < end, "Task creation persistence child exceeded its bound");
        std::thread::sleep(Duration::from_millis(10));
    }
}

fn binding(resource: &str) -> TaskResumeBinding {
    let descriptor = PartitionDescriptor::from_verified_facts(
        "fixture-provider", 1, "https://issuer.example", resource, "fixture-tenant",
        "owner", "interaction-client", 1, 1, &[b"resource-bound".as_slice()],
    ).unwrap();
    let owner = DurableOwnerKey::derive(&descriptor, 1).unwrap();
    TaskResumeBinding::from_verified_owner(url(resource), "creation", &owner, [2; 32], [3; 32], [4; 32]).unwrap()
}
fn ids(first: i64) -> ManagedTaskRequestIds {
    ManagedTaskRequestIds::new(RequestId::Number(first), RequestId::Number(first + 1)).unwrap()
}
fn arguments() -> Value { json!({"payload":"PRIVATE-ARGUMENT","applicationKey":"host-chosen"}) }

async fn round(peer: &Peer, first: i64, case: Case, effects: &Cell<usize>) {
    let discovered = peer.response(first, if matches!(case, Case::Refused) { NO_TASKS } else { DISCOVER }).await;
    assert_eq!(discovered["method"], "server/discover");
    assert!(discovered["params"].get("inputResponses").is_none());
    assert!(discovered["params"].get("requestState").is_none());
    if matches!(case, Case::Refused) { return; }
    let (mut tls, bytes) = peer.request(false).await;
    let request: Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(request["id"], first + 1);
    assert_eq!(request["method"], "tools/call");
    assert_eq!(request["params"]["name"], "echo");
    assert_eq!(request["params"]["arguments"], arguments());
    assert_eq!(request["params"]["_meta"], discovered["params"]["_meta"]);
    assert_eq!(request["params"]["_meta"]["io.modelcontextprotocol/clientCapabilities"]["extensions"],
        json!({"io.modelcontextprotocol/tasks":{}}));
    assert!(request["params"].get("task").is_none());
    if first == 3 {
        assert_eq!(request["params"]["requestState"], "  sealed+/%\0  ");
        assert_eq!(request["params"]["inputResponses"], json!({"first":{"roots":[]}}));
    } else {
        assert!(request["params"].get("requestState").is_none());
        assert!(request["params"].get("inputResponses").is_none());
    }
    // The parent peer independently checks exact bearer/routing headers and
    // rejects legacy session/replay headers on every real TLS POST.
    effects.set(effects.get() + 1);
    match case {
        Case::Unknown => {
            tls.write_all(b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 128\r\nConnection: close\r\n\r\n{\"jsonrpc\":").await.unwrap();
            tls.flush().await.unwrap();
        }
        Case::Trailing => {
            sse_head(&mut tls).await;
            event(&mut tls, &terminal(first + 1, TASK), false).await;
            event(&mut tls, CHANGED, true).await;
        }
        Case::Persist => {
            sse_head(&mut tls).await;
            event(&mut tls, CHANGED, false).await;
            event(&mut tls, &terminal(first + 1, TASK), true).await;
        }
        Case::Continue if first == 1 => json_reply(&mut tls, &terminal(first + 1, FIRST)).await,
        Case::Ordinary => json_reply(&mut tls, &terminal(first + 1, COMPLETE)).await,
        Case::Expired => {
            let mut expired: Value = serde_json::from_str(TASK).unwrap();
            expired["ttlMs"] = json!(1);
            json_reply(&mut tls, &terminal(first + 1, &expired.to_string())).await;
        }
        _ => json_reply(&mut tls, &terminal(first + 1, TASK)).await,
    }
}

// Explicitly controlled asynchronous save: success is withheld until the test
// permits it. It owns no disk or cryptographic provider and claims neither.
struct Save<'a> {
    case: Case,
    permit: &'a Cell<bool>,
    entered: &'a Cell<bool>,
    dropped: &'a Cell<bool>,
    acknowledged: &'a Cell<bool>,
    session: ManagedOAuthSession,
    cancellation: McpRequestCancellation,
}
impl Future for Save<'_> {
    type Output = Result<(), &'static str>;
    fn poll(self: std::pin::Pin<&mut Self>, _: &mut std::task::Context<'_>) -> Poll<Self::Output> {
        let this = self.get_mut();
        this.entered.set(true);
        match this.case {
            Case::Fail => Poll::Ready(Err("PRIVATE-STORAGE-ERROR")),
            Case::CloseReady => {
                this.acknowledged.set(true);
                this.session.close();
                Poll::Ready(Ok(()))
            }
            Case::CancelReady => {
                this.acknowledged.set(true);
                this.cancellation.cancel();
                Poll::Ready(Ok(()))
            }
            _ if !this.permit.get() => Poll::Pending,
            _ => {
                this.acknowledged.set(true);
                Poll::Ready(Ok(()))
            }
        }
    }
}
impl Drop for Save<'_> { fn drop(&mut self) { self.dropped.set(true); } }

fn run(case: Case) {
    RuntimeBuilder::current_thread().with_reactor(create_reactor().unwrap()).build().unwrap().block_on(Box::pin(async {
        let cx = Cx::current().unwrap();
        let scenario = Box::pin(async {
            let peer = Peer::new().await;
            let ((), login) = pair(Box::pin(peer.login()), Box::pin(ManagedOAuthSession::authorize(
                &cx, peer.client(), OAuthSessionPolicy::default(), browser,
            ))).await;
            let session = login.unwrap();
            let cancellation = McpRequestCancellation::new();
            let timeout = if matches!(case, Case::Timeout) { Duration::from_secs(3) } else { Duration::from_secs(15) };
            let capabilities: ClientCapabilities = serde_json::from_value(json!({"roots":{}})).unwrap();
            let client = ManagedTasksClient::new(session.clone(), FinalRequestMeta::new(capabilities),
                ManagedTasksLimits::new(65536, 65536, 16, timeout).unwrap()).unwrap();
            let resource = if matches!(case, Case::WrongResource) { format!("{}/other", peer.resource()) } else { peer.resource() };
            let current = binding(&resource);
            let saves = Cell::new(0_usize);
            let effects = Cell::new(0_usize);
            let entered = Cell::new(false);
            let permit = Cell::new(false);
            let dropped = Cell::new(false);
            let acknowledged = Cell::new(false);
            let encoded = RefCell::new(None::<Vec<u8>>);
            let prepared = client.prepare_tool_submission_persisted(ids(1), "echo".to_owned(), Some(arguments()),
                ManagedTaskInteractionPolicy::new(4, 8, 16).unwrap(), current,
                TaskResumeCapturePolicy::new(Duration::from_secs(60)).unwrap(), |insert: TaskResumeInsert| {
                    saves.set(saves.get() + 1);
                    assert_eq!(insert.record().task_id().as_str(), "  actual / peer Task  ");
                    let bytes = insert.record().encode().unwrap();
                    assert!(!bytes.windows(7).any(|window| window == b"PRIVATE"));
                    assert!(!bytes.windows(11).any(|window| window == b"host-chosen"));
                    *encoded.borrow_mut() = Some(bytes);
                    Save { case, permit: &permit, entered: &entered, dropped: &dropped,
                        acknowledged: &acknowledged, session: session.clone(), cancellation: cancellation.clone() }
                });
            if matches!(case, Case::WrongResource) {
                assert!(matches!(prepared, Err(PersistedTaskSubmissionError::Resume(TaskResumeError::Unavailable))));
                assert_eq!(saves.get(), 0);
                assert_eq!(peer.posts.load(Ordering::SeqCst), 0);
                peer.quiet();
                session.close();
                return;
            }
            let mut owner = prepared.unwrap();
            assert_eq!(owner.submission_state(), TaskSubmissionState::Prepared);
            assert_eq!(saves.get(), 0);
            drop(Box::pin(owner.send(&cx)));
            assert_eq!(owner.submission_state(), TaskSubmissionState::Prepared, "unpolled send is inert");
            if matches!(case, Case::PreCancelled) {
                cancellation.cancel();
                assert!(matches!(owner.send_with_cancellation(&cx, &cancellation).await,
                    Err(PersistedTaskSubmissionError::Submission(ManagedTaskSubmissionError::NotDispatched(_)))));
                assert_eq!(peer.posts.load(Ordering::SeqCst), 0);
                assert_eq!(saves.get(), 0);
                assert_eq!(owner.submission_state(), TaskSubmissionState::NotDispatched);
                peer.quiet();
                session.close();
                return;
            }
            let ((), sent) = pair(Box::pin(round(&peer, 1, case, &effects)),
                Box::pin(owner.send_with_cancellation(&cx, &cancellation))).await;
            if matches!(case, Case::Refused) {
                assert!(matches!(sent, Err(PersistedTaskSubmissionError::Submission(ManagedTaskSubmissionError::NotDispatched(_)))));
                assert_eq!(effects.get(), 0);
                assert_eq!(peer.posts.load(Ordering::SeqCst), 1);
                assert_eq!(saves.get(), 0);
                peer.quiet();
                session.close();
                return;
            }
            if matches!(case, Case::Unknown | Case::Trailing) {
                let failure = match sent { Err(error) => error, Ok(()) => owner.next_event(&cx).await.err().unwrap() };
                assert!(matches!(failure, PersistedTaskSubmissionError::Submission(ManagedTaskSubmissionError::TaskCreationDeliveryUnknown(_))));
                assert_eq!(owner.submission_state(), TaskSubmissionState::DeliveryUnknown);
                assert!(owner.pending().is_none());
                assert_eq!(saves.get(), 0, "an unadmitted provisional Task cannot reach storage");
                assert_eq!(peer.posts.load(Ordering::SeqCst), 2);
                assert!(owner.send(&cx).await.is_err());
                owner.close();
                assert_eq!(owner.submission_state(), TaskSubmissionState::DeliveryUnknown);
                peer.quiet();
                session.close();
                return;
            }
            sent.unwrap();
            drop(Box::pin(owner.next_event(&cx)));
            assert_eq!(saves.get(), 0, "unpolled read does not save");
            if matches!(case, Case::Persist) {
                assert!(matches!(owner.next_event(&cx).await.unwrap(), Some(PersistedTaskSubmissionEvent::Notification(_))));
                assert_eq!(saves.get(), 0);
            }
            if matches!(case, Case::Continue) {
                assert!(matches!(owner.next_event(&cx).await.unwrap(), Some(PersistedTaskSubmissionEvent::InputRequired(_))));
                assert_eq!(saves.get(), 0);
                assert!(matches!(owner.next_event(&cx).await, Err(PersistedTaskSubmissionError::Submission(ManagedTaskSubmissionError::InputPending))));
                assert!(owner.resume(&cx, ids(3), Some(answers("wrong"))).await.is_err());
                assert!(owner.pending_input().is_some());
                assert_eq!(owner.request_id(), &RequestId::Number(2));
                assert_eq!(peer.posts.load(Ordering::SeqCst), 2);
                let ((), continued) = pair(Box::pin(round(&peer, 3, case, &effects)),
                    Box::pin(owner.resume(&cx, ids(3), Some(answers("first"))))).await;
                continued.unwrap();
                assert_eq!(saves.get(), 0);
            }
            let mut reading = Box::pin(owner.next_event(&cx));
            if matches!(case, Case::Persist | Case::Continue | Case::Cancel | Case::DropSave | Case::Timeout) {
                poll_fn(|task| {
                    assert!(reading.as_mut().poll(task).is_pending(), "normal result must await persistence");
                    if entered.get() { Poll::Ready(()) } else { Poll::Pending }
                }).await;
                assert_eq!(saves.get(), 1);
                assert!(!acknowledged.get());
                if matches!(case, Case::DropSave) {
                    drop(reading);
                    assert!(dropped.get());
                    assert_eq!(owner.submission_state(), TaskSubmissionState::Resolved);
                    assert!(!owner.is_finished(), "result still belongs to pending custody");
                    let pending = owner.pending().unwrap();
                    assert_eq!(pending.persistence(), TaskResumePersistenceState::Unconfirmed);
                    assert_eq!(pending.record().unwrap().encode().unwrap(), *encoded.borrow().as_ref().unwrap());
                    assert!(matches!(pending.result(), FinalCoreResult::ToolsCallTask { .. }));
                    assert!(matches!(owner.next_event(&cx).await, Err(PersistedTaskSubmissionError::Closed)));
                    assert!(owner.send(&cx).await.is_err());
                    owner.close();
                    let (result, record, state) = owner.take_pending().unwrap().into_parts();
                    assert!(matches!(*result, FinalCoreResult::ToolsCallTask { .. }));
                    assert_eq!(record.unwrap().task_id().as_str(), "  actual / peer Task  ");
                    assert_eq!(state, TaskResumePersistenceState::Unconfirmed);
                    assert_eq!(saves.get(), 1);
                    assert_eq!(peer.posts.load(Ordering::SeqCst), 2);
                    assert!(!cancellation.is_cancel_requested());
                    peer.quiet();
                    session.close();
                    return;
                }
                if matches!(case, Case::Cancel) { cancellation.cancel(); }
                if matches!(case, Case::Persist | Case::Continue) { permit.set(true); }
            }
            let Some(PersistedTaskSubmissionEvent::Result(receipt)) = reading.await.unwrap() else {
                panic!("actual result and persistence receipt required");
            };
            match case {
                Case::Ordinary => {
                    assert!(matches!(receipt.result(), FinalCoreResult::ToolsCall { .. }));
                    assert!(receipt.record().is_none() && receipt.warning().is_none());
                    assert_eq!(receipt.persistence(), TaskResumePersistenceState::NotAttempted);
                    assert_eq!(saves.get(), 0);
                }
                Case::Expired => {
                    assert!(matches!(receipt.result(), FinalCoreResult::ToolsCallTask { .. }));
                    assert!(matches!(receipt.warning(), Some(ResumePersistenceWarning::Record(_))));
                    assert!(receipt.record().is_none());
                    assert_eq!(receipt.persistence(), TaskResumePersistenceState::NotAttempted);
                    assert_eq!(saves.get(), 0);
                }
                _ => {
                    assert!(matches!(receipt.result(), FinalCoreResult::ToolsCallTask { result, .. }
                        if result.task.base().task_id.as_str() == "  actual / peer Task  "));
                    assert_eq!(receipt.record().unwrap().encode().unwrap(), *encoded.borrow().as_ref().unwrap());
                    assert_eq!(saves.get(), 1);
                    match case {
                        Case::Persist | Case::Continue => {
                            assert!(receipt.warning().is_none());
                            assert_eq!(receipt.persistence(), TaskResumePersistenceState::Acknowledged);
                        }
                        Case::Fail => {
                            assert!(matches!(receipt.warning(), Some(ResumePersistenceWarning::Persistence("PRIVATE-STORAGE-ERROR"))));
                            assert_eq!(receipt.persistence(), TaskResumePersistenceState::Unconfirmed);
                            assert!(!format!("{:?}", receipt.warning()).contains("PRIVATE"));
                        }
                        Case::Cancel | Case::CancelReady => {
                            assert!(matches!(receipt.warning(), Some(ResumePersistenceWarning::Session(OAuthSessionError::Cancelled))));
                            assert_eq!(receipt.persistence(), if matches!(case, Case::CancelReady) {
                                TaskResumePersistenceState::Acknowledged
                            } else { TaskResumePersistenceState::Unconfirmed });
                        }
                        Case::CloseReady => {
                            assert!(matches!(receipt.warning(), Some(ResumePersistenceWarning::Session(OAuthSessionError::Closed))));
                            assert_eq!(receipt.persistence(), TaskResumePersistenceState::Acknowledged);
                        }
                        Case::Timeout => {
                            assert!(matches!(receipt.warning(), Some(ResumePersistenceWarning::Session(OAuthSessionError::TimedOut))));
                            assert_eq!(receipt.persistence(), TaskResumePersistenceState::Unconfirmed);
                        }
                        _ => unreachable!(),
                    }
                    assert!(dropped.get(), "save future ownership was released");
                }
            }
            assert!(owner.is_finished());
            assert!(owner.pending().is_none());
            assert!(owner.next_event(&cx).await.unwrap().is_none());
            assert!(owner.send(&cx).await.is_err());
            assert!(owner.resume(&cx, ids(91), Some(answers("first"))).await.is_err());
            let calls = if matches!(case, Case::Continue) { 2 } else { 1 };
            assert_eq!(effects.get(), calls);
            assert_eq!(peer.posts.load(Ordering::SeqCst), 2 * calls);
            assert_eq!(peer.tokens.load(Ordering::SeqCst), 1);
            assert_eq!(cancellation.is_cancel_requested(), matches!(case, Case::Cancel | Case::CancelReady));
            assert!(cx.checkpoint().is_ok(), "ambient caller and siblings remain live");
            peer.quiet();
            session.close();
        });
        Box::pin(asupersync::time::timeout_at(cx.now().saturating_add_nanos(20_000_000_000), scenario)).await
            .expect("creation persistence fixture must settle within its bound");
    }));
}

#[test]
fn creation_result_waits_for_initial_persistence_but_notifications_do_not() { isolated("creation_result_waits_for_initial_persistence_but_notifications_do_not", Case::Persist); }
#[test]
fn failed_save_returns_the_actual_task_with_exportable_controls() { isolated("failed_save_returns_the_actual_task_with_exportable_controls", Case::Fail); }
#[test]
fn cancelling_initial_save_returns_known_task_not_unknown_creation() { isolated("cancelling_initial_save_returns_known_task_not_unknown_creation", Case::Cancel); }
#[test]
fn abandoned_save_retains_task_and_unconfirmed_record_without_replay() { isolated("abandoned_save_retains_task_and_unconfirmed_record_without_replay", Case::DropSave); }
#[test]
fn original_submission_deadline_also_bounds_initial_persistence() { isolated("original_submission_deadline_also_bounds_initial_persistence", Case::Timeout); }
#[test]
fn acknowledged_save_survives_ready_callback_session_closure() { isolated("acknowledged_save_survives_ready_callback_session_closure", Case::CloseReady); }
#[test]
fn acknowledged_save_survives_ready_callback_cancellation() { isolated("acknowledged_save_survives_ready_callback_cancellation", Case::CancelReady); }
#[test]
fn ordinary_tool_completion_never_enters_the_resume_store() { isolated("ordinary_tool_completion_never_enters_the_resume_store", Case::Ordinary); }
#[test]
fn explicit_tool_continuation_persists_only_the_final_created_task() { isolated("explicit_tool_continuation_persists_only_the_final_created_task", Case::Continue); }
#[test]
fn unknown_creation_never_saves_a_guessed_task() { isolated("unknown_creation_never_saves_a_guessed_task", Case::Unknown); }
#[test]
fn trailing_wire_data_prevents_provisional_task_persistence() { isolated("trailing_wire_data_prevents_provisional_task_persistence", Case::Trailing); }
#[test]
fn expired_creation_controls_warn_without_erasing_the_real_task() { isolated("expired_creation_controls_warn_without_erasing_the_real_task", Case::Expired); }
#[test]
fn wrong_persistence_endpoint_is_rejected_before_any_mcp_post() { isolated("wrong_persistence_endpoint_is_rejected_before_any_mcp_post", Case::WrongResource); }
#[test]
fn unnegotiated_tasks_do_not_dispatch_or_persist_creation() { isolated("unnegotiated_tasks_do_not_dispatch_or_persist_creation", Case::Refused); }
#[test]
fn pre_cancelled_creation_performs_neither_tool_post_nor_save() { isolated("pre_cancelled_creation_performs_neither_tool_post_nor_save", Case::PreCancelled); }
