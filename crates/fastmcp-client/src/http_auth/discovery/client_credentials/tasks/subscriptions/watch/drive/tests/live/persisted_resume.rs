//! Public machine persisted-watch composition through the existing native TLS
//! fixture. The conditional in-memory store models save failures, not durability
//! or cryptographic provider qualification. Issuer grants are pre-acquired.
use super::*;
use std::sync::atomic::AtomicBool;
use fastmcp_core::partition::{DurableOwnerKey, PartitionDescriptor};
use crate::http_auth::discovery::client_credentials::tasks::subscriptions::watch::{
    cancellation::{ClientCredentialsTaskCancellationError, TaskCancellationState},
    recovery::ClientCredentialsTaskRecoveryPolicy,
    resume::{TaskResumeBinding, TaskResumeError, TaskResumeRecord},
    resume::lifecycle::{PersistedClientCredentialsTaskWatchError, TaskResumePersistenceState},
};
use crate::http_auth::managed::tasks::watch::checkpoint::resume::client::lifecycle::TaskResumeChange;

#[derive(Clone, Copy)]
enum Scenario {
    Complete, Recover, FailSave, LostSave, DropSave, LocalSave, RemoteSave,
    ReadyCancel, Retention, Conflict, LostCleanup, DropCleanup,
}
impl Scenario {
    fn stops_first(self) -> bool {
        matches!(self, Self::FailSave | Self::LostSave | Self::DropSave | Self::LocalSave
            | Self::RemoteSave | Self::ReadyCancel | Self::Retention)
    }
    fn pending_save(self) -> bool {
        matches!(self, Self::DropSave | Self::LocalSave | Self::RemoteSave | Self::Retention)
    }
}

#[derive(Debug)]
struct StoreError;
impl std::fmt::Display for StoreError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result { f.write_str("PRIVATE-STORE-PATH") }
}
impl std::error::Error for StoreError {}
type Error = PersistedClientCredentialsTaskWatchError<StoreError>;
struct Saved { record: Option<TaskResumeRecord>, calls: usize, commits: usize }
struct DropProbe(Arc<AtomicUsize>);
impl Drop for DropProbe { fn drop(&mut self) { self.0.fetch_add(1, Ordering::SeqCst); } }

fn binding(client: &ClientCredentialsTasksClient) -> TaskResumeBinding {
    let resource = client.client.resource().clone();
    let facts = PartitionDescriptor::from_verified_facts("fixture", 1, "https://issuer.example",
        resource.as_str(), "tenant", "machine-owner", "watch-fixture", 1, 1, &[b"machine".as_slice()]).unwrap();
    let owner = DurableOwnerKey::derive(&facts, 1).unwrap();
    TaskResumeBinding::from_verified_owner(resource, "persisted-machine", &owner, [1; 32], [2; 32], [3; 32]).unwrap()
}
fn snapshot(status: &str, second: u8) -> serde_json::Value {
    let mut value = json!({"taskId":"one", "status":status,
        "createdAt":"2020-01-01T00:00:00Z", "lastUpdatedAt":format!("2020-01-01T00:00:{second:02}Z"),
        "ttlMs":null, "pollIntervalMs":20});
    match status {
        "input_required" => value["inputRequests"] = json!({"PRIVATE-INPUT":{"method":"roots/list"}}),
        "completed" => value["result"] = json!({"content":[{"type":"text","text":"PRIVATE-RESULT"}]}),
        _ => {},
    }
    value
}
async fn get(peer: &Peer, status: &str, second: u8) {
    peer.discover().await;
    let (mut socket, request) = peer.rpc("tasks/get").await;
    assert_eq!(request["params"]["taskId"], "one");
    let mut result = snapshot(status, second);
    result["resultType"] = json!("complete");
    reply(&mut socket, json!({"jsonrpc":"2.0", "id":request["id"], "result":result})).await;
}
async fn terminal_notice(stream: &mut TlsStream<TcpStream>, subscription: &serde_json::Value) {
    let mut params = snapshot("completed", 4);
    params["_meta"] = json!({(FINAL_SUBSCRIPTION_ID_META_KEY):subscription});
    event(stream, json!({"jsonrpc":"2.0", "method":"notifications/tasks", "params":params})).await;
}
async fn cancel(peer: &Peer) {
    peer.discover().await;
    let (mut socket, request) = peer.rpc("tasks/cancel").await;
    assert_eq!(request["params"]["taskId"], "one");
    assert_eq!(request["id"], "persisted:cancel:operation");
    reply(&mut socket, json!({"jsonrpc":"2.0", "id":request["id"], "result":{"resultType":"complete"}})).await;
}

fn isolated_case(name: &str, case: Scenario) {
    isolated_run(&format!("persisted_resume::{name}"), || run_persisted(case));
}
fn run_persisted(case: Scenario) {
    runtime().block_on(async {
        let cx = Cx::current().unwrap();
        let scenario = async {
            let peer = Peer::new().await;
            let client = peer.client();
            let current = binding(&client);
            let retention = if matches!(case, Scenario::Retention) { Duration::from_secs(2) }
                else { Duration::from_secs(60) };
            let initial = TaskResumeRecord::capture(&cx, &current,
                &serde_json::from_value(snapshot("working", 1)).unwrap(), retention).unwrap();
            let original = initial.encode().unwrap();
            let saved = Arc::new(Mutex::new(Saved { record: Some(initial.clone()), calls: 0, commits: 0 }));
            let entered = Arc::new(AtomicBool::new(false));
            let dropped = Arc::new(AtomicUsize::new(0));
            let cancellation = McpRequestCancellation::new();
            let provider_state = Arc::clone(&saved);
            let provider_entered = Arc::clone(&entered);
            let provider_dropped = Arc::clone(&dropped);
            let provider_cancel = cancellation.clone();
            let persist = move |change: TaskResumeChange| {
                let saved = Arc::clone(&provider_state);
                let entered = Arc::clone(&provider_entered);
                let dropped = Arc::clone(&provider_dropped);
                let cancellation = provider_cancel.clone();
                async move {
                    let _probe = DropProbe(dropped);
                    let cleanup = change.replacement().is_none();
                    {
                        let mut state = saved.lock().unwrap();
                        state.calls += 1;
                        assert_eq!(state.record.as_ref(), Some(change.previous()), "conditional predecessor must match exactly");
                        if let Some(record) = change.replacement() {
                            assert!(!record.encode().unwrap().windows(7).any(|bytes| bytes == b"PRIVATE"));
                        }
                    }
                    if (!cleanup && case.pending_save()) || (cleanup && matches!(case, Scenario::DropCleanup)) {
                        entered.store(true, Ordering::SeqCst);
                        std::future::pending::<()>().await;
                    }
                    if !cleanup && matches!(case, Scenario::FailSave) { return Err(StoreError); }
                    {
                        let mut state = saved.lock().unwrap();
                        assert_eq!(state.record.as_ref(), Some(change.previous()));
                        state.record = change.replacement().cloned();
                        state.commits += 1;
                    }
                    if (!cleanup && matches!(case, Scenario::LostSave)) || (cleanup && matches!(case, Scenario::LostCleanup)) {
                        return Err(StoreError);
                    }
                    if matches!(case, Scenario::ReadyCancel) { cancellation.cancel(); }
                    Ok(())
                }
            };
            let policy = ClientCredentialsTaskWatchPolicy::new(Duration::from_secs(10), 16, 32).unwrap();
            let recovery = ClientCredentialsTaskRecoveryPolicy::new(1, Duration::from_millis(20), Duration::from_millis(20)).unwrap();
            let ((mut stream, subscription), admitted) = Box::pin(pair(
                peer.listen(json!(["one"]), false),
                client.resume_task_watch_persisted_with_cancellation(&cx, &cancellation, current.clone(),
                    initial, "persisted".to_owned(), policy, recovery, persist),
            )).await;
            let mut watch = admitted.unwrap();
            let handle = watch.cancel_handle();
            assert_eq!(saved.lock().unwrap().calls, 0, "admission cannot save or publish a snapshot");
            drop(watch.next_snapshot(&cx));
            assert_eq!(saved.lock().unwrap().calls, 0);
            assert_eq!(watch.reconnection_attempts(), 0);
            assert!(matches!(watch.acknowledge_terminal(&cx).await, Err(Error::NoTerminal)));
            // Ordinary reacquisition would now renew; all reads and pending
            // persistence must instead remain bound to the original credential.
            client.client.inner.state.try_lock_owned().unwrap().current.as_mut().unwrap().renew_after = Instant::now();
            let server = async {
                get(&peer, "input_required", 2).await;
                if case.stops_first() {
                    if matches!(case, Scenario::RemoteSave) { cancel(&peer).await; }
                    closed(&mut stream).await;
                    return;
                }
                if matches!(case, Scenario::Recover) {
                    stream.write_all(b"0\r\n\r\n").await.unwrap();
                    stream.shutdown().await.unwrap();
                    let (mut replacement, id) = peer.listen(json!(["one"]), false).await;
                    get(&peer, "input_required", 3).await;
                    terminal_notice(&mut replacement, &id).await;
                    get(&peer, "completed", 4).await;
                    closed(&mut replacement).await;
                } else {
                    terminal_notice(&mut stream, &subscription).await;
                    get(&peer, "completed", if matches!(case, Scenario::Conflict) { 2 } else { 3 }).await;
                    closed(&mut stream).await;
                }
            };
            let application = async {
                let mut read = Box::pin(watch.next_snapshot(&cx));
                if case.pending_save() {
                    poll_fn(|task| {
                        assert!(read.as_mut().poll(task).is_pending());
                        if entered.load(Ordering::SeqCst) { Poll::Ready(()) }
                        else { task.waker().wake_by_ref(); Poll::Pending }
                    }).await;
                }
                if matches!(case, Scenario::DropSave) {
                    drop(read);
                } else {
                    if matches!(case, Scenario::LocalSave) { cancellation.cancel(); }
                    let result = if matches!(case, Scenario::RemoteSave) {
                        let (read, cancelled) = Box::pin(pair(read, handle.request_cancel(&cx))).await;
                        cancelled.unwrap();
                        read
                    } else { read.await };
                    if case.stops_first() {
                        let error = result.err().expect("interrupted save cannot publish the snapshot");
                        assert!(!format!("{error:?} {error}").contains("PRIVATE"));
                        match (case, error) {
                            (Scenario::FailSave | Scenario::LostSave, Error::Persistence(_)) => {},
                            (Scenario::RemoteSave, Error::CancellationRequested) => {},
                            (Scenario::LocalSave | Scenario::ReadyCancel | Scenario::Retention, Error::Authentication(_)) => {},
                            (_, error) => panic!("unexpected persisted watch error: {error:?}"),
                        }
                    } else {
                        let observed = result.unwrap().unwrap();
                        assert!(matches!(*observed.task, Task::InputRequired { .. }));
                        assert_eq!(saved.lock().unwrap().record.as_ref(), Some(watch.last_published_record()));
                        assert_eq!(saved.lock().unwrap().calls, 1);
                        assert!(watch.pending().is_none());
                    }
                }
                if case.stops_first() {
                    let pending = watch.pending().expect("interrupted persistence must retain its snapshot and command");
                    assert_eq!(pending.persistence(), if matches!(case, Scenario::ReadyCancel) {
                        TaskResumePersistenceState::Acknowledged
                    } else { TaskResumePersistenceState::Unconfirmed });
                    assert_eq!(pending.change().previous().encode().unwrap(), original);
                    assert_eq!(watch.last_published_record().encode().unwrap(), original);
                    assert!(watch.terminal_cleanup().is_none());
                    assert!(watch.next_snapshot(&cx).await.is_err());
                    assert!(watch.acknowledge_terminal(&cx).await.is_err());
                    assert_eq!(saved.lock().unwrap().calls, 1);
                    assert_eq!(saved.lock().unwrap().commits, usize::from(matches!(case, Scenario::LostSave | Scenario::ReadyCancel)));
                    assert_eq!(dropped.load(Ordering::SeqCst), 1);
                    assert!(watch.take_pending().is_some());
                    assert!(watch.pending().is_none());
                    assert!(watch.next_snapshot(&cx).await.is_err());
                    assert_eq!(watch.reconnection_attempts(), 0);
                } else {
                    if matches!(case, Scenario::Recover) {
                        let next = watch.next_snapshot(&cx).await.unwrap().unwrap();
                        assert_eq!(next.cause, ManagedTaskSnapshotCause::Reconnected);
                        assert_eq!(watch.reconnection_attempts(), 1);
                        assert_eq!(saved.lock().unwrap().calls, 2);
                    }
                    let result = watch.next_snapshot(&cx).await;
                    if matches!(case, Scenario::Conflict) {
                        assert!(matches!(result, Err(Error::Resume(TaskResumeError::ConflictingSnapshot))));
                        assert!(watch.terminal_cleanup().is_none());
                        assert_eq!(saved.lock().unwrap().calls, 1);
                        assert!(saved.lock().unwrap().record.is_some());
                        assert!(watch.next_snapshot(&cx).await.is_err());
                    } else {
                        let terminal = result.unwrap().unwrap();
                        assert!(matches!(*terminal.task, Task::Completed { .. }));
                        let active_saves = if matches!(case, Scenario::Recover) { 2 } else { 1 };
                        assert_eq!(saved.lock().unwrap().calls, active_saves, "terminal delivery must not delete its checkpoint");
                        assert!(saved.lock().unwrap().record.is_some());
                        assert!(watch.terminal_cleanup().unwrap().replacement().is_none());
                        assert_eq!(watch.cleanup_state(), TaskResumePersistenceState::NotAttempted);
                        assert!(matches!(watch.next_snapshot(&cx).await, Err(Error::TerminalAcknowledgementRequired)));
                        assert!(matches!(handle.request_cancel(&cx).await, Err(ClientCredentialsTaskCancellationError::Closed)));
                        let mut cleanup = Box::pin(watch.acknowledge_terminal(&cx));
                        if matches!(case, Scenario::DropCleanup) {
                            poll_fn(|task| {
                                assert!(cleanup.as_mut().poll(task).is_pending());
                                if entered.load(Ordering::SeqCst) { Poll::Ready(()) }
                                else { task.waker().wake_by_ref(); Poll::Pending }
                            }).await;
                            drop(cleanup);
                        } else {
                            let result = cleanup.await;
                            if matches!(case, Scenario::LostCleanup) { assert!(matches!(result, Err(Error::Persistence(_)))); }
                            else { result.unwrap(); }
                        }
                        let uncertain = matches!(case, Scenario::LostCleanup | Scenario::DropCleanup);
                        assert_eq!(watch.cleanup_state(), if uncertain { TaskResumePersistenceState::Unconfirmed }
                            else { TaskResumePersistenceState::Acknowledged });
                        assert_eq!(saved.lock().unwrap().record.is_some(), matches!(case, Scenario::DropCleanup));
                        if uncertain {
                            assert!(watch.acknowledge_terminal(&cx).await.is_err());
                            assert!(watch.next_snapshot(&cx).await.is_err());
                        } else {
                            watch.acknowledge_terminal(&cx).await.unwrap();
                            assert!(watch.next_snapshot(&cx).await.unwrap().is_none());
                        }
                        assert_eq!(saved.lock().unwrap().calls, active_saves + 1);
                        assert_eq!(dropped.load(Ordering::SeqCst), active_saves + 1);
                    }
                }
                if matches!(case, Scenario::RemoteSave) { assert_eq!(handle.state(), TaskCancellationState::Acknowledged); }
                else { assert_eq!(handle.state(), TaskCancellationState::Ready); }
                assert!(!client.client.inner.closed.is_cancel_requested());
                watch.close();
            };
            Box::pin(pair(server, application)).await;
            let count = if case.stops_first() { 4 } else if matches!(case, Scenario::Recover) { 10 } else { 6 };
            let mut expected: BTreeSet<_> = (0..count).map(|n| format!("persisted:{n}")).collect();
            if matches!(case, Scenario::RemoteSave) {
                expected.insert("persisted:cancel:discovery".to_owned());
                expected.insert("persisted:cancel:operation".to_owned());
            }
            assert_eq!(*peer.seen.lock().unwrap(), expected);
            assert_eq!(peer.updates.load(Ordering::SeqCst), 0, "observation must never install input execution");
            peer.quiet();
        };
        asupersync::time::timeout_at(cx.now().saturating_add_nanos(15_000_000_000), Box::pin(scenario)).await.unwrap();
    });
}

#[test]
fn active_save_precedes_publication_and_terminal_cleanup_is_explicit() { isolated_case("active_save_precedes_publication_and_terminal_cleanup_is_explicit", Scenario::Complete); }
#[test]
fn saved_controls_and_budgets_survive_observation_recovery() { isolated_case("saved_controls_and_budgets_survive_observation_recovery", Scenario::Recover); }
#[test]
fn failed_active_save_cannot_publish_or_retry() { isolated_case("failed_active_save_cannot_publish_or_retry", Scenario::FailSave); }
#[test]
fn committed_save_with_lost_reply_keeps_pending_custody() { isolated_case("committed_save_with_lost_reply_keeps_pending_custody", Scenario::LostSave); }
#[test]
fn abandoned_active_save_closes_without_losing_snapshot() { isolated_case("abandoned_active_save_closes_without_losing_snapshot", Scenario::DropSave); }
#[test]
fn local_cancellation_interrupts_storage_without_remote_mutation() { isolated_case("local_cancellation_interrupts_storage_without_remote_mutation", Scenario::LocalSave); }
#[test]
fn remote_cancel_interrupts_save_without_deleting_checkpoint() { isolated_case("remote_cancel_interrupts_save_without_deleting_checkpoint", Scenario::RemoteSave); }
#[test]
fn ready_poll_cancellation_retains_acknowledged_save() { isolated_case("ready_poll_cancellation_retains_acknowledged_save", Scenario::ReadyCancel); }
#[test]
fn original_checkpoint_retention_bounds_pending_persistence() { isolated_case("original_checkpoint_retention_bounds_pending_persistence", Scenario::Retention); }
#[test]
fn conflicting_terminal_never_elects_cleanup() { isolated_case("conflicting_terminal_never_elects_cleanup", Scenario::Conflict); }
#[test]
fn lost_cleanup_receipt_never_retries_conditional_removal() { isolated_case("lost_cleanup_receipt_never_retries_conditional_removal", Scenario::LostCleanup); }
#[test]
fn abandoned_cleanup_keeps_its_unconfirmed_disposition() { isolated_case("abandoned_cleanup_keeps_its_unconfirmed_disposition", Scenario::DropCleanup); }
