//! Native OAuth/TLS lifecycle tests with an explicit host persistence fixture.
//! The callback is an in-process control-record store, not a durable protector.
//! Real protected-file CAS/reopen behavior is covered by task_resume_store.
use super::*;
use std::cell::{Cell, RefCell};
use std::rc::Rc;
use fastmcp_core::partition::{DurableOwnerKey, PartitionDescriptor};
use fastmcp_client::http_auth::managed::tasks::watch::checkpoint::resume::{
    TaskResumeBinding, TaskResumeError, TaskResumeRecord,
};
use fastmcp_client::http_auth::managed::tasks::watch::checkpoint::resume::client::lifecycle::{
    PersistedTaskWatchError, TaskResumeChange, TaskResumePersistenceState,
};

#[derive(Clone, Copy)]
enum PersistenceCase {
    Success, Reconnect, WriteError, CancelWrite, DropWrite, CancelAfterWrite,
    CleanupError, CleanupCancel, ForeignTask, StaleSnapshot, Redelivery, Preflight,
}

fn controls(status: &str, sequence: u8) -> Value {
    let mut value = json!({"taskId":"one", "status":status,
        "createdAt":"2020-01-01T00:00:00Z",
        "lastUpdatedAt":format!("2020-01-01T00:00:{sequence:02}Z"),
        "ttlMs":null, "statusMessage":"PRIVATE-STATUS"});
    match status {
        "input_required" => value["inputRequests"] = json!({"PRIVATE-INPUT":{"method":"roots/list"}}),
        "completed" => value["result"] = json!({"content":[{"type":"text","text":"PRIVATE-RESULT"}]}),
        _ => {},
    }
    value
}
fn bound(resource: &str, subject: &str) -> TaskResumeBinding {
    let facts = PartitionDescriptor::from_verified_facts("fixture", 1, "https://issuer.example",
        resource, "tenant", subject, "watch-client", 1, 1, &[b"task-observation".as_slice()]).unwrap();
    let owner = DurableOwnerKey::derive(&facts, 1).unwrap();
    TaskResumeBinding::from_verified_owner(url(resource), "persisted-watch", &owner,
        [2; 32], [3; 32], [4; 32]).unwrap()
}
fn seed(cx: &Cx, binding: &TaskResumeBinding) -> TaskResumeRecord {
    TaskResumeRecord::capture(cx, binding, &serde_json::from_value(controls("working", 1)).unwrap(),
        Duration::from_secs(120)).unwrap()
}
async fn get_controls(peer: &Peer, mut task: Value) {
    peer.discover().await;
    let (mut socket, request) = peer.request("tasks/get").await;
    peer.gets.fetch_add(1, Ordering::SeqCst);
    assert_eq!(request["params"]["taskId"], "one");
    task["resultType"] = json!("complete");
    reply(&mut socket, json!({"jsonrpc":"2.0", "id":request["id"], "result":task})).await;
}
async fn changed(stream: &mut TlsStream<TcpStream>, subscription: &Value) {
    let mut params = controls("working", 1); // Deliberately stale invalidation.
    params["_meta"] = json!({(FINAL_SUBSCRIPTION_ID_META_KEY):subscription});
    event(stream, json!({"jsonrpc":"2.0", "method":"notifications/tasks", "params":params})).await;
}

fn isolated_persistence(name: &str, case: PersistenceCase) {
    let name = format!("checkpoint::persistence::{name}");
    isolated_run(&name, || {
        RuntimeBuilder::current_thread().with_reactor(create_reactor().unwrap()).build().unwrap().block_on(async {
            let cx = Cx::current().unwrap();
            let test = Box::pin(async {
                let peer = Peer::new().await;
                match case {
                    PersistenceCase::Redelivery => Box::pin(redelivery(&peer, &cx)).await,
                    PersistenceCase::Preflight => preflight(&peer, &cx).await,
                    _ => Box::pin(lifecycle(&peer, &cx, case)).await,
                }
                peer.no_extra_request();
                assert!(cx.checkpoint().is_ok());
                assert_eq!(peer.discoveries.load(Ordering::SeqCst),
                    peer.gets.load(Ordering::SeqCst) + peer.listens.load(Ordering::SeqCst));
            });
            asupersync::time::timeout_at(cx.now().saturating_add_nanos(20_000_000_000), test).await.unwrap();
        });
    });
}

async fn lifecycle(peer: &Peer, cx: &Cx, case: PersistenceCase) {
    let (session, _) = login(peer, cx).await;
    let caps = serde_json::from_value(json!({"roots":{"listChanged":true}})).unwrap();
    let client = ManagedTasksClient::new(session.clone(), FinalRequestMeta::new(caps), ManagedTasksLimits::default()).unwrap();
    let current = bound(&peer.resource(), "subject");
    let original = seed(cx, &current);
    let memory = Rc::new(RefCell::new(Some(original.clone())));
    let calls = Rc::new(Cell::new(0));
    let gate = Rc::new(Cell::new(false));
    let cancellation = McpRequestCancellation::new();
    let progressing = matches!(case, PersistenceCase::Success | PersistenceCase::Reconnect);
    let terminal_first = matches!(case, PersistenceCase::CleanupError | PersistenceCase::CleanupCancel);
    let server = Box::pin(async {
        let (mut stream, subscription) = peer.listen(json!(["one"]), false).await;
        let mut first = controls(if terminal_first { "completed" } else { "working" },
            if matches!(case, PersistenceCase::StaleSnapshot) { 0 } else { 2 });
        if matches!(case, PersistenceCase::ForeignTask) { first["taskId"] = json!("other"); }
        get_controls(peer, first).await;
        if progressing {
            let subscription = if matches!(case, PersistenceCase::Reconnect) {
                drop(stream);
                let (replacement, id) = peer.listen(json!(["one"]), false).await;
                stream = replacement;
                id
            } else {
                changed(&mut stream, &subscription).await;
                subscription
            };
            get_controls(peer, controls("input_required", 3)).await;
            changed(&mut stream, &subscription).await;
            get_controls(peer, controls("completed", 4)).await;
        }
        assert_closed(&mut stream).await;
    });
    let application = Box::pin(async {
        let persist = |change: TaskResumeChange| {
            calls.set(calls.get() + 1);
            let invocation = calls.get();
            let memory = Rc::clone(&memory);
            let gate = Rc::clone(&gate);
            let cancellation = cancellation.clone();
            async move {
                if invocation == 1 && matches!(case,
                    PersistenceCase::Success | PersistenceCase::CancelWrite | PersistenceCase::DropWrite)
                {
                    poll_fn(|_| if gate.get() { Poll::Ready(()) } else { Poll::Pending }).await;
                }
                if matches!(case, PersistenceCase::WriteError | PersistenceCase::CleanupError) {
                    return Err(std::io::Error::other("PRIVATE-PROVIDER-ERROR"));
                }
                {
                    let mut slot = memory.borrow_mut();
                    assert_eq!(slot.as_ref(), Some(change.previous()));
                    for record in [Some(change.previous()), change.replacement()].into_iter().flatten() {
                        assert!(!record.encode().unwrap().windows(7).any(|part| part == b"PRIVATE"));
                    }
                    *slot = change.replacement().cloned();
                }
                if matches!(case, PersistenceCase::CancelAfterWrite | PersistenceCase::CleanupCancel) {
                    cancellation.cancel();
                }
                Ok::<(), std::io::Error>(())
            }
        };
        let mut watch = Box::pin(client.resume_task_watch_persisted_with_cancellation(
            cx, &cancellation, current, original.clone(), "persist".to_owned(), policy(), recovery(), persist,
        )).await.unwrap();
        assert_eq!(calls.get(), 0, "admission cannot write a record or publish a saved snapshot");
        assert!(matches!(watch.acknowledge_terminal(cx).await, Err(PersistedTaskWatchError::NoTerminal)));
        let first = if matches!(case, PersistenceCase::Success | PersistenceCase::CancelWrite | PersistenceCase::DropWrite) {
            let mut reading = Box::pin(watch.next_snapshot(cx));
            poll_fn(|task| {
                assert!(reading.as_mut().poll(task).is_pending(), "snapshot cannot outrun persistence");
                if calls.get() == 1 { Poll::Ready(()) } else { Poll::Pending }
            }).await;
            assert_eq!(*memory.borrow(), Some(original.clone()));
            if matches!(case, PersistenceCase::DropWrite) {
                drop(reading);
                assert_eq!(watch.pending().unwrap().persistence(), TaskResumePersistenceState::Unconfirmed);
                assert!(matches!(watch.next_snapshot(cx).await, Err(PersistedTaskWatchError::Closed)));
                assert!(watch.take_pending().is_some());
                return;
            }
            if matches!(case, PersistenceCase::CancelWrite) { cancellation.cancel(); }
            else { gate.set(true); }
            reading.await
        } else { Box::pin(watch.next_snapshot(cx)).await };
        if matches!(case, PersistenceCase::ForeignTask | PersistenceCase::StaleSnapshot) {
            match case {
                PersistenceCase::ForeignTask => {
                    let Err(PersistedTaskWatchError::Recovery(ManagedTaskRecoveryError::Watch(error))) = first
                        else { panic!("foreign Task identity must retain its watch failure"); };
                    assert!(matches!(error, ManagedTaskWatchError::Task(ManagedTasksError::TaskIdMismatch)));
                }
                _ => assert!(matches!(first, Err(PersistedTaskWatchError::Resume(TaskResumeError::StaleSnapshot)))),
            }
            assert_eq!(calls.get(), 0);
            assert!(watch.pending().is_none());
            assert!(matches!(watch.next_snapshot(cx).await, Err(PersistedTaskWatchError::Closed)));
        } else if matches!(case, PersistenceCase::WriteError | PersistenceCase::CancelWrite | PersistenceCase::CancelAfterWrite) {
            match case {
                PersistenceCase::WriteError => {
                    let error = first.err().unwrap();
                    assert!(matches!(&error, PersistedTaskWatchError::Persistence(_)));
                    assert!(!format!("{error:?} {error}").contains("PRIVATE"));
                    assert!(std::error::Error::source(&error).unwrap().downcast_ref::<std::io::Error>().is_some());
                }
                _ => assert!(matches!(first, Err(PersistedTaskWatchError::Session(OAuthSessionError::Cancelled)))),
            }
            let pending = watch.pending().unwrap();
            assert!(matches!(&*pending.snapshot().task, Task::Working(_)));
            let acknowledged = matches!(case, PersistenceCase::CancelAfterWrite);
            assert_eq!(pending.persistence(), if acknowledged { TaskResumePersistenceState::Acknowledged } else { TaskResumePersistenceState::Unconfirmed });
            assert_eq!(watch.last_published_record(), &original);
            assert_eq!(*memory.borrow(), if acknowledged { pending.change().replacement().cloned() } else { Some(original.clone()) });
            assert!(matches!(watch.next_snapshot(cx).await, Err(PersistedTaskWatchError::Closed)));
            assert_eq!(calls.get(), 1, "failed persistence must not replay");
        } else {
            let first = first.unwrap().unwrap();
            let terminal = if progressing {
                assert!(matches!(*first.task, Task::Working(_)));
                assert_eq!(first.cause, ManagedTaskSnapshotCause::Initial);
                assert_eq!(memory.borrow().as_ref(), Some(watch.last_published_record()));
                let second = Box::pin(watch.next_snapshot(cx)).await.unwrap().unwrap();
                assert!(matches!(*second.task, Task::InputRequired { .. }));
                assert_eq!(second.cause, if matches!(case, PersistenceCase::Reconnect) {
                    ManagedTaskSnapshotCause::Reconnected
                } else { ManagedTaskSnapshotCause::ChangeNotification });
                assert_eq!(memory.borrow().as_ref(), Some(watch.last_published_record()));
                assert!(watch.pending().is_none());
                Box::pin(watch.next_snapshot(cx)).await.unwrap().unwrap()
            } else { first };
            assert!(matches!(*terminal.task, Task::Completed { .. }));
            let before_cleanup = calls.get();
            assert_eq!(before_cleanup, if progressing { 2 } else { 0 });
            assert!(memory.borrow().is_some(), "delivering terminal must not erase the resume hint");
            assert!(watch.terminal_cleanup().unwrap().replacement().is_none());
            assert!(matches!(watch.next_snapshot(cx).await, Err(PersistedTaskWatchError::TerminalAcknowledgementRequired)));
            let cleaned = Box::pin(watch.acknowledge_terminal(cx)).await;
            if progressing {
                cleaned.unwrap();
                assert!(memory.borrow().is_none());
                assert!(watch.next_snapshot(cx).await.unwrap().is_none());
                watch.acknowledge_terminal(cx).await.unwrap();
            } else {
                match case {
                    PersistenceCase::CleanupError => {
                        assert!(matches!(cleaned, Err(PersistedTaskWatchError::Persistence(_))));
                        assert_eq!(watch.cleanup_state(), TaskResumePersistenceState::Unconfirmed);
                        assert!(memory.borrow().is_some());
                    }
                    _ => {
                        assert!(matches!(cleaned, Err(PersistedTaskWatchError::Session(OAuthSessionError::Cancelled))));
                        assert_eq!(watch.cleanup_state(), TaskResumePersistenceState::Acknowledged);
                        assert!(memory.borrow().is_none());
                    }
                }
                assert!(matches!(watch.acknowledge_terminal(cx).await, Err(PersistedTaskWatchError::Closed)));
            }
            assert_eq!(calls.get(), before_cleanup + 1);
        }
    });
    pair(server, application).await;
    assert_eq!(peer.gets.load(Ordering::SeqCst), if progressing { 3 } else { 1 });
    assert_eq!(peer.listens.load(Ordering::SeqCst), if matches!(case, PersistenceCase::Reconnect) { 2 } else { 1 });
    assert!(session.credential(cx).await.is_ok(), "observation never closes its managed login");
}

async fn redelivery(peer: &Peer, cx: &Cx) {
    let current = bound(&peer.resource(), "subject");
    let original = seed(cx, &current);
    let memory = Rc::new(RefCell::new(Some(original.clone())));
    let calls = Cell::new(0);
    for round in 0..2 {
        let (session, client) = login(peer, cx).await;
        let server = Box::pin(async {
            let (mut stream, _) = peer.listen(json!(["one"]), false).await;
            get_controls(peer, controls("completed", 4)).await;
            assert_closed(&mut stream).await;
        });
        let application = Box::pin(async {
            let mut watch = Box::pin(client.resume_task_watch_persisted(
                cx, current.clone(), original.clone(), format!("redeliver-{round}"), policy(), recovery(),
                |change: TaskResumeChange| {
                    calls.set(calls.get() + 1);
                    assert_eq!(memory.borrow().as_ref(), Some(change.previous()));
                    *memory.borrow_mut() = change.replacement().cloned();
                    std::future::ready(Ok::<(), std::io::Error>(()))
                },
            )).await.unwrap();
            let terminal = Box::pin(watch.next_snapshot(cx)).await.unwrap().unwrap();
            assert!(matches!(*terminal.task, Task::Completed { .. }));
            assert_eq!(calls.get(), 0);
            assert_eq!(*memory.borrow(), Some(original.clone()));
            if round == 1 { watch.acknowledge_terminal(cx).await.unwrap(); }
            // No implicit cleanup on close/drop, even after a terminal delivery.
            watch.close();
            if round == 0 {
                assert!(matches!(watch.acknowledge_terminal(cx).await, Err(PersistedTaskWatchError::Closed)));
            } else { watch.acknowledge_terminal(cx).await.unwrap(); }
            session.close();
        });
        pair(server, application).await;
        assert_eq!(memory.borrow().is_none(), round == 1);
    }
    assert_eq!(calls.get(), 1);
    assert_eq!(peer.gets.load(Ordering::SeqCst), 2);
    assert_eq!(peer.listens.load(Ordering::SeqCst), 2);
}

async fn preflight(peer: &Peer, cx: &Cx) {
    let (session, client) = login(peer, cx).await;
    let current = bound(&peer.resource(), "subject");
    let original = seed(cx, &current);
    let calls = Cell::new(0);
    for dimension in 0..5 {
        let mut binding = current.clone();
        let mut record = original.clone();
        let cancellation = McpRequestCancellation::new();
        match dimension {
            0 => binding = bound(&peer.resource(), "other-subject"),
            1 => binding = bound(&format!("{}/other", peer.resource()), "subject"),
            2 => {
                let mut bytes = record.encode().unwrap();
                let offset = bytes.len() - 16;
                bytes[offset..].copy_from_slice(&1_577_836_802_000_000_000_i128.to_be_bytes());
                record = TaskResumeRecord::decode(&bytes).unwrap();
            }
            3 => { cancellation.cancel(); }
            _ => session.close(),
        }
        let result = Box::pin(client.resume_task_watch_persisted_with_cancellation(
            cx, &cancellation, binding, record, "preflight".to_owned(), policy(), recovery(),
            |_| { calls.set(calls.get() + 1); std::future::ready(Ok::<(), std::io::Error>(())) },
        )).await;
        match dimension {
            0..=2 => assert!(matches!(result, Err(PersistedTaskWatchError::Resume(TaskResumeError::Unavailable)))),
            3 => assert!(matches!(result, Err(PersistedTaskWatchError::Session(OAuthSessionError::Cancelled)))),
            _ => assert!(matches!(result, Err(PersistedTaskWatchError::Session(OAuthSessionError::Closed)))),
        }
        peer.no_extra_request();
    }
    assert_eq!(calls.get(), 0);
    assert_eq!(peer.gets.load(Ordering::SeqCst), 0);
    assert_eq!(peer.listens.load(Ordering::SeqCst), 0);
}

#[test]
fn active_delivery_waits_for_persistence_and_terminal_waits_for_host_ack() { isolated_persistence("active_delivery_waits_for_persistence_and_terminal_waits_for_host_ack", PersistenceCase::Success); }
#[test]
fn recovered_snapshots_keep_the_same_conditional_record_chain() { isolated_persistence("recovered_snapshots_keep_the_same_conditional_record_chain", PersistenceCase::Reconnect); }
#[test]
fn failed_persistence_retains_snapshot_and_closes_without_replay() { isolated_persistence("failed_persistence_retains_snapshot_and_closes_without_replay", PersistenceCase::WriteError); }
#[test]
fn cancellation_during_persistence_preserves_an_unconfirmed_snapshot() { isolated_persistence("cancellation_during_persistence_preserves_an_unconfirmed_snapshot", PersistenceCase::CancelWrite); }
#[test]
fn abandoned_persistence_read_preserves_snapshot_and_releases_stream() { isolated_persistence("abandoned_persistence_read_preserves_snapshot_and_releases_stream", PersistenceCase::DropWrite); }
#[test]
fn cancellation_after_storage_ack_does_not_hide_the_committed_change() { isolated_persistence("cancellation_after_storage_ack_does_not_hide_the_committed_change", PersistenceCase::CancelAfterWrite); }
#[test]
fn failed_terminal_cleanup_is_not_retried() { isolated_persistence("failed_terminal_cleanup_is_not_retried", PersistenceCase::CleanupError); }
#[test]
fn cancellation_after_terminal_cleanup_retains_its_acknowledged_status() { isolated_persistence("cancellation_after_terminal_cleanup_retains_its_acknowledged_status", PersistenceCase::CleanupCancel); }
#[test]
fn foreign_task_snapshot_cannot_reach_storage() { isolated_persistence("foreign_task_snapshot_cannot_reach_storage", PersistenceCase::ForeignTask); }
#[test]
fn regressed_snapshot_cannot_reach_storage() { isolated_persistence("regressed_snapshot_cannot_reach_storage", PersistenceCase::StaleSnapshot); }
#[test]
fn unacknowledged_terminal_survives_owner_replacement_and_is_redelivered() { isolated_persistence("unacknowledged_terminal_survives_owner_replacement_and_is_redelivered", PersistenceCase::Redelivery); }
#[test]
fn invalid_resume_authority_never_contacts_peer_or_persistence() { isolated_persistence("invalid_resume_authority_never_contacts_peer_or_persistence", PersistenceCase::Preflight); }

// Exercise the real remote-cancel controller together with the persistence
// boundary above. Neither a cancellation signal nor a transport is injected.
mod remote_cancellation {
    use super::*;
    use fastmcp_client::http_auth::managed::tasks::watch::cancellation::{
        ManagedTaskCancelHandle, TaskCancellationError, TaskCancellationState,
    };

    #[derive(Clone, Copy)]
    enum Case {
        BeforeRead, PendingGet, Idle, PendingSave, CommittedSave, ReadySave,
        WrongAck, LostAck, RefusedAck, DropRead, TerminalFirst, StaleTerminal,
        ClosedOwner, Backoff,
    }
    fn failed_cancel(case: Case) -> bool {
        matches!(case, Case::WrongAck | Case::LostAck | Case::RefusedAck)
    }
    fn waits_for_save(case: Case) -> bool {
        matches!(case, Case::PendingSave | Case::CommittedSave | Case::DropRead) || failed_cancel(case)
    }

    fn run(name: &str, case: Case) {
        let name = format!("checkpoint::persistence::remote_cancellation::{name}");
        isolated_run(&name, || {
            RuntimeBuilder::current_thread().with_reactor(create_reactor().unwrap()).build().unwrap().block_on(async {
                let cx = Cx::current().unwrap();
                let test = Box::pin(exercise(&cx, case));
                asupersync::time::timeout_at(cx.now().saturating_add_nanos(20_000_000_000), test)
                    .await.expect("persisted cancellation must settle within the fixture budget");
            });
        });
    }

    async fn cancel_request(peer: &Peer) -> (TlsStream<TcpStream>, Value) {
        peer.discover().await;
        assert!(peer.seen.lock().unwrap().contains("persist-remote:cancel:discovery"));
        let (socket, request) = peer.request("tasks/cancel").await;
        assert_eq!(request["id"], "persist-remote:cancel:operation");
        assert_eq!(request["params"]["taskId"], "one");
        assert!(request["params"].get("inputResponses").is_none());
        assert!(request["params"].get("requestState").is_none());
        (socket, request)
    }

    async fn cancel_reply(peer: &Peer, case: Case) {
        let (mut socket, request) = cancel_request(peer).await;
        match case {
            Case::LostAck => {
                socket.write_all(b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 128\r\nConnection: close\r\n\r\n{\"jsonrpc\":").await.unwrap();
                socket.flush().await.unwrap();
            }
            Case::RefusedAck => {
                socket.write_all(b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\nConnection: close\r\n\r\n").await.unwrap();
                socket.flush().await.unwrap();
            }
            _ => {
                let id = if matches!(case, Case::WrongAck) { json!("wrong-cancellation") } else { request["id"].clone() };
                reply(&mut socket, json!({"jsonrpc":"2.0", "id":id, "result":{"resultType":"complete"}})).await;
            }
        }
    }

    async fn exercise(cx: &Cx, case: Case) {
        let peer = Peer::new().await;
        let (session, client) = login(&peer, cx).await;
        let current = bound(&peer.resource(), "subject");
        let original = seed(cx, &current);
        let memory = Rc::new(RefCell::new(Some(original.clone())));
        let calls = Cell::new(0);
        let release_save = McpRequestCancellation::new();
        let local_cancel = McpRequestCancellation::new();
        let installed: RefCell<Option<ManagedTaskCancelHandle>> = RefCell::new(None);
        let (entered_tx, mut entered_rx) = oneshot::channel::<()>();
        let server = Box::pin(async {
            let (mut stream, subscription) = peer.listen(json!(["one"]), false).await;
            if matches!(case, Case::BeforeRead | Case::ClosedOwner) {
                if matches!(case, Case::BeforeRead) { cancel_reply(&peer, case).await; }
                assert_closed(&mut stream).await;
                return;
            }
            if matches!(case, Case::PendingGet) {
                peer.discover().await;
                let (mut pending, request) = peer.request("tasks/get").await;
                peer.gets.fetch_add(1, Ordering::SeqCst);
                assert_eq!(request["params"]["taskId"], "one");
                entered_tx.send(cx, ()).unwrap();
                cancel_reply(&peer, case).await;
                assert_closed(&mut pending).await;
                assert_closed(&mut stream).await;
                return;
            }
            if matches!(case, Case::TerminalFirst | Case::StaleTerminal) {
                get_controls(&peer, controls("completed", if matches!(case, Case::StaleTerminal) { 0 } else { 4 })).await;
                assert_closed(&mut stream).await;
                return;
            }
            get_controls(&peer, controls("working", 2)).await;
            if matches!(case, Case::Backoff) {
                // End HTTP framing without a subscription terminal. Observation
                // must recover or stop, never turn this EOF into Task completion.
                stream.write_all(b"0\r\n\r\n").await.unwrap();
                stream.flush().await.unwrap();
            }
            if matches!(case, Case::DropRead) {
                let (mut pending, _) = cancel_request(&peer).await;
                entered_tx.send(cx, ()).unwrap();
                assert_closed(&mut pending).await;
            } else {
                cancel_reply(&peer, case).await;
                if failed_cancel(case) {
                    changed(&mut stream, &subscription).await;
                    get_controls(&peer, controls("completed", 4)).await;
                }
            }
            assert_closed(&mut stream).await;
        });
        let application = Box::pin(async {
            let persist = |change: TaskResumeChange| {
                calls.set(calls.get() + 1);
                let first = calls.get() == 1;
                let memory = Rc::clone(&memory);
                let release = release_save.clone();
                let handle = installed.borrow().clone();
                let host_cx = cx.clone();
                async move {
                    assert_eq!(memory.borrow().as_ref(), Some(change.previous()));
                    for record in [Some(change.previous()), change.replacement()].into_iter().flatten() {
                        assert!(!record.encode().unwrap().windows(7).any(|part| part == b"PRIVATE"));
                    }
                    if first && matches!(case, Case::CommittedSave) {
                        // Commit before parking, but WITHHOLD its acknowledgement.
                        *memory.borrow_mut() = change.replacement().cloned();
                    }
                    if first && waits_for_save(case) { release.cancelled().await; }
                    if first && matches!(case, Case::ReadySave) {
                        // The real network ACK is admitted inside the callback's
                        // final poll. Persist then acknowledges in that SAME poll.
                        handle.unwrap().request_cancel(&host_cx).await.unwrap();
                    }
                    if !(first && matches!(case, Case::CommittedSave)) {
                        *memory.borrow_mut() = change.replacement().cloned();
                    }
                    Ok::<(), std::io::Error>(())
                }
            };
            let recovery_policy = if matches!(case, Case::Backoff) {
                ManagedTaskRecoveryPolicy::new(2, Duration::from_secs(60), Duration::from_secs(60)).unwrap()
            } else { recovery() };
            let mut watch = Box::pin(client.resume_task_watch_persisted_with_cancellation(
                cx, &local_cancel, current, original.clone(), "persist-remote".to_owned(),
                policy(), recovery_policy, persist,
            )).await.unwrap();
            let handle = watch.cancel_handle();
            *installed.borrow_mut() = Some(handle.clone());
            assert_eq!(handle.state(), TaskCancellationState::Ready);
            assert_eq!(calls.get(), 0);

            if matches!(case, Case::ClosedOwner) {
                watch.close();
                assert!(matches!(handle.request_cancel(cx).await, Err(TaskCancellationError::Closed)));
                assert!(matches!(watch.next_snapshot(cx).await, Err(PersistedTaskWatchError::Closed)));
                assert_eq!(*memory.borrow(), Some(original.clone()));
                assert_eq!(calls.get(), 0);
                return;
            }
            if matches!(case, Case::BeforeRead) {
                handle.request_cancel(cx).await.unwrap();
                assert!(matches!(watch.next_snapshot(cx).await, Err(PersistedTaskWatchError::CancellationRequested)));
                assert!(watch.pending().is_none() && watch.terminal_cleanup().is_none());
                assert_eq!(*memory.borrow(), Some(original.clone()));
                assert_eq!(calls.get(), 0);
                return;
            }
            if matches!(case, Case::TerminalFirst | Case::StaleTerminal) {
                let observed = Box::pin(watch.next_snapshot(cx)).await;
                assert!(matches!(handle.request_cancel(cx).await, Err(TaskCancellationError::Closed)));
                assert_eq!(handle.state(), TaskCancellationState::Ready);
                assert_eq!(*memory.borrow(), Some(original.clone()));
                assert_eq!(calls.get(), 0);
                if matches!(case, Case::StaleTerminal) {
                    assert!(matches!(observed, Err(PersistedTaskWatchError::Resume(TaskResumeError::StaleSnapshot))));
                    assert!(watch.terminal_cleanup().is_none());
                    assert!(matches!(watch.acknowledge_terminal(cx).await, Err(PersistedTaskWatchError::NoTerminal)));
                } else {
                    assert!(matches!(*observed.unwrap().unwrap().task, Task::Completed { .. }));
                    assert!(matches!(watch.next_snapshot(cx).await, Err(PersistedTaskWatchError::TerminalAcknowledgementRequired)));
                    watch.acknowledge_terminal(cx).await.unwrap();
                    assert!(memory.borrow().is_none());
                    assert_eq!(calls.get(), 1);
                    assert!(watch.next_snapshot(cx).await.unwrap().is_none());
                }
                return;
            }

            if matches!(case, Case::Idle | Case::Backoff) {
                let observed = Box::pin(watch.next_snapshot(cx)).await.unwrap().unwrap();
                assert!(matches!(*observed.task, Task::Working(_)));
                assert_eq!(memory.borrow().as_ref(), Some(watch.last_published_record()));
                assert_eq!(calls.get(), 1);
            }
            let mut reading = Box::pin(watch.next_snapshot(cx));
            if matches!(case, Case::ReadySave) {
                assert!(matches!(reading.await, Err(PersistedTaskWatchError::CancellationRequested)));
            } else {
                if waits_for_save(case) {
                    poll_fn(|task| {
                        assert!(reading.as_mut().poll(task).is_pending());
                        if calls.get() == 1 { Poll::Ready(()) } else { Poll::Pending }
                    }).await;
                } else if matches!(case, Case::PendingGet) {
                    let mut entered = Box::pin(entered_rx.recv(cx));
                    poll_fn(|task| {
                        assert!(reading.as_mut().poll(task).is_pending());
                        entered.as_mut().poll(task)
                    }).await.unwrap();
                } else {
                    // Keep polling observation through an idle interval, including
                    // the EOF-to-backoff transition when that case is selected.
                    let mut pause = Box::pin(asupersync::time::Sleep::new(cx.now().saturating_add_nanos(50_000_000)));
                    poll_fn(|task| {
                        assert!(reading.as_mut().poll(task).is_pending());
                        pause.as_mut().poll(task)
                    }).await;
                }
                if matches!(case, Case::DropRead) {
                    let mut cancelling = Box::pin(handle.request_cancel(cx));
                    let mut entered = Box::pin(entered_rx.recv(cx));
                    poll_fn(|task| {
                        assert!(cancelling.as_mut().poll(task).is_pending());
                        entered.as_mut().poll(task)
                    }).await.unwrap();
                    drop(reading);
                    assert!(matches!(cancelling.await, Err(TaskCancellationError::Unconfirmed(_))));
                    assert_eq!(handle.state(), TaskCancellationState::Unconfirmed);
                    assert_eq!(watch.pending().unwrap().persistence(), TaskResumePersistenceState::Unconfirmed);
                    assert_eq!(*memory.borrow(), Some(original.clone()));
                    assert!(matches!(watch.next_snapshot(cx).await, Err(PersistedTaskWatchError::Closed)));
                    assert!(matches!(handle.request_cancel(cx).await, Err(TaskCancellationError::AlreadyAttempted)));
                    assert_eq!(calls.get(), 1);
                    return;
                }
                let cancelled = handle.request_cancel(cx).await;
                if failed_cancel(case) {
                    let error = cancelled.err().unwrap();
                    match case {
                        Case::WrongAck => assert!(matches!(error,
                            TaskCancellationError::Unconfirmed(ManagedTasksError::ResponseIdMismatch))),
                        Case::LostAck => assert!(matches!(error,
                            TaskCancellationError::Unconfirmed(ManagedTasksError::Session(OAuthSessionError::Http(_))))),
                        _ => assert!(matches!(error,
                            TaskCancellationError::Unconfirmed(ManagedTasksError::HttpStatus { status: 403 }))),
                    }
                    assert_eq!(handle.state(), TaskCancellationState::Unconfirmed);
                    assert_eq!(*memory.borrow(), Some(original.clone()));
                    release_save.cancel();
                    let observed = reading.await.unwrap().unwrap();
                    assert!(matches!(*observed.task, Task::Working(_)));
                    assert_eq!(memory.borrow().as_ref(), Some(watch.last_published_record()));
                    let terminal = Box::pin(watch.next_snapshot(cx)).await.unwrap().unwrap();
                    assert!(matches!(*terminal.task, Task::Completed { .. }));
                    assert!(memory.borrow().is_some());
                    assert_eq!(calls.get(), 1);
                    watch.acknowledge_terminal(cx).await.unwrap();
                    assert!(memory.borrow().is_none());
                    assert_eq!(calls.get(), 2);
                    assert!(matches!(handle.request_cancel(cx).await, Err(TaskCancellationError::AlreadyAttempted)));
                    return;
                }
                cancelled.unwrap();
                assert!(matches!(reading.await, Err(PersistedTaskWatchError::CancellationRequested)));
            }

            assert_eq!(handle.state(), TaskCancellationState::Acknowledged);
            assert!(watch.terminal_cleanup().is_none(), "cancel ACK is not terminal deletion authority");
            assert_eq!(watch.cleanup_state(), TaskResumePersistenceState::NotAttempted);
            if matches!(case, Case::PendingSave | Case::CommittedSave | Case::ReadySave) {
                let pending = watch.pending().unwrap();
                assert!(matches!(&*pending.snapshot().task, Task::Working(_)));
                assert_eq!(pending.persistence(), if matches!(case, Case::ReadySave) {
                    TaskResumePersistenceState::Acknowledged
                } else { TaskResumePersistenceState::Unconfirmed });
                assert_eq!(watch.last_published_record(), &original);
                assert_eq!(*memory.borrow(), if matches!(case, Case::CommittedSave | Case::ReadySave) {
                    pending.change().replacement().cloned()
                } else { Some(original.clone()) });
                assert_eq!(calls.get(), 1);
            } else {
                assert!(watch.pending().is_none());
                assert_eq!(memory.borrow().as_ref(), Some(watch.last_published_record()));
                assert_eq!(calls.get(), i32::from(!matches!(case, Case::PendingGet)));
            }
            assert!(matches!(watch.acknowledge_terminal(cx).await, Err(PersistedTaskWatchError::NoTerminal)));
            let before = calls.get();
            assert!(matches!(watch.next_snapshot(cx).await, Err(PersistedTaskWatchError::CancellationRequested)));
            assert!(matches!(handle.request_cancel(cx).await, Err(TaskCancellationError::AlreadyAttempted)));
            assert_eq!(calls.get(), before, "neither a cancelled read nor its write may replay");
            if matches!(case, Case::PendingSave | Case::CommittedSave | Case::ReadySave) {
                assert!(watch.take_pending().is_some());
                assert!(watch.take_pending().is_none());
            }
        });
        pair(server, application).await;
        let cancel_count = usize::from(!matches!(case, Case::ClosedOwner | Case::TerminalFirst | Case::StaleTerminal));
        let gets = if matches!(case, Case::BeforeRead | Case::ClosedOwner) { 0 }
            else if failed_cancel(case) { 2 } else { 1 };
        assert_eq!(peer.gets.load(Ordering::SeqCst), gets);
        assert_eq!(peer.listens.load(Ordering::SeqCst), 1, "cancel ACK must not reopen observation");
        assert_eq!(peer.discoveries.load(Ordering::SeqCst), 1 + gets + cancel_count);
        assert_eq!(peer.seen.lock().unwrap().len(), 2 * (1 + gets + cancel_count));
        assert!(!local_cancel.is_cancel_requested(), "remote cancellation is not ambient cancellation");
        assert!(cx.checkpoint().is_ok());
        assert!(session.credential(cx).await.is_ok(), "cancellation cannot revoke the login");
        peer.no_extra_request();
    }

    #[test]
    fn acknowledged_cancel_prevents_the_first_get_and_any_storage_write() { run("acknowledged_cancel_prevents_the_first_get_and_any_storage_write", Case::BeforeRead); }
    #[test]
    fn acknowledged_cancel_closes_an_outstanding_get_without_persisting() { run("acknowledged_cancel_closes_an_outstanding_get_without_persisting", Case::PendingGet); }
    #[test]
    fn acknowledged_cancel_stops_idle_observation_without_deleting_saved_controls() { run("acknowledged_cancel_stops_idle_observation_without_deleting_saved_controls", Case::Idle); }
    #[test]
    fn acknowledged_cancel_preserves_a_pending_uncommitted_save() { run("acknowledged_cancel_preserves_a_pending_uncommitted_save", Case::PendingSave); }
    #[test]
    fn acknowledged_cancel_cannot_relabel_a_committed_unconfirmed_save_as_rollback() { run("acknowledged_cancel_cannot_relabel_a_committed_unconfirmed_save_as_rollback", Case::CommittedSave); }
    #[test]
    fn remote_ack_inside_ready_save_preserves_storage_acknowledgement() { run("remote_ack_inside_ready_save_preserves_storage_acknowledgement", Case::ReadySave); }
    #[test]
    fn wrong_cancel_identity_does_not_stop_persistence_or_terminal_delivery() { run("wrong_cancel_identity_does_not_stop_persistence_or_terminal_delivery", Case::WrongAck); }
    #[test]
    fn lost_cancel_reply_does_not_stop_persistence_or_terminal_delivery() { run("lost_cancel_reply_does_not_stop_persistence_or_terminal_delivery", Case::LostAck); }
    #[test]
    fn refused_cancel_does_not_stop_persistence_or_terminal_delivery() { run("refused_cancel_does_not_stop_persistence_or_terminal_delivery", Case::RefusedAck); }
    #[test]
    fn abandoning_a_save_retires_an_outstanding_remote_cancel_attempt() { run("abandoning_a_save_retires_an_outstanding_remote_cancel_attempt", Case::DropRead); }
    #[test]
    fn delivered_terminal_retires_cancel_but_preserves_explicit_cleanup() { run("delivered_terminal_retires_cancel_but_preserves_explicit_cleanup", Case::TerminalFirst); }
    #[test]
    fn stale_terminal_never_authorizes_checkpoint_cleanup() { run("stale_terminal_never_authorizes_checkpoint_cleanup", Case::StaleTerminal); }
    #[test]
    fn closing_a_persisted_owner_retires_its_remote_cancel_handle() { run("closing_a_persisted_owner_retires_its_remote_cancel_handle", Case::ClosedOwner); }
    #[test]
    fn remote_cancel_interrupts_recovery_without_resetting_observation() { run("remote_cancel_interrupts_recovery_without_resetting_observation", Case::Backoff); }
}
