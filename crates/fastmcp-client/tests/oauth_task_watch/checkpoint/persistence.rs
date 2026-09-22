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
                    PersistenceCase::Redelivery => redelivery(&peer, &cx).await,
                    PersistenceCase::Preflight => preflight(&peer, &cx).await,
                    _ => lifecycle(&peer, &cx, case).await,
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
