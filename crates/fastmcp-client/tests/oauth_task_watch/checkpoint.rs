//! Checkpoint export and restore through the public native TLS watch API.
//! Reuses the existing OAuth peer, strict request checks and isolated trust store.

use super::*;
use fastmcp_client::http_auth::managed::tasks::watch::checkpoint::{
    ManagedTaskCheckpointError, ManagedTaskWatchCheckpoint,
};
use fastmcp_client::http_auth::managed::tasks::watch::recovery::{
    ManagedTaskRecoveryError, ManagedTaskRecoveryPolicy,
};

#[derive(Clone, Copy)]
enum CheckpointCase { Restart, Recovering, Resource, Cancelled, Closed, Limits, PartialAck, RemoteError, WrongTask }

fn policy() -> ManagedTaskWatchPolicy {
    ManagedTaskWatchPolicy::new(Duration::from_secs(10), 16, 64).unwrap()
}
fn recovery() -> ManagedTaskRecoveryPolicy {
    ManagedTaskRecoveryPolicy::new(1, Duration::from_millis(1), Duration::from_millis(1)).unwrap()
}
fn selection() -> Vec<TaskId> { vec![TaskId::parse("one").unwrap(), TaskId::parse("two").unwrap()] }
async fn login(peer: &Peer, cx: &Cx) -> (ManagedOAuthSession, ManagedTasksClient) {
    let ((), session) = pair(peer.login(), ManagedOAuthSession::authorize(
        cx, peer.client(), OAuthSessionPolicy::default(), browser,
    )).await;
    let session = session.unwrap();
    let client = ManagedTasksClient::new(session.clone(), FinalRequestMeta::new(ClientCapabilities::default()), ManagedTasksLimits::default()).unwrap();
    (session, client)
}

fn isolated_checkpoint(name: &str, case: CheckpointCase) {
    isolated_run(name, || {
        RuntimeBuilder::current_thread().with_reactor(create_reactor().unwrap()).build().unwrap().block_on(async {
            let cx = Cx::current().unwrap();
            let test = Box::pin(async {
                let peer = Peer::new().await;
                match case {
                    CheckpointCase::Restart | CheckpointCase::Recovering => restart(&peer, &cx, matches!(case, CheckpointCase::Recovering)).await,
                    _ => refusals(&peer, &cx, case).await,
                }
            });
            asupersync::time::timeout_at(cx.now().saturating_add_nanos(20_000_000_000), test)
                .await.expect("checkpoint TLS case must settle within the original process bound");
        });
    });
}

async fn restart(peer: &Peer, cx: &Cx, recovering: bool) {
    let bytes = {
        let (session, client) = login(peer, cx).await;
        let server = Box::pin(async {
            let (mut stream, _) = peer.listen(json!(["one", "two"]), false).await;
            peer.get("one", "working", Case::Multi).await;
            peer.get("two", "cancelled", Case::Multi).await;
            assert_closed(&mut stream).await;
        });
        let application = Box::pin(async {
            let mut watch = Box::pin(client.watch_tasks(cx, selection(), "checkpoint-before".to_owned(), policy())).await.unwrap();
            let one = Box::pin(watch.next_snapshot(cx)).await.unwrap().unwrap();
            assert!(matches!(*one.task, Task::Working(_)));
            let two = Box::pin(watch.next_snapshot(cx)).await.unwrap().unwrap();
            assert!(matches!(*two.task, Task::Cancelled(_)));
            assert_eq!(watch.remaining_tasks(), 1);
            let bytes = watch.checkpoint().unwrap().encode().unwrap();
            watch.close();
            assert_eq!(watch.checkpoint().unwrap().encode().unwrap(), bytes);
            assert!(matches!(Box::pin(watch.next_snapshot(cx)).await, Err(ManagedTaskWatchError::Closed)));
            session.close();
            bytes
        });
        let ((), bytes) = pair(server, application).await;
        bytes
        // Every old watch, snapshot, managed client and login is dropped here.
    };
    let saved: Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(saved.as_object().unwrap().len(), 5);
    assert_eq!(saved["taskIds"], json!(["one", "two"]));
    assert_eq!(saved["resource"], peer.resource());
    assert!(!String::from_utf8(bytes.clone()).unwrap().contains("watch-access"));
    // Exercise host-owned file storage, not an in-memory clone of a watch.
    // This fixture recreates the login and all owners, not an OS crash oracle.
    let path = std::env::temp_dir().join(format!("fastmcp-task-watch-checkpoint-{}-{recovering}.json", std::process::id()));
    std::fs::write(&path, &bytes).unwrap();
    drop(bytes);
    let checkpoint = ManagedTaskWatchCheckpoint::decode(&std::fs::read(path).unwrap()).unwrap();
    assert_eq!(checkpoint.task_ids(), selection());
    let (session, client) = login(peer, cx).await;
    let server = Box::pin(async {
        let (mut stream, _) = peer.listen(json!(["one", "two"]), false).await;
        peer.get("one", if recovering { "working" } else { "cancelled" }, Case::Multi).await;
        // Even the Task previously delivered terminal is freshly authorized.
        peer.get("two", "cancelled", Case::Multi).await;
        if recovering {
            // Lose the stream, then finish task one during the observation gap.
            // Only the unfinished selection is acknowledged on reconnection.
            drop(stream);
            let (mut replacement, _) = peer.listen(json!(["one"]), false).await;
            peer.get("one", "cancelled", Case::Multi).await;
            assert_closed(&mut replacement).await;
        } else {
            assert_closed(&mut stream).await;
        }
    });
    let application = Box::pin(async {
        if recovering {
            let mut watch = Box::pin(client.resume_task_watch_recovering(
                cx, &checkpoint, "checkpoint-after".to_owned(), policy(), recovery(),
            )).await.unwrap();
            let one = Box::pin(watch.next_snapshot(cx)).await.unwrap().unwrap();
            assert!(matches!(*one.task, Task::Working(_)));
            assert_eq!(one.cause, ManagedTaskSnapshotCause::Initial);
            let two = Box::pin(watch.next_snapshot(cx)).await.unwrap().unwrap();
            assert_eq!(two.task.base().task_id, TaskId::parse("two").unwrap());
            assert!(matches!(*two.task, Task::Cancelled(_)));
            let terminal = Box::pin(watch.next_snapshot(cx)).await.unwrap().unwrap();
            assert_eq!(terminal.task.base().task_id, TaskId::parse("one").unwrap());
            assert_eq!(terminal.cause, ManagedTaskSnapshotCause::Reconnected);
            assert!(matches!(*terminal.task, Task::Cancelled(_)));
            assert_eq!(watch.reconnection_attempts(), 1);
            assert!(Box::pin(watch.next_snapshot(cx)).await.unwrap().is_none());
        } else {
            let mut watch = Box::pin(client.resume_task_watch(
                cx, &checkpoint, "checkpoint-after".to_owned(), policy(),
            )).await.unwrap();
            assert_eq!(watch.remaining_tasks(), 2, "saved terminal delivery is not restored as authority");
            for expected in ["one", "two"] {
                let snapshot = Box::pin(watch.next_snapshot(cx)).await.unwrap().unwrap();
                assert_eq!(snapshot.task.base().task_id, TaskId::parse(expected).unwrap());
                assert_eq!(snapshot.cause, ManagedTaskSnapshotCause::Initial);
                assert!(matches!(*snapshot.task, Task::Cancelled(_)));
            }
            assert_eq!(watch.remaining_tasks(), 0);
            assert!(Box::pin(watch.next_snapshot(cx)).await.unwrap().is_none());
        }
        assert!(session.credential(cx).await.is_ok());
        assert!(cx.checkpoint().is_ok());
    });
    pair(server, application).await;
    let gets = if recovering { 5 } else { 4 };
    let listens = if recovering { 3 } else { 2 };
    assert_eq!(peer.gets.load(Ordering::SeqCst), gets);
    assert_eq!(peer.listens.load(Ordering::SeqCst), listens);
    assert_eq!(peer.discoveries.load(Ordering::SeqCst), gets + listens);
    peer.no_extra_request();
}

async fn refusals(peer: &Peer, cx: &Cx, case: CheckpointCase) {
    let (session, client) = login(peer, cx).await;
    let checkpoint = client.task_watch_checkpoint(selection()).unwrap();
    let original = checkpoint.encode().unwrap();
    match case {
        CheckpointCase::Resource => {
            let mut wrong: Value = serde_json::from_slice(&original).unwrap();
            wrong["resource"] = json!(format!("{}/other", peer.resource()));
            let wrong = ManagedTaskWatchCheckpoint::decode(wrong.to_string().as_bytes()).unwrap();
            assert!(matches!(Box::pin(client.resume_task_watch(cx, &wrong, "wrong".to_owned(), policy())).await,
                Err(ManagedTaskCheckpointError::ResourceMismatch)));
            assert!(matches!(Box::pin(client.resume_task_watch_recovering(cx, &wrong, "wrong".to_owned(), policy(), recovery())).await,
                Err(ManagedTaskCheckpointError::ResourceMismatch)));
        }
        CheckpointCase::Cancelled | CheckpointCase::Closed => {
            let cancellation = McpRequestCancellation::new();
            if matches!(case, CheckpointCase::Closed) { session.close(); } else { cancellation.cancel(); }
            let result = Box::pin(client.resume_task_watch_with_cancellation(
                cx, &cancellation, &checkpoint, "rejected".to_owned(), policy(),
            )).await;
            let error = result.err().expect("closed/cancelled restore cannot admit a watch");
            match case {
                CheckpointCase::Closed => assert!(matches!(&error, ManagedTaskCheckpointError::Watch(ManagedTaskWatchError::Session(OAuthSessionError::Closed)))),
                _ => assert!(matches!(&error, ManagedTaskCheckpointError::Watch(ManagedTaskWatchError::Session(OAuthSessionError::Cancelled)))),
            }
            assert!(std::error::Error::source(&error).unwrap().downcast_ref::<ManagedTaskWatchError>().is_some());
            let result = Box::pin(client.resume_task_watch_recovering_with_cancellation(
                cx, &cancellation, &checkpoint, "rejected-recovery".to_owned(), policy(), recovery(),
            )).await;
            match case {
                CheckpointCase::Closed => assert!(matches!(result, Err(ManagedTaskCheckpointError::Recovery(ManagedTaskRecoveryError::Watch(ManagedTaskWatchError::Session(OAuthSessionError::Closed)))))),
                _ => assert!(matches!(result, Err(ManagedTaskCheckpointError::Recovery(ManagedTaskRecoveryError::Watch(ManagedTaskWatchError::Session(OAuthSessionError::Cancelled)))))),
            }
        }
        CheckpointCase::Limits => {
            let too_few = ManagedTaskWatchPolicy::new(Duration::from_secs(10), 1, 64).unwrap();
            assert!(matches!(Box::pin(client.resume_task_watch(cx, &checkpoint, "limits".to_owned(), too_few)).await,
                Err(ManagedTaskCheckpointError::Watch(ManagedTaskWatchError::InvalidSelection))));
            assert!(matches!(Box::pin(client.resume_task_watch(cx, &checkpoint, "bad:prefix".to_owned(), policy())).await,
                Err(ManagedTaskCheckpointError::Watch(ManagedTaskWatchError::InvalidIdPrefix))));
            let too_few = ManagedTaskWatchPolicy::new(Duration::from_secs(10), 16, 2).unwrap();
            assert!(matches!(Box::pin(client.resume_task_watch_recovering(cx, &checkpoint, "limits".to_owned(), too_few, recovery())).await,
                Err(ManagedTaskCheckpointError::Recovery(ManagedTaskRecoveryError::InvalidPolicy))));
        }
        CheckpointCase::PartialAck | CheckpointCase::RemoteError | CheckpointCase::WrongTask => {
            let server = Box::pin(async {
                let (mut stream, _) = peer.listen(json!(["one", "two"]), matches!(case, CheckpointCase::PartialAck)).await;
                if matches!(case, CheckpointCase::WrongTask) {
                    peer.get("one", "cancelled", Case::WrongTask).await;
                } else if matches!(case, CheckpointCase::RemoteError) {
                    peer.discover().await;
                    let (mut socket, request) = peer.request("tasks/get").await;
                    peer.gets.fetch_add(1, Ordering::SeqCst);
                    assert_eq!(request["params"]["taskId"], "one");
                    reply(&mut socket, json!({"jsonrpc":"2.0", "id":request["id"], "error":{
                        "code":-32602, "message":"Task is unavailable for this login",
                    }})).await;
                }
                assert_closed(&mut stream).await;
            });
            let application = Box::pin(async {
                let result = Box::pin(client.resume_task_watch(cx, &checkpoint, "resume-refusal".to_owned(), policy())).await;
                if matches!(case, CheckpointCase::PartialAck) {
                    assert!(matches!(result, Err(ManagedTaskCheckpointError::Watch(ManagedTaskWatchError::IncompleteAcknowledgement))));
                    return;
                }
                let mut watch = result.unwrap();
                let snapshot = Box::pin(watch.next_snapshot(cx)).await;
                if matches!(case, CheckpointCase::WrongTask) {
                    assert!(matches!(snapshot, Err(ManagedTaskWatchError::Task(ManagedTasksError::TaskIdMismatch))));
                } else {
                    assert!(matches!(snapshot, Err(ManagedTaskWatchError::Task(_))), "unavailable Task must remain an error, not a synthetic terminal");
                }
                assert_eq!(watch.remaining_tasks(), 2);
                assert!(matches!(Box::pin(watch.next_snapshot(cx)).await, Err(ManagedTaskWatchError::Closed)));
            });
            pair(server, application).await;
        }
        _ => unreachable!("restart has a separate positive path"),
    }
    assert_eq!(checkpoint.encode().unwrap(), original, "refusal does not mutate saved selection");
    assert!(cx.checkpoint().is_ok());
    if !matches!(case, CheckpointCase::Closed) { assert!(session.credential(cx).await.is_ok()); }
    let gets = usize::from(matches!(case, CheckpointCase::RemoteError | CheckpointCase::WrongTask));
    let listens = usize::from(matches!(case, CheckpointCase::PartialAck | CheckpointCase::RemoteError | CheckpointCase::WrongTask));
    assert_eq!(peer.gets.load(Ordering::SeqCst), gets);
    assert_eq!(peer.listens.load(Ordering::SeqCst), listens);
    assert_eq!(peer.discoveries.load(Ordering::SeqCst), gets + listens);
    peer.no_extra_request();
}

#[test]
fn saved_selection_resumes_with_a_new_login_and_fresh_terminal_snapshots() {
    isolated_checkpoint("checkpoint::saved_selection_resumes_with_a_new_login_and_fresh_terminal_snapshots", CheckpointCase::Restart);
}
#[test]
fn restored_watch_can_reconnect_without_replaying_or_reviving_terminal_tasks() {
    isolated_checkpoint("checkpoint::restored_watch_can_reconnect_without_replaying_or_reviving_terminal_tasks", CheckpointCase::Recovering);
}
#[test]
fn wrong_checkpoint_resource_is_refused_before_any_mcp_traffic() {
    isolated_checkpoint("checkpoint::wrong_checkpoint_resource_is_refused_before_any_mcp_traffic", CheckpointCase::Resource);
}
#[test]
fn precancelled_restore_preserves_session_and_typed_failure_without_traffic() {
    isolated_checkpoint("checkpoint::precancelled_restore_preserves_session_and_typed_failure_without_traffic", CheckpointCase::Cancelled);
}
#[test]
fn saved_selection_cannot_reopen_a_closed_login() {
    isolated_checkpoint("checkpoint::saved_selection_cannot_reopen_a_closed_login", CheckpointCase::Closed);
}
#[test]
fn restore_rechecks_current_snapshot_identity_and_recovery_budgets() {
    isolated_checkpoint("checkpoint::restore_rechecks_current_snapshot_identity_and_recovery_budgets", CheckpointCase::Limits);
}
#[test]
fn restored_selection_requires_complete_subscription_acknowledgement() {
    isolated_checkpoint("checkpoint::restored_selection_requires_complete_subscription_acknowledgement", CheckpointCase::PartialAck);
}
#[test]
fn unavailable_saved_task_is_not_recreated_or_reported_complete() {
    isolated_checkpoint("checkpoint::unavailable_saved_task_is_not_recreated_or_reported_complete", CheckpointCase::RemoteError);
}
#[test]
fn restored_watch_rejects_a_foreign_task_snapshot_without_publication() {
    isolated_checkpoint("checkpoint::restored_watch_rejects_a_foreign_task_snapshot_without_publication", CheckpointCase::WrongTask);
}

#[path = "checkpoint/persistence.rs"]
mod persistence;
