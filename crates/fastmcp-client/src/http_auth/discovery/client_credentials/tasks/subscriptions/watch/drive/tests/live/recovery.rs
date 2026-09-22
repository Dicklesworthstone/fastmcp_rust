//! Native HTTPS regressions sharing the existing machine Task peer and trust
//! fixture. Initial credentials are pre-acquired; issuer grant execution and
//! real-time token expiry are not claimed by these cases.

use super::*;
use std::sync::atomic::AtomicBool;

use crate::http_auth::discovery::client_credentials::{ClientCredentialsError, OAuthDiscoveryError};
use crate::http_auth::discovery::client_credentials::tasks::{ClientCredentialsTasksError, ManagedTasksError};
use crate::http_auth::discovery::client_credentials::tasks::subscriptions::watch::recovery::{
    ClientCredentialsTaskRecoveryError as RecoveryError,
    ClientCredentialsTaskRecoveryPolicy as RecoveryPolicy,
};

#[derive(Clone, Copy)]
enum RecoveryCase {
    Resume, OrdinaryStops, PartialAck, ForeignSnapshot, RemoteRefusal,
    Exhausted, SnapshotLimit, RecordLimit, CancelBackoff, CloseOwner,
    DropBackoff, RevokeBackoff, Deadline,
}

impl RecoveryCase {
    fn controlled_backoff(self) -> bool {
        matches!(self, Self::CancelBackoff | Self::CloseOwner | Self::DropBackoff | Self::RevokeBackoff)
    }

    fn expected_requests(self) -> usize {
        match self {
            Self::Resume | Self::ForeignSnapshot | Self::Exhausted => 10,
            Self::PartialAck | Self::RemoteRefusal | Self::RecordLimit => 8,
            _ => 6,
        }
    }
}

fn isolated_recovery(name: &str, case: RecoveryCase) {
    isolated_run(&format!("recovery::{name}"), || run_recovery(case));
}

async fn end_listen(stream: &mut TlsStream<TcpStream>) {
    // A complete HTTP body without a JSON-RPC terminal is an interrupted
    // subscription, never successful completion of the selected Tasks.
    stream.write_all(b"0\r\n\r\n").await.unwrap();
    stream.shutdown().await.unwrap();
    closed(stream).await;
}

async fn get_foreign_snapshot(peer: &Peer) {
    peer.discover().await;
    let (mut socket, request) = peer.rpc("tasks/get").await;
    assert_eq!(request["params"]["taskId"], "two");
    let mut result = task("foreign-task", "cancelled");
    result["resultType"] = json!("complete");
    reply(&mut socket, json!({"jsonrpc":"2.0","id":request["id"],"result":result})).await;
}

fn is_interruption(error: &ClientCredentialsTaskWatchError) -> bool {
    matches!(error,
        ClientCredentialsTaskWatchError::Interrupted
        | ClientCredentialsTaskWatchError::Task(ClientCredentialsTasksError::Protocol(ManagedTasksError::MissingTerminal))
    )
}

fn run_recovery(case: RecoveryCase) {
    runtime().block_on(async {
        let cx = Cx::current().unwrap();
        let scenario = async {
            let peer = Peer::new().await;
            let mut client = peer.client();
            // Leave room for deliberate backoff without changing token custody.
            Arc::get_mut(&mut client.client.inner).unwrap().timeout = Duration::from_secs(12);
            let cancellation = McpRequestCancellation::new();
            let old_closed = AtomicBool::new(false);
            let snapshots = if matches!(case, RecoveryCase::SnapshotLimit) { 2 } else { 16 };
            let records = if matches!(case, RecoveryCase::RecordLimit) { 4 } else { 32 };
            let watch_policy = ClientCredentialsTaskWatchPolicy::new(Duration::from_secs(10), snapshots, records).unwrap();
            let delay = if case.controlled_backoff() { Duration::from_secs(2) }
                else if matches!(case, RecoveryCase::Deadline) { Duration::from_secs(11) }
                else { Duration::from_millis(20) };
            let recovery_policy = RecoveryPolicy::new(1, delay, delay).unwrap();
            let selected = json!(["one", "two"]);

            let server = async {
                let (mut stream, listen_id) = peer.listen(selected.clone(), false).await;
                peer.get("one", if matches!(case, RecoveryCase::PartialAck) { "working" } else { "cancelled" }).await;
                peer.get("two", "working").await;
                if matches!(case, RecoveryCase::RecordLimit) {
                    for _ in 0..2 {
                        let mut notice = task("two", "working");
                        notice["_meta"] = json!({(FINAL_SUBSCRIPTION_ID_META_KEY):listen_id});
                        event(&mut stream, json!({"jsonrpc":"2.0","method":"notifications/tasks","params":notice})).await;
                    }
                    peer.get("two", "working").await;
                    closed(&mut stream).await;
                    return;
                }
                end_listen(&mut stream).await;
                old_closed.store(true, Ordering::SeqCst);
                if case.controlled_backoff() || matches!(case,
                    RecoveryCase::OrdinaryStops | RecoveryCase::SnapshotLimit | RecoveryCase::Deadline
                ) { return; }
                if matches!(case, RecoveryCase::RemoteRefusal) {
                    peer.discover().await;
                    let (mut socket, request) = peer.rpc("subscriptions/listen").await;
                    assert_eq!(request["params"]["notifications"], json!({"taskIds":["two"]}));
                    socket.write_all(b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\nConnection: close\r\n\r\n").await.unwrap();
                    socket.shutdown().await.unwrap();
                    return;
                }
                let pending = if matches!(case, RecoveryCase::PartialAck) { selected.clone() } else { json!(["two"]) };
                let (mut replacement, _) = peer.listen(pending, matches!(case, RecoveryCase::PartialAck)).await;
                if matches!(case, RecoveryCase::PartialAck) {
                    closed(&mut replacement).await;
                    return;
                }
                if matches!(case, RecoveryCase::ForeignSnapshot) {
                    get_foreign_snapshot(&peer).await;
                } else {
                    peer.get("two", if matches!(case, RecoveryCase::Exhausted) { "working" } else { "cancelled" }).await;
                }
                if matches!(case, RecoveryCase::Exhausted) { end_listen(&mut replacement).await; }
                else { closed(&mut replacement).await; }
            };

            let application = async {
                let ids = serde_json::from_value(selected.clone()).unwrap();
                if matches!(case, RecoveryCase::OrdinaryStops) {
                    let mut watch = Box::pin(client.watch_tasks(&cx, ids, "ordinary".to_owned(), watch_policy)).await.unwrap();
                    assert!(matches!(*watch.next_snapshot(&cx).await.unwrap().unwrap().task, Task::Cancelled(_)));
                    assert!(matches!(*watch.next_snapshot(&cx).await.unwrap().unwrap().task, Task::Working(_)));
                    let error = watch.next_snapshot(&cx).await.err().expect("ordinary watch must not reconnect");
                    assert!(is_interruption(&error));
                    assert!(matches!(watch.next_snapshot(&cx).await, Err(ClientCredentialsTaskWatchError::Closed)));
                    return;
                }
                let mut watch = Box::pin(client.watch_tasks_recovering_with_cancellation(
                    &cx, &cancellation, ids, "recover".to_owned(), watch_policy, recovery_policy,
                )).await.unwrap();
                let first = watch.next_snapshot(&cx).await.unwrap().unwrap();
                assert_eq!(first.cause, ManagedTaskSnapshotCause::Initial);
                assert_eq!(first.task.base().task_id, TaskId::parse("one").unwrap());
                if matches!(case, RecoveryCase::PartialAck) { assert!(matches!(*first.task, Task::Working(_))); }
                else { assert!(matches!(*first.task, Task::Cancelled(_))); }
                let second = watch.next_snapshot(&cx).await.unwrap().unwrap();
                assert_eq!(second.cause, ManagedTaskSnapshotCause::Initial);
                assert_eq!(second.task.base().task_id, TaskId::parse("two").unwrap());
                assert!(matches!(*second.task, Task::Working(_)));

                if case.controlled_backoff() {
                    let mut reading = Box::pin(watch.next_snapshot(&cx));
                    // The peer observes EOF only after the client released the
                    // old stream. Keep driving the actual public read until
                    // then, so cancellation/drop targets recovery, not ingress.
                    poll_fn(|task| {
                        assert!(reading.as_mut().poll(task).is_pending());
                        if old_closed.load(Ordering::SeqCst) { Poll::Ready(()) }
                        else { task.waker().wake_by_ref(); Poll::Pending }
                    }).await;
                    if matches!(case, RecoveryCase::DropBackoff) {
                        drop(reading);
                        assert!(!cancellation.is_cancel_requested());
                    } else {
                        match case {
                            RecoveryCase::CancelBackoff => { cancellation.cancel(); }
                            RecoveryCase::CloseOwner => client.client.close(),
                            RecoveryCase::RevokeBackoff => {
                                client.client.inner.state.try_lock_owned().unwrap().current.as_ref().unwrap().bearer.revoke();
                            }
                            _ => unreachable!(),
                        }
                        let error = reading.await.err().expect("recovery must observe local closure");
                        match (case, error) {
                            (RecoveryCase::CancelBackoff, RecoveryError::Watch(ClientCredentialsTaskWatchError::Task(
                                ClientCredentialsTasksError::Authentication(ClientCredentialsError::Discovery(OAuthDiscoveryError::Cancelled))
                            ))) => {},
                            (RecoveryCase::CloseOwner, RecoveryError::Watch(ClientCredentialsTaskWatchError::Task(
                                ClientCredentialsTasksError::Authentication(ClientCredentialsError::Closed)
                            ))) => {},
                            (RecoveryCase::RevokeBackoff, RecoveryError::Watch(ClientCredentialsTaskWatchError::Task(
                                ClientCredentialsTasksError::Authentication(ClientCredentialsError::Expired)
                            ))) => {},
                            (_, error) => panic!("wrong recovery cancellation cause: {error:?}"),
                        }
                    }
                    assert_eq!(watch.reconnection_attempts(), 1);
                } else {
                    let result = watch.next_snapshot(&cx).await;
                    match case {
                        RecoveryCase::Resume => {
                            let snapshot = result.unwrap().unwrap();
                            assert_eq!(snapshot.cause, ManagedTaskSnapshotCause::Reconnected);
                            assert_eq!(snapshot.task.base().task_id, TaskId::parse("two").unwrap());
                            assert!(matches!(*snapshot.task, Task::Cancelled(_)));
                            assert_eq!(watch.reconnection_attempts(), 1);
                            assert!(watch.next_snapshot(&cx).await.unwrap().is_none());
                            return;
                        }
                        RecoveryCase::Exhausted => {
                            let snapshot = result.unwrap().unwrap();
                            assert_eq!(snapshot.cause, ManagedTaskSnapshotCause::Reconnected);
                            assert!(matches!(*snapshot.task, Task::Working(_)));
                            let error = watch.next_snapshot(&cx).await.err().expect("one reconnect cannot become two");
                            assert!(std::error::Error::source(&error).is_some());
                            let RecoveryError::RecoveryLimit { last_error } = error else { panic!("recovery limit required"); };
                            assert!(is_interruption(&last_error));
                            assert_eq!(watch.reconnection_attempts(), 1);
                        }
                        RecoveryCase::PartialAck => assert!(matches!(result,
                            Err(RecoveryError::Watch(ClientCredentialsTaskWatchError::IncompleteAcknowledgement)))),
                        RecoveryCase::ForeignSnapshot => assert!(matches!(result,
                            Err(RecoveryError::Watch(ClientCredentialsTaskWatchError::Task(
                                ClientCredentialsTasksError::Protocol(ManagedTasksError::TaskIdMismatch)
                            ))))),
                        RecoveryCase::RemoteRefusal => assert!(matches!(result,
                            Err(RecoveryError::Watch(ClientCredentialsTaskWatchError::Task(
                                ClientCredentialsTasksError::Protocol(ManagedTasksError::HttpStatus { status: 403 })
                            ))))),
                        RecoveryCase::SnapshotLimit => {
                            assert!(matches!(result, Err(RecoveryError::Watch(ClientCredentialsTaskWatchError::SnapshotLimit))));
                            assert_eq!(watch.reconnection_attempts(), 0);
                        }
                        RecoveryCase::RecordLimit => {
                            let snapshot = result.unwrap().unwrap();
                            assert_eq!(snapshot.cause, ManagedTaskSnapshotCause::ChangeNotification);
                            assert!(matches!(*snapshot.task, Task::Working(_)));
                            assert!(matches!(watch.next_snapshot(&cx).await,
                                Err(RecoveryError::Watch(ClientCredentialsTaskWatchError::Task(
                                    ClientCredentialsTasksError::Protocol(ManagedTasksError::RecordLimit)
                                )))));
                            assert_eq!(watch.reconnection_attempts(), 0);
                        }
                        RecoveryCase::Deadline => assert!(matches!(result,
                            Err(RecoveryError::Watch(ClientCredentialsTaskWatchError::Task(
                                ClientCredentialsTasksError::Authentication(ClientCredentialsError::Discovery(OAuthDiscoveryError::TimedOut))
                            ))))),
                        _ => unreachable!(),
                    }
                }
                assert!(matches!(watch.next_snapshot(&cx).await,
                    Err(RecoveryError::Watch(ClientCredentialsTaskWatchError::Closed))));
            };
            Box::pin(pair(server, application)).await;
            // The peer checks unique IDs, exact bearer and both negotiated
            // extensions on EVERY POST. No hidden mutation or extra get can
            // satisfy these exact counts or the final no-pending-socket check.
            assert_eq!(peer.seen.lock().unwrap().len(), case.expected_requests());
            assert_eq!(peer.updates.load(Ordering::SeqCst), 0);
            peer.quiet();
        };
        asupersync::time::timeout_at(cx.now().saturating_add_nanos(15_000_000_000), Box::pin(scenario)).await.unwrap();
    });
}

#[test]
fn tls_recovery_reconciles_only_unfinished_tasks() { isolated_recovery("tls_recovery_reconciles_only_unfinished_tasks", RecoveryCase::Resume); }
#[test]
fn tls_ordinary_watch_does_not_opt_into_recovery() { isolated_recovery("tls_ordinary_watch_does_not_opt_into_recovery", RecoveryCase::OrdinaryStops); }
#[test]
fn tls_recovery_requires_complete_replacement_ack() { isolated_recovery("tls_recovery_requires_complete_replacement_ack", RecoveryCase::PartialAck); }
#[test]
fn tls_recovery_rejects_foreign_task_snapshots() { isolated_recovery("tls_recovery_rejects_foreign_task_snapshots", RecoveryCase::ForeignSnapshot); }
#[test]
fn tls_recovery_does_not_retry_authorization_refusal() { isolated_recovery("tls_recovery_does_not_retry_authorization_refusal", RecoveryCase::RemoteRefusal); }
#[test]
fn tls_recovery_exhaustion_preserves_cause_and_closes() { isolated_recovery("tls_recovery_exhaustion_preserves_cause_and_closes", RecoveryCase::Exhausted); }
#[test]
fn tls_recovery_preserves_the_global_snapshot_budget() { isolated_recovery("tls_recovery_preserves_the_global_snapshot_budget", RecoveryCase::SnapshotLimit); }
#[test]
fn tls_recovery_reserves_stream_records_without_refunding() { isolated_recovery("tls_recovery_reserves_stream_records_without_refunding", RecoveryCase::RecordLimit); }
#[test]
fn tls_recovery_cancel_during_backoff_stops_contact() { isolated_recovery("tls_recovery_cancel_during_backoff_stops_contact", RecoveryCase::CancelBackoff); }
#[test]
fn tls_recovery_owner_close_during_backoff_stops_contact() { isolated_recovery("tls_recovery_owner_close_during_backoff_stops_contact", RecoveryCase::CloseOwner); }
#[test]
fn tls_recovery_dropped_read_during_backoff_stays_closed() { isolated_recovery("tls_recovery_dropped_read_during_backoff_stays_closed", RecoveryCase::DropBackoff); }
#[test]
fn tls_recovery_revocation_during_backoff_cannot_renew() { isolated_recovery("tls_recovery_revocation_during_backoff_cannot_renew", RecoveryCase::RevokeBackoff); }
#[test]
fn tls_recovery_cannot_extend_deadline_to_fit_backoff() { isolated_recovery("tls_recovery_cannot_extend_deadline_to_fit_backoff", RecoveryCase::Deadline); }
