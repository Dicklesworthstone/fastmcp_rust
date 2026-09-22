//! Real TLS cancellation and input-update races using the existing peer.
//! Only the pre-acquired grant is a fixture; every watch, request, decoder and
//! host-input transition is the production implementation. No worker is spawned.
use super::*;
use std::cell::Cell;
use crate::http_auth::discovery::client_credentials::tasks::subscriptions::watch::cancellation::{
    ClientCredentialsTaskCancellationError, TaskCancellationState,
};

const PREFIX: &str = "machine-control";
#[derive(Clone, Copy)]
enum ControlCase {
    BeforeFirst, Resolver, ReadyResolver, UpdatePending, GetPending,
    WrongAck, LostAck, Refused, DropResolver, DropUpdate, Terminal, Return,
    LocalCancel, Revoked, Deadline,
}
fn isolated_control(name: &str, case: ControlCase) {
    isolated_run(&format!("cancellation::{name}"), || run_control(case));
}
fn failed_cancel(case: ControlCase) -> bool {
    matches!(case, ControlCase::WrongAck | ControlCase::LostAck | ControlCase::Refused)
}
fn waiting_resolver(case: ControlCase) -> bool {
    failed_cancel(case) || matches!(case, ControlCase::Resolver | ControlCase::DropResolver | ControlCase::LocalCancel)
}
fn no_resolver(_: TaskInputRequests) -> std::future::Ready<Result<ManagedTaskInputAction, ClientCredentialsTaskWatchDriveError>> {
    panic!("closed or terminal input owner must not call the resolver")
}
fn no_observer(_: &Task) -> Result<(), ClientCredentialsTaskWatchDriveError> {
    panic!("closed input owner must not publish a snapshot")
}
struct DropFlag<'a>(&'a Cell<bool>);
impl Drop for DropFlag<'_> { fn drop(&mut self) { self.0.set(true); } }

async fn cancel_reply(peer: &Peer, case: ControlCase) {
    if matches!(case, ControlCase::Refused) {
        let (mut socket, request) = peer.rpc("server/discover").await;
        assert_eq!(request["id"], format!("{PREFIX}:cancel:discovery"));
        assert!(request["params"].get("taskId").is_none());
        socket.write_all(b"HTTP/1.1 401 Unauthorized\r\nContent-Length: 0\r\nConnection: close\r\n\r\n").await.unwrap();
        socket.flush().await.unwrap();
        return;
    }
    peer.discover().await;
    let (mut socket, request) = peer.rpc("tasks/cancel").await;
    assert_eq!(request["id"], format!("{PREFIX}:cancel:operation"));
    assert_eq!(request["params"]["taskId"], "one");
    assert_eq!(request["params"]["_meta"]["com.example/tenant"], "retained");
    assert_eq!(request["params"].as_object().unwrap().len(), 2);
    if matches!(case, ControlCase::LostAck) {
        socket.write_all(b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 128\r\nConnection: close\r\n\r\n{\"jsonrpc\":").await.unwrap();
        socket.flush().await.unwrap();
        return;
    }
    let id = if matches!(case, ControlCase::WrongAck) { json!("foreign-response") } else { request["id"].clone() };
    reply(&mut socket, json!({"jsonrpc":"2.0","id":id,"result":{"resultType":"complete"}})).await;
}
async fn update_head(peer: &Peer) -> (TlsStream<TcpStream>, serde_json::Value) {
    peer.discover().await;
    let (socket, request) = peer.rpc("tasks/update").await;
    assert_eq!(request["id"], format!("{PREFIX}:5"));
    assert_eq!(request["params"]["taskId"], "one");
    assert_eq!(request["params"]["inputResponses"], json!({"one":{"roots":[]}}));
    assert_eq!(request["params"]["_meta"]["com.example/tenant"], "retained");
    assert_eq!(request["params"].as_object().unwrap().len(), 3);
    peer.updates.fetch_add(1, Ordering::SeqCst);
    (socket, request["id"].clone())
}
fn expect_ids(peer: &Peer, numeric: usize, cancel: usize) {
    let mut expected: BTreeSet<String> = (0..numeric).map(|id| format!("{PREFIX}:{id}")).collect();
    if cancel >= 1 { expected.insert(format!("{PREFIX}:cancel:discovery")); }
    if cancel == 2 { expected.insert(format!("{PREFIX}:cancel:operation")); }
    assert_eq!(*peer.seen.lock().unwrap(), expected, "exact wire IDs forbid hidden polling, renewal or replay");
    peer.quiet();
}

fn run_control(case: ControlCase) {
    runtime().block_on(async {
        let cx = Cx::current().unwrap();
        let scenario = async {
            let peer = Peer::new().await;
            let client = peer.client();
            let shared = McpRequestCancellation::new();
            let timeout = if matches!(case, ControlCase::Deadline) { Duration::from_secs(1) } else { Duration::from_secs(10) };
            let policy = ClientCredentialsTaskWatchDrivePolicy::new(
                ClientCredentialsTaskWatchPolicy::new(timeout, 16, 32).unwrap(), 4, 8, 4096,
            ).unwrap();
            let ((mut stream, _), opened) = Box::pin(pair(peer.listen(json!(["one"]), false),
                client.watch_task_inputs_with_cancellation(&cx, &shared,
                    TaskId::parse("one").unwrap(), PREFIX.to_owned(), policy))).await;
            let mut driver = opened.unwrap();
            let handle = driver.cancel_handle();
            drop(Box::pin(driver.drive(&cx, no_resolver, no_observer)));
            assert_eq!(driver.update_state(), TaskInputUpdateState::NotAttempted);
            expect_ids(&peer, 2, 0);
            // Any implicit renewal would contact the deliberately unusable issuer.
            // Every subsequent peer-accepted request must use the original bearer.
            client.client.inner.state.try_lock_owned().unwrap().current.as_mut().unwrap().renew_after = Instant::now();
            if matches!(case, ControlCase::BeforeFirst) {
                let ((), accepted) = Box::pin(pair(cancel_reply(&peer, case), handle.request_cancel(&cx))).await;
                accepted.unwrap();
                assert!(matches!(driver.drive(&cx, no_resolver, no_observer).await,
                    Err(ClientCredentialsTaskWatchDriveError::CancellationRequested)));
                assert_eq!(handle.state(), TaskCancellationState::Acknowledged);
                assert_eq!(driver.update_state(), TaskInputUpdateState::NotAttempted);
                expect_ids(&peer, 2, 2);
            } else if matches!(case, ControlCase::Revoked | ControlCase::Deadline) {
                if matches!(case, ControlCase::Revoked) {
                    client.client.inner.state.try_lock_owned().unwrap().current.as_ref().unwrap().bearer.revoke();
                } else {
                    asupersync::time::Sleep::new(cx.now().saturating_add_nanos(1_100_000_000)).await;
                }
                assert!(matches!(handle.request_cancel(&cx).await, Err(ClientCredentialsTaskCancellationError::NotAttempted(_))));
                assert_eq!(handle.state(), TaskCancellationState::Ready);
                assert!(driver.drive(&cx, no_resolver, no_observer).await.is_err());
                expect_ids(&peer, 2, 0);
            } else {
                let phase = McpRequestCancellation::new();
                let release = McpRequestCancellation::new();
                let resolutions = Cell::new(0);
                let observations = Cell::new(0);
                let dropped = Cell::new(false);
                let server = async {
                    if matches!(case, ControlCase::Terminal) {
                        peer.get("one", "cancelled").await;
                        return;
                    }
                    peer.get("one", "input_required").await;
                    match case {
                        ControlCase::UpdatePending | ControlCase::DropUpdate => {
                            let (mut update, _) = update_head(&peer).await;
                            phase.cancel();
                            if matches!(case, ControlCase::UpdatePending) { cancel_reply(&peer, case).await; }
                            closed(&mut update).await;
                        }
                        ControlCase::GetPending => {
                            let (mut update, id) = update_head(&peer).await;
                            reply(&mut update, json!({"jsonrpc":"2.0","id":id,"result":{"resultType":"complete"}})).await;
                            peer.discover().await;
                            let (mut get, request) = peer.rpc("tasks/get").await;
                            assert_eq!(request["id"], format!("{PREFIX}:7"));
                            assert_eq!(request["params"]["taskId"], "one");
                            phase.cancel();
                            cancel_reply(&peer, case).await;
                            closed(&mut get).await;
                        }
                        ControlCase::Return | ControlCase::DropResolver | ControlCase::LocalCancel => {},
                        _ => {
                            cancel_reply(&peer, case).await;
                            if failed_cancel(case) {
                                peer.update("one", false).await;
                                peer.get("one", "cancelled").await;
                            }
                        }
                    }
                };
                let application = async {
                    let phase_ref = &phase;
                    let release_ref = &release;
                    let dropped_ref = &dropped;
                    let handle_ref = &handle;
                    let cx_ref = &cx;
                    let mut driving = Box::pin(driver.drive(&cx, |pending| {
                        assert_eq!(pending.keys().map(String::as_str).collect::<Vec<_>>(), ["one", "two"]);
                        resolutions.set(resolutions.get() + 1);
                        let guard = DropFlag(dropped_ref);
                        async move {
                            let _guard = guard;
                            if waiting_resolver(case) {
                                phase_ref.cancel();
                                release_ref.cancelled().await;
                            }
                            if matches!(case, ControlCase::ReadyResolver) {
                                // Admit a real ACK while this resolver is being
                                // polled, then return otherwise-valid input. No
                                // update may escape the same-poll stop decision.
                                handle_ref.request_cancel(cx_ref).await.unwrap();
                            }
                            if matches!(case, ControlCase::Return) { return Ok(ManagedTaskInputAction::ReturnToCaller); }
                            Ok(ManagedTaskInputAction::Respond(answers(json!({"one":{"roots":[]}}))))
                        }
                    }, |_| { observations.set(observations.get() + 1); Ok(()) }));
                    if matches!(case, ControlCase::DropResolver | ControlCase::DropUpdate) {
                        let mut reached = std::pin::pin!(phase.cancelled());
                        poll_fn(|task| {
                            assert!(driving.as_mut().poll(task).is_pending());
                            reached.as_mut().poll(task)
                        }).await;
                        drop(driving);
                        assert!(dropped.get());
                    } else {
                        let cancellation = async {
                            if matches!(case, ControlCase::Terminal | ControlCase::Return | ControlCase::ReadyResolver) { return; }
                            phase.cancelled().await;
                            if matches!(case, ControlCase::LocalCancel) { shared.cancel(); return; }
                            let result = handle.request_cancel(&cx).await;
                            if failed_cancel(case) {
                                assert!(matches!(result, Err(ClientCredentialsTaskCancellationError::Unconfirmed(_))));
                                assert_eq!(handle.state(), TaskCancellationState::Unconfirmed);
                                release.cancel();
                            } else { result.unwrap(); }
                        };
                        let (outcome, ()) = Box::pin(pair(driving, cancellation)).await;
                        if failed_cancel(case) || matches!(case, ControlCase::Terminal) {
                            assert!(matches!(outcome, Ok(ManagedTaskRunOutcome::Terminal(task)) if matches!(*task, Task::Cancelled(_))));
                        } else if matches!(case, ControlCase::Return) {
                            assert!(matches!(outcome, Ok(ManagedTaskRunOutcome::InputRequired(_))));
                        } else if matches!(case, ControlCase::LocalCancel) {
                            assert!(matches!(outcome, Err(ClientCredentialsTaskWatchDriveError::Watch(_))));
                        } else {
                            assert!(matches!(outcome, Err(ClientCredentialsTaskWatchDriveError::CancellationRequested)));
                            assert_eq!(handle.state(), TaskCancellationState::Acknowledged);
                        }
                    }
                    let attempted_update = failed_cancel(case) || matches!(case,
                        ControlCase::UpdatePending | ControlCase::GetPending | ControlCase::DropUpdate);
                    let acknowledged = failed_cancel(case) || matches!(case, ControlCase::GetPending);
                    let state = if acknowledged { TaskInputUpdateState::Acknowledged }
                        else if attempted_update { TaskInputUpdateState::Unconfirmed }
                        else { TaskInputUpdateState::NotAttempted };
                    assert_eq!(driver.update_state(), state);
                    assert_eq!(driver.acknowledged_updates(), usize::from(acknowledged));
                    let expected = attempted_update.then(|| RequestId::String(format!("{PREFIX}:5")));
                    assert_eq!(driver.last_update_request_id(), expected.as_ref());
                    assert_eq!(peer.updates.load(Ordering::SeqCst), usize::from(attempted_update));
                    assert_eq!(resolutions.get(), usize::from(!matches!(case, ControlCase::Terminal)));
                    assert_eq!(observations.get(), if failed_cancel(case) { 2 } else { 1 });
                    if !matches!(case, ControlCase::Terminal) { assert!(dropped.get()); }
                    driver.close();
                    assert_eq!(driver.update_state(), state, "close cannot erase an uncertain update or receipt");
                    assert!(matches!(driver.drive(&cx, no_resolver, no_observer).await,
                        Err(ClientCredentialsTaskWatchDriveError::CancellationRequested)
                        | Err(ClientCredentialsTaskWatchDriveError::Watch(ClientCredentialsTaskWatchError::Closed))));
                    let repeated = handle.request_cancel(&cx).await;
                    if handle.state() == TaskCancellationState::Ready {
                        assert!(matches!(repeated, Err(ClientCredentialsTaskCancellationError::Closed)));
                    } else { assert!(matches!(repeated, Err(ClientCredentialsTaskCancellationError::AlreadyAttempted))); }
                };
                Box::pin(pair(server, application)).await;
                let (numeric, cancel) = match case {
                    ControlCase::UpdatePending => (6, 2),
                    ControlCase::GetPending | ControlCase::WrongAck | ControlCase::LostAck => (8, 2),
                    ControlCase::Refused => (8, 1),
                    ControlCase::DropUpdate => (6, 0),
                    ControlCase::Resolver | ControlCase::ReadyResolver => (4, 2),
                    _ => (4, 0),
                };
                expect_ids(&peer, numeric, cancel);
            }
            closed(&mut stream).await;
            assert!(!client.client.inner.closed.is_cancel_requested());
            if !matches!(case, ControlCase::LocalCancel) { assert!(!shared.is_cancel_requested()); }
            peer.quiet();
        };
        asupersync::time::timeout_at(cx.now().saturating_add_nanos(15_000_000_000), Box::pin(scenario)).await.unwrap();
    });
}

#[test]
fn tls_cancel_before_first_snapshot_never_enters_host_code() { isolated_control("tls_cancel_before_first_snapshot_never_enters_host_code", ControlCase::BeforeFirst); }
#[test]
fn tls_cancel_drops_pending_resolver_without_update() { isolated_control("tls_cancel_drops_pending_resolver_without_update", ControlCase::Resolver); }
#[test]
fn tls_ack_in_ready_resolver_poll_prevents_update() { isolated_control("tls_ack_in_ready_resolver_poll_prevents_update", ControlCase::ReadyResolver); }
#[test]
fn tls_cancel_retains_uncertainty_for_peer_accepted_update() { isolated_control("tls_cancel_retains_uncertainty_for_peer_accepted_update", ControlCase::UpdatePending); }
#[test]
fn tls_cancel_during_reconciliation_retains_update_receipt() { isolated_control("tls_cancel_during_reconciliation_retains_update_receipt", ControlCase::GetPending); }
#[test]
fn tls_wrong_cancel_ack_does_not_stop_input_execution() { isolated_control("tls_wrong_cancel_ack_does_not_stop_input_execution", ControlCase::WrongAck); }
#[test]
fn tls_lost_cancel_ack_does_not_stop_input_execution() { isolated_control("tls_lost_cancel_ack_does_not_stop_input_execution", ControlCase::LostAck); }
#[test]
fn tls_refused_cancel_discovery_sends_no_task_id() { isolated_control("tls_refused_cancel_discovery_sends_no_task_id", ControlCase::Refused); }
#[test]
fn tls_abandoned_resolver_closes_cancel_admission() { isolated_control("tls_abandoned_resolver_closes_cancel_admission", ControlCase::DropResolver); }
#[test]
fn tls_abandoned_update_retains_uncertainty_without_replay() { isolated_control("tls_abandoned_update_retains_uncertainty_without_replay", ControlCase::DropUpdate); }
#[test]
fn tls_terminal_retires_remote_cancel_authority() { isolated_control("tls_terminal_retires_remote_cancel_authority", ControlCase::Terminal); }
#[test]
fn tls_host_handoff_is_not_a_reusable_input_challenge() { isolated_control("tls_host_handoff_is_not_a_reusable_input_challenge", ControlCase::Return); }
#[test]
fn tls_local_cancel_does_not_send_remote_cancel() { isolated_control("tls_local_cancel_does_not_send_remote_cancel", ControlCase::LocalCancel); }
#[test]
fn tls_revoked_input_authority_cannot_renew_for_cancel() { isolated_control("tls_revoked_input_authority_cannot_renew_for_cancel", ControlCase::Revoked); }
#[test]
fn tls_unpolled_driver_cannot_extend_original_deadline() { isolated_control("tls_unpolled_driver_cannot_extend_original_deadline", ControlCase::Deadline); }

#[test]
fn tls_cancellable_watch_ack_interrupts_idle_notification_read() {
    isolated_run("cancellation::tls_cancellable_watch_ack_interrupts_idle_notification_read", || {
        runtime().block_on(async {
            let cx = Cx::current().unwrap();
            let scenario = async {
                let peer = Peer::new().await;
                let client = peer.client();
                let ((mut stream, _), opened) = Box::pin(pair(peer.listen(json!(["one"]), false),
                    client.watch_task_cancellable(&cx, TaskId::parse("one").unwrap(), PREFIX.to_owned(),
                        ClientCredentialsTaskWatchPolicy::new(Duration::from_secs(10), 8, 16).unwrap()))).await;
                let mut watch = opened.unwrap();
                let handle = watch.cancel_handle();
                let ((), initial) = Box::pin(pair(peer.get("one", "working"), watch.next_snapshot(&cx))).await;
                assert_eq!(initial.unwrap().unwrap().cause, ManagedTaskSnapshotCause::Initial);
                let application = async {
                    let (observed, accepted) = Box::pin(pair(watch.next_snapshot(&cx), handle.request_cancel(&cx))).await;
                    accepted.unwrap();
                    assert!(matches!(observed, Err(CancellableClientCredentialsTaskWatchError::CancellationRequested)));
                    assert!(matches!(watch.next_snapshot(&cx).await, Err(CancellableClientCredentialsTaskWatchError::CancellationRequested)));
                };
                Box::pin(pair(cancel_reply(&peer, ControlCase::Resolver), application)).await;
                assert_eq!(handle.state(), TaskCancellationState::Acknowledged);
                assert_eq!(peer.updates.load(Ordering::SeqCst), 0);
                closed(&mut stream).await;
                expect_ids(&peer, 4, 2);
                assert!(!client.client.inner.closed.is_cancel_requested());
            };
            asupersync::time::timeout_at(cx.now().saturating_add_nanos(15_000_000_000), Box::pin(scenario)).await.unwrap();
        });
    });
}
