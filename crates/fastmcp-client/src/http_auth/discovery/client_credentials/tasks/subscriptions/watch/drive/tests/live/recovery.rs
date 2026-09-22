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

// Public input-driver recovery shares this file's existing isolated TLS peer.
// The original observation-only cases above retain their complete assertions.
mod input_driver {
    use super::*;
    use std::cell::Cell;
    use crate::http_auth::discovery::client_credentials::tasks::subscriptions::watch::cancellation::{
        ClientCredentialsTaskCancellationError, TaskCancellationState,
    };

    #[derive(Clone, Copy)]
    enum InputCase {
        LostGet, EndedListen, InitialGet, NoRecovery, LostUpdate, MalformedGet,
        ChangedAnswered, ChangedUnanswered, EmptyAck, Foreign, Refused, Exhausted,
        SnapshotLimit, UpdateLimit, RemoteBackoff, RemoteAck, DropBackoff, DropAck,
        LocalBackoff, RevokeBackoff, Deadline,
    }
    impl InputCase {
        fn controlled_backoff(self) -> bool {
            matches!(self, Self::RemoteBackoff | Self::DropBackoff | Self::LocalBackoff | Self::RevokeBackoff)
        }
        fn controlled_ack(self) -> bool { matches!(self, Self::RemoteAck | Self::DropAck) }
        fn remote(self) -> bool { matches!(self, Self::RemoteBackoff | Self::RemoteAck) }
        fn successful(self) -> bool { matches!(self, Self::LostGet | Self::EndedListen | Self::InitialGet) }
        fn numeric_requests(self) -> usize {
            match self {
                Self::LostGet | Self::EndedListen | Self::InitialGet => 16,
                Self::LostUpdate => 6,
                Self::EmptyAck | Self::RemoteAck | Self::DropAck => 10,
                Self::Refused => 9,
                Self::ChangedAnswered | Self::ChangedUnanswered | Self::Foreign | Self::Exhausted | Self::UpdateLimit => 12,
                _ => 8,
            }
        }
        fn reconnects(self) -> usize {
            if matches!(self, Self::NoRecovery | Self::LostUpdate | Self::MalformedGet | Self::SnapshotLimit) { 0 } else { 1 }
        }
    }

    fn isolated_input(name: &str, case: InputCase) {
        isolated_run(&format!("recovery::input_driver::{name}"), || run_input(case));
    }
    fn no_resolver(_: TaskInputRequests) -> std::future::Ready<Result<ManagedTaskInputAction, ClientCredentialsTaskWatchDriveError>> {
        panic!("closed or unpolled input driver must not resolve input")
    }
    fn no_observer(_: &Task) -> Result<(), ClientCredentialsTaskWatchDriveError> {
        panic!("closed or unpolled input driver must not publish a snapshot")
    }

    async fn broken_json(mut socket: TlsStream<TcpStream>, complete: bool) {
        // Identical JSON prefix: only the HTTP framing completeness differs.
        // A failed native body read can recover; complete invalid JSON cannot.
        let prefix = "{\"jsonrpc\":";
        let length = if complete { prefix.len() } else { 128 };
        socket.write_all(format!("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {length}\r\nConnection: close\r\n\r\n{prefix}").as_bytes()).await.unwrap();
        socket.shutdown().await.unwrap();
    }
    async fn lost_get(peer: &Peer, complete: bool) {
        peer.discover().await;
        let (socket, request) = peer.rpc("tasks/get").await;
        assert_eq!(request["params"]["taskId"], "one");
        broken_json(socket, complete).await;
    }
    async fn changed_get(peer: &Peer, changed: Option<&str>, foreign: bool) {
        peer.discover().await;
        let (mut socket, request) = peer.rpc("tasks/get").await;
        assert_eq!(request["params"]["taskId"], "one");
        let mut result = task(if foreign { "foreign-task" } else { "one" }, "input_required");
        result["resultType"] = json!("complete");
        if let Some(key) = changed {
            result["inputRequests"][key] = json!({"method":"sampling/createMessage","params":{"messages":[],"maxTokens":16}});
        }
        reply(&mut socket, json!({"jsonrpc":"2.0","id":request["id"],"result":result})).await;
    }
    async fn cancel(peer: &Peer) {
        peer.discover().await;
        let (mut socket, request) = peer.rpc("tasks/cancel").await;
        assert_eq!(request["id"], "input-recover:cancel:operation");
        assert_eq!(request["params"]["taskId"], "one");
        reply(&mut socket, json!({"jsonrpc":"2.0","id":request["id"],"result":{"resultType":"complete"}})).await;
    }
    async fn replacement_head(peer: &Peer) -> (TlsStream<TcpStream>, serde_json::Value) {
        peer.discover().await;
        let (mut socket, request) = peer.rpc("subscriptions/listen").await;
        assert_eq!(request["params"]["notifications"], json!({"taskIds":["one"]}));
        socket.write_all(b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nTransfer-Encoding: chunked\r\n\r\n").await.unwrap();
        socket.flush().await.unwrap();
        (socket, request["id"].clone())
    }

    fn run_input(case: InputCase) {
        runtime().block_on(async {
            let cx = Cx::current().unwrap();
            let scenario = async {
                let peer = Peer::new().await;
                let mut client = peer.client();
                Arc::get_mut(&mut client.client.inner).unwrap().timeout = Duration::from_secs(12);
                let cancellation = McpRequestCancellation::new();
                let snapshots = if matches!(case, InputCase::SnapshotLimit) { 2 } else { 16 };
                let watch = ClientCredentialsTaskWatchPolicy::new(Duration::from_secs(10), snapshots, 32).unwrap();
                let updates = if matches!(case, InputCase::UpdateLimit) { 1 } else { 4 };
                let mut policy = ClientCredentialsTaskWatchDrivePolicy::new(watch, updates, 8, 4096).unwrap();
                if !matches!(case, InputCase::NoRecovery) {
                    let delay = if case.controlled_backoff() { Duration::from_secs(2) }
                        else if matches!(case, InputCase::Deadline) { Duration::from_secs(11) }
                        else { Duration::from_millis(20) };
                    policy = policy.with_recovery(RecoveryPolicy::new(1, delay, delay).unwrap()).unwrap();
                }
                let ((mut stream, _), admitted) = pair(
                    Box::pin(peer.listen(json!(["one"]), false)),
                    Box::pin(client.watch_task_inputs_with_cancellation(&cx, &cancellation,
                        TaskId::parse("one").unwrap(), "input-recover".to_owned(), policy)),
                ).await;
                let mut driver = admitted.unwrap();
                let handle = driver.cancel_handle();
                // Hidden reacquisition must fail: the token endpoint is not our
                // peer, and ordinary acquisition would now attempt renewal.
                client.client.inner.state.try_lock_owned().unwrap().current.as_mut().unwrap().renew_after = Instant::now();
                drop(Box::pin(driver.drive(&cx, no_resolver, no_observer)));
                assert_eq!(peer.seen.lock().unwrap().len(), 2);
                assert_eq!(driver.reconnection_attempts(), 0);
                let old_closed = AtomicBool::new(false);
                let ack_pending = AtomicBool::new(false);
                let resolutions = Cell::new(0);
                let observations = Cell::new(0);

                let server = async {
                    if matches!(case, InputCase::InitialGet) {
                        lost_get(&peer, false).await;
                    } else {
                        peer.get("one", "input_required").await;
                        if matches!(case, InputCase::LostUpdate) {
                            peer.discover().await;
                            let (socket, request) = peer.rpc("tasks/update").await;
                            assert_eq!(request["params"]["taskId"], "one");
                            assert_eq!(request["params"]["inputResponses"], json!({"one":{"roots":[]}}));
                            peer.updates.fetch_add(1, Ordering::SeqCst);
                            broken_json(socket, false).await;
                            closed(&mut stream).await;
                            old_closed.store(true, Ordering::SeqCst);
                            return;
                        }
                        peer.update("one", false).await;
                        if matches!(case, InputCase::EndedListen) {
                            peer.get("one", "working").await;
                            end_listen(&mut stream).await;
                        } else {
                            lost_get(&peer, matches!(case, InputCase::MalformedGet)).await;
                            closed(&mut stream).await;
                        }
                    }
                    if matches!(case, InputCase::InitialGet) { closed(&mut stream).await; }
                    old_closed.store(true, Ordering::SeqCst);
                    if case.controlled_backoff() {
                        if case.remote() { cancel(&peer).await; }
                        return;
                    }
                    if matches!(case, InputCase::NoRecovery | InputCase::MalformedGet | InputCase::SnapshotLimit | InputCase::Deadline) {
                        return;
                    }
                    if matches!(case, InputCase::Refused) {
                        let (mut socket, request) = peer.rpc("server/discover").await;
                        assert!(request["params"].get("taskId").is_none());
                        socket.write_all(b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\nConnection: close\r\n\r\n").await.unwrap();
                        socket.shutdown().await.unwrap();
                        return;
                    }
                    if matches!(case, InputCase::EmptyAck) || case.controlled_ack() {
                        let (mut replacement, id) = replacement_head(&peer).await;
                        if matches!(case, InputCase::EmptyAck) {
                            event(&mut replacement, json!({"jsonrpc":"2.0","method":"notifications/subscriptions/acknowledged",
                                "params":{"_meta":{(FINAL_SUBSCRIPTION_ID_META_KEY):id},"notifications":{"taskIds":[]}}})).await;
                        } else {
                            ack_pending.store(true, Ordering::SeqCst);
                            if case.remote() { cancel(&peer).await; }
                        }
                        closed(&mut replacement).await;
                        return;
                    }
                    let (mut replacement, _) = peer.listen(json!(["one"]), false).await;
                    if matches!(case, InputCase::Exhausted) {
                        lost_get(&peer, false).await;
                    } else if matches!(case, InputCase::ChangedAnswered | InputCase::ChangedUnanswered | InputCase::Foreign) {
                        let changed = match case {
                            InputCase::ChangedAnswered => Some("one"),
                            InputCase::ChangedUnanswered => Some("two"),
                            _ => None,
                        };
                        changed_get(&peer, changed, matches!(case, InputCase::Foreign)).await;
                    } else {
                        peer.get("one", "input_required").await;
                        if case.successful() {
                            if matches!(case, InputCase::InitialGet) {
                                peer.update("one", false).await;
                                peer.get("one", "input_required").await;
                            }
                            peer.update("two", false).await;
                            peer.get("one", "cancelled").await;
                        }
                    }
                    closed(&mut replacement).await;
                };

                let application = async {
                    let mut driving = Box::pin(driver.drive(&cx, |pending| {
                        let count = resolutions.get() + 1;
                        resolutions.set(count);
                        assert!(count <= 2, "recovery cannot replay a successful host answer");
                        let key = if count == 1 { "one" } else { "two" };
                        assert_eq!(pending.len(), if count == 1 { 2 } else { 1 });
                        assert!(pending.contains_key(key));
                        if count == 2 { assert!(!pending.contains_key("one")); }
                        std::future::ready(Ok(ManagedTaskInputAction::Respond(answers(json!({key:{"roots":[]}})))))
                    }, |_| { observations.set(observations.get() + 1); Ok(()) }));
                    let controlled = case.controlled_backoff() || case.controlled_ack();
                    if controlled {
                        poll_fn(|cx| {
                            assert!(driving.as_mut().poll(cx).is_pending());
                            let ready = if case.controlled_ack() { ack_pending.load(Ordering::SeqCst) }
                                else { old_closed.load(Ordering::SeqCst) };
                            if ready { Poll::Ready(()) } else { cx.waker().wake_by_ref(); Poll::Pending }
                        }).await;
                    }
                    if matches!(case, InputCase::DropBackoff | InputCase::DropAck) {
                        drop(driving);
                        assert!(!cancellation.is_cancel_requested());
                    } else {
                        if matches!(case, InputCase::LocalBackoff) { cancellation.cancel(); }
                        if matches!(case, InputCase::RevokeBackoff) {
                            client.client.inner.state.try_lock_owned().unwrap().current.as_ref().unwrap().bearer.revoke();
                        }
                        let result = if case.remote() {
                            let (result, cancelled) = pair(driving, Box::pin(handle.request_cancel(&cx))).await;
                            cancelled.unwrap();
                            result
                        } else { driving.await };
                        if case.successful() {
                            assert!(matches!(result, Ok(ManagedTaskRunOutcome::Terminal(task)) if matches!(*task, Task::Cancelled(_))));
                        } else {
                            let error = result.err().expect("failed recovery must not fabricate a terminal");
                            match (case, error) {
                                (InputCase::NoRecovery, ClientCredentialsTaskWatchDriveError::Watch(error)) => assert!(is_interruption(&error)),
                                (InputCase::LostUpdate | InputCase::MalformedGet, ClientCredentialsTaskWatchDriveError::Watch(ClientCredentialsTaskWatchError::Task(
                                    ClientCredentialsTasksError::Protocol(ManagedTasksError::InvalidResponse)))) => {},
                                (InputCase::ChangedAnswered | InputCase::ChangedUnanswered, ClientCredentialsTaskWatchDriveError::Input(ClientCredentialsTaskWaitError::InputKeyReused)) => {},
                                (InputCase::UpdateLimit, ClientCredentialsTaskWatchDriveError::Input(ClientCredentialsTaskWaitError::UpdateLimit)) => {},
                                (InputCase::EmptyAck, ClientCredentialsTaskWatchDriveError::Watch(ClientCredentialsTaskWatchError::IncompleteAcknowledgement)) => {},
                                (InputCase::Foreign, ClientCredentialsTaskWatchDriveError::Watch(ClientCredentialsTaskWatchError::Task(
                                    ClientCredentialsTasksError::Protocol(ManagedTasksError::TaskIdMismatch)))) => {},
                                (InputCase::Refused, ClientCredentialsTaskWatchDriveError::Watch(ClientCredentialsTaskWatchError::Task(
                                    ClientCredentialsTasksError::Protocol(ManagedTasksError::HttpStatus { status: 403 })))) => {},
                                (InputCase::Exhausted, ClientCredentialsTaskWatchDriveError::Recovery(RecoveryError::RecoveryLimit { last_error })) => assert!(is_interruption(&last_error)),
                                (InputCase::SnapshotLimit, ClientCredentialsTaskWatchDriveError::Watch(ClientCredentialsTaskWatchError::SnapshotLimit)) => {},
                                (InputCase::RemoteBackoff | InputCase::RemoteAck, ClientCredentialsTaskWatchDriveError::CancellationRequested) => {},
                                (InputCase::LocalBackoff, ClientCredentialsTaskWatchDriveError::Watch(ClientCredentialsTaskWatchError::Task(
                                    ClientCredentialsTasksError::Authentication(ClientCredentialsError::Discovery(OAuthDiscoveryError::Cancelled))))) => {},
                                (InputCase::RevokeBackoff, ClientCredentialsTaskWatchDriveError::Watch(ClientCredentialsTaskWatchError::Task(
                                    ClientCredentialsTasksError::Authentication(ClientCredentialsError::Expired)))) => {},
                                (InputCase::Deadline, ClientCredentialsTaskWatchDriveError::Watch(ClientCredentialsTaskWatchError::Task(
                                    ClientCredentialsTasksError::Authentication(ClientCredentialsError::Discovery(OAuthDiscoveryError::TimedOut))))) => {},
                                (_, error) => panic!("unexpected input recovery outcome: {error:?}"),
                            }
                        }
                    }
                    let acknowledged = if case.successful() { 2 } else if matches!(case, InputCase::LostUpdate) { 0 } else { 1 };
                    assert_eq!(driver.acknowledged_updates(), acknowledged);
                    assert_eq!(driver.update_state(), if matches!(case, InputCase::LostUpdate) {
                        TaskInputUpdateState::Unconfirmed
                    } else { TaskInputUpdateState::Acknowledged });
                    assert_eq!(driver.last_update_request_id(), Some(&RequestId::String(
                        if case.successful() { "input-recover:13" } else { "input-recover:5" }.to_owned())));
                    assert_eq!(driver.reconnection_attempts(), case.reconnects());
                    assert_eq!(resolutions.get(), if case.successful() { 2 } else { 1 });
                    let expected_observations = if matches!(case, InputCase::EndedListen) { 4 }
                        else if case.successful() { 3 }
                        else if matches!(case, InputCase::ChangedAnswered | InputCase::ChangedUnanswered | InputCase::UpdateLimit) { 2 }
                        else { 1 };
                    assert_eq!(observations.get(), expected_observations);
                    if case.remote() { assert_eq!(handle.state(), TaskCancellationState::Acknowledged); }
                    else { assert_eq!(handle.state(), TaskCancellationState::Ready); }
                    driver.close();
                    assert_eq!(driver.acknowledged_updates(), acknowledged);
                    assert_eq!(driver.reconnection_attempts(), case.reconnects());
                    assert!(driver.drive(&cx, no_resolver, no_observer).await.is_err());
                    assert!(matches!(handle.request_cancel(&cx).await,
                        Err(ClientCredentialsTaskCancellationError::Closed | ClientCredentialsTaskCancellationError::AlreadyAttempted)));
                    assert!(!client.client.inner.closed.is_cancel_requested());
                };
                Box::pin(pair(server, application)).await;
                assert!(old_closed.load(Ordering::SeqCst));
                let mut expected: BTreeSet<_> = (0..case.numeric_requests()).map(|n| format!("input-recover:{n}")).collect();
                if case.remote() {
                    expected.insert("input-recover:cancel:discovery".to_owned());
                    expected.insert("input-recover:cancel:operation".to_owned());
                }
                assert_eq!(*peer.seen.lock().unwrap(), expected);
                assert_eq!(peer.updates.load(Ordering::SeqCst), if case.successful() { 2 } else { 1 });
                assert_eq!(cancellation.is_cancel_requested(), matches!(case, InputCase::LocalBackoff));
                peer.quiet();
            };
            asupersync::time::timeout_at(cx.now().saturating_add_nanos(15_000_000_000), Box::pin(scenario)).await.unwrap();
        });
    }

    #[test]
    fn tls_input_recovery_keeps_partial_answers_after_lost_get() { isolated_input("tls_input_recovery_keeps_partial_answers_after_lost_get", InputCase::LostGet); }
    #[test]
    fn tls_input_recovery_keeps_partial_answers_after_ended_listen() { isolated_input("tls_input_recovery_keeps_partial_answers_after_ended_listen", InputCase::EndedListen); }
    #[test]
    fn tls_input_recovery_reconciles_an_interrupted_initial_get() { isolated_input("tls_input_recovery_reconciles_an_interrupted_initial_get", InputCase::InitialGet); }
    #[test]
    fn tls_input_recovery_is_never_implicitly_enabled() { isolated_input("tls_input_recovery_is_never_implicitly_enabled", InputCase::NoRecovery); }
    #[test]
    fn tls_input_recovery_never_replays_a_lost_update_reply() { isolated_input("tls_input_recovery_never_replays_a_lost_update_reply", InputCase::LostUpdate); }
    #[test]
    fn tls_input_recovery_rejects_complete_malformed_json() { isolated_input("tls_input_recovery_rejects_complete_malformed_json", InputCase::MalformedGet); }
    #[test]
    fn tls_input_recovery_rejects_changed_answered_descriptors() { isolated_input("tls_input_recovery_rejects_changed_answered_descriptors", InputCase::ChangedAnswered); }
    #[test]
    fn tls_input_recovery_rejects_changed_unanswered_descriptors() { isolated_input("tls_input_recovery_rejects_changed_unanswered_descriptors", InputCase::ChangedUnanswered); }
    #[test]
    fn tls_input_recovery_requires_complete_replacement_ack() { isolated_input("tls_input_recovery_requires_complete_replacement_ack", InputCase::EmptyAck); }
    #[test]
    fn tls_input_recovery_rejects_foreign_snapshots() { isolated_input("tls_input_recovery_rejects_foreign_snapshots", InputCase::Foreign); }
    #[test]
    fn tls_input_recovery_stops_at_current_authorization_refusal() { isolated_input("tls_input_recovery_stops_at_current_authorization_refusal", InputCase::Refused); }
    #[test]
    fn tls_input_recovery_cannot_refund_reconnections() { isolated_input("tls_input_recovery_cannot_refund_reconnections", InputCase::Exhausted); }
    #[test]
    fn tls_input_recovery_cannot_refund_snapshot_reservations() { isolated_input("tls_input_recovery_cannot_refund_snapshot_reservations", InputCase::SnapshotLimit); }
    #[test]
    fn tls_input_recovery_cannot_refund_acknowledged_updates() { isolated_input("tls_input_recovery_cannot_refund_acknowledged_updates", InputCase::UpdateLimit); }
    #[test]
    fn tls_input_remote_cancel_interrupts_recovery_backoff() { isolated_input("tls_input_remote_cancel_interrupts_recovery_backoff", InputCase::RemoteBackoff); }
    #[test]
    fn tls_input_remote_cancel_interrupts_replacement_ack() { isolated_input("tls_input_remote_cancel_interrupts_replacement_ack", InputCase::RemoteAck); }
    #[test]
    fn tls_input_abandonment_closes_recovery_backoff() { isolated_input("tls_input_abandonment_closes_recovery_backoff", InputCase::DropBackoff); }
    #[test]
    fn tls_input_abandonment_closes_replacement_ack() { isolated_input("tls_input_abandonment_closes_replacement_ack", InputCase::DropAck); }
    #[test]
    fn tls_input_local_cancel_interrupts_recovery_without_remote_cancel() { isolated_input("tls_input_local_cancel_interrupts_recovery_without_remote_cancel", InputCase::LocalBackoff); }
    #[test]
    fn tls_input_revocation_during_recovery_cannot_renew_authority() { isolated_input("tls_input_revocation_during_recovery_cannot_renew_authority", InputCase::RevokeBackoff); }
    #[test]
    fn tls_input_recovery_cannot_extend_the_original_deadline() { isolated_input("tls_input_recovery_cannot_extend_the_original_deadline", InputCase::Deadline); }
}
