//! Public machine checkpoint reconciliation and restart over the existing TLS
//! peer. Records are serialized then restored under a fresh machine owner.
//! Credentials are pre-acquired: these cases do not qualify issuer acquisition,
//! cryptographic storage providers, or process-crash persistence.

use super::*;
use std::sync::atomic::AtomicBool;
use fastmcp_core::partition::{DurableOwnerKey, PartitionDescriptor};
use crate::http_auth::discovery::client_credentials::{ClientCredentialsError, OAuthDiscoveryError};
use crate::http_auth::discovery::client_credentials::tasks::{ClientCredentialsTasksError, ManagedTasksError};
use crate::http_auth::discovery::client_credentials::tasks::subscriptions::watch::resume::{
    ClientCredentialsTaskResumeError as ResumeError,
    ClientCredentialsTaskResumeReconciliation as Reconciliation,
    ClientCredentialsTaskRestartOutcome as RestartOutcome,
    ClientCredentialsTaskRestartPolicy as RestartPolicy,
    TaskResumeBinding, TaskResumeError, TaskResumeRecord,
};

#[derive(Clone, Copy)]
enum ResumeCase {
    Mixed, WrongTask, WrongResponse, Creation, Ttl, Stale, SameTime,
    Malformed, LostBody, ForbiddenDiscovery, ServerError,
    DropRead, CancelRead, CloseOwner, Revoke, Expiry, Deadline, CallerPause,
}
impl ResumeCase {
    fn held_read(self) -> bool {
        matches!(self, Self::DropRead | Self::CancelRead | Self::CloseOwner
            | Self::Revoke | Self::Expiry | Self::Deadline)
    }
}
fn isolated_resume(name: &str, case: ResumeCase) {
    isolated_run(&format!("resume::{name}"), || run_resume(case));
}
fn resume_binding(client: &ClientCredentialsTasksClient) -> TaskResumeBinding {
    let resource = client.client.resource();
    let facts = PartitionDescriptor::from_verified_facts("fixture", 1, "https://issuer.example",
        resource.as_str(), "tenant", "machine-owner", "watch-fixture", 1, 1,
        &[b"bound-resource".as_slice()]).unwrap();
    let owner = DurableOwnerKey::derive(&facts, 1).unwrap();
    TaskResumeBinding::from_verified_owner(resource.clone(), "machine-resume", &owner,
        [1; 32], [2; 32], [3; 32]).unwrap()
}
fn resume_task(id: &str, status: &str, second: u8) -> serde_json::Value {
    let mut value = json!({"taskId":id, "status":status,
        "createdAt":"2020-01-01T00:00:00Z",
        "lastUpdatedAt":format!("2020-01-01T00:00:{second:02}Z"),
        "ttlMs":null, "statusMessage":"PRIVATE-STATUS"});
    match status {
        "input_required" => value["inputRequests"] = json!({"PRIVATE-INPUT":{"method":"roots/list"}}),
        "completed" => value["result"] = json!({"content":[{"type":"text","text":"PRIVATE-RESULT"}]}),
        "failed" => value["error"] = json!({"code":-32603,"message":"PRIVATE-ERROR"}),
        _ => {},
    }
    value
}
fn saved_record(cx: &Cx, owner: &TaskResumeBinding, id: &str) -> TaskResumeRecord {
    let task: Task = serde_json::from_value(resume_task(id, "working", 1)).unwrap();
    let record = TaskResumeRecord::capture(cx, owner, &task, Duration::from_secs(3600)).unwrap();
    let mut bytes = record.encode().unwrap();
    if id == "expired" {
        // Valid but expired host retention, without a scheduling-sensitive sleep.
        let end = bytes.len();
        bytes[end - 16..].copy_from_slice(&1_577_836_802_000_000_000_i128.to_be_bytes());
    }
    TaskResumeRecord::decode(&bytes).unwrap()
}
async fn resume_rpc(peer: &Peer, method: &str) -> (TlsStream<TcpStream>, serde_json::Value) {
    let (socket, request) = peer.rpc(method).await;
    // The common peer checks exact bearer, both profiles and unique IDs.
    assert_eq!(request["params"]["_meta"]["com.example/tenant"], "retained");
    (socket, request)
}
async fn resume_discover(peer: &Peer, refuse: bool) {
    let (mut socket, request) = resume_rpc(peer, "server/discover").await;
    if refuse { status_reply(&mut socket, 403).await; }
    else {
        reply(&mut socket, json!({"jsonrpc":"2.0","id":request["id"],"result":{
            "resultType":"complete","supportedVersions":["2026-07-28"],"ttlMs":0,"cacheScope":"private",
            "capabilities":{"extensions":{TASKS_EXTENSION:{},CLIENT_CREDENTIALS_EXTENSION:{}}}
        }})).await;
    }
}
async fn status_reply(socket: &mut TlsStream<TcpStream>, status: u16) {
    socket.write_all(format!("HTTP/1.1 {status} Refused\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
        .as_bytes()).await.unwrap();
    socket.shutdown().await.unwrap();
}
async fn resume_reply(socket: &mut TlsStream<TcpStream>, request: &serde_json::Value, mut task: serde_json::Value) {
    task["resultType"] = json!("complete");
    reply(socket, json!({"jsonrpc":"2.0","id":request["id"],"result":task})).await;
}
fn mixed_status(id: &str) -> &str {
    match id {
        "work" => "working", "input/é" => "input_required", "complete" => "completed",
        "failed" => "failed", "cancelled" => "cancelled", _ => "working",
    }
}
fn assert_no_payload(record: &TaskResumeRecord) {
    assert!(!record.encode().unwrap().windows(7).any(|part| part == b"PRIVATE"));
}

fn run_resume(case: ResumeCase) {
    runtime().block_on(async {
        let cx = Cx::current().unwrap();
        let scenario = async {
            let peer = Peer::new().await;
            let original_client = peer.client();
            let owner = resume_binding(&original_client);
            let names: &[&str] = if matches!(case, ResumeCase::Mixed) {
                &["work", "input/é", "complete", "failed", "cancelled", "missing", "expired"]
            } else { &["one", "two"] };
            let mut selected: Vec<_> = names.iter().map(|id| saved_record(&cx, &owner, id)).collect();
            selected.sort_by_key(TaskResumeRecord::key);
            let original_bytes: Vec<_> = selected.iter().map(|record| record.encode().unwrap()).collect();
            drop(original_client);
            // Re-establish current machine custody independently of saved bytes.
            let mut client = peer.client();
            Arc::get_mut(&mut client.client.inner).unwrap().timeout = Duration::from_secs(10);
            let current = resume_binding(&client);
            assert_eq!(owner.associated_data(), current.associated_data());
            if matches!(case, ResumeCase::Expiry) {
                let expires_at = Instant::now() + Duration::from_secs(2);
                let bearer = BoundBearerCredential::bind_with_expiry(client.client.resource().clone(),
                    "watched-access", expires_at).unwrap().for_owner(&client.client.inner.closed).unwrap();
                client.client.inner.state.try_lock_owned().unwrap().current = Some(ServiceToken {
                    bearer, scopes: vec![], expires_at, renew_after: expires_at,
                });
            }
            let cancellation = McpRequestCancellation::new();
            let timeout = if matches!(case, ResumeCase::Deadline | ResumeCase::CallerPause) {
                Duration::from_secs(2)
            } else { Duration::from_secs(10) };
            let policy = RestartPolicy::new(16, 65536, timeout).unwrap();
            let mut staged = selected.clone();
            if matches!(case, ResumeCase::Mixed) { staged.push(selected[0].clone()); }
            let mut restart = client.prepare_task_restart_with_cancellation(&cx, &cancellation,
                current.clone(), staged, "restart".to_owned(), policy).unwrap();
            // Creating and abandoning an UNPOLLED read does not consume custody.
            drop(restart.next_reconciled(&cx));
            assert_eq!((restart.remaining(), restart.attempted(), restart.delivered()), (selected.len(), 0, 0));
            assert!(peer.seen.lock().unwrap().is_empty());
            let entered = AtomicBool::new(false);

            let server = async {
                if matches!(case, ResumeCase::Mixed) {
                    for saved in &selected {
                        let id = saved.task_id().as_str();
                        if id == "expired" { continue; }
                        resume_discover(&peer, false).await;
                        let (mut socket, request) = resume_rpc(&peer, "tasks/get").await;
                        assert_eq!(request["params"]["taskId"], id);
                        if id == "missing" { status_reply(&mut socket, 404).await; }
                        else { resume_reply(&mut socket, &request, resume_task(id, mixed_status(id), 2)).await; }
                    }
                    return;
                }
                if matches!(case, ResumeCase::ForbiddenDiscovery) {
                    resume_discover(&peer, true).await;
                    resume_discover(&peer, false).await;
                    let (mut socket, request) = resume_rpc(&peer, "tasks/get").await;
                    assert_eq!(request["params"]["taskId"], selected[1].task_id().as_str());
                    resume_reply(&mut socket, &request, resume_task(selected[1].task_id().as_str(), "completed", 2)).await;
                    return;
                }
                resume_discover(&peer, false).await;
                let (mut socket, mut request) = resume_rpc(&peer, "tasks/get").await;
                let first_id = selected[0].task_id().as_str();
                assert_eq!(request["params"]["taskId"], first_id);
                if case.held_read() {
                    socket.write_all(b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 128\r\n\r\n{").await.unwrap();
                    socket.flush().await.unwrap();
                    entered.store(true, Ordering::SeqCst);
                    closed(&mut socket).await;
                    return;
                }
                if matches!(case, ResumeCase::Malformed | ResumeCase::LostBody) {
                    // The same JSON prefix, differing ONLY in HTTP completeness.
                    let length = if matches!(case, ResumeCase::Malformed) { 1 } else { 128 };
                    socket.write_all(format!("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {length}\r\nConnection: close\r\n\r\n{{")
                        .as_bytes()).await.unwrap();
                    socket.shutdown().await.unwrap();
                    return;
                }
                if matches!(case, ResumeCase::ServerError) { status_reply(&mut socket, 503).await; return; }
                let mut result = resume_task(first_id, "input_required", 2);
                match case {
                    ResumeCase::WrongTask => result["taskId"] = json!("foreign-task"),
                    ResumeCase::WrongResponse => request["id"] = json!("foreign-request"),
                    ResumeCase::Creation => result["createdAt"] = json!("2019-01-01T00:00:00Z"),
                    ResumeCase::Ttl => result["ttlMs"] = json!(60000),
                    ResumeCase::Stale => result["lastUpdatedAt"] = json!("2020-01-01T00:00:00Z"),
                    ResumeCase::SameTime => result["lastUpdatedAt"] = json!("2020-01-01T00:00:01Z"),
                    ResumeCase::CallerPause => {},
                    _ => unreachable!(),
                }
                resume_reply(&mut socket, &request, result).await;
            };

            let application = async {
                if matches!(case, ResumeCase::Mixed) {
                    for (index, saved) in selected.iter().enumerate() {
                        let item = Box::pin(restart.next_reconciled(&cx)).await.unwrap().unwrap();
                        assert_eq!(&item.previous, saved);
                        let id = saved.task_id().as_str();
                        match &item.outcome {
                            RestartOutcome::Unavailable => assert!(matches!(id, "expired" | "missing")),
                            RestartOutcome::Reconciled(Reconciliation::Active { task, record }) => {
                                assert!(matches!(id, "work" | "input/é"));
                                assert_eq!(task.base().task_id, *saved.task_id());
                                assert_eq!(serde_json::to_value(&**task).unwrap()["status"], mixed_status(id));
                                assert_no_payload(record);
                                assert_eq!(record.key(), saved.key());
                                assert_eq!(item.storage_change(&cx, &current).unwrap().replacement(), Some(record));
                            }
                            RestartOutcome::Reconciled(Reconciliation::Terminal(task)) => {
                                assert!(matches!(id, "complete" | "failed" | "cancelled"));
                                assert_eq!(serde_json::to_value(&**task).unwrap()["status"], mixed_status(id));
                                assert_eq!(task.base().task_id, *saved.task_id());
                            }
                        }
                        let change = item.storage_change(&cx, &current).unwrap();
                        assert_eq!(change.previous(), saved);
                        assert_no_payload(change.previous());
                        assert_eq!(change.replacement().is_none(), !matches!(id, "work" | "input/é"));
                        assert_eq!(restart.delivered(), index + 1);
                    }
                    assert_eq!((restart.remaining(), restart.attempted(), restart.delivered()), (0, 6, 7));
                    client.client.close();
                    assert!(Box::pin(restart.next_reconciled(&cx)).await.unwrap().is_none());
                    return;
                }
                if matches!(case, ResumeCase::ForbiddenDiscovery) {
                    let item = Box::pin(restart.next_reconciled(&cx)).await.unwrap().unwrap();
                    assert_eq!(item.previous, selected[0]);
                    assert!(matches!(item.outcome, RestartOutcome::Unavailable));
                    assert!(item.storage_change(&cx, &current).unwrap().replacement().is_none());
                    let item = Box::pin(restart.next_reconciled(&cx)).await.unwrap().unwrap();
                    assert_eq!(item.previous, selected[1]);
                    assert!(matches!(item.outcome, RestartOutcome::Reconciled(Reconciliation::Terminal(task))
                        if matches!(*task, Task::Completed { .. })));
                    assert_eq!((restart.remaining(), restart.attempted(), restart.delivered()), (0, 2, 2));
                    assert!(Box::pin(restart.next_reconciled(&cx)).await.unwrap().is_none());
                    return;
                }
                if matches!(case, ResumeCase::CallerPause) {
                    let item = Box::pin(restart.next_reconciled(&cx)).await.unwrap().unwrap();
                    assert_eq!(item.previous, selected[0]);
                    assert!(matches!(item.outcome, RestartOutcome::Reconciled(Reconciliation::Active { .. })));
                    asupersync::time::Sleep::new(cx.now().saturating_add_nanos(3_000_000_000)).await;
                    assert!(matches!(Box::pin(restart.next_reconciled(&cx)).await,
                        Err(ResumeError::Task(ClientCredentialsTasksError::Authentication(
                            ClientCredentialsError::Discovery(OAuthDiscoveryError::TimedOut))))));
                    assert_eq!((restart.remaining(), restart.attempted(), restart.delivered()), (1, 1, 1));
                    assert!(restart.pending_record().is_none());
                    assert_eq!(restart.unvisited().next().unwrap(), &selected[1]);
                    assert!(matches!(Box::pin(restart.next_reconciled(&cx)).await, Err(ResumeError::Closed)));
                    return;
                }
                let mut reading = Box::pin(restart.next_reconciled(&cx));
                if case.held_read() {
                    poll_fn(|cx| {
                        assert!(reading.as_mut().poll(cx).is_pending());
                        if entered.load(Ordering::SeqCst) { Poll::Ready(()) }
                        else { cx.waker().wake_by_ref(); Poll::Pending }
                    }).await;
                }
                if matches!(case, ResumeCase::DropRead) { drop(reading); }
                else {
                    match case {
                        ResumeCase::CancelRead => {
                            cancellation.cancel();
                        }
                        ResumeCase::CloseOwner => client.client.close(),
                        ResumeCase::Revoke => client.client.inner.state.try_lock_owned().unwrap()
                            .current.as_ref().unwrap().bearer.revoke(),
                        _ => {},
                    }
                    let error = reading.await.err().expect("failed restart must not invent a current Task");
                    assert!(!format!("{error:?} {error}").contains("PRIVATE"));
                    match (case, error) {
                        (ResumeCase::WrongTask, ResumeError::Task(ClientCredentialsTasksError::Protocol(ManagedTasksError::TaskIdMismatch))) => {},
                        (ResumeCase::WrongResponse, ResumeError::Task(ClientCredentialsTasksError::Protocol(ManagedTasksError::ResponseIdMismatch))) => {},
                        (ResumeCase::Creation | ResumeCase::Ttl | ResumeCase::SameTime, ResumeError::Resume(TaskResumeError::ConflictingSnapshot)) => {},
                        (ResumeCase::Stale, ResumeError::Resume(TaskResumeError::StaleSnapshot)) => {},
                        (ResumeCase::Malformed, ResumeError::Task(ClientCredentialsTasksError::Protocol(ManagedTasksError::InvalidResponse))) => {},
                        (ResumeCase::LostBody, ResumeError::Task(ClientCredentialsTasksError::Protocol(ManagedTasksError::MissingTerminal))) => {},
                        (ResumeCase::ServerError, ResumeError::Task(ClientCredentialsTasksError::Protocol(ManagedTasksError::HttpStatus { status: 503 }))) => {},
                        (ResumeCase::CancelRead, ResumeError::Task(ClientCredentialsTasksError::Authentication(ClientCredentialsError::Discovery(OAuthDiscoveryError::Cancelled)))) => {},
                        (ResumeCase::CloseOwner, ResumeError::Task(ClientCredentialsTasksError::Authentication(ClientCredentialsError::Closed))) => {},
                        (ResumeCase::Revoke, ResumeError::Task(ClientCredentialsTasksError::Authentication(ClientCredentialsError::Expired))) => {},
                        (ResumeCase::Expiry, ResumeError::Task(ClientCredentialsTasksError::Authentication(
                            ClientCredentialsError::Expired | ClientCredentialsError::Discovery(OAuthDiscoveryError::TimedOut)))) => {},
                        (ResumeCase::Deadline, ResumeError::Task(ClientCredentialsTasksError::Authentication(ClientCredentialsError::Discovery(OAuthDiscoveryError::TimedOut)))) => {},
                        (_, error) => panic!("unexpected restart refusal: {error:?}"),
                    }
                }
                assert_eq!((restart.remaining(), restart.attempted(), restart.delivered()), (2, 1, 0));
                assert_eq!(restart.pending_record().unwrap(), &selected[0]);
                assert!(restart.pending_outcome().is_none());
                assert_eq!(restart.unvisited().next().unwrap(), &selected[1]);
                assert!(matches!(Box::pin(restart.next_reconciled(&cx)).await, Err(ResumeError::Closed)));
                let (pending, outcome) = restart.take_pending().unwrap();
                assert_eq!(pending, selected[0]);
                assert!(outcome.is_none());
                assert_eq!(restart.remaining(), 1);
                assert!(matches!(Box::pin(restart.next_reconciled(&cx)).await, Err(ResumeError::Closed)));
            };
            Box::pin(pair(server, application)).await;
            assert_eq!(selected.iter().map(|record| record.encode().unwrap()).collect::<Vec<_>>(), original_bytes);
            let ids: Vec<usize> = match case {
                ResumeCase::Mixed => (0..12).collect(),
                ResumeCase::ForbiddenDiscovery => vec![0, 2, 3],
                _ => vec![0, 1],
            };
            let expected: BTreeSet<_> = ids.into_iter().map(|id| format!("restart:{id}")).collect();
            assert_eq!(*peer.seen.lock().unwrap(), expected);
            assert_eq!(peer.updates.load(Ordering::SeqCst), 0);
            assert_eq!(cancellation.is_cancel_requested(), matches!(case, ResumeCase::CancelRead));
            assert_eq!(client.client.inner.closed.is_cancel_requested(), matches!(case, ResumeCase::Mixed | ResumeCase::CloseOwner));
            peer.quiet();
        };
        asupersync::time::timeout_at(cx.now().saturating_add_nanos(20_000_000_000), Box::pin(scenario)).await.unwrap();
    });
}

#[test]
fn tls_machine_restart_reconciles_mixed_records_without_mutation_or_subscription() { isolated_resume("tls_machine_restart_reconciles_mixed_records_without_mutation_or_subscription", ResumeCase::Mixed); }
#[test]
fn tls_machine_restart_rejects_a_foreign_task() { isolated_resume("tls_machine_restart_rejects_a_foreign_task", ResumeCase::WrongTask); }
#[test]
fn tls_machine_restart_rejects_a_foreign_response_id() { isolated_resume("tls_machine_restart_rejects_a_foreign_response_id", ResumeCase::WrongResponse); }
#[test]
fn tls_machine_restart_rejects_reused_task_creation_identity() { isolated_resume("tls_machine_restart_rejects_reused_task_creation_identity", ResumeCase::Creation); }
#[test]
fn tls_machine_restart_rejects_changed_ttl() { isolated_resume("tls_machine_restart_rejects_changed_ttl", ResumeCase::Ttl); }
#[test]
fn tls_machine_restart_rejects_regressed_snapshots() { isolated_resume("tls_machine_restart_rejects_regressed_snapshots", ResumeCase::Stale); }
#[test]
fn tls_machine_restart_rejects_conflicting_same_time_status() { isolated_resume("tls_machine_restart_rejects_conflicting_same_time_status", ResumeCase::SameTime); }
#[test]
fn tls_machine_restart_preserves_complete_malformed_response_failure() { isolated_resume("tls_machine_restart_preserves_complete_malformed_response_failure", ResumeCase::Malformed); }
#[test]
fn tls_machine_restart_retains_lost_read_without_retrying() { isolated_resume("tls_machine_restart_retains_lost_read_without_retrying", ResumeCase::LostBody); }
#[test]
fn tls_machine_restart_can_continue_after_explicit_unavailable_discovery() { isolated_resume("tls_machine_restart_can_continue_after_explicit_unavailable_discovery", ResumeCase::ForbiddenDiscovery); }
#[test]
fn tls_machine_restart_server_failure_cannot_skip_to_the_next_record() { isolated_resume("tls_machine_restart_server_failure_cannot_skip_to_the_next_record", ResumeCase::ServerError); }
#[test]
fn tls_machine_restart_abandoned_response_keeps_pending_and_unvisited_records() { isolated_resume("tls_machine_restart_abandoned_response_keeps_pending_and_unvisited_records", ResumeCase::DropRead); }
#[test]
fn tls_machine_restart_local_cancel_releases_only_its_read() { isolated_resume("tls_machine_restart_local_cancel_releases_only_its_read", ResumeCase::CancelRead); }
#[test]
fn tls_machine_restart_owner_close_ends_pending_response() { isolated_resume("tls_machine_restart_owner_close_ends_pending_response", ResumeCase::CloseOwner); }
#[test]
fn tls_machine_restart_revocation_cannot_become_unavailable_or_retry() { isolated_resume("tls_machine_restart_revocation_cannot_become_unavailable_or_retry", ResumeCase::Revoke); }
#[test]
fn tls_machine_restart_credential_expiry_stops_the_original_read() { isolated_resume("tls_machine_restart_credential_expiry_stops_the_original_read", ResumeCase::Expiry); }
#[test]
fn tls_machine_restart_deadline_drops_pending_response_without_skipping() { isolated_resume("tls_machine_restart_deadline_drops_pending_response_without_skipping", ResumeCase::Deadline); }
#[test]
fn tls_machine_restart_caller_pause_does_not_reset_the_deadline() { isolated_resume("tls_machine_restart_caller_pause_does_not_reset_the_deadline", ResumeCase::CallerPause); }
