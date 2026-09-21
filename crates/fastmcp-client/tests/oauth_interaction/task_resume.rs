//! Public checkpoint reconciliation through the existing real OAuth/TLS peer.
//! Run oauth_interaction with tasks,native-tls-roots. These cases qualify the
//! read-only client boundary, not a durable encryption provider or file store.
use super::*;
use fastmcp_core::partition::{DurableOwnerKey, PartitionDescriptor};
use fastmcp_client::http_auth::managed::OAuthSessionError;
use fastmcp_client::http_auth::managed::tasks::{
    ManagedTaskRequestIds, ManagedTasksClient, ManagedTasksError, ManagedTasksLimits,
};
use fastmcp_client::http_auth::managed::tasks::watch::checkpoint::resume::{
    TaskResumeBinding, TaskResumeError, TaskResumeRecord,
};
use fastmcp_client::http_auth::managed::tasks::watch::checkpoint::resume::client::{
    TaskResumeReconciliation, TaskResumeReconciliationError,
};
use fastmcp_protocol::{ClientCapabilities, FinalRequestMeta};
use fastmcp_protocol::tasks_extension::Task;

const CASE_ENV: &str = "FASTMCP_TEST_TASK_RESUME_RECONCILIATION";
const DISCOVER: &str = r#"{"resultType":"complete","supportedVersions":["2026-07-28"],"capabilities":{"tools":{},"extensions":{"io.modelcontextprotocol/tasks":{}}},"ttlMs":0,"cacheScope":"private"}"#;

#[derive(Clone, Copy)]
enum Case { Active, Terminal, GetUnavailable, DiscoveryUnavailable, ForeignTask,
    ChangedBirth, Regressed, Cancel, Drop, Expired, WrongOwner, WrongEndpoint }

fn isolated(name: &str, case: Case) {
    let exact = format!("driver::task_resume::{name}");
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
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        if let Some(status) = child.0.try_wait().unwrap() {
            assert!(status.success(), "Task resume HTTPS case failed");
            return;
        }
        assert!(Instant::now() < deadline, "Task resume HTTPS child exceeded its bound");
        std::thread::sleep(Duration::from_millis(10));
    }
}

fn binding(resource: &str, subject: &str) -> TaskResumeBinding {
    // Fixture-authenticated account facts. No peer checkpoint supplies any of
    // these fields, and the production binding constructor accepts a typed key.
    let descriptor = PartitionDescriptor::from_verified_facts(
        "fixture-provider", 1, "https://issuer.example", resource, "fixture-tenant",
        subject, "interaction-client", 1, 1, &[b"resource-bound".as_slice()],
    ).unwrap();
    let owner = DurableOwnerKey::derive(&descriptor, 1).unwrap();
    TaskResumeBinding::from_verified_owner(url(resource), "fixture", &owner,
        [2; 32], [3; 32], [4; 32]).unwrap()
}

fn working() -> Task {
    // Null remote TTL and finite local capture retention avoid making these
    // tests expire when the calendar passes a hard-coded fixture date.
    serde_json::from_value(json!({"taskId":"checkpoint task", "status":"working",
        "createdAt":"2020-01-01T00:00:00Z", "lastUpdatedAt":"2020-01-01T00:00:01Z",
        "ttlMs":null, "pollIntervalMs":10})).unwrap()
}
async fn reject(tls: &mut TlsStream<TcpStream>, status: u16) {
    tls.write_all(format!("HTTP/1.1 {status} Unavailable\r\nContent-Length: 0\r\nConnection: close\r\n\r\n").as_bytes()).await.unwrap();
    tls.flush().await.unwrap();
}

fn run(case: Case) {
    RuntimeBuilder::current_thread().with_reactor(create_reactor().unwrap()).build().unwrap().block_on(Box::pin(async {
        let cx = Cx::current().unwrap();
        let scenario = Box::pin(async {
            let peer = Peer::new().await;
            let ((), login) = pair(Box::pin(peer.login()), Box::pin(ManagedOAuthSession::authorize(
                &cx, peer.client(), OAuthSessionPolicy::default(), browser,
            ))).await;
            let session = login.unwrap();
            let client = ManagedTasksClient::new(session.clone(), FinalRequestMeta::new(ClientCapabilities::default()),
                ManagedTasksLimits::new(65536, 65536, 16, Duration::from_secs(15)).unwrap()).unwrap();
            let resource = if matches!(case, Case::WrongEndpoint) { format!("{}/other", peer.resource()) } else { peer.resource() };
            let stored_binding = binding(&resource, "owner");
            let current_binding = if matches!(case, Case::WrongOwner) { binding(&resource, "another-owner") } else { stored_binding.clone() };
            let retention = if matches!(case, Case::Expired) { Duration::from_nanos(1) } else { Duration::from_secs(60) };
            let saved = TaskResumeRecord::capture(&cx, &stored_binding, &working(), retention).unwrap();
            // Exercise the actual public record codec before reconciliation.
            let encoded = saved.encode().unwrap();
            let record = TaskResumeRecord::decode(&encoded).unwrap();
            if matches!(case, Case::Expired) { Sleep::new(cx.now().saturating_add_nanos(1_000_000)).await; }
            let cancellation = McpRequestCancellation::new();
            let (accepted_tx, mut accepted_rx) = oneshot::channel::<()>();
            let server = Box::pin(async {
                if matches!(case, Case::Expired | Case::WrongOwner | Case::WrongEndpoint) { return 0; }
                let (mut discovery_socket, bytes) = peer.request(false).await;
                let discovery: Value = serde_json::from_slice(&bytes).unwrap();
                assert_eq!(discovery["id"], 41);
                assert_eq!(discovery["method"], "server/discover");
                assert!(discovery["params"].get("taskId").is_none());
                if matches!(case, Case::DiscoveryUnavailable) {
                    reject(&mut discovery_socket, 401).await;
                    return 1;
                }
                json_reply(&mut discovery_socket, &terminal(41, DISCOVER)).await;
                drop(discovery_socket);
                let (mut socket, bytes) = peer.request(false).await;
                let get: Value = serde_json::from_slice(&bytes).unwrap();
                assert_eq!(get["id"], 42);
                assert_eq!(get["method"], "tasks/get", "resume never repeats tools/call");
                assert_eq!(get["params"]["taskId"], "checkpoint task");
                assert_eq!(get["params"]["_meta"], discovery["params"]["_meta"]);
                assert!(get["params"].get("inputResponses").is_none());
                assert!(get["params"].get("requestState").is_none());
                if matches!(case, Case::GetUnavailable) {
                    reject(&mut socket, 403).await;
                    return 2;
                }
                if matches!(case, Case::Cancel | Case::Drop) {
                    accepted_tx.send(&cx, ()).unwrap();
                    let mut byte = [0; 1];
                    match socket.read(&mut byte).await {
                        Ok(0) | Err(_) => {},
                        Ok(_) => panic!("abandoned checkpoint read retained or reused its socket"),
                    }
                    return 2;
                }
                let mut task = json!({"resultType":"complete","taskId":"checkpoint task","status":"input_required",
                    "createdAt":"2020-01-01T00:00:00Z","lastUpdatedAt":"2020-01-01T00:00:02Z",
                    "ttlMs":null,"pollIntervalMs":20,"inputRequests":{"PRIVATE-INPUT":{"method":"roots/list"}}});
                match case {
                    Case::Terminal => {
                        task["status"] = json!("completed");
                        task.as_object_mut().unwrap().remove("inputRequests");
                        task["result"] = json!({"content":[],"structuredContent":{"PRIVATE-RESULT":42}});
                    }
                    Case::ForeignTask => task["taskId"] = json!("another task"),
                    Case::ChangedBirth => task["createdAt"] = json!("2019-01-01T00:00:00Z"),
                    Case::Regressed => task["lastUpdatedAt"] = json!("2020-01-01T00:00:00Z"),
                    _ => {},
                }
                json_reply(&mut socket, &terminal(42, &task.to_string())).await;
                2
            });
            let consumer = Box::pin(async {
                let ids = ManagedTaskRequestIds::new(RequestId::Number(41), RequestId::Number(42)).unwrap();
                let mut read = Box::pin(client.reconcile_task_resume_with_cancellation(
                    &cx, &cancellation, &current_binding, &record, ids,
                ));
                if matches!(case, Case::Drop) {
                    let mut accepted = Box::pin(accepted_rx.recv(&cx));
                    poll_fn(|task| {
                        assert!(read.as_mut().poll(task).is_pending());
                        match accepted.as_mut().poll(task) {
                            Poll::Ready(value) => { value.unwrap(); Poll::Ready(()) }
                            Poll::Pending => Poll::Pending,
                        }
                    }).await;
                    drop(read);
                    return None;
                }
                if matches!(case, Case::Cancel) {
                    let cancel = Box::pin(async {
                        accepted_rx.recv(&cx).await.unwrap();
                        cancellation.cancel();
                    });
                    let (result, ()) = pair(read, cancel).await;
                    Some(result)
                } else { Some(read.await) }
            });
            let (posts, result) = pair(server, consumer).await;
            match case {
                Case::Active => {
                    let TaskResumeReconciliation::Active { task, record: refreshed, selection } = result.unwrap().unwrap() else { panic!("fresh active state required") };
                    assert!(matches!(*task, Task::InputRequired { .. }));
                    assert_eq!(refreshed.key(), record.key());
                    assert_eq!(selection.resource().as_str(), peer.resource());
                    assert_eq!(selection.task_ids(), [record.task_id().clone()]);
                    assert!(!refreshed.encode().unwrap().windows(7).any(|part| part == b"PRIVATE"));
                }
                Case::Terminal => {
                    let TaskResumeReconciliation::Terminal(task) = result.unwrap().unwrap() else { panic!("fresh terminal state required") };
                    assert!(matches!(*task, Task::Completed { .. }));
                    assert!(matches!(TaskResumeRecord::capture(&cx, &current_binding, &task, Duration::from_secs(60)), Err(TaskResumeError::NotResumable)));
                }
                Case::GetUnavailable | Case::DiscoveryUnavailable | Case::Expired | Case::WrongOwner | Case::WrongEndpoint => {
                    assert!(matches!(result.unwrap(), Err(TaskResumeReconciliationError::Resume(TaskResumeError::Unavailable))));
                }
                Case::ForeignTask => {
                    assert!(matches!(result.unwrap(), Err(TaskResumeReconciliationError::Task(ManagedTasksError::TaskIdMismatch))));
                }
                Case::ChangedBirth => {
                    assert!(matches!(result.unwrap(), Err(TaskResumeReconciliationError::Resume(TaskResumeError::ConflictingSnapshot))));
                }
                Case::Regressed => {
                    assert!(matches!(result.unwrap(), Err(TaskResumeReconciliationError::Resume(TaskResumeError::StaleSnapshot))));
                }
                Case::Cancel => {
                    assert!(matches!(result.unwrap(), Err(TaskResumeReconciliationError::Task(ManagedTasksError::Session(OAuthSessionError::Cancelled)))));
                }
                Case::Drop => assert!(result.is_none()),
            }
            assert_eq!(record.encode().unwrap(), encoded, "reconciliation cannot mutate stored custody");
            assert_eq!(peer.posts.load(Ordering::SeqCst), posts);
            assert_eq!(peer.tokens.load(Ordering::SeqCst), 1);
            assert_eq!(cancellation.is_cancel_requested(), matches!(case, Case::Cancel));
            assert!(cx.checkpoint().is_ok());
            peer.quiet();
            session.close();
        });
        Box::pin(asupersync::time::timeout_at(cx.now().saturating_add_nanos(20_000_000_000), scenario)).await
            .expect("Task resume fixture must settle within its bound");
    }));
}

#[test]
fn restored_record_yields_fresh_input_state_and_existing_watch_selection() { isolated("restored_record_yields_fresh_input_state_and_existing_watch_selection", Case::Active); }
#[test]
fn completion_after_checkpoint_returns_result_without_persisting_it() { isolated("completion_after_checkpoint_returns_result_without_persisting_it", Case::Terminal); }
#[test]
fn unavailable_get_is_not_retried_or_recreated() { isolated("unavailable_get_is_not_retried_or_recreated", Case::GetUnavailable); }
#[test]
fn rejected_discovery_never_sends_task_id() { isolated("rejected_discovery_never_sends_task_id", Case::DiscoveryUnavailable); }
#[test]
fn foreign_task_response_cannot_replace_checkpoint_identity() { isolated("foreign_task_response_cannot_replace_checkpoint_identity", Case::ForeignTask); }
#[test]
fn reused_task_id_with_changed_creation_is_rejected() { isolated("reused_task_id_with_changed_creation_is_rejected", Case::ChangedBirth); }
#[test]
fn regressed_remote_snapshot_does_not_replace_saved_controls() { isolated("regressed_remote_snapshot_does_not_replace_saved_controls", Case::Regressed); }
#[test]
fn cancelled_resume_closes_its_socket_without_mutation() { isolated("cancelled_resume_closes_its_socket_without_mutation", Case::Cancel); }
#[test]
fn abandoned_resume_closes_its_socket_without_changing_record() { isolated("abandoned_resume_closes_its_socket_without_changing_record", Case::Drop); }
#[test]
fn expired_record_is_rejected_without_contacting_peer() { isolated("expired_record_is_rejected_without_contacting_peer", Case::Expired); }
#[test]
fn wrong_current_owner_is_rejected_before_discovery() { isolated("wrong_current_owner_is_rejected_before_discovery", Case::WrongOwner); }
#[test]
fn wrong_selected_endpoint_is_rejected_before_discovery() { isolated("wrong_selected_endpoint_is_rejected_before_discovery", Case::WrongEndpoint); }
