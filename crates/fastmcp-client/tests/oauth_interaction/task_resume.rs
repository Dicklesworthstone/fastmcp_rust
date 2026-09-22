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

mod restart {
    use super::*;
    use fastmcp_protocol::tasks_extension::TaskId;
    use fastmcp_client::http_auth::managed::tasks::watch::checkpoint::resume::client::restart::{
        TaskResumeRestartError, TaskResumeRestartOutcome, TaskResumeRestartPlan, TaskResumeRestartPolicy,
    };

    const RESTART_ENV: &str = "FASTMCP_TEST_TASK_RESTART";
    #[derive(Clone, Copy)]
    enum RestartCase {
        Mixed, Duplicate, Expired, Unavailable(u16), DiscoveryDenied,
        ForeignTask, LostReply, Cancel, DropRead, Deadline, SessionClose,
        WrongOwner, WrongEndpoint, Precancel, Empty,
    }

    fn isolated_restart(name: &str, case: RestartCase) {
        let exact = format!("driver::task_resume::restart::{name}");
        if let Ok(selected) = std::env::var(RESTART_ENV) {
            assert_eq!(selected, exact);
            run_restart(case);
            return;
        }
        let roots = RootFile::create();
        struct Child(std::process::Child);
        impl Drop for Child {
            fn drop(&mut self) { let _ = self.0.kill(); let _ = self.0.wait(); }
        }
        let mut child = Child(Command::new(std::env::current_exe().unwrap())
            .args(["--exact", &exact, "--nocapture", "--test-threads=1"])
            .env(RESTART_ENV, &exact).env("SSL_CERT_FILE", &roots.0).env_remove("SSL_CERT_DIR")
            .stdin(Stdio::null()).stdout(Stdio::inherit()).stderr(Stdio::inherit()).spawn().unwrap());
        let deadline = Instant::now() + Duration::from_secs(30);
        loop {
            if let Some(status) = child.0.try_wait().unwrap() {
                assert!(status.success(), "Task restart HTTPS case failed");
                return;
            }
            assert!(Instant::now() < deadline, "Task restart child exceeded its bound");
            std::thread::sleep(Duration::from_millis(10));
        }
    }

    fn source_records(cx: &Cx, current: &TaskResumeBinding) -> Vec<TaskResumeRecord> {
        let mut records: Vec<_> = ["one", "two", "three"].into_iter().map(|suffix| {
            let mut task = working();
            if let Task::Working(base) = &mut task {
                base.task_id = TaskId::parse(format!("restart-{suffix}")).unwrap();
            }
            TaskResumeRecord::capture(cx, current, &task, Duration::from_secs(120)).unwrap()
        }).collect();
        records.sort_by_key(TaskResumeRecord::key);
        records
    }
    fn response(number: usize, result: Value) -> String {
        json!({"jsonrpc":"2.0", "id":format!("restart:{number}"), "result":result}).to_string()
    }
    async fn exact_request(peer: &Peer, number: usize, method: &str) -> (TlsStream<TcpStream>, Value) {
        let (socket, bytes) = peer.request(false).await;
        let request: Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(request["id"], format!("restart:{number}"));
        assert_eq!(request["method"], method);
        assert!(matches!(method, "server/discover" | "tasks/get"), "restart cannot mutate, poll or subscribe");
        assert!(request["params"].get("inputResponses").is_none());
        assert!(request["params"].get("requestState").is_none());
        // The shared peer also asserts exact bearer and method/version routing.
        (socket, request)
    }

    fn run_restart(case: RestartCase) {
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
                let resource = if matches!(case, RestartCase::WrongEndpoint) { format!("{}/other", peer.resource()) } else { peer.resource() };
                let stored_binding = binding(&resource, "owner");
                let current = if matches!(case, RestartCase::WrongOwner) { binding(&resource, "other") } else { stored_binding.clone() };
                let mut records = source_records(&cx, &stored_binding);
                if matches!(case, RestartCase::Empty) { records.clear(); }
                if matches!(case, RestartCase::Expired) {
                    let mut bytes = records[0].encode().unwrap();
                    let start = bytes.len() - 16;
                    bytes[start..].copy_from_slice(&1_577_836_802_000_000_000_i128.to_be_bytes());
                    records[0] = TaskResumeRecord::decode(&bytes).unwrap();
                }
                let source: Vec<_> = records.iter().map(|record| record.encode().unwrap()).collect();
                let mut import = records.clone();
                if matches!(case, RestartCase::Duplicate) { import.push(records[0].clone()); }
                let timeout = if matches!(case, RestartCase::Deadline) { Duration::from_secs(3) } else { Duration::from_secs(15) };
                let policy = TaskResumeRestartPolicy::new(8, 65536, timeout).unwrap();
                let plan = TaskResumeRestartPlan::from_records(&cx, &stored_binding, import, policy).unwrap();
                assert_eq!(plan.len(), records.len());
                assert_eq!(plan.charged_records(), records.len() + usize::from(matches!(case, RestartCase::Duplicate)));
                let cancellation = McpRequestCancellation::new();
                if matches!(case, RestartCase::Precancel) { cancellation.cancel(); }
                let prepared = client.prepare_task_restart_with_cancellation(&cx, &cancellation, current, plan, "restart".to_owned());
                if matches!(case, RestartCase::WrongOwner | RestartCase::WrongEndpoint | RestartCase::Precancel) {
                    match case {
                        RestartCase::Precancel => assert!(matches!(prepared, Err(TaskResumeRestartError::Session(OAuthSessionError::Cancelled)))),
                        _ => assert!(matches!(prepared, Err(TaskResumeRestartError::Resume(TaskResumeError::Unavailable)))),
                    }
                    assert_eq!(peer.posts.load(Ordering::SeqCst), 0);
                    assert_eq!(peer.tokens.load(Ordering::SeqCst), 1);
                    peer.quiet();
                    session.close();
                    return;
                }
                let mut owner = prepared.unwrap();
                // Preparation and an unpolled read have no transport effects.
                drop(Box::pin(owner.next_reconciled(&cx)));
                assert_eq!(owner.remaining(), records.len());
                assert_eq!(owner.attempted(), 0);
                assert_eq!(owner.delivered(), 0);
                assert!(owner.pending_record().is_none());
                assert_eq!(peer.posts.load(Ordering::SeqCst), 0);
                let (entered_tx, mut entered_rx) = oneshot::channel::<()>();
                let server = Box::pin(async {
                    let mut calls = 0;
                    let mut posts = 0;
                    for (index, record) in records.iter().enumerate() {
                        if index == 0 && matches!(case, RestartCase::Expired) { continue; }
                        if index == 1 && matches!(case, RestartCase::Deadline | RestartCase::SessionClose) { return posts; }
                        let discovery_id = calls * 2;
                        calls += 1;
                        let (mut socket, discovered) = exact_request(&peer, discovery_id, "server/discover").await;
                        posts += 1;
                        assert!(discovered["params"].get("taskId").is_none());
                        if index == 0 && matches!(case, RestartCase::DiscoveryDenied) {
                            reject(&mut socket, 401).await;
                            continue;
                        }
                        json_reply(&mut socket, &response(discovery_id, serde_json::from_str(DISCOVER).unwrap())).await;
                        drop(socket);
                        let (mut socket, get) = exact_request(&peer, discovery_id + 1, "tasks/get").await;
                        posts += 1;
                        assert_eq!(get["params"]["taskId"], record.task_id().as_str());
                        assert_eq!(get["params"]["_meta"], discovered["params"]["_meta"]);
                        if index == 0 {
                            if let RestartCase::Unavailable(status) = case {
                                reject(&mut socket, status).await;
                                continue;
                            }
                        }
                        if index == 1 && matches!(case, RestartCase::Cancel | RestartCase::DropRead) {
                            entered_tx.send(&cx, ()).unwrap();
                            let mut byte = [0; 1];
                            assert!(!matches!(socket.read(&mut byte).await, Ok(count) if count > 0), "interrupted read must close its socket");
                            return posts;
                        }
                        if index == 1 && matches!(case, RestartCase::LostReply) {
                            socket.write_all(b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 128\r\nConnection: close\r\n\r\n{\"jsonrpc\":").await.unwrap();
                            socket.flush().await.unwrap();
                            return posts;
                        }
                        let mut value = json!({"resultType":"complete", "taskId":record.task_id().as_str(),
                            "status":"input_required", "createdAt":"2020-01-01T00:00:00Z",
                            "lastUpdatedAt":"2020-01-01T00:00:02Z", "ttlMs":null, "pollIntervalMs":20,
                            "inputRequests":{"PRIVATE-INPUT":{"method":"roots/list"}}});
                        if index == 1 {
                            value["status"] = json!("completed");
                            value.as_object_mut().unwrap().remove("inputRequests");
                            value["result"] = json!({"content":[{"type":"text","text":"PRIVATE-RESULT"}]});
                        }
                        if index == 1 && matches!(case, RestartCase::ForeignTask) { value["taskId"] = json!("another-task"); }
                        json_reply(&mut socket, &response(discovery_id + 1, value)).await;
                        if index == 1 && matches!(case, RestartCase::ForeignTask) { return posts; }
                    }
                    posts
                });
                let consumer = Box::pin(async {
                    for (index, previous) in records.iter().enumerate() {
                        if index == 1 && matches!(case, RestartCase::Deadline) {
                            Sleep::new(cx.now().saturating_add_nanos(3_100_000_000)).await;
                        }
                        if index == 1 && matches!(case, RestartCase::SessionClose) { session.close(); }
                        let mut reading = Box::pin(owner.next_reconciled(&cx));
                        let result = if index == 1 && matches!(case, RestartCase::DropRead) {
                            let mut entered = Box::pin(entered_rx.recv(&cx));
                            poll_fn(|task| {
                                assert!(reading.as_mut().poll(task).is_pending());
                                match entered.as_mut().poll(task) {
                                    Poll::Ready(value) => { value.unwrap(); Poll::Ready(()) }
                                    Poll::Pending => Poll::Pending,
                                }
                            }).await;
                            drop(reading);
                            None
                        } else if index == 1 && matches!(case, RestartCase::Cancel) {
                            let cancel = Box::pin(async { entered_rx.recv(&cx).await.unwrap(); cancellation.cancel(); });
                            let (result, ()) = pair(reading, cancel).await;
                            Some(result)
                        } else { Some(reading.await) };
                        if index == 1 && matches!(case, RestartCase::ForeignTask | RestartCase::LostReply |
                            RestartCase::Cancel | RestartCase::DropRead | RestartCase::Deadline | RestartCase::SessionClose)
                        {
                            match case {
                                RestartCase::ForeignTask => assert!(matches!(result.unwrap(), Err(TaskResumeRestartError::Reconciliation(
                                    TaskResumeReconciliationError::Task(ManagedTasksError::TaskIdMismatch))))),
                                RestartCase::LostReply => assert!(matches!(result.unwrap(), Err(TaskResumeRestartError::Reconciliation(
                                    TaskResumeReconciliationError::Task(ManagedTasksError::Session(OAuthSessionError::Http(_))))))),
                                RestartCase::Cancel => assert!(matches!(result.unwrap(), Err(TaskResumeRestartError::Session(OAuthSessionError::Cancelled)))),
                                RestartCase::Deadline => assert!(matches!(result.unwrap(), Err(TaskResumeRestartError::Session(OAuthSessionError::TimedOut)))),
                                RestartCase::SessionClose => assert!(matches!(result.unwrap(), Err(TaskResumeRestartError::Session(OAuthSessionError::Closed)))),
                                _ => assert!(result.is_none()),
                            }
                            assert_eq!(owner.remaining(), 2);
                            assert_eq!(owner.delivered(), 1);
                            let before_read = matches!(case, RestartCase::Deadline | RestartCase::SessionClose);
                            assert_eq!(owner.attempted(), if before_read { 1 } else { 2 });
                            assert_eq!(owner.unvisited().count(), if before_read { 2 } else { 1 });
                            assert!(owner.pending_outcome().is_none());
                            if before_read { assert!(owner.pending_record().is_none()); }
                            else {
                                assert_eq!(owner.pending_record(), Some(previous));
                                let (retained, outcome) = owner.take_pending().unwrap();
                                assert_eq!(&retained, previous);
                                assert!(outcome.is_none());
                            }
                            assert!(matches!(owner.next_reconciled(&cx).await, Err(TaskResumeRestartError::Closed)));
                            return;
                        }
                        let item = result.unwrap().unwrap().unwrap();
                        assert_eq!(&item.previous, previous);
                        if index == 0 && matches!(case, RestartCase::Expired | RestartCase::Unavailable(_) | RestartCase::DiscoveryDenied) {
                            assert!(matches!(item.outcome, TaskResumeRestartOutcome::Unavailable));
                        } else {
                            match item.outcome {
                                TaskResumeRestartOutcome::Reconciled(TaskResumeReconciliation::Active { task, record, selection }) => {
                                    assert_ne!(index, 1);
                                    assert!(matches!(*task, Task::InputRequired { .. }));
                                    assert_eq!(record.key(), previous.key());
                                    assert_ne!(record.encode().unwrap(), previous.encode().unwrap(), "returned state must be fresh");
                                    assert!(!record.encode().unwrap().windows(7).any(|part| part == b"PRIVATE"));
                                    assert_eq!(selection.resource().as_str(), peer.resource());
                                    assert_eq!(selection.task_ids(), [previous.task_id().clone()]);
                                }
                                TaskResumeRestartOutcome::Reconciled(TaskResumeReconciliation::Terminal(task)) => {
                                    assert_eq!(index, 1);
                                    assert!(matches!(*task, Task::Completed { .. }));
                                }
                                _ => panic!("fresh remote state required"),
                            }
                        }
                        assert_eq!(owner.remaining(), records.len() - index - 1);
                        assert_eq!(owner.delivered(), index + 1);
                        assert!(owner.pending_record().is_none() && owner.pending_outcome().is_none());
                    }
                    // Complete enumeration needs no further authority. This is
                    // paired with SessionClose above, which stops an unfinished
                    // batch instead of pretending its remaining records vanished.
                    session.close();
                    assert!(owner.next_reconciled(&cx).await.unwrap().is_none());
                    assert!(owner.next_reconciled(&cx).await.unwrap().is_none());
                    assert_eq!(owner.attempted(), records.len() - usize::from(matches!(case, RestartCase::Expired)));
                    assert_eq!(owner.delivered(), records.len());
                });
                let (posts, ()) = pair(server, consumer).await;
                assert_eq!(peer.posts.load(Ordering::SeqCst), posts);
                assert_eq!(peer.tokens.load(Ordering::SeqCst), 1, "restart must not introduce another login");
                assert_eq!(records.iter().map(|record| record.encode().unwrap()).collect::<Vec<_>>(), source,
                    "network reconciliation cannot mutate staged source records");
                assert_eq!(cancellation.is_cancel_requested(), matches!(case, RestartCase::Cancel));
                assert!(cx.checkpoint().is_ok());
                peer.quiet();
                owner.close();
                session.close();
            });
            Box::pin(asupersync::time::timeout_at(cx.now().saturating_add_nanos(20_000_000_000), scenario)).await
                .expect("Task restart fixture must settle within its bound");
        }));
    }

    #[test]
    fn restart_reconciles_all_records_and_preserves_active_terminal_distinctions() {
        isolated_restart("restart_reconciles_all_records_and_preserves_active_terminal_distinctions", RestartCase::Mixed);
    }
    #[test]
    fn duplicate_imports_do_not_repeat_remote_reconciliation() {
        isolated_restart("duplicate_imports_do_not_repeat_remote_reconciliation", RestartCase::Duplicate);
    }
    #[test]
    fn expired_record_is_an_explicit_item_without_a_remote_read() {
        isolated_restart("expired_record_is_an_explicit_item_without_a_remote_read", RestartCase::Expired);
    }
    #[test]
    fn missing_task_does_not_hide_later_live_tasks() {
        isolated_restart("missing_task_does_not_hide_later_live_tasks", RestartCase::Unavailable(404));
    }
    #[test]
    fn forbidden_task_has_the_same_unavailable_disposition() {
        isolated_restart("forbidden_task_has_the_same_unavailable_disposition", RestartCase::Unavailable(403));
    }
    #[test]
    fn rejected_discovery_never_discloses_that_records_task_id() {
        isolated_restart("rejected_discovery_never_discloses_that_records_task_id", RestartCase::DiscoveryDenied);
    }
    #[test]
    fn foreign_reply_keeps_pending_and_unvisited_controls_without_retry() {
        isolated_restart("foreign_reply_keeps_pending_and_unvisited_controls_without_retry", RestartCase::ForeignTask);
    }
    #[test]
    fn lost_reply_closes_restart_without_skipping_or_replaying_the_record() {
        isolated_restart("lost_reply_closes_restart_without_skipping_or_replaying_the_record", RestartCase::LostReply);
    }
    #[test]
    fn cancelled_restart_retains_pending_and_unvisited_records() {
        isolated_restart("cancelled_restart_retains_pending_and_unvisited_records", RestartCase::Cancel);
    }
    #[test]
    fn abandoned_restart_read_retains_custody_and_closes_its_socket() {
        isolated_restart("abandoned_restart_read_retains_custody_and_closes_its_socket", RestartCase::DropRead);
    }
    #[test]
    fn one_original_deadline_includes_pauses_between_records() {
        isolated_restart("one_original_deadline_includes_pauses_between_records", RestartCase::Deadline);
    }
    #[test]
    fn closed_login_cannot_resume_the_next_record() {
        isolated_restart("closed_login_cannot_resume_the_next_record", RestartCase::SessionClose);
    }
    #[test]
    fn current_owner_must_match_before_any_restart_contact() {
        isolated_restart("current_owner_must_match_before_any_restart_contact", RestartCase::WrongOwner);
    }
    #[test]
    fn current_endpoint_must_match_before_any_restart_contact() {
        isolated_restart("current_endpoint_must_match_before_any_restart_contact", RestartCase::WrongEndpoint);
    }
    #[test]
    fn precancelled_restart_has_no_peer_effects() {
        isolated_restart("precancelled_restart_has_no_peer_effects", RestartCase::Precancel);
    }
    #[test]
    fn empty_restart_finishes_without_discovery_or_task_requests() {
        isolated_restart("empty_restart_finishes_without_discovery_or_task_requests", RestartCase::Empty);
    }
}
