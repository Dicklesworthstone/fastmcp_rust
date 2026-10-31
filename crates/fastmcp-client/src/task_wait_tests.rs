use super::*;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::thread::JoinHandle;

use asupersync::runtime::{RuntimeBuilder, reactor::create_reactor};
use fastmcp_protocol::{ClientCapabilities, ClientInfo, ServerDiscoverResult, ServerInfo};
use serde_json::{Value, json};

struct Reply {
    task: Value,
    minimum_delay: Duration,
    hold: Duration,
    cancel: Option<McpRequestCancellation>,
}

impl Reply {
    fn new(task: Value, minimum_ms: u64) -> Self {
        Self {
            task,
            minimum_delay: Duration::from_millis(minimum_ms),
            hold: Duration::ZERO,
            cancel: None,
        }
    }
}

fn task(status: &str, poll: Option<u64>) -> Value {
    let mut task = json!({
        "taskId": "wait-task",
        "status": status,
        "createdAt": "2026-07-28T12:00:00Z",
        "lastUpdatedAt": "2026-07-28T12:00:01Z",
        "ttlMs": null
    });
    if let Some(poll) = poll {
        task["pollIntervalMs"] = json!(poll);
    }
    match status {
        "input_required" => {
            task["inputRequests"] = json!({
                "roots": {"method": "roots/list"}
            })
        }
        "completed" => {
            task["result"] = json!({
                "content": [{"type": "text", "text": "finished"}],
                "opaque": {"x": [1, true, "kept"]}
            })
        }
        "failed" => {
            task["error"] = json!({
                "code": -32000,
                "message": "application failed",
                "opaque": [false, 7]
            })
        }
        _ => {}
    }
    task
}

fn snapshot(value: &Value) -> FinalTask {
    serde_json::from_str(&value.to_string()).unwrap()
}

fn response(id: u64, mut task: Value) -> Value {
    task["resultType"] = json!("complete");
    json!({"jsonrpc": "2.0", "id": id, "result": task})
}

fn discovery() -> Value {
    let capabilities = fastmcp_protocol::ServerDiscoverCapabilities::from_registry(
        &fastmcp_protocol::ServerBehaviorRegistry::from_behaviors([
            fastmcp_protocol::ServerBehavior::ToolsList,
        ]),
        std::collections::BTreeMap::from([(
            fastmcp_protocol::TASKS_EXTENSION.to_owned(),
            json!({}),
        )]),
    )
    .unwrap();
    let result = ServerDiscoverResult::new(
        capabilities,
        ServerInfo {
            name: "task-wait-peer".to_owned(),
            version: "1".to_owned(),
        },
        None,
        fastmcp_protocol::DiscoveryCacheHints::private_ttl_ms(0),
    );
    let mut response = json!({"jsonrpc": "2.0", "id": 1, "result": result});
    response["result"]["supportedVersions"] = json!([crate::MODERN_PROTOCOL_VERSION]);
    response
}

fn accept(listener: &TcpListener) -> TcpStream {
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        match listener.accept() {
            Ok((stream, _)) => {
                stream
                    .set_read_timeout(Some(Duration::from_secs(3)))
                    .unwrap();
                stream
                    .set_write_timeout(Some(Duration::from_secs(3)))
                    .unwrap();
                return stream;
            }
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                assert!(
                    Instant::now() < deadline,
                    "public Task wait peer received no expected request"
                );
                std::thread::sleep(Duration::from_millis(1));
            }
            Err(error) => panic!("Task wait accept: {error}"),
        }
    }
}

fn read(stream: &mut TcpStream) -> Value {
    let mut bytes = Vec::new();
    let mut buffer = [0_u8; 4096];
    let end = loop {
        let count = stream.read(&mut buffer).unwrap();
        assert!(count > 0, "request ended before its headers");
        bytes.extend_from_slice(&buffer[..count]);
        assert!(bytes.len() <= 128 * 1024);
        if let Some(index) = bytes.windows(4).position(|part| part == b"\r\n\r\n") {
            break index + 4;
        }
    };
    let length = std::str::from_utf8(&bytes[..end])
        .unwrap()
        .lines()
        .find_map(|line| {
            let (name, value) = line.split_once(':')?;
            name.eq_ignore_ascii_case("content-length")
                .then(|| value.trim().parse::<usize>().unwrap())
        })
        .unwrap();
    assert!(length <= 64 * 1024);
    while bytes.len() < end + length {
        let count = stream.read(&mut buffer).unwrap();
        assert!(count > 0, "request ended before its body");
        bytes.extend_from_slice(&buffer[..count]);
    }
    serde_json::from_slice(&bytes[end..end + length]).unwrap()
}

fn write(stream: &mut TcpStream, value: &Value) -> std::io::Result<()> {
    let body = serde_json::to_vec(value).unwrap();
    write!(
        stream,
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    )?;
    stream.write_all(&body)?;
    stream.flush()
}

fn peer(initial: Value, replies: Vec<Reply>) -> (String, JoinHandle<Vec<Duration>>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let target = format!("http://{}/mcp", listener.local_addr().unwrap());
    let peer = std::thread::spawn(move || {
        let mut discover = accept(&listener);
        let request = read(&mut discover);
        assert_eq!(request["id"], 1);
        assert_eq!(request["method"], "server/discover");
        write(&mut discover, &discovery()).unwrap();
        drop(discover);

        let mut attach = accept(&listener);
        let request = read(&mut attach);
        assert_eq!(request["id"], 2);
        assert_eq!(request["method"], "tasks/get");
        assert_eq!(request["params"]["taskId"], "wait-task");
        write(&mut attach, &response(2, initial)).unwrap();
        let mut sent = Instant::now();
        drop(attach);
        let mut delays = Vec::new();
        let next_id = 3 + replies.len() as u64;
        for (index, reply) in replies.into_iter().enumerate() {
            let mut poll = accept(&listener);
            let request = read(&mut poll);
            let elapsed = sent.elapsed();
            // Permit only sub-millisecond response-flush/receipt skew.
            assert!(
                elapsed + Duration::from_millis(2) >= reply.minimum_delay,
                "client polled before the advertised minimum"
            );
            delays.push(elapsed);
            assert_eq!(request["id"], 3 + index as u64);
            assert_eq!(request["method"], "tasks/get");
            assert_eq!(request["params"]["taskId"], "wait-task");
            assert!(request["params"].get("inputResponses").is_none());
            if let Some(cancel) = reply.cancel {
                cancel.cancel();
            }
            if !reply.hold.is_zero() {
                std::thread::sleep(reply.hold);
            }
            let result = write(&mut poll, &response(3 + index as u64, reply.task));
            if reply.hold.is_zero() {
                result.unwrap();
            }
            sent = Instant::now();
        }

        // A healthy sibling request follows every outcome. An extra poll,
        // input update or remote cancellation is a hard protocol failure.
        let mut sentinel = accept(&listener);
        let request = read(&mut sentinel);
        assert_eq!(request["id"], next_id);
        assert_eq!(
            request["method"], "tools/list",
            "the wait must stop without another Task or input-effect request"
        );
        write(
            &mut sentinel,
            &json!({
                "jsonrpc": "2.0", "id": next_id,
                "result": {"resultType": "complete", "tools": [], "ttlMs": 0, "cacheScope": "private"}
            }),
        )
        .unwrap();
        delays
    });
    (target, peer)
}

fn plan(target: &str) -> crate::ClientProtocolPlan {
    crate::ClientProtocolPlan::http(
        crate::ProtocolPolicy::ModernOnly,
        Some(crate::CanonicalHttpUrl::parse(target).unwrap()),
        None,
        None,
        "task-wait-credential".to_owned(),
        "task-wait-security".to_owned(),
        "task-wait-transport".to_owned(),
        1,
        1,
        0,
    )
    .unwrap()
}

fn run(
    initial: Value,
    replies: Vec<Reply>,
    policy: FinalTaskWaitPolicy,
    cancellation: McpRequestCancellation,
    cancel_after: Option<Duration>,
    expected: Result<FinalTaskWaitOutcome, ()>,
) -> (FinalTask, Vec<Duration>) {
    let before = serde_json::to_vec(&snapshot(&initial)).unwrap();
    let (target, peer) = peer(initial, replies);
    let retained = RuntimeBuilder::current_thread()
        .with_reactor(create_reactor().unwrap())
        .build()
        .unwrap()
        .block_on(async {
            let cx = Cx::current().unwrap();
            let mut client = HttpClient::connect(
                &cx,
                plan(&target),
                ClientInfo {
                    name: "task-wait-client".to_owned(),
                    version: "1".to_owned(),
                },
                ClientCapabilities {
                    roots: Some(Default::default()),
                    ..ClientCapabilities::default()
                },
            )
            .await
            .unwrap();
            let mut handle = client
                .attach_final_task(&cx, FinalTaskId::parse("wait-task").unwrap())
                .await
                .unwrap();
            let cancel_thread = cancel_after.map(|delay| {
                let cancellation = cancellation.clone();
                std::thread::spawn(move || {
                    std::thread::sleep(delay);
                    cancellation.cancel();
                })
            });
            let result = handle.wait(&cx, &mut client, &cancellation, policy).await;
            match expected {
                Ok(expected) => {
                    assert_eq!(result.unwrap(), expected);
                    if matches!(
                        expected,
                        FinalTaskWaitOutcome::Completed
                            | FinalTaskWaitOutcome::Failed
                            | FinalTaskWaitOutcome::Cancelled
                            | FinalTaskWaitOutcome::InputRequired
                    ) {
                        assert_eq!(
                            handle
                                .wait(&cx, &mut client, &cancellation, policy)
                                .await
                                .unwrap(),
                            expected,
                            "retained terminal/input snapshots require no second get"
                        );
                    }
                }
                Err(()) => {
                    assert!(result.is_err());
                    assert_eq!(
                        serde_json::to_vec(handle.task()).unwrap(),
                        before,
                        "a rejected identity must not mutate the retained snapshot"
                    );
                }
            }
            if let Some(thread) = cancel_thread {
                thread.join().unwrap();
            }
            assert!(
                cx.checkpoint().is_ok(),
                "the caller and sibling requests remain usable"
            );
            client.list_tools(&cx, None).await.unwrap();
            handle.task().clone()
        });
    (retained, peer.join().unwrap())
}

fn policy(timeout_ms: u64, polls: usize, fallback_ms: u64) -> FinalTaskWaitPolicy {
    FinalTaskWaitPolicy::new(
        Duration::from_millis(timeout_ms),
        polls,
        Duration::from_millis(fallback_ms),
    )
    .unwrap()
}

#[test]
fn public_http_wait_returns_every_task_outcome_and_preserves_payloads() {
    for (status, expected) in [
        ("completed", FinalTaskWaitOutcome::Completed),
        ("failed", FinalTaskWaitOutcome::Failed),
        ("cancelled", FinalTaskWaitOutcome::Cancelled),
        ("input_required", FinalTaskWaitOutcome::InputRequired),
    ] {
        let final_task = task(status, None);
        let (retained, delays) = run(
            task("working", Some(25)),
            vec![Reply::new(final_task.clone(), 25)],
            policy(1000, 8, 10),
            McpRequestCancellation::new(),
            None,
            Ok(expected),
        );
        assert_eq!(delays.len(), 1);
        assert_eq!(serde_json::to_value(retained).unwrap(), final_task);
    }
}

#[test]
fn public_http_wait_replaces_present_and_absent_poll_suggestions() {
    let (retained, delays) = run(
        task("working", Some(30)),
        vec![
            Reply::new(task("working", None), 30),
            Reply::new(task("working", Some(45)), 10),
            Reply::new(task("completed", None), 45),
        ],
        policy(1500, 8, 10),
        McpRequestCancellation::new(),
        None,
        Ok(FinalTaskWaitOutcome::Completed),
    );
    assert_eq!(delays.len(), 3);
    assert!(matches!(retained, FinalTask::Completed { .. }));
    let default = FinalTaskWaitPolicy::default();
    assert_eq!(
        next_delay(&snapshot(&task("working", None)), default).unwrap(),
        Duration::from_secs(1)
    );
    assert_eq!(
        next_delay(&snapshot(&task("working", Some(600001))), default).unwrap(),
        Duration::from_millis(600001)
    );
    assert_eq!(
        next_delay(&snapshot(&task("working", None)), policy(1000, 8, 10)).unwrap(),
        Duration::from_millis(10),
        "absence clears the previous suggestion"
    );
}

#[test]
fn public_http_wait_stops_at_poll_budget_and_never_shortens_server_minimum() {
    run(
        task("working", Some(10)),
        vec![Reply::new(task("working", Some(10)), 10)],
        policy(1000, 1, 1),
        McpRequestCancellation::new(),
        None,
        Ok(FinalTaskWaitOutcome::PollLimitReached),
    );
    for interval in [600001, u64::MAX] {
        run(
            task("working", Some(interval)),
            vec![],
            policy(30, 8, 1),
            McpRequestCancellation::new(),
            None,
            Ok(FinalTaskWaitOutcome::DeadlineElapsed),
        );
    }
    // A fresh snapshot can move the next poll beyond the same original budget.
    run(
        task("working", Some(10)),
        vec![Reply::new(task("working", Some(600001)), 10)],
        policy(50, 8, 1),
        McpRequestCancellation::new(),
        None,
        Ok(FinalTaskWaitOutcome::DeadlineElapsed),
    );
}

#[test]
fn public_http_wait_cancels_sleep_and_inflight_read_without_cancelling_task() {
    for cancelled_before in [false, true] {
        let cancellation = McpRequestCancellation::new();
        if cancelled_before {
            cancellation.cancel();
        }
        let (retained, _) = run(
            task("working", Some(600001)),
            vec![],
            policy(1000, 8, 1),
            cancellation,
            (!cancelled_before).then_some(Duration::from_millis(15)),
            Ok(FinalTaskWaitOutcome::ObservationCancelled),
        );
        assert!(matches!(retained, FinalTask::Working(_)));
    }
    let cancellation = McpRequestCancellation::new();
    let mut reply = Reply::new(task("completed", None), 5);
    reply.cancel = Some(cancellation.clone());
    reply.hold = Duration::from_millis(40);
    let (retained, _) = run(
        task("working", Some(5)),
        vec![reply],
        policy(1000, 8, 1),
        cancellation,
        None,
        Ok(FinalTaskWaitOutcome::ObservationCancelled),
    );
    assert!(
        matches!(retained, FinalTask::Working(_)),
        "a completing or late read cannot publish after cancellation"
    );
}

#[test]
fn public_http_wait_deadline_includes_pending_response_without_reset() {
    let mut reply = Reply::new(task("completed", None), 5);
    reply.hold = Duration::from_millis(90);
    let (retained, _) = run(
        task("working", Some(5)),
        vec![reply],
        policy(35, 8, 1),
        McpRequestCancellation::new(),
        None,
        Ok(FinalTaskWaitOutcome::DeadlineElapsed),
    );
    assert!(matches!(retained, FinalTask::Working(_)));
}

#[test]
fn public_http_wait_rejects_changed_identity_and_retains_original_snapshot() {
    for field in ["taskId", "createdAt"] {
        let mut changed = task("completed", None);
        changed[field] = match field {
            "taskId" => json!("foreign-task"),
            "createdAt" => json!("2026-07-28T12:00:02Z"),
            _ => unreachable!(),
        };
        run(
            task("working", Some(5)),
            vec![Reply::new(changed, 5)],
            policy(1000, 8, 1),
            McpRequestCancellation::new(),
            None,
            Err(()),
        );
    }
    let mut equivalent = task("completed", None);
    equivalent["createdAt"] = json!("2026-07-28T08:00:00-04:00");
    run(
        task("working", Some(5)),
        vec![Reply::new(equivalent, 5)],
        policy(1000, 8, 1),
        McpRequestCancellation::new(),
        None,
        Ok(FinalTaskWaitOutcome::Completed),
    );
}

fn run_http_task_identity_case(
    initial: Value,
    through_watch: bool,
    reconcile: bool,
    candidate: Value,
    admitted: bool,
) {
    let before = serde_json::to_vec(&snapshot(&initial)).unwrap();
    let expected = serde_json::to_vec(&snapshot(&candidate)).unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let target = format!("http://{}/mcp", listener.local_addr().unwrap());
    let peer = std::thread::spawn(move || {
        let mut discover = accept(&listener);
        assert_eq!(read(&mut discover)["method"], "server/discover");
        write(&mut discover, &discovery()).unwrap();
        let mut attach = accept(&listener);
        assert_eq!(read(&mut attach)["method"], "tasks/get");
        write(&mut attach, &response(2, initial.clone())).unwrap();

        let mut observe = accept(&listener);
        let request = read(&mut observe);
        assert_eq!(request["id"], 3);
        if through_watch {
            assert_eq!(request["method"], "subscriptions/listen");
            assert_eq!(
                request["params"]["notifications"]["taskIds"],
                json!(["wait-task"])
            );
            let mut notified = if reconcile {
                let mut ambiguous = initial;
                ambiguous["statusMessage"] = json!("requires authoritative reconciliation");
                ambiguous
            } else {
                candidate.clone()
            };
            notified["_meta"] = json!({"io.modelcontextprotocol/subscriptionId": 3});
            let acknowledged = json!({
                "jsonrpc": "2.0",
                "method": "notifications/subscriptions/acknowledged",
                "params": {
                    "_meta": {"io.modelcontextprotocol/subscriptionId": 3},
                    "notifications": {"taskIds": ["wait-task"]}
                }
            });
            let notification = json!({
                "jsonrpc": "2.0", "method": "notifications/tasks", "params": notified
            });
            let terminal = json!({"jsonrpc":"2.0", "id":3,
                "result":{"resultType":"complete",
                    "_meta":{"io.modelcontextprotocol/subscriptionId":3}}});
            let body =
                format!("data: {acknowledged}\n\ndata: {notification}\n\ndata: {terminal}\n\n");
            write!(
                observe,
                "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len(),
            )
            .unwrap();
            observe.flush().unwrap();
            if reconcile {
                let mut get = accept(&listener);
                let request = read(&mut get);
                assert_eq!(request["id"], 4);
                assert_eq!(request["method"], "tasks/get");
                write(&mut get, &response(4, candidate)).unwrap();
            }
        } else {
            assert_eq!(request["method"], "tasks/get");
            write(&mut observe, &response(3, candidate)).unwrap();
        }

        // A changed identity must not provoke an extra reconciliation or
        // consume the next request's response. The same client stays usable.
        let expected_id = if reconcile { 5 } else { 4 };
        let mut sibling = accept(&listener);
        let request = read(&mut sibling);
        assert_eq!(request["method"], "tools/list");
        assert_eq!(request["id"], expected_id);
        write(
            &mut sibling,
            &json!({"jsonrpc":"2.0", "id":expected_id,
                "result":{"resultType":"complete", "tools":[], "ttlMs":0, "cacheScope":"private"}}),
        )
        .unwrap();
    });

    RuntimeBuilder::current_thread()
        .with_reactor(create_reactor().unwrap())
        .build()
        .unwrap()
        .block_on(async {
            let cx = Cx::current().unwrap();
            let mut client = HttpClient::connect(
                &cx,
                plan(&target),
                ClientInfo {
                    name: "task-identity-client".to_owned(),
                    version: "1".to_owned(),
                },
                ClientCapabilities::default(),
            )
            .await
            .unwrap();
            let mut handle = client
                .attach_final_task(&cx, FinalTaskId::parse("wait-task").unwrap())
                .await
                .unwrap();
            if through_watch {
                let mut watch = handle
                    .watch(
                        &cx,
                        &mut client,
                        crate::sse::SseLimits::new(4096, 8192, 8).unwrap(),
                    )
                    .await
                    .unwrap();
                assert!(matches!(
                    watch.next_event(&cx).await.unwrap(),
                    Some(crate::FinalTaskWatchEvent::Acknowledged { .. })
                ));
                let event = watch.next_event(&cx).await;
                if admitted {
                    if reconcile {
                        assert!(matches!(
                            event.unwrap(),
                            Some(crate::FinalTaskWatchEvent::TaskReconciled { .. })
                        ));
                    } else {
                        assert!(matches!(
                            event.unwrap(),
                            Some(crate::FinalTaskWatchEvent::TaskUpdated(_))
                        ));
                    }
                } else {
                    assert!(
                        event.is_err(),
                        "a changed identity must not replace the handle"
                    );
                    assert!(watch.next_event(&cx).await.unwrap().is_none());
                }
            } else {
                assert_eq!(handle.poll(&cx, &mut client).await.is_ok(), admitted);
            }
            assert_eq!(
                serde_json::to_vec(handle.task()).unwrap(),
                if admitted { expected } else { before },
                "a refused snapshot must leave the exact retained state unchanged"
            );
            assert!(cx.checkpoint().is_ok());
            client.list_tools(&cx, None).await.unwrap();
        });
    peer.join().unwrap();
}

#[test]
fn public_http_task_poll_preserves_creation_identity() {
    let mut changed = task("working", None);
    changed["lastUpdatedAt"] = json!("2026-07-28T12:00:02Z");
    changed["createdAt"] = json!("2026-07-28T12:00:01Z");
    run_http_task_identity_case(task("working", None), false, false, changed, false);
    let mut equivalent = task("working", None);
    equivalent["createdAt"] = json!("2026-07-28T08:00:00-04:00");
    equivalent["lastUpdatedAt"] = json!("2026-07-28T12:00:02Z");
    run_http_task_identity_case(task("working", None), false, false, equivalent, true);
}

#[test]
fn public_http_task_watch_preserves_identity_before_and_after_reconciliation() {
    for (reconcile, updated) in [
        (false, "2026-07-28T12:00:02Z"),
        (false, "2026-07-28T12:00:01Z"),
        (true, "2026-07-28T12:00:01Z"),
    ] {
        let mut changed = task("working", None);
        changed["lastUpdatedAt"] = json!(updated);
        changed["createdAt"] = json!("2026-07-28T12:00:01Z");
        run_http_task_identity_case(task("working", None), true, reconcile, changed, false);
    }
    let mut equivalent = task("working", None);
    equivalent["createdAt"] = json!("2026-07-28T08:00:00-04:00");
    equivalent["lastUpdatedAt"] = json!("2026-07-28T12:00:02Z");
    run_http_task_identity_case(task("working", None), true, false, equivalent, true);
}

#[test]
fn public_http_task_poll_and_watch_accept_authoritative_retention_changes() {
    for (previous_ttl, next_ttl) in [
        (None, Some(u64::MAX / 2)),
        (Some(u64::MAX / 2), Some(u64::MAX)),
        (Some(u64::MAX), Some(u64::MAX / 2)),
        (Some(u64::MAX), None),
    ] {
        for (through_watch, reconcile) in [(false, false), (true, false), (true, true)] {
            let mut initial = task("working", None);
            initial["ttlMs"] = json!(previous_ttl);
            let mut candidate = initial.clone();
            candidate["ttlMs"] = json!(next_ttl);
            candidate["lastUpdatedAt"] = json!("2026-07-28T12:00:02Z");
            run_http_task_identity_case(initial, through_watch, reconcile, candidate, true);
        }
    }
}

#[test]
fn public_http_task_input_expiry_refuses_before_request_allocation() {
    let live_expiry_ms = u64::try_from(wall_now_nanos() / 1_000_000).unwrap() + 300_000;
    for ttl_ms in [None, Some(live_expiry_ms), Some(1)] {
        let expired = ttl_ms == Some(1);
        let mut initial = task("input_required", None);
        initial["createdAt"] = json!("1970-01-01T00:00:00Z");
        initial["ttlMs"] = json!(ttl_ms);
        let before = serde_json::to_vec(&snapshot(&initial)).unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let target = format!("http://{}/mcp", listener.local_addr().unwrap());
        let peer = std::thread::spawn(move || {
            let mut discover = accept(&listener);
            assert_eq!(read(&mut discover)["method"], "server/discover");
            write(&mut discover, &discovery()).unwrap();
            let mut attach = accept(&listener);
            assert_eq!(read(&mut attach)["method"], "tasks/get");
            write(&mut attach, &response(2, initial)).unwrap();
            if !expired {
                let mut update = accept(&listener);
                let request = read(&mut update);
                assert_eq!(request["id"], 3);
                assert_eq!(request["method"], "tasks/update");
                assert_eq!(request["params"]["taskId"], "wait-task");
                assert_eq!(
                    request["params"]["inputResponses"],
                    json!({"roots":{"roots":[]}})
                );
                write(
                    &mut update,
                    &json!({"jsonrpc":"2.0", "id":3,
                    "result":{"resultType":"complete"}}),
                )
                .unwrap();
            }
            let expected_id = if expired { 3 } else { 4 };
            let mut sibling = accept(&listener);
            let request = read(&mut sibling);
            assert_eq!(
                request["method"], "tools/list",
                "expired input must not be transmitted or retried"
            );
            assert_eq!(
                request["id"], expected_id,
                "local refusal must not consume a request ID"
            );
            write(
                &mut sibling,
                &json!({"jsonrpc":"2.0", "id":expected_id,
                    "result":{"resultType":"complete", "tools":[], "ttlMs":0, "cacheScope":"private"}}),
            )
            .unwrap();
        });
        RuntimeBuilder::current_thread()
            .with_reactor(create_reactor().unwrap())
            .build()
            .unwrap()
            .block_on(async {
                let cx = Cx::current().unwrap();
                let mut client = HttpClient::connect(
                    &cx,
                    plan(&target),
                    ClientInfo {
                        name: "task-input-client".to_owned(),
                        version: "1".to_owned(),
                    },
                    ClientCapabilities {
                        roots: Some(Default::default()),
                        ..Default::default()
                    },
                )
                .await
                .unwrap();
                let mut handle = client
                    .attach_final_task(&cx, FinalTaskId::parse("wait-task").unwrap())
                    .await
                    .unwrap();
                let inputs = serde_json::from_value(json!({"roots":{"roots":[]}})).unwrap();
                let updated = handle.resume_input(&cx, &mut client, inputs).await;
                assert_eq!(updated.is_ok(), !expired);
                assert_eq!(
                    serde_json::to_vec(handle.task()).unwrap(),
                    before,
                    "an update acknowledgement or refusal cannot invent a Task state"
                );
                assert!(cx.checkpoint().is_ok());
                client.list_tools(&cx, None).await.unwrap();
            });
        peer.join().unwrap();
    }
}

#[test]
fn task_wait_policy_and_missing_timer_fail_before_transport_activity() {
    for (timeout, polls, fallback) in [
        (Duration::ZERO, 1, Duration::from_secs(1)),
        (Duration::from_secs(86401), 1, Duration::from_secs(1)),
        (Duration::from_secs(1), 0, Duration::from_secs(1)),
        (Duration::from_secs(1), 4097, Duration::from_secs(1)),
        (Duration::from_secs(1), 1, Duration::ZERO),
        (Duration::from_secs(1), 1, Duration::from_secs(301)),
    ] {
        assert!(FinalTaskWaitPolicy::new(timeout, polls, fallback).is_err());
    }
    assert!(
        FinalTaskWaitPolicy::new(Duration::from_secs(86400), 4096, Duration::from_secs(300),)
            .is_ok()
    );

    struct NoReads;
    impl TaskWaitTransport for NoReads {
        type Error = McpError;
        async fn read_task(
            &mut self,
            _: &Cx,
            _: &McpRequestCancellation,
            _: FinalTaskId,
        ) -> McpResult<FinalTask> {
            panic!("unavailable timer must refuse before a transport read")
        }
    }
    let cx = Cx::for_request();
    assert!(cx.timer_driver().is_none());
    let mut handle = FinalTaskHandle::new(snapshot(&task("working", Some(1))));
    let cancellation = McpRequestCancellation::new();
    let mut transport = NoReads;
    let mut wait = std::pin::pin!(wait_for_task(
        &mut handle,
        &cx,
        &mut transport,
        &cancellation,
        policy(1000, 8, 1),
    ));
    let waker = std::task::Waker::noop();
    let mut context = std::task::Context::from_waker(waker);
    assert!(matches!(
        wait.as_mut().poll(&mut context),
        Poll::Ready(Ok(FinalTaskWaitOutcome::TimerUnavailable))
    ));
}

#[test]
fn public_http_task_watch_acknowledgements_use_exact_set_subsets() {
    for mode in ["duplicates", "empty", "absent", "foreign"] {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let target = format!("http://{}/mcp", listener.local_addr().unwrap());
        let peer = std::thread::spawn(move || {
            let mut discover = accept(&listener);
            assert_eq!(read(&mut discover)["method"], "server/discover");
            write(&mut discover, &discovery()).unwrap();
            let mut attach = accept(&listener);
            assert_eq!(read(&mut attach)["method"], "tasks/get");
            write(&mut attach, &response(2, task("working", None))).unwrap();

            let mut observe = accept(&listener);
            let request = read(&mut observe);
            assert_eq!(request["id"], 3);
            assert_eq!(request["method"], "subscriptions/listen");
            assert_eq!(
                request["params"]["notifications"]["taskIds"],
                json!(["wait-task"])
            );
            let accepted = match mode {
                "duplicates" => json!({"taskIds":["wait-task", "wait-task"]}),
                "empty" => json!({"taskIds":[]}),
                "absent" => json!({}),
                "foreign" => json!({"taskIds":["wait-task", "foreign-task"]}),
                _ => unreachable!(),
            };
            let acknowledged = json!({"jsonrpc":"2.0", "method":"notifications/subscriptions/acknowledged", "params":{
                "_meta":{"io.modelcontextprotocol/subscriptionId":3}, "notifications":accepted
            }});
            let mut body = format!("data: {acknowledged}\n\n");
            if mode == "duplicates" {
                let mut completed = task("completed", None);
                completed["lastUpdatedAt"] = json!("2026-07-28T12:00:02Z");
                completed["_meta"] = json!({"io.modelcontextprotocol/subscriptionId":3});
                let notification =
                    json!({"jsonrpc":"2.0", "method":"notifications/tasks", "params":completed});
                body.push_str(&format!("data: {notification}\n\n"));
            }
            let terminal = json!({"jsonrpc":"2.0", "id":3, "result":{
                "resultType":"complete", "_meta":{"io.modelcontextprotocol/subscriptionId":3}
            }});
            body.push_str(&format!("data: {terminal}\n\n"));
            // Keep a valid live response open through the next independent
            // request. Empty acceptance must exhaust before the queued
            // normal terminal, and cannot rely on an early transport EOF.
            write!(observe,
                "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n{:x}\r\n{body}\r\n",
                body.len(),
            ).unwrap();
            observe.flush().unwrap();

            let mut sibling = accept(&listener);
            let request = read(&mut sibling);
            assert_eq!(
                request["method"], "tools/list",
                "no implicit Task cancellation or extra observation request"
            );
            assert_eq!(request["id"], 4);
            write(
                &mut sibling,
                &json!({"jsonrpc":"2.0", "id":4, "result":{
                    "resultType":"complete", "tools":[], "ttlMs":0, "cacheScope":"private"
                }}),
            )
            .unwrap();
            drop(observe);
        });
        RuntimeBuilder::current_thread()
            .with_reactor(create_reactor().unwrap())
            .build()
            .unwrap()
            .block_on(async {
                let cx = Cx::current().unwrap();
                let mut client = HttpClient::connect(
                    &cx,
                    plan(&target),
                    ClientInfo {
                        name: "task-ack-client".to_owned(),
                        version: "1".to_owned(),
                    },
                    ClientCapabilities::default(),
                )
                .await
                .unwrap();
                let mut handle = client
                    .attach_final_task(&cx, FinalTaskId::parse("wait-task").unwrap())
                    .await
                    .unwrap();
                let before = serde_json::to_vec(handle.task()).unwrap();
                let mut watch = handle
                    .watch(
                        &cx,
                        &mut client,
                        crate::sse::SseLimits::new(4096, 8192, 8).unwrap(),
                    )
                    .await
                    .unwrap();
                let acknowledged = watch.next_event(&cx).await;
                if mode == "foreign" {
                    assert!(
                        acknowledged.is_err(),
                        "a distinct unrequested ID must not widen the watch"
                    );
                } else {
                    let Some(crate::FinalTaskWatchEvent::Acknowledged { accepted_filter }) =
                        acknowledged.unwrap()
                    else {
                        panic!("valid accepted subsets must reach the caller");
                    };
                    let accepted = fastmcp_protocol::task_subscription_ids(&accepted_filter)
                        .unwrap()
                        .unwrap_or_default();
                    assert_eq!(accepted.is_empty(), mode != "duplicates");
                    assert!(
                        accepted
                            .iter()
                            .all(|id| id == &FinalTaskId::parse("wait-task").unwrap())
                    );
                }
                if mode == "duplicates" {
                    let Some(crate::FinalTaskWatchEvent::TaskUpdated(notification)) =
                        watch.next_event(&cx).await.unwrap()
                    else {
                        panic!("duplicate accepted IDs must permit the owned Task event");
                    };
                    assert!(matches!(
                        notification.params.task,
                        FinalTask::Completed { .. }
                    ));
                }
                let exhausted = asupersync::time::timeout_at(
                    cx.now() + Duration::from_millis(250),
                    watch.next_event(&cx),
                )
                .await
                .expect("exhausted watches must not wait for peer data")
                .unwrap();
                assert!(exhausted.is_none());
                drop(watch);
                if mode == "duplicates" {
                    assert!(matches!(handle.task(), FinalTask::Completed { .. }));
                    assert_eq!(
                        serde_json::to_value(handle.task()).unwrap()["result"]["opaque"],
                        json!({"x":[1,true,"kept"]})
                    );
                } else {
                    assert_eq!(serde_json::to_vec(handle.task()).unwrap(), before);
                }
                assert!(cx.checkpoint().is_ok());
                client.list_tools(&cx, None).await.unwrap();
            });
        peer.join().unwrap();
    }
}
