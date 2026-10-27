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
                "result": {"resultType": "complete", "tools": []}
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
    for field in ["taskId", "createdAt", "ttlMs"] {
        let mut changed = task("completed", None);
        changed[field] = match field {
            "taskId" => json!("foreign-task"),
            "createdAt" => json!("2026-07-28T12:00:02Z"),
            _ => json!(60000),
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
