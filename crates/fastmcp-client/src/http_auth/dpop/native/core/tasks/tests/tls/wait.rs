//! Public Task waiting against actual HTTPS, using the parent's TLS fixture.

use super::*;
use std::collections::HashSet;
use crate::http_auth::dpop::native::core::tasks::wait::{
    DpopTaskWaitError, DpopTaskWaitOutcome, DpopTaskWaitPolicy,
};

fn snapshot(status: &str, interval: u64) -> String {
    let mut value = json!({
        "resultType":"complete","taskId":"task-one","status":status,
        "createdAt":"2026-09-16T00:00:00Z","lastUpdatedAt":"2026-09-16T00:00:00Z",
        "ttlMs":null,"pollIntervalMs":interval,
    });
    match status {
        "completed" => { value["result"] = json!({"content":[{"type":"text","text":"exact-result"}]}); }
        "failed" => { value["error"] = json!({"code":-32603,"message":"private-task-error","data":{"kept":true}}); }
        "input_required" => { value["inputRequests"] = json!({"roots":{"method":"roots/list"}}); }
        "working" | "cancelled" => {}
        _ => panic!("invalid Task fixture"),
    }
    value.to_string()
}

fn correlated(prefix: &str, index: usize, discovery: bool, body: &str) -> DpopHttpResponse {
    let suffix = if discovery { "discover" } else { "get" };
    response(200, envelope(&RequestId::String(format!("{prefix}.{index}.{suffix}")), body))
}

fn polling(maximum: usize) -> DpopTaskWaitPolicy {
    DpopTaskWaitPolicy::new(maximum, Duration::from_millis(1)).unwrap()
}

async fn answer_poll(
    listener: &TcpListener,
    acceptor: &TlsAcceptor,
    prefix: &str,
    index: usize,
    final_body: &str,
    proof_ids: &mut HashSet<String>,
) {
    for (is_discovery, method, body) in [
        (true, "server/discover", discovery_result().to_string()),
        (false, TASK_GET, final_body.to_owned()),
    ] {
        let (socket, _) = listener.accept().await.unwrap();
        let mut socket = acceptor.accept(socket).await.unwrap();
        let (head, request) = read_request(&mut socket).await;
        let suffix = if is_discovery { "discover" } else { "get" };
        assert_eq!(request["id"], format!("{prefix}.{index}.{suffix}"));
        assert_eq!(request["method"], method);
        assert_eq!(request["params"]["_meta"][FINAL_CLIENT_CAPABILITIES_META_KEY]["extensions"],
            json!({TASKS_EXTENSION:{}}));
        assert_eq!(header(&head, "authorization"), "DPoP tasks-token");
        assert_eq!(header(&head, "accept"), "application/json");
        if !is_discovery {
            assert_eq!(request["params"]["taskId"], "task-one");
        }
        assert!(request["params"].get("inputResponses").is_none());
        let proof = claims(header(&head, "dpop"));
        assert!(proof_ids.insert(proof["jti"].as_str().unwrap().to_owned()));
        if index != 0 || !is_discovery {
            assert_eq!(proof["nonce"], "resource-next");
        }
        send(&mut socket, correlated(prefix, index, is_discovery, &body)).await;
    }
}

#[test]
fn public_wait_stops_on_every_terminal_input_handoff_and_poll_limit_without_mutations() {
    for status in ["completed", "failed", "cancelled", "input_required", "working"] {
        run(async move {
            let cx = Cx::current().unwrap();
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let (mut client, credential, acceptor) = configured(&format!(
                "https://{}/mcp", listener.local_addr().unwrap()));
            let body = snapshot(status, 300_000);
            let mut proofs = HashSet::new();
            let application = client.wait_task(&cx, &credential, metadata(), id(), "stop",
                polling(1), ManagedCoreLimits::default());
            let peer = answer_poll(&listener, &acceptor, "stop", 0, &body, &mut proofs);
            let (result, ()) = pair(application, peer).await;
            match status {
                "working" => assert!(matches!(result, Err(DpopTaskWaitError::PollLimit))),
                "input_required" => {
                    let DpopTaskWaitOutcome::InputRequired(result) = result.unwrap() else {
                        panic!("input must be handed back without an update");
                    };
                    assert!(matches!(result.task, Task::InputRequired { .. }));
                }
                _ => {
                    let outcome = result.unwrap();
                    assert!(!format!("{outcome:?}").contains("private-task-error"));
                    let DpopTaskWaitOutcome::Terminal(result) = outcome else {
                        panic!("terminal Task must not become input-required");
                    };
                    let value = serde_json::to_value(result).unwrap();
                    assert_eq!(value["status"], status);
                    if status == "completed" {
                        assert_eq!(value["result"]["content"][0]["text"], "exact-result");
                    }
                    if status == "failed" {
                        assert_eq!(value["error"]["data"]["kept"], true);
                    }
                }
            }
            assert_eq!(proofs.len(), 2);
            assert!(listener.poll_accept(&mut Context::from_waker(Waker::noop())).is_pending());
            assert!(cx.checkpoint().is_ok());
            assert!(!client.revocation_handle().is_revoked());
        });
    }
}

#[test]
fn public_wait_freshly_negotiates_each_get_and_shares_one_exact_response_budget() {
    for exact in [false, true] {
        run(async move {
            let cx = Cx::current().unwrap();
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let (mut client, credential, acceptor) = configured(&format!(
                "https://{}/mcp", listener.local_addr().unwrap()));
            let working = snapshot("working", 1);
            let complete = snapshot("completed", 1);
            let sizes: Vec<_> = [
                (0, true, discovery_result().to_string()), (0, false, working.clone()),
                (1, true, discovery_result().to_string()), (1, false, complete.clone()),
            ].into_iter().map(|(index, discovery, body)| {
                correlated("quota", index, discovery, &body).body.len()
            }).collect();
            let total = sizes.iter().sum::<usize>() - usize::from(!exact);
            let limits = ManagedCoreLimits::new(8192, *sizes.iter().max().unwrap(), total, 0,
                Duration::from_secs(10)).unwrap();
            let application = client.wait_task(&cx, &credential, metadata(), id(), "quota",
                polling(3), limits);
            let mut proofs = HashSet::new();
            let peer = async {
                answer_poll(&listener, &acceptor, "quota", 0, &working, &mut proofs).await;
                answer_poll(&listener, &acceptor, "quota", 1, &complete, &mut proofs).await;
            };
            let (result, ()) = pair(application, peer).await;
            if exact {
                assert!(matches!(result, Ok(DpopTaskWaitOutcome::Terminal(_))));
            } else {
                assert!(matches!(result, Err(DpopTaskWaitError::Task(DpopTasksError::Core(
                    DpopCoreError::Protocol(ManagedCoreError::ResponseByteLimit)
                )))));
            }
            assert_eq!(proofs.len(), 4, "each discovery/get uses a fresh proof");
            assert!(listener.poll_accept(&mut Context::from_waker(Waker::noop())).is_pending());
        });
    }
}

#[test]
fn public_wait_cancel_and_abandonment_release_a_later_get_without_revoking_the_session() {
    for abandon in [false, true] {
        run(async move {
            let cx = Cx::current().unwrap();
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let (mut client, credential, acceptor) = configured(&format!(
                "https://{}/mcp", listener.local_addr().unwrap()));
            let cancellation = McpRequestCancellation::new();
            let reached = McpRequestCancellation::new();
            let application = async {
                let mut call = Some(Box::pin(client.wait_task_with_cancellation(&cx, &cancellation,
                    &credential, metadata(), id(), "cancel", polling(3), ManagedCoreLimits::default())));
                let mut signal = pin!(reached.cancelled());
                let mut acted = false;
                let result = poll_fn(|task| {
                    if let Poll::Ready(value) = call.as_mut().unwrap().as_mut().poll(task) {
                        assert!(acted, "must first reach the second get's withheld body");
                        return Poll::Ready(Some(value));
                    }
                    if !acted && signal.as_mut().poll(task).is_ready() {
                        acted = true;
                        if abandon {
                            drop(call.take());
                            return Poll::Ready(None);
                        }
                        cancellation.cancel();
                    }
                    Poll::Pending
                }).await;
                drop(call);
                if abandon {
                    assert!(result.is_none());
                } else {
                    assert!(matches!(result, Some(Err(DpopTaskWaitError::Task(DpopTasksError::Core(
                        DpopCoreError::Transport(DpopHttpError::Cancelled)
                    ))))));
                }
            };
            let peer = async {
                let mut proofs = HashSet::new();
                answer_poll(&listener, &acceptor, "cancel", 0, &snapshot("working", 1), &mut proofs).await;
                let (socket, _) = listener.accept().await.unwrap();
                let mut socket = acceptor.accept(socket).await.unwrap();
                let (_, request) = read_request(&mut socket).await;
                assert_eq!(request["id"], "cancel.1.discover");
                send(&mut socket, correlated("cancel", 1, true, &discovery_result().to_string())).await;
                let (socket, _) = listener.accept().await.unwrap();
                let mut socket = acceptor.accept(socket).await.unwrap();
                let (_, request) = read_request(&mut socket).await;
                assert_eq!(request["id"], "cancel.1.get");
                assert_eq!(request["method"], TASK_GET);
                socket.write_all(b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 1024\r\nConnection: close\r\n\r\n{").await.unwrap();
                socket.flush().await.unwrap();
                reached.cancel();
                let mut byte = [0];
                assert!(!matches!(socket.read(&mut byte).await, Ok(count) if count > 0),
                    "stopped observation must release its pending TLS read");
            };
            pair(application, peer).await;
            assert!(!client.revocation_handle().is_revoked());
            assert!(cx.checkpoint().is_ok());
            // The same login can serve an independently selected observation.
            let mut proofs = HashSet::new();
            let body = snapshot("completed", 1);
            let application = client.wait_task(&cx, &credential, metadata(), id(), "fresh",
                polling(1), ManagedCoreLimits::default());
            let peer = answer_poll(&listener, &acceptor, "fresh", 0, &body, &mut proofs);
            let (result, ()) = pair(application, peer).await;
            assert!(matches!(result, Ok(DpopTaskWaitOutcome::Terminal(_))));
            assert!(listener.poll_accept(&mut Context::from_waker(Waker::noop())).is_pending());
        });
    }
}

#[test]
fn public_wait_deadline_bounds_a_long_poll_hint_without_another_discovery() {
    run(async {
        let cx = Cx::current().unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let (mut client, credential, acceptor) = configured(&format!(
            "https://{}/mcp", listener.local_addr().unwrap()));
        let limits = ManagedCoreLimits::new(8192, 8192, 32_768, 0, Duration::from_secs(1)).unwrap();
        let body = snapshot("working", 300_000);
        let mut proofs = HashSet::new();
        let application = client.wait_task(&cx, &credential, metadata(), id(), "deadline",
            polling(64), limits);
        let peer = answer_poll(&listener, &acceptor, "deadline", 0, &body, &mut proofs);
        let (result, ()) = pair(application, peer).await;
        assert!(matches!(result, Err(DpopTaskWaitError::Task(DpopTasksError::Core(
            DpopCoreError::Transport(DpopHttpError::TimedOut)
        )))));
        assert_eq!(proofs.len(), 2);
        assert!(listener.poll_accept(&mut Context::from_waker(Waker::noop())).is_pending(),
            "a long peer hint must not be clamped into an early extra poll");
        assert!(cx.checkpoint().is_ok());
    });
}
