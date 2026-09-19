//! Uses the same real OAuth/MCP TLS fixture as the manual continuation tests.
use super::*;
use std::cell::Cell;
use fastmcp_client::http_auth::rpc::interaction::ManagedInputReply;

#[cfg(feature = "tasks")]
#[path = "tasks.rs"]
mod tasks;

#[cfg(feature = "tasks")]
#[path = "task_subscriptions.rs"]
mod task_subscriptions;

#[cfg(feature = "tasks")]
#[path = "task_driver.rs"]
mod task_driver;

#[path = "catalogs.rs"]
mod catalogs;

#[path = "catalog_watch.rs"]
mod catalog_watch;

#[path = "resources.rs"]
mod resources;

#[path = "partial.rs"]
mod partial;

#[derive(Clone, Copy)]
enum DriverCase { Complete, Cancel, Timeout, Refuse, Drop }

fn isolated_driver(name: &str, case: DriverCase) {
    if let Ok(selected) = std::env::var(CHILD) {
        assert_eq!(selected, name);
        run_driver(case);
        return;
    }
    let roots = RootFile::create();
    let mut child = Command::new(std::env::current_exe().unwrap())
        .args(["--exact", name, "--nocapture", "--test-threads=1"])
        .env(CHILD, name).env("SSL_CERT_FILE", &roots.0).env_remove("SSL_CERT_DIR")
        .stdin(Stdio::null()).stdout(Stdio::inherit()).stderr(Stdio::inherit())
        .spawn().unwrap();
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        if let Some(status) = child.try_wait().unwrap() {
            assert!(status.success(), "HTTPS resolver case {name} failed");
            return;
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            panic!("HTTPS resolver case {name} exceeded its process bound");
        }
        std::thread::sleep(Duration::from_millis(10));
    }
}

fn run_driver(case: DriverCase) {
    RuntimeBuilder::current_thread().with_reactor(create_reactor().unwrap()).build().unwrap().block_on(async {
        let cx = Cx::current().unwrap();
        let scenario = async {
            let peer = Peer::new().await;
            let ((), session) = pair(peer.login(), ManagedOAuthSession::authorize(
                &cx, peer.client(), OAuthSessionPolicy::default(), browser,
            )).await;
            let session = session.unwrap();
            let cancellation = McpRequestCancellation::new();
            let timeout = if matches!(case, DriverCase::Timeout) { Duration::from_secs(1) } else { Duration::from_secs(15) };
            let core_limits = ManagedCoreLimits::new(4096, 4096, 16384, 8, timeout).unwrap();
            let limits = ManagedInteractionLimits::new(core_limits, 2, 2).unwrap();
            let (_, operation) = pair(peer.response(41, FIRST), session.start_core_interaction_with_cancellation(
                &cx, &cancellation, core("tools/call", true), RequestId::Number(41), limits,
            )).await;
            let mut operation = operation.unwrap();
            // Demonstrate handing a manually observed challenge to the driver.
            pending(&mut operation, &cx).await;
            let calls = Cell::new(0_usize);
            match case {
                DriverCase::Complete => {
                    let notifications = Cell::new(0_usize);
                    let (release_tx, mut release_rx) = oneshot::channel::<()>();
                    let mut release = Some(release_tx);
                    let server = async {
                        let second = peer.response(42, SECOND).await;
                        assert_eq!(second["params"]["requestState"], "  sealed+/%\0  ");
                        assert_eq!(second["params"]["inputResponses"], json!({"first":{"roots":[]}}));
                        let (mut tls, body) = peer.request(false).await;
                        let third: Value = serde_json::from_slice(&body).unwrap();
                        assert_eq!(third["id"], 43);
                        assert_eq!(third["params"]["inputResponses"], json!({"second":{"roots":[]}}));
                        assert!(third["params"].get("requestState").is_none());
                        sse_head(&mut tls).await;
                        event(&mut tls, CHANGED, false).await;
                        release_rx.recv(&cx).await.unwrap();
                        event(&mut tls, &terminal(43, complete("tools/call")), true).await;
                    };
                    let driven = operation.drive(&cx, |input| {
                        let round = calls.get();
                        calls.set(round + 1);
                        let name = if round == 0 { "first" } else { "second" };
                        assert_eq!(input.input_requests().unwrap().members()[0].name, name);
                        std::future::ready(Ok(ManagedInputReply {
                            request_id: RequestId::Number(42 + round as i64),
                            input_responses: Some(answers(name)),
                        }))
                    }, |_notification| {
                        notifications.set(notifications.get() + 1);
                        // The terminal is withheld until this callback runs.
                        release.take().unwrap().send(&cx, ()).unwrap();
                        Ok(())
                    });
                    let ((), result) = pair(server, driven).await;
                    assert!(result.unwrap().encode().unwrap().contains("1.20e+4"));
                    assert_eq!(calls.get(), 2);
                    assert_eq!(notifications.get(), 1);
                    assert_eq!(peer.posts.load(Ordering::SeqCst), 3);
                }
                DriverCase::Cancel | DriverCase::Timeout | DriverCase::Refuse => {
                    let result = operation.drive(&cx, |_input| {
                        calls.set(calls.get() + 1);
                        let cancellation = &cancellation;
                        async move {
                            match case {
                                DriverCase::Cancel => {
                                    cancellation.cancel();
                                    Ok(ManagedInputReply {
                                        request_id: RequestId::Number(42),
                                        input_responses: Some(answers("first")),
                                    })
                                }
                                DriverCase::Timeout => std::future::pending().await,
                                DriverCase::Refuse => Err(ManagedInteractionError::AbortedByHost),
                                _ => unreachable!(),
                            }
                        }
                    }, |_| Ok(())).await;
                    match case {
                        DriverCase::Cancel => assert!(matches!(result, Err(ManagedInteractionError::Core(ManagedCoreError::Cancelled)))),
                        DriverCase::Timeout => assert!(matches!(result, Err(ManagedInteractionError::Core(ManagedCoreError::TimedOut)))),
                        DriverCase::Refuse => assert!(matches!(result, Err(ManagedInteractionError::AbortedByHost))),
                        _ => unreachable!(),
                    }
                    assert_eq!(calls.get(), 1, "the host resolver must never be retried");
                    assert_eq!(peer.posts.load(Ordering::SeqCst), 1, "no continuation may follow a failed resolver");
                    assert!(cx.checkpoint().is_ok());
                }
                DriverCase::Drop => {
                    struct PendingResolver<'a>(&'a Cell<bool>);
                    impl Future for PendingResolver<'_> {
                        type Output = Result<ManagedInputReply, ManagedInteractionError>;
                        fn poll(self: std::pin::Pin<&mut Self>, _: &mut std::task::Context<'_>) -> Poll<Self::Output> {
                            Poll::Pending
                        }
                    }
                    impl Drop for PendingResolver<'_> {
                        fn drop(&mut self) { self.0.set(true); }
                    }
                    let dropped = Cell::new(false);
                    let mut driven = Box::pin(operation.drive(&cx, |_input| {
                        calls.set(calls.get() + 1);
                        PendingResolver(&dropped)
                    }, |_| Ok(())));
                    poll_fn(|task| {
                        assert!(driven.as_mut().poll(task).is_pending());
                        Poll::Ready(())
                    }).await;
                    assert_eq!(calls.get(), 1);
                    assert!(!dropped.get());
                    drop(driven);
                    assert!(dropped.get(), "abandonment drops the host resolver future");
                    assert!(!cancellation.is_cancel_requested());
                    assert!(cx.checkpoint().is_ok());
                    assert_eq!(peer.posts.load(Ordering::SeqCst), 1);
                }
            }
            peer.quiet();
            assert_eq!(peer.tokens.load(Ordering::SeqCst), 1);
            session.close();
        };
        asupersync::time::timeout_at(cx.now().saturating_add_nanos(20_000_000_000), scenario).await
            .expect("resolver fixture must settle within its bound");
    });
}

#[test]
fn host_driver_resolves_each_round_and_delivers_notifications() {
    isolated_driver("driver::host_driver_resolves_each_round_and_delivers_notifications", DriverCase::Complete);
}
#[test]
fn host_driver_cancellation_discards_ready_answers_before_post() {
    isolated_driver("driver::host_driver_cancellation_discards_ready_answers_before_post", DriverCase::Cancel);
}
#[test]
fn host_driver_deadline_interrupts_an_idle_resolver() {
    isolated_driver("driver::host_driver_deadline_interrupts_an_idle_resolver", DriverCase::Timeout);
}
#[test]
fn host_driver_refusal_is_not_retried() {
    isolated_driver("driver::host_driver_refusal_is_not_retried", DriverCase::Refuse);
}
#[test]
fn dropped_host_driver_releases_its_pending_resolver() {
    isolated_driver("driver::dropped_host_driver_releases_its_pending_resolver", DriverCase::Drop);
}
