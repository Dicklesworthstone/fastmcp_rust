//! Public tool catalog ownership over actual OAuth, verified TLS, and SSE.
//! Run with `cargo test -p fastmcp-client --features native-tls-roots --test oauth_tool_catalog`.
#![cfg(feature = "native-tls-roots")]

use std::cell::Cell;
use std::future::{Future, poll_fn};
use std::process::{Command, Stdio};
use std::sync::Mutex;
use std::sync::atomic::Ordering;
use std::task::Poll;
use std::time::{Duration, Instant};

use asupersync::Cx;
use asupersync::channel::oneshot;
use asupersync::runtime::{RuntimeBuilder, reactor::create_reactor};
use fastmcp_client::http_auth::managed::{ManagedOAuthSession, OAuthSessionPolicy};
use fastmcp_client::http_auth::rpc::catalog::ManagedCatalogError;
use fastmcp_client::http_auth::rpc::catalog::watch::{
    ManagedCatalogWatchControl, ManagedCatalogWatchError, ManagedCatalogWatchOutcome,
    ManagedCatalogWatchRecoveryPolicy,
};
use fastmcp_client::http_auth::rpc::{ManagedCoreError, ManagedCoreEvent, ManagedCoreLimits};
use fastmcp_client::http_auth::tool::catalog::{
    ManagedToolCatalogError, ManagedToolCatalogEvent, ManagedToolCatalogLimits,
    ManagedToolCatalogRecoveryEvent, ManagedToolCatalogSnapshot,
};
use fastmcp_client::http_auth::tool::{ManagedToolClient, ManagedToolError};
use fastmcp_core::McpRequestCancellation;
use fastmcp_protocol::protocol_policy::ProtocolEra;
use fastmcp_protocol::{
    ClientCapabilities, CoreRequest, FinalRequestMeta, RequestId, ServerNotification,
};
use serde_json::{Value, json};

#[path = "oauth_tool_catalog/peer.rs"]
mod peer;
use peer::{Peer, ROOT, browser, chunk, closed, pair};

const CHILD: &str = "FASTMCP_TEST_TOOL_CATALOG_CASE";
#[derive(Clone, Copy, PartialEq, Eq)]
enum Case {
    Replace,
    MalformedReplacement,
    Cancel,
}

fn isolated(name: &str, run_case: impl FnOnce()) {
    if let Ok(selected) = std::env::var(CHILD) {
        assert_eq!(selected, name);
        run_case();
        return;
    }
    struct Child(std::process::Child);
    impl Drop for Child {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }
    let roots = std::env::temp_dir().join(format!(
        "fastmcp-tool-catalog-{}-{name}.pem",
        std::process::id()
    ));
    std::fs::write(&roots, ROOT).unwrap();
    let mut child = Child(
        Command::new(std::env::current_exe().unwrap())
            .args(["--exact", name, "--nocapture", "--test-threads=1"])
            .env(CHILD, name)
            .env("SSL_CERT_FILE", roots)
            .env_remove("SSL_CERT_DIR")
            .stdin(Stdio::null())
            .stdout(Stdio::inherit())
            .stderr(Stdio::inherit())
            .spawn()
            .unwrap(),
    );
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        if let Some(status) = child.0.try_wait().unwrap() {
            assert!(status.success(), "tool catalog TLS case failed");
            return;
        }
        assert!(
            Instant::now() < deadline,
            "tool catalog TLS case exceeded its process bound"
        );
        std::thread::sleep(Duration::from_millis(10));
    }
}

fn core(method: &str, mut params: Value) -> CoreRequest {
    params["_meta"] =
        serde_json::to_value(FinalRequestMeta::new(ClientCapabilities::default())).unwrap();
    CoreRequest::decode(ProtocolEra::Modern2026, method, Some(&params)).unwrap()
}

fn call_request(count: i64) -> CoreRequest {
    core(
        "tools/call",
        json!({"name":"calculate","arguments":{"count":count}}),
    )
}

async fn call(tool: &ManagedToolClient, cx: &Cx, id: i64, count: i64) {
    let mut call = tool
        .request(
            cx,
            call_request(count),
            RequestId::Number(id),
            ManagedCoreLimits::default(),
        )
        .await
        .unwrap();
    let Some(ManagedCoreEvent::Result(result)) = call.next_event(cx).await.unwrap() else {
        panic!("tool result expected");
    };
    assert!(result.encode().unwrap().contains("1.20e+4"));
    assert!(call.next_event(cx).await.unwrap().is_none());
}

fn run(case: Case) {
    RuntimeBuilder::current_thread().with_reactor(create_reactor().unwrap()).build().unwrap().block_on(async {
        let cx = Cx::current().unwrap();
        asupersync::time::timeout(cx.now(), Duration::from_secs(20), Box::pin(async {
            let peer = Peer::new().await;
            let ((), session) = Box::pin(pair(peer.login(), ManagedOAuthSession::authorize(
                &cx, peer.client(), OAuthSessionPolicy::default(), browser,
            ))).await;
            let session = session.unwrap();
            let wrong = session.watch_tool_catalog(&cx, core("prompts/list", json!({})),
                ManagedToolCatalogLimits::default(), || Ok(RequestId::Number(1)), |_| Ok(ManagedCatalogWatchControl::Continue)).await;
            assert!(matches!(wrong, Err(ManagedToolCatalogError::NotToolsList)));
            peer.no_extra_connections();

            let cancellation = McpRequestCancellation::new();
            let saved = Mutex::new(Vec::<ManagedToolCatalogSnapshot>::new());
            let (first_tx, mut first_rx) = oneshot::channel::<ManagedToolCatalogSnapshot>();
            let (second_tx, mut second_rx) = oneshot::channel::<ManagedToolCatalogSnapshot>();
            let (changed_tx, mut changed_rx) = oneshot::channel::<()>();
            let (first_done, mut first_done_rx) = oneshot::channel::<()>();
            let (second_done, mut second_done_rx) = oneshot::channel::<()>();
            let mut first_tx = Some(first_tx);
            let mut second_tx = Some(second_tx);
            let mut changed_tx = Some(changed_tx);
            let mut next_id = 10;
            let mut acknowledged = false;
            let watch = session.watch_tool_catalog_with_cancellation(
                &cx, &cancellation, core("tools/list", json!({})), ManagedToolCatalogLimits::default(),
                || { let id = next_id; next_id += 1; Ok(RequestId::Number(id)) },
                |event| {
                    match event {
                        ManagedToolCatalogEvent::Acknowledged { accepted_filter } => {
                            assert!(!acknowledged);
                            acknowledged = true;
                            assert_eq!(accepted_filter.tools_list_changed, Some(true));
                        }
                        ManagedToolCatalogEvent::Notification(notification) => {
                            assert!(matches!(*notification, ServerNotification::ToolsListChanged(_)));
                            assert!(saved.lock().unwrap().last().unwrap().is_invalidated(), "invalidation must precede host notification");
                            changed_tx.take().unwrap().send(&cx, ()).unwrap();
                        }
                        ManagedToolCatalogEvent::Snapshot(snapshot) => {
                            assert!(acknowledged);
                            assert!(!snapshot.is_invalidated());
                            assert_eq!(snapshot.names().collect::<Vec<_>>(), ["calculate"]);
                            assert_eq!(snapshot.catalog().pages().len(), 1);
                            let count = { let mut saved = saved.lock().unwrap(); saved.push(snapshot.clone()); saved.len() };
                            if count == 1 {
                                first_tx.take().unwrap().send(&cx, snapshot).unwrap();
                            } else {
                                assert_eq!(count, 2);
                                second_tx.take().unwrap().send(&cx, snapshot).unwrap();
                            }
                        }
                    }
                    Ok(ManagedCatalogWatchControl::Continue)
                },
            );
            let server = async {
                let mut stream = peer.listen(10).await;
                peer.catalog(11, 1, false).await;
                peer.call(100, 2).await;
                first_done_rx.recv(&cx).await.unwrap();
                if case != Case::Cancel {
                    chunk(&mut stream, r#"{"jsonrpc":"2.0","method":"notifications/tools/list_changed"}"#, false).await;
                    peer.catalog(12, 10, case == Case::MalformedReplacement).await;
                    if case == Case::Replace {
                        peer.call(101, 10).await;
                        second_done_rx.recv(&cx).await.unwrap();
                        chunk(&mut stream, r#"{"jsonrpc":"2.0","id":10,"result":{"resultType":"complete","_meta":{"io.modelcontextprotocol/subscriptionId":10}}}"#, true).await;
                    }
                }
                closed(&mut stream).await;
            };
            let application = async {
                let first = first_rx.recv(&cx).await.unwrap();
                let old_tool = first.tool("calculate").unwrap().unwrap();
                assert!(first.tool("missing").unwrap().is_none());
                Box::pin(call(&old_tool, &cx, 100, 2)).await;
                first_done.send(&cx, ()).unwrap();
                if case == Case::Cancel { cancellation.cancel(); return; }
                changed_rx.recv(&cx).await.unwrap();
                assert!(old_tool.is_invalidated());
                assert!(matches!(first.tool("calculate"), Err(ManagedToolCatalogError::Invalidated)));
                assert!(matches!(old_tool.request(&cx, call_request(2), RequestId::Number(999), ManagedCoreLimits::default()).await,
                    Err(ManagedToolError::Invalidated)), "a stale handle must not open a POST");
                if case == Case::Replace {
                    let second = second_rx.recv(&cx).await.unwrap();
                    let new_tool = second.tool("calculate").unwrap().unwrap();
                    assert!(matches!(new_tool.request(&cx, call_request(2), RequestId::Number(998), ManagedCoreLimits::default()).await,
                        Err(ManagedToolError::InvalidArguments)), "the replacement minimum must govern the new handle");
                    Box::pin(call(&new_tool, &cx, 101, 10)).await;
                    second_done.send(&cx, ()).unwrap();
                }
            };
            let (outcome, ((), ())) = Box::pin(pair(watch, Box::pin(pair(server, application)))).await;
            match case {
                Case::Replace => assert!(matches!(outcome, Ok(ManagedCatalogWatchOutcome::SubscriptionEnded))),
                Case::MalformedReplacement => assert!(matches!(outcome, Err(ManagedToolCatalogError::Tool(ManagedToolError::InvalidInputSchema)))),
                Case::Cancel => assert!(matches!(outcome, Err(ManagedToolCatalogError::Watch(_)))),
            }
            let expected_snapshots = if case == Case::Replace { 2 } else { 1 };
            assert_eq!(saved.lock().unwrap().len(), expected_snapshots);
            assert!(saved.lock().unwrap().iter().all(ManagedToolCatalogSnapshot::is_invalidated));
            let posts = match case { Case::Replace => 5, Case::MalformedReplacement => 4, Case::Cancel => 3 };
            assert_eq!(peer.mcp_posts.load(Ordering::SeqCst), posts);
            assert_eq!(peer.token_posts.load(Ordering::SeqCst), 1);
            peer.no_extra_connections();
            assert!(cx.checkpoint().is_ok(), "local watch shutdown must not cancel the caller");
            // A fresh explicit sibling operation still uses the same login.
            let sibling = async {
                let mut call = session.request_core(&cx, core("tools/list", json!({})), RequestId::Number(900), ManagedCoreLimits::default()).await.unwrap();
                assert!(matches!(call.next_event(&cx).await.unwrap(), Some(ManagedCoreEvent::Result(_))));
            };
            Box::pin(pair(peer.catalog(900, 1, false), sibling)).await;
            assert_eq!(peer.mcp_posts.load(Ordering::SeqCst), posts + 1);
            assert_eq!(peer.token_posts.load(Ordering::SeqCst), 1);
            peer.no_extra_connections();
        })).await.expect("bounded OAuth tool catalog exchange");
    });
}

#[test]
fn tool_watch_replaces_contracts_and_refuses_stale_calls() {
    isolated(
        "tool_watch_replaces_contracts_and_refuses_stale_calls",
        || run(Case::Replace),
    );
}

#[test]
fn tool_watch_invalid_replacement_refuses_all_handles() {
    isolated(
        "tool_watch_invalid_replacement_refuses_all_handles",
        || run(Case::MalformedReplacement),
    );
}

#[test]
fn tool_watch_cancellation_keeps_login_usable() {
    isolated("tool_watch_cancellation_keeps_login_usable", || run(Case::Cancel));
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum RecoveryCase {
    Replace,
    InvalidSchema,
    RefusedAcknowledgment,
    StopAtGap,
    CancelBackoff,
    DropBackoff,
    ReconnectLimit,
}

fn run_recovery(case: RecoveryCase) {
    RuntimeBuilder::current_thread()
        .with_reactor(create_reactor().unwrap())
        .build()
        .unwrap()
        .block_on(async {
            let cx = Cx::current().unwrap();
            asupersync::time::timeout(cx.now(), Duration::from_secs(20), Box::pin(async {
                let peer = Peer::new().await;
                let ((), session) = Box::pin(pair(
                    peer.login(),
                    ManagedOAuthSession::authorize(
                        &cx, peer.client(), OAuthSessionPolicy::default(), browser,
                    ),
                )).await;
                let session = session.unwrap();
                let recovery = ManagedCatalogWatchRecoveryPolicy::new(
                    1, Duration::from_millis(250), Duration::from_millis(250),
                ).unwrap();
                let wrong = session.watch_tool_catalog_recovering(
                    &cx, core("prompts/list", json!({})),
                    ManagedToolCatalogLimits::default(), recovery,
                    || Ok(RequestId::Number(1)),
                    |_| Ok(ManagedCatalogWatchControl::Continue),
                ).await;
                assert!(matches!(wrong, Err(ManagedToolCatalogError::NotToolsList)));
                peer.no_extra_connections();

                let cancellation = McpRequestCancellation::new();
                let saved = Mutex::new(Vec::<ManagedToolCatalogSnapshot>::new());
                let stale = Mutex::new(None::<ManagedToolClient>);
                let acknowledgments = Cell::new(0);
                let gaps = Cell::new(0);
                let (first_tx, mut first_rx) = oneshot::channel::<ManagedToolCatalogSnapshot>();
                let (second_tx, mut second_rx) = oneshot::channel::<ManagedToolCatalogSnapshot>();
                let (gap_tx, mut gap_rx) = oneshot::channel::<()>();
                let (first_done, mut first_done_rx) = oneshot::channel::<()>();
                let (second_done, mut second_done_rx) = oneshot::channel::<()>();
                let mut first_tx = Some(first_tx);
                let mut second_tx = Some(second_tx);
                let mut gap_tx = Some(gap_tx);
                let mut next_id = 10;
                let watch = session.watch_tool_catalog_recovering_with_cancellation(
                    &cx, &cancellation, core("tools/list", json!({})),
                    ManagedToolCatalogLimits::default(), recovery,
                    || { let id = next_id; next_id += 1; Ok(RequestId::Number(id)) },
                    |event| {
                        match event {
                            ManagedToolCatalogRecoveryEvent::Gap { reconnect_attempt } => {
                                assert_eq!(reconnect_attempt, 1);
                                gaps.set(gaps.get() + 1);
                                assert_eq!(gaps.get(), 1);
                                assert_eq!(peer.mcp_posts.load(Ordering::SeqCst), 3,
                                    "Gap must precede the replacement listen POST");
                                assert!(saved.lock().unwrap().iter().all(
                                    ManagedToolCatalogSnapshot::is_invalidated));
                                assert!(stale.lock().unwrap().as_ref().unwrap().is_invalidated(),
                                    "issued tool handles must be revoked before host Gap effects");
                                gap_tx.take().unwrap().send(&cx, ()).unwrap();
                                if case == RecoveryCase::StopAtGap {
                                    return Ok(ManagedCatalogWatchControl::Stop);
                                }
                            }
                            ManagedToolCatalogRecoveryEvent::Watch(event) => match event {
                                ManagedToolCatalogEvent::Acknowledged { accepted_filter } => {
                                    assert_eq!(accepted_filter.tools_list_changed, Some(true));
                                    acknowledgments.set(acknowledgments.get() + 1);
                                    if acknowledgments.get() == 2 {
                                        assert_eq!(gaps.get(), 1);
                                        assert!(stale.lock().unwrap().as_ref().unwrap().is_invalidated());
                                    }
                                }
                                ManagedToolCatalogEvent::Notification(_) => {
                                    panic!("the peer sent an interruption, not a change notification");
                                }
                                ManagedToolCatalogEvent::Snapshot(snapshot) => {
                                    assert!(!snapshot.is_invalidated());
                                    assert_eq!(snapshot.names().collect::<Vec<_>>(), ["calculate"]);
                                    let count = {
                                        let mut saved = saved.lock().unwrap();
                                        saved.push(snapshot.clone());
                                        saved.len()
                                    };
                                    assert_eq!(acknowledgments.get(), count,
                                        "a fresh ACK must precede each recovered snapshot");
                                    if count == 1 {
                                        first_tx.take().unwrap().send(&cx, snapshot).unwrap();
                                    } else {
                                        assert_eq!(count, 2);
                                        second_tx.take().unwrap().send(&cx, snapshot).unwrap();
                                    }
                                }
                            },
                        }
                        Ok(ManagedCatalogWatchControl::Continue)
                    },
                );
                let driver = async {
                    let mut watch = Box::pin(watch);
                    if case == RecoveryCase::DropBackoff {
                        poll_fn(|task| {
                            assert!(watch.as_mut().poll(task).is_pending(),
                                "recovery must await its nonzero backoff");
                            if gaps.get() == 1 { Poll::Ready(()) } else { Poll::Pending }
                        }).await;
                        drop(watch);
                        None
                    } else {
                        Some(watch.await)
                    }
                };
                let server = async {
                    let stream = peer.listen(10).await;
                    peer.catalog(11, 1, false).await;
                    peer.call(100, 2).await;
                    first_done_rx.recv(&cx).await.unwrap();
                    drop(stream);
                    if matches!(case, RecoveryCase::StopAtGap
                        | RecoveryCase::CancelBackoff | RecoveryCase::DropBackoff)
                    {
                        return;
                    }
                    let mut stream = peer.listen_with_coverage(
                        12, case != RecoveryCase::RefusedAcknowledgment,
                    ).await;
                    if case == RecoveryCase::RefusedAcknowledgment {
                        closed(&mut stream).await;
                        return;
                    }
                    peer.catalog(13, 10, case == RecoveryCase::InvalidSchema).await;
                    if case == RecoveryCase::InvalidSchema {
                        closed(&mut stream).await;
                        return;
                    }
                    peer.call(101, 10).await;
                    second_done_rx.recv(&cx).await.unwrap();
                    if case == RecoveryCase::ReconnectLimit {
                        drop(stream);
                    } else {
                        chunk(&mut stream, r#"{"jsonrpc":"2.0","id":12,"result":{"resultType":"complete","_meta":{"io.modelcontextprotocol/subscriptionId":12}}}"#, true).await;
                        closed(&mut stream).await;
                    }
                };
                let application = async {
                    let first = first_rx.recv(&cx).await.unwrap();
                    let old_tool = first.tool("calculate").unwrap().unwrap();
                    *stale.lock().unwrap() = Some(old_tool.clone());
                    Box::pin(call(&old_tool, &cx, 100, 2)).await;
                    first_done.send(&cx, ()).unwrap();
                    gap_rx.recv(&cx).await.unwrap();
                    assert!(first.is_invalidated());
                    assert!(matches!(first.tool("calculate"),
                        Err(ManagedToolCatalogError::Invalidated)));
                    assert!(matches!(old_tool.request(
                        &cx, call_request(2), RequestId::Number(999), ManagedCoreLimits::default(),
                    ).await, Err(ManagedToolError::Invalidated)),
                        "a pre-gap handle cannot open a new POST during recovery");
                    if case == RecoveryCase::CancelBackoff {
                        asupersync::time::sleep(cx.now(), Duration::from_millis(20)).await;
                        assert_eq!(peer.mcp_posts.load(Ordering::SeqCst), 3);
                        cancellation.cancel();
                    }
                    if matches!(case, RecoveryCase::Replace | RecoveryCase::ReconnectLimit) {
                        let second = second_rx.recv(&cx).await.unwrap();
                        let new_tool = second.tool("calculate").unwrap().unwrap();
                        assert!(!new_tool.is_invalidated());
                        assert!(old_tool.is_invalidated());
                        assert!(matches!(new_tool.request(
                            &cx, call_request(2), RequestId::Number(998), ManagedCoreLimits::default(),
                        ).await, Err(ManagedToolError::InvalidArguments)),
                            "recovery must bind the changed schema before exposing a handle");
                        Box::pin(call(&new_tool, &cx, 101, 10)).await;
                        second_done.send(&cx, ()).unwrap();
                    }
                };
                let (outcome, ((), ())) = Box::pin(pair(driver, Box::pin(pair(server, application)))).await;
                let posts = match case {
                    RecoveryCase::Replace => {
                        assert!(matches!(outcome,
                            Some(Ok(ManagedCatalogWatchOutcome::SubscriptionEnded))));
                        6
                    }
                    RecoveryCase::ReconnectLimit => {
                        assert!(matches!(outcome, Some(Err(ManagedToolCatalogError::Watch(
                            ManagedCatalogWatchError::ReconnectLimit)))));
                        6
                    }
                    RecoveryCase::InvalidSchema => {
                        assert!(matches!(outcome, Some(Err(ManagedToolCatalogError::Tool(
                            ManagedToolError::InvalidInputSchema)))));
                        5
                    }
                    RecoveryCase::RefusedAcknowledgment => {
                        assert!(matches!(outcome, Some(Err(ManagedToolCatalogError::Watch(
                            ManagedCatalogWatchError::CoverageRefused)))));
                        4
                    }
                    RecoveryCase::StopAtGap => {
                        assert!(matches!(outcome,
                            Some(Ok(ManagedCatalogWatchOutcome::StoppedByHost))));
                        3
                    }
                    RecoveryCase::CancelBackoff => {
                        assert!(matches!(outcome, Some(Err(ManagedToolCatalogError::Watch(
                            ManagedCatalogWatchError::Catalog(ManagedCatalogError::Core(
                                ManagedCoreError::Cancelled,
                            )),
                        )))));
                        3
                    }
                    RecoveryCase::DropBackoff => {
                        assert!(outcome.is_none());
                        3
                    }
                };
                assert_eq!(gaps.get(), 1);
                let expected_snapshots = if matches!(case,
                    RecoveryCase::Replace | RecoveryCase::ReconnectLimit) { 2 } else { 1 };
                assert_eq!(saved.lock().unwrap().len(), expected_snapshots);
                assert!(saved.lock().unwrap().iter().all(ManagedToolCatalogSnapshot::is_invalidated));
                assert!(stale.lock().unwrap().as_ref().unwrap().is_invalidated());
                assert_eq!(peer.mcp_posts.load(Ordering::SeqCst), posts);
                assert_eq!(peer.token_posts.load(Ordering::SeqCst), 1);
                peer.no_extra_connections();
                assert!(cx.checkpoint().is_ok());
                let sibling = async {
                    let mut response = session.request_core(
                        &cx, core("tools/list", json!({})), RequestId::Number(900),
                        ManagedCoreLimits::default(),
                    ).await.unwrap();
                    assert!(matches!(response.next_event(&cx).await.unwrap(),
                        Some(ManagedCoreEvent::Result(_))));
                };
                Box::pin(pair(peer.catalog(900, 1, false), sibling)).await;
                assert_eq!(peer.mcp_posts.load(Ordering::SeqCst), posts + 1);
                assert_eq!(peer.token_posts.load(Ordering::SeqCst), 1);
                peer.no_extra_connections();
            })).await.expect("bounded recovering tool catalog exchange");
        });
}

#[test]
fn tool_watch_recovery_replaces_handles_only_after_fresh_ack_and_schema() {
    isolated("tool_watch_recovery_replaces_handles_only_after_fresh_ack_and_schema",
        || run_recovery(RecoveryCase::Replace));
}

#[test]
fn tool_watch_recovery_invalid_schema_keeps_all_old_handles_revoked() {
    isolated("tool_watch_recovery_invalid_schema_keeps_all_old_handles_revoked",
        || run_recovery(RecoveryCase::InvalidSchema));
}

#[test]
fn tool_watch_recovery_refused_ack_never_collects_a_replacement() {
    isolated("tool_watch_recovery_refused_ack_never_collects_a_replacement",
        || run_recovery(RecoveryCase::RefusedAcknowledgment));
}

#[test]
fn tool_watch_recovery_stop_at_gap_never_reconnects() {
    isolated("tool_watch_recovery_stop_at_gap_never_reconnects",
        || run_recovery(RecoveryCase::StopAtGap));
}

#[test]
fn tool_watch_recovery_cancel_and_drop_backoff_keep_login_usable() {
    isolated("tool_watch_recovery_cancel_and_drop_backoff_keep_login_usable", || {
        run_recovery(RecoveryCase::CancelBackoff);
        run_recovery(RecoveryCase::DropBackoff);
    });
}

#[test]
fn tool_watch_recovery_cannot_reset_the_reconnect_budget_after_a_snapshot() {
    isolated("tool_watch_recovery_cannot_reset_the_reconnect_budget_after_a_snapshot",
        || run_recovery(RecoveryCase::ReconnectLimit));
}
