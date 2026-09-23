//! Public tool catalog ownership over actual OAuth, verified TLS, and SSE.
//! Run with `cargo test -p fastmcp-client --features native-tls-roots --test oauth_tool_catalog`.
#![cfg(feature = "native-tls-roots")]

use std::process::{Command, Stdio};
use std::sync::Mutex;
use std::sync::atomic::Ordering;
use std::time::{Duration, Instant};

use asupersync::Cx;
use asupersync::channel::oneshot;
use asupersync::runtime::{RuntimeBuilder, reactor::create_reactor};
use fastmcp_client::http_auth::managed::{ManagedOAuthSession, OAuthSessionPolicy};
use fastmcp_client::http_auth::rpc::{ManagedCoreEvent, ManagedCoreLimits};
use fastmcp_client::http_auth::rpc::catalog::watch::{ManagedCatalogWatchControl, ManagedCatalogWatchOutcome};
use fastmcp_client::http_auth::tool::{ManagedToolClient, ManagedToolError};
use fastmcp_client::http_auth::tool::catalog::{
    ManagedToolCatalogError, ManagedToolCatalogEvent, ManagedToolCatalogLimits, ManagedToolCatalogSnapshot,
};
use fastmcp_core::McpRequestCancellation;
use fastmcp_protocol::{ClientCapabilities, CoreRequest, FinalRequestMeta, RequestId, ServerNotification};
use fastmcp_protocol::protocol_policy::ProtocolEra;
use serde_json::{Value, json};

#[path = "oauth_tool_catalog/peer.rs"]
mod peer;
use peer::{Peer, ROOT, browser, chunk, closed, pair};

const CHILD: &str = "FASTMCP_TEST_TOOL_CATALOG_CASE";
#[derive(Clone, Copy, PartialEq, Eq)]
enum Case { Replace, MalformedReplacement, Cancel }

fn isolated(name: &str, case: Case) {
    if let Ok(selected) = std::env::var(CHILD) {
        assert_eq!(selected, name);
        run(case);
        return;
    }
    struct Child(std::process::Child);
    impl Drop for Child {
        fn drop(&mut self) { let _ = self.0.kill(); let _ = self.0.wait(); }
    }
    let roots = std::env::temp_dir().join(format!("fastmcp-tool-catalog-{}-{name}.pem", std::process::id()));
    std::fs::write(&roots, ROOT).unwrap();
    let mut child = Child(Command::new(std::env::current_exe().unwrap())
        .args(["--exact", name, "--nocapture", "--test-threads=1"])
        .env(CHILD, name).env("SSL_CERT_FILE", roots).env_remove("SSL_CERT_DIR")
        .stdin(Stdio::null()).stdout(Stdio::inherit()).stderr(Stdio::inherit()).spawn().unwrap());
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        if let Some(status) = child.0.try_wait().unwrap() { assert!(status.success(), "tool catalog TLS case failed"); return; }
        assert!(Instant::now() < deadline, "tool catalog TLS case exceeded its process bound");
        std::thread::sleep(Duration::from_millis(10));
    }
}

fn core(method: &str, mut params: Value) -> CoreRequest {
    params["_meta"] = serde_json::to_value(FinalRequestMeta::new(ClientCapabilities::default())).unwrap();
    CoreRequest::decode(ProtocolEra::Modern2026, method, Some(&params)).unwrap()
}

fn call_request(count: i64) -> CoreRequest {
    core("tools/call", json!({"name":"calculate","arguments":{"count":count}}))
}

async fn call(tool: &ManagedToolClient, cx: &Cx, id: i64, count: i64) {
    let mut call = tool.request(cx, call_request(count), RequestId::Number(id), ManagedCoreLimits::default()).await.unwrap();
    let Some(ManagedCoreEvent::Result(result)) = call.next_event(cx).await.unwrap() else { panic!("tool result expected"); };
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
                call(&old_tool, &cx, 100, 2).await;
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
                    call(&new_tool, &cx, 101, 10).await;
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
    isolated("tool_watch_replaces_contracts_and_refuses_stale_calls", Case::Replace);
}

#[test]
fn tool_watch_invalid_replacement_refuses_all_handles() {
    isolated("tool_watch_invalid_replacement_refuses_all_handles", Case::MalformedReplacement);
}

#[test]
fn tool_watch_cancellation_keeps_login_usable() {
    isolated("tool_watch_cancellation_keeps_login_usable", Case::Cancel);
}
