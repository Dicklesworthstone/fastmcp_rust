//! Public catalog-watch tests sharing the real OAuth/MCP loopback TLS fixture.
//! No mock transport: acknowledgment, list pages, changes and interrupted reads
//! traverse native HTTP/SSE. The parent target requires native-tls-roots.
use super::*;
use fastmcp_client::http_auth::managed::OAuthSessionError;
use fastmcp_client::http_auth::managed::subscriptions::ManagedSubscriptionError;
use fastmcp_client::http_auth::rpc::catalog::watch::{
    ManagedCatalogWatchControl as Control, ManagedCatalogWatchError as WatchError,
    ManagedCatalogWatchEvent as WatchEvent, ManagedCatalogWatchLimits,
    ManagedCatalogWatchOutcome as Outcome, ManagedCatalogWatchRecoveryEvent as RecoveryEvent,
    ManagedCatalogWatchRecoveryPolicy as RecoveryPolicy,
};
use fastmcp_client::http_auth::rpc::catalog::{
    ManagedCatalogClient, ManagedCatalogConsistency, ManagedCatalogError, ManagedCatalogLimits,
};
use fastmcp_protocol::{ClientCapabilities, FINAL_SUBSCRIPTION_ID_META_KEY, FinalRequestMeta};

const WATCH_CHILD: &str = "FASTMCP_TEST_CATALOG_WATCH_CASE";

#[derive(Clone, Copy)]
enum WatchCase {
    Live,
    Resources,
    Templates,
    Prompts,
    DuringPage,
    ChangeOnPage,
    PageHostFailure,
    PageHostStop,
    NarrowAck,
    Gap,
    Terminal,
    PeerCancellation,
    ForeignCancellation,
    Malformed,
    RebuildLimit,
    RepeatedId,
    Cancel,
    SessionClose,
    Drop,
    Timeout,
    Expired,
    StopAck,
    Preflight,
    Revoked,
    CallbackOverrun,
    ScopedCache,
    ClearPublication,
    WholeLive,
    WholeClearPublication,
}

fn isolated_watch(name: &str, case: WatchCase) {
    isolated_catalog_case(name, || run_watch(case));
}

fn isolated_catalog_case(name: &str, run: impl FnOnce()) {
    if let Ok(selected) = std::env::var(WATCH_CHILD) {
        assert_eq!(selected, name);
        run();
        return;
    }
    let roots = RootFile::create();
    struct Child(std::process::Child);
    impl Drop for Child {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }
    let exact = format!("driver::catalog_watch::{name}");
    let mut child = Child(
        Command::new(std::env::current_exe().unwrap())
            .args(["--exact", &exact, "--nocapture", "--test-threads=1"])
            .env(WATCH_CHILD, name)
            .env("SSL_CERT_FILE", &roots.0)
            .env_remove("SSL_CERT_DIR")
            .stdin(Stdio::null())
            .stdout(Stdio::inherit())
            .stderr(Stdio::inherit())
            .spawn()
            .unwrap(),
    );
    let until = Instant::now() + Duration::from_secs(30);
    loop {
        if let Some(status) = child.0.try_wait().unwrap() {
            assert!(status.success(), "catalog watch HTTPS case failed");
            return;
        }
        assert!(
            Instant::now() < until,
            "catalog watch child exceeded its process bound"
        );
        std::thread::sleep(Duration::from_millis(10));
    }
}

fn request(method: &str) -> CoreRequest {
    CoreRequest::decode(
        ProtocolEra::Modern2026,
        method,
        Some(&json!({
            "_meta": FinalRequestMeta::new(ClientCapabilities::default()),
            "includeTags":["selected"], "excludeTags":[],
        })),
    )
    .unwrap()
}

fn filter(method: &str) -> Value {
    match method {
        "tools/list" => json!({"toolsListChanged":true}),
        "resources/list" | "resources/templates/list" => json!({"resourcesListChanged":true}),
        "prompts/list" => json!({"promptsListChanged":true}),
        _ => unreachable!(),
    }
}

fn notification(method: &str) -> String {
    let name = match method {
        "tools/list" => "notifications/tools/list_changed",
        "resources/list" | "resources/templates/list" => "notifications/resources/list_changed",
        "prompts/list" => "notifications/prompts/list_changed",
        _ => unreachable!(),
    };
    json!({"jsonrpc":"2.0","method":name}).to_string()
}

fn subscription_notification(method: &str) -> String {
    let mut value: Value = serde_json::from_str(&notification(method)).unwrap();
    value["params"] = json!({"_meta":{(FINAL_SUBSCRIPTION_ID_META_KEY):1}});
    value.to_string()
}

fn ack(accepted: Value) -> String {
    json!({"jsonrpc":"2.0","method":"notifications/subscriptions/acknowledged",
        "params":{"_meta":{(FINAL_SUBSCRIPTION_ID_META_KEY):1},"notifications":accepted}})
    .to_string()
}

fn page(method: &str, name: &str, next: Option<&str>) -> String {
    let (key, item) = match method {
        "tools/list" => (
            "tools",
            json!({"name":name,"inputSchema":{"type":"object"}}),
        ),
        "resources/list" => (
            "resources",
            json!({"name":name,"uri":format!("file:///{name}")}),
        ),
        "resources/templates/list" => (
            "resourceTemplates",
            json!({"name":name,"uriTemplate":format!("file:///{name}/{{key}}")}),
        ),
        "prompts/list" => ("prompts", json!({"name":name})),
        _ => unreachable!(),
    };
    let cursor = next.map_or(String::new(), |next| {
        format!(",\"nextCursor\":{}", serde_json::to_string(next).unwrap())
    });
    format!(
        r#"{{"resultType":"complete","{key}":[{item}],"ttlMs":60000,"cacheScope":"private"{cursor},"x-exact":{{"z":900719925474099312345,"a":1.20e+4}}}}"#
    )
}

async fn accept_listen(peer: &Peer, cx: &Cx, method: &str) -> TlsStream<TcpStream> {
    let (mut tls, body) = peer.request(false).await;
    let wire: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(wire["id"], 1);
    assert_eq!(wire["method"], "subscriptions/listen");
    assert_eq!(wire["params"]["notifications"], filter(method));
    assert_eq!(
        wire["params"]["_meta"],
        request(method).encode_params().unwrap().unwrap()["_meta"]
    );
    assert!(wire["params"].get("includeTags").is_none());
    sse_head(&mut tls).await;
    tls.flush().await.unwrap();
    Sleep::new(cx.now().saturating_add_nanos(20_000_000)).await;
    peer.quiet(); // No list is allowed before the acknowledgment exists.
    tls
}

async fn accept_page(
    peer: &Peer,
    method: &str,
    id: i64,
    cursor: Option<&str>,
) -> TlsStream<TcpStream> {
    let (tls, body) = peer.request(false).await;
    let wire: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(wire["id"], id);
    assert_eq!(wire["method"], method);
    let mut expected = request(method).encode_params().unwrap().unwrap();
    if let Some(cursor) = cursor {
        expected["cursor"] = json!(cursor);
    }
    assert_eq!(wire["params"], expected);
    tls
}

async fn serve_page(
    peer: &Peer,
    method: &str,
    id: i64,
    cursor: Option<&str>,
    name: &str,
    next: Option<&str>,
) {
    let mut tls = accept_page(peer, method, id, cursor).await;
    json_reply(&mut tls, &terminal(id, &page(method, name, next))).await;
}

async fn closed(mut tls: TlsStream<TcpStream>) {
    let mut byte = [0];
    assert!(
        !matches!(tls.read(&mut byte).await, Ok(count) if count > 0),
        "the driver must release its response socket"
    );
}

async fn closed_without_request(peer: &Peer, tls: TlsStream<TcpStream>) {
    let mut closing = Box::pin(closed(tls));
    poll_fn(|task| {
        assert!(
            peer.listener.poll_accept(task).is_pending(),
            "a host failure or stop must not start another request"
        );
        closing.as_mut().poll(task)
    })
    .await;
}

fn run_watch(case: WatchCase) {
    RuntimeBuilder::current_thread().with_reactor(create_reactor().unwrap()).build().unwrap().block_on(Box::pin(async {
        let cx = Cx::current().unwrap();
        let scenario = Box::pin(async {
            let peer = Peer::new().await;
            let login = async {
                let (mut tls, _) = peer.request(true).await;
                let seconds = if matches!(case, WatchCase::Expired) { 2 } else { 300 };
                json_reply(&mut tls, &json!({"access_token":"interaction-access","token_type":"Bearer",
                    "expires_in":seconds,"refresh_token":"interaction-refresh"}).to_string()).await;
            };
            let policy = OAuthSessionPolicy::new(Duration::ZERO, Duration::from_secs(30), Duration::from_secs(15), 64).unwrap();
            let ((), session) = pair(Box::pin(login), Box::pin(ManagedOAuthSession::authorize(&cx, peer.client(), policy, browser))).await;
            let session = session.unwrap();
            let credential = session.credential(&cx).await.unwrap();
            let limits = ManagedCatalogLimits::new(ManagedCoreLimits::new(4096,4096,65536,16,Duration::from_secs(15)).unwrap(), 16, 128, 16384).unwrap();
            let client = ManagedCatalogClient::new(session.clone(), limits).with_cache_limits(16, 1048576).unwrap();
            let client = if matches!(case, WatchCase::WholeLive | WatchCase::WholeClearPublication) {
                client.with_consistency(ManagedCatalogConsistency::RefreshWholeCatalog { maximum_rebuilds: 1 }).unwrap()
            } else { client };
            let method = match case {
                WatchCase::Resources => "resources/list",
                WatchCase::Templates => "resources/templates/list",
                WatchCase::Prompts => "prompts/list",
                _ => "tools/list",
            };
            if matches!(case, WatchCase::Live | WatchCase::WholeLive | WatchCase::ScopedCache) {
                let warm_method = if matches!(case, WatchCase::ScopedCache) { "prompts/list" } else { method };
                let ((), result) = pair(Box::pin(serve_page(&peer, warm_method, 90, None, "old-cache", None)),
                    Box::pin(client.collect(&cx, request(warm_method), || Ok(RequestId::Number(90)), |_| Ok(())))).await;
                assert_eq!(result.unwrap().item_count(), 1);
            }
            let snapshots = Cell::new(0_usize);
            let notices = Cell::new(0_usize);
            let acknowledgments = Cell::new(0_usize);
            let ids = Cell::new(0_i64);
            let cancellation = McpRequestCancellation::new();
            let (first_tx, mut first_rx) = oneshot::channel::<()>();
            let mut first_tx = Some(first_tx);
            let watch_limits = ManagedCatalogWatchLimits::new(
                if matches!(case, WatchCase::Timeout | WatchCase::CallbackOverrun) { Duration::from_secs(1) } else { Duration::from_secs(15) },
                if matches!(case, WatchCase::RebuildLimit) { 1 } else { 8 }, 64, 16384, 128,
            ).unwrap();
            let server = Box::pin(async {
                if matches!(case, WatchCase::Preflight) { return; }
                let mut listen = accept_listen(&peer, &cx, method).await;
                event(&mut listen, &ack(if matches!(case, WatchCase::NarrowAck) { json!({}) } else { filter(method) }), false).await;
                if matches!(case, WatchCase::NarrowAck | WatchCase::RepeatedId | WatchCase::StopAck | WatchCase::CallbackOverrun | WatchCase::ScopedCache) {
                    closed(listen).await;
                    return;
                }
                if matches!(case, WatchCase::Gap) {
                    let page = accept_page(&peer, method, 2, None).await;
                    drop(listen); // Unannounced gap while the first list is pending.
                    closed(page).await;
                    return;
                }
                if matches!(case, WatchCase::DuringPage | WatchCase::RebuildLimit) {
                    serve_page(&peer, method, 2, None, "obsolete-one", Some("old-tail")).await;
                    let page = accept_page(&peer, method, 3, Some("old-tail")).await;
                    event(&mut listen, &subscription_notification(method), false).await;
                    closed(page).await; // Invalidation must wake an idle list response.
                    if matches!(case, WatchCase::DuringPage) {
                        serve_page(&peer, method, 4, None, "fresh-one", Some("")).await;
                        serve_page(&peer, method, 5, Some(""), "fresh-two", None).await;
                    }
                    closed(listen).await;
                    return;
                }
                if matches!(case, WatchCase::ChangeOnPage | WatchCase::PageHostFailure | WatchCase::PageHostStop) {
                    let mut page = accept_page(&peer, method, 2, None).await;
                    sse_head(&mut page).await;
                    event(&mut page, &notification(method), false).await;
                    closed(page).await;
                    if matches!(case, WatchCase::PageHostFailure | WatchCase::PageHostStop) {
                        closed_without_request(&peer, listen).await;
                        return;
                    }
                    serve_page(&peer, method, 3, None, "fresh-one", None).await;
                    closed(listen).await;
                    return;
                }
                if matches!(case, WatchCase::Malformed) {
                    let mut page = accept_page(&peer, method, 2, None).await;
                    json_reply(&mut page, &terminal(2, r#"{"resultType":"complete","wrong":[],"ttlMs":0,"cacheScope":"private"}"#)).await;
                    drop(page);
                    closed(listen).await;
                    return;
                }
                serve_page(&peer, method, 2, None, "first", None).await;
                if matches!(case, WatchCase::ClearPublication | WatchCase::WholeClearPublication) {
                    closed(listen).await;
                    return;
                }
                first_rx.recv(&cx).await.unwrap();
                if matches!(case, WatchCase::Live | WatchCase::WholeLive | WatchCase::Resources | WatchCase::Templates | WatchCase::Prompts) {
                    // The first snapshot has already reached the host while the
                    // original pending listen read must remain open and usable.
                    event(&mut listen, &subscription_notification(method), false).await;
                    serve_page(&peer, method, 3, None, "second", None).await;
                } else if matches!(case, WatchCase::Terminal) {
                    event(&mut listen, &terminal(1, &json!({"resultType":"complete",
                        "_meta":{(FINAL_SUBSCRIPTION_ID_META_KEY):1}}).to_string()), true).await;
                    return;
                } else if matches!(case, WatchCase::PeerCancellation | WatchCase::ForeignCancellation) {
                    event(&mut listen, &json!({"jsonrpc":"2.0", "method":"notifications/cancelled", "params":{
                        "requestId":1, "reason":"watch maintenance",
                        "_meta":{(FINAL_SUBSCRIPTION_ID_META_KEY):if matches!(case, WatchCase::ForeignCancellation) { 99 } else { 1 }}
                    }}).to_string(), false).await;
                }
                closed(listen).await;
            });
            let application = Box::pin(async {
                if matches!(case, WatchCase::Preflight) {
                    let mut params = request(method).encode_params().unwrap().unwrap();
                    params["cursor"] = json!("");
                    let suffix = CoreRequest::decode(ProtocolEra::Modern2026, method, Some(&params)).unwrap();
                    assert!(matches!(Box::pin(client.watch(&cx, suffix, watch_limits, || panic!("no IDs before preflight"), |_| Ok(Control::Stop))).await, Err(WatchError::CursorNotAllowed)));
                    assert!(matches!(Box::pin(client.watch(&cx, core("tools/call", false), watch_limits, || panic!("no IDs for non-catalog"), |_| Ok(Control::Stop))).await, Err(WatchError::Catalog(ManagedCatalogError::NotCatalog))));
                    cancellation.cancel();
                    assert!(Box::pin(client.watch_with_cancellation(&cx, &cancellation, request(method), watch_limits, || panic!("no IDs after cancellation"), |_| Ok(Control::Stop))).await.is_err());
                    return;
                }
                let mut watching = Box::pin(client.watch_with_cancellation(&cx, &cancellation, request(method), watch_limits,
                    || {
                        let id = ids.get() + 1; ids.set(id);
                        if matches!(case, WatchCase::RepeatedId) && id == 2 { Ok(serde_json::from_str("1e0").unwrap()) }
                        else { Ok(RequestId::Number(id)) }
                    },
                    |event| {
                        // Watch observers are not invoked under the cache lock.
                        let _ = client.cache_stats().unwrap();
                        match event {
                            WatchEvent::Acknowledged { accepted_filter } => {
                                acknowledgments.set(acknowledgments.get() + 1);
                                assert_eq!(serde_json::to_value(accepted_filter).unwrap(), filter(method));
                                if matches!(case, WatchCase::CallbackOverrun) { std::thread::sleep(Duration::from_millis(1100)); }
                                if matches!(case, WatchCase::StopAck | WatchCase::ScopedCache) { return Ok(Control::Stop); }
                            }
                            WatchEvent::Notification(_) => {
                                notices.set(notices.get() + 1);
                                assert!(client.cache_stats().unwrap().invalidations > 0);
                                if matches!(case, WatchCase::PageHostFailure) {
                                    return Err(ManagedCatalogError::AbortedByHost);
                                }
                                if matches!(case, WatchCase::PageHostStop) {
                                    return Ok(Control::Stop);
                                }
                            }
                            WatchEvent::Snapshot(catalog) => {
                                let count = snapshots.get() + 1;
                                snapshots.set(count);
                                assert_eq!(acknowledgments.get(), 1);
                                assert_eq!(catalog.method(), method);
                                assert_eq!(catalog.credential_generation(), 1);
                                let expected_items = if matches!(case, WatchCase::DuringPage) { 2 } else { 1 };
                                assert_eq!(catalog.item_count(), expected_items);
                                for page in catalog.pages() {
                                    let encoded = page.encode().unwrap();
                                    assert!(encoded.contains("900719925474099312345") && encoded.contains("1.20e+4"));
                                    assert!(!encoded.contains("old-cache") && !encoded.contains("obsolete"));
                                    if matches!(case, WatchCase::DuringPage | WatchCase::ChangeOnPage) { assert!(encoded.contains("fresh-")); }
                                }
                                if let Some(sender) = first_tx.take() { sender.send(&cx, ()).unwrap(); }
                                if matches!(case, WatchCase::Revoked) { credential.credential().revoke(); }
                                if matches!(case, WatchCase::DuringPage | WatchCase::ChangeOnPage) || count == 2 { return Ok(Control::Stop); }
                            }
                        }
                        Ok(Control::Continue)
                    },
                ));
                if matches!(case, WatchCase::ClearPublication | WatchCase::WholeClearPublication) {
                    poll_fn(|task| {
                        assert!(watching.as_mut().poll(task).is_pending());
                        if client.cache_stats().unwrap().fills == 1 { Poll::Ready(()) } else { Poll::Pending }
                    }).await;
                    assert_eq!(snapshots.get(), 0, "completed pages remain private during the publication yield");
                    client.clear().unwrap();
                }
                if matches!(case, WatchCase::Cancel | WatchCase::SessionClose | WatchCase::Drop) {
                    poll_fn(|task| {
                        assert!(watching.as_mut().poll(task).is_pending());
                        if snapshots.get() == 1 { Poll::Ready(()) } else { Poll::Pending }
                    }).await;
                    match case {
                        WatchCase::Cancel => { cancellation.cancel(); },
                        WatchCase::SessionClose => session.close(),
                        WatchCase::Drop => { drop(watching); return; },
                        _ => unreachable!(),
                    }
                }
                let result = watching.await;
                match case {
                    WatchCase::Live | WatchCase::WholeLive | WatchCase::Resources | WatchCase::Templates | WatchCase::Prompts | WatchCase::DuringPage | WatchCase::ChangeOnPage | WatchCase::PageHostStop | WatchCase::StopAck | WatchCase::ScopedCache => {
                        assert_eq!(result.unwrap(), Outcome::StoppedByHost);
                    }
                    WatchCase::PageHostFailure => {
                        assert!(matches!(result, Err(WatchError::Catalog(ManagedCatalogError::AbortedByHost))));
                    }
                    WatchCase::Terminal | WatchCase::PeerCancellation => assert_eq!(result.unwrap(), Outcome::SubscriptionEnded),
                    WatchCase::ForeignCancellation => assert!(matches!(result, Err(WatchError::Subscription(fastmcp_client::http_auth::managed::subscriptions::ManagedSubscriptionError::InvalidResponse)))),
                    WatchCase::NarrowAck => assert!(matches!(result, Err(WatchError::CoverageRefused))),
                    WatchCase::RebuildLimit => assert!(matches!(result, Err(WatchError::CollectionLimit))),
                    WatchCase::RepeatedId => assert!(matches!(result, Err(WatchError::Catalog(ManagedCatalogError::RepeatedRequestId)))),
                    WatchCase::Malformed => assert!(matches!(result, Err(WatchError::Catalog(ManagedCatalogError::Core(ManagedCoreError::InvalidResult))))),
                    WatchCase::Timeout | WatchCase::CallbackOverrun => assert!(matches!(result, Err(WatchError::Catalog(ManagedCatalogError::Core(ManagedCoreError::TimedOut))))),
                    WatchCase::Cancel => assert!(matches!(result, Err(WatchError::Catalog(ManagedCatalogError::Core(ManagedCoreError::Cancelled))))),
                    WatchCase::Revoked => assert!(matches!(result, Err(WatchError::Catalog(ManagedCatalogError::CredentialRevoked)))),
                    WatchCase::ClearPublication | WatchCase::WholeClearPublication => {
                        assert!(matches!(result, Err(WatchError::Catalog(ManagedCatalogError::Invalidated))));
                        assert_eq!(snapshots.get(), 0, "an externally invalidated candidate must never be published");
                        assert_eq!(ids.get(), 2, "an external clear cannot trigger a hidden refetch");
                    }
                    WatchCase::SessionClose => assert!(matches!(result,
                        Err(WatchError::Catalog(ManagedCatalogError::CredentialRevoked)
                        | WatchError::Subscription(fastmcp_client::http_auth::managed::subscriptions::ManagedSubscriptionError::Session(OAuthSessionError::Closed)))
                    )),
                    WatchCase::Gap | WatchCase::Expired => assert!(result.is_err()),
                    WatchCase::Drop | WatchCase::Preflight => unreachable!(),
                }
            });
            pair(server, application).await;
            assert!(cx.checkpoint().is_ok(), "watch cancellation does not cancel its caller context");
            let expected = match case {
                WatchCase::Live | WatchCase::WholeLive => 4,
                WatchCase::Resources | WatchCase::Templates | WatchCase::Prompts | WatchCase::ChangeOnPage | WatchCase::RebuildLimit => 3,
                WatchCase::DuringPage => 5,
                WatchCase::NarrowAck | WatchCase::RepeatedId | WatchCase::StopAck | WatchCase::CallbackOverrun => 1,
                WatchCase::Preflight => 0,
                _ => 2,
            };
            assert_eq!(peer.posts.load(Ordering::SeqCst), expected);
            assert_eq!(peer.tokens.load(Ordering::SeqCst), 1);
            peer.quiet(); // No automatic resubscribe, refresh or arbitrary retry.
            if matches!(case, WatchCase::PageHostFailure | WatchCase::PageHostStop) {
                assert_eq!(notices.get(), 1);
                assert_eq!(snapshots.get(), 0);
                assert_eq!(ids.get(), 2);
                assert_eq!(client.cache_stats().unwrap().fills, 0);
            }
            if matches!(case, WatchCase::ScopedCache) {
                let cached = Box::pin(client.collect(&cx, request("prompts/list"), || panic!("unrelated catalog was not cleared"), |_| Ok(()))).await.unwrap();
                assert_eq!(cached.item_count(), 1);
            }
            if matches!(case, WatchCase::Live | WatchCase::Terminal | WatchCase::PeerCancellation | WatchCase::Drop) {
                // Exit invalidates even on a graceful stop: no cached snapshot
                // can bridge the gap until the caller explicitly fetches again.
                let ((), result) = pair(Box::pin(serve_page(&peer, method, 80, None, "after-gap", None)),
                    Box::pin(client.collect(&cx, request(method), || Ok(RequestId::Number(80)), |_| Ok(())))).await;
                assert!(result.unwrap().pages()[0].encode().unwrap().contains("after-gap"));
                assert_eq!(peer.posts.load(Ordering::SeqCst), expected + 1);
            }
            session.close();
        });
        asupersync::time::timeout_at(cx.now().saturating_add_nanos(20_000_000_000), scenario).await.expect("catalog watch TLS fixture must settle");
    }));
}

#[test]
fn tools_watch_refreshes_live_and_discards_preexisting_cache() {
    isolated_watch(
        "tools_watch_refreshes_live_and_discards_preexisting_cache",
        WatchCase::Live,
    );
}
#[test]
fn resources_watch_uses_resource_catalog_changes() {
    isolated_watch(
        "resources_watch_uses_resource_catalog_changes",
        WatchCase::Resources,
    );
}
#[test]
fn templates_watch_uses_resource_catalog_changes() {
    isolated_watch(
        "templates_watch_uses_resource_catalog_changes",
        WatchCase::Templates,
    );
}
#[test]
fn prompts_watch_uses_prompt_catalog_changes() {
    isolated_watch(
        "prompts_watch_uses_prompt_catalog_changes",
        WatchCase::Prompts,
    );
}
#[test]
fn change_during_pagination_cancels_obsolete_page_and_restarts_from_first() {
    isolated_watch(
        "change_during_pagination_cancels_obsolete_page_and_restarts_from_first",
        WatchCase::DuringPage,
    );
}
#[test]
fn change_on_a_catalog_response_reconciles_without_restarting_the_listen() {
    isolated_watch(
        "change_on_a_catalog_response_reconciles_without_restarting_the_listen",
        WatchCase::ChangeOnPage,
    );
}

#[test]
fn catalog_page_notification_host_failure_and_stop_end_the_watch() {
    isolated_catalog_case(
        "catalog_page_notification_host_failure_and_stop_end_the_watch",
        || {
            run_watch(WatchCase::PageHostFailure);
            run_watch(WatchCase::PageHostStop);
        },
    );
}
#[test]
fn missing_acknowledgment_coverage_prevents_any_list_post() {
    isolated_watch(
        "missing_acknowledgment_coverage_prevents_any_list_post",
        WatchCase::NarrowAck,
    );
}
#[test]
fn subscription_gap_cancels_pending_list_and_never_publishes_partial_state() {
    isolated_watch(
        "subscription_gap_cancels_pending_list_and_never_publishes_partial_state",
        WatchCase::Gap,
    );
}
#[test]
fn graceful_subscription_end_does_not_bridge_cache_across_the_gap() {
    isolated_watch(
        "graceful_subscription_end_does_not_bridge_cache_across_the_gap",
        WatchCase::Terminal,
    );
}
#[test]
fn peer_subscription_cancellation_ends_catalog_watch_without_reconnect() {
    isolated_watch(
        "peer_subscription_cancellation_ends_catalog_watch_without_reconnect",
        WatchCase::PeerCancellation,
    );
}
#[test]
fn foreign_subscription_cancellation_cannot_end_catalog_watch_successfully() {
    isolated_watch(
        "foreign_subscription_cancellation_cannot_end_catalog_watch_successfully",
        WatchCase::ForeignCancellation,
    );
}
#[test]
fn malformed_page_is_not_retried_as_an_invalidation() {
    isolated_watch(
        "malformed_page_is_not_retried_as_an_invalidation",
        WatchCase::Malformed,
    );
}
#[test]
fn reconciliation_budget_prevents_another_traversal() {
    isolated_watch(
        "reconciliation_budget_prevents_another_traversal",
        WatchCase::RebuildLimit,
    );
}
#[test]
fn listen_request_id_cannot_be_reused_by_a_catalog_page() {
    isolated_watch(
        "listen_request_id_cannot_be_reused_by_a_catalog_page",
        WatchCase::RepeatedId,
    );
}
#[test]
fn cancellation_wakes_an_idle_watch_without_cancelling_the_context() {
    isolated_watch(
        "cancellation_wakes_an_idle_watch_without_cancelling_the_context",
        WatchCase::Cancel,
    );
}
#[test]
fn session_close_wakes_an_idle_catalog_watch() {
    isolated_watch(
        "session_close_wakes_an_idle_catalog_watch",
        WatchCase::SessionClose,
    );
}
#[test]
fn dropped_watch_releases_its_subscription_and_invalidates_cached_pages() {
    isolated_watch(
        "dropped_watch_releases_its_subscription_and_invalidates_cached_pages",
        WatchCase::Drop,
    );
}
#[test]
fn whole_watch_deadline_includes_idle_time_after_a_snapshot() {
    isolated_watch(
        "whole_watch_deadline_includes_idle_time_after_a_snapshot",
        WatchCase::Timeout,
    );
}
#[test]
fn opening_token_expiry_ends_the_watch_without_renewal_or_reconnect() {
    isolated_watch(
        "opening_token_expiry_ends_the_watch_without_renewal_or_reconnect",
        WatchCase::Expired,
    );
}
#[test]
fn host_can_stop_after_acknowledgment_without_a_catalog_post() {
    isolated_watch(
        "host_can_stop_after_acknowledgment_without_a_catalog_post",
        WatchCase::StopAck,
    );
}
#[test]
fn watch_preflight_rejects_suffixes_mutations_and_precancellation() {
    isolated_watch(
        "watch_preflight_rejects_suffixes_mutations_and_precancellation",
        WatchCase::Preflight,
    );
}
#[test]
fn callback_revocation_prevents_further_watch_effects() {
    isolated_watch(
        "callback_revocation_prevents_further_watch_effects",
        WatchCase::Revoked,
    );
}
#[test]
fn overdue_acknowledgment_callback_cannot_start_a_catalog_fetch() {
    isolated_watch(
        "overdue_acknowledgment_callback_cannot_start_a_catalog_fetch",
        WatchCase::CallbackOverrun,
    );
}
#[test]
fn closing_one_catalog_watch_does_not_flush_unrelated_catalogs() {
    isolated_watch(
        "closing_one_catalog_watch_does_not_flush_unrelated_catalogs",
        WatchCase::ScopedCache,
    );
}
#[test]
fn external_clear_after_collection_prevents_snapshot_publication() {
    isolated_watch(
        "external_clear_after_collection_prevents_snapshot_publication",
        WatchCase::ClearPublication,
    );
}
#[test]
fn whole_catalog_policy_composes_with_live_watch_snapshots() {
    isolated_watch(
        "whole_catalog_policy_composes_with_live_watch_snapshots",
        WatchCase::WholeLive,
    );
}
#[test]
fn whole_catalog_policy_preserves_the_external_clear_publication_fence() {
    isolated_watch(
        "whole_catalog_policy_preserves_the_external_clear_publication_fence",
        WatchCase::WholeClearPublication,
    );
}

#[derive(Clone, Copy, Debug)]
enum RecoveryCase {
    Gap,
    DuringPage,
    ReconnectLimit,
    CollectionLimit,
    IdLimit,
    IdBytes,
    RepeatedId,
    RecordLimit,
    Cancel,
    Drop,
    StopGap,
    Deadline,
    Revoked,
    SessionClose,
    Expired,
    Protocol,
    CatalogProtocol,
    CatalogTransport,
    ResyncCatalogTransport,
    ResyncPageHostFailure,
    ResyncPageHostStop,
    Auth,
    ReplacementAuth,
    InitialEof,
    Terminal,
    PeerCancellation,
    Host,
    GapHost,
    Generation,
    Preflight,
}

async fn accept_recovery_listen(peer: &Peer, id: i64) -> TlsStream<TcpStream> {
    let (tls, body) = peer.request(false).await;
    let wire: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(wire["id"], id, "each replacement has a fresh listen ID");
    assert_eq!(wire["method"], "subscriptions/listen");
    assert_eq!(
        wire["params"],
        json!({
            "_meta": request("tools/list").encode_params().unwrap().unwrap()["_meta"],
            "notifications": filter("tools/list"),
        })
    );
    tls
}

async fn acknowledge_recovery_listen(
    peer: &Peer,
    cx: &Cx,
    tls: &mut TlsStream<TcpStream>,
    id: i64,
) {
    sse_head(tls).await;
    tls.flush().await.unwrap();
    Sleep::new(cx.now().saturating_add_nanos(20_000_000)).await;
    peer.quiet(); // A previous ACK or cached page cannot admit a replacement list.
    event(
        tls,
        &json!({
            "jsonrpc":"2.0",
            "method":"notifications/subscriptions/acknowledged",
            "params":{
                "_meta":{(FINAL_SUBSCRIPTION_ID_META_KEY):id},
                "notifications":filter("tools/list"),
            }
        })
        .to_string(),
        false,
    )
    .await;
}

async fn deny_recovery_listen(mut tls: TlsStream<TcpStream>) {
    tls.write_all(
        b"HTTP/1.1 401 Unauthorized\r\nContent-Type: application/json\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}",
    )
    .await
    .unwrap();
    tls.flush().await.unwrap();
}

async fn interrupt_catalog_page(peer: &Peer, id: i64) {
    let mut tls = accept_page(peer, "tools/list", id, None).await;
    tls.write_all(
        b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 128\r\nConnection: close\r\n\r\n{",
    )
    .await
    .unwrap();
    tls.flush().await.unwrap();
    // The advertised body is truncated. A list body failure is not a listen gap.
}

// The parent fixture intentionally admits only authorization-code token POSTs.
// This one scenario explicitly admits a refresh exchange and rotates the bearer.
async fn refresh_recovery_login(peer: &Peer) {
    let (socket, _) = peer.listener.accept().await.unwrap();
    let mut tls = peer.acceptor.accept(socket).await.unwrap();
    let mut bytes = Vec::new();
    let mut chunk = [0; 2048];
    let end = loop {
        let count = tls.read(&mut chunk).await.unwrap();
        assert!(count > 0 && bytes.len() + count <= 32 * 1024);
        bytes.extend_from_slice(&chunk[..count]);
        if let Some(index) = bytes.windows(4).position(|part| part == b"\r\n\r\n") {
            break index + 4;
        }
    };
    let head = std::str::from_utf8(&bytes[..end]).unwrap();
    assert!(head.starts_with("POST /token HTTP/1.1\r\n"));
    let headers: BTreeMap<String, String> = head
        .lines()
        .filter_map(|line| {
            line.split_once(':')
                .map(|(name, value)| (name.to_ascii_lowercase(), value.trim().to_owned()))
        })
        .collect();
    assert!(!headers.contains_key("authorization"));
    let size: usize = headers["content-length"].parse().unwrap();
    assert!(end + size <= 32 * 1024);
    while bytes.len() < end + size {
        let count = tls.read(&mut chunk).await.unwrap();
        assert!(count > 0 && bytes.len() + count <= 32 * 1024);
        bytes.extend_from_slice(&chunk[..count]);
    }
    assert_eq!(bytes.len(), end + size);
    let fields = form(std::str::from_utf8(&bytes[end..]).unwrap());
    assert_eq!(fields["grant_type"], "refresh_token");
    assert_eq!(fields["refresh_token"], "interaction-refresh");
    assert_eq!(fields["resource"], peer.resource());
    peer.tokens.fetch_add(1, Ordering::SeqCst);
    json_reply(
        &mut tls,
        &json!({
            "access_token":"replacement-access", "token_type":"Bearer",
            "expires_in":300, "refresh_token":"replacement-refresh",
        })
        .to_string(),
    )
    .await;
}

fn run_recovery(case: RecoveryCase) {
    RuntimeBuilder::current_thread()
        .with_reactor(create_reactor().unwrap())
        .build()
        .unwrap()
        .block_on(Box::pin(async {
            let cx = Cx::current().unwrap();
            let scenario = Box::pin(async {
                let peer = Peer::new().await;
                let login = async {
                    let (mut tls, _) = peer.request(true).await;
                    let seconds = match case {
                        RecoveryCase::Expired => 2,
                        RecoveryCase::Generation => 8,
                        _ => 300,
                    };
                    json_reply(
                        &mut tls,
                        &json!({
                            "access_token":"interaction-access", "token_type":"Bearer",
                            "expires_in":seconds, "refresh_token":"interaction-refresh",
                        })
                        .to_string(),
                    )
                    .await;
                };
                let policy = OAuthSessionPolicy::new(
                    if matches!(case, RecoveryCase::Generation) {
                        Duration::from_secs(4)
                    } else {
                        Duration::ZERO
                    },
                    Duration::from_secs(30),
                    Duration::from_secs(15),
                    64,
                )
                .unwrap();
                let ((), session) = pair(
                    Box::pin(login),
                    Box::pin(ManagedOAuthSession::authorize(&cx, peer.client(), policy, browser)),
                )
                .await;
                let session = session.unwrap();
                let credential = session.credential(&cx).await.unwrap();
                let limits = ManagedCatalogLimits::new(
                    ManagedCoreLimits::new(4096, 4096, 65536, 16, Duration::from_secs(15))
                        .unwrap(),
                    16,
                    128,
                    16384,
                )
                .unwrap();
                let client = ManagedCatalogClient::new(session.clone(), limits)
                    .with_cache_limits(16, 1048576)
                    .unwrap();
                let watch_limits = ManagedCatalogWatchLimits::new(
                    if matches!(case, RecoveryCase::Deadline) {
                        Duration::from_secs(1)
                    } else {
                        Duration::from_secs(15)
                    },
                    if matches!(case, RecoveryCase::CollectionLimit) { 1 } else { 8 },
                    if matches!(case, RecoveryCase::IdLimit) { 2 } else { 64 },
                    if matches!(case, RecoveryCase::IdBytes) { 2 } else { 16384 },
                    if matches!(case, RecoveryCase::RecordLimit) { 2 } else { 128 },
                )
                .unwrap();
                let backoff = if matches!(
                    case,
                    RecoveryCase::Deadline
                        | RecoveryCase::Expired
                        | RecoveryCase::Cancel
                        | RecoveryCase::Revoked
                        | RecoveryCase::SessionClose
                ) {
                    Duration::from_secs(5)
                } else {
                    Duration::from_millis(20)
                };
                let recovery = RecoveryPolicy::new(
                    if matches!(case, RecoveryCase::ReconnectLimit) { 1 } else { 3 },
                    backoff,
                    backoff,
                )
                .unwrap();
                let snapshots = Cell::new(0_usize);
                let acknowledgments = Cell::new(0_usize);
                let gaps = Cell::new(0_usize);
                let ids = Cell::new(0_i64);
                let events = std::cell::RefCell::new(Vec::new());
                let cancellation = McpRequestCancellation::new();
                let (first_tx, mut first_rx) = oneshot::channel::<()>();
                let (second_tx, mut second_rx) = oneshot::channel::<()>();
                let mut first_tx = Some(first_tx);
                let mut second_tx = Some(second_tx);

                let server = Box::pin(async {
                    if matches!(case, RecoveryCase::Preflight) {
                        return;
                    }
                    let mut listen = accept_recovery_listen(&peer, 1).await;
                    if matches!(case, RecoveryCase::Auth) {
                        deny_recovery_listen(listen).await;
                        return;
                    }
                    if matches!(case, RecoveryCase::InitialEof) {
                        sse_head(&mut listen).await;
                        listen.flush().await.unwrap();
                        return;
                    }
                    acknowledge_recovery_listen(&peer, &cx, &mut listen, 1).await;
                    if matches!(case, RecoveryCase::Host) {
                        closed(listen).await;
                        return;
                    }
                    if matches!(case, RecoveryCase::Protocol) {
                        let pending = accept_page(&peer, "tools/list", 2, None).await;
                        event(
                            &mut listen,
                            &json!({
                                "jsonrpc":"2.0", "method":"notifications/tools/list_changed",
                                "params":{"_meta":{(FINAL_SUBSCRIPTION_ID_META_KEY):999}},
                            })
                            .to_string(),
                            false,
                        )
                        .await;
                        closed(pending).await;
                        closed(listen).await;
                        return;
                    }
                    if matches!(case, RecoveryCase::CatalogProtocol) {
                        let mut page = accept_page(&peer, "tools/list", 2, None).await;
                        json_reply(
                            &mut page,
                            &terminal(2, r#"{"resultType":"complete","wrong":[],"ttlMs":0,"cacheScope":"private"}"#),
                        )
                        .await;
                        drop(page);
                        closed(listen).await;
                        return;
                    }
                    if matches!(case, RecoveryCase::CatalogTransport) {
                        interrupt_catalog_page(&peer, 2).await;
                        closed(listen).await;
                        return;
                    }
                    let replacement_id = if matches!(case, RecoveryCase::DuringPage) {
                        serve_page(&peer, "tools/list", 2, None, "obsolete-prefix", Some("old-tail"))
                            .await;
                        let pending = accept_page(&peer, "tools/list", 3, Some("old-tail")).await;
                        drop(listen);
                        closed(pending).await;
                        4
                    } else {
                        serve_page(&peer, "tools/list", 2, None, "before-gap", None).await;
                        first_rx.recv(&cx).await.unwrap();
                        if matches!(case, RecoveryCase::Terminal) {
                            event(
                                &mut listen,
                                &terminal(1, &json!({
                                    "resultType":"complete",
                                    "_meta":{(FINAL_SUBSCRIPTION_ID_META_KEY):1},
                                }).to_string()),
                                true,
                            ).await;
                            return;
                        }
                        if matches!(case, RecoveryCase::PeerCancellation) {
                            event(
                                &mut listen,
                                &json!({
                                    "jsonrpc":"2.0", "method":"notifications/cancelled",
                                    "params":{
                                        "requestId":1,
                                        "reason":"catalog watch complete",
                                        "_meta":{(FINAL_SUBSCRIPTION_ID_META_KEY):1},
                                    },
                                }).to_string(),
                                false,
                            ).await;
                            closed(listen).await;
                            return;
                        }
                        if matches!(case, RecoveryCase::Generation) {
                            // Renewal is permitted halfway through this 8-second
                            // grant. Keep ample original lifetime for recovery.
                            let refresh_at = credential.expires_at()
                                .checked_sub(Duration::from_millis(3800)).unwrap();
                            let wait = refresh_at.saturating_duration_since(Instant::now());
                            Sleep::new(cx.now().saturating_add_nanos(
                                u64::try_from(wait.as_nanos()).unwrap(),
                            )).await;
                        }
                        drop(listen);
                        3
                    };

                    if matches!(
                        case,
                        RecoveryCase::IdLimit
                            | RecoveryCase::IdBytes
                            | RecoveryCase::RepeatedId
                            | RecoveryCase::Cancel
                            | RecoveryCase::Drop
                            | RecoveryCase::StopGap
                            | RecoveryCase::Deadline
                            | RecoveryCase::Revoked
                            | RecoveryCase::SessionClose
                            | RecoveryCase::Expired
                            | RecoveryCase::GapHost
                    ) {
                        return;
                    }
                    if matches!(case, RecoveryCase::Generation) {
                        refresh_recovery_login(&peer).await;
                    }
                    let mut listen = accept_recovery_listen(&peer, replacement_id).await;
                    if matches!(case, RecoveryCase::ReplacementAuth) {
                        deny_recovery_listen(listen).await;
                        return;
                    }
                    acknowledge_recovery_listen(&peer, &cx, &mut listen, replacement_id).await;
                    if matches!(case, RecoveryCase::CollectionLimit | RecoveryCase::RecordLimit) {
                        closed(listen).await;
                        return;
                    }
                    if matches!(case, RecoveryCase::ResyncCatalogTransport) {
                        interrupt_catalog_page(&peer, replacement_id + 1).await;
                        closed(listen).await;
                        return;
                    }
                    if matches!(case, RecoveryCase::ResyncPageHostFailure | RecoveryCase::ResyncPageHostStop) {
                        let mut page = accept_page(&peer, "tools/list", replacement_id + 1, None).await;
                        sse_head(&mut page).await;
                        event(&mut page, &notification("tools/list"), false).await;
                        closed(page).await;
                        closed_without_request(&peer, listen).await;
                        return;
                    }
                    if matches!(case, RecoveryCase::ReconnectLimit) {
                        serve_page(&peer, "tools/list", replacement_id + 1, None, "after-gap", None)
                            .await;
                        second_rx.recv(&cx).await.unwrap();
                        drop(listen);
                        return;
                    }
                    serve_page(&peer, "tools/list", replacement_id + 1, None, "after-gap-one", Some(""))
                        .await;
                    serve_page(&peer, "tools/list", replacement_id + 2, Some(""), "after-gap-two", None)
                        .await;
                    closed(listen).await;
                });

                let application = Box::pin(async {
                    if matches!(case, RecoveryCase::Preflight) {
                        let mut params = request("tools/list").encode_params().unwrap().unwrap();
                        params["cursor"] = json!("");
                        let suffix = CoreRequest::decode(
                            ProtocolEra::Modern2026, "tools/list", Some(&params),
                        ).unwrap();
                        assert!(matches!(
                            Box::pin(client.watch_recovering(
                                &cx, suffix, watch_limits, recovery,
                                || panic!("no ID for a catalog suffix"),
                                |_| panic!("no callback for a catalog suffix"),
                            )).await,
                            Err(WatchError::CursorNotAllowed),
                        ));
                        assert!(matches!(
                            Box::pin(client.watch_recovering(
                                &cx, core("tools/call", false), watch_limits, recovery,
                                || panic!("no ID for a mutation"),
                                |_| panic!("no callback for a mutation"),
                            )).await,
                            Err(WatchError::Catalog(ManagedCatalogError::NotCatalog)),
                        ));
                        cancellation.cancel();
                        assert!(matches!(
                            Box::pin(client.watch_recovering_with_cancellation(
                                &cx, &cancellation, request("tools/list"), watch_limits, recovery,
                                || panic!("no ID after cancellation"),
                                |_| panic!("no callback after cancellation"),
                            )).await,
                            Err(WatchError::Catalog(ManagedCatalogError::Core(ManagedCoreError::Cancelled))),
                        ));
                        return;
                    }
                    let mut watching = Box::pin(client.watch_recovering_with_cancellation(
                        &cx,
                        &cancellation,
                        request("tools/list"),
                        watch_limits,
                        recovery,
                        || {
                            let id = ids.get() + 1;
                            ids.set(id);
                            if matches!(case, RecoveryCase::RepeatedId) && id == 3 {
                                Ok(serde_json::from_str("1e0").unwrap())
                            } else {
                                Ok(RequestId::Number(id))
                            }
                        },
                        |event| {
                            // Every callback can inspect the cache without deadlock.
                            let stats = client.cache_stats().unwrap();
                            match event {
                                RecoveryEvent::Gap { reconnect_attempt } => {
                                    gaps.set(gaps.get() + 1);
                                    assert_eq!(reconnect_attempt, gaps.get());
                                    assert_eq!(acknowledgments.get(), gaps.get());
                                    assert!(stats.invalidations > 0);
                                    events.borrow_mut().push("gap");
                                    if matches!(case, RecoveryCase::StopGap) {
                                        return Ok(Control::Stop);
                                    }
                                    if matches!(case, RecoveryCase::GapHost) {
                                        return Err(ManagedCatalogError::AbortedByHost);
                                    }
                                }
                                RecoveryEvent::Watch(WatchEvent::Acknowledged { accepted_filter }) => {
                                    acknowledgments.set(acknowledgments.get() + 1);
                                    assert_eq!(acknowledgments.get(), gaps.get() + 1);
                                    assert_eq!(serde_json::to_value(accepted_filter).unwrap(), filter("tools/list"));
                                    events.borrow_mut().push("ack");
                                    if matches!(case, RecoveryCase::Host) {
                                        return Err(ManagedCatalogError::AbortedByHost);
                                    }
                                }
                                RecoveryEvent::Watch(WatchEvent::Notification(_)) => {
                                    if matches!(case, RecoveryCase::ResyncPageHostFailure | RecoveryCase::ResyncPageHostStop) {
                                        assert_eq!(snapshots.get(), 1);
                                        assert_eq!(acknowledgments.get(), 2);
                                        assert!(stats.invalidations > 0);
                                        events.borrow_mut().push("notification");
                                        return if matches!(case, RecoveryCase::ResyncPageHostFailure) {
                                            Err(ManagedCatalogError::AbortedByHost)
                                        } else {
                                            Ok(Control::Stop)
                                        };
                                    }
                                    panic!("no admitted notification is expected in this fixture");
                                }
                                RecoveryEvent::Watch(WatchEvent::Snapshot(catalog)) => {
                                    let count = snapshots.get() + 1;
                                    snapshots.set(count);
                                    assert_eq!(catalog.credential_generation(), 1);
                                    assert_eq!(catalog.method(), "tools/list");
                                    events.borrow_mut().push("snapshot");
                                    for page in catalog.pages() {
                                        let encoded = page.encode().unwrap();
                                        assert!(encoded.contains("900719925474099312345"));
                                        assert!(encoded.contains("1.20e+4"));
                                        assert!(!encoded.contains("obsolete"));
                                        assert_eq!(encoded.contains("after-gap"), gaps.get() > 0);
                                    }
                                    if gaps.get() > 0 && !matches!(case, RecoveryCase::ReconnectLimit) {
                                        assert_eq!(catalog.item_count(), 2);
                                    } else {
                                        assert_eq!(catalog.item_count(), 1);
                                    }
                                    if count == 1 {
                                        if let Some(sender) = first_tx.take() {
                                            sender.send(&cx, ()).unwrap();
                                        }
                                    } else if let Some(sender) = second_tx.take() {
                                        sender.send(&cx, ()).unwrap();
                                    }
                                    if gaps.get() > 0 && !matches!(case, RecoveryCase::ReconnectLimit) {
                                        return Ok(Control::Stop);
                                    }
                                }
                            }
                            Ok(Control::Continue)
                        },
                    ));
                    if matches!(
                        case,
                        RecoveryCase::Cancel
                            | RecoveryCase::Drop
                            | RecoveryCase::Revoked
                            | RecoveryCase::SessionClose
                            | RecoveryCase::Generation
                    ) {
                        poll_fn(|task| {
                            assert!(watching.as_mut().poll(task).is_pending());
                            if gaps.get() == 1 { Poll::Ready(()) } else { Poll::Pending }
                        }).await;
                        match case {
                            RecoveryCase::Cancel => { cancellation.cancel(); }
                            RecoveryCase::Drop => {
                                drop(watching);
                                Sleep::new(cx.now().saturating_add_nanos(80_000_000)).await;
                                peer.quiet();
                                return;
                            }
                            RecoveryCase::Revoked => credential.credential().revoke(),
                            RecoveryCase::SessionClose => session.close(),
                            RecoveryCase::Generation => {
                                let current = session.credential(&cx).await.unwrap();
                                assert_eq!(current.generation(), 2);
                                assert!(!credential.credential().is_revoked());
                                // Peer::request checks every MCP POST still uses
                                // interaction-access, never replacement-access.
                            }
                            _ => unreachable!(),
                        }
                    }
                    let result = watching.await;
                    match case {
                        RecoveryCase::Gap | RecoveryCase::DuringPage
                        | RecoveryCase::StopGap | RecoveryCase::Generation | RecoveryCase::ResyncPageHostStop => {
                            assert_eq!(result.unwrap(), Outcome::StoppedByHost);
                        }
                        RecoveryCase::Terminal | RecoveryCase::PeerCancellation => {
                            assert_eq!(result.unwrap(), Outcome::SubscriptionEnded);
                        }
                        RecoveryCase::ReconnectLimit => {
                            assert!(matches!(result, Err(WatchError::ReconnectLimit)));
                        }
                        RecoveryCase::CollectionLimit => {
                            assert!(matches!(result, Err(WatchError::CollectionLimit)));
                        }
                        RecoveryCase::IdLimit | RecoveryCase::IdBytes => {
                            assert!(matches!(result, Err(WatchError::Catalog(ManagedCatalogError::StateLimit))));
                        }
                        RecoveryCase::RepeatedId => {
                            assert!(matches!(result, Err(WatchError::Catalog(ManagedCatalogError::RepeatedRequestId))));
                        }
                        RecoveryCase::RecordLimit => {
                            assert!(matches!(result, Err(WatchError::Subscription(ManagedSubscriptionError::RecordLimit))));
                        }
                        RecoveryCase::Cancel => {
                            assert!(matches!(result, Err(WatchError::Catalog(ManagedCatalogError::Core(ManagedCoreError::Cancelled)))));
                        }
                        RecoveryCase::Deadline => {
                            assert!(matches!(result, Err(WatchError::Catalog(ManagedCatalogError::Core(
                                ManagedCoreError::TimedOut | ManagedCoreError::Session(OAuthSessionError::TimedOut)
                            )))));
                        }
                        RecoveryCase::Revoked => {
                            assert!(matches!(result, Err(WatchError::Catalog(ManagedCatalogError::CredentialRevoked))
                                | Err(WatchError::Catalog(ManagedCatalogError::Core(ManagedCoreError::Session(OAuthSessionError::LoginRequired))))));
                        }
                        RecoveryCase::SessionClose => {
                            assert!(matches!(result, Err(WatchError::Catalog(ManagedCatalogError::CredentialRevoked))
                                | Err(WatchError::Catalog(ManagedCatalogError::Core(ManagedCoreError::Session(OAuthSessionError::Closed))))));
                        }
                        RecoveryCase::Expired => {
                            assert!(matches!(result, Err(WatchError::Catalog(ManagedCatalogError::Core(
                                ManagedCoreError::Session(OAuthSessionError::LoginRequired)
                            )))));
                        }
                        RecoveryCase::Protocol => {
                            assert!(matches!(result, Err(WatchError::Subscription(ManagedSubscriptionError::InvalidResponse))));
                        }
                        RecoveryCase::CatalogProtocol => {
                            assert!(matches!(result, Err(WatchError::Catalog(ManagedCatalogError::Core(ManagedCoreError::InvalidResult)))));
                        }
                        RecoveryCase::CatalogTransport | RecoveryCase::ResyncCatalogTransport => {
                            assert!(matches!(result, Err(WatchError::Catalog(ManagedCatalogError::Core(_)))));
                        }
                        RecoveryCase::Auth | RecoveryCase::ReplacementAuth => {
                            assert!(matches!(result, Err(WatchError::Subscription(ManagedSubscriptionError::Session(
                                OAuthSessionError::AuthorizationRejected { status: 401 }
                            )))));
                        }
                        RecoveryCase::InitialEof => {
                            assert!(matches!(result, Err(WatchError::Subscription(_))));
                        }
                        RecoveryCase::Host | RecoveryCase::GapHost | RecoveryCase::ResyncPageHostFailure => {
                            assert!(matches!(result, Err(WatchError::Catalog(ManagedCatalogError::AbortedByHost))));
                        }
                        RecoveryCase::Drop | RecoveryCase::Preflight => unreachable!(),
                    }
                });
                pair(server, application).await;
                assert!(cx.checkpoint().is_ok(), "recovery must not cancel the caller context");
                let expected_posts = match case {
                    RecoveryCase::Preflight => 0,
                    RecoveryCase::Auth | RecoveryCase::InitialEof | RecoveryCase::Host => 1,
                    RecoveryCase::Gap | RecoveryCase::Generation => 5,
                    RecoveryCase::DuringPage => 6,
                    RecoveryCase::CollectionLimit | RecoveryCase::RecordLimit | RecoveryCase::ReplacementAuth => 3,
                    RecoveryCase::ReconnectLimit | RecoveryCase::ResyncCatalogTransport
                    | RecoveryCase::ResyncPageHostFailure | RecoveryCase::ResyncPageHostStop => 4,
                    _ => 2,
                };
                assert_eq!(peer.posts.load(Ordering::SeqCst), expected_posts, "{case:?}");
                assert_eq!(peer.tokens.load(Ordering::SeqCst), if matches!(case, RecoveryCase::Generation) { 2 } else { 1 });
                peer.quiet();
                match case {
                    RecoveryCase::Gap | RecoveryCase::Generation => {
                        assert_eq!(*events.borrow(), ["ack", "snapshot", "gap", "ack", "snapshot"]);
                        assert_eq!(ids.get(), 5);
                    }
                    RecoveryCase::DuringPage => {
                        assert_eq!(*events.borrow(), ["ack", "gap", "ack", "snapshot"]);
                        assert_eq!(ids.get(), 6);
                    }
                    RecoveryCase::ReconnectLimit => {
                        assert_eq!(gaps.get(), 1);
                        assert_eq!(acknowledgments.get(), 2);
                        assert_eq!(snapshots.get(), 2);
                        assert_eq!(ids.get(), 4);
                    }
                    RecoveryCase::IdLimit => assert_eq!(ids.get(), 2),
                    RecoveryCase::IdBytes | RecoveryCase::RepeatedId => assert_eq!(ids.get(), 3),
                    RecoveryCase::CollectionLimit | RecoveryCase::RecordLimit => {
                        assert_eq!(acknowledgments.get(), 2);
                        assert_eq!(snapshots.get(), 1);
                        assert_eq!(ids.get(), 3);
                    }
                    RecoveryCase::ResyncPageHostFailure | RecoveryCase::ResyncPageHostStop => {
                        assert_eq!(*events.borrow(), ["ack", "snapshot", "gap", "ack", "notification"]);
                        assert_eq!(ids.get(), 4);
                        assert_eq!(snapshots.get(), 1);
                    }
                    RecoveryCase::Protocol | RecoveryCase::CatalogProtocol
                    | RecoveryCase::CatalogTransport | RecoveryCase::Auth
                    | RecoveryCase::InitialEof | RecoveryCase::Terminal
                    | RecoveryCase::PeerCancellation | RecoveryCase::Host | RecoveryCase::Preflight => {
                        assert_eq!(gaps.get(), 0, "terminal failures must not schedule recovery");
                    }
                    _ => assert_eq!(gaps.get(), 1),
                }
                session.close();
            });
            asupersync::time::timeout_at(cx.now().saturating_add_nanos(20_000_000_000), scenario)
                .await
                .expect("catalog recovery TLS fixture must settle");
        }));
}

#[test]
fn catalog_watch_recovers_gap_with_fresh_ack_and_cursorless_snapshot() {
    isolated_catalog_case(
        "catalog_watch_recovers_gap_with_fresh_ack_and_cursorless_snapshot",
        || {
            run_recovery(RecoveryCase::Gap);
            run_recovery(RecoveryCase::DuringPage);
        },
    );
}

#[test]
fn catalog_watch_recovery_keeps_cumulative_attempt_and_request_id_bounds() {
    isolated_catalog_case(
        "catalog_watch_recovery_keeps_cumulative_attempt_and_request_id_bounds",
        || {
            for case in [
                RecoveryCase::ReconnectLimit,
                RecoveryCase::CollectionLimit,
                RecoveryCase::IdLimit,
                RecoveryCase::IdBytes,
                RecoveryCase::RepeatedId,
                RecoveryCase::RecordLimit,
            ] {
                run_recovery(case);
            }
        },
    );
}

#[test]
fn catalog_watch_recovery_keeps_original_deadline_and_cancellation() {
    isolated_catalog_case(
        "catalog_watch_recovery_keeps_original_deadline_and_cancellation",
        || {
            for case in [
                RecoveryCase::Cancel,
                RecoveryCase::Drop,
                RecoveryCase::StopGap,
                RecoveryCase::Deadline,
                RecoveryCase::Revoked,
                RecoveryCase::SessionClose,
                RecoveryCase::Expired,
            ] {
                run_recovery(case);
            }
        },
    );
}

#[test]
fn catalog_watch_recovery_rejects_protocol_auth_and_host_failures() {
    isolated_catalog_case(
        "catalog_watch_recovery_rejects_protocol_auth_and_host_failures",
        || {
            for case in [
                RecoveryCase::Protocol,
                RecoveryCase::CatalogProtocol,
                RecoveryCase::CatalogTransport,
                RecoveryCase::ResyncCatalogTransport,
                RecoveryCase::Auth,
                RecoveryCase::ReplacementAuth,
                RecoveryCase::InitialEof,
                RecoveryCase::Terminal,
                RecoveryCase::PeerCancellation,
                RecoveryCase::Host,
                RecoveryCase::GapHost,
                RecoveryCase::Preflight,
            ] {
                run_recovery(case);
            }
        },
    );
}

#[test]
fn recovered_catalog_page_notification_host_failure_and_stop_are_terminal() {
    isolated_catalog_case(
        "recovered_catalog_page_notification_host_failure_and_stop_are_terminal",
        || {
            run_recovery(RecoveryCase::ResyncPageHostFailure);
            run_recovery(RecoveryCase::ResyncPageHostStop);
        },
    );
}

#[test]
fn catalog_watch_recovery_keeps_opening_credential_after_sibling_renewal() {
    isolated_catalog_case(
        "catalog_watch_recovery_keeps_opening_credential_after_sibling_renewal",
        || run_recovery(RecoveryCase::Generation),
    );
}
