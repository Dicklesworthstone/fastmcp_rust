//! Public catalog-watch tests sharing the real OAuth/MCP loopback TLS fixture.
//! No mock transport: acknowledgment, list pages, changes and interrupted reads
//! traverse native HTTP/SSE. The parent target requires native-tls-roots.
use super::*;
use fastmcp_client::http_auth::managed::OAuthSessionError;
use fastmcp_client::http_auth::rpc::catalog::{ManagedCatalogClient, ManagedCatalogError, ManagedCatalogLimits};
use fastmcp_client::http_auth::rpc::catalog::watch::{
    ManagedCatalogWatchControl as Control, ManagedCatalogWatchEvent as WatchEvent,
    ManagedCatalogWatchError as WatchError, ManagedCatalogWatchLimits,
    ManagedCatalogWatchOutcome as Outcome,
};
use fastmcp_protocol::{ClientCapabilities, FinalRequestMeta, FINAL_SUBSCRIPTION_ID_META_KEY};

const WATCH_CHILD: &str = "FASTMCP_TEST_CATALOG_WATCH_CASE";

#[derive(Clone, Copy)]
enum WatchCase {
    Live, Resources, Templates, Prompts, DuringPage, ChangeOnPage, NarrowAck,
    Gap, Terminal, Malformed, RebuildLimit, RepeatedId, Cancel, SessionClose,
    Drop, Timeout, Expired, StopAck, Preflight, Revoked, CallbackOverrun, ScopedCache,
    ClearPublication,
}

fn isolated_watch(name: &str, case: WatchCase) {
    if let Ok(selected) = std::env::var(WATCH_CHILD) {
        assert_eq!(selected, name);
        run_watch(case);
        return;
    }
    let roots = RootFile::create();
    struct Child(std::process::Child);
    impl Drop for Child { fn drop(&mut self) { let _ = self.0.kill(); let _ = self.0.wait(); } }
    let exact = format!("driver::catalog_watch::{name}");
    let mut child = Child(Command::new(std::env::current_exe().unwrap())
        .args(["--exact", &exact, "--nocapture", "--test-threads=1"])
        .env(WATCH_CHILD, name).env("SSL_CERT_FILE", &roots.0).env_remove("SSL_CERT_DIR")
        .stdin(Stdio::null()).stdout(Stdio::inherit()).stderr(Stdio::inherit()).spawn().unwrap());
    let until = Instant::now() + Duration::from_secs(30);
    loop {
        if let Some(status) = child.0.try_wait().unwrap() {
            assert!(status.success(), "catalog watch HTTPS case failed");
            return;
        }
        assert!(Instant::now() < until, "catalog watch child exceeded its process bound");
        std::thread::sleep(Duration::from_millis(10));
    }
}

fn request(method: &str) -> CoreRequest {
    CoreRequest::decode(ProtocolEra::Modern2026, method, Some(&json!({
        "_meta": FinalRequestMeta::new(ClientCapabilities::default()),
        "includeTags":["selected"], "excludeTags":[],
    }))).unwrap()
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

fn ack(accepted: Value) -> String {
    json!({"jsonrpc":"2.0","method":"notifications/subscriptions/acknowledged",
        "params":{"_meta":{(FINAL_SUBSCRIPTION_ID_META_KEY):1},"notifications":accepted}}).to_string()
}

fn page(method: &str, name: &str, next: Option<&str>) -> String {
    let (key, item) = match method {
        "tools/list" => ("tools", json!({"name":name,"inputSchema":{"type":"object"}})),
        "resources/list" => ("resources", json!({"name":name,"uri":format!("file:///{name}")})),
        "resources/templates/list" => ("resourceTemplates", json!({"name":name,"uriTemplate":format!("file:///{name}/{{key}}")})),
        "prompts/list" => ("prompts", json!({"name":name})),
        _ => unreachable!(),
    };
    let cursor = next.map_or(String::new(), |next| format!(",\"nextCursor\":{}", serde_json::to_string(next).unwrap()));
    format!(r#"{{"resultType":"complete","{key}":[{item}],"ttlMs":60000,"cacheScope":"private"{cursor},"x-exact":{{"z":900719925474099312345,"a":1.20e+4}}}}"#)
}

async fn accept_listen(peer: &Peer, cx: &Cx, method: &str) -> TlsStream<TcpStream> {
    let (mut tls, body) = peer.request(false).await;
    let wire: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(wire["id"], 1);
    assert_eq!(wire["method"], "subscriptions/listen");
    assert_eq!(wire["params"]["notifications"], filter(method));
    assert_eq!(wire["params"]["_meta"], request(method).encode_params().unwrap().unwrap()["_meta"]);
    assert!(wire["params"].get("includeTags").is_none());
    sse_head(&mut tls).await;
    tls.flush().await.unwrap();
    Sleep::new(cx.now().saturating_add_nanos(20_000_000)).await;
    peer.quiet(); // No list is allowed before the acknowledgment exists.
    tls
}

async fn accept_page(peer: &Peer, method: &str, id: i64, cursor: Option<&str>) -> TlsStream<TcpStream> {
    let (tls, body) = peer.request(false).await;
    let wire: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(wire["id"], id);
    assert_eq!(wire["method"], method);
    let mut expected = request(method).encode_params().unwrap().unwrap();
    if let Some(cursor) = cursor { expected["cursor"] = json!(cursor); }
    assert_eq!(wire["params"], expected);
    tls
}

async fn serve_page(peer: &Peer, method: &str, id: i64, cursor: Option<&str>, name: &str, next: Option<&str>) {
    let mut tls = accept_page(peer, method, id, cursor).await;
    json_reply(&mut tls, &terminal(id, &page(method, name, next))).await;
}

async fn closed(mut tls: TlsStream<TcpStream>) {
    let mut byte = [0];
    assert!(!matches!(tls.read(&mut byte).await, Ok(count) if count > 0), "the driver must release its response socket");
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
            let method = match case {
                WatchCase::Resources => "resources/list",
                WatchCase::Templates => "resources/templates/list",
                WatchCase::Prompts => "prompts/list",
                _ => "tools/list",
            };
            if matches!(case, WatchCase::Live | WatchCase::ScopedCache) {
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
                    event(&mut listen, &notification(method), false).await;
                    closed(page).await; // Invalidation must wake an idle list response.
                    if matches!(case, WatchCase::DuringPage) {
                        serve_page(&peer, method, 4, None, "fresh-one", Some("")).await;
                        serve_page(&peer, method, 5, Some(""), "fresh-two", None).await;
                    }
                    closed(listen).await;
                    return;
                }
                if matches!(case, WatchCase::ChangeOnPage) {
                    let mut page = accept_page(&peer, method, 2, None).await;
                    sse_head(&mut page).await;
                    event(&mut page, &notification(method), false).await;
                    closed(page).await;
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
                if matches!(case, WatchCase::ClearPublication) {
                    closed(listen).await;
                    return;
                }
                first_rx.recv(&cx).await.unwrap();
                if matches!(case, WatchCase::Live | WatchCase::Resources | WatchCase::Templates | WatchCase::Prompts) {
                    // The first snapshot has already reached the host while the
                    // original pending listen read must remain open and usable.
                    event(&mut listen, &notification(method), false).await;
                    serve_page(&peer, method, 3, None, "second", None).await;
                } else if matches!(case, WatchCase::Terminal) {
                    event(&mut listen, &terminal(1, &json!({"resultType":"complete",
                        "_meta":{(FINAL_SUBSCRIPTION_ID_META_KEY):1}}).to_string()), true).await;
                    return;
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
                if matches!(case, WatchCase::ClearPublication) {
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
                    WatchCase::Live | WatchCase::Resources | WatchCase::Templates | WatchCase::Prompts | WatchCase::DuringPage | WatchCase::ChangeOnPage | WatchCase::StopAck | WatchCase::ScopedCache => {
                        assert_eq!(result.unwrap(), Outcome::StoppedByHost);
                    }
                    WatchCase::Terminal => assert_eq!(result.unwrap(), Outcome::SubscriptionEnded),
                    WatchCase::NarrowAck => assert!(matches!(result, Err(WatchError::CoverageRefused))),
                    WatchCase::RebuildLimit => assert!(matches!(result, Err(WatchError::CollectionLimit))),
                    WatchCase::RepeatedId => assert!(matches!(result, Err(WatchError::Catalog(ManagedCatalogError::RepeatedRequestId)))),
                    WatchCase::Malformed => assert!(matches!(result, Err(WatchError::Catalog(ManagedCatalogError::Core(ManagedCoreError::InvalidResult))))),
                    WatchCase::Timeout | WatchCase::CallbackOverrun => assert!(matches!(result, Err(WatchError::Catalog(ManagedCatalogError::Core(ManagedCoreError::TimedOut))))),
                    WatchCase::Cancel => assert!(matches!(result, Err(WatchError::Catalog(ManagedCatalogError::Core(ManagedCoreError::Cancelled))))),
                    WatchCase::Revoked => assert!(matches!(result, Err(WatchError::Catalog(ManagedCatalogError::CredentialRevoked)))),
                    WatchCase::ClearPublication => {
                        assert!(matches!(result, Err(WatchError::Catalog(ManagedCatalogError::Invalidated))));
                        assert_eq!(snapshots.get(), 0, "an externally invalidated candidate must never be published");
                        assert_eq!(ids.get(), 2, "an external clear cannot trigger a hidden refetch");
                    }
                    WatchCase::SessionClose => assert!(matches!(result,
                        Err(WatchError::Catalog(ManagedCatalogError::CredentialRevoked))
                        | Err(WatchError::Subscription(fastmcp_client::http_auth::managed::subscriptions::ManagedSubscriptionError::Session(OAuthSessionError::Closed)))
                    )),
                    WatchCase::Gap | WatchCase::Expired => assert!(result.is_err()),
                    WatchCase::Drop | WatchCase::Preflight => unreachable!(),
                }
            });
            pair(server, application).await;
            assert!(cx.checkpoint().is_ok(), "watch cancellation does not cancel its caller context");
            let expected = match case {
                WatchCase::Live => 4,
                WatchCase::Resources | WatchCase::Templates | WatchCase::Prompts | WatchCase::ChangeOnPage | WatchCase::RebuildLimit => 3,
                WatchCase::DuringPage => 5,
                WatchCase::NarrowAck | WatchCase::RepeatedId | WatchCase::StopAck | WatchCase::CallbackOverrun => 1,
                WatchCase::Preflight => 0,
                _ => 2,
            };
            assert_eq!(peer.posts.load(Ordering::SeqCst), expected);
            assert_eq!(peer.tokens.load(Ordering::SeqCst), 1);
            peer.quiet(); // No automatic resubscribe, refresh or arbitrary retry.
            if matches!(case, WatchCase::ScopedCache) {
                let cached = Box::pin(client.collect(&cx, request("prompts/list"), || panic!("unrelated catalog was not cleared"), |_| Ok(()))).await.unwrap();
                assert_eq!(cached.item_count(), 1);
            }
            if matches!(case, WatchCase::Live | WatchCase::Terminal | WatchCase::Drop) {
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
fn tools_watch_refreshes_live_and_discards_preexisting_cache() { isolated_watch("tools_watch_refreshes_live_and_discards_preexisting_cache", WatchCase::Live); }
#[test]
fn resources_watch_uses_resource_catalog_changes() { isolated_watch("resources_watch_uses_resource_catalog_changes", WatchCase::Resources); }
#[test]
fn templates_watch_uses_resource_catalog_changes() { isolated_watch("templates_watch_uses_resource_catalog_changes", WatchCase::Templates); }
#[test]
fn prompts_watch_uses_prompt_catalog_changes() { isolated_watch("prompts_watch_uses_prompt_catalog_changes", WatchCase::Prompts); }
#[test]
fn change_during_pagination_cancels_obsolete_page_and_restarts_from_first() { isolated_watch("change_during_pagination_cancels_obsolete_page_and_restarts_from_first", WatchCase::DuringPage); }
#[test]
fn change_on_a_catalog_response_reconciles_without_restarting_the_listen() { isolated_watch("change_on_a_catalog_response_reconciles_without_restarting_the_listen", WatchCase::ChangeOnPage); }
#[test]
fn missing_acknowledgment_coverage_prevents_any_list_post() { isolated_watch("missing_acknowledgment_coverage_prevents_any_list_post", WatchCase::NarrowAck); }
#[test]
fn subscription_gap_cancels_pending_list_and_never_publishes_partial_state() { isolated_watch("subscription_gap_cancels_pending_list_and_never_publishes_partial_state", WatchCase::Gap); }
#[test]
fn graceful_subscription_end_does_not_bridge_cache_across_the_gap() { isolated_watch("graceful_subscription_end_does_not_bridge_cache_across_the_gap", WatchCase::Terminal); }
#[test]
fn malformed_page_is_not_retried_as_an_invalidation() { isolated_watch("malformed_page_is_not_retried_as_an_invalidation", WatchCase::Malformed); }
#[test]
fn reconciliation_budget_prevents_another_traversal() { isolated_watch("reconciliation_budget_prevents_another_traversal", WatchCase::RebuildLimit); }
#[test]
fn listen_request_id_cannot_be_reused_by_a_catalog_page() { isolated_watch("listen_request_id_cannot_be_reused_by_a_catalog_page", WatchCase::RepeatedId); }
#[test]
fn cancellation_wakes_an_idle_watch_without_cancelling_the_context() { isolated_watch("cancellation_wakes_an_idle_watch_without_cancelling_the_context", WatchCase::Cancel); }
#[test]
fn session_close_wakes_an_idle_catalog_watch() { isolated_watch("session_close_wakes_an_idle_catalog_watch", WatchCase::SessionClose); }
#[test]
fn dropped_watch_releases_its_subscription_and_invalidates_cached_pages() { isolated_watch("dropped_watch_releases_its_subscription_and_invalidates_cached_pages", WatchCase::Drop); }
#[test]
fn whole_watch_deadline_includes_idle_time_after_a_snapshot() { isolated_watch("whole_watch_deadline_includes_idle_time_after_a_snapshot", WatchCase::Timeout); }
#[test]
fn opening_token_expiry_ends_the_watch_without_renewal_or_reconnect() { isolated_watch("opening_token_expiry_ends_the_watch_without_renewal_or_reconnect", WatchCase::Expired); }
#[test]
fn host_can_stop_after_acknowledgment_without_a_catalog_post() { isolated_watch("host_can_stop_after_acknowledgment_without_a_catalog_post", WatchCase::StopAck); }
#[test]
fn watch_preflight_rejects_suffixes_mutations_and_precancellation() { isolated_watch("watch_preflight_rejects_suffixes_mutations_and_precancellation", WatchCase::Preflight); }
#[test]
fn callback_revocation_prevents_further_watch_effects() { isolated_watch("callback_revocation_prevents_further_watch_effects", WatchCase::Revoked); }
#[test]
fn overdue_acknowledgment_callback_cannot_start_a_catalog_fetch() { isolated_watch("overdue_acknowledgment_callback_cannot_start_a_catalog_fetch", WatchCase::CallbackOverrun); }
#[test]
fn closing_one_catalog_watch_does_not_flush_unrelated_catalogs() { isolated_watch("closing_one_catalog_watch_does_not_flush_unrelated_catalogs", WatchCase::ScopedCache); }
#[test]
fn external_clear_after_collection_prevents_snapshot_publication() { isolated_watch("external_clear_after_collection_prevents_snapshot_publication", WatchCase::ClearPublication); }
