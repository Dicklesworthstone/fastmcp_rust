//! Public multi-page catalog collection and caching over the real OAuth/TLS peer.
//! Included by oauth_interaction with native-tls-roots, independently of Tasks.
use super::*;
use fastmcp_client::http_auth::managed::OAuthSessionError;
use fastmcp_client::http_auth::rpc::catalog::{
    CollectedCatalog, ManagedCatalogClient, ManagedCatalogError, ManagedCatalogLimits,
};
use fastmcp_protocol::{ClientCapabilities, FinalRequestMeta, JsonRpcRequest, ServerNotification};

const CATALOG_CHILD: &str = "FASTMCP_TEST_CATALOG_CASE";
const OTHER_CHANGED: &str = r#"{"jsonrpc":"2.0","method":"notifications/prompts/list_changed"}"#;

#[derive(Clone, Copy)]
enum CatalogCase {
    AllMethods, CacheHit, Clear, ExternalInvalidation, Metadata, ZeroTtl, Invalidate, Unrelated,
    CursorLoop, Scope, PageLimit, ItemLimit, ByteLimit, NotificationLimit,
    RepeatedId, Cancel, Close, Drop, LateId, Preflight, Renewal,
    RevokedCache, RevokeBeforePost, ClearBeforePost, RevokeInObserver,
}

fn isolated_catalog(name: &str, case: CatalogCase) {
    if let Ok(selected) = std::env::var(CATALOG_CHILD) {
        assert_eq!(selected, name);
        run_catalog(case);
        return;
    }
    let roots = RootFile::create();
    struct Child(std::process::Child);
    impl Drop for Child { fn drop(&mut self) { let _ = self.0.kill(); let _ = self.0.wait(); } }
    let exact = format!("driver::catalogs::{name}");
    let mut child = Child(Command::new(std::env::current_exe().unwrap())
        .args(["--exact", &exact, "--nocapture", "--test-threads=1"])
        .env(CATALOG_CHILD, name).env("SSL_CERT_FILE", &roots.0).env_remove("SSL_CERT_DIR")
        .stdin(Stdio::null()).stdout(Stdio::inherit()).stderr(Stdio::inherit()).spawn().unwrap());
    let end = Instant::now() + Duration::from_secs(30);
    loop {
        if let Some(status) = child.0.try_wait().unwrap() {
            assert!(status.success(), "public catalog TLS case failed");
            return;
        }
        assert!(Instant::now() < end, "catalog TLS child exceeded its process bound");
        std::thread::sleep(Duration::from_millis(10));
    }
}

fn catalog_request(method: &str) -> CoreRequest {
    CoreRequest::decode(ProtocolEra::Modern2026, method, Some(&json!({
        "_meta": FinalRequestMeta::new(ClientCapabilities::default()),
        "includeTags":["selected"], "excludeTags":[],
    }))).unwrap()
}

fn page(method: &str, name: &str, next: Option<&str>, ttl: u64, scope: &str) -> String {
    let (field, item) = match method {
        "tools/list" => ("tools", json!({"name":name,"inputSchema":{"type":"object"}})),
        "resources/list" => ("resources", json!({"name":name,"uri":format!("file:///{name}")})),
        "resources/templates/list" => ("resourceTemplates", json!({"name":name,"uriTemplate":format!("file:///{name}/{{path}}")})),
        "prompts/list" => ("prompts", json!({"name":name})),
        _ => panic!("unsupported catalog fixture"),
    };
    let cursor = next.map_or(String::new(), |next| format!(",\"nextCursor\":{}", serde_json::to_string(next).unwrap()));
    format!(r#"{{"resultType":"complete","{field}":[{item}],"ttlMs":{ttl},"cacheScope":"{scope}"{cursor},"x-exact":{{"z":900719925474099312345,"a":1.20e+4}}}}"#)
}

async fn serve_page(peer: &Peer, method: &str, id: i64, cursor: Option<&str>, result: &str) {
    let request = peer.response(id, result).await;
    assert_eq!(request["method"], method);
    assert_eq!(request["params"]["includeTags"], json!(["selected"]));
    assert_eq!(request["params"]["excludeTags"], json!([]));
    match cursor {
        Some(cursor) => assert_eq!(request["params"]["cursor"], cursor),
        None => assert!(request["params"].get("cursor").is_none()),
    }
}

async fn pages(peer: &Peer, method: &str, first: i64, ttl: u64, scope: &str) {
    serve_page(peer, method, first, None, &page(method, "one", Some(""), 60000, scope)).await;
    serve_page(peer, method, first + 1, Some(""), &page(method, "two", None, ttl, scope)).await;
}

fn next_id(counter: &Cell<i64>) -> Result<RequestId, ManagedCatalogError> {
    let next = counter.get();
    counter.set(next + 1);
    Ok(RequestId::Number(next))
}

fn assert_complete(result: &CollectedCatalog, method: &str) {
    assert_eq!(result.method(), method);
    assert_eq!(result.pages().len(), 2);
    assert_eq!(result.item_count(), 2);
    for page in result.pages() {
        let encoded = page.encode().unwrap();
        assert!(encoded.contains("900719925474099312345") && encoded.contains("1.20e+4"));
    }
}

fn changed(method: &str) -> ServerNotification {
    ServerNotification::decode(&JsonRpcRequest::notification(method, None)).unwrap()
}

async fn accept_refresh(peer: &Peer) {
    let (socket, _) = peer.listener.accept().await.unwrap();
    let mut tls = peer.acceptor.accept(socket).await.unwrap();
    let mut wire = Vec::new();
    let mut buffer = [0; 2048];
    let end = loop {
        let count = tls.read(&mut buffer).await.unwrap();
        assert!(count > 0 && wire.len() + count <= 32768);
        wire.extend_from_slice(&buffer[..count]);
        if let Some(index) = wire.windows(4).position(|part| part == b"\r\n\r\n") { break index + 4; }
    };
    let head = std::str::from_utf8(&wire[..end]).unwrap();
    assert!(head.starts_with("POST /token HTTP/1.1\r\n"));
    assert!(!head.to_ascii_lowercase().contains("authorization:"));
    let size: usize = head.lines().find_map(|line| {
        let (name, value) = line.split_once(':')?;
        name.eq_ignore_ascii_case("content-length").then(|| value.trim().parse::<usize>().unwrap())
    }).unwrap();
    assert!(end + size <= 32768);
    while wire.len() < end + size {
        let count = tls.read(&mut buffer).await.unwrap();
        assert!(count > 0 && wire.len() + count <= 32768);
        wire.extend_from_slice(&buffer[..count]);
    }
    assert_eq!(wire.len(), end + size);
    let form = form(std::str::from_utf8(&wire[end..]).unwrap());
    assert_eq!(form["grant_type"], "refresh_token");
    assert_eq!(form["refresh_token"], "interaction-refresh");
    assert_eq!(form["resource"], peer.resource());
    peer.tokens.fetch_add(1, Ordering::SeqCst);
    // Even an issuer returning the same token bytes creates a new managed
    // generation; prior cached pages must not be joined across that renewal.
    json_reply(&mut tls, r#"{"access_token":"interaction-access","token_type":"Bearer","expires_in":300,"refresh_token":"renewed-refresh"}"#).await;
}

fn run_catalog(case: CatalogCase) {
    RuntimeBuilder::current_thread().with_reactor(create_reactor().unwrap()).build().unwrap().block_on(Box::pin(async {
        let cx = Cx::current().unwrap();
        let scenario = Box::pin(async {
            let peer = Peer::new().await;
            let login = async {
                let (mut tls, _) = peer.request(true).await;
                let ttl = if matches!(case, CatalogCase::Renewal) { 2 } else { 300 };
                json_reply(&mut tls, &json!({"access_token":"interaction-access","token_type":"Bearer","expires_in":ttl,"refresh_token":"interaction-refresh"}).to_string()).await;
            };
            let policy = OAuthSessionPolicy::new(Duration::ZERO, Duration::from_secs(30), Duration::from_secs(15), 64).unwrap();
            let ((), login) = pair(Box::pin(login), Box::pin(ManagedOAuthSession::authorize(&cx, peer.client(), policy, browser))).await;
            let session = login.unwrap();
            let core_limits = ManagedCoreLimits::new(4096,
                if matches!(case, CatalogCase::ByteLimit) { 512 } else { 4096 },
                if matches!(case, CatalogCase::ByteLimit) { 512 } else { 65536 },
                if matches!(case, CatalogCase::NotificationLimit) { 1 } else { 8 },
                if matches!(case, CatalogCase::LateId) { Duration::from_secs(1) } else { Duration::from_secs(15) },
            ).unwrap();
            let limits = ManagedCatalogLimits::new(core_limits,
                if matches!(case, CatalogCase::PageLimit) { 1 } else { 16 },
                if matches!(case, CatalogCase::ItemLimit) { 1 } else { 128 }, 16384,
            ).unwrap();
            let client = ManagedCatalogClient::new(session.clone(), limits).with_cache_limits(16, 1024 * 1024).unwrap();
            let method = "tools/list";
            let first = Cell::new(41);
            let cancellation = McpRequestCancellation::new();
            match case {
                CatalogCase::AllMethods => {
                    for (index, method) in ["tools/list", "resources/list", "resources/templates/list", "prompts/list"].into_iter().enumerate() {
                        let id = 41 + index as i64 * 2;
                        let ((), result) = pair(Box::pin(pages(&peer, method, id, 60000, "private")), Box::pin(client.collect(
                            &cx, catalog_request(method), || next_id(&first), |_| Ok(()),
                        ))).await;
                        assert_complete(&result.unwrap(), method);
                    }
                    assert_eq!(peer.posts.load(Ordering::SeqCst), 8);
                }
                CatalogCase::CacheHit | CatalogCase::Clear | CatalogCase::ExternalInvalidation | CatalogCase::Metadata | CatalogCase::ZeroTtl => {
                    let ttl = if matches!(case, CatalogCase::ZeroTtl) { 0 } else { 60000 };
                    let ((), result) = pair(Box::pin(pages(&peer, method, 41, ttl, "public")), Box::pin(client.collect(
                        &cx, catalog_request(method), || next_id(&first), |_| Ok(()),
                    ))).await;
                    let original = result.unwrap();
                    assert_complete(&original, method);
                    if matches!(case, CatalogCase::CacheHit) {
                        let cached = Box::pin(client.clone().collect(&cx, catalog_request(method),
                            || panic!("cache hits must not allocate RPC IDs"), |_| panic!("cached results must not invent notifications"),
                        )).await.unwrap();
                        for (first, next) in original.pages().iter().zip(cached.pages()) { assert_eq!(first.encode().unwrap(), next.encode().unwrap()); }
                        assert_complete(&cached, method);
                        assert_eq!(client.cache_stats().unwrap().hits, 2);
                        assert_eq!(peer.posts.load(Ordering::SeqCst), 2);
                        // Public does not share a cache even with a separately
                        // constructed client using the same login/resource.
                        let isolated = ManagedCatalogClient::new(session.clone(), limits).with_cache_limits(16, 1048576).unwrap();
                        let ((), fresh) = pair(Box::pin(pages(&peer, method, 43, 60000, "public")), Box::pin(isolated.collect(
                            &cx, catalog_request(method), || next_id(&first), |_| Ok(()),
                        ))).await;
                        assert_complete(&fresh.unwrap(), method);
                        assert_eq!(peer.posts.load(Ordering::SeqCst), 4);
                    } else if matches!(case, CatalogCase::ZeroTtl) {
                        let ((), repeated) = pair(Box::pin(serve_page(&peer, method, 43, Some(""), &page(method, "two", None, 0, "public"))), Box::pin(client.collect(
                            &cx, catalog_request(method), || next_id(&first), |_| Ok(()),
                        ))).await;
                        assert_complete(&repeated.unwrap(), method);
                        assert_eq!(peer.posts.load(Ordering::SeqCst), 3);
                    } else {
                        let mut request = catalog_request(method);
                        if matches!(case, CatalogCase::Clear) { client.clone().clear().unwrap(); }
                        else if matches!(case, CatalogCase::ExternalInvalidation) {
                            client.invalidate_notification(&changed("notifications/tools/list_changed")).unwrap();
                        } else {
                            let mut params = request.encode_params().unwrap().unwrap();
                            params["_meta"]["com.example/view"] = json!("different");
                            request = CoreRequest::decode(ProtocolEra::Modern2026, method, Some(&params)).unwrap();
                        }
                        let ((), repeated) = pair(Box::pin(pages(&peer, method, 43, 60000, "public")), Box::pin(client.collect(
                            &cx, request, || next_id(&first), |_| Ok(()),
                        ))).await;
                        assert_complete(&repeated.unwrap(), method);
                        assert_eq!(peer.posts.load(Ordering::SeqCst), 4);
                    }
                }
                CatalogCase::Invalidate | CatalogCase::Unrelated | CatalogCase::NotificationLimit => {
                    let notices = Cell::new(0);
                    let server = Box::pin(async {
                        if matches!(case, CatalogCase::NotificationLimit) {
                            let (mut tls, _) = peer.request(false).await;
                            sse_head(&mut tls).await;
                            event(&mut tls, OTHER_CHANGED, false).await;
                            event(&mut tls, &terminal(41, &page(method, "one", Some(""), 60000, "private")), true).await;
                        } else { serve_page(&peer, method, 41, None, &page(method, "one", Some(""), 60000, "private")).await; }
                        let (mut tls, _) = peer.request(false).await;
                        sse_head(&mut tls).await;
                        event(&mut tls, if matches!(case, CatalogCase::Invalidate) { CHANGED } else { OTHER_CHANGED }, false).await;
                        if matches!(case, CatalogCase::Unrelated) {
                            event(&mut tls, &terminal(42, &page(method, "two", None, 60000, "private")), true).await;
                        } else {
                            let mut byte = [0];
                            assert!(!matches!(tls.read(&mut byte).await, Ok(count) if count > 0));
                        }
                    });
                    let ((), result) = pair(server, Box::pin(client.collect(&cx, catalog_request(method), || next_id(&first), |_| {
                        notices.set(notices.get() + 1);
                        // Acquiring this same mutex proves observers are not
                        // invoked under the internal cache lock.
                        let _ = client.cache_stats().unwrap();
                        Ok(())
                    }))).await;
                    assert_eq!(notices.get(), 1);
                    match case {
                        CatalogCase::Invalidate => assert!(matches!(result, Err(ManagedCatalogError::Invalidated))),
                        CatalogCase::NotificationLimit => assert!(matches!(result, Err(ManagedCatalogError::Core(ManagedCoreError::NotificationLimit)))),
                        _ => assert_complete(&result.unwrap(), method),
                    }
                    assert_eq!(peer.posts.load(Ordering::SeqCst), 2);
                }
                CatalogCase::CursorLoop | CatalogCase::Scope | CatalogCase::PageLimit | CatalogCase::ItemLimit | CatalogCase::ByteLimit | CatalogCase::RepeatedId | CatalogCase::LateId => {
                    let server = Box::pin(async {
                        let first_page = page(method, "one", Some(""), 60000, "private");
                        serve_page(&peer, method, 41, None, &first_page).await;
                        if matches!(case, CatalogCase::PageLimit | CatalogCase::RepeatedId | CatalogCase::LateId) { return; }
                        let second = page(method, "two", if matches!(case, CatalogCase::CursorLoop) { Some("") } else { None }, 60000,
                            if matches!(case, CatalogCase::Scope) { "public" } else { "private" });
                        let second = if matches!(case, CatalogCase::ByteLimit) {
                            let large = format!(r#"{{"resultType":"complete","tools":[],"ttlMs":0,"cacheScope":"private","padding":"{}"}}"#, "x".repeat(250));
                            assert!(terminal(42, &large).len() < 512);
                            assert!(terminal(41, &first_page).len() + terminal(42, &large).len() > 512);
                            large
                        } else { second };
                        serve_page(&peer, method, 42, Some(""), &second).await;
                    });
                    let ((), result) = pair(server, Box::pin(client.collect(&cx, catalog_request(method), || {
                        if first.get() == 42 {
                            if matches!(case, CatalogCase::RepeatedId) { return Ok(serde_json::from_str("41e0").unwrap()); }
                            if matches!(case, CatalogCase::LateId) { std::thread::sleep(Duration::from_millis(1100)); }
                        }
                        next_id(&first)
                    }, |_| Ok(())))).await;
                    let error = result.err().unwrap();
                    match case {
                        CatalogCase::CursorLoop => assert!(matches!(error, ManagedCatalogError::RepeatedCursor)),
                        CatalogCase::Scope => assert!(matches!(error, ManagedCatalogError::ScopeChanged)),
                        CatalogCase::PageLimit => assert!(matches!(error, ManagedCatalogError::PageLimit)),
                        CatalogCase::ItemLimit => assert!(matches!(error, ManagedCatalogError::ItemLimit)),
                        CatalogCase::ByteLimit => assert!(matches!(error, ManagedCatalogError::Core(ManagedCoreError::ResponseByteLimit))),
                        CatalogCase::RepeatedId => assert!(matches!(error, ManagedCatalogError::RepeatedRequestId)),
                        _ => assert!(matches!(error, ManagedCatalogError::Core(ManagedCoreError::TimedOut))),
                    }
                    assert_eq!(peer.posts.load(Ordering::SeqCst), if matches!(case, CatalogCase::PageLimit | CatalogCase::RepeatedId | CatalogCase::LateId) { 1 } else { 2 });
                }
                CatalogCase::Cancel | CatalogCase::Close | CatalogCase::Drop => {
                    let (tx, mut rx) = oneshot::channel::<()>();
                    let server = Box::pin(async {
                        serve_page(&peer, method, 41, None, &page(method, "one", Some(""), 60000, "private")).await;
                        let (mut tls, _) = peer.request(false).await;
                        tx.send(&cx, ()).unwrap();
                        let mut byte = [0];
                        assert!(!matches!(tls.read(&mut byte).await, Ok(count) if count > 0));
                    });
                    let application = Box::pin(async {
                        let mut collecting = Box::pin(client.collect_with_cancellation(&cx, &cancellation, catalog_request(method), || next_id(&first), |_| Ok(())));
                        let mut started = std::pin::pin!(rx.recv(&cx));
                        poll_fn(|task| {
                            assert!(collecting.as_mut().poll(task).is_pending());
                            started.as_mut().poll(task)
                        }).await.unwrap();
                        match case {
                            CatalogCase::Drop => drop(collecting),
                            CatalogCase::Cancel => {
                                cancellation.cancel();
                                assert!(matches!(collecting.await, Err(ManagedCatalogError::Core(ManagedCoreError::Cancelled))));
                            }
                            _ => {
                                session.close();
                                assert!(matches!(collecting.await, Err(ManagedCatalogError::Core(ManagedCoreError::Session(OAuthSessionError::Closed)))));
                            }
                        }
                        assert_eq!(client.cache_stats().unwrap().fills, 1, "an unfinished page never fills the cache");
                        assert!(cx.checkpoint().is_ok());
                    });
                    pair(server, application).await;
                    assert_eq!(peer.posts.load(Ordering::SeqCst), 2);
                }
                CatalogCase::Preflight => {
                    assert!(matches!(Box::pin(client.collect(&cx, core("tools/call", false), || panic!("no ID before method admission"), |_| Ok(()))).await, Err(ManagedCatalogError::NotCatalog)));
                    cancellation.cancel();
                    assert!(matches!(Box::pin(client.collect_with_cancellation(&cx, &cancellation, catalog_request(method), || panic!("no ID after cancellation"), |_| Ok(()))).await, Err(ManagedCatalogError::Core(ManagedCoreError::Cancelled))));
                    assert_eq!(peer.posts.load(Ordering::SeqCst), 0);
                }
                CatalogCase::Renewal => {
                    let server = Box::pin(async {
                        serve_page(&peer, method, 41, None, &page(method, "one", Some(""), 60000, "private")).await;
                        accept_refresh(&peer).await;
                        serve_page(&peer, method, 42, Some(""), &page(method, "two", None, 60000, "private")).await;
                        pages(&peer, method, 51, 60000, "private").await;
                    });
                    let application = Box::pin(async {
                        let result = Box::pin(client.collect(&cx, catalog_request(method), || {
                            if first.get() == 42 { std::thread::sleep(Duration::from_millis(2100)); }
                            next_id(&first)
                        }, |_| Ok(()))).await;
                        assert!(matches!(result, Err(ManagedCatalogError::CredentialChanged)));
                        first.set(51);
                        let fresh = Box::pin(client.collect(&cx, catalog_request(method), || next_id(&first), |_| Ok(()))).await.unwrap();
                        assert_complete(&fresh, method);
                        assert_eq!(fresh.credential_generation(), 2);
                        assert_eq!(client.cache_stats().unwrap().fills, 3);
                    });
                    pair(server, application).await;
                    assert_eq!(peer.posts.load(Ordering::SeqCst), 4);
                    assert_eq!(peer.tokens.load(Ordering::SeqCst), 2);
                }
                CatalogCase::RevokedCache => {
                    let ((), result) = pair(Box::pin(pages(&peer, method, 41, 60000, "public")), Box::pin(client.collect(
                        &cx, catalog_request(method), || next_id(&first), |_| Ok(()),
                    ))).await;
                    assert_complete(&result.unwrap(), method);
                    let cached = Box::pin(client.collect(&cx, catalog_request(method), || panic!("warm pages need no POST"), |_| Ok(()))).await.unwrap();
                    assert_complete(&cached, method);
                    let before = client.cache_stats().unwrap();
                    assert_eq!(before.hits, 2);
                    let credential = session.credential(&cx).await.unwrap();
                    credential.credential().revoke();
                    let result = Box::pin(client.collect(&cx, catalog_request(method), || panic!("revoked cache access must not attempt a POST"), |_| Ok(()))).await;
                    // Acquisition refuses an already-revoked login before the
                    // collector receives a snapshot or touches its cache.
                    assert!(matches!(result, Err(ManagedCatalogError::Core(
                        fastmcp_client::http_auth::rpc::ManagedCoreError::Session(OAuthSessionError::LoginRequired)
                    ))));
                    assert_eq!(client.cache_stats().unwrap(), before, "revocation is checked before lookup or fill");
                    assert_eq!(peer.posts.load(Ordering::SeqCst), 2);
                }
                CatalogCase::RevokeBeforePost | CatalogCase::ClearBeforePost => {
                    let credential = session.credential(&cx).await.unwrap();
                    let ids = Cell::new(0);
                    let result = Box::pin(client.collect(&cx, catalog_request(method), || {
                        ids.set(ids.get() + 1);
                        if matches!(case, CatalogCase::RevokeBeforePost) { credential.credential().revoke(); }
                        else { client.clone().clear().unwrap(); }
                        Ok(RequestId::Number(41))
                    }, |_| panic!("no peer event before dispatch"))).await;
                    if matches!(case, CatalogCase::RevokeBeforePost) {
                        assert!(matches!(result, Err(ManagedCatalogError::CredentialRevoked)));
                    } else {
                        assert!(matches!(result, Err(ManagedCatalogError::Invalidated)));
                    }
                    assert_eq!(ids.get(), 1);
                    assert_eq!(peer.posts.load(Ordering::SeqCst), 0);
                    assert_eq!(client.cache_stats().unwrap().fills, 0);
                }
                CatalogCase::RevokeInObserver => {
                    let credential = session.credential(&cx).await.unwrap();
                    let notices = Cell::new(0);
                    let server = Box::pin(async {
                        let (mut tls, _) = peer.request(false).await;
                        sse_head(&mut tls).await;
                        event(&mut tls, OTHER_CHANGED, false).await;
                        let mut byte = [0];
                        assert!(!matches!(tls.read(&mut byte).await, Ok(count) if count > 0), "revoked response is retired without awaiting its terminal");
                    });
                    let ((), result) = pair(server, Box::pin(client.collect(&cx, catalog_request(method), || next_id(&first), |_| {
                        notices.set(notices.get() + 1);
                        credential.credential().revoke();
                        Ok(())
                    }))).await;
                    assert!(matches!(result, Err(ManagedCatalogError::CredentialRevoked)));
                    assert_eq!(notices.get(), 1);
                    assert_eq!(peer.posts.load(Ordering::SeqCst), 1);
                    assert_eq!(client.cache_stats().unwrap().fills, 0);
                }
            }
            if !matches!(case, CatalogCase::Renewal) { assert_eq!(peer.tokens.load(Ordering::SeqCst), 1); }
            peer.quiet();
            session.close();
        });
        asupersync::time::timeout_at(cx.now().saturating_add_nanos(20_000_000_000), scenario).await.expect("catalog fixture must settle within its bound");
    }));
}

#[test]
fn all_four_catalogs_follow_exact_empty_cursors_and_preserve_payloads() { isolated_catalog("all_four_catalogs_follow_exact_empty_cursors_and_preserve_payloads", CatalogCase::AllMethods); }
#[test]
fn cached_pages_avoid_posts_but_public_hints_do_not_share_clients() { isolated_catalog("cached_pages_avoid_posts_but_public_hints_do_not_share_clients", CatalogCase::CacheHit); }
#[test]
fn clearing_a_shared_cache_refetches_every_page() { isolated_catalog("clearing_a_shared_cache_refetches_every_page", CatalogCase::Clear); }
#[test]
fn external_change_notification_invalidates_all_cached_catalog_pages() { isolated_catalog("external_change_notification_invalidates_all_cached_catalog_pages", CatalogCase::ExternalInvalidation); }
#[test]
fn different_request_metadata_cannot_reuse_cached_pages() { isolated_catalog("different_request_metadata_cannot_reuse_cached_pages", CatalogCase::Metadata); }
#[test]
fn zero_ttl_refetches_only_the_uncacheable_page() { isolated_catalog("zero_ttl_refetches_only_the_uncacheable_page", CatalogCase::ZeroTtl); }
#[test]
fn invalidation_is_delivered_before_rejecting_the_partial_collection() { isolated_catalog("invalidation_is_delivered_before_rejecting_the_partial_collection", CatalogCase::Invalidate); }
#[test]
fn unrelated_catalog_changes_do_not_break_collection() { isolated_catalog("unrelated_catalog_changes_do_not_break_collection", CatalogCase::Unrelated); }
#[test]
fn cursor_cycle_is_terminal_without_automatic_retry() { isolated_catalog("cursor_cycle_is_terminal_without_automatic_retry", CatalogCase::CursorLoop); }
#[test]
fn cache_scope_changes_cannot_produce_a_mixed_collection() { isolated_catalog("cache_scope_changes_cannot_produce_a_mixed_collection", CatalogCase::Scope); }
#[test]
fn page_budget_prevents_a_later_post() { isolated_catalog("page_budget_prevents_a_later_post", CatalogCase::PageLimit); }
#[test]
fn item_budget_is_shared_across_pages() { isolated_catalog("item_budget_is_shared_across_pages", CatalogCase::ItemLimit); }
#[test]
fn response_byte_budget_is_shared_across_pages() { isolated_catalog("response_byte_budget_is_shared_across_pages", CatalogCase::ByteLimit); }
#[test]
fn notification_budget_is_shared_across_pages() { isolated_catalog("notification_budget_is_shared_across_pages", CatalogCase::NotificationLimit); }
#[test]
fn numeric_id_alias_is_rejected_before_a_later_post() { isolated_catalog("numeric_id_alias_is_rejected_before_a_later_post", CatalogCase::RepeatedId); }
#[test]
fn cancelled_collection_closes_the_pending_page_without_filling_it() { isolated_catalog("cancelled_collection_closes_the_pending_page_without_filling_it", CatalogCase::Cancel); }
#[test]
fn session_closure_interrupts_a_pending_catalog_page() { isolated_catalog("session_closure_interrupts_a_pending_catalog_page", CatalogCase::Close); }
#[test]
fn abandoned_collection_releases_the_pending_page() { isolated_catalog("abandoned_collection_releases_the_pending_page", CatalogCase::Drop); }
#[test]
fn late_id_callback_cannot_dispatch_after_the_collection_deadline() { isolated_catalog("late_id_callback_cannot_dispatch_after_the_collection_deadline", CatalogCase::LateId); }
#[test]
fn invalid_or_precancelled_collections_have_no_post_effects() { isolated_catalog("invalid_or_precancelled_collections_have_no_post_effects", CatalogCase::Preflight); }
#[test]
fn renewal_rejects_mixed_pages_and_old_cache_entries_are_not_reused() { isolated_catalog("renewal_rejects_mixed_pages_and_old_cache_entries_are_not_reused", CatalogCase::Renewal); }
#[test]
fn local_revocation_blocks_warm_catalog_cache_without_peer_effects() { isolated_catalog("local_revocation_blocks_warm_catalog_cache_without_peer_effects", CatalogCase::RevokedCache); }
#[test]
fn revocation_in_id_supplier_prevents_the_catalog_post() { isolated_catalog("revocation_in_id_supplier_prevents_the_catalog_post", CatalogCase::RevokeBeforePost); }
#[test]
fn cache_clear_in_id_supplier_prevents_the_catalog_post() { isolated_catalog("cache_clear_in_id_supplier_prevents_the_catalog_post", CatalogCase::ClearBeforePost); }
#[test]
fn observer_revocation_retires_the_unfinished_page_without_a_fill() { isolated_catalog("observer_revocation_retires_the_unfinished_page_without_a_fill", CatalogCase::RevokeInObserver); }
