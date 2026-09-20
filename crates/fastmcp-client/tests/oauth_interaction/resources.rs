//! Resource reads and cache ownership through the public OAuth/TLS APIs.
//! Included in oauth_interaction; no new transport, certificate or parser fixture.
use super::*;
use fastmcp_client::http_auth::rpc::resource::{
    ManagedResourceClient, ManagedResourceError as ReadError, ManagedResourceLimits,
};
use fastmcp_protocol::{ClientCapabilities, FinalRequestMeta, JsonRpcRequest, ServerNotification};

const RESOURCE_CHILD: &str = "FASTMCP_TEST_RESOURCE_READ_CASE";
const URI: &str = "file:///one";
const OTHER_NOTICE: &str = r#"{"jsonrpc":"2.0","method":"notifications/prompts/list_changed"}"#;
const UPDATED: &str = r#"{"jsonrpc":"2.0","method":"notifications/resources/updated","params":{"uri":"file:///one"}}"#;
const INPUT: &str = r#"{"resultType":"input_required","requestState":"","ttlMs":60000,"cacheScope":"public","x-exact":1.20e+4}"#;

#[derive(Clone, Copy)]
enum ResourceCase {
    Cached, DefaultUncached, ZeroTtl, TinyCache, Metadata, DifferentUri,
    Continuation, InputRequired, Clear, ExternalUpdate, ExternalListChange,
    InlineUpdate, Incremental, HostRefusal, InvalidResult, ContentsLimit,
    Cancel, Close, Drop, Expire, RevokeBeforePost, ClearBeforePost, RevokedHit,
    PendingInvalidation, Preflight,
}

fn isolated_resource(name: &str, case: ResourceCase) {
    if let Ok(selected) = std::env::var(RESOURCE_CHILD) {
        assert_eq!(selected, name);
        run_resource(case);
        return;
    }
    let roots = RootFile::create();
    struct Child(std::process::Child);
    impl Drop for Child { fn drop(&mut self) { let _ = self.0.kill(); let _ = self.0.wait(); } }
    let exact = format!("driver::resources::{name}");
    let mut child = Child(Command::new(std::env::current_exe().unwrap())
        .args(["--exact", &exact, "--nocapture", "--test-threads=1"])
        .env(RESOURCE_CHILD, name).env("SSL_CERT_FILE", &roots.0).env_remove("SSL_CERT_DIR")
        .stdin(Stdio::null()).stdout(Stdio::inherit()).stderr(Stdio::inherit()).spawn().unwrap());
    let end = Instant::now() + Duration::from_secs(30);
    loop {
        if let Some(status) = child.0.try_wait().unwrap() {
            assert!(status.success(), "resource-read HTTPS case failed");
            return;
        }
        assert!(Instant::now() < end, "resource-read child exceeded its bound");
        std::thread::sleep(Duration::from_millis(10));
    }
}

fn read_request(uri: &str) -> CoreRequest {
    CoreRequest::decode(ProtocolEra::Modern2026, "resources/read", Some(&json!({
        "uri":uri, "_meta":FinalRequestMeta::new(ClientCapabilities::default()),
    }))).unwrap()
}
fn changed_request(request: &CoreRequest, key: &str, value: Value) -> CoreRequest {
    let mut params = request.encode_params().unwrap().unwrap();
    params[key] = value;
    CoreRequest::decode(ProtocolEra::Modern2026, "resources/read", Some(&params)).unwrap()
}
fn read_result(ttl: u64) -> String {
    format!(r#"{{"resultType":"complete","contents":[{{"uri":"file:///one","text":"exact first"}},{{"uri":"file:///two","blob":"AAEC"}}],"ttlMs":{ttl},"cacheScope":"public","x-exact":{{"z":900719925474099312345,"a":1.20e+4}}}}"#)
}
fn next_id(ids: &Cell<i64>) -> RequestId {
    let id = ids.get();
    ids.set(id + 1);
    RequestId::Number(id)
}
fn notification(method: &str) -> ServerNotification {
    let params = (method == "notifications/resources/updated").then(|| json!({"uri":URI}));
    ServerNotification::decode(&JsonRpcRequest::notification(method, params)).unwrap()
}
async fn serve_read(peer: &Peer, id: i64, expected: &CoreRequest, result: &str) {
    let request = peer.response(id, result).await;
    assert_eq!(request["method"], "resources/read");
    assert_eq!(request["params"], expected.encode_params().unwrap().unwrap());
}
async fn socket_closed(mut tls: TlsStream<TcpStream>) {
    let mut byte = [0];
    assert!(!matches!(tls.read(&mut byte).await, Ok(count) if count > 0), "retired read must release its socket");
}

fn run_resource(case: ResourceCase) {
    RuntimeBuilder::current_thread().with_reactor(create_reactor().unwrap()).build().unwrap().block_on(Box::pin(async {
        let cx = Cx::current().unwrap();
        let scenario = Box::pin(async {
            let peer = Peer::new().await;
            let login = async {
                let (mut tls, _) = peer.request(true).await;
                let ttl = if matches!(case, ResourceCase::Expire) { 2 } else { 300 };
                json_reply(&mut tls, &json!({"access_token":"interaction-access","token_type":"Bearer",
                    "expires_in":ttl,"refresh_token":"interaction-refresh"}).to_string()).await;
            };
            let policy = OAuthSessionPolicy::new(Duration::ZERO, Duration::from_secs(15), Duration::from_secs(15), 64).unwrap();
            let ((), session) = pair(Box::pin(login), Box::pin(ManagedOAuthSession::authorize(&cx, peer.client(), policy, browser))).await;
            let session = session.unwrap();
            let core_limits = ManagedCoreLimits::new(4096, 4096, 16384, 8, Duration::from_secs(15)).unwrap();
            let limits = ManagedResourceLimits::new(core_limits, if matches!(case, ResourceCase::ContentsLimit) { 1 } else { 16 }).unwrap();
            let client = ManagedResourceClient::new(session.clone(), limits);
            let client = if matches!(case, ResourceCase::DefaultUncached) { client }
                else { client.with_cache_limits(8, if matches!(case, ResourceCase::TinyCache) { 1 } else { 65536 }).unwrap() };
            let request = read_request(URI);
            let ids = Cell::new(41_i64);
            let cancellation = McpRequestCancellation::new();
            match case {
                ResourceCase::Cached | ResourceCase::DefaultUncached | ResourceCase::ZeroTtl
                | ResourceCase::TinyCache | ResourceCase::Metadata | ResourceCase::DifferentUri
                | ResourceCase::Clear | ResourceCase::ExternalUpdate | ResourceCase::ExternalListChange => {
                    let ttl = if matches!(case, ResourceCase::ZeroTtl) { 0 } else { 60000 };
                    let wire = read_result(ttl);
                    let ((), first) = pair(Box::pin(serve_read(&peer, 41, &request, &wire)),
                        Box::pin(client.read(&cx, request.clone(), || Ok(next_id(&ids)), |_| Ok(())))).await;
                    let first = first.unwrap();
                    assert!(first.is_complete() && !first.is_cache_hit());
                    assert_eq!(first.uri(), URI);
                    assert_eq!(first.credential_generation(), 1);
                    let original = first.result().encode().unwrap();
                    assert!(original.contains("1.20e+4") && original.contains("900719925474099312345"));
                    assert!(original.contains("exact first") && original.contains("AAEC") && original.contains("file:///two"));
                    if matches!(case, ResourceCase::Cached) {
                        let hit = Box::pin(client.clone().read(&cx, request.clone(),
                            || panic!("cached read must not allocate an ID"), |_| panic!("cached read must not replay notifications"),
                        )).await.unwrap();
                        assert!(hit.is_cache_hit());
                        assert_eq!(hit.result().encode().unwrap(), original);
                        assert_eq!(peer.posts.load(Ordering::SeqCst), 1);
                        assert_eq!(client.cache_stats().unwrap().hits, 1);
                        // Even a public hint does not share entries with a new
                        // consumer using exactly the same managed login.
                        let separate = ManagedResourceClient::new(session.clone(), limits).with_cache_limits(8, 65536).unwrap();
                        let ((), fresh) = pair(Box::pin(serve_read(&peer, 42, &request, &wire)),
                            Box::pin(separate.read(&cx, request.clone(), || Ok(next_id(&ids)), |_| Ok(())))).await;
                        assert!(!fresh.unwrap().is_cache_hit());
                    } else {
                        let next = match case {
                            ResourceCase::Metadata => {
                                let mut metadata = request.encode_params().unwrap().unwrap()["_meta"].clone();
                                metadata["com.example/tenant"] = json!("another");
                                changed_request(&request, "_meta", metadata)
                            }
                            ResourceCase::DifferentUri => read_request("file:///other"),
                            ResourceCase::Clear => { client.clone().clear().unwrap(); request.clone() }
                            ResourceCase::ExternalUpdate => {
                                client.invalidate_notification(&notification("notifications/resources/updated")).unwrap(); request.clone()
                            }
                            ResourceCase::ExternalListChange => {
                                client.invalidate_notification(&notification("notifications/resources/list_changed")).unwrap(); request.clone()
                            }
                            _ => request.clone(),
                        };
                        let ((), second) = pair(Box::pin(serve_read(&peer, 42, &next, &wire)),
                            Box::pin(client.read(&cx, next.clone(), || Ok(next_id(&ids)), |_| Ok(())))).await;
                        assert!(!second.unwrap().is_cache_hit());
                    }
                    assert_eq!(peer.posts.load(Ordering::SeqCst), 2);
                }
                ResourceCase::Continuation => {
                    let wire = read_result(60000);
                    let ((), base) = pair(Box::pin(serve_read(&peer, 41, &request, &wire)),
                        Box::pin(client.read(&cx, request.clone(), || Ok(next_id(&ids)), |_| Ok(())))).await;
                    assert!(base.unwrap().is_complete());
                    for (index, continued) in [
                        changed_request(&request, "requestState", json!("")),
                        changed_request(&request, "inputResponses", json!({})),
                    ].into_iter().enumerate() {
                        for repeat in 0..2 {
                            let id = 42 + (index * 2 + repeat) as i64;
                            let ((), result) = pair(Box::pin(serve_read(&peer, id, &continued, &wire)),
                                Box::pin(client.read(&cx, continued.clone(), || Ok(next_id(&ids)), |_| Ok(())))).await;
                            assert!(result.unwrap().is_complete());
                        }
                    }
                    let base = Box::pin(client.read(&cx, request, || panic!("continuations cannot replace the ordinary cache"), |_| Ok(()))).await.unwrap();
                    assert!(base.is_cache_hit());
                    assert_eq!(client.cache_stats().unwrap().fills, 1);
                    assert_eq!(peer.posts.load(Ordering::SeqCst), 5);
                }
                ResourceCase::InputRequired => {
                    for id in [41, 42] {
                        let ((), result) = pair(Box::pin(serve_read(&peer, id, &request, INPUT)),
                            Box::pin(client.read(&cx, request.clone(), || Ok(next_id(&ids)), |_| Ok(())))).await;
                        let result = result.unwrap();
                        assert!(!result.is_complete() && !result.is_cache_hit());
                        assert!(result.result().encode().unwrap().contains("1.20e+4"));
                        peer.quiet();
                    }
                    assert_eq!(client.cache_stats().unwrap().fills, 0);
                    assert_eq!(peer.posts.load(Ordering::SeqCst), 2);
                }
                ResourceCase::Incremental | ResourceCase::InlineUpdate | ResourceCase::HostRefusal => {
                    let (sender, mut receiver) = oneshot::channel::<()>();
                    let mut sender = Some(sender);
                    let notices = Cell::new(0);
                    let server = async {
                        let (mut tls, _) = peer.request(false).await;
                        sse_head(&mut tls).await;
                        event(&mut tls, if matches!(case, ResourceCase::InlineUpdate) { UPDATED } else { OTHER_NOTICE }, false).await;
                        receiver.recv(&cx).await.unwrap();
                        if matches!(case, ResourceCase::Incremental) {
                            event(&mut tls, &terminal(41, &read_result(60000)), true).await;
                        } else { socket_closed(tls).await; }
                    };
                    let read = client.read(&cx, request, || Ok(next_id(&ids)), |notice| {
                        notices.set(notices.get() + 1);
                        let _ = client.cache_stats().unwrap(); // callback runs outside the cache mutex
                        if matches!(case, ResourceCase::InlineUpdate) {
                            assert!(matches!(*notice, ServerNotification::ResourceUpdated(_)));
                            assert_eq!(client.cache_stats().unwrap().invalidations, 1);
                        }
                        sender.take().unwrap().send(&cx, ()).unwrap();
                        if matches!(case, ResourceCase::HostRefusal) { Err(ReadError::AbortedByHost) } else { Ok(()) }
                    });
                    let ((), result) = pair(Box::pin(server), Box::pin(read)).await;
                    match case {
                        ResourceCase::Incremental => assert!(result.unwrap().is_complete()),
                        ResourceCase::InlineUpdate => assert!(matches!(result, Err(ReadError::Invalidated))),
                        _ => assert!(matches!(result, Err(ReadError::AbortedByHost))),
                    }
                    assert_eq!(notices.get(), 1);
                    assert_eq!(peer.posts.load(Ordering::SeqCst), 1);
                }
                ResourceCase::InvalidResult | ResourceCase::ContentsLimit => {
                    let malformed = r#"{"resultType":"complete","contents":[{"uri":"file:///one","text":"secret","blob":"AAEC"}],"ttlMs":60000,"cacheScope":"private"}"#;
                    let body = if matches!(case, ResourceCase::ContentsLimit) { read_result(60000) } else { malformed.to_owned() };
                    let ((), result) = pair(Box::pin(serve_read(&peer, 41, &request, &body)),
                        Box::pin(client.read(&cx, request.clone(), || Ok(next_id(&ids)), |_| Ok(())))).await;
                    assert!(result.is_err());
                    assert_eq!(client.cache_stats().unwrap().fills, 0);
                    let corrected = r#"{"resultType":"complete","contents":[],"ttlMs":60000,"cacheScope":"private"}"#;
                    let ((), result) = pair(Box::pin(serve_read(&peer, 42, &request, corrected)),
                        Box::pin(client.read(&cx, request.clone(), || Ok(next_id(&ids)), |_| Ok(())))).await;
                    assert!(result.unwrap().is_complete());
                    assert_eq!(peer.posts.load(Ordering::SeqCst), 2);
                }
                ResourceCase::Cancel | ResourceCase::Close | ResourceCase::Drop | ResourceCase::Expire => {
                    let (sender, mut receiver) = oneshot::channel::<()>();
                    let server = async {
                        let (mut tls, _) = peer.request(false).await;
                        sse_head(&mut tls).await;
                        tls.flush().await.unwrap();
                        sender.send(&cx, ()).unwrap();
                        socket_closed(tls).await;
                    };
                    let application = async {
                        let mut read = Box::pin(client.read_with_cancellation(&cx, &cancellation,
                            request, || Ok(next_id(&ids)), |_| Ok(())));
                        let mut started = std::pin::pin!(receiver.recv(&cx));
                        poll_fn(|task| { assert!(read.as_mut().poll(task).is_pending()); started.as_mut().poll(task) }).await.unwrap();
                        if matches!(case, ResourceCase::Drop) { drop(read); }
                        else {
                            match case {
                                ResourceCase::Cancel => { cancellation.cancel(); },
                                ResourceCase::Close => session.close(),
                                _ => {},
                            }
                            assert!(read.await.is_err());
                        }
                    };
                    pair(Box::pin(server), Box::pin(application)).await;
                    assert_eq!(client.cache_stats().unwrap().fills, 0);
                    assert_eq!(peer.posts.load(Ordering::SeqCst), 1);
                    assert_eq!(peer.tokens.load(Ordering::SeqCst), 1);
                }
                ResourceCase::RevokeBeforePost | ResourceCase::ClearBeforePost => {
                    let credential = session.credential(&cx).await.unwrap();
                    let result = Box::pin(client.read(&cx, request, || {
                        if matches!(case, ResourceCase::RevokeBeforePost) { credential.credential().revoke(); }
                        else { client.clear().unwrap(); }
                        Ok(next_id(&ids))
                    }, |_| Ok(()))).await;
                    match case {
                        ResourceCase::RevokeBeforePost => assert!(matches!(result, Err(ReadError::CredentialUnavailable))),
                        _ => assert!(matches!(result, Err(ReadError::Invalidated))),
                    }
                    assert_eq!(peer.posts.load(Ordering::SeqCst), 0);
                }
                ResourceCase::RevokedHit => {
                    let wire = read_result(60000);
                    let ((), first) = pair(Box::pin(serve_read(&peer, 41, &request, &wire)),
                        Box::pin(client.read(&cx, request.clone(), || Ok(next_id(&ids)), |_| Ok(())))).await;
                    assert!(first.unwrap().is_complete());
                    session.credential(&cx).await.unwrap().credential().revoke();
                    assert!(Box::pin(client.read(&cx, request, || panic!("revoked read cannot dispatch"), |_| Ok(()))).await.is_err());
                    assert_eq!(peer.posts.load(Ordering::SeqCst), 1);
                    assert_eq!(client.cache_stats().unwrap().hits, 0);
                }
                ResourceCase::PendingInvalidation => {
                    let (sender, mut receiver) = oneshot::channel::<()>();
                    let (released, mut release) = oneshot::channel::<()>();
                    let server = async {
                        let (mut tls, _) = peer.request(false).await;
                        sender.send(&cx, ()).unwrap();
                        release.recv(&cx).await.unwrap();
                        json_reply(&mut tls, &terminal(41, &read_result(60000))).await;
                    };
                    let read = client.read(&cx, request.clone(), || Ok(next_id(&ids)), |_| Ok(()));
                    let clear = async {
                        receiver.recv(&cx).await.unwrap();
                        client.clone().clear().unwrap();
                        released.send(&cx, ()).unwrap();
                    };
                    let ((), (result, ())) = pair(Box::pin(server), Box::pin(pair(Box::pin(read), Box::pin(clear)))).await;
                    assert!(matches!(result, Err(ReadError::Invalidated)));
                    assert_eq!(client.cache_stats().unwrap().fills, 0);
                    let ((), fresh) = pair(Box::pin(serve_read(&peer, 42, &request, &read_result(60000))),
                        Box::pin(client.read(&cx, request.clone(), || Ok(next_id(&ids)), |_| Ok(())))).await;
                    assert!(fresh.unwrap().is_complete());
                    assert_eq!(peer.posts.load(Ordering::SeqCst), 2);
                }
                ResourceCase::Preflight => {
                    let wrong = core("tools/call", false);
                    assert!(matches!(Box::pin(client.read(&cx, wrong, || panic!("wrong method cannot allocate ID"), |_| Ok(()))).await,
                        Err(ReadError::NotResourceRead)));
                    let mut params = request.encode_params().unwrap().unwrap();
                    params["_meta"]["com.example/oversized"] = json!("x".repeat(8192));
                    let oversized = CoreRequest::decode(ProtocolEra::Modern2026, "resources/read", Some(&params)).unwrap();
                    assert!(matches!(Box::pin(client.read(&cx, oversized, || panic!("oversize cannot allocate ID"), |_| Ok(()))).await,
                        Err(ReadError::Core(ManagedCoreError::RequestTooLarge))));
                    cancellation.cancel();
                    assert!(matches!(Box::pin(client.read_with_cancellation(&cx, &cancellation, request, || Ok(next_id(&ids)), |_| Ok(()))).await,
                        Err(ReadError::Core(ManagedCoreError::Cancelled))));
                    assert_eq!(peer.posts.load(Ordering::SeqCst), 0);
                    assert_eq!(peer.tokens.load(Ordering::SeqCst), 1);
                }
            }
            assert!(cx.checkpoint().is_ok());
            peer.quiet();
            session.close();
        });
        asupersync::time::timeout_at(cx.now().saturating_add_nanos(20_000_000_000), scenario)
            .await.expect("resource-read scenario must settle within its bound");
    }));
}

#[test]
fn complete_resources_reuse_exact_cached_contents_without_notifications_or_ids() { isolated_resource("complete_resources_reuse_exact_cached_contents_without_notifications_or_ids", ResourceCase::Cached); }
#[test]
fn resource_caching_is_disabled_until_explicitly_enabled() { isolated_resource("resource_caching_is_disabled_until_explicitly_enabled", ResourceCase::DefaultUncached); }
#[test]
fn zero_ttl_read_is_never_reused() { isolated_resource("zero_ttl_read_is_never_reused", ResourceCase::ZeroTtl); }
#[test]
fn oversized_cache_entry_returns_data_without_retention() { isolated_resource("oversized_cache_entry_returns_data_without_retention", ResourceCase::TinyCache); }
#[test]
fn resource_cache_identity_keeps_request_metadata() { isolated_resource("resource_cache_identity_keeps_request_metadata", ResourceCase::Metadata); }
#[test]
fn resource_cache_identity_keeps_exact_read_uri() { isolated_resource("resource_cache_identity_keeps_exact_read_uri", ResourceCase::DifferentUri); }
#[test]
fn present_empty_continuations_always_post_without_replacing_ordinary_cached_read() { isolated_resource("present_empty_continuations_always_post_without_replacing_ordinary_cached_read", ResourceCase::Continuation); }
#[test]
fn input_required_is_returned_without_caching_or_automatic_continuation() { isolated_resource("input_required_is_returned_without_caching_or_automatic_continuation", ResourceCase::InputRequired); }
#[test]
fn clearing_a_shared_resource_cache_forces_an_explicit_fresh_read() { isolated_resource("clearing_a_shared_resource_cache_forces_an_explicit_fresh_read", ResourceCase::Clear); }
#[test]
fn validated_external_resource_update_invalidates_retained_read() { isolated_resource("validated_external_resource_update_invalidates_retained_read", ResourceCase::ExternalUpdate); }
#[test]
fn resource_catalog_visibility_change_invalidates_retained_read() { isolated_resource("resource_catalog_visibility_change_invalidates_retained_read", ResourceCase::ExternalListChange); }
#[test]
fn inline_resource_update_retires_old_read_without_replaying_it() { isolated_resource("inline_resource_update_retires_old_read_without_replaying_it", ResourceCase::InlineUpdate); }
#[test]
fn unrelated_notifications_are_delivered_before_resource_terminal() { isolated_resource("unrelated_notifications_are_delivered_before_resource_terminal", ResourceCase::Incremental); }
#[test]
fn host_refusal_releases_resource_response_without_cache_fill() { isolated_resource("host_refusal_releases_resource_response_without_cache_fill", ResourceCase::HostRefusal); }
#[test]
fn malformed_resource_result_cannot_poison_subsequent_reads() { isolated_resource("malformed_resource_result_cannot_poison_subsequent_reads", ResourceCase::InvalidResult); }
#[test]
fn resource_content_count_limit_is_checked_before_cache_fill() { isolated_resource("resource_content_count_limit_is_checked_before_cache_fill", ResourceCase::ContentsLimit); }
#[test]
fn cancelled_resource_read_releases_idle_response() { isolated_resource("cancelled_resource_read_releases_idle_response", ResourceCase::Cancel); }
#[test]
fn closed_login_releases_idle_resource_response() { isolated_resource("closed_login_releases_idle_resource_response", ResourceCase::Close); }
#[test]
fn abandoned_resource_read_releases_idle_response() { isolated_resource("abandoned_resource_read_releases_idle_response", ResourceCase::Drop); }
#[test]
fn resource_read_cannot_outlive_its_opening_token_or_trigger_renewal() { isolated_resource("resource_read_cannot_outlive_its_opening_token_or_trigger_renewal", ResourceCase::Expire); }
#[test]
fn request_id_callback_revocation_prevents_resource_post() { isolated_resource("request_id_callback_revocation_prevents_resource_post", ResourceCase::RevokeBeforePost); }
#[test]
fn request_id_callback_clear_prevents_resource_post() { isolated_resource("request_id_callback_clear_prevents_resource_post", ResourceCase::ClearBeforePost); }
#[test]
fn revoked_credentials_cannot_use_an_already_warm_resource_cache() { isolated_resource("revoked_credentials_cannot_use_an_already_warm_resource_cache", ResourceCase::RevokedHit); }
#[test]
fn external_clear_fences_an_already_pending_resource_fill() { isolated_resource("external_clear_fences_an_already_pending_resource_fill", ResourceCase::PendingInvalidation); }
#[test]
fn resource_preflight_failures_have_no_id_or_network_effects() { isolated_resource("resource_preflight_failures_have_no_id_or_network_effects", ResourceCase::Preflight); }
