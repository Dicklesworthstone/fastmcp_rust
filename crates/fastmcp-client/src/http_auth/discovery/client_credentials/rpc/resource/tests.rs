use super::*;
use std::cell::Cell;
use std::sync::atomic::AtomicUsize;
use std::time::Duration;

use fastmcp_core::CanonicalHttpUrl;
use fastmcp_protocol::{ClientCapabilities, FinalRequestMeta, JsonRpcRequest};
use fastmcp_protocol::protocol_policy::ProtocolEra;
use serde_json::{Value, json};

use crate::http_auth::BoundBearerCredential;
use crate::http_auth::discovery::client_credentials::{
    ClientInner, ClientSecret, MachineAuthentication, ServiceToken, TokenState,
};

fn request(mut params: Value) -> CoreRequest {
    params["_meta"] = serde_json::to_value(FinalRequestMeta::new(ClientCapabilities::default())).unwrap();
    CoreRequest::decode(ProtocolEra::Modern2026, "resources/read", Some(&params)).unwrap()
}
pub(super) fn ordinary() -> CoreRequest { request(json!({"uri":"file:///one"})) }
pub(super) fn complete(request: &CoreRequest, ttl: u64, scope: &str) -> CoreResult {
    request.decode_result(&format!(r#"{{"resultType":"complete","contents":[{{"uri":"file:///one","text":"first"}},{{"uri":"file:///two","blob":"AAEC"}}],"ttlMs":{ttl},"cacheScope":"{scope}","x-exact":{{"z":900719925474099312345,"a":1.20e+4}}}}"#)).unwrap()
}
fn notification(method: &str, params: Option<Value>) -> ServerNotification {
    ServerNotification::decode(&JsonRpcRequest::notification(method, params)).unwrap()
}
pub(super) fn runtime() -> asupersync::runtime::Runtime {
    asupersync::runtime::RuntimeBuilder::current_thread()
        .with_reactor(asupersync::runtime::reactor::create_reactor().unwrap())
        .blocking_threads(0, 2).build().unwrap()
}

// A pre-acquired, owner-bound credential isolates the public cache-consumer
// path. These tests do not claim issuer discovery or authenticated HTTPS proof.
// Cache misses deliberately stop in next_ids before any network dispatch.
pub(super) fn consumer(limits: ClientCredentialsResourceLimits) -> ClientCredentialsResourceClient {
    let resource = CanonicalHttpUrl::parse("https://machine.example/mcp").unwrap();
    let closed = McpRequestCancellation::new();
    let expires_at = Instant::now() + Duration::from_secs(600);
    let bearer = BoundBearerCredential::bind_with_expiry(resource.clone(), "resource-test-token", expires_at)
        .unwrap().for_owner(&closed).unwrap();
    let token = ServiceToken { bearer, scopes: vec![], expires_at, renew_after: expires_at };
    let client = ClientCredentialsClient { inner: Arc::new(ClientInner {
        resource,
        token_endpoint: CanonicalHttpUrl::parse("https://issuer.example/token").unwrap(),
        client_id: "resource-test-client".to_owned(), scopes: vec![],
        authentication: MachineAuthentication::Basic(Arc::new(ClientSecret("test-secret".to_owned()))),
        issuer_roots: vec![], resource_tls: None, timeout: Duration::from_secs(5),
        maximum_lifetime: Duration::from_secs(600), leeway: Duration::from_secs(30),
        closed, pending: AtomicUsize::new(0),
        state: Arc::new(asupersync::sync::Mutex::new(TokenState { current: Some(token), generation: 1 })),
    }) };
    ClientCredentialsResourceClient::new(client, limits).with_cache_limits(8, 64 * 1024).unwrap()
}
pub(super) fn prime(client: &ClientCredentialsResourceClient, request: &CoreRequest, result: CoreResult) {
    let (_, stamped) = prepare(client.client.resource(), request, &RequestId::Number(1)).unwrap();
    let key = cache_key(client.client.resource().as_str(), &stamped, 1).unwrap();
    let mut cache = client.cache().unwrap();
    let captured = cache.begin_fetch(key.result_set());
    assert_eq!(cache.insert_if_current(key, captured, result), FinalCacheInsert::Stored);
}
fn abort_ids() -> Result<(RequestId, RequestId), ClientCredentialsResourceError> {
    Err(ManagedResourceError::AbortedByHost.into())
}

#[test]
fn machine_read_preserves_mixed_contents_and_exact_unknown_payloads() {
    let request = ordinary();
    let result = complete(&request, 60000, "private");
    assert!(admit_result(&result, 2).unwrap());
    assert!(matches!(admit_result(&result, 1), Err(ManagedResourceError::ContentsLimit)));
    let encoded = result.encode().unwrap();
    assert!(encoded.contains("900719925474099312345") && encoded.contains("1.20e+4"));
    assert!(encoded.find("first").unwrap() < encoded.find("AAEC").unwrap());
    let read = ClientCredentialsResourceRead { uri: "file:///one".to_owned(), result, credential_generation: 7, cache_hit: false };
    assert!(read.is_complete());
    assert_eq!(read.uri(), "file:///one");
    assert_eq!(read.credential_generation(), 7);
    assert!(!read.is_cache_hit());
    assert_eq!(read.into_result().encode().unwrap(), encoded);
}

#[test]
fn machine_input_required_and_present_empty_continuations_never_become_reusable() {
    let result = ordinary().decode_result(r#"{"resultType":"input_required","requestState":"","ttlMs":60000,"cacheScope":"public"}"#).unwrap();
    assert!(!admit_result(&result, 0).unwrap());
    assert!(crate::cache::final_cache_hints(&result).is_none());
    let read = ClientCredentialsResourceRead { uri: "file:///one".to_owned(), result, credential_generation: 1, cache_hit: false };
    assert!(!read.is_complete());
    for params in [
        json!({"uri":"file:///one","requestState":""}),
        json!({"uri":"file:///one","inputResponses":{}}),
        json!({"uri":"file:///one","requestState":"opaque","inputResponses":{}}),
    ] {
        let request = request(params);
        assert!(!read_identity(&request).unwrap().1);
        assert!(cache_key("https://machine.example/mcp", &request, 1).is_err());
    }
}

#[test]
fn machine_resource_keys_bind_target_generation_uri_and_exact_metadata() {
    let original = ordinary();
    let key = cache_key("https://machine.example/mcp", &original, 1).unwrap();
    assert_ne!(key, cache_key("https://machine.example/mcp", &original, 2).unwrap());
    assert_ne!(key, cache_key("https://other.example/mcp", &original, 1).unwrap());
    assert_ne!(key, cache_key("https://machine.example/mcp", &request(json!({"uri":"file:///two"})), 1).unwrap());
    let mut params = original.encode_params().unwrap().unwrap();
    params["_meta"]["com.example/tenant"] = json!("different");
    let changed = CoreRequest::decode(ProtocolEra::Modern2026, "resources/read", Some(&params)).unwrap();
    assert_ne!(key, cache_key("https://machine.example/mcp", &changed, 1).unwrap());
}

#[test]
fn machine_resource_updates_fence_inflight_fills_even_when_caching_is_disabled() {
    let request = ordinary();
    let key = cache_key("https://machine.example/mcp", &request, 1).unwrap();
    for enabled in [false, true] {
        for (method, params) in [
            ("notifications/resources/updated", Some(json!({"uri":"file:///one"}))),
            ("notifications/resources/list_changed", None),
        ] {
            let mut cache = FinalResultCache::default();
            cache.set_enabled(enabled);
            let captured = cache.begin_fetch(key.result_set());
            cache.invalidate_notification(&notification(method, params));
            assert_ne!(captured, cache.begin_fetch(key.result_set()));
            if enabled {
                assert_eq!(cache.insert_if_current(key.clone(), captured, complete(&request, 60000, "public")), FinalCacheInsert::InvalidatedDuringFetch);
            }
        }
    }
    let mut cache = FinalResultCache::default();
    let captured = cache.begin_fetch(key.result_set());
    cache.invalidate_notification(&notification("notifications/tools/list_changed", None));
    assert_eq!(captured, cache.begin_fetch(key.result_set()));
}

#[test]
fn machine_resource_zero_ttl_and_oversized_entries_are_not_retained() {
    let request = ordinary();
    let key = cache_key("https://machine.example/mcp", &request, 1).unwrap();
    let mut cache = FinalResultCache::with_limits(1, 1);
    let captured = cache.begin_fetch(key.result_set());
    assert_eq!(cache.insert_if_current(key.clone(), captured, complete(&request, 0, "private")), FinalCacheInsert::ImmediatelyStale);
    assert_eq!(cache.insert_if_current(key.clone(), captured, complete(&request, 60000, "private")), FinalCacheInsert::Oversized);
    assert!(matches!(cache.lookup(&key), FinalCacheLookup::Miss(_)));
}

#[test]
fn machine_resource_public_cache_hit_uses_current_custody_without_callbacks() {
    runtime().block_on(async {
        let cx = Cx::current().unwrap();
        let client = consumer(ClientCredentialsResourceLimits::default());
        let request = ordinary();
        let result = complete(&request, 60000, "public");
        let encoded = result.encode().unwrap();
        prime(&client, &request, result);
        let read = Box::pin(client.clone().read(&cx, request,
            || panic!("a cache hit must not allocate request IDs"),
            |_| panic!("a cache hit must not replay notifications"))).await.unwrap();
        assert!(read.is_cache_hit() && read.is_complete());
        assert_eq!(read.credential_generation(), 1);
        assert_eq!(read.result().encode().unwrap(), encoded);
    });
}

#[test]
fn machine_resource_cached_data_cannot_escape_cancel_close_revoke_or_expiry() {
    runtime().block_on(async {
        let cx = Cx::current().unwrap();
        for case in 0..4 {
            let client = consumer(ClientCredentialsResourceLimits::default());
            let request = ordinary();
            prime(&client, &request, complete(&request, 60000, "public"));
            let cancellation = McpRequestCancellation::new();
            match case {
                0 => { cancellation.cancel(); },
                1 => client.client.close(),
                _ => {
                    let mut state = client.client.inner.state.try_lock_owned().unwrap();
                    let token = state.current.as_mut().unwrap();
                    if case == 2 { token.bearer.revoke(); }
                    else { token.expires_at = Instant::now(); }
                }
            }
            let result = Box::pin(client.read_with_cancellation(&cx, &cancellation, request,
                || panic!("unusable credentials must not reach request IDs"), |_| Ok(()))).await;
            assert!(result.is_err());
        }
    });
}

#[test]
fn machine_resource_public_cache_cannot_cross_generation_or_consumer_instances() {
    runtime().block_on(async {
        let cx = Cx::current().unwrap();
        let client = consumer(ClientCredentialsResourceLimits::default());
        let request = ordinary();
        prime(&client, &request, complete(&request, 60000, "public"));
        let separate = ClientCredentialsResourceClient::new(client.client.clone(), client.limits)
            .with_cache_limits(8, 64 * 1024).unwrap();
        assert!(matches!(Box::pin(separate.read(&cx, request.clone(), abort_ids, |_| Ok(()))).await,
            Err(ClientCredentialsResourceError::Resource(ManagedResourceError::AbortedByHost))));
        client.client.inner.state.try_lock_owned().unwrap().generation = 2;
        assert!(matches!(Box::pin(client.read(&cx, request, abort_ids, |_| Ok(()))).await,
            Err(ClientCredentialsResourceError::Resource(ManagedResourceError::AbortedByHost))));
    });
}

#[test]
fn machine_resource_notifications_and_clone_clear_retire_cached_reads() {
    runtime().block_on(async {
        let cx = Cx::current().unwrap();
        for case in 0..3 {
            let client = consumer(ClientCredentialsResourceLimits::default());
            let request = ordinary();
            prime(&client, &request, complete(&request, 60000, "private"));
            match case {
                0 => client.clone().clear().unwrap(),
                1 => client.invalidate_notification(&notification("notifications/resources/updated", Some(json!({"uri":"file:///one"})))).unwrap(),
                _ => client.invalidate_notification(&notification("notifications/resources/list_changed", None)).unwrap(),
            }
            assert!(matches!(Box::pin(client.read(&cx, request, abort_ids, |_| Ok(()))).await,
                Err(ClientCredentialsResourceError::Resource(ManagedResourceError::AbortedByHost))));
        }
    });
}

#[test]
fn machine_resource_continuations_bypass_ordinary_cached_answers() {
    runtime().block_on(async {
        let cx = Cx::current().unwrap();
        let client = consumer(ClientCredentialsResourceLimits::default());
        let original = ordinary();
        prime(&client, &original, complete(&original, 60000, "public"));
        for params in [json!({"uri":"file:///one","requestState":""}), json!({"uri":"file:///one","inputResponses":{}})] {
            let calls = Cell::new(0);
            let result = Box::pin(client.read(&cx, request(params), || { calls.set(calls.get() + 1); abort_ids() }, |_| Ok(()))).await;
            assert!(matches!(result, Err(ClientCredentialsResourceError::Resource(ManagedResourceError::AbortedByHost))));
            assert_eq!(calls.get(), 1);
        }
    });
}

#[test]
fn machine_resource_callback_invalidation_and_cancellation_prevent_dispatch() {
    runtime().block_on(async {
        let cx = Cx::current().unwrap();
        for case in 0..3 {
            let client = consumer(ClientCredentialsResourceLimits::default());
            let cancellation = McpRequestCancellation::new();
            let calls = Cell::new(0);
            let result = Box::pin(client.read_with_cancellation(&cx, &cancellation, ordinary(), || {
                calls.set(calls.get() + 1);
                match case {
                    0 => client.clear().unwrap(),
                    1 => { cancellation.cancel(); },
                    _ => client.client.close(),
                }
                Ok((RequestId::Number(10), RequestId::Number(11)))
            }, |_| Ok(()))).await;
            if case == 0 {
                assert!(matches!(result, Err(ClientCredentialsResourceError::Resource(ManagedResourceError::Invalidated))));
            } else { assert!(result.is_err()); }
            assert_eq!(calls.get(), 1);
        }
    });
}

#[test]
fn machine_resource_cache_hits_still_enforce_content_and_byte_limits() {
    runtime().block_on(async {
        let cx = Cx::current().unwrap();
        let client = consumer(ClientCredentialsResourceLimits::new(ManagedCoreLimits::default(), 1).unwrap());
        let request = ordinary();
        prime(&client, &request, complete(&request, 60000, "private"));
        assert!(matches!(Box::pin(client.read(&cx, request.clone(), || panic!("expected a hit"), |_| Ok(()))).await,
            Err(ClientCredentialsResourceError::Resource(ManagedResourceError::ContentsLimit))));
        let core = ManagedCoreLimits::new(4096, 1024, 2048, 1, Duration::from_secs(1)).unwrap();
        let client = consumer(ClientCredentialsResourceLimits::new(core, 2).unwrap());
        let large = request.decode_result(&json!({
            "resultType":"complete", "contents":[{"uri":"file:///one", "text":"x".repeat(2048)}],
            "ttlMs":60000, "cacheScope":"private",
        }).to_string()).unwrap();
        prime(&client, &request, large);
        assert!(matches!(Box::pin(client.read(&cx, request, || panic!("expected a hit"), |_| Ok(()))).await,
            Err(ClientCredentialsResourceError::Core(ClientCredentialsCoreError::Protocol(ManagedCoreError::ResponseByteLimit)))));
    });
}

#[test]
fn machine_resource_rejects_wrong_methods_results_and_unbounded_policy() {
    let params = json!({"_meta":FinalRequestMeta::new(ClientCapabilities::default())});
    let catalog = CoreRequest::decode(ProtocolEra::Modern2026, "resources/list", Some(&params)).unwrap();
    assert!(matches!(read_identity(&catalog), Err(ManagedResourceError::NotResourceRead)));
    let result = catalog.decode_result(r#"{"resultType":"complete","resources":[],"ttlMs":0,"cacheScope":"private"}"#).unwrap();
    assert!(matches!(admit_result(&result, 10), Err(ManagedResourceError::InvalidResult)));
    assert!(ClientCredentialsResourceLimits::new(ManagedCoreLimits::default(), 100_001).is_err());
    let client = consumer(ClientCredentialsResourceLimits::default());
    for (entries, bytes) in [(0, 1), (1, 0), (MAX_FINAL_CACHE_CAPACITY + 1, 1), (1, MAX_FINAL_CACHE_MAX_BYTES + 1)] {
        assert!(client.clone().with_cache_limits(entries, bytes).is_err());
    }
}
