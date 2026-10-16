//! Public DPoP catalog calls through a real local TLS peer.
//!
//! Requires native-tls-roots. All certificate bytes are the repository's
//! existing TEST ONLY OAuth fixture, inlined because RCH excludes PEM files.
//! Proof claims below are decoded for assertions, not validated as a server.

use std::collections::HashSet;
use std::future::{Future, poll_fn};
use std::pin::pin;
use std::task::{Context, Poll, Waker};
use std::time::{Duration, Instant};

use asupersync::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use asupersync::net::TcpListener;
use asupersync::runtime::{RuntimeBuilder, reactor::create_reactor};
use asupersync::tls::{Certificate, CertificateChain, PrivateKey, TlsAcceptorBuilder};
use fastmcp_core::CanonicalHttpUrl;
use fastmcp_protocol::dpop::DpopKey;
use fastmcp_protocol::{ClientCapabilities, FinalRequestMeta};
use serde::Serialize;
use serde_json::json;

use super::*;
use crate::http_auth::dpop::DpopSession;
use crate::http_auth::dpop::native::DpopHttpPolicy;

const ROOT: &[u8] = b"-----BEGIN CERTIFICATE-----\nMIIBgzCCASmgAwIBAgICA+kwCgYIKoZIzj0EAwIwJzElMCMGA1UEAwwcRmFzdE1D\nUCBPQXV0aCBURVNUIE9OTFkgUm9vdDAeFw0yMDAxMDEwMDAwMDBaFw00OTEyMzEw\nMDAwMDBaMCcxJTAjBgNVBAMMHEZhc3RNQ1AgT0F1dGggVEVTVCBPTkxZIFJvb3Qw\nWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAAS5t2O8JZ0hNjgI38E9Ov6i6mKoDRGo\nApMsykFkvgb6Zm9/5gCZ90eIKw7aWgK6iNs7lbtVY9mysZBIqm6pKQO2o0UwQzAS\nBgNVHRMBAf8ECDAGAQH/AgEAMA4GA1UdDwEB/wQEAwIBhjAdBgNVHQ4EFgQU6QNI\nrmvMiLoV3jIoCyohXARwI8gwCgYIKoZIzj0EAwIDSAAwRQIgCKOrW3vhzUJ2EyuY\nvQUTdqGFhy0zEHj4ITFLvXPz1X8CIQCLKD4EKCvS/zkBSu/6uee1WV9d97UpK3yW\nX/aCEJ5+hA==\n-----END CERTIFICATE-----\n";
const LEAF: &[u8] = b"-----BEGIN CERTIFICATE-----\nMIIBjjCCATSgAwIBAgICA+owCgYIKoZIzj0EAwIwJzElMCMGA1UEAwwcRmFzdE1D\nUCBPQXV0aCBURVNUIE9OTFkgUm9vdDAeFw0yMDAxMDEwMDAwMDBaFw00OTEyMzEw\nMDAwMDBaMBQxEjAQBgNVBAMMCWxvY2FsaG9zdDBZMBMGByqGSM49AgEGCCqGSM49\nAwEHA0IABPPKylLna9VpWAlpshHBhSsQHNOv3BaEGX4HSBhHiBVel0ce+qfHF15O\n0T63Zlp7TtxlMdEY+rPpgioSFDQVadijYzBhMAwGA1UdEwEB/wQCMAAwLAYDVR0R\nBCUwI4IJbG9jYWxob3N0hwR/AAABhxAAAAAAAAAAAAAAAAAAAAABMBMGA1UdJQQM\nMAoGCCsGAQUFBwMBMA4GA1UdDwEB/wQEAwIHgDAKBggqhkjOPQQDAgNIADBFAiEA\n6qrAr2qp/t6K62T9Et2mUU/zfd4kJb+ekyoAim1yTFcCICb6SdVY2fg15/SXf0vE\nIvYelqtTk8FQInCEcIxvfF3m\n-----END CERTIFICATE-----\n";
const KEY: &[u8] = b"-----BEGIN PRIVATE KEY-----\nMIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgcCe44IBKhbw+D/s7\nBjDHOOV0g+EoxFno7VJGKhJeer2hRANCAATzyspS52vVaVgJabIRwYUrEBzTr9wW\nhBl+B0gYR4gVXpdHHvqnxxdeTtE+t2Zae07cZTHRGPqz6YIqEhQ0FWnY\n-----END PRIVATE KEY-----\n";

fn run<F, Fut>(test: F)
where
    F: FnOnce(Cx) -> Fut,
    Fut: Future<Output = ()>,
{
    let runtime = RuntimeBuilder::current_thread()
        .with_reactor(create_reactor().unwrap())
        .blocking_threads(0, 0)
        .build()
        .unwrap();
    runtime.block_on(async {
        let cx = Cx::current().unwrap();
        assert!(cx.blocking_pool_handle().is_none());
        asupersync::time::timeout(cx.now(), Duration::from_secs(20), test(cx))
            .await
            .expect("DPoP catalog TLS test did not settle within its external bound");
    });
    assert!(runtime.shutdown_timeout(Duration::from_secs(1)));
}

fn acceptor() -> TlsAcceptorBuilder {
    TlsAcceptorBuilder::new(
        CertificateChain::from_pem(LEAF).unwrap(),
        PrivateKey::from_pem(KEY).unwrap(),
    )
    .alpn_protocols(vec![b"http/1.1".to_vec()])
}

async fn fixture() -> (TcpListener, DpopHttpClient, DpopCredential) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let target = CanonicalHttpUrl::parse(&format!(
        "https://{}/mcp?tenant=one", listener.local_addr().unwrap(),
    )).unwrap();
    let issuer = CanonicalHttpUrl::parse("https://issuer.example/token").unwrap();
    let session = DpopSession::new(DpopKey::generate().unwrap(), issuer.clone(), target).unwrap();
    let credential = session.admit_token_response(
        &issuer, 200,
        br#"{"access_token":"catalog-access","token_type":"DPoP","expires_in":60}"#,
        Instant::now(), Duration::from_secs(60),
    ).unwrap();
    let root = Certificate::from_pem(ROOT).unwrap().remove(0);
    let policy = DpopHttpPolicy::default()
        .with_resource_root_der(root.as_der().to_vec()).unwrap();
    (listener, DpopHttpClient::new(session, policy).unwrap(), credential)
}

fn request(method: &str) -> CoreRequest {
    CoreRequest::decode(
        ProtocolEra::Modern2026,
        method,
        Some(&json!({
            "includeTags":["selected"],
            "_meta":FinalRequestMeta::new(ClientCapabilities::default()),
        })),
    ).unwrap()
}

fn payload(method: &str, empty: bool, cursor: Option<&str>) -> Value {
    let (field, entry) = match method {
        "tools/list" => ("tools", json!({"name":"private-entry","inputSchema":{"type":"object"}})),
        "resources/list" => ("resources", json!({"name":"private-entry","uri":"note:///item"})),
        "resources/templates/list" => ("resourceTemplates", json!({"name":"private-entry","uriTemplate":"note:///{id}"})),
        "prompts/list" => ("prompts", json!({"name":"private-entry"})),
        _ => panic!("not a catalog"),
    };
    let mut result = json!({"resultType":"complete","ttlMs":0,"cacheScope":"private"});
    result[field] = if empty { json!([]) } else { json!([entry]) };
    if let Some(cursor) = cursor {
        result["nextCursor"] = json!(cursor);
    }
    result
}

async fn pair<L: Future, R: Future>(left: L, right: R) -> (L::Output, R::Output) {
    let mut left = pin!(left);
    let mut right = pin!(right);
    let (mut one, mut two) = (None, None);
    poll_fn(|task| {
        if one.is_none() {
            if let Poll::Ready(value) = left.as_mut().poll(task) { one = Some(value); }
        }
        if two.is_none() {
            if let Poll::Ready(value) = right.as_mut().poll(task) { two = Some(value); }
        }
        if one.is_some() && two.is_some() {
            Poll::Ready((one.take().unwrap(), two.take().unwrap()))
        } else {
            Poll::Pending
        }
    }).await
}

async fn read_request<IO: AsyncRead + Unpin>(io: &mut IO) -> (String, Value) {
    let mut bytes = Vec::new();
    let mut buffer = [0; 2048];
    let end = loop {
        let count = io.read(&mut buffer).await.unwrap();
        assert!(count > 0 && bytes.len() + count <= 32 * 1024);
        bytes.extend_from_slice(&buffer[..count]);
        if let Some(index) = bytes.windows(4).position(|part| part == b"\r\n\r\n") {
            break index + 4;
        }
    };
    let headers = std::str::from_utf8(&bytes[..end]).unwrap().to_owned();
    let length: usize = header(&headers, "content-length").parse().unwrap();
    assert!(end + length <= 32 * 1024);
    while bytes.len() < end + length {
        let count = io.read(&mut buffer).await.unwrap();
        assert!(count > 0 && bytes.len() + count <= 32 * 1024);
        bytes.extend_from_slice(&buffer[..count]);
    }
    assert_eq!(bytes.len(), end + length);
    (headers, serde_json::from_slice(&bytes[end..]).unwrap())
}

fn header<'a>(headers: &'a str, wanted: &str) -> &'a str {
    let fields: Vec<_> = headers.lines().filter_map(|line| line.split_once(':'))
        .filter(|(name, _)| name.eq_ignore_ascii_case(wanted))
        .map(|(_, value)| value.trim()).collect();
    assert_eq!(fields.len(), 1, "one {wanted} field must reach the peer");
    fields[0]
}

// Assertion-only decoder for the locally generated compact JWT. No crypto
// or production admission claim is made by decoding these fixture bytes.
fn claims(segment: &str) -> Value {
    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    assert!(segment.len() <= 8192);
    let (mut bits, mut accumulator) = (0_u32, 0_u32);
    let mut bytes = Vec::new();
    for byte in segment.bytes() {
        let value = ALPHABET.iter().position(|candidate| *candidate == byte).unwrap() as u32;
        accumulator = (accumulator << 6) | value;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            bytes.push((accumulator >> bits) as u8);
            accumulator &= (1 << bits) - 1;
        }
    }
    assert_eq!(accumulator, 0);
    serde_json::from_slice(&bytes).unwrap()
}

async fn respond<IO: AsyncWrite + Unpin>(
    io: &mut IO, id: Value, status: u16, result: Value, nonce: &str,
) {
    let body = serde_json::to_vec(&json!({"jsonrpc":"2.0","id":id,"result":result})).unwrap();
    io.write_all(format!(
        "HTTP/1.1 {status} Reply\r\nContent-Type: application/json\r\nContent-Length: {}\r\nDPoP-Nonce: {nonce}\r\nConnection: close\r\n\r\n", body.len(),
    ).as_bytes()).await.unwrap();
    io.write_all(&body).await.unwrap();
    io.shutdown().await.unwrap();
}

fn check_catalog<T: Serialize>(catalog: &ManagedCatalog<T>) {
    assert_eq!(catalog.entries().len(), 2);
    assert_eq!(catalog.page_count(), 3);
    assert!(catalog.page_entries(1).unwrap().is_empty());
    assert_eq!(catalog.page_has_continuation(0), Some(true));
    assert_eq!(catalog.page_has_continuation(2), Some(false));
    for entry in serde_json::to_value(catalog.entries()).unwrap().as_array().unwrap() {
        assert_eq!(entry["name"], "private-entry");
    }
    assert!(!format!("{catalog:?}").contains("private-entry"));
}

#[test]
fn https_traversal_preserves_filters_and_uses_fresh_ids_proofs_and_resource_nonces() {
    for method in ["tools/list", "resources/list", "resources/templates/list", "prompts/list"] {
        run(|cx| async move {
            let (listener, mut client, credential) = fixture().await;
            let target = client.resource().as_str().to_owned();
            let acceptor = acceptor().build().unwrap();
            let application = client.collect_catalog(
                &cx, &credential, request(method), "wire", ManagedCoreLimits::default(), CatalogLimits::default(),
            );
            let server = async {
                let mut identities = HashSet::new();
                let mut key = None;
                for index in 0..3 {
                    let (socket, _) = listener.accept().await.unwrap();
                    let mut socket = acceptor.accept(socket).await.unwrap();
                    let (head, body) = read_request(&mut socket).await;
                    assert!(head.starts_with("POST /mcp?tenant=one HTTP/1.1\r\n"));
                    assert_eq!(header(&head, "authorization"), "DPoP catalog-access");
                    assert_eq!(header(&head, "accept"), "application/json");
                    assert_eq!(header(&head, "mcp-method"), method);
                    assert_eq!(body["method"], method);
                    assert_eq!(body["id"], format!("wire.{index}"));
                    assert_eq!(body["params"]["includeTags"], json!(["selected"]));
                    assert_eq!(body["params"].get("cursor"), (index != 0).then_some(&json!("same-雪%2F")));
                    let segments: Vec<_> = header(&head, "dpop").split('.').collect();
                    assert_eq!(segments.len(), 3);
                    assert!(!segments[2].is_empty());
                    let protected = claims(segments[0]);
                    let proof = claims(segments[1]);
                    assert_eq!(protected["typ"], "dpop+jwt");
                    assert_eq!(protected["alg"], "ES256");
                    assert!(protected["jwk"].get("d").is_none());
                    if let Some(key) = &key { assert_eq!(&protected["jwk"], key); }
                    key = Some(protected["jwk"].clone());
                    assert_eq!(proof["htm"], "POST");
                    assert_eq!(proof["htu"], target.split('?').next().unwrap());
                    assert_eq!(proof["ath"], "AOO12QmN2BnA56Mimn-9ypA5UgHbRqWGhu4E9AXpTJU");
                    assert!(identities.insert(proof["jti"].as_str().unwrap().to_owned()));
                    assert_eq!(proof["nonce"].as_str(), match index { 0 => None, 1 => Some("nonce-0"), _ => Some("nonce-1") });
                    respond(
                        &mut socket, body["id"].clone(), 200,
                        payload(method, index == 1, if index == 2 { None } else { Some("same-雪%2F") }),
                        &format!("nonce-{index}"),
                    ).await;
                }
            };
            let (result, ()) = pair(application, server).await;
            match (method, result.unwrap()) {
                ("tools/list", CatalogCollection::Tools(catalog)) => check_catalog(&catalog),
                ("resources/list", CatalogCollection::Resources(catalog)) => check_catalog(&catalog),
                ("resources/templates/list", CatalogCollection::Templates(catalog)) => check_catalog(&catalog),
                ("prompts/list", CatalogCollection::Prompts(catalog)) => check_catalog(&catalog),
                _ => panic!("the initial method must own the complete catalog"),
            }
            assert!(listener.poll_accept(&mut Context::from_waker(Waker::noop())).is_pending());
        });
    }
}

#[test]
fn https_catalog_bounds_and_bad_continuations_never_replay_or_publish_partial_entries() {
    for case in 0..5 {
        run(|cx| async move {
            let (listener, mut client, credential) = fixture().await;
            let acceptor = acceptor().build().unwrap();
            let limits = CatalogLimits::new(if case == 1 { 1 } else { 2 }, if case == 2 { 1 } else { 2 }, 8192).unwrap();
            let application = client.collect_catalog(
                &cx, &credential, request("tools/list"), "bound", ManagedCoreLimits::default(), limits,
            );
            let server = async {
                let expected = if case == 1 { 1 } else { 2 };
                for index in 0..expected {
                    let (socket, _) = listener.accept().await.unwrap();
                    let mut socket = acceptor.accept(socket).await.unwrap();
                    let (_, body) = read_request(&mut socket).await;
                    assert_eq!(body["id"], format!("bound.{index}"));
                    let second = index == 1;
                    let id = if case == 3 && second { json!("bound.0") } else { body["id"].clone() };
                    respond(
                        &mut socket, id, if case == 4 && second { 401 } else { 200 },
                        payload("tools/list", false, if second { None } else { Some("next") }), "admitted-nonce",
                    ).await;
                }
            };
            let (result, ()) = pair(application, server).await;
            match case {
                0 => {
                    let CatalogCollection::Tools(catalog) = result.unwrap() else { panic!("wrong catalog"); };
                    assert_eq!(catalog.entries().len(), 2);
                    assert_eq!(catalog.page_count(), 2);
                }
                1 => assert!(matches!(result, Err(DpopCatalogError::Catalog(CatalogError::PageLimit)))),
                2 => assert!(matches!(result, Err(DpopCatalogError::Catalog(CatalogError::EntryLimit)))),
                3 => assert!(matches!(result, Err(DpopCatalogError::Core(DpopCoreError::Protocol(ManagedCoreError::ResponseIdMismatch))))),
                _ => assert!(matches!(result, Err(DpopCatalogError::Core(DpopCoreError::Protocol(ManagedCoreError::HttpStatus { status: 401 }))))),
            }
            assert!(!client.revocation_handle().is_revoked());
            assert!(listener.poll_accept(&mut Context::from_waker(Waker::noop())).is_pending());
        });
    }
}

#[test]
fn https_stalled_continuation_retires_on_cancellation_revocation_or_owner_abandonment() {
    for cause in 0..4 {
        run(|cx| async move {
            let (listener, mut client, credential) = fixture().await;
            let acceptor = acceptor().build().unwrap();
            let cancelled = McpRequestCancellation::new();
            let abandon = McpRequestCancellation::new();
            let owner = client.revocation_handle();
            let application = async {
                let mut operation = pin!(client.collect_catalog_with_cancellation(
                    &cx, &cancelled, &credential, request("tools/list"), "stop", ManagedCoreLimits::default(), CatalogLimits::default(),
                ));
                let mut dropped = pin!(abandon.cancelled());
                poll_fn(|task| {
                    if dropped.as_mut().poll(task).is_ready() { return Poll::Ready(None); }
                    operation.as_mut().poll(task).map(Some)
                }).await
            };
            let server = async {
                let (socket, _) = listener.accept().await.unwrap();
                let mut socket = acceptor.accept(socket).await.unwrap();
                let (_, body) = read_request(&mut socket).await;
                assert_eq!(body["id"], "stop.0");
                respond(&mut socket, body["id"].clone(), 200, payload("tools/list", false, Some("next")), "next-nonce").await;
                drop(socket);
                let (socket, _) = listener.accept().await.unwrap();
                let mut socket = acceptor.accept(socket).await.unwrap();
                let (_, body) = read_request(&mut socket).await;
                assert_eq!(body["id"], "stop.1");
                // No second-page response exists. This proves that pending
                // network ownership, not just a post-response check, retires.
                match cause {
                    0 => { cancelled.cancel(); }
                    1 => { credential.revoke(); }
                    2 => { owner.revoke(); }
                    _ => { abandon.cancel(); }
                }
                let mut byte = [0];
                assert!(!matches!(socket.read(&mut byte).await, Ok(count) if count > 0));
            };
            let (result, ()) = pair(application, server).await;
            match cause {
                0 => assert!(matches!(result, Some(Err(DpopCatalogError::Core(DpopCoreError::Transport(DpopHttpError::Cancelled)))))),
                1 | 2 => assert!(matches!(result, Some(Err(DpopCatalogError::Core(DpopCoreError::Transport(DpopHttpError::Authorization(_))))))),
                _ => assert!(result.is_none()),
            }
            assert_eq!(owner.is_revoked(), cause == 2);
            assert!(!cx.is_cancel_requested());
            assert!(listener.poll_accept(&mut Context::from_waker(Waker::noop())).is_pending());
            if cause == 0 || cause == 3 {
                // A separate explicit operation can still use the live session
                // and credential after request cancellation or abandonment.
                let next = client.request_core(
                    &cx, &credential, request("tools/list"), RequestId::Number(99), ManagedCoreLimits::default(),
                );
                let peer = async {
                    let (socket, _) = listener.accept().await.unwrap();
                    let mut socket = acceptor.accept(socket).await.unwrap();
                    let (_, body) = read_request(&mut socket).await;
                    assert_eq!(body["id"], 99);
                    respond(&mut socket, body["id"].clone(), 200, payload("tools/list", false, None), "later").await;
                };
                let (result, ()) = pair(next, peer).await;
                assert!(result.is_ok());
            }
        });
    }
}

#[test]
fn https_catalog_deadline_includes_time_spent_on_the_previous_page() {
    run(|cx| async move {
        let (listener, mut client, credential) = fixture().await;
        client.policy = client.policy.clone().with_timeout(Duration::from_secs(3)).unwrap();
        let acceptor = acceptor().build().unwrap();
        let application = client.collect_catalog(
            &cx, &credential, request("tools/list"), "deadline", ManagedCoreLimits::default(), CatalogLimits::default(),
        );
        let server = async {
            let (socket, _) = listener.accept().await.unwrap();
            let mut socket = acceptor.accept(socket).await.unwrap();
            let (_, body) = read_request(&mut socket).await;
            assert_eq!(body["id"], "deadline.0");
            // Deliberately consume most of the original three-second budget.
            asupersync::time::sleep(cx.now(), Duration::from_secs(2)).await;
            respond(&mut socket, body["id"].clone(), 200, payload("tools/list", false, Some("next")), "next").await;
            drop(socket);
            let (socket, _) = listener.accept().await.unwrap();
            let mut socket = acceptor.accept(socket).await.unwrap();
            let (_, body) = read_request(&mut socket).await;
            assert_eq!(body["id"], "deadline.1");
            let started = Instant::now();
            let mut byte = [0];
            assert!(!matches!(socket.read(&mut byte).await, Ok(count) if count > 0));
            started.elapsed()
        };
        let (result, second_page_wait) = pair(application, server).await;
        assert!(matches!(result, Err(DpopCatalogError::Core(DpopCoreError::Transport(DpopHttpError::TimedOut)))));
        // A fresh three-second timeout for page two violates this assertion.
        // The margin allows scheduling overhead without erasing the distinction.
        assert!(second_page_wait < Duration::from_secs(2));
        assert!(listener.poll_accept(&mut Context::from_waker(Waker::noop())).is_pending());
        assert!(!client.revocation_handle().is_revoked());
    });
}

const CATALOG_CHANGE: &str = "data: {\"jsonrpc\":\"2.0\",\"method\":\"notifications/tools/list_changed\"}\r\n\r\n";

fn result_event(id: Value, result: Value) -> String {
    format!("data: {}\r\n\r\n", json!({"jsonrpc":"2.0","id":id,"result":result}))
}

async fn respond_events<IO: AsyncWrite + Unpin>(io: &mut IO, body: &str, nonce: &str) {
    // Send one coalesced response: a callback or malformed tail may close the
    // client before the peer's TLS close-notify completes. The test's result
    // and request-count assertions, not teardown success, decide admission.
    let bytes = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nContent-Length: {}\r\nDPoP-Nonce: {nonce}\r\nConnection: close\r\n\r\n{body}", body.len(),
    );
    io.write_all(bytes.as_bytes()).await.unwrap();
    let _ = io.shutdown().await;
}

#[test]
fn https_streaming_catalog_preserves_mixed_pages_filters_proofs_and_nonces() {
    for method in ["tools/list", "resources/list", "resources/templates/list", "prompts/list"] {
        run(|cx| async move {
            let (listener, mut client, credential) = fixture().await;
            let acceptor = acceptor().build().unwrap();
            let cancellation = McpRequestCancellation::new();
            let mut observed = 0;
            let application = client.collect_catalog_with_events(
                &cx, &cancellation, &credential, request(method), "stream",
                DpopStreamLimits::default(), CatalogLimits::default(),
                |_| { observed += 1; true },
            );
            let server = async {
                let mut proofs = HashSet::new();
                for index in 0..3 {
                    let (socket, _) = listener.accept().await.unwrap();
                    let mut socket = acceptor.accept(socket).await.unwrap();
                    let (head, body) = read_request(&mut socket).await;
                    let accept = header(&head, "accept");
                    assert!(accept.contains("application/json") && accept.contains("text/event-stream"));
                    assert_eq!(header(&head, "authorization"), "DPoP catalog-access");
                    assert_eq!(header(&head, "mcp-method"), method);
                    assert_eq!(body["id"], format!("stream.{index}"));
                    assert_eq!(body["method"], method);
                    assert_eq!(body["params"]["includeTags"], json!(["selected"]));
                    assert_eq!(body["params"].get("cursor"), (index != 0).then_some(&json!("same-雪%2F")));
                    let segments: Vec<_> = header(&head, "dpop").split('.').collect();
                    assert_eq!(segments.len(), 3);
                    let proof = claims(segments[1]);
                    assert!(proofs.insert(proof["jti"].as_str().unwrap().to_owned()));
                    assert_eq!(proof["nonce"].as_str(), match index { 0 => None, 1 => Some("stream-0"), _ => Some("stream-1") });
                    let page = payload(method, index == 1, if index == 2 { None } else { Some("same-雪%2F") });
                    if index == 1 {
                        respond(&mut socket, body["id"].clone(), 200, page, "stream-1").await;
                    } else {
                        let events = format!(": heartbeat\r\n{CATALOG_CHANGE}{}", result_event(body["id"].clone(), page));
                        respond_events(&mut socket, &events, &format!("stream-{index}")).await;
                    }
                }
            };
            let (result, ()) = pair(application, server).await;
            assert_eq!(observed, 2);
            match (method, result.unwrap()) {
                ("tools/list", CatalogCollection::Tools(catalog)) => check_catalog(&catalog),
                ("resources/list", CatalogCollection::Resources(catalog)) => check_catalog(&catalog),
                ("resources/templates/list", CatalogCollection::Templates(catalog)) => check_catalog(&catalog),
                ("prompts/list", CatalogCollection::Prompts(catalog)) => check_catalog(&catalog),
                _ => panic!("the original method must own the complete streaming catalog"),
            }
            assert!(listener.poll_accept(&mut Context::from_waker(Waker::noop())).is_pending());
        });
    }
}

#[test]
fn https_streaming_catalog_waits_for_clean_eof_before_following_a_cursor() {
    for case in 0..5 {
        run(|cx| async move {
            let (listener, mut client, credential) = fixture().await;
            let acceptor = acceptor().build().unwrap();
            let cancellation = McpRequestCancellation::new();
            let mut observed = 0;
            let application = client.collect_catalog_with_events(
                &cx, &cancellation, &credential, request("tools/list"), "tail",
                DpopStreamLimits::default(), CatalogLimits::default(),
                |_| { observed += 1; true },
            );
            let server = async {
                let (socket, _) = listener.accept().await.unwrap();
                let mut socket = acceptor.accept(socket).await.unwrap();
                let (_, body) = read_request(&mut socket).await;
                assert_eq!(body["id"], "tail.0");
                let id = if case == 4 { json!("unrelated") } else { body["id"].clone() };
                let terminal = result_event(id, payload("tools/list", false, Some("next")));
                let events = match case {
                    1 => format!("{terminal}{terminal}"),
                    2 => format!("{terminal}data: {{}}\n"),
                    3 => format!("{terminal}{CATALOG_CHANGE}"),
                    _ => terminal,
                };
                respond_events(&mut socket, &events, "tail-0").await;
                if case == 0 {
                    let (socket, _) = listener.accept().await.unwrap();
                    let mut socket = acceptor.accept(socket).await.unwrap();
                    let (_, body) = read_request(&mut socket).await;
                    assert_eq!(body["id"], "tail.1");
                    assert_eq!(body["params"]["cursor"], "next");
                    respond(&mut socket, body["id"].clone(), 200, payload("tools/list", false, None), "tail-1").await;
                }
            };
            let (result, ()) = pair(application, server).await;
            assert_eq!(observed, 0, "late notifications must not escape the terminal boundary");
            match case {
                0 => {
                    let CatalogCollection::Tools(catalog) = result.unwrap() else { panic!("wrong catalog"); };
                    assert_eq!(catalog.entries().len(), 2);
                    assert_eq!(catalog.page_count(), 2);
                }
                4 => assert!(matches!(result, Err(DpopCatalogError::Core(DpopCoreError::Protocol(ManagedCoreError::ResponseIdMismatch))))),
                _ => assert!(matches!(result, Err(DpopCatalogError::Core(DpopCoreError::Protocol(ManagedCoreError::InvalidResponse))))),
            }
            assert!(listener.poll_accept(&mut Context::from_waker(Waker::noop())).is_pending());
            assert!(!client.revocation_handle().is_revoked());
        });
    }
}

#[test]
fn https_streaming_catalog_notification_limits_and_observer_stops_span_pages() {
    for case in 0..6 {
        run(|cx| async move {
            let (listener, mut client, credential) = fixture().await;
            let acceptor = acceptor().build().unwrap();
            let cancellation = McpRequestCancellation::new();
            let core = ManagedCoreLimits::new(
                8192, 8192, 32768, if case == 1 { 1 } else { 2 }, Duration::from_secs(60),
            ).unwrap();
            let limits = DpopStreamLimits::new(core, Duration::from_secs(10)).unwrap();
            let mut observed = 0;
            let application = client.collect_catalog_with_events(
                &cx, &cancellation, &credential, request("tools/list"), "observe",
                limits, CatalogLimits::default(), |_| {
                    observed += 1;
                    match case {
                        2 => false,
                        3 => { cancellation.cancel(); true }
                        4 => { credential.revoke(); true }
                        5 => panic!("catalog observer failure"),
                        _ => true,
                    }
                },
            );
            let server = async {
                for index in 0..if case <= 1 { 2 } else { 1 } {
                    let (socket, _) = listener.accept().await.unwrap();
                    let mut socket = acceptor.accept(socket).await.unwrap();
                    let (_, body) = read_request(&mut socket).await;
                    assert_eq!(body["id"], format!("observe.{index}"));
                    let terminal = result_event(
                        body["id"].clone(), payload("tools/list", false, if index == 0 { Some("next") } else { None }),
                    );
                    respond_events(&mut socket, &format!("{CATALOG_CHANGE}{terminal}"), "observe-nonce").await;
                }
            };
            let (result, ()) = pair(application, server).await;
            assert_eq!(observed, if case == 0 { 2 } else { 1 });
            match case {
                0 => {
                    let CatalogCollection::Tools(catalog) = result.unwrap() else { panic!("wrong catalog"); };
                    assert_eq!(catalog.page_count(), 2);
                    assert_eq!(catalog.entries().len(), 2);
                }
                1 => assert!(matches!(result, Err(DpopCatalogError::Core(DpopCoreError::Protocol(_))))),
                2 => assert!(matches!(result, Err(DpopCatalogError::Stream(DpopStreamError::ObserverStopped)))),
                3 => assert!(matches!(result, Err(DpopCatalogError::Core(DpopCoreError::Transport(DpopHttpError::Cancelled))))),
                4 => assert!(matches!(result, Err(DpopCatalogError::Core(DpopCoreError::Transport(DpopHttpError::Authorization(_)))))),
                _ => assert!(matches!(result, Err(DpopCatalogError::Stream(DpopStreamError::ObserverPanicked)))),
            }
            assert!(!cx.is_cancel_requested());
            assert!(!client.revocation_handle().is_revoked());
            assert!(listener.poll_accept(&mut Context::from_waker(Waker::noop())).is_pending());
        });
    }
}

#[test]
fn https_streaming_catalog_keeps_the_original_deadline_after_a_complete_page() {
    run(|cx| async move {
        let (listener, mut client, credential) = fixture().await;
        client.policy = client.policy.clone().with_timeout(Duration::from_secs(3)).unwrap();
        let acceptor = acceptor().build().unwrap();
        let cancellation = McpRequestCancellation::new();
        let application = client.collect_catalog_with_events(
            &cx, &cancellation, &credential, request("tools/list"), "stream-deadline",
            DpopStreamLimits::default(), CatalogLimits::default(), |_| true,
        );
        let server = async {
            let (socket, _) = listener.accept().await.unwrap();
            let mut socket = acceptor.accept(socket).await.unwrap();
            let (_, body) = read_request(&mut socket).await;
            assert_eq!(body["id"], "stream-deadline.0");
            asupersync::time::sleep(cx.now(), Duration::from_secs(2)).await;
            let events = result_event(body["id"].clone(), payload("tools/list", false, Some("next")));
            respond_events(&mut socket, &events, "deadline-next").await;
            drop(socket);
            let (socket, _) = listener.accept().await.unwrap();
            let mut socket = acceptor.accept(socket).await.unwrap();
            let (_, body) = read_request(&mut socket).await;
            assert_eq!(body["id"], "stream-deadline.1");
            let started = Instant::now();
            let mut byte = [0];
            assert!(!matches!(socket.read(&mut byte).await, Ok(count) if count > 0));
            started.elapsed()
        };
        let (result, second_page_wait) = pair(application, server).await;
        assert!(matches!(result, Err(DpopCatalogError::Core(DpopCoreError::Transport(DpopHttpError::TimedOut)))));
        assert!(second_page_wait < Duration::from_secs(2));
        assert!(listener.poll_accept(&mut Context::from_waker(Waker::noop())).is_pending());
        assert!(!client.revocation_handle().is_revoked());
    });
}
