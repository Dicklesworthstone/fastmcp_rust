//! Native OAuth login -> capture -> file reopen -> renewal -> existing client.
//! The browser callback and HTTP peers are test fixtures. Token admission,
//! persistence, cancellation and the managed client use production code.
//! The parent fixture's protection/anchor doubles are NOT durable providers.

use super::*;
use std::net::SocketAddr;
use std::sync::atomic::AtomicUsize;
use std::time::Instant;

use asupersync::io::{AsyncReadExt, AsyncWriteExt};
use asupersync::net::{TcpListener, TcpStream};
use asupersync::tls::TlsStream;
use fastmcp_core::CanonicalHttpUrl;
use fastmcp_protocol::{ClientCapabilities, CoreRequest, FinalRequestMeta, RequestId};
use fastmcp_protocol::protocol_policy::ProtocolEra;
use crate::http_auth::oauth::{OAuthClientConfiguration, encode_form};
use crate::http_auth::rpc::{ManagedCoreEvent, ManagedCoreLimits};
use serde_json::{Value, json};

fn url(value: &str) -> CanonicalHttpUrl { CanonicalHttpUrl::parse(value).unwrap() }
fn form(input: &str) -> BTreeMap<String, String> {
    fn decode(input: &str) -> String {
        let mut bytes = input.bytes();
        let mut output = Vec::new();
        while let Some(byte) = bytes.next() {
            match byte {
                b'+' => output.push(b' '),
                b'%' => {
                    let high = char::from(bytes.next().unwrap()).to_digit(16).unwrap();
                    let low = char::from(bytes.next().unwrap()).to_digit(16).unwrap();
                    output.push((16 * high + low) as u8);
                }
                byte => output.push(byte),
            }
        }
        String::from_utf8(output).unwrap()
    }
    input.split('&').map(|field| {
        let (key, value) = field.split_once('=').unwrap();
        (decode(key), decode(value))
    }).collect()
}

async fn browser(authorization: CanonicalHttpUrl) -> Result<(), OAuthError> {
    let fields = form(authorization.query().unwrap());
    assert_eq!(fields["code_challenge_method"], "S256");
    assert_eq!(fields["code_challenge"].len(), 43);
    let callback = &fields["redirect_uri"];
    let address: SocketAddr = callback.strip_prefix("http://").unwrap().split('/').next().unwrap().parse().unwrap();
    assert!(address.ip().is_loopback());
    let query = encode_form(&[("code", "capture-code"), ("iss", "https://issuer.example"), ("state", &fields["state"])])?;
    let mut socket = TcpStream::connect(address).await.map_err(|_| OAuthError::CallbackRejected)?;
    socket.write_all(format!("GET /oauth/callback?{query} HTTP/1.1\r\nHost: {address}\r\n\r\n").as_bytes())
        .await.map_err(|_| OAuthError::CallbackRejected)?;
    // A browser launcher returns after sending the callback; waiting here for
    // its response would deadlock the native driver's launch/receive ordering.
    Ok(())
}

async fn reply(socket: &mut TlsStream<TcpStream>, body: &str) {
    socket.write_all(format!("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nCache-Control: no-store\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len()).as_bytes()).await.unwrap();
    socket.shutdown().await.unwrap();
}
fn quiet(listener: &TcpListener) {
    let mut task = std::task::Context::from_waker(std::task::Waker::noop());
    assert!(listener.poll_accept(&mut task).is_pending(), "no unrequested login, renewal or MCP replay");
}
struct Peer { issuer: TcpListener, resource: TcpListener, client: OAuthClient }
impl Peer {
    async fn new() -> Self {
        let issuer = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let resource = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let configuration = OAuthClientConfiguration::from_trusted_endpoints(
            "https://issuer.example", url("https://issuer.example/authorize"),
            url(&format!("https://{}/token", issuer.local_addr().unwrap())),
            url(&format!("https://{}/mcp", resource.local_addr().unwrap())),
            "native-client", vec!["tools:read".to_owned(), "tools:write".to_owned()],
        ).unwrap().with_extra_root_certificate(native::test_root()).unwrap()
            .with_resource_root_certificate(native::test_root()).unwrap();
        Self { issuer, resource, client: OAuthClient::new(configuration) }
    }
    async fn token(&self, grant_type: &str, body: &str) {
        let (socket, _) = self.issuer.accept().await.unwrap();
        let mut socket = native::test_acceptor().accept(socket).await.unwrap();
        let (head, fields) = native::read_token_request(&mut socket).await.unwrap();
        assert!(head.starts_with("POST /token HTTP/1.1\r\n"));
        assert!(!head.to_ascii_lowercase().contains("authorization:"));
        assert_eq!(fields["grant_type"], grant_type);
        assert_eq!(fields["resource"], self.client.configuration.resource.as_str());
        assert_eq!(fields["client_id"], "native-client");
        if grant_type == "authorization_code" {
            assert_eq!(fields["code"], "capture-code");
            assert!((43..=128).contains(&fields["code_verifier"].len()));
        } else {
            assert_eq!(fields["refresh_token"], "login-refresh");
            assert_eq!(fields["scope"], "tools:read tools:write");
            assert!(!fields.contains_key("code_verifier"));
        }
        reply(&mut socket, body).await;
    }
    async fn login(&self, cx: &Cx, body: &str) -> ManagedOAuthSession {
        let launches = AtomicUsize::new(0);
        let login = ManagedOAuthSession::authorize(cx, self.client.clone(), OAuthSessionPolicy::default(), |authorization| {
            launches.fetch_add(1, Ordering::SeqCst);
            browser(authorization)
        });
        let (_, result) = native::pair(self.token("authorization_code", body), login).await;
        assert_eq!(launches.load(Ordering::SeqCst), 1);
        quiet(&self.issuer);
        result.unwrap()
    }
    async fn mcp(&self, expected: &Value, fixture: &Fixture) {
        let (socket, _) = self.resource.accept().await.unwrap();
        let mut socket = native::test_acceptor().accept(socket).await.unwrap();
        let mut bytes = Vec::new(); let mut chunk = [0; 2048];
        let end = loop {
            let count = socket.read(&mut chunk).await.unwrap();
            assert!(count > 0 && bytes.len() + count <= 64 * 1024);
            bytes.extend_from_slice(&chunk[..count]);
            if let Some(at) = bytes.windows(4).position(|s| s == b"\r\n\r\n") { break at + 4; }
        };
        let head = std::str::from_utf8(&bytes[..end]).unwrap().to_owned();
        let length = head.lines().find_map(|line| {
            let (name, value) = line.split_once(':')?;
            name.eq_ignore_ascii_case("content-length").then(|| value.trim().parse::<usize>().unwrap())
        }).unwrap();
        assert!(end + length <= 64 * 1024);
        while bytes.len() < end + length {
            let count = socket.read(&mut chunk).await.unwrap();
            assert!(count > 0 && bytes.len() + count <= 64 * 1024); bytes.extend_from_slice(&chunk[..count]);
        }
        assert_eq!(bytes.len(), end + length);
        assert!(head.to_ascii_lowercase().contains("authorization: bearer renewed-access\r\n"));
        assert!(!head.to_ascii_lowercase().contains("mcp-session-id:"));
        let wire: Value = serde_json::from_slice(&bytes[end..]).unwrap();
        assert_eq!(wire["method"], "tools/call"); assert_eq!(wire["params"], *expected); assert_eq!(wire["id"], 73);
        {
            let state = fixture.provider.0.lock().unwrap();
            assert_eq!(state.writes, 6, "captured grant, consumed grant and replacement are all settled before dispatch");
            assert!(matches!(state.anchor.state(), CredentialAnchorState::Stable(Some(revision)) if revision.generation() == 3));
        }
        reply(&mut socket, &json!({"jsonrpc":"2.0","id":73,"result":{"resultType":"complete","content":[{"type":"text","text":"capture-journey"}]}}).to_string()).await;
    }
}
const FIRST: &str = r#"{"access_token":"login-access","token_type":"Bearer","expires_in":300,"refresh_token":"login-refresh"}"#;
const NEXT: &str = r#"{"access_token":"renewed-access","token_type":"Bearer","expires_in":300,"refresh_token":"renewed-refresh","scope":"tools:read"}"#;

#[test]
fn native_login_capture_reopen_renew_install_and_mcp_reuse_the_original_session() {
    run(|cx| async move {
        let peer = Peer::new().await; let f = Fixture::new();
        let session = peer.login(&cx, FIRST).await; let sibling = session.clone();
        let snapshot = session.credential(&cx).await.unwrap(); let expiry = snapshot.expires_at();
        let store = f.open(&cx, &peer.client).await;
        let mut capture = f.begin(&cx, &session, store); capture.run(&cx).await.unwrap();
        let (store, revision) = capture.take_store().unwrap();
        assert_eq!(revision.generation(), 1); assert_eq!(f.writes(), 2); assert_eq!(f.seals(), 1);
        assert_eq!(sibling.credential(&cx).await.unwrap().expires_at(), expiry);
        quiet(&peer.issuer); quiet(&peer.resource);
        close(&cx, store).await;
        let store = f.open(&cx, &peer.client).await;
        let mut renewal = store.begin_renewal(&cx, &peer.client, f.auth, &McpRequestCancellation::new(), Duration::from_secs(30)).unwrap();
        // Explicit phase separation lets the test check that persistence was
        // consumed before the ONLY issuer refresh exchange, without races in
        // two independent acceptors inspecting the same listener.
        renewal.advance(&cx).await.unwrap(); renewal.advance(&cx).await.unwrap();
        assert_eq!(f.writes(), 4);
        let (_, renewed) = native::pair(peer.token("refresh_token", NEXT), renewal.run(&cx)).await;
        renewed.unwrap(); quiet(&peer.issuer);
        let (store, receipt) = renewal.install_managed_access(&cx, &session, 1).await.unwrap();
        assert_eq!(receipt.session_generation(), 2); assert_eq!(receipt.stored_revision().generation(), 3);
        assert_eq!(snapshot.generation(), 1); assert_eq!(snapshot.expires_at(), expiry);
        let active = sibling.credential(&cx).await.unwrap();
        assert_eq!(active.generation(), 2); assert_eq!(active.scopes(), ["tools:read".to_owned()]);
        let metadata = serde_json::to_value(FinalRequestMeta::new(ClientCapabilities::default())).unwrap();
        let params = json!({"_meta":metadata,"name":"echo","arguments":{"text":"capture-journey"}});
        let request = CoreRequest::decode(ProtocolEra::Modern2026, "tools/call", Some(&params)).unwrap();
        let application = async {
            let mut call = sibling.request_core(&cx, request, RequestId::Number(73), ManagedCoreLimits::default()).await.unwrap();
            let Some(ManagedCoreEvent::Result(result)) = call.next_event(&cx).await.unwrap() else { panic!("complete native result"); };
            let result: Value = serde_json::from_str(&result.encode().unwrap()).unwrap();
            assert_eq!(result["content"][0]["text"], "capture-journey");
            assert!(call.next_event(&cx).await.unwrap().is_none());
        };
        native::pair(peer.mcp(&params, &f), application).await;
        quiet(&peer.resource); quiet(&peer.issuer);
        session.close(); assert!(active.credential().authorization_for_target(session.resource()).is_none());
        assert!(snapshot.credential().authorization_for_target(session.resource()).is_none());
        close(&cx, store).await;
        let store = f.open(&cx, &peer.client).await;
        let (store, outcome) = store.take_refresh(&cx, f.auth).unwrap().wait(&cx).await.unwrap().into_parts();
        assert_eq!(outcome.unwrap().unwrap().refresh_token, "renewed-refresh");
        close(&cx, store).await;
    });
}

#[test]
fn native_login_without_refresh_refuses_capture_without_relogin_or_file_mutation() {
    run(|cx| async move {
        let peer = Peer::new().await; let f = Fixture::new();
        let session = peer.login(&cx, r#"{"access_token":"login-access","token_type":"Bearer","expires_in":300}"#).await;
        let store = f.open(&cx, &peer.client).await;
        let mut capture = f.begin(&cx, &session, store);
        assert!(matches!(capture.run(&cx).await, Err(OAuthRefreshCaptureError::Transfer(
            OAuthRefreshTransferError::Session(OAuthSessionError::OAuth(OAuthError::RefreshUnavailable))))));
        assert_eq!(f.writes(), 0); assert_eq!(f.seals(), 0); quiet(&peer.issuer);
        assert_eq!(session.credential(&cx).await.unwrap().generation(), 1);
        close(&cx, stopped_store(capture)).await; session.close();
    });
}

#[test]
fn captured_native_session_does_not_refresh_in_memory_at_access_expiry() {
    run(|cx| async move {
        let peer = Peer::new().await; let f = Fixture::new();
        let session = peer.login(&cx, r#"{"access_token":"login-access","token_type":"Bearer","expires_in":2,"refresh_token":"login-refresh"}"#).await;
        let store = f.open(&cx, &peer.client).await;
        let mut capture = f.begin(&cx, &session, store);
        ready_to_store(&mut capture, &cx).await;
        // Observe the original issuer-admitted expiry without calling ordinary
        // acquisition before capture: a slow host could already be inside the
        // early-refresh window, which would legitimately issue another grant.
        let OAuthRefreshCaptureCustody::ReadyToStore { credentials, .. } = &capture.custody else {
            panic!("capture retains the original grant before persistence");
        };
        let expiry = credentials.expires_at();
        capture.run(&cx).await.unwrap();
        asupersync::time::sleep(cx.now(), expiry.saturating_duration_since(Instant::now()) + Duration::from_millis(10)).await;
        assert!(matches!(session.credential(&cx).await, Err(OAuthSessionError::LoginRequired)));
        quiet(&peer.issuer);
        let (store, _) = capture.take_store().unwrap();
        let (store, outcome) = store.take_refresh(&cx, f.auth).unwrap().wait(&cx).await.unwrap().into_parts();
        assert_eq!(outcome.unwrap().unwrap().refresh_token, "login-refresh");
        close(&cx, store).await; session.close();
    });
}

#[test]
fn capture_abandoned_grant_lock_wait_leaves_both_owners_reusable() {
    run(|cx| async move {
        let f = Fixture::new(); let client = client(); let session = session(&cx, &client);
        let store = f.open(&cx, &client).await;
        let mut capture = f.begin(&cx, &session, store); ready_to_transfer(&mut capture, &cx).await;
        let cancel = McpRequestCancellation::new();
        let held = session.reserve_refresh_transfer(&cx, &cancel, 1, &client).await.unwrap();
        let mut waiting = Box::pin(capture.advance(&cx));
        poll_fn(|task| { assert!(waiting.as_mut().poll(task).is_pending()); Poll::Ready(()) }).await;
        drop(waiting); drop(held);
        assert_eq!(capture.stage(), OAuthRefreshCaptureStage::ReadyToTransfer); assert_eq!(f.seals(), 0);
        capture.run(&cx).await.unwrap(); assert_eq!(f.seals(), 1);
        close(&cx, capture.take_store().unwrap().0).await; session.close();
    });
}

#[test]
fn capture_cancelled_grant_lock_wait_cannot_extract_refresh() {
    run(|cx| async move {
        let f = Fixture::new(); let client = client(); let session = session(&cx, &client);
        let store = f.open(&cx, &client).await;
        let cancellation = McpRequestCancellation::new();
        let mut capture = store.begin_capture(&cx, &session, 1, f.auth, None, &cancellation, Duration::from_secs(30)).unwrap();
        ready_to_transfer(&mut capture, &cx).await;
        let cancel = McpRequestCancellation::new();
        let held = session.reserve_refresh_transfer(&cx, &cancel, 1, &client).await.unwrap();
        let mut waiting = Box::pin(capture.advance(&cx));
        poll_fn(|task| { assert!(waiting.as_mut().poll(task).is_pending()); Poll::Ready(()) }).await;
        cancellation.cancel();
        assert!(matches!(waiting.await, Err(OAuthRefreshCaptureError::Context(OAuthError::Cancelled))));
        drop(held); assert_eq!(f.seals(), 0);
        let mut valid = f.begin(&cx, &session, stopped_store(capture)); valid.run(&cx).await.unwrap();
        close(&cx, valid.take_store().unwrap().0).await; session.close();
    });
}

#[test]
fn capture_grant_lock_keeps_the_session_acquisition_deadline() {
    run(|cx| async move {
        let f = Fixture::new(); let client = client();
        let policy = OAuthSessionPolicy::new(Duration::ZERO, Duration::from_millis(20), Duration::from_secs(1), 4).unwrap();
        let session = ManagedOAuthSession::from_credentials(&cx, client.clone(), policy, native::renewable_grant(&client.configuration)).unwrap();
        let store = f.open(&cx, &client).await;
        let mut capture = f.begin(&cx, &session, store); ready_to_transfer(&mut capture, &cx).await;
        let cancel = McpRequestCancellation::new();
        let held = session.reserve_refresh_transfer(&cx, &cancel, 1, &client).await.unwrap();
        assert!(matches!(capture.advance(&cx).await, Err(OAuthRefreshCaptureError::Transfer(
            OAuthRefreshTransferError::Session(OAuthSessionError::TimedOut)))));
        drop(held); assert_eq!(f.seals(), 0);
        capture.run(&cx).await.unwrap(); close(&cx, capture.take_store().unwrap().0).await; session.close();
    });
}

#[test]
fn capture_revoked_generation_cannot_be_migrated_but_expired_access_can() {
    run(|cx| async move {
        for revoked in [false, true] {
            let f = Fixture::new(); let client = client();
            let mut credentials = native::renewable_grant(&client.configuration);
            credentials.expires_at = Instant::now() + Duration::from_millis(50);
            let bearer = credentials.bearer_credential().clone();
            let session = ManagedOAuthSession::from_credentials(&cx, client.clone(), OAuthSessionPolicy::default(), credentials).unwrap();
            let store = f.open(&cx, &client).await;
            if revoked { bearer.revoke(); }
            asupersync::time::sleep(cx.now(), Duration::from_millis(60)).await;
            let mut capture = f.begin(&cx, &session, store);
            if revoked {
                assert!(matches!(capture.run(&cx).await, Err(OAuthRefreshCaptureError::Transfer(
                    OAuthRefreshTransferError::Session(OAuthSessionError::LoginRequired)))));
                assert_eq!(f.seals(), 0); close(&cx, stopped_store(capture)).await;
            } else {
                capture.run(&cx).await.unwrap(); assert_eq!(f.seals(), 1);
                close(&cx, capture.take_store().unwrap().0).await;
            }
            session.close();
        }
    });
}
