//! AUTH-03 public API tests: real TLS metadata GETs, registration and token
//! POSTs, with an in-process browser-callback simulator. No external IdP/browser
//! is exercised. All registration writes are confined to the local TLS fixture.

use std::collections::BTreeMap;
use std::future::{Future, poll_fn};
use std::net::SocketAddr;
use std::sync::Mutex;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::task::Poll;
use std::time::Duration;

use asupersync::Cx;
use asupersync::channel::oneshot;
use asupersync::io::{AsyncReadExt, AsyncWriteExt};
use asupersync::net::{TcpListener, TcpStream};
use asupersync::runtime::{RuntimeBuilder, reactor::create_reactor};
use asupersync::tls::{Certificate, CertificateChain, PrivateKey, TlsAcceptor, TlsAcceptorBuilder, TlsStream};
use fastmcp_client::http_auth::BoundBearerCredential;
use fastmcp_client::http_auth::discovery::{OAuthDiscoveryError, OAuthDiscoveryPlan, TrustedOAuthIssuer};
use fastmcp_client::http_auth::discovery::registration::{
    NativeClientRegistration, OAuthRegistrationError, NATIVE_REGISTRATION_REDIRECT_URIS,
};
use fastmcp_client::http_auth::managed::OAuthSessionPolicy;
use fastmcp_client::http_auth::oauth::OAuthError;
use fastmcp_core::CanonicalHttpUrl;
use serde_json::{Value, json};

// Public TEST ONLY fixture material. These keys must never be deployment keys.
const ROOT: &[u8] = b"-----BEGIN CERTIFICATE-----\nMIIBgzCCASmgAwIBAgICA+kwCgYIKoZIzj0EAwIwJzElMCMGA1UEAwwcRmFzdE1D\nUCBPQXV0aCBURVNUIE9OTFkgUm9vdDAeFw0yMDAxMDEwMDAwMDBaFw00OTEyMzEw\nMDAwMDBaMCcxJTAjBgNVBAMMHEZhc3RNQ1AgT0F1dGggVEVTVCBPTkxZIFJvb3Qw\nWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAAS5t2O8JZ0hNjgI38E9Ov6i6mKoDRGo\nApMsykFkvgb6Zm9/5gCZ90eIKw7aWgK6iNs7lbtVY9mysZBIqm6pKQO2o0UwQzAS\nBgNVHRMBAf8ECDAGAQH/AgEAMA4GA1UdDwEB/wQEAwIBhjAdBgNVHQ4EFgQU6QNI\nrmvMiLoV3jIoCyohXARwI8gwCgYIKoZIzj0EAwIDSAAwRQIgCKOrW3vhzUJ2EyuY\nvQUTdqGFhy0zEHj4ITFLvXPz1X8CIQCLKD4EKCvS/zkBSu/6uee1WV9d97UpK3yW\nX/aCEJ5+hA==\n-----END CERTIFICATE-----\n";
const LEAF: &[u8] = b"-----BEGIN CERTIFICATE-----\nMIIBjjCCATSgAwIBAgICA+owCgYIKoZIzj0EAwIwJzElMCMGA1UEAwwcRmFzdE1D\nUCBPQXV0aCBURVNUIE9OTFkgUm9vdDAeFw0yMDAxMDEwMDAwMDBaFw00OTEyMzEw\nMDAwMDBaMBQxEjAQBgNVBAMMCWxvY2FsaG9zdDBZMBMGByqGSM49AgEGCCqGSM49\nAwEHA0IABPPKylLna9VpWAlpshHBhSsQHNOv3BaEGX4HSBhHiBVel0ce+qfHF15O\n0T63Zlp7TtxlMdEY+rPpgioSFDQVadijYzBhMAwGA1UdEwEB/wQCMAAwLAYDVR0R\nBCUwI4IJbG9jYWxob3N0hwR/AAABhxAAAAAAAAAAAAAAAAAAAAABMBMGA1UdJQQM\nMAoGCCsGAQUFBwMBMA4GA1UdDwEB/wQEAwIHgDAKBggqhkjOPQQDAgNIADBFAiEA\n6qrAr2qp/t6K62T9Et2mUU/zfd4kJb+ekyoAim1yTFcCICb6SdVY2fg15/SXf0vE\nIvYelqtTk8FQInCEcIxvfF3m\n-----END CERTIFICATE-----\n";
const KEY: &[u8] = b"-----BEGIN PRIVATE KEY-----\nMIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgcCe44IBKhbw+D/s7\nBjDHOOV0g+EoxFno7VJGKhJeer2hRANCAATzyspS52vVaVgJabIRwYUrEBzTr9wW\nhBl+B0gYR4gVXpdHHvqnxxdeTtE+t2Zae07cZTHRGPqz6YIqEhQ0FWnY\n-----END PRIVATE KEY-----\n";

fn root() -> Certificate { Certificate::from_pem(ROOT).unwrap().remove(0) }
fn url(value: &str) -> CanonicalHttpUrl { CanonicalHttpUrl::parse(value).unwrap() }

fn run(future: impl Future<Output = ()>) {
    RuntimeBuilder::current_thread().with_reactor(create_reactor().unwrap())
        .build().unwrap().block_on(async {
            let cx = Cx::current().unwrap();
            asupersync::time::timeout_at(cx.now().saturating_add_nanos(20_000_000_000), future)
                .await.expect("complete discovery fixture must settle within its bound");
        });
}

async fn pair<L: Future, R: Future>(left: L, right: R) -> (L::Output, R::Output) {
    let mut left = std::pin::pin!(left);
    let mut right = std::pin::pin!(right);
    let mut left_result = None;
    let mut right_result = None;
    poll_fn(|task| {
        if left_result.is_none() {
            if let Poll::Ready(value) = left.as_mut().poll(task) { left_result = Some(value); }
        }
        if right_result.is_none() {
            if let Poll::Ready(value) = right.as_mut().poll(task) { right_result = Some(value); }
        }
        if left_result.is_some() && right_result.is_some() {
            Poll::Ready((left_result.take().unwrap(), right_result.take().unwrap()))
        } else { Poll::Pending }
    }).await
}

struct Peer {
    listener: TcpListener,
    acceptor: TlsAcceptor,
    paths: Mutex<Vec<String>>,
}

impl Peer {
    async fn new() -> Self {
        Self {
            listener: TcpListener::bind("127.0.0.1:0").await.unwrap(),
            acceptor: TlsAcceptorBuilder::new(
                CertificateChain::from_pem(LEAF).unwrap(), PrivateKey::from_pem(KEY).unwrap(),
            ).alpn_protocols(vec![b"http/1.1".to_vec()]).build().unwrap(),
            paths: Mutex::new(Vec::new()),
        }
    }

    fn origin(&self) -> String { format!("https://{}", self.listener.local_addr().unwrap()) }
    fn issuer(&self) -> String { format!("{}/tenant", self.origin()) }
    fn resource(&self) -> String { format!("{}/mcp", self.origin()) }

    fn plan(&self, trust_resource: bool, trust_issuer: bool) -> OAuthDiscoveryPlan {
        let issuer = TrustedOAuthIssuer::new(self.issuer()).unwrap();
        let issuer = if trust_issuer { issuer.with_root_certificate(root()).unwrap() } else { issuer };
        let plan = OAuthDiscoveryPlan::new(url(&self.resource()), vec![issuer],
            "registered-native-client", vec!["tools:read".to_owned()]).unwrap();
        if trust_resource { plan.with_resource_root_certificate(root()).unwrap() } else { plan }
    }

    fn registration(&self) -> NativeClientRegistration {
        NativeClientRegistration::new(
            url(&self.resource()),
            vec![TrustedOAuthIssuer::new(self.issuer()).unwrap().with_root_certificate(root()).unwrap()],
            "Dynamic native integration", vec!["tools:read".to_owned()],
        ).unwrap().with_resource_root_certificate(root()).unwrap()
    }

    fn resource_document(&self) -> Value {
        json!({
            "resource": self.resource(),
            "authorization_servers": ["https://never-fetch-untrusted.invalid/issuer", self.issuer()],
            "scopes_supported": ["tools:read"],
            "bearer_methods_supported": ["header"]
        })
    }

    fn issuer_document(&self) -> Value {
        json!({
            "issuer": self.issuer(),
            "authorization_endpoint": format!("{}/authorize", self.origin()),
            "token_endpoint": format!("{}/token", self.origin()),
            "response_types_supported": ["code"],
            "grant_types_supported": ["authorization_code", "refresh_token"],
            "token_endpoint_auth_methods_supported": ["none"],
            "code_challenge_methods_supported": ["S256"],
            "authorization_response_iss_parameter_supported": true,
            "scopes_supported": ["tools:read"],
            "protected_resources": [self.resource()]
        })
    }

    fn registration_document(&self, endpoint: &str) -> Value {
        let mut metadata = self.issuer_document();
        metadata["registration_endpoint"] = json!(endpoint);
        metadata
    }

    async fn registration_discovery(&self, document: &Value) {
        self.serve("/.well-known/oauth-protected-resource/mcp", 200, &self.resource_document().to_string()).await;
        self.serve("/.well-known/oauth-authorization-server/tenant", 200, &document.to_string()).await;
    }

    async fn request(&self, method: &str, path: &str) -> (TlsStream<TcpStream>, Vec<u8>) {
        self.request_with_authorization(method, path, None).await
    }

    async fn request_with_authorization(
        &self, method: &str, path: &str, expected: Option<&str>,
    ) -> (TlsStream<TcpStream>, Vec<u8>) {
        let (socket, _) = self.listener.accept().await.unwrap();
        let mut tls = self.acceptor.accept(socket).await.unwrap();
        let mut wire = Vec::new();
        let mut chunk = [0; 2048];
        let end = loop {
            let count = tls.read(&mut chunk).await.unwrap();
            assert!(count > 0 && wire.len() + count <= 16 * 1024);
            wire.extend_from_slice(&chunk[..count]);
            if let Some(index) = wire.windows(4).position(|value| value == b"\r\n\r\n") { break index + 4; }
        };
        let head = std::str::from_utf8(&wire[..end]).unwrap();
        assert!(head.starts_with(&format!("{method} {path} HTTP/1.1\r\n")));
        let authorization: Vec<&str> = head.lines().filter_map(|line| {
            let (name, value) = line.split_once(':')?;
            name.eq_ignore_ascii_case("authorization").then(|| value.trim())
        }).collect();
        match expected {
            None => assert!(authorization.is_empty()),
            Some(expected) => assert_eq!(authorization, vec![expected]),
        }
        assert!(!head.to_ascii_lowercase().contains("cookie:"));
        let length = head.lines().find_map(|line| {
            let (name, value) = line.split_once(':')?;
            name.eq_ignore_ascii_case("content-length").then(|| value.trim().parse::<usize>().unwrap())
        }).unwrap_or(0);
        assert!(end + length <= 16 * 1024);
        while wire.len() < end + length {
            let count = tls.read(&mut chunk).await.unwrap();
            assert!(count > 0 && wire.len() + count <= 16 * 1024);
            wire.extend_from_slice(&chunk[..count]);
        }
        assert_eq!(wire.len(), end + length);
        if method == "GET" { assert_eq!(length, 0); }
        self.paths.lock().unwrap().push(path.to_owned());
        (tls, wire[end..].to_vec())
    }

    async fn serve(&self, path: &str, status: u16, body: &str) {
        let (mut tls, _) = self.request("GET", path).await;
        reply(&mut tls, status, body).await;
    }

    fn assert_no_extra_connections(&self) {
        let mut task = std::task::Context::from_waker(std::task::Waker::noop());
        assert!(self.listener.poll_accept(&mut task).is_pending(), "discovery must not replay or widen its fetch plan");
    }
}

async fn reply(tls: &mut TlsStream<TcpStream>, status: u16, body: &str) {
    let response = format!(
        "HTTP/1.1 {status} Fixture\r\nContent-Type: application/json\r\nContent-Length: {}\r\nLocation: https://127.0.0.1:9/must-not-follow\r\nConnection: close\r\n\r\n{body}", body.len(),
    );
    tls.write_all(response.as_bytes()).await.unwrap();
    tls.shutdown().await.unwrap();
}

fn decode_component(input: &str) -> String {
    let mut output = Vec::new();
    let mut bytes = input.bytes();
    while let Some(byte) = bytes.next() {
        match byte {
            b'+' => output.push(b' '),
            b'%' => {
                let high = char::from(bytes.next().unwrap()).to_digit(16).unwrap();
                let low = char::from(bytes.next().unwrap()).to_digit(16).unwrap();
                output.push((high * 16 + low) as u8);
            }
            byte => output.push(byte),
        }
    }
    String::from_utf8(output).unwrap()
}

fn form(input: &str) -> BTreeMap<String, String> {
    input.split('&').map(|field| {
        let (name, value) = field.split_once('=').unwrap();
        (decode_component(name), decode_component(value))
    }).collect()
}

fn encode_component(input: &str) -> String {
    let mut output = String::new();
    for byte in input.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~') {
            output.push(char::from(byte));
        } else {
            use std::fmt::Write;
            write!(&mut output, "%{byte:02X}").unwrap();
        }
    }
    output
}

async fn callback(authorization: CanonicalHttpUrl, issuer: &str, resource: &str) -> Result<(), OAuthError> {
    callback_for_client(authorization, issuer, resource, "registered-native-client").await
}

async fn callback_for_client(
    authorization: CanonicalHttpUrl, issuer: &str, resource: &str, client_id: &str,
) -> Result<(), OAuthError> {
    let fields = form(authorization.query().unwrap());
    assert_eq!(fields["client_id"], client_id);
    assert_eq!(fields["resource"], resource);
    assert_eq!(fields["code_challenge_method"], "S256");
    let address: SocketAddr = fields["redirect_uri"].strip_prefix("http://").unwrap()
        .split('/').next().unwrap().parse().unwrap();
    assert!(address.ip().is_loopback());
    let query = format!("code=fixture-code&iss={}&state={}", encode_component(issuer), fields["state"]);
    let request = format!("GET /oauth/callback?{query} HTTP/1.1\r\nHost: {address}\r\n\r\n");
    let mut socket = TcpStream::connect(address).await.map_err(|_| OAuthError::CallbackRejected)?;
    socket.write_all(request.as_bytes()).await.map_err(|_| OAuthError::CallbackRejected)
}

#[test]
fn public_discovery_fallbacks_feed_the_actual_managed_pkce_login() {
    run(async {
        let cx = Cx::current().unwrap();
        let peer = Peer::new().await;
        let plan = peer.plan(true, true);
        let issuer = peer.issuer();
        let resource = peer.resource();
        let launches = AtomicUsize::new(0);
        let server = async {
            peer.serve("/.well-known/oauth-protected-resource/mcp", 200, &peer.resource_document().to_string()).await;
            peer.serve("/.well-known/oauth-authorization-server/tenant", 404, "").await;
            peer.serve("/.well-known/openid-configuration/tenant", 410, "").await;
            peer.serve("/tenant/.well-known/openid-configuration", 200, &peer.issuer_document().to_string()).await;
            let (mut tls, body) = peer.request("POST", "/token").await;
            let fields = form(std::str::from_utf8(&body).unwrap());
            assert_eq!(fields["grant_type"], "authorization_code");
            assert_eq!(fields["client_id"], "registered-native-client");
            assert_eq!(fields["resource"], resource);
            assert_eq!(fields["code"], "fixture-code");
            assert_eq!(fields["code_verifier"].len(), 64);
            reply(&mut tls, 200,
                r#"{"access_token":"discovered-access","token_type":"Bearer","expires_in":300,"refresh_token":"discovered-refresh","scope":"tools:read"}"#,
            ).await;
        };
        let application = async {
            let session = plan.authorize_managed(&cx, OAuthSessionPolicy::default(), |authorization| {
                launches.fetch_add(1, Ordering::SeqCst);
                callback(authorization, &issuer, &resource)
            }).await.unwrap();
            let snapshot = session.credential(&cx).await.unwrap();
            assert_eq!(snapshot.generation(), 1);
            assert_eq!(snapshot.credential().authorization_for_target(&url(&resource)), Some("Bearer discovered-access".to_owned()));
            session.close();
        };
        pair(server, application).await;
        assert_eq!(launches.load(Ordering::SeqCst), 1);
        assert_eq!(peer.paths.lock().unwrap().len(), 5);
        peer.assert_no_extra_connections();
    });
}

#[test]
fn issuer_http_failures_do_not_fallback_or_launch_the_browser() {
    for status in [302, 307, 401, 403, 500] {
        run(async {
            let cx = Cx::current().unwrap();
            let peer = Peer::new().await;
            let plan = peer.plan(true, true);
            let launches = AtomicUsize::new(0);
            let server = async {
                peer.serve("/.well-known/oauth-protected-resource/mcp", 200, &peer.resource_document().to_string()).await;
                peer.serve("/.well-known/oauth-authorization-server/tenant", status, "peer-error-canary").await;
            };
            let application = plan.authorize_managed(&cx, OAuthSessionPolicy::default(), |_| {
                launches.fetch_add(1, Ordering::SeqCst);
                async { Ok(()) }
            });
            let ((), result) = pair(server, application).await;
            let error = result.err().unwrap();
            assert!(matches!(error, OAuthDiscoveryError::HttpStatus { status: actual } if actual == status));
            assert!(!format!("{error:?} {error}").contains("peer-error-canary"));
            assert_eq!(launches.load(Ordering::SeqCst), 0);
            assert_eq!(peer.paths.lock().unwrap().len(), 2);
            peer.assert_no_extra_connections();
        });
    }
}

#[test]
fn invalid_issuer_metadata_has_no_browser_or_token_endpoint_effects() {
    for dimension in 0..7 {
        run(async {
            let cx = Cx::current().unwrap();
            let peer = Peer::new().await;
            let plan = peer.plan(true, true);
            let mut document = peer.issuer_document();
            match dimension {
                0 => document["issuer"] = json!("https://wrong-issuer.invalid"),
                1 => document["token_endpoint"] = json!("https://untrusted-token.invalid/token"),
                2 => document["code_challenge_methods_supported"] = json!(["plain"]),
                3 => document["authorization_response_iss_parameter_supported"] = Value::Null,
                4 => document["scopes_supported"] = json!(["admin"]),
                5 => document["signed_metadata"] = json!("unverified.jwt.value"),
                _ => {},
            }
            let mut body = document.to_string();
            if dimension == 6 {
                body.pop();
                body.push_str(",\"iss\\u0075er\":\"https://duplicate.invalid\"}");
            }
            let launches = AtomicUsize::new(0);
            let server = async {
                peer.serve("/.well-known/oauth-protected-resource/mcp", 200, &peer.resource_document().to_string()).await;
                peer.serve("/.well-known/oauth-authorization-server/tenant", 200, &body).await;
            };
            let application = plan.authorize_managed(&cx, OAuthSessionPolicy::default(), |_| {
                launches.fetch_add(1, Ordering::SeqCst);
                async { Ok(()) }
            });
            let ((), result) = pair(server, application).await;
            assert!(result.is_err());
            assert_eq!(launches.load(Ordering::SeqCst), 0);
            assert_eq!(peer.paths.lock().unwrap().len(), 2);
            peer.assert_no_extra_connections();
        });
    }
}

#[test]
fn invalid_resource_identity_or_untrusted_issuer_stops_before_issuer_contact() {
    for trusted in [false, true] {
        run(async {
            let cx = Cx::current().unwrap();
            let peer = Peer::new().await;
            let plan = peer.plan(true, true);
            let mut document = peer.resource_document();
            if trusted {
                document["resource"] = json!(format!("{}/different", peer.origin()));
            } else {
                document["authorization_servers"] = json!(["https://127.0.0.1:9/forbidden"]);
            }
            let application = plan.discover(&cx);
            let ((), result) = pair(peer.serve("/.well-known/oauth-protected-resource/mcp", 200, &document.to_string()), application).await;
            if trusted {
                assert!(matches!(result, Err(OAuthDiscoveryError::ResourceMismatch)));
            } else {
                assert!(matches!(result, Err(OAuthDiscoveryError::NoTrustedIssuer)));
            }
            assert_eq!(peer.paths.lock().unwrap().len(), 1);
            peer.assert_no_extra_connections();
        });
    }
}

#[test]
fn each_discovery_leg_requires_its_own_tls_trust_before_sending_a_get() {
    for trust_resource in [false, true] {
        run(async {
            let cx = Cx::current().unwrap();
            let peer = Peer::new().await;
            let plan = peer.plan(trust_resource, false);
            let server = async {
                if trust_resource {
                    peer.serve("/.well-known/oauth-protected-resource/mcp", 200, &peer.resource_document().to_string()).await;
                }
                let (socket, _) = peer.listener.accept().await.unwrap();
                assert!(peer.acceptor.accept(socket).await.is_err(), "untrusted certificate cannot become an HTTP stream");
            };
            let ((), result) = pair(server, plan.discover(&cx)).await;
            assert!(matches!(result, Err(OAuthDiscoveryError::TransportFailed)));
            assert_eq!(peer.paths.lock().unwrap().len(), usize::from(trust_resource));
            peer.assert_no_extra_connections();
        });
    }
}

#[test]
fn dropping_an_active_discovery_releases_its_socket_without_cancelling_the_parent() {
    run(async {
        let cx = Cx::current().unwrap();
        let peer = Peer::new().await;
        let plan = peer.plan(true, true);
        let (started_tx, mut started_rx) = oneshot::channel::<()>();
        let server = async {
            peer.serve("/.well-known/oauth-protected-resource/mcp", 200, &peer.resource_document().to_string()).await;
            let (mut socket, _) = peer.request("GET", "/.well-known/oauth-authorization-server/tenant").await;
            started_tx.send(()).unwrap();
            let mut byte = [0];
            assert!(!matches!(socket.read(&mut byte).await, Ok(count) if count > 0));
        };
        let application = async {
            let mut discovery = Box::pin(plan.discover(&cx));
            let mut started = std::pin::pin!(started_rx.recv(&cx));
            poll_fn(|task| {
                assert!(discovery.as_mut().poll(task).is_pending());
                started.as_mut().poll(task)
            }).await.unwrap();
            drop(discovery);
            assert!(cx.checkpoint().is_ok());
        };
        pair(server, application).await;
        assert_eq!(peer.paths.lock().unwrap().len(), 2);
        peer.assert_no_extra_connections();
    });
}

#[test]
fn metadata_location_exhaustion_is_bounded_and_precancellation_has_no_contact() {
    run(async {
        let cx = Cx::current().unwrap();
        let peer = Peer::new().await;
        let plan = peer.plan(true, true);
        let server = async {
            peer.serve("/.well-known/oauth-protected-resource/mcp", 200, &peer.resource_document().to_string()).await;
            for path in ["/.well-known/oauth-authorization-server/tenant", "/.well-known/openid-configuration/tenant", "/tenant/.well-known/openid-configuration"] {
                peer.serve(path, 404, "").await;
            }
        };
        let ((), result) = pair(server, plan.discover(&cx)).await;
        assert!(matches!(result, Err(OAuthDiscoveryError::MetadataNotFound)));
        assert_eq!(peer.paths.lock().unwrap().len(), 4);
        let cancelled = Cx::detached_cancel_context();
        cancelled.cancel_with(asupersync::CancelKind::User, Some("test cancellation"));
        assert!(matches!(plan.discover(&cancelled).await, Err(OAuthDiscoveryError::Cancelled)));
        peer.assert_no_extra_connections();
    });
}

fn registration_reply(request: &[u8], client_id: &str) -> Value {
    let mut body: Value = serde_json::from_slice(request).unwrap();
    assert!(body.get("client_id").is_none(), "registration must not invent an identity");
    assert!(body.get("client_secret").is_none());
    assert_eq!(body["application_type"], "native");
    assert_eq!(body["token_endpoint_auth_method"], "none");
    assert_eq!(body["response_types"], json!(["code"]));
    assert_eq!(body["redirect_uris"], json!(NATIVE_REGISTRATION_REDIRECT_URIS));
    assert_eq!(body["scope"], "tools:read");
    body["client_id"] = json!(client_id);
    // These unrequested extension values remain inert, never fetched or
    // carried into the returned client's configuration or diagnostics.
    body["registration_client_uri"] = json!("https://127.0.0.1:9/no-management-contact");
    body["registration_access_token"] = json!("management-token-canary");
    body
}

#[test]
fn native_registration_login_and_refresh_reuse_one_admitted_client_id() {
    for protected in [false, true] {
        run(async {
            let cx = Cx::current().unwrap();
            let peer = Peer::new().await;
            let endpoint = format!("{}/register", peer.origin());
            let issuer = peer.issuer();
            let resource = peer.resource();
            let assigned_id = format!("dynamic-client-{}", peer.listener.local_addr().unwrap().port());
            let document = peer.registration_document(&endpoint);
            let owner = peer.registration();
            let owner = if protected {
                owner.with_initial_access_token(BoundBearerCredential::bind(url(&endpoint), "initial-registration-canary").unwrap()).unwrap()
            } else { owner };
            let observed_redirect = Mutex::new(None::<String>);
            let server = async {
                peer.registration_discovery(&document).await;
                let expected = protected.then_some("Bearer initial-registration-canary");
                let (mut socket, request) = peer.request_with_authorization("POST", "/register", expected).await;
                let registered = registration_reply(&request, &assigned_id);
                assert_eq!(registered["grant_types"], json!(["authorization_code", "refresh_token"]));
                reply(&mut socket, 201, &registered.to_string()).await;
                let (mut socket, request) = peer.request("POST", "/token").await;
                let request = form(std::str::from_utf8(&request).unwrap());
                assert_eq!(request["client_id"], assigned_id);
                assert_eq!(request["resource"], resource);
                assert_eq!(request["grant_type"], "authorization_code");
                assert_eq!(request["code"], "fixture-code");
                assert_eq!(Some(&request["redirect_uri"]), observed_redirect.lock().unwrap().as_ref());
                assert_eq!(request["code_verifier"].len(), 64);
                reply(&mut socket, 200, r#"{"access_token":"registration-access-one","token_type":"Bearer","expires_in":1,"refresh_token":"registration-refresh-one","scope":"tools:read"}"#).await;
                let (mut socket, request) = peer.request("POST", "/token").await;
                let request = form(std::str::from_utf8(&request).unwrap());
                assert_eq!(request["client_id"], assigned_id);
                assert_eq!(request["resource"], resource);
                assert_eq!(request["grant_type"], "refresh_token");
                assert_eq!(request["refresh_token"], "registration-refresh-one");
                reply(&mut socket, 200, r#"{"access_token":"registration-access-two","token_type":"Bearer","expires_in":300,"refresh_token":"registration-refresh-two","scope":"tools:read"}"#).await;
            };
            let application = async {
                let registered = owner.register(&cx).await.unwrap();
                assert_eq!(registered.client_id(), assigned_id);
                let diagnostics = format!("{registered:?} {:?}", registered.configuration());
                assert!(!diagnostics.contains("initial-registration-canary"));
                assert!(!diagnostics.contains("management-token-canary"));
                // A browser launch failure does not discard the registration or
                // cause another registration POST on the next explicit login.
                assert!(registered.authorize_managed(&cx, OAuthSessionPolicy::default(), |_| async {
                    Err(OAuthError::BrowserLaunchFailed)
                }).await.is_err());
                let session = registered.authorize_managed(&cx, OAuthSessionPolicy::default(), |authorization| {
                    let fields = form(authorization.query().unwrap());
                    let redirect = url(&fields["redirect_uri"]);
                    assert_eq!(redirect.path(), "/oauth/callback");
                    assert!(redirect.as_str().starts_with("http://127.0.0.1:") || redirect.as_str().starts_with("http://[::1]:"));
                    *observed_redirect.lock().unwrap() = Some(fields["redirect_uri"].clone());
                    callback_for_client(authorization, &issuer, &resource, &assigned_id)
                }).await.unwrap();
                asupersync::time::Sleep::with_timer_driver(
                    cx.now().saturating_add_nanos(1_100_000_000), cx.timer_driver().unwrap(),
                ).await;
                let snapshot = session.credential(&cx).await.unwrap();
                assert_eq!(snapshot.generation(), 2);
                assert_eq!(snapshot.credential().authorization_for_target(&url(&resource)), Some("Bearer registration-access-two".to_owned()));
                session.close();
            };
            pair(server, application).await;
            assert_eq!(*peer.paths.lock().unwrap(), vec![
                "/.well-known/oauth-protected-resource/mcp", "/.well-known/oauth-authorization-server/tenant",
                "/register", "/token", "/token",
            ]);
            peer.assert_no_extra_connections();
        });
    }
}

#[test]
fn cross_origin_registration_requires_its_own_write_grant_over_tls() {
    for permitted in [false, true] {
        run(async {
            let cx = Cx::current().unwrap();
            let issuer = Peer::new().await;
            let registrar = Peer::new().await;
            let document = issuer.registration_document(&format!("{}/register", registrar.origin()));
            let trusted = TrustedOAuthIssuer::new(issuer.issuer()).unwrap()
                .with_root_certificate(root()).unwrap()
                .with_endpoint_origin(url(&format!("{}/", registrar.origin()))).unwrap();
            let owner = NativeClientRegistration::new(url(&issuer.resource()), vec![trusted],
                "Separate registration", vec!["tools:read".to_owned()]).unwrap()
                .with_resource_root_certificate(root()).unwrap();
            let owner = if permitted {
                owner.with_registration_origin(url(&format!("{}/", registrar.origin()))).unwrap()
            } else { owner };
            let server = async {
                issuer.registration_discovery(&document).await;
                if permitted {
                    let (mut socket, request) = registrar.request("POST", "/register").await;
                    reply(&mut socket, 201, &registration_reply(&request, "separate-client").to_string()).await;
                }
            };
            let ((), result) = pair(server, owner.register(&cx)).await;
            if permitted { assert_eq!(result.unwrap().client_id(), "separate-client"); }
            else { assert!(matches!(result, Err(OAuthRegistrationError::EndpointNotTrusted))); }
            assert_eq!(issuer.paths.lock().unwrap().len(), 2);
            assert_eq!(registrar.paths.lock().unwrap().len(), usize::from(permitted));
            issuer.assert_no_extra_connections();
            registrar.assert_no_extra_connections();
        });
    }
}

#[test]
fn changed_registration_metadata_never_reaches_the_browser() {
    for dimension in 0..9 {
        run(async {
            let cx = Cx::current().unwrap();
            let peer = Peer::new().await;
            let document = peer.registration_document(&format!("{}/register", peer.origin()));
            let owner = peer.registration();
            let launches = AtomicUsize::new(0);
            let server = async {
                peer.registration_discovery(&document).await;
                let (mut socket, request) = peer.request("POST", "/register").await;
                let mut body = registration_reply(&request, "not-admitted-client");
                match dimension {
                    0 => body["redirect_uris"] = json!(["https://attacker.invalid/redirect"]),
                    1 => body["token_endpoint_auth_method"] = json!("client_secret_basic"),
                    2 => body["client_secret"] = json!("peer-secret-canary"),
                    3 => body["scope"] = json!("admin"),
                    4 => body["grant_types"] = json!(["authorization_code", "client_credentials"]),
                    5 => body["application_type"] = json!("web"),
                    6 => body["client_id"] = Value::Null,
                    7 => body = json!([body]),
                    _ => {},
                }
                let mut wire = body.to_string();
                if dimension == 8 {
                    wire.pop();
                    wire.push_str(",\"client_\\u0069d\":\"duplicate\"}");
                }
                reply(&mut socket, 201, &wire).await;
            };
            let application = async {
                let result = owner.register(&cx).await;
                if let Ok(registered) = &result {
                    let _ = registered.authorize_managed(&cx, OAuthSessionPolicy::default(), |_| {
                        launches.fetch_add(1, Ordering::SeqCst);
                        async { Err(OAuthError::BrowserLaunchFailed) }
                    }).await;
                }
                result
            };
            let ((), result) = pair(server, application).await;
            let error = result.err().unwrap();
            assert!(matches!(error, OAuthRegistrationError::ResponseRejected));
            assert!(!format!("{error:?} {error}").contains("peer-secret-canary"));
            assert_eq!(launches.load(Ordering::SeqCst), 0);
            assert_eq!(peer.paths.lock().unwrap().len(), 3);
            peer.assert_no_extra_connections();
        });
    }
}

#[test]
fn registration_checks_the_complete_code_flow_before_creating_remote_state() {
    for dimension in 0..4 {
        run(async {
            let cx = Cx::current().unwrap();
            let peer = Peer::new().await;
            let mut document = peer.registration_document(&format!("{}/register", peer.origin()));
            match dimension {
                0 => document["code_challenge_methods_supported"] = json!(["plain"]),
                1 => document["issuer"] = json!("https://other.invalid/tenant"),
                2 => document["token_endpoint"] = json!("https://untrusted.invalid/token"),
                _ => { document.as_object_mut().unwrap().remove("registration_endpoint"); },
            }
            let ((), result) = pair(peer.registration_discovery(&document), peer.registration().register(&cx)).await;
            assert!(result.is_err());
            assert_eq!(peer.paths.lock().unwrap().len(), 2);
            peer.assert_no_extra_connections();
        });
    }
}

#[test]
fn registration_status_redirect_and_lost_response_never_retry_the_post() {
    for status in [Some(200), Some(302), Some(307), Some(401), Some(500), None] {
        run(async {
            let cx = Cx::current().unwrap();
            let peer = Peer::new().await;
            let document = peer.registration_document(&format!("{}/register", peer.origin()));
            let server = async {
                peer.registration_discovery(&document).await;
                let (mut socket, request) = peer.request("POST", "/register").await;
                if let Some(status) = status {
                    reply(&mut socket, status, &registration_reply(&request, "candidate").to_string()).await;
                }
                // In the lost-response case, the registration might already
                // exist remotely. Dropping the socket must not provoke a retry.
            };
            let ((), result) = pair(server, peer.registration().register(&cx)).await;
            match status {
                Some(status) => assert!(matches!(result, Err(OAuthRegistrationError::HttpStatus { status: actual }) if actual == status)),
                None => assert!(matches!(result, Err(OAuthRegistrationError::Discovery(OAuthDiscoveryError::TransportFailed)))),
            }
            assert_eq!(peer.paths.lock().unwrap().len(), 3);
            peer.assert_no_extra_connections();
        });
    }
}

#[test]
fn initial_registration_credential_cannot_be_sent_to_a_different_endpoint() {
    run(async {
        let cx = Cx::current().unwrap();
        let peer = Peer::new().await;
        let document = peer.registration_document(&format!("{}/register", peer.origin()));
        let owner = peer.registration().with_initial_access_token(
            BoundBearerCredential::bind(url(&format!("{}/other-registration", peer.origin())), "initial-registration-canary").unwrap(),
        ).unwrap();
        let ((), result) = pair(peer.registration_discovery(&document), owner.register(&cx)).await;
        assert!(matches!(result, Err(OAuthRegistrationError::InitialCredentialRejected)));
        assert_eq!(peer.paths.lock().unwrap().len(), 2);
        peer.assert_no_extra_connections();
    });
}

#[test]
fn dropping_a_registration_after_post_closes_the_owned_exchange_without_replay() {
    run(async {
        let cx = Cx::current().unwrap();
        let peer = Peer::new().await;
        let document = peer.registration_document(&format!("{}/register", peer.origin()));
        let (started_tx, mut started_rx) = oneshot::channel::<()>();
        let server = async {
            peer.registration_discovery(&document).await;
            let (mut socket, _) = peer.request("POST", "/register").await;
            started_tx.send(()).unwrap();
            let mut byte = [0];
            assert!(!matches!(socket.read(&mut byte).await, Ok(count) if count > 0));
        };
        let application = async {
            let mut attempt = Box::pin(peer.registration().register(&cx));
            let mut started = std::pin::pin!(started_rx.recv(&cx));
            poll_fn(|task| {
                assert!(attempt.as_mut().poll(task).is_pending());
                started.as_mut().poll(task)
            }).await.unwrap();
            drop(attempt);
            assert!(cx.checkpoint().is_ok());
        };
        pair(server, application).await;
        assert_eq!(peer.paths.lock().unwrap().len(), 3);
        peer.assert_no_extra_connections();
    });
}

#[test]
fn registration_deadline_covers_the_post_and_precancellation_has_no_contact() {
    run(async {
        let cx = Cx::current().unwrap();
        let peer = Peer::new().await;
        let document = peer.registration_document(&format!("{}/register", peer.origin()));
        let owner = peer.registration().with_timeout(Duration::from_secs(2)).unwrap();
        let server = async {
            peer.registration_discovery(&document).await;
            let (mut socket, _) = peer.request("POST", "/register").await;
            let mut byte = [0];
            assert!(!matches!(socket.read(&mut byte).await, Ok(count) if count > 0));
        };
        let ((), result) = pair(server, owner.register(&cx)).await;
        assert!(matches!(result, Err(OAuthRegistrationError::Discovery(OAuthDiscoveryError::TimedOut))));
        assert!(cx.checkpoint().is_ok());
        assert_eq!(peer.paths.lock().unwrap().len(), 3);
        let cancelled = Cx::detached_cancel_context();
        cancelled.cancel_with(asupersync::CancelKind::User, Some("registration preflight"));
        assert!(matches!(peer.registration().register(&cancelled).await,
            Err(OAuthRegistrationError::Discovery(OAuthDiscoveryError::Cancelled))));
        peer.assert_no_extra_connections();
    });
}
