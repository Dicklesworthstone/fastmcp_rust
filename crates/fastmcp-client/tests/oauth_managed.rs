//! Public managed-OAuth lifecycle tests using real loopback TLS exchanges.
//! The authorization server is an in-process fixture, not an external IdP.

use std::collections::BTreeMap;
use std::future::{Future, poll_fn};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::task::Poll;
use std::time::Duration;

use asupersync::Cx;
use asupersync::channel::oneshot;
use asupersync::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};
use asupersync::net::{TcpListener, TcpStream};
use asupersync::runtime::{RuntimeBuilder, reactor::create_reactor};
use asupersync::time::Sleep;
use asupersync::tls::{Certificate, CertificateChain, PrivateKey, TlsAcceptor, TlsAcceptorBuilder};
use fastmcp_client::http_auth::managed::{ManagedOAuthSession, OAuthSessionError, OAuthSessionPolicy};
use fastmcp_client::http_auth::oauth::{OAuthClient, OAuthClientConfiguration, OAuthError};
use fastmcp_client::http_executor::ModernHttpRequest;
use fastmcp_core::{CanonicalHttpUrl, McpRequestCancellation};

// TEST ONLY. Shared with the native OAuth fixture's trust domain; valid 2020-2049.
const ROOT: &[u8] = b"-----BEGIN CERTIFICATE-----\nMIIBgzCCASmgAwIBAgICA+kwCgYIKoZIzj0EAwIwJzElMCMGA1UEAwwcRmFzdE1D\nUCBPQXV0aCBURVNUIE9OTFkgUm9vdDAeFw0yMDAxMDEwMDAwMDBaFw00OTEyMzEw\nMDAwMDBaMCcxJTAjBgNVBAMMHEZhc3RNQ1AgT0F1dGggVEVTVCBPTkxZIFJvb3Qw\nWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAAS5t2O8JZ0hNjgI38E9Ov6i6mKoDRGo\nApMsykFkvgb6Zm9/5gCZ90eIKw7aWgK6iNs7lbtVY9mysZBIqm6pKQO2o0UwQzAS\nBgNVHRMBAf8ECDAGAQH/AgEAMA4GA1UdDwEB/wQEAwIBhjAdBgNVHQ4EFgQU6QNI\nrmvMiLoV3jIoCyohXARwI8gwCgYIKoZIzj0EAwIDSAAwRQIgCKOrW3vhzUJ2EyuY\nvQUTdqGFhy0zEHj4ITFLvXPz1X8CIQCLKD4EKCvS/zkBSu/6uee1WV9d97UpK3yW\nX/aCEJ5+hA==\n-----END CERTIFICATE-----\n";
const LEAF: &[u8] = b"-----BEGIN CERTIFICATE-----\nMIIBjjCCATSgAwIBAgICA+owCgYIKoZIzj0EAwIwJzElMCMGA1UEAwwcRmFzdE1D\nUCBPQXV0aCBURVNUIE9OTFkgUm9vdDAeFw0yMDAxMDEwMDAwMDBaFw00OTEyMzEw\nMDAwMDBaMBQxEjAQBgNVBAMMCWxvY2FsaG9zdDBZMBMGByqGSM49AgEGCCqGSM49\nAwEHA0IABPPKylLna9VpWAlpshHBhSsQHNOv3BaEGX4HSBhHiBVel0ce+qfHF15O\n0T63Zlp7TtxlMdEY+rPpgioSFDQVadijYzBhMAwGA1UdEwEB/wQCMAAwLAYDVR0R\nBCUwI4IJbG9jYWxob3N0hwR/AAABhxAAAAAAAAAAAAAAAAAAAAABMBMGA1UdJQQM\nMAoGCCsGAQUFBwMBMA4GA1UdDwEB/wQEAwIHgDAKBggqhkjOPQQDAgNIADBFAiEA\n6qrAr2qp/t6K62T9Et2mUU/zfd4kJb+ekyoAim1yTFcCICb6SdVY2fg15/SXf0vE\nIvYelqtTk8FQInCEcIxvfF3m\n-----END CERTIFICATE-----\n";
const KEY: &[u8] = b"-----BEGIN PRIVATE KEY-----\nMIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgcCe44IBKhbw+D/s7\nBjDHOOV0g+EoxFno7VJGKhJeer2hRANCAATzyspS52vVaVgJabIRwYUrEBzTr9wW\nhBl+B0gYR4gVXpdHHvqnxxdeTtE+t2Zae07cZTHRGPqz6YIqEhQ0FWnY\n-----END PRIVATE KEY-----\n";
const FIRST: &str = r#"{"access_token":"access-one","token_type":"Bearer","expires_in":1,"refresh_token":"refresh-one"}"#;
const NEXT: &str = r#"{"access_token":"access-two","token_type":"Bearer","expires_in":300,"refresh_token":"refresh-two","scope":"tools:read"}"#;
const NO_REFRESH: &str = r#"{"access_token":"access-one","token_type":"Bearer","expires_in":1}"#;

fn run(future: impl Future<Output = ()>) {
    RuntimeBuilder::current_thread()
        .with_reactor(create_reactor().unwrap())
        .build().unwrap().block_on(async {
            let cx = Cx::current().unwrap();
            asupersync::time::timeout_at(cx.now().saturating_add_nanos(20_000_000_000), future)
                .await.expect("the complete TLS fixture must settle within twenty seconds");
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

fn url(text: &str) -> CanonicalHttpUrl { CanonicalHttpUrl::parse(text).unwrap() }

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

fn decode_form(input: &str) -> BTreeMap<String, String> {
    input.split('&').map(|field| {
        let (key, value) = field.split_once('=').unwrap();
        (decode_component(key), decode_component(value))
    }).collect()
}

async fn browser_callback(authorization: CanonicalHttpUrl) -> Result<(), OAuthError> {
    let fields = decode_form(authorization.query().unwrap());
    let callback = &fields["redirect_uri"];
    let address: SocketAddr = callback.strip_prefix("http://").unwrap()
        .split('/').next().unwrap().parse().unwrap();
    assert!(address.ip().is_loopback());
    assert_eq!(fields["code_challenge_method"], "S256");
    let request = format!(
        "GET /oauth/callback?code=fixture-code&iss=https%3A%2F%2Fissuer.example&state={} HTTP/1.1\r\nHost: {address}\r\n\r\n",
        fields["state"],
    );
    let mut socket = TcpStream::connect(address).await.map_err(|_| OAuthError::CallbackRejected)?;
    socket.write_all(request.as_bytes()).await.map_err(|_| OAuthError::CallbackRejected)?;
    Ok(())
}

async fn read_form<IO: AsyncRead + Unpin>(io: &mut IO) -> BTreeMap<String, String> {
    let mut wire = Vec::new();
    let mut buffer = [0; 2048];
    let end = loop {
        let count = io.read(&mut buffer).await.unwrap();
        assert!(count > 0 && wire.len() + count <= 32 * 1024);
        wire.extend_from_slice(&buffer[..count]);
        if let Some(index) = wire.windows(4).position(|bytes| bytes == b"\r\n\r\n") { break index + 4; }
    };
    let head = std::str::from_utf8(&wire[..end]).unwrap();
    assert!(head.starts_with("POST /token HTTP/1.1\r\n"));
    assert!(!head.to_ascii_lowercase().contains("authorization:"));
    let length = head.lines().find_map(|line| {
        let (name, value) = line.split_once(':')?;
        name.eq_ignore_ascii_case("content-length").then(|| value.trim().parse::<usize>().unwrap())
    }).unwrap();
    assert!(end + length <= 32 * 1024);
    while wire.len() < end + length {
        let count = io.read(&mut buffer).await.unwrap();
        assert!(count > 0 && wire.len() + count <= 32 * 1024);
        wire.extend_from_slice(&buffer[..count]);
    }
    assert_eq!(wire.len(), end + length);
    decode_form(std::str::from_utf8(&wire[end..]).unwrap())
}

async fn reply(io: &mut asupersync::tls::TlsStream<TcpStream>, body: &str) {
    let response = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nCache-Control: no-store\r\nConnection: close\r\n\r\n{body}", body.len(),
    );
    io.write_all(response.as_bytes()).await.unwrap();
    io.shutdown().await.unwrap();
}

struct Peer {
    listener: TcpListener,
    acceptor: TlsAcceptor,
    requests: AtomicUsize,
}

impl Peer {
    async fn new() -> Self {
        Self {
            listener: TcpListener::bind("127.0.0.1:0").await.unwrap(),
            acceptor: TlsAcceptorBuilder::new(
                CertificateChain::from_pem(LEAF).unwrap(), PrivateKey::from_pem(KEY).unwrap(),
            ).alpn_protocols(vec![b"http/1.1".to_vec()]).build().unwrap(),
            requests: AtomicUsize::new(0),
        }
    }

    fn client(&self) -> OAuthClient {
        OAuthClient::new(OAuthClientConfiguration::from_trusted_endpoints(
            "https://issuer.example", url("https://issuer.example/authorize"),
            url(&format!("https://{}/token", self.listener.local_addr().unwrap())),
            url("https://mcp.example/mcp"), "native-client",
            vec!["tools:read".to_owned(), "tools:write".to_owned()],
        ).unwrap().with_extra_root_certificate(Certificate::from_pem(ROOT).unwrap().remove(0)).unwrap())
    }

    async fn accept(&self, grant_type: &str) -> asupersync::tls::TlsStream<TcpStream> {
        let (socket, _) = self.listener.accept().await.unwrap();
        let mut tls = self.acceptor.accept(socket).await.unwrap();
        let form = read_form(&mut tls).await;
        assert_eq!(form["grant_type"], grant_type);
        assert_eq!(form["client_id"], "native-client");
        assert_eq!(form["resource"], "https://mcp.example/mcp");
        if grant_type == "refresh_token" {
            assert_eq!(form["refresh_token"], "refresh-one");
            assert!(!form.contains_key("code_verifier"));
        } else {
            assert_eq!(form["code"], "fixture-code");
            assert!((43..=128).contains(&form["code_verifier"].len()));
        }
        self.requests.fetch_add(1, Ordering::SeqCst);
        tls
    }

    async fn login(&self, body: &str) {
        reply(&mut self.accept("authorization_code").await, body).await;
    }

    fn assert_no_extra_connection(&self) {
        let mut task = std::task::Context::from_waker(std::task::Waker::noop());
        assert!(self.listener.poll_accept(&mut task).is_pending());
    }
}

async fn expire_first_grant(cx: &Cx) {
    Sleep::new(cx.now().saturating_add_nanos(1_100_000_000)).await;
}

#[test]
fn managed_oauth_concurrent_callers_share_one_live_refresh_and_generation() {
    run(async {
        let cx = Cx::current().unwrap();
        let peer = Peer::new().await;
        let server = async {
            peer.login(FIRST).await;
            reply(&mut peer.accept("refresh_token").await, NEXT).await;
        };
        let application = async {
            let session = ManagedOAuthSession::authorize(&cx, peer.client(), OAuthSessionPolicy::default(), browser_callback).await.unwrap();
            expire_first_grant(&cx).await;
            let clone = session.clone();
            let (one, two) = pair(session.credential(&cx), clone.credential(&cx)).await;
            for snapshot in [one.unwrap(), two.unwrap(), session.credential(&cx).await.unwrap()] {
                assert_eq!(snapshot.generation(), 2);
                assert_eq!(snapshot.scopes(), ["tools:read".to_owned()]);
                assert_eq!(snapshot.credential().authorization_for_target(session.resource()), Some("Bearer access-two".to_owned()));
                assert!(snapshot.credential().authorization_for_target(&url("https://other.example/mcp")).is_none());
                assert!(!format!("{snapshot:?} {session:?}").contains("access-two"));
            }
        };
        Box::pin(pair(server, application)).await;
        assert_eq!(peer.requests.load(Ordering::SeqCst), 2);
        peer.assert_no_extra_connection();
    });
}

#[test]
fn cancelling_a_refresh_waiter_does_not_cancel_the_refresh_owner() {
    run(async {
        let cx = Cx::current().unwrap();
        let peer = Peer::new().await;
        let (started_tx, mut started_rx) = oneshot::channel::<()>();
        let (release_tx, mut release_rx) = oneshot::channel::<()>();
        let server = async {
            peer.login(FIRST).await;
            let mut tls = peer.accept("refresh_token").await;
            started_tx.send(&cx, ()).unwrap();
            release_rx.recv(&cx).await.unwrap();
            reply(&mut tls, NEXT).await;
        };
        let application = async {
            let session = ManagedOAuthSession::authorize(&cx, peer.client(), OAuthSessionPolicy::default(), browser_callback).await.unwrap();
            expire_first_grant(&cx).await;
            let cancellation = McpRequestCancellation::new();
            let owner = session.credential(&cx);
            let waiter = async {
                let mut waiter = Box::pin(session.credential_with_cancellation(&cx, &cancellation));
                let mut started = std::pin::pin!(started_rx.recv(&cx));
                poll_fn(|task| {
                    assert!(waiter.as_mut().poll(task).is_pending(), "waiter must queue behind the retained refresh");
                    started.as_mut().poll(task)
                }).await.unwrap();
                cancellation.cancel();
                assert!(matches!(waiter.await, Err(OAuthSessionError::Cancelled)));
                assert!(cx.checkpoint().is_ok());
                release_tx.send(&cx, ()).unwrap();
            };
            let (snapshot, ()) = pair(owner, waiter).await;
            assert_eq!(snapshot.unwrap().generation(), 2);
            assert_eq!(session.credential(&cx).await.unwrap().generation(), 2);
        };
        Box::pin(pair(server, application)).await;
        assert_eq!(peer.requests.load(Ordering::SeqCst), 2);
        peer.assert_no_extra_connection();
    });
}

#[test]
fn bounded_refresh_admission_recovers_after_saturation() {
    run(async {
        let cx = Cx::current().unwrap();
        let peer = Peer::new().await;
        let (started_tx, mut started_rx) = oneshot::channel::<()>();
        let (release_tx, mut release_rx) = oneshot::channel::<()>();
        let server = async {
            peer.login(FIRST).await;
            let mut tls = peer.accept("refresh_token").await;
            started_tx.send(&cx, ()).unwrap();
            release_rx.recv(&cx).await.unwrap();
            reply(&mut tls, NEXT).await;
        };
        let application = async {
            let policy = OAuthSessionPolicy::new(Duration::from_secs(30), Duration::from_secs(10), Duration::from_secs(10), 1).unwrap();
            let session = ManagedOAuthSession::authorize(&cx, peer.client(), policy, browser_callback).await.unwrap();
            expire_first_grant(&cx).await;
            let owner = session.credential(&cx);
            let contender = async {
                started_rx.recv(&cx).await.unwrap();
                assert!(matches!(session.credential(&cx).await, Err(OAuthSessionError::Saturated)));
                release_tx.send(&cx, ()).unwrap();
            };
            let (snapshot, ()) = pair(owner, contender).await;
            assert_eq!(snapshot.unwrap().generation(), 2);
            assert_eq!(session.credential(&cx).await.unwrap().generation(), 2);
        };
        Box::pin(pair(server, application)).await;
        assert_eq!(peer.requests.load(Ordering::SeqCst), 2);
        peer.assert_no_extra_connection();
    });
}

#[test]
fn abandoned_or_closed_refresh_never_reuses_the_consumed_lineage() {
    for close in [false, true] {
        run(async {
            let cx = Cx::current().unwrap();
            let peer = Peer::new().await;
            let (started_tx, mut started_rx) = oneshot::channel::<()>();
            let server = async {
                peer.login(FIRST).await;
                let mut tls = peer.accept("refresh_token").await;
                started_tx.send(&cx, ()).unwrap();
                let mut byte = [0];
                assert!(!matches!(tls.read(&mut byte).await, Ok(count) if count > 0), "abandonment closes the owned exchange");
            };
            let application = async {
                let session = ManagedOAuthSession::authorize(&cx, peer.client(), OAuthSessionPolicy::default(), browser_callback).await.unwrap();
                expire_first_grant(&cx).await;
                let mut owner = Box::pin(session.credential(&cx));
                let mut started = std::pin::pin!(started_rx.recv(&cx));
                poll_fn(|task| {
                    assert!(owner.as_mut().poll(task).is_pending());
                    started.as_mut().poll(task)
                }).await.unwrap();
                if close {
                    session.close();
                    assert!(matches!(owner.await, Err(OAuthSessionError::Closed)));
                    assert!(matches!(session.credential(&cx).await, Err(OAuthSessionError::Closed)));
                } else {
                    drop(owner);
                    assert!(matches!(session.credential(&cx).await, Err(OAuthSessionError::LoginRequired)));
                }
                assert!(cx.checkpoint().is_ok());
            };
            Box::pin(pair(server, application)).await;
            assert_eq!(peer.requests.load(Ordering::SeqCst), 2);
            peer.assert_no_extra_connection();
        });
    }
}

#[test]
fn wrong_target_and_precancelled_calls_do_not_trigger_token_renewal() {
    run(async {
        let cx = Cx::current().unwrap();
        let peer = Peer::new().await;
        let application = async {
            let session = ManagedOAuthSession::authorize(&cx, peer.client(), OAuthSessionPolicy::default(), browser_callback).await.unwrap();
            expire_first_grant(&cx).await;
            let request = ModernHttpRequest::new("https://other.example/mcp", b"{}".to_vec(), "2026-07-28", "tools/call", None).unwrap();
            assert!(matches!(session.execute(&cx, &request).await, Err(OAuthSessionError::TargetMismatch)));
            let cancelled = McpRequestCancellation::new();
            cancelled.cancel();
            assert!(matches!(session.credential_with_cancellation(&cx, &cancelled).await, Err(OAuthSessionError::Cancelled)));
            session.close();
            assert!(matches!(session.clone().credential(&cx).await, Err(OAuthSessionError::Closed)));
        };
        Box::pin(pair(peer.login(FIRST), application)).await;
        assert_eq!(peer.requests.load(Ordering::SeqCst), 1);
        peer.assert_no_extra_connection();
    });
}

#[test]
fn a_nonrenewable_expired_grant_requires_explicit_login_without_peer_contact() {
    run(async {
        let cx = Cx::current().unwrap();
        let peer = Peer::new().await;
        let application = async {
            let session = ManagedOAuthSession::authorize(&cx, peer.client(), OAuthSessionPolicy::default(), browser_callback).await.unwrap();
            expire_first_grant(&cx).await;
            assert!(matches!(session.credential(&cx).await, Err(OAuthSessionError::LoginRequired)));
        };
        Box::pin(pair(peer.login(NO_REFRESH), application)).await;
        assert_eq!(peer.requests.load(Ordering::SeqCst), 1);
        peer.assert_no_extra_connection();
    });
}

#[test]
fn issued_credentials_cannot_outlive_close_or_the_last_managed_login_owner() {
    for explicit_close in [false, true] {
        run(async {
            let cx = Cx::current().unwrap();
            let peer = Peer::new().await;
            let application = async {
                // A long-lived grant distinguishes revocation from expiry.
                let session = ManagedOAuthSession::authorize(&cx, peer.client(), OAuthSessionPolicy::default(), browser_callback).await.unwrap();
                let resource = session.resource().clone();
                let snapshot = session.credential(&cx).await.unwrap();
                let extracted = snapshot.credential().clone();
                let remaining_owner = session.clone();
                drop(session);
                assert_eq!(extracted.authorization_for_target(&resource), Some("Bearer access-two".to_owned()));
                if explicit_close {
                    remaining_owner.close();
                    assert!(matches!(remaining_owner.credential(&cx).await, Err(OAuthSessionError::Closed)));
                } else {
                    drop(remaining_owner);
                }
                for credential in [snapshot.credential(), &extracted] {
                    assert!(credential.is_revoked());
                    assert_eq!(credential.authorization_for_target(&resource), None);
                    assert!(credential.expires_at().unwrap() > std::time::Instant::now());
                }
                assert!(cx.checkpoint().is_ok());
            };
            Box::pin(pair(peer.login(NEXT), application)).await;
            assert_eq!(peer.requests.load(Ordering::SeqCst), 1);
            peer.assert_no_extra_connection();
        });
    }
}

#[test]
fn revoking_an_issued_snapshot_prevents_reacquisition_and_authenticated_dispatch() {
    run(async {
        let cx = Cx::current().unwrap();
        let peer = Peer::new().await;
        let application = async {
            let session = ManagedOAuthSession::authorize(&cx, peer.client(), OAuthSessionPolicy::default(), browser_callback).await.unwrap();
            let first = session.credential(&cx).await.unwrap();
            let second = session.credential(&cx).await.unwrap();
            first.credential().clone().revoke();
            assert!(first.credential().is_revoked());
            assert!(second.credential().is_revoked());
            assert_eq!(second.credential().authorization_for_target(session.resource()), None);
            assert!(matches!(session.credential(&cx).await, Err(OAuthSessionError::LoginRequired)));
            let request = ModernHttpRequest::new(session.resource().as_str(), b"{}".to_vec(), "2026-07-28", "tools/call", None).unwrap();
            assert!(matches!(session.execute(&cx, &request).await, Err(OAuthSessionError::LoginRequired)));
            assert!(cx.checkpoint().is_ok());
            // Revocation requires explicit login; it is not session close.
            session.close();
            assert!(matches!(session.credential(&cx).await, Err(OAuthSessionError::Closed)));
        };
        Box::pin(pair(peer.login(NEXT), application)).await;
        assert_eq!(peer.requests.load(Ordering::SeqCst), 1);
        peer.assert_no_extra_connection();
    });
}
