//! Native login and shared renewal over TLS. Only the due-time is advanced
//! directly; grants, refresh-token rotation and snapshot admission are real.

use std::collections::BTreeMap;
use std::time::Duration;

use asupersync::io::{AsyncReadExt, AsyncWriteExt};
use asupersync::net::{TcpListener, TcpStream};
use asupersync::runtime::{RuntimeBuilder, reactor::create_reactor};
use asupersync::tls::{Certificate, CertificateChain, PrivateKey, TlsAcceptor, TlsAcceptorBuilder};

use super::*;
use crate::http_auth::managed::OAuthSessionPolicy;
use crate::http_auth::oauth::{OAuthClient, OAuthClientConfiguration, OAuthError};

// Existing public TEST ONLY identity; never deployment credentials.
// Inlined rather than included: `*.pem` is transfer-excluded, so an
// `include_bytes!` of this fixture makes the target UNBUILDABLE on a remote
// worker, and a test target that fails to build can report `0 passed` instead
// of failing. Same remedy, same bytes, as the eight-plus files that already
// inline this fixture, and as LEAF and KEY immediately below.
const ROOT: &[u8] = b"-----BEGIN CERTIFICATE-----\nMIIBgzCCASmgAwIBAgICA+kwCgYIKoZIzj0EAwIwJzElMCMGA1UEAwwcRmFzdE1D\nUCBPQXV0aCBURVNUIE9OTFkgUm9vdDAeFw0yMDAxMDEwMDAwMDBaFw00OTEyMzEw\nMDAwMDBaMCcxJTAjBgNVBAMMHEZhc3RNQ1AgT0F1dGggVEVTVCBPTkxZIFJvb3Qw\nWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAAS5t2O8JZ0hNjgI38E9Ov6i6mKoDRGo\nApMsykFkvgb6Zm9/5gCZ90eIKw7aWgK6iNs7lbtVY9mysZBIqm6pKQO2o0UwQzAS\nBgNVHRMBAf8ECDAGAQH/AgEAMA4GA1UdDwEB/wQEAwIBhjAdBgNVHQ4EFgQU6QNI\nrmvMiLoV3jIoCyohXARwI8gwCgYIKoZIzj0EAwIDSAAwRQIgCKOrW3vhzUJ2EyuY\nvQUTdqGFhy0zEHj4ITFLvXPz1X8CIQCLKD4EKCvS/zkBSu/6uee1WV9d97UpK3yW\nX/aCEJ5+hA==\n-----END CERTIFICATE-----\n";
const LEAF: &[u8] = b"-----BEGIN CERTIFICATE-----\nMIIBjjCCATSgAwIBAgICA+owCgYIKoZIzj0EAwIwJzElMCMGA1UEAwwcRmFzdE1D\nUCBPQXV0aCBURVNUIE9OTFkgUm9vdDAeFw0yMDAxMDEwMDAwMDBaFw00OTEyMzEw\nMDAwMDBaMBQxEjAQBgNVBAMMCWxvY2FsaG9zdDBZMBMGByqGSM49AgEGCCqGSM49\nAwEHA0IABPPKylLna9VpWAlpshHBhSsQHNOv3BaEGX4HSBhHiBVel0ce+qfHF15O\n0T63Zlp7TtxlMdEY+rPpgioSFDQVadijYzBhMAwGA1UdEwEB/wQCMAAwLAYDVR0R\nBCUwI4IJbG9jYWxob3N0hwR/AAABhxAAAAAAAAAAAAAAAAAAAAABMBMGA1UdJQQM\nMAoGCCsGAQUFBwMBMA4GA1UdDwEB/wQEAwIHgDAKBggqhkjOPQQDAgNIADBFAiEA\n6qrAr2qp/t6K62T9Et2mUU/zfd4kJb+ekyoAim1yTFcCICb6SdVY2fg15/SXf0vE\nIvYelqtTk8FQInCEcIxvfF3m\n-----END CERTIFICATE-----\n";
const KEY: &[u8] = b"-----BEGIN PRIVATE KEY-----\nMIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgcCe44IBKhbw+D/s7\nBjDHOOV0g+EoxFno7VJGKhJeer2hRANCAATzyspS52vVaVgJabIRwYUrEBzTr9wW\nhBl+B0gYR4gVXpdHHvqnxxdeTtE+t2Zae07cZTHRGPqz6YIqEhQ0FWnY\n-----END PRIVATE KEY-----\n";

type Stream = asupersync::tls::TlsStream<TcpStream>;

fn url(value: &str) -> CanonicalHttpUrl {
    CanonicalHttpUrl::parse(value).unwrap()
}

fn encode(value: &str) -> String {
    value
        .bytes()
        .map(|byte| match byte {
            b'a'..=b'z' | b'A'..=b'Z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                char::from(byte).to_string()
            }
            byte => format!("%{byte:02X}"),
        })
        .collect()
}

fn decode(value: &str) -> String {
    let mut bytes = value.bytes();
    let mut output = Vec::new();
    while let Some(byte) = bytes.next() {
        output.push(match byte {
            b'+' => b' ',
            b'%' => {
                let a = char::from(bytes.next().unwrap()).to_digit(16).unwrap();
                let b = char::from(bytes.next().unwrap()).to_digit(16).unwrap();
                u8::try_from(a * 16 + b).unwrap()
            }
            byte => byte,
        });
    }
    String::from_utf8(output).unwrap()
}

fn form(value: &str) -> BTreeMap<String, String> {
    let mut fields = BTreeMap::new();
    for item in value.split('&') {
        let (name, value) = item.split_once('=').unwrap();
        assert!(fields.insert(decode(name), decode(value)).is_none());
    }
    fields
}

async fn callback(authorization: CanonicalHttpUrl, issuer: String) -> Result<(), OAuthError> {
    let fields = form(authorization.query().unwrap());
    assert_eq!(fields["code_challenge_method"], "S256");
    let redirect = url(&fields["redirect_uri"]);
    let authority = redirect
        .as_str()
        .strip_prefix("http://")
        .unwrap()
        .split('/')
        .next()
        .unwrap();
    let mut stream = TcpStream::connect(authority.to_owned())
        .await
        .map_err(|_| OAuthError::TransportFailed)?;
    let request = format!(
        "GET /oauth/callback?code=renew-code&state={}&iss={} HTTP/1.1\r\nHost: {authority}\r\nConnection: close\r\n\r\n",
        encode(&fields["state"]),
        encode(&issuer),
    );
    stream
        .write_all(request.as_bytes())
        .await
        .map_err(|_| OAuthError::TransportFailed)?;
    let mut response = Vec::new();
    stream
        .read_to_end(&mut response)
        .await
        .map_err(|_| OAuthError::TransportFailed)?;
    assert!(response.starts_with(b"HTTP/1.1 200"));
    Ok(())
}

async fn pair<L: Future, R: Future>(left: L, right: R) -> (L::Output, R::Output) {
    let mut left = std::pin::pin!(left);
    let mut right = std::pin::pin!(right);
    let (mut first, mut second) = (None, None);
    poll_fn(|task| {
        if first.is_none() {
            if let Poll::Ready(value) = left.as_mut().poll(task) {
                first = Some(value);
            }
        }
        if second.is_none() {
            if let Poll::Ready(value) = right.as_mut().poll(task) {
                second = Some(value);
            }
        }
        if first.is_some() && second.is_some() {
            Poll::Ready((first.take().unwrap(), second.take().unwrap()))
        } else {
            Poll::Pending
        }
    })
    .await
}

struct Peer {
    listener: TcpListener,
    tls: TlsAcceptor,
}

impl Peer {
    async fn new() -> Self {
        Self {
            listener: TcpListener::bind("127.0.0.1:0").await.unwrap(),
            tls: TlsAcceptorBuilder::new(
                CertificateChain::from_pem(LEAF).unwrap(),
                PrivateKey::from_pem(KEY).unwrap(),
            )
            .alpn_protocols(vec![b"http/1.1".to_vec()])
            .build()
            .unwrap(),
        }
    }

    fn origin(&self) -> String {
        format!("https://{}", self.listener.local_addr().unwrap())
    }

    async fn token_request(&self) -> (Stream, BTreeMap<String, String>) {
        let (tcp, _) = self.listener.accept().await.unwrap();
        let mut stream = self.tls.accept(tcp).await.unwrap();
        let mut wire = Vec::new();
        let mut buffer = [0; 2048];
        let end = loop {
            let n = stream.read(&mut buffer).await.unwrap();
            assert!(n > 0 && wire.len() + n <= 16 * 1024);
            wire.extend_from_slice(&buffer[..n]);
            if let Some(at) = wire.windows(4).position(|bytes| bytes == b"\r\n\r\n") {
                break at + 4;
            }
        };
        let head = std::str::from_utf8(&wire[..end]).unwrap();
        assert!(head.starts_with("POST /token HTTP/1.1\r\n"));
        assert!(!head.to_ascii_lowercase().contains("authorization:"));
        let length = head
            .lines()
            .find_map(|line| {
                let (name, value) = line.split_once(':')?;
                name.eq_ignore_ascii_case("content-length")
                    .then(|| value.trim().parse::<usize>().unwrap())
            })
            .unwrap();
        assert!(end + length <= 16 * 1024);
        while wire.len() < end + length {
            let n = stream.read(&mut buffer).await.unwrap();
            assert!(n > 0 && wire.len() + n <= 16 * 1024);
            wire.extend_from_slice(&buffer[..n]);
        }
        assert_eq!(wire.len(), end + length);
        (stream, form(std::str::from_utf8(&wire[end..]).unwrap()))
    }

    async fn reply(stream: &mut Stream, access: &str, refresh: &str) {
        let body = format!(
            r#"{{"access_token":"{access}","refresh_token":"{refresh}","token_type":"Bearer","expires_in":3600}}"#,
        );
        let wire = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len(),
        );
        stream.write_all(wire.as_bytes()).await.unwrap();
        stream.shutdown().await.unwrap();
    }

    async fn login(&self, cx: &Cx) -> ManagedOAuthSession {
        let origin = self.origin();
        let configuration = OAuthClientConfiguration::from_trusted_endpoints(
            origin.clone(),
            url(&format!("{origin}/authorize")),
            url(&format!("{origin}/token")),
            url(&format!("{origin}/mcp")),
            "native-client",
            vec![],
        )
        .unwrap()
        .with_extra_root_certificate(Certificate::from_pem(ROOT).unwrap().remove(0))
        .unwrap();
        let policy = OAuthSessionPolicy::new(
            Duration::from_secs(30),
            Duration::from_secs(8),
            Duration::from_secs(10),
            8,
        )
        .unwrap();
        let (session, ()) = pair(
            ManagedOAuthSession::authorize_with_browser_driver(
                cx,
                OAuthClient::new(configuration),
                policy,
                Duration::from_secs(10),
                |authorization| callback(authorization, origin.clone()),
            ),
            async {
                let (mut stream, request) = self.token_request().await;
                assert_eq!(request["grant_type"], "authorization_code");
                assert_eq!(request["code"], "renew-code");
                assert_eq!(request["code_verifier"].len(), 64);
                Self::reply(&mut stream, "original-access", "original-refresh").await;
            },
        )
        .await;
        session.unwrap()
    }
}

#[derive(Clone, Copy)]
enum Case {
    Complete,
    RevokeHead,
    RevokeBody,
    CancelOwner,
    Close,
    Abandon,
}

#[test]
fn native_shared_renewal_preserves_revocation_single_flight_and_quarantine() {
    for case in [
        Case::Complete,
        Case::RevokeHead,
        Case::RevokeBody,
        Case::CancelOwner,
        Case::Close,
        Case::Abandon,
    ] {
        RuntimeBuilder::current_thread()
            .with_reactor(create_reactor().unwrap())
            .blocking_threads(0, 8)
            .build()
            .unwrap()
            .block_on(async {
                let cx = Cx::current().unwrap();
                asupersync::time::timeout_at(cx.now().saturating_add_nanos(25_000_000_000), async {
                    let peer = Peer::new().await;
                    let session = peer.login(&cx).await;
                    let original = session.credential(&cx).await.unwrap();
                    assert_eq!(original.generation(), 1);
                    // Advance scheduling only: do not fake a grant, access expiry,
                    // token exchange or successful snapshot admission.
                    session.inner.state.try_lock_owned().unwrap().as_mut().unwrap().renew_after = Instant::now();
                    let cancellation = McpRequestCancellation::new();
                    let reached = McpRequestCancellation::new();
                    let application = async {
                        let mut owner = Box::pin(session.credential_with_cancellation(&cx, &cancellation));
                        let mut queued = Box::pin(session.credential(&cx));
                        if matches!(case, Case::Abandon) {
                            let mut reached = std::pin::pin!(reached.cancelled());
                            poll_fn(|task| {
                                assert!(owner.as_mut().poll(task).is_pending());
                                assert!(queued.as_mut().poll(task).is_pending());
                                reached.as_mut().poll(task)
                            }).await;
                            drop(owner);
                            (None, queued.await)
                        } else {
                            let (one, two) = pair(owner, queued).await;
                            (Some(one), two)
                        }
                    };
                    let server = async {
                        let (mut stream, request) = peer.token_request().await;
                        assert_eq!(request["grant_type"], "refresh_token");
                        assert_eq!(request["refresh_token"], "original-refresh");
                        assert_eq!(request["client_id"], "native-client");
                        assert_eq!(request["resource"], session.resource().as_str());
                        assert_eq!(session.inner.pending.load(Ordering::Acquire), 2);
                        match case {
                            Case::Complete => {
                                Peer::reply(&mut stream, "replacement-access", "replacement-refresh").await;
                                return;
                            }
                            Case::RevokeBody => {
                                stream.write_all(b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 1024\r\nConnection: close\r\n\r\n{").await.unwrap();
                                stream.flush().await.unwrap();
                                original.credential().revoke();
                            }
                            Case::RevokeHead => original.credential().revoke(),
                            Case::CancelOwner => { cancellation.cancel(); }
                            Case::Close => session.close(),
                            Case::Abandon => { reached.cancel(); }
                        }
                        let mut byte = [0];
                        assert!(!matches!(stream.read(&mut byte).await, Ok(n) if n > 0));
                    };
                    let ((owner, queued), ()) = pair(application, server).await;
                    assert_eq!(session.inner.pending.load(Ordering::Acquire), 0);
                    match case {
                        Case::Complete => {
                            assert_eq!(owner.unwrap().unwrap().generation(), 2);
                            let replacement = queued.unwrap();
                            assert_eq!(replacement.generation(), 2);
                            assert_eq!(replacement.credential().authorization_for_target(session.resource()).as_deref(), Some("Bearer replacement-access"));
                            // An old signal cannot invalidate a handoff already admitted.
                            original.credential().revoke();
                            assert_eq!(session.credential(&cx).await.unwrap().generation(), 2);
                            assert!(!replacement.credential().is_revoked());
                        }
                        Case::Close => {
                            assert!(matches!(owner.unwrap(), Err(OAuthSessionError::Closed)));
                            assert!(matches!(queued, Err(OAuthSessionError::Closed)));
                            assert!(session.inner.state.try_lock_owned().unwrap().is_none());
                        }
                        _ => {
                            if matches!(case, Case::CancelOwner) {
                                assert!(matches!(owner.unwrap(), Err(OAuthSessionError::Cancelled)));
                            } else if matches!(case, Case::Abandon) {
                                assert!(owner.is_none());
                            } else {
                                assert!(matches!(owner.unwrap(), Err(OAuthSessionError::LoginRequired)));
                            }
                            assert!(matches!(queued, Err(OAuthSessionError::LoginRequired)));
                            {
                                let state = session.inner.state.try_lock_owned().unwrap();
                                let state = state.as_ref().unwrap();
                                assert!(state.renewal_failed);
                                assert_eq!(state.generation, 1);
                                assert!(!state.credentials.has_refresh_token());
                            }
                            assert!(matches!(session.credential(&cx).await, Err(OAuthSessionError::LoginRequired)));
                            assert!(!session.inner.closed.is_cancel_requested());
                        }
                    }
                    assert!(cx.checkpoint().is_ok());
                    assert!(peer.listener.poll_accept(&mut Context::from_waker(Waker::noop())).is_pending());
                }).await.expect("native renewal races must settle without replay");
            });
    }
}
