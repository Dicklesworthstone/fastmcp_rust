//! Native TLS request-boundary tests, not a qualified external issuer.
use super::*;
use std::future::{Future, poll_fn};
use std::sync::atomic::{AtomicBool, Ordering};
use std::task::{Context, Poll, Waker};
use std::time::{Duration, Instant};

use asupersync::io::{AsyncReadExt, AsyncWriteExt};
use asupersync::net::TcpListener;
use crate::http_auth::oauth::{OAuthClientConfiguration, tests as native};
use fastmcp_core::CanonicalHttpUrl;

fn configuration() -> OAuthClientConfiguration {
    native::config().with_trusted_revocation_endpoint(
        CanonicalHttpUrl::parse("https://issuer.example/revoke").unwrap(),
    ).unwrap()
}

fn grant(configuration: &OAuthClientConfiguration) -> OAuthRefreshGrant {
    native::renewable_grant(configuration).take_refresh_grant().unwrap()
}

fn ready<T>(future: impl Future<Output = T>) -> T {
    let mut future = std::pin::pin!(future);
    match future.as_mut().poll(&mut Context::from_waker(Waker::noop())) {
        Poll::Ready(value) => value,
        Poll::Pending => panic!("revocation preflight entered I/O"),
    }
}

fn run(work: impl Future<Output = ()>) {
    asupersync::runtime::RuntimeBuilder::current_thread()
        .with_reactor(asupersync::runtime::reactor::create_reactor().unwrap())
        .blocking_threads(0, 2).build().unwrap().block_on(async {
            let cx = Cx::current().unwrap();
            asupersync::time::timeout_at(cx.now().saturating_add_nanos(15_000_000_000), work)
                .await.expect("revocation fixture settled within its bound");
        });
}

#[test]
fn refresh_revocation_unavailable_endpoint_is_synchronous_without_access_mutation() {
    let config = native::config();
    let mut credentials = native::renewable_grant(&config);
    let expiry = credentials.expires_at();
    let grant = credentials.take_refresh_grant().unwrap();
    assert_eq!(ready(OAuthClient::new(config).revoke_refresh_grant(&Cx::for_testing(), grant)),
        Err(OAuthRevocationError::EndpointUnavailable));
    assert!(!credentials.has_refresh_token());
    assert!(!credentials.bearer_credential().is_revoked());
    assert_eq!(credentials.expires_at(), expiry);
}

#[test]
fn refresh_revocation_rejects_changed_configuration_before_contact() {
    let original = configuration();
    for dimension in 0..5 {
        let mut changed = original.clone();
        match dimension {
            0 => changed.client_id.push_str("-other"),
            1 => changed.resource = CanonicalHttpUrl::parse("https://other.example/mcp").unwrap(),
            2 => changed.issuer.push('/'),
            3 => changed.revocation_endpoint = Some(CanonicalHttpUrl::parse("https://other.example/revoke").unwrap()),
            _ => changed = changed.with_extra_root_certificate(native::test_root()).unwrap(),
        }
        assert_eq!(ready(OAuthClient::new(changed).revoke_refresh_grant(&Cx::for_testing(), grant(&original))),
            Err(OAuthRevocationError::CredentialBindingMismatch));
    }
}

#[test]
fn refresh_revocation_precancellation_never_starts_an_exchange() {
    let config = configuration();
    let cx = Cx::for_testing_with_budget(asupersync::Budget::ZERO);
    assert_eq!(ready(OAuthClient::new(config.clone()).revoke_refresh_grant(&cx, grant(&config))),
        Err(OAuthRevocationError::Cancelled));
}

async fn peer_request(
    listener: &TcpListener,
) -> asupersync::tls::TlsStream<asupersync::net::TcpStream> {
    let (socket, _) = listener.accept().await.unwrap();
    let mut tls = native::test_acceptor().accept(socket).await.unwrap();
    let (head, form) = native::read_token_request(&mut tls).await.unwrap();
    assert!(head.starts_with("POST /revoke HTTP/1.1\r\n"));
    assert!(!head.to_ascii_lowercase().contains("authorization:"));
    assert!(!head.to_ascii_lowercase().contains("cookie:"));
    assert_eq!(form.len(), 3);
    assert_eq!(form["token"], "refresh-one");
    assert_eq!(form["token_type_hint"], "refresh_token");
    assert_eq!(form["client_id"], "native-client");
    tls
}

async fn fixture() -> (TcpListener, OAuthClientConfiguration) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let mut config = configuration().with_extra_root_certificate(native::test_root()).unwrap();
    config.revocation_endpoint = Some(CanonicalHttpUrl::parse(
        &format!("https://{}/revoke", listener.local_addr().unwrap()),
    ).unwrap());
    (listener, config)
}

fn no_more_requests(listener: &TcpListener) {
    assert!(listener.poll_accept(&mut Context::from_waker(Waker::noop())).is_pending(),
        "revocation cannot renew, send an access token, follow redirects, or retry");
}

#[test]
fn refresh_revocation_tls_preserves_each_status_without_followup_requests() {
    run(async {
        let cx = Cx::current().unwrap();
        for status in [200, 204, 400, 307, 503] {
            let (listener, config) = fixture().await;
            let client = OAuthClient::new(config.clone());
            let server = async {
                let mut tls = peer_request(&listener).await;
                // RFC 7009 ignores a successful body's content. It must not be
                // parsed as OAuth token JSON or reflected in diagnostics.
                let body = if status == 204 { "" } else { "private-peer-detail" };
                let response = format!("HTTP/1.1 {status} Fixture\r\nContent-Length: {}\r\nLocation: https://127.0.0.1:9/forbidden\r\nConnection: close\r\n\r\n{body}", body.len());
                tls.write_all(response.as_bytes()).await.unwrap();
                tls.shutdown().await.unwrap();
            };
            let (_, result) = Box::pin(native::pair(server, client.revoke_refresh_grant(&cx, grant(&config)))).await;
            let result = result.unwrap();
            assert_eq!(result, if status == 200 { OAuthTokenRevocationOutcome::Succeeded }
                else { OAuthTokenRevocationOutcome::Rejected { status } });
            assert!(!format!("{result:?}").contains("private-peer-detail"));
            no_more_requests(&listener);
        }
    });
}

#[test]
fn refresh_revocation_lost_reply_is_uncertain_without_renewal_or_retry() {
    run(async {
        let cx = Cx::current().unwrap();
        let (listener, config) = fixture().await;
        let client = OAuthClient::new(config.clone());
        let server = async { drop(peer_request(&listener).await); };
        let (_, outcome) = Box::pin(native::pair(server, client.revoke_refresh_grant(&cx, grant(&config)))).await;
        assert_eq!(outcome.unwrap(), OAuthTokenRevocationOutcome::Uncertain);
        no_more_requests(&listener);
    });
}

#[test]
fn refresh_revocation_does_not_need_a_live_access_token() {
    run(async {
        let cx = Cx::current().unwrap();
        let (listener, config) = fixture().await;
        let client = OAuthClient::new(config.clone());
        let mut credentials = native::renewable_grant(&config);
        let grant = credentials.take_refresh_grant().unwrap();
        credentials.bearer_credential().revoke();
        credentials.expires_at = Instant::now();
        let server = async {
            let mut tls = peer_request(&listener).await;
            tls.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n").await.unwrap();
            tls.shutdown().await.unwrap();
        };
        let (_, outcome) = Box::pin(native::pair(server, client.revoke_refresh_grant(&cx, grant))).await;
        assert_eq!(outcome.unwrap(), OAuthTokenRevocationOutcome::Succeeded);
        assert!(credentials.bearer_credential().is_revoked());
        assert!(credentials.expires_at() <= Instant::now());
        no_more_requests(&listener);
    });
}

#[test]
fn refresh_revocation_abandoned_network_wait_releases_the_socket() {
    run(async {
        let cx = Cx::current().unwrap();
        let (listener, config) = fixture().await;
        let client = OAuthClient::new(config.clone());
        let received = AtomicBool::new(false);
        let server = async {
            let mut tls = peer_request(&listener).await;
            received.store(true, Ordering::Release);
            let mut byte = [0];
            assert!(!matches!(tls.read(&mut byte).await, Ok(n) if n > 0));
        };
        let application = async {
            let mut operation = Box::pin(client.revoke_refresh_grant(&cx, grant(&config)));
            // The timer wakes this observer after the server has received the
            // request; there is no self-waking busy loop or background worker.
            loop {
                poll_fn(|task| { assert!(operation.as_mut().poll(task).is_pending()); Poll::Ready(()) }).await;
                if received.load(Ordering::Acquire) { break; }
                asupersync::time::sleep(cx.now(), Duration::from_millis(1)).await;
            }
            drop(operation);
        };
        Box::pin(native::pair(server, application)).await;
        no_more_requests(&listener);
    });
}
