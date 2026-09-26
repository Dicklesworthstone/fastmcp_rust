//! Token-local revocation inside the existing managed operation lifetime.
//!
//! Only a cancellation handle is retained by response owners; no bearer text,
//! grant lock, renewal worker or polling timer is introduced. Session closure
//! and expiry keep their existing checks and error precedence.

use std::future::{Future, poll_fn};
use std::task::Poll;
use std::time::Instant;

use asupersync::Cx;
use asupersync::types::Time;
use fastmcp_core::McpRequestCancellation;

use super::{
    ManagedOAuthResponse, ManagedOAuthSession, OAuthCredentialSnapshot,
    OAuthSessionError,
};
use crate::http_executor::ModernHttpResponseStream;

impl ManagedOAuthSession {
    /// The snapshot's local revocation cannot be replaced by a newer session
    /// generation. The outer lifetime guard still owns cancellation and time.
    pub(super) async fn await_credential<T>(
        &self,
        cx: &Cx,
        cancellation: &McpRequestCancellation,
        deadline: Time,
        expiry: Instant,
        revocation: &McpRequestCancellation,
        operation: impl Future<Output = Result<T, OAuthSessionError>>,
    ) -> Result<T, OAuthSessionError> {
        self.await_active(cx, cancellation, deadline, Some(expiry), async {
            let mut revoked = std::pin::pin!(revocation.cancelled());
            let mut operation = std::pin::pin!(operation);
            poll_fn(|task| {
                if revocation.is_cancel_requested() || revoked.as_mut().poll(task).is_ready() {
                    return Poll::Ready(Err(OAuthSessionError::LoginRequired));
                }
                let result = operation.as_mut().poll(task);
                // A ready operation can trigger revocation itself. Discard its
                // value rather than releasing one last body/event on that poll.
                if revocation.is_cancel_requested() {
                    Poll::Ready(Err(OAuthSessionError::LoginRequired))
                } else {
                    result
                }
            }).await
        }).await
    }
}

impl ManagedOAuthResponse {
    /// All authenticated constructors retain the exact dispatch snapshot's
    /// revocation signal, even after its session installs a replacement grant.
    pub(super) fn from_snapshot(
        response: ModernHttpResponseStream,
        session: ManagedOAuthSession,
        cancellation: McpRequestCancellation,
        snapshot: &OAuthCredentialSnapshot,
    ) -> Self {
        Self {
            response,
            session,
            cancellation,
            expires_at: snapshot.expires_at,
            generation: snapshot.generation,
            revocation: snapshot.credential.revoked.clone(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::task::{Context, Wake, Waker};
    use std::time::Duration;

    use asupersync::io::{AsyncReadExt, AsyncWriteExt};
    use asupersync::net::TcpListener;
    use crate::http_auth::{BoundBearerCredential, CanonicalHttpUrl};
    use crate::http_auth::oauth::{OAuthClient, OAuthClientConfiguration};
    use crate::http_executor::{ModernHttpExecutor, ModernHttpExecutorError, ModernHttpRequest};
    use crate::sse::SseLimits;
    use super::super::OAuthSessionPolicy;

    // Native session/snapshot ownership with no retained session grant.
    // HTTP cases below inject body custody, never cleartext authority.
    fn session() -> ManagedOAuthSession {
        let url = |value| CanonicalHttpUrl::parse(value).unwrap();
        let configuration = OAuthClientConfiguration::from_trusted_endpoints(
            "https://issuer.example", url("https://issuer.example/authorize"),
            url("https://issuer.example/token"), url("https://mcp.example/mcp"),
            "native-client", vec![],
        ).unwrap();
        ManagedOAuthSession {
            inner: Arc::new(super::super::SessionInner {
                client: OAuthClient::new(configuration),
                resource: url("https://mcp.example/mcp"),
                policy: OAuthSessionPolicy::default(),
                state: Arc::new(asupersync::sync::Mutex::new(None)),
                closed: McpRequestCancellation::new(),
                logout_handoff: std::sync::atomic::AtomicBool::new(false),
                pending: AtomicUsize::new(0),
            }),
        }
    }

    fn snapshot(session: &ManagedOAuthSession, token: &str) -> OAuthCredentialSnapshot {
        let expiry = Instant::now() + Duration::from_secs(60);
        let credential = BoundBearerCredential::bind_with_expiry(
            session.resource().clone(), token, expiry,
        ).unwrap();
        OAuthCredentialSnapshot::new(&credential, &[], 7, expiry, &session.inner.closed).unwrap()
    }

    fn run(future: impl Future<Output = ()>) {
        asupersync::runtime::RuntimeBuilder::current_thread()
            .with_reactor(asupersync::runtime::reactor::create_reactor().unwrap())
            .build().unwrap().block_on(async {
                let cx = Cx::current().unwrap();
                asupersync::time::timeout_at(cx.now().saturating_add_nanos(10_000_000_000), future)
                    .await.unwrap();
            });
    }

    async fn guarded<T>(
        cx: &Cx, session: &ManagedOAuthSession, snapshot: &OAuthCredentialSnapshot,
        future: impl Future<Output = Result<T, OAuthSessionError>>,
    ) -> Result<T, OAuthSessionError> {
        session.await_credential(cx, &McpRequestCancellation::new(),
            cx.now().saturating_add_nanos(5_000_000_000), snapshot.expires_at,
            &snapshot.credential.revoked, future).await
    }

    #[derive(Default)]
    struct WakeCount(AtomicUsize);
    impl Wake for WakeCount {
        fn wake(self: Arc<Self>) { self.0.fetch_add(1, Ordering::SeqCst); }
        fn wake_by_ref(self: &Arc<Self>) { self.0.fetch_add(1, Ordering::SeqCst); }
    }
    struct ResultOwner(Arc<AtomicUsize>);
    impl Drop for ResultOwner {
        fn drop(&mut self) { self.0.fetch_add(1, Ordering::SeqCst); }
    }

    #[test]
    fn revoked_snapshot_never_polls_or_publishes_a_ready_operation() {
        run(async {
            let cx = Cx::current().unwrap();
            let session = session();
            let snapshot = snapshot(&session, "private-access");
            let polls = AtomicUsize::new(0);
            let drops = Arc::new(AtomicUsize::new(0));
            let owner = ResultOwner(drops.clone());
            snapshot.credential.revoke();
            let result = guarded(&cx, &session, &snapshot, async {
                polls.fetch_add(1, Ordering::SeqCst);
                Ok(owner)
            }).await;
            assert!(matches!(result, Err(OAuthSessionError::LoginRequired)));
            assert_eq!(polls.load(Ordering::SeqCst), 0);
            assert_eq!(drops.load(Ordering::SeqCst), 1);
        });
    }

    #[test]
    fn revocation_during_ready_poll_drops_the_value_before_delivery() {
        run(async {
            let cx = Cx::current().unwrap();
            let session = session();
            let snapshot = snapshot(&session, "private-access");
            let drops = Arc::new(AtomicUsize::new(0));
            let result = guarded(&cx, &session, &snapshot, async {
                snapshot.credential.revoke();
                Ok(ResultOwner(drops.clone()))
            }).await;
            assert!(matches!(result, Err(OAuthSessionError::LoginRequired)));
            assert_eq!(drops.load(Ordering::SeqCst), 1);
            assert!(!session.inner.closed.is_cancel_requested());
        });
    }

    #[test]
    fn local_revocation_wakes_an_idle_guard_without_socket_or_timer_activity() {
        run(async {
            let cx = Cx::current().unwrap();
            let session = session();
            let snapshot = snapshot(&session, "private-access");
            let clone = snapshot.credential.clone();
            let counter = Arc::new(WakeCount::default());
            let waker = Waker::from(counter.clone());
            let mut context = Context::from_waker(&waker);
            let mut pending = Box::pin(guarded(&cx, &session, &snapshot,
                std::future::pending::<Result<(), OAuthSessionError>>()));
            assert!(pending.as_mut().poll(&mut context).is_pending());
            let before = counter.0.load(Ordering::SeqCst);
            clone.revoke();
            assert!(counter.0.load(Ordering::SeqCst) > before);
            assert!(matches!(pending.await, Err(OAuthSessionError::LoginRequired)));
            assert!(cx.checkpoint().is_ok());
        });
    }

    #[test]
    fn dropping_guard_removes_revocation_wakeup_without_revoking_the_token() {
        run(async {
            let cx = Cx::current().unwrap();
            let session = session();
            let snapshot = snapshot(&session, "private-access");
            let counter = Arc::new(WakeCount::default());
            let waker = Waker::from(counter.clone());
            let mut context = Context::from_waker(&waker);
            let mut pending = Box::pin(guarded(&cx, &session, &snapshot,
                std::future::pending::<Result<(), OAuthSessionError>>()));
            assert!(pending.as_mut().poll(&mut context).is_pending());
            drop(pending);
            assert!(!snapshot.credential.is_revoked());
            let before = counter.0.load(Ordering::SeqCst);
            snapshot.credential.revoke();
            assert_eq!(counter.0.load(Ordering::SeqCst), before);
            assert!(!session.inner.closed.is_cancel_requested());
        });
    }

    #[test]
    fn token_revocation_does_not_revoke_an_independent_binding_or_later_snapshot() {
        run(async {
            let cx = Cx::current().unwrap();
            let session = session();
            let first = snapshot(&session, "same-text");
            let second = snapshot(&session, "same-text");
            first.credential.revoke();
            assert!(matches!(guarded(&cx, &session, &first, std::future::ready(Ok(1))).await,
                Err(OAuthSessionError::LoginRequired)));
            assert_eq!(guarded(&cx, &session, &second, std::future::ready(Ok(2))).await.unwrap(), 2);
            session.close();
            assert!(matches!(guarded(&cx, &session, &second, std::future::ready(Ok(3))).await,
                Err(OAuthSessionError::Closed)));
        });
    }

    #[test]
    fn original_expiry_and_request_deadline_remain_distinct_terminal_reasons() {
        run(async {
            let cx = Cx::current().unwrap();
            let session = session();
            let snapshot = snapshot(&session, "private-access");
            let cancellation = McpRequestCancellation::new();
            let result = session.await_credential(&cx, &cancellation,
                cx.now().saturating_add_nanos(20_000_000), snapshot.expires_at,
                &snapshot.credential.revoked, std::future::pending::<Result<(), OAuthSessionError>>()).await;
            assert!(matches!(result, Err(OAuthSessionError::TimedOut)));
            assert!(!snapshot.credential.is_revoked());
            let result = session.await_credential(&cx, &cancellation,
                cx.now().saturating_add_nanos(1_000_000_000), Instant::now(),
                &snapshot.credential.revoked, std::future::ready(Ok(()))).await;
            assert!(matches!(result, Err(OAuthSessionError::LoginRequired)));
        });
    }

    async fn pair<L: Future, R: Future>(left: L, right: R) -> (L::Output, R::Output) {
        let mut left = std::pin::pin!(left);
        let mut right = std::pin::pin!(right);
        let (mut one, mut two) = (None, None);
        poll_fn(|task| {
            if one.is_none() { if let Poll::Ready(value) = left.as_mut().poll(task) { one = Some(value); } }
            if two.is_none() { if let Poll::Ready(value) = right.as_mut().poll(task) { two = Some(value); } }
            if one.is_some() && two.is_some() { Poll::Ready((one.take().unwrap(), two.take().unwrap())) }
            else { Poll::Pending }
        }).await
    }

    async fn peer(listener: &TcpListener, sse: bool) {
        let (mut socket, _) = listener.accept().await.unwrap();
        let mut bytes = Vec::new();
        let mut chunk = [0; 2048];
        loop {
            let count = socket.read(&mut chunk).await.unwrap();
            assert!(count > 0 && bytes.len() + count <= 8192);
            bytes.extend_from_slice(&chunk[..count]);
            if let Some(end) = bytes.windows(4).position(|p| p == b"\r\n\r\n") {
                if bytes.len() >= end + 6 { break; }
            }
        }
        assert!(!String::from_utf8_lossy(&bytes).to_ascii_lowercase().contains("authorization:"));
        let mime = if sse { "text/event-stream" } else { "application/json" };
        socket.write_all(format!("HTTP/1.1 200 OK\r\nContent-Type: {mime}\r\nTransfer-Encoding: chunked\r\n\r\n").as_bytes()).await.unwrap();
        if sse {
            let body = "data: first\n\n";
            socket.write_all(format!("{:X}\r\n{body}\r\n", body.len()).as_bytes()).await.unwrap();
        }
        socket.flush().await.unwrap();
        let mut one = [0];
        assert!(!matches!(socket.read(&mut one).await, Ok(n) if n > 0), "revoked read releases its socket");
    }

    #[test]
    fn managed_json_and_sse_reads_retain_the_dispatch_revocation_signal() {
        for sse in [false, true] {
            run(async {
                let cx = Cx::current().unwrap();
                let session = session();
                let original = snapshot(&session, "response-secret");
                let unrelated = snapshot(&session, "replacement-secret");
                let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
                let application = async {
                    let request = ModernHttpRequest::new(
                        format!("http://{}/mcp", listener.local_addr().unwrap()), b"{}".to_vec(),
                        "2026-07-28", "tools/call", None,
                    ).unwrap();
                    let raw = ModernHttpExecutor::new().execute(&cx, &request).await.unwrap();
                    // Response custody is deliberately injected after an
                    // unauthenticated loopback exchange, not a TLS login proof.
                    let response = ManagedOAuthResponse::from_snapshot(
                        raw, session.clone(), McpRequestCancellation::new(), &original,
                    );
                    if sse {
                        let mut stream = response.into_sse_stream(SseLimits::new(4096, 4096, 64).unwrap()).unwrap();
                        assert_eq!(stream.next_event(&cx).await.unwrap().as_deref(), Some("first"));
                        let mut pending = Box::pin(stream.next_event(&cx));
                        poll_fn(|task| { assert!(pending.as_mut().poll(task).is_pending()); Poll::Ready(()) }).await;
                        original.credential.revoke();
                        assert!(matches!(pending.await, Err(OAuthSessionError::LoginRequired)));
                        assert!(matches!(stream.next_event(&cx).await,
                            Err(OAuthSessionError::Http(ModernHttpExecutorError::SseStreamClosed))));
                    } else {
                        let mut pending = Box::pin(response.read_to_end(&cx, 4096));
                        poll_fn(|task| { assert!(pending.as_mut().poll(task).is_pending()); Poll::Ready(()) }).await;
                        original.credential.revoke();
                        assert!(matches!(pending.await, Err(OAuthSessionError::LoginRequired)));
                    }
                    assert_eq!(guarded(&cx, &session, &unrelated, std::future::ready(Ok(7))).await.unwrap(), 7);
                    assert!(cx.checkpoint().is_ok());
                };
                pair(peer(&listener, sse), application).await;
            });
        }
    }
}
