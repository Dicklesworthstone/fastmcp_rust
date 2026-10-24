//! Bounded, explicit DPoP resource requests over native HTTPS.
//!
//! This consumer owns the HTTPS exchange rather than returning proof headers
//! whose credential can expire before a caller eventually sends them. It does
//! not negotiate an MCP extension, acquire tokens automatically, follow a
//! redirect, or replay a request. Each explicit call signs a fresh POST proof.
//!
//! The response is deliberately raw: the caller owns JSON-RPC correlation and
//! result admission. This JSON-only entrypoint is not a streaming subscription
//! or the high-level MCP client's bidirectional/MRTR execution API.

use std::fmt;
use std::future::{Future, poll_fn};
use std::pin::pin;
use std::task::Poll;
use std::time::{Duration, Instant};

use asupersync::Cx;
use asupersync::channel::oneshot;
use asupersync::http::h1::{HttpClient, Method, RedirectPolicy, RetryPolicy};
use asupersync::time::Sleep;
use asupersync::tls::{Certificate, RootCertStore};
use asupersync::types::Time;
use fastmcp_core::{CanonicalHttpUrl, McpRequestCancellation};

use super::{DpopClientError, DpopCredential, DpopSession, require_credential};
use crate::http_auth::caller::with_caller;
use crate::http_executor::ModernHttpRequest;

/// Method-owned core MCP calls over the same bounded DPoP transport.
pub mod core;

const MAX_BODY_BYTES: usize = 8 * 1024 * 1024;
const MAX_ROOT_BYTES: usize = 64 * 1024;
const MAX_ROOTS: usize = 16;
const MAX_TIMEOUT: Duration = Duration::from_mins(15);

/// Redacted failures; no peer text, URL, proof, token or response body is stored.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DpopHttpError {
    InvalidPolicy,
    RuntimeUnavailable,
    Cancelled,
    TimedOut,
    BodyTooLarge,
    TransportFailed,
    InvalidResponseHeaders,
    Authorization(DpopClientError),
}

impl fmt::Display for DpopHttpError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::InvalidPolicy => "invalid DPoP HTTPS policy",
            Self::RuntimeUnavailable => "DPoP HTTPS requires the caller's I/O and timer",
            Self::Cancelled => "DPoP HTTPS operation cancelled",
            Self::TimedOut => "DPoP HTTPS deadline exceeded",
            Self::BodyTooLarge => "DPoP HTTPS body limit exceeded",
            Self::TransportFailed => "DPoP HTTPS transport failed; request not replayed",
            Self::InvalidResponseHeaders => "DPoP HTTPS response headers rejected",
            Self::Authorization(_) => "DPoP HTTPS authorization refused",
        })
    }
}

impl std::error::Error for DpopHttpError {}

impl From<DpopClientError> for DpopHttpError {
    fn from(error: DpopClientError) -> Self {
        Self::Authorization(error)
    }
}

/// Immutable resource trust, timeout and buffering policy. Private roots are
/// explicitly trusted by the application, not learned from a remote response.
/// Native system roots are available only with `native-tls-roots` enabled.
#[derive(Clone)]
pub struct DpopHttpPolicy {
    timeout: Duration,
    max_body_bytes: usize,
    resource_roots: Vec<Vec<u8>>,
}

impl Default for DpopHttpPolicy {
    fn default() -> Self {
        Self {
            timeout: Duration::from_secs(120),
            max_body_bytes: MAX_BODY_BYTES,
            resource_roots: Vec::new(),
        }
    }
}

impl fmt::Debug for DpopHttpPolicy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DpopHttpPolicy")
            .field("timeout", &self.timeout)
            .field("max_body_bytes", &self.max_body_bytes)
            .field("resource_root_count", &self.resource_roots.len())
            .finish()
    }
}

impl DpopHttpPolicy {
    pub fn with_timeout(mut self, timeout: Duration) -> Result<Self, DpopHttpError> {
        if timeout.is_zero() || timeout > MAX_TIMEOUT {
            return Err(DpopHttpError::InvalidPolicy);
        }
        self.timeout = timeout;
        Ok(self)
    }

    /// One cap for the request body and the completely buffered response body.
    pub fn with_max_body_bytes(mut self, limit: usize) -> Result<Self, DpopHttpError> {
        if limit == 0 || limit > MAX_BODY_BYTES {
            return Err(DpopHttpError::InvalidPolicy);
        }
        self.max_body_bytes = limit;
        Ok(self)
    }

    pub fn with_resource_root_der(mut self, der: Vec<u8>) -> Result<Self, DpopHttpError> {
        if der.is_empty() || der.len() > MAX_ROOT_BYTES || self.resource_roots.len() >= MAX_ROOTS {
            return Err(DpopHttpError::InvalidPolicy);
        }
        let mut roots = RootCertStore::empty();
        roots
            .add(&Certificate::from_der(der.clone()))
            .map_err(|_| DpopHttpError::InvalidPolicy)?;
        self.resource_roots.push(der);
        Ok(self)
    }
}

/// One bounded raw response. Debug does not print headers or body; either may
/// contain credentials deliberately reflected by the resource server.
/// Non-success status codes remain observable without automatically retrying.
pub struct DpopHttpResponse {
    status: u16,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
}

impl fmt::Debug for DpopHttpResponse {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DpopHttpResponse")
            .field("status", &self.status)
            .field("body_bytes", &self.body.len())
            .finish_non_exhaustive()
    }
}

impl DpopHttpResponse {
    pub fn status(&self) -> u16 {
        self.status
    }

    /// Sensitive peer-controlled values: callers must apply their own logging
    /// policy. In particular, do not turn reflected tokens into diagnostics.
    pub fn headers(&self) -> &[(String, String)] {
        &self.headers
    }

    pub fn body(&self) -> &[u8] {
        &self.body
    }

    pub fn into_body(self) -> Vec<u8> {
        self.body
    }
}

/// A revoke-only owner handle. Unlike the general request cancellation type,
/// this handle cannot finalize the domain and thereby disable revocation.
#[derive(Clone)]
pub struct DpopHttpRevocation(McpRequestCancellation);

impl fmt::Debug for DpopHttpRevocation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("DpopHttpRevocation(<redacted>)")
    }
}

impl DpopHttpRevocation {
    pub fn revoke(&self) {
        self.0.cancel();
    }

    pub fn is_revoked(&self) -> bool {
        self.0.is_cancel_requested()
    }
}

/// Explicit DPoP POST executor bound to one session and one resource-trust
/// policy. Token issuance and refresh remain caller-owned through DpopSession.
/// Dropping this client revokes credentials admitted by its session.
///
/// No response stream or unguarded HTTP client escapes. Cancellation, local
/// token revocation and token expiry bound the entire response read, not just
/// header generation. Already-sent bytes and remote side effects cannot be
/// recalled; failures never cause an automatic retry.
pub struct DpopHttpClient {
    session: DpopSession,
    policy: DpopHttpPolicy,
    transport: HttpClient,
}

impl fmt::Debug for DpopHttpClient {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DpopHttpClient")
            .field("policy", &self.policy)
            .finish_non_exhaustive()
    }
}

impl DpopHttpClient {
    /// Consumes an explicitly configured session without performing I/O.
    pub fn new(session: DpopSession, policy: DpopHttpPolicy) -> Result<Self, DpopHttpError> {
        session.require_active()?;
        let mut builder = HttpClient::builder()
            .redirect_policy(RedirectPolicy::None)
            .retry_policy(RetryPolicy::None)
            .no_proxy()
            .no_cookie_store()
            .max_body_size(policy.max_body_bytes)
            .max_total_connections(1);
        for der in &policy.resource_roots {
            builder = builder.add_root_certificate(Certificate::from_der(der.clone()));
        }
        Ok(Self {
            session,
            policy,
            transport: builder.build(),
        })
    }

    pub fn resource(&self) -> &CanonicalHttpUrl {
        &self.session.resource
    }

    /// Revokes this session and all credentials it admitted. No HTTP is sent.
    pub fn close(&self) {
        self.session.revoke();
    }

    /// Obtain a revoke-only handle for an in-flight close from another task.
    pub fn revocation_handle(&self) -> DpopHttpRevocation {
        DpopHttpRevocation(self.session.cancellation.clone())
    }

    /// Drop the native transport and recover the original session for explicit
    /// token refresh. Its key, AS/RS nonces and existing token ownership remain
    /// intact. Rebuilding a client does not replay any prior resource request.
    pub fn into_session(self) -> DpopSession {
        self.session
    }

    /// Performs exactly one HTTPS POST with a fresh access-token-bound proof.
    /// The MCP Accept header is narrowed to JSON: callers needing SSE or
    /// bidirectional execution must use a separately integrated streaming path.
    /// A nonce received on any status is retained for the next *explicit* call.
    pub async fn post_resource(
        &mut self,
        cx: &Cx,
        cancellation: &McpRequestCancellation,
        credential: &DpopCredential,
        request: &ModernHttpRequest,
    ) -> Result<DpopHttpResponse, DpopHttpError> {
        let bounds = WaitBounds::new(cx, self.policy.timeout, credential)?;
        self.post_resource_with_bounds(cx, cancellation, credential, request, bounds)
            .await
    }

    // Typed calls freeze this bound before encoding, then retain it through
    // HTTP and result admission. Preparation must not restart the timeout.
    async fn post_resource_with_bounds(
        &mut self,
        cx: &Cx,
        cancellation: &McpRequestCancellation,
        credential: &DpopCredential,
        request: &ModernHttpRequest,
        bounds: WaitBounds,
    ) -> Result<DpopHttpResponse, DpopHttpError> {
        let response = within(cx, cancellation, &self.session, credential, bounds, async {
            let headers = resource_headers(&self.session, credential, request, &self.policy)?;
            let body = request.body().to_vec();
            // Proof signing and allocation are synchronous; re-admit before
            // the first network poll, not only after that poll completes.
            check_live(cx, cancellation, &self.session, credential, bounds)?;
            let response = self
                .transport
                .request(
                    cx,
                    Method::Post,
                    self.session.resource.as_str(),
                    headers,
                    body,
                )
                .await
                .map_err(|_| DpopHttpError::TransportFailed)?;
            Ok(DpopHttpResponse {
                status: response.status,
                headers: response.headers,
                body: response.body,
            })
        })
        .await?;
        check_live(cx, cancellation, &self.session, credential, bounds)?;
        let response = finish_response(&mut self.session, &self.policy, response)?;
        check_live(cx, cancellation, &self.session, credential, bounds)?;
        Ok(response)
    }
}

fn resource_headers(
    session: &DpopSession,
    credential: &DpopCredential,
    request: &ModernHttpRequest,
    policy: &DpopHttpPolicy,
) -> Result<Vec<(String, String)>, DpopHttpError> {
    if request.body().len() > policy.max_body_bytes {
        return Err(DpopHttpError::BodyTooLarge);
    }
    let target =
        CanonicalHttpUrl::parse(request.target()).map_err(|_| DpopClientError::EndpointMismatch)?;
    let mut headers = request.headers();
    for (name, value) in &mut headers {
        if name.eq_ignore_ascii_case("Accept") {
            *value = "application/json".to_owned();
        }
    }
    session
        .resource_request_headers("POST", &target, credential)?
        .apply_to(&mut headers)?;
    headers.push(("Connection".to_owned(), "close".to_owned()));
    Ok(headers)
}

fn finish_response(
    session: &mut DpopSession,
    policy: &DpopHttpPolicy,
    response: DpopHttpResponse,
) -> Result<DpopHttpResponse, DpopHttpError> {
    if response.body.len() > policy.max_body_bytes {
        return Err(DpopHttpError::BodyTooLarge);
    }
    // Never sniff an SSE or encoded body into JSON. HTTP failures remain raw
    // so callers can handle nonce challenges and redirects without replay.
    if (200..300).contains(&response.status) {
        let mut content_types = response
            .headers
            .iter()
            .filter(|(name, _)| name.eq_ignore_ascii_case("Content-Type"));
        if response.status == 202 {
            // Modern notification acknowledgement is deliberately body-free
            // and Content-Type-free, rather than an empty JSON document.
            if !response.body.is_empty() || content_types.next().is_some() {
                return Err(DpopHttpError::InvalidResponseHeaders);
            }
        } else {
            let Some((_, content_type)) = content_types.next() else {
                return Err(DpopHttpError::InvalidResponseHeaders);
            };
            if content_types.next().is_some() || !is_json_content_type(content_type) {
                return Err(DpopHttpError::InvalidResponseHeaders);
            }
        }
    }
    let mut encodings = response
        .headers
        .iter()
        .filter(|(name, _)| name.eq_ignore_ascii_case("Content-Encoding"));
    if let Some((_, encoding)) = encodings.next() {
        if encodings.next().is_some()
            || !encoding
                .trim_matches([' ', '\t'])
                .eq_ignore_ascii_case("identity")
        {
            return Err(DpopHttpError::InvalidResponseHeaders);
        }
    }
    let source = session.resource.clone();
    session.observe_resource_nonce(&source, &response.headers)?;
    Ok(response)
}

fn is_json_content_type(value: &str) -> bool {
    let mut parts = value.split(';');
    if !parts.next().is_some_and(|part| {
        part.trim_matches([' ', '\t'])
            .eq_ignore_ascii_case("application/json")
    }) {
        return false;
    }
    match parts.next() {
        None => true,
        Some(parameter) => {
            let Some((name, value)) = parameter.split_once('=') else {
                return false;
            };
            name.trim_matches([' ', '\t'])
                .eq_ignore_ascii_case("charset")
                && ["utf-8", "\"utf-8\""].iter().any(|allowed| {
                    value
                        .trim_matches([' ', '\t'])
                        .eq_ignore_ascii_case(allowed)
                })
                && parts.next().is_none()
        }
    }
}

#[derive(Clone, Copy)]
struct WaitBounds {
    deadline: Time,
    terminal: DpopHttpError,
}

impl WaitBounds {
    fn new(cx: &Cx, timeout: Duration, credential: &DpopCredential) -> Result<Self, DpopHttpError> {
        if cx.checkpoint().is_err() {
            return Err(DpopHttpError::Cancelled);
        }
        require_credential(credential)?;
        with_caller(cx, || require_runtime(cx))?;
        if timeout.is_zero() || timeout > MAX_TIMEOUT {
            return Err(DpopHttpError::InvalidPolicy);
        }
        // Sample the caller clock first: conversion must never extend the
        // credential's original monotonic lifetime by preparation overhead.
        let now = cx.now();
        let remaining = credential
            .expires_at()
            .and_then(|expiry| expiry.checked_duration_since(Instant::now()))
            .filter(|remaining| !remaining.is_zero())
            .ok_or(DpopClientError::CredentialUnavailable)?;
        let requested =
            now.saturating_add_nanos(u64::try_from(timeout.as_nanos()).unwrap_or(u64::MAX));
        let deadline = cx
            .budget()
            .deadline
            .map_or(requested, |parent| parent.min(requested));
        let expiry =
            now.saturating_add_nanos(u64::try_from(remaining.as_nanos()).unwrap_or(u64::MAX));
        let bounds = if expiry <= deadline {
            Self {
                deadline: expiry,
                terminal: DpopClientError::CredentialUnavailable.into(),
            }
        } else {
            Self {
                deadline,
                terminal: DpopHttpError::TimedOut,
            }
        };
        if cx.now() >= bounds.deadline {
            return Err(bounds.terminal);
        }
        Ok(bounds)
    }
}

// Called inside with_caller: possession of a native driver does not override
// the surrounding effect ceiling. The whole DPoP exchange needs time and I/O,
// including when it is paused in host resolution rather than network polling.
fn require_runtime(cx: &Cx) -> Result<(), DpopHttpError> {
    if cx.timer_driver().is_none()
        || !Cx::current().is_some_and(|active| {
            let capabilities = active.capabilities();
            capabilities.time && capabilities.io
        })
    {
        return Err(DpopHttpError::RuntimeUnavailable);
    }
    Ok(())
}

fn check_live(
    cx: &Cx,
    cancellation: &McpRequestCancellation,
    session: &DpopSession,
    credential: &DpopCredential,
    bounds: WaitBounds,
) -> Result<(), DpopHttpError> {
    check_live_owner(cx, cancellation, &session.cancellation, credential, bounds)
}

// The revoke-only owner signal lets an already-admitted response remain live
// while the single mutable session owner processes another response nonce.
// It cannot sign a proof, admit a credential, select an endpoint, or renew time.
fn check_live_owner(
    cx: &Cx,
    cancellation: &McpRequestCancellation,
    owner: &McpRequestCancellation,
    credential: &DpopCredential,
    bounds: WaitBounds,
) -> Result<(), DpopHttpError> {
    if cancellation.is_cancel_requested() || cx.checkpoint().is_err() {
        return Err(DpopHttpError::Cancelled);
    }
    if owner.is_cancel_requested() {
        return Err(DpopClientError::SessionRevoked.into());
    }
    require_credential(credential)?;
    if cx.now() >= bounds.deadline {
        return Err(bounds.terminal);
    }
    Ok(())
}

async fn within<T>(
    cx: &Cx,
    cancellation: &McpRequestCancellation,
    session: &DpopSession,
    credential: &DpopCredential,
    bounds: WaitBounds,
    future: impl Future<Output = Result<T, DpopHttpError>>,
) -> Result<T, DpopHttpError> {
    within_owner(cx, cancellation, &session.cancellation, credential, bounds, future).await
}

// Same cancellation domains, effect ceiling, timer and error ordering as
// `within`; only the mutable nonce owner is no longer borrowed by the waiter.
async fn within_owner<T>(
    cx: &Cx,
    cancellation: &McpRequestCancellation,
    owner: &McpRequestCancellation,
    credential: &DpopCredential,
    bounds: WaitBounds,
    future: impl Future<Output = Result<T, DpopHttpError>>,
) -> Result<T, DpopHttpError> {
    check_live_owner(cx, cancellation, owner, credential, bounds)?;
    // Public Sleep resolves its driver when polled. The non-widening caller
    // scope below covers every timer, cancellation and application poll, and
    // is restored before suspension. Nested host runners inherit the ceiling.
    let mut timer = pin!(Sleep::new(bounds.deadline));
    let (_sender, mut receiver) = oneshot::channel::<()>();
    let mut caller = pin!(receiver.recv(cx));
    let mut operation_cancelled = pin!(cancellation.cancelled());
    let mut owner_cancelled = pin!(owner.cancelled());
    let mut token_cancelled = pin!(credential.bound.revoked.cancelled());
    let mut credential_owner_cancelled = pin!(async {
        match &credential.bound.owner_cancellation {
            Some(owner) => owner.cancelled().await,
            None => std::future::pending::<()>().await,
        }
    });
    let mut future = pin!(future);
    poll_fn(|task| {
        with_caller(cx, || {
            check_live_owner(cx, cancellation, owner, credential, bounds)?;
            require_runtime(cx)?;
            if caller.as_mut().poll(task).is_ready()
                || operation_cancelled.as_mut().poll(task).is_ready()
            {
                return Poll::Ready(Err(DpopHttpError::Cancelled));
            }
            if owner_cancelled.as_mut().poll(task).is_ready() {
                return Poll::Ready(Err(DpopClientError::SessionRevoked.into()));
            }
            if token_cancelled.as_mut().poll(task).is_ready()
                || credential_owner_cancelled.as_mut().poll(task).is_ready()
            {
                return Poll::Ready(Err(DpopClientError::CredentialUnavailable.into()));
            }
            if timer.as_mut().poll(task).is_ready() {
                return Poll::Ready(Err(bounds.terminal));
            }
            let result = future.as_mut().poll(task);
            check_live_owner(cx, cancellation, owner, credential, bounds)?;
            result
        })
    })
    .await
}

#[cfg(test)]
mod tests {
    use std::pin::Pin;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::task::{Context, Wake, Waker};

    use asupersync::Budget;
    use asupersync::runtime::{Runtime, RuntimeBuilder};
    use asupersync::time::{TimerDriverHandle, VirtualClock};
    use fastmcp_protocol::dpop::{DpopKey, DpopNonce};

    use super::*;
    use crate::http_auth::BoundBearerCredential;

    mod authority;

    fn url(value: &str) -> CanonicalHttpUrl {
        CanonicalHttpUrl::parse(value).unwrap()
    }

    fn session() -> DpopSession {
        DpopSession::new(
            DpopKey::generate().unwrap(),
            url("https://issuer.example/token"),
            url("https://mcp.example/api?tenant=one"),
        )
        .unwrap()
    }

    fn credential(session: &DpopSession) -> DpopCredential {
        session
            .admit_token_response(
                &session.token_endpoint,
                200,
                br#"{"access_token":"private-token","token_type":"DPoP","expires_in":60}"#,
                Instant::now(),
                Duration::from_secs(60),
            )
            .unwrap()
    }

    fn request(target: &str) -> ModernHttpRequest {
        ModernHttpRequest::new(
            target,
            br#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"echo","arguments":{}}}"#.to_vec(),
            fastmcp_protocol::FINAL_PROTOCOL_VERSION,
            "tools/call",
            Some("echo".to_owned()),
        ).unwrap()
    }

    fn response(status: u16, headers: &[(&str, &str)], body: &[u8]) -> DpopHttpResponse {
        DpopHttpResponse {
            status,
            headers: headers
                .iter()
                .map(|(name, value)| (name.to_string(), value.to_string()))
                .collect(),
            body: body.to_vec(),
        }
    }

    fn runtime() -> (Runtime, Cx, TimerDriverHandle, Arc<VirtualClock>) {
        let clock = Arc::new(VirtualClock::new());
        let timer = TimerDriverHandle::with_virtual_clock(Arc::clone(&clock));
        let runtime = RuntimeBuilder::current_thread()
            .blocking_threads(0, 0)
            .with_timer_driver(timer.clone())
            .build()
            .unwrap();
        let cx = runtime.request_cx_with_budget(Budget::INFINITE);
        (runtime, cx, timer, clock)
    }

    #[derive(Default)]
    struct WakeCount(AtomicUsize);

    impl Wake for WakeCount {
        fn wake(self: Arc<Self>) {
            self.0.fetch_add(1, Ordering::SeqCst);
        }
        fn wake_by_ref(self: &Arc<Self>) {
            self.0.fetch_add(1, Ordering::SeqCst);
        }
    }

    struct PendingIo(Arc<AtomicUsize>);

    impl Future for PendingIo {
        type Output = Result<(), DpopHttpError>;
        fn poll(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<Self::Output> {
            Poll::Pending
        }
    }

    impl Drop for PendingIo {
        fn drop(&mut self) {
            self.0.fetch_add(1, Ordering::SeqCst);
        }
    }

    #[test]
    fn resource_post_preserves_mcp_headers_and_signs_each_attempt() {
        let session = session();
        let credential = credential(&session);
        let request = request(session.resource.as_str());
        let policy = DpopHttpPolicy::default();
        let first = resource_headers(&session, &credential, &request, &policy).unwrap();
        let second = resource_headers(&session, &credential, &request, &policy).unwrap();
        for (name, expected) in [
            ("Authorization", "DPoP private-token"),
            ("Accept", "application/json"),
            ("Accept-Encoding", "identity"),
            ("Mcp-Method", "tools/call"),
            ("Mcp-Name", "echo"),
            (
                "MCP-Protocol-Version",
                fastmcp_protocol::FINAL_PROTOCOL_VERSION,
            ),
            ("Connection", "close"),
        ] {
            let values: Vec<_> = first
                .iter()
                .filter(|(key, _)| key.eq_ignore_ascii_case(name))
                .collect();
            assert_eq!(values.len(), 1, "{name}");
            assert_eq!(values[0].1, expected, "{name}");
        }
        let proof = |headers: &Vec<(String, String)>| {
            headers
                .iter()
                .find(|(name, _)| name == "DPoP")
                .unwrap()
                .1
                .clone()
        };
        assert_ne!(
            proof(&first),
            proof(&second),
            "an explicit retry must not replay a proof"
        );
        assert!(!request.headers().iter().any(|(name, _)| name == "DPoP"));
    }

    #[test]
    fn resource_post_refuses_changed_query_conflicting_bearer_and_revoked_token() {
        let session = session();
        let credential = credential(&session);
        let policy = DpopHttpPolicy::default();
        let exact = request(session.resource.as_str());
        assert!(resource_headers(&session, &credential, &exact, &policy).is_ok());
        let changed = request("https://mcp.example/api?tenant=two");
        assert_eq!(
            resource_headers(&session, &credential, &changed, &policy).unwrap_err(),
            DpopHttpError::Authorization(DpopClientError::EndpointMismatch)
        );
        let bearer =
            BoundBearerCredential::bind(session.resource.clone(), "bearer-secret").unwrap();
        let conflict = exact.clone().with_authorization(&bearer);
        assert_eq!(
            resource_headers(&session, &credential, &conflict, &policy).unwrap_err(),
            DpopHttpError::Authorization(DpopClientError::HeaderConflict)
        );
        credential.revoke();
        assert_eq!(
            resource_headers(&session, &credential, &exact, &policy).unwrap_err(),
            DpopHttpError::Authorization(DpopClientError::CredentialUnavailable)
        );
    }

    #[test]
    fn request_body_cap_is_exact_and_policy_is_bounded() {
        let session = session();
        let credential = credential(&session);
        let request = request(session.resource.as_str());
        let policy = DpopHttpPolicy::default()
            .with_max_body_bytes(request.body().len())
            .unwrap();
        assert!(resource_headers(&session, &credential, &request, &policy).is_ok());
        let smaller = policy
            .with_max_body_bytes(request.body().len() - 1)
            .unwrap();
        assert_eq!(
            resource_headers(&session, &credential, &request, &smaller).unwrap_err(),
            DpopHttpError::BodyTooLarge
        );
        for bytes in [0, MAX_BODY_BYTES + 1] {
            assert!(
                DpopHttpPolicy::default()
                    .with_max_body_bytes(bytes)
                    .is_err()
            );
        }
        for timeout in [Duration::ZERO, MAX_TIMEOUT + Duration::from_secs(1)] {
            assert!(DpopHttpPolicy::default().with_timeout(timeout).is_err());
        }
        assert!(
            DpopHttpPolicy::default()
                .with_resource_root_der(vec![1, 2, 3])
                .is_err()
        );
    }

    #[test]
    fn response_nonce_is_captured_on_success_and_challenge_without_touching_as_nonce() {
        let mut session = session();
        session.token_nonce = Some(DpopNonce::new("as-nonce").unwrap());
        for (status, nonce) in [
            (200, "rs-success"),
            (401, "rs-challenge"),
            (307, "rs-redirect"),
        ] {
            let response = response(
                status,
                &[("Content-Type", "application/json"), ("DPoP-Nonce", nonce)],
                b"{}",
            );
            let accepted =
                finish_response(&mut session, &DpopHttpPolicy::default(), response).unwrap();
            assert_eq!(accepted.status(), status);
            assert_eq!(accepted.body(), b"{}");
            assert_eq!(session.resource_nonce, Some(DpopNonce::new(nonce).unwrap()));
            assert_eq!(
                session.token_nonce,
                Some(DpopNonce::new("as-nonce").unwrap())
            );
        }
    }

    #[test]
    fn rejected_response_does_not_overwrite_the_previous_nonce() {
        let mut session = session();
        let initial = DpopNonce::new("last-admitted").unwrap();
        session.resource_nonce = Some(initial.clone());
        for headers in [
            vec![
                ("Content-Type", "application/json"),
                ("DPoP-Nonce", "new"),
                ("dpop-nonce", "new"),
            ],
            vec![("Content-Type", "text/event-stream"), ("DPoP-Nonce", "new")],
            vec![
                ("Content-Type", "application/json"),
                ("content-type", "application/json"),
                ("DPoP-Nonce", "new"),
            ],
            vec![
                ("Content-Type", "application/json"),
                ("Content-Encoding", "gzip"),
                ("DPoP-Nonce", "new"),
            ],
        ] {
            assert!(
                finish_response(
                    &mut session,
                    &DpopHttpPolicy::default(),
                    response(200, &headers, b"{}")
                )
                .is_err()
            );
            assert_eq!(session.resource_nonce, Some(initial.clone()));
        }
        let policy = DpopHttpPolicy::default().with_max_body_bytes(1).unwrap();
        assert_eq!(
            finish_response(
                &mut session,
                &policy,
                response(
                    200,
                    &[("Content-Type", "application/json"), ("DPoP-Nonce", "new")],
                    b"{}"
                )
            )
            .unwrap_err(),
            DpopHttpError::BodyTooLarge
        );
        assert_eq!(session.resource_nonce, Some(initial));
    }

    #[test]
    fn json_media_type_admission_does_not_accept_sse_or_duplicate_charsets() {
        for value in [
            "application/json",
            "Application/JSON; charset=UTF-8",
            "application/json;charset=\"utf-8\"",
        ] {
            assert!(is_json_content_type(value), "{value}");
        }
        for value in [
            "text/event-stream",
            "application/json;charset=utf-16",
            "application/json;charset=utf-8;charset=utf-8",
            "application/json, text/event-stream",
            "application/json;",
        ] {
            assert!(!is_json_content_type(value), "{value}");
        }
    }

    #[test]
    fn notification_acknowledgement_requires_empty_body_and_no_content_type() {
        let mut session = session();
        let policy = DpopHttpPolicy::default();
        let accepted = finish_response(&mut session, &policy, response(202, &[], b"")).unwrap();
        assert_eq!(accepted.status(), 202);
        for rejected in [
            response(202, &[], b"{}"),
            response(202, &[("Content-Type", "application/json")], b""),
            response(200, &[], b""),
        ] {
            assert_eq!(
                finish_response(&mut session, &policy, rejected).unwrap_err(),
                DpopHttpError::InvalidResponseHeaders
            );
        }
    }

    #[test]
    fn cancelled_caller_cannot_poll_a_ready_network_operation() {
        let cx = Cx::for_testing();
        cx.set_cancel_requested(true);
        let session = session();
        let credential = credential(&session);
        let cancellation = McpRequestCancellation::new();
        let bounds = WaitBounds {
            deadline: Time::from_nanos(u64::MAX),
            terminal: DpopHttpError::TimedOut,
        };
        let mut operation = Box::pin(within(
            &cx,
            &cancellation,
            &session,
            &credential,
            bounds,
            poll_fn(|_| -> Poll<Result<(), DpopHttpError>> {
                panic!("cancelled caller admitted network work")
            }),
        ));
        assert_eq!(
            operation
                .as_mut()
                .poll(&mut Context::from_waker(Waker::noop())),
            Poll::Ready(Err(DpopHttpError::Cancelled))
        );
    }

    #[test]
    fn pending_io_is_woken_and_dropped_by_each_cancellation_domain() {
        for kind in 0..4 {
            let (runtime, cx, timer, _) = runtime();
            let session = session();
            let credential = credential(&session);
            let cancellation = McpRequestCancellation::new();
            let drops = Arc::new(AtomicUsize::new(0));
            let counter = Arc::new(WakeCount::default());
            let waker = Waker::from(Arc::clone(&counter));
            let mut task = Context::from_waker(&waker);
            let bounds = WaitBounds::new(&cx, Duration::from_secs(10), &credential).unwrap();
            let mut operation = Box::pin(within(
                &cx,
                &cancellation,
                &session,
                &credential,
                bounds,
                PendingIo(Arc::clone(&drops)),
            ));
            assert!(operation.as_mut().poll(&mut task).is_pending());
            assert_eq!(counter.0.load(Ordering::SeqCst), 0);
            match kind {
                0 => cx.set_cancel_requested(true),
                1 => {
                    cancellation.cancel();
                }
                2 => session.revoke(),
                _ => credential.revoke(),
            }
            assert!(
                counter.0.load(Ordering::SeqCst) > 0,
                "domain {kind} failed to wake pending I/O"
            );
            let Poll::Ready(Err(error)) = operation.as_mut().poll(&mut task) else {
                panic!("cancelled I/O stayed pending");
            };
            let expected = match kind {
                0 | 1 => DpopHttpError::Cancelled,
                2 => DpopClientError::SessionRevoked.into(),
                _ => DpopClientError::CredentialUnavailable.into(),
            };
            assert_eq!(error, expected);
            assert_eq!(drops.load(Ordering::SeqCst), 1);
            assert_eq!(timer.pending_count(), 0);
            drop(operation);
            drop(cx);
            assert!(runtime.shutdown_timeout(Duration::from_secs(1)));
        }
    }

    #[test]
    fn deadline_wakes_pending_io_and_token_expiry_can_only_shorten_it() {
        for short_timeout in [false, true] {
            let (runtime, cx, timer, clock) = runtime();
            let session = session();
            let credential = credential(&session);
            let cancellation = McpRequestCancellation::new();
            let timeout = Duration::from_secs(if short_timeout { 10 } else { 120 });
            let bounds = WaitBounds::new(&cx, timeout, &credential).unwrap();
            let expected = if short_timeout {
                DpopHttpError::TimedOut
            } else {
                DpopClientError::CredentialUnavailable.into()
            };
            assert_eq!(bounds.terminal, expected);
            assert!(bounds.deadline.as_nanos() <= timeout.as_nanos() as u64);
            let drops = Arc::new(AtomicUsize::new(0));
            let counter = Arc::new(WakeCount::default());
            let waker = Waker::from(Arc::clone(&counter));
            let mut task = Context::from_waker(&waker);
            let mut operation = Box::pin(within(
                &cx,
                &cancellation,
                &session,
                &credential,
                bounds,
                PendingIo(Arc::clone(&drops)),
            ));
            assert!(operation.as_mut().poll(&mut task).is_pending());
            clock.advance(bounds.deadline.as_nanos());
            assert!(timer.process_timers() > 0);
            assert!(
                counter.0.load(Ordering::SeqCst) > 0,
                "deadline must wake before manual repoll"
            );
            let Poll::Ready(Err(error)) = operation.as_mut().poll(&mut task) else {
                panic!("expired operation stayed pending");
            };
            assert_eq!(error, expected);
            assert_eq!(drops.load(Ordering::SeqCst), 1);
            assert_eq!(timer.pending_count(), 0);
            drop(operation);
            drop(cx);
            assert!(runtime.shutdown_timeout(Duration::from_secs(1)));
        }
    }

    #[test]
    fn abandonment_retires_timer_and_all_cancellation_waiters() {
        let (runtime, cx, timer, clock) = runtime();
        let session = session();
        let credential = credential(&session);
        let cancellation = McpRequestCancellation::new();
        let bounds = WaitBounds::new(&cx, Duration::from_secs(10), &credential).unwrap();
        let drops = Arc::new(AtomicUsize::new(0));
        let counter = Arc::new(WakeCount::default());
        let waker = Waker::from(Arc::clone(&counter));
        let mut operation = Box::pin(within(
            &cx,
            &cancellation,
            &session,
            &credential,
            bounds,
            PendingIo(Arc::clone(&drops)),
        ));
        assert!(
            operation
                .as_mut()
                .poll(&mut Context::from_waker(&waker))
                .is_pending()
        );
        drop(operation);
        assert_eq!(drops.load(Ordering::SeqCst), 1);
        assert_eq!(timer.pending_count(), 0);
        assert_eq!(Arc::strong_count(&counter), 2);
        cancellation.cancel();
        credential.revoke();
        session.revoke();
        cx.set_cancel_requested(true);
        clock.advance(bounds.deadline.as_nanos());
        assert_eq!(timer.process_timers(), 0);
        assert_eq!(counter.0.load(Ordering::SeqCst), 0);
        drop(cx);
        assert!(runtime.shutdown_timeout(Duration::from_secs(1)));
    }

    #[test]
    fn ready_result_is_not_published_after_mid_poll_revocation() {
        let (runtime, cx, timer, _) = runtime();
        let session = session();
        let credential = credential(&session);
        let cancellation = McpRequestCancellation::new();
        let bounds = WaitBounds::new(&cx, Duration::from_secs(10), &credential).unwrap();
        let mut operation = Box::pin(within(
            &cx,
            &cancellation,
            &session,
            &credential,
            bounds,
            async {
                credential.revoke();
                Ok("must-not-be-delivered")
            },
        ));
        assert_eq!(
            operation
                .as_mut()
                .poll(&mut Context::from_waker(Waker::noop())),
            Poll::Ready(Err(DpopClientError::CredentialUnavailable.into()))
        );
        assert_eq!(timer.pending_count(), 0);
        drop(operation);
        drop(cx);
        assert!(runtime.shutdown_timeout(Duration::from_secs(1)));
    }

    #[test]
    fn live_operation_uses_caller_context_and_restores_ambient_context() {
        let (runtime, cx, timer, _) = runtime();
        let session = session();
        let credential = credential(&session);
        let cancellation = McpRequestCancellation::new();
        let bounds = WaitBounds::new(&cx, Duration::from_secs(10), &credential).unwrap();
        let ambient = Cx::for_testing();
        let _ambient = Cx::set_current(Some(ambient.clone()));
        let mut operation = Box::pin(within(
            &cx,
            &cancellation,
            &session,
            &credential,
            bounds,
            async {
                assert!(Cx::current().unwrap().timer_driver().is_some());
                Ok(42)
            },
        ));
        assert_eq!(
            operation
                .as_mut()
                .poll(&mut Context::from_waker(Waker::noop())),
            Poll::Ready(Ok(42))
        );
        assert!(Cx::current().unwrap().timer_driver().is_none());
        assert!(!ambient.is_cancel_requested());
        assert_eq!(timer.pending_count(), 0);
        drop(operation);
        drop(cx);
        assert!(runtime.shutdown_timeout(Duration::from_secs(1)));
    }

    #[test]
    fn owner_handle_is_revoke_only_and_session_can_be_recovered_without_revocation() {
        let session = session();
        let credential = credential(&session);
        let client = DpopHttpClient::new(session, DpopHttpPolicy::default()).unwrap();
        let owner = client.revocation_handle();
        assert!(!owner.is_revoked());
        let session = client.into_session();
        assert!(!credential.is_revoked());
        owner.revoke();
        assert!(owner.is_revoked());
        assert!(credential.is_revoked());
        assert_eq!(
            session.require_active(),
            Err(DpopClientError::SessionRevoked)
        );
    }

    #[test]
    fn pending_deadline_uses_the_callers_driver_not_an_unrelated_ambient_driver() {
        let (caller_runtime, cx, timer, clock) = runtime();
        let (ambient_runtime, ambient_cx, ambient_timer, _) = runtime();
        let ambient_guard = Cx::set_current(Some(ambient_cx.clone()));
        let session = session();
        let credential = credential(&session);
        let cancellation = McpRequestCancellation::new();
        let bounds = WaitBounds::new(&cx, Duration::from_secs(10), &credential).unwrap();
        let drops = Arc::new(AtomicUsize::new(0));
        let counter = Arc::new(WakeCount::default());
        let waker = Waker::from(Arc::clone(&counter));
        let mut task = Context::from_waker(&waker);
        let mut operation = Box::pin(within(
            &cx,
            &cancellation,
            &session,
            &credential,
            bounds,
            PendingIo(Arc::clone(&drops)),
        ));
        assert!(operation.as_mut().poll(&mut task).is_pending());
        assert_eq!(timer.pending_count(), 1);
        assert_eq!(ambient_timer.pending_count(), 0);
        assert_eq!(counter.0.load(Ordering::SeqCst), 0);
        clock.advance(bounds.deadline.as_nanos());
        assert!(timer.process_timers() > 0);
        assert!(counter.0.load(Ordering::SeqCst) > 0);
        assert_eq!(
            operation.as_mut().poll(&mut task),
            Poll::Ready(Err(DpopHttpError::TimedOut))
        );
        assert_eq!(drops.load(Ordering::SeqCst), 1);
        assert_eq!(timer.pending_count(), 0);
        assert_eq!(ambient_timer.pending_count(), 0);
        assert_eq!(Cx::current().unwrap().now(), ambient_timer.now());
        assert_ne!(cx.now(), ambient_timer.now());
        drop(operation);
        drop(ambient_guard);
        drop(ambient_cx);
        drop(cx);
        assert!(ambient_runtime.shutdown_timeout(Duration::from_secs(1)));
        assert!(caller_runtime.shutdown_timeout(Duration::from_secs(1)));
    }

    #[test]
    fn native_response_debug_cannot_print_reflected_authorization() {
        let response = response(
            401,
            &[
                ("DPoP-Nonce", "private-nonce"),
                ("X-Reflect", "private-token"),
            ],
            b"private-token",
        );
        let debug = format!("{response:?}");
        assert!(!debug.contains("private-token"));
        assert!(!debug.contains("private-nonce"));
        assert!(debug.contains("401"));
    }
}

// This exercises the production transport against real TLS sockets. It is
// feature-gated like the existing native OAuth integration targets; unit
// tests above are not presented as a substitute for this test.
#[cfg(all(test, feature = "native-tls-roots"))]
mod tls_tests {
    use std::task::{Context, Waker};

    use asupersync::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};
    use asupersync::net::TcpListener;
    use asupersync::runtime::{RuntimeBuilder, reactor::create_reactor};
    use asupersync::tls::{CertificateChain, PrivateKey, TlsAcceptorBuilder};
    use fastmcp_protocol::dpop::{DpopKey, DpopNonce};

    use super::*;

    // TEST ONLY: the existing oauth_managed fixture identity, valid 2020-2049.
    // The private key is public test material, never a deployment credential.
    // Inlined, not included: `*.pem` is transfer-excluded, so including it
    // makes this target unbuildable on a remote worker and a target that fails
    // to build can report `0 passed` instead of failing. Same bytes and same
    // remedy as LEAF and KEY below.
    const ROOT: &[u8] = b"-----BEGIN CERTIFICATE-----\nMIIBgzCCASmgAwIBAgICA+kwCgYIKoZIzj0EAwIwJzElMCMGA1UEAwwcRmFzdE1D\nUCBPQXV0aCBURVNUIE9OTFkgUm9vdDAeFw0yMDAxMDEwMDAwMDBaFw00OTEyMzEw\nMDAwMDBaMCcxJTAjBgNVBAMMHEZhc3RNQ1AgT0F1dGggVEVTVCBPTkxZIFJvb3Qw\nWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAAS5t2O8JZ0hNjgI38E9Ov6i6mKoDRGo\nApMsykFkvgb6Zm9/5gCZ90eIKw7aWgK6iNs7lbtVY9mysZBIqm6pKQO2o0UwQzAS\nBgNVHRMBAf8ECDAGAQH/AgEAMA4GA1UdDwEB/wQEAwIBhjAdBgNVHQ4EFgQU6QNI\nrmvMiLoV3jIoCyohXARwI8gwCgYIKoZIzj0EAwIDSAAwRQIgCKOrW3vhzUJ2EyuY\nvQUTdqGFhy0zEHj4ITFLvXPz1X8CIQCLKD4EKCvS/zkBSu/6uee1WV9d97UpK3yW\nX/aCEJ5+hA==\n-----END CERTIFICATE-----\n";
    const LEAF: &[u8] = b"-----BEGIN CERTIFICATE-----\nMIIBjjCCATSgAwIBAgICA+owCgYIKoZIzj0EAwIwJzElMCMGA1UEAwwcRmFzdE1D\nUCBPQXV0aCBURVNUIE9OTFkgUm9vdDAeFw0yMDAxMDEwMDAwMDBaFw00OTEyMzEw\nMDAwMDBaMBQxEjAQBgNVBAMMCWxvY2FsaG9zdDBZMBMGByqGSM49AgEGCCqGSM49\nAwEHA0IABPPKylLna9VpWAlpshHBhSsQHNOv3BaEGX4HSBhHiBVel0ce+qfHF15O\n0T63Zlp7TtxlMdEY+rPpgioSFDQVadijYzBhMAwGA1UdEwEB/wQCMAAwLAYDVR0R\nBCUwI4IJbG9jYWxob3N0hwR/AAABhxAAAAAAAAAAAAAAAAAAAAABMBMGA1UdJQQM\nMAoGCCsGAQUFBwMBMA4GA1UdDwEB/wQEAwIHgDAKBggqhkjOPQQDAgNIADBFAiEA\n6qrAr2qp/t6K62T9Et2mUU/zfd4kJb+ekyoAim1yTFcCICb6SdVY2fg15/SXf0vE\nIvYelqtTk8FQInCEcIxvfF3m\n-----END CERTIFICATE-----\n";
    const KEY: &[u8] = b"-----BEGIN PRIVATE KEY-----\nMIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgcCe44IBKhbw+D/s7\nBjDHOOV0g+EoxFno7VJGKhJeer2hRANCAATzyspS52vVaVgJabIRwYUrEBzTr9wW\nhBl+B0gYR4gVXpdHHvqnxxdeTtE+t2Zae07cZTHRGPqz6YIqEhQ0FWnY\n-----END PRIVATE KEY-----\n";

    async fn pair<L: Future, R: Future>(left: L, right: R) -> (L::Output, R::Output) {
        let mut left = pin!(left);
        let mut right = pin!(right);
        let mut l = None;
        let mut r = None;
        poll_fn(|task| {
            if l.is_none() {
                if let Poll::Ready(result) = left.as_mut().poll(task) {
                    l = Some(result);
                }
            }
            if r.is_none() {
                if let Poll::Ready(result) = right.as_mut().poll(task) {
                    r = Some(result);
                }
            }
            if l.is_some() && r.is_some() {
                Poll::Ready((l.take().unwrap(), r.take().unwrap()))
            } else {
                Poll::Pending
            }
        })
        .await
    }

    async fn read_request<IO: AsyncRead + Unpin>(io: &mut IO) -> (String, Vec<u8>) {
        let mut wire = Vec::new();
        let mut buffer = [0; 2048];
        let end = loop {
            let count = io.read(&mut buffer).await.unwrap();
            assert!(count > 0 && wire.len() + count <= 32 * 1024);
            wire.extend_from_slice(&buffer[..count]);
            if let Some(index) = wire.windows(4).position(|bytes| bytes == b"\r\n\r\n") {
                break index + 4;
            }
        };
        let head = std::str::from_utf8(&wire[..end]).unwrap().to_owned();
        let length = head
            .lines()
            .find_map(|line| {
                let (name, value) = line.split_once(':')?;
                name.eq_ignore_ascii_case("content-length")
                    .then(|| value.trim().parse::<usize>().unwrap())
            })
            .unwrap();
        assert!(end + length <= 32 * 1024);
        while wire.len() < end + length {
            let count = io.read(&mut buffer).await.unwrap();
            assert!(count > 0 && wire.len() + count <= 32 * 1024);
            wire.extend_from_slice(&buffer[..count]);
        }
        assert_eq!(wire.len(), end + length);
        (head, wire[end..].to_vec())
    }

    #[test]
    fn native_https_typed_calls_correlate_results_and_leave_continuations_to_the_host() {
        use super::core::DpopCoreError;
        use crate::http_auth::rpc::{ManagedCoreError, ManagedCoreLimits};
        use fastmcp_protocol::protocol_policy::ProtocolEra;
        use fastmcp_protocol::{
            ClientCapabilities, CoreRequest, CoreResult, FinalCoreResult, FinalRequestMeta,
            RequestId,
        };

        RuntimeBuilder::current_thread()
            .with_reactor(create_reactor().unwrap())
            .build().unwrap().block_on(async {
                let cx = Cx::current().unwrap();
                let deadline = cx.now().saturating_add_nanos(20_000_000_000);
                asupersync::time::timeout_at(deadline, async {
                    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
                    let address = listener.local_addr().unwrap();
                    let target = CanonicalHttpUrl::parse(&format!("https://{address}/mcp")).unwrap();
                    let session = DpopSession::new(
                        DpopKey::generate().unwrap(),
                        CanonicalHttpUrl::parse("https://issuer.example/token").unwrap(),
                        target.clone(),
                    ).unwrap();
                    let credential = session.admit_token_response(
                        &session.token_endpoint, 200,
                        br#"{"access_token":"typed-token","token_type":"DPoP","expires_in":60}"#,
                        Instant::now(), Duration::from_secs(60),
                    ).unwrap();
                    let root = Certificate::from_pem(ROOT).unwrap().remove(0);
                    let policy = DpopHttpPolicy::default()
                        .with_resource_root_der(root.as_der().to_vec()).unwrap();
                    let mut client = DpopHttpClient::new(session, policy).unwrap();
                    let acceptor = TlsAcceptorBuilder::new(
                        CertificateChain::from_pem(LEAF).unwrap(),
                        PrivateKey::from_pem(KEY).unwrap(),
                    ).alpn_protocols(vec![b"http/1.1".to_vec()]).build().unwrap();
                    let server = async {
                        let mut proofs = Vec::new();
                        for (status, body) in [
                            (200, r#"{"jsonrpc":"2.0","id":7,"result":{"resultType":"complete","tools":[],"ttlMs":0,"cacheScope":"private"}}"#),
                            (200, r#"{"jsonrpc":"2.0","id":8,"result":{"resultType":"complete","tools":[],"ttlMs":0,"cacheScope":"private"}}"#),
                            (200, r#"{"jsonrpc":"2.0","id":7,"result":{"resultType":"input_required","inputRequests":{"roots":{"method":"roots/list"}},"requestState":"opaque-state"}}"#),
                            (401, r#"{"error":"use_dpop_nonce","secret":"must-not-enter-diagnostics"}"#),
                        ] {
                            let (socket, _) = listener.accept().await.unwrap();
                            let mut socket = acceptor.accept(socket).await.unwrap();
                            let (head, payload) = read_request(&mut socket).await;
                            let payload: serde_json::Value = serde_json::from_slice(&payload).unwrap();
                            assert_eq!(payload["id"], 7);
                            assert_eq!(payload["params"]["_meta"]["io.modelcontextprotocol/protocolVersion"], fastmcp_protocol::FINAL_PROTOCOL_VERSION);
                            let headers: Vec<_> = head.lines().filter_map(|line| line.split_once(':'))
                                .map(|(name, value)| (name.to_ascii_lowercase(), value.trim().to_owned()))
                                .collect();
                            assert!(headers.iter().any(|(name, value)| name == "authorization" && value == "DPoP typed-token"));
                            assert!(headers.iter().any(|(name, value)| name == "mcp-method" && Some(value.as_str()) == payload["method"].as_str()));
                            let proof = headers.iter().find(|(name, _)| name == "dpop").unwrap().1.clone();
                            assert!(!proofs.contains(&proof));
                            proofs.push(proof);
                            let response = format!(
                                "HTTP/1.1 {status} Fixture\r\nContent-Type: application/json\r\nContent-Length: {}\r\nDPoP-Nonce: typed-nonce\r\nConnection: close\r\n\r\n{body}",
                                body.len()
                            );
                            socket.write_all(response.as_bytes()).await.unwrap();
                            socket.shutdown().await.unwrap();
                        }
                        proofs
                    };
                    let request = |method: &str, mut params: serde_json::Value| {
                        params["_meta"] = serde_json::to_value(
                            FinalRequestMeta::new(ClientCapabilities::default())
                        ).unwrap();
                        CoreRequest::decode(ProtocolEra::Modern2026, method, Some(&params)).unwrap()
                    };
                    let application = async {
                        let result = client.request_core(
                            &cx, &credential, request("tools/list", serde_json::json!({})),
                            RequestId::Number(7), ManagedCoreLimits::default(),
                        ).await.unwrap();
                        assert!(result.encode().unwrap().contains("\"tools\":[]"));
                        assert!(matches!(
                            client.request_core(
                                &cx, &credential, request("tools/list", serde_json::json!({})),
                                RequestId::Number(7), ManagedCoreLimits::default(),
                            ).await,
                            Err(DpopCoreError::Protocol(ManagedCoreError::ResponseIdMismatch))
                        ));
                        let result = client.request_core(
                            &cx, &credential, request("resources/read", serde_json::json!({"uri":"file:///sample"})),
                            RequestId::Number(7), ManagedCoreLimits::default(),
                        ).await.unwrap();
                        assert!(matches!(result, CoreResult::Final(FinalCoreResult::ResourcesReadInputRequired { .. })));
                        assert!(matches!(
                            client.request_core(
                                &cx, &credential, request("tools/list", serde_json::json!({})),
                                RequestId::Number(7), ManagedCoreLimits::default(),
                            ).await,
                            Err(DpopCoreError::Protocol(ManagedCoreError::HttpStatus { status: 401 }))
                        ));
                        assert_eq!(client.session.resource_nonce, Some(DpopNonce::new("typed-nonce").unwrap()));
                        assert!(client.session.token_nonce.is_none());
                    };
                    let (proofs, ()) = pair(server, application).await;
                    assert_eq!(proofs.len(), 4);
                    assert!(listener.poll_accept(&mut Context::from_waker(Waker::noop())).is_pending());
                }).await.expect("typed DPoP calls must settle without hidden continuations");
            });
    }

    #[test]
    fn native_https_posts_use_fresh_proofs_and_do_not_replay_challenges_or_redirects() {
        RuntimeBuilder::current_thread()
            .with_reactor(create_reactor().unwrap())
            .build().unwrap().block_on(async {
                let cx = Cx::current().unwrap();
                let deadline = cx.now().saturating_add_nanos(20_000_000_000);
                asupersync::time::timeout_at(deadline, async {
                    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
                    let address = listener.local_addr().unwrap();
                    let target = CanonicalHttpUrl::parse(&format!("https://{address}/mcp?tenant=one")).unwrap();
                    let session = DpopSession::new(
                        DpopKey::generate().unwrap(),
                        CanonicalHttpUrl::parse("https://issuer.example/token").unwrap(),
                        target.clone(),
                    ).unwrap();
                    let credential = session.admit_token_response(
                        &session.token_endpoint, 200,
                        br#"{"access_token":"socket-token","token_type":"DPoP","expires_in":60}"#,
                        Instant::now(), Duration::from_secs(60),
                    ).unwrap();
                    let root = Certificate::from_pem(ROOT).unwrap().remove(0);
                    let policy = DpopHttpPolicy::default()
                        .with_resource_root_der(root.as_der().to_vec()).unwrap();
                    let mut client = DpopHttpClient::new(session, policy).unwrap();
                    let cancellation = McpRequestCancellation::new();
                    let body = br#"{"jsonrpc":"2.0","id":1,"method":"ping"}"#.to_vec();
                    let request = ModernHttpRequest::new(
                        target.as_str(), body.clone(), fastmcp_protocol::FINAL_PROTOCOL_VERSION,
                        "ping", None,
                    ).unwrap();
                    let wrong_target = ModernHttpRequest::new(
                        format!("https://{address}/mcp?tenant=two"), body.clone(),
                        fastmcp_protocol::FINAL_PROTOCOL_VERSION, "ping", None,
                    ).unwrap();
                    assert!(matches!(
                        client.post_resource(&cx, &cancellation, &credential, &wrong_target).await,
                        Err(DpopHttpError::Authorization(DpopClientError::EndpointMismatch))
                    ));
                    assert!(listener.poll_accept(&mut Context::from_waker(Waker::noop())).is_pending());
                    let acceptor = TlsAcceptorBuilder::new(
                        CertificateChain::from_pem(LEAF).unwrap(),
                        PrivateKey::from_pem(KEY).unwrap(),
                    ).alpn_protocols(vec![b"http/1.1".to_vec()]).build().unwrap();
                    let server = async {
                        let mut proofs = Vec::new();
                        for (status, nonce) in [(401, "first"), (200, "second"), (307, "third")] {
                            let (socket, _) = listener.accept().await.unwrap();
                            let mut socket = acceptor.accept(socket).await.unwrap();
                            let (head, actual_body) = read_request(&mut socket).await;
                            assert!(head.starts_with("POST /mcp?tenant=one HTTP/1.1\r\n"));
                            assert_eq!(actual_body, body);
                            let headers: Vec<_> = head.lines().filter_map(|line| line.split_once(':'))
                                .map(|(name, value)| (name.to_ascii_lowercase(), value.trim().to_owned()))
                                .collect();
                            assert_eq!(headers.iter().filter(|(name, _)| name == "authorization").count(), 1);
                            assert!(headers.iter().any(|(name, value)| name == "authorization" && value == "DPoP socket-token"));
                            assert!(headers.iter().any(|(name, value)| name == "accept" && value == "application/json"));
                            assert_eq!(headers.iter().filter(|(name, _)| name == "dpop").count(), 1);
                            let proof = headers.iter().find(|(name, _)| name == "dpop").unwrap().1.clone();
                            assert!(!proofs.contains(&proof), "an explicit second call reused a proof");
                            proofs.push(proof);
                            let reply = format!(
                                "HTTP/1.1 {status} Fixture\r\nContent-Type: application/json\r\nContent-Length: 2\r\nDPoP-Nonce: {nonce}\r\nLocation: https://{address}/must-not-follow\r\nConnection: close\r\n\r\n{{}}"
                            );
                            socket.write_all(reply.as_bytes()).await.unwrap();
                            socket.shutdown().await.unwrap();
                        }
                        proofs
                    };
                    let application = async {
                        for (status, nonce) in [(401, "first"), (200, "second"), (307, "third")] {
                            let response = client.post_resource(&cx, &cancellation, &credential, &request).await.unwrap();
                            assert_eq!(response.status(), status);
                            assert_eq!(response.body(), b"{}");
                            assert_eq!(client.session.resource_nonce, Some(DpopNonce::new(nonce).unwrap()));
                            assert!(client.session.token_nonce.is_none());
                        }
                    };
                    let (proofs, ()) = pair(server, application).await;
                    assert_eq!(proofs.len(), 3);
                    credential.revoke();
                    assert!(matches!(
                        client.post_resource(&cx, &cancellation, &credential, &request).await,
                        Err(DpopHttpError::Authorization(DpopClientError::CredentialUnavailable))
                    ));
                    assert!(listener.poll_accept(&mut Context::from_waker(Waker::noop())).is_pending());
                }).await.expect("the native DPoP TLS fixture must settle");
            });
    }
}
