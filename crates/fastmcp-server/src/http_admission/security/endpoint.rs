//! Origin-bound embedding entry point for the shipped HTTP dispatcher.
//!
//! Security refusals, browser preflights and explicitly configured resource
//! metadata GETs complete before a server session is opened. Actual POSTs use
//! the existing authentication, authorization, strict protocol decoder and
//! dispatch path. No credential or request header is removed to evade a
//! downstream policy. The server's configured policy may be stricter.
//!
//! This is explicit embedding, not automatic installation on `serve_http`.
//! Write the returned response head, not the original head retained privately by
//! an SSE body. The SSE owner retains its session until explicit async close or
//! drop; returning a stream never drops the session that owns its dispatch.

/// Socket-to-dispatch security for the caller-owned native HTTP listener.
pub mod listener;

use std::future::{Future, poll_fn};
use std::task::Poll;

use asupersync::{Cx, channel::oneshot, time::Sleep};
use fastmcp_transport::http::{HttpRequest, HttpResponse};

use super::{CorsResponseHeaders, HttpSecurityError, HttpSecurityHead, HttpSecurityPolicy};
use crate::{ServerHttpEndpoint, ServerHttpEndpointResponse, ServerHttpSession, ServerHttpSseResponse};

/// Response bytes/head plus an optional native SSE body with its owning session.
/// An immediate response carries its buffered body; a stream carries it in the
/// second part. No polling task or queue is hidden behind this owner.
#[must_use = "write the response and asynchronously close any returned SSE owner"]
pub struct SecuredHttpEndpointResponse {
    response: HttpResponse,
    stream: Option<SecuredHttpSseResponse>,
}

impl SecuredHttpEndpointResponse {
    pub fn response(&self) -> &HttpResponse { &self.response }
    pub fn is_streaming(&self) -> bool { self.stream.is_some() }

    /// Write this head before driving the stream on the caller's Cx. Its CORS
    /// headers are authoritative; the native body's old response head is not.
    pub fn into_parts(self) -> (HttpResponse, Option<SecuredHttpSseResponse>) {
        (self.response, self.stream)
    }

    fn immediate(response: HttpResponse) -> Self { Self { response, stream: None } }
}

/// A native SSE response and the session owning its dispatch. Borrowing the
/// native stream cannot detach it from that session. Call `close` after terminal
/// delivery or peer disconnect to join dispatch tasks on the caller's runtime.
/// Drop cancels both owners but cannot synchronously join asynchronous work.
#[must_use = "close the SSE owner asynchronously after driving its response body"]
pub struct SecuredHttpSseResponse {
    // Declaration order deliberately drops the response before its session.
    stream: Option<Box<ServerHttpSseResponse>>,
    session: Option<ServerHttpSession>,
}

impl SecuredHttpSseResponse {
    /// Access the existing native body API without extracting its ownership.
    /// None means explicit close has already retired the response.
    pub fn stream(&mut self) -> Option<&mut ServerHttpSseResponse> {
        self.stream.as_deref_mut()
    }

    /// Release the body, then join its session-owned dispatch. A dropped close
    /// future still drops the local session, invoking its cancellation fallback.
    pub async fn close(&mut self, cx: &Cx) {
        self.stream = None;
        if let Some(mut session) = self.session.take() { session.close(cx).await; }
    }
}

/// Fixed diagnostics intentionally do not retain lower-layer request/peer text.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SecuredHttpEndpointError {
    PolicyRouteMismatch,
    Cancelled,
    TimedOut,
    TimerUnavailable,
    SessionUnavailable,
    DispatchFailed,
    UnexpectedLegacyStream,
}

impl std::fmt::Display for SecuredHttpEndpointError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::PolicyRouteMismatch => "HTTP security policy does not match the server route",
            Self::Cancelled => "secured HTTP dispatch cancelled",
            Self::TimedOut => "secured HTTP dispatch deadline expired",
            Self::TimerUnavailable => "secured HTTP dispatch requires the caller's deadline timer",
            Self::SessionUnavailable => "secured HTTP session could not be opened",
            Self::DispatchFailed => "secured HTTP dispatch failed",
            Self::UnexpectedLegacyStream => "modern secured HTTP dispatch produced a legacy stream",
        })
    }
}
impl std::error::Error for SecuredHttpEndpointError {}

impl ServerHttpEndpoint {
    /// Handles one stateless modern POST, browser preflight, or configured
    /// resource-metadata GET through an administrator-selected origin policy.
    /// No runtime is created. The caller's Cx deadline and cancellation span
    /// session opening and awaited dispatch.
    ///
    /// Only head/body security checks run here; JSON-RPC error construction stays
    /// in the existing dispatcher. Preflight and public metadata do not open a
    /// session, parse JSON, authenticate, run middleware or invoke a handler.
    ///
    /// The supplied policy must describe the server's configured modern path.
    /// Existing server CORS/authorization policy is still enforced and can refuse
    /// a POST even after preflight. Configure both from the same deployment policy.
    /// The returned SSE owner retains the native session and request lifetime;
    /// this opening future installs no stream runtime or reconnect policy.
    pub async fn handle_secured_async(
        &self,
        cx: &Cx,
        policy: &HttpSecurityPolicy,
        request: HttpRequest,
    ) -> Result<SecuredHttpEndpointResponse, SecuredHttpEndpointError> {
        checkpoint(cx)?;
        if self.server.configured_http_request_handler().config().base_path != policy.endpoint().path() {
            return Err(SecuredHttpEndpointError::PolicyRouteMismatch);
        }
        let prepared = prepare_request(policy, &request);
        checkpoint(cx)?;
        let cors = match prepared {
            PreparedRequest::Immediate(response) => return Ok(SecuredHttpEndpointResponse::immediate(response)),
            PreparedRequest::Post(cors) => cors,
        };
        // Transfer the session together with its response. Dropping it inside
        // this future would cancel a successfully opened modern SSE dispatch.
        let (response, mut session) = await_dispatch(cx, async {
            let mut session = self.open_session(cx).map_err(|_| SecuredHttpEndpointError::SessionUnavailable)?;
            match session.handle_async(cx, request).await {
                Ok(response) => Ok((response, session)),
                Err(_) => {
                    session.close(cx).await;
                    Err(SecuredHttpEndpointError::DispatchFailed)
                }
            }
        }).await?;
        let response = match response {
            ServerHttpEndpointResponse::Immediate(mut response) => {
                await_dispatch(cx, async { session.close(cx).await; Ok(()) }).await?;
                cors.apply_to(&mut response);
                SecuredHttpEndpointResponse::immediate(response)
            }
            ServerHttpEndpointResponse::ModernSse(stream) => {
                let mut response = stream.response().clone();
                cors.apply_to(&mut response);
                SecuredHttpEndpointResponse {
                    response,
                    stream: Some(SecuredHttpSseResponse {
                        stream: Some(Box::new(stream)), session: Some(session),
                    }),
                }
            }
            #[allow(unreachable_patterns)]
            other => {
                drop(other);
                await_dispatch(cx, async { session.close(cx).await; Ok(()) }).await?;
                return Err(SecuredHttpEndpointError::UnexpectedLegacyStream);
            }
        };
        checkpoint(cx)?;
        Ok(response)
    }
}

enum PreparedRequest {
    Immediate(HttpResponse),
    Post(CorsResponseHeaders),
}

fn prepare_request(policy: &HttpSecurityPolicy, request: &HttpRequest) -> PreparedRequest {
    // Bound before cloning the public map into the duplicate-preserving admission
    // representation. Differently-cased map keys remain distinct and are checked.
    // A wire adapter must already reject duplicates lost before this map exists.
    let limits = policy.endpoint().limits();
    let rejection = if let Err(error) = policy.admit_route(request.method.as_str(), &request.path) {
        Some(error)
    } else if policy.is_metadata_path(&request.path) && !request.query.is_empty() {
        // Public metadata has one configured resource. A query cannot select
        // another tenant, disclose a credential, or change the published data.
        Some(HttpSecurityError::EndpointMismatch)
    } else if request.headers.len() > limits.max_header_count()
        || request.headers.iter().fold(0_usize, |size, (name, value)|
            size.saturating_add(name.len()).saturating_add(value.len())) > limits.max_header_block_bytes()
    {
        Some(HttpSecurityError::HeaderLimit)
    } else { None };
    if let Some(rejection) = rejection { return PreparedRequest::Immediate(rejection.response()); }
    let headers: Vec<_> = request.headers.iter().map(|(name, value)| (name.clone(), value.clone())).collect();
    let head = match policy.admit_head(request.method.as_str(), &request.path, &headers) {
        Ok(head) => head,
        Err(error) => return PreparedRequest::Immediate(error.response()),
    };
    if let Err(error) = policy.validate_body(!matches!(&head, HttpSecurityHead::Post(_)), &headers, &request.body) {
        let mut response = error.response();
        if let HttpSecurityHead::Post(cors) = head { cors.apply_to(&mut response); }
        return PreparedRequest::Immediate(response);
    }
    match head {
        HttpSecurityHead::Preflight(response) | HttpSecurityHead::Metadata(response) => PreparedRequest::Immediate(response),
        HttpSecurityHead::Post(cors) => PreparedRequest::Post(cors),
    }
}

fn checkpoint(cx: &Cx) -> Result<(), SecuredHttpEndpointError> {
    cx.checkpoint().map_err(|_| SecuredHttpEndpointError::Cancelled)?;
    if cx.budget().deadline.is_some_and(|deadline| cx.now() >= deadline) {
        return Err(SecuredHttpEndpointError::TimedOut);
    }
    Ok(())
}

async fn await_dispatch<T>(
    cx: &Cx,
    future: impl Future<Output = Result<T, SecuredHttpEndpointError>>,
) -> Result<T, SecuredHttpEndpointError> {
    let deadline = cx.budget().deadline;
    if deadline.is_some() && cx.timer_driver().is_none() { return Err(SecuredHttpEndpointError::TimerUnavailable); }
    let mut timeout = deadline.map(|deadline| Box::pin(Sleep::new(deadline)));
    let (_sender, mut receiver) = oneshot::channel::<()>();
    let mut cancelled = std::pin::pin!(receiver.recv(cx));
    let mut future = std::pin::pin!(future);
    poll_fn(|task| {
        checkpoint(cx)?;
        let _current = Cx::set_current(Some(cx.clone()));
        if cancelled.as_mut().poll(task).is_ready() { return Poll::Ready(Err(SecuredHttpEndpointError::Cancelled)); }
        if timeout.as_mut().is_some_and(|timeout| timeout.as_mut().poll(task).is_ready()) {
            return Poll::Ready(Err(SecuredHttpEndpointError::TimedOut));
        }
        let result = future.as_mut().poll(task);
        checkpoint(cx)?;
        result
    }).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::http_admission::{HttpAdmissionLimits, HttpEndpointConfig};
    use fastmcp_transport::http::HttpMethod;

    fn policy() -> HttpSecurityPolicy {
        HttpSecurityPolicy::new(
            HttpEndpointConfig::new("/mcp", HttpAdmissionLimits::new(32, 8192, 4096).unwrap()).unwrap(),
            "https://service.example", vec!["https://app.example".to_owned()],
        ).unwrap()
    }

    #[test]
    fn buffered_preflight_is_an_immediate_response_without_a_dispatch_permit() {
        let request = HttpRequest::new(HttpMethod::Options, "/mcp")
            .with_header("host", "service.example")
            .with_header("origin", "https://app.example")
            .with_header("access-control-request-method", "POST")
            .with_header("access-control-request-headers", "mcp-method, authorization");
        let PreparedRequest::Immediate(response) = prepare_request(&policy(), &request)
            else { panic!("preflight must never dispatch") };
        assert_eq!(response.status.0, 204);
        assert!(response.body.is_empty());
        let request = request.with_body(b"not empty".to_vec());
        let PreparedRequest::Immediate(response) = prepare_request(&policy(), &request)
            else { panic!("body must not dispatch") };
        assert_eq!(response.status.0, 400);
    }

    #[test]
    fn security_refusal_precedes_json_while_json_errors_stay_with_native_dispatch() {
        let mut request = HttpRequest::new(HttpMethod::Post, "/mcp")
            .with_header("host", "service.example")
            .with_header("origin", "https://app.example")
            .with_body(b"malformed JSON".to_vec());
        assert!(matches!(prepare_request(&policy(), &request), PreparedRequest::Post(_)));
        request.headers.insert("origin".to_owned(), "https://attacker.example".to_owned());
        let PreparedRequest::Immediate(response) = prepare_request(&policy(), &request)
            else { panic!("origin must not dispatch") };
        assert_eq!(response.status.0, 403);
        assert!(!response.headers.contains_key("access-control-allow-origin"));
    }

    #[test]
    fn map_bounds_duplicate_casing_and_body_bounds_do_not_allocate_a_session() {
        let request = HttpRequest::new(HttpMethod::Post, "/mcp").with_header("host", "service.example");
        let mut duplicate = request.clone();
        duplicate.headers.insert("HOST".to_owned(), "service.example".to_owned());
        let PreparedRequest::Immediate(response) = prepare_request(&policy(), &duplicate)
            else { panic!("duplicate must not dispatch") };
        assert_eq!(response.status.0, 400);
        let oversized = request.with_body(vec![b'x'; 4097]);
        let PreparedRequest::Immediate(response) = prepare_request(&policy(), &oversized)
            else { panic!("oversized body must not dispatch") };
        assert_eq!(response.status.0, 413);
    }

    #[test]
    fn abandoning_a_polled_guard_releases_the_owned_dispatch_future() {
        use std::sync::{Arc, atomic::{AtomicBool, Ordering}};
        struct Pending(Arc<AtomicBool>);
        impl Future for Pending {
            type Output = Result<(), SecuredHttpEndpointError>;
            fn poll(self: std::pin::Pin<&mut Self>, _: &mut std::task::Context<'_>) -> Poll<Self::Output> { Poll::Pending }
        }
        impl Drop for Pending { fn drop(&mut self) { self.0.store(true, Ordering::Release); } }
        asupersync::runtime::RuntimeBuilder::current_thread()
            .with_reactor(asupersync::runtime::reactor::create_reactor().unwrap())
            .build().unwrap().block_on(async {
                let cx = Cx::current().unwrap();
                let dropped = Arc::new(AtomicBool::new(false));
                let mut waiting = Box::pin(await_dispatch(&cx, Pending(Arc::clone(&dropped))));
                poll_fn(|task| { assert!(waiting.as_mut().poll(task).is_pending()); Poll::Ready(()) }).await;
                drop(waiting);
                assert!(dropped.load(Ordering::Acquire));
                assert!(cx.checkpoint().is_ok());
            });
    }

    #[test]
    fn buffered_metadata_is_immediate_and_cannot_select_a_resource_by_query() {
        use super::super::resource_metadata::ProtectedResourceMetadata;
        let policy = policy().with_resource_metadata(ProtectedResourceMetadata::new(
            vec!["https://issuer.example".to_owned()],
        ).unwrap()).unwrap();
        let request = HttpRequest::new(HttpMethod::Get, policy.resource_metadata_path().unwrap())
            .with_header("host", "service.example");
        let PreparedRequest::Immediate(response) = prepare_request(&policy, &request)
            else { panic!("metadata must never dispatch") };
        assert_eq!(response.status.0, 200);
        assert_eq!(serde_json::from_slice::<serde_json::Value>(&response.body).unwrap()["resource"], "https://service.example/mcp");
        let mut with_query = request.clone();
        with_query.query.insert("resource".to_owned(), "https://attacker.example".to_owned());
        let PreparedRequest::Immediate(response) = prepare_request(&policy, &with_query)
            else { panic!("query must never dispatch") };
        assert_eq!(response.status.0, 404);
        let PreparedRequest::Immediate(response) = prepare_request(&policy, &request.with_body(b"x".to_vec()))
            else { panic!("body must never dispatch") };
        assert_eq!(response.status.0, 400);
    }
}
