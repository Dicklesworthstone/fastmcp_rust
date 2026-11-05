//! Native HTTP admission through request-owned asynchronous authentication.

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::task::{Context, Poll, Waker};
use std::time::{Duration, Instant};

use asupersync::{Budget, Cx, types::Time};
use fastmcp_core::{AuthContext, McpContext, McpError, McpErrorCode, McpResult};
use fastmcp_protocol::protocol_policy::ProtocolPolicy;
use fastmcp_protocol::{Content, JsonRpcRequest, JsonRpcResponse, RequestId, Tool};
use fastmcp_transport::http::{HttpMethod, HttpRequest, HttpResponse, HttpStatus};
use serde_json::{Value, json};

use crate::auth::{AUTH_PROVIDER_UNAVAILABLE_CODE, AuthFuture};
use crate::handler::ToolHandler;
use crate::{
    AuthProvider, AuthRequest, InboundRequestContext, InboundRequestTransport, Server,
    ServerHttpEndpoint, ServerHttpEndpointResponse, TransportAuthorization,
};

const TOKEN: &str = "native-async-secret-canary";
const PRIVATE_ERROR: &str = "provider-private-diagnostic-canary";

#[derive(Clone, Copy)]
enum Behavior {
    YieldSuccess,
    Pending,
    ConstructionPanic,
    PollPanic,
    Unavailable,
    Denied,
    CancelReady,
    ExpiredReady,
}

#[derive(Clone)]
struct Provider {
    behavior: Behavior,
    calls: Arc<AtomicUsize>,
    polls: Arc<AtomicUsize>,
    drops: Arc<AtomicUsize>,
    valid_until: Option<Instant>,
}

impl Provider {
    fn new(behavior: Behavior) -> Self {
        Self {
            behavior,
            calls: Arc::new(AtomicUsize::new(0)),
            polls: Arc::new(AtomicUsize::new(0)),
            drops: Arc::new(AtomicUsize::new(0)),
            valid_until: None,
        }
    }
}

impl AuthProvider for Provider {
    fn authenticate(&self, _: &McpContext, _: AuthRequest<'_>) -> McpResult<AuthContext> {
        panic!("native async admission must not invoke synchronous authentication");
    }

    fn authenticate_async<'a>(
        &'a self,
        ctx: &'a McpContext,
        request: AuthRequest<'a>,
    ) -> AuthFuture<'a> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        assert_eq!(request.access_token().unwrap().token, TOKEN);
        assert!(ctx.auth().is_none(), "provider facts start isolated");
        if matches!(self.behavior, Behavior::ConstructionPanic) {
            panic!("{PRIVATE_ERROR}");
        }
        Box::pin(ProviderFuture {
            provider: self,
            context: ctx,
            yielded: false,
        })
    }
}

struct ProviderFuture<'a> {
    provider: &'a Provider,
    context: &'a McpContext,
    yielded: bool,
}

impl Future for ProviderFuture<'_> {
    type Output = McpResult<AuthContext>;

    fn poll(self: Pin<&mut Self>, task: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.get_mut();
        this.provider.polls.fetch_add(1, Ordering::SeqCst);
        match this.provider.behavior {
            Behavior::YieldSuccess if !this.yielded => {
                this.yielded = true;
                task.waker().wake_by_ref();
                return Poll::Pending;
            }
            Behavior::Pending => return Poll::Pending,
            Behavior::PollPanic => panic!("{PRIVATE_ERROR}"),
            Behavior::Unavailable => {
                return Poll::Ready(Err(McpError::new(
                    AUTH_PROVIDER_UNAVAILABLE_CODE,
                    PRIVATE_ERROR,
                )));
            }
            Behavior::Denied => {
                return Poll::Ready(Err(McpError::new(
                    McpErrorCode::ResourceForbidden,
                    PRIVATE_ERROR,
                )));
            }
            _ => {}
        }
        // Even a provider that mutates its isolated staging context cannot
        // substitute those facts for the explicit verified return value.
        assert!(
            this.context
                .set_auth(AuthContext::with_subject("uncommitted-canary"))
        );
        let mut facts = AuthContext::with_subject("async-owner");
        facts.scopes = vec!["read".to_owned()];
        if let Some(deadline) = this.provider.valid_until {
            facts = facts.with_verification_valid_until(deadline);
        }
        if matches!(this.provider.behavior, Behavior::ExpiredReady) {
            facts = facts.with_verification_valid_until(Instant::now());
        }
        if matches!(this.provider.behavior, Behavior::CancelReady) {
            this.context.request_cancellation().cancel();
        }
        Poll::Ready(Ok(facts))
    }
}

impl Drop for ProviderFuture<'_> {
    fn drop(&mut self) {
        self.provider.drops.fetch_add(1, Ordering::SeqCst);
    }
}

struct AuthenticatedTool(Arc<AtomicUsize>);

impl ToolHandler for AuthenticatedTool {
    fn definition(&self) -> Tool {
        Tool {
            name: "async_auth_probe".to_owned(),
            description: None,
            input_schema: json!({"type":"object"}),
            output_schema: None,
            icon: None,
            version: None,
            tags: Vec::new(),
            annotations: None,
        }
    }

    fn call(&self, context: &McpContext, _: Value) -> McpResult<Vec<Content>> {
        context.checkpoint()?;
        let auth = context
            .auth()
            .expect("native admission committed verified facts");
        assert_eq!(auth.subject.as_deref(), Some("async-owner"));
        assert_eq!(auth.scopes, vec!["read"]);
        self.0.fetch_add(1, Ordering::SeqCst);
        Ok(vec![Content::text("authenticated asynchronously")])
    }
}

fn server(provider: impl AuthProvider + 'static, calls: &Arc<AtomicUsize>) -> Server {
    Server::new("native-async-auth", "1")
        .protocol_policy(ProtocolPolicy::ModernOnly)
        .unwrap()
        .request_timeout(0)
        .auth_provider(provider)
        .tool(AuthenticatedTool(Arc::clone(calls)))
        .build()
}

fn endpoint(server: Server) -> ServerHttpEndpoint {
    #[cfg(feature = "legacy-2024-11-05")]
    return server.into_http_endpoint("http://127.0.0.1:31337").unwrap();
    #[cfg(not(feature = "legacy-2024-11-05"))]
    return server.into_http_endpoint().unwrap();
}

fn rpc() -> JsonRpcRequest {
    JsonRpcRequest::new(
        "tools/call",
        Some(json!({
            "name":"async_auth_probe", "arguments":{},
            "_meta":{
                "io.modelcontextprotocol/protocolVersion":fastmcp_protocol::FINAL_PROTOCOL_VERSION,
                "io.modelcontextprotocol/clientCapabilities":{}
            }
        })),
        RequestId::Number(7),
    )
}

fn request() -> HttpRequest {
    HttpRequest::new(HttpMethod::Post, "/mcp")
        .with_header("content-type", "application/json")
        .with_header("accept", "application/json")
        .with_header(
            "mcp-protocol-version",
            fastmcp_protocol::FINAL_PROTOCOL_VERSION,
        )
        .with_header("mcp-method", "tools/call")
        .with_header("mcp-name", "async_auth_probe")
        .with_header("authorization", format!("Bearer {TOKEN}"))
        .with_body(serde_json::to_vec(&rpc()).unwrap())
}

fn authorization() -> TransportAuthorization {
    TransportAuthorization::from_singleton_header(Some(&format!("Bearer {TOKEN}")))
}

fn run<F, Fut>(scenario: F)
where
    F: FnOnce(Cx) -> Fut + Send + 'static,
    Fut: Future<Output = ()> + Send + 'static,
{
    asupersync::runtime::RuntimeBuilder::current_thread()
        .with_reactor(asupersync::runtime::reactor::create_reactor().unwrap())
        .blocking_threads(1, 4)
        .build()
        .unwrap()
        .block_on(async move {
            let cx = Cx::current().unwrap();
            let mut task = cx.spawn(scenario).unwrap();
            task.join(&cx).await.unwrap();
        });
}

async fn call(cx: &Cx, endpoint: &ServerHttpEndpoint, request: HttpRequest) -> HttpResponse {
    let mut session = endpoint.open_session(cx).unwrap();
    let response = asupersync::time::timeout(
        cx.now(),
        Duration::from_secs(5),
        Box::pin(session.handle_async(cx, request)),
    )
    .await
    .expect("native authentication must settle before the test watchdog")
    .unwrap();
    session.close(cx).await;
    let ServerHttpEndpointResponse::Immediate(response) = response else {
        panic!("ordinary tool call must produce an immediate JSON response");
    };
    response
}

fn assert_sanitized(response: &HttpResponse) {
    let body = String::from_utf8_lossy(&response.body);
    let headers = format!("{:?}", response.headers);
    for canary in [TOKEN, PRIVATE_ERROR, "uncommitted-canary"] {
        assert!(!body.contains(canary));
        assert!(!headers.contains(canary));
    }
}

#[test]
fn native_http_async_auth_yields_then_dispatches_once_without_sync_fallback() {
    run(|cx| async move {
        let provider = Provider::new(Behavior::YieldSuccess);
        let calls = Arc::new(AtomicUsize::new(0));
        let endpoint = endpoint(server(provider.clone(), &calls));
        let response = call(&cx, &endpoint, request()).await;
        assert_eq!(response.status, HttpStatus::OK);
        let rpc: JsonRpcResponse = serde_json::from_slice(&response.body).unwrap();
        assert!(rpc.error.is_none());
        assert_eq!(rpc.id, Some(RequestId::Number(7)));
        assert_eq!(provider.calls.load(Ordering::SeqCst), 1);
        assert_eq!(provider.polls.load(Ordering::SeqCst), 2);
        assert_eq!(provider.drops.load(Ordering::SeqCst), 1);
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        assert!(cx.checkpoint().is_ok());
        assert_sanitized(&response);
    });
}

#[test]
fn native_http_async_auth_rejects_missing_and_inband_credentials_before_provider() {
    run(|cx| async move {
        let provider = Provider::new(Behavior::YieldSuccess);
        let calls = Arc::new(AtomicUsize::new(0));
        let endpoint = endpoint(server(provider.clone(), &calls));
        for in_band in [false, true] {
            let mut request = request();
            if in_band {
                let mut value = rpc();
                value.params.as_mut().unwrap()["_meta"]["authorization"] =
                    json!(format!("Bearer {TOKEN}"));
                request.body = serde_json::to_vec(&value).unwrap();
            } else {
                request.headers.remove("authorization");
            }
            let response = call(&cx, &endpoint, request).await;
            assert_eq!(response.status, HttpStatus::UNAUTHORIZED);
            assert_sanitized(&response);
        }
        assert_eq!(provider.calls.load(Ordering::SeqCst), 0);
        assert_eq!(provider.polls.load(Ordering::SeqCst), 0);
        assert_eq!(calls.load(Ordering::SeqCst), 0);
    });
}

#[test]
fn native_http_async_auth_panic_denial_and_unavailability_are_sanitized() {
    run(|cx| async move {
        for behavior in [
            Behavior::ConstructionPanic,
            Behavior::PollPanic,
            Behavior::Denied,
            Behavior::Unavailable,
        ] {
            let provider = Provider::new(behavior);
            let calls = Arc::new(AtomicUsize::new(0));
            let endpoint = endpoint(server(provider.clone(), &calls));
            let response = call(&cx, &endpoint, request()).await;
            assert_eq!(
                response.status,
                if matches!(behavior, Behavior::Unavailable) {
                    HttpStatus::SERVICE_UNAVAILABLE
                } else {
                    HttpStatus::UNAUTHORIZED
                }
            );
            assert_eq!(provider.calls.load(Ordering::SeqCst), 1);
            assert_eq!(calls.load(Ordering::SeqCst), 0);
            assert_sanitized(&response);
            if matches!(behavior, Behavior::Unavailable) {
                assert_eq!(
                    response.headers.get("retry-after").map(String::as_str),
                    Some("1")
                );
                assert_eq!(
                    response.headers.get("cache-control").map(String::as_str),
                    Some("no-store")
                );
            }
        }
        assert!(cx.checkpoint().is_ok());
    });
}

#[test]
fn native_http_async_auth_ready_cancellation_and_expired_verdict_never_dispatch() {
    run(|cx| async move {
        for behavior in [Behavior::CancelReady, Behavior::ExpiredReady] {
            let provider = Provider::new(behavior);
            let calls = Arc::new(AtomicUsize::new(0));
            let endpoint = endpoint(server(provider.clone(), &calls));
            let response = call(&cx, &endpoint, request()).await;
            assert_eq!(
                response.status,
                if matches!(behavior, Behavior::CancelReady) {
                    HttpStatus::SERVICE_UNAVAILABLE
                } else {
                    HttpStatus::UNAUTHORIZED
                }
            );
            assert_eq!(calls.load(Ordering::SeqCst), 0);
            assert_eq!(provider.calls.load(Ordering::SeqCst), 1);
            assert_eq!(provider.drops.load(Ordering::SeqCst), 1);
            assert!(
                cx.checkpoint().is_ok(),
                "request cancellation does not cancel its caller"
            );
            assert_sanitized(&response);
        }
    });
}

#[test]
fn native_async_auth_silent_provider_obeys_deadline_cancellation_and_abandonment() {
    struct WakeCount(AtomicUsize);
    impl std::task::Wake for WakeCount {
        fn wake(self: Arc<Self>) {
            self.0.fetch_add(1, Ordering::SeqCst);
        }

        fn wake_by_ref(self: &Arc<Self>) {
            self.0.fetch_add(1, Ordering::SeqCst);
        }
    }

    for ending in [
        "caller-deadline",
        "hard-ceiling",
        "cancel",
        "request-cancel",
        "drop",
    ] {
        let clock = Arc::new(asupersync::time::VirtualClock::new());
        let runtime = asupersync::runtime::RuntimeBuilder::current_thread()
            .blocking_threads(0, 0)
            .with_timer_driver(asupersync::time::TimerDriverHandle::with_virtual_clock(
                Arc::clone(&clock),
            ))
            .build()
            .unwrap();
        let budget = if ending == "caller-deadline" {
            Budget::INFINITE.with_deadline(Time::from_nanos(10_000_000))
        } else {
            Budget::INFINITE
        };
        let cx = runtime.request_cx_with_budget(budget);
        let provider = Provider::new(Behavior::Pending);
        let calls = Arc::new(AtomicUsize::new(0));
        let endpoint = endpoint(server(provider.clone(), &calls));
        let mut session = endpoint.open_session(&cx).unwrap();
        let cancellation = fastmcp_core::McpRequestCancellation::new();
        let mut pending = Box::pin(session.handle_with_modern_request_cancellation_async(
            &cx,
            request(),
            Some(cancellation.clone()),
            false,
            None,
        ));
        let wakes = Arc::new(WakeCount(AtomicUsize::new(0)));
        let waker = Waker::from(Arc::clone(&wakes));
        assert!(
            pending
                .as_mut()
                .poll(&mut Context::from_waker(&waker))
                .is_pending()
        );
        assert_eq!(provider.calls.load(Ordering::SeqCst), 1);
        assert_eq!(provider.polls.load(Ordering::SeqCst), 1);
        let wakes_before = wakes.0.load(Ordering::SeqCst);
        match ending {
            "caller-deadline" => {
                clock.advance_to(Time::from_nanos(10_000_000));
            }
            "hard-ceiling" => {
                clock.advance_to(Time::from_nanos(30_000_000_000));
            }
            "cancel" => {
                cx.set_cancel_requested(true);
            }
            "request-cancel" => {
                assert!(cancellation.cancel());
                assert!(wakes.0.load(Ordering::SeqCst) > wakes_before);
                assert!(
                    cx.checkpoint().is_ok(),
                    "request cancellation leaves the caller live"
                );
            }
            _ => {}
        }
        if ending != "drop" {
            let Poll::Ready(Ok(ServerHttpEndpointResponse::Immediate(response))) =
                pending.as_mut().poll(&mut Context::from_waker(&waker))
            else {
                panic!("silent authentication must settle at its owning boundary");
            };
            assert_eq!(response.status, HttpStatus::SERVICE_UNAVAILABLE);
            assert_sanitized(&response);
        }
        drop(pending);
        assert_eq!(provider.drops.load(Ordering::SeqCst), 1);
        assert_eq!(
            provider.polls.load(Ordering::SeqCst),
            1,
            "no application re-poll after expiry or cancellation"
        );
        assert_eq!(calls.load(Ordering::SeqCst), 0);
        assert!(
            session.selected_era.is_none(),
            "failed authentication cannot pin a public session era"
        );
        let sibling = runtime.request_cx_with_budget(Budget::INFINITE);
        assert!(sibling.checkpoint().is_ok());
        drop(session);
        assert!(runtime.shutdown_timeout(Duration::from_secs(2)));
    }
}

#[test]
fn native_async_auth_receipt_expiry_prevents_commit_without_mutating_context() {
    run(|cx| async move {
        let mut provider = Provider::new(Behavior::YieldSuccess);
        let deadline = Instant::now() + Duration::from_millis(250);
        provider.valid_until = Some(deadline);
        let calls = Arc::new(AtomicUsize::new(0));
        let server = server(provider.clone(), &calls);
        let request = rpc();
        let authorization = authorization();
        let receipt = server
            .preauthenticate_http_request_async(&cx, &request, &authorization)
            .await
            .unwrap();
        let inbound = InboundRequestContext::new(cx.clone(), 7, InboundRequestTransport::Http);
        let (fresh, _fresh_lease) = McpContext::new(cx.clone(), 7)
            .begin_request_scope()
            .unwrap();
        let mut admitted = request.clone();
        receipt.commit(&fresh, &inbound, &mut admitted).unwrap();
        assert_eq!(
            fresh.auth().unwrap().subject.as_deref(),
            Some("async-owner")
        );
        asupersync::time::sleep(
            cx.now(),
            deadline.saturating_duration_since(Instant::now()) + Duration::from_millis(1),
        )
        .await;
        let (expired, _expired_lease) = McpContext::new(cx.clone(), 7)
            .begin_request_scope()
            .unwrap();
        let mut refused = request.clone();
        let before = serde_json::to_vec(&refused).unwrap();
        let error = receipt
            .commit(&expired, &inbound, &mut refused)
            .unwrap_err();
        assert_eq!(error.code, McpErrorCode::ResourceForbidden);
        assert!(expired.auth().is_none());
        assert_eq!(serde_json::to_vec(&refused).unwrap(), before);
        assert_eq!(provider.calls.load(Ordering::SeqCst), 1);
        assert_eq!(calls.load(Ordering::SeqCst), 0);
    });
}

#[test]
fn auth_verification_deadline_tightens_clones_and_never_serializes_as_authority() {
    let now = Instant::now();
    let early = now + Duration::from_secs(1);
    let late = now + Duration::from_secs(2);
    let facts = AuthContext::with_subject("verified")
        .with_verification_valid_until(late)
        .with_verification_valid_until(early)
        .with_verification_valid_until(late);
    assert_eq!(facts.verification_valid_until(), Some(early));
    assert_eq!(facts.clone().verification_valid_until(), Some(early));
    let without_deadline = AuthContext::with_subject("verified");
    assert_eq!(
        crate::auth::principal_fingerprint(Some(&facts)).unwrap(),
        crate::auth::principal_fingerprint(Some(&without_deadline)).unwrap()
    );
    let encoded = serde_json::to_value(&facts).unwrap();
    assert_eq!(encoded, json!({"subject":"verified"}));
    let restored: AuthContext = serde_json::from_value(encoded).unwrap();
    assert!(restored.verification_valid_until().is_none());
    let injected: AuthContext = serde_json::from_value(json!({
        "subject":"verified", "verification_valid_until":99999999
    }))
    .unwrap();
    assert!(injected.verification_valid_until().is_none());
}

#[test]
fn native_async_auth_preserves_ambient_effect_ceiling_across_provider_polls() {
    use asupersync::cx::cap::{CapSet, CapSetRuntimeMask};
    use std::sync::Mutex;

    struct CapabilityProvider {
        observed: Arc<Mutex<Vec<(u8, bool)>>>,
        dropped: Arc<AtomicUsize>,
    }

    struct CapabilityFuture {
        observed: Arc<Mutex<Vec<(u8, bool)>>>,
        dropped: Arc<AtomicUsize>,
    }

    impl AuthProvider for CapabilityProvider {
        fn authenticate(&self, _: &McpContext, _: AuthRequest<'_>) -> McpResult<AuthContext> {
            panic!("native capability admission must use asynchronous authentication");
        }

        fn authenticate_async<'a>(
            &'a self,
            _: &'a McpContext,
            _: AuthRequest<'a>,
        ) -> AuthFuture<'a> {
            Box::pin(CapabilityFuture {
                observed: Arc::clone(&self.observed),
                dropped: Arc::clone(&self.dropped),
            })
        }
    }

    impl Future for CapabilityFuture {
        type Output = McpResult<AuthContext>;

        fn poll(self: Pin<&mut Self>, task: &mut Context<'_>) -> Poll<Self::Output> {
            let active = Cx::current().expect("provider polls install their owning caller");
            let caps = active.capabilities();
            let bits = u8::from(caps.spawn)
                | (u8::from(caps.time) << 1)
                | (u8::from(caps.entropy) << 2)
                | (u8::from(caps.io) << 3)
                | (u8::from(caps.remote) << 4);
            self.observed
                .lock()
                .unwrap()
                .push((bits, active.timer_driver().is_some()));
            task.waker().wake_by_ref();
            Poll::Pending
        }
    }

    impl Drop for CapabilityFuture {
        fn drop(&mut self) {
            self.dropped.fetch_add(1, Ordering::SeqCst);
        }
    }

    const ALL: u8 = 31;
    const TIME: u8 = 2;
    let no_time = CapSet::<true, false, true, true, true>::MASK;
    for (denied, restriction) in [
        (1, CapSet::<false, true, true, true, true>::MASK),
        (TIME, no_time),
        (4, CapSet::<true, true, false, true, true>::MASK),
        (8, CapSet::<true, true, true, false, true>::MASK),
        (16, CapSet::<true, true, true, true, false>::MASK),
    ] {
        let clock = Arc::new(asupersync::time::VirtualClock::new());
        let runtime = asupersync::runtime::RuntimeBuilder::current_thread()
            .blocking_threads(0, 0)
            .with_timer_driver(asupersync::time::TimerDriverHandle::with_virtual_clock(
                clock,
            ))
            .build()
            .unwrap();
        // Retain the broad explicit caller before installing either ambient
        // form of the restriction. Selecting its drivers must not restore an
        // effect denied by the caller currently polling authentication.
        let caller = runtime.request_cx_with_budget(Budget::INFINITE);
        assert!(caller.timer_driver().is_some());
        let observed = Arc::new(Mutex::new(Vec::new()));
        let dropped = Arc::new(AtomicUsize::new(0));
        let provider = CapabilityProvider {
            observed: Arc::clone(&observed),
            dropped: Arc::clone(&dropped),
        };
        let calls = Arc::new(AtomicUsize::new(0));
        let endpoint = endpoint(server(provider, &calls));
        let mut session = endpoint.open_session(&caller).unwrap();
        let mut pending = Box::pin(session.handle_async(&caller, request()));
        let expected = ALL & !denied;
        let mut expected_polls = Vec::new();
        for retained_ambient in [false, true] {
            let ambient = if retained_ambient {
                let _current = Cx::set_current(Some(caller.clone()));
                let _restriction = Cx::push_restriction(restriction);
                Cx::current().unwrap()
            } else {
                caller.clone()
            };
            let _current = Cx::set_current(Some(ambient));
            let _restriction = (!retained_ambient).then(|| Cx::push_restriction(restriction));
            let result = pending
                .as_mut()
                .poll(&mut Context::from_waker(Waker::noop()));
            expected_polls.push((expected, denied != TIME));
            assert_eq!(*observed.lock().unwrap(), expected_polls);
            if denied == TIME {
                let Poll::Ready(Ok(ServerHttpEndpointResponse::Immediate(response))) = result
                else {
                    panic!("pending authentication without time authority must refuse immediately");
                };
                assert_eq!(response.status, HttpStatus::SERVICE_UNAVAILABLE);
                assert_sanitized(&response);
                break;
            }
            assert!(
                result.is_pending(),
                "the same provider future must survive the yield"
            );
            assert_eq!(dropped.load(Ordering::SeqCst), 0);
        }
        if denied != TIME {
            let _current = Cx::set_current(Some(caller.clone()));
            let _restriction = Cx::push_restriction(restriction.intersect(no_time));
            let Poll::Ready(Ok(ServerHttpEndpointResponse::Immediate(response))) = pending
                .as_mut()
                .poll(&mut Context::from_waker(Waker::noop()))
            else {
                panic!("a later time restriction must stop the pending authentication");
            };
            expected_polls.push((expected & !TIME, false));
            assert_eq!(*observed.lock().unwrap(), expected_polls);
            assert_eq!(response.status, HttpStatus::SERVICE_UNAVAILABLE);
            assert_sanitized(&response);
        }
        drop(pending);
        assert_eq!(dropped.load(Ordering::SeqCst), 1);
        assert_eq!(calls.load(Ordering::SeqCst), 0);
        assert!(session.selected_era.is_none());
        assert!(caller.checkpoint().is_ok());
        drop(session);
        drop(caller);
        assert!(runtime.shutdown_timeout(Duration::from_secs(2)));
    }
}

#[cfg(feature = "jwt-resource-auth")]
mod introspection {
    use super::*;
    use fastmcp_core::{
        AccessToken, CanonicalHttpUrl, CanonicalResourceId, CanonicalResourceIdPolicy,
    };
    use fastmcp_transport::http::{
        GuardedHttpFetchPolicy, GuardedHttpFetchResponse, GuardedHttpFetcher, GuardedHttpRequest,
        GuardedHttpsUrl,
    };

    use crate::TokenAuthProvider;
    use crate::providers::introspection::test_support::{
        Exchange, claims, response, with_exchange,
    };
    use crate::providers::introspection::{
        IntrospectionAdmissionPool, IntrospectionError, IntrospectionPolicy, IntrospectionVerifier,
    };
    use crate::providers::jwt_resource::{AcceptedAudienceId, AcceptedAudiencePolicy};

    const ISSUER: &str = "https://issuer.example";
    const RESOURCE: &str = "https://tools.example/mcp";

    #[derive(Clone, Copy)]
    enum Answer {
        Active,
        Inactive,
        Unavailable,
        Pending,
    }

    struct ScriptedExchange {
        answer: Answer,
        calls: AtomicUsize,
        resumed: AtomicUsize,
    }

    impl ScriptedExchange {
        fn new(answer: Answer) -> Arc<Self> {
            Arc::new(Self {
                answer,
                calls: AtomicUsize::new(0),
                resumed: AtomicUsize::new(0),
            })
        }
    }

    // Only the configured endpoint exchange is scripted. The actual verifier,
    // token provider, native HTTP admission and tool dispatch stay in the path.
    // This is a provider integration fixture, not a TLS-wire test.
    impl Exchange for ScriptedExchange {
        fn post<'a>(
            &'a self,
            _: &'a McpContext,
            _: &'a GuardedHttpsUrl,
            _: &'a GuardedHttpRequest,
        ) -> Pin<
            Box<
                dyn Future<Output = Result<GuardedHttpFetchResponse, IntrospectionError>>
                    + Send
                    + 'a,
            >,
        > {
            self.calls.fetch_add(1, Ordering::SeqCst);
            Box::pin(async move {
                asupersync::runtime::yield_now().await;
                self.resumed.fetch_add(1, Ordering::SeqCst);
                match self.answer {
                    Answer::Active => {
                        let mut document = claims();
                        document["username"] = json!(PRIVATE_ERROR);
                        document["extension"] = json!({"private": TOKEN});
                        Ok(response(&document))
                    }
                    Answer::Inactive => Ok(response(&json!({"active": false}))),
                    Answer::Unavailable => Err(IntrospectionError::EndpointUnavailable),
                    Answer::Pending => std::future::pending().await,
                }
            })
        }
    }

    fn verifier(
        exchange: Arc<ScriptedExchange>,
        pool: IntrospectionAdmissionPool,
    ) -> IntrospectionVerifier {
        let endpoint = CanonicalHttpUrl::parse(RESOURCE).unwrap();
        let configured = [fastmcp_core::uri::ConfiguredResourceEndpoint::new(
            "mcp",
            &endpoint,
            CanonicalResourceIdPolicy::DEFAULT,
        )];
        let resource =
            CanonicalResourceId::parse_for_configured_endpoints(RESOURCE, &configured).unwrap();
        let audiences = AcceptedAudiencePolicy::new(
            ISSUER,
            resource,
            "native-introspection",
            "native-deployment",
            1,
            [AcceptedAudienceId::new(RESOURCE).unwrap()],
        )
        .unwrap();
        let policy = IntrospectionPolicy::new(
            audiences,
            "https://issuer.example/introspect",
            ["read".to_owned()],
            Duration::from_secs(3600),
        )
        .unwrap();
        let fetch_policy = GuardedHttpFetchPolicy::new(
            16 * 1024,
            Duration::from_secs(2),
            Duration::from_secs(1),
            "introspection-tests",
        )
        .unwrap();
        let verifier = IntrospectionVerifier::new(
            policy,
            GuardedHttpFetcher::new(fetch_policy).unwrap(),
            "resource-server",
            asupersync::security::SecretString::from_string("endpoint-secret".to_owned()),
            pool,
        )
        .unwrap();
        with_exchange(verifier, exchange)
    }

    struct IntrospectionTool(Arc<AtomicUsize>);

    impl ToolHandler for IntrospectionTool {
        fn definition(&self) -> Tool {
            AuthenticatedTool(Arc::clone(&self.0)).definition()
        }

        fn call(&self, context: &McpContext, _: Value) -> McpResult<Vec<Content>> {
            context.checkpoint()?;
            let auth = context.auth().expect("introspection facts were committed");
            assert_eq!(auth.subject.as_deref(), Some("alice"));
            assert_eq!(auth.scopes, vec!["read"]);
            assert!(auth.session_owner().is_some());
            assert!(
                auth.verification_valid_until()
                    .is_some_and(|deadline| deadline > Instant::now())
            );
            assert_eq!(
                auth.claims,
                Some(json!({
                    "iss": ISSUER, "aud": RESOURCE, "client_id": "mcp-client",
                }))
            );
            self.0.fetch_add(1, Ordering::SeqCst);
            Ok(vec![Content::text("verified opaque credential")])
        }
    }

    fn native_endpoint(
        verifier: IntrospectionVerifier,
        calls: &Arc<AtomicUsize>,
    ) -> ServerHttpEndpoint {
        endpoint(
            Server::new("native-introspection", "1")
                .protocol_policy(ProtocolPolicy::ModernOnly)
                .unwrap()
                .request_timeout(0)
                .auth_provider(TokenAuthProvider::new(verifier))
                .tool(IntrospectionTool(Arc::clone(calls)))
                .build(),
        )
    }

    #[test]
    fn native_http_introspection_yields_and_commits_only_sanitized_live_facts() {
        run(|cx| async move {
            let exchange = ScriptedExchange::new(Answer::Active);
            let verifier = verifier(exchange.clone(), IntrospectionAdmissionPool::default());
            let calls = Arc::new(AtomicUsize::new(0));
            let endpoint = native_endpoint(verifier, &calls);
            let response = call(&cx, &endpoint, request()).await;
            assert_eq!(response.status, HttpStatus::OK);
            let rpc: JsonRpcResponse = serde_json::from_slice(&response.body).unwrap();
            assert!(rpc.error.is_none());
            assert_eq!(rpc.id, Some(RequestId::Number(7)));
            assert_eq!(exchange.calls.load(Ordering::SeqCst), 1);
            assert_eq!(exchange.resumed.load(Ordering::SeqCst), 1);
            assert_eq!(calls.load(Ordering::SeqCst), 1);
            assert_sanitized(&response);
        });
    }

    #[test]
    fn native_http_introspection_inactive_outage_and_pool_saturation_never_dispatch() {
        run(|cx| async move {
            for (answer, status) in [
                (Answer::Inactive, HttpStatus::UNAUTHORIZED),
                (Answer::Unavailable, HttpStatus::SERVICE_UNAVAILABLE),
            ] {
                let exchange = ScriptedExchange::new(answer);
                let verifier = verifier(exchange.clone(), IntrospectionAdmissionPool::default());
                let calls = Arc::new(AtomicUsize::new(0));
                let endpoint = native_endpoint(verifier, &calls);
                let response = call(&cx, &endpoint, request()).await;
                assert_eq!(response.status, status);
                assert_eq!(exchange.calls.load(Ordering::SeqCst), 1);
                assert_eq!(exchange.resumed.load(Ordering::SeqCst), 1);
                assert_eq!(calls.load(Ordering::SeqCst), 0);
                assert_sanitized(&response);
                if status == HttpStatus::SERVICE_UNAVAILABLE {
                    assert_eq!(
                        response.headers.get("retry-after").map(String::as_str),
                        Some("1")
                    );
                    assert_eq!(
                        response.headers.get("cache-control").map(String::as_str),
                        Some("no-store")
                    );
                }
            }

            let pool = IntrospectionAdmissionPool::new(1).unwrap();
            let held_exchange = ScriptedExchange::new(Answer::Pending);
            let held_verifier = verifier(held_exchange.clone(), pool.clone());
            let context = McpContext::new(cx.clone(), 1);
            let token = AccessToken::parse(&format!("Bearer {TOKEN}")).unwrap();
            let mut held = Box::pin(held_verifier.verify_access_token_async(&context, &token));
            assert!(
                held.as_mut()
                    .poll(&mut Context::from_waker(Waker::noop()))
                    .is_pending()
            );
            assert_eq!(held_exchange.calls.load(Ordering::SeqCst), 1);

            let exchange = ScriptedExchange::new(Answer::Active);
            let calls = Arc::new(AtomicUsize::new(0));
            let endpoint = native_endpoint(verifier(exchange.clone(), pool), &calls);
            let saturated = call(&cx, &endpoint, request()).await;
            assert_eq!(saturated.status, HttpStatus::SERVICE_UNAVAILABLE);
            assert_eq!(
                saturated.headers.get("retry-after").map(String::as_str),
                Some("1")
            );
            assert_eq!(
                exchange.calls.load(Ordering::SeqCst),
                0,
                "no endpoint exchange beyond the shared quota"
            );
            assert_eq!(calls.load(Ordering::SeqCst), 0);
            assert_sanitized(&saturated);

            drop(held);
            let recovered = call(&cx, &endpoint, request()).await;
            assert_eq!(recovered.status, HttpStatus::OK);
            assert_eq!(exchange.calls.load(Ordering::SeqCst), 1);
            assert_eq!(calls.load(Ordering::SeqCst), 1);
            assert!(cx.checkpoint().is_ok());
            assert_sanitized(&recovered);
        });
    }
}
