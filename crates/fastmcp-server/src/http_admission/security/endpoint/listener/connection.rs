//! Secured connection dispatch using native authentication, JSON and SSE owners.

use std::future::{Future, poll_fn};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::task::Poll;
use std::time::Duration;

use asupersync::Cx;
use asupersync::io::{AsyncReadExt, AsyncWriteExt};
use asupersync::sync::Notify;
use fastmcp_core::McpRequestCancellation;
use fastmcp_transport::{TransportError, http::{HttpRequest, HttpResponse, HttpStatus}};

use super::{SecuredHttpIoLimits, ingress::{Ingress, SecuredCodec}, tls::ConnectionIo};
use super::super::{scope, guard_response};
use super::super::revalidation::SseAuthorizationLease;
use super::super::super::{CorsResponseHeaders, HttpSecurityPolicy};
use super::super::super::scope_policy::request::ScopeRequestPolicy;
use crate::{
    AuthDispatchCustody, DualEraHttpEndpointError, DualEraHttpSseResponse,
    FinalSubscriptionTerminalDelivery, Framed, HttpListenerShutdown,
    InboundRequestContext, InboundRequestTransport, JsonRpcRequest, LiveModernHttpSession,
    LiveModernHttpSessionRegistry, ModernSseDispatchElection, ModernSseOutcomeGate,
    NativeHttp1Codec, OwnedModernHttpDispatch, Server, ServerHttpEndpoint, ServerHttpEndpointError,
    TransportAuthorization, admit_modern_http_post, await_modern_sse_dispatch_election,
    close_detached_modern_http_session, dispatch_modern_http_request_with_cancellation_and_transport_authorization,
    final_subscription_terminal_event, final_subscription_terminal_response_event,
    h1_request_to_transport, h1_transport_authorization, http_endpoint_error_response,
    http_endpoint_response_to_static, http_request_accepts_sse, native_http1_codec,
    next_live_modern_http_response_body_generation, next_modern_http_stream_generation,
    pop_sse_body_event, request_id_to_u64, send_h1_bad_request_response, send_h1_response,
    spawn_modern_sse_dispatch, sse_response_head,
};

pub(super) async fn serve(
    cx: &Cx,
    stream: ConnectionIo,
    endpoint: Arc<ServerHttpEndpoint>,
    sessions: LiveModernHttpSessionRegistry,
    shutdown: HttpListenerShutdown,
    policy: Arc<HttpSecurityPolicy>,
    io: SecuredHttpIoLimits,
) {
    let body_limit = endpoint.server.http_config.handler_config.max_body_size;
    let mut framed = Framed::new(stream, SecuredCodec::new(Arc::clone(&policy), body_limit)
        .with_oauth_routes(endpoint.server.oauth_http_routes.as_ref()));
    let mut writing_continue = false;
    let read = super::ingress::receive(
        cx, &shutdown, &mut framed, io.write_timeout, &mut writing_continue,
    );
    let incoming = asupersync::time::timeout(cx.now(), io.request_timeout, read).await;
    // A request timeout can interrupt the interim response midway through a
    // short socket/TLS write. Close instead of appending a 408 to partial bytes.
    if writing_continue { return; }
    let pipelined = !framed.read_buffer().is_empty();
    let mut framed = Framed::new(framed.into_inner(), native_http1_codec(&endpoint));
    let incoming = match incoming {
        Ok(Some(Ok(incoming))) => incoming,
        Ok(None) => return,
        Ok(Some(Err(_))) => {
            buffered(cx, &shutdown, &mut framed, HttpResponse::bad_request(), None, io).await;
            return;
        }
        Err(_) => {
            buffered(cx, &shutdown, &mut framed, HttpResponse::new(HttpStatus(408)), None, io).await;
            return;
        }
    };
    let (request, cors) = match incoming {
        Ingress::Immediate(response) => {
            buffered(cx, &shutdown, &mut framed, response, None, io).await;
            return;
        }
        Ingress::Request { request, cors } => (request, cors),
        // The ingress driver consumes interim decisions without dispatching.
        Ingress::Continue => return,
    };
    if pipelined {
        buffered(cx, &shutdown, &mut framed, HttpResponse::bad_request(), Some(&cors), io).await;
        return;
    }
    let raw_path = request.uri.split_once('?').map_or(request.uri.as_str(), |(path, _)| path);
    if let Some(routes) = endpoint.server.oauth_http_routes.as_ref().filter(|routes| routes.has_path(raw_path)) {
        if raw_path == routes.metadata_path() {
            // This bounded document has no provider work or mutable issuer
            // state. Keep discovery available when token/consent workers are
            // unavailable, after the same Host, Origin and body admission.
            let query = request.uri.split_once('?').map_or("", |(_, query)| query);
            let response = crate::dispatch_oauth_h1_request(routes, &request, raw_path, query);
            buffered(cx, &shutdown, &mut framed, response, Some(&cors), io).await;
            return;
        }
        issuer(cx, framed.into_inner(), endpoint.clone(), sessions, shutdown,
            routes.clone(), request, cors, io).await;
        return;
    }
    // Raw security fields have already passed before body allocation. Retain
    // their cardinality through the existing protocol/header mirror boundary.
    if let Err(response) = admit_modern_http_post(
        &endpoint.server.http_config.handler_config, "POST", raw_path, &request.headers, &request.body,
    ) {
        buffered(cx, &shutdown, &mut framed, response, Some(&cors), io).await;
        return;
    }
    let authorization = match h1_transport_authorization(&request) {
        Ok(authorization) => authorization,
        Err(response) => {
            buffered(cx, &shutdown, &mut framed, response, Some(&cors), io).await;
            return;
        }
    };
    let request = match h1_request_to_transport(&request) {
        Ok(request) => request,
        Err(response) => {
            buffered(cx, &shutdown, &mut framed, response, Some(&cors), io).await;
            return;
        }
    };
    if !http_request_accepts_sse(&request) {
        json(cx, framed.into_inner(), endpoint, sessions, shutdown, request, authorization,
            cors, policy.scope_authorization.clone(), io).await;
        return;
    }
    if request.header("mcp-session-id").is_some() {
        buffered(cx, &shutdown, &mut framed, HttpResponse::bad_request(), Some(&cors), io).await;
        return;
    }
    let mut session = match endpoint.open_session(cx) {
        Ok(session) => session,
        Err(_) => {
            buffered(cx, &shutdown, &mut framed, HttpResponse::internal_error(), Some(&cors), io).await;
            return;
        }
    };
    let http_parameter_headers = crate::http_admission::http_parameter_headers(&request.headers);
    let opening = match &policy.scope_authorization {
        Some(scopes) => Box::pin(scope::begin_sse(&mut session, cx, scopes, request.clone(), authorization.clone(), policy.sse_revalidation)).await,
        None => session.begin_modern_sse(cx, request.clone(), authorization.clone()).await
            .map(|opening| opening.map(|(request, response, raw, receipt)| (request, response, raw, receipt, None))),
    };
    let opened = match opening {
        Ok(Ok((request, response, raw_params, receipt, lease))) => Ok(Ok((
            InboundRequestContext::with_modern_connection_and_transport_authorization(
                cx.clone(), request_id_to_u64(request.id.as_ref()), InboundRequestTransport::Http,
                &session.modern_connection, authorization,
            ).with_http_parameter_headers(http_parameter_headers), request, raw_params, receipt, response, lease,
        ))),
        Ok(Err(response)) => Ok(Err(response)),
        Err(error) => Err(ServerHttpEndpointError::from_internal(error)),
    };
    let live = Arc::new(LiveModernHttpSession::new(session));
    match opened {
        Ok(Ok((inbound, request, raw_params, receipt, response, lease))) => {
            let generation = next_live_modern_http_response_body_generation();
            if let Err(live) = sessions.register_response_body(generation, Arc::clone(&live)) {
                close_detached_modern_http_session(&sessions, live);
                buffered(cx, &shutdown, &mut framed, HttpResponse::new(HttpStatus::SERVICE_UNAVAILABLE), Some(&cors), io).await;
                return;
            }
            let _body_owner = RegisteredResponseBody {
                sessions: Arc::clone(&sessions), generation,
            };
            let _ = sse(cx, &shutdown, framed.into_inner(), Arc::clone(&endpoint.server), &live,
                &sessions, next_modern_http_stream_generation(), inbound, request, raw_params,
                Some(receipt), response, &cors, lease, io).await;
        }
        Ok(Err(response)) => {
            buffered(cx, &shutdown, &mut framed, http_endpoint_response_to_static(cx, *response), Some(&cors), io).await;
            close_detached_modern_http_session(&sessions, live);
        }
        Err(error) => {
            buffered(cx, &shutdown, &mut framed, http_endpoint_error_response(&request, error, body_limit), Some(&cors), io).await;
            close_detached_modern_http_session(&sessions, live);
        }
    }
}

/// Own the registry entry across every suspension of the response driver.
/// Cancellation or abandonment must retire dispatches even when execution never
/// reaches the code after `sse().await`. The registry keeps unsettled handles.
struct RegisteredResponseBody {
    sessions: LiveModernHttpSessionRegistry,
    generation: u64,
}

impl Drop for RegisteredResponseBody {
    fn drop(&mut self) {
        // Phase-one listener shutdown may already have evacuated this entry.
        // In that case its terminal-drain owner, not this guard, must perform
        // destructive phase-two close. TTL removal is similarly idempotent.
        if let Some(live) = self.sessions.take_response_body(self.generation) {
            close_detached_modern_http_session(&self.sessions, live);
        }
    }
}

async fn buffered<T: asupersync::io::AsyncWrite + Unpin>(
    cx: &Cx, shutdown: &HttpListenerShutdown, framed: &mut Framed<T, NativeHttp1Codec>,
    response: HttpResponse, cors: Option<&CorsResponseHeaders>, io: SecuredHttpIoLimits,
) {
    // Admission refusals own no dispatch. Their only remaining action is to
    // close this one-request connection, whether delivery succeeds or fails.
    let _ = write_buffered(cx, shutdown, framed, response, cors, io).await;
}

async fn write_buffered<T: asupersync::io::AsyncWrite + Unpin>(
    cx: &Cx, shutdown: &HttpListenerShutdown, framed: &mut Framed<T, NativeHttp1Codec>,
    mut response: HttpResponse, cors: Option<&CorsResponseHeaders>, io: SecuredHttpIoLimits,
) -> Result<(), ()> {
    if response.status.0 >= 400 {
        response = response.with_header("cache-control", "no-store");
    }
    if let Some(cors) = cors { cors.apply_to(&mut response); }
    asupersync::time::timeout(cx.now(), io.write_timeout,
        send_h1_response(cx, shutdown, framed, response)).await.map_err(|_| ())?.map_err(|_| ())
}

#[derive(Default)]
struct IssuerCompletion {
    done: AtomicBool,
    changed: Notify,
}

struct IssuerCompletionGuard(Arc<IssuerCompletion>);

impl Drop for IssuerCompletionGuard {
    fn drop(&mut self) {
        self.0.done.store(true, Ordering::Release);
        let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| self.0.changed.notify_waiters()));
    }
}

// The completion guard is last: Rust drops the captured issuer, raw request,
// context, cancellation and capacity permit before waking the async owner.
// Calling run consumes this whole object, including when pool submission drops
// an uninvoked closure, so capture splitting cannot publish completion early.
struct IssuerWork {
    routes: crate::OAuthHttpRoutes,
    request: asupersync::http::h1::Request,
    cx: Cx,
    cancellation: McpRequestCancellation,
    _permit: crate::BlockingDispatchPermit,
    _completion: IssuerCompletionGuard,
}

impl IssuerWork {
    fn run(self, sender: asupersync::channel::oneshot::Sender<HttpResponse>) {
        if self.cx.checkpoint().is_err() || self.cancellation.is_cancel_requested() { return; }
        let _current = Cx::set_current(Some(self.cx.clone()));
        let _lane = fastmcp_core::runtime::enter_blocking_lane();
        let (path, query) = self.request.uri.split_once('?')
            .map_or((self.request.uri.as_str(), ""), |(path, query)| (path, query));
        let response = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            crate::dispatch_oauth_h1_request(&self.routes, &self.request, path, query)
        })).unwrap_or_else(|_| HttpResponse::internal_error());
        if self.cx.checkpoint().is_ok() && !self.cancellation.is_cancel_requested() {
            let _ = sender.send_blocking(response);
        }
    }
}

// The issuer keeps its own client/consent/PKCE/token policy. It never enters
// MCP routing, bearer verification or protected-resource scope authorization.
// Admission has already preserved raw query and header cardinality and bounded
// the exact issuer route before accepting the request body.
#[allow(clippy::too_many_arguments)]
async fn issuer(
    cx: &Cx, stream: ConnectionIo, endpoint: Arc<ServerHttpEndpoint>,
    sessions: LiveModernHttpSessionRegistry, shutdown: HttpListenerShutdown,
    routes: crate::OAuthHttpRoutes, request: asupersync::http::h1::Request,
    cors: CorsResponseHeaders, io: SecuredHttpIoLimits,
) {
    let unavailable = || HttpResponse::new(HttpStatus::SERVICE_UNAVAILABLE)
        .with_header("cache-control", "no-store");
    let Some(pool) = cx.blocking_pool_handle() else {
        let mut framed = Framed::new(stream, native_http1_codec(&endpoint));
        buffered(cx, &shutdown, &mut framed, unavailable(), Some(&cors), io).await;
        return;
    };
    let Some(permit) = crate::try_reserve_blocking_dispatch() else {
        let mut framed = Framed::new(stream, native_http1_codec(&endpoint));
        buffered(cx, &shutdown, &mut framed, unavailable(), Some(&cors), io).await;
        return;
    };
    let cancellation = McpRequestCancellation::new();
    let worker_cancellation = cancellation.clone();
    let (sender, receiver) = asupersync::channel::oneshot::channel::<HttpResponse>();
    let task = cx.spawn(move |worker_cx| async move {
        let (result_sender, mut result_receiver) = asupersync::channel::oneshot::channel();
        let completion = Arc::new(IssuerCompletion::default());
        let work = IssuerWork {
            routes, request, cx: worker_cx.clone(), cancellation: worker_cancellation,
            _permit: permit, _completion: IssuerCompletionGuard(Arc::clone(&completion)),
        };
        // Raw pool submission refuses without invoking the closure. The permit
        // remains with executing synchronous work even when its peer disappears.
        let pool_task = crate::BlockingTaskGuard(pool.spawn(move || work.run(result_sender)));
        let response = result_receiver.recv(&worker_cx).await;
        if worker_cx.is_cancel_requested() { pool_task.0.cancel(); }
        completion.changed.wait_until(|| completion.done.load(Ordering::Acquire)).await;
        if worker_cx.checkpoint().is_ok() {
            let response = response.unwrap_or_else(|_| HttpResponse::new(HttpStatus::SERVICE_UNAVAILABLE));
            let _ = sender.send_blocking(response.with_header("cache-control", "no-store"));
        }
    });
    let dispatch = match task {
        Ok(task) => OwnedJsonDispatch { task: Some(task), sessions, cancellation: cancellation.clone() },
        Err(_) => {
            let mut framed = Framed::new(stream, native_http1_codec(&endpoint));
            buffered(cx, &shutdown, &mut framed, unavailable(), Some(&cors), io).await;
            return;
        }
    };
    let (mut reader, writer) = stream.into_split();
    let mut byte = [0_u8; 1];
    let mut framed = Framed::new(writer, native_http1_codec(&endpoint));
    let _ = deliver_buffered_response(
        cx, dispatch, receiver, reader.read(&mut byte), unavailable(),
        |response| write_buffered(cx, &shutdown, &mut framed, response, Some(&cors), io),
    ).await;
}

#[allow(clippy::too_many_arguments)]
async fn json(
    cx: &Cx, stream: ConnectionIo, endpoint: Arc<ServerHttpEndpoint>,
    sessions: LiveModernHttpSessionRegistry, shutdown: HttpListenerShutdown,
    request: HttpRequest, authorization: TransportAuthorization,
    cors: CorsResponseHeaders, scopes: Option<ScopeRequestPolicy>, io: SecuredHttpIoLimits,
) {
    let (mut reader, writer) = stream.into_split();
    let cancellation = McpRequestCancellation::new();
    let dispatch_endpoint = Arc::clone(&endpoint);
    let dispatch_sessions = Arc::clone(&sessions);
    let dispatch_cancellation = cancellation.clone();
    let (sender, receiver) = asupersync::channel::oneshot::channel::<HttpResponse>();
    let task = cx.spawn(move |request_cx| async move {
        let response = match scopes {
            Some(scopes) => Box::pin(scope::dispatch_socket_json(
                &request_cx, &dispatch_endpoint, &dispatch_sessions, &scopes,
                request, authorization, dispatch_cancellation,
            )).await,
            None => dispatch_modern_http_request_with_cancellation_and_transport_authorization(
                &request_cx, &dispatch_endpoint, &dispatch_sessions, request, authorization, Some(dispatch_cancellation),
            ).await,
        };
        let _ = sender.send_blocking(response);
    });
    let dispatch = match task {
        Ok(task) => OwnedJsonDispatch { task: Some(task), sessions, cancellation: cancellation.clone() },
        Err(_) => {
            cancellation.cancel();
            let mut framed = Framed::new(writer, native_http1_codec(&endpoint));
            buffered(cx, &shutdown, &mut framed, HttpResponse::new(HttpStatus::SERVICE_UNAVAILABLE), Some(&cors), io).await;
            return;
        }
    };
    let mut byte = [0_u8; 1];
    let mut framed = Framed::new(writer, native_http1_codec(&endpoint));
    let _ = deliver_buffered_response(
        cx, dispatch, receiver, reader.read(&mut byte), HttpResponse::internal_error(),
        |response| write_buffered(cx, &shutdown, &mut framed, response, Some(&cors), io),
    ).await;
}

/// Own one peer read across result retrieval, child settlement and final write.
/// A queued result is not proof that its producer has quiesced or that any
/// bytes reached the peer. Neither the join nor the bounded write may escape
/// disconnect monitoring, including for issuer responses without MCP terminals.
/// On abandonment the dispatch guard transfers any unfinished child to the
/// listener; after settlement the peer guard still owns request cancellation.
async fn deliver_buffered_response<P, W, F>(
    cx: &Cx,
    mut dispatch: OwnedJsonDispatch,
    mut receiver: asupersync::channel::oneshot::Receiver<HttpResponse>,
    peer: P,
    failure: HttpResponse,
    write: W,
) -> Result<(), ()>
where
    P: Future<Output = std::io::Result<usize>>,
    W: FnOnce(HttpResponse) -> F,
    F: Future<Output = Result<(), ()>>,
{
    let cancellation = dispatch.cancellation.clone();
    monitor_response_peer(&cancellation, peer, async move {
        let response = receiver.recv(cx).await;
        if cx.checkpoint().is_err() { return Err(()); }
        let mut response = response.unwrap_or_else(|_| failure.clone());
        if !dispatch.finish(cx).await {
            if cx.checkpoint().is_err() { return Err(()); }
            response = failure;
        }
        // Transfer failed/unsettled custody before writing, but leave the peer
        // monitor armed. In particular, a write error must not count as success
        // merely because the task handle has already been joined and released.
        drop(dispatch);
        write(response).await
    }).await
}

/// Keep a JSON request's child handle even if its result wait or join is dropped.
/// The one-slot result channel carries data; only this owner carries settlement.
struct OwnedJsonDispatch {
    task: Option<asupersync::runtime::TaskHandle<()>>,
    sessions: LiveModernHttpSessionRegistry,
    cancellation: McpRequestCancellation,
}

impl OwnedJsonDispatch {
    async fn finish(&mut self, cx: &Cx) -> bool {
        let Some(task) = self.task.as_mut() else { return true; };
        if task.join(cx).await.is_err() { return false; }
        self.task = None;
        true
    }
}

impl Drop for OwnedJsonDispatch {
    fn drop(&mut self) {
        if let Some(task) = self.task.take() {
            self.cancellation.cancel();
            task.abort();
            self.sessions.retain_retired_dispatches(vec![task]);
        }
    }
}

// Keep native representation election, dispatch custody and terminal receipts.
// A credential failure never drains a successful terminal. The existing error
// path cancels the request and retains children for ordinary session settlement.
#[allow(clippy::too_many_arguments)]
async fn sse(
    cx: &Cx, shutdown: &HttpListenerShutdown, stream: ConnectionIo,
    server: Arc<Server>, live: &LiveModernHttpSession, sessions: &LiveModernHttpSessionRegistry,
    generation: u64, inbound: InboundRequestContext, request: JsonRpcRequest,
    raw_params: Option<Arc<str>>, receipt: Option<AuthDispatchCustody>,
    response: DualEraHttpSseResponse, cors: &CorsResponseHeaders,
    mut lease: Option<SseAuthorizationLease>, io: SecuredHttpIoLimits,
) -> Result<(), ()> {
    if let Some(lease) = lease.as_mut() { lease.check(cx).map_err(|_| ())?; }
    let sender = response.sender();
    let cancellation = sender.request_cancellation();
    let terminal = Arc::new(FinalSubscriptionTerminalDelivery::default());
    let (gate, mut election) = ModernSseOutcomeGate::new();
    let (mut reader, mut writer) = stream.into_split();
    let task = spawn_modern_sse_dispatch(cx, Arc::clone(&server), generation, inbound, request,
        raw_params, receipt, sender, Arc::clone(&terminal), Some(gate)).map_err(|_| ())?;
    let dispatch = OwnedModernHttpDispatch {
        owner_generation: generation, request_cancellation: cancellation.clone(), task,
    };
    if let Err(dispatch) = live.register_modern_dispatch(dispatch) {
        server.final_subscriptions.cancel_modern_http_owner(dispatch.owner_generation);
        dispatch.request_cancellation.cancel();
        dispatch.task.abort();
        sessions.retain_retired_dispatches(vec![dispatch.task]);
        return Err(());
    }
    let mut peer_byte = [0_u8; 1];
    let result = monitor_response_peer(&cancellation, reader.read(&mut peer_byte), async {
        let elected = guard_response(cx, &mut lease,
            await_modern_sse_dispatch_election(cx, &cancellation, &mut election))
            .await.map_err(|_| ())??;
        match elected {
            ModernSseDispatchElection::Stream => {},
            ModernSseDispatchElection::Immediate(mut response) => {
                cors.apply_to(&mut response);
                return guard_response(cx, &mut lease, asupersync::time::timeout(cx.now(), io.write_timeout,
                    send_h1_bad_request_response(cx, shutdown, &mut writer, &response)))
                    .await.map_err(|_| ())?.map_err(|_| ())?;
            }
            ModernSseDispatchElection::Failed => return Err(()),
        }
        let mut head = response.response().clone();
        cors.apply_to(&mut head);
        let head = sse_response_head(&head)?;
        guard_response(cx, &mut lease, write_parts(cx, &mut writer, &[&head], io))
            .await.map_err(|_| ())??;
        loop {
            if let Some(lease) = lease.as_mut() { lease.check(cx).map_err(|_| ())?; }
            if terminal.is_settled() { return Err(()); }
            match pop_sse_body_event(&response) {
                Ok(Some(event)) => {
                    let control = final_subscription_terminal_event(&event);
                    let complete = final_subscription_terminal_response_event(&event);
                    let bytes = event.to_bytes().map_err(|_| ())?;
                    let prefix = format!("{:X}\r\n", bytes.len());
                    guard_response(cx, &mut lease, write_parts(cx, &mut writer,
                        &[prefix.as_bytes(), &bytes, b"\r\n"], io)).await.map_err(|_| ())??;
                    if control { terminal.mark_drained(); }
                    if complete { terminal.mark_completion_drained(); }
                    if terminal.is_settled() { break; }
                }
                Ok(None) if response.is_finished() => break,
                Ok(None) if cancellation.is_cancel_requested() && !terminal.is_committed() => {
                    terminal.mark_failed();
                    break;
                }
                Ok(None) if cx.checkpoint().is_err() => {
                    terminal.mark_failed();
                    break;
                }
                Ok(None) => asupersync::time::sleep(cx.now(), Duration::from_millis(1)).await,
                Err(DualEraHttpEndpointError::Transport(TransportError::Closed)) if response.is_finished() => break,
                Err(_) => return Err(()),
            }
        }
        guard_response(cx, &mut lease, write_parts(cx, &mut writer, &[b"0\r\n\r\n"], io))
            .await.map_err(|_| ())?
    }).await;
    if result.is_err() {
        terminal.mark_failed();
        sessions.retain_retired_dispatches(live.cancel_modern_dispatch(generation));
    } else if !terminal.is_settled() {
        terminal.mark_failed();
    }
    live.reap_modern_dispatches();
    result
}

/// Poll the one outstanding peer read before a JSON or SSE response, without a
/// spawned task or repeatedly cancelling/recreating a partially completed write.
///
/// EOF retires the outstanding request just like a reset. TCP cannot distinguish
/// a peer dropping its socket from a deliberate write-half-close, so this native
/// one-request listener requires the client to keep its write side open until
/// the response completes. Ignoring EOF would leave blocking handlers running
/// for an absent caller until their deadline, even though they poll cancellation.
/// Any received byte is unsupported pipelining and also retires the request.
///
/// Only the existing request-local cancellation domain is signalled; the ambient
/// Cx and sibling requests are untouched. Its atomic terminal election preserves
/// a finalization that won first, but that cannot turn a failed socket delivery
/// into a successful terminal drain. The caller retains dispatch settlement.
async fn monitor_response_peer<P, F, T>(
    cancellation: &McpRequestCancellation,
    peer: P,
    response: F,
) -> Result<T, ()>
where
    P: Future<Output = std::io::Result<usize>>,
    F: Future<Output = Result<T, ()>>,
{
    let mut owner = CancelAbandonedResponse {
        cancellation: cancellation.clone(),
        armed: true,
    };
    let mut peer = std::pin::pin!(peer);
    let mut response = std::pin::pin!(response);
    let result = poll_fn(|task| {
        if peer.as_mut().poll(task).is_ready() {
            cancellation.cancel();
            return Poll::Ready(Err(()));
        }
        // Do not reject solely because the request token was cancelled: a
        // committed graceful terminal may still need to drain on this socket.
        // The native response/election state machine owns that distinction.
        response.as_mut().poll(task)
    }).await;
    if result.is_ok() { owner.armed = false; }
    result
}

struct CancelAbandonedResponse {
    cancellation: McpRequestCancellation,
    armed: bool,
}

impl Drop for CancelAbandonedResponse {
    fn drop(&mut self) {
        if self.armed { self.cancellation.cancel(); }
    }
}

async fn write_parts<W: asupersync::io::AsyncWrite + Unpin>(
    cx: &Cx, writer: &mut W, parts: &[&[u8]], io: SecuredHttpIoLimits,
) -> Result<(), ()> {
    asupersync::time::timeout(cx.now(), io.write_timeout, async {
        for part in parts { writer.write_all(part).await.map_err(|_| ())?; }
        writer.flush().await.map_err(|_| ())
    }).await.map_err(|_| ())?
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::future::{pending, ready};
    use std::io;
    use std::pin::Pin;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::task::{Context, Wake, Waker};

    // These tests drive the production response/peer arbitration directly.
    // They test ownership and scheduling, not TLS or kernel reset behavior.
    struct Tracked<F> {
        future: Pin<Box<F>>,
        polls: Arc<AtomicUsize>,
        drops: Arc<AtomicUsize>,
    }

    impl<F> Tracked<F> {
        fn new(future: F) -> Self {
            Self {
                future: Box::pin(future),
                polls: Arc::new(AtomicUsize::new(0)),
                drops: Arc::new(AtomicUsize::new(0)),
            }
        }
    }

    impl<F: Future> Future for Tracked<F> {
        type Output = F::Output;
        fn poll(self: Pin<&mut Self>, task: &mut Context<'_>) -> Poll<Self::Output> {
            let this = self.get_mut();
            this.polls.fetch_add(1, Ordering::SeqCst);
            this.future.as_mut().poll(task)
        }
    }

    impl<F> Drop for Tracked<F> {
        fn drop(&mut self) { self.drops.fetch_add(1, Ordering::SeqCst); }
    }

    async fn registered_body(cx: &Cx) -> (crate::BoundHttpServer, Arc<LiveModernHttpSession>, u64) {
        let bound = Server::new("secured-body-lifetime", "1")
            .protocol_policy(fastmcp_protocol::protocol_policy::ProtocolPolicy::ModernOnly).unwrap()
            .build().bind_http(cx, "127.0.0.1:0").await.unwrap();
        let live = Arc::new(LiveModernHttpSession::new(bound.endpoint.open_session(cx).unwrap()));
        let generation = next_live_modern_http_response_body_generation();
        assert!(bound.modern_sessions.register_response_body(generation, Arc::clone(&live)).is_ok());
        (bound, live, generation)
    }

    #[test]
    fn secured_sse_abandoned_body_releases_registry_and_retains_cancelled_dispatch() {
        asupersync::runtime::RuntimeBuilder::current_thread()
            .with_reactor(asupersync::runtime::reactor::create_reactor().unwrap())
            .build().unwrap().block_on(async {
                let cx = Cx::current().unwrap();
                let (bound, live, generation) = registered_body(&cx).await;
                let registry = Arc::clone(&bound.modern_sessions);
                let sibling = Arc::new(LiveModernHttpSession::new(bound.endpoint.open_session(&cx).unwrap()));
                let sibling_generation = next_live_modern_http_response_body_generation();
                assert!(registry.register_response_body(sibling_generation, Arc::clone(&sibling)).is_ok());
                let sibling_owner = RegisteredResponseBody {
                    sessions: Arc::clone(&registry), generation: sibling_generation,
                };
                let cancellation = McpRequestCancellation::new();
                let (sender, mut receiver) = asupersync::channel::oneshot::channel::<()>();
                let task = cx.spawn(move |child_cx| async move {
                    let _ = receiver.recv(&child_cx).await;
                }).unwrap();
                assert!(live.register_modern_dispatch(OwnedModernHttpDispatch {
                    owner_generation: next_modern_http_stream_generation(),
                    request_cancellation: cancellation.clone(), task,
                }).is_ok());
                let owner = RegisteredResponseBody { sessions: Arc::clone(&registry), generation };
                let response = Tracked::new(pending::<()>());
                let drops = Arc::clone(&response.drops);
                let mut waiting = Box::pin(async move {
                    let _owner = owner;
                    response.await;
                });
                poll_fn(|task| {
                    assert!(waiting.as_mut().poll(task).is_pending());
                    Poll::Ready(())
                }).await;
                assert_eq!(registry.sessions.lock().unwrap().len(), 2);
                assert!(!live.is_closing());
                assert!(!cancellation.is_cancel_requested());

                drop(waiting);
                assert_eq!(drops.load(Ordering::SeqCst), 1);
                assert_eq!(registry.sessions.lock().unwrap().len(), 1);
                assert!(!registry.sessions.lock().unwrap().contains_key(&generation));
                assert!(registry.sessions.lock().unwrap().contains_key(&sibling_generation));
                assert!(live.finalized.load(Ordering::Acquire));
                assert!(cancellation.is_cancel_requested());
                assert!(!sibling.is_closing());
                let mut retired = registry.take_retired_dispatches();
                assert_eq!(retired.len(), 1, "aborted child custody remains with the listener");
                let _ = retired[0].join(&cx).await;
                drop(sender);
                drop(sibling_owner);
                assert!(sibling.finalized.load(Ordering::Acquire));
                assert!(registry.sessions.lock().unwrap().is_empty());
            });
    }

    #[test]
    fn secured_sse_body_owner_preserves_listener_terminal_drain_custody() {
        asupersync::runtime::RuntimeBuilder::current_thread()
            .with_reactor(asupersync::runtime::reactor::create_reactor().unwrap())
            .build().unwrap().block_on(async {
                let cx = Cx::current().unwrap();
                let (bound, live, generation) = registered_body(&cx).await;
                let registry = Arc::clone(&bound.modern_sessions);
                let owner = RegisteredResponseBody { sessions: Arc::clone(&registry), generation };
                let expiry = *live.expires_at.lock().unwrap();
                let closing = crate::detach_live_modern_http_sessions(&registry);
                assert_eq!(closing.len(), 1);
                assert!(live.is_closing());
                assert!(!live.finalized.load(Ordering::Acquire));
                drop(owner);
                assert!(!live.finalized.load(Ordering::Acquire), "response drop cannot steal phase-two close");
                assert_eq!(*live.expires_at.lock().unwrap(), expiry);
                let unsettled = crate::finish_live_modern_http_sessions(&registry, closing).await;
                assert!(unsettled.is_empty());
                assert!(live.finalized.load(Ordering::Acquire));
                assert!(registry.sessions.lock().unwrap().is_empty());
            });
    }

    #[test]
    fn secured_json_abandoned_join_cancels_request_and_retains_child() {
        asupersync::runtime::RuntimeBuilder::current_thread()
            .with_reactor(asupersync::runtime::reactor::create_reactor().unwrap())
            .build().unwrap().block_on(async {
                let cx = Cx::current().unwrap();
                let registry = Arc::new(crate::LiveModernHttpSessionRegistryState::new());
                let cancellation = McpRequestCancellation::new();
                let sibling = McpRequestCancellation::new();
                let (sender, mut receiver) = asupersync::channel::oneshot::channel::<()>();
                let task = cx.spawn(move |child_cx| async move {
                    let _ = receiver.recv(&child_cx).await;
                }).unwrap();
                let mut owner = OwnedJsonDispatch {
                    task: Some(task), sessions: Arc::clone(&registry), cancellation: cancellation.clone(),
                };
                let join_cx = cx.clone();
                let mut waiting = Box::pin(async move { owner.finish(&join_cx).await });
                poll_fn(|task| {
                    assert!(waiting.as_mut().poll(task).is_pending());
                    Poll::Ready(())
                }).await;
                assert!(!cancellation.is_cancel_requested());
                assert!(registry.retired_dispatches.lock().unwrap().is_empty());
                drop(waiting);
                assert!(cancellation.is_cancel_requested());
                assert!(!sibling.is_cancel_requested());
                let mut retired = registry.take_retired_dispatches();
                assert_eq!(retired.len(), 1);
                let _ = retired[0].join(&cx).await;
                drop(sender);
                assert!(cx.checkpoint().is_ok());
            });
    }

    #[test]
    fn secured_json_completed_dispatch_releases_custody_without_cancelling_request() {
        asupersync::runtime::RuntimeBuilder::current_thread()
            .with_reactor(asupersync::runtime::reactor::create_reactor().unwrap())
            .build().unwrap().block_on(async {
                let cx = Cx::current().unwrap();
                let registry = Arc::new(crate::LiveModernHttpSessionRegistryState::new());
                let cancellation = McpRequestCancellation::new();
                let effects = Arc::new(AtomicUsize::new(0));
                let observed = Arc::clone(&effects);
                let task = cx.spawn(move |_| async move {
                    observed.fetch_add(1, Ordering::SeqCst);
                }).unwrap();
                let mut owner = OwnedJsonDispatch {
                    task: Some(task), sessions: Arc::clone(&registry), cancellation: cancellation.clone(),
                };
                assert!(owner.finish(&cx).await);
                assert!(owner.task.is_none());
                drop(owner);
                assert_eq!(effects.load(Ordering::SeqCst), 1);
                assert!(!cancellation.is_cancel_requested());
                assert!(registry.retired_dispatches.lock().unwrap().is_empty());
                assert!(cx.checkpoint().is_ok());
            });
    }

    #[test]
    fn secured_json_disconnect_wins_over_a_queued_result() {
        asupersync::runtime::RuntimeBuilder::current_thread()
            .with_reactor(asupersync::runtime::reactor::create_reactor().unwrap())
            .build().unwrap().block_on(async {
                let cx = Cx::current().unwrap();
                for reset in [false, true] {
                    let registry = Arc::new(crate::LiveModernHttpSessionRegistryState::new());
                    let cancellation = McpRequestCancellation::new();
                    let (sender, mut receiver) = asupersync::channel::oneshot::channel::<HttpResponse>();
                    let task = cx.spawn(move |_| async move {
                        let _ = sender.send_blocking(HttpResponse::new(HttpStatus(201)));
                    }).unwrap();
                    let mut owner = OwnedJsonDispatch {
                        task: Some(task), sessions: Arc::clone(&registry), cancellation: cancellation.clone(),
                    };
                    assert!(owner.finish(&cx).await, "the result is queued before peer arbitration");
                    let peer = if reset { Err(io::Error::from(io::ErrorKind::ConnectionReset)) } else { Ok(0) };
                    let result = monitor_response_peer(&cancellation, ready(peer), async {
                        receiver.recv(&cx).await.map_err(|_| ())
                    }).await;
                    assert!(result.is_err());
                    assert_eq!(receiver.try_recv().unwrap().status.0, 201, "EOF/reset must not consume the queued result");
                    drop(owner);
                    assert!(cancellation.is_cancel_requested());
                    assert!(registry.retired_dispatches.lock().unwrap().is_empty());
                }
            });
    }

    #[test]
    fn secured_sse_ready_reset_wins_over_a_ready_response() {
        let cancellation = McpRequestCancellation::new();
        let sibling = McpRequestCancellation::new();
        let peer = ready(Err(io::Error::from(io::ErrorKind::ConnectionReset)));
        let response = Tracked::new(ready(Ok::<_, ()>(7)));
        let polls = Arc::clone(&response.polls);
        let drops = Arc::clone(&response.drops);
        let mut work = Box::pin(monitor_response_peer(&cancellation, peer, response));
        let mut task = Context::from_waker(Waker::noop());
        assert_eq!(work.as_mut().poll(&mut task), Poll::Ready(Err(())));
        drop(work);
        assert_eq!(polls.load(Ordering::SeqCst), 0, "no response write after observed reset");
        assert_eq!(drops.load(Ordering::SeqCst), 1);
        assert!(cancellation.is_cancel_requested());
        assert!(!sibling.is_cancel_requested());
    }

    #[test]
    fn secured_sse_late_request_data_is_not_a_second_dispatch() {
        let cancellation = McpRequestCancellation::new();
        let response = Tracked::new(ready(Ok::<_, ()>(7)));
        let polls = Arc::clone(&response.polls);
        let mut work = Box::pin(monitor_response_peer(&cancellation, ready(Ok(1)), response));
        let mut task = Context::from_waker(Waker::noop());
        assert_eq!(work.as_mut().poll(&mut task), Poll::Ready(Err(())));
        assert_eq!(polls.load(Ordering::SeqCst), 0);
        assert!(cancellation.is_cancel_requested());
    }

    #[test]
    fn secured_peer_eof_cancels_only_its_request_context() {
        let cx = Cx::for_testing();
        let cancellation = McpRequestCancellation::new();
        let context = fastmcp_core::McpContext::new(cx.clone(), 7)
            .with_request_cancellation(cancellation.clone());
        let sibling = fastmcp_core::McpContext::new(cx.clone(), 7);
        let mut work = Box::pin(monitor_response_peer(
            &cancellation, ready(Ok(0)), pending::<Result<(), ()>>(),
        ));
        let mut task = Context::from_waker(Waker::noop());
        assert_eq!(work.as_mut().poll(&mut task), Poll::Ready(Err(())));
        drop(work);
        assert!(context.is_cancelled());
        assert!(cancellation.is_cancel_requested());
        assert!(!cancellation.begin_finalization(), "disconnect won the terminal race");
        assert!(!sibling.is_cancelled(), "even the same request ID has independent ownership");
        assert!(cx.checkpoint().is_ok());
    }

    #[test]
    fn secured_peer_eof_drops_the_response_without_polling_it() {
        let cancellation = McpRequestCancellation::new();
        let peer = Tracked::new(ready(Ok(0)));
        let reads = Arc::clone(&peer.polls);
        let peer_drops = Arc::clone(&peer.drops);
        let response = Tracked::new(ready(Ok::<_, ()>(7)));
        let calls = Arc::clone(&response.polls);
        let response_drops = Arc::clone(&response.drops);
        let mut work = Box::pin(monitor_response_peer(&cancellation, peer, response));
        let mut task = Context::from_waker(Waker::noop());
        assert_eq!(work.as_mut().poll(&mut task), Poll::Ready(Err(())));
        drop(work);
        assert_eq!(reads.load(Ordering::SeqCst), 1);
        assert_eq!(calls.load(Ordering::SeqCst), 0);
        assert_eq!(peer_drops.load(Ordering::SeqCst), 1);
        assert_eq!(response_drops.load(Ordering::SeqCst), 1);
        assert!(cancellation.is_cancel_requested());
    }

    #[test]
    fn secured_peer_disconnect_does_not_reverse_finalization_or_claim_delivery() {
        for reset in [false, true] {
            let cancellation = McpRequestCancellation::new();
            assert!(cancellation.begin_finalization());
            let peer = if reset { Err(io::Error::from(io::ErrorKind::ConnectionReset)) } else { Ok(0) };
            let mut work = Box::pin(monitor_response_peer(
                &cancellation, ready(peer), ready(Ok::<_, ()>(7)),
            ));
            let mut task = Context::from_waker(Waker::noop());
            assert_eq!(work.as_mut().poll(&mut task), Poll::Ready(Err(())));
            drop(work);
            assert!(cancellation.is_finalizing());
            assert!(!cancellation.is_cancel_requested());
            assert!(!cancellation.cancel());
        }
    }

    #[test]
    fn secured_peer_eof_racing_finalization_has_one_terminal_owner() {
        for _ in 0..64 {
            let cancellation = McpRequestCancellation::new();
            let start = std::sync::Barrier::new(2);
            let finalized = std::thread::scope(|scope| {
                let finalizer = scope.spawn(|| {
                    start.wait();
                    cancellation.begin_finalization()
                });
                let mut work = Box::pin(monitor_response_peer(
                    &cancellation, ready(Ok(0)), ready(Ok::<_, ()>(7)),
                ));
                let mut task = Context::from_waker(Waker::noop());
                start.wait();
                assert_eq!(work.as_mut().poll(&mut task), Poll::Ready(Err(())));
                drop(work);
                finalizer.join().unwrap()
            });
            assert!(cancellation.is_terminal());
            assert_eq!(cancellation.is_finalizing(), finalized);
            assert_eq!(cancellation.is_cancel_requested(), !finalized);
            assert_eq!(cancellation.begin_finalization(), finalized);
            assert!(!cancellation.cancel(), "the terminal winner cannot change");
        }
    }

    #[test]
    fn secured_sse_success_releases_a_pending_peer_read_without_cancellation() {
        let cancellation = McpRequestCancellation::new();
        let peer = Tracked::new(pending::<io::Result<usize>>());
        let drops = Arc::clone(&peer.drops);
        let mut work = Box::pin(monitor_response_peer(&cancellation, peer, ready(Ok::<_, ()>(7))));
        let mut task = Context::from_waker(Waker::noop());
        assert_eq!(work.as_mut().poll(&mut task), Poll::Ready(Ok(7)));
        drop(work);
        assert_eq!(drops.load(Ordering::SeqCst), 1);
        assert!(!cancellation.is_cancel_requested());
    }

    #[test]
    fn secured_sse_abandoned_wait_cancels_request_and_drops_both_futures() {
        let cancellation = McpRequestCancellation::new();
        let sibling = McpRequestCancellation::new();
        let peer = Tracked::new(pending::<io::Result<usize>>());
        let response = Tracked::new(pending::<Result<(), ()>>());
        let peer_drops = Arc::clone(&peer.drops);
        let response_drops = Arc::clone(&response.drops);
        let mut work = Box::pin(monitor_response_peer(&cancellation, peer, response));
        let mut task = Context::from_waker(Waker::noop());
        assert!(work.as_mut().poll(&mut task).is_pending());
        assert!(!cancellation.is_cancel_requested());
        drop(work);
        assert!(cancellation.is_cancel_requested());
        assert!(!sibling.is_cancel_requested());
        assert_eq!(peer_drops.load(Ordering::SeqCst), 1);
        assert_eq!(response_drops.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn secured_sse_failed_write_retires_the_request() {
        let cancellation = McpRequestCancellation::new();
        let mut work = Box::pin(monitor_response_peer(
            &cancellation, pending::<io::Result<usize>>(), ready(Err::<(), _>(())),
        ));
        let mut task = Context::from_waker(Waker::noop());
        assert_eq!(work.as_mut().poll(&mut task), Poll::Ready(Err(())));
        drop(work);
        assert!(cancellation.is_cancel_requested());
    }

    #[test]
    fn secured_sse_peer_monitor_does_not_short_circuit_graceful_terminal_drain() {
        let cancellation = McpRequestCancellation::new();
        cancellation.cancel();
        let mut work = Box::pin(monitor_response_peer(
            &cancellation, pending::<io::Result<usize>>(), ready(Ok::<_, ()>(7)),
        ));
        let mut task = Context::from_waker(Waker::noop());
        assert_eq!(work.as_mut().poll(&mut task), Poll::Ready(Ok(7)));
        assert!(cancellation.is_cancel_requested(), "success never reverses cancellation");
    }

    #[test]
    fn buffered_delivery_raw_tcp_disconnect_interrupts_post_result_join() {
        asupersync::runtime::RuntimeBuilder::current_thread()
            .with_reactor(asupersync::runtime::reactor::create_reactor().unwrap())
            .build().unwrap().block_on(async {
                let cx = Cx::current().unwrap();
                let bound = Server::new("buffered-join-peer", "1")
                    .protocol_policy(fastmcp_protocol::protocol_policy::ProtocolPolicy::ModernOnly).unwrap()
                    .build().bind_http(&cx, "127.0.0.1:0").await.unwrap();
                let peer = std::net::TcpStream::connect_timeout(
                    &bound.local_addr().unwrap(), Duration::from_secs(2),
                ).unwrap();
                let (stream, _) = bound.listener.accept().await.unwrap();
                let (mut reader, writer) = ConnectionIo::Plain(stream).into_split();
                let registry = Arc::clone(&bound.modern_sessions);
                let cancellation = McpRequestCancellation::new();
                let sibling = fastmcp_core::McpContext::new(cx.clone(), 7);
                let (sender, receiver) = asupersync::channel::oneshot::channel();
                let (queued, mut queue_ready) = asupersync::channel::oneshot::channel();
                let (release, mut cleanup) = asupersync::channel::oneshot::channel::<()>();
                let child = cx.spawn(move |child_cx| async move {
                    let _ = sender.send_blocking(HttpResponse::new(HttpStatus(201)));
                    let _ = queued.send_blocking(());
                    // Producing a value is deliberately distinct from retiring
                    // the child's remaining cleanup and captured resources.
                    let _ = cleanup.recv(&child_cx).await;
                }).unwrap();
                let dispatch = OwnedJsonDispatch {
                    task: Some(child), sessions: Arc::clone(&registry), cancellation: cancellation.clone(),
                };
                queue_ready.recv(&cx).await.unwrap();
                let writes = AtomicUsize::new(0);
                let shutdown = HttpListenerShutdown::new(&cx);
                let mut framed = Framed::new(writer, native_http1_codec(&bound.endpoint));
                let mut byte = [0_u8; 1];
                let mut delivery = Box::pin(deliver_buffered_response(
                    &cx, dispatch, receiver, reader.read(&mut byte), HttpResponse::internal_error(),
                    |response| {
                        writes.fetch_add(1, Ordering::SeqCst);
                        write_buffered(&cx, &shutdown, &mut framed, response, None, SecuredHttpIoLimits::default())
                    },
                ));
                poll_fn(|task| {
                    assert!(delivery.as_mut().poll(task).is_pending(), "queued response must still join its child");
                    Poll::Ready(())
                }).await;
                assert_eq!(writes.load(Ordering::SeqCst), 0);
                assert!(!cancellation.is_cancel_requested());
                drop(peer); // Real FIN, not a fabricated read result or Cx abort.
                let result = asupersync::time::timeout(
                    cx.now(), Duration::from_secs(2), delivery.as_mut(),
                ).await;
                drop(delivery);
                let _ = release.send_blocking(());
                let mut retired = registry.take_retired_dispatches();
                assert_eq!(retired.len(), 1, "disconnect retains the unfinished child for settlement");
                let _ = asupersync::time::timeout(
                    cx.now(), Duration::from_secs(2), retired[0].join(&cx),
                ).await.expect("retired child settles after release");
                assert_eq!(result.expect("peer monitoring must remain active during join"), Err(()));
                assert_eq!(writes.load(Ordering::SeqCst), 0, "no buffered response starts after EOF");
                assert!(cancellation.is_cancel_requested());
                assert!(!sibling.is_cancelled());
                assert!(cx.checkpoint().is_ok());
            });
    }

    #[test]
    fn buffered_delivery_owns_pending_write_after_child_settlement() {
        for finalized in [false, true] {
            for abandon in [false, true] {
                let cx = Cx::for_testing();
                let cancellation = McpRequestCancellation::new();
                if finalized { assert!(cancellation.begin_finalization()); }
                let registry = Arc::new(crate::LiveModernHttpSessionRegistryState::new());
                // The producer has already joined; its guard can no longer be
                // relied on to signal loss of response ownership.
                let dispatch = OwnedJsonDispatch {
                    task: None, sessions: Arc::clone(&registry), cancellation: cancellation.clone(),
                };
                let (sender, receiver) = asupersync::channel::oneshot::channel();
                sender.send_blocking(HttpResponse::new(HttpStatus(201))).unwrap();
                let disconnected = AtomicBool::new(false);
                let peer = Tracked::new(poll_fn(|_| {
                    if disconnected.load(Ordering::SeqCst) { Poll::Ready(Ok(0)) }
                    else { Poll::Pending }
                }));
                let peer_drops = Arc::clone(&peer.drops);
                let write = Tracked::new(pending::<Result<(), ()>>());
                let write_polls = Arc::clone(&write.polls);
                let write_drops = Arc::clone(&write.drops);
                let starts = AtomicUsize::new(0);
                let mut delivery = Box::pin(deliver_buffered_response(
                    &cx, dispatch, receiver, peer, HttpResponse::internal_error(),
                    |response| {
                        assert_eq!(response.status.0, 201);
                        starts.fetch_add(1, Ordering::SeqCst);
                        write
                    },
                ));
                let mut task = Context::from_waker(Waker::noop());
                assert!(delivery.as_mut().poll(&mut task).is_pending());
                assert!(delivery.as_mut().poll(&mut task).is_pending());
                assert_eq!(starts.load(Ordering::SeqCst), 1, "never recreate a partially completed write");
                assert_eq!(write_polls.load(Ordering::SeqCst), 2);
                assert!(!cancellation.is_cancel_requested());
                if !abandon {
                    disconnected.store(true, Ordering::SeqCst);
                    assert_eq!(delivery.as_mut().poll(&mut task), Poll::Ready(Err(())));
                }
                drop(delivery);
                assert_eq!(write_polls.load(Ordering::SeqCst), 2, "no further write poll after observed EOF");
                assert_eq!(write_drops.load(Ordering::SeqCst), 1);
                assert_eq!(peer_drops.load(Ordering::SeqCst), 1);
                assert_eq!(cancellation.is_cancel_requested(), !finalized);
                assert_eq!(cancellation.is_finalizing(), finalized);
                assert!(registry.retired_dispatches.lock().unwrap().is_empty());
                assert!(cx.checkpoint().is_ok());
            }
        }
    }

    #[derive(Clone, Copy)]
    enum BufferedWriteMode { Complete, Fail, Stall }

    struct BufferedTestWriter {
        mode: BufferedWriteMode,
        bytes: Vec<u8>,
    }

    impl asupersync::io::AsyncWrite for BufferedTestWriter {
        fn poll_write(mut self: Pin<&mut Self>, _: &mut Context<'_>, bytes: &[u8]) -> Poll<io::Result<usize>> {
            if !self.bytes.is_empty() {
                match self.mode {
                    BufferedWriteMode::Fail => return Poll::Ready(Err(io::ErrorKind::BrokenPipe.into())),
                    BufferedWriteMode::Stall => return Poll::Pending,
                    BufferedWriteMode::Complete => {},
                }
            }
            let count = bytes.len().min(3);
            self.bytes.extend_from_slice(&bytes[..count]);
            Poll::Ready(Ok(count))
        }
        fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> { Poll::Ready(Ok(())) }
        fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> { Poll::Ready(Ok(())) }
    }

    #[test]
    fn buffered_delivery_checks_real_partial_writes_errors_and_timeouts() {
        asupersync::runtime::RuntimeBuilder::current_thread()
            .with_reactor(asupersync::runtime::reactor::create_reactor().unwrap())
            .build().unwrap().block_on(async {
                let cx = Cx::current().unwrap();
                let bound = Server::new("buffered-write-result", "1")
                    .protocol_policy(fastmcp_protocol::protocol_policy::ProtocolPolicy::ModernOnly).unwrap()
                    .build().bind_http(&cx, "127.0.0.1:0").await.unwrap();
                for finalized in [false, true] {
                    for mode in [BufferedWriteMode::Complete, BufferedWriteMode::Fail, BufferedWriteMode::Stall] {
                        let cancellation = McpRequestCancellation::new();
                        if finalized { assert!(cancellation.begin_finalization()); }
                        let registry = Arc::clone(&bound.modern_sessions);
                        let child = cx.spawn(|_| async {}).unwrap();
                        let mut dispatch = OwnedJsonDispatch {
                            task: Some(child), sessions: Arc::clone(&registry), cancellation: cancellation.clone(),
                        };
                        assert!(dispatch.finish(&cx).await);
                        let (sender, receiver) = asupersync::channel::oneshot::channel();
                        sender.send_blocking(HttpResponse::new(HttpStatus(201))).unwrap();
                        let writer = BufferedTestWriter { mode, bytes: Vec::new() };
                        let mut framed = Framed::new(writer, native_http1_codec(&bound.endpoint));
                        let shutdown = HttpListenerShutdown::new(&cx);
                        let io = SecuredHttpIoLimits::new(Duration::from_secs(1), Duration::from_millis(20)).unwrap();
                        let result = asupersync::time::timeout(cx.now(), Duration::from_secs(2),
                            deliver_buffered_response(
                                &cx, dispatch, receiver, pending::<io::Result<usize>>(), HttpResponse::internal_error(),
                                |response| write_buffered(&cx, &shutdown, &mut framed, response, None, io),
                            ),
                        ).await.expect("bounded final response write");
                        let complete = matches!(mode, BufferedWriteMode::Complete);
                        assert_eq!(result.is_ok(), complete, "a partial/failed response is not successful delivery");
                        let bytes = framed.into_inner().bytes;
                        if complete {
                            assert!(bytes.starts_with(b"HTTP/1.1 201"));
                            assert!(bytes.ends_with(b"\r\n\r\n"));
                        } else {
                            assert_eq!(bytes, b"HTT", "a failed short write is not restarted or replaced with a 500");
                        }
                        assert_eq!(cancellation.is_cancel_requested(), !complete && !finalized);
                        assert_eq!(cancellation.is_finalizing(), finalized);
                        assert!(registry.retired_dispatches.lock().unwrap().is_empty());
                        assert!(cx.checkpoint().is_ok());
                    }
                }
            });
    }

    #[test]
    fn buffered_delivery_preserves_fallback_response_when_producer_closes_without_a_value() {
        let cx = Cx::for_testing();
        for status in [500, 503] {
            let cancellation = McpRequestCancellation::new();
            let dispatch = OwnedJsonDispatch {
                task: None, sessions: Arc::new(crate::LiveModernHttpSessionRegistryState::new()),
                cancellation: cancellation.clone(),
            };
            let (sender, receiver) = asupersync::channel::oneshot::channel::<HttpResponse>();
            drop(sender);
            let mut delivery = Box::pin(deliver_buffered_response(
                &cx, dispatch, receiver, pending::<io::Result<usize>>(),
                HttpResponse::new(HttpStatus(status)).with_header("cache-control", "no-store"),
                |response| {
                    assert_eq!(response.status.0, status);
                    assert_eq!(response.headers.get("cache-control").map(String::as_str), Some("no-store"));
                    ready(Ok(()))
                },
            ));
            let mut task = Context::from_waker(Waker::noop());
            assert_eq!(delivery.as_mut().poll(&mut task), Poll::Ready(Ok(())));
            drop(delivery);
            assert!(!cancellation.is_cancel_requested());
        }
    }

    #[test]
    fn secured_sse_peer_wakeup_interrupts_an_idle_response() {
        use std::sync::Mutex;
        struct WakeFlag(AtomicBool);
        impl Wake for WakeFlag {
            fn wake(self: Arc<Self>) { self.0.store(true, Ordering::SeqCst); }
        }
        let cancelled = McpRequestCancellation::new();
        let reset = Arc::new(AtomicBool::new(false));
        let waiter = Arc::new(Mutex::new(None::<Waker>));
        let peer_reset = Arc::clone(&reset);
        let peer_waiter = Arc::clone(&waiter);
        let peer = poll_fn(move |task| {
            if peer_reset.load(Ordering::SeqCst) {
                Poll::Ready(Err(io::Error::from(io::ErrorKind::ConnectionReset)))
            } else {
                *peer_waiter.lock().unwrap() = Some(task.waker().clone());
                Poll::Pending
            }
        });
        let response = Tracked::new(pending::<Result<(), ()>>());
        let polls = Arc::clone(&response.polls);
        let drops = Arc::clone(&response.drops);
        let flag = Arc::new(WakeFlag(AtomicBool::new(false)));
        let waker = Waker::from(Arc::clone(&flag));
        let mut task = Context::from_waker(&waker);
        let mut work = Box::pin(monitor_response_peer(&cancelled, peer, response));
        assert!(work.as_mut().poll(&mut task).is_pending());
        assert_eq!(polls.load(Ordering::SeqCst), 1);
        reset.store(true, Ordering::SeqCst);
        waiter.lock().unwrap().take().unwrap().wake();
        assert!(flag.0.load(Ordering::SeqCst));
        assert_eq!(work.as_mut().poll(&mut task), Poll::Ready(Err(())));
        drop(work);
        assert!(cancelled.is_cancel_requested());
        assert_eq!(polls.load(Ordering::SeqCst), 1, "idle response is not polled after reset");
        assert_eq!(drops.load(Ordering::SeqCst), 1);
    }
}
