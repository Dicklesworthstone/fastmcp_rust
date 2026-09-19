//! Typed, incremental core responses for machine-to-machine OAuth clients.
//!
//! This composes the existing same-token client-credentials discovery/dispatch
//! path with the same core result and notification validator used by interactive
//! OAuth clients. Basic and private-key JWT authentication use this one path.
//! Neither progress, input-required results, nor transport errors replay a POST.
//!
//! The deadline covers preflight, credential acquisition, resource discovery,
//! dispatch, and every body read. Credential expiry, local revocation and owner
//! closure remain enforced by the original machine credential snapshot. This
//! does not negotiate Tasks, Apps, or subscriptions.

/// Complete, bounded and invalidation-aware machine catalog discovery.
pub mod catalog;
/// Explicit, bounded host-driven input-required continuations.
pub mod interaction;
/// Bounded resource reads with opt-in, credential-local result caching.
pub mod resource;

use std::fmt;

use asupersync::Cx;
use asupersync::types::Time;
use fastmcp_core::{CanonicalHttpUrl, McpRequestCancellation};
use fastmcp_protocol::protocol_policy::ProtocolEra;
use fastmcp_protocol::{CoreRequest, RequestId};

use super::{
    ClientCredentialsClient, ClientCredentialsError, ClientCredentialsResponse,
    ClientCredentialsSnapshot, active, discovery_deadline, prepare,
};
use crate::http_auth::rpc::{CoreDecoder, ManagedCoreError};
use crate::http_executor::{
    ModernHttpResponseKind, ModernHttpResponseStream, ModernHttpSseResponseStream,
};
use crate::sse::SseLimits;

// Match the Tasks machine-client API: share the already-public event and limit
// vocabulary instead of defining a parallel set of protocol/result types.
pub use crate::http_auth::rpc::{ManagedCoreEvent, ManagedCoreLimits};

/// Sanitized authentication or core-protocol failure. Peer error messages,
/// malformed input, credential values and result payloads are not retained.
#[derive(Debug)]
pub enum ClientCredentialsCoreError {
    Authentication(ClientCredentialsError),
    Protocol(ManagedCoreError),
}

impl fmt::Display for ClientCredentialsCoreError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Authentication(error) => fmt::Display::fmt(error, formatter),
            Self::Protocol(error) => fmt::Display::fmt(error, formatter),
        }
    }
}

impl std::error::Error for ClientCredentialsCoreError {}

impl From<ClientCredentialsError> for ClientCredentialsCoreError {
    fn from(error: ClientCredentialsError) -> Self {
        Self::Authentication(error)
    }
}

impl From<ManagedCoreError> for ClientCredentialsCoreError {
    fn from(error: ManagedCoreError) -> Self {
        Self::Protocol(error)
    }
}

impl ClientCredentialsClient {
    /// Sends one core operation after fresh discovery under the same credential.
    /// Both encoded request documents must fit the supplied request limit before
    /// a credential can be acquired or either POST can be dispatched.
    ///
    /// Consume the returned call with [`ClientCredentialsCoreCall::next_event`].
    /// Keep a client clone alive while doing so: dropping the last machine
    /// client closes its credential owner and retires outstanding responses.
    pub async fn request_core(
        &self,
        cx: &Cx,
        request: CoreRequest,
        discovery_id: RequestId,
        request_id: RequestId,
        limits: ManagedCoreLimits,
    ) -> Result<ClientCredentialsCoreCall, ClientCredentialsCoreError> {
        self.request_core_with_cancellation(
            cx,
            &McpRequestCancellation::new(),
            request,
            discovery_id,
            request_id,
            limits,
        )
        .await
    }

    /// Request-local cancellation spans acquisition, discovery and incremental
    /// response reads. It does not cancel sibling calls or send a modern HTTP
    /// cancellation notification. Cancellation after dispatch does not establish
    /// that the remote operation was undone.
    pub async fn request_core_with_cancellation(
        &self,
        cx: &Cx,
        cancellation: &McpRequestCancellation,
        request: CoreRequest,
        discovery_id: RequestId,
        request_id: RequestId,
        limits: ManagedCoreLimits,
    ) -> Result<ClientCredentialsCoreCall, ClientCredentialsCoreError> {
        let deadline = discovery_deadline(cx, limits.timeout().min(self.inner.timeout))
            .map_err(ClientCredentialsError::from)?;
        preflight(self.resource(), &request, &discovery_id, &request_id, limits)?;
        let response = active(
            cx,
            deadline,
            &self.inner.closed,
            cancellation,
            None,
            self.execute_core_with_cancellation(cx, cancellation, request, discovery_id, request_id),
        )
        .await?;
        ClientCredentialsCoreCall::from_response(response, limits, deadline)
    }
}

/// Preflight uses the actual client-credentials encoder, including its explicit
/// auth extension stamp, rather than measuring the unstamped caller document.
fn preflight(
    resource: &CanonicalHttpUrl,
    request: &CoreRequest,
    discovery_id: &RequestId,
    request_id: &RequestId,
    limits: ManagedCoreLimits,
) -> Result<(), ClientCredentialsCoreError> {
    discovery_id.validate().map_err(|_| ManagedCoreError::InvalidRequest)?;
    if discovery_id.correlates_with(request_id) {
        return Err(ManagedCoreError::InvalidRequest.into());
    }
    let (wire, stamped) = prepare(resource, request, request_id)?;
    if wire.body().len() > limits.request_bytes() {
        return Err(ManagedCoreError::RequestTooLarge.into());
    }
    let params = stamped.encode_params().map_err(|_| ManagedCoreError::InvalidRequest)?
        .ok_or(ManagedCoreError::InvalidRequest)?;
    let discovery = CoreRequest::decode(
        ProtocolEra::Modern2026,
        "server/discover",
        Some(&serde_json::json!({"_meta": params["_meta"]})),
    )
    .map_err(|_| ManagedCoreError::InvalidRequest)?;
    let (wire, _) = prepare(resource, &discovery, discovery_id)?;
    if wire.body().len() > limits.request_bytes() {
        return Err(ManagedCoreError::RequestTooLarge.into());
    }
    Ok(())
}

enum Body {
    Json(ModernHttpResponseStream),
    Sse(ModernHttpSseResponseStream),
}

/// One owned core response. JSON and SSE produce the same typed result, with
/// exact-number/unknown-member preservation and explicit input-required results.
/// Notifications are delivered in wire order before the terminal result.
///
/// A started read takes ownership of the body before suspension. Dropping that
/// future, encountering an error, closing the call, or exhausting its lifetime
/// closes the body instead of leaving a partially consumed parser reusable.
/// Only delivery of a terminal result permits subsequent `Ok(None)`.
pub struct ClientCredentialsCoreCall {
    body: Option<Box<Body>>,
    decoder: CoreDecoder,
    snapshot: ClientCredentialsSnapshot,
    owner: McpRequestCancellation,
    cancellation: McpRequestCancellation,
    request_id: RequestId,
    deadline: Time,
    limits: ManagedCoreLimits,
    finished: bool,
}

impl ClientCredentialsCoreCall {
    fn from_response(
        response: ClientCredentialsResponse,
        limits: ManagedCoreLimits,
        deadline: Time,
    ) -> Result<Self, ClientCredentialsCoreError> {
        if response.metadata().status() != 200 {
            return Err(ManagedCoreError::HttpStatus { status: response.metadata().status() }.into());
        }
        let ClientCredentialsResponse {
            response, snapshot, owner, cancellation, request, request_id,
            deadline: dispatch_deadline,
        } = response;
        let decoder = CoreDecoder::for_request(request, request_id.clone(), limits)?;
        let body = match response.metadata().kind() {
            ModernHttpResponseKind::Json => Body::Json(response),
            ModernHttpResponseKind::Sse => {
                let frame = limits.frame_bytes();
                let framing = SseLimits::new(frame + 16, frame + 64, 64)
                    .ok_or(ManagedCoreError::InvalidLimits)?;
                Body::Sse(response.into_sse_stream(framing)
                    .map_err(|_| ManagedCoreError::InvalidResponse)?)
            }
            _ => return Err(ManagedCoreError::InvalidResponse.into()),
        };
        Ok(Self {
            body: Some(Box::new(body)), decoder, snapshot, owner, cancellation,
            request_id, deadline: deadline.min(dispatch_deadline), limits, finished: false,
        })
    }

    pub fn request_id(&self) -> &RequestId {
        &self.request_id
    }

    /// Local credential generation, not an identity or cross-client cache key.
    pub fn credential_generation(&self) -> u64 {
        self.snapshot.generation()
    }

    pub fn close(&mut self) {
        self.body = None;
    }

    pub async fn next_event(
        &mut self,
        cx: &Cx,
    ) -> Result<Option<ManagedCoreEvent>, ClientCredentialsCoreError> {
        if self.finished {
            return Ok(None);
        }
        let body = self.body.take().ok_or(ManagedCoreError::Closed)?;
        let decoder = &mut self.decoder;
        let maximum = self.limits.frame_bytes();
        let cancellation = &self.cancellation;
        let read = async {
            let (source, remaining) = match *body {
                Body::Json(response) => {
                    let bytes = response.read_to_end_with_cancellation(cx, cancellation, maximum)
                        .await.map_err(|_| ClientCredentialsError::UnexpectedResponse)?;
                    (bytes, None)
                }
                Body::Sse(mut stream) => {
                    let source = stream.next_event(cx).await
                        .map_err(|_| ClientCredentialsError::UnexpectedResponse)?
                        .ok_or(ManagedCoreError::MissingTerminal)?;
                    (source.into_bytes(), Some(Box::new(Body::Sse(stream))))
                }
            };
            let event = decoder.admit(&source, remaining.is_some())?;
            Ok::<_, ClientCredentialsCoreError>((event, remaining))
        };
        // Keep protocol admission inside active(): expiry or revocation during
        // decoding cannot turn into a successfully delivered result. The nested
        // Result retains the shared decoder's typed protocol failures.
        let (event, remaining) = active(
            cx, self.deadline, &self.owner, cancellation, Some(&self.snapshot),
            async { Ok(read.await) },
        )
        .await??;
        match &event {
            ManagedCoreEvent::Result(_) => self.finished = true,
            ManagedCoreEvent::Notification(_) => self.body = remaining,
        }
        Ok(Some(event))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    use fastmcp_protocol::{ClientCapabilities, CoreResult, FinalRequestMeta};
    use serde_json::{Value, json};

    use super::super::CLIENT_CREDENTIALS_EXTENSION;

    fn resource() -> CanonicalHttpUrl {
        CanonicalHttpUrl::parse("https://machine.example/mcp").unwrap()
    }

    fn request(method: &str, mut params: Value) -> CoreRequest {
        params["_meta"] = serde_json::to_value(FinalRequestMeta::new(ClientCapabilities::default())).unwrap();
        CoreRequest::decode(ProtocolEra::Modern2026, method, Some(&params)).unwrap()
    }

    fn decoder(method: &str, params: Value, limits: ManagedCoreLimits) -> CoreDecoder {
        let (_, stamped) = prepare(&resource(), &request(method, params), &RequestId::Number(7)).unwrap();
        CoreDecoder::for_request(stamped, RequestId::Number(7), limits).unwrap()
    }

    fn terminal(result: &str) -> Vec<u8> {
        format!(r#"{{"jsonrpc":"2.0","id":7,"result":{result}}}"#).into_bytes()
    }

    #[test]
    fn preflight_measures_both_stamped_documents_and_rejects_reused_ids() {
        let core = request("tools/list", json!({}));
        let id = RequestId::Number(7);
        let discovery_id = RequestId::String("discovery-with-a-longer-correlation-identity".to_owned());
        let (wire, _) = prepare(&resource(), &core, &id).unwrap();
        let body: Value = serde_json::from_slice(wire.body()).unwrap();
        assert_eq!(body["params"]["_meta"]["io.modelcontextprotocol/clientCapabilities"]["extensions"],
            json!({CLIENT_CREDENTIALS_EXTENSION: {}}));
        assert!(preflight(&resource(), &core, &discovery_id, &id, ManagedCoreLimits::default()).is_ok());
        let exact_operation_only = ManagedCoreLimits::new(
            wire.body().len(), 1024, 1024, 1, Duration::from_secs(1),
        ).unwrap();
        assert!(matches!(preflight(&resource(), &core, &discovery_id, &id, exact_operation_only),
            Err(ClientCredentialsCoreError::Protocol(ManagedCoreError::RequestTooLarge))));
        assert!(matches!(preflight(&resource(), &core, &id, &id, ManagedCoreLimits::default()),
            Err(ClientCredentialsCoreError::Protocol(ManagedCoreError::InvalidRequest))));
        let tiny = ManagedCoreLimits::new(1, 1024, 1024, 1, Duration::from_secs(1)).unwrap();
        assert!(matches!(preflight(&resource(), &core, &discovery_id, &id, tiny),
            Err(ClientCredentialsCoreError::Protocol(ManagedCoreError::RequestTooLarge))));
    }

    #[test]
    fn machine_profile_stays_core_only_even_when_other_extensions_are_compiled() {
        let mut params = request("tools/call", json!({"name":"echo"})).encode_params().unwrap().unwrap();
        params["_meta"]["io.modelcontextprotocol/clientCapabilities"]["extensions"] =
            json!({"io.modelcontextprotocol/tasks": {}});
        let core = CoreRequest::decode(ProtocolEra::Modern2026, "tools/call", Some(&params)).unwrap();
        assert!(preflight(&resource(), &core, &RequestId::Number(6), &RequestId::Number(7),
            ManagedCoreLimits::default()).is_err());
        let mut decoder = decoder("tools/call", json!({"name":"echo"}), ManagedCoreLimits::default());
        assert!(matches!(decoder.admit(&terminal(r#"{"resultType":"task"}"#), true),
            Err(ManagedCoreError::UnsupportedResult)));
    }

    #[test]
    fn machine_json_and_sse_preserve_exact_result_payloads() {
        let result = r#"{"resultType":"complete","tools":[],"ttlMs":0,"cacheScope":"private","x-exact":{"z":900719925474099312345,"a":1.20e+4}}"#;
        for sse in [false, true] {
            let mut decoder = decoder("tools/list", json!({}), ManagedCoreLimits::default());
            let ManagedCoreEvent::Result(result) = decoder.admit(&terminal(result), sse).unwrap()
                else { panic!("expected typed result") };
            let encoded = result.encode().unwrap();
            assert!(encoded.contains("900719925474099312345"));
            assert!(encoded.contains("1.20e+4"));
            assert!(encoded.find("\"z\"").unwrap() < encoded.find("\"a\"").unwrap());
        }
    }

    #[test]
    fn machine_progress_uses_the_original_request_marker_and_monotonic_order() {
        let mut params = request("tools/call", json!({"name":"echo"})).encode_params().unwrap().unwrap();
        params["_meta"]["progressToken"] = json!("owned-progress");
        let core = CoreRequest::decode(ProtocolEra::Modern2026, "tools/call", Some(&params)).unwrap();
        let (_, stamped) = prepare(&resource(), &core, &RequestId::Number(7)).unwrap();
        let mut decoder = CoreDecoder::for_request(stamped, RequestId::Number(7), ManagedCoreLimits::default()).unwrap();
        let update = |token: &str, progress: u64| serde_json::to_vec(&json!({
            "jsonrpc":"2.0", "method":"notifications/progress",
            "params":{"progressToken":token, "progress":progress},
        })).unwrap();
        assert!(matches!(decoder.admit(&update("owned-progress", 1), true), Ok(ManagedCoreEvent::Notification(_))));
        assert!(matches!(decoder.admit(&update("foreign-progress", 2), true), Err(ManagedCoreError::InvalidProgress)));
        assert!(matches!(decoder.admit(&update("owned-progress", 1), true), Err(ManagedCoreError::InvalidProgress)));
        assert!(matches!(decoder.admit(&update("owned-progress", 2), true), Ok(ManagedCoreEvent::Notification(_))));
        assert!(matches!(decoder.admit(&terminal(r#"{"resultType":"complete","content":[]}"#), true), Ok(ManagedCoreEvent::Result(_))));
    }

    #[test]
    fn machine_input_required_remains_an_explicit_typed_terminal() {
        let mut decoder = decoder("resources/read", json!({"uri":"file:///sample"}), ManagedCoreLimits::default());
        let result = terminal(r#"{"resultType":"input_required","inputRequests":{"roots":{"method":"roots/list"}},"requestState":"opaque-state"}"#);
        let ManagedCoreEvent::Result(result) = decoder.admit(&result, true).unwrap()
            else { panic!("expected input-required result") };
        assert!(matches!(*result, CoreResult::Final(fastmcp_protocol::FinalCoreResult::ResourcesReadInputRequired { .. })));
    }

    #[test]
    fn machine_notification_and_payload_limits_still_reserve_a_terminal_result() {
        let limits = ManagedCoreLimits::new(1024, 1024, 2048, 1, Duration::from_secs(1)).unwrap();
        let mut decoder = decoder("tools/list", json!({}), limits);
        let notification = br#"{"jsonrpc":"2.0","method":"notifications/tools/list_changed"}"#;
        assert!(matches!(decoder.admit(notification, true), Ok(ManagedCoreEvent::Notification(_))));
        assert!(matches!(decoder.admit(notification, true), Err(ManagedCoreError::NotificationLimit)));
        assert!(matches!(decoder.admit(&terminal(r#"{"resultType":"complete","tools":[],"ttlMs":0,"cacheScope":"private"}"#), true),
            Ok(ManagedCoreEvent::Result(_))));
        let mut bounded = self::decoder("tools/list", json!({}), limits);
        assert!(matches!(bounded.admit(&vec![b' '; 1025], true), Err(ManagedCoreError::ResponseByteLimit)));
    }

    #[test]
    fn machine_frames_reject_wrong_ids_duplicate_fields_and_reverse_requests() {
        for frame in [
            r#"{"jsonrpc":"2.0","id":8,"result":{}}"#,
            r#"{"jsonrpc":"2.0","id":"7","result":{}}"#,
            r#"{"jsonrpc":"2.0","id":7,"id":7,"result":{}}"#,
            r#"{"jsonrpc":"2.0","id":7,"method":"roots/list"}"#,
            r#"[{"jsonrpc":"2.0","id":7,"result":{}}]"#,
        ] {
            let mut decoder = decoder("tools/list", json!({}), ManagedCoreLimits::default());
            assert!(decoder.admit(frame.as_bytes(), true).is_err());
        }
    }

    // These tests isolate the shipped native response pipeline and credential
    // lifetime checks. The loopback peer is not an OAuth issuer: acquisition,
    // HTTPS credential delivery and discovery negotiation are not proved here.
    fn runtime() -> asupersync::runtime::Runtime {
        asupersync::runtime::RuntimeBuilder::current_thread()
            .with_reactor(asupersync::runtime::reactor::create_reactor().unwrap())
            .blocking_threads(0, 2)
            .build()
            .unwrap()
    }

    async fn native_response(
        cx: &Cx,
        body: &'static str,
        content_type: &'static str,
        hold_partial_body: bool,
    ) -> (ClientCredentialsResponse, std::thread::JoinHandle<()>) {
        use std::io::{BufRead, Read, Write};
        use std::net::TcpListener;
        use std::time::Instant;

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        listener.set_nonblocking(true).unwrap();
        let peer = std::thread::spawn(move || {
            let deadline = Instant::now() + Duration::from_secs(5);
            let mut socket = loop {
                match listener.accept() {
                    Ok((socket, _)) => break socket,
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        assert!(Instant::now() < deadline, "native response peer was never contacted");
                        std::thread::sleep(Duration::from_millis(1));
                    }
                    Err(error) => panic!("accept failed: {error}"),
                }
            };
            socket.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
            socket.set_write_timeout(Some(Duration::from_secs(5))).unwrap();
            {
                let mut reader = std::io::BufReader::new(&mut socket);
                let mut length = None;
                let mut header_bytes = 0;
                loop {
                    let mut line = String::new();
                    assert_ne!(reader.read_line(&mut line).unwrap(), 0);
                    header_bytes += line.len();
                    assert!(header_bytes <= 32 * 1024);
                    if line == "\r\n" { break; }
                    if let Some((name, value)) = line.split_once(':')
                        && name.eq_ignore_ascii_case("content-length")
                    {
                        length = Some(value.trim().parse::<usize>().unwrap());
                    }
                }
                let length = length.expect("request has a bounded content length");
                assert!(length < 8192);
                let mut request = vec![0; length];
                reader.read_exact(&mut request).unwrap();
            }
            let length = body.len() + if hold_partial_body { 100 } else { 0 };
            write!(socket,
                "HTTP/1.1 200 OK\r\nContent-Type: {content_type}\r\nContent-Length: {length}\r\nMCP-Protocol-Version: 2026-07-28\r\nConnection: close\r\n\r\n{body}"
            ).unwrap();
            socket.flush().unwrap();
            if hold_partial_body {
                // A dropped pending read must release its real socket. The
                // read timeout makes a missing close a bounded test failure.
                let mut byte = [0];
                match socket.read(&mut byte) {
                    Ok(0) => {},
                    Err(error) if matches!(error.kind(),
                        std::io::ErrorKind::ConnectionReset | std::io::ErrorKind::ConnectionAborted) => {},
                    other => panic!("abandoned response did not close its socket: {other:?}"),
                }
            }
        });
        let request = request("tools/list", json!({}));
        let request_id = RequestId::Number(7);
        let (wire, request) = prepare(&resource(), &request, &request_id).unwrap();
        let loopback = crate::http_executor::ModernHttpRequest::new(
            &format!("http://{address}/mcp"), wire.body().to_vec(),
            fastmcp_protocol::FINAL_PROTOCOL_VERSION, "tools/list", None,
        ).unwrap();
        let cancellation = McpRequestCancellation::new();
        let response = crate::http_executor::ModernHttpExecutor::new()
            .execute_with_cancellation(cx, &cancellation, &loopback).await.unwrap();
        let owner = McpRequestCancellation::new();
        let expires_at = Instant::now() + Duration::from_secs(60);
        let bearer = crate::http_auth::BoundBearerCredential::bind_with_expiry(
            resource(), "response-lifetime-test-token", expires_at,
        ).unwrap().for_owner(&owner).unwrap();
        let snapshot = ClientCredentialsSnapshot {
            bearer, scopes: vec![], expires_at, generation: 1,
        };
        (ClientCredentialsResponse {
            response, snapshot, owner, cancellation, request, request_id,
            deadline: discovery_deadline(cx, Duration::from_secs(5)).unwrap(),
        }, peer)
    }

    #[test]
    fn native_machine_json_and_sse_deliver_one_typed_terminal() {
        runtime().block_on(async {
            let cx = Cx::current().unwrap();
            for (body, content_type, notification) in [
                (r#"{"jsonrpc":"2.0","id":7,"result":{"resultType":"complete","tools":[],"ttlMs":0,"cacheScope":"private"}}"#,
                    "application/json", false),
                (concat!(
                    "data: {\"jsonrpc\":\"2.0\",\"method\":\"notifications/tools/list_changed\"}\n\n",
                    "data: {\"jsonrpc\":\"2.0\",\"id\":7,\"result\":{\"resultType\":\"complete\",\"tools\":[],\"ttlMs\":0,\"cacheScope\":\"private\"}}\n\n"
                ), "text/event-stream", true),
            ] {
                let (response, peer) = native_response(&cx, body, content_type, false).await;
                let deadline = response.deadline;
                let mut call = ClientCredentialsCoreCall::from_response(response, ManagedCoreLimits::default(), deadline).unwrap();
                assert_eq!(call.request_id(), &RequestId::Number(7));
                assert_eq!(call.credential_generation(), 1);
                if notification {
                    assert!(matches!(call.next_event(&cx).await.unwrap(), Some(ManagedCoreEvent::Notification(_))));
                }
                assert!(matches!(call.next_event(&cx).await.unwrap(), Some(ManagedCoreEvent::Result(_))));
                assert!(call.next_event(&cx).await.unwrap().is_none());
                peer.join().unwrap();
            }
        });
    }

    #[test]
    fn native_machine_sse_eof_without_a_terminal_is_not_success() {
        runtime().block_on(async {
            let cx = Cx::current().unwrap();
            let (response, peer) = native_response(&cx,
                "data: {\"jsonrpc\":\"2.0\",\"method\":\"notifications/tools/list_changed\"}\n\n",
                "text/event-stream", false).await;
            let deadline = response.deadline;
            let mut call = ClientCredentialsCoreCall::from_response(response, ManagedCoreLimits::default(), deadline).unwrap();
            assert!(matches!(call.next_event(&cx).await.unwrap(), Some(ManagedCoreEvent::Notification(_))));
            assert!(matches!(call.next_event(&cx).await,
                Err(ClientCredentialsCoreError::Protocol(ManagedCoreError::MissingTerminal))));
            assert!(matches!(call.next_event(&cx).await,
                Err(ClientCredentialsCoreError::Protocol(ManagedCoreError::Closed))));
            peer.join().unwrap();
        });
    }

    #[test]
    fn native_machine_buffered_results_cannot_outlive_cancellation_or_credentials() {
        runtime().block_on(async {
            let cx = Cx::current().unwrap();
            for case in 0..5 {
                let (mut response, peer) = native_response(&cx,
                    r#"{"jsonrpc":"2.0","id":7,"result":{"resultType":"complete","tools":[],"ttlMs":0,"cacheScope":"private"}}"#,
                    "application/json", false).await;
                match case {
                    0 => { response.cancellation.cancel(); },
                    1 => { response.owner.cancel(); },
                    2 => { response.snapshot.bearer.revoke(); },
                    3 => response.snapshot.expires_at = std::time::Instant::now(),
                    _ => response.deadline = cx.now(),
                }
                let deadline = response.deadline;
                let mut call = ClientCredentialsCoreCall::from_response(response, ManagedCoreLimits::default(), deadline).unwrap();
                assert!(call.next_event(&cx).await.is_err());
                assert!(matches!(call.next_event(&cx).await,
                    Err(ClientCredentialsCoreError::Protocol(ManagedCoreError::Closed))));
                peer.join().unwrap();
            }
        });
    }

    #[test]
    fn native_machine_abandoned_pending_read_retires_the_real_body() {
        use std::future::{Future, poll_fn};
        use std::task::Poll;

        runtime().block_on(async {
            let cx = Cx::current().unwrap();
            let (response, peer) = native_response(&cx, "data: {", "text/event-stream", true).await;
            let deadline = response.deadline;
            let mut call = ClientCredentialsCoreCall::from_response(response, ManagedCoreLimits::default(), deadline).unwrap();
            {
                let mut pending = std::pin::pin!(call.next_event(&cx));
                poll_fn(|task| match pending.as_mut().poll(task) {
                    Poll::Pending => Poll::Ready(()),
                    Poll::Ready(_) => panic!("incomplete response should remain pending"),
                }).await;
            }
            assert!(matches!(call.next_event(&cx).await,
                Err(ClientCredentialsCoreError::Protocol(ManagedCoreError::Closed))));
            peer.join().unwrap();
        });
    }
}
