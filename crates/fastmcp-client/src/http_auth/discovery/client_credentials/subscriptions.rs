//! Core resource and catalog subscriptions for machine-to-machine OAuth.
//!
//! This path is available without the Tasks feature. Fresh discovery and the
//! listen POST use one credential snapshot. The native subscription decoder
//! owns acknowledgment ordering, filter narrowing, notification ownership and
//! terminal correlation. No reconnection, credential replacement or POST retry
//! is implicit. Caller cancellation, owner closure, credential expiry and the
//! original deadline continue to apply to every incremental response read.

use std::fmt;
use std::io::{self, Write};
use std::time::Duration;

use asupersync::Cx;
use asupersync::types::Time;
use fastmcp_core::{CanonicalHttpUrl, McpRequestCancellation};
use fastmcp_protocol::protocol_policy::ProtocolEra;
use fastmcp_protocol::{
    CoreRequest, FINAL_PROTOCOL_VERSION, FinalRequestMeta, JsonInteger, RequestId,
    SubscriptionFilter,
};
use serde_json::json;

use super::{
    ClientCredentialsClient, ClientCredentialsError, ClientCredentialsSnapshot,
    active, admit_resource, authorize, discovery_deadline, prepare,
};
use crate::http_executor::{
    ModernHttpExecutor, ModernHttpRequest, ModernHttpResponseKind,
    ModernHttpSubscriptionListenError, ModernHttpSubscriptionListener,
};
use crate::sse::SseLimits;

// Re-export the existing event vocabulary rather than inventing a second
// representation of protocol acknowledgments, notifications and terminal data.
pub use crate::http_executor::ModernHttpSubscriptionListenEvent;

/// Fixed diagnostics do not retain peer messages, payloads or credentials.
#[derive(Debug)]
pub enum ClientCredentialsCoreSubscriptionError {
    Authentication(ClientCredentialsError),
    InvalidLimits,
    InvalidRequest,
    RequestTooLarge,
    InvalidResponse,
    MissingTerminal,
    RecordLimit,
    Closed,
    Remote { code: JsonInteger },
}

impl fmt::Display for ClientCredentialsCoreSubscriptionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Authentication(_) => "machine subscription authentication or lifetime failed",
            Self::InvalidLimits => "invalid machine subscription limits",
            Self::InvalidRequest => "invalid core machine subscription request",
            Self::RequestTooLarge => "machine subscription request exceeds its byte limit",
            Self::InvalidResponse => "machine subscription response rejected",
            Self::MissingTerminal => "machine subscription ended without a terminal response",
            Self::RecordLimit => "machine subscription record limit exhausted",
            Self::Closed => "machine subscription is closed",
            Self::Remote { .. } => "machine subscription returned a remote protocol error",
        })
    }
}

impl std::error::Error for ClientCredentialsCoreSubscriptionError {}

impl From<ClientCredentialsError> for ClientCredentialsCoreSubscriptionError {
    fn from(error: ClientCredentialsError) -> Self { Self::Authentication(error) }
}

/// Bounds acquisition, discovery, listen and all later response reads.
/// Records include the acknowledgment and terminal. The machine client's
/// configured timeout and the caller's context can impose tighter deadlines.
#[derive(Clone, Copy, Debug)]
pub struct ClientCredentialsCoreSubscriptionLimits {
    request_bytes: usize,
    frame_bytes: usize,
    records: usize,
    timeout: Duration,
}

impl Default for ClientCredentialsCoreSubscriptionLimits {
    fn default() -> Self {
        Self {
            request_bytes: 64 * 1024,
            frame_bytes: 64 * 1024,
            records: 1024,
            timeout: Duration::from_mins(15),
        }
    }
}

impl ClientCredentialsCoreSubscriptionLimits {
    pub fn new(
        request_bytes: usize,
        frame_bytes: usize,
        records: usize,
        timeout: Duration,
    ) -> Result<Self, ClientCredentialsCoreSubscriptionError> {
        if !(1..=64 * 1024).contains(&request_bytes)
            || !(1..=64 * 1024).contains(&frame_bytes)
            || !(2..=4096).contains(&records)
            || timeout.is_zero()
            || timeout > Duration::from_secs(3600)
        {
            return Err(ClientCredentialsCoreSubscriptionError::InvalidLimits);
        }
        Ok(Self { request_bytes, frame_bytes, records, timeout })
    }

    pub fn request_bytes(&self) -> usize { self.request_bytes }
    pub fn frame_bytes(&self) -> usize { self.frame_bytes }
    pub fn records(&self) -> usize { self.records }
    pub fn timeout(&self) -> Duration { self.timeout }
}

impl ClientCredentialsClient {
    /// Opens a core resource/catalog subscription with explicit caller metadata.
    /// Unknown extension filters, including `taskIds` (even empty), are rejected
    /// before credential acquisition. Use the Tasks client for Tasks filters.
    /// Both request IDs must be valid and non-correlating.
    ///
    /// The first event is the server acknowledgment, including the actually
    /// accepted filter. A narrowed filter is not evidence that all requested
    /// resources are watched. Neither acknowledgment nor reconnection is a
    /// snapshot or an event-history recovery guarantee.
    #[allow(clippy::too_many_arguments)]
    pub async fn subscribe_core(
        &self,
        cx: &Cx,
        metadata: FinalRequestMeta,
        discovery_id: RequestId,
        request_id: RequestId,
        filter: SubscriptionFilter,
        limits: ClientCredentialsCoreSubscriptionLimits,
    ) -> Result<ClientCredentialsCoreSubscription, ClientCredentialsCoreSubscriptionError> {
        self.subscribe_core_with_cancellation(
            cx, &McpRequestCancellation::new(), metadata,
            discovery_id, request_id, filter, limits,
        ).await
    }

    /// Request-local cancellation spans acquisition, discovery, listen and reads.
    /// The opening credential cannot be replaced by a concurrent renewal. Keep
    /// a machine-client clone alive: dropping its last owner revokes credentials
    /// and retires outstanding streams. Closing a subscription does not cancel
    /// sibling calls or the supplied cancellation domain.
    #[allow(clippy::too_many_arguments)]
    pub async fn subscribe_core_with_cancellation(
        &self,
        cx: &Cx,
        cancellation: &McpRequestCancellation,
        metadata: FinalRequestMeta,
        discovery_id: RequestId,
        request_id: RequestId,
        filter: SubscriptionFilter,
        limits: ClientCredentialsCoreSubscriptionLimits,
    ) -> Result<ClientCredentialsCoreSubscription, ClientCredentialsCoreSubscriptionError> {
        let prepared = prepare_subscription(
            self.resource(), metadata, &discovery_id, &request_id, filter, limits,
        )?;
        let deadline = discovery_deadline(cx, limits.timeout.min(self.inner.timeout))
            .map_err(ClientCredentialsError::from)?;
        let owner = &self.inner.closed;
        active(cx, deadline, owner, cancellation, None, async {
            Ok(async {
                let snapshot = self.credential_with_cancellation(cx, cancellation).await?;
                let executor = ModernHttpExecutor::new();
                let discovery_wire = authorize(&snapshot, prepared.discovery_wire)?;
                let response = active(cx, deadline, owner, cancellation, Some(&snapshot), async {
                    executor.execute_with_cancellation(cx, cancellation, &discovery_wire).await
                        .map_err(|_| ClientCredentialsError::Transport)
                }).await?;
                if response.metadata().status() != 200
                    || response.metadata().kind() != ModernHttpResponseKind::Json
                {
                    return Err(ClientCredentialsError::Negotiation.into());
                }
                let bytes = active(cx, deadline, owner, cancellation, Some(&snapshot), async {
                    response.read_to_end_with_cancellation(cx, cancellation, limits.frame_bytes).await
                        .map_err(|_| ClientCredentialsError::UnexpectedResponse)
                }).await?;
                // Admission validates strict response identity, typed discovery,
                // protocol support and the official machine-auth extension.
                admit_resource(&prepared.discovery, &discovery_id, &bytes)?;
                let wire = authorize(&snapshot, prepared.listen_wire)?;
                let response = active(cx, deadline, owner, cancellation, Some(&snapshot), async {
                    executor.execute_with_cancellation(cx, cancellation, &wire).await
                        .map_err(|_| ClientCredentialsError::Transport)
                }).await?;
                if response.metadata().status() != 200
                    || response.metadata().kind() != ModernHttpResponseKind::Sse
                {
                    return Err(ClientCredentialsCoreSubscriptionError::InvalidResponse);
                }
                let framing = SseLimits::new(limits.frame_bytes, limits.frame_bytes, 64)
                    .ok_or(ClientCredentialsCoreSubscriptionError::InvalidLimits)?;
                let listener = response.into_final_subscriptions_listener(
                    request_id.clone(), prepared.filter, framing,
                ).map_err(subscription_error)?;
                Ok(ClientCredentialsCoreSubscription {
                    listener: Some(Box::new(listener)), snapshot, owner: owner.clone(),
                    cancellation: cancellation.clone(), request_id,
                    accepted_filter: None, deadline, limits, records: 0, finished: false,
                })
            }.await)
        }).await?
    }
}

/// One non-Clone, caller-owned subscription. A started read owns its body before
/// suspension: abandoning that future, encountering an error, closing or
/// dropping the handle releases it instead of making partial framing reusable.
pub struct ClientCredentialsCoreSubscription {
    listener: Option<Box<ModernHttpSubscriptionListener>>,
    snapshot: ClientCredentialsSnapshot,
    owner: McpRequestCancellation,
    cancellation: McpRequestCancellation,
    request_id: RequestId,
    accepted_filter: Option<SubscriptionFilter>,
    deadline: Time,
    limits: ClientCredentialsCoreSubscriptionLimits,
    records: usize,
    finished: bool,
}

impl ClientCredentialsCoreSubscription {
    pub fn request_id(&self) -> &RequestId { &self.request_id }
    pub fn credential_generation(&self) -> u64 { self.snapshot.generation() }
    pub fn accepted_filter(&self) -> Option<&SubscriptionFilter> { self.accepted_filter.as_ref() }
    pub fn records_delivered(&self) -> usize { self.records }
    pub fn is_closed(&self) -> bool { self.listener.is_none() }
    pub fn close(&mut self) { self.listener = None; }

    /// Returns `None` only after a validated terminal was delivered. EOF,
    /// cancellation, exhausted limits and malformed streams are errors, not
    /// successful completion. Native acknowledgment/filter state is published
    /// only after the opening credential and both cancellation domains pass
    /// the post-poll lifetime checks.
    pub async fn next_event(
        &mut self,
        cx: &Cx,
    ) -> Result<Option<ModernHttpSubscriptionListenEvent>, ClientCredentialsCoreSubscriptionError> {
        if self.finished { return Ok(None); }
        let mut listener = self.listener.take().ok_or(ClientCredentialsCoreSubscriptionError::Closed)?;
        let event = active(
            cx, self.deadline, &self.owner, &self.cancellation, Some(&self.snapshot), async {
                Ok(async {
                    if self.records >= self.limits.records {
                        return Err(ClientCredentialsCoreSubscriptionError::RecordLimit);
                    }
                    listener.next_event(cx).await.map_err(subscription_error)?
                        .ok_or(ClientCredentialsCoreSubscriptionError::MissingTerminal)
                }.await)
            },
        ).await??;
        // Compiling Tasks does not opt this core-only owner into Task events.
        // Retire the body rather than exposing an extension event to the caller.
        #[cfg(feature = "tasks")]
        if matches!(&event, ModernHttpSubscriptionListenEvent::TaskNotification(_)) {
            return Err(ClientCredentialsCoreSubscriptionError::InvalidResponse);
        }
        if let ModernHttpSubscriptionListenEvent::Acknowledged { accepted_filter } = &event {
            self.accepted_filter = Some(accepted_filter.clone());
        }
        self.records += 1;
        if matches!(&event, ModernHttpSubscriptionListenEvent::Terminal { .. }) {
            self.finished = true;
        } else {
            self.listener = Some(listener);
        }
        Ok(Some(event))
    }
}

struct PreparedSubscription {
    discovery: CoreRequest,
    discovery_wire: ModernHttpRequest,
    listen_wire: ModernHttpRequest,
    filter: SubscriptionFilter,
}

fn prepare_subscription(
    resource: &CanonicalHttpUrl,
    metadata: FinalRequestMeta,
    discovery_id: &RequestId,
    request_id: &RequestId,
    filter: SubscriptionFilter,
    limits: ClientCredentialsCoreSubscriptionLimits,
) -> Result<PreparedSubscription, ClientCredentialsCoreSubscriptionError> {
    discovery_id.validate().map_err(|_| ClientCredentialsCoreSubscriptionError::InvalidRequest)?;
    request_id.validate().map_err(|_| ClientCredentialsCoreSubscriptionError::InvalidRequest)?;
    if discovery_id.correlates_with(request_id) || !filter.additional.is_empty() {
        return Err(ClientCredentialsCoreSubscriptionError::InvalidRequest);
    }
    let metadata = serde_json::to_value(metadata)
        .map_err(|_| ClientCredentialsCoreSubscriptionError::InvalidRequest)?;
    let discovery = CoreRequest::decode(
        ProtocolEra::Modern2026, "server/discover", Some(&json!({"_meta": metadata})),
    ).map_err(|_| ClientCredentialsCoreSubscriptionError::InvalidRequest)?;
    // Reuse the parent's core-only auth stamping and extension validation.
    let (discovery_wire, discovery) = prepare(resource, &discovery, discovery_id)?;
    if discovery_wire.body().len() > limits.request_bytes {
        return Err(ClientCredentialsCoreSubscriptionError::RequestTooLarge);
    }
    let params = discovery.encode_params()
        .map_err(|_| ClientCredentialsCoreSubscriptionError::InvalidRequest)?
        .ok_or(ClientCredentialsCoreSubscriptionError::InvalidRequest)?;
    let listen = CoreRequest::decode(
        ProtocolEra::Modern2026, "subscriptions/listen",
        Some(&json!({"_meta": params["_meta"], "notifications": filter})),
    ).map_err(|_| ClientCredentialsCoreSubscriptionError::InvalidRequest)?;
    let params = listen.encode_params()
        .map_err(|_| ClientCredentialsCoreSubscriptionError::InvalidRequest)?
        .ok_or(ClientCredentialsCoreSubscriptionError::InvalidRequest)?;
    let envelope = json!({"jsonrpc":"2.0", "id":request_id,
        "method":"subscriptions/listen", "params":params});
    let mut body = SubscriptionBody { bytes: Vec::new(), maximum: limits.request_bytes };
    serde_json::to_writer(&mut body, &envelope)
        .map_err(|_| ClientCredentialsCoreSubscriptionError::RequestTooLarge)?;
    let listen_wire = ModernHttpRequest::new(
        resource.as_str(), body.bytes, FINAL_PROTOCOL_VERSION, "subscriptions/listen", None,
    ).map_err(|_| ClientCredentialsCoreSubscriptionError::InvalidRequest)?;
    Ok(PreparedSubscription { discovery, discovery_wire, listen_wire, filter })
}

struct SubscriptionBody { bytes: Vec<u8>, maximum: usize }

impl Write for SubscriptionBody {
    fn write(&mut self, input: &[u8]) -> io::Result<usize> {
        if input.len() > self.maximum.saturating_sub(self.bytes.len()) {
            return Err(io::Error::other("machine subscription request limit"));
        }
        self.bytes.extend_from_slice(input);
        Ok(input.len())
    }
    fn flush(&mut self) -> io::Result<()> { Ok(()) }
}

fn subscription_error(error: ModernHttpSubscriptionListenError) -> ClientCredentialsCoreSubscriptionError {
    match error {
        ModernHttpSubscriptionListenError::RemoteError { code, .. } =>
            ClientCredentialsCoreSubscriptionError::Remote { code },
        ModernHttpSubscriptionListenError::EndOfStream { .. } =>
            ClientCredentialsCoreSubscriptionError::MissingTerminal,
        _ => ClientCredentialsCoreSubscriptionError::InvalidResponse,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    // Test-only: the production paths in this module build `_meta` through
    // `FinalRequestMeta`, so the subscription-id key is referenced only by the
    // fixtures below. Importing it at module scope makes it an unused import in
    // a non-test build, which fails a `-D warnings` gate.
    use fastmcp_protocol::{ClientCapabilities, FINAL_SUBSCRIPTION_ID_META_KEY};
    use serde_json::Value;

    use super::super::CLIENT_CREDENTIALS_EXTENSION;

    fn resource() -> CanonicalHttpUrl {
        CanonicalHttpUrl::parse("https://machine.example/mcp").unwrap()
    }

    fn metadata() -> FinalRequestMeta {
        FinalRequestMeta::new(ClientCapabilities::default())
    }

    fn filter() -> SubscriptionFilter {
        serde_json::from_value(json!({
            "resourceSubscriptions": ["file:///tmp/watched", "file:///tmp/also-requested"],
            "toolsListChanged": true,
        }))
        .unwrap()
    }

    fn prepared(
        limits: ClientCredentialsCoreSubscriptionLimits,
    ) -> Result<PreparedSubscription, ClientCredentialsCoreSubscriptionError> {
        prepare_subscription(
            &resource(), metadata(), &RequestId::Number(6),
            &RequestId::Number(7), filter(), limits,
        )
    }

    #[test]
    fn defaults_are_valid_bounded_limits() {
        let limits = ClientCredentialsCoreSubscriptionLimits::default();
        assert!(ClientCredentialsCoreSubscriptionLimits::new(
            limits.request_bytes(), limits.frame_bytes(), limits.records(), limits.timeout(),
        ).is_ok());
        assert_eq!(limits.request_bytes(), 64 * 1024);
        assert_eq!(limits.frame_bytes(), 64 * 1024);
        assert_eq!(limits.records(), 1024);
        assert_eq!(limits.timeout(), Duration::from_mins(15));
    }

    #[test]
    fn limit_construction_rejects_unbounded_or_unusable_values() {
        for (request, frame, records, timeout) in [
            (0, 1024, 2, Duration::from_secs(1)),
            (65_537, 1024, 2, Duration::from_secs(1)),
            (1024, 0, 2, Duration::from_secs(1)),
            (1024, 65_537, 2, Duration::from_secs(1)),
            (1024, 1024, 0, Duration::from_secs(1)),
            (1024, 1024, 1, Duration::from_secs(1)),
            (1024, 1024, 4097, Duration::from_secs(1)),
            (1024, 1024, 2, Duration::ZERO),
            (1024, 1024, 2, Duration::from_secs(3601)),
        ] {
            assert!(matches!(
                ClientCredentialsCoreSubscriptionLimits::new(request, frame, records, timeout),
                Err(ClientCredentialsCoreSubscriptionError::InvalidLimits),
            ));
        }
        assert!(ClientCredentialsCoreSubscriptionLimits::new(
            65_536, 65_536, 4096, Duration::from_secs(3600),
        ).is_ok());
    }

    #[test]
    fn both_requests_are_machine_stamped_without_negotiating_tasks() {
        let prepared = prepared(ClientCredentialsCoreSubscriptionLimits::default()).unwrap();
        let discovery: Value = serde_json::from_slice(prepared.discovery_wire.body()).unwrap();
        let listen: Value = serde_json::from_slice(prepared.listen_wire.body()).unwrap();
        for document in [&discovery, &listen] {
            assert_eq!(
                document["params"]["_meta"]["io.modelcontextprotocol/clientCapabilities"]["extensions"],
                json!({CLIENT_CREDENTIALS_EXTENSION: {}}),
            );
        }
        assert_eq!(discovery["method"], "server/discover");
        assert_eq!(discovery["id"], 6);
        assert_eq!(listen["method"], "subscriptions/listen");
        assert_eq!(listen["id"], 7);
        assert_eq!(listen["params"]["notifications"], serde_json::to_value(filter()).unwrap());
        assert_eq!(listen["params"]["_meta"], discovery["params"]["_meta"]);
        assert!(prepared.filter.additional.is_empty());
    }

    #[test]
    fn reused_discovery_and_listen_ids_are_rejected() {
        for id in [RequestId::Number(7), RequestId::String("same-id".to_owned())] {
            assert!(matches!(prepare_subscription(
                &resource(), metadata(), &id, &id, filter(),
                ClientCredentialsCoreSubscriptionLimits::default(),
            ), Err(ClientCredentialsCoreSubscriptionError::InvalidRequest)));
        }
    }

    #[test]
    fn core_filter_rejects_tasks_even_when_the_task_filter_is_empty() {
        let mut filters = filter();
        filters.additional.insert("taskIds".to_owned(), json!([]));
        assert!(matches!(prepare_subscription(
            &resource(), metadata(), &RequestId::Number(6), &RequestId::Number(7), filters,
            ClientCredentialsCoreSubscriptionLimits::default(),
        ), Err(ClientCredentialsCoreSubscriptionError::InvalidRequest)));
    }

    #[test]
    fn core_filter_rejects_unknown_extensions() {
        let mut filters = filter();
        filters.additional.insert("unnegotiated".to_owned(), json!({"enabled": true}));
        assert!(matches!(prepare_subscription(
            &resource(), metadata(), &RequestId::Number(6), &RequestId::Number(7), filters,
            ClientCredentialsCoreSubscriptionLimits::default(),
        ), Err(ClientCredentialsCoreSubscriptionError::InvalidRequest)));
    }

    #[test]
    fn admission_measures_both_stamped_requests_at_the_exact_byte_boundary() {
        let initial = prepared(ClientCredentialsCoreSubscriptionLimits::default()).unwrap();
        let maximum = initial.discovery_wire.body().len().max(initial.listen_wire.body().len());
        let with_bound = |bytes| ClientCredentialsCoreSubscriptionLimits::new(
            bytes, 65_536, 2, Duration::from_secs(1),
        ).unwrap();
        assert!(prepared(with_bound(maximum)).is_ok());
        assert!(matches!(prepared(with_bound(maximum - 1)),
            Err(ClientCredentialsCoreSubscriptionError::RequestTooLarge)));

        // Discovery itself must pass admission before the listen is prepared.
        assert!(initial.discovery_wire.body().len() > 1);
        assert!(matches!(prepared(with_bound(1)),
            Err(ClientCredentialsCoreSubscriptionError::RequestTooLarge)));

    }

    #[test]
    fn bounded_serialization_does_not_partially_append_an_over_limit_write() {
        let mut writer = SubscriptionBody { bytes: Vec::new(), maximum: 4 };
        writer.write_all(b"abc").unwrap();
        assert!(writer.write_all(b"de").is_err());
        assert_eq!(writer.bytes, b"abc");
        writer.write_all(b"d").unwrap();
        writer.write_all(b"").unwrap();
        assert_eq!(writer.bytes, b"abcd");
        assert!(writer.write_all(b"e").is_err());
        assert_eq!(writer.bytes.len(), writer.maximum);
    }

    // These peers exercise the shipped native HTTP response decoder and this
    // wrapper's lifetime/admission behavior. They do not constitute an OAuth
    // issuer, HTTPS credential-delivery or full discovery-negotiation test.
    fn runtime() -> asupersync::runtime::Runtime {
        asupersync::runtime::RuntimeBuilder::current_thread()
            .with_reactor(asupersync::runtime::reactor::create_reactor().unwrap())
            .blocking_threads(0, 2)
            .build()
            .unwrap()
    }

    /// The one subscription id this harness threads through BOTH the fixture and
    /// the subscription under test. A literal on each side would let the
    /// correlation check compare two constants that happen to agree, which
    /// passes whether or not the id is actually carried.
    const SUBSCRIPTION_ID: i64 = 7;

    /// Builds an acknowledgment carrying its subscription id in `_meta`, which
    /// is where `validate_http_subscription_acknowledgement` reads it from. The
    /// id is a PARAMETER so a wrong one can be planted; see
    /// `native_core_acknowledgment_with_a_foreign_subscription_id_is_refused`.
    fn ack(id: i64) -> String {
        // The `data: ` prefix and the blank-line terminator are the SSE framing,
        // not decoration: without them the stream parser rejects the frame and
        // EVERY test using it fails with InvalidResponse -- including the ones
        // whose assertions are `is_err()`, which then pass for the wrong reason.
        format!(
            "data: {}\n\n",
            json!({"jsonrpc":"2.0", "method":"notifications/subscriptions/acknowledged",
                "params":{"_meta":{(FINAL_SUBSCRIPTION_ID_META_KEY): id},
                          "notifications":{"resourceSubscriptions":["file:///tmp/watched"]}}})
        )
    }

    const UPDATE: &str = concat!(
        "data: {\"jsonrpc\":\"2.0\",\"method\":\"notifications/resources/updated\",",
        "\"params\":{\"_meta\":{\"io.modelcontextprotocol/subscriptionId\":7},",
        "\"uri\":\"file:///tmp/watched\"}}\n\n"
    );
    /// The listen terminal must satisfy TWO independent requirements, and they are
    /// checked in this order -- derived from source, not measured:
    ///   messages.rs:4260  decode_final_complete(..)        requires resultType
    ///                     "complete"; "empty" yields UnexpectedFinalResultType
    ///   messages.rs:4261  subscription_id_from_result(..)? requires
    ///                     _meta[subscriptionId]; absent yields InvalidResult
    ///                     (messages.rs:4806)
    /// Because :4260 runs first, a fixture fixing only the resultType would then
    /// fail on the absent _meta -- both are needed, neither alone suffices.
    ///
    /// The literal 7 must equal SUBSCRIPTION_ID; a const cannot interpolate it.
    /// It is left as a literal so the mismatch negative below can keep using
    /// `.replace("\"id\":7", ..)` to perturb ONLY the JSON-RPC response id. That
    /// substring does not occur inside the _meta member, whose key ends `...Id`
    /// with no quote before it, so the perturbation stays surgical.
    const TERMINAL: &str = concat!(
        "data: {\"jsonrpc\":\"2.0\",\"id\":7,\"result\":{\"resultType\":\"complete\",",
        "\"_meta\":{\"io.modelcontextprotocol/subscriptionId\":7}}}\n\n"
    );

    async fn native_subscription(
        cx: &Cx,
        body: String,
        hold_partial_body: bool,
        limits: ClientCredentialsCoreSubscriptionLimits,
    ) -> (ClientCredentialsCoreSubscription, std::thread::JoinHandle<()>) {
        use std::io::{BufRead, Read};
        use std::net::TcpListener;
        use std::time::Instant;

        let socket_listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = socket_listener.local_addr().unwrap();
        socket_listener.set_nonblocking(true).unwrap();
        let peer = std::thread::spawn(move || {
            let deadline = Instant::now() + Duration::from_secs(5);
            let mut socket = loop {
                match socket_listener.accept() {
                    Ok((socket, _)) => break socket,
                    Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                        assert!(Instant::now() < deadline, "subscription peer was never contacted");
                        std::thread::sleep(Duration::from_millis(1));
                    }
                    Err(error) => panic!("accept failed: {error}"),
                }
            };
            socket.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
            socket.set_write_timeout(Some(Duration::from_secs(5))).unwrap();
            {
                let mut reader = io::BufReader::new(&mut socket);
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
                let request: Value = serde_json::from_slice(&request).unwrap();
                assert_eq!(request["method"], "subscriptions/listen");
                assert_eq!(request["id"], 7);
            }
            let length = body.len() + if hold_partial_body { 100 } else { 0 };
            write!(socket,
                "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nContent-Length: {length}\r\nMCP-Protocol-Version: {FINAL_PROTOCOL_VERSION}\r\nConnection: close\r\n\r\n{body}"
            ).unwrap();
            socket.flush().unwrap();
            if hold_partial_body {
                let mut byte = [0];
                match socket.read(&mut byte) {
                    Ok(0) => {},
                    Err(error) if matches!(error.kind(),
                        io::ErrorKind::ConnectionReset | io::ErrorKind::ConnectionAborted) => {},
                    other => panic!("abandoned subscription did not close its socket: {other:?}"),
                }
            }
        });
        let prepared = prepared(limits).unwrap();
        let wire = ModernHttpRequest::new(
            &format!("http://{address}/mcp"), prepared.listen_wire.body().to_vec(),
            FINAL_PROTOCOL_VERSION, "subscriptions/listen", None,
        ).unwrap();
        let cancellation = McpRequestCancellation::new();
        let response = ModernHttpExecutor::new()
            .execute_with_cancellation(cx, &cancellation, &wire).await.unwrap();
        let framing = SseLimits::new(limits.frame_bytes, limits.frame_bytes, 64).unwrap();
        let listener = response.into_final_subscriptions_listener(
            RequestId::Number(7), prepared.filter, framing,
        ).unwrap();
        let owner = McpRequestCancellation::new();
        let expires_at = Instant::now() + Duration::from_secs(60);
        let bearer = crate::http_auth::BoundBearerCredential::bind_with_expiry(
            resource(), "subscription-lifetime-test-token", expires_at,
        ).unwrap().for_owner(&owner).unwrap();
        let snapshot = ClientCredentialsSnapshot {
            bearer, scopes: vec![], expires_at, generation: 1,
        };
        (ClientCredentialsCoreSubscription {
            listener: Some(Box::new(listener)), snapshot, owner, cancellation,
            request_id: RequestId::Number(SUBSCRIPTION_ID), accepted_filter: None,
            deadline: discovery_deadline(cx, Duration::from_secs(5)).unwrap(),
            limits, records: 0, finished: false,
        }, peer)
    }

    #[test]
    fn native_core_acknowledgment_narrows_the_filter_and_delivers_terminal() {
        runtime().block_on(async {
            let cx = Cx::current().unwrap();
            let (mut subscription, peer) = native_subscription(
                &cx, [ack(SUBSCRIPTION_ID).as_str(), UPDATE, TERMINAL].concat(), false,
                ClientCredentialsCoreSubscriptionLimits::default(),
            ).await;
            assert!(subscription.accepted_filter().is_none());
            assert_eq!(subscription.request_id(), &RequestId::Number(SUBSCRIPTION_ID));
            assert_eq!(subscription.credential_generation(), 1);
            assert!(matches!(subscription.next_event(&cx).await.unwrap(),
                Some(ModernHttpSubscriptionListenEvent::Acknowledged { .. })));
            let accepted = subscription.accepted_filter().unwrap();
            assert_eq!(accepted.resource_subscriptions, Some(vec!["file:///tmp/watched".to_owned()]));
            assert_eq!(accepted.tools_list_changed, None);
            assert!(matches!(subscription.next_event(&cx).await.unwrap(),
                Some(ModernHttpSubscriptionListenEvent::Notification(_))));
            assert!(matches!(subscription.next_event(&cx).await.unwrap(),
                Some(ModernHttpSubscriptionListenEvent::Terminal { .. })));
            assert_eq!(subscription.records_delivered(), 3);
            assert!(subscription.is_closed());
            assert!(subscription.next_event(&cx).await.unwrap().is_none());
            peer.join().unwrap();
        });
    }

    /// The positive above passes whenever the acknowledgment's id AGREES with the
    /// subscription's, which is exactly what a correlation check exists to
    /// enforce -- so a harness writing the same literal on both sides cannot
    /// distinguish a live check from an absent one. It would pass against an
    /// implementation that never read the id at all.
    ///
    /// This plants a FOREIGN id and changes nothing else: same filter, same
    /// stream, same limits, one value different. It fails if and only if the id
    /// is genuinely carried from the subscribe request through to validation.
    #[test]
    fn native_core_acknowledgment_with_a_foreign_subscription_id_is_refused() {
        runtime().block_on(async {
            let cx = Cx::current().unwrap();
            let (mut subscription, peer) = native_subscription(
                &cx,
                [ack(SUBSCRIPTION_ID + 1).as_str(), UPDATE, TERMINAL].concat(),
                false,
                ClientCredentialsCoreSubscriptionLimits::default(),
            )
            .await;
            assert!(subscription.next_event(&cx).await.is_err());
            // The refused acknowledgment must not have been published either:
            // rejecting the event while retaining its filter would leave the
            // subscription claiming a narrowing no peer ever granted.
            assert!(subscription.accepted_filter().is_none());
            assert_eq!(subscription.records_delivered(), 0);
            peer.join().unwrap();
        });
    }

    #[test]
    fn native_core_terminal_requires_prior_acknowledgment_and_correlation() {
        runtime().block_on(async {
            let cx = Cx::current().unwrap();
            for (body, has_ack) in [
                (TERMINAL.to_owned(), false),
                ([ack(SUBSCRIPTION_ID).as_str(), &TERMINAL.replace("\"id\":7", "\"id\":8")].concat(), true),
                ([ack(SUBSCRIPTION_ID).as_str(), &TERMINAL.replace("subscriptionId\":7", "subscriptionId\":8")].concat(), true),
            ] {
                let (mut subscription, peer) = native_subscription(
                    &cx, body, false, ClientCredentialsCoreSubscriptionLimits::default(),
                ).await;
                if has_ack {
                    assert!(matches!(subscription.next_event(&cx).await.unwrap(),
                        Some(ModernHttpSubscriptionListenEvent::Acknowledged { .. })));
                }
                assert!(subscription.next_event(&cx).await.is_err());
                assert!(subscription.is_closed());
                assert!(matches!(subscription.next_event(&cx).await,
                    Err(ClientCredentialsCoreSubscriptionError::Closed)));
                peer.join().unwrap();
            }
        });
    }

    #[test]
    fn native_core_updates_outside_the_accepted_filter_are_rejected() {
        runtime().block_on(async {
            let cx = Cx::current().unwrap();
            let outside = UPDATE.replace("file:///tmp/watched", "file:///tmp/also-requested");
            let (mut subscription, peer) = native_subscription(
                &cx, [ack(SUBSCRIPTION_ID).as_str(), &outside, TERMINAL].concat(), false,
                ClientCredentialsCoreSubscriptionLimits::default(),
            ).await;
            assert!(matches!(subscription.next_event(&cx).await.unwrap(),
                Some(ModernHttpSubscriptionListenEvent::Acknowledged { .. })));
            assert!(subscription.next_event(&cx).await.is_err());
            assert!(subscription.is_closed());
            assert_eq!(subscription.records_delivered(), 1);
            peer.join().unwrap();
        });
    }

    #[test]
    fn native_core_eof_without_terminal_is_not_success() {
        runtime().block_on(async {
            let cx = Cx::current().unwrap();
            let (mut subscription, peer) = native_subscription(
                &cx, [ack(SUBSCRIPTION_ID).as_str(), UPDATE].concat(), false,
                ClientCredentialsCoreSubscriptionLimits::default(),
            ).await;
            assert!(subscription.next_event(&cx).await.unwrap().is_some());
            assert!(subscription.next_event(&cx).await.unwrap().is_some());
            assert!(matches!(subscription.next_event(&cx).await,
                Err(ClientCredentialsCoreSubscriptionError::MissingTerminal)));
            assert!(subscription.is_closed());
            peer.join().unwrap();
        });
    }

    #[test]
    fn native_core_record_limit_cannot_be_bypassed_by_buffered_data() {
        runtime().block_on(async {
            let cx = Cx::current().unwrap();
            let limits = ClientCredentialsCoreSubscriptionLimits::new(
                65_536, 65_536, 2, Duration::from_secs(5),
            ).unwrap();
            let (mut subscription, peer) = native_subscription(
                &cx, [ack(SUBSCRIPTION_ID).as_str(), UPDATE, TERMINAL].concat(), false, limits,
            ).await;
            assert!(subscription.next_event(&cx).await.unwrap().is_some());
            assert!(subscription.next_event(&cx).await.unwrap().is_some());
            assert!(matches!(subscription.next_event(&cx).await,
                Err(ClientCredentialsCoreSubscriptionError::RecordLimit)));
            assert_eq!(subscription.records_delivered(), 2);
            assert!(subscription.is_closed());
            peer.join().unwrap();
        });
    }

    #[test]
    fn native_core_lifetime_checks_precede_publication_of_buffered_events() {
        runtime().block_on(async {
            let cx = Cx::current().unwrap();
            for case in 0..5 {
                let (mut subscription, peer) = native_subscription(
                    &cx, [ack(SUBSCRIPTION_ID).as_str(), UPDATE, TERMINAL].concat(), false,
                    ClientCredentialsCoreSubscriptionLimits::default(),
                ).await;
                match case {
                    0 => { subscription.cancellation.cancel(); },
                    1 => { subscription.owner.cancel(); },
                    2 => { subscription.snapshot.bearer.revoke(); },
                    3 => subscription.snapshot.expires_at = std::time::Instant::now(),
                    _ => subscription.deadline = cx.now(),
                }
                assert!(matches!(subscription.next_event(&cx).await,
                    Err(ClientCredentialsCoreSubscriptionError::Authentication(_))));
                assert!(subscription.accepted_filter().is_none());
                assert_eq!(subscription.records_delivered(), 0);
                assert!(subscription.is_closed());
                peer.join().unwrap();
            }
        });
    }

    #[test]
    fn native_core_abandoning_pending_read_retires_the_real_body() {
        use std::future::{Future, poll_fn};
        use std::task::Poll;

        runtime().block_on(async {
            let cx = Cx::current().unwrap();
            let (mut subscription, peer) = native_subscription(
                &cx, "data: {".to_owned(), true,
                ClientCredentialsCoreSubscriptionLimits::default(),
            ).await;
            {
                let mut pending = std::pin::pin!(subscription.next_event(&cx));
                poll_fn(|task| match pending.as_mut().poll(task) {
                    Poll::Pending => Poll::Ready(()),
                    Poll::Ready(_) => panic!("incomplete subscription record should remain pending"),
                }).await;
            }
            assert!(subscription.is_closed());
            assert!(matches!(subscription.next_event(&cx).await,
                Err(ClientCredentialsCoreSubscriptionError::Closed)));
            peer.join().unwrap();
        });
    }

    #[test]
    fn native_core_close_drops_body_without_cancelling_siblings() {
        runtime().block_on(async {
            let cx = Cx::current().unwrap();
            let (mut subscription, peer) = native_subscription(
                &cx, "data: {".to_owned(), true,
                ClientCredentialsCoreSubscriptionLimits::default(),
            ).await;
            subscription.close();
            assert!(subscription.is_closed());
            assert!(matches!(subscription.next_event(&cx).await,
                Err(ClientCredentialsCoreSubscriptionError::Closed)));
            assert!(!subscription.cancellation.is_cancel_requested());
            assert!(!subscription.owner.is_cancel_requested());
            peer.join().unwrap();
        });
    }
}
