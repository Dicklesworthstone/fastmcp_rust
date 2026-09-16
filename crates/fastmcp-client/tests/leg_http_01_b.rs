//! LEG-HTTP-01 B — exact `2024-11-05` GET+SSE origin/auth security, framing,
//! backpressure, and deterministic close.
//!
//! External consumer of the shipped `fastmcp_client` public surface, reached as
//! a downstream crate reaches it — never `use super::` and never a
//! `#[cfg(test)]` module (PL-3). Every case drives the real
//! `LegacySseHttpClient` over real loopback sockets.
//!
//! # The bounds here are measured, never declared
//!
//! The acceptance criteria forbid copied-constant evidence, and the transport's
//! limits are private to it. So the line bound is found by **doubling a real SSE
//! data line until the shipped transport refuses it**, and the observation
//! records the accepted/refused bracket rather than asserting an exact number
//! the probe never established. If the transport's bound moves, this moves with
//! it; nothing is hand-synced.
//!
//! # Framing
//!
//! Every streaming body is `Transfer-Encoding: chunked` with a terminating
//! `0\r\n\r\n`. A response head carrying neither `Content-Length` nor
//! `Transfer-Encoding` frames an EMPTY body in asupersync, so an under-asserting
//! case would pass against a stream that never delivered anything.

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

use asupersync::runtime::RuntimeBuilder;
use asupersync::{CancelKind, Cx};
use fastmcp_client::http_auth::BoundBearerCredential;
use fastmcp_client::http_executor::ModernHttpClient;
use fastmcp_client::{
    CanonicalHttpUrl, ClientProtocolPlan, LEG_HTTP_01_B_EVALUATOR_MANIFEST_V1, LimitConflict,
    ObservedLimit, ProtocolPolicy, frozen_limits, leg_http_01_b_manifest_digest, ordered_rows,
};
use fastmcp_protocol::{ClientCapabilities, ClientInfo};

/// Largest line the probe will attempt. The frozen guarded floor is 8 MiB + 8 B,
/// so a transport that admits this has no line conflict to record.
const PROBE_CEILING_BYTES: usize = 8 * 1024 * 1024 + 8;

fn runtime_block_on<F: std::future::Future>(future: F) -> F::Output {
    RuntimeBuilder::current_thread()
        .build()
        .expect("the test owns its caller runtime")
        .block_on(future)
}

fn client_info() -> ClientInfo {
    ClientInfo {
        name: "leg-http-01-b-client".to_owned(),
        version: "1.0.0".to_owned(),
    }
}

fn plan(modern: &str, sse: &str, message: &str) -> ClientProtocolPlan {
    let url = |value: &str| CanonicalHttpUrl::parse(value).expect("fixture target is canonical");
    ClientProtocolPlan::http(
        ProtocolPolicy::Auto,
        Some(url(modern)),
        Some(url(sse)),
        Some(url(message)),
        "credential-partition-leg-http-01-b".to_owned(),
        "security-partition-leg-http-01-b".to_owned(),
        "native-h1-leg-http-01-b".to_owned(),
        1,
        1,
        0,
    )
    .expect("the dual-era plan is accepted")
}

fn accept_bounded(listener: &TcpListener) -> TcpStream {
    let deadline = Instant::now() + Duration::from_secs(20);
    listener.set_nonblocking(true).expect("set nonblocking");
    loop {
        match listener.accept() {
            Ok((stream, _)) => {
                stream.set_nonblocking(false).expect("set blocking");
                stream
                    .set_read_timeout(Some(Duration::from_secs(20)))
                    .expect("bound reads");
                stream
                    .set_write_timeout(Some(Duration::from_secs(20)))
                    .expect("bound writes");
                return stream;
            }
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                assert!(Instant::now() < deadline, "timed out awaiting a connection");
                thread::sleep(Duration::from_millis(5));
            }
            Err(error) => panic!("unexpected accept error: {error}"),
        }
    }
}

fn read_head(stream: &mut TcpStream) -> String {
    let mut wire = Vec::new();
    let mut chunk = [0_u8; 4096];
    loop {
        let read = stream.read(&mut chunk).expect("read request");
        assert!(read > 0, "peer closed before a complete request head");
        wire.extend_from_slice(&chunk[..read]);
        if let Some(end) = wire.windows(4).position(|w| w == b"\r\n\r\n") {
            let head = String::from_utf8_lossy(&wire[..end + 4]).into_owned();
            let length = head
                .lines()
                .find_map(|line| {
                    let (name, value) = line.split_once(':')?;
                    name.eq_ignore_ascii_case("content-length")
                        .then(|| value.trim().parse::<usize>().expect("numeric length"))
                })
                .unwrap_or(0);
            while wire.len() < end + 4 + length {
                let read = stream.read(&mut chunk).expect("read request body");
                assert!(read > 0, "peer closed before the advertised body");
                wire.extend_from_slice(&chunk[..read]);
            }
            return head;
        }
    }
}

fn write_bounded(stream: &mut TcpStream, status: u16, content_type: &str, body: &[u8]) {
    write!(
        stream,
        "HTTP/1.1 {status} Fixture\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    )
    .expect("write head");
    stream.write_all(body).expect("write body");
    stream.flush().expect("flush");
}

/// Writes a redirect or bare status with no body.
fn write_status(stream: &mut TcpStream, status: u16, location: Option<&str>) {
    write!(stream, "HTTP/1.1 {status} Fixture\r\n").expect("write status");
    if let Some(location) = location {
        write!(stream, "Location: {location}\r\n").expect("write location");
    }
    write!(stream, "Content-Length: 0\r\nConnection: close\r\n\r\n").expect("write head end");
    stream.flush().expect("flush");
}

fn begin_sse(stream: &mut TcpStream) {
    write!(
        stream,
        "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n"
    )
    .expect("write SSE head");
    stream.flush().expect("flush SSE head");
}

/// Writes one chunk. A zero-length chunk would terminate the body, so it is
/// refused rather than silently ending the stream.
fn write_chunk(stream: &mut TcpStream, bytes: &[u8]) {
    assert!(!bytes.is_empty(), "a zero-length chunk would end the body");
    write!(stream, "{:x}\r\n", bytes.len()).expect("write chunk length");
    stream.write_all(bytes).expect("write chunk payload");
    write!(stream, "\r\n").expect("write chunk terminator");
    stream.flush().expect("flush chunk");
}

fn end_sse(stream: &mut TcpStream) {
    write!(stream, "0\r\n\r\n").expect("write terminating chunk");
    stream.flush().expect("flush terminator");
}

fn endpoint_event(message_target: &str) -> Vec<u8> {
    format!("event: endpoint\ndata: {message_target}\n\n").into_bytes()
}

fn message_event(payload: &str) -> Vec<u8> {
    format!("event: message\ndata: {payload}\n\n").into_bytes()
}

/// What the fixture should do after the `endpoint` event.
#[derive(Debug, Clone)]
enum Script {
    /// Emit one well-formed message and close.
    OneMessage,
    /// Emit a single `data:` line of exactly this many payload bytes.
    DataLine(usize),
    /// Emit a second `endpoint` event, which must never be admitted.
    SecondEndpoint,
    /// Advertise a different message target than the configured one.
    MismatchedEndpoint(String),
    /// Send a first event that is not `endpoint`.
    FirstEventNotEndpoint,
    /// Close the stream before any `endpoint` event.
    CloseBeforeEndpoint,
    /// Answer the SSE GET with this status instead of a stream.
    SseStatus(u16, Option<String>),
}

struct Fixture {
    listener: TcpListener,
    modern: String,
    sse: String,
    message: String,
}

impl Fixture {
    fn bind() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind fixture listener");
        let address = listener.local_addr().expect("read fixture address");
        Self {
            listener,
            modern: format!("http://{address}/mcp"),
            sse: format!("http://{address}/legacy-sse"),
            message: format!("http://{address}/legacy-message"),
        }
    }
}

/// Everything one legacy session observed.
///
/// Rendered as strings so a case can assert on a typed refusal without this
/// target needing to name every private error shape.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
struct SessionOutcome {
    /// `None` when the legacy lane never opened.
    configured: Option<String>,
    advertised: Option<String>,
    /// One rendered result per `next_message` call performed.
    messages: Vec<String>,
    /// Set when connect or lane selection refused.
    open_error: Option<String>,
}

impl SessionOutcome {
    fn opened(&self) -> bool {
        self.open_error.is_none()
    }
}

/// Runs one legacy session end to end.
///
/// The fixture answers the modern probe with the frozen eligible 404/empty
/// refusal so `Auto` selects the exact-2024 lane, then runs `script`. Every
/// await happens inside the caller runtime: a future doing socket I/O cannot be
/// driven by polling it with a noop waker, because nothing would advance the
/// reactor.
fn legacy_session(script: Script, reads: usize) -> SessionOutcome {
    legacy_session_with(script, reads, false)
}

/// As [`legacy_session`], but optionally cancels the CLIENT's context after the
/// lane opens and before the first read.
///
/// The client is given a context this function mints, never the ambient one, so
/// cancelling it cancels the client alone and leaves the runtime's own context
/// intact. `Cx::clone` would not do: it is an alias, so cancelling a clone would
/// take the ambient domain down with it.
fn legacy_session_with(script: Script, reads: usize, cancel_before_read: bool) -> SessionOutcome {
    let fixture = Fixture::bind();
    let (modern, sse, message) = (
        fixture.modern.clone(),
        fixture.sse.clone(),
        fixture.message.clone(),
    );
    let listener = fixture.listener;
    let message_for_server = message.clone();
    let (ready_tx, ready_rx) = mpsc::channel::<()>();

    let server = thread::spawn(move || {
        // 1. The disposable modern probe: the frozen eligible refusal.
        let mut probe = accept_bounded(&listener);
        let _ = read_head(&mut probe);
        write_bounded(&mut probe, 404, "text/plain", b"");
        drop(probe);

        // 2. The one legacy SSE GET.
        let mut sse_stream = accept_bounded(&listener);
        let head = read_head(&mut sse_stream);
        assert!(
            head.starts_with("GET /legacy-sse HTTP/1.1\r\n"),
            "the legacy lane must GET its configured SSE route: {head:?}"
        );
        assert!(
            !head.contains("MCP-Protocol-Version:"),
            "the exact-2024 GET must not carry modern routing headers"
        );

        if let Script::SseStatus(status, location) = &script {
            write_status(&mut sse_stream, *status, location.as_deref());
            let _ = ready_tx.send(());
            return;
        }

        begin_sse(&mut sse_stream);
        match &script {
            Script::FirstEventNotEndpoint => {
                write_chunk(
                    &mut sse_stream,
                    &message_event(r#"{"jsonrpc":"2.0","id":1,"result":{}}"#),
                );
                end_sse(&mut sse_stream);
            }
            Script::CloseBeforeEndpoint => {
                write_chunk(&mut sse_stream, b": keepalive\n\n");
                end_sse(&mut sse_stream);
            }
            Script::MismatchedEndpoint(other) => {
                write_chunk(&mut sse_stream, &endpoint_event(other));
                end_sse(&mut sse_stream);
            }
            Script::OneMessage => {
                write_chunk(&mut sse_stream, &endpoint_event(&message_for_server));
                write_chunk(
                    &mut sse_stream,
                    &message_event(r#"{"jsonrpc":"2.0","id":1,"result":{"ok":true}}"#),
                );
                end_sse(&mut sse_stream);
            }
            Script::SecondEndpoint => {
                write_chunk(&mut sse_stream, &endpoint_event(&message_for_server));
                write_chunk(&mut sse_stream, &endpoint_event(&message_for_server));
                end_sse(&mut sse_stream);
            }
            Script::DataLine(size) => {
                write_chunk(&mut sse_stream, &endpoint_event(&message_for_server));
                let mut event = Vec::with_capacity(size + 32);
                event.extend_from_slice(b"event: message\ndata: ");
                event.extend(std::iter::repeat_n(b'x', *size));
                event.extend_from_slice(b"\n\n");
                write_chunk(&mut sse_stream, &event);
                end_sse(&mut sse_stream);
            }
            Script::SseStatus(..) => unreachable!("handled above"),
        }
        let _ = ready_tx.send(());
    });

    let outcome = runtime_block_on(async {
        // A context minted for the client, not the ambient one.
        let cx = Cx::for_request();
        let mut outcome = SessionOutcome::default();
        let connected = ModernHttpClient::connect(
            &cx,
            plan(&modern, &sse, &message),
            client_info(),
            ClientCapabilities::default(),
        )
        .await;
        let mut legacy = match connected {
            Ok(selected) => match selected.into_legacy_sse() {
                Some(legacy) => legacy,
                None => {
                    outcome.open_error =
                        Some("the eligible refusal did not open the legacy lane".to_owned());
                    return outcome;
                }
            },
            Err(error) => {
                outcome.open_error = Some(format!("{error:?}"));
                return outcome;
            }
        };
        outcome.configured = Some(legacy.configured_message_post_target().to_owned());
        outcome.advertised = Some(legacy.advertised_message_post_target().to_owned());
        if cancel_before_read {
            cx.cancel_with(CancelKind::User, Some("leg-http-01-b row 10"));
        }
        for _ in 0..reads {
            let result = legacy.next_message(&cx).await;
            outcome.messages.push(format!("{result:?}"));
        }
        outcome
    });

    let _ = ready_rx.recv_timeout(Duration::from_secs(20));
    let _ = server.join();
    outcome
}

/// Feeds one `data:` line of `size` payload bytes and reports whether the
/// shipped transport admitted it.
fn line_of_size_is_admitted(size: usize) -> bool {
    let outcome = legacy_session(Script::DataLine(size), 1);
    outcome.opened()
        && outcome
            .messages
            .first()
            .is_some_and(|rendered| rendered.starts_with("Ok("))
}

/// Measures the shipped SSE line bound by doubling until refusal.
///
/// Returns the accepted/refused bracket. Stops at the frozen guarded floor: a
/// transport that admits that has no conflict to record.
fn measure_sse_line_bound() -> Option<ObservedLimit> {
    let mut accepted = 0_usize;
    let mut size = 1024_usize;
    while size <= PROBE_CEILING_BYTES {
        if line_of_size_is_admitted(size) {
            accepted = size;
            size = size.saturating_mul(2);
        } else {
            return Some(ObservedLimit::new(accepted as u64, size as u64));
        }
    }
    None
}

#[test]
fn leg_http_01_b_positive() {
    // ---- the frozen manifest -------------------------------------------
    let manifest = LEG_HTTP_01_B_EVALUATOR_MANIFEST_V1;
    assert!(manifest.ends_with('\n'), "the manifest is LF-terminated");
    assert!(!manifest.contains('\r'), "the manifest is LF-canonical");
    assert_eq!(leg_http_01_b_manifest_digest().as_bytes().len(), 32);

    let rows = ordered_rows();
    assert_eq!(rows.len(), 11, "the frozen contract declares eleven rows");
    for (index, (ordinal, _)) in rows.iter().enumerate() {
        assert_eq!(
            usize::from(*ordinal),
            index + 1,
            "rows are declared in order with no gap"
        );
    }
    let limits = frozen_limits();
    assert!(limits.len() >= 7, "every frozen floor is declared");
    for limit in &limits {
        assert!(
            limit.guarded() <= limit.hard(),
            "{}: the guarded floor cannot exceed the hard ceiling",
            limit.name()
        );
    }

    // ---- row 01: same-origin URI admission -----------------------------
    let admitted = legacy_session(Script::OneMessage, 1);
    assert!(
        admitted.opened(),
        "the eligible refusal must open the legacy lane"
    );
    assert_eq!(
        admitted.configured, admitted.advertised,
        "the advertised endpoint must be the configured one, byte for byte"
    );
    assert!(
        admitted.messages[0].starts_with("Ok("),
        "a well-formed message event must be admitted, observed {}",
        admitted.messages[0]
    );

    // ---- row 07: endpoint-mutation denial ------------------------------
    let mutated = legacy_session(Script::SecondEndpoint, 2);
    assert!(mutated.opened(), "the first endpoint event opens the lane");
    assert!(
        mutated.messages[1].contains("UnexpectedEndpointEvent"),
        "a second endpoint event must be refused, observed {}",
        mutated.messages[1]
    );

    // ---- row 03: malformed SSE framing ---------------------------------
    let not_endpoint = legacy_session(Script::FirstEventNotEndpoint, 0);
    assert!(
        !not_endpoint.opened(),
        "a first event that is not `endpoint` must not open a legacy lane"
    );
    assert!(
        not_endpoint
            .open_error
            .as_deref()
            .is_some_and(|error| error.contains("FirstEventWasNotEndpoint")),
        "the refusal must be the typed first-event boundary, observed {:?}",
        not_endpoint.open_error
    );

    let closed_early = legacy_session(Script::CloseBeforeEndpoint, 0);
    assert!(
        !closed_early.opened(),
        "a stream that closes before its endpoint event must not open a lane"
    );
    assert!(
        closed_early
            .open_error
            .as_deref()
            .is_some_and(|error| error.contains("SseEndedBeforeEndpoint")),
        "observed {:?}",
        closed_early.open_error
    );

    // ---- rows 04 and 05: redirect and 5xx denial -----------------------
    for (status, location, marker) in [
        (
            302_u16,
            Some("http://127.0.0.1:1/elsewhere".to_owned()),
            "SseGetRedirect",
        ),
        (
            307,
            Some("http://127.0.0.1:1/elsewhere".to_owned()),
            "SseGetRedirect",
        ),
        (500, None, "SseGetRejected"),
        (503, None, "SseGetRejected"),
    ] {
        let refused = legacy_session(Script::SseStatus(status, location), 0);
        assert!(
            !refused.opened(),
            "status {status} must not open a legacy lane"
        );
        assert!(
            refused
                .open_error
                .as_deref()
                .is_some_and(|error| error.contains(marker)),
            "status {status} must reach {marker}, observed {:?}",
            refused.open_error
        );
    }

    // ---- row 02: credential binding, to the extent it is provable ------
    //
    // The exact-2024 lane never carries a credential, and that is structural
    // rather than incidental: `BoundBearerCredential::bind` refuses a cleartext
    // resource outright, so no credential can even be constructed for a
    // loopback `http:` legacy lane. The transport-side guard exists too - an
    // authorised legacy fallback with a credential in hand refuses with
    // `AuthenticatedLegacyFallback` rather than opening the lane - but driving
    // that live needs an HTTPS fixture, which this target does not have. That
    // half is declared unproven rather than implied; see the report on this
    // bead.
    for cleartext in [
        "http://127.0.0.1:8443/mcp",
        "http://[::1]:8443/mcp",
        "http://localhost:8443/mcp",
    ] {
        let resource = CanonicalHttpUrl::parse(cleartext).expect("the cleartext variant parses");
        assert!(
            BoundBearerCredential::bind(resource, "leg-http-01-b-secret").is_err(),
            "{cleartext}: a cleartext legacy lane must not be able to hold a credential"
        );
    }

    // ---- row 10: cancellation ------------------------------------------
    //
    // The client is cancelled, not the ambient runtime context - the session
    // helper mints the client's own context for exactly this reason.
    let cancelled = legacy_session_with(Script::OneMessage, 1, true);
    assert!(
        cancelled.opened(),
        "the lane must open before the caller cancels it"
    );
    assert!(
        cancelled.messages[0].contains("Cancelled"),
        "a cancelled caller must reach the typed cancellation boundary, observed {}",
        cancelled.messages[0]
    );

    // ---- row 06: size backpressure, MEASURED not declared --------------
    let observed = measure_sse_line_bound()
        .expect("the shipped transport refuses some line below the frozen guarded floor");
    let line_floor = limits
        .iter()
        .find(|limit| limit.name() == "sse-line")
        .expect("the manifest declares the sse-line floor");
    let conflict = LimitConflict::detect(line_floor, observed);

    // This is the recorded disagreement, not a resolved one. It fails loudly
    // and names both numbers; widening the production bound to make it pass
    // would buy a green row by moving the thing being measured.
    assert!(
        conflict.is_none(),
        "{}",
        conflict.expect("checked above").render()
    );
}

#[test]
fn leg_http_01_b_planted_negative() {
    // Baseline: the advertised endpoint is the configured one and the lane opens.
    let baseline = legacy_session(Script::OneMessage, 0);
    assert!(baseline.opened(), "the baseline lane must open");
    let advertised = baseline
        .advertised
        .clone()
        .expect("an opened lane records its advertised endpoint");
    assert!(
        advertised.ends_with("/legacy-message"),
        "the accepted advertisement names the configured route, observed {advertised}"
    );

    // Planted: exactly one variable changes - the advertised endpoint route.
    // The probe refusal, the SSE route, the framing and the call sequence are
    // all identical; only the `data:` payload of the endpoint event differs.
    let planted = legacy_session(
        Script::MismatchedEndpoint("http://127.0.0.1:1/other-route".to_owned()),
        0,
    );
    assert!(
        !planted.opened(),
        "an advertised endpoint that is not the configured route must be refused"
    );
    assert!(
        planted
            .open_error
            .as_deref()
            .is_some_and(|error| error.contains("AdvertisedMessagePostTargetMismatch")),
        "the refusal must be the typed advertisement boundary, observed {:?}",
        planted.open_error
    );

    // Unchanged state: the refusal yields no lane at all, so no configured or
    // advertised endpoint is retained and no message was ever read.
    assert_eq!(planted.configured, None);
    assert_eq!(planted.advertised, None);
    assert!(planted.messages.is_empty());
    assert_ne!(planted.open_error, baseline.open_error);
}
