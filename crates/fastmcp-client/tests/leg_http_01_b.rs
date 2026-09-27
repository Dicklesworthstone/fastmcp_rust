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

use std::future::{Future, poll_fn};
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::mpsc;
use std::task::Poll;
use std::thread;
use std::time::{Duration, Instant};

use asupersync::io::{AsyncReadExt, AsyncWriteExt};
use asupersync::net::TcpListener as AsyncTcpListener;
use asupersync::runtime::{RuntimeBuilder, reactor::create_reactor};
use asupersync::tls::{Certificate, CertificateChain, PrivateKey, TlsAcceptorBuilder};
use asupersync::{CancelKind, Cx};
use fastmcp_client::http_auth::BoundBearerCredential;
use fastmcp_client::http_executor::{LegacySseHttpClient, ModernHttpClient};
use fastmcp_client::{
    CanonicalHttpUrl, ClientBuilder, ClientProtocolPlan, LEG_HTTP_01_B_EVALUATOR_MANIFEST_V1,
    LimitConflict, ObservedLimit, ProtocolPolicy, frozen_limits, leg_http_01_b_manifest_digest,
    ordered_rows,
};
use fastmcp_protocol::{
    ClientCapabilities, ClientInfo, JsonRpcMessage, JsonRpcRequest, JsonRpcResponse, RequestId,
};

/// Largest line the probe will attempt. The frozen guarded floor is 8 MiB + 8 B,
/// so a transport that admits this has no line conflict to record.
const PROBE_CEILING_BYTES: usize = 8 * 1024 * 1024 + 8;

/// TEST-ONLY private CA and `localhost`/`127.0.0.1`/`::1` leaf, valid 2020-2049,
/// the same fixture chain the OAuth challenge target uses.
const TEST_ROOT: &[u8] = b"-----BEGIN CERTIFICATE-----\nMIIBgzCCASmgAwIBAgICA+kwCgYIKoZIzj0EAwIwJzElMCMGA1UEAwwcRmFzdE1D\nUCBPQXV0aCBURVNUIE9OTFkgUm9vdDAeFw0yMDAxMDEwMDAwMDBaFw00OTEyMzEw\nMDAwMDBaMCcxJTAjBgNVBAMMHEZhc3RNQ1AgT0F1dGggVEVTVCBPTkxZIFJvb3Qw\nWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAAS5t2O8JZ0hNjgI38E9Ov6i6mKoDRGo\nApMsykFkvgb6Zm9/5gCZ90eIKw7aWgK6iNs7lbtVY9mysZBIqm6pKQO2o0UwQzAS\nBgNVHRMBAf8ECDAGAQH/AgEAMA4GA1UdDwEB/wQEAwIBhjAdBgNVHQ4EFgQU6QNI\nrmvMiLoV3jIoCyohXARwI8gwCgYIKoZIzj0EAwIDSAAwRQIgCKOrW3vhzUJ2EyuY\nvQUTdqGFhy0zEHj4ITFLvXPz1X8CIQCLKD4EKCvS/zkBSu/6uee1WV9d97UpK3yW\nX/aCEJ5+hA==\n-----END CERTIFICATE-----\n";
const TEST_LEAF: &[u8] = b"-----BEGIN CERTIFICATE-----\nMIIBjjCCATSgAwIBAgICA+owCgYIKoZIzj0EAwIwJzElMCMGA1UEAwwcRmFzdE1D\nUCBPQXV0aCBURVNUIE9OTFkgUm9vdDAeFw0yMDAxMDEwMDAwMDBaFw00OTEyMzEw\nMDAwMDBaMBQxEjAQBgNVBAMMCWxvY2FsaG9zdDBZMBMGByqGSM49AgEGCCqGSM49\nAwEHA0IABPPKylLna9VpWAlpshHBhSsQHNOv3BaEGX4HSBhHiBVel0ce+qfHF15O\n0T63Zlp7TtxlMdEY+rPpgioSFDQVadijYzBhMAwGA1UdEwEB/wQCMAAwLAYDVR0R\nBCUwI4IJbG9jYWxob3N0hwR/AAABhxAAAAAAAAAAAAAAAAAAAAABMBMGA1UdJQQM\nMAoGCCsGAQUFBwMBMA4GA1UdDwEB/wQEAwIHgDAKBggqhkjOPQQDAgNIADBFAiEA\n6qrAr2qp/t6K62T9Et2mUU/zfd4kJb+ekyoAim1yTFcCICb6SdVY2fg15/SXf0vE\nIvYelqtTk8FQInCEcIxvfF3m\n-----END CERTIFICATE-----\n";
const TEST_KEY: &[u8] = b"-----BEGIN PRIVATE KEY-----\nMIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgcCe44IBKhbw+D/s7\nBjDHOOV0g+EoxFno7VJGKhJeer2hRANCAATzyspS52vVaVgJabIRwYUrEBzTr9wW\nhBl+B0gYR4gVXpdHHvqnxxdeTtE+t2Zae07cZTHRGPqz6YIqEhQ0FWnY\n-----END PRIVATE KEY-----\n";

/// Drives two futures on one task until both finish.
async fn pair<L: Future, R: Future>(left: L, right: R) -> (L::Output, R::Output) {
    let mut left = Box::pin(left);
    let mut right = Box::pin(right);
    let mut one = None;
    let mut two = None;
    poll_fn(|task| {
        if one.is_none()
            && let Poll::Ready(result) = left.as_mut().poll(task)
        {
            one = Some(result);
        }
        if two.is_none()
            && let Poll::Ready(result) = right.as_mut().poll(task)
        {
            two = Some(result);
        }
        match (one.take(), two.take()) {
            (Some(one), Some(two)) => Poll::Ready((one, two)),
            (left_result, right_result) => {
                one = left_result;
                two = right_result;
                Poll::Pending
            }
        }
    })
    .await
}

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
                write_chunk(
                    &mut sse_stream,
                    &message_event(&sized_jsonrpc_payload(*size)),
                );
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

/// Builds a VALID JSON-RPC message whose `data:` payload is exactly `size`
/// bytes, so line length is the ONLY variable across probe sizes.
///
/// An earlier revision padded with raw `x` bytes. That payload is not JSON-RPC,
/// so every probe was refused by the decoder regardless of its length and the
/// search never admitted anything - the measurement was vacuous and the ratio
/// computed from it was an artifact of the first probe size, not a bound.
fn sized_jsonrpc_payload(size: usize) -> String {
    let envelope = r#"{"jsonrpc":"2.0","id":1,"result":{"pad":""}}"#;
    assert!(
        size >= envelope.len(),
        "a probe size must leave room for the JSON-RPC envelope ({} bytes)",
        envelope.len()
    );
    let pad = "x".repeat(size - envelope.len());
    format!(r#"{{"jsonrpc":"2.0","id":1,"result":{{"pad":"{pad}"}}}}"#)
}

/// What the shipped transport did with one sized line.
#[derive(Debug)]
enum LineProbe {
    /// Admitted and decoded as one JSON-RPC message.
    Admitted,
    /// Refused specifically because of its size.
    RefusedForSize,
    /// Anything else. Never counted as either, because a probe that cannot tell
    /// admission from refusal has measured nothing.
    Inconclusive(String),
}

/// Feeds one valid, sized `data:` line and classifies the transport's answer.
fn probe_line(size: usize) -> LineProbe {
    let outcome = legacy_session(Script::DataLine(size), 1);
    if !outcome.opened() {
        return LineProbe::Inconclusive(format!(
            "the legacy lane did not open: {:?}",
            outcome.open_error
        ));
    }
    let Some(observed) = outcome.messages.first() else {
        return LineProbe::Inconclusive("no read was performed".to_owned());
    };
    if observed.starts_with("Ok(Some(") {
        LineProbe::Admitted
    } else if observed.contains("SseLineTooLong") || observed.contains("SseEventTooLarge") {
        LineProbe::RefusedForSize
    } else {
        LineProbe::Inconclusive(observed.clone())
    }
}

/// Measures the shipped SSE line bound by doubling until a SIZE refusal.
///
/// Returns the accepted/refused bracket, or `None` when the transport admits the
/// frozen guarded floor and there is therefore no conflict to record.
///
/// Panics rather than returning a bracket when the transport never admits
/// anything or answers inconclusively: a conflict recorded against a measurement
/// that never happened is worse than no conflict, because the number in it is
/// evidence someone will act on.
fn measure_sse_line_bound() -> Option<ObservedLimit> {
    let mut accepted = 0_usize;
    let mut size = 1024_usize;
    while size <= PROBE_CEILING_BYTES {
        match probe_line(size) {
            LineProbe::Admitted => {
                accepted = size;
                size = size.saturating_mul(2);
            }
            LineProbe::RefusedForSize => {
                assert!(
                    accepted > 0,
                    "the transport refused {size} bytes for size without ever admitting a \
                     smaller line, so no bound was bracketed. A conflict computed from this \
                     would divide the frozen floor by the first probe size and report an \
                     artifact, not a measurement."
                );
                return Some(ObservedLimit::new(accepted as u64, size as u64));
            }
            LineProbe::Inconclusive(reason) => panic!(
                "the line probe at {size} bytes is INCONCLUSIVE ({reason}); it distinguishes \
                 neither admission nor a size refusal, so nothing may be recorded from it"
            ),
        }
    }
    None
}

/// One step a scripted legacy peer serves, in order, on one listener.
enum Step {
    /// The disposable modern probe, answered with the frozen eligible refusal.
    ModernProbe,
    /// A legacy SSE GET answered with a chunked event stream that carries
    /// `extra_headers`, then `events`, and is then ended or held open.
    Stream {
        extra_headers: &'static [(&'static str, &'static str)],
        events: Vec<Vec<u8>>,
        end: bool,
    },
    /// A legacy SSE GET answered with a bare status.
    GetStatus(u16),
    /// Legacy SSE GETs, each answered with one `endpoint` event for the next
    /// session and then ended, until none arrives within the quiet window.
    EndingStreamsUntilQuiet,
    /// A message POST answered with `status` and `extra_headers`.
    Post {
        status: u16,
        extra_headers: &'static [(&'static str, &'static str)],
    },
    /// One chunk written on the most recently held stream.
    Write(Vec<u8>),
    /// Ends the most recently held stream.
    End,
    /// Waits for the client to close the most recently held stream.
    ExpectHeldClosed,
}

/// Everything a scripted peer received.
#[derive(Debug, Default)]
struct PeerLog {
    /// Every request head, in arrival order.
    heads: Vec<String>,
    /// `(request line, body)` for every message POST.
    posts: Vec<(String, String)>,
    /// Heads of connections that arrived when none was scripted.
    unexpected: Vec<String>,
    /// Whether the client closed the held stream, when a step asked.
    held_closed_by_client: Option<bool>,
}

impl PeerLog {
    fn count(&self, request_line_prefix: &str) -> usize {
        self.heads
            .iter()
            .filter(|head| head.starts_with(request_line_prefix))
            .count()
    }

    fn gets(&self) -> usize {
        self.count("GET /legacy-sse ")
    }

    fn modern_probes(&self) -> usize {
        self.count("POST /mcp ")
    }

    /// Whether any exact-2024 request carried a header of this name. The one
    /// modern probe is a modern request and is excluded.
    fn legacy_carried(&self, name: &str) -> bool {
        self.heads
            .iter()
            .filter(|head| !head.starts_with("POST /mcp "))
            .any(|head| {
                head.lines().skip(1).any(|line| {
                    line.split_once(':')
                        .is_some_and(|(field, _)| field.trim().eq_ignore_ascii_case(name))
                })
            })
    }

    /// Asserts what every legacy exchange must hold: one modern probe and no
    /// other modern request, and legacy requests that carry no credential,
    /// no modern routing header, no 2025 session or replay state, no DELETE,
    /// and nothing the script did not expect.
    fn assert_legacy_hygiene(&self, case: &str) {
        assert_eq!(self.modern_probes(), 1, "{case}: exactly one modern probe");
        for header in [
            "Authorization",
            "Mcp-Session-Id",
            "Last-Event-ID",
            "MCP-Protocol-Version",
        ] {
            assert!(
                !self.legacy_carried(header),
                "{case}: no legacy request may carry {header}"
            );
        }
        assert_eq!(self.count("DELETE "), 0, "{case}: no DELETE");
        assert!(
            self.unexpected.is_empty(),
            "{case}: unscripted connections {:?}",
            self.unexpected
        );
    }
}

/// Reads one request head and its `Content-Length` body.
fn read_request(stream: &mut TcpStream) -> (String, String) {
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
            let body = String::from_utf8_lossy(&wire[end + 4..end + 4 + length]).into_owned();
            return (head, body);
        }
    }
}

/// Accepts one connection if it arrives within `window`.
fn accept_within(listener: &TcpListener, window: Duration) -> Option<TcpStream> {
    listener.set_nonblocking(true).expect("set nonblocking");
    let deadline = Instant::now() + window;
    loop {
        match listener.accept() {
            Ok((stream, _)) => {
                stream.set_nonblocking(false).expect("set blocking");
                stream
                    .set_read_timeout(Some(Duration::from_secs(20)))
                    .expect("bound reads");
                return Some(stream);
            }
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                if Instant::now() >= deadline {
                    return None;
                }
                thread::sleep(Duration::from_millis(5));
            }
            Err(error) => panic!("unexpected accept error: {error}"),
        }
    }
}

fn begin_sse_with(stream: &mut TcpStream, extra_headers: &[(&str, &str)]) {
    write!(
        stream,
        "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n"
    )
    .expect("write SSE head");
    for (name, value) in extra_headers {
        write!(stream, "{name}: {value}\r\n").expect("write extra header");
    }
    write!(stream, "\r\n").expect("end SSE head");
    stream.flush().expect("flush SSE head");
}

fn write_post_reply(stream: &mut TcpStream, status: u16, extra_headers: &[(&str, &str)]) {
    write!(stream, "HTTP/1.1 {status} Fixture\r\n").expect("write POST status");
    for (name, value) in extra_headers {
        write!(stream, "{name}: {value}\r\n").expect("write extra header");
    }
    write!(stream, "Content-Length: 0\r\nConnection: close\r\n\r\n").expect("end POST head");
    stream.flush().expect("flush POST reply");
}

/// A scripted legacy peer on its own listener thread.
struct Peer {
    modern: String,
    sse: String,
    message: String,
    server: thread::JoinHandle<PeerLog>,
}

impl Peer {
    /// Serves the steps `script` builds from the configured message target,
    /// then records any connection arriving in a final quiet window.
    fn serve(script: impl FnOnce(&str) -> Vec<Step>) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind peer listener");
        let address = listener.local_addr().expect("read peer address");
        let modern = format!("http://{address}/mcp");
        let sse = format!("http://{address}/legacy-sse");
        let message = format!("http://{address}/legacy-message");
        let steps = script(&message);
        let session_base = message.clone();
        let server = thread::spawn(move || {
            let mut log = PeerLog::default();
            let mut held: Vec<TcpStream> = Vec::new();
            let mut next_session = 2_u32;
            for step in steps {
                match step {
                    Step::ModernProbe => {
                        let mut probe = accept_bounded(&listener);
                        let (head, _) = read_request(&mut probe);
                        log.heads.push(head);
                        write_bounded(&mut probe, 404, "text/plain", b"");
                    }
                    Step::Stream {
                        extra_headers,
                        events,
                        end,
                    } => {
                        let mut stream = accept_bounded(&listener);
                        let (head, _) = read_request(&mut stream);
                        log.heads.push(head);
                        begin_sse_with(&mut stream, extra_headers);
                        for event in events {
                            write_chunk(&mut stream, &event);
                        }
                        if end {
                            end_sse(&mut stream);
                        } else {
                            held.push(stream);
                        }
                    }
                    Step::GetStatus(status) => {
                        let mut stream = accept_bounded(&listener);
                        let (head, _) = read_request(&mut stream);
                        log.heads.push(head);
                        write_status(&mut stream, status, None);
                    }
                    Step::EndingStreamsUntilQuiet => {
                        while let Some(mut stream) =
                            accept_within(&listener, Duration::from_secs(2))
                        {
                            let (head, _) = read_request(&mut stream);
                            log.heads.push(head);
                            begin_sse_with(&mut stream, &[]);
                            write_chunk(
                                &mut stream,
                                &endpoint_event(&format!("{session_base}?session={next_session}")),
                            );
                            next_session += 1;
                            end_sse(&mut stream);
                        }
                    }
                    Step::Post {
                        status,
                        extra_headers,
                    } => {
                        let mut post = accept_bounded(&listener);
                        let (head, body) = read_request(&mut post);
                        let request_line = head.lines().next().unwrap_or_default().to_owned();
                        log.heads.push(head);
                        log.posts.push((request_line, body));
                        write_post_reply(&mut post, status, extra_headers);
                    }
                    Step::Write(bytes) => {
                        let stream = held.last_mut().expect("a held stream to write");
                        write_chunk(stream, &bytes);
                    }
                    Step::End => {
                        let stream = held.last_mut().expect("a held stream to end");
                        end_sse(stream);
                    }
                    Step::ExpectHeldClosed => {
                        let stream = held.last_mut().expect("a held stream to watch");
                        stream
                            .set_read_timeout(Some(Duration::from_secs(2)))
                            .expect("bound the close wait");
                        let mut byte = [0_u8; 1];
                        log.held_closed_by_client = Some(matches!(stream.read(&mut byte), Ok(0)));
                    }
                }
            }
            while let Some(mut stray) = accept_within(&listener, Duration::from_millis(400)) {
                stray
                    .set_read_timeout(Some(Duration::from_secs(2)))
                    .expect("bound the stray read");
                let mut head = [0_u8; 256];
                let read = stray.read(&mut head).unwrap_or(0);
                log.unexpected
                    .push(String::from_utf8_lossy(&head[..read]).into_owned());
            }
            log
        });
        Self {
            modern,
            sse,
            message,
            server,
        }
    }

    fn finish(self) -> PeerLog {
        self.server
            .join()
            .expect("the scripted peer must not panic")
    }
}

/// Opens the exact-2024 lane against `peer` through the public `Auto` path.
async fn open_legacy(cx: &Cx, peer: &Peer) -> Result<LegacySseHttpClient, String> {
    let selected = ModernHttpClient::connect(
        cx,
        plan(&peer.modern, &peer.sse, &peer.message),
        client_info(),
        ClientCapabilities::default(),
    )
    .await
    .map_err(|error| format!("{error:?}"))?;
    selected
        .into_legacy_sse()
        .ok_or_else(|| "the eligible refusal did not open the legacy lane".to_owned())
}

/// Asserts a stream-level refusal that the parser meets either while `connect`
/// still holds the frame that carried the endpoint event, or on the first
/// read if the offending bytes arrived in a later frame. Either way it is the
/// named typed refusal, and a lane that did open then refuses to POST to the
/// refused stream's target and stays on its first generation.
fn assert_refused_at_open_or_first_read(peer: &Peer, marker: &str) {
    let observed = runtime_block_on(async {
        let cx = Cx::for_request();
        match open_legacy(&cx, peer).await {
            Err(error) => (error, None),
            Ok(mut legacy) => {
                let refusal = format!("{:?}", legacy.next_message(&cx).await);
                let after = format!("{:?}", legacy.send(&cx, &ping(1)).await);
                (refusal, Some((after, legacy.stream_generation())))
            }
        }
    });
    assert!(
        observed.0.contains(marker),
        "{marker}: observed {}",
        observed.0
    );
    if let Some((after, generation)) = observed.1 {
        assert_eq!(after, "Err(StreamGenerationEnded)", "{marker}");
        assert_eq!(generation, 1, "{marker}");
    }
}

/// A client request the peer can recognise in the POST body.
fn ping(id: i64) -> JsonRpcMessage {
    JsonRpcMessage::Request(JsonRpcRequest::new("ping", None, id))
}

/// `count` minimal complete events in one body frame, after the endpoint.
fn backlog(message_target: &str, count: usize) -> Vec<u8> {
    let mut body = endpoint_event(message_target);
    for _ in 0..count {
        body.extend_from_slice(b"data: {}\n\n");
    }
    body
}

/// One valid JSON-RPC response spread over exactly `lines` `data:` lines.
fn multiline_message_event(lines: usize) -> Vec<u8> {
    assert!(lines >= 3, "the envelope needs three lines");
    let mut event = b"event: message\ndata: {\"jsonrpc\":\"2.0\",\n".to_vec();
    for _ in 0..lines - 3 {
        event.extend_from_slice(b"data: \n");
    }
    event.extend_from_slice(b"data: \"id\":1,\ndata: \"result\":{}}\n\n");
    event
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
    // The shipped contract refuses a second `endpoint` event outright:
    // `next_legacy_sse_message` maps `Some(LegacySseEvent::Endpoint(_))` to
    // `Err(UnexpectedEndpointEvent)` (http_executor.rs:8452). The refusal
    // therefore lands on whichever read first meets that event, which depends on
    // how the body frames chunk rather than on the contract. So this asserts on
    // the observed SEQUENCE rather than on a fixed index: an earlier revision
    // indexed `messages[1]` and reported a contract violation that was really a
    // fixture-chunking assumption.
    let mutated = legacy_session(Script::SecondEndpoint, 2);
    assert!(mutated.opened(), "the first endpoint event opens the lane");
    let refusal = mutated
        .messages
        .iter()
        .position(|observed| observed.contains("UnexpectedEndpointEvent"));
    assert!(
        refusal.is_some(),
        "a second endpoint event must be refused, observed {:?}",
        mutated.messages
    );
    // Nothing may be admitted from the mutated stream before the refusal.
    for observed in mutated
        .messages
        .iter()
        .take(refusal.expect("checked above"))
    {
        assert!(
            !observed.starts_with("Ok(Some("),
            "no message may be admitted before the endpoint-mutation refusal, observed {observed}"
        );
    }

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
    // loopback `http:` legacy lane. Over HTTPS the transport-side guard holds
    // instead: an authorised legacy fallback with a credential in hand refuses
    // with `AuthenticatedLegacyFallback` rather than opening the lane (below).
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

    // Over HTTPS: the credential binds the modern endpoint and goes to it,
    // and nowhere else. The peer answers the credentialed probe with the
    // eligible 404, which selects the legacy lane for an anonymous client;
    // with a credential the client refuses before any exact-2024 request.
    let (probe_head, refusal, legacy_contacted) = RuntimeBuilder::current_thread()
        .with_reactor(create_reactor().expect("create the reactor"))
        .build()
        .expect("the test owns its caller runtime")
        .block_on(Box::pin(async {
            let cx = Cx::for_request();
            let listener = AsyncTcpListener::bind("127.0.0.1:0")
                .await
                .expect("bind the HTTPS peer");
            let origin = format!("https://{}", listener.local_addr().expect("peer address"));
            let acceptor = TlsAcceptorBuilder::new(
                CertificateChain::from_pem(TEST_LEAF).expect("the test leaf parses"),
                PrivateKey::from_pem(TEST_KEY).expect("the test key parses"),
            )
            .alpn_protocols(vec![b"http/1.1".to_vec()])
            .build()
            .expect("the test acceptor builds");
            let modern = CanonicalHttpUrl::parse(&format!("{origin}/mcp")).expect("canonical");
            let credential = BoundBearerCredential::bind(modern.clone(), "leg-http-01-b-secret")
                .expect("an HTTPS modern endpoint can hold a credential");
            let root = Certificate::from_pem(TEST_ROOT)
                .expect("the test root parses")
                .remove(0);
            let client = ClientBuilder::new()
                .protocol_plan(plan(
                    &format!("{origin}/mcp"),
                    &format!("{origin}/legacy-sse"),
                    &format!("{origin}/legacy-message"),
                ))
                .http_bearer_credential(credential)
                .http_resource_root_certificate(modern, root)
                .expect("the private root is admitted")
                .connect_http_with_cx(&cx);
            let peer = async {
                let (socket, _) = listener.accept().await.expect("accept the probe");
                let mut tls = acceptor
                    .accept(socket)
                    .await
                    .expect("the trusted handshake completes");
                let mut wire = Vec::new();
                let mut buffer = [0_u8; 4096];
                let end = loop {
                    let count = tls.read(&mut buffer).await.expect("read the probe");
                    assert!(count > 0, "the probe arrives");
                    wire.extend_from_slice(&buffer[..count]);
                    if let Some(end) = wire.windows(4).position(|window| window == b"\r\n\r\n") {
                        break end + 4;
                    }
                };
                tls.write_all(
                    b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                )
                .await
                .expect("answer the eligible refusal");
                tls.flush().await.expect("flush the refusal");
                String::from_utf8_lossy(&wire[..end]).into_owned()
            };
            let (probe_head, connected) = Box::pin(pair(peer, client)).await;
            let mut task = std::task::Context::from_waker(std::task::Waker::noop());
            let legacy_contacted = listener.poll_accept(&mut task).is_ready();
            (
                probe_head,
                format!("{:?}", connected.err()),
                legacy_contacted,
            )
        }));
    assert!(
        probe_head.starts_with("POST /mcp HTTP/1.1\r\n"),
        "the credentialed modern probe, observed {probe_head:?}"
    );
    assert!(
        probe_head
            .to_ascii_lowercase()
            .contains("authorization: bearer "),
        "the credential goes to the modern endpoint it binds"
    );
    assert!(
        refusal.contains("AuthenticatedLegacyFallback"),
        "an authenticated client must refuse the legacy fallback, observed {refusal}"
    );
    assert!(
        !legacy_contacted,
        "no exact-2024 request, so the credential never reaches it"
    );

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
    let line_floor = limits
        .iter()
        .find(|limit| limit.name() == "sse-line")
        .expect("the manifest declares the sse-line floor");
    // `None` means the doubling probe reached the ceiling without a size
    // refusal: the shipped transport admits every probed line up to the frozen
    // floor. A bracketed refusal below the floor is the recorded conflict and
    // fails loudly, naming both numbers.
    if let Some(observed) = measure_sse_line_bound() {
        let conflict = LimitConflict::detect(line_floor, observed);
        assert!(
            conflict.is_none(),
            "{}",
            conflict.expect("checked above").render()
        );
    }
    // Positive proof at the floor itself, not only the absence of a refusal:
    // an event whose `data:` line is exactly the frozen guarded floor (the
    // payload plus `data: ` and CRLF) must be admitted and delivered.
    let floor_payload = usize::try_from(line_floor.guarded())
        .expect("the sse-line floor fits usize")
        - b"data: \r\n".len();
    assert!(
        matches!(probe_line(floor_payload), LineProbe::Admitted),
        "a {floor_payload}-byte data line (the frozen sse-line floor) must be admitted"
    );

    // ---- row 06: queue and data-line backpressure at the frozen floors --
    let floor = |name: &str| {
        let limit = limits
            .iter()
            .find(|limit| limit.name() == name)
            .unwrap_or_else(|| panic!("the manifest declares the {name} floor"));
        usize::try_from(limit.guarded()).expect("the floor fits usize")
    };
    // One body frame holding exactly the queue floor: the endpoint event and
    // the messages behind it all wait for delivery together.
    let queue_floor = floor("outbound-queue-events");
    let queue = Peer::serve(|message| {
        vec![
            Step::ModernProbe,
            Step::Stream {
                extra_headers: &[],
                events: vec![backlog(message, queue_floor - 1)],
                end: true,
            },
        ]
    });
    let opened = runtime_block_on(async {
        let cx = Cx::for_request();
        open_legacy(&cx, &queue).await.map(|_| ())
    });
    assert!(
        opened.is_ok(),
        "a backlog of exactly {queue_floor} events must be admitted: {opened:?}"
    );
    queue.finish().assert_legacy_hygiene("row 06 queue floor");

    let lines_floor = floor("sse-data-lines-per-event");
    let lines = Peer::serve(|message| {
        vec![
            Step::ModernProbe,
            Step::Stream {
                extra_headers: &[],
                events: vec![
                    endpoint_event(message),
                    multiline_message_event(lines_floor),
                ],
                end: true,
            },
        ]
    });
    let delivered = runtime_block_on(async {
        let cx = Cx::for_request();
        let mut legacy = open_legacy(&cx, &lines).await.expect("the lane opens");
        format!("{:?}", legacy.next_message(&cx).await)
    });
    assert!(
        delivered.starts_with("Ok(Some(Response("),
        "a message spread over exactly {lines_floor} data lines must be delivered, observed {delivered}"
    );
    lines
        .finish()
        .assert_legacy_hygiene("row 06 data-line floor");

    // ---- rows 08 and 09: reconnect, then frames both ways ---------------
    //
    // Generation 1 ends after its endpoint. The caller reconnects; the new
    // GET must again open with exactly one endpoint, here a new session. The
    // request, the server's response and its own request, and the client's
    // reply then all travel on generation 2 and its POST target.
    let reconnect = Peer::serve(|message| {
        vec![
            Step::ModernProbe,
            Step::Stream {
                extra_headers: &[],
                events: vec![endpoint_event(&format!("{message}?session=1"))],
                end: true,
            },
            Step::Stream {
                extra_headers: &[],
                events: vec![endpoint_event(&format!("{message}?session=2"))],
                end: false,
            },
            Step::Post {
                status: 202,
                extra_headers: &[],
            },
            Step::Write(message_event(r#"{"jsonrpc":"2.0","id":7,"result":{}}"#)),
            Step::Write(message_event(
                r#"{"jsonrpc":"2.0","id":"srv-1","method":"ping"}"#,
            )),
            Step::Post {
                status: 202,
                extra_headers: &[],
            },
            Step::End,
        ]
    });
    let message_target = reconnect.message.clone();
    let observed = runtime_block_on(async {
        let cx = Cx::for_request();
        let mut legacy = open_legacy(&cx, &reconnect)
            .await
            .expect("generation 1 opens");
        let mut observed = vec![format!(
            "generation {} at {}",
            legacy.stream_generation(),
            legacy.advertised_message_post_target()
        )];
        observed.push(format!("{:?}", legacy.next_message(&cx).await));
        legacy
            .reconnect(&cx)
            .await
            .expect("a fresh generation with one endpoint is admitted");
        observed.push(format!(
            "generation {} at {} after {} attempt(s)",
            legacy.stream_generation(),
            legacy.advertised_message_post_target(),
            legacy.reconnect_attempts()
        ));
        legacy
            .send(&cx, &ping(7))
            .await
            .expect("the new generation's target accepts the request");
        observed.push(format!("{:?}", legacy.next_message(&cx).await));
        observed.push(format!("{:?}", legacy.next_message(&cx).await));
        legacy
            .send(
                &cx,
                &JsonRpcMessage::Response(JsonRpcResponse::success(
                    RequestId::String("srv-1".to_owned()),
                    serde_json::json!({}),
                )),
            )
            .await
            .expect("the reply to the server's request is posted");
        observed.push(format!("{:?}", legacy.next_message(&cx).await));
        observed
    });
    assert_eq!(
        observed[0],
        format!("generation 1 at {message_target}?session=1")
    );
    assert_eq!(observed[1], "Ok(None)", "generation 1 ends");
    assert_eq!(
        observed[2],
        format!("generation 2 at {message_target}?session=2 after 1 attempt(s)")
    );
    assert!(
        observed[3].starts_with("Ok(Some(Response(") && observed[3].contains("Number(7)"),
        "the response to the request arrives on generation 2, observed {}",
        observed[3]
    );
    assert!(
        observed[4].starts_with("Ok(Some(Request(") && observed[4].contains("\"ping\""),
        "the server's own request arrives on generation 2, observed {}",
        observed[4]
    );
    assert_eq!(
        observed[5], "Ok(None)",
        "generation 2 ends after the exchange"
    );
    let log = reconnect.finish();
    assert_eq!(log.gets(), 2, "one GET per generation");
    assert_eq!(log.posts.len(), 2, "the request and the reply");
    for (request_line, _) in &log.posts {
        assert_eq!(
            request_line, "POST /legacy-message?session=2 HTTP/1.1",
            "every POST goes to generation 2's target"
        );
    }
    assert!(
        log.posts[0].1.contains("\"method\":\"ping\"") && log.posts[0].1.contains("\"id\":7"),
        "the POSTed request, observed {}",
        log.posts[0].1
    );
    assert!(
        log.posts[1].1.contains("\"id\":\"srv-1\"") && log.posts[1].1.contains("\"result\""),
        "the POSTed reply, observed {}",
        log.posts[1].1
    );
    log.assert_legacy_hygiene("rows 08-09");

    // ---- row 11: deterministic close ------------------------------------
    //
    // The client stays alive for a while after `close`, so the peer seeing
    // the stream close inside its short watch proves that `close` closed it,
    // not the drop at the end of the block.
    let close = Peer::serve(|message| {
        vec![
            Step::ModernProbe,
            Step::Stream {
                extra_headers: &[],
                events: vec![endpoint_event(message)],
                end: false,
            },
            Step::ExpectHeldClosed,
        ]
    });
    let observed = runtime_block_on(async {
        let cx = Cx::for_request();
        let mut legacy = open_legacy(&cx, &close).await.expect("the lane opens");
        let observed = vec![
            format!("{}", legacy.close()),
            format!("{}", legacy.close()),
            format!("{}", legacy.is_closed()),
            format!("{:?}", legacy.send(&cx, &ping(9)).await),
            format!("{:?}", legacy.next_message(&cx).await),
            format!("{:?}", legacy.reconnect(&cx).await),
            format!("{}", legacy.stream_generation()),
        ];
        // Longer than the peer's two-second watch.
        thread::sleep(Duration::from_secs(3));
        drop(legacy);
        observed
    });
    assert_eq!(
        observed,
        [
            "true",
            "false",
            "true",
            "Err(Closed)",
            "Err(Closed)",
            "Err(Closed)",
            "1"
        ],
        "close is one-shot and leaves every operation refused"
    );
    let log = close.finish();
    assert_eq!(
        log.held_closed_by_client,
        Some(true),
        "the peer sees the stream closed by `close` itself"
    );
    assert!(log.posts.is_empty(), "nothing is POSTed after close");
    assert_eq!(log.gets(), 1, "a closed client never reconnects");
    log.assert_legacy_hygiene("row 11");
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

    // Every case below changes one variable of a baseline the positive test
    // admits, and reaches a typed refusal. None POSTs after the refusal,
    // carries a credential, or touches modern state (`assert_legacy_hygiene`),
    // and each leaves the prior stream generation as it was.
    let limits = frozen_limits();
    let floor = |name: &str| {
        let limit = limits
            .iter()
            .find(|limit| limit.name() == name)
            .unwrap_or_else(|| panic!("the manifest declares the {name} floor"));
        usize::try_from(limit.guarded()).expect("the floor fits usize")
    };
    let open_error = |peer: &Peer| {
        runtime_block_on(async {
            let cx = Cx::for_request();
            open_legacy(&cx, peer).await.map(|_| ())
        })
        .expect_err("the planted lane must not open")
    };

    // ---- auth result: the SSE GET answers 401 instead of a stream -------
    let peer = Peer::serve(|_| vec![Step::ModernProbe, Step::GetStatus(401)]);
    let error = open_error(&peer);
    assert!(
        error.contains("SseGetRejected { status: 401 }"),
        "observed {error}"
    );
    let log = peer.finish();
    assert!(log.posts.is_empty());
    log.assert_legacy_hygiene("auth result");

    // ---- injected 2025 session header on the SSE GET response -----------
    let peer = Peer::serve(|message| {
        vec![
            Step::ModernProbe,
            Step::Stream {
                extra_headers: &[("Mcp-Session-Id", "2025-11-25-session")],
                events: vec![endpoint_event(message)],
                end: true,
            },
        ]
    });
    let error = open_error(&peer);
    assert!(
        error.contains("ForbiddenResponseSessionHeader"),
        "observed {error}"
    );
    let log = peer.finish();
    assert!(log.posts.is_empty());
    log.assert_legacy_hygiene("injected session header on GET");

    // ---- one over the queue floor in one body frame ---------------------
    let queue_floor = floor("outbound-queue-events");
    let peer = Peer::serve(|message| {
        vec![
            Step::ModernProbe,
            Step::Stream {
                extra_headers: &[],
                events: vec![backlog(message, queue_floor)],
                end: true,
            },
        ]
    });
    let error = open_error(&peer);
    assert!(
        error.contains("PendingSseEventCountExceeded"),
        "observed {error}"
    );
    let log = peer.finish();
    assert!(log.posts.is_empty());
    log.assert_legacy_hygiene("queue floor + 1");

    // Cases on an open lane: `run` opens it, applies `act`, and returns what
    // `act` observed, then the send it attempts afterwards, the generation,
    // and the advertised target.
    let run = |peer: &Peer, reconnect: bool| {
        runtime_block_on(async {
            let cx = Cx::for_request();
            let mut legacy = open_legacy(&cx, peer).await.expect("the lane opens");
            let advertised = legacy.advertised_message_post_target().to_owned();
            let refusal = if reconnect {
                let _ended = legacy.next_message(&cx).await;
                format!("{:?}", legacy.reconnect(&cx).await)
            } else {
                format!("{:?}", legacy.next_message(&cx).await)
            };
            let after = format!("{:?}", legacy.send(&cx, &ping(1)).await);
            (
                refusal,
                after,
                legacy.stream_generation(),
                legacy.advertised_message_post_target() == advertised,
            )
        })
    };

    // ---- malformed frame: one non-UTF-8 byte in a field line ------------
    let peer = Peer::serve(|message| {
        vec![
            Step::ModernProbe,
            Step::Stream {
                extra_headers: &[],
                events: vec![endpoint_event(message), b"data: \xff\n\n".to_vec()],
                end: false,
            },
        ]
    });
    assert_refused_at_open_or_first_read(&peer, "SseInvalidUtf8");
    let log = peer.finish();
    assert!(log.posts.is_empty());
    log.assert_legacy_hygiene("malformed frame");

    // ---- one over the data-line floor ------------------------------------
    let lines_floor = floor("sse-data-lines-per-event");
    let peer = Peer::serve(|message| {
        vec![
            Step::ModernProbe,
            Step::Stream {
                extra_headers: &[],
                events: vec![
                    endpoint_event(message),
                    multiline_message_event(lines_floor + 1),
                ],
                end: false,
            },
        ]
    });
    assert_refused_at_open_or_first_read(&peer, "SseEventTooManyDataLines");
    let log = peer.finish();
    assert!(log.posts.is_empty());
    log.assert_legacy_hygiene("data-line floor + 1");

    // ---- batch row: a JSON-RPC batch instead of one envelope -------------
    let peer = Peer::serve(|message| {
        vec![
            Step::ModernProbe,
            Step::Stream {
                extra_headers: &[],
                events: vec![
                    endpoint_event(message),
                    message_event(r#"[{"jsonrpc":"2.0","id":1,"result":{}}]"#),
                ],
                end: true,
            },
        ]
    });
    let observed = runtime_block_on(async {
        let cx = Cx::for_request();
        let mut legacy = open_legacy(&cx, &peer).await.expect("the lane opens");
        format!("{:?}", legacy.next_message(&cx).await)
    });
    assert_eq!(observed, "Err(MessageDecodeFailed)");
    let log = peer.finish();
    assert!(log.posts.is_empty());
    log.assert_legacy_hygiene("batch row");

    // ---- generation ended and no reconnect: its POST target is gone ------
    let peer = Peer::serve(|message| {
        vec![
            Step::ModernProbe,
            Step::Stream {
                extra_headers: &[],
                events: vec![endpoint_event(message)],
                end: true,
            },
        ]
    });
    let (ended, after, generation, unchanged) = run(&peer, false);
    assert_eq!(ended, "Ok(None)");
    assert_eq!(after, "Err(StreamGenerationEnded)");
    assert_eq!((generation, unchanged), (1, true));
    let log = peer.finish();
    assert!(log.posts.is_empty(), "no POST to an ended generation");
    log.assert_legacy_hygiene("send after generation end");

    // ---- endpoint mutation across generations ----------------------------
    let peer = Peer::serve(|message| {
        vec![
            Step::ModernProbe,
            Step::Stream {
                extra_headers: &[],
                events: vec![endpoint_event(&format!("{message}?session=1"))],
                end: true,
            },
            Step::Stream {
                extra_headers: &[],
                events: vec![endpoint_event("http://127.0.0.1:1/legacy-message")],
                end: true,
            },
        ]
    });
    let (refusal, after, generation, unchanged) = run(&peer, true);
    assert!(
        refusal.starts_with("Err(AdvertisedMessagePostTargetMismatch"),
        "observed {refusal}"
    );
    assert_eq!(after, "Err(StreamGenerationEnded)");
    assert_eq!(
        (generation, unchanged),
        (1, true),
        "the refused generation changes nothing"
    );
    let log = peer.finish();
    assert_eq!(log.gets(), 2);
    assert!(log.posts.is_empty());
    log.assert_legacy_hygiene("cross-generation endpoint mutation");

    // ---- POST redirect and 5xx, and an injected session header on the
    // POST reply: each changes only the peer's answer to the one POST ------
    for (status, extra_headers, marker) in [
        (
            307_u16,
            &[("Location", "http://127.0.0.1:1/elsewhere")][..],
            "Err(MessagePostRedirect { status: 307 })",
        ),
        (500, &[][..], "Err(MessagePostRejected { status: 500 })"),
        (
            202,
            &[("Mcp-Session-Id", "2025-11-25-session")][..],
            "Err(ForbiddenResponseSessionHeader)",
        ),
    ] {
        let peer = Peer::serve(|message| {
            vec![
                Step::ModernProbe,
                Step::Stream {
                    extra_headers: &[],
                    events: vec![endpoint_event(message)],
                    end: false,
                },
                Step::Post {
                    status,
                    extra_headers,
                },
            ]
        });
        let observed = runtime_block_on(async {
            let cx = Cx::for_request();
            let legacy = open_legacy(&cx, &peer).await.expect("the lane opens");
            (
                format!("{:?}", legacy.send(&cx, &ping(1)).await),
                legacy.stream_generation(),
            )
        });
        assert_eq!(observed, (marker.to_owned(), 1), "status {status}");
        let log = peer.finish();
        assert_eq!(
            log.posts.len(),
            1,
            "status {status}: the POST is not followed or retried"
        );
        log.assert_legacy_hygiene(marker);
    }

    // ---- one reconnect past the bound ------------------------------------
    //
    // The bound is measured: every admitted attempt costs one GET, and the
    // refused one costs none and changes nothing.
    let peer = Peer::serve(|message| {
        vec![
            Step::ModernProbe,
            Step::Stream {
                extra_headers: &[],
                events: vec![endpoint_event(&format!("{message}?session=1"))],
                end: true,
            },
            Step::EndingStreamsUntilQuiet,
        ]
    });
    let (admitted, refusal, before, after) = runtime_block_on(async {
        let cx = Cx::for_request();
        let mut legacy = open_legacy(&cx, &peer).await.expect("the lane opens");
        let mut admitted = 0_u32;
        loop {
            let before = (
                legacy.stream_generation(),
                legacy.reconnect_attempts(),
                legacy.advertised_message_post_target().to_owned(),
            );
            match legacy.reconnect(&cx).await {
                Ok(()) => admitted += 1,
                Err(error) => {
                    let after = (
                        legacy.stream_generation(),
                        legacy.reconnect_attempts(),
                        legacy.advertised_message_post_target().to_owned(),
                    );
                    break (admitted, format!("{error:?}"), before, after);
                }
            }
            assert!(admitted < 64, "reconnect must be bounded");
        }
    });
    assert!(
        refusal.starts_with("Err(ReconnectLimitExceeded")
            || refusal.starts_with("ReconnectLimitExceeded"),
        "observed {refusal}"
    );
    assert!(admitted >= 1, "the bound admits at least one reconnect");
    assert_eq!(before, after, "the refused attempt changes nothing");
    assert_eq!(
        after.0,
        admitted + 1,
        "each admitted attempt is one generation"
    );
    let log = peer.finish();
    assert_eq!(
        log.gets(),
        1 + usize::try_from(admitted).expect("small"),
        "the refused attempt sends no GET"
    );
    assert!(log.posts.is_empty());
    log.assert_legacy_hygiene("reconnect bound + 1");
}
