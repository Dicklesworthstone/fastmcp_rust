//! HTTP-03 integration (role `I`): join the accepted implementation A and
//! implementation B capability slices through shipped public entrypoints only.
//!
//! This target is an external consumer of the published facade. It reaches the
//! joined surface exclusively through `fastmcp_rust::...` and never through
//! `use super::...` or a `#[cfg(test)]` module, so what it proves is the
//! packaged public surface rather than crate-internal behaviour (PL-3).
//!
//! The join has two halves and both are mandatory:
//!
//! * The **manifest half** consumes the exact `http_03_evaluator_manifest_v1`
//!   inputs published by implementation A (`HTTP-03.01`..`HTTP-03.13`) and
//!   implementation B (`HTTP-03.14`..`HTTP-03.26`) together with their
//!   SHA-256 digests, and verifies the ordered union across both producers.
//!   The manifests are producer-owned inputs: this file deliberately does not
//!   define, mirror, or reconstruct them, because a locally authored manifest
//!   would prove nothing about the producers.
//! * The **execution half** drives the shipped modern HTTP client against real
//!   `TcpListener` fixtures and records, per manifest case, the exact POST
//!   method/body/headers, the JSON-or-SSE terminal outcome, stream-close and
//!   progress ownership, endpoint/security partition identity, the canonical
//!   target, the discovery frame, and the 3x3 no-downgrade observation state.
//!
//! The `floor=N` value declared by each producer row is enforced by execution:
//! the evaluator must actually perform at least `N` observations for that case.
//! No floor table is duplicated here, so raising a producer floor raises what
//! this join demands rather than silently passing.

use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

// The caller-owned runtime comes from the `asupersync` dev-dependency directly,
// never through `fastmcp_rust::asupersync`: that facade re-export is gated behind
// the `testing-lab` feature, so reaching it would drag `asupersync/test-internals`
// into this target's graph and force a `required-features` stanza. The AC requires
// this target to be auto-discovered under the DEFAULT facade feature set, and
// `cfg(test)`-only or lab-only behaviour cannot prove shipped behaviour (PL-3).
// Every sibling target does the same; see `tests/e2e_stress.rs:18`.
use asupersync::{CancelKind, Cx};
use asupersync::runtime::RuntimeBuilder;
use fastmcp_rust::client::http_executor::{
    HTTP_03_A_EVALUATOR_MANIFEST_V1, HTTP_03_B_EVALUATOR_MANIFEST_V1, ModernHttpFinalCoreEvent,
    ModernHttpFinalCoreListenError, http_03_a_manifest_digest, http_03_b_manifest_digest,
};
use fastmcp_rust::client::{
    BearerBindingError, BoundBearerCredential, ClientBuilder, ClientHttpConnection,
    ClientHttpConnectionError, ClientHttpNegotiation, ClientHttpNegotiationDecision,
    ClientHttpNegotiationError, ClientHttpResponse, ClientProtocolPlan, MODERN_MCP_ACCEPT,
    MODERN_MCP_ACCEPT_ENCODING, MODERN_MCP_CONTENT_TYPE, ModernHttpClientError,
    ModernHttpExecutorError, ModernHttpRequest, ModernHttpResponseKind, RequestTimeoutPolicy,
    SseLimits, validate_response_head,
};
use fastmcp_rust::{
    CanonicalHttpUrl, FinalCoreResult, HttpEndpointBundleKey, HttpModernProbe, HttpProbeBody,
    JsonRpcRequest, ProgressMarker, ProtocolEra, ProtocolPolicy, RequestId, ServerNotification,
    Sha256Digest, sha256_bounded,
};

/// The join's own public entrypoint, recorded in the receipt (PL-3).
const JOINED_PUBLIC_ENTRYPOINT: &str =
    "fastmcp_rust::client::ClientBuilder::connect_http_with_cx -> ClientHttpConnection";

/// Ordered case identifiers the union must equal, inclusive.
const FIRST_CASE_ORDINAL: usize = 1;
const LAST_CASE_ORDINAL: usize = 26;

/// Minimum ordered positive cases the integrated evaluator must execute.
const MINIMUM_POSITIVE_CASES: usize = 26;
/// Minimum ordered one-variable planted-negative cases it must execute.
const MINIMUM_NEGATIVE_CASES: usize = 26;

/// The manifest case whose single variable the planted-negative test changes.
const PLANTED_CASE_ID: &str = "HTTP-03.11";

/// The clock regime this join runs under (PL-5 records clocks).
///
/// These are the single source for both the shipped `RequestTimeoutPolicy` the
/// join installs AND the value the receipt reports, so the recorded regime
/// cannot drift from the one actually executed. They are DECLARED bounds, not
/// measured elapsed time: a declared limit is stable across runs, whereas a
/// measurement would differ between the accepted and planted passes and break
/// the byte-for-byte case equality `http_03_i_planted_negative` depends on.
const JOIN_IDLE_TIMEOUT: Duration = Duration::from_secs(5);
const JOIN_ABSOLUTE_TIMEOUT: Duration = Duration::from_secs(20);
/// The idle bound HTTP-03.15 arms against a held-open, silent peer.
const DEADLINE_LANE_IDLE_TIMEOUT: Duration = Duration::from_millis(50);

/// Bound used for every manifest digest recomputation.
const MAX_MANIFEST_BYTES: usize = 64 * 1024;

/// The bearer secret used for credential-binding observations. It must never
/// reach a wire capture or a rendered diagnostic.
const BEARER_SECRET: &str = "http-03-integration-bearer-secret";

/// Placeholder substituted for the ephemeral fixture authority so that case
/// records are byte-comparable across runs.
const FIXTURE_AUTHORITY_PLACEHOLDER: &str = "<fixture-authority>";

// ---------------------------------------------------------------------------
// Producer manifest consumption
// ---------------------------------------------------------------------------

/// One ordered evaluator case declared by a producer manifest.
#[derive(Debug, Clone, PartialEq, Eq)]
struct ManifestCase {
    id: String,
    name: String,
    floor: usize,
}

/// One producer's parsed `http_03_evaluator_manifest_v1`.
#[derive(Debug, Clone)]
struct ProducerManifest {
    header: String,
    producer_revision: String,
    producer_tree: String,
    entrypoint: String,
    cases: Vec<ManifestCase>,
}

/// Parses one producer manifest, enforcing LF canonicality before any row is
/// interpreted. Anything that is not exactly the frozen shape is a failure of
/// the join, never something this side repairs.
fn parse_producer_manifest(expected_header: &str, text: &str) -> ProducerManifest {
    assert!(
        !text.is_empty(),
        "{expected_header}: the producer manifest must not be empty"
    );
    assert!(
        text.ends_with('\n'),
        "{expected_header}: the producer manifest must be LF-terminated"
    );
    assert!(
        !text.contains('\r'),
        "{expected_header}: the producer manifest must be LF-canonical (no CR)"
    );

    let mut lines = text.split('\n');
    let mut rows: Vec<&str> = Vec::new();
    for line in lines.by_ref() {
        if line.is_empty() {
            break;
        }
        assert_eq!(
            line.trim_end(),
            line,
            "{expected_header}: manifest rows must not carry trailing whitespace"
        );
        rows.push(line);
    }
    assert!(
        lines.next().is_none(),
        "{expected_header}: the manifest must contain no blank or trailing lines"
    );
    assert!(
        rows.len() > 4,
        "{expected_header}: the manifest needs its four header rows and at least one case row"
    );

    assert_eq!(
        rows[0], expected_header,
        "the producer manifest must declare its exact frozen header"
    );
    let producer_revision = required_field(expected_header, rows[1], "producer-revision");
    let producer_tree = required_field(expected_header, rows[2], "producer-tree");
    let entrypoint = required_field(expected_header, rows[3], "entrypoint");
    assert!(
        is_lowercase_hex(&producer_revision),
        "{expected_header}: producer-revision must be a lowercase hex object name"
    );
    assert!(
        is_lowercase_hex(&producer_tree),
        "{expected_header}: producer-tree must be a lowercase hex object name"
    );
    assert!(
        entrypoint.starts_with("fastmcp"),
        "{expected_header}: entrypoint must name a shipped public path, got {entrypoint:?}"
    );

    let cases = rows[4..]
        .iter()
        .map(|row| parse_case_row(expected_header, row))
        .collect::<Vec<_>>();

    ProducerManifest {
        header: rows[0].to_owned(),
        producer_revision,
        producer_tree,
        entrypoint,
        cases,
    }
}

fn required_field(header: &str, row: &str, key: &str) -> String {
    let value = row
        .strip_prefix(key)
        .and_then(|rest| rest.strip_prefix(' '))
        .unwrap_or_else(|| panic!("{header}: expected a `{key} <value>` row, got {row:?}"));
    assert!(
        !value.is_empty(),
        "{header}: the `{key}` row must carry a value"
    );
    value.to_owned()
}

fn parse_case_row(header: &str, row: &str) -> ManifestCase {
    let mut fields = row.split(' ');
    let id = fields
        .next()
        .unwrap_or_else(|| panic!("{header}: empty case row"))
        .to_owned();
    let name = fields
        .next()
        .unwrap_or_else(|| panic!("{header}: case {id} has no case name"))
        .to_owned();
    let floor_field = fields
        .next()
        .unwrap_or_else(|| panic!("{header}: case {id} has no `floor=` field"));
    assert!(
        fields.next().is_none(),
        "{header}: case {id} carries unexpected trailing fields"
    );
    let floor: usize = floor_field
        .strip_prefix("floor=")
        .unwrap_or_else(|| {
            panic!("{header}: case {id} must declare `floor=<N>`, got {floor_field:?}")
        })
        .parse()
        .unwrap_or_else(|_| panic!("{header}: case {id} declares a non-numeric floor"));
    assert!(
        floor >= 1,
        "{header}: case {id} must declare a positive numeric floor"
    );
    assert!(
        !name.is_empty(),
        "{header}: case {id} must declare a non-empty case name"
    );
    ManifestCase { id, name, floor }
}

fn is_lowercase_hex(value: &str) -> bool {
    !value.is_empty()
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

/// The ordered union of both producer manifests plus the digest binding.
#[derive(Debug, Clone)]
struct JoinedManifest {
    a: ProducerManifest,
    b: ProducerManifest,
    a_digest: Sha256Digest,
    b_digest: Sha256Digest,
    cases: Vec<ManifestCase>,
}

impl JoinedManifest {
    /// Consumes both producer manifests through their shipped public accessors
    /// and verifies the ordered union `HTTP-03.01`..`HTTP-03.26`.
    fn consume() -> Self {
        let a = parse_producer_manifest(
            "HTTP-03-A evaluator manifest v1",
            HTTP_03_A_EVALUATOR_MANIFEST_V1,
        );
        let b = parse_producer_manifest(
            "HTTP-03-B evaluator manifest v1",
            HTTP_03_B_EVALUATOR_MANIFEST_V1,
        );

        // The published digest must bind the published bytes. A digest that
        // does not recompute means the two halves of the producer's own
        // acceptance input have drifted apart.
        let a_digest = recompute_digest(HTTP_03_A_EVALUATOR_MANIFEST_V1);
        let b_digest = recompute_digest(HTTP_03_B_EVALUATOR_MANIFEST_V1);
        assert_eq!(
            http_03_a_manifest_digest().as_bytes(),
            a_digest.as_bytes(),
            "implementation A's published digest must bind its published manifest bytes"
        );
        assert_eq!(
            http_03_b_manifest_digest().as_bytes(),
            b_digest.as_bytes(),
            "implementation B's published digest must bind its published manifest bytes"
        );
        assert_ne!(
            a_digest.as_bytes(),
            b_digest.as_bytes(),
            "the two producer manifests must be distinct acceptance inputs"
        );

        assert_ne!(
            a.header, b.header,
            "the A and B manifests must declare distinct frozen headers"
        );

        let mut cases = a.cases.clone();
        cases.extend(b.cases.iter().cloned());

        let expected: Vec<String> = (FIRST_CASE_ORDINAL..=LAST_CASE_ORDINAL)
            .map(|ordinal| format!("HTTP-03.{ordinal:02}"))
            .collect();
        let observed: Vec<String> = cases.iter().map(|case| case.id.clone()).collect();
        assert_eq!(
            observed, expected,
            "the ordered union of the A and B manifests must be exactly HTTP-03.01..HTTP-03.26 \
             with no omission, duplication, or reorder"
        );

        let mut names: BTreeMap<&str, &str> = BTreeMap::new();
        for case in &cases {
            assert!(
                names.insert(case.name.as_str(), case.id.as_str()).is_none(),
                "case name {:?} is declared twice in the joined manifest",
                case.name
            );
        }

        Self {
            a,
            b,
            a_digest,
            b_digest,
            cases,
        }
    }
}

fn recompute_digest(manifest: &str) -> Sha256Digest {
    sha256_bounded(manifest.as_bytes(), MAX_MANIFEST_BYTES)
        .expect("a producer manifest must stay within the bounded digest input")
}

fn render_digest(digest: &Sha256Digest) -> String {
    use std::fmt::Write as _;
    digest.as_bytes().iter().fold(String::new(), |mut rendered, byte| {
        let _ = write!(rendered, "{byte:02x}");
        rendered
    })
}

// ---------------------------------------------------------------------------
// Real-socket fixture
// ---------------------------------------------------------------------------

/// One HTTP request exactly as it arrived at the fixture.
#[derive(Debug, Clone)]
struct CapturedRequest {
    head: String,
    body: Vec<u8>,
}

impl CapturedRequest {
    fn header(&self, name: &str) -> Option<String> {
        self.head.lines().find_map(|line| {
            line.split_once(':').and_then(|(field, value)| {
                field
                    .eq_ignore_ascii_case(name)
                    .then(|| value.trim().to_owned())
            })
        })
    }

    fn request_line(&self) -> &str {
        self.head.lines().next().unwrap_or_default()
    }

    fn json_body(&self) -> serde_json::Value {
        serde_json::from_slice(&self.body).expect("every captured MCP POST body must be JSON-RPC")
    }
}

fn read_request(stream: &mut TcpStream) -> CapturedRequest {
    let mut wire = Vec::new();
    let mut buffer = [0_u8; 4096];
    let head_end = loop {
        let read = stream.read(&mut buffer).expect("read fixture HTTP request");
        assert!(read > 0, "client closed before a complete request arrived");
        wire.extend_from_slice(&buffer[..read]);
        if let Some(position) = wire.windows(4).position(|window| window == b"\r\n\r\n") {
            break position + 4;
        }
    };
    let head = std::str::from_utf8(&wire[..head_end])
        .expect("request head must be UTF-8")
        .to_owned();
    let content_length = head
        .lines()
        .find_map(|line| {
            line.split_once(':').and_then(|(field, value)| {
                field.eq_ignore_ascii_case("content-length").then(|| {
                    value
                        .trim()
                        .parse::<usize>()
                        .expect("numeric Content-Length")
                })
            })
        })
        .unwrap_or(0);
    while wire.len() < head_end.saturating_add(content_length) {
        let read = stream.read(&mut buffer).expect("read fixture request body");
        assert!(read > 0, "client closed before the advertised body arrived");
        wire.extend_from_slice(&buffer[..read]);
    }
    CapturedRequest {
        head,
        body: wire[head_end..head_end + content_length].to_vec(),
    }
}

fn write_bounded_response(
    stream: &mut TcpStream,
    status: u16,
    content_type: &str,
    content_encoding: Option<&str>,
    body: &[u8],
) {
    let reason = match status {
        200 => "OK",
        202 => "Accepted",
        _ => "Fixture Response",
    };
    write!(stream, "HTTP/1.1 {status} {reason}\r\n").expect("write fixture status line");
    write!(stream, "Content-Type: {content_type}\r\n").expect("write fixture content type");
    if let Some(encoding) = content_encoding {
        write!(stream, "Content-Encoding: {encoding}\r\n").expect("write fixture content coding");
    }
    write!(stream, "Content-Length: {}\r\n", body.len()).expect("write fixture content length");
    write!(stream, "Connection: close\r\n\r\n").expect("write fixture head terminator");
    stream.write_all(body).expect("write fixture body");
    stream.flush().expect("flush fixture response");
}

/// Writes the streaming SSE response head.
///
/// The head MUST carry an explicit framing header. In asupersync 0.5.0 a
/// response with neither `Content-Length` nor `Transfer-Encoding` frames an
/// **empty** body — `BodyKind` has only `ContentLength`, `Chunked`, and
/// `Empty`, with no close-delimited variant — so the client would observe zero
/// events on a stream the fixture believed it had written. That failure mode is
/// silent for any test that only checks "no error", which is why the framing is
/// chunked here and the terminating chunk is always written.
fn begin_sse_response(stream: &mut TcpStream) {
    write!(
        stream,
        "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nContent-Encoding: identity\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n"
    )
    .expect("write fixture SSE head");
    stream.flush().expect("flush fixture SSE head");
}

/// Writes one SSE event as its own chunk, so a chunk boundary sits between
/// every dispatched event.
fn write_sse_event(stream: &mut TcpStream, payload: &serde_json::Value) {
    let body = format!("data: {payload}\n\n").into_bytes();
    assert!(
        !body.is_empty(),
        "a zero-length chunk would terminate the response body early"
    );
    write!(stream, "{:x}\r\n", body.len()).expect("write fixture chunk length");
    stream
        .write_all(&body)
        .expect("write fixture chunk payload");
    write!(stream, "\r\n").expect("write fixture chunk terminator");
    stream.flush().expect("flush fixture SSE event");
}

/// Closes a chunked SSE body with its terminating zero-length chunk.
/// Writes one SSE event carrying an explicit `id:` field.
///
/// Used only to PLANT resumption bait. A stream that publishes an event id is
/// the one condition under which a client could plausibly start carrying
/// resumption state into later requests, so HTTP-03.25's negative creates that
/// condition deliberately rather than asserting an absence that nothing ever
/// challenged.
fn write_sse_event_with_id(stream: &mut TcpStream, id: &str, payload: &serde_json::Value) {
    let body = format!("id: {id}\ndata: {payload}\n\n").into_bytes();
    write!(stream, "{:x}\r\n", body.len()).expect("write fixture chunk length");
    stream
        .write_all(&body)
        .expect("write fixture chunk payload");
    write!(stream, "\r\n").expect("write fixture chunk terminator");
    stream.flush().expect("flush fixture SSE event");
}

fn end_sse_response(stream: &mut TcpStream) {
    write!(stream, "0\r\n\r\n").expect("write fixture terminating chunk");
    stream.flush().expect("flush fixture terminating chunk");
}

fn accept_bounded(listener: &TcpListener) -> TcpStream {
    let deadline = Instant::now() + Duration::from_secs(10);
    listener
        .set_nonblocking(true)
        .expect("set fixture listener nonblocking");
    loop {
        match listener.accept() {
            Ok((stream, _)) => {
                stream
                    .set_nonblocking(false)
                    .expect("set accepted fixture stream blocking");
                stream
                    .set_read_timeout(Some(Duration::from_secs(10)))
                    .expect("bound accepted fixture reads");
                stream
                    .set_write_timeout(Some(Duration::from_secs(10)))
                    .expect("bound accepted fixture writes");
                return stream;
            }
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                assert!(
                    Instant::now() < deadline,
                    "timed out waiting for a client connection on the fixture listener"
                );
                thread::sleep(Duration::from_millis(5));
            }
            Err(error) => panic!("unexpected fixture accept error: {error}"),
        }
    }
}

fn discovery_body(id: u64, instance: &str) -> Vec<u8> {
    serde_json::to_vec(&serde_json::json!({
        "jsonrpc": "2.0",
        "id": id,
        "result": {
            "resultType": "complete",
            "supportedVersions": ["2026-07-28"],
            "capabilities": {},
            "ttlMs": 0,
            "cacheScope": "private",
            "_meta": {
                "io.modelcontextprotocol/serverInfo": {
                    "name": format!("http-03-integration-{instance}"),
                    "version": "1.0.0"
                }
            }
        }
    }))
    .expect("fixture discovery result must serialize")
}

fn progress_event(marker: &ProgressMarker, progress: u64) -> serde_json::Value {
    serde_json::json!({
        "jsonrpc": "2.0",
        "method": "notifications/progress",
        "params": {
            "progressToken": marker,
            "progress": progress,
            "total": 2,
        },
    })
}

fn terminal_tool_event(request_id: u64) -> serde_json::Value {
    serde_json::json!({
        "jsonrpc": "2.0",
        "id": request_id,
        "result": {
            "resultType": "complete",
            "content": [{"type": "text", "text": "http-03-join-terminal"}],
            "isError": false,
        },
    })
}

fn ping_body(id: u64) -> Vec<u8> {
    serde_json::to_vec(&serde_json::json!({
        "jsonrpc": "2.0",
        "id": id,
        "result": {},
    }))
    .expect("fixture ping result must serialize")
}

// ---------------------------------------------------------------------------
// Wire observations produced by one fixture run
// ---------------------------------------------------------------------------

/// Everything the joined run observed on real sockets and through the public
/// client state, normalized so it is byte-comparable between runs.
#[derive(Debug, Clone)]
struct WireObservations {
    fixture_authority: String,
    a_probe: CapturedRequest,
    a_call: CapturedRequest,
    b_probe: CapturedRequest,
    b_ping: CapturedRequest,
    b_lane_probe: CapturedRequest,
    a_progress: Vec<String>,
    a_terminal: String,
    a_post_terminal: String,
    a_discovery: String,
    a_versions: Vec<String>,
    a_endpoint_key: HttpEndpointBundleKey,
    a_target: String,
    a_era: ProtocolEra,
    b_discovery: String,
    b_versions: Vec<String>,
    b_endpoint_key: HttpEndpointBundleKey,
    b_target: String,
    b_era: ProtocolEra,
    b_json_outcome: String,
    b_lane_refusal: String,
    method_count: BTreeMap<String, usize>,
    legacy_get_count: usize,
    uncertain_dispatch: LaneObservation,
    deadline_race: LaneObservation,
    caller_cancellation: CancellationObservation,
    independent_server_request: ServerRequestObservation,
    extension_notification: NotificationObservation,
}

impl WireObservations {
    /// Replaces the ephemeral fixture authority so records compare byte-for-byte.
    fn normalize(&self, value: &str) -> String {
        value.replace(&self.fixture_authority, FIXTURE_AUTHORITY_PLACEHOLDER)
    }
}

fn canonical_plan(
    target: &str,
    policy: ProtocolPolicy,
    security_partition: &str,
) -> ClientProtocolPlan {
    ClientProtocolPlan::http(
        policy,
        Some(CanonicalHttpUrl::parse(target).expect("fixture target must be canonical")),
        None,
        None,
        "credential-partition-http-03-integration".to_owned(),
        security_partition.to_owned(),
        "native-h1-http-03-integration".to_owned(),
        1,
        1,
        0,
    )
    .expect("the modern-only integration plan must be accepted")
}

/// A dual-era classification plan whose endpoint set is identical for every
/// policy, so the no-downgrade matrix can change the policy and nothing else.
fn classification_plan(policy: ProtocolPolicy) -> ClientProtocolPlan {
    ClientProtocolPlan::http(
        policy,
        Some(
            CanonicalHttpUrl::parse("https://mcp.example.test/mcp")
                .expect("the classification modern target is canonical"),
        ),
        Some(
            CanonicalHttpUrl::parse("https://mcp.example.test/sse")
                .expect("the classification legacy SSE target is canonical"),
        ),
        Some(
            CanonicalHttpUrl::parse("https://mcp.example.test/messages")
                .expect("the classification legacy message target is canonical"),
        ),
        "credential-partition-http-03-integration".to_owned(),
        "security-partition-http-03-integration".to_owned(),
        "native-h1-http-03-integration".to_owned(),
        1,
        1,
        0,
    )
    .expect("the classification plan must be accepted for every policy")
}

/// Replaces a dedicated lane's own ephemeral authority with a stable placeholder.
///
/// Each lane binds `127.0.0.1:0`, so its address differs on every run AND between
/// the accepted and planted passes of `evaluate_join`. `http_03_i_planted_negative`
/// requires every case except the planted one to be byte-for-byte identical across
/// those two passes, so any address that reached a recorded string would fail an
/// unrelated case and look like a real regression. Normalizing at the point of
/// capture makes the record stable by construction rather than by luck about
/// whether a given typed error happens to embed its peer.
fn normalize_lane(address: SocketAddr, value: String) -> String {
    // Only the full `host:port` authority is replaced. Replacing the bare port
    // as well would be over-broad: an ephemeral port is an ordinary small
    // integer and could collide with a legitimate number in the same string -
    // `SseLimits::new(4_096, ..)` against a port of 4096 - silently corrupting
    // the record this case is supposed to compare.
    value.replace(&address.to_string(), FIXTURE_AUTHORITY_PLACEHOLDER)
}

/// What a single dedicated real-socket scenario observed.
///
/// `connections_after_return` is how the no-retry claim is made without any
/// timing tolerance. A retry, if the client performed one, is issued *inside*
/// the failing call, so by the time that call has returned its connection is
/// already sitting in the listener's accept backlog. Draining the backlog after
/// the call returns therefore observes a retry that happened, and cannot
/// observe one that has not happened yet. No sleep, no deadline, no tolerance.
#[derive(Debug, Clone)]
struct LaneObservation {
    outcome: String,
    followup_outcome: String,
    requests_during_call: usize,
    connections_after_return: usize,
    server_held_connection_open: bool,
}

/// Drives one request against a dedicated fixture whose behaviour after reading
/// the POST is chosen by `stall_then_hold`.
///
/// `stall_then_hold == false`: the fixture reads the whole POST and closes
/// without answering - the request certainly arrived, and the client cannot
/// know whether it was dispatched (HTTP-03.16).
///
/// `stall_then_hold == true`: the fixture reads the whole POST and then holds
/// the connection OPEN, sending nothing, until the driver releases it. The
/// connection never breaks, so a timeout here is the deadline winning rather
/// than a disconnect being misreported (HTTP-03.15).
fn observe_lane(stall_then_hold: bool, idle_timeout: Duration) -> LaneObservation {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind the lane fixture");
    let address = listener.local_addr().expect("read the lane fixture address");
    let target = format!("http://{address}/mcp-lane");
    let (release_tx, release_rx) = mpsc::channel::<()>();
    let (report_tx, report_rx) = mpsc::channel::<(usize, usize, bool)>();
    let (drained_tx, drained_rx) = mpsc::channel::<usize>();

    let server = thread::spawn(move || {
        let mut requests = 0_usize;

        // 1. Answer the one-shot discovery probe normally so the connection
        //    classifies modern before the lane under test is exercised.
        let mut probe = accept_bounded(&listener);
        let _probe_request = read_request(&mut probe);
        write_bounded_response(
            &mut probe,
            200,
            "application/json",
            Some("identity"),
            &discovery_body(1, "lane"),
        );
        drop(probe);

        // 2. Read the request POST in full, then either close or hold.
        let mut call = accept_bounded(&listener);
        let _call_request = read_request(&mut call);
        requests += 1;
        let held = if stall_then_hold {
            // Hold the socket open and send nothing. `call` stays alive across
            // the wait, so the peer observes an open, silent connection.
            release_rx.recv().expect("driver releases the stalled lane");
            true
        } else {
            drop(call);
            release_rx.recv().expect("driver reports the call returned");
            false
        };

        // 3. Drain the accept backlog BEFORE anything else reaches this
        //    listener. Any retry the client made is already queued, so this is a
        //    drain, not a poll - and it must complete before the deliberate
        //    follow-up below, or a caller-initiated request would be miscounted
        //    as a client-initiated retry. That ordering is the whole reason the
        //    count is published on its own channel first.
        listener
            .set_nonblocking(true)
            .expect("set the lane listener nonblocking for the backlog drain");
        let mut extra = 0_usize;
        while let Ok((stream, _)) = listener.accept() {
            extra += 1;
            drop(stream);
        }
        drained_tx.send(extra).expect("publish the retry count");

        // 4. Serve one deliberate follow-up so the caller can establish that the
        //    refusal left the connection usable rather than poisoned.
        listener
            .set_nonblocking(false)
            .expect("restore blocking accept for the follow-up");
        let mut followup = accept_bounded(&listener);
        let _followup_request = read_request(&mut followup);
        requests += 1;
        write_bounded_response(
            &mut followup,
            200,
            "application/json",
            Some("identity"),
            &ping_body(43),
        );
        drop(followup);

        report_tx
            .send((requests, extra, held))
            .expect("report lane observations");
    });

    let runtime = RuntimeBuilder::current_thread()
        .build()
        .expect("the lane scenario owns its caller runtime");
    let outcome = runtime.block_on(async {
        let cx = Cx::current().expect("the caller runtime must install a current Cx");
        let mut connection = ClientBuilder::new()
            .client_info("http-03-integration-client", "1.0.0")
            .protocol_plan(canonical_plan(
                &target,
                ProtocolPolicy::ModernOnly,
                "security-partition-http-03-integration",
            ))
            .request_timeout_policy(
                RequestTimeoutPolicy::new(idle_timeout, JOIN_ABSOLUTE_TIMEOUT)
                    .expect("the lane timeout policy must be valid")
                    .reset_idle_on_matching_progress(true),
            )
            .connect_http_with_cx(&cx)
            .await
            .expect("the lane endpoint must connect through the public builder");

        let first = match connection
            .request_json(
                &cx,
                "ping",
                serde_json::json!({}),
                RequestId::Number(41),
                65_536,
            )
            .await
        {
            Ok(response) => format!("unexpected-success id={:?}", response.id),
            Err(error) => render_connection_error(&error),
        };

        // Side four of the boundary shape: a refusal must leave the connection
        // USABLE, not poisoned. Ordering matters - the fixture publishes its
        // retry count before serving this, so a deliberate follow-up can never
        // be miscounted as a client-initiated retry.
        release_tx
            .send(())
            .expect("tell the lane fixture the call returned");
        let drained = drained_rx
            .recv()
            .expect("the lane fixture publishes its retry count before the follow-up");

        let followup = match connection
            .request_json(
                &cx,
                "ping",
                serde_json::json!({}),
                RequestId::Number(43),
                65_536,
            )
            .await
        {
            Ok(response) => format!("followup-ok id={:?}", response.id),
            Err(error) => format!("followup-refused::{}", render_connection_error(&error)),
        };
        (first, followup, drained)
    });
    let (outcome, followup_outcome, _drained) = outcome;
    let outcome = normalize_lane(address, outcome);
    let followup_outcome = normalize_lane(address, followup_outcome);

    let (requests_during_call, connections_after_return, server_held_connection_open) =
        report_rx.recv().expect("collect lane observations");
    server.join().expect("the lane fixture thread must not panic");

    LaneObservation {
        outcome,
        followup_outcome,
        requests_during_call,
        connections_after_return,
        server_held_connection_open,
    }
}

/// What the HTTP-03.14 caller-cancellation scenario observed.
#[derive(Debug, Clone)]
struct CancellationObservation {
    progress_before_cancel: usize,
    post_cancel_outcome: String,
    server_saw_stream_close: bool,
    requests_during_call: usize,
    connections_after_return: usize,
}

/// Opens a request-scoped SSE stream, consumes one progress event to prove the
/// stream is live, cancels the caller's `Cx`, and observes both what the caller
/// sees and what the server sees.
///
/// The server half matters as much as the client half: `server_saw_stream_close`
/// is EOF observed on the response connection. Without it this would prove only
/// that the caller stopped reading, which is not the same claim as the response
/// stream being closed - a leaked connection would look identical from inside
/// the client. The wait for EOF is bounded and the case REQUIRES the close, so a
/// leak fails here rather than being tolerated.
fn observe_caller_cancellation() -> CancellationObservation {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind the cancellation fixture");
    let address = listener
        .local_addr()
        .expect("read the cancellation fixture address");
    let target = format!("http://{address}/mcp-cancel");
    let marker = ProgressMarker::from("http-03-integration-cancel");
    let server_marker = marker.clone();
    let (release_tx, release_rx) = mpsc::channel::<()>();
    let (report_tx, report_rx) = mpsc::channel::<(usize, bool, usize)>();

    let server = thread::spawn(move || {
        let mut probe = accept_bounded(&listener);
        let _probe_request = read_request(&mut probe);
        write_bounded_response(
            &mut probe,
            200,
            "application/json",
            Some("identity"),
            &discovery_body(1, "cancel"),
        );
        drop(probe);

        let mut call = accept_bounded(&listener);
        let _call_request = read_request(&mut call);
        begin_sse_response(&mut call);
        write_sse_event(&mut call, &progress_event(&server_marker, 1));

        // Block reading the response connection. A cancelling caller closes it,
        // which surfaces here as EOF.
        call.set_read_timeout(Some(Duration::from_secs(10)))
            .expect("bound the cancellation fixture read");
        let mut sink = [0_u8; 1024];
        let saw_close = matches!(call.read(&mut sink), Ok(0));
        drop(call);

        release_rx
            .recv()
            .expect("driver reports the cancelled call returned");
        listener
            .set_nonblocking(true)
            .expect("set the cancellation listener nonblocking for the backlog drain");
        let mut extra = 0_usize;
        while let Ok((stream, _)) = listener.accept() {
            extra += 1;
            drop(stream);
        }
        report_tx
            .send((1, saw_close, extra))
            .expect("report cancellation observations");
    });

    let runtime = RuntimeBuilder::current_thread()
        .build()
        .expect("the cancellation scenario owns its caller runtime");
    let (progress_before_cancel, post_cancel_outcome) = runtime.block_on(async {
        let cx = Cx::current().expect("the caller runtime must install a current Cx");
        let limits = SseLimits::new(4_096, 65_536, 8).expect("bounded SSE limits are nonzero");
        let connection = integration_builder(&target)
            .connect_http_with_cx(&cx)
            .await
            .expect("the cancellation endpoint must connect through the public builder");
        let mut stream_listener = connection
            .open_final_core_listener(
                &cx,
                "tools/call",
                serde_json::json!({
                    "name": "http_03_cancel_tool",
                    "arguments": {},
                    "_meta": {"progressToken": marker.clone()},
                }),
                RequestId::Number(51),
                limits,
            )
            .await
            .expect("the shipped SSE lane must open a request-owned listener");

        // One live progress event proves the stream is open and delivering
        // before anything is cancelled.
        let mut seen = 0_usize;
        match stream_listener.next_event(&cx).await {
            Ok(Some(ModernHttpFinalCoreEvent::Progress(progress))) => {
                assert_eq!(
                    progress.progress_token, marker,
                    "progress must reach only the request that owns the marker"
                );
                seen += 1;
            }
            other => panic!("expected a live progress event before cancelling, observed {other:?}"),
        }

        // The single variable: the caller cancels.
        cx.cancel_with(CancelKind::User, Some("http-03-integration caller cancellation"));

        let outcome = match stream_listener.next_event(&cx).await {
            Ok(Some(event)) => format!("unexpected-event::{event:?}"),
            Ok(None) => "unexpected-clean-end".to_owned(),
            Err(error) => format!("listen::{error:?}"),
        };
        (seen, normalize_lane(address, outcome))
    });

    release_tx
        .send(())
        .expect("release the cancellation fixture");
    let (requests_during_call, server_saw_stream_close, connections_after_return) =
        report_rx.recv().expect("collect cancellation observations");
    server
        .join()
        .expect("the cancellation fixture thread must not panic");

    CancellationObservation {
        progress_before_cancel,
        post_cancel_outcome,
        server_saw_stream_close,
        requests_during_call,
        connections_after_return,
    }
}

/// What the HTTP-03.24 independent-server-request scenario observed.
#[derive(Debug, Clone)]
struct ServerRequestObservation {
    outcome: String,
    requests_during_call: usize,
    connections_after_return: usize,
}

/// Delivers an independent server->client JSON-RPC *request* over a response
/// stream the caller opened for its own request, and observes what the shipped
/// client does with it.
///
/// The frame carries both `id` and `method`, which is what makes it a request
/// rather than a response or a notification. A response stream is owned by the
/// caller's request; an independent request arriving on it is not the caller's
/// result and must not be handed back as one.
///
/// The outcome is captured rather than predicted. This records whatever the
/// shipped surface does and asserts only that the frame was NOT delivered as an
/// ordinary event - if the client admitted it, that is a real finding and this
/// case is where it surfaces.
fn observe_independent_server_request() -> ServerRequestObservation {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind the server-request fixture");
    let address = listener
        .local_addr()
        .expect("read the server-request fixture address");
    let target = format!("http://{address}/mcp-server-request");
    let (release_tx, release_rx) = mpsc::channel::<()>();
    let (report_tx, report_rx) = mpsc::channel::<(usize, usize)>();

    let server = thread::spawn(move || {
        let mut probe = accept_bounded(&listener);
        let _probe_request = read_request(&mut probe);
        write_bounded_response(
            &mut probe,
            200,
            "application/json",
            Some("identity"),
            &discovery_body(1, "server-request"),
        );
        drop(probe);

        let mut call = accept_bounded(&listener);
        let _call_request = read_request(&mut call);
        begin_sse_response(&mut call);
        // An independent server->client request: `id` AND `method` together.
        write_sse_event(
            &mut call,
            &serde_json::json!({
                "jsonrpc": "2.0",
                "id": 9001,
                "method": "sampling/createMessage",
                "params": {},
            }),
        );
        release_rx
            .recv()
            .expect("driver reports the server-request call returned");
        drop(call);

        listener
            .set_nonblocking(true)
            .expect("set the server-request listener nonblocking for the backlog drain");
        let mut extra = 0_usize;
        while let Ok((stream, _)) = listener.accept() {
            extra += 1;
            drop(stream);
        }
        report_tx
            .send((1, extra))
            .expect("report server-request observations");
    });

    let runtime = RuntimeBuilder::current_thread()
        .build()
        .expect("the server-request scenario owns its caller runtime");
    let outcome = runtime.block_on(async {
        let cx = Cx::current().expect("the caller runtime must install a current Cx");
        let limits = SseLimits::new(4_096, 65_536, 8).expect("bounded SSE limits are nonzero");
        let connection = integration_builder(&target)
            .connect_http_with_cx(&cx)
            .await
            .expect("the server-request endpoint must connect through the public builder");
        let mut stream_listener = connection
            .open_final_core_listener(
                &cx,
                "tools/call",
                serde_json::json!({
                    "name": "http_03_server_request_tool",
                    "arguments": {},
                }),
                RequestId::Number(61),
                limits,
            )
            .await
            .expect("the shipped SSE lane must open a request-owned listener");

        let raw = match stream_listener.next_event(&cx).await {
            Ok(Some(event)) => format!("admitted::{event:?}"),
            Ok(None) => "clean-end".to_owned(),
            Err(error) => format!("rejected::{error:?}"),
        };
        normalize_lane(address, raw)
    });

    release_tx
        .send(())
        .expect("release the server-request fixture");
    let (requests_during_call, connections_after_return) = report_rx
        .recv()
        .expect("collect server-request observations");
    server
        .join()
        .expect("the server-request fixture thread must not panic");

    ServerRequestObservation {
        outcome,
        requests_during_call,
        connections_after_return,
    }
}

/// What the HTTP-03.23 extension/notification scenario observed.
#[derive(Debug, Clone)]
struct NotificationObservation {
    first_event: String,
    second_request_resumption_header: Option<String>,
    terminal_after_notification: String,
    era_after_notification: ProtocolEra,
    requests_during_call: usize,
    connections_after_return: usize,
}

/// Delivers an admitted final-server notification on a caller-owned response
/// stream, ahead of the caller's terminal.
///
/// # Why this proves the reachable half of B's subject and says so
///
/// B names `extension-activation-proof-notification`. The activation-receipt
/// half of that - `mcp_apps_active` / `mcp_apps_activation_receipt` - is
/// `#[cfg(feature = "apps")]`, and `apps` is NOT in the default feature set
/// (facade default is `legacy-2024-11-05` + `tasks`; the client default is
/// `legacy-2024-11-05`). Those accessors are therefore not compiled into this
/// target at all. Adding `required-features = ["apps"]` would make the
/// no-flags runner in AC-7 stop discovering this target entirely, which AC-9
/// counts as a feature-disabled zero-run row - a worse outcome than an honest
/// partial proof.
///
/// So this exercises the half that IS on the default surface: the notification
/// delivery path, which carries no `cfg(feature)` gate
/// (`http_executor.rs:1454`, produced at `:1606`). The activation-receipt half
/// is reported as out of reach rather than simulated.
fn observe_extension_notification() -> NotificationObservation {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind the notification fixture");
    let address = listener
        .local_addr()
        .expect("read the notification fixture address");
    let target = format!("http://{address}/mcp-notification");
    let (release_tx, release_rx) = mpsc::channel::<()>();
    let (report_tx, report_rx) = mpsc::channel::<(usize, usize, Option<String>)>();

    let server = thread::spawn(move || {
        let mut probe = accept_bounded(&listener);
        let _probe_request = read_request(&mut probe);
        write_bounded_response(
            &mut probe,
            200,
            "application/json",
            Some("identity"),
            &discovery_body(1, "notification"),
        );
        drop(probe);

        let mut call = accept_bounded(&listener);
        let _call_request = read_request(&mut call);
        begin_sse_response(&mut call);
        // An admitted final-server notification: a method, no id.
        write_sse_event(
            &mut call,
            &serde_json::json!({
                "jsonrpc": "2.0",
                "method": "notifications/tools/list_changed",
            }),
        );
        // The caller's own terminal still follows it - and it PUBLISHES AN
        // EVENT ID, which is HTTP-03.25's planted variable.
        write_sse_event_with_id(&mut call, "planted-event-id-25", &terminal_tool_event(71));
        end_sse_response(&mut call);
        drop(call);

        // A SECOND request on a fresh connection. If the client retained any
        // resumption state from the id above, this is where it would surface as
        // a Last-Event-ID header.
        let mut second = accept_bounded(&listener);
        let second_request = read_request(&mut second);
        write_bounded_response(
            &mut second,
            200,
            "application/json",
            Some("identity"),
            &ping_body(72),
        );
        drop(second);

        release_rx
            .recv()
            .expect("driver reports the notification call returned");

        listener
            .set_nonblocking(true)
            .expect("set the notification listener nonblocking for the backlog drain");
        let mut extra = 0_usize;
        while let Ok((stream, _)) = listener.accept() {
            extra += 1;
            drop(stream);
        }
        report_tx
            .send((2, extra, second_request.header("Last-Event-ID")))
            .expect("report notification observations");
    });

    let runtime = RuntimeBuilder::current_thread()
        .build()
        .expect("the notification scenario owns its caller runtime");
    let (first_event, terminal_after_notification, era_after_notification) =
        runtime.block_on(async {
            let cx = Cx::current().expect("the caller runtime must install a current Cx");
            let limits = SseLimits::new(4_096, 65_536, 8).expect("bounded SSE limits are nonzero");
            let mut connection = integration_builder(&target)
                .connect_http_with_cx(&cx)
                .await
                .expect("the notification endpoint must connect through the public builder");
            let mut stream_listener = connection
                .open_final_core_listener(
                    &cx,
                    "tools/call",
                    serde_json::json!({
                        "name": "http_03_notification_tool",
                        "arguments": {},
                    }),
                    RequestId::Number(71),
                    limits,
                )
                .await
                .expect("the shipped SSE lane must open a request-owned listener");

            let first = match stream_listener.next_event(&cx).await {
                Ok(Some(ModernHttpFinalCoreEvent::Notification(notification))) => {
                    format!("notification::{notification:?}")
                }
                Ok(Some(other)) => format!("other::{other:?}"),
                Ok(None) => "clean-end".to_owned(),
                Err(error) => format!("rejected::{error:?}"),
            };
            let terminal = match stream_listener.next_event(&cx).await {
                Ok(Some(ModernHttpFinalCoreEvent::Terminal(_))) => "terminal=tools_call".to_owned(),
                Ok(Some(other)) => format!("other::{other:?}"),
                Ok(None) => "clean-end".to_owned(),
                Err(error) => format!("rejected::{error:?}"),
            };
            let era = connection.selected_protocol_era();
            let first = normalize_lane(address, first);
            let terminal = normalize_lane(address, terminal);

            // Release the stream borrow, then issue the SECOND request. This is
            // what gives HTTP-03.25's planted event id somewhere to leak to.
            drop(stream_listener);
            connection
                .request_json(
                    &cx,
                    "ping",
                    serde_json::json!({}),
                    RequestId::Number(72),
                    65_536,
                )
                .await
                .expect("the follow-up request must still succeed");

            (first, terminal, era)
        });

    release_tx
        .send(())
        .expect("release the notification fixture");
    let (requests_during_call, connections_after_return, second_request_resumption_header) =
        report_rx
            .recv()
            .expect("collect notification observations");
    server
        .join()
        .expect("the notification fixture thread must not panic");

    NotificationObservation {
        first_event,
        second_request_resumption_header,
        terminal_after_notification,
        era_after_notification,
        requests_during_call,
        connections_after_return,
    }
}

fn integration_builder(target: &str) -> ClientBuilder {
    ClientBuilder::new()
        .client_info("http-03-integration-client", "1.0.0")
        .protocol_plan(canonical_plan(
            target,
            ProtocolPolicy::ModernOnly,
            "security-partition-http-03-integration",
        ))
        .request_timeout_policy(
            RequestTimeoutPolicy::new(JOIN_IDLE_TIMEOUT, JOIN_ABSOLUTE_TIMEOUT)
                .expect("integration request timeout policy must be valid")
                .reset_idle_on_matching_progress(true),
        )
}

/// What the joined client half of one fixture run observed.
struct ClientOutcome {
    a_era: ProtocolEra,
    a_discovery: String,
    a_versions: Vec<String>,
    a_endpoint_key: HttpEndpointBundleKey,
    a_progress: Vec<String>,
    a_terminal: String,
    a_post_terminal: String,
    b_era: ProtocolEra,
    b_discovery: String,
    b_versions: Vec<String>,
    b_endpoint_key: HttpEndpointBundleKey,
    b_json_outcome: String,
    b_lane_refusal: String,
}

fn endpoint_key(connection: &ClientHttpConnection) -> HttpEndpointBundleKey {
    connection
        .protocol_plan()
        .http_endpoints()
        .expect("an HTTP connection must retain its configured endpoint bundle")
        .key()
}

/// Drives one complete fixture run. `plant_case_11` changes exactly one
/// variable: the `Content-Encoding` of the `/mcp-b` JSON terminal response.
fn run_fixture(plant_case_11: bool) -> WireObservations {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind the HTTP-03 integration fixture");
    let address = listener
        .local_addr()
        .expect("read the fixture listener address");
    let authority = address.to_string();
    let a_target = format!("http://{authority}/mcp-a");
    let b_target = format!("http://{authority}/mcp-b");
    let marker = ProgressMarker::from("http-03-integration-progress");
    let server_marker = marker.clone();
    let (captures_tx, captures_rx) = mpsc::channel();

    let server = thread::spawn(move || {
        // 1. /mcp-a one-shot discovery probe.
        let mut a_probe_stream = accept_bounded(&listener);
        let a_probe = read_request(&mut a_probe_stream);
        write_bounded_response(
            &mut a_probe_stream,
            200,
            "application/json",
            Some("identity"),
            &discovery_body(1, "a"),
        );
        captures_tx.send(a_probe).expect("record /mcp-a probe");

        // 2. /mcp-a streaming tools/call: head plus progress, terminal held back
        //    so the caller's waiter stays live across the /mcp-b exchanges.
        let mut a_call_stream = accept_bounded(&listener);
        let a_call = read_request(&mut a_call_stream);
        captures_tx.send(a_call).expect("record /mcp-a tools/call");
        begin_sse_response(&mut a_call_stream);
        write_sse_event(&mut a_call_stream, &progress_event(&server_marker, 1));
        write_sse_event(&mut a_call_stream, &progress_event(&server_marker, 2));

        // 3. /mcp-b one-shot discovery probe on the same origin.
        let mut b_probe_stream = accept_bounded(&listener);
        let b_probe = read_request(&mut b_probe_stream);
        write_bounded_response(
            &mut b_probe_stream,
            200,
            "application/json",
            Some("identity"),
            &discovery_body(1, "b"),
        );
        captures_tx.send(b_probe).expect("record /mcp-b probe");

        // 4. /mcp-b JSON terminal. The planted run changes only this coding.
        let mut b_ping_stream = accept_bounded(&listener);
        let b_ping = read_request(&mut b_ping_stream);
        write_bounded_response(
            &mut b_ping_stream,
            200,
            "application/json",
            Some(if plant_case_11 { "gzip" } else { "identity" }),
            &ping_body(11),
        );
        captures_tx.send(b_ping).expect("record /mcp-b ping");

        // 5. /mcp-b second JSON terminal, used for the lane-selection refusal.
        let mut b_lane_stream = accept_bounded(&listener);
        let b_lane = read_request(&mut b_lane_stream);
        write_bounded_response(
            &mut b_lane_stream,
            200,
            "application/json",
            Some("identity"),
            &ping_body(12),
        );
        captures_tx.send(b_lane).expect("record /mcp-b lane probe");

        // 6. Release the held /mcp-a terminal only now, proving the sibling
        //    stream and its waiter survived everything that happened on
        //    /mcp-b, including the planted refusal.
        write_sse_event(&mut a_call_stream, &terminal_tool_event(2));
        end_sse_response(&mut a_call_stream);
        drop(a_call_stream);
    });

    let runtime = RuntimeBuilder::current_thread()
        .build()
        .expect("the integration test owns its caller runtime");

    let outcome = runtime.block_on(async {
        let cx = Cx::current().expect("the caller runtime must install a current Cx");
        let limits = SseLimits::new(4_096, 65_536, 8).expect("bounded SSE limits are nonzero");

        let a_connection = integration_builder(&a_target)
            .connect_http_with_cx(&cx)
            .await
            .expect("the /mcp-a endpoint instance must connect through the public builder");
        let a_era = a_connection.selected_protocol_era();
        let a_discovery_result = a_connection
            .server_discovery()
            .expect("a modern connection retains its discovery frame");
        let a_versions: Vec<String> = a_discovery_result.supported_versions().to_vec();
        let a_discovery = format!("{a_discovery_result:?}");
        let a_endpoint_key = endpoint_key(&a_connection);

        let mut a_listener = a_connection
            .open_final_core_listener(
                &cx,
                "tools/call",
                serde_json::json!({
                    "name": "http_03_join_tool",
                    "arguments": {},
                    "_meta": {"progressToken": marker.clone()},
                }),
                RequestId::Number(2),
                limits,
            )
            .await
            .expect("the shipped SSE lane must open a request-owned listener");

        let mut a_progress = Vec::new();
        for _ in 0_u8..2 {
            let event = a_listener
                .next_event(&cx)
                .await
                .expect("request-scoped progress must remain admissible")
                .expect("a progress event must precede the terminal");
            match event {
                ModernHttpFinalCoreEvent::Progress(progress) => {
                    assert_eq!(
                        progress.progress_token, marker,
                        "progress must be delivered only to the request that owns the marker"
                    );
                    a_progress.push(progress.progress.as_str().to_owned());
                }
                other => panic!("expected a progress record, observed {other:?}"),
            }
        }

        // The /mcp-a waiter is now live and pending. Everything below happens
        // on a different endpoint instance while that stream stays open.
        let mut b_connection = integration_builder(&b_target)
            .connect_http_with_cx(&cx)
            .await
            .expect("the /mcp-b endpoint instance must connect through the public builder");
        let b_era = b_connection.selected_protocol_era();
        let b_discovery_result = b_connection
            .server_discovery()
            .expect("a modern connection retains its discovery frame");
        let b_versions: Vec<String> = b_discovery_result.supported_versions().to_vec();
        let b_discovery = format!("{b_discovery_result:?}");
        let b_endpoint_key = endpoint_key(&b_connection);

        let b_json_outcome = match b_connection
            .request_json(
                &cx,
                "ping",
                serde_json::json!({}),
                RequestId::Number(11),
                65_536,
            )
            .await
        {
            Ok(response) => format!(
                "terminal=json id={:?} result={}",
                response.id,
                response
                    .result
                    .as_ref()
                    .map_or_else(|| "<none>".to_owned(), serde_json::Value::to_string)
            ),
            Err(error) => format!("refusal={}", render_connection_error(&error)),
        };

        // A second JSON terminal, converted through the SSE lane entrypoint.
        // Only the requested lane differs from the accepted JSON consumption.
        let b_lane_refusal = match b_connection
            .request(&cx, "ping", serde_json::json!({}), RequestId::Number(12))
            .await
            .expect("the second /mcp-b JSON exchange must reach a response head")
        {
            ClientHttpResponse::Modern(stream) => {
                assert_eq!(
                    stream.metadata().kind(),
                    ModernHttpResponseKind::Json,
                    "the fixture answered this POST on the JSON lane"
                );
                match stream.into_sse_stream(limits) {
                    Ok(_) => panic!("a JSON response must not be admitted as an SSE stream"),
                    Err(error) => format!("{error:?}"),
                }
            }
            #[cfg(feature = "legacy-2024-11-05")]
            ClientHttpResponse::Legacy(_) => {
                panic!("a modern-only plan must never yield a legacy response")
            }
        };

        // Back to the still-open sibling stream.
        let a_terminal = match a_listener
            .next_event(&cx)
            .await
            .expect("the sibling stream must still deliver its terminal")
            .expect("the terminal record must arrive")
        {
            ModernHttpFinalCoreEvent::Terminal(FinalCoreResult::ToolsCall { .. }) => {
                "terminal=tools_call".to_owned()
            }
            other => panic!("expected the correlated tools/call terminal, observed {other:?}"),
        };

        // Reading past the terminal is the stream-close observation.
        //
        // THE CONTRACT, so nobody re-inverts it: `Ok(None)` is the correct and
        // deliberate "this stream is finished" signal. Delivering the terminal
        // sets `terminal_received = true` and calls `stream.close()`, and
        // `ModernHttpFinalCoreListener::next_event` then short-circuits on that
        // flag before touching the body at all (`http_executor.rs:1488-1490`).
        //
        // `Err(EndOfStream)` is NOT the healthy post-terminal outcome — it is
        // what a body that ended *without* a terminal produces, i.e. truncation.
        // An earlier revision of this fixture asserted exactly that, demanding
        // the failure condition and rejecting the success one, which is why the
        // first execution of this join reported a closed stream "yielding None".
        //
        // Both outcomes are still observed here, on opposite sides: `Ok(None)`
        // passes, and truncation now fails as the distinct defect it is.
        let post_terminal = a_listener.next_event(&cx).await;
        let a_post_terminal = match post_terminal {
            Ok(None) => "closed=terminal_then_none".to_owned(),
            Ok(Some(event)) => {
                panic!("a stream closed by its terminal must not yield another record: {event:?}")
            }
            Err(ModernHttpFinalCoreListenError::EndOfStream { framing }) => panic!(
                "the response body ended without delivering a terminal (framing {framing:?}); \
                 that is truncation, not the post-terminal close this case observes"
            ),
            Err(other) => panic!(
                "the post-terminal observation is INCONCLUSIVE ({other:?}); it proves neither a \
                 clean close nor a leaked record"
            ),
        };

        // The close is stable, not a one-shot transition: a second read past the
        // terminal must give the same clean signal rather than an error or a
        // revived record.
        match a_listener.next_event(&cx).await {
            Ok(None) => {}
            Ok(Some(event)) => {
                panic!("a closed stream must stay closed, but a later read yielded {event:?}")
            }
            Err(error) => panic!(
                "a closed stream must keep reporting its clean terminal signal, observed {error:?}"
            ),
        }

        ClientOutcome {
            a_era,
            a_discovery,
            a_versions,
            a_endpoint_key,
            a_progress,
            a_terminal,
            a_post_terminal,
            b_era,
            b_discovery,
            b_versions,
            b_endpoint_key,
            b_json_outcome,
            b_lane_refusal,
        }
    });

    server.join().expect("the fixture server thread must join");

    let a_probe = captures_rx.recv().expect("the /mcp-a probe was captured");
    let a_call = captures_rx
        .recv()
        .expect("the /mcp-a tools/call was captured");
    let b_probe = captures_rx.recv().expect("the /mcp-b probe was captured");
    let b_ping = captures_rx.recv().expect("the /mcp-b ping was captured");
    let b_lane_probe = captures_rx
        .recv()
        .expect("the /mcp-b lane probe was captured");
    assert!(
        captures_rx.try_recv().is_err(),
        "the fixture must observe exactly the five expected requests"
    );

    let ClientOutcome {
        a_era,
        a_discovery,
        a_versions,
        a_endpoint_key,
        a_progress,
        a_terminal,
        a_post_terminal,
        b_era,
        b_discovery,
        b_versions,
        b_endpoint_key,
        b_json_outcome,
        b_lane_refusal,
    } = outcome;

    let captured = [&a_probe, &a_call, &b_probe, &b_ping, &b_lane_probe];
    let mut method_count: BTreeMap<String, usize> = BTreeMap::new();
    let mut legacy_get_count = 0_usize;
    for request in captured {
        if request.request_line().starts_with("GET ") {
            legacy_get_count += 1;
        }
        if let Some(method) = request.header("Mcp-Method") {
            *method_count.entry(method).or_default() += 1;
        }
    }

    // Two dedicated real-socket lanes. They are separate fixtures on purpose:
    // each needs the server to misbehave in a specific way after reading the
    // POST, which the shared A/B fixture above must not do.
    let uncertain_dispatch = observe_lane(false, Duration::from_secs(5));
    let deadline_race = observe_lane(true, DEADLINE_LANE_IDLE_TIMEOUT);
    let caller_cancellation = observe_caller_cancellation();
    let independent_server_request = observe_independent_server_request();
    let extension_notification = observe_extension_notification();

    WireObservations {
        fixture_authority: authority,
        a_probe,
        a_call,
        b_probe,
        b_ping,
        b_lane_probe,
        a_progress,
        a_terminal,
        a_post_terminal,
        a_discovery,
        a_versions,
        a_endpoint_key,
        a_target,
        a_era,
        b_discovery,
        b_versions,
        b_endpoint_key,
        b_target,
        b_era,
        b_json_outcome,
        b_lane_refusal,
        method_count,
        legacy_get_count,
        uncertain_dispatch,
        deadline_race,
        caller_cancellation,
        independent_server_request,
        extension_notification,
    }
}

fn render_connection_error(error: &ClientHttpConnectionError) -> String {
    match error {
        ClientHttpConnectionError::Modern(ModernHttpClientError::Executor(executor)) => {
            format!("executor::{executor:?}")
        }
        ClientHttpConnectionError::Modern(modern) => format!("modern::{modern:?}"),
        other => format!("connection::{other:?}"),
    }
}

// ---------------------------------------------------------------------------
// Joined evaluator
// ---------------------------------------------------------------------------

/// One evaluated manifest case: its ordered record plus the observation counts
/// that the producer's declared floor is checked against.
#[derive(Debug, Clone, PartialEq, Eq)]
struct CaseRecord {
    id: String,
    name: String,
    floor: usize,
    positive_observations: usize,
    negative_observations: usize,
    record: String,
}

/// Accumulates one case's observations in evaluation order.
struct CaseBuilder {
    positive_observations: usize,
    negative_observations: usize,
    record: String,
}

impl CaseBuilder {
    fn new() -> Self {
        Self {
            positive_observations: 0,
            negative_observations: 0,
            record: String::new(),
        }
    }

    /// Records one positive observation of the shipped joined behaviour.
    fn positive(&mut self, field: &str, observed: &str) {
        self.positive_observations += 1;
        writeln!(self.record, "+ {field} = {observed}").expect("record writes are infallible");
    }

    /// Records one one-variable planted-negative observation.
    fn negative(&mut self, variable: &str, observed: &str) {
        self.negative_observations += 1;
        writeln!(self.record, "- {variable} -> {observed}").expect("record writes are infallible");
    }
}

/// The receipt produced by one complete joined evaluation.
#[derive(Debug, Clone)]
struct JoinReceipt {
    joined_entrypoint: String,
    clock_regime: String,
    producer_a_revision: String,
    producer_a_tree: String,
    producer_a_entrypoint: String,
    producer_b_revision: String,
    producer_b_tree: String,
    producer_b_entrypoint: String,
    a_digest: String,
    b_digest: String,
    endpoint_identity: String,
    canonical_targets: (String, String),
    fixture_identity: String,
    discovery_frames: (String, String),
    no_downgrade_matrix: Vec<String>,
    cases: Vec<CaseRecord>,
}

impl JoinReceipt {
    /// One line naming how much was actually executed.
    ///
    /// `2 passed` does not tell a reader that 26 ordered cases ran inside those
    /// two tests, and nothing else in the run output names a case. The count is
    /// already ENFORCED - an unregistered id panics, `cases.len()` is pinned to
    /// the ordered union, and every case must meet the producer's declared floor
    /// by execution - so a short-circuiting case fails rather than passing
    /// quietly. This makes the same fact legible instead of only guaranteed.
    ///
    /// `cargo test` captures stdout for passing tests, so this surfaces under
    /// `--nocapture`. It is deliberately not wired into the frozen AC-7 runner,
    /// which takes no flags.
    fn execution_summary(&self) -> String {
        let floors: usize = self.cases.iter().map(|case| case.floor).sum();
        let positive = self.total_positive();
        let negative = self.total_negative();
        format!(
            "HTTP-03 join executed {} ordered cases: {positive} positive + {negative} \
             negative = {} observations against {floors} declared floor-observations \
             (entrypoint {}; clocks: {})",
            self.cases.len(),
            positive + negative,
            self.joined_entrypoint,
            self.clock_regime,
        )
    }

    fn case(&self, id: &str) -> &CaseRecord {
        self.cases
            .iter()
            .find(|case| case.id == id)
            .unwrap_or_else(|| panic!("the receipt must carry {id}"))
    }

    fn total_positive(&self) -> usize {
        self.cases
            .iter()
            .map(|case| case.positive_observations)
            .sum()
    }

    fn total_negative(&self) -> usize {
        self.cases
            .iter()
            .map(|case| case.negative_observations)
            .sum()
    }
}

/// What each registered predicate actually exercises, keyed by case ID.
///
/// # Why this exists
///
/// The floor gate cannot catch a semantic mismatch. A producer that derives its
/// `floor=N` values from *this* evaluator's observation counts - which is exactly
/// what was asked for and supplied - will produce floors that match perfectly
/// even if it has assigned completely different behaviour to those case IDs. The
/// gate would then confirm the numbers while the receipt mislabels what was
/// proved, which is laundered evidence of precisely the kind this join exists to
/// prevent.
///
/// So each predicate declares the subject it observes, and the join refuses to
/// run a predicate under a case name that means something else.
const PREDICATE_SUBJECTS: &[(&str, &str)] = &[
    ("HTTP-03.01", "post-route"),
    ("HTTP-03.02", "request-content-type"),
    ("HTTP-03.03", "request-accept-two-ranges"),
    ("HTTP-03.04", "request-accept-encoding-identity"),
    ("HTTP-03.05", "protocol-version-header"),
    ("HTTP-03.06", "method-mirror-header"),
    ("HTTP-03.07", "name-header"),
    ("HTTP-03.08", "request-body-stamping"),
    ("HTTP-03.09", "immediate-json-lane"),
    ("HTTP-03.10", "request-scoped-sse-lane"),
    ("HTTP-03.11", "response-content-encoding"),
    ("HTTP-03.12", "bounded-sse-parse"),
    ("HTTP-03.13", "terminal-outcome-and-stream-close"),
    ("HTTP-03.14", "caller-cancellation-response-close"),
    ("HTTP-03.15", "deadline-and-disconnect-races"),
    ("HTTP-03.16", "uncertain-dispatch-no-retry"),
    ("HTTP-03.17", "authorization-redaction"),
    ("HTTP-03.18", "https-only-bearer-attachment"),
    ("HTTP-03.19", "redirect-no-follow-no-replay"),
    ("HTTP-03.20", "discover-preclassification-frame"),
    ("HTTP-03.21", "fresh-probe-identity-after-authorization"),
    ("HTTP-03.22", "endpoint-instance-key-partition"),
    ("HTTP-03.23", "extension-activation-proof-notification"),
    ("HTTP-03.24", "independent-server-request-rejection"),
    ("HTTP-03.25", "no-event-id-retry-resumption-state"),
    ("HTTP-03.26", "modern-observation-table-and-no-downgrade"),
];

/// Refuses to evaluate a case whose producer-declared name does not match the
/// subject this evaluator's predicate for that ID actually observes.
fn assert_predicate_matches_declared_case(case: &ManifestCase) {
    let expected = PREDICATE_SUBJECTS
        .iter()
        .find(|(id, _)| *id == case.id)
        .map(|(_, subject)| *subject)
        .unwrap_or_else(|| panic!("no registered predicate subject for {}", case.id));
    assert_eq!(
        case.name, expected,
        "SEMANTIC MISMATCH on {}: the producer manifest declares this case as `{}`, but this \
         join's predicate for that ID observes `{}`. The floor gate cannot catch this - the \
         producer took its floor from this evaluator's own observation counts, so the numbers \
         agree while the meanings do not. Running anyway would record a receipt claiming `{}` \
         was proved when it was never exercised. Either the producer renumbers, or this join \
         grows a predicate for `{}`; nothing may be recorded until one of those happens.",
        case.id, case.name, expected, case.name, case.name
    );
}

/// Evaluates the full ordered join. `plant_case_11` changes exactly one
/// variable across the whole evaluation.
fn evaluate_join(plant_case_11: bool) -> JoinReceipt {
    let manifest = JoinedManifest::consume();
    let wire = run_fixture(plant_case_11);
    let matrix = no_downgrade_matrix();

    let mut cases = Vec::with_capacity(manifest.cases.len());
    for declared in &manifest.cases {
        assert_predicate_matches_declared_case(declared);
        let mut builder = CaseBuilder::new();
        match declared.id.as_str() {
            "HTTP-03.01" => case_post_route(&mut builder, &wire),
            "HTTP-03.02" => case_request_content_type(&mut builder, &wire),
            "HTTP-03.03" => case_request_accept(&mut builder, &wire),
            "HTTP-03.04" => case_request_accept_encoding(&mut builder, &wire),
            "HTTP-03.05" => case_protocol_version_header(&mut builder, &wire),
            "HTTP-03.06" => case_method_mirror_header(&mut builder, &wire),
            "HTTP-03.07" => case_name_header(&mut builder, &wire),
            "HTTP-03.08" => case_body_stamping(&mut builder, &wire),
            "HTTP-03.09" => case_json_lane(&mut builder, &wire),
            "HTTP-03.10" => case_sse_lane(&mut builder, &wire),
            "HTTP-03.11" => case_content_encoding(&mut builder, &wire, plant_case_11),
            "HTTP-03.12" => case_bounded_sse_parse(&mut builder, &wire),
            "HTTP-03.13" => case_terminal_and_close(&mut builder, &wire),
            // --- B half. Each arm is keyed to the subject B DECLARES for that
            // --- ordinal, not to the subject this join used to assume.
            "HTTP-03.14" => case_caller_cancellation_close(&mut builder, &wire),
            "HTTP-03.15" => case_deadline_and_disconnect_races(&mut builder, &wire),
            "HTTP-03.16" => case_uncertain_dispatch_no_retry(&mut builder, &wire),
            "HTTP-03.17" => case_authorization_redaction(&mut builder, &wire),
            "HTTP-03.18" => case_https_only_bearer_attachment(&mut builder),
            "HTTP-03.19" => case_redirect_no_follow_no_replay(&mut builder),
            "HTTP-03.20" => case_discover_preclassification_frame(&mut builder, &wire),
            "HTTP-03.21" => case_fresh_probe_identity_after_authorization(&mut builder, &wire),
            "HTTP-03.22" => case_endpoint_instance_key_partition(&mut builder, &wire),
            "HTTP-03.23" => case_extension_activation_notification(&mut builder, &wire),
            "HTTP-03.24" => case_independent_server_request_rejection(&mut builder, &wire),
            "HTTP-03.25" => case_no_event_id_retry_resumption(&mut builder, &wire),
            "HTTP-03.26" => case_no_downgrade_matrix(&mut builder, &matrix),
            other => panic!("the joined evaluator has no registered predicate for {other}"),
        }

        let observations = builder.positive_observations + builder.negative_observations;
        assert!(
            observations >= declared.floor,
            "{} ({}) declares floor={} but the evaluator performed only {observations} \
             observations; the producer floor is enforced by execution, never re-declared here",
            declared.id,
            declared.name,
            declared.floor
        );
        assert!(
            builder.positive_observations >= 1,
            "{} must perform at least one positive observation",
            declared.id
        );
        assert!(
            builder.negative_observations >= 1,
            "{} must perform at least one one-variable planted-negative observation",
            declared.id
        );

        cases.push(CaseRecord {
            id: declared.id.clone(),
            name: declared.name.clone(),
            floor: declared.floor,
            positive_observations: builder.positive_observations,
            negative_observations: builder.negative_observations,
            record: builder.record,
        });
    }

    JoinReceipt {
        joined_entrypoint: JOINED_PUBLIC_ENTRYPOINT.to_owned(),
        clock_regime: format!(
            "join idle={}ms absolute={}ms reset_idle_on_matching_progress=true; \
             deadline-lane idle={}ms",
            JOIN_IDLE_TIMEOUT.as_millis(),
            JOIN_ABSOLUTE_TIMEOUT.as_millis(),
            DEADLINE_LANE_IDLE_TIMEOUT.as_millis(),
        ),
        producer_a_revision: manifest.a.producer_revision.clone(),
        producer_a_tree: manifest.a.producer_tree.clone(),
        producer_a_entrypoint: manifest.a.entrypoint.clone(),
        producer_b_revision: manifest.b.producer_revision.clone(),
        producer_b_tree: manifest.b.producer_tree.clone(),
        producer_b_entrypoint: manifest.b.entrypoint.clone(),
        a_digest: render_digest(&manifest.a_digest),
        b_digest: render_digest(&manifest.b_digest),
        endpoint_identity: format!("a={:?} b={:?}", wire.a_endpoint_key, wire.b_endpoint_key),
        canonical_targets: (
            wire.normalize(&wire.a_target),
            wire.normalize(&wire.b_target),
        ),
        fixture_identity: format!(
            "loopback-tcp authority={} routes=/mcp-a,/mcp-b requests={}",
            wire.fixture_authority,
            wire.method_count.values().sum::<usize>()
        ),
        discovery_frames: (
            wire.normalize(&wire.a_discovery),
            wire.normalize(&wire.b_discovery),
        ),
        no_downgrade_matrix: matrix.iter().map(|row| row.render.clone()).collect(),
        cases,
    }
}

// ---------------------------------------------------------------------------
// Per-case predicates — A group (executor: request, response, stream)
// ---------------------------------------------------------------------------

fn case_post_route(builder: &mut CaseBuilder, wire: &WireObservations) {
    for (label, request) in [
        ("mcp-a-probe", &wire.a_probe),
        ("mcp-a-call", &wire.a_call),
        ("mcp-b-probe", &wire.b_probe),
        ("mcp-b-ping", &wire.b_ping),
    ] {
        builder.positive(label, request.request_line());
    }
    assert!(
        wire.a_call
            .request_line()
            .starts_with("POST /mcp-a HTTP/1.1")
    );
    assert!(
        wire.b_ping
            .request_line()
            .starts_with("POST /mcp-b HTTP/1.1")
    );

    // One variable: the configured target is emptied; nothing else changes.
    let refusal = ModernHttpRequest::new(
        "",
        wire.a_call.body.clone(),
        "2026-07-28",
        "tools/call",
        Some("http_03_join_tool".to_owned()),
    )
    .expect_err("an empty target must not build a modern POST");
    assert!(matches!(
        refusal,
        ModernHttpExecutorError::InvalidRequestMetadata
    ));
    builder.negative("target=\"\"", &format!("{refusal:?}"));
}

fn case_request_content_type(builder: &mut CaseBuilder, wire: &WireObservations) {
    for (label, request) in [("mcp-a-call", &wire.a_call), ("mcp-b-ping", &wire.b_ping)] {
        let observed = request
            .header("Content-Type")
            .expect("every modern JSON-RPC POST carries a content type");
        assert_eq!(observed, MODERN_MCP_CONTENT_TYPE);
        assert_eq!(observed, "application/json");
        builder.positive(label, &observed);
        assert!(
            request.header("Content-Encoding").is_none(),
            "an uncoded request body must not advertise a content coding"
        );
        builder.positive(&format!("{label}-request-content-encoding"), "<absent>");
    }

    // One variable: the response media type gains a non-UTF-8 charset.
    let refusal = validate_response_head(
        200,
        &[(
            "Content-Type".to_owned(),
            "application/json; charset=us-ascii".to_owned(),
        )],
    )
    .expect_err("only an optional charset=utf-8 parameter is admitted");
    assert!(matches!(
        refusal,
        ModernHttpExecutorError::UnsupportedSuccessContentType
    ));
    builder.negative("charset=us-ascii", &format!("{refusal:?}"));
}

fn case_request_accept(builder: &mut CaseBuilder, wire: &WireObservations) {
    for (label, request) in [("mcp-a-call", &wire.a_call), ("mcp-b-ping", &wire.b_ping)] {
        let observed = request
            .header("Accept")
            .expect("every modern POST advertises both response media types");
        assert_eq!(observed, MODERN_MCP_ACCEPT);
        assert_eq!(observed, "application/json, text/event-stream");
        builder.positive(label, &observed);
    }

    // One variable: a weakened media range. The shipped builder exposes no
    // input that can produce one, so the negative is proven both at the public
    // builder and on the captured wire.
    let built = ModernHttpRequest::new(
        wire.b_target.as_str(),
        b"{}".to_vec(),
        "2026-07-28",
        "ping",
        None,
    )
    .expect("a canonical modern POST builds")
    .headers()
    .into_iter()
    .find(|(field, _)| field == "Accept")
    .map(|(_, value)| value)
    .expect("the builder always emits Accept");
    assert_eq!(built, MODERN_MCP_ACCEPT);
    for weakened in ["*/*", "application/json, text/event-stream;q=0", "q=0"] {
        assert!(
            !wire.a_call.head.contains(weakened) && !wire.b_ping.head.contains(weakened),
            "a weakened accept range {weakened:?} must never reach the wire"
        );
    }
    builder.negative(
        "accept-weakening-input",
        &format!("builder Accept stays {built}"),
    );
}

fn case_request_accept_encoding(builder: &mut CaseBuilder, wire: &WireObservations) {
    for (label, request) in [("mcp-a-call", &wire.a_call), ("mcp-b-ping", &wire.b_ping)] {
        let observed = request
            .header("Accept-Encoding")
            .expect("every modern POST requests the canonical identity coding");
        assert_eq!(observed, MODERN_MCP_ACCEPT_ENCODING);
        assert_eq!(observed, "identity");
        builder.positive(label, &observed);
    }

    // One variable: a compressed coding offered on the request.
    let built = ModernHttpRequest::new(
        wire.b_target.as_str(),
        b"{}".to_vec(),
        "2026-07-28",
        "ping",
        None,
    )
    .expect("a canonical modern POST builds")
    .headers()
    .into_iter()
    .find(|(field, _)| field == "Accept-Encoding")
    .map(|(_, value)| value)
    .expect("the builder always emits Accept-Encoding");
    assert_eq!(built, "identity");
    assert!(
        !wire.a_call.head.contains("gzip") && !wire.b_ping.head.contains("gzip"),
        "a compressed coding must never be offered on a modern MCP POST"
    );
    builder.negative(
        "accept-encoding-gzip-input",
        &format!("builder Accept-Encoding stays {built}"),
    );
}

fn case_protocol_version_header(builder: &mut CaseBuilder, wire: &WireObservations) {
    for (label, request) in [
        ("mcp-a-probe", &wire.a_probe),
        ("mcp-a-call", &wire.a_call),
        ("mcp-b-ping", &wire.b_ping),
    ] {
        let observed = request
            .header("MCP-Protocol-Version")
            .expect("every JSON-RPC request carries the negotiated version");
        assert_eq!(observed, "2026-07-28");
        builder.positive(label, &observed);
    }

    // One variable: the protocol version supplied to the public builder.
    let refusal = ModernHttpRequest::new(wire.b_target.as_str(), b"{}".to_vec(), "", "ping", None)
        .expect_err("an empty protocol version must not build a modern POST");
    assert!(matches!(
        refusal,
        ModernHttpExecutorError::InvalidRequestMetadata
    ));
    builder.negative("protocol_version=\"\"", &format!("{refusal:?}"));
}

fn case_method_mirror_header(builder: &mut CaseBuilder, wire: &WireObservations) {
    for (label, request, expected) in [
        ("mcp-a-probe", &wire.a_probe, "server/discover"),
        ("mcp-a-call", &wire.a_call, "tools/call"),
        ("mcp-b-probe", &wire.b_probe, "server/discover"),
        ("mcp-b-ping", &wire.b_ping, "ping"),
    ] {
        let observed = request
            .header("Mcp-Method")
            .expect("every JSON-RPC request mirrors its method");
        assert_eq!(observed, expected);
        assert_eq!(request.json_body()["method"], expected);
        builder.positive(label, &observed);
    }

    // One variable: the mirrored method name.
    let refusal = ModernHttpRequest::new(
        wire.b_target.as_str(),
        b"{}".to_vec(),
        "2026-07-28",
        "",
        None,
    )
    .expect_err("an empty method must not build a modern POST");
    assert!(matches!(
        refusal,
        ModernHttpExecutorError::InvalidRequestMetadata
    ));
    builder.negative("method=\"\"", &format!("{refusal:?}"));
}

fn case_name_header(builder: &mut CaseBuilder, wire: &WireObservations) {
    let call_name = wire
        .a_call
        .header("Mcp-Name")
        .expect("tools/call mirrors its tool name");
    assert_eq!(call_name, "http_03_join_tool");
    assert_eq!(
        wire.a_call.json_body()["params"]["name"],
        "http_03_join_tool"
    );
    builder.positive("mcp-a-call", &call_name);

    // `ping` is not a name-bearing method, so the header must be absent.
    assert!(wire.b_ping.header("Mcp-Name").is_none());
    builder.positive("mcp-b-ping", "<absent>");

    // One variable: the name-bearing parameter is removed from tools/call.
    let refusal = ModernHttpRequest::new(
        wire.a_target.as_str(),
        br#"{"jsonrpc":"2.0","id":9,"method":"tools/call","params":{}}"#.to_vec(),
        "2026-07-28",
        "tools/call",
        Some("name\r\nInjected: header".to_owned()),
    )
    .expect_err("a header-splitting name mirror must not build a modern POST");
    assert!(matches!(
        refusal,
        ModernHttpExecutorError::InvalidRequestMetadata
    ));
    builder.negative(
        "name=\"name\\r\\nInjected: header\"",
        &format!("{refusal:?}"),
    );
}

fn case_body_stamping(builder: &mut CaseBuilder, wire: &WireObservations) {
    for (label, request, method) in [
        ("mcp-a-probe", &wire.a_probe, "server/discover"),
        ("mcp-a-call", &wire.a_call, "tools/call"),
        ("mcp-b-ping", &wire.b_ping, "ping"),
    ] {
        let body = request.json_body();
        assert_eq!(body["jsonrpc"], "2.0");
        assert_eq!(body["method"], method);
        assert_eq!(
            body["params"]["_meta"]["io.modelcontextprotocol/protocolVersion"],
            "2026-07-28"
        );
        assert_eq!(
            body["params"]["_meta"]["io.modelcontextprotocol/clientInfo"]["name"],
            "http-03-integration-client"
        );
        builder.positive(label, &body["method"].to_string());
    }

    // One variable: the POST becomes a reverse-response envelope rather than a
    // client request. Request-only stamping must disappear with it, so a
    // reverse response can never be mistaken for a stamped client request.
    let reverse = ModernHttpRequest::for_jsonrpc_response(
        wire.b_target.as_str(),
        "2026-07-28",
        br#"{"jsonrpc":"2.0","id":7,"result":{}}"#.to_vec(),
    )
    .expect("a reverse-response POST builds");
    let reverse_headers = reverse.headers();
    assert!(
        reverse_headers
            .iter()
            .all(|(field, _)| field != "Mcp-Method"),
        "a reverse-response POST must not mirror a client request method"
    );
    assert!(
        reverse_headers.iter().all(|(field, _)| field != "Mcp-Name"),
        "a reverse-response POST must not mirror a client request name"
    );
    builder.negative(
        "envelope=jsonrpc-response",
        "Mcp-Method and Mcp-Name absent",
    );
}

fn case_json_lane(builder: &mut CaseBuilder, wire: &WireObservations) {
    let head = validate_response_head(
        200,
        &[
            ("Content-Type".to_owned(), "application/json".to_owned()),
            ("Content-Encoding".to_owned(), "identity".to_owned()),
        ],
    )
    .expect("an identity-coded JSON head selects the JSON lane");
    assert_eq!(head.kind(), ModernHttpResponseKind::Json);
    builder.positive("json-head-kind", &format!("{:?}", head.kind()));

    // The live JSON lane is observed here only through the fixture's second
    // `/mcp-b` exchange, whose head is never the planted variable. The planted
    // terminal itself belongs to HTTP-03.11 alone.
    assert!(
        wire.b_lane_probe.request_line().starts_with("POST /mcp-b"),
        "the JSON lane observation must come from the /mcp-b endpoint instance"
    );
    builder.positive("json-lane-route", wire.b_lane_probe.request_line());

    let charset = validate_response_head(
        200,
        &[(
            "Content-Type".to_owned(),
            "APPLICATION/JSON; CHARSET=UTF-8".to_owned(),
        )],
    )
    .expect("the JSON essence and charset parameter are case-insensitive");
    assert_eq!(charset.kind(), ModernHttpResponseKind::Json);
    builder.positive(
        "json-head-case-insensitive",
        &format!("{:?}", charset.kind()),
    );

    // One variable: the media type.
    let refusal =
        validate_response_head(200, &[("Content-Type".to_owned(), "text/html".to_owned())])
            .expect_err("an unrelated media type must not select a body lane");
    assert!(matches!(
        refusal,
        ModernHttpExecutorError::UnsupportedSuccessContentType
    ));
    builder.negative("content-type=text/html", &format!("{refusal:?}"));
}

fn case_sse_lane(builder: &mut CaseBuilder, wire: &WireObservations) {
    let head = validate_response_head(
        200,
        &[(
            "Content-Type".to_owned(),
            "text/event-stream; charset=utf-8".to_owned(),
        )],
    )
    .expect("a charset-utf-8 event stream selects the SSE lane");
    assert_eq!(head.kind(), ModernHttpResponseKind::Sse);
    builder.positive("sse-head-kind", &format!("{:?}", head.kind()));
    builder.positive("mcp-a-progress-count", &wire.a_progress.len().to_string());

    // One variable: the live response lane the caller asks the stream for.
    assert!(
        wire.b_lane_refusal.contains("ExpectedSseResponse"),
        "a JSON response must refuse SSE conversion, observed {}",
        wire.b_lane_refusal
    );
    builder.negative("json-response-as-sse", &wire.b_lane_refusal);
}

fn case_content_encoding(builder: &mut CaseBuilder, wire: &WireObservations, planted: bool) {
    let accepted = validate_response_head(
        200,
        &[
            ("Content-Type".to_owned(), "application/json".to_owned()),
            ("Content-Encoding".to_owned(), "IDENTITY".to_owned()),
        ],
    )
    .expect("a case-insensitive singleton identity coding is admitted");
    assert_eq!(accepted.kind(), ModernHttpResponseKind::Json);
    builder.positive("singleton-identity-ci", &format!("{:?}", accepted.kind()));

    // This is the one variable the planted-negative test changes: the live
    // `/mcp-b` terminal response coding.
    builder.positive("mcp-b-live-terminal", &wire.b_json_outcome);
    if planted {
        assert!(
            wire.b_json_outcome.contains("UnsupportedContentEncoding"),
            "the planted gzip coding must reach the typed refusal boundary, observed {}",
            wire.b_json_outcome
        );
    } else {
        assert!(
            wire.b_json_outcome.starts_with("terminal=json"),
            "the accepted identity coding must yield a JSON terminal, observed {}",
            wire.b_json_outcome
        );
    }

    // One variable: the response content coding.
    let refusal = validate_response_head(
        200,
        &[
            ("Content-Type".to_owned(), "application/json".to_owned()),
            ("Content-Encoding".to_owned(), "gzip".to_owned()),
        ],
    )
    .expect_err("a compressed response coding must be refused before body decoding");
    assert!(matches!(
        refusal,
        ModernHttpExecutorError::UnsupportedContentEncoding
    ));
    builder.negative("content-encoding=gzip", &format!("{refusal:?}"));
}

fn case_bounded_sse_parse(builder: &mut CaseBuilder, wire: &WireObservations) {
    assert_eq!(wire.a_progress, vec!["1".to_owned(), "2".to_owned()]);
    builder.positive("assembled-progress", &wire.a_progress.join(","));
    builder.positive("assembled-terminal", &wire.a_terminal);

    // One variable: the event ceiling supplied to the public parser bound.
    assert!(
        SseLimits::new(4_096, 65_536, 8).is_some(),
        "the accepted bounds are constructible"
    );
    assert!(
        SseLimits::new(4_096, 0, 8).is_none(),
        "a zero event ceiling must fail closed at configuration time"
    );
    builder.negative("max_event_bytes=0", "SseLimits::new -> None");
}

fn case_terminal_and_close(builder: &mut CaseBuilder, wire: &WireObservations) {
    builder.positive("terminal", &wire.a_terminal);
    assert_eq!(wire.a_terminal, "terminal=tools_call");

    // One variable: the read position moves past the terminal record. The
    // stream answers with its clean finished signal rather than another record.
    assert_eq!(wire.a_post_terminal, "closed=terminal_then_none");
    builder.negative("read-past-terminal", &wire.a_post_terminal);
}

// ---------------------------------------------------------------------------
// Per-case predicates — B group (isolation, auth, redirects, partitioning)
// ---------------------------------------------------------------------------

fn case_one_shot_probe(builder: &mut CaseBuilder, wire: &WireObservations) {
    assert_eq!(
        wire.method_count
            .get("server/discover")
            .copied()
            .unwrap_or_default(),
        2,
        "exactly one discovery probe per endpoint instance, never a replay"
    );
    builder.positive("discover-probe-count", "2");
    builder.positive(
        "mcp-a-probe-body",
        &wire.a_probe.json_body()["method"].to_string(),
    );
    builder.positive(
        "mcp-b-probe-body",
        &wire.b_probe.json_body()["method"].to_string(),
    );
    assert_eq!(wire.legacy_get_count, 0);
    builder.positive("legacy-get-count", "0");

    // One variable: a second probe on the same attempt.
    let mut negotiation = integration_builder(&wire.a_target)
        .http_negotiation()
        .expect("the configured plan starts one classification attempt");
    negotiation
        .observe_modern_probe(HttpModernProbe {
            status: 200,
            body: HttpProbeBody::RecognizedModernJsonRpc,
        })
        .expect("the one permitted probe is admitted");
    let refusal = negotiation
        .observe_modern_probe(HttpModernProbe {
            status: 200,
            body: HttpProbeBody::RecognizedModernJsonRpc,
        })
        .expect_err("a probe replay must be refused");
    assert!(matches!(
        refusal,
        ClientHttpNegotiationError::ModernProbeAlreadyDispatched
    ));
    builder.negative("second-probe-on-same-attempt", &format!("{refusal:?}"));
}

fn case_modern_era_selection(builder: &mut CaseBuilder, wire: &WireObservations) {
    assert_eq!(wire.a_era, ProtocolEra::Modern2026);
    assert_eq!(wire.b_era, ProtocolEra::Modern2026);
    builder.positive("mcp-a-era", &format!("{:?}", wire.a_era));
    builder.positive("mcp-b-era", &format!("{:?}", wire.b_era));

    let mut negotiation = integration_builder(&wire.a_target)
        .http_negotiation()
        .expect("the configured plan starts one classification attempt");
    let decision = negotiation
        .observe_modern_probe(HttpModernProbe {
            status: 200,
            body: HttpProbeBody::RecognizedModernJsonRpc,
        })
        .expect("a recognized modern JSON-RPC probe selects modern");
    assert_eq!(decision, ClientHttpNegotiationDecision::ModernSelected);
    assert_eq!(
        negotiation.state().selected_era(),
        Some(ProtocolEra::Modern2026)
    );
    builder.positive("classifier-decision", &format!("{decision:?}"));

    // One variable: the probe body class.
    let mut planted = integration_builder(&wire.a_target)
        .http_negotiation()
        .expect("the configured plan starts one classification attempt");
    let refusal = planted
        .observe_modern_probe(HttpModernProbe {
            status: 200,
            body: HttpProbeBody::Unrecognized,
        })
        .expect_err("an unrecognized body must not select an era");
    assert!(matches!(
        refusal,
        ClientHttpNegotiationError::ModernProbeRejectedWithoutLegacyFallback {
            status: 200,
            body: HttpProbeBody::Unrecognized,
        }
    ));
    assert_eq!(planted.state().selected_era(), None);
    assert!(!planted.state().legacy_sse_fallback_authorized());
    builder.negative("probe-body=Unrecognized", &format!("{refusal:?}"));
}

fn case_discovery_frames(builder: &mut CaseBuilder, wire: &WireObservations) {
    assert_eq!(wire.a_versions, vec!["2026-07-28".to_owned()]);
    assert_eq!(wire.b_versions, vec!["2026-07-28".to_owned()]);
    builder.positive("mcp-a-versions", &wire.a_versions.join(","));
    builder.positive("mcp-b-versions", &wire.b_versions.join(","));
    assert_ne!(
        wire.a_discovery, wire.b_discovery,
        "each endpoint instance retains its own discovery frame"
    );
    builder.positive("frames-distinct", "true");

    // One variable: the probe body class becomes a transport failure.
    let mut planted = integration_builder(&wire.a_target)
        .http_negotiation()
        .expect("the configured plan starts one classification attempt");
    let refusal = planted
        .observe_modern_probe(HttpModernProbe {
            status: 200,
            body: HttpProbeBody::TransportFailure,
        })
        .expect_err("a transport failure is never a downgrade signal");
    assert!(matches!(
        refusal,
        ClientHttpNegotiationError::ModernProbeTransportFailure
    ));
    assert_eq!(planted.state().selected_era(), None);
    builder.negative("probe-body=TransportFailure", &format!("{refusal:?}"));
}

fn case_bearer_bound_target(builder: &mut CaseBuilder) {
    let resource = CanonicalHttpUrl::parse("https://mcp.example.test/mcp")
        .expect("the admitted protected target is canonical HTTPS");
    let credential = BoundBearerCredential::bind(resource.clone(), BEARER_SECRET)
        .expect("an HTTPS target binds the caller-acquired credential");
    assert_eq!(credential.resource(), &resource);
    builder.positive("bound-resource", resource.as_str());

    let authorized = ModernHttpRequest::new(
        resource.as_str(),
        br#"{"jsonrpc":"2.0","id":1,"method":"ping"}"#.to_vec(),
        "2026-07-28",
        "ping",
        None,
    )
    .expect("a canonical modern POST builds")
    .with_authorization(&credential);
    let header = authorized
        .headers()
        .into_iter()
        .find(|(field, _)| field == "Authorization")
        .map(|(_, value)| value)
        .expect("the exact bound target carries the credential");
    assert_eq!(header, format!("Bearer {BEARER_SECRET}"));
    builder.positive("authorization-attached", "Bearer <redacted>");

    // One variable: the bound resource scheme.
    let cleartext = CanonicalHttpUrl::parse("http://mcp.example.test/mcp")
        .expect("the cleartext variant parses");
    let refusal = BoundBearerCredential::bind(cleartext, BEARER_SECRET)
        .expect_err("a cleartext resource must not bind a bearer credential");
    assert_eq!(refusal, BearerBindingError::CleartextResource);
    builder.negative("scheme=http", &format!("{refusal:?}"));
}

fn case_bearer_not_forwarded(builder: &mut CaseBuilder) {
    let resource = CanonicalHttpUrl::parse("https://mcp.example.test/mcp")
        .expect("the admitted protected target is canonical HTTPS");
    let credential = BoundBearerCredential::bind(resource.clone(), BEARER_SECRET)
        .expect("an HTTPS target binds the caller-acquired credential");
    let bound = ModernHttpRequest::new(
        resource.as_str(),
        b"{}".to_vec(),
        "2026-07-28",
        "ping",
        None,
    )
    .expect("a canonical modern POST builds")
    .with_authorization(&credential);
    assert!(
        bound
            .headers()
            .iter()
            .any(|(field, _)| field == "Authorization")
    );
    builder.positive("exact-target", "Authorization present");

    // One variable: the request target, against the same credential.
    for other in [
        "https://mcp.example.test/mcp-b",
        "https://other.example.test/mcp",
    ] {
        let elsewhere = ModernHttpRequest::new(other, b"{}".to_vec(), "2026-07-28", "ping", None)
            .expect("a canonical modern POST builds")
            .with_authorization(&credential);
        assert!(
            elsewhere
                .headers()
                .iter()
                .all(|(field, _)| field != "Authorization"),
            "a bearer credential must never follow a changed canonical target"
        );
        builder.negative(&format!("target={other}"), "Authorization absent");
    }
}

fn case_bearer_never_cleartext(builder: &mut CaseBuilder) {
    let secure = CanonicalHttpUrl::parse("https://mcp.example.test/mcp")
        .expect("the admitted protected target is canonical HTTPS");
    assert!(BoundBearerCredential::bind(secure, BEARER_SECRET).is_ok());
    builder.positive("https-target", "bound");

    // One variable: the same local server addressed over cleartext.
    for cleartext in [
        "http://127.0.0.1:8443/mcp",
        "http://[::1]:8443/mcp",
        "http://localhost:8443/mcp",
    ] {
        let resource = CanonicalHttpUrl::parse(cleartext).expect("the cleartext variant parses");
        let refusal = BoundBearerCredential::bind(resource, BEARER_SECRET)
            .expect_err("a loopback cleartext resource must not bind a bearer credential");
        assert_eq!(refusal, BearerBindingError::CleartextResource);
        builder.negative(cleartext, &format!("{refusal:?}"));
    }
}

fn case_bearer_token_bytes(builder: &mut CaseBuilder) {
    let resource = CanonicalHttpUrl::parse("https://mcp.example.test/mcp")
        .expect("the admitted protected target is canonical HTTPS");
    assert!(BoundBearerCredential::bind(resource.clone(), BEARER_SECRET).is_ok());
    builder.positive("token-bytes", "admitted");

    // One variable: the token bytes.
    let empty = BoundBearerCredential::bind(resource.clone(), "")
        .expect_err("an empty token must not bind");
    assert_eq!(empty, BearerBindingError::EmptyToken);
    builder.negative("token=\"\"", &format!("{empty:?}"));

    let injected = BoundBearerCredential::bind(resource, "secret\r\nInjected: header")
        .expect_err("a header-splitting token must not bind");
    assert_eq!(injected, BearerBindingError::InvalidTokenBytes);
    builder.negative(
        "token=\"secret\\r\\nInjected: header\"",
        &format!("{injected:?}"),
    );
}

fn case_credential_redaction(builder: &mut CaseBuilder, wire: &WireObservations) {
    let resource = CanonicalHttpUrl::parse("https://mcp.example.test/mcp")
        .expect("the admitted protected target is canonical HTTPS");
    let credential = BoundBearerCredential::bind(resource.clone(), BEARER_SECRET)
        .expect("an HTTPS target binds the caller-acquired credential");
    let credential_debug = format!("{credential:?}");
    assert!(!credential_debug.contains(BEARER_SECRET));
    builder.positive("credential-debug", &credential_debug);

    let request_debug = format!(
        "{:?}",
        ModernHttpRequest::new(
            resource.as_str(),
            b"{}".to_vec(),
            "2026-07-28",
            "ping",
            None
        )
        .expect("a canonical modern POST builds")
        .with_authorization(&credential)
    );
    assert!(request_debug.contains("<redacted>"));
    assert!(!request_debug.contains(BEARER_SECRET));
    builder.positive("request-debug", &request_debug);

    // One variable: search the same secret across every captured wire head and
    // body of the unauthenticated fixture exchanges.
    for (label, request) in [
        ("mcp-a-probe", &wire.a_probe),
        ("mcp-a-call", &wire.a_call),
        ("mcp-b-probe", &wire.b_probe),
        ("mcp-b-ping", &wire.b_ping),
        ("mcp-b-lane", &wire.b_lane_probe),
    ] {
        assert!(!request.head.contains(BEARER_SECRET));
        assert!(!String::from_utf8_lossy(&request.body).contains(BEARER_SECRET));
        assert!(request.header("Authorization").is_none());
        builder.negative(&format!("{label}-secret-search"), "absent");
    }
}

fn case_redirects_rejected(builder: &mut CaseBuilder) {
    let accepted = validate_response_head(
        200,
        &[("Content-Type".to_owned(), "application/json".to_owned())],
    )
    .expect("a 200 JSON head is admitted");
    assert_eq!(accepted.kind(), ModernHttpResponseKind::Json);
    builder.positive("status=200", &format!("{:?}", accepted.kind()));

    // One variable: the response status.
    for status in [301_u16, 302, 303, 307, 308] {
        let refusal = validate_response_head(
            status,
            &[
                (
                    "Location".to_owned(),
                    "https://redirect.example.test/mcp".to_owned(),
                ),
                ("Content-Type".to_owned(), "application/json".to_owned()),
            ],
        )
        .expect_err("every 3xx must be refused without a replay");
        assert!(matches!(
            refusal,
            ModernHttpExecutorError::Redirect { status: observed } if observed == status
        ));
        builder.negative(&format!("status={status}"), &format!("{refusal:?}"));
    }
}

fn case_endpoint_instance_partition(builder: &mut CaseBuilder, wire: &WireObservations) {
    // Determinism: identical configured inputs reproduce the same identity.
    let repeat_a = canonical_plan(
        &wire.a_target,
        ProtocolPolicy::ModernOnly,
        "security-partition-http-03-integration",
    );
    let repeat_key = repeat_a
        .http_endpoints()
        .expect("the plan retains its endpoint bundle")
        .key();
    assert_eq!(repeat_key, wire.a_endpoint_key);
    builder.positive("mcp-a-identity-deterministic", "true");
    builder.positive("mcp-a-target", &wire.normalize(&wire.a_target));
    builder.positive("mcp-b-target", &wire.normalize(&wire.b_target));

    // One variable: the configured path on the same origin.
    assert_ne!(
        wire.a_endpoint_key, wire.b_endpoint_key,
        "same-origin /mcp-a and /mcp-b are distinct endpoint instances"
    );
    builder.negative("path=/mcp-b", "endpoint identity differs");
}

fn case_security_partition(builder: &mut CaseBuilder, wire: &WireObservations) {
    let baseline = canonical_plan(
        &wire.a_target,
        ProtocolPolicy::ModernOnly,
        "security-partition-http-03-integration",
    );
    let baseline_key = baseline
        .http_endpoints()
        .expect("the plan retains its endpoint bundle")
        .key();
    assert_eq!(baseline_key, wire.a_endpoint_key);
    builder.positive("baseline-identity", "matches the live connection");

    // One variable: the security partition.
    let repartitioned = canonical_plan(
        &wire.a_target,
        ProtocolPolicy::ModernOnly,
        "security-partition-http-03-integration-other",
    );
    let repartitioned_key = repartitioned
        .http_endpoints()
        .expect("the plan retains its endpoint bundle")
        .key();
    assert_ne!(
        repartitioned_key, baseline_key,
        "a changed security partition must not share a cache entry"
    );
    builder.negative("security_partition=<other>", "endpoint identity differs");
}

fn case_configuration_generation(builder: &mut CaseBuilder, wire: &WireObservations) {
    let modern_target =
        CanonicalHttpUrl::parse(&wire.a_target).expect("the fixture target is canonical");
    let baseline = ClientProtocolPlan::http(
        ProtocolPolicy::ModernOnly,
        Some(modern_target.clone()),
        None,
        None,
        "credential-partition-http-03-integration".to_owned(),
        "security-partition-http-03-integration".to_owned(),
        "native-h1-http-03-integration".to_owned(),
        1,
        1,
        0,
    )
    .expect("the baseline plan is accepted")
    .http_endpoints()
    .expect("the plan retains its endpoint bundle")
    .key();
    assert_eq!(baseline, wire.a_endpoint_key);
    builder.positive("configuration_generation=1", "matches the live connection");

    // One variable: the configuration generation.
    let regenerated = ClientProtocolPlan::http(
        ProtocolPolicy::ModernOnly,
        Some(modern_target),
        None,
        None,
        "credential-partition-http-03-integration".to_owned(),
        "security-partition-http-03-integration".to_owned(),
        "native-h1-http-03-integration".to_owned(),
        1,
        2,
        0,
    )
    .expect("the regenerated plan is accepted")
    .http_endpoints()
    .expect("the plan retains its endpoint bundle")
    .key();
    assert_ne!(
        regenerated, baseline,
        "a changed configuration generation must not share a cache entry"
    );
    builder.negative("configuration_generation=2", "endpoint identity differs");
}

/// One cell of the 3x3 no-downgrade observation matrix.
#[derive(Debug, Clone)]
struct MatrixCell {
    render: String,
}

/// Builds the 3x3 ineligible-status by body-class matrix. No cell may select
/// an era, authorize a legacy fallback, or mutate retained state.
fn no_downgrade_matrix() -> Vec<MatrixCell> {
    let mut cells = Vec::with_capacity(9);
    for status in [401_u16, 429, 500] {
        for body in [
            HttpProbeBody::Empty,
            HttpProbeBody::Unrecognized,
            HttpProbeBody::TransportFailure,
        ] {
            let plan = classification_plan(ProtocolPolicy::Auto);
            let mut negotiation = ClientHttpNegotiation::from_protocol_plan(&plan)
                .expect("the configured Auto plan starts one classification attempt");
            let before = negotiation.state();
            assert!(!before.probe_dispatched());
            let refusal = negotiation
                .observe_modern_probe(HttpModernProbe { status, body })
                .expect_err("an ineligible observation must never authorize a downgrade");
            let after = negotiation.state();
            assert_eq!(after.selected_era(), None);
            assert!(!after.legacy_sse_fallback_authorized());
            cells.push(MatrixCell {
                render: format!("{status}/{body:?} -> {refusal:?}"),
            });
        }
    }
    assert_eq!(cells.len(), 9);
    cells
}

// ---------------------------------------------------------------------------
// B-half predicates, keyed to the subjects HTTP_03_B_EVALUATOR_MANIFEST_V1
// DECLARES.
//
// This join previously assigned its own subjects to ordinals 14..26 and
// disagreed with B on all thirteen. The A half matched 13/13, and B's names map
// onto the frozen package contract's `Tests:` bullets while three of this
// join's did not appear there at all - so the stale side was this file. The
// floor gate could never have caught it: B derived its floors from this
// evaluator's own observation counts, so the numbers agreed while the meanings
// did not. `assert_predicate_matches_declared_case` is what caught it.
//
// Where an existing predicate already observed B's declared subject it is
// reused verbatim rather than rewritten, and where B's subject is broader than
// one old predicate the related observations are folded in - they were always
// real observations of real behaviour, only recorded under the wrong name.
// ---------------------------------------------------------------------------

/// HTTP-03.17 `authorization-redaction` (floor 3).
fn case_authorization_redaction(builder: &mut CaseBuilder, wire: &WireObservations) {
    case_credential_redaction(builder, wire);
}

/// HTTP-03.18 `https-only-bearer-attachment` (floor 3).
///
/// B's subject is the attachment rule itself, which is exactly what the
/// bound-target, never-cleartext and token-byte observations prove between
/// them: a bearer reaches an HTTPS target, never an `http:` one, and its bytes
/// are bound rather than copied.
fn case_https_only_bearer_attachment(builder: &mut CaseBuilder) {
    case_bearer_bound_target(builder);
    case_bearer_never_cleartext(builder);
    case_bearer_token_bytes(builder);
}

/// HTTP-03.19 `redirect-no-follow-no-replay` (floor 4).
fn case_redirect_no_follow_no_replay(builder: &mut CaseBuilder) {
    case_redirects_rejected(builder);
}

/// HTTP-03.20 `discover-preclassification-frame` (floor 3).
///
/// The era selection folded in here is the classification the discovery frame
/// feeds; B names the frame, and the selected era is the observable it produces.
fn case_discover_preclassification_frame(builder: &mut CaseBuilder, wire: &WireObservations) {
    case_discovery_frames(builder, wire);
    case_modern_era_selection(builder, wire);
}

/// HTTP-03.21 `fresh-probe-identity-after-authorization` (floor 7).
///
/// The one-shot probe proves the probe is issued exactly once per connection;
/// the not-forwarded observation proves the credential from one target does not
/// ride along on the next probe. Together they are the identity claim B names.
fn case_fresh_probe_identity_after_authorization(
    builder: &mut CaseBuilder,
    wire: &WireObservations,
) {
    case_one_shot_probe(builder, wire);
    case_bearer_not_forwarded(builder);
}

/// HTTP-03.22 `endpoint-instance-key-partition` (floor 6).
///
/// The endpoint-instance, security-partition and configuration-generation
/// observations are the three components of the bundle key B names.
fn case_endpoint_instance_key_partition(builder: &mut CaseBuilder, wire: &WireObservations) {
    case_endpoint_instance_partition(builder, wire);
    case_security_partition(builder, wire);
    case_configuration_generation(builder, wire);
}

// --- Not yet proven. ---------------------------------------------------------
//
// B declares these four subjects and this join does not yet exercise them. They
// need fixture scenarios that do not exist here yet: a cancelled caller, an
// armed deadline racing a disconnect, a mid-flight disconnect whose dispatch is
// uncertain, an extension activation notification, an independent server->client
// request, and an SSE stream carrying no event id.
//
// They deliberately record NOTHING. The floor gate below then fails the case by
// its declared floor and names the shortfall, which is the honest state: the
// behaviour is unproven, and a predicate that recorded a placeholder observation
// to reach a floor would be exactly the unevidenced box this evaluator exists to
// prevent. A check that cannot fail is not evidence.

/// HTTP-03.14 `caller-cancellation-response-close` (floor 5).
///
/// B's subject has two halves and this proves both. The caller half is that a
/// cancelled caller gets a typed refusal rather than a hang or a silent clean
/// end. The server half is that the response stream is actually CLOSED - EOF
/// observed on the response connection - which is the claim a purely
/// client-side assertion cannot make, because a leaked connection looks
/// identical from inside the client.
fn case_caller_cancellation_close(builder: &mut CaseBuilder, wire: &WireObservations) {
    let cancel = &wire.caller_cancellation;

    assert_eq!(
        cancel.progress_before_cancel, 1,
        "the stream must deliver a live progress event before anything is cancelled, \
         otherwise this case proves only that a dead stream stayed dead"
    );
    builder.positive("cancel-progress-before-cancel", "1");

    assert!(
        cancel.post_cancel_outcome.starts_with("listen::"),
        "a cancelled caller must observe a typed listen refusal; observed {}",
        cancel.post_cancel_outcome
    );
    // One variable: the caller cancelled. Everything else - the fixture, the
    // request, the stream - is identical to the live case above, and the
    // observed outcome is the typed refusal that variable produces.
    builder.negative("caller-cancelled", &cancel.post_cancel_outcome);

    assert!(
        cancel.server_saw_stream_close,
        "the server must observe EOF on the response connection; without it the caller \
         merely stopped reading and the response stream was not proven closed"
    );
    builder.positive("cancel-response-stream-closed", "true");

    assert_eq!(
        cancel.requests_during_call, 1,
        "the cancellation lane must post exactly once"
    );
    builder.positive("cancel-requests", "1");

    assert_eq!(
        cancel.connections_after_return, 0,
        "a cancelled request must not be replayed; {} retry connection(s) were queued",
        cancel.connections_after_return
    );
    builder.positive("cancel-retry-connections", "0");
}

/// HTTP-03.15 `deadline-and-disconnect-races` (floor 4).
///
/// The discrimination B names is which of the two racing conditions actually
/// fired. A stalled-but-OPEN connection is the only way to tell them apart: the
/// socket never breaks, so a transport error here would mean the client
/// misreported a deadline as a disconnect, and a timeout means the deadline
/// genuinely won. `server_held_connection_open` is what makes that claim
/// checkable rather than asserted.
fn case_deadline_and_disconnect_races(builder: &mut CaseBuilder, wire: &WireObservations) {
    let lane = &wire.deadline_race;
    assert!(
        lane.server_held_connection_open,
        "the deadline lane must hold its connection open, otherwise a timeout and a \
         disconnect are indistinguishable and this case proves nothing"
    );
    builder.positive("deadline-connection-held-open", "true");

    assert!(
        lane.outcome.starts_with("executor::Timeout("),
        "an armed idle deadline over an open, silent connection must surface a typed \
         timeout; observed {}",
        lane.outcome
    );
    // One variable: the idle bound is armed short while the peer stays silent.
    // The connection is never broken, so this refusal is the deadline's.
    builder.negative("idle-deadline-armed", &lane.outcome);

    assert_eq!(
        lane.requests_during_call, 2,
        "the deadline lane posts twice on purpose: the refused call, then one deliberate \
         follow-up establishing that the refusal did not poison the connection"
    );
    builder.positive("deadline-requests", "2 (refused + deliberate follow-up)");

    // Side four of the boundary shape: a refusal must leave the connection
    // USABLE. Without it, "it refused" is indistinguishable from "it refused and
    // broke everything after it", and only the first is the contract. The
    // fixture publishes its retry count before serving this, so a deliberate
    // follow-up can never be miscounted as a client-initiated retry.
    assert!(
        lane.followup_outcome.starts_with("followup-ok"),
        "a timed-out request must leave the connection usable; the follow-up observed {}",
        lane.followup_outcome
    );
    builder.positive("deadline-refusal-is-recoverable", &lane.followup_outcome);

    assert_eq!(
        lane.connections_after_return, 0,
        "a timed-out request must not be replayed; {} retry connection(s) were queued",
        lane.connections_after_return
    );
    builder.positive("deadline-retry-connections", "0");
}

/// HTTP-03.16 `uncertain-dispatch-no-retry` (floor 4).
///
/// The fixture reads the whole POST and then closes without answering. The
/// request certainly arrived; whether the server acted on it is unknowable to
/// the client. A non-idempotent request in that state must NOT be replayed, and
/// the outcome must stay a transport failure rather than being resolved into a
/// decided refusal the client is not entitled to claim.
fn case_uncertain_dispatch_no_retry(builder: &mut CaseBuilder, wire: &WireObservations) {
    let lane = &wire.uncertain_dispatch;
    assert_eq!(
        lane.requests_during_call, 2,
        "the uncertain lane posts twice on purpose: the refused call, then one deliberate \
         follow-up establishing that the refusal did not poison the connection"
    );
    builder.positive("uncertain-requests", "2 (refused + deliberate follow-up)");

    // Side four of the boundary shape: a refusal must leave the connection
    // USABLE. Without it, "it refused" is indistinguishable from "it refused and
    // broke everything after it", and only the first is the contract. The
    // fixture publishes its retry count before serving this, so a deliberate
    // follow-up can never be miscounted as a client-initiated retry.
    assert!(
        lane.followup_outcome.starts_with("followup-ok"),
        "an uncertainly-dispatched request must leave the connection usable; the follow-up observed {}",
        lane.followup_outcome
    );
    builder.positive("uncertain-refusal-is-recoverable", &lane.followup_outcome);

    assert!(
        !lane.outcome.starts_with("unexpected-success"),
        "a request whose peer closed without answering cannot succeed; observed {}",
        lane.outcome
    );
    // One variable: the peer closes after reading the POST and never answers.
    builder.negative("peer-closed-unanswered", &lane.outcome);

    assert!(
        !lane.outcome.starts_with("executor::Timeout("),
        "a peer that closed is a disconnect, not a deadline; reporting {} here would be \
         the mirror of the HTTP-03.15 confusion",
        lane.outcome
    );
    builder.positive("uncertain-not-a-deadline", "true");

    assert_eq!(
        lane.connections_after_return, 0,
        "an uncertain dispatch must not be retried; {} retry connection(s) were queued",
        lane.connections_after_return
    );
    builder.positive("uncertain-retry-connections", "0");
}

/// HTTP-03.23 `extension-activation-proof-notification` (floor 4).
///
/// Proves the half of B's subject that the DEFAULT feature set exposes. See
/// [`observe_extension_notification`] for why the activation-receipt half is
/// out of reach here and is reported rather than simulated.
fn case_extension_activation_notification(builder: &mut CaseBuilder, wire: &WireObservations) {
    let observed = &wire.extension_notification;

    assert!(
        observed.first_event.starts_with("notification::"),
        "an admitted final-server notification must surface as a Notification event rather \
         than as progress, a terminal, or a refusal; observed {}",
        observed.first_event
    );
    builder.positive("extension-notification-admitted", &observed.first_event);

    assert_eq!(
        observed.terminal_after_notification, "terminal=tools_call",
        "the caller's terminal must still arrive after an interleaved notification; a \
         notification must not consume or close the caller's stream"
    );
    builder.positive(
        "terminal-survives-notification",
        &observed.terminal_after_notification,
    );

    assert_eq!(
        observed.era_after_notification,
        ProtocolEra::Modern2026,
        "an interleaved server notification must not mutate the negotiated era"
    );
    builder.positive("era-unchanged-by-notification", "Modern2026");

    assert_eq!(
        observed.connections_after_return, 0,
        "an interleaved notification must not cause a replay; {} retry connection(s) queued",
        observed.connections_after_return
    );
    assert_eq!(
        observed.requests_during_call, 2,
        "the notification lane posts twice on purpose: the streamed call, then the \
         follow-up that gives HTTP-03.25's planted event id somewhere to leak to"
    );
    builder.positive("notification-no-replay", "2 posts, 0 retries");

    // One variable: the notification method is not one of the eight a final
    // server may originate. Everything else about the frame is well formed.
    // Driven through the facade-exported public decode, not a private parser.
    let undeclared = JsonRpcRequest::notification("notifications/not_a_real_method", None);
    let refusal = ServerNotification::decode(&undeclared)
        .expect_err("a method outside the declared set must not be admitted");
    builder.negative("notification-method=undeclared", &format!("{refusal:?}"));
}

/// HTTP-03.24 `independent-server-request-rejection` (floor 2).
fn case_independent_server_request_rejection(builder: &mut CaseBuilder, wire: &WireObservations) {
    let observed = &wire.independent_server_request;

    assert!(
        !observed.outcome.starts_with("admitted::"),
        "an independent server->client request arriving on a caller-owned response stream \
         must not be handed back as the caller's event; observed {}",
        observed.outcome
    );
    // One variable: the frame carries `id` AND `method`, making it a request
    // rather than a response or notification. The rejection is the boundary.
    builder.negative("frame-is-a-server-request", &observed.outcome);

    assert_eq!(
        observed.connections_after_return, 0,
        "rejecting an independent server request must not replay the caller's request; {} \
         retry connection(s) were queued",
        observed.connections_after_return
    );
    assert_eq!(
        observed.requests_during_call, 1,
        "the server-request lane must post exactly once"
    );
    builder.positive("independent-server-request-no-replay", "1 post, 0 retries");
}

/// HTTP-03.25 `no-event-id-retry-resumption-state` (floor 2).
///
/// Every event this fixture writes is `data:` only - it carries no `id:` field,
/// so the stream offers the client nothing to resume from. Two things follow and
/// both are checked against the wire rather than against the client's internals.
///
/// This is a negative-space assertion, so it is worth saying why it is not
/// tautological: it fails the moment the shipped client starts emitting a
/// resumption header, which is exactly the regression it guards. The second
/// observation keeps it from resting on absence alone by requiring that the
/// terminal still arrived - delivery must not depend on resumption state that
/// was never established.
fn case_no_event_id_retry_resumption(builder: &mut CaseBuilder, wire: &WireObservations) {
    let requests = [
        ("a_probe", &wire.a_probe),
        ("a_call", &wire.a_call),
        ("b_probe", &wire.b_probe),
        ("b_ping", &wire.b_ping),
        ("b_lane_probe", &wire.b_lane_probe),
    ];
    for (name, request) in requests {
        assert!(
            request.header("Last-Event-ID").is_none(),
            "no request may carry a resumption header when the stream published no event \
             ids; {name} carried Last-Event-ID"
        );
    }
    builder.positive("resumption-header-absent-on-all-requests", "5/5");

    assert!(
        wire.a_terminal.starts_with("terminal="),
        "the id-less stream must still deliver its terminal; observed {}",
        wire.a_terminal
    );
    builder.positive(
        "terminal-delivered-without-event-ids",
        &wire.normalize(&wire.a_terminal),
    );

    // One variable: a stream DID publish `id: planted-event-id-25`, and the
    // client then issued a second request. That is the only condition under
    // which resumption state could plausibly appear, so the negative creates it
    // rather than resting on an absence nothing ever challenged.
    let leaked = &wire.extension_notification.second_request_resumption_header;
    assert!(
        leaked.is_none(),
        "a published event id must not become resumption state on a later request; the \
         follow-up request carried Last-Event-ID: {leaked:?}"
    );
    builder.negative("stream-published-event-id", "no Last-Event-ID on the next request");
}

fn case_no_downgrade_matrix(builder: &mut CaseBuilder, matrix: &[MatrixCell]) {
    for cell in matrix {
        builder.positive("no-downgrade", &cell.render);
    }

    // One variable: the policy, against the single eligible observation. Both
    // plans carry the identical endpoint set, so policy is the only difference.
    let plan = classification_plan(ProtocolPolicy::Auto);
    let mut eligible = ClientHttpNegotiation::from_protocol_plan(&plan)
        .expect("the configured Auto plan starts one classification attempt");
    let decision = eligible
        .observe_modern_probe(HttpModernProbe {
            status: 404,
            body: HttpProbeBody::Unrecognized,
        })
        .expect("Auto admits the isolated-first-probe fallback authorization");
    assert_eq!(
        decision,
        ClientHttpNegotiationDecision::LegacySseFallbackAuthorized
    );
    assert_eq!(
        eligible.state().selected_era(),
        None,
        "authorizing an observation is never an era selection"
    );
    builder.positive("policy=Auto,404/Unrecognized", &format!("{decision:?}"));

    let modern_only = classification_plan(ProtocolPolicy::ModernOnly);
    let mut planted = ClientHttpNegotiation::from_protocol_plan(&modern_only)
        .expect("the configured ModernOnly plan starts one classification attempt");
    let before = planted.state();
    let refusal = planted
        .observe_modern_probe(HttpModernProbe {
            status: 404,
            body: HttpProbeBody::Unrecognized,
        })
        .expect_err("ModernOnly must refuse the same observation");
    assert!(matches!(
        refusal,
        ClientHttpNegotiationError::ModernProbeRejectedWithoutLegacyFallback {
            status: 404,
            body: HttpProbeBody::Unrecognized,
        }
    ));
    let after = planted.state();
    assert_eq!(after.selected_era(), before.selected_era());
    assert_eq!(
        after.legacy_sse_fallback_authorized(),
        before.legacy_sse_fallback_authorized()
    );
    builder.negative("policy=ModernOnly", &format!("{refusal:?}"));
}

// ---------------------------------------------------------------------------
// Frozen acceptance IDs
// ---------------------------------------------------------------------------

#[test]
fn http_03_i_positive() {
    let receipt = evaluate_join(false);
    println!("{}", receipt.execution_summary());

    // Manifest half: the join consumed both producer inputs and their digests.
    assert_eq!(receipt.cases.len(), LAST_CASE_ORDINAL);
    // PL-5 clocks: the regime is RECORDED, deliberately not re-asserted here.
    //
    // An assertion comparing `receipt.clock_regime` against a string rebuilt
    // from the same constants cannot fail - both sides read
    // JOIN_IDLE_TIMEOUT and friends - so it would be ceremony, not evidence.
    // Drift is prevented structurally instead: those constants are the single
    // source for both the RequestTimeoutPolicy the join installs and the string
    // the receipt reports, so there is no second place to forget to update.
    //
    // The behavioural proof that the recorded regime is the one in force lives
    // in HTTP-03.15, which only reaches `executor::Timeout(Idle)` if the armed
    // idle bound genuinely expires against a held-open, silent peer.
    assert_eq!(receipt.a_digest.len(), 64);
    assert_eq!(receipt.b_digest.len(), 64);
    assert_ne!(receipt.a_digest, receipt.b_digest);
    assert!(!receipt.producer_a_revision.is_empty());
    assert!(!receipt.producer_a_tree.is_empty());
    assert!(!receipt.producer_b_revision.is_empty());
    assert!(!receipt.producer_b_tree.is_empty());
    assert!(receipt.producer_a_entrypoint.starts_with("fastmcp"));
    assert!(receipt.producer_b_entrypoint.starts_with("fastmcp"));
    assert_eq!(receipt.joined_entrypoint, JOINED_PUBLIC_ENTRYPOINT);

    // Execution half: the declared ordered floors were met by real work.
    assert!(
        receipt.total_positive() >= MINIMUM_POSITIVE_CASES,
        "the integrated evaluator executed {} positive observations, below the floor of {}",
        receipt.total_positive(),
        MINIMUM_POSITIVE_CASES
    );
    assert!(
        receipt.total_negative() >= MINIMUM_NEGATIVE_CASES,
        "the integrated evaluator executed {} planted-negative observations, below the floor of {}",
        receipt.total_negative(),
        MINIMUM_NEGATIVE_CASES
    );

    // Recorded observation fields required of the join.
    assert_eq!(receipt.no_downgrade_matrix.len(), 9);
    assert!(receipt.canonical_targets.0.ends_with("/mcp-a"));
    assert!(receipt.canonical_targets.1.ends_with("/mcp-b"));
    assert_ne!(receipt.discovery_frames.0, receipt.discovery_frames.1);
    assert!(
        receipt
            .fixture_identity
            .starts_with("loopback-tcp authority=")
    );
    assert!(receipt.endpoint_identity.contains("a=") && receipt.endpoint_identity.contains("b="));

    // The live terminal outcomes on both lanes.
    assert!(
        receipt.case("HTTP-03.11").record.contains("terminal=json"),
        "the JSON lane must reach its terminal under the accepted identity coding"
    );
    assert!(
        receipt
            .case("HTTP-03.13")
            .record
            .contains("terminal=tools_call"),
        "the SSE lane must reach its correlated terminal"
    );
    assert!(
        receipt
            .case("HTTP-03.13")
            .record
            .contains("closed=terminal_then_none"),
        "the owning stream must close exactly once after its terminal"
    );
}

#[test]
fn http_03_i_planted_negative() {
    let accepted = evaluate_join(false);
    let planted = evaluate_join(true);
    println!("accepted: {}", accepted.execution_summary());
    println!("planted:  {}", planted.execution_summary());

    // The one changed variable is the `/mcp-b` terminal response coding, which
    // lives in exactly one manifest case.
    let planted_case = planted.case(PLANTED_CASE_ID);
    let accepted_case = accepted.case(PLANTED_CASE_ID);
    assert_ne!(
        planted_case.record, accepted_case.record,
        "the planted variable must change the case it was planted in"
    );
    assert!(
        planted_case.record.contains("UnsupportedContentEncoding"),
        "the planted coding must reach the registered typed refusal, observed: {}",
        planted_case.record
    );
    assert!(
        !planted_case.record.contains("terminal=json"),
        "a refused response coding must not also yield a decoded JSON terminal"
    );

    // Every other manifest case is byte-for-byte unchanged.
    assert_eq!(accepted.cases.len(), planted.cases.len());
    for (accepted_case, planted_case) in accepted.cases.iter().zip(planted.cases.iter()) {
        assert_eq!(accepted_case.id, planted_case.id);
        assert_eq!(accepted_case.name, planted_case.name);
        assert_eq!(accepted_case.floor, planted_case.floor);
        if accepted_case.id == PLANTED_CASE_ID {
            continue;
        }
        assert_eq!(
            accepted_case, planted_case,
            "{} must be unchanged by a plant in {PLANTED_CASE_ID}",
            accepted_case.id
        );
    }

    // The unrelated sibling stream and its waiter completed normally while the
    // planted POST was refused on the other endpoint instance.
    assert_eq!(
        planted.case("HTTP-03.12").record,
        accepted.case("HTTP-03.12").record
    );
    assert!(
        planted
            .case("HTTP-03.13")
            .record
            .contains("terminal=tools_call"),
        "the sibling SSE stream must still reach its terminal"
    );
    assert!(
        planted
            .case("HTTP-03.13")
            .record
            .contains("closed=terminal_then_none"),
        "the sibling stream must close exactly once, unaffected by the plant"
    );

    // Credential, cache, endpoint-selection, and era state are unchanged.
    //
    // Each of AC-4's named categories is checked twice: that the case still
    // CARRIES the evidence for that category, and that the record is identical
    // across both passes. The containment half matters - the ordered loop above
    // already proves every non-planted case equal, so an equality assertion
    // alone could never fail on its own and would silently keep passing even if
    // it named a case that had nothing to do with the category. That is exactly
    // how these four came to point at the wrong cases after the B-half re-key:
    // numbers agreeing while meanings drifted.
    for (category, id, evidence) in [
        ("credential", "HTTP-03.17", "credential-debug"),
        ("era selection", "HTTP-03.20", "mcp-a-era"),
        ("endpoint selection", "HTTP-03.22", "mcp-a-identity-deterministic"),
        // The cache claim is the endpoint bundle key: a changed security
        // partition or configuration generation must not share a cache entry,
        // and both of those observations live in HTTP-03.22.
        ("cache partition (security)", "HTTP-03.22", "security_partition=<other>"),
        ("cache partition (generation)", "HTTP-03.22", "configuration_generation=2"),
    ] {
        let planted_record = &planted.case(id).record;
        assert!(
            planted_record.contains(evidence),
            "{category} state is claimed unchanged against {id}, but that case records no \
             `{evidence}` - the claim would be unfalsifiable"
        );
        assert_eq!(
            planted_record,
            &accepted.case(id).record,
            "{category} state must be unchanged by a plant in {PLANTED_CASE_ID}"
        );
    }
    assert_eq!(
        planted.no_downgrade_matrix, accepted.no_downgrade_matrix,
        "the 3x3 no-downgrade observation state must be unchanged"
    );
    assert_eq!(planted.discovery_frames, accepted.discovery_frames);

    // An ineligible observation performs zero legacy GET and zero era mutation.
    //
    // The count is recorded by the one-shot probe, which the re-key folded into
    // HTTP-03.21. This previously read HTTP-03.14, which after the re-key is
    // caller cancellation and records no such field - so it asserted the
    // presence of a string that case never writes.
    assert!(
        planted
            .case("HTTP-03.21")
            .record
            .contains("legacy-get-count = 0"),
        "the planted run must issue no legacy GET"
    );
    assert_eq!(
        planted.case("HTTP-03.21").record,
        accepted.case("HTTP-03.21").record
    );

    // Producer identity is bound to both runs.
    assert_eq!(planted.a_digest, accepted.a_digest);
    assert_eq!(planted.b_digest, accepted.b_digest);
    assert_eq!(planted.producer_a_revision, accepted.producer_a_revision);
    assert_eq!(planted.producer_b_revision, accepted.producer_b_revision);
}
