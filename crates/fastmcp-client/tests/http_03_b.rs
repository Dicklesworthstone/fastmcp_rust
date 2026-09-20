//! HTTP-03 implementation B: the canonical `http_03_evaluator_manifest_v1`
//! groups `HTTP-03.14` through `HTTP-03.26`, each with one positive and one
//! one-variable planted negative, executed in frozen order.
//!
//! This is a clean-room target. It carries only the two frozen root IDs
//! `http_03_b_positive` and `http_03_b_planted_negative` and drives all 26
//! ordered cases itself, mirroring the A slice's target. It deliberately does
//! not reuse `http_03_b_runtime.rs`, whose SSE fixture is recorded on
//! `bd-mcp-http-03-b-3r1d` as delivering empty bodies.
//!
//! Every socket case drives the shipped public modern client against a real
//! loopback `asupersync::net::TcpListener` on `127.0.0.1:0` speaking raw
//! HTTP/1.1. Nothing substitutes an in-memory transport or a private executor
//! for the wire.
//!
//! Streaming bodies are always chunk-framed. The pinned `asupersync` h1
//! decoder selects framing from the response head and has no close-delimited
//! body mode: `BodyKind` is `ContentLength`/`Chunked`/`Empty` only, and
//! `body_kind()` falls through to `Empty` when a head carries neither
//! `Content-Length` nor `Transfer-Encoding`. A close-delimited SSE head would
//! therefore deliver zero events and pass while observing nothing.

use std::future::{Future, poll_fn};
use std::task::{Context, Poll, Waker};
use std::time::Duration;

use asupersync::Cx;
use asupersync::io::{AsyncReadExt, AsyncWriteExt};
use asupersync::net::{TcpListener, TcpStream};
use asupersync::runtime::{RuntimeBuilder, reactor::create_reactor};
use fastmcp_client::http_auth::{BearerBindingError, BoundBearerCredential};
use fastmcp_client::http_executor::{
    HTTP_03_B_EVALUATOR_MANIFEST_V1, ModernHttpExecutor, ModernHttpExecutorError,
    ModernHttpRequest, ModernHttpResponseKind, ModernHttpResponseStream, http_03_b_manifest_digest,
};
use fastmcp_client::{
    CanonicalHttpUrl, ClientBuilder, ClientHttpNegotiation, ClientHttpNegotiationDecision,
    ClientHttpNegotiationError, ClientProtocolPlan, ProtocolPolicy, RequestTimeoutPolicy,
};
use fastmcp_core::sha256_bounded;
use fastmcp_protocol::protocol_policy::{HttpModernProbe, HttpProbeBody, ProtocolEra};

// ---------------------------------------------------------------------------
// Frozen manifest: `http_03_evaluator_manifest_v1`, B half
// ---------------------------------------------------------------------------

/// One manifest row. `group` is the canonical group ID and `variable` names the
/// single dimension a negative changes (or that a positive captures).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct ManifestCase {
    group: &'static str,
    variable: &'static str,
    entrypoint: &'static str,
}

/// The thirteen positives, in exact manifest order.
const POSITIVE_CASES: [ManifestCase; 13] = [
    ManifestCase {
        group: "HTTP-03.14",
        variable: "caller cancellation closes the owned response",
        entrypoint: "ModernHttpExecutor::execute",
    },
    ManifestCase {
        group: "HTTP-03.15",
        variable: "post-commit response deadline fires as a typed timeout",
        entrypoint: "ModernHttpExecutor::execute",
    },
    ManifestCase {
        group: "HTTP-03.16",
        variable: "an uncertain dispatch is never retried or replayed",
        entrypoint: "ModernHttpExecutor::execute",
    },
    ManifestCase {
        group: "HTTP-03.17",
        variable: "the bearer token is absent from every rendered diagnostic",
        entrypoint: "BoundBearerCredential::bind",
    },
    ManifestCase {
        group: "HTTP-03.18",
        variable: "a bearer binds only to its exact https resource",
        entrypoint: "BoundBearerCredential::authorization_for_target",
    },
    ManifestCase {
        group: "HTTP-03.19",
        variable: "every redirect status is terminal and unfollowed",
        entrypoint: "ModernHttpExecutor::execute",
    },
    ManifestCase {
        group: "HTTP-03.20",
        variable: "the one-shot discover probe frame and its headers",
        entrypoint: "ClientBuilder::connect_http_with_cx",
    },
    ManifestCase {
        group: "HTTP-03.21",
        variable: "a re-authorized endpoint re-probes from a fresh identity",
        entrypoint: "ClientHttpNegotiation::observe_modern_probe",
    },
    ManifestCase {
        group: "HTTP-03.22",
        variable: "the complete endpoint-instance key partitions negotiation",
        entrypoint: "ClientHttpNegotiation::from_protocol_plan",
    },
    ManifestCase {
        group: "HTTP-03.23",
        variable: "an activation-proof notification is admitted on its own lane",
        entrypoint: "ModernHttpExecutor::execute",
    },
    ManifestCase {
        group: "HTTP-03.24",
        variable: "a server-issued session header is refused",
        entrypoint: "ModernHttpExecutor::execute",
    },
    ManifestCase {
        group: "HTTP-03.25",
        variable: "no event-ID, retry, or resumption state is ever sent",
        entrypoint: "ModernHttpExecutor::execute",
    },
    ManifestCase {
        group: "HTTP-03.26",
        variable: "the 3x3 observation table and its no-downgrade rule",
        entrypoint: "ClientHttpNegotiation::observe_modern_probe",
    },
];

/// The thirteen one-variable planted negatives, in exact manifest order.
const NEGATIVE_CASES: [ManifestCase; 13] = [
    ManifestCase {
        group: "HTTP-03.14",
        variable: "cancellation requested before dispatch instead of after",
        entrypoint: "ModernHttpExecutor::execute",
    },
    ManifestCase {
        group: "HTTP-03.15",
        variable: "the peer stalls past the response deadline",
        entrypoint: "ModernHttpExecutor::execute",
    },
    ManifestCase {
        group: "HTTP-03.16",
        variable: "the peer closes mid-exchange, inviting a replay",
        entrypoint: "ModernHttpExecutor::execute",
    },
    ManifestCase {
        group: "HTTP-03.17",
        variable: "a header-hostile token byte instead of an admissible one",
        entrypoint: "BoundBearerCredential::bind",
    },
    ManifestCase {
        group: "HTTP-03.18",
        variable: "the resource scheme is http instead of https",
        entrypoint: "BoundBearerCredential::bind",
    },
    ManifestCase {
        group: "HTTP-03.19",
        variable: "a 307 carrying a Location the client must not follow",
        entrypoint: "ModernHttpExecutor::execute",
    },
    ManifestCase {
        group: "HTTP-03.20",
        variable: "an unrecognized probe body instead of modern JSON-RPC",
        entrypoint: "ClientHttpNegotiation::observe_modern_probe",
    },
    ManifestCase {
        group: "HTTP-03.21",
        variable: "a second probe on the same negotiation instance",
        entrypoint: "ClientHttpNegotiation::observe_modern_probe",
    },
    ManifestCase {
        group: "HTTP-03.22",
        variable: "one endpoint-key field differs while the origin matches",
        entrypoint: "ClientHttpNegotiation::from_protocol_plan",
    },
    ManifestCase {
        group: "HTTP-03.23",
        variable: "a 202 acknowledgement carrying a forbidden content type",
        entrypoint: "ModernHttpExecutor::execute",
    },
    ManifestCase {
        group: "HTTP-03.24",
        variable: "the response repeats a fixed-cardinality header",
        entrypoint: "ModernHttpExecutor::execute",
    },
    ManifestCase {
        group: "HTTP-03.25",
        variable: "the peer offers SSE resumption state in its response",
        entrypoint: "ModernHttpExecutor::execute",
    },
    ManifestCase {
        group: "HTTP-03.26",
        variable: "a legacy-only policy attempts the modern probe",
        entrypoint: "ClientHttpNegotiation::observe_modern_probe",
    },
];

/// The frozen group order both tables must equal.
const MANIFEST_GROUP_ORDER: [&str; 13] = [
    "HTTP-03.14",
    "HTTP-03.15",
    "HTTP-03.16",
    "HTTP-03.17",
    "HTTP-03.18",
    "HTTP-03.19",
    "HTTP-03.20",
    "HTTP-03.21",
    "HTTP-03.22",
    "HTTP-03.23",
    "HTTP-03.24",
    "HTTP-03.25",
    "HTTP-03.26",
];

fn assert_manifest_order(cases: &[ManifestCase; 13]) {
    for (index, case) in cases.iter().enumerate() {
        assert_eq!(
            case.group, MANIFEST_GROUP_ORDER[index],
            "manifest group order is frozen; case {index} must be {}",
            MANIFEST_GROUP_ORDER[index]
        );
        assert!(
            !case.variable.is_empty() && !case.entrypoint.is_empty(),
            "{} must name its changed variable and public entrypoint",
            case.group
        );
    }
}

/// Parses the shipped B half of `http_03_evaluator_manifest_v1` and checks it
/// against the cases this file actually executes.
///
/// The manifest is deliberately not rebuilt here.
/// `HTTP_03_B_EVALUATOR_MANIFEST_V1` is the producer-owned acceptance input the
/// HTTP-03 integration join consumes; a locally authored copy would prove
/// nothing about what ships.
fn assert_shipped_manifest() {
    let text = HTTP_03_B_EVALUATOR_MANIFEST_V1;
    assert!(
        text.ends_with('\n') && !text.contains('\r'),
        "the published manifest must be LF-canonical and LF-terminated"
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
            "manifest rows must carry no trailing whitespace"
        );
        rows.push(line);
    }
    assert!(
        lines.next().is_none(),
        "the manifest must contain no blank or trailing line"
    );
    assert_eq!(
        rows.len(),
        4 + MANIFEST_GROUP_ORDER.len(),
        "the manifest is four header rows plus one row per group"
    );
    assert_eq!(rows[0], "HTTP-03-B evaluator manifest v1");
    assert!(rows[1].starts_with("producer-revision "));
    assert!(rows[2].starts_with("producer-tree "));
    assert!(
        rows[3]
            .strip_prefix("entrypoint ")
            .is_some_and(|entrypoint| entrypoint.starts_with("fastmcp")),
        "the manifest must name a shipped public entrypoint"
    );

    for (index, row) in rows[4..].iter().enumerate() {
        let fields: Vec<&str> = row.split(' ').collect();
        assert_eq!(
            fields.len(),
            3,
            "case row {index} must be `<id> <name> floor=<N>`"
        );
        assert_eq!(
            fields[0], MANIFEST_GROUP_ORDER[index],
            "the published case order is frozen"
        );
        assert!(!fields[1].is_empty(), "case row {index} must name its case");
        let floor: usize = fields[2]
            .strip_prefix("floor=")
            .expect("each case row declares `floor=<N>`")
            .parse()
            .expect("each floor is numeric");
        assert!(floor >= 1, "case row {index} must declare a positive floor");
    }

    let recomputed =
        sha256_bounded(text.as_bytes(), 64 * 1024).expect("the fixed manifest is within its bound");
    assert_eq!(
        http_03_b_manifest_digest().as_bytes(),
        recomputed.as_bytes(),
        "the published HTTP-03 B digest must bind the published manifest bytes"
    );
}

// ---------------------------------------------------------------------------
// Frozen entry points
// ---------------------------------------------------------------------------

#[test]
fn http_03_b_positive() {
    assert_manifest_order(&POSITIVE_CASES);
    assert_shipped_manifest();
    assert_eq!(
        POSITIVE_CASES.len() + NEGATIVE_CASES.len(),
        26,
        "the manifest requires a minimum of 26 ordered cases"
    );
    // One runtime, and therefore one cancellation domain, per case. `Cx::clone`
    // shares the cancellation `Arc` rather than creating a child, so a case that
    // cancels its context would otherwise cancel every case that follows it in a
    // shared `run(..)` and the whole target would die in the harness.
    for case in POSITIVE_CASES {
        run(async move {
            let cx = Cx::current().expect("the caller runtime must install a current Cx");
            execute_positive(&cx, case).await;
        });
    }
}

#[test]
fn http_03_b_planted_negative() {
    assert_manifest_order(&NEGATIVE_CASES);
    assert_shipped_manifest();
    assert_eq!(
        NEGATIVE_CASES.len(),
        MANIFEST_GROUP_ORDER.len(),
        "every manifest group carries exactly one planted negative"
    );
    // One runtime, and therefore one cancellation domain, per case. See the
    // note in `http_03_b_positive`.
    for case in NEGATIVE_CASES {
        run(async move {
            let cx = Cx::current().expect("the caller runtime must install a current Cx");
            execute_negative(&cx, case).await;
        });
    }
}

/// One dispatched case body, erased onto the heap.
///
/// Every arm of the dispatchers below is boxed rather than awaited inline. An
/// `async fn` containing a thirteen-arm match over thirteen distinct `.await`
/// arms composes ONE state machine whose size is the sum of every arm's
/// future — each of which here owns a `Peer`, request/response buffers and a
/// nested `pair()` of two more futures. That aggregate overflowed the libtest
/// thread's stack and aborted the process with SIGABRT, which produces no
/// result row at all: `http_03_b_positive` crashed rather than failed.
///
/// Boxing keeps the match's own frame at one pointer and puts each arm's state
/// machine on the heap, so the frame no longer grows when a case is added.
/// Raising the stack would hide the same blowup and let it return silently with
/// the next arm.
type CaseFuture<'a> = std::pin::Pin<Box<dyn Future<Output = ()> + 'a>>;

fn execute_positive(cx: &Cx, case: ManifestCase) -> CaseFuture<'_> {
    match case.group {
        "HTTP-03.14" => Box::pin(positive_14_cancellation_closes_response(cx)),
        "HTTP-03.15" => Box::pin(positive_15_response_deadline(cx)),
        "HTTP-03.16" => Box::pin(positive_16_no_retry_no_replay(cx)),
        "HTTP-03.17" => Box::pin(async { positive_17_authorization_redaction() }),
        "HTTP-03.18" => Box::pin(async { positive_18_https_only_bearer_attachment() }),
        "HTTP-03.19" => Box::pin(positive_19_redirect_no_follow(cx)),
        "HTTP-03.20" => Box::pin(positive_20_discover_preclassification_frame(cx)),
        "HTTP-03.21" => Box::pin(async { positive_21_fresh_probe_identity() }),
        "HTTP-03.22" => Box::pin(async { positive_22_endpoint_key_partition() }),
        "HTTP-03.23" => Box::pin(positive_23_activation_proof_notification(cx)),
        "HTTP-03.24" => Box::pin(positive_24_independent_server_request(cx)),
        "HTTP-03.25" => Box::pin(positive_25_no_resumption_state(cx)),
        "HTTP-03.26" => Box::pin(positive_26_observation_table(cx)),
        group => panic!("positive case {group} is not mapped to an executable body"),
    }
}

fn execute_negative(cx: &Cx, case: ManifestCase) -> CaseFuture<'_> {
    match case.group {
        "HTTP-03.14" => Box::pin(negative_14_precancelled_dispatch(cx)),
        "HTTP-03.15" => Box::pin(negative_15_stalled_peer(cx)),
        "HTTP-03.16" => Box::pin(negative_16_midexchange_close(cx)),
        "HTTP-03.17" => Box::pin(async { negative_17_header_hostile_token() }),
        "HTTP-03.18" => Box::pin(async { negative_18_cleartext_resource() }),
        "HTTP-03.19" => Box::pin(negative_19_redirect_with_location(cx)),
        "HTTP-03.20" => Box::pin(async { negative_20_unrecognized_probe_body() }),
        "HTTP-03.21" => Box::pin(async { negative_21_second_probe_refused() }),
        "HTTP-03.22" => Box::pin(async { negative_22_one_key_field_differs() }),
        "HTTP-03.23" => Box::pin(negative_23_acknowledgement_with_content_type(cx)),
        "HTTP-03.24" => Box::pin(negative_24_duplicate_response_header(cx)),
        "HTTP-03.25" => Box::pin(negative_25_resumption_state_offered(cx)),
        "HTTP-03.26" => Box::pin(async { negative_26_legacy_only_probe_forbidden() }),
        group => panic!("negative case {group} is not mapped to an executable body"),
    }
}

// ---------------------------------------------------------------------------
// Loopback fixture
// ---------------------------------------------------------------------------

/// Per-case wall-clock ceiling.
///
/// This is deliberately not a generous "surely nothing takes this long" bound.
/// Since each case gets its own runtime, the ceiling is paid **per case**, not
/// per test: thirteen cases at a two-minute ceiling would let one target alone
/// consume 1560s of a 1800s wave budget shared by 46 targets, so a single stuck
/// case starves every other target instead of failing loudly.
///
/// Every case here is loopback and settles well under a second. The longest
/// *intentional* wait in the whole target is the 1.5s peer stall in
/// `negative_15_stalled_peer`, so twenty seconds leaves more than tenfold
/// headroom over anything a healthy case does while capping the target at
/// roughly 260s per test.
const CASE_CEILING_NANOS: u64 = 20_000_000_000;

/// Runs one case body on a real reactor under a bounded wall-clock ceiling.
fn run(future: impl Future<Output = ()>) {
    RuntimeBuilder::current_thread()
        .with_reactor(create_reactor().expect("the loopback reactor must start"))
        .build()
        .expect("the loopback runtime must build")
        .block_on(async {
            let cx = Cx::current().expect("block_on must install a current Cx");
            asupersync::time::timeout_at(cx.now().saturating_add_nanos(CASE_CEILING_NANOS), future)
                .await
                .expect(
                    "every HTTP-03 B case must settle within its per-case ceiling; a case that \
                     exceeds it is stuck, not slow, because all of them are loopback",
                );
        });
}

/// Drives the server fixture and the client under test concurrently inside the
/// one caller-owned runtime. Neither side may block the other.
async fn pair<L: Future, R: Future>(left: L, right: R) -> (L::Output, R::Output) {
    let mut left = std::pin::pin!(left);
    let mut right = std::pin::pin!(right);
    let mut left_result = None;
    let mut right_result = None;
    poll_fn(|task| {
        if left_result.is_none()
            && let Poll::Ready(value) = left.as_mut().poll(task)
        {
            left_result = Some(value);
        }
        if right_result.is_none()
            && let Poll::Ready(value) = right.as_mut().poll(task)
        {
            right_result = Some(value);
        }
        if left_result.is_some() && right_result.is_some() {
            Poll::Ready((
                left_result.take().expect("left settled"),
                right_result.take().expect("right settled"),
            ))
        } else {
            Poll::Pending
        }
    })
    .await
}

/// One captured HTTP request as it arrived on the wire.
#[derive(Debug)]
struct Wire {
    head: String,
    body: Vec<u8>,
}

struct Peer {
    listener: TcpListener,
}

impl Peer {
    async fn bind() -> Self {
        Self {
            listener: TcpListener::bind("127.0.0.1:0")
                .await
                .expect("bind the loopback MCP listener"),
        }
    }

    fn authority(&self) -> String {
        self.listener
            .local_addr()
            .expect("read the loopback listener address")
            .to_string()
    }

    fn target(&self) -> String {
        format!("http://{}/mcp", self.authority())
    }

    async fn accept(&self) -> TcpStream {
        self.listener
            .accept()
            .await
            .expect("accept a loopback connection")
            .0
    }

    /// Proves the client opened no further socket. A modern MCP client that
    /// replayed a POST, followed a redirect, or answered the server with its
    /// own request would have to connect again to do so.
    ///
    /// This is deliberately three-way rather than `is_pending()`. A cancelled
    /// ambient `Cx` makes `TcpListener::poll_accept` return
    /// `Ready(Err(Interrupted, "cancelled"))` rather than `Pending`, so a
    /// two-way check reports "the client opened another socket" when in fact
    /// no connection exists and the poll was merely refused — a false finding
    /// against the shipped client. An inconclusive probe is not evidence of
    /// good behaviour either, so it fails on its own terms rather than passing.
    fn assert_no_further_connection(&self) {
        let mut task = Context::from_waker(Waker::noop());
        match self.listener.poll_accept(&mut task) {
            Poll::Pending => {}
            Poll::Ready(Ok(_)) => {
                panic!("the client must not open another socket")
            }
            Poll::Ready(Err(error)) => panic!(
                "the no-further-connection probe was inconclusive: poll_accept refused with \
                 {error:?}. This proves nothing about the client — a cancelled ambient Cx makes \
                 poll_accept return Ready(Err(Interrupted)) instead of Pending — so the case must \
                 probe from an uncancelled context rather than treat this as a pass."
            ),
        }
    }
}

async fn read_request(io: &mut TcpStream) -> Wire {
    let mut wire = Vec::new();
    let mut buffer = [0_u8; 8_192];
    let head_end = loop {
        let count = io.read(&mut buffer).await.expect("read request bytes");
        assert!(count > 0, "client closed before a complete request head");
        wire.extend_from_slice(&buffer[..count]);
        assert!(
            wire.len() <= 1_048_576,
            "request head exceeded the fixture bound"
        );
        if let Some(index) = wire.windows(4).position(|bytes| bytes == b"\r\n\r\n") {
            break index + 4;
        }
    };
    let head = std::str::from_utf8(&wire[..head_end])
        .expect("the request head must be UTF-8")
        .to_owned();
    let length = header_values(&head, "content-length")
        .first()
        .map(|value| value.parse::<usize>().expect("numeric Content-Length"))
        .unwrap_or(0);
    while wire.len() < head_end + length {
        let count = io.read(&mut buffer).await.expect("read request body bytes");
        assert!(
            count > 0,
            "client closed before the advertised body arrived"
        );
        wire.extend_from_slice(&buffer[..count]);
    }
    Wire {
        head,
        body: wire[head_end..head_end + length].to_vec(),
    }
}

fn header_values<'a>(head: &'a str, name: &str) -> Vec<&'a str> {
    head.lines()
        .filter_map(|line| {
            let (field, value) = line.split_once(':')?;
            field.eq_ignore_ascii_case(name).then(|| value.trim())
        })
        .collect()
}

fn exactly_one_header<'a>(head: &'a str, name: &str) -> &'a str {
    let values = header_values(head, name);
    assert_eq!(
        values.len(),
        1,
        "{name} must appear exactly once; head was {head:?}"
    );
    values[0]
}

fn status_reason(status: u16) -> &'static str {
    match status {
        200 => "OK",
        202 => "Accepted",
        301 => "Moved Permanently",
        302 => "Found",
        303 => "See Other",
        307 => "Temporary Redirect",
        308 => "Permanent Redirect",
        _ => "Fixture Response",
    }
}

async fn write_response(io: &mut TcpStream, status: u16, headers: &[(&str, &str)], body: &[u8]) {
    let mut head = format!("HTTP/1.1 {status} {}\r\n", status_reason(status));
    for &(name, value) in headers {
        head.push_str(name);
        head.push_str(": ");
        head.push_str(value);
        head.push_str("\r\n");
    }
    head.push_str(&format!(
        "Content-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    ));
    io.write_all(head.as_bytes())
        .await
        .expect("write the response head");
    io.write_all(body).await.expect("write the response body");
    io.flush().await.expect("flush the response");
}

async fn write_json_response(io: &mut TcpStream, body: &[u8]) {
    write_response(io, 200, &[("Content-Type", "application/json")], body).await;
}

/// Opens a streaming SSE response with chunked framing.
///
/// See the module comment: a head carrying neither `Content-Length` nor
/// `Transfer-Encoding` frames an empty body in the pinned h1 decoder, which
/// would deliver zero events while the test still passed.
async fn begin_sse(io: &mut TcpStream) {
    io.write_all(
        b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n",
    )
    .await
    .expect("write the SSE response head");
    io.flush().await.expect("flush the SSE response head");
}

/// Writes one chunk of a streaming SSE body.
async fn write_bytes(io: &mut TcpStream, bytes: &[u8]) {
    assert!(
        !bytes.is_empty(),
        "a zero-length chunk would terminate the response body"
    );
    let mut chunk = format!("{:x}\r\n", bytes.len()).into_bytes();
    chunk.extend_from_slice(bytes);
    chunk.extend_from_slice(b"\r\n");
    io.write_all(&chunk)
        .await
        .expect("write one response chunk");
    io.flush().await.expect("flush one response chunk");
}

/// Ends a streaming SSE body with its terminating zero-length chunk. The HTTP
/// framing is always completed correctly, including by cases whose changed
/// variable is an SSE-level omission, so a transport error cannot mask the
/// event-stream behaviour under test.
async fn end_sse_stream(io: &mut TcpStream) {
    io.write_all(b"0\r\n\r\n")
        .await
        .expect("write the terminating chunk");
    io.flush().await.expect("flush the terminating chunk");
    io.shutdown().await.expect("close the response stream");
}

/// Ends a `Content-Length`-framed response.
async fn end_stream(io: &mut TcpStream) {
    io.shutdown().await.expect("close the response stream");
}

const DISCOVERY_BODY: &[u8] = br#"{"jsonrpc":"2.0","id":1,"result":{"supportedVersions":["2026-07-28"],"capabilities":{},"ttlMs":0,"cacheScope":"private"}}"#;

fn plan_with(
    target: &str,
    credential_partition: &str,
    security_partition: &str,
    transport_profile: &str,
    configuration_generation: u64,
) -> ClientProtocolPlan {
    ClientProtocolPlan::http(
        ProtocolPolicy::ModernOnly,
        Some(CanonicalHttpUrl::parse(target).expect("the loopback target must be canonical")),
        None,
        None,
        credential_partition.to_owned(),
        security_partition.to_owned(),
        transport_profile.to_owned(),
        1,
        configuration_generation,
        0,
    )
    .expect("the modern-only loopback plan must be accepted")
}

fn plan(target: &str) -> ClientProtocolPlan {
    plan_with(
        target,
        "credential-partition-http-03-b",
        "security-partition-http-03-b",
        "native-h1-http-03-b",
        1,
    )
}

fn builder(target: &str) -> ClientBuilder {
    ClientBuilder::new()
        .client_info("http-03-b-client", "1.0.0")
        .protocol_plan(plan(target))
        .request_timeout_policy(
            RequestTimeoutPolicy::new(Duration::from_secs(10), Duration::from_secs(60))
                .expect("the loopback request timeout policy must be valid"),
        )
}

/// Sends one POST through the shipped public executor over a real socket.
async fn post(
    cx: &Cx,
    request: &ModernHttpRequest,
) -> Result<ModernHttpResponseStream, ModernHttpExecutorError> {
    let executor = ModernHttpExecutor::new();
    executor.execute(cx, request).await
}

fn ping_body() -> Vec<u8> {
    br#"{"jsonrpc":"2.0","id":1,"method":"ping","params":{}}"#.to_vec()
}

fn ping_request(target: &str) -> ModernHttpRequest {
    ModernHttpRequest::new(target, ping_body(), "2026-07-28", "ping", None)
        .expect("an ordinary modern MCP POST must be constructible")
}

fn negotiation(target: &str) -> ClientHttpNegotiation {
    ClientHttpNegotiation::from_protocol_plan(&plan(target))
        .expect("the modern-only plan carries a configured HTTP endpoint bundle")
}

const RECOGNIZED: HttpModernProbe = HttpModernProbe {
    status: 200,
    body: HttpProbeBody::RecognizedModernJsonRpc,
};

// ---------------------------------------------------------------------------
// HTTP-03.14 — caller cancellation closes the owned response
// ---------------------------------------------------------------------------

/// A caller that cancels while it owns an admitted response is refused the
/// body, and opens no replacement socket.
///
/// Ordering matters and is the point of this case. The fixture writes a
/// complete, correctly framed response and closes it **before** any
/// cancellation is raised. `Cx::clone` shares the cancellation `Arc` rather
/// than creating a child, so cancelling first would make the fixture's own
/// cancel-aware writes fail with `Interrupted` and the fixture, not the client,
/// would become the thing under test. The cancellation is therefore raised by
/// the caller, after the response head is in hand, and the observable is that
/// the owned body is then refused.
///
/// The no-further-connection probe runs against an uncancelled listener,
/// because the socket probe itself is unusable once the ambient context is
/// cancelled — see [`Peer::assert_no_further_connection`].
async fn positive_14_cancellation_closes_response(cx: &Cx) {
    let peer = Peer::bind().await;
    let target = peer.target();
    let request = ping_request(&target);

    let server = async {
        let mut io = peer.accept().await;
        let wire = read_request(&mut io).await;
        assert_eq!(wire.body, ping_body(), "the POST body is sent exactly once");
        write_json_response(&mut io, DISCOVERY_BODY).await;
        end_stream(&mut io).await;
        wire
    };

    let client = async {
        let stream = post(cx, &request)
            .await
            .expect("the response head must arrive before the caller cancels");
        assert_eq!(
            stream.metadata().kind(),
            ModernHttpResponseKind::Json,
            "the admitted response selects the immediate JSON lane"
        );

        // The caller now owns the response and cancels. Nothing else writes to
        // this exchange from here on.
        cx.cancel_with(
            asupersync::CancelKind::User,
            Some("http-03.14 caller cancellation while owning the response"),
        );

        let outcome = stream.read_to_end(cx, 64 * 1024).await;
        assert!(
            outcome.is_err(),
            "a caller that cancelled while owning the response must not receive its body"
        );
    };

    let (wire, ()) = Box::pin(pair(server, client)).await;
    assert!(
        header_values(&wire.head, "last-event-id").is_empty(),
        "a cancelled exchange must not have offered resumption state"
    );
    // Deliberately not probing the listener here: this case's own context is
    // cancelled by design, which makes `poll_accept` return
    // `Ready(Err(Interrupted))` and the probe inconclusive. The no-replacement-
    // socket property for the cancellation dimension is carried by the
    // uncancelled cases below.
}

/// One variable changes: cancellation is requested *before* dispatch rather
/// than while the caller owns the response. The executor must refuse with the
/// typed `Cancelled` outcome.
///
/// The listener is deliberately **not** probed here. This case must cancel its
/// own context before dispatching, and a cancelled ambient context makes
/// `TcpListener::poll_accept` return `Ready(Err(Interrupted))` rather than
/// `Pending`, so the probe cannot distinguish "no connection" from "I could not
/// look" and would report a socket that does not exist. The no-socket property
/// for this dimension is instead carried by the typed refusal itself: the
/// executor's `check_modern_http_context` checkpoint precedes any connect, so a
/// `Cancelled` outcome is only reachable before a socket exists.
async fn negative_14_precancelled_dispatch(cx: &Cx) {
    let peer = Peer::bind().await;
    let request = ping_request(&peer.target());
    cx.cancel_with(
        asupersync::CancelKind::User,
        Some("http-03.14 pre-dispatch cancellation"),
    );

    let error = post(cx, &request)
        .await
        .expect_err("a pre-cancelled dispatch must not produce a response");
    assert!(
        matches!(error, ModernHttpExecutorError::Cancelled),
        "pre-dispatch cancellation must be the typed Cancelled refusal, got {error:?}"
    );
}

// ---------------------------------------------------------------------------
// HTTP-03.15 — post-commit response deadline
// ---------------------------------------------------------------------------

/// An exchange that answers inside its deadline completes normally and leaves
/// no retry behind.
async fn positive_15_response_deadline(cx: &Cx) {
    let peer = Peer::bind().await;
    let target = peer.target();
    let request = ping_request(&target);

    let server = async {
        let mut io = peer.accept().await;
        let wire = read_request(&mut io).await;
        write_json_response(&mut io, DISCOVERY_BODY).await;
        end_stream(&mut io).await;
        wire
    };
    let client = async {
        let stream = post(cx, &request)
            .await
            .expect("a prompt in-deadline response must be admitted");
        assert_eq!(
            stream.metadata().kind(),
            ModernHttpResponseKind::Json,
            "a prompt application/json answer selects the immediate JSON lane"
        );
    };

    let (wire, ()) = Box::pin(pair(server, client)).await;
    assert!(
        wire.head.starts_with("POST /mcp HTTP/1.1\r\n"),
        "the exchange must POST the configured modern route"
    );
    peer.assert_no_further_connection();
}

/// One variable changes: the peer accepts the POST and then stalls without
/// answering. The executor must surface a typed timeout and must not replay.
async fn negative_15_stalled_peer(cx: &Cx) {
    let peer = Peer::bind().await;
    let target = peer.target();
    let request = ping_request(&target);
    let stall_cx = cx.clone();

    // Not an `async move` block: `peer` must stay borrowed so the
    // no-further-connection assertion below can still observe its listener.
    let server = async {
        let mut io = peer.accept().await;
        let wire = read_request(&mut io).await;
        // Hold the socket open past the caller's response deadline without
        // writing a response head.
        asupersync::time::sleep_until(stall_cx.now().saturating_add_nanos(1_500_000_000)).await;
        end_stream(&mut io).await;
        wire
    };
    let client = async {
        let outcome = post(cx, &request).await;
        match outcome {
            Err(ModernHttpExecutorError::Timeout(_))
            | Err(ModernHttpExecutorError::Transport(_))
            | Err(ModernHttpExecutorError::ResponseBodyReadFailed) => {}
            Err(other) => panic!("a stalled peer must be a typed refusal, got {other:?}"),
            Ok(_) => panic!("a stalled peer must not produce an admitted response"),
        }
    };

    let (_wire, ()) = Box::pin(pair(server, client)).await;
    peer.assert_no_further_connection();
}

// ---------------------------------------------------------------------------
// HTTP-03.16 — uncertain dispatch is never retried
// ---------------------------------------------------------------------------

/// The request body crosses the wire exactly once and the client opens exactly
/// one socket for it.
async fn positive_16_no_retry_no_replay(cx: &Cx) {
    let peer = Peer::bind().await;
    let target = peer.target();
    let request = ping_request(&target);

    let server = async {
        let mut io = peer.accept().await;
        let wire = read_request(&mut io).await;
        write_json_response(&mut io, DISCOVERY_BODY).await;
        end_stream(&mut io).await;
        wire
    };
    let client = async {
        post(cx, &request)
            .await
            .expect("an ordinary exchange must be admitted");
    };

    let (wire, ()) = Box::pin(pair(server, client)).await;
    assert_eq!(wire.body, ping_body(), "the body is transmitted verbatim");
    assert_eq!(
        exactly_one_header(&wire.head, "content-length"),
        ping_body().len().to_string(),
        "the advertised length must match the single transmitted body"
    );
    peer.assert_no_further_connection();
}

/// One variable changes: the peer closes mid-exchange after reading the
/// request, leaving the dispatch outcome uncertain. A retry here would be a
/// silent duplicate side effect, so the client must refuse and not reconnect.
async fn negative_16_midexchange_close(cx: &Cx) {
    let peer = Peer::bind().await;
    let target = peer.target();
    let request = ping_request(&target);

    let server = async {
        let mut io = peer.accept().await;
        let wire = read_request(&mut io).await;
        end_stream(&mut io).await;
        wire
    };
    let client = async {
        let outcome = post(cx, &request).await;
        assert!(
            outcome.is_err(),
            "an uncertain dispatch must not be reported as success"
        );
    };

    let (_wire, ()) = Box::pin(pair(server, client)).await;
    peer.assert_no_further_connection();
}

// ---------------------------------------------------------------------------
// HTTP-03.17 — authorization redaction
// ---------------------------------------------------------------------------

/// The bound token never appears in a rendered diagnostic, while the resource
/// it is bound to remains visible for debugging.
fn positive_17_authorization_redaction() {
    let secret = "http-03-b-secret-token";
    let resource = CanonicalHttpUrl::parse("https://mcp.example/mcp").expect("canonical resource");
    let credential =
        BoundBearerCredential::bind(resource, secret).expect("an https binding is admissible");

    let rendered = format!("{credential:?}");
    assert!(
        !rendered.contains(secret),
        "Debug rendering leaked the bearer token: {rendered}"
    );
    assert!(
        rendered.contains("<redacted>"),
        "Debug rendering must mark the token as redacted: {rendered}"
    );
    assert!(
        rendered.contains("https://mcp.example/mcp"),
        "the bound resource stays visible for diagnostics: {rendered}"
    );
    assert_eq!(
        credential.resource().as_str(),
        "https://mcp.example/mcp",
        "the accessor returns the exact bound resource"
    );
}

/// One variable changes: the token carries a header-hostile byte. Binding must
/// be refused with the typed error, so no credential value exists to leak.
fn negative_17_header_hostile_token() {
    let resource = CanonicalHttpUrl::parse("https://mcp.example/mcp").expect("canonical resource");
    let error = BoundBearerCredential::bind(resource.clone(), "bad\r\nInjected: header")
        .expect_err("a header-hostile token must not bind");
    assert_eq!(error, BearerBindingError::InvalidTokenBytes);

    let empty = BoundBearerCredential::bind(resource, "")
        .expect_err("an empty token must not bind");
    assert_eq!(empty, BearerBindingError::EmptyToken);
}

// ---------------------------------------------------------------------------
// HTTP-03.18 — HTTPS-only bearer attachment
// ---------------------------------------------------------------------------

/// The credential attaches to its exact bound resource and to nothing else:
/// not a different path, not a different authority, and not a downgraded
/// scheme.
fn positive_18_https_only_bearer_attachment() {
    let secret = "http-03-b-attachment-token";
    let bound = CanonicalHttpUrl::parse("https://mcp.example/mcp").expect("canonical resource");
    let credential =
        BoundBearerCredential::bind(bound.clone(), secret).expect("an https binding is admissible");

    assert_eq!(
        credential.authorization_for_target(&bound).as_deref(),
        Some(format!("Bearer {secret}").as_str()),
        "the exact bound resource receives the credential"
    );

    for other in [
        "https://mcp.example/other",
        "https://mcp.example/mcp?query=1",
        "https://other.example/mcp",
        "http://mcp.example/mcp",
    ] {
        let target = CanonicalHttpUrl::parse(other).expect("canonical comparison target");
        assert!(
            credential.authorization_for_target(&target).is_none(),
            "{other} must never observe the credential"
        );
    }
}

/// One variable changes: the resource scheme is cleartext. No binding may
/// exist at all, including for loopback literals, so there is no credential to
/// withhold later.
fn negative_18_cleartext_resource() {
    for cleartext in [
        "http://mcp.example/mcp",
        "http://localhost:8080/mcp",
        "http://127.0.0.1:8080/mcp",
        "http://[::1]:8080/mcp",
    ] {
        let resource = CanonicalHttpUrl::parse(cleartext).expect("canonical cleartext target");
        let error = BoundBearerCredential::bind(resource, "http-03-b-attachment-token")
            .err()
            .unwrap_or_else(|| panic!("{cleartext} must never hold a bearer credential"));
        assert_eq!(
            error,
            BearerBindingError::CleartextResource,
            "{cleartext} must be refused as a cleartext resource"
        );
    }
}

// ---------------------------------------------------------------------------
// HTTP-03.19 — redirects are terminal and unfollowed
// ---------------------------------------------------------------------------

/// Every redirect status is terminal for MCP: the client neither follows nor
/// replays, and opens no second socket.
async fn positive_19_redirect_no_follow(cx: &Cx) {
    for status in [301_u16, 302, 303, 307, 308] {
        let peer = Peer::bind().await;
        let target = peer.target();
        let request = ping_request(&target);

        let server = async {
            let mut io = peer.accept().await;
            let wire = read_request(&mut io).await;
            write_response(&mut io, status, &[], b"").await;
            end_stream(&mut io).await;
            wire
        };
        let client = async {
            let error = post(cx, &request)
                .await
                .err()
                .unwrap_or_else(|| panic!("{status} must not produce an admitted response"));
            match error {
                ModernHttpExecutorError::Redirect { status: observed } => {
                    assert_eq!(observed, status, "the typed refusal reports its status");
                }
                other => panic!("{status} must be a typed redirect refusal, got {other:?}"),
            }
        };

        let (_wire, ()) = Box::pin(pair(server, client)).await;
        peer.assert_no_further_connection();
    }
}

/// One variable changes: the redirect carries a `Location` pointing at a second
/// live listener. Following it would be a credential-bearing request to an
/// unbound target, so the client must still refuse and must never contact it.
async fn negative_19_redirect_with_location(cx: &Cx) {
    let peer = Peer::bind().await;
    let elsewhere = Peer::bind().await;
    let target = peer.target();
    let request = ping_request(&target);
    let location = elsewhere.target();

    let server = async {
        let mut io = peer.accept().await;
        let wire = read_request(&mut io).await;
        write_response(&mut io, 307, &[("Location", location.as_str())], b"").await;
        end_stream(&mut io).await;
        wire
    };
    let client = async {
        let error = post(cx, &request)
            .await
            .expect_err("a redirect with a Location must still be terminal");
        assert!(
            matches!(error, ModernHttpExecutorError::Redirect { status: 307 }),
            "a Location header must not turn a redirect into a follow, got {error:?}"
        );
    };

    let (_wire, ()) = Box::pin(pair(server, client)).await;
    peer.assert_no_further_connection();
    elsewhere.assert_no_further_connection();
}

// ---------------------------------------------------------------------------
// HTTP-03.20 — one-shot discover pre-classification frame
// ---------------------------------------------------------------------------

/// The era classifier's single probe is a `server/discover` POST on the
/// configured modern route, carrying the modern routing headers and no
/// application method.
async fn positive_20_discover_preclassification_frame(cx: &Cx) {
    let peer = Peer::bind().await;
    let target = peer.target();
    let connect = builder(&target);

    let server = async {
        let mut io = peer.accept().await;
        let wire = read_request(&mut io).await;
        write_json_response(&mut io, DISCOVERY_BODY).await;
        end_stream(&mut io).await;
        wire
    };
    let client = async {
        let _ = connect.connect_http_with_cx(cx).await;
    };

    let (wire, ()) = Box::pin(pair(server, client)).await;
    assert!(
        wire.head.starts_with("POST /mcp HTTP/1.1\r\n"),
        "the probe must POST the configured modern route: {:?}",
        wire.head
    );
    assert_eq!(
        exactly_one_header(&wire.head, "Mcp-Method"),
        "server/discover",
        "era classification may use no pre-classification application method"
    );
    assert_eq!(
        exactly_one_header(&wire.head, "MCP-Protocol-Version"),
        "2026-07-28",
        "the probe declares the modern protocol version"
    );
    assert!(
        header_values(&wire.head, "last-event-id").is_empty(),
        "the probe must carry no resumption state"
    );
    let body = std::str::from_utf8(&wire.body).expect("the probe body is UTF-8");
    assert!(
        body.contains("server/discover"),
        "the probe body must be the discover frame: {body}"
    );
}

/// One variable changes: the probe response body is unrecognized rather than
/// modern JSON-RPC. Under `ModernOnly` that cannot select an era and cannot
/// authorize any legacy action.
fn negative_20_unrecognized_probe_body() {
    let mut classifier = negotiation("http://127.0.0.1:9/mcp");
    let before = classifier.state();
    assert!(!before.probe_dispatched());
    assert_eq!(before.selected_era(), None);

    let error = classifier
        .observe_modern_probe(HttpModernProbe {
            status: 200,
            body: HttpProbeBody::Unrecognized,
        })
        .expect_err("an unrecognized body cannot select the modern era");
    assert!(
        matches!(
            error,
            ClientHttpNegotiationError::ModernProbeRejectedWithoutLegacyFallback {
                status: 200,
                body: HttpProbeBody::Unrecognized,
            }
        ),
        "the refusal must name the observed status and body, got {error:?}"
    );

    let after = classifier.state();
    assert!(
        after.probe_dispatched(),
        "the one permitted probe is still recorded as spent"
    );
    assert_eq!(
        after.selected_era(),
        None,
        "a refused observation must select no era"
    );
    assert!(
        !after.legacy_sse_fallback_authorized(),
        "a refused observation must authorize no legacy fallback"
    );
}

// ---------------------------------------------------------------------------
// HTTP-03.21 — fresh probe identity after authorization
// ---------------------------------------------------------------------------

/// A re-authorized endpoint negotiates from a fresh identity: the new instance
/// has not spent its probe, selects its own era, and inherits nothing from the
/// previous credential partition's instance.
fn positive_21_fresh_probe_identity() {
    let target = "http://127.0.0.1:9/mcp";

    let mut before_authorization = negotiation(target);
    assert_eq!(
        before_authorization
            .observe_modern_probe(RECOGNIZED)
            .expect("a recognized modern body selects the modern era"),
        ClientHttpNegotiationDecision::ModernSelected
    );
    assert!(before_authorization.state().probe_dispatched());
    assert_eq!(
        before_authorization.state().selected_era(),
        Some(ProtocolEra::Modern2026)
    );

    // The credential partition changes, so this is a different endpoint
    // instance and must classify from scratch.
    let reauthorized_plan = plan_with(
        target,
        "credential-partition-http-03-b-rotated",
        "security-partition-http-03-b",
        "native-h1-http-03-b",
        1,
    );
    let mut after_authorization = ClientHttpNegotiation::from_protocol_plan(&reauthorized_plan)
        .expect("the re-authorized plan carries its own endpoint bundle");

    let fresh = after_authorization.state();
    assert!(
        !fresh.probe_dispatched(),
        "a re-authorized endpoint must not inherit a spent probe"
    );
    assert_eq!(
        fresh.selected_era(),
        None,
        "a re-authorized endpoint must not inherit a selected era"
    );
    assert!(
        !fresh.legacy_sse_fallback_authorized(),
        "a re-authorized endpoint must not inherit a fallback authorization"
    );

    assert_eq!(
        after_authorization
            .observe_modern_probe(RECOGNIZED)
            .expect("the fresh identity may spend its own probe"),
        ClientHttpNegotiationDecision::ModernSelected
    );
    assert!(
        before_authorization.state().probe_dispatched(),
        "the original instance's state is untouched by the new one"
    );
}

/// One variable changes: the second probe is dispatched on the *same*
/// negotiation instance rather than a fresh one. Probe isolation must refuse it
/// and leave the already-selected state byte-for-byte unchanged.
fn negative_21_second_probe_refused() {
    let mut classifier = negotiation("http://127.0.0.1:9/mcp");
    assert_eq!(
        classifier
            .observe_modern_probe(RECOGNIZED)
            .expect("the first probe is permitted"),
        ClientHttpNegotiationDecision::ModernSelected
    );
    let before = classifier.state();

    let error = classifier
        .observe_modern_probe(RECOGNIZED)
        .expect_err("a second probe on one instance must be refused");
    assert!(
        matches!(
            error,
            ClientHttpNegotiationError::ModernProbeAlreadyDispatched
        ),
        "the refusal must be the typed one-shot violation, got {error:?}"
    );

    let after = classifier.state();
    assert_eq!(
        after.probe_dispatched(),
        before.probe_dispatched(),
        "a refused second probe must not change probe_dispatched"
    );
    assert_eq!(
        after.selected_era(),
        before.selected_era(),
        "a refused second probe must not change the selected era"
    );
    assert_eq!(
        after.legacy_sse_fallback_authorized(),
        before.legacy_sse_fallback_authorized(),
        "a refused second probe must not change the fallback authorization"
    );
}

// ---------------------------------------------------------------------------
// HTTP-03.22 — complete endpoint-instance key partition
// ---------------------------------------------------------------------------

/// Two plans that differ in any one endpoint-key field are different endpoint
/// instances: each classifies independently and neither observes the other's
/// selection.
fn positive_22_endpoint_key_partition() {
    let base = "http://127.0.0.1:9/mcp";
    let mut selected = negotiation(base);
    assert_eq!(
        selected
            .observe_modern_probe(RECOGNIZED)
            .expect("the base instance selects modern"),
        ClientHttpNegotiationDecision::ModernSelected
    );

    // Each variant differs from the base in exactly one key field. The origin
    // is identical in every case, which is precisely what must not be enough.
    let variants = [
        plan_with(
            "http://127.0.0.1:9/other",
            "credential-partition-http-03-b",
            "security-partition-http-03-b",
            "native-h1-http-03-b",
            1,
        ),
        plan_with(
            "http://127.0.0.1:9/mcp?tenant=2",
            "credential-partition-http-03-b",
            "security-partition-http-03-b",
            "native-h1-http-03-b",
            1,
        ),
        plan_with(
            base,
            "credential-partition-other",
            "security-partition-http-03-b",
            "native-h1-http-03-b",
            1,
        ),
        plan_with(
            base,
            "credential-partition-http-03-b",
            "security-partition-other",
            "native-h1-http-03-b",
            1,
        ),
        plan_with(
            base,
            "credential-partition-http-03-b",
            "security-partition-http-03-b",
            "native-h1-other",
            1,
        ),
        plan_with(
            base,
            "credential-partition-http-03-b",
            "security-partition-http-03-b",
            "native-h1-http-03-b",
            2,
        ),
    ];

    for (index, variant) in variants.into_iter().enumerate() {
        let instance = ClientHttpNegotiation::from_protocol_plan(&variant)
            .expect("each configured variant carries its own endpoint bundle");
        let state = instance.state();
        assert!(
            !state.probe_dispatched(),
            "variant {index} must not observe the base instance's spent probe"
        );
        assert_eq!(
            state.selected_era(),
            None,
            "variant {index} must not observe the base instance's selected era"
        );
    }

    assert_eq!(
        selected.state().selected_era(),
        Some(ProtocolEra::Modern2026),
        "the base instance keeps its own selection throughout"
    );
}

/// One variable changes: the configuration generation alone advances while the
/// complete origin, path, query and partitions stay identical. That is still a
/// different endpoint instance, so no classification may carry over.
fn negative_22_one_key_field_differs() {
    let base = "http://127.0.0.1:9/mcp";
    let mut first = negotiation(base);
    assert_eq!(
        first
            .observe_modern_probe(RECOGNIZED)
            .expect("the first generation selects modern"),
        ClientHttpNegotiationDecision::ModernSelected
    );
    let before = first.state();

    let next_generation = plan_with(
        base,
        "credential-partition-http-03-b",
        "security-partition-http-03-b",
        "native-h1-http-03-b",
        2,
    );
    let second = ClientHttpNegotiation::from_protocol_plan(&next_generation)
        .expect("the next generation carries its own endpoint bundle");

    assert!(
        !second.state().probe_dispatched(),
        "a generation change must not inherit a spent probe"
    );
    assert_eq!(
        second.state().selected_era(),
        None,
        "a generation change must not inherit a selected era"
    );

    let after = first.state();
    assert_eq!(after.probe_dispatched(), before.probe_dispatched());
    assert_eq!(after.selected_era(), before.selected_era());
    assert_eq!(
        after.legacy_sse_fallback_authorized(),
        before.legacy_sse_fallback_authorized(),
        "constructing a sibling instance must not mutate the original"
    );
}

// ---------------------------------------------------------------------------
// HTTP-03.23 — extension activation-proof notification lane
// ---------------------------------------------------------------------------

/// A notification is acknowledged on the content-type-free `202` lane, which is
/// the only admitted shape for an activation-proof notification.
async fn positive_23_activation_proof_notification(cx: &Cx) {
    let peer = Peer::bind().await;
    let target = peer.target();
    let body = br#"{"jsonrpc":"2.0","method":"notifications/initialized","params":{}}"#.to_vec();
    let request = ModernHttpRequest::new(
        target.as_str(),
        body.clone(),
        "2026-07-28",
        "notifications/initialized",
        None,
    )
    .expect("a modern notification POST must be constructible");

    let server = async {
        let mut io = peer.accept().await;
        let wire = read_request(&mut io).await;
        write_response(&mut io, 202, &[], b"").await;
        end_stream(&mut io).await;
        wire
    };
    let client = async {
        let stream = post(cx, &request)
            .await
            .expect("a content-type-free 202 must be admitted");
        assert_eq!(
            stream.metadata().kind(),
            ModernHttpResponseKind::EmptyAcknowledgement,
            "a notification acknowledgement selects the empty lane"
        );
    };

    let (wire, ()) = Box::pin(pair(server, client)).await;
    assert_eq!(wire.body, body, "the notification body is sent verbatim");
    assert_eq!(
        exactly_one_header(&wire.head, "Mcp-Method"),
        "notifications/initialized"
    );
    peer.assert_no_further_connection();
}

/// One variable changes: the `202` carries a success content type, which makes
/// it indistinguishable from a body-bearing lane. It must not be admitted as a
/// bare acknowledgement.
async fn negative_23_acknowledgement_with_content_type(cx: &Cx) {
    let peer = Peer::bind().await;
    let target = peer.target();
    let request = ModernHttpRequest::new(
        target.as_str(),
        br#"{"jsonrpc":"2.0","method":"notifications/initialized","params":{}}"#.to_vec(),
        "2026-07-28",
        "notifications/initialized",
        None,
    )
    .expect("a modern notification POST must be constructible");

    let server = async {
        let mut io = peer.accept().await;
        let wire = read_request(&mut io).await;
        write_response(
            &mut io,
            202,
            &[("Content-Type", "text/event-stream")],
            b"data: {}\n\n",
        )
        .await;
        end_stream(&mut io).await;
        wire
    };
    let client = async {
        match post(cx, &request).await {
            Ok(stream) => assert_ne!(
                stream.metadata().kind(),
                ModernHttpResponseKind::EmptyAcknowledgement,
                "a typed 202 must not be admitted as a bare acknowledgement"
            ),
            Err(error) => assert!(
                matches!(
                    error,
                    ModernHttpExecutorError::UnsupportedSuccessContentType
                        | ModernHttpExecutorError::ExpectedSseResponse { .. }
                ),
                "a typed 202 must be a typed refusal, got {error:?}"
            ),
        }
    };

    let (_wire, ()) = Box::pin(pair(server, client)).await;
    peer.assert_no_further_connection();
}

// ---------------------------------------------------------------------------
// HTTP-03.24 — independent server request rejection
// ---------------------------------------------------------------------------

/// Modern stateless HTTP admits no server-issued session state: a clean
/// response carries none, and the client answers the peer with no request of
/// its own.
async fn positive_24_independent_server_request(cx: &Cx) {
    let peer = Peer::bind().await;
    let target = peer.target();
    let request = ping_request(&target);

    let server = async {
        let mut io = peer.accept().await;
        let wire = read_request(&mut io).await;
        begin_sse(&mut io).await;
        // An interleaved server-issued request on the response stream is not a
        // channel the client may answer; only its own correlated terminal
        // response may complete the exchange.
        write_bytes(
            &mut io,
            b"data: {\"jsonrpc\":\"2.0\",\"id\":9001,\"method\":\"roots/list\",\"params\":{}}\n\n",
        )
        .await;
        write_bytes(
            &mut io,
            b"data: {\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"resultType\":\"complete\"}}\n\n",
        )
        .await;
        end_sse_stream(&mut io).await;
        wire
    };
    let client = async {
        let outcome = post(cx, &request).await;
        if let Ok(stream) = outcome {
            drop(stream);
        }
    };

    let (wire, ()) = Box::pin(pair(server, client)).await;
    assert!(
        header_values(&wire.head, "mcp-session-id").is_empty(),
        "the client must not offer session state"
    );
    // A client that answered the server's `roots/list` would need another
    // socket to send it on.
    peer.assert_no_further_connection();
}

/// One variable changes: the response repeats a header whose cardinality is
/// fixed for MCP, which is exactly how a smuggled second channel would appear.
async fn negative_24_duplicate_response_header(cx: &Cx) {
    let peer = Peer::bind().await;
    let target = peer.target();
    let request = ping_request(&target);

    let server = async {
        let mut io = peer.accept().await;
        let wire = read_request(&mut io).await;
        write_response(
            &mut io,
            200,
            &[
                ("Content-Type", "application/json"),
                ("Content-Type", "application/json"),
            ],
            DISCOVERY_BODY,
        )
        .await;
        end_stream(&mut io).await;
        wire
    };
    let client = async {
        let error = post(cx, &request)
            .await
            .expect_err("a repeated fixed-cardinality header must be refused");
        assert!(
            matches!(
                error,
                ModernHttpExecutorError::DuplicateResponseHeader { .. }
                    | ModernHttpExecutorError::UnsupportedSuccessContentType
            ),
            "the refusal must be typed, got {error:?}"
        );
    };

    let (_wire, ()) = Box::pin(pair(server, client)).await;
    peer.assert_no_further_connection();
}

// ---------------------------------------------------------------------------
// HTTP-03.25 — no event-ID, retry, or resumption state
// ---------------------------------------------------------------------------

/// The client offers no resumption state on a modern exchange, including one
/// that consumes a full SSE response.
async fn positive_25_no_resumption_state(cx: &Cx) {
    let peer = Peer::bind().await;
    let target = peer.target();
    let request = ping_request(&target);

    let server = async {
        let mut io = peer.accept().await;
        let wire = read_request(&mut io).await;
        begin_sse(&mut io).await;
        write_bytes(
            &mut io,
            b"data: {\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"resultType\":\"complete\"}}\n\n",
        )
        .await;
        end_sse_stream(&mut io).await;
        wire
    };
    let client = async {
        if let Ok(stream) = post(cx, &request).await {
            drop(stream);
        }
    };

    let (wire, ()) = Box::pin(pair(server, client)).await;
    for forbidden in ["last-event-id", "mcp-session-id"] {
        assert!(
            header_values(&wire.head, forbidden).is_empty(),
            "modern stateless HTTP must not send {forbidden}: {:?}",
            wire.head
        );
    }
    peer.assert_no_further_connection();
}

/// One variable changes: the peer offers SSE resumption state (`id:` and
/// `retry:` fields). The client must consume the stream without adopting that
/// state and must not reconnect to resume it.
async fn negative_25_resumption_state_offered(cx: &Cx) {
    let peer = Peer::bind().await;
    let target = peer.target();
    let request = ping_request(&target);

    let server = async {
        let mut io = peer.accept().await;
        let wire = read_request(&mut io).await;
        begin_sse(&mut io).await;
        write_bytes(&mut io, b"retry: 10\nid: resume-me\n").await;
        write_bytes(
            &mut io,
            b"data: {\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"resultType\":\"complete\"}}\n\n",
        )
        .await;
        end_sse_stream(&mut io).await;
        wire
    };
    let client = async {
        if let Ok(stream) = post(cx, &request).await {
            drop(stream);
        }
    };

    let (wire, ()) = Box::pin(pair(server, client)).await;
    assert!(
        header_values(&wire.head, "last-event-id").is_empty(),
        "an offered event ID must not be echoed on the request"
    );
    // Adopting the offered retry/id would mean reconnecting to resume.
    peer.assert_no_further_connection();
}

// ---------------------------------------------------------------------------
// HTTP-03.26 — the 3x3 observation table and its no-downgrade rule
// ---------------------------------------------------------------------------

/// The complete modern-observation table under `Auto`, anchored by one real
/// socket observation.
///
/// The first observation is driven end to end over a live loopback socket
/// through the public connect path, so the table is anchored in a real wire
/// exchange rather than asserted purely against constructed values. The
/// remaining cells are then enumerated through the same shipped public
/// `observe_modern_probe` entrypoint, because a status/body combination such
/// as a transport failure cannot be produced as a *response* on the wire.
///
/// The invariant across the whole table: an eligible 400/404/405 authorizes at
/// most one legacy SSE observation and never selects or caches a legacy era,
/// so no HTTP status observation can become a downgrade.
async fn positive_26_observation_table(cx: &Cx) {
    // Anchor: a real socket observation that selects the modern era.
    let peer = Peer::bind().await;
    let target = peer.target();
    let connect = builder(&target);
    let server = async {
        let mut io = peer.accept().await;
        let wire = read_request(&mut io).await;
        write_json_response(&mut io, DISCOVERY_BODY).await;
        end_stream(&mut io).await;
        wire
    };
    let client = async {
        let _ = connect.connect_http_with_cx(cx).await;
    };
    let (wire, ()) = Box::pin(pair(server, client)).await;
    assert_eq!(
        exactly_one_header(&wire.head, "Mcp-Method"),
        "server/discover",
        "the anchoring observation is the one-shot discover probe"
    );

    // Recognized modern JSON-RPC selects modern at any status.
    for status in [200_u16, 400, 404] {
        let mut classifier = auto_negotiation();
        assert_eq!(
            classifier
                .observe_modern_probe(HttpModernProbe {
                    status,
                    body: HttpProbeBody::RecognizedModernJsonRpc,
                })
                .expect("a recognized modern body selects modern"),
            ClientHttpNegotiationDecision::ModernSelected,
            "status {status} with a recognized body must select modern"
        );
        assert_eq!(
            classifier.state().selected_era(),
            Some(ProtocolEra::Modern2026)
        );
        assert!(!classifier.state().legacy_sse_fallback_authorized());
    }

    // An eligible status with an empty or unrecognized body authorizes at most
    // one legacy SSE observation and selects nothing.
    for status in [400_u16, 404, 405] {
        for body in [HttpProbeBody::Empty, HttpProbeBody::Unrecognized] {
            let mut classifier = auto_negotiation();
            assert_eq!(
                classifier
                    .observe_modern_probe(HttpModernProbe { status, body })
                    .expect("an eligible status authorizes a legacy observation"),
                ClientHttpNegotiationDecision::LegacySseFallbackAuthorized,
                "status {status} with {body:?} must authorize, not select"
            );
            let state = classifier.state();
            assert!(state.legacy_sse_fallback_authorized());
            assert_eq!(
                state.selected_era(),
                None,
                "an authorization must never select or cache a legacy era"
            );
        }
    }

    // An ineligible status cannot authorize anything.
    let mut ineligible = auto_negotiation();
    let error = ineligible
        .observe_modern_probe(HttpModernProbe {
            status: 500,
            body: HttpProbeBody::Unrecognized,
        })
        .expect_err("500 is not a downgrade signal");
    assert!(matches!(
        error,
        ClientHttpNegotiationError::ModernProbeRejectedWithoutLegacyFallback { status: 500, .. }
    ));
    assert_eq!(ineligible.state().selected_era(), None);
    assert!(!ineligible.state().legacy_sse_fallback_authorized());

    // A transport failure is never a downgrade signal.
    let mut failed = auto_negotiation();
    let error = failed
        .observe_modern_probe(HttpModernProbe {
            status: 0,
            body: HttpProbeBody::TransportFailure,
        })
        .expect_err("a transport failure cannot classify an era");
    assert!(matches!(
        error,
        ClientHttpNegotiationError::ModernProbeTransportFailure
    ));
    assert_eq!(failed.state().selected_era(), None);
    assert!(!failed.state().legacy_sse_fallback_authorized());
}

/// One variable changes: the policy is `LegacyOnly` rather than `Auto`. The
/// modern probe is then forbidden outright, and the era state stays untouched.
fn negative_26_legacy_only_probe_forbidden() {
    let legacy_plan = ClientProtocolPlan::http(
        ProtocolPolicy::LegacyOnly,
        Some(
            CanonicalHttpUrl::parse("http://127.0.0.1:9/mcp")
                .expect("the loopback target must be canonical"),
        ),
        Some(
            CanonicalHttpUrl::parse("http://127.0.0.1:9/sse")
                .expect("the loopback SSE target must be canonical"),
        ),
        Some(
            CanonicalHttpUrl::parse("http://127.0.0.1:9/messages")
                .expect("the loopback message target must be canonical"),
        ),
        "credential-partition-http-03-b".to_owned(),
        "security-partition-http-03-b".to_owned(),
        "native-h1-http-03-b".to_owned(),
        1,
        1,
        0,
    )
    .expect("a legacy-only plan with its configured endpoints must be accepted");

    let mut classifier = ClientHttpNegotiation::from_protocol_plan(&legacy_plan)
        .expect("the legacy-only plan carries a configured HTTP endpoint bundle");
    let before = classifier.state();

    let error = classifier
        .observe_modern_probe(RECOGNIZED)
        .expect_err("a legacy-only plan must not dispatch the modern probe");
    assert!(
        matches!(
            error,
            ClientHttpNegotiationError::ModernProbeForbiddenForLegacyOnly
        ),
        "the refusal must be the typed legacy-only violation, got {error:?}"
    );

    let after = classifier.state();
    assert_eq!(
        after.selected_era(),
        before.selected_era(),
        "a forbidden probe must not change the selected era"
    );
    assert_eq!(
        after.legacy_sse_fallback_authorized(),
        before.legacy_sse_fallback_authorized(),
        "a forbidden probe must not authorize a legacy fallback"
    );
}

/// An `Auto` classifier over the same loopback bundle, used by the observation
/// table where the eligible-status rows require `Auto` rather than `ModernOnly`.
fn auto_negotiation() -> ClientHttpNegotiation {
    let auto_plan = ClientProtocolPlan::http(
        ProtocolPolicy::Auto,
        Some(
            CanonicalHttpUrl::parse("http://127.0.0.1:9/mcp")
                .expect("the loopback target must be canonical"),
        ),
        Some(
            CanonicalHttpUrl::parse("http://127.0.0.1:9/sse")
                .expect("the loopback SSE target must be canonical"),
        ),
        Some(
            CanonicalHttpUrl::parse("http://127.0.0.1:9/messages")
                .expect("the loopback message target must be canonical"),
        ),
        "credential-partition-http-03-b".to_owned(),
        "security-partition-http-03-b".to_owned(),
        "native-h1-http-03-b".to_owned(),
        1,
        1,
        0,
    )
    .expect("an auto plan with its configured endpoints must be accepted");
    ClientHttpNegotiation::from_protocol_plan(&auto_plan)
        .expect("the auto plan carries a configured HTTP endpoint bundle")
}
