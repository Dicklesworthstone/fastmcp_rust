//! HTTP-03 implementation A: the canonical `http_03_evaluator_manifest_v1`
//! groups `HTTP-03.01` through `HTTP-03.13`, each with one positive and one
//! one-variable planted negative, executed in frozen order.
//!
//! Every case drives the shipped public modern client against a real loopback
//! TCP socket. The server side is an ordinary `asupersync::net::TcpListener`
//! speaking raw HTTP/1.1 on `127.0.0.1:0`; the client side is the public
//! `ClientBuilder`/`ClientHttpConnection` surface or the public
//! `ModernHttpExecutor`, both of which open their own sockets through
//! `asupersync`. Nothing here substitutes a fixture parser, an in-memory
//! transport, or a private executor for the wire.
//!
//! The two frozen top-level test IDs, `http_03_a_positive` and
//! `http_03_a_planted_negative`, are the only entry points. The 26 cases hang
//! off the two ordered tables below so the group order, the single changed
//! variable per negative, and the numeric floors are readable from the source.

use std::future::{Future, poll_fn};
use std::task::{Context, Poll, Waker};
use std::time::Duration;

use asupersync::Cx;
use asupersync::io::{AsyncReadExt, AsyncWriteExt};
use asupersync::net::{TcpListener, TcpStream};
use asupersync::runtime::{RuntimeBuilder, reactor::create_reactor};
use fastmcp_client::http_executor::{
    HTTP_03_A_EVALUATOR_MANIFEST_V1, MAX_MODERN_HTTP_PROBE_BODY_BYTES,
    MAX_PENDING_MODERN_HTTP_SSE_EVENT_BYTES, MAX_PENDING_MODERN_HTTP_SSE_EVENTS,
    MAX_QUEUED_FINAL_HTTP_PROGRESS_NOTIFICATIONS, MODERN_MCP_ACCEPT, MODERN_MCP_ACCEPT_ENCODING,
    MODERN_MCP_CONTENT_TYPE, ModernHttpClientError, ModernHttpErrorBodyAdmission,
    ModernHttpExecutor, ModernHttpExecutorError, ModernHttpFinalCoreCollector,
    ModernHttpFinalCoreEvent, ModernHttpFinalCoreListenError, ModernHttpRequest,
    ModernHttpResponseKind, ModernHttpResponseStream, http_03_a_manifest_digest,
};
use fastmcp_client::sse::{SseLimits, SseParseError};
use fastmcp_client::{
    CanonicalHttpUrl, ClientBuilder, ClientHttpConnection, ClientHttpConnectionError,
    ClientHttpNegotiation, ClientHttpNegotiationDecision, ClientHttpNegotiationError,
    ClientProtocolPlan, ProtocolPolicy, RequestTimeoutPolicy,
};
use fastmcp_core::sha256_bounded;
use fastmcp_protocol::protocol_policy::{HttpModernProbe, HttpProbeBody};
use fastmcp_protocol::{JsonRpcAdmissionError, ProgressMarker, RawJsonAdmissionError, RequestId};

// ---------------------------------------------------------------------------
// Frozen manifest: `http_03_evaluator_manifest_v1`
// ---------------------------------------------------------------------------

/// One manifest row. `group` is the canonical group ID, `variable` names the
/// single dimension a negative changes (or the dimension a positive captures),
/// `entrypoint` is the public surface the case drives, and `byte_floor` records the
/// case's numeric floor in bytes (0 when the group has no byte floor).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct ManifestCase {
    group: &'static str,
    variable: &'static str,
    entrypoint: &'static str,
    byte_floor: usize,
}

/// Consecutive non-dispatching SSE lines admitted between dispatched events.
/// The comment-flood positive runs exactly this many; its planted negative runs
/// exactly one more, so the two cannot drift apart.
const KEEPALIVE_CEILING: usize = 8;

/// The thirteen positives, in exact manifest order.
const POSITIVE_CASES: [ManifestCase; 13] = [
    ManifestCase {
        group: "HTTP-03.01",
        variable: "real-socket public-client request construction",
        entrypoint: "ClientBuilder::connect_http_with_cx",
        byte_floor: 1,
    },
    ManifestCase {
        group: "HTTP-03.02",
        variable: "one POST and exact JSON body bytes",
        entrypoint: "ModernHttpExecutor::execute",
        byte_floor: 1,
    },
    ManifestCase {
        group: "HTTP-03.03",
        variable: "exact request Content-Type and two-range Accept",
        entrypoint: "ModernHttpExecutor::execute",
        byte_floor: 2,
    },
    ManifestCase {
        group: "HTTP-03.04",
        variable: "lowercase identity Accept-Encoding and no decompression",
        entrypoint: "ModernHttpExecutor::execute",
        byte_floor: 1,
    },
    ManifestCase {
        group: "HTTP-03.05",
        variable: "protocol/method/name routing headers",
        entrypoint: "ClientHttpConnection::open_final_core_listener",
        byte_floor: 3,
    },
    ManifestCase {
        group: "HTTP-03.06",
        variable: "immediate JSON strict UTF-8 admission",
        entrypoint: "ClientHttpConnection::request_json",
        byte_floor: 1,
    },
    ManifestCase {
        group: "HTTP-03.07",
        variable: "exact response Content-Type selection",
        entrypoint: "ModernHttpExecutor::execute",
        byte_floor: 2,
    },
    ManifestCase {
        group: "HTTP-03.08",
        variable: "streaming SSE replacement decoder and leading-BOM rule",
        entrypoint: "ClientHttpConnection::open_final_core_listener",
        byte_floor: 1,
    },
    ManifestCase {
        group: "HTTP-03.09",
        variable: "CR/LF/CRLF and data-field assembly",
        entrypoint: "ModernHttpResponseStream::into_sse_stream",
        byte_floor: 7,
    },
    ManifestCase {
        group: "HTTP-03.10",
        variable: "comments/empty-data/EOF and inert event/id/retry fields",
        entrypoint: "ClientHttpConnection::open_final_core_listener",
        byte_floor: 1,
    },
    ManifestCase {
        group: "HTTP-03.11",
        variable: "line/event/message and memory bounds",
        entrypoint: "ModernHttpResponseStream::into_sse_stream",
        // Decoded payload N = 4_090: `data: ` line N+6 raw octets, N+8 on the
        // wire under CRLF, N+10 for the complete event including its blank line.
        byte_floor: 4_090,
    },
    ManifestCase {
        group: "HTTP-03.12",
        variable: "malformed/invalid-direction response isolation",
        entrypoint: "ClientHttpConnection::open_final_core_listener",
        byte_floor: 2,
    },
    ManifestCase {
        group: "HTTP-03.13",
        variable: "JSON-or-SSE one terminal outcome with request-scoped progress",
        entrypoint: "ClientHttpConnection::{open_final_core_listener,request_json}",
        byte_floor: 3,
    },
];

/// The thirteen planted negatives, in exact manifest order. Each varies only
/// the single dimension named in `variable`.
const NEGATIVE_CASES: [ManifestCase; 13] = [
    ManifestCase {
        group: "HTTP-03.01",
        variable: "request target gains one CRLF (header-splitting attempt)",
        entrypoint: "ModernHttpRequest::new",
        byte_floor: 0,
    },
    ManifestCase {
        group: "HTTP-03.02",
        variable: "request params shape: object becomes array",
        entrypoint: "ClientHttpConnection::request_json",
        byte_floor: 0,
    },
    ManifestCase {
        group: "HTTP-03.03",
        variable: "Mcp-Name value gains one CRLF (Accept-weakening attempt)",
        entrypoint: "ModernHttpRequest::new",
        byte_floor: 0,
    },
    ManifestCase {
        group: "HTTP-03.04",
        variable: "response Content-Encoding: identity becomes gzip",
        entrypoint: "ModernHttpExecutor::execute",
        byte_floor: 0,
    },
    ManifestCase {
        group: "HTTP-03.05",
        variable: "tools/call body omits the Mcp-Name mirror member",
        entrypoint: "ClientHttpConnection::request_json",
        byte_floor: 0,
    },
    ManifestCase {
        group: "HTTP-03.06",
        variable: "JSON response body gains a three-byte leading BOM",
        entrypoint: "ClientHttpConnection::request_json",
        byte_floor: 3,
    },
    ManifestCase {
        group: "HTTP-03.07",
        variable: "response charset parameter utf-8 becomes utf-16",
        entrypoint: "ModernHttpExecutor::execute",
        byte_floor: 0,
    },
    ManifestCase {
        group: "HTTP-03.08",
        variable: "malformed byte moves from inside to outside the JSON string",
        entrypoint: "ClientHttpConnection::open_final_core_listener",
        byte_floor: 1,
    },
    ManifestCase {
        group: "HTTP-03.09",
        variable: "data field name case: `data` becomes `Data`",
        entrypoint: "ModernHttpResponseStream::into_sse_stream",
        byte_floor: 0,
    },
    ManifestCase {
        group: "HTTP-03.10",
        variable: "terminating blank line removed before EOF",
        entrypoint: "ClientHttpConnection::open_final_core_listener",
        byte_floor: 0,
    },
    ManifestCase {
        group: "HTTP-03.11",
        variable: "one byte across the line ceiling, one byte across the event ceiling",
        entrypoint: "ModernHttpResponseStream::into_sse_stream",
        // N+1: payload 4_091 makes a 4_097-octet line against a 4_096 ceiling.
        byte_floor: 4_091,
    },
    ManifestCase {
        group: "HTTP-03.12",
        variable: "SSE message direction: notification becomes server request",
        entrypoint: "ClientHttpConnection::open_final_core_listener",
        byte_floor: 0,
    },
    ManifestCase {
        group: "HTTP-03.13",
        variable: "terminal response id no longer correlates with the request",
        entrypoint: "ClientHttpConnection::request_json",
        byte_floor: 0,
    },
];

/// The canonical group order the manifest freezes.
const MANIFEST_GROUP_ORDER: [&str; 13] = [
    "HTTP-03.01",
    "HTTP-03.02",
    "HTTP-03.03",
    "HTTP-03.04",
    "HTTP-03.05",
    "HTTP-03.06",
    "HTTP-03.07",
    "HTTP-03.08",
    "HTTP-03.09",
    "HTTP-03.10",
    "HTTP-03.11",
    "HTTP-03.12",
    "HTTP-03.13",
];

fn assert_manifest_order(cases: &[ManifestCase; 13]) {
    for (index, case) in cases.iter().enumerate() {
        assert_eq!(
            case.group, MANIFEST_GROUP_ORDER[index],
            "manifest group order is frozen; case {index} must be {}",
            MANIFEST_GROUP_ORDER[index]
        );
    }
}

/// Returns the byte count this file's case table froze for one group. The case
/// bodies read their sizes from here so an executed byte count cannot drift
/// away from the row that documents it. This is a byte quantity and is
/// deliberately distinct from the shipped manifest's observation `floor=`.
fn case_bytes(cases: &[ManifestCase; 13], group: &str) -> usize {
    cases
        .iter()
        .find(|case| case.group == group)
        .unwrap_or_else(|| panic!("{group} must be present in the manifest"))
        .byte_floor
}

/// Parses the shipped `http_03_evaluator_manifest_v1` this slice publishes and
/// checks it against the cases this file actually executes.
///
/// The manifest is deliberately not rebuilt here. `HTTP_03_A_EVALUATOR_MANIFEST_V1`
/// is the producer-owned acceptance input the HTTP-03 integration join consumes;
/// a locally authored copy would prove nothing about what ships. This asserts
/// the published bytes are LF-canonical, that their thirteen case rows are
/// exactly `HTTP-03.01`..`HTTP-03.13` in frozen order, that every row declares a
/// positive observation floor, and that the published digest still binds the
/// published bytes.
fn assert_shipped_manifest() {
    let text = HTTP_03_A_EVALUATOR_MANIFEST_V1;
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
    assert_eq!(rows[0], "HTTP-03-A evaluator manifest v1");
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

    // The published digest must bind the published bytes; a digest that no
    // longer recomputes means the producer's two halves have drifted apart.
    let recomputed = sha256_bounded(text.as_bytes(), 64 * 1024)
        .expect("the fixed manifest is within its byte bound");
    assert_eq!(
        http_03_a_manifest_digest().as_bytes(),
        recomputed.as_bytes(),
        "the published HTTP-03 A digest must bind the published manifest bytes"
    );
}

// ---------------------------------------------------------------------------
// Frozen entry points
// ---------------------------------------------------------------------------

#[test]
fn http_03_a_positive() {
    assert_manifest_order(&POSITIVE_CASES);
    assert_shipped_manifest();
    assert_eq!(
        POSITIVE_CASES.len() + NEGATIVE_CASES.len(),
        26,
        "the manifest requires a minimum of 26 ordered cases"
    );
    run(async {
        let cx = Cx::current().expect("the caller runtime must install a current Cx");
        for case in POSITIVE_CASES {
            execute_positive(&cx, case).await;
        }
    });

    // No-downgrade status matrix. Era classification is synchronous and needs
    // no socket, so it runs outside the runtime block.
    //
    // An ordinary failure is never a downgrade signal. Authentication, payment,
    // permission, rate-limit, conflict and every 5xx status must leave the
    // negotiation with no legacy authorization and no selected era.
    for status in [
        401_u16, 402, 403, 407, 409, 410, 418, 422, 429, 500, 501, 502, 503, 504,
    ] {
        for body in [HttpProbeBody::Empty, HttpProbeBody::Unrecognized] {
            let (outcome, authorized, era) = observe_once(ProtocolPolicy::Auto, status, body);
            assert_eq!(
                outcome,
                Err(
                    ClientHttpNegotiationError::ModernProbeRejectedWithoutLegacyFallback {
                        status,
                        body
                    }
                ),
                "status {status} with {body:?} must not authorize a legacy fallback"
            );
            assert!(
                !authorized,
                "status {status} with {body:?} left a legacy authorization"
            );
            assert_eq!(era, None, "status {status} with {body:?} selected an era");
        }
    }

    // A transport failure is not a status at all and is never a downgrade
    // signal, under either era-capable policy.
    for policy in [ProtocolPolicy::Auto, ProtocolPolicy::ModernOnly] {
        let (outcome, authorized, era) = observe_once(policy, 0, HttpProbeBody::TransportFailure);
        assert_eq!(
            outcome,
            Err(ClientHttpNegotiationError::ModernProbeTransportFailure),
            "{policy:?} downgraded on a transport failure"
        );
        assert!(!authorized);
        assert_eq!(era, None);
    }

    // ModernOnly never downgrades, whatever the status - including the one
    // status that authorizes a fallback under Auto.
    for status in [400_u16, 401, 429, 500] {
        let (outcome, authorized, era) = observe_once(
            ProtocolPolicy::ModernOnly,
            status,
            HttpProbeBody::Unrecognized,
        );
        assert_eq!(
            outcome,
            Err(
                ClientHttpNegotiationError::ModernProbeRejectedWithoutLegacyFallback {
                    status,
                    body: HttpProbeBody::Unrecognized
                }
            ),
            "ModernOnly must never authorize a fallback, saw status {status}"
        );
        assert!(
            !authorized,
            "ModernOnly authorized a fallback at status {status}"
        );
        assert_eq!(era, None);
    }

    // A recognized modern JSON-RPC body selects modern regardless of the status
    // that carried it, so a failing status cannot suppress a valid modern peer.
    for status in [200_u16, 400, 401, 500] {
        let (outcome, authorized, era) = observe_once(
            ProtocolPolicy::Auto,
            status,
            HttpProbeBody::RecognizedModernJsonRpc,
        );
        assert_eq!(
            outcome,
            Ok(ClientHttpNegotiationDecision::ModernSelected),
            "a recognized modern body at status {status} must select modern"
        );
        assert!(
            !authorized,
            "selecting modern must not also authorize legacy"
        );
        assert_eq!(
            era,
            Some(fastmcp_protocol::protocol_policy::ProtocolEra::Modern2026)
        );
    }

    // The probe is never replayed: a second observation is refused whatever it
    // carries, so no status sequence can walk the client into a downgrade.
    let mut negotiation = negotiation_for(ProtocolPolicy::Auto);
    assert!(
        negotiation
            .observe_modern_probe(HttpModernProbe {
                status: 500,
                body: HttpProbeBody::Unrecognized
            })
            .is_err()
    );
    assert_eq!(
        negotiation.observe_modern_probe(HttpModernProbe {
            status: 400,
            body: HttpProbeBody::Empty
        }),
        Err(ClientHttpNegotiationError::ModernProbeAlreadyDispatched),
        "a refused probe must not leave the attempt open to a second, downgrading probe"
    );
    assert!(!negotiation.state().legacy_sse_fallback_authorized());
}

#[test]
fn http_03_a_planted_negative() {
    assert_manifest_order(&NEGATIVE_CASES);
    assert_shipped_manifest();
    assert_eq!(
        NEGATIVE_CASES.len(),
        MANIFEST_GROUP_ORDER.len(),
        "every manifest group carries exactly one planted negative"
    );
    run(async {
        let cx = Cx::current().expect("the caller runtime must install a current Cx");
        for case in NEGATIVE_CASES {
            execute_negative(&cx, case).await;
        }
    });

    // No-downgrade planted negative. The accepted case is the one status that
    // authorizes a legacy fallback under Auto: 400 with an unrecognized body.
    // Each mutation below changes exactly ONE variable of that accepted case and
    // must lose the authorization.
    let accepted = observe_once(ProtocolPolicy::Auto, 400, HttpProbeBody::Unrecognized);
    assert_eq!(
        accepted.0,
        Ok(ClientHttpNegotiationDecision::LegacySseFallbackAuthorized),
        "the accepted downgrade case is 400 with an unrecognized body under Auto"
    );
    assert!(
        accepted.1,
        "the accepted case authorizes the legacy fallback"
    );

    // (a) One variable: the policy. Auto becomes ModernOnly.
    let (outcome, authorized, era) =
        observe_once(ProtocolPolicy::ModernOnly, 400, HttpProbeBody::Unrecognized);
    assert_eq!(
        outcome,
        Err(
            ClientHttpNegotiationError::ModernProbeRejectedWithoutLegacyFallback {
                status: 400,
                body: HttpProbeBody::Unrecognized
            }
        ),
        "changing only the policy must withdraw the authorization"
    );
    assert!(!authorized);
    assert_eq!(era, None);

    // (b) One variable: the status. 400 becomes 500.
    let (outcome, authorized, _) =
        observe_once(ProtocolPolicy::Auto, 500, HttpProbeBody::Unrecognized);
    assert_eq!(
        outcome,
        Err(
            ClientHttpNegotiationError::ModernProbeRejectedWithoutLegacyFallback {
                status: 500,
                body: HttpProbeBody::Unrecognized
            }
        ),
        "changing only the status must withdraw the authorization"
    );
    assert!(!authorized);

    // (c) One variable: the body class. Unrecognized becomes a recognized
    //     modern JSON-RPC body, which selects modern rather than downgrading.
    let (outcome, authorized, _) = observe_once(
        ProtocolPolicy::Auto,
        400,
        HttpProbeBody::RecognizedModernJsonRpc,
    );
    assert_eq!(
        outcome,
        Ok(ClientHttpNegotiationDecision::ModernSelected),
        "changing only the body class must select modern"
    );
    assert!(!authorized, "selecting modern must not authorize legacy");

    // (d) One variable: the body class becomes a transport failure.
    let (outcome, authorized, _) =
        observe_once(ProtocolPolicy::Auto, 400, HttpProbeBody::TransportFailure);
    assert_eq!(
        outcome,
        Err(ClientHttpNegotiationError::ModernProbeTransportFailure),
        "a transport failure is never a downgrade signal"
    );
    assert!(!authorized);

    // Restored: the unmutated accepted case still authorizes, so each refusal
    // above came from its single changed variable and not a poisoned path.
    let restored = observe_once(ProtocolPolicy::Auto, 400, HttpProbeBody::Unrecognized);
    assert_eq!(
        restored.0,
        Ok(ClientHttpNegotiationDecision::LegacySseFallbackAuthorized)
    );
    assert!(restored.1);
}

async fn execute_positive(cx: &Cx, case: ManifestCase) {
    match case.group {
        "HTTP-03.01" => Box::pin(positive_01_request_construction(cx)).await,
        "HTTP-03.02" => Box::pin(positive_02_single_post_exact_body(cx)).await,
        "HTTP-03.03" => Box::pin(positive_03_content_type_and_accept(cx)).await,
        "HTTP-03.04" => Box::pin(positive_04_identity_accept_encoding(cx)).await,
        "HTTP-03.05" => Box::pin(positive_05_routing_headers(cx)).await,
        "HTTP-03.06" => Box::pin(positive_06_json_strict_utf8(cx)).await,
        "HTTP-03.07" => Box::pin(positive_07_response_content_type(cx)).await,
        "HTTP-03.08" => Box::pin(positive_08_replacement_decoder_and_bom(cx)).await,
        "HTTP-03.09" => Box::pin(positive_09_line_endings_and_data_fields(cx)).await,
        "HTTP-03.10" => Box::pin(positive_10_comments_and_inert_fields(cx)).await,
        "HTTP-03.11" => Box::pin(positive_11_bounds(cx)).await,
        "HTTP-03.12" => Box::pin(positive_12_response_isolation(cx)).await,
        "HTTP-03.13" => Box::pin(positive_13_terminal_outcome_and_progress(cx)).await,
        group => panic!("positive case {group} is not mapped to an executable body"),
    }
}

async fn execute_negative(cx: &Cx, case: ManifestCase) {
    match case.group {
        "HTTP-03.01" => Box::pin(negative_01_target_header_split(cx)).await,
        "HTTP-03.02" => Box::pin(negative_02_non_object_params(cx)).await,
        "HTTP-03.03" => Box::pin(negative_03_name_header_split(cx)).await,
        "HTTP-03.04" => Box::pin(negative_04_compressed_response(cx)).await,
        "HTTP-03.05" => Box::pin(negative_05_missing_name_mirror(cx)).await,
        "HTTP-03.06" => Box::pin(negative_06_json_byte_order_mark(cx)).await,
        "HTTP-03.07" => Box::pin(negative_07_wrong_charset_parameter(cx)).await,
        "HTTP-03.08" => Box::pin(negative_08_replacement_outside_json(cx)).await,
        "HTTP-03.09" => Box::pin(negative_09_uppercase_data_field(cx)).await,
        "HTTP-03.10" => Box::pin(negative_10_eof_without_blank_line(cx)).await,
        "HTTP-03.11" => Box::pin(negative_11_one_byte_over_bounds(cx)).await,
        "HTTP-03.12" => Box::pin(negative_12_invalid_direction(cx)).await,
        "HTTP-03.13" => Box::pin(negative_13_terminal_id_mismatch(cx)).await,
        group => panic!("negative case {group} is not mapped to an executable body"),
    }
}

// ---------------------------------------------------------------------------
// Loopback fixture
// ---------------------------------------------------------------------------

/// Runs one case body on a real reactor under a bounded wall-clock ceiling.
fn run(future: impl Future<Output = ()>) {
    RuntimeBuilder::current_thread()
        .with_reactor(create_reactor().expect("the loopback reactor must start"))
        .build()
        .expect("the loopback runtime must build")
        .block_on(async {
            let cx = Cx::current().expect("block_on must install a current Cx");
            asupersync::time::timeout_at(cx.now().saturating_add_nanos(120_000_000_000), future)
                .await
                .expect("every HTTP-03 A case must settle within two minutes");
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
    fn assert_no_further_connection(&self) {
        let mut task = Context::from_waker(Waker::noop());
        assert!(
            self.listener.poll_accept(&mut task).is_pending(),
            "the client must not open another socket"
        );
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

/// Opens a streaming SSE response.
///
/// The body is chunk-framed rather than close-delimited. HTTP/1.1 offers no
/// length for a stream of unknown size other than chunked transfer coding, and
/// the client's h1 decoder selects its body framing from the response head: a
/// head carrying neither `Content-Length` nor `Transfer-Encoding` frames an
/// empty body, which would silently deliver zero events instead of the stream
/// under test. Chunk framing also lets each write land on a boundary the
/// fixture chooses, which is what makes the parser's chunk-boundary invariance
/// observable rather than assumed.
async fn begin_sse(io: &mut TcpStream) {
    io.write_all(
        b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n",
    )
    .await
    .expect("write the SSE response head");
    io.flush().await.expect("flush the SSE response head");
}

/// Writes one chunk of a streaming SSE body. Each call is its own chunk, so a
/// caller can place a chunk boundary anywhere, including mid-payload.
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

/// Ends a streaming SSE body with its terminating zero-length chunk.
///
/// The HTTP framing is always completed correctly, including by the cases whose
/// changed variable is an SSE-level framing omission: a truncated chunked body
/// would fail at the transport layer and mask the event-stream behaviour under
/// test.
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

/// Answers the one-shot `server/discover` probe the modern era classifier
/// sends before any application method, and returns its captured wire form.
async fn serve_probe(peer: &Peer) -> Wire {
    let mut io = peer.accept().await;
    let wire = read_request(&mut io).await;
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
    write_json_response(&mut io, DISCOVERY_BODY).await;
    end_stream(&mut io).await;
    wire
}

fn plan(target: &str) -> ClientProtocolPlan {
    ClientProtocolPlan::http(
        ProtocolPolicy::ModernOnly,
        Some(CanonicalHttpUrl::parse(target).expect("the loopback target must be canonical")),
        None,
        None,
        "credential-partition-http-03-a".to_owned(),
        "security-partition-http-03-a".to_owned(),
        "native-h1-http-03-a".to_owned(),
        1,
        1,
        0,
    )
    .expect("the modern-only loopback plan must be accepted")
}

fn builder(target: &str) -> ClientBuilder {
    ClientBuilder::new()
        .client_info("http-03-a-client", "1.0.0")
        .protocol_plan(plan(target))
        .request_timeout_policy(
            RequestTimeoutPolicy::new(Duration::from_secs(10), Duration::from_secs(60))
                .expect("the loopback request timeout policy must be valid"),
        )
}

fn limits() -> SseLimits {
    SseLimits::new(4_096, 65_536, 64).expect("bounded SSE limits")
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

fn terminal_tool_result(request_id: u64, text: &str) -> Vec<u8> {
    serde_json::to_vec(&serde_json::json!({
        "jsonrpc": "2.0",
        "id": request_id,
        "result": {
            "resultType": "complete",
            "content": [{"type": "text", "text": text}],
            "isError": false,
        },
    }))
    .expect("the terminal tools/call fixture must serialize")
}

fn progress_notification(marker: &ProgressMarker, progress: u64) -> Vec<u8> {
    serde_json::to_vec(&serde_json::json!({
        "jsonrpc": "2.0",
        "method": "notifications/progress",
        "params": {
            "progressToken": marker,
            "progress": progress,
            "total": 32,
        },
    }))
    .expect("the progress fixture must serialize")
}

fn tool_call_params(name: &str) -> serde_json::Value {
    serde_json::json!({"name": name, "arguments": {}})
}

/// Connects the public modern client, answering its probe on the fixture.
async fn connect(cx: &Cx, peer: &Peer) -> ClientHttpConnection {
    let target = peer.target();
    let (_, connection) = pair(serve_probe(peer), async {
        builder(&target)
            .connect_http_with_cx(cx)
            .await
            .expect("the public modern client must connect over the loopback socket")
    })
    .await;
    connection
}

// ---------------------------------------------------------------------------
// HTTP-03.01 — real-socket public-client request construction
// ---------------------------------------------------------------------------

async fn positive_01_request_construction(cx: &Cx) {
    let peer = Peer::bind().await;
    let target = peer.target();
    let authority = peer.authority();

    let (probe, connection) = pair(serve_probe(&peer), async {
        builder(&target)
            .connect_http_with_cx(cx)
            .await
            .expect("the public modern client must connect over the loopback socket")
    })
    .await;

    assert!(
        probe.head.starts_with("POST /mcp HTTP/1.1\r\n"),
        "the public client must construct its POST on the configured path"
    );
    assert_eq!(
        exactly_one_header(&probe.head, "Host"),
        authority,
        "the request must address the socket it actually opened"
    );
    assert_eq!(
        connection.protocol_version(),
        Some("2026-07-28"),
        "the loopback exchange must select the modern era"
    );
    // One socket total: the probe is never replayed.
    peer.assert_no_further_connection();
}

async fn negative_01_target_header_split(cx: &Cx) {
    let peer = Peer::bind().await;
    let target = peer.target();

    // Control: the unmutated target constructs and reaches the live listener.
    let accepted = ModernHttpRequest::new(target.as_str(), ping_body(), "2026-07-28", "ping", None);
    assert!(
        accepted.is_ok(),
        "the unmutated loopback target must construct"
    );

    // The sole changed variable is the target string, which gains one CRLF.
    let planted = ModernHttpRequest::new(
        format!("{target}\r\nAccept: */*"),
        ping_body(),
        "2026-07-28",
        "ping",
        None,
    );
    assert!(
        matches!(
            planted,
            Err(ModernHttpExecutorError::InvalidRequestMetadata)
        ),
        "a target carrying header controls must be refused before any socket"
    );

    // The listener really was live; only the mutated construction was refused.
    // Exactly one socket is consumed here, by the control request.
    let request = accepted.expect("control request");
    let (wire, bytes) = pair(
        async {
            let mut io = peer.accept().await;
            let wire = read_request(&mut io).await;
            write_json_response(&mut io, br#"{"jsonrpc":"2.0","id":1,"result":{}}"#).await;
            end_stream(&mut io).await;
            wire
        },
        async {
            post(cx, &request)
                .await
                .expect("the unmutated request must reach the live listener")
                .read_to_end(cx, 64 * 1024)
                .await
                .expect("the control response body must be readable")
        },
    )
    .await;
    assert_eq!(header_values(&wire.head, "accept").len(), 1);
    assert_eq!(bytes, br#"{"jsonrpc":"2.0","id":1,"result":{}}"#.to_vec());
    // Endpoint state is unchanged: the refused construction opened no socket
    // of its own, so the control exchange accounts for every connection.
    peer.assert_no_further_connection();
}

// ---------------------------------------------------------------------------
// HTTP-03.02 — one POST and exact JSON body
// ---------------------------------------------------------------------------

async fn positive_02_single_post_exact_body(cx: &Cx) {
    let peer = Peer::bind().await;
    let request = ping_request(&peer.target());
    let expected_body = ping_body();

    let (wire, body) = pair(
        async {
            let mut io = peer.accept().await;
            let wire = read_request(&mut io).await;
            write_json_response(&mut io, br#"{"jsonrpc":"2.0","id":1,"result":{}}"#).await;
            end_stream(&mut io).await;
            wire
        },
        async {
            let response = post(cx, &request)
                .await
                .expect("one modern POST must complete over the loopback socket");
            assert_eq!(response.metadata().kind(), ModernHttpResponseKind::Json);
            response
                .read_to_end(cx, 64 * 1024)
                .await
                .expect("the JSON response body must be readable")
        },
    )
    .await;

    assert!(
        wire.head.starts_with("POST /mcp HTTP/1.1\r\n"),
        "the method must be POST: {:?}",
        wire.head
    );
    assert_eq!(
        exactly_one_header(&wire.head, "content-length"),
        expected_body.len().to_string(),
        "the advertised length must equal the JSON-RPC body length"
    );
    assert_eq!(
        wire.body, expected_body,
        "the body must reach the server byte-for-byte as constructed"
    );
    assert_eq!(body, br#"{"jsonrpc":"2.0","id":1,"result":{}}"#.to_vec());
    // Exactly one POST: no replay, no second attempt.
    peer.assert_no_further_connection();
}

async fn negative_02_non_object_params(cx: &Cx) {
    let peer = Peer::bind().await;
    let mut connection = connect(cx, &peer).await;

    // The sole changed variable is the parameter shape: object becomes array.
    let refusal = connection
        .request_json(
            cx,
            "tools/list",
            serde_json::json!([]),
            RequestId::Number(2),
            64 * 1024,
        )
        .await
        .expect_err("non-object parameters cannot become a modern POST body");
    assert!(
        matches!(
            refusal,
            ClientHttpConnectionError::Modern(ModernHttpClientError::RequestParametersMustBeObject)
        ),
        "expected a typed parameter-shape refusal, saw {refusal:?}"
    );
    // No body was ever framed, so no socket beyond the probe was opened.
    peer.assert_no_further_connection();
}

// ---------------------------------------------------------------------------
// HTTP-03.03 — exact Content-Type and two-range Accept
// ---------------------------------------------------------------------------

async fn positive_03_content_type_and_accept(cx: &Cx) {
    let peer = Peer::bind().await;
    let request = ping_request(&peer.target());

    let (wire, ()) = pair(
        async {
            let mut io = peer.accept().await;
            let wire = read_request(&mut io).await;
            write_json_response(&mut io, br#"{"jsonrpc":"2.0","id":1,"result":{}}"#).await;
            end_stream(&mut io).await;
            wire
        },
        async {
            post(cx, &request)
                .await
                .expect("the modern POST must complete")
                .read_to_end(cx, 64 * 1024)
                .await
                .expect("the response body must be readable");
        },
    )
    .await;

    assert_eq!(
        exactly_one_header(&wire.head, "content-type"),
        MODERN_MCP_CONTENT_TYPE,
        "every JSON-RPC POST carries the exact JSON content type"
    );
    assert_eq!(MODERN_MCP_CONTENT_TYPE, "application/json");
    let accept = exactly_one_header(&wire.head, "accept");
    assert_eq!(
        accept, MODERN_MCP_ACCEPT,
        "both response media ranges must be advertised verbatim"
    );
    assert_eq!(accept, "application/json, text/event-stream");
    // Positive implicit quality: neither range carries a parameter or q-value,
    // and neither is replaced by a wildcard.
    assert!(
        !accept.contains('*'),
        "no wildcard may stand in for a range"
    );
    assert!(
        !accept.contains(';'),
        "no media parameter may weaken a range"
    );
    assert!(
        accept.contains("application/json") && accept.contains("text/event-stream"),
        "both required response media types must be present"
    );
    // The uncoded request body carries no Content-Encoding at all.
    assert!(
        header_values(&wire.head, "content-encoding").is_empty(),
        "the uncoded JSON-RPC request body must omit Content-Encoding"
    );
}

async fn negative_03_name_header_split(cx: &Cx) {
    let peer = Peer::bind().await;
    let target = peer.target();

    // Control: the same request with a clean Mcp-Name constructs.
    let accepted = ModernHttpRequest::new(
        target.as_str(),
        ping_body(),
        "2026-07-28",
        "tools/call",
        Some("probe_tool".to_owned()),
    );
    assert!(accepted.is_ok(), "a clean Mcp-Name must construct");

    // The sole changed variable is the Mcp-Name value, which gains one CRLF
    // in an attempt to append a weaker Accept range to the request head.
    let planted = ModernHttpRequest::new(
        target.as_str(),
        ping_body(),
        "2026-07-28",
        "tools/call",
        Some("probe_tool\r\nAccept: application/json;q=0".to_owned()),
    );
    assert!(
        matches!(
            planted,
            Err(ModernHttpExecutorError::InvalidRequestMetadata)
        ),
        "the public builder must refuse header injection rather than weaken Accept"
    );

    // The unweakened Accept still reaches the live listener unchanged.
    let request = accepted.expect("control request");
    let (wire, ()) = pair(
        async {
            let mut io = peer.accept().await;
            let wire = read_request(&mut io).await;
            write_json_response(&mut io, br#"{"jsonrpc":"2.0","id":1,"result":{}}"#).await;
            end_stream(&mut io).await;
            wire
        },
        async {
            post(cx, &request)
                .await
                .expect("the control request must complete")
                .read_to_end(cx, 64 * 1024)
                .await
                .expect("the control body must be readable");
        },
    )
    .await;
    assert_eq!(exactly_one_header(&wire.head, "accept"), MODERN_MCP_ACCEPT);
    // The refused construction opened no socket of its own.
    peer.assert_no_further_connection();
}

// ---------------------------------------------------------------------------
// HTTP-03.04 — lowercase identity Accept-Encoding and no decompression
// ---------------------------------------------------------------------------

/// Mirrors the production private ceiling
/// `MAX_IGNORED_RESPONSE_CONTENT_ENCODING_EMPTY_ELEMENTS`
/// (`http_executor.rs:345`). It is a design limit rather than a measurement, so
/// a fixed literal is correct here; it is named only so the positive's run and
/// its planted negative's N+1 cannot drift apart.
const IGNORED_EMPTY_CODING_CEILING: usize = 16;

/// Drives one response whose only variable is the `Content-Encoding` field
/// value, and returns the admitted body or the typed refusal.
async fn content_encoding_outcome(
    cx: &Cx,
    encoding: Option<&str>,
) -> Result<Vec<u8>, ModernHttpExecutorError> {
    const PAYLOAD: &[u8] = br#"{"jsonrpc":"2.0","id":1,"result":{"note":"uncoded"}}"#;
    let peer = Peer::bind().await;
    let request = ping_request(&peer.target());
    let mut headers = vec![("Content-Type", "application/json")];
    if let Some(encoding) = encoding {
        headers.push(("Content-Encoding", encoding));
    }
    let ((), outcome) = pair(
        async {
            let mut io = peer.accept().await;
            let _ = read_request(&mut io).await;
            write_response(&mut io, 200, &headers, PAYLOAD).await;
            end_stream(&mut io).await;
        },
        async {
            match post(cx, &request).await {
                Ok(response) => response.read_to_end(cx, 64 * 1024).await,
                Err(error) => Err(error),
            }
        },
    )
    .await;
    outcome
}

/// Drives one response carrying `Content-Encoding` TWICE, which is a header
/// cardinality violation rather than a coding violation.
async fn duplicate_content_encoding_outcome(cx: &Cx) -> ModernHttpExecutorError {
    let peer = Peer::bind().await;
    let request = ping_request(&peer.target());
    let ((), error) = pair(
        async {
            let mut io = peer.accept().await;
            let _ = read_request(&mut io).await;
            write_response(
                &mut io,
                200,
                &[
                    ("Content-Type", "application/json"),
                    ("Content-Encoding", "identity"),
                    ("Content-Encoding", "identity"),
                ],
                b"{}",
            )
            .await;
            end_stream(&mut io).await;
        },
        async {
            post(cx, &request)
                .await
                .err()
                .expect("a repeated Content-Encoding must be refused")
        },
    )
    .await;
    error
}

async fn positive_04_identity_accept_encoding(cx: &Cx) {
    let peer = Peer::bind().await;
    let request = ping_request(&peer.target());
    let payload = br#"{"jsonrpc":"2.0","id":1,"result":{"note":"uncoded"}}"#;

    let (wire, body) = pair(
        async {
            let mut io = peer.accept().await;
            let wire = read_request(&mut io).await;
            write_response(
                &mut io,
                200,
                &[
                    ("Content-Type", "application/json"),
                    ("Content-Encoding", "identity"),
                ],
                payload,
            )
            .await;
            end_stream(&mut io).await;
            wire
        },
        async {
            post(cx, &request)
                .await
                .expect("a singleton identity coding must be admitted")
                .read_to_end(cx, 64 * 1024)
                .await
                .expect("the identity-coded body must be readable")
        },
    )
    .await;

    let accept_encoding = exactly_one_header(&wire.head, "accept-encoding");
    assert_eq!(accept_encoding, MODERN_MCP_ACCEPT_ENCODING);
    assert_eq!(accept_encoding, "identity");
    assert_eq!(
        accept_encoding,
        accept_encoding.to_ascii_lowercase(),
        "the canonical coding token is lowercase on the wire"
    );
    assert_eq!(
        body,
        payload.to_vec(),
        "no decompression may be applied to an identity-coded body"
    );

    // ---------------------------------------------------------------------
    // The admitted RFC 9110 list grammar for a response content coding. Exactly
    // one semantic coding, compared ASCII-case-insensitively against the
    // canonical `identity` token, with bounded empty list elements ignored as
    // framing noise. Every case below carries the SAME body, and the admitted
    // bytes are asserted unchanged, so an accidental decompression on any of
    // these forms would be visible.
    // ---------------------------------------------------------------------
    const PAYLOAD: &[u8] = br#"{"jsonrpc":"2.0","id":1,"result":{"note":"uncoded"}}"#;
    let mut ceiling_run = ",".repeat(IGNORED_EMPTY_CODING_CEILING);
    ceiling_run.push_str("identity");

    for encoding in [
        None,
        Some("identity"),
        Some("IDENTITY"),
        Some("Identity"),
        Some("  identity  "),
        Some(", identity"),
        Some("identity,"),
        Some(",,identity,,"),
        Some(ceiling_run.as_str()),
    ] {
        let body = content_encoding_outcome(cx, encoding)
            .await
            .unwrap_or_else(|error| {
                panic!("Content-Encoding {encoding:?} must be admitted, saw {error:?}")
            });
        assert_eq!(
            body,
            PAYLOAD.to_vec(),
            "Content-Encoding {encoding:?} must deliver the body unchanged"
        );
    }
}

async fn negative_04_compressed_response(cx: &Cx) {
    let peer = Peer::bind().await;
    let request = ping_request(&peer.target());
    let payload = br#"{"jsonrpc":"2.0","id":1,"result":{"note":"uncoded"}}"#;

    // The sole changed variable is the response content coding.
    let ((), refusal) = pair(
        async {
            let mut io = peer.accept().await;
            let _ = read_request(&mut io).await;
            write_response(
                &mut io,
                200,
                &[
                    ("Content-Type", "application/json"),
                    ("Content-Encoding", "gzip"),
                ],
                payload,
            )
            .await;
            end_stream(&mut io).await;
        },
        async {
            post(cx, &request)
                .await
                .err()
                .expect("a compressed response must be refused")
        },
    )
    .await;

    assert!(
        matches!(refusal, ModernHttpExecutorError::UnsupportedContentEncoding),
        "expected a typed content-coding refusal, saw {refusal:?}"
    );
    // The refusal precedes any body lane, so no byte was ever decompressed:
    // `execute` returned an error instead of a response stream.
    peer.assert_no_further_connection();

    // ---------------------------------------------------------------------
    // Content-coding planted negatives. The accepted case is the bare
    // `identity` token; each row below changes exactly ONE thing about that
    // field value and must fail closed before any body byte is exposed.
    // ---------------------------------------------------------------------
    assert!(
        content_encoding_outcome(cx, Some("identity")).await.is_ok(),
        "the unmutated accepted coding must be admitted"
    );

    let mut over_ceiling = ",".repeat(IGNORED_EMPTY_CODING_CEILING + 1);
    over_ceiling.push_str("identity");

    for (encoding, why) in [
        ("identity, identity", "two semantic codings"),
        ("identity, gzip", "a second, compressed coding"),
        (",", "present but all-empty, so no semantic coding at all"),
        (",,,", "empty-element saturation with no coding"),
        ("identity;q=1", "a parameterised coding token"),
        (
            "x-identity",
            "a token that merely contains the canonical one",
        ),
        (
            "identityx",
            "a token that merely starts with the canonical one",
        ),
        (
            over_ceiling.as_str(),
            "one empty element past the ignored ceiling",
        ),
    ] {
        let error = content_encoding_outcome(cx, Some(encoding))
            .await
            .err()
            .unwrap_or_else(|| panic!("Content-Encoding {encoding:?} must be refused ({why})"));
        assert!(
            matches!(error, ModernHttpExecutorError::UnsupportedContentEncoding),
            "{encoding:?} ({why}) must raise the typed coding refusal, saw {error:?}"
        );
    }

    // A repeated field line is a header-cardinality violation, and is reported
    // as such rather than being folded into the coding refusal - the two are
    // different defects and a caller can tell them apart.
    let duplicate = duplicate_content_encoding_outcome(cx).await;
    assert!(
        matches!(
            duplicate,
            ModernHttpExecutorError::DuplicateResponseHeader { name } if name == "Content-Encoding"
        ),
        "a repeated Content-Encoding must be a duplicate-header refusal, saw {duplicate:?}"
    );

    // Restored: the unmutated coding is admitted again, so every refusal above
    // came from its own changed variable rather than a poisoned path.
    assert!(
        content_encoding_outcome(cx, Some("identity")).await.is_ok(),
        "the unmutated accepted coding must be admitted again"
    );
}

// ---------------------------------------------------------------------------
// HTTP-03.05 — protocol/method/name routing headers
// ---------------------------------------------------------------------------

async fn positive_05_routing_headers(cx: &Cx) {
    let peer = Peer::bind().await;
    let connection = connect(cx, &peer).await;

    let (wire, ()) = pair(
        async {
            let mut io = peer.accept().await;
            let wire = read_request(&mut io).await;
            begin_sse(&mut io).await;
            write_bytes(&mut io, b"data: ").await;
            write_bytes(&mut io, &terminal_tool_result(2, "routing-ok")).await;
            write_bytes(&mut io, b"\n\n").await;
            end_sse_stream(&mut io).await;
            wire
        },
        async {
            let mut listener = connection
                .open_final_core_listener(
                    cx,
                    "tools/call",
                    tool_call_params("probe_tool"),
                    RequestId::Number(2),
                    limits(),
                )
                .await
                .expect("the routing-header request must reach the peer");
            let event = listener
                .next_event(cx)
                .await
                .expect("the terminal must be admissible")
                .expect("a terminal event must arrive");
            assert!(matches!(event, ModernHttpFinalCoreEvent::Terminal(_)));
        },
    )
    .await;

    assert_eq!(
        exactly_one_header(&wire.head, "MCP-Protocol-Version"),
        "2026-07-28"
    );
    assert_eq!(exactly_one_header(&wire.head, "Mcp-Method"), "tools/call");
    assert_eq!(exactly_one_header(&wire.head, "Mcp-Name"), "probe_tool");
}

async fn negative_05_missing_name_mirror(cx: &Cx) {
    let peer = Peer::bind().await;
    let mut connection = connect(cx, &peer).await;

    // The sole changed variable is the body member the Mcp-Name header
    // mirrors: `name` is absent while the method stays `tools/call`.
    let refusal = connection
        .request_json(
            cx,
            "tools/call",
            serde_json::json!({"arguments": {}}),
            RequestId::Number(2),
            64 * 1024,
        )
        .await
        .expect_err("a tools/call without its name mirror cannot be routed");
    assert!(
        matches!(
            &refusal,
            ClientHttpConnectionError::Modern(ModernHttpClientError::MissingRequestName { method })
                if method == "tools/call"
        ),
        "expected a typed missing-name refusal, saw {refusal:?}"
    );
    peer.assert_no_further_connection();
}

// ---------------------------------------------------------------------------
// HTTP-03.06 — immediate JSON strict UTF-8/BOM admission
// ---------------------------------------------------------------------------

/// Builds a JSON-RPC response whose `note` string holds the caller's raw bytes.
///
/// The surrounding envelope is byte-identical across every case, so the only
/// thing that varies between an admitted and a refused body is the injected
/// sequence itself.
fn json_response_with_raw_note(raw_note: &[u8]) -> Vec<u8> {
    let mut body = Vec::new();
    body.extend_from_slice(br#"{"jsonrpc":"2.0","id":2,"result":{"note":""#);
    body.extend_from_slice(raw_note);
    body.extend_from_slice(br#""}}"#);
    body
}

/// Sends one direct-lane JSON response with an exact body and returns the
/// strict-admission outcome through the public client.
async fn direct_json_admission(cx: &Cx, body: Vec<u8>) -> Result<(), ClientHttpConnectionError> {
    let peer = Peer::bind().await;
    let mut connection = connect(cx, &peer).await;
    let ((), outcome) = pair(
        async {
            let mut io = peer.accept().await;
            let _ = read_request(&mut io).await;
            write_json_response(&mut io, &body).await;
            end_stream(&mut io).await;
        },
        async {
            connection
                .request_json(
                    cx,
                    "tools/list",
                    serde_json::json!({}),
                    RequestId::Number(2),
                    64 * 1024,
                )
                .await
                .map(|_| ())
        },
    )
    .await;
    outcome
}

/// A valid JSON-RPC response whose result carries a multi-byte UTF-8 scalar.
fn utf8_json_response() -> Vec<u8> {
    serde_json::to_vec(&serde_json::json!({
        "jsonrpc": "2.0",
        "id": 2,
        "result": {"note": "prüfung-✓"},
    }))
    .expect("the strict UTF-8 fixture must serialize")
}

async fn positive_06_json_strict_utf8(cx: &Cx) {
    let peer = Peer::bind().await;
    let mut connection = connect(cx, &peer).await;
    let body = utf8_json_response();

    let ((), response) = pair(
        async {
            let mut io = peer.accept().await;
            let _ = read_request(&mut io).await;
            write_json_response(&mut io, &body).await;
            end_stream(&mut io).await;
        },
        async {
            connection
                .request_json(
                    cx,
                    "tools/list",
                    serde_json::json!({}),
                    RequestId::Number(2),
                    64 * 1024,
                )
                .await
                .expect("valid UTF-8 JSON must be admitted without repair")
        },
    )
    .await;

    assert_eq!(response.id, Some(RequestId::Number(2)));
    assert!(
        response.error.is_none(),
        "the admitted response must be the peer's result"
    );

    // A correctly encoded U+FFFD is ordinary text and is admitted. The direct
    // lane refuses MALFORMED BYTES, not the replacement character itself - and
    // the distinction matters, because the negative half proves the same
    // logical character arrives legitimately over SSE.
    direct_json_admission(cx, json_response_with_raw_note("\u{FFFD}".as_bytes()))
        .await
        .expect("a well-formed U+FFFD is ordinary UTF-8 and must be admitted");
}

async fn negative_06_json_byte_order_mark(cx: &Cx) {
    let peer = Peer::bind().await;
    let mut connection = connect(cx, &peer).await;

    // The sole changed variable is the three leading bytes: the identical JSON
    // document gains a UTF-8 BOM.
    let mut body = vec![0xEF, 0xBB, 0xBF];
    assert_eq!(
        body.len(),
        case_bytes(&NEGATIVE_CASES, "HTTP-03.06"),
        "the case table records the three-byte BOM this negative prepends"
    );
    body.extend_from_slice(&utf8_json_response());

    let ((), refusal) = pair(
        async {
            let mut io = peer.accept().await;
            let _ = read_request(&mut io).await;
            write_json_response(&mut io, &body).await;
            end_stream(&mut io).await;
        },
        async {
            connection
                .request_json(
                    cx,
                    "tools/list",
                    serde_json::json!({}),
                    RequestId::Number(2),
                    64 * 1024,
                )
                .await
                .expect_err("a BOM must be rejected, never stripped or repaired")
        },
    )
    .await;

    assert!(
        matches!(
            refusal,
            ClientHttpConnectionError::ResponseAdmission(JsonRpcAdmissionError::Raw(
                RawJsonAdmissionError::ByteOrderMark
            ))
        ),
        "expected a typed BOM refusal on the direct JSON lane, saw {refusal:?}"
    );

    // ---------------------------------------------------------------------
    // A BOM is refused wherever it appears, not merely at byte 0. The changed
    // variable is the BOM's POSITION: here it sits inside a string value, deep
    // in an otherwise valid document.
    // ---------------------------------------------------------------------
    let mut midstream_note = Vec::new();
    midstream_note.extend_from_slice(b"before");
    midstream_note.extend_from_slice(&[0xEF, 0xBB, 0xBF]);
    midstream_note.extend_from_slice(b"after");
    let midstream = direct_json_admission(cx, json_response_with_raw_note(&midstream_note))
        .await
        .expect_err("a midstream BOM must be refused, not just a leading one");
    assert!(
        matches!(
            midstream,
            ClientHttpConnectionError::ResponseAdmission(JsonRpcAdmissionError::Raw(
                RawJsonAdmissionError::ByteOrderMark
            ))
        ),
        "a midstream BOM must raise the same typed BOM refusal, saw {midstream:?}"
    );

    // ---------------------------------------------------------------------
    // DECODER-DISPATCH DIFFERENTIAL. This is the case the contract names: one
    // byte sequence that is invalid UTF-8 and would become a VALID JSON
    // document if it were replacement-decoded.
    //
    // The direct JSON lane must refuse it outright - strict UTF-8, never
    // repaired. The SSE lane must replacement-decode the identical bytes into
    // an ordinary U+FFFD inside a valid assembled payload. Same bytes, two
    // lanes, two different and both-correct outcomes; a single shared decoder
    // could not produce both.
    // ---------------------------------------------------------------------
    const LONE_CONTINUATION: &[u8] = &[0xFF];

    let malformed = direct_json_admission(cx, json_response_with_raw_note(LONE_CONTINUATION))
        .await
        .expect_err("malformed UTF-8 must be refused on the direct lane, never repaired");
    assert!(
        matches!(
            malformed,
            ClientHttpConnectionError::ResponseAdmission(JsonRpcAdmissionError::Raw(
                RawJsonAdmissionError::InvalidUtf8
            ))
        ),
        "the direct lane must refuse malformed UTF-8 as such, saw {malformed:?}"
    );

    let peer = Peer::bind().await;
    let mut sse_body = Vec::new();
    sse_body.extend_from_slice(b"data: ");
    sse_body.extend_from_slice(&json_response_with_raw_note(LONE_CONTINUATION));
    sse_body.extend_from_slice(b"\n\n");
    let payloads = drain_sse(cx, &peer, sse_body, limits())
        .await
        .expect("the SSE lane replacement-decodes rather than refusing");
    assert_eq!(
        payloads.len(),
        1,
        "the malformed byte must not break event framing"
    );
    assert!(
        payloads[0].contains('\u{FFFD}'),
        "the SSE lane must replace the malformed byte with U+FFFD: {:?}",
        payloads[0]
    );
    assert!(
        !payloads[0].as_bytes().contains(&0xFF),
        "no raw malformed byte may survive the SSE decoder"
    );
}

// ---------------------------------------------------------------------------
// HTTP-03.07 — exact response Content-Type selection
// ---------------------------------------------------------------------------

async fn positive_07_response_content_type(cx: &Cx) {
    for (content_type, expected) in [
        ("application/json", ModernHttpResponseKind::Json),
        (
            "application/json; charset=utf-8",
            ModernHttpResponseKind::Json,
        ),
        ("APPLICATION/JSON", ModernHttpResponseKind::Json),
        ("text/event-stream", ModernHttpResponseKind::Sse),
        (
            "text/event-stream; charset=UTF-8",
            ModernHttpResponseKind::Sse,
        ),
    ] {
        let peer = Peer::bind().await;
        let request = ping_request(&peer.target());
        let ((), kind) = pair(
            async {
                let mut io = peer.accept().await;
                let _ = read_request(&mut io).await;
                write_response(&mut io, 200, &[("Content-Type", content_type)], b"").await;
                end_stream(&mut io).await;
            },
            async {
                post(cx, &request)
                    .await
                    .unwrap_or_else(|error| {
                        panic!("{content_type} must select a body lane, saw {error:?}")
                    })
                    .metadata()
                    .kind()
            },
        )
        .await;
        assert_eq!(
            kind, expected,
            "{content_type} must select exactly one body lane"
        );
    }

    // ---------------------------------------------------------------------
    // Status-specific error bodies. A non-success response is admitted for
    // JSON-RPC error parsing only when its own declared content type is exactly
    // JSON; every other non-success response stays an opaque bounded failure.
    // The decision is taken from the head, before any body byte is read, so it
    // cannot be reached by sniffing the payload - every case below sends the
    // SAME JSON-RPC error bytes and only the declared type varies.
    // ---------------------------------------------------------------------
    for (status, content_type, expected) in [
        (
            400_u16,
            Some("application/json"),
            ModernHttpErrorBodyAdmission::JsonRpcError,
        ),
        (
            401,
            Some("application/json; charset=utf-8"),
            ModernHttpErrorBodyAdmission::JsonRpcError,
        ),
        (
            500,
            Some("APPLICATION/JSON"),
            ModernHttpErrorBodyAdmission::JsonRpcError,
        ),
        // Admitted for a success lane, but never as an error envelope.
        (
            503,
            Some("text/event-stream"),
            ModernHttpErrorBodyAdmission::Opaque,
        ),
        (
            502,
            Some("text/plain"),
            ModernHttpErrorBodyAdmission::Opaque,
        ),
        // Conflicting, unknown-parameter and absent forms are not admitted.
        (
            400,
            Some("application/json; charset=utf-16"),
            ModernHttpErrorBodyAdmission::Opaque,
        ),
        (
            429,
            Some("application/json; boundary=x"),
            ModernHttpErrorBodyAdmission::Opaque,
        ),
        (404, None, ModernHttpErrorBodyAdmission::Opaque),
    ] {
        let peer = Peer::bind().await;
        let request = ping_request(&peer.target());
        let headers: Vec<(&str, &str)> = content_type
            .map(|value| vec![("Content-Type", value)])
            .unwrap_or_default();
        let ((), metadata) = pair(
            async {
                let mut io = peer.accept().await;
                let _ = read_request(&mut io).await;
                write_response(
                    &mut io,
                    status,
                    &headers,
                    br#"{"jsonrpc":"2.0","id":1,"error":{"code":-32000,"message":"denied"}}"#,
                )
                .await;
                end_stream(&mut io).await;
            },
            async {
                post(cx, &request)
                    .await
                    .unwrap_or_else(|error| {
                        panic!("status {status} must admit a response head, saw {error:?}")
                    })
                    .metadata()
                    .clone()
            },
        )
        .await;

        assert_eq!(metadata.status(), status);
        assert_eq!(
            metadata.kind(),
            ModernHttpResponseKind::HttpFailure,
            "status {status} is a non-success response"
        );
        assert_eq!(
            metadata.error_body_admission(),
            Some(expected),
            "status {status} with content type {content_type:?}"
        );
    }

    // A successful response is not an error body at all, so it carries no
    // admission rather than an opaque one.
    let peer = Peer::bind().await;
    let request = ping_request(&peer.target());
    let ((), admission) = pair(
        async {
            let mut io = peer.accept().await;
            let _ = read_request(&mut io).await;
            write_response(&mut io, 200, &[("Content-Type", "application/json")], b"{}").await;
            end_stream(&mut io).await;
        },
        async {
            post(cx, &request)
                .await
                .expect("a success response must be admitted")
                .metadata()
                .error_body_admission()
        },
    )
    .await;
    assert_eq!(
        admission, None,
        "a success response carries no error-body admission"
    );
}

async fn negative_07_wrong_charset_parameter(cx: &Cx) {
    let peer = Peer::bind().await;
    let request = ping_request(&peer.target());

    // The sole changed variable is the charset parameter value.
    let ((), refusal) = pair(
        async {
            let mut io = peer.accept().await;
            let _ = read_request(&mut io).await;
            write_response(
                &mut io,
                200,
                &[("Content-Type", "application/json; charset=utf-16")],
                b"{}",
            )
            .await;
            end_stream(&mut io).await;
        },
        async {
            post(cx, &request)
                .await
                .err()
                .expect("a conflicting charset parameter must be refused")
        },
    )
    .await;

    assert!(
        matches!(
            refusal,
            ModernHttpExecutorError::UnsupportedSuccessContentType
        ),
        "expected a typed content-type refusal, saw {refusal:?}"
    );
    // The refusal precedes body decoding: no lane was selected and the client
    // did not sniff the `{}` payload it never read.
    peer.assert_no_further_connection();

    // ---------------------------------------------------------------------
    // Status-specific error-body planted negative. The accepted case is a 400
    // whose declared type is exactly JSON, so its bounded body may be read as
    // one JSON-RPC error. The sole changed variable is that declared type; the
    // status, the headers' cardinality and the body bytes are byte-for-byte
    // identical across both halves.
    // ---------------------------------------------------------------------
    const ERROR_BODY: &[u8] =
        br#"{"jsonrpc":"2.0","id":1,"error":{"code":-32000,"message":"denied"}}"#;

    async fn error_body_admission(
        cx: &Cx,
        content_type: &str,
    ) -> Option<ModernHttpErrorBodyAdmission> {
        let peer = Peer::bind().await;
        let request = ping_request(&peer.target());
        let ((), admission) = pair(
            async {
                let mut io = peer.accept().await;
                let _ = read_request(&mut io).await;
                write_response(&mut io, 400, &[("Content-Type", content_type)], ERROR_BODY).await;
                end_stream(&mut io).await;
            },
            async {
                post(cx, &request)
                    .await
                    .unwrap_or_else(|error| panic!("a 400 head must be admitted, saw {error:?}"))
                    .metadata()
                    .error_body_admission()
            },
        )
        .await;
        admission
    }

    assert_eq!(
        error_body_admission(cx, "application/json").await,
        Some(ModernHttpErrorBodyAdmission::JsonRpcError),
        "the accepted error body declares exactly JSON"
    );
    assert_eq!(
        error_body_admission(cx, "text/plain").await,
        Some(ModernHttpErrorBodyAdmission::Opaque),
        "the same bytes under a non-JSON declared type must stay opaque"
    );
    // Restored: the refusal came from the declared type, not from a poisoned
    // admission path.
    assert_eq!(
        error_body_admission(cx, "application/json").await,
        Some(ModernHttpErrorBodyAdmission::JsonRpcError),
        "the unmutated declared type is admitted again"
    );
}

// ---------------------------------------------------------------------------
// No-downgrade status matrix
//
// Era classification must never be talked into the legacy adapter by an
// ordinary failure. These helpers drive the shipped public
// `ClientHttpNegotiation` surface, one fresh negotiation per cell, because a
// negotiation admits exactly one probe and must not be replayed.
//
// DELIBERATE OMISSION: statuses 404 and 405 are NOT asserted here. The frozen
// package contract says "Do not interpret 404/405 as this adapter; those
// statuses participate only in the excluded deprecated HTTP+SSE GET fallback",
// but `negotiation.rs` currently authorizes a downgrade on 400 | 404 | 405 and
// three other live targets encode that same behaviour. Asserting either way
// here would either contradict the shipped client or add a fourth site
// cementing a contract violation. The conflict is reported for a ruling rather
// than resolved inside a test.
// ---------------------------------------------------------------------------

/// Builds a fresh negotiation for one policy against a loopback-shaped plan.
fn negotiation_for(policy: ProtocolPolicy) -> ClientHttpNegotiation {
    let modern =
        CanonicalHttpUrl::parse("https://downgrade.example.test/mcp").expect("modern target");
    let legacy_sse =
        CanonicalHttpUrl::parse("https://downgrade.example.test/sse").expect("legacy sse target");
    let legacy_message = CanonicalHttpUrl::parse("https://downgrade.example.test/messages")
        .expect("legacy message target");
    let plan = ClientProtocolPlan::http(
        policy,
        (!matches!(policy, ProtocolPolicy::LegacyOnly)).then_some(modern),
        (!matches!(policy, ProtocolPolicy::ModernOnly)).then_some(legacy_sse),
        (!matches!(policy, ProtocolPolicy::ModernOnly)).then_some(legacy_message),
        "credential-partition-http-03-a".to_owned(),
        "security-partition-http-03-a".to_owned(),
        "native-h1-http-03-a".to_owned(),
        1,
        1,
        0,
    )
    .expect("the downgrade-matrix plan must be accepted");
    ClientHttpNegotiation::from_protocol_plan(&plan)
        .expect("the plan creates a negotiation attempt")
}

/// Observes one probe on a fresh negotiation and returns both the outcome and
/// the post-state, so a caller can prove no legacy authorization leaked.
fn observe_once(
    policy: ProtocolPolicy,
    status: u16,
    body: HttpProbeBody,
) -> (
    Result<ClientHttpNegotiationDecision, ClientHttpNegotiationError>,
    bool,
    Option<fastmcp_protocol::protocol_policy::ProtocolEra>,
) {
    let mut negotiation = negotiation_for(policy);
    let outcome = negotiation.observe_modern_probe(HttpModernProbe { status, body });
    let state = negotiation.state();
    (
        outcome,
        state.legacy_sse_fallback_authorized(),
        state.selected_era(),
    )
}

// ---------------------------------------------------------------------------
// HTTP-03.08 — streaming SSE replacement decoder and leading-BOM rule
// ---------------------------------------------------------------------------

/// Builds an SSE body with a leading UTF-8 BOM and a single lone `0xFF` octet
/// placed either inside the terminal result's JSON string or outside it.
fn replacement_stream(inside_json_string: bool) -> Vec<u8> {
    let mut body = vec![0xEF, 0xBB, 0xBF];
    body.extend_from_slice(b"data: ");
    if inside_json_string {
        body.extend_from_slice(
            br#"{"jsonrpc":"2.0","id":2,"result":{"resultType":"complete","content":[{"type":"text","text":""#,
        );
        body.push(0xFF);
        body.extend_from_slice(br#""}],"isError":false}}"#);
    } else {
        body.extend_from_slice(b"{");
        body.push(0xFF);
        body.extend_from_slice(
            br#""jsonrpc":"2.0","id":2,"result":{"resultType":"complete","content":[{"type":"text","text":"ok"}],"isError":false}}"#,
        );
    }
    body.extend_from_slice(b"\n\n");
    body
}

async fn positive_08_replacement_decoder_and_bom(cx: &Cx) {
    let peer = Peer::bind().await;
    let connection = connect(cx, &peer).await;
    let body = replacement_stream(true);

    let ((), ()) = pair(
        async {
            let mut io = peer.accept().await;
            let _ = read_request(&mut io).await;
            begin_sse(&mut io).await;
            write_bytes(&mut io, &body).await;
            end_sse_stream(&mut io).await;
        },
        async {
            let mut listener = connection
                .open_final_core_listener(
                    cx,
                    "tools/call",
                    tool_call_params("replacement_tool"),
                    RequestId::Number(2),
                    limits(),
                )
                .await
                .expect("the SSE request must reach the peer");
            let event = listener
                .next_event(cx)
                .await
                .expect(
                    "the leading BOM must be stripped and the malformed octet replaced, \
                     leaving one admissible JSON-RPC object",
                )
                .expect("a terminal event must arrive");
            assert!(
                matches!(event, ModernHttpFinalCoreEvent::Terminal(_)),
                "replacement inside a JSON string must survive as U+FFFD"
            );
        },
    )
    .await;
}

async fn negative_08_replacement_outside_json(cx: &Cx) {
    let peer = Peer::bind().await;
    let connection = connect(cx, &peer).await;
    // The sole changed variable is the malformed octet's position: it moves
    // from inside the JSON string to a structural position outside it.
    let body = replacement_stream(false);

    let ((), refusal) = pair(
        async {
            let mut io = peer.accept().await;
            let _ = read_request(&mut io).await;
            begin_sse(&mut io).await;
            write_bytes(&mut io, &body).await;
            end_sse_stream(&mut io).await;
        },
        async {
            let mut listener = connection
                .open_final_core_listener(
                    cx,
                    "tools/call",
                    tool_call_params("replacement_tool"),
                    RequestId::Number(2),
                    limits(),
                )
                .await
                .expect("the SSE request must reach the peer");
            listener
                .next_event(cx)
                .await
                .err()
                .expect("replacement outside the JSON string must not be repaired")
        },
    )
    .await;

    assert!(
        matches!(refusal, ModernHttpFinalCoreListenError::JsonRpcAdmission(_)),
        "expected a typed JSON-RPC admission refusal, saw {refusal:?}"
    );
    // The client failed its own stream and posted nothing back to the server.
    peer.assert_no_further_connection();
}

// ---------------------------------------------------------------------------
// HTTP-03.09 — CR/LF/CRLF and data-field assembly
// ---------------------------------------------------------------------------

/// Opens one raw SSE payload stream through the public executor and drains
/// every dispatched payload in wire order, delivering the body in chunks of
/// `chunk_bytes` so the caller controls exactly where the boundaries fall.
async fn drain_sse_in_chunks(
    cx: &Cx,
    peer: &Peer,
    body: Vec<u8>,
    sse_limits: SseLimits,
    chunk_bytes: usize,
) -> Result<Vec<String>, ModernHttpExecutorError> {
    assert!(chunk_bytes > 0, "a chunk must carry at least one byte");
    let request = ping_request(&peer.target());
    let ((), payloads) = pair(
        async {
            let mut io = peer.accept().await;
            let _ = read_request(&mut io).await;
            begin_sse(&mut io).await;
            for chunk in body.chunks(chunk_bytes) {
                write_bytes(&mut io, chunk).await;
            }
            end_sse_stream(&mut io).await;
        },
        async {
            let response = post(cx, &request)
                .await
                .expect("the SSE response head must be admitted");
            assert_eq!(response.metadata().kind(), ModernHttpResponseKind::Sse);
            let mut stream = response
                .into_sse_stream(sse_limits)
                .expect("an admitted SSE response must convert to an event stream");
            let mut payloads = Vec::new();
            loop {
                match stream.next_event(cx).await {
                    Ok(Some(payload)) => payloads.push(payload),
                    Ok(None) => return Ok(payloads),
                    Err(error) => return Err(error),
                }
            }
        },
    )
    .await;
    payloads
}

/// Drains one SSE stream delivered as a single chunk.
async fn drain_sse(
    cx: &Cx,
    peer: &Peer,
    body: Vec<u8>,
    sse_limits: SseLimits,
) -> Result<Vec<String>, ModernHttpExecutorError> {
    let chunk_bytes = body.len().max(1);
    drain_sse_in_chunks(cx, peer, body, sse_limits, chunk_bytes).await
}

async fn positive_09_line_endings_and_data_fields(cx: &Cx) {
    // Seven events: CR-, LF- and CRLF-terminated multi-data joins, then the
    // four `data` field spellings the standard distinguishes.
    let mut body = Vec::new();
    body.extend_from_slice(b"data: alpha\rdata: beta\r\r");
    body.extend_from_slice(b"data: alpha\ndata: beta\n\n");
    body.extend_from_slice(b"data: alpha\r\ndata: beta\r\n\r\n");
    body.extend_from_slice(b"data\n\n");
    body.extend_from_slice(b"data:x\n\n");
    body.extend_from_slice(b"data: x\n\n");
    body.extend_from_slice(b"data:  x\n\n");

    // The same bytes, delivered one byte per chunk, seven bytes per chunk, and
    // as one chunk, must dispatch identical payloads: the accepted dialect is
    // frozen to the event-stream algorithm and is independent of chunking.
    let mut by_chunking = Vec::new();
    for chunk_bytes in [1_usize, 7, body.len()] {
        let peer = Peer::bind().await;
        by_chunking.push(
            drain_sse_in_chunks(cx, &peer, body.clone(), limits(), chunk_bytes)
                .await
                .expect("a well-formed event stream must assemble without refusal"),
        );
    }
    assert_eq!(
        by_chunking[0], by_chunking[1],
        "byte-by-byte and seven-byte chunking must agree"
    );
    assert_eq!(
        by_chunking[1], by_chunking[2],
        "seven-byte and whole-body chunking must agree"
    );
    let payloads = by_chunking.pop().expect("three chunkings were collected");

    assert_eq!(
        payloads.len(),
        7,
        "seven events must dispatch in wire order"
    );
    // Line terminators are interchangeable: all three produce the same join.
    assert_eq!(payloads[0], "alpha\nbeta", "bare CR terminates a line");
    assert_eq!(payloads[1], "alpha\nbeta", "bare LF terminates a line");
    assert_eq!(payloads[2], "alpha\nbeta", "CRLF is one terminator");
    // Multiple data lines join with one LF each and the final appended LF is
    // removed exactly once at dispatch.
    assert!(!payloads[1].ends_with('\n'));
    // Field spellings: `data`, `data:`, `data: ` and `data:  `.
    assert_eq!(
        payloads[3], "",
        "a bare `data` field contributes an empty value"
    );
    assert_eq!(payloads[4], "x", "`data:x` keeps its value verbatim");
    assert_eq!(payloads[5], "x", "`data: x` removes exactly one U+0020");
    assert_eq!(
        payloads[6], " x",
        "`data:  x` removes only the first U+0020"
    );
}

async fn negative_09_uppercase_data_field(cx: &Cx) {
    let peer = Peer::bind().await;
    // The sole changed variable is the field name's case on the first event.
    let mut body = Vec::new();
    body.extend_from_slice(b"Data: alpha\n\n");
    body.extend_from_slice(b"data: beta\n\n");

    let payloads = drain_sse(cx, &peer, body, limits())
        .await
        .expect("an inert unknown field must not refuse the stream");

    assert_eq!(
        payloads.len(),
        1,
        "`Data` is an unknown field and dispatches no MCP message"
    );
    assert_eq!(
        payloads[0], "beta",
        "the sibling event is delivered unchanged"
    );
}

// ---------------------------------------------------------------------------
// HTTP-03.10 — comments/empty-data/EOF and inert event/id/retry fields
// ---------------------------------------------------------------------------

async fn positive_10_comments_and_inert_fields(cx: &Cx) {
    let peer = Peer::bind().await;
    let connection = connect(cx, &peer).await;

    let mut first = Vec::new();
    first.extend_from_slice(b": keepalive comment\n");
    first.extend_from_slice(b"\n"); // blank line with no data: no MCP message
    first.extend_from_slice(b"event: message\n");
    first.extend_from_slice(b"id: 42\n");
    first.extend_from_slice(b"retry: 5000\n");
    first.extend_from_slice(b"unknown: ignored\n");
    first.extend_from_slice(b"data: ");
    first.extend_from_slice(&terminal_tool_result(2, "inert-ok"));
    first.extend_from_slice(b"\n\n");

    let (second_wire, ()) = pair(
        async {
            let mut io = peer.accept().await;
            let _ = read_request(&mut io).await;
            begin_sse(&mut io).await;
            write_bytes(&mut io, &first).await;
            end_sse_stream(&mut io).await;

            let mut io = peer.accept().await;
            let wire = read_request(&mut io).await;
            begin_sse(&mut io).await;
            write_bytes(&mut io, b"data: ").await;
            write_bytes(&mut io, &terminal_tool_result(3, "second-ok")).await;
            write_bytes(&mut io, b"\n\n").await;
            end_sse_stream(&mut io).await;
            wire
        },
        async {
            let mut listener = connection
                .open_final_core_listener(
                    cx,
                    "tools/call",
                    tool_call_params("inert_tool"),
                    RequestId::Number(2),
                    limits(),
                )
                .await
                .expect("the inert-field request must reach the peer");
            let event = listener
                .next_event(cx)
                .await
                .expect("comments and inert fields must not refuse the stream")
                .expect("the terminal must arrive");
            assert!(
                matches!(event, ModernHttpFinalCoreEvent::Terminal(_)),
                "comments, blank no-data lines and inert fields produce no MCP message, \
                 so the first delivered event is the terminal"
            );

            let mut second = connection
                .open_final_core_listener(
                    cx,
                    "tools/call",
                    tool_call_params("inert_tool"),
                    RequestId::Number(3),
                    limits(),
                )
                .await
                .expect("the second request must reach the peer");
            let event = second
                .next_event(cx)
                .await
                .expect("the second stream must be admissible")
                .expect("the second terminal must arrive");
            assert!(matches!(event, ModernHttpFinalCoreEvent::Terminal(_)));
        },
    )
    .await;

    // `id: 42` created no resumption state: the next request carries neither
    // spelling of the event-ID resumption header.
    assert!(
        header_values(&second_wire.head, "last-event-id").is_empty(),
        "no event-ID state may be retained across requests: {:?}",
        second_wire.head
    );

    // ---------------------------------------------------------------------
    // Comment flood. Keepalive traffic is bounded: a peer may hold a stream
    // open with colon-comments, but only up to the configured ceiling of
    // CONSECUTIVE non-dispatching lines. A dispatched event resets that budget,
    // which is what lets a well-behaved long-lived stream stay open
    // indefinitely while a silent one cannot.
    // ---------------------------------------------------------------------
    let flood_limits =
        SseLimits::new(4_096, 65_536, KEEPALIVE_CEILING).expect("keepalive-bounded limits");

    // Exactly the ceiling is admitted, twice over, because the dispatched event
    // between the two runs resets the consecutive count to zero.
    let peer = Peer::bind().await;
    let mut body = Vec::new();
    for run in ["alpha", "beta"] {
        for index in 0..KEEPALIVE_CEILING {
            body.extend_from_slice(format!(": keepalive {index}\n").as_bytes());
        }
        body.extend_from_slice(format!("data: {run}\n\n").as_bytes());
    }
    let payloads = drain_sse(cx, &peer, body, flood_limits)
        .await
        .expect("comment runs at exactly the ceiling must be admitted");
    assert_eq!(
        payloads,
        vec!["alpha".to_owned(), "beta".to_owned()],
        "a dispatched event resets the consecutive keepalive budget"
    );

    // Inert fields and blank no-data lines spend the same budget as comments,
    // so a mixed run of ceiling length is admitted on the same rule.
    let peer = Peer::bind().await;
    let mut mixed = Vec::new();
    mixed.extend_from_slice(b": comment\n");
    mixed.extend_from_slice(b"\n");
    mixed.extend_from_slice(b"event: message\n");
    mixed.extend_from_slice(b"id: 7\n");
    mixed.extend_from_slice(b"retry: 1000\n");
    mixed.extend_from_slice(b"unknown: ignored\n");
    mixed.extend_from_slice(b"data: mixed\n\n");
    assert_eq!(
        drain_sse(
            cx,
            &peer,
            mixed,
            SseLimits::new(4_096, 65_536, 6).expect("mixed keepalive limits")
        )
        .await
        .expect("six mixed non-dispatching lines at a ceiling of six must be admitted"),
        vec!["mixed".to_owned()],
    );
}

async fn negative_10_eof_without_blank_line(cx: &Cx) {
    let peer = Peer::bind().await;
    let connection = connect(cx, &peer).await;

    // The sole changed variable is the terminating blank line, which is
    // removed so the stream ends with an unterminated pending event.
    let mut body = Vec::new();
    body.extend_from_slice(b"data: ");
    body.extend_from_slice(&terminal_tool_result(2, "never-dispatched"));
    body.extend_from_slice(b"\n");

    let ((), refusal) = pair(
        async {
            let mut io = peer.accept().await;
            let _ = read_request(&mut io).await;
            begin_sse(&mut io).await;
            write_bytes(&mut io, &body).await;
            end_sse_stream(&mut io).await;
        },
        async {
            let mut listener = connection
                .open_final_core_listener(
                    cx,
                    "tools/call",
                    tool_call_params("eof_tool"),
                    RequestId::Number(2),
                    limits(),
                )
                .await
                .expect("the request must reach the peer");
            listener
                .next_event(cx)
                .await
                .err()
                .expect("an unterminated pending event must never be dispatched")
        },
    )
    .await;

    match refusal {
        ModernHttpFinalCoreListenError::EndOfStream { framing } => {
            let framing = framing.expect("end-of-stream framing must be reported");
            assert!(
                framing.discarded_pending_event,
                "the pending event must be discarded, never completed by a synthesized blank line"
            );
        }
        other => panic!("expected a typed end-of-stream refusal, saw {other:?}"),
    }
    peer.assert_no_further_connection();

    // ---------------------------------------------------------------------
    // Comment-flood planted negative. The accepted case is KEEPALIVE_CEILING
    // consecutive colon-comments followed by a dispatching event. The sole
    // changed variable is ONE additional comment line: same ceiling, same
    // event, same ordering.
    // ---------------------------------------------------------------------
    let flood_limits =
        SseLimits::new(4_096, 65_536, KEEPALIVE_CEILING).expect("keepalive-bounded limits");

    let comment_run = |count: usize| {
        let mut body = Vec::new();
        for index in 0..count {
            body.extend_from_slice(format!(": keepalive {index}\n").as_bytes());
        }
        body.extend_from_slice(b"data: alpha\n\n");
        body
    };

    // Accepted at exactly the ceiling.
    let peer = Peer::bind().await;
    assert_eq!(
        drain_sse(cx, &peer, comment_run(KEEPALIVE_CEILING), flood_limits)
            .await
            .expect("the ceiling itself must be admitted"),
        vec!["alpha".to_owned()],
    );

    // One more comment line, and nothing else, must fail closed.
    let peer = Peer::bind().await;
    let refusal = drain_sse(cx, &peer, comment_run(KEEPALIVE_CEILING + 1), flood_limits)
        .await
        .err()
        .expect("one comment line over the ceiling must fail closed");
    assert!(
        matches!(
            refusal,
            ModernHttpExecutorError::SseParse(SseParseError::KeepaliveFlood { limit_lines })
                if limit_lines == KEEPALIVE_CEILING
        ),
        "expected a typed keepalive-flood refusal naming the ceiling, saw {refusal:?}"
    );
    peer.assert_no_further_connection();

    // The refusal is about CONSECUTIVE lines, not a total: the same number of
    // comments split by a dispatching event is still admitted, so the flood
    // bound cannot be mistaken for a lifetime quota on keepalive traffic.
    let peer = Peer::bind().await;
    let mut split_run = Vec::new();
    for index in 0..KEEPALIVE_CEILING {
        split_run.extend_from_slice(format!(": keepalive {index}\n").as_bytes());
    }
    split_run.extend_from_slice(b"data: alpha\n\n");
    for index in 0..KEEPALIVE_CEILING {
        split_run.extend_from_slice(format!(": keepalive {index}\n").as_bytes());
    }
    split_run.extend_from_slice(b"data: beta\n\n");
    assert_eq!(
        drain_sse(cx, &peer, split_run, flood_limits)
            .await
            .expect("a dispatched event resets the consecutive budget"),
        vec!["alpha".to_owned(), "beta".to_owned()],
    );
}

// ---------------------------------------------------------------------------
// HTTP-03.11 — line/event/message and memory bounds
// ---------------------------------------------------------------------------

/// Builds one CRLF-framed `data: ` event carrying `payload_bytes` ASCII octets
/// per data line.
fn sized_event(payload_bytes: usize, data_lines: usize) -> Vec<u8> {
    let mut body = Vec::new();
    for _ in 0..data_lines {
        body.extend_from_slice(b"data: ");
        body.extend(std::iter::repeat_n(b'a', payload_bytes));
        body.extend_from_slice(b"\r\n");
    }
    body.extend_from_slice(b"\r\n");
    body
}

/// The aggregate memory ceilings this target freezes, transcribed independently
/// of the public constants they check.
///
/// Spelled as literals on purpose. `assert_eq!(MAX_X, MAX_X)` anchors the
/// assertion to the value under test (RH-5) and can never fail: widening the
/// progress queue from 64 to 4_096 would still pass. An independently
/// transcribed literal fails on exactly that change, which is the failure this
/// half of the criterion exists to catch.
///
/// Freezing them is legitimate because each one DECLARES A DESIGN LIMIT rather
/// than MEASURING MUTABLE CONTENT. None of them moves as the crate grows, so
/// none of them rots.
const DECLARED_PENDING_SSE_EVENT_CEILING: usize = 128;
const DECLARED_PENDING_SSE_EVENT_BYTE_CEILING: usize = 64 * 1024;
const DECLARED_PROGRESS_QUEUE_CEILING: usize = 64;
const DECLARED_PROBE_BODY_BYTE_CEILING: usize = 64 * 1024;

/// Builds one SSE body carrying `progress_events` request-scoped progress
/// notifications followed by exactly one terminal result.
///
/// The positive and the planted negative share this builder, so the only thing
/// that differs between them is `progress_events`.
fn progress_then_terminal_body(
    marker: &ProgressMarker,
    progress_events: usize,
    request_id: u64,
) -> Vec<u8> {
    let mut body = Vec::new();
    for progress in 1..=progress_events {
        body.extend_from_slice(b"data: ");
        body.extend_from_slice(&progress_notification(marker, progress as u64));
        body.extend_from_slice(b"\n\n");
    }
    body.extend_from_slice(b"data: ");
    body.extend_from_slice(&terminal_tool_result(request_id, "progress-queue-terminal"));
    body.extend_from_slice(b"\n\n");
    body
}

/// Runs one final core request whose SSE response carries `progress_events`
/// progress notifications ahead of its terminal, and returns what the caller
/// observed.
///
/// The whole body is written as a single chunk. That is deliberate on both
/// counts: the progress queue is a per-request collector rather than a
/// per-frame one, so it is invariant to chunk framing, and writing once keeps
/// the server's remaining writes from racing the client's refusal on the
/// planted-negative path.
async fn collect_with_progress(
    cx: &Cx,
    progress_events: usize,
) -> Result<ModernHttpFinalCoreCollector, ModernHttpFinalCoreListenError> {
    const REQUEST_ID: u64 = 11;
    let peer = Peer::bind().await;
    let connection = connect(cx, &peer).await;
    let marker = ProgressMarker::from("http-03-a-progress-queue");
    let body = progress_then_terminal_body(&marker, progress_events, REQUEST_ID);

    // The fixture stays strictly under both SSE aggregate ceilings, so an
    // outcome here can only be the progress queue's and never a pending-event
    // bound wearing its name.
    assert!(
        progress_events + 1 < DECLARED_PENDING_SSE_EVENT_CEILING,
        "the fixture must not reach the pending-event count ceiling"
    );
    assert!(
        body.len() < DECLARED_PENDING_SSE_EVENT_BYTE_CEILING,
        "the fixture must not reach the pending-event byte ceiling"
    );

    let ((), collected) = pair(
        async {
            let mut io = peer.accept().await;
            let _ = read_request(&mut io).await;
            begin_sse(&mut io).await;
            write_bytes(&mut io, &body).await;
            end_sse_stream(&mut io).await;
        },
        async {
            connection
                .open_final_core_listener(
                    cx,
                    "tools/call",
                    serde_json::json!({
                        "name": "progress_tool",
                        "arguments": {},
                        // Cloned: `json!` serializes by value, and the marker is
                        // still borrowed by the body built above.
                        "_meta": {"progressToken": marker.clone()},
                    }),
                    RequestId::Number(REQUEST_ID),
                    limits(),
                )
                .await
                .expect("the progress request must reach the peer")
                .collect(cx)
                .await
        },
    )
    .await;
    collected
}

async fn positive_11_bounds(cx: &Cx) {
    // Line ceiling, exactly N. A 4_090-octet payload makes a `data: ` line of
    // 4_096 raw octets against a 4_096-octet line ceiling: N+6 charged octets,
    // N+8 wire bytes under CRLF, N+10 for the whole event with its blank line.
    let line_ceiling = 4_096_usize;
    // N comes from the case table so the executed byte count and the row that
    // documents it cannot drift apart.
    let payload = case_bytes(&POSITIVE_CASES, "HTTP-03.11");
    assert_eq!(payload, line_ceiling - b"data: ".len());
    assert_eq!(payload, 4_090);
    let body = sized_event(payload, 1);
    assert_eq!(
        body.len(),
        payload + 10,
        "the complete CRLF-framed event occupies N+10 wire bytes"
    );
    assert_eq!(
        body.len() - 2,
        payload + 8,
        "the `data: ` line occupies N+8 wire bytes under CRLF"
    );

    let peer = Peer::bind().await;
    let payloads = drain_sse(
        cx,
        &peer,
        body,
        SseLimits::new(line_ceiling, 65_536, 64).expect("line-ceiling limits"),
    )
    .await
    .expect("a line at exactly the ceiling must be admitted");
    assert_eq!(payloads.len(), 1);
    assert_eq!(payloads[0].len(), payload);

    // Event ceiling, exactly N. Two 4_090-octet data lines charge
    // 2 * (4_090 + 6) = 8_192 raw octets against an 8_192-octet event ceiling.
    let event_ceiling = 8_192_usize;
    assert_eq!(2 * (payload + b"data: ".len()), event_ceiling);
    let peer = Peer::bind().await;
    let payloads = drain_sse(
        cx,
        &peer,
        sized_event(payload, 2),
        SseLimits::new(line_ceiling, event_ceiling, 64).expect("event-ceiling limits"),
    )
    .await
    .expect("an event at exactly the ceiling must be admitted");
    assert_eq!(payloads.len(), 1);
    assert_eq!(
        payloads[0].len(),
        payload * 2 + 1,
        "two data lines join with exactly one LF"
    );
    // -----------------------------------------------------------------------
    // The aggregate memory ceilings, proved from outside the crate.
    //
    // All four are public and enforced on shipped paths, but every proof of
    // them lived in `http_executor.rs`'s `#[cfg(test)]` module. A `cfg(test)`
    // assertion cannot prove shipped behaviour (PL-3), and it cannot notice
    // that a ceiling stopped being reachable by a consumer at all. This target
    // is an external consumer, so it can.
    // -----------------------------------------------------------------------
    assert_eq!(
        MAX_PENDING_MODERN_HTTP_SSE_EVENTS,
        DECLARED_PENDING_SSE_EVENT_CEILING
    );
    assert_eq!(
        MAX_PENDING_MODERN_HTTP_SSE_EVENT_BYTES,
        DECLARED_PENDING_SSE_EVENT_BYTE_CEILING
    );
    assert_eq!(
        MAX_QUEUED_FINAL_HTTP_PROGRESS_NOTIFICATIONS,
        DECLARED_PROGRESS_QUEUE_CEILING
    );
    assert_eq!(
        MAX_MODERN_HTTP_PROBE_BODY_BYTES,
        DECLARED_PROBE_BODY_BYTE_CEILING
    );

    // Progress queue, exactly N. Sixty-four request-scoped progress
    // notifications ahead of one terminal are all delivered, in order, to the
    // caller that owns them, and the terminal still arrives.
    let collected = collect_with_progress(cx, DECLARED_PROGRESS_QUEUE_CEILING)
        .await
        .expect("a progress queue at exactly the ceiling must be admitted");
    assert_eq!(
        collected.progress_notifications.len(),
        DECLARED_PROGRESS_QUEUE_CEILING,
        "every queued progress notification reaches its own caller"
    );
    assert_eq!(collected.request_id, RequestId::Number(11));
    for (index, progress) in collected.progress_notifications.iter().enumerate() {
        assert_eq!(progress.progress.as_str(), (index + 1).to_string());
    }
}

async fn negative_11_one_byte_over_bounds(cx: &Cx) {
    let line_ceiling = 4_096_usize;
    let payload = case_bytes(&POSITIVE_CASES, "HTTP-03.11");
    let over_payload = case_bytes(&NEGATIVE_CASES, "HTTP-03.11");
    assert_eq!(
        over_payload,
        payload + 1,
        "the planted negative is exactly N+1"
    );

    // The sole changed variable is one payload byte: N becomes N+1, so the
    // `data: ` line occupies 4_097 raw octets against a 4_096 ceiling.
    let peer = Peer::bind().await;
    let refusal = drain_sse(
        cx,
        &peer,
        sized_event(over_payload, 1),
        SseLimits::new(line_ceiling, 65_536, 64).expect("line-ceiling limits"),
    )
    .await
    .err()
    .expect("a line one octet over the ceiling must be refused");
    assert!(
        matches!(
            refusal,
            ModernHttpExecutorError::SseParse(SseParseError::LineTooLong { limit_bytes })
                if limit_bytes == line_ceiling
        ),
        "expected a typed line-bound refusal, saw {refusal:?}"
    );
    peer.assert_no_further_connection();

    // The sole changed variable is one event-budget byte: the same two-line
    // event is charged 8_192 raw octets against an 8_191-octet ceiling.
    let peer = Peer::bind().await;
    let event_ceiling = 8_191_usize;
    let refusal = drain_sse(
        cx,
        &peer,
        sized_event(payload, 2),
        SseLimits::new(line_ceiling, event_ceiling, 64).expect("event-ceiling limits"),
    )
    .await
    .err()
    .expect("an event one octet over the ceiling must be refused");
    assert!(
        matches!(
            refusal,
            ModernHttpExecutorError::SseParse(SseParseError::EventTooLarge { limit_bytes })
                if limit_bytes == event_ceiling
        ),
        "expected a typed event-bound refusal, saw {refusal:?}"
    );
    peer.assert_no_further_connection();
    // The sole changed variable is one queued progress notification: N becomes
    // N+1 ahead of a byte-identical terminal on an otherwise identical stream.
    // The framing, the marker, the request ID, the chunking and the terminal
    // are all unchanged.
    let refusal = collect_with_progress(cx, DECLARED_PROGRESS_QUEUE_CEILING + 1)
        .await
        .err()
        .expect("a progress queue one notification over the ceiling must be refused");
    assert!(
        matches!(refusal, ModernHttpFinalCoreListenError::ProgressQueueFull),
        "expected a typed progress-queue refusal, saw {refusal:?}"
    );
}

// ---------------------------------------------------------------------------
// HTTP-03.12 — malformed/invalid-direction response isolation
// ---------------------------------------------------------------------------

/// A JSON-RPC message the server may not originate on a request-scoped MCP
/// response stream: an independent server request carrying its own ID.
fn independent_server_request() -> Vec<u8> {
    serde_json::to_vec(&serde_json::json!({
        "jsonrpc": "2.0",
        "id": 900,
        "method": "sampling/createMessage",
        "params": {},
    }))
    .expect("the reverse-request fixture must serialize")
}

async fn positive_12_response_isolation(cx: &Cx) {
    let peer = Peer::bind().await;
    let connection = connect(cx, &peer).await;

    let ((), ()) = pair(
        async {
            let mut first = peer.accept().await;
            let _ = read_request(&mut first).await;
            begin_sse(&mut first).await;

            let mut second = peer.accept().await;
            let _ = read_request(&mut second).await;
            begin_sse(&mut second).await;
            write_bytes(&mut second, b"data: ").await;
            write_bytes(&mut second, &terminal_tool_result(3, "sibling-ok")).await;
            write_bytes(&mut second, b"\n\n").await;
            end_sse_stream(&mut second).await;

            write_bytes(&mut first, b"data: ").await;
            write_bytes(&mut first, &terminal_tool_result(2, "owner-ok")).await;
            write_bytes(&mut first, b"\n\n").await;
            end_sse_stream(&mut first).await;
        },
        async {
            let mut owner = connection
                .open_final_core_listener(
                    cx,
                    "tools/call",
                    tool_call_params("owner_tool"),
                    RequestId::Number(2),
                    limits(),
                )
                .await
                .expect("the first request must reach the peer");
            let mut sibling = connection
                .open_final_core_listener(
                    cx,
                    "tools/call",
                    tool_call_params("sibling_tool"),
                    RequestId::Number(3),
                    limits(),
                )
                .await
                .expect("the second request must reach the peer");

            let sibling_event = sibling
                .next_event(cx)
                .await
                .expect("the sibling stream must be admissible")
                .expect("the sibling terminal must arrive");
            assert!(matches!(
                sibling_event,
                ModernHttpFinalCoreEvent::Terminal(_)
            ));

            let owner_event = owner
                .next_event(cx)
                .await
                .expect("the owning stream must be admissible")
                .expect("the owning terminal must arrive");
            assert!(matches!(owner_event, ModernHttpFinalCoreEvent::Terminal(_)));
        },
    )
    .await;
}

async fn negative_12_invalid_direction(cx: &Cx) {
    let peer = Peer::bind().await;
    let connection = connect(cx, &peer).await;

    let ((), ()) = pair(
        async {
            let mut first = peer.accept().await;
            let _ = read_request(&mut first).await;
            begin_sse(&mut first).await;

            let mut second = peer.accept().await;
            let _ = read_request(&mut second).await;
            begin_sse(&mut second).await;
            write_bytes(&mut second, b"data: ").await;
            write_bytes(&mut second, &terminal_tool_result(3, "sibling-ok")).await;
            write_bytes(&mut second, b"\n\n").await;
            end_sse_stream(&mut second).await;

            // The sole changed variable is the direction of the owning
            // stream's message: an admissible server notification becomes an
            // independent server request.
            write_bytes(&mut first, b"data: ").await;
            write_bytes(&mut first, &independent_server_request()).await;
            write_bytes(&mut first, b"\n\n").await;
            end_sse_stream(&mut first).await;
        },
        async {
            let mut owner = connection
                .open_final_core_listener(
                    cx,
                    "tools/call",
                    tool_call_params("owner_tool"),
                    RequestId::Number(2),
                    limits(),
                )
                .await
                .expect("the first request must reach the peer");
            let mut sibling = connection
                .open_final_core_listener(
                    cx,
                    "tools/call",
                    tool_call_params("sibling_tool"),
                    RequestId::Number(3),
                    limits(),
                )
                .await
                .expect("the second request must reach the peer");

            let sibling_event = sibling
                .next_event(cx)
                .await
                .expect("the sibling stream must remain unaffected")
                .expect("the sibling terminal must arrive");
            assert!(
                matches!(sibling_event, ModernHttpFinalCoreEvent::Terminal(_)),
                "only the owning execution may fail"
            );

            let refusal = owner
                .next_event(cx)
                .await
                .err()
                .expect("an independent server request must be refused");
            assert!(
                matches!(
                    refusal,
                    ModernHttpFinalCoreListenError::NotificationAdmission(_)
                        | ModernHttpFinalCoreListenError::JsonRpcAdmission(_)
                ),
                "expected a typed server-direction refusal, saw {refusal:?}"
            );

            // The sibling is still usable after the owner failed.
            assert!(
                sibling
                    .next_event(cx)
                    .await
                    .expect("a terminated sibling reports no further event")
                    .is_none()
            );
        },
    )
    .await;

    // No JSON-RPC parse/invalid-request response was posted back to the
    // server: answering would require opening another socket.
    peer.assert_no_further_connection();
}

// ---------------------------------------------------------------------------
// HTTP-03.13 — JSON-or-SSE one terminal outcome with request-scoped progress
// ---------------------------------------------------------------------------

async fn positive_13_terminal_outcome_and_progress(cx: &Cx) {
    let peer = Peer::bind().await;
    let mut connection = connect(cx, &peer).await;
    let marker = ProgressMarker::from("http-03-a-progress");
    let server_marker = marker.clone();

    let (wire, ()) = pair(
        async {
            // SSE lane: request-scoped progress then exactly one terminal.
            let mut sse = peer.accept().await;
            let wire = read_request(&mut sse).await;
            begin_sse(&mut sse).await;
            for progress in 1..=3 {
                write_bytes(&mut sse, b"data: ").await;
                write_bytes(&mut sse, &progress_notification(&server_marker, progress)).await;
                write_bytes(&mut sse, b"\n\n").await;
            }
            write_bytes(&mut sse, b"data: ").await;
            write_bytes(&mut sse, &terminal_tool_result(2, "sse-terminal")).await;
            write_bytes(&mut sse, b"\n\n").await;
            end_sse_stream(&mut sse).await;

            // JSON lane: the same client surface, one immediate terminal.
            let mut json = peer.accept().await;
            let _ = read_request(&mut json).await;
            write_json_response(
                &mut json,
                br#"{"jsonrpc":"2.0","id":3,"result":{"resultType":"complete","tools":[],"ttlMs":0,"cacheScope":"private"}}"#,
            )
            .await;
            end_stream(&mut json).await;
            wire
        },
        async {
            let collected = connection
                .open_final_core_listener(
                    cx,
                    "tools/call",
                    serde_json::json!({
                        "name": "progress_tool",
                        "arguments": {},
                        // Cloned: `json!` serializes by value, and the marker is
                        // still needed to prove progress ownership afterwards.
                        "_meta": {"progressToken": marker.clone()},
                    }),
                    RequestId::Number(2),
                    limits(),
                )
                .await
                .expect("the progress request must reach the peer")
                .collect(cx)
                .await
                .expect("the SSE lane must produce exactly one terminal outcome");

            assert_eq!(collected.request_id, RequestId::Number(2));
            assert_eq!(
                collected.progress_notifications.len(),
                3,
                "every request-scoped progress notification reaches its own caller"
            );
            for (index, progress) in collected.progress_notifications.iter().enumerate() {
                assert_eq!(
                    progress.progress_token, marker,
                    "progress ownership is bound to the request that opened the stream"
                );
                assert_eq!(progress.progress.as_str(), (index + 1).to_string());
            }

            let response = connection
                .request_json(
                    cx,
                    "tools/list",
                    serde_json::json!({}),
                    RequestId::Number(3),
                    64 * 1024,
                )
                .await
                .expect("the JSON lane must produce exactly one terminal outcome");
            assert_eq!(response.id, Some(RequestId::Number(3)));
            assert!(response.error.is_none());
        },
    )
    .await;

    assert_eq!(exactly_one_header(&wire.head, "Mcp-Method"), "tools/call");
    let body: serde_json::Value =
        serde_json::from_slice(&wire.body).expect("the request body must be JSON-RPC");
    assert_eq!(
        body["params"]["_meta"]["progressToken"],
        serde_json::to_value(&marker).expect("the marker must serialize"),
        "the progress token travels with the request that owns it"
    );
}

async fn negative_13_terminal_id_mismatch(cx: &Cx) {
    let peer = Peer::bind().await;
    let mut connection = connect(cx, &peer).await;

    // The sole changed variable is the terminal response ID.
    let ((), refusal) = pair(
        async {
            let mut io = peer.accept().await;
            let _ = read_request(&mut io).await;
            write_json_response(
                &mut io,
                br#"{"jsonrpc":"2.0","id":99,"result":{"resultType":"complete","tools":[],"ttlMs":0,"cacheScope":"private"}}"#,
            )
            .await;
            end_stream(&mut io).await;
        },
        async {
            connection
                .request_json(
                    cx,
                    "tools/list",
                    serde_json::json!({}),
                    RequestId::Number(3),
                    64 * 1024,
                )
                .await
                .expect_err("an uncorrelated terminal must not be delivered")
        },
    )
    .await;

    assert!(
        matches!(
            &refusal,
            ClientHttpConnectionError::ResponseIdMismatch { expected, actual }
                if *expected == RequestId::Number(3)
                    && *actual == Some(RequestId::Number(99))
        ),
        "expected a typed correlation refusal, saw {refusal:?}"
    );
    peer.assert_no_further_connection();
}
