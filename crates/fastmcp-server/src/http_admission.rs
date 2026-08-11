//! HTTP-02 A: modern server HTTP admission and validation pipeline.
//!
//! One small, auditable authority boundary in front of authentication and
//! application dispatch. The pipeline admits exactly one HTTP shape — a
//! byte-exact `POST` to the one configured MCP endpoint path carrying a
//! strict MCP 2026-07-28 JSON-RPC request — and, for each admitted request,
//! selects exactly one response representation (immediate JSON or a
//! request-scoped SSE body) from the request's `Accept` fields.
//!
//! Deterministic rejection precedence, checked in this order and always
//! before body parsing can influence anything downstream:
//!
//! 1. endpoint path (byte-exact), 2. method (byte-exact `POST`),
//! 3. header count/byte bounds, 4. singleton-header duplication,
//! 5. request media type, 6. request content coding,
//! 7. `Accept` representation negotiation,
//! 8. bounded raw JSON-RPC admission (UTF-8/BOM/nesting, and top-level
//!    arrays rejected — a batch is never iterated or partially dispatched,
//!    even an array of one valid request),
//! 9. strict envelope decode, 10. request-shape (a response or notification
//!    is not admissible here), 11. final protocol-version and
//!    `Mcp-Method`/`Mcp-Name` header-body mirror admission.
//!
//! Every rejection is side-effect free: no authentication, no dispatch, no
//! response-writer allocation, no state mutation. The pipeline is a pure
//! function over `(method, path, headers, body)`; downstream ownership —
//! authentication, authorization, catalog resolution, execution, and the
//! actual response writer — remains with the dispatcher and later HTTP-02
//! slices. Header handling here is deliberately minimal and local; the
//! shared HDR-01 routing-header contract replaces it at integration when
//! that package lands.
//!
//! Bounds are caller-supplied with no ambient defaults: the frozen central
//! ceilings must be wired explicitly by the integration layer.

use core::fmt;

use fastmcp_protocol::{
    FINAL_PROTOCOL_VERSION_META_KEY, FinalHttpRequestMetadata, FinalProtocolVersion,
    JsonRpcAdmissionError, JsonRpcMessage, JsonRpcRequest, MCP_METHOD_HEADER, MCP_NAME_HEADER,
    MCP_PROTOCOL_VERSION_HEADER, RawJsonAdmissionError, RequestAdmissionError,
    RequestVersionMetadata, admit_final_http_request, decode_strict_jsonrpc_message,
};
use serde_json::Value;

/// The one admitted HTTP method, compared byte-exactly.
pub const MODERN_MCP_HTTP_METHOD: &str = "POST";

/// Maximum ignored empty RFC 9110 list elements in one `Content-Encoding`
/// value, mirroring the client-side bound: framing noise stays finite.
const MAX_IGNORED_CONTENT_ENCODING_EMPTY_ELEMENTS: usize = 16;

/// Maximum parsed `Accept` media-range members across all `Accept` field
/// lines. `Accept` is a list field, so multiple lines merge; the bound keeps
/// negotiation work finite regardless.
const MAX_ACCEPT_MEMBERS: usize = 16;

/// Singleton request fields this boundary refuses to see twice.
const SINGLETON_HEADERS: [&str; 6] = [
    "content-type",
    "content-length",
    "content-encoding",
    MCP_PROTOCOL_VERSION_HEADER,
    MCP_METHOD_HEADER,
    MCP_NAME_HEADER,
];

/// Explicit, caller-supplied bounds for one admission evaluation.
///
/// There is deliberately no `Default`: the frozen numeric ceilings belong to
/// the central bounds package and are wired in explicitly at integration.
#[allow(
    clippy::struct_field_names,
    reason = "the private fields intentionally mirror the public constructor's distinct admission ceilings"
)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HttpAdmissionLimits {
    max_header_count: usize,
    max_header_block_bytes: usize,
    max_body_bytes: usize,
}

impl HttpAdmissionLimits {
    /// Constructs bounds; every ceiling must be nonzero.
    #[must_use]
    pub const fn new(
        max_header_count: usize,
        max_header_block_bytes: usize,
        max_body_bytes: usize,
    ) -> Option<Self> {
        if max_header_count == 0 || max_header_block_bytes == 0 || max_body_bytes == 0 {
            return None;
        }
        Some(Self {
            max_header_count,
            max_header_block_bytes,
            max_body_bytes,
        })
    }

    /// Maximum number of request header fields.
    #[must_use]
    pub const fn max_header_count(&self) -> usize {
        self.max_header_count
    }

    /// Maximum total bytes across all header names and values.
    #[must_use]
    pub const fn max_header_block_bytes(&self) -> usize {
        self.max_header_block_bytes
    }

    /// Maximum request body bytes, also enforced by raw JSON admission.
    #[must_use]
    pub const fn max_body_bytes(&self) -> usize {
        self.max_body_bytes
    }
}

/// The one immutable configured MCP endpoint this boundary serves.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HttpEndpointConfig {
    path: String,
    limits: HttpAdmissionLimits,
}

impl HttpEndpointConfig {
    /// Binds the configured MCP path at construction. The path must begin
    /// with `/` and contain no whitespace or control bytes; anything else is
    /// a configuration error, not a runtime branch.
    #[must_use]
    pub fn new(path: impl Into<String>, limits: HttpAdmissionLimits) -> Option<Self> {
        let path = path.into();
        if !path.starts_with('/')
            || path
                .bytes()
                .any(|byte| byte.is_ascii_control() || byte == b' ')
        {
            return None;
        }
        Some(Self { path, limits })
    }

    /// Returns the immutable configured endpoint path.
    #[must_use]
    pub fn path(&self) -> &str {
        &self.path
    }

    /// Returns the configured admission bounds.
    #[must_use]
    pub const fn limits(&self) -> HttpAdmissionLimits {
        self.limits
    }
}

/// The exactly-one response representation selected for an admitted request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResponseRepresentation {
    /// One immediate `application/json` response body.
    Json,
    /// One request-scoped `text/event-stream` response body that closes
    /// after this request's terminal outcome and creates no state beyond
    /// the request's response writer.
    RequestScopedSse,
}

/// A fully admitted modern POST, ready for authentication and dispatch.
#[derive(Debug, Clone)]
pub struct AdmittedModernPost {
    request: JsonRpcRequest,
    protocol_version: FinalProtocolVersion,
    representation: ResponseRepresentation,
}

impl AdmittedModernPost {
    /// Returns the validated JSON-RPC request.
    #[must_use]
    pub const fn request(&self) -> &JsonRpcRequest {
        &self.request
    }

    /// Returns the admitted final protocol version.
    #[must_use]
    pub const fn protocol_version(&self) -> FinalProtocolVersion {
        self.protocol_version
    }

    /// Returns the representation selected from the request's `Accept`.
    #[must_use]
    pub const fn representation(&self) -> ResponseRepresentation {
        self.representation
    }

    /// Consumes the admission and yields the request for dispatch.
    #[must_use]
    pub fn into_request(self) -> JsonRpcRequest {
        self.request
    }
}

/// Typed, side-effect-free rejections in deterministic precedence order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ModernPostRejection {
    /// The request targeted a different path than the one configured MCP
    /// endpoint. The route's fixed empty-body rejection applies.
    EndpointMismatch,
    /// The request used a method other than byte-exact `POST`.
    MethodNotAllowed,
    /// The request exceeded the header-count ceiling.
    TooManyHeaders {
        /// The configured header-count ceiling.
        limit: usize,
    },
    /// The request exceeded the total header-byte ceiling.
    HeaderBlockTooLarge {
        /// The configured header-block ceiling in bytes.
        limit: usize,
    },
    /// A singleton request field appeared more than once.
    DuplicateSingletonHeader {
        /// The lowercase singleton field name.
        name: &'static str,
    },
    /// The request media type is not `application/json` (with at most one
    /// `charset=utf-8` parameter).
    UnsupportedMediaType,
    /// The request content coding is neither absent nor singleton identity.
    UnsupportedContentCoding,
    /// Neither JSON nor SSE is acceptable to the request's `Accept` fields.
    NotAcceptable,
    /// Bounded raw JSON-RPC admission refused the body before parsing,
    /// including every top-level array.
    Raw(RawJsonAdmissionError),
    /// The admitted raw document is not a strict JSON-RPC envelope.
    InvalidEnvelope,
    /// The strict envelope is a response or notification, which this
    /// request-admission boundary does not accept.
    NotARequest,
    /// Final protocol-version or header/body mirror admission refused the
    /// request.
    FinalAdmission(RequestAdmissionError),
}

impl fmt::Display for ModernPostRejection {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EndpointMismatch => formatter.write_str("request path is not the MCP endpoint"),
            Self::MethodNotAllowed => formatter.write_str("only byte-exact POST is admitted"),
            Self::TooManyHeaders { limit } => {
                write!(formatter, "request exceeds {limit} header fields")
            }
            Self::HeaderBlockTooLarge { limit } => {
                write!(formatter, "request headers exceed {limit} bytes")
            }
            Self::DuplicateSingletonHeader { name } => {
                write!(formatter, "singleton header {name} repeats")
            }
            Self::UnsupportedMediaType => {
                formatter.write_str("request media type is not application/json")
            }
            Self::UnsupportedContentCoding => {
                formatter.write_str("request content coding is not identity")
            }
            Self::NotAcceptable => {
                formatter.write_str("neither JSON nor SSE is acceptable to this request")
            }
            Self::Raw(error) => write!(formatter, "raw JSON-RPC admission refused: {error:?}"),
            Self::InvalidEnvelope => formatter.write_str("body is not a strict JSON-RPC envelope"),
            Self::NotARequest => formatter.write_str("body is not a JSON-RPC request with an id"),
            Self::FinalAdmission(error) => {
                write!(formatter, "final request admission refused: {error:?}")
            }
        }
    }
}

impl std::error::Error for ModernPostRejection {}

/// Admits one modern MCP POST or returns the first typed rejection in
/// precedence order.
///
/// The pipeline is pure: it allocates no response state, performs no
/// authentication, and dispatches nothing. On success the caller hands the
/// admitted request and its request-local representation to authentication
/// and the modern dispatcher.
///
/// # Errors
///
/// Returns the first failing [`ModernPostRejection`] in the documented
/// precedence order; every rejection is side-effect free.
pub fn admit_modern_post(
    config: &HttpEndpointConfig,
    method: &str,
    path: &str,
    headers: &[(String, String)],
    body: &[u8],
) -> Result<AdmittedModernPost, ModernPostRejection> {
    if path != config.path() {
        return Err(ModernPostRejection::EndpointMismatch);
    }
    if method != MODERN_MCP_HTTP_METHOD {
        return Err(ModernPostRejection::MethodNotAllowed);
    }

    let limits = config.limits();
    if headers.len() > limits.max_header_count() {
        return Err(ModernPostRejection::TooManyHeaders {
            limit: limits.max_header_count(),
        });
    }
    let header_block_bytes: usize = headers
        .iter()
        .map(|(name, value)| name.len().saturating_add(value.len()))
        .fold(0_usize, usize::saturating_add);
    if header_block_bytes > limits.max_header_block_bytes() {
        return Err(ModernPostRejection::HeaderBlockTooLarge {
            limit: limits.max_header_block_bytes(),
        });
    }
    for name in SINGLETON_HEADERS {
        let occurrences = headers
            .iter()
            .filter(|(header, _)| header.eq_ignore_ascii_case(name))
            .count();
        if occurrences > 1 {
            return Err(ModernPostRejection::DuplicateSingletonHeader { name });
        }
    }

    let content_type = singleton_value(headers, "content-type");
    if !content_type.is_some_and(is_admitted_json_media_type) {
        return Err(ModernPostRejection::UnsupportedMediaType);
    }
    if let Some(coding) = singleton_value(headers, "content-encoding")
        && !is_singleton_identity_coding(coding)
    {
        return Err(ModernPostRejection::UnsupportedContentCoding);
    }

    let representation = negotiate_representation(headers)?;

    decode_strict_jsonrpc_message(body, limits.max_body_bytes())
        .map_err(|error| match error {
            JsonRpcAdmissionError::Raw(raw) => ModernPostRejection::Raw(raw),
            _ => ModernPostRejection::InvalidEnvelope,
        })
        .and_then(|message| match message {
            JsonRpcMessage::Request(request) if request.id.is_some() => Ok(request),
            JsonRpcMessage::Request(_) | JsonRpcMessage::Response(_) => {
                Err(ModernPostRejection::NotARequest)
            }
        })
        .and_then(|request| {
            let protocol_version = {
                let metadata = FinalHttpRequestMetadata {
                    version: RequestVersionMetadata {
                        header_version: singleton_value(headers, MCP_PROTOCOL_VERSION_HEADER),
                        body_version: body_protocol_version(&request),
                    },
                    header_method: singleton_value(headers, MCP_METHOD_HEADER),
                    body_method: Some(request.method.as_str()),
                    header_name: singleton_value(headers, MCP_NAME_HEADER),
                    body_name: body_mirror_name(&request),
                };
                admit_final_http_request(metadata)
                    .map_err(ModernPostRejection::FinalAdmission)?
                    .protocol_version()
            };
            Ok(AdmittedModernPost {
                request,
                protocol_version,
                representation,
            })
        })
}

fn singleton_value<'a>(headers: &'a [(String, String)], name: &str) -> Option<&'a str> {
    headers
        .iter()
        .find(|(header, _)| header.eq_ignore_ascii_case(name))
        .map(|(_, value)| value.as_str())
}

fn trim_http_ows(value: &str) -> &str {
    value.trim_matches([' ', '\t'])
}

/// Accepts exactly `application/json`, optionally with one
/// `charset=utf-8` parameter, ASCII-case-insensitively.
fn is_admitted_json_media_type(value: &str) -> bool {
    let mut parts = value.split(';');
    let Some(essence) = parts.next().map(trim_http_ows) else {
        return false;
    };
    if !essence.eq_ignore_ascii_case("application/json") {
        return false;
    }
    let Some(parameter) = parts.next() else {
        return true;
    };
    if parts.next().is_some() {
        return false;
    }
    let Some((name, charset)) = trim_http_ows(parameter).split_once('=') else {
        return false;
    };
    trim_http_ows(name).eq_ignore_ascii_case("charset")
        && trim_http_ows(charset).eq_ignore_ascii_case("utf-8")
}

/// Accepts an absent header at the caller; a present value must reduce to
/// exactly one semantic `identity` token after ignoring a bounded number of
/// empty RFC 9110 list elements.
fn is_singleton_identity_coding(value: &str) -> bool {
    let mut ignored_empty_elements = 0_usize;
    let mut semantic_codings = 0_usize;
    for element in value.split(',') {
        let element = trim_http_ows(element);
        if element.is_empty() {
            ignored_empty_elements += 1;
            if ignored_empty_elements > MAX_IGNORED_CONTENT_ENCODING_EMPTY_ELEMENTS {
                return false;
            }
            continue;
        }
        if !element.eq_ignore_ascii_case("identity") {
            return false;
        }
        semantic_codings += 1;
        if semantic_codings > 1 {
            return false;
        }
    }
    semantic_codings == 1
}

/// Selects JSON when JSON is acceptable, SSE only when SSE is acceptable,
/// and rejects when neither representation is. A request with no `Accept`
/// field accepts every representation and selects JSON. Media ranges that
/// cannot be parsed grant no acceptance.
fn negotiate_representation(
    headers: &[(String, String)],
) -> Result<ResponseRepresentation, ModernPostRejection> {
    let mut members = 0_usize;
    let mut saw_accept_header = false;
    let mut json_acceptable = false;
    let mut sse_acceptable = false;
    for (name, value) in headers {
        if !name.eq_ignore_ascii_case("accept") {
            continue;
        }
        saw_accept_header = true;
        for member in value.split(',') {
            let member = trim_http_ows(member);
            if member.is_empty() {
                continue;
            }
            members += 1;
            if members > MAX_ACCEPT_MEMBERS {
                return Err(ModernPostRejection::NotAcceptable);
            }
            let mut parameters = member.split(';');
            let Some(essence) = parameters.next().map(trim_http_ows) else {
                continue;
            };
            if media_range_weight_is_zero(parameters) {
                continue;
            }
            if matches_media_range(essence, "application", "json") {
                json_acceptable = true;
            }
            if matches_media_range(essence, "text", "event-stream") {
                sse_acceptable = true;
            }
        }
    }
    if !saw_accept_header {
        return Ok(ResponseRepresentation::Json);
    }
    if json_acceptable {
        return Ok(ResponseRepresentation::Json);
    }
    if sse_acceptable {
        return Ok(ResponseRepresentation::RequestScopedSse);
    }
    Err(ModernPostRejection::NotAcceptable)
}

/// `true` when a `q` parameter is present and denotes zero weight.
fn media_range_weight_is_zero<'a>(parameters: impl Iterator<Item = &'a str>) -> bool {
    for parameter in parameters {
        let Some((name, value)) = trim_http_ows(parameter).split_once('=') else {
            continue;
        };
        if !trim_http_ows(name).eq_ignore_ascii_case("q") {
            continue;
        }
        let value = trim_http_ows(value);
        let mut chars = value.chars();
        if chars.next() != Some('0') {
            return false;
        }
        let rest = chars.as_str();
        let fraction = rest.strip_prefix('.').unwrap_or(rest);
        return fraction.len() <= 3 && fraction.chars().all(|digit| digit == '0');
    }
    false
}

fn matches_media_range(essence: &str, wanted_type: &str, wanted_subtype: &str) -> bool {
    let Some((range_type, range_subtype)) = essence.split_once('/') else {
        return false;
    };
    let range_type = trim_http_ows(range_type);
    let range_subtype = trim_http_ows(range_subtype);
    (range_type == "*" || range_type.eq_ignore_ascii_case(wanted_type))
        && (range_subtype == "*" || range_subtype.eq_ignore_ascii_case(wanted_subtype))
}

fn body_protocol_version(request: &JsonRpcRequest) -> Option<&str> {
    request
        .params
        .as_ref()
        .and_then(|params| params.get("_meta"))
        .and_then(|meta| meta.get(FINAL_PROTOCOL_VERSION_META_KEY))
        .and_then(Value::as_str)
}

/// Returns the body value mirrored by `Mcp-Name` for the methods that
/// require it; the final admission itself decides whether a mirror is
/// mandatory for the request's method.
fn body_mirror_name(request: &JsonRpcRequest) -> Option<&str> {
    let key = match request.method.as_str() {
        "tools/call" | "prompts/get" => "name",
        "resources/read" => "uri",
        "tasks/get" | "tasks/update" | "tasks/cancel" => "taskId",
        _ => return None,
    };
    request
        .params
        .as_ref()
        .and_then(|params| params.get(key))
        .and_then(Value::as_str)
}

#[cfg(test)]
mod tests {
    use fastmcp_protocol::FINAL_PROTOCOL_VERSION;
    use serde_json::json;

    use super::{
        AdmittedModernPost, HttpAdmissionLimits, HttpEndpointConfig, ModernPostRejection,
        ResponseRepresentation, admit_modern_post,
    };

    fn config() -> HttpEndpointConfig {
        HttpEndpointConfig::new(
            "/mcp",
            HttpAdmissionLimits::new(32, 8_192, 65_536).expect("nonzero limits"),
        )
        .expect("valid endpoint path")
    }

    fn canonical_headers() -> Vec<(String, String)> {
        vec![
            ("Content-Type".to_owned(), "application/json".to_owned()),
            (
                "Accept".to_owned(),
                "application/json, text/event-stream".to_owned(),
            ),
            (
                "MCP-Protocol-Version".to_owned(),
                FINAL_PROTOCOL_VERSION.to_owned(),
            ),
            ("Mcp-Method".to_owned(), "server/discover".to_owned()),
        ]
    }

    fn canonical_body() -> Vec<u8> {
        serde_json::to_vec(&json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "server/discover",
            "params": {
                "_meta": {
                    "io.modelcontextprotocol/protocolVersion": FINAL_PROTOCOL_VERSION,
                    "io.modelcontextprotocol/clientCapabilities": {}
                }
            }
        }))
        .expect("canonical body serializes")
    }

    fn admit(
        headers: &[(String, String)],
        body: &[u8],
    ) -> Result<AdmittedModernPost, ModernPostRejection> {
        admit_modern_post(&config(), "POST", "/mcp", headers, body)
    }

    #[test]
    fn admits_canonical_modern_post_with_json_representation() {
        let admitted = admit(&canonical_headers(), &canonical_body())
            .expect("canonical modern POST is admitted");
        assert_eq!(admitted.representation(), ResponseRepresentation::Json);
        assert_eq!(admitted.protocol_version().as_str(), FINAL_PROTOCOL_VERSION);
        assert_eq!(admitted.request().method, "server/discover");
    }

    #[test]
    fn selects_sse_only_when_json_is_not_acceptable() {
        let mut headers = canonical_headers();
        headers[1].1 = "text/event-stream".to_owned();
        let admitted = admit(&headers, &canonical_body()).expect("SSE-only accept admits");
        assert_eq!(
            admitted.representation(),
            ResponseRepresentation::RequestScopedSse
        );
    }

    #[test]
    fn zero_quality_json_yields_sse() {
        let mut headers = canonical_headers();
        headers[1].1 = "application/json;q=0, text/event-stream".to_owned();
        let admitted = admit(&headers, &canonical_body()).expect("q=0 excludes JSON only");
        assert_eq!(
            admitted.representation(),
            ResponseRepresentation::RequestScopedSse
        );
    }

    #[test]
    fn wildcard_and_absent_accept_select_json() {
        let mut headers = canonical_headers();
        headers[1].1 = "*/*".to_owned();
        let admitted = admit(&headers, &canonical_body()).expect("wildcard admits");
        assert_eq!(admitted.representation(), ResponseRepresentation::Json);

        let headers: Vec<_> = canonical_headers()
            .into_iter()
            .filter(|(name, _)| name != "Accept")
            .collect();
        let admitted = admit(&headers, &canonical_body()).expect("absent Accept admits");
        assert_eq!(admitted.representation(), ResponseRepresentation::Json);
    }

    #[test]
    fn unusable_accept_is_not_acceptable() {
        let mut headers = canonical_headers();
        headers[1].1 = "text/plain, application/xml".to_owned();
        assert_eq!(
            admit(&headers, &canonical_body()).map(|_| ()),
            Err(ModernPostRejection::NotAcceptable)
        );

        let mut headers = canonical_headers();
        headers[1].1 = "garbage-without-slash".to_owned();
        assert_eq!(
            admit(&headers, &canonical_body()).map(|_| ()),
            Err(ModernPostRejection::NotAcceptable),
            "unparseable media ranges grant no acceptance"
        );
    }

    #[test]
    fn wrong_path_and_method_reject_before_everything_else() {
        let result = admit_modern_post(
            &config(),
            "POST",
            "/other",
            &canonical_headers(),
            &canonical_body(),
        );
        assert_eq!(
            result.map(|_| ()),
            Err(ModernPostRejection::EndpointMismatch)
        );

        for method in ["GET", "post", "PUT", "DELETE", "OPTIONS"] {
            let result = admit_modern_post(
                &config(),
                method,
                "/mcp",
                &canonical_headers(),
                &canonical_body(),
            );
            assert_eq!(
                result.map(|_| ()),
                Err(ModernPostRejection::MethodNotAllowed),
                "method {method:?} must be refused byte-exactly"
            );
        }
    }

    #[test]
    fn header_bounds_are_exact() {
        let limits = HttpAdmissionLimits::new(4, 8_192, 65_536).expect("limits");
        let config = HttpEndpointConfig::new("/mcp", limits).expect("config");
        let headers = canonical_headers();
        assert_eq!(headers.len(), 4);
        assert!(admit_modern_post(&config, "POST", "/mcp", &headers, &canonical_body()).is_ok());

        let mut extra = headers.clone();
        extra.push(("X-Extra".to_owned(), "y".to_owned()));
        assert_eq!(
            admit_modern_post(&config, "POST", "/mcp", &extra, &canonical_body()).map(|_| ()),
            Err(ModernPostRejection::TooManyHeaders { limit: 4 })
        );

        let tight = HttpEndpointConfig::new(
            "/mcp",
            HttpAdmissionLimits::new(32, 16, 65_536).expect("limits"),
        )
        .expect("config");
        assert_eq!(
            admit_modern_post(&tight, "POST", "/mcp", &headers, &canonical_body()).map(|_| ()),
            Err(ModernPostRejection::HeaderBlockTooLarge { limit: 16 })
        );
    }

    #[test]
    fn duplicate_singleton_headers_reject() {
        let mut headers = canonical_headers();
        headers.push(("content-type".to_owned(), "application/json".to_owned()));
        assert_eq!(
            admit(&headers, &canonical_body()).map(|_| ()),
            Err(ModernPostRejection::DuplicateSingletonHeader {
                name: "content-type"
            })
        );
    }

    #[test]
    fn media_type_admission_is_exact() {
        for (value, admitted) in [
            ("application/json", true),
            ("Application/JSON", true),
            ("application/json; charset=utf-8", true),
            ("application/json; charset=UTF-8", true),
            ("application/json; charset=utf-16", false),
            ("application/json; charset=utf-8; boundary=x", false),
            ("text/plain", false),
            ("application/json-seq", false),
        ] {
            let mut headers = canonical_headers();
            headers[0].1 = value.to_owned();
            let result = admit(&headers, &canonical_body());
            assert_eq!(
                result.is_ok(),
                admitted,
                "content type {value:?} admission mismatch"
            );
            if !admitted {
                assert_eq!(
                    result.map(|_| ()),
                    Err(ModernPostRejection::UnsupportedMediaType)
                );
            }
        }

        let headers: Vec<_> = canonical_headers()
            .into_iter()
            .filter(|(name, _)| name != "Content-Type")
            .collect();
        assert!(
            matches!(
                admit(&headers, &canonical_body()),
                Err(ModernPostRejection::UnsupportedMediaType)
            ),
            "a missing request content type is fail-closed"
        );
    }

    #[test]
    fn content_coding_admission_is_identity_only() {
        for (value, admitted) in [
            ("identity", true),
            ("Identity", true),
            (", identity", true),
            ("gzip", false),
            ("identity, identity", false),
            ("", false),
            (",,,", false),
        ] {
            let mut headers = canonical_headers();
            headers.push(("Content-Encoding".to_owned(), value.to_owned()));
            let result = admit(&headers, &canonical_body());
            assert_eq!(
                result.is_ok(),
                admitted,
                "content coding {value:?} admission mismatch"
            );
            if !admitted {
                assert_eq!(
                    result.map(|_| ()),
                    Err(ModernPostRejection::UnsupportedContentCoding)
                );
            }
        }
    }

    #[test]
    fn top_level_arrays_are_rejected_before_any_dispatch() {
        use fastmcp_protocol::RawJsonAdmissionError;
        // Even an array of one valid request is a refused batch.
        let body = serde_json::to_vec(&json!([{
            "jsonrpc": "2.0",
            "id": 1,
            "method": "server/discover",
            "params": {
                "_meta": {
                    "io.modelcontextprotocol/protocolVersion": FINAL_PROTOCOL_VERSION,
                    "io.modelcontextprotocol/clientCapabilities": {}
                }
            }
        }]))
        .expect("array body serializes");
        assert_eq!(
            admit(&canonical_headers(), &body).map(|_| ()),
            Err(ModernPostRejection::Raw(
                RawJsonAdmissionError::TopLevelBatch
            ))
        );
    }

    #[test]
    fn notifications_and_responses_are_not_admitted_here() {
        let notification = serde_json::to_vec(&json!({
            "jsonrpc": "2.0",
            "method": "notifications/whatever",
            "params": {}
        }))
        .expect("notification serializes");
        assert_eq!(
            admit(&canonical_headers(), &notification).map(|_| ()),
            Err(ModernPostRejection::NotARequest)
        );
    }

    #[test]
    fn version_mirror_mismatch_is_refused() {
        // Change only the header version: the body still says 2026-07-28.
        let mut headers = canonical_headers();
        headers[2].1 = "2025-11-25".to_owned();
        let result = admit(&headers, &canonical_body());
        assert!(
            matches!(result, Err(ModernPostRejection::FinalAdmission(_))),
            "a mismatched version mirror must be refused, got {result:?}"
        );
    }

    #[test]
    fn name_mirror_is_required_for_tools_call() {
        let body = serde_json::to_vec(&json!({
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/call",
            "params": {
                "name": "echo",
                "arguments": {},
                "_meta": {
                    "io.modelcontextprotocol/protocolVersion": FINAL_PROTOCOL_VERSION,
                    "io.modelcontextprotocol/clientCapabilities": {}
                }
            }
        }))
        .expect("tools/call body serializes");

        let mut headers = canonical_headers();
        headers[3].1 = "tools/call".to_owned();
        assert!(
            matches!(
                admit(&headers, &body),
                Err(ModernPostRejection::FinalAdmission(_))
            ),
            "tools/call without Mcp-Name must be refused"
        );

        headers.push(("Mcp-Name".to_owned(), "echo".to_owned()));
        let admitted = admit(&headers, &body).expect("mirrored tools/call admits");
        assert_eq!(admitted.request().method, "tools/call");
    }

    #[test]
    fn task_lifecycle_methods_mirror_task_id_through_mcp_name() {
        for method in ["tasks/get", "tasks/update", "tasks/cancel"] {
            let body = serde_json::to_vec(&json!({
                "jsonrpc": "2.0",
                "id": 2,
                "method": method,
                "params": {
                    "taskId": "task-73",
                    "_meta": {
                        "io.modelcontextprotocol/protocolVersion": FINAL_PROTOCOL_VERSION,
                        "io.modelcontextprotocol/clientCapabilities": {
                            "extensions": {"io.modelcontextprotocol/tasks": {}}
                        }
                    }
                }
            }))
            .expect("Tasks lifecycle body serializes");
            let mut headers = canonical_headers();
            headers[3].1 = method.to_owned();
            headers.push(("Mcp-Name".to_owned(), "task-73".to_owned()));

            let admitted =
                admit(&headers, &body).expect("a matching taskId/Mcp-Name mirror must be admitted");
            assert_eq!(admitted.request().method, method);
        }
    }

    #[test]
    fn task_get_rejects_only_a_mismatched_task_id_mcp_name_before_dispatch() {
        let body = serde_json::to_vec(&json!({
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tasks/get",
            "params": {
                "taskId": "task-73",
                "_meta": {
                    "io.modelcontextprotocol/protocolVersion": FINAL_PROTOCOL_VERSION,
                    "io.modelcontextprotocol/clientCapabilities": {
                        "extensions": {"io.modelcontextprotocol/tasks": {}}
                    }
                }
            }
        }))
        .expect("Tasks lifecycle body serializes");
        let mut headers = canonical_headers();
        headers[3].1 = "tasks/get".to_owned();
        headers.push(("Mcp-Name".to_owned(), "task-other".to_owned()));

        assert!(
            matches!(
                admit(&headers, &body),
                Err(ModernPostRejection::FinalAdmission(_))
            ),
            "changing only Mcp-Name must reject before dispatch"
        );
    }

    #[test]
    fn rejections_precede_body_parsing_for_transport_failures() {
        // A hopeless body is never parsed when the media type already fails:
        // the typed rejection proves precedence, and a pure pipeline over
        // borrowed inputs has no state to mutate.
        let mut headers = canonical_headers();
        headers[0].1 = "text/plain".to_owned();
        assert_eq!(
            admit(&headers, b"this is not json").map(|_| ()),
            Err(ModernPostRejection::UnsupportedMediaType)
        );
    }

    #[test]
    fn invalid_configurations_are_refused_at_construction() {
        assert!(HttpAdmissionLimits::new(0, 1, 1).is_none());
        assert!(HttpAdmissionLimits::new(1, 0, 1).is_none());
        assert!(HttpAdmissionLimits::new(1, 1, 0).is_none());
        let limits = HttpAdmissionLimits::new(1, 1, 1).expect("limits");
        assert!(HttpEndpointConfig::new("mcp", limits).is_none());
        assert!(HttpEndpointConfig::new("/m cp", limits).is_none());
        assert!(HttpEndpointConfig::new("/mcp\r", limits).is_none());
    }
}
