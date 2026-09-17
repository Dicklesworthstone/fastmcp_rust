//! FND-05 si9y: the uncoded request content-coding probe matrix, from OUTSIDE.
//!
//! The package body requires a request/response probe matrix over
//! `Content-Encoding`: absent, case-varied singleton `identity`, and bounded
//! empty-element variants as POSITIVES; all-empty, empty-element N+1,
//! parameterized, duplicate-field, multi-semantic-coding and other-coding as
//! NEGATIVES.
//!
//! SURFACE. Value-level cases drive
//! `HttpRequestHandler::admit_modern_request`, the shipped public admission
//! entry point — every type used here is re-exported from the crate root. The
//! duplicate-FIELD-LINE case cannot be expressed there at all, because
//! `HttpRequest::headers` is a `HashMap<String, String>` and therefore cannot
//! hold two `Content-Encoding` lines; that case belongs to the wire parser and
//! is driven through `HttpTransport::read_request` below.
//!
//! RH-5 DISCIPLINE. Every case is built by the same constructor and differs in
//! exactly one dimension: the `Content-Encoding` value. Method, path,
//! content-type, protocol-version mirror and body are byte-identical across
//! the whole matrix, so an outcome difference can only be attributable to the
//! coding value.
//!
//! WHAT IS NOT COVERED HERE. The RESPONSE half of the matrix (omitted response
//! `Content-Encoding`, auto-decompression disabled) requires a completed
//! `GuardedHttpFetcher` fetch response, and both routes to eliciting one are
//! `#[cfg(test)]` — see the exchange-seam decision on bd-ho7of (comment 2559).
//! It is recorded there as unprovable from the public surface at this revision
//! rather than silently omitted.

#![forbid(unsafe_code)]

use std::io::Cursor;

use fastmcp_transport::http::{
    HttpError, HttpMethod, HttpRequest, HttpRequestHandler, HttpTransport,
};

/// One valid JSON-RPC request body, identical for every case in the matrix.
fn body() -> Vec<u8> {
    serde_json::to_vec(&serde_json::json!({
        "jsonrpc": "2.0",
        "method": "tools/list",
        "params": {
            "_meta": {
                "io.modelcontextprotocol/protocolVersion": "2026-07-28"
            }
        },
        "id": 73
    }))
    .expect("the fixed JSON-RPC body serializes")
}

/// Builds the identical admitted request, varying ONLY `Content-Encoding`.
fn request_with_coding(handler: &HttpRequestHandler, coding: Option<&str>) -> HttpRequest {
    let request = HttpRequest::new(HttpMethod::Post, handler.config().base_path.clone())
        .with_header("content-type", "application/json")
        .with_header("accept", "application/json")
        .with_header("MCP-Protocol-Version", "2026-07-28")
        .with_header("Mcp-Method", "tools/list");
    let request = match coding {
        Some(value) => request.with_header("content-encoding", value),
        None => request,
    };
    request.with_body(body())
}

/// True when admission refused this request for its content coding.
fn refused_for_coding(coding: Option<&str>) -> bool {
    let handler = HttpRequestHandler::new();
    matches!(
        handler.admit_modern_request(&request_with_coding(&handler, coding)),
        Err(HttpError::UnsupportedContentEncoding(_))
    )
}

/// `n` empty list elements followed by one `identity` token.
fn empty_elements_then_identity(n: usize) -> String {
    format!("{}identity", ",".repeat(n))
}

/// POSITIVES: absent, case-varied singleton `identity`, and bounded
/// empty-element variants in leading, interior and trailing position.
#[test]
fn fnd_05_uncoded_request_matrix_positives() {
    // The bound is 16 ignored empty elements; 16 is admitted, 17 is not.
    let sixteen = empty_elements_then_identity(16);
    let cases: Vec<(String, &str)> = vec![
        ("identity".to_owned(), "canonical lowercase singleton"),
        ("IDENTITY".to_owned(), "uppercase singleton"),
        ("Identity".to_owned(), "mixed-case singleton"),
        ("iDeNtItY".to_owned(), "alternating-case singleton"),
        (" identity ".to_owned(), "surrounding optional whitespace"),
        (",identity".to_owned(), "one leading empty element"),
        ("identity,".to_owned(), "one trailing empty element"),
        (",,identity".to_owned(), "two leading empty elements"),
        ("identity,,".to_owned(), "two trailing empty elements"),
        (", ,identity".to_owned(), "empty elements with whitespace"),
        (sixteen, "empty-element bound N = 16, admitted"),
    ];

    let mut refused = Vec::new();
    for (value, label) in &cases {
        if refused_for_coding(Some(value)) {
            refused.push(format!("{label}: Content-Encoding: {value:?} was REFUSED"));
        }
    }

    // Absent header is the baseline positive: an uncoded request carries no
    // Content-Encoding at all.
    let handler = HttpRequestHandler::new();
    let absent = handler.admit_modern_request(&request_with_coding(&handler, None));
    assert!(
        absent.is_ok(),
        "a request with NO Content-Encoding must be admitted; if this fails the whole matrix \
         below is measuring something other than content coding. Got {absent:?}"
    );

    assert!(
        refused.is_empty(),
        "{} of {} uncoded-equivalent request(s) were refused. RFC 9110 list syntax admits \
         bounded empty elements and the token is case-insensitive, so each line is an \
         over-refusal:\n{}",
        refused.len(),
        cases.len(),
        refused.join("\n"),
    );
}

/// NEGATIVES: all-empty, empty-element N+1, parameterized, multi-semantic
/// coding, and other codings.
///
/// This is the discriminator for the positives above. A handler that admitted
/// everything would satisfy the positive test perfectly; these cases are what
/// separate "admits uncoded requests" from "admits anything".
#[test]
fn fnd_05_uncoded_request_matrix_planted_negatives() {
    let seventeen = empty_elements_then_identity(17);
    let cases: Vec<(String, &str)> = vec![
        (String::new(), "all-empty value"),
        (",".to_owned(), "all-empty, two elements"),
        (",,,".to_owned(), "all-empty, four elements"),
        (seventeen, "empty-element bound N+1 = 17, refused"),
        ("identity;q=1".to_owned(), "parameterized token"),
        ("identity ;q=1".to_owned(), "parameterized with whitespace"),
        ("gzip".to_owned(), "other coding"),
        ("br".to_owned(), "other coding"),
        ("deflate".to_owned(), "other coding"),
        ("identity, gzip".to_owned(), "two semantic codings"),
        (
            "gzip, identity".to_owned(),
            "two semantic codings, reordered",
        ),
        ("identity, identity".to_owned(), "duplicate semantic token"),
        ("x-identity".to_owned(), "near-miss token"),
        ("identityy".to_owned(), "near-miss token, one byte longer"),
    ];

    let mut admitted = Vec::new();
    for (value, label) in &cases {
        if !refused_for_coding(Some(value)) {
            admitted.push(format!("{label}: Content-Encoding: {value:?} was ADMITTED"));
        }
    }

    assert!(
        admitted.is_empty(),
        "{} of {} coded or malformed request(s) were admitted. A present Content-Encoding must \
         reduce to exactly one semantic `identity` token; anything else must fail before body \
         processing, or a coded body reaches JSON admission and fails there with a misleading \
         diagnostic:\n{}",
        admitted.len(),
        cases.len(),
        admitted.join("\n"),
    );

    // THE ONE-VARIABLE CONTRAST, asserted rather than left implicit: the bound
    // is exactly 16. N is admitted and N+1 is refused, and the two values
    // differ by a single comma.
    assert!(
        !refused_for_coding(Some(&empty_elements_then_identity(16))),
        "16 empty elements must be admitted"
    );
    assert!(
        refused_for_coding(Some(&empty_elements_then_identity(17))),
        "17 empty elements must be refused; if both 16 and 17 behave alike the bound is not \
         being enforced at the declared value"
    );
}

/// DUPLICATE FIELD LINES, which the admission surface cannot express.
///
/// `HttpRequest::headers` is a `HashMap`, so two `Content-Encoding` lines
/// cannot survive to admission — the wire parser must refuse them first. This
/// drives the raw reader directly so the case is covered on the surface that
/// actually decides it.
#[test]
fn fnd_05_uncoded_duplicate_field_line_is_refused() {
    const DUPLICATE: &str = "POST /mcp/v1 HTTP/1.1\r\nHost: example.invalid\r\n\
         Content-Length: 0\r\nContent-Encoding: identity\r\nContent-Encoding: gzip\r\n\r\n";

    let mut transport = HttpTransport::new(Cursor::new(DUPLICATE.as_bytes().to_vec()), Vec::new());
    let outcome = transport.read_request();
    assert!(
        outcome.is_err(),
        "two Content-Encoding field lines must be refused by the wire parser; admitting them \
         lets a HashMap silently drop one and decide framing from whichever survived. \
         Got {outcome:?}"
    );

    // Discriminator: the SAME request with one field line is accepted, so the
    // refusal tracks duplication rather than the header's presence.
    const SINGLE: &str = "POST /mcp/v1 HTTP/1.1\r\nHost: example.invalid\r\n\
         Content-Length: 0\r\nContent-Encoding: identity\r\n\r\n";

    let mut single = HttpTransport::new(Cursor::new(SINGLE.as_bytes().to_vec()), Vec::new());
    assert!(
        single.read_request().is_ok(),
        "a single Content-Encoding: identity line must be accepted, or the duplicate case above \
         proves only that the parser rejects the header outright"
    );
}
