//! Exact-name HTTP-03 harness against the shipped client executor surface.

use fastmcp_client::http_executor::{
    MODERN_MCP_ACCEPT, MODERN_MCP_ACCEPT_ENCODING, MODERN_MCP_CONTENT_TYPE,
    ModernHttpExecutorError, ModernHttpRequest, ModernHttpResponseKind, validate_response_head,
};

#[test]
fn http_03_a_positive() {
    let request = ModernHttpRequest::new(
        "https://server.example.test/mcp",
        br#"{"jsonrpc":"2.0","id":1,"method":"ping"}"#.to_vec(),
        "2026-07-28",
        "ping",
        None,
    )
    .expect("a normal modern MCP POST is constructible");
    assert_eq!(
        request.headers(),
        vec![
            (
                "Content-Type".to_owned(),
                MODERN_MCP_CONTENT_TYPE.to_owned()
            ),
            ("Accept".to_owned(), MODERN_MCP_ACCEPT.to_owned()),
            (
                "Accept-Encoding".to_owned(),
                MODERN_MCP_ACCEPT_ENCODING.to_owned(),
            ),
            ("MCP-Protocol-Version".to_owned(), "2026-07-28".to_owned()),
            ("Mcp-Method".to_owned(), "ping".to_owned()),
        ]
    );
    let response = validate_response_head(
        200,
        &[(
            "Content-Type".to_owned(),
            "text/event-stream; charset=utf-8".to_owned(),
        )],
    )
    .expect("a singleton SSE response selects the stream lane");
    assert_eq!(response.kind(), ModernHttpResponseKind::Sse);
}

#[test]
fn http_03_a_planted_negative() {
    let accepted_headers = vec![
        (
            "Content-Type".to_owned(),
            "text/event-stream; charset=utf-8".to_owned(),
        ),
        ("Content-Encoding".to_owned(), "identity".to_owned()),
    ];
    assert!(validate_response_head(200, &accepted_headers).is_ok());

    // The sole changed field is the response content coding. The request and
    // response media type remain identical, but no body lane is selected.
    let planted_headers = vec![
        (
            "Content-Type".to_owned(),
            "text/event-stream; charset=utf-8".to_owned(),
        ),
        ("Content-Encoding".to_owned(), "gzip".to_owned()),
    ];
    assert!(matches!(
        validate_response_head(200, &planted_headers),
        Err(ModernHttpExecutorError::UnsupportedContentEncoding)
    ));
}
