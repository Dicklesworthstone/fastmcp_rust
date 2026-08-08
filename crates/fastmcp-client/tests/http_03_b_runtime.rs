//! Shipped-API coverage for the native modern HTTP client runtime.

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

use asupersync::Cx;
use asupersync::runtime::RuntimeBuilder;
use fastmcp_client::http_executor::{
    LegacySseHttpClientError, ModernHttpClient, ModernHttpClientError, ModernHttpConnectOutcome,
    ModernHttpResponseKind,
};
use fastmcp_client::sse::{SseEndOfStream, SseLimits};
use fastmcp_client::{CanonicalHttpUrl, ClientProtocolPlan, ProtocolEra, ProtocolPolicy};
use fastmcp_protocol::{ClientCapabilities, ClientInfo, JsonRpcMessage, JsonRpcRequest, RequestId};

#[derive(Debug)]
struct CapturedHttpRequest {
    head: String,
    body: Vec<u8>,
}

fn runtime_block_on<F: std::future::Future>(future: F) -> F::Output {
    RuntimeBuilder::current_thread()
        .build()
        .expect("native HTTP runtime must build")
        .block_on(future)
}

fn plan(
    modern_target: &str,
    legacy_sse_target: &str,
    legacy_message_target: &str,
    policy: ProtocolPolicy,
) -> ClientProtocolPlan {
    let modern_target =
        CanonicalHttpUrl::parse(modern_target).expect("local modern target must be canonical");
    let legacy_sse =
        CanonicalHttpUrl::parse(legacy_sse_target).expect("legacy SSE target must be canonical");
    let legacy_message = CanonicalHttpUrl::parse(legacy_message_target)
        .expect("legacy message target must be canonical");
    ClientProtocolPlan::http(
        policy,
        (!matches!(policy, ProtocolPolicy::LegacyOnly)).then_some(modern_target),
        (!matches!(policy, ProtocolPolicy::ModernOnly)).then_some(legacy_sse),
        (!matches!(policy, ProtocolPolicy::ModernOnly)).then_some(legacy_message),
        "credential-partition-http-03".to_owned(),
        "security-partition-http-03".to_owned(),
        "native-h1-http-03".to_owned(),
        1,
        1,
        0,
    )
    .expect("the complete HTTP plan must be accepted")
}

fn client_info() -> ClientInfo {
    ClientInfo {
        name: "http-03-runtime-client".to_owned(),
        version: "1.0.0".to_owned(),
    }
}

fn read_request(stream: &mut TcpStream) -> CapturedHttpRequest {
    let mut wire = Vec::new();
    let mut buffer = [0_u8; 4096];
    let head_end = loop {
        let read = stream.read(&mut buffer).expect("read native HTTP request");
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
        .find_map(|line| line.strip_prefix("Content-Length: "))
        .map(|value| {
            value
                .parse::<usize>()
                .expect("Content-Length must be numeric")
        })
        .unwrap_or(0);
    while wire.len() < head_end.saturating_add(content_length) {
        let read = stream
            .read(&mut buffer)
            .expect("read native HTTP request body");
        assert!(read > 0, "client closed before the advertised body arrived");
        wire.extend_from_slice(&buffer[..read]);
    }

    CapturedHttpRequest {
        head,
        body: wire[head_end..head_end + content_length].to_vec(),
    }
}

fn write_response(stream: &mut TcpStream, status: u16, content_type: &str, body: &[u8]) {
    let reason = match status {
        200 => "OK",
        202 => "Accepted",
        401 => "Unauthorized",
        404 => "Not Found",
        _ => "Test Response",
    };
    write!(
        stream,
        "HTTP/1.1 {status} {reason}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    )
    .expect("write native HTTP response head");
    stream
        .write_all(body)
        .expect("write native HTTP response body");
    stream.flush().expect("flush native HTTP response");
}

fn assert_final_metadata(request: &CapturedHttpRequest, expected_method: &str) {
    assert!(
        request.head.starts_with("POST /mcp HTTP/1.1\r\n"),
        "request must use the configured modern POST route: {:?}",
        request.head
    );
    assert!(
        request
            .head
            .contains("MCP-Protocol-Version: 2026-07-28\r\n"),
        "modern version header must be sent"
    );
    assert!(
        request
            .head
            .contains(&format!("Mcp-Method: {expected_method}\r\n")),
        "method mirror header must be sent"
    );
    let body: serde_json::Value =
        serde_json::from_slice(&request.body).expect("request body must be JSON-RPC");
    assert_eq!(body["method"], expected_method);
    assert_eq!(
        body["params"]["_meta"]["io.modelcontextprotocol/protocolVersion"],
        "2026-07-28"
    );
    assert_eq!(
        body["params"]["_meta"]["io.modelcontextprotocol/clientInfo"]["name"],
        "http-03-runtime-client"
    );
}

#[test]
fn http_03_b_runtime_positive() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind native HTTP listener");
    let address = listener
        .local_addr()
        .expect("read native HTTP listener address");
    let target = format!("http://{address}/mcp");
    let (requests_tx, requests_rx) = mpsc::channel();
    let server = thread::spawn(move || {
        let (mut probe, _) = listener.accept().expect("accept modern probe");
        let probe_request = read_request(&mut probe);
        requests_tx
            .send(probe_request)
            .expect("record modern probe request");
        write_response(
            &mut probe,
            200,
            "application/json",
            br#"{"jsonrpc":"2.0","id":1,"result":{"supportedVersions":["2026-07-28"],"capabilities":{},"ttlMs":0,"cacheScope":"private"}}"#,
        );

        let (mut normal, _) = listener.accept().expect("accept normal modern request");
        let normal_request = read_request(&mut normal);
        requests_tx
            .send(normal_request)
            .expect("record normal modern request");
        write_response(
            &mut normal,
            200,
            "text/event-stream",
            br#"data: {"jsonrpc":"2.0","id":2,"result":{"ok":true}}

"#,
        );
    });

    let cx = Cx::for_request();
    let outcome = runtime_block_on(ModernHttpClient::connect(
        &cx,
        plan(
            &target,
            "http://127.0.0.1:9/legacy-sse",
            "http://127.0.0.1:9/legacy-message",
            ProtocolPolicy::Auto,
        ),
        client_info(),
        ClientCapabilities::default(),
    ))
    .expect("recognized modern JSON-RPC probe must select the modern client");
    assert_eq!(outcome.selected_era(), Some(ProtocolEra::Modern2026));
    let client = outcome
        .into_modern()
        .expect("recognized modern probe must return a ready modern client");
    assert_eq!(client.modern_post_target(), target);
    assert_eq!(
        client.server_discovery().supported_versions(),
        ["2026-07-28"]
    );

    let response = runtime_block_on(client.request(
        &cx,
        "tools/call",
        serde_json::json!({"name": "echo", "arguments": {"value": 7}}),
        Some(RequestId::Number(2)),
    ))
    .expect("normal modern request must use the native executor");
    assert_eq!(response.metadata().kind(), ModernHttpResponseKind::Sse);
    let mut stream = response
        .into_sse_stream(SseLimits::new(4_096, 65_536, 8).expect("nonzero parser limits"))
        .expect("SSE response must use the shipped parser");
    let body = runtime_block_on(stream.next_event(&cx))
        .expect("bounded SSE response must be readable")
        .expect("SSE response must contain a data event");
    assert_eq!(
        serde_json::from_str::<serde_json::Value>(&body).expect("SSE payload is JSON")["result"]["ok"],
        true
    );
    assert_eq!(
        runtime_block_on(stream.next_event(&cx)).expect("SSE stream must end cleanly"),
        None
    );
    assert_eq!(
        stream.end_of_stream(),
        Some(SseEndOfStream {
            discarded_pending_event: false,
            discarded_partial_line: false,
        })
    );

    server.join().expect("native HTTP server must join");
    let probe = requests_rx.recv().expect("probe capture");
    let normal = requests_rx.recv().expect("normal request capture");
    assert_final_metadata(&probe, "server/discover");
    assert_final_metadata(&normal, "tools/call");
    assert!(normal.head.contains("Mcp-Name: echo\r\n"));

    let fallback_listener =
        TcpListener::bind("127.0.0.1:0").expect("bind fallback native HTTP listener");
    let fallback_address = fallback_listener
        .local_addr()
        .expect("read fallback listener address");
    let fallback_target = format!("http://{fallback_address}/mcp");
    let fallback_sse_target = format!("http://{fallback_address}/legacy-sse");
    let fallback_message_target = format!("http://{fallback_address}/legacy-message?session=one");
    let fallback_server = thread::spawn(move || {
        let (mut probe, _) = fallback_listener.accept().expect("accept disposable probe");
        let probe_request = read_request(&mut probe);
        write_response(&mut probe, 404, "text/plain", b"");

        let (mut sse, _) = fallback_listener.accept().expect("accept legacy SSE GET");
        let sse_request = read_request(&mut sse);
        let sse_body = format!(
            "event: endpoint\ndata: http://{fallback_address}/legacy-message?session=one\n\nevent: message\ndata: {{\"jsonrpc\":\"2.0\",\"id\":7,\"result\":{{\"legacy\":true}}}}\n\n"
        );
        write_response(&mut sse, 200, "text/event-stream", sse_body.as_bytes());

        let (mut post, _) = fallback_listener
            .accept()
            .expect("accept advertised legacy POST");
        let post_request = read_request(&mut post);
        write_response(&mut post, 202, "application/json", b"");
        (probe_request, sse_request, post_request)
    });

    let fallback = runtime_block_on(ModernHttpClient::connect(
        &cx,
        plan(
            &fallback_target,
            &fallback_sse_target,
            &fallback_message_target,
            ProtocolPolicy::Auto,
        ),
        client_info(),
        ClientCapabilities::default(),
    ))
    .expect("the configured 404 empty refusal must open the exact legacy SSE client");
    assert_eq!(fallback.selected_era(), Some(ProtocolEra::Legacy2024));
    let mut legacy = fallback
        .into_legacy_sse()
        .expect("recognized refusal must return the opened legacy client");
    assert_eq!(
        legacy.configured_message_post_target(),
        fallback_message_target
    );
    assert_eq!(
        legacy.advertised_message_post_target(),
        fallback_message_target
    );
    runtime_block_on(legacy.send(
        &cx,
        &JsonRpcMessage::Request(JsonRpcRequest::new(
            "initialize",
            Some(serde_json::json!({"protocolVersion": "2024-11-05"})),
            RequestId::Number(7),
        )),
    ))
    .expect("legacy client must POST to its advertised endpoint");
    let legacy_message = runtime_block_on(legacy.next_message(&cx))
        .expect("legacy message event must be strict JSON-RPC")
        .expect("legacy SSE must provide a message event");
    assert_eq!(
        serde_json::to_value(legacy_message).expect("JSON-RPC message is serializable")["result"]["legacy"],
        true
    );

    let (probe, sse, post) = fallback_server
        .join()
        .expect("fallback native HTTP server must join");
    assert_final_metadata(&probe, "server/discover");
    assert!(sse.head.starts_with("GET /legacy-sse HTTP/1.1\r\n"));
    assert!(sse.head.contains("Accept: text/event-stream\r\n"));
    assert!(!sse.head.contains("MCP-Protocol-Version:"));
    assert!(
        post.head
            .starts_with("POST /legacy-message?session=one HTTP/1.1\r\n")
    );
    assert!(post.head.contains("Content-Type: application/json\r\n"));
    assert!(!post.head.contains("MCP-Protocol-Version:"));
    let posted: serde_json::Value =
        serde_json::from_slice(&post.body).expect("legacy POST must contain JSON-RPC");
    assert_eq!(posted["method"], "initialize");
}

#[test]
fn http_03_b_runtime_planted_negative() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind native HTTP listener");
    listener
        .set_nonblocking(false)
        .expect("set initial listener blocking mode");
    let address = listener
        .local_addr()
        .expect("read native HTTP listener address");
    let target = format!("http://{address}/mcp");
    let server = thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("accept disposable probe");
        let captured = read_request(&mut stream);
        // Only the status differs from the accepted 404/empty refusal above.
        write_response(&mut stream, 401, "text/plain", b"");
        listener
            .set_nonblocking(true)
            .expect("allow bounded second-connection observation");
        let deadline = Instant::now() + Duration::from_millis(100);
        loop {
            match listener.accept() {
                Ok(_) => panic!("an unauthorized response must not trigger a legacy connection"),
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    if Instant::now() >= deadline {
                        break;
                    }
                    thread::sleep(Duration::from_millis(5));
                }
                Err(error) => panic!("observe unintended legacy connection: {error}"),
            }
        }
        captured
    });

    let cx = Cx::for_request();
    let refusal = runtime_block_on(ModernHttpClient::connect(
        &cx,
        plan(&target, ProtocolPolicy::Auto),
        client_info(),
        ClientCapabilities::default(),
    ));

    assert!(matches!(
        refusal,
        Err(ModernHttpClientError::Negotiation(
            fastmcp_client::ClientHttpNegotiationError::ModernProbeRejectedWithoutLegacyFallback {
                status: 401,
                body: fastmcp_client::HttpProbeBody::Empty,
            }
        ))
    ));
    assert_final_metadata(
        &server
            .join()
            .expect("negative native HTTP server must join"),
        "server/discover",
    );
}
