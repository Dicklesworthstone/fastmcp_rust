//! Shipped-API coverage for the native modern HTTP client runtime.

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
#[cfg(feature = "legacy-2024-11-05")]
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

use asupersync::Cx;
use asupersync::runtime::RuntimeBuilder;
#[cfg(feature = "legacy-2024-11-05")]
use fastmcp_client::ProtocolEra;
#[cfg(feature = "legacy-2024-11-05")]
use fastmcp_client::http_executor::ModernHttpResponseKind;
use fastmcp_client::http_executor::{ModernHttpClient, ModernHttpClientError};
#[cfg(feature = "legacy-2024-11-05")]
use fastmcp_client::sse::{SseEndOfStream, SseLimits};
use fastmcp_client::{CanonicalHttpUrl, ClientProtocolPlan, ProtocolPolicy};
use fastmcp_protocol::{ClientCapabilities, ClientInfo};
#[cfg(feature = "legacy-2024-11-05")]
use fastmcp_protocol::{JsonRpcMessage, JsonRpcRequest, RequestId};

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

#[cfg(feature = "legacy-2024-11-05")]
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
    #[cfg(feature = "legacy-2024-11-05")]
    let rejection_policy = ProtocolPolicy::Auto;
    #[cfg(not(feature = "legacy-2024-11-05"))]
    let rejection_policy = ProtocolPolicy::ModernOnly;
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind native HTTP listener");
    listener
        .set_nonblocking(false)
        .expect("set initial listener blocking mode");
    let address = listener
        .local_addr()
        .expect("read native HTTP listener address");
    let target = format!("http://{address}/mcp");
    let legacy_sse_target = format!("http://{address}/legacy-sse");
    let legacy_message_target = format!("http://{address}/legacy-message");
    let server = thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("accept disposable probe");
        let captured = read_request(&mut stream);
        // With legacy enabled, only the status differs from the accepted
        // Auto 404/empty refusal above. Core-only verifies ModernOnly rejection.
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
        plan(
            &target,
            &legacy_sse_target,
            &legacy_message_target,
            rejection_policy,
        ),
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

fn bearer_request(target: &str) -> fastmcp_client::http_executor::ModernHttpRequest {
    fastmcp_client::http_executor::ModernHttpRequest::new(
        target,
        br#"{"jsonrpc":"2.0","id":7,"method":"ping"}"#.to_vec(),
        "2026-07-28",
        "ping",
        None,
    )
    .expect("construct the same request for each target")
}

#[test]
fn http_03_b_bearer_actual_target_positive() {
    let target = CanonicalHttpUrl::parse("https://mcp.example/api?tenant=one").unwrap();
    let credential = fastmcp_client::http_auth::BoundBearerCredential::bind(
        target.clone(),
        "runtime-test-token",
    )
    .unwrap();
    let request = bearer_request(target.as_str()).with_authorization(&credential);
    assert_eq!(
        request
            .headers()
            .iter()
            .find(|(name, _)| name == "Authorization"),
        Some(&(
            "Authorization".to_owned(),
            "Bearer runtime-test-token".to_owned()
        ))
    );
    assert!(!format!("{request:?}").contains("runtime-test-token"));
}

#[test]
fn http_03_b_bearer_actual_target_planted_negative() {
    let resource = CanonicalHttpUrl::parse("https://mcp.example/api?tenant=one").unwrap();
    let credential = fastmcp_client::http_auth::BoundBearerCredential::bind(
        resource.clone(),
        "runtime-test-token",
    )
    .unwrap();
    let original = bearer_request(resource.as_str());
    let admitted = original.clone().with_authorization(&credential);
    assert!(
        admitted
            .headers()
            .iter()
            .any(|(name, _)| name == "Authorization")
    );
    for changed_target in [
        "http://mcp.example/api?tenant=one",
        "https://other.example/api?tenant=one",
        "https://mcp.example/other?tenant=one",
        "https://mcp.example/api?tenant=two",
        "http://localhost/api?tenant=one",
        "http://127.0.0.1/api?tenant=one",
        "http://[::1]/api?tenant=one",
    ] {
        let changed = bearer_request(changed_target).with_authorization(&credential);
        assert!(
            !changed
                .headers()
                .iter()
                .any(|(name, _)| name == "Authorization")
        );
        assert_eq!(changed.body(), original.body());
        assert_eq!(changed.headers(), original.headers());
        assert_eq!(credential.resource(), &resource);
    }
}

#[test]
fn http_03_b_bound_credential_mismatch_refuses_before_contact() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let address = listener.local_addr().unwrap();
    let target = format!("http://{address}/mcp");
    let resource = CanonicalHttpUrl::parse(&format!("https://{address}/mcp")).unwrap();
    let credential =
        fastmcp_client::http_auth::BoundBearerCredential::bind(resource, "canary").unwrap();
    let builder = fastmcp_client::ClientBuilder::new()
        .protocol_plan(plan(&target, &target, &target, ProtocolPolicy::ModernOnly))
        .http_bearer_credential(credential);
    assert!(!format!("{builder:?}").contains("canary"));
    let cx = Cx::for_request();
    let outcome = runtime_block_on(builder.connect_http_client_with_cx(&cx));
    assert!(matches!(
        outcome,
        Err(fastmcp_client::HttpClientError::Connection(
            fastmcp_client::ClientHttpConnectionError::Modern(
                ModernHttpClientError::CredentialTargetMismatch
            )
        ))
    ));
    assert_eq!(
        listener.accept().unwrap_err().kind(),
        std::io::ErrorKind::WouldBlock
    );
}

/// TLS protocol-peer tests, not a deployed MCP server or tenant-isolation proof.
/// The child process confines SSL_CERT_FILE to one caller and uses the same
/// native-root feature that private-CA applications can select in production.
#[cfg(all(unix, feature = "native-tls-roots"))]
mod authenticated_tls {
    use super::*;
    use std::path::Path;
    use std::process::{Child, Command, Stdio};

    struct OwnedProcess(Child);

    impl Drop for OwnedProcess {
        fn drop(&mut self) {
            if self.0.try_wait().ok().flatten().is_none() {
                let _ = self.0.kill();
            }
            let _ = self.0.wait();
        }
    }

    fn openssl(directory: &Path, arguments: &[&str]) {
        let output = Command::new("openssl")
            .current_dir(directory)
            .args(arguments)
            .output()
            .expect("openssl is required for the real TLS test");
        let step = arguments
            .windows(2)
            .find(|pair| pair[0] == "-keyout")
            .map_or("sign", |pair| pair[1]);
        std::fs::write(
            directory.join(format!("openssl-{step}.stdout")),
            &output.stdout,
        )
        .unwrap();
        std::fs::write(
            directory.join(format!("openssl-{step}.stderr")),
            &output.stderr,
        )
        .unwrap();
        assert!(
            output.status.success(),
            "openssl failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }

    fn bounded_wait(child: &mut Child) -> std::process::ExitStatus {
        let deadline = Instant::now() + Duration::from_secs(30);
        loop {
            if let Some(status) = child.try_wait().expect("observe owned TLS child") {
                return status;
            }
            assert!(
                Instant::now() < deadline,
                "TLS child exceeded its 30-second bound"
            );
            thread::sleep(Duration::from_millis(10));
        }
    }

    fn run_case(name: &str, trusted_ca: bool, check: impl FnOnce(&str, &str, &Path)) {
        if std::env::var("FASTMCP_HTTP03_TLS_CASE").as_deref() == Ok(name) {
            let target = std::env::var("FASTMCP_HTTP03_TLS_TARGET").expect("child target");
            let token = std::env::var("FASTMCP_HTTP03_TLS_TOKEN").expect("child token");
            let log = std::env::var("FASTMCP_HTTP03_TLS_LOG").expect("child observation path");
            check(&target, &token, Path::new(&log));
            return;
        }
        for key in [
            "FASTMCP_HTTP03_TLS_CASE",
            "FASTMCP_HTTP03_TLS_TARGET",
            "FASTMCP_HTTP03_TLS_TOKEN",
            "FASTMCP_HTTP03_TLS_LOG",
        ] {
            assert!(
                std::env::var_os(key).is_none(),
                "parent TLS test environment must be isolated: {key}"
            );
        }
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let directory =
            std::env::temp_dir().join(format!("fastmcp-http03-tls-{}-{nonce}", std::process::id()));
        std::fs::create_dir(&directory).unwrap();
        std::fs::create_dir(directory.join("empty-roots")).unwrap();
        std::fs::write(directory.join("leaf.ext"), "basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\nsubjectAltName=DNS:localhost,IP:127.0.0.1\n").unwrap();
        openssl(
            &directory,
            &[
                "req",
                "-x509",
                "-newkey",
                "rsa:2048",
                "-nodes",
                "-keyout",
                "ca.key",
                "-out",
                "ca.pem",
                "-days",
                "1",
                "-subj",
                "/CN=FastMCP ephemeral test CA",
            ],
        );
        openssl(
            &directory,
            &[
                "req",
                "-newkey",
                "rsa:2048",
                "-nodes",
                "-keyout",
                "leaf.key",
                "-out",
                "leaf.csr",
                "-subj",
                "/CN=localhost",
            ],
        );
        if !trusted_ca {
            openssl(
                &directory,
                &[
                    "req",
                    "-x509",
                    "-newkey",
                    "rsa:2048",
                    "-nodes",
                    "-keyout",
                    "untrusted.key",
                    "-out",
                    "untrusted.pem",
                    "-days",
                    "1",
                    "-subj",
                    "/CN=Unrelated ephemeral test CA",
                ],
            );
        }
        openssl(
            &directory,
            &[
                "x509",
                "-req",
                "-in",
                "leaf.csr",
                "-CA",
                "ca.pem",
                "-CAkey",
                "ca.key",
                "-CAcreateserial",
                "-out",
                "leaf.pem",
                "-days",
                "1",
                "-extfile",
                "leaf.ext",
            ],
        );
        let token = format!("runtime-{nonce}");
        let log = directory.join("requests.jsonl");
        let ready = directory.join("ready");
        let mut peer = OwnedProcess(
            Command::new("python3")
                .arg("-c")
                .arg(TLS_PEER)
                .current_dir(&directory)
                .env("FASTMCP_HTTP03_TLS_TOKEN", &token)
                .stdout(Stdio::from(
                    std::fs::File::create(directory.join("peer.stdout")).unwrap(),
                ))
                .stderr(Stdio::from(
                    std::fs::File::create(directory.join("peer.stderr")).unwrap(),
                ))
                .spawn()
                .expect("start TLS protocol peer"),
        );
        let deadline = Instant::now() + Duration::from_secs(10);
        while !ready.exists() {
            assert!(
                peer.0.try_wait().unwrap().is_none(),
                "TLS peer exited: {}",
                std::fs::read_to_string(directory.join("peer.stderr")).unwrap()
            );
            assert!(Instant::now() < deadline, "TLS peer did not bind");
            thread::sleep(Duration::from_millis(10));
        }
        let target = std::fs::read_to_string(ready).unwrap();
        let mut child = OwnedProcess(
            Command::new(std::env::current_exe().unwrap())
                .args(["--exact", name, "--nocapture"])
                .env("FASTMCP_HTTP03_TLS_CASE", name)
                .env("FASTMCP_HTTP03_TLS_TARGET", target)
                .env("FASTMCP_HTTP03_TLS_TOKEN", token)
                .env("FASTMCP_HTTP03_TLS_LOG", log)
                .env(
                    "SSL_CERT_FILE",
                    directory.join(if trusted_ca {
                        "ca.pem"
                    } else {
                        "untrusted.pem"
                    }),
                )
                .env("SSL_CERT_DIR", directory.join("empty-roots"))
                .stdout(Stdio::from(
                    std::fs::File::create(directory.join("child.stdout")).unwrap(),
                ))
                .stderr(Stdio::from(
                    std::fs::File::create(directory.join("child.stderr")).unwrap(),
                ))
                .spawn()
                .expect("start isolated native-root client"),
        );
        let status = bounded_wait(&mut child.0);
        let stdout = std::fs::read_to_string(directory.join("child.stdout")).unwrap();
        let stderr = std::fs::read_to_string(directory.join("child.stderr")).unwrap();
        let peer_stderr = std::fs::read_to_string(directory.join("peer.stderr")).unwrap();
        assert!(
            status.success(),
            "TLS case failed; artifacts at {}\n{stdout}\n{stderr}\nPeer stderr:\n{peer_stderr}",
            directory.display()
        );
        assert!(
            stdout.contains("1 passed; 0 failed; 0 ignored"),
            "the exact child test must execute: {stdout}"
        );
        println!(
            "TLS case {name}: retained artifacts at {}",
            directory.display()
        );
        // Retain certificates and observations for diagnosis; no test cleanup
        // deletes files. Both owned processes are joined by their guards.
    }

    fn connect(
        target: &str,
        token: &str,
    ) -> Result<fastmcp_client::HttpClient, fastmcp_client::HttpClientError> {
        connect_with_handlers(target, token, fastmcp_client::ReverseRequestHandlers::new())
    }

    fn connect_with_handlers(
        target: &str,
        token: &str,
        handlers: fastmcp_client::ReverseRequestHandlers,
    ) -> Result<fastmcp_client::HttpClient, fastmcp_client::HttpClientError> {
        let credential = fastmcp_client::http_auth::BoundBearerCredential::bind(
            CanonicalHttpUrl::parse(target).unwrap(),
            token,
        )
        .unwrap();
        let cx = Cx::for_request();
        runtime_block_on(
            fastmcp_client::ClientBuilder::new()
                .client_info("http-03-runtime-client", "1.0.0")
                .protocol_plan(plan(target, target, target, ProtocolPolicy::ModernOnly))
                .http_bearer_credential(credential)
                .reverse_request_handlers(handlers)
                .connect_http_client_with_cx(&cx),
        )
    }

    fn observations(path: &Path) -> Vec<serde_json::Value> {
        std::fs::read_to_string(path)
            .unwrap()
            .lines()
            .map(|line| serde_json::from_str(line).unwrap())
            .collect()
    }

    #[test]
    fn http_03_b_authenticated_client_positive() {
        run_case(
            "authenticated_tls::http_03_b_authenticated_client_positive",
            true,
            |target, token, log| {
                let mut client =
                    connect(target, token).expect("credential must reach HTTPS discovery");
                let cx = Cx::for_request();
                runtime_block_on(client.ping(&cx)).expect("credential must reach ordinary POST");
                let filter = fastmcp_protocol::SubscriptionFilter::default();
                let mut listener = runtime_block_on(client.open_subscriptions_listener(
                    &cx,
                    filter.clone(),
                    fastmcp_client::sse::SseLimits::new(4096, 16384, 16).unwrap(),
                ))
                .expect("credential must reach subscription POST");
                assert!(
                    matches!(runtime_block_on(listener.next_event(&cx)).unwrap(), Some(
                fastmcp_client::http_executor::ModernHttpSubscriptionListenEvent::Acknowledged { accepted_filter }
            ) if accepted_filter == filter)
                );
                assert!(
                    matches!(runtime_block_on(listener.next_event(&cx)).unwrap(), Some(
                fastmcp_client::http_executor::ModernHttpSubscriptionListenEvent::Terminal { .. }
            ))
                );
                let rows = observations(log);
                assert_eq!(
                    rows.iter()
                        .map(|row| row["method"].as_str().unwrap())
                        .collect::<Vec<_>>(),
                    ["server/discover", "ping", "subscriptions/listen"]
                );
                assert!(
                    rows.iter()
                        .all(|row| row["authorized"] == true && row["target"] == "/mcp")
                );
                assert_ne!(
                    rows[0]["peer"], rows[1]["peer"],
                    "discovery and ordinary POST use different sockets; executor isolation is a separate source invariant"
                );
            },
        );
    }

    #[test]
    fn http_03_b_authenticated_reverse_response_positive() {
        run_case(
            "authenticated_tls::http_03_b_authenticated_reverse_response_positive",
            true,
            |target, token, log| {
                let handlers = fastmcp_client::ReverseRequestHandlers::new()
                    .with_modern_sampling_create_message(|_cx, _cancellation, params| {
                        Box::pin(async move {
                            assert_eq!(params.max_tokens.to_string(), "8");
                            Ok(fastmcp_protocol::FinalCreateMessageResult {
                                content: fastmcp_protocol::FinalSamplingMessageContent::Block(
                                    fastmcp_protocol::common_types::SamplingContentBlock::Text {
                                        text: "sampled over authenticated TLS".to_owned(),
                                        annotations: None,
                                        meta: None,
                                        additional: std::collections::BTreeMap::new(),
                                    },
                                ),
                                model: "http-03-authenticated-handler".to_owned(),
                                role: fastmcp_protocol::Role::Assistant,
                                stop_reason: None,
                                meta: None,
                            })
                        })
                    });
                let mut client = connect_with_handlers(target, token, handlers).unwrap();
                let tools = runtime_block_on(client.list_tools(&Cx::for_request(), None)).unwrap();
                assert!(matches!(tools,
                    fastmcp_protocol::CoreResult::Final(
                        fastmcp_protocol::FinalCoreResult::ToolsList { result, .. }
                    ) if result.payload.tools.is_empty()
                ));
                let rows = observations(log);
                assert_eq!(rows.len(), 3);
                assert_eq!(rows[0]["method"], "server/discover");
                assert_eq!(rows[1]["method"], "tools/list");
                assert_eq!(rows[2]["method"], "response");
                assert!(rows.iter().all(|row| row["authorized"] == true));
                let response: serde_json::Value =
                    serde_json::from_str(rows[2]["body"].as_str().unwrap()).unwrap();
                assert_eq!(response["id"], 99);
                assert_eq!(response["result"]["model"], "http-03-authenticated-handler");
                assert_eq!(
                    response["result"]["content"]["text"],
                    "sampled over authenticated TLS"
                );
            },
        );
    }

    #[test]
    fn http_03_b_authenticated_client_planted_negative() {
        run_case(
            "authenticated_tls::http_03_b_authenticated_client_planted_negative",
            true,
            |target, token, log| {
                let wrong = format!("{token}-wrong");
                let error = connect(target, &wrong)
                    .err()
                    .expect("wrong token must fail discovery");
                let diagnostic = format!("{error:?} {error}");
                assert!(!diagnostic.contains(token));
                let rejected = observations(log);
                assert_eq!(rejected.len(), 1, "no retry or fallback after refusal");
                assert_eq!(rejected[0]["authorized"], false);
                assert_eq!(rejected[0]["method"], "server/discover");
                let mut client = connect(target, token).expect("change only the token to valid");
                runtime_block_on(client.ping(&Cx::for_request())).unwrap();
                let rows = observations(log);
                assert_eq!(rows.len(), 3);
                assert_eq!(
                    rows[0]["body"], rows[1]["body"],
                    "only Authorization changes between discovery attempts"
                );
                assert_eq!(rows[1]["authorized"], true);
                assert_eq!(rows[2]["method"], "ping");
                assert_eq!(rows[2]["authorized"], true);
            },
        );
    }

    #[test]
    fn http_03_b_peer_error_reflection_planted_negative() {
        run_case(
            "authenticated_tls::http_03_b_peer_error_reflection_planted_negative",
            true,
            |target, token, log| {
                let mode = log.parent().unwrap().join("error-mode.json");
                let mut client = connect(target, token).unwrap();
                runtime_block_on(client.ping(&Cx::for_request())).unwrap();
                for stage in ["server/discover", "ping", "subscriptions/listen"] {
                    for location in ["safe", "message", "data", "key", "escaped"] {
                        std::fs::write(
                            &mode,
                            serde_json::to_vec(&serde_json::json!({
                                "stage": stage, "location": location
                            }))
                            .unwrap(),
                        )
                        .unwrap();
                        let diagnostic = peer_error_diagnostic(target, token, stage);
                        assert!(!diagnostic.contains(token));
                        if location == "safe" {
                            assert!(diagnostic.contains("request denied"), "{diagnostic}");
                            assert!(diagnostic.contains("-32603"), "{diagnostic}");
                        } else {
                            assert!(
                                diagnostic.contains("payload withheld"),
                                "{stage}/{location}: {diagnostic}"
                            );
                        }
                    }
                }
                std::fs::write(&mode, br#"{"stage":"none"}"#).unwrap();
                let mut healthy = connect(target, token).unwrap();
                runtime_block_on(healthy.ping(&Cx::for_request())).unwrap();
                let rows = observations(log);
                assert_eq!(rows.len(), 29, "no diagnostic refusal retries any POST");
                assert!(rows.iter().all(|row| row["authorized"] == true));
                assert!(
                    !std::fs::read_to_string(log).unwrap().contains(token),
                    "credentials never enter protocol request parameters"
                );
            },
        );
    }

    fn peer_error_diagnostic(target: &str, token: &str, stage: &str) -> String {
        let connected = connect(target, token);
        if stage == "server/discover" {
            let error = connected.err().expect("peer rejects discovery");
            return format!("{error:?} {error}");
        }
        let mut client = connected.expect("discovery remains successful");
        let cx = Cx::for_request();
        if stage == "ping" {
            let error = runtime_block_on(client.ping(&cx)).expect_err("peer rejects ping");
            format!("{error:?} {error}")
        } else {
            let mut stream = runtime_block_on(client.open_subscriptions_listener(
                &cx,
                fastmcp_protocol::SubscriptionFilter::default(),
                fastmcp_client::sse::SseLimits::new(4096, 16384, 16).unwrap(),
            ))
            .expect("peer opens an SSE response");
            let error = runtime_block_on(stream.next_event(&cx))
                .expect_err("peer terminates subscription with an error");
            assert!(
                matches!(
                    runtime_block_on(stream.next_event(&cx)),
                    Err(fastmcp_client::HttpClientError::Connection(
                        fastmcp_client::ClientHttpConnectionError::SubscriptionsListen(
                            fastmcp_client::http_executor::ModernHttpSubscriptionListenError::Executor(
                                fastmcp_client::http_executor::ModernHttpExecutorError::SseStreamClosed
                            )
                        )
                    ))
                ),
                "a refused subscription must retain its closed state"
            );
            format!("{error:?} {error}")
        }
    }

    #[test]
    fn http_03_b_response_debug_redacts_peer_payload() {
        run_case(
            "authenticated_tls::http_03_b_response_debug_redacts_peer_payload",
            true,
            |target, token, log| {
                std::fs::write(
                    log.parent().unwrap().join("error-mode.json"),
                    br#"{"stage":"ping","location":"message","echo_header":true}"#,
                )
                .unwrap();
                let credential = fastmcp_client::http_auth::BoundBearerCredential::bind(
                    CanonicalHttpUrl::parse(target).unwrap(),
                    token,
                )
                .unwrap();
                let request = bearer_request(target).with_authorization(&credential);
                let executor = fastmcp_client::http_executor::ModernHttpExecutor::new();
                let cx = Cx::for_request();
                let response = runtime_block_on(executor.execute(&cx, &request)).unwrap();
                let diagnostic = format!("{response:?}");
                assert!(diagnostic.contains("metadata"));
                assert!(!diagnostic.contains(token));
                assert!(matches!(
                    runtime_block_on(response.read_to_end(&cx, 4096)),
                    Err(fastmcp_client::http_executor::ModernHttpExecutorError::CredentialInPeerError)
                ));
                let rows = observations(log);
                assert_eq!(rows.len(), 1);
                assert_eq!(rows[0]["authorized"], true);
            },
        );
    }

    #[test]
    fn http_03_b_untrusted_ca_planted_negative() {
        run_case(
            "authenticated_tls::http_03_b_untrusted_ca_planted_negative",
            false,
            |target, token, log| {
                let error = connect(target, token)
                    .err()
                    .expect("an unrelated trust root must reject TLS");
                let diagnostic = format!("{error:?} {error}");
                assert!(
                    diagnostic.contains("TLS") || diagnostic.contains("certificate"),
                    "expected certificate admission failure: {diagnostic}"
                );
                assert!(!diagnostic.contains(token));
                assert!(
                    !log.exists(),
                    "certificate refusal must precede every HTTP request"
                );
            },
        );
    }

    #[cfg(feature = "legacy-2024-11-05")]
    #[test]
    fn http_03_b_authenticated_auto_never_contacts_legacy() {
        run_case(
            "authenticated_tls::http_03_b_authenticated_auto_never_contacts_legacy",
            true,
            |target, token, log| {
                let trap = TcpListener::bind("127.0.0.1:0").unwrap();
                trap.set_nonblocking(true).unwrap();
                let legacy = format!("http://{}/legacy", trap.local_addr().unwrap());
                let cx = Cx::for_request();
                // A valid Auto discovery remains usable with the same auth configuration.
                let credential = fastmcp_client::http_auth::BoundBearerCredential::bind(
                    CanonicalHttpUrl::parse(target).unwrap(),
                    token,
                )
                .unwrap();
                let accepted = runtime_block_on(
                    fastmcp_client::ClientBuilder::new()
                        .protocol_plan(plan(target, &legacy, &legacy, ProtocolPolicy::Auto))
                        .http_bearer_credential(credential)
                        .connect_http_with_cx(&cx),
                )
                .expect("authenticated Auto may select modern");
                assert_eq!(
                    accepted.selected_protocol_era(),
                    fastmcp_client::ProtocolEra::Modern2026
                );
                let refused_target = format!("{target}?refuse=1");
                let credential = fastmcp_client::http_auth::BoundBearerCredential::bind(
                    CanonicalHttpUrl::parse(&refused_target).unwrap(),
                    token,
                )
                .unwrap();
                let rejected = runtime_block_on(
                    fastmcp_client::ClientBuilder::new()
                        .protocol_plan(plan(
                            &refused_target,
                            &legacy,
                            &legacy,
                            ProtocolPolicy::Auto,
                        ))
                        .http_bearer_credential(credential)
                        .connect_http_with_cx(&cx),
                );
                assert!(matches!(
                    rejected,
                    Err(fastmcp_client::ClientHttpConnectionError::Modern(
                        ModernHttpClientError::AuthenticatedLegacyFallback
                    ))
                ));
                assert_eq!(
                    trap.accept().unwrap_err().kind(),
                    std::io::ErrorKind::WouldBlock
                );
                let rows = observations(log);
                assert_eq!(rows.len(), 2);
                assert!(
                    rows.iter()
                        .all(|row| row["authorized"] == true && row["method"] == "server/discover")
                );
                assert_eq!(
                    accepted.selected_protocol_era(),
                    fastmcp_client::ProtocolEra::Modern2026,
                    "the accepted sibling retains its era"
                );
            },
        );
    }

    const TLS_PEER: &str = r"
import http.server, json, os, pathlib, ssl
class Peer(http.server.BaseHTTPRequestHandler):
    protocol_version = 'HTTP/1.1'
    def log_message(self, *args): pass
    def do_POST(self):
        length = int(self.headers['Content-Length'])
        assert 0 < length <= 65536
        body = self.rfile.read(length)
        request = json.loads(body)
        authorized = self.headers.get('Authorization') == 'Bearer ' + os.environ['FASTMCP_HTTP03_TLS_TOKEN']
        with open('requests.jsonl', 'a') as log:
            log.write(json.dumps({'method':request.get('method', 'response'), 'target':self.path, 'authorized':authorized, 'peer':self.client_address[1], 'body':body.decode()}) + '\n')
        if not authorized:
            self.respond(401, 'text/plain', b'Unauthorized')
            return
        if self.path == '/mcp?refuse=1':
            self.respond(404, 'text/plain', b'')
            return
        method, identifier = request.get('method'), request['id']
        mode = json.loads(pathlib.Path('error-mode.json').read_text()) if pathlib.Path('error-mode.json').exists() else {}
        if 'stage' in mode and mode['stage'] == method:
            token = os.environ['FASTMCP_HTTP03_TLS_TOKEN']
            error = {'code':-32603,'message':'request denied','data':{'detail':['safe diagnostic']}}
            if mode['location'] in ['message', 'escaped']: error['message'] += ': ' + token
            elif mode['location'] == 'data': error['data']['detail'] = ['safe', {'nested':token}]
            elif mode['location'] == 'key': error['data'] = {token:'safe'}
            payload = json.dumps({'jsonrpc':'2.0','id':identifier,'error':error})
            if mode['location'] == 'escaped': payload = payload.replace(token, ''.join('\\u%04x' % ord(c) for c in token))
            if method == 'subscriptions/listen': self.respond(200, 'text/event-stream', ('data: '+payload+'\n\n').encode())
            else: self.respond(200, 'application/json', payload.encode())
            return
        if method == 'server/discover':
            result = {'resultType':'complete','supportedVersions':['2026-07-28'],'capabilities':{},'ttlMs':0,'cacheScope':'private','_meta':{'io.modelcontextprotocol/serverInfo':{'name':'tls-auth-peer','version':'1'}}}
        elif method == 'ping':
            result = {'resultType':'complete'}
        elif method == 'tools/list':
            reverse = {'jsonrpc':'2.0','id':99,'method':'sampling/createMessage','params':{'_meta':{},'messages':[{'role':'user','content':{'type':'text','text':'hello'}}],'maxTokens':8}}
            terminal = {'jsonrpc':'2.0','id':identifier,'result':{'resultType':'complete','tools':[],'ttlMs':0,'cacheScope':'private'}}
            self.respond(200, 'text/event-stream', ''.join('data: '+json.dumps(x)+'\n\n' for x in [reverse,terminal]).encode())
            return
        elif method is None:
            assert identifier == 99 and request['result']['model'] == 'http-03-authenticated-handler'
            assert self.headers.get('Mcp-Method') is None and self.headers.get('Mcp-Name') is None
            self.respond(202, 'application/json', b'')
            return
        elif method == 'subscriptions/listen':
            meta = {'io.modelcontextprotocol/subscriptionId':identifier}
            ack = {'jsonrpc':'2.0','method':'notifications/subscriptions/acknowledged','params':{'_meta':meta,'notifications':request['params']['notifications']}}
            terminal = {'jsonrpc':'2.0','id':identifier,'result':{'resultType':'complete','_meta':meta}}
            self.respond(200, 'text/event-stream', ''.join('data: '+json.dumps(x)+'\n\n' for x in [ack,terminal]).encode())
            return
        else:
            raise AssertionError('unexpected method')
        self.respond(200, 'application/json', json.dumps({'jsonrpc':'2.0','id':identifier,'result':result}).encode())
    def respond(self, status, content_type, body):
        self.send_response(status)
        mode = json.loads(pathlib.Path('error-mode.json').read_text()) if pathlib.Path('error-mode.json').exists() else {}
        if mode.get('echo_header'): self.send_header('X-Credential-Reflection', os.environ['FASTMCP_HTTP03_TLS_TOKEN'])
        self.send_header('Content-Type', content_type)
        self.send_header('Content-Length', str(len(body)))
        self.send_header('Connection', 'keep-alive')
        self.end_headers()
        self.wfile.write(body)
        self.wfile.flush()
        self.close_connection = False
server = http.server.ThreadingHTTPServer(('127.0.0.1',0), Peer)
context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
context.load_cert_chain('leaf.pem', 'leaf.key')
server.socket = context.wrap_socket(server.socket, server_side=True)
with open('ready', 'w') as ready: ready.write('https://127.0.0.1:%d/mcp' % server.server_port)
server.serve_forever()
";
}
