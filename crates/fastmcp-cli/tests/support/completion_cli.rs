//! Exercise completion through the installed CLI and independent wire peers.
//! The peers record each actual request, so a refusal cannot pass by emitting
//! an error only after contacting a backend or spawning the selected child.

use super::*;
use serde_json::{Value, json};

const PEER: &str = r#"
import http.server
import json
import os
import queue
import sys

era, transport, log_path, ready_path = sys.argv[1:]
events = queue.Queue()

def respond(request):
    with open(log_path, "a", encoding="utf-8") as log:
        log.write(json.dumps({"request": request, "pid": os.getpid()}, ensure_ascii=False) + "\n")
    if "id" not in request:
        assert request["method"] == "notifications/initialized"
        return None
    method = request["method"]
    if method in ("server/discover", "initialize"):
        identity = {"name": "completion-cli-peer", "version": "1"}
        if era == "legacy":
            assert method == "initialize"
            result = json.dumps({"protocolVersion": "2024-11-05",
                                 "capabilities": {"completions": {}}, "serverInfo": identity})
        else:
            assert method == "server/discover"
            result = json.dumps({"resultType": "complete", "supportedVersions": ["2026-07-28"],
                                 "capabilities": {"completions": {}}, "ttlMs": 0,
                                 "cacheScope": "private",
                                 "_meta": {"io.modelcontextprotocol/serverInfo": identity}})
    else:
        assert method == "completion/complete", "completion must not invoke a tool or prompt"
        params = request["params"]
        assert set(params) <= {"ref", "argument", "context", "_meta"}
        assert params["ref"]["type"] in ("ref/prompt", "ref/resource")
        echo = {"ref": params["ref"], "argument": params["argument"],
                "hasContext": "context" in params}
        if "context" in params:
            echo["context"] = params["context"]
        if era == "legacy":
            assert set(params) == {"ref", "argument"}, "no modern fields in exact legacy params"
        else:
            assert isinstance(params["_meta"], dict)
        prefix = params["argument"]["value"]
        region = params.get("context", {}).get("arguments", {}).get("region", "")
        values = [prefix + "-second:" + region, prefix + "-first:" + region]
        completion = '{"values":' + json.dumps(values, ensure_ascii=False) + ',"total":'
        completion += "2" if era == "legacy" else "184467440737095516160"
        completion += ',"hasMore":false}'
        metadata = '{"z-last":1,"a-first":2,"com.example/input":' + json.dumps(echo, ensure_ascii=False) + '}'
        result = '{"completion":' + completion + ',"_meta":' + metadata
        if era != "legacy":
            result += ',"resultType":"complete","com.example/exponent":1.20e+4'
        result += '}'
    return '{"jsonrpc":"2.0","id":' + json.dumps(request["id"]) + ',"result":' + result + '}'

if transport == "stdio":
    for line in sys.stdin:
        response = respond(json.loads(line))
        if response is not None:
            print(response, flush=True)
else:
    class Handler(http.server.BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def do_GET(self):
            assert era == "legacy" and self.path == "/sse"
            self.send_response(200)
            self.send_header("Content-Type", "text/event-stream")
            self.send_header("Transfer-Encoding", "chunked")
            self.send_header("Connection", "keep-alive")
            self.end_headers()
            def chunk(event):
                encoded = event.encode("utf-8")
                self.wfile.write(("%X\r\n" % len(encoded)).encode("ascii") + encoded + b"\r\n")
                self.wfile.flush()
            chunk("event: endpoint\ndata: http://127.0.0.1:" + str(self.server.server_port) + "/messages\n\n")
            try:
                while True:
                    chunk("event: message\ndata: " + events.get(timeout=10) + "\n\n")
            except (BrokenPipeError, ConnectionResetError, queue.Empty):
                self.close_connection = True

        def do_POST(self):
            assert self.path == ("/messages" if era == "legacy" else "/mcp")
            length = int(self.headers["Content-Length"])
            assert 0 < length <= 1024 * 1024
            response = respond(json.loads(self.rfile.read(length)))
            if era == "legacy":
                self.send_response(202)
                self.send_header("Content-Length", "0")
                self.send_header("Connection", "close")
                self.end_headers()
                self.wfile.flush()
                if response is not None:
                    events.put(response)
            else:
                payload = response.encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(payload)))
                self.send_header("Connection", "close")
                self.end_headers()
                self.wfile.write(payload)
            self.close_connection = True

        def log_message(self, *args):
            pass

    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    with open(ready_path, "w", encoding="utf-8") as ready:
        ready.write("http://127.0.0.1:" + str(server.server_port))
    server.serve_forever()
"#;

fn invoke_peer(
    http: bool,
    legacy: bool,
    arguments: &[&str],
    context_file: Option<&str>,
) -> (Output, Vec<Value>) {
    let root = TestTempDir::new("completion-cli");
    let script = root.join("peer.py");
    let log = root.join("requests.jsonl");
    let ready = root.join("ready");
    std::fs::write(&script, PEER).unwrap();
    let peer_arguments = [
        if legacy { "legacy" } else { "modern" },
        if http { "http" } else { "stdio" },
        log.to_str().unwrap(),
        ready.to_str().unwrap(),
    ];
    let mut command = Command::new(get_binary_path());
    command.arg("complete").args(arguments).args([
        "--json",
        "--timeout",
        "5",
        "--protocol-policy",
        if legacy { "legacy-only" } else { "modern-only" },
    ]);
    if let Some(context) = context_file {
        let path = root.join("context.json");
        std::fs::write(&path, context).unwrap();
        command.arg("--context-file").arg(path);
    }
    let mut backend = None;
    if http {
        let mut peer = Command::new("python3");
        peer.arg("-u")
            .arg(&script)
            .args(peer_arguments)
            .stdin(Stdio::null())
            .stdout(std::fs::File::create(root.join("peer.stdout")).unwrap())
            .stderr(std::fs::File::create(root.join("peer.stderr")).unwrap());
        backend = Some(ProcessGroupGuard::spawn(&mut peer));
        let started = Instant::now();
        let endpoint = loop {
            if let Ok(endpoint) = std::fs::read_to_string(&ready)
                && endpoint.starts_with("http://")
            {
                break endpoint;
            }
            assert!(
                started.elapsed() < Duration::from_secs(5),
                "completion peer did not bind: {}",
                std::fs::read_to_string(root.join("peer.stderr")).unwrap_or_default()
            );
            std::thread::sleep(Duration::from_millis(10));
        };
        if legacy {
            command.args([
                "--legacy-sse-url",
                &format!("{endpoint}/sse"),
                "--legacy-message-url",
                &format!("{endpoint}/messages"),
            ]);
        } else {
            command.args(["--http-url", &format!("{endpoint}/mcp")]);
        }
    } else {
        command.args(["--server", "python3", "--server-arg", "-u", "--server-arg"]);
        command.arg(&script);
        for argument in peer_arguments {
            command.arg("--server-arg").arg(argument);
        }
    }
    let output = run_with_deadline(command, Duration::from_secs(15))
        .expect("completion command must finish within its owned deadline");
    if let Some(mut backend) = backend {
        backend.kill_and_reap().expect("completion HTTP peer cleanup");
    }
    let requests = std::fs::read_to_string(log)
        .unwrap_or_default()
        .lines()
        .map(|line| serde_json::from_str::<Value>(line).unwrap()["request"].clone())
        .collect();
    (output, requests)
}

fn assert_completion(
    output: &Output,
    requests: &[Value],
    reference: Value,
    prefix: &str,
    context: Option<Value>,
    legacy: bool,
) {
    assert!(output.status.success(), "{}", stderr_str(output));
    let text = stdout_str(output);
    let result: Value = serde_json::from_str(&text).unwrap();
    let calls: Vec<_> = requests
        .iter()
        .filter(|request| request["method"] == "completion/complete")
        .collect();
    assert_eq!(calls.len(), 1, "{requests:?}");
    assert_eq!(calls[0]["id"], 2);
    assert_eq!(calls[0]["params"]["ref"], reference);
    assert_eq!(calls[0]["params"]["argument"], json!({"name": "environment", "value": prefix}));
    assert_eq!(calls[0]["params"].get("context"), context.as_ref());
    let echo = &result["_meta"]["com.example/input"];
    assert_eq!(echo["ref"], reference);
    assert_eq!(echo["argument"], calls[0]["params"]["argument"]);
    assert_eq!(echo["hasContext"], context.is_some());
    assert_eq!(echo.get("context"), context.as_ref());
    let region = context.as_ref()
        .and_then(|value| value["arguments"]["region"].as_str())
        .unwrap_or("");
    assert_eq!(result["completion"]["values"], json!([
        format!("{prefix}-second:{region}"),
        format!("{prefix}-first:{region}"),
    ]));
    assert_eq!(result["completion"]["hasMore"], false);
    let methods: Vec<_> = requests.iter().map(|request| request["method"].as_str().unwrap()).collect();
    if legacy {
        assert_eq!(methods, ["initialize", "notifications/initialized", "completion/complete"]);
        assert!(result.get("resultType").is_none());
        assert_eq!(result["completion"]["total"], 2);
        assert_eq!(calls[0]["params"].as_object().unwrap().len(), 2);
        assert!(text.find("\"z-last\"").unwrap() < text.find("\"a-first\"").unwrap());
    } else {
        assert_eq!(methods, ["server/discover", "completion/complete"]);
        assert_eq!(result["resultType"], "complete");
        assert!(text.contains("184467440737095516160"), "{text}");
        assert!(text.contains("1.20e+4"), "{text}");
        assert!(calls[0]["params"]["_meta"].is_object());
    }
}

fn modern_completion_cases(http: bool) {
    for context in [None, Some("{}"), Some(r#"{"arguments":{}}"#)] {
        let mut arguments = vec!["--prompt", "deploy", "--argument", "environment", "--value", "sta"];
        if let Some(context) = context {
            arguments.extend(["--context", context]);
        }
        let (output, requests) = invoke_peer(http, false, &arguments, None);
        assert_completion(&output, &requests, json!({"type":"ref/prompt","name":"deploy"}), "sta",
            context.map(|value| serde_json::from_str(value).unwrap()), false);
    }
    let context = r#"{"arguments":{"region":"東京\\literal\n\t","account":"caller-selected"}}"#;
    let arguments = [
        "--resource-template", "test://catalog/{region}/{environment}",
        "--argument", "environment", "--value", "",
    ];
    let (output, requests) = invoke_peer(http, false, &arguments, Some(context));
    assert_completion(&output, &requests,
        json!({"type":"ref/resource","uri":"test://catalog/{region}/{environment}"}), "",
        Some(serde_json::from_str(context).unwrap()), false);
}

#[test]
fn completion_cli_stdio_preserves_reference_context_and_result() {
    modern_completion_cases(false);
}

#[test]
fn completion_cli_http_preserves_reference_context_and_result() {
    modern_completion_cases(true);
}

#[cfg(feature = "legacy-2024-11-05")]
#[test]
fn completion_cli_legacy_preserves_exact_result_without_context() {
    for http in [false, true] {
        for (flag, target, reference) in [
            ("--prompt", "deploy", json!({"type":"ref/prompt","name":"deploy"})),
            ("--resource-template", "test://catalog/{environment}",
                json!({"type":"ref/resource","uri":"test://catalog/{environment}"})),
        ] {
            let (output, requests) = invoke_peer(http, true,
                &[flag, target, "--argument", "environment", "--value", "sta"], None);
            assert_completion(&output, &requests, reference, "sta", None, true);
        }
    }
}

#[test]
fn completion_cli_help_exposes_target_and_context_options() {
    let root = run_cli(&["--help"]);
    assert!(root.status.success(), "{}", stderr_str(&root));
    assert!(stdout_str(&root).contains("complete"));
    let complete = run_cli(&["complete", "--help"]);
    assert!(complete.status.success(), "{}", stderr_str(&complete));
    for flag in ["--prompt", "--resource-template", "--argument", "--value", "--context", "--context-file"] {
        assert!(stdout_str(&complete).contains(flag), "missing {flag}");
    }
}

#[test]
fn completion_cli_rejects_invalid_input_before_contact() {
    let root = TestTempDir::new("completion-cli-refusals");
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let endpoint = format!("http://{}/mcp", listener.local_addr().unwrap());
    let websocket_endpoint = format!("ws://{}/mcp", listener.local_addr().unwrap());
    let context_file = root.join("context.json");
    let marker = root.join("child-started");
    let script = root.join("must-not-run.sh");
    std::fs::write(&script, "printf started > \"$1\"\n").unwrap();
    let mut contexts = vec![
        "null".to_owned(),
        "[]".to_owned(),
        r#"{"arguments":null}"#.to_owned(),
        r#"{"arguments":{"region":1}}"#.to_owned(),
        r#"{"arguments":{"region":"one","region":"two"}}"#.to_owned(),
        r#"{"arguments":{},"arguments":{}}"#.to_owned(),
        r#"{"inputResponses":{}}"#.to_owned(),
        format!(r#"{{"arguments":{{"{}":"value"}}}}"#, "k".repeat(1025)),
        format!(r#"{{"arguments":{{"region":"{}"}}}}"#, "v".repeat(16 * 1024 + 1)),
        format!(r#"{{"arguments":{{"region":"{}"}}}}"#, "\\u0061".repeat(3000)),
        " ".repeat(1024 * 1024 + 1),
    ];
    let too_many: serde_json::Map<String, Value> =
        (0..257).map(|index| (format!("k{index}"), json!("v"))).collect();
    contexts.push(json!({"arguments": too_many}).to_string());
    let too_large: serde_json::Map<String, Value> =
        (0..20).map(|index| (format!("k{index}"), json!("v".repeat(16 * 1024)))).collect();
    contexts.push(json!({"arguments": too_large}).to_string());
    for context in contexts {
        std::fs::write(&context_file, context).unwrap();
        for transport in ["http", "stdio", "websocket"] {
            if transport == "websocket" && !cfg!(feature = "websocket-experimental") {
                continue;
            }
            let mut command = Command::new(get_binary_path());
            command.args(["complete", "--prompt", "deploy", "--argument", "environment",
                "--value", "sta", "--protocol-policy", "modern-only", "--json", "--context-file"])
                .arg(&context_file);
            if transport == "stdio" {
                command.args(["--server", "/bin/sh", "--server-arg"]).arg(&script)
                    .arg("--server-arg").arg(&marker);
            } else if transport == "websocket" {
                command.args(["--websocket-url", &format!("ws://{}/mcp", listener.local_addr().unwrap())]);
            } else {
                command.args(["--http-url", &endpoint]);
            }
            let output = run_with_deadline(command, Duration::from_secs(5)).unwrap();
            assert!(!output.status.success());
            let error: Value = serde_json::from_slice(&output.stdout).unwrap();
            assert_eq!(error["command"], "complete");
            assert!(!marker.exists(), "invalid completion spawned its child");
            assert_eq!(listener.accept().unwrap_err().kind(), std::io::ErrorKind::WouldBlock);
        }
    }
    std::fs::write(&context_file, "{}").unwrap();
    #[cfg(feature = "legacy-2024-11-05")]
    for policy in ["legacy-only", "auto"] {
        // Stdio is otherwise constructible for both policies. If context
        // admission regresses, this selected child records the unwanted spawn.
        let mut command = Command::new(get_binary_path());
        command.args(["complete", "--prompt", "deploy", "--argument", "environment",
            "--value", "sta", "--protocol-policy", policy, "--context", "{}", "--json",
            "--server", "/bin/sh", "--server-arg"]).arg(&script)
            .arg("--server-arg").arg(&marker);
        let output = run_with_deadline(command, Duration::from_secs(5)).unwrap();
        assert!(!output.status.success());
        assert!(!marker.exists(), "legacy-incompatible context spawned its child");
        let error: Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(error["error"]["message"],
            "completion context requires --protocol-policy modern-only");
        assert_eq!(listener.accept().unwrap_err().kind(), std::io::ErrorKind::WouldBlock);
    }
    for extra in [
        vec!["--protocol-policy", "modern-only", "--context", "{}", "--context-file", context_file.to_str().unwrap()],
        vec!["--protocol-policy", "modern-only", "--input-capability", "roots"],
        vec!["--protocol-policy", "modern-only", "--resume-result-file", "/never-read",
            "--input-responses-file", "/never-read"],
        vec!["--protocol-policy", "modern-only", "--websocket-url", &websocket_endpoint],
        vec!["--protocol-policy", "modern-only", "--server", "/bin/sh",
            "--server-arg", script.to_str().unwrap(), "--server-arg", marker.to_str().unwrap()],
        vec!["--protocol-policy", "modern-only", "--unknown-option"],
    ] {
        let authority_refusal = extra.contains(&"--input-capability")
            || extra.contains(&"--resume-result-file");
        let mut command = Command::new(get_binary_path());
        command.args(["complete", "--prompt", "deploy", "--argument", "environment",
            "--value", "sta", "--http-url", &endpoint, "--json"]).args(extra);
        let output = run_with_deadline(command, Duration::from_secs(5)).unwrap();
        assert!(!output.status.success());
        assert!(!marker.exists(), "conflicting completion transport spawned its child");
        if authority_refusal {
            let error: Value = serde_json::from_slice(&output.stdout).unwrap();
            assert_eq!(error["error"]["message"],
                "completion does not accept input capabilities or resume files");
        }
        assert_eq!(listener.accept().unwrap_err().kind(), std::io::ErrorKind::WouldBlock);
    }
    for selectors in [
        vec!["--prompt".to_owned(), String::new()],
        vec!["--prompt".to_owned(), "p".repeat(1025)],
        vec!["--resource-template".to_owned(), "test:///{unclosed".to_owned()],
        vec!["--prompt".to_owned(), "deploy".to_owned(), "--resource-template".to_owned(), "test:///{x}".to_owned()],
        vec![],
    ] {
        let mut command = Command::new(get_binary_path());
        command.arg("complete").args(selectors).args(["--argument", "environment",
            "--value", "sta", "--protocol-policy", "modern-only", "--http-url", &endpoint, "--json"]);
        let output = run_with_deadline(command, Duration::from_secs(5)).unwrap();
        assert!(!output.status.success());
        assert_eq!(listener.accept().unwrap_err().kind(), std::io::ErrorKind::WouldBlock);
    }
    for (name, value) in [
        (String::new(), "sta".to_owned()),
        ("bad\nname".to_owned(), "sta".to_owned()),
        ("environment".to_owned(), "v".repeat(16 * 1024 + 1)),
    ] {
        let mut command = Command::new(get_binary_path());
        command.args(["complete", "--prompt", "deploy", "--argument", &name,
            "--value", &value, "--protocol-policy", "modern-only", "--http-url", &endpoint, "--json"]);
        let output = run_with_deadline(command, Duration::from_secs(5)).unwrap();
        assert!(!output.status.success());
        assert_eq!(listener.accept().unwrap_err().kind(), std::io::ErrorKind::WouldBlock);
    }
}

#[cfg(feature = "websocket-experimental")]
#[test]
fn websocket_cli_completion_preserves_reference_context_and_result() {
    for (flag, target, reference) in [
        ("--prompt", "deploy", json!({"type":"ref/prompt","name":"deploy"})),
        ("--resource-template", "test://catalog/{region}/{environment}",
            json!({"type":"ref/resource","uri":"test://catalog/{region}/{environment}"})),
    ] {
        let (ready, address) = mpsc::sync_channel(1);
        let peer = std::thread::spawn(move || {
            let runtime = asupersync::runtime::RuntimeBuilder::current_thread()
                .with_reactor(asupersync::runtime::reactor::create_reactor().unwrap())
                .blocking_threads(0, 16)
                .build()
                .unwrap();
            runtime.block_on(async {
                let cx = asupersync::Cx::current().unwrap();
                let listener = fastmcp_transport::websocket::WebSocketListener::bind("127.0.0.1:0")
                    .await.unwrap();
                ready.send(listener.local_addr().unwrap()).unwrap();
                asupersync::time::timeout(cx.now(), Duration::from_secs(10), async {
                    let upgrade = listener.accept(&cx).await.unwrap();
                    assert_eq!(upgrade.path(), "/mcp");
                    let mut transport = upgrade.into_admission().unwrap().complete(&cx).await.unwrap();
                    let mut requests = Vec::new();
                    for index in 0..2 {
                        let fastmcp_protocol::JsonRpcMessage::Request(request) =
                            transport.recv(&cx).await.unwrap()
                        else {
                            panic!("completion peer expected a JSON-RPC request");
                        };
                        assert_eq!(request.id, Some(fastmcp_protocol::RequestId::Number(index + 1)));
                        let result = if index == 0 {
                            assert_eq!(request.method, "server/discover");
                            json!({
                                "resultType": "complete", "supportedVersions": ["2026-07-28"],
                                "capabilities": {"completions": {}}, "ttlMs": 0, "cacheScope": "private",
                                "_meta": {"io.modelcontextprotocol/serverInfo": {
                                    "name": "websocket-completion-peer", "version": "1",
                                }},
                            }).to_string()
                        } else {
                            assert_eq!(request.method, "completion/complete");
                            let params = request.params.as_ref().unwrap();
                            assert!(params.get("inputResponses").is_none());
                            assert!(params.get("requestState").is_none());
                            let prefix = params["argument"]["value"].as_str().unwrap();
                            let region = params["context"]["arguments"]["region"].as_str().unwrap();
                            let values = json!([
                                format!("{prefix}-second:{region}"),
                                format!("{prefix}-first:{region}"),
                            ]);
                            let echo = json!({
                                "ref": params["ref"], "argument": params["argument"],
                                "hasContext": true, "context": params["context"],
                            });
                            format!(
                                "{{\"resultType\":\"complete\",\"completion\":{{\"values\":{values},\"total\":184467440737095516160,\"hasMore\":false}},\"_meta\":{{\"com.example/input\":{echo}}},\"com.example/exponent\":1.20e+4}}"
                            )
                        };
                        let response = fastmcp_protocol::JsonRpcResponse::success_with_raw_result(
                            request.id.clone().unwrap(), result, 1024 * 1024,
                        ).unwrap();
                        requests.push(serde_json::to_value(request).unwrap());
                        transport.send(&cx, &fastmcp_protocol::JsonRpcMessage::Response(response))
                            .await.unwrap();
                    }
                    assert!(matches!(transport.recv(&cx).await,
                        Err(fastmcp_transport::TransportError::Closed)));
                    requests
                }).await.expect("completion peer must observe bounded cleanup")
            })
        });
        let endpoint = format!("ws://{}/mcp", address.recv_timeout(Duration::from_secs(5)).unwrap());
        let context = r#"{"arguments":{"region":"東京\\literal\n\t"}}"#;
        let mut command = Command::new(get_binary_path());
        command.args(["complete", flag, target, "--argument", "environment", "--value", "sta",
            "--context", context, "--websocket-url", &endpoint, "--protocol-policy", "modern-only",
            "--timeout", "5", "--json"]);
        let output = run_with_deadline(command, Duration::from_secs(15)).unwrap();
        let requests = peer.join().unwrap();
        assert_completion(&output, &requests, reference, "sta",
            Some(serde_json::from_str(context).unwrap()), false);
    }
}
