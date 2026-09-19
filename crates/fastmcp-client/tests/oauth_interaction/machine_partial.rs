//! Public client-credentials discovery, grant and partial MRTR over actual TLS.
//! Shares only the transport fixture/inline test CA with interactive OAuth;
//! machine authentication does not execute a browser or authorization-code flow.
use super::*;
use fastmcp_client::http_auth::discovery::TrustedOAuthIssuer;
use fastmcp_client::http_auth::discovery::client_credentials::{ClientCredentialsPlan, CLIENT_CREDENTIALS_EXTENSION};
use fastmcp_client::http_auth::discovery::client_credentials::rpc::interaction::{
    ClientCredentialsInteraction, ClientCredentialsInteractionError, ClientCredentialsInputReply,
};

#[path = "mixed_inputs.rs"]
mod mixed_inputs;

#[path = "host_execution.rs"]
mod host_execution;

const DISCOVERY: &str = r#"{"resultType":"complete","supportedVersions":["2026-07-28"],"capabilities":{"tools":{},"resources":{},"prompts":{},"extensions":{"io.modelcontextprotocol/oauth-client-credentials":{}}},"ttlMs":0,"cacheScope":"private"}"#;
const TWO: &str = r#"{"resultType":"input_required","inputRequests":{"one":{"method":"roots/list"},"two":{"method":"roots/list"}},"requestState":"machine-first"}"#;
const REST: &str = r#"{"resultType":"input_required","inputRequests":{"two":{"method":"roots/list"}},"requestState":"machine-next"}"#;
const BASIC: &str = "Basic c2VydmljZS1jbGllbnQ6c2VydmljZS1zZWNyZXQ=";
#[derive(Clone, Copy)]
enum MachineCase { Manual(&'static str), Driver, OwnerClose, DiscoveryRefusal }

fn isolated_machine(name: &str, case: MachineCase) {
    if let Ok(selected) = std::env::var(CHILD) {
        assert_eq!(selected, name);
        run_machine(case);
        return;
    }
    let roots = RootFile::create();
    struct Child(std::process::Child);
    impl Drop for Child { fn drop(&mut self) { let _ = self.0.kill(); let _ = self.0.wait(); } }
    let mut child = Child(Command::new(std::env::current_exe().unwrap())
        .args(["--exact", name, "--nocapture", "--test-threads=1"])
        .env(CHILD, name).env("SSL_CERT_FILE", &roots.0).env_remove("SSL_CERT_DIR")
        .stdin(Stdio::null()).stdout(Stdio::inherit()).stderr(Stdio::inherit()).spawn().unwrap());
    let end = Instant::now() + Duration::from_secs(30);
    loop {
        if let Some(status) = child.0.try_wait().unwrap() { assert!(status.success()); return; }
        assert!(Instant::now() < end, "machine partial TLS child exceeded its bound");
        std::thread::sleep(Duration::from_millis(10));
    }
}

// The inherited Peer::request enforces the MCP side. Bootstrap GET/token POSTs
// have different authentication and therefore use this bounded fixture reader.
async fn bootstrap_request(peer: &Peer) -> (TlsStream<TcpStream>, String, BTreeMap<String,String>, Vec<u8>) {
    let (socket, _) = peer.listener.accept().await.unwrap();
    let mut socket = peer.acceptor.accept(socket).await.unwrap();
    let mut bytes = Vec::new();
    let mut chunk = [0; 2048];
    let end = loop {
        let count = socket.read(&mut chunk).await.unwrap();
        assert!(count > 0 && bytes.len() + count <= 32768);
        bytes.extend_from_slice(&chunk[..count]);
        if let Some(offset) = bytes.windows(4).position(|slice| slice == b"\r\n\r\n") { break offset + 4; }
    };
    let head = std::str::from_utf8(&bytes[..end]).unwrap();
    let start = head.lines().next().unwrap().to_owned();
    let mut headers = BTreeMap::new();
    for line in head.lines().skip(1).filter(|line| !line.is_empty()) {
        let (name,value) = line.split_once(':').unwrap();
        assert!(headers.insert(name.to_ascii_lowercase(), value.trim().to_owned()).is_none());
    }
    let size = headers.get("content-length").map_or(0, |size| size.parse::<usize>().unwrap());
    assert!(end + size <= 32768);
    while bytes.len() < end + size {
        let count = socket.read(&mut chunk).await.unwrap();
        assert!(count > 0 && bytes.len() + count <= 32768);
        bytes.extend_from_slice(&chunk[..count]);
    }
    assert_eq!(bytes.len(), end + size);
    (socket, start, headers, bytes[end..].to_vec())
}
fn origin(peer: &Peer) -> String { format!("https://{}", peer.listener.local_addr().unwrap()) }
fn plan(peer: &Peer) -> ClientCredentialsPlan {
    let root = Certificate::from_pem(ROOT).unwrap().remove(0);
    let issuer = TrustedOAuthIssuer::new(format!("{}/issuer", origin(peer))).unwrap()
        .with_root_certificate(root.clone()).unwrap();
    ClientCredentialsPlan::new(url(&peer.resource()), issuer, "service-client", "service-secret", vec!["read".to_owned()]).unwrap()
        .with_resource_root_certificate(root).unwrap().with_renewal_leeway(Duration::ZERO).unwrap()
        .with_timeout(Duration::from_secs(15)).unwrap()
}
async fn metadata(peer: &Peer) {
    for (path, result) in [
        ("/.well-known/oauth-protected-resource/mcp", json!({"resource":peer.resource(),
            "authorization_servers":[format!("{}/issuer", origin(peer))], "scopes_supported":["read"]})),
        ("/.well-known/oauth-authorization-server/issuer", json!({"issuer":format!("{}/issuer", origin(peer)),
            "token_endpoint":format!("{}/token", origin(peer)), "grant_types_supported":["client_credentials"],
            "token_endpoint_auth_methods_supported":["client_secret_basic"], "scopes_supported":["read"]})),
    ] {
        let (mut socket, start, headers, body) = bootstrap_request(peer).await;
        assert_eq!(start, format!("GET {path} HTTP/1.1"));
        assert!(!headers.contains_key("authorization") && body.is_empty());
        json_reply(&mut socket, &result.to_string()).await;
    }
}
async fn grant(peer: &Peer) {
    let (mut socket, start, headers, body) = bootstrap_request(peer).await;
    assert_eq!(start, "POST /token HTTP/1.1");
    assert_eq!(headers["authorization"], BASIC);
    let fields = form(std::str::from_utf8(&body).unwrap());
    assert_eq!(fields["grant_type"], "client_credentials");
    assert_eq!(fields["resource"], peer.resource());
    assert_eq!(fields["scope"], "read");
    assert_eq!(fields.len(), 3, "no browser code or refresh token in a machine grant");
    peer.tokens.fetch_add(1, Ordering::SeqCst);
    json_reply(&mut socket, r#"{"access_token":"interaction-access","token_type":"Bearer","expires_in":300,"scope":"read"}"#).await;
}
async fn round(peer: &Peer, id: i64, result: &str) -> Value {
    let discovery = peer.response(id, DISCOVERY).await;
    assert_eq!(discovery["method"], "server/discover");
    assert_eq!(discovery["params"]["_meta"]["io.modelcontextprotocol/clientCapabilities"]["extensions"],
        json!({CLIENT_CREDENTIALS_EXTENSION:{}}));
    peer.response(id + 1, result).await
}
fn assert_wire(wire: &Value, original: &Value, key: &str, state: &str) {
    assert_eq!(wire["params"]["inputResponses"], json!({key:{"roots":[]}}));
    assert_eq!(wire["params"]["requestState"], state);
    let mut params = wire["params"].clone();
    params.as_object_mut().unwrap().remove("inputResponses");
    params.as_object_mut().unwrap().remove("requestState");
    assert_eq!(&params, original);
}
async fn challenge(operation: &mut ClientCredentialsInteraction, cx: &Cx) {
    assert!(matches!(operation.next_event(cx).await.unwrap(), Some(ManagedInteractionEvent::InputRequired(_))));
}
async fn complete_machine(operation: &mut ClientCredentialsInteraction, cx: &Cx) {
    let Some(ManagedInteractionEvent::Complete(result)) = operation.next_event(cx).await.unwrap() else { panic!("complete machine result expected"); };
    assert!(result.encode().unwrap().contains("1.20e+4"));
    assert!(operation.next_event(cx).await.unwrap().is_none());
}

fn run_machine(case: MachineCase) {
    RuntimeBuilder::current_thread().with_reactor(create_reactor().unwrap()).build().unwrap().block_on(async {
        let cx = Cx::current().unwrap();
        let scenario = async {
            let peer = Peer::new().await;
            let plan = plan(&peer);
            let ((), client) = pair(metadata(&peer), plan.discover(&cx)).await;
            let client = client.unwrap();
            let method = match case { MachineCase::Manual(method) => method, _ => "tools/call" };
            let request = core(method, true);
            let mut original = request.encode_params().unwrap().unwrap();
            original["_meta"]["io.modelcontextprotocol/clientCapabilities"]["extensions"] = json!({CLIENT_CREDENTIALS_EXTENSION:{}});
            let limits = ManagedInteractionLimits::new(
                ManagedCoreLimits::new(4096, 4096, 16384, 4, Duration::from_secs(15)).unwrap(), 2, 2).unwrap();
            let server = async { grant(&peer).await; round(&peer, 60, TWO).await };
            let (wire, operation) = pair(server, client.start_core_interaction(&cx, request,
                RequestId::Number(60), RequestId::Number(61), limits)).await;
            assert_eq!(wire["params"], original);
            let mut operation = operation.unwrap();
            challenge(&mut operation, &cx).await;
            let expected_posts = match case {
                MachineCase::Manual(_) => {
                    // Reused discovery ID, wrong key, and strict-subset refusal
                    // cannot perform even a fresh discovery POST.
                    assert!(matches!(operation.resume_partial(&cx, RequestId::Number(60), RequestId::Number(63), answers("one")).await,
                        Err(ClientCredentialsInteractionError::Interaction(ManagedInteractionError::RepeatedRequestId))));
                    assert!(matches!(operation.resume_partial(&cx, RequestId::Number(62), RequestId::Number(63), answers("foreign")).await,
                        Err(ClientCredentialsInteractionError::Interaction(ManagedInteractionError::InvalidInputResponses))));
                    assert!(matches!(operation.resume(&cx, RequestId::Number(62), RequestId::Number(63), Some(answers("one"))).await,
                        Err(ClientCredentialsInteractionError::Interaction(ManagedInteractionError::InvalidInputResponses))));
                    peer.quiet();
                    let (wire, result) = pair(round(&peer, 62, REST), operation.resume_partial(
                        &cx, RequestId::Number(62), RequestId::Number(63), answers("one"))).await;
                    result.unwrap();
                    assert_wire(&wire, &original, "one", "machine-first");
                    challenge(&mut operation, &cx).await;
                    assert!(matches!(operation.resume_partial(&cx, RequestId::Number(64), RequestId::Number(65), answers("one")).await,
                        Err(ClientCredentialsInteractionError::Interaction(ManagedInteractionError::InvalidInputResponses))));
                    let (wire, result) = pair(round(&peer, 64, complete(method)), operation.resume_partial(
                        &cx, RequestId::Number(64), RequestId::Number(65), answers("two"))).await;
                    result.unwrap();
                    assert_wire(&wire, &original, "two", "machine-next");
                    complete_machine(&mut operation, &cx).await;
                    assert_eq!(operation.continuation_count(), 2);
                    assert_eq!(operation.credential_generation(), 1);
                    6
                }
                MachineCase::Driver => {
                    let calls = Cell::new(0);
                    let server = async {
                        assert_wire(&round(&peer, 62, REST).await, &original, "one", "machine-first");
                        assert_wire(&round(&peer, 64, complete(method)).await, &original, "two", "machine-next");
                    };
                    let driver = operation.drive_partial(&cx, |input| {
                        let round = calls.get(); calls.set(round + 1);
                        assert_eq!(input.input_requests().unwrap().members().len(), if round == 0 {2} else {1});
                        std::future::ready(Ok(ClientCredentialsInputReply {
                            discovery_id:RequestId::Number(62 + round * 2), request_id:RequestId::Number(63 + round * 2),
                            input_responses:Some(answers(if round == 0 {"one"} else {"two"})),
                        }))
                    }, |_| Ok(()));
                    let ((), result) = pair(server, driver).await;
                    assert!(result.unwrap().encode().unwrap().contains("1.20e+4"));
                    assert_eq!(calls.get(), 2);
                    6
                }
                MachineCase::OwnerClose => {
                    let calls = Cell::new(0);
                    let result = operation.drive_partial(&cx, |_| {
                        calls.set(calls.get()+1); client.close();
                        std::future::ready(Ok(ClientCredentialsInputReply {
                            discovery_id:RequestId::Number(62), request_id:RequestId::Number(63),
                            input_responses:Some(answers("one")),
                        }))
                    }, |_| Ok(())).await;
                    assert!(result.is_err()); assert_eq!(calls.get(),1);
                    2
                }
                MachineCase::DiscoveryRefusal => {
                    let denied = r#"{"resultType":"complete","supportedVersions":["2026-07-28"],"capabilities":{"tools":{}},"ttlMs":0,"cacheScope":"private"}"#;
                    let (wire, result) = pair(peer.response(62, denied), operation.resume_partial(
                        &cx, RequestId::Number(62), RequestId::Number(63), answers("one"))).await;
                    assert_eq!(wire["method"], "server/discover");
                    assert!(result.is_err()); assert!(operation.pending_input().is_none());
                    assert_eq!(operation.continuation_count(),1);
                    assert!(matches!(operation.resume_partial(&cx, RequestId::Number(64), RequestId::Number(65), answers("one")).await,
                        Err(ClientCredentialsInteractionError::Interaction(ManagedInteractionError::Closed))));
                    3
                }
            };
            assert_eq!(peer.posts.load(Ordering::SeqCst), expected_posts);
            assert_eq!(peer.tokens.load(Ordering::SeqCst), 1);
            peer.quiet();
            client.close();
        };
        asupersync::time::timeout_at(cx.now().saturating_add_nanos(20_000_000_000), scenario).await.unwrap();
    });
}

#[test]
fn machine_partial_tool_uses_fresh_discovery_and_exact_successor() {
    isolated_machine("driver::machine_partial::machine_partial_tool_uses_fresh_discovery_and_exact_successor", MachineCase::Manual("tools/call"));
}
#[test]
fn machine_partial_resource_uses_fresh_discovery_and_exact_successor() {
    isolated_machine("driver::machine_partial::machine_partial_resource_uses_fresh_discovery_and_exact_successor", MachineCase::Manual("resources/read"));
}
#[test]
fn machine_partial_prompt_uses_fresh_discovery_and_exact_successor() {
    isolated_machine("driver::machine_partial::machine_partial_prompt_uses_fresh_discovery_and_exact_successor", MachineCase::Manual("prompts/get"));
}
#[test]
fn machine_partial_driver_honors_the_selected_answers_only() {
    isolated_machine("driver::machine_partial::machine_partial_driver_honors_the_selected_answers_only", MachineCase::Driver);
}
#[test]
fn machine_partial_owner_close_prevents_the_next_discovery() {
    isolated_machine("driver::machine_partial::machine_partial_owner_close_prevents_the_next_discovery", MachineCase::OwnerClose);
}
#[test]
fn machine_partial_discovery_refusal_cannot_authorize_a_replay() {
    isolated_machine("driver::machine_partial::machine_partial_discovery_refusal_cannot_authorize_a_replay", MachineCase::DiscoveryRefusal);
}
