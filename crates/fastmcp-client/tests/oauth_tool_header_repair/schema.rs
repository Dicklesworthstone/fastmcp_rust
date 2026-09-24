//! Public schema-bound repair over the parent's real OAuth/TLS fixture.
//! The remote pre-dispatch guarantee is scripted, not proven for a server.

use super::*;
use fastmcp_client::http_auth::tool::{ManagedToolClient, ManagedToolError};
use fastmcp_client::http_auth::tool::headers::repair::{
    ManagedToolHeaderRepairOutcome, ManagedToolRepairError,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum SchemaCase {
    Repair, Fresh, MissingOutput, InvalidOutput, InvalidSchema, ChangedInput,
    InvalidBeforeRefresh, InvalidDefinitionCallback, InvalidHeaderCallback, InvalidIdCallback,
    PendingCatalog, PendingResult, CancelRead, DropRead, BufferedInvalidation,
    SecondRejection, InputRequired, NoReview, InvalidInitial,
}

fn isolated_schema(name: &str, case: SchemaCase) {
    if let Ok(selected) = std::env::var(CHILD) {
        assert_eq!(selected, name);
        asupersync::runtime::RuntimeBuilder::current_thread()
            .with_reactor(asupersync::runtime::reactor::create_reactor().unwrap())
            .build().unwrap().block_on(async {
                let cx = Cx::current().unwrap();
                asupersync::time::timeout(cx.now(), Duration::from_secs(20), Box::pin(scenario(&cx, case)))
                    .await.expect("bounded schema-bound header repair");
            });
        return;
    }
    struct Child(std::process::Child);
    impl Drop for Child { fn drop(&mut self) { let _ = self.0.kill(); let _ = self.0.wait(); } }
    struct Root(std::path::PathBuf);
    impl Drop for Root { fn drop(&mut self) { let _ = std::fs::remove_file(&self.0); } }
    let root = Root(std::env::temp_dir().join(format!("fastmcp-schema-repair-{}-{name}.pem", std::process::id())));
    let mut file = std::fs::OpenOptions::new().write(true).create_new(true).open(&root.0).unwrap();
    file.write_all(ROOT).unwrap();
    drop(file);
    let mut child = Child(Command::new(std::env::current_exe().unwrap())
        .args(["--exact", name, "--nocapture", "--test-threads=1"])
        .env(CHILD, name).env("SSL_CERT_FILE", &root.0).env_remove("SSL_CERT_DIR")
        .stdin(Stdio::null()).stdout(Stdio::inherit()).stderr(Stdio::inherit()).spawn().unwrap());
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        if let Some(status) = child.0.try_wait().unwrap() { assert!(status.success(), "{case:?}"); return; }
        assert!(Instant::now() < deadline, "schema repair child exceeded its bound");
        std::thread::sleep(Duration::from_millis(10));
    }
}

fn schema_definition(fresh: bool) -> FinalTool {
    let mut tool = definition("lookup", if fresh { "Fresh" } else { "Old" });
    tool.input_schema["required"] = json!(["region"]);
    let field = if fresh { "total" } else { "old" };
    let mut properties = serde_json::Map::new();
    properties.insert(field.to_owned(), json!({"type":"integer"}));
    tool.output_schema = Some(json!({"type":"object","properties":properties,"required":[field]}));
    if fresh {
        // The successful public repair path must retain opaque schema data.
        // Validation-shaped members here have no assertion or header authority.
        let annotation = json!({"minimum":"opaque", "$ref":"https://unresolved.example/schema", "x-mcp-header":"Ignored"});
        tool.input_schema["unknownValidationKeyword"] = annotation.clone();
        tool.output_schema.as_mut().unwrap()["unknownValidationKeyword"] = annotation;
    }
    tool
}

fn structured_reply(id: i64, case: SchemaCase) -> String {
    let result = match case {
        SchemaCase::Fresh => r#"{"resultType":"complete","content":[],"structuredContent":{"old":2},"x-exact":1.20e+4}"#,
        SchemaCase::MissingOutput => r#"{"resultType":"complete","content":[]}"#,
        SchemaCase::InvalidOutput => r#"{"resultType":"complete","content":[],"structuredContent":{"total":"private-output-canary"}}"#,
        SchemaCase::InputRequired => r#"{"resultType":"input_required","requestState":"new-opaque-challenge"}"#,
        _ => r#"{"resultType":"complete","content":[],"structuredContent":{"total":2},"x-exact":1.20e+4}"#,
    };
    format!(r#"{{"jsonrpc":"2.0","id":{id},"result":{result}}}"#)
}

async fn stalled_json(socket: &mut TlsStream<TcpStream>) {
    socket.write_all(b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 4096\r\n\r\n{\"jsonrpc\":").await.unwrap();
    socket.flush().await.unwrap();
}
async fn assert_closed(socket: &mut TlsStream<TcpStream>) {
    let mut byte = [0];
    assert!(!matches!(socket.read(&mut byte).await, Ok(n) if n > 0), "owned TLS response must close");
}

fn retries(case: SchemaCase) -> bool {
    matches!(case, SchemaCase::Repair | SchemaCase::MissingOutput | SchemaCase::InvalidOutput
        | SchemaCase::PendingResult | SchemaCase::CancelRead | SchemaCase::DropRead
        | SchemaCase::BufferedInvalidation | SchemaCase::SecondRejection | SchemaCase::InputRequired)
}

async fn refresh_peer(peer: &Peer, source: &ManagedToolClient, case: SchemaCase) -> Option<TlsStream<TcpStream>> {
    for index in 0..2 {
        let (mut socket, request) = peer.rpc("tools/list", 11 + index, None).await;
        if case == SchemaCase::PendingCatalog {
            stalled_json(&mut socket).await;
            source.invalidate();
            assert_closed(&mut socket).await;
            return None;
        }
        if index == 0 { assert!(request["params"].get("cursor").is_none()); }
        else { assert_eq!(request["params"]["cursor"], "schema-page-two"); }
        assert!(request["params"]["_meta"].get("com.example/private-observation").is_none());
        let mut selected = schema_definition(true);
        if case == SchemaCase::InvalidSchema {
            selected.output_schema.as_mut().unwrap()["properties"]["total"]["minimum"] = json!("invalid-schema-private-canary");
        }
        if case == SchemaCase::ChangedInput { selected.input_schema["properties"]["region"]["minLength"] = json!(2); }
        let tools = if index == 0 { vec![selected] } else { vec![definition("other", "Unused")] };
        let mut result = json!({"resultType":"complete","tools":tools,"ttlMs":0,"cacheScope":"private"});
        if index == 0 { result["nextCursor"] = json!("schema-page-two"); }
        reply(&mut socket, 200, "application/json", &json!({"jsonrpc":"2.0","id":11+index,"result":result}).to_string(), false).await;
    }
    if !retries(case) { return None; }
    let (mut socket, _) = peer.rpc("tools/call", 13, Some("mcp-param-fresh")).await;
    if matches!(case, SchemaCase::PendingResult | SchemaCase::CancelRead | SchemaCase::DropRead) {
        stalled_json(&mut socket).await;
        return Some(socket);
    }
    if case == SchemaCase::SecondRejection {
        reply(&mut socket, 400, "application/json", &error(13, -32020), false).await;
    } else {
        reply(&mut socket, 200, "application/json", &structured_reply(13, case), false).await;
    }
    None
}

async fn scenario(cx: &Cx, case: SchemaCase) {
    let peer = Peer::new().await;
    let ((), session) = pair(peer.login(), ManagedOAuthSession::authorize(cx, peer.client(), OAuthSessionPolicy::default(), browser)).await;
    let session = session.unwrap();
    let cancellation = McpRequestCancellation::new();
    let unconfigured = ManagedToolClient::new(session.clone(), schema_definition(false)).unwrap();
    let source = if case == SchemaCase::NoReview { unconfigured }
        else { unconfigured.review_headers(|_| true).unwrap() };
    let region = if case == SchemaCase::InvalidInitial { Value::Null } else { json!("雪") };
    let request = core("tools/call", json!({"name":"lookup","arguments":{"region":region,"private":"body-only"}}));
    let original = request.encode_params().unwrap().unwrap();
    let limits = ToolHeaderRepairLimits::new(
        ManagedCoreLimits::new(4096, 4096, 65536, 0, Duration::from_secs(10)).unwrap(), 16384, 4, 8,
    ).unwrap();
    let initial = source.request_with_header_repair_and_cancellation(cx, &cancellation, request,
        RequestId::Number(10), ToolHeaderRepairContract::for_configured_endpoint(peer.resource()).unwrap(), limits);
    let no_initial = matches!(case, SchemaCase::NoReview | SchemaCase::InvalidInitial);
    let first_peer = async {
        if no_initial { return; }
        if case == SchemaCase::Fresh {
            let (mut socket, _) = peer.rpc("tools/call", 10, Some("mcp-param-old")).await;
            reply(&mut socket, 200, "application/json", &structured_reply(10, case), false).await;
        } else { peer.first(Case::Repair).await; }
    };
    let ((), outcome) = pair(first_peer, initial).await;
    peer.quiet();
    assert_eq!(peer.requests.lock().unwrap().len(), usize::from(!no_initial));
    let mut expected = usize::from(!no_initial);
    match outcome {
        Err(error) => match case {
            SchemaCase::NoReview => assert!(matches!(error, ManagedToolRepairError::HeaderReviewRequired)),
            SchemaCase::InvalidInitial => assert!(matches!(error, ManagedToolRepairError::Tool(ManagedToolError::InvalidArguments))),
            _ => panic!("unexpected initial failure: {error:?}"),
        },
        Ok(ManagedToolHeaderRepairOutcome::Call(mut call)) => {
            assert_eq!(case, SchemaCase::Fresh);
            let Some(ManagedCoreEvent::Result(result)) = call.next_event(cx).await.unwrap() else { panic!("initial complete result"); };
            assert!(result.encode().unwrap().contains("1.20e+4"));
            assert!(call.next_event(cx).await.unwrap().is_none());
        }
        Ok(ManagedToolHeaderRepairOutcome::Rejected(rejected)) => {
            if case == SchemaCase::InvalidBeforeRefresh { source.invalidate(); }
            let approvals = AtomicUsize::new(0);
            let disclosures = AtomicUsize::new(0);
            let ids = AtomicUsize::new(0);
            let retry = rejected.refresh_and_retry(cx,
                || {
                    let at = ids.fetch_add(1, Ordering::SeqCst);
                    assert!(at < 3, "no third tool attempt");
                    if case == SchemaCase::InvalidIdCallback && at == 2 { source.invalidate(); }
                    Ok(RequestId::Number(11 + at as i64))
                },
                |definition| {
                    assert_eq!(peer.requests.lock().unwrap().len(), 3, "approve only complete catalogs");
                    assert_eq!(definition.input_schema, schema_definition(true).input_schema);
                    assert_eq!(definition.output_schema, schema_definition(true).output_schema);
                    approvals.fetch_add(1, Ordering::SeqCst);
                    if case == SchemaCase::InvalidDefinitionCallback { source.invalidate(); }
                    true
                },
                |_| {
                    disclosures.fetch_add(1, Ordering::SeqCst);
                    if case == SchemaCase::InvalidHeaderCallback { source.invalidate(); }
                    true
                });
            let server = async {
                if case == SchemaCase::InvalidBeforeRefresh { None }
                else { refresh_peer(&peer, &source, case).await }
            };
            let (mut stalled, outcome) = pair(server, retry).await;
            expected += if case == SchemaCase::InvalidBeforeRefresh { 0 }
                else if case == SchemaCase::PendingCatalog { 1 } else { 2 };
            if retries(case) { expected += 1; }
            if retries(case) && case != SchemaCase::SecondRejection {
                let mut call = outcome.unwrap();
                if case == SchemaCase::BufferedInvalidation { source.invalidate(); }
                let read_result = if let Some(socket) = stalled.as_mut() {
                    let mut read = Box::pin(call.next_event(cx));
                    poll_fn(|task| {
                        assert!(read.as_mut().poll(task).is_pending(), "partial result must wait");
                        Poll::Ready(())
                    }).await;
                    if case == SchemaCase::DropRead {
                        drop(read);
                        call.next_event(cx).await
                    } else {
                        if case == SchemaCase::CancelRead { cancellation.cancel(); }
                        else { source.invalidate(); }
                        let result = read.await;
                        assert_closed(socket).await;
                        result
                    }
                } else { call.next_event(cx).await };
                match case {
                    SchemaCase::MissingOutput => assert!(matches!(read_result, Err(ManagedToolError::MissingStructuredOutput))),
                    SchemaCase::InvalidOutput => {
                        let error = read_result.err().unwrap();
                        assert!(matches!(error, ManagedToolError::InvalidStructuredOutput));
                        assert!(!format!("{error:?} {error}").contains("private-output-canary"));
                    }
                    SchemaCase::BufferedInvalidation | SchemaCase::PendingResult => assert!(matches!(read_result, Err(ManagedToolError::Invalidated))),
                    SchemaCase::CancelRead => assert!(matches!(read_result, Err(ManagedToolError::Core(ManagedCoreError::Cancelled)))),
                    SchemaCase::DropRead => {
                        assert!(matches!(read_result, Err(ManagedToolError::Closed)));
                        assert_closed(stalled.as_mut().unwrap()).await;
                        assert!(!source.is_invalidated());
                    }
                    SchemaCase::Repair | SchemaCase::InputRequired => {
                        let Some(ManagedCoreEvent::Result(result)) = read_result.unwrap() else { panic!("checked result"); };
                        let encoded = result.encode().unwrap();
                        if case == SchemaCase::InputRequired { assert!(encoded.contains("new-opaque-challenge")); }
                        else { assert!(encoded.contains("1.20e+4") && encoded.contains("total")); }
                        assert!(call.next_event(cx).await.unwrap().is_none());
                    }
                    _ => panic!("unexpected read case"),
                }
            } else {
                match case {
                    SchemaCase::ChangedInput => assert!(matches!(outcome, Err(ManagedToolRepairError::Tool(ManagedToolError::InvalidArguments)))),
                    SchemaCase::InvalidSchema => assert!(matches!(outcome, Err(ManagedToolRepairError::Tool(ManagedToolError::InvalidOutputSchema)))),
                    SchemaCase::SecondRejection => assert!(matches!(outcome, Err(ManagedToolRepairError::Repair(ToolHeaderRepairError::Core(ManagedCoreError::HttpStatus { status: 400 }))))),
                    _ => assert!(matches!(outcome, Err(ManagedToolRepairError::Tool(ManagedToolError::Invalidated)))),
                }
            }
            let early = matches!(case, SchemaCase::InvalidBeforeRefresh | SchemaCase::PendingCatalog | SchemaCase::InvalidSchema | SchemaCase::ChangedInput);
            assert_eq!(approvals.load(Ordering::SeqCst), usize::from(!early));
            assert_eq!(disclosures.load(Ordering::SeqCst), if early || case == SchemaCase::InvalidDefinitionCallback { 0 }
                else if case == SchemaCase::InvalidHeaderCallback { 1 } else { 2 });
            assert_eq!(ids.load(Ordering::SeqCst), if case == SchemaCase::InvalidBeforeRefresh { 0 }
                else if case == SchemaCase::PendingCatalog { 1 }
                else if retries(case) || case == SchemaCase::InvalidIdCallback { 3 } else { 2 });
        }
    }
    peer.quiet();
    {
        let requests = peer.requests.lock().unwrap();
        assert_eq!(requests.len(), expected);
        for request in requests.iter().filter(|request| request["method"] == "tools/call") {
            assert_eq!(request["params"], original, "schema approval never replaces invocation data");
        }
    }
    assert!(cx.checkpoint().is_ok());
    let sibling = async {
        let mut call = session.request_core(cx, core("tools/list", json!({})), RequestId::Number(900), ManagedCoreLimits::default()).await.unwrap();
        assert!(matches!(call.next_event(cx).await.unwrap(), Some(ManagedCoreEvent::Result(_))));
    };
    pair(peer.sibling(), sibling).await;
    assert_eq!(peer.requests.lock().unwrap().len(), expected + 1);
    assert_eq!(peer.grants.load(Ordering::SeqCst), 1, "reuse the original login");
    peer.quiet();
    session.close();
}

macro_rules! schema_cases {
    ($($name:ident => $case:ident),+ $(,)?) => { $(
        #[test] fn $name() { isolated_schema(concat!("schema::", stringify!($name)), SchemaCase::$case); }
    )+ };
}
schema_cases! {
    repair_checks_new_schema_and_preserves_original_parameters => Repair,
    fresh_success_uses_the_original_output_contract => Fresh,
    repaired_result_cannot_omit_structured_output => MissingOutput,
    repaired_result_cannot_violate_the_new_output_schema => InvalidOutput,
    malformed_replacement_schema_never_reaches_host_approval => InvalidSchema,
    changed_input_schema_refuses_original_arguments_before_retry => ChangedInput,
    invalidated_rejection_cannot_start_catalog_refresh => InvalidBeforeRefresh,
    definition_callback_invalidation_stops_disclosure_and_retry => InvalidDefinitionCallback,
    disclosure_callback_invalidation_stops_later_callbacks_and_retry => InvalidHeaderCallback,
    retry_id_callback_invalidation_prevents_the_post => InvalidIdCallback,
    invalidation_aborts_a_stalled_catalog_body => PendingCatalog,
    invalidation_aborts_a_stalled_repaired_result => PendingResult,
    cancellation_aborts_only_the_repaired_call => CancelRead,
    abandoned_repaired_read_is_not_reusable => DropRead,
    invalidation_withholds_an_already_buffered_repaired_result => BufferedInvalidation,
    second_rejection_never_yields_a_third_attempt => SecondRejection,
    repaired_input_required_is_not_an_automatic_continuation => InputRequired,
    missing_header_review_refuses_before_the_first_post => NoReview,
    schema_invalid_initial_arguments_refuse_before_the_first_post => InvalidInitial,
}
