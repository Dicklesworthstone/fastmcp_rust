//! Real managed-provider catalog review and header-bearing execution against
//! an annotated native server tool. All MCP replies come from native secured
//! dispatch; the TLS bridge only inspects and forwards the original request.
//! The parent isolates test trust, owns the runtime, and bounds each process.

use super::*;
use fastmcp_core::McpErrorCode;
use fastmcp_protocol::http_headers::decode_mcp_header_value;
use fastmcp_server::providers::managed_oauth::ManagedOAuthProvider;
use fastmcp_server::providers::managed_oauth::interaction::{
    ManagedOAuthInputCapabilities, ManagedOAuthInputHandler, ManagedOAuthInputPolicy,
    ManagedOAuthInputResponseMode,
};

#[derive(Clone, Copy, Debug)]
pub(super) enum Case {
    Native, BodyOnly, ReviewDenied, Complete, Partial, HostDeclined,
    CancelBefore, CancelAnswer, WrongType, LostReply, PartialRoundLimit,
}

impl Case {
    fn interactive(self) -> bool {
        matches!(self, Self::Complete | Self::Partial | Self::HostDeclined
            | Self::CancelAnswer | Self::LostReply | Self::PartialRoundLimit)
    }
    fn partial(self) -> bool { matches!(self, Self::Partial | Self::PartialRoundLimit) }
}

struct AnnotatedProbe { probe: Probe, interactive: bool }

impl AnnotatedProbe {
    fn invoke<'a>(&'a self, ctx: &'a McpContext, cx: &'a Cx, arguments: Value,
        inputs: Option<&'a MrtrCompletedInputs>) -> BoxFuture<'a, McpOutcome<FinalToolOutcome>>
    {
        if self.interactive {
            return self.probe.call_final_outcome_async_resuming_in_request(ctx, cx, arguments, inputs);
        }
        Box::pin(async move {
            cx.checkpoint().unwrap();
            ctx.ensure_live().unwrap();
            assert!(inputs.is_none());
            self.probe.starts.fetch_add(1, Ordering::SeqCst);
            let effect = self.probe.effects.fetch_add(1, Ordering::SeqCst) + 1;
            let result: FinalCallToolResult = serde_json::from_value(json!({
                "content":[], "structuredContent":{"quantity":arguments["quantity"],"effect":effect}
            })).unwrap();
            Outcome::Ok(FinalToolOutcome::Complete(CompleteResult::new(result, ResultMeta::empty())))
        })
    }
}

impl ToolHandler for AnnotatedProbe {
    fn definition(&self) -> Tool {
        let mut definition = self.probe.definition();
        definition.input_schema = json!({"type":"object","properties":{
            "quantity":{"type":"integer","x-mcp-header":"Quantity"},
            "region":{"type":"string","x-mcp-header":"Region"},
            "private":{"type":"string"}
        },"required":["quantity","region"]});
        definition
    }
    fn execution_mode(&self) -> ToolExecutionMode { ToolExecutionMode::Async }
    fn declares_final_mrtr(&self) -> bool { self.interactive }
    fn call(&self, _: &McpContext, _: Value) -> McpResult<Vec<Content>> { panic!("request-owned hook required") }
    fn call_final_outcome_async_in_request<'a>(
        &'a self, ctx: &'a McpContext, cx: &'a Cx, arguments: Value,
    ) -> BoxFuture<'a, McpOutcome<FinalToolOutcome>> {
        self.invoke(ctx, cx, arguments, None)
    }
    fn call_final_outcome_async_resuming_in_request<'a>(
        &'a self, ctx: &'a McpContext, cx: &'a Cx, arguments: Value, inputs: Option<&'a MrtrCompletedInputs>,
    ) -> BoxFuture<'a, McpOutcome<FinalToolOutcome>> {
        self.invoke(ctx, cx, arguments, inputs)
    }
}

fn install_annotated_tool(peer: &mut Peer, case: Case) {
    let origin = format!("https://{}", peer.listener.local_addr().unwrap());
    let mut auth = AuthContext::with_subject("alice".to_owned());
    auth.scopes = vec!["tools:call".to_owned()];
    let provider = TokenAuthProvider::new(StaticTokenVerifier::new([(peer.token.clone(), auth)]).unwrap());
    // The fixture explicitly selects these two non-sensitive annotation paths.
    // Only the new endpoint executes requests; the parent's unannotated one is
    // replaced before login/catalog collection and is never used as a bypass.
    let builder = Server::new("reviewed-provider-upstream", "1")
        .protocol_policy(ProtocolPolicy::ModernOnly).unwrap().auth_provider(provider)
        .tool(AnnotatedProbe { probe: peer.probe.clone(), interactive: case.interactive() })
        .middleware(peer.journal.clone()).middleware(Stamp(peer.probe.transforms.clone()));
    #[cfg(feature = "legacy-2024-11-05")]
    let endpoint = builder.build_http_endpoint(&origin).unwrap();
    #[cfg(not(feature = "legacy-2024-11-05"))]
    let endpoint = builder.build_http_endpoint().unwrap();
    peer.endpoint = endpoint;
}

struct Host { case: Case, calls: AtomicUsize, answers: AtomicUsize }

impl ManagedOAuthInputHandler for Host {
    fn resolve<'a>(&'a self, ctx: &'a McpContext, _: &'a Cx, input: Box<InputRequiredResult>)
        -> BoxFuture<'a, McpResult<Option<FinalInputResponses>>>
    {
        let round = self.calls.fetch_add(1, Ordering::SeqCst);
        Box::pin(async move {
            assert!(!input.request_state().unwrap().is_empty());
            assert_ne!(input.request_state(), Some("handler-private-state"));
            let requests = input.input_requests().unwrap();
            assert_eq!(requests.members().len(), if self.case.partial() && round > 0 { 1 } else { 2 });
            if round > 0 { assert!(requests.get("left").is_none(), "never resolve the accepted input again"); }
            if matches!(self.case, Case::HostDeclined) {
                return Err(McpError::invalid_params("PRIVATE-HOST-REFUSAL"));
            }
            let keys: &[&str] = if self.case.partial() {
                if round == 0 { &["left"] } else { &["right"] }
            } else { &["left", "right"] };
            let response = answers(keys, &self.answers);
            if matches!(self.case, Case::CancelAnswer) { ctx.request_cancellation().cancel(); }
            Ok(Some(response))
        })
    }
}

async fn dispatch(peer: &Peer, cx: &Cx, reviewed: bool, delivery: Delivery) -> Value {
    let (mut socket, start, headers, body) = peer.receive().await;
    assert_eq!(start, "POST /mcp HTTP/1.1");
    assert_eq!(headers["authorization"], format!("Bearer {}", peer.token));
    assert_eq!(headers["mcp-protocol-version"], FINAL_PROTOCOL_VERSION);
    for name in ["cookie", "mcp-session-id", "last-event-id"] { assert!(!headers.contains_key(name)); }
    let wire: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(headers["mcp-method"], wire["method"].as_str().unwrap());
    let parameters: Vec<_> = headers.iter().filter(|(name, _)| name.starts_with("mcp-param-")).collect();
    if wire["method"] == "tools/call" {
        assert_eq!(wire["params"]["name"], "checkout");
        assert_eq!(headers["mcp-name"], "checkout", "local namespace is not the upstream identity");
        if reviewed {
            assert_eq!(parameters.len(), 2);
            assert_eq!(headers["mcp-param-quantity"], "7");
            assert_eq!(decode_mcp_header_value(headers["mcp-param-region"].as_bytes()).unwrap(), "eu-雪\r\n");
        } else { assert!(parameters.is_empty()); }
    } else {
        assert_eq!(wire["method"], "tools/list");
        assert!(parameters.is_empty(), "reviewed headers belong to tools, not catalog requests");
    }
    assert!(!headers.values().any(|value| value.contains("PRIVATE-BODY-CANARY") || value.contains("DOWNSTREAM-CANARY")));
    peer.seen.lock().unwrap().push(wire);
    let mut request = HttpRequest::new(HttpMethod::Post, "/mcp");
    for (name, value) in headers { request = request.with_header(name, value); }
    request = request.with_body(body);
    let reply = Box::pin(peer.endpoint.handle_secured_async(cx, &peer.policy, request)).await.unwrap();
    assert!(!reply.is_streaming());
    let (response, stream) = reply.into_parts();
    assert!(stream.is_none());
    let value = serde_json::from_slice(&response.body).unwrap();
    // No substitute response or artificial MCP success. Loss happens only
    // after native authentication, header checks, dispatch and journal capture.
    write_reply(&mut socket, response.status.0, &response.headers, &response.body, delivery).await;
    value
}

pub(super) async fn scenario(cx: Cx, case: Case) {
    let mut peer = Peer::new(&cx, true).await;
    install_annotated_tool(&mut peer, case);
    let ((), session) = pair(peer.login(), ManagedOAuthSession::authorize(
        &cx, peer.client(), OAuthSessionPolicy::default(), browser,
    )).await;
    let session = session.unwrap();
    let host = Arc::new(Host { case, calls: AtomicUsize::new(0), answers: AtomicUsize::new(0) });
    let mut provider = ManagedOAuthProvider::new(session.clone()).with_namespace("remote").unwrap();
    if case.interactive() {
        let policy = ManagedOAuthInputPolicy::new(
            ManagedOAuthInputCapabilities { roots: true, ..Default::default() },
            if matches!(case, Case::PartialRoundLimit) { 1 } else { 2 }, 2,
        ).unwrap();
        let policy = if case.partial() { policy.with_response_mode(ManagedOAuthInputResponseMode::Partial) } else { policy };
        provider = provider.with_input_handler(policy, host.clone());
    }
    // Selecting call bounds after input configuration must preserve the backend
    // and its resolver; header review then preserves both and the shared IDs.
    provider = provider.with_limits(
        ManagedCoreLimits::new(8192, 8192, 131072, 0, Duration::from_secs(15)).unwrap(),
        fastmcp_client::http_auth::rpc::catalog::ManagedCatalogLimits::default(),
    );
    let visits = AtomicUsize::new(0);
    let reviewed_schemas = Mutex::new(Vec::new());
    let (catalog, tools) = pair(dispatch(&peer, &cx, false, Delivery::Complete), async {
        if matches!(case, Case::BodyOnly) { return provider.tools(&cx).await; }
        provider.tools_with_header_review(&cx, |tool, binding| {
            assert_eq!(tool.name, "checkout");
            assert!(matches!(binding.header_name(), "Mcp-Param-Quantity" | "Mcp-Param-Region"));
            visits.fetch_add(1, Ordering::SeqCst);
            reviewed_schemas.lock().unwrap().push(tool.input_schema.clone());
            !matches!(case, Case::ReviewDenied)
        }).await
    }).await;
    assert!(catalog.get("error").is_none());
    assert_eq!(visits.load(Ordering::SeqCst), match case { Case::BodyOnly => 0, Case::ReviewDenied => 1, _ => 2 });
    for schema in reviewed_schemas.lock().unwrap().iter() { assert_eq!(schema, &catalog["result"]["tools"][0]["inputSchema"]); }
    let transforms_before = peer.probe.transforms.load(Ordering::SeqCst);
    let posts = match case {
        Case::ReviewDenied | Case::CancelBefore | Case::WrongType => 0,
        Case::Native | Case::BodyOnly | Case::HostDeclined | Case::CancelAnswer => 1,
        Case::Complete | Case::LostReply | Case::PartialRoundLimit => 2,
        Case::Partial => 3,
    };
    if matches!(case, Case::ReviewDenied) {
        assert!(tools.is_err(), "no partially reviewed handlers may escape");
    } else {
        let tool = tools.unwrap().into_iter().next().unwrap();
        assert_eq!(tool.catalog_definition().name, "remote/checkout");
        assert!(!tool.declares_final_mrtr(), "inputs are resolved at the gateway, not relayed downstream");
        let ctx = McpContext::new(cx.clone(), 700);
        if matches!(case, Case::CancelBefore) { ctx.request_cancellation().cancel(); }
        let mut arguments = json!({"quantity":7, "region":"eu-雪\r\n", "private":"PRIVATE-BODY-CANARY",
            "_meta":{"authorization":"DOWNSTREAM-CANARY"}});
        if matches!(case, Case::WrongType) { arguments["quantity"] = json!("invalid-integer"); }
        let server = async {
            let mut replies = Vec::new();
            for index in 0..posts {
                let delivery = if matches!(case, Case::LostReply) && index + 1 == posts { Delivery::LoseHead } else { Delivery::Complete };
                let reply = dispatch(&peer, &cx, !matches!(case, Case::BodyOnly), delivery).await;
                if matches!(case, Case::BodyOnly) {
                    assert_eq!(reply["error"]["code"], fastmcp_protocol::HEADER_MISMATCH_ERROR_CODE);
                } else {
                    assert!(reply.get("error").is_none(), "native upstream refused a reviewed request: {reply}");
                    if case.interactive() && (index == 0 || (case.partial() && index == 1)) {
                        assert_eq!(reply["result"]["resultType"], "input_required");
                        assert_ne!(reply["result"]["requestState"], "handler-private-state");
                    } else { assert_eq!(reply["result"]["resultType"], "complete"); }
                }
                replies.push(reply);
            }
            replies
        };
        let (replies, outcome) = pair(server, tool.call_final_outcome_async_in_request(&ctx, &cx, arguments.clone())).await;
        match (case, outcome) {
            (Case::Native | Case::Complete | Case::Partial, Outcome::Ok(FinalToolOutcome::Complete(result))) => {
                assert_eq!(result.payload.structured_content.as_ref().unwrap()["quantity"], 7);
                assert_eq!(result.payload.structured_content.as_ref().unwrap()["effect"], 1);
            }
            (Case::Native | Case::Complete | Case::Partial, _) => panic!("reviewed provider call must complete"),
            (_, Outcome::Err(error)) => {
                assert!(!error.to_string().contains("CANARY"));
                assert!(!error.to_string().contains("PRIVATE-HOST-REFUSAL"));
                if matches!(case, Case::CancelBefore | Case::CancelAnswer) { assert_eq!(error.code, McpErrorCode::RequestCancelled); }
            }
            _ => panic!("refusal or lost reply must not become a successful call"),
        }
        let requests = peer.seen.lock().unwrap();
        for (index, request) in requests.iter().skip(1).enumerate() {
            assert_eq!(request["params"]["arguments"], arguments);
            assert_eq!(request["params"]["_meta"]["io.modelcontextprotocol/clientCapabilities"],
                if case.interactive() { json!({"roots":{}}) } else { json!({}) });
            if index == 0 {
                assert!(request["params"].get("requestState").is_none());
                assert!(request["params"].get("inputResponses").is_none());
            } else {
                assert_eq!(request["params"]["requestState"], replies[index - 1]["result"]["requestState"]);
                let submitted = request["params"]["inputResponses"].as_object().unwrap();
                assert_eq!(submitted.len(), if case.partial() { 1 } else { 2 });
                if case.partial() { assert!(submitted.contains_key(if index == 1 { "left" } else { "right" })); }
            }
        }
        for (index, request) in requests.iter().enumerate() {
            let id: RequestId = serde_json::from_value(request["id"].clone()).unwrap();
            for previous in &requests[..index] {
                let previous: RequestId = serde_json::from_value(previous["id"].clone()).unwrap();
                assert!(!id.correlates_with(&previous));
            }
        }
    }
    let effects = usize::from(matches!(case, Case::Native | Case::Complete | Case::Partial | Case::LostReply));
    assert_eq!(peer.probe.effects.load(Ordering::SeqCst), effects);
    assert_eq!(peer.probe.transforms.load(Ordering::SeqCst), transforms_before + effects);
    assert_eq!(peer.probe.starts.load(Ordering::SeqCst), usize::from(posts > 0 && !matches!(case, Case::BodyOnly)));
    assert_eq!(host.calls.load(Ordering::SeqCst), match case {
        Case::Partial => 2,
        Case::Complete | Case::HostDeclined | Case::CancelAnswer | Case::LostReply | Case::PartialRoundLimit => 1,
        _ => 0,
    });
    assert_eq!(host.answers.load(Ordering::SeqCst), match case {
        Case::Complete | Case::Partial | Case::CancelAnswer | Case::LostReply => 2,
        Case::PartialRoundLimit => 1,
        _ => 0,
    });
    assert_eq!(peer.seen.lock().unwrap().len(), 1 + posts);
    peer.quiet();
    assert!(!cx.is_cancel_requested());
    // Refusal/cancellation/loss is request-local: the same login and ordinary
    // catalog path remain usable, and headers never bleed into that sibling.
    let (reply, sibling) = pair(dispatch(&peer, &cx, false, Delivery::Complete), provider.tools(&cx)).await;
    assert!(reply.get("error").is_none());
    assert_eq!(sibling.unwrap().len(), 1);
    assert_eq!(peer.seen.lock().unwrap().len(), 2 + posts);
    assert_eq!(peer.grants.load(Ordering::SeqCst), 1);
    peer.quiet();
    session.close();
    peer.journal.close().unwrap();
}

#[test] fn native_reviewed_headers_reach_the_annotated_upstream() { isolated("provider_headers::native_reviewed_headers_reach_the_annotated_upstream", super::Case::ProviderHeaders(Case::Native)); }
#[test] fn body_only_control_is_refused_before_the_upstream_handler() { isolated("provider_headers::body_only_control_is_refused_before_the_upstream_handler", super::Case::ProviderHeaders(Case::BodyOnly)); }
#[test] fn disclosure_denial_returns_no_handlers_and_keeps_the_login() { isolated("provider_headers::disclosure_denial_returns_no_handlers_and_keeps_the_login", super::Case::ProviderHeaders(Case::ReviewDenied)); }
#[test] fn reviewed_headers_survive_complete_host_input_workflows() { isolated("provider_headers::reviewed_headers_survive_complete_host_input_workflows", super::Case::ProviderHeaders(Case::Complete)); }
#[test] fn reviewed_headers_survive_both_partial_continuations() { isolated("provider_headers::reviewed_headers_survive_both_partial_continuations", super::Case::ProviderHeaders(Case::Partial)); }
#[test] fn host_decline_never_posts_a_header_bearing_continuation() { isolated("provider_headers::host_decline_never_posts_a_header_bearing_continuation", super::Case::ProviderHeaders(Case::HostDeclined)); }
#[test] fn precancelled_reviewed_tool_never_opens_a_post() { isolated("provider_headers::precancelled_reviewed_tool_never_opens_a_post", super::Case::ProviderHeaders(Case::CancelBefore)); }
#[test] fn cancelled_ready_answer_is_not_disclosed_in_a_continuation() { isolated("provider_headers::cancelled_ready_answer_is_not_disclosed_in_a_continuation", super::Case::ProviderHeaders(Case::CancelAnswer)); }
#[test] fn invalid_header_primitive_never_reaches_the_upstream() { isolated("provider_headers::invalid_header_primitive_never_reaches_the_upstream", super::Case::ProviderHeaders(Case::WrongType)); }
#[test] fn lost_reviewed_reply_never_reexecutes_or_resolves_again() { isolated("provider_headers::lost_reviewed_reply_never_reexecutes_or_resolves_again", super::Case::ProviderHeaders(Case::LostReply)); }
#[test] fn reviewed_partial_work_keeps_its_original_round_limit() { isolated("provider_headers::reviewed_partial_work_keeps_its_original_round_limit", super::Case::ProviderHeaders(Case::PartialRoundLimit)); }
