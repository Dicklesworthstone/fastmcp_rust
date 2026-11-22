use super::super::{build_prompts, build_resources, build_tools, core_request};
use super::*;
use crate::handler::{PromptHandler, ResourceHandler, ToolHandler};
use crate::router::{InboundRequestContext, InboundRequestTransport, ModernConnection, Router};
use fastmcp_core::{ClientCapabilityInfo, McpErrorCode, block_on};
use fastmcp_protocol::{CoreResult, JsonRpcRequest};
use serde_json::json;
use std::collections::VecDeque;
use std::sync::Mutex;
use std::sync::atomic::AtomicU64;

// These tests exercise the real router, binding registry and returned handler
// types. Only the already typed native RPC boundary is scripted; real OAuth,
// secured HTTP and TLS composition is covered by managed_provider/downstream.
struct Backend {
    calls: Mutex<Vec<(String, Value)>>,
    replies: Mutex<VecDeque<FinalCoreResult>>,
    cancel_on_return: bool,
}

impl CoreBackend for Backend {
    fn execute<'a>(
        &'a self,
        ctx: &'a McpContext,
        _cx: &'a Cx,
        request: CoreRequest,
        _id: RequestId,
        _limits: ManagedCoreLimits,
    ) -> BoxFuture<'a, McpResult<FinalCoreResult>> {
        Box::pin(async move {
            self.calls.lock().unwrap().push((
                request.method().to_owned(),
                request.encode_params().unwrap().unwrap(),
            ));
            if self.cancel_on_return {
                ctx.request_cancellation().cancel();
            }
            self.replies
                .lock()
                .unwrap()
                .pop_front()
                .ok_or_else(|| McpError::internal_error("test response queue exhausted"))
        })
    }
}

fn roots_policy() -> ManagedOAuthInputCapabilities {
    ManagedOAuthInputCapabilities {
        roots: true,
        ..Default::default()
    }
}

fn context(cx: &Cx, connection: &ModernConnection, id: u64) -> McpContext {
    InboundRequestContext::with_modern_connection(
        cx.clone(),
        id,
        InboundRequestTransport::Memory,
        connection,
    )
    .request_context()
    .with_client_capabilities(ClientCapabilityInfo::new().with_roots(false))
}

#[derive(Clone, Copy, Debug)]
enum Family {
    Tool,
    Resource,
    Template,
    Prompt,
}

impl Family {
    fn method(self) -> &'static str {
        match self {
            Self::Tool => "tools/call",
            Self::Resource | Self::Template => "resources/read",
            Self::Prompt => "prompts/get",
        }
    }

    fn parameters(self, upstream: bool) -> Value {
        match self {
            Self::Tool => json!({
                "name": if upstream { "lookup" } else { "remote/lookup" },
                "arguments":{"key":"kept","_meta":{"application-data":7}}
            }),
            Self::Resource | Self::Template => json!({"uri":"report://monthly/alpha"}),
            Self::Prompt => json!({
                "name": if upstream { "compose" } else { "remote/compose" },
                "arguments":{"topic":"kept"}
            }),
        }
    }

    fn complete(self) -> Value {
        match self {
            Self::Tool => {
                json!({"resultType":"complete","content":[],"structuredContent":{"answer":42}})
            }
            Self::Resource | Self::Template => json!({
                "resultType":"complete","contents":[{"uri":"report://monthly/alpha","text":"report"}],
                "ttlMs":0,"cacheScope":"private"
            }),
            Self::Prompt => json!({"resultType":"complete","messages":[],"description":"composed"}),
        }
    }

    fn result(self, value: Value) -> FinalCoreResult {
        let request = core_request(self.method(), self.parameters(true), None).unwrap();
        let CoreResult::Final(result) = request
            .decode_result(&serde_json::to_string(&value).unwrap())
            .unwrap()
        else {
            panic!("expected modern result");
        };
        result
    }

    fn install(self, router: &mut Router, forwarder: Arc<Forwarder>) {
        match self {
            Self::Tool => {
                let tool = build_tools(
                    forwarder,
                    vec![
                        serde_json::from_value(json!({
                            "name":"lookup","inputSchema":{"type":"object"}
                        }))
                        .unwrap(),
                    ],
                    Some("remote"),
                )
                .unwrap()
                .pop()
                .unwrap();
                assert!(tool.declares_final_mrtr());
                router.add_tool(tool).unwrap();
            }
            Self::Resource => {
                let resource = build_resources(
                    forwarder,
                    vec![
                        serde_json::from_value(json!({
                            "uri":"report://monthly/alpha","name":"Monthly report"
                        }))
                        .unwrap(),
                    ],
                )
                .unwrap()
                .pop()
                .unwrap();
                assert!(resource.declares_final_mrtr());
                router.add_resource(resource);
            }
            Self::Template => {
                let template = super::super::dynamic::build_templates(
                    forwarder,
                    vec![
                        serde_json::from_value(json!({
                            "uriTemplate":"report://monthly/{name}","name":"Monthly report"
                        }))
                        .unwrap(),
                    ],
                )
                .unwrap()
                .pop()
                .unwrap();
                assert!(template.declares_final_mrtr());
                router.add_resource(template);
            }
            Self::Prompt => {
                let prompt = build_prompts(
                    forwarder,
                    vec![
                        serde_json::from_value(json!({
                            "name":"compose","arguments":[{"name":"topic","required":true}]
                        }))
                        .unwrap(),
                    ],
                    Some("remote"),
                )
                .unwrap()
                .pop()
                .unwrap();
                assert!(prompt.declares_final_mrtr());
                router.add_prompt(prompt);
            }
        }
    }
}

fn fixture(family: Family, challenge: Value, cancel_on_return: bool) -> (Router, Arc<Backend>) {
    let backend = Arc::new(Backend {
        calls: Mutex::new(Vec::new()),
        replies: Mutex::new(
            vec![family.result(challenge), family.result(family.complete())].into(),
        ),
        cancel_on_return,
    });
    let forwarder = Arc::new(Forwarder {
        backend: Arc::new(DownstreamBackend {
            inner: backend.clone(),
            allowed: roots_policy(),
        }),
        next_id: Arc::new(AtomicU64::new(1)),
        limits: ManagedCoreLimits::default(),
    });
    let mut router = Router::new();
    family.install(&mut router, forwarder);
    (router, backend)
}

fn request(family: Family, id: i64, mut parameters: Value) -> JsonRpcRequest {
    parameters["_meta"] = json!({
        "io.modelcontextprotocol/protocolVersion":"2026-07-28",
        "io.modelcontextprotocol/clientCapabilities":{"roots":{}},
        "io.modelcontextprotocol/clientInfo":{"name":"DOWNSTREAM-IDENTITY","version":"1"},
        "com.example/downstream-private":"PRIVATE-METADATA"
    });
    JsonRpcRequest::new(family.method(), Some(parameters), id)
}

fn dispatch(router: &Router, ctx: &McpContext, request: &JsonRpcRequest) -> McpResult<Value> {
    let raw = serde_json::to_string(request.params.as_ref().unwrap()).unwrap();
    block_on(router.dispatch_stateless_with_raw_params(ctx, request, Some(&raw)))
}

#[test]
fn downstream_all_handler_families_seal_and_resume_absent_empty_and_opaque_upstream_state() {
    for family in [
        Family::Tool,
        Family::Resource,
        Family::Template,
        Family::Prompt,
    ] {
        for upstream in [None, Some(""), Some("UPSTREAM-PRIVATE-STATE")] {
            let mut challenge = json!({
                "resultType":"input_required",
                "inputRequests":{"roots":{"method":"roots/list"}},
                "_meta":{"com.example/private":"PRIVATE-UPSTREAM-METADATA"},
                "com.example/private":"PRIVATE-UPSTREAM-SIBLING"
            });
            if let Some(state) = upstream {
                challenge["requestState"] = json!(state);
            }
            let (router, backend) = fixture(family, challenge, false);
            let cx = Cx::for_testing();
            let connection = ModernConnection::new();
            let ctx = context(&cx, &connection, 1);
            let initial =
                dispatch(&router, &ctx, &request(family, 1, family.parameters(false))).unwrap();
            assert_eq!(initial["resultType"], "input_required");
            let public_state = initial["requestState"].as_str().unwrap();
            assert!(!public_state.is_empty());
            assert_ne!(Some(public_state), upstream);
            let public_json = serde_json::to_string(&initial).unwrap();
            for secret in [
                "UPSTREAM-PRIVATE-STATE",
                "PRIVATE-UPSTREAM",
                CONTINUATION_VERSION,
            ] {
                assert!(!public_json.contains(secret));
            }
            let mut parameters = family.parameters(false);
            parameters["requestState"] = json!(public_state);
            parameters["inputResponses"] = json!({"roots":{"roots":[{"uri":"file:///approved"}]}});
            let retry = request(family, 2, parameters);
            let result = dispatch(&router, &context(&cx, &connection, 2), &retry).unwrap();
            assert_eq!(result["resultType"], "complete", "{family:?}");
            let calls = backend.calls.lock().unwrap();
            assert_eq!(calls.len(), 2);
            assert_eq!(calls[0].0, family.method());
            assert!(calls[0].1.get("requestState").is_none());
            assert_eq!(
                calls[1].1.get("requestState"),
                upstream.map(Value::from).as_ref()
            );
            assert_eq!(
                calls[1].1["inputResponses"],
                json!({"roots":{"roots":[{"uri":"file:///approved"}]}})
            );
            for (_, parameters) in calls.iter() {
                assert_eq!(
                    parameters["_meta"][FINAL_CLIENT_CAPABILITIES_META_KEY],
                    json!({"roots":{}})
                );
                assert!(
                    parameters["_meta"]
                        .get("io.modelcontextprotocol/clientInfo")
                        .is_none()
                );
                assert!(
                    parameters["_meta"]
                        .get("com.example/downstream-private")
                        .is_none()
                );
                let original = family.parameters(true);
                for (key, value) in original.as_object().unwrap() {
                    assert_eq!(&parameters[key], value);
                }
            }
            drop(calls);
            assert!(dispatch(&router, &context(&cx, &connection, 3), &retry).is_err());
            assert_eq!(backend.calls.lock().unwrap().len(), 2);
        }
    }
}

#[test]
fn downstream_state_only_challenges_preserve_absent_input_responses_in_every_family() {
    for family in [
        Family::Tool,
        Family::Resource,
        Family::Template,
        Family::Prompt,
    ] {
        let (router, backend) = fixture(
            family,
            json!({
                "resultType":"input_required","requestState":"UPSTREAM-STATE-ONLY"
            }),
            false,
        );
        let cx = Cx::for_testing();
        let connection = ModernConnection::new();
        let initial = dispatch(
            &router,
            &context(&cx, &connection, 1),
            &request(family, 1, family.parameters(false)),
        )
        .unwrap();
        assert!(initial.get("inputRequests").is_none());
        let mut parameters = family.parameters(false);
        parameters["requestState"] = initial["requestState"].clone();
        let result = dispatch(
            &router,
            &context(&cx, &connection, 2),
            &request(family, 2, parameters),
        )
        .unwrap();
        assert_eq!(result["resultType"], "complete");
        let calls = backend.calls.lock().unwrap();
        assert_eq!(calls.len(), 2);
        assert_eq!(calls[1].1["requestState"], "UPSTREAM-STATE-ONLY");
        assert!(calls[1].1.get("inputResponses").is_none());
    }
}

#[test]
fn downstream_capability_drift_and_pre_cancelled_retry_refuse_before_upstream_effects() {
    for cancel in [false, true] {
        let family = Family::Tool;
        let (router, backend) = fixture(
            family,
            json!({
                "resultType":"input_required","requestState":"UPSTREAM",
                "inputRequests":{"roots":{"method":"roots/list"}}
            }),
            false,
        );
        let cx = Cx::for_testing();
        let connection = ModernConnection::new();
        let initial = dispatch(
            &router,
            &context(&cx, &connection, 1),
            &request(family, 1, family.parameters(false)),
        )
        .unwrap();
        let mut parameters = family.parameters(false);
        parameters["requestState"] = initial["requestState"].clone();
        parameters["inputResponses"] = json!({"roots":{"roots":[]}});
        let mut retry = request(family, 2, parameters);
        let ctx = if cancel {
            let ctx = context(&cx, &connection, 2);
            ctx.request_cancellation().cancel();
            ctx
        } else {
            retry.params.as_mut().unwrap()["_meta"][FINAL_CLIENT_CAPABILITIES_META_KEY] = json!({});
            context(&cx, &connection, 2).with_client_capabilities(ClientCapabilityInfo::new())
        };
        if cancel {
            let error = dispatch(&router, &ctx, &retry).unwrap_err();
            assert_eq!(error.code, McpErrorCode::RequestCancelled);
            assert!(!error.message.contains("UPSTREAM"));
        } else {
            // Router::handle_tools_call maps tool-handler InvalidParams refusals
            // into a tool-level error result (`isError: true`) without leaking
            // upstream continuation state.
            let refused = dispatch(&router, &ctx, &retry).unwrap();
            assert_eq!(refused["resultType"], "complete");
            assert_eq!(refused["isError"], true);
            let message = refused["content"][0]["text"].as_str().unwrap();
            assert_eq!(message, CONTINUATION_REJECTED);
            assert!(!message.contains("UPSTREAM"));
        }
        assert_eq!(backend.calls.lock().unwrap().len(), 1);
    }
}

#[test]
fn downstream_requires_retained_owner_and_checks_cancellation_after_native_return() {
    let family = Family::Tool;
    let challenge = json!({
        "resultType":"input_required","requestState":"UPSTREAM",
        "inputRequests":{"roots":{"method":"roots/list"}}
    });
    let (_, backend) = fixture(family, challenge.clone(), false);
    let native = DownstreamBackend {
        inner: backend.clone(),
        allowed: roots_policy(),
    };
    let cx = Cx::for_testing();
    let ctx = McpContext::new(cx.clone(), 1)
        .with_client_capabilities(ClientCapabilityInfo::new().with_roots(false));
    let result = block_on(native.execute(
        &ctx,
        &cx,
        core_request("tools/call", family.parameters(true), None).unwrap(),
        RequestId::Number(1),
        ManagedCoreLimits::default(),
    ));
    assert!(result.is_err());
    assert!(backend.calls.lock().unwrap().is_empty());

    let (router, backend) = fixture(family, challenge, true);
    let connection = ModernConnection::new();
    let error = dispatch(
        &router,
        &context(&cx, &connection, 2),
        &request(family, 2, family.parameters(false)),
    )
    .unwrap_err();
    assert_eq!(error.code, McpErrorCode::RequestCancelled);
    assert_eq!(backend.calls.lock().unwrap().len(), 1);
}

#[test]
fn downstream_intersection_retains_only_explicit_leaf_permissions() {
    let all = ManagedOAuthInputCapabilities {
        roots: true,
        sampling: true,
        sampling_tools: true,
        sampling_context: true,
        form_elicitation: true,
        url_elicitation: true,
    };
    let cx = Cx::for_testing();
    let plain = McpContext::new(cx.clone(), 1);
    assert_eq!(capability_bits(intersect_capabilities(all, &plain)), 0);
    let basic = plain.clone().with_client_capabilities(
        ClientCapabilityInfo::new()
            .with_sampling()
            .with_elicitation(true, false),
    );
    let allowed = intersect_capabilities(all, &basic);
    assert!(allowed.sampling && allowed.form_elicitation);
    assert!(
        !allowed.roots
            && !allowed.sampling_tools
            && !allowed.sampling_context
            && !allowed.url_elicitation
    );
    let nested = serde_json::from_value(json!({"private-advisory":"NEVER-FORWARD"})).unwrap();
    let full = plain.with_client_capabilities(
        ClientCapabilityInfo::new()
            .with_roots(true)
            .with_sampling_capabilities(Some(nested), Some(serde_json::Map::new()))
            .with_elicitation(true, true),
    );
    let capabilities = intersect_capabilities(all, &full);
    assert_eq!(capability_bits(capabilities), 63);
    assert!(
        !capabilities
            .metadata()
            .to_string()
            .contains("NEVER-FORWARD")
    );
    assert_eq!(
        capability_bits(intersect_capabilities(
            ManagedOAuthInputCapabilities::default(),
            &full
        )),
        0
    );
}

#[test]
fn downstream_descriptor_admission_distinguishes_sampling_context_tools_and_elicitation_modes() {
    fn admit(value: &Value, allowed: ManagedOAuthInputCapabilities) -> McpResult<()> {
        admit_descriptor(value, allowed)?;
        MrtrInputRequest::from_wire(value).map(|_| ())
    }
    let sampling =
        json!({"method":"sampling/createMessage","params":{"messages":[],"maxTokens":16}});
    let form = json!({"method":"elicitation/create","params":{
        "mode":"form","message":"details","requestedSchema":{"type":"object","properties":{}}
    }});
    let url = json!({"method":"elicitation/create","params":{
        "mode":"url","message":"approve","url":"https://example.com/approve"
    }});
    let basic = ManagedOAuthInputCapabilities {
        sampling: true,
        form_elicitation: true,
        ..Default::default()
    };
    assert!(admit(&sampling, basic).is_ok());
    assert!(admit(&form, basic).is_ok());
    assert!(admit(&url, basic).is_err());
    assert!(admit(&json!({"method":"roots/list"}), basic).is_err());
    let all = ManagedOAuthInputCapabilities {
        roots: true,
        sampling: true,
        sampling_tools: true,
        sampling_context: true,
        form_elicitation: true,
        url_elicitation: true,
    };
    assert!(admit(&url, all).is_ok());
    for (field, value) in [
        ("tools", json!([])),
        ("toolChoice", json!({"mode":"auto"})),
        ("includeContext", json!("allServers")),
    ] {
        let mut request = sampling.clone();
        request["params"][field] = value;
        assert!(admit(&request, basic).is_err(), "{field}");
        assert!(admit(&request, all).is_ok(), "{field}");
        request["params"][field] = Value::Null;
        assert!(admit(&request, all).is_err(), "explicit null {field}");
    }
    for (field, value) in [
        ("tools", json!([[]])),
        ("toolChoice", json!({"mode":null})),
        ("includeContext", json!(false)),
    ] {
        let mut request = sampling.clone();
        request["params"][field] = value;
        assert!(admit(&request, all).is_err());
    }
    for invalid in [
        json!({"method":"roots/list","params":[]}),
        json!({"method":"elicitation/create","params":{"mode":"unknown","message":"details","requestedSchema":{"type":"object","properties":{}}}}),
        json!({"method":"elicitation/create","params":{"mode":"form","message":"details","requestedSchema":{"type":"string"}}}),
        json!({"method":"sampling/createMessage","params":null}),
    ] {
        assert!(admit(&invalid, all).is_err());
    }
}

#[test]
fn downstream_private_envelope_preserves_provider_metadata_and_refuses_wrong_policy() {
    let mut request = core_request(
        "tools/call",
        Family::Tool.parameters(true),
        Some(json!("PROVIDER-PROGRESS")),
    )
    .unwrap()
    .encode_params()
    .unwrap()
    .unwrap();
    request["_meta"]["io.modelcontextprotocol/clientInfo"] =
        json!({"name":"provider","version":"1"});
    request["_meta"][FINAL_CLIENT_CAPABILITIES_META_KEY]["extensions"] =
        json!({"com.example/provider-owned":{}});
    request["_meta"][FINAL_CLIENT_CAPABILITIES_META_KEY]["sampling"] = json!({"tools":{}});
    request["requestState"] =
        json!(serde_json::to_string(&(CONTINUATION_VERSION, 1_u8, Some(""))).unwrap());
    let request =
        CoreRequest::decode(ProtocolEra::Modern2026, "tools/call", Some(&request)).unwrap();
    let prepared = prepare_request(request, roots_policy())
        .unwrap()
        .encode_params()
        .unwrap()
        .unwrap();
    assert_eq!(prepared["requestState"], "");
    assert_eq!(prepared["_meta"]["progressToken"], "PROVIDER-PROGRESS");
    assert_eq!(
        prepared["_meta"]["io.modelcontextprotocol/clientInfo"]["name"],
        "provider"
    );
    assert_eq!(
        prepared["_meta"][FINAL_CLIENT_CAPABILITIES_META_KEY],
        json!({
            "roots":{},"extensions":{"com.example/provider-owned":{}}
        })
    );

    for retained in [
        json!(serde_json::to_string(&(CONTINUATION_VERSION, 0_u8, Some("private"))).unwrap()),
        json!(serde_json::to_string(&("wrong-version", 1_u8, Some("private"))).unwrap()),
        json!("arbitrary-public-state"),
    ] {
        let mut parameters = Family::Tool.parameters(true);
        parameters["requestState"] = retained;
        let error = prepare_request(
            core_request("tools/call", parameters, None).unwrap(),
            roots_policy(),
        )
        .err()
        .unwrap();
        assert_eq!(error.message, CONTINUATION_REJECTED);
    }
}
