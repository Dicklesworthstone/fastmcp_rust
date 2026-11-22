//! Public machine-provider acquisition and the real retained router boundary.
//! The parent scripts only the independently authenticated native RPC seam;
//! the HTTP integration fixture separately proves machine-grant custody.

use super::*;
use crate::router::{InboundRequestContext, InboundRequestTransport, ModernConnection, Router};
use fastmcp_core::{ClientCapabilityInfo, block_on};
use fastmcp_protocol::JsonRpcRequest;

const ROOTS: &str = r#"{"resultType":"input_required","requestState":"MACHINE-PRIVATE-STATE","inputRequests":{"roots":{"method":"roots/list"}},"_meta":{"private":"PRIVATE-UPSTREAM-METADATA"}}"#;
const EMPTY_STATE: &str = r#"{"resultType":"input_required","requestState":"","inputRequests":{"roots":{"method":"roots/list"}}}"#;
const ABSENT_STATE: &str =
    r#"{"resultType":"input_required","inputRequests":{"roots":{"method":"roots/list"}}}"#;
const STATE_ONLY: &str =
    r#"{"resultType":"input_required","requestState":"MACHINE-PRIVATE-STATE"}"#;

fn roots_policy() -> ManagedOAuthInputCapabilities {
    ManagedOAuthInputCapabilities {
        roots: true,
        ..Default::default()
    }
}

fn context(cx: &Cx, connection: &ModernConnection, id: u64, roots: bool) -> McpContext {
    let capabilities = if roots {
        ClientCapabilityInfo::new().with_roots(false)
    } else {
        ClientCapabilityInfo::new()
    };
    InboundRequestContext::with_modern_connection(
        cx.clone(),
        id,
        InboundRequestTransport::Memory,
        connection,
    )
    .request_context()
    .with_client_capabilities(capabilities)
}

fn dispatch(router: &Router, ctx: &McpContext, request: &JsonRpcRequest) -> McpResult<Value> {
    let raw = serde_json::to_string(request.params.as_ref().unwrap()).unwrap();
    block_on(router.dispatch_stateless_with_raw_params(ctx, request, Some(&raw)))
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
                "name": if upstream { "lookup" } else { "machine/lookup" },
                "arguments":{"key":"kept","_meta":{"application-data":7}}
            }),
            Self::Resource | Self::Template => json!({"uri":"note://documents/one"}),
            Self::Prompt => json!({
                "name": if upstream { "summarize" } else { "machine/summarize" },
                "arguments":{"subject":"kept"}
            }),
        }
    }

    fn complete(self) -> &'static str {
        match self {
            Self::Tool => TOOL_RESULT,
            Self::Resource | Self::Template => RESOURCE_RESULT,
            Self::Prompt => PROMPT_RESULT,
        }
    }

    fn install(self, provider: &ClientCredentialsProvider, cx: &Cx) -> Router {
        let mut router = Router::new();
        match self {
            Self::Tool => {
                let tool = ready(provider.tools(cx)).unwrap().pop().unwrap();
                assert!(tool.declares_final_mrtr());
                router.add_tool(tool).unwrap();
            }
            Self::Resource => {
                let resource = ready(provider.resources(cx)).unwrap().pop().unwrap();
                assert!(resource.declares_final_mrtr());
                router.add_resource(resource);
            }
            Self::Template => {
                let template = ready(provider.resource_templates(cx))
                    .unwrap()
                    .pop()
                    .unwrap();
                assert!(template.declares_final_mrtr());
                router.add_resource(template);
            }
            Self::Prompt => {
                let prompt = ready(provider.prompts(cx)).unwrap().pop().unwrap();
                assert!(prompt.declares_final_mrtr());
                router.add_prompt(prompt);
            }
        }
        router
    }

    fn request(self, id: i64, mut parameters: Value, roots: bool) -> JsonRpcRequest {
        parameters["_meta"] = json!({
            "io.modelcontextprotocol/protocolVersion":"2026-07-28",
            "io.modelcontextprotocol/clientCapabilities":if roots { json!({"roots":{}}) } else { json!({}) },
            "io.modelcontextprotocol/clientInfo":{"name":"DOWNSTREAM-IDENTITY","version":"1"},
            "com.example/private":"DOWNSTREAM-PRIVATE-METADATA"
        });
        JsonRpcRequest::new(self.method(), Some(parameters), id)
    }
}

fn provider(source: Arc<Source>) -> ClientCredentialsProvider {
    ClientCredentialsProvider::from_source(source)
        .with_downstream_inputs(roots_policy())
        .unwrap()
        .with_namespace("machine")
        .unwrap()
}

#[test]
fn downstream_machine_all_public_families_preserve_state_arguments_limits_and_one_use() {
    for family in [
        Family::Tool,
        Family::Resource,
        Family::Template,
        Family::Prompt,
    ] {
        for (challenge, state, inputs) in [
            (ROOTS, Some("MACHINE-PRIVATE-STATE"), true),
            (EMPTY_STATE, Some(""), true),
            (ABSENT_STATE, None, true),
            (STATE_ONLY, Some("MACHINE-PRIVATE-STATE"), false),
        ] {
            let source = source(vec![challenge, family.complete()]);
            let limits =
                ManagedCoreLimits::new(4096, 4096, 8192, 32, Duration::from_secs(7)).unwrap();
            let provider = provider(source.clone())
                .with_limits(limits, ClientCredentialsCatalogLimits::default());
            let cx = Cx::for_testing();
            let router = family.install(&provider, &cx);
            let connection = ModernConnection::new();
            let first = dispatch(
                &router,
                &context(&cx, &connection, 1, true),
                &family.request(1, family.parameters(false), true),
            )
            .unwrap();
            assert_eq!(first["resultType"], "input_required", "{family:?}");
            let public = first["requestState"].as_str().unwrap();
            assert!(!public.is_empty());
            assert_ne!(Some(public), state);
            assert_eq!(first.get("inputRequests").is_some(), inputs);
            for private in [
                "MACHINE-PRIVATE-STATE",
                "PRIVATE-UPSTREAM-METADATA",
                "fastmcp.managed-oauth.mrtr/v1",
            ] {
                assert!(!first.to_string().contains(private));
            }
            let mut parameters = family.parameters(false);
            parameters["requestState"] = first["requestState"].clone();
            if inputs {
                parameters["inputResponses"] =
                    json!({"roots":{"roots":[{"uri":"file:///approved"}]}});
            }
            let retry = family.request(2, parameters, true);
            let result = dispatch(&router, &context(&cx, &connection, 2, true), &retry).unwrap();
            assert_eq!(result["resultType"], "complete", "{family:?}");
            assert_ne!(result.get("isError"), Some(&Value::Bool(true)));
            let calls = source.calls.lock().unwrap();
            assert_eq!(calls.len(), 2);
            assert!(calls[0].get("requestState").is_none());
            assert_eq!(
                calls[1].get("requestState"),
                state.map(Value::from).as_ref()
            );
            assert_eq!(calls[1].get("inputResponses").is_some(), inputs);
            if inputs {
                assert_eq!(
                    calls[1]["inputResponses"],
                    json!({"roots":{"roots":[{"uri":"file:///approved"}]}})
                );
            }
            for call in calls.iter() {
                for (key, value) in family.parameters(true).as_object().unwrap() {
                    assert_eq!(&call[key], value);
                }
                assert_eq!(
                    call["_meta"]["io.modelcontextprotocol/clientCapabilities"],
                    json!({"roots":{}})
                );
                assert!(
                    call["_meta"]
                        .get("io.modelcontextprotocol/clientInfo")
                        .is_none()
                );
                assert!(call["_meta"].get("com.example/private").is_none());
            }
            drop(calls);
            assert_eq!(*source.input_modes.lock().unwrap(), vec![None, None]);
            assert_eq!(
                *source.call_policies.lock().unwrap(),
                vec![format!("{limits:?}"); 2]
            );
            let ids = source.ids.lock().unwrap();
            assert_eq!(
                ids.len(),
                6,
                "catalog and both operations own fresh ID pairs"
            );
            assert_eq!(ids.iter().collect::<HashSet<_>>().len(), 6);
            drop(ids);
            assert!(dispatch(&router, &context(&cx, &connection, 3, true), &retry).is_err());
            assert_eq!(source.calls.lock().unwrap().len(), 2);
        }
    }
}

#[test]
fn downstream_machine_conflicting_modes_refuse_all_acquisitions_before_source_effects() {
    let source = source(vec![TOOL_RESULT, TOOL_RESULT, COMPLETION_RESULT]);
    let provider = ClientCredentialsProvider::from_source(source.clone());
    let cx = Cx::for_testing();
    let old_tool = ready(provider.tools(&cx)).unwrap().pop().unwrap();
    let selected = selected_resource(&provider, &cx);
    let policy = ManagedOAuthInputPolicy::new(roots_policy(), 3, 8).unwrap();
    let host = provider
        .clone()
        .with_input_handler(policy, Arc::new(NoInput));
    assert!(host.clone().with_downstream_inputs(roots_policy()).is_err());
    assert!(host.validate_input_mode().is_ok());
    let downstream = provider.with_downstream_inputs(roots_policy()).unwrap();
    assert!(
        downstream
            .clone()
            .with_downstream_inputs(roots_policy())
            .is_err()
    );
    let conflict = downstream
        .clone()
        .with_input_handler(policy, Arc::new(NoInput));
    let expected = conflict.validate_input_mode().unwrap_err();
    assert_eq!(expected.code, McpErrorCode::InvalidParams);
    let previous_ids = source.ids.lock().unwrap().len();
    for error in [
        ready(conflict.tools(&cx)).err().unwrap(),
        ready(conflict.resources(&cx)).err().unwrap(),
        ready(conflict.prompts(&cx)).err().unwrap(),
        ready(conflict.resource_templates(&cx)).err().unwrap(),
        ready(conflict.open_resource_updates(
            &cx,
            &McpRequestCancellation::new(),
            &[selected],
            ClientCredentialsCoreSubscriptionLimits::default(),
        ))
        .err()
        .unwrap(),
    ] {
        assert_eq!(error.code, expected.code);
        assert_eq!(error.message, expected.message);
    }
    assert_eq!(source.ids.lock().unwrap().len(), previous_ids);
    assert!(source.calls.lock().unwrap().is_empty());
    assert!(source.subscription_filters.lock().unwrap().is_empty());

    // A failed reconfiguration neither mutates earlier handlers nor changes the
    // retained host/downstream clones. Completion stays a complete-only route.
    let ctx = McpContext::new(cx.clone(), 81);
    assert!(ready(old_tool.call_final_async_in_request(&ctx, &cx, json!({}))).is_ok());
    let host_tool = ready(host.tools(&cx)).unwrap().pop().unwrap();
    assert!(ready(host_tool.call_final_async_in_request(&ctx, &cx, json!({}))).is_ok());
    let prompt = ready(downstream.prompts(&cx)).unwrap().pop().unwrap();
    let completion = prompt.completion_handler().unwrap();
    let params: FinalCompletionParams = serde_json::from_value(json!({
        "_meta":{},"ref":{"type":"ref/prompt","name":"summarize"},
        "argument":{"name":"subject","value":"o"}
    }))
    .unwrap();
    assert!(ready(completion.complete_final_async_in_request(&ctx, &cx, params)).is_ok());
    assert_eq!(
        *source.input_modes.lock().unwrap(),
        vec![None, Some(ManagedOAuthInputResponseMode::Complete), None]
    );
    assert!(downstream.validate_input_mode().is_ok());
}

#[test]
fn downstream_machine_intersects_local_and_admitted_capabilities() {
    for (allowed, advertised, admitted) in [
        (true, true, true),
        (false, true, false),
        (true, false, false),
    ] {
        let source = source(vec![ROOTS]);
        let configured = ClientCredentialsProvider::from_source(source.clone())
            .with_downstream_inputs(if allowed {
                roots_policy()
            } else {
                ManagedOAuthInputCapabilities::default()
            })
            .unwrap()
            .with_namespace("machine")
            .unwrap();
        let cx = Cx::for_testing();
        let router = Family::Tool.install(&configured, &cx);
        let connection = ModernConnection::new();
        let result = dispatch(
            &router,
            &context(&cx, &connection, 1, advertised),
            &Family::Tool.request(1, Family::Tool.parameters(false), advertised),
        )
        .unwrap();
        assert_eq!(
            result["resultType"],
            if admitted {
                "input_required"
            } else {
                "complete"
            }
        );
        if !admitted {
            assert_eq!(result["isError"], true);
            assert!(result.get("requestState").is_none());
            assert!(result.get("inputRequests").is_none());
        }
        assert_eq!(
            source.calls.lock().unwrap()[0]["_meta"]["io.modelcontextprotocol/clientCapabilities"],
            if admitted {
                json!({"roots":{}})
            } else {
                json!({})
            }
        );
        assert!(!result.to_string().contains("MACHINE-PRIVATE-STATE"));
    }
}

#[test]
fn downstream_machine_retries_reject_capability_drift_and_cancellation_without_new_effects() {
    for cancel in [false, true] {
        let source = source(vec![ROOTS]);
        let provider = provider(source.clone());
        let cx = Cx::for_testing();
        let router = Family::Tool.install(&provider, &cx);
        let connection = ModernConnection::new();
        let first = dispatch(
            &router,
            &context(&cx, &connection, 1, true),
            &Family::Tool.request(1, Family::Tool.parameters(false), true),
        )
        .unwrap();
        let mut parameters = Family::Tool.parameters(false);
        parameters["requestState"] = first["requestState"].clone();
        parameters["inputResponses"] = json!({"roots":{"roots":[]}});
        let ctx = context(&cx, &connection, 2, cancel);
        if cancel {
            ctx.request_cancellation().cancel();
        }
        let outcome = dispatch(&router, &ctx, &Family::Tool.request(2, parameters, cancel));
        if cancel {
            assert_eq!(outcome.unwrap_err().code, McpErrorCode::RequestCancelled);
        } else {
            let result = outcome.unwrap();
            assert_eq!(result["isError"], true);
            assert!(result.get("requestState").is_none());
            assert!(!result.to_string().contains("MACHINE-PRIVATE-STATE"));
        }
        assert_eq!(source.calls.lock().unwrap().len(), 1);
        assert_eq!(source.ids.lock().unwrap().len(), 4);
    }
}

#[test]
fn downstream_machine_requires_retained_owner_and_discards_cancelled_native_results() {
    let source = source(vec![ROOTS]);
    let provider = provider(source.clone());
    let cx = Cx::for_testing();
    let tool = ready(provider.tools(&cx)).unwrap().pop().unwrap();
    let ctx = McpContext::new(cx.clone(), 1)
        .with_client_capabilities(ClientCapabilityInfo::new().with_roots(false));
    assert!(ready(tool.call_final_async_in_request(&ctx, &cx, json!({}))).is_err());
    assert!(source.calls.lock().unwrap().is_empty());
    source.cancel.store(true, Ordering::SeqCst);
    let router = Family::Tool.install(&provider, &cx);
    let connection = ModernConnection::new();
    let error = dispatch(
        &router,
        &context(&cx, &connection, 2, true),
        &Family::Tool.request(2, Family::Tool.parameters(false), true),
    )
    .unwrap_err();
    assert_eq!(error.code, McpErrorCode::RequestCancelled);
    assert_eq!(source.calls.lock().unwrap().len(), 1);
    assert_eq!(source.drops.load(Ordering::SeqCst), 1);
}
