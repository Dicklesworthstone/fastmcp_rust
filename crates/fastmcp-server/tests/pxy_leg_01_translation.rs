//! Literal frozen runner entries for PXY-LEG-01 implementation B.

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::Duration;

use asupersync::Cx;
use fastmcp_core::{McpContext, McpError, McpErrorCode, McpResult};
use fastmcp_protocol::protocol_policy::{
    ProtocolEra, ProtocolPolicy, ProtocolVersion, StdioOpeningFrame,
};
use fastmcp_protocol::{
    Content, CoreRequest, CoreResult, Prompt, PromptMessage, Resource, ResourceContent,
    ResourceTemplate, Tool,
};
use fastmcp_server::{
    BoxFuture, PendingRequests, ProxyAsyncRequest, ProxyBackend, ProxyCatalog, ProxyClient,
    RequestSender, Server, ServerBuilder, Session,
};
use serde_json::json;

/// An owned upstream request exercises the same typed proxy dispatch used by
/// native transports. Its synchronous fallbacks deliberately cannot succeed.
struct OpenLegacyBackend {
    wrong_era: Arc<AtomicBool>,
    executions: Arc<AtomicUsize>,
}

struct OpenLegacyRequest {
    wrong_era: bool,
    executions: Arc<AtomicUsize>,
}

fn open_legacy_result(method: &str) -> serde_json::Value {
    match method {
        "tools/call" => json!({
            "content": [
                {"type": "text", "text": "upstream tool error", "annotations": {
                    "audience": ["user"], "priority": 0.75, "example/annotation": "retained"
                }, "example/content": {"trace": 7}},
                {"type": "image", "data": "AQID", "mimeType": "image/png",
                    "annotations": {"audience": ["assistant"]}},
                {"type": "resource", "resource": {"uri": "data://report", "text": "detail",
                    "example/resource": {"uri": "data://opaque"}},
                    "annotations": {"priority": 0.5}}
            ],
            "isError": true,
            "_meta": {"example/result": "tool"},
            "example/result": {"preserved": true}
        }),
        "resources/read" => json!({
            "contents": [
                {"uri": "data://report", "text": "report", "mimeType": "text/plain",
                    "example/resource": {"uri": "data://opaque"}},
                {"uri": "data://attachment", "blob": "AQID", "mimeType": "application/octet-stream",
                    "example/resource": "binary"}
            ],
            "_meta": {"example/result": "resource"},
            "example/result": {"preserved": true}
        }),
        "prompts/get" => json!({
            "description": "Invocation-specific upstream description",
            "messages": [{"role": "assistant", "content": {
                "type": "text", "text": "use the report",
                "annotations": {"audience": ["assistant"], "priority": 1.0},
                "example/content": "retained"
            }, "example/message": {"retained": true}}],
            "_meta": {"example/result": "prompt"},
            "example/result": {"preserved": true}
        }),
        _ => panic!("unexpected upstream method {method}"),
    }
}

impl ProxyAsyncRequest for OpenLegacyRequest {
    fn client_implementation(&self) -> fastmcp_protocol::common_types::Implementation {
        fastmcp_protocol::common_types::Implementation::try_new("legacy-proxy-test", "1")
            .expect("fixed identity")
    }

    fn execute<'a>(
        self: Box<Self>,
        ctx: &'a McpContext,
        request: CoreRequest,
        _on_progress: &'a mut (dyn FnMut(fastmcp_protocol::FinalProgressNotificationParams) + Send),
    ) -> BoxFuture<'a, McpResult<CoreResult>> {
        Box::pin(async move {
            ctx.checkpoint()?;
            assert_eq!(request.era(), ProtocolEra::Legacy2024);
            let mut result = open_legacy_result(request.method());
            let request = if self.wrong_era {
                result["resultType"] = json!("complete");
                if request.method() == "resources/read" {
                    result["ttlMs"] = json!(0);
                    result["cacheScope"] = json!("private");
                }
                let mut params = request.encode_params().expect("legacy params").unwrap();
                params["_meta"] = json!({
                    "io.modelcontextprotocol/protocolVersion": "2026-07-28",
                    "io.modelcontextprotocol/clientCapabilities": {}
                });
                CoreRequest::decode(ProtocolEra::Modern2026, request.method(), Some(&params))
                    .expect("only the result era is substituted")
            } else {
                request
            };
            let result = request
                .decode_result(&result.to_string())
                .expect("upstream fixture must be valid in its selected era");
            self.executions.fetch_add(1, Ordering::SeqCst);
            Ok(result)
        })
    }
}

impl ProxyBackend for OpenLegacyBackend {
    fn async_protocol_era(&self) -> Option<ProtocolEra> {
        Some(ProtocolEra::Legacy2024)
    }

    fn prepare_async_request(&mut self) -> McpResult<Option<Box<dyn ProxyAsyncRequest>>> {
        Ok(Some(Box::new(OpenLegacyRequest {
            wrong_era: self.wrong_era.load(Ordering::SeqCst),
            executions: Arc::clone(&self.executions),
        })))
    }

    fn list_tools(&mut self) -> McpResult<Vec<Tool>> {
        Ok(Vec::new())
    }
    fn list_resources(&mut self) -> McpResult<Vec<Resource>> {
        Ok(Vec::new())
    }
    fn list_resource_templates(&mut self) -> McpResult<Vec<ResourceTemplate>> {
        Ok(Vec::new())
    }
    fn list_prompts(&mut self) -> McpResult<Vec<Prompt>> {
        Ok(Vec::new())
    }
    fn call_tool(&mut self, _: &str, _: serde_json::Value) -> McpResult<Vec<Content>> {
        panic!("exact legacy dispatch must not project through closed content")
    }
    fn call_tool_with_progress(
        &mut self,
        _: &str,
        _: serde_json::Value,
        _: &mut dyn FnMut(f64, Option<f64>, Option<String>),
    ) -> McpResult<Vec<Content>> {
        panic!("exact legacy dispatch must not project through closed content")
    }
    fn read_resource(&mut self, _: &str) -> McpResult<Vec<ResourceContent>> {
        panic!("exact legacy dispatch must not project through closed resource content")
    }
    fn get_prompt(&mut self, _: &str, _: HashMap<String, String>) -> McpResult<Vec<PromptMessage>> {
        panic!("exact legacy dispatch must not project through closed prompt messages")
    }
}

fn open_legacy_gateway(wrong_era: &Arc<AtomicBool>, executions: &Arc<AtomicUsize>) -> Server {
    let mut bindings = ProxyClient::upstream_binding_registry();
    let binding = bindings
        .bind_stdio(
            "open-legacy-route",
            "stdio:open-legacy-peer",
            "open-legacy-receipt",
            1,
            ProtocolPolicy::LegacyOnly,
            StdioOpeningFrame::LegacyInitialize,
        )
        .expect("exact legacy route");
    let client = ProxyClient::from_backend_with_upstream_binding(
        OpenLegacyBackend {
            wrong_era: Arc::clone(wrong_era),
            executions: Arc::clone(executions),
        },
        binding,
        "2024-11-05",
    )
    .expect("bound custom upstream");
    let catalog =
        ProxyCatalog {
            tool_catalog_era: Some(ProtocolEra::Legacy2024),
            tools: vec![
                serde_json::from_value(json!({
                    "name": "report", "inputSchema": {"type": "object"}
                }))
                .unwrap(),
            ],
            resources: vec![
                serde_json::from_value(json!({
                    "name": "report", "uri": "data://report"
                }))
                .unwrap(),
            ],
            prompts: vec![serde_json::from_value(json!({
            "name": "report", "description": "Catalog description must not replace the result"
        })).unwrap()],
            ..ProxyCatalog::default()
        };
    ServerBuilder::new("legacy-gateway", "1")
        .protocol_policy(ProtocolPolicy::LegacyOnly)
        .expect("legacy compiled")
        .proxy(client, catalog)
        .expect("exact legacy catalog")
        .build()
}

fn public_legacy_proxy_result_probe(method: &str, reject_other_era: bool) {
    let runtime = asupersync::runtime::RuntimeBuilder::current_thread()
        .build()
        .expect("caller runtime");
    let cx = runtime.request_cx_with_budget(asupersync::Budget::default());
    let wrong_era = Arc::new(AtomicBool::new(false));
    let executions = Arc::new(AtomicUsize::new(0));
    let server = open_legacy_gateway(&wrong_era, &executions);
    let mut session = Session::new(server.info().clone(), server.capabilities().clone());
    session.initialize(
        fastmcp_protocol::ClientInfo {
            name: "downstream".into(),
            version: "1".into(),
        },
        fastmcp_protocol::ClientCapabilities::default(),
        "2024-11-05".to_owned(),
    );
    let notifications: fastmcp_server::NotificationSender = Arc::new(|_| {});
    let requests = RequestSender::new(
        Arc::new(PendingRequests::new()),
        Arc::new(|_| Err("unexpected reverse request".to_owned())),
    );
    runtime.block_on(async {
        let rounds = if reject_other_era { 3 } else { 1 };
        for round in 0..rounds {
            let negative = reject_other_era && round == 1;
            wrong_era.store(negative, Ordering::SeqCst);
            let params = match method {
                "resources/read" => json!({"uri": "data://report"}),
                _ => json!({"name": "report", "arguments": {}}),
            };
            let response = server
                .dispatch_request(
                    &cx,
                    &mut session,
                    fastmcp_protocol::JsonRpcRequest::new(
                        method,
                        Some(params),
                        i64::from(round) + 1,
                    ),
                    &notifications,
                    &requests,
                )
                .await
                .expect("public request produces one response");
            if negative {
                if method == "tools/call" {
                    let result = response
                        .result
                        .expect("upstream validation is a tool error");
                    assert_eq!(result["isError"], true);
                    assert!(result.get("_meta").is_none());
                    assert!(result.get("example/result").is_none());
                    assert_ne!(result["content"], open_legacy_result(method)["content"]);
                } else {
                    assert!(
                        response.error.is_some(),
                        "wrong-era result must be refused: {response:?}"
                    );
                    assert!(response.result.is_none());
                }
            } else {
                assert!(
                    response.error.is_none(),
                    "exact result should succeed: {response:?}"
                );
                assert_eq!(response.result, Some(open_legacy_result(method)));
            }
        }
        assert_eq!(
            executions.load(Ordering::SeqCst),
            usize::try_from(rounds).unwrap()
        );
        assert_eq!(session.protocol_version(), Some("2024-11-05"));
    });
    assert!(runtime.shutdown_timeout(Duration::from_secs(2)));
}

#[test]
fn public_legacy_proxy_tool_result_preserves_annotations_metadata_and_error_content() {
    public_legacy_proxy_result_probe("tools/call", false);
}

#[test]
fn public_legacy_proxy_resource_result_preserves_text_blob_and_open_members() {
    public_legacy_proxy_result_probe("resources/read", false);
}

#[test]
fn public_legacy_proxy_prompt_result_preserves_invocation_description_and_open_members() {
    public_legacy_proxy_result_probe("prompts/get", false);
}

#[test]
fn public_legacy_proxy_result_rejects_other_era_and_keeps_the_same_route_usable() {
    for method in ["tools/call", "resources/read", "prompts/get"] {
        public_legacy_proxy_result_probe(method, true);
    }
}

#[derive(Clone)]
struct ResultBackend {
    content: Vec<Content>,
    era: ProtocolEra,
}

impl ProxyBackend for ResultBackend {
    fn list_tools(&mut self) -> McpResult<Vec<Tool>> {
        Ok(Vec::new())
    }
    fn list_resources(&mut self) -> McpResult<Vec<Resource>> {
        Ok(Vec::new())
    }
    fn list_resource_templates(&mut self) -> McpResult<Vec<ResourceTemplate>> {
        Ok(Vec::new())
    }
    fn list_prompts(&mut self) -> McpResult<Vec<Prompt>> {
        Ok(Vec::new())
    }
    fn call_tool(&mut self, _: &str, _: serde_json::Value) -> McpResult<Vec<Content>> {
        Ok(self.content.clone())
    }
    fn call_tool_result(
        &mut self,
        name: &str,
        arguments: serde_json::Value,
    ) -> McpResult<CoreResult> {
        let params = match self.era {
            ProtocolEra::Legacy2024 => json!({"name": name, "arguments": arguments}),
            ProtocolEra::Modern2026 => json!({
                "_meta": {
                    "io.modelcontextprotocol/protocolVersion": "2026-07-28",
                    "io.modelcontextprotocol/clientCapabilities": {}
                },
                "name": name,
                "arguments": arguments
            }),
        };
        let request = CoreRequest::decode(
            self.era,
            fastmcp_protocol::methods::TOOLS_CALL,
            Some(&params),
        )
        .map_err(|error| McpError::invalid_request(error.to_string()))?;
        let result = match self.era {
            ProtocolEra::Legacy2024 => json!({"content": self.content}),
            ProtocolEra::Modern2026 => {
                json!({"resultType": "complete", "content": self.content})
            }
        };
        request
            .decode_result(
                &serde_json::to_string(&result)
                    .map_err(|error| McpError::internal_error(error.to_string()))?,
            )
            .map_err(|error| McpError::invalid_request(error.to_string()))
    }
    fn call_tool_with_progress(
        &mut self,
        _: &str,
        _: serde_json::Value,
        _: &mut dyn FnMut(f64, Option<f64>, Option<String>),
    ) -> McpResult<Vec<Content>> {
        Ok(self.content.clone())
    }
    fn read_resource(&mut self, _: &str) -> McpResult<Vec<ResourceContent>> {
        Ok(Vec::new())
    }
    fn get_prompt(&mut self, _: &str, _: HashMap<String, String>) -> McpResult<Vec<PromptMessage>> {
        Ok(Vec::new())
    }
}

#[test]
fn pxy_leg_01_b_positive() {
    let mut bindings = ProxyClient::upstream_binding_registry();
    let legacy = bindings
        .bind_stdio(
            "route-legacy-translation",
            "stdio:legacy-upstream",
            "leg-01-receipt-legacy",
            21,
            ProtocolPolicy::Auto,
            StdioOpeningFrame::LegacyInitialize,
        )
        .expect("an exact-2024 upstream selects only its own legacy route");
    let modern = bindings
        .bind_stdio(
            "route-modern-translation",
            "stdio:modern-upstream",
            "leg-01-receipt-modern",
            21,
            ProtocolPolicy::Auto,
            StdioOpeningFrame::ModernRequest {
                protocol_version: "2026-07-28".to_owned(),
            },
        )
        .expect("an unrelated exact-2026 upstream selects its own modern route");

    let legacy_result = json!({"content": [{"type": "text", "text": "legacy"}]});
    let modern_result = json!({
        "content": [{"type": "text", "text": "modern"}],
        "structuredContent": {"route": "modern-only"}
    });

    assert_eq!(legacy.era(), ProtocolEra::Legacy2024);
    assert_eq!(modern.era(), ProtocolEra::Modern2026);
    assert_eq!(
        legacy
            .admit_upstream_protocol_version("2024-11-05")
            .expect("legacy binding admits only its exact version"),
        ProtocolVersion::LEGACY_2024
    );
    assert_eq!(
        modern
            .admit_upstream_protocol_version("2026-07-28")
            .expect("modern binding admits only its exact version"),
        ProtocolVersion::MODERN_2026
    );
    assert_eq!(
        legacy
            .translate_upstream_result("tools/call", legacy_result.clone())
            .expect("lossless exact-2024 tool result crosses the legacy route"),
        legacy_result
    );
    assert_eq!(
        modern
            .translate_upstream_result("tools/call", modern_result.clone())
            .expect("modern-only result stays on the unrelated modern route"),
        modern_result
    );
}

#[test]
fn pxy_leg_01_b_planted_negative() {
    let mut bindings = ProxyClient::upstream_binding_registry();
    let binding = bindings
        .bind_stdio(
            "route-modern-translation",
            "stdio:modern-upstream",
            "leg-01-receipt-modern",
            21,
            ProtocolPolicy::Auto,
            StdioOpeningFrame::ModernRequest {
                protocol_version: "2026-07-28".to_owned(),
            },
        )
        .expect("baseline exact modern route selects before the planted change");
    let before = format!("{bindings:#?}");

    // One field changes: only the declared version becomes the unsupported 2025 era.
    let error = binding
        .admit_upstream_protocol_version("2025-11-25")
        .expect_err("the planted intermediary version cannot alter the selected route");

    assert_eq!(error.code, McpErrorCode::InvalidRequest);
    assert_eq!(format!("{bindings:#?}"), before);
    assert_eq!(binding.era(), ProtocolEra::Modern2026);
    assert_eq!(
        binding
            .admit_upstream_protocol_version("2026-07-28")
            .expect("rejection leaves the original exact modern route usable"),
        ProtocolVersion::MODERN_2026
    );
}

#[test]
fn pxy_leg_01_i_positive() {
    let mut bindings = ProxyClient::upstream_binding_registry();
    let legacy = bindings
        .bind_stdio(
            "route-legacy-execution",
            "stdio:legacy-execution",
            "leg-01-execution-receipt",
            34,
            ProtocolPolicy::Auto,
            StdioOpeningFrame::LegacyInitialize,
        )
        .expect("legacy route binding");
    let modern = bindings
        .bind_stdio(
            "route-modern-execution",
            "stdio:modern-execution",
            "modern-execution-receipt",
            34,
            ProtocolPolicy::Auto,
            StdioOpeningFrame::ModernRequest {
                protocol_version: "2026-07-28".into(),
            },
        )
        .expect("modern sibling route binding");
    let legacy_content = vec![Content::text("legacy execution")];
    let modern_content = vec![Content::text("modern execution")];
    let legacy_client = ProxyClient::from_backend_with_upstream_binding(
        ResultBackend {
            content: legacy_content.clone(),
            era: ProtocolEra::Legacy2024,
        },
        legacy,
        "2024-11-05",
    )
    .expect("exact legacy version enters normal proxy execution");
    let modern_client = ProxyClient::from_backend_with_upstream_binding(
        ResultBackend {
            content: modern_content.clone(),
            era: ProtocolEra::Modern2026,
        },
        modern,
        "2026-07-28",
    )
    .expect("exact modern version enters independent normal proxy execution");
    let context = McpContext::new(Cx::for_testing(), 910);

    assert_eq!(legacy_client.upstream_binding(), Some(legacy));
    assert_eq!(modern_client.upstream_binding(), Some(modern));
    let legacy_result = legacy_client
        .call_tool_typed(&context, "echo", json!({}))
        .expect("lossless legacy result crosses ordinary typed proxy execution");
    assert_eq!(legacy_result.era(), ProtocolEra::Legacy2024);
    let legacy_wire: serde_json::Value = serde_json::from_str(
        &legacy_result
            .encode()
            .expect("legacy typed result re-encodes"),
    )
    .expect("legacy result wire");
    assert_eq!(
        legacy_wire["content"],
        serde_json::to_value(legacy_content).expect("legacy baseline wire"),
    );

    let modern_result = modern_client
        .call_tool_typed(&context, "echo", json!({}))
        .expect("modern sibling remains independent");
    assert_eq!(modern_result.era(), ProtocolEra::Modern2026);
    let modern_wire: serde_json::Value = serde_json::from_str(
        &modern_result
            .encode()
            .expect("modern typed result re-encodes"),
    )
    .expect("modern result wire");
    assert_eq!(
        modern_wire["content"],
        serde_json::to_value(modern_content).expect("modern baseline wire"),
    );
}

#[test]
fn pxy_leg_01_i_planted_negative() {
    let mut bindings = ProxyClient::upstream_binding_registry();
    let modern = bindings
        .bind_stdio(
            "route-modern-execution",
            "stdio:modern-execution",
            "modern-execution-receipt",
            34,
            ProtocolPolicy::Auto,
            StdioOpeningFrame::ModernRequest {
                protocol_version: "2026-07-28".into(),
            },
        )
        .expect("modern baseline binding");
    let before = format!("{bindings:#?}");
    let baseline = vec![Content::text("modern execution")];

    let error = match ProxyClient::from_backend_with_upstream_binding(
        ResultBackend {
            content: baseline.clone(),
            era: ProtocolEra::Modern2026,
        },
        modern,
        "2025-11-25",
    ) {
        Ok(_) => panic!("changing only the upstream version to 2025 must reject"),
        Err(error) => error,
    };
    assert_eq!(error.code, McpErrorCode::InvalidRequest);
    assert_eq!(format!("{bindings:#?}"), before);

    let client = ProxyClient::from_backend_with_upstream_binding(
        ResultBackend {
            content: baseline.clone(),
            era: ProtocolEra::Modern2026,
        },
        modern,
        "2026-07-28",
    )
    .expect("rejection leaves the exact modern route usable");
    let result = client
        .call_tool_typed(&McpContext::new(Cx::for_testing(), 911), "echo", json!({}))
        .expect("ordinary typed execution after rejected planted era");
    assert_eq!(result.era(), ProtocolEra::Modern2026);
    let result_wire: serde_json::Value = serde_json::from_str(
        &result
            .encode()
            .expect("post-rejection typed result re-encodes"),
    )
    .expect("post-rejection result wire");
    assert_eq!(
        result_wire["content"],
        serde_json::to_value(baseline).expect("post-rejection baseline wire"),
    );
}
