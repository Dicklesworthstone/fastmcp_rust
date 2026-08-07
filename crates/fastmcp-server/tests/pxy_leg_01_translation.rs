//! Literal frozen runner entries for PXY-LEG-01 implementation B.

use std::collections::HashMap;

use asupersync::Cx;
use fastmcp_core::{McpContext, McpErrorCode, McpResult};
use fastmcp_protocol::protocol_policy::{
    ProtocolEra, ProtocolPolicy, ProtocolVersion, StdioOpeningFrame,
};
use fastmcp_protocol::{
    Content, Prompt, PromptMessage, Resource, ResourceContent, ResourceTemplate, Tool,
};
use fastmcp_server::{ProxyBackend, ProxyClient};
use serde_json::json;

#[derive(Clone)]
struct ResultBackend {
    content: Vec<Content>,
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
        },
        legacy,
        "2024-11-05",
    )
    .expect("exact legacy version enters normal proxy execution");
    let modern_client = ProxyClient::from_backend_with_upstream_binding(
        ResultBackend {
            content: modern_content.clone(),
        },
        modern,
        "2026-07-28",
    )
    .expect("exact modern version enters independent normal proxy execution");
    let context = McpContext::new(Cx::for_testing(), 910);

    assert_eq!(legacy_client.upstream_binding(), Some(legacy));
    assert_eq!(modern_client.upstream_binding(), Some(modern));
    assert_eq!(
        serde_json::to_value(
            legacy_client
                .call_tool(&context, "echo", json!({}))
                .expect("lossless legacy result crosses ordinary ProxyClient execution"),
        )
        .expect("legacy result wire"),
        serde_json::to_value(legacy_content).expect("legacy baseline wire"),
    );
    assert_eq!(
        serde_json::to_value(
            modern_client
                .call_tool(&context, "echo", json!({}))
                .expect("modern sibling remains independent"),
        )
        .expect("modern result wire"),
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
        },
        modern,
        "2026-07-28",
    )
    .expect("rejection leaves the exact modern route usable");
    assert_eq!(
        serde_json::to_value(
            client
                .call_tool(&McpContext::new(Cx::for_testing(), 911), "echo", json!({}))
                .expect("ordinary execution after rejected planted era"),
        )
        .expect("post-rejection result wire"),
        serde_json::to_value(baseline).expect("post-rejection baseline wire"),
    );
}
