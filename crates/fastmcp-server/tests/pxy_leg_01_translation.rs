//! Literal frozen runner entries for PXY-LEG-01 implementation B.

use fastmcp_core::McpErrorCode;
use fastmcp_protocol::protocol_policy::{
    ProtocolEra, ProtocolPolicy, ProtocolVersion, StdioOpeningFrame,
};
use fastmcp_server::ProxyClient;
use serde_json::json;

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
