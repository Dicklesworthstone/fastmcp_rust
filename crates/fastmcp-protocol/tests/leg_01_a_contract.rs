//! Literal frozen LEG-01 A runner entries.

use fastmcp_core::sha256_bounded;
use fastmcp_protocol::methods::{
    decode_legacy_2024_11_05_envelope, legacy_2024_11_05_schema, translate_legacy_2024_result,
    Legacy2024Envelope, LEGACY_2024_11_05_METHODS, LEGACY_2024_11_05_PROTOCOL_VERSION,
    LEGACY_2024_11_05_SCHEMA_SHA256, TOOLS_CALL,
};
use serde_json::{json, Value};

fn exact_initialize() -> Value {
    json!({
        "jsonrpc": "2.0", "id": "legacy-a", "method": "initialize",
        "params": {
            "protocolVersion": LEGACY_2024_11_05_PROTOCOL_VERSION,
            "capabilities": {"sampling": {}, "roots": {"listChanged": true}},
            "clientInfo": {"name": "legacy-public-consumer", "version": "1.0.0"},
        },
    })
}

#[test]
fn leg_01_a_positive() {
    let schema = legacy_2024_11_05_schema().expect("pinned exact schema must parse");
    assert_eq!(LEGACY_2024_11_05_METHODS.len(), 24);
    assert_eq!(
        schema["definitions"]["InitializeRequest"]["properties"]["method"]["const"],
        "initialize"
    );
    assert_eq!(
        schema["definitions"]["ClientCapabilities"]["properties"].get("elicitation"),
        None
    );
    assert_eq!(
        LEGACY_2024_11_05_SCHEMA_SHA256,
        "61cea2392d4f284092d09bc84b9ac488c0d5618ac2b38a56942fc5b99fd960ce"
    );
    let checksum = sha256_bounded(
        fastmcp_protocol::methods::LEGACY_2024_11_05_SCHEMA_JSON.as_bytes(),
        fastmcp_protocol::methods::LEGACY_2024_11_05_SCHEMA_JSON.len(),
    )
    .expect("pinned schema has a fixed bounded size")
    .as_bytes()
    .iter()
    .map(|byte| format!("{byte:02x}"))
    .collect::<String>();
    assert_eq!(checksum, LEGACY_2024_11_05_SCHEMA_SHA256);
    assert!(matches!(
        decode_legacy_2024_11_05_envelope(exact_initialize())
            .expect("public exact initialize must decode"),
        Legacy2024Envelope::Request { method, id, .. }
            if method.name == "initialize" && id == json!("legacy-a")
    ));
    let ordinary = json!({"content": [{"type": "text", "text": "legacy"}]});
    assert_eq!(
        translate_legacy_2024_result(TOOLS_CALL, ordinary.clone())
            .expect("ordinary complete tool result must remain lossless"),
        ordinary
    );
}

#[test]
fn leg_01_a_planted_negative() {
    let mut modern_only = json!({"content": [{"type": "text", "text": "legacy"}]});
    modern_only["structuredContent"] = json!({"answer": 42});
    assert_eq!(
        translate_legacy_2024_result(TOOLS_CALL, modern_only)
            .expect_err("one modern-only result member must be refused")
            .reason(),
        "modern-only result member cannot be represented by exact MCP 2024-11-05"
    );
}
