//! Configuration-driven startup must not silently discard a registry or controls.

use fastmcp_client::mcp_config::McpConfig;
use serde_json::{Value, json};

fn literal_vscode() -> Value {
    json!({
        "servers": {
            "local": {
                "type": "stdio",
                "command": "server",
                "args": ["--literal", "https://example.test/a//b"],
                "env": {"EXAMPLE": "value"},
                "cwd": "/workspace",
                "disabled": true
            }
        }
    })
}

#[test]
fn vscode_stdio_registry_retains_every_launch_field() {
    let config = McpConfig::from_json(&literal_vscode().to_string()).expect("literal stdio config");
    let server = config.get_server("local").expect("registry must not disappear");
    assert_eq!(server.command, "server");
    assert_eq!(server.args, ["--literal", "https://example.test/a//b"]);
    assert_eq!(server.env.get("EXAMPLE").map(String::as_str), Some("value"));
    assert_eq!(server.cwd.as_deref(), Some("/workspace"));
    assert!(server.disabled);
    assert!(server.http_endpoint_config().is_none());
    assert!(config.enabled_servers().is_empty());
}

#[test]
fn vscode_omitted_type_is_stdio_and_empty_inputs_are_inert() {
    let mut value = literal_vscode();
    value["servers"]["local"].as_object_mut().unwrap().remove("type");
    value["inputs"] = json!([]);
    value["$schema"] = json!("https://example.test/config-schema.json");
    assert!(McpConfig::from_json(&value.to_string()).is_ok());
}

#[test]
fn toml_snake_case_registry_loads_instead_of_becoming_empty() {
    let config = McpConfig::from_toml(
        r#"
        [mcp_servers.local]
        command = "server"
        args = ["--flag"]
        [mcp_servers.local.env]
        EXAMPLE = "value"
        "#,
    )
    .expect("documented TOML dialect");
    let server = config.get_server("local").expect("TOML registry retained");
    assert_eq!(server.command, "server");
    assert_eq!(server.args, ["--flag"]);
    assert_eq!(server.env.get("EXAMPLE").map(String::as_str), Some("value"));
}

#[test]
fn native_json_and_camel_case_toml_remain_supported() {
    let json = r#"{"mcpServers":{"local":{"command":"server"}}}"#;
    let toml = "[mcpServers.local]\ncommand = \"server\"\n";
    for config in [McpConfig::from_json(json), McpConfig::from_toml(toml)] {
        assert_eq!(config.unwrap().get_server("local").unwrap().command, "server");
    }
    assert!(McpConfig::from_json("{}").unwrap().mcp_servers.is_empty());
}

#[test]
fn serialization_keeps_the_existing_native_dialect() {
    let config = McpConfig::from_json(&literal_vscode().to_string()).unwrap();
    let encoded: Value = serde_json::from_str(&config.to_json()).unwrap();
    assert!(encoded.get("mcpServers").is_some());
    assert!(encoded.get("servers").is_none());
    assert!(encoded.get("mcp_servers").is_none());
    let reparsed = McpConfig::from_toml(&config.to_toml()).expect("native TOML round trip");
    let server = reparsed.get_server("local").unwrap();
    assert_eq!(server.command, "server");
    assert_eq!(server.cwd.as_deref(), Some("/workspace"));
    assert!(server.disabled);
}

#[test]
fn ambiguous_or_null_registries_are_refused() {
    for input in [
        r#"{"mcpServers":{},"servers":{}}"#,
        r#"{"mcp_servers":{},"servers":{}}"#,
        r#"{"mcpServers":{},"mcp_servers":{}}"#,
        r#"{"mcpServers":{},"mcpServers":{}}"#,
        r#"{"servers":{},"servers":{}}"#,
        r#"{"mcpServers":null}"#,
        r#"{"mcp_servers":null}"#,
        r#"{"servers":null}"#,
        r#"{"servers":null,"mcpServers":{}}"#,
    ] {
        assert!(McpConfig::from_json(input).is_err(), "accepted: {input}");
    }
    assert!(McpConfig::from_toml("[mcpServers]\n[mcp_servers]\n").is_err());
}

#[test]
fn vscode_security_and_interactive_controls_are_not_silently_dropped() {
    for (key, value) in [
        ("sandbox", json!({})),
        ("inputs", json!([{"id":"token","type":"promptString"}])),
        ("inputs", Value::Null),
        ("unsupportedControl", json!(true)),
    ] {
        let mut config = literal_vscode();
        config[key] = value;
        assert!(McpConfig::from_json(&config.to_string()).is_err(), "accepted {key}");
        // Direct serde callers must receive the same admission, not a bypass.
        assert!(serde_json::from_value::<McpConfig>(config).is_err());
    }
}

#[test]
fn vscode_remote_and_unknown_execution_fields_are_not_stdio_fallbacks() {
    for (key, value) in [
        ("type", json!("http")),
        ("type", json!("sse")),
        ("type", Value::Null),
        ("url", json!("https://example.test/mcp")),
        ("headers", json!({"Authorization":"secret-value"})),
        ("envFile", json!(".env")),
        ("sandboxEnabled", json!(true)),
        ("dev", json!({"watch":"**/*.rs"})),
        ("command", json!("  ")),
    ] {
        let mut config = literal_vscode();
        config["servers"]["local"][key] = value;
        assert!(McpConfig::from_json(&config.to_string()).is_err(), "accepted {key}");
    }
}

#[test]
fn unresolved_vscode_variables_are_never_passed_to_processes() {
    for field in ["command", "args", "env", "cwd"] {
        let mut value = literal_vscode();
        value["servers"]["local"][field] = match field {
            "args" => json!(["${input:token}"]),
            "env" => json!({"EXAMPLE":"${env:SECRET}"}),
            _ => json!("${workspaceFolder}"),
        };
        assert!(McpConfig::from_json(&value.to_string()).is_err());
    }
}

#[test]
fn native_literal_dollar_syntax_is_not_reinterpreted_as_vscode() {
    let config = McpConfig::from_json(
        r#"{"mcpServers":{"local":{"command":"server","args":["${literal}"]}}}"#,
    )
    .unwrap();
    assert_eq!(config.get_server("local").unwrap().args, ["${literal}"]);
}

#[test]
fn jsonc_supports_comments_trailing_commas_and_bom() {
    let config = McpConfig::from_jsonc(
        "\u{feff}{\r\n\
            // configuration comment\r\n\
            \"servers\": {\"local\": {\r\n\
                /* multi-line\r\ncomment */\r\n\
                \"command\": \"server\",\r\n\
                \"args\": [\"x\",],\r\n\
            },},\r\n\
        } // final comment without newline",
    )
    .expect("JSONC syntax extension");
    assert_eq!(config.get_server("local").unwrap().args, ["x"]);
}

#[test]
fn jsonc_never_changes_strings_or_utf8() {
    let args = [
        "https://example.test/a//b?x=/*literal*/",
        "quote: \" comma:,} escaped:\\",
        "雪 café 🦀",
        "line\nnext\r\ntab\tend",
    ];
    let mut value = literal_vscode();
    value["servers"]["local"]["args"] = json!(args);
    let config = McpConfig::from_jsonc(&value.to_string()).unwrap();
    assert_eq!(config.get_server("local").unwrap().args, args);
}

#[test]
fn jsonc_rejects_token_joining_empty_commas_and_json5() {
    for input in [
        "{,}",
        "[,]",
        r#"{"mcpServers":,}"#,
        r#"{"mcpServers":{},,"extra":1}"#,
        r#"{"mcpServers":{},"extra":[,]}"#,
        r#"{"mcpServers":{},"extra":[1,,]}"#,
        r#"{"mcpServers":{},"extra":1/* comment */2}"#,
        r#"{"mcpServers":{},"extra":tru/* comment */e}"#,
        r#"{"mcpServers":{},"extra":["a"/* comment */"b"]}"#,
        r#"{"mcpServers":{}}/* unterminated"#,
        r#"{"mcpServers":{}}/"#,
        "{'mcpServers':{}}",
        "{mcpServers:{}}",
    ] {
        assert!(McpConfig::from_jsonc(input).is_err(), "accepted: {input}");
    }
}

#[test]
fn json_stays_strict_even_though_jsonc_is_supported() {
    for input in [r#"{/* comment */"mcpServers":{}}"#, r#"{"mcpServers":{},}"#] {
        assert!(McpConfig::from_json(input).is_err());
        assert!(McpConfig::from_jsonc(input).is_ok());
    }
}

#[test]
fn configuration_errors_do_not_echo_credentials_or_input_text() {
    let marker = "do-not-print-this-credential";
    for error in [
        McpConfig::from_json(&format!("{{\"servers\":{{}},\"inputs\":[\"{marker}\"]}}"))
            .unwrap_err(),
        McpConfig::from_jsonc(&format!("{{ /* {marker}")).unwrap_err(),
        McpConfig::from_toml(&format!("{marker} = [")).unwrap_err(),
    ] {
        assert!(!error.to_string().contains(marker));
        assert!(!format!("{error:?}").contains(marker));
    }
}

#[test]
fn jsonc_string_lexer_preserves_every_ascii_scalar() {
    for byte in 0_u8..=127 {
        let text = format!("left{}right", char::from(byte));
        let value = json!({"mcpServers":{"local":{"command":"server","args":[text]}}});
        let config = McpConfig::from_jsonc(&value.to_string()).unwrap();
        assert_eq!(config.get_server("local").unwrap().args, [text]);
    }
}
