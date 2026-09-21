//! Configuration dialect admission. No variable expansion or transport inference.

use std::collections::HashMap;

use serde::{Deserialize, Deserializer, de::Error as _};

use super::{ConfigError, McpConfig, ServerConfig};

// Collect maps without discarding an earlier definition or control before
// validation. Keys are checked after deserialization, including JSON escapes.
fn unique_map<'de, D, T>(
    deserializer: D,
    duplicate_message: &'static str,
) -> Result<HashMap<String, T>, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de>,
{
    struct UniqueMapVisitor<T> {
        duplicate_message: &'static str,
        value: std::marker::PhantomData<T>,
    }

    impl<'de, T: Deserialize<'de>> serde::de::Visitor<'de> for UniqueMapVisitor<T> {
        type Value = HashMap<String, T>;

        fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            formatter.write_str("a configuration map with unique keys")
        }

        fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
        where
            A: serde::de::MapAccess<'de>,
        {
            let mut values = HashMap::new();
            while let Some(name) = map.next_key::<String>()? {
                match values.entry(name) {
                    std::collections::hash_map::Entry::Vacant(entry) => {
                        entry.insert(map.next_value::<T>()?);
                    }
                    std::collections::hash_map::Entry::Occupied(_) => {
                        return Err(A::Error::custom(self.duplicate_message));
                    }
                }
            }
            Ok(values)
        }
    }

    deserializer.deserialize_map(UniqueMapVisitor::<T> {
        duplicate_message,
        value: std::marker::PhantomData,
    })
}

// `Option` distinguishes an absent registry from an explicitly empty one. A
// present null is not an absent registry: the map visitor rejects it.
fn present<'de, D, T>(deserializer: D) -> Result<Option<HashMap<String, T>>, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de>,
{
    unique_map(deserializer, "duplicate server name in configuration registry").map(Some)
}

fn extra_fields<'de, D>(deserializer: D) -> Result<HashMap<String, serde_json::Value>, D::Error>
where
    D: Deserializer<'de>,
{
    unique_map(deserializer, "duplicate top-level configuration field")
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct ConfigWire {
    #[serde(default, alias = "mcp_servers", deserialize_with = "present")]
    mcp_servers: Option<HashMap<String, ServerConfig>>,
    #[serde(default, deserialize_with = "present")]
    servers: Option<HashMap<String, VscodeStdioServer>>,
    #[serde(flatten, deserialize_with = "extra_fields")]
    extra: HashMap<String, serde_json::Value>,
}

// Do not silently discard VS Code controls that this client cannot enforce.
// In particular, envFile, sandbox, remote URLs, and development settings must
// never turn into a less-constrained stdio launch.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct VscodeStdioServer {
    #[serde(rename = "type", default = "stdio_kind")]
    kind: String,
    command: String,
    #[serde(default)]
    args: Vec<String>,
    #[serde(default)]
    env: HashMap<String, String>,
    #[serde(default)]
    cwd: Option<String>,
    #[serde(default)]
    disabled: bool,
}

fn stdio_kind() -> String {
    "stdio".to_owned()
}

impl VscodeStdioServer {
    fn into_config(self) -> Result<ServerConfig, &'static str> {
        if self.kind != "stdio" {
            return Err("VS Code imports support literal stdio servers only");
        }
        if self.command.trim().is_empty() {
            return Err("VS Code stdio server command must be nonempty");
        }
        // There is no VS Code variable resolver in this library. Passing an
        // unresolved value to an executable would not implement its meaning.
        let mut strings = std::iter::once(self.command.as_str())
            .chain(self.args.iter().map(String::as_str))
            .chain(self.env.keys().map(String::as_str))
            .chain(self.env.values().map(String::as_str))
            .chain(self.cwd.as_deref());
        if strings.any(|value| value.contains("${") || value.contains('\0')) {
            return Err("VS Code variable substitution and NUL bytes are not supported");
        }
        let mut config = ServerConfig::new(self.command);
        config.args = self.args;
        config.env = self.env;
        config.cwd = self.cwd;
        config.disabled = self.disabled;
        Ok(config)
    }
}

impl<'de> Deserialize<'de> for McpConfig {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let wire = ConfigWire::deserialize(deserializer)?;
        match (wire.mcp_servers, wire.servers) {
            (Some(_), Some(_)) => Err(D::Error::custom(
                "configuration contains more than one server registry dialect",
            )),
            (Some(mcp_servers), None) => Ok(Self { mcp_servers }),
            (None, Some(servers)) => {
                for (name, value) in &wire.extra {
                    match (name.as_str(), value) {
                        ("$schema", serde_json::Value::String(_)) => {}
                        ("inputs", serde_json::Value::Array(inputs)) if inputs.is_empty() => {}
                        _ => {
                            return Err(D::Error::custom(
                                "unsupported VS Code configuration control; no controls were applied",
                            ));
                        }
                    }
                }
                let mcp_servers = servers
                    .into_iter()
                    .map(|(name, server)| {
                        server
                            .into_config()
                            .map(|config| (name, config))
                            .map_err(D::Error::custom)
                    })
                    .collect::<Result<HashMap<_, _>, _>>()?;
                Ok(Self { mcp_servers })
            }
            (None, None) => Ok(Self::default()),
        }
    }
}

pub(super) fn from_jsonc(json: &str) -> Result<McpConfig, ConfigError> {
    let invalid = || ConfigError::ParseError("Invalid JSONC configuration".to_owned());
    let mut bytes = json
        .strip_prefix('\u{feff}')
        .unwrap_or(json)
        .as_bytes()
        .to_vec();
    strip_comments(&mut bytes).map_err(|()| invalid())?;
    strip_trailing_commas(&mut bytes);
    serde_json::from_slice(&bytes).map_err(|_| invalid())
}

// Replace comments with spaces instead of deleting them. This both preserves
// byte positions and prevents invalid tokens such as `1/*comment*/2` from
// becoming the valid (but different) number `12`. Strings are never rewritten.
fn strip_comments(bytes: &mut [u8]) -> Result<(), ()> {
    let mut index = 0;
    let mut in_string = false;
    let mut escaped = false;
    while index < bytes.len() {
        let byte = bytes[index];
        if in_string {
            if escaped {
                escaped = false;
            } else if byte == b'\\' {
                escaped = true;
            } else if byte == b'"' {
                in_string = false;
            }
            index += 1;
            continue;
        }
        match byte {
            b'"' => {
                in_string = true;
                index += 1;
            }
            b'/' if bytes.get(index + 1) == Some(&b'/') => {
                while index < bytes.len() && !matches!(bytes[index], b'\r' | b'\n') {
                    bytes[index] = b' ';
                    index += 1;
                }
            }
            b'/' if bytes.get(index + 1) == Some(&b'*') => {
                bytes[index] = b' ';
                bytes[index + 1] = b' ';
                index += 2;
                loop {
                    if index >= bytes.len() {
                        return Err(());
                    }
                    if bytes[index] == b'*' && bytes.get(index + 1) == Some(&b'/') {
                        bytes[index] = b' ';
                        bytes[index + 1] = b' ';
                        index += 2;
                        break;
                    }
                    if !matches!(bytes[index], b'\r' | b'\n') {
                        bytes[index] = b' ';
                    }
                    index += 1;
                }
            }
            _ => index += 1,
        }
    }
    Ok(())
}

fn is_json_whitespace(byte: u8) -> bool {
    matches!(byte, b' ' | b'\t' | b'\r' | b'\n')
}

// Only erase a comma following a value and immediately preceding a closing
// delimiter. `{,}`, `[,]`, and `{"x":,}` must remain invalid JSON.
fn strip_trailing_commas(bytes: &mut [u8]) {
    let mut in_string = false;
    let mut escaped = false;
    let mut previous = None;
    for index in 0..bytes.len() {
        let byte = bytes[index];
        if in_string {
            if escaped {
                escaped = false;
            } else if byte == b'\\' {
                escaped = true;
            } else if byte == b'"' {
                in_string = false;
                previous = Some(b'"');
            }
            continue;
        }
        if byte == b'"' {
            in_string = true;
        } else if byte == b',' {
            let after_value =
                previous.is_some_and(|value| !matches!(value, b'{' | b'[' | b',' | b':'));
            let next = bytes[index + 1..]
                .iter()
                .copied()
                .find(|value| !is_json_whitespace(*value));
            if after_value && matches!(next, Some(b'}' | b']')) {
                bytes[index] = b' ';
            }
            // Retain the original comma in the lexical state. A second comma
            // is not a trailing-comma spelling of the same value.
            previous = Some(b',');
        } else if !is_json_whitespace(byte) {
            previous = Some(byte);
        }
    }
}

pub(super) fn from_path_content(
    path: &std::path::Path,
    content: &str,
) -> Result<McpConfig, ConfigError> {
    let extension = path.extension().and_then(std::ffi::OsStr::to_str);
    if extension.is_some_and(|extension| extension.eq_ignore_ascii_case("toml")) {
        return McpConfig::from_toml(content);
    }
    let vscode_json = path.file_name() == Some(std::ffi::OsStr::new("mcp.json"))
        && path.parent().and_then(std::path::Path::file_name)
            == Some(std::ffi::OsStr::new(".vscode"));
    if vscode_json || extension.is_some_and(|extension| extension.eq_ignore_ascii_case("jsonc")) {
        return from_jsonc(content);
    }
    // No trial-and-error fallback: a malformed JSON file must not be
    // reinterpreted as a different, more permissive configuration dialect.
    McpConfig::from_json(content)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    #[test]
    fn file_dialect_is_selected_by_the_explicit_path() {
        let toml = "[mcp_servers.local]\ncommand = \"server\"\n";
        let jsonc = r#"{/*comment*/"servers":{"local":{"command":"server",},},}"#;
        for name in ["config.toml", "config.TOML"] {
            assert!(from_path_content(Path::new(name), toml).is_ok());
        }
        for name in ["config.jsonc", "config.JSONC", ".vscode/mcp.json"] {
            assert!(from_path_content(Path::new(name), jsonc).is_ok());
        }
        for name in ["config.json", ".mcp/config.json", "mcp.json"] {
            assert!(from_path_content(Path::new(name), jsonc).is_err());
            assert!(from_path_content(Path::new(name), toml).is_err());
        }
        assert!(from_path_content(Path::new("config.toml"), r#"{"mcpServers":{}}"#).is_err());
    }

    #[test]
    fn comment_replacement_keeps_offsets_and_line_endings() {
        let mut bytes = "{ /* café\r\n */ \"mcpServers\": {} }".as_bytes().to_vec();
        let original = bytes.clone();
        strip_comments(&mut bytes).expect("closed comment");
        assert_eq!(bytes.len(), original.len());
        for (before, after) in original.iter().zip(&bytes) {
            if matches!(*before, b'\r' | b'\n') {
                assert_eq!(before, after);
            }
        }
        let config: McpConfig = serde_json::from_slice(&bytes).expect("valid normalized JSON");
        assert!(config.mcp_servers.is_empty());
    }

    #[test]
    fn duplicate_server_names_cannot_replace_disabled_definitions() {
        let distinct = r#"{"first":{"command":"original","disabled":true},"second":{"command":"replacement"}}"#;
        let duplicate = r#"{"first":{"command":"original","disabled":true},"first":{"command":"replacement"}}"#;
        for registry in ["mcpServers", "mcp_servers", "servers"] {
            let valid = format!(r#"{{"{registry}":{distinct}}}"#);
            let invalid = format!(r#"{{"{registry}":{duplicate}}}"#);
            for config in [
                McpConfig::from_json(&valid).unwrap(),
                McpConfig::from_jsonc(&valid).unwrap(),
            ] {
                assert_eq!(config.mcp_servers.len(), 2);
                let first = config.get_server("first").unwrap();
                assert_eq!(first.command, "original");
                assert!(first.disabled);
                assert_eq!(config.get_server("second").unwrap().command, "replacement");
            }
            assert!(McpConfig::from_json(&invalid).is_err(), "{registry}");
            assert!(McpConfig::from_jsonc(&invalid).is_err(), "{registry}");
        }
    }

    #[test]
    fn duplicate_detection_uses_decoded_names_and_also_rejects_identical_entries() {
        for registry in ["mcpServers", "mcp_servers", "servers"] {
            for entries in [
                r#"{"same":{"command":"original"},"s\u0061me":{"command":"replacement"}}"#,
                r#"{"same":{"command":"original"},"same":{"command":"original"}}"#,
            ] {
                let json = format!(r#"{{"{registry}":{entries}}}"#);
                let error = serde_json::from_str::<McpConfig>(&json).unwrap_err();
                assert!(error.to_string().contains("duplicate server name"));
                assert!(McpConfig::from_jsonc(&json).is_err());
            }
        }
    }

    #[test]
    fn unique_registry_admission_keeps_empty_absent_null_and_toml_semantics() {
        assert!(McpConfig::from_json("{}").unwrap().mcp_servers.is_empty());
        for registry in ["mcpServers", "mcp_servers", "servers"] {
            let empty = format!(r#"{{"{registry}":{{}}}}"#);
            assert!(McpConfig::from_json(&empty).unwrap().mcp_servers.is_empty());
            let null = format!(r#"{{"{registry}":null}}"#);
            assert!(McpConfig::from_json(&null).is_err());
        }
        let toml = "[mcp_servers.first]\ncommand = \"original\"\ndisabled = true\n\n[mcp_servers.second]\ncommand = \"replacement\"\n";
        let config = McpConfig::from_toml(toml).unwrap();
        assert_eq!(config.mcp_servers.len(), 2);
        assert!(config.get_server("first").unwrap().disabled);
        assert_eq!(config.get_server("second").unwrap().command, "replacement");
    }

    #[test]
    fn duplicate_top_level_controls_cannot_hide_unsupported_values() {
        for controls in [
            r#""inputs":[{"id":"ask","type":"promptString"}],"inputs":[]"#,
            r#""inputs":false,"inputs":[]"#,
            r#""inputs":[],"in\u0070uts":[]"#,
            r#""$schema":false,"$schema":"schema.json""#,
            r#""$schema":"first.json","$schema":"second.json""#,
        ] {
            let json = format!(r#"{{"servers":{{"local":{{"command":"server"}}}},{controls}}}"#);
            let error = serde_json::from_str::<McpConfig>(&json).unwrap_err();
            assert!(error.to_string().contains("duplicate top-level configuration field"));
            assert!(McpConfig::from_json(&json).is_err());
            assert!(McpConfig::from_jsonc(&json).is_err());
        }
        let valid_jsonc = r#"{/*config*/"servers":{"local":{"command":"server",},},"inputs":[],}"#;
        let invalid_jsonc = r#"{/*config*/"servers":{"local":{"command":"server",},},"inputs":[{"id":"ask"}],"inputs":[],}"#;
        assert!(McpConfig::from_jsonc(valid_jsonc).is_ok());
        assert!(McpConfig::from_jsonc(invalid_jsonc).is_err());
    }

    #[test]
    fn unique_top_level_controls_keep_their_existing_validation() {
        let valid = r#"{"servers":{"local":{"command":"server"}},"inputs":[],"$schema":"schema.json"}"#;
        let config = McpConfig::from_json(valid).unwrap();
        assert_eq!(config.get_server("local").unwrap().command, "server");
        assert!(McpConfig::from_jsonc(valid).is_ok());
        for control in [
            r#""inputs":[{"id":"ask","type":"promptString"}]"#,
            r#""inputs":false"#,
            r#""$schema":false"#,
            r#""sandbox":true"#,
        ] {
            let json = format!(r#"{{"servers":{{"local":{{"command":"server"}}}},{control}}}"#);
            assert!(McpConfig::from_json(&json).is_err());
            assert!(McpConfig::from_jsonc(&json).is_err());
        }
    }
}
