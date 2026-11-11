//! Configuration dialect admission. No variable expansion or transport inference.

use std::collections::HashMap;

use serde::{Deserialize, Deserializer, de::Error as _};

use super::{ConfigError, HttpEndpointConfig, McpConfig, ServerConfig};

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
    unique_map(
        deserializer,
        "duplicate server name in configuration registry",
    )
    .map(Some)
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
    mcp_servers: Option<HashMap<String, NativeServerConfig>>,
    #[serde(default, deserialize_with = "present")]
    servers: Option<HashMap<String, NativeServerConfig>>,
    #[serde(flatten, deserialize_with = "extra_fields")]
    extra: HashMap<String, serde_json::Value>,
}

// Preserve field presence independently of the field's decoded value. In
// particular, a present nullable cwd/http cannot hide an earlier occurrence
// or disappear when checking an HTTP entry for conflicting stdio controls.
fn present_field<'de, D, T>(deserializer: D) -> Result<Option<T>, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de>,
{
    T::deserialize(deserializer).map(Some)
}

// Entries are executable policy, not an extension bag. The exact same closed
// field inventory is used for native registries, VS Code imports and direct
// ServerConfig decoding; dialect-specific admission happens before conversion.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct NativeServerConfig {
    #[serde(rename = "type", default, deserialize_with = "present_field")]
    kind: Option<String>,
    #[serde(default, deserialize_with = "present_field")]
    command: Option<String>,
    #[serde(default, deserialize_with = "present_field")]
    url: Option<String>,
    #[serde(default, deserialize_with = "present_field")]
    args: Option<Vec<String>>,
    #[serde(default, deserialize_with = "present_field")]
    env: Option<HashMap<String, String>>,
    #[allow(
        clippy::option_option,
        reason = "distinguishes absent JSON field (None) from explicit null/present value"
    )]
    #[serde(default, deserialize_with = "present_field")]
    cwd: Option<Option<String>>,
    #[serde(default)]
    disabled: bool,
    #[allow(
        clippy::option_option,
        reason = "distinguishes absent JSON field (None) from explicit null/present value"
    )]
    #[serde(default, deserialize_with = "present_field")]
    http: Option<Option<HttpEndpointConfig>>,
}

impl NativeServerConfig {
    pub(super) fn into_config(self, vscode: bool) -> Result<ServerConfig, &'static str> {
        if vscode && self.http.is_some() {
            return Err("VS Code entries cannot contain native HTTP endpoint bundles");
        }
        if self.kind.as_deref() == Some("http") {
            if self.command.is_some()
                || self.args.is_some()
                || self.env.is_some()
                || self.cwd.is_some()
                || self.http.is_some()
            {
                return Err("HTTP shorthand cannot contain stdio settings or another HTTP bundle");
            }
            let url = self.url.ok_or("HTTP shorthand requires a literal URL")?;
            let http = HttpEndpointConfig::from_literal_url(url)
                .map_err(|_| "HTTP shorthand requires a valid credential-free literal endpoint")?;
            let mut config = ServerConfig::from_http_bundle(http);
            config.disabled = self.disabled;
            return Ok(config);
        }
        if self.url.is_some() {
            return Err("a URL requires explicit HTTP transport without a stdio command");
        }
        if self.kind.as_deref().is_some_and(|kind| kind != "stdio") {
            return Err("unsupported configured server transport");
        }

        let http = self.http.flatten();
        let Some(command) = self.command else {
            // HTTP shorthand serializes to a native, fully explicit bundle.
            // No executable command is invented during that round trip.
            if self.kind.is_some()
                || self.args.is_some()
                || self.env.is_some()
                || self.cwd.is_some()
            {
                return Err("HTTP-only endpoint bundles cannot contain stdio settings");
            }
            let mut config = ServerConfig::from_http_bundle(
                http.ok_or("stdio server configuration requires a command")?,
            );
            config.disabled = self.disabled;
            return Ok(config);
        };
        let args = self.args.unwrap_or_default();
        let env = self.env.unwrap_or_default();
        let cwd = self.cwd.flatten();
        if vscode {
            if command.trim().is_empty() {
                return Err("VS Code stdio server command must be nonempty");
            }
            // Unresolved VS Code substitutions cannot become executable text.
            let mut strings = std::iter::once(command.as_str())
                .chain(args.iter().map(String::as_str))
                .chain(env.keys().map(String::as_str))
                .chain(env.values().map(String::as_str))
                .chain(cwd.as_deref());
            if strings.any(|value| value.contains("${") || value.contains('\0')) {
                return Err("VS Code variable substitution and NUL bytes are not supported");
            }
        }
        let mut config = ServerConfig::new(command);
        config.args = args;
        config.env = env;
        config.cwd = cwd;
        config.disabled = self.disabled;
        config.http = http;
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
            (Some(mcp_servers), None) => Ok(Self {
                mcp_servers: mcp_servers
                    .into_iter()
                    .map(|(name, server)| {
                        server
                            .into_config(false)
                            .map(|config| (name, config))
                            .map_err(D::Error::custom)
                    })
                    .collect::<Result<HashMap<_, _>, _>>()?,
            }),
            (Some(_), Some(_)) => Err(D::Error::custom(
                "configuration contains more than one server registry dialect",
            )),
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
                            .into_config(true)
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
        let duplicate =
            r#"{"first":{"command":"original","disabled":true},"first":{"command":"replacement"}}"#;
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
    fn native_server_controls_cannot_be_silently_discarded() {
        let baseline = r#"{"mcpServers":{"local":{"command":"server"}}}"#;
        assert!(McpConfig::from_json(baseline).is_ok());
        assert!(McpConfig::from_jsonc(baseline).is_ok());

        for (field, value) in [
            ("type", r#""http""#),
            ("url", r#""https://example.test/mcp""#),
            ("headers", r#"{"Authorization":"Bearer secret"}"#),
            ("envFile", r#""/run/secrets/mcp.env""#),
            ("sandbox", r#"{"enabled":true}"#),
            ("dev", r#"{"watch":"**/*.rs"}"#),
        ] {
            let changed = format!(
                r#"{{"mcpServers":{{"local":{{"command":"server","{field}":{value}}}}}}}"#
            );
            assert!(
                McpConfig::from_json(&changed).is_err(),
                "native server control {field} must not be discarded"
            );
            assert!(
                McpConfig::from_jsonc(&changed).is_err(),
                "JSONC native server control {field} must not be discarded"
            );
        }

        for field in ["url", "headers", "envFile", "sandbox"] {
            let toml = format!(
                "[mcp_servers.local]\ncommand = \"server\"\n{field} = \"unsupported\"\n"
            );
            assert!(
                McpConfig::from_toml(&toml).is_err(),
                "TOML native server control {field} must not be discarded"
            );
        }
    }

    #[test]
    fn native_server_supported_fields_keep_their_existing_semantics() {
        let json = r#"{"mcpServers":{"local":{
            "command":"server",
            "args":["--literal"],
            "env":{"EXAMPLE":"value"},
            "cwd":"/workspace",
            "disabled":true
        }}}"#;
        let config = McpConfig::from_json(json).unwrap();
        let local = config.get_server("local").unwrap();
        assert_eq!(local.command, "server");
        assert_eq!(local.args, ["--literal"]);
        assert_eq!(local.env.get("EXAMPLE").map(String::as_str), Some("value"));
        assert_eq!(local.cwd.as_deref(), Some("/workspace"));
        assert!(local.disabled);
    }


    #[test]
    fn literal_http_registry_entries_round_trip_without_a_stdio_command() {
        let url = "https://example.test/mcp/v1%2Fitems?tenant=one&selection=%2f+two&empty=";
        for registry in ["mcpServers", "mcp_servers", "servers"] {
            for disabled in [false, true] {
                let source = serde_json::json!({
                    (registry): {
                        "remote": {"type": "http", "url": url, "disabled": disabled}
                    }
                })
                .to_string();
                for config in [
                    McpConfig::from_json(&source).unwrap(),
                    McpConfig::from_jsonc(&source).unwrap(),
                ] {
                    let server = config.get_server("remote").unwrap();
                    assert!(!server.stdio_configured);
                    assert!(server.command.is_empty());
                    assert_eq!(server.disabled, disabled);
                    let http = server.http_endpoint_config().unwrap();
                    assert_eq!(http.policy(), super::super::ProtocolPolicy::ModernOnly);
                    assert_eq!(http.modern_post.as_ref().unwrap().as_str(), url);
                    assert!(http.legacy_sse.is_none());
                    assert!(http.legacy_message_post.is_none());
                    assert_eq!(config.enabled_servers().is_empty(), disabled);
                    let key = http.endpoint_bundle().key();

                    let encoded: serde_json::Value =
                        serde_json::from_str(&config.to_json()).unwrap();
                    assert!(encoded["mcpServers"]["remote"].get("command").is_none());
                    assert!(encoded["mcpServers"]["remote"].get("args").is_none());
                    assert!(encoded["mcpServers"]["remote"].get("env").is_none());
                    for restored in [
                        McpConfig::from_json(&config.to_json()).unwrap(),
                        McpConfig::from_toml(&config.to_toml()).unwrap(),
                    ] {
                        let remote = restored.get_server("remote").unwrap();
                        assert!(!remote.stdio_configured);
                        assert_eq!(remote.disabled, disabled);
                        assert_eq!(
                            remote.http_endpoint_config().unwrap().endpoint_bundle().key(),
                            key
                        );
                    }
                    let direct: ServerConfig =
                        serde_json::from_value(encoded["mcpServers"]["remote"].clone()).unwrap();
                    assert!(!direct.stdio_configured);
                    assert_eq!(
                        direct.http_endpoint_config().unwrap().endpoint_bundle().key(),
                        key
                    );
                }
            }
        }
        let toml = "[mcp_servers.remote]\ntype = \"http\"\nurl = \"https://example.test/mcp?tenant=one\"\n";
        let config = McpConfig::from_toml(toml).unwrap();
        assert!(!config.get_server("remote").unwrap().stdio_configured);
    }

    #[test]
    fn literal_http_registry_partitions_include_the_complete_endpoint() {
        let endpoint = |url: &str| HttpEndpointConfig::from_literal_url(url.to_owned()).unwrap();
        let first = endpoint("https://example.test/mcp?tenant=one");
        let equivalent = endpoint("https://EXAMPLE.test:443/mcp?tenant=one");
        assert_eq!(first.endpoint_bundle().key(), equivalent.endpoint_bundle().key());
        for changed in [
            "https://example.test/other?tenant=one",
            "https://example.test/mcp?tenant=two",
            "https://example.test/mcp?",
            "https://example.test/mcp",
        ] {
            let changed = endpoint(changed);
            assert_ne!(first.endpoint_bundle().key(), changed.endpoint_bundle().key());
            assert_ne!(first.security_partition, changed.security_partition);
            assert_ne!(first.credential_partition, changed.credential_partition);
        }
        assert_ne!(
            endpoint("https://example.test/mcp?").endpoint_bundle().key(),
            endpoint("https://example.test/mcp").endpoint_bundle().key()
        );
        assert!(!first.security_partition.contains("tenant"));
        assert!(!format!("{first:?}").contains("tenant"));
    }

    #[test]
    fn literal_http_registry_rejects_conflicting_or_unimplemented_controls() {
        for registry in ["mcpServers", "mcp_servers", "servers"] {
            for (field, value) in [
                ("command", serde_json::json!("server")),
                ("command", serde_json::json!("")),
                ("command", serde_json::Value::Null),
                ("args", serde_json::json!([])),
                ("env", serde_json::json!({})),
                ("cwd", serde_json::Value::Null),
                ("http", serde_json::Value::Null),
                ("headers", serde_json::json!({})),
                ("headers", serde_json::json!({"Authorization": "Bearer secret-control"})),
                ("auth", serde_json::json!({"token": "secret-control"})),
                ("envFile", serde_json::json!("/run/secrets/mcp.env")),
                ("sandbox", serde_json::json!({"enabled": true})),
                ("dev", serde_json::json!({"watch": "**/*.rs"})),
            ] {
                let mut server =
                    serde_json::json!({"type":"http", "url":"https://example.test/mcp"});
                server[field] = value;
                let source = serde_json::json!({(registry): {"remote": server}}).to_string();
                for error in [
                    McpConfig::from_json(&source).unwrap_err(),
                    McpConfig::from_jsonc(&source).unwrap_err(),
                ] {
                    assert!(matches!(error, ConfigError::ParseError(_)), "{registry}: {field}");
                    assert!(!format!("{error:?}").contains("secret-control"));
                }
            }
            for server in [
                serde_json::json!({"url":"https://example.test/mcp"}),
                serde_json::json!({"type":"stdio", "url":"https://example.test/mcp"}),
                serde_json::json!({"type":"sse", "url":"https://example.test/mcp"}),
                serde_json::json!({"type":"http"}),
                serde_json::json!({"type":"http", "url":null}),
            ] {
                let source = serde_json::json!({(registry): {"remote": server}}).to_string();
                assert!(McpConfig::from_json(&source).is_err());
            }
        }
    }

    #[test]
    fn literal_http_registry_rejects_credential_syntax_fragments_and_variables() {
        for url in [
            "https://user:secret-url@example.test/mcp",
            "https://@example.test/mcp",
            "https://example.test/mcp#fragment",
            "https://example.test/mcp#",
            concat!("https://", "$", "{input:host}/mcp"),
            concat!("https://example.test/mcp?token=", "$", "{env:TOKEN}"),
            " https://example.test/mcp",
            "https://example.test/mcp\n",
            "https://example.test/mcp\0",
            "https://example.test/has space",
            "https:\\example.test\\mcp",
            "https:example.test/mcp",
            "https://example.test/mcp?bad=%zz",
            "wss://example.test/mcp",
            "/relative/mcp",
        ] {
            for registry in ["mcpServers", "servers"] {
                let source = serde_json::json!({
                    (registry): {"remote": {"type":"http", "url":url}}
                })
                .to_string();
                let error = McpConfig::from_json(&source).unwrap_err();
                assert!(matches!(error, ConfigError::ParseError(_)), "{url}");
                assert!(!format!("{error:?}").contains("secret-url"));
            }
        }
    }

    #[test]
    fn literal_http_registry_duplicate_fields_cannot_replace_transport_policy() {
        for fields in [
            r#""type":"http","type":"http","url":"https://example.test/mcp""#,
            r#""type":null,"type":"http","url":"https://example.test/mcp""#,
            r#""type":"http","url":"https://example.test/first","url":"https://example.test/second""#,
            r#""type":"http","url":null,"url":"https://example.test/mcp""#,
            r#""type":"http","url":"https://example.test/first","u\u0072l":"https://example.test/second""#,
            r#""type":"http","url":"https://example.test/mcp","disabled":true,"disabled":false"#,
            r#""command":"server","cwd":null,"cwd":"/other""#,
            r#""command":"server","http":null,"http":null"#,
        ] {
            for registry in ["mcpServers", "mcp_servers", "servers"] {
                let source = format!(r#"{{"{registry}":{{"remote":{{{fields}}}}}}}"#);
                assert!(McpConfig::from_json(&source).is_err(), "{registry}: {fields}");
                assert!(McpConfig::from_jsonc(&source).is_err());
            }
        }
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
            assert!(
                error
                    .to_string()
                    .contains("duplicate top-level configuration field")
            );
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
        let valid =
            r#"{"servers":{"local":{"command":"server"}},"inputs":[],"$schema":"schema.json"}"#;
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
