//! Request/response traffic rendering for MCP JSON-RPC.

use std::time::Duration;

use fastmcp_protocol::{JsonRpcError, JsonRpcRequest, JsonRpcResponse, RequestId};
use serde_json::Value;

use crate::console::{
    FastMcpConsole, REDACTED_VALUE, bounded_rich_fragment, bounded_rich_text, is_credential_key,
    redact_free_text_credentials, terminal_text_is_unsafe as is_terminal_unsafe,
};
use crate::detection::DisplayContext;
use crate::theme::FastMcpTheme;

const PEER_METHOD_MAX_CHARS: usize = 128;
const PEER_ERROR_SUMMARY_MAX_CHARS: usize = 192;
const PEER_ID_MAX_CHARS: usize = 128;
const TRUNCATION_MARKER: &str = "...";
const JSON_PREVIEW_OMITTED: &str = "<payload omitted: preview budget exceeded>";
const JSON_PREVIEW_SERIALIZATION_FAILED: &str = "<payload omitted: serialization failed>";
const JSON_PREVIEW_MAX_NODES: usize = 1_024;
const JSON_PREVIEW_HARD_MAX_DEPTH: usize = 64;
const JSON_PREVIEW_MIN_SOURCE_BYTES: usize = 1_024;
const JSON_PREVIEW_MAX_SOURCE_BYTES: usize = 64 * 1_024;
const JSON_PREVIEW_SOURCE_MULTIPLIER: usize = 8;

fn truncate_to_fixed_budget(text: &str, max_chars: usize, force_marker: bool) -> String {
    let char_count = text.chars().count();
    if char_count <= max_chars && !force_marker {
        return text.to_owned();
    }
    if max_chars <= TRUNCATION_MARKER.len() {
        return TRUNCATION_MARKER.chars().take(max_chars).collect();
    }

    let retained = max_chars - TRUNCATION_MARKER.len();
    let mut truncated: String = text.chars().take(retained).collect();
    truncated.push_str(TRUNCATION_MARKER);
    truncated
}

fn peer_metadata_preview(text: &str, max_chars: usize) -> String {
    // Scan only a small multiple of the display budget. This contains allocation
    // even when a peer supplies a multi-megabyte method or error string, while
    // leaving enough look-ahead for a credential value near the display edge.
    let scan_limit = max_chars.saturating_mul(4);
    let mut characters = text.chars();
    let bounded_input: String = characters.by_ref().take(scan_limit).collect();
    let source_was_truncated = characters.next().is_some();
    let redacted = redact_free_text_credentials(&bounded_input);
    let sanitized = sanitize_terminal_text(&redacted);

    truncate_to_fixed_budget(&sanitized, max_chars, source_was_truncated)
}

fn json_rpc_error_class(code: i32) -> &'static str {
    match code {
        -32700 => "parse-error",
        -32600 => "invalid-request",
        -32601 => "method-not-found",
        -32602 => "invalid-params",
        -32603 => "internal-error",
        -32099..=-32000 => "server-error",
        _ => "application-error",
    }
}

fn redact_credentials(value: &Value, max_depth: usize, source_byte_budget: usize) -> Option<Value> {
    json_preview_is_within_budget(value, max_depth, source_byte_budget)
        .then(|| redact_credentials_prevalidated(value))
}

fn redact_credentials_prevalidated(value: &Value) -> Value {
    match value {
        Value::Object(object) => {
            let mut redacted = serde_json::Map::new();
            for (key, value) in object {
                let value = if is_credential_key(key) {
                    Value::String(REDACTED_VALUE.to_owned())
                } else {
                    redact_credentials_prevalidated(value)
                };
                insert_collision_safe_json_key(
                    &mut redacted,
                    redact_free_text_credentials(key),
                    value,
                );
            }
            Value::Object(redacted)
        }
        Value::Array(values) => {
            Value::Array(values.iter().map(redact_credentials_prevalidated).collect())
        }
        Value::String(string) => Value::String(redact_free_text_credentials(string)),
        _ => value.clone(),
    }
}

fn insert_collision_safe_json_key(
    object: &mut serde_json::Map<String, Value>,
    display_key: String,
    value: Value,
) {
    if let serde_json::map::Entry::Vacant(entry) = object.entry(display_key.clone()) {
        entry.insert(value);
        return;
    }

    for collision_index in 2usize.. {
        let candidate = format!("{display_key} [{collision_index}]");
        if let serde_json::map::Entry::Vacant(entry) = object.entry(candidate) {
            entry.insert(value);
            return;
        }
    }
    unreachable!("usize collision suffix space is finite but cannot be exhausted in memory");
}

fn json_preview_source_budget(truncate_at: usize) -> usize {
    truncate_at
        .saturating_mul(JSON_PREVIEW_SOURCE_MULTIPLIER)
        .clamp(JSON_PREVIEW_MIN_SOURCE_BYTES, JSON_PREVIEW_MAX_SOURCE_BYTES)
}

fn json_preview_is_within_budget(
    value: &Value,
    configured_max_depth: usize,
    source_byte_budget: usize,
) -> bool {
    let max_depth = configured_max_depth.min(JSON_PREVIEW_HARD_MAX_DEPTH);
    let mut remaining_bytes = source_byte_budget.min(JSON_PREVIEW_MAX_SOURCE_BYTES);
    let mut scheduled_nodes = 1usize;
    let mut stack = vec![(value, 0usize)];

    while let Some((value, depth)) = stack.pop() {
        if depth > max_depth || !charge_preview_bytes(&mut remaining_bytes, 1) {
            return false;
        }

        match value {
            Value::Null => {
                if !charge_preview_bytes(&mut remaining_bytes, 4) {
                    return false;
                }
            }
            Value::Bool(_) => {
                if !charge_preview_bytes(&mut remaining_bytes, 5) {
                    return false;
                }
            }
            Value::Number(number) => {
                if !charge_preview_bytes(&mut remaining_bytes, number.as_str().len()) {
                    return false;
                }
            }
            Value::String(string) => {
                if !charge_preview_bytes(&mut remaining_bytes, string.len()) {
                    return false;
                }
            }
            Value::Array(values) => {
                if !schedule_preview_children(
                    &mut stack,
                    &mut scheduled_nodes,
                    values.iter(),
                    depth,
                ) {
                    return false;
                }
            }
            Value::Object(object) => {
                for key in object.keys() {
                    if !charge_preview_bytes(&mut remaining_bytes, key.len()) {
                        return false;
                    }
                }
                if !schedule_preview_children(
                    &mut stack,
                    &mut scheduled_nodes,
                    object.values(),
                    depth,
                ) {
                    return false;
                }
            }
        }
    }
    true
}

fn schedule_preview_children<'a>(
    stack: &mut Vec<(&'a Value, usize)>,
    scheduled_nodes: &mut usize,
    children: impl ExactSizeIterator<Item = &'a Value>,
    parent_depth: usize,
) -> bool {
    let child_count = children.len();
    let Some(total_nodes) = scheduled_nodes.checked_add(child_count) else {
        return false;
    };
    if total_nodes > JSON_PREVIEW_MAX_NODES || stack.try_reserve(child_count).is_err() {
        return false;
    }
    let Some(child_depth) = parent_depth.checked_add(1) else {
        return false;
    };
    *scheduled_nodes = total_nodes;
    stack.extend(children.map(|child| (child, child_depth)));
    true
}

fn charge_preview_bytes(remaining: &mut usize, amount: usize) -> bool {
    let Some(after) = remaining.checked_sub(amount) else {
        return false;
    };
    *remaining = after;
    true
}

fn sanitize_terminal_text(text: &str) -> String {
    let mut sanitized = String::with_capacity(text.len());
    for character in text.chars() {
        if is_terminal_unsafe(character) {
            sanitized.extend(character.escape_default());
        } else {
            sanitized.push(character);
        }
    }
    sanitized
}

fn escape_rich_text(text: &str) -> String {
    // `markup::escape` alone is not safe for attacker-controlled backslash
    // runs immediately before `[`: rich_rust interprets odd/even slash parity.
    // Reuse the shared parity-aware, terminal-safe bounded embedding helper.
    bounded_rich_fragment(text, usize::MAX)
}

/// Renders JSON-RPC request/response traffic for debugging.
#[derive(Debug, Clone)]
pub struct RequestResponseRenderer {
    theme: &'static FastMcpTheme,
    context: DisplayContext,
    /// Whether to show request params.
    pub show_params: bool,
    /// Whether to show response result or error details.
    pub show_result: bool,
    /// Maximum preview length for JSON payloads.
    pub truncate_at: usize,
    /// Maximum nested depth admitted before a JSON preview fails closed.
    pub max_json_depth: usize,
    /// Whether to show timing information when available.
    pub show_timing: bool,
}

impl RequestResponseRenderer {
    /// Create a renderer with explicit display context.
    #[must_use]
    pub fn new(context: DisplayContext) -> Self {
        Self {
            theme: crate::theme::theme(),
            context,
            show_params: true,
            show_result: true,
            truncate_at: 200,
            max_json_depth: 5,
            show_timing: true,
        }
    }

    /// Create a renderer using auto-detected display context.
    #[must_use]
    pub fn detect() -> Self {
        Self::new(DisplayContext::detect())
    }

    /// Render an incoming request.
    pub fn render_request(&self, request: &JsonRpcRequest, console: &FastMcpConsole) {
        if !self.should_use_rich(console) {
            self.render_request_plain(request, console);
            return;
        }

        let method_color = self.method_color(&request.method);
        let dim_color = self.dim_color();
        let method = escape_rich_text(&peer_metadata_preview(
            &request.method,
            PEER_METHOD_MAX_CHARS,
        ));
        let id = escape_rich_text(&self.format_request_id(&request.id));

        console.print(&format!(
            "\n[bold]->[/] [{}]{}[/] [{}]id={}[/]",
            method_color, method, dim_color, id
        ));

        if self.show_params {
            if let Some(params) = &request.params {
                self.render_json_preview("Params", params, console);
            }
        }
    }

    /// Render an outgoing response.
    pub fn render_response(
        &self,
        response: &JsonRpcResponse,
        duration: Option<Duration>,
        console: &FastMcpConsole,
    ) {
        if !self.should_use_rich(console) {
            self.render_response_plain(response, duration, console);
            return;
        }

        let (label, status_color) = if response.error.is_some() {
            ("ERR", self.error_color())
        } else {
            ("OK", self.success_color())
        };

        let dim_color = self.dim_color();
        let id = escape_rich_text(&self.format_response_id(&response.id));
        let timing = if self.show_timing {
            duration
                .map(|d| format!(" [{}]({})[/]", dim_color, self.format_duration(d)))
                .unwrap_or_default()
        } else {
            String::new()
        };

        console.print(&format!(
            "[bold]<-[/] [{}]{}[/] [{}]id={}[/]{}",
            status_color, label, dim_color, id, timing
        ));

        if self.show_result {
            if let Some(error) = &response.error {
                self.render_error_preview(error, console);
            } else if let Some(result) = &response.result {
                self.render_json_preview("Result", result, console);
            }
        }
    }

    /// Render a request/response pair together.
    pub fn render_pair(
        &self,
        request: &JsonRpcRequest,
        response: &JsonRpcResponse,
        duration: Duration,
        console: &FastMcpConsole,
    ) {
        if !self.should_use_rich(console) {
            self.render_pair_plain(request, response, duration, console);
            return;
        }

        let method_color = self.method_color(&request.method);
        let dim_color = self.dim_color();
        let method = escape_rich_text(&peer_metadata_preview(
            &request.method,
            PEER_METHOD_MAX_CHARS,
        ));
        let status = if response.error.is_some() {
            "FAIL"
        } else {
            "OK"
        };
        let status_color = if response.error.is_some() {
            self.error_color()
        } else {
            self.success_color()
        };

        console.print(&format!(
            "[{}]{}[/] [{}]{}[/] [{}]{}[/]",
            method_color,
            method,
            status_color,
            status,
            dim_color,
            self.format_duration(duration)
        ));
    }

    fn should_use_rich(&self, console: &FastMcpConsole) -> bool {
        self.context.is_human() && console.is_rich()
    }

    fn render_json_preview(
        &self,
        label: &str,
        value: &serde_json::Value,
        console: &FastMcpConsole,
    ) {
        let preview = self.json_preview(value, true);
        let dim_color = self.dim_color();

        console.print(&format!("  [{}]{}:[/]", dim_color, label));
        for line in preview.lines() {
            console.print(&format!("    [{}]{}[/]", dim_color, escape_rich_text(line)));
        }
    }

    fn render_error_preview(&self, error: &JsonRpcError, console: &FastMcpConsole) {
        let error_color = self.error_color();
        let error_class = json_rpc_error_class(error.code);
        let message = bounded_rich_text(
            &peer_metadata_preview(&error.message, PEER_ERROR_SUMMARY_MAX_CHARS),
            usize::MAX,
        );
        console.print(&format!(
            "  [{}]Error {} ({})[/]: {}",
            error_color, error.code, error_class, message
        ));

        if let Some(data) = &error.data {
            let data = escape_rich_text(&self.json_preview(data, false));
            console.print(&format!("  [{}]Data: {}[/]", self.dim_color(), data));
        }
    }

    fn method_color(&self, method: &str) -> String {
        let color = if method.starts_with("tools/") {
            &self.theme.primary
        } else if method.starts_with("resources/") {
            &self.theme.accent
        } else if method.starts_with("prompts/") {
            &self.theme.secondary
        } else if method.starts_with("initialize") || method.starts_with("shutdown") {
            &self.theme.warning
        } else {
            &self.theme.text
        };

        color
            .triplet
            .map(|triplet| triplet.hex())
            .unwrap_or_else(|| "white".to_string())
    }

    fn dim_color(&self) -> String {
        self.theme
            .text_dim
            .triplet
            .map(|triplet| triplet.hex())
            .unwrap_or_else(|| "white".to_string())
    }

    fn success_color(&self) -> String {
        self.theme
            .success
            .triplet
            .map(|triplet| triplet.hex())
            .unwrap_or_else(|| "white".to_string())
    }

    fn error_color(&self) -> String {
        self.theme
            .error
            .triplet
            .map(|triplet| triplet.hex())
            .unwrap_or_else(|| "white".to_string())
    }

    fn format_present_id(&self, id: &RequestId) -> String {
        match id {
            RequestId::Number(n) => n.to_string(),
            RequestId::Integer(lexeme) => peer_metadata_preview(lexeme, PEER_ID_MAX_CHARS),
            RequestId::String(s) => peer_metadata_preview(s, PEER_ID_MAX_CHARS),
        }
    }

    fn format_request_id(&self, id: &Option<RequestId>) -> String {
        id.as_ref().map_or_else(
            || "<notification>".to_owned(),
            |id| self.format_present_id(id),
        )
    }

    fn format_response_id(&self, id: &Option<RequestId>) -> String {
        id.as_ref()
            .map_or_else(|| "<absent>".to_owned(), |id| self.format_present_id(id))
    }

    fn format_duration(&self, d: Duration) -> String {
        let micros = d.as_micros();
        if micros < 1000 {
            format!("{}us", micros)
        } else if micros < 1_000_000 {
            format!("{:.1}ms", micros as f64 / 1000.0)
        } else {
            format!("{:.2}s", micros as f64 / 1_000_000.0)
        }
    }

    fn truncate_string(&self, s: &str) -> String {
        // `truncate_at` is a total output budget, including the marker.
        truncate_to_fixed_budget(s, self.truncate_at, false)
    }

    fn json_preview(&self, value: &Value, pretty: bool) -> String {
        let Some(redacted) = redact_credentials(
            value,
            self.max_json_depth,
            json_preview_source_budget(self.truncate_at),
        ) else {
            return self.truncate_string(JSON_PREVIEW_OMITTED);
        };
        let json = if pretty {
            serde_json::to_string_pretty(&redacted)
        } else {
            serde_json::to_string(&redacted)
        }
        .unwrap_or_else(|_| JSON_PREVIEW_SERIALIZATION_FAILED.to_owned());
        self.truncate_string(&json)
    }

    fn render_request_plain(&self, request: &JsonRpcRequest, console: &FastMcpConsole) {
        let method = peer_metadata_preview(&request.method, PEER_METHOD_MAX_CHARS);
        console.print_plain(&format!(
            "-> {} (id={})",
            method,
            self.format_request_id(&request.id)
        ));

        if self.show_params {
            if let Some(params) = &request.params {
                self.render_json_preview_plain("Params", params, console);
            }
        }
    }

    fn render_response_plain(
        &self,
        response: &JsonRpcResponse,
        duration: Option<Duration>,
        console: &FastMcpConsole,
    ) {
        let status = if response.error.is_some() {
            "error"
        } else {
            "ok"
        };
        let timing = if self.show_timing {
            duration
                .map(|d| format!(" ({})", self.format_duration(d)))
                .unwrap_or_default()
        } else {
            String::new()
        };

        console.print_plain(&format!(
            "<- {} (id={}){}",
            status,
            self.format_response_id(&response.id),
            timing
        ));

        if self.show_result {
            if let Some(error) = &response.error {
                self.render_error_preview_plain(error, console);
            } else if let Some(result) = &response.result {
                self.render_json_preview_plain("Result", result, console);
            }
        }
    }

    fn render_pair_plain(
        &self,
        request: &JsonRpcRequest,
        response: &JsonRpcResponse,
        duration: Duration,
        console: &FastMcpConsole,
    ) {
        let status = if response.error.is_some() {
            "FAIL"
        } else {
            "OK"
        };
        let method = peer_metadata_preview(&request.method, PEER_METHOD_MAX_CHARS);
        console.print_plain(&format!(
            "{} [{}] {}",
            method,
            status,
            self.format_duration(duration)
        ));
    }

    fn render_json_preview_plain(
        &self,
        label: &str,
        value: &serde_json::Value,
        console: &FastMcpConsole,
    ) {
        let preview = self.json_preview(value, true);
        console.print_plain(&format!("  {}:", label));
        for line in preview.lines() {
            console.print_plain(&format!("    {}", sanitize_terminal_text(line)));
        }
    }

    fn render_error_preview_plain(&self, error: &JsonRpcError, console: &FastMcpConsole) {
        let message = peer_metadata_preview(&error.message, PEER_ERROR_SUMMARY_MAX_CHARS);
        console.print_plain(&format!(
            "  Error {} ({}): {}",
            error.code,
            json_rpc_error_class(error.code),
            message
        ));
        if let Some(data) = &error.data {
            let data = sanitize_terminal_text(&self.json_preview(data, false));
            console.print_plain(&format!("  Data: {}", data));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::TestConsole;
    use fastmcp_protocol::{JsonRpcError, JsonRpcRequest, JsonRpcResponse, RequestId};
    use serde_json::json;

    #[test]
    fn test_render_request_plain() {
        let renderer = RequestResponseRenderer::new(DisplayContext::new_agent());
        let console = TestConsole::new();
        let request = JsonRpcRequest::new("tools/list", None, 1i64);

        renderer.render_request(&request, console.console());

        let output = console.output_string();
        assert!(output.contains("-> tools/list"));
        assert!(output.contains("id=1"));
    }

    #[test]
    fn test_render_response_plain_error() {
        let renderer = RequestResponseRenderer::new(DisplayContext::new_agent());
        let console = TestConsole::new();
        let error = JsonRpcError {
            code: -32001,
            message: "boom".to_string(),
            data: Some(serde_json::json!({"detail": "oops"})),
        };
        let response = JsonRpcResponse::error(Some(RequestId::Number(1)), error);

        renderer.render_response(&response, Some(Duration::from_millis(2)), console.console());

        let output = console.output_string();
        assert!(output.contains("<- error"));
        assert!(output.contains("Error -32001"));
    }

    #[test]
    fn test_render_pair_plain_ok() {
        let renderer = RequestResponseRenderer::new(DisplayContext::new_agent());
        let console = TestConsole::new();
        let request = JsonRpcRequest::new("resources/list", None, 2i64);
        let response =
            JsonRpcResponse::success(RequestId::Number(2), serde_json::json!({"ok": true}));

        renderer.render_pair(
            &request,
            &response,
            Duration::from_millis(12),
            console.console(),
        );

        let output = console.output_string();
        assert!(output.contains("resources/list"));
        assert!(output.contains("OK"));
    }

    #[test]
    fn test_render_request_plain_with_params() {
        let renderer = RequestResponseRenderer::new(DisplayContext::new_agent());
        let console = TestConsole::new();
        let request = JsonRpcRequest::new(
            "tools/call",
            Some(json!({"name": "echo", "args": {"text": "hi"}})),
            7i64,
        );

        renderer.render_request(&request, console.console());

        let output = console.output_string();
        assert!(output.contains("-> tools/call"));
        assert!(output.contains("id=7"));
        assert_eq!(output.matches("Params:").count(), 1, "output: {output}");
        assert!(output.contains("echo"));
    }

    const REQUEST_CREDENTIAL_CANARIES: &[&str] = &[
        "Bearer",
        "top-level-canary",
        "nested-auth-canary",
        "object-canary",
        "header-canary",
        "snake-canary",
        "camel-canary",
        "refresh-snake-canary",
        "refresh-camel-canary",
        "client-kebab-canary",
        "client-camel-canary",
        "verifier-snake-canary",
        "verifier-camel-canary",
        "cookie-canary",
        "set-cookie-canary",
        "api-snake-canary",
        "api-camel-canary",
        "x-api-canary",
        "password-canary",
        "id-snake-canary",
        "id-camel-canary",
        "generic-secret-canary",
        "credentials-canary",
        "github-token-canary",
        "openai-api-key-canary",
        "db-password-canary",
        "private-key-canary",
        "session-token-canary",
        "authorization-header-canary",
    ];

    fn credential_fixture() -> Value {
        json!({
            "Authorization": "Bearer top-level-canary",
            "payload": [
                {
                    "AUTH": "nested-auth-canary",
                    "ToKeN": {"secret": "object-canary"}
                },
                {
                    "_meta": {
                        "headers": {
                            "authorization": "Bearer header-canary",
                            "Access_Token": "snake-canary"
                        },
                        "accessToken": "camel-canary"
                    }
                }
            ],
            "common_secrets": {
                "refresh_token": "refresh-snake-canary",
                "refreshToken": "refresh-camel-canary",
                "client-secret": "client-kebab-canary",
                "clientSecret": "client-camel-canary",
                "code_verifier": "verifier-snake-canary",
                "codeVerifier": "verifier-camel-canary",
                "cookie": "cookie-canary",
                "Set-Cookie": "set-cookie-canary",
                "api_key": "api-snake-canary",
                "apiKey": "api-camel-canary",
                "x-api-key": "x-api-canary",
                "password": "password-canary",
                "id_token": "id-snake-canary",
                "idToken": "id-camel-canary"
            },
            "boundary_secrets": {
                "secret": "generic-secret-canary",
                "credentials": "credentials-canary",
                "github_token": "github-token-canary",
                "openai_api_key": "openai-api-key-canary",
                "db_password": "db-password-canary",
                "private_key": "private-key-canary",
                "session_token": "session-token-canary",
                "authorization_header": "authorization-header-canary"
            },
            "ordinary": {
                "authentication": "benign-authentication-visible",
                "refreshTokenCount": "benign-refresh-count-visible",
                "clientSecretHint": "benign-client-hint-visible",
                "codeVerifierLength": "benign-verifier-length-visible",
                "cookiePolicy": "benign-cookie-policy-visible",
                "apiKeyName": "benign-api-name-visible",
                "x-api-key-name": "benign-x-api-name-visible",
                "passwordless": "benign-passwordless-visible",
                "idTokenType": "benign-id-type-visible",
                "secretHint": "benign-secret-hint-visible",
                "credentialsCount": "benign-credentials-count-visible",
                "privateKeyHint": "benign-private-key-hint-visible",
                "sessionTokenCount": "benign-session-count-visible",
                "dbPasswordHint": "benign-db-hint-visible",
                "openaiApiKeyName": "benign-openai-name-visible"
            }
        })
    }

    #[test]
    fn credentials_are_redacted_recursively_and_case_insensitively() {
        let redacted = redact_credentials(
            &credential_fixture(),
            JSON_PREVIEW_HARD_MAX_DEPTH,
            JSON_PREVIEW_MAX_SOURCE_BYTES,
        )
        .expect("bounded fixture should redact");

        for pointer in [
            "/Authorization",
            "/payload/0/AUTH",
            "/payload/0/ToKeN",
            "/payload/1/_meta/headers/authorization",
            "/payload/1/_meta/headers/Access_Token",
            "/payload/1/_meta/accessToken",
            "/common_secrets/refresh_token",
            "/common_secrets/refreshToken",
            "/common_secrets/client-secret",
            "/common_secrets/clientSecret",
            "/common_secrets/code_verifier",
            "/common_secrets/codeVerifier",
            "/common_secrets/cookie",
            "/common_secrets/Set-Cookie",
            "/common_secrets/api_key",
            "/common_secrets/apiKey",
            "/common_secrets/x-api-key",
            "/common_secrets/password",
            "/common_secrets/id_token",
            "/common_secrets/idToken",
            "/boundary_secrets/secret",
            "/boundary_secrets/credentials",
            "/boundary_secrets/github_token",
            "/boundary_secrets/openai_api_key",
            "/boundary_secrets/db_password",
            "/boundary_secrets/private_key",
            "/boundary_secrets/session_token",
            "/boundary_secrets/authorization_header",
        ] {
            assert_eq!(
                redacted.pointer(pointer),
                Some(&Value::String(REDACTED_VALUE.to_owned())),
                "credential at {pointer} was not redacted"
            );
        }
        for pointer in [
            "/ordinary/authentication",
            "/ordinary/refreshTokenCount",
            "/ordinary/clientSecretHint",
            "/ordinary/codeVerifierLength",
            "/ordinary/cookiePolicy",
            "/ordinary/apiKeyName",
            "/ordinary/x-api-key-name",
            "/ordinary/passwordless",
            "/ordinary/idTokenType",
            "/ordinary/secretHint",
            "/ordinary/credentialsCount",
            "/ordinary/privateKeyHint",
            "/ordinary/sessionTokenCount",
            "/ordinary/dbPasswordHint",
            "/ordinary/openaiApiKeyName",
        ] {
            assert_ne!(
                redacted.pointer(pointer),
                Some(&Value::String(REDACTED_VALUE.to_owned())),
                "benign key at {pointer} was over-redacted"
            );
        }

        let serialized = redacted.to_string();
        for canary in REQUEST_CREDENTIAL_CANARIES {
            assert!(!serialized.contains(canary), "leaked {canary}");
        }
        assert!(serialized.contains(REDACTED_VALUE));
    }

    #[test]
    fn redacted_object_keys_remain_collision_safe() {
        let source = json!({
            "token=alpha-secret": "first",
            "token=beta-secret": "second"
        });
        let redacted = redact_credentials(
            &source,
            JSON_PREVIEW_HARD_MAX_DEPTH,
            JSON_PREVIEW_MAX_SOURCE_BYTES,
        )
        .expect("bounded fixture should redact");
        let object = redacted
            .as_object()
            .expect("redacted object should remain an object");

        assert_eq!(object.len(), 2);
        // A token-bearing key classifies the whole entry as credential-like,
        // so both values are conservatively redacted alongside the key text;
        // collision suffixing must still keep the two entries distinct.
        assert!(
            object
                .values()
                .all(|value| value.as_str() == Some(REDACTED_VALUE)),
            "{redacted}"
        );
        let keys: Vec<&String> = object.keys().collect();
        assert_ne!(keys[0], keys[1], "{redacted}");
        let serialized = redacted.to_string();
        assert!(!serialized.contains("alpha-secret"));
        assert!(!serialized.contains("beta-secret"));
    }

    #[test]
    fn credential_key_matching_is_boundary_aware() {
        for key in [
            "refresh_token",
            "refreshToken",
            "REFRESH-TOKEN",
            "client_secret",
            "clientSecret",
            "code.verifier",
            "codeVerifier",
            "cookie",
            "SET_COOKIE",
            "api key",
            "apiKey",
            "X-Api-Key",
            "password",
            "id_token",
            "idToken",
            "secret",
            "credentials",
            "github_token",
            "openai_api_key",
            "db_password",
            "private_key",
            "sessionToken",
            "authorization_header",
            "token_value",
        ] {
            assert!(is_credential_key(key), "missed credential key {key}");
        }

        for key in [
            "authentication",
            "tokenizer",
            "refreshTokenCount",
            "clientSecretHint",
            "codeVerifierLength",
            "cookiePolicy",
            "apiKeyName",
            "x-api-key-name",
            "passwordless",
            "idTokenType",
            "secretHint",
            "credentialsCount",
            "privateKeyHint",
            "sessionTokenCount",
            "dbPasswordHint",
            "openaiApiKeyName",
        ] {
            assert!(!is_credential_key(key), "over-redacted benign key {key}");
        }
    }

    fn free_text_credential_fixture() -> Value {
        json!({
            "message": "Authorization: Bearer ordinary-auth-canary",
            "detail": "db_password=ordinary-password-canary",
            "nested": [
                "github_token: ordinary-token-canary",
                "private_key=ordinary-private-key-canary",
                "credentials: ordinary-credentials-canary"
            ],
            "password=object-key-canary": true
        })
    }

    fn assert_free_text_credentials_are_redacted(context: DisplayContext, rich: bool) {
        let mut renderer = RequestResponseRenderer::new(context);
        renderer.truncate_at = 2_000;
        let console = if rich {
            TestConsole::new_rich()
        } else {
            TestConsole::new()
        };
        let request =
            JsonRpcRequest::new("tools/call", Some(free_text_credential_fixture()), 14_i64);

        renderer.render_request(&request, console.console());

        let output = console.output_string();
        assert!(output.contains(REDACTED_VALUE));
        for canary in [
            "ordinary-auth-canary",
            "ordinary-password-canary",
            "ordinary-token-canary",
            "ordinary-private-key-canary",
            "ordinary-credentials-canary",
            "object-key-canary",
        ] {
            assert!(!output.contains(canary), "leaked {canary}: {output}");
        }
    }

    #[test]
    fn free_text_credentials_are_redacted_in_plain_traffic() {
        assert_free_text_credentials_are_redacted(DisplayContext::new_agent(), false);
    }

    #[test]
    fn free_text_credentials_are_redacted_in_rich_traffic() {
        assert_free_text_credentials_are_redacted(DisplayContext::new_human(), true);
    }

    fn assert_request_credentials_are_redacted(console: &TestConsole) {
        let output = console.output_string();
        assert!(output.contains(REDACTED_VALUE), "output: {output}");
        for canary in REQUEST_CREDENTIAL_CANARIES {
            assert!(!output.contains(canary), "leaked {canary}: {output}");
        }
        for benign in [
            "benign-authentication-visible",
            "benign-refresh-count-visible",
            "benign-client-hint-visible",
            "benign-verifier-length-visible",
            "benign-cookie-policy-visible",
            "benign-api-name-visible",
            "benign-x-api-name-visible",
            "benign-passwordless-visible",
            "benign-id-type-visible",
            "benign-secret-hint-visible",
            "benign-credentials-count-visible",
            "benign-private-key-hint-visible",
            "benign-session-count-visible",
            "benign-db-hint-visible",
            "benign-openai-name-visible",
        ] {
            assert!(
                output.contains(benign),
                "missing benign value {benign}: {output}"
            );
        }
    }

    #[test]
    fn request_params_are_redacted_in_plain_output() {
        let mut renderer = RequestResponseRenderer::new(DisplayContext::new_agent());
        renderer.truncate_at = 2_000;
        let console = TestConsole::new();
        let request = JsonRpcRequest::new("tools/call", Some(credential_fixture()), 11i64);

        renderer.render_request(&request, console.console());

        assert_request_credentials_are_redacted(&console);
    }

    #[test]
    fn request_params_are_redacted_in_rich_output() {
        let mut renderer = RequestResponseRenderer::new(DisplayContext::new_human());
        renderer.truncate_at = 2_000;
        let console = TestConsole::new_rich();
        let request = JsonRpcRequest::new("tools/call", Some(credential_fixture()), 12i64);

        renderer.render_request(&request, console.console());

        assert_request_credentials_are_redacted(&console);
    }

    fn markup_and_control_request() -> JsonRpcRequest {
        JsonRpcRequest::new(
            "tools/[bold]call[/]\n\u{1b}\u{202e}",
            None,
            RequestId::String("[link=https://invalid]id[/link]\r\u{7}".to_owned()),
        )
    }

    fn assert_request_text_is_terminal_safe(console: &TestConsole) {
        let output = console.output_string();
        assert!(output.contains("[bold]call[/]"), "output: {output}");
        assert!(
            output.contains("[link=https://invalid]id[/link]"),
            "output: {output}"
        );
        for escaped in ["\\n", "\\u{1b}", "\\u{202e}", "\\r", "\\u{7}"] {
            assert!(output.contains(escaped), "missing {escaped}: {output}");
        }
        for line in console.output() {
            assert!(
                !line.chars().any(is_terminal_unsafe),
                "unsafe terminal character remained in {line:?}"
            );
        }
    }

    #[test]
    fn terminal_sanitizer_escapes_control_and_directional_codepoints() {
        let mut unsafe_text: String = (0..=0x9f)
            .filter_map(char::from_u32)
            .filter(|character| character.is_control())
            .collect();
        unsafe_text.push_str(
            "\u{00ad}\u{034f}\u{061c}\u{180e}\u{200b}\u{200c}\u{200d}\u{200e}\u{200f}\u{2028}\u{2029}\u{202a}\u{202b}\u{202c}\u{202d}\u{202e}\u{2060}\u{2061}\u{2066}\u{2067}\u{2068}\u{2069}\u{206f}\u{fe0f}\u{feff}\u{e0001}\u{e007f}\u{e0100}",
        );

        let sanitized = sanitize_terminal_text(&unsafe_text);

        assert!(!sanitized.chars().any(is_terminal_unsafe));
        assert_eq!(sanitize_terminal_text("tools/call ☃"), "tools/call ☃");
    }

    #[test]
    fn request_method_and_id_are_safe_in_plain_output() {
        let renderer = RequestResponseRenderer::new(DisplayContext::new_agent());
        let console = TestConsole::new();

        renderer.render_request(&markup_and_control_request(), console.console());

        assert_request_text_is_terminal_safe(&console);
    }

    #[test]
    fn request_method_and_id_are_safe_in_rich_output() {
        let renderer = RequestResponseRenderer::new(DisplayContext::new_human());
        let console = TestConsole::new_rich();

        renderer.render_request(&markup_and_control_request(), console.console());

        assert_request_text_is_terminal_safe(&console);
    }

    fn hostile_method() -> String {
        let mut method =
            "tools/call?access_token=method-secret-canary&password=method-password-canary\n\u{1b}\u{202e}"
                .to_owned();
        method.push_str(&"x".repeat(20_000));
        method.push_str("METHOD_TAIL_MUST_NOT_RENDER");
        method
    }

    fn assert_hostile_method_is_bounded_and_safe(context: DisplayContext, rich: bool) {
        let renderer = RequestResponseRenderer::new(context);
        let console = if rich {
            TestConsole::new_rich()
        } else {
            TestConsole::new()
        };
        let request = JsonRpcRequest::new(hostile_method(), None, 31i64);
        let response = JsonRpcResponse::success(RequestId::Number(31), json!(null));

        renderer.render_request(&request, console.console());
        renderer.render_pair(
            &request,
            &response,
            Duration::from_micros(1),
            console.console(),
        );

        let output = console.output_string();
        assert!(output.contains(REDACTED_VALUE), "output: {output}");
        assert!(output.contains("..."), "output: {output}");
        assert!(output.contains("\\n"), "output: {output}");
        assert!(output.contains("\\u{1b}"), "output: {output}");
        assert!(output.contains("\\u{202e}"), "output: {output}");
        for secret in ["method-secret-canary", "method-password-canary"] {
            assert!(!output.contains(secret), "leaked {secret}: {output}");
        }
        assert!(!output.contains("METHOD_TAIL_MUST_NOT_RENDER"));
        assert!(output.chars().count() < 700, "unbounded output: {output}");
        for line in console.output() {
            assert!(
                !line.chars().any(is_terminal_unsafe),
                "unsafe terminal character remained in {line:?}"
            );
        }
    }

    #[test]
    fn hostile_request_method_is_bounded_and_safe_in_plain_output() {
        assert_hostile_method_is_bounded_and_safe(DisplayContext::new_agent(), false);
    }

    #[test]
    fn hostile_request_method_is_bounded_and_safe_in_rich_output() {
        assert_hostile_method_is_bounded_and_safe(DisplayContext::new_human(), true);
    }

    fn hostile_error_message() -> String {
        let mut message =
            "upstream rejected Authorization: Bearer error-secret-canary; password=error-password-canary\n\u{1b}\u{202e}"
                .to_owned();
        message.push_str(&"y".repeat(20_000));
        message.push_str("ERROR_TAIL_MUST_NOT_RENDER");
        message
    }

    fn assert_hostile_error_is_bounded_and_safe(context: DisplayContext, rich: bool) {
        let renderer = RequestResponseRenderer::new(context);
        let console = if rich {
            TestConsole::new_rich()
        } else {
            TestConsole::new()
        };
        let response = JsonRpcResponse::error(
            Some(RequestId::Number(32)),
            JsonRpcError {
                code: -32042,
                message: hostile_error_message(),
                data: None,
            },
        );

        renderer.render_response(&response, None, console.console());

        let output = console.output_string();
        assert!(
            output.contains("Error -32042 (server-error)"),
            "output: {output}"
        );
        assert!(output.contains(REDACTED_VALUE), "output: {output}");
        assert!(output.contains("..."), "output: {output}");
        assert!(output.contains("\\n"), "output: {output}");
        assert!(output.contains("\\u{1b}"), "output: {output}");
        assert!(output.contains("\\u{202e}"), "output: {output}");
        for secret in ["error-secret-canary", "error-password-canary"] {
            assert!(!output.contains(secret), "leaked {secret}: {output}");
        }
        assert!(!output.contains("ERROR_TAIL_MUST_NOT_RENDER"));
        assert!(output.chars().count() < 500, "unbounded output: {output}");
        for line in console.output() {
            assert!(
                !line.chars().any(is_terminal_unsafe),
                "unsafe terminal character remained in {line:?}"
            );
        }
    }

    #[test]
    fn hostile_error_message_is_bounded_and_safe_in_plain_output() {
        assert_hostile_error_is_bounded_and_safe(DisplayContext::new_agent(), false);
    }

    #[test]
    fn hostile_error_message_is_bounded_and_safe_in_rich_output() {
        assert_hostile_error_is_bounded_and_safe(DisplayContext::new_human(), true);
    }

    #[test]
    fn peer_metadata_preview_redacts_common_free_text_credentials() {
        // The remainder of an authorization header is one opaque credential:
        // line-end redaction keeps auth-params after ';' from leaking
        // piecemeal, so the whole tail collapses into a single marker.
        let header = peer_metadata_preview(
            r#"Authorization: Bearer auth-canary; access_token=query-canary&password="password-canary""#,
            PEER_ERROR_SUMMARY_MAX_CHARS,
        );
        assert_eq!(header.matches(REDACTED_VALUE).count(), 1, "{header}");
        for secret in ["auth-canary", "query-canary", "password-canary"] {
            assert!(!header.contains(secret), "leaked {secret}: {header}");
        }

        // Outside a header context each credential assignment redacts
        // individually, preserving the surrounding free text.
        let assignments = peer_metadata_preview(
            r#"access_token=query-canary&password="password-canary""#,
            PEER_ERROR_SUMMARY_MAX_CHARS,
        );
        assert_eq!(
            assignments.matches(REDACTED_VALUE).count(),
            2,
            "{assignments}"
        );
        for secret in ["query-canary", "password-canary"] {
            assert!(
                !assignments.contains(secret),
                "leaked {secret}: {assignments}"
            );
        }
    }

    #[test]
    fn peer_metadata_preview_enforces_total_character_budget() {
        let preview = peer_metadata_preview(&"z".repeat(10_000), PEER_METHOD_MAX_CHARS);

        assert_eq!(preview.chars().count(), PEER_METHOD_MAX_CHARS);
        assert!(preview.ends_with(TRUNCATION_MARKER));
    }

    fn response_security_fixture(first_canary: &str, second_canary: &str) -> Value {
        json!({
            "AuTh": first_canary,
            "nested": [{"AcCeSs_ToKeN": second_canary}],
            "common_secrets": {
                "refreshToken": first_canary,
                "client_secret": second_canary,
                "code-verifier": first_canary,
                "COOKIE": second_canary,
                "set_cookie": first_canary,
                "apiKey": second_canary,
                "X-Api-Key": first_canary,
                "PassWord": second_canary,
                "id_token": first_canary
            },
            "ordinary": {
                "authentication": "ordinary-authentication-visible",
                "tokenizer": "ordinary-tokenizer-visible",
                "accessTokenCount": 3,
                "refreshTokenCount": "ordinary-refresh-count-visible",
                "clientSecretHint": "ordinary-client-hint-visible",
                "codeVerifierLength": "ordinary-verifier-length-visible",
                "cookiePolicy": "ordinary-cookie-policy-visible",
                "apiKeyName": "ordinary-api-name-visible",
                "x-api-key-name": "ordinary-x-api-name-visible",
                "passwordless": "ordinary-passwordless-visible",
                "idTokenType": "ordinary-id-type-visible",
                "display": "[bold]literal[/]\n\u{1b}\u{202e}"
            }
        })
    }

    fn assert_response_json_is_redacted_and_terminal_safe(
        console: &TestConsole,
        canaries: &[&str],
    ) {
        let output = console.output_string();
        assert!(output.contains(REDACTED_VALUE), "output: {output}");
        assert!(
            output.contains("ordinary-authentication-visible"),
            "ordinary field was over-redacted: {output}"
        );
        assert!(
            output.contains("ordinary-tokenizer-visible"),
            "ordinary field was over-redacted: {output}"
        );
        for benign in [
            "accessTokenCount",
            "ordinary-refresh-count-visible",
            "ordinary-client-hint-visible",
            "ordinary-verifier-length-visible",
            "ordinary-cookie-policy-visible",
            "ordinary-api-name-visible",
            "ordinary-x-api-name-visible",
            "ordinary-passwordless-visible",
            "ordinary-id-type-visible",
        ] {
            assert!(
                output.contains(benign),
                "missing benign value {benign}: {output}"
            );
        }
        assert!(output.contains("[bold]literal[/]"), "output: {output}");
        for escaped in ["\\n", "\\u001b", "\\u{202e}"] {
            assert!(output.contains(escaped), "missing {escaped}: {output}");
        }
        for canary in canaries {
            assert!(!output.contains(canary), "leaked {canary}: {output}");
        }
        for line in console.output() {
            assert!(
                !line.chars().any(is_terminal_unsafe),
                "unsafe terminal character remained in {line:?}"
            );
        }
    }

    #[test]
    fn response_result_is_redacted_and_terminal_safe_in_plain_output() {
        let mut renderer = RequestResponseRenderer::new(DisplayContext::new_agent());
        renderer.truncate_at = 2_000;
        let console = TestConsole::new();
        let response = JsonRpcResponse::success(
            RequestId::Number(21),
            response_security_fixture("plain-result-canary", "plain-result-nested-canary"),
        );

        renderer.render_response(&response, None, console.console());

        console.assert_contains("Result");
        assert_response_json_is_redacted_and_terminal_safe(
            &console,
            &["plain-result-canary", "plain-result-nested-canary"],
        );
    }

    #[test]
    fn response_result_is_redacted_and_terminal_safe_in_rich_output() {
        let mut renderer = RequestResponseRenderer::new(DisplayContext::new_human());
        renderer.truncate_at = 2_000;
        let console = TestConsole::new_rich();
        let response = JsonRpcResponse::success(
            RequestId::Number(22),
            response_security_fixture("rich-result-canary", "rich-result-nested-canary"),
        );

        renderer.render_response(&response, None, console.console());

        console.assert_contains("Result");
        assert_response_json_is_redacted_and_terminal_safe(
            &console,
            &["rich-result-canary", "rich-result-nested-canary"],
        );
    }

    #[test]
    fn response_error_data_is_redacted_and_terminal_safe_in_plain_output() {
        let mut renderer = RequestResponseRenderer::new(DisplayContext::new_agent());
        renderer.truncate_at = 2_000;
        let console = TestConsole::new();
        let response = JsonRpcResponse::error(
            Some(RequestId::Number(23)),
            JsonRpcError {
                code: -32023,
                message: "[italic]literal error[/]\n\u{202e}".to_owned(),
                data: Some(response_security_fixture(
                    "plain-error-canary",
                    "plain-error-nested-canary",
                )),
            },
        );

        renderer.render_response(&response, None, console.console());

        console.assert_contains("Data:");
        console.assert_contains("[italic]literal error[/]");
        assert_response_json_is_redacted_and_terminal_safe(
            &console,
            &["plain-error-canary", "plain-error-nested-canary"],
        );
    }

    #[test]
    fn response_error_data_is_redacted_and_terminal_safe_in_rich_output() {
        let mut renderer = RequestResponseRenderer::new(DisplayContext::new_human());
        renderer.truncate_at = 2_000;
        let console = TestConsole::new_rich();
        let response = JsonRpcResponse::error(
            Some(RequestId::Number(24)),
            JsonRpcError {
                code: -32024,
                message: "[italic]literal error[/]\n\u{202e}".to_owned(),
                data: Some(response_security_fixture(
                    "rich-error-canary",
                    "rich-error-nested-canary",
                )),
            },
        );

        renderer.render_response(&response, None, console.console());

        console.assert_contains("Data:");
        console.assert_contains("[italic]literal error[/]");
        assert_response_json_is_redacted_and_terminal_safe(
            &console,
            &["rich-error-canary", "rich-error-nested-canary"],
        );
    }

    #[test]
    fn test_render_request_plain_hides_params_when_disabled() {
        let mut renderer = RequestResponseRenderer::new(DisplayContext::new_agent());
        renderer.show_params = false;
        let console = TestConsole::new();
        let request = JsonRpcRequest::new("tools/call", Some(json!({"x": 1})), 1i64);

        renderer.render_request(&request, console.console());

        let output = console.output_string();
        assert!(output.contains("-> tools/call"));
        assert!(!output.contains("Params"));
    }

    #[test]
    fn test_render_request_plain_notification_id_is_absent() {
        let renderer = RequestResponseRenderer::new(DisplayContext::new_agent());
        let console = TestConsole::new();
        let request = JsonRpcRequest::notification("notifications/progress", Some(json!({"n": 1})));

        renderer.render_request(&request, console.console());

        let output = console.output_string();
        assert!(output.contains("id=<notification>"));
        assert!(!output.contains("id=null"));
    }

    #[test]
    fn test_render_request_rich_notification_id_is_absent() {
        let renderer = RequestResponseRenderer::new(DisplayContext::new_human());
        let console = TestConsole::new_rich();
        let request = JsonRpcRequest::notification("notifications/progress", None);

        renderer.render_request(&request, console.console());

        let output = console.output_string();
        assert!(output.contains("id=<notification>"), "output: {output}");
        assert!(!output.contains("id=null"), "output: {output}");
    }

    #[test]
    fn test_render_response_plain_success_with_result() {
        let renderer = RequestResponseRenderer::new(DisplayContext::new_agent());
        let console = TestConsole::new();
        let response = JsonRpcResponse::success(
            RequestId::String("req-1".to_string()),
            json!({"items": [1, 2, 3]}),
        );

        renderer.render_response(
            &response,
            Some(Duration::from_micros(1500)),
            console.console(),
        );

        let output = console.output_string();
        assert!(output.contains("<- ok"));
        assert!(output.contains("1.5ms"));
        assert!(output.contains("Result"));
    }

    #[test]
    fn test_render_response_plain_hides_result_and_timing() {
        let mut renderer = RequestResponseRenderer::new(DisplayContext::new_agent());
        renderer.show_result = false;
        renderer.show_timing = false;
        let console = TestConsole::new();
        let response = JsonRpcResponse::success(RequestId::Number(9), json!({"ok": true}));

        renderer.render_response(&response, Some(Duration::from_millis(8)), console.console());

        let output = console.output_string();
        assert!(output.contains("<- ok (id=9)"));
        assert!(!output.contains("8.0ms"));
        assert!(!output.contains("Result"));
    }

    #[test]
    fn test_render_response_plain_error_without_data() {
        let renderer = RequestResponseRenderer::new(DisplayContext::new_agent());
        let console = TestConsole::new();
        let response = JsonRpcResponse::error(
            None,
            JsonRpcError {
                code: -32601,
                message: "Method not found".to_string(),
                data: None,
            },
        );

        renderer.render_response(&response, None, console.console());

        let output = console.output_string();
        assert!(output.contains("<- error (id=<absent>)"));
        assert!(!output.contains("id=null"));
        assert!(output.contains("-32601"));
        assert!(output.contains("Method not found"));
        assert!(!output.contains("Data:"));
    }

    #[test]
    fn test_render_response_rich_absent_id_is_not_reported_as_null() {
        let renderer = RequestResponseRenderer::new(DisplayContext::new_human());
        let console = TestConsole::new_rich();
        let response = JsonRpcResponse::error(
            None,
            JsonRpcError {
                code: -32600,
                message: "Invalid Request".to_owned(),
                data: None,
            },
        );

        renderer.render_response(&response, None, console.console());

        let output = console.output_string();
        assert!(output.contains("id=<absent>"), "output: {output}");
        assert!(!output.contains("id=null"), "output: {output}");
    }

    #[test]
    fn test_render_pair_plain_fail() {
        let renderer = RequestResponseRenderer::new(DisplayContext::new_agent());
        let console = TestConsole::new();
        let request = JsonRpcRequest::new("tools/call", None, 10i64);
        let response = JsonRpcResponse::error(
            Some(RequestId::Number(10)),
            JsonRpcError {
                code: -32000,
                message: "boom".to_string(),
                data: None,
            },
        );

        renderer.render_pair(
            &request,
            &response,
            Duration::from_micros(320),
            console.console(),
        );

        let output = console.output_string();
        assert!(output.contains("tools/call"));
        assert!(output.contains("FAIL"));
        assert!(output.contains("320us"));
    }

    #[test]
    fn test_render_request_rich_path() {
        let renderer = RequestResponseRenderer::new(DisplayContext::new_human());
        let console = TestConsole::new_rich();
        let request =
            JsonRpcRequest::new("resources/read", Some(json!({"uri": "file://a"})), 42i64);

        renderer.render_request(&request, console.console());

        let output = console.output_string();
        assert!(output.contains("resources/read"));
        assert!(output.contains("id=42"));
        assert!(output.contains("Params"));
    }

    #[test]
    fn test_render_response_rich_error_with_data() {
        let renderer = RequestResponseRenderer::new(DisplayContext::new_human());
        let console = TestConsole::new_rich();
        let response = JsonRpcResponse::error(
            Some(RequestId::String("abc".to_string())),
            JsonRpcError {
                code: -32042,
                message: "failed".to_string(),
                data: Some(json!({"retryable": false})),
            },
        );

        renderer.render_response(&response, Some(Duration::from_secs(2)), console.console());

        let output = console.output_string();
        assert!(output.contains("ERR"));
        assert!(output.contains("id=abc"));
        assert!(output.contains("2.00s"));
        assert!(output.contains("Error -32042"));
        assert!(output.contains("Data:"));
    }

    #[test]
    fn test_render_pair_rich_ok_and_fail() {
        let renderer = RequestResponseRenderer::new(DisplayContext::new_human());
        let console = TestConsole::new_rich();
        let request = JsonRpcRequest::new("initialize", None, 1i64);
        let ok = JsonRpcResponse::success(RequestId::Number(1), json!({"ok": true}));
        renderer.render_pair(&request, &ok, Duration::from_millis(7), console.console());
        console.assert_contains("initialize");
        console.assert_contains("OK");

        let err = JsonRpcResponse::error(
            Some(RequestId::Number(1)),
            JsonRpcError {
                code: -1,
                message: "nope".to_string(),
                data: None,
            },
        );
        renderer.render_pair(&request, &err, Duration::from_millis(7), console.console());
        console.assert_contains("FAIL");
    }

    #[test]
    fn test_method_and_color_helpers_return_values() {
        let renderer = RequestResponseRenderer::new(DisplayContext::new_agent());

        assert!(!renderer.method_color("tools/list").is_empty());
        assert!(!renderer.method_color("resources/list").is_empty());
        assert!(!renderer.method_color("prompts/list").is_empty());
        assert!(!renderer.method_color("initialize").is_empty());
        assert!(!renderer.method_color("misc/method").is_empty());
        assert!(!renderer.dim_color().is_empty());
        assert!(!renderer.success_color().is_empty());
        assert!(!renderer.error_color().is_empty());
    }

    #[test]
    fn test_format_request_id_variants() {
        let renderer = RequestResponseRenderer::new(DisplayContext::new_agent());
        assert_eq!(renderer.format_request_id(&Some(RequestId::Number(5))), "5");
        assert_eq!(
            renderer.format_request_id(&Some(RequestId::String("r-1".to_string()))),
            "r-1"
        );
        assert_eq!(renderer.format_request_id(&None), "<notification>");
    }

    #[test]
    fn test_format_response_id_variants() {
        let renderer = RequestResponseRenderer::new(DisplayContext::new_agent());
        assert_eq!(
            renderer.format_response_id(&Some(RequestId::Number(5))),
            "5"
        );
        assert_eq!(
            renderer.format_response_id(&Some(RequestId::String("r-1".to_string()))),
            "r-1"
        );
        assert_eq!(renderer.format_response_id(&None), "<absent>");
    }

    #[test]
    fn json_rpc_error_classes_are_fixed_from_numeric_codes() {
        assert_eq!(json_rpc_error_class(-32700), "parse-error");
        assert_eq!(json_rpc_error_class(-32600), "invalid-request");
        assert_eq!(json_rpc_error_class(-32601), "method-not-found");
        assert_eq!(json_rpc_error_class(-32602), "invalid-params");
        assert_eq!(json_rpc_error_class(-32603), "internal-error");
        assert_eq!(json_rpc_error_class(-32042), "server-error");
        assert_eq!(json_rpc_error_class(7), "application-error");
    }

    #[test]
    fn test_format_duration_branches() {
        let renderer = RequestResponseRenderer::new(DisplayContext::new_agent());
        assert_eq!(
            renderer.format_duration(Duration::from_micros(999)),
            "999us"
        );
        assert_eq!(
            renderer.format_duration(Duration::from_micros(1234)),
            "1.2ms"
        );
        assert_eq!(
            renderer.format_duration(Duration::from_millis(2500)),
            "2.50s"
        );
    }

    #[test]
    fn test_truncate_string_branches() {
        let mut renderer = RequestResponseRenderer::new(DisplayContext::new_agent());
        renderer.truncate_at = 8;
        assert_eq!(renderer.truncate_string("short"), "short");
        assert_eq!(renderer.truncate_string("123456789"), "12345...");

        renderer.truncate_at = 2;
        assert_eq!(renderer.truncate_string("long"), "..");
        renderer.truncate_at = 0;
        assert_eq!(renderer.truncate_string("long"), "");
    }

    #[test]
    fn test_plain_json_and_error_preview_helpers() {
        let mut renderer = RequestResponseRenderer::new(DisplayContext::new_agent());
        renderer.truncate_at = 10;
        let console = TestConsole::new();

        renderer.render_json_preview_plain(
            "Payload",
            &json!({"long": "abcdefghijklmnopqrstuvwxyz"}),
            console.console(),
        );
        console.assert_contains("Payload:");
        console.assert_contains("...");

        renderer.render_error_preview_plain(
            &JsonRpcError {
                code: -32001,
                message: "boom".to_string(),
                data: Some(json!({"details": "abcdefghijklmnopqrstuvwxyz"})),
            },
            console.console(),
        );
        console.assert_contains("Error -32001 (server-error): boom");
        console.assert_contains("Data:");
    }

    #[test]
    fn json_preview_fails_closed_before_cloning_oversized_values() {
        let mut renderer = RequestResponseRenderer::new(DisplayContext::new_agent());
        renderer.truncate_at = 200;
        let secret = "oversized-preview-secret-canary";
        let oversized = json!({"ordinary": format!("{secret}{}", "x".repeat(100_000))});

        let preview = renderer.json_preview(&oversized, true);

        assert!(preview.contains("payload omitted"));
        assert!(!preview.contains(secret));
    }

    #[test]
    fn json_preview_honors_configured_depth_and_hard_node_bound() {
        let mut renderer = RequestResponseRenderer::new(DisplayContext::new_agent());
        renderer.truncate_at = 200;
        renderer.max_json_depth = 2;
        let too_deep = json!({"one": {"two": {"three": "depth-secret-canary"}}});
        let too_many = Value::Array(vec![Value::Null; JSON_PREVIEW_MAX_NODES + 1]);

        let deep_preview = renderer.json_preview(&too_deep, false);
        let wide_preview = renderer.json_preview(&too_many, false);

        assert!(deep_preview.contains("payload omitted"));
        assert!(!deep_preview.contains("depth-secret-canary"));
        assert!(wide_preview.contains("payload omitted"));
    }

    // =========================================================================
    // Additional coverage tests (bd-cqqa)
    // =========================================================================

    #[test]
    fn renderer_debug_and_clone() {
        let renderer = RequestResponseRenderer::new(DisplayContext::new_agent());
        let debug = format!("{renderer:?}");
        assert!(debug.contains("RequestResponseRenderer"));
        assert!(debug.contains("show_params"));
        assert!(debug.contains("truncate_at"));
        assert!(debug.contains("max_json_depth"));

        let cloned = renderer.clone();
        assert!(cloned.show_params);
        assert_eq!(cloned.truncate_at, 200);
        assert_eq!(cloned.max_json_depth, 5);
    }

    #[test]
    fn detect_constructor() {
        let renderer = RequestResponseRenderer::detect();
        assert_eq!(renderer.truncate_at, 200);
        assert_eq!(renderer.max_json_depth, 5);
        assert!(renderer.show_params);
        assert!(renderer.show_result);
        assert!(renderer.show_timing);
    }

    #[test]
    fn render_response_rich_success() {
        let renderer = RequestResponseRenderer::new(DisplayContext::new_human());
        let console = TestConsole::new_rich();
        let response = JsonRpcResponse::success(RequestId::Number(7), json!({"items": [1, 2, 3]}));

        renderer.render_response(&response, Some(Duration::from_millis(5)), console.console());

        let output = console.output_string();
        assert!(output.contains("OK"));
        assert!(output.contains("id=7"));
        assert!(output.contains("Result"));
    }

    #[test]
    fn render_response_rich_no_duration() {
        let renderer = RequestResponseRenderer::new(DisplayContext::new_human());
        let console = TestConsole::new_rich();
        let response = JsonRpcResponse::success(RequestId::Number(8), json!({"ok": true}));

        renderer.render_response(&response, None, console.console());

        let output = console.output_string();
        assert!(output.contains("OK"));
        assert!(output.contains("id=8"));
    }

    #[test]
    fn render_request_rich_no_params() {
        let renderer = RequestResponseRenderer::new(DisplayContext::new_human());
        let console = TestConsole::new_rich();
        let request = JsonRpcRequest::new("tools/list", None, 3i64);

        renderer.render_request(&request, console.console());

        let output = console.output_string();
        assert!(output.contains("tools/list"));
        assert!(output.contains("id=3"));
        assert!(!output.contains("Params"));
    }

    #[test]
    fn method_color_shutdown_prefix() {
        let renderer = RequestResponseRenderer::new(DisplayContext::new_agent());
        let init_color = renderer.method_color("initialize");
        let shut_color = renderer.method_color("shutdown");
        // Both initialize and shutdown use the same warning color
        assert_eq!(init_color, shut_color);
    }

    #[test]
    fn render_response_rich_show_timing_disabled() {
        let mut renderer = RequestResponseRenderer::new(DisplayContext::new_human());
        renderer.show_timing = false;
        let console = TestConsole::new_rich();
        let response = JsonRpcResponse::success(RequestId::Number(9), json!(null));

        renderer.render_response(
            &response,
            Some(Duration::from_millis(50)),
            console.console(),
        );

        let output = console.output_string();
        assert!(output.contains("OK"));
        // Timing should NOT appear
        assert!(!output.contains("50"));
    }

    #[test]
    fn render_error_preview_plain_without_data() {
        let renderer = RequestResponseRenderer::new(DisplayContext::new_agent());
        let console = TestConsole::new();

        renderer.render_error_preview_plain(
            &JsonRpcError {
                code: -32600,
                message: "Invalid Request".to_string(),
                data: None,
            },
            console.console(),
        );

        console.assert_contains("Error -32600");
        console.assert_contains("Invalid Request");
        console.assert_not_contains("Data:");
    }
}
