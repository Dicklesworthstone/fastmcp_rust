//! Request/response traffic rendering for MCP JSON-RPC.

use std::time::Duration;

use fastmcp_protocol::{JsonRpcError, JsonRpcRequest, JsonRpcResponse, RequestId};

use crate::console::FastMcpConsole;
use crate::detection::DisplayContext;
use crate::theme::FastMcpTheme;

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

        console.print(&format!(
            "\n[bold]->[/] [{}]{}[/] [{}]id={}[/]",
            method_color,
            request.method,
            dim_color,
            self.format_id(&request.id)
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
        let timing = if self.show_timing {
            duration
                .map(|d| format!(" [{}]({})[/]", dim_color, self.format_duration(d)))
                .unwrap_or_default()
        } else {
            String::new()
        };

        console.print(&format!(
            "[bold]<-[/] [{}]{}[/] [{}]id={}[/]{}",
            status_color,
            label,
            dim_color,
            self.format_id(&response.id),
            timing
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
            request.method,
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
        let json_str = serde_json::to_string_pretty(value).unwrap_or_default();
        let preview = self.truncate_string(&json_str);
        let dim_color = self.dim_color();

        console.print(&format!("  [{}]{}:[/]", dim_color, label));
        for line in preview.lines() {
            console.print(&format!("    [{}]{}[/]", dim_color, line));
        }
    }

    fn render_error_preview(&self, error: &JsonRpcError, console: &FastMcpConsole) {
        let error_color = self.error_color();
        console.print(&format!(
            "  [{}]Error {}[/]: {}",
            error_color, error.code, error.message
        ));

        if let Some(data) = &error.data {
            console.print(&format!(
                "  [{}]Data: {}[/]",
                self.dim_color(),
                self.truncate_string(&data.to_string())
            ));
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

    fn format_id(&self, id: &Option<RequestId>) -> String {
        match id {
            Some(RequestId::Number(n)) => n.to_string(),
            Some(RequestId::String(s)) => s.clone(),
            None => "null".to_string(),
        }
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
        let len = s.chars().count();
        if len <= self.truncate_at {
            s.to_string()
        } else {
            let truncated: String = s.chars().take(self.truncate_at).collect();
            format!("{}...", truncated)
        }
    }

    fn render_request_plain(&self, request: &JsonRpcRequest, console: &FastMcpConsole) {
        console.print_plain(&format!(
            "-> {} (id={})",
            request.method,
            self.format_id(&request.id)
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
            self.format_id(&response.id),
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
        console.print_plain(&format!(
            "{} [{}] {}",
            request.method,
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
        let json_str = serde_json::to_string_pretty(value).unwrap_or_default();
        let preview = self.truncate_string(&json_str);
        console.print_plain(&format!("  {}:", label));
        for line in preview.lines() {
            console.print_plain(&format!("    {}", line));
        }
    }

    fn render_error_preview_plain(&self, error: &JsonRpcError, console: &FastMcpConsole) {
        console.print_plain(&format!("  Error {}: {}", error.code, error.message));
        if let Some(data) = &error.data {
            console.print_plain(&format!(
                "  Data: {}",
                self.truncate_string(&data.to_string())
            ));
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
        assert!(output.contains("Params"));
        assert!(output.contains("echo"));
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
    fn test_render_request_plain_notification_id_is_null() {
        let renderer = RequestResponseRenderer::new(DisplayContext::new_agent());
        let console = TestConsole::new();
        let request = JsonRpcRequest::notification("notifications/progress", Some(json!({"n": 1})));

        renderer.render_request(&request, console.console());

        let output = console.output_string();
        assert!(output.contains("id=null"));
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
        assert!(output.contains("<- error (id=null)"));
        assert!(output.contains("-32601"));
        assert!(output.contains("Method not found"));
        assert!(!output.contains("Data:"));
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
    fn test_format_id_variants() {
        let renderer = RequestResponseRenderer::new(DisplayContext::new_agent());
        assert_eq!(renderer.format_id(&Some(RequestId::Number(5))), "5");
        assert_eq!(
            renderer.format_id(&Some(RequestId::String("r-1".to_string()))),
            "r-1"
        );
        assert_eq!(renderer.format_id(&None), "null");
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
        assert_eq!(renderer.truncate_string("123456789"), "12345678...");
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
        console.assert_contains("Error -32001: boom");
        console.assert_contains("Data:");
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

        let cloned = renderer.clone();
        assert!(cloned.show_params);
        assert_eq!(cloned.truncate_at, 200);
    }

    #[test]
    fn detect_constructor() {
        let renderer = RequestResponseRenderer::detect();
        assert_eq!(renderer.truncate_at, 200);
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
