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
        console.print(&format!(
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

        console.print(&format!(
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
        // Use escaped brackets to avoid rich markup interpretation
        console.print(&format!(
            "{} \\[{}\\] {}",
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
        console.print(&format!("  {}:", label));
        for line in preview.lines() {
            console.print(&format!("    {}", line));
        }
    }

    fn render_error_preview_plain(&self, error: &JsonRpcError, console: &FastMcpConsole) {
        console.print(&format!("  Error {}: {}", error.code, error.message));
        if let Some(data) = &error.data {
            console.print(&format!(
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
    use fastmcp_protocol::{JsonRpcResponse, RequestId};

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
}
