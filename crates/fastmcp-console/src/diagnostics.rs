//! Error/warning formatting

use crate::console::FastMcpConsole;
use crate::theme::FastMcpTheme;
use fastmcp_core::{McpError, McpErrorCode};
use rich_rust::prelude::*;

/// Renders errors in a beautiful, informative format
pub struct RichErrorRenderer {
    show_suggestions: bool,
    show_backtrace: bool,
    show_error_code: bool,
}

impl Default for RichErrorRenderer {
    fn default() -> Self {
        Self {
            show_suggestions: true,
            show_backtrace: std::env::var("RUST_BACKTRACE").is_ok(),
            show_error_code: true,
        }
    }
}

impl RichErrorRenderer {
    pub fn new() -> Self {
        Self::default()
    }

    /// Render an error with full context
    pub fn render(&self, error: &McpError, console: &FastMcpConsole) {
        if !console.is_rich() {
            self.render_plain(error, console);
            return;
        }

        let theme = console.theme();

        // Error header
        let category = self.categorize_error(error);
        self.render_header(category, theme, console);

        // Main error panel
        self.render_error_panel(error, theme, console);

        // Suggestions
        if self.show_suggestions {
            if let Some(suggestions) = self.get_suggestions(error) {
                self.render_suggestions(&suggestions, theme, console);
            }
        }

        // Context/backtrace
        if self.show_backtrace {
            // Fallback: reuse render_panic when McpError doesn't carry a backtrace.
            self.render_panic(&error.message, None, console);
        }
    }

    fn categorize_error(&self, error: &McpError) -> ErrorCategory {
        match error.code {
            McpErrorCode::ParseError => ErrorCategory::Protocol,
            McpErrorCode::InvalidRequest => ErrorCategory::Protocol,
            McpErrorCode::MethodNotFound => ErrorCategory::Protocol,
            McpErrorCode::InvalidParams => ErrorCategory::Protocol,
            McpErrorCode::InternalError => ErrorCategory::Internal,
            McpErrorCode::ToolExecutionError => ErrorCategory::Handler,
            McpErrorCode::ResourceNotFound => ErrorCategory::Handler,
            McpErrorCode::ResourceForbidden => ErrorCategory::Handler,
            McpErrorCode::PromptNotFound => ErrorCategory::Handler,
            McpErrorCode::RequestCancelled => ErrorCategory::Cancelled,
            McpErrorCode::Custom(_) => ErrorCategory::Unknown,
        }
    }

    fn render_header(
        &self,
        category: ErrorCategory,
        theme: &FastMcpTheme,
        console: &FastMcpConsole,
    ) {
        let (icon, label, style) = match category {
            ErrorCategory::Connection => ("🔌", "Connection Error", theme.error_style.clone()),
            ErrorCategory::Protocol => ("📋", "Protocol Error", theme.error_style.clone()),
            ErrorCategory::Handler => ("⚙️", "Handler Error", theme.warning_style.clone()),
            ErrorCategory::Timeout => ("⏱️", "Timeout", theme.warning_style.clone()),
            ErrorCategory::Cancelled => ("✋", "Cancelled", theme.info_style.clone()),
            ErrorCategory::Internal => ("💥", "Internal Error", theme.error_style.clone()),
            ErrorCategory::Unknown => ("❌", "Error", theme.error_style.clone()),
        };

        // Use Text::from to convert format! string to Text
        let rule = Rule::with_title(Text::from(format!("{} {}", icon, label))).style(style);
        console.render(&rule);
    }

    fn render_error_panel(&self, error: &McpError, theme: &FastMcpTheme, console: &FastMcpConsole) {
        let message = &error.message;
        let code = i32::from(error.code);

        let content = if self.show_error_code {
            format!("[bold]{}[/]\n\n{}", code, message)
        } else {
            message.clone()
        };

        // Add data context if present
        let content = if let Some(data) = &error.data {
            if let Ok(pretty) = serde_json::to_string_pretty(data) {
                format!("{}\n\n[dim]Context:[/]\n{}", content, pretty)
            } else {
                content
            }
        } else {
            content
        };

        let panel = Panel::from_text(&content)
            .style(theme.border_style.clone()) // Use border style for panel
            .padding(1);

        console.render(&panel);
    }

    fn render_suggestions(
        &self,
        suggestions: &[String],
        _theme: &FastMcpTheme,
        console: &FastMcpConsole,
    ) {
        console.print("\n[bold cyan]💡 Suggestions:[/]");
        for (i, suggestion) in suggestions.iter().enumerate() {
            console.print(&format!("  [dim]{}.[/] {}", i + 1, suggestion));
        }
    }

    fn get_suggestions(&self, error: &McpError) -> Option<Vec<String>> {
        match error.code {
            McpErrorCode::MethodNotFound => Some(vec![
                "Verify the method name is correct".to_string(),
                "Check that the handler is registered".to_string(),
                "Run with RUST_LOG=debug for more details".to_string(),
            ]),
            McpErrorCode::ParseError => Some(vec![
                "Validate the JSON structure".to_string(),
                "Ensure text encoding is UTF-8".to_string(),
            ]),
            McpErrorCode::ResourceNotFound => Some(vec![
                "Verify the resource URI".to_string(),
                "Check if the resource provider is active".to_string(),
            ]),
            _ => None,
        }
    }

    fn render_plain(&self, error: &McpError, console: &FastMcpConsole) {
        console.print_plain(&format!(
            "ERROR [{}]: {}",
            i32::from(error.code),
            error.message
        ));
        if let Some(data) = &error.data {
            console.print_plain(&format!("Context: {:?}", data));
        }
    }

    pub fn render_panic(&self, message: &str, backtrace: Option<&str>, console: &FastMcpConsole) {
        let theme = console.theme();
        if !console.is_rich() {
            eprintln!("PANIC: {}", message);
            if let Some(bt) = backtrace {
                eprintln!("Backtrace:\n{}", bt);
            }
            return;
        }

        // Main error panel
        let panel = Panel::from_text(message)
            .title("[bold red]PANIC[/]")
            .border_style(theme.error_style.clone())
            .rounded();

        console.render(&panel);

        // Backtrace if available
        if let Some(bt) = backtrace {
            // Fix hex call
            let label_color = theme
                .label_style
                .color
                .as_ref()
                .map(|c| c.triplet.unwrap_or_default().hex())
                .unwrap_or_default();
            console.print(&format!("\n[{}]Backtrace:[/]", label_color));

            // Syntax-highlight the backtrace (if syntax feature enabled)
            #[cfg(feature = "syntax")]
            {
                let syntax = Syntax::new(bt, "rust")
                    .line_numbers(true)
                    .theme("base16-ocean.dark");
                console.render(&syntax);
            }

            #[cfg(not(feature = "syntax"))]
            {
                for line in bt.lines() {
                    // Fix hex call
                    let text_color = theme.text_dim.triplet.unwrap_or_default().hex();
                    console.print(&format!("  [{}]{}[/]", text_color, line));
                }
            }
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(dead_code)]
enum ErrorCategory {
    Connection,
    Protocol,
    Handler,
    Timeout,
    Cancelled,
    Internal,
    Unknown,
}

/// Render an MCP error with full context (legacy helper)
pub fn render_error(error: &McpError, console: &FastMcpConsole) {
    RichErrorRenderer::default().render(error, console);
}

/// Render a warning
pub fn render_warning(message: &str, console: &FastMcpConsole) {
    if console.is_rich() {
        console.print(&format!(
            "[{}]⚠[/] [{}]Warning:[/] {}",
            console.theme().warning.triplet.unwrap_or_default().hex(),
            console.theme().warning.triplet.unwrap_or_default().hex(),
            message
        ));
    } else {
        eprintln!("[WARN] {}", message);
    }
}

/// Render an info message
pub fn render_info(message: &str, console: &FastMcpConsole) {
    if console.is_rich() {
        console.print(&format!(
            "[{}]ℹ[/] {}",
            console.theme().info.triplet.unwrap_or_default().hex(),
            message
        ));
    } else {
        eprintln!("[INFO] {}", message);
    }
}

/// Format a panic/error with stack trace
pub fn render_panic(message: &str, backtrace: Option<&str>, console: &FastMcpConsole) {
    RichErrorRenderer::default().render_panic(message, backtrace, console);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::TestConsole;

    /// Minimal writer for creating a non-rich (plain) console in tests.
    struct PlainWriter(std::sync::Arc<std::sync::Mutex<Vec<u8>>>);

    impl std::io::Write for PlainWriter {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(buf);
            Ok(buf.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn render_warning_includes_message() {
        let tc = TestConsole::new();
        render_warning("something happened", tc.console());
        assert!(tc.contains("warning"));
        assert!(tc.contains("something happened"));
    }

    #[test]
    fn render_info_includes_message() {
        let tc = TestConsole::new();
        render_info("hello", tc.console());
        assert!(tc.contains("hello"));
    }

    #[test]
    fn rich_error_renderer_renders_error_message() {
        let tc = TestConsole::new();
        let err = McpError::new(McpErrorCode::MethodNotFound, "missing method");
        RichErrorRenderer::default().render(&err, tc.console());
        assert!(tc.contains("missing method"));
    }

    #[test]
    fn categorize_error_maps_codes() {
        let renderer = RichErrorRenderer::default();

        let protocol = McpError::new(McpErrorCode::ParseError, "bad parse");
        assert_eq!(
            renderer.categorize_error(&protocol),
            ErrorCategory::Protocol
        );

        let handler = McpError::new(McpErrorCode::ResourceNotFound, "missing");
        assert_eq!(renderer.categorize_error(&handler), ErrorCategory::Handler);

        let cancelled = McpError::new(McpErrorCode::RequestCancelled, "cancelled");
        assert_eq!(
            renderer.categorize_error(&cancelled),
            ErrorCategory::Cancelled
        );

        let internal = McpError::new(McpErrorCode::InternalError, "boom");
        assert_eq!(
            renderer.categorize_error(&internal),
            ErrorCategory::Internal
        );

        let unknown = McpError::new(McpErrorCode::Custom(42), "custom");
        assert_eq!(renderer.categorize_error(&unknown), ErrorCategory::Unknown);
    }

    #[test]
    fn suggestions_exist_for_selected_codes() {
        let renderer = RichErrorRenderer::default();

        let missing = McpError::new(McpErrorCode::MethodNotFound, "missing");
        let method_suggestions = renderer.get_suggestions(&missing).unwrap_or_default();
        assert!(method_suggestions.len() >= 2);

        let parse = McpError::new(McpErrorCode::ParseError, "parse");
        let parse_suggestions = renderer.get_suggestions(&parse).unwrap_or_default();
        assert!(parse_suggestions.iter().any(|s| s.contains("JSON")));

        let internal = McpError::new(McpErrorCode::InternalError, "internal");
        assert!(renderer.get_suggestions(&internal).is_none());
    }

    #[test]
    fn render_header_renders_all_categories() {
        let tc = TestConsole::new();
        let renderer = RichErrorRenderer::default();
        let theme = tc.console().theme();

        renderer.render_header(ErrorCategory::Connection, theme, tc.console());
        assert!(tc.contains("Connection Error"));
        tc.clear();

        renderer.render_header(ErrorCategory::Timeout, theme, tc.console());
        assert!(tc.contains("Timeout"));
        tc.clear();

        renderer.render_header(ErrorCategory::Cancelled, theme, tc.console());
        assert!(tc.contains("Cancelled"));
    }

    #[test]
    fn render_error_panel_and_suggestions_include_expected_text() {
        let tc = TestConsole::new();
        let renderer = RichErrorRenderer {
            show_suggestions: true,
            show_backtrace: false,
            show_error_code: true,
        };

        let err = McpError::with_data(
            McpErrorCode::MethodNotFound,
            "missing method",
            serde_json::json!({ "method": "tools/missing" }),
        );
        renderer.render_error_panel(&err, tc.console().theme(), tc.console());
        assert!(tc.contains("missing method"));
        assert!(tc.contains("-32601"));
        assert!(tc.contains("tools/missing"));

        tc.clear();
        renderer.render_suggestions(
            &["Check handler registration".to_string()],
            tc.console().theme(),
            tc.console(),
        );
        assert!(tc.contains("Suggestions"));
        assert!(tc.contains("Check handler registration"));
    }

    #[test]
    fn render_respects_show_error_code_flag() {
        let tc = TestConsole::new();
        let with_code = RichErrorRenderer {
            show_suggestions: false,
            show_backtrace: false,
            show_error_code: true,
        };
        let without_code = RichErrorRenderer {
            show_suggestions: false,
            show_backtrace: false,
            show_error_code: false,
        };
        let err = McpError::new(McpErrorCode::InvalidParams, "invalid params");

        with_code.render(&err, tc.console());
        assert!(tc.contains("-32602"));
        tc.clear();

        without_code.render(&err, tc.console());
        assert!(!tc.contains("-32602"));
        assert!(tc.contains("invalid params"));
    }

    #[test]
    fn render_panic_with_backtrace_and_helper_wrapper() {
        let tc = TestConsole::new();
        let renderer = RichErrorRenderer::default();

        renderer.render_panic("panic happened", Some("frame1\nframe2"), tc.console());
        assert!(tc.contains("PANIC"));
        assert!(tc.contains("panic happened"));
        assert!(tc.contains("Backtrace"));
        assert!(tc.contains("frame1"));

        tc.clear();
        render_panic("wrapped panic", Some("trace"), tc.console());
        assert!(tc.contains("wrapped panic"));
    }

    // =========================================================================
    // Additional coverage tests (bd-2z7s)
    // =========================================================================

    #[test]
    fn categorize_error_remaining_protocol_and_handler_codes() {
        let renderer = RichErrorRenderer::new();

        // Protocol codes
        assert_eq!(
            renderer.categorize_error(&McpError::new(McpErrorCode::InvalidRequest, "")),
            ErrorCategory::Protocol
        );
        assert_eq!(
            renderer.categorize_error(&McpError::new(McpErrorCode::MethodNotFound, "")),
            ErrorCategory::Protocol
        );
        assert_eq!(
            renderer.categorize_error(&McpError::new(McpErrorCode::InvalidParams, "")),
            ErrorCategory::Protocol
        );

        // Handler codes
        assert_eq!(
            renderer.categorize_error(&McpError::new(McpErrorCode::ToolExecutionError, "")),
            ErrorCategory::Handler
        );
        assert_eq!(
            renderer.categorize_error(&McpError::new(McpErrorCode::ResourceForbidden, "")),
            ErrorCategory::Handler
        );
        assert_eq!(
            renderer.categorize_error(&McpError::new(McpErrorCode::PromptNotFound, "")),
            ErrorCategory::Handler
        );
    }

    #[test]
    fn render_header_remaining_categories() {
        let tc = TestConsole::new();
        let renderer = RichErrorRenderer::new();
        let theme = tc.console().theme();

        renderer.render_header(ErrorCategory::Protocol, theme, tc.console());
        assert!(tc.contains("Protocol Error"));
        tc.clear();

        renderer.render_header(ErrorCategory::Handler, theme, tc.console());
        assert!(tc.contains("Handler Error"));
        tc.clear();

        renderer.render_header(ErrorCategory::Internal, theme, tc.console());
        assert!(tc.contains("Internal Error"));
        tc.clear();

        renderer.render_header(ErrorCategory::Unknown, theme, tc.console());
        assert!(tc.contains("Error"));
    }

    #[test]
    fn get_suggestions_resource_not_found() {
        let renderer = RichErrorRenderer::new();
        let err = McpError::new(McpErrorCode::ResourceNotFound, "missing");
        let suggestions = renderer.get_suggestions(&err).unwrap();
        assert!(suggestions.iter().any(|s| s.contains("URI")));
    }

    #[test]
    fn render_plain_error_without_data() {
        let buf = std::sync::Arc::new(std::sync::Mutex::new(Vec::<u8>::new()));
        let console = FastMcpConsole::with_writer(PlainWriter(buf.clone()), false);
        let err = McpError::new(McpErrorCode::InternalError, "something broke");
        RichErrorRenderer::new().render(&err, &console);
        let output = String::from_utf8(buf.lock().unwrap().clone()).unwrap();
        assert!(output.contains("ERROR"));
        assert!(output.contains("something broke"));
    }

    #[test]
    fn render_plain_error_with_data() {
        let buf = std::sync::Arc::new(std::sync::Mutex::new(Vec::<u8>::new()));
        let console = FastMcpConsole::with_writer(PlainWriter(buf.clone()), false);
        let err = McpError::with_data(
            McpErrorCode::InvalidParams,
            "bad params",
            serde_json::json!({"field": "name"}),
        );
        RichErrorRenderer::new().render(&err, &console);
        let output = String::from_utf8(buf.lock().unwrap().clone()).unwrap();
        assert!(output.contains("bad params"));
        assert!(output.contains("Context"));
    }

    #[test]
    fn render_panic_without_backtrace() {
        let tc = TestConsole::new();
        let renderer = RichErrorRenderer::new();
        renderer.render_panic("oops", None, tc.console());
        assert!(tc.contains("PANIC"));
        assert!(tc.contains("oops"));
        assert!(!tc.contains("Backtrace"));
    }

    #[test]
    fn render_warning_and_info_plain_mode() {
        // Warning and info in plain mode write to stderr via eprintln!, which
        // we cannot capture through the writer. We just verify the non-rich
        // branch doesn't panic by constructing a non-rich console.
        let buf = std::sync::Arc::new(std::sync::Mutex::new(Vec::<u8>::new()));
        let console = FastMcpConsole::with_writer(PlainWriter(buf.clone()), false);
        assert!(!console.is_rich());
        render_warning("disk full", &console);
        render_info("started", &console);
        // No panic = success; output goes to stderr, not our buffer
    }

    #[test]
    fn error_category_debug_clone_copy() {
        let cat = ErrorCategory::Protocol;
        let debug = format!("{cat:?}");
        assert!(debug.contains("Protocol"));

        let cloned = cat;
        assert_eq!(cloned, ErrorCategory::Protocol);
    }

    #[test]
    fn render_error_panel_without_data() {
        let tc = TestConsole::new();
        let renderer = RichErrorRenderer {
            show_suggestions: false,
            show_backtrace: false,
            show_error_code: true,
        };
        let err = McpError::new(McpErrorCode::ParseError, "bad json");
        renderer.render_error_panel(&err, tc.console().theme(), tc.console());
        assert!(tc.contains("bad json"));
        assert!(tc.contains("-32700"));
    }

    #[test]
    fn render_error_helper_function() {
        let tc = TestConsole::new();
        let err = McpError::new(McpErrorCode::InternalError, "boom");
        render_error(&err, tc.console());
        assert!(tc.contains("boom"));
    }
}
