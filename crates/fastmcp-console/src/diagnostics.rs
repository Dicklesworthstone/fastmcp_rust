//! Error/warning formatting

use std::collections::HashSet;

use crate::config::ConsoleConfig;
use crate::console::{
    DEFAULT_LOG_MESSAGE_MAX_CHARS, FastMcpConsole, REDACTED_VALUE, bounded_redacted_rich_fragment,
    bounded_redacted_rich_text, bounded_redacted_terminal_text, is_credential_key,
    redact_free_text_credentials,
};
use crate::theme::FastMcpTheme;
use fastmcp_core::{McpError, McpErrorCode};
use rich_rust::markup;
use rich_rust::prelude::*;
use serde_json::Value;

const ERROR_DATA_MAX_DEPTH: usize = 24;
const ERROR_DATA_MAX_NODES: usize = 1_024;
const ERROR_DATA_MAX_SOURCE_BYTES: usize = 16 * 1_024;
const ERROR_DATA_MAX_DISPLAY_CHARS: usize = 2_048;
const BACKTRACE_MAX_CHARS: usize = 4_096;
const ERROR_DATA_OMITTED: &str = "<error data omitted: diagnostic budget exceeded>";
const ERROR_DATA_SERIALIZATION_FAILED: &str = "<error data omitted: serialization failed>";

fn error_data_preview(data: &Value, rich: bool) -> String {
    if !error_data_is_within_budget(data) {
        return ERROR_DATA_OMITTED.to_owned();
    }

    let redacted = redact_error_data_prevalidated(data);
    let serialized = serde_json::to_string(&redacted)
        .unwrap_or_else(|_| ERROR_DATA_SERIALIZATION_FAILED.to_owned());
    if rich {
        bounded_redacted_rich_text(&serialized, ERROR_DATA_MAX_DISPLAY_CHARS)
    } else {
        bounded_redacted_terminal_text(&serialized, ERROR_DATA_MAX_DISPLAY_CHARS)
    }
}

fn error_data_is_within_budget(data: &Value) -> bool {
    let mut remaining_bytes = ERROR_DATA_MAX_SOURCE_BYTES;
    let mut scheduled_nodes = 1usize;
    let mut stack = vec![(data, 0usize)];

    while let Some((value, depth)) = stack.pop() {
        if depth > ERROR_DATA_MAX_DEPTH || !charge_error_data_bytes(&mut remaining_bytes, 1) {
            return false;
        }

        match value {
            Value::Null => {
                if !charge_error_data_bytes(&mut remaining_bytes, 4) {
                    return false;
                }
            }
            Value::Bool(_) => {
                if !charge_error_data_bytes(&mut remaining_bytes, 5) {
                    return false;
                }
            }
            Value::Number(number) => {
                if !charge_error_data_bytes(&mut remaining_bytes, number.as_str().len()) {
                    return false;
                }
            }
            Value::String(string) => {
                if !charge_error_data_bytes(&mut remaining_bytes, string.len()) {
                    return false;
                }
            }
            Value::Array(values) => {
                if !schedule_error_data_children(
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
                    if !charge_error_data_bytes(&mut remaining_bytes, key.len()) {
                        return false;
                    }
                }
                if !schedule_error_data_children(
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

fn schedule_error_data_children<'a>(
    stack: &mut Vec<(&'a Value, usize)>,
    scheduled_nodes: &mut usize,
    children: impl ExactSizeIterator<Item = &'a Value>,
    parent_depth: usize,
) -> bool {
    let child_count = children.len();
    let Some(total_nodes) = scheduled_nodes.checked_add(child_count) else {
        return false;
    };
    let Some(child_depth) = parent_depth.checked_add(1) else {
        return false;
    };
    if total_nodes > ERROR_DATA_MAX_NODES || stack.try_reserve(child_count).is_err() {
        return false;
    }

    *scheduled_nodes = total_nodes;
    stack.extend(children.map(|child| (child, child_depth)));
    true
}

fn charge_error_data_bytes(remaining: &mut usize, amount: usize) -> bool {
    let Some(after) = remaining.checked_sub(amount) else {
        return false;
    };
    *remaining = after;
    true
}

fn redact_error_data_prevalidated(value: &Value) -> Value {
    match value {
        Value::Object(object) => {
            let mut used_display_keys = HashSet::new();
            Value::Object(
                object
                    .iter()
                    .map(|(key, value)| {
                        let value = if is_credential_key(key) {
                            Value::String(REDACTED_VALUE.to_owned())
                        } else {
                            redact_error_data_prevalidated(value)
                        };
                        let key = collision_safe_display_key(
                            redact_free_text_credentials(key),
                            &mut used_display_keys,
                        );
                        (key, value)
                    })
                    .collect(),
            )
        }
        Value::Array(values) => {
            Value::Array(values.iter().map(redact_error_data_prevalidated).collect())
        }
        Value::String(string) => Value::String(redact_free_text_credentials(string)),
        _ => value.clone(),
    }
}

fn collision_safe_display_key(base: String, used: &mut HashSet<String>) -> String {
    if used.insert(base.clone()) {
        return base;
    }

    // Error-data objects are preflight-limited, so this deterministic suffix
    // search is bounded while preserving every member whose display key
    // collides after credential redaction.
    for suffix in 2..=ERROR_DATA_MAX_NODES {
        let candidate = format!("{base}#{suffix}");
        if used.insert(candidate.clone()) {
            return candidate;
        }
    }

    // This requires more colliding keys than the preflight currently admits.
    // Still guarantee uniqueness if those limits are ever changed separately.
    let mut candidate = format!("{base}#overflow");
    while !used.insert(candidate.clone()) {
        candidate.push('#');
    }
    candidate
}

/// Renders errors in a beautiful, informative format
pub struct RichErrorRenderer {
    show_suggestions: bool,
    show_error_code: bool,
    show_backtrace: bool,
}

impl Default for RichErrorRenderer {
    fn default() -> Self {
        Self {
            show_suggestions: true,
            show_error_code: true,
            // Supplying a backtrace through the direct API is an explicit
            // request. `from_config` applies the centralized policy instead.
            show_backtrace: true,
        }
    }
}

impl RichErrorRenderer {
    pub fn new() -> Self {
        Self::default()
    }

    /// Create a renderer from centralized console configuration.
    #[must_use]
    pub fn from_config(config: &ConsoleConfig) -> Self {
        Self {
            show_suggestions: config.show_suggestions,
            show_error_code: config.show_error_codes,
            show_backtrace: config.show_backtrace,
        }
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
        let message = bounded_redacted_rich_text(&error.message, DEFAULT_LOG_MESSAGE_MAX_CHARS);
        let code = i32::from(error.code);

        let content = if self.show_error_code {
            format!("[bold]{}[/]\n\n{}", code, message)
        } else {
            message
        };

        // Add data context if present
        let content = if let Some(data) = &error.data {
            let preview = error_data_preview(data, true);
            format!("{}\n\n[dim]Context:[/]\n{}", content, preview)
        } else {
            content
        };

        // `Panel::from_text` deliberately treats markup as literal. Parse the
        // trusted framing tags once; all peer-controlled fragments were
        // parity-safe escaped before interpolation above.
        let text = markup::render_or_plain(&content);
        // Panels never wrap: overlong lines are truncated at the content
        // width, which can clip redacted context. Fold to the inner width
        // (borders plus the 1-cell padding on each side) before framing.
        let content_width = console.width().saturating_sub(4).max(1);
        let wrapped = Text::new("\n").join(&text.wrap(content_width));
        let panel = Panel::from_rich_text(&wrapped, console.width())
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
        let message = bounded_redacted_terminal_text(&error.message, DEFAULT_LOG_MESSAGE_MAX_CHARS);
        if self.show_error_code {
            console.print_plain(&format!("ERROR [{}]: {}", i32::from(error.code), message));
        } else {
            console.print_plain(&format!("ERROR: {message}"));
        }
        if let Some(data) = &error.data {
            console.print_plain(&format!("Context: {}", error_data_preview(data, false)));
        }
        if self.show_suggestions {
            if let Some(suggestions) = self.get_suggestions(error) {
                console.print_plain("Suggestions:");
                for (index, suggestion) in suggestions.iter().enumerate() {
                    console.print_plain(&format!("  {}. {suggestion}", index + 1));
                }
            }
        }
    }

    pub fn render_panic(&self, message: &str, backtrace: Option<&str>, console: &FastMcpConsole) {
        let theme = console.theme();
        if !console.is_rich() {
            let message = bounded_redacted_terminal_text(message, DEFAULT_LOG_MESSAGE_MAX_CHARS);
            console.print_plain(&format!("PANIC: {message}"));
            if self.show_backtrace
                && let Some(bt) = backtrace
            {
                let backtrace = bounded_redacted_terminal_text(bt, BACKTRACE_MAX_CHARS);
                console.print_plain(&format!("Backtrace: {backtrace}"));
            }
            return;
        }

        // Panel text is not markup-aware, so retain literal brackets without
        // inserting rich escape backslashes into the visible output.
        let message = bounded_redacted_terminal_text(message, DEFAULT_LOG_MESSAGE_MAX_CHARS);

        // Main error panel
        let panel = Panel::from_text(message.as_str())
            .title_from_markup("[bold red]PANIC[/]")
            .border_style(theme.error_style.clone())
            .rounded();

        console.render(&panel);

        // Backtrace if available
        if self.show_backtrace
            && let Some(bt) = backtrace
        {
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
                let backtrace = bounded_redacted_terminal_text(bt, BACKTRACE_MAX_CHARS);
                let syntax = Syntax::new(&backtrace, "rust")
                    .line_numbers(true)
                    .theme("base16-ocean.dark");
                console.render(&syntax);
            }

            #[cfg(not(feature = "syntax"))]
            {
                let backtrace = bounded_redacted_rich_fragment(bt, BACKTRACE_MAX_CHARS);
                // Fix hex call
                let text_color = theme.text_dim.triplet.unwrap_or_default().hex();
                console.print(&format!("  [{}]{}[/]", text_color, backtrace));
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
        let message = bounded_redacted_rich_text(message, DEFAULT_LOG_MESSAGE_MAX_CHARS);
        console.print(&format!(
            "[{}]⚠[/] [{}]Warning:[/] {}",
            console.theme().warning.triplet.unwrap_or_default().hex(),
            console.theme().warning.triplet.unwrap_or_default().hex(),
            message
        ));
    } else {
        let message = bounded_redacted_terminal_text(message, DEFAULT_LOG_MESSAGE_MAX_CHARS);
        console.print_plain(&format!("[WARN] {message}"));
    }
}

/// Render an info message
pub fn render_info(message: &str, console: &FastMcpConsole) {
    if console.is_rich() {
        let message = bounded_redacted_rich_text(message, DEFAULT_LOG_MESSAGE_MAX_CHARS);
        console.print(&format!(
            "[{}]ℹ[/] {}",
            console.theme().info.triplet.unwrap_or_default().hex(),
            message
        ));
    } else {
        let message = bounded_redacted_terminal_text(message, DEFAULT_LOG_MESSAGE_MAX_CHARS);
        console.print_plain(&format!("[INFO] {message}"));
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
        // The rich path labels "Warning:" and the plain path "[WARN]";
        // assert the semantic marker case-insensitively.
        assert!(tc.output_string().to_lowercase().contains("warn"));
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
        let tc = TestConsole::new_rich();
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
        let tc = TestConsole::new_rich();
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
        let tc = TestConsole::new_rich();
        let renderer = RichErrorRenderer {
            show_suggestions: true,
            show_error_code: true,
            show_backtrace: true,
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
        let tc = TestConsole::new_rich();
        let with_code = RichErrorRenderer {
            show_suggestions: false,
            show_error_code: true,
            show_backtrace: true,
        };
        let without_code = RichErrorRenderer {
            show_suggestions: false,
            show_error_code: false,
            show_backtrace: true,
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
    fn renderer_from_config_honors_diagnostic_and_backtrace_controls() {
        let mut config = ConsoleConfig::new().without_suggestions();
        config.show_error_codes = false;
        config.show_backtrace = false;
        let renderer = RichErrorRenderer::from_config(&config);

        assert!(!renderer.show_suggestions);
        assert!(!renderer.show_error_code);
        assert!(!renderer.show_backtrace);

        let output = std::sync::Arc::new(std::sync::Mutex::new(Vec::<u8>::new()));
        let console = FastMcpConsole::with_writer(PlainWriter(output.clone()), false);
        let error = McpError::new(McpErrorCode::MethodNotFound, "missing method");
        renderer.render(&error, &console);
        renderer.render_panic("panic", Some("hidden frame"), &console);
        let output = String::from_utf8(output.lock().unwrap().clone()).unwrap();
        assert!(output.contains("ERROR: missing method"), "{output}");
        assert!(!output.contains("-32601"), "{output}");
        assert!(!output.contains("Suggestions"), "{output}");
        assert!(!output.contains("hidden frame"), "{output}");

        config.show_backtrace = true;
        let renderer = RichErrorRenderer::from_config(&config);
        let output = std::sync::Arc::new(std::sync::Mutex::new(Vec::<u8>::new()));
        let console = FastMcpConsole::with_writer(PlainWriter(output.clone()), false);
        renderer.render_panic("panic", Some("visible frame"), &console);
        let output = String::from_utf8(output.lock().unwrap().clone()).unwrap();
        assert!(output.contains("visible frame"), "{output}");
    }

    #[test]
    fn render_panic_with_backtrace_and_helper_wrapper() {
        let tc = TestConsole::new_rich();
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
        let tc = TestConsole::new_rich();
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
    fn render_plain_respects_code_and_suggestion_flags() {
        let error = McpError::new(McpErrorCode::MethodNotFound, "missing method");

        let without_extras = std::sync::Arc::new(std::sync::Mutex::new(Vec::<u8>::new()));
        let console = FastMcpConsole::with_writer(PlainWriter(without_extras.clone()), false);
        RichErrorRenderer {
            show_suggestions: false,
            show_error_code: false,
            show_backtrace: true,
        }
        .render(&error, &console);
        let output = String::from_utf8(
            without_extras
                .lock()
                .expect("plain diagnostic output lock poisoned")
                .clone(),
        )
        .expect("plain diagnostic output must be UTF-8");
        assert!(output.contains("ERROR: missing method"), "{output}");
        assert!(!output.contains("-32601"), "{output}");
        assert!(!output.contains("Suggestions"), "{output}");
        assert!(!output.contains("PANIC"), "{output}");

        let with_extras = std::sync::Arc::new(std::sync::Mutex::new(Vec::<u8>::new()));
        let console = FastMcpConsole::with_writer(PlainWriter(with_extras.clone()), false);
        RichErrorRenderer {
            show_suggestions: true,
            show_error_code: true,
            show_backtrace: true,
        }
        .render(&error, &console);
        let output = String::from_utf8(
            with_extras
                .lock()
                .expect("plain diagnostic output lock poisoned")
                .clone(),
        )
        .expect("plain diagnostic output must be UTF-8");
        assert!(
            output.contains("ERROR [-32601]: missing method"),
            "{output}"
        );
        assert!(output.contains("Suggestions:"), "{output}");
        assert!(output.contains("Verify the method name"), "{output}");
    }

    #[test]
    fn render_panic_without_backtrace() {
        let tc = TestConsole::new_rich();
        let renderer = RichErrorRenderer::new();
        renderer.render_panic("oops", None, tc.console());
        assert!(tc.contains("PANIC"));
        assert!(tc.contains("oops"));
        assert!(!tc.contains("Backtrace"));
    }

    #[test]
    fn render_warning_and_info_plain_mode() {
        let buf = std::sync::Arc::new(std::sync::Mutex::new(Vec::<u8>::new()));
        let console = FastMcpConsole::with_writer(PlainWriter(buf.clone()), false);
        assert!(!console.is_rich());
        render_warning("disk full", &console);
        render_info("started", &console);
        let output = String::from_utf8(buf.lock().unwrap().clone()).unwrap();
        assert!(output.contains("[WARN] disk full"));
        assert!(output.contains("[INFO] started"));
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
        let tc = TestConsole::new_rich();
        let renderer = RichErrorRenderer {
            show_suggestions: false,
            show_error_code: true,
            show_backtrace: true,
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

    #[test]
    fn error_data_preflight_rejects_deep_wide_and_oversized_values() {
        let mut too_deep = serde_json::json!("leaf");
        for _ in 0..=ERROR_DATA_MAX_DEPTH {
            too_deep = serde_json::json!({"nested": too_deep});
        }
        assert!(!error_data_is_within_budget(&too_deep));

        let too_wide = Value::Array((0..ERROR_DATA_MAX_NODES).map(|_| Value::Null).collect());
        assert!(!error_data_is_within_budget(&too_wide));

        let too_large = Value::String("x".repeat(ERROR_DATA_MAX_SOURCE_BYTES + 1));
        assert!(!error_data_is_within_budget(&too_large));
        assert!(error_data_is_within_budget(&serde_json::json!({
            "ordinary": [1, 2, 3]
        })));
    }

    #[test]
    fn redacted_error_data_preserves_members_with_colliding_display_keys() {
        let data = serde_json::json!({
            "https://alice:first-secret@example.test": "first value",
            "https://alice:second-secret@example.test": "second value"
        });
        let redacted = redact_error_data_prevalidated(&data);
        let object = redacted.as_object().expect("redacted object");

        assert_eq!(object.len(), 2);
        assert!(object.keys().any(|key| key.ends_with("#2")), "{object:?}");
        assert!(
            object
                .values()
                .any(|value| value.as_str() == Some("first value"))
        );
        assert!(
            object
                .values()
                .any(|value| value.as_str() == Some("second value"))
        );
        for key in object.keys() {
            assert!(!key.contains("first-secret"), "{key}");
            assert!(!key.contains("second-secret"), "{key}");
        }

        let preview = error_data_preview(&data, false);
        assert!(preview.contains("first value"), "{preview}");
        assert!(preview.contains("second value"), "{preview}");
        assert!(!preview.contains("first-secret"), "{preview}");
        assert!(!preview.contains("second-secret"), "{preview}");
    }

    #[test]
    fn rich_error_output_redacts_credentials_and_escapes_hostile_text() {
        let tc = TestConsole::new_rich();
        let renderer = RichErrorRenderer {
            show_suggestions: false,
            show_error_code: true,
            show_backtrace: true,
        };
        let error = McpError::with_data(
            McpErrorCode::InternalError,
            "failure [bold red]owned[/] Authorization: Bearer message-secret-canary \u{1b}\u{202e}",
            serde_json::json!({
                "client_secret": "structured-secret-canary",
                "ordinary": "still useful",
                "nested": {"detail": "password=free-text-secret-canary"}
            }),
        );

        renderer.render(&error, tc.console());
        let output = tc.output_string();
        assert!(output.contains("[bold red]owned[/]"), "{output}");
        assert!(output.contains("still useful"), "{output}");
        assert!(output.contains("[REDACTED]"), "{output}");
        for secret in [
            "message-secret-canary",
            "structured-secret-canary",
            "free-text-secret-canary",
        ] {
            assert!(!output.contains(secret), "leaked {secret}: {output}");
        }
        assert!(!output.contains('\u{202e}'), "{output}");
    }

    #[test]
    fn plain_error_output_is_bounded_redacted_and_terminal_safe() {
        let buf = std::sync::Arc::new(std::sync::Mutex::new(Vec::<u8>::new()));
        let console = FastMcpConsole::with_writer(PlainWriter(buf.clone()), false);
        let renderer = RichErrorRenderer {
            show_suggestions: false,
            show_error_code: true,
            show_backtrace: true,
        };
        let message = format!(
            "\u{1b}\u{202e} Authorization: Bearer plain-message-secret {}",
            "x".repeat(20_000)
        );
        let error = McpError::with_data(
            McpErrorCode::InternalError,
            message,
            serde_json::json!({
                "access_token": "plain-data-secret",
                "ordinary": "visible"
            }),
        );

        renderer.render(&error, &console);
        let output = String::from_utf8(buf.lock().unwrap().clone()).unwrap();
        assert!(output.contains("visible"), "{output}");
        assert!(output.contains(REDACTED_VALUE), "{output}");
        assert!(!output.contains("plain-message-secret"), "{output}");
        assert!(!output.contains("plain-data-secret"), "{output}");
        assert!(!output.contains('\u{1b}'), "{output}");
        assert!(!output.contains('\u{202e}'), "{output}");
        assert!(output.contains("\\u{1b}"), "{output}");
        assert!(output.chars().count() <= 4_200, "output was unbounded");
    }

    #[test]
    fn over_budget_error_data_is_omitted_before_serialization() {
        let buf = std::sync::Arc::new(std::sync::Mutex::new(Vec::<u8>::new()));
        let console = FastMcpConsole::with_writer(PlainWriter(buf.clone()), false);
        let renderer = RichErrorRenderer {
            show_suggestions: false,
            show_error_code: true,
            show_backtrace: true,
        };
        let secret = "oversized-data-secret-canary";
        let error = McpError::with_data(
            McpErrorCode::InternalError,
            "bounded message",
            serde_json::json!({"ordinary": format!("{secret}{}", "x".repeat(20_000))}),
        );

        renderer.render(&error, &console);
        let output = String::from_utf8(buf.lock().unwrap().clone()).unwrap();
        assert!(output.contains(ERROR_DATA_OMITTED), "{output}");
        assert!(!output.contains(secret), "{output}");
    }

    #[test]
    fn panic_output_redacts_and_bounds_message_and_backtrace() {
        let buf = std::sync::Arc::new(std::sync::Mutex::new(Vec::<u8>::new()));
        let console = FastMcpConsole::with_writer(PlainWriter(buf.clone()), false);
        let message = format!("password=panic-message-secret \u{1b}{}", "m".repeat(20_000));
        let backtrace = format!(
            "Authorization: Bearer backtrace-secret \u{202e}{}",
            "b".repeat(20_000)
        );

        RichErrorRenderer::new().render_panic(&message, Some(&backtrace), &console);
        let output = String::from_utf8(buf.lock().unwrap().clone()).unwrap();
        assert!(!output.contains("panic-message-secret"), "{output}");
        assert!(!output.contains("backtrace-secret"), "{output}");
        assert!(!output.contains('\u{1b}'), "{output}");
        assert!(!output.contains('\u{202e}'), "{output}");
        assert!(output.contains(REDACTED_VALUE), "{output}");
        assert!(output.chars().count() <= 6_200, "output was unbounded");
    }

    #[test]
    fn warning_and_info_redact_hostile_peer_text_in_both_modes() {
        let message = "[bold red]owned[/] token=diagnostic-secret \u{1b}\u{202e} ordinary detail";

        let rich = TestConsole::new_rich();
        render_warning(message, rich.console());
        render_info(message, rich.console());
        let rich_output = rich.output_string();
        assert!(rich_output.contains("[bold red]owned[/]"), "{rich_output}");
        assert!(rich_output.contains("ordinary detail"), "{rich_output}");
        assert!(!rich_output.contains("diagnostic-secret"), "{rich_output}");
        assert!(!rich_output.contains('\u{202e}'), "{rich_output}");

        let buf = std::sync::Arc::new(std::sync::Mutex::new(Vec::<u8>::new()));
        let plain = FastMcpConsole::with_writer(PlainWriter(buf.clone()), false);
        render_warning(message, &plain);
        render_info(message, &plain);
        let plain_output = String::from_utf8(buf.lock().unwrap().clone()).unwrap();
        assert!(plain_output.contains("ordinary detail"), "{plain_output}");
        assert!(
            !plain_output.contains("diagnostic-secret"),
            "{plain_output}"
        );
        assert!(!plain_output.contains('\u{1b}'), "{plain_output}");
        assert!(!plain_output.contains('\u{202e}'), "{plain_output}");
    }
}
