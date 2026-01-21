//! Error/warning formatting

use rich_rust::prelude::*;
use fastmcp_core::{McpError, McpErrorCode};
use crate::console::FastMcpConsole;
use crate::theme::FastMcpTheme;

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
            self.render_panic(&error.message, None, console); // Reuse render_panic for now if no backtrace in Error
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

    fn render_header(&self, category: ErrorCategory, theme: &FastMcpTheme, console: &FastMcpConsole) {
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
        let rule = Rule::with_title(Text::from(format!("{} {}", icon, label)))
            .style(style);
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

    fn render_suggestions(&self, suggestions: &[String], _theme: &FastMcpTheme, console: &FastMcpConsole) {
        console.print("\n[bold cyan]💡 Suggestions:[/]");
        for (i, suggestion) in suggestions.iter().enumerate() {
            console.print(&format!("  [dim]{}.[/] {}", i + 1, suggestion));
        }
    }

    fn get_suggestions(&self, error: &McpError) -> Option<Vec<String>> {
        match error.code {
            McpErrorCode::MethodNotFound => {
                Some(vec![
                    "Verify the method name is correct".to_string(),
                    "Check that the handler is registered".to_string(),
                    "Run with RUST_LOG=debug for more details".to_string(),
                ])
            },
            McpErrorCode::ParseError => {
                Some(vec![
                    "Validate the JSON structure".to_string(),
                    "Ensure text encoding is UTF-8".to_string(),
                ])
            },
             McpErrorCode::ResourceNotFound => {
                Some(vec![
                    "Verify the resource URI".to_string(),
                    "Check if the resource provider is active".to_string(),
                ])
            },
            _ => None,
        }
    }

    fn render_plain(&self, error: &McpError, console: &FastMcpConsole) {
        console.print_plain(&format!("ERROR [{}]: {}", i32::from(error.code), error.message));
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
            let label_color = theme.label_style.color.as_ref().map(|c| c.triplet.unwrap_or_default().hex()).unwrap_or_default();
            console.print(&format!("\n[{}]Backtrace:[/] инструкция", label_color));

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
                    console.print(&format!("  [{}]{}[/] инструкция", text_color, line));
                }
            }
        }
    }
}

#[derive(Debug, Clone, Copy)]
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
