//! Console wrapper for rich stderr output.
//!
//! `FastMcpConsole` is the core output surface for fastmcp-console. It wraps
//! a `rich_rust::Console` configured to write to stderr, and it automatically
//! falls back to plain text when running in agent contexts.
//!
//! # Quick Example
//!
//! ```rust,ignore
//! use fastmcp_console::console::FastMcpConsole;
//!
//! let console = FastMcpConsole::new();
//! console.rule(Some("FastMCP Console"));
//! console.print("Ready.");
//! ```

use crate::theme::FastMcpTheme;
use rich_rust::prelude::*;
use rich_rust::renderables::Renderable;
use std::io::{self, Write};
use std::sync::{Mutex, OnceLock};

/// FastMCP console for rich output to stderr.
///
/// This type centralizes rich-vs-plain output behavior and exposes
/// convenience methods for printing tables, panels, and styled text.
///
/// # Example
///
/// ```rust,ignore
/// use fastmcp_console::console::FastMcpConsole;
/// use rich_rust::prelude::Style;
///
/// let console = FastMcpConsole::new();
/// console.print_styled("Server started", Style::new().bold());
/// ```
pub struct FastMcpConsole {
    inner: Mutex<Console>,
    enabled: bool,
    theme: &'static FastMcpTheme,
}

impl FastMcpConsole {
    /// Create with automatic detection
    #[must_use]
    pub fn new() -> Self {
        let enabled = crate::detection::should_enable_rich();
        Self::with_enabled(enabled)
    }

    /// Create with explicit enable/disable
    #[must_use]
    pub fn with_enabled(enabled: bool) -> Self {
        let inner = if enabled {
            Console::builder()
                .file(Box::new(io::stderr()))
                .force_terminal(true)
                .markup(true)
                .emoji(true)
                .build()
        } else {
            Console::builder()
                .file(Box::new(io::stderr()))
                .no_color()
                .markup(false)
                .emoji(false)
                .build()
        };

        Self {
            inner: Mutex::new(inner),
            enabled,
            theme: crate::theme::theme(),
        }
    }

    /// Create with custom writer (for testing)
    #[must_use]
    pub fn with_writer<W: Write + Send + 'static>(writer: W, enabled: bool) -> Self {
        let mut builder = Console::builder()
            .file(Box::new(writer))
            .markup(enabled)
            .emoji(enabled);

        if !enabled {
            builder = builder.no_color();
        }

        let inner = if enabled {
            builder.force_terminal(true).build()
        } else {
            builder.build()
        };

        Self {
            inner: Mutex::new(inner),
            enabled,
            theme: crate::theme::theme(),
        }
    }

    // ─────────────────────────────────────────────────
    // State Queries
    // ─────────────────────────────────────────────────

    /// Check if rich output is enabled.
    pub fn is_rich(&self) -> bool {
        self.enabled
    }

    /// Get the theme used for standard styling.
    pub fn theme(&self) -> &FastMcpTheme {
        self.theme
    }

    /// Get terminal width (or default 80).
    pub fn width(&self) -> usize {
        if let Ok(c) = self.inner.lock() {
            c.width()
        } else {
            80
        }
    }

    /// Get terminal height (or default 24).
    pub fn height(&self) -> usize {
        if let Ok(c) = self.inner.lock() {
            c.height()
        } else {
            24
        }
    }

    // ─────────────────────────────────────────────────
    // Output Methods
    // ─────────────────────────────────────────────────

    /// Print styled text (auto-detects markup).
    pub fn print(&self, content: &str) {
        if self.enabled {
            if let Ok(console) = self.inner.lock() {
                console.print(content);
            }
        } else {
            eprintln!("{}", strip_markup(content));
        }
    }

    /// Print plain text (no markup processing ever).
    pub fn print_plain(&self, text: &str) {
        if let Ok(console) = self.inner.lock() {
            // Escape brackets with backslash (rich markup escape sequence)
            // to prevent markup interpretation, then print through the console's
            // configured writer
            let escaped = text.replace('[', "\\[").replace(']', "\\]");
            console.print(&escaped);
        } else {
            eprintln!("{text}");
        }
    }

    /// Print a renderable.
    pub fn render<R: Renderable>(&self, renderable: &R) {
        if self.enabled {
            if let Ok(console) = self.inner.lock() {
                console.print_renderable(renderable);
            }
        } else {
            // Plain fallback: caller should provide alternative or we log a placeholder
            eprintln!("[Complex Output]");
        }
    }

    /// Print a renderable with plain-text fallback closure.
    pub fn render_or<F>(&self, render_op: F, plain_fallback: &str)
    where
        F: FnOnce(&Console),
    {
        if self.enabled {
            if let Ok(console) = self.inner.lock() {
                render_op(&console);
            }
        } else {
            eprintln!("{plain_fallback}");
        }
    }

    // ─────────────────────────────────────────────────
    // Convenience Methods
    // ─────────────────────────────────────────────────

    /// Print a horizontal rule.
    pub fn rule(&self, title: Option<&str>) {
        if self.enabled {
            if let Ok(console) = self.inner.lock() {
                match title {
                    Some(t) => console.print_renderable(
                        &Rule::with_title(t).style(self.theme.border_style.clone()),
                    ),
                    None => console
                        .print_renderable(&Rule::new().style(self.theme.border_style.clone())),
                }
            }
        } else {
            match title {
                Some(t) => eprintln!("--- {t} ---"),
                None => eprintln!("---"),
            }
        }
    }

    /// Print a blank line.
    pub fn newline(&self) {
        eprintln!();
    }

    /// Print styled text with a specific style.
    pub fn print_styled(&self, text: &str, style: Style) {
        if self.enabled {
            if let Ok(console) = self.inner.lock() {
                console.print_styled(text, style);
            }
        } else {
            eprintln!("{text}");
        }
    }

    /// Print a table (with plain fallback).
    pub fn print_table(&self, table: &Table, plain_fallback: &str) {
        if self.enabled {
            if let Ok(console) = self.inner.lock() {
                console.print_renderable(table);
            }
        } else {
            eprintln!("{plain_fallback}");
        }
    }

    /// Print a panel (with plain fallback).
    pub fn print_panel(&self, panel: &Panel, plain_fallback: &str) {
        if self.enabled {
            if let Ok(console) = self.inner.lock() {
                console.print_renderable(panel);
            }
        } else {
            eprintln!("{plain_fallback}");
        }
    }
}

impl Default for FastMcpConsole {
    fn default() -> Self {
        Self::new()
    }
}

// ─────────────────────────────────────────────────────────
// Global Console Accessor
// ─────────────────────────────────────────────────────────

static CONSOLE: OnceLock<FastMcpConsole> = OnceLock::new();

/// Get the global FastMCP console instance.
///
/// # Example
///
/// ```rust,ignore
/// let console = fastmcp_console::console::console();
/// console.print("Hello from global console");
/// ```
#[must_use]
pub fn console() -> &'static FastMcpConsole {
    CONSOLE.get_or_init(FastMcpConsole::new)
}

/// Initialize the global console with specific settings.
///
/// Must be called before any output; returns error if already initialized.
///
/// # Example
///
/// ```rust,ignore
/// use fastmcp_console::console::init_console;
///
/// init_console(false).expect("console already initialized");
/// ```
pub fn init_console(enabled: bool) -> Result<(), &'static str> {
    CONSOLE
        .set(FastMcpConsole::with_enabled(enabled))
        .map_err(|_| "Console already initialized")
}

// ─────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────

/// Strip markup tags from text (for plain output).
///
/// Handles escaped brackets (`[[` -> `[`) and strips valid tags (`[...]`).
#[must_use]
pub fn strip_markup(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut chars = text.chars().peekable();

    while let Some(ch) = chars.next() {
        match ch {
            '[' => {
                // Check for escaped bracket [[
                if let Some('[') = chars.peek() {
                    out.push('[');
                    chars.next(); // Consume the second [
                } else {
                    // It's a tag start, skip until ]
                    // Note: This is a simple skippper; it doesn't handle nested brackets
                    // or quoted strings inside tags, but covers standard style tags.
                    for c in chars.by_ref() {
                        if c == ']' {
                            break;
                        }
                    }
                }
            }
            _ => out.push(ch),
        }
    }

    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_strip_markup_simple() {
        assert_eq!(strip_markup("[bold]Hello[/]"), "Hello");
    }

    #[test]
    fn test_strip_markup_nested() {
        assert_eq!(strip_markup("[bold][red]Error[/][/]"), "Error");
    }

    #[test]
    fn test_strip_markup_multiple_tags() {
        assert_eq!(
            strip_markup("[green]✓[/] Success [dim](100ms)[/]"),
            "✓ Success (100ms)"
        );
    }

    #[test]
    fn test_strip_markup_no_tags() {
        assert_eq!(strip_markup("Plain text"), "Plain text");
    }

    #[test]
    fn test_strip_markup_empty() {
        assert_eq!(strip_markup(""), "");
    }

    #[test]
    fn test_strip_markup_only_tags() {
        assert_eq!(strip_markup("[bold][/]"), "");
    }

    #[test]
    fn test_strip_markup_preserves_unicode() {
        assert_eq!(strip_markup("[info]⚡ Fast[/]"), "⚡ Fast");
    }

    #[test]
    fn test_console_with_enabled_true() {
        let console = FastMcpConsole::with_enabled(true);
        assert!(console.is_rich());
    }

    #[test]
    fn test_console_with_enabled_false() {
        let console = FastMcpConsole::with_enabled(false);
        assert!(!console.is_rich());
    }

    #[test]
    fn test_console_theme_access() {
        let console = FastMcpConsole::with_enabled(false);
        let theme = console.theme();
        // Verify theme is accessible
        assert_eq!(theme.primary.triplet.map(|tr| tr.blue), Some(255));
    }

    #[test]
    fn test_console_dimensions_default() {
        let console = FastMcpConsole::with_enabled(false);
        // Non-TTY should return defaults
        assert!(console.width() > 0);
        assert!(console.height() > 0);
    }
}
