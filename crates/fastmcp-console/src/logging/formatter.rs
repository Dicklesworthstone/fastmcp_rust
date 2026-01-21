//! Rich log formatting for tracing events.
//!
//! This module provides `RichLogFormatter` which transforms tracing events
//! into beautifully styled console output using rich_rust.

use crate::detection::DisplayContext;
use crate::theme::FastMcpTheme;
use rich_rust::prelude::*;

/// Formats tracing events into rich, styled output.
///
/// The formatter is aware of the display context and will produce plain
/// text output when running in agent mode (machine parsing) vs rich
/// styled output when running in human mode (interactive terminal).
#[derive(Debug)]
pub struct RichLogFormatter {
    theme: &'static FastMcpTheme,
    context: DisplayContext,
    show_target: bool,
    show_timestamp: bool,
    show_file_line: bool,
    max_message_width: Option<usize>,
}

impl RichLogFormatter {
    /// Create a new formatter with the given theme and context.
    #[must_use]
    pub fn new(theme: &'static FastMcpTheme, context: DisplayContext) -> Self {
        Self {
            theme,
            context,
            show_target: true,
            show_timestamp: true,
            show_file_line: false,
            max_message_width: None,
        }
    }

    /// Create a formatter that auto-detects the context.
    #[must_use]
    pub fn detect() -> Self {
        Self::new(crate::theme::theme(), DisplayContext::detect())
    }

    /// Set whether to show the target/module path.
    #[must_use]
    pub fn with_target(mut self, show: bool) -> Self {
        self.show_target = show;
        self
    }

    /// Set whether to show timestamps.
    #[must_use]
    pub fn with_timestamp(mut self, show: bool) -> Self {
        self.show_timestamp = show;
        self
    }

    /// Set whether to show file:line information.
    #[must_use]
    pub fn with_file_line(mut self, show: bool) -> Self {
        self.show_file_line = show;
        self
    }

    /// Set maximum width for message/target truncation.
    #[must_use]
    pub fn with_max_width(mut self, width: Option<usize>) -> Self {
        self.max_message_width = width;
        self
    }

    /// Check if rich output should be used.
    #[must_use]
    pub fn should_use_rich(&self) -> bool {
        self.context.is_human()
    }

    /// Get the style for a given log level.
    #[must_use]
    pub fn style_for_level(&self, level: LogLevel) -> &Style {
        match level {
            LogLevel::Error => &self.theme.error_style,
            LogLevel::Warn => &self.theme.warning_style,
            LogLevel::Info => &self.theme.info_style,
            LogLevel::Debug => &self.theme.muted_style,
            LogLevel::Trace => &self.theme.muted_style,
        }
    }

    /// Format a level badge (e.g., "[ERROR]", "[INFO ]").
    #[must_use]
    pub fn format_level_badge(&self, level: LogLevel) -> String {
        let text = format!("{:5}", level.as_str());

        if self.should_use_rich() {
            let style = self.style_for_level(level);
            let color_hex = style
                .color
                .as_ref()
                .and_then(|c| c.triplet)
                .map(|t| t.hex())
                .unwrap_or_default();
            format!("[{color_hex}]{text}[/]")
        } else {
            format!("[{text}]")
        }
    }

    /// Format a timestamp.
    #[must_use]
    pub fn format_timestamp(&self, timestamp: &str) -> Option<String> {
        if !self.show_timestamp {
            return None;
        }

        if self.should_use_rich() {
            let dim_hex = self
                .theme
                .text_dim
                .triplet
                .map(|t| t.hex())
                .unwrap_or_default();
            Some(format!("[{dim_hex}]{timestamp}[/]"))
        } else {
            Some(timestamp.to_string())
        }
    }

    /// Format a target/module path.
    #[must_use]
    pub fn format_target(&self, target: &str) -> Option<String> {
        if !self.show_target {
            return None;
        }

        // Strip "fastmcp::" prefix for cleaner output
        let target = target.strip_prefix("fastmcp::").unwrap_or(target);
        let target = self.truncate_text(target);

        if self.should_use_rich() {
            let muted_hex = self
                .theme
                .text_muted
                .triplet
                .map(|t| t.hex())
                .unwrap_or_default();
            Some(format!("[{muted_hex}]{target}[/]"))
        } else {
            Some(target.to_string())
        }
    }

    /// Format structured fields (key=value pairs).
    #[must_use]
    pub fn format_fields(&self, fields: &[(String, String)]) -> String {
        if fields.is_empty() {
            return String::new();
        }

        if self.should_use_rich() {
            let dim_hex = self
                .theme
                .text_dim
                .triplet
                .map(|t| t.hex())
                .unwrap_or_default();
            fields
                .iter()
                .map(|(k, v)| format!("[{dim_hex}]{k}[/]={v}"))
                .collect::<Vec<_>>()
                .join(" ")
        } else {
            fields
                .iter()
                .map(|(k, v)| format!("{k}={v}"))
                .collect::<Vec<_>>()
                .join(" ")
        }
    }

    /// Format a complete log event.
    #[must_use]
    pub fn format_event(&self, event: &LogEvent) -> FormattedLog {
        let level_badge = self.format_level_badge(event.level);
        let timestamp = event
            .timestamp
            .as_deref()
            .and_then(|ts| self.format_timestamp(ts));
        let target = event.target.as_deref().and_then(|t| self.format_target(t));
        let message = self.truncate_text(&event.message);

        let mut fields = event.fields.clone();
        if self.show_file_line {
            if let Some(file) = event.file.as_deref() {
                let file_line = if let Some(line) = event.line {
                    format!("{file}:{line}")
                } else {
                    file.to_string()
                };
                fields.push(("file".to_string(), file_line));
            }
        }

        let fields = self.format_fields(&fields);

        FormattedLog {
            level_badge,
            timestamp,
            target,
            message,
            fields,
        }
    }

    /// Format a log event to a single line string.
    #[must_use]
    pub fn format_line(&self, event: &LogEvent) -> String {
        let formatted = self.format_event(event);
        formatted.to_line()
    }

    fn truncate_text(&self, text: &str) -> String {
        let Some(max) = self.max_message_width else {
            return text.to_string();
        };

        let len = text.chars().count();
        if len <= max {
            return text.to_string();
        }

        if max <= 3 {
            return text.chars().take(max).collect();
        }

        let mut truncated: String = text.chars().take(max - 3).collect();
        truncated.push_str("...");
        truncated
    }
}

impl Default for RichLogFormatter {
    fn default() -> Self {
        Self::detect()
    }
}

/// Log level enum (mirrors tracing levels).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LogLevel {
    Error,
    Warn,
    Info,
    Debug,
    Trace,
}

impl LogLevel {
    /// Get the string representation.
    #[must_use]
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Error => "ERROR",
            Self::Warn => "WARN",
            Self::Info => "INFO",
            Self::Debug => "DEBUG",
            Self::Trace => "TRACE",
        }
    }
}

impl From<log::Level> for LogLevel {
    fn from(level: log::Level) -> Self {
        match level {
            log::Level::Error => Self::Error,
            log::Level::Warn => Self::Warn,
            log::Level::Info => Self::Info,
            log::Level::Debug => Self::Debug,
            log::Level::Trace => Self::Trace,
        }
    }
}

impl From<tracing::Level> for LogLevel {
    fn from(level: tracing::Level) -> Self {
        match level {
            tracing::Level::ERROR => Self::Error,
            tracing::Level::WARN => Self::Warn,
            tracing::Level::INFO => Self::Info,
            tracing::Level::DEBUG => Self::Debug,
            tracing::Level::TRACE => Self::Trace,
        }
    }
}

/// A log event to be formatted.
#[derive(Debug, Clone)]
pub struct LogEvent {
    pub level: LogLevel,
    pub message: String,
    pub target: Option<String>,
    pub timestamp: Option<String>,
    pub file: Option<String>,
    pub line: Option<u32>,
    pub fields: Vec<(String, String)>,
}

impl LogEvent {
    /// Create a new log event.
    #[must_use]
    pub fn new(level: LogLevel, message: impl Into<String>) -> Self {
        Self {
            level,
            message: message.into(),
            target: None,
            timestamp: None,
            file: None,
            line: None,
            fields: Vec::new(),
        }
    }

    /// Set the target.
    #[must_use]
    pub fn with_target(mut self, target: impl Into<String>) -> Self {
        self.target = Some(target.into());
        self
    }

    /// Set the timestamp.
    #[must_use]
    pub fn with_timestamp(mut self, timestamp: impl Into<String>) -> Self {
        self.timestamp = Some(timestamp.into());
        self
    }

    /// Set the file location.
    #[must_use]
    pub fn with_file(mut self, file: impl Into<String>) -> Self {
        self.file = Some(file.into());
        self
    }

    /// Set the line number.
    #[must_use]
    pub fn with_line(mut self, line: u32) -> Self {
        self.line = Some(line);
        self
    }

    /// Add a field.
    #[must_use]
    pub fn with_field(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.fields.push((key.into(), value.into()));
        self
    }
}

/// Formatted log output ready for rendering.
#[derive(Debug, Clone)]
pub struct FormattedLog {
    pub level_badge: String,
    pub timestamp: Option<String>,
    pub target: Option<String>,
    pub message: String,
    pub fields: String,
}

impl FormattedLog {
    /// Convert to a single line string.
    #[must_use]
    pub fn to_line(&self) -> String {
        let mut parts = Vec::with_capacity(5);

        if let Some(ref ts) = self.timestamp {
            parts.push(ts.as_str());
        }

        parts.push(&self.level_badge);

        if let Some(ref target) = self.target {
            parts.push(target.as_str());
        }

        parts.push(&self.message);

        if !self.fields.is_empty() {
            parts.push(&self.fields);
        }

        parts.join(" ")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_formatter_agent() -> RichLogFormatter {
        RichLogFormatter::new(crate::theme::theme(), DisplayContext::new_agent())
    }

    fn test_formatter_human() -> RichLogFormatter {
        RichLogFormatter::new(crate::theme::theme(), DisplayContext::new_human())
    }

    #[test]
    fn test_level_badge_formatting_plain() {
        let formatter = test_formatter_agent();
        assert_eq!(formatter.format_level_badge(LogLevel::Error), "[ERROR]");
        assert_eq!(formatter.format_level_badge(LogLevel::Warn), "[WARN ]");
        assert_eq!(formatter.format_level_badge(LogLevel::Info), "[INFO ]");
        assert_eq!(formatter.format_level_badge(LogLevel::Debug), "[DEBUG]");
        assert_eq!(formatter.format_level_badge(LogLevel::Trace), "[TRACE]");
    }

    #[test]
    fn test_level_badge_formatting_rich() {
        let formatter = test_formatter_human();
        let badge = formatter.format_level_badge(LogLevel::Error);
        // Rich badges contain markup
        assert!(badge.contains("[/]"));
        assert!(badge.contains("ERROR"));
    }

    #[test]
    fn test_timestamp_formatting() {
        let formatter = test_formatter_agent();
        let ts = formatter.format_timestamp("2026-01-21 12:00:00");
        assert_eq!(ts, Some("2026-01-21 12:00:00".to_string()));

        let formatter_no_ts = formatter.with_timestamp(false);
        assert_eq!(
            formatter_no_ts.format_timestamp("2026-01-21 12:00:00"),
            None
        );
    }

    #[test]
    fn test_target_formatting() {
        let formatter = test_formatter_agent();

        // Should strip fastmcp:: prefix
        let target = formatter.format_target("fastmcp::server::router");
        assert_eq!(target, Some("server::router".to_string()));

        // Non-fastmcp targets remain unchanged
        let target = formatter.format_target("tokio::runtime");
        assert_eq!(target, Some("tokio::runtime".to_string()));
    }

    #[test]
    fn test_target_disabled() {
        let formatter = test_formatter_agent().with_target(false);
        assert_eq!(formatter.format_target("any::target"), None);
    }

    #[test]
    fn test_target_truncation() {
        let formatter = test_formatter_agent().with_max_width(Some(8));
        let target = formatter.format_target("fastmcp::server::router");
        assert_eq!(target, Some("serve...".to_string()));
    }

    #[test]
    fn test_fields_formatting_plain() {
        let formatter = test_formatter_agent();
        let fields = vec![
            ("request_id".to_string(), "123".to_string()),
            ("method".to_string(), "GET".to_string()),
        ];
        assert_eq!(
            formatter.format_fields(&fields),
            "request_id=123 method=GET"
        );
    }

    #[test]
    fn test_fields_empty() {
        let formatter = test_formatter_agent();
        assert_eq!(formatter.format_fields(&[]), "");
    }

    #[test]
    fn test_format_event_plain() {
        let formatter = test_formatter_agent();
        let event = LogEvent::new(LogLevel::Info, "Server started")
            .with_target("fastmcp::server")
            .with_timestamp("12:00:00");

        let formatted = formatter.format_event(&event);
        assert_eq!(formatted.level_badge, "[INFO ]");
        assert_eq!(formatted.target, Some("server".to_string()));
        assert_eq!(formatted.message, "Server started");
    }

    #[test]
    fn test_file_line_field() {
        let formatter = test_formatter_agent().with_file_line(true);
        let event = LogEvent::new(LogLevel::Info, "File info")
            .with_file("src/main.rs")
            .with_line(42);

        let formatted = formatter.format_event(&event);
        assert!(formatted.fields.contains("file=src/main.rs:42"));
    }

    #[test]
    fn test_message_truncation() {
        let formatter = test_formatter_agent().with_max_width(Some(8));
        let event = LogEvent::new(LogLevel::Info, "HelloWorld");
        let formatted = formatter.format_event(&event);
        assert_eq!(formatted.message, "Hello...");
    }

    #[test]
    fn test_format_line() {
        let formatter = test_formatter_agent();
        let event = LogEvent::new(LogLevel::Error, "Connection failed")
            .with_target("fastmcp::transport")
            .with_timestamp("12:00:00")
            .with_field("error", "timeout");

        let line = formatter.format_line(&event);
        assert!(line.contains("[ERROR]"));
        assert!(line.contains("Connection failed"));
        assert!(line.contains("transport"));
        assert!(line.contains("error=timeout"));
    }

    #[test]
    fn test_log_level_from_log_crate() {
        assert_eq!(LogLevel::from(log::Level::Error), LogLevel::Error);
        assert_eq!(LogLevel::from(log::Level::Warn), LogLevel::Warn);
        assert_eq!(LogLevel::from(log::Level::Info), LogLevel::Info);
        assert_eq!(LogLevel::from(log::Level::Debug), LogLevel::Debug);
        assert_eq!(LogLevel::from(log::Level::Trace), LogLevel::Trace);
    }

    #[test]
    fn test_log_event_builder() {
        let event = LogEvent::new(LogLevel::Info, "test")
            .with_target("target")
            .with_timestamp("ts")
            .with_file("file.rs")
            .with_line(42)
            .with_field("key", "value");

        assert_eq!(event.level, LogLevel::Info);
        assert_eq!(event.message, "test");
        assert_eq!(event.target, Some("target".to_string()));
        assert_eq!(event.timestamp, Some("ts".to_string()));
        assert_eq!(event.file, Some("file.rs".to_string()));
        assert_eq!(event.line, Some(42));
        assert_eq!(event.fields, vec![("key".to_string(), "value".to_string())]);
    }

    #[test]
    fn test_formatter_default() {
        let formatter = RichLogFormatter::default();
        // Should work without panicking
        let _ = formatter.format_level_badge(LogLevel::Info);
    }
}
