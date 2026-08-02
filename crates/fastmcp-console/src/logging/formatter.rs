//! Rich log formatting for tracing events.
//!
//! This module provides `RichLogFormatter` which transforms tracing events
//! into beautifully styled console output using rich_rust.

use crate::console::{
    DEFAULT_LOG_MESSAGE_MAX_CHARS, DEFAULT_TERMINAL_FIELD_MAX_CHARS, REDACTED_VALUE,
    bounded_redacted_rich_fragment, bounded_redacted_rich_text, bounded_redacted_terminal_text,
    is_credential_key,
};
use crate::detection::DisplayContext;
use crate::theme::FastMcpTheme;
use rich_rust::prelude::*;

const MAX_LOG_FIELDS: usize = 64;

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

    /// Format a level badge (e.g., `[ERROR]`, `[INFO ]`).
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

        let timestamp = self.format_untrusted_fragment(timestamp, self.effective_max_width());
        if self.should_use_rich() {
            let dim_hex = self
                .theme
                .text_dim
                .triplet
                .map(|t| t.hex())
                .unwrap_or_default();
            Some(format!("[{dim_hex}]{timestamp}[/]"))
        } else {
            Some(timestamp)
        }
    }

    /// Format a target/module path.
    #[must_use]
    pub fn format_target(&self, target: &str) -> Option<String> {
        if !self.show_target {
            return None;
        }

        // Strip "fastmcp_rust::" prefix for cleaner output
        let target = target.strip_prefix("fastmcp_rust::").unwrap_or(target);
        let target = self.format_untrusted_fragment(target, self.effective_max_width());

        if self.should_use_rich() {
            let muted_hex = self
                .theme
                .text_muted
                .triplet
                .map(|t| t.hex())
                .unwrap_or_default();
            Some(format!("[{muted_hex}]{target}[/]"))
        } else {
            Some(target)
        }
    }

    /// Format structured fields (key=value pairs).
    #[must_use]
    pub fn format_fields(&self, fields: &[(String, String)]) -> String {
        self.format_field_pairs(
            fields
                .iter()
                .map(|(key, value)| (key.as_str(), value.as_str())),
            fields.len(),
        )
    }

    fn format_field_pairs<'a, I>(&self, fields: I, total_fields: usize) -> String
    where
        I: Iterator<Item = (&'a str, &'a str)>,
    {
        if total_fields == 0 {
            return String::new();
        }

        let aggregate_limit = self.effective_max_width();
        if aggregate_limit == 0 {
            return String::new();
        }
        let component_limit = aggregate_limit.min(DEFAULT_TERMINAL_FIELD_MAX_CHARS);
        let dim_hex = self
            .theme
            .text_dim
            .triplet
            .map(|triplet| triplet.hex())
            .unwrap_or_default();
        let mut rendered_fields = Vec::new();
        let mut rendered_chars = 0usize;

        for (key, value) in fields.take(MAX_LOG_FIELDS) {
            // Classify the original key before display truncation. The shared
            // classifier has its own fixed scan bound and fails closed when the
            // complete key cannot be inspected; classifying `bounded_key`
            // would let truncation erase a sensitive suffix.
            let credential_field = is_credential_key(key);
            let bounded_key = bounded_redacted_terminal_text(key, component_limit);
            let key = if self.should_use_rich() {
                bounded_redacted_rich_fragment(&bounded_key, component_limit)
            } else {
                bounded_key
            };
            let value = if credential_field {
                self.format_untrusted_text(REDACTED_VALUE, component_limit)
            } else {
                self.format_untrusted_text(value, component_limit)
            };
            let field = if self.should_use_rich() {
                format!("[{dim_hex}]{key}[/]={value}")
            } else {
                format!("{key}={value}")
            };
            let separator_chars = usize::from(!rendered_fields.is_empty());
            let field_chars = field.chars().count();
            if rendered_chars
                .saturating_add(separator_chars)
                .saturating_add(field_chars)
                > aggregate_limit
            {
                break;
            }
            rendered_chars = rendered_chars
                .saturating_add(separator_chars)
                .saturating_add(field_chars);
            rendered_fields.push((field, field_chars));
        }

        if rendered_fields.len() < total_fields {
            let marker: String = "...".chars().take(aggregate_limit).collect();
            let marker_chars = marker.chars().count();
            while !rendered_fields.is_empty()
                && rendered_chars
                    .saturating_add(1)
                    .saturating_add(marker_chars)
                    > aggregate_limit
            {
                if let Some((_, removed_chars)) = rendered_fields.pop() {
                    rendered_chars = rendered_chars.saturating_sub(removed_chars);
                    if !rendered_fields.is_empty() {
                        rendered_chars = rendered_chars.saturating_sub(1);
                    }
                }
            }
            rendered_fields.push((marker, marker_chars));
        }

        rendered_fields
            .into_iter()
            .map(|(field, _)| field)
            .collect::<Vec<_>>()
            .join(" ")
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
        let message = self.format_untrusted_text(&event.message, self.effective_max_width());

        let component_limit = self
            .effective_max_width()
            .min(DEFAULT_TERMINAL_FIELD_MAX_CHARS);
        let file_line = if self.show_file_line {
            event.file.as_deref().map(|file| {
                let file = bounded_redacted_terminal_text(file, component_limit);
                let file_line = if let Some(line) = event.line {
                    format!("{file}:{line}")
                } else {
                    file
                };
                bounded_redacted_terminal_text(&file_line, component_limit)
            })
        } else {
            None
        };
        let reserved_file_fields = usize::from(file_line.is_some());
        let event_field_limit = MAX_LOG_FIELDS.saturating_sub(reserved_file_fields);
        let total_fields = event.fields.len().saturating_add(reserved_file_fields);
        let fields = self.format_field_pairs(
            event
                .fields
                .iter()
                .take(event_field_limit)
                .map(|(key, value)| (key.as_str(), value.as_str()))
                .chain(file_line.as_deref().map(|value| ("file", value))),
            total_fields,
        );

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

    fn effective_max_width(&self) -> usize {
        self.max_message_width
            .unwrap_or(DEFAULT_LOG_MESSAGE_MAX_CHARS)
            .min(DEFAULT_LOG_MESSAGE_MAX_CHARS)
    }

    fn format_untrusted_text(&self, text: &str, max_chars: usize) -> String {
        if self.should_use_rich() {
            bounded_redacted_rich_text(text, max_chars)
        } else {
            bounded_redacted_terminal_text(text, max_chars)
        }
    }

    fn format_untrusted_fragment(&self, text: &str, max_chars: usize) -> String {
        if self.should_use_rich() {
            bounded_redacted_rich_fragment(text, max_chars)
        } else {
            bounded_redacted_terminal_text(text, max_chars)
        }
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
    fn test_level_badge_formatting_rich_all_levels() {
        let formatter = test_formatter_human();
        for level in [
            LogLevel::Warn,
            LogLevel::Info,
            LogLevel::Debug,
            LogLevel::Trace,
        ] {
            let badge = formatter.format_level_badge(level);
            assert!(badge.contains("[/]"));
            assert!(badge.contains(level.as_str().trim()));
        }
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

        // Should strip fastmcp_rust:: prefix
        let target = formatter.format_target("fastmcp_rust::server::router");
        assert_eq!(target, Some("server::router".to_string()));

        // Non-fastmcp targets remain unchanged
        let target = formatter.format_target("tokio::runtime");
        assert_eq!(target, Some("tokio::runtime".to_string()));
    }

    #[test]
    fn test_timestamp_and_target_formatting_rich() {
        let formatter = test_formatter_human();
        let ts = formatter
            .format_timestamp("2026-01-21 12:00:00")
            .expect("timestamp should be present");
        assert!(ts.contains("[/]"));
        assert!(ts.contains("2026-01-21 12:00:00"));

        let target = formatter
            .format_target("fastmcp_rust::server::router")
            .expect("target should be present");
        assert!(target.contains("[/]"));
        assert!(target.contains("server::router"));
    }

    #[test]
    fn rich_wrapped_components_protect_trailing_backslash_runs() {
        fn trailing_backslashes_before(rendered: &str, suffix: &str) -> usize {
            rendered
                .strip_suffix(suffix)
                .expect("trusted rich suffix should be present")
                .as_bytes()
                .iter()
                .rev()
                .take_while(|byte| **byte == b'\\')
                .count()
        }

        let formatter = test_formatter_human();
        for slash_count in 1..=3 {
            let slashes = "\\".repeat(slash_count);
            let timestamp = formatter
                .format_timestamp(&format!("timestamp{slashes}"))
                .expect("timestamp should be present");
            let target = formatter
                .format_target(&format!("fastmcp_rust::target{slashes}"))
                .expect("target should be present");
            let fields =
                formatter.format_fields(&[(format!("field{slashes}"), "value".to_string())]);
            let protected_count = slash_count * 2;

            assert_eq!(
                trailing_backslashes_before(&timestamp, "[/]"),
                protected_count
            );
            assert_eq!(trailing_backslashes_before(&target, "[/]"), protected_count);
            assert_eq!(
                trailing_backslashes_before(&fields, "[/]=value"),
                protected_count
            );
        }
    }

    #[test]
    fn test_target_disabled() {
        let formatter = test_formatter_agent().with_target(false);
        assert_eq!(formatter.format_target("any::target"), None);
    }

    #[test]
    fn test_target_truncation() {
        let formatter = test_formatter_agent().with_max_width(Some(8));
        let target = formatter.format_target("fastmcp_rust::server::router");
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
    fn test_fields_formatting_rich() {
        let formatter = test_formatter_human();
        let fields = vec![
            ("request_id".to_string(), "123".to_string()),
            ("method".to_string(), "GET".to_string()),
        ];

        let rendered = formatter.format_fields(&fields);
        assert!(rendered.contains("[/]"));
        assert!(rendered.contains("request_id"));
        assert!(rendered.contains("method"));
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
            .with_target("fastmcp_rust::server")
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
    fn test_file_field_without_line_number() {
        let formatter = test_formatter_agent().with_file_line(true);
        let event = LogEvent::new(LogLevel::Info, "File info").with_file("src/main.rs");

        let formatted = formatter.format_event(&event);
        assert!(formatted.fields.contains("file=src/main.rs"));
        assert!(!formatted.fields.contains("src/main.rs:"));
    }

    #[test]
    fn test_message_truncation() {
        let formatter = test_formatter_agent().with_max_width(Some(8));
        let event = LogEvent::new(LogLevel::Info, "HelloWorld");
        let formatted = formatter.format_event(&event);
        assert_eq!(formatted.message, "Hello...");
    }

    #[test]
    fn test_message_truncation_for_tiny_width() {
        let formatter = test_formatter_agent().with_max_width(Some(3));
        let event = LogEvent::new(LogLevel::Info, "HelloWorld");
        let formatted = formatter.format_event(&event);
        assert_eq!(formatted.message, "Hel");
    }

    #[test]
    fn test_format_line() {
        let formatter = test_formatter_agent();
        let event = LogEvent::new(LogLevel::Error, "Connection failed")
            .with_target("fastmcp_rust::transport")
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
    fn test_log_level_from_tracing_crate() {
        assert_eq!(LogLevel::from(tracing::Level::ERROR), LogLevel::Error);
        assert_eq!(LogLevel::from(tracing::Level::WARN), LogLevel::Warn);
        assert_eq!(LogLevel::from(tracing::Level::INFO), LogLevel::Info);
        assert_eq!(LogLevel::from(tracing::Level::DEBUG), LogLevel::Debug);
        assert_eq!(LogLevel::from(tracing::Level::TRACE), LogLevel::Trace);
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

    // =========================================================================
    // Additional coverage tests (bd-m32k)
    // =========================================================================

    #[test]
    fn truncate_text_exact_max_no_truncation() {
        let formatter = test_formatter_agent().with_max_width(Some(5));
        let event = LogEvent::new(LogLevel::Info, "Hello");
        let formatted = formatter.format_event(&event);
        // Exactly at max → no truncation
        assert_eq!(formatted.message, "Hello");
    }

    #[test]
    fn truncate_text_no_max_returns_full() {
        let formatter = test_formatter_agent().with_max_width(None);
        let event = LogEvent::new(
            LogLevel::Info,
            "A long message that should not be truncated at all",
        );
        let formatted = formatter.format_event(&event);
        assert_eq!(
            formatted.message,
            "A long message that should not be truncated at all"
        );
    }

    #[test]
    fn truncate_text_width_one_and_two() {
        // max <= 3 takes first max chars (no ellipsis)
        let f1 = test_formatter_agent().with_max_width(Some(1));
        let e = LogEvent::new(LogLevel::Info, "Hello");
        assert_eq!(f1.format_event(&e).message, "H");

        let f2 = test_formatter_agent().with_max_width(Some(2));
        assert_eq!(f2.format_event(&e).message, "He");
    }

    #[test]
    fn should_use_rich_agent_vs_human() {
        let agent = test_formatter_agent();
        assert!(!agent.should_use_rich());

        let human = test_formatter_human();
        assert!(human.should_use_rich());
    }

    #[test]
    fn style_for_level_all_levels() {
        let formatter = test_formatter_agent();
        // Just verify each level returns a style without panicking
        let _ = formatter.style_for_level(LogLevel::Error);
        let _ = formatter.style_for_level(LogLevel::Warn);
        let _ = formatter.style_for_level(LogLevel::Info);
        let _ = formatter.style_for_level(LogLevel::Debug);
        let _ = formatter.style_for_level(LogLevel::Trace);
        // Debug and Trace should return the same muted style
        assert!(std::ptr::eq(
            formatter.style_for_level(LogLevel::Debug),
            formatter.style_for_level(LogLevel::Trace)
        ));
    }

    #[test]
    fn formatted_log_to_line_minimal() {
        // No timestamp, no target, no fields → just "badge message"
        let log = FormattedLog {
            level_badge: "[INFO ]".to_string(),
            timestamp: None,
            target: None,
            message: "hello".to_string(),
            fields: String::new(),
        };
        assert_eq!(log.to_line(), "[INFO ] hello");
    }

    #[test]
    fn formatted_log_debug_and_clone() {
        let log = FormattedLog {
            level_badge: "[INFO ]".to_string(),
            timestamp: Some("12:00:00".to_string()),
            target: Some("server".to_string()),
            message: "msg".to_string(),
            fields: "k=v".to_string(),
        };
        let debug = format!("{log:?}");
        assert!(debug.contains("FormattedLog"));

        let cloned = log.clone();
        assert_eq!(cloned.message, "msg");
        assert_eq!(cloned.to_line(), log.to_line());
    }

    #[test]
    fn log_level_as_str_and_traits() {
        // as_str
        assert_eq!(LogLevel::Error.as_str(), "ERROR");
        assert_eq!(LogLevel::Warn.as_str(), "WARN");
        assert_eq!(LogLevel::Info.as_str(), "INFO");
        assert_eq!(LogLevel::Debug.as_str(), "DEBUG");
        assert_eq!(LogLevel::Trace.as_str(), "TRACE");

        // Debug
        let debug = format!("{:?}", LogLevel::Error);
        assert!(debug.contains("Error"));

        // Clone + Copy
        let level = LogLevel::Warn;
        let copied = level;
        assert_eq!(level, copied);
    }

    #[test]
    fn log_event_debug_and_clone() {
        let event = LogEvent::new(LogLevel::Info, "test")
            .with_target("t")
            .with_field("k", "v");

        let debug = format!("{event:?}");
        assert!(debug.contains("LogEvent"));
        assert!(debug.contains("test"));

        let cloned = event.clone();
        assert_eq!(cloned.message, "test");
        assert_eq!(cloned.target, Some("t".to_string()));
        assert_eq!(cloned.fields.len(), 1);
    }

    #[test]
    fn format_event_with_all_options_enabled() {
        let formatter = test_formatter_agent()
            .with_file_line(true)
            .with_max_width(Some(50));

        let event = LogEvent::new(LogLevel::Error, "Connection failed")
            .with_target("fastmcp_rust::transport::http")
            .with_timestamp("2026-01-01T00:00:00Z")
            .with_file("src/transport/http.rs")
            .with_line(42)
            .with_field("peer", "127.0.0.1");

        let formatted = formatter.format_event(&event);
        assert_eq!(formatted.level_badge, "[ERROR]");
        assert!(formatted.timestamp.is_some());
        assert!(formatted.target.is_some());
        // file:line should be in fields
        assert!(formatted.fields.contains("file=src/transport/http.rs:42"));
        assert!(formatted.fields.contains("peer=127.0.0.1"));
    }

    #[test]
    fn format_target_rich_with_truncation() {
        let formatter = test_formatter_human().with_max_width(Some(10));
        let target = formatter
            .format_target("fastmcp_rust::server::router::handler")
            .unwrap();
        // Should contain markup and be truncated
        assert!(target.contains("[/]"));
        assert!(target.contains("..."));
    }

    #[test]
    fn hostile_log_components_are_terminal_safe_markup_safe_and_bounded() {
        let message = format!(
            "[bold]literal[/]\n\u{001b}\u{202e}{}",
            "m".repeat(DEFAULT_LOG_MESSAGE_MAX_CHARS * 2)
        );
        let fields = (0..100).fold(
            LogEvent::new(LogLevel::Warn, &message)
                .with_target("[link]peer\u{0007}")
                .with_timestamp("time\rstamp"),
            |event, index| {
                event.with_field(
                    format!("[key{index}]\u{001b}"),
                    format!("[value{index}]{}", "v".repeat(256)),
                )
            },
        );

        let plain = test_formatter_agent().format_line(&fields);
        let rich = test_formatter_human().format_line(&fields);

        for rendered in [&plain, &rich] {
            assert!(
                !rendered
                    .chars()
                    .any(crate::console::terminal_text_is_unsafe)
            );
            assert!(rendered.contains("\\n"));
            assert!(rendered.contains("\\u{1b}"));
            assert!(rendered.contains("\\u{202e}"));
            assert!(rendered.chars().count() < 4_500);
        }
        assert!(plain.contains("[WARN ]"));
        assert!(plain.contains("[bold]literal[/]"));
        assert!(rich.contains("\\[bold]literal\\[/]"));
    }

    #[test]
    fn no_explicit_width_still_has_a_hard_default_bound() {
        let formatter = test_formatter_agent().with_max_width(None);
        let event = LogEvent::new(
            LogLevel::Info,
            "x".repeat(DEFAULT_LOG_MESSAGE_MAX_CHARS * 4),
        );

        let formatted = formatter.format_event(&event);

        assert_eq!(
            formatted.message.chars().count(),
            DEFAULT_LOG_MESSAGE_MAX_CHARS
        );
        assert!(formatted.message.ends_with("..."));
    }

    #[test]
    fn log_messages_and_structured_fields_redact_credentials() {
        let event = LogEvent::new(
            LogLevel::Info,
            "Authorization: Bearer message-canary password=message-password-canary",
        )
        .with_field("access_token", "field-token-canary")
        .with_field("clientSecret", "field-secret-canary")
        .with_field("secretHint", "safe-hint")
        .with_field("ordinary", "api_key=embedded-canary");

        for formatter in [test_formatter_agent(), test_formatter_human()] {
            let rendered = formatter.format_line(&event);
            for canary in [
                "message-canary",
                "message-password-canary",
                "field-token-canary",
                "field-secret-canary",
                "embedded-canary",
            ] {
                assert!(!rendered.contains(canary), "leaked {canary}: {rendered}");
            }
            assert!(rendered.contains("[REDACTED]") || rendered.contains("\\[REDACTED]"));
            assert!(rendered.contains("safe-hint"));
        }
    }

    #[test]
    fn field_omission_marker_never_exceeds_aggregate_limit() {
        let fields = vec![
            ("first".to_string(), "value".repeat(32)),
            ("second".to_string(), "value".repeat(32)),
        ];

        for limit in 0..=16 {
            let rendered = test_formatter_agent()
                .with_max_width(Some(limit))
                .format_fields(&fields);
            assert!(
                rendered.chars().count() <= limit,
                "limit={limit}, rendered={rendered:?}"
            );
            if limit > 0 {
                let expected_marker: String = "...".chars().take(limit).collect();
                assert!(rendered.ends_with(&expected_marker));
            }
        }
    }

    #[test]
    fn oversized_public_field_keys_fail_closed_before_classification() {
        let huge_key = format!("{}access_token", "benign".repeat(100_000));
        let fields = vec![(huge_key, "credential-canary".to_string())];
        let rendered = test_formatter_agent()
            .with_max_width(Some(80))
            .format_fields(&fields);

        assert!(!rendered.contains("credential-canary"));
        assert!(rendered.contains(REDACTED_VALUE) || rendered == "...");
        assert!(rendered.chars().count() <= 80);
    }

    #[test]
    fn display_truncation_cannot_erase_a_sensitive_field_suffix() {
        const SUFFIX: &str = "_access_token";

        for key_chars in [257usize, 600, 2_048] {
            let key = format!("{}{}", "k".repeat(key_chars - SUFFIX.len()), SUFFIX);
            let fields = vec![(key, format!("suffix-canary-{key_chars}"))];

            for formatter in [test_formatter_agent(), test_formatter_human()] {
                let rendered = formatter.with_max_width(Some(1_024)).format_fields(&fields);
                assert!(
                    !rendered.contains(&format!("suffix-canary-{key_chars}")),
                    "long sensitive-key value leaked: {rendered}"
                );
                assert!(
                    rendered.contains(REDACTED_VALUE) || rendered.contains("\\[REDACTED]"),
                    "redaction marker missing: {rendered}"
                );
            }
        }
    }

    #[test]
    fn oversized_public_field_values_and_file_locations_are_bounded() {
        let mut value_event = LogEvent::new(LogLevel::Info, "bounded value");
        value_event
            .fields
            .push(("ordinary".to_string(), "v".repeat(100_000)));
        let value_fields = test_formatter_agent()
            .with_max_width(Some(96))
            .format_event(&value_event)
            .fields;

        let file_event = LogEvent::new(LogLevel::Info, "bounded location")
            .with_file(format!("src/{}\npassword=file-canary", "x".repeat(100_000)))
            .with_line(u32::MAX);
        let file_fields = test_formatter_agent()
            .with_file_line(true)
            .with_max_width(Some(96))
            .format_event(&file_event)
            .fields;

        assert!(value_fields.chars().count() <= 96);
        assert!(file_fields.chars().count() <= 96);
        assert!(!file_fields.contains("file-canary"));
        assert!(
            !file_fields
                .chars()
                .any(crate::console::terminal_text_is_unsafe)
        );
    }
}
