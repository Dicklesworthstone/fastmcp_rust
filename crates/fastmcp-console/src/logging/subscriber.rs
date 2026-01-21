//! Rich tracing subscriber integration.
//!
//! Provides a tracing `Layer` and builder that route events through the
//! [`RichLogFormatter`] for styled output to stderr.

use std::fmt;

use time::{OffsetDateTime, format_description};
use tracing::{Event, Subscriber};
use tracing::field::{Field, Visit};
use tracing_subscriber::filter::LevelFilter;
use tracing_subscriber::layer::{Context, Layer};
use tracing_subscriber::registry::LookupSpan;
use tracing_subscriber::prelude::*;

use crate::console::{FastMcpConsole, strip_markup};
use crate::detection::DisplayContext;
use crate::theme::FastMcpTheme;

use super::{LogEvent, LogLevel, RichLogFormatter};

/// A tracing layer that renders events using rich formatting.
pub struct RichLayer {
    formatter: RichLogFormatter,
    console: &'static FastMcpConsole,
    include_timestamps: bool,
}

impl RichLayer {
    /// Create a new rich layer.
    #[must_use]
    pub fn new(formatter: RichLogFormatter, include_timestamps: bool) -> Self {
        Self {
            formatter,
            console: crate::console::console(),
            include_timestamps,
        }
    }

    fn timestamp_string(&self) -> Option<String> {
        if !self.include_timestamps {
            return None;
        }

        let now = OffsetDateTime::now_utc();
        if let Ok(fmt) = format_description::parse("[hour]:[minute]:[second]") {
            now.format(&fmt).ok()
        } else {
            None
        }
    }
}

#[derive(Default)]
struct FieldCollector {
    message: Option<String>,
    fields: Vec<(String, String)>,
}

impl FieldCollector {
    fn record_value(&mut self, field: &Field, value: String) {
        if field.name() == "message" {
            if self.message.is_none() {
                self.message = Some(value);
            }
        } else {
            self.fields.push((field.name().to_string(), value));
        }
    }
}

impl Visit for FieldCollector {
    fn record_debug(&mut self, field: &Field, value: &dyn fmt::Debug) {
        self.record_value(field, format!("{value:?}"));
    }

    fn record_str(&mut self, field: &Field, value: &str) {
        self.record_value(field, value.to_string());
    }

    fn record_bool(&mut self, field: &Field, value: bool) {
        self.record_value(field, value.to_string());
    }

    fn record_i64(&mut self, field: &Field, value: i64) {
        self.record_value(field, value.to_string());
    }

    fn record_u64(&mut self, field: &Field, value: u64) {
        self.record_value(field, value.to_string());
    }

    fn record_f64(&mut self, field: &Field, value: f64) {
        self.record_value(field, value.to_string());
    }
}

impl<S> Layer<S> for RichLayer
where
    S: Subscriber + for<'lookup> LookupSpan<'lookup>,
{
    fn on_event(&self, event: &Event<'_>, ctx: Context<'_, S>) {
        let metadata = event.metadata();
        let mut collector = FieldCollector::default();
        event.record(&mut collector);

        if let Some(scope) = ctx.event_scope(event) {
            let spans: Vec<String> = scope.from_root().map(|span| span.name().to_string()).collect();
            if !spans.is_empty() {
                collector
                    .fields
                    .push(("span".to_string(), spans.join("::")));
            }
        }

        let level = LogLevel::from(*metadata.level());
        let message = collector
            .message
            .unwrap_or_else(|| metadata.name().to_string());

        let mut log_event = LogEvent::new(level, message).with_target(metadata.target());

        if let Some(ts) = self.timestamp_string() {
            log_event = log_event.with_timestamp(ts);
        }
        if let Some(file) = metadata.file() {
            log_event = log_event.with_file(file);
        }
        if let Some(line) = metadata.line() {
            log_event = log_event.with_line(line);
        }
        for (key, value) in collector.fields {
            log_event = log_event.with_field(key, value);
        }

        let line = self.formatter.format_line(&log_event);
        if self.console.is_rich() {
            self.console.print(&line);
        } else {
            eprintln!("{}", strip_markup(&line));
        }
    }
}

/// Builder for configuring a rich tracing subscriber.
#[derive(Debug)]
pub struct RichSubscriberBuilder {
    theme: Option<&'static FastMcpTheme>,
    show_timestamps: bool,
    show_targets: bool,
    show_file_line: bool,
    max_width: Option<usize>,
    level_filter: LevelFilter,
}

impl Default for RichSubscriberBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl RichSubscriberBuilder {
    /// Create a new builder with defaults.
    #[must_use]
    pub fn new() -> Self {
        Self {
            theme: None,
            show_timestamps: true,
            show_targets: true,
            show_file_line: false,
            max_width: None,
            level_filter: LevelFilter::INFO,
        }
    }

    /// Set a custom theme.
    #[must_use]
    pub fn with_theme(mut self, theme: &'static FastMcpTheme) -> Self {
        self.theme = Some(theme);
        self
    }

    /// Toggle timestamp rendering.
    #[must_use]
    pub fn with_timestamps(mut self, show: bool) -> Self {
        self.show_timestamps = show;
        self
    }

    /// Toggle target/module rendering.
    #[must_use]
    pub fn with_targets(mut self, show: bool) -> Self {
        self.show_targets = show;
        self
    }

    /// Toggle file:line rendering.
    #[must_use]
    pub fn with_file_line(mut self, show: bool) -> Self {
        self.show_file_line = show;
        self
    }

    /// Set maximum width for message/target truncation.
    #[must_use]
    pub fn with_max_width(mut self, width: Option<usize>) -> Self {
        self.max_width = width;
        self
    }

    /// Set the minimum log level.
    #[must_use]
    pub fn with_level_filter(mut self, filter: LevelFilter) -> Self {
        self.level_filter = filter;
        self
    }

    /// Build the subscriber without installing it.
    #[must_use]
    pub fn build(self) -> impl Subscriber {
        let context = DisplayContext::detect();
        let theme = self.theme.unwrap_or_else(crate::theme::theme);

        let formatter = RichLogFormatter::new(theme, context)
            .with_timestamp(self.show_timestamps)
            .with_target(self.show_targets)
            .with_file_line(self.show_file_line)
            .with_max_width(self.max_width);

        let layer = RichLayer::new(formatter, self.show_timestamps);

        tracing_subscriber::registry()
            .with(self.level_filter)
            .with(layer)
    }

    /// Build and install as the global subscriber.
    pub fn init(self) -> Result<(), tracing::subscriber::SetGlobalDefaultError> {
        let subscriber = self.build();
        tracing::subscriber::set_global_default(subscriber)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_builder_defaults() {
        let builder = RichSubscriberBuilder::default();
        assert!(builder.show_timestamps);
        assert!(builder.show_targets);
        assert!(!builder.show_file_line);
        assert_eq!(builder.max_width, None);
        assert_eq!(builder.level_filter, LevelFilter::INFO);
    }

    #[test]
    fn test_builder_builds() {
        let _subscriber = RichSubscriberBuilder::new().build();
    }
}
