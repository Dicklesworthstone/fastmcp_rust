//! Rich tracing subscriber integration.
//!
//! Provides a tracing `Layer` and builder that route events through the
//! [`RichLogFormatter`] for styled output to stderr.

use std::fmt;

use time::{OffsetDateTime, format_description};
use tracing::field::{Field, Visit};
use tracing::{Event, Subscriber};
use tracing_subscriber::filter::LevelFilter;
use tracing_subscriber::layer::{Context, Layer};
use tracing_subscriber::prelude::*;
use tracing_subscriber::registry::LookupSpan;

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
            let spans: Vec<String> = scope
                .from_root()
                .map(|span| span.name().to_string())
                .collect();
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
    use tracing::{Level, debug, event, info, info_span};

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

    #[test]
    fn test_builder_option_setters() {
        let builder = RichSubscriberBuilder::new()
            .with_theme(crate::theme::theme())
            .with_timestamps(false)
            .with_targets(false)
            .with_file_line(true)
            .with_max_width(Some(64))
            .with_level_filter(LevelFilter::DEBUG);

        assert!(builder.theme.is_some());
        assert!(!builder.show_timestamps);
        assert!(!builder.show_targets);
        assert!(builder.show_file_line);
        assert_eq!(builder.max_width, Some(64));
        assert_eq!(builder.level_filter, LevelFilter::DEBUG);
    }

    #[test]
    fn test_rich_layer_timestamp_toggle() {
        let formatter = RichLogFormatter::new(crate::theme::theme(), DisplayContext::new_agent());

        let no_ts_layer = RichLayer::new(formatter, false);
        assert_eq!(no_ts_layer.timestamp_string(), None);

        let with_ts_layer = RichLayer::new(
            RichLogFormatter::new(crate::theme::theme(), DisplayContext::new_agent()),
            true,
        );
        let timestamp = with_ts_layer.timestamp_string();
        assert!(timestamp.is_some());
        let timestamp = timestamp.unwrap_or_default();
        assert_eq!(timestamp.len(), 8);
        assert_eq!(timestamp.chars().nth(2), Some(':'));
        assert_eq!(timestamp.chars().nth(5), Some(':'));
    }

    #[test]
    fn test_layer_processes_event_without_span_scope() {
        let formatter = RichLogFormatter::new(crate::theme::theme(), DisplayContext::new_agent())
            .with_timestamp(false)
            .with_target(true)
            .with_file_line(true)
            .with_max_width(Some(80));
        let layer = RichLayer::new(formatter, false);
        let subscriber = tracing_subscriber::registry().with(layer);

        tracing::subscriber::with_default(subscriber, || {
            event!(Level::INFO, action = "sync");
            info!(
                message = "plain_event",
                user = "alice",
                retries = 2_u64,
                ok = true
            );
        });
    }

    #[test]
    fn test_layer_processes_event_with_span_scope_and_all_field_types() {
        let formatter = RichLogFormatter::new(crate::theme::theme(), DisplayContext::new_agent())
            .with_timestamp(true)
            .with_target(true)
            .with_file_line(true)
            .with_max_width(Some(120));
        let layer = RichLayer::new(formatter, true);
        let subscriber = tracing_subscriber::registry().with(layer);

        tracing::subscriber::with_default(subscriber, || {
            let span = info_span!("subscriber_scope");
            let _guard = span.enter();

            info!(
                message = "structured",
                flag = true,
                count_i = -5_i64,
                count_u = 42_u64,
                ratio = 3.5_f64,
                debug_val = ?vec![1, 2, 3]
            );

            debug!(message = "second_message");
        });
    }

    // =========================================================================
    // Additional coverage tests (bd-i167)
    // =========================================================================

    #[test]
    fn field_collector_default_is_empty() {
        let collector = FieldCollector::default();
        assert!(collector.message.is_none());
        assert!(collector.fields.is_empty());
    }

    #[test]
    fn field_collector_message_only_set_once() {
        use tracing::field::FieldSet;

        let mut collector = FieldCollector::default();

        // Simulate first message field
        let fields = FieldSet::new(&["message"], tracing::callsite::Identifier(&NOP_CALLSITE));
        let field = fields.field("message").unwrap();
        collector.record_str(&field, "first");
        assert_eq!(collector.message.as_deref(), Some("first"));

        // Second message field is ignored
        collector.record_str(&field, "second");
        assert_eq!(collector.message.as_deref(), Some("first"));
    }

    #[test]
    fn field_collector_non_message_fields_accumulate() {
        use tracing::field::FieldSet;

        let mut collector = FieldCollector::default();

        let fields = FieldSet::new(&["user"], tracing::callsite::Identifier(&NOP_CALLSITE));
        let field = fields.field("user").unwrap();
        collector.record_str(&field, "alice");

        assert!(collector.message.is_none());
        assert_eq!(collector.fields.len(), 1);
        assert_eq!(collector.fields[0].0, "user");
        assert_eq!(collector.fields[0].1, "alice");
    }

    #[test]
    fn rich_subscriber_builder_debug_output() {
        let builder = RichSubscriberBuilder::new();
        let debug = format!("{builder:?}");
        assert!(debug.contains("RichSubscriberBuilder"));
        assert!(debug.contains("show_timestamps"));
        assert!(debug.contains("level_filter"));
    }

    #[test]
    fn field_collector_record_typed_values() {
        use tracing::field::FieldSet;

        let mut collector = FieldCollector::default();
        let fields = FieldSet::new(
            &["flag", "count_i", "count_u", "ratio"],
            tracing::callsite::Identifier(&NOP_CALLSITE),
        );

        let flag = fields.field("flag").unwrap();
        collector.record_bool(&flag, true);

        let count_i = fields.field("count_i").unwrap();
        collector.record_i64(&count_i, -42);

        let count_u = fields.field("count_u").unwrap();
        collector.record_u64(&count_u, 100);

        let ratio = fields.field("ratio").unwrap();
        collector.record_f64(&ratio, 3.14);

        assert_eq!(collector.fields.len(), 4);
        assert_eq!(
            collector.fields[0],
            ("flag".to_string(), "true".to_string())
        );
        assert_eq!(
            collector.fields[1],
            ("count_i".to_string(), "-42".to_string())
        );
        assert_eq!(
            collector.fields[2],
            ("count_u".to_string(), "100".to_string())
        );
        assert_eq!(
            collector.fields[3],
            ("ratio".to_string(), "3.14".to_string())
        );
    }

    #[test]
    fn field_collector_record_debug_format() {
        use tracing::field::FieldSet;

        let mut collector = FieldCollector::default();
        let fields = FieldSet::new(&["data"], tracing::callsite::Identifier(&NOP_CALLSITE));
        let field = fields.field("data").unwrap();
        collector.record_debug(&field, &vec![1, 2, 3]);

        assert_eq!(collector.fields.len(), 1);
        assert_eq!(collector.fields[0].0, "data");
        assert_eq!(collector.fields[0].1, "[1, 2, 3]");
    }

    #[test]
    fn builder_default_matches_new() {
        let def = RichSubscriberBuilder::default();
        let new = RichSubscriberBuilder::new();
        assert_eq!(def.show_timestamps, new.show_timestamps);
        assert_eq!(def.show_targets, new.show_targets);
        assert_eq!(def.show_file_line, new.show_file_line);
        assert_eq!(def.max_width, new.max_width);
        assert_eq!(def.level_filter, new.level_filter);
    }

    #[test]
    fn builder_with_max_width_none_clears() {
        let builder = RichSubscriberBuilder::new()
            .with_max_width(Some(80))
            .with_max_width(None);
        assert_eq!(builder.max_width, None);
    }

    // Minimal callsite for field tests.
    static NOP_CALLSITE: NopCallsite = NopCallsite;

    struct NopCallsite;

    impl tracing::callsite::Callsite for NopCallsite {
        fn set_interest(&self, _interest: tracing::subscriber::Interest) {}
        fn metadata(&self) -> &tracing::Metadata<'_> {
            static META: tracing::Metadata<'static> = tracing::Metadata::new(
                "nop",
                "test",
                Level::INFO,
                None,
                None,
                None,
                tracing::field::FieldSet::new(
                    &[],
                    tracing::callsite::Identifier(&NOP_CALLSITE_INNER),
                ),
                tracing::metadata::Kind::EVENT,
            );
            &META
        }
    }

    static NOP_CALLSITE_INNER: NopCallsite = NopCallsite;
}
