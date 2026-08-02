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

use crate::console::{
    DEFAULT_LOG_MESSAGE_MAX_CHARS, DEFAULT_TERMINAL_FIELD_MAX_CHARS, FastMcpConsole,
    bounded_redacted_terminal_text, strip_markup,
};
use crate::detection::DisplayContext;
use crate::theme::FastMcpTheme;

use super::{LogEvent, LogLevel, RichLogFormatter};

const MAX_CAPTURE_FIELDS: usize = 64;
const LOG_SOURCE_CAPTURE_MULTIPLIER: usize = 4;

struct BoundedValueWriter {
    output: String,
    remaining_chars: usize,
    truncated: bool,
}

impl BoundedValueWriter {
    fn new(max_chars: usize) -> Self {
        Self {
            output: String::with_capacity(max_chars.min(1_024)),
            remaining_chars: max_chars,
            truncated: false,
        }
    }

    fn finish(mut self) -> String {
        if self.truncated {
            self.output.push_str("...");
        }
        self.output
    }
}

impl fmt::Write for BoundedValueWriter {
    fn write_str(&mut self, value: &str) -> fmt::Result {
        if self.remaining_chars == 0 {
            self.truncated |= !value.is_empty();
            return if value.is_empty() {
                Ok(())
            } else {
                Err(fmt::Error)
            };
        }

        let mut characters = value.chars();
        for character in characters.by_ref().take(self.remaining_chars) {
            self.output.push(character);
            self.remaining_chars -= 1;
        }
        if characters.next().is_some() {
            self.truncated = true;
            Err(fmt::Error)
        } else {
            Ok(())
        }
    }
}

fn bounded_source_text(value: &str, max_chars: usize) -> String {
    let mut writer = BoundedValueWriter::new(max_chars);
    let _ = fmt::Write::write_str(&mut writer, value);
    writer.finish()
}

fn bounded_debug_value(value: &dyn fmt::Debug, max_chars: usize) -> String {
    let mut writer = BoundedValueWriter::new(max_chars);
    let _ = fmt::write(&mut writer, format_args!("{value:?}"));
    writer.finish()
}

/// A tracing layer that renders events using rich formatting.
pub struct RichLayer {
    formatter: RichLogFormatter,
    console: LayerConsole,
    include_timestamps: bool,
}

enum LayerConsole {
    Global(&'static FastMcpConsole),
    Owned(FastMcpConsole),
}

impl LayerConsole {
    fn get(&self) -> &FastMcpConsole {
        match self {
            Self::Global(console) => console,
            Self::Owned(console) => console,
        }
    }
}

impl RichLayer {
    /// Create a new rich layer.
    #[must_use]
    pub fn new(formatter: RichLogFormatter, include_timestamps: bool) -> Self {
        Self {
            formatter,
            console: LayerConsole::Global(crate::console::console()),
            include_timestamps,
        }
    }

    /// Route this layer through an owned console instead of the global console.
    ///
    /// Owning the console keeps custom writers and explicit rich/plain modes
    /// usable by global subscribers without requiring a leaked reference.
    #[must_use]
    pub fn with_console(mut self, console: FastMcpConsole) -> Self {
        self.console = LayerConsole::Owned(console);
        self
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
    fn record_value(&mut self, field: &Field, value: &str) {
        let display_limit = if field.name() == "message" {
            DEFAULT_LOG_MESSAGE_MAX_CHARS
        } else {
            DEFAULT_TERMINAL_FIELD_MAX_CHARS
        };
        let capture_limit = display_limit.saturating_mul(LOG_SOURCE_CAPTURE_MULTIPLIER);
        let value = bounded_source_text(value, capture_limit);
        if field.name() == "message" {
            if self.message.is_none() {
                self.message = Some(value);
            }
        } else if self.fields.len() < MAX_CAPTURE_FIELDS {
            let key = bounded_redacted_terminal_text(
                field.name(),
                DEFAULT_TERMINAL_FIELD_MAX_CHARS.saturating_mul(LOG_SOURCE_CAPTURE_MULTIPLIER),
            );
            self.fields.push((key, value));
        }
    }
}

impl Visit for FieldCollector {
    fn record_debug(&mut self, field: &Field, value: &dyn fmt::Debug) {
        let display_limit = if field.name() == "message" {
            DEFAULT_LOG_MESSAGE_MAX_CHARS
        } else {
            DEFAULT_TERMINAL_FIELD_MAX_CHARS
        };
        let value = bounded_debug_value(
            value,
            display_limit.saturating_mul(LOG_SOURCE_CAPTURE_MULTIPLIER),
        );
        self.record_value(field, &value);
    }

    fn record_str(&mut self, field: &Field, value: &str) {
        self.record_value(field, value);
    }

    fn record_bool(&mut self, field: &Field, value: bool) {
        self.record_value(field, if value { "true" } else { "false" });
    }

    fn record_i64(&mut self, field: &Field, value: i64) {
        self.record_value(field, &value.to_string());
    }

    fn record_u64(&mut self, field: &Field, value: u64) {
        self.record_value(field, &value.to_string());
    }

    fn record_f64(&mut self, field: &Field, value: f64) {
        self.record_value(field, &value.to_string());
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
                .take(MAX_CAPTURE_FIELDS)
                .map(|span| bounded_source_text(span.name(), DEFAULT_TERMINAL_FIELD_MAX_CHARS))
                .collect();
            if !spans.is_empty() && collector.fields.len() < MAX_CAPTURE_FIELDS {
                collector
                    .fields
                    .push(("span".to_string(), spans.join("::")));
            }
        }

        let level = LogLevel::from(*metadata.level());
        let message = collector.message.unwrap_or_else(|| {
            bounded_redacted_terminal_text(
                metadata.name(),
                DEFAULT_LOG_MESSAGE_MAX_CHARS.saturating_mul(LOG_SOURCE_CAPTURE_MULTIPLIER),
            )
        });

        let target = bounded_redacted_terminal_text(
            metadata.target(),
            DEFAULT_TERMINAL_FIELD_MAX_CHARS.saturating_mul(LOG_SOURCE_CAPTURE_MULTIPLIER),
        );
        let mut log_event = LogEvent::new(level, message).with_target(target);

        if let Some(ts) = self.timestamp_string() {
            log_event = log_event.with_timestamp(ts);
        }
        if let Some(file) = metadata.file() {
            log_event = log_event.with_file(bounded_redacted_terminal_text(
                file,
                DEFAULT_TERMINAL_FIELD_MAX_CHARS.saturating_mul(LOG_SOURCE_CAPTURE_MULTIPLIER),
            ));
        }
        if let Some(line) = metadata.line() {
            log_event = log_event.with_line(line);
        }
        log_event.fields = collector.fields;

        let line = self.formatter.format_line(&log_event);
        let console = self.console.get();
        if console.is_rich() && self.formatter.should_use_rich() {
            console.print(&line);
        } else if self.formatter.should_use_rich() {
            console.print_plain(&strip_markup(&line));
        } else {
            console.print_plain(&line);
        }
    }
}

/// Builder for configuring a rich tracing subscriber.
pub struct RichSubscriberBuilder {
    theme: Option<&'static FastMcpTheme>,
    context: Option<DisplayContext>,
    console: Option<FastMcpConsole>,
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
            context: None,
            console: None,
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

    /// Set the display context used by both formatting and default output.
    ///
    /// When omitted, the context is auto-detected at build time and output is
    /// routed through the global console. When set explicitly and no custom
    /// console is supplied, the subscriber owns a stderr console configured
    /// for the requested rich or plain mode.
    #[must_use]
    pub fn with_context(mut self, context: DisplayContext) -> Self {
        self.context = Some(context);
        self
    }

    /// Route subscriber output through an owned console.
    ///
    /// If [`with_context`](Self::with_context) is omitted, the injected
    /// console's rich/plain mode also selects the formatting context. If both
    /// are supplied, the explicit context controls formatting while the
    /// console controls final output rendering.
    #[must_use]
    pub fn with_console(mut self, console: FastMcpConsole) -> Self {
        self.console = Some(console);
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
        let (level_filter, layer) = self.build_layer();

        tracing_subscriber::registry()
            .with(level_filter)
            .with(layer)
    }

    fn build_layer(self) -> (LevelFilter, RichLayer) {
        let explicit_context = self.context;
        let context = explicit_context.unwrap_or_else(|| {
            self.console
                .as_ref()
                .map_or_else(DisplayContext::detect, |console| {
                    if console.is_rich() {
                        DisplayContext::new_human()
                    } else {
                        DisplayContext::new_agent()
                    }
                })
        });
        let theme = self.theme.unwrap_or_else(crate::theme::theme);

        let formatter = RichLogFormatter::new(theme, context)
            .with_timestamp(self.show_timestamps)
            .with_target(self.show_targets)
            .with_file_line(self.show_file_line)
            .with_max_width(self.max_width);

        let console = if let Some(console) = self.console {
            LayerConsole::Owned(console)
        } else if explicit_context.is_some() {
            LayerConsole::Owned(FastMcpConsole::with_enabled(context.is_human()))
        } else {
            LayerConsole::Global(crate::console::console())
        };
        let layer = RichLayer {
            formatter,
            console,
            include_timestamps: self.show_timestamps,
        };

        (self.level_filter, layer)
    }

    /// Build and install as the global subscriber.
    pub fn init(self) -> Result<(), tracing::subscriber::SetGlobalDefaultError> {
        let subscriber = self.build();
        tracing::subscriber::set_global_default(subscriber)
    }
}

impl fmt::Debug for RichSubscriberBuilder {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RichSubscriberBuilder")
            .field("theme", &self.theme)
            .field("context", &self.context)
            .field(
                "console_mode",
                &self.console.as_ref().map(|console| {
                    if console.is_rich() {
                        DisplayContext::new_human()
                    } else {
                        DisplayContext::new_agent()
                    }
                }),
            )
            .field("show_timestamps", &self.show_timestamps)
            .field("show_targets", &self.show_targets)
            .field("show_file_line", &self.show_file_line)
            .field("max_width", &self.max_width)
            .field("level_filter", &self.level_filter)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use tracing::{Level, debug, event, info, info_span};

    struct EndlessDebugIterator<'a> {
        visits: &'a AtomicUsize,
    }

    impl fmt::Debug for EndlessDebugIterator<'_> {
        fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            for value in std::iter::repeat("x") {
                self.visits.fetch_add(1, Ordering::Relaxed);
                formatter.write_str(value)?;
            }
            Ok(())
        }
    }

    #[test]
    fn bounded_value_writer_short_circuits_adversarial_debug_iterator() {
        let visits = AtomicUsize::new(0);
        let value = EndlessDebugIterator { visits: &visits };

        let captured = bounded_debug_value(&value, 8);

        assert_eq!(visits.load(Ordering::Relaxed), 9);
        assert_eq!(captured, "xxxxxxxx...");
    }

    #[test]
    fn test_builder_defaults() {
        let builder = RichSubscriberBuilder::default();
        assert_eq!(builder.context, None);
        assert!(builder.console.is_none());
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
            .with_context(DisplayContext::new_agent())
            .with_timestamps(false)
            .with_targets(false)
            .with_file_line(true)
            .with_max_width(Some(64))
            .with_level_filter(LevelFilter::DEBUG);

        assert!(builder.theme.is_some());
        assert_eq!(builder.context, Some(DisplayContext::new_agent()));
        assert!(!builder.show_timestamps);
        assert!(!builder.show_targets);
        assert!(builder.show_file_line);
        assert_eq!(builder.max_width, Some(64));
        assert_eq!(builder.level_filter, LevelFilter::DEBUG);
    }

    #[test]
    fn explicit_context_controls_formatter_and_output_without_global_console() {
        for (context, rich) in [
            (DisplayContext::new_agent(), false),
            (DisplayContext::new_human(), true),
        ] {
            let (_, layer) = RichSubscriberBuilder::new()
                .with_context(context)
                .build_layer();

            assert_eq!(layer.formatter.should_use_rich(), rich);
            assert_eq!(layer.console.get().is_rich(), rich);
            assert!(matches!(&layer.console, LayerConsole::Owned(_)));
        }
    }

    #[test]
    fn explicit_context_overrides_ambient_detection() {
        let detected = DisplayContext::detect();
        let forced = if detected.is_human() {
            DisplayContext::new_agent()
        } else {
            DisplayContext::new_human()
        };

        let (_, layer) = RichSubscriberBuilder::new()
            .with_context(forced)
            .build_layer();

        assert_eq!(layer.formatter.should_use_rich(), forced.is_human());
        assert_eq!(layer.console.get().is_rich(), forced.is_human());
        assert_ne!(layer.formatter.should_use_rich(), detected.is_human());
        assert!(matches!(&layer.console, LayerConsole::Owned(_)));
    }

    #[test]
    fn injected_console_selects_context_without_ambient_detection() {
        for rich in [false, true] {
            let (_, layer) = RichSubscriberBuilder::new()
                .with_console(FastMcpConsole::with_enabled(rich))
                .build_layer();

            assert_eq!(layer.formatter.should_use_rich(), rich);
            assert_eq!(layer.console.get().is_rich(), rich);
            assert!(matches!(&layer.console, LayerConsole::Owned(_)));
        }
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
        assert_eq!(def.context, new.context);
        assert_eq!(def.console.is_some(), new.console.is_some());
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
