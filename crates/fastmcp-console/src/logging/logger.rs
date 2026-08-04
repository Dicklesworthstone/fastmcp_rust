//! Rich-formatted log output to stderr.
//!
//! Provides a `log` crate compatible logger that uses [`RichLogFormatter`]
//! for styled output.
//!
//! # Usage
//!
//! The simplest way to use the rich logger:
//!
//! ```ignore
//! use fastmcp_console::logging::RichLogger;
//! use log::Level;
//!
//! // Simple initialization
//! RichLogger::init(Level::Info);
//!
//! // Or use the builder for more control
//! RichLoggerBuilder::new()
//!     .level(Level::Debug)
//!     .with_timestamps(true)
//!     .with_targets(true)
//!     .init();
//! ```

use std::fmt;

use log::{Level, LevelFilter, Log, Metadata, Record};
use time::{OffsetDateTime, format_description};

use super::{LogEvent, LogLevel, RichLogFormatter};
use crate::console::{
    DEFAULT_LOG_MESSAGE_MAX_CHARS, DEFAULT_TERMINAL_FIELD_MAX_CHARS, FastMcpConsole,
    bounded_redacted_terminal_text, strip_markup,
};
use crate::detection::DisplayContext;

const LOG_SOURCE_CAPTURE_MULTIPLIER: usize = 4;

struct BoundedMessageWriter {
    output: String,
    remaining_chars: usize,
    truncated: bool,
}

impl BoundedMessageWriter {
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

impl fmt::Write for BoundedMessageWriter {
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

fn bounded_record_message(arguments: &fmt::Arguments<'_>) -> String {
    let capture_limit = DEFAULT_LOG_MESSAGE_MAX_CHARS.saturating_mul(LOG_SOURCE_CAPTURE_MULTIPLIER);
    let mut writer = BoundedMessageWriter::new(capture_limit);
    let _ = fmt::write(&mut writer, *arguments);
    writer.finish()
}

/// Rich-formatted logger that writes to stderr.
///
/// This logger uses the [`RichLogFormatter`] to produce styled output
/// when running in human context, and plain text when running in agent context.
pub struct RichLogger {
    console: FastMcpConsole,
    formatter: RichLogFormatter,
    level_filter: LevelFilter,
    show_timestamps: bool,
}

impl RichLogger {
    /// Create a new rich logger with the given minimum level.
    #[must_use]
    pub fn new(min_level: Level) -> Self {
        RichLoggerBuilder::new().level(min_level).build()
    }

    /// Create a logger using the builder pattern.
    #[must_use]
    pub fn builder() -> RichLoggerBuilder {
        RichLoggerBuilder::new()
    }

    /// Initialize as the global logger.
    ///
    /// Returns an error if a logger has already been set.
    pub fn init(min_level: Level) -> Result<(), log::SetLoggerError> {
        let logger = Box::new(Self::new(min_level));
        log::set_boxed_logger(logger)?;
        log::set_max_level(min_level.to_level_filter());
        Ok(())
    }

    /// Initialize as the global logger, ignoring errors if already set.
    pub fn try_init(min_level: Level) {
        let _ = Self::init(min_level);
    }

    /// Convert a log::Record to a LogEvent.
    fn record_to_event(&self, record: &Record) -> LogEvent {
        let level = LogLevel::from(record.level());
        let message = bounded_record_message(record.args());

        let target = bounded_redacted_terminal_text(
            record.target(),
            DEFAULT_TERMINAL_FIELD_MAX_CHARS.saturating_mul(LOG_SOURCE_CAPTURE_MULTIPLIER),
        );
        let mut event = LogEvent::new(level, message).with_target(target);

        // Add timestamp if enabled
        if self.show_timestamps {
            let now = OffsetDateTime::now_utc();
            // Format: HH:MM:SS
            if let Ok(fmt) = format_description::parse("[hour]:[minute]:[second]") {
                if let Ok(ts) = now.format(&fmt) {
                    event = event.with_timestamp(ts);
                }
            }
        }

        if let Some(file) = record.file() {
            event = event.with_file(bounded_redacted_terminal_text(
                file,
                DEFAULT_TERMINAL_FIELD_MAX_CHARS.saturating_mul(LOG_SOURCE_CAPTURE_MULTIPLIER),
            ));
        }
        if let Some(line) = record.line() {
            event = event.with_line(line);
        }

        event
    }
}

/// Builder for configuring the rich logger.
///
/// # Example
///
/// ```ignore
/// use fastmcp_console::logging::RichLoggerBuilder;
/// use log::Level;
///
/// RichLoggerBuilder::new()
///     .level(Level::Debug)
///     .with_timestamps(true)
///     .with_targets(true)
///     .init()
///     .expect("Failed to initialize logger");
/// ```
#[derive(Debug)]
pub struct RichLoggerBuilder {
    level_filter: LevelFilter,
    context: Option<DisplayContext>,
    show_timestamps: bool,
    show_targets: bool,
    show_file_line: bool,
    max_width: Option<usize>,
}

impl Default for RichLoggerBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl RichLoggerBuilder {
    /// Create a new builder with default settings.
    #[must_use]
    pub fn new() -> Self {
        Self {
            level_filter: LevelFilter::Info,
            context: None,
            show_timestamps: true,
            show_targets: true,
            show_file_line: false,
            max_width: None,
        }
    }

    /// Set the minimum log level.
    #[must_use]
    pub fn level(mut self, level: Level) -> Self {
        self.level_filter = level.to_level_filter();
        self
    }

    /// Set the minimum log level from a LevelFilter.
    #[must_use]
    pub fn level_filter(mut self, filter: LevelFilter) -> Self {
        self.level_filter = filter;
        self
    }

    /// Set the display context used by both formatting and output.
    ///
    /// When omitted, the context is auto-detected at build time.
    #[must_use]
    pub fn with_context(mut self, context: DisplayContext) -> Self {
        self.context = Some(context);
        self
    }

    /// Set whether to show timestamps.
    #[must_use]
    pub fn with_timestamps(mut self, show: bool) -> Self {
        self.show_timestamps = show;
        self
    }

    /// Set whether to show target/module paths.
    #[must_use]
    pub fn with_targets(mut self, show: bool) -> Self {
        self.show_targets = show;
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
        self.max_width = width;
        self
    }

    /// Build the logger without installing it.
    #[must_use]
    pub fn build(self) -> RichLogger {
        let context = self.context.unwrap_or_else(DisplayContext::detect);
        let theme = crate::theme::theme();

        let formatter = RichLogFormatter::new(theme, context)
            .with_timestamp(self.show_timestamps)
            .with_target(self.show_targets)
            .with_file_line(self.show_file_line)
            .with_max_width(self.max_width);

        RichLogger {
            console: FastMcpConsole::with_enabled(context.is_human()),
            formatter,
            level_filter: self.level_filter,
            show_timestamps: self.show_timestamps,
        }
    }

    /// Build and install as the global logger.
    ///
    /// Returns an error if a logger has already been set.
    pub fn init(self) -> Result<(), log::SetLoggerError> {
        let level_filter = self.level_filter;
        let logger = Box::new(self.build());
        log::set_boxed_logger(logger)?;
        log::set_max_level(level_filter);
        Ok(())
    }

    /// Build and install, ignoring errors if already set.
    pub fn try_init(self) {
        let _ = self.init();
    }
}

impl Log for RichLogger {
    fn enabled(&self, metadata: &Metadata) -> bool {
        self.level_filter
            .to_level()
            .is_some_and(|level| metadata.level() <= level)
    }

    fn log(&self, record: &Record) {
        if !self.enabled(record.metadata()) {
            return;
        }

        let event = self.record_to_event(record);
        let line = self.formatter.format_line(&event);

        if self.console.is_rich() && self.formatter.should_use_rich() {
            self.console.print(&line);
        } else if self.formatter.should_use_rich() {
            self.console.print_plain(&strip_markup(&line));
        } else {
            self.console.print_plain(&line);
        }
    }

    fn flush(&self) {}
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex};

    struct CountingDisplay<'a> {
        visits: &'a AtomicUsize,
    }

    impl fmt::Display for CountingDisplay<'_> {
        fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            loop {
                self.visits.fetch_add(1, Ordering::Relaxed);
                formatter.write_str("x")?;
            }
        }
    }

    #[derive(Clone)]
    struct SharedWriter(Arc<Mutex<Vec<u8>>>);

    impl std::io::Write for SharedWriter {
        fn write(&mut self, buffer: &[u8]) -> std::io::Result<usize> {
            self.0
                .lock()
                .expect("shared output lock should not be poisoned")
                .extend_from_slice(buffer);
            Ok(buffer.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn record_message_capture_is_bounded_before_log_event_allocation() {
        let huge = "x".repeat(DEFAULT_LOG_MESSAGE_MAX_CHARS * 16);
        let captured = bounded_record_message(&format_args!("prefix:{huge}"));

        assert!(
            captured.chars().count()
                <= DEFAULT_LOG_MESSAGE_MAX_CHARS * LOG_SOURCE_CAPTURE_MULTIPLIER + 3
        );
        assert!(captured.starts_with("prefix:"));
        assert!(captured.ends_with("..."));
    }

    #[test]
    fn bounded_message_writer_short_circuits_adversarial_display() {
        let visits = AtomicUsize::new(0);
        let value = CountingDisplay { visits: &visits };
        let mut writer = BoundedMessageWriter::new(8);

        let result = fmt::write(&mut writer, format_args!("{value}"));
        let captured = writer.finish();

        assert!(result.is_err(), "exhaustion should stop fmt traversal");
        assert_eq!(visits.load(Ordering::Relaxed), 9);
        assert_eq!(captured, "xxxxxxxx...");
    }

    #[test]
    fn test_rich_logger_enabled() {
        let logger = RichLogger::new(Level::Info);

        // Info and above should be enabled
        assert!(
            logger.enabled(
                &log::Metadata::builder()
                    .level(Level::Error)
                    .target("test")
                    .build()
            )
        );
        assert!(
            logger.enabled(
                &log::Metadata::builder()
                    .level(Level::Warn)
                    .target("test")
                    .build()
            )
        );
        assert!(
            logger.enabled(
                &log::Metadata::builder()
                    .level(Level::Info)
                    .target("test")
                    .build()
            )
        );

        // Debug and Trace should be disabled
        assert!(
            !logger.enabled(
                &log::Metadata::builder()
                    .level(Level::Debug)
                    .target("test")
                    .build()
            )
        );
        assert!(
            !logger.enabled(
                &log::Metadata::builder()
                    .level(Level::Trace)
                    .target("test")
                    .build()
            )
        );
    }

    #[test]
    fn test_rich_logger_new() {
        let logger = RichLogger::new(Level::Debug);
        // Should not panic
        assert!(
            logger.enabled(
                &log::Metadata::builder()
                    .level(Level::Debug)
                    .target("test")
                    .build()
            )
        );
    }

    #[test]
    fn test_builder_default() {
        let builder = RichLoggerBuilder::default();
        // Default level should be Info
        assert_eq!(builder.level_filter, LevelFilter::Info);
        assert_eq!(builder.context, None);
        assert!(builder.show_timestamps);
        assert!(builder.show_targets);
        assert!(!builder.show_file_line);
    }

    #[test]
    fn test_builder_level() {
        let builder = RichLoggerBuilder::new().level(Level::Debug);
        assert_eq!(builder.level_filter, LevelFilter::Debug);
    }

    #[test]
    fn test_builder_level_filter() {
        let builder = RichLoggerBuilder::new().level_filter(LevelFilter::Warn);
        assert_eq!(builder.level_filter, LevelFilter::Warn);
    }

    #[test]
    fn test_builder_level_filter_off_disables_every_level_and_emits_nothing() {
        let output = Arc::new(Mutex::new(Vec::new()));
        let mut logger = RichLoggerBuilder::new()
            .level_filter(LevelFilter::Off)
            .with_context(DisplayContext::new_agent())
            .with_timestamps(false)
            .build();
        logger.console = FastMcpConsole::with_writer(SharedWriter(Arc::clone(&output)), false);

        for level in [
            Level::Error,
            Level::Warn,
            Level::Info,
            Level::Debug,
            Level::Trace,
        ] {
            let metadata = log::Metadata::builder().level(level).target("test").build();
            assert!(!logger.enabled(&metadata));
        }

        let record = log::Record::builder()
            .args(format_args!("must not be emitted"))
            .level(Level::Error)
            .target("test")
            .build();
        logger.log(&record);

        assert!(
            output
                .lock()
                .expect("shared output lock should not be poisoned")
                .is_empty()
        );
    }

    #[test]
    fn builder_context_keeps_formatter_and_output_mode_in_sync() {
        let agent = RichLoggerBuilder::new()
            .with_context(DisplayContext::new_agent())
            .build();
        assert!(!agent.formatter.should_use_rich());
        assert!(!agent.console.is_rich());

        let human = RichLoggerBuilder::new()
            .with_context(DisplayContext::new_human())
            .build();
        assert!(human.formatter.should_use_rich());
        assert!(human.console.is_rich());
    }

    #[test]
    fn test_builder_timestamps() {
        let builder = RichLoggerBuilder::new().with_timestamps(false);
        assert!(!builder.show_timestamps);
    }

    #[test]
    fn test_builder_targets() {
        let builder = RichLoggerBuilder::new().with_targets(false);
        assert!(!builder.show_targets);
    }

    #[test]
    fn test_builder_file_line() {
        let builder = RichLoggerBuilder::new().with_file_line(true);
        assert!(builder.show_file_line);
    }

    #[test]
    fn test_builder_max_width() {
        let builder = RichLoggerBuilder::new().with_max_width(Some(80));
        assert_eq!(builder.max_width, Some(80));
    }

    #[test]
    fn test_builder_build() {
        let logger = RichLoggerBuilder::new()
            .level(Level::Debug)
            .with_timestamps(false)
            .build();

        // Logger should be configured
        assert!(
            logger.enabled(
                &log::Metadata::builder()
                    .level(Level::Debug)
                    .target("test")
                    .build()
            )
        );
        assert!(!logger.show_timestamps);
    }

    #[test]
    fn test_logger_builder_method() {
        let builder = RichLogger::builder();
        // Should create a default builder
        assert_eq!(builder.level_filter, LevelFilter::Info);
    }

    #[test]
    fn test_record_to_event_with_timestamp_and_location() {
        let logger = RichLogger::new(Level::Trace);

        let record = log::Record::builder()
            .args(format_args!("hello world"))
            .level(Level::Warn)
            .target("fastmcp_rust::logger")
            .file(Some("src/logger.rs"))
            .line(Some(77))
            .build();

        let event = logger.record_to_event(&record);
        assert_eq!(event.level, LogLevel::Warn);
        assert_eq!(event.message, "hello world");
        assert_eq!(event.target.as_deref(), Some("fastmcp_rust::logger"));
        assert_eq!(event.file.as_deref(), Some("src/logger.rs"));
        assert_eq!(event.line, Some(77));
        assert!(event.timestamp.is_some());
    }

    #[test]
    fn test_record_to_event_without_timestamp_or_location() {
        let logger = RichLoggerBuilder::new().with_timestamps(false).build();

        let record = log::Record::builder()
            .args(format_args!("no timestamp"))
            .level(Level::Info)
            .target("fastmcp_rust::logger")
            .build();

        let event = logger.record_to_event(&record);
        assert_eq!(event.level, LogLevel::Info);
        assert_eq!(event.message, "no timestamp");
        assert_eq!(event.timestamp, None);
        assert_eq!(event.file, None);
        assert_eq!(event.line, None);
    }

    #[test]
    fn test_log_and_flush_paths() {
        let logger = RichLoggerBuilder::new()
            .level(Level::Info)
            .with_timestamps(false)
            .build();

        let debug_record = log::Record::builder()
            .args(format_args!("ignored debug"))
            .level(Level::Debug)
            .target("fastmcp_rust::logger")
            .build();
        logger.log(&debug_record);

        let error_record = log::Record::builder()
            .args(format_args!("emitted error"))
            .level(Level::Error)
            .target("fastmcp_rust::logger")
            .build();
        logger.log(&error_record);

        logger.flush();
    }
}
