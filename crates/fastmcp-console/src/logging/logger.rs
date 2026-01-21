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

use log::{Level, LevelFilter, Log, Metadata, Record};
use time::{OffsetDateTime, format_description};

use super::{LogEvent, LogLevel, RichLogFormatter};
use crate::console::FastMcpConsole;
use crate::detection::DisplayContext;

/// Rich-formatted logger that writes to stderr.
///
/// This logger uses the [`RichLogFormatter`] to produce styled output
/// when running in human context, and plain text when running in agent context.
pub struct RichLogger {
    console: &'static FastMcpConsole,
    formatter: RichLogFormatter,
    min_level: Level,
    show_timestamps: bool,
}

impl RichLogger {
    /// Create a new rich logger with the given minimum level.
    #[must_use]
    pub fn new(min_level: Level) -> Self {
        Self {
            console: crate::console::console(),
            formatter: RichLogFormatter::detect(),
            min_level,
            show_timestamps: true,
        }
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
        let message = format!("{}", record.args());

        let mut event = LogEvent::new(level, message).with_target(record.target());

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
            event = event.with_file(file);
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
    min_level: Level,
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
            min_level: Level::Info,
            show_timestamps: true,
            show_targets: true,
            show_file_line: false,
            max_width: None,
        }
    }

    /// Set the minimum log level.
    #[must_use]
    pub fn level(mut self, level: Level) -> Self {
        self.min_level = level;
        self
    }

    /// Set the minimum log level from a LevelFilter.
    #[must_use]
    pub fn level_filter(mut self, filter: LevelFilter) -> Self {
        self.min_level = filter.to_level().unwrap_or(Level::Trace);
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
        let context = DisplayContext::detect();
        let theme = crate::theme::theme();

        let formatter = RichLogFormatter::new(theme, context)
            .with_timestamp(self.show_timestamps)
            .with_target(self.show_targets)
            .with_file_line(self.show_file_line)
            .with_max_width(self.max_width);

        RichLogger {
            console: crate::console::console(),
            formatter,
            min_level: self.min_level,
            show_timestamps: self.show_timestamps,
        }
    }

    /// Build and install as the global logger.
    ///
    /// Returns an error if a logger has already been set.
    pub fn init(self) -> Result<(), log::SetLoggerError> {
        let level = self.min_level;
        let logger = Box::new(self.build());
        log::set_boxed_logger(logger)?;
        log::set_max_level(level.to_level_filter());
        Ok(())
    }

    /// Build and install, ignoring errors if already set.
    pub fn try_init(self) {
        let _ = self.init();
    }
}

impl Log for RichLogger {
    fn enabled(&self, metadata: &Metadata) -> bool {
        metadata.level() <= self.min_level
    }

    fn log(&self, record: &Record) {
        if !self.enabled(record.metadata()) {
            return;
        }

        let event = self.record_to_event(record);
        let line = self.formatter.format_line(&event);

        if self.console.is_rich() {
            self.console.print(&line);
        } else {
            eprintln!("{}", crate::console::strip_markup(&line));
        }
    }

    fn flush(&self) {}
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rich_logger_enabled() {
        let logger = RichLogger::new(Level::Info);

        // Info and above should be enabled
        assert!(logger.enabled(&log::Metadata::builder().level(Level::Error).target("test").build()));
        assert!(logger.enabled(&log::Metadata::builder().level(Level::Warn).target("test").build()));
        assert!(logger.enabled(&log::Metadata::builder().level(Level::Info).target("test").build()));

        // Debug and Trace should be disabled
        assert!(!logger.enabled(&log::Metadata::builder().level(Level::Debug).target("test").build()));
        assert!(!logger.enabled(&log::Metadata::builder().level(Level::Trace).target("test").build()));
    }

    #[test]
    fn test_rich_logger_new() {
        let logger = RichLogger::new(Level::Debug);
        // Should not panic
        assert!(logger.enabled(&log::Metadata::builder().level(Level::Debug).target("test").build()));
    }

    #[test]
    fn test_builder_default() {
        let builder = RichLoggerBuilder::default();
        // Default level should be Info
        assert_eq!(builder.min_level, Level::Info);
        assert!(builder.show_timestamps);
        assert!(builder.show_targets);
        assert!(!builder.show_file_line);
    }

    #[test]
    fn test_builder_level() {
        let builder = RichLoggerBuilder::new().level(Level::Debug);
        assert_eq!(builder.min_level, Level::Debug);
    }

    #[test]
    fn test_builder_level_filter() {
        let builder = RichLoggerBuilder::new().level_filter(LevelFilter::Warn);
        assert_eq!(builder.min_level, Level::Warn);
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
        assert!(logger.enabled(&log::Metadata::builder().level(Level::Debug).target("test").build()));
        assert!(!logger.show_timestamps);
    }

    #[test]
    fn test_logger_builder_method() {
        let builder = RichLogger::builder();
        // Should create a default builder
        assert_eq!(builder.min_level, Level::Info);
    }
}
