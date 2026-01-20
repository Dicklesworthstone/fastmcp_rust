//! Rich log formatting

use log::{Level, Log, Metadata, Record};
use rich_rust::prelude::*;
use crate::console::FastMcpConsole;

/// Rich-formatted log output to stderr
pub struct RichLogger {
    console: &'static FastMcpConsole,
    min_level: Level,
}

impl RichLogger {
    pub fn new(min_level: Level) -> Self {
        Self {
            console: crate::console(),
            min_level,
        }
    }

    pub fn init(min_level: Level) {
        let logger = Box::new(Self::new(min_level));
        log::set_boxed_logger(logger).ok();
        log::set_max_level(min_level.to_level_filter());
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

        let theme = self.console.theme();

        if self.console.is_rich() {
            let (icon, style) = match record.level() {
                Level::Error => ("✗", &theme.error_style),
                Level::Warn => ("⚠", &theme.warning_style),
                Level::Info => ("ℹ", &theme.info_style),
                Level::Debug => ("●", &theme.muted_style),
                Level::Trace => ("·", &theme.muted_style),
            };

            let target = if record.target().starts_with("fastmcp") {
                record.target().strip_prefix("fastmcp::").unwrap_or(record.target())
            } else {
                record.target()
            };

            self.console.print(&format!(
                "[{}]{}[/] [{}]{}[/] {}",
                style.color.as_ref().map(|c| c.triplet.unwrap_or_default().hex()).unwrap_or_default(),
                icon,
                theme.text_dim.triplet.unwrap_or_default().hex(),
                target,
                record.args()
            ));
        } else {
            let level_str = match record.level() {
                Level::Error => "ERROR",
                Level::Warn => "WARN",
                Level::Info => "INFO",
                Level::Debug => "DEBUG",
                Level::Trace => "TRACE",
            };

            eprintln!("[{}] {}: {}", level_str, record.target(), record.args());
        }
    }

    fn flush(&self) {}
}