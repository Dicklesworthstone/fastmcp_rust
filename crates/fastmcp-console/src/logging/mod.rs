//! Rich log formatting module.
//!
//! This module provides rich-formatted logging capabilities:
//! - [`RichLogFormatter`] - Transforms log events into styled output
//! - [`RichLogger`] - A `log` crate logger implementation
//! - [`RichSubscriberBuilder`] - Tracing subscriber builder
//!
//! # Architecture
//!
//! The logging system is designed to be context-aware:
//! - In **human context** (interactive terminal): Rich styling with colors, icons
//! - In **agent context** (machine parsing): Plain text output
//!
//! # Example
//!
//! ```ignore
//! use fastmcp_console::logging::{RichLogFormatter, LogEvent, LogLevel};
//!
//! let formatter = RichLogFormatter::detect();
//! let event = LogEvent::new(LogLevel::Info, "Server started")
//!     .with_target("fastmcp::server");
//!
//! let line = formatter.format_line(&event);
//! eprintln!("{}", line);
//! ```

mod formatter;
mod logger;
mod subscriber;

pub use formatter::{FormattedLog, LogEvent, LogLevel, RichLogFormatter};
pub use logger::{RichLogger, RichLoggerBuilder};
pub use subscriber::{RichLayer, RichSubscriberBuilder};
