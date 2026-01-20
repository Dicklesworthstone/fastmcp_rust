#![forbid(unsafe_code)]
#![doc = include_str!("../README.md")]

pub mod console;
pub mod detection;
pub mod theme;

// Modules will be added as they are implemented:
pub mod banner;      // Startup banner
pub mod status;      // Request logging
// pub mod progress;    // Progress indicators
pub mod diagnostics; // Error formatting
pub mod logging;     // Rich log formatter
pub mod tables;      // Info tables
pub mod stats;       // Runtime metrics
pub mod testing;     // Test utilities

pub use console::console;
pub mod config;

pub use config::ConsoleConfig;
pub use detection::{is_agent_context, should_enable_rich, DisplayContext};
pub use rich_rust;
pub use theme::theme;
