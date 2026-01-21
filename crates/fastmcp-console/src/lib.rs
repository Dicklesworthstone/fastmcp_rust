#![forbid(unsafe_code)]
#![doc = include_str!("../README.md")]

pub mod console;
pub mod detection;
pub mod theme;

// Modules will be added as they are implemented:
pub mod banner; // Startup banner
pub mod client; // Client info rendering
pub mod status; // Request logging
// pub mod progress;    // Progress indicators
pub mod diagnostics; // Error formatting
pub mod error; // Error boundary wrapper
pub mod handlers; // Unified handler registry display
pub mod logging; // Rich log formatter (RichLogFormatter, RichLogger)
pub mod stats; // Runtime metrics
pub mod tables; // Info tables
pub mod testing; // Test utilities

pub use console::console;
pub mod config;

pub use client::RequestResponseRenderer;
pub use config::ConsoleConfig;
pub use detection::{DisplayContext, is_agent_context, should_enable_rich};
pub use error::ErrorBoundary;
pub use handlers::{HandlerRegistryRenderer, ServerCapabilities};
pub use rich_rust;
pub use theme::theme;
