#![forbid(unsafe_code)]
#![doc = include_str!("../README.md")]

pub mod console;
pub mod detection;
pub mod theme;

pub mod banner;
#[cfg(any(feature = "legacy-2024-11-05", feature = "tasks", feature = "apps"))]
pub mod client;
pub mod diagnostics;
pub mod error;
#[cfg(any(feature = "legacy-2024-11-05", feature = "tasks", feature = "apps"))]
pub mod handlers;
pub mod logging;
pub mod stats;
pub mod status;
#[cfg(any(feature = "legacy-2024-11-05", feature = "tasks", feature = "apps"))]
pub mod tables;
pub mod testing;
#[path = "client/traffic.rs"]
pub mod traffic;

pub use console::{UntrustedDisplayText, console};
pub mod config;

pub use config::ConsoleConfig;
pub use detection::{DisplayContext, is_agent_context, should_enable_rich};
pub use error::ErrorBoundary;
#[cfg(any(feature = "legacy-2024-11-05", feature = "tasks", feature = "apps"))]
pub use handlers::{HandlerRegistryRenderer, ServerCapabilities};
pub use rich_rust;
pub use theme::theme;
pub use traffic::RequestResponseRenderer;

#[cfg(test)]
mod feature_surface_tests {
    #[cfg(not(any(feature = "legacy-2024-11-05", feature = "tasks", feature = "apps")))]
    #[test]
    fn empty_graph_exposes_only_generic_console_surface() {
        let console = super::console::FastMcpConsole::with_enabled(false);
        let _ = super::ConsoleConfig::new();
        let _ = super::ErrorBoundary::new(&console);
        let _ = super::logging::RichLoggerBuilder::new();
        let _ = super::RequestResponseRenderer::new(super::DisplayContext::new_agent());
    }

    #[cfg(any(feature = "legacy-2024-11-05", feature = "tasks", feature = "apps"))]
    #[test]
    fn protocol_rendering_surface_is_enabled_with_a_protocol_feature() {
        let context = super::DisplayContext::new_agent();
        let _ = super::client::ClientInfoRenderer::new(context.clone());
        let _ = super::handlers::HandlerRegistryRenderer::new(context.clone());
        let _ = super::handlers::ServerCapabilities::new();
        let _ = super::tables::ToolTableRenderer::new(context);
    }
}
