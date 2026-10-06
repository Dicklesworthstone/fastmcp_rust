#![forbid(unsafe_code)]
#![doc = include_str!("../README.md")]

pub mod console;
pub mod detection;
pub mod theme;

pub mod banner;
// `renderers` is implied by `legacy-2024-11-05`, `tasks` and `apps`; see the
// feature's comment in Cargo.toml for why the three-way `any(..)` was named.
#[cfg(feature = "renderers")]
pub mod client;
pub mod diagnostics;
pub mod error;
#[cfg(feature = "renderers")]
pub mod handlers;
pub mod logging;
pub mod stats;
pub mod status;
#[cfg(feature = "renderers")]
pub mod tables;
pub mod testing;
#[path = "client/traffic.rs"]
pub mod traffic;

pub use console::{UntrustedDisplayText, console};
pub mod config;

pub use config::ConsoleConfig;
pub use detection::{DisplayContext, is_agent_context, should_enable_rich};
pub use error::ErrorBoundary;
#[cfg(feature = "renderers")]
pub use handlers::{HandlerRegistryRenderer, ServerCapabilities};
pub use rich_rust;
pub use theme::theme;
pub use traffic::RequestResponseRenderer;

#[cfg(test)]
mod feature_surface_tests {
    #[cfg(not(feature = "renderers"))]
    #[test]
    fn empty_graph_exposes_only_generic_console_surface() {
        let console = super::console::FastMcpConsole::with_enabled(false);
        let _ = super::ConsoleConfig::new();
        let _ = super::ErrorBoundary::new(&console);
        let _ = super::logging::RichLoggerBuilder::new();
        let _ = super::RequestResponseRenderer::new(super::DisplayContext::new_agent());
    }

    #[cfg(feature = "renderers")]
    #[test]
    fn protocol_rendering_surface_is_enabled_with_a_protocol_feature() {
        let context = super::DisplayContext::new_agent();
        let _ = super::client::ClientInfoRenderer::new(context.clone());
        let _ = super::handlers::HandlerRegistryRenderer::new(context.clone());
        let _ = super::handlers::ServerCapabilities::new();
        let _ = super::tables::ToolTableRenderer::new(context);
    }
}
