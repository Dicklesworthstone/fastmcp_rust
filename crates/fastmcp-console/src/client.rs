//! Client info rendering for connection status display.
//!
//! Provides beautiful rendering of connected client information,
//! with plain-text fallback for agent contexts.

pub mod traffic;
pub use traffic::RequestResponseRenderer;

use fastmcp_protocol::{ClientCapabilities, ClientInfo};
use rich_rust::r#box::ROUNDED;
use rich_rust::prelude::*;

use crate::console::FastMcpConsole;
use crate::detection::DisplayContext;
use crate::theme::FastMcpTheme;

/// Renders client connection information.
///
/// Displays client name, version, and capabilities in a beautiful format
/// when a client connects or disconnects from the server.
#[derive(Debug, Clone)]
pub struct ClientInfoRenderer {
    theme: &'static FastMcpTheme,
    context: DisplayContext,
}

impl ClientInfoRenderer {
    /// Create a new renderer with explicit display context.
    #[must_use]
    pub fn new(context: DisplayContext) -> Self {
        Self {
            theme: crate::theme::theme(),
            context,
        }
    }

    /// Create a renderer using auto-detected display context.
    #[must_use]
    pub fn detect() -> Self {
        Self::new(DisplayContext::detect())
    }

    /// Render client connection notification.
    pub fn render_connected(&self, client: &ClientInfo, console: &FastMcpConsole) {
        if !self.should_use_rich(console) {
            self.render_connected_plain(client, console);
            return;
        }

        console.print(&format!(
            "\n[green bold]Client Connected[/]: [cyan]{}[/] [dim]v{}[/]",
            client.name, client.version
        ));
    }

    /// Render client connection with capabilities.
    pub fn render_connected_with_caps(
        &self,
        client: &ClientInfo,
        capabilities: &ClientCapabilities,
        console: &FastMcpConsole,
    ) {
        if !self.should_use_rich(console) {
            self.render_connected_with_caps_plain(client, capabilities, console);
            return;
        }

        console.print(&format!(
            "\n[green bold]Client Connected[/]: [cyan]{}[/] [dim]v{}[/]",
            client.name, client.version
        ));

        let caps = self.format_capabilities(capabilities);
        if !caps.is_empty() {
            console.print(&format!("  [dim]Capabilities:[/] {}", caps));
        }
    }

    /// Render client disconnection notification.
    pub fn render_disconnected(&self, client: &ClientInfo, console: &FastMcpConsole) {
        if !self.should_use_rich(console) {
            self.render_disconnected_plain(client, None, console);
            return;
        }

        console.print(&format!(
            "[yellow]Client Disconnected[/]: [cyan]{}[/]",
            client.name
        ));
    }

    /// Render client disconnection with reason.
    pub fn render_disconnected_with_reason(
        &self,
        client: &ClientInfo,
        reason: &str,
        console: &FastMcpConsole,
    ) {
        if !self.should_use_rich(console) {
            self.render_disconnected_plain(client, Some(reason), console);
            return;
        }

        console.print(&format!(
            "[yellow]Client Disconnected[/]: [cyan]{}[/] [dim]({})[/]",
            client.name, reason
        ));
    }

    /// Render detailed client information panel.
    pub fn render_detail(&self, client: &ClientInfo, console: &FastMcpConsole) {
        if !self.should_use_rich(console) {
            self.render_detail_plain(client, console);
            return;
        }

        let mut table = Table::new()
            .title("Connected Client")
            .title_style(self.theme.header_style.clone())
            .box_style(&ROUNDED)
            .border_style(self.theme.border_style.clone())
            .show_header(true);

        table.add_column(Column::new("Property").style(self.theme.muted_style.clone()));
        table.add_column(Column::new("Value"));

        table.add_row_cells(["Name", client.name.as_str()]);
        table.add_row_cells(["Version", client.version.as_str()]);

        console.render(&table);
    }

    /// Render detailed client information with capabilities.
    pub fn render_detail_with_caps(
        &self,
        client: &ClientInfo,
        capabilities: &ClientCapabilities,
        console: &FastMcpConsole,
    ) {
        if !self.should_use_rich(console) {
            self.render_detail_with_caps_plain(client, capabilities, console);
            return;
        }

        let mut table = Table::new()
            .title("Connected Client")
            .title_style(self.theme.header_style.clone())
            .box_style(&ROUNDED)
            .border_style(self.theme.border_style.clone())
            .show_header(true);

        table.add_column(Column::new("Property").style(self.theme.muted_style.clone()));
        table.add_column(Column::new("Value"));

        table.add_row_cells(["Name", client.name.as_str()]);
        table.add_row_cells(["Version", client.version.as_str()]);

        let caps = self.format_capabilities(capabilities);
        let caps_display = if caps.is_empty() { "none" } else { &caps };
        table.add_row_cells(["Capabilities", caps_display]);

        console.render(&table);
    }

    /// Format capabilities as a comma-separated string.
    fn format_capabilities(&self, caps: &ClientCapabilities) -> String {
        let mut items = Vec::new();

        if caps.sampling.is_some() {
            items.push("sampling");
        }
        if let Some(roots) = &caps.roots {
            if roots.list_changed {
                items.push("roots (list_changed)");
            } else {
                items.push("roots");
            }
        }

        items.join(", ")
    }

    fn should_use_rich(&self, console: &FastMcpConsole) -> bool {
        self.context.is_human() && console.is_rich()
    }

    fn render_connected_plain(&self, client: &ClientInfo, console: &FastMcpConsole) {
        console.print(&format!(
            "Client Connected: {} v{}",
            client.name, client.version
        ));
    }

    fn render_connected_with_caps_plain(
        &self,
        client: &ClientInfo,
        capabilities: &ClientCapabilities,
        console: &FastMcpConsole,
    ) {
        console.print(&format!(
            "Client Connected: {} v{}",
            client.name, client.version
        ));
        let caps = self.format_capabilities(capabilities);
        if !caps.is_empty() {
            console.print(&format!("  Capabilities: {}", caps));
        }
    }

    fn render_disconnected_plain(
        &self,
        client: &ClientInfo,
        reason: Option<&str>,
        console: &FastMcpConsole,
    ) {
        if let Some(r) = reason {
            console.print(&format!("Client Disconnected: {} ({})", client.name, r));
        } else {
            console.print(&format!("Client Disconnected: {}", client.name));
        }
    }

    fn render_detail_plain(&self, client: &ClientInfo, console: &FastMcpConsole) {
        console.print("Connected Client:");
        console.print(&format!("  Name: {}", client.name));
        console.print(&format!("  Version: {}", client.version));
    }

    fn render_detail_with_caps_plain(
        &self,
        client: &ClientInfo,
        capabilities: &ClientCapabilities,
        console: &FastMcpConsole,
    ) {
        console.print("Connected Client:");
        console.print(&format!("  Name: {}", client.name));
        console.print(&format!("  Version: {}", client.version));
        let caps = self.format_capabilities(capabilities);
        let caps_display = if caps.is_empty() { "none" } else { &caps };
        console.print(&format!("  Capabilities: {}", caps_display));
    }
}

impl Default for ClientInfoRenderer {
    fn default() -> Self {
        Self::detect()
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::TestConsole;
    use fastmcp_protocol::RootsCapability;

    fn sample_client() -> ClientInfo {
        ClientInfo {
            name: "Claude Desktop".to_string(),
            version: "1.2.3".to_string(),
        }
    }

    fn sample_capabilities() -> ClientCapabilities {
        ClientCapabilities {
            sampling: Some(fastmcp_protocol::SamplingCapability {}),
            roots: Some(RootsCapability { list_changed: true }),
        }
    }

    #[test]
    fn test_render_connected_plain() {
        let client = sample_client();
        let console = TestConsole::new();
        let renderer = ClientInfoRenderer::new(DisplayContext::new_agent());
        renderer.render_connected(&client, console.console());
        console.assert_contains("Client Connected: Claude Desktop v1.2.3");
    }

    #[test]
    fn test_render_connected_with_caps_plain() {
        let client = sample_client();
        let caps = sample_capabilities();
        let console = TestConsole::new();
        let renderer = ClientInfoRenderer::new(DisplayContext::new_agent());
        renderer.render_connected_with_caps(&client, &caps, console.console());
        console.assert_contains("Client Connected: Claude Desktop v1.2.3");
        console.assert_contains("Capabilities: sampling, roots (list_changed)");
    }

    #[test]
    fn test_render_disconnected_plain() {
        let client = sample_client();
        let console = TestConsole::new();
        let renderer = ClientInfoRenderer::new(DisplayContext::new_agent());
        renderer.render_disconnected(&client, console.console());
        console.assert_contains("Client Disconnected: Claude Desktop");
    }

    #[test]
    fn test_render_disconnected_with_reason_plain() {
        let client = sample_client();
        let console = TestConsole::new();
        let renderer = ClientInfoRenderer::new(DisplayContext::new_agent());
        renderer.render_disconnected_with_reason(&client, "timeout", console.console());
        console.assert_contains("Client Disconnected: Claude Desktop (timeout)");
    }

    #[test]
    fn test_render_detail_plain() {
        let client = sample_client();
        let console = TestConsole::new();
        let renderer = ClientInfoRenderer::new(DisplayContext::new_agent());
        renderer.render_detail(&client, console.console());
        console.assert_contains("Connected Client:");
        console.assert_contains("Name: Claude Desktop");
        console.assert_contains("Version: 1.2.3");
    }

    #[test]
    fn test_render_detail_with_caps_plain() {
        let client = sample_client();
        let caps = sample_capabilities();
        let console = TestConsole::new();
        let renderer = ClientInfoRenderer::new(DisplayContext::new_agent());
        renderer.render_detail_with_caps(&client, &caps, console.console());
        console.assert_contains("Connected Client:");
        console.assert_contains("Name: Claude Desktop");
        console.assert_contains("Capabilities: sampling, roots (list_changed)");
    }

    #[test]
    fn test_format_capabilities_empty() {
        let renderer = ClientInfoRenderer::new(DisplayContext::new_agent());
        let caps = ClientCapabilities::default();
        assert_eq!(renderer.format_capabilities(&caps), "");
    }

    #[test]
    fn test_format_capabilities_sampling_only() {
        let renderer = ClientInfoRenderer::new(DisplayContext::new_agent());
        let caps = ClientCapabilities {
            sampling: Some(fastmcp_protocol::SamplingCapability {}),
            roots: None,
        };
        assert_eq!(renderer.format_capabilities(&caps), "sampling");
    }

    #[test]
    fn test_format_capabilities_roots_only() {
        let renderer = ClientInfoRenderer::new(DisplayContext::new_agent());
        let caps = ClientCapabilities {
            sampling: None,
            roots: Some(RootsCapability {
                list_changed: false,
            }),
        };
        assert_eq!(renderer.format_capabilities(&caps), "roots");
    }
}
