//! Unified handler registry renderer.
//!
//! Provides a comprehensive display of all server capabilities (tools, resources, prompts)
//! in a well-organized format, combining the individual table renderers.

use fastmcp_protocol::{Prompt, Resource, Tool};

use crate::console::FastMcpConsole;
use crate::detection::DisplayContext;
use crate::tables::{PromptTableRenderer, ResourceTableRenderer, ToolTableRenderer};
use crate::theme::FastMcpTheme;

/// Server capabilities combining tools, resources, and prompts.
///
/// This struct mirrors what a server exposes, making it easy to display
/// everything at once via the `HandlerRegistryRenderer`.
#[derive(Debug, Clone, Default)]
pub struct ServerCapabilities {
    /// Registered tools that can be called
    pub tools: Vec<Tool>,
    /// Registered resources that can be read
    pub resources: Vec<Resource>,
    /// Registered prompts that can be requested
    pub prompts: Vec<Prompt>,
}

impl ServerCapabilities {
    /// Create empty capabilities.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Create capabilities with the given collections.
    #[must_use]
    pub fn with(tools: Vec<Tool>, resources: Vec<Resource>, prompts: Vec<Prompt>) -> Self {
        Self {
            tools,
            resources,
            prompts,
        }
    }

    /// Total number of all capabilities.
    #[must_use]
    pub fn total(&self) -> usize {
        self.tools.len() + self.resources.len() + self.prompts.len()
    }

    /// Check if there are any capabilities.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.tools.is_empty() && self.resources.is_empty() && self.prompts.is_empty()
    }
}

/// Unified renderer for displaying all server capabilities.
///
/// Combines tools, resources, and prompts into a cohesive display with
/// proper sections, headers, footers, and summaries.
///
/// # Example
///
/// ```rust,ignore
/// use fastmcp_console::handlers::{HandlerRegistryRenderer, ServerCapabilities};
/// use fastmcp_console::detection::DisplayContext;
///
/// let renderer = HandlerRegistryRenderer::new(DisplayContext::detect());
/// let capabilities = ServerCapabilities::new();
/// renderer.render(&capabilities, console);
/// ```
#[derive(Debug, Clone)]
pub struct HandlerRegistryRenderer {
    theme: &'static FastMcpTheme,
    context: DisplayContext,
    tool_renderer: ToolTableRenderer,
    resource_renderer: ResourceTableRenderer,
    prompt_renderer: PromptTableRenderer,
}

impl HandlerRegistryRenderer {
    /// Create a new renderer with explicit display context.
    #[must_use]
    pub fn new(context: DisplayContext) -> Self {
        Self {
            theme: crate::theme::theme(),
            context: context.clone(),
            tool_renderer: ToolTableRenderer::new(context.clone()),
            resource_renderer: ResourceTableRenderer::new(context.clone()),
            prompt_renderer: PromptTableRenderer::new(context),
        }
    }

    /// Create a renderer using auto-detected display context.
    #[must_use]
    pub fn detect() -> Self {
        Self::new(DisplayContext::detect())
    }

    /// Render complete server capabilities.
    ///
    /// Shows all tools, resources, and prompts with section headers and a summary footer.
    pub fn render(&self, capabilities: &ServerCapabilities, console: &FastMcpConsole) {
        if capabilities.is_empty() {
            self.render_empty(console);
            return;
        }

        if !self.should_use_rich(console) {
            self.render_plain(capabilities, console);
            return;
        }

        // Header
        self.render_header(capabilities, console);

        // Tools section
        if !capabilities.tools.is_empty() {
            console.print("");
            self.tool_renderer.render(&capabilities.tools, console);
        }

        // Resources section
        if !capabilities.resources.is_empty() {
            console.print("");
            self.resource_renderer
                .render(&capabilities.resources, console);
        }

        // Prompts section
        if !capabilities.prompts.is_empty() {
            console.print("");
            self.prompt_renderer.render(&capabilities.prompts, console);
        }

        // Footer
        self.render_footer(capabilities, console);
    }

    /// Render a compact summary of capabilities.
    ///
    /// Shows counts and status without full tables.
    pub fn render_summary(&self, capabilities: &ServerCapabilities, console: &FastMcpConsole) {
        if !self.should_use_rich(console) {
            self.render_summary_plain(capabilities, console);
            return;
        }

        let title_color = self
            .theme
            .primary
            .triplet
            .map(|t| t.hex())
            .unwrap_or_else(|| "cyan".to_string());

        console.print(&format!(
            "\n[{}][bold]Server Capabilities[/][/]",
            title_color
        ));

        let dim = self
            .theme
            .text_dim
            .triplet
            .map(|t| t.hex())
            .unwrap_or_else(|| "white".to_string());

        // Tools
        let tools_status = if capabilities.tools.is_empty() {
            format!("[{}]none[/]", dim)
        } else {
            format!("[green]{}[/]", capabilities.tools.len())
        };
        console.print(&format!("  Tools:     {}", tools_status));

        // Resources
        let resources_status = if capabilities.resources.is_empty() {
            format!("[{}]none[/]", dim)
        } else {
            format!("[green]{}[/]", capabilities.resources.len())
        };
        console.print(&format!("  Resources: {}", resources_status));

        // Prompts
        let prompts_status = if capabilities.prompts.is_empty() {
            format!("[{}]none[/]", dim)
        } else {
            format!("[green]{}[/]", capabilities.prompts.len())
        };
        console.print(&format!("  Prompts:   {}", prompts_status));

        console.print(&format!(
            "\n[{}]Total: {} capabilities[/]",
            dim,
            capabilities.total()
        ));
    }

    /// Render only if there are capabilities.
    ///
    /// Returns true if anything was rendered.
    pub fn render_if_present(
        &self,
        capabilities: &ServerCapabilities,
        console: &FastMcpConsole,
    ) -> bool {
        if capabilities.is_empty() {
            return false;
        }
        self.render(capabilities, console);
        true
    }

    fn should_use_rich(&self, console: &FastMcpConsole) -> bool {
        self.context.is_human() && console.is_rich()
    }

    fn render_empty(&self, console: &FastMcpConsole) {
        if self.should_use_rich(console) {
            let dim = self
                .theme
                .text_dim
                .triplet
                .map(|t| t.hex())
                .unwrap_or_else(|| "white".to_string());
            console.print(&format!("[{}]No capabilities registered[/]", dim));
        } else {
            console.print("No capabilities registered");
        }
    }

    fn render_header(&self, capabilities: &ServerCapabilities, console: &FastMcpConsole) {
        let primary_color = self
            .theme
            .primary
            .triplet
            .map(|t| t.hex())
            .unwrap_or_else(|| "cyan".to_string());

        console.print(&format!(
            "\n[{}][bold]Server Capabilities ({} total)[/][/]",
            primary_color,
            capabilities.total()
        ));
    }

    fn render_footer(&self, capabilities: &ServerCapabilities, console: &FastMcpConsole) {
        let tools = capabilities.tools.len();
        let resources = capabilities.resources.len();
        let prompts = capabilities.prompts.len();

        let dim = self
            .theme
            .text_dim
            .triplet
            .map(|t| t.hex())
            .unwrap_or_else(|| "white".to_string());

        console.print(&format!(
            "\n[{}]Summary: {} tool{}, {} resource{}, {} prompt{}[/]",
            dim,
            tools,
            if tools == 1 { "" } else { "s" },
            resources,
            if resources == 1 { "" } else { "s" },
            prompts,
            if prompts == 1 { "" } else { "s" }
        ));
    }

    fn render_plain(&self, capabilities: &ServerCapabilities, console: &FastMcpConsole) {
        console.print(&format!(
            "=== Server Capabilities ({} total) ===",
            capabilities.total()
        ));

        if !capabilities.tools.is_empty() {
            console.print("");
            self.tool_renderer.render(&capabilities.tools, console);
        }

        if !capabilities.resources.is_empty() {
            console.print("");
            self.resource_renderer
                .render(&capabilities.resources, console);
        }

        if !capabilities.prompts.is_empty() {
            console.print("");
            self.prompt_renderer.render(&capabilities.prompts, console);
        }

        self.render_summary_footer_plain(capabilities, console);
    }

    fn render_summary_plain(&self, capabilities: &ServerCapabilities, console: &FastMcpConsole) {
        console.print("Server Capabilities:");
        console.print(&format!("  Tools:     {}", capabilities.tools.len()));
        console.print(&format!("  Resources: {}", capabilities.resources.len()));
        console.print(&format!("  Prompts:   {}", capabilities.prompts.len()));
        console.print(&format!("  Total:     {}", capabilities.total()));
    }

    fn render_summary_footer_plain(
        &self,
        capabilities: &ServerCapabilities,
        console: &FastMcpConsole,
    ) {
        let tools = capabilities.tools.len();
        let resources = capabilities.resources.len();
        let prompts = capabilities.prompts.len();

        console.print(&format!(
            "\nSummary: {} tool{}, {} resource{}, {} prompt{}",
            tools,
            if tools == 1 { "" } else { "s" },
            resources,
            if resources == 1 { "" } else { "s" },
            prompts,
            if prompts == 1 { "" } else { "s" }
        ));
    }
}

impl Default for HandlerRegistryRenderer {
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
    use serde_json::json;

    fn sample_tools() -> Vec<Tool> {
        vec![
            Tool {
                name: "calculate".to_string(),
                description: Some("Perform calculations".to_string()),
                input_schema: json!({"type": "object", "properties": {}}),
                icon: None,
            },
            Tool {
                name: "search".to_string(),
                description: Some("Search for items".to_string()),
                input_schema: json!({"type": "object", "properties": {}}),
                icon: None,
            },
        ]
    }

    fn sample_resources() -> Vec<Resource> {
        vec![Resource {
            uri: "file://example.txt".to_string(),
            name: "example.txt".to_string(),
            description: Some("Example file".to_string()),
            mime_type: Some("text/plain".to_string()),
            icon: None,
        }]
    }

    fn sample_prompts() -> Vec<Prompt> {
        vec![Prompt {
            name: "code_review".to_string(),
            description: Some("Review code changes".to_string()),
            arguments: vec![],
            icon: None,
        }]
    }

    #[test]
    fn test_render_empty_capabilities() {
        let tc = TestConsole::new();
        let renderer = HandlerRegistryRenderer::new(DisplayContext::new_agent());
        let caps = ServerCapabilities::new();

        renderer.render(&caps, tc.console());

        tc.assert_contains("No capabilities registered");
    }

    #[test]
    fn test_render_tools_only() {
        let tc = TestConsole::new();
        let renderer = HandlerRegistryRenderer::new(DisplayContext::new_agent());
        let caps = ServerCapabilities::with(sample_tools(), vec![], vec![]);

        renderer.render(&caps, tc.console());

        tc.assert_contains("Server Capabilities");
        tc.assert_contains("2 total");
        tc.assert_contains("calculate");
        tc.assert_contains("search");
        tc.assert_contains("2 tools");
        tc.assert_contains("0 resources");
        tc.assert_contains("0 prompts");
    }

    #[test]
    fn test_render_all_capabilities() {
        let tc = TestConsole::new();
        let renderer = HandlerRegistryRenderer::new(DisplayContext::new_agent());
        let caps = ServerCapabilities::with(sample_tools(), sample_resources(), sample_prompts());

        renderer.render(&caps, tc.console());

        tc.assert_contains("Server Capabilities");
        tc.assert_contains("4 total");
        // Tools
        tc.assert_contains("calculate");
        tc.assert_contains("search");
        // Resources
        tc.assert_contains("example.txt");
        // Prompts
        tc.assert_contains("code_review");
        // Summary
        tc.assert_contains("2 tools");
        tc.assert_contains("1 resource");
        tc.assert_contains("1 prompt");
    }

    #[test]
    fn test_render_summary() {
        let tc = TestConsole::new();
        let renderer = HandlerRegistryRenderer::new(DisplayContext::new_agent());
        let caps = ServerCapabilities::with(sample_tools(), sample_resources(), sample_prompts());

        renderer.render_summary(&caps, tc.console());

        tc.assert_contains("Server Capabilities");
        tc.assert_contains("Tools:");
        tc.assert_contains("Resources:");
        tc.assert_contains("Prompts:");
        tc.assert_contains("Total:");
        tc.assert_contains("4");
    }

    #[test]
    fn test_render_if_present_empty() {
        let tc = TestConsole::new();
        let renderer = HandlerRegistryRenderer::new(DisplayContext::new_agent());
        let caps = ServerCapabilities::new();

        let rendered = renderer.render_if_present(&caps, tc.console());

        assert!(!rendered);
        assert!(tc.output().is_empty());
    }

    #[test]
    fn test_render_if_present_with_content() {
        let tc = TestConsole::new();
        let renderer = HandlerRegistryRenderer::new(DisplayContext::new_agent());
        let caps = ServerCapabilities::with(sample_tools(), vec![], vec![]);

        let rendered = renderer.render_if_present(&caps, tc.console());

        assert!(rendered);
        tc.assert_contains("calculate");
    }

    #[test]
    fn test_server_capabilities_total() {
        let caps = ServerCapabilities::with(sample_tools(), sample_resources(), sample_prompts());
        assert_eq!(caps.total(), 4);
    }

    #[test]
    fn test_server_capabilities_is_empty() {
        let empty = ServerCapabilities::new();
        assert!(empty.is_empty());

        let non_empty = ServerCapabilities::with(sample_tools(), vec![], vec![]);
        assert!(!non_empty.is_empty());
    }
}
