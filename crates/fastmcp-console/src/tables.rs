//! Server info table renderers
//!
//! Provides beautiful table displays for tools, resources, and prompts
//! using rich_rust, with plain-text fallback for agent contexts.

use std::collections::HashMap;

use fastmcp_protocol::{Prompt, PromptArgument, Resource, Tool};
use rich_rust::r#box::ROUNDED;
use rich_rust::prelude::*;
use rich_rust::text::OverflowMethod;
use serde_json::Value;

use crate::console::FastMcpConsole;
use crate::detection::DisplayContext;
use crate::theme::FastMcpTheme;

// ============================================================================
// Tool Table Renderer
// ============================================================================

/// Renders tool registry as beautiful tables.
///
/// Supports both summary table view and detailed single-tool view,
/// with configuration options for what information to display.
#[derive(Debug, Clone)]
pub struct ToolTableRenderer {
    theme: &'static FastMcpTheme,
    context: DisplayContext,
    /// Whether to show parameter counts in the table
    pub show_parameters: bool,
    /// Maximum width for description column before truncation
    pub max_description_width: usize,
}

impl ToolTableRenderer {
    /// Create a new renderer with explicit display context.
    #[must_use]
    pub fn new(context: DisplayContext) -> Self {
        Self {
            theme: crate::theme::theme(),
            context,
            show_parameters: true,
            max_description_width: 50,
        }
    }

    /// Create a renderer using auto-detected display context.
    #[must_use]
    pub fn detect() -> Self {
        Self::new(DisplayContext::detect())
    }

    /// Render a collection of tools as a table.
    pub fn render(&self, tools: &[Tool], console: &FastMcpConsole) {
        if tools.is_empty() {
            if self.should_use_rich(console) {
                console.print("[dim]No tools registered[/]");
            } else {
                console.print("No tools registered");
            }
            return;
        }

        if !self.should_use_rich(console) {
            self.render_plain(tools, console);
            return;
        }

        let mut table = Table::new()
            .title(format!("Registered Tools ({})", tools.len()))
            .title_style(self.theme.header_style.clone())
            .box_style(&ROUNDED)
            .border_style(self.theme.border_style.clone())
            .show_header(true);

        table.add_column(Column::new("Name").style(self.theme.key_style.clone()));
        table.add_column(
            Column::new("Description")
                .max_width(self.max_description_width)
                .overflow(OverflowMethod::Ellipsis),
        );

        if self.show_parameters {
            table.add_column(Column::new("Parameters").justify(JustifyMethod::Center));
        }

        for tool in tools {
            let desc = tool.description.as_deref().unwrap_or("-");
            let truncated_desc = self.truncate_description(desc);

            if self.show_parameters {
                let params = self.format_parameters(&tool.input_schema);
                table.add_row_cells([tool.name.as_str(), truncated_desc.as_str(), params.as_str()]);
            } else {
                table.add_row_cells([tool.name.as_str(), truncated_desc.as_str()]);
            }
        }

        console.render(&table);
    }

    /// Render a single tool in detail.
    pub fn render_detail(&self, tool: &Tool, console: &FastMcpConsole) {
        if !self.should_use_rich(console) {
            self.render_detail_plain(tool, console);
            return;
        }

        // Tool name header
        console.print(&format!("\n[bold cyan]{}[/]", tool.name));
        console.print(&format!(
            "[dim]{}[/]\n",
            tool.description.as_deref().unwrap_or("No description")
        ));

        // Parameters table (extracted from JSON Schema)
        let params = self.extract_parameters(&tool.input_schema);
        if !params.is_empty() {
            let mut param_table = Table::new()
                .title("Parameters")
                .title_style(self.theme.subheader_style.clone())
                .box_style(&ROUNDED)
                .border_style(self.theme.border_style.clone())
                .show_header(true);

            param_table.add_column(Column::new("Name").style(self.theme.key_style.clone()));
            param_table.add_column(Column::new("Type"));
            param_table.add_column(Column::new("Required").justify(JustifyMethod::Center));
            param_table.add_column(Column::new("Description").max_width(40));

            for param in &params {
                let required_mark = if param.required { "✓" } else { "" };
                param_table.add_row_cells([
                    param.name.as_str(),
                    &param.type_name,
                    required_mark,
                    param.description.as_deref().unwrap_or("-"),
                ]);
            }

            console.render(&param_table);
        } else {
            console.print("[dim]No parameters[/]");
        }
    }

    fn should_use_rich(&self, console: &FastMcpConsole) -> bool {
        self.context.is_human() && console.is_rich()
    }

    fn format_parameters(&self, schema: &Value) -> String {
        let params = self.extract_parameters(schema);
        if params.is_empty() {
            "none".to_string()
        } else {
            let required = params.iter().filter(|p| p.required).count();
            let optional = params.len() - required;

            match (required, optional) {
                (r, 0) => format!("{r} required"),
                (0, o) => format!("{o} optional"),
                (r, o) => format!("{r} req, {o} opt"),
            }
        }
    }

    fn extract_parameters(&self, schema: &Value) -> Vec<ParameterInfo> {
        let mut params = Vec::new();

        let properties = schema.get("properties").and_then(Value::as_object);
        let required = schema
            .get("required")
            .and_then(Value::as_array)
            .map(|arr| {
                arr.iter()
                    .filter_map(Value::as_str)
                    .map(String::from)
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();

        if let Some(props) = properties {
            for (name, prop) in props {
                let type_name = prop
                    .get("type")
                    .and_then(Value::as_str)
                    .unwrap_or("any")
                    .to_string();

                let description = prop
                    .get("description")
                    .and_then(Value::as_str)
                    .map(String::from);

                params.push(ParameterInfo {
                    name: name.clone(),
                    type_name,
                    required: required.contains(name),
                    description,
                });
            }
        }

        // Sort: required first, then alphabetically
        params.sort_by(|a, b| match (a.required, b.required) {
            (true, false) => std::cmp::Ordering::Less,
            (false, true) => std::cmp::Ordering::Greater,
            _ => a.name.cmp(&b.name),
        });

        params
    }

    fn truncate_description(&self, desc: &str) -> String {
        if desc.len() <= self.max_description_width {
            desc.to_string()
        } else {
            format!(
                "{}...",
                &desc[..self.max_description_width.saturating_sub(3)]
            )
        }
    }

    fn render_plain(&self, tools: &[Tool], console: &FastMcpConsole) {
        console.print(&format!("Registered Tools ({})", tools.len()));
        console.print(&"=".repeat(40));
        for tool in tools {
            let desc = tool.description.as_deref().unwrap_or("-");
            if self.show_parameters {
                let params = self.format_parameters(&tool.input_schema);
                console.print(&format!("  {} - {} [{}]", tool.name, desc, params));
            } else {
                console.print(&format!("  {} - {}", tool.name, desc));
            }
        }
    }

    fn render_detail_plain(&self, tool: &Tool, console: &FastMcpConsole) {
        console.print(&format!("Tool: {}", tool.name));
        console.print(&format!(
            "Description: {}",
            tool.description.as_deref().unwrap_or("No description")
        ));

        let params = self.extract_parameters(&tool.input_schema);
        if params.is_empty() {
            console.print("Parameters: none");
        } else {
            console.print("Parameters:");
            for param in &params {
                let req = if param.required {
                    "required"
                } else {
                    "optional"
                };
                console.print(&format!(
                    "  - {}: {} ({}) - {}",
                    param.name,
                    param.type_name,
                    req,
                    param.description.as_deref().unwrap_or("-")
                ));
            }
        }
    }
}

impl Default for ToolTableRenderer {
    fn default() -> Self {
        Self::detect()
    }
}

/// Parameter information extracted from JSON Schema.
#[derive(Debug, Clone)]
struct ParameterInfo {
    name: String,
    type_name: String,
    required: bool,
    description: Option<String>,
}

// ============================================================================
// Resource Table Renderer
// ============================================================================

/// Renders resource registry as beautiful tables.
#[derive(Debug, Clone)]
pub struct ResourceTableRenderer {
    theme: &'static FastMcpTheme,
    context: DisplayContext,
    /// Maximum width for description column
    pub max_description_width: usize,
    /// Whether to show MIME type column
    pub show_mime_type: bool,
}

impl ResourceTableRenderer {
    /// Create a new renderer with explicit display context.
    #[must_use]
    pub fn new(context: DisplayContext) -> Self {
        Self {
            theme: crate::theme::theme(),
            context,
            max_description_width: 40,
            show_mime_type: true,
        }
    }

    /// Create a renderer using auto-detected display context.
    #[must_use]
    pub fn detect() -> Self {
        Self::new(DisplayContext::detect())
    }

    /// Render a collection of resources as a table.
    pub fn render(&self, resources: &[Resource], console: &FastMcpConsole) {
        if resources.is_empty() {
            if self.should_use_rich(console) {
                console.print("[dim]No resources registered[/]");
            } else {
                console.print("No resources registered");
            }
            return;
        }

        if !self.should_use_rich(console) {
            self.render_plain(resources, console);
            return;
        }

        let mut table = Table::new()
            .title(format!("Registered Resources ({})", resources.len()))
            .title_style(self.theme.header_style.clone())
            .box_style(&ROUNDED)
            .border_style(self.theme.border_style.clone())
            .show_header(true);

        table.add_column(Column::new("Name").style(self.theme.key_style.clone()));
        table.add_column(Column::new("URI").style(self.theme.muted_style.clone()));
        table.add_column(
            Column::new("Description")
                .max_width(self.max_description_width)
                .overflow(OverflowMethod::Ellipsis),
        );

        if self.show_mime_type {
            table.add_column(Column::new("Type"));
        }

        for resource in resources {
            let desc = resource.description.as_deref().unwrap_or("-");
            let truncated_desc = self.truncate_description(desc);
            let formatted_uri = self.format_uri(&resource.uri);

            if self.show_mime_type {
                let mime = resource.mime_type.as_deref().unwrap_or("-");
                table.add_row_cells([
                    resource.name.as_str(),
                    formatted_uri.as_str(),
                    truncated_desc.as_str(),
                    mime,
                ]);
            } else {
                table.add_row_cells([
                    resource.name.as_str(),
                    formatted_uri.as_str(),
                    truncated_desc.as_str(),
                ]);
            }
        }

        console.render(&table);
    }

    /// Render a single resource in detail.
    pub fn render_detail(&self, resource: &Resource, console: &FastMcpConsole) {
        if !self.should_use_rich(console) {
            self.render_detail_plain(resource, console);
            return;
        }

        console.print(&format!("\n[bold cyan]{}[/]", resource.name));
        console.print(&format!("[dim]URI:[/] {}", self.format_uri(&resource.uri)));
        console.print(&format!(
            "[dim]Description:[/] {}",
            resource.description.as_deref().unwrap_or("No description")
        ));
        if let Some(mime) = &resource.mime_type {
            console.print(&format!("[dim]MIME Type:[/] {}", mime));
        }
    }

    /// Render resources as a tree grouped by URI prefix/scheme.
    ///
    /// Resources are grouped by their URI scheme (file://, config://, db://, etc.)
    /// and displayed in a hierarchical tree structure.
    pub fn render_tree(&self, resources: &[Resource], console: &FastMcpConsole) {
        if resources.is_empty() {
            if self.should_use_rich(console) {
                console.print("[dim]No resources registered[/]");
            } else {
                console.print("No resources registered");
            }
            return;
        }

        if !self.should_use_rich(console) {
            self.render_plain(resources, console);
            return;
        }

        // Group resources by URI scheme/prefix
        let mut groups: HashMap<String, Vec<&Resource>> = HashMap::new();
        for resource in resources {
            let prefix = self.extract_uri_prefix(&resource.uri);
            groups.entry(prefix).or_default().push(resource);
        }

        // Build tree
        let root = TreeNode::with_icon("📄", format!("[bold]Resources[/] ({})", resources.len()));

        // Sort group keys for consistent ordering
        let mut sorted_keys: Vec<_> = groups.keys().cloned().collect();
        sorted_keys.sort();

        let root = sorted_keys.into_iter().fold(root, |root, prefix| {
            let group_resources = groups.get(&prefix).unwrap();
            let group_node =
                TreeNode::new(format!("[cyan]{}[/] ({})", prefix, group_resources.len()));

            // Add each resource as a child
            let group_node = group_resources.iter().fold(group_node, |node, resource| {
                let name_part = self.extract_uri_path(&resource.uri);
                let desc = self.truncate_description(resource.description.as_deref().unwrap_or(""));
                let leaf_label = if desc.is_empty() {
                    self.format_uri(&name_part)
                } else {
                    format!("{} [dim]- {}[/]", self.format_uri(&name_part), desc)
                };
                node.child(TreeNode::new(leaf_label))
            });

            root.child(group_node)
        });

        let tree = Tree::new(root).guides(TreeGuides::Rounded);
        console.render(&tree);
    }

    /// Format a URI with template parts highlighted in yellow.
    ///
    /// Template parts like `{path}` or `{id}` are highlighted to make
    /// them visually distinct from static URI parts.
    fn format_uri(&self, uri: &str) -> String {
        if !uri.contains('{') {
            return uri.to_string();
        }

        // Highlight template placeholders {name} in yellow
        let mut result = String::new();
        let mut chars = uri.chars().peekable();

        while let Some(c) = chars.next() {
            if c == '{' {
                result.push_str("[yellow]{");
                // Consume until closing brace
                while let Some(&next) = chars.peek() {
                    chars.next();
                    result.push(next);
                    if next == '}' {
                        result.push_str("[/]");
                        break;
                    }
                }
            } else {
                result.push(c);
            }
        }

        result
    }

    /// Extract the URI scheme/prefix (e.g., "file", "config", "db").
    fn extract_uri_prefix(&self, uri: &str) -> String {
        if let Some(idx) = uri.find("://") {
            uri[..idx].to_string()
        } else if let Some(idx) = uri.find(':') {
            uri[..idx].to_string()
        } else {
            "other".to_string()
        }
    }

    /// Extract the path portion of a URI after the scheme.
    fn extract_uri_path(&self, uri: &str) -> String {
        if let Some(idx) = uri.find("://") {
            uri[idx + 3..].to_string()
        } else if let Some(idx) = uri.find(':') {
            uri[idx + 1..].to_string()
        } else {
            uri.to_string()
        }
    }

    fn should_use_rich(&self, console: &FastMcpConsole) -> bool {
        self.context.is_human() && console.is_rich()
    }

    fn truncate_description(&self, desc: &str) -> String {
        if desc.len() <= self.max_description_width {
            desc.to_string()
        } else {
            format!(
                "{}...",
                &desc[..self.max_description_width.saturating_sub(3)]
            )
        }
    }

    fn render_plain(&self, resources: &[Resource], console: &FastMcpConsole) {
        console.print(&format!("Registered Resources ({})", resources.len()));
        console.print(&"=".repeat(40));
        for resource in resources {
            let desc = resource.description.as_deref().unwrap_or("-");
            console.print(&format!(
                "  {} ({}) - {}",
                resource.name, resource.uri, desc
            ));
        }
    }

    fn render_detail_plain(&self, resource: &Resource, console: &FastMcpConsole) {
        console.print(&format!("Resource: {}", resource.name));
        console.print(&format!("URI: {}", resource.uri));
        console.print(&format!(
            "Description: {}",
            resource.description.as_deref().unwrap_or("No description")
        ));
        if let Some(mime) = &resource.mime_type {
            console.print(&format!("MIME Type: {}", mime));
        }
    }
}

impl Default for ResourceTableRenderer {
    fn default() -> Self {
        Self::detect()
    }
}

// ============================================================================
// Prompt Table Renderer
// ============================================================================

/// Renders prompt registry as beautiful tables.
#[derive(Debug, Clone)]
pub struct PromptTableRenderer {
    theme: &'static FastMcpTheme,
    context: DisplayContext,
    /// Maximum width for description column
    pub max_description_width: usize,
    /// Whether to show argument counts
    pub show_arguments: bool,
}

impl PromptTableRenderer {
    /// Create a new renderer with explicit display context.
    #[must_use]
    pub fn new(context: DisplayContext) -> Self {
        Self {
            theme: crate::theme::theme(),
            context,
            max_description_width: 50,
            show_arguments: true,
        }
    }

    /// Create a renderer using auto-detected display context.
    #[must_use]
    pub fn detect() -> Self {
        Self::new(DisplayContext::detect())
    }

    /// Render a collection of prompts as a table.
    pub fn render(&self, prompts: &[Prompt], console: &FastMcpConsole) {
        if prompts.is_empty() {
            if self.should_use_rich(console) {
                console.print("[dim]No prompts registered[/]");
            } else {
                console.print("No prompts registered");
            }
            return;
        }

        if !self.should_use_rich(console) {
            self.render_plain(prompts, console);
            return;
        }

        let mut table = Table::new()
            .title(format!("Registered Prompts ({})", prompts.len()))
            .title_style(self.theme.header_style.clone())
            .box_style(&ROUNDED)
            .border_style(self.theme.border_style.clone())
            .show_header(true);

        table.add_column(Column::new("Name").style(self.theme.key_style.clone()));
        table.add_column(
            Column::new("Description")
                .max_width(self.max_description_width)
                .overflow(OverflowMethod::Ellipsis),
        );

        if self.show_arguments {
            table.add_column(Column::new("Arguments").justify(JustifyMethod::Center));
        }

        for prompt in prompts {
            let desc = prompt.description.as_deref().unwrap_or("-");
            let truncated_desc = self.truncate_description(desc);

            if self.show_arguments {
                let args = self.format_arguments(&prompt.arguments);
                table.add_row_cells([prompt.name.as_str(), truncated_desc.as_str(), args.as_str()]);
            } else {
                table.add_row_cells([prompt.name.as_str(), truncated_desc.as_str()]);
            }
        }

        console.render(&table);
    }

    /// Render a single prompt in detail.
    pub fn render_detail(&self, prompt: &Prompt, console: &FastMcpConsole) {
        if !self.should_use_rich(console) {
            self.render_detail_plain(prompt, console);
            return;
        }

        console.print(&format!("\n[bold cyan]{}[/]", prompt.name));
        console.print(&format!(
            "[dim]{}[/]\n",
            prompt.description.as_deref().unwrap_or("No description")
        ));

        // Arguments table
        if !prompt.arguments.is_empty() {
            let mut arg_table = Table::new()
                .title("Arguments")
                .title_style(self.theme.subheader_style.clone())
                .box_style(&ROUNDED)
                .border_style(self.theme.border_style.clone())
                .show_header(true);

            arg_table.add_column(Column::new("Name").style(self.theme.key_style.clone()));
            arg_table.add_column(Column::new("Required").justify(JustifyMethod::Center));
            arg_table.add_column(Column::new("Description").max_width(40));

            for arg in &prompt.arguments {
                let required_mark = if arg.required { "✓" } else { "" };
                arg_table.add_row_cells([
                    arg.name.as_str(),
                    required_mark,
                    arg.description.as_deref().unwrap_or("-"),
                ]);
            }

            console.render(&arg_table);
        } else {
            console.print("[dim]No arguments[/]");
        }
    }

    fn should_use_rich(&self, console: &FastMcpConsole) -> bool {
        self.context.is_human() && console.is_rich()
    }

    fn format_arguments(&self, args: &[PromptArgument]) -> String {
        if args.is_empty() {
            return "none".to_string();
        }
        let required = args.iter().filter(|a| a.required).count();
        let optional = args.len() - required;

        match (required, optional) {
            (r, 0) => format!("{r} required"),
            (0, o) => format!("{o} optional"),
            (r, o) => format!("{r} req, {o} opt"),
        }
    }

    fn truncate_description(&self, desc: &str) -> String {
        if desc.len() <= self.max_description_width {
            desc.to_string()
        } else {
            format!(
                "{}...",
                &desc[..self.max_description_width.saturating_sub(3)]
            )
        }
    }

    fn render_plain(&self, prompts: &[Prompt], console: &FastMcpConsole) {
        console.print(&format!("Registered Prompts ({})", prompts.len()));
        console.print(&"=".repeat(40));
        for prompt in prompts {
            let desc = prompt.description.as_deref().unwrap_or("-");
            if self.show_arguments {
                let args = self.format_arguments(&prompt.arguments);
                console.print(&format!("  {} - {} [{}]", prompt.name, desc, args));
            } else {
                console.print(&format!("  {} - {}", prompt.name, desc));
            }
        }
    }

    fn render_detail_plain(&self, prompt: &Prompt, console: &FastMcpConsole) {
        console.print(&format!("Prompt: {}", prompt.name));
        console.print(&format!(
            "Description: {}",
            prompt.description.as_deref().unwrap_or("No description")
        ));

        if prompt.arguments.is_empty() {
            console.print("Arguments: none");
        } else {
            console.print("Arguments:");
            for arg in &prompt.arguments {
                let req = if arg.required { "required" } else { "optional" };
                console.print(&format!(
                    "  - {} ({}) - {}",
                    arg.name,
                    req,
                    arg.description.as_deref().unwrap_or("-")
                ));
            }
        }
    }
}

impl Default for PromptTableRenderer {
    fn default() -> Self {
        Self::detect()
    }
}

// ============================================================================
// Legacy Functions (for backwards compatibility)
// ============================================================================

/// Display registered tools in a table (legacy function).
///
/// Use `ToolTableRenderer` for more control.
pub fn render_tools_table(tools: &[Tool], console: &FastMcpConsole) {
    ToolTableRenderer::detect().render(tools, console);
}

/// Display registered resources in a table (legacy function).
///
/// Use `ResourceTableRenderer` for more control.
pub fn render_resources_table(resources: &[Resource], console: &FastMcpConsole) {
    ResourceTableRenderer::detect().render(resources, console);
}

/// Display registered prompts in a table (legacy function).
///
/// Use `PromptTableRenderer` for more control.
pub fn render_prompts_table(prompts: &[Prompt], console: &FastMcpConsole) {
    PromptTableRenderer::detect().render(prompts, console);
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
                description: Some("Perform mathematical calculations".to_string()),
                input_schema: json!({
                    "type": "object",
                    "properties": {
                        "expression": {
                            "type": "string",
                            "description": "Mathematical expression to evaluate"
                        },
                        "precision": {
                            "type": "integer",
                            "description": "Number of decimal places"
                        }
                    },
                    "required": ["expression"]
                }),
            },
            Tool {
                name: "search".to_string(),
                description: Some("Search for files matching a pattern".to_string()),
                input_schema: json!({
                    "type": "object",
                    "properties": {
                        "pattern": {
                            "type": "string",
                            "description": "Search pattern"
                        }
                    },
                    "required": ["pattern"]
                }),
            },
        ]
    }

    fn sample_resources() -> Vec<Resource> {
        vec![
            Resource {
                uri: "file://config.json".to_string(),
                name: "config".to_string(),
                description: Some("Application configuration".to_string()),
                mime_type: Some("application/json".to_string()),
            },
            Resource {
                uri: "file://data.csv".to_string(),
                name: "data".to_string(),
                description: Some("Data file".to_string()),
                mime_type: Some("text/csv".to_string()),
            },
        ]
    }

    fn sample_prompts() -> Vec<Prompt> {
        vec![
            Prompt {
                name: "greeting".to_string(),
                description: Some("Generate a greeting message".to_string()),
                arguments: vec![PromptArgument {
                    name: "name".to_string(),
                    description: Some("Person's name".to_string()),
                    required: true,
                }],
            },
            Prompt {
                name: "summarize".to_string(),
                description: Some("Summarize the given text".to_string()),
                arguments: vec![
                    PromptArgument {
                        name: "text".to_string(),
                        description: Some("Text to summarize".to_string()),
                        required: true,
                    },
                    PromptArgument {
                        name: "length".to_string(),
                        description: Some("Target length".to_string()),
                        required: false,
                    },
                ],
            },
        ]
    }

    #[test]
    fn test_tool_table_render_plain() {
        let tools = sample_tools();
        let console = TestConsole::new();
        let renderer = ToolTableRenderer::new(DisplayContext::new_agent());
        renderer.render(&tools, console.console());
        console.assert_contains("Registered Tools (2)");
        console.assert_contains("calculate");
        console.assert_contains("search");
    }

    #[test]
    fn test_tool_table_render_rich() {
        let tools = sample_tools();
        let console = TestConsole::new_rich();
        let renderer = ToolTableRenderer::new(DisplayContext::new_human());
        renderer.render(&tools, console.console());
        console.assert_contains("Registered Tools");
        console.assert_contains("calculate");
    }

    #[test]
    fn test_tool_table_empty() {
        let console = TestConsole::new();
        let renderer = ToolTableRenderer::new(DisplayContext::new_agent());
        renderer.render(&[], console.console());
        console.assert_contains("No tools registered");
    }

    #[test]
    fn test_tool_parameter_extraction() {
        let tools = sample_tools();
        let renderer = ToolTableRenderer::new(DisplayContext::new_agent());
        let params = renderer.extract_parameters(&tools[0].input_schema);
        assert_eq!(params.len(), 2);
        // First should be required (expression)
        assert!(params[0].required);
        assert_eq!(params[0].name, "expression");
    }

    #[test]
    fn test_resource_table_render_plain() {
        let resources = sample_resources();
        let console = TestConsole::new();
        let renderer = ResourceTableRenderer::new(DisplayContext::new_agent());
        renderer.render(&resources, console.console());
        console.assert_contains("Registered Resources (2)");
        console.assert_contains("config");
    }

    #[test]
    fn test_resource_table_empty() {
        let console = TestConsole::new();
        let renderer = ResourceTableRenderer::new(DisplayContext::new_agent());
        renderer.render(&[], console.console());
        console.assert_contains("No resources registered");
    }

    #[test]
    fn test_prompt_table_render_plain() {
        let prompts = sample_prompts();
        let console = TestConsole::new();
        let renderer = PromptTableRenderer::new(DisplayContext::new_agent());
        renderer.render(&prompts, console.console());
        console.assert_contains("Registered Prompts (2)");
        console.assert_contains("greeting");
        console.assert_contains("summarize");
    }

    #[test]
    fn test_prompt_table_empty() {
        let console = TestConsole::new();
        let renderer = PromptTableRenderer::new(DisplayContext::new_agent());
        renderer.render(&[], console.console());
        console.assert_contains("No prompts registered");
    }

    #[test]
    fn test_prompt_arguments_formatting() {
        let renderer = PromptTableRenderer::new(DisplayContext::new_agent());

        // Empty
        assert_eq!(renderer.format_arguments(&[]), "none");

        // Mixed
        let args = vec![
            PromptArgument {
                name: "a".to_string(),
                description: None,
                required: true,
            },
            PromptArgument {
                name: "b".to_string(),
                description: None,
                required: false,
            },
        ];
        assert_eq!(renderer.format_arguments(&args), "1 req, 1 opt");
    }

    #[test]
    fn test_description_truncation() {
        let renderer = ToolTableRenderer {
            theme: crate::theme::theme(),
            context: DisplayContext::new_agent(),
            show_parameters: true,
            max_description_width: 20,
        };

        assert_eq!(renderer.truncate_description("Short"), "Short");
        assert_eq!(
            renderer
                .truncate_description("This is a very long description that should be truncated"),
            "This is a very lo..."
        );
    }

    #[test]
    fn test_uri_template_highlighting() {
        let renderer = ResourceTableRenderer::new(DisplayContext::new_human());

        // No template - unchanged
        assert_eq!(
            renderer.format_uri("file://config.json"),
            "file://config.json"
        );

        // Simple template
        assert_eq!(
            renderer.format_uri("file://{path}"),
            "file://[yellow]{path}[/]"
        );

        // Multiple templates
        assert_eq!(
            renderer.format_uri("db://{table}/{id}"),
            "db://[yellow]{table}[/]/[yellow]{id}[/]"
        );

        // Template in the middle
        assert_eq!(
            renderer.format_uri("api://users/{id}/profile"),
            "api://users/[yellow]{id}[/]/profile"
        );
    }

    #[test]
    fn test_uri_prefix_extraction() {
        let renderer = ResourceTableRenderer::new(DisplayContext::new_agent());

        assert_eq!(renderer.extract_uri_prefix("file://path"), "file");
        assert_eq!(renderer.extract_uri_prefix("db://table"), "db");
        assert_eq!(renderer.extract_uri_prefix("config:settings"), "config");
        assert_eq!(renderer.extract_uri_prefix("no-scheme"), "other");
    }

    #[test]
    fn test_uri_path_extraction() {
        let renderer = ResourceTableRenderer::new(DisplayContext::new_agent());

        assert_eq!(
            renderer.extract_uri_path("file://config.json"),
            "config.json"
        );
        assert_eq!(renderer.extract_uri_path("db://users/{id}"), "users/{id}");
        assert_eq!(renderer.extract_uri_path("config:settings"), "settings");
    }

    fn sample_resources_with_templates() -> Vec<Resource> {
        vec![
            Resource {
                uri: "file://{path}".to_string(),
                name: "file".to_string(),
                description: Some("Read file contents".to_string()),
                mime_type: None,
            },
            Resource {
                uri: "file://config.json".to_string(),
                name: "config".to_string(),
                description: Some("Application config".to_string()),
                mime_type: Some("application/json".to_string()),
            },
            Resource {
                uri: "db://users/{id}".to_string(),
                name: "user".to_string(),
                description: Some("User record by ID".to_string()),
                mime_type: None,
            },
            Resource {
                uri: "cache://stats".to_string(),
                name: "stats".to_string(),
                description: Some("Cached statistics".to_string()),
                mime_type: None,
            },
        ]
    }

    #[test]
    fn test_resource_tree_render_plain() {
        let resources = sample_resources_with_templates();
        let console = TestConsole::new();
        let renderer = ResourceTableRenderer::new(DisplayContext::new_agent());
        // Tree falls back to plain render in agent mode
        renderer.render_tree(&resources, console.console());
        console.assert_contains("Registered Resources (4)");
    }

    #[test]
    fn test_resource_tree_empty() {
        let console = TestConsole::new();
        let renderer = ResourceTableRenderer::new(DisplayContext::new_agent());
        renderer.render_tree(&[], console.console());
        console.assert_contains("No resources registered");
    }
}
