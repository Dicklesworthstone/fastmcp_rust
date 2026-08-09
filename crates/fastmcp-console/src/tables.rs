//! Server info table renderers
//!
//! Provides beautiful table displays for tools, resources, and prompts
//! using rich_rust, with plain-text fallback for agent contexts.

use std::collections::{HashMap, HashSet};

use fastmcp_protocol::{Prompt, PromptArgument, Resource, Tool};
use rich_rust::r#box::ROUNDED;
use rich_rust::prelude::*;
use rich_rust::text::OverflowMethod;
use serde_json::Value;

use crate::config::ConsoleConfig;
use crate::console::{
    DEFAULT_TERMINAL_FIELD_MAX_CHARS, FastMcpConsole, bounded_redacted_rich_fragment,
    bounded_redacted_rich_text, bounded_redacted_terminal_text,
};
use crate::detection::DisplayContext;
use crate::theme::FastMcpTheme;

const TABLE_ROWS_HARD_MAX: usize = 1_000;
const REQUIRED_NAMES_SCAN_HARD_MAX: usize = 4_096;
const REQUIRED_NAME_SOURCE_MAX_BYTES: usize = 2_048;
const REQUIRED_NAMES_SOURCE_MAX_BYTES: usize = 65_536;
const URI_TEMPLATE_HIGHLIGHT_MAX: usize = 16;

// `Table::add_row_cells` wraps strings as plain `Text`; its values must be
// terminal-safe but must not carry rich escaping, which would render visibly.
fn effective_row_limit(configured: usize) -> usize {
    configured.min(TABLE_ROWS_HARD_MAX)
}

fn omitted_count(total: usize, shown: usize) -> usize {
    total.saturating_sub(shown)
}

fn omitted_label(omitted: usize) -> String {
    format!("... {omitted} more omitted")
}

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
    /// Maximum number of rows rendered (subject to an internal hard ceiling).
    pub max_rows: usize,
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
            max_rows: crate::config::ConsoleConfig::default().max_table_rows,
        }
    }

    /// Create a renderer from centralized console configuration.
    ///
    /// The configured display context and table-row limit are resolved once
    /// when the renderer is constructed.
    #[must_use]
    pub fn from_config(config: &ConsoleConfig) -> Self {
        let mut renderer = Self::new(config.resolve_context());
        renderer.max_rows = config.max_table_rows;
        renderer
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
                console.print_plain("No tools registered");
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
                .max_width(self.description_limit())
                .overflow(OverflowMethod::Ellipsis),
        );

        if self.show_parameters {
            table.add_column(Column::new("Parameters").justify(JustifyMethod::Center));
        }

        let row_limit = self.row_limit();
        for tool in tools.iter().take(row_limit) {
            let name = bounded_redacted_terminal_text(&tool.name, DEFAULT_TERMINAL_FIELD_MAX_CHARS);
            let desc = tool.description.as_deref().unwrap_or("-");
            let truncated_desc = self.truncate_description(desc);

            if self.show_parameters {
                let params = self.format_parameters(&tool.input_schema);
                table.add_row_cells([name.as_str(), truncated_desc.as_str(), params.as_str()]);
            } else {
                table.add_row_cells([name.as_str(), truncated_desc.as_str()]);
            }
        }

        let omitted = omitted_count(tools.len(), row_limit.min(tools.len()));
        if omitted > 0 {
            let label = omitted_label(omitted);
            if self.show_parameters {
                table.add_row_cells([label.as_str(), "", ""]);
            } else {
                table.add_row_cells([label.as_str(), ""]);
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
        let name = bounded_redacted_rich_fragment(&tool.name, DEFAULT_TERMINAL_FIELD_MAX_CHARS);
        let description =
            self.rich_description(tool.description.as_deref().unwrap_or("No description"));
        console.print(&format!("\n[bold cyan]{name}[/]"));
        console.print(&format!("[dim]{description}[/]\n"));

        // Parameters table (extracted from JSON Schema)
        let params = self.extract_parameters(&tool.input_schema);
        let parameter_count = self.parameter_count(&tool.input_schema);
        if parameter_count != 0 {
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

            let row_limit = self.row_limit();
            for param in params.iter().take(row_limit) {
                let required_mark = match param.requiredness {
                    ParameterRequiredness::Required => "✓",
                    ParameterRequiredness::Optional => "",
                    ParameterRequiredness::Unknown => "?",
                };
                let param_name =
                    bounded_redacted_terminal_text(&param.name, DEFAULT_TERMINAL_FIELD_MAX_CHARS);
                let type_name = bounded_redacted_terminal_text(
                    &param.type_name,
                    DEFAULT_TERMINAL_FIELD_MAX_CHARS,
                );
                let description = bounded_redacted_terminal_text(
                    param.description.as_deref().unwrap_or("-"),
                    self.description_limit().min(40),
                );
                param_table.add_row_cells([
                    param_name.as_str(),
                    type_name.as_str(),
                    required_mark,
                    description.as_str(),
                ]);
            }

            let omitted = omitted_count(parameter_count, params.len());
            if omitted > 0 {
                let label = omitted_label(omitted);
                param_table.add_row_cells([label.as_str(), "", "", ""]);
            }

            console.render(&param_table);
        } else {
            console.print("[dim]No parameters[/]");
        }
    }

    fn should_use_rich(&self, console: &FastMcpConsole) -> bool {
        self.context.is_human() && console.is_rich()
    }

    fn row_limit(&self) -> usize {
        effective_row_limit(self.max_rows)
    }

    fn description_limit(&self) -> usize {
        self.max_description_width
            .clamp(1, DEFAULT_TERMINAL_FIELD_MAX_CHARS)
    }

    fn rich_description(&self, description: &str) -> String {
        bounded_redacted_rich_fragment(description, self.description_limit())
    }

    fn format_parameters(&self, schema: &Value) -> String {
        let params = self.extract_parameters(schema);
        let omitted = omitted_count(self.parameter_count(schema), params.len());
        if params.is_empty() {
            if omitted == 0 {
                "none".to_string()
            } else {
                format!("{omitted} omitted")
            }
        } else {
            let required = params
                .iter()
                .filter(|p| p.requiredness == ParameterRequiredness::Required)
                .count();
            let optional = params
                .iter()
                .filter(|p| p.requiredness == ParameterRequiredness::Optional)
                .count();
            let unknown = params.len() - required - optional;

            let visible = match (required, optional, unknown) {
                (r, 0, 0) => format!("{r} required"),
                (0, o, 0) => format!("{o} optional"),
                (r, o, 0) => format!("{r} req, {o} opt"),
                (0, 0, u) => format!("{u} unknown"),
                (r, 0, u) => format!("{r} req, {u} unknown"),
                (0, o, u) => format!("{o} opt, {u} unknown"),
                (r, o, u) => format!("{r} req, {o} opt, {u} unknown"),
            };
            if omitted == 0 {
                visible
            } else {
                format!("{visible}, {omitted} omitted")
            }
        }
    }

    fn parameter_count(&self, schema: &Value) -> usize {
        schema
            .get("properties")
            .and_then(Value::as_object)
            .map_or(0, serde_json::Map::len)
    }

    fn extract_parameters(&self, schema: &Value) -> Vec<ParameterInfo> {
        let mut params = Vec::new();

        let properties = schema.get("properties").and_then(Value::as_object);
        let required_values = schema.get("required").and_then(Value::as_array);
        let mut required_scan_incomplete =
            required_values.is_some_and(|values| values.len() > REQUIRED_NAMES_SCAN_HARD_MAX);
        let mut required_source_bytes = 0usize;
        let mut required = HashSet::new();
        if let Some(values) = required_values {
            for value in values.iter().take(REQUIRED_NAMES_SCAN_HARD_MAX) {
                let Some(name) = value.as_str() else {
                    required_scan_incomplete = true;
                    continue;
                };
                if name.len() > REQUIRED_NAME_SOURCE_MAX_BYTES {
                    required_scan_incomplete = true;
                    continue;
                }
                let Some(next_source_bytes) = required_source_bytes.checked_add(name.len()) else {
                    required_scan_incomplete = true;
                    break;
                };
                if next_source_bytes > REQUIRED_NAMES_SOURCE_MAX_BYTES {
                    required_scan_incomplete = true;
                    break;
                }
                required_source_bytes = next_source_bytes;
                required.insert(name);
            }
        }

        if let Some(props) = properties {
            for (raw_name, prop) in props.iter().take(self.row_limit()) {
                let raw_name_is_bounded = raw_name.len() <= REQUIRED_NAME_SOURCE_MAX_BYTES;
                let requiredness = if raw_name_is_bounded && required.contains(raw_name.as_str()) {
                    ParameterRequiredness::Required
                } else if required_scan_incomplete || !raw_name_is_bounded {
                    ParameterRequiredness::Unknown
                } else {
                    ParameterRequiredness::Optional
                };
                let name =
                    bounded_redacted_terminal_text(raw_name, DEFAULT_TERMINAL_FIELD_MAX_CHARS);
                let type_name = prop.get("type").and_then(Value::as_str).unwrap_or("any");

                let description = prop
                    .get("description")
                    .and_then(Value::as_str)
                    .map(|value| {
                        bounded_redacted_terminal_text(value, DEFAULT_TERMINAL_FIELD_MAX_CHARS)
                    });

                params.push(ParameterInfo {
                    requiredness,
                    name,
                    type_name: bounded_redacted_terminal_text(
                        type_name,
                        DEFAULT_TERMINAL_FIELD_MAX_CHARS,
                    ),
                    description,
                });
            }
        }

        // Sort known-required entries first, then unknown, then known-optional;
        // preserve alphabetical ordering within each truthfulness class.
        params.sort_by(|a, b| {
            a.requiredness
                .sort_rank()
                .cmp(&b.requiredness.sort_rank())
                .then_with(|| a.name.cmp(&b.name))
        });

        params
    }

    fn truncate_description(&self, desc: &str) -> String {
        bounded_redacted_terminal_text(desc, self.description_limit())
    }

    fn render_plain(&self, tools: &[Tool], console: &FastMcpConsole) {
        console.print_plain(&format!("Registered Tools ({})", tools.len()));
        console.print_plain(&"=".repeat(40));
        let row_limit = self.row_limit();
        for tool in tools.iter().take(row_limit) {
            let name = bounded_redacted_terminal_text(&tool.name, DEFAULT_TERMINAL_FIELD_MAX_CHARS);
            let desc = self.truncate_description(tool.description.as_deref().unwrap_or("-"));
            if self.show_parameters {
                let params = self.format_parameters(&tool.input_schema);
                console.print_plain(&format!("  {name} - {desc} [{params}]"));
            } else {
                console.print_plain(&format!("  {name} - {desc}"));
            }
        }
        let omitted = omitted_count(tools.len(), row_limit.min(tools.len()));
        if omitted > 0 {
            console.print_plain(&format!("  {}", omitted_label(omitted)));
        }
    }

    fn render_detail_plain(&self, tool: &Tool, console: &FastMcpConsole) {
        let name = bounded_redacted_terminal_text(&tool.name, DEFAULT_TERMINAL_FIELD_MAX_CHARS);
        console.print_plain(&format!("Tool: {name}"));
        console.print_plain(&format!(
            "Description: {}",
            self.truncate_description(tool.description.as_deref().unwrap_or("No description"))
        ));

        let params = self.extract_parameters(&tool.input_schema);
        let parameter_count = self.parameter_count(&tool.input_schema);
        if parameter_count == 0 {
            console.print_plain("Parameters: none");
        } else {
            console.print_plain("Parameters:");
            let row_limit = self.row_limit();
            for param in params.iter().take(row_limit) {
                let req = match param.requiredness {
                    ParameterRequiredness::Required => "required",
                    ParameterRequiredness::Optional => "optional",
                    ParameterRequiredness::Unknown => "requiredness unknown",
                };
                console.print_plain(&format!(
                    "  - {}: {} ({}) - {}",
                    param.name,
                    param.type_name,
                    req,
                    param.description.as_deref().unwrap_or("-")
                ));
            }
            let omitted = omitted_count(parameter_count, params.len());
            if omitted > 0 {
                console.print_plain(&format!("  {}", omitted_label(omitted)));
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
    requiredness: ParameterRequiredness,
    description: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ParameterRequiredness {
    Required,
    Optional,
    /// The schema's required-name list exceeded the defensive scan budget,
    /// so absence from the scanned prefix cannot prove optionality.
    Unknown,
}

impl ParameterRequiredness {
    const fn sort_rank(self) -> u8 {
        match self {
            Self::Required => 0,
            Self::Unknown => 1,
            Self::Optional => 2,
        }
    }
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
    /// Maximum number of rows or tree leaves rendered (subject to a hard ceiling).
    pub max_rows: usize,
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
            max_rows: crate::config::ConsoleConfig::default().max_table_rows,
        }
    }

    /// Create a renderer from centralized console configuration.
    ///
    /// The configured display context and table-row limit are resolved once
    /// when the renderer is constructed.
    #[must_use]
    pub fn from_config(config: &ConsoleConfig) -> Self {
        let mut renderer = Self::new(config.resolve_context());
        renderer.max_rows = config.max_table_rows;
        renderer
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
                console.print_plain("No resources registered");
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
                .max_width(self.description_limit())
                .overflow(OverflowMethod::Ellipsis),
        );

        if self.show_mime_type {
            table.add_column(Column::new("Type"));
        }

        let row_limit = self.row_limit();
        for resource in resources.iter().take(row_limit) {
            let name =
                bounded_redacted_terminal_text(&resource.name, DEFAULT_TERMINAL_FIELD_MAX_CHARS);
            let desc = resource.description.as_deref().unwrap_or("-");
            let truncated_desc = self.truncate_description(desc);
            let formatted_uri =
                bounded_redacted_terminal_text(&resource.uri, DEFAULT_TERMINAL_FIELD_MAX_CHARS);

            if self.show_mime_type {
                let mime = bounded_redacted_terminal_text(
                    resource.mime_type.as_deref().unwrap_or("-"),
                    DEFAULT_TERMINAL_FIELD_MAX_CHARS,
                );
                table.add_row_cells([
                    name.as_str(),
                    formatted_uri.as_str(),
                    truncated_desc.as_str(),
                    mime.as_str(),
                ]);
            } else {
                table.add_row_cells([
                    name.as_str(),
                    formatted_uri.as_str(),
                    truncated_desc.as_str(),
                ]);
            }
        }

        let omitted = omitted_count(resources.len(), row_limit.min(resources.len()));
        if omitted > 0 {
            let label = omitted_label(omitted);
            if self.show_mime_type {
                table.add_row_cells([label.as_str(), "", "", ""]);
            } else {
                table.add_row_cells([label.as_str(), "", ""]);
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

        let name = bounded_redacted_rich_fragment(&resource.name, DEFAULT_TERMINAL_FIELD_MAX_CHARS);
        let description =
            self.rich_description(resource.description.as_deref().unwrap_or("No description"));
        console.print(&format!("\n[bold cyan]{name}[/]"));
        console.print(&format!("[dim]URI:[/] {}", self.format_uri(&resource.uri)));
        console.print(&format!("[dim]Description:[/] {description}"));
        if let Some(mime) = &resource.mime_type {
            let mime = bounded_redacted_rich_text(mime, DEFAULT_TERMINAL_FIELD_MAX_CHARS);
            console.print(&format!("[dim]MIME Type:[/] {mime}"));
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
                console.print_plain("No resources registered");
            }
            return;
        }

        if !self.should_use_rich(console) {
            self.render_plain(resources, console);
            return;
        }

        // Group resources by URI scheme/prefix
        let mut groups: HashMap<String, Vec<&Resource>> = HashMap::new();
        let row_limit = self.row_limit();
        for resource in resources.iter().take(row_limit) {
            let prefix = self.extract_uri_prefix(&resource.uri);
            groups.entry(prefix).or_default().push(resource);
        }

        // Build tree
        let root = TreeNode::with_icon("📄", format!("[bold]Resources[/] ({})", resources.len()));

        // Sort group keys for consistent ordering
        let mut sorted_keys: Vec<_> = groups.keys().cloned().collect();
        sorted_keys.sort();

        let root = sorted_keys.into_iter().fold(root, |root, prefix| {
            let Some(group_resources) = groups.get(&prefix) else {
                return root;
            };
            let prefix = bounded_redacted_rich_fragment(&prefix, DEFAULT_TERMINAL_FIELD_MAX_CHARS);
            let group_node =
                TreeNode::new(format!("[cyan]{prefix}[/] ({})", group_resources.len()));

            // Add each resource as a child
            let group_node = group_resources.iter().fold(group_node, |node, resource| {
                let name_part = self.extract_uri_path(&resource.uri);
                let desc = bounded_redacted_rich_fragment(
                    resource.description.as_deref().unwrap_or(""),
                    self.description_limit(),
                );
                let leaf_label = if desc.is_empty() {
                    self.format_uri(&name_part)
                } else {
                    format!("{} [dim]- {}[/]", self.format_uri(&name_part), desc)
                };
                node.child(TreeNode::new(leaf_label))
            });

            root.child(group_node)
        });

        let omitted = omitted_count(resources.len(), row_limit.min(resources.len()));
        let root = if omitted > 0 {
            root.child(TreeNode::new(omitted_label(omitted)))
        } else {
            root
        };

        let tree = Tree::new(root).guides(TreeGuides::Rounded);
        console.render(&tree);
    }

    /// Format a URI with template parts highlighted in yellow.
    ///
    /// Template parts like `{path}` or `{id}` are highlighted to make
    /// them visually distinct from static URI parts.
    fn format_uri(&self, uri: &str) -> String {
        let uri = bounded_redacted_terminal_text(uri, DEFAULT_TERMINAL_FIELD_MAX_CHARS);
        if !uri.contains('{') {
            return bounded_redacted_rich_text(&uri, DEFAULT_TERMINAL_FIELD_MAX_CHARS);
        }

        let mut result = String::with_capacity(uri.len().saturating_add(64));
        let mut literal = String::new();
        let mut buffer = String::new();
        let mut in_template = false;
        let mut highlighted = 0usize;

        for c in uri.chars() {
            if in_template {
                buffer.push(c);
                if c == '}' {
                    if highlighted < URI_TEMPLATE_HIGHLIGHT_MAX {
                        result.push_str("[yellow]");
                        result.push_str(&bounded_redacted_rich_fragment(
                            &buffer,
                            DEFAULT_TERMINAL_FIELD_MAX_CHARS,
                        ));
                        result.push_str("[/]");
                        highlighted += 1;
                    } else {
                        result.push_str(&bounded_redacted_rich_text(
                            &buffer,
                            DEFAULT_TERMINAL_FIELD_MAX_CHARS,
                        ));
                    }
                    buffer.clear();
                    in_template = false;
                } else if c == '{' {
                    buffer.pop();
                    result.push_str(&bounded_redacted_rich_fragment(
                        &buffer,
                        DEFAULT_TERMINAL_FIELD_MAX_CHARS,
                    ));
                    buffer.clear();
                    buffer.push(c);
                }
            } else if c == '{' {
                result.push_str(&bounded_redacted_rich_fragment(
                    &literal,
                    DEFAULT_TERMINAL_FIELD_MAX_CHARS,
                ));
                literal.clear();
                in_template = true;
                buffer.push(c);
            } else {
                literal.push(c);
            }
        }

        result.push_str(&bounded_redacted_rich_text(
            &literal,
            DEFAULT_TERMINAL_FIELD_MAX_CHARS,
        ));
        if in_template {
            result.push_str(&bounded_redacted_rich_text(
                &buffer,
                DEFAULT_TERMINAL_FIELD_MAX_CHARS,
            ));
        }

        result
    }

    /// Extract the URI scheme/prefix (e.g., "file", "config", "db").
    fn extract_uri_prefix(&self, uri: &str) -> String {
        let uri = bounded_redacted_terminal_text(uri, DEFAULT_TERMINAL_FIELD_MAX_CHARS);
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
        let uri = bounded_redacted_terminal_text(uri, DEFAULT_TERMINAL_FIELD_MAX_CHARS);
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

    fn row_limit(&self) -> usize {
        effective_row_limit(self.max_rows)
    }

    fn description_limit(&self) -> usize {
        self.max_description_width
            .clamp(1, DEFAULT_TERMINAL_FIELD_MAX_CHARS)
    }

    fn rich_description(&self, description: &str) -> String {
        bounded_redacted_rich_text(description, self.description_limit())
    }

    fn truncate_description(&self, desc: &str) -> String {
        bounded_redacted_terminal_text(desc, self.description_limit())
    }

    fn render_plain(&self, resources: &[Resource], console: &FastMcpConsole) {
        console.print_plain(&format!("Registered Resources ({})", resources.len()));
        console.print_plain(&"=".repeat(40));
        let row_limit = self.row_limit();
        for resource in resources.iter().take(row_limit) {
            let name =
                bounded_redacted_terminal_text(&resource.name, DEFAULT_TERMINAL_FIELD_MAX_CHARS);
            let uri =
                bounded_redacted_terminal_text(&resource.uri, DEFAULT_TERMINAL_FIELD_MAX_CHARS);
            let desc = self.truncate_description(resource.description.as_deref().unwrap_or("-"));
            console.print_plain(&format!("  {name} ({uri}) - {desc}"));
        }
        let omitted = omitted_count(resources.len(), row_limit.min(resources.len()));
        if omitted > 0 {
            console.print_plain(&format!("  {}", omitted_label(omitted)));
        }
    }

    fn render_detail_plain(&self, resource: &Resource, console: &FastMcpConsole) {
        let name = bounded_redacted_terminal_text(&resource.name, DEFAULT_TERMINAL_FIELD_MAX_CHARS);
        let uri = bounded_redacted_terminal_text(&resource.uri, DEFAULT_TERMINAL_FIELD_MAX_CHARS);
        console.print_plain(&format!("Resource: {name}"));
        console.print_plain(&format!("URI: {uri}"));
        console.print_plain(&format!(
            "Description: {}",
            self.truncate_description(resource.description.as_deref().unwrap_or("No description"))
        ));
        if let Some(mime) = &resource.mime_type {
            let mime = bounded_redacted_terminal_text(mime, DEFAULT_TERMINAL_FIELD_MAX_CHARS);
            console.print_plain(&format!("MIME Type: {mime}"));
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
    /// Maximum number of rows rendered (subject to an internal hard ceiling).
    pub max_rows: usize,
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
            max_rows: crate::config::ConsoleConfig::default().max_table_rows,
        }
    }

    /// Create a renderer from centralized console configuration.
    ///
    /// The configured display context and table-row limit are resolved once
    /// when the renderer is constructed.
    #[must_use]
    pub fn from_config(config: &ConsoleConfig) -> Self {
        let mut renderer = Self::new(config.resolve_context());
        renderer.max_rows = config.max_table_rows;
        renderer
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
                console.print_plain("No prompts registered");
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
                .max_width(self.description_limit())
                .overflow(OverflowMethod::Ellipsis),
        );

        if self.show_arguments {
            table.add_column(Column::new("Arguments").justify(JustifyMethod::Center));
        }

        let row_limit = self.row_limit();
        for prompt in prompts.iter().take(row_limit) {
            let name =
                bounded_redacted_terminal_text(&prompt.name, DEFAULT_TERMINAL_FIELD_MAX_CHARS);
            let desc = prompt.description.as_deref().unwrap_or("-");
            let truncated_desc = self.truncate_description(desc);

            if self.show_arguments {
                let args = self.format_arguments(&prompt.arguments);
                table.add_row_cells([name.as_str(), truncated_desc.as_str(), args.as_str()]);
            } else {
                table.add_row_cells([name.as_str(), truncated_desc.as_str()]);
            }
        }

        let omitted = omitted_count(prompts.len(), row_limit.min(prompts.len()));
        if omitted > 0 {
            let label = omitted_label(omitted);
            if self.show_arguments {
                table.add_row_cells([label.as_str(), "", ""]);
            } else {
                table.add_row_cells([label.as_str(), ""]);
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

        let name = bounded_redacted_rich_fragment(&prompt.name, DEFAULT_TERMINAL_FIELD_MAX_CHARS);
        let description =
            self.rich_description(prompt.description.as_deref().unwrap_or("No description"));
        console.print(&format!("\n[bold cyan]{name}[/]"));
        console.print(&format!("[dim]{description}[/]\n"));

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

            let row_limit = self.row_limit();
            for arg in prompt.arguments.iter().take(row_limit) {
                let required_mark = if arg.required { "✓" } else { "" };
                let name =
                    bounded_redacted_terminal_text(&arg.name, DEFAULT_TERMINAL_FIELD_MAX_CHARS);
                let description = bounded_redacted_terminal_text(
                    arg.description.as_deref().unwrap_or("-"),
                    self.description_limit().min(40),
                );
                arg_table.add_row_cells([name.as_str(), required_mark, description.as_str()]);
            }

            let omitted = omitted_count(
                prompt.arguments.len(),
                row_limit.min(prompt.arguments.len()),
            );
            if omitted > 0 {
                let label = omitted_label(omitted);
                arg_table.add_row_cells([label.as_str(), "", ""]);
            }

            console.render(&arg_table);
        } else {
            console.print("[dim]No arguments[/]");
        }
    }

    fn should_use_rich(&self, console: &FastMcpConsole) -> bool {
        self.context.is_human() && console.is_rich()
    }

    fn row_limit(&self) -> usize {
        effective_row_limit(self.max_rows)
    }

    fn description_limit(&self) -> usize {
        self.max_description_width
            .clamp(1, DEFAULT_TERMINAL_FIELD_MAX_CHARS)
    }

    fn rich_description(&self, description: &str) -> String {
        bounded_redacted_rich_fragment(description, self.description_limit())
    }

    fn format_arguments(&self, args: &[PromptArgument]) -> String {
        if args.is_empty() {
            return "none".to_string();
        }
        let shown = self.row_limit().min(args.len());
        let required = args.iter().take(shown).filter(|a| a.required).count();
        let optional = shown - required;
        let visible = match (required, optional) {
            (r, 0) => format!("{r} required"),
            (0, o) => format!("{o} optional"),
            (r, o) => format!("{r} req, {o} opt"),
        };
        let omitted = omitted_count(args.len(), shown);
        if omitted == 0 {
            visible
        } else if shown == 0 {
            format!("{omitted} omitted")
        } else {
            format!("{visible}, {omitted} omitted")
        }
    }

    fn truncate_description(&self, desc: &str) -> String {
        bounded_redacted_terminal_text(desc, self.description_limit())
    }

    fn render_plain(&self, prompts: &[Prompt], console: &FastMcpConsole) {
        console.print_plain(&format!("Registered Prompts ({})", prompts.len()));
        console.print_plain(&"=".repeat(40));
        let row_limit = self.row_limit();
        for prompt in prompts.iter().take(row_limit) {
            let name =
                bounded_redacted_terminal_text(&prompt.name, DEFAULT_TERMINAL_FIELD_MAX_CHARS);
            let desc = self.truncate_description(prompt.description.as_deref().unwrap_or("-"));
            if self.show_arguments {
                let args = self.format_arguments(&prompt.arguments);
                console.print_plain(&format!("  {name} - {desc} [{args}]"));
            } else {
                console.print_plain(&format!("  {name} - {desc}"));
            }
        }
        let omitted = omitted_count(prompts.len(), row_limit.min(prompts.len()));
        if omitted > 0 {
            console.print_plain(&format!("  {}", omitted_label(omitted)));
        }
    }

    fn render_detail_plain(&self, prompt: &Prompt, console: &FastMcpConsole) {
        let name = bounded_redacted_terminal_text(&prompt.name, DEFAULT_TERMINAL_FIELD_MAX_CHARS);
        console.print_plain(&format!("Prompt: {name}"));
        console.print_plain(&format!(
            "Description: {}",
            self.truncate_description(prompt.description.as_deref().unwrap_or("No description"))
        ));

        if prompt.arguments.is_empty() {
            console.print_plain("Arguments: none");
        } else {
            console.print_plain("Arguments:");
            let row_limit = self.row_limit();
            for arg in prompt.arguments.iter().take(row_limit) {
                let req = if arg.required { "required" } else { "optional" };
                let name =
                    bounded_redacted_terminal_text(&arg.name, DEFAULT_TERMINAL_FIELD_MAX_CHARS);
                let description = bounded_redacted_terminal_text(
                    arg.description.as_deref().unwrap_or("-"),
                    self.description_limit().min(40),
                );
                console.print_plain(&format!("  - {name} ({req}) - {description}"));
            }
            let omitted = omitted_count(
                prompt.arguments.len(),
                row_limit.min(prompt.arguments.len()),
            );
            if omitted > 0 {
                console.print_plain(&format!("  {}", omitted_label(omitted)));
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
                output_schema: None,
                icon: None,
                version: None,
                tags: vec![],
                annotations: None,
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
                output_schema: None,
                icon: None,
                version: None,
                tags: vec![],
                annotations: None,
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
                icon: None,
                version: None,
                tags: vec![],
            },
            Resource {
                uri: "file://data.csv".to_string(),
                name: "data".to_string(),
                description: Some("Data file".to_string()),
                mime_type: Some("text/csv".to_string()),
                icon: None,
                version: None,
                tags: vec![],
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
                icon: None,
                version: None,
                tags: vec![],
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
                icon: None,
                version: None,
                tags: vec![],
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
    fn test_tool_table_empty_rich() {
        let console = TestConsole::new_rich();
        let renderer = ToolTableRenderer::new(DisplayContext::new_human());
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
        assert_eq!(params[0].requiredness, ParameterRequiredness::Required);
        assert_eq!(params[0].name, "expression");
    }

    #[test]
    fn config_constructors_apply_resolved_context_and_table_row_limit() {
        let config = ConsoleConfig::new()
            .with_context(DisplayContext::new_agent())
            .with_max_table_rows(1);

        let tool_renderer = ToolTableRenderer::from_config(&config);
        let resource_renderer = ResourceTableRenderer::from_config(&config);
        let prompt_renderer = PromptTableRenderer::from_config(&config);
        assert_eq!(tool_renderer.context, DisplayContext::Agent);
        assert_eq!(resource_renderer.context, DisplayContext::Agent);
        assert_eq!(prompt_renderer.context, DisplayContext::Agent);
        assert_eq!(tool_renderer.max_rows, 1);
        assert_eq!(resource_renderer.max_rows, 1);
        assert_eq!(prompt_renderer.max_rows, 1);

        let tools = TestConsole::new();
        tool_renderer.render(&sample_tools(), tools.console());
        tools.assert_contains("1 more omitted");
        tools.assert_not_contains("search");

        let resources = TestConsole::new();
        resource_renderer.render(&sample_resources(), resources.console());
        resources.assert_contains("1 more omitted");
        resources.assert_not_contains("data.csv");

        let prompts = TestConsole::new();
        prompt_renderer.render(&sample_prompts(), prompts.console());
        prompts.assert_contains("1 more omitted");
        prompts.assert_not_contains("summarize");
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
    fn test_resource_table_empty_rich() {
        let console = TestConsole::new_rich();
        let renderer = ResourceTableRenderer::new(DisplayContext::new_human());
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
    fn test_prompt_table_empty_rich() {
        let console = TestConsole::new_rich();
        let renderer = PromptTableRenderer::new(DisplayContext::new_human());
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
            max_rows: 100,
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
                icon: None,
                version: None,
                tags: vec![],
            },
            Resource {
                uri: "file://config.json".to_string(),
                name: "config".to_string(),
                description: Some("Application config".to_string()),
                mime_type: Some("application/json".to_string()),
                icon: None,
                version: None,
                tags: vec![],
            },
            Resource {
                uri: "db://users/{id}".to_string(),
                name: "user".to_string(),
                description: Some("User record by ID".to_string()),
                mime_type: None,
                icon: None,
                version: None,
                tags: vec![],
            },
            Resource {
                uri: "cache://stats".to_string(),
                name: "stats".to_string(),
                description: Some("Cached statistics".to_string()),
                mime_type: None,
                icon: None,
                version: None,
                tags: vec![],
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

    #[test]
    fn test_tool_table_plain_without_parameter_summary() {
        let tools = sample_tools();
        let console = TestConsole::new();
        let mut renderer = ToolTableRenderer::new(DisplayContext::new_agent());
        renderer.show_parameters = false;
        renderer.render(&tools, console.console());
        console.assert_contains("Registered Tools (2)");
        console.assert_not_contains("[");
    }

    #[test]
    fn test_tool_table_rich_without_parameter_summary() {
        let tools = sample_tools();
        let console = TestConsole::new_rich();
        let mut renderer = ToolTableRenderer::new(DisplayContext::new_human());
        renderer.show_parameters = false;
        renderer.render(&tools, console.console());
        console.assert_contains("Registered Tools");
        console.assert_contains("calculate");
    }

    #[test]
    fn test_tool_detail_plain_and_rich() {
        let tools = sample_tools();

        let plain = TestConsole::new();
        let renderer_plain = ToolTableRenderer::new(DisplayContext::new_agent());
        renderer_plain.render_detail(&tools[0], plain.console());
        plain.assert_contains("Tool: calculate");
        plain.assert_contains("Parameters:");
        plain.assert_contains("expression: string (required)");

        let rich = TestConsole::new_rich();
        let renderer_rich = ToolTableRenderer::new(DisplayContext::new_human());
        renderer_rich.render_detail(&tools[0], rich.console());
        rich.assert_contains("calculate");
        rich.assert_contains("Parameters");
    }

    #[test]
    fn test_tool_detail_plain_no_parameters() {
        let tool = Tool {
            name: "ping".to_string(),
            description: Some("No args".to_string()),
            input_schema: json!({"type": "object"}),
            output_schema: None,
            icon: None,
            version: None,
            tags: vec![],
            annotations: None,
        };
        let console = TestConsole::new();
        let renderer = ToolTableRenderer::new(DisplayContext::new_agent());
        renderer.render_detail(&tool, console.console());
        console.assert_contains("Parameters: none");
    }

    #[test]
    fn test_tool_detail_rich_no_parameters() {
        let tool = Tool {
            name: "ping".to_string(),
            description: Some("No args".to_string()),
            input_schema: json!({"type": "object"}),
            output_schema: None,
            icon: None,
            version: None,
            tags: vec![],
            annotations: None,
        };
        let console = TestConsole::new_rich();
        let renderer = ToolTableRenderer::new(DisplayContext::new_human());
        renderer.render_detail(&tool, console.console());
        console.assert_contains("ping");
        console.assert_contains("No parameters");
    }

    #[test]
    fn test_tool_format_parameters_variants() {
        let renderer = ToolTableRenderer::new(DisplayContext::new_agent());
        assert_eq!(
            renderer.format_parameters(&json!({"type": "object"})),
            "none"
        );
        assert_eq!(
            renderer.format_parameters(&json!({
                "type": "object",
                "properties": {"a": {"type": "string"}},
                "required": ["a"]
            })),
            "1 required"
        );
        assert_eq!(
            renderer.format_parameters(&json!({
                "type": "object",
                "properties": {"a": {"type": "string"}}
            })),
            "1 optional"
        );
        assert_eq!(
            renderer.format_parameters(&json!({
                "type": "object",
                "properties": {"a": {"type": "string"}, "b": {"type": "number"}},
                "required": ["a"]
            })),
            "1 req, 1 opt"
        );
    }

    #[test]
    fn test_tool_extract_parameters_defaults_to_any() {
        let renderer = ToolTableRenderer::new(DisplayContext::new_agent());
        let params = renderer.extract_parameters(&json!({
            "type": "object",
            "properties": {
                "raw": {}
            }
        }));
        assert_eq!(params.len(), 1);
        assert_eq!(params[0].name, "raw");
        assert_eq!(params[0].type_name, "any");
        assert_eq!(params[0].requiredness, ParameterRequiredness::Optional);
        assert!(params[0].description.is_none());
    }

    #[test]
    fn test_tool_extract_parameters_sorts_required_before_optional() {
        let renderer = ToolTableRenderer::new(DisplayContext::new_agent());
        let params = renderer.extract_parameters(&json!({
            "type": "object",
            "properties": {
                "a": {"type": "string"},
                "z": {"type": "number"}
            },
            "required": ["z"]
        }));
        assert_eq!(params.len(), 2);
        assert_eq!(params[0].name, "z");
        assert_eq!(params[0].requiredness, ParameterRequiredness::Required);
        assert_eq!(params[1].name, "a");
        assert_eq!(params[1].requiredness, ParameterRequiredness::Optional);
    }

    #[test]
    fn tool_requiredness_uses_raw_names_before_display_truncation() {
        let common_prefix = "x".repeat(DEFAULT_TERMINAL_FIELD_MAX_CHARS + 8);
        let required_name = format!("{common_prefix}-required");
        let optional_name = format!("{common_prefix}-optional");
        let mut properties = serde_json::Map::new();
        properties.insert(required_name.clone(), json!({"type": "string"}));
        properties.insert(optional_name, json!({"type": "string"}));
        let schema = json!({
            "type": "object",
            "properties": properties,
            "required": [required_name]
        });

        let renderer = ToolTableRenderer::new(DisplayContext::new_agent());
        let params = renderer.extract_parameters(&schema);
        assert_eq!(params.len(), 2);
        assert_eq!(params[0].name, params[1].name);
        assert_eq!(
            params
                .iter()
                .filter(|param| param.requiredness == ParameterRequiredness::Required)
                .count(),
            1
        );
        assert_eq!(
            params
                .iter()
                .filter(|param| param.requiredness == ParameterRequiredness::Optional)
                .count(),
            1
        );
    }

    #[test]
    fn tool_requiredness_bounds_each_raw_schema_name_before_hashing() {
        let bounded_name = "a".repeat(REQUIRED_NAME_SOURCE_MAX_BYTES);
        let oversized_name = "b".repeat(REQUIRED_NAME_SOURCE_MAX_BYTES + 1);
        let mut properties = serde_json::Map::new();
        properties.insert(bounded_name.clone(), json!({"type": "string"}));
        properties.insert(oversized_name.clone(), json!({"type": "string"}));
        let schema = json!({
            "type": "object",
            "properties": properties,
            "required": [bounded_name, oversized_name]
        });

        let params =
            ToolTableRenderer::new(DisplayContext::new_agent()).extract_parameters(&schema);
        assert_eq!(params.len(), 2);
        assert_eq!(
            params
                .iter()
                .filter(|param| param.requiredness == ParameterRequiredness::Required)
                .count(),
            1
        );
        assert_eq!(
            params
                .iter()
                .filter(|param| param.requiredness == ParameterRequiredness::Unknown)
                .count(),
            1
        );
    }

    #[test]
    fn tool_requiredness_bounds_aggregate_required_name_bytes() {
        let mut required = (0..(REQUIRED_NAMES_SOURCE_MAX_BYTES / REQUIRED_NAME_SOURCE_MAX_BYTES))
            .map(|index| {
                format!(
                    "{index:04}{}",
                    "r".repeat(REQUIRED_NAME_SOURCE_MAX_BYTES - 4)
                )
            })
            .collect::<Vec<_>>();
        assert_eq!(
            required.iter().map(String::len).sum::<usize>(),
            REQUIRED_NAMES_SOURCE_MAX_BYTES
        );
        let accepted_name = required[0].clone();
        let late_name = "late".to_string();
        required.push(late_name.clone());
        let schema = json!({
            "type": "object",
            "properties": {
                (accepted_name): {"type": "string"},
                "early_optional": {"type": "string"},
                (late_name): {"type": "string"}
            },
            "required": required
        });

        let params =
            ToolTableRenderer::new(DisplayContext::new_agent()).extract_parameters(&schema);
        assert_eq!(params.len(), 3);
        assert_eq!(
            params
                .iter()
                .filter(|param| param.requiredness == ParameterRequiredness::Required)
                .count(),
            1
        );
        assert_eq!(
            params
                .iter()
                .filter(|param| param.requiredness == ParameterRequiredness::Unknown)
                .count(),
            2
        );
    }

    #[test]
    fn oversized_property_name_is_bounded_and_has_unknown_requiredness() {
        let huge_name = "p".repeat(100_000);
        let mut properties = serde_json::Map::new();
        properties.insert(huge_name, json!({"type": "string"}));
        let schema = json!({
            "type": "object",
            "properties": properties,
            "required": []
        });

        let params =
            ToolTableRenderer::new(DisplayContext::new_agent()).extract_parameters(&schema);
        assert_eq!(params.len(), 1);
        assert_eq!(params[0].requiredness, ParameterRequiredness::Unknown);
        assert!(params[0].name.chars().count() <= DEFAULT_TERMINAL_FIELD_MAX_CHARS);
        assert!(params[0].name.ends_with("..."));
    }

    #[test]
    fn tool_requiredness_is_unknown_when_required_scan_is_incomplete() {
        let mut required = Vec::with_capacity(REQUIRED_NAMES_SCAN_HARD_MAX + 1);
        required.push(Value::String("early_required".to_string()));
        required.extend(
            (1..REQUIRED_NAMES_SCAN_HARD_MAX)
                .map(|index| Value::String(format!("irrelevant_{index}"))),
        );
        required.push(Value::String("late_required".to_string()));
        let schema = json!({
            "type": "object",
            "properties": {
                "early_required": {"type": "string"},
                "late_required": {"type": "string"},
                "actually_optional": {"type": "string"}
            },
            "required": required
        });

        let renderer = ToolTableRenderer::new(DisplayContext::new_agent());
        let params = renderer.extract_parameters(&schema);
        assert_eq!(params.len(), 3);
        assert_eq!(
            params
                .iter()
                .find(|param| param.name == "early_required")
                .map(|param| param.requiredness),
            Some(ParameterRequiredness::Required)
        );
        for name in ["late_required", "actually_optional"] {
            assert_eq!(
                params
                    .iter()
                    .find(|param| param.name == name)
                    .map(|param| param.requiredness),
                Some(ParameterRequiredness::Unknown)
            );
        }
        assert_eq!(renderer.format_parameters(&schema), "1 req, 2 unknown");

        let console = TestConsole::new();
        let tool = Tool {
            name: "scan-limited".to_string(),
            description: None,
            input_schema: schema,
            output_schema: None,
            icon: None,
            version: None,
            tags: vec![],
            annotations: None,
        };
        renderer.render_detail(&tool, console.console());
        console.assert_contains("late_required: string (requiredness unknown)");
        console.assert_contains("actually_optional: string (requiredness unknown)");
        console.assert_not_contains("late_required: string (optional)");
    }

    #[test]
    fn test_resource_table_without_mime_column() {
        let resources = sample_resources();
        let console = TestConsole::new();
        let mut renderer = ResourceTableRenderer::new(DisplayContext::new_agent());
        renderer.show_mime_type = false;
        renderer.render(&resources, console.console());
        console.assert_contains("Registered Resources (2)");
        console.assert_contains("config (file://config.json) - Application configuration");
    }

    #[test]
    fn test_resource_table_rich_with_and_without_mime_column() {
        let resources = sample_resources();
        let console = TestConsole::new_rich();
        let mut renderer = ResourceTableRenderer::new(DisplayContext::new_human());

        renderer.render(&resources, console.console());
        console.assert_contains("Registered Resources");
        console.assert_contains("application/json");

        console.clear();
        renderer.show_mime_type = false;
        renderer.render(&resources, console.console());
        console.assert_contains("Registered Resources");
        console.assert_not_contains("application/json");
    }

    #[test]
    fn test_resource_detail_plain_and_rich() {
        let resources = sample_resources();

        let plain = TestConsole::new();
        let renderer_plain = ResourceTableRenderer::new(DisplayContext::new_agent());
        renderer_plain.render_detail(&resources[0], plain.console());
        plain.assert_contains("Resource: config");
        plain.assert_contains("URI: file://config.json");
        plain.assert_contains("MIME Type: application/json");

        let rich = TestConsole::new_rich();
        let renderer_rich = ResourceTableRenderer::new(DisplayContext::new_human());
        renderer_rich.render_detail(&resources[0], rich.console());
        rich.assert_contains("config");
        rich.assert_contains("URI:");
    }

    #[test]
    fn test_resource_detail_plain_without_mime() {
        let resource = Resource {
            uri: "cache://hits".to_string(),
            name: "hits".to_string(),
            description: Some("Cache hits".to_string()),
            mime_type: None,
            icon: None,
            version: None,
            tags: vec![],
        };
        let console = TestConsole::new();
        let renderer = ResourceTableRenderer::new(DisplayContext::new_agent());
        renderer.render_detail(&resource, console.console());
        console.assert_contains("Resource: hits");
        console.assert_not_contains("MIME Type:");
    }

    #[test]
    fn test_resource_tree_render_rich_groups_by_prefix() {
        let resources = sample_resources_with_templates();
        let console = TestConsole::new_rich();
        let renderer = ResourceTableRenderer::new(DisplayContext::new_human());
        renderer.render_tree(&resources, console.console());
        console.assert_contains("Resources");
        console.assert_contains("(4)");
        console.assert_contains("file");
        console.assert_contains("db");
        console.assert_contains("cache");
    }

    #[test]
    fn test_resource_tree_render_rich_with_empty_description_leaf() {
        let mut resources = sample_resources_with_templates();
        resources.push(Resource {
            uri: "file://no-desc".to_string(),
            name: "no_desc".to_string(),
            description: None,
            mime_type: None,
            icon: None,
            version: None,
            tags: vec![],
        });

        let console = TestConsole::new_rich();
        let renderer = ResourceTableRenderer::new(DisplayContext::new_human());
        renderer.render_tree(&resources, console.console());
        console.assert_contains("no-desc");
        console.assert_not_contains("no-desc -");
    }

    #[test]
    fn test_resource_format_uri_unclosed_and_nested_braces() {
        let renderer = ResourceTableRenderer::new(DisplayContext::new_agent());
        assert_eq!(renderer.format_uri("file://{path"), "file://{path");
        assert_eq!(
            renderer.format_uri("weird://{a{b}"),
            "weird://{a[yellow]{b}[/]"
        );
    }

    #[test]
    fn test_resource_extract_uri_path_no_scheme() {
        let renderer = ResourceTableRenderer::new(DisplayContext::new_agent());
        assert_eq!(renderer.extract_uri_path("just-a-path"), "just-a-path");
    }

    #[test]
    fn test_prompt_table_plain_without_argument_summary() {
        let prompts = sample_prompts();
        let console = TestConsole::new();
        let mut renderer = PromptTableRenderer::new(DisplayContext::new_agent());
        renderer.show_arguments = false;
        renderer.render(&prompts, console.console());
        console.assert_contains("Registered Prompts (2)");
        console.assert_contains("greeting - Generate a greeting message");
    }

    #[test]
    fn test_prompt_table_rich_without_argument_summary() {
        let prompts = sample_prompts();
        let console = TestConsole::new_rich();
        let mut renderer = PromptTableRenderer::new(DisplayContext::new_human());
        renderer.show_arguments = false;
        renderer.render(&prompts, console.console());
        console.assert_contains("Registered Prompts");
        console.assert_contains("greeting");
    }

    #[test]
    fn test_prompt_detail_plain_and_rich() {
        let prompts = sample_prompts();

        let plain = TestConsole::new();
        let renderer_plain = PromptTableRenderer::new(DisplayContext::new_agent());
        renderer_plain.render_detail(&prompts[1], plain.console());
        plain.assert_contains("Prompt: summarize");
        plain.assert_contains("Arguments:");
        plain.assert_contains("text (required)");
        plain.assert_contains("length (optional)");

        let rich = TestConsole::new_rich();
        let renderer_rich = PromptTableRenderer::new(DisplayContext::new_human());
        renderer_rich.render_detail(&prompts[1], rich.console());
        rich.assert_contains("summarize");
        rich.assert_contains("Arguments");
    }

    #[test]
    fn test_prompt_detail_plain_no_arguments() {
        let prompt = Prompt {
            name: "ping".to_string(),
            description: Some("No args".to_string()),
            arguments: vec![],
            icon: None,
            version: None,
            tags: vec![],
        };
        let console = TestConsole::new();
        let renderer = PromptTableRenderer::new(DisplayContext::new_agent());
        renderer.render_detail(&prompt, console.console());
        console.assert_contains("Arguments: none");
    }

    #[test]
    fn test_prompt_detail_rich_no_arguments() {
        let prompt = Prompt {
            name: "ping".to_string(),
            description: Some("No args".to_string()),
            arguments: vec![],
            icon: None,
            version: None,
            tags: vec![],
        };
        let console = TestConsole::new_rich();
        let renderer = PromptTableRenderer::new(DisplayContext::new_human());
        renderer.render_detail(&prompt, console.console());
        console.assert_contains("ping");
        console.assert_contains("No arguments");
    }

    #[test]
    fn test_resource_and_prompt_description_truncation_helpers() {
        let resource_renderer = ResourceTableRenderer {
            theme: crate::theme::theme(),
            context: DisplayContext::new_human(),
            max_description_width: 12,
            show_mime_type: true,
            max_rows: 100,
        };
        assert_eq!(resource_renderer.truncate_description("short"), "short");
        assert_eq!(
            resource_renderer.truncate_description("this description is too long"),
            "this desc..."
        );

        let prompt_renderer = PromptTableRenderer {
            theme: crate::theme::theme(),
            context: DisplayContext::new_human(),
            max_description_width: 12,
            show_arguments: true,
            max_rows: 100,
        };
        assert_eq!(prompt_renderer.truncate_description("short"), "short");
        assert_eq!(
            prompt_renderer.truncate_description("this description is too long"),
            "this desc..."
        );
    }

    #[test]
    fn test_prompt_format_arguments_variants() {
        let renderer = PromptTableRenderer::new(DisplayContext::new_agent());
        assert_eq!(renderer.format_arguments(&[]), "none");
        assert_eq!(
            renderer.format_arguments(&[PromptArgument {
                name: "a".to_string(),
                description: None,
                required: true,
            }]),
            "1 required"
        );
        assert_eq!(
            renderer.format_arguments(&[PromptArgument {
                name: "b".to_string(),
                description: None,
                required: false,
            }]),
            "1 optional"
        );
    }

    #[test]
    fn test_legacy_render_functions() {
        let tools = sample_tools();
        let resources = sample_resources();
        let prompts = sample_prompts();
        let console = TestConsole::new();

        render_tools_table(&tools, console.console());
        render_resources_table(&resources, console.console());
        render_prompts_table(&prompts, console.console());

        console.assert_contains("Registered Tools (2)");
        console.assert_contains("Registered Resources (2)");
        console.assert_contains("Registered Prompts (2)");
    }

    #[test]
    fn test_renderer_defaults_detect() {
        let _tool = ToolTableRenderer::default();
        let _resource = ResourceTableRenderer::default();
        let _prompt = PromptTableRenderer::default();
    }

    #[test]
    fn test_plain_tables_preserve_brackets_and_escape_terminal_controls() {
        let hostile = "[literal]\nnext\u{1b}\u{202e}";

        let tool = Tool {
            name: hostile.to_string(),
            description: Some(hostile.to_string()),
            input_schema: json!({"type": "object"}),
            output_schema: None,
            icon: None,
            version: None,
            tags: vec![],
            annotations: None,
        };
        let tool_console = TestConsole::new();
        ToolTableRenderer::new(DisplayContext::new_agent()).render(&[tool], tool_console.console());
        tool_console.assert_contains("[literal]");
        tool_console.assert_contains(r"\nnext\u{1b}\u{202e}");
        tool_console.assert_not_contains(r"\[literal]");

        let resource = Resource {
            uri: format!("file://{hostile}"),
            name: hostile.to_string(),
            description: Some(hostile.to_string()),
            mime_type: Some(hostile.to_string()),
            icon: None,
            version: None,
            tags: vec![],
        };
        let resource_console = TestConsole::new();
        ResourceTableRenderer::new(DisplayContext::new_agent())
            .render_detail(&resource, resource_console.console());
        resource_console.assert_contains("Resource: [literal]");
        resource_console.assert_contains(r"\nnext\u{1b}\u{202e}");
        resource_console.assert_not_contains(r"\[literal]");

        let prompt = Prompt {
            name: hostile.to_string(),
            description: Some(hostile.to_string()),
            arguments: vec![PromptArgument {
                name: hostile.to_string(),
                description: Some(hostile.to_string()),
                required: true,
            }],
            icon: None,
            version: None,
            tags: vec![],
        };
        let prompt_console = TestConsole::new();
        PromptTableRenderer::new(DisplayContext::new_agent())
            .render_detail(&prompt, prompt_console.console());
        prompt_console.assert_contains("Prompt: [literal]");
        prompt_console.assert_contains(r"\nnext\u{1b}\u{202e}");
        prompt_console.assert_not_contains(r"\[literal]");
    }

    #[test]
    fn test_rich_tables_render_untrusted_markup_as_literal_text() {
        let canary = "[bold red]FORGED[/]";
        let parity_canary = r"\[link=https://attacker.invalid]PARITY[/]";
        let tool = Tool {
            name: canary.to_string(),
            description: Some(parity_canary.to_string()),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "[italic]parameter[/]": {
                        "type": "[blue]string[/]",
                        "description": canary
                    }
                }
            }),
            output_schema: None,
            icon: None,
            version: None,
            tags: vec![],
            annotations: None,
        };
        let console = TestConsole::new_rich();
        let renderer = ToolTableRenderer::new(DisplayContext::new_human());
        renderer.render(&[tool.clone()], console.console());
        renderer.render_detail(&tool, console.console());
        console.assert_contains(canary);
        console.assert_contains(parity_canary);
        console.assert_contains("[italic]parameter[/]");
        console.assert_contains("[blue]string[/]");
        console.assert_not_contains(r"\[bold red]FORGED\[/]");
        console.assert_not_contains(r"\[italic]parameter\[/]");
        console.assert_not_contains(r"\[blue]string\[/]");

        let resource_renderer = ResourceTableRenderer::new(DisplayContext::new_human());
        let formatted = resource_renderer.format_uri("file://[bold]x[/]/{id}\u{1b}");
        assert!(formatted.contains(r"\[bold]x\[/]"));
        assert!(formatted.contains("[yellow]{id}[/]"));
        assert!(!formatted.contains('\u{1b}'));
    }

    #[test]
    fn test_rich_resource_summary_uses_plain_terminal_safe_uri_cells() {
        // Cells must FIT the default 80-column table: truncation would clip
        // the very literals this test asserts on, so the hostile fixture
        // stays short while still covering markup pass-through and redaction.
        let resource = Resource {
            uri: "[bold]s[/]?token=uri-canary".to_string(),
            name: "[cyan]resource[/]".to_string(),
            description: Some("[dim]d[/]".to_string()),
            mime_type: Some("[green]a[/]".to_string()),
            icon: None,
            version: None,
            tags: vec![],
        };
        let console = TestConsole::new_rich();
        ResourceTableRenderer::new(DisplayContext::new_human())
            .render(&[resource], console.console());

        console.assert_contains("[cyan]resource[/]");
        console.assert_contains("[bold]s[/]?token=[REDACTED]");
        console.assert_contains("[dim]d[/]");
        console.assert_contains("[green]a[/]");
        console.assert_not_contains("[yellow]");
        console.assert_not_contains(r"\[bold]s\[/]");
        console.assert_not_contains("uri-canary");
    }

    #[test]
    fn test_collection_and_tree_renderers_enforce_row_limits() {
        let mut tools = sample_tools();
        let mut extra_tool = tools[0].clone();
        extra_tool.name = "third-tool".to_string();
        tools.push(extra_tool);
        let tool_console = TestConsole::new();
        let mut tool_renderer = ToolTableRenderer::new(DisplayContext::new_agent());
        tool_renderer.max_rows = 1;
        tool_renderer.render(&tools, tool_console.console());
        tool_console.assert_contains("calculate");
        tool_console.assert_contains("2 more omitted");
        tool_console.assert_not_contains("search");
        tool_console.assert_not_contains("third-tool");

        let resources = sample_resources_with_templates();
        let resource_console = TestConsole::new_rich();
        let mut resource_renderer = ResourceTableRenderer::new(DisplayContext::new_human());
        resource_renderer.max_rows = 1;
        resource_renderer.render_tree(&resources, resource_console.console());
        resource_console.assert_contains("3 more omitted");
        resource_console.assert_contains("{path}");
        resource_console.assert_not_contains("config.json");
        resource_console.assert_not_contains("users/{id}");

        let prompts = sample_prompts();
        let prompt_console = TestConsole::new();
        let mut prompt_renderer = PromptTableRenderer::new(DisplayContext::new_agent());
        prompt_renderer.max_rows = 1;
        prompt_renderer.render(&prompts, prompt_console.console());
        prompt_console.assert_contains("greeting");
        prompt_console.assert_contains("1 more omitted");
        prompt_console.assert_not_contains("summarize");
    }

    #[test]
    fn test_detail_renderers_enforce_nested_row_limits() {
        let tool = Tool {
            name: "bounded-tool".to_string(),
            description: None,
            input_schema: json!({
                "type": "object",
                "properties": {
                    "a": {"type": "string"},
                    "b": {"type": "string"},
                    "c": {"type": "string"}
                }
            }),
            output_schema: None,
            icon: None,
            version: None,
            tags: vec![],
            annotations: None,
        };
        let tool_console = TestConsole::new();
        let mut tool_renderer = ToolTableRenderer::new(DisplayContext::new_agent());
        tool_renderer.max_rows = 1;
        tool_renderer.render_detail(&tool, tool_console.console());
        tool_console.assert_contains("a: string");
        tool_console.assert_contains("2 more omitted");
        tool_console.assert_not_contains("b: string");
        tool_console.assert_not_contains("c: string");

        let prompt = Prompt {
            name: "bounded-prompt".to_string(),
            description: None,
            arguments: vec![
                PromptArgument {
                    name: "first".to_string(),
                    description: None,
                    required: true,
                },
                PromptArgument {
                    name: "second".to_string(),
                    description: None,
                    required: false,
                },
            ],
            icon: None,
            version: None,
            tags: vec![],
        };
        let prompt_console = TestConsole::new();
        let mut prompt_renderer = PromptTableRenderer::new(DisplayContext::new_agent());
        prompt_renderer.max_rows = 1;
        prompt_renderer.render_detail(&prompt, prompt_console.console());
        prompt_console.assert_contains("first (required)");
        prompt_console.assert_contains("1 more omitted");
        prompt_console.assert_not_contains("second (optional)");
    }

    #[test]
    fn test_row_and_description_limits_have_hard_ceilings() {
        let mut renderer = ToolTableRenderer::new(DisplayContext::new_agent());
        renderer.max_rows = usize::MAX;
        renderer.max_description_width = usize::MAX;
        assert_eq!(renderer.row_limit(), TABLE_ROWS_HARD_MAX);
        assert_eq!(
            renderer.description_limit(),
            DEFAULT_TERMINAL_FIELD_MAX_CHARS
        );
    }
}
