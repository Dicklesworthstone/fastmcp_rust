//! Startup banner for FastMCP servers.
//!
//! Displays a banner when the server starts, showing server info,
//! capabilities, and ready status.

use crate::console::FastMcpConsole;
use crate::theme::FastMcpTheme;
use rich_rust::r#box::ROUNDED;
use rich_rust::markup;
use rich_rust::prelude::*;

/// ASCII art logo for FastMCP.
const LOGO_FULL: &str = r"
  ╭─────────────────────────────────────╮
  │                                     │
  │   ███████╗ █████╗ ███████╗████████╗ │
  │   ██╔════╝██╔══██╗██╔════╝╚══██╔══╝ │
  │   █████╗  ███████║███████╗   ██║    │
  │   ██╔══╝  ██╔══██║╚════██║   ██║    │
  │   ██║     ██║  ██║███████║   ██║    │
  │   ╚═╝     ╚═╝  ╚═╝╚══════╝   ╚═╝    │
  │          ███╗   ███╗ ██████╗██████╗ │
  │          ████╗ ████║██╔════╝██╔══██╗│
  │          ██╔████╔██║██║     ██████╔╝│
  │          ██║╚██╔╝██║██║     ██╔═══╝ │
  │          ██║ ╚═╝ ██║╚██████╗██║     │
  │          ╚═╝     ╚═╝ ╚═════╝╚═╝     │
  │                                     │
  ╰─────────────────────────────────────╯
";

/// Compact logo for narrow terminals.
const LOGO_COMPACT: &str = r"
╭──────────────────────────╮
│  ⚡ FastMCP Rust         │
│  High-Performance MCP    │
╰──────────────────────────╯
";

/// Minimal logo fallback.
const LOGO_MINIMAL: &str = "FastMCP Rust";

/// Builder for the startup banner.
pub struct StartupBanner {
    /// Server name (from ServerInfo)
    server_name: String,
    /// Server version
    version: String,
    /// Optional description/instructions
    description: Option<String>,
    /// Number of registered tools
    tools_count: usize,
    /// Number of registered resources
    resources_count: usize,
    /// Number of registered prompts
    prompts_count: usize,
    /// Transport type being used
    transport: String,
    /// Whether to show the logo
    show_logo: bool,
}

impl StartupBanner {
    /// Create a new banner with server name and version.
    #[must_use]
    pub fn new(server_name: impl Into<String>, version: impl Into<String>) -> Self {
        Self {
            server_name: server_name.into(),
            version: version.into(),
            description: None,
            tools_count: 0,
            resources_count: 0,
            prompts_count: 0,
            transport: "stdio".to_string(),
            show_logo: true,
        }
    }

    /// Set the server description.
    #[must_use]
    pub fn description(mut self, desc: impl Into<String>) -> Self {
        self.description = Some(desc.into());
        self
    }

    /// Set the number of tools.
    #[must_use]
    pub fn tools(mut self, count: usize) -> Self {
        self.tools_count = count;
        self
    }

    /// Set the number of resources.
    #[must_use]
    pub fn resources(mut self, count: usize) -> Self {
        self.resources_count = count;
        self
    }

    /// Set the number of prompts.
    #[must_use]
    pub fn prompts(mut self, count: usize) -> Self {
        self.prompts_count = count;
        self
    }

    /// Set the transport type.
    #[must_use]
    pub fn transport(mut self, transport: impl Into<String>) -> Self {
        self.transport = transport.into();
        self
    }

    /// Disable the logo (show only info).
    #[must_use]
    pub fn no_logo(mut self) -> Self {
        self.show_logo = false;
        self
    }

    /// Render the complete banner.
    pub fn render(&self, console: &FastMcpConsole) {
        if !console.is_rich() {
            self.render_plain();
            return;
        }

        let theme = console.theme();

        // 1. Logo (if enabled)
        if self.show_logo {
            render_logo(console, theme);
            console.newline();
        }

        // 2. Server info panel
        self.render_info_panel(console, theme);
        console.newline();

        // 3. Capabilities table
        self.render_capabilities_table(console, theme);
        console.newline();

        // 4. Ready status
        self.render_ready_status(console, theme);

        // 5. Divider
        console.rule(None);
    }

    fn render_info_panel(&self, console: &FastMcpConsole, theme: &FastMcpTheme) {
        let title_line = format!(
            "[{}]{}[/] [{}]v{}[/]",
            color_hex(&theme.primary),
            self.server_name,
            color_hex(&theme.text_muted),
            self.version
        );

        let mut content = String::new();
        content.push_str(&title_line);

        if let Some(desc) = &self.description {
            content.push_str(&format!("\n[{}]{}[/]", color_hex(&theme.text_dim), desc));
        }

        content.push_str(&format!(
            "\n[{}]High-performance Model Context Protocol framework[/]",
            color_hex(&theme.text_dim)
        ));

        let text = markup::render_or_plain(&content);
        let panel = Panel::from_rich_text(&text, console.width())
            .border_style(theme.border_style.clone())
            .rounded();

        console.render(&panel);
    }

    fn render_capabilities_table(&self, console: &FastMcpConsole, theme: &FastMcpTheme) {
        let mut table = Table::new()
            .title("Capabilities")
            .title_style(theme.header_style.clone())
            .box_style(&ROUNDED)
            .border_style(theme.border_style.clone())
            .show_header(true)
            .with_column(Column::new("Type").style(theme.label_style.clone()))
            .with_column(Column::new("Count").justify(JustifyMethod::Right))
            .with_column(Column::new("Status"));

        let tools_status = status_text(self.tools_count > 0, theme);
        let resources_status = status_text(self.resources_count > 0, theme);
        let prompts_status = status_text(self.prompts_count > 0, theme);

        table.add_row(Row::new(vec![
            Cell::new("Tools"),
            Cell::new(self.tools_count.to_string()),
            Cell::new(tools_status),
        ]));
        table.add_row(Row::new(vec![
            Cell::new("Resources"),
            Cell::new(self.resources_count.to_string()),
            Cell::new(resources_status),
        ]));
        table.add_row(Row::new(vec![
            Cell::new("Prompts"),
            Cell::new(self.prompts_count.to_string()),
            Cell::new(prompts_status),
        ]));

        console.render(&table);
    }

    fn render_ready_status(&self, console: &FastMcpConsole, theme: &FastMcpTheme) {
        console.print(&format!(
            "[{}]✓[/] Server ready on [{}]{}[/]",
            color_hex(&theme.success),
            color_hex(&theme.accent),
            self.transport
        ));
    }

    /// Plain text fallback for agent/CI contexts.
    fn render_plain(&self) {
        eprintln!("FastMCP Server: {} v{}", self.server_name, self.version);
        if let Some(desc) = &self.description {
            eprintln!("  {desc}");
        }
        eprintln!("  Tools: {}", self.tools_count);
        eprintln!("  Resources: {}", self.resources_count);
        eprintln!("  Prompts: {}", self.prompts_count);
        eprintln!("  Transport: {}", self.transport);
        eprintln!("Server ready.");
    }
}

fn status_text(registered: bool, theme: &FastMcpTheme) -> Text {
    let (color, label) = if registered {
        (color_hex(&theme.success), "✓ registered")
    } else {
        (color_hex(&theme.text_dim), "○ none")
    };

    markup::render_or_plain(&format!("[{}]{}[/]", color, label))
}

fn color_hex(color: &Color) -> String {
    color.get_truecolor().hex()
}

/// Choose appropriate logo based on terminal width.
fn choose_logo(width: usize) -> &'static str {
    if width >= 50 {
        LOGO_FULL
    } else if width >= 30 {
        LOGO_COMPACT
    } else {
        LOGO_MINIMAL
    }
}

/// Render logo with gradient (rich mode only).
fn render_logo(console: &FastMcpConsole, theme: &FastMcpTheme) {
    let logo = choose_logo(console.width());
    let gradient = gradient_text(logo, &theme.primary, &theme.secondary);
    console.print(&gradient);
}

/// Render text with a vertical gradient between two colors.
fn gradient_text(text: &str, start: &Color, end: &Color) -> String {
    let lines: Vec<&str> = text.lines().collect();
    let line_count = lines.len().max(1);
    let mut result = String::new();

    for (i, line) in lines.iter().enumerate() {
        let t = if line_count > 1 {
            i as f64 / (line_count - 1) as f64
        } else {
            0.0
        };

        let color = interpolate_colors(start, end, t);
        result.push_str(&format!("[{}]{}[/]\n", color_hex(&color), line));
    }

    result
}

/// Linear interpolation between two colors.
fn interpolate_colors(start: &Color, end: &Color, t: f64) -> Color {
    let start_rgb = start.get_truecolor();
    let end_rgb = end.get_truecolor();

    let r = lerp(start_rgb.red, end_rgb.red, t);
    let g = lerp(start_rgb.green, end_rgb.green, t);
    let b = lerp(start_rgb.blue, end_rgb.blue, t);

    Color::from_rgb(r, g, b)
}

fn lerp(a: u8, b: u8, t: f64) -> u8 {
    let a = a as f64;
    let b = b as f64;
    (a + (b - a) * t).round() as u8
}
