//! Startup banner for FastMCP servers.
//!
//! Displays a banner when the server starts, showing server info,
//! capabilities, and ready status.

use crate::console::{
    FastMcpConsole, bounded_redacted_rich_fragment, bounded_redacted_terminal_text,
};
use crate::theme::FastMcpTheme;
use rich_rust::r#box::ROUNDED;
use rich_rust::markup;
use rich_rust::prelude::*;

const SERVER_NAME_MAX_CHARS: usize = 128;
const SERVER_VERSION_MAX_CHARS: usize = 64;
const SERVER_DESCRIPTION_MAX_CHARS: usize = 512;
const TRANSPORT_NAME_MAX_CHARS: usize = 128;

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
│  MCP Framework for Rust  │
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
    /// Whether to show the capabilities table/counts.
    show_capabilities: bool,
    /// Whether to render the single-line minimal form.
    minimal: bool,
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
            show_capabilities: true,
            minimal: false,
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

    /// Set whether the banner includes registered capability counts.
    #[must_use]
    pub fn show_capabilities(mut self, show: bool) -> Self {
        self.show_capabilities = show;
        self
    }

    /// Render a single-line startup banner.
    #[must_use]
    pub fn minimal(mut self) -> Self {
        self.minimal = true;
        self.show_logo = false;
        self.show_capabilities = false;
        self
    }

    /// Render the complete banner.
    pub fn render(&self, console: &FastMcpConsole) {
        if self.minimal {
            self.render_minimal(console);
            return;
        }
        if !console.is_rich() {
            self.render_plain(console);
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
        if self.show_capabilities {
            self.render_capabilities_table(console, theme);
            console.newline();
        }

        // 4. Ready status
        self.render_ready_status(console, theme);

        // 5. Divider
        console.rule(None);
    }

    fn render_minimal(&self, console: &FastMcpConsole) {
        if console.is_rich() {
            let server_name =
                bounded_redacted_rich_fragment(&self.server_name, SERVER_NAME_MAX_CHARS);
            let version = bounded_redacted_rich_fragment(&self.version, SERVER_VERSION_MAX_CHARS);
            let transport =
                bounded_redacted_rich_fragment(&self.transport, TRANSPORT_NAME_MAX_CHARS);
            let theme = console.theme();
            console.print(&format!(
                "[{}]FastMCP[/] {} [{}]v{}[/] [{}]{}[/] [{}]ready[/]",
                color_hex(&theme.primary),
                server_name,
                color_hex(&theme.text_muted),
                version,
                color_hex(&theme.accent),
                transport,
                color_hex(&theme.success)
            ));
        } else {
            let server_name =
                bounded_redacted_terminal_text(&self.server_name, SERVER_NAME_MAX_CHARS);
            let version = bounded_redacted_terminal_text(&self.version, SERVER_VERSION_MAX_CHARS);
            let transport =
                bounded_redacted_terminal_text(&self.transport, TRANSPORT_NAME_MAX_CHARS);
            console.print_plain(&format!(
                "FastMCP {server_name} v{version} {transport} ready"
            ));
        }
    }

    fn render_info_panel(&self, console: &FastMcpConsole, theme: &FastMcpTheme) {
        let server_name = bounded_redacted_rich_fragment(&self.server_name, SERVER_NAME_MAX_CHARS);
        let version = bounded_redacted_rich_fragment(&self.version, SERVER_VERSION_MAX_CHARS);
        let title_line = format!(
            "[{}]{}[/] [{}]v{}[/]",
            color_hex(&theme.primary),
            server_name,
            color_hex(&theme.text_muted),
            version
        );

        let mut content = String::new();
        content.push_str(&title_line);

        if let Some(desc) = &self.description {
            let description = bounded_redacted_rich_fragment(desc, SERVER_DESCRIPTION_MAX_CHARS);
            content.push_str(&format!(
                "\n[{}]{}[/]",
                color_hex(&theme.text_dim),
                description
            ));
        }

        content.push_str(&format!(
            "\n[{}]Model Context Protocol framework for Rust[/]",
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
        let transport = bounded_redacted_rich_fragment(&self.transport, TRANSPORT_NAME_MAX_CHARS);
        console.print(&format!(
            "[{}]✓[/] Server ready on [{}]{}[/]",
            color_hex(&theme.success),
            color_hex(&theme.accent),
            transport
        ));
    }

    /// Plain text fallback for agent/CI contexts.
    fn render_plain(&self, console: &FastMcpConsole) {
        let server_name = bounded_redacted_terminal_text(&self.server_name, SERVER_NAME_MAX_CHARS);
        let version = bounded_redacted_terminal_text(&self.version, SERVER_VERSION_MAX_CHARS);
        let transport = bounded_redacted_terminal_text(&self.transport, TRANSPORT_NAME_MAX_CHARS);
        console.print_plain(&format!("FastMCP Server: {server_name} v{version}"));
        if let Some(desc) = &self.description {
            let description = bounded_redacted_terminal_text(desc, SERVER_DESCRIPTION_MAX_CHARS);
            console.print_plain(&format!("  {description}"));
        }
        if self.show_capabilities {
            console.print_plain(&format!("  Tools: {}", self.tools_count));
            console.print_plain(&format!("  Resources: {}", self.resources_count));
            console.print_plain(&format!("  Prompts: {}", self.prompts_count));
        }
        console.print_plain(&format!("  Transport: {transport}"));
        console.print_plain("Server ready.");
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
    let mut result = Vec::new();

    for (i, line) in lines.iter().enumerate() {
        let t = if line_count > 1 {
            i as f64 / (line_count - 1) as f64
        } else {
            0.0
        };

        let color = interpolate_colors(start, end, t);
        result.push(format!("[{}]{}[/]", color_hex(&color), line));
    }

    result.join("\n")
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::TestConsole;

    #[test]
    fn choose_logo_respects_width_thresholds() {
        assert_eq!(choose_logo(80), LOGO_FULL);
        assert_eq!(choose_logo(50), LOGO_FULL);
        assert_eq!(choose_logo(49), LOGO_COMPACT);
        assert_eq!(choose_logo(30), LOGO_COMPACT);
        assert_eq!(choose_logo(29), LOGO_MINIMAL);
    }

    #[test]
    fn startup_banner_renders_rich_output() {
        let tc = TestConsole::new_rich();
        let console = tc.console();

        StartupBanner::new("test-server", "1.2.3")
            .description("hello")
            .tools(2)
            .resources(1)
            .prompts(0)
            .transport("stdio")
            .render(console);

        assert!(tc.contains("test-server"));
        assert!(tc.contains("v1.2.3"));
        assert!(tc.contains("Capabilities"));
        assert!(tc.contains("Server ready"));
        assert!(tc.contains("stdio"));
    }

    // =========================================================================
    // Additional coverage tests (bd-2c61)
    // =========================================================================

    #[test]
    fn startup_banner_no_logo() {
        let tc = TestConsole::new_rich();
        let console = tc.console();

        StartupBanner::new("srv", "0.1.0").no_logo().render(console);

        // The information panel still renders, but none of the width-selected
        // logo variants may appear.
        assert!(tc.contains("srv"));
        assert!(!tc.contains("███"));
        assert!(!tc.contains("⚡ FastMCP Rust"));
        assert!(!tc.contains("FastMCP Rust"));
    }

    #[test]
    fn startup_banner_can_hide_capabilities() {
        let tc = TestConsole::new_rich();

        StartupBanner::new("srv", "0.1.0")
            .tools(3)
            .show_capabilities(false)
            .no_logo()
            .render(tc.console());

        assert!(tc.contains("srv"));
        assert!(!tc.contains("Capabilities"));
        assert!(!tc.contains("Tools"));
    }

    #[test]
    fn startup_banner_plain_can_hide_capabilities() {
        let tc = TestConsole::new();

        StartupBanner::new("srv", "0.1.0")
            .tools(3)
            .show_capabilities(false)
            .render(tc.console());

        assert!(tc.contains("srv"));
        assert!(tc.contains("Transport: stdio"));
        assert!(!tc.contains("Tools:"));
        assert!(!tc.contains("Resources:"));
        assert!(!tc.contains("Prompts:"));
    }

    #[test]
    fn minimal_startup_banner_is_one_line() {
        let tc = TestConsole::new_rich();

        StartupBanner::new("srv", "0.1.0")
            .tools(3)
            .transport("stdio")
            .minimal()
            .render(tc.console());

        let nonempty_lines = tc
            .output()
            .into_iter()
            .filter(|line| !line.trim().is_empty())
            .count();
        assert_eq!(nonempty_lines, 1);
        assert!(tc.contains("srv"));
        assert!(tc.contains("ready"));
        assert!(!tc.contains("Capabilities"));
    }

    #[test]
    fn minimal_startup_banner_plain_is_one_line_without_capabilities() {
        let tc = TestConsole::new();

        StartupBanner::new("srv", "0.1.0")
            .tools(3)
            .resources(2)
            .prompts(1)
            .transport("sse")
            .minimal()
            .render(tc.console());

        let nonempty_lines = tc
            .output()
            .into_iter()
            .filter(|line| !line.trim().is_empty())
            .count();
        assert_eq!(nonempty_lines, 1);
        assert!(tc.contains("FastMCP srv v0.1.0 sse ready"));
        assert!(!tc.contains("Tools:"));
        assert!(!tc.contains("Resources:"));
        assert!(!tc.contains("Prompts:"));
    }

    #[test]
    fn startup_banner_plain_shows_capability_counts() {
        let tc = TestConsole::new();

        StartupBanner::new("srv", "0.1.0")
            .tools(3)
            .resources(2)
            .prompts(1)
            .render(tc.console());

        assert!(tc.contains("Tools: 3"));
        assert!(tc.contains("Resources: 2"));
        assert!(tc.contains("Prompts: 1"));
    }

    #[test]
    fn startup_banner_default_transport_is_stdio() {
        let tc = TestConsole::new();
        let console = tc.console();

        StartupBanner::new("srv", "0.1.0").render(console);

        assert!(tc.contains("stdio"));
    }

    #[test]
    fn startup_banner_custom_transport() {
        let tc = TestConsole::new();
        let console = tc.console();

        StartupBanner::new("srv", "0.1.0")
            .transport("sse")
            .render(console);

        assert!(tc.contains("sse"));
    }

    #[test]
    fn startup_banner_without_description() {
        let tc = TestConsole::new();
        let console = tc.console();

        // Render without calling .description()
        StartupBanner::new("srv", "0.1.0").tools(1).render(console);

        assert!(tc.contains("srv"));
        assert!(tc.contains("v0.1.0"));
    }

    #[test]
    fn lerp_boundaries() {
        assert_eq!(lerp(0, 255, 0.0), 0);
        assert_eq!(lerp(0, 255, 1.0), 255);
        assert_eq!(lerp(0, 200, 0.5), 100);
        assert_eq!(lerp(100, 100, 0.5), 100);
    }

    #[test]
    fn interpolate_colors_start_and_end() {
        let start = Color::from_rgb(0, 0, 0);
        let end = Color::from_rgb(255, 255, 255);

        let at_start = interpolate_colors(&start, &end, 0.0);
        let at_end = interpolate_colors(&start, &end, 1.0);
        let at_mid = interpolate_colors(&start, &end, 0.5);

        assert_eq!(at_start.get_truecolor().red, 0);
        assert_eq!(at_end.get_truecolor().red, 255);
        // Midpoint should be roughly 128
        let mid_r = at_mid.get_truecolor().red;
        assert!((126..=129).contains(&mid_r), "mid_r was {mid_r}");
    }

    #[test]
    fn gradient_text_produces_markup_per_line() {
        let text = "line1\nline2\nline3";
        let start = Color::from_rgb(255, 0, 0);
        let end = Color::from_rgb(0, 0, 255);
        let result = gradient_text(text, &start, &end);

        // Each line should be wrapped in color markup
        let lines: Vec<&str> = result.lines().collect();
        assert_eq!(lines.len(), 3);
        for line in &lines {
            assert!(line.starts_with('['));
            assert!(line.ends_with("[/]"));
        }
    }

    #[test]
    fn gradient_text_single_line() {
        let text = "only one";
        let start = Color::from_rgb(100, 100, 100);
        let end = Color::from_rgb(200, 200, 200);
        let result = gradient_text(text, &start, &end);

        // Single line: t=0.0 → uses start color
        assert!(result.contains("only one"));
        assert_eq!(result.lines().count(), 1);
    }

    // =========================================================================
    // Additional coverage tests (bd-2q7c)
    // =========================================================================

    #[test]
    fn status_text_registered_and_none() {
        let theme = crate::theme::theme();
        let registered = status_text(true, theme);
        let plain_reg = registered.plain();
        assert!(plain_reg.contains("registered"));

        let none = status_text(false, theme);
        let plain_none = none.plain();
        assert!(plain_none.contains("none"));
    }

    #[test]
    fn color_hex_returns_hex_string() {
        let red = Color::from_rgb(255, 0, 0);
        let hex = color_hex(&red);
        assert!(hex.starts_with('#'));
        assert_eq!(hex.len(), 7);
    }

    #[test]
    fn capabilities_table_shows_registered_and_none() {
        let tc = TestConsole::new_rich();
        StartupBanner::new("srv", "0.1.0")
            .tools(3)
            .resources(0)
            .prompts(0)
            .no_logo()
            .render(tc.console());

        assert!(tc.contains("3"));
        assert!(tc.contains("registered"));
        assert!(tc.contains("none"));
    }

    #[test]
    fn logo_constants_content() {
        // LOGO_FULL uses box-drawing characters for "FAST MCP"
        assert!(LOGO_FULL.contains("███"));
        assert!(LOGO_COMPACT.contains("FastMCP"));
        assert!(LOGO_MINIMAL.contains("FastMCP"));
    }

    #[test]
    fn gradient_text_empty_produces_empty() {
        let start = Color::from_rgb(0, 0, 0);
        let end = Color::from_rgb(255, 255, 255);
        let result = gradient_text("", &start, &end);
        // Empty string → single line with start color markup
        assert!(result.is_empty() || result.contains('#'));
    }

    #[test]
    fn banner_new_defaults() {
        let b = StartupBanner::new("srv", "1.0.0");
        assert_eq!(b.server_name, "srv");
        assert_eq!(b.version, "1.0.0");
        assert!(b.description.is_none());
        assert_eq!(b.tools_count, 0);
        assert_eq!(b.resources_count, 0);
        assert_eq!(b.prompts_count, 0);
        assert_eq!(b.transport, "stdio");
        assert!(b.show_logo);
    }

    #[test]
    fn render_logo_does_not_panic() {
        let tc = TestConsole::new_rich();
        let theme = tc.console().theme();
        render_logo(tc.console(), theme);
        // Just verify it produced some output
        assert_ne!(tc.output_string(), "");
    }

    #[test]
    fn hostile_banner_metadata_is_bounded_redacted_and_terminal_safe() {
        let banner = StartupBanner::new(
            "server[prod] [bold]literal[/]\n\u{001b}\u{202e} token=name-canary",
            format!("1.0 password=version-canary {}", "v".repeat(1_000)),
        )
        .description(format!(
            "[red]description[/]\r Authorization: Bearer description-canary {}",
            "d".repeat(4_000)
        ))
        .transport("stdio[peer]\n api_key=transport-canary")
        .no_logo();

        let plain = TestConsole::new();
        banner.render_plain(plain.console());
        let rich = TestConsole::new_rich();
        banner.render(rich.console());

        for output in [plain.output_string(), rich.output_string()] {
            assert!(
                output.contains("server[prod]"),
                "brackets were corrupted: {output}"
            );
            assert!(
                output.contains("[bold]literal[/]"),
                "markup was executed: {output}"
            );
            assert!(output.contains("\\n"));
            assert!(output.contains("\\u{1b}"));
            assert!(output.contains("\\u{202e}"));
            for canary in [
                "name-canary",
                "version-canary",
                "description-canary",
                "transport-canary",
            ] {
                assert!(!output.contains(canary), "leaked {canary}: {output}");
            }
            assert!(output.chars().count() < 1_500, "unbounded output: {output}");
        }
    }
}
