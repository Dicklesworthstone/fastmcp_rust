# Rich Rust Integration Plan for FastMCP Rust

> Comprehensive plan to integrate rich_rust for beautiful terminal output while preserving agent compatibility.

---

## Executive Summary

This plan describes how to deeply integrate `rich_rust` into FastMCP Rust to provide stunning, professional terminal output for human observers while maintaining perfect compatibility with AI coding agents (the primary users). The key insight is that **MCP protocol messages flow over stdout** and must remain pristine JSON-RPC, while **diagnostic/status output can flow over stderr** with full rich styling.

---

## Critical Constraint: Agent Compatibility

### The Problem

FastMCP servers communicate via JSON-RPC over stdio. AI agents like Claude Code, Codex, and Cursor:
1. **Parse stdout as NDJSON** - Any non-JSON text corrupts the protocol
2. **May not understand ANSI codes** - Escape sequences could confuse parsing
3. **Need deterministic output** - Progress spinners and animations interfere with testing

### The Solution: Dual-Stream Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│                        FastMCP Server                                │
├─────────────────────────────────────────────────────────────────────┤
│                                                                      │
│  stdout (JSON-RPC)              stderr (Rich Diagnostics)           │
│  ════════════════               ═══════════════════════════          │
│  • Pure NDJSON only             • All human-readable output          │
│  • Never styled                 • Full rich_rust styling             │
│  • Protocol messages            • Startup banners, progress          │
│  • Tool results                 • Logging, warnings, errors          │
│                                 • Status updates, metrics            │
│                                                                      │
│  ┌─────────────────┐            ┌────────────────────────────────┐  │
│  │ {"jsonrpc":"2.0" │           │ ╭──────────────────────────────╮ │  │
│  │  "method":"..."} │           │ │  FastMCP v1.0.0              │ │  │
│  │ {"jsonrpc":"2.0" │           │ │  ━━━━━━━━━━━━━━━━━━━━━━━━━━  │ │  │
│  │  "result":...}   │           │ │  ✓ Server initialized        │ │  │
│  └─────────────────┘            │ │  ✓ 3 tools registered        │ │  │
│         │                       │ │  ✓ Listening on stdio        │ │  │
│         │                       │ ╰──────────────────────────────╯ │  │
│         ▼                       └────────────────────────────────┘  │
│    To MCP Client                    To Human Observer (terminal)    │
│                                                                      │
└─────────────────────────────────────────────────────────────────────┘
```

---

## Detection Strategy: Agent vs Human

### Environment-Based Detection

```rust
/// Determine if we're running in an agent context
pub fn is_agent_context() -> bool {
    // MCP clients set these when spawning servers
    std::env::var("MCP_CLIENT").is_ok()
        || std::env::var("CLAUDE_CODE").is_ok()
        || std::env::var("CODEX_CLI").is_ok()
        || std::env::var("CURSOR_SESSION").is_ok()
        // Generic agent indicators
        || std::env::var("CI").is_ok()
        || std::env::var("AGENT_MODE").is_ok()
        // Explicit rich disable
        || std::env::var("FASTMCP_PLAIN").is_ok()
        || std::env::var("NO_COLOR").is_ok()
}

/// Determine if rich output should be enabled
pub fn should_enable_rich() -> bool {
    // Explicit enable always wins
    if std::env::var("FASTMCP_RICH").is_ok() {
        return true;
    }

    // In agent context, disable rich by default
    if is_agent_context() {
        return false;
    }

    // Check if stderr is a terminal (human watching)
    terminal::is_stderr_terminal()
}
```

### Configuration Hierarchy

1. **`FASTMCP_RICH=1`** - Force rich output (human debugging agent runs)
2. **`FASTMCP_PLAIN=1`** - Force plain output
3. **`NO_COLOR`** - Respect standard (disable colors)
4. **`MCP_CLIENT` / agent env vars** - Disable rich (agent context)
5. **stderr is TTY** - Enable rich (human watching)
6. **stderr is pipe** - Disable rich (captured logs)

---

## Integration Architecture

### New Crate: `fastmcp-console`

Create a new crate in the workspace dedicated to rich console output:

```
crates/
├── fastmcp-console/         # NEW: Rich console integration
│   ├── Cargo.toml
│   └── src/
│       ├── lib.rs           # Module root, re-exports
│       ├── detection.rs     # Agent/human context detection
│       ├── theme.rs         # FastMCP color theme
│       ├── console.rs       # Configured Console wrapper
│       ├── banner.rs        # Startup banner rendering
│       ├── status.rs        # Status/progress output
│       ├── tables.rs        # Server info tables
│       ├── logging.rs       # Rich log formatting
│       └── diagnostics.rs   # Error/warning formatting
```

### Dependency Integration

```toml
# crates/fastmcp-console/Cargo.toml
[package]
name = "fastmcp-console"
version = "0.1.0"
edition = "2024"

[dependencies]
rich_rust = { path = "/dp/rich_rust" }  # Or git dependency
log = "0.4"

[features]
default = []
full = ["rich_rust/full"]  # Include syntax, markdown, json
```

---

## Phase 1: Core Infrastructure

### 1.1 FastMCP Theme System

Define a cohesive visual theme that matches FastMCP's identity:

```rust
// crates/fastmcp-console/src/theme.rs

use rich_rust::prelude::*;

/// FastMCP color palette
pub struct FastMcpTheme {
    // Primary colors
    pub primary: Color,        // Vibrant cyan (#00d4ff)
    pub secondary: Color,      // Soft purple (#a855f7)
    pub accent: Color,         // Electric green (#22c55e)

    // Semantic colors
    pub success: Color,        // Green (#22c55e)
    pub warning: Color,        // Amber (#f59e0b)
    pub error: Color,          // Red (#ef4444)
    pub info: Color,           // Blue (#3b82f6)

    // Neutral palette
    pub text: Color,           // Light gray (#e5e7eb)
    pub text_muted: Color,     // Medium gray (#9ca3af)
    pub text_dim: Color,       // Dark gray (#6b7280)
    pub border: Color,         // Border gray (#374151)
    pub background: Color,     // Dark background (#1f2937)

    // Styles
    pub header_style: Style,
    pub subheader_style: Style,
    pub label_style: Style,
    pub value_style: Style,
    pub key_style: Style,
    pub muted_style: Style,
    pub success_style: Style,
    pub warning_style: Style,
    pub error_style: Style,
    pub info_style: Style,
}

impl Default for FastMcpTheme {
    fn default() -> Self {
        Self {
            // Colors
            primary: Color::from_rgb(0, 212, 255),
            secondary: Color::from_rgb(168, 85, 247),
            accent: Color::from_rgb(34, 197, 94),
            success: Color::from_rgb(34, 197, 94),
            warning: Color::from_rgb(245, 158, 11),
            error: Color::from_rgb(239, 68, 68),
            info: Color::from_rgb(59, 130, 246),
            text: Color::from_rgb(229, 231, 235),
            text_muted: Color::from_rgb(156, 163, 175),
            text_dim: Color::from_rgb(107, 114, 128),
            border: Color::from_rgb(55, 65, 81),
            background: Color::from_rgb(31, 41, 55),

            // Styles
            header_style: Style::new()
                .bold()
                .color(Color::from_rgb(0, 212, 255)),
            subheader_style: Style::new()
                .color(Color::from_rgb(156, 163, 175)),
            label_style: Style::new()
                .color(Color::from_rgb(107, 114, 128)),
            value_style: Style::new()
                .color(Color::from_rgb(229, 231, 235)),
            key_style: Style::new()
                .bold()
                .color(Color::from_rgb(168, 85, 247)),
            muted_style: Style::new()
                .dim()
                .color(Color::from_rgb(107, 114, 128)),
            success_style: Style::new()
                .bold()
                .color(Color::from_rgb(34, 197, 94)),
            warning_style: Style::new()
                .bold()
                .color(Color::from_rgb(245, 158, 11)),
            error_style: Style::new()
                .bold()
                .color(Color::from_rgb(239, 68, 68)),
            info_style: Style::new()
                .color(Color::from_rgb(59, 130, 246)),
        }
    }
}

/// Global theme access
pub fn theme() -> &'static FastMcpTheme {
    static THEME: std::sync::OnceLock<FastMcpTheme> = std::sync::OnceLock::new();
    THEME.get_or_init(FastMcpTheme::default)
}
```

### 1.2 Console Wrapper

A wrapper around rich_rust's Console that handles agent detection:

```rust
// crates/fastmcp-console/src/console.rs

use rich_rust::prelude::*;
use std::io::{self, Write};

/// FastMCP console for rich output to stderr
pub struct FastMcpConsole {
    inner: Console,
    enabled: bool,
    theme: &'static FastMcpTheme,
}

impl FastMcpConsole {
    /// Create with automatic detection
    pub fn new() -> Self {
        let enabled = crate::detection::should_enable_rich();
        Self::with_enabled(enabled)
    }

    /// Create with explicit enable/disable
    pub fn with_enabled(enabled: bool) -> Self {
        let inner = if enabled {
            Console::builder()
                .file(Box::new(io::stderr()))
                .force_terminal(true)
                .markup(true)
                .emoji(true)
                .build()
        } else {
            Console::builder()
                .file(Box::new(io::stderr()))
                .color_system(None)  // Disable colors
                .markup(false)
                .emoji(false)
                .build()
        };

        Self {
            inner,
            enabled,
            theme: crate::theme::theme(),
        }
    }

    /// Check if rich output is enabled
    pub fn is_rich(&self) -> bool {
        self.enabled
    }

    /// Get the theme
    pub fn theme(&self) -> &FastMcpTheme {
        self.theme
    }

    /// Print styled text (auto-detects markup)
    pub fn print(&self, content: &str) {
        if self.enabled {
            self.inner.print(content);
        } else {
            // Strip markup for plain output
            eprintln!("{}", strip_markup(content));
        }
    }

    /// Print a renderable
    pub fn render<R: Renderable>(&self, renderable: &R) {
        if self.enabled {
            self.inner.print_renderable(renderable);
        } else {
            // Fall back to plain text representation
            self.print_plain_fallback(renderable);
        }
    }

    /// Print plain text (no markup processing)
    pub fn print_plain(&self, text: &str) {
        eprintln!("{}", text);
    }

    /// Print a horizontal rule
    pub fn rule(&self, title: Option<&str>) {
        if self.enabled {
            match title {
                Some(t) => self.inner.print_renderable(
                    &Rule::with_title(t).style(self.theme.border_style())
                ),
                None => self.inner.print_renderable(
                    &Rule::new().style(self.theme.border_style())
                ),
            }
        } else {
            match title {
                Some(t) => eprintln!("--- {} ---", t),
                None => eprintln!("---"),
            }
        }
    }

    /// Print a blank line
    pub fn newline(&self) {
        eprintln!();
    }

    // ... more helper methods
}

/// Global console accessor
pub fn console() -> &'static FastMcpConsole {
    static CONSOLE: std::sync::OnceLock<FastMcpConsole> = std::sync::OnceLock::new();
    CONSOLE.get_or_init(FastMcpConsole::new)
}
```

---

## Phase 2: Server Startup Experience

### 2.1 Startup Banner

Create a stunning startup banner when humans are watching:

```rust
// crates/fastmcp-console/src/banner.rs

use rich_rust::prelude::*;

/// ASCII art logo for FastMCP
const LOGO_ASCII: &str = r#"
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
"#;

/// Compact logo for narrow terminals
const LOGO_COMPACT: &str = r#"
╭──────────────────────────╮
│  ⚡ FastMCP Rust         │
│  High-Performance MCP    │
╰──────────────────────────╯
"#;

pub struct StartupBanner {
    server_name: String,
    version: String,
    tools_count: usize,
    resources_count: usize,
    prompts_count: usize,
    transport: String,
}

impl StartupBanner {
    pub fn new(server_name: &str, version: &str) -> Self {
        Self {
            server_name: server_name.to_string(),
            version: version.to_string(),
            tools_count: 0,
            resources_count: 0,
            prompts_count: 0,
            transport: "stdio".to_string(),
        }
    }

    pub fn tools(mut self, count: usize) -> Self {
        self.tools_count = count;
        self
    }

    pub fn resources(mut self, count: usize) -> Self {
        self.resources_count = count;
        self
    }

    pub fn prompts(mut self, count: usize) -> Self {
        self.prompts_count = count;
        self
    }

    pub fn transport(mut self, transport: &str) -> Self {
        self.transport = transport.to_string();
        self
    }

    /// Render the full startup banner
    pub fn render(&self, console: &FastMcpConsole) {
        if !console.is_rich() {
            // Plain text fallback
            self.render_plain();
            return;
        }

        let theme = console.theme();
        let width = console.width().unwrap_or(80);

        // Choose logo based on terminal width
        let logo = if width >= 50 { LOGO_ASCII } else { LOGO_COMPACT };

        // Render gradient logo
        console.print(&gradient_text(logo, &theme.primary, &theme.secondary));

        // Server info panel
        let info_panel = self.build_info_panel(theme);
        console.render(&info_panel);

        // Capabilities table
        let caps_table = self.build_capabilities_table(theme);
        console.render(&caps_table);

        // Status line
        console.print(&format!(
            "[{}]✓[/] Server ready on [{}]{}[/]",
            theme.success.hex(),
            theme.accent.hex(),
            self.transport
        ));

        console.rule(None);
    }

    fn build_info_panel(&self, theme: &FastMcpTheme) -> Panel {
        let content = format!(
            "[{}]{}[/] [{}]v{}[/]\n\
             [{}]High-performance Model Context Protocol framework[/]",
            theme.primary.hex(),
            self.server_name,
            theme.text_muted.hex(),
            self.version,
            theme.text_dim.hex()
        );

        Panel::from_text(&content)
            .border_style(theme.border_style())
            .rounded()
    }

    fn build_capabilities_table(&self, theme: &FastMcpTheme) -> Table {
        let mut table = Table::new()
            .box_style(&rich_rust::r#box::ROUNDED)
            .show_header(true)
            .header_style(theme.header_style.clone())
            .border_style(theme.border_style());

        table.add_column(Column::new("Capability").style(theme.label_style.clone()));
        table.add_column(Column::new("Count").justify(JustifyMethod::Right));
        table.add_column(Column::new("Status"));

        // Tools row
        table.add_row_cells([
            "Tools",
            &self.tools_count.to_string(),
            if self.tools_count > 0 { "✓ registered" } else { "○ none" },
        ]);

        // Resources row
        table.add_row_cells([
            "Resources",
            &self.resources_count.to_string(),
            if self.resources_count > 0 { "✓ registered" } else { "○ none" },
        ]);

        // Prompts row
        table.add_row_cells([
            "Prompts",
            &self.prompts_count.to_string(),
            if self.prompts_count > 0 { "✓ registered" } else { "○ none" },
        ]);

        table
    }

    fn render_plain(&self) {
        eprintln!("FastMCP Server: {} v{}", self.server_name, self.version);
        eprintln!("  Tools: {}", self.tools_count);
        eprintln!("  Resources: {}", self.resources_count);
        eprintln!("  Prompts: {}", self.prompts_count);
        eprintln!("  Transport: {}", self.transport);
        eprintln!("Server ready.");
    }
}

/// Create gradient text between two colors
fn gradient_text(text: &str, start: &Color, end: &Color) -> String {
    // Implementation: interpolate colors across lines
    // ...
}
```

### 2.2 Integration into Server

```rust
// In crates/fastmcp-server/src/lib.rs

impl Server {
    pub fn run_stdio(self) -> ! {
        // Show startup banner to humans
        fastmcp_console::banner::StartupBanner::new(&self.info.name, &self.info.version)
            .tools(self.router.tools_count())
            .resources(self.router.resources_count())
            .prompts(self.router.prompts_count())
            .transport("stdio")
            .render(&fastmcp_console::console());

        // Continue with normal operation...
        self.run_stdio_internal()
    }
}
```

---

## Phase 3: Runtime Status Display

### 3.1 Request/Response Logging

Show beautiful request logs for human observers:

```rust
// crates/fastmcp-console/src/status.rs

use rich_rust::prelude::*;
use std::time::{Duration, Instant};

/// Format for displaying request/response activity
pub struct RequestLog {
    method: String,
    id: Option<String>,
    start: Instant,
    status: RequestStatus,
}

pub enum RequestStatus {
    Pending,
    Success(Duration),
    Error(String, Duration),
    Cancelled(Duration),
}

impl RequestLog {
    pub fn new(method: &str, id: Option<&str>) -> Self {
        Self {
            method: method.to_string(),
            id: id.map(String::from),
            start: Instant::now(),
            status: RequestStatus::Pending,
        }
    }

    pub fn success(mut self) -> Self {
        self.status = RequestStatus::Success(self.start.elapsed());
        self
    }

    pub fn error(mut self, msg: &str) -> Self {
        self.status = RequestStatus::Error(msg.to_string(), self.start.elapsed());
        self
    }

    pub fn cancelled(mut self) -> Self {
        self.status = RequestStatus::Cancelled(self.start.elapsed());
        self
    }

    /// Render to console
    pub fn render(&self, console: &FastMcpConsole) {
        if !console.is_rich() {
            self.render_plain();
            return;
        }

        let theme = console.theme();
        let (icon, style, duration) = match &self.status {
            RequestStatus::Pending => ("◐", &theme.info_style, None),
            RequestStatus::Success(d) => ("✓", &theme.success_style, Some(d)),
            RequestStatus::Error(_, d) => ("✗", &theme.error_style, Some(d)),
            RequestStatus::Cancelled(d) => ("⊘", &theme.warning_style, Some(d)),
        };

        let id_str = self.id.as_ref()
            .map(|id| format!(" [{}]#{}[/]", theme.text_dim.hex(), id))
            .unwrap_or_default();

        let duration_str = duration
            .map(|d| format!(" [{}]{}[/]", theme.text_muted.hex(), format_duration(*d)))
            .unwrap_or_default();

        console.print(&format!(
            "[{}]{}[/] [{}]{}[/]{}{}",
            style.color.as_ref().map(|c| c.hex()).unwrap_or_default(),
            icon,
            theme.key_style.color.as_ref().map(|c| c.hex()).unwrap_or_default(),
            self.method,
            id_str,
            duration_str
        ));

        if let RequestStatus::Error(msg, _) = &self.status {
            console.print(&format!(
                "  [{}]└─ {}[/]",
                theme.error.hex(),
                msg
            ));
        }
    }

    fn render_plain(&self) {
        let (icon, duration) = match &self.status {
            RequestStatus::Pending => ("...", None),
            RequestStatus::Success(d) => ("OK", Some(d)),
            RequestStatus::Error(_, d) => ("ERR", Some(d)),
            RequestStatus::Cancelled(d) => ("CANCEL", Some(d)),
        };

        let duration_str = duration
            .map(|d| format!(" ({})", format_duration(*d)))
            .unwrap_or_default();

        let id_str = self.id.as_ref()
            .map(|id| format!(" #{}", id))
            .unwrap_or_default();

        eprintln!("[{}] {}{}{}", icon, self.method, id_str, duration_str);

        if let RequestStatus::Error(msg, _) = &self.status {
            eprintln!("  Error: {}", msg);
        }
    }
}

fn format_duration(d: Duration) -> String {
    if d.as_millis() < 1000 {
        format!("{}ms", d.as_millis())
    } else if d.as_secs() < 60 {
        format!("{:.2}s", d.as_secs_f64())
    } else {
        format!("{}m {}s", d.as_secs() / 60, d.as_secs() % 60)
    }
}
```

### 3.2 Progress Indicators

For long-running operations:

```rust
// crates/fastmcp-console/src/progress.rs

use rich_rust::prelude::*;

/// Progress reporter for long-running tool calls
pub struct ToolProgress {
    tool_name: String,
    bar: Option<ProgressBar>,
    spinner: Option<Spinner>,
    console: &'static FastMcpConsole,
}

impl ToolProgress {
    pub fn new(tool_name: &str) -> Self {
        let console = crate::console();

        Self {
            tool_name: tool_name.to_string(),
            bar: None,
            spinner: if console.is_rich() {
                Some(Spinner::dots().style(console.theme().primary_style()))
            } else {
                None
            },
            console,
        }
    }

    /// Start indeterminate progress (spinner)
    pub fn start(&mut self, message: &str) {
        if let Some(spinner) = &mut self.spinner {
            self.console.print(&format!(
                "{} [{}]{}[/]: {}",
                spinner.next_frame(),
                self.console.theme().key.hex(),
                self.tool_name,
                message
            ));
        } else {
            eprintln!("[...] {}: {}", self.tool_name, message);
        }
    }

    /// Update with determinate progress
    pub fn update(&mut self, progress: f64, total: Option<f64>, message: Option<&str>) {
        if !self.console.is_rich() {
            if let Some(msg) = message {
                eprintln!("[{:.0}%] {}: {}", progress * 100.0, self.tool_name, msg);
            }
            return;
        }

        // Create or update progress bar
        let bar = self.bar.get_or_insert_with(|| {
            ProgressBar::default()
                .width(40)
                .bar_style(BarStyle::Block)
                .show_percentage(true)
        });

        bar.set_completed(progress);
        if let Some(msg) = message {
            bar.description(Text::new(msg));
        }

        self.console.render(bar);
    }

    /// Mark as complete
    pub fn finish(&self, message: &str) {
        if self.console.is_rich() {
            self.console.print(&format!(
                "[{}]✓[/] [{}]{}[/]: {}",
                self.console.theme().success.hex(),
                self.console.theme().key.hex(),
                self.tool_name,
                message
            ));
        } else {
            eprintln!("[OK] {}: {}", self.tool_name, message);
        }
    }
}
```

---

## Phase 4: Error Display

### 4.1 Rich Error Formatting

Beautiful error panels for debugging:

```rust
// crates/fastmcp-console/src/diagnostics.rs

use rich_rust::prelude::*;
use fastmcp_core::McpError;

/// Render an MCP error with full context
pub fn render_error(error: &McpError, console: &FastMcpConsole) {
    if !console.is_rich() {
        render_error_plain(error);
        return;
    }

    let theme = console.theme();

    // Error header
    let header = format!(
        "[{}]✗ Error[/] [{}][{}][/]",
        theme.error.hex(),
        theme.text_muted.hex(),
        error.code
    );

    // Error body with context
    let mut body_lines = vec![
        format!("[{}]{}[/]", theme.text.hex(), error.message),
    ];

    if let Some(data) = &error.data {
        body_lines.push(String::new());
        body_lines.push(format!("[{}]Context:[/]", theme.label.hex()));

        // Pretty-print JSON data if possible
        if let Ok(pretty) = serde_json::to_string_pretty(data) {
            for line in pretty.lines() {
                body_lines.push(format!("  [{}]{}[/]", theme.text_dim.hex(), line));
            }
        }
    }

    let panel = Panel::from_text(&body_lines.join("\n"))
        .title(&header)
        .border_style(Style::new().color(theme.error.clone()))
        .rounded();

    console.render(&panel);
}

fn render_error_plain(error: &McpError) {
    eprintln!("Error [{}]: {}", error.code, error.message);
    if let Some(data) = &error.data {
        if let Ok(pretty) = serde_json::to_string_pretty(data) {
            eprintln!("Context:");
            for line in pretty.lines() {
                eprintln!("  {}", line);
            }
        }
    }
}

/// Render a warning
pub fn render_warning(message: &str, console: &FastMcpConsole) {
    if console.is_rich() {
        console.print(&format!(
            "[{}]⚠[/] [{}]Warning:[/] {}",
            console.theme().warning.hex(),
            console.theme().warning.hex(),
            message
        ));
    } else {
        eprintln!("[WARN] {}", message);
    }
}

/// Render an info message
pub fn render_info(message: &str, console: &FastMcpConsole) {
    if console.is_rich() {
        console.print(&format!(
            "[{}]ℹ[/] {}",
            console.theme().info.hex(),
            message
        ));
    } else {
        eprintln!("[INFO] {}", message);
    }
}
```

### 4.2 Stack Trace Formatting

```rust
/// Format a panic/error with stack trace
pub fn render_panic(message: &str, backtrace: Option<&str>, console: &FastMcpConsole) {
    if !console.is_rich() {
        eprintln!("PANIC: {}", message);
        if let Some(bt) = backtrace {
            eprintln!("Backtrace:\n{}", bt);
        }
        return;
    }

    let theme = console.theme();

    // Main error panel
    let panel = Panel::from_text(message)
        .title("[bold red]PANIC[/]")
        .border_style(Style::new().color(theme.error.clone()))
        .rounded();

    console.render(&panel);

    // Backtrace if available
    if let Some(bt) = backtrace {
        console.print(&format!("\n[{}]Backtrace:[/]", theme.label.hex()));

        // Syntax-highlight the backtrace (if syntax feature enabled)
        #[cfg(feature = "syntax")]
        {
            let syntax = Syntax::new(bt, "rust")
                .line_numbers(true)
                .theme("base16-ocean.dark");
            console.render(&syntax);
        }

        #[cfg(not(feature = "syntax"))]
        {
            for line in bt.lines() {
                console.print(&format!("  [{}]{}[/]", theme.text_dim.hex(), line));
            }
        }
    }
}
```

---

## Phase 5: Logging Integration

### 5.1 Rich Log Formatter

Integrate with the `log` crate for beautiful log output:

```rust
// crates/fastmcp-console/src/logging.rs

use log::{Level, Log, Metadata, Record};
use rich_rust::prelude::*;

/// Rich-formatted log output to stderr
pub struct RichLogger {
    console: &'static FastMcpConsole,
    min_level: Level,
}

impl RichLogger {
    pub fn new(min_level: Level) -> Self {
        Self {
            console: crate::console(),
            min_level,
        }
    }

    pub fn init(min_level: Level) {
        let logger = Box::new(Self::new(min_level));
        log::set_boxed_logger(logger).ok();
        log::set_max_level(min_level.to_level_filter());
    }
}

impl Log for RichLogger {
    fn enabled(&self, metadata: &Metadata) -> bool {
        metadata.level() <= self.min_level
    }

    fn log(&self, record: &Record) {
        if !self.enabled(record.metadata()) {
            return;
        }

        let theme = self.console.theme();

        if self.console.is_rich() {
            let (icon, style) = match record.level() {
                Level::Error => ("✗", &theme.error_style),
                Level::Warn => ("⚠", &theme.warning_style),
                Level::Info => ("ℹ", &theme.info_style),
                Level::Debug => ("●", &theme.muted_style),
                Level::Trace => ("·", &theme.muted_style),
            };

            let target = if record.target().starts_with("fastmcp") {
                record.target().strip_prefix("fastmcp::").unwrap_or(record.target())
            } else {
                record.target()
            };

            self.console.print(&format!(
                "[{}]{}[/] [{}]{}[/] {}",
                style.color.as_ref().map(|c| c.hex()).unwrap_or_default(),
                icon,
                theme.text_dim.hex(),
                target,
                record.args()
            ));
        } else {
            let level_str = match record.level() {
                Level::Error => "ERROR",
                Level::Warn => "WARN",
                Level::Info => "INFO",
                Level::Debug => "DEBUG",
                Level::Trace => "TRACE",
            };

            eprintln!("[{}] {}: {}", level_str, record.target(), record.args());
        }
    }

    fn flush(&self) {}
}
```

### 5.2 Log Macros Integration

```rust
// In fastmcp-core, update logging macros

/// Log with rich formatting
#[macro_export]
macro_rules! log_info {
    ($($arg:tt)*) => {
        log::info!(target: "fastmcp", $($arg)*);
    };
}

#[macro_export]
macro_rules! log_error {
    ($($arg:tt)*) => {
        log::error!(target: "fastmcp", $($arg)*);
    };
}

// ... etc
```

---

## Phase 6: Handler-Specific Rich Output

### 6.1 Tool Call Visualization

```rust
// crates/fastmcp-console/src/handlers.rs

/// Visualize a tool being called
pub fn render_tool_call(
    tool_name: &str,
    arguments: &serde_json::Value,
    console: &FastMcpConsole,
) {
    if !console.is_rich() {
        eprintln!("Calling tool: {} with {:?}", tool_name, arguments);
        return;
    }

    let theme = console.theme();

    // Tool name header
    console.print(&format!(
        "[{}]▶[/] Calling [{}bold]{}[/]",
        theme.accent.hex(),
        theme.key.hex(),
        tool_name
    ));

    // Arguments as pretty JSON
    #[cfg(feature = "json")]
    {
        let json = Json::new(arguments.clone())
            .indent(2)
            .theme(JsonTheme {
                key: theme.key_style.clone(),
                string: Style::new().color(theme.accent.clone()),
                number: Style::new().color(theme.info.clone()),
                boolean: Style::new().color(theme.warning.clone()),
                null: theme.muted_style.clone(),
                bracket: theme.border_style(),
                punctuation: theme.muted_style.clone(),
            });
        console.render(&json);
    }

    #[cfg(not(feature = "json"))]
    {
        if let Ok(pretty) = serde_json::to_string_pretty(arguments) {
            for line in pretty.lines() {
                console.print(&format!("  [{}]{}[/]", theme.text_dim.hex(), line));
            }
        }
    }
}

/// Visualize tool result
pub fn render_tool_result(
    tool_name: &str,
    result: &[Content],
    duration: Duration,
    console: &FastMcpConsole,
) {
    if !console.is_rich() {
        eprintln!("Tool {} completed in {:?}", tool_name, duration);
        return;
    }

    let theme = console.theme();

    console.print(&format!(
        "[{}]✓[/] [{}bold]{}[/] completed in [{}]{}[/]",
        theme.success.hex(),
        theme.key.hex(),
        tool_name,
        theme.text_muted.hex(),
        format_duration(duration)
    ));

    // Show result summary
    for content in result {
        match content {
            Content::Text { text } => {
                let preview = if text.len() > 100 {
                    format!("{}...", &text[..100])
                } else {
                    text.clone()
                };
                console.print(&format!(
                    "  [{}]└─[/] [{}]{}[/]",
                    theme.border.hex(),
                    theme.text.hex(),
                    preview
                ));
            }
            Content::Image { mime_type, .. } => {
                console.print(&format!(
                    "  [{}]└─[/] [{}italic]<{} image>[/]",
                    theme.border.hex(),
                    theme.text_muted.hex(),
                    mime_type
                ));
            }
            Content::Resource { resource } => {
                console.print(&format!(
                    "  [{}]└─[/] [{}]Resource: {}[/]",
                    theme.border.hex(),
                    theme.info.hex(),
                    resource.uri
                ));
            }
        }
    }
}
```

### 6.2 Resource Read Visualization

```rust
/// Visualize resource being read
pub fn render_resource_read(
    uri: &str,
    console: &FastMcpConsole,
) {
    if console.is_rich() {
        console.print(&format!(
            "[{}]📄[/] Reading [{}underline]{}[/]",
            console.theme().info.hex(),
            console.theme().accent.hex(),
            uri
        ));
    } else {
        eprintln!("Reading resource: {}", uri);
    }
}
```

---

## Phase 7: Client-Side Rich Output

### 7.1 Client Initialization Display

```rust
// crates/fastmcp-client/src/display.rs

/// Show client connection status
pub fn render_client_connecting(command: &str, console: &FastMcpConsole) {
    if console.is_rich() {
        let mut spinner = Spinner::dots().style(console.theme().info_style.clone());
        console.print(&format!(
            "{} Connecting to [{}]{}[/]...",
            spinner.next_frame(),
            console.theme().accent.hex(),
            command
        ));
    } else {
        eprintln!("Connecting to {}...", command);
    }
}

/// Show successful connection
pub fn render_client_connected(
    server_name: &str,
    server_version: &str,
    capabilities: &ServerCapabilities,
    console: &FastMcpConsole,
) {
    if !console.is_rich() {
        eprintln!("Connected to {} v{}", server_name, server_version);
        return;
    }

    let theme = console.theme();

    console.print(&format!(
        "[{}]✓[/] Connected to [{}bold]{}[/] [{}]v{}[/]",
        theme.success.hex(),
        theme.primary.hex(),
        server_name,
        theme.text_muted.hex(),
        server_version
    ));

    // Show capabilities
    let mut caps = vec![];
    if capabilities.tools.is_some() {
        caps.push("tools");
    }
    if capabilities.resources.is_some() {
        caps.push("resources");
    }
    if capabilities.prompts.is_some() {
        caps.push("prompts");
    }

    if !caps.is_empty() {
        console.print(&format!(
            "  [{}]Capabilities:[/] {}",
            theme.label.hex(),
            caps.iter()
                .map(|c| format!("[{}]{}[/]", theme.accent.hex(), c))
                .collect::<Vec<_>>()
                .join(", ")
        ));
    }
}
```

---

## Phase 8: Server Info Display

### 8.1 Server Capabilities Table

```rust
// crates/fastmcp-console/src/tables.rs

/// Display registered tools in a table
pub fn render_tools_table(tools: &[Tool], console: &FastMcpConsole) {
    if tools.is_empty() {
        return;
    }

    if !console.is_rich() {
        eprintln!("Registered tools:");
        for tool in tools {
            eprintln!("  - {}: {}", tool.name, tool.description.as_deref().unwrap_or("-"));
        }
        return;
    }

    let theme = console.theme();

    let mut table = Table::new()
        .title("Registered Tools")
        .title_style(theme.header_style.clone())
        .box_style(&rich_rust::r#box::ROUNDED)
        .border_style(theme.border_style())
        .add_column(Column::new("Name").style(theme.key_style.clone()))
        .add_column(Column::new("Description"));

    for tool in tools {
        table.add_row_cells([
            &tool.name,
            tool.description.as_deref().unwrap_or("-"),
        ]);
    }

    console.render(&table);
}

/// Display registered resources in a table
pub fn render_resources_table(resources: &[Resource], console: &FastMcpConsole) {
    // Similar implementation...
}

/// Display registered prompts in a table
pub fn render_prompts_table(prompts: &[Prompt], console: &FastMcpConsole) {
    // Similar implementation...
}
```

---

## Phase 9: Testing Support

### 9.1 Captured Output for Tests

```rust
// crates/fastmcp-console/src/testing.rs

use std::sync::{Arc, Mutex};

/// Capture console output for testing
pub struct CapturedConsole {
    buffer: Arc<Mutex<Vec<String>>>,
    console: FastMcpConsole,
}

impl CapturedConsole {
    pub fn new() -> Self {
        let buffer = Arc::new(Mutex::new(Vec::new()));
        let buffer_clone = buffer.clone();

        // Create console that writes to buffer
        let console = FastMcpConsole::with_writer(
            Box::new(BufferWriter { buffer: buffer_clone })
        );

        Self { buffer, console }
    }

    /// Get captured output
    pub fn output(&self) -> Vec<String> {
        self.buffer.lock().unwrap().clone()
    }

    /// Get output as single string
    pub fn output_string(&self) -> String {
        self.output().join("\n")
    }

    /// Clear captured output
    pub fn clear(&self) {
        self.buffer.lock().unwrap().clear();
    }

    /// Get console reference
    pub fn console(&self) -> &FastMcpConsole {
        &self.console
    }
}

struct BufferWriter {
    buffer: Arc<Mutex<Vec<String>>>,
}

impl std::io::Write for BufferWriter {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        if let Ok(s) = std::str::from_utf8(buf) {
            self.buffer.lock().unwrap().push(s.to_string());
        }
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}
```

### 9.2 Test Utilities

```rust
/// Assert that output contains expected text (ignoring ANSI codes)
pub fn assert_output_contains(captured: &CapturedConsole, expected: &str) {
    let output = strip_ansi(&captured.output_string());
    assert!(
        output.contains(expected),
        "Expected output to contain '{}', but got:\n{}",
        expected,
        output
    );
}

/// Strip ANSI codes from text
pub fn strip_ansi(text: &str) -> String {
    // Regex to match ANSI escape codes
    let re = regex::Regex::new(r"\x1b\[[0-9;]*m").unwrap();
    re.replace_all(text, "").to_string()
}
```

---

## Phase 10: Configuration API

### 10.1 Server Builder Integration

```rust
// Update ServerBuilder to include rich options

impl ServerBuilder {
    /// Enable rich console output (default: auto-detect)
    pub fn rich_output(mut self, enabled: bool) -> Self {
        self.rich_enabled = Some(enabled);
        self
    }

    /// Set the rich theme
    pub fn theme(mut self, theme: FastMcpTheme) -> Self {
        self.theme = Some(theme);
        self
    }

    /// Disable startup banner
    pub fn no_banner(mut self) -> Self {
        self.show_banner = false;
        self
    }

    /// Set log level for rich output
    pub fn log_level(mut self, level: log::Level) -> Self {
        self.log_level = Some(level);
        self
    }
}
```

### 10.2 Environment Variable Reference

| Variable | Description | Values |
|----------|-------------|--------|
| `FASTMCP_RICH` | Force rich output | `1`, `true`, `yes` |
| `FASTMCP_PLAIN` | Force plain output | `1`, `true`, `yes` |
| `FASTMCP_NO_BANNER` | Disable startup banner | `1`, `true`, `yes` |
| `FASTMCP_LOG_LEVEL` | Set log verbosity | `error`, `warn`, `info`, `debug`, `trace` |
| `NO_COLOR` | Disable all colors (standard) | Any value |
| `FORCE_COLOR` | Force color level | `0`-`3` |
| `MCP_CLIENT` | Indicate agent context | Any value |

---

## Implementation Order

### Phase 1: Foundation (Week 1)
1. Create `fastmcp-console` crate
2. Implement detection module
3. Implement theme system
4. Implement console wrapper

### Phase 2: Server Startup (Week 1-2)
5. Implement startup banner
6. Integrate into Server::run_stdio()
7. Add environment variable support

### Phase 3: Logging (Week 2)
8. Implement RichLogger
9. Integrate with existing log macros
10. Test with verbose output

### Phase 4: Runtime Display (Week 2-3)
11. Implement request logging
12. Implement progress indicators
13. Integrate into server main loop

### Phase 5: Error Handling (Week 3)
14. Implement error panels
15. Implement warning display
16. Integrate throughout codebase

### Phase 6: Handler Display (Week 3-4)
17. Implement tool call visualization
18. Implement resource read display
19. Implement prompt display

### Phase 7: Client Integration (Week 4)
20. Implement client display functions
21. Integrate into Client

### Phase 8: Polish (Week 4-5)
22. Implement tables module
23. Add testing utilities
24. Documentation and examples

---

## Critical Implementation Notes

### DO:
- Always write rich output to **stderr** (never stdout)
- Respect `NO_COLOR` and agent environment variables
- Provide plain-text fallbacks for everything
- Test with both TTY and non-TTY stderr
- Use the theme system consistently

### DON'T:
- Never write anything to stdout except JSON-RPC
- Never use animations that could delay agent responses
- Never require rich_rust for basic functionality
- Never block on rendering (keep it fast)
- Never add emoji/unicode that could break in some terminals without fallback

### Testing Checklist:
- [ ] Run with `MCP_CLIENT=1` - should show plain output
- [ ] Run with `FASTMCP_RICH=1` - should show rich output regardless
- [ ] Run with `NO_COLOR=1` - should disable colors
- [ ] Pipe stdout to file - should be valid JSON-RPC
- [ ] Pipe stderr to file - should be human-readable
- [ ] Run in CI - should auto-disable rich

---

## Example: Complete Flow

```rust
// Example of how a request flows with rich output

// Server receives request
log_info!("Received request"); // → stderr (rich)

// Tool is called
render_tool_call("my_tool", &args, console()); // → stderr (rich)

// Tool progress (optional)
let mut progress = ToolProgress::new("my_tool");
progress.start("Processing..."); // → stderr (rich)
progress.update(0.5, None, Some("Halfway done")); // → stderr (rich)

// Tool completes
render_tool_result("my_tool", &result, duration, console()); // → stderr (rich)

// Response sent
transport.send_response(&response); // → stdout (pure JSON)
log_info!("Sent response"); // → stderr (rich)
```

---

## Conclusion

This integration plan provides a complete framework for adding beautiful terminal output to FastMCP Rust while maintaining perfect compatibility with AI coding agents. The dual-stream architecture (JSON-RPC on stdout, rich diagnostics on stderr) ensures that the protocol remains uncorrupted while humans get a premium visual experience.

The key innovations are:
1. **Automatic context detection** - Smart defaults that work for both agents and humans
2. **Theme system** - Consistent, professional visual identity
3. **Comprehensive fallbacks** - Plain text alternatives for every rich feature
4. **Non-intrusive integration** - Rich output is additive, not required
