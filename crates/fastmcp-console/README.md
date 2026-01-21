# fastmcp-console

Rich console output for FastMCP servers.

fastmcp-console renders human-friendly output to stderr and keeps stdout
reserved for JSON-RPC (NDJSON). This preserves protocol correctness for agents
while giving humans polished output.

## Quick Start

```rust
use fastmcp_console::banner::StartupBanner;
use fastmcp_console::console::FastMcpConsole;
use fastmcp_console::logging::RichLoggerBuilder;
use log::Level;

fn main() {
    // Optional: initialize rich logger (stderr only)
    let _ = RichLoggerBuilder::new()
        .level(Level::Info)
        .with_targets(true)
        .init();

    let console = FastMcpConsole::new();
    console.rule(Some("FastMCP Console"));

    let banner = StartupBanner::new("demo-server", "0.1.0")
        .tools(3)
        .resources(2)
        .prompts(1)
        .transport("stdio");
    banner.render(&console);

    console.print("Ready.");
}
```

## Key Concepts

- Dual-stream architecture: stdout is JSON-RPC only, stderr is human output.
- DisplayContext: automatic detection of agent vs human context.

## Detection and Environment Variables

Rich output is enabled when we are in a human context and not explicitly
suppressed. The most common toggles are:

- FASTMCP_RICH=1 forces rich output.
- FASTMCP_PLAIN=1 or NO_COLOR=1 forces plain output.
- Agent detection: MCP_CLIENT, CLAUDE_CODE, CODEX_CLI, CURSOR_SESSION,
  CI, or AGENT_MODE set.

ConsoleConfig::from_env() also supports:
- FASTMCP_FORCE_COLOR, FASTMCP_BANNER, FASTMCP_LOG,
  FASTMCP_LOG_TIMESTAMPS, FASTMCP_TRAFFIC, RUST_BACKTRACE

## API Overview

- console::FastMcpConsole: printing, renderables, rules, tables, panels
- banner::StartupBanner: startup banner
- tables::ToolTableRenderer / ResourceTableRenderer / PromptTableRenderer
- handlers::HandlerRegistryRenderer: combined capabilities view
- logging::RichLogger / RichLoggerBuilder / RichLayer (tracing)
- stats::ServerStats + StatsRenderer
- config::ConsoleConfig for customization
- detection::DisplayContext and helpers
- testing::TestConsole + SnapshotTest

## Examples

See `crates/fastmcp-console/examples`:
- basic.rs
- tables.rs
- custom_theme.rs
- agent_detection.rs

## Troubleshooting

- JSON-RPC output corrupted: ensure you never print to stdout. Use stderr only.
- No colors: set FASTMCP_RICH=1 or FASTMCP_FORCE_COLOR=1; clear NO_COLOR.
- Too much output: disable banner or traffic logging via ConsoleConfig or env vars.

## License

MIT. See LICENSE-MIT.
