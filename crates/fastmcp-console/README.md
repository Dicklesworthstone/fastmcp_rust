# fastmcp-console

Rich console output for FastMCP servers.

MCP 2026-07-28 support is under implementation and remains unverified. The
workspace's public protocol constant is still `2024-11-05`; console rendering
is not aggregate conformance or release evidence.

fastmcp-console renders human-friendly output to stderr and keeps stdout
reserved for JSON-RPC (NDJSON). This preserves protocol correctness for agents
while giving humans polished output.

## Role in FastMCP

fastmcp-console is the **human-facing output layer** of FastMCP. The server
and CLI use it to render banners, tables, and logs to stderr while keeping
stdout strictly reserved for JSON-RPC. This separation is critical for MCP
clients and agents that parse stdout as a protocol stream.

## Quick Start

```rust
use fastmcp_console::banner::StartupBanner;
use fastmcp_console::console::FastMcpConsole;
use fastmcp_console::logging::RichLoggerBuilder;

fn main() {
    // Optional: initialize rich logger (stderr only)
    let _ = RichLoggerBuilder::new()
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

## Feature Boundaries

The default feature set is protocol-free. It provides the generic console,
banner, diagnostics, logging, status, statistics, theme, configuration, and
test utilities without pulling `fastmcp-protocol` into the dependency graph.

Protocol-aware request traffic, client information, capability tables, and
handler rendering require one of the protocol features:

- `legacy-2024-11-05` for exact legacy rendering.
- `tasks` for Tasks rendering.
- `apps` for Apps rendering.

The remaining nonsecurity presentation features compose those protocol
features where needed: `proxy-legacy` implies `proxy` and
`legacy-2024-11-05`; `proxy-tasks` implies `proxy` and `tasks`; and
`redis-tasks` implies `tasks`.

## Detection and Environment Variables

Rich output is enabled when we are in a human context and not explicitly
suppressed. The most common toggles are:

- FASTMCP_RICH=1 forces rich output.
- FASTMCP_PLAIN=1 or NO_COLOR=1 forces plain output.
- Agent detection: MCP_CLIENT, CLAUDE_CODE, CODEX_CLI, CURSOR_SESSION,
  CI, or AGENT_MODE set.

ConsoleConfig::from_env() also supports:
- FASTMCP_FORCE_COLOR, FASTMCP_BANNER, FASTMCP_NO_BANNER, FASTMCP_LOG,
  FASTMCP_LOG_TIMESTAMPS, FASTMCP_LOG_TARGETS, FASTMCP_LOG_FILE_LINE,
  FASTMCP_TRAFFIC, RUST_BACKTRACE

## API Overview

- console::FastMcpConsole: printing, renderables, rules, tables, panels
- banner::StartupBanner: startup banner
- tables::ToolTableRenderer / ResourceTableRenderer / PromptTableRenderer
  (requires a protocol feature)
- handlers::HandlerRegistryRenderer: combined capabilities view (requires a
  protocol feature)
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

The workspace release-license representation is unresolved: Cargo metadata,
the root `LICENSE`, and the root `LICENSE-MIT` do not currently describe one
consistent set of terms. Do not infer authoritative release terms from this
crate page; publication remains blocked pending the explicit license decision
required by the implementation plan.
