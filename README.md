<p align="center">
  <img src="fastmcp_rust_illustration.webp" alt="FastMCP Rust - High-performance MCP framework" width="800">
</p>

<h1 align="center">FastMCP Rust</h1>

<p align="center">
  <strong>High-performance Model Context Protocol (MCP) framework for Rust</strong>
</p>

<p align="center">
  <em>A Rust port of <a href="https://github.com/jlowin/fastmcp">jlowin/fastmcp</a> (Python), extended with <a href="https://github.com/Dicklesworthstone/asupersync">asupersync</a> for structured concurrency and cancel-correct async.</em>
</p>

<p align="center">
  <a href="https://github.com/Dicklesworthstone/fastmcp_rust/actions/workflows/ci.yml"><img src="https://github.com/Dicklesworthstone/fastmcp_rust/actions/workflows/ci.yml/badge.svg" alt="CI"></a>
  <a href="LICENSE-MIT"><img src="https://img.shields.io/badge/license-MIT-blue.svg" alt="License"></a>
  <img src="https://img.shields.io/badge/rust-1.85%2B_(nightly)-orange.svg" alt="Rust Version">
  <img src="https://img.shields.io/badge/edition-2024-purple.svg" alt="Rust Edition">
</p>

---

```bash
# Add to your project
cargo add fastmcp --git https://github.com/Dicklesworthstone/fastmcp_rust
```

---

## TL;DR

### The Problem

Building MCP servers in Rust is painful:
- No first-class async support with proper cancellation
- Manual JSON-RPC boilerplate for every tool
- No structured concurrency—orphan tasks and resource leaks
- Request timeouts are afterthoughts, not guarantees

### The Solution

**FastMCP Rust** is a batteries-included MCP framework with cancel-correct async, attribute macros, and structured concurrency baked in:

```rust
use fastmcp::prelude::*;

#[tool]
async fn greet(ctx: &McpContext, name: String) -> String {
    ctx.checkpoint()?;  // Cancellation point
    format!("Hello, {name}!")
}

fn main() {
    Server::new("my-server", "1.0.0")
        .tool(greet)
        .run_stdio();
}
```

### Why FastMCP Rust?

| Feature | FastMCP Rust | Manual Implementation |
|---------|--------------|----------------------|
| **Async handlers** | `#[tool] async fn` | Manual Future boxing |
| **Cancellation** | `ctx.checkpoint()` | Hope for the best |
| **Timeouts** | Budget-based, automatic | Roll your own |
| **Structured concurrency** | Region-scoped tasks | Orphan task leaks |
| **Error handling** | 4-valued Outcome | 2-valued Result |
| **Boilerplate** | Zero (macros) | 100+ lines per tool |

---

## AGENTS.md

This project includes an [`AGENTS.md`](AGENTS.md) file with guidelines for AI coding agents. Key points:

- **Porting methodology:** Extract spec from legacy → implement from spec → never translate line-by-line
- **Runtime:** Uses [asupersync](https://github.com/Dicklesworthstone/asupersync) for cancel-correct async (not tokio directly)
- **Unsafe code:** Forbidden (`#![forbid(unsafe_code)]`)
- **Toolchain:** Rust 2024 edition, nightly required

---

## Quick Example

```rust
use fastmcp::prelude::*;

// Define a tool with automatic JSON schema generation
#[tool(description = "Calculate the sum of two numbers")]
async fn add(ctx: &McpContext, a: i64, b: i64) -> i64 {
    ctx.checkpoint()?;  // Check for client disconnect
    a + b
}

// Define a resource
#[resource(uri = "file://config.json", description = "Application config")]
async fn read_config(ctx: &McpContext) -> String {
    ctx.checkpoint()?;
    std::fs::read_to_string("config.json").unwrap_or_default()
}

// Define a prompt template
#[prompt(description = "Generate a greeting message")]
async fn greeting_prompt(ctx: &McpContext, name: String) -> Vec<PromptMessage> {
    ctx.checkpoint()?;
    vec![PromptMessage::user(format!("Please greet {name} warmly."))]
}

fn main() {
    Server::new("example-server", "1.0.0")
        .tool(add)
        .resource(read_config)
        .prompt(greeting_prompt)
        .request_timeout(30)  // 30-second budget per request
        .run_stdio();
}
```

Run it:

```bash
cargo run --example server
```

---

## Design Philosophy

### 1. Cancel-Correctness Over Convenience

Every async operation must be cancellable. Silent drops cause data loss. FastMCP uses checkpoints:

```rust
#[tool]
async fn process_items(ctx: &McpContext, items: Vec<Item>) -> Vec<Result> {
    let mut results = vec![];
    for item in items {
        ctx.checkpoint()?;  // Allow graceful cancellation between items
        results.push(process(item).await);
    }
    results
}
```

### 2. Budgets, Not Timeouts

Timeouts are "we gave up." Budgets are "you have X resources." The Budget type tracks deadline, poll quota, and cost quota as a product semiring:

```rust
// Server enforces 30-second budget per request
Server::new("server", "1.0.0")
    .request_timeout(30)
    .tool(my_tool)
    .run_stdio();

// Handler can check remaining budget
#[tool]
async fn my_tool(ctx: &McpContext) -> String {
    if ctx.budget().is_exhausted() {
        return "Budget exhausted".to_string();
    }
    // ... work ...
}
```

### 3. Four-Valued Outcomes

`Result<T, E>` conflates "operation failed" with "operation was cancelled" and "operation panicked." FastMCP uses `Outcome<T, E>`:

```rust
enum Outcome<T, E> {
    Ok(T),           // Success
    Err(E),          // Expected failure
    Cancelled(Why),  // External interruption
    Panicked(Msg),   // Internal failure
}
```

### 4. Capability Security

No ambient authority. All effects flow through explicit `McpContext`:

```rust
// BAD: Global state access
async fn bad_tool() {
    let db = GLOBAL_DB.lock().await;  // Hidden dependency
}

// GOOD: Explicit capability
async fn good_tool(ctx: &McpContext, db: &DbHandle) {
    db.query(ctx.cx(), "SELECT ...").await;  // Explicit
}
```

### 5. Structured Concurrency

All spawned tasks belong to regions. When a region closes, all children complete or drain. No orphan tasks:

```rust
#[tool]
async fn parallel_fetch(ctx: &McpContext, urls: Vec<String>) -> Vec<String> {
    // All spawned tasks are scoped to this request's region
    let handles: Vec<_> = urls.iter()
        .map(|url| ctx.spawn(fetch(url.clone())))
        .collect();

    // Region waits for all children before returning
    join_all(handles).await
}
```

---

## Comparison vs Alternatives

| Feature | FastMCP Rust | rmcp | jsonrpc-core |
|---------|-------------|------|--------------|
| **MCP-native** | Yes | Yes | No (generic) |
| **Async handlers** | Native | Native | Native |
| **Cancellation** | Checkpoints + masks | Manual | None |
| **Timeouts** | Budget-based | Timer-based | Manual |
| **Macros** | `#[tool]`, `#[resource]`, `#[prompt]` | Manual impl | Manual impl |
| **Runtime** | asupersync (cancel-correct) | tokio | tokio |
| **Outcome type** | 4-valued | 2-valued | 2-valued |
| **Structured concurrency** | Region-scoped | Manual | Manual |
| **Unsafe code** | Forbidden | Allowed | Allowed |

---

## Installation

### As a Git Dependency

```toml
[dependencies]
fastmcp = { git = "https://github.com/Dicklesworthstone/fastmcp_rust" }
```

### From Source

```bash
git clone https://github.com/Dicklesworthstone/fastmcp_rust.git
cd fastmcp_rust
cargo build --release
```

**Requirements:**
- Rust 1.85+ (nightly) for Edition 2024 features
- [asupersync](https://github.com/Dicklesworthstone/asupersync) as a sibling directory (or adjust path in `Cargo.toml`)

---

## Quick Start

### 1. Create a New Project

```bash
cargo new my-mcp-server
cd my-mcp-server
```

### 2. Add FastMCP

```toml
# Cargo.toml
[dependencies]
fastmcp = { git = "https://github.com/Dicklesworthstone/fastmcp_rust" }
```

### 3. Write Your Server

```rust
// src/main.rs
use fastmcp::prelude::*;

#[tool(description = "Echo the input message")]
async fn echo(ctx: &McpContext, message: String) -> String {
    ctx.checkpoint()?;
    message
}

fn main() {
    Server::new("echo-server", "1.0.0")
        .tool(echo)
        .instructions("A simple echo server for testing")
        .run_stdio();
}
```

### 4. Run

```bash
cargo run
```

### 5. Test with MCP Inspector

```bash
npx @anthropic-ai/mcp-inspector cargo run
```

---

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                        MCP Client                               │
└─────────────────────────────────────────────────────────────────┘
                              │
                              │ JSON-RPC over stdio
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│                      StdioTransport                             │
│  ┌─────────────┐    ┌─────────────┐    ┌─────────────┐         │
│  │   Codec     │───▶│   recv()    │───▶│   send()    │         │
│  │  (NDJSON)   │    │             │    │             │         │
│  └─────────────┘    └─────────────┘    └─────────────┘         │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│                         Server                                  │
│  ┌─────────────┐    ┌─────────────┐    ┌─────────────┐         │
│  │   Session   │    │   Router    │    │   Budget    │         │
│  │  (state)    │    │ (dispatch)  │    │ (timeout)   │         │
│  └─────────────┘    └─────────────┘    └─────────────┘         │
│                              │                                  │
│                              ▼                                  │
│  ┌─────────────────────────────────────────────────────────────┐│
│  │                     McpContext                              ││
│  │  ┌─────┐  ┌──────────┐  ┌────────┐  ┌──────┐              ││
│  │  │ Cx  │  │checkpoint│  │ budget │  │masked│              ││
│  │  └─────┘  └──────────┘  └────────┘  └──────┘              ││
│  └─────────────────────────────────────────────────────────────┘│
│                              │                                  │
│                              ▼                                  │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐         │
│  │ ToolHandler  │  │ResourceHandler│ │PromptHandler │         │
│  │  call_async  │  │  read_async  │  │  get_async   │         │
│  └──────────────┘  └──────────────┘  └──────────────┘         │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│                       asupersync                                │
│  ┌─────────┐  ┌─────────┐  ┌─────────┐  ┌─────────┐           │
│  │ Runtime │  │  Scope  │  │ Budget  │  │ Outcome │           │
│  └─────────┘  └─────────┘  └─────────┘  └─────────┘           │
└─────────────────────────────────────────────────────────────────┘
```

---

## Crate Structure

FastMCP is organized as a workspace with focused crates:

```
fastmcp_rust/
├── crates/
│   ├── fastmcp/           # Facade crate (re-exports everything)
│   ├── fastmcp-core/      # McpContext, errors, runtime helpers
│   ├── fastmcp-protocol/  # MCP types, JSON-RPC messages
│   ├── fastmcp-transport/ # Stdio transport (SSE/WS future)
│   ├── fastmcp-server/    # Server builder, router, handlers
│   ├── fastmcp-client/    # Client implementation
│   └── fastmcp-macros/    # #[tool], #[resource], #[prompt] macros
```

| Crate | Purpose |
|-------|---------|
| `fastmcp` | Convenience re-exports for simple `use fastmcp::prelude::*` |
| `fastmcp-core` | `McpContext` wrapper, error types, `block_on` helper |
| `fastmcp-protocol` | MCP message types, capabilities, JSON-RPC framing |
| `fastmcp-transport` | Transport trait, stdio implementation |
| `fastmcp-server` | `Server`, `ServerBuilder`, routing, handler traits |
| `fastmcp-client` | `Client` for calling MCP servers |
| `fastmcp-macros` | Procedural macros for handler generation |

---

## Handler Traits

### ToolHandler

```rust
pub trait ToolHandler: Send + Sync {
    fn definition(&self) -> Tool;
    fn call(&self, ctx: &McpContext, arguments: Value) -> McpResult<Vec<Content>>;

    // Override for true async (default delegates to call())
    fn call_async<'a>(&'a self, ctx: &'a McpContext, arguments: Value)
        -> BoxFuture<'a, McpResult<Vec<Content>>>;
}
```

### ResourceHandler

```rust
pub trait ResourceHandler: Send + Sync {
    fn definition(&self) -> Resource;
    fn read(&self, ctx: &McpContext) -> McpResult<Vec<ResourceContent>>;

    // Override for true async
    fn read_async<'a>(&'a self, ctx: &'a McpContext)
        -> BoxFuture<'a, McpResult<Vec<ResourceContent>>>;
}
```

### PromptHandler

```rust
pub trait PromptHandler: Send + Sync {
    fn definition(&self) -> Prompt;
    fn get(&self, ctx: &McpContext, arguments: HashMap<String, String>)
        -> McpResult<Vec<PromptMessage>>;

    // Override for true async
    fn get_async<'a>(&'a self, ctx: &'a McpContext, arguments: HashMap<String, String>)
        -> BoxFuture<'a, McpResult<Vec<PromptMessage>>>;
}
```

---

## Troubleshooting

| Problem | Cause | Fix |
|---------|-------|-----|
| `McpError::MethodNotFound("tool: my_tool")` | Tool not registered | Add `.tool(my_tool)` to server builder |
| Request cancelled mid-operation | Client disconnect or timeout | Use `ctx.masked()` for critical sections |
| Budget exhausted errors | Timeout too short | Increase `.request_timeout(120)` |
| `#[tool]` macro compilation error | Missing trait bounds | Ensure handler returns `McpResult<T>` or `Into<Vec<Content>>` |
| `TransportError::Io` on startup | stdin unavailable | Ensure nothing else reads stdin |

### Critical Section Example

```rust
#[tool]
async fn critical_write(ctx: &McpContext, data: String) -> String {
    // This section won't be interrupted
    ctx.masked(|| {
        fs::write("important.txt", &data).unwrap();
    });
    "Written".to_string()
}
```

---

## Limitations

| Limitation | Details |
|------------|---------|
| **Nightly Required** | Uses Rust 2024 edition features |
| **Stdio Only** | SSE and WebSocket transports planned but not implemented |
| **No Built-in TLS** | Transport encryption must be handled externally |
| **Single-threaded Loop** | Main server loop is sequential (parallel handlers planned) |
| **Sibling Dependency** | Requires asupersync at `../asupersync` |
| **Early Development** | API may change before 1.0 |

---

## FAQ

**Q: Why not use tokio directly?**

A: Tokio doesn't provide cancel-correctness out of the box. Dropping a Future silently discards work. asupersync provides checkpoints, masks, and 4-valued outcomes that make cancellation explicit and safe.

**Q: Can I use this with Claude Desktop?**

A: Yes! FastMCP servers speak standard MCP protocol over stdio. Configure Claude Desktop to spawn your server binary.

**Q: How do I add authentication?**

A: MCP doesn't define authentication at the protocol level. For Claude Desktop, the process is already trusted. For network transports, wrap the connection with TLS and implement auth at the transport layer.

**Q: What's the performance overhead of checkpoints?**

A: Checkpoints are a simple flag check (atomic load). The overhead is negligible—typically < 1 nanosecond per call.

**Q: Can I use other async runtimes?**

A: FastMCP is designed around asupersync's structured concurrency model. While you could theoretically swap runtimes, you'd lose cancel-correctness guarantees.

**Q: How do I test my handlers?**

A: Use `McpContext::for_testing()` to create a test context:
```rust
#[test]
fn test_my_tool() {
    let ctx = McpContext::for_testing();
    let result = my_tool(&ctx, "input".to_string());
    assert!(result.is_ok());
}
```

---

## About Contributions

Please don't take this the wrong way, but I do not accept outside contributions for any of my projects. I simply don't have the mental bandwidth to review anything, and it's my name on the thing, so I'm responsible for any problems it causes; thus, the risk-reward is highly asymmetric from my perspective. I'd also have to worry about other "stakeholders," which seems unwise for tools I mostly make for myself for free. Feel free to submit issues, and even PRs if you want to illustrate a proposed fix, but know I won't merge them directly. Instead, I'll have Claude or Codex review submissions via `gh` and independently decide whether and how to address them. Bug reports in particular are welcome. Sorry if this offends, but I want to avoid wasted time and hurt feelings. I understand this isn't in sync with the prevailing open-source ethos that seeks community contributions, but it's the only way I can move at this velocity and keep my sanity.

---

## License

FastMCP Rust is licensed under the MIT License. See [LICENSE-MIT](LICENSE-MIT).

---

<p align="center">
  <sub>Built with <a href="https://github.com/Dicklesworthstone/asupersync">asupersync</a> for cancel-correct async</sub>
</p>
