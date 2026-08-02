<p align="center">
  <img src="fastmcp_rust_illustration.webp" alt="FastMCP Rust - cancel-aware MCP framework" width="800">
</p>

<h1 align="center">FastMCP Rust</h1>

<p align="center">
  <strong>Cancel-aware Model Context Protocol (MCP) framework for Rust</strong>
</p>

<p align="center">
  <em>A Rust port of <a href="https://github.com/jlowin/fastmcp">jlowin/fastmcp</a> (Python), extended with <a href="https://github.com/Dicklesworthstone/asupersync">asupersync</a> capability contexts and cooperative-cancellation primitives.</em>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/License-review%20required-yellow.svg" alt="License review required">
  <img src="https://img.shields.io/badge/rust-nightly--2026--07--11-orange.svg" alt="Rust Version">
  <img src="https://img.shields.io/badge/edition-2024-purple.svg" alt="Rust Edition">
  <img src="https://img.shields.io/badge/MCP%202026--07--28-under%20implementation-yellow.svg" alt="MCP status">
</p>

> **Protocol status (2026-08-01):** MCP 2026-07-28 support is under
> implementation and remains unverified. The current public
> `PROTOCOL_VERSION` is `2024-11-05`. Source presence, examples, and historical
> parity rows are not conformance or release evidence. Release publication
> remains quarantined; source edits alone do not prove historical workflow
> identities, queued runs, or credentials inert, so provider-side evidence is
> still required.

### Current qualification boundaries

- **Wire cancellation is only partially qualified:** the primary stdio path now
  keeps receiving while one bounded worker serializes dispatch, so it can route
  a cancellation while a handler is running. Custom/SSE/WebSocket entry points
  still use the legacy sequential loop, and independently owned request `Cx`
  lifetimes plus reliable `awaitCleanup` semantics remain unverified.
- **Bidirectional calls are not qualified:** the stdio receive pump can route
  sampling, elicitation, and roots responses while its dispatch worker is
  occupied. Custom/SSE/WebSocket paths still reject or lack that split routing,
  public HTTP is fail-closed, and end-to-end lifecycle/cancellation evidence is
  incomplete.
- **Response caching is conservatively partitioned:** eligible production
  requests are keyed by committed authentication facts plus opaque session
  identity and revision. Uncommitted authentication, local-only state views,
  allocation failure, or state mutation during a request cause cache admission
  to fail closed rather than sharing an entry.
- **Authentication admission is incomplete:** recognized credentials in JSON-RPC
  params are supported only as a legacy fallback and are stripped before
  extension middleware and handlers. The quarantined private HTTP helper now
  carries its native `Authorization` field separately through pre-dispatch
  admission, but the public turnkey HTTP path remains fail-closed and no
  complete transport-boundary admission/challenge integration is qualified.
- **Tasks are quarantined:** `tasks/list`, `tasks/get`, `tasks/submit`, and
  `tasks/cancel` are not advertised and return JSON-RPC `MethodNotFound`.
- **OAuth/OIDC are unpromoted source surfaces:** their public building blocks
  remain available for development, but production security/profile
  conformance is unverified and no production-support claim is made for them.

---

```bash
# Historical published package; it does not contain unverified in-tree work
cargo add fastmcp-rust

# Or use the git dependency for bleeding-edge changes
cargo add fastmcp-rust --git https://github.com/Dicklesworthstone/fastmcp_rust
```

---

## TL;DR

### The Problem

MCP server implementations need to solve several recurring problems:

- Handler schemas and JSON-RPC dispatch
- Cooperative cancellation and request budgets
- Ownership of concurrent child work
- Transport framing and session lifecycle

### The Solution

**FastMCP Rust** is an MCP framework with asupersync capability contexts, attribute macros, and explicit cancellation/budget surfaces:

```rust
use fastmcp_rust::prelude::*;

#[tool]
async fn greet(ctx: &McpContext, name: String) -> McpResult<String> {
    ctx.checkpoint()?;  // Cancellation point
    Ok(format!("Hello, {name}!"))
}

fn main() {
    Server::new("my-server", "1.0.0")
        // Attribute macros generate PascalCase handler values.
        .tool(Greet)
        .build()
        .run_stdio();
}
```

### Why FastMCP Rust?

| Feature | FastMCP Rust | Manual Implementation |
|---------|--------------|----------------------|
| **Async handler API** | `#[tool] async fn` plus handler trait hooks | Manual Future boxing |
| **Cancellation** | Local request checkpoints; live wire interruption remains unverified | Application-specific checks |
| **Timeouts** | Request and handler budget surfaces | Application-specific timers |
| **Concurrent-future ownership** | Context combinators poll caller-owned futures | Manual ownership |
| **Error handling** | 4-valued Outcome | 2-valued Result |
| **Boilerplate** | Generated handler/schema implementations | Handwritten handler/schema implementations |

---

## AGENTS.md

This project includes an [`AGENTS.md`](AGENTS.md) file with guidelines for AI coding agents. Key points:

- **Porting methodology:** Extract spec from legacy → implement from spec → never translate line-by-line
- **Runtime:** Uses [asupersync](https://github.com/Dicklesworthstone/asupersync) exclusively; Tokio and Tokio-based adapters are unsupported
- **Unsafe code:** Forbidden (`#![forbid(unsafe_code)]`)
- **Toolchain:** Rust 2024 edition; pinned `nightly-2026-07-11` / rustc 1.99.0-nightly (`rust-version = "1.99"`)
- **MCP 2026-07-28 support is under implementation and remains unverified.**
- **Aggregate MCP 2026-07-28 support is not claimed by FND-01.**
- **The current public `PROTOCOL_VERSION` is still `2024-11-05`; newer in-tree types are not proof of negotiated 2026-07-28 support.**

---

## Quick Example

```rust
use fastmcp_rust::prelude::*;

// Define a tool with automatic JSON schema generation
#[tool(description = "Calculate the sum of two numbers")]
async fn add(ctx: &McpContext, a: i64, b: i64) -> McpResult<String> {
    ctx.checkpoint()?;  // Check the local cancellation token and budget
    Ok((a + b).to_string())
}

// Define an in-memory resource. Potentially blocking filesystem work is not
// performed inline on the dispatch worker.
#[resource(uri = "config://settings", description = "Application config")]
fn config(ctx: &McpContext) -> McpResult<String> {
    ctx.checkpoint()?;
    Ok(r#"{"theme":"dark"}"#.to_owned())
}

// Define a prompt template
#[prompt(description = "Generate a greeting message")]
async fn greeting(ctx: &McpContext, name: String) -> McpResult<Vec<PromptMessage>> {
    ctx.checkpoint()?;
    Ok(vec![PromptMessage {
        role: Role::User,
        content: Content::text(format!("Please greet {name} warmly.")),
    }])
}

fn main() {
    Server::new("example-server", "1.0.0")
        .tool(Add)
        .resource(ConfigResource)
        .prompt(GreetingPrompt)
        .request_timeout(30)  // 30-second budget per request
        .build()
        .run_stdio();
}
```

Run it:

```bash
cargo run -p fastmcp-rust --example echo_server
```

---

## Design Philosophy

### 1. Explicit Cooperative Cancellation

Handlers should check cancellation at natural suspension or iteration boundaries. FastMCP exposes cooperative checkpoints. These local context semantics do not, by themselves, make cancellation interruptible over a live connection; see the qualification boundaries above.

```rust
#[tool]
async fn process_items(
    ctx: &McpContext,
    items: Vec<String>,
) -> McpResult<Vec<Content>> {
    let mut results = vec![];
    for item in items {
        ctx.checkpoint()?;  // Allow graceful cancellation between items
        results.push(Content::text(process(item).await?));
    }
    Ok(results)
}
```

### 2. Budgets, Not Timeouts

Timeouts are "we gave up." Budgets are "you have X resources." The `Budget` type represents deadline, poll-quota, and cost-quota dimensions:

```rust
// Configure a 30-second server-owned request ceiling
Server::new("server", "1.0.0")
    .request_timeout(30)
    .tool(MyTool)
    .build()
    .run_stdio();

// Handler can check remaining budget
#[tool]
async fn my_tool(ctx: &McpContext) -> McpResult<String> {
    ctx.checkpoint()?;
    // ... work ...
    Ok("work completed".to_string())
}
```

### 3. Four-Valued Outcomes

`Result<T, E>` has no distinct cancellation or panic variants. FastMCP's asynchronous handler boundary uses `Outcome<T, E>`:

```rust
enum Outcome<T, E> {
    Ok(T),                    // Success
    Err(E),                   // Expected failure
    Cancelled(CancelReason),  // External interruption
    Panicked(PanicPayload),   // Internal failure
}
```

### 4. Capability-oriented handlers

Request authority flows through `McpContext`; application dependencies should likewise be passed explicitly instead of hidden in globals:

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

### 5. Owned Concurrent Futures

Concurrent child futures remain owned by the request handler and are polled together by context combinators:

```rust
use std::future::Future;
use std::pin::Pin;

#[tool]
async fn parallel_fetch(
    ctx: &McpContext,
    urls: Vec<String>,
) -> McpResult<Vec<Content>> {
    type FetchFuture = Pin<Box<dyn Future<Output = McpResult<String>> + Send>>;

    let futures: Vec<FetchFuture> = urls
        .into_iter()
        .map(|url| Box::pin(fetch(url)) as FetchFuture)
        .collect();

    let results = ctx.join_all(futures).await?;
    results
        .into_iter()
        .map(|result| result.map(Content::text))
        .collect()
}
```

---

## Design Positioning

These are FastMCP Rust design surfaces, not benchmark results or an MCP 2026-07-28 conformance certificate. Competing projects change independently and should be evaluated from their current documentation rather than a static comparison table.

| Area | FastMCP Rust design |
|------|---------------------|
| **Handler API** | `#[tool]`, `#[resource]`, and `#[prompt]` macros plus explicit handler traits |
| **Cancellation** | `McpContext` checkpoints and masks backed by asupersync |
| **Timeouts** | Request and handler budget surfaces |
| **Runtime** | asupersync only; Tokio adapters are unsupported |
| **Outcomes** | Four-valued `Outcome`: success, expected error, cancellation, or panic |
| **Unsafe code** | Forbidden in workspace crates with `#![forbid(unsafe_code)]` |

---

## Installation

### From crates.io (historical 0.3.2 package)

The published `0.3.2` package predates the current in-tree hardening work. Do
not treat installing it as evidence for the source-tree examples or MCP
2026-07-28 support.

```toml
[dependencies]
fastmcp-rust = "0.3.2"
```

### As a Git Dependency

```toml
[dependencies]
fastmcp-rust = { git = "https://github.com/Dicklesworthstone/fastmcp_rust" }
```

### From Source

```bash
git clone https://github.com/Dicklesworthstone/fastmcp_rust.git
cd fastmcp_rust
cargo build --release
```

### CLI (optional; historical 0.3.2 package)

```bash
cargo install fastmcp-cli
```

**Requirements:**
- Rust nightly-2026-07-11 (see `rust-toolchain.toml`) for Edition 2024 + FND-01 contract

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
fastmcp-rust = { git = "https://github.com/Dicklesworthstone/fastmcp_rust" }
```

### 3. Write Your Server

```rust
// src/main.rs
use fastmcp_rust::prelude::*;

#[tool(description = "Echo the input message")]
async fn echo(ctx: &McpContext, message: String) -> McpResult<String> {
    ctx.checkpoint()?;
    Ok(message)
}

fn main() {
    Server::new("echo-server", "1.0.0")
        .tool(Echo)
        .instructions("A simple echo server for testing")
        .build()
        .run_stdio();
}
```

### 4. Run

```bash
cargo run
```

### 5. Test with MCP Inspector

```bash
npx @modelcontextprotocol/inspector cargo run
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
│   ├── fastmcp/           # Facade crate (published as fastmcp-rust)
│   ├── fastmcp-core/      # McpContext, errors, runtime helpers
│   ├── fastmcp-protocol/  # MCP types, JSON-RPC messages
│   ├── fastmcp-transport/ # Transport implementations (stdio, SSE, WebSocket, HTTP, memory)
│   ├── fastmcp-server/    # Server builder, router, handlers
│   ├── fastmcp-client/    # Client implementation
│   ├── fastmcp-macros/    # Proc-macro crate, published as fastmcp-derive
│   ├── fastmcp-console/   # Console rendering and statistics
│   └── fastmcp-cli/       # fastmcp command-line interface
```

| Crate | Purpose |
|-------|---------|
| `fastmcp-rust` | Convenience re-exports for simple `use fastmcp_rust::prelude::*` |
| `fastmcp-core` | `McpContext` wrapper, error types, `block_on` helper |
| `fastmcp-protocol` | MCP message types, capabilities, JSON-RPC framing |
| `fastmcp-transport` | Transport trait and stdio/SSE/WebSocket/HTTP/memory implementations |
| `fastmcp-server` | `Server`, `ServerBuilder`, routing, handler traits |
| `fastmcp-client` | Subprocess-stdio `Client`; lower-level SSE/WebSocket transport types are not wired into this public client |
| `fastmcp-derive` | Procedural macros for handler generation |

---

## Handler Traits

The signatures below are abridged; asynchronous trait methods return four-valued `McpOutcome` values, not ordinary `McpResult` values.

### ToolHandler

```rust
pub trait ToolHandler: Send + Sync {
    fn definition(&self) -> Tool;
    fn call(
        &self,
        ctx: &McpContext,
        arguments: serde_json::Value,
    ) -> McpResult<Vec<Content>>;

    // Override for true async (default delegates to call())
    fn call_async<'a>(&'a self, ctx: &'a McpContext, arguments: serde_json::Value)
        -> std::pin::Pin<Box<dyn std::future::Future<Output = McpOutcome<Vec<Content>>> + Send + 'a>>;
}
```

### ResourceHandler

```rust
pub trait ResourceHandler: Send + Sync {
    fn definition(&self) -> Resource;
    fn read(&self, ctx: &McpContext) -> McpResult<Vec<ResourceContent>>;

    // Override for true async
    fn read_async<'a>(&'a self, ctx: &'a McpContext)
        -> std::pin::Pin<Box<dyn std::future::Future<Output = McpOutcome<Vec<ResourceContent>>> + Send + 'a>>;
}
```

### PromptHandler

```rust
pub trait PromptHandler: Send + Sync {
    fn definition(&self) -> Prompt;
    fn get(&self, ctx: &McpContext, arguments: std::collections::HashMap<String, String>)
        -> McpResult<Vec<PromptMessage>>;

    // Override for true async
    fn get_async<'a>(
        &'a self,
        ctx: &'a McpContext,
        arguments: std::collections::HashMap<String, String>,
    )
        -> std::pin::Pin<Box<dyn std::future::Future<Output = McpOutcome<Vec<PromptMessage>>> + Send + 'a>>;
}
```

---

## Troubleshooting

| Problem | Cause | Fix |
|---------|-------|-----|
| JSON-RPC `MethodNotFound` for `tools/call` | Tool not registered | Register the generated handler, for example `.tool(MyTool)` |
| Request cancelled mid-operation | Local request cancellation or budget exhaustion | Add checkpoints and mask only the smallest atomic section that must finish; stdio has a continuous receive pump, but custom/SSE/WebSocket loops and request-owned cleanup semantics remain unqualified |
| Budget exhausted errors | Deadline, poll, or cost dimension exhausted | Inspect the exhausted dimension; increase `.request_timeout(...)` only for a deadline that is intentionally too short |
| `#[tool]` macro compilation error | Unsupported return conversion or argument schema | Prefer `String`, `Vec<Content>`, `McpResult<String>`, or `McpResult<Vec<Content>>` and ensure custom argument types implement `JsonSchema` |
| `TransportError::Io` on startup | stdin unavailable | Ensure nothing else reads stdin |

### Critical Section Example

```rust
use std::sync::atomic::{AtomicU64, Ordering};

// A handler that owns `committed` can call this helper after validation.
fn commit_revision(
    ctx: &McpContext,
    revision: u64,
    committed: &AtomicU64,
) -> McpResult<()> {
    // Mask only a small, non-blocking atomic commit. Masking does not make
    // synchronous filesystem or device I/O bounded or cancel-safe.
    ctx.masked(|| committed.store(revision, Ordering::Release))
        .map_err(|error| McpError::internal_error(error.to_string()))?;
    Ok(())
}
```

---

## Limitations

| Limitation | Details |
|------------|---------|
| **Pinned Nightly Required** | The project contract pins `nightly-2026-07-11`; do not substitute a different toolchain merely because it supports Edition 2024 |
| **Protocol Modernization** | The public protocol constant remains `2024-11-05`; MCP 2026-07-28 implementation and verification are incomplete |
| **Runtime-context migration** | The workspace still enables asupersync `test-internals` as a stopgap while synchronous entry points are migrated to runtime-managed contexts |
| **Network Transports** | HTTP parsing/framing primitives exist, but the turnkey `run_http*` entry points fail closed before binding until stateless per-request dispatch is qualified; SSE and WebSocket entry points require caller-provided I/O integration |
| **Client Transport Coverage** | The public `fastmcp-client::Client` currently connects only to subprocess stdio; lower-level SSE and WebSocket transport types do not constitute client integration |
| **No Built-in TLS** | Transport encryption must be handled externally |
| **HTTP Dispatch Qualification** | The old sessionful listener is private and unreachable; public `run_http*` calls fail closed before binding. Modern `LatestOnly` still needs immutable stateless per-request dispatch and an owned request execution; a bounded owner-bound Session registry belongs only to the feature-gated LEG-02 MCP 2025-11-25 adapter |
| **Wire Cancellation** | Stdio has a continuous receive pump plus serialized dispatch worker and can route `notifications/cancelled` during handler execution. Custom/SSE/WebSocket loops remain sequential, while request-owned `Cx` isolation and reliable `awaitCleanup` semantics remain unverified |
| **Silent stdio peers** | On Unix, the public subprocess `Client` polls child stdout before every otherwise-blocking buffer fill, so initialization and response receive deadlines/cancellation also bound silent and partial-frame peers. Generic blocking `StdioTransport::recv`, non-Unix child-pipe reads, and blocking writes retain their documented frame/I/O-boundary limitation; the configured request timeout is therefore a hard Unix receive bound, not a portable end-to-end wall-clock bound. Those residuals remain FND-04 work |
| **Request Cancellation Ownership** | Request work does not yet have an independently owned child `Cx`; cancellation must not be treated as a sibling-isolated guarantee |
| **Bidirectional Response Routing** | Stdio continuously routes inbound responses while its dispatch worker is occupied. Custom/SSE/WebSocket paths do not provide the same split routing, public HTTP is fail-closed, and end-to-end lifecycle qualification remains open |
| **Response Cache Partitioning** | Eligible entries are partitioned by committed authentication facts and opaque session identity/revision; ambiguous admission and state mutation fail closed. This does not promote OAuth/OIDC or establish protocol conformance |
| **Authentication Admission** | JSON-RPC credential fields are a stripped legacy fallback. The quarantined private HTTP helper carries native `Authorization` metadata separately, but public turnkey HTTP remains fail-closed and no complete transport-boundary admission/challenge path is qualified |
| **Tasks RPC** | Task methods are not advertised and return `MethodNotFound`; client/task source presence is not a usable server capability |
| **OAuth/OIDC Promotion** | Public source APIs exist, but production security and profile conformance remain unverified; they are quarantined from production-support claims |
| **Early Development** | API may change before 1.0 |

---

## FAQ

**Q: Why is Tokio unsupported?**

A: FastMCP Rust is built around asupersync capability contexts, budgets, and cooperative-cancellation surfaces. Tokio and Tokio-based adapters are outside the supported runtime model.

**Q: Can I use this with Claude Desktop?**

A: Stdio integration exists, but compatibility must be checked against the client because the current public protocol constant is `2024-11-05` and MCP 2026-07-28 support is not yet verified.

**Q: How do I add authentication?**

A: Static-token, OAuth, and OIDC implementation code exists, but OAuth/OIDC
production security and profile conformance remain unverified. Recognized
credentials in JSON-RPC params are only a legacy fallback; FastMCP authenticates
them and strips those fields before extension middleware and handlers. The
quarantined private HTTP helper carries native `Authorization` metadata through
pre-dispatch admission, but a public transport integration still needs a
qualified admission/challenge boundary, TLS, and profile-specific validation.

**Q: What's the performance overhead of checkpoints?**

A: Checkpoints perform cancellation and budget checks. No project benchmark currently supports a universal per-call latency claim; measure them in the target workload if the cost matters.

**Q: Can I use other async runtimes?**

A: No. The current API and implementation require asupersync; other async runtimes are not supported.

**Q: How do I test my handlers?**

A: Construct `McpContext` from an asupersync testing context and a request ID:
```rust
use fastmcp_rust::{Cx, McpContext, McpResult, tool};

#[tool]
fn my_tool(ctx: &McpContext, input: String) -> McpResult<String> {
    ctx.checkpoint()?;
    Ok(input)
}

#[test]
fn test_my_tool() {
    let ctx = McpContext::new(Cx::for_testing(), 1);
    let result = my_tool(&ctx, "input".to_string());
    assert_eq!(result.unwrap(), "input");
}
```

---

## About Contributions

Please don't take this the wrong way, but I do not accept outside contributions for any of my projects. I simply don't have the mental bandwidth to review anything, and it's my name on the thing, so I'm responsible for any problems it causes; thus, the risk-reward is highly asymmetric from my perspective. I'd also have to worry about other "stakeholders," which seems unwise for tools I mostly make for myself for free. Feel free to submit issues, and even PRs if you want to illustrate a proposed fix, but know I won't merge them directly. Instead, I'll have Claude or Codex review submissions via `gh` and independently decide whether and how to address them. Bug reports in particular are welcome. Sorry if this offends, but I want to avoid wasted time and hurt feelings. I understand this isn't in sync with the prevailing open-source ethos that seeks community contributions, but it's the only way I can move at this velocity and keep my sanity.

---

## License

The release-license representation is unresolved: workspace Cargo metadata
declares `MIT`, [LICENSE](LICENSE) contains an additional OpenAI/Anthropic
rider, and [LICENSE-MIT](LICENSE-MIT) contains plain MIT text. Do not infer
authoritative release terms from one of these inputs in isolation. Publication
remains blocked until the explicit release-license decision required by the
implementation plan is reviewed and applied consistently.

---

<p align="center">
  <sub>Built with <a href="https://github.com/Dicklesworthstone/asupersync">asupersync</a> for context-aware async</sub>
</p>
