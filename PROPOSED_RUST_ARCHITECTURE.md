# Proposed Rust Architecture (FastMCP Rust)

This document captures the current Rust architecture for FastMCP and how it maps to the
spec in `EXISTING_FASTMCP_STRUCTURE.md`. It is intended to be the reference design for
implementation and future changes.

## Goals and Invariants

- Cancel-correct async: cooperative cancellation via asupersync.
- Budget-aware request handling: deadlines and resource quotas apply to every request.
- Protocol purity: stdout is NDJSON JSON-RPC only; human output goes to stderr.
- Structured concurrency: request work is scoped to regions (no orphan tasks).
- Minimal deps: serde/serde_json + asupersync + rich_rust where needed.
- Unsafe code forbidden.

## High-Level Layering

```
fastmcp (facade)
  ├── fastmcp-core (context, errors, runtime glue)
  ├── fastmcp-protocol (JSON-RPC + MCP types)
  ├── fastmcp-transport (NDJSON + stdio transport)
  ├── fastmcp-server (builder, router, handlers, session)
  ├── fastmcp-client (stdio client + handshake)
  ├── fastmcp-derive (#[tool], #[resource], #[prompt], JsonSchema)
  └── fastmcp-console (rich stderr output, stats, banner)
```

## Crate Responsibilities

### `fastmcp` (facade)
- Re-exports public types, macros, and prelude for ergonomic use.
- Provides the unified API surface (`use fastmcp_rust::prelude::*`).

### `fastmcp-core`
- `McpContext` wraps `asupersync::Cx` and exposes:
  - `checkpoint()`, `masked()`, `budget()`, `is_cancelled()`, `trace()`
- Error model: `McpError`, `McpErrorCode`, `McpResult`
- Outcome bridging: `IntoOutcome` for 4-valued semantics
- Runtime glue: `block_on` for simple async execution
- Progress reporting: `NotificationSender`, `ProgressReporter`

### `fastmcp-protocol`
- JSON-RPC 2.0 request/response/message types
- MCP domain types (Tools, Resources, Prompts, Capabilities)
- Schema validation helpers for tool input

### `fastmcp-transport`
- `Transport` trait: send/recv/close with cancellation checks
- `Codec`: NDJSON framing and JSON (de)serialization
- `StdioTransport`: stdin/stdout implementation (primary)
- Two-phase send (`SendPermit`, `TwoPhaseTransport`) for cancel-safe output

### `fastmcp-server`
- `ServerBuilder` and `Server` lifecycle
- `Router`: dispatches MCP methods (`initialize`, `tools/list`, `tools/call`, etc.)
- `Session`: tracks client capabilities and negotiated protocol version
- Handler traits: `ToolHandler`, `ResourceHandler`, `PromptHandler`
- Progress notifications via `NotificationSender` callback
- Stats integration via `fastmcp-console::stats` (optional)

### `fastmcp-client`
- Stdio client spawning a subprocess
- Initialization handshake (initialize + initialized)
- Call APIs for tools/resources/prompts
- Progress notification handling for tool calls

### `fastmcp-derive`
- `#[tool]`: converts a function into a `ToolHandler` impl
- `#[resource]`: converts a function into a `ResourceHandler` impl
- `#[prompt]`: converts a function into a `PromptHandler` impl
- `#[derive(JsonSchema)]`: generates JSON Schema for input structs/enums

### `fastmcp-console`
- Rich stderr output (banner, tables, logging, diagnostics)
- Display context detection (agent vs human)
- Server stats rendering
- Designed to never touch stdout

## Request Flow (Server)

```
StdioTransport.recv() -> JsonRpcMessage::Request
  -> Server::handle_request()
    -> Server::dispatch_method()
      -> Router::handle_*()
        -> Handler call (tool/resource/prompt)
  -> JsonRpcResponse
  -> StdioTransport.send()
```

Key points:
- Each request gets an internal `request_id` (u64) for tracing.
- `Budget` is created per request from server config.
- Cancellation and budget exhaustion are checked pre-dispatch.
- Progress notifications are sent via a callback that writes NDJSON to stdout
  while the main recv loop is blocked.

## Cancellation and Budgeting

- `McpContext::checkpoint()` is the cooperative cancellation point.
- `Budget` is enforced by callers (server) and checked by handlers.
- `masked()` protects critical sections from cancellation.

## Transport and Protocol

- NDJSON is the wire format (newline-delimited JSON).
- `Codec` handles encode/decode, buffering partial lines.
- `Transport::send/recv` must check `Cx` for cancellation.
- Two-phase send ensures no message loss across cancellation points.

## Progress Notifications

- Request metadata may include a `progress_token`.
- `ProgressNotificationSender` wraps the token and sends
  `notifications/progress` messages via the transport callback.
- `McpContext` exposes `report_progress()` helpers.

## Console Output Separation

- **stdout:** JSON-RPC only, no styling, no banners.
- **stderr:** human-oriented rich output (banners, logs, tables, stats).
- `fastmcp-console` renders all human-facing output and respects agent context
  detection and NO_COLOR.

## Current Implementation Notes

- Stdio is the primary transport; SSE/WebSocket transport modules are implemented,
  with HTTP/upgrade integration handled externally.
- Handlers are invoked via `block_on` in the router to keep API simple
  while the broader async runtime integration evolves.
- Server stats collection is optional and can be disabled for performance.

## Mapping to Spec (`EXISTING_FASTMCP_STRUCTURE.md`)

- **Regions / structured concurrency:** represented by `Cx` and `McpContext`.
- **Outcome model:** exposed via `Outcome` re-exports; `McpError` mapping.
- **Budgets:** created per request and checked before dispatch.
- **Two-phase transport:** implemented in `fastmcp-transport`.
- **Tools/Resources/Prompts:** macro-generated handlers + router dispatch.

## Future Work (Tracked in Beads)

- Rich logging subscriber integration
- ConsoleConfig wiring into `ServerBuilder`
- HTTP server adapters for SSE/WebSocket (routing, upgrade, auth)
- Deterministic testing with `LabRuntime` in more modules

---

This document should evolve as implementation changes land. Keep it aligned with
actual code structure, and update when adding new crates or major flows.
