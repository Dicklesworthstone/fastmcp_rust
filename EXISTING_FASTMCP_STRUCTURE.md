# Existing FastMCP Structure (Spec)

This is the spec for FastMCP Rust. It defines the required behavior and API surface that must be
implemented, independent of any particular legacy implementation.

Baseline parity target is Python FastMCP as referenced in `FEATURE_PARITY.md`.

## Core Concepts

- **Protocol transport**: JSON-RPC 2.0 over newline-delimited JSON (NDJSON).
- **MCP methods**: the server implements MCP RPC methods and notifications; the client can call them.
- **Handlers**:
  - Tools: executable functions with typed args and `Content` output.
  - Resources: readable entities addressed by URI (and templates).
  - Prompts: prompt templates producing prompt message sequences.
- **Context**: every handler receives `&McpContext` which provides cancellation, budgets, and capability access.
- **Cancellation**: handlers must be cooperative via `ctx.checkpoint()` and `ctx.masked(|| ...)`.
- **Budgets**: each request has a budget; exceeding budget is an error (or cancellation) with deterministic behavior.

## Wire Format Invariants

- **stdout** MUST be MCP NDJSON JSON-RPC only. No banners, logs, or diagnostics.
- **stderr** MAY be used for human-readable output (rich styling allowed), but must never affect stdout.
- Each JSON-RPC message is a single JSON object followed by `\\n`.

## Protocol Methods (Server)

The server MUST support these MCP methods and their semantics.

### Lifecycle / Negotiation

- `initialize`: negotiate protocol version and capabilities; returns server info and capabilities.
- `initialized` (notification): marks client ready; server may begin sending notifications.
- `ping`: health check.

### Tools

- `tools/list`: list tool definitions with cursor-based pagination.
- `tools/call`: call a tool by name with optional `arguments`.
  - Progress notifications: if a progress token is supplied, server emits `notifications/progress`.
  - Result uses MCP `Content` items (text/image/audio/resource, etc.).

### Resources

- `resources/list`: list resources with cursor-based pagination.
- `resources/read`: return resource content for a URI.
- `resources/templates/list`: list resource templates with cursor pagination.
- `resources/subscribe` / `resources/unsubscribe`: protocol support for resource subscriptions.

### Prompts

- `prompts/list`: list prompt definitions with cursor pagination.
- `prompts/get`: instantiate a prompt with arguments.

### Logging

- `logging/setLevel`: set server log level (if supported).
- `notifications/message`: server-to-client log message notifications.

### Cancellation and Progress

- `notifications/cancelled`: cancellation notification with `await_cleanup` semantics (if applicable).
- `notifications/progress`: progress events (server-to-client).

### Background Tasks (Docket)

- `tasks/list`: list tasks with optional status filter and cursor pagination.
- `tasks/get`: return task status and result (when available).
- `tasks/submit`: submit a task for background execution.
- `tasks/cancel`: cancel a task with optional reason.

### Sampling (Server-to-Client)

- `sampling/createMessage`: server requests the client to create a model message.

### Roots (Server-to-Client)

- `roots/list`: server requests client roots list (when client supports it).

### Elicitation (Server-to-Client)

- Elicitation request/response round-trip (method names/types as in protocol types).

## Pagination Conventions

- List methods return `next_cursor` when more items exist; otherwise `next_cursor = null`.
- Clients SHOULD follow cursors until exhaustion.
- Implementations MUST defend against malformed servers:
  - Cursor repetition cycles must not create infinite loops.
  - Excessive page counts must be bounded.

## Content Model

Content items represent tool results and messages:

- Text: UTF-8 string.
- Image: base64 or bytes + MIME type.
- Audio: base64 or bytes + MIME type.
- Resource: references a resource by URI and may include `text` and/or `blob`.

Spec requirement: conversions between protocol content and internal/core content MUST be lossless
for all fields used by MCP (notably resource `blob` and non-text content types).

## Server API Surface (Rust)

The Rust public API must provide:

- `Server::new(name, version)` + fluent builder methods:
  - register tools/resources/prompts
  - configure instructions, logging, timeouts/budgets, strict validation, masking
  - mounting/composition (`mount`) with deterministic ordering
  - duplicate behavior policy
  - tag include/exclude filtering
- `run_stdio()` as the primary runtime entrypoint, plus optional SSE/HTTP/WS run modes.

## Handler Contracts

### Tool Handlers

- Definition includes: name, description, input schema, optional output schema, tags, icon, version, annotations.
- Call must validate input (respecting server strictness), run with budget/cancellation, and return content.

### Resource Handlers

- Definition includes: URI, name, description, MIME type, tags, icon, version.
- Read returns `ResourceContent` items with `text` and/or `blob`.

### Prompt Handlers

- Definition includes: name, description, args schema, tags, icon, version.
- Get returns a list of `PromptMessage` items.

## Macro / Decorator Parity

Rust provides procedural macros that match Python decorator behavior:

- `#[tool]`, `#[resource]`, `#[prompt]` transform functions into handlers.
- Doc comments contribute default descriptions when not overridden.
- Attribute parameters cover: name, description, tags, icon, version, timeout.
- Default parameter values:
  - Rust cannot have default fn args; defaults are expressed via macro attributes.
  - `#[tool(defaults(foo = 123, bar = \"baz\"))]`
  - `#[prompt(defaults(greeting = \"Hi\"))]`
  - Defaults affect generated schema (`default` fields) and runtime argument filling.

## Test Obligations

Parity is only considered satisfied when covered by tests:

- Router dispatch tests for every MCP method
- Mount/composition ordering tests
- Content round-trip tests (including resource blob and audio)
- Pagination robustness tests (cycle and page limit)
- Macro expansion + runtime behavior tests for defaults/schema metadata

