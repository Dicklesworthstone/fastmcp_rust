# Plan To Port FastMCP To Rust

This document describes the porting strategy for FastMCP Rust.

FastMCP Rust targets **feature-for-feature, behavior-for-behavior parity** with Python FastMCP
(baseline referenced in `FEATURE_PARITY.md`). The port is not a line-by-line translation; it is
an implementation from a stable spec (`EXISTING_FASTMCP_STRUCTURE.md`) with an idiomatic Rust
architecture (`PROPOSED_RUST_ARCHITECTURE.md`).

## Non-Negotiables

- **Protocol correctness**: stdout is NDJSON JSON-RPC only. All human output must go to stderr.
- **Cancel-correctness**: cooperative cancellation via `asupersync` (`McpContext::checkpoint()`).
- **Budgeted execution**: request-scoped budgets are enforced; handlers can introspect remaining budget.
- **Structured concurrency**: spawned work is scoped; no orphan tasks.
- **Unsafe is forbidden**: `#![forbid(unsafe_code)]` across crates.
- **Minimal dependencies**: prefer small, well-known crates; pin versions explicitly in Cargo.toml.

## Source Of Truth

1. `EXISTING_FASTMCP_STRUCTURE.md` (the spec)
2. `PROPOSED_RUST_ARCHITECTURE.md` (how Rust implements the spec)
3. `FEATURE_PARITY.md` (audit report and parity checklist)

Python legacy code is a reference for edge cases and conformance only; implementation decisions
must be justified in terms of the spec and the Rust architecture.

## Work Breakdown (Phases)

### Phase 1: Protocol + Types

- JSON-RPC framing types (Request/Response/Notifications)
- MCP domain types: tools/resources/prompts/tasks/sampling/roots/elicitations
- Cursor-based pagination types and conventions
- Serialization/deserialization with `serde`

Acceptance: round-trip serde tests; schema tests; fixtures for representative MCP messages.

### Phase 2: Transport Layer

- `Transport` trait and cancel-aware send/recv
- Stdio NDJSON transport (primary)
- SSE client/server transport with resumability and bounded memory behavior
- HTTP / Streamable HTTP transport, WebSocket transport
- In-process `MemoryTransport` for tests

Acceptance: transport e2e tests; codec boundary tests (size limits, partial reads, invalid UTF-8).

### Phase 3: Server Core

- `ServerBuilder` surface matches Python functionality
- `Session` tracks negotiated protocol version and capabilities
- `Router` dispatches all MCP methods; supports mounting and composition
- Strict input validation and error-masking behavior
- Progress notifications and cancellation behavior

Acceptance: server conformance tests for every method; mount/composition tests; tag filtering tests.

### Phase 4: Macros / Derive

- `#[tool]`, `#[resource]`, `#[prompt]` map functions into handler traits
- JSON schema generation for args and (when applicable) output
- Attribute coverage: names, descriptions, tags, icons, versions, timeouts, defaults

Acceptance: macro expansion tests + runtime invocation tests (including defaults and schema metadata).

### Phase 5: Client

- Initialization handshake
- Request/response routing and id validation
- Pagination helpers with robustness guards
- Support for server-to-client protocols (sampling, elicitation, roots)

Acceptance: client integration tests against `MemoryTransport` and local server instances.

### Phase 6: Console + CLI

- `fastmcp-console`: rich stderr UI; plain fallback must preserve semantics
- `fastmcp-cli`: run/inspect/install workflows; dry-run outputs must be explicit

Acceptance: snapshot tests for console; CLI integration tests for install generators (dry-run).

## Quality Gates (Always)

After substantive changes:

```bash
cargo fmt --check
cargo check --all-targets
cargo clippy --all-targets -- -D warnings
cargo test --all --all-targets
```

