# FastMCP Rust Feature Parity Report

> **Assessment Date:** 2026-01-28 (historical matrix below; FND-01 status updated 2026-07-31)
> **Assessed by:** VioletFalcon (claude-opus-4-5-20251101)
> **Prior Assessors:** GoldReef, AzureDeer, DustyReef (claude-opus-4-5-20251101)
> **Methodology:** Porting-to-Rust Phase 5 Conformance Analysis (comprehensive source comparison)
> **Python FastMCP Version:** 2.14.4

## FND-01 / MCP 2026-07-28 status (authoritative)

**MCP 2026-07-28 support is under implementation and remains unverified.**  
**Aggregate MCP 2026-07-28 support is not claimed by FND-01.**

Toolchain: pinned `nightly-2026-07-11` / rustc 1.99.0-nightly (`rust-version = "1.99"`).  
Production JWT (`jsonwebtoken`), Docket/Redis, Apps media rendering, and aggregate release-gate claims are **not** FND-01 deliverables. Treat rows below that still say “complete” for those areas as **historical pre-FND notes**, not current support claims.

## Executive Summary

This is a comprehensive feature parity assessment comparing the Rust port against Python FastMCP v2.14.4. The historical matrix below was produced before FND-01 freeze discipline; **do not treat it as a current aggregate-support certificate**.

**Current honest posture:** MCP 2026-07-28 foundation work is in progress under FND-01; later packages own full protocol-era parity, Redis Tasks, and media.

### Key Strengths (Better Than Python)
- **Cancel-correctness**: Cooperative cancellation via checkpoints and masks
- **4-valued outcomes**: Ok/Err/Cancelled/Panicked (vs Python's 2-valued)
- **Structured concurrency**: All tasks scoped to regions
- **Budget system**: Superior timeout mechanism via asupersync
- **Rich console**: Banners, traffic display, statistics collection
- **Parallel combinators**: join_all, race, quorum, first_ok

### Landed areas (subject to FND-01 nonpromotion)
- OAuth/OIDC code paths exist in-tree but are **not** aggregate 2026-07-28 certified
- Middleware / HTTP / CLI / transports exist; Redis Docket is **not** a production FND-01 edge
- MCPConfig and memory transport remain useful for development

---

## Feature Comparison Matrix

### Legend
- ✅ **Implemented** - Fully working in Rust
- 🟡 **Partial** - Partially implemented or stub exists
- ❌ **Missing** - Not implemented
- ⊘ **Excluded** - Intentionally not ported (per plan)

---

## 1. Server Core Features

| Feature | Python | Rust | Notes |
|---------|--------|------|-------|
| Basic server creation | ✅ | ✅ | `Server::new()` |
| Server builder pattern | ✅ | ✅ | `ServerBuilder` with fluent API |
| Name/version/instructions | ✅ | ✅ | All configured via builder |
| Stdio transport | ✅ | ✅ | Full NDJSON support |
| SSE transport | ✅ | ✅ | `run_sse()` with `SseServerTransport` |
| WebSocket transport | ✅ | ✅ | `run_websocket()` with `WsTransport` (RFC 6455) |
| **HTTP transport** | ✅ | ✅ | `http.rs` with stateless and streamable modes |
| **Streamable HTTP transport** | ✅ | ✅ | `StreamableHttpTransport` |
| Request timeout/budget | ✅ | ✅ | Via asupersync Budget (superior) |
| Cancel-correctness | 🟡 | ✅ | **Better in Rust** via asupersync |
| Lifecycle hooks (lifespan) | ✅ | ✅ | `on_startup()` / `on_shutdown()` |
| Ping/health check | ✅ | ✅ | `ping` method handled |
| Statistics collection | ❌ | ✅ | `ServerStats` with snapshots |
| Console/banner rendering | ❌ | ✅ | `fastmcp-console` crate |

### Server Gaps (All Completed ✅)

| Feature | Python | Rust | Notes |
|---------|--------|------|-------|
| **Dynamic enable/disable** | ✅ | ✅ | Per-session visibility via state.rs, context.rs |
| **Component versioning** | ✅ | ✅ | Version fields on Tool, Resource, Prompt types |
| **Tags for filtering** | ✅ | ✅ | `include_tags`/`exclude_tags` in router.rs |
| **Icons support** | ✅ | ✅ | Icon metadata in types.rs, handler.rs |
| **Error masking** | ✅ | ✅ | `mask_error_details` in builder.rs |
| **Strict input validation** | ✅ | ✅ | `strict_input_validation` in router.rs |
| **Duplicate handling** | ✅ | ✅ | `on_duplicate` in builder.rs |
| **as_proxy() method** | ✅ | ✅ | Implemented in builder.rs, proxy.rs |
| **mount() composition** | ✅ | ✅ | Implemented in builder.rs, router.rs |

---

## 2. Decorators / Macros

| Feature | Python | Rust | Notes |
|---------|--------|------|-------|
| `@tool` / `#[tool]` | ✅ | ✅ | Full functionality |
| `@resource` / `#[resource]` | ✅ | ✅ | Full functionality with URI templates |
| `@prompt` / `#[prompt]` | ✅ | ✅ | Full functionality |
| Auto JSON schema | ✅ | ✅ | `#[derive(JsonSchema)]` + inline generation |
| Description from docstrings | ✅ | ✅ | Doc comments → descriptions |
| Default parameter values | ✅ | ✅ | Implemented via `defaults(...)` on `#[tool]`/`#[prompt]` (e.g. `#[tool(defaults(foo = 123, bar = \"baz\"))]`) |
| name/description override | ✅ | ✅ | Attribute parameters supported |

### Decorator Gaps (All Completed ✅)

| Feature | Python | Rust | Notes |
|---------|--------|------|-------|
| **Icons** | ✅ | ✅ | Supported in handler.rs, types.rs |
| **Tags** | ✅ | ✅ | Supported for filtering in router.rs |
| **Output schema** | ✅ | ✅ | Tool output schema in macros, handler.rs |
| **Tool annotations** | ✅ | ✅ | MCP annotations in types.rs, handler.rs |
| **Timeout per handler** | ✅ | ✅ | Per-handler timeout in handler.rs |

---

## 3. Transport Layer

| Feature | Python | Rust | Notes |
|---------|--------|------|-------|
| **Stdio transport** | ✅ | ✅ | Full NDJSON implementation |
| **SSE transport** | ✅ | ✅ | `SseServerTransport`, `SseClientTransport` |
| **WebSocket transport** | ✅ | ✅ | `WsTransport` with RFC 6455 compliance |
| **HTTP transport** | ✅ | ✅ | `HttpTransport`, `HttpRequestHandler` |
| **Streamable HTTP** | ✅ | ✅ | `StreamableHttpTransport` |
| **MemoryTransport (in-process)** | ✅ | ✅ | `memory.rs` for testing |
| **Two-phase send** | ❌ | ✅ | Cancel-safe output (Rust-only feature) |
| **Codec with size limits** | ✅ | ✅ | Configurable max message size |
| **EventStore** | ✅ | ✅ | `event_store.rs` with TTL-based retention |

---

## 4. Protocol Methods

| MCP Method | Python | Rust | Notes |
|------------|--------|------|-------|
| `initialize` | ✅ | ✅ | Full capability negotiation |
| `initialized` | ✅ | ✅ | Notification handled |
| `ping` | ✅ | ✅ | Health check |
| `tools/list` | ✅ | ✅ | With cursor pagination |
| `tools/call` | ✅ | ✅ | With progress token support |
| `resources/list` | ✅ | ✅ | With cursor pagination |
| `resources/read` | ✅ | ✅ | With progress token support |
| `resources/templates/list` | ✅ | ✅ | RFC 6570 template support |
| `resources/subscribe` | ✅ | ✅ | Protocol support |
| `resources/unsubscribe` | ✅ | ✅ | Protocol support |
| `prompts/list` | ✅ | ✅ | With cursor pagination |
| `prompts/get` | ✅ | ✅ | With argument support |
| `logging/setLevel` | ✅ | ✅ | Full LogLevel enum support |
| `notifications/cancelled` | ✅ | ✅ | With await_cleanup support |
| `notifications/progress` | ✅ | ✅ | Progress token support |

### Background Tasks (Docket/SEP-1686)

| MCP Method | Python | Rust | Notes |
|------------|--------|------|-------|
| `tasks/list` | ✅ | ✅ | With status filtering, cursor pagination |
| `tasks/get` | ✅ | ✅ | Full TaskInfo and TaskResult |
| `tasks/submit` | ✅ | ✅ | Background task submission |
| `tasks/cancel` | ✅ | ✅ | With reason support |

### Sampling Protocol

| MCP Method | Python | Rust | Notes |
|------------|--------|------|-------|
| `sampling/createMessage` | ✅ | ✅ | Protocol types + McpContext::sample() |

### Server-to-Client Protocols

| MCP Method | Python | Rust | Notes |
|------------|--------|------|-------|
| **Elicitation** | ✅ | ✅ | `ctx.elicit()` via `TransportElicitationSender` |
| **Roots** | ✅ | ✅ | `TransportRootsProvider` for `roots/list` |

### Bidirectional Communication Infrastructure

✅ **COMPLETE** - Full bidirectional communication implemented:
1. ✅ `PendingRequests` - Tracks server-to-client requests with response routing
2. ✅ `RequestSender` - Sends requests through transport with response awaiting
3. ✅ `TransportSamplingSender` - Implements `SamplingSender` trait
4. ✅ `TransportElicitationSender` - Implements `ElicitationSender` trait
5. ✅ `TransportRootsProvider` - Provides `roots/list` requests
6. ✅ Main loop routes responses to pending requests
7. ✅ `Server` struct has `pending_requests` field for tracking

---

## 5. Client Features

| Feature | Python | Rust | Notes |
|---------|--------|------|-------|
| Subprocess spawning | ✅ | ✅ | Via `Command` with proper cleanup |
| Tool invocation | ✅ | ✅ | `call_tool()` |
| Resource reading | ✅ | ✅ | `read_resource()` |
| Prompt fetching | ✅ | ✅ | `get_prompt()` |
| Progress callbacks | ✅ | ✅ | `call_tool_with_progress()` |
| List operations | ✅ | ✅ | All list methods |
| Request cancellation | ✅ | ✅ | `cancel_request()` |
| Log level setting | ✅ | ✅ | `set_log_level()` |
| Response ID validation | ✅ | ✅ | Validates response IDs |
| Timeout support | ✅ | ✅ | Configurable timeout |
| **MCPConfig client creation** | ✅ | ✅ | `mcp_config.rs` with JSON/TOML parsing |
| **SamplingHandler** | ✅ | ✅ | Fully wired via `ctx.sample()` |
| **ElicitationHandler** | ✅ | ✅ | Fully wired via `ctx.elicit()` |

### Client Gaps (All Completed ✅)

| Feature | Python | Rust | Notes |
|---------|--------|------|-------|
| **Auto-initialize** | ✅ | ✅ | Implemented in client builder.rs |
| **Task client methods** | ✅ | ✅ | `submit_task()`, `list_tasks()`, etc. in client lib.rs |

---

## 6. Context / Dependency Injection

| Feature | Python | Rust | Notes |
|---------|--------|------|-------|
| Context object | ✅ | ✅ | `McpContext` |
| Progress reporting | ✅ | ✅ | `report_progress()`, `report_progress_with_total()` |
| Checkpoint for cancellation | ✅ | ✅ | `checkpoint()` |
| Budget access | ✅ | ✅ | `budget()` |
| Request ID access | ✅ | ✅ | `request_id()` |
| Region ID access | ❌ | ✅ | `region_id()` (Rust-only) |
| Task ID access | ❌ | ✅ | `task_id()` (Rust-only) |
| Masked critical sections | ❌ | ✅ | `masked()` (Rust-only) |
| Session state | ✅ | ✅ | `get_state()` / `set_state()` / `remove_state()` |
| Auth context | ✅ | ✅ | `auth()` / `set_auth()` |
| Parallel combinators | ❌ | ✅ | `join_all()`, `race()`, `quorum()`, `first_ok()` |
| Sampling from handler | ✅ | ✅ | `ctx.sample()` and `ctx.sample_with_request()` |
| **Elicitation from handler** | ✅ | ✅ | `ctx.elicit()` |

### Context Gaps (All Completed ✅)

| Feature | Python | Rust | Notes |
|---------|--------|------|-------|
| **Resource reading from handler** | ✅ | ✅ | `ctx.read_resource()` in context.rs |
| **Tool calling from handler** | ✅ | ✅ | `ctx.call_tool()` in context.rs |
| **MCP capabilities access** | ✅ | ✅ | `ctx.client_capabilities()`, `ctx.server_capabilities()` |

---

## 7. Authentication

| Feature | Python | Rust | Notes |
|---------|--------|------|-------|
| AuthProvider base trait | ✅ | ✅ | `AuthProvider` trait |
| Token verification | ✅ | ✅ | `TokenVerifier` trait |
| Static token verifier | ✅ | ✅ | `StaticTokenVerifier` |
| JWT support | ✅ | 🚧 | Process-global JWT crypto removed under FND-01; ring RS256 evidence path supersedes `jsonwebtoken` (no `jwt` feature) |
| Access token handling | ✅ | ✅ | `AuthContext` with token |
| **Full OAuth 2.0/2.1 Server** | ✅ | 🚧 | `oauth.rs` present; not an FND-01 aggregate support claim |
| **OIDC Provider** | ✅ | 🚧 | `oidc.rs` present; enterprise/OIDC promotion is later packages |
| **Authorization code flow** | ✅ | ✅ | With PKCE (OAuth 2.1 compliant) |
| **Token issuance** | ✅ | ✅ | Access + refresh tokens |
| **Token revocation** | ✅ | ✅ | RFC 7009 compliant |
| **Client registration** | ✅ | ✅ | Dynamic client registration |
| **Scope validation** | ✅ | ✅ | Fine-grained scope control |
| **Redirect validation** | ✅ | ✅ | Security-critical validation |

---

## 8. Middleware

| Feature | Python | Rust | Notes |
|---------|--------|------|-------|
| Middleware trait | ✅ | ✅ | `Middleware` trait |
| Request filtering | ✅ | ✅ | `on_request()` |
| Response transformation | ✅ | ✅ | `on_response()` |
| Error handling | ✅ | ✅ | `on_error()` |
| Middleware chain | ✅ | ✅ | Vec<Box<dyn Middleware>> |
| **ResponseCachingMiddleware** | ✅ | ✅ | `caching.rs` with TTL, LRU eviction |
| **RateLimitingMiddleware** | ✅ | ✅ | `rate_limiting.rs` - Token bucket |
| **SlidingWindowRateLimiting** | ✅ | ✅ | `rate_limiting.rs` - Sliding window |

---

## 9. Providers & Dynamic Components

| Feature | Python | Rust | Notes |
|---------|--------|------|-------|
| **Proxy to remote server** | ✅ | ✅ | `ProxyClient`, `ProxyCatalog` |
| **ProxyToolManager** | ✅ | ✅ | Tool proxying |
| **ProxyResourceManager** | ✅ | ✅ | Resource proxying |
| **ProxyPromptManager** | ✅ | ✅ | Prompt proxying |
| **Tool Transformations** | ✅ | ✅ | `transform.rs` - Dynamic schema modification |
| **TransformedTool** | ✅ | ✅ | Dynamic tool modification |
| **ArgTransform** | ✅ | ✅ | Argument transformation rules |

### Provider Gaps (All Completed ✅)

| Provider | Python | Rust | Notes |
|----------|--------|------|-------|
| **FilesystemProvider** | ✅ | ✅ | Implemented in providers/filesystem.rs |
| **OpenAPIProvider** | ✅ | ⊘ | Excluded per plan (intentional) |

---

## 10. Configuration & Settings

| Feature | Python | Rust | Notes |
|---------|--------|------|-------|
| Log level configuration | ✅ | ✅ | Via environment + LoggingConfig |
| Console configuration | ✅ | ✅ | ConsoleConfig |
| Timeout configuration | ✅ | ✅ | Via builder |
| Banner configuration | ✅ | ✅ | BannerStyle enum |
| Traffic verbosity | ✅ | ✅ | TrafficVerbosity enum |
| Environment variables | ✅ | ✅ | FASTMCP_LOG, FASTMCP_NO_BANNER, etc. |
| **DocketSettings** | ✅ | ✅ | `docket.rs` - Task queue configuration |
| **MCPConfig file support** | ✅ | ✅ | `mcp_config.rs` - JSON/TOML parsing |

### Configuration Gaps (All Completed ✅)

| Config | Python | Rust | Notes |
|--------|--------|------|-------|
| **include_tags/exclude_tags** | ✅ | ✅ | Component filtering in router.rs |
| **mask_error_details** | ✅ | ✅ | Implemented in builder.rs |
| **check_for_updates** | ✅ | ✅ | Implemented in `fastmcp-cli` (crates.io max_version check; opt-out via `FASTMCP_CHECK_FOR_UPDATES=0`) |

---

## 11. Testing Utilities

| Feature | Python | Rust | Notes |
|---------|--------|------|-------|
| In-process testing | ✅ | ✅ | Via Lab runtime + MemoryTransport |
| Virtual time | ✅ | ✅ | asupersync Lab |
| Deterministic testing | ❌ | ✅ | **Better in Rust** |
| Fault injection | ❌ | 🟡 | asupersync supports it |
| Test context | ✅ | ✅ | `McpContext::for_testing()` |
| **MemoryTransport** | ✅ | ✅ | `memory.rs` - In-process channel transport |

---

## 12. CLI Tooling (All Complete ✅)

| Command | Python | Rust | Notes |
|---------|--------|------|-------|
| **`fastmcp run`** | ✅ | ✅ | `fastmcp-cli` crate |
| **`fastmcp inspect`** | ✅ | ✅ | JSON/text/mcp output formats |
| **`fastmcp install`** | ✅ | ✅ | Claude Desktop, Cursor, Cline targets |
| **`fastmcp dev`** | ✅ | ✅ | Hot reloading with file watching |
| **`fastmcp list`** | ✅ | ✅ | List available servers |
| **`fastmcp test`** | ✅ | ✅ | Test server connectivity |
| **`fastmcp tasks`** | ✅ | ✅ | Task queue management (list, show, cancel, stats) |

---

## 13. Advanced Features

| Feature | Python | Rust | Notes |
|---------|--------|------|-------|
| **Docket (distributed tasks)** | ✅ | 🚧 | Memory backend present; Redis backend gated by later TASKR-01 (no `redis` feature on default FND-01 graph) |
| **EventStore** | ✅ | ✅ | `event_store.rs` - SSE resumability with TTL |
| **Rich content types** | ✅ | ✅ | `Content` supports `audio` and includes helpers: `Content::{text,image_base64,image_bytes,audio_base64,audio_bytes,resource_text,resource_blob_base64,resource_blob_bytes}` |

---

## Summary: Historical gap list (not an MCP 2026-07-28 certificate)

The list below is a historical Phase-5 gap-closure inventory. It does **not** certify aggregate MCP 2026-07-28 support.

### Completed Features (Formerly Listed as Gaps)

1. ✅ **Dynamic enable/disable** - Per-session visibility control (state.rs, context.rs)
2. ✅ **Component metadata** - Tags, icons, versions (all implemented)
3. ✅ **Error masking** - `mask_error_details` setting (builder.rs)
4. ✅ **Server composition** - mount(), as_proxy() (builder.rs, proxy.rs, router.rs)
5. ✅ **CLI commands** - dev, test, tasks (all implemented with full functionality)
6. ✅ **FilesystemProvider** - Built-in filesystem resource provider (providers/filesystem.rs)
7. ✅ **Auto-initialize** - Client auto-initialization (client/builder.rs)
8. ✅ **Cross-component access** - ctx.read_resource(), ctx.call_tool() (context.rs)
9. ✅ **Capabilities access** - ctx.client_capabilities(), ctx.server_capabilities() (context.rs)
10. ✅ **Per-handler timeout** - Handler-level timeout configuration (handler.rs)
11. ✅ **Output schema** - Tool output schema support (macros, handler.rs)
12. ✅ **Tool annotations** - MCP tool annotations (types.rs, handler.rs)
13. ✅ **Strict validation** - strict_input_validation setting (router.rs, builder.rs)
14. ✅ **Duplicate handling** - on_duplicate behavior (builder.rs)

---

## Intentionally Excluded (Per Plan)

1. Pydantic integration → Replaced by serde
2. Python decorators → Replaced by proc macros
3. TestClient (httpx) → Using Lab runtime + MemoryTransport
4. OpenAPI provider → Out of scope
5. TypeAdapter caching → serde handles differently
6. check_for_updates → Removed for FND-01 (no eager crates.io / ureq update path)

---

## Rust-Only Features (Advantages Over Python)

1. **Cancel-correctness** - Cooperative cancellation via checkpoints
2. **4-valued outcomes** - Ok/Err/Cancelled/Panicked
3. **Structured concurrency** - Region-scoped tasks
4. **Two-phase send** - Cancel-safe transport output
5. **Parallel combinators** - join_all, race, quorum, first_ok
6. **Budget system** - Superior to simple timeouts
7. **Statistics collection** - Built-in server stats
8. **Rich console** - Banners, traffic display, logging
9. **Masking** - Critical section protection

---

## Conclusion

Historical Phase-5 snapshots claimed near-complete parity with Python FastMCP v2.14.4. **That is not a current MCP 2026-07-28 support claim.**

**Current FND-01 stance (2026-07-31):**
- Foundation evidence, dependency freeze, and integration assembly are in progress under beads FND-01
- JWT/`jsonwebtoken` and Redis optional features are **removed** from the default graph for FND-01
- OAuth/OIDC/Redis Tasks/Apps/media remain later work packages (AUTH-*, TASKR-01, etc.)
- Aggregate support requires GATE / final attestation packages — not this document

**Honest current strengths (not an aggregate claim):**
- Cancel-correct async (asupersync `Cx`, 4-valued outcomes)
- Core protocol surfaces and transports with ongoing 2026-07-28 modernization
- CLI tooling without eager crates.io update networking
- Rich console and structured concurrency patterns

**Not production-certified for MCP 2026-07-28** until final attestation and GATE packages pass.
