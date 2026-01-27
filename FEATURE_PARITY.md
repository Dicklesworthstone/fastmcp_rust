# FastMCP Rust Feature Parity Report

> **Assessment Date:** 2026-01-27
> **Assessed by:** AzureDeer (claude-opus-4-5-20251101)
> **Prior Assessors:** DustyReef (claude-opus-4-5-20251101)
> **Methodology:** Porting-to-Rust Phase 5 Conformance Analysis (comprehensive Python source comparison)
> **Python FastMCP Version:** 2.14.4

## Executive Summary

This is a comprehensive feature parity assessment comparing the Rust port against Python FastMCP v2.14.4. The analysis was conducted by directly examining the Python source at `/home/ubuntu/.local/pipx/venvs/fastmcp/lib/python3.13/site-packages/fastmcp/` (90+ files totaling ~600+ KB).

**Feature Parity Estimate: ~60-65%** (revised downward after comprehensive source analysis)

The Rust port covers **core MCP protocol functionality well**, but lacks several significant Python FastMCP features:

### Key Strengths (Better Than Python)
- **Cancel-correctness**: Cooperative cancellation via checkpoints and masks
- **4-valued outcomes**: Ok/Err/Cancelled/Panicked (vs Python's 2-valued)
- **Structured concurrency**: All tasks scoped to regions
- **Budget system**: Superior timeout mechanism via asupersync
- **Rich console**: Banners, traffic display, statistics collection
- **Parallel combinators**: join_all, race, quorum, first_ok

### Key Gaps (Not in Rust)
- **Full OAuth 2.0/2.1 Server** (93 KB Python module)
- **OIDC Provider** (18 KB Python module)
- **Tool Transformations** (37 KB Python module for dynamic tool modification)
- **Middleware Ecosystem** (caching, rate limiting implementations)
- **Docket Distributed Task Queue** (Redis/memory backends)
- **CLI Tooling** (fastmcp run/dev/install/inspect commands)
- **EventStore** (SSE resumability with TTL)
- **Elicitation & Roots** (protocol methods)

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
| Request timeout/budget | ✅ | ✅ | Via asupersync Budget (superior) |
| Cancel-correctness | 🟡 | ✅ | **Better in Rust** via asupersync |
| Lifecycle hooks (lifespan) | ✅ | ✅ | `on_startup()` / `on_shutdown()` |
| Ping/health check | ✅ | ✅ | `ping` method handled |
| Statistics collection | ❌ | ✅ | `ServerStats` with snapshots |
| Console/banner rendering | ❌ | ✅ | `fastmcp-console` crate |

### Missing Server Features

| Feature | Python | Rust | Priority | Notes |
|---------|--------|------|----------|-------|
| **HTTP transport** | ✅ | ❌ | Medium | `run_http()` creates ASGI app |
| **Streamable HTTP transport** | ✅ | ❌ | Medium | Stateless HTTP |
| **FastMCPTransport (in-process)** | ✅ | ❌ | Medium | In-memory testing transport |
| **Dynamic enable/disable** | ✅ | ❌ | Medium | No visibility control per-session |
| **Component versioning** | ✅ | ❌ | Low | No version support on components |
| **Tags for filtering** | ✅ | ❌ | Medium | `include_tags`/`exclude_tags` |
| **Icons support** | ✅ | ❌ | Low | Not implemented |
| **Error masking** | ✅ | ❌ | Medium | `mask_error_details` setting |
| **Strict input validation** | ✅ | ❌ | Medium | `strict_input_validation` setting |
| **Duplicate handling** | ✅ | ❌ | Low | `on_duplicate` behavior |
| **as_proxy() method** | ✅ | ❌ | Medium | Create proxy from existing server |
| **mount() composition** | ✅ | ❌ | Medium | Mount tools from another FastMCP |

---

## 2. Decorators / Macros

| Feature | Python | Rust | Notes |
|---------|--------|------|-------|
| `@tool` / `#[tool]` | ✅ | ✅ | Full functionality |
| `@resource` / `#[resource]` | ✅ | ✅ | Full functionality with URI templates |
| `@prompt` / `#[prompt]` | ✅ | ✅ | Full functionality |
| Auto JSON schema | ✅ | ✅ | `#[derive(JsonSchema)]` + inline generation |
| Description from docstrings | ✅ | ✅ | Doc comments → descriptions |
| Default parameter values | ✅ | 🟡 | Via Option<T> |
| name/description override | ✅ | ✅ | Attribute parameters supported |

### Missing Decorator Features

| Feature | Python | Rust | Priority | Notes |
|---------|--------|------|----------|-------|
| **Icons** | ✅ | ❌ | Low | Not supported |
| **Tags** | ✅ | ❌ | Medium | For filtering |
| **Output schema** | ✅ | ❌ | Medium | Tool output schema |
| **Tool annotations** | ✅ | ❌ | Medium | MCP tool annotations |
| **Task configuration** | ✅ | 🟡 | Medium | Background tasks work, but not per-handler config |
| **Timeout per handler** | ✅ | ❌ | Medium | Only server-level |
| **Authorization checks** | ✅ | 🟡 | Medium | Auth exists but not per-handler |

---

## 3. Transport Layer

| Feature | Python | Rust | Notes |
|---------|--------|------|-------|
| **Stdio transport** | ✅ | ✅ | Full NDJSON implementation |
| **SSE transport** | ✅ | ✅ | `SseServerTransport`, `SseClientTransport` |
| **WebSocket transport** | ✅ | ✅ | `WsTransport` with RFC 6455 compliance |
| **Two-phase send** | ❌ | ✅ | Cancel-safe output (Rust-only feature) |
| **Codec with size limits** | ✅ | ✅ | Configurable max message size |

### Missing Transport Features

| Feature | Python | Rust | Priority | Notes |
|---------|--------|------|----------|-------|
| **HTTP transport** | ✅ | ❌ | Medium | Would need HTTP server |
| **Streamable HTTP** | ✅ | ❌ | Medium | Not implemented |
| **FastMCPTransport (in-process)** | ✅ | ❌ | Medium | No in-memory transport |
| **Multiple client transport types** | ✅ | 🟡 | Medium | Only stdio subprocess wired |
| **Transport auth options** | ✅ | 🟡 | Medium | Basic auth exists |

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

### Protocol Methods In Progress

| MCP Method | Python | Rust | Priority | Notes |
|------------|--------|------|----------|-------|
| **Elicitation** | ✅ | 🟡 | **High** | Protocol types + McpContext::elicit_*() implemented (bd-j6n), server wiring blocked on bd-2wm |
| **Roots** | ✅ | 🟡 | Medium | Protocol types implemented (bd-10g), server wiring blocked on bd-2wm |

### Architecture: Server-to-Client Requests

**Status (bd-2wm):** ✅ **RESOLVED** - Bidirectional communication infrastructure implemented!

**Implemented Solution:**
1. ✅ `PendingRequests` - Tracks server-to-client requests with response routing
2. ✅ `RequestSender` - Sends requests through transport with response awaiting
3. ✅ `TransportSamplingSender` - Implements `SamplingSender` trait for `sampling/createMessage`
4. ✅ `TransportElicitationSender` - Implements `ElicitationSender` trait for `elicitation/elicit`
5. ✅ `TransportRootsProvider` - Provides `roots/list` requests
6. ✅ Main loop routes responses to pending requests (no longer ignores them)
7. ✅ `Server` struct has `pending_requests` field for tracking

**Wiring Complete (bd-21v, bd-10g, bd-j6n):**
✅ `RequestSender` passed through handler execution path
✅ `BidirectionalSenders` created based on client capabilities
✅ Sampling/elicitation senders attached to `McpContext` in tool/resource/prompt handlers
✅ `ctx.sample()` and `ctx.elicit()` now work when client supports the capability

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

### Missing Client Features

| Feature | Python | Rust | Priority | Notes |
|---------|--------|------|----------|-------|
| **SamplingHandler** | ✅ | ✅ | Medium | Fully wired via `ctx.sample()` |
| **ElicitationHandler** | ✅ | ✅ | **High** | Fully wired via `ctx.elicit()` |
| **RootsHandler** | ✅ | 🟡 | Medium | `TransportRootsProvider` exists, needs context access |
| **SSE client transport** | ✅ | 🟡 | Medium | Protocol exists, not wired |
| **WebSocket client transport** | ✅ | 🟡 | Medium | Protocol exists, not wired |
| **MCPConfig client creation** | ✅ | ❌ | Medium | Server registry from files |
| **Auto-initialize** | ✅ | ❌ | Low | Always manual initialize |
| **Task client methods** | ✅ | ❌ | Medium | tasks/submit, tasks/list from client |

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

### Missing Context Features

| Feature | Python | Rust | Priority | Notes |
|---------|--------|------|----------|-------|
| **Elicitation from handler** | ✅ | ❌ | **High** | `Context.elicit()` |
| **Roots from handler** | ✅ | ❌ | Medium | `Context.get_roots()` |
| **Logging via context** | ✅ | 🟡 | Medium | Server logs, not handler-level |
| **Resource reading from handler** | ✅ | ❌ | Medium | Not in McpContext |
| **Tool calling from handler** | ✅ | ❌ | Medium | Not in McpContext |
| **MCP capabilities access** | ✅ | ❌ | Low | Not exposed |

### Dependency Injection

| Feature | Python | Rust | Notes |
|---------|--------|------|-------|
| **`Depends()`** | ✅ | ⊘ | Different pattern - explicit context passing |
| **`CurrentContext()`** | ✅ | ✅ | Context passed as first parameter |
| **`CurrentFastMCP()`** | ✅ | ❌ | No server access from handlers |
| **`get_access_token()`** | ✅ | ✅ | Via `ctx.auth()` |
| **`get_http_headers()`** | ✅ | ❌ | HTTP-specific |
| **`get_http_request()`** | ✅ | ❌ | HTTP-specific |
| **`get_docket()`/`get_worker()`** | ✅ | ❌ | No Docket support |

---

## 7. Resource Templates

| Feature | Python | Rust | Notes |
|---------|--------|------|-------|
| Basic template definition | ✅ | ✅ | `ResourceTemplate` type |
| URI parameter matching | ✅ | ✅ | Template matching in macros |
| RFC 6570 templates | ✅ | 🟡 | Basic support, not full RFC |
| Query parameter extraction | ✅ | ❌ | Not implemented |
| Wildcard path support (`{path*}`) | ✅ | ❌ | Not implemented |

---

## 8. Authentication

| Feature | Python | Rust | Notes |
|---------|--------|------|-------|
| AuthProvider base trait | ✅ | ✅ | `AuthProvider` trait |
| Token verification | ✅ | ✅ | `TokenVerifier` trait |
| Static token verifier | ✅ | ✅ | `StaticTokenVerifier` |
| JWT support | ✅ | ✅ | `JwtTokenVerifier` (feature: jwt) |
| Access token handling | ✅ | ✅ | `AuthContext` with token |

### Missing Auth Features

| Feature | Python | Rust | Priority | Notes |
|---------|--------|------|----------|-------|
| **Full OAuth 2.0/2.1 Server** | ✅ | ❌ | **High** | 93 KB Python module (oauth_proxy.py) |
| **OIDC Provider** | ✅ | ❌ | Medium | 18 KB Python module (oidc_proxy.py) |
| **Authorization code flow** | ✅ | ❌ | **High** | Part of OAuth server |
| **Token issuance** | ✅ | ❌ | **High** | JWT issuer (jwt_issuer.py) |
| **Token revocation** | ✅ | ❌ | Medium | OAuth token management |
| **Client registration** | ✅ | ❌ | Medium | Dynamic client registration |
| **Required scopes** | ✅ | ❌ | Medium | No scope validation |
| **Per-handler auth** | ✅ | ❌ | Medium | Only server-level |
| **Redirect validation** | ✅ | ❌ | Medium | OAuth redirect security |

---

## 9. Middleware

| Feature | Python | Rust | Notes |
|---------|--------|------|-------|
| Middleware trait | ✅ | ✅ | `Middleware` trait |
| Request filtering | ✅ | ✅ | `on_request()` |
| Response transformation | ✅ | ✅ | `on_response()` |
| Error handling | ✅ | ✅ | `on_error()` |
| Middleware chain | ✅ | ✅ | Vec<Box<dyn Middleware>> |

### Missing Middleware Types

| Middleware | Python | Rust | Priority | Notes |
|------------|--------|------|----------|-------|
| **ResponseCachingMiddleware** | ✅ | ❌ | Medium | Async key-value backend, LRU eviction |
| **RateLimitingMiddleware** | ✅ | ❌ | Medium | Token bucket implementation |
| **SlidingWindowRateLimiting** | ✅ | ❌ | Medium | Sliding window implementation |
| **Logging middleware** | ✅ | 🟡 | Low | Console has logging |
| **Timing middleware** | ✅ | 🟡 | Low | Stats has timing |
| **ToolInjection middleware** | ✅ | ❌ | Low | Dynamically inject tools |

---

## 10. Providers & Dynamic Components

| Feature | Python | Rust | Notes |
|---------|--------|------|-------|
| **Proxy to remote server** | ✅ | ✅ | `ProxyClient`, `ProxyCatalog` |
| **ProxyToolManager** | ✅ | ✅ | Tool proxying |
| **ProxyResourceManager** | ✅ | ✅ | Resource proxying |
| **ProxyPromptManager** | ✅ | ✅ | Prompt proxying |

### Missing Providers

| Provider | Python | Rust | Priority | Notes |
|----------|--------|------|----------|-------|
| **Tool Transformations** | ✅ | ❌ | Medium | 37 KB Python module (tool_transform.py) |
| **TransformedTool** | ✅ | ❌ | Medium | Dynamic tool modification |
| **ArgTransform** | ✅ | ❌ | Medium | Argument transformation rules |
| **forward()/forward_raw()** | ✅ | ❌ | Medium | Transformation chaining |
| **FilesystemProvider** | ✅ | ❌ | Low | Not implemented |
| **OpenAPIProvider** | ✅ | ⊘ | N/A | Excluded per plan |

---

## 11. Configuration & Settings

| Feature | Python | Rust | Notes |
|---------|--------|------|-------|
| Log level configuration | ✅ | ✅ | Via environment + LoggingConfig |
| Console configuration | ✅ | ✅ | ConsoleConfig |
| Timeout configuration | ✅ | ✅ | Via builder |
| Banner configuration | ✅ | ✅ | BannerStyle enum |
| Traffic verbosity | ✅ | ✅ | TrafficVerbosity enum |
| Environment variables | ✅ | ✅ | FASTMCP_LOG, FASTMCP_NO_BANNER, etc. |

### Missing Configuration

| Config | Python | Rust | Priority | Notes |
|--------|--------|------|----------|-------|
| **Settings class (Pydantic)** | ✅ | ❌ | Medium | Full config management |
| **DocketSettings** | ✅ | ❌ | Medium | Task queue configuration |
| **ExperimentalSettings** | ✅ | ❌ | Low | Feature flags |
| **MCPConfig file support** | ✅ | ❌ | Medium | Server registry from files |
| **include_tags/exclude_tags** | ✅ | ❌ | Medium | Component filtering |
| **HTTP settings** | ✅ | ❌ | Medium | host, port, paths |
| **mask_error_details** | ✅ | ❌ | Medium | Security feature |
| **check_for_updates** | ✅ | ❌ | Low | Version checking |

---

## 12. Testing Utilities

| Feature | Python | Rust | Notes |
|---------|--------|------|-------|
| In-process testing | ✅ | ✅ | Via Lab runtime |
| Virtual time | ✅ | ✅ | asupersync Lab |
| Deterministic testing | ❌ | ✅ | **Better in Rust** |
| Fault injection | ❌ | 🟡 | asupersync supports it |
| Test context | ✅ | ✅ | `McpContext::for_testing()` |

---

## 13. CLI Tooling

| Command | Python | Rust | Priority | Notes |
|---------|--------|------|----------|-------|
| **`fastmcp run`** | ✅ | ❌ | Medium | Run a server |
| **`fastmcp dev`** | ✅ | ❌ | Medium | Development mode |
| **`fastmcp install`** | ✅ | ❌ | Low | Install/configure servers |
| **`fastmcp inspect`** | ✅ | ❌ | Low | Introspect capabilities |
| **`fastmcp list`** | ✅ | ❌ | Low | List available servers |
| **`fastmcp test`** | ✅ | ❌ | Low | Test server connectivity |
| **`fastmcp tasks`** | ✅ | ❌ | Low | Task queue management |

---

## 14. Advanced Features

| Feature | Python | Rust | Priority | Notes |
|---------|--------|------|----------|-------|
| **Docket (distributed tasks)** | ✅ | ❌ | **High** | Redis/memory backends, worker coordination |
| **EventStore** | ✅ | ❌ | Medium | SSE event storage for resumability |
| **LowLevelServer** | ✅ | ❌ | Low | MCP SDK wrapper |
| **MiddlewareServerSession** | ✅ | ❌ | Low | Session with middleware routing |
| **Rich content types** | ✅ | 🟡 | Medium | Audio/File/Image helpers |

---

## Summary of Critical Gaps

### High Priority (Blocking Full Parity)

1. **Elicitation** - User input request protocol (Python has 18 KB module)
2. **Full OAuth 2.0/2.1 Server** - Major Python feature (93 KB oauth_proxy.py)
3. **Docket Integration** - Distributed task queue with Redis backend
4. **Tool Transformations** - Dynamic tool modification (37 KB tool_transform.py)

### Medium Priority

5. **HTTP/Streamable transports** - Enable non-subprocess deployment
6. **Middleware implementations** - Caching, rate limiting
7. **OIDC Provider** - OpenID Connect support (18 KB oidc_proxy.py)
8. **MCPConfig support** - Server registry from config files
9. **Roots protocol** - Filesystem roots listing
10. **In-process transport** - `FastMCPTransport` for unit tests
11. **EventStore** - SSE event storage with TTL

### Lower Priority

12. **CLI tooling** - fastmcp run/dev/install/inspect
13. **Component metadata** - Tags, icons, versions
14. **Full RFC 6570** - Query parameters, wildcards
15. **Server composition** - mount(), as_proxy()

---

## Intentionally Excluded (Per Plan)

1. Pydantic integration → Replaced by serde
2. Python decorators → Replaced by proc macros
3. TestClient (httpx) → Using Lab runtime
4. OpenAPI provider → Out of scope
5. TypeAdapter caching → serde handles differently

---

## Rust-Only Features (Advantages)

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

The FastMCP Rust port provides a **solid foundation** for MCP protocol operations:

**What works well:**
- Core protocol methods (tools, resources, prompts)
- Background tasks (SEP-1686 protocol, in-memory only)
- Three transport types (Stdio, SSE, WebSocket)
- Basic authentication (static tokens + JWT)
- Middleware framework (trait defined, no implementations)
- Proxy support for remote servers
- Cancel-correct async (superior to Python)
- Rich console and statistics
- Sampling protocol (types + context methods)

**What's missing for production parity:**
- Full OAuth 2.0/2.1 authentication server (large Python feature)
- Elicitation protocol for user input
- Distributed task queues (Docket with Redis)
- Middleware implementations (caching, rate limiting)
- CLI tooling for development workflows
- Client transport flexibility (SSE/WS connections)
- Tool transformations for dynamic schemas
- OIDC provider integration

**Estimated completion:** ~60-65%

The port is suitable for:
- Simple MCP servers with tools/resources/prompts
- Applications requiring cancel-correct async
- Systems needing background task execution (in-memory)
- Binary distribution scenarios

For production deployments requiring OAuth, distributed tasks, advanced middleware, or elicitation, significant additional work is needed.

---

## Beads for Gap Implementation

The following high-priority gaps should be tracked as beads:

1. **Elicitation Protocol** - `elicit()` method in McpContext
2. **OAuth 2.0/2.1 Server** - Full authorization code flow
3. **Docket Distributed Tasks** - Redis/memory backend
4. **Tool Transformations** - Dynamic schema modification
5. **Roots Protocol** - Filesystem roots listing
6. **Caching Middleware** - Response caching with async backend
7. **Rate Limiting Middleware** - Token bucket/sliding window
