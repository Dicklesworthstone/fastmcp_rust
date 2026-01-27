# FastMCP Rust Feature Parity Report

> **Assessment Date:** 2026-01-27
> **Assessed by:** DustyReef (claude-opus-4-5-20251101)
> **Methodology:** Porting-to-Rust Phase 5 Conformance Analysis (comprehensive code exploration)

## Executive Summary

The FastMCP Rust port implements **significantly more** than previously assessed. This updated analysis reflects actual code exploration rather than estimates. The Rust version covers the **core MCP protocol** with excellent cancel-correctness via asupersync, plus several advanced features.

**Revised Feature Parity: ~70-75%** of Python FastMCP functionality

### Key Strengths (Better Than Python)
- **Cancel-correctness**: Cooperative cancellation via checkpoints and masks
- **4-valued outcomes**: Ok/Err/Cancelled/Panicked (vs Python's 2-valued)
- **Structured concurrency**: All tasks scoped to regions
- **Background tasks**: Full Docket/SEP-1686 protocol support
- **Transport layer**: Complete Stdio, SSE, and WebSocket implementations

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
| **Middleware pipeline** | ✅ | ✅ | N/A | Basic middleware trait implemented |
| **Authentication providers** | ✅ | ✅ | N/A | Token/JWT providers implemented |
| **Dynamic enable/disable** | ✅ | ❌ | Medium | No visibility control per-session |
| **Component versioning** | ✅ | ❌ | Low | No version support on components |
| **Tags for filtering** | ✅ | ❌ | Low | No tag system |
| **Icons support** | ✅ | ❌ | Low | Not implemented |
| **Website URL** | ✅ | ❌ | Low | Not in server config |
| **Duplicate handling** | ✅ | ❌ | Low | No on_duplicate behavior |
| **Error masking** | ✅ | ❌ | Medium | Not implemented |

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
| **Tags** | ✅ | ❌ | Low | Not supported |
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
| **HTTP transport** | ✅ | ❌ | Low | Would need HTTP server |
| **Streamable HTTP** | ✅ | ❌ | Low | Not implemented |
| **FastMCPTransport (in-process)** | ✅ | ❌ | Medium | No in-memory transport |
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

### Missing Protocol Methods

| MCP Method | Python | Rust | Priority | Notes |
|------------|--------|------|----------|-------|
| **`sampling/create`** | ✅ | ❌ | High | LLM sampling support |
| **Elicitation** | ✅ | ❌ | Medium | User input requests |
| **Roots** | ✅ | ❌ | Medium | Filesystem roots |

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
| **SamplingHandler** | ✅ | ❌ | High | No sampling |
| **ElicitationHandler** | ✅ | ❌ | Medium | No elicitation |
| **RootsHandler** | ✅ | ❌ | Medium | No roots |
| **SSE/WS client transports** | ✅ | 🟡 | Medium | Protocol exists, not wired |
| **Multiple transport types** | ✅ | ❌ | Medium | Only stdio subprocess |

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

### Missing Context Features

| Feature | Python | Rust | Priority | Notes |
|---------|--------|------|----------|-------|
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

---

## 7. Resource Templates

| Feature | Python | Rust | Notes |
|---------|--------|------|-------|
| Basic template definition | ✅ | ✅ | `ResourceTemplate` type |
| URI parameter matching | ✅ | ✅ | Template matching in macros |
| RFC 6570 templates | ✅ | 🟡 | Basic support, not full RFC |
| Query parameter extraction | ✅ | ❌ | Not implemented |

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
| **OAuth proxy** | ✅ | ❌ | Medium | Not implemented |
| **OIDC proxy** | ✅ | ❌ | Medium | Not implemented |
| **Required scopes** | ✅ | ❌ | Medium | No scope validation |
| **Per-handler auth** | ✅ | ❌ | Medium | Only server-level |

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

| Middleware | Python | Rust | Priority |
|------------|--------|------|----------|
| Caching middleware | ✅ | ❌ | Medium |
| Rate limiting middleware | ✅ | ❌ | Medium |
| Logging middleware | ✅ | 🟡 | Low (console has logging) |
| Timing middleware | ✅ | 🟡 | Low (stats has timing) |

---

## 10. Providers & Dynamic Components

| Feature | Python | Rust | Notes |
|---------|--------|------|-------|
| **Proxy to remote server** | ✅ | ✅ | `ProxyClient`, `ProxyCatalog` |
| **FilesystemProvider** | ✅ | ❌ | Not implemented |
| **OpenAPIProvider** | ✅ | ⊘ | Excluded per plan |

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

## Summary of Critical Gaps

### High Priority (Needed for Feature Parity)

1. **Sampling/Completions** - No `sampling/create` support for LLM integration
2. **Elicitation** - No user input request support
3. **Roots** - No filesystem roots support

### Medium Priority

4. **Dynamic visibility control** - No per-session component enable/disable
5. **Per-handler configuration** - Timeout, auth, task config per handler
6. **Resource/tool calling from handlers** - Context lacks these methods
7. **In-memory transport** - For testing without subprocess

### Lower Priority

8. **Component metadata** - Tags, icons, versions
9. **Full RFC 6570** - Query parameters in resource templates
10. **Additional providers** - Filesystem, OpenAPI

---

## Intentionally Excluded (Per Plan)

1. Pydantic integration → Replaced by serde
2. Python decorators → Replaced by proc macros
3. TestClient (httpx) → Using Lab runtime
4. CLI tools (fastmcp dev) → Different Rust paradigm
5. OpenAPI provider → Out of scope

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

---

## Conclusion

The FastMCP Rust port is **significantly more complete** than the prior assessment suggested. It successfully implements:

- **All core MCP protocol methods** including pagination
- **Background tasks** (Docket/SEP-1686) - fully functional
- **Three transport types** - Stdio, SSE, WebSocket
- **Authentication framework** - Token and JWT support
- **Middleware system** - Request/response/error hooks
- **Proxy support** - Can proxy to remote MCP servers
- **Session state** - Key-value storage per session
- **Cancel-correct async** - Superior to Python

The port is suitable for:
- Production MCP servers with tools/resources/prompts
- Applications requiring cancel-correct async
- Systems needing background task execution
- Binary distribution scenarios

The main gaps are:
- Sampling/elicitation/roots protocol methods
- Dynamic per-session visibility control
- Per-handler configuration (timeout, auth)

The project is approximately **70-75% feature complete** compared to Python FastMCP, with several areas where Rust implementation is **superior** (cancel-correctness, structured concurrency, 4-valued outcomes).
