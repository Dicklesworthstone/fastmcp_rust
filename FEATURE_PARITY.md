# FastMCP Rust Feature Parity Report

> **Assessment Date:** 2026-01-25
> **Assessed by:** BoldGorge (claude-opus-4-5-20251101)
> **Methodology:** Porting-to-Rust Phase 5 Conformance Analysis

## Executive Summary

The FastMCP Rust port implements the **core MCP protocol functionality** but is **NOT a complete port** of the Python FastMCP library. The Rust version focuses on the fundamental MCP server/client implementation with asupersync integration, while omitting many advanced features present in the Python version.

**Estimated Feature Parity: ~35-40%** of Python FastMCP functionality

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
| Server builder pattern | ✅ | ✅ | `ServerBuilder` |
| Name/version/instructions | ✅ | ✅ | Configured at build |
| Stdio transport | ✅ | ✅ | Full NDJSON support |
| Request timeout/budget | ✅ | ✅ | Via asupersync Budget |
| Cancel-correctness | 🟡 | ✅ | Better in Rust via asupersync |

### Missing Server Features

| Feature | Python | Rust | Notes |
|---------|--------|------|-------|
| **Middleware pipeline** | ✅ | ❌ | No middleware system |
| **Lifecycle hooks (lifespan)** | ✅ | ❌ | No lifespan management |
| **Authentication providers** | ✅ | ❌ | No auth system |
| **Dynamic enable/disable** | ✅ | ❌ | No visibility control |
| **Component versioning** | ✅ | ❌ | No version support |
| **Tags for filtering** | ✅ | ❌ | No tag system |
| **Icons support** | ✅ | ❌ | Not implemented |
| **Website URL** | ✅ | ❌ | Not in server config |
| **Custom HTTP routes** | ✅ | ❌ | No HTTP server |
| **Duplicate handling** | ✅ | ❌ | No on_duplicate behavior |
| **Error masking** | ✅ | ❌ | Not implemented |

---

## 2. Decorators / Macros

| Feature | Python | Rust | Notes |
|---------|--------|------|-------|
| `@tool` / `#[tool]` | ✅ | ✅ | Basic functionality |
| `@resource` / `#[resource]` | ✅ | ✅ | Basic functionality |
| `@prompt` / `#[prompt]` | ✅ | ✅ | Basic functionality |
| Auto JSON schema | ✅ | ✅ | `#[derive(JsonSchema)]` |
| Description from docstrings | ✅ | ✅ | Doc comments work |
| Default parameter values | ✅ | 🟡 | Limited support |

### Missing Decorator Features

| Feature | Python | Rust | Notes |
|---------|--------|------|-------|
| **name/version/title** | ✅ | 🟡 | Only name supported |
| **Icons** | ✅ | ❌ | Not supported |
| **Tags** | ✅ | ❌ | Not supported |
| **Output schema** | ✅ | ❌ | Not supported |
| **Tool annotations** | ✅ | ❌ | Not supported |
| **Task configuration** | ✅ | ❌ | No background tasks |
| **Timeout per handler** | ✅ | ❌ | Only server-level |
| **Authorization checks** | ✅ | ❌ | No auth system |
| **exclude_args** | ✅ | ⊘ | Deprecated in Python |

---

## 3. Transport Layer

| Feature | Python | Rust | Notes |
|---------|--------|------|-------|
| **Stdio transport** | ✅ | ✅ | Full implementation |
| **SSE transport** | ✅ | 🟡 | Module exists, ~700 lines, not integrated |
| **WebSocket transport** | ✅ | 🟡 | Module exists, ~700 lines, not integrated |
| **HTTP transport** | ✅ | ❌ | No HTTP server |
| **Streamable HTTP** | ✅ | ❌ | Not implemented |

### Missing Transport Features

| Feature | Python | Rust | Notes |
|---------|--------|------|-------|
| **Custom client transports** | ✅ | ❌ | Only stdio subprocess |
| **UvStdioTransport** | ✅ | ❌ | Pattern available but not structured |
| **NpxStdioTransport** | ✅ | ❌ | Pattern available but not structured |
| **FastMCPTransport (in-process)** | ✅ | ❌ | Not implemented |
| **Transport auth options** | ✅ | ❌ | No auth headers/OAuth |
| **SSE read timeout config** | ✅ | ❌ | Not configurable |

---

## 4. Protocol Methods

| MCP Method | Python | Rust | Notes |
|------------|--------|------|-------|
| `initialize` | ✅ | ✅ | Full handshake |
| `tools/list` | ✅ | ✅ | Implemented |
| `tools/call` | ✅ | ✅ | With progress support |
| `resources/list` | ✅ | ✅ | Implemented |
| `resources/read` | ✅ | ✅ | With progress support |
| `resources/templates/list` | ✅ | ✅ | Implemented |
| `prompts/list` | ✅ | ✅ | Implemented |
| `prompts/get` | ✅ | ✅ | With progress support |

### Missing Protocol Methods

| MCP Method | Python | Rust | Notes |
|------------|--------|------|-------|
| **`tasks/list`** | ✅ | ❌ | No background tasks |
| **`tasks/get`** | ✅ | ❌ | No background tasks |
| **`tasks/get_payload`** | ✅ | ❌ | No background tasks |
| **`tasks/cancel`** | ✅ | ❌ | No background tasks |
| **`sampling/create`** | ✅ | ❌ | No sampling support |
| **Elicitation** | ✅ | ❌ | No user input requests |
| **Roots** | ✅ | ❌ | No filesystem roots |

---

## 5. Client Features

| Feature | Python | Rust | Notes |
|---------|--------|------|-------|
| Subprocess spawning | ✅ | ✅ | Via `Command` |
| Tool invocation | ✅ | ✅ | `call_tool()` |
| Resource reading | ✅ | ✅ | `read_resource()` |
| Prompt fetching | ✅ | ✅ | `get_prompt()` |
| Progress callbacks | ✅ | ✅ | `call_tool_with_progress()` |
| List operations | ✅ | ✅ | All list methods |

### Missing Client Features

| Feature | Python | Rust | Notes |
|---------|--------|------|-------|
| **Reentrant async context manager** | ✅ | ❌ | No reference counting |
| **SamplingHandler** | ✅ | ❌ | No sampling |
| **LogHandler** | ✅ | ❌ | No log handling |
| **MessageHandler** | ✅ | ❌ | No message handling |
| **ElicitationHandler** | ✅ | ❌ | No elicitation |
| **RootsHandler** | ✅ | ❌ | No roots |
| **TaskNotificationHandler** | ✅ | ❌ | No tasks |
| **run_middleware option** | ✅ | ❌ | No middleware |
| **Transport abstraction** | ✅ | ❌ | Only stdio hardcoded |

---

## 6. Context / Dependency Injection

| Feature | Python | Rust | Notes |
|---------|--------|------|-------|
| Context object | ✅ | ✅ | `McpContext` |
| Progress reporting | ✅ | ✅ | `report_progress()` |
| Checkpoint for cancellation | ✅ | ✅ | `checkpoint()` |
| Budget access | ✅ | ✅ | `budget()` |

### Missing Context Features

| Feature | Python | Rust | Notes |
|---------|--------|------|-------|
| **Logging via context** | ✅ | 🟡 | Methods exist but not wired to client |
| **Session state (get/set)** | ✅ | ❌ | No session state |
| **Resource reading from handler** | ✅ | ❌ | Not in McpContext |
| **Tool calling from handler** | ✅ | ❌ | Not in McpContext |
| **MCP capabilities access** | ✅ | ❌ | Not exposed |
| **Request ID access** | ✅ | ✅ | Available |
| **Client ID** | ✅ | ❌ | Not exposed |

### Missing Dependency Injection

| Feature | Python | Rust | Notes |
|---------|--------|------|-------|
| **`Depends()`** | ✅ | ❌ | No DI system |
| **`CurrentContext()`** | ✅ | ⊘ | N/A - context is passed explicitly |
| **`CurrentFastMCP()`** | ✅ | ❌ | No server access from handlers |
| **`CurrentDocket()`** | ✅ | ❌ | No tasks/docket |
| **`AccessToken`** | ✅ | ❌ | No auth |
| **HTTP headers access** | ✅ | ❌ | No HTTP |
| **HTTP request access** | ✅ | ❌ | No HTTP |

---

## 7. Resource Templates

| Feature | Python | Rust | Notes |
|---------|--------|------|-------|
| Basic template definition | ✅ | 🟡 | Templates can be registered |
| URI parameter matching | ✅ | ❌ | No URI matcher implementation |
| RFC 6570 templates | ✅ | ❌ | Not implemented |
| Query parameter extraction | ✅ | ❌ | Not implemented |
| Dynamic resource creation | ✅ | ❌ | Not implemented |

---

## 8. Advanced Features

| Feature | Python | Rust | Notes |
|---------|--------|------|-------|
| **Middleware** | ✅ | ❌ | Not implemented |
| **Providers** | ✅ | ❌ | Not implemented |
| **Transforms** | ✅ | ❌ | Not implemented |
| **Proxy/Composition** | ✅ | ❌ | Not implemented |
| **OpenAPI integration** | ✅ | ⊘ | Excluded per plan |
| **FastAPI integration** | ✅ | ⊘ | Excluded per plan |
| **Filesystem provider** | ✅ | ❌ | Not implemented |

---

## 9. Middleware (Completely Missing)

The Python FastMCP has a comprehensive middleware system:

| Middleware | Status |
|------------|--------|
| Authorization middleware | ❌ |
| Caching middleware | ❌ |
| Error handling middleware | ❌ |
| Logging middleware | ❌ |
| Ping middleware | ❌ |
| Rate limiting middleware | ❌ |
| Timing middleware | ❌ |
| Tool injection middleware | ❌ |
| Base middleware hooks | ❌ |

---

## 10. Authentication (Completely Missing)

| Feature | Status |
|---------|--------|
| AuthProvider base class | ❌ |
| Access token handling | ❌ |
| Token verification | ❌ |
| JWT support | ❌ |
| OAuth proxy | ❌ |
| OIDC proxy | ❌ |
| Custom routes for auth | ❌ |
| Required scopes | ❌ |

---

## 11. Background Tasks / Docket (Completely Missing)

| Feature | Status |
|---------|--------|
| Task protocol methods | ❌ |
| TaskConfig | ❌ |
| Task status notifications | ❌ |
| Long-running operations | ❌ |
| Task cancellation | ❌ |
| Progress tracking per task | ❌ |

---

## 12. Settings / Configuration

| Feature | Python | Rust | Notes |
|---------|--------|------|-------|
| Log level configuration | ✅ | ✅ | Via environment |
| Console configuration | ✅ | ✅ | ConsoleConfig |
| Timeout configuration | ✅ | ✅ | Via builder |

### Missing Configuration

| Feature | Status | Notes |
|---------|--------|-------|
| Rich logging toggle | ❌ | |
| Rich tracebacks | ❌ | |
| Deprecation warnings | ❌ | |
| JSON depth limits | ❌ | |
| Docket settings | ❌ | |
| MCPConfig file format | ❌ | |
| Stateless HTTP mode | ❌ | |

---

## 13. Testing Utilities

| Feature | Python | Rust | Notes |
|---------|--------|------|-------|
| In-process testing | ✅ | ✅ | Via Lab runtime |
| Virtual time | ✅ | ✅ | asupersync Lab |
| Deterministic testing | ❌ | ✅ | Better in Rust |
| Fault injection | ❌ | 🟡 | asupersync supports it |

### Missing Testing Features

| Feature | Status |
|---------|--------|
| `run_server_async()` | ❌ |
| `run_server_in_process()` | ❌ |
| `temporary_settings()` | ❌ |
| TestClient (httpx equivalent) | ⊘ |

---

## 14. Contrib / Extensions (All Missing)

| Extension | Status |
|-----------|--------|
| Bulk tool caller | ❌ |
| Component manager | ❌ |
| MCP mixin | ❌ |

---

## Summary of Gaps

### Critical Missing Features (High Impact)

1. **Middleware System** - No request/response interceptors
2. **Authentication** - No auth providers, JWT, OAuth
3. **Background Tasks** - No Docket/SEP-1686 support
4. **Resource Templates** - URI matching not implemented
5. **Proxy/Composition** - Cannot proxy to other MCP servers
6. **SSE/WebSocket Integration** - Code exists but not wired up

### Moderate Missing Features

7. **Dependency Injection** - No Depends() system
8. **Session State** - No get_state/set_state
9. **Lifecycle Hooks** - No lifespan management
10. **Sampling/Completions** - No LLM sampling support
11. **Dynamic Enable/Disable** - No visibility control
12. **Component Versioning** - No version support

### Lower Priority Missing Features

13. **Tags/Icons** - Cosmetic metadata
14. **Custom HTTP routes** - Would need HTTP server
15. **OpenAPI integration** - Excluded per plan
16. **Contrib modules** - Utility extensions

---

## Intentionally Excluded (Per Plan)

The following were explicitly excluded from the port:

1. Pydantic integration → Replaced by serde
2. Python decorators → Replaced by proc macros
3. TestClient (httpx) → Using Lab runtime
4. CLI tools (fastmcp dev) → Different Rust paradigm
5. Auth providers → Out of scope for initial port
6. Image handling → Can add later

---

## Recommendations

### To Achieve Basic Feature Parity (~60%)

1. Implement URI template matching for resources
2. Wire up SSE transport
3. Add basic middleware hooks
4. Implement session state

### To Achieve Good Feature Parity (~80%)

5. Add authentication provider system
6. Implement background task support
7. Add proxy/composition capability
8. Implement sampling support

### To Achieve Full Feature Parity (~100%)

9. All middleware types
10. Full dependency injection
11. Lifecycle hooks
12. All contrib modules
13. MCPConfig file format

---

## Conclusion

The FastMCP Rust port successfully implements the **core MCP protocol** with excellent cancel-correctness via asupersync. However, it represents only about **35-40% of the Python FastMCP feature set**.

The port is suitable for:
- Simple MCP servers with basic tools/resources/prompts
- Applications requiring cancel-correct async
- Scenarios where binary distribution is important

The port is NOT suitable for:
- Production systems requiring authentication
- Systems needing middleware pipelines
- Multi-server composition scenarios
- Background task workflows

The project correctly states it's in "early development" and the PLAN document shows Phase 6 (Polish) as complete for the **initial port scope**, not the full Python feature set.
