# FastMCP Rust Historical Feature Inventory and Current Gaps

> **Assessment Date:** 2026-01-28 (historical matrix below; status language corrected 2026-08-01)
> **Assessed by:** VioletFalcon (claude-opus-4-5-20251101)
> **Prior Assessors:** GoldReef, AzureDeer, DustyReef (claude-opus-4-5-20251101)
> **Methodology:** Porting-to-Rust Phase 5 Conformance Analysis (comprehensive source comparison)
> **Python FastMCP Version:** 2.14.4

## FND-01 / MCP 2026-07-28 status (authoritative)

**MCP 2026-07-28 support is under implementation and remains unverified.**  
**Aggregate MCP 2026-07-28 support is not claimed by FND-01.**

Toolchain: pinned `nightly-2026-07-11` / rustc 1.99.0-nightly (`rust-version = "1.99"`).  
The current public `PROTOCOL_VERSION` remains `2024-11-05`. Newer protocol types and method handlers present in the tree do not, by themselves, establish negotiated MCP 2026-07-28 support. Production JWT (`jsonwebtoken`), Docket/Redis, Apps media rendering, and aggregate release-gate claims are **not** FND-01 deliverables.

Release publication remains quarantined. This document supplies neither publication authority nor provider-side evidence that historical workflows, queued runs, and credentials are inert.

### Current qualification snapshot

- On Unix, the primary stdio path now keeps a receive pump active while one
  bounded worker serializes dispatch, so cancellation can be routed during
  handler execution. Non-Unix stdio and custom/SSE/WebSocket entry points
  retain sequential or blocking boundaries; request-owned `Cx` isolation and
  reliable cleanup qualification remain open across the aggregate surface.
- Unix stdio can route sampling, elicitation, and roots responses while its
  dispatch worker is occupied. Non-Unix stdio and custom/SSE/WebSocket paths
  reject or lack equivalent split routing. Public turnkey HTTP is live for
  dual-era request/response; bidirectional lifecycle qualification remains
  incomplete.
- Eligible production cache entries are partitioned by committed authentication
  facts plus opaque session identity and revision. Ambiguous authentication,
  unsafe state views, allocation failure, and state mutation fail closed.
- JSON-RPC credentials are a legacy fallback. Recognized fields are consumed by
  authentication and stripped before extension middleware and handlers. The
  quarantined private HTTP helper carries native `Authorization` metadata
  separately through pre-dispatch admission. Public turnkey HTTP is live;
  transport-boundary admission and challenge behavior remain unqualified.
- Legacy `tasks/list` and `tasks/submit` return `MethodNotFound`. Official
  `tasks/get`, `tasks/update`, and `tasks/cancel` are served by default
  (process-local in-memory store). `ServerBuilder::final_tasks` replaces
  that store; `with_task_manager` still does not install official Tasks.
- OAuth/OIDC public source APIs exist for development, but production security
  and profile conformance remain unverified and quarantined from support claims.
- Explicit client close now returns process/transport cleanup failures. The
  anchored owned-process-group mode used by `fastmcp test` is Unix-only; Drop
  is best effort, and group/session escape, fork-copied descriptors, competing
  reapers, and Windows Job Object support remain unqualified.

## Executive Summary

This is a historical source comparison between the Rust port and Python FastMCP v2.14.4. It was produced before FND-01 freeze discipline; **do not treat it as a current conformance report, release gate, or aggregate-support certificate**.

**Current honest posture:** MCP 2026-07-28 foundation work is in progress under FND-01. The library still advertises `2024-11-05`; later packages own protocol-era parity, Redis Tasks, auth promotion, and media.

### Architectural differentiators (not benchmark or conformance claims)

- **Cancellation surfaces**: Cooperative checkpoints and masks are exposed
- **4-valued outcomes**: Ok/Err/Cancelled/Panicked (vs Python's 2-valued)
- **Context model**: Request work carries an asupersync capability context
- **Budget system**: Deadline, poll, and cost dimensions are exposed through asupersync
- **Rich console**: Banners, traffic display, statistics collection
- **Parallel combinators**: join_all, race, quorum, first_ok

### Landed areas (subject to FND-01 nonpromotion)

- OAuth/OIDC code paths exist in-tree but are **not** aggregate 2026-07-28 certified
- Middleware / HTTP / CLI / transports exist; Redis Docket is **not** a production FND-01 edge
- MCPConfig and memory transport remain useful for development

---

## Feature Comparison Matrix

### Legend

- ✅ **Source present** - A corresponding Rust implementation surface exists; this is not release or conformance verification
- 🟡 **Partial** - Part of the surface exists, or important integration/verification is still missing
- 🚧 **Deferred / unpromoted** - Source may exist, but the feature is outside the current promoted production surface
- ❌ **Missing** - Not implemented
- ⊘ **Excluded** - Intentionally not ported (per plan)

---

## 1. Server Core Features

| Feature | Python | Rust | Notes |
|---------|--------|------|-------|
| Basic server creation | ✅ | ✅ | `Server::new()` |
| Server builder pattern | ✅ | ✅ | `ServerBuilder` with fluent API |
| Name/version/instructions | ✅ | ✅ | All configured via builder |
| Stdio transport | ✅ | ✅ | NDJSON implementation present |
| SSE transport | ✅ | ✅ | `run_sse()` with `SseServerTransport` |
| WebSocket transport | ✅ | ✅ | `run_websocket()` with `WsTransport` and caller-provided reader/writer integration |
| **HTTP transport** | ✅ | 🟡 | Public native HTTP admission and listener paths implement modern MCP 2026-07-28 and isolated exact MCP 2024-11-05 routing; aggregate qualification remains unverified |
| **Streamable HTTP transport** | ✅ | 🟡 | `StreamableHttpTransport` and public modern/legacy HTTP paths exist; aggregate protocol qualification remains unverified |
| Server request timeout/budget | ✅ | 🟡 | Server dispatch uses asupersync `Budget`; request-owned child-context isolation and end-to-end cleanup qualification remain open (FND-04) |
| Cancellation behavior | 🟡 | 🟡 | Unix stdio keeps receiving while a bounded worker dispatches and can route a live cancellation; non-Unix stdio and custom/SSE/WebSocket paths retain sequential/blocking boundaries, and request-owned child `Cx` isolation plus cleanup qualification remain open |
| HTTP multi-client isolation | ✅ | 🟡 | The unsafe shared-Session listener is quarantined and unreachable. Current public HTTP routing separates modern MCP 2026-07-28 admission from exact MCP 2024-11-05 lifecycle handling; aggregate multi-client and request-execution qualification remains unverified |
| Lifecycle hooks (lifespan) | ✅ | ✅ | `on_startup()` / `on_shutdown()` |
| Ping/health check | ✅ | ✅ | `ping` method handled |
| Statistics collection | ❌ | ✅ | `ServerStats` with snapshots |
| Console/banner rendering | ❌ | ✅ | `fastmcp-console` crate |

### Historical server gap-closure inventory

| Feature | Python | Rust | Notes |
|---------|--------|------|-------|
| **Dynamic enable/disable** | ✅ | ✅ | Per-session visibility via state.rs, context.rs; `disable_*`/`enable_*` emit 2024 `list_changed` and publish the same events to modern `subscriptions/listen` |
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
| `@tool` / `#[tool]` | ✅ | 🟡 | Macro implementation exists; modern request-owned dispatch and exact-2024 session dispatch both drive `call_async_in_request`. The session path still `block_on`s that request-owned future |
| `@resource` / `#[resource]` | ✅ | 🟡 | Macro plus RFC 6570 reversible templates exist; lossy prefix/explode forms are refused rather than guessed |
| `@prompt` / `#[prompt]` | ✅ | 🟡 | Macro implementation exists; modern request-owned dispatch and exact-2024 session dispatch both drive `get_async_in_request`. The session path still `block_on`s that request-owned future |
| Auto JSON schema | ✅ | ✅ | `#[derive(JsonSchema)]` + inline generation |
| Description from docstrings | ✅ | ✅ | Doc comments → descriptions |
| Default parameter values | ✅ | ✅ | Implemented via `defaults(...)` on `#[tool]`/`#[prompt]` (e.g. `#[tool(defaults(foo = 123, bar = \"baz\"))]`) |
| name/description override | ✅ | ✅ | Attribute parameters supported |

### Historical macro gap-closure inventory

| Feature | Python | Rust | Notes |
|---------|--------|------|-------|
| **Icons** | ✅ | ✅ | `#[tool]`, `#[resource]`, and `#[prompt]` accept `icon = "..."` (URL or data URI) |
| **Tags** | ✅ | ✅ | Supported for filtering in router.rs |
| **Output schema** | ✅ | ✅ | Tool output schema in macros, handler.rs |
| **Tool annotations** | ✅ | ✅ | MCP annotations in types.rs, handler.rs |
| **Timeout per handler** | ✅ | 🟡 | Handler timeout surface exists; enforcement and panic-boundary hardening are active work |

---

## 3. Transport Layer

| Feature | Python | Rust | Notes |
|---------|--------|------|-------|
| **Stdio transport** | ✅ | ✅ | NDJSON implementation present |
| **SSE transport** | ✅ | 🟡 | Low-level `SseServerTransport`/`SseClientTransport` types exist; public `Client::sse` / `Client::sse_with_cx` connect an exact-2024 HTTP+SSE client without probing modern HTTP. Auto still uses SSE only as a fallback |
| **WebSocket transport** | ✅ | 🟡 | `WsTransport` framing plus `ClientBuilder::connect_websocket_with_cx` exist behind `websocket-experimental`; aggregate lifecycle qualification remains open |
| **HTTP transport** | ✅ | 🟡 | Public `Server::run_http*` binds a dual-era listener; `Client::http` is the high-level client. Aggregate admission/challenge and bidirectional qualification remain open |
| **Streamable HTTP** | ✅ | 🟡 | `StreamableHttpTransport` and public modern/legacy HTTP paths exist; aggregate protocol qualification remains unverified |
| **MemoryTransport (in-process)** | ✅ | ✅ | `memory.rs` for testing |
| **Two-phase send** | ❌ | ✅ | `TwoPhaseTransport` reserve/commit support exists for stdio |
| **Codec with size limits** | ✅ | ✅ | Configurable max message size |
| **EventStore** | ✅ | ✅ | `event_store.rs` with TTL-based retention |

---

## 4. Protocol Methods

| MCP Method | Python | Rust | Notes |
|------------|--------|------|-------|
| `initialize` | ✅ | 🟡 | Negotiation code exists, but the public version constant still advertises `2024-11-05` |
| `initialized` | ✅ | ✅ | Notification handled |
| `ping` | ✅ | ✅ | Health check. Public stdio, HTTP, and WebSocket `ping` / `ping_with_cancellation` work on modern sessions; the server answers `{}` without requiring ping in the official 2026 client-request union |
| `tools/list` | ✅ | ✅ | With cursor pagination |
| `tools/call` | ✅ | ✅ | With progress token support |
| `resources/list` | ✅ | ✅ | With cursor pagination |
| `resources/read` | ✅ | ✅ | With progress token support. Final `#[resource]` handlers that author a complete result keep their `ttlMs` / `cacheScope`; the router default (one hour, private) applies only to the legacy-bridge projection |
| `resources/templates/list` | ✅ | 🟡 | Listing plus RFC 6570 reversible matching exist; lossy prefix/explode templates are refused rather than guessed |
| `resources/subscribe` | ✅ | ✅ | Session dispatch serves subscribe for registered URIs; registering a resource or template advertises `resources.subscribe` on initialize |
| `resources/unsubscribe` | ✅ | ✅ | Protocol support |
| `prompts/list` | ✅ | ✅ | With cursor pagination |
| `prompts/get` | ✅ | ✅ | With argument support |
| `completion/complete` | ✅ | ✅ | Session and stateless dispatch serve a registered handler; both `completion_handler()` and `legacy_completion_handler()` advertise `capabilities.completions` on initialize. Final discover still requires a modern provider |
| `logging/setLevel` | ✅ | ✅ | Exact-2024 sends `logging/setLevel`. Modern stdio, HTTP, and WebSocket `set_log_level` store `io.modelcontextprotocol/logLevel` on later requests and never send the removed final RPC |
| `notifications/cancelled` | ✅ | 🟡 | Stdio can receive and route the notification while its dispatch worker runs. Custom/SSE/WebSocket loops remain sequential; end-to-end interruption, request ownership, and reliable `awaitCleanup` remain unverified |
| `notifications/progress` | ✅ | ✅ | Progress token support |
| `notifications/tools/list_changed` | ✅ | ✅ | Emitted on session catalog mutation and published to `subscriptions/listen` |
| `notifications/resources/list_changed` | ✅ | ✅ | Emitted on session catalog mutation and published to `subscriptions/listen` |
| `notifications/prompts/list_changed` | ✅ | ✅ | Emitted on session catalog mutation and published to `subscriptions/listen` |
| `notifications/resources/updated` | ✅ | ✅ | `ctx.notify_resource_updated` plus matching listen filters |
| `subscriptions/listen` | ✅ | 🟡 | Owned HTTP incremental listener (`start_subscriptions_listener` keeps the same `HttpClient` free to issue requests), stdio incremental catalog/Tasks listeners on the same `Client`, `ProxyClient::start_catalog_listener` for stdio and modern HTTP upstreams, WebSocket incremental catalog listen (`WebSocketClient::open_subscriptions_listener`), detached sequential pumps, and `Server::open_subscription_listen` for in-process callers. `dispatch_stateless` rejects listen instead of returning `MethodNotFound`. Collect-to-terminal stdio/WebSocket and the borrowing HTTP listener remain available |

### Background Tasks (Docket/SEP-1686; network surface quarantined)

| MCP Method | Python | Rust | Notes |
|------------|--------|------|-------|
| `tasks/list` | ✅ | 🚧 | Legacy method; RPC returns `MethodNotFound` |
| `tasks/get` | ✅ | 🟡 | Served by default (in-memory store); `final_tasks` replaces the store |
| `tasks/update` | ✅ | 🟡 | Served by default (in-memory store); `final_tasks` replaces the store |
| `tasks/submit` | ✅ | 🚧 | Legacy method; RPC returns `MethodNotFound` |
| `tasks/cancel` | ✅ | 🟡 | Served by default (in-memory store); `final_tasks` replaces the store |

The historical `TaskManager` source remains test-only for implementation
archaeology. Production builds expose neither a manager constructor/builder
edge nor a network capability while TASK-01/TASK-02 remain open.

### Sampling Protocol

| MCP Method | Python | Rust | Notes |
|------------|--------|------|-------|
| `sampling/createMessage` | ✅ | 🟡 | Protocol/context/send/response routing exists on the stdio receive-pump path. Modern WebSocket answers typed `sampling/createMessage` reverse requests when a modern handler is installed; exact-2024 reverse handlers stay rejected on ModernOnly. Modern HTTP answers those reverse requests on a request-owned SSE body by POSTing the JSON-RPC response. Modern server sampling is MRTR `input_required`, not reverse JSON-RPC; live `bind_http` JSON `tools/call` returns that result for `ctx.final_sampling` (write-half EOF is ordinary H1 completion and does not cancel). Public `HttpClient::call_tool` / `WebSocketClient::call_tool` fulfill installed reverse handlers locally and retry with `inputResponses`. `modern::HttpClient::{call_tool,read_resource,get_prompt}_result` (plus HTTP cancellation and the matching WebSocket methods) keep a live `input_required` branch when no handlers are installed. Facade `read_resource` / `get_prompt` now use the same installed-handler follow path as `call_tool`. Stateless HTTP retries stay session-bound, so a second POST cannot resume the first POST's `requestState`. Custom/stdio lifecycle qualification remains open |

### Server-to-Client Protocols

| MCP Method | Python | Rust | Notes |
|------------|--------|------|-------|
| **Elicitation** | ✅ | 🟡 | `ctx.elicit_form()`, `ctx.elicit_url()`, and `ctx.elicit_with_request()` plus stdio response routing exist. Modern WebSocket and modern HTTP answer typed `elicitation/create` reverse requests when a modern handler is installed. Modern server elicitation is MRTR `input_required` (`ctx.final_elicitation_form` / `final_elicitation_url`); live `bind_http` `read_resource_result` / `get_prompt_result` return the form branch, and live `bind_http` `call_tool_result` returns the URL branch when the client advertises `elicitation.url` and rejects when it does not. Public `call_tool` / `read_resource` / `get_prompt` fulfill an installed elicitation handler locally. Custom-loop qualification remains open |
| **Roots** | ✅ | 🟡 | `TransportRootsProvider` exists. Modern WebSocket and modern HTTP answer typed `roots/list` reverse requests when a modern handler is installed. Modern server roots are MRTR `input_required` via `ctx.final_roots` (capability-gated, same pattern as `ctx.final_sampling`); live `bind_http` `call_tool_result` returns that branch when the client advertises `roots` and rejects `InvalidRequest` when it does not. Public `call_tool` fulfills an installed roots handler locally. Custom-loop qualification remains open |

### Bidirectional Communication Infrastructure

The following bidirectional building blocks exist in source. This inventory does not certify end-to-end behavior for MCP 2026-07-28. On Unix, the primary stdio path keeps a receive pump active while its dispatch worker runs. Non-Unix stdio and custom/SSE/WebSocket paths retain sequential/blocking boundaries and do not provide equivalent response routing. Public turnkey HTTP is live for dual-era request/response; request-owned bidirectional lifecycle qualification remains incomplete.

1. ✅ `PendingRequests` - Tracks server-to-client requests with response routing
2. ✅ `RequestSender` - Sends requests through transport with response awaiting
3. ✅ `TransportSamplingSender` - Implements `SamplingSender` trait
4. ✅ `TransportElicitationSender` - Implements `ElicitationSender` trait
5. ✅ `TransportRootsProvider` - Provides `roots/list` requests
6. 🟡 The Unix primary-stdio receive pump continues routing responses during handler dispatch. Modern WebSocket and modern HTTP answer typed reverse `sampling/createMessage` requests when a modern handler is installed, and public `call_tool` also follows modern server `input_required` by invoking those same handlers locally. Non-Unix stdio and custom loops do not yet provide equivalent split routing
7. ✅ `Server` struct has `pending_requests` field for tracking

---

## 5. Client Features

| Feature | Python | Rust | Notes |
|---------|--------|------|-------|
| Subprocess spawning | ✅ | 🟡 | Stdio subprocess integration exists. Explicit `Client::close` returns cleanup failures; opt-in anchored group ownership is Unix-only and is not portable process-tree containment |
| Client transport integration | ✅ | 🟡 | Public `Client` covers subprocess stdio, HTTP (`Client::http` with typed `list_tools`/`call_tool`/`read_resource`/`get_prompt` plus cancellation variants), and exact-2024 SSE (`Client::sse`); `modern::Client` stdio `call_tool_result` / `read_resource_result` / `get_prompt_result` keep a live `input_required` branch the same way the HTTP/WebSocket result verbs do. A Modern2026 stdio session stamps the same `_meta` protocol version and client capabilities on `start_multiplexed_request` and on cloned `StdioRequestExecutor::execute` that the typed verbs already send. Public stdio `read_resource` / `get_prompt` follow installed modern reverse handlers the same way `call_tool` does. Public stdio `modern::Client` exposes typed `list_*`/`call_tool`/`read_resource`/`get_prompt`/`complete` `*_with_cancellation` verbs. WebSocket (`websocket-experimental`) and modern HTTP have incremental catalog listen plus the same typed verbs and the same cancellation methods so the same connection can keep issuing or cancel ordinary requests |
| Tool invocation | ✅ | ✅ | `call_tool()` |
| Resource reading | ✅ | ✅ | `read_resource()` |
| Prompt fetching | ✅ | ✅ | `get_prompt()` |
| Progress callbacks | ✅ | ✅ | `call_tool_with_progress()` |
| List operations | ✅ | ✅ | Tool/resource/prompt list methods exist |
| Request cancellation | ✅ | 🟡 | `cancel_request()` emits the notification and the Unix stdio receive pump can route it during dispatch. Public HTTP `request_final_core_with_cancellation` plus typed `list_*`/`call_tool`/`read_resource`/`get_prompt`/`complete` `*_with_cancellation` verbs honor a caller-owned cancellation domain for ordinary core requests. Public stdio `modern::Client` exposes the same typed verbs and rejects before send when the domain is already cancelled. WebSocket typed verbs reject before send and retire after send; a blocked ingress wait still belongs to the connection `Cx` until the next frame. Non-Unix stdio and custom/SSE loops retain sequential/blocking boundaries; reliable interruption, cleanup waiting, and request-owned isolation remain open |
| Log level setting | ✅ | ✅ | Exact-2024 `set_log_level()` sends `logging/setLevel`. Modern stdio, HTTP, and WebSocket `set_log_level` stamp `io.modelcontextprotocol/logLevel` on later requests. Modern HTTP `take_server_notifications` then retains the request-scoped `notifications/message` frames that floor admits |
| Response ID validation | ✅ | ✅ | Validates response IDs |
| Client request idle/absolute deadlines | ✅ | 🟡 | Ordinary requests use monotonic `Instant` deadlines that begin after send commit (30-second idle and 120-second non-resettable absolute defaults). Unix subprocess stdout receives, including silent and partial frames, are bounded; generic blocking `recv`, non-Unix child pipes, synchronous writes, and best-effort Drop prevent a portable end-to-end wall-clock guarantee (FND-04) |
| **MCPConfig client creation** | ✅ | ✅ | `mcp_config.rs` with JSON/TOML parsing |
| **SamplingHandler** | ✅ | 🟡 | Context and transport sender paths exist with stdio response routing. Modern HTTP/WebSocket `call_tool` and public stdio `call_tool` / `read_resource` / `get_prompt` fulfill an installed sampling handler against server `input_required`. Custom transport routing and lifecycle qualification remain open |
| **ElicitationHandler** | ✅ | 🟡 | Context and transport sender paths exist with stdio response routing. Modern HTTP/WebSocket `call_tool` and public stdio `call_tool` / `read_resource` / `get_prompt` fulfill an installed elicitation handler against server `input_required`. Custom transport routing and lifecycle qualification remain open |

### Historical client gap-closure inventory

| Feature | Python | Rust | Notes |
|---------|--------|------|-------|
| **Auto-initialize** | ✅ | ✅ | Implemented in client builder.rs |
| **Task client methods** | ✅ | 🟡 | Client methods exist; the default server serves official `tasks/get`, `tasks/update`, and `tasks/cancel` |

---

## 6. Context / Dependency Injection

| Feature | Python | Rust | Notes |
|---------|--------|------|-------|
| Context object | ✅ | ✅ | `McpContext` |
| Progress reporting | ✅ | ✅ | `report_progress()`, `report_progress_with_total()`. Modern HTTP, WebSocket, and stdio `call_tool_with_progress_marker` stamp `progressToken`; `take_progress_notifications` retains the request-scoped frames |
| Handler log notifications | ✅ | ✅ | `ctx.debug()`/`info()`/`notice()`/`warning()`/`error()` emit `notifications/message` after `logging/setLevel`. Exact-2024 uses the session `setLevel` floor. Modern HTTP and stdio apply the request `io.modelcontextprotocol/logLevel` floor to `ctx.info` and friends; public `take_server_notifications` drains the frames |
| Resource update notifications | ✅ | ✅ | `ctx.notify_resource_updated(uri)` emits 2024 `resources/updated` to session subscribers and publishes the same event to matching `subscriptions/listen` streams |
| Checkpoint for cancellation | ✅ | ✅ | `checkpoint()` |
| Budget access | ✅ | ✅ | `budget()` |
| Request ID access | ✅ | ✅ | `request_id()` |
| Region ID access | ❌ | ✅ | `region_id()` (Rust-only) |
| Task ID access | ❌ | ✅ | `task_id()` (Rust-only) |
| Masked critical sections | ❌ | ✅ | `masked()` (Rust-only) |
| Session state | ✅ | ✅ | `get_state()` / `set_state()` / `remove_state()` |
| Auth context | ✅ | ✅ | `auth()` / `set_auth()` |
| Parallel combinators | ❌ | ✅ | `join_all()`, `race()`, `quorum()`, `first_ok()` |
| Sampling from handler | ✅ | 🟡 | Exact-2024 `ctx.sample()` / `ctx.sample_with_request()` use reverse JSON-RPC on stdio. Modern handlers use `ctx.final_sampling` → `input_required`; public HTTP/WebSocket `call_tool` and public stdio `call_tool` / `read_resource` / `get_prompt` fulfill installed sampling handlers locally. Custom-loop qualification remains open |
| **Elicitation from handler** | ✅ | 🟡 | Exact-2024 `ctx.elicit_form()` / `ctx.elicit_url()` use reverse JSON-RPC on stdio. Modern handlers use `ctx.final_elicitation_form` / `final_elicitation_url` → `input_required`; public HTTP/WebSocket `call_tool` and public stdio `call_tool` / `read_resource` / `get_prompt` fulfill installed elicitation handlers locally. Custom-loop qualification remains open |
| Roots from handler | ✅ | 🟡 | Exact-2024 `ctx.list_roots()` uses reverse JSON-RPC on stdio. Modern handlers use `ctx.final_roots` → `input_required`; live `bind_http` `call_tool_result` returns that branch. Public `call_tool` / `read_resource` / `get_prompt` fulfill an installed roots handler locally on HTTP, WebSocket, and stdio. Custom-loop qualification remains open |

### Historical context gap-closure inventory

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
| Token verification | ✅ | 🟡 | `TokenVerifier` extension surface exists and provider failures are sanitized at the framework boundary; aggregate transport/auth promotion remains open |
| Static token verifier | ✅ | 🟡 | Configuration now rejects empty, malformed, duplicate, or unbounded tokens/schemes, but raw `AccessToken` custody and the public transport admission profile remain unpromoted |
| JWT support | ✅ | 🚧 | No public production JWT verifier is promoted by FND-01; `jsonwebtoken` and the old `jwt` feature are absent from the default graph |
| Access token handling | ✅ | 🟡 | Native authorization uses strict scheme/token68 grammar; malformed, multiple, or mixed credential locations fail closed and provider error payloads are sanitized. JSON-RPC fields remain a stripped legacy fallback, raw `AccessToken` strings remain a custody promotion gate, and public transport admission/challenges are unqualified |
| **OAuth 2.0/2.1 server code** | ✅ | 🚧 | Public `oauth.rs` building blocks are present for development; production security/profile conformance remains unverified and quarantined from support claims |
| **OIDC Provider** | ✅ | 🚧 | Public `oidc.rs` building blocks are present, with ID-token issuance fail-closed; the overall production security/profile remains unverified and unpromoted |
| **Authorization code flow** | ✅ | 🚧 | Authorization-code and PKCE code paths exist; AUTH promotion gates remain |
| **Token issuance** | ✅ | 🚧 | Access/refresh-token code paths exist; AUTH promotion gates remain |
| **Token revocation** | ✅ | 🚧 | Revocation code exists; RFC/profile conformance is not currently certified |
| **Client registration** | ✅ | 🚧 | Registration code exists; AUTH promotion gates remain |
| **Scope validation** | ✅ | 🚧 | Scope-validation code exists; AUTH promotion gates remain |
| **Redirect validation** | ✅ | 🚧 | Redirect checks exist; AUTH promotion gates remain |

---

## 8. Middleware

| Feature | Python | Rust | Notes |
|---------|--------|------|-------|
| Middleware trait | ✅ | ✅ | `Middleware` trait |
| Request filtering | ✅ | ✅ | `on_request()` |
| Response transformation | ✅ | ✅ | `on_response()` |
| Error handling | ✅ | ✅ | `on_error()` |
| Middleware chain | ✅ | ✅ | Vec<Box<dyn Middleware>> |
| **ResponseCachingMiddleware** | ✅ | 🟡 | Eligible entries use committed-auth plus opaque session/revision partitions and fail closed on ambiguous admission or state mutation; broader production and conformance qualification remains incomplete |
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

### Historical provider gap-closure inventory

| Provider | Python | Rust | Notes |
|----------|--------|------|-------|
| **FilesystemProvider** | ✅ | 🟡 | Public `build()` constructs a handler on Linux/macOS and routes I/O through the caller-owned blocking pool; other targets remain fail-closed |
| **OpenAPIProvider** | ✅ | ⊘ | Excluded per plan (intentional) |

---

## 10. Configuration & Settings

| Feature | Python | Rust | Notes |
|---------|--------|------|-------|
| Log level configuration | ✅ | ✅ | Via environment + LoggingConfig |
| Console configuration | ✅ | ✅ | ConsoleConfig |
| Timeout configuration | ✅ | 🟡 | Builder surface exists; end-to-end enforcement gates remain |
| Banner configuration | ✅ | ✅ | BannerStyle enum |
| Traffic verbosity | ✅ | ✅ | TrafficVerbosity enum |
| Environment variables | ✅ | ✅ | FASTMCP_LOG, FASTMCP_NO_BANNER, etc. |
| **DocketSettings** | ✅ | 🚧 | Docket source is retained but not re-exported as an FND-01 production surface; Redis belongs to TASKR-01 |
| **MCPConfig file support** | ✅ | ✅ | `mcp_config.rs` - JSON/TOML parsing |

### Historical configuration gap-closure inventory

| Config | Python | Rust | Notes |
|--------|--------|------|-------|
| **include_tags/exclude_tags** | ✅ | ✅ | Component filtering in router.rs |
| **mask_error_details** | ✅ | ✅ | Implemented in builder.rs |
| **check_for_updates** | ✅ | ⊘ | Removed for FND-01; the CLI has no eager crates.io/`ureq` update client |

---

## 11. Testing Utilities

| Feature | Python | Rust | Notes |
|---------|--------|------|-------|
| In-process testing | ✅ | ✅ | Via Lab runtime + MemoryTransport |
| Virtual time | ✅ | ✅ | asupersync Lab |
| Deterministic testing | ❌ | ✅ | asupersync Lab support is available |
| Fault injection | ❌ | 🟡 | asupersync supports it |
| Test context | ✅ | ✅ | Construct with `McpContext::new(Cx::for_testing(), request_id)`; there is no `McpContext::for_testing()` constructor |
| **MemoryTransport** | ✅ | ✅ | `memory.rs` - In-process channel transport |

---

## 12. CLI Tooling (implementation inventory)

| Command | Python | Rust | Notes |
|---------|--------|------|-------|
| **`fastmcp run`** | ✅ | ✅ | `fastmcp-cli` crate |
| **`fastmcp inspect`** | ✅ | ✅ | JSON/text/mcp output formats |
| **`fastmcp install`** | ✅ | ✅ | Claude Desktop, Cursor, Cline targets |
| **`fastmcp dev`** | ✅ | 🟡 | Unix file-watching/restart paths use bounded owned-group cleanup plus an in-group watchdog tied to an owner-held control pipe, covering CLI owner death and child-handle drop. Descriptor copies made by a host fork and group/session escape remain outside the boundary; non-Unix fails closed |
| **`fastmcp list`** | ✅ | ✅ | List available servers |
| **`fastmcp test`** | ✅ | 🟡 | Tests connectivity using anchored Unix process-group ownership; successful connections report explicit final cleanup separately, and initialization-cleanup failures remain visible; non-Unix fails before spawn until a Job Object/equivalent ownership path exists |
| **`fastmcp tasks`** | ✅ | 🟡 | CLI command paths exist; official `tasks/get`/`update`/`cancel` are served by default, while legacy `list`/`submit` stay `MethodNotFound` |

---

## 13. Advanced Features

| Feature | Python | Rust | Notes |
|---------|--------|------|-------|
| **Docket (distributed tasks)** | ✅ | 🚧 | Historical/test-only task-manager source remains; official in-process Tasks RPC is served by default, while Redis Docket is gated by TASKR-01 and absent from the default FND-01 graph |
| **EventStore** | ✅ | ✅ | `event_store.rs` - SSE resumability with TTL |
| **Rich content types** | ✅ | ✅ | `Content` supports `audio` and includes helpers: `Content::{text,image_base64,image_bytes,audio_base64,audio_bytes,resource_text,resource_blob_base64,resource_blob_bytes}` |

---

## Summary: Historical gap list (not an MCP 2026-07-28 certificate)

The list below is a historical Phase-5 gap-closure inventory. It does **not** certify aggregate MCP 2026-07-28 support.

### Source areas formerly listed as gaps

1. ✅ **Dynamic enable/disable** - Per-session visibility plus mutation-only `list_changed` notifications
2. ✅ **Component metadata** - Tags, icons, and version fields are present
3. ✅ **Error masking** - `mask_error_details` setting (builder.rs)
4. ✅ **Server composition** - mount(), as_proxy() (builder.rs, proxy.rs, router.rs)
5. ✅ **CLI commands** - dev, test, and tasks command paths are present; this is not an end-to-end verification claim
6. 🟡 **FilesystemProvider** - Public construction works on Linux/macOS; other targets remain fail-closed
7. ✅ **Auto-initialize** - Client auto-initialization (client/builder.rs)
8. ✅ **Cross-component access** - ctx.read_resource(), ctx.call_tool() (context.rs)
9. ✅ **Capabilities access** - ctx.client_capabilities(), ctx.server_capabilities() (context.rs)
10. 🟡 **Per-handler timeout** - Handler-level configuration exists and both modern and exact-2024 session dispatch now enforce it through `run_handler_in_request`; panic-boundary hardening remains active
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

## Rust-specific design surfaces

1. **Cancellation surfaces** - Cooperative checkpoints and masks
2. **4-valued outcomes** - Ok/Err/Cancelled/Panicked
3. **Context model** - `McpContext` wraps asupersync `Cx`; combinators poll caller-owned futures
4. **Two-phase send** - Reserve/commit support on stdio transports
5. **Parallel combinators** - join_all, race, quorum, first_ok
6. **Budget system** - Deadline, poll, and cost dimensions
7. **Statistics collection** - Built-in server stats
8. **Rich console** - Banners, traffic display, logging
9. **Masking** - Closure-scoped cancellation-checkpoint masking

---

## Conclusion

Historical Phase-5 snapshots claimed near-complete parity with Python FastMCP v2.14.4. **That is not a current MCP 2026-07-28 support claim.**

**Current FND-01 stance (2026-08-02):**

- Foundation evidence, dependency freeze, and integration assembly are in progress under beads FND-01
- JWT/`jsonwebtoken` and Redis are absent from the current workspace dependency graph
- OAuth/OIDC production promotion, Redis Tasks, Apps, and media remain later work packages (AUTH-*, TASKR-01, etc.)
- Aggregate support requires GATE / final attestation packages — not this document

**Current implementation surfaces (not an aggregate claim):**

- asupersync `Cx`, cooperative checkpoints, budgets, and 4-valued outcomes
- Core protocol surfaces and transports with ongoing 2026-07-28 modernization
- CLI tooling without eager crates.io update networking
- Rich console and asupersync context/combinator patterns

**Current architecture gaps:**

- The private, unwired legacy HTTP dispatch helper deliberately serializes through
  one shared session mutex; advisory read-only metadata is not a concurrency
  boundary. It remains quarantined and is not the public HTTP routing path
- Public HTTP routing separates modern MCP 2026-07-28 admission from exact
  MCP 2024-11-05 lifecycle handling. Aggregate multi-client isolation and
  request-owned execution qualification remain unverified
- Unix stdio keeps a receive pump active while a bounded worker serializes
  dispatch, allowing cancellation routing during handler execution. Non-Unix
  stdio and custom/SSE/WebSocket loops retain sequential/blocking boundaries,
  and request-owned interruption plus reliable `awaitCleanup` are not yet
  qualified
- Unix primary-stdio output is serialized and bounded for ordinary pipes and
  sockets; write/notification failure is terminal, and shutdown hooks require
  worker quiescence. Regular files/devices, non-Unix output, and handlers that
  ignore cancellation retain documented bounds or process-exit limitations
- Low-level HTTP reads checkpoint and retry interruption, but a generic
  synchronous `Read` already blocked in the kernel is not preemptible
- `Client::close` is proof-bearing and retryable while the client remains
  owned; Drop is best effort. Anchored group ownership does not contain
  group/session escape, fork-copied descriptors, or hostile/global reapers
- Unix stdio can route sampling, elicitation, and roots responses while its
  worker is occupied. Non-Unix stdio and custom/SSE/WebSocket paths lack
  equivalent split routing. Public turnkey HTTP is live; end-to-end
  bidirectional lifecycle qualification remains open
- Request work still needs an independently owned child `Cx`; cancellation is
  not a sibling-isolated guarantee until that boundary exists
- Eligible response-cache entries use committed-auth plus opaque
  session/revision partitions; ambiguous admission and state mutation bypass
  cache storage or lookup
- Recognized JSON-RPC credentials are stripped before extension middleware and
  handlers, but they remain a legacy fallback. The quarantined private HTTP
  helper carries native authorization separately; public transport-boundary
  admission and challenge behavior remain unqualified
- Legacy `tasks/list` and `tasks/submit` return `MethodNotFound`; official `tasks/get`, `tasks/update`, and `tasks/cancel` are served by default
- OAuth/OIDC source APIs remain public for development, but their production
  security/profile conformance is unverified and quarantined from support claims
- The public client supports subprocess stdio and HTTP (`Client::http` with
  typed list/call/read/get verbs). WebSocket is behind
  `websocket-experimental` and now has incremental catalog listen plus the
  same typed verbs; SSE is used as the exact-2024 HTTP fallback and remains a
  lower-level transport type

**Not production-certified for MCP 2026-07-28** until final attestation and GATE packages pass.
