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
| Name/version/instructions | ✅ | ✅ | All configured via builder. Live `bind_http` `server_discovery().instructions()` retains the configured string; a peer without instructions stays bare. Live exact-2024 HTTP `legacy_2024::HttpClient::instructions()` retains the same initialize string; a peer without instructions stays bare. Live stdio modern discovery and exact-2024 initialize retain the shipped echo instructions; `FASTMCP_NO_INSTRUCTIONS=1` keeps that peer bare. Public `ServerBuilder` / `modern::ServerBuilder` also accept modern-only `title` / `description` / `website_url` / `icons`; live `bind_http`, live public `bind_websocket`, and live shipped-echo stdio `server_discovery().implementation()` retain those extras on `_meta` `io.modelcontextprotocol/serverInfo`; a peer without extras (`FASTMCP_NO_IDENTITY=1` on stdio) stays name/version-only (`implementation() == None`) while still advertising `server_info()`. Public `ClientBuilder` / `modern::ClientBuilder` accept the same modern-only extras; live `bind_http`, live public `bind_websocket`, and live shipped-echo stdio `tools/call` attach them onto `McpContext::client_implementation()` (`title=Client Title`); a name/version-only client stays `title=none`. Live as_proxy HTTP, WebSocket, and stdio-upstream HTTP gateways forward those inbound extras to the upstream handler the same way. Exact-2024 initialize `clientInfo` name/version is attached the same way on live `bind_http`, live `bind_websocket`, and live shipped-echo stdio (`title=none`); changing only the client name changes the handler-visible identity |
| Stdio transport | ✅ | ✅ | NDJSON implementation present |
| SSE transport | ✅ | ✅ | `run_sse()` with `SseServerTransport` |
| WebSocket transport | ✅ | ✅ | `run_websocket()` with `WsTransport` and caller-provided reader/writer integration |
| **HTTP transport** | ✅ | 🟡 | Public native HTTP admission and listener paths implement modern MCP 2026-07-28 and isolated exact MCP 2024-11-05 routing. Live `bind_http` JSON-only `Accept: application/json` composes `ctx.call_tool` + `ctx.read_resource` the same way the SSE client does. Live exact-2024 HTTP/SSE polls request-owned handler futures on the connection `Cx` instead of `block_on`. Aggregate qualification remains unverified |
| **Streamable HTTP transport** | ✅ | 🟡 | `StreamableHttpTransport` and public modern/legacy HTTP paths exist; aggregate protocol qualification remains unverified |
| Server request timeout/budget | ✅ | 🟡 | Server dispatch uses asupersync `Budget`; request-owned child-context isolation and end-to-end cleanup qualification remain open (FND-04) |
| Cancellation behavior | 🟡 | 🟡 | Unix stdio keeps receiving while a bounded worker dispatches and can route a live cancellation. Live exact-2024 HTTP+SSE `notifications/cancelled` of an in-flight `tools/call` stops the request-owned wait handler, suppresses that request's JSON-RPC result on the live SSE body (2024-11-05 contract), and still admits a peer `tools/call`. Live exact-2024 WebSocket `call_tool_with_cancellation` of an in-flight wait tool emits `notifications/cancelled`, the handler observes the request cancellation and does not publish `waited`, and a peer socket still admits `tools/call`. Live public modern `bind_websocket` `call_tool_with_cancellation` of an in-flight wait tool retires as request-cancelled without publishing `waited`, the handler observes the request cancellation, and a peer socket still admits `tools/call`. Non-Unix stdio and custom loops retain sequential/blocking boundaries, and request-owned child `Cx` isolation plus cleanup qualification remain open |
| HTTP multi-client isolation | ✅ | 🟡 | The unsafe shared-Session listener is quarantined and unreachable. Live `bind_http` two independent ModernOnly clients each invoke the same tool with distinct arguments and both handler results are retained. Live public `bind_websocket` two independent ModernOnly sockets do the same (`tool:alpha` / `tool:beta`) without mixing results. Live exact-2024 HTTP+SSE two independent `legacy_2024::HttpClient` sessions do the same (`tool:alpha` / `tool:beta`) without mixing results. Live exact-2024 WebSocket two independent sockets do the same without mixing results. Aggregate request-execution qualification remains unverified |
| Lifecycle hooks (lifespan) | ✅ | ✅ | `on_startup()` / `on_shutdown()`. Live `bind_http` public facade hooks run once: startup before traffic, shutdown on cooperative drain; a peer without hooks stays unhooked. Live exact-2024 HTTP+SSE `LegacyOnly` `bind_http` runs the same public hooks once; a peer without hooks stays unhooked. Live `bind_websocket` runs `on_startup` before the first admitted `ping` and `on_shutdown` on cooperative drain after the listener `Cx` is cancelled; a peer without hooks stays unhooked. Live exact-2024 `bind_websocket` keeps the same cooperative startup/shutdown split |
| Ping/health check | ✅ | ✅ | `ping` method handled. Live `bind_http` answers `ping` without invoking a tools/call handler, then admits a later `tools/call` |
| Statistics collection | ❌ | ✅ | `ServerStats` with snapshots |
| Console/banner rendering | ❌ | ✅ | `fastmcp-console` crate |

### Historical server gap-closure inventory

| Feature | Python | Rust | Notes |
|---------|--------|------|-------|
| **Dynamic enable/disable** | ✅ | ✅ | Per-session visibility via state.rs, context.rs; `disable_*`/`enable_*` emit 2024 `list_changed` and publish the same events to modern `subscriptions/listen`. Live `bind_http` incremental listen retains handler `disable_tool` / `disable_resource` / `disable_prompt` publication and same-request `enable_tool` after `disable_tool`; anonymous HTTP POSTs get a request-local `SessionState` so that mutation can fire without inventing `Mcp-Session-Id`. Live shipped-echo stdio `hide_catalog` refuses a later `info://server` read and `greeting` get on the same session; `show_catalog` restores both. Live exact-2024 stdio keeps the same hide/refuse/show restore split. Live exact-2024 stdio `hide_echo` refuses a later `echo` call, still admits `add`, and `show_echo` restores `echo`. Live modern stdio keeps the same hide/refuse/show restore split |
| **Component versioning** | ✅ | ✅ | Version fields on Tool, Resource, Prompt types |
| **Tags for filtering** | ✅ | ✅ | `include_tags`/`exclude_tags` in router.rs. Live shipped-echo stdio `list_tools_with_params` `includeTags=["demo"]` retains `echo` and omits `add`; changing only that filter to `math` retains `add` and omits `echo`; `excludeTags=["demo"]` omits only `echo`; an unfiltered list keeps both. Live exact-2024 stdio keeps the same include/exclude split and retains the `demo` tag on `echo`. Live public modern `bind_http` and live public `bind_websocket` `list_tools_with_params` `includeTags=["cursor"]` retain the cursor-tagged tools and omit `public-http-e2e-cursor-other`; changing only that filter to `other` retains the other-tagged tool and omits the cursor tools; `excludeTags=["cursor"]` omits only the cursor tools; an unfiltered list keeps both groups. Live shipped-echo stdio `list_resources_with_params` / `list_prompts_with_params` / `list_resource_templates_with_params` keep the same include/exclude split on `info://server` (`server`) vs `info://leak` (`secret`), `greeting` (`onboarding`) vs `compose_greeting` (`compose`), and `note://{name}` (`notes`) vs `memo://{name}` (`memos`). Live exact-2024 stdio keeps those resource/prompt/template splits and retains the `server` / `onboarding` / `notes` tags. Live public modern `bind_http` and live public modern/exact-2024 `bind_websocket` `list_resources_with_params` / `list_prompts_with_params` / `list_resource_templates_with_params` (exact-2024 WebSocket uses the existing `list_*_page` verbs plus `list_resource_templates_page`) keep the same include/exclude split on the cursor-tagged catalog entries versus the untagged snapshot/prompt and the other-tagged template; an uncancelled modern HTTP `list_tools_with_params_and_cancellation` / `list_resources_with_params_and_cancellation` / `list_prompts_with_params_and_cancellation` / `list_resource_templates_with_params_and_cancellation` still sends `includeTags`, and a pre-cancelled domain rejects those tagged lists locally. Live public modern `bind_websocket` keeps the same catalog cancellation+includeTags split. Live shipped-echo stdio `modern::Client` keeps the same uncancelled includeTags / pre-send reject split on resources, prompts, and templates |
| **Icons support** | ✅ | ✅ | Icon metadata in types.rs, handler.rs. Live `bind_http` and live public `bind_websocket` `tools/list` retain `final_icons` and `final_title` on the advertised tool; a near-identical peer without those hooks stays untitled and iconless. Live `bind_http` and live public `bind_websocket` `resources/list` and `prompts/list` retain the same `final_icons` / `final_title` split on a matching resource and prompt; the near-identical peers stay untitled and iconless. Live shipped-echo stdio `info://server` / `greeting` retain their authored icons on ModernOnly `resources/list` / `prompts/list` and on exact-2024 `icon.src`; `info://leak` / `compose_greeting` stay iconless Live exact-2024 HTTP+SSE `tools/list` retains version, tags, and `readOnlyHint`/`idempotentHint` annotations on the same tool; the near-identical peer stays bare. Live exact-2024 WebSocket keeps the same version/tags/annotation split |
| **Error masking** | ✅ | ✅ | `mask_error_details` in builder.rs. Live `bind_http` `mask_error_details(true)` replaces a resource `ToolExecutionError` secret with `Internal server error`; changing only that flag to `false` keeps the secret. Live exact-2024 HTTP+SSE does the same through `legacy_2024::HttpClient::read_resource`. Live exact-2024 WebSocket and live public modern `bind_websocket` keep the same mask/unmask split. Live shipped-echo stdio `FASTMCP_MASK_ERROR_DETAILS=1` replaces `info://leak` `secret-db-dsn` with `Internal server error`; omitting that flag keeps the secret. Live exact-2024 stdio keeps the same mask/unmask split |
| **Strict input validation** | ✅ | ✅ | `strict_input_validation` in router.rs. Live `bind_http` with the flag on refuses a `tools/call` that adds only an unknown property and still admits the declared arguments; changing only that flag to `false` admits the same extra property. Live public `bind_websocket` keeps the same on/off split. Live exact-2024 HTTP+SSE honors the same flag through `legacy_2024::HttpClient`. Live exact-2024 WebSocket refuses the extra property as `InvalidParams` (`additional property not allowed: extra`) when the flag is on and admits it when the flag is off. Live shipped-echo stdio `FASTMCP_STRICT_INPUT=1` refuses `echo` with only an extra property and still admits declared arguments; omitting that flag admits the extra property. Live exact-2024 stdio keeps the same on/off split. Modern final dispatch now honors the flag the same way legacy dispatch already did |
| **Duplicate handling** | ✅ | ✅ | `on_duplicate` in builder.rs. Live `bind_http` `DuplicateBehavior::Error` keeps the first `tools/call` handler (`tool:alpha`); changing only that flag to `Replace` installs the second handler (`replaced:alpha`). Live exact-2024 HTTP+SSE retains the same Error/Replace split through `legacy_2024::HttpClient`. Live exact-2024 WebSocket and live public modern `bind_websocket` keep the same Error/Replace split. Live shipped-echo stdio `FASTMCP_REPLACE_ECHO=1` installs the second `echo` handler (`replaced:alpha`) on ModernOnly and LegacyOnly; omitting that flag keeps the first handler |
| **as_proxy() method** | ✅ | ✅ | Implemented in builder.rs, proxy.rs. Live `bind_http` `proxy_typed` lists the upstream catalog and forwards `tools/call`, `prompts/get`, `resources/read`, and `completion/complete`. Live `bind_http` `as_proxy_typed("ext", …)` prefixes tools/prompts as `ext/...`, keeps exact-final resource URIs and RFC 6570 templates unprefixed, and forwards `tools/call`, `prompts/get`, `resources/read` (including a matched template URI and a live FilesystemProvider file URI), and `completion/complete`. A near-identical unmatched template path stays `InvalidParams` before the upstream handler. Prefixed `as_proxy_typed` installs the same route-bound official Tasks relay as `proxy_typed` and binds that relay onto prefixed final tools so a gateway `tools/call` can create. Live official Tasks through that relay: create via `ext/<tool>` on live `bind_http`, live `bind_websocket`, and live `as_proxy("ext", stdio Client)` (`call_tool_outcome` returns the Task branch; changing only the unprefixed name is refused). Live `call_tool_outcome_with_progress_marker` through the HTTP, WebSocket, and stdio-upstream HTTP as_proxy gateways still returns that same Task branch (a progress token does not require an SSE body or a second POST on HTTP), `tasks/get` of that gateway-created id and of an upstream-created Task, `tasks/update` of its `input_required` snapshot (a near-identical wrong-kind roots payload is refused and leaves the Task in place), and `tasks/cancel` of the resumed Task. Live as_proxy forwards inbound modern `ClientBuilder` Implementation extras (`title=Caller Title`) onto the upstream handler-visible `McpContext::client_implementation()` through `bind_http` `as_proxy_typed`, live public `bind_websocket` `as_proxy_typed`, and `as_proxy("ext", stdio Client)`; a name/version-only inbound client stays `title=none`, and changing only the unprefixed tool name is refused. Live as_proxy forwards inbound modern `set_log_level` (`io.modelcontextprotocol/logLevel`) onto the upstream request so handler `ctx.info` is admitted: live `bind_http` `as_proxy_typed` `ext/public-http-e2e-log` and live `as_proxy("ext", stdio Client)` `ext/echo` retain `notifications/message` after `set_log_level(Info)`; raising only the floor to Emergency keeps that info silent; changing only the unprefixed tool name is refused. Ordinary public `call_tool` advertises the negotiated official Tasks extension so those prefixed as_proxy tools are not HTTP-400 missing-capability refused. Live public `watch_final_task` through that same `as_proxy_typed` HTTP gateway acknowledges the upstream-created id, retains `Cancelled` after `tasks/cancel`, and later `tasks/get` on the same gateway session still returns that cancelled snapshot. A near-identical missing id stays an error for `tasks/get` and `tasks/cancel`. Live `as_proxy("ext", stdio Client)` against the shipped echo server binds HTTP, prefixes tools/prompts as `ext/echo` and `ext/greeting`, forwards `tools/call`, `prompts/get`, `completion/complete` of `ext/greeting` (rewritten to upstream `greeting`), and `resources/read` of unprefixed `info://server`, and refuses the unprefixed tool/prompt/completion names. Live `ext/hide_echo` forwards the session-local disable: the gateway snapshot still lists `ext/echo`, a later `ext/echo` is a `Method not found` tool error, and `ext/add` still returns `5`. Live `ext/show_echo` restores that same prefixed echo tool. Live `ext/hide_catalog` keeps the gateway snapshot, leaves a warmed HTTP client's cached `info://server` read in place, refuses a later uncached `info://server` read and `ext/greeting` get, and live `ext/show_catalog` restores a later uncached read and the prefixed greeting get. Live official Tasks on that same stdio client: `tasks/get` of its `input_required` snapshot, `tasks/update` with matching roots, and `tasks/cancel` of the resumed Task; a near-identical missing id stays an error. Live `watch_final_task` through that stdio as_proxy HTTP gateway acknowledges the echo-created id, retains `Cancelled` after `tasks/cancel`, and later `tasks/get` on the same gateway session still returns that cancelled snapshot. Live `ProxyClient::start_catalog_listener` against a modern `bind_http` upstream retains `notifications/tools/list_changed` after a forwarded hide tool. `as_proxy_typed` keeps the live ModernHttp binding. Live exact-2024 HTTP+SSE `as_proxy_typed("child", …)` against a live LegacyOnly upstream prefixes tools, prompts, and resource keys (`child/...`) through `legacy_2024::HttpClient` and refuses the unprefixed upstream tool; those prefixed legacy resource keys register exact-2024-only so they are not projected into the modern catalog |
| **mount() composition** | ✅ | ✅ | Implemented in builder.rs, router.rs. Public Auto/modern facades `mount()` prefix tools/prompts and keep exact resource URIs so they stay on the modern catalog. Live `bind_http` `mount(child, Some("child"))` lists `child/...` tools/prompts and reads the original resource URI. Live `mount()` of a FilesystemProvider child keeps `file:///{prefix}/{+path}` exact, expands a matching file URI, and refuses an unmatched prefix before the child handler. Live exact-2024 HTTP+SSE `LegacyOnly` `mount(child, Some("child"))` prefixes tools, prompts, and resource keys (`child/...`) through `legacy_2024::HttpClient` and refuses the unprefixed child tool name. Live exact-2024 HTTP+SSE `as_proxy_typed("child", …)` against a live LegacyOnly upstream now does the same prefix split (`child/...` tools/prompts/resources) and refuses the unprefixed upstream tool; prefixed legacy resource keys stay exact-2024-only so they are not projected into the modern catalog. `mount_tools` / `mount_resources` / `mount_prompts` remain available |

---

## 2. Decorators / Macros

| Feature | Python | Rust | Notes |
|---------|--------|------|-------|
| `@tool` / `#[tool]` | ✅ | 🟡 | Macro implementation exists; modern request-owned dispatch and exact-2024 session dispatch both drive `call_async_in_request`. Async `#[tool]` now generates `call_final_async` that promotes `call_async`, so modern `tools/call` reaches the async body instead of the sync `call` rejection. Live `bind_http` a generated async `#[tool]` composes `ctx.call_tool` + `ctx.read_resource`. Live exact-2024 HTTP/SSE polls that request-owned future on the connection `Cx` instead of `block_on`. Live shipped-echo stdio polls the same request-owned future on the pump/request `Cx` for `compose_echo` on both ModernOnly and LegacyOnly |
| `@resource` / `#[resource]` | ✅ | 🟡 | Macro plus RFC 6570 reversible templates exist; lossy prefix/explode forms are refused rather than guessed. Async `#[resource]` now generates `read_final_outcome_async_with_uri_in_request` so modern `resources/read` reaches the async body instead of the sync `read` rejection. Live `bind_http` `resources/read` composes `ctx.call_tool` + `ctx.read_resource` through that hook for both a handwritten resource and a generated async `#[resource]`. Live exact-2024 HTTP/SSE polls that request-owned future on the connection `Cx` instead of `block_on`. Live shipped-echo stdio `info://compose` polls the same request-owned future on the pump/request `Cx` and composes nested `echo` + `info://server` on both ModernOnly and LegacyOnly |
| `@prompt` / `#[prompt]` | ✅ | 🟡 | Macro implementation exists; modern request-owned dispatch and exact-2024 session dispatch both drive `get_async_in_request`. Async `#[prompt]` now also generates `get_final_outcome_async_in_request` so modern `prompts/get` reaches the async body instead of the sync `get` rejection. Live `bind_http` `prompts/get` composes `ctx.call_tool` + `ctx.read_resource` through that hook for both a handwritten prompt and a generated async `#[prompt]`. Live exact-2024 HTTP/SSE polls that request-owned future on the connection `Cx` instead of `block_on` and retains the handler `InvalidRequest` message instead of rewriting it to a fixed adapter string. Live shipped-echo stdio `compose_greeting` polls the same request-owned future on the pump/request `Cx` and composes nested `echo` + `info://server` on both ModernOnly and LegacyOnly |
| Auto JSON schema | ✅ | ✅ | `#[derive(JsonSchema)]` + inline generation |
| Description from docstrings | ✅ | ✅ | Doc comments → descriptions |
| Default parameter values | ✅ | ✅ | Implemented via `defaults(...)` on `#[tool]`/`#[prompt]`. Live `bind_http` and live public `bind_websocket` advertise a generated default, inject it when omitted, override it when supplied, and refuse a missing required sibling. Live exact-2024 HTTP+SSE `legacy_2024::HttpClient` retains the same generated default on `tools/list`, injects it when omitted, overrides it when supplied, and refuses a missing required sibling. Live exact-2024 WebSocket keeps the same inject/override/refuse split. Live shipped-echo stdio `greet` and `compose_greeting` inject, override, and refuse on both ModernOnly and LegacyOnly |
| name/description override | ✅ | ✅ | Attribute parameters supported |

### Historical macro gap-closure inventory

| Feature | Python | Rust | Notes |
|---------|--------|------|-------|
| **Icons** | ✅ | ✅ | `#[tool]`, `#[resource]`, and `#[prompt]` accept `icon = "..."` (URL or data URI). The facade `__private::protocol` path now re-exports `Icon` so those expansions compile in a `fastmcp-rust` consumer; live shipped-echo stdio `info://server` / `greeting` retain the authored icons |
| **Tags** | ✅ | ✅ | Supported for filtering in router.rs |
| **Output schema** | ✅ | ✅ | Tool output schema in macros, handler.rs. Live `bind_http`, live public `bind_websocket`, and live shipped-echo stdio `structured_echo` retain `outputSchema` on `tools/list` and matching `structuredContent` on modern `tools/call`; a peer without an output schema stays bare. Live exact-2024 stdio, live exact-2024 HTTP+SSE, and live exact-2024 WebSocket list the same `outputSchema` and still return the handler text without inventing `structuredContent` |
| **Tool annotations** | ✅ | ✅ | MCP annotations in types.rs, handler.rs |
| **Timeout per handler** | ✅ | ✅ | Handler timeout surface exists. Live `bind_http` a 10ms tool timeout refuses a late `tools/call` and still admits a near-identical fast peer tool. Live public `bind_websocket` does the same. Live exact-2024 HTTP+SSE refuses the same late tool through `legacy_2024::HttpClient` and still admits the fast peer. Live shipped-echo stdio `FASTMCP_PANIC_TOOL=1` `panic_probe` becomes sanitized `Internal server error` without the planted unwind payload on both ModernOnly and LegacyOnly, then peer `echo` still completes; omitting that flag keeps `panic_probe` unregistered. Live shipped-echo stdio `FASTMCP_PANIC_CATALOG=1` `info://panic` / `panic_greeting` keep the same sanitized-panic / peer-admitted split for `resources/read` and `prompts/get`. Live shipped-echo stdio `FASTMCP_PANIC_COMPLETE=1` `completion/complete` of `greeting` keeps the same sanitized-panic / peer-admitted split. Live `bind_http`, live exact-2024 HTTP+SSE, live public `bind_websocket`, and live exact-2024 WebSocket keep the same sanitized-panic / peer-admitted split for tools, resources, prompts, and `completion/complete` |

---

## 3. Transport Layer

| Feature | Python | Rust | Notes |
|---------|--------|------|-------|
| **Stdio transport** | ✅ | ✅ | NDJSON implementation present |
| **SSE transport** | ✅ | 🟡 | Low-level `SseServerTransport`/`SseClientTransport` types exist; public `Client::sse` / `Client::sse_with_cx` connect an exact-2024 HTTP+SSE client without probing modern HTTP. Live `bind_http` LegacyOnly `Client::sse_with_cx` invokes a real tool handler. Auto still uses SSE only as a fallback |
| **WebSocket transport** | ✅ | 🟡 | `WsTransport` framing plus `ClientBuilder::connect_websocket_with_cx` exist behind `websocket-experimental`. Live public `bind_websocket` plus `AsyncWsClientTransport::connect` retains modern `ping`, `set_log_level` + `ctx.info`, `call_tool_with_progress_marker`, incremental `subscriptions/listen` `tools/list_changed` and `resources/updated`, `ctx.call_tool` + `ctx.read_resource` compose, handler timeout (late refused, fast peer admitted), handler panic sanitized to `Internal server error` without the planted unwind payload (fast peer still admitted), static-token upgrade 401 / subject commit, and `call_tool_result` MRTR `input_required` for sampling/roots plus URL/form elicitation (omitting only roots or only `elicitation.url` fails closed). Public `call_tool` / `read_resource` / `get_prompt` complete those elicitation retries from an installed `elicitation/create` handler. Live `legacy_2024::Server::bind_websocket` plus `legacy_2024::ClientBuilder::connect_websocket_with_cx` admit exact-2024 `ping`, `tools/list`, `tools/call`, `resources/list`, `resources/read`, `prompts/list`, and `prompts/get` (a missing tool/resource/prompt stays refused). Live exact-2024 WebSocket `logging/setLevel(Info)` then tools/call retains `notifications/message` for `ctx.info`; omitting only that RPC, or raising the floor to Emergency, keeps `ctx.info` silent. Live exact-2024 WebSocket `ctx.call_tool` + `ctx.read_resource` compose completes, and a missing nested tool stays refused. Live exact-2024 WebSocket a 10ms tool timeout refuses a late `tools/call` and still admits a near-identical fast peer. Live exact-2024 WebSocket a panicking `tools/call` becomes sanitized `Internal server error` without the planted unwind payload and still admits a near-identical fast peer. Live exact-2024 WebSocket `disable_tool` retains `notifications/tools/list_changed`; omitting the catalog mutation stays silent. Live exact-2024 WebSocket `resources/subscribe` then a matching `notify_resource_updated` retains `notifications/resources/updated`; omitting only subscribe, or notifying a different URI, stays silent. Live exact-2024 WebSocket `ctx.sample` / `ctx.list_roots` issue reverse `sampling/createMessage` / `roots/list` on the same socket and complete the originating `tools/call` from the installed handler; omitting only the advertised capability fails closed. Live exact-2024 WebSocket `completion/complete` retains advertised values when a completion handler is installed; omitting only that handler refuses complete. Live exact-2024 WebSocket static-token upgrade refuses a missing or wrong bearer with `401` + `WWW-Authenticate` and commits the matching subject into `ctx.auth()`. Live exact-2024 WebSocket `FilesystemProvider` lists its reversible file template and reads the live file; an unmatched prefix stays `ResourceNotFound`. Live exact-2024 WebSocket `call_tool` / `read_resource` / `get_prompt` with a progress marker retain `notifications/progress`; omitting only the token stays silent. Live exact-2024 WebSocket initialize retains configured instructions; omitting them keeps the peer bare. Live exact-2024 WebSocket `on_startup` runs before the first admitted `tools/call`; a peer without hooks invents none. Live exact-2024 WebSocket session state is retained across later `tools/call` on the same socket and isolated from a peer socket. Live exact-2024 WebSocket `mask_error_details` replaces a leaking `resources/read` secret with `Internal server error`; disabling it keeps the secret. Live exact-2024 WebSocket `mount(child, Some("child"))` prefixes tool/prompt/resource names and still dispatches the child handlers. Live exact-2024 WebSocket `as_proxy_typed("child", …)` against a live LegacyOnly HTTP upstream prefixes tool/prompt/resource names and still dispatches the upstream handlers. Live exact-2024 WebSocket `TransformedTool` rename_arg rewrites `query` back to the parent handler and keeps the parent name unknown; `hide_arg` drops `value`, injects `hidden-default`, and keeps the parent name unknown. Live exact-2024 WebSocket `RateLimitingMiddleware` burst-1 refuses a second `tools/call` with `Rate limit exceeded` and still admits `tools/list`. Live exact-2024 WebSocket `call_tool_with_cancellation` of an in-flight wait tool emits `notifications/cancelled`, the handler observes the request cancellation and does not publish `waited`, and a peer socket still admits `tools/call`. Live exact-2024 WebSocket `ResponseCachingMiddleware` `include_tools` serves a second identical `tools/call` from cache and misses when only the arguments change. Live exact-2024 WebSocket `on_duplicate(Error)` keeps the first registration and `on_duplicate(Replace)` installs the second. Live exact-2024 WebSocket a custom `TokenVerifier` (not `StaticTokenVerifier`) refuses missing/wrong bearer upgrades with `401` + `WWW-Authenticate` and commits `Bearer gamma` into `ctx.auth()`. Live exact-2024 WebSocket `list_page_size(1)` continues tagged `tools/list`, `resources/list`, and `prompts/list` cursors to the second page and refuses a cursor when only `includeTags` or the catalog kind changes. Live public `bind_websocket` official Tasks create/`tasks/get`/`tasks/update`/`tasks/cancel` of an in-memory Task, refuse a missing id, and refuse a wrong-kind update in place. Live public `bind_websocket` `on_startup` runs before the first admitted `ping`; cooperative listener drain after `Cx` cancel runs `on_shutdown`; a peer without hooks invents none. Live exact-2024 `bind_websocket` keeps the same cooperative startup/shutdown split. Live public `bind_websocket` `call_tool_with_cancellation` of an in-flight wait tool retires as request-cancelled without publishing `waited`, the handler observes the request cancellation, and a peer socket still admits `tools/call`. Live public `bind_websocket` `completion/complete` retains advertised provider values when a completion handler is installed; omitting only that handler omits `server/discover` `completions` and refuses complete. Live public `bind_websocket` `FilesystemProvider` lists `file:///e2e/{+path}` and reads the live file; an unmatched prefix stays `InvalidParams`. Live public `bind_websocket` `mount(child, Some("child"))` prefixes tools/prompts and keeps the exact child resource URI. Live public `bind_websocket` `as_proxy_typed("child", …)` against a live ModernOnly HTTP upstream prefixes tools/prompts and keeps exact resource URIs. Live public `bind_websocket` `TransformedTool` rename_arg rewrites `query` back to the parent handler and keeps the parent name unknown; `hide_arg` drops `value`, injects `hidden-default`, and keeps the parent name unknown. Live public `bind_websocket` `RateLimitingMiddleware` burst-1 refuses a second `tools/call` with `Rate limit exceeded` and still admits `tools/list`. Live public `bind_websocket` `ResponseCachingMiddleware` `include_tools` serves a second identical `tools/call` from cache and misses when only the arguments change. Live public `bind_websocket` a custom `TokenVerifier` refuses missing/wrong bearer upgrades with `401` + `WWW-Authenticate` and commits `Bearer gamma` into `ctx.auth()`. Live public `bind_websocket` session state is retained across later `tools/call` on the same socket and isolated from a peer socket. Live public `bind_websocket` `mask_error_details` replaces a leaking `resources/read` secret with `Internal server error`; disabling it keeps the secret. Live public `bind_websocket` `on_duplicate(Error)` keeps the first registration and `on_duplicate(Replace)` installs the second. Live public `bind_websocket` `list_page_size(1)` continues `tools/list` to the second page and refuses that tools cursor on `resources/list`. Live public `bind_websocket` initialize/`server/discover` retains configured instructions; omitting them keeps the peer bare. Live public `bind_websocket` `list_page_size(1)` also continues `resources/list` and `prompts/list` and refuses a cursor when only the catalog kind changes. Live exact-2024 WebSocket `SlidingWindowRateLimitingMiddleware` 1-request/60s refuses a second `tools/call` with `Rate limit exceeded` and still admits `tools/list`. Live exact-2024 WebSocket `strict_input_validation` refuses an extra property as `InvalidParams` and still admits declared arguments; changing only that flag to `false` admits the extra property. Live exact-2024 WebSocket a generated default is advertised, injected when omitted, overridden when supplied, and a missing required sibling is refused. Live exact-2024 WebSocket retains the authored image block and does not invent audio; a text-only peer stays text-only. Live exact-2024 WebSocket lists `outputSchema` and still returns handler text without inventing `structuredContent`. Live exact-2024 WebSocket two independent sockets call the same tool as `tool:alpha` / `tool:beta` without mixing results. Live exact-2024 WebSocket `tools/list` retains version, tags, and `readOnlyHint`/`idempotentHint`; a near-identical peer stays bare. |
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
| `ping` | ✅ | ✅ | Health check. Public stdio, HTTP, and WebSocket `ping` / `ping_with_cancellation` work on modern sessions; the server answers `{}` without requiring ping in the official 2026 client-request union. Live exact-2024 stdio and live exact-2024 HTTP+SSE `legacy_2024::{Client,HttpClient}::ping` are admitted; a near-identical missing `tools/call` stays refused |
| `tools/list` | ✅ | ✅ | With cursor pagination. Live exact-2024 HTTP+SSE `list_page_size(1)` continues a tagged `tools/list` cursor to the second tool and refuses the same cursor when only `includeTags` or the list method changes. Live exact-2024 WebSocket `list_tools_page` keeps the same tagged continuation and the same query/kind refusals. Live public modern `bind_websocket` `list_page_size(1)` continues `tools/list` to a different second page and refuses that tools cursor on `resources/list`. Live public modern `bind_http` `list_tools_with_params` now sends `includeTags`/`excludeTags` on the typed page instead of a cursor-only object. Live shipped-echo stdio `FASTMCP_LIST_PAGE_SIZE=1` continues `tools/list` to a different second page on ModernOnly and through public `legacy_2024::Client::list_tools_page` on LegacyOnly, and refuses that tools cursor on `resources/list`. Live shipped-echo stdio the same page-size-1 flag continues `resources/list`, `prompts/list`, and `resources/templates/list` to a different second page on ModernOnly and through public `legacy_2024::Client::list_resources_page` / `list_prompts_page` / `list_resource_templates_page` on LegacyOnly, and refuses a cursor when only the catalog kind changes |
| `tools/call` | ✅ | ✅ | With progress token support |
| `resources/list` | ✅ | ✅ | With cursor pagination. Live exact-2024 HTTP+SSE `list_page_size(1)` continues a tagged `resources/list` cursor to the second resource and refuses the same cursor on `prompts/list`. Live exact-2024 WebSocket `list_resources_page` keeps the same tagged continuation and kind refusal. Live public modern `bind_websocket` `list_page_size(1)` continues `resources/list` to a different second page and refuses that resources cursor on `prompts/list`. Live shipped-echo stdio `FASTMCP_LIST_PAGE_SIZE=1` continues `resources/list` to a different second page on ModernOnly and through public `legacy_2024::Client::list_resources_page` on LegacyOnly, and refuses that resources cursor on `prompts/list` |
| `resources/read` | ✅ | ✅ | With progress token support. Final `#[resource]` handlers that author a complete result keep their `ttlMs` / `cacheScope`; the router default (one hour, private) applies only to the legacy-bridge projection |
| `resources/templates/list` | ✅ | 🟡 | Listing plus RFC 6570 reversible matching exist; lossy prefix/explode templates are refused rather than guessed. Live `bind_http` `list_resource_templates` retains a registered reversible template; `resources/read` expands a matching URI through `read_with_uri` and refuses a near-identical unmatched path before the handler runs. Live public modern `bind_http` and live public modern/exact-2024 `bind_websocket` `list_resource_templates_with_params` / `list_resource_templates_page` `includeTags=["cursor"]` retain `test://public-http-e2e/tmpl-cursor/{id}` and omit the other-tagged template; changing only that filter to `other` flips the set. Live shipped-echo stdio `list_resource_templates_with_params` keeps the same include/exclude split on `note://{name}` vs `memo://{name}` for ModernOnly and LegacyOnly. Live exact-2024 HTTP+SSE FilesystemProvider lists `file:///e2e/{+path}`, reads the matched file URI, and refuses a near-identical unmatched prefix as `ResourceNotFound`. Live `as_proxy_typed("ext", …)` keeps the exact template URI unprefixed and forwards a matched `resources/read` while refusing the unmatched path before the upstream handler |
| `resources/subscribe` | ✅ | ✅ | Session dispatch serves subscribe for registered URIs; registering a resource or template advertises `resources.subscribe` on initialize. Live exact-2024 stdio and live exact-2024 HTTP+SSE `resources/subscribe` then `touch` delivers `notifications/resources/updated`; omitting only subscribe stays silent |
| `resources/unsubscribe` | ✅ | ✅ | Session dispatch ends a matching subscription. Live exact-2024 stdio and live exact-2024 HTTP+SSE `resources/unsubscribe` after `subscribe` then `touch` keep later `notifications/resources/updated` silent; the same touch after subscribe still delivers the frame |
| `prompts/list` | ✅ | ✅ | With cursor pagination. Live exact-2024 HTTP+SSE `list_page_size(1)` continues a tagged `prompts/list` cursor to the second prompt and refuses the same cursor on `tools/list`. Live exact-2024 WebSocket `list_prompts_page` keeps the same tagged continuation and kind refusal. Live public modern `bind_websocket` `list_page_size(1)` continues `prompts/list` to a different second page and refuses that prompts cursor on `tools/list`. Live shipped-echo stdio `FASTMCP_LIST_PAGE_SIZE=1` continues `prompts/list` to a different second page on ModernOnly and through public `legacy_2024::Client::list_prompts_page` on LegacyOnly, and refuses that prompts cursor on `tools/list` |
| `prompts/get` | ✅ | ✅ | With argument support |
| `completion/complete` | ✅ | ✅ | Session and stateless dispatch serve a registered handler; both `completion_handler()` and `legacy_completion_handler()` advertise `capabilities.completions` on initialize. Per-template providers register through `resource_template_completion_handler()` (modern) and `legacy_resource_template_completion_handler()` (exact-2024) and take precedence over the server-wide fallback. Live `bind_http` discovery advertises `completions` only when a handler is installed; `completion/complete` retains provider values, a missing required prompt argument is refused, and a peer without a handler omits the capability and refuses complete. Live public `bind_http` `ref/resource` `test://public-http-e2e/tmpl-cursor/{id}` retains `alice`; changing only the argument name or only the template URI stays `InvalidParams`, and a peer `tools/call` is still admitted. Live public `bind_websocket` `server/discover` advertises `completions` only when a handler is installed; `complete` retains provider values and a peer without a handler omits the capability and refuses complete. Live public `bind_websocket` keeps the same resource-template retain / undeclared-argument / missing-template / peer-admitted split. Live shipped-echo stdio `modern::Client::complete` of `note://{name}` retains `alice`; an undeclared template variable and `memo://{name}` without a provider stay `InvalidParams`, and the greeting prompt provider still completes. Live exact-2024 stdio `legacy_2024::Client::complete` retains the shipped greeting provider values; `FASTMCP_NO_COMPLETIONS=1` omits the capability and refuses complete. Live exact-2024 stdio `ref/resource` `note://{name}` retains `stdio-note-completion-legacy`; changing only the URI to `memo://{name}` is refused, and greeting complete still works. Live exact-2024 HTTP+SSE `legacy_completion_handler` advertises `completions` and retains provider values through `legacy_2024::HttpClient::complete`; a peer without a handler omits the capability and refuses complete. Live exact-2024 HTTP+SSE and live exact-2024 WebSocket keep the same resource-template retain / missing-template / peer-admitted split |
| `logging/setLevel` | ✅ | ✅ | Exact-2024 sends `logging/setLevel`. Live shipped-echo stdio `legacy_2024::Client::set_log_level(Info)` then `echo` retains `notifications/message`; omitting only that RPC keeps `ctx.info` silent. Live exact-2024 HTTP+SSE `set_log_level(Info)` then tool/resource/prompt retains `notifications/message` through `take_server_notification`; omitting only that RPC, or raising the floor to Emergency, keeps `ctx.info` silent. Modern stdio, HTTP, and WebSocket `set_log_level` store `io.modelcontextprotocol/logLevel` on later requests and never send the removed final RPC |
| `notifications/cancelled` | ✅ | 🟡 | Stdio can receive and route the notification while its dispatch worker runs. Live exact-2024 HTTP+SSE admits a separate `notifications/cancelled` POST against an in-flight `tools/call`, the wait handler observes the request cancellation and does not publish `waited`, and the live SSE body keeps the 2024-11-05 suppressed-result contract (no JSON-RPC result for id 2); a peer `tools/call` stays admitted. Live exact-2024 WebSocket `call_tool_with_cancellation` emits the same notification on the live socket, retires without waiting for a suppressed JSON-RPC result, and still admits a peer `tools/call`. Live public modern `bind_websocket` `call_tool_with_cancellation` of an in-flight wait tool retires as request-cancelled without publishing `waited`, the handler observes the request cancellation, and a peer socket still admits `tools/call`. Custom loops remain sequential; reliable `awaitCleanup` remains unverified |
| `notifications/progress` | ✅ | ✅ | Progress token support. Live shipped-echo modern stdio retains request-scoped progress after `*_with_progress_marker`; omitting only the token stays silent. Live exact-2024 stdio `legacy_2024::Client::{call_tool,read_resource,get_prompt,complete}_with_progress_marker` retains the same frames through `take_server_notifications`; omitting only the token stays silent. Live exact-2024 HTTP+SSE retains the same tool/resource/prompt/completion frames through `take_server_notification` when `_meta.progressToken` is set; omitting only the token stays silent. Live exact-2024 WebSocket `legacy_2024::WebSocketClient::complete_with_progress_marker` retains `completion-legacy-halfway` through `take_server_notifications`; omitting only the token stays silent. Live public modern `bind_websocket` `complete_with_progress_marker` retains `completion-halfway` through `take_progress_notifications`; omitting only the token stays silent |
| `notifications/tools/list_changed` | ✅ | ✅ | Emitted on session catalog mutation and published to `subscriptions/listen`. Live shipped-echo exact-2024 stdio `hide_echo` retains the typed notification through `take_server_notifications`; a near-identical `echo` call stays silent. Live exact-2024 HTTP+SSE `hide` retains the same frame through `take_server_notification`; a near-identical non-mutating `tools/call` stays silent |
| `notifications/resources/list_changed` | ✅ | ✅ | Emitted on session catalog mutation and published to `subscriptions/listen`. Live exact-2024 HTTP+SSE `hide_catalog` retains the typed frame through `take_server_notification`; a near-identical non-mutating touch stays silent |
| `notifications/prompts/list_changed` | ✅ | ✅ | Emitted on session catalog mutation and published to `subscriptions/listen`. Live exact-2024 HTTP+SSE `hide_catalog` retains the typed frame through `take_server_notification`; a near-identical non-mutating touch stays silent |
| `notifications/resources/updated` | ✅ | ✅ | `ctx.notify_resource_updated` plus matching listen filters. Live exact-2024 HTTP+SSE `resources/subscribe` then `touch` retains `notifications/resources/updated` through `take_server_notification`; omitting only subscribe stays silent |
| `subscriptions/listen` | ✅ | 🟡 | Owned HTTP incremental listener (`start_subscriptions_listener` keeps the same `HttpClient` free to issue requests), stdio incremental catalog/Tasks listeners on the same `Client`, `ProxyClient::start_catalog_listener` plus `start_final_task_listener` for stdio and modern HTTP upstreams, WebSocket incremental catalog listen (`WebSocketClient::open_subscriptions_listener`) plus official Tasks listen (`open_final_task_subscription_listener`), detached sequential pumps, and `Server::open_subscription_listen` for in-process callers. Live `bind_http` incremental listen retains handler `notifications/resources/updated` and tool/resource/prompt `list_changed`. Live public `bind_websocket` incremental listen retains `notifications/tools/list_changed` after a handler `disable_tool` while a later `tools/list` on the same client still completes. Live shipped-echo stdio uses split stdin/stdout so listen acknowledgements, `resources/updated`, and tool/resource/prompt `list_changed` publish while the receive pump is blocked. Public `modern::Client` and `modern::WebSocketClient` expose `open_final_task_subscription_listener` plus `next_final_task_subscription_event` as the official Tasks incremental path; catalog `open_subscriptions_listener` refuses `taskIds`. Live shipped-echo stdio and live public `bind_websocket` each create a durable Task, catalog listen with `taskIds` stays refused, Tasks listen acknowledges the created id, `tasks/cancel` publishes `Cancelled` on that listener, and later `tasks/get` on the same session still returns that cancelled snapshot. Live `ProxyClient::start_catalog_listener` against a modern `bind_http` upstream retains `notifications/tools/list_changed` after a forwarded hide tool while a near-identical non-mutating touch does not enqueue a tools event; catalog start refuses `taskIds`. Live `ProxyClient::start_final_task_listener` against the same bind_http Task service acknowledges the created id, `tasks/cancel` publishes `Cancelled` on that listener, and later `tasks/get` still returns that cancelled snapshot. Live `as_proxy_typed("ext", …)` `watch_final_task` through the HTTP gateway keeps the same acknowledge / `Cancelled` / later `tasks/get` split for an upstream-created Task. Live `as_proxy("ext", stdio Client)` `watch_final_task` through the same HTTP gateway keeps that split for a shipped-echo `durable_task`. Live public `bind_websocket` `as_proxy_typed("ext", …)` `open_final_task_subscription_listener` keeps the same acknowledge / `Cancelled` / later `tasks/get` split. `dispatch_stateless` rejects listen instead of returning `MethodNotFound`. Collect-to-terminal stdio/WebSocket and the borrowing HTTP listener remain available |

### Background Tasks (Docket/SEP-1686; network surface quarantined)

| MCP Method | Python | Rust | Notes |
|------------|--------|------|-------|
| `tasks/list` | ✅ | 🚧 | Legacy method; RPC returns `MethodNotFound` |
| `tasks/get` | ✅ | 🟡 | Served by default (in-memory store); `final_tasks` replaces the store. Live `bind_http` with a ready in-memory service creates a Task and `tasks/get` returns that same id; a near-identical missing id stays an error. Live `bind_websocket` keeps the same create/`tasks/get`/missing-id split. Live `as_proxy_typed("ext", …)` and live `as_proxy("ext", stdio Client)` forward `tasks/get` of an upstream-created Task and refuse a near-identical missing id |
| `tasks/update` | ✅ | 🟡 | Served by default (in-memory store); `final_tasks` replaces the store. Live `bind_http` with a ready in-memory service resumes an `input_required` Task after a matching roots update and refuses a near-identical wrong-kind roots payload without leaving that Task. Live `bind_websocket` keeps the same matching-update / wrong-kind-in-place split. Live `as_proxy_typed("ext", …)` and live `as_proxy("ext", stdio Client)` forward a matching `tasks/update` of an upstream `input_required` Task. The HTTP path also refuses a near-identical wrong-kind roots payload without leaving that Task |
| `tasks/submit` | ✅ | 🚧 | Legacy method; RPC returns `MethodNotFound` |
| `tasks/cancel` | ✅ | 🟡 | Served by default (in-memory store); `final_tasks` replaces the store. Live `bind_http` `tasks/cancel` of a created Task reaches `FinalTask::Cancelled`; a near-identical missing id stays an error. Live `bind_websocket` keeps the same cancel/`Cancelled`/missing-id split. Live `as_proxy_typed("ext", …)` and live `as_proxy("ext", stdio Client)` forward `tasks/cancel` of an upstream-created Task and refuse a near-identical missing id |

The historical `TaskManager` source remains test-only for implementation
archaeology. Production builds expose neither a manager constructor/builder
edge nor a network capability while TASK-01/TASK-02 remain open.

### Sampling Protocol

| MCP Method | Python | Rust | Notes |
|------------|--------|------|-------|
| `sampling/createMessage` | ✅ | 🟡 | Protocol/context/send/response routing exists on the stdio receive-pump path. Modern WebSocket answers typed `sampling/createMessage` reverse requests when a modern handler is installed; exact-2024 reverse handlers stay rejected on ModernOnly. Modern HTTP answers those reverse requests on a request-owned SSE body by POSTing the JSON-RPC response. Modern server sampling is MRTR `input_required`, not reverse JSON-RPC; live `bind_http` JSON `tools/call` returns that result for `ctx.final_sampling` (write-half EOF is ordinary H1 completion and does not cancel). Live shipped-echo stdio `sample_echo` keeps the same `input_required` branch on `call_tool_result` and completes through public `call_tool` when a sampling handler is installed; omitting only the sampling capability fails closed. Live exact-2024 HTTP+SSE `ctx.sample` issues reverse `sampling/createMessage` on the live SSE body and completes the originating `tools/call` from the installed handler; omitting only the sampling capability fails closed. Live exact-2024 WebSocket `ctx.sample` issues the same reverse `sampling/createMessage` on the live socket and completes the originating `tools/call` from the installed handler; omitting only the sampling capability fails closed. Public `HttpClient::call_tool` / `WebSocketClient::call_tool` fulfill installed reverse handlers locally and retry with `inputResponses`. `modern::HttpClient::{call_tool,read_resource,get_prompt}_result` (plus HTTP cancellation and the matching WebSocket methods) keep a live `input_required` branch when no handlers are installed. Facade `read_resource` / `get_prompt` now use the same installed-handler follow path as `call_tool`. Stateless HTTP retries stay session-bound, so a second POST cannot resume the first POST's `requestState`. Custom-loop qualification remains open |

### Server-to-Client Protocols

| MCP Method | Python | Rust | Notes |
|------------|--------|------|-------|
| **Elicitation** | ✅ | 🟡 | `ctx.elicit_form()`, `ctx.elicit_url()`, and `ctx.elicit_with_request()` plus stdio response routing exist. Modern WebSocket and modern HTTP answer typed `elicitation/create` reverse requests when a modern handler is installed. Modern server elicitation is MRTR `input_required` (`ctx.final_elicitation_form` / `final_elicitation_url`); live `bind_http` and live `bind_websocket` `read_resource_result` / `get_prompt_result` return the form branch, and live `bind_http` / `bind_websocket` `call_tool_result` return the URL branch when the client advertises `elicitation.url` and reject when they do not. Live `bind_websocket` `call_tool` / `read_resource` / `get_prompt` complete those retries from an installed elicitation handler. Live shipped-echo stdio keeps the same form branch on `info://elicit-form` / `elicit_form_greeting` and the URL branch on `url_elicit_echo`; public `call_tool` / `read_resource` / `get_prompt` complete those retries from an installed elicitation handler, and omitting only `elicitation.url` fails closed. Stateless HTTP retries stay session-bound, so a second POST cannot resume the first POST's `requestState`. Custom-loop qualification remains open |
| **Roots** | ✅ | 🟡 | `TransportRootsProvider` exists. Modern WebSocket and modern HTTP answer typed `roots/list` reverse requests when a modern handler is installed. Modern server roots are MRTR `input_required` via `ctx.final_roots` (capability-gated, same pattern as `ctx.final_sampling`); live `bind_http` `call_tool_result` returns that branch when the client advertises `roots` and rejects `InvalidRequest` when it does not. Live shipped-echo stdio `roots_echo` keeps the same `input_required` branch and public `call_tool` completes it from an installed roots handler. Live exact-2024 HTTP+SSE `ctx.list_roots` issues reverse `roots/list` on the live SSE body and completes the originating `tools/call` from the installed handler; omitting only the roots capability fails closed. Live exact-2024 WebSocket `ctx.list_roots` issues the same reverse `roots/list` on the live socket and completes the originating `tools/call` from the installed handler; omitting only the roots capability fails closed. Custom-loop qualification remains open |

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
| Client transport integration | ✅ | 🟡 | Public `Client` covers subprocess stdio, HTTP (`Client::http` with typed `list_tools`/`call_tool`/`read_resource`/`get_prompt` plus cancellation variants), and exact-2024 SSE (`Client::sse`); `modern::Client` stdio `call_tool_result` / `read_resource_result` / `get_prompt_result` keep a live `input_required` branch the same way the HTTP/WebSocket result verbs do. A Modern2026 stdio session stamps the same `_meta` protocol version and client capabilities on `start_multiplexed_request` and on cloned `StdioRequestExecutor::execute` that the typed verbs already send. Public stdio `read_resource` / `get_prompt` follow installed modern reverse handlers the same way `call_tool` does. Public stdio `modern::Client` and `legacy_2024::Client` expose typed `list_*`/`call_tool`/`read_resource`/`get_prompt`/`complete` `*_with_cancellation` verbs. WebSocket (`websocket-experimental`) and modern HTTP have incremental catalog listen plus the same typed verbs and the same cancellation methods so the same connection can keep issuing or cancel ordinary requests |
| Tool invocation | ✅ | ✅ | `call_tool()` |
| Resource reading | ✅ | ✅ | `read_resource()` |
| Prompt fetching | ✅ | ✅ | `get_prompt()` |
| Progress callbacks | ✅ | ✅ | `call_tool_with_progress()` |
| List operations | ✅ | ✅ | Tool/resource/prompt list methods exist |
| Request cancellation | ✅ | 🟡 | `cancel_request()` emits the notification and the Unix stdio receive pump can route it during dispatch. Public HTTP `request_final_core_with_cancellation` plus typed `list_*`/`call_tool`/`read_resource`/`get_prompt`/`complete` `*_with_cancellation` verbs honor a caller-owned cancellation domain for ordinary core requests. Public stdio `modern::Client` and `legacy_2024::Client` expose the same typed verbs and reject before send when the domain is already cancelled. Live shipped-echo exact-2024 stdio pre-send cancellation of ping, catalog list, tools/call, resources/read, prompts/get, and completion/complete stays `RequestCancelled` with no transport contact; an uncancelled `call_tool_with_cancellation` of `echo` still returns `hi`, and later `ping`/`list_tools` on that same session still complete. Live exact-2024 HTTP+SSE `legacy_2024::HttpClient` pre-send cancellation of those same verbs stays `RequestCancelled`; an uncancelled `call_tool_with_cancellation` of `public-http-e2e-tool` still returns `tool:cross-era`, and later `ping` on that same session still completes. Public exact-2024 WebSocket now exposes the same typed `ping`/`list_*`/`call_tool`/`read_resource`/`get_prompt`/`complete` `*_with_cancellation` verbs. Live exact-2024 WebSocket pre-send cancellation of those verbs stays `RequestCancelled`; an uncancelled `call_tool_with_cancellation` still returns `logged`, and later `ping` on that same socket still completes. WebSocket typed verbs reject before send and retire after send. Live exact-2024 WebSocket `call_tool_with_cancellation` polls ingress so a cancelled request can retire without waiting for a suppressed 2024 result. Live public modern `bind_websocket` `call_tool_with_cancellation` of an in-flight wait tool retires as request-cancelled, the handler observes the request cancellation, and a peer socket still admits `tools/call`. Non-Unix stdio and custom/SSE loops retain sequential/blocking boundaries; reliable interruption, cleanup waiting, and request-owned isolation remain open |
| Log level setting | ✅ | ✅ | Exact-2024 `set_log_level()` sends `logging/setLevel`. Modern stdio, HTTP, and WebSocket `set_log_level` stamp `io.modelcontextprotocol/logLevel` on later requests. Modern HTTP `take_server_notifications` then retains the request-scoped `notifications/message` frames that floor admits |
| Response ID validation | ✅ | ✅ | Validates response IDs |
| Client request idle/absolute deadlines | ✅ | 🟡 | Ordinary requests use monotonic `Instant` deadlines that begin after send commit (30-second idle and 120-second non-resettable absolute defaults). Unix subprocess stdout receives, including silent and partial frames, are bounded; generic blocking `recv`, non-Unix child pipes, synchronous writes, and best-effort Drop prevent a portable end-to-end wall-clock guarantee (FND-04) |
| **MCPConfig client creation** | ✅ | ✅ | `mcp_config.rs` with JSON/TOML parsing |
| **SamplingHandler** | ✅ | 🟡 | Context and transport sender paths exist with stdio response routing. Modern HTTP/WebSocket `call_tool` and live shipped-echo stdio `call_tool` fulfill an installed sampling handler against server `input_required`. Custom-loop qualification remains open |
| **ElicitationHandler** | ✅ | 🟡 | Context and transport sender paths exist with stdio response routing. Modern HTTP/WebSocket `call_tool` and live shipped-echo stdio `call_tool` / `read_resource` / `get_prompt` fulfill an installed elicitation handler against server `input_required`. Custom-loop qualification remains open |

### Historical client gap-closure inventory

| Feature | Python | Rust | Notes |
|---------|--------|------|-------|
| **Auto-initialize** | ✅ | ✅ | Implemented in client builder.rs |
| **Task client methods** | ✅ | 🟡 | Client methods exist; the default server serves official `tasks/get`, `tasks/update`, and `tasks/cancel`. Live `bind_http` with a ready in-memory service creates a Task, `tasks/get` returns it, `tasks/update` resumes a matching roots payload (wrong-kind is refused in place), and `tasks/cancel` reaches `Cancelled`. Live `bind_websocket` `modern::WebSocketClient` exposes the same create/`get`/`update`/`cancel` split plus incremental official Tasks listen (`open_final_task_subscription_listener`); catalog listen refuses `taskIds`. Live shipped-echo stdio `modern::Client` exposes the same incremental official Tasks listen; catalog listen refuses `taskIds`. Live public `modern::HttpClient` exposes the same incremental official Tasks listen (`open_final_task_subscription_listener`) on a separate SSE POST so the same client can still `tasks/cancel` / `tasks/get`; catalog `start_subscriptions_listener` refuses `taskIds`. Live `ProxyClient::start_final_task_listener` against a modern `bind_http` Task service keeps the same catalog-`taskIds` refusal plus cancel/`Cancelled`/`tasks/get` split. Live `as_proxy_typed` HTTP forwards those three verbs to an upstream-created Task and live `watch_final_task` through that gateway retains `Cancelled` after `tasks/cancel`. Live `as_proxy("ext", stdio Client)` `watch_final_task` through the HTTP gateway keeps the same acknowledge / `Cancelled` / later `tasks/get` split. Live public `bind_websocket` `as_proxy_typed` keeps that split on `open_final_task_subscription_listener`. Live `call_tool_outcome` of `ext/<tool>` through the HTTP, WebSocket, and stdio-upstream HTTP gateways returns the official Task branch and `tasks/get` of that gateway-created id; changing only the unprefixed name is refused. Live `call_tool_outcome_with_progress_marker` through the HTTP and WebSocket as_proxy gateways keeps that same create/`tasks/get` split |

---

## 6. Context / Dependency Injection

| Feature | Python | Rust | Notes |
|---------|--------|------|-------|
| Context object | ✅ | ✅ | `McpContext` |
| Progress reporting | ✅ | ✅ | `report_progress()`, `report_progress_with_total()`. Modern HTTP, WebSocket, and stdio `call_tool_with_progress_marker` / `read_resource_with_progress_marker` / `get_prompt_with_progress_marker` stamp `progressToken`; modern HTTP, WebSocket, and stdio also expose `complete_with_progress_marker`. Exact-2024 stdio, HTTP+SSE, and WebSocket now expose the same `complete_with_progress_marker` and retain request-scoped `notifications/progress` when `_meta.progressToken` is set. `take_progress_notifications` retains the request-scoped frames |
| Handler log notifications | ✅ | ✅ | `ctx.debug()`/`info()`/`notice()`/`warning()`/`error()` emit `notifications/message` after `logging/setLevel`. Exact-2024 uses the session `setLevel` floor; live shipped-echo stdio `legacy_2024::Client` retains those frames through `take_server_notifications`. Modern HTTP and stdio apply the request `io.modelcontextprotocol/logLevel` floor to `ctx.info` and friends on tools, resources, and prompts; public `take_server_notifications` drains the frames |
| Resource update notifications | ✅ | ✅ | `ctx.notify_resource_updated(uri)` emits 2024 `resources/updated` to session subscribers and publishes the same event to matching `subscriptions/listen` streams. Live `bind_http` and live shipped-echo stdio incremental listen retain the handler publish |
| Checkpoint for cancellation | ✅ | ✅ | `checkpoint()` |
| Budget access | ✅ | ✅ | `budget()` |
| Request ID access | ✅ | ✅ | `request_id()` |
| Region ID access | ❌ | ✅ | `region_id()` (Rust-only) |
| Task ID access | ❌ | ✅ | `task_id()` (Rust-only) |
| Masked critical sections | ❌ | ✅ | `masked()` (Rust-only) |
| Session state | ✅ | ✅ | `get_state()` / `set_state()` / `remove_state()`. Live modern `bind_http` writes and reads on the same POST; a later POST does not reuse that request-local bag. Live exact-2024 HTTP+SSE writes and later reads on the same SSE session retain the bag; a peer session stays empty |
| Auth context | ✅ | ✅ | `auth()` / `set_auth()` |
| Parallel combinators | ❌ | ✅ | `join_all()`, `race()`, `quorum()`, `first_ok()` |
| Sampling from handler | ✅ | 🟡 | Exact-2024 `ctx.sample()` / `ctx.sample_with_request()` use reverse JSON-RPC on stdio. Live shipped-echo stdio `sample_text` reaches an installed `sampling/createMessage` callback and returns its text; omitting only that callback fails closed. Modern handlers use `ctx.final_sampling` → `input_required`; public HTTP/WebSocket `call_tool` and live shipped-echo stdio `call_tool` fulfill installed sampling handlers locally. Custom-loop qualification remains open |
| **Elicitation from handler** | ✅ | 🟡 | Exact-2024 `ctx.elicit_form()` / `ctx.elicit_url()` use reverse JSON-RPC on stdio. Modern handlers use `ctx.final_elicitation_form` / `final_elicitation_url` → `input_required`; public HTTP/WebSocket `call_tool` and live shipped-echo stdio `call_tool` / `read_resource` / `get_prompt` fulfill installed elicitation handlers locally. Custom-loop qualification remains open |
| Roots from handler | ✅ | 🟡 | Exact-2024 `ctx.list_roots()` uses reverse JSON-RPC on stdio. Modern handlers use `ctx.final_roots` → `input_required`; live `bind_http` `call_tool_result` and live shipped-echo stdio `roots_echo` return that branch. Public `call_tool` / `read_resource` / `get_prompt` fulfill an installed roots handler locally on HTTP, WebSocket, and stdio. Custom-loop qualification remains open |

### Historical context gap-closure inventory

| Feature | Python | Rust | Notes |
|---------|--------|------|-------|
| **Resource reading from handler** | ✅ | ✅ | `ctx.read_resource()` in context.rs. Live `bind_http` compose reads the peer resource through the request-owned reader from a tool handler, a prompt handler, and a resource handler. Live exact-2024 HTTP+SSE `legacy_2024::HttpClient` `tools/call` of the compose tool returns `compose:tool:alpha|resource:deterministic` after the nested `resources/read`. Live shipped-echo stdio `compose_echo`, `compose_greeting`, and `info://compose` read `info://server` after the nested `echo` on both ModernOnly and LegacyOnly |
| **Tool calling from handler** | ✅ | ✅ | `ctx.call_tool()` in context.rs. Live `bind_http` compose calls the peer tool through the request-owned caller from a tool handler, a prompt handler, and a resource handler. Live exact-2024 HTTP+SSE `legacy_2024::HttpClient` `tools/call` of the compose tool returns `compose:tool:alpha|resource:deterministic`; changing only the nested tool name stays a handler-visible refusal without invoking the peer tool. Live shipped-echo stdio `compose_echo`, `compose_greeting`, and `info://compose` nest `echo` + `info://server` on both ModernOnly and LegacyOnly |
| **MCP capabilities access** | ✅ | ✅ | `ctx.client_capabilities()`, `ctx.server_capabilities()`. Live modern `bind_http` attaches the advertised server slice on every request. Live exact-2024 `Client::sse` now copies initialize sampling/roots onto the handler context: a default client sees `sampling=false;roots=false;tools=true;resources=true`, advertising sampling+roots (with matching reverse handlers) flips those client flags, and omitting the resource registration clears only `resources` |

---

## 7. Authentication

| Feature | Python | Rust | Notes |
|---------|--------|------|-------|
| AuthProvider base trait | ✅ | ✅ | `AuthProvider` trait |
| Token verification | ✅ | 🟡 | `TokenVerifier` extension surface exists and provider failures are sanitized at the framework boundary. Live `bind_http` native admission refuses a missing `Authorization` header and a near-identical wrong bearer token with HTTP 401 `WWW-Authenticate: Bearer` before the handler runs; the matching bearer commits the verifier subject into `ctx.auth()`. Live exact-2024 HTTP+SSE does the same on GET `/sse` and POST `/messages` through raw native HTTP (localhost cannot hold a public-client bearer) and commits the subject into `ctx.auth()` on the matching `tools/call`. Live `bind_http` a custom `TokenVerifier` (not `StaticTokenVerifier`) admits `Bearer gamma` and commits its own subject, while missing/wrong tokens stay HTTP 401. Live exact-2024 HTTP+SSE the same custom verifier refuses `Bearer alpha` and admits `Bearer gamma` into `ctx.auth()`. Live exact-2024 WebSocket the same custom verifier refuses missing/wrong bearer upgrades with `401` + `WWW-Authenticate` and commits `Bearer gamma` into `ctx.auth()`. Live public modern `bind_websocket` the same custom verifier refuses missing/wrong bearer upgrades with `401` + `WWW-Authenticate` and commits `Bearer gamma` into `ctx.auth()`. Raw `AccessToken` custody and aggregate transport/auth promotion remain open |
| Static token verifier | ✅ | 🟡 | Configuration now rejects empty, malformed, duplicate, or unbounded tokens/schemes. Live `bind_http` `StaticTokenVerifier` plus `TokenAuthProvider` admits `Bearer alpha` and refuses missing/wrong tokens before dispatch. Live exact-2024 HTTP+SSE `StaticTokenVerifier` plus `TokenAuthProvider` refuses missing/wrong tokens on GET `/sse` and POST `/messages` with HTTP 401 `WWW-Authenticate: Bearer` and admits `Bearer alpha` into `ctx.auth()`. Live `bind_http` a custom verifier that is not static still uses the same native 401 challenge. Raw `AccessToken` custody remains a promotion gate |
| JWT support | ✅ | 🚧 | No public production JWT verifier is promoted by FND-01; `jsonwebtoken` and the old `jwt` feature are absent from the default graph |
| Access token handling | ✅ | 🟡 | Native authorization uses strict scheme/token68 grammar; malformed, multiple, or mixed credential locations fail closed and provider error payloads are sanitized. Live `bind_http` challenges missing and wrong bearer credentials with HTTP 401 before dispatch and commits the matching subject into `ctx.auth()`. Live exact-2024 HTTP+SSE uses the same native 401 challenge on GET `/sse` and POST `/messages` and commits the matching subject on the live `tools/call`. JSON-RPC fields remain a stripped legacy fallback, and raw `AccessToken` strings remain a custody promotion gate |
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
| **ResponseCachingMiddleware** | ✅ | ✅ | Eligible entries use committed-auth plus opaque session/revision partitions and fail closed on ambiguous admission or state mutation. Live `bind_http` `include_tools` serves a second identical `tools/call` from cache without re-invoking the counting handler; changing only the arguments misses and increments the handler. Request-local modern HTTP sessions share the stateless partition so a per-POST bag cannot orphan every entry. Live exact-2024 HTTP+SSE, live exact-2024 WebSocket, and live public modern `bind_websocket` keep the same include_tools hit/miss split on one session. Live shipped-echo stdio `FASTMCP_CACHE_TOOLS=1` keeps the same `cache_probe` hit/miss split on ModernOnly and LegacyOnly; omitting that flag invokes the handler twice |
| **RateLimitingMiddleware** | ✅ | ✅ | `rate_limiting.rs` - Token bucket. Live `bind_http` burst-1 refuses a second `tools/call` with `Rate limit exceeded` and still admits `tools/list` on the method-partitioned limiter. Live exact-2024 HTTP+SSE, live exact-2024 WebSocket, and live public modern `bind_websocket` keep the same method partition. Live shipped-echo stdio `FASTMCP_RATE_LIMIT=1` refuses a second `echo` `tools/call` with `Rate limit exceeded` and still admits `ping` on ModernOnly and `tools/list` on LegacyOnly |
| **SlidingWindowRateLimiting** | ✅ | ✅ | `rate_limiting.rs` - Sliding window. Live `bind_http` a 1-request/60s window refuses a second `tools/call` with `Rate limit exceeded` and still admits `tools/list`. Live public `bind_websocket` keeps the same method partition. Live exact-2024 HTTP+SSE keeps the same method partition. Live exact-2024 WebSocket keeps the same method partition. Live shipped-echo stdio `FASTMCP_SLIDING_WINDOW=1` refuses a second `echo` `tools/call` with `Rate limit exceeded` and still admits `ping` on ModernOnly and `tools/list` on LegacyOnly |

---

## 9. Providers & Dynamic Components

| Feature | Python | Rust | Notes |
|---------|--------|------|-------|
| **Proxy to remote server** | ✅ | ✅ | `ProxyClient`, `ProxyCatalog`. Live modern `bind_http` `as_proxy_typed` forwards prefixed tools/prompts and keeps exact resource URIs. Live exact-2024 HTTP+SSE `as_proxy_typed("child", …)` prefixes tools, prompts, and resource keys through `legacy_2024::HttpClient` and refuses the unprefixed upstream tool. Live exact-2024 WebSocket `as_proxy_typed("child", …)` against a live LegacyOnly HTTP upstream does the same prefix split through `legacy_2024::WebSocketClient`. Live public modern `bind_websocket` `as_proxy_typed("child", …)` against a live ModernOnly HTTP upstream prefixes tools/prompts and keeps exact resource URIs through `modern::WebSocketClient` |
| **ProxyToolManager** | ✅ | ✅ | Tool proxying |
| **ProxyResourceManager** | ✅ | ✅ | Resource proxying |
| **ProxyPromptManager** | ✅ | ✅ | Prompt proxying |
| **Tool Transformations** | ✅ | ✅ | `transform.rs` - Dynamic schema modification. Live `bind_http` `TransformedTool::from_tool` renames the catalog name and argument, rewrites `query` back to the parent handler, hides `value` and injects the configured default, and keeps the parent tool name unknown. Live exact-2024 HTTP+SSE retains the same rename/hide split through `legacy_2024::HttpClient`. Live exact-2024 WebSocket retains the same rename/hide split through `legacy_2024::WebSocketClient`. Live public modern `bind_websocket` retains the same rename/hide split through `modern::WebSocketClient`. Live shipped-echo stdio `FASTMCP_TRANSFORM_ECHO=1` advertises `echo_text` with `text` rewritten to the parent `message` on ModernOnly and LegacyOnly; calling the pre-rename `message` argument fails and the parent `echo` stays registered. Live shipped-echo stdio `FASTMCP_TRANSFORM_HIDE=1` advertises `echo_hidden` that injects `hidden-default` for the hidden `message` argument on both eras; the listed `echo_hidden` input schema drops `message` while the parent `echo` schema keeps it |
| **TransformedTool** | ✅ | ✅ | Dynamic tool modification. Live `bind_http`, live exact-2024 HTTP+SSE, live exact-2024 WebSocket, and live public modern `bind_websocket` rename and hide-arg proofs above |
| **ArgTransform** | ✅ | ✅ | Argument transformation rules. Live `bind_http` and live exact-2024 HTTP+SSE `rename_arg` and `hide_arg` reach the parent handler |

### Historical provider gap-closure inventory

| Provider | Python | Rust | Notes |
|----------|--------|------|-------|
| **FilesystemProvider** | ✅ | 🟡 | Public `build()` constructs a handler on Linux/macOS and routes I/O through the caller-owned blocking pool. Live `bind_http` lists `file:///{prefix}/{+path}` and `resources/read` expands a matching file URI through `read_with_uri`; a near-identical unmatched prefix is refused before the handler runs. Live public `bind_websocket` lists the same template and reads the live file; an unmatched prefix stays `InvalidParams`. Live shipped-echo stdio `FASTMCP_FS_ROOT` installs the same provider and live ModernOnly `list_resource_templates` + `resources/read` retain the file; an unmatched prefix stays `InvalidParams`. Live exact-2024 stdio lists the same `file:///e2e/{+path}` template and reads the live file; an unmatched prefix stays `ResourceNotFound`. Live `as_proxy_typed("ext", …)` and live `mount(child, Some("child"))` keep that same exact template unprefixed and forward a matching file read. Other targets remain fail-closed |
| **OpenAPIProvider** | ✅ | ⊘ | Excluded per plan (intentional) |

---

## 10. Configuration & Settings

| Feature | Python | Rust | Notes |
|---------|--------|------|-------|
| Log level configuration | ✅ | ✅ | Via environment + LoggingConfig |
| Console configuration | ✅ | ✅ | ConsoleConfig |
| Timeout configuration | ✅ | ✅ | Builder surface exists. Live `bind_http` and live shipped-echo stdio enforce a per-handler timeout through `run_handler_in_request` |
| Banner configuration | ✅ | ✅ | BannerStyle enum |
| Traffic verbosity | ✅ | ✅ | TrafficVerbosity enum |
| Environment variables | ✅ | ✅ | FASTMCP_LOG, FASTMCP_NO_BANNER, etc. |
| **DocketSettings** | ✅ | 🚧 | Docket source is retained but not re-exported as an FND-01 production surface; Redis belongs to TASKR-01 |
| **MCPConfig file support** | ✅ | ✅ | `mcp_config.rs` - JSON/TOML parsing |

### Historical configuration gap-closure inventory

| Config | Python | Rust | Notes |
|--------|--------|------|-------|
| **include_tags/exclude_tags** | ✅ | ✅ | Component filtering in router.rs. Live shipped-echo stdio `modern::Client::list_tools_with_params` / `list_resources_with_params` / `list_prompts_with_params` / `list_resource_templates_with_params` and the matching `legacy_2024::Client` verbs send those filters on the wire; a filtered modern list-cache key includes the tags so a demo/server/onboarding/notes page cannot be served from an unfiltered one. Live public modern `HttpClient::list_tools_with_params` / `list_resources_with_params` / `list_prompts_with_params` / `list_resource_templates_with_params` and the matching `list_*_with_params_and_cancellation` verbs send the same filters on `bind_http`. Live public modern `WebSocketClient::list_tools_with_params` / `list_resources_with_params` / `list_prompts_with_params` / `list_resource_templates_with_params` and the matching `list_*_with_params_and_cancellation` verbs send the same filters on `bind_websocket`. Live shipped-echo stdio `modern::Client` `list_resources_with_params_and_cancellation` / `list_prompts_with_params_and_cancellation` / `list_resource_templates_with_params_and_cancellation` keep those filters under a live cancellation domain and reject a pre-cancelled tagged list locally. Live exact-2024 WebSocket `list_resources_page` / `list_prompts_page` / `list_resource_templates_page` keep the same include/exclude split and retain the `cursor` tag on the listed resource |
| **mask_error_details** | ✅ | ✅ | Implemented in builder.rs. Live `bind_http` `mask_error_details(true)` replaces a resource execution secret with `Internal server error`; the same handler with masking off keeps the secret. Live exact-2024 HTTP+SSE retains the same split. Live exact-2024 WebSocket and live public modern `bind_websocket` keep the same mask/unmask split. Live shipped-echo stdio `FASTMCP_MASK_ERROR_DETAILS=1` replaces `info://leak` `secret-db-dsn` with `Internal server error`; omitting that flag keeps the secret. Live exact-2024 stdio keeps the same mask/unmask split |
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
| **Rich content types** | ✅ | ✅ | `Content` supports `audio` and includes helpers: `Content::{text,image_base64,image_bytes,audio_base64,audio_bytes,resource_text,resource_blob_base64,resource_blob_bytes}`. Live `bind_http`, live public `bind_websocket`, and live shipped-echo stdio `rich_echo` retain authored image and audio blocks on modern `tools/call`; a text-only peer stays text-only. Live exact-2024 stdio, live exact-2024 HTTP+SSE, and live exact-2024 WebSocket retain the image block from the representable `call()` hook and still refuse audio in the 2024 content union |

---

## Summary: Historical gap list (not an MCP 2026-07-28 certificate)

The list below is a historical Phase-5 gap-closure inventory. It does **not** certify aggregate MCP 2026-07-28 support.

### Source areas formerly listed as gaps

1. ✅ **Dynamic enable/disable** - Per-session visibility plus mutation-only `list_changed` notifications
2. ✅ **Component metadata** - Tags, icons, and version fields are present
3. ✅ **Error masking** - `mask_error_details` setting (builder.rs)
4. ✅ **Server composition** - mount(), as_proxy() (builder.rs, proxy.rs, router.rs)
5. ✅ **CLI commands** - dev, test, and tasks command paths are present; this is not an end-to-end verification claim
6. 🟡 **FilesystemProvider** - Public construction, live `bind_http` list+read, live public `bind_websocket` list+read, and live shipped-echo stdio `FASTMCP_FS_ROOT` list+read work on Linux/macOS for ModernOnly and exact-2024, including through a prefixed `as_proxy_typed` gateway that keeps the exact `file:///` template; other targets remain fail-closed
7. ✅ **Auto-initialize** - Client auto-initialization (client/builder.rs)
8. ✅ **Cross-component access** - ctx.read_resource(), ctx.call_tool(), ctx.get_prompt() (context.rs). Live modern `bind_http` a handler `ctx.call_tool_text` plus `ctx.read_resource_text` returns `compose:tool:alpha|resource:deterministic` on both the public SSE client and a raw `Accept: application/json` POST, including when the composer is a handwritten or generated async `#[tool]`, `#[prompt]`, or `#[resource]`. Live exact-2024 `Client::sse` on LegacyOnly composes the same nested pair through session `call_async_in_request`, `get_async_in_request`, and `read_async_with_uri_in_request`. Live exact-2024 HTTP+SSE `legacy_2024::HttpClient` retains that same nested pair from `tools/call`, `prompts/get`, and `resources/read`; changing only the nested tool name stays a handler-visible refusal. Live shipped-echo stdio polls those same request-owned futures on the pump/request `Cx` for `compose_echo`, `compose_greeting`, `compose_prompt`, `compose_from_prompt`, `info://compose`, and `info://compose-prompt` on both ModernOnly and LegacyOnly. Live shipped-echo stdio `compose_prompt`, `info://compose-prompt`, and `compose_from_prompt` retain `compose-prompt:Please greet alpha in a friendly way.` on both ModernOnly and LegacyOnly; changing only the nested prompt name stays a handler-visible refusal. Live `bind_http` and live public `bind_websocket` `ctx.get_prompt_text` return `compose-prompt:prompt:alpha` on both ModernOnly and exact-2024 from a tool, a resource (`test://public-http-e2e/compose-prompt`), and a prompt (`public-http-e2e-from-prompt`); changing only the nested prompt name stays a handler-visible refusal and a peer `tools/call` is still admitted. A near-identical unknown nested tool, resource, or prompt is refused without invoking the missing peer
9. ✅ **Capabilities access** - ctx.client_capabilities(), ctx.server_capabilities() (context.rs)
10. ✅ **Per-handler timeout** - Handler-level configuration exists and both modern and exact-2024 session dispatch now enforce it through `run_handler_in_request`. Live `bind_http` refuses a late tool and still admits a fast peer. Live exact-2024 HTTP+SSE refuses the same late tool and still admits the fast peer. Live shipped-echo stdio `slow_echo` is refused with `Request timeout exceeded` on both ModernOnly and LegacyOnly, then `fast_echo` still completes. Live shipped-echo stdio `FASTMCP_PANIC_TOOL=1` `panic_probe` becomes sanitized `Internal server error` without the planted unwind payload on both ModernOnly and LegacyOnly, then peer `echo` still completes; omitting that flag keeps `panic_probe` unregistered. Live shipped-echo stdio `FASTMCP_PANIC_CATALOG=1` `info://panic` / `panic_greeting` keep the same sanitized-panic / peer-admitted split for `resources/read` and `prompts/get`. Live shipped-echo stdio `FASTMCP_PANIC_COMPLETE=1` `completion/complete` of `greeting` keeps the same sanitized-panic / peer-admitted split. Live `bind_http`, live exact-2024 HTTP+SSE, live public `bind_websocket`, and live exact-2024 WebSocket keep the same sanitized-panic / peer-admitted split for tools, resources, prompts, and `completion/complete`
11. ✅ **Output schema** - Tool output schema support (macros, handler.rs)
12. ✅ **Tool annotations** - MCP tool annotations (types.rs, handler.rs). Live `bind_http` and live public `bind_websocket` `tools/list` retain projected `readOnlyHint`/`idempotentHint` on the advertised tool; a near-identical peer without annotations stays bare
13. ✅ **Strict validation** - `strict_input_validation` setting. Live `bind_http` refuses an unknown property when the flag is on and admits the same extra property when it is off; live exact-2024 HTTP+SSE does the same; live shipped-echo stdio `FASTMCP_STRICT_INPUT=1` and live exact-2024 stdio keep the same on/off split; modern final `tools/call` now consults the flag
14. ✅ **Duplicate handling** - on_duplicate behavior (builder.rs). Live `bind_http` Error keeps the first handler and Replace installs the second

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
