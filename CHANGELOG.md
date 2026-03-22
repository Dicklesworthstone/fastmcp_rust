# Changelog

All notable changes to [FastMCP Rust](https://github.com/Dicklesworthstone/fastmcp_rust) are documented here.

Format: version timeline, organized by landed capabilities. Commit links point to representative commits, not exhaustive diffs. Versions with a GitHub Release are marked accordingly.

---

## [Unreleased] (after v0.2.0)

Development since the v0.2.0 release on 2026-02-15, covering concurrency infrastructure, HTTP serving, public dispatch APIs, and continued hardening.

### Concurrency and Dispatch

- **Concurrent tool dispatch (Phase 1)** -- Replace sequential Phase 0 stubs with true concurrent combinators (`join_all`, `race`, `quorum`, `first_ok`) using safe-Rust `poll_fn` + pinned futures. HTTP accept loop now spawns one `std::thread` per connection with an `AtomicUsize` semaphore enforcing `max_connections`. ([`9a24313`](https://github.com/Dicklesworthstone/fastmcp_rust/commit/9a243130c0660e1465030d662d5494c43cd4ca88))
- **Concurrent read-only HTTP dispatch via session snapshots** -- Classify JSON-RPC methods as `ConcurrentReadOnly` vs `ExclusiveSession`. Read-only methods (`tools/call`, `resources/read`, `prompts/get`) snapshot session state in under 1 us and release the mutex immediately, eliminating head-of-line blocking. ([`402bc43`](https://github.com/Dicklesworthstone/fastmcp_rust/commit/402bc43b7a2470abebef3ed2a04088f39feb7d53))
- **Public `dispatch_request` API** -- `Server::dispatch_request()` lets external code process a JSON-RPC request without going through a Transport abstraction, enabling custom transports, HTTP proxies, and embedded MCP endpoints. Re-exports `NotificationSender`, `RequestSender`, `PendingRequests`, and the bidirectional module from the facade crate. ([`27f00a6`](https://github.com/Dicklesworthstone/fastmcp_rust/commit/27f00a62c29c7bb68c4c5425b344f916d70c8663))
- **`dispatch_request_concurrent` for lock-free read-only dispatch** -- Exposes session-snapshot-based concurrent dispatch as a public API, snapshotting in under 1 us and releasing the mutex for read-only methods. Closes #17. ([`d2fd587`](https://github.com/Dicklesworthstone/fastmcp_rust/commit/d2fd587e158b644b32e3b20a66416d6e155dced3))

### HTTP Server

- **Turnkey HTTP server with Streamable HTTP transport** -- `run_http` / `run_http_with_cx` / `run_http_returning` variants on `Server` that bind a TCP listener and serve MCP JSON-RPC over HTTP. `HttpServerConfig` builder exposes `mcp_path`, `health_path`, `max_connections`, CORS, body-size, and timeout tuning. Routes `POST /mcp` to JSON-RPC dispatch, `GET /health` to health check, `OPTIONS /mcp` to CORS preflight. ([`693bc06`](https://github.com/Dicklesworthstone/fastmcp_rust/commit/693bc06f83ab6e579f1d8ea3167d4a5495b3e430))

### Server and Session Enhancements

- **Request-scoped auth context and typed session state** -- Auth context moved from session-state key lookup to a dedicated `Arc<Mutex<Option<AuthContext>>>` on `McpContext`. `SessionState` gains typed `get`/`set`/`remove`, iterator support, and `Clone` for stored values. Resource template parameter extraction and validation added to router. ([`5e9086c`](https://github.com/Dicklesworthstone/fastmcp_rust/commit/5e9086c94f74a3cd1e36c6aee391b0ac229769f1))
- **Enhanced resource handling, session management, and middleware hooks** -- Finer-grained request interception, improved router resource template matching and URI resolution, and extensive test coverage for resource handling and auth flows. ([`36bcf82`](https://github.com/Dicklesworthstone/fastmcp_rust/commit/36bcf826d925327b5cafc7485d99df4e3b2f481b))

### Protocol

- **Re-export `ToolAnnotations` from fastmcp-protocol** -- Consumers can annotate tools with metadata (`readOnlyHint`, `destructiveHint`, etc.) without reaching into the protocol crate directly. ([`c6e6e1c`](https://github.com/Dicklesworthstone/fastmcp_rust/commit/c6e6e1c6064fa5a22f9da858ed49e2963a194e33))

### Bug Fixes

- **`block_on` I/O reactor and Cx context** -- The `#[tool]` macro generates nested `block_on` calls whose runtime lacked an I/O reactor and never installed a `Cx` context. Without them, socket readiness events never arrived and `asupersync` networking primitives deadlocked. Fixed by creating a platform reactor and installing a `Cx` carrying the `IoDriverHandle`. ([`d26379f`](https://github.com/Dicklesworthstone/fastmcp_rust/commit/d26379f8686e9a85487f2af49d551f29abf4702e))
- **Session snapshot isolation, duplicate request rejection, HTTP cancellation** -- Snapshot copies prevent cross-request mutation, duplicate JSON-RPC IDs are rejected, HTTP cancellation responsiveness improved, and pre-failed tasks short-circuit. ([`a3d0cb7`](https://github.com/Dicklesworthstone/fastmcp_rust/commit/a3d0cb73b7f68710d2002300fcad36fb2ce3ed80))
- **Quorum combinator `quorum_met` correctness** -- Fix incorrect `quorum_met` flag in the `quorum_timeout` all-done branch. ([`ade6f9d`](https://github.com/Dicklesworthstone/fastmcp_rust/commit/ade6f9de7e0b6300725b8d8c0c6d92276aeaf9a0))
- **Allow `Pending -> Failed` task state transition** -- Previously rejected, now correctly permits tasks that fail before starting execution. ([`1f265da`](https://github.com/Dicklesworthstone/fastmcp_rust/commit/1f265dae0c263eafce184fec9dc740404ea24a05))
- **Log mutex poisoning in concurrent dispatch** -- Surface poisoned-lock diagnostics instead of silently propagating errors. ([`7fa856a`](https://github.com/Dicklesworthstone/fastmcp_rust/commit/7fa856a27bb28a359a082df606d7616ae475bf65))
- **`rustfmt` formatting for `block_on` RuntimeWithIo construction** -- Code formatting consistency fix. ([`a512c3b`](https://github.com/Dicklesworthstone/fastmcp_rust/commit/a512c3bef804b47798239018ab19fdc4ba9149f3))

### Maintenance

- Update license to MIT with OpenAI/Anthropic Rider. ([`35c685b`](https://github.com/Dicklesworthstone/fastmcp_rust/commit/35c685bdce89a8e3ffba6f0c660dce867678576a))
- Upgrade dependencies and loosen version specs across workspace. ([`9c882fc`](https://github.com/Dicklesworthstone/fastmcp_rust/commit/9c882fc348084903506b776bca7ddba7bdc04360))
- Bump GH Actions versions. ([`6bf0d54`](https://github.com/Dicklesworthstone/fastmcp_rust/commit/6bf0d54e301f7f040a85463872383e0fd9002e7f))

---

## [v0.2.0] -- 2026-02-15 (GitHub Release)

Second release. Major themes: comprehensive test coverage, crates.io publishing readiness, security hardening, and macro improvements. 344 commits from initial commit to this tag.

**Release notes:** <https://github.com/Dicklesworthstone/fastmcp_rust/releases/tag/v0.2.0>

### Crates Published

| Crate | Version |
|-------|---------|
| fastmcp-rust (facade) | 0.2.0 |
| fastmcp-core | 0.2.0 |
| fastmcp-derive | 0.2.0 |
| fastmcp-protocol | 0.2.0 |
| fastmcp-transport | 0.2.0 |
| fastmcp-server | 0.2.0 |
| fastmcp-client | 0.2.0 |
| fastmcp-console | 0.2.0 |
| fastmcp-cli | 0.2.0 |

### Test Coverage Campaign (2026-02-09 through 2026-02-15)

A massive test campaign added hundreds of unit and E2E tests across every crate, organized through the beads issue tracker. Key areas covered:

- **Server:** auth token extraction/verification, session lifecycle, handler dispatch, builder fluent API, middleware trait delegation, router registration/filtering/pagination/mount, task manager state transitions, proxy progress/catalog failures, docket cancellation/FIFO ordering, bidirectional request sender cancellation, OAuth revocation/expired validation/redirect state. ([`d0b88c1`](https://github.com/Dicklesworthstone/fastmcp_rust/commit/d0b88c1b07bed253ac6b58fddd525aaf315679ef), [`7d389f8`](https://github.com/Dicklesworthstone/fastmcp_rust/commit/7d389f8bdc8bad6b4f691866cce19a3da4828c2e), [`d17dc5f`](https://github.com/Dicklesworthstone/fastmcp_rust/commit/d17dc5f840079198b7f37c77732b88b6339dc837), [`7d32716`](https://github.com/Dicklesworthstone/fastmcp_rust/commit/7d3271669cf7455d2ba9fca9ff7227beb7807126), [`b6ba48e`](https://github.com/Dicklesworthstone/fastmcp_rust/commit/b6ba48ec923d49af687365730459f1b4f0827ea4), [`40e0d64`](https://github.com/Dicklesworthstone/fastmcp_rust/commit/40e0d649284b878c5a9e9211f7700753d7d72d41))
- **Transport:** codec, memory transport, Transport trait, SendPermit, TransportError, SSE event type/writer/reader, WebSocket frame edge cases, stdio CRLF handling. ([`4077f0d`](https://github.com/Dicklesworthstone/fastmcp_rust/commit/4077f0d808beb8a44e03b20e9c4eccca6e7c12aa), [`15bb1f9`](https://github.com/Dicklesworthstone/fastmcp_rust/commit/15bb1f9c1850bf6808aa99f3aed25ef4ac88327d), [`31b188a`](https://github.com/Dicklesworthstone/fastmcp_rust/commit/31b188a3ee7b746d54ee4b22a0e95723e1c3208f), [`a4a957c`](https://github.com/Dicklesworthstone/fastmcp_rust/commit/a4a957c0cf0810e4f0ccd49e234cf51b4757bbf3), [`347a8bd`](https://github.com/Dicklesworthstone/fastmcp_rust/commit/347a8bd6b9e9577e636691eb0d102ce97955ea73))
- **Client:** session, builder, config, progress debug, IO detail preservation, capabilities, rich rendering branches. ([`a0d30d8`](https://github.com/Dicklesworthstone/fastmcp_rust/commit/a0d30d858d4a8f0c31649b85253c0e5497fe79b2), [`177c341`](https://github.com/Dicklesworthstone/fastmcp_rust/commit/177c34121646098f16601b81fb0611350ab4a61a), [`5e90f16`](https://github.com/Dicklesworthstone/fastmcp_rust/commit/5e90f16e2928159c28712fd90247ed60f232940e))
- **Protocol:** ToolAnnotations, Icon, Content factories, schema.rs validation. ([`caefc30`](https://github.com/Dicklesworthstone/fastmcp_rust/commit/caefc302870f3ff6cdbe2958109bb96fdfa26244), [`1b6e04b`](https://github.com/Dicklesworthstone/fastmcp_rust/commit/1b6e04b4658d76758be2417a52ab1228263318c3))
- **Core:** context helper types, error.rs and duration.rs edge cases, context sampling/elicitation and McpContext builders. ([`3d37595`](https://github.com/Dicklesworthstone/fastmcp_rust/commit/3d37595c6793548713f6a6ef5c8921a05c20f1ee), [`05f38cb`](https://github.com/Dicklesworthstone/fastmcp_rust/commit/05f38cbd59377a7453df421c49961c6c1dfedeb3), [`2b98a19`](https://github.com/Dicklesworthstone/fastmcp_rust/commit/2b98a19c4e257497051f06898d496c6524a9ef27))
- **Console:** banner, diagnostics, status, config, tables, stats renderer, formatter, tracing levels, logging. ([`ef7cedd`](https://github.com/Dicklesworthstone/fastmcp_rust/commit/ef7cedd9a4e20feebde0b60dd95c4c3c6da17cd6), [`67314c8`](https://github.com/Dicklesworthstone/fastmcp_rust/commit/67314c82727acaf60e6df24647b24aecbf5e8f3a))
- **Macros:** helper function unit tests, macro expansion tests, trybuild compile-time tests. ([`25f0a9b`](https://github.com/Dicklesworthstone/fastmcp_rust/commit/25f0a9b57d17befb39793b76d803c158daa9b241), [`a8054233`](https://github.com/Dicklesworthstone/fastmcp_rust/commit/a8054233bab30c917f828607ec1447b71cbeca5e))
- **E2E suites:** transport (stdio NDJSON, SSE streaming, WebSocket, HTTP), CLI commands, client session management, task management, middleware integration, background tasks, auth flows (static, JWT, OAuth). ([`0d7451b`](https://github.com/Dicklesworthstone/fastmcp_rust/commit/0d7451b9eb0503e09cf41e1ca84f4908082e2750), [`098059f`](https://github.com/Dicklesworthstone/fastmcp_rust/commit/098059f721bbba446637feade3317a0772ede23a), [`8e8855c`](https://github.com/Dicklesworthstone/fastmcp_rust/commit/8e8855c4e22a1c9df159e169e8263f0151435dcd), [`baf839b`](https://github.com/Dicklesworthstone/fastmcp_rust/commit/baf839be34200728233b6ae14acc259dee545528))

### Macro Enhancements

- **`#[tool]` annotations and version support** -- `#[tool(annotations(read_only_hint = true, destructive_hint = false), version = "1.0")]` syntax for rich tool metadata at the macro level. ([`4244ab8`](https://github.com/Dicklesworthstone/fastmcp_rust/commit/4244ab8ec9ae58ed96fe4945fc3e2fc4ea3d2cb0))
- **`#[resource]` and `#[prompt]` version and tags** -- `#[resource(version = "2.0", tags = ["config"])]` and `#[prompt(tags = ["greeting"])]` support. ([`0f78298`](https://github.com/Dicklesworthstone/fastmcp_rust/commit/0f782988e6761e1a0a3d5ad190fcd3042f363f1e))
- **`Vec<ResourceContent>` return type in `#[resource]`** -- Resources can now return multiple content items. ([`f9f3f3e`](https://github.com/Dicklesworthstone/fastmcp_rust/commit/f9f3f3ee64061763c6ad5b8359b76dce805aac3a))
- **Tool tags macro support** -- `#[tool(tags = ["math", "utility"])]` for tag-based tool filtering. ([`c4257d8`](https://github.com/Dicklesworthstone/fastmcp_rust/commit/c4257d8e7fbb6085f91ea7196d0fc953c534856e))
- **E2E handler conversion to macros** -- Systematic refactoring of all manual `ToolHandler`/`ResourceHandler`/`PromptHandler` impls in tests to `#[tool]`/`#[resource]`/`#[prompt]` macros, validating real-world macro correctness. ([`4332672`](https://github.com/Dicklesworthstone/fastmcp_rust/commit/43326722ce639abdec71b8bf1bc6027abfbf8b4a), [`dba5092`](https://github.com/Dicklesworthstone/fastmcp_rust/commit/dba5092a7150c529c74aa274797622298ac7978a), [`58e2f6a`](https://github.com/Dicklesworthstone/fastmcp_rust/commit/58e2f6a5ef3088d6438cf10bd7d52baf04b0f096), [`fcc3180`](https://github.com/Dicklesworthstone/fastmcp_rust/commit/fcc31800a645ab53dea3238cc0f55fa044c9fccc))

### Security

- **Redact access token values from Debug output** -- Prevents accidental credential leakage in logs. ([`5615ee4`](https://github.com/Dicklesworthstone/fastmcp_rust/commit/5615ee4f9e22563df41bbb45e21f5bf84fb6080a))
- **Real crypto for OAuth/OIDC** -- Replace placeholder token generation with cryptographically secure implementations, harden HTTP request parsing. ([`df51b46`](https://github.com/Dicklesworthstone/fastmcp_rust/commit/df51b46adbc4b2f3c30bf501b539edc1bd8fbeab))
- **Fix OIDC RS256/JWKS misrepresentation** -- Correct the OIDC token validation to properly handle RS256 and JWKS key sets. ([`2fb19c6`](https://github.com/Dicklesworthstone/fastmcp_rust/commit/2fb19c61e1a678992cdc34c593e54103b093fbd4))

### Robustness and Bug Fixes

- **Harden TaskManager runtime startup and task scheduling** -- Prevent race conditions during task manager initialization. ([`c6ec853`](https://github.com/Dicklesworthstone/fastmcp_rust/commit/c6ec853df55345ff04fcae5ba97ea0f1a69705f7))
- **Pagination cursor overflow** -- Fix integer overflow when router list pagination cursors exceed bounds. ([`3ea17f8`](https://github.com/Dicklesworthstone/fastmcp_rust/commit/3ea17f8f8ab9f7489c8589d9d95d49793d2deccf))
- **ClientBuilder retry overflow for `u32::MAX`** -- Prevent arithmetic overflow when max retries is set to `u32::MAX`. ([`225e4ec`](https://github.com/Dicklesworthstone/fastmcp_rust/commit/225e4ec9d88686c25c7b8efeba617be5382c24b0))
- **Harden macros and stream queues from deep audit** -- Address edge cases found during code audit of macro expansion and stream queue implementations. ([`20ee715`](https://github.com/Dicklesworthstone/fastmcp_rust/commit/20ee71504a977a3794f493b7284a7d985e181c28))
- **Poison-safe locks** -- OAuth stats, pending-request lock, and stream helper queues all recover gracefully from mutex poisoning instead of panicking. ([`20375f8`](https://github.com/Dicklesworthstone/fastmcp_rust/commit/20375f81de71120b0712074599749a7c76bdfe1d), [`2522c0b`](https://github.com/Dicklesworthstone/fastmcp_rust/commit/2522c0bc0199dfd85d9f3005eeaea929183a2f32), [`074ce51`](https://github.com/Dicklesworthstone/fastmcp_rust/commit/074ce51b0d138b39bb2efefca4dd5e519f19e14d))
- **Client `cx` cancellation in stdio retry loop** -- Honor cancellation during client reconnection attempts. ([`e7371b3`](https://github.com/Dicklesworthstone/fastmcp_rust/commit/e7371b341926c7619ded6491265ca62019f073f7))
- **FIFO stream queues and invalid stream send rejection** -- Enforce ordering and reject malformed stream sends in transport layer. ([`3b7998e`](https://github.com/Dicklesworthstone/fastmcp_rust/commit/3b7998e7b2d227f402d82677d43cd44f089b128d))
- **Propagate mutex poison errors in StreamableHttpTransport** -- Surface errors instead of silently dropping them. ([`5d4c2c3`](https://github.com/Dicklesworthstone/fastmcp_rust/commit/5d4c2c3119238461e97c7878346767e08b4ab59c))
- **Pagination safety limits and infinite loop detection** -- Client `list` methods detect and break out of infinite pagination loops. ([`5077aca`](https://github.com/Dicklesworthstone/fastmcp_rust/commit/5077aca66b3912e767237a4adf3c295fc3624dbc))
- **Resolve all clippy pedantic warnings** across the workspace. ([`f9cd3d8`](https://github.com/Dicklesworthstone/fastmcp_rust/commit/f9cd3d833efa0e5730fbf987e1b42df0d076c3f0))
- **Remove UBS-critical `panic!` macros** in transport and middleware tests, replacing with `assert` + `let-else`. ([`d768948`](https://github.com/Dicklesworthstone/fastmcp_rust/commit/d768948892459c4d704fe49ece5b2207854b9b64))

### CI and Publishing

- **CI coverage job with lcov artifacts** -- Add code coverage collection and artifact upload to CI pipeline. ([`4abbbf8`](https://github.com/Dicklesworthstone/fastmcp_rust/commit/4abbbf8e3c08006f7f196b458a54f72d9586b154))
- **Tighten CI coverage gate and upload test trace artifacts** -- Coverage thresholds enforced in CI. ([`878bf3f`](https://github.com/Dicklesworthstone/fastmcp_rust/commit/878bf3ff836280554467cf9cf29d2679bbd4f918))
- **CI dependency setup hardening** -- Replace fragile Cargo.toml path rewriting with symlinks for sibling repo dependencies. ([`c3f3ad9`](https://github.com/Dicklesworthstone/fastmcp_rust/commit/c3f3ad9a35f051a79fed569ea7a5ff3f24ff53d3))
- **Prepare all crates for crates.io publishing** -- Add required metadata, version specifications, module documentation, and README files across all workspace crates. ([`965dad9`](https://github.com/Dicklesworthstone/fastmcp_rust/commit/965dad971b42e2955db52797a6fe17ba7a935bcb))
- **Rename `fastmcp-macros` to `fastmcp-derive`** -- Align crate naming with Rust ecosystem conventions. ([`e50dbd1`](https://github.com/Dicklesworthstone/fastmcp_rust/commit/e50dbd1eecbd611f3f1fb57fc7932b61bb143f2e))
- **Rename facade crate to `fastmcp-rust`** -- Align published crate name with repository. ([`0a53d3c`](https://github.com/Dicklesworthstone/fastmcp_rust/commit/0a53d3c7376157af98d53a413a1955c3de74e9ce))
- **Switch asupersync and rich_rust to crates.io** -- Remove local path dependencies in favor of published versions. ([`2ab2c8d`](https://github.com/Dicklesworthstone/fastmcp_rust/commit/2ab2c8d577675aae46a040fdb8dc89805a8b8607), [`9893f6d`](https://github.com/Dicklesworthstone/fastmcp_rust/commit/9893f6d27cd686772e7e7d67a39ccad78796f239))

---

## Initial Development (v0.1.0 era) -- 2026-01-18 through 2026-01-28

The foundational development period, establishing the full FastMCP Rust framework from initial commit to feature parity with Python FastMCP v2.14.4. No tagged release was cut for this phase; the code was subsequently published as part of v0.2.0.

### Core Framework (2026-01-18)

- **Initial commit** -- Batteries-included MCP framework with cancel-correct async via asupersync, `#[tool]`/`#[resource]`/`#[prompt]` macros, budget-based timeouts, 4-valued `Outcome` type, structured concurrency with region-scoped tasks, and zero unsafe code. Workspace organized as `fastmcp-core`, `fastmcp-protocol`, `fastmcp-transport`, `fastmcp-server`, `fastmcp-client`, and `fastmcp-derive` crates. ([`fe916bf`](https://github.com/Dicklesworthstone/fastmcp_rust/commit/fe916bf4c40eb34ddcc1c497526f511a9fd56b25))

### Console and Terminal UI (2026-01-20 through 2026-01-21)

- **`fastmcp-console` crate** -- Rich terminal output via `rich_rust` integration. Startup banner shows server name, version, and capability counts on stderr (preserving JSON-RPC on stdout). Suppressible via `FASTMCP_NO_BANNER=1`. ([`62fe623`](https://github.com/Dicklesworthstone/fastmcp_rust/commit/62fe623f3226d9fb4c13ba66d55b32b0d9a26fd5))
- **Table renderers and stats integration** -- `ResourceTableRenderer` with URI highlighting and tree view, stats renderer module, comprehensive table rendering for tools, resources, and prompts. ([`457ce8f`](https://github.com/Dicklesworthstone/fastmcp_rust/commit/457ce8fbfd952ad4243e39962218d5863f115958), [`e8d938b`](https://github.com/Dicklesworthstone/fastmcp_rust/commit/e8d938b1565f51894d2606c5d19ab3b1c43da903), [`9e97040`](https://github.com/Dicklesworthstone/fastmcp_rust/commit/9e97040921c24fc1421991c11bb72bb32b472242))

### Server Architecture (2026-01-21 through 2026-01-25)

- **Client module and error boundaries** -- MCP client implementation with error boundary handling. ([`a4f8f06`](https://github.com/Dicklesworthstone/fastmcp_rust/commit/a4f8f0629ccbb55b5b3e4d1f5309fc541d06be7a))
- **Server builder and console logging** -- Fluent `ServerBuilder` API, refactored console logging subsystem. ([`991a8c3`](https://github.com/Dicklesworthstone/fastmcp_rust/commit/991a8c32c530396ab68208d2b0c0b31d9dc4612f))
- **Transport runners and doc alignment** -- Transport abstraction layer with runner implementations for stdio. ([`734945d`](https://github.com/Dicklesworthstone/fastmcp_rust/commit/734945d39d54a61c82a6a1cad4dab551a66a1fe0))
- **Budget cancellation semantics** -- Implement budget-based cancellation where exhausted budgets trigger graceful `Cancelled` outcomes rather than hard errors. ([`fa47763`](https://github.com/Dicklesworthstone/fastmcp_rust/commit/fa47763e630b85537c4e80aea4e67cb9c35721f0))
- **Auth, state management, middleware, and task systems** -- Server-side authentication, session state management, middleware pipeline, and background task infrastructure. ([`41c4104`](https://github.com/Dicklesworthstone/fastmcp_rust/commit/41c4104643f0e8ab8e530e8e9e1ab63e4ac3ef03), [`244db06`](https://github.com/Dicklesworthstone/fastmcp_rust/commit/244db06e02aa6b7c535b691deba3348b344d6d81))

### Transport Layer (2026-01-25 through 2026-01-27)

- **Enhanced codec and transport robustness** -- Strengthen NDJSON codec parsing, transport error handling, and connection lifecycle. ([`f5a9479`](https://github.com/Dicklesworthstone/fastmcp_rust/commit/f5a9479c6922c3bb8be41c243c43cd95a4a97bbe))
- **HTTP transport for web-based MCP** -- Full HTTP transport implementation enabling browser and HTTP-client-based MCP interactions. ([`286eed9`](https://github.com/Dicklesworthstone/fastmcp_rust/commit/286eed930723e7a3a4bc18a94e58cd3f6350734a))
- **WebSocket RFC 6455 compliance** -- Reject invalid frames, enforce mask requirement with CSPRNG mask keys, reject interleaved binary frames during fragmentation. ([`8103b30`](https://github.com/Dicklesworthstone/fastmcp_rust/commit/8103b30d9cc2500281dc7b44ab229dfa889e4982), [`ddeaf57`](https://github.com/Dicklesworthstone/fastmcp_rust/commit/ddeaf577ad9d0deb3c582b21b975849341f2b16c), [`825a9a0`](https://github.com/Dicklesworthstone/fastmcp_rust/commit/825a9a0670407d93bd75819cfda60909474195e3))
- **SSE memory exhaustion prevention** -- Bounded line and event size limits for SSE streams. ([`4a86245`](https://github.com/Dicklesworthstone/fastmcp_rust/commit/4a862455abb1914ad3e96cbf0af5c862c4b61e5c))

### Protocol Extensions (2026-01-27)

- **Sampling/createMessage protocol** -- Implement the MCP sampling request type for LLM completion capability. ([`2a296c9`](https://github.com/Dicklesworthstone/fastmcp_rust/commit/2a296c93d92c97679deced913140cbb8e691bdc8))
- **Elicitation and Roots protocol methods** -- User input request capability and workspace roots listing. ([`1e3973a`](https://github.com/Dicklesworthstone/fastmcp_rust/commit/1e3973a35630c4b9ccaaa81dbbd7ada75a468ffa))
- **Completion messages and expanded elicitation types** -- Protocol support for auto-completion suggestions. ([`3114837`](https://github.com/Dicklesworthstone/fastmcp_rust/commit/3114837096c597de02fda3629a9fac1ed03ac50c))
- **ToolAnnotations for MCP tool metadata** -- `readOnlyHint`, `destructiveHint`, `idempotentHint`, `openWorldHint` annotations on tool definitions. ([`94d3c7b`](https://github.com/Dicklesworthstone/fastmcp_rust/commit/94d3c7b15cc6ad784a6cf680d93d7adeebdcf7af))
- **Icon infrastructure for component metadata** -- Icon type for visual component identification in MCP clients. ([`af5b567`](https://github.com/Dicklesworthstone/fastmcp_rust/commit/af5b5675eee4680cfc4b523a46c0b509fd2b80e8))
- **`output_schema` field on Tool definition** -- Structured output schema for tool return types. ([`ad59248`](https://github.com/Dicklesworthstone/fastmcp_rust/commit/ad59248a03c7d4287b2c833ff635a5cd8b79b61c))
- **Version and tags metadata** -- Version strings and tag arrays on tools, resources, and prompts for component lifecycle and filtering. ([`c7b4fe0`](https://github.com/Dicklesworthstone/fastmcp_rust/commit/c7b4fe01cb000206afdb3c671e969f6ed3378d83), [`7ca0d59`](https://github.com/Dicklesworthstone/fastmcp_rust/commit/7ca0d59d7373d3dcbe87908b4ca651598fef5296))

### Server Features (2026-01-27)

- **OAuth 2.1 authorization server** -- Complete OAuth 2.0/2.1 with mandatory PKCE, token issuance, RFC 7009 revocation, dynamic client registration, scope validation, and cryptographically secure token generation. ([`ecc4b9d`](https://github.com/Dicklesworthstone/fastmcp_rust/commit/ecc4b9dd086e33b4353bc2b79a976b3d5385f7a4))
- **OIDC integration** -- OpenID Connect provider discovery, JWKS fetching/caching, ID token validation and claims extraction. ([`ecc4b9d`](https://github.com/Dicklesworthstone/fastmcp_rust/commit/ecc4b9dd086e33b4353bc2b79a976b3d5385f7a4))
- **Bidirectional MCP features** -- Full-duplex transport handling with `BidirectionalSenders` for sampling and elicitation. Session capability queries: `supports_sampling()`, `supports_elicitation()`, `supports_roots()`. ([`ecc4b9d`](https://github.com/Dicklesworthstone/fastmcp_rust/commit/ecc4b9dd086e33b4353bc2b79a976b3d5385f7a4))
- **Docket distributed task queue** -- Background job processing with `DocketClient`, worker pool, `DocketBackend` trait, memory backend (with Redis stub). Task lifecycle: submit, claim, execute, retry with backoff. ([`154136b`](https://github.com/Dicklesworthstone/fastmcp_rust/commit/154136bd2c5bc3ea11596bba521b59c540c8ca38))
- **Middleware pipeline** -- Response caching with LRU eviction, token-bucket rate limiting, tool transformation pipeline, SSE event store with TTL for resumability. ([`e6801d9`](https://github.com/Dicklesworthstone/fastmcp_rust/commit/e6801d9dfa1691b08847961931d0497cb335a115))
- **Providers module** -- Filesystem resource provider and auth/caching infrastructure refactoring. ([`aaa9845`](https://github.com/Dicklesworthstone/fastmcp_rust/commit/aaa98456aea44c88ca8cb8ec45d049217123e9af))
- **Tag-based filtering** -- Filter tools, resources, and prompts by tags in list requests. ([`56497ce`](https://github.com/Dicklesworthstone/fastmcp_rust/commit/56497ced6875da2c48f0d0974482ce11385660d9))
- **Dynamic enable/disable** -- Per-session visibility control for tools, resources, and prompts. ([`1309d4e`](https://github.com/Dicklesworthstone/fastmcp_rust/commit/1309d4edc10969f89c4083c2dfc5c7b39fae22d9))
- **Strict input validation** -- Optional `strict_input_validation` setting for schema enforcement. ([`2536c29`](https://github.com/Dicklesworthstone/fastmcp_rust/commit/2536c29807e41c16b2c1a6895fd2bd7b858dc1fd))
- **Cross-component access and server composition** -- Enable servers to reference each other's tools, resources, and prompts for compositional architectures. ([`b19bdd2`](https://github.com/Dicklesworthstone/fastmcp_rust/commit/b19bdd25d308254e6b61a05e49918ce37bc9a430))
- **Error masking and server builder improvements** -- Core error type improvements and builder pattern refinements. ([`f698b93`](https://github.com/Dicklesworthstone/fastmcp_rust/commit/f698b931239678fae7f6cb8b86b0a9b9873cd696))

### Client Features (2026-01-27 through 2026-01-28)

- **MCP configuration file support** -- Client-side server registry loaded from configuration files, supporting named server definitions. ([`36fe087`](https://github.com/Dicklesworthstone/fastmcp_rust/commit/36fe08784cdec5b0fef8167af284100dfa810809))
- **Capabilities access from McpContext** -- Handlers can query server and client capabilities at runtime. ([`940ae19`](https://github.com/Dicklesworthstone/fastmcp_rust/commit/940ae19eefcb2f81440c7f4dfb3ba6d85097b639))
- **Resource cleanup and request ID validation** -- Client properly cleans up resources on disconnect and validates request IDs. ([`8b583fb`](https://github.com/Dicklesworthstone/fastmcp_rust/commit/8b583fb6307609c42f524259ce5419e3da629357))

### CLI (2026-01-27 through 2026-01-28)

- **`fastmcp-cli` crate** -- Command-line tool for MCP server development and management. ([`b71c2d3`](https://github.com/Dicklesworthstone/fastmcp_rust/commit/b71c2d38882a85f139f5c89b0d1f45a82e9aa41b))
- **`list` and `test` commands** -- Introspect server tools/resources/prompts and run test suites. ([`dfb8a0e`](https://github.com/Dicklesworthstone/fastmcp_rust/commit/dfb8a0e3f5c01e5476859c04388cb626b6c0c3f9))
- **`dev` command with hot reloading** -- Watch for source changes and restart the server automatically. ([`92aefba`](https://github.com/Dicklesworthstone/fastmcp_rust/commit/92aefbac6a04d930876dac4f66b8282aa8f372ee))
- **`tasks` command** -- Background task management via CLI. ([`c669f1b`](https://github.com/Dicklesworthstone/fastmcp_rust/commit/c669f1b2ad2dc9220daa53a42903249e00735f72))
- **Install commands with shared config helpers** -- CLI install subcommands with common configuration management. ([`142f583`](https://github.com/Dicklesworthstone/fastmcp_rust/commit/142f583a02164c2dcf67d1bcc63b2418537b8b2d))

### Performance (2026-01-27)

- **`Cow<'static, str>` for JSON-RPC version field** -- Avoid allocating the constant `"2.0"` string on every message. ([`9c3fb79`](https://github.com/Dicklesworthstone/fastmcp_rust/commit/9c3fb7929bb36ac34f08d32ae7982af5a7b021c5))
- **Deferred buffer compaction in codec** -- Reduce unnecessary memory copies in the NDJSON codec. ([`7093766`](https://github.com/Dicklesworthstone/fastmcp_rust/commit/7093766c3c7ce22a84e72a377df7fd801358827a))
- **Pre-sort resource template keys by specificity** -- Improve resource routing lookup performance. ([`7a40f56`](https://github.com/Dicklesworthstone/fastmcp_rust/commit/7a40f56e8f3df70971f7df739465a7b7264feb4b))
- **Optimize schema validation algorithms** -- Reduce validation overhead for JSON schema checks. ([`d9ac701`](https://github.com/Dicklesworthstone/fastmcp_rust/commit/d9ac701412ea839c02eb899b78f45d69ddca5260))

### Hardening (2026-01-27)

- **Graceful lock recovery** -- Replace `panic!` on mutex poisoning with graceful recovery in server and router. ([`fc5eb8f`](https://github.com/Dicklesworthstone/fastmcp_rust/commit/fc5eb8fbe490270928b66ab5aa6505bf6758ed38))
- **Fail-safe URI template fallback** -- Router falls back gracefully instead of panicking on invalid URI templates. ([`9db1215`](https://github.com/Dicklesworthstone/fastmcp_rust/commit/9db121531bc42aa0ade88f7f06f42186b1645b90))
- **Client timeout propagation** -- `Client::from_parts` correctly passes `timeout_ms`. ([`67366d5`](https://github.com/Dicklesworthstone/fastmcp_rust/commit/67366d553f56bf9b56c76489f86fb1155be04f88))

### Testing Infrastructure (2026-01-28)

- **Testing module** -- `McpContext::for_testing()`, `TestServer`, `TestClient` constructors for unit testing handlers without a running server. ([`51459a5`](https://github.com/Dicklesworthstone/fastmcp_rust/commit/51459a5de7cfd016e79a1fb599be65934f035a4f))
- **Comprehensive E2E test suites** -- End-to-end tests for all transport types, CLI commands, task management, middleware, and protocol workflows. ([`0d7451b`](https://github.com/Dicklesworthstone/fastmcp_rust/commit/0d7451b9eb0503e09cf41e1ca84f4908082e2750), [`b67cb49`](https://github.com/Dicklesworthstone/fastmcp_rust/commit/b67cb490dcb228f042b3ed759d0b2820e2fc650a), [`098059f`](https://github.com/Dicklesworthstone/fastmcp_rust/commit/098059f721bbba446637feade3317a0772ede23a))

### Documentation and Licensing

- **Feature parity assessment** -- Comprehensive analysis vs Python FastMCP v2.14.4, initially at ~90-95%, reaching 100% by 2026-01-28. ([`408b50e`](https://github.com/Dicklesworthstone/fastmcp_rust/commit/408b50e762851c3e04fd3dda0979dadfc22195c9), [`a075688`](https://github.com/Dicklesworthstone/fastmcp_rust/commit/a0756881d864d952d1d725880816b3e9797e76dd))
- **MIT License** with attribution to original FastMCP Python library. ([`812269b`](https://github.com/Dicklesworthstone/fastmcp_rust/commit/812269b51b7972689d2fdaed691d3a5512e35d8c), [`ca4964a`](https://github.com/Dicklesworthstone/fastmcp_rust/commit/ca4964ae161b59fe53949194fe91444af4e68b1f))
