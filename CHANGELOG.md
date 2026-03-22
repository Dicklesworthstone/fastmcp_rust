# Changelog

All notable changes to [FastMCP Rust](https://github.com/Dicklesworthstone/fastmcp_rust) are documented here.

Format: version timeline, organized by landed capabilities. Commit links point to representative commits, not exhaustive diffs. Versions with a GitHub Release are marked accordingly.

---

## [Unreleased] (after v0.2.0)

> **Covers:** 2026-02-15 through 2026-03-20 (HEAD at [`6e86ca5`](https://github.com/Dicklesworthstone/fastmcp_rust/commit/6e86ca5c6776bdbca2c01f1a9c5d43fa7e1ee34b))
> **Diff:** [`v0.2.0...main`](https://github.com/Dicklesworthstone/fastmcp_rust/compare/v0.2.0...main)

### Added

- **Turnkey HTTP server with Streamable HTTP transport** -- `Server::run_http()` for web-based MCP deployments without manual transport wiring ([`693bc06`](https://github.com/Dicklesworthstone/fastmcp_rust/commit/693bc06f83ab6e579f1d8ea3167d4a5495b3e430))
- **Phase 1 concurrent tool dispatch** (#14) -- lock-free read-only dispatch path for parallel tool execution ([`9a24313`](https://github.com/Dicklesworthstone/fastmcp_rust/commit/9a243130c0660e1465030d662d5494c43cd4ca88))
- **Concurrent read-only HTTP request handling** via session snapshots ([`402bc43`](https://github.com/Dicklesworthstone/fastmcp_rust/commit/402bc43b7a2470abebef3ed2a04088f39feb7d53))
- **Public `dispatch_request` API** (#15) and `dispatch_request_concurrent` for embedding the server in custom hosts ([`27f00a6`](https://github.com/Dicklesworthstone/fastmcp_rust/commit/27f00a62c29c7bb68c4c5425b344f916d70c8663), [`d2fd587`](https://github.com/Dicklesworthstone/fastmcp_rust/commit/d2fd587e158b644b32e3b20a66416d6e155dced3))
- **Request-scoped auth context, typed session state, and resource template validation** ([`5e9086c`](https://github.com/Dicklesworthstone/fastmcp_rust/commit/5e9086c94f74a3cd1e36c6aee391b0ac229769f1))
- **Enhanced resource handling, session management, and middleware hooks** ([`36bcf82`](https://github.com/Dicklesworthstone/fastmcp_rust/commit/36bcf826d925327b5cafc7485d99df4e3b2f481b))
- **Re-export `ToolAnnotations` from `fastmcp-protocol`** for downstream ergonomics ([`c6e6e1c`](https://github.com/Dicklesworthstone/fastmcp_rust/commit/c6e6e1c6064fa5a22f9da858ed49e2963a194e33))

### Fixed

- **I/O reactor and `Cx` context in `block_on`** (#18) -- enables I/O-heavy tools to work from synchronous entry points ([`d26379f`](https://github.com/Dicklesworthstone/fastmcp_rust/commit/d26379f8686e9a85487f2af49d551f29abf4702e))
- **Session snapshot isolation, duplicate request rejection, HTTP cancellation responsiveness**, and pre-failed task short-circuit ([`a3d0cb7`](https://github.com/Dicklesworthstone/fastmcp_rust/commit/a3d0cb73b7f68710d2002300fcad36fb2ce3ed80))
- Allow `Pending -> Failed` state transition in task manager ([`1f265da`](https://github.com/Dicklesworthstone/fastmcp_rust/commit/1f265dae0c263eafce184fec9dc740404ea24a05))
- Correct `quorum_met` in `quorum_timeout` all-done branch ([`ade6f9d`](https://github.com/Dicklesworthstone/fastmcp_rust/commit/ade6f9de7e0b6300725b8d8c0c6d92276aeaf9a0))
- Log mutex poisoning in `dispatch_request_concurrent` instead of panicking ([`7fa856a`](https://github.com/Dicklesworthstone/fastmcp_rust/commit/7fa856a27bb28a359a082df606d7616ae475bf65))

### Changed

- License updated to MIT with OpenAI/Anthropic Rider ([`35c685b`](https://github.com/Dicklesworthstone/fastmcp_rust/commit/35c685bdce89a8e3ffba6f0c660dce867678576a))
- Dependency upgrades and loosened version specs across workspace ([`9c882fc`](https://github.com/Dicklesworthstone/fastmcp_rust/commit/9c882fc348084903506b776bca7ddba7bdc04360))
- Bumped GH Actions versions (upload-artifact v7, download-artifact v8)

---

## [v0.2.0] -- 2026-02-15 (GitHub Release)

> **Tag:** [`v0.2.0`](https://github.com/Dicklesworthstone/fastmcp_rust/releases/tag/v0.2.0)
> **Commit:** [`a682584`](https://github.com/Dicklesworthstone/fastmcp_rust/commit/a682584f0638e2ca194176d04a4c2b4276cdd51f)
> **Diff from initial commit:** [`fe916bf...v0.2.0`](https://github.com/Dicklesworthstone/fastmcp_rust/compare/fe916bf...v0.2.0) (344 commits, 162 files, +101k lines)
> **Crates:** fastmcp-core, fastmcp-derive, fastmcp-protocol, fastmcp-transport, fastmcp-client, fastmcp-server, fastmcp-console, fastmcp-cli, fastmcp-rust -- all at 0.2.0

This is the first published release encompassing the full feature set. The initial commit on 2026-01-18 already contained a working multi-crate workspace; v0.2.0 represents the first cut deemed ready for crates.io.

### Core Framework (Jan 18 -- Jan 21)

- **Initial multi-crate workspace** with `#[tool]`, `#[resource]`, `#[prompt]` attribute macros, cancel-correct async via [asupersync](https://github.com/Dicklesworthstone/asupersync), budget-based timeouts, four-valued `Outcome` type, and structured concurrency ([`fe916bf`](https://github.com/Dicklesworthstone/fastmcp_rust/commit/fe916bf4c40eb34ddcc1c497526f511a9fd56b25))
- **Transport layer:** stdio (NDJSON), SSE, and WebSocket transports with CRLF handling and codec abstraction
- **Server:** router with URI template matching, session management, handler registry, and server builder pattern
- **Client:** MCP client with builder, session management, and request ID validation
- **Protocol:** JSON-RPC 2.0 message types, JSON Schema generation, MCP message definitions

### Console & Rich Output (Jan 20 -- Jan 21)

- **`fastmcp-console` crate** with rich startup banner, stats renderer, resource table with URI highlighting and tree view, comprehensive table renderers ([`62fe623`](https://github.com/Dicklesworthstone/fastmcp_rust/commit/62fe623f3226d9fb4c13ba66d55b32b0d9a26fd5))

### Transport Hardening (Jan 24 -- Jan 27)

- Transport runners with async I/O enhancements and codec robustness ([`f5a9479`](https://github.com/Dicklesworthstone/fastmcp_rust/commit/f5a9479c6922c3bb8be41c243c43cd95a4a97bbe))
- **RFC 6455 WebSocket compliance:** reject invalid frames, reject interleaved binary frames during fragmentation, CSPRNG mask keys, mask enforcement ([`8103b30`](https://github.com/Dicklesworthstone/fastmcp_rust/commit/8103b30d9cc2500281dc7b44ab229dfa889e4982), [`ddeaf57`](https://github.com/Dicklesworthstone/fastmcp_rust/commit/ddeaf577ad9d0deb3c582b21b975849341f2b16c))
- **SSE safety:** bounded line/event size limits to prevent memory exhaustion ([`4a86245`](https://github.com/Dicklesworthstone/fastmcp_rust/commit/4a862455abb1914ad3e96cbf0af5c862c4b61e5c))

### Protocol Feature Parity (Jan 27 -- Jan 28)

Comprehensive sprint to reach 100% feature parity with Python FastMCP v2.14.4:

- **Sampling/createMessage** protocol ([`2a296c9`](https://github.com/Dicklesworthstone/fastmcp_rust/commit/2a296c93d92c97679deced913140cbb8e691bdc8))
- **Elicitation and Roots** MCP protocol methods ([`1e3973a`](https://github.com/Dicklesworthstone/fastmcp_rust/commit/1e3973a35630c4b9ccaaa81dbbd7ada75a468ffa))
- **Completion messages** and expanded elicitation types
- **ToolAnnotations** for MCP tool metadata ([`94d3c7b`](https://github.com/Dicklesworthstone/fastmcp_rust/commit/94d3c7b15cc6ad784a6cf680d93d7adeebdcf7af))
- **`output_schema`** field on Tool definitions
- **Icon infrastructure** for component metadata ([`af5b567`](https://github.com/Dicklesworthstone/fastmcp_rust/commit/af5b5675eee4680cfc4b523a46c0b509fd2b80e8))
- **Version metadata** and **tags infrastructure** for components ([`c7b4fe0`](https://github.com/Dicklesworthstone/fastmcp_rust/commit/c7b4fe01cb000206afdb3c671e969f6ed3378d83), [`7ca0d59`](https://github.com/Dicklesworthstone/fastmcp_rust/commit/7ca0d59d7373d3dcbe87908b4ca651598fef5296))

### Server Capabilities (Jan 27 -- Jan 28)

- **OAuth 2.1 authorization server** and bidirectional MCP features ([`ecc4b9d`](https://github.com/Dicklesworthstone/fastmcp_rust/commit/ecc4b9dd086e33b4353bc2b79a976b3d5385f7a4))
- **Docket distributed task queue** system ([`154136b`](https://github.com/Dicklesworthstone/fastmcp_rust/commit/154136bd2c5bc3ea11596bba521b59c540c8ca38))
- **Middleware implementations** and transport enhancements ([`e6801d9`](https://github.com/Dicklesworthstone/fastmcp_rust/commit/e6801d9dfa1691b08847961931d0497cb335a115))
- **Auth, state management, middleware, and task systems** ([`41c4104`](https://github.com/Dicklesworthstone/fastmcp_rust/commit/41c4104643f0e8ab8e530e8e9e1ab63e4ac3ef03))
- **Providers module** with auth/caching infrastructure ([`aaa9845`](https://github.com/Dicklesworthstone/fastmcp_rust/commit/aaa9845))
- **Cross-component access** and server composition ([`b19bdd2`](https://github.com/Dicklesworthstone/fastmcp_rust/commit/b19bdd25d308254e6b61a05e49918ce37bc9a430))
- **Dynamic enable/disable** per-session visibility ([`1309d4e`](https://github.com/Dicklesworthstone/fastmcp_rust/commit/1309d4edc10969f89c4083c2dfc5c7b39fae22d9))
- **Strict input validation** setting ([`2536c29`](https://github.com/Dicklesworthstone/fastmcp_rust/commit/2536c29807e41c16b2c1a6895fd2bd7b858dc1fd))
- **Tag-based filtering** for tools, prompts, and resources ([`56497ce`](https://github.com/Dicklesworthstone/fastmcp_rust/commit/56497ced6875da2c48f0d0974482ce11385660d9))
- **Capabilities access** from McpContext ([`940ae19`](https://github.com/Dicklesworthstone/fastmcp_rust/commit/940ae19eefcb2f81440c7f4dfb3ba6d85097b639))
- **Error masking** and server builder improvements ([`f698b93`](https://github.com/Dicklesworthstone/fastmcp_rust/commit/f698b931239678fae7f6cb8b86b0a9b9873cd696))
- **Tool handler lifecycle hooks** extended

### Client Enhancements (Jan 27 -- Jan 28)

- **MCP configuration file support** for server registry ([`36fe087`](https://github.com/Dicklesworthstone/fastmcp_rust/commit/36fe08784cdec5b0fef8167af284100dfa810809))
- **HTTP transport** for web-based MCP deployments ([`286eed9`](https://github.com/Dicklesworthstone/fastmcp_rust/commit/286eed930723e7a3a4bc18a94e58cd3f6350734a))
- **Client builder, server proxy**, and session management improvements
- **Resource cleanup** and request ID validation

### CLI Tooling (Jan 27 -- Feb 9)

- **`fastmcp-cli` crate** for MCP server tooling ([`b71c2d3`](https://github.com/Dicklesworthstone/fastmcp_rust/commit/b71c2d38882a85f139f5c89b0d1f45a82e9aa41b))
- **`fastmcp dev`** command with hot reloading ([`92aefba`](https://github.com/Dicklesworthstone/fastmcp_rust/commit/92aefbac6a04d930876dac4f66b8282aa8f372ee))
- **`list` and `test`** commands with full options
- **`tasks`** command for background task management
- **`install`** commands with shared config helpers
- Exit code propagation from `run` command

### Macro System (Jan 27 -- Feb 13)

- **Extended `#[tool]` macro:** annotations, version, tags support ([`4244ab8`](https://github.com/Dicklesworthstone/fastmcp_rust/commit/4244ab8ec9ae58ed96fe4945fc3e2fc4ea3d2cb0))
- **Extended `#[resource]` and `#[prompt]` macros:** version and tags support ([`0f78298`](https://github.com/Dicklesworthstone/fastmcp_rust/commit/0f782988e6761e1a0a3d5ad190fcd3042f363f1e))
- **`Vec<ResourceContent>` return type** support in `#[resource]` macro ([`f9f3f3e`](https://github.com/Dicklesworthstone/fastmcp_rust/commit/f9f3f3ee64061763c6ad5b8359b76dce805aac3a))
- Crate renamed from `fastmcp-macros` to `fastmcp-derive` ([`e50dbd1`](https://github.com/Dicklesworthstone/fastmcp_rust/commit/e50dbd1eecbd611f3f1fb57fc7932b61bb143f2e))
- Facade crate renamed to `fastmcp-rust` ([`0a53d3c`](https://github.com/Dicklesworthstone/fastmcp_rust/commit/0a53d3c7376157af98d53a413a1955c3de74e9ce))

### Performance (Jan 27)

- `Cow<'static, str>` for JSON-RPC version field to avoid repeated allocations
- Deferred buffer compaction in codec
- Pre-sorted resource template keys by specificity for faster matching
- Optimized schema validation algorithms

### Security & Robustness (Jan 27 -- Feb 11)

- **Real crypto for OAuth/OIDC** and hardened HTTP parsing ([`df51b46`](https://github.com/Dicklesworthstone/fastmcp_rust/commit/df51b46adbc4b2f3c30bf501b539edc1bd8fbeab))
- **OIDC RS256/JWKS** misrepresentation fix ([`2fb19c6`](https://github.com/Dicklesworthstone/fastmcp_rust/commit/2fb19c61e1a678992cdc34c593e54103b093fbd4))
- **Access token values redacted** from Debug output ([`5615ee4`](https://github.com/Dicklesworthstone/fastmcp_rust/commit/5615ee4f9e22563df41bbb45e21f5bf84fb6080a))
- Replaced all `panic-on-poison` with graceful lock recovery ([`fc5eb8f`](https://github.com/Dicklesworthstone/fastmcp_rust/commit/fc5eb8fbe490270928b66ab5aa6505bf6758ed38))
- Replaced panic on invalid URI template with fail-safe fallback ([`9db1215`](https://github.com/Dicklesworthstone/fastmcp_rust/commit/9db121531bc42aa0ade88f7f06f42186b1645b90))
- FIFO stream queue enforcement and invalid stream send rejection ([`3b7998e`](https://github.com/Dicklesworthstone/fastmcp_rust/commit/3b7998e7b2d227f402d82677d43cd44f089b128d))
- Poison-safe OAuth stats and pending-request lock ([`20375f8`](https://github.com/Dicklesworthstone/fastmcp_rust/commit/20375f81de71120b0712074599749a7c76bdfe1d), [`2522c0b`](https://github.com/Dicklesworthstone/fastmcp_rust/commit/2522c0bc0199dfd85d9f3005eeaea929183a2f32))
- Client honors `Cx` cancellation during stdio retry loop ([`e7371b3`](https://github.com/Dicklesworthstone/fastmcp_rust/commit/e7371b341926c7619ded6491265ca62019f073f7))
- Propagate mutex poison errors in `StreamableHttpTransport` instead of silently dropping ([`5d4c2c3`](https://github.com/Dicklesworthstone/fastmcp_rust/commit/5d4c2c3119238461e97c7878346767e08b4ab59c))
- Pagination cursor overflow fix and ClientBuilder retry overflow fix ([`3ea17f8`](https://github.com/Dicklesworthstone/fastmcp_rust/commit/3ea17f8f8ab9f7489c8589d9d95d49793d2deccf), [`225e4ec`](https://github.com/Dicklesworthstone/fastmcp_rust/commit/225e4ec9d88686c25c7b8efeba617be5382c24b0))
- Pagination safety limits and infinite loop detection in client list methods ([`5077aca`](https://github.com/Dicklesworthstone/fastmcp_rust/commit/5077aca66b3912e767237a4adf3c295fc3624dbc))
- Hardened TaskManager runtime startup and task scheduling ([`c6ec853`](https://github.com/Dicklesworthstone/fastmcp_rust/commit/c6ec853df55345ff04fcae5ba97ea0f1a69705f7))

### Testing (Jan 28 -- Feb 14)

Massive test coverage campaign: 172 test-related commits adding unit tests, E2E tests, and compile-time (`trybuild`) tests across every crate.

- **E2E suites:** stdio NDJSON, SSE streaming, WebSocket, HTTP, CLI commands, background tasks, client session management, task management, middleware integration, auth flows (static/JWT/OAuth)
- **Unit test waves:** 56-bead coverage epic covering protocol, server (auth, builder, handler, router, tasks, session, middleware, caching, rate limiting, docket, OAuth, OIDC, proxy, bidirectional, transform), client (session, builder, config), transport (codec, memory, trait, SSE, WebSocket, HTTP, stdio), core (context, error, duration, logging), console (banner, diagnostics, status, stats, renderer, formatter, subscriber), and macros
- **De-mocking campaign:** replaced mock middleware/handlers with real `#[tool]` handlers and real OAuth flows in tests
- **CI:** coverage job with lcov artifact upload ([`4abbbf8`](https://github.com/Dicklesworthstone/fastmcp_rust/commit/4abbbf8e3c08006f7f196b458a54f72d9586b154))
- All clippy pedantic warnings resolved ([`f9cd3d8`](https://github.com/Dicklesworthstone/fastmcp_rust/commit/f9cd3d833efa0e5730fbf987e1b42df0d076c3f0))

### Publishing & Dependencies

- All crates prepared for crates.io publishing ([`965dad9`](https://github.com/Dicklesworthstone/fastmcp_rust/commit/965dad971b42e2955db52797a6fe17ba7a935bcb))
- Switched `asupersync` and `rich_rust` from local path/git refs to crates.io releases
- Workspace dependency versions aligned for 0.2.0

---

## Initial Commit -- 2026-01-18

> **Commit:** [`fe916bf`](https://github.com/Dicklesworthstone/fastmcp_rust/commit/fe916bf4c40eb34ddcc1c497526f511a9fd56b25)
> **Stats:** 51 files, +14,700 lines

The initial commit landed a working multi-crate MCP framework:

- **9 workspace crates:** fastmcp (facade), fastmcp-core, fastmcp-macros, fastmcp-protocol, fastmcp-transport, fastmcp-server, fastmcp-client, plus examples
- **Transports:** stdio, SSE, WebSocket
- **Macros:** `#[tool]`, `#[resource]`, `#[prompt]`
- **Runtime:** cancel-correct async via asupersync, budget-based timeouts, `Outcome<T, E>` type
- **Infrastructure:** CI workflow, release workflow, dependabot config
- **Examples:** calculator, echo, notes, weather servers and benchmark harness

---

## Version Reference

| Version | Date | Tag | GitHub Release | Commit |
|---------|------|-----|----------------|--------|
| 0.2.0 | 2026-02-15 | `v0.2.0` | [Yes](https://github.com/Dicklesworthstone/fastmcp_rust/releases/tag/v0.2.0) | [`a682584`](https://github.com/Dicklesworthstone/fastmcp_rust/commit/a682584f0638e2ca194176d04a4c2b4276cdd51f) |
| Initial | 2026-01-18 | -- | -- | [`fe916bf`](https://github.com/Dicklesworthstone/fastmcp_rust/commit/fe916bf4c40eb34ddcc1c497526f511a9fd56b25) |

## Workspace Crates

| Crate | Purpose |
|-------|---------|
| `fastmcp-rust` | Facade re-exporting all sub-crates via `prelude::*` |
| `fastmcp-core` | `McpContext`, `Budget`, `Outcome`, logging, runtime |
| `fastmcp-derive` | `#[tool]`, `#[resource]`, `#[prompt]` proc macros |
| `fastmcp-protocol` | JSON-RPC 2.0, MCP message types, JSON Schema, `ToolAnnotations` |
| `fastmcp-transport` | Stdio, SSE, WebSocket, HTTP, async I/O, codec |
| `fastmcp-server` | Server builder, router, session, auth, middleware, task queue (Docket), OAuth 2.1, OIDC |
| `fastmcp-client` | MCP client, builder, session, config file support |
| `fastmcp-console` | Rich terminal banner, stats renderer, table renderers |
| `fastmcp-cli` | CLI: `run`, `dev`, `list`, `test`, `inspect`, `install`, `tasks` |
