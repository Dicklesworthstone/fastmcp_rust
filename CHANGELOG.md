# Changelog

Selected notable changes to [FastMCP Rust](https://github.com/Dicklesworthstone/fastmcp_rust) are documented here. Exact per-release contents remain authoritative in the linked release tags and repository diffs.

Format: version timeline, organized by landed capabilities. Commit links point to representative commits, not exhaustive diffs. Versions with a GitHub Release are marked accordingly.

---

## [Unreleased] (after v0.7.0)

### Macros / schema generation

- **`Option<T>` tool parameters are now nullable on the wire.** The generated
  input schema widens `Option<T>` to a `["<T>", "null"]` type union, and the
  generated extraction treats an explicit JSON `null` argument exactly like an
  omitted field (both produce `None`; a declared `default` still applies).
  Previously an explicit `null` failed input-schema validation and, past that,
  deserialization — surfacing as `InvalidParams` naming the field. Required
  (non-`Option`) parameters still reject `null` loudly. The same widening
  applies to `Option<T>` fields in `#[derive(JsonSchema)]` structs, whose
  serde deserialization already accepted `null`. Schemas without a `"type"`
  keyword (empty or custom `json_schema()` shapes) are left untouched.
  (Requested via mcp_agent_mail_rust GH#255 transcript-safe identity parity.)

---

## [v0.7.0](https://github.com/Dicklesworthstone/fastmcp_rust/releases/tag/v0.7.0) -- 2026-08-20 (GitHub Release)

Product + maintenance release (pre-1.0 minor bump). Workspace crates move to
0.7.0. This does **not** claim aggregate MCP 2026-07-28 conformance, FND-01
freeze, or GATE-ALL-MCP-READY.

### Toolchain

- **Dated nightly** -- `rust-toolchain.toml` moves from `nightly-2026-08-19`
  to `nightly-2026-08-20` / rustc 1.100.0-nightly. Workspace `rust-version`
  stays `1.100`. The last FND-01 evidence snapshot still records
  `nightly-2026-07-11` until that harness is re-attested.

### Dependencies

- **asupersync** `=0.4.8` → `=0.4.9` -- latest crates.io patch on the v0.4.3
  public compatibility floor (additive `RuntimeHandle` request-Cx / blocking-pool
  APIs, SQLite cancel correctness, owned-OTLP mapping). No public item was
  removed or renamed. Transitive FrankenSuite crates (`franken-kernel`,
  `franken-evidence`, `franken-decision`, `asupersync-macros`) move with it.
- **cap-std / cap-fs-ext** `=4.0.2` → `=4.0.3` -- latest capability-fs patch
  used by the filesystem resource provider.
- **rich_rust** stays `=0.2.3` (already latest stable). FastMCP does not
  directly depend on frankensqlite, frankensearch, or franken_networkx.
- All other direct exact pins remain latest stable (notify 9 / argon2 0.6
  remain RC-only and were not taken).

### Server / proxy product fixes

- **as_proxy WebSocket completions advertise/omit** -- live `bind_websocket`
  as_proxy_typed has the same initialize advertise/omit split as HTTP and
  stdio. (`bd-campaign-product-remainder-2t3gf.10`, [`0f0a5bf`](https://github.com/Dicklesworthstone/fastmcp_rust/commit/0f0a5bf))
- **Prefixed subscribe / resource updates** -- mounted and as_proxy subscribe
  rewrite inbound URIs; nested prefixes strip at `://` rather than
  `split_once('/')`; identity rewrites no longer double-deliver
  `resources/updated`. ([`41cbf0e`](https://github.com/Dicklesworthstone/fastmcp_rust/commit/41cbf0e), [`af9c0b0`](https://github.com/Dicklesworthstone/fastmcp_rust/commit/af9c0b0), [`c99f71e`](https://github.com/Dicklesworthstone/fastmcp_rust/commit/c99f71e))
- **TransformedTool final hooks** -- rename/hide wrappers forward timeout,
  exact final catalog, MRTR resume, and `call_final` instead of promoting
  legacy `call()`. ([`29c4fb9`](https://github.com/Dicklesworthstone/fastmcp_rust/commit/29c4fb9))
- **HTTP proxy listen** -- handshake and SSE wait no longer hold the route
  mutex. ([`619d621`](https://github.com/Dicklesworthstone/fastmcp_rust/commit/619d621), [`360c225`](https://github.com/Dicklesworthstone/fastmcp_rust/commit/360c225))
- **Nested era dispatch / exact-2024 list cursors / SSE opener bind /
  hidden-arg defaults / completion mount transfer** -- remaining dual-era
  product holes closed after v0.6.0. ([`9208fb5`](https://github.com/Dicklesworthstone/fastmcp_rust/commit/9208fb5), [`bc7cdf3`](https://github.com/Dicklesworthstone/fastmcp_rust/commit/bc7cdf3), [`879eead`](https://github.com/Dicklesworthstone/fastmcp_rust/commit/879eead), [`f4a21c3`](https://github.com/Dicklesworthstone/fastmcp_rust/commit/f4a21c3), [`d5e184b`](https://github.com/Dicklesworthstone/fastmcp_rust/commit/d5e184b))

**Exact changes:** [v0.6.0...v0.7.0](https://github.com/Dicklesworthstone/fastmcp_rust/compare/v0.6.0...v0.7.0)

---

## [v0.6.0](https://github.com/Dicklesworthstone/fastmcp_rust/releases/tag/v0.6.0) -- 2026-08-18 (GitHub Release)

Maintenance release: latest crates.io library pins, current dated nightly, and
a pre-1.0 minor bump. Workspace crates move to 0.6.0. This does **not** claim
aggregate MCP 2026-07-28 conformance, FND-01 freeze, or GATE-ALL-MCP-READY.

### Toolchain

- **Dated nightly** -- `rust-toolchain.toml` moves from `nightly-2026-07-11`
  / rustc 1.99.0-nightly to `nightly-2026-08-19` / rustc 1.100.0-nightly.
  Workspace `rust-version` is `1.100`. The last FND-01 evidence snapshot still
  records the previous nightly until that harness is re-attested.

### Dependencies

- **asupersync** `=0.4.5` → `=0.4.8` -- latest crates.io patch on the v0.4.3
  public compatibility floor (timer/cancel, HTTP/1 RFC OWS, ambient `Cx` guard
  teardown). No public item was removed or renamed.
- **redis** (optional `redis-tasks` only) `=1.4.1` → `=1.6.0` -- additive
  streams/cluster/sentinel fixes. Redis remains absent from the default graph.
- All other direct exact pins were already at latest stable (notify 9 / argon2
  0.6 remain RC-only and were not taken).

**Exact changes:** [v0.5.0...v0.6.0](https://github.com/Dicklesworthstone/fastmcp_rust/compare/v0.5.0...v0.6.0)

---

## [v0.5.0](https://github.com/Dicklesworthstone/fastmcp_rust/releases/tag/v0.5.0) -- 2026-08-18 (GitHub Release)

Feature release (pre-1.0 minor bump) of the dual-era `as_proxy` gateway.
Workspace crates move to 0.5.0. This does **not** claim aggregate MCP
2026-07-28 conformance, FND-01 freeze, or GATE-ALL-MCP-READY.

### Proxy gateway

- **Completions advertise/omit** -- `as_proxy` advertises `completions` only
  when the proxied upstream's initialize payload includes that member (exact
  2024) or discovery reports a final completion handler (modern). Public
  `completion_handler` / `legacy_completion_handler` /
  `legacy_resource_template_completion_handler` builders now set the same
  capability. Prefixed catalog install binds completion handlers only after
  the target actually registers. ([`23190f9`](https://github.com/Dicklesworthstone/fastmcp_rust/commit/23190f9), [`8feeedf`](https://github.com/Dicklesworthstone/fastmcp_rust/commit/8feeedf))
- **on_duplicate / strict input / list page / session state** -- colliding
  catalog members skip one component and keep the rest; gateway
  `strict` input is honored on proxied FinalTools; list page size and
  session-state bags are proven over HTTP, WebSocket, and stdio. ([`252090e`](https://github.com/Dicklesworthstone/fastmcp_rust/commit/252090e), [`c07d870`](https://github.com/Dicklesworthstone/fastmcp_rust/commit/c07d870), [`7f138fc`](https://github.com/Dicklesworthstone/fastmcp_rust/commit/7f138fc))
- **Compose, request timeout, includeTags** -- `as_proxy` compose-from-prompt,
  gateway `request_timeout` via `hold_echo`, and includeTags filtering are
  live. Nested `isError` tool text is preserved through the proxy. ([`3e9fb00`](https://github.com/Dicklesworthstone/fastmcp_rust/commit/3e9fb00), [`369a5d0`](https://github.com/Dicklesworthstone/fastmcp_rust/commit/369a5d0))
- **Exact-2024 completion progressToken** -- stdio completion forwards stamp
  the request `progressToken`. Panic sanitization on the gateway is covered
  by e2e. ([`2511b76`](https://github.com/Dicklesworthstone/fastmcp_rust/commit/2511b76), [`1613bfa`](https://github.com/Dicklesworthstone/fastmcp_rust/commit/1613bfa))

### Release packaging

- First GitHub Release to include a Windows `x86_64-pc-windows-msvc` CLI
  archive (`fastmcp-windows-amd64.zip`) alongside the existing Linux and
  macOS `tar.xz` assets. Native Windows build hosts were offline; the
  Windows binary is produced with `cargo-xwin` on the Linux builder.

**Exact changes:** [v0.4.0...v0.5.0](https://github.com/Dicklesworthstone/fastmcp_rust/compare/v0.4.0...v0.5.0)

---

## [v0.4.0](https://github.com/Dicklesworthstone/fastmcp_rust/releases/tag/v0.4.0) -- 2026-08-17 (GitHub Release)

Breaking release (pre-1.0 minor bump): `Legacy2024EnvelopeError` gains a new
public `Method` variant, which breaks exhaustive matchers downstream. All
workspace crates move to 0.4.0. This release covers work landed since the
v0.3.2 release on 2026-06-18.

### MCP 2026-07-28 support (in progress)

MCP 2026-07-28 support is under implementation and remains unverified.  
Aggregate MCP 2026-07-28 support is not claimed by FND-01.

- **FND-01 foundation work (in progress)** — preparing authoritative protocol/SDK/toolchain evidence, core crypto/URI pins, and integration-surface dependency policy for final attestation. Supported compiler: `nightly-2026-07-11` / rustc 1.99.0-nightly (`rust-version = "1.99"`). JWT (`jsonwebtoken`) and Redis are absent from the current workspace dependency graph; Redis Tasks and enterprise auth remain later packages.

### Protocol and Runtime Maintenance

- **JSON-RPC error taxonomy correction for unknown legacy methods (breaking)** -- A structurally valid JSON-RPC request naming a method outside the exact MCP 2024-11-05 inventory is now refused with `-32601` Method Not Found instead of `-32600` Invalid Request, matching the JSON-RPC 2.0 taxonomy (`-32600` remains reserved for envelope-structure failures). `Legacy2024EnvelopeError` gains a `Method` class, which is API-breaking for exhaustive matchers; this change is what makes v0.4.0 a breaking (pre-1.0 minor) version bump. ([`2a5ee3b`](https://github.com/Dicklesworthstone/fastmcp_rust/commit/2a5ee3bf769f94b0b2fca33b0b699874ca8f833f))
- **Streamable HTTP survives malformed POST bodies** -- A well-framed HTTP POST whose body fails JSON-RPC decoding no longer strands the connection's single response slot: the receive path still surfaces the codec error so a server can answer with a correlated `-32700` response, but if the server declines and receives again (era admission skips malformed opening frames), the transport completes the abandoned exchange with `400 Bad Request` and keeps serving subsequent exchanges instead of terminating on a phantom `WouldBlock`.
- **Proxy gateways adopt upstream `Implementation` extras** -- `as_proxy` gateways propagate upstream implementation metadata and preserve upstream JSON-RPC error codes through the proxy boundary. ([`b1c4f59`](https://github.com/Dicklesworthstone/fastmcp_rust/commit/b1c4f59c7c9fa134e5a55b0ebdc36afa0b84f0e6))
- **MCP wire corrections** -- Correct tool-annotation field names and the lifecycle notification method name. ([`f8ec1e0`](https://github.com/Dicklesworthstone/fastmcp_rust/commit/f8ec1e0ab86501439fd437f52ce825da4641ed97))
- **Runtime upgrades** -- Adapt the workspace to later asupersync 0.3 releases and their context/deadline APIs. ([`a0f6a39`](https://github.com/Dicklesworthstone/fastmcp_rust/commit/a0f6a3948341efc60f969ee196e694c263f6acfb), [`6cebdde`](https://github.com/Dicklesworthstone/fastmcp_rust/commit/6cebdde16664101393d5dc8bcae00171d903f384), [`5c6cd65`](https://github.com/Dicklesworthstone/fastmcp_rust/commit/5c6cd6585c0d5b36801993130fb578d43f351193))
- **Client dual request deadlines (breaking, in progress)** -- Replace the single client `timeout_ms` setting with `RequestTimeoutPolicy` (30-second idle and 120-second non-resettable absolute response-wait defaults, both starting after send commit). Replace `fastmcp test --timeout` with independent bounded `--idle-timeout` and `--absolute-timeout` options. Historical release entries below retain their original API names.
- **Observable client cleanup (breaking, in progress)** -- `Client::close` now requires `&mut self` and returns `McpResult<()>`; transport and subprocess cleanup failures are no longer silently discarded. After a successful connection, the `fastmcp test` runner reports explicit final cleanup as a distinct result; initialization-cleanup failures are also reported separately. It opts into an anchored Unix process group with owner-death signalling. Non-Unix subprocess testing fails before spawn pending Job Object/equivalent support. Drop remains best effort, group/session escape and hostile/global reapers remain outside the proof boundary, and this work is not FND-04 or aggregate protocol closure.
- **Development subprocess custody (in progress)** -- Unix `fastmcp dev` build/server groups now contain a signal-immune watchdog bound to a private owner-held control pipe. Normal shutdown, child-handle drop, and CLI owner death release the watchdog to perform bounded TERM-then-KILL cleanup without later signalling a remembered PGID. Host-fork descriptor copies, group/session escape, and non-Unix process-tree ownership remain unqualified.
- **Stdio and returning-runner hardening (in progress)** -- Unix primary-stdio receive uses a stop-aware readiness pump, and ordinary pipe/socket output uses serialized bounded nonblocking commits. Notification encode/lock/write failure is connection-fatal; shutdown hooks run only after dispatch-worker quiescence. `run_transport_returning*` now returns fatal receive/send/close failures and preserves simultaneous run-plus-close errors. Generic synchronous HTTP reads still cannot be preempted once blocked in the kernel, non-Unix stdio retains blocking boundaries, and no conformance claim follows from these source changes.

### Current Capability Boundaries

Current safety posture (2026-08-02): advisory
`ToolAnnotations.readOnlyHint` metadata is not an execution-safety boundary.
The old sessionful HTTP listener is private and unreachable. Public native HTTP
routing separates modern MCP 2026-07-28 admission from exact MCP 2024-11-05
lifecycle handling. Multi-client isolation, cancellation, and `await_cleanup`
remain partial rather than isolated end-to-end guarantees, and aggregate
MCP 2026-07-28 support remains unverified.

- **`dispatch_request_concurrent` API name retained without a lock-free guarantee** -- The public entry point exists, but the current implementation serializes through the same shared session mutex as ordinary dispatch. Historical lock-free and sub-microsecond snapshot claims are withdrawn. ([`d2fd587`](https://github.com/Dicklesworthstone/fastmcp_rust/commit/d2fd587e158b644b32e3b20a66416d6e155dced3))
- **Historical turnkey HTTP server (quarantined)** -- `run_http` / `run_http_with_cx` / `run_http_returning` were introduced with a sessionful listener. That listener is private and unreachable because it shared mutable legacy state across clients. Current public native HTTP routing separates modern MCP 2026-07-28 admission from exact MCP 2024-11-05 lifecycle handling; aggregate qualification remains unverified. ([`693bc06`](https://github.com/Dicklesworthstone/fastmcp_rust/commit/693bc06f83ab6e579f1d8ea3167d4a5495b3e430))
- **OAuth/OIDC limits** -- CSPRNG-backed opaque-token draws and PKCE verification are not evidence of complete OAuth 2.0/2.1 or OIDC conformance. The current OIDC surface advertises no signing algorithms or JWKS endpoint and fails closed for ID-token issuance.

**Exact changes:** [v0.3.2...v0.4.0](https://github.com/Dicklesworthstone/fastmcp_rust/compare/v0.3.2...v0.4.0)

---

## [v0.3.2](https://github.com/Dicklesworthstone/fastmcp_rust/releases/tag/v0.3.2) -- 2026-06-18 (GitHub Release)

- Restored source compatibility with published asupersync 0.3.4 and migrated tests to its wall-clock timeout API. ([`a6459f5`](https://github.com/Dicklesworthstone/fastmcp_rust/commit/a6459f51a2490c23af49f4bd4a3a4e059b962cfc), [`1a9bb92`](https://github.com/Dicklesworthstone/fastmcp_rust/commit/1a9bb92958e462ca56fa03201f0ae8fa8a3357d5))
- Bumped all workspace crates to 0.3.2. ([`9e3a443`](https://github.com/Dicklesworthstone/fastmcp_rust/commit/9e3a443a7c9b15b2a11c70cb4bd93ed80afe4e4c))

**Exact changes:** [v0.3.1...v0.3.2](https://github.com/Dicklesworthstone/fastmcp_rust/compare/v0.3.1...v0.3.2)

## [v0.3.1](https://github.com/Dicklesworthstone/fastmcp_rust/releases/tag/v0.3.1) -- 2026-05-08 (GitHub Release)

- Corrected MCP configuration discovery across BSD and other Unix-family targets and treated an empty `XDG_CONFIG_HOME` as unset. ([`975f6bc`](https://github.com/Dicklesworthstone/fastmcp_rust/commit/975f6bc2a40141578b4676b8c218c64f1226ee47), [`cf7bf68`](https://github.com/Dicklesworthstone/fastmcp_rust/commit/cf7bf68e578eaccbd6712e9bfa09f7aee073d244), [`b9c4284`](https://github.com/Dicklesworthstone/fastmcp_rust/commit/b9c428479e95c03b8367ec1534a7832fc094bc50))
- Refreshed dependencies and bumped all workspace crates to 0.3.1. ([`c597ffb`](https://github.com/Dicklesworthstone/fastmcp_rust/commit/c597ffbb37c510be5df47b2928aa033c18375df8), [`d5c3e01`](https://github.com/Dicklesworthstone/fastmcp_rust/commit/d5c3e012ececb08ec0de32255a9b99fe2ff4d11b))

**Exact changes:** [v0.3.0...v0.3.1](https://github.com/Dicklesworthstone/fastmcp_rust/compare/v0.3.0...v0.3.1)

## [v0.3.0](https://github.com/Dicklesworthstone/fastmcp_rust/releases/tag/v0.3.0) -- 2026-04-21 (GitHub Release)

- Moved the workspace to asupersync 0.3.0 and bumped all workspace crates to 0.3.0; the release commit records no source changes for that runtime update. ([`7f211e1`](https://github.com/Dicklesworthstone/fastmcp_rust/commit/7f211e1ae3cf2f21d6f6fcc7658c5fcf9d62d8ed), [`7a274a4`](https://github.com/Dicklesworthstone/fastmcp_rust/commit/7a274a4cbee14351ab7f947c1e6f454537910ebf))
- Fixed release CI dependencies and Windows-specific E2E/test portability before the version bump. ([`18b4b2d`](https://github.com/Dicklesworthstone/fastmcp_rust/commit/18b4b2d1ed5e07e9757fadd9a3201fee4f09b62a), [`72462ff`](https://github.com/Dicklesworthstone/fastmcp_rust/commit/72462ffe7ce016bc7e2594ce15d8a4aa86eb4916), [`5896695`](https://github.com/Dicklesworthstone/fastmcp_rust/commit/589669520aa2e5f9f19390eb93868d89a80f19cd))

**Exact changes:** [v0.2.1...v0.3.0](https://github.com/Dicklesworthstone/fastmcp_rust/compare/v0.2.1...v0.3.0)

## [v0.2.1](https://github.com/Dicklesworthstone/fastmcp_rust/releases/tag/v0.2.1) -- 2026-04-16 (GitHub Release)

- Added concurrent combinators and bounded HTTP acceptance, plus a read-only session-snapshot experiment that is now withdrawn. The sessionful HTTP listener is quarantined, and `dispatch_request_concurrent` currently provides no lock-free guarantee. ([`9a24313`](https://github.com/Dicklesworthstone/fastmcp_rust/commit/9a243130c0660e1465030d662d5494c43cd4ca88), [`402bc43`](https://github.com/Dicklesworthstone/fastmcp_rust/commit/402bc43b7a2470abebef3ed2a04088f39feb7d53), [`d2fd587`](https://github.com/Dicklesworthstone/fastmcp_rust/commit/d2fd587e158b644b32e3b20a66416d6e155dced3))
- Added public direct request dispatch, request-scoped auth context, typed session state, resource-template validation, and middleware/resource handling refinements. ([`27f00a6`](https://github.com/Dicklesworthstone/fastmcp_rust/commit/27f00a62c29c7bb68c4c5425b344f916d70c8663), [`5e9086c`](https://github.com/Dicklesworthstone/fastmcp_rust/commit/5e9086c94f74a3cd1e36c6aee391b0ac229769f1), [`36bcf82`](https://github.com/Dicklesworthstone/fastmcp_rust/commit/36bcf826d925327b5cafc7485d99df4e3b2f481b))
- Fixed nested `block_on` I/O readiness and context installation, duplicate request-ID handling, task-state and quorum edge cases, and poisoned-lock diagnostics. ([`d26379f`](https://github.com/Dicklesworthstone/fastmcp_rust/commit/d26379f8686e9a85487f2af49d551f29abf4702e), [`a3d0cb7`](https://github.com/Dicklesworthstone/fastmcp_rust/commit/a3d0cb73b7f68710d2002300fcad36fb2ce3ed80), [`1f265da`](https://github.com/Dicklesworthstone/fastmcp_rust/commit/1f265dae0c263eafce184fec9dc740404ea24a05), [`ade6f9d`](https://github.com/Dicklesworthstone/fastmcp_rust/commit/ade6f9de7e0b6300725b8d8c0c6d92276aeaf9a0), [`7fa856a`](https://github.com/Dicklesworthstone/fastmcp_rust/commit/7fa856a27bb28a359a082df606d7616ae475bf65))
- Updated dependencies, licensing, and release automation and re-exported `ToolAnnotations` from `fastmcp-protocol`. ([`9c882fc`](https://github.com/Dicklesworthstone/fastmcp_rust/commit/9c882fc348084903506b776bca7ddba7bdc04360), [`35c685b`](https://github.com/Dicklesworthstone/fastmcp_rust/commit/35c685bdce89a8e3ffba6f0c660dce867678576a), [`c6e6e1c`](https://github.com/Dicklesworthstone/fastmcp_rust/commit/c6e6e1c6064fa5a22f9da858ed49e2963a194e33), [`99a66dc`](https://github.com/Dicklesworthstone/fastmcp_rust/commit/99a66dcafd18a93ae7bfa3c8c4053ec83beaa2cc))

**Exact changes:** [v0.2.0...v0.2.1](https://github.com/Dicklesworthstone/fastmcp_rust/compare/v0.2.0...v0.2.1)

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

- **`#[tool]` annotations and version support** -- `#[tool(annotations(read_only = true, destructive = false), version = "1.0")]` syntax for rich tool metadata at the macro level. ([`4244ab8`](https://github.com/Dicklesworthstone/fastmcp_rust/commit/4244ab8ec9ae58ed96fe4945fc3e2fc4ea3d2cb0))
- **`#[resource]` and `#[prompt]` version and tags** -- `#[resource(version = "2.0", tags = ["config"])]` and `#[prompt(tags = ["greeting"])]` support. ([`0f78298`](https://github.com/Dicklesworthstone/fastmcp_rust/commit/0f782988e6761e1a0a3d5ad190fcd3042f363f1e))
- **`Vec<ResourceContent>` return type in `#[resource]`** -- Resources can now return multiple content items. ([`f9f3f3e`](https://github.com/Dicklesworthstone/fastmcp_rust/commit/f9f3f3ee64061763c6ad5b8359b76dce805aac3a))
- **Tool tags macro support** -- `#[tool(tags = ["math", "utility"])]` for tag-based tool filtering. ([`c4257d8`](https://github.com/Dicklesworthstone/fastmcp_rust/commit/c4257d8e7fbb6085f91ea7196d0fc953c534856e))
- **E2E handler conversion to macros** -- Systematic refactoring of all manual `ToolHandler`/`ResourceHandler`/`PromptHandler` impls in tests to `#[tool]`/`#[resource]`/`#[prompt]` macros, validating real-world macro correctness. ([`4332672`](https://github.com/Dicklesworthstone/fastmcp_rust/commit/43326722ce639abdec71b8bf1bc6027abfbf8b4a), [`dba5092`](https://github.com/Dicklesworthstone/fastmcp_rust/commit/dba5092a7150c529c74aa274797622298ac7978a), [`58e2f6a`](https://github.com/Dicklesworthstone/fastmcp_rust/commit/58e2f6a5ef3088d6438cf10bd7d52baf04b0f096), [`fcc3180`](https://github.com/Dicklesworthstone/fastmcp_rust/commit/fcc31800a645ab53dea3238cc0f55fa044c9fccc))

### Security

- **Redact access token values from Debug output** -- Prevents accidental credential leakage in logs. ([`5615ee4`](https://github.com/Dicklesworthstone/fastmcp_rust/commit/5615ee4f9e22563df41bbb45e21f5bf84fb6080a))
- **Historical token, PKCE, and parser hardening** -- Replaced placeholder opaque-token draws with a CSPRNG-backed source, replaced placeholder SHA-256/HMAC helpers, and hardened HTTP parsing. The associated OIDC signing/JWKS path has since been withdrawn, and these changes did not establish OAuth/OIDC profile conformance or current OIDC support. ([`df51b46`](https://github.com/Dicklesworthstone/fastmcp_rust/commit/df51b46adbc4b2f3c30bf501b539edc1bd8fbeab))
- **Historical OIDC RS256/JWKS work (now withdrawn)** -- Earlier code attempted RS256/JWKS validation. The current source advertises no signing algorithms or JWKS endpoint and fails closed for ID-token issuance; this entry is provenance, not a current capability claim. ([`2fb19c6`](https://github.com/Dicklesworthstone/fastmcp_rust/commit/2fb19c61e1a678992cdc34c593e54103b093fbd4))

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

The foundational development period established the initial FastMCP Rust framework. No tagged release was cut for this phase; the code was subsequently published as part of v0.2.0. Historical parity assessments from this period are provenance, not verified current support claims.

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
- **Historical HTTP transport prototype** -- Introduced HTTP parsing/framing and a sessionful listener; that listener is now quarantined and is not current public HTTP support. ([`286eed9`](https://github.com/Dicklesworthstone/fastmcp_rust/commit/286eed930723e7a3a4bc18a94e58cd3f6350734a))
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

- **Historical OAuth authorization-server prototype** -- Introduced authorization-code, opaque-token, revocation, client-registration, scope-validation, and PKCE-verification surfaces. Its initial placeholder cryptographic helpers were hardened later; neither change established OAuth 2.0/2.1 conformance or current production readiness. ([`ecc4b9d`](https://github.com/Dicklesworthstone/fastmcp_rust/commit/ecc4b9dd086e33b4353bc2b79a976b3d5385f7a4), [`df51b46`](https://github.com/Dicklesworthstone/fastmcp_rust/commit/df51b46adbc4b2f3c30bf501b539edc1bd8fbeab))
- **Historical OIDC integration prototype (quarantined)** -- Introduced provider-discovery and claims surfaces, but current source advertises no signing algorithms/JWKS and fails closed for ID-token issuance. JWKS fetch/cache and ID-token validation are not current supported capabilities. ([`ecc4b9d`](https://github.com/Dicklesworthstone/fastmcp_rust/commit/ecc4b9dd086e33b4353bc2b79a976b3d5385f7a4))
- **Historical bidirectional MCP building blocks** -- Introduced `BidirectionalSenders` and capability queries for sampling, elicitation, and roots. Current split response routing is limited to the primary stdio path; custom/SSE/WebSocket paths remain sequential and public HTTP is fail-closed, so aggregate full-duplex support is not claimed. ([`ecc4b9d`](https://github.com/Dicklesworthstone/fastmcp_rust/commit/ecc4b9dd086e33b4353bc2b79a976b3d5385f7a4))
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

- **Historical feature-parity assessment** -- Contemporary project documents estimated parity with Python FastMCP v2.14.4 at ~90-95% and later recorded 100%. Those estimates were not a protocol-conformance attestation and are not a current aggregate-support claim. ([`408b50e`](https://github.com/Dicklesworthstone/fastmcp_rust/commit/408b50e762851c3e04fd3dda0979dadfc22195c9), [`a075688`](https://github.com/Dicklesworthstone/fastmcp_rust/commit/a0756881d864d952d1d725880816b3e9797e76dd))
- **MIT License** with attribution to original FastMCP Python library. ([`812269b`](https://github.com/Dicklesworthstone/fastmcp_rust/commit/812269b51b7972689d2fdaed691d3a5512e35d8c), [`ca4964a`](https://github.com/Dicklesworthstone/fastmcp_rust/commit/ca4964ae161b59fe53949194fe91444af4e68b1f))
