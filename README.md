<p align="center">
  <img src="fastmcp_rust_illustration.webp" alt="FastMCP Rust - cancel-aware MCP framework" width="800">
</p>

<h1 align="center">FastMCP Rust</h1>

<p align="center">
  <strong>Cancel-aware Model Context Protocol (MCP) framework for Rust</strong>
</p>

<p align="center">
  <em>A Rust port of <a href="https://github.com/jlowin/fastmcp">jlowin/fastmcp</a> (Python), extended with <a href="https://github.com/Dicklesworthstone/asupersync">asupersync</a> capability contexts and cooperative-cancellation primitives.</em>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/License-MIT%20with%20rider-blue.svg" alt="MIT License with rider">
  <img src="https://img.shields.io/badge/rust-nightly--2026--08--25-orange.svg" alt="Rust Version">
  <img src="https://img.shields.io/badge/edition-2024-purple.svg" alt="Rust Edition">
  <img src="https://img.shields.io/badge/MCP%202026--07--28-under%20implementation-yellow.svg" alt="MCP status">
</p>

> **Protocol status (2026-11-22):** MCP 2026-07-28 support is under
> implementation and remains unverified. The root compatibility
> `PROTOCOL_VERSION` is `2024-11-05`; the modern facade's
> `modern::PROTOCOL_VERSION` is `2026-07-28`. Source presence, examples, and
> historical parity rows are not conformance or release evidence. Versions
> through 0.14.0 have been published, but publication and source edits alone do
> not prove historical workflow identities, queued runs, or credentials inert;
> provider-side release-safety evidence is still required.

### Measured official-conformance standing

Run it yourself with `scripts/run_official_conformance.sh`; it owns the suite
pin and the result tally. Measurements use
`@modelcontextprotocol/conformance@0.2.0-alpha.10`,
`--spec-version 2026-07-28 --suite all`, server mode against the in-tree
`conformance_server` adapter:

| revision | date | scenarios | checks | SUCCESS | FAILURE | WARNING | INFO |
|---|---|---|---|---|---|---|---|
| `65d2247d` | 2026-11-20 | 40 | 115 | **112** | **0** | 2 | 1 |
| `1c2dc896` | 2026-10-12 | 40 | 115 | **112** | **0** | 2 | 1 |
| `e2a0ac5c` | 2026-10-12 | 40 | 115 | 110 | **0** | 4 | 1 |
| `99a3b4e8` | 2026-10-05 | 40 | 115 | 110 | **0** | 4 | 1 |
| working tree (unanchored) | 2026-10-04 | 40 | 115 | 110 | **0** | 4 | 1 |
| `6b54e023` | 2026-10-03 | 40 | 114 | 108 | 1 | 4 | 1 |
| `bba5a09f` | 2026-10-01 | 40 | 92 | 54 | 38 | 0 | 0 |

The latest `65d2247d` re-measurement (2026-11-20, arm64 Darwin, pinned
`nightly-2026-08-25`, `conformance_server` adapter blob
`a2d1f906889039b7d5935464b2fa934adc585630`, binary sha256
`c3b4385de40dc4d0...f2deb37ec`, `suite exit status: 0`) reproduces the
`112 SUCCESS / 0 FAILURE / 2 WARNING / 1 INFO` standing across all 40 scenarios
and 115 checks.

The `99a3b4e8` row is bound to identity rather than to a date, which the row
above it is not: 98 commits and 388 lines across four server-mode source files
(`fastmcp-core/src/context.rs`, `fastmcp-protocol/src/server_discovery.rs`,
`fastmcp-server/src/lib.rs`, `fastmcp/src/lib.rs`) landed after the 2026-10-04
measurement, which under this project's own receipt rules invalidated it. The
re-measurement reproduces it exactly, so the standing held across that drift —
but that is now a measured fact rather than an assumption. Its bindings:

    HEAD              99a3b4e8f0ebd56357f34953754ac6912df0597b
    adapter blob      0b887aedeb0b7f6ad3ddceb5ea3cc3523bbab29b
    adapter sha256    a66f0bee...e149b4   crates/fastmcp/examples/conformance_server.rs
    binary sha256     74c18713...e54a1a   target/debug/conformance_server
    toolchain         rustc 1.100.0-nightly (e7769602a 2026-08-24)
    host              hz3 (x86_64 linux), direct ssh, RCH scheduler bypassed
    build             cargo build --locked -p fastmcp-rust --features tasks
                      --bin conformance_server, rc 0, 32m24s

**`--baseline` cannot currently pass, and that is a property of the gate, not
of the server.** The suite's own `--expected-failures` treats a scenario
carrying a SHOULD-level WARNING as a scenario failure, so this run reported
`suite exit status: 1` and named `server-stateless`,
`input-required-result-missing-input-response` and
`input-required-result-ignore-extra-params` as "unexpected failures" while its
own tally printed `110 passed, 0 failed`. Anyone wiring `--baseline` into a
gate today gets a permanent red. Resolving that means either listing those
scenarios (an expected-failures edit, which `scripts/conformance-expected-failures.yaml`
deliberately reserves to its owner) or gating on the tally instead; it is not
resolved here.

**These rows are not a ratio, and the denominator is not fixed.** It rose 92 →
114 → 115 because a scenario that fails an early check never runs its later
ones, so fixing one check can *add* checks to the run. The corollary is a trap:
a regression that makes a scenario abort earlier shrinks the denominator and can
push a percentage *up*. Compare the *sets* of failing check ids, which is what
`scripts/conformance-expected-failures.yaml` records and what the suite's own
`--expected-failures` gates on.

**Client mode.** The gate is the harness passing in *both* modes.
32 scenarios / 155 checks: SUCCESS=55, FAILURE=46, SKIPPED=2, WARNING=1,
INFO=51. Re-measured 2026-11-20 at `65d2247d` (adapter blob
`fcf1296f971c60ce778bfd63dc5cdd7dcd610b22`, binary sha256
`066a512dc2a2d92d...99170934ca`, arm64 Darwin, pinned `nightly-2026-08-25`),
reproducing the 2026-10-13 `2b6c519e` baseline (`crates` tree `6a57e7ca`,
adapter binary sha256 `2d47186b24962718e3e9a01be48f746449823ecf...`, host `hz3`,
suite `@modelcontextprotocol/conformance@0.2.0-alpha.10`,
`client --suite all --spec-version 2026-07-28`, build rc 0, suite rc 1)
across all five counts:

This row previously read "most recent run" with no revision, date, host or
toolchain, which made it unverifiable; the re-measurement reproduces all five
counts exactly. Split it before quoting it, because the halves measure
different things:

| | checks | SUCCESS | FAILURE |
|---|---|---|---|
| non-authorization | 55 | 52 | **0** |
| authorization | 100 | 3 | 46 |

- **Non-authorization: no FAILURE-level check remains.** `http-custom-headers`
  18/18, `http-invalid-tool-headers` 11/11, `http-standard-headers` 9/9 (2
  skipped), `sep-2322-client-request-state` 5/5, `json-schema-ref-no-deref`,
  `request-metadata` (1 SHOULD warning) and `tools_call` clean. SEP-2243
  parameter-header mirroring is exercised end to end: designated parameters are
  sent as `Mcp-Param-*`, encoded where the value is header-unsafe, omitted when
  null, and never added for an undesignated parameter — and a tool whose
  `x-mcp-header` annotations are invalid is excluded rather than called.
- **Authorization: the adapter, not the library.** `conformance_client`
  supplies no interactive OAuth driver, so these measure adapter completeness.
  It does ship a *non-interactive* authorization-code driver —
  `examples/conformance_oauth.rs` plus its `managed` submodule, compiled into
  the adapter as a module and wired at `conformance_client.rs:376` — but that
  driver is inert unless `FASTMCP_CONFORMANCE_OAUTH` carries its configuration,
  and nothing in this repository sets it, including
  `scripts/run_official_conformance.sh`. So these checks measure the adapter
  with authorization switched off. **No value of that variable can switch it
  on, though.** Measured 2026-10-12 against the pinned suite: `configure`
  requires the `resource` member to equal the MCP endpoint *and* to use
  `https` (`conformance_oauth.rs:306`), and `issuer` and
  `authorization_endpoint` are required static pins rather than discovered
  values. The suite serves plain HTTP on an ephemeral loopback port and has no
  TLS capability at all — a census of its 472,891-byte bundle finds
  `http://localhost:${this.port}` and `http://127.0.0.1:${e}` against **zero**
  occurrences of `createSecureServer`, `node:tls`, or any cert/key material —
  and it stands up a fresh authorization server per scenario, across 25
  `auth/*` client scenarios that deliberately vary the issuer
  (`iss-wrong-issuer`, `metadata-issuer-mismatch`,
  `authorization-server-migration`). So the driver refuses any configuration
  naming the suite's endpoint, on two independent grounds. Closing these needs
  **more than an adapter profile**, which is worth stating precisely because
  the cheap-sounding estimate is wrong. The HTTPS requirement is not one check
  in the conformance adapter: a census of `crates/fastmcp-client/src`, with
  `cfg(test)` modules excluded, finds **32 production HTTPS enforcement points
  across 24 files**: 30 independent `scheme() != "https"`,
  `starts_with("https://")`, or `scheme().is("https")` refusals in `http_auth.rs`, `device/wire.rs`,
  `challenge.rs`,
  `private_key_jwt.rs`, `metadata_document.rs`, `dpop.rs`,
  `dpop/native/core/stream/task_subscription/watch/checkpoint.rs`, `driver.rs`,
  `redirect.rs`, `enterprise/identity.rs`, `enterprise/identity/sector.rs`,
  `enterprise/keys.rs`, `enterprise/oidc.rs`,
  `enterprise/policy.rs`, `http_client.rs`, `managed/client.rs`, `resume.rs`,
  `oauth.rs`, `revocation.rs`, `recovery.rs`, `repair.rs`, `http_executor.rs`
  and `parameter_headers.rs`, plus the two central helpers `validate_https`
  and `https_url` in `discovery.rs`. Thirteen further call sites — in
  `challenge.rs`, `step_up.rs`, `issuer.rs` and `registration.rs` — inherit
  those helpers' refusal rather than repeating it, so they are not separate
  edits.
  *(This row previously read "32 production HTTPS hard-gates across 19 files"
  and then named 18. Both figures were wrong when written rather than stale:
  the same instrument returns 22 across 17 both at the authoring commit
  `aac6f67c` and at HEAD, so the subject never moved. The corrected figure is
  smaller, i.e. the earlier row overstated the work.)*
  Reaching the suite's ephemeral plain-HTTP loopback authorization
  server therefore means threading a loopback exemption through all of them,
  which is a change to the transport security posture of the whole client
  authorization subsystem, plus accepting a *discovered* issuer where
  `OAuthDiscoveryPlan` currently takes a caller-supplied `TrustedOAuthIssuer`
  allowlist. And the exemption is **not** spec-backed in the
  direction that matters: RFC 8252 §7.3 permits loopback `http` for the
  *client's own redirect URI*, which is not what blocks us, while OAuth 2.1
  requires `https` for the authorization server's own endpoints — exactly the
  URLs these 32 enforcement points refuse. The pinned suite serves its
  authorization server
  over plain `http` as a harness convenience, not because the spec allows it.
  So permitting it would be a real relaxation beyond the spec, not a reviewed
  alignment with it, and it is a library decision rather than adapter plumbing.
  It is not taken here.

  **But a reviewed loopback-HTTP exemption already exists in this library, and
  the conformance adapter already uses it.** This row previously claimed "no
  loopback exemption anywhere", which is false.
  `ReviewedToolHeaders::new_for_loopback_http`
  (`http_executor/parameter_headers.rs`) is public and documented: it admits
  canonical IPv4/IPv6 loopback *literals* over plain `http` and deliberately
  refuses DNS names, `localhost` included, "because a name can be rebound and
  is therefore not proof of a loopback peer". Its doc states the threat model
  it accepts — "loopback provides neither peer authentication nor secrecy from
  other local processes" — and requires per-binding caller review.
  `examples/conformance_client.rs` branches on the endpoint scheme to call it,
  and resolves the harness's `http://localhost:<port>` to the loopback literal
  **in the adapter**, on the stated ground that "resolving the name is the
  HOST's decision to make, not the library's … the library's literal-only
  boundary stays intact". So the precedent, the threat model, and the
  host-versus-library trust split are all settled here already — for parameter
  headers. What is *not* settled, and is the actual decision, is whether the
  same split is acceptable for the authorization server's own endpoints, where
  these 32 points protect credential transport rather than header mirroring.
  That is a strictly stronger property, so the existing precedent narrows the
  question rather than answering it.

  **A trap for whoever does take it.** Gating the exemption behind a
  conformance-only feature or `cfg` would be the cheap version and is
  self-defeating as proof: the 46 passing checks would then measure a profile
  no user can build, so they would be evidence about a conformance-only code
  path rather than about shipped behaviour. Either the shipped validators take a
  beyond-spec loopback exemption as an explicit, reviewed decision, or these 46
  stay closed and are reported as a deliberate boundary — which, given that
  OAuth 2.1 requires `https` for authorization-server endpoints, is a defensible
  place to land rather than a gap to apologise for.
  **They are also not one problem.** The
  pinned suite drives PKCE (`code_challenge`), `authorization_code`, dynamic
  `register`, and 401 `WWW-Authenticate` + `resource_metadata` discovery, all of
  which this client implements. **None of the 46 is DPoP**, which this row used to imply. The suite does carry
  DPoP client scenarios — `auth/dpop` and `auth/dpop-nonce` — but both are
  tagged `[extension]` rather than a dated spec version, so `--spec-version
  2026-07-28` filters them out: `list --client` reports 43 scenarios
  unfiltered and 32 at that version, and `dpop`/`sep-1932` appear **zero**
  times anywhere in the run. So DPoP is not measured at this pin, and the
  46 are entirely authorization-flow checks (protected-resource and
  authorization-server metadata, client registration, authorization and token
  requests, `iss` handling, scope derivation and step-up, the three
  token-endpoint auth methods, CIMD, pre-registration, offline access and AS
  migration). DPoP
  (RFC 9449) primitives now **exist and compile**, which was not true before
  2026-10-12, and the surface is growing faster than this row can be rewritten:
  measured 2026-10-16 at `7bd44cd0`, `fastmcp_client::http_auth::dpop` was
  **57 files, 24,095 lines, 151 public items and 311 in-module tests**, plus 515
  lines and 7 tests in `fastmcp_protocol::dpop` behind the `jose` feature —
  24,610 lines in all; re-measured 2026-11-20, the three DPoP trees
  (`fastmcp-client/src/http_auth/dpop`, `fastmcp-client/src/http_auth/oauth/dpop`,
  and `fastmcp-protocol/src/dpop.rs`) span **78 files and 36,739 lines**. The trajectory is the point rather than any one reading:
  781 lines on 2026-10-12, 6,699 at `a6559ff2`, 10,541 at `acc20148`, and
  24,095 at `7bd44cd0` two days after that — **30.8× in four days**, with the
  in-workspace caller count zero at every reading. That is the module keeping
  its own promise, not a widening gap: it is caller-driven by design, so the
  consumer is the application. Treat the counts as a
  dated reading of a module under active construction, not a durable fact; the
  gate below deliberately does not pin them, because a check that reddens on
  ordinary growth is a check that gets switched off. It is reachable by facade
  users through `pub use fastmcp_client::http_auth`. It had been **unwired
  rather than absent** — the file was created by `2612a7d4`, the `pub mod
  dpop;` that puts it in the build was added only by `ac00c6ad`, and the only
  `mod dpop` declaration in `http_auth.rs` is that one, so those lines had
  never been compiled until then. (They had never been formatted either;
  `c65eced1` restored `cargo fmt --check` afterwards.)
  **It has no in-workspace consumer, and that is its design rather than a
  gap** — a correction to what this row said earlier today. The module
  documentation states that it "never promotes a DPoP token into the existing
  bearer-only OAuth driver" and "does not install automatic OAuth negotiation
  or HTTP retries", so the intended consumer is the *application*, not this
  SDK. See **Sender-constrained credentials: DPoP** under Authenticated HTTP
  clients for the caller-facing flow; the real gap was that nothing pointed a
  reader at it, which is now fixed.
  So `readme_mechanical_claims.rs` gates the zero in the opposite sense from
  the one this row first claimed: the check fails if the library ever starts
  driving DPoP itself, which is the promise the module makes and the thing
  worth protecting. The size and its growth rate are still worth recording:
  781 lines on 2026-10-12 to 24,610 across two crates four days later.
  *(An earlier version of this sentence ranked that against "`http.rs` is
  14,734 lines and `websocket.rs` 6,828". That comparison was wrong and is
  withdrawn: it set a whole module against a whole module, while the unclaimed
  surface in those two is one adapter struct and one `cfg(test)` codec
  respectively. `http.rs` itself is heavily consumed — `HttpResponse`,
  `HttpStatus`, `HttpRequest` and `HttpMethod` alone account for 680 mentions
  in `fastmcp-server/src` — so its line count measures something else
  entirely.)* Tracked as `bd-iaqgd`.
  Across every member `src/` file outside the three
  DPoP module trees, the lowercase path spelling `dpop` occurs **three** times, and
  all three are the `pub mod dpop;` declarations that put the modules in the build
  (`http_auth.rs:39`, `http_auth/oauth.rs:45`, `fastmcp-protocol/src/lib.rs:44`); outside
  `src/`, integration test targets (`crates/fastmcp-client/tests/dpop_task_recovery.rs`
  and `crates/fastmcp/tests/public_reexport_closure.rs`) exercise the public DPoP API
  surface, while shipped library paths in `src/` remain caller-driven rather than
  auto-wired. Case is the discriminator — Rust spells the path `dpop` while prose
  and wire values spell it `DPoP`. Beyond those three declarations, the
  automatic path still states "No automatic login/retry, DPoP, DCR, DNS
  pinning, or OIDC identity authentication is installed"
  (`http_auth/discovery/challenge.rs`), and the client-credentials path still
  *rejects* a sender-constrained token (`token_type: "DPoP"`, or a `cnf`
  holding `jkt`) under the test
  `machine_token_cannot_downgrade_sender_constraints_or_exchange_grants`. So
  the five DPoP checks stay unreachable, but the estimate changed: it is now
  "drive an existing primitive from the adapter", not "implement DPoP" — and it
  is still behind the loopback-HTTP blocker above, since the adapter cannot
  address the suite's authorization server at all. The split across causes **is**
  now measured, and it is not a split: all 46 are the adapter-profile blocker
  and none is a missing library capability.
  The nine
  in-tree `oauth_*` test targets are gated on `native-tls-roots`; each one now
  carries a matching `required-features` stanza, so a default run *excludes*
  them and naming one explicitly makes cargo refuse. They are therefore not a
  vacuous pass — but they are also not evidence those flows work, because a
  default run does not execute them at all.

Client-mode conformance is measured; aggregate conformance is still **not**
claimed, in either mode.

No server-mode FAILURE-level check remains, and **two of the four SHOULD-level
warnings are now gone**. The two that cleared were
`sep-2575-server-sends-tools-list-changed-on-subscription` and its prompts
counterpart, which the adapter had declined on the stated grounds that "the
server has no runtime catalog-mutation API". That was false: `McpContext`
exposes `disable_tool`/`enable_tool` and the resource and prompt pairs, each
publishing a catalog change, and the server already attached both the session
state and the `subscriptions/listen` publisher. Serving the suite's two trigger
fixtures through that API took no library change at all — only
`examples/conformance_server.rs`, +93/-4. The `e2a0ac5c` and `1c2dc896` rows
above are a measured before/after over an identical 99-check id set, with
exactly those two statuses changing and nothing else moving, so the +2 is not a
denominator shift.

The two remaining warnings are enumerated in that same file: both are the
deliberate fail-closed choice about empty MRTR response maps that the suite
would prefer we relax.

**What this is not.** It is a count of named checks at one revision, under one
adapter, over HTTP. It is not aggregate MCP 2026-07-28 conformance, and it says
nothing about the qualification boundaries below — several of which (OAuth/OIDC
production profile, end-to-end quiescence, `awaitCleanup`) the suite does not
exercise at all. The suite's default `--suite active` omits roughly half the
scenarios, including every input-required one, so a measurement taken without
`--suite all` is not comparable to these rows.

### Current qualification boundaries

- **Wire cancellation is only partially qualified:** on Unix, the primary
  stdio path keeps receiving while bounded modern requests run in independent
  request-owned children, so it can route cancellation during handler
  execution. Response and notification commits remain serialized at the
  output writer, while exact MCP 2024-11-05 traffic remains serialized through
  its lifecycle worker. WebSocket connections use native asynchronous I/O for
  Auto, ModernOnly, and LegacyOnly, without a connection-wide blocking worker.
  Exact-2024 handlers remain serialized while reverse replies and cancellation
  continue to be received. Non-Unix stdio and custom/SSE entry points retain
  sequential or blocking boundaries, except that an unsplit custom
  transport runs `subscriptions/listen` off its receive loop and queues output
  produced while `recv` blocks until `recv` returns. A non-cooperative handler can
  still exceed the bounded process-exit drain, so end-to-end quiescence and
  reliable `awaitCleanup` semantics remain unverified.
- **Bidirectional calls are only partly qualified:** the Unix stdio receive
  pump can route sampling, elicitation, and roots responses while exact-2024
  lifecycle work or modern request children are active. The WebSocket server
  uses the native dispatcher for every policy; custom split transports retain
  their synchronous receive pump. The `bind_websocket` regression tests cover
  an exact-2024 handler awaiting `ctx.sample` or `ctx.list_roots`
  (including a synchronous handler that bridges with `block_on`) receives the
  client's reply, and a client without the capability gets a typed refusal
  instead of a hang. Non-Unix stdio, unsplit custom transports, and SSE still
  reject or lack that split routing. Public HTTP has its own dual-era request
  and response routing, but end-to-end bidirectional lifecycle/cancellation
  evidence is incomplete.
- **Response caching is conservatively partitioned:** eligible production
  requests are keyed by committed authentication facts plus opaque session
  identity and revision. Uncommitted authentication, local-only state views,
  allocation failure, or state mutation during a request cause cache admission
  to fail closed rather than sharing an entry.
- **Authentication admission is incomplete:** native HTTP accepts credentials
  only from `Authorization`; recognized body/meta and query credential fields
  are rejected before the provider or application runs. Other adapters retain
  a stripped legacy JSON-RPC credential fallback. Providers can attach bounded,
  clone-shared live policy constraints with
  `AuthContext::with_verification_cancellation`. Revoking a constraint denies
  queued authentication receipts, the next guarded request or Task operation,
  and retained SSE delivery, including revocation during an asynchronous
  revalidation. `ManagedJwtResourceVerifier` retires previously returned facts
  on successful key replacement or explicit trust revocation. Facts keep their
  original expiry and identity; policy constraints do not become cache keys,
  serialize as authority, or cancel sibling requests. Already-running
  application code is not preempted. Complete authorization and OAuth challenge
  qualification remain open.
- **Legacy Tasks RPC stays dead:** `tasks/list` and `tasks/submit` return
  JSON-RPC `MethodNotFound`. Official MCP 2026-07-28 methods `tasks/get`,
  `tasks/update`, and `tasks/cancel` are served by default (process-local
  in-memory store). Call `ServerBuilder::final_tasks` to supply an
  application-owned store.
- **Task creation needs an application supervisor.** Configure
  `ServerBuilder::task_supervisor(Arc::new(supervisor))` to host an
  `ApplicationTaskSupervisor` on the default runtime or the runtime supplied
  by `final_tasks`. The server starts the service within the caller-owned
  serve lifetime, waits for readiness, and settles it on exit. The shipped
  `echo_server` uses this hook. A server without a ready service still refuses
  creation with `Final task creation requires an installed ready task service`.
  Applications may instead install and drive `AuthorizedTaskServiceRunner`
  explicitly; combining that installation with the builder hook is rejected.
  Each elected attempt receives a separate child region in the caller's runtime.
  Its deadline is capped by the caller and the remaining attempt, total-lifetime,
  and retention limits; lease renewal cannot extend it. Cancelling a Task leaves
  the service and sibling Tasks independent. The built-in store keeps execution
  capacity reserved until the attempt and its descendants settle. Custom stores
  must provide equivalent admission across lease expiry and changes of owner.
  Descendants must cooperate with cancellation; dropping the service requests
  cleanup owned by the caller's runtime, and abrupt runtime destruction does not
  prove cleanup completed.
- **Running Tasks can publish status messages.** An elected mutable
  `FinalTaskInitialWork` or `FinalTaskAcceptedInput` can call
  `update_status_message(Some("Processing the next batch".into()))` while
  continuing its work. Passing `None` clears the message. Each accepted update
  advances the record version, refreshes `lastUpdatedAt`, and publishes the
  matching Tasks status notification. It preserves the invocation's input,
  execution permit, lease and deadlines, so the same worker can later request
  input or finish. Current authorization, cancellation and the elected fence
  are checked before a write. The built-in store supports this path; custom
  stores must implement the atomic working-status and handoff-continuity hooks.
  For stores that need to await I/O, both handoff types also provide
  `update_status_message_with_cx` and the other
  [asynchronous worker transitions](#asynchronous-task-worker-transitions).
- **Authenticated local Tasks retain their caller:** task creation atomically
  stores a private principal binding, original tool registration, and immutable
  creation generation. Protected task-producing tools require both
  `ServerBuilder::task_access_authorizer` for current request grants and
  `ServerBuilder::task_execution_authorizer` for current autonomous execution
  grants. Execution policies are bounded application callbacks that recheck
  owner/operation permission, expiry, and revocation before application work,
  while it is pending, and before accepting a transition through a Task handoff.
  `FinalTaskAccessMetadata::principal_for_auth` derives an identity lookup key
  from verified authentication facts; that key is not itself an execution grant.
  Policies must consult current trusted application state and must not retain
  an ingress context or credential. A refreshed credential for the same owner
  can access the task when its current request grants permit it. Custom stores
  must preserve the identity and operation metadata atomically with every
  snapshot.
  Context-free runtime and subscription APIs are trusted embedding controls.
  These controls are process-local; durable authorization, external revocation
  discovery, anonymous client isolation, and proxy Tasks ownership remain
  unqualified.
- **Proxied Tasks keep their original tool authorization.** Install
  `ServerBuilder::task_access_authorizer`, `with_scope_authorization`, or
  `with_operation_scope_authorization` on the gateway before protected Task
  creation. The gateway binds each issued handle to the exact originating
  tool registration and rechecks current original-operation and management
  grants before upstream controls, reconciliation reads, and subscription
  events, including queued aliases. An unauthorized selection opens no upstream
  listener. These policies govern the current gateway process; they do not
  authorize an upstream worker's execution lifetime or provide restart recovery.
- **Proxied Task capacity can be divided among callers.** Before installing a
  `ProxyClient` in the gateway, call
  `proxy.with_task_limits(ProxyTaskLimits::new(128, 8)?)?` to allow at most 128
  handles on that upstream route and eight per stable authenticated owner.
  Both limits include pending creation reservations, so a rejected call sends
  no upstream `tools/call`. Client clones and rebuilt relays share the same
  accounting and limits; configuration becomes immutable when a Tasks relay
  is admitted. Completed handles, aliases, and expired snapshots retained for
  authoritative recovery continue to consume capacity until their mappings
  are reclaimed. The default remains 128 handles per route and per owner.
- **Proxied Tasks require a finite retention contract.** Before installing the
  client, configure `ProxyClient::with_task_retention_policy` with
  `ProxyTaskRetentionPolicy::new(maximum_upstream_ttl, mapping_lifetime)`.
  Both durations must be positive, the upstream maximum must fit the mapping
  lifetime, and the mapping lifetime cannot exceed 365 days. For example,
  `Duration::from_secs(86_400)` and `Duration::from_secs(2_592_000)` declare a
  one-day upstream maximum within a thirty-day local mapping ceiling. The
  ordinary builder methods `as_proxy_with_task_retention` and
  `as_proxy_raw_with_task_retention` accept the same policy directly; they are
  also available through the modern and auto facades. The
  upstream maximum is a trusted deployment contract, not a value accepted from
  peer discovery. A missing contract prevents Task creation from reaching the
  upstream, and clones share an immutable policy after relay admission.
  Arbitrary remote upstreams cannot use null-TTL Tasks under this profile.
  Contract violations and permanent ambiguity produce an explicit
  `UpstreamStateUnknown` outcome with a bounded, redacted, process-local orphan
  audit available through `task_orphan_audit`. An authorized best-effort
  cancellation request does not establish that upstream work has stopped.
  Gateway restart invalidates mappings; this profile provides neither shared
  durable mappings nor atomic administration across the two systems.
- **Task control requests validate approaching retention deadlines.** The
  retention policy's renewal margin defaults to the smaller of thirty seconds
  and the configured upstream maximum TTL. Set it with
  `policy.with_renewal_margin(duration)?`; the margin must be positive and no
  greater than that maximum. Before an update, cancellation, or new listener,
  a snapshot inside this margin or past its cached deadline requires a fresh
  `tasks/get`. The caller needs current permission for both the requested
  action and that read, including after the read completes. Renewal runs
  within the caller's request and budget, and preserves the original mapping
  ceiling. An unavailable upstream prevents the requested control operation
  while retaining the mapping and its quota charge until the hard ceiling.
- **OAuth/OIDC are unpromoted source surfaces:** their public building blocks
  remain available for development, but production security/profile
  conformance is unverified and no production-support claim is made for them.
- **CLI inspection is bounded diagnostics, not conformance evidence:** with
  default features in a current source checkout, `fastmcp inspect
  --protocol-policy` reports the selected `auto`, `modern-only`, or
  `legacy-only` era. A selected modern session requires valid
  `_meta.io.modelcontextprotocol/serverInfo` metadata and retains the open
  discovery capability shape (including `completions` and `extensions`)
  subject to output bounds and credential/control-text sanitization; a
  selected legacy session renders only the exact legacy capability shape.
  Modern `inspect --format json` uses `fastmcp.cli.inspect/v2` over both stdio
  and HTTP, retaining catalog titles, icons, annotations, resource sizes,
  prompt argument metadata, and `_meta` (including MCP Apps UI bindings),
  together with rich discovery identity and open capability fields. Retained
  fields preserve optional-field presence and numeric spellings within the
  existing redaction and size limits; truncation and schema completeness are
  reported explicitly. Exact legacy inspection keeps the v1 schema. A
  `--no-default-features` build supports `modern-only` only. This does not
  qualify either protocol era as aggregate conformance or production readiness.
- **Subprocess cleanup is explicit and platform-bounded:**
  `Client::close(&mut self)` returns cleanup failures. The opt-in owned-group mode used by
  `fastmcp test` is Unix-only and fails before spawn elsewhere. Its
  `--protocol-policy` option binds both client negotiation and the launched
  FastMCP server profile. It uses a live
  anchor plus an owner-death channel, but cannot contain descendants that
  change group/session, withstand a competing global child reaper, or close a
  control descriptor copied by a host-side fork. Drop is best effort.

---

```bash
# Current published package; publication is not aggregate conformance evidence
cargo add fastmcp-rust@0.14.0

# Or use the git dependency for bleeding-edge changes
cargo add fastmcp-rust --git https://github.com/Dicklesworthstone/fastmcp_rust
```

---

## TL;DR

### The Problem

MCP server implementations need to solve several recurring problems:

- Handler schemas and JSON-RPC dispatch
- Cooperative cancellation and request budgets
- Ownership of concurrent child work
- Transport framing and session lifecycle

### The Solution

**FastMCP Rust** is an MCP framework with asupersync capability contexts, attribute macros, and explicit cancellation/budget surfaces:

```rust
use asupersync::runtime::{RuntimeBuilder, reactor::create_reactor};
use fastmcp_rust::{auto::ServerBuilder, prelude::*};

#[tool]
async fn greet(ctx: &McpContext, name: String) -> McpResult<String> {
    ctx.checkpoint()?; // Cancellation point
    Ok(format!("Hello, {name}!"))
}

fn main() {
    let runtime = RuntimeBuilder::current_thread()
        .with_reactor(create_reactor().expect("create I/O reactor"))
        .blocking_threads(0, 16)
        .build()
        .expect("create application runtime");
    runtime.block_on(async {
        let cx = Cx::current().expect("application context");
        ServerBuilder::new("my-server", "1.0.0")
            // Attribute macros generate PascalCase handler values.
            .tool(Greet)
            .build()
            .run_stdio_with_cx(&cx)
            .await
    });
}
```

The application creates the runtime once and supplies its context. FastMCP does
not create a runtime at this entry point. `run_stdio_with_cx` needs a blocking
pool because its receive pump blocks on `recv`; that is a property of this entry
point, not of the framework. On Unix you can instead serve reactor-driven
process stdio with no blocking pool at all — see
[Non-blocking stdio](#non-blocking-stdio-unix-opt-in). See Quick Start below for
the dependency declarations.

`auto::ServerBuilder` serves MCP 2026-07-28 clients and also the exact
2024-11-05 `initialize` handshake that today's desktop clients and the MCP
Inspector open with. `modern::ServerBuilder` pins a server to 2026-07-28 alone,
so it refuses those clients.

### Why FastMCP Rust?

| Feature | FastMCP Rust | Manual Implementation |
|---------|--------------|----------------------|
| **Async handler API** | `#[tool] async fn` plus handler trait hooks | Manual Future boxing |
| **Cancellation** | Local request checkpoints; live wire interruption remains unverified | Application-specific checks |
| **Timeouts** | Request and handler budget surfaces | Application-specific timers |
| **Concurrent-future ownership** | Context combinators poll caller-owned futures | Manual ownership |
| **Error handling** | 4-valued Outcome | 2-valued Result |
| **Boilerplate** | Generated handler/schema implementations | Handwritten handler/schema implementations |

---

## AGENTS.md

This project includes an [`AGENTS.md`](AGENTS.md) file with guidelines for AI coding agents. Key points:

- **Porting methodology:** Extract spec from legacy → implement from spec → never translate line-by-line
- **Runtime:** Uses [asupersync](https://github.com/Dicklesworthstone/asupersync) exclusively; Tokio and Tokio-based adapters are unsupported
- **Unsafe code:** Forbidden (`#![forbid(unsafe_code)]`)
- **Toolchain:** Rust 2024 edition; pinned `nightly-2026-08-25` / rustc 1.100.0-nightly (`rust-version = "1.100"`)
- **MCP 2026-07-28 support is under implementation and remains unverified.**
- **Aggregate MCP 2026-07-28 support is not claimed by FND-01.**
- **The root compatibility `PROTOCOL_VERSION` is `2024-11-05`; the modern facade's `modern::PROTOCOL_VERSION` is `2026-07-28`. Neither is proof of negotiated 2026-07-28 support.**

---

## Quick Example

```rust
use asupersync::runtime::{RuntimeBuilder, reactor::create_reactor};
use fastmcp_rust::{auto::ServerBuilder, prelude::*};

// Define a tool with automatic JSON schema generation
#[tool(description = "Calculate the sum of two numbers")]
async fn add(ctx: &McpContext, a: i64, b: i64) -> McpResult<String> {
    ctx.checkpoint()?; // Check the local cancellation token and budget
    Ok((a + b).to_string())
}

// Define an in-memory resource. Potentially blocking filesystem work is not
// performed inline on the dispatch worker.
#[resource(uri = "config://settings", description = "Application config")]
fn config(ctx: &McpContext) -> McpResult<String> {
    ctx.checkpoint()?;
    Ok(r#"{"theme":"dark"}"#.to_owned())
}

// Define a prompt template
#[prompt(description = "Generate a greeting message")]
async fn greeting(ctx: &McpContext, name: String) -> McpResult<Vec<PromptMessage>> {
    ctx.checkpoint()?;
    Ok(vec![PromptMessage {
        role: Role::User,
        content: Content::text(format!("Please greet {name} warmly.")),
    }])
}

fn main() {
    let runtime = RuntimeBuilder::current_thread()
        .with_reactor(create_reactor().expect("create I/O reactor"))
        .blocking_threads(0, 16)
        .build()
        .expect("create application runtime");
    runtime.block_on(async {
        let cx = Cx::current().expect("application context");
        ServerBuilder::new("example-server", "1.0.0")
            .tool(Add)
            .resource(ConfigResource)
            .prompt(GreetingPrompt)
            .request_timeout(30) // 30-second budget per request
            .build()
            .run_stdio_with_cx(&cx)
            .await
    });
}
```

Run it:

```bash
# echo_server is a shipped binary target of the facade crate, not an example
cargo run -p fastmcp-rust --bin echo_server
```

---

## Design Philosophy

### 1. Explicit Cooperative Cancellation

Handlers should check cancellation at natural suspension or iteration boundaries. FastMCP exposes cooperative checkpoints. These local context semantics do not, by themselves, make cancellation interruptible over a live connection; see the qualification boundaries above.

```rust
#[tool]
async fn process_items(
    ctx: &McpContext,
    items: Vec<String>,
) -> McpResult<Vec<Content>> {
    let mut results = vec![];
    for item in items {
        ctx.checkpoint()?;  // Allow graceful cancellation between items
        results.push(Content::text(process(item).await?));
    }
    Ok(results)
}
```

### 2. Budgets, Not Timeouts

Timeouts are "we gave up." Budgets are "you have X resources." The `Budget` type represents deadline, poll-quota, and cost-quota dimensions:

```rust
// Called from the application's runtime with its context.
async fn serve(cx: &Cx) -> ! {
    ServerBuilder::new("server", "1.0.0")
        .request_timeout(30) // 30-second server-owned request ceiling
        .tool(MyTool)
        .build()
        .run_stdio_with_cx(cx)
        .await
}

// Handler can check remaining budget
#[tool]
async fn my_tool(ctx: &McpContext) -> McpResult<String> {
    ctx.checkpoint()?;
    // ... work ...
    Ok("work completed".to_string())
}
```

### 3. Four-Valued Outcomes

`Result<T, E>` has no distinct cancellation or panic variants. FastMCP's asynchronous handler boundary uses `Outcome<T, E>`:

```rust
enum Outcome<T, E> {
    Ok(T),                    // Success
    Err(E),                   // Expected failure
    Cancelled(CancelReason),  // External interruption
    Panicked(PanicPayload),   // Internal failure
}
```

### 4. Capability-oriented handlers

Request authority flows through `McpContext`; application dependencies should likewise be passed explicitly instead of hidden in globals:

```rust
// BAD: Global state access
async fn bad_tool() {
    let db = GLOBAL_DB.lock().await;  // Hidden dependency
}

// GOOD: Explicit capability
async fn good_tool(ctx: &McpContext, db: &DbHandle) {
    db.query(ctx.cx(), "SELECT ...").await;  // Explicit
}
```

### 5. Owned Concurrent Futures

Concurrent child futures remain owned by the request handler and are polled together by context combinators:

```rust
use std::future::Future;
use std::pin::Pin;

#[tool]
async fn parallel_fetch(
    ctx: &McpContext,
    urls: Vec<String>,
) -> McpResult<Vec<Content>> {
    type FetchFuture = Pin<Box<dyn Future<Output = McpResult<String>> + Send>>;

    let futures: Vec<FetchFuture> = urls
        .into_iter()
        .map(|url| Box::pin(fetch(url)) as FetchFuture)
        .collect();

    let results = ctx.join_all(futures).await?;
    results
        .into_iter()
        .map(|result| result.map(Content::text))
        .collect()
}
```

---

## Design Positioning

These are FastMCP Rust design surfaces, not benchmark results or an MCP 2026-07-28 conformance certificate. Competing projects change independently and should be evaluated from their current documentation rather than a static comparison table.

| Area | FastMCP Rust design |
|------|---------------------|
| **Handler API** | `#[tool]`, `#[resource]`, and `#[prompt]` macros plus explicit handler traits |
| **Cancellation** | `McpContext` checkpoints and masks backed by asupersync |
| **Timeouts** | Request and handler budget surfaces |
| **Runtime** | asupersync only; Tokio adapters are unsupported |
| **Outcomes** | Four-valued `Outcome`: success, expected error, cancellation, or panic |
| **Unsafe code** | Forbidden in workspace crates with `#![forbid(unsafe_code)]` |

---

## Installation

### From crates.io (current 0.14.0 package)

The `0.14.0` package was published on 2026-11-22. Publication does
not establish aggregate MCP 2026-07-28 conformance, production readiness, or
qualification of every in-tree feature.

```toml
[dependencies]
fastmcp-rust = "0.14.0"
```

### As a Git Dependency

```toml
[dependencies]
fastmcp-rust = { git = "https://github.com/Dicklesworthstone/fastmcp_rust" }
asupersync = "=0.6.2"
```

### Headless server embeddings (current source tree)

Direct `fastmcp-server` consumers can omit rich terminal output by disabling
its default features. The `console` feature is default-on; an embedded
modern server that supplies its own logger can use:

```toml
[dependencies]
fastmcp-server = { git = "https://github.com/Dicklesworthstone/fastmcp_rust", default-features = false }
```

Enable `legacy-2024-11-05`, `tasks`, `apps`, or the supported transport features
explicitly as needed. These selections do not activate the server's console
dependency. Headless servers retain request dispatch, protocol logging,
statistics collection, and `stats()` / `stats_collector()`; they do not install
a global logger or render banners, traffic previews, or statistics panels.
`ConsoleConfig`, banner/traffic controls, and `display_stats()` require
`console`. The idempotent `without_banner()` and `plain_mode()` helpers work
in both profiles.

This removes the direct server's `fastmcp-console` / `rich_rust` rendering
dependency. It does not promise a `chrono`-free graph: Tasks and OAuth use
timestamps for protocol and security behavior. The `fastmcp-rust` facade
retains its existing console-enabled behavior, so depend on `fastmcp-server`
directly when that dependency boundary is required.
This feature selection does not change the transport qualification boundaries
described above.

### Asynchronous server startup and cleanup (current source tree)

The modern, Auto and exact-2024 server builders provide `on_startup_async` and
`on_shutdown_async` for application initialization and cleanup that await I/O.
Each callback receives an owned `Cx` derived from the serving caller and
returns a `Send` future with an `McpResult<()>` result:

```rust
use fastmcp_rust::modern;

let server = modern::ServerBuilder::new("application", "1")
    .on_startup_async(|cx| async move {
        // Await initialization using this caller-owned context.
        let _ = cx;
        Ok(())
    })
    .on_shutdown_async(|cx| async move {
        // Await application cleanup after request and Task work settles.
        let _ = cx;
        Ok(())
    })
    .build();
```

Native memory, stdio, HTTP (including secured HTTP/HTTPS) and WebSocket serving
await startup before admitting requests or starting the hosted Task service.
`bind_secured_http` and `bind_secured_https` only bind and validate configuration;
their `serve` method awaits startup before accepting connections or TLS
handshakes. A startup error prevents protocol admission. If the startup callback
was entered, configured asynchronous cleanup is attempted before that error
returns, so partially initialized resources can be released. A refusal before
startup entry does not invoke cleanup.

Shutdown follows request and hosted Task quiescence. Pending cleanup remains
owned by the caller's runtime; HTTP and WebSocket shutdown handles retain its
completion when the transport reports a nonquiescent exit. Secured HTTP/HTTPS
also retains pending cleanup when every connection has already closed. Each hook
has one 30-second work bound, capped by the original caller deadline. Child-region
settlement is still awaited or retained after that bound, so a timeout does not
certify that noncooperative child work finished. Dropping a serve or shutdown
observer requests abandonment and does not run cleanup over live handlers.

The hooks use the caller's task and timer capabilities and do not create a
runtime or blocking pool. Synchronous hooks remain available. Registering a
sync or async hook replaces the previous hook for the same phase. Blocking
server runners reject asynchronous lifespan configuration before startup;
use a native serving method for these hooks.

### Native HTTP readiness and draining (current source tree)

`BoundHttpServer` and `BoundSecuredHttpServer` expose `GET /health` for listener
liveness and `GET /ready` for connection readiness. Configure their paths with
`HttpServerConfig::health_path` and `HttpServerConfig::readiness_path`.
Diagnostic paths must be distinct absolute paths and cannot overlap MCP,
legacy SSE, or installed OAuth routes; invalid configurations fail before bind.

The readiness response is a bounded, `Cache-Control: no-store` JSON snapshot
with schema `fastmcp.http.readiness/v1`. It returns 200 only while the listener
is running, structurally ready, and has spare connection capacity. Saturation,
draining, an unavailable snapshot, or an endpoint without a bound listener
returns 503. The snapshot reports lifecycle, capacity, fixed counters, `schemaVersion`,
and reason tokens;
it contains no request identifiers or credentials and invokes no authentication
provider or application handler. It observes capacity without reserving it.

A listener retains one bounded diagnostic connection when protocol capacity
is full or admission is draining. This connection has an 8 KiB header limit,
accepts no request body, and has one-second read and write bounds. It cannot
become a protocol connection if capacity becomes available while it is open.

Keep the handle returned by `bound.operator_handle()` and call
`operator.begin_drain()?` before cancelling the listener's serving context.
The call fences new protocol admission and revokes unused reservations while
accepted work retains its permits. `/ready` then returns 503, and `/health`
remains available so a load balancer can observe the draining listener.
Draining is irreversible for that listener generation; the call does not wait
for requests to finish. A busy admission cell returns a retryable `Busy` error.

Native secured HTTP/HTTPS diagnostics retain the configured Host and Origin
checks and support the corresponding GET preflight. They reject bodies,
queries, duplicate security headers, and collisions with protected-resource
metadata. TLS handshakes consume admission capacity; the extra diagnostic
slot also has a one-second handshake allowance and retains its permit through
bounded TLS shutdown. Its admission cannot become MCP or OAuth work later.
The same `operator_handle()` and `begin_drain()` workflow applies to both
listeners. Embedding adapters without a bound listener cannot report live
connection readiness. These observations do not establish upstream
availability, durable Tasks, or OAuth security qualification.

### Bounded Prometheus diagnostics (current source tree)

Metrics are disabled by default. Install a separate diagnostic route with an
explicit access policy on either native HTTP listener:

```rust
use fastmcp_rust::{HttpMetricsConfig, HttpServerConfig, McpResult};

fn http_config(scrape_token: &str) -> McpResult<HttpServerConfig> {
    Ok(HttpServerConfig::new().metrics(
        HttpMetricsConfig::bearer("/metrics", scrape_token)?,
    ))
}
```

The scrape credential is independent of MCP authentication. Only a
purpose-specific keyed verifier is retained; authorization happens before
snapshot capture. Use HTTPS or a trusted TLS terminator when transmitting the
credential. `HttpMetricsConfig::public("/metrics")` explicitly permits public
scrapes when that is the deployment's intended policy. Route collisions fail
before binding, including OAuth and protected-resource metadata routes.

The GET response uses Prometheus text 0.0.4, `Cache-Control: no-store`, and a
16 KiB output ceiling. A successful capture returns 200 even during saturation
or drain, so those conditions remain observable as gauges; an unavailable
snapshot returns 503. Metrics share the single bounded diagnostic lane with
health/readiness and release protocol admission before capture. Secured HTTP
and HTTPS preserve their Host, Origin, framing, and diagnostic I/O limits.

With the `tasks` feature, add `.with_task_store()` to the metrics configuration
to include Task state counts, retained payload and reservation bytes, execution
slots, and reclamation receipt storage in the same scrape. The Task series use
the prefix `fastmcp_operator_tasks_`. Counts of saturated owner partitions
let operators distinguish an individual quota from a full store without
exposing owner identities. A missing or busy Task observer returns 503 when
this option is enabled. The combined response shares the 16 KiB ceiling.

Application-owned exporters can use `prometheus_text()` and
`prometheus_text_with_limit(bytes)` on HTTP, client-executor, stdio-output,
and Task-store snapshots. The existing 30-series HTTP, executor, and stdio
contributors retain their prefixes `fastmcp_operator_http_`,
`fastmcp_operator_executor_`, and `fastmcp_operator_stdio_`. Each snapshot
carries its own protocol profile and configuration generation. Encoding uses
fixed metric names and takes no admission permit.

### Modern subscription admission (current source tree)

Modern subscription listeners share a server-wide capacity of 64 streams and
a default limit of 32 streams per verified principal. Configure smaller bounds
through the root, `auto`, or `modern` server builder:

```rust
let server = fastmcp_rust::modern::ServerBuilder::new("bounded-listeners", "1.0")
    .subscription_capacity(32, 8)?
    .build();
```

Both values must be positive; the per-principal limit cannot exceed the total,
and the total cannot exceed 64. Token rotation, scope changes, request IDs, and
new HTTP connections do not reset a verified principal's count. Anonymous
listeners share one admission partition. These partitions govern capacity;
existing authorization checks still govern event access.

Opening acknowledgements, active listeners, and retained callbacks or terminal
drains consume capacity until their owners release it. Saturation rejects the
new listen before acknowledgement without evicting an existing listener.
In-process callers must drop finished listen handles to release their slots.

Subscription data events, including completed Task results, have an 8 MiB
encoded-frame limit. The server retains at most 9 MiB / 64 events per listener,
64 MiB per principal, and 256 MiB across its subscription registry. Reservations
cover recipient copies and remain held until active delivery callbacks return.
Memory client listeners and stdio Task listeners retain at most 9 MiB / 256
events each and share a 64 MiB budget per connection. Consuming or discarding
events releases their charges. An overflowing listener is retired independently,
and late Task events cannot revive its retired owner. These limits account for
encoded event ownership; they do not bound application-owned results or all
temporary decoded allocations.

### From Source

```bash
git clone https://github.com/Dicklesworthstone/fastmcp_rust.git
cd fastmcp_rust
cargo build --release
```

### CLI binaries (GitHub Releases)

The latest published release, v0.14.0, provides prebuilt `fastmcp` binaries on
GitHub Releases. The `fastmcp-cli` source package is also available from
crates.io for Cargo-based installation. Archives follow a `fastmcp-<os>-<arch>`
pattern (`.tar.xz` on Unix, `.zip` on Windows).

**This repository does not establish what the published archives are named.**
The checked-in release workflow is a quarantined verification surface and does
not publish new GitHub Releases: it has held `contents: read` since 2026-08-02,
and that permission cannot create a Release. v0.14.0 was built and published
with the maintainer's local release tooling, not this workflow, so this
repository does not establish whether those archives are downloadable either,
and nothing in it can. That workflow's build matrix — the
`SURF-RELEASE-ASSET-CLOSURE` rows in
`evidence/fnd-01/dependency-verification.toml` — describes what the quarantined
workflow *would* produce, which is not evidence of what the release contains;
do not read it as the published filenames.

Take the exact filename from the v0.14.0 release page. The command below pins
the tag rather than `releases/latest` — under a workflow that does not publish,
`latest` is a moving pointer whose meaning is not stated anywhere.
**If the download does not resolve, build from source as shown above; that path
is verified by this repository and the download is not.**

```bash
# Replace <asset> with the exact filename listed on the v0.14.0 release page.
curl -fsSL -O https://github.com/Dicklesworthstone/fastmcp_rust/releases/download/v0.14.0/<asset>
tar -xJf <asset>
./fastmcp --version
```

### CLI via Cargo (optional)

```bash
rustup toolchain install nightly-2026-08-25
cargo +nightly-2026-08-25 install fastmcp-cli --version 0.14.0 --locked
```

### Completing prompt and resource-template arguments (current source tree)

`fastmcp complete` sends one `completion/complete` request and returns suggestions
in the provider's order. Select an exact prompt name or RFC 6570 resource-template
URI, the argument to complete, and its partial value (which may be empty):

```bash
fastmcp complete --prompt deploy --argument environment --value sta \
  --server ./my-server --protocol-policy modern-only --json

fastmcp complete --resource-template 'files:///{region}/{name}' \
  --argument name --value '' --context '{"arguments":{"region":"us-east-1"}}' \
  --http-url https://mcp.example/mcp --protocol-policy modern-only --json
```

Build the current checkout to use this command; for example:

```bash
cargo run -p fastmcp-cli -- complete --prompt deploy --argument environment \
  --value sta --server ./my-server --protocol-policy modern-only --json
```

Use `--context-file context.json` for sensitive or larger context. Omitted context,
`{}`, and `{"arguments":{}}` remain distinct; values are strings and the existing
protocol bounds apply (256 sibling arguments, 1 KiB keys, 16 KiB values, and
256 KiB of encoded argument data). The file must be regular and at most 1 MiB.
Prompt and argument names are bounded to 1 KiB; the partial value is bounded
to 16 KiB.

The existing connection options also support `--websocket-url` with
`websocket-experimental` and explicit `modern-only`. Context requires
`modern-only` on every transport. Context-free stdio and configured HTTP
connections retain existing Auto and exact MCP 2024-11-05 behavior when the
legacy feature is enabled. Completion does not accept input-capability or
resume-file flags. `--json` preserves the admitted result, including metadata,
exact numeric values, and the selected era's envelope. The existing
`--timeout` budget and connection cleanup apply.

### Manual CLI input continuations (current source tree)

`fastmcp call`, `fastmcp read`, and `fastmcp prompt` can complete MCP 2026-07-28
HTTP operations that return `input_required`. Each invocation sends one
application request. Select the kinds of input you can answer with repeatable
`--input-capability` options: `elicitation-form`, `elicitation-url`, `roots`,
or `sampling`. These options advertise manual support; the CLI emits the
request for review and waits for a separate, explicit invocation with answers.
The default capability set remains empty.

For example, begin a tool call and save its result:

```bash
fastmcp call publish-report \
  --http-url https://example.com/mcp --protocol-policy modern-only \
  --input-capability elicitation-form --arguments-file arguments.json \
  --json > round-1.json
```

An `input_required` result intentionally exits nonzero, while preserving the
result JSON on stdout. Check the saved document's `resultType` before resuming;
a connection or protocol failure also exits nonzero. If `inputRequests`
contains an elicitation keyed by `approval`, an answers file might contain:

```json
{"approval":{"action":"accept","content":{"approved":true}}}
```

Use the exact keys and response shapes requested by your server. Repeat the
original endpoint, command, target, arguments, and capabilities when submitting
the saved challenge and answers together:

```bash
fastmcp call publish-report \
  --http-url https://example.com/mcp --protocol-policy modern-only \
  --input-capability elicitation-form --arguments-file arguments.json \
  --resume-result-file round-1.json --input-responses-file answers.json \
  --json > round-2.json
```

The CLI validates the saved result and correlates every supplied answer before
contacting the server. Valid partial answers are accepted. If the server returns
another `input_required`, use that new result for the next explicit invocation;
its opaque `requestState` is forwarded unchanged. A result containing only
`requestState` requires an explicit empty `{}` answers file and sends no
`inputResponses` member. The server validates whether its state belongs to the
repeated operation and caller.

Both files must be readable regular files without duplicate JSON members.
The saved result is limited to 6 MiB and answers to 1 MiB. `--json` preserves
unredacted result content, including continuation state. Resume files and manual
input capabilities require an explicit HTTP endpoint with `modern-only` policy;
they cannot be used with Auto negotiation, legacy routes, or a newly spawned
stdio server. Timeouts and peer errors exit nonzero without replaying the action.

### Client request deadlines (current source tree)

Ordinary client requests use separate idle and absolute response-wait
deadlines. Both begin after the request send commits. The idle deadline
defaults to 30 seconds; the non-resettable absolute deadline defaults to 120
seconds. Serialization, sending, and teardown are outside these timers.
Unix subprocess sends have a separate two-second bound covering writer-lock
acquisition and the native pipe commit. These commits remain synchronous;
non-Unix sends retain blocking-I/O limits. Native WebSocket request sends have
their own absolute bound and observe request-local cancellation while writing;
an interrupted partial frame retires the connection without flushing its suffix.
Only a valid matching progress
notification on a request that actually supplied a progress token can reset idle.

On Unix, eager `ClientBuilder::connect_stdio_with_cx` initialization also
yields between bounded receive turns, including partial responses and Auto
negotiation. A fallback child starts only after the disposable modern child
has been cleaned up. With `auto_initialize(true)`, async requests and
`Client::ensure_initialized_with_cx` also yield during the first handshake.
Dropping that future preserves the handshake, partial response and original
deadline; the next async or synchronous call resumes it without another send.
Explicit cancellation after the handshake starts fails the connection.
Synchronous constructors and synchronous first use retain their blocking
boundaries; subprocess creation and write commits remain synchronous.

```rust
use std::time::Duration;

use fastmcp_rust::prelude::{Client, ClientBuilder, Cx, McpResult, RequestTimeoutPolicy};

async fn connect(cx: &Cx) -> McpResult<Client> {
    let policy = RequestTimeoutPolicy::new(
        Duration::from_secs(20),
        Duration::from_secs(90),
    )?;
    ClientBuilder::new()
        .request_timeout_policy(policy)
        .connect_stdio_with_cx(cx, "my-mcp-server", &[])
        .await
}
```

### Supervised stdio recovery (Unix)

`modern::ClientBuilder::connect_supervised_stdio_with_cx` creates an explicitly
supervised subprocess connection. Use `client_mut()` for application operations
and call `recover(cx, cancellation)` after a confirmed subprocess exit. Recovery
cleans up the failed generation, waits with bounded exponential backoff and
jitter, starts a replacement from frozen command, arguments, environment and
working directory, and completes fresh modern discovery before publishing a
new generation.

```rust
use fastmcp_rust::{Cx, StdioRestartError, StdioRestartPolicy, SupervisedStdioClient, modern};

async fn connect_supervised(cx: &Cx) -> Result<SupervisedStdioClient, StdioRestartError> {
    modern::client_builder()
        .connect_supervised_stdio_with_cx(cx, "my-mcp-server", &[], StdioRestartPolicy::default())
        .await
}
```

The default policy permits three replacement attempts in a sixty-second window,
with a 100-millisecond initial backoff, a five-second cap, and equal jitter. Attempts and
the recovery deadline remain charged when a recovery future is dropped or
cancelled. Dropping an in-progress discovery retains its replacement child for
resumption; explicit cancellation settles that child before another attempt.
If a replacement naturally exits during discovery, another attempt can use the
remaining original budget. Invalid or rejected discovery remains terminal.

An interrupted request carries `StdioInterruptedRequest` diagnostic evidence:
its outcome is unknown and any reissue must be explicit. Recovery never repeats
an application RPC or transfers old request handles to the replacement.
Write-side disconnects notify old handles before the process status can be
checked, so their diagnostic exit evidence can be absent; recovery still
requires the connection owner's private OS exit proof.
Protocol errors, application errors, timeouts, cancellation, explicit close,
EOF from a still-running process, and unverified cleanup do not authorize a
restart. The command configuration is frozen, but executable file contents are
not snapshotted. Call `close_with_cx` to await final process cleanup.

To keep observing catalog or resource changes across a subprocess restart, open
the listener through `SupervisedStdioClient::open_subscriptions_listener`, with
the caller context, cancellation token, `SubscriptionListenRequest` (or
`SubscriptionFilter`), and `SubscriptionTimeoutPolicy`. This explicitly opts
one listener into recovery. Read its events through the supervisor's
`next_subscription_event_with_cx` method.

After fresh discovery, recovery sends a new listen request and waits for a valid
acknowledgement before publishing the replacement connection. Request IDs keep
increasing across generations, including failed replacement attempts.
`StdioRecovery::catalog_subscription` reports the old and new listener IDs when
a listener was restored. This reports an observation gap: refresh the affected
catalogs or resources before relying on new events, because events during the
outage are not replayed. The new acknowledgement remains the first event the
application receives, and it may accept a narrower filter than the old peer.

Explicit listener cancellation and consumed subscription-terminal events remove
the recovery configuration. Dropping an in-progress restoration retains its one
committed listen request; resuming recovery does not send it again. Invalid acknowledgements,
subscription errors, and acknowledgement deadlines keep the replacement
unpublished and settle its subprocess. Listeners opened directly on `client_mut()`
and Tasks listeners require application-managed recovery.

### Proxy upstreams

A live modern `subscriptions/listen` can stay open on the same stdio
`Client` while other requests complete. Call
`Client::open_subscriptions_listener` and then
`Client::next_subscription_event` to drain acknowledgement, catalog, and
resource-update events without collecting the stream to terminal.
On Unix, `open_subscriptions_listener_with_cx` and
`next_subscription_event_with_cx` yield during initialization and between
bounded receive turns. Tasks offer the corresponding
`open_final_task_subscription_listener_with_cx` and
`next_final_task_subscription_event_with_cx` APIs. Dropping an event future
preserves the stream and partial frame for resumption; explicit cancellation
retires only that listener, leaving sibling requests usable. Cancellation
write failures retain the listener and its error. Writes remain synchronous.
`listen_subscriptions_typed` remains the collect-to-terminal adapter.
The same incremental pattern exists on HTTP (`HttpClient::start_subscriptions_listener`),
modern WebSocket (`WebSocketClient::open_subscriptions_listener`), and
`ProxyClient::start_catalog_listener` for stdio and modern HTTP upstreams.
Proxy catalog and Tasks listener startup and event methods are async and
take the caller's `&Cx`. HTTP opening yields while awaiting headers;
cancelling or dropping that opening closes its socket and releases the
route for another attempt. Dropping an event future preserves the installed
listener for resumption. Stdio startup and bounded receive turns retain
their synchronous I/O limits.
`ProxyUpstreamBindingRegistry::connect_http_with_protocol_plan` and
`connect_stdio_with_protocol_plan` are async and take the caller's `&Cx`
first. HTTP negotiation and exact-2024 initialization await that runtime;
Unix stdio initialization uses the client's yielding receive path. Interrupted
openings leave the registry cache unchanged, allowing a fresh attempt. Keep
the caller runtime alive while using a cached legacy HTTP/SSE connection.
Use `ProxyClient::catalog_typed_with_cx` or `catalog_with_cx` to fetch HTTP or stdio
catalogs on that runtime, including every page and its modern cache hints.
These methods release the route lock while awaiting HTTP I/O or between bounded
stdio receive turns and reject cursor cycles without returning a partial
catalog. Stdio writes and individual receive turns retain their synchronous
I/O limits. Backends without an upstream binding retain their synchronous
catalog implementation.

With `proxy` and `websocket-experimental` enabled, an idle modern WebSocket
client can also become a proxy upstream:

```rust
use fastmcp_rust::{AsyncWsClientTransport, Cx, modern};

async fn websocket_gateway(cx: &Cx) -> Result<modern::Server, Box<dyn std::error::Error>> {
    let transport = AsyncWsClientTransport::connect(cx, "ws://127.0.0.1:8080/mcp").await?;
    let upstream = modern::client_builder().connect_websocket_with_cx(cx, transport).await?;
    let proxy = upstream.into_proxy(1)?;
    let catalog = proxy.catalog_typed_with_cx(cx).await?;
    Ok(modern::server_builder("gateway", "1.0")
        .as_proxy_typed("remote", proxy, catalog)?
        .build())
}
```

The native adapter forwards tools, resources, resource templates, prompts and
completion, including typed `input_required` continuations and exact unknown
result fields. Matching progress and requested log notifications are forwarded
while a request is running, without accumulating them in the retained queue. Requests
share one cancellation-aware connection owner. Cancelling a queued request has
no upstream effect, and an active request retains ownership until its native
cancellation cleanup finishes. Keep the caller runtime alive for the connection.
Catalog and resource subscriptions share bounded ingress turns with ordinary
requests. With `tasks`, complete upstream Tasks discovery and an explicit
`ProxyTaskRetentionPolicy` also enable Task creation, get/update/cancel controls,
and status subscriptions. Task handles remain bound to their original route,
caller and authorized tool, including when an input-required call later creates
a Task. `ProxyClient::from_websocket` exposes the same adapter for callers using
the lower-level native client.

Task subscription acknowledgement and event waits honor the opening operation's
deadline and cancellation together with the listener owner's cancellation.
Cancellation finishes the native control write before releasing the connection
for reuse. A control rejected before dispatch leaves sibling requests usable;
an interrupted partial request send retires the uncertain connection instead of
appending another request to it. Request-specific Task identity and capabilities
never replace the shared session's metadata.

Exact-2024 proxy invocations preserve complete upstream `tools/call`,
`resources/read`, and `prompts/get` results, including content annotations,
metadata, open fields, tool error content, and the invocation's prompt
description. Custom handlers can provide these results through
`ToolHandler::call_legacy_result_async_in_request`,
`ResourceHandler::read_legacy_result_async_with_uri_in_request`, and
`PromptHandler::get_legacy_result_async_in_request`. Mounted handlers and tool
transformations forward these hooks; mounted resources rewrite their known URI
fields while retaining opaque extension data. Ordinary handlers retain the
checked conversion from their existing application result types.

Completion handlers preserve their result envelopes too. Modern
`completion/complete` proxy results retain `_meta`, unknown result members, and
exact JSON number spellings; exact-2024 results retain their opaque `_meta`.
Custom handlers can override
`CompletionHandler::complete_final_result_async_in_request` or
`complete_legacy_result_async_in_request` to return these complete results.
The defaults delegate to the existing request-owned completion value hooks.
Mounted target handlers and server-wide fallback handlers forward the result
hooks while rewriting the request reference to its original child name.
The router still checks completion value limits, final totals, and the selected
protocol era's metadata before emission. Target visibility, caller cancellation,
handler timeouts, and panic handling also apply to these hooks.

Exact-2024 resource subscribe/unsubscribe hooks also have awaited variants:
`ResourceHandler::on_subscribe_async` and `on_unsubscribe_async`. The live
dispatcher and mounted resources forward these hooks on the caller runtime.
Native proxies release the route lock during HTTP/SSE waits and between bounded
stdio receive turns.
Failed or interrupted proxy requests preserve local URI rewrites, and failed
synchronous hooks roll back the session's subscription membership. Remote
effects already acknowledged upstream cannot be rolled back by these guarantees.

HTTP and WebSocket clients also expose typed `list_tools`/`call_tool`/
`read_resource`/`get_prompt` verbs so callers do not have to decode a raw
core result for ordinary catalog and invocation traffic. HTTP and WebSocket
`list_tools_with_cancellation`/`call_tool_with_cancellation`/
`read_resource_with_cancellation`/`get_prompt_with_cancellation` honor a
caller-owned cancellation domain for those ordinary verbs.
Exact MCP 2024-11-05 HTTP+SSE clients use `Client::sse_with_cx` when the GET
event stream and POST message endpoints are already known.

With `websocket-experimental`, high-level modern WebSocket catalog calls and
initial resource reads reuse complete results while their peer TTL remains
fresh. Entries belong to one connection, retain exact result metadata and
unknown members, and report only their remaining TTL. Queued catalog/resource
notifications are processed before a candidate hit; invalidation also fences
responses already in flight. A full catalog traversal rebuilds a cached
nonterminal prefix under its existing cumulative limits.

The direct, `auto`, and `modern` WebSocket clients expose
`final_result_cache_enabled`, `set_final_result_cache_enabled`,
`final_result_cache_stats`, and `clear_final_result_cache`. Disabling the cache
does not pause TTL expiry or invalidation; clearing or closing the connection
erases retained entries. Raw requests, tool calls, prompt retrieval, Tasks,
input-required results, and MRTR continuations are not cached. Exact-2024
WebSocket calls keep their existing uncached behavior.

On Unix, `Client::call_tool_with_cx`, `read_resource_with_cx`, and
`get_prompt_with_cx` follow installed async reverse handlers when a modern
peer requests input. After initialization, all rounds and handler waits share
one absolute deadline; cancellation drops pending handler work and preserves
the connection. Deferred discovery keeps its separate initialization deadline
and connection-ending cancellation rules. Each
retry carries the original arguments and only the latest continuation state.
Without installed handlers, the input-required result is returned to the caller.

Installed modern MRTR callbacks also remain cancellable while pending in HTTP
and WebSocket clients, including callbacks that never wake themselves. Dropping
or interrupting a callback cancels its local token and prevents a continuation;
callback panics become redacted errors. These checks run between callback polls
and cannot preempt synchronous work or undo external effects inside user code.

Modern server continuations also have retained-payload limits. The default
router admits at most 4,096 live continuations overall and 1,024 for one
verified owner, with 64 MiB of retained payload overall and 32 MiB per owner.
`ServerBuilder::mrtr_retention_capacity(states_per_owner, bytes, bytes_per_owner)`
configures these bounds before startup, including through the `auto` and
`modern` facades. Verified ownership spans connections and credential rotation;
anonymous and unverified callers share one bounded partition. The accounting
includes input schemas, descriptors, accumulated answers, and private handler
state. A full partition refuses additional retained work without evicting
another conversation; a rejected growing partial answer leaves its original
continuation usable. Completion, cancellation, expiry, and listener shutdown
reclaim the corresponding retained state. These are process-local payload
limits, rather than allocator measurements or durable continuation storage.

With the `tasks` feature on Unix, `Client::call_tool_final_outcome_with_cx`
creates tasks without blocking the runtime while waiting for the peer. It
returns the typed complete, task, or input-required outcome. A returned task ID
can be used with `get_task_final_with_cx` and `cancel_task_final_with_cx` on the
same client. An already-admitted valid task result survives caller cancellation;
other results remain cancellation-first. Input-required results are returned
without automatic continuation. Pipe writes remain synchronous.

The published 0.14.0 CLI includes these flags. From a current source checkout,
run the CLI through the workspace to configure the two limits independently:

```bash
cargo run -p fastmcp-cli -- test --protocol-policy auto --idle-timeout 30 --absolute-timeout 120 my-mcp-server
```

The current `fastmcp test` subprocess runner is Unix-only because success
includes verified owned-process-group cleanup. Library callers should likewise
call `client.close()` and handle its `McpResult`; dropping a client is only a
best-effort safety net. The group anchor protects its numeric PGID while it is
live and closes an owner-death channel when the host exits, but this is not
portable process-tree containment or a substitute for Windows Job Objects.

### Test HTTP connectivity (current source tree)

A CLI built from the current source can test an HTTP server's negotiation,
liveness, and advertised tools, resources, and prompts without starting a
subprocess.

```bash
# Modern MCP endpoint
fastmcp test \
  --protocol-policy modern-only \
  --http-url https://mcp.example/mcp \
  --json

# Auto: supply the modern endpoint and both explicit legacy endpoints
fastmcp test \
  --protocol-policy auto \
  --http-url https://mcp.example/mcp \
  --legacy-sse-url https://mcp.example/sse \
  --legacy-message-url https://mcp.example/messages \
  --json

# Exact MCP 2024-11-05 over SSE and message POST
fastmcp test \
  --protocol-policy legacy-only \
  --legacy-sse-url https://mcp.example/sse \
  --legacy-message-url https://mcp.example/messages \
  --verbose
```

From a source checkout, replace `fastmcp` with `cargo run -p fastmcp-cli --`.
Auto and legacy-only require the `legacy-2024-11-05` feature. Auto requires all
three endpoints and falls back only when negotiation permits it; an application
failure after modern selection does not trigger a downgrade. The legacy SSE
and message endpoints must share an origin. Omit the subprocess command when
supplying HTTP endpoints.

For bearer authentication, add `--bearer-token-file ./mcp-token.txt` to the modern
command. The file must be a regular file containing at most 16 KiB, and the
modern endpoint must use HTTPS. Authenticated requests never fall back to
legacy. Add `--idle-timeout 10 --absolute-timeout 30` for shorter probe deadlines.
The defaults are 30 seconds idle and 120 seconds absolute; accepted ranges are
1–300 and 1–900 seconds respectively. For HTTP, the absolute limit also bounds
the complete connection handshake and each probe, including connection setup.
These limits do not impose one deadline on the entire command.

Modern liveness uses `server/discover`; legacy liveness uses `ping`. Catalog
probes fetch one bounded page for each advertised capability, mark unadvertised
capabilities as skipped, and report when more entries were omitted. `--json`
emits bounded, sanitized `fastmcp.cli.test/v1` results with the negotiated
protocol, probe outcomes, and local idle/absolute timeout sources. Failures
before testing begins use `fastmcp.cli.error/v2`. Failed tests return a nonzero
exit status; use `--verbose` for detailed text output.

**Requirements:**
- Rust nightly-2026-08-25 (see `rust-toolchain.toml`) for Edition 2024. The last FND-01 evidence snapshot still records `nightly-2026-07-11` until that harness is re-attested.

### Test native WebSocket connectivity (current source tree)

Build the CLI with `websocket-experimental` to run the same connectivity
diagnostics against a native WebSocket endpoint:

```bash
cargo run -p fastmcp-cli --features websocket-experimental -- test \
  --protocol-policy modern-only \
  --websocket-url wss://mcp.example/mcp \
  --idle-timeout 10 --absolute-timeout 30 \
  --json
```

This path requires explicit `modern-only` and accepts `ws://` or `wss://`.
Omit a subprocess command, HTTP/legacy endpoint flags, and bearer-token files.
Invalid transport combinations and unavailable feature builds fail before
opening a socket.

The command reports negotiation, fresh `server/discover` liveness, one uncached
page of each advertised tools/resources/prompts catalog, and explicit connection
cleanup. Unadvertised catalogs are skipped without sending their list requests.
The absolute bound covers connection setup and each probe; it is not one
deadline for the whole command. Cleanup retains the native client's bounded
close procedure, including after probe failure. JSON uses the existing
`fastmcp.cli.test/v1` schema and records timeout sources only when established
locally; peer-supplied error metadata cannot impersonate local diagnostics.

### Caller-owned modern stdio workflows (current source tree, Unix)

The modern stdio facade exposes asynchronous catalog traversal, ordinary
content operations, completion, liveness checks, and incremental listeners.
Each method takes the caller's `&Cx` and an explicit
`&McpRequestCancellation`, and yields between bounded receive turns.

For one page at a time, `list_tools_with_cx`,
`list_resources_with_cx`, `list_resource_templates_with_cx`, and
`list_prompts_with_cx` return the corresponding typed final page. They
preserve include/exclude tag filters and an optional opaque cursor, reuse
fresh results under the connection's invalidation rules, and do not fetch
the next page automatically. Pass the returned cursor explicitly to continue.

The four `list_all_*_with_cx` methods return `modern::CollectedCatalog`.
Its `pages()` contain complete `FinalCoreResult` values, retaining cache
hints, metadata, unknown result members, and exact numbers. Traversal keeps
opaque cursors intact and enforces cumulative page, item, byte, and elapsed
limits, including the permitted cache rebuild. An error returns no partial
collection; pass an absent initial cursor.

The modern HTTP facade exposes the same complete catalogs through
`list_all_tools`, `list_all_resources`, `list_all_resource_templates`, and
`list_all_prompts`. Each also has a `_with_cancellation` variant accepting a
request-local `McpRequestCancellation`. One token and one absolute deadline
cover all pages and the permitted cache rebuild. Cancellation interrupts a
stalled page and takes precedence over a cache hit, while independently owned
HTTP executions and the caller's `Cx` remain usable. The returned
`modern::CollectedCatalog` retains every complete typed page.

```rust
use fastmcp_rust::{
    ListToolsParams,
    modern::{Client, Cx, FinalCoreResult, McpRequestCancellation, McpResult},
};

#[cfg(unix)]
async fn discover_and_call(
    client: &mut Client,
    cx: &Cx,
    cancellation: &McpRequestCancellation,
) -> McpResult<FinalCoreResult> {
    let catalog = client
        .list_all_tools_with_cx(cx, cancellation, ListToolsParams::default())
        .await?;
    eprintln!(
        "{} tools across {} pages",
        catalog.item_count(),
        catalog.pages().len(),
    );
    client
        .call_tool_result_with_cx(
            cx,
            cancellation,
            "index_workspace",
            serde_json::json!({"uri": "file:///workspace"}),
        )
        .await
}
```

`call_tool_result_with_cx`, `read_resource_result_with_cx`, and
`get_prompt_result_with_cx` follow installed modern reverse handlers under
one operation-wide absolute deadline. Install those handlers with
`ClientBuilder::modern_reverse_request_handlers`. With no modern reverse
handlers installed, the complete `input_required` result is returned.
`complete_with_cx` and `ping_with_cx` provide the corresponding ordinary
completion and liveness operations.

Initial complete resource reads use the same connection-local result cache as
the synchronous typed resource API. Replays preserve result metadata and exact
unknown fields while aging the peer's TTL. Before a replay, the sole stdio
reader processes ready invalidations; partial frames, buffered input, or a
busy peer force a fresh request. Cancellation also applies to cache hits.
Input-required results and continuation rounds never populate this cache.
The yielding path starts cache freshness at the beginning of the fetch, so
wire and scheduling delay can shorten reuse but cannot extend the peer's TTL.

Use `open_subscriptions_listener_with_cx` and
`next_subscription_event_with_cx` to interleave a live catalog listener
with ordinary client requests. Dropping an event wait preserves the stream
for resumption; explicit cancellation retires that listener.

With the `tasks` feature, the facade also exposes
`call_tool_outcome_with_cx`, `get_task_with_cx`, `update_task_with_cx`,
`cancel_task_with_cx`, `open_final_task_subscription_listener_with_cx`,
and `next_final_task_subscription_event_with_cx`. Tool outcomes retain
their distinct complete, task, and input-required branches. These controls
do not imply persistent task storage.

Published request cancellation remains request-local. Deferred discovery
keeps its own connection-level cancellation rules, and dropped request
cancellation is flushed by the next drive, send, or close. Subprocess
creation and bounded pipe writes retain their synchronous limits.

### Explicit cancellation for exact-2024 stdio requests (Unix)

The sealed `legacy_2024::Client` supports a separate
`McpRequestCancellation` token for tool calls, ping, logging-level changes,
and resource subscribe/unsubscribe requests through their
`*_with_cx_and_cancellation` methods. Each method takes the caller's `&Cx`
followed by `&McpRequestCancellation`, then its ordinary arguments.

The component-level
`request_legacy_core_with_cx_and_cancellation` accepts the same token with
a typed `LegacyCoreRequest`. It keeps the caller and token attached to the
execution before publication, including while the future is parked. A
pre-cancelled token sends no application request. After initialization,
cancelling or dropping one published request retires that execution; queued
cancellation controls are serviced on the next drive, send, or close.
Cancelling a published initialization handshake retains its connection-level
cleanup behavior.

Responses still use exact-2024 decoding from their admitted wire source.
Control acknowledgements must be empty, modern result discriminators are
rejected, and resource updates or log messages received while waiting remain
available through the typed notification accessors. Ordinary peer errors
and tool-level error results keep their existing request-local behavior.
Response waits yield on the caller's runtime; bounded pipe writes and
subprocess creation remain synchronous.

### Live exact stdio progress (current source tree, Unix)

Modern stdio clients can observe progress while awaiting a tool, resource,
prompt, or completion result. The client generates and owns a progress token,
validates matching updates, and calls your observer on the caller's runtime.
Delivered updates are consumed immediately, so a long-running operation can
report more than the client's 64 retained diagnostic entries without filling
that queue. Progress and total retain their original JSON numeric spelling;
use `as_str()` when values must remain exact.

```rust
use fastmcp_rust::modern::{
    Client, Cx, FinalCoreResult, McpRequestCancellation, McpResult,
};

#[cfg(unix)]
async fn index_with_progress(client: &mut Client, cx: &Cx) -> McpResult<FinalCoreResult> {
    let cancellation = McpRequestCancellation::new();
    client
        .call_tool_result_with_progress(
            cx,
            &cancellation,
            "index_workspace",
            serde_json::json!({"uri": "file:///workspace"}),
            |update| {
                eprintln!(
                    "progress={} total={:?}",
                    update.progress.as_str(),
                    update.total.as_ref().map(|total| total.as_str()),
                );
            },
        )
        .await
}
```

The corresponding methods are `read_resource_result_with_progress`,
`get_prompt_result_with_progress`, and `complete_with_progress`.
For ordinary core catalog operations, the underlying `fastmcp_client::Client`
also offers `request_core_with_progress_with_cx`; that method rejects
caller-supplied `_meta.progressToken` values because it owns token allocation.

Keep observers short and nonblocking. A caught observer panic produces a
sanitized error; cancellation, timeout, or dropping the published request
retires only that request and preserves unrelated requests. Dropping queues
wire cancellation for the next client drive, send, or close. Deferred discovery
retains its separate connection-level cancellation rules. These methods send
one request and preserve the complete typed result, including
`input_required`, without automatically continuing MRTR or advertising Tasks.
They use the existing yielding receive path; subprocess creation and bounded
pipe writes retain their synchronous limits.

### Calling a tool and waiting for its Task (current source tree, optional)

On Unix, build the CLI with `--features tasks` and use `call --wait` to keep
the originating stdio process or HTTP client alive while an accepted Task
finishes. The peer must support the Tasks extension, and the protocol policy
must be explicitly `modern-only`:

```bash
fastmcp call generate-report --wait --protocol-policy modern-only \
  --server ./report-server --arguments '{"format":"pdf"}' --timeout 120 --json

fastmcp call generate-report --wait --protocol-policy modern-only \
  --http-url http://127.0.0.1:8000/mcp \
  --arguments '{"format":"pdf"}' --timeout 120 --json
```

The CLI sends the creating tool call once and prints its accepted Task receipt
before waiting. It observes that Task through the same client and request-ID
allocator, honoring the initial and subsequent `pollIntervalMs` values. An
immediate complete result or already terminal Task produces one JSON line.
A working Task produces its creation receipt followed by the latest admitted
Task snapshot when observation ends. The latter has no `resultType` wrapper
or copied creation-envelope metadata; completed result source is preserved.
Treat this output as newline-delimited JSON, including on a failed command.

Successful completion exits zero. Failed or cancelled Tasks, completed results
with `isError: true`, input-required pauses, expired retention, and local
observation failures exit nonzero. The accepted receipt remains available even
when observation fails. Waiting submits no input, repeats no tool call, and
does not send `tasks/cancel`. Manual input capabilities and continuation files
cannot be combined with `--wait`.

One `--timeout` covers connection setup, the creating call, and observation.
Each admitted Task output has a separate settlement of up to 250 ms for
ordinary Unix pipes and sockets; regular files and devices retain their OS
I/O behavior. Stdio cleanup is also bounded and may finish after the
active-work deadline. A blocked output pipe fails without starting another
request. The CLI cleans up a child it started, so recovery of a process-local
stdio Task after exit still requires server-owned persistence. This command
does not add durable Task storage or automatic reconnects.

### Tasks commands (current source tree, optional)

Build the CLI with `--features tasks` to expose `tasks get`, `watch`, `update`,
and `cancel`. These commands require modern MCP and bilateral
`io.modelcontextprotocol/tasks` support. The pinned extension is experimental;
this source implementation remains provisional. The published default
binaries do not include these commands.

```bash
cargo run -p fastmcp-cli --features tasks -- tasks get TASK_ID --http-url http://127.0.0.1:8000/mcp --json
cargo run -p fastmcp-cli --features tasks -- tasks watch TASK_ID --http-url http://127.0.0.1:8000/mcp --timeout 60 --max-events 100 --json
cargo run -p fastmcp-cli --features tasks -- tasks update TASK_ID --http-url http://127.0.0.1:8000/mcp --input-file responses.json --json
cargo run -p fastmcp-cli --features tasks -- tasks cancel TASK_ID --http-url http://127.0.0.1:8000/mcp --json
```

The input file contains the `inputResponses` map itself, for example
`{"roots":{"roots":[]}}` when the task's outstanding input key is `roots`
and its method is `roots/list`. Files are limited to 1 MiB. Updates use the
current task's input request types. Update and cancellation success mean
acknowledgement; use `get` or `watch` to observe subsequent task state.

Watch emits an initial snapshot and exits successfully if the task is already
completed, failed, or cancelled. Otherwise it subscribes to live updates and
reads the task again after subscription acknowledgement, so a terminal change
during subscription setup is also reported. It ends successfully on a terminal
update or after `--max-events` updates. Each
successful exit includes a `watch-ended` event; ending a watch does not cancel
the task. It does not reconnect or promise replay across disconnects.
`--timeout` defaults to 30 seconds, and timeout is a failed command. JSON mode
emits one document per event; human output bounds and sanitizes fields and
redacts recognizable credentials.

Use `--server EXECUTABLE` and repeat `--server-arg ARGUMENT` for stdio. Each
command starts a fresh process, so previously issued task IDs require a store
retained outside the prior process. For authenticated HTTPS, Tasks commands and
`inspect` accept `--bearer-token-file PATH`:

```bash
cargo run -p fastmcp-cli --features tasks,native-tls-roots -- tasks get TASK_ID --http-url https://mcp.example.com/mcp --bearer-token-file token.txt --json
```

The file must contain a UTF-8 token of at most 16 KiB, including an optional
trailing LF or CRLF. Do not include a `Bearer ` prefix or other whitespace or
control characters. The CLI reads a regular file once per invocation; callers
own token acquisition and refresh. Credentials require HTTPS and a modern or
auto protocol policy. Core-only builds omit Tasks from help and explain
the required feature when a Tasks command is attempted.

### Awaiting application input during a request

The memory client offers `call_tool_with_async_mrtr_retry`,
`read_resource_with_async_mrtr_retry`, and
`get_prompt_with_async_mrtr_retry` for operation-local responders that need
to await consent, model calls, or other asynchronous input sources. Pass the
caller `Cx`, a request cancellation token, one absolute deadline, and a
responder returning `MrtrResponderFuture`. The responder receives the same
caller context and a borrowed `InputRequiredResult`; return
`Box::pin(async move { ... })` with the complete response map.

Configure the responder's capabilities before connecting. The client admits
the entire input batch before invoking application code, checks the returned
keys before sending a continuation, and retains the original request arguments,
capabilities, and deadline across fresh request IDs. Cancellation, deadline
expiry, or dropping the operation drops a pending responder. Responders should
await cooperative operations; blocking inside a future's poll cannot be
preempted. No responder task or runtime is created.

With `tasks` enabled, use
`call_tool_final_outcome_with_async_mrtr_retry` to retain explicit Tasks
negotiation through the same continuation driver. An admitted Task receipt
still survives cancellation in the same final poll. This method does not
observe or cancel the resulting Task.

With `websocket-experimental` enabled, native WebSocket clients expose the
same three async responder methods, including the `modern::WebSocketClient`
and `auto::WebSocketClient` facades. They accept the explicit cancellation
token and keep one absolute deadline across the entire exchange, capped by the
configured request timeout. Auto sessions selected to exact 2024 reject these
modern-only operations before writing a frame.

With `tasks` enabled as well, the WebSocket facades expose
`call_tool_outcome_with_async_mrtr_retry`; the underlying client calls it
`call_tool_final_outcome_with_async_mrtr_retry`. Tasks capability negotiation
and accepted receipt handling follow the same rules as their synchronous
responder counterparts.

On Unix, `modern::Client` exposes the same three async responder methods
over native stdio. The underlying `Client` and the Auto client expose them
with a `_with_cx` suffix. Deferred initialization and every continuation share
the caller's cancellation token and absolute deadline. Exact legacy results
pass through the underlying and Auto clients without invoking the responder;
the Modern facade retains the complete modern result envelope. Ordinary
stdio responder operations do not opt into Tasks.

### Observing a Task returned by a tool

With `tasks` enabled, a Tasks-aware tool call returns
`FinalToolCallOutcome::Task(created)` when the server accepts asynchronous
work. For HTTP, `HttpClient::call_tool_final_outcome_with_cancellation` checks
that the peer supports Tasks before dispatch and returns the complete, Task,
or input-required outcome from exactly one tool call. It does not invoke
installed input callbacks. Unix stdio offers the corresponding
`call_tool_final_outcome_with_cx` method.

In the current source, configure the memory client with
`MemoryClient::builder(client_info).with_tasks()` before connecting.
`MemoryClient::call_tool_final_outcome` likewise returns one outcome without
automatic continuation. Use `call_tool_final_outcome_with_handlers` to fulfill
MRTR inputs through installed modern sampling, roots, and elicitation handlers,
or `call_tool_final_outcome_with_mrtr_retry` to supply a responder and an absolute
deadline for this operation. Advertise the responder's capabilities before
connecting; supplying it does not expand the connection's capabilities.

Both memory continuation methods retain the original tool, arguments, and Tasks
negotiation across fresh request IDs. They admit each complete input batch
before callbacks, bound continuation rounds and answers, and preserve the
original cancellation domain and operation deadline. A server can complete
normally or create a Task on any round. Without installed handlers, the handler
variant returns input-required directly. An already-admitted Task receipt
survives cancellation in the same final poll; these methods do not poll or
persist the Task, or repeat a call after uncertain delivery.

With `tasks` and `websocket-experimental` enabled, `modern::WebSocketClient`
also exposes `call_tool_outcome_with_handlers` and
`call_tool_outcome_with_mrtr_retry`. The underlying
`fastmcp_client::WebSocketClient` exposes the corresponding
`call_tool_final_outcome_with_handlers` and
`call_tool_final_outcome_with_mrtr_retry` methods. These submit the original
tool and each input continuation through the native WebSocket request owner,
preserving the initial capability advertisement, arguments, and absolute
deadline. A server may create a Task after any input round. Task receipts and
complete results retain their original result fields, metadata, and numeric
spellings. A Task receipt already admitted by the receiver survives
cancellation in the same receive poll; other outcomes still observe the
operation's cancellation and timeout. The caller owns subsequent Task
observation and cancellation. These calls neither use the result cache nor
repeat an uncertain send. The `auto::WebSocketClient` wrapper provides the
same two methods when legacy interoperability is enabled; a connection
selected to exact 2024 rejects them before sending a request.

Use `FinalTaskHandle::from_created(&created)` to retain that Task on the same
client without sending an extra `tasks/get` or repeating the tool call.
The creation receipt remains yours, including its metadata and unknown
envelope members; the handle retains the exact Task result.

The handle's `wait`, `wait_with_stdio`, `wait_with_memory`, and
`wait_with_websocket` methods respect the accepted Task's initial
`pollIntervalMs` before their first read. They stop at terminal state,
input-required, local cancellation, expiry, or the configured finite bounds.
Waiting does not answer input or cancel remote work. Keep using the original
client and authenticated identity. This in-process handoff does not persist a
Task or establish permission to use it through another client.

### Subscription-assisted Task driving (current source tree, optional)

With `tasks` enabled, a retained `FinalTaskHandle` can become a
`FinalTaskDriver` through `into_driver(FinalTaskDrivePolicy)`. Its
`drive_watching` method combines native HTTP Task notifications with bounded
polling and installed input callbacks. `drive_watching_with_memory` provides
the same workflow through the Memory dispatcher. Unix stdio uses
`drive_watching_with_stdio`; WebSocket uses `drive_watching_with_websocket`
with `websocket-experimental` enabled. Configure the client's roots, sampling,
and elicitation callbacks before connecting. The `modern` facade's stdio,
HTTP, and WebSocket clients expose this as `drive_final_task_watching`.

The driver can answer newly requested input and observe completion directly
from the subscription. Authoritative reads cover the attach/listen gap,
acknowledged input updates, ambiguous notification timestamps, and silent
streams. Reads respect the Task's latest `pollIntervalMs`. One invocation
budget covers subscription setup, waiting, reads, callbacks, and updates;
`with_maximum_notifications` also bounds repeated notifications.

Keep the same driver when continuing a Task. Its lifetime input ledger prevents
an already answered input key from invoking a callback again, including after
a partial update or a switch between watching and polling. Dropping or
cancelling input resolution preserves an interruption latch and requires
explicit reconciliation before further automatic callbacks. An empty accepted
filter or a normal subscription terminal falls back to bounded polling once;
an interrupted or malformed stream returns its error. The driver never
reconnects, replays an uncertain update, or cancels the remote Task merely
because local observation ends.

Stdio and WebSocket share each connection's existing reader between Task
notifications and authoritative reads, preserving a partially received frame
when a poll becomes due. An existing Task listener is left intact and prevents
the driver from opening a second one. Clean cancellation or dropping the driver
retires its exact listener while preserving independently owned catalog
listeners; a broken transport still follows its normal connection-failure rules.

### Authenticated HTTP clients (current source tree)

The SDK accepts a caller-acquired bearer credential bound to one exact HTTPS
endpoint. For example, with a caller-owned `cx` and an existing `token`:

```rust
use fastmcp_rust::{BoundBearerCredential, CanonicalHttpUrl, modern};

let endpoint = CanonicalHttpUrl::parse("https://mcp.example.com/mcp")?;
let credential = BoundBearerCredential::bind(endpoint.clone(), token)?;
let client = modern::ClientBuilder::new()
    .http_bearer_credential(credential)
    .connect_http_with_cx(cx, endpoint)
    .await?;
```

The same credential binding covers discovery, later request/subscription
POSTs, and reverse-response POSTs. It never attaches to cleartext HTTP, a different path or query, or a
redirect target. An authenticated Auto client refuses legacy fallback.
Applications own token acquisition and refresh; create a new client when the
credential changes. The CLI's `--bearer-token-file` uses this same binding.

The bounded JSON/SSE readers withhold JSON-RPC errors that reflect the exact
credential into their message or data, returning a typed diagnostic instead.
Successful application results and the raw native-stream API remain unmodified.

HTTPS uses the transport's bundled WebPKI roots by default. Enable
`native-tls-roots` on `fastmcp-rust`, `fastmcp-client`, or `fastmcp-cli` for the platform trust
store. That profile also honors the native certificate provider's
`SSL_CERT_FILE` and `SSL_CERT_DIR` overrides; these select the trust source,
and do not disable certificate or hostname verification.

### Built-in OAuth client secret verification (current source tree)

With `builtin-auth-server`, confidential client secrets use Argon2id v19 with
64 MiB of memory, three passes, one lane, a fresh 16-byte salt drawn by the
core's fallible OS-random boundary, and a 32-byte output. Registrations retain
the encoded PHC verifier instead of the original secret. Verification admits
only this exact policy, salt width, output width, and bounded canonical PHC
encoding before allocating Argon2 memory; imported higher costs and weaker
parameters are rejected.

The issuer runs this work on a dedicated Asupersync blocking pool. Two jobs
can hash concurrently, with at most 32 admitted jobs and 64 admissions per
one-second window. An admitted caller waits at most 30 seconds and checks its
runtime cancellation and deadline while waiting. Cancelling a waiter does
not release a running job's quota until its secret and work retire.
Overload or unavailable verification returns an explicit availability error.
Unknown clients, wrong authentication methods, and public-client exchanges
perform bounded dummy verification and share the same KDF admission budget.

Credential work holds no issuer-state lock. After verification, the issuer
revalidates the client's exact registration under the guard that reads or
commits state, so a result from a removed registration cannot authorize its
replacement. Cancellation is checked again before consuming codes, rotating
refresh tokens, or committing token and revocation state.

Native OAuth HTTP routes require an admitted blocking worker and refuse
expensive dispatch with 503 when none is available. Immutable authorization
server metadata remains available without that worker. Listener cancellation
is forwarded to the route's context, and connection ownership continues until
the blocking callback retires. Application callbacks must still cooperate
with cancellation. The synchronous `OAuthServer` APIs wait for KDF completion;
async embedders must call them from a blocking lane.

The profile without `builtin-auth-server` retains its development-only salted
SHA-256 verifier. This change does not promote the in-memory issuer to durable
or production-qualified OAuth/OIDC support.

### Enterprise authorization components (native, opt-in)

Enable `enterprise-auth` to use
`fastmcp_rust::http_auth::enterprise`. Its modules keep independently
configured trust, OIDC code-flow handling, cryptographic verification,
response admission and local identity resolution separate:

- `policy::EnterpriseProfile::from_documents` admits both authorization
  servers and both preregistered clients. It checks their exact issuers,
  endpoints, grant declarations and confidential-client methods. OIDC and
  ID-JAG signing authority are configured separately.
- `keys::EnterpriseKeySource` fetches both configured JWKS endpoints through
  credential-free guarded HTTPS under the caller's context. It returns
  separate OIDC and ID-JAG key owners together, bound to the frozen profile
  and their independent key generations.
- `oidc::OidcCodeFlowConfiguration` admits the strict web/code/query/S256
  registration and the original IdP permission to request `openid`. It generates
  independent state, nonce and verifier values under the caller's capability
  and time budget, then serializes an exact authorization GET.
- `verification` verifies real RS256 signatures under distinct OIDC and
  ID-JAG key types. It checks exact audience/client/resource bindings,
  configured tenancy, nonce, optional OIDC `at_hash`, and bounded lifetimes.
  NumericDate fractions and exponents are evaluated exactly without floats.
- `response` composes that verification with bounded HTTP/JSON admission.
  OIDC code responses, ID-JAG responses and final access-token responses have
  distinct accepted shapes. Signed scope narrowing must agree with the
  top-level grant, and the final response must name the exact scalar resource
  and explicit scope subset.
- `identity::EnterpriseSubjectMappingTable` resolves the verified OIDC and
  ID-JAG subjects through an immutable, preexisting mapping table. Its reviewed
  snapshot fixes three distinct registration roles, explicit tenant
  relationships, trust domains and client-ID scope. Pairwise subject strings
  may differ; matching text never creates an account association. Lookup is
  bounded and uses an ordered index, with no create, link or update operation.
- `replay::IdentityAssertionReplay` consumes a verified assertion and composes
  persistent MAC derivation, a registered restore-authority write intent, an
  atomic assertion-use store, and independent commit acknowledgment. It returns
  an exclusive reserved assertion only after the complete transaction succeeds.
- `credentials::EnterpriseClientCredentialProvider` reads a confidential-client
  secret from an exact, independently selected `PersistentBlobStore` revision.
  Its protected record binds the complete profile, current identity snapshot,
  credential role and generation. Rotation and revocation invalidate pending
  reads and exchanges as well as credentials already acquired by the driver.

The native OIDC sequence is
`OidcCodeFlowConfiguration::prepare` →
`PreparedOidcAuthorization::admit_callback` →
`EnterpriseExchangeDriver::exchange_oidc_code_for_identity`. Callback admission
checks the exact route, state, issuer and decoded parameter uniqueness. The
driver consumes the code grant, adds the preregistered Basic or secret-post
client authentication, and posts to the original IdP endpoint through guarded
HTTPS. The form contains the grant, code, redirect URI and PKCE verifier;
MCP scope, resource and audience fields are never added to this code grant.

The response validator retains the generated nonce and selected client/tenant
expectations, and verifies the real ID-token signature and optional access-token
hash. Profile, response-policy or key-generation drift is rejected before any
POST. Dispatch shares the driver's single-flight slot and is bounded by the
code's original expiry, the caller's budget and the fetch policy. Redirects and
automatic retries are refused; each outcome consumes the code grant.

A successful identity still needs `IdentityAssertionReplay::reserve` before
`exchange_identity_for_id_jag` can redeem it. Its sealed result retains the
original verified OIDC identity alongside the verified ID-JAG. The subsequent
`exchange_id_jag_for_access_token` requires the current
`EnterpriseSubjectMappingTable` and an independently selected expected snapshot.
It resolves that exact same-flow subject pair before constructing the
resource-AS authenticated request, and checks the mapping again through
dispatch and response admission. An absent row, changed subject, expired review
or mismatched snapshot prevents redemption. Unequal pairwise subjects work
only through an explicit preexisting row.

The resulting resource-bound credential retains the resolved local subject,
snapshot and signed-token binding digests. Its usable lifetime cannot exceed
either signed assertion or the mapping review. Code redemption does not bypass
the durable replay boundary, and successful mapping does not create or link an
account.

For protected credential custody, provision separate IdP and resource-AS records
using `EnterpriseCredentialBinding::new` and `encode_record`, then commit them
with the registered protected store's `create` or `replace` operation. Retain
each exact returned revision in trusted configuration and pass it, its
credential generation and a monotonic validity deadline to
`EnterpriseClientCredentialProvider::new`. The IdP role serves code redemption
and ID-JAG exchange; the resource-AS role serves final JWT-bearer redemption.
The backend cannot select a newer record or substitute another role or profile.

Use the driver's `exchange_oidc_code_for_identity_with_provider`,
`exchange_identity_for_id_jag_with_provider`, and
`exchange_id_jag_for_access_token_with_provider` methods to consume those
providers. Each requires the independently current identity snapshot. Input,
key and subject-mapping admission precedes credential access, and acquisition,
serialization, POST and response admission retain the original deadline and
caller capability ceiling. A provider error ends the operation; these entry
points do not accept a fallback plaintext secret.

After committing a replacement record, `provider.rotate` selects its exact
revision and a strictly higher credential generation. It immediately invalidates
the prior generation, including exchanges waiting for a response.
`provider.revoke` permanently revokes that provider. Neither operation cancels
sibling caller contexts, and a refused exchange does not retry its grant.
The protected store's external envelope, blob and restore-authority providers
remain deployment trust boundaries. This component does not establish durable
browser-flow custody or activate the complete enterprise authorization profile.

To use that result with the native MCP HTTP client, create an
`http::EnterpriseHttpPolicy` from the same admitted `EnterpriseProfile`, the
independently selected current identity snapshot, and the independently
established monotonic freshness deadlines for the IdP and resource-AS metadata.
The token's subject binding must match that policy snapshot exactly. Then consume
the exchanged token with
`EnterpriseBoundAccessToken::into_http_credential(&policy, now, wall_now)` and
pass the result to `modern::ClientBuilder::http_bearer_credential`.

The builder carries the exact
`io.modelcontextprotocol/enterprise-managed-authorization: {}` client
declaration on discovery and subsequent modern MCP requests. Existing Tasks,
Apps, and application extension settings are preserved. A conflicting nonempty
enterprise declaration is rejected. This authorization overlay does not invent
a `server/discover` capability or extension descriptor.

Keep the policy owner alive for the client's lifetime. Revoking, replacing, or
dropping it invalidates every credential lease, including a request prepared
before revocation. Policy replacement must advance its policy generation and
cannot roll back metadata, registration, key or identity snapshot generations.
Changing the identity snapshot requires advancing its generation; a rejected
replacement leaves existing leases unchanged. The complete exchange profile,
identity snapshot and original metadata document identities must match, and the
earlier metadata deadline can only shorten the token's original lifetime.
Raw HTTP requests must carry the exact current declaration in their encoded
metadata before the credential can be attached; the target-only credential
accessor withholds policy-bound enterprise tokens. Raw notifications and replies
use `ModernHttpRequest::control` to omit request-only routing headers. This is the
post-exchange MCP HTTP path; browser custody, deployment-provider qualification, SAML, and
built-in enterprise token issuance retain their separate implementation gates.

#### Protecting a native HTTP resource

The facade's `enterprise-auth` feature also enables the resource-server path.
Create an `EnterpriseResourceConfiguration` with the exact IdP and resource-AS
issuer/token-endpoint pairs, the canonical MCP resource, and nonzero policy and
metadata generations. `EnterpriseResourcePolicy::new` admits both bounded,
duplicate-free metadata documents and their original monotonic freshness
deadlines. The IdP must advertise token exchange and the ID-JAG requested token
type; the resource AS must advertise the ID-JAG grant profile and JWT bearer
grant. Metadata provenance remains the deployment's responsibility.

Install the policy through the ordinary authentication hook:

```rust
use fastmcp_rust::{
    EnterpriseResourceError, EnterpriseResourcePolicy, modern::ServerBuilder,
    providers::JwtResourceVerifier,
};

fn protected_server(
    policy: &EnterpriseResourcePolicy,
    verifier: JwtResourceVerifier,
) -> Result<ServerBuilder, EnterpriseResourceError> {
    Ok(ServerBuilder::new("enterprise-resource", "1.0")
        .auth_provider(policy.provider(verifier)?))
}
```

The independently provisioned `JwtResourceVerifier` must match the configured
resource-AS issuer and MCP resource. It verifies the real RS256 signature,
`at+jwt` token type, issuer, resource audience and lifetime on each access token.
Every modern MCP request must also carry the exact official enterprise
declaration with `{}` settings. The provider accepts only native HTTP
`Authorization`; an extension declaration, ID Token, or ID-JAG cannot substitute
for a verified resource access token. This profile adds no `server/discover`
RPC extension descriptor.

Keep the policy owner alive while the server is serving. Revocation, owner drop
or successful policy replacement invalidates previously issued authentication
leases as well as new admission. Replacement advances the policy generation,
rejects metadata generation rollback, and cannot change the resource or its
token issuer. JWT key replacement and revocation independently retire leases
from the old key generation. Refreshed authorization preserves the same verified
owner identity, so rotation does not strand an otherwise authorized Task. These
leases are enforced at request, Task and output checkpoints; already completed
application effects cannot be recalled. SAML, browser custody, built-in
enterprise issuance and durable deployment qualification remain separate work.

The lower-level `OidcCodeGrant::write_token_form` and
`OidcCodeResponseAdmission::admit_token_response` remain available to embeddings
with their own dispatcher. That codec writes to a caller-selected confidential
sink, which can observe the code/verifier and must erase its buffers. A partial
write cannot produce a response-admission owner. The authorization URL still
requires an external browser adapter; local byte digests do not establish
browser-launch provenance or durable callback custody.

For native signing-key acquisition, construct `keys::EnterpriseKeySource` with
the admitted profile, a `GuardedHttpFetcher`, and a nonzero fetch-policy
generation. Configure at most 64 KiB per response and a fetch deadline no
greater than 30 seconds. Reuse or clone the source so overlapping calls share
its single acquisition slot.

Calling `fetch(cx).await` makes separate GETs for the configured OIDC and ID-JAG
sources, even when the operator explicitly selects the same URL for both
purposes. The entire pair shares one original deadline and the caller's
authority. Redirects, malformed documents, mismatched transport provenance or
failure of either fetch prevent publication of the pair. Cancellation and
abandonment retain the acquisition slot until guarded child operations settle.

The returned `EnterpriseVerificationKeySet` exposes `profile()`, `oidc()` and
`id_jag()` for the existing signed-response consumers. Its observations retain
the exact endpoints, document digests, key generations and guarded TLS
provenance. Refresh is explicit; key identifiers in peer tokens cannot initiate
network requests.

With an already-admitted profile, purpose-bound ID-JAG keys, and a response
obtained from the selected trusted endpoint:

```rust
use std::time::SystemTime;
use fastmcp_rust::http_auth::enterprise::{
    response::{EnterpriseResponsePolicy, EnterpriseTokenResponse},
    verification::{ResourceTenantExpectation, TenantExpectation},
};

let admitted = profile.admit_id_jag_response(
    EnterpriseTokenResponse { status, headers, body },
    &id_jag_keys,
    TenantExpectation::SingleTenant,
    ResourceTenantExpectation::SingleTenant,
    EnterpriseResponsePolicy::default(),
    SystemTime::now(),
)?;
```

The result distinguishes success, a redacted OAuth denial, and a bounded
first-stage step-up indication. Step-up never automatically launches a browser
or reuses an assertion. Successful owners keep compact tokens private in
zeroizing memory and have no Clone, Debug, serialization or bearer-header
conversion. An admitted ID-JAG owner is consumed when validating a final
response; its original scope request, signed IdP grant and final grant remain
separate. Missing cache-prevention headers produce bounded diagnostics, while
conflicting or explicitly cacheable policies are rejected.

Optional signed ID-JAG disclosures require an explicit
`verification::disclosure::IdJagDisclosurePolicy` for the exact IdP and
resource-AS relationship. The current schemas cover `email`, `auth_time`,
`acr` and `amr`; each permission has a reviewed purpose and the policy has a
finite review window. Use `verify_id_jag_with_disclosure` or
`EnterpriseProfile::admit_id_jag_response_with_disclosure` to select it.
Values are validated and discarded. Only admitted claim names and the
configuration digest remain, and review expiry bounds later response admission
and the locally retained final token. The ordinary verification method keeps
its closed claim set; actor, subject-alias, RAR and sender-constraining claims
cannot be enabled through this policy.

The native driver performs the three distinct grant exchanges, but complete
enterprise sign-in still requires browser/callback custody and deployment
qualification. These components do not activate the MCP extension.
The mapping table supports public, redirect-host pairwise, and explicitly
reviewed sector-document OIDC subject namespaces. It rechecks the current
profile, selected snapshot, signed token bindings and review/claim lifetimes on
every lookup; results retain the exact token and snapshot digests. A local
snapshot digest does not establish a rollback-resistant policy fence or prove
that responses came from one exchange.

For a preregistration that declares `sector_identifier_uri`, first call
`identity::OidcSectorDocumentReview::fetch` with the complete relying-party
registration, its explicit Client or ResourceAuthorizationServer role, and a
`GuardedHttpFetcher` under the caller's context. This performs one bounded,
credential-free HTTPS GET. The response must be an HTTP 200 JSON array containing
every exact registered redirect URI. Additional document entries never authorize
callbacks. The review binds the registration generation, issuer, tenant, client,
role, redirect set, sector URL, exact document digest, fetch policy and observed
TLS provenance.

Use `oidc::OidcCodeFlowConfiguration::from_documents_with_sector_review` to select
one callback from that complete reviewed registration, including registrations
with multiple redirect hosts. Use
`identity::EnterpriseSubjectMappingTable::from_trusted_configuration_with_sector_reviews`
to bind the independently reviewed client and resource-AS sectors into the
mapping snapshot. Both consumers retain the frozen evidence and perform no
refetch during ordinary authorization flows.

#### Protected persistent records

`fastmcp_rust::persistent::PersistentBlobStore` provides asynchronous `create`,
`read` and `replace` operations over a configured external encryption provider,
transactional blob store and registered restore authority. These operations use
the caller's context and deadline and share finite operation and buffer budgets.

- Creation inserts a new random record ID only if it is absent. Replacement
  compares the complete expected revision; it never performs an unrestricted
  upsert.
- Every write durably prepares its restore intent before encryption. The store
  atomically commits the exact ciphertext, revision and intent under the durable
  restore fence, and the authority verifies the commit proof before the caller
  receives the new revision.
- Reads require an exact `PersistentBlobRevision` retained in trusted
  application control state. Canonical framing, the admitted key generation,
  ciphertext digest and authenticated record context are checked before
  plaintext is released. Store data cannot choose a newer revision or substitute
  its own expected context.
- `BoundedPlaintext` owns a zeroizing allocation. Returned plaintext retains its
  byte reservation until it is dropped or explicitly transferred to its caller.
  Limits account for allocation capacity, including spare capacity.
- A failed comparison returns `Conflict` only after durable evidence proves that
  the losing operation cannot commit later and the authority settles its intent.
  Unknown outcomes leave the deployment closed for recovery.

`PersistentEnvelopeBackend` owns the complete persistent key, nonce and AEAD
implementation. The facade accepts only canonical FMCPBOX version 1 with the
XC20P suite and constructs typed FMCPENV authenticated context for the fixed
protected-blob payload purpose. The encryption provider and blob store each
have independently pinned artifact and configuration identities. No raw
persistent key is passed into the process-ephemeral protector.

Applications retain the returned revision, including across restart, and
implement the external provider contracts for their deployment. This is a
protected-record storage API; native enterprise sign-in, durable OIDC flow
orchestration, key-provider qualification and epoch migration remain separate
work.

#### External replay and restore providers

The replay path has three independently implemented provider boundaries:

- `fastmcp_core::replay::PersistentHmacSha256Backend` supplies persistent MAC
  creation and verification. `PersistentReplayDigest` constructs the exact
  purpose-separated input and derives aliases under **every** configured active
  and previous generation. Partial results never become an alias set.
- `fastmcp_core::restore::RestoreEpochAuthority` supplies external store-set
  registration, current-epoch certification, write-intent preparation and
  completion. `RestoreEpochFacade::register` fixes the entire configured store
  union before releasing any `RegisteredRestoreStore`. Canonical stable binding
  digests exclude transient operation IDs, observation times and transport data.
- `replay::IdentityAssertionUseStore` atomically checks and reserves the whole
  alias set, journals its exact outcome with the durable fence CAS, and returns
  a commit proof for the independent restore authority to verify. The client
  pins the store adapter's artifact and configuration identity as well as the
  MAC ring and its deployment acknowledgment identity.

Facade users can import the provider modules through
`fastmcp_rust::http_auth::enterprise::replay::{persistent_mac, restore_authority}`.

The replay key depends on the exact verified issuer and compact-token digest.
Changing flow, browser session, client registration or policy evidence cannot
create a second key for the same assertion. Tombstones retain authority through
the signed expiration plus the fixed global 300-second positive-skew ceiling;
a later policy cannot shorten that horizon. Rotation looks up every admitted
previous alias before allowing a new reservation.

`IdentityAssertionReplay::reserve` consumes the protected assertion on every
outcome. Its caller-owned operation is bounded by the caller deadline, remaining
assertion lifetime and a 30-second ceiling; store work is also bounded by the
write intent's expiry. An uncertain write, malformed receipt, cancelled
post-dispatch operation or abandoned fence closes the registered deployment to
new writes and preserves unresolved external state. Dropping a local owner
never releases a tombstone or automatically retries a mutation.

These contracts are implementable external boundaries, not bundled persistent
services or attestations. The adapters must independently prove durable key
custody, atomic all-generation reservation, cluster ring agreement, external
rollback/clone resistance and authenticated commit verification. The shipped
test adapters are explicitly in-memory fault fixtures.

`RestoreEpochFacade::recover` reconciles a bounded, snapshot-consistent view of
unresolved writes through the exact pre-registered store union. Each independent
`RestoreStoreRecovery` adapter must supply either the real durable commit proof
or a durable terminal noncommit proof that fences out the original writer.
A missing record, timeout or expired intent is insufficient. The authority
verifies each proof against the original intent before settling it.

After process loss, `RestoreEpochFacade::recover_after_restart` accepts the
original deployment configuration and complete store union without requiring
an existing facade. It creates only quarantined internal handles, resolves the
persisted intents, and performs ordinary authority registration only at the
end. Every provider request must match the authority's previously registered
deployment, configuration and store-set identity; recovery cannot bootstrap a
new authority namespace or silently change an epoch.

Recovery permanently retires the old handles. A completed snapshot returns a
summary; fresh handles are returned only if a new authority registration
atomically refuses every remaining unresolved intent or closed deployment and
every store retains its original stable epoch binding. A proved live CAS loser
can use `RegisteredRestoreStore::reconcile_write` to settle its owned fence and
return a normal conflict. Unknown outcomes remain unresolved. Administrative
epoch advance and fenced migration remain unfinished.

Durable browser launch/callback custody, confidential credential providers,
attested mapping authority and qualified deployments of the replay/restore
providers remain required before activation.
SAML and durable/distributed server Task stores remain separate incomplete
extension work.

### Sender-constrained credentials: DPoP (RFC 9449), caller-driven

`fastmcp_rust::http_auth::dpop` is a **public, explicit, caller-driven** API for
DPoP. It is deliberately *not* wired into the bearer OAuth driver: its module
documentation states that it "never promotes a DPoP token into the existing
bearer-only OAuth driver" and "does not install automatic OAuth negotiation or
HTTP retries". With the low-level session API, the application owns authenticated
HTTPS I/O, response-size limits, and cancellation of in-flight I/O. The explicit
native adapters described below can own those operations. The application
chooses when to acquire a DPoP grant and whether to retry a nonce challenge;
ordinary bearer operations never switch to DPoP automatically.

One session pins one HTTPS token endpoint, one exact HTTPS MCP resource, and
one ES256 proof key. The two types a caller must name to open one — `DpopKey`,
the first argument, and `DpopError`, carried by `DpopClientError::Proof` — are
re-exported from this same module, so `fastmcp_rust::http_auth::dpop` is
self-contained. They originate in `fastmcp_protocol::dpop`, which the facade
does not forward, so without that re-export the API would be reachable without
being constructible. The flow, in call order:

1. `DpopSession::new` — pin the endpoint, resource and key.
   `DpopSession::authorization_jkt` exposes the key thumbprint for a
   confirmation claim.
2. `DpopSession::token_request_headers` — build the headers for your token
   request, then perform that request yourself.
3. `DpopSession::admit_token_response` — strict, bounded, duplicate-free
   admission of the response. It yields a `DpopCredential`, and refuses a
   bearer downgrade or a mismatched proof key rather than accepting one.
4. `DpopSession::resource_request_headers` — build the headers for the MCP
   request, again performed by you.
5. On a nonce challenge, feed the nonce back with
   `DpopSession::observe_token_nonce` or
   `DpopSession::observe_resource_nonce` and generate *new* headers for a
   retry you deliberately admit. Never replay a proof, and never
   automatically replay a possibly-executed MCP call.

`DpopRequestHeaders::apply_to` and `DpopRequestHeaders::into_headers` move the
prepared fields onto your request. `DpopCredential::expires_at`,
`DpopCredential::revoke` and `DpopCredential::is_revoked` cover lifetime and
revocation; `DpopSession::revoke` irreversibly retires the session and every
credential it issued. AS and RS nonce state are kept separate. Errors are the
redacted `DpopClientError` variants — no peer text, URL, proof, token or
response body is retained.

The full contract, including what each refusal means, is the module
documentation on `fastmcp_client::http_auth::dpop`; read it before driving the
flow, because several of the rules above are the caller's to honour rather than
the library's to enforce. `fastmcp_protocol::dpop` holds the ES256 proof and
RFC 7638 thumbprint primitives behind the `jose` feature. A bounded native
HTTPS resource POST is available under the module's `native` submodule for
callers who would rather not own that I/O.

#### Native DPoP authorization-code acquisition

`http_auth::oauth::OAuthClient` also provides explicit native-public-client
entry points: `authorize_dpop(cx, key, launch_browser)` uses a loopback callback,
and `authorize_dpop_with_redirect_driver(cx, key, redirect_uri, driver)` uses
the host's independently registered HTTPS callback. The caller supplies the
proof key and browser or callback driver. Both paths retain state, S256 PKCE,
issuer, scope, resource, and exact callback checks; the authorization request
binds `dpop_jkt`, and the bounded HTTPS token POST carries a fresh proof for
that same key.

The result is `oauth::dpop::DpopAuthorizationOutcome`. `Authorized` owns the
session and proof-bound access credential; `into_parts` transfers them to the
explicit `dpop::native::DpopHttpClient`, whose resource TLS policy is selected
separately. `NonceRequired` owns one in-memory continuation. After choosing to
continue, consume it with `retry(cx)` for at most one token-endpoint nonce
retry. It preserves the original code, key, cancellation, and deadline, also
enforces a stricter supplied caller, and produces a fresh proof. An ambiguous
transport failure does not authorize another retry.

This access-only flow rejects bearer downgrades, wrong proof-key bindings,
scope expansion, and refresh, ID-token, or token-exchange response profiles.
Authorization-server and resource-server nonces stay separate. No credential
is converted to the bearer driver, and no browser process, automatic refresh,
resource-operation replay, or durable callback custody is created.

#### Explicit rotating DPoP refresh

Public clients whose validated issuer registration and requested scopes permit
refresh can select `authorize_renewable_dpop` or
`authorize_renewable_dpop_with_redirect_driver`. These entry points retain the
same callback and proof-key checks and require a valid refresh token in the
initial response. The access-only entry points keep their existing response
policy.

`DpopAuthorization::into_renewable_parts` returns the session, access credential,
and exclusive `DpopRefreshToken` custody. An existing native resource client can
renew in place with `DpopHttpClient::refresh_authorization(cx, refresh_token)`.
It retains the same HTTP transport, resource TLS roots, body-size limit, request
timeout, nonce state and existing revocation handles. The token endpoint still
uses its separately admitted issuer TLS policy. The consuming nonce continuation
keeps the client mutably borrowed until explicitly retried or dropped, so no
resource request can race the pending renewal.

For low-level session ownership, recover the original session with
`DpopHttpClient::into_session` and call `refresh_token.refresh(cx, &mut session)`.
Both paths use the original issuer, client, token endpoint, resource, TLS trust
and granted scope ceiling. Renewal cannot transfer to another session, even one
with the same proof key and endpoints.

`DpopRefreshOutcome::Refreshed` contains a new access credential and a
byte-distinct successor refresh token. A narrowed scope grant becomes the next
refresh ceiling; an omitted scope preserves that ceiling. Existing access
snapshots retain their original expiration. Access expiration permits renewal,
while local credential or session revocation prevents it.

`DpopRefreshOutcome::NonceRequired` hands one consuming continuation back to the
application. Its explicit `retry(cx)` retains the original transaction and
deadline and produces a fresh proof. A second challenge is terminal. The
authorization-server nonce remains separate from the resource-server nonce.

After renewal preflight succeeds, cancellation, a dropped future or continuation,
a disconnect, or any rejected response revokes the complete session, including
access snapshots from earlier rotations. The consumed refresh token is erased
and never automatically replayed. Preflight refusal sends nothing and preserves
existing access snapshots, although the consuming refresh owner is erased.
Dropping unused refresh custody also erases only that secret. This API provides
in-memory rotating custody; it does not provide persistent refresh storage,
automatic login, nonrotating refresh, or automatic resource-call retries.

#### Protected DPoP Task restart

With the `tasks` feature, `DpopHttpClient::prepare_task_restart` consumes a
complete `TaskResumeRestartPlan` of protected, owner-bound Task controls. The
host supplies its current verified owner/profile binding and explicitly selects
the DPoP client and credential. Saved records cannot select a login, endpoint,
proof key, or TLS trust policy.

The returned `DpopTaskRestart` reconciles records sequentially through fresh
authenticated discovery and `tasks/get`. The batch retains one deadline and one
response-byte budget across records. Local expiry and remote unavailable results
are explicit outcomes; operational errors and an abandoned read close that
restart owner while retaining the pending record, any completed response, and
unvisited records for inspection. The workflow does not replay Task creation,
submit inputs, cancel remote work, or automatically open watches.

Handle a terminal application result before applying the item's conditional
`storage_change`. An active replacement preserves the original local retention
window, and writes compare the exact staged version. A changed checkpoint must
be reconciled explicitly. Loading a plan stages the complete bounded selection
before network work, so later checkpoint writes cannot invalidate an enumeration
cursor halfway through recovery.

On Linux, a completed `AsyncTaskResumeStore::try_load_restart` operation can
call `prepare_persisted_dpop_restart` to bind that staged selection and its
protected store to the DPoP client. The returned `PersistedDpopTaskRestart`
retains each application outcome until the host explicitly `acknowledge`s it
or takes it without persisting. An interrupted acknowledgement keeps the
original storage job; the next acknowledgement observes that job instead of
submitting a second write. A failed write retains the result, exact checkpoint
change, and store for recovery through `into_parts`. Local acknowledgement has
its own caller budget and does not renew the batch's remote authorization or
retention window. Handle or durably save terminal results before acknowledging;
a crash before acknowledgement can deliver the result again.

---

## Quick Start

### 1. Create a New Project

```bash
cargo new my-mcp-server
cd my-mcp-server
```

### 2. Add FastMCP

```toml
# Cargo.toml
[dependencies]
fastmcp-rust = { git = "https://github.com/Dicklesworthstone/fastmcp_rust" }
asupersync = "=0.6.2"
```

### 3. Write Your Server

```rust
// src/main.rs
use asupersync::runtime::{RuntimeBuilder, reactor::create_reactor};
use fastmcp_rust::{auto::ServerBuilder, prelude::*};

#[tool(description = "Echo the input message")]
async fn echo(ctx: &McpContext, message: String) -> McpResult<String> {
    ctx.checkpoint()?;
    Ok(message)
}

fn main() {
    let runtime = RuntimeBuilder::current_thread()
        .with_reactor(create_reactor().expect("create I/O reactor"))
        .blocking_threads(0, 16)
        .build()
        .expect("create application runtime");
    runtime.block_on(async {
        let cx = Cx::current().expect("application context");
        ServerBuilder::new("echo-server", "1.0.0")
            .tool(Echo)
            .instructions("A simple echo server for testing")
            .build()
            .run_stdio_with_cx(&cx)
            .await
    });
}
```

### 4. Run

```bash
cargo run
```

### 5. Test with MCP Inspector

```bash
npx @modelcontextprotocol/inspector cargo run
```

---

## Non-blocking stdio (Unix, opt-in)

`run_stdio_with_cx` above is the portable default, and it is blocking: it hands
`run_stdio_pump` to `spawn_blocking` and reads through `StdioTransport::stdio()`
and `AsyncStdout`, whose own documentation records that they "perform blocking
I/O internally. An async trait alone does not make those standard-stream
operations nonblocking." Several stdio caveats in
[Limitations](#limitations) are consequences of that choice rather than of the
framework, and the rows that describe only this entry point now say so. Others,
such as the client-subprocess rows, are unrelated to it and still apply.

On Unix there is a second path. `NativePipeReader::from_stdin` and
`NativePipeWriter::from_stdout` claim the real process descriptors, register
them with the caller's reactor, and observe that caller's cancellation and
deadline — no helper thread, no blocking pool, and no change to descriptor
flags that is not restored on release. `serve_stdio_io` then serves the
transport over them. `modern::ServerBuilder` is already modern-only, so no
protocol-policy call is needed:

```rust
use fastmcp_rust::modern::ServerBuilder;
use fastmcp_rust::{NativePipeReader, NativePipeWriter};

// Note blocking_threads(0, 0): this path needs no blocking pool at all.
let runtime = RuntimeBuilder::current_thread()
    .with_reactor(create_reactor().expect("create I/O reactor"))
    .blocking_threads(0, 0)
    .build()
    .expect("create application runtime");
runtime.block_on(async {
    let cx = Cx::current().expect("application context");
    let server = ServerBuilder::new("native-process-stdio", "1.0")
        .tool(Echo)
        .build();
    let input = NativePipeReader::from_stdin(&cx)?;
    let output = NativePipeWriter::from_stdout(&cx)?;
    server.serve_stdio_io(&cx, input, output).await
})
```

That is the wiring, not a complete program: acquiring the second descriptor can
fail after the first succeeded, and the two halves report `io::Error` while
`serve_stdio_io` reports `McpResult`, so a real `main` has to reconcile both.
`crates/fastmcp-server/examples/native_stdio.rs` does, including closing the
already-claimed reader rather than implying a partial process binding was
released. It is a checked-in target with no `required-features`; run it with
`cargo run -p fastmcp-server --example native_stdio`.

**Bind both endpoints to the same `Cx` that serves the transport.** A pipe whose
own context is cancelled or past its deadline reports a cooperative stop on
every poll while the serving context stays live. The transport retries a
bounded number of those and then fails the endpoint with a diagnostic naming
this cause, instead of retrying without end.

**What this does not claim.** This is an opt-in transport pairing, not the
default, and not an aggregate cancellation, quiescence, or conformance
qualification — every boundary in [Limitations](#limitations) still applies
except where it is explicitly about the blocking default. `from_stdin` and
`from_stdout` are `#[cfg(unix)]`; there is no non-Unix equivalent, because
asupersync's readiness `Source` is socket-bound on Windows while Windows
standard streams are handles.

---

## Legacy sampling options in proxies

The exact-2024 stdio and HTTP reverse-request bridges carry text and image
messages, model preferences, context selection, and provider metadata to the
downstream sampling handler. Image data and MIME types retain their original
strings. Responses preserve their declared user/assistant role and stop reason,
including an omitted `stopReason` or a provider-defined value.

```rust
use fastmcp_rust::{
    SamplingIncludeContext, SamplingModelHint, SamplingModelPreferences,
    SamplingRequest,
};

let request = SamplingRequest::prompt("Summarize this result", 256)
    .with_model_preferences(SamplingModelPreferences {
        hints: vec![SamplingModelHint {
            name: Some("preferred-model".to_owned()),
        }],
        cost_priority: Some(0.8),
        speed_priority: Some(0.6),
        intelligence_priority: Some(0.9),
    })
    .with_include_context(SamplingIncludeContext::ThisServer);
```

Pass the request to `ctx.sample_with_request(request).await`. For image inputs,
construct a conversation with `SamplingRequest::new` and
`SamplingRequestMessage::image(role, base64_data, mime_type)`. A conversation
can mix text and image messages. A sampling handler can return
`SamplingResponse::image(data, mime_type, model)` and select a role with
`with_role`.

Both messages and responses expose one typed `content` field:
`SamplingMessageContent::Text { text }` or
`SamplingMessageContent::Image { data, mime_type }`. Match that enum when
handling either kind. `text_content()` borrows text when present;
`SamplingResponse::into_text()` extracts text or returns an error for an image.

Use `with_metadata` for a provider-specific JSON object. Leaving
`include_context` unset differs from explicitly selecting
`SamplingIncludeContext::None`; optional model preferences and metadata also
retain their presence. The `with_model_hints` shorthand replaces only hints
and retains any configured priorities.

For direct struct construction on `SamplingRequest`, the former `model_hints`
field is now `model_preferences`; initialize `include_context` and
`metadata` as well, or use the constructors and builders. The former message
and response `text` fields are now typed `content`, and responses include an
explicit `role`. Wider token budgets, content annotations, and exact
request/result `_meta` preservation still require the protocol-specific APIs.

## Typed extension handlers (opt-in, current source tree)

The `extension-authoring` feature adds typed extension settings, request and
response schemas, and `#[extension]` handlers. Enable it from the current Git
source; the dependency can be renamed, and no component crates are required:

```toml
[dependencies]
fm = { package = "fastmcp-rust", git = "https://github.com/Dicklesworthstone/fastmcp_rust", branch = "main", default-features = false, features = ["extension-authoring"] }
```

This complete program constructs and installs an asynchronous echo handler:

```rust
use fm::extensions::authoring::{ExtensionBuilder, ExtensionContext};
use fm::serde::{Deserialize, Serialize};
use fm::{JsonSchema, McpResult, extension, modern};

#[derive(Deserialize, Serialize, JsonSchema)]
#[serde(crate = "fm::serde", deny_unknown_fields)]
struct Settings {}

#[derive(Deserialize, Serialize, JsonSchema)]
#[serde(crate = "fm::serde", deny_unknown_fields)]
struct Message {
    value: u32,
}

#[extension(
    method = "com.example/echo",
    params_schema = "echo-params-v1",
    result_schema = "echo-result-v1"
)]
async fn echo(
    context: ExtensionContext<'_, Settings>,
    request: Message,
) -> McpResult<Message> {
    context.checkpoint()?;
    Ok(request)
}

fn main() {
    let builder = ExtensionBuilder::<Settings, Settings, Settings>::new(
        "com.example/typed-echo",
        1,
        "empty-settings-v1",
        "empty-settings-v1",
        Settings {},
        |_client, server| Ok(server),
    )
    .expect("admitted typed settings");
    let registration = EchoExtension
        .register(builder)
        .expect("typed handler registration")
        .build()
        .expect("sealed extension registration");
    let _server = modern::ServerBuilder::new("typed-echo", "1.0")
        .extension(registration)
        .expect("extension installation")
        .try_build()
        .expect("frozen server");
}
```

The resolver receives typed client and server settings and returns the effective
settings exposed by `context.settings()`. The explicit `serde(crate = "fm::serde")`
keeps the derives valid with only the renamed facade dependency. Use the resulting
server with an existing caller-owned `serve_*` path to handle requests; the program
above only constructs the server and creates no runtime or transport.

Activation requires both sides to opt in on each request. The server advertises
the installed extension, and the client must include compatible settings in the
request's `_meta["io.modelcontextprotocol/clientCapabilities"].extensions` object.
For this example, that object contains `"com.example/typed-echo": {}`. Missing or
incompatible settings refuse the call before the handler runs. Settings and
request payloads are schema checked before callbacks; returned responses are
schema checked before publication. Framework `_meta` is removed before decoding
the typed request, so `deny_unknown_fields` applies to the application payload.

`ExtensionContext` provides typed settings, immutable descriptor information,
cancellation and deadline observations, and `checkpoint()`. It exposes no raw
`McpContext`, `Cx`, credentials, or registry access. One registration can contain
multiple typed methods. Installation does not merge an existing extension
registry. These construction and admission APIs do not imply complete extension
qualification.

Use `ExtensionBuilder::typed_notification` (or `typed_notification_sync`) for a
modern client-to-server notification. Registration requires an explicit operation
authorization callback and a metadata key for a self-contained settings proof.
Every message must supply compatible settings in that exact `params._meta` field;
an earlier request's capabilities cannot activate a later notification. The
framework authenticates each message, validates its typed payload, applies the
operation policy, and resolves its settings before invoking the handler with an
`ExtensionNotificationContext`. This context offers the same bounded cancellation
and deadline observations without exposing transport or task-spawning authority.

Typed notifications run on caller-owned HTTP, stdio, memory, and WebSocket serving
paths after the transport selects the modern era. HTTP returns an empty 202 only
after the callback and its scope settle. Stream transports emit no JSON-RPC
response for successful or rejected notifications. Pending notification work is
cancelled and drained on connection shutdown, and each notification has a finite
deadline even when ordinary request timeouts are disabled. Legacy extension
notifications are outside this surface.

### Calling extensions from clients

Configure `ClientBuilder::extension_registry` with the client's descriptor
registry, local settings, and a compatibility-resolver factory before connecting.
The connected HTTP and WebSocket clients, and the Unix stdio client, expose
`notify_final_extension(cx, extension_id, method, parameters)`, including the
recommended modern facade. A retained `StdioRequestExecutor` can also publish a
notification while other request handles remain live. The client attaches fresh
settings proof in the exact location named by `NotificationActivationProofDescriptor`;
applications do not have to construct that proof manually. Conflicting caller
proof, unconfigured methods, wrong directions, and legacy sessions fail before
publication. Notifications consume no request ID or response waiter. HTTP waits
for the empty 202 acknowledgement; stdio, memory, and WebSocket publication does
not imply that the server callback has completed.

On Unix, `modern::Client::request_final_extension(cx, extension_id, method,
parameters)` also drives stdio extension responses cooperatively on the supplied
runtime, including deferred discovery. Use `request_final_extension_with_cancellation`
to retain an explicit request-local cancellation token along with the original
caller context. A cancelled or dropped request leaves the connection reusable;
its late response cannot complete a later request. Unregistered methods and
wrong-direction calls are refused before publication, and successful responses
must belong to the extension's admitted result owner. An intact result with the
wrong extension owner fails that request; loss of the original result source
retires the connection. Use `close_with_cx(cx)` for
yielding, bounded subprocess and callback cleanup. The lower-level
`StdioRequestExecutor::execute_final_extension_with_cancellation` provides the
same cancellation ownership for separately retained request handles.

The in-process client now accepts the same frozen extension configuration through
`MemoryClient::builder(client_info).extension_registry(...)`. Connect it to an
owned bounded memory endpoint with `connect(cx, transport)`. Existing
`MemoryClient::connect` calls continue to work for ordinary core methods; a raw
extension capability advertisement alone does not authorize extension calls.

Use `execute_final_extension(cx, cancellation, extension_id, method, parameters)`
to obtain a `MemoryExtensionExecution`, then drive it with
`next_extension_event(cx, cancellation, execution)`. Each handle retains its own
progress, admitted result, cancellation, and exact result JSON source. Core and
extension handles may share the connection, and driving one routes its siblings'
responses without consuming them. `request_final_extension` is the convenience
form that waits for the result. Memory notifications take the explicit
cancellation token as well.

Memory publication waits for channel capacity while continuing to route incoming
responses, including when both bounded directions are full. Dropping or cancelling
an unsent wait allocates no ID or waiter. Dropping a published execution schedules
its cancellation before later application messages, and late results remain
owned by that execution rather than a sibling. These clients run on the supplied
runtime and do not create a background pump. A caller timer driver is required
for response deadlines and the finite send-admission timeout.

---

### Forwarding typed extension requests over HTTP

With both `extension-authoring` and `proxy` enabled, a typed gateway can forward
request/result extension methods to an independently configured modern HTTP
upstream. Reuse the same complete extension declaration on both legs. The
declaration's schema and contract checks remain inside the framework.

Within an asynchronous serving setup, the following uses `Settings`, `Message`,
and `EchoExtension` from the example above. Supply your caller-owned `cx` and
canonical upstream `endpoint`:

```rust
let make_builder = || {
    ExtensionBuilder::<Settings, Settings, Settings>::new(
        "com.example/typed-echo",
        1,
        "empty-settings-v1",
        "empty-settings-v1",
        Settings {},
        |_client, server| Ok(server),
    )
};
let declaration = EchoExtension.register(make_builder()?)?.build()?;
let upstream = modern::ClientBuilder::new()
    .connect_extension_http_upstream_with_cx(
        cx,
        endpoint,
        declaration,
        &Settings {},
    )
    .await?;
let registration = make_builder()?
    .typed_http_proxy_request::<Message, Message>(
        "com.example/echo",
        "echo-params-v1",
        "echo-result-v1",
        upstream,
    )?
    .build()?;
let gateway = modern::ServerBuilder::new("typed-gateway", "1.0")
    .extension(registration)?
    .try_build()?;
```

The connection helper consumes the declaration to configure discovery and typed
settings negotiation; its local request callbacks are not invoked. Configure the
upstream client builder's identity, credentials, TLS, and timeout policy before
connecting. The gateway uses that configured upstream identity. Each forwarded
call must match the registered contract and independently negotiated effective
settings, and its request and result pass the typed schema checks.

The request/result route rejects contracts that declare notifications. To relay
request-owned server notifications as they arrive, declare the same event on both
legs and choose the explicit notification-aware route. This variant uses
`Message` for the event payload as well:

```rust
let with_notices = || {
    make_builder()?.typed_request_notification::<Message>(
        "com.example/echo/changed",
        "echo-changed-v1",
        "com.example/echo-request-id",
    )
};
let declaration = EchoExtension.register(with_notices()?)?.build()?;
let upstream = modern::ClientBuilder::new()
    .connect_extension_http_upstream_with_cx(
        cx,
        endpoint,
        declaration,
        &Settings {},
    )
    .await?;
let registration = with_notices()?
    .typed_http_proxy_request_with_notifications::<Message, Message, Message>(
        "com.example/echo",
        "echo-params-v1",
        "echo-result-v1",
        upstream,
    )?
    .build()?;
```

The upstream server must advertise that same complete contract. Install the
resulting registration on the gateway as above. Each event is bounded, checked
against its schema, decoded and re-encoded through the declared Rust type, and
checked again before downstream publication. Upstream `_meta` is consumed locally;
typed serialization cannot inject replacement metadata. The gateway reconstructs
correlation for the downstream request, using its owned SSE stream for HTTP or its
own request ID for memory and stdio. A request without an output sink is refused
before any upstream request is started.

All intermediate events share a 64-event budget. Core progress and log events
count toward the budget and are consumed without being relayed. Downstream framework
metadata is not application payload or an upstream activation proof. Cancelling
or dropping a forwarded request closes its owned upstream execution while sibling
requests continue independently.

Standalone client-to-server notifications use
`ExtensionBuilder::typed_http_proxy_notification::<Notification, _>`. Register the
same notification method, schema identity, and activation-metadata key on both
legs, supply an explicit typed authorization policy, and pass the independently
connected `ExtensionHttpUpstream`. Request and notification routes may share one
upstream when their complete contracts match.

Each notification consumes its own downstream activation proof and the exact
payload admitted by its authorization policy. The gateway checks typed
serialization and effective-settings equality, then sends a fresh upstream
notification with the upstream client's own proof and credentials. A change in
the upstream resolver's effective settings is rejected before sending. Only an
empty HTTP 202 acknowledges completion. The upstream handle admits at most 64
concurrent notification POSTs across its clones; completion, cancellation, or
Drop releases the permit. Notifications allocate no request ID or response
waiter and are never retried automatically.

### Typed extension gateways to stdio subprocesses (Unix)

With `extension-authoring` and `proxy` enabled, the same typed extension
contracts can forward to a local subprocess. Consume the upstream declaration
with `modern::ClientBuilder::connect_extension_stdio_upstream_with_cx`, supplying
the caller's `cx`, executable, arguments, and typed client settings. Discovery
and settings negotiation finish before it returns an `ExtensionStdioUpstream`,
including when the builder defers ordinary initialization.

Install the complete matching contract on the gateway with
`typed_stdio_proxy_request::<Request, Response>`. For request-owned server
notifications, declare the event and use
`typed_stdio_proxy_request_with_notifications::<Request, Response, Notification>`.
Standalone client notifications use `typed_stdio_proxy_notification` with an
explicit typed authorization policy. Both legs independently negotiate;
contract identities, schemas, and effective settings must match. Framework
metadata is rebuilt for the upstream leg, and request-owned notification IDs
are rewritten for the downstream request.

Cloned upstream handles share one subprocess and one bounded ingress driver.
Requests have independent IDs, cancellation, deadlines, and a 64-event
intermediate-notification bound. Cancelling or dropping a forwarded call
publishes its retirement even when no sibling request is driving the child.
Standalone notifications allocate no request IDs; success means publication
to the pipe. The adapter does not create a detached task or private runtime,
and its receive turns retain the native client's bounded synchronous slices.
After dropping installed routes and other handles, consume the last handle
with `close_with_cx` to await observable subprocess cleanup.

### Typed extension gateways to WebSocket upstreams

Enable `extension-authoring`, `proxy`, and `websocket-experimental`. The caller
supplies an owned `AsyncWsClientTransport`, acquired with `connect`, `connect_wss`,
or its own Upgrade/TLS setup. Reusing the typed echo declaration above:

```rust
let upstream = modern::ClientBuilder::new()
    .connect_extension_websocket_upstream_with_cx(
        cx,
        transport,
        EchoExtension.register(make_builder()?)?.build()?,
        &Settings {},
    )
    .await?;
let registration = make_builder()?
    .typed_websocket_proxy_request::<Message, Message, _>(
        "com.example/echo",
        "echo-params-v1",
        "echo-result-v1",
        upstream.clone(),
    )?
    .build()?;
```

Install `registration` on the gateway as above. Both legs independently
negotiate the complete contract; schema identities and effective settings must
match. The adapter validates typed payloads and creates fresh upstream IDs and
metadata. Cloned handles share one connection and admit at most 64 running or
waiting operations on the caller's runtime.

Awaited cancellation settles native request retirement before connection reuse.
Dropped requests retain cleanup ownership for the next operation or close.
After serving finishes, call `upstream.close(cx).await?`; retain the handle to
retry an acquisition failure. Idle cleanup accepts a cancelled caller; busy
cleanup requires the caller's timer and has a finite acquisition bound.

Standalone client notifications use
`typed_websocket_proxy_notification::<Notification, _, _>` with an explicit
authorization policy and the same complete declaration. They receive fresh
activation proof, allocate no request ID, and are never retried automatically.
This adapter supports finite request/results and standalone client notifications;
request-owned server notifications, Tasks, and subscription relays remain outside
its supported contract.

## In-process test clients

Enable the facade's `testing` feature to use `testing::TestClient` with a
caller-owned `Cx` and `MemoryTransport`. `TestClient::new_modern` selects exact
MCP `2026-07-28`; `new` retains the exact-2024 helper when that protocol feature
is enabled. These helpers do not create a runtime. Synchronous requests require
the peer to be driven independently.

Use `initialize_core()` to retain the complete modern discovery, including its
optional identity, cache contract, and open members. `request_core(method,
params)` returns the full typed method result with its original JSON number
lexemes and modern `input_required` state. Legacy-shaped convenience helpers
report an input-required result as an error directing the caller to that typed
API. Invalid discovery, malformed results, and mismatched response IDs retire
the endpoint. Valid peer errors preserve their data and leave it usable.

For concurrent requests, reverse interactions, subscriptions, or explicitly
configured Tasks, consume an unused helper with `connect_modern().await` or
`connect_modern_with(configure).await`. These transfer the existing endpoint
and caller context to the shipped asynchronous `MemoryClient`;
`connect_modern_with` exposes its normal builder for reverse handlers and
extension settings. The resulting client owns normal request cancellation and
terminal results, and the server can run on the same caller runtime. No
blocking pool or deterministic test runtime is required for Memory I/O.

`new_auto` only retries after an admitted, correlated modern
`MethodNotFound`. Install `with_legacy_transport_factory` to supply a fresh,
independently driven endpoint for that one exact-2024 attempt. The modern probe
is closed before the factory runs. Without the factory, the error is returned;
the probe endpoint is never reused for a different protocol era.

## Client executor observations

`OperatorExecutorSnapshot` captures the selected protocol profile, lifecycle,
structural readiness, and the capacity actually charged by a client executor.
It is available from `RequestExecutor`, a retained `StdioRequestExecutor`
handle, and `MemoryClient`:

```rust
use fastmcp_rust::{
    OperatorExecutorCapacity, OperatorExecutorSnapshot,
    OperatorSnapshotError, OperatorSnapshotSource,
};

fn observe(
    client: &(impl OperatorSnapshotSource<OperatorExecutorCapacity> + ?Sized),
) -> Result<OperatorExecutorSnapshot, OperatorSnapshotError> {
    OperatorExecutorSnapshot::capture(client)
}
```

A snapshot's `requests()` counts pending requests and deferred transport
controls. Its `correlations()` counts pending requests, retained tombstones,
and unconsumed terminal outcomes. These use the same charge arithmetic as
request admission. Capturing a snapshot never sends a message, reads the
transport, reserves a slot, or performs expiry maintenance. If an executor turn
currently holds its state lock, capture returns `OperatorSnapshotError::Busy`
immediately.

`Ready` describes structural admission; the capacity gauges can simultaneously
report saturation. Ordinary service turns release expired and abandoned-owner
charges. The snapshot includes no request IDs, peer data, credentials, endpoint
addresses, or error text. Retained handles keep their configuration generation
after shutdown and distinguish an intentional stop from a real connection
failure, including a failure followed by successful cleanup.

HTTP listeners retain their existing `OperatorSnapshot` connection-admission
surface. These client observations cover the executor-backed stdio and memory
paths; they do not imply readiness of other client transports, durable task
workers, credentials, or the entire application.

### Asynchronous Task worker transitions

With `tasks` enabled, an elected `FinalTaskInitialWork` or
`FinalTaskAcceptedInput` can await storage through the caller's `Cx` when
publishing progress, requesting input, completing, failing, or honoring
cancellation. Each method preserves the original execution authorization,
claim generation, owner, and dispatch fence across suspension. For example,
an application supervisor can publish a result through its elected handoff:

```rust
async fn publish_result(
    cx: &fastmcp_rust::Cx,
    mut work: fastmcp_rust::FinalTaskInitialWork,
    result: fastmcp_rust::FinalTaskCallToolResult,
) -> fastmcp_rust::McpResult<fastmcp_rust::FinalTask> {
    work.update_status_message_with_cx(cx, Some("Publishing result".into()))
        .await?;
    if work.is_cancellation_requested_with_cx(cx).await? {
        return work.honor_cancellation_with_cx(cx, None).await;
    }
    work.complete_task_with_cx(cx, result, None).await
}
```

Use `require_input_with_cx` to suspend for a validated input batch, or
`fail_task_with_cx` to retain a typed failure. The same methods are available
on resumed work. Cancellation-intent reads check the exact Task incarnation
before and after awaiting storage, so a reused identifier cannot substitute
another Task's cancellation state.

An asynchronous `FinalTaskStore` overrides the snapshot, access-metadata,
handoff-metadata, and cancellation-read hooks, plus
`replace_task_and_clear_input_for_handoff_with_context` and
`update_working_status_for_handoff_with_context`. The mutation hooks receive
a sealed `FinalTaskWorkerAdmission`. Use its context for I/O and call
`checkpoint_before_write()` immediately before the first irreversible write,
including after suspension. The store must atomically compare the expected
record, claim, owner, dispatch fence, cancellation disposition, and execution
budgets while enforcing the existing quotas and input-history rules.

Pending reads and unadmitted writes observe caller cancellation and deadlines.
Each elected handoff admits at most one pending asynchronous mutation. Once a
write may have committed, a framework-owned slot retains that provider
operation independently of the application's observing future. Cancellation,
revocation, execution expiry, and application drop cannot discard its pending
receipt. During shutdown the framework closes application admission before
settling the provider alone; it does not resume application code merely to
learn whether a write committed.

A validated commit receipt survives late cancellation or policy revocation,
and a notification-delivery failure cannot undo it. Working-status receipts
preserve the live claim; terminal and input-required receipts consume it.
An ambiguous admitted error, invalid receipt, or provider panic leaves an
uncertain outcome. The framework suppresses restoration of that invocation
as though rollback were established; reconcile the exact fenced operation
before retrying it. Providers must settle their original operation and must
not leave detached writes running after returning. The bounded
`retention_clock_now` hook must remain nonblocking and perform no storage I/O.

The built-in in-memory store uses bounded synchronous defaults for these
hooks. Application stores may also suspend dispatch election, lease renewal,
and final settlement on the caller's runtime.

### Asynchronous Task service recovery

Application stores can suspend startup and periodic recovery, signaled Task
lookups, and owner-bound handoff claims on the service's caller-owned `Cx`.
Override the `FinalTaskStore` hooks `next_initial_work_snapshot_after_with_cx`,
`next_accepted_input_snapshot_after_with_cx`,
`next_expired_execution_snapshot_with_cx`, `get_task_snapshot_with_cx`,
`take_initial_work_handoff_for_owner_if_current_with_cx`,
`take_input_handoff_for_owner_if_current_with_cx`, and
`expire_task_execution_if_current_with_cx`. Notification delivery also uses
`get_task_access_metadata_with_cx` to recheck each observer's current Task
incarnation without a synchronous metadata read. The default implementations
retain the bounded in-memory behavior.

The runner keeps existing handoffs progressing while recovery storage is
pending, including at full configured concurrency. It preserves scan cursors,
initial/resumed fairness, active-task exclusions, and bounded retry work.
Caller cancellation, deadlines, and permission restrictions are checked even
when a storage provider never wakes.

A running worker also uses these async hooks for its bulk execution-expiry
maintenance. While that scan is pending, it renews its own exact dispatch lease
and lets unrelated tasks progress. Task cancellation returns to the existing
cooperative cleanup window; lease loss prevents further application polls and
keeps restoration bound to the original owner and generation.

A returned claim stays under restoration custody while the runtime awaits a
fresh snapshot and checks its exact Task, generation, owner, principal, and
originating operation. Cancellation or abandonment during that check restores
only the known claim through the existing fenced cleanup path. If a provider
is dropped before its claim outcome is known, it must keep the original
payload behind its finite owner lease so another service can recover it after
expiry. It must not treat cancellation as proof of rollback or start detached
writes. A committed execution-expiry result remains committed if notification
delivery is cancelled or an observer fails.

After the application region and its descendants have stopped, the service
awaits the store's owner- and fence-bound finish or restoration. A failed
initial attempt returns its original work descriptor. A failed resumed attempt
returns its exact accepted inputs. Stores can override
`finish_handoff_dispatch_for_owner_if_current_with_cx`,
`restore_initial_work_for_owner_if_current_with_cx`, and
`restore_input_for_owner_if_current_with_cx` to perform that work asynchronously.
A missing receipt leaves recovery with the backend's finite lease. The
framework never reissues the admitted final mutation from a destructor.

A handoff abandoned before final settlement still uses the bounded synchronous
restoration path. Per-attempt authorization and cancellation checks also retain
synchronous store operations. The built-in store remains process-local.

### Tasks retention administration

With `tasks` enabled, install a `TaskRetentionAdministrator` on the
`FinalTaskRuntime` to inspect and reclaim a terminal Task under separate,
current administrative authority. The asynchronous methods
`inspect_task_retention_with_context`, `reclaim_task_retention_with_context`,
and `task_retention_audit_with_context` run on the caller's `McpContext` and
allow an application store to suspend its I/O without blocking sibling work.
The inspection returns an exact generation-bound target; reusing an old
target cannot remove a successor Task with the same identifier.

An asynchronous `FinalTaskStore` overrides `get_task_snapshot_with_context`,
`reclaim_terminal_task_with_context`, and `task_retention_audit_with_context`.
The reclamation hook receives a sealed `FinalTaskRetentionAdmission`. Use
its context for I/O and call `checkpoint_before_write()` immediately before
the first irreversible write, including after a suspension. Once a write may
have committed, settle its original receipt. A verified committed receipt is
preserved if cancellation arrives afterward; cancellation does not imply that
the Task was retained. Repeated reclamation within the journal's lifetime
returns the original receipt and reason. Audit reads remain bounded and
require current administrative authorization.

The built-in `InMemoryFinalTaskStore` supports these methods through bounded
synchronous operations. Retention and handoff-lease expiry checks use ordered
deadlines to inspect only due entries; renewing a lease replaces its previous
deadline entry. Storage and the reclamation journal remain process-local;
these APIs do not add a durable or distributed backend.

### Tasks store observations

With `tasks` enabled, `FinalTaskRuntime::task_operator_handle()` returns an
optional `TaskOperatorHandle` for the installed store. The built-in
`InMemoryFinalTaskStore` supplies this handle; custom stores may omit it.
Capture it through the same exporter-neutral API:

```rust
use fastmcp_rust::{OperatorTaskSnapshot, OperatorSnapshotError, TaskOperatorHandle};

fn observe_tasks(
    handle: &TaskOperatorHandle,
) -> Result<OperatorTaskSnapshot, OperatorSnapshotError> {
    OperatorTaskSnapshot::capture(handle)
}
```

The observation includes retained task states, storage counts and encoded-byte
charges, reserved retirement capacity, active execution capacity, and retention
journal usage. These gauges come from the store's actual admission accounting.
Terminal results continue to consume storage until normal expiry or authorized
reclamation; an execution permit remains charged while its service future is
still cleaning up. The snapshot exposes aggregate pressure without task IDs,
principal identities, input values, results, or error messages.

Capture uses immediate lock attempts and returns `Busy` when a store mutation
owns the necessary state. It does not scan task payloads, run expiry maintenance,
invoke application clocks or providers, or reserve capacity. A retained handle
does not keep a discarded store alive. The HTTP readiness response includes
the optional Tasks observation when available, while connection readiness
continues to describe HTTP admission: a full Tasks store does not prevent
ordinary tool, resource, or catalog requests from using available connections.
This is process-local operational visibility, not persistent Tasks or an
application-wide readiness guarantee.

---

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                        MCP Client                               │
└─────────────────────────────────────────────────────────────────┘
                              │
                              │ JSON-RPC over stdio
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│                      StdioTransport                             │
│  ┌─────────────┐    ┌─────────────┐    ┌─────────────┐         │
│  │   Codec     │───▶│   recv()    │───▶│   send()    │         │
│  │  (NDJSON)   │    │             │    │             │         │
│  └─────────────┘    └─────────────┘    └─────────────┘         │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│                         Server                                  │
│  ┌─────────────┐    ┌─────────────┐    ┌─────────────┐         │
│  │   Session   │    │   Router    │    │   Budget    │         │
│  │  (state)    │    │ (dispatch)  │    │ (timeout)   │         │
│  └─────────────┘    └─────────────┘    └─────────────┘         │
│                              │                                  │
│                              ▼                                  │
│  ┌─────────────────────────────────────────────────────────────┐│
│  │                     McpContext                              ││
│  │  ┌─────┐  ┌──────────┐  ┌────────┐  ┌──────┐              ││
│  │  │ Cx  │  │checkpoint│  │ budget │  │masked│              ││
│  │  └─────┘  └──────────┘  └────────┘  └──────┘              ││
│  └─────────────────────────────────────────────────────────────┘│
│                              │                                  │
│                              ▼                                  │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐         │
│  │ ToolHandler  │  │ResourceHandler│ │PromptHandler │         │
│  │  call_async  │  │  read_async  │  │  get_async   │         │
│  └──────────────┘  └──────────────┘  └──────────────┘         │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│                       asupersync                                │
│  ┌─────────┐  ┌─────────┐  ┌─────────┐  ┌─────────┐           │
│  │ Runtime │  │  Scope  │  │ Budget  │  │ Outcome │           │
│  └─────────┘  └─────────┘  └─────────┘  └─────────┘           │
└─────────────────────────────────────────────────────────────────┘
```

---

## Crate Structure

FastMCP is organized as a workspace with focused crates:

```
fastmcp_rust/
├── crates/
│   ├── fastmcp/           # Facade crate (published as fastmcp-rust)
│   ├── fastmcp-core/      # McpContext, errors, runtime helpers
│   ├── fastmcp-protocol/  # MCP types, JSON-RPC messages
│   ├── fastmcp-transport/ # Transport implementations (stdio, SSE, WebSocket, HTTP, memory)
│   ├── fastmcp-server/    # Server builder, router, handlers
│   ├── fastmcp-client/    # Client implementation
│   ├── fastmcp-macros/    # Proc-macro crate, published as fastmcp-derive
│   ├── fastmcp-console/   # Console rendering and statistics
│   └── fastmcp-cli/       # fastmcp command-line interface
```

| Crate | Purpose |
|-------|---------|
| `fastmcp-rust` | Convenience re-exports for simple `use fastmcp_rust::prelude::*` |
| `fastmcp-core` | `McpContext` wrapper, error types, `block_on` helper |
| `fastmcp-protocol` | MCP message types, capabilities, JSON-RPC framing |
| `fastmcp-transport` | Transport trait and stdio/SSE/WebSocket/HTTP/memory implementations |
| `fastmcp-server` | `Server`, `ServerBuilder`, routing, handler traits |
| `fastmcp-client` | Three clients: `Client` drives a subprocess over stdio; `HttpClient` covers modern HTTP and exact legacy SSE and is returned by `Client::http_with_cx` and (with `legacy-2024-11-05`) `Client::sse_with_cx`, with `ClientHttpConnection` beneath it; `WebSocketClient` exists only with the `websocket-experimental` feature, where it accepts owned native async transports and Auto negotiation uses a caller-owned factory that supplies a fresh upgraded transport for its permitted retry |
| `fastmcp-derive` | Procedural macros for handler generation |

---

## Handler Traits

The signatures below are abridged; asynchronous trait methods return four-valued `McpOutcome` values, not ordinary `McpResult` values.

### ToolHandler

```rust
pub trait ToolHandler: Send + Sync {
    fn definition(&self) -> Tool;
    fn call(
        &self,
        ctx: &McpContext,
        arguments: serde_json::Value,
    ) -> McpResult<Vec<Content>>;

    // Override for true async (default delegates to call())
    fn call_async<'a>(&'a self, ctx: &'a McpContext, arguments: serde_json::Value)
        -> std::pin::Pin<Box<dyn std::future::Future<Output = McpOutcome<Vec<Content>>> + Send + 'a>>;
}
```

### ResourceHandler

```rust
pub trait ResourceHandler: Send + Sync {
    fn definition(&self) -> Resource;
    fn read(&self, ctx: &McpContext) -> McpResult<Vec<ResourceContent>>;

    // Override for true async
    fn read_async<'a>(&'a self, ctx: &'a McpContext)
        -> std::pin::Pin<Box<dyn std::future::Future<Output = McpOutcome<Vec<ResourceContent>>> + Send + 'a>>;
}
```

### PromptHandler

```rust
pub trait PromptHandler: Send + Sync {
    fn definition(&self) -> Prompt;
    fn get(&self, ctx: &McpContext, arguments: std::collections::HashMap<String, String>)
        -> McpResult<Vec<PromptMessage>>;

    // Override for true async
    fn get_async<'a>(
        &'a self,
        ctx: &'a McpContext,
        arguments: std::collections::HashMap<String, String>,
    )
        -> std::pin::Pin<Box<dyn std::future::Future<Output = McpOutcome<Vec<PromptMessage>>> + Send + 'a>>;
}
```

---

## Troubleshooting

| Problem | Cause | Fix |
|---------|-------|-----|
| JSON-RPC `InvalidParams` (`-32602`) `Unknown tool: <name>` for `tools/call` | Tool not registered | Register the generated handler, for example `.tool(MyTool)` |
| Request cancelled mid-operation | Local request cancellation or budget exhaustion | Add checkpoints and mask only the smallest atomic section that must finish; Unix stdio and native WebSocket connections keep receiving while bounded modern request children run, but output commits are serialized, non-Unix/custom/SSE loops retain blocking boundaries, and a non-cooperative handler can exceed the process-exit quiescence drain |
| JSON-RPC `RequestCancelled` (`-32004`) error `Request timeout exceeded` | The request outlived the server-owned deadline (`.request_timeout(...)`, 30 seconds by default), whether the server or the handler's own checkpoint observed it first | Add checkpoints so work stops promptly; increase `.request_timeout(...)` only for a deadline that is intentionally too short |
| `#[tool]` macro compilation error | Unsupported return conversion or argument schema | Prefer `String`, `Vec<Content>`, `McpResult<String>`, or `McpResult<Vec<Content>>` and ensure custom argument types implement `JsonSchema` |
| `TransportError::Io` on startup | stdin unavailable | Ensure nothing else reads stdin |

### Critical Section Example

```rust
use std::sync::atomic::{AtomicU64, Ordering};

// A handler that owns `committed` can call this helper after validation.
fn commit_revision(
    ctx: &McpContext,
    revision: u64,
    committed: &AtomicU64,
) -> McpResult<()> {
    // Mask only a small, non-blocking atomic commit. Masking does not make
    // synchronous filesystem or device I/O bounded or cancel-safe.
    ctx.masked(|| committed.store(revision, Ordering::Release))
        .map_err(|error| McpError::internal_error(error.to_string()))?;
    Ok(())
}
```

---

## Limitations

| Limitation | Details |
|------------|---------|
| **Pinned Nightly Required** | The project contract pins `nightly-2026-08-25`; do not substitute a different toolchain merely because it supports Edition 2024 |
| **Protocol Modernization** | The root compatibility `PROTOCOL_VERSION` remains `2024-11-05`; the modern facade's `modern::PROTOCOL_VERSION` is `2026-07-28`. MCP 2026-07-28 implementation and verification are incomplete |
| **Poll-quota accounting is scoped to framework operations** | `McpContext::checkpoint` keeps a clone-shared request debit counter. The synchronous client `RequestExecutor` also consumes a finite poll budget during `execute`, `drive`, and `wait`, sharing it across nested control maintenance and every frame of a `wait`. Exhausting this local ledger stops that call without cancelling the caller's shared `Cx` or unrelated request owners. This operation-admission limit also applies inside `Cx::masked`; runtime cancellation and deadline delivery retain the original mask semantics. An already exhausted raw budget retains the runtime's existing cancellation behavior. Separate executor calls start separate budget snapshots; this is not a global quota across calls or a bound inside an arbitrary blocking transport. Other APIs that checkpoint only a raw `Cx` still reject an already exhausted quota without consuming a positive one: asupersync 0.6.2 exposes that budget as a read-only `Copy` snapshot. Deadline and explicit cancellation remain effective at their documented boundaries |
| **Runtime-context migration** | Library client constructors and returning/custom transport runners require a caller-owned `Cx`. The process-owning CLI and `Server::run_stdio_with_cx` install the ambient context at their top-level runtime boundary; `test-internals` is confined to test-only dependencies and the facade's opt-in `testing-lab` feature |
| **Network Transports** | The turnkey `run_http*` entry points provide a caller-owned dual-era HTTP listener and dispatch lifecycle. The experimental `websocket-experimental` facade profile provides native async `bind_websocket` and `serve_websocket` listener and connection lifecycles for Auto, ModernOnly, and exact-2024 LegacyOnly, plus caller-driven client connection. Every server policy retains the accepted Upgrade authentication, configured request limits, and caller authority; Auto binds each connection to one protocol era. These surfaces do not establish aggregate conformance or complete lifecycle qualification |
| **Client Transport Coverage** | The `fastmcp-client::Client` type drives a subprocess over stdio. Its `Client::http_with_cx` and (exact-2024) `Client::sse_with_cx` constructors return a separate `HttpClient`, and `WebSocketClient` requires `websocket-experimental`. Public `ClientHttpConnection` and `HttpClient` provide modern HTTP and exact legacy SSE integration with typed `list_tools`/`call_tool`/`read_resource`/`get_prompt` verbs. Modern HTTP answers typed reverse `sampling/createMessage`, `roots/list`, and `elicitation/create` requests that arrive on a request-owned SSE body by POSTing the JSON-RPC response. Public `HttpClient::call_tool` and `WebSocketClient::call_tool` also follow modern server `input_required` by invoking those same installed handlers locally and retrying with `inputResponses`. Live `bind_http` JSON `tools/call` returns `ctx.final_sampling` and `ctx.final_roots` as `input_required`; a write-half EOF after the request is ordinary H1 completion and does not cancel that result. Public `modern::Client` stdio `call_tool_result` / `read_resource_result` / `get_prompt_result` keep the same live `input_required` branch. A Modern2026 stdio session stamps the same `_meta` protocol version and client capabilities on `start_multiplexed_request` that the typed verbs already send. Public stdio `read_resource` / `get_prompt` follow installed modern reverse handlers the same way `call_tool` does. Eligible stateless HTTP MRTR retries use framework-issued opaque, single-use `requestState` and may resume on a later POST only when the method, target, arguments, and admitted principal still match; forged or replayed state is rejected. Elicitation resumes the same way: the client's answer travels in `inputResponses` on the retry POST, bound to the original request by that single-use state. With `websocket-experimental`, the facade exposes `WebSocketClient` with incremental catalog listen, the same typed verbs, and the same modern reverse handlers: ModernOnly and LegacyOnly builders accept an owned async WebSocket transport, while Auto accepts a caller-owned factory that yields a fresh upgraded transport for initial modern discovery and its sole permitted exact-2024 retry |
| **Two modules ship with tests but no consumer** | `fastmcp_transport::event_store` (TTL retention, per-stream caps, `replay_bounded` cursor paging, 45 tests) has no consumer anywhere: its only references are its own `pub mod` declaration and the facade re-export. SSE resumption is deliberately not wired — exact 2024-11-05 reconnects start a fresh stream and `Last-Event-ID` is intentionally ignored, pinned by `dual_era_endpoint_ignores_last_event_id_and_starts_a_fresh_legacy_stream`. `fastmcp_transport::http::HttpTransport` is a complete synchronous HTTP/1.1 `Read`/`Write` adapter (request-line and token validation, obs-fold and duplicate-`Host` rejection, `Content-Length`/`Transfer-Encoding` conflict rejection, chunked decoding, 183 tests); the live listener does not use it, reaching the wire through `asupersync::http::h1::Http1Codec` instead, and its only out-of-crate consumer is one `#[cfg(test)]` fixture in `fastmcp-server`. Neither is an overclaim — this README promises no SSE replay — but 228 green tests exercise code no shipped request path reaches, so treat them as unclaimed library surface rather than as coverage of the HTTP or SSE paths |
| **Experimental WebSocket framing** | The frame codec that ships is asupersync's. `fastmcp_transport::websocket` compiles unconditionally, but its own RFC 6455 implementation — `WsFrame`, `WsReader::read_frame`, `WsWriter::write_frame`, `WsClientWriter`, `generate_mask`, `EndpointRole::validate_peer_mask`, `WsTransport`/`WsClientTransport` and their `Transport` impls — is `#[cfg(test)]` and is in no release binary. `getrandom`'s WebSocket-masking use is likewise test-only. The shipping path (`AsyncWsClientTransport`, `AsyncWsServerTransport`, `WebSocketListener`, `WebSocketUpgradeAdmission`) uses `asupersync::net::websocket` for handshake and framing; FastMCP owns fragmentation assembly, opcode dispatch, size ceilings, pending-write bounds and close-code selection above it. Those production transports implement no `Transport` impl, unlike `AsyncStdioTransport`. Consequently any RFC 6455 invariant proven only against the `cfg(test)` codec — mask direction in particular — is not evidence about the shipped path |
| **Experimental WebSocket TLS** | The experimental async transport supports `ws://` and `wss://`. `wss://` can use the built-in WebPKI-rooted connector or a caller-supplied TLS connector for private roots, pinning, or client certificates; this connection support does not imply complete TLS, lifecycle, or MCP conformance qualification |
| **HTTP Dispatch Qualification** | Public `run_http*` binds and serves the caller-owned dual-era HTTP lifecycle. `ModernOnly` selects the exact MCP 2026-07-28 era and `LegacyOnly` selects the exact MCP 2024-11-05 era; MCP 2025-11-25 is not an adapter or supported policy. This executable surface does not establish aggregate MCP conformance or complete lifecycle qualification |
| **Wire Cancellation** | The modern-only split receive pump, including Unix stdio, admits bounded concurrent requests on the caller's dispatch runtime, including `subscriptions/listen`. It authenticates cancellation against the existing connection owner and serializes cancellation, response, and notification commits at the writer. Synchronous split runners use the bounded asupersync blocking bridge. Unsplit custom transports dispatch ordinary requests serially because receive and send share one handle; a `subscriptions/listen` runs off the receive loop, and output produced while `recv` blocks is queued and written as soon as `recv` returns. Transport reads and writes can still block. The dual-era Unix stdio pump retains its concurrent modern children and serialized exact MCP 2024-11-05 worker. A non-cooperative handler can exceed the bounded process-exit drain, and reliable `awaitCleanup` semantics remain unverified. "Transport reads and writes can still block" is a statement about the blocking stdio and custom adapters; a Unix `serve_stdio_io` server over the native process pipes does not block in its reader or writer, which removes that one residual without establishing any of the others |
| **Silent stdio peers** | On Unix, the public subprocess `Client` enforces configured idle/absolute deadlines at child-pipe readiness and decode boundaries, including silent and partial-frame peers. Generic blocking `StdioTransport::recv` and non-Unix child-pipe I/O retain their documented frame/I/O-boundary limitation. Unix client writes use a separate two-second queue-and-commit deadline, so response-wait deadlines are not an end-to-end request or process wall-clock guarantee. Those residuals remain FND-04 work |
| **Stdio output backpressure** | On Unix, primary server responses and notifications use serialized nonblocking writes with a two-second commit deadline for ordinary pipes/sockets; a timeout, lock poison, partial write, notification encoding failure, or descriptor-flag restoration failure is connection-fatal. The writer attempts to restore descriptor flags before releasing the local lock; on restoration failure the descriptor may remain nonblocking, and inherited duplicate descriptors can observe the temporary `O_NONBLOCK` setting. Regular files/devices and non-Unix stdout retain blocking-I/O limits. A handler that ignores cancellation may force unsuccessful process exit after the bounded drain; shutdown hooks are skipped unless all worker and modern-child quiescence is proven. This row describes the `run_stdio_with_cx` writer; a `serve_stdio_io` server over `NativePipeWriter` commits through the asynchronous transport instead, which has its own separate boundaries (see [Non-blocking stdio](#non-blocking-stdio-unix-opt-in)) |
| **Subprocess cleanup** | `Client::close(&mut self) -> McpResult<()>` is the proof-bearing path; Drop is best effort. `fastmcp test` uses Unix-only anchored process-group ownership; successful connections report explicit final cleanup separately, and initialization-cleanup failures remain visible. Descendants can escape via a new group/session, host forks can copy the control descriptor, and `SIGCHLD=SIG_IGN`, `SA_NOCLDWAIT`, or competing global reapers can invalidate reap evidence. Windows Job Object support is not implemented |
| **Development subprocess cleanup** | On Unix, each `fastmcp dev` build/server group contains a signal-immune watchdog tied to a private owner-held control pipe, so ordinary shutdown, child-handle drop, and CLI owner death trigger bounded TERM-then-KILL cleanup. A host-side fork that copies the owner descriptor or a descendant that changes group/session remains outside this boundary; non-Unix `dev` remains fail-closed |
| **CLI `--output` atomic publication** | On Unix (Linux and macOS), `fastmcp inspect -o/--output <PATH>` stages to a sibling temporary file, refuses symbolic links and `..` parent traversal, and publishes atomically without clobbering existing files on upstream failure. Non-Unix targets fail closed until atomic no-symlink publication is verified there |
| **Synchronous HTTP readers** | Low-level HTTP parsing checkpoints before/after reads and retries `EINTR`, but a generic synchronous `Read` already blocked in the kernel cannot be preempted. A bounded host must supply readiness-aware/asynchronous I/O. Public turnkey `run_http*` uses its caller-owned asynchronous listener lifecycle, whose broader qualification boundaries remain documented here |
| **Returning transport runners** | `run_transport_returning_with_cx` and the split returning variants return fatal receive/send/close errors and preserve simultaneous run-plus-close failures. Clean EOF/cancellation is `Ok(())`. Each exact-2024 handler dispatch now opens and closes a budgeted child region of the caller's runtime, requiring a runtime-backed `Cx`. Blocking transport I/O and complete cancellation/cleanup guarantees remain unresolved |
| **Request Cancellation Ownership** | Unix modern stdio request work runs in independently owned bounded child contexts, but process-exiting shutdown does not wait unboundedly for a non-cooperative child; cancellation therefore is not yet a complete quiescence or `awaitCleanup` guarantee |
| **Bidirectional Response Routing** | On Unix, stdio continuously routes inbound responses while exact-2024 lifecycle work or modern request children are active. Native WebSocket connections preserve this routing for every policy, including exact-2024 reverse sampling, roots, and owner-authenticated cancellation while serialized handler work awaits. Custom split transports retain their synchronous routing pump. Non-Unix stdio, unsplit custom transports, and SSE do not provide the same split routing. Public HTTP has separate dual-era routing, while end-to-end bidirectional lifecycle qualification remains open |
| **Response Cache Partitioning** | Eligible entries are partitioned by committed authentication facts and opaque session identity/revision; ambiguous admission and state mutation fail closed. This does not promote OAuth/OIDC or establish protocol conformance |
| **Authentication Admission** | Native HTTP requires `Authorization` for protected requests and rejects recognized body/meta and query credential fields before provider invocation. Other adapters retain a stripped legacy fallback. Complete authorization, lease/revocation, and OAuth challenge qualification remain open |
| **Tasks RPC** | `tasks/list` and `tasks/submit` stay `MethodNotFound`. Official `tasks/get`, `tasks/update`, and `tasks/cancel` run by default on a process-local in-memory store; `ServerBuilder::final_tasks` replaces that store. `ServerBuilder::task_supervisor(Arc::new(supervisor))` hosts the application's task service during each serve, waits for bounded readiness, and settles the service before returning. Without a ready service, task creation is refused |
| **MCP Apps (opt-in `apps` feature)** | Off by default. The facade `apps` feature adds the official MCP Apps extension: server `ServerBuilder::mcp_apps` (bilateral capability negotiation and `server/discover` metadata; Apps owns no client-to-server method), `mcp_apps_ui_resource` for final-only `ui://` HTML documents and `mcp_apps_tool` for tools linked to one; client `ClientBuilder::mcp_apps` and the `mcp_apps` host bridge (`McpAppsHost`, `McpAppsBridgeTransport`). These are unit-tested (for example `builder_mcp_apps_ui_resource_binds_a_final_only_ui_catalog_entry`); Apps media rendering and Apps conformance are not claimed |
| **Feature flags that gate nothing** | `fastmcp-server`'s `enterprise-auth` now gates `auth::enterprise` and enables `jwt-resource-auth`; the facade enables both the client exchange and resource-server policy. Its `jwt-resource-auth` **does** gate code and this row claimed the opposite until 2026-10-20: since 2026-10-14 it gates `providers::jwt_resource` and `providers::managed_jwks` (3,735 lines and 45 tests as of 2026-11-20) implementing two `TokenVerifier`s that install through the ordinary `TokenAuthProvider` hook, so an inbound-JWT resource-server path does exist for it to reach. A consumer reaches them as `fastmcp_rust::providers::JwtResourceVerifier` once the facade's own `jwt-resource-auth` equation — added 2026-10-20, because until then the published facade declared no such feature and Cargo refused to resolve it — is enabled. `fastmcp-server`'s `websocket-experimental` is also inert: it forwards only to `fastmcp-transport`'s empty feature and is a *different* feature from `fastmcp-server/websocket`, which does gate code. The CLI's `jwt-resource-auth` forwards to the server feature above and carries `dep:fastmcp-server`, linking the server crate into the CLI. `fastmcp-console`'s `enterprise-auth`, `oauth-client-credentials`, `builtin-auth-server`, `jwt-resource-auth`, `proxy` and `websocket-experimental` are empty, so its `proxy-legacy` and `proxy-tasks` reduce to `legacy-2024-11-05` and `tasks`. `fastmcp-transport`'s `websocket-experimental` is empty because `fastmcp_transport::websocket` is compiled unconditionally — but see **Experimental WebSocket framing** below: the always-compiled frame codec is not the one that ships. By contrast `fastmcp-server`'s `oauth-client-credentials` is **not** inert: together with `builtin-auth-server` it gates 34 sites, including the `client_credentials` arm of the token endpoint and the advertised `grant_types_supported` list. The facade and client `websocket-experimental` features gate code: `WebSocketClient`, `ClientBuilder::connect_websocket_with_cx`, and (through `fastmcp-server/websocket`) `bind_websocket`. This list is complete as measured 2026-11-05 over every declared feature in the nine crates that declare any (`fastmcp-core` declares exactly one, `test-runtime`, added 2026-11-02 by `0035bc4d`; it is not inert, carrying eight `cfg(feature = "test-runtime")` sites): the seven user-enableable features with zero `cfg(feature = ...)` sites in their own crate's `src` **and** an empty value list are exactly `fastmcp-console`'s six above plus `fastmcp-transport`'s `websocket-experimental` |
| **HTTP as_proxy auto-follow** | A gateway HTTP `as_proxy` does not auto-follow an upstream server `input_required` task across POSTs; per-request dispatch is stateless and upstream request state cannot resume. Callers resume such upstream tasks through an explicit matching `tasks/update` |
| **OAuth/OIDC Promotion** | Public source APIs exist, but production security and profile conformance remain unverified; they are quarantined from production-support claims |
| **Early Development** | API may change before 1.0 |

### MCP Apps host sampling

With the `apps` feature, a negotiated `McpAppsWireHost` accepts the View's
standard `sampling/createMessage` request when its committed `ui/initialize`
response advertises `hostCapabilities.sampling`. Supply the model operation
through `McpAppsWireHostEffects::sampling_create_message` and attach the effects
with `host.with_effects(effects)`. The public facade exports
`McpAppsSamplingCapability`, `McpAppsSamplingParams`, and `McpAppsSamplingResult`
at the root and under `modern`.

The callback owns approval for each invocation, model selection, any requested
context inclusion, and consent to disclose the result to that View. Its default
refuses the request. Advertising `sampling: {}` permits plain sampling;
`sampling: { tools: {} }` additionally permits the `tools` and `toolChoice`
parameters. Tool descriptions grant no permission to execute those tools.
The request runs under the caller's context with a bounded deadline; matching
View cancellation drops its pending work and suppresses its response.

Sampling uses the isolated Apps JSON-RPC channel and never forwards a standalone
sampling request to the MCP server. Plain requests return one text, image, or
audio block; requests carrying `tools` may return extended sampling content.
Results are validated against the original request before disclosure, preserve
the View's request ID, and carry no modern MCP `resultType`. This is a
browser-neutral Host capability: the embedder still supplies its model provider
and rendering environment.

### MCP Apps Task cancellation and input lifetime

With `apps` and `tasks`, a Host can override
`McpAppsWireHostEffects::approve_server_task_cancellation` to authorize one
remote `tasks/cancel` when a matching View cancellation stops observation of an
approved, nonterminal server Task. The default returns `false`, so existing
Hosts retain local-only cancellation. The synchronous hook checks the current
View, origin, principal and consent policy; ordinary cancellation observers run
first. When effects are composed, only the most recently installed effects can
grant remote cancellation.

The framework supplies the original View parameters and the last approved Task
snapshot to that hook. It obtains the Task ID from the authenticated MCP peer,
never from the View's cancellation frame. HTTP, Unix stdio, WebSocket and Memory
use their existing typed Task methods, including the independently negotiated
`tasks/cancel` permission, a fresh MCP request ID, and the original caller's
authority. The grant expires within five seconds and cannot extend the original
request deadline. Native transport cleanup retires the abandoned observation
before dispatch where necessary.

An authorized cancellation is attempted once. Losing its response or dropping
cleanup does not replay the mutation; acknowledgement does not establish that
the Task has reached a terminal state. Arbitrary future drop, timeout and View
disconnect do not grant cancellation. Denial or an approval-hook error leaves
cancellation local. A failure during authorized native cleanup closes that
View through the existing transport-failure path.

For `input_required` Tasks, the Host checks retention before invoking consent,
sampling or elicitation effects. A finite remaining lifetime shortens the
operation's monotonic deadline, including pending Host callbacks and subsequent
updates or reads. An expired snapshot cannot disclose input to a Host callback,
and later wall-clock rollback cannot extend an already admitted deadline.

---

## FAQ

**Q: Why is Tokio unsupported?**

A: FastMCP Rust is built around asupersync capability contexts, budgets, and cooperative-cancellation surfaces. Tokio and Tokio-based adapters are outside the supported runtime model.

**Q: Can I use this with Claude Desktop?**

A: Stdio integration exists, but compatibility must be checked against the client: the root compatibility `PROTOCOL_VERSION` is `2024-11-05`, the modern facade's `modern::PROTOCOL_VERSION` is `2026-07-28`, and MCP 2026-07-28 support is not yet verified.

**Q: How do I add authentication?**

A: Install an `AuthProvider` through the server builder. Native HTTP uses the
`Authorization` header and rejects recognized credentials in JSON-RPC params,
their `_meta`/`headers` containers, and query parameters with a fixed migration
diagnostic. Static tokens remain a non-OAuth deployment mode; applications own
TLS termination and token provisioning. Other transport adapters retain a
stripped legacy JSON-RPC credential fallback. OAuth/OIDC production security,
continuous authorization and profile conformance remain unverified.

**Q: What's the performance overhead of checkpoints?**

A: Checkpoints perform cancellation and budget checks. No project benchmark currently supports a universal per-call latency claim; measure them in the target workload if the cost matters.

**Q: Can I use other async runtimes?**

A: No. The current API and implementation require asupersync; other async runtimes are not supported.

**Q: How do I test my handlers?**

A: `#[tool]` keeps your function, so call it directly with an `McpContext`
built from a runtime's context and a request ID. (`Cx::for_testing()` needs
asupersync's `test-internals` feature; this form needs no extra features.)
```rust
use asupersync::runtime::RuntimeBuilder;
use fastmcp_rust::{Cx, McpContext, McpResult, tool};

#[tool]
fn my_tool(ctx: &McpContext, input: String) -> McpResult<String> {
    ctx.checkpoint()?;
    Ok(input)
}

#[test]
fn test_my_tool() {
    let runtime = RuntimeBuilder::current_thread()
        .build()
        .expect("create test runtime");
    runtime.block_on(async {
        let ctx = McpContext::new(Cx::current().expect("test context"), 1);
        let result = my_tool(&ctx, "input".to_string());
        assert_eq!(result.unwrap(), "input");
    });
}
```

---

## Verifying a Checkout

From a committed checkout, use the repository's DSR entrypoint. It supplies
identical `fastmcp` and `fastmcp_rust` registrations, runs compilation and tests
through RCH, and retains the commands, source revision, logs, and test IDs.
Python 3.11 or newer, DSR, and RCH must be available on `PATH`.

```bash
# Compile every workspace target with every feature enabled.
scripts/verify_batch.sh --scope '--workspace --all-targets' --all-features --check-only

# Exercise the facade library, including the real Memory test-server helpers.
scripts/verify_batch.sh --scope '-p fastmcp-rust --lib' --features testing-lab

# Check the installed DSR contract without compiling Rust.
scripts/verify_batch.sh --self-test-dsr-contract
```

Test runs require the selected targets' features and compare discovered,
started, and passed tests exactly. Empty or incomplete runs fail. A successful
run proves its recorded scope only; aggregate MCP conformance remains unverified.

---

## About Contributions

Please don't take this the wrong way, but I do not accept outside contributions for any of my projects. I simply don't have the mental bandwidth to review anything, and it's my name on the thing, so I'm responsible for any problems it causes; thus, the risk-reward is highly asymmetric from my perspective. I'd also have to worry about other "stakeholders," which seems unwise for tools I mostly make for myself for free. Feel free to submit issues, and even PRs if you want to illustrate a proposed fix, but know I won't merge them directly. Instead, I'll have Claude or Codex review submissions via `gh` and independently decide whether and how to address them. Bug reports in particular are welcome. Sorry if this offends, but I want to avoid wasted time and hurt feelings. I understand this isn't in sync with the prevailing open-source ethos that seeks community contributions, but it's the only way I can move at this velocity and keep my sanity.

---

## License

FastMCP Rust is distributed under the terms in [LICENSE](LICENSE): the MIT
License with the included OpenAI/Anthropic rider. Every workspace crate uses
that file as its Cargo `license-file`. [LICENSE-MIT](LICENSE-MIT) is retained
as a reference copy of the underlying MIT text; it is not an alternative
license for this project.

---

<p align="center">
  <sub>Built with <a href="https://github.com/Dicklesworthstone/asupersync">asupersync</a> for context-aware async</sub>
</p>
