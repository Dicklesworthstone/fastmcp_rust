# Dependency Upgrade Log

**Date:** 2026-09-12 | **Project:** fastmcp_rust | **Language:** Rust

## Current upgrade run

The crates.io API was queried for all 38 direct registry dependencies. Six have
new stable releases; the other 32 pins are current. Registry build metadata
suffixes are ignored when comparing versions. Internal path dependencies and
the dated nightly toolchain remain outside dependency upgrades.

| Dependency | Current | Target | Status |
|---|---|---|---|
| asupersync | 0.4.10 | 0.5.0 | Passed: original four shutdown tests and caller-capability test after two production scheduling fixes; full suite pending |
| console | 0.16.4 | 0.16.6 | Passed: CLI units 186, help contract 2, live CLI integration 74 |
| dirs | 6.0.0 | 7.0.0 | Passed: all 727 client library tests with all features |
| html5ever | 0.39.0 | 0.40.0 | Passed: both Apps graphs compile and their selected tests pass |
| toml | 1.1.5 | 1.1.6 | Passed: 46 client configuration tests and all 186 CLI unit tests |
| trybuild | 1.0.120 | 1.0.121 | Passed: all six downstream compilation harness tests, no golden regeneration |

### asupersync 0.4.11

[Published release](https://github.com/Dicklesworthstone/asupersync/releases/tag/v0.4.11)
at `9b114c1f2305f20f8373a476c9decc74122b961c` retains the documented public API
floor. It repairs runtime teardown, cancellation and I/O readiness. Its
current-thread runtime now drives child tasks on the calling thread while
`block_on` runs; a root that synchronously waits for a child can deadlock.
FastMCP's bridge and proxy consumers therefore require runtime tests, not just
a successful compile. The first all-feature library/binary run compiled and
completed CLI, client, console, core, derive, protocol, and facade suites, but
the server's nonquiescent stdio shutdown test failed and its noncooperative
HTTP shutdown test stalled. RCH then lost its connection and exited 103;
server and transport suite completion is not claimed. The focused stdio test
also failed its 30-second result bound; releasing its child allowed teardown
to complete. The failed runs are retained as
`/tmp/fastmcp-release-asupersync-0411-tests-20260912.log` and
`/tmp/fastmcp-release-asupersync-0411-stdio-diagnostic-20260912.log`.

An initial HTTP diagnostic incorrectly wrapped shutdown in `timeout_at`:
0.4.11's cancellation-aware sleep completed early when the probe deliberately
cancelled its caller, producing a spurious deadline error in both ownership
tests. Those wrappers were removed. The release-on-failure guard remains,
with all original shutdown assertions. The cooperative case then passed;
the noncooperative case still exceeded 60 seconds. These attempts are retained
in the `http-ssh-01` and `http-ssh-02` logs under `/tmp/fastmcp-release-asupersync-0411-*`.

The baseline verification snapshot retains 0.4.10 and the exact preceding lockfile selection
(asupersync-macros and the three franken support crates at 0.4.9). No upstream
root cause or successful runtime migration is claimed. The user authorized
direct SSH builds in isolated directories without sync deletion or cleanup,
after the installed RCH synchronization path was found to delete files.

### asupersync 0.5.0

A registry recheck at 19:14 UTC found [0.5.0](https://github.com/Dicklesworthstone/asupersync/releases/tag/v0.5.0),
published at 06:22 UTC during the pause. The other five upgrade targets are
unchanged. This release preserves existing public method signatures while
making ambient context installation retain capability restrictions. FastMCP
must not depend on installing a narrowed context to regain authority.
It also retires workers and wake callbacks outside their locks and exposes
inherited blocking-pool handles only with spawn authority. The source is
`78b64636e99fea4ea2d868096576021dd3b8e519`; the registry checksum is
`f34b1a19ffd6b74570339a156912436335bb09c594c675c62ea164b19a1f2511`.
The identical four shutdown tests passed on the restored 0.4.10 lockfile
(4 passed, 0 ignored, 10.78 seconds). On 0.5.0 the cooperative HTTP and SSE
ownership cases passed, but the stdio case again failed its 30-second result
bound and the noncooperative HTTP case stalled for over six minutes. The
isolated candidate process group was then terminated; this is a failed run,
not completed suite evidence. The logs are
`/tmp/fastmcp-release-asupersync-0410-shutdown-ssh-03-20260912.log` and
`/tmp/fastmcp-release-asupersync-050-shutdown-ssh-04-20260912.log`.
These failures initially led to retaining 0.4.10 while investigating the
runtime interaction. No assertions or shutdown bounds were weakened.

Subsequent fetch found independently pushed commit `57899320`, which adopts
0.5.0 for caller capability ceilings. That work includes a real polling
regression. It was preserved in merge `d0d62955`. The failure was then traced
to two FastMCP blocking-completion loops: cancelled `Sleep` becomes ready
immediately, so HTTP cleanup and modern router dispatch can monopolize one
current-thread scheduler poll. Both loops now explicitly yield after cancelled
sleep while retaining the exact physical-completion requirement.

The HTTP-only correction passed all three ownership cases in source07; stdio
still failed because the router loop had the same defect. A wakeable-channel
test-harness experiment in source08 did not fix stdio and was reverted. The
original stdio channel, 30-second deadline, and all assertions are restored.
Source09 verifies both production fixes with the original four shutdown tests
and the upstream caller-capability regression: all five passed, none ignored,
in 15.79 seconds. Snapshot SHA256:
`5e4d5cad839d2bd61ff4b97911d57f2bb9b437a28f5472b35b3923216f039fcf`.
Log: `/tmp/fastmcp-release-asupersync-050-shutdown-ssh-09-20260912.log`.
Independent review checked both production loops and confirmed that physical
completion, error handling, and the original test assertions remain intact.
The full workspace matrix remains required before release.

### console 0.16.6

Source snapshot `151041c934692eb62af8177847e11b6ee9b218419b39ea6e0e101ce73f3f2e7b`
passed all 262 selected CLI tests (186 unit, 2 documentation contract, 74 live
integration), with zero ignored or filtered tests. Direct SSH log:
`/tmp/fastmcp-release-console-0166-ssh-05b-20260912.log`. The first invocation
incorrectly selected a nonexistent CLI library target and exited before
compilation; the corrected command selects its binary targets.
The fixture binary contains no unit tests and earns no test credit. An earlier
progress count incorrectly carried forward a 16-test contract inventory;
the actual two discovered contract tests are authoritative.

### Remaining migration research

Trybuild 1.0.121 passed all six downstream harness tests, with zero ignored or
filtered tests, in 742.91 seconds. This includes unchanged diagnostic fixtures,
direct Tasks derives, feature and symbol isolation, renamed-facade consumers,
and bounded child-process exit handling. Source12 SHA256:
`3ebbe445b2440140ae5ec7548fa65498684c18ae4d8f60aa6a237006b42f43e0`.
Log: `/tmp/fastmcp-release-trybuild-121-csd-12-20260912.log`; command exited zero.

The first source12 attempt on hz3 was interrupted with exit 143 after sustained
filesystem waits; it is not a completed test result. Only its two observed
process groups were terminated, and all files were retained. The identical
source ran on the previous release host, csd, using the pinned real Cargo in
a task-private command path. The replacement profile disables debug symbols
and incremental artifacts (`CARGO_PROFILE_DEV_DEBUG=0`,
`CARGO_PROFILE_TEST_DEBUG=0`, `CARGO_INCREMENTAL=0`), retaining debug assertions.
It uses eight compilation jobs and a separate target directory. No shared
toolchain, RCH routing, or security configuration was modified.

TOML 1.1.6 passed all 46 selected client configuration tests and all 186 CLI
unit tests, with zero ignored tests. The CLI run includes schema rejection,
credential redaction, and actual server command execution. Source11 SHA256:
`e0e6022ad89f3642ce2b3e998a7dd218efe714eab96d6c900d54c7161d92e79a`.
Log: `/tmp/fastmcp-release-toml-116-ssh-11-20260912.log`; command exited zero.

The html5ever 0.40 update compiled both optional Apps graphs. Source10
(`1d259515d5c2f4fe19ace1a69c158f75ac27b5422fb63050053431ee8e5de8ad`)
passed the selected client and server Apps tests, with no ignored tests.
Log: `/tmp/fastmcp-release-html5ever-040-ssh-10b-20260912.log`.
The first invocation started before source transfer completed and failed
before compilation; that failed attempt remains in the corresponding `10` log.
Only the corrected invocation after successful transfer provides test evidence.

The dirs 7 update passed all 727 client library tests, zero ignored or
filtered, in 23.47 seconds on source09. The run includes configuration-path
selection, actual configured connections, HTTP, and WebSocket consumers.
Log: `/tmp/fastmcp-release-dirs-070-ssh-09-20260912.log`.

- [console 0.16.4–0.16.6](https://github.com/console-rs/console/compare/0.16.4...0.16.6):
  repairs OSC/DCS stripping and UTF-8 truncation, improves visible-width
  calculation. The CLI consumes its terminal and styling APIs.
- [dirs 6–7 source comparison](https://codeberg.org/dirs/dirs-rs/compare/00511bdc252f491a72ac89f6d6a2463406266fb2...793c8a97bea55669a806499839abd7b1d844279f):
  Windows `preference_dir` changes from local to roaming application data.
  FastMCP uses `home_dir` and `data_dir`, whose APIs remain unchanged.
- [html5ever 0.39–0.40 source comparison](https://github.com/servo/html5ever/compare/ce64836c685025a5fef0860fa2e9c80b2683e8d0...a193ea7f2492d1e51eb32955a09c241345348dba):
  updates markup5ever and prevents a truncated meta-charset panic. Its Rust
  1.85 minimum is below this project's pinned compiler. It is an optional
  dependency in both Apps graphs, but no current production code calls its
  parser. Compile those graphs and run their existing Apps tests; do not claim
  parser/sanitizer runtime verification or newly implemented HTML handling.
- [toml 1.1.5–1.1.6 source comparison](https://github.com/toml-rs/toml/compare/e93ed4e1dec245fb523aec2afd0a300da4207f4e...572c005d80cca5f7bd163805c2f33ba0a5207b6d):
  removes unnecessary parser key clones; verify CLI configuration parsing.
- [trybuild 1.0.120–1.0.121](https://github.com/dtolnay/trybuild/compare/1.0.120...1.0.121):
  renames its target metadata dependency from `target-triple` to `target-tuple`.
  All six downstream compile harness tests must run after upgrading.

Full product tests, strict Clippy, dependency audit, and release artifact checks
remain pending. Historical FND attestation failures retain their original
revision boundary; dependency hashes will not be rewritten to manufacture a
passing attestation.

---

**Date:** 2026-09-04  |  **Project:** fastmcp_rust  |  **Language:** Rust

## Summary
- **Updated:** 4  |  **Skipped:** remaining exact pins already latest stable; frankensqlite / frankensearch are not direct deps  |  **Failed:** 0  |  **Needs attention:** final batch verification and FND-01 evidence re-attest

## Updates

### asupersync: 0.4.9 → 0.4.10
- **Notes:** Additive ambient child-region support; no FastMCP source changes were required.
- **Verification:** Exact locked workspace/all-targets check passed at `8551966` via RCH job `30004650421780728` with no warnings.

### flate2: 1.1.9 → 1.1.10
- **Notes:** Patch upgrade for the HTTP transport's gzip/deflate support. The lockfile contains optional `zlib-rs`, but it is not active in the workspace feature graph.
- **Verification:** Exact locked workspace/all-targets check passed at `8a1998f` via RCH job `30004650421780759` with no warnings.

### toml: 1.1.4 → 1.1.5
- **Notes:** Patch upgrade for CLI configuration parsing.
- **Verification:** Exact locked workspace/all-targets check passed at `de48ccb` via RCH job `30004650421780769` with no warnings.

### argon2: 0.5.3 → 0.6.0
- **Notes:** Optional `builtin-auth-server` dependency. The current server source does not yet consume Argon2 as a production verifier, so this update earns no authentication or security capability credit.
- **Verification:** The exact shipped-library profile (`--lib --no-default-features --features builtin-auth-server`) passed at `8535837` via RCH job `30004650421780774`. The first all-targets/no-default-features attempt, RCH job `30004650421780771`, correctly failed because two legacy-only integration targets lacked Cargo feature gates. Commit `7c71457` adds those gates; the unchanged all-targets command passed there via RCH job `30004650421780779`. The final workspace batch remains pending.

## Skipped
- `fsqlite` / `frankensqlite` and `frankensearch` are not current FastMCP dependencies and are not added.
- No aggregate MCP 2026-07-28 conformance or maturity promotion is claimed from this maintenance bump.

## Verification boundary
- The entries above record only completed commands bound to their named revisions. They do not claim the final workspace clippy, formatting, or test batch before those commands run.
- The frozen FND-01 evidence still binds older manifests and toolchain state. It must be regenerated by its real producer before re-attestation; hashes are not rewritten around the upgrades.

---

**Date:** 2026-08-20  |  **Project:** fastmcp_rust  |  **Language:** Rust

## Summary
- **Updated:** 3  |  **Skipped:** remaining exact pins already latest stable; frankensqlite / frankensearch / franken_networkx are not direct deps  |  **Failed:** 0  |  **Needs attention:** FND-01 evidence re-attest

## Updates

### asupersync: 0.4.8 → 0.4.9
- **Breaking:** None. Changelog states 0.4.9 preserves the v0.4.3 public floor (additive APIs only).
- **Notes:** `RuntimeHandle::request_cx_with_budget`, `Cx::with_blocking_pool_handle`, SQLite cancel/row-metadata correctness, owned-OTLP mapping. Transitive `franken-kernel` / `franken-evidence` / `franken-decision` / `asupersync-macros` 0.4.9.
- **Tests:** `cargo check --workspace --all-targets --locked` green on
  `nightly-2026-08-20` / rustc 1.100.0-nightly.

### cap-std / cap-fs-ext: 4.0.2 → 4.0.3
- **Breaking:** None expected (patch).
- **Notes:** Filesystem resource provider capability-fs handles.
- **Tests:** included in the same locked workspace `cargo check`.

## Skipped (already latest stable)

Queried crates.io `max_stable_version` on 2026-08-20:

rich_rust 0.2.3, rustix 1.1.4, serde 1.0.229, serde_json 1.0.151, serde_yaml 0.9.34, log 0.4.33, base64 0.23.1, semver 1.0.28, flate2 1.1.9, chrono 0.4.45, notify 8.2.0, glob 0.3.4, console 0.16.4, toml 1.1.4, dirs 6.0.0, url 2.5.8, getrandom 0.4.3, sha2 0.11.0, hmac 0.13.0, zeroize 1.9.0, ring 0.17.14, proc-macro2 1.0.107, proc-macro-crate 3.5.0, regex 1.13.1, clap 4.6.6, trybuild 1.0.120, html5ever 0.39.0, argon2 0.5.3, redis 1.6.0, time 0.3.55, syn 3.0.3.

serde_yaml `0.9.34+deprecated` and toml `1.1.4+spec-1.1.0` are the same versions with registry metadata suffixes.

frankensqlite (`fsqlite` 0.3.7), frankensearch (crates.io 0.3.2 / git v1.6.0), and franken_networkx are **not** direct FastMCP dependencies; they are not added to the graph.

## Skipped (not stable)

- notify 9.0.0-rc.4 — RC only; stay on 8.2.0
- argon2 0.6.0-rc.8 — RC only; stay on 0.5.3

## Toolchain

- rust-toolchain.toml `nightly-2026-08-19` → `nightly-2026-08-20` / rustc 1.100.0-nightly
- workspace `rust-version` stays `1.100`
- Dated pin kept (not floating `nightly`) for reproducible DSR/RCH builds

## Needs Attention

### FND-01 evidence harness
- **Issue:** `crates/fastmcp/tests/fnd_01_dependency_evidence.rs` and `evidence/fnd-01/*` still freeze `nightly-2026-07-11` / earlier workspace versions. Rewriting hashes without re-running the producer would be fake attestation.
- **Action:** Test binary remains behind `testing-lab`. FND-01 remains unverified and unclaimed.

## Workspace version

- 0.6.0 → 0.7.0 (pre-1.0 minor bump: product remainder fixes + franken pin bump)

---

# Prior log (2026-08-18)

**Date:** 2026-08-18  |  **Project:** fastmcp_rust  |  **Language:** Rust

## Summary
- **Updated:** 2  |  **Skipped:** remaining exact pins already latest stable  |  **Failed:** 0  |  **Needs attention:** FND-01 evidence re-attest

## Updates

### asupersync: 0.4.5 → 0.4.8
- **Breaking:** None. Changelog states 0.4.6–0.4.8 preserve the v0.4.3 public floor (no public item removed or renamed).
- **Notes:** Internal timer/cancel, HTTP/1 RFC OWS framing, ambient `Cx` guard identity teardown, QUIC/ATP reassembly bounds.
- **Tests:** `cargo check --workspace --all-targets --locked` green on csd
  (`nightly-2026-08-19`). Isolated `e2e_modern_http` handler test green.
  `fastmcp-core --lib` 341/341. `fastmcp-cli` `e2e_dev` 12/12 with rustup
  cargo (RCH shim refuses `/tmp` fixtures). Protocol `--lib` 580/581; the
  one fail (`final_subscriptions_listen_rejects_one_field_response_id_mismatch`)
  is unrelated to this pin bump. Full `cargo test --workspace` still log-bombs
  `fastmcp-server --lib` and includes pre-existing client/e2e_install failures.

### redis: 1.4.1 → 1.6.0 (optional `redis-tasks` / FND-01 probe only)
- **Breaking:** None listed 1.4.1 → 1.6.0 (additive XNACK, reconnect limits, cluster/sentinel fixes).
- **Notes:** Still absent from the default workspace graph. Not published with `--all-features`.
- **Tests:** default graph does not compile this edge; pin-only update

## Skipped (already latest stable)

asupersync siblings and all other direct exact pins were queried against crates.io `max_stable_version` on 2026-08-18:

rich_rust 0.2.3, rustix 1.1.4, serde 1.0.229, serde_json 1.0.151, serde_yaml 0.9.34, log 0.4.33, base64 0.23.1, semver 1.0.28, flate2 1.1.9, chrono 0.4.45, notify 8.2.0, glob 0.3.4, console 0.16.4, toml 1.1.4, dirs 6.0.0, url 2.5.8, getrandom 0.4.3, sha2 0.11.0, hmac 0.13.0, zeroize 1.9.0, ring 0.17.14, proc-macro2 1.0.107, proc-macro-crate 3.5.0, cap-std 4.0.2, cap-fs-ext 4.0.2, regex 1.13.1, clap 4.6.6, trybuild 1.0.120, html5ever 0.39.0, argon2 0.5.3, syn 3.0.3, quote 1.0.47, time 0.3.55, strip-ansi-escapes 0.2.1, tracing 0.1.44, tracing-subscriber 0.3.23, tempfile 3.27.0, chacha20poly1305 0.11.0.

serde_yaml `0.9.34+deprecated` and toml `1.1.4+spec-1.1.0` are the same versions with registry metadata suffixes.

## Skipped (not stable)

- notify 9.0.0-rc.4 — RC only; stay on 8.2.0
- argon2 0.6.0-rc.8 — RC only; stay on 0.5.3

## Toolchain

- rust-toolchain.toml `nightly-2026-07-11` / rustc 1.99.0-nightly → `nightly-2026-08-19` / rustc 1.100.0-nightly (`e71c0f1e3` 2026-08-18)
- workspace `rust-version` `1.99` → `1.100`
- Dated pin kept (not floating `nightly`) for reproducible DSR/RCH builds

## Needs Attention

### FND-01 evidence harness
- **Issue:** `crates/fastmcp/tests/fnd_01_dependency_evidence.rs` and `evidence/fnd-01/*` still freeze `nightly-2026-07-11` / workspace 0.5.0. Rewriting hashes without re-running the producer would be fake attestation.
- **Action:** Gated the test binary behind `testing-lab` so the default 0.6.0 product test gate does not compile it. FND-01 remains unverified and unclaimed.

## Workspace version

- 0.5.0 → 0.6.0 (pre-1.0 minor bump requested with this upgrade)
