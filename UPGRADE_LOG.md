# Dependency Upgrade Log

**Date:** 2026-02-19  |  **Project:** fastmcp_rust  |  **Language:** Rust

## Summary
- **Updated:** 10  |  **Skipped:** 0  |  **Failed:** 0  |  **Needs attention:** 1

## Updates

### asupersync: 0.2.0 → 0.2.5
- **Spec change:** `"0.2.0"` → `"0.2"` (allow future patches)
- **Breaking:** None
- **Tests:** Passed (1439/1441 — 2 pre-existing failures unrelated to deps)

### rich_rust: spec loosened
- **Spec change:** `"0.2.0"` → `"0.2"` (allow future patches)
- **Breaking:** None (still resolves to 0.2.0, which is latest)
- **Tests:** Passed

### console: 0.15.11 → 0.16.2
- **Spec change:** `"0.15"` → `"0.16"` (minor version bump)
- **Breaking:** None encountered — `Term` and `style` APIs compatible
- **Tests:** Passed

### toml: 0.8.23 → 1.0.3
- **Spec change:** `"0.8"` → `"1.0"` (major version bump)
- **Breaking:** None encountered — `from_str`, `to_string_pretty`, `Value` all compatible
- **Tests:** Passed

### getrandom: 0.3.4 → 0.4.1
- **Spec change:** `"0.3"` → `"0.4"` (breaking pre-1.0 bump)
- **Breaking:** None encountered — `getrandom::fill` API preserved
- **Tests:** Passed

### redis: 1.0.3 → 1.0.4
- **Spec change:** `"1.0.3"` → `"1"` (loosened to allow future patches)
- **Breaking:** None
- **Tests:** Passed

### semver: spec loosened
- **Spec change:** `"1.0.27"` → `"1"` (allow future patches)
- **Breaking:** None
- **Tests:** Passed

### ureq: spec loosened
- **Spec change:** `"3.2.0"` → `"3"` (allow future patches)
- **Breaking:** None
- **Tests:** Passed

### sha2: spec loosened
- **Spec change:** `"0.10.8"` → `"0.10"` (allow future patches)
- **Breaking:** None
- **Tests:** Passed

### hmac: spec loosened
- **Spec change:** `"0.12.1"` → `"0.12"` (allow future patches)
- **Breaking:** None
- **Tests:** Passed

### regex: spec loosened
- **Spec change:** `"1.11.1"` → `"1"` (allow future patches)
- **Breaking:** None
- **Tests:** Passed

### jsonwebtoken: spec loosened (crate-level)
- **Spec change:** `"10.2.0"` → `"10"` in fastmcp/Cargo.toml and fastmcp-server/Cargo.toml
- **Breaking:** None
- **Tests:** Passed

### Cargo.lock patch updates (via `cargo update`)
- **syn:** 2.0.115 → 2.0.116
- **clap:** 4.5.58 → 4.5.60
- **bumpalo:** 3.19.1 → 3.20.2
- **unicode-ident:** 1.0.23 → 1.0.24

## Failed

_(None)_

## Needs Attention

- **serde_yaml** `0.9.34+deprecated` — officially deprecated by maintainer. Consider migrating to `serde_yml` (community fork) or alternative format. No code changes required yet — the crate still works.

## Pre-existing Test Failures (not caused by upgrades)

Two tests in `fastmcp-server/src/tasks.rs` fail independently of dependency changes:
- `tasks::tests::can_transition_invalid_pairs` — `can_transition(Pending, Failed)` returns true but test expects false
- `tasks::tests::fail_task_on_pending_is_ignored` — task transitions to Failed from Pending but test expects it to stay Pending
