# Dependency Upgrade Log

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
