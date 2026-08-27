//! Remote coordinator for the frozen FND-01 evidence gate.
//!
//! The implementation intentionally lives in the independently reviewed
//! verifier module. This example only supplies Cargo's executable entrypoint
//! for the integration producer.

#![forbid(unsafe_code)]

// The included module compiles under three cfg surfaces (bootstrap binary,
// integration test, and this non-test binary). Off-Linux non-test builds bind
// Linux-gated helpers without consuming them, so the binary-context lint
// classes below are allowed here instead of churning the shared, bead-owned
// verifier source.
#[allow(
    dead_code,
    unused_imports,
    unused_variables,
    unused_mut,
    unreachable_code,
    clippy::used_underscore_binding,
    clippy::diverging_sub_expression
)]
#[path = "../tests/fnd_01_dependency_evidence.rs"]
mod evidence;

// `cargo test --all-targets` also compiles examples as test harnesses. The
// included verifier deliberately keeps its executable entry point out of
// `cfg(test)`, so only bind that entry point for the actual example binary.
#[cfg(not(test))]
fn main() {
    std::process::exit(evidence::harness_main(std::env::args_os()));
}
