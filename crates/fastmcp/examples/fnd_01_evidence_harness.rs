//! Remote coordinator for the frozen FND-01 evidence gate.
//!
//! The implementation intentionally lives in the independently reviewed
//! verifier module. This example only supplies Cargo's executable entrypoint
//! for the integration producer.

#![forbid(unsafe_code)]

#[allow(dead_code, unused_imports)]
#[path = "../tests/fnd_01_dependency_evidence.rs"]
mod evidence;

fn main() {
    std::process::exit(evidence::harness_main(std::env::args_os()));
}
