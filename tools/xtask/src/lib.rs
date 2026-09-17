//! FastMCP workspace tooling.
//!
//! Non-publishable. This crate exists so the FND-02 traceability checker is
//! real shipped code with a real entrypoint rather than test scaffolding: the
//! binary and the integration tests reach the same public surface.

#![forbid(unsafe_code)]

pub mod plan_tracker;
