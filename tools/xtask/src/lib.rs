//! FastMCP workspace tooling.
//!
//! Non-publishable. This crate exists so the FND-02 traceability checker is
//! real shipped code with a real entrypoint rather than test scaffolding: the
//! binary and the integration tests reach the same public surface. The
//! REL-071 release-binding evaluator is here for the same reason.

#![forbid(unsafe_code)]

pub mod plan_tracker;
pub mod rel_071;
