//! Enterprise-managed authorization building blocks for native clients.
//!
//! This module keeps IdP and resource-AS registrations, signing-key purposes and
//! token-response stages distinct. The OIDC codec connects a generated GET,
//! callback, protected code form and signed response. Bounded duplicate-aware
//! admission precedes typed decoding; verified assertion owners retain no
//! public compact-token or bearer conversion.
//!
//! Replay reservation composes persistent MAC aliases, a registered external
//! restore authority and an atomic assertion-use store. Provider implementations
//! remain deployment trust boundaries, with no built-in durability attestation.
//! Explicit sector-document review and purpose-separated signing-key acquisition
//! use bounded credential-free guarded HTTPS GETs under the caller's context.
//! The guarded two-stage token driver consumes a completed assertion reservation
//! and returns an exclusively owned, resource-bound bearer credential. This
//! low-level dispatch component does not activate the MCP extension or launch a
//! browser. Protected-blob credential providers bind each native POST to an
//! independently selected role, complete profile and reviewed identity snapshot.
//! Durable browser-flow custody and independently attested deployment/identity
//! authority remain separate work.
//! A local byte digest or subject lookup is not a launch or authorization receipt.
//! The opt-in HTTP policy owner binds an already exchanged grant to fresh
//! admitted metadata and checks its declaration on each outgoing MCP request.

pub mod credentials;
/// Post-exchange, request-local enterprise binding for the native HTTP client.
pub mod http;
pub mod identity;
pub mod keys;
pub mod oidc;
pub mod policy;
pub mod replay;
pub mod response;

/// Purpose-separated RS256 verification shared with other protocol roles.
pub use fastmcp_protocol::jose::enterprise as verification;
