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
//! Explicit sector-document review uses a bounded credential-free guarded GET.
//! These components do not activate the MCP extension, launch a browser,
//! dispatch credential-bearing HTTP or install an MCP credential. Durable browser-flow custody,
//! confidential credential providers and independently attested deployment/
//! identity authority remain separate work. A local byte digest or subject
//! lookup is not a launch, dispatch or authorization receipt.

pub mod identity;
pub mod oidc;
pub mod policy;
pub mod replay;
pub mod response;

/// Purpose-separated RS256 verification shared with other protocol roles.
pub use fastmcp_protocol::jose::enterprise as verification;
