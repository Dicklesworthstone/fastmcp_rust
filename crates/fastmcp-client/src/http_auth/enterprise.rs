//! Enterprise-managed authorization building blocks for native clients.
//!
//! This module keeps IdP and resource-AS registrations, signing-key purposes and
//! token-response stages distinct. Bounded duplicate-aware JSON admission
//! precedes typed decoding. Assertions receive real RS256 verification; private
//! zeroizing response owners expose no compact token or credential conversion.
//!
//! These are local policy, response-validation and read-only mapping operations.
//! They do not activate the MCP extension, acquire browser assertions, dispatch
//! exchanges, attest a deployment, or install an MCP bearer credential.
//! Framework-owned OIDC acquisition, confidential credential custody, durable
//! one-use stores and deployment policy attestation remain separate work.
//! A local subject lookup does not establish exchange provenance, a durable
//! mapping receipt, replay reservation or authorization.

pub mod identity;
pub mod policy;
pub mod response;

/// Purpose-separated RS256 verification shared with other protocol roles.
pub use fastmcp_protocol::jose::enterprise as verification;
