//! MCP protocol types and JSON-RPC implementation.
//!
//! This crate provides:
//! - JSON-RPC 2.0 message types
//! - MCP-specific method types (tools, resources, prompts)
//! - Protocol version negotiation
//! - Message serialization/deserialization
//!
//! MCP 2026-07-28 support is under implementation and remains unverified. The
//! public `PROTOCOL_VERSION` is still `2024-11-05`; newer source types are not
//! aggregate conformance or release evidence.
//!
//! # MCP Protocol Overview
//!
//! MCP (Model Context Protocol) uses JSON-RPC 2.0 over various transports.
//! The protocol defines:
//!
//! - **Tools**: Executable functions the client can invoke
//! - **Resources**: Data sources the client can read
//! - **Prompts**: Template prompts for the client to use
//!
//! # Wire Format
//!
//! Protocol values serialize as JSON-RPC. Framing is transport-specific; the
//! stdio transport uses newline-delimited JSON (NDJSON).
//!
//! # Role in the System
//!
//! `fastmcp-protocol` is the **shared vocabulary** for FastMCP:
//! - The server uses these types to validate and serialize responses.
//! - The client uses the same types to construct requests and parse replies.
//! - Transports carry these messages without needing to know business logic.
//!
//! If you are integrating FastMCP with a custom runtime or embedding it into
//! another system, depend on this crate to use FastMCP's current JSON-RPC and
//! MCP data models. The modernization disclaimer above still applies.

#![forbid(unsafe_code)]
#![allow(dead_code)]

pub mod common_types;
pub mod extensions;
mod jsonrpc;
mod messages;
pub mod methods;
pub mod protocol_policy;
pub mod protocol_version;
mod result;
pub mod schema;
mod server_discovery;
mod types;

pub use jsonrpc::{
    ClientIngressFailureScope, CorrelationKey, JSONRPC_VERSION, JsonRpcAdmissionError,
    JsonRpcEndpointRole, JsonRpcError, JsonRpcMessage, JsonRpcMessageDirection, JsonRpcRequest,
    JsonRpcResponse, MAX_JSONRPC_STRING_ID_ENCODED_BYTES, MAX_RAW_JSON_AGGREGATE_NUMBER_BYTES,
    MAX_RAW_JSON_CONTAINER_ENTRIES, MAX_RAW_JSON_EXPONENT, MAX_RAW_JSON_NESTING_DEPTH,
    MAX_RAW_JSON_NUMBER_BYTES, RawJsonAdmissionError, RawJsonRpcDisposition, RequestId,
    UncorrelatedJsonRpcErrorResponse, admit_raw_jsonrpc_document, decode_strict_jsonrpc_message,
    dispose_raw_jsonrpc_failure,
};
pub use messages::*;
pub use result::*;
pub use schema::{ValidationError, ValidationResult, validate, validate_strict};
pub use server_discovery::{
    DiscoveryCacheHints, MAX_SERVER_INSTRUCTIONS_BYTES, SERVER_DISCOVER_METHOD,
    SERVER_DISCOVER_SUPPORTED_VERSIONS, ServerBehavior, ServerBehaviorRegistry,
    ServerDiscoverCapabilities, ServerDiscoverRequest, ServerDiscoverResult, ServerDiscoveryError,
    ServerInstructionError, ServerInstructions,
};
pub use types::*;

// The FND-03 contract freezes unqualified `cargo test -- --exact` IDs. Keep
// the executable entry points at the crate root while retaining their full
// assertions beside the policy implementation.
#[cfg(test)]
#[test]
fn fnd_03_policy_receipts_positive() {
    protocol_policy::tests::fnd_03_policy_receipts_positive();
}

#[cfg(test)]
#[test]
fn fnd_03_policy_receipts_planted_negative() {
    protocol_policy::tests::fnd_03_policy_receipts_planted_negative();
}

#[cfg(test)]
#[test]
fn fnd_03_era_classification_positive() {
    protocol_policy::tests::fnd_03_era_classification_positive();
}

#[cfg(test)]
#[test]
fn fnd_03_era_classification_planted_negative() {
    protocol_policy::tests::fnd_03_era_classification_planted_negative();
}
