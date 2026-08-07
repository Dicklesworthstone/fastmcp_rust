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

mod jsonrpc;
mod messages;
mod result;
pub mod methods;
pub mod schema;
mod types;

pub use jsonrpc::{
    JSONRPC_VERSION, ClientIngressFailureScope, CorrelationKey, JsonRpcAdmissionError,
    JsonRpcEndpointRole,
    JsonRpcError, JsonRpcMessage, JsonRpcMessageDirection, JsonRpcRequest, JsonRpcResponse,
    RawJsonAdmissionError, RawJsonRpcDisposition, RequestId, UncorrelatedJsonRpcErrorResponse,
    MAX_JSONRPC_STRING_ID_ENCODED_BYTES, MAX_RAW_JSON_AGGREGATE_NUMBER_BYTES,
    MAX_RAW_JSON_CONTAINER_ENTRIES, MAX_RAW_JSON_EXPONENT, MAX_RAW_JSON_NESTING_DEPTH,
    MAX_RAW_JSON_NUMBER_BYTES, admit_raw_jsonrpc_document, decode_strict_jsonrpc_message,
    dispose_raw_jsonrpc_failure,
};
pub use messages::*;
pub use result::*;
pub use schema::{ValidationError, ValidationResult, validate, validate_strict};
pub use types::*;
