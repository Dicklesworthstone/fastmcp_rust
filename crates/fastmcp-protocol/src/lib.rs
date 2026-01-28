//! MCP protocol types and JSON-RPC implementation.
//!
//! This crate provides:
//! - JSON-RPC 2.0 message types
//! - MCP-specific method types (tools, resources, prompts)
//! - Protocol version negotiation
//! - Message serialization/deserialization
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
//! All messages are newline-delimited JSON (NDJSON).

#![forbid(unsafe_code)]
#![allow(dead_code)]

mod jsonrpc;
mod messages;
pub mod schema;
mod types;

pub use jsonrpc::{
    JSONRPC_VERSION, JsonRpcError, JsonRpcMessage, JsonRpcRequest, JsonRpcResponse, RequestId,
};
pub use messages::*;
pub use schema::{ValidationError, ValidationResult, validate, validate_strict};
pub use types::*;
