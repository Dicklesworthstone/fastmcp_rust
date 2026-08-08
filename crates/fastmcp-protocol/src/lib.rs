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
pub mod tasks_extension;
mod types;

pub use extensions::{
    ClientExtensionDiscovery, ExtensionDescriptor, ExtensionDescriptorRegistry, ExtensionDirection,
    ExtensionDiscovery, ExtensionFallbackPolicy, ExtensionHttpEraDisposition, ExtensionId,
    ExtensionMethodDescriptor, ExtensionNegotiationResolver, ExtensionNotificationDescriptor,
    ExtensionRegistryError, ExtensionRegistryReceipt, ExtensionRoutingHeaderDescriptor,
    ExtensionSettings, ExtensionSettingsSchema, MAX_EXTENSION_DESCRIPTORS, MAX_EXTENSION_ID_BYTES,
    MAX_EXTENSION_REGISTRY_CANONICAL_BYTES, ServerExtensionDiscovery, StdioCorrelationDescriptor,
};
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
pub use methods::SERVER_DISCOVER;
pub use protocol_version::{
    FINAL_PROTOCOL_VERSION, FinalHttpRequestMetadata, FinalProtocolVersion, FinalRequestAdmission,
    HEADER_MISMATCH_ERROR_CODE, HeaderMismatchError, HeaderMismatchReason,
    MAX_REQUIRED_CAPABILITIES_ERROR_DATA_BYTES, MCP_METHOD_HEADER, MCP_NAME_HEADER,
    MCP_PROTOCOL_VERSION_HEADER, MISSING_REQUIRED_CLIENT_CAPABILITY_ERROR_CODE,
    MissingRequiredClientCapabilityError, ProtocolVersionError, RequestAdmissionError,
    RequestVersionMetadata, RequiredCapabilitiesError, SUPPORTED_FINAL_PROTOCOL_VERSIONS,
    UNSUPPORTED_PROTOCOL_VERSION_ERROR_CODE, UnsupportedProtocolVersionError,
    admit_final_http_request, admit_final_request, validate_final_protocol_version,
};
pub use result::*;
pub use schema::{ValidationError, ValidationResult, validate, validate_strict};
pub use server_discovery::{
    DiscoveryCacheHints, MAX_SERVER_INSTRUCTIONS_BYTES, SERVER_DISCOVER_METHOD,
    SERVER_DISCOVER_SUPPORTED_VERSIONS, ServerBehavior, ServerBehaviorRegistry,
    ServerDiscoverCapabilities, ServerDiscoverRequest, ServerDiscoverResult, ServerDiscoveryError,
    ServerInstructionError, ServerInstructions,
};
pub use tasks_extension::{
    CancelTaskParams as FinalCancelTaskParams, CancelTaskResult as FinalCancelTaskResult,
    CompleteTaskResult, CreateTaskResult, EmptyTaskResult, FinalTaskCallToolResult, FinalTaskError,
    GetTaskParams as FinalGetTaskParams, GetTaskResult as FinalGetTaskResult, MAX_TASK_ID_BYTES,
    MAX_TASK_INPUT_MAP_ENTRIES, MAX_TASK_SUBSCRIPTION_IDS, RELATED_TASK_META_KEY, TASK_CANCEL,
    TASK_GET, TASK_STATUS_NOTIFICATION, TASK_SUBSCRIPTION_IDS_KEY, TASKS_EXTENSION, Task, TaskBase,
    TaskDuration, TaskId as FinalTaskId, TaskInputLedger, TaskInputRequests, TaskInputResponses,
    TaskMethodRequest, TaskRequestMeta, TaskStatus as FinalTaskStatus, TaskStatusNotification,
    TaskStatusNotificationParams as FinalTaskStatusNotificationParams, TaskTimestamp,
    TaskWireError, UpdateTaskParams, UpdateTaskResult, set_task_subscription_ids,
    task_subscription_ids,
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

#[cfg(test)]
#[test]
fn prt_03_i_positive() {
    let required_capabilities = ClientCapabilities {
        roots: Some(RootsCapability { list_changed: true }),
        ..ClientCapabilities::default()
    };
    let metadata = FinalRequestMeta::new(required_capabilities.clone());
    let admission = admit_final_http_request(FinalHttpRequestMetadata {
        version: metadata.version_metadata(Some(FINAL_PROTOCOL_VERSION)),
        header_method: Some(SERVER_DISCOVER),
        body_method: Some(SERVER_DISCOVER),
        header_name: None,
        body_name: None,
    })
    .expect("canonical final metadata and server discovery must be admitted");
    let missing =
        MissingRequiredClientCapabilityError::from_client_capabilities(&required_capabilities)
            .expect("typed required capabilities must encode as final error data");

    assert_eq!(FINAL_PROTOCOL_VERSION, "2026-07-28");
    assert_eq!(SERVER_DISCOVER, SERVER_DISCOVER_METHOD);
    assert_eq!(MCP_PROTOCOL_VERSION_HEADER, "MCP-Protocol-Version");
    assert_eq!(MCP_METHOD_HEADER, "Mcp-Method");
    assert_eq!(MCP_NAME_HEADER, "Mcp-Name");
    assert_eq!(
        admission.protocol_version().as_str(),
        FINAL_PROTOCOL_VERSION
    );
    assert_eq!(missing.http_status(), 400);
    assert_eq!(
        missing.jsonrpc_error_code(),
        MISSING_REQUIRED_CLIENT_CAPABILITY_ERROR_CODE
    );
    assert_eq!(
        missing.canonical_error_data(),
        serde_json::json!({"requiredCapabilities": {"roots": {"listChanged": true}}})
    );
}

#[cfg(test)]
#[test]
fn prt_03_i_planted_negative() {
    let metadata = FinalRequestMeta::new(ClientCapabilities {
        roots: Some(RootsCapability { list_changed: true }),
        ..ClientCapabilities::default()
    });
    let wire_before = serde_json::to_value(&metadata).expect("metadata serializes");
    let error = admit_final_http_request(FinalHttpRequestMetadata {
        version: metadata.version_metadata(Some("2025-11-25")),
        header_method: Some(SERVER_DISCOVER),
        body_method: Some(SERVER_DISCOVER),
        header_name: None,
        body_name: None,
    })
    .expect_err("changing only the protocol header must reject the request");

    assert!(
        matches!(&error, RequestAdmissionError::HeaderMismatch(_)),
        "a mismatched version mirror must precede unsupported-version classification"
    );
    let RequestAdmissionError::HeaderMismatch(error) = error else {
        return;
    };
    assert_eq!(
        error.reason(),
        HeaderMismatchReason::HeaderBodyVersionMismatch
    );
    assert_eq!(error.http_status(), 400);
    assert_eq!(error.jsonrpc_error_code(), HEADER_MISMATCH_ERROR_CODE);
    assert_eq!(error.canonical_error_data(), None);
    assert_eq!(
        serde_json::to_value(&metadata).expect("metadata remains serializable"),
        wire_before
    );
}
