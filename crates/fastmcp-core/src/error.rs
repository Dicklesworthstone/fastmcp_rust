//! Error types for MCP operations.
//!
//! Defines the standard MCP error codes and error types used throughout
//! the FastMCP framework.

use serde::{Deserialize, Serialize};

/// Standard MCP/JSON-RPC error codes.
///
/// These follow the JSON-RPC 2.0 specification and MCP protocol.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(into = "i32", from = "i32")]
pub enum McpErrorCode {
    /// Invalid JSON was received.
    ParseError,
    /// The JSON sent is not a valid Request object.
    InvalidRequest,
    /// The method does not exist or is not available.
    MethodNotFound,
    /// Invalid method parameters.
    InvalidParams,
    /// Internal JSON-RPC error.
    InternalError,
    /// Tool execution failed.
    ToolExecutionError,
    /// Resource not found.
    ResourceNotFound,
    /// Resource access forbidden.
    ResourceForbidden,
    /// Prompt not found.
    PromptNotFound,
    /// Request was cancelled.
    RequestCancelled,
    /// Custom error code (server-defined).
    Custom(i32),
}

impl From<McpErrorCode> for i32 {
    fn from(code: McpErrorCode) -> Self {
        match code {
            McpErrorCode::ParseError => -32700,
            McpErrorCode::InvalidRequest => -32600,
            McpErrorCode::MethodNotFound => -32601,
            McpErrorCode::InvalidParams => -32602,
            McpErrorCode::InternalError => -32603,
            // MCP-specific codes (use server error range -32000 to -32099)
            McpErrorCode::ToolExecutionError => -32000,
            McpErrorCode::ResourceNotFound => -32001,
            McpErrorCode::ResourceForbidden => -32002,
            McpErrorCode::PromptNotFound => -32003,
            McpErrorCode::RequestCancelled => -32004,
            McpErrorCode::Custom(code) => code,
        }
    }
}

impl From<i32> for McpErrorCode {
    fn from(code: i32) -> Self {
        match code {
            -32700 => McpErrorCode::ParseError,
            -32600 => McpErrorCode::InvalidRequest,
            -32601 => McpErrorCode::MethodNotFound,
            -32602 => McpErrorCode::InvalidParams,
            -32603 => McpErrorCode::InternalError,
            -32000 => McpErrorCode::ToolExecutionError,
            -32001 => McpErrorCode::ResourceNotFound,
            -32002 => McpErrorCode::ResourceForbidden,
            -32003 => McpErrorCode::PromptNotFound,
            -32004 => McpErrorCode::RequestCancelled,
            code => McpErrorCode::Custom(code),
        }
    }
}

/// An MCP error response.
///
/// This maps directly to the JSON-RPC error object and can be serialized
/// for transport.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct McpError {
    /// The error code.
    pub code: McpErrorCode,
    /// A short description of the error.
    pub message: String,
    /// Additional error data (optional).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<serde_json::Value>,
}

impl McpError {
    /// Creates a new MCP error.
    #[must_use]
    pub fn new(code: McpErrorCode, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
            data: None,
        }
    }

    /// Creates a new MCP error with additional data.
    #[must_use]
    pub fn with_data(
        code: McpErrorCode,
        message: impl Into<String>,
        data: serde_json::Value,
    ) -> Self {
        Self {
            code,
            message: message.into(),
            data: Some(data),
        }
    }

    /// Creates a parse error.
    #[must_use]
    pub fn parse_error(message: impl Into<String>) -> Self {
        Self::new(McpErrorCode::ParseError, message)
    }

    /// Creates an invalid request error.
    #[must_use]
    pub fn invalid_request(message: impl Into<String>) -> Self {
        Self::new(McpErrorCode::InvalidRequest, message)
    }

    /// Creates a method not found error.
    #[must_use]
    pub fn method_not_found(method: &str) -> Self {
        Self::new(
            McpErrorCode::MethodNotFound,
            format!("Method not found: {method}"),
        )
    }

    /// Creates an invalid params error.
    #[must_use]
    pub fn invalid_params(message: impl Into<String>) -> Self {
        Self::new(McpErrorCode::InvalidParams, message)
    }

    /// Creates an internal error.
    #[must_use]
    pub fn internal_error(message: impl Into<String>) -> Self {
        Self::new(McpErrorCode::InternalError, message)
    }

    /// Creates a tool execution error.
    #[must_use]
    pub fn tool_error(message: impl Into<String>) -> Self {
        Self::new(McpErrorCode::ToolExecutionError, message)
    }

    /// Creates a resource not found error.
    #[must_use]
    pub fn resource_not_found(uri: &str) -> Self {
        Self::new(
            McpErrorCode::ResourceNotFound,
            format!("Resource not found: {uri}"),
        )
    }

    /// Creates a request cancelled error.
    #[must_use]
    pub fn request_cancelled() -> Self {
        Self::new(McpErrorCode::RequestCancelled, "Request was cancelled")
    }

    /// Returns a masked version of this error for client responses.
    ///
    /// When masking is enabled, internal error details are hidden to prevent
    /// leaking sensitive information (file paths, stack traces, internal state).
    ///
    /// # What gets masked
    ///
    /// - `InternalError`, `ToolExecutionError`, `Custom` codes: message replaced
    ///   with "Internal server error" and data removed
    ///
    /// # What's preserved
    ///
    /// - Error code (for programmatic handling)
    /// - Client errors (`ParseError`, `InvalidRequest`, `MethodNotFound`,
    ///   `InvalidParams`, `ResourceNotFound`, `ResourceForbidden`, `PromptNotFound`,
    ///   `RequestCancelled`): preserved as-is since they don't contain internal details
    ///
    /// # Example
    ///
    /// ```
    /// use fastmcp_core::{McpError, McpErrorCode};
    ///
    /// let internal = McpError::internal_error("Connection failed at /etc/secrets/db.conf");
    /// let masked = internal.masked(true);
    /// assert_eq!(masked.message, "Internal server error");
    /// assert!(masked.data.is_none());
    ///
    /// // Client errors are preserved
    /// let client = McpError::invalid_params("Missing field 'name'");
    /// let masked_client = client.masked(true);
    /// assert!(masked_client.message.contains("name"));
    /// ```
    #[must_use]
    pub fn masked(&self, mask_enabled: bool) -> McpError {
        if !mask_enabled {
            return self.clone();
        }

        match self.code {
            // Client errors are preserved - they don't contain internal details
            McpErrorCode::ParseError
            | McpErrorCode::InvalidRequest
            | McpErrorCode::MethodNotFound
            | McpErrorCode::InvalidParams
            | McpErrorCode::ResourceNotFound
            | McpErrorCode::ResourceForbidden
            | McpErrorCode::PromptNotFound
            | McpErrorCode::RequestCancelled => self.clone(),

            // Internal errors are masked
            McpErrorCode::InternalError
            | McpErrorCode::ToolExecutionError
            | McpErrorCode::Custom(_) => McpError {
                code: self.code,
                message: "Internal server error".to_string(),
                data: None,
            },
        }
    }

    /// Returns whether this error contains internal details that should be masked.
    #[must_use]
    pub fn is_internal(&self) -> bool {
        matches!(
            self.code,
            McpErrorCode::InternalError
                | McpErrorCode::ToolExecutionError
                | McpErrorCode::Custom(_)
        )
    }
}

impl std::fmt::Display for McpError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "[{}] {}", i32::from(self.code), self.message)
    }
}

impl std::error::Error for McpError {}

impl Default for McpError {
    fn default() -> Self {
        Self::internal_error("Unknown error")
    }
}

impl From<crate::CancelledError> for McpError {
    fn from(_: crate::CancelledError) -> Self {
        Self::request_cancelled()
    }
}

impl From<serde_json::Error> for McpError {
    fn from(err: serde_json::Error) -> Self {
        Self::parse_error(err.to_string())
    }
}

/// Result type alias for MCP operations.
pub type McpResult<T> = Result<T, McpError>;

/// Outcome type alias for MCP operations with 4-valued returns.
///
/// This is the preferred return type for handler functions as it properly
/// represents all possible states: success, error, cancellation, and panic.
///
/// # Mapping to JSON-RPC
///
/// | Outcome | JSON-RPC Response |
/// |---------|-------------------|
/// | `Ok(value)` | `{"result": value}` |
/// | `Err(McpError)` | `{"error": {"code": ..., "message": ...}}` |
/// | `Cancelled` | `{"error": {"code": -32004, "message": "Request cancelled"}}` |
/// | `Panicked` | `{"error": {"code": -32603, "message": "Internal error"}}` |
pub type McpOutcome<T> = Outcome<T, McpError>;

// === Outcome Integration ===

use asupersync::Outcome;
use asupersync::types::CancelReason;

/// Extension trait for converting Outcomes to MCP-friendly forms.
pub trait OutcomeExt<T> {
    /// Convert an Outcome to a McpResult, mapping Cancelled to RequestCancelled error.
    fn into_mcp_result(self) -> McpResult<T>;

    /// Map the success value, preserving cancellation and panic states.
    fn map_ok<U>(self, f: impl FnOnce(T) -> U) -> Outcome<U, McpError>;
}

impl<T> OutcomeExt<T> for Outcome<T, McpError> {
    fn into_mcp_result(self) -> McpResult<T> {
        match self {
            Outcome::Ok(v) => Ok(v),
            Outcome::Err(e) => Err(e),
            Outcome::Cancelled(_) => Err(McpError::request_cancelled()),
            Outcome::Panicked(payload) => Err(McpError::internal_error(format!(
                "Internal panic: {}",
                payload.message()
            ))),
        }
    }

    fn map_ok<U>(self, f: impl FnOnce(T) -> U) -> Outcome<U, McpError> {
        match self {
            Outcome::Ok(v) => Outcome::Ok(f(v)),
            Outcome::Err(e) => Outcome::Err(e),
            Outcome::Cancelled(r) => Outcome::Cancelled(r),
            Outcome::Panicked(p) => Outcome::Panicked(p),
        }
    }
}

/// Extension trait for converting Results to Outcomes.
pub trait ResultExt<T, E> {
    /// Convert a Result to an Outcome.
    fn into_outcome(self) -> Outcome<T, E>;
}

impl<T, E> ResultExt<T, E> for Result<T, E> {
    fn into_outcome(self) -> Outcome<T, E> {
        match self {
            Ok(v) => Outcome::Ok(v),
            Err(e) => Outcome::Err(e),
        }
    }
}

impl<T> ResultExt<T, McpError> for Result<T, crate::CancelledError> {
    fn into_outcome(self) -> Outcome<T, McpError> {
        match self {
            Ok(v) => Outcome::Ok(v),
            Err(_) => Outcome::Cancelled(CancelReason::user("request cancelled")),
        }
    }
}

#[must_use]
/// Creates an MCP error Outcome from a cancellation.
pub fn cancelled<T>() -> Outcome<T, McpError> {
    Outcome::Cancelled(CancelReason::user("request cancelled"))
}

#[must_use]
/// Creates an MCP error Outcome with the given error.
pub fn err<T>(error: McpError) -> Outcome<T, McpError> {
    Outcome::Err(error)
}

#[must_use]
/// Creates an MCP success Outcome.
pub fn ok<T>(value: T) -> Outcome<T, McpError> {
    Outcome::Ok(value)
}

#[cfg(test)]
mod tests {
    use super::*;
    use asupersync::types::PanicPayload;

    // ========================================
    // McpErrorCode tests
    // ========================================

    #[test]
    fn test_error_code_serialization() {
        let code = McpErrorCode::MethodNotFound;
        let value: i32 = code.into();
        assert_eq!(value, -32601);
    }

    #[test]
    fn test_all_standard_error_codes() {
        assert_eq!(i32::from(McpErrorCode::ParseError), -32700);
        assert_eq!(i32::from(McpErrorCode::InvalidRequest), -32600);
        assert_eq!(i32::from(McpErrorCode::MethodNotFound), -32601);
        assert_eq!(i32::from(McpErrorCode::InvalidParams), -32602);
        assert_eq!(i32::from(McpErrorCode::InternalError), -32603);
        assert_eq!(i32::from(McpErrorCode::ToolExecutionError), -32000);
        assert_eq!(i32::from(McpErrorCode::ResourceNotFound), -32001);
        assert_eq!(i32::from(McpErrorCode::ResourceForbidden), -32002);
        assert_eq!(i32::from(McpErrorCode::PromptNotFound), -32003);
        assert_eq!(i32::from(McpErrorCode::RequestCancelled), -32004);
    }

    #[test]
    fn test_error_code_roundtrip() {
        let codes = vec![
            McpErrorCode::ParseError,
            McpErrorCode::InvalidRequest,
            McpErrorCode::MethodNotFound,
            McpErrorCode::InvalidParams,
            McpErrorCode::InternalError,
            McpErrorCode::ToolExecutionError,
            McpErrorCode::ResourceNotFound,
            McpErrorCode::ResourceForbidden,
            McpErrorCode::PromptNotFound,
            McpErrorCode::RequestCancelled,
        ];

        for code in codes {
            let value: i32 = code.into();
            let roundtrip: McpErrorCode = value.into();
            assert_eq!(code, roundtrip);
        }
    }

    #[test]
    fn test_custom_error_code() {
        let custom = McpErrorCode::Custom(-99999);
        let value: i32 = custom.into();
        assert_eq!(value, -99999);

        let from_int: McpErrorCode = (-99999).into();
        assert!(matches!(from_int, McpErrorCode::Custom(-99999)));
    }

    // ========================================
    // McpError tests
    // ========================================

    #[test]
    fn test_error_display() {
        let err = McpError::method_not_found("tools/call");
        assert!(err.to_string().contains("-32601"));
        assert!(err.to_string().contains("tools/call"));
    }

    #[test]
    fn test_error_factory_methods() {
        let parse = McpError::parse_error("invalid json");
        assert_eq!(parse.code, McpErrorCode::ParseError);

        let invalid_req = McpError::invalid_request("bad request");
        assert_eq!(invalid_req.code, McpErrorCode::InvalidRequest);

        let method = McpError::method_not_found("foo/bar");
        assert_eq!(method.code, McpErrorCode::MethodNotFound);

        let params = McpError::invalid_params("missing field");
        assert_eq!(params.code, McpErrorCode::InvalidParams);

        let internal = McpError::internal_error("panic");
        assert_eq!(internal.code, McpErrorCode::InternalError);

        let tool = McpError::tool_error("execution failed");
        assert_eq!(tool.code, McpErrorCode::ToolExecutionError);

        let resource = McpError::resource_not_found("file://test");
        assert_eq!(resource.code, McpErrorCode::ResourceNotFound);

        let cancelled = McpError::request_cancelled();
        assert_eq!(cancelled.code, McpErrorCode::RequestCancelled);
    }

    #[test]
    fn test_error_with_data() {
        let data = serde_json::json!({"details": "more info"});
        let err = McpError::with_data(McpErrorCode::InternalError, "error", data.clone());

        assert_eq!(err.code, McpErrorCode::InternalError);
        assert_eq!(err.message, "error");
        assert_eq!(err.data, Some(data));
    }

    #[test]
    fn test_error_default() {
        let err = McpError::default();
        assert_eq!(err.code, McpErrorCode::InternalError);
    }

    #[test]
    fn test_error_from_cancelled() {
        let cancelled_err = crate::CancelledError;
        let mcp_err: McpError = cancelled_err.into();
        assert_eq!(mcp_err.code, McpErrorCode::RequestCancelled);
    }

    #[test]
    fn test_error_serialization() {
        let err = McpError::method_not_found("test");
        let json = serde_json::to_string(&err).unwrap();
        assert!(json.contains("-32601"));
        assert!(json.contains("Method not found: test"));
    }

    // ========================================
    // Outcome extension tests
    // ========================================

    #[test]
    fn test_outcome_into_mcp_result_ok() {
        let outcome: Outcome<i32, McpError> = Outcome::Ok(42);
        let result = outcome.into_mcp_result();
        assert!(matches!(result, Ok(42)));
    }

    #[test]
    fn test_outcome_into_mcp_result_err() {
        let outcome: Outcome<i32, McpError> = Outcome::Err(McpError::internal_error("test"));
        let result = outcome.into_mcp_result();
        assert!(result.is_err());
    }

    #[test]
    fn test_outcome_into_mcp_result_cancelled() {
        let outcome: Outcome<i32, McpError> = Outcome::Cancelled(CancelReason::user("user cancel"));
        let result = outcome.into_mcp_result();
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().code, McpErrorCode::RequestCancelled);
    }

    #[test]
    fn test_outcome_into_mcp_result_panicked() {
        let outcome: Outcome<i32, McpError> = Outcome::Panicked(PanicPayload::new("test panic"));
        let result = outcome.into_mcp_result();
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().code, McpErrorCode::InternalError);
    }

    #[test]
    fn test_outcome_map_ok() {
        let outcome: Outcome<i32, McpError> = Outcome::Ok(21);
        let mapped = outcome.map_ok(|x| x * 2);
        assert!(matches!(mapped, Outcome::Ok(42)));
    }

    #[test]
    fn test_result_ext_into_outcome() {
        let result: Result<i32, McpError> = Ok(42);
        let outcome = result.into_outcome();
        assert!(matches!(outcome, Outcome::Ok(42)));

        let err_result: Result<i32, McpError> = Err(McpError::internal_error("test"));
        let outcome = err_result.into_outcome();
        assert!(matches!(outcome, Outcome::Err(_)));
    }

    // ========================================
    // Helper function tests
    // ========================================

    #[test]
    fn test_helper_ok() {
        let outcome: Outcome<i32, McpError> = ok(42);
        assert!(matches!(outcome, Outcome::Ok(42)));
    }

    #[test]
    fn test_helper_err() {
        let outcome: Outcome<i32, McpError> = err(McpError::internal_error("test"));
        assert!(matches!(outcome, Outcome::Err(_)));
    }

    #[test]
    fn test_helper_cancelled() {
        let outcome: Outcome<i32, McpError> = cancelled();
        assert!(matches!(outcome, Outcome::Cancelled(_)));
    }

    // ========================================
    // Error masking tests
    // ========================================

    #[test]
    fn test_masked_preserves_client_errors() {
        // Client errors should be preserved
        let parse = McpError::parse_error("invalid json");
        let masked = parse.masked(true);
        assert_eq!(masked.message, "invalid json");

        let invalid = McpError::invalid_request("bad request");
        let masked = invalid.masked(true);
        assert!(masked.message.contains("bad request"));

        let method = McpError::method_not_found("unknown");
        let masked = method.masked(true);
        assert!(masked.message.contains("unknown"));

        let params = McpError::invalid_params("missing field");
        let masked = params.masked(true);
        assert!(masked.message.contains("missing field"));

        let resource = McpError::resource_not_found("file://test");
        let masked = resource.masked(true);
        assert!(masked.message.contains("file://test"));

        let cancelled = McpError::request_cancelled();
        let masked = cancelled.masked(true);
        assert!(masked.message.contains("cancelled"));
    }

    #[test]
    fn test_masked_hides_internal_errors() {
        // Internal errors should be masked
        let internal = McpError::internal_error("Connection failed at /etc/secrets/db.conf");
        let masked = internal.masked(true);
        assert_eq!(masked.message, "Internal server error");
        assert!(masked.data.is_none());
        assert_eq!(masked.code, McpErrorCode::InternalError);

        let tool = McpError::tool_error("Failed: /home/user/secret.txt");
        let masked = tool.masked(true);
        assert_eq!(masked.message, "Internal server error");
        assert!(masked.data.is_none());

        let custom = McpError::new(McpErrorCode::Custom(-99999), "Stack trace: ...");
        let masked = custom.masked(true);
        assert_eq!(masked.message, "Internal server error");
    }

    #[test]
    fn test_masked_with_data_removed() {
        let data = serde_json::json!({"internal": "secret", "path": "/etc/passwd"});
        let internal = McpError::with_data(McpErrorCode::InternalError, "Failure", data);

        // With masking enabled
        let masked = internal.masked(true);
        assert_eq!(masked.message, "Internal server error");
        assert!(masked.data.is_none());

        // With masking disabled
        let unmasked = internal.masked(false);
        assert_eq!(unmasked.message, "Failure");
        assert!(unmasked.data.is_some());
    }

    #[test]
    fn test_masked_disabled() {
        // When masking is disabled, all errors should be preserved
        let internal = McpError::internal_error("Full details here");
        let masked = internal.masked(false);
        assert_eq!(masked.message, "Full details here");
    }

    #[test]
    fn test_is_internal() {
        assert!(McpError::internal_error("test").is_internal());
        assert!(McpError::tool_error("test").is_internal());
        assert!(McpError::new(McpErrorCode::Custom(-99999), "test").is_internal());

        assert!(!McpError::parse_error("test").is_internal());
        assert!(!McpError::invalid_request("test").is_internal());
        assert!(!McpError::method_not_found("test").is_internal());
        assert!(!McpError::invalid_params("test").is_internal());
        assert!(!McpError::resource_not_found("test").is_internal());
        assert!(!McpError::request_cancelled().is_internal());
        assert!(!McpError::new(McpErrorCode::ResourceForbidden, "forbidden").is_internal());
        assert!(!McpError::new(McpErrorCode::PromptNotFound, "not found").is_internal());
    }

    // =========================================================================
    // Additional coverage tests (bd-2qlj)
    // =========================================================================

    #[test]
    fn from_serde_json_error() {
        // Trigger a real serde_json::Error via invalid JSON parse
        let serde_err: serde_json::Error =
            serde_json::from_str::<serde_json::Value>("{{bad json").unwrap_err();
        let mcp_err: McpError = serde_err.into();
        assert_eq!(mcp_err.code, McpErrorCode::ParseError);
        assert!(!mcp_err.message.is_empty());
    }

    #[test]
    fn map_ok_err_variant() {
        let outcome: Outcome<i32, McpError> = Outcome::Err(McpError::internal_error("oops"));
        let mapped = outcome.map_ok(|x| x * 2);
        match mapped {
            Outcome::Err(e) => assert_eq!(e.code, McpErrorCode::InternalError),
            other => panic!("expected Err, got {other:?}"),
        }
    }

    #[test]
    fn map_ok_cancelled_variant() {
        let outcome: Outcome<i32, McpError> = Outcome::Cancelled(CancelReason::user("test cancel"));
        let mapped = outcome.map_ok(|x| x * 2);
        assert!(matches!(mapped, Outcome::Cancelled(_)));
    }

    #[test]
    fn map_ok_panicked_variant() {
        let outcome: Outcome<i32, McpError> = Outcome::Panicked(PanicPayload::new("boom"));
        let mapped = outcome.map_ok(|x| x * 2);
        assert!(matches!(mapped, Outcome::Panicked(_)));
    }

    #[test]
    fn result_ext_cancelled_error_ok() {
        let result: Result<i32, crate::CancelledError> = Ok(42);
        let outcome: Outcome<i32, McpError> = result.into_outcome();
        assert!(matches!(outcome, Outcome::Ok(42)));
    }

    #[test]
    fn result_ext_cancelled_error_err() {
        let result: Result<i32, crate::CancelledError> = Err(crate::CancelledError);
        let outcome: Outcome<i32, McpError> = result.into_outcome();
        assert!(matches!(outcome, Outcome::Cancelled(_)));
    }

    #[test]
    fn error_code_json_serde_roundtrip() {
        let codes = [
            McpErrorCode::ParseError,
            McpErrorCode::InvalidRequest,
            McpErrorCode::MethodNotFound,
            McpErrorCode::InvalidParams,
            McpErrorCode::InternalError,
            McpErrorCode::ToolExecutionError,
            McpErrorCode::ResourceNotFound,
            McpErrorCode::ResourceForbidden,
            McpErrorCode::PromptNotFound,
            McpErrorCode::RequestCancelled,
            McpErrorCode::Custom(-12345),
        ];
        for code in codes {
            let json = serde_json::to_string(&code).unwrap();
            let deserialized: McpErrorCode = serde_json::from_str(&json).unwrap();
            assert_eq!(code, deserialized, "roundtrip failed for {code:?}");
        }
    }

    #[test]
    fn mcp_error_json_deserialization() {
        let json = r#"{"code":-32601,"message":"Method not found: test","data":{"key":"val"}}"#;
        let err: McpError = serde_json::from_str(json).unwrap();
        assert_eq!(err.code, McpErrorCode::MethodNotFound);
        assert!(err.message.contains("test"));
        assert!(err.data.is_some());
        assert_eq!(err.data.unwrap()["key"], "val");
    }

    #[test]
    fn mcp_error_json_deserialization_no_data() {
        let json = r#"{"code":-32603,"message":"Internal error"}"#;
        let err: McpError = serde_json::from_str(json).unwrap();
        assert_eq!(err.code, McpErrorCode::InternalError);
        assert!(err.data.is_none());
    }

    #[test]
    fn masked_preserves_resource_forbidden() {
        let err = McpError::new(McpErrorCode::ResourceForbidden, "access denied");
        let masked = err.masked(true);
        assert_eq!(masked.message, "access denied");
        assert_eq!(masked.code, McpErrorCode::ResourceForbidden);
    }

    #[test]
    fn masked_preserves_prompt_not_found() {
        let err = McpError::new(McpErrorCode::PromptNotFound, "no such prompt");
        let masked = err.masked(true);
        assert_eq!(masked.message, "no such prompt");
        assert_eq!(masked.code, McpErrorCode::PromptNotFound);
    }

    #[test]
    fn mcp_error_is_std_error() {
        let err = McpError::internal_error("test");
        let _: &dyn std::error::Error = &err;
    }

    #[test]
    fn mcp_error_debug_and_clone() {
        let err = McpError::with_data(
            McpErrorCode::ToolExecutionError,
            "fail",
            serde_json::json!({"x": 1}),
        );
        let debug = format!("{err:?}");
        assert!(debug.contains("McpError"));
        assert!(debug.contains("fail"));
        let cloned = err.clone();
        assert_eq!(cloned.code, err.code);
        assert_eq!(cloned.message, err.message);
        assert_eq!(cloned.data, err.data);
    }

    #[test]
    fn error_code_debug_clone_copy() {
        let code = McpErrorCode::ResourceForbidden;
        let debug = format!("{code:?}");
        assert!(debug.contains("ResourceForbidden"));
        let cloned = code;
        assert_eq!(code, cloned);
    }
}
