//! JSON-RPC 2.0 message types.

use std::borrow::Cow;

use serde::de::{Error as _, Visitor};
use serde::ser::Error as _;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use serde_json::Value;

/// The JSON-RPC version string. Used as a static reference to avoid allocations.
pub const JSONRPC_VERSION: &str = "2.0";

/// Maximum encoded bytes in one JSON-RPC string ID, including quotes.
pub const MAX_JSONRPC_STRING_ID_ENCODED_BYTES: usize = 256;

/// Serializes the jsonrpc version field.
fn serialize_jsonrpc_version<S>(value: &str, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    if value == JSONRPC_VERSION {
        serializer.serialize_str(JSONRPC_VERSION)
    } else {
        Err(S::Error::custom("jsonrpc must be exactly \"2.0\""))
    }
}

/// Deserializes the required JSON-RPC version, rejecting every value but
/// exactly `"2.0"`.
fn deserialize_jsonrpc_version<'de, D>(deserializer: D) -> Result<Cow<'static, str>, D::Error>
where
    D: Deserializer<'de>,
{
    let s: Cow<'de, str> = Cow::deserialize(deserializer)?;
    if s == JSONRPC_VERSION {
        Ok(Cow::Borrowed(JSONRPC_VERSION))
    } else {
        Err(D::Error::custom("jsonrpc must be exactly \"2.0\""))
    }
}

/// JSON-RPC request ID.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum RequestId {
    /// Integer ID.
    Number(i64),
    /// String ID.
    String(String),
}

impl RequestId {
    /// Verifies that this ID can be represented within the JSON-RPC wire
    /// limits enforced by this crate.
    ///
    /// # Errors
    ///
    /// Returns an error for a string ID whose canonical JSON encoding exceeds
    /// [`MAX_JSONRPC_STRING_ID_ENCODED_BYTES`]. Raw decoders must additionally
    /// enforce the byte length of the received token before escape decoding.
    pub fn validate(&self) -> Result<(), &'static str> {
        if let Self::String(value) = self
            && encoded_json_string_len(value) > MAX_JSONRPC_STRING_ID_ENCODED_BYTES
        {
            return Err("JSON-RPC string id exceeds byte limit");
        }
        Ok(())
    }
}

impl Serialize for RequestId {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        self.validate().map_err(S::Error::custom)?;
        match self {
            Self::Number(number) => serializer.serialize_i64(*number),
            Self::String(value) => serializer.serialize_str(value),
        }
    }
}

impl<'de> Deserialize<'de> for RequestId {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct RequestIdVisitor;

        impl Visitor<'_> for RequestIdVisitor {
            type Value = RequestId;

            fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                formatter.write_str("a bounded JSON-RPC string id or signed 64-bit integer id")
            }

            fn visit_i64<E>(self, value: i64) -> Result<Self::Value, E> {
                Ok(RequestId::Number(value))
            }

            fn visit_u64<E>(self, value: u64) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                i64::try_from(value)
                    .map(RequestId::Number)
                    .map_err(|_| E::custom("JSON-RPC integer id exceeds signed 64-bit range"))
            }

            fn visit_borrowed_str<E>(self, value: &'_ str) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                self.visit_str(value)
            }

            fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                if encoded_json_string_len(value) > MAX_JSONRPC_STRING_ID_ENCODED_BYTES {
                    return Err(E::custom("JSON-RPC string id exceeds byte limit"));
                }
                Ok(RequestId::String(value.to_owned()))
            }

            fn visit_string<E>(self, value: String) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                if encoded_json_string_len(&value) > MAX_JSONRPC_STRING_ID_ENCODED_BYTES {
                    return Err(E::custom("JSON-RPC string id exceeds byte limit"));
                }
                Ok(RequestId::String(value))
            }
        }

        deserializer.deserialize_any(RequestIdVisitor)
    }
}

fn encoded_json_string_len(value: &str) -> usize {
    value.chars().fold(2_usize, |length, character| {
        let encoded = match character {
            '"' | '\\' | '\u{0008}' | '\u{000c}' | '\n' | '\r' | '\t' => 2,
            '\u{0000}'..='\u{001f}' => 6,
            _ => character.len_utf8(),
        };
        length.saturating_add(encoded)
    })
}

fn deserialize_request_id<'de, D>(deserializer: D) -> Result<Option<RequestId>, D::Error>
where
    D: Deserializer<'de>,
{
    RequestId::deserialize(deserializer).map(Some)
}

impl From<i64> for RequestId {
    fn from(id: i64) -> Self {
        RequestId::Number(id)
    }
}

impl From<String> for RequestId {
    fn from(id: String) -> Self {
        RequestId::String(id)
    }
}

impl From<&str> for RequestId {
    fn from(id: &str) -> Self {
        RequestId::String(id.to_owned())
    }
}

impl std::fmt::Display for RequestId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RequestId::Number(n) => write!(f, "{n}"),
            RequestId::String(s) => write!(f, "{s}"),
        }
    }
}

/// JSON-RPC 2.0 request.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct JsonRpcRequest {
    /// Protocol version (always "2.0").
    #[serde(
        serialize_with = "serialize_jsonrpc_version",
        deserialize_with = "deserialize_jsonrpc_version"
    )]
    pub jsonrpc: Cow<'static, str>,
    /// Method name.
    pub method: String,
    /// Request parameters.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub params: Option<Value>,
    /// Request ID (absent for notifications).
    ///
    /// An explicit JSON `null` is rejected instead of being conflated with an
    /// absent member. Notifications omit `id` entirely.
    #[serde(
        default,
        deserialize_with = "deserialize_request_id",
        skip_serializing_if = "Option::is_none"
    )]
    pub id: Option<RequestId>,
}

impl JsonRpcRequest {
    /// Creates a new request with the given method and parameters.
    #[must_use]
    pub fn new(method: impl Into<String>, params: Option<Value>, id: impl Into<RequestId>) -> Self {
        Self {
            jsonrpc: Cow::Borrowed(JSONRPC_VERSION),
            method: method.into(),
            params,
            id: Some(id.into()),
        }
    }

    /// Creates a notification (request without ID).
    #[must_use]
    pub fn notification(method: impl Into<String>, params: Option<Value>) -> Self {
        Self {
            jsonrpc: Cow::Borrowed(JSONRPC_VERSION),
            method: method.into(),
            params,
            id: None,
        }
    }

    /// Creates the MCP lifecycle `notifications/initialized` notification.
    ///
    /// Uses the spec-correct method name (`notifications/initialized`), avoiding
    /// the bare `initialized` spelling that compliant servers do not route as the
    /// lifecycle ack.
    #[must_use]
    pub fn initialized_notification() -> Self {
        Self::notification(crate::methods::NOTIFICATIONS_INITIALIZED, None)
    }

    /// Returns true if this is a notification (no ID).
    #[must_use]
    pub fn is_notification(&self) -> bool {
        self.id.is_none()
    }

    /// Verifies invariants that can otherwise be bypassed by constructing or
    /// mutating this public protocol type directly.
    ///
    /// # Errors
    ///
    /// Returns an error for a non-standard protocol version or invalid ID.
    pub fn validate(&self) -> Result<(), &'static str> {
        if self.jsonrpc != JSONRPC_VERSION {
            return Err("jsonrpc must be exactly \"2.0\"");
        }
        if let Some(id) = &self.id {
            id.validate()?;
        }
        Ok(())
    }
}

/// JSON-RPC 2.0 error object.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JsonRpcError {
    /// Error code.
    pub code: i32,
    /// Error message.
    pub message: String,
    /// Additional error data.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<Value>,
}

impl From<fastmcp_core::McpError> for JsonRpcError {
    fn from(err: fastmcp_core::McpError) -> Self {
        Self {
            code: err.code.into(),
            message: err.message,
            data: err.data,
        }
    }
}

fn deserialize_response_result<'de, D>(deserializer: D) -> Result<Option<Value>, D::Error>
where
    D: Deserializer<'de>,
{
    Value::deserialize(deserializer).map(Some)
}

fn deserialize_response_error<'de, D>(deserializer: D) -> Result<Option<JsonRpcError>, D::Error>
where
    D: Deserializer<'de>,
{
    JsonRpcError::deserialize(deserializer).map(Some)
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct JsonRpcResponseWire {
    /// Protocol version (always "2.0").
    #[serde(
        serialize_with = "serialize_jsonrpc_version",
        deserialize_with = "deserialize_jsonrpc_version"
    )]
    jsonrpc: Cow<'static, str>,
    #[serde(
        default,
        deserialize_with = "deserialize_response_result",
        skip_serializing_if = "Option::is_none"
    )]
    result: Option<Value>,
    #[serde(
        default,
        deserialize_with = "deserialize_response_error",
        skip_serializing_if = "Option::is_none"
    )]
    error: Option<JsonRpcError>,
    #[serde(
        default,
        deserialize_with = "deserialize_request_id",
        skip_serializing_if = "Option::is_none"
    )]
    id: Option<RequestId>,
}

/// JSON-RPC 2.0 response.
#[derive(Debug, Clone)]
pub struct JsonRpcResponse {
    /// Protocol version (always "2.0").
    pub jsonrpc: Cow<'static, str>,
    /// Result (present on success, including an explicit JSON `null`).
    pub result: Option<Value>,
    /// Error (present on failure).
    pub error: Option<JsonRpcError>,
    /// Request ID this is responding to.
    pub id: Option<RequestId>,
}

impl Serialize for JsonRpcResponse {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        self.validate().map_err(S::Error::custom)?;

        JsonRpcResponseWire {
            jsonrpc: self.jsonrpc.clone(),
            result: self.result.clone(),
            error: self.error.clone(),
            id: self.id.clone(),
        }
        .serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for JsonRpcResponse {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let wire = JsonRpcResponseWire::deserialize(deserializer)?;
        let response = Self {
            jsonrpc: wire.jsonrpc,
            result: wire.result,
            error: wire.error,
            id: wire.id,
        };
        response.validate().map_err(D::Error::custom)?;
        Ok(response)
    }
}

impl JsonRpcResponse {
    /// Creates a success response.
    #[must_use]
    pub fn success(id: RequestId, result: Value) -> Self {
        Self {
            jsonrpc: Cow::Borrowed(JSONRPC_VERSION),
            result: Some(result),
            error: None,
            id: Some(id),
        }
    }

    /// Creates an error response.
    #[must_use]
    pub fn error(id: Option<RequestId>, error: JsonRpcError) -> Self {
        Self {
            jsonrpc: Cow::Borrowed(JSONRPC_VERSION),
            result: None,
            error: Some(error),
            id,
        }
    }

    /// Returns true if this is an error response.
    #[must_use]
    pub fn is_error(&self) -> bool {
        self.error.is_some()
    }

    /// Verifies invariants that can otherwise be bypassed by constructing or
    /// mutating this public protocol type directly.
    ///
    /// # Errors
    ///
    /// Returns an error unless the protocol version is exact, exactly one
    /// outcome member is present, every ID is valid, and success is correlated
    /// to a request ID.
    pub fn validate(&self) -> Result<(), &'static str> {
        if self.jsonrpc != JSONRPC_VERSION {
            return Err("jsonrpc must be exactly \"2.0\"");
        }
        if self.result.is_some() == self.error.is_some() {
            return Err("JSON-RPC response must contain exactly one of result or error");
        }
        if self.result.is_some() && self.id.is_none() {
            return Err("JSON-RPC success response must contain an id");
        }
        if let Some(id) = &self.id {
            id.validate()?;
        }
        Ok(())
    }
}

/// A JSON-RPC message (request, response, or notification).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum JsonRpcMessage {
    /// A request or notification.
    Request(JsonRpcRequest),
    /// A response.
    Response(JsonRpcResponse),
}

impl JsonRpcMessage {
    /// Verifies the contained request or response invariants.
    ///
    /// Typed transports that do not serialize through [`serde_json`] should
    /// call this before accepting a message.
    ///
    /// # Errors
    ///
    /// Returns the first violated request or response invariant.
    pub fn validate(&self) -> Result<(), &'static str> {
        match self {
            Self::Request(request) => request.validate(),
            Self::Response(response) => response.validate(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    // ========================================================================
    // RequestId Tests
    // ========================================================================

    #[test]
    fn request_id_number_serialization() {
        let id = RequestId::Number(42);
        let value = serde_json::to_value(&id).expect("serialize");
        assert_eq!(value, 42);
    }

    #[test]
    fn request_id_string_serialization() {
        let id = RequestId::String("req-1".to_string());
        let value = serde_json::to_value(&id).expect("serialize");
        assert_eq!(value, "req-1");
    }

    #[test]
    fn request_id_number_deserialization() {
        let id: RequestId = serde_json::from_value(json!(99)).expect("deserialize");
        assert_eq!(id, RequestId::Number(99));
    }

    #[test]
    fn request_id_string_deserialization() {
        let id: RequestId = serde_json::from_value(json!("abc")).expect("deserialize");
        assert_eq!(id, RequestId::String("abc".to_string()));
    }

    #[test]
    fn request_id_string_enforces_encoded_byte_limit() {
        let exact = "a".repeat(MAX_JSONRPC_STRING_ID_ENCODED_BYTES - 2);
        let too_long = "a".repeat(MAX_JSONRPC_STRING_ID_ENCODED_BYTES - 1);
        let exact_json = format!("\"{exact}\"");
        let too_long_json = format!("\"{too_long}\"");

        assert!(serde_json::from_str::<RequestId>(&exact_json).is_ok());
        assert!(serde_json::from_str::<RequestId>(&too_long_json).is_err());
        assert!(serde_json::to_string(&RequestId::String(exact)).is_ok());
        assert!(serde_json::to_string(&RequestId::String(too_long)).is_err());

        let escaped_exact = format!("\"{}\"", "\\u0001".repeat(42));
        let escaped_too_long = format!("\"{}\"", "\\u0001".repeat(43));
        assert_eq!(escaped_exact.len(), 254);
        assert!(serde_json::from_str::<RequestId>(&escaped_exact).is_ok());
        assert!(serde_json::from_str::<RequestId>(&escaped_too_long).is_err());
    }

    #[test]
    fn request_id_validation_catches_direct_construction_bypass() {
        let too_long = RequestId::String("a".repeat(MAX_JSONRPC_STRING_ID_ENCODED_BYTES));

        assert_eq!(
            too_long.validate(),
            Err("JSON-RPC string id exceeds byte limit")
        );
    }

    #[test]
    fn request_rejects_explicit_null_id_but_accepts_absent_id() {
        let error = serde_json::from_str::<JsonRpcRequest>(
            r#"{"jsonrpc":"2.0","method":"notifications/initialized","id":null}"#,
        )
        .expect_err("an explicit null id must not become a notification");
        assert!(error.to_string().contains("invalid type"));

        let notification = serde_json::from_str::<JsonRpcRequest>(
            r#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#,
        )
        .expect("an absent id denotes a notification");
        assert!(notification.is_notification());
    }

    #[test]
    fn request_id_from_i64() {
        let id: RequestId = 7i64.into();
        assert_eq!(id, RequestId::Number(7));
    }

    #[test]
    fn request_id_from_string() {
        let id: RequestId = "test-id".to_string().into();
        assert_eq!(id, RequestId::String("test-id".to_string()));
    }

    #[test]
    fn request_id_from_str() {
        let id: RequestId = "test-id".into();
        assert_eq!(id, RequestId::String("test-id".to_string()));
    }

    #[test]
    fn request_id_display() {
        assert_eq!(format!("{}", RequestId::Number(42)), "42");
        assert_eq!(
            format!("{}", RequestId::String("req-1".to_string())),
            "req-1"
        );
    }

    #[test]
    fn request_id_equality() {
        assert_eq!(RequestId::Number(1), RequestId::Number(1));
        assert_ne!(RequestId::Number(1), RequestId::Number(2));
        assert_eq!(
            RequestId::String("a".to_string()),
            RequestId::String("a".to_string())
        );
        assert_ne!(RequestId::Number(1), RequestId::String("1".to_string()));
    }

    // ========================================================================
    // JsonRpcRequest Tests
    // ========================================================================

    #[test]
    fn jsonrpc_version_deserialize_borrows_static_for_request() {
        let req: JsonRpcRequest =
            serde_json::from_str(r#"{"jsonrpc":"2.0","method":"tools/list","id":1}"#)
                .expect("deserialize");
        assert!(matches!(req.jsonrpc, Cow::Borrowed(JSONRPC_VERSION)));
    }

    #[test]
    fn request_rejects_nonstandard_missing_and_non_string_jsonrpc_versions() {
        for input in [
            r#"{"jsonrpc":"2.1","method":"tools/list","id":1}"#,
            r#"{"jsonrpc":"1.0","method":"tools/list","id":1}"#,
            r#"{"jsonrpc":null,"method":"tools/list","id":1}"#,
            r#"{"method":"tools/list","id":1}"#,
        ] {
            let error = serde_json::from_str::<JsonRpcRequest>(input).unwrap_err();
            assert!(error.is_data(), "unexpected error for {input}: {error}");
        }
    }

    #[test]
    fn request_serialization() {
        let req = JsonRpcRequest::new("tools/list", None, 1i64);
        let json = serde_json::to_string(&req).unwrap();
        assert!(json.contains("\"jsonrpc\":\"2.0\""));
        assert!(json.contains("\"method\":\"tools/list\""));
        assert!(json.contains("\"id\":1"));
    }

    #[test]
    fn request_with_params() {
        let params = json!({"name": "greet", "arguments": {"name": "World"}});
        let req = JsonRpcRequest::new("tools/call", Some(params.clone()), 2i64);
        let value = serde_json::to_value(&req).expect("serialize");
        assert_eq!(value["jsonrpc"], "2.0");
        assert_eq!(value["method"], "tools/call");
        assert_eq!(value["params"]["name"], "greet");
        assert_eq!(value["id"], 2);
    }

    #[test]
    fn request_without_params_omits_field() {
        let req = JsonRpcRequest::new("tools/list", None, 1i64);
        let value = serde_json::to_value(&req).expect("serialize");
        assert!(value.get("params").is_none());
    }

    #[test]
    fn notification_has_no_id() {
        let notif = JsonRpcRequest::notification("notifications/progress", None);
        assert!(notif.is_notification());
        assert!(notif.id.is_none());
        let value = serde_json::to_value(&notif).expect("serialize");
        assert!(value.get("id").is_none());
    }

    #[test]
    fn notification_with_params() {
        let params = json!({"uri": "file://changed.txt"});
        let notif = JsonRpcRequest::notification("notifications/resources/updated", Some(params));
        assert!(notif.is_notification());
        let value = serde_json::to_value(&notif).expect("serialize");
        assert_eq!(value["params"]["uri"], "file://changed.txt");
    }

    #[test]
    fn request_is_not_notification() {
        let req = JsonRpcRequest::new("tools/list", None, 1i64);
        assert!(!req.is_notification());
    }

    #[test]
    fn request_with_string_id() {
        let req = JsonRpcRequest::new("tools/list", None, "req-abc");
        let value = serde_json::to_value(&req).expect("serialize");
        assert_eq!(value["id"], "req-abc");
    }

    #[test]
    fn request_round_trip() {
        let original = JsonRpcRequest::new(
            "tools/call",
            Some(json!({"name": "add", "arguments": {"a": 1, "b": 2}})),
            42i64,
        );
        let json_str = serde_json::to_string(&original).expect("serialize");
        let deserialized: JsonRpcRequest = serde_json::from_str(&json_str).expect("deserialize");
        assert_eq!(deserialized.method, "tools/call");
        assert_eq!(deserialized.id, Some(RequestId::Number(42)));
        assert!(deserialized.params.is_some());
    }

    #[test]
    fn request_rejects_unknown_top_level_envelope_members() {
        let error = serde_json::from_str::<JsonRpcRequest>(
            r#"{"jsonrpc":"2.0","method":"tools/list","id":1,"extension":true}"#,
        )
        .expect_err("request envelopes are closed");

        assert!(error.to_string().contains("unknown field"));
    }

    // ========================================================================
    // JsonRpcError Tests
    // ========================================================================

    #[test]
    fn jsonrpc_error_from_mcp_error_preserves_code_message_and_data() {
        let err = fastmcp_core::McpError::with_data(
            fastmcp_core::McpErrorCode::InvalidParams,
            "bad params",
            json!({"field":"name"}),
        );
        let rpc_err: JsonRpcError = err.into();
        assert_eq!(rpc_err.code, -32602);
        assert_eq!(rpc_err.message, "bad params");
        assert_eq!(rpc_err.data, Some(json!({"field":"name"})));
    }

    #[test]
    fn jsonrpc_error_serialization() {
        let error = JsonRpcError {
            code: -32600,
            message: "Invalid Request".to_string(),
            data: None,
        };
        let value = serde_json::to_value(&error).expect("serialize");
        assert_eq!(value["code"], -32600);
        assert_eq!(value["message"], "Invalid Request");
        assert!(value.get("data").is_none());
    }

    #[test]
    fn jsonrpc_error_with_data() {
        let error = JsonRpcError {
            code: -32602,
            message: "Invalid params".to_string(),
            data: Some(json!({"field": "name", "reason": "required"})),
        };
        let value = serde_json::to_value(&error).expect("serialize");
        assert_eq!(value["code"], -32602);
        assert_eq!(value["data"]["field"], "name");
    }

    #[test]
    fn jsonrpc_error_standard_codes() {
        // Parse error
        let err = JsonRpcError {
            code: -32700,
            message: "Parse error".to_string(),
            data: None,
        };
        assert_eq!(serde_json::to_value(&err).unwrap()["code"], -32700);

        // Method not found
        let err = JsonRpcError {
            code: -32601,
            message: "Method not found".to_string(),
            data: None,
        };
        assert_eq!(serde_json::to_value(&err).unwrap()["code"], -32601);

        // Internal error
        let err = JsonRpcError {
            code: -32603,
            message: "Internal error".to_string(),
            data: None,
        };
        assert_eq!(serde_json::to_value(&err).unwrap()["code"], -32603);
    }

    // ========================================================================
    // JsonRpcResponse Tests
    // ========================================================================

    #[test]
    fn jsonrpc_version_deserialize_borrows_static_for_response() {
        let resp: JsonRpcResponse =
            serde_json::from_str(r#"{"jsonrpc":"2.0","result":{"tools":[]},"id":1}"#)
                .expect("deserialize");
        assert!(matches!(resp.jsonrpc, Cow::Borrowed(JSONRPC_VERSION)));
    }

    #[test]
    fn response_rejects_nonstandard_missing_and_non_string_jsonrpc_versions() {
        for input in [
            r#"{"jsonrpc":"2.1","result":{"tools":[]},"id":1}"#,
            r#"{"jsonrpc":"1.0","result":{"tools":[]},"id":1}"#,
            r#"{"jsonrpc":null,"result":{"tools":[]},"id":1}"#,
            r#"{"result":{"tools":[]},"id":1}"#,
        ] {
            let error = serde_json::from_str::<JsonRpcResponse>(input).unwrap_err();
            assert!(error.is_data(), "unexpected error for {input}: {error}");
        }
    }

    #[test]
    fn serialization_rejects_mutated_nonstandard_jsonrpc_version() {
        let mut request = JsonRpcRequest::new("tools/list", None, 1_i64);
        request.jsonrpc = Cow::Borrowed("2.1");
        assert!(serde_json::to_string(&request).is_err());

        let mut response = JsonRpcResponse::success(RequestId::Number(1), Value::Null);
        response.jsonrpc = Cow::Borrowed("1.0");
        assert!(serde_json::to_string(&response).is_err());
    }

    #[test]
    fn response_success() {
        let resp = JsonRpcResponse::success(RequestId::Number(1), json!({"result": "ok"}));
        let value = serde_json::to_value(&resp).expect("serialize");
        assert_eq!(value["jsonrpc"], "2.0");
        assert_eq!(value["result"]["result"], "ok");
        assert_eq!(value["id"], 1);
        assert!(value.get("error").is_none());
        assert!(!resp.is_error());
    }

    #[test]
    fn response_error() {
        let error = JsonRpcError {
            code: -32601,
            message: "Method not found".to_string(),
            data: None,
        };
        let resp = JsonRpcResponse::error(Some(RequestId::Number(1)), error);
        let value = serde_json::to_value(&resp).expect("serialize");
        assert_eq!(value["jsonrpc"], "2.0");
        assert!(value.get("result").is_none());
        assert_eq!(value["error"]["code"], -32601);
        assert_eq!(value["error"]["message"], "Method not found");
        assert_eq!(value["id"], 1);
        assert!(resp.is_error());
    }

    #[test]
    fn uncorrelated_response_error_omits_id() {
        let error = JsonRpcError {
            code: -32700,
            message: "Parse error".to_string(),
            data: None,
        };
        let resp = JsonRpcResponse::error(None, error);
        let value = serde_json::to_value(&resp).expect("serialize");
        assert!(value.get("id").is_none());
    }

    #[test]
    fn response_rejects_explicit_null_id_but_accepts_absent_id() {
        let explicit_null = serde_json::from_str::<JsonRpcResponse>(
            r#"{"jsonrpc":"2.0","error":{"code":-32700,"message":"Parse error"},"id":null}"#,
        );
        assert!(explicit_null.is_err());

        let absent = serde_json::from_str::<JsonRpcResponse>(
            r#"{"jsonrpc":"2.0","error":{"code":-32700,"message":"Parse error"}}"#,
        )
        .expect("an uncorrelated MCP error omits id");
        assert!(absent.id.is_none());
    }

    #[test]
    fn response_round_trip() {
        let original =
            JsonRpcResponse::success(RequestId::String("abc".to_string()), json!({"tools": []}));
        let json_str = serde_json::to_string(&original).expect("serialize");
        let deserialized: JsonRpcResponse = serde_json::from_str(&json_str).expect("deserialize");
        assert!(!deserialized.is_error());
        assert!(deserialized.result.is_some());
        assert_eq!(deserialized.id, Some(RequestId::String("abc".to_string())));
    }

    #[test]
    fn response_null_result_round_trip_preserves_member_presence() {
        let raw = r#"{"jsonrpc":"2.0","result":null,"id":1}"#;
        let response: JsonRpcResponse = serde_json::from_str(raw).expect("deserialize response");

        assert_eq!(response.result, Some(Value::Null));
        assert!(response.error.is_none());

        let encoded = serde_json::to_value(response).expect("serialize response");
        assert_eq!(encoded.get("result"), Some(&Value::Null));
        assert!(encoded.get("error").is_none());
    }

    #[test]
    fn response_rejects_both_or_neither_outcome_members() {
        for raw in [
            r#"{"jsonrpc":"2.0","result":null,"error":{"code":-32603,"message":"failure"},"id":1}"#,
            r#"{"jsonrpc":"2.0","id":1}"#,
        ] {
            let error = serde_json::from_str::<JsonRpcResponse>(raw)
                .expect_err("invalid response envelope must be rejected");
            assert!(error.to_string().contains("exactly one"));
        }

        let both = JsonRpcResponse {
            jsonrpc: Cow::Borrowed(JSONRPC_VERSION),
            result: Some(Value::Null),
            error: Some(JsonRpcError {
                code: -32_603,
                message: "failure".to_string(),
                data: None,
            }),
            id: Some(RequestId::Number(1)),
        };
        assert!(serde_json::to_value(both).is_err());

        let neither = JsonRpcResponse {
            jsonrpc: Cow::Borrowed(JSONRPC_VERSION),
            result: None,
            error: None,
            id: Some(RequestId::Number(1)),
        };
        assert!(serde_json::to_value(neither).is_err());
    }

    #[test]
    fn response_rejects_unknown_top_level_envelope_members() {
        let error = serde_json::from_str::<JsonRpcResponse>(
            r#"{"jsonrpc":"2.0","result":null,"id":1,"extension":true}"#,
        )
        .expect_err("response envelopes are closed");

        assert!(error.to_string().contains("unknown field"));
    }

    #[test]
    fn response_validation_rejects_uncorrelated_success() {
        let response = JsonRpcResponse {
            jsonrpc: Cow::Borrowed(JSONRPC_VERSION),
            result: Some(Value::Null),
            error: None,
            id: None,
        };

        assert_eq!(
            response.validate(),
            Err("JSON-RPC success response must contain an id")
        );
        assert!(serde_json::to_value(response).is_err());
        assert!(
            serde_json::from_str::<JsonRpcResponse>(r#"{"jsonrpc":"2.0","result":null}"#).is_err()
        );
    }

    // ========================================================================
    // JsonRpcMessage Tests
    // ========================================================================

    #[test]
    fn message_request_variant() {
        let req = JsonRpcRequest::new("tools/list", None, 1i64);
        let msg = JsonRpcMessage::Request(req);
        let value = serde_json::to_value(&msg).expect("serialize");
        assert_eq!(value["method"], "tools/list");
    }

    #[test]
    fn message_response_variant() {
        let resp = JsonRpcResponse::success(RequestId::Number(1), json!("ok"));
        let msg = JsonRpcMessage::Response(resp);
        let value = serde_json::to_value(&msg).expect("serialize");
        assert_eq!(value["result"], "ok");
    }

    #[test]
    fn message_deserialize_as_request() {
        let json_str = r#"{"jsonrpc":"2.0","method":"tools/list","id":1}"#;
        let msg: JsonRpcMessage = serde_json::from_str(json_str).expect("deserialize");
        let (method, id) = match msg {
            JsonRpcMessage::Request(req) => (req.method, req.id),
            JsonRpcMessage::Response(_) => (String::new(), None),
        };
        assert_eq!(method, "tools/list");
        assert_eq!(id, Some(RequestId::Number(1)));
    }

    #[test]
    fn message_deserialize_as_response() {
        let json_str = r#"{"jsonrpc":"2.0","result":{"tools":[]},"id":1}"#;
        let msg: JsonRpcMessage = serde_json::from_str(json_str).expect("deserialize");
        let (is_error, id) = match msg {
            JsonRpcMessage::Response(resp) => (resp.is_error(), resp.id),
            JsonRpcMessage::Request(_) => (true, None),
        };
        assert!(!is_error);
        assert_eq!(id, Some(RequestId::Number(1)));
    }

    #[test]
    fn message_rejects_mixed_request_and_response_envelopes() {
        for raw in [
            r#"{"jsonrpc":"2.0","method":"tools/list","result":null,"id":1}"#,
            r#"{"jsonrpc":"2.0","params":{},"error":{"code":-32603,"message":"failure"},"id":1}"#,
        ] {
            assert!(
                serde_json::from_str::<JsonRpcMessage>(raw).is_err(),
                "mixed envelope was accepted: {raw}"
            );
        }
    }

    #[test]
    fn message_validation_catches_public_field_mutation() {
        let mut request = JsonRpcRequest::new("tools/list", None, 1_i64);
        request.jsonrpc = Cow::Borrowed("2.1");
        let message = JsonRpcMessage::Request(request);

        assert_eq!(message.validate(), Err("jsonrpc must be exactly \"2.0\""));
    }

    // ========================================================================
    // JSONRPC_VERSION constant test
    // ========================================================================

    #[test]
    fn jsonrpc_version_constant() {
        assert_eq!(JSONRPC_VERSION, "2.0");
    }
}
