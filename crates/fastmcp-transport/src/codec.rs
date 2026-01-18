//! Message codec for framing JSON-RPC messages.
//!
//! MCP uses newline-delimited JSON (NDJSON) for message framing.

use fastmcp_protocol::{JsonRpcMessage, JsonRpcRequest, JsonRpcResponse};

/// Codec for encoding/decoding JSON-RPC messages.
#[derive(Debug, Default)]
pub struct Codec {
    /// Buffer for incomplete messages.
    buffer: Vec<u8>,
}

impl Codec {
    /// Creates a new codec.
    #[must_use]
    pub fn new() -> Self {
        Self { buffer: Vec::new() }
    }

    /// Encodes a request to bytes.
    ///
    /// # Errors
    ///
    /// Returns an error if serialization fails.
    pub fn encode_request(&self, request: &JsonRpcRequest) -> Result<Vec<u8>, CodecError> {
        let mut bytes = serde_json::to_vec(request)?;
        bytes.push(b'\n');
        Ok(bytes)
    }

    /// Encodes a response to bytes.
    ///
    /// # Errors
    ///
    /// Returns an error if serialization fails.
    pub fn encode_response(&self, response: &JsonRpcResponse) -> Result<Vec<u8>, CodecError> {
        let mut bytes = serde_json::to_vec(response)?;
        bytes.push(b'\n');
        Ok(bytes)
    }

    /// Decodes bytes into a message, returning any complete messages.
    ///
    /// Incomplete data is buffered for the next call.
    ///
    /// # Errors
    ///
    /// Returns an error if a complete line fails to parse.
    pub fn decode(&mut self, data: &[u8]) -> Result<Vec<JsonRpcMessage>, CodecError> {
        self.buffer.extend_from_slice(data);

        let mut messages = Vec::new();
        let mut start = 0;

        for (i, &byte) in self.buffer.iter().enumerate() {
            if byte == b'\n' {
                let line = &self.buffer[start..i];
                if !line.is_empty() {
                    let msg: JsonRpcMessage = serde_json::from_slice(line)?;
                    messages.push(msg);
                }
                start = i + 1;
            }
        }

        // Keep any incomplete data in buffer
        if start > 0 {
            self.buffer.drain(..start);
        }

        Ok(messages)
    }

    /// Clears the internal buffer.
    pub fn clear(&mut self) {
        self.buffer.clear();
    }
}

/// Codec error types.
#[derive(Debug)]
pub enum CodecError {
    /// JSON parsing error.
    Json(serde_json::Error),
    /// Message too large.
    MessageTooLarge(usize),
}

impl std::fmt::Display for CodecError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CodecError::Json(e) => write!(f, "JSON error: {e}"),
            CodecError::MessageTooLarge(size) => write!(f, "Message too large: {size} bytes"),
        }
    }
}

impl std::error::Error for CodecError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            CodecError::Json(e) => Some(e),
            CodecError::MessageTooLarge(_) => None,
        }
    }
}

impl From<serde_json::Error> for CodecError {
    fn from(err: serde_json::Error) -> Self {
        CodecError::Json(err)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use fastmcp_protocol::RequestId;
    use std::error::Error;

    #[test]
    fn test_encode_decode_roundtrip() {
        let codec = Codec::new();
        let request = JsonRpcRequest::new("test/method", None, 1i64);

        let encoded = codec.encode_request(&request).unwrap();
        assert!(encoded.ends_with(b"\n"));

        let mut codec2 = Codec::new();
        let messages = codec2.decode(&encoded).unwrap();
        assert_eq!(messages.len(), 1);
    }

    #[test]
    fn test_encode_response() {
        let codec = Codec::new();
        let response =
            JsonRpcResponse::success(RequestId::Number(1), serde_json::json!({"result": "ok"}));

        let encoded = codec.encode_response(&response).unwrap();
        assert!(encoded.ends_with(b"\n"));

        let mut codec2 = Codec::new();
        let messages = codec2.decode(&encoded).unwrap();
        assert_eq!(messages.len(), 1);

        match &messages[0] {
            JsonRpcMessage::Response(resp) => {
                assert_eq!(resp.id, Some(RequestId::Number(1)));
            }
            JsonRpcMessage::Request(_) => panic!("Expected response"),
        }
    }

    #[test]
    fn test_decode_multiple_messages() {
        let input = b"{\"jsonrpc\":\"2.0\",\"method\":\"test1\",\"id\":1}\n{\"jsonrpc\":\"2.0\",\"method\":\"test2\",\"id\":2}\n";

        let mut codec = Codec::new();
        let messages = codec.decode(input).unwrap();

        assert_eq!(messages.len(), 2);

        match &messages[0] {
            JsonRpcMessage::Request(req) => assert_eq!(req.method, "test1"),
            JsonRpcMessage::Response(_) => panic!("Expected request"),
        }

        match &messages[1] {
            JsonRpcMessage::Request(req) => assert_eq!(req.method, "test2"),
            JsonRpcMessage::Response(_) => panic!("Expected request"),
        }
    }

    #[test]
    fn test_decode_partial_message() {
        let mut codec = Codec::new();

        // Feed partial data without newline
        let partial = b"{\"jsonrpc\":\"2.0\",\"method\":\"test\"";
        let messages = codec.decode(partial).unwrap();
        assert_eq!(messages.len(), 0); // No complete messages yet

        // Feed the rest including newline
        let rest = b",\"id\":1}\n";
        let messages = codec.decode(rest).unwrap();
        assert_eq!(messages.len(), 1);

        match &messages[0] {
            JsonRpcMessage::Request(req) => assert_eq!(req.method, "test"),
            JsonRpcMessage::Response(_) => panic!("Expected request"),
        }
    }

    #[test]
    fn test_decode_invalid_json() {
        let mut codec = Codec::new();
        let invalid = b"not valid json\n";

        let result = codec.decode(invalid);
        assert!(result.is_err());

        match result.unwrap_err() {
            CodecError::Json(_) => {} // Expected
            CodecError::MessageTooLarge(_) => panic!("Expected JSON error"),
        }
    }

    #[test]
    fn test_decode_empty_line() {
        let mut codec = Codec::new();
        let input = b"\n{\"jsonrpc\":\"2.0\",\"method\":\"test\",\"id\":1}\n";

        let messages = codec.decode(input).unwrap();
        assert_eq!(messages.len(), 1); // Empty line skipped
    }

    #[test]
    fn test_clear_buffer() {
        let mut codec = Codec::new();

        // Feed partial data
        let partial = b"{\"jsonrpc\":\"2.0\"";
        codec.decode(partial).unwrap();

        // Clear and verify buffer is empty
        codec.clear();

        // Feed a complete message - should parse without old partial data
        let complete = b"{\"jsonrpc\":\"2.0\",\"method\":\"fresh\",\"id\":1}\n";
        let messages = codec.decode(complete).unwrap();

        assert_eq!(messages.len(), 1);
        match &messages[0] {
            JsonRpcMessage::Request(req) => assert_eq!(req.method, "fresh"),
            JsonRpcMessage::Response(_) => panic!("Expected request"),
        }
    }

    #[test]
    fn test_codec_error_display() {
        let json_err = CodecError::Json(serde_json::from_str::<()>("invalid").unwrap_err());
        let size_err = CodecError::MessageTooLarge(1000);

        assert!(json_err.to_string().contains("JSON error"));
        assert!(size_err.to_string().contains("1000"));
    }

    #[test]
    fn test_codec_error_source() {
        let json_err = CodecError::Json(serde_json::from_str::<()>("invalid").unwrap_err());
        let size_err = CodecError::MessageTooLarge(1000);

        assert!(json_err.source().is_some());
        assert!(size_err.source().is_none());
    }
}
