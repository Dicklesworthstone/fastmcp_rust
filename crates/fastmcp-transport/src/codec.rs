//! Message codec for framing JSON-RPC messages.
//!
//! MCP uses newline-delimited JSON (NDJSON) for message framing.

use fastmcp_protocol::{JsonRpcMessage, JsonRpcRequest, JsonRpcResponse};

/// Codec for encoding/decoding JSON-RPC messages.
#[derive(Debug)]
pub struct Codec {
    /// Buffer for incomplete messages.
    buffer: Vec<u8>,
    /// Read position in buffer (data before this has been consumed).
    read_pos: usize,
    /// Maximum allowed message size in bytes.
    max_message_size: usize,
}

impl Default for Codec {
    fn default() -> Self {
        Self::new()
    }
}

/// Threshold for compacting buffer (when read_pos exceeds this fraction of capacity).
const COMPACT_THRESHOLD: usize = 4096;

impl Codec {
    /// Creates a new codec with default settings (10MB limit).
    #[must_use]
    pub fn new() -> Self {
        Self {
            buffer: Vec::new(),
            read_pos: 0,
            max_message_size: 10 * 1024 * 1024, // 10MB
        }
    }

    /// Returns the maximum allowed message size in bytes.
    #[must_use]
    pub fn max_message_size(&self) -> usize {
        self.max_message_size
    }

    /// Sets the maximum allowed message size in bytes.
    pub fn set_max_message_size(&mut self, size: usize) {
        self.max_message_size = size;
        let unread = self.buffer.len() - self.read_pos;
        if unread > size {
            self.buffer.clear();
            self.read_pos = 0;
        }
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
    /// Returns an error if a complete line fails to parse or if the buffer exceeds the limit.
    pub fn decode(&mut self, data: &[u8]) -> Result<Vec<JsonRpcMessage>, CodecError> {
        // Calculate unread data size
        let unread_len = self.buffer.len() - self.read_pos;
        let projected_size = unread_len.saturating_add(data.len());

        // Check projected size BEFORE extending to prevent temporary memory exhaustion
        if projected_size > self.max_message_size {
            self.buffer.clear();
            self.read_pos = 0;
            return Err(CodecError::MessageTooLarge(projected_size));
        }

        // Compact buffer if read_pos is large (to prevent unbounded growth)
        if self.read_pos >= COMPACT_THRESHOLD {
            self.buffer.drain(..self.read_pos);
            self.read_pos = 0;
        }

        self.buffer.extend_from_slice(data);

        let mut messages = Vec::new();
        let mut start = self.read_pos;

        #[allow(clippy::mut_range_bound)]
        for i in start..self.buffer.len() {
            if self.buffer[i] == b'\n' {
                let line_len = i - start;
                if line_len > self.max_message_size {
                    self.buffer.clear();
                    self.read_pos = 0;
                    return Err(CodecError::MessageTooLarge(line_len));
                }
                let line = &self.buffer[start..i];
                if !line.is_empty() {
                    let msg: JsonRpcMessage = serde_json::from_slice(line)?;
                    messages.push(msg);
                }
                start = i + 1;
            }
        }

        // Update read position instead of draining for each decode call
        self.read_pos = start;

        // Check remaining unread data
        let remaining = self.buffer.len() - self.read_pos;
        if remaining > self.max_message_size {
            self.buffer.clear();
            self.read_pos = 0;
            return Err(CodecError::MessageTooLarge(remaining));
        }

        Ok(messages)
    }

    /// Clears the internal buffer.
    pub fn clear(&mut self) {
        self.buffer.clear();
        self.read_pos = 0;
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

        assert!(
            matches!(&messages[0], JsonRpcMessage::Response(_)),
            "Expected response"
        );
        if let JsonRpcMessage::Response(resp) = &messages[0] {
            assert_eq!(resp.id, Some(RequestId::Number(1)));
        }
    }

    #[test]
    fn test_decode_multiple_messages() {
        let input = b"{\"jsonrpc\":\"2.0\",\"method\":\"test1\",\"id\":1}\n{\"jsonrpc\":\"2.0\",\"method\":\"test2\",\"id\":2}\n";

        let mut codec = Codec::new();
        let messages = codec.decode(input).unwrap();

        assert_eq!(messages.len(), 2);

        assert!(
            matches!(&messages[0], JsonRpcMessage::Request(_)),
            "Expected request"
        );
        if let JsonRpcMessage::Request(req) = &messages[0] {
            assert_eq!(req.method, "test1");
        }

        assert!(
            matches!(&messages[1], JsonRpcMessage::Request(_)),
            "Expected request"
        );
        if let JsonRpcMessage::Request(req) = &messages[1] {
            assert_eq!(req.method, "test2");
        }
    }

    #[test]
    fn test_decode_allows_multiple_messages_in_separate_chunks() {
        // Since the codec now pre-checks chunk size, send messages in separate chunks
        let req1 = JsonRpcRequest::new("test1", None, 1i64);
        let req2 = JsonRpcRequest::new("test2", None, 2i64);
        let mut line1 = serde_json::to_vec(&req1).unwrap();
        let mut line2 = serde_json::to_vec(&req2).unwrap();
        line1.push(b'\n');
        line2.push(b'\n');

        let mut codec = Codec::new();
        // Set limit to accommodate one message at a time
        codec.set_max_message_size(line1.len());

        // Decode first message
        let messages1 = codec.decode(&line1).unwrap();
        assert_eq!(messages1.len(), 1);

        // Decode second message
        let messages2 = codec.decode(&line2).unwrap();
        assert_eq!(messages2.len(), 1);
    }

    #[test]
    fn test_decode_rejects_oversized_incomplete_line() {
        let req = JsonRpcRequest::new("oversized", None, 1i64);
        let line = serde_json::to_vec(&req).unwrap();

        let mut codec = Codec::new();
        codec.max_message_size = line.len().saturating_sub(1);

        let result = codec.decode(&line);
        assert!(matches!(result, Err(CodecError::MessageTooLarge(_))));
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

        assert!(
            matches!(&messages[0], JsonRpcMessage::Request(_)),
            "Expected request"
        );
        if let JsonRpcMessage::Request(req) = &messages[0] {
            assert_eq!(req.method, "test");
        }
    }

    #[test]
    fn test_decode_invalid_json() {
        let mut codec = Codec::new();
        let invalid = b"not valid json\n";

        let result = codec.decode(invalid);
        assert!(result.is_err());

        let err = result.unwrap_err();
        assert!(matches!(err, CodecError::Json(_)));
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
        assert!(
            matches!(&messages[0], JsonRpcMessage::Request(_)),
            "Expected request"
        );
        if let JsonRpcMessage::Request(req) = &messages[0] {
            assert_eq!(req.method, "fresh");
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
