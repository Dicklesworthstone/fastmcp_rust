//! Result admission for an already negotiated extension request.
//!
//! Validation neither activates a second extension nor rewrites a handler's
//! schema-defined payload. The same gate protects producer results and the
//! final value after response middleware.

use std::io::{self, Write};

use fastmcp_core::{McpError, McpResult};
use fastmcp_protocol::extensions::NegotiatedExtensionSet;
use fastmcp_protocol::protocol_policy::ProtocolEra;
// From the crate ROOT, not `fastmcp_protocol::result::`. That module is
// declared `mod result;` (private) at fastmcp-protocol/src/lib.rs:56 and its
// contents reach consumers through `pub use result::*;` at :131 -- the same
// shape as `jsonrpc`, `messages` and `types`. The module PATH is private even
// though every item on it is public, so naming the path is E0603 while naming
// the root is fine. All nine items below resolve at the root.
use fastmcp_protocol::{
    DecodedResult, DeferringResultDiscriminatorPolicy, ExactJsonValue, ExtensionId,
    JsonRpcRequest, MAX_RESULT_CONTAINER_MEMBERS, MAX_RESULT_DEPTH, MAX_RESULT_ENCODED_BYTES,
    decode_peer_result_for_era,
};
use serde_json::Value;

use super::ExtensionHandlerRegistry;

fn invalid_result() -> McpError {
    // Handler payloads and discriminator text can contain private data.
    McpError::internal_error("extension response violates its negotiated result contract")
}

impl ExtensionHandlerRegistry {
    /// Checks a result under the exact request admission, preserving its value.
    ///
    /// A retained source must come from the same unchanged response value.
    /// Callers use JsonRpcResponse::retained_result_source for that binding;
    /// middleware replacements are encoded under the result codec's byte bound.
    pub(crate) fn validate_response_result(
        &self,
        negotiated: &NegotiatedExtensionSet,
        protocol_era: ProtocolEra,
        extension_id: &ExtensionId,
        request: &JsonRpcRequest,
        value: &Value,
        source: Option<&str>,
    ) -> McpResult<()> {
        self.admitted_handler(negotiated, protocol_era, extension_id, request)
            .map_err(|_| invalid_result())?;
        if !value.is_object() {
            return Err(invalid_result());
        }

        let encoded;
        let source = if let Some(source) = source {
            source
        } else {
            encoded = encode_result(value)?;
            &encoded
        };
        let (decoded, _) =
            decode_peer_result_for_era(source, protocol_era, &DeferringResultDiscriminatorPolicy)
                .map_err(|_| invalid_result())?;

        match decoded {
            // Absent resultType retains the protocol's complete-result
            // compatibility behavior. No marker is injected into the value.
            DecodedResult::Complete(_) | DecodedResult::InputRequired(_) => Ok(()),
            DecodedResult::Deferred(envelope) => {
                // Deferred raw admission deliberately stops before ordinary
                // metadata typing. Activating a custom result must close that
                // seam, including explicit null and other non-object values.
                if envelope.members().iter().any(|member| {
                    member.name == "_meta" && !matches!(&member.value, ExactJsonValue::Object(_))
                }) {
                    return Err(invalid_result());
                }
                // Task creation is a tools/call result, never the outcome of
                // a generic extension method such as tasks/get or tasks/update.
                if envelope.discriminator() == "task" {
                    return Err(invalid_result());
                }
                negotiated
                    .admit_result_discriminator(
                        &self.descriptor_registry,
                        protocol_era,
                        extension_id,
                        envelope.discriminator(),
                    )
                    .map(|_| ())
                    .map_err(|_| invalid_result())
            }
        }
    }
}

/// Bounded serialization for values with no retained wire representation.
fn encode_result(value: &Value) -> McpResult<String> {
    // A byte-limited writer alone cannot stop serde's recursive traversal of
    // deeply nested programmatic Values. Check depth before descending, with
    // a conservative work bound: every encoded node consumes at least one byte.
    let mut remaining_nodes = MAX_RESULT_ENCODED_BYTES;
    validate_value_shape(value, 0, &mut remaining_nodes)?;

    struct ResultWriter(Vec<u8>);

    impl Write for ResultWriter {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            if bytes.len() > MAX_RESULT_ENCODED_BYTES.saturating_sub(self.0.len()) {
                return Err(io::Error::other("extension result byte limit exceeded"));
            }
            let required = self.0.len() + bytes.len();
            if required > self.0.capacity() {
                let capacity = required
                    .max(self.0.capacity().saturating_mul(2))
                    .max(256)
                    .min(MAX_RESULT_ENCODED_BYTES);
                self.0
                    .try_reserve_exact(capacity - self.0.len())
                    .map_err(|_| io::Error::other("extension result allocation refused"))?;
            }
            self.0.extend_from_slice(bytes);
            Ok(bytes.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    let mut writer = ResultWriter(Vec::new());
    serde_json::to_writer(&mut writer, value).map_err(|_| invalid_result())?;
    String::from_utf8(writer.0).map_err(|_| invalid_result())
}

fn validate_value_shape(value: &Value, depth: usize, remaining_nodes: &mut usize) -> McpResult<()> {
    if depth > MAX_RESULT_DEPTH || *remaining_nodes == 0 {
        return Err(invalid_result());
    }
    *remaining_nodes -= 1;
    match value {
        Value::Array(values) => {
            if values.len() > MAX_RESULT_CONTAINER_MEMBERS {
                return Err(invalid_result());
            }
            for child in values {
                validate_value_shape(child, depth + 1, remaining_nodes)?;
            }
        }
        Value::Object(values) => {
            if values.len() > MAX_RESULT_CONTAINER_MEMBERS {
                return Err(invalid_result());
            }
            for child in values.values() {
                validate_value_shape(child, depth + 1, remaining_nodes)?;
            }
        }
        _ => {}
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn payload(value: Value) -> Value {
        Value::Object(serde_json::Map::from_iter([("payload".to_owned(), value)]))
    }

    #[test]
    fn extension_result_encoding_checks_depth_before_serialization() {
        for (arrays, admitted) in [(MAX_RESULT_DEPTH - 1, true), (MAX_RESULT_DEPTH, false)] {
            let mut value = Value::Null;
            for _ in 0..arrays {
                value = Value::Array(vec![value]);
            }
            let encoded = encode_result(&payload(value));
            assert_eq!(encoded.is_ok(), admitted, "nested array count: {arrays}");
            if let Ok(source) = encoded {
                decode_peer_result_for_era(
                    &source,
                    ProtocolEra::Modern2026,
                    &DeferringResultDiscriminatorPolicy,
                )
                .expect("the encoder and exact decoder share the depth boundary");
            }
        }
    }

    #[test]
    fn extension_result_encoding_checks_container_width_before_serialization() {
        for (members, admitted) in [
            (MAX_RESULT_CONTAINER_MEMBERS, true),
            (MAX_RESULT_CONTAINER_MEMBERS + 1, false),
        ] {
            assert_eq!(
                encode_result(&payload(Value::Array(vec![Value::Null; members]))).is_ok(),
                admitted,
                "container members: {members}",
            );
        }
    }
}
