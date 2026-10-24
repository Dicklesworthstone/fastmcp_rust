//! Typed modern core requests over explicit DPoP HTTPS authorization.
//!
//! The shared MCP decoder, not this transport, owns correlation, lossless
//! result admission and the complete/input-required distinction. Each call
//! performs one POST. The JSON-only methods remain terminal collectors;
//! [`stream`] additionally delivers request-scoped SSE notifications. Neither
//! path installs discovery, OAuth login, extension negotiation, a result cache,
//! or retries. Explicit multi-round execution lives in [`interaction`].
//! The separately selected `tasks` module adds authenticated Tasks discovery
//! and operations without changing the core-only request contract.

use std::fmt;
use std::io::{self, Write};

use asupersync::Cx;
use fastmcp_core::McpRequestCancellation;
use fastmcp_protocol::{
    CoreRequest, CoreResult, FINAL_CLIENT_CAPABILITIES_META_KEY, FINAL_PROTOCOL_VERSION, RequestId,
};

use super::{
    DpopCredential, DpopHttpClient, DpopHttpError, DpopHttpResponse, ModernHttpRequest, WaitBounds,
    check_live,
};
use crate::http_auth::rpc::{
    CoreDecoder, ManagedCoreError, ManagedCoreEvent, ManagedCoreLimits, core_routing_name,
};

/// Complete catalog traversal under one original credential and deadline.
pub mod catalog;
/// Explicit host-driven multi-round operations with one credential and deadline.
pub mod interaction;
/// Incremental JSON/SSE core responses under the original DPoP credential.
pub mod stream;
/// Explicit official Tasks discovery and operations over the same DPoP transport.
#[cfg(feature = "tasks")]
pub mod tasks;

/// Diagnostics retain no peer message, body, nonce or authorization header.
/// An admitted JSON-RPC error exposes only its numeric code through Protocol.
#[derive(Debug)]
pub enum DpopCoreError {
    Protocol(ManagedCoreError),
    Transport(DpopHttpError),
}

impl fmt::Display for DpopCoreError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Protocol(error) => error.fmt(f),
            Self::Transport(error) => error.fmt(f),
        }
    }
}

impl std::error::Error for DpopCoreError {}

impl From<ManagedCoreError> for DpopCoreError {
    fn from(error: ManagedCoreError) -> Self {
        Self::Protocol(error)
    }
}

impl From<DpopHttpError> for DpopCoreError {
    fn from(error: DpopHttpError) -> Self {
        Self::Transport(error)
    }
}

impl DpopHttpClient {
    /// Send one typed core request with an already-admitted DPoP credential.
    /// The caller supplies final request metadata, including capabilities, and
    /// a valid correlation ID. Nonempty extension offers are refused because
    /// this entrypoint has not negotiated them. Input-required is returned to
    /// the host as a typed result, never followed by another automatic POST.
    pub async fn request_core(
        &mut self,
        cx: &Cx,
        credential: &DpopCredential,
        request: CoreRequest,
        request_id: RequestId,
        limits: ManagedCoreLimits,
    ) -> Result<CoreResult, DpopCoreError> {
        self.request_core_with_cancellation(
            cx,
            &McpRequestCancellation::new(),
            credential,
            request,
            request_id,
            limits,
        )
        .await
    }

    /// The earlier native/typed/caller deadline bounds preparation, network
    /// execution and result publication together. Original credential expiry
    /// and all revocation domains remain authoritative through decoding.
    /// Native buffering has its own finite cap; the shared decoder additionally
    /// enforces the supplied frame and total-payload limits on the read body.
    pub async fn request_core_with_cancellation(
        &mut self,
        cx: &Cx,
        cancellation: &McpRequestCancellation,
        credential: &DpopCredential,
        request: CoreRequest,
        request_id: RequestId,
        limits: ManagedCoreLimits,
    ) -> Result<CoreResult, DpopCoreError> {
        let timeout = self.policy.timeout.min(limits.timeout());
        let bounds = WaitBounds::new(cx, timeout, credential)?;
        check_live(cx, cancellation, &self.session, credential, bounds)?;
        let (wire, mut decoder) = prepare(
            self.resource().as_str(),
            request,
            request_id,
            limits,
            self.policy.max_body_bytes,
        )?;
        let response = self
            .post_resource_with_bounds(cx, cancellation, credential, &wire, bounds)
            .await?;
        check_live(cx, cancellation, &self.session, credential, bounds)?;
        let outcome = decode_response(&mut decoder, response);
        // Even a fully read result is withheld if decoding outlived its owner,
        // credential or original deadline. Remote diagnostics follow the same
        // publication check and cannot bypass cancellation via an error arm.
        check_live(cx, cancellation, &self.session, credential, bounds)?;
        outcome
    }
}

fn prepare(
    target: &str,
    request: CoreRequest,
    request_id: RequestId,
    limits: ManagedCoreLimits,
    transport_limit: usize,
) -> Result<(ModernHttpRequest, CoreDecoder), DpopCoreError> {
    let params = request
        .encode_params()
        .map_err(|_| ManagedCoreError::InvalidRequest)?
        .ok_or(ManagedCoreError::InvalidRequest)?;
    let method = request.method().to_owned();
    // The decoder's constructor owns the supported era/method table and ID
    // validation. Do not fork that table into a DPoP-specific implementation.
    let decoder = CoreDecoder::for_request(request, request_id.clone(), limits)?;
    admit_core_metadata(&params)?;
    let name = core_routing_name(&method, &params);
    let envelope = serde_json::json!({
        "jsonrpc": "2.0", "id": request_id, "method": method, "params": params,
    });
    let mut encoded = BoundedWriter {
        bytes: Vec::new(),
        maximum: limits.request_bytes().min(transport_limit),
    };
    serde_json::to_writer(&mut encoded, &envelope)
        .map_err(|_| ManagedCoreError::RequestTooLarge)?;
    let wire = ModernHttpRequest::new(target, encoded.bytes, FINAL_PROTOCOL_VERSION, method, name)
        .map_err(|_| ManagedCoreError::InvalidRequest)?;
    Ok((wire, decoder))
}

fn admit_core_metadata(params: &serde_json::Value) -> Result<(), ManagedCoreError> {
    let metadata = params
        .get("_meta")
        .and_then(serde_json::Value::as_object)
        .ok_or(ManagedCoreError::InvalidRequest)?;
    if let Some(extensions) = metadata
        .get(FINAL_CLIENT_CAPABILITIES_META_KEY)
        .and_then(|capabilities| capabilities.get("extensions"))
        && !extensions
            .as_object()
            .is_some_and(serde_json::Map::is_empty)
    {
        return Err(ManagedCoreError::UnsupportedRequest);
    }
    Ok(())
}

fn decode_response(
    decoder: &mut CoreDecoder,
    response: DpopHttpResponse,
) -> Result<CoreResult, DpopCoreError> {
    // A 202 acknowledgement is not a result for a request with an ID. Neither
    // an HTTP failure nor a redirect may promote itself by looking like JSON.
    if response.status() != 200 {
        return Err(ManagedCoreError::HttpStatus {
            status: response.status(),
        }
        .into());
    }
    match decoder.admit(response.body(), false)? {
        ManagedCoreEvent::Result(result) => Ok(*result),
        ManagedCoreEvent::Notification(_) => Err(ManagedCoreError::UnexpectedNotification.into()),
    }
}

struct BoundedWriter {
    bytes: Vec<u8>,
    maximum: usize,
}

impl Write for BoundedWriter {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if bytes.len() > self.maximum.saturating_sub(self.bytes.len()) {
            return Err(io::Error::other("DPoP core request byte limit"));
        }
        self.bytes.extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::future::Future;
    use std::task::{Context, Poll, Waker};
    use std::time::{Duration, Instant};

    use fastmcp_core::CanonicalHttpUrl;
    use fastmcp_protocol::dpop::DpopKey;
    use fastmcp_protocol::protocol_policy::ProtocolEra;
    use fastmcp_protocol::{ClientCapabilities, FinalCoreResult, FinalRequestMeta};
    use serde_json::{Value, json};

    use super::*;
    use crate::http_auth::dpop::DpopSession;
    use crate::http_auth::dpop::native::DpopHttpPolicy;

    fn request(method: &str, mut params: Value) -> CoreRequest {
        params["_meta"] =
            serde_json::to_value(FinalRequestMeta::new(ClientCapabilities::default())).unwrap();
        CoreRequest::decode(ProtocolEra::Modern2026, method, Some(&params)).unwrap()
    }

    fn prepared(method: &str, params: Value) -> (ModernHttpRequest, CoreDecoder) {
        prepare(
            "https://mcp.example/mcp",
            request(method, params),
            RequestId::Number(7),
            ManagedCoreLimits::default(),
            8 * 1024 * 1024,
        )
        .unwrap()
    }

    fn response(status: u16, body: &[u8]) -> DpopHttpResponse {
        DpopHttpResponse {
            status,
            headers: vec![("Content-Type".to_owned(), "application/json".to_owned())],
            body: body.to_vec(),
        }
    }

    fn frame(result: &str) -> Vec<u8> {
        format!(r#"{{"jsonrpc":"2.0","id":7,"result":{result}}}"#).into_bytes()
    }

    #[test]
    fn typed_preparation_preserves_metadata_arguments_and_routing_identity() {
        let (wire, _) = prepared("tools/call", json!({"name":"echo","arguments":{"x":42}}));
        let body: Value = serde_json::from_slice(wire.body()).unwrap();
        assert_eq!(body["id"], 7);
        assert_eq!(body["method"], "tools/call");
        assert_eq!(body["params"]["arguments"]["x"], 42);
        assert_eq!(
            body["params"]["_meta"]["io.modelcontextprotocol/protocolVersion"],
            FINAL_PROTOCOL_VERSION
        );
        assert!(
            wire.headers()
                .iter()
                .any(|(name, value)| name == "Mcp-Name" && value == "echo")
        );
        assert!(
            !wire
                .headers()
                .iter()
                .any(|(name, _)| name == "Authorization" || name == "DPoP")
        );
    }

    #[test]
    fn resource_reads_mirror_the_exact_uri_without_changing_the_authenticated_target() {
        for uri in [
            "file:///sample",
            "https://resources.example/a%2Fb?q=one#section",
            "https://resources.example/a%2fb?q=two#section",
        ] {
            let (wire, _) = prepared("resources/read", json!({"uri":uri}));
            let body: Value = serde_json::from_slice(wire.body()).unwrap();
            let headers = wire.headers();
            let mirrors: Vec<_> = headers.iter()
                .filter(|(name, _)| name.eq_ignore_ascii_case("mcp-name"))
                .collect();
            assert_eq!(mirrors.len(), 1);
            assert_eq!(
                fastmcp_protocol::http_headers::decode_mcp_header_value(mirrors[0].1.as_bytes()).unwrap(),
                uri,
            );
            assert_eq!(body["params"]["uri"], uri);
            assert_eq!(wire.target(), "https://mcp.example/mcp");
            assert!(!headers.iter().any(|(name, _)| name == "Authorization" || name == "DPoP"));
        }
        for method in ["resources/list", "resources/templates/list", "tools/list", "prompts/list"] {
            let (wire, _) = prepared(method, json!({}));
            assert!(!wire.headers().iter().any(|(name, _)| name.eq_ignore_ascii_case("mcp-name")));
        }
    }

    #[test]
    fn typed_encoding_obeys_both_native_and_core_byte_caps_exactly() {
        let (wire, _) = prepared("tools/list", json!({}));
        let length = wire.body().len();
        for native_cap in [false, true] {
            for exact in [false, true] {
                let cap = length - usize::from(!exact);
                let limits = ManagedCoreLimits::new(
                    if native_cap { 8192 } else { cap },
                    8192,
                    8192,
                    0,
                    Duration::from_secs(1),
                )
                .unwrap();
                let result = prepare(
                    "https://mcp.example/mcp",
                    request("tools/list", json!({})),
                    RequestId::Number(7),
                    limits,
                    if native_cap { cap } else { 8192 },
                );
                if exact {
                    assert!(result.is_ok());
                } else {
                    assert!(matches!(
                        result,
                        Err(DpopCoreError::Protocol(ManagedCoreError::RequestTooLarge))
                    ));
                }
            }
        }
    }

    #[test]
    fn extension_advertisement_is_not_an_implicit_negotiation() {
        let mut params = request("tools/list", json!({}))
            .encode_params()
            .unwrap()
            .unwrap();
        assert!(admit_core_metadata(&params).is_ok());
        params["_meta"][FINAL_CLIENT_CAPABILITIES_META_KEY]["extensions"] = json!({});
        assert!(admit_core_metadata(&params).is_ok());
        for offer in [
            json!({"io.modelcontextprotocol/tasks":{}}),
            json!([]),
            Value::Null,
        ] {
            params["_meta"][FINAL_CLIENT_CAPABILITIES_META_KEY]["extensions"] = offer;
            assert!(matches!(
                admit_core_metadata(&params),
                Err(ManagedCoreError::UnsupportedRequest)
            ));
        }
    }

    #[test]
    fn typed_dpop_results_use_the_shared_lossless_method_decoder() {
        let (_, mut decoder) = prepared("tools/list", json!({}));
        let bytes = frame(
            r#"{"resultType":"complete","tools":[],"ttlMs":100,"cacheScope":"private","x-exact":{"z":900719925474099312345,"a":1.20e+4}}"#,
        );
        let result = decode_response(&mut decoder, response(200, &bytes)).unwrap();
        let encoded = result.encode().unwrap();
        assert!(encoded.contains("900719925474099312345"));
        assert!(encoded.contains("1.20e+4"));
        assert!(encoded.find("\"z\"").unwrap() < encoded.find("\"a\"").unwrap());
        let (_, mut wrong_method) = prepared("resources/read", json!({"uri":"file:///sample"}));
        assert!(matches!(
            decode_response(&mut wrong_method, response(200, &bytes)),
            Err(DpopCoreError::Protocol(ManagedCoreError::InvalidResult))
        ));
        assert_eq!(wrong_method.usage(), (0, 0));
    }

    #[test]
    fn foreign_ids_duplicate_members_batches_and_trailing_frames_are_rejected() {
        for invalid in [
            r#"{"jsonrpc":"2.0","id":8,"result":{"resultType":"complete","tools":[],"ttlMs":0,"cacheScope":"private"}}"#,
            r#"{"jsonrpc":"2.0","id":"7","result":{"resultType":"complete","tools":[],"ttlMs":0,"cacheScope":"private"}}"#,
            r#"{"jsonrpc":"2.0","id":null,"result":{}}"#,
            r#"{"jsonrpc":"2.0","id":7,"id":7,"result":{}}"#,
            r#"[{"jsonrpc":"2.0","id":7,"result":{}}]"#,
            r#"{"jsonrpc":"2.0","id":7,"result":{}}{}"#,
        ] {
            let (_, mut decoder) = prepared("tools/list", json!({}));
            assert!(decode_response(&mut decoder, response(200, invalid.as_bytes())).is_err());
            assert_eq!(decoder.usage(), (0, 0));
        }
    }

    #[test]
    fn input_required_stays_a_typed_terminal_and_tasks_stay_unnegotiated() {
        let (_, mut decoder) = prepared("resources/read", json!({"uri":"file:///sample"}));
        let bytes = frame(
            r#"{"resultType":"input_required","inputRequests":{"roots":{"method":"roots/list"}},"requestState":"opaque-state"}"#,
        );
        let result = decode_response(&mut decoder, response(200, &bytes)).unwrap();
        assert!(matches!(
            result,
            CoreResult::Final(FinalCoreResult::ResourcesReadInputRequired { .. })
        ));
        let (_, mut decoder) = prepared("tools/call", json!({"name":"echo"}));
        let task = frame(r#"{"resultType":"task","taskId":"opaque","status":"working"}"#);
        assert!(matches!(
            decode_response(&mut decoder, response(200, &task)),
            Err(DpopCoreError::Protocol(ManagedCoreError::UnsupportedResult))
        ));
        assert_eq!(decoder.usage(), (0, 0));
    }

    #[test]
    fn status_notifications_and_remote_diagnostics_cannot_bypass_core_admission() {
        let valid =
            frame(r#"{"resultType":"complete","tools":[],"ttlMs":0,"cacheScope":"private"}"#);
        for status in [202, 204, 307, 401, 500] {
            let (_, mut decoder) = prepared("tools/list", json!({}));
            assert!(matches!(
                decode_response(&mut decoder, response(status, &valid)),
                Err(DpopCoreError::Protocol(ManagedCoreError::HttpStatus { status: actual })) if actual == status
            ));
            assert_eq!(decoder.usage(), (0, 0));
        }
        let (_, mut decoder) = prepared("tools/list", json!({}));
        let notification = br#"{"jsonrpc":"2.0","method":"notifications/tools/list_changed"}"#;
        assert!(matches!(
            decode_response(&mut decoder, response(200, notification)),
            Err(DpopCoreError::Protocol(
                ManagedCoreError::UnexpectedNotification
            ))
        ));
        let peer_error = br#"{"jsonrpc":"2.0","id":7,"error":{"code":-32603,"message":"secret-token","data":{"private":"secret-proof"}}}"#;
        let error = decode_response(&mut decoder, response(200, peer_error))
            .err()
            .unwrap();
        assert!(matches!(
            &error,
            DpopCoreError::Protocol(ManagedCoreError::Remote { .. })
        ));
        assert!(!format!("{error:?} {error}").contains("secret"));
    }

    #[test]
    fn the_typed_frame_limit_is_exact_and_rejection_does_not_advance_decoder() {
        let bytes =
            frame(r#"{"resultType":"complete","tools":[],"ttlMs":0,"cacheScope":"private"}"#);
        for exact in [true, false] {
            let maximum = bytes.len() - usize::from(!exact);
            let limits =
                ManagedCoreLimits::new(8192, maximum, maximum, 0, Duration::from_secs(1)).unwrap();
            let (_, mut decoder) = prepare(
                "https://mcp.example/mcp",
                request("tools/list", json!({})),
                RequestId::Number(7),
                limits,
                8192,
            )
            .unwrap();
            let outcome = decode_response(&mut decoder, response(200, &bytes));
            if exact {
                assert!(outcome.is_ok());
                assert_eq!(decoder.usage(), (bytes.len(), 0));
            } else {
                assert!(matches!(
                    outcome,
                    Err(DpopCoreError::Protocol(ManagedCoreError::ResponseByteLimit))
                ));
                assert_eq!(decoder.usage(), (0, 0));
            }
        }
    }

    #[test]
    fn cancelled_public_typed_call_stops_before_a_network_operation() {
        let cx = Cx::for_testing();
        cx.set_cancel_requested(true);
        let session = DpopSession::new(
            DpopKey::generate().unwrap(),
            CanonicalHttpUrl::parse("https://issuer.example/token").unwrap(),
            CanonicalHttpUrl::parse("https://mcp.example/mcp").unwrap(),
        )
        .unwrap();
        let credential = session
            .admit_token_response(
                &CanonicalHttpUrl::parse("https://issuer.example/token").unwrap(),
                200,
                br#"{"access_token":"token","token_type":"DPoP","expires_in":60}"#,
                Instant::now(),
                Duration::from_secs(60),
            )
            .unwrap();
        let mut client = DpopHttpClient::new(session, DpopHttpPolicy::default()).unwrap();
        let mut call = Box::pin(client.request_core(
            &cx,
            &credential,
            request("tools/list", json!({})),
            RequestId::Number(7),
            ManagedCoreLimits::default(),
        ));
        assert!(matches!(
            call.as_mut().poll(&mut Context::from_waker(Waker::noop())),
            Poll::Ready(Err(DpopCoreError::Transport(DpopHttpError::Cancelled)))
        ));
    }
}
