//! Explicit parameter-header disclosure through the managed OAuth call owner.
//!
//! Reuses the normal core codec, managed credential lifecycle, one-POST dispatch,
//! incremental notifications and request-local cancellation. An annotation in a
//! catalog is never sufficient to enable this API: the host supplies a reviewed
//! plan bound to this resource and tool. Ordinary calls remain header-free.

use std::fmt;
use std::sync::Arc;

use asupersync::Cx;
use fastmcp_core::McpRequestCancellation;
use fastmcp_protocol::{CoreRequest, RequestId};

use super::{
    CoreDecoder, ManagedCoreCall, ManagedCoreError, ManagedCoreLimits,
    ManagedOAuthSession, bounded_wait, call_deadline, prepare,
};
use crate::http_executor::ModernHttpRequest;
use crate::http_executor::parameter_headers::{ReviewedToolHeaders, ToolHeaderDispatchError};
use super::interaction::{ManagedInteraction, ManagedInteractionError, ManagedInteractionLimits};

/// Header admission and core transport errors contain no disclosed values.
#[derive(Debug)]
pub enum ManagedToolHeaderError {
    Headers(ToolHeaderDispatchError),
    Core(ManagedCoreError),
}

impl fmt::Display for ManagedToolHeaderError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Headers(error) => fmt::Display::fmt(error, f),
            Self::Core(error) => fmt::Display::fmt(error, f),
        }
    }
}

impl std::error::Error for ManagedToolHeaderError {}
impl From<ToolHeaderDispatchError> for ManagedToolHeaderError {
    fn from(error: ToolHeaderDispatchError) -> Self { Self::Headers(error) }
}
impl From<ManagedCoreError> for ManagedToolHeaderError {
    fn from(error: ManagedCoreError) -> Self { Self::Core(error) }
}

// One preparation path is shared by initial calls and explicit continuations.
// It must run before credential acquisition and before consuming retry state.
pub(crate) fn prepare_optional(
    target: &str,
    request: CoreRequest,
    request_id: RequestId,
    limits: ManagedCoreLimits,
    reviewed: Option<&ReviewedToolHeaders>,
) -> Result<(ModernHttpRequest, CoreDecoder), ManagedToolHeaderError> {
    let (wire, decoder) = prepare(target, request, request_id, limits)?;
    let wire = match reviewed {
        Some(reviewed) => wire.with_reviewed_tool_headers(reviewed)?,
        None => wire,
    };
    Ok((wire, decoder))
}

impl ManagedOAuthSession {
    /// Starts an explicitly resumed operation with one immutable header review.
    /// Original arguments are projected on the first POST, every continuation,
    /// and any separately authorized journal recovery. Input answers and opaque
    /// state never become a replacement schema or a source of routing fields.
    pub async fn start_tool_interaction_with_headers(
        &self,
        cx: &Cx,
        request: CoreRequest,
        request_id: RequestId,
        reviewed: Arc<ReviewedToolHeaders>,
        limits: ManagedInteractionLimits,
    ) -> Result<ManagedInteraction, ManagedInteractionError> {
        self.start_tool_interaction_with_headers_and_cancellation(
            cx, &McpRequestCancellation::new(), request, request_id, reviewed, limits,
        ).await
    }

    /// Retains the original cancellation domain, deadline and review across
    /// host pauses. A review grants disclosure only; it does not grant replay
    /// authority or permission to run an input resolver.
    #[allow(clippy::too_many_arguments)]
    pub async fn start_tool_interaction_with_headers_and_cancellation(
        &self,
        cx: &Cx,
        cancellation: &McpRequestCancellation,
        request: CoreRequest,
        request_id: RequestId,
        reviewed: Arc<ReviewedToolHeaders>,
        limits: ManagedInteractionLimits,
    ) -> Result<ManagedInteraction, ManagedInteractionError> {
        self.start_core_interaction_configured(
            cx, cancellation, request, request_id, limits, Some(reviewed),
        ).await
    }

    /// Sends one tools/call with explicitly reviewed schema-derived headers.
    /// All binding, body, field-type and byte checks run before renewal or I/O.
    /// This returns the ordinary incremental core call; an input-required result
    /// does not automatically trigger a continuation or an input resolver.
    pub async fn request_tool_with_headers(
        &self,
        cx: &Cx,
        request: CoreRequest,
        request_id: RequestId,
        reviewed: &ReviewedToolHeaders,
        limits: ManagedCoreLimits,
    ) -> Result<ManagedCoreCall, ManagedToolHeaderError> {
        self.request_tool_with_headers_and_cancellation(
            cx, &McpRequestCancellation::new(), request, request_id, reviewed, limits,
        ).await
    }

    /// Retains one cancellation domain and absolute deadline through preparation,
    /// credential renewal and every response read. No sibling is cancelled and
    /// no side-effecting operation is replayed by this method.
    #[allow(clippy::too_many_arguments)]
    pub async fn request_tool_with_headers_and_cancellation(
        &self,
        cx: &Cx,
        cancellation: &McpRequestCancellation,
        request: CoreRequest,
        request_id: RequestId,
        reviewed: &ReviewedToolHeaders,
        limits: ManagedCoreLimits,
    ) -> Result<ManagedCoreCall, ManagedToolHeaderError> {
        let deadline = call_deadline(cx, cancellation, limits.timeout)?;
        let (wire, decoder) = prepare_optional(
            self.resource().as_str(), request, request_id, limits, Some(reviewed),
        )?;
        let response = bounded_wait(cx, cancellation, deadline, async {
            self.execute_with_cancellation(cx, cancellation, &wire)
                .await.map_err(ManagedCoreError::from)
        }).await?;
        ManagedCoreCall::from_response(response, decoder, cancellation.clone(), deadline)
            .map_err(ManagedToolHeaderError::from)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use fastmcp_core::CanonicalHttpUrl;
    use fastmcp_protocol::protocol_policy::ProtocolEra;
    use fastmcp_protocol::{ClientCapabilities, FinalRequestMeta};
    use serde_json::{Value, json};

    const TARGET: &str = "https://tools.example/mcp";

    fn review() -> ReviewedToolHeaders {
        ReviewedToolHeaders::new(CanonicalHttpUrl::parse(TARGET).unwrap(), "lookup", json!({
            "type":"object", "properties":{"region":{"type":"string","x-mcp-header":"Region"}},
        }), |binding| binding.property_path() == ["region".to_owned()]
            && binding.header_name() == "Mcp-Param-Region").unwrap()
    }

    fn request(method: &str, mut params: Value) -> CoreRequest {
        params["_meta"] = serde_json::to_value(FinalRequestMeta::new(ClientCapabilities::default())).unwrap();
        CoreRequest::decode(ProtocolEra::Modern2026, method, Some(&params)).unwrap()
    }

    #[test]
    fn managed_preparation_retains_the_core_decoder_and_exact_parameters() {
        let request = request("tools/call", json!({"name":"lookup","arguments":{"region":"eu","private":"body-only"}}));
        let before = request.encode_params().unwrap().unwrap();
        let (wire, decoder) = prepare_optional(TARGET, request, RequestId::Number(17), ManagedCoreLimits::default(), Some(&review())).unwrap();
        let body: Value = serde_json::from_slice(wire.body()).unwrap();
        assert_eq!(body["params"], before);
        assert_eq!(body["id"], 17);
        assert_eq!(decoder.request_id, RequestId::Number(17));
        assert!(wire.headers().iter().any(|(name, value)| name == "Mcp-Param-Region" && value == "eu"));
        assert!(!wire.headers().iter().any(|(_, value)| value.contains("body-only")));
        assert!(!wire.headers().iter().any(|(name, _)| name == "Authorization"));
    }

    #[test]
    fn invalid_binding_type_or_size_fails_during_local_preparation() {
        let review = review();
        for (target, request) in [
            ("https://tools.example/other", request("tools/call", json!({"name":"lookup"}))),
            (TARGET, request("tools/call", json!({"name":"other"}))),
            (TARGET, request("tools/call", json!({"name":"lookup","arguments":{"region":42}}))),
            (TARGET, request("tools/list", json!({}))),
        ] {
            assert!(prepare_optional(target, request, RequestId::Number(17), ManagedCoreLimits::default(), Some(&review)).is_err());
        }
        let tiny = ManagedCoreLimits::new(1, 1024, 1024, 1, std::time::Duration::from_secs(1)).unwrap();
        assert!(matches!(prepare_optional(TARGET, request("tools/call", json!({"name":"lookup"})), RequestId::Number(17), tiny, Some(&review)),
            Err(ManagedToolHeaderError::Core(ManagedCoreError::RequestTooLarge))));
    }

    #[test]
    fn header_opt_in_does_not_activate_extensions_or_change_ordinary_calls() {
        let core = request("tools/call", json!({"name":"lookup","arguments":{"region":"eu"}}));
        let (ordinary, _) = prepare_optional(TARGET, core.clone(), RequestId::Number(17), ManagedCoreLimits::default(), None).unwrap();
        assert!(!ordinary.headers().iter().any(|(name, _)| name.starts_with("Mcp-Param-")));
        let mut params = core.encode_params().unwrap().unwrap();
        params["_meta"]["io.modelcontextprotocol/clientCapabilities"]["extensions"] = json!({"io.modelcontextprotocol/tasks":{}});
        let core = CoreRequest::decode(ProtocolEra::Modern2026, "tools/call", Some(&params)).unwrap();
        assert!(matches!(prepare_optional(TARGET, core, RequestId::Number(17), ManagedCoreLimits::default(), Some(&review())),
            Err(ManagedToolHeaderError::Core(ManagedCoreError::UnsupportedRequest))));
    }

    fn challenge(original: &CoreRequest, state: Option<&str>) -> fastmcp_protocol::InputRequiredResult {
        let mut value = json!({"resultType":"input_required", "inputRequests":{
            "one":{"method":"roots/list"}, "two":{"method":"roots/list"}
        }});
        if let Some(state) = state { value["requestState"] = json!(state); }
        let result = original.decode_result(&value.to_string()).unwrap();
        super::super::interaction::input_required(&result).unwrap().clone()
    }

    fn continuation_source() -> CoreRequest {
        let original = request("tools/call", json!({"name":"lookup", "arguments":{"region":"eu", "private":"body-only"}}));
        let mut params = original.encode_params().unwrap().unwrap();
        params["_meta"]["io.modelcontextprotocol/clientCapabilities"] = json!({"roots":{}});
        CoreRequest::decode(ProtocolEra::Modern2026, "tools/call", Some(&params)).unwrap()
    }

    #[test]
    fn full_and_partial_continuations_project_only_immutable_original_arguments() {
        use super::super::interaction::{InputSelection, continuation_request_selected};
        let original = continuation_source();
        let before = original.encode_params().unwrap().unwrap();
        let input = challenge(&original, Some("  opaque\0  "));
        let review = review();
        for (selection, answers) in [
            (InputSelection::Complete, json!({"one":{"roots":[]},"two":{"roots":[]}})),
            (InputSelection::Partial, json!({"two":{"roots":[]}})),
        ] {
            let next = continuation_request_selected(&original, &input,
                Some(serde_json::from_value(answers.clone()).unwrap()), selection).unwrap();
            let (wire, _) = prepare_optional(TARGET, next, RequestId::Number(18), ManagedCoreLimits::default(), Some(&review)).unwrap();
            let encoded: Value = serde_json::from_slice(wire.body()).unwrap();
            assert_eq!(encoded["params"]["arguments"], before["arguments"]);
            assert_eq!(encoded["params"]["_meta"], before["_meta"]);
            assert_eq!(encoded["params"]["inputResponses"], answers);
            assert_eq!(encoded["params"]["requestState"], "  opaque\0  ");
            let fields: Vec<_> = wire.headers().into_iter().filter(|(name, _)| name.starts_with("Mcp-Param-")).collect();
            assert_eq!(fields, vec![("Mcp-Param-Region".to_owned(), "eu".to_owned())]);
        }
        assert_eq!(original.encode_params().unwrap().unwrap(), before);
    }

    #[test]
    fn invalid_partial_answers_never_become_a_header_bearing_continuation() {
        use super::super::interaction::{InputSelection, continuation_request_selected};
        let original = continuation_source();
        let before = original.encode_params().unwrap().unwrap();
        for (input, answers) in [
            (challenge(&original, None), json!({"one":{"roots":[]}})),
            (challenge(&original, Some("state")), json!({"foreign":{"roots":[]}})),
            (challenge(&original, Some("state")), json!({})),
        ] {
            assert!(continuation_request_selected(&original, &input,
                Some(serde_json::from_value(answers).unwrap()), InputSelection::Partial).is_err());
        }
        assert_eq!(original.encode_params().unwrap().unwrap(), before);
    }

    #[test]
    fn reply_recovery_changes_the_rpc_id_but_not_the_projected_headers_or_params() {
        use super::super::interaction::continuation_request;
        let original = continuation_source();
        let input = challenge(&original, Some("journal-state"));
        let answers = serde_json::from_value(json!({"one":{"roots":[]},"two":{"roots":[]}})).unwrap();
        let request = continuation_request(&original, &input, Some(answers)).unwrap();
        let review = review();
        let (first, _) = prepare_optional(TARGET, request.clone(), RequestId::Number(18), ManagedCoreLimits::default(), Some(&review)).unwrap();
        let (next, _) = prepare_optional(TARGET, request, RequestId::Number(19), ManagedCoreLimits::default(), Some(&review)).unwrap();
        let first_body: Value = serde_json::from_slice(first.body()).unwrap();
        let next_body: Value = serde_json::from_slice(next.body()).unwrap();
        assert_ne!(first_body["id"], next_body["id"]);
        assert_eq!(first_body["params"], next_body["params"]);
        assert_eq!(first.headers(), next.headers());
    }

    #[test]
    fn state_only_continuation_keeps_absence_and_still_projects_the_original_input() {
        use super::super::interaction::{continuation_request, input_required};
        let original = continuation_source();
        let result = original.decode_result(r#"{"resultType":"input_required","requestState":""}"#).unwrap();
        let next = continuation_request(&original, input_required(&result).unwrap(), None).unwrap();
        let (wire, _) = prepare_optional(TARGET, next, RequestId::Number(18), ManagedCoreLimits::default(), Some(&review())).unwrap();
        let value: Value = serde_json::from_slice(wire.body()).unwrap();
        assert_eq!(value["params"]["requestState"], "");
        assert!(value["params"].get("inputResponses").is_none());
        assert!(wire.headers().iter().any(|(name, value)| name == "Mcp-Param-Region" && value == "eu"));
    }
}
