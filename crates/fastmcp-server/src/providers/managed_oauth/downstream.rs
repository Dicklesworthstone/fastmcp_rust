//! Opt-in forwarding of authenticated upstream inputs to the downstream client.
//!
//! The server owns every continuation. It seals upstream request state together
//! with the effective input capabilities; clients receive only a fresh,
//! principal- and operation-bound, one-use server token. Each resumed request
//! is reauthorized by the server before typed answers reach this adapter.
//!
//! Only an explicit local allowlist intersected with the admitted downstream
//! capabilities is advertised. Credentials, identity, extensions and arbitrary
//! request metadata are never copied from the downstream client. The managed
//! login remains a service account, not delegated downstream authentication.
//!
//! Native call limits apply to each POST. The server's MRTR retention, round,
//! input and byte limits bound the cross-POST conversation; this does not extend
//! the managed client's single-operation timeout across downstream pauses.

use std::sync::Arc;

use asupersync::Cx;
use fastmcp_client::http_auth::rpc::ManagedCoreLimits;
use fastmcp_client::http_executor::parameter_headers::ReviewedToolHeaders;
use fastmcp_core::{McpContext, McpError, McpResult};
use fastmcp_protocol::{
    CoreRequest, FinalCoreResult, FinalEmbeddedElicitationParams, FinalEmbeddedInputRequest,
    InputRequiredResult, RequestId, ResultMeta, exact_json_to_serde,
};
use serde_json::Value;

use super::interaction::ManagedOAuthInputCapabilities;
use super::{
    BoxFuture, CoreBackend, FINAL_CLIENT_CAPABILITIES_META_KEY, Forwarder, ManagedOAuthProvider,
    ProtocolEra, check_cx,
};
use crate::bidirectional::{
    DEFAULT_MAX_MRTR_REQUEST_STATE_BYTES, MrtrCompletedInputs, MrtrInputKind, MrtrInputRequest,
    MrtrInputRequests,
};

const INPUT_MODE_CONFLICT: &str =
    "Managed OAuth host and downstream input modes cannot be combined";
const INPUT_REJECTED: &str = "Authenticated upstream input is not permitted";
const CONTINUATION_REJECTED: &str = "Managed OAuth continuation is invalid or no longer authorized";
const CONTINUATION_VERSION: &str = "fastmcp.managed-oauth.mrtr/v1";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum InputMode {
    Complete,
    Host,
    Downstream,
    Conflicting,
}

impl ManagedOAuthProvider {
    /// Lets subsequently collected handlers ask their admitted downstream client
    /// for roots, sampling or elicitation, within this explicit local allowlist.
    ///
    /// Capabilities are rebuilt from the intersection on every request. An
    /// unadvertised capability cannot be enabled by this policy, and downstream
    /// identity, extensions, credentials and open metadata are never forwarded.
    /// Sampling tools/context imply basic sampling permission as in the local
    /// input-handler policy. Unsupported context requests are refused rather
    /// than broadening a disclosure permission.
    ///
    /// Tools, concrete resources, templates and prompts use the server's bounded
    /// MRTR registry. Upstream state stays private, and only framework-admitted
    /// typed answers resume it. A retry must retain the same effective input
    /// capabilities. Complete results keep their existing exact payloads.
    /// Catalogs, completions and resource-update subscriptions remain unchanged.
    ///
    /// Host-resolved and downstream-resolved inputs are mutually exclusive.
    /// Selecting this mode after `with_input_handler` returns an error. Selecting
    /// `with_input_handler` afterwards leaves an invalid configuration, detectable
    /// with [Self::validate_input_mode], which refuses all subsequent acquisition
    /// and execution before credential renewal, network contact or callbacks.
    /// Existing clones and previously collected handlers retain their own mode.
    pub fn with_downstream_inputs(
        mut self,
        allowed: ManagedOAuthInputCapabilities,
    ) -> McpResult<Self> {
        self.forwarder = enable_downstream_inputs(&self.forwarder, allowed)?;
        Ok(self)
    }

    /// Checks that host and downstream input resolution were not both selected.
    /// The same check precedes every provider acquisition and handler execution.
    /// It performs no credential, callback or network work.
    pub fn validate_input_mode(&self) -> McpResult<()> {
        self.forwarder.validate_input_mode()
    }
}

/// Both managed login and machine grants use the same sealed continuation
/// boundary. Only the independently authenticated inner backend differs.
pub(super) fn enable_downstream_inputs(
    forwarder: &Arc<Forwarder>,
    allowed: ManagedOAuthInputCapabilities,
) -> McpResult<Arc<Forwarder>> {
    forwarder.validate_input_mode()?;
    if forwarder.backend.input_mode() != InputMode::Complete {
        return Err(mode_conflict());
    }
    Ok(Arc::new(Forwarder {
        backend: Arc::new(DownstreamBackend {
            inner: Arc::clone(&forwarder.backend),
            allowed,
        }),
        next_id: Arc::clone(&forwarder.next_id),
        limits: forwarder.limits,
    }))
}

pub(super) fn mode_conflict() -> McpError {
    McpError::invalid_params(INPUT_MODE_CONFLICT)
}

pub(super) fn conflicting_backend() -> Arc<dyn CoreBackend> {
    Arc::new(ConflictingBackend)
}

struct ConflictingBackend;

impl CoreBackend for ConflictingBackend {
    fn input_mode(&self) -> InputMode {
        InputMode::Conflicting
    }

    fn execute<'a>(
        &'a self,
        _ctx: &'a McpContext,
        _cx: &'a Cx,
        _request: CoreRequest,
        _id: RequestId,
        _limits: ManagedCoreLimits,
    ) -> BoxFuture<'a, McpResult<FinalCoreResult>> {
        Box::pin(async { Err(mode_conflict()) })
    }
}

struct DownstreamBackend {
    inner: Arc<dyn CoreBackend>,
    allowed: ManagedOAuthInputCapabilities,
}

impl CoreBackend for DownstreamBackend {
    fn input_mode(&self) -> InputMode {
        InputMode::Downstream
    }

    fn with_reviewed_headers(
        &self,
        reviewed: Arc<ReviewedToolHeaders>,
    ) -> McpResult<Arc<dyn CoreBackend>> {
        Ok(Arc::new(Self {
            inner: self.inner.with_reviewed_headers(reviewed)?,
            allowed: self.allowed,
        }))
    }

    fn execute<'a>(
        &'a self,
        ctx: &'a McpContext,
        cx: &'a Cx,
        request: CoreRequest,
        id: RequestId,
        limits: ManagedCoreLimits,
    ) -> BoxFuture<'a, McpResult<FinalCoreResult>> {
        Box::pin(async move {
            ctx.checkpoint()?;
            check_cx(cx)?;
            if !matches!(
                request.method(),
                "tools/call" | "resources/read" | "prompts/get"
            ) {
                return self.inner.execute(ctx, cx, request, id, limits).await;
            }
            // Direct handler invocation must obey the same custody requirement
            // as router dispatch, before acquiring the upstream credential.
            if ctx.retained_continuation_partition().is_none() {
                return Err(McpError::invalid_params(
                    "Managed OAuth downstream inputs require a retained continuation owner",
                ));
            }
            let capabilities = intersect_capabilities(self.allowed, ctx);
            let request = prepare_request(request, capabilities)?;
            let result = self.inner.execute(ctx, cx, request, id, limits).await;
            check_cx(cx)?;
            ctx.checkpoint()?;
            seal_result(result?, capabilities)
        })
    }
}

fn intersect_capabilities(
    allowed: ManagedOAuthInputCapabilities,
    ctx: &McpContext,
) -> ManagedOAuthInputCapabilities {
    let Some(inbound) = ctx.client_capabilities() else {
        return ManagedOAuthInputCapabilities::default();
    };
    let sampling = inbound.sampling
        && (allowed.sampling || allowed.sampling_tools || allowed.sampling_context);
    ManagedOAuthInputCapabilities {
        roots: allowed.roots && inbound.roots,
        sampling,
        sampling_tools: sampling && allowed.sampling_tools && inbound.sampling_tools.is_some(),
        sampling_context: sampling
            && allowed.sampling_context
            && inbound.sampling_context.is_some(),
        form_elicitation: allowed.form_elicitation
            && inbound.elicitation
            && inbound.elicitation_form,
        url_elicitation: allowed.url_elicitation && inbound.elicitation && inbound.elicitation_url,
    }
}

fn capability_bits(capabilities: ManagedOAuthInputCapabilities) -> u8 {
    u8::from(capabilities.roots)
        | (u8::from(capabilities.sampling) << 1)
        | (u8::from(capabilities.sampling_tools) << 2)
        | (u8::from(capabilities.sampling_context) << 3)
        | (u8::from(capabilities.form_elicitation) << 4)
        | (u8::from(capabilities.url_elicitation) << 5)
}

fn prepare_request(
    request: CoreRequest,
    capabilities: ManagedOAuthInputCapabilities,
) -> McpResult<CoreRequest> {
    let method = request.method();
    let mut parameters = request
        .encode_params()
        .map_err(|_| continuation_rejected())?
        .ok_or_else(continuation_rejected)?;
    let object = parameters
        .as_object_mut()
        .ok_or_else(continuation_rejected)?;
    if let Some(retained) = object.remove("requestState") {
        let retained = retained.as_str().ok_or_else(continuation_rejected)?;
        if retained.len() > DEFAULT_MAX_MRTR_REQUEST_STATE_BYTES {
            return Err(continuation_rejected());
        }
        let (version, bits, upstream): (String, u8, Option<String>) =
            serde_json::from_str(retained).map_err(|_| continuation_rejected())?;
        if version != CONTINUATION_VERSION || bits != capability_bits(capabilities) {
            return Err(continuation_rejected());
        }
        if let Some(upstream) = upstream {
            object.insert("requestState".to_owned(), Value::String(upstream));
        }
    }
    let metadata = object
        .get_mut("_meta")
        .and_then(Value::as_object_mut)
        .ok_or_else(continuation_rejected)?;
    // The containing request was reconstructed by this provider. Preserve its
    // own identity and control metadata; overwrite only the input declaration.
    let declared = metadata
        .get_mut(FINAL_CLIENT_CAPABILITIES_META_KEY)
        .and_then(Value::as_object_mut)
        .ok_or_else(continuation_rejected)?;
    for name in ["roots", "sampling", "elicitation"] {
        declared.remove(name);
    }
    let Value::Object(inputs) = capabilities.metadata() else {
        return Err(continuation_rejected());
    };
    declared.extend(inputs);
    CoreRequest::decode(ProtocolEra::Modern2026, method, Some(&parameters))
        .map_err(|_| continuation_rejected())
}

pub(super) fn overlay_resume(
    mut parameters: Value,
    resume: &MrtrCompletedInputs,
) -> McpResult<Value> {
    let object = parameters
        .as_object_mut()
        .ok_or_else(continuation_rejected)?;
    // This field is the private, registry-retained envelope, never a request
    // state's wire value supplied directly by the downstream peer.
    let retained = resume
        .handler_request_state()
        .ok_or_else(continuation_rejected)?;
    object.insert(
        "requestState".to_owned(),
        Value::String(retained.to_owned()),
    );
    if !resume.responses().is_empty() {
        let mut responses = serde_json::Map::new();
        for (key, response) in resume.responses().iter() {
            let value = match response.kind() {
                MrtrInputKind::Elicitation => serde_json::to_value(response.elicitation_result()?),
                MrtrInputKind::Sampling => serde_json::to_value(response.sampling_result()?),
                MrtrInputKind::Roots => serde_json::to_value(response.roots_result()?),
            }
            .map_err(|_| continuation_rejected())?;
            responses.insert(key.to_owned(), value);
        }
        object.insert("inputResponses".to_owned(), Value::Object(responses));
    }
    Ok(parameters)
}

fn seal_result(
    result: FinalCoreResult,
    capabilities: ManagedOAuthInputCapabilities,
) -> McpResult<FinalCoreResult> {
    Ok(match result {
        FinalCoreResult::ToolsCallInputRequired { result, .. } => {
            FinalCoreResult::ToolsCallInputRequired {
                result: seal_input(result, capabilities)?,
                diagnostic: None,
            }
        }
        FinalCoreResult::ResourcesReadInputRequired { result, .. } => {
            FinalCoreResult::ResourcesReadInputRequired {
                result: seal_input(result, capabilities)?,
                diagnostic: None,
            }
        }
        FinalCoreResult::PromptsGetInputRequired { result, .. } => {
            FinalCoreResult::PromptsGetInputRequired {
                result: seal_input(result, capabilities)?,
                diagnostic: None,
            }
        }
        other => other,
    })
}

fn seal_input(
    input: InputRequiredResult,
    capabilities: ManagedOAuthInputCapabilities,
) -> McpResult<InputRequiredResult> {
    if let Some(requests) = input.input_requests() {
        if requests.members().is_empty() {
            return Err(input_rejected());
        }
        let mut admitted = Vec::new();
        for member in requests.members() {
            let value = exact_json_to_serde(&member.value).map_err(|_| input_rejected())?;
            admit_descriptor(&value, capabilities)?;
            admitted.push((
                member.name.clone(),
                MrtrInputRequest::from_wire(&value).map_err(|_| input_rejected())?,
            ));
        }
        MrtrInputRequests::new(admitted).map_err(|_| input_rejected())?;
    }
    let retained = serde_json::to_string(&(
        CONTINUATION_VERSION,
        capability_bits(capabilities),
        input.request_state(),
    ))
    .map_err(|_| continuation_rejected())?;
    if retained.len() > DEFAULT_MAX_MRTR_REQUEST_STATE_BYTES {
        return Err(continuation_rejected());
    }
    // The router separately reconstructs all downstream result metadata and
    // its public one-use state. Inert upstream siblings never cross that seam.
    InputRequiredResult::new(
        input.input_requests().cloned(),
        Some(retained),
        ResultMeta::empty(),
    )
    .map_err(|_| input_rejected())
}

fn admit_descriptor(value: &Value, capabilities: ManagedOAuthInputCapabilities) -> McpResult<()> {
    if let Some(params) = value.get("params") {
        if !params.is_object() {
            return Err(input_rejected());
        }
        if value.get("method").and_then(Value::as_str) == Some("sampling/createMessage") {
            if params.get("tools").is_some_and(|tools| {
                !tools
                    .as_array()
                    .is_some_and(|tools| tools.iter().all(Value::is_object))
            }) || params.get("toolChoice").is_some_and(|choice| {
                !choice.is_object() || choice.get("mode").is_some_and(|mode| !mode.is_string())
            }) || params
                .get("includeContext")
                .is_some_and(|context| !context.is_string())
            {
                return Err(input_rejected());
            }
        }
    }
    let descriptor: FinalEmbeddedInputRequest =
        serde_json::from_value(value.clone()).map_err(|_| input_rejected())?;
    let allowed = match descriptor {
        FinalEmbeddedInputRequest::Roots(_) => capabilities.roots,
        FinalEmbeddedInputRequest::Sampling(params) => {
            capabilities.sampling
                && ((params.tools.is_none() && params.tool_choice.is_none())
                    || capabilities.sampling_tools)
                && (params
                    .include_context
                    .is_none_or(|context| context == fastmcp_protocol::IncludeContext::None)
                    || capabilities.sampling_context)
        }
        FinalEmbeddedInputRequest::Elicitation(FinalEmbeddedElicitationParams::Form(_)) => {
            capabilities.form_elicitation
        }
        FinalEmbeddedInputRequest::Elicitation(FinalEmbeddedElicitationParams::Url(_)) => {
            capabilities.url_elicitation
        }
    };
    if allowed {
        Ok(())
    } else {
        Err(input_rejected())
    }
}

fn input_rejected() -> McpError {
    McpError::invalid_request(INPUT_REJECTED)
}

fn continuation_rejected() -> McpError {
    McpError::invalid_params(CONTINUATION_REJECTED)
}

#[cfg(test)]
mod tests;
