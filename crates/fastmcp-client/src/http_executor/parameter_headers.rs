//! Explicitly reviewed, resource-bound tool parameter-header dispatch.
//!
//! A schema describes projection, never permission to disclose arguments. The
//! host must approve every compiled binding before this module will retain a
//! plan. Projection reads the immutable outgoing JSON-RPC bytes, not a separate
//! argument map. No schema lookup, credential acquisition, retry or I/O occurs.
//!
//! The host owns catalog freshness and disclosure policy. A changed definition
//! or policy requires a new review; retaining a plan does not make it current.
//! This module does not authorize execution or validate the entire invocation.

use std::collections::BTreeMap;
use std::fmt;
use std::sync::{Arc, PoisonError, RwLock};

use fastmcp_core::CanonicalHttpUrl;
use fastmcp_protocol::http_headers::{
    AdmittedToolHeaderSchema, MAX_MCP_HEADER_VALUE_BYTES, McpHeaderError,
    ParameterHeaderBinding,
};
use fastmcp_protocol::protocol_policy::ProtocolEra;
use fastmcp_protocol::{
    CoreRequest, FINAL_PROTOCOL_VERSION, FINAL_PROTOCOL_VERSION_META_KEY,
    JsonRpcMessage, decode_strict_jsonrpc_message,
};
use serde_json::Value;

use super::ModernHttpRequest;

/// Hard ceiling for duplicate-aware admission of the exact outgoing body.
pub const MAX_TOOL_HEADER_REQUEST_BYTES: usize = 8 * 1024 * 1024;

/// Diagnostics never retain a resource, schema, binding, or argument value.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ToolHeaderDispatchError {
    InvalidBinding,
    DisclosureDenied,
    TargetMismatch,
    OperationMismatch,
    AlreadyProjected,
    InvalidRequest,
    RequestTooLarge,
    Projection(McpHeaderError),
}

impl fmt::Display for ToolHeaderDispatchError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::InvalidBinding => "invalid tool-header resource or name binding",
            Self::DisclosureDenied => "tool parameter-header disclosure was not approved",
            Self::TargetMismatch => "tool-header plan belongs to a different HTTPS resource",
            Self::OperationMismatch => "tool-header plan does not match the request operation",
            Self::AlreadyProjected => "tool parameter headers were already installed",
            Self::InvalidRequest => "tool-header projection requires an admitted final tool request",
            Self::RequestTooLarge => "tool-header request exceeds the source-byte limit",
            Self::Projection(error) => return fmt::Display::fmt(error, f),
        })
    }
}

impl std::error::Error for ToolHeaderDispatchError {}

impl From<McpHeaderError> for ToolHeaderDispatchError {
    fn from(error: McpHeaderError) -> Self { Self::Projection(error) }
}

/// Immutable approval of one exact tool schema at one canonical HTTPS resource.
///
/// No arbitrary header map can be installed. The complete source is admitted
/// before the first review callback. Rejecting any binding rejects the plan,
/// including previously approved siblings. Unannotated arguments remain body
/// data. This value is deliberately neither Clone nor serializable; an owner
/// may explicitly share it through an Arc without sharing invocation data.
pub struct ReviewedToolHeaders {
    resource: CanonicalHttpUrl,
    tool_name: String,
    schema: AdmittedToolHeaderSchema,
}

impl ReviewedToolHeaders {
    /// The callback reviews an exact property path, field name and primitive
    /// type. It receives no invocation values and must apply the host's local
    /// disclosure policy rather than trusting server annotations as consent.
    pub fn new(
        resource: CanonicalHttpUrl,
        tool_name: impl Into<String>,
        schema: Value,
        mut review: impl FnMut(&ParameterHeaderBinding) -> bool,
    ) -> Result<Self, ToolHeaderDispatchError> {
        let tool_name = tool_name.into();
        if resource.scheme() != "https"
            || resource.has_userinfo()
            || resource.fragment().is_some()
            || resource.as_str().len() > MAX_MCP_HEADER_VALUE_BYTES
            || tool_name.is_empty()
            || tool_name.len() > MAX_MCP_HEADER_VALUE_BYTES
            || tool_name.bytes().any(|byte| byte < 0x20 || byte == 0x7f)
        {
            return Err(ToolHeaderDispatchError::InvalidBinding);
        }
        if schema.get("type").and_then(Value::as_str) != Some("object") {
            return Err(McpHeaderError::InvalidSchema.into());
        }
        let schema = AdmittedToolHeaderSchema::admit(schema)?;
        for binding in schema.header_plan().bindings() {
            if !review(binding) {
                return Err(ToolHeaderDispatchError::DisclosureDenied);
            }
        }
        Ok(Self { resource, tool_name, schema })
    }

    pub fn resource(&self) -> &CanonicalHttpUrl { &self.resource }
    pub fn tool_name(&self) -> &str { &self.tool_name }
    pub fn schema(&self) -> &Value { self.schema.schema() }
    pub fn bindings(&self) -> &[ParameterHeaderBinding] { self.schema.header_plan().bindings() }

    fn project_request(
        &self,
        request: &ModernHttpRequest,
    ) -> Result<Vec<(String, String)>, ToolHeaderDispatchError> {
        if request.parameter_headers.is_some() {
            return Err(ToolHeaderDispatchError::AlreadyProjected);
        }
        let target = CanonicalHttpUrl::parse(request.target())
            .map_err(|_| ToolHeaderDispatchError::TargetMismatch)?;
        if target != self.resource {
            return Err(ToolHeaderDispatchError::TargetMismatch);
        }
        project_exact_tool_call(request, &self.tool_name, &self.schema)
    }
}

/// Projects `schema`'s mirrors from the exact outgoing `tools/call` body of
/// `request` for `tool_name`. The body is admitted as the executor will send it;
/// no separate argument map is read, so the fields cannot disagree with it.
fn project_exact_tool_call(
    request: &ModernHttpRequest,
    tool_name: &str,
    schema: &AdmittedToolHeaderSchema,
) -> Result<Vec<(String, String)>, ToolHeaderDispatchError> {
    if request.parameter_headers.is_some() {
        return Err(ToolHeaderDispatchError::AlreadyProjected);
    }
    if !request.include_method_header
        || request.protocol_version != FINAL_PROTOCOL_VERSION
        || request.method != "tools/call"
        || request.name.as_deref() != Some(tool_name)
    {
        return Err(ToolHeaderDispatchError::OperationMismatch);
    }
    if request.body().len() > MAX_TOOL_HEADER_REQUEST_BYTES {
        return Err(ToolHeaderDispatchError::RequestTooLarge);
    }
    let message = decode_strict_jsonrpc_message(request.body(), MAX_TOOL_HEADER_REQUEST_BYTES)
        .map_err(|_| ToolHeaderDispatchError::InvalidRequest)?;
    let JsonRpcMessage::Request(envelope) = message else {
        return Err(ToolHeaderDispatchError::InvalidRequest);
    };
    if envelope.id.is_none() || envelope.method != request.method {
        return Err(ToolHeaderDispatchError::InvalidRequest);
    }
    let params = envelope.params.as_ref().and_then(Value::as_object)
        .ok_or(ToolHeaderDispatchError::InvalidRequest)?;
    if params.get("name").and_then(Value::as_str) != Some(tool_name) {
        return Err(ToolHeaderDispatchError::OperationMismatch);
    }
    if params.get("_meta").and_then(|meta| meta.get(FINAL_PROTOCOL_VERSION_META_KEY))
        .and_then(Value::as_str) != Some(FINAL_PROTOCOL_VERSION)
    {
        return Err(ToolHeaderDispatchError::InvalidRequest);
    }
    // Raw duplicate/batch admission precedes typed method/metadata admission.
    // Neither decoder rewrites the immutable body which the executor sends.
    let _ = CoreRequest::decode(ProtocolEra::Modern2026, "tools/call", envelope.params.as_ref())
        .map_err(|_| ToolHeaderDispatchError::InvalidRequest)?;
    Ok(schema.header_plan().project(params.get("arguments"))?.into_fields())
}

/// A gateway's `Mcp-Param-*` recomputation plans for one upstream, keyed by the
/// exact upstream tool name and built from that upstream's validated
/// `tools/list` input schemas (PXY-04).
///
/// A `tools/call` for a planned tool gets its mirrors projected from the exact
/// outgoing body, exactly as [`ReviewedToolHeaders`] does, but with no HTTPS or
/// review gate: the gateway mirrors arguments it already sends in that body to
/// the same upstream, so the fields disclose nothing the body does not. The
/// downstream's own fields are never involved. Debug reports a count only.
#[derive(Default)]
pub struct GatewayToolHeaders {
    plans: RwLock<BTreeMap<String, Arc<AdmittedToolHeaderSchema>>>,
}

impl GatewayToolHeaders {
    /// Replaces every plan with those of one complete upstream `tools/list`
    /// catalog of `(name, inputSchema)` pairs, so a tool that left the catalog
    /// leaves no plan behind. A schema with no admissible annotation recognizes
    /// nothing, as on the server, so its tool gets no plan rather than a guess.
    pub fn replace<'a>(&self, catalog: impl IntoIterator<Item = (&'a str, &'a Value)>) {
        let plans = catalog.into_iter()
            .filter_map(|(name, schema)| {
                let admitted = AdmittedToolHeaderSchema::admit(schema.clone()).ok()?;
                (!admitted.header_plan().bindings().is_empty())
                    .then(|| (name.to_owned(), Arc::new(admitted)))
            })
            .collect();
        *self.plans.write().unwrap_or_else(PoisonError::into_inner) = plans;
    }

    fn plan(&self, tool_name: &str) -> Option<Arc<AdmittedToolHeaderSchema>> {
        self.plans.read().unwrap_or_else(PoisonError::into_inner).get(tool_name).cloned()
    }
}

impl fmt::Debug for GatewayToolHeaders {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let plans = self.plans.read().unwrap_or_else(PoisonError::into_inner).len();
        f.debug_struct("GatewayToolHeaders").field("plan_count", &plans).finish()
    }
}

impl fmt::Debug for ReviewedToolHeaders {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ReviewedToolHeaders")
            .field("binding_count", &self.bindings().len())
            .finish_non_exhaustive()
    }
}

impl ModernHttpRequest {
    /// Atomically installs reviewed fields from this request's exact body.
    /// An empty projection also seals the request against replacing its plan.
    /// Body bytes, credentials and routing identity are not replaced.
    ///
    /// Execute the returned request through the existing native/managed APIs.
    /// Their authentication, TLS, cancellation and response bounds remain in
    /// force. Explicit `headers()` output contains disclosed values, just as
    /// it can already contain a credential, and must not be logged casually.
    pub fn with_reviewed_tool_headers(
        mut self,
        reviewed: &ReviewedToolHeaders,
    ) -> Result<Self, ToolHeaderDispatchError> {
        let headers = reviewed.project_request(&self)?;
        self.parameter_headers = Some(headers);
        Ok(self)
    }

    /// Installs a gateway's recomputed mirrors when this is a `tools/call` for
    /// a planned upstream tool. Every other request is returned unchanged.
    pub(crate) fn with_gateway_tool_headers(
        mut self,
        gateway: &GatewayToolHeaders,
    ) -> Result<Self, ToolHeaderDispatchError> {
        if self.method != "tools/call" {
            return Ok(self);
        }
        let Some(schema) = self.name.as_deref().and_then(|name| gateway.plan(name)) else {
            return Ok(self);
        };
        let headers = project_exact_tool_call(&self, self.name.as_deref().unwrap_or_default(), &schema)?;
        self.parameter_headers = Some(headers);
        Ok(self)
    }
}

#[cfg(test)]
mod tests;
