//! Explicitly reviewed, resource-bound tool parameter-header dispatch.
//!
//! A schema describes projection, never permission to disclose arguments. The
//! host must approve every compiled binding before this module will retain a
//! plan. Projection reads the immutable outgoing JSON-RPC bytes, not a separate
//! argument map. No schema lookup, credential acquisition, retry or I/O occurs
//! during plan construction or projection. The explicit high-level client
//! exchange APIs compose these plans with bounded catalog repair and MRTR.
//!
//! The host owns catalog freshness and disclosure policy. A changed definition
//! or policy requires a new review; retaining a plan does not make it current.
//! This module does not authorize execution or validate the entire invocation.

use std::collections::BTreeMap;
use std::fmt;
use std::net::IpAddr;
use std::sync::{Arc, PoisonError, RwLock};

use fastmcp_core::CanonicalHttpUrl;
use fastmcp_protocol::http_headers::{
    AdmittedToolHeaderSchema, MAX_MCP_HEADER_VALUE_BYTES, McpHeaderError, ParameterHeaderBinding,
};
use fastmcp_protocol::protocol_policy::ProtocolEra;
use fastmcp_protocol::{
    CoreRequest, FINAL_PROTOCOL_VERSION, FINAL_PROTOCOL_VERSION_META_KEY, JsonRpcMessage,
    decode_strict_jsonrpc_message,
};
use serde_json::Value;

use super::ModernHttpRequest;

mod exchange;

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
            Self::TargetMismatch => "tool-header plan belongs to a different resource",
            Self::OperationMismatch => "tool-header plan does not match the request operation",
            Self::AlreadyProjected => "tool parameter headers were already installed",
            Self::InvalidRequest => {
                "tool-header projection requires an admitted final tool request"
            }
            Self::RequestTooLarge => "tool-header request exceeds the source-byte limit",
            Self::Projection(error) => return fmt::Display::fmt(error, f),
        })
    }
}

impl std::error::Error for ToolHeaderDispatchError {}

impl From<McpHeaderError> for ToolHeaderDispatchError {
    fn from(error: McpHeaderError) -> Self {
        Self::Projection(error)
    }
}

/// Immutable approval of one exact tool schema at one canonical resource.
///
/// [`Self::new`] requires HTTPS. Local applications can explicitly select
/// [`Self::new_for_loopback_http`] for a numeric loopback HTTP endpoint.
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
    /// Reviews a tool at an HTTPS resource. Cleartext targets, including
    /// loopback, are refused by this constructor.
    ///
    /// The callback reviews an exact property path, field name and primitive
    /// type. It receives no invocation values and must apply the host's local
    /// disclosure policy rather than trusting server annotations as consent.
    pub fn new(
        resource: CanonicalHttpUrl,
        tool_name: impl Into<String>,
        schema: Value,
        review: impl FnMut(&ParameterHeaderBinding) -> bool,
    ) -> Result<Self, ToolHeaderDispatchError> {
        if resource.scheme() != "https" {
            return Err(ToolHeaderDispatchError::InvalidBinding);
        }
        Self::review_resource(resource, tool_name.into(), schema, review)
    }

    /// Explicitly reviews a tool at a numeric loopback HTTP resource.
    ///
    /// This is intended for a host-controlled local server. It is not a TLS
    /// substitute: loopback provides neither peer authentication nor secrecy
    /// from other local processes. The caller must trust that local endpoint
    /// and approve each disclosed binding just as for [`Self::new`].
    ///
    /// Only canonical IPv4/IPv6 loopback literals are admitted. DNS names
    /// (including `localhost`), unspecified, private and public non-loopback
    /// addresses, and IPv4-mapped IPv6 addresses are refused before review.
    /// No DNS lookup or change to transport/credential policy occurs. A plan
    /// remains bound to the entire canonical URL, including port/path/query;
    /// it cannot be reused for another endpoint or an HTTPS-to-HTTP downgrade.
    pub fn new_for_loopback_http(
        resource: CanonicalHttpUrl,
        tool_name: impl Into<String>,
        schema: Value,
        review: impl FnMut(&ParameterHeaderBinding) -> bool,
    ) -> Result<Self, ToolHeaderDispatchError> {
        let host = resource.host();
        let literal = host
            .strip_prefix('[')
            .and_then(|host| host.strip_suffix(']'))
            .unwrap_or(host);
        if resource.scheme() != "http"
            || !literal.parse::<IpAddr>().is_ok_and(|ip| ip.is_loopback())
        {
            return Err(ToolHeaderDispatchError::InvalidBinding);
        }
        Self::review_resource(resource, tool_name.into(), schema, review)
    }

    fn review_resource(
        resource: CanonicalHttpUrl,
        tool_name: String,
        schema: Value,
        mut review: impl FnMut(&ParameterHeaderBinding) -> bool,
    ) -> Result<Self, ToolHeaderDispatchError> {
        if resource.has_userinfo()
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
        Ok(Self {
            resource,
            tool_name,
            schema,
        })
    }

    pub fn resource(&self) -> &CanonicalHttpUrl {
        &self.resource
    }
    pub fn tool_name(&self) -> &str {
        &self.tool_name
    }
    pub fn schema(&self) -> &Value {
        self.schema.schema()
    }
    pub fn bindings(&self) -> &[ParameterHeaderBinding] {
        self.schema.header_plan().bindings()
    }

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
    if request.protocol_version != FINAL_PROTOCOL_VERSION
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
    let params = envelope
        .params
        .as_ref()
        .and_then(Value::as_object)
        .ok_or(ToolHeaderDispatchError::InvalidRequest)?;
    if params.get("name").and_then(Value::as_str) != Some(tool_name) {
        return Err(ToolHeaderDispatchError::OperationMismatch);
    }
    if params
        .get("_meta")
        .and_then(|meta| meta.get(FINAL_PROTOCOL_VERSION_META_KEY))
        .and_then(Value::as_str)
        != Some(FINAL_PROTOCOL_VERSION)
    {
        return Err(ToolHeaderDispatchError::InvalidRequest);
    }
    // Raw duplicate/batch admission precedes typed method/metadata admission.
    // Neither decoder rewrites the immutable body which the executor sends.
    let _ = CoreRequest::decode(
        ProtocolEra::Modern2026,
        "tools/call",
        envelope.params.as_ref(),
    )
    .map_err(|_| ToolHeaderDispatchError::InvalidRequest)?;
    Ok(schema
        .header_plan()
        .project(params.get("arguments"))?
        .into_fields())
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
        let plans = catalog
            .into_iter()
            .filter_map(|(name, schema)| {
                let admitted = AdmittedToolHeaderSchema::admit(schema.clone()).ok()?;
                (!admitted.header_plan().bindings().is_empty())
                    .then(|| (name.to_owned(), Arc::new(admitted)))
            })
            .collect();
        *self.plans.write().unwrap_or_else(PoisonError::into_inner) = plans;
    }

    fn plan(&self, tool_name: &str) -> Option<Arc<AdmittedToolHeaderSchema>> {
        self.plans
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .get(tool_name)
            .cloned()
    }
}

impl fmt::Debug for GatewayToolHeaders {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let plans = self
            .plans
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .len();
        f.debug_struct("GatewayToolHeaders")
            .field("plan_count", &plans)
            .finish()
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
        let headers =
            project_exact_tool_call(&self, self.name.as_deref().unwrap_or_default(), &schema)?;
        self.parameter_headers = Some(headers);
        Ok(self)
    }
}

#[cfg(test)]
mod tests;

#[cfg(test)]
mod loopback_tests {
    use super::*;
    use fastmcp_protocol::{ClientCapabilities, FinalRequestMeta};
    use serde_json::json;

    fn schema() -> Value {
        json!({"type":"object","properties":{
            "region":{"type":"string","x-mcp-header":"Region"}
        }})
    }

    fn request(target: &str) -> ModernHttpRequest {
        let body = serde_json::to_vec(&json!({
            "jsonrpc":"2.0", "id":1, "method":"tools/call",
            "params":{
                "name":"lookup", "arguments":{"region":"eu", "private":"body-only"},
                "_meta":FinalRequestMeta::new(ClientCapabilities::default())
            }
        }))
        .unwrap();
        ModernHttpRequest::new(
            target,
            body,
            FINAL_PROTOCOL_VERSION,
            "tools/call",
            Some("lookup".to_owned()),
        )
        .unwrap()
    }

    #[test]
    fn explicit_loopback_projection_preserves_body_and_https_only_default() {
        for target in ["http://127.0.0.1:8123/mcp", "http://[::1]:8123/mcp"] {
            let resource = CanonicalHttpUrl::parse(target).unwrap();
            let mut calls = 0;
            assert!(matches!(
                ReviewedToolHeaders::new(resource.clone(), "lookup", schema(), |_| {
                    calls += 1;
                    true
                }),
                Err(ToolHeaderDispatchError::InvalidBinding)
            ));
            assert_eq!(calls, 0);
            let plan = ReviewedToolHeaders::new_for_loopback_http(
                resource,
                "lookup",
                schema(),
                |binding| {
                    calls += 1;
                    binding.header_name() == "Mcp-Param-Region"
                },
            )
            .unwrap();
            assert_eq!(calls, 1);
            let original = request(target);
            let projected = original.clone().with_reviewed_tool_headers(&plan).unwrap();
            assert_eq!(projected.body(), original.body());
            let parameters: Vec<_> = projected
                .headers()
                .into_iter()
                .filter(|(name, _)| name.starts_with("Mcp-Param-"))
                .collect();
            assert_eq!(
                parameters,
                vec![("Mcp-Param-Region".to_owned(), "eu".to_owned())]
            );
            assert!(
                !projected
                    .headers()
                    .iter()
                    .any(|(_, value)| value.contains("body-only"))
            );
            assert!(matches!(
                projected.with_reviewed_tool_headers(&plan),
                Err(ToolHeaderDispatchError::AlreadyProjected)
            ));
        }
    }

    #[test]
    fn loopback_constructor_rejects_untrusted_targets_before_review() {
        for target in [
            "http://localhost:8123/mcp",
            "http://localhost.example:8123/mcp",
            "http://127.0.0.1.example:8123/mcp",
            "http://0.0.0.0:8123/mcp",
            "http://192.168.1.1:8123/mcp",
            "http://192.0.2.1:8123/mcp",
            "http://[::]:8123/mcp",
            "http://[2001:db8::1]:8123/mcp",
            "http://[::ffff:127.0.0.1]:8123/mcp",
            "http://user@127.0.0.1:8123/mcp",
            "http://127.0.0.1:8123/mcp#",
            "https://127.0.0.1:8123/mcp",
        ] {
            let mut calls = 0;
            assert!(
                matches!(
                    ReviewedToolHeaders::new_for_loopback_http(
                        CanonicalHttpUrl::parse(target).unwrap(),
                        "lookup",
                        schema(),
                        |_| {
                            calls += 1;
                            true
                        }
                    ),
                    Err(ToolHeaderDispatchError::InvalidBinding)
                ),
                "{target}"
            );
            assert_eq!(calls, 0, "{target}");
        }
    }

    #[test]
    fn loopback_review_keeps_schema_and_disclosure_gates() {
        let resource = CanonicalHttpUrl::parse("http://127.0.0.1:8123/mcp").unwrap();
        assert!(matches!(
            ReviewedToolHeaders::new_for_loopback_http(
                resource.clone(),
                "lookup",
                schema(),
                |_| false
            ),
            Err(ToolHeaderDispatchError::DisclosureDenied)
        ));
        for source in [
            json!({"type":"string"}),
            json!({"type":"object","properties":{
                "region":{"type":"object","x-mcp-header":"Region"}
            }}),
            json!({"type":"object","properties":{
                "region":{"type":"string","x-mcp-header":"Region"},
                "other":{"type":"string","x-mcp-header":"region"}
            }}),
        ] {
            let mut calls = 0;
            assert!(
                ReviewedToolHeaders::new_for_loopback_http(
                    resource.clone(),
                    "lookup",
                    source,
                    |_| {
                        calls += 1;
                        true
                    }
                )
                .is_err()
            );
            assert_eq!(calls, 0);
        }
    }

    #[test]
    fn loopback_plan_cannot_cross_port_path_query_address_or_scheme() {
        let target = "http://127.0.0.1:8123/mcp";
        let plan = ReviewedToolHeaders::new_for_loopback_http(
            CanonicalHttpUrl::parse(target).unwrap(),
            "lookup",
            schema(),
            |_| true,
        )
        .unwrap();
        assert!(request(target).with_reviewed_tool_headers(&plan).is_ok());
        for other in [
            "http://127.0.0.1:8124/mcp",
            "http://127.0.0.1:8123/other",
            "http://127.0.0.1:8123/mcp?tenant=other",
            "http://127.0.0.2:8123/mcp",
            "http://[::1]:8123/mcp",
            "https://127.0.0.1:8123/mcp",
        ] {
            let original = request(other);
            assert!(matches!(
                original.clone().with_reviewed_tool_headers(&plan),
                Err(ToolHeaderDispatchError::TargetMismatch)
            ));
            assert!(
                !original
                    .headers()
                    .iter()
                    .any(|(name, _)| name.starts_with("Mcp-Param-"))
            );
        }
    }
}
