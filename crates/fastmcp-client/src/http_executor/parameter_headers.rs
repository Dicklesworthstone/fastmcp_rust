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
/// including previously approved siblings. A `writeOnly` or password-formatted
/// field, or a field inside such an object, cannot be approved for disclosure.
/// These checks precede every callback, even when the secret is a later binding.
/// Unannotated arguments remain body data. This value is deliberately neither
/// Clone nor serializable; an owner may explicitly share it through an Arc
/// without sharing invocation data.
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
        if header_plan_discloses_secret(&schema) {
            return Err(ToolHeaderDispatchError::DisclosureDenied);
        }
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

// The shared compiler resolves effective confidentiality once, including every
// containing object. Server registration, explicit client reviews and automatic
// gateway projection must consume that same decision rather than reinterpreting
// schema traversal or policy independently at each call site.
fn header_plan_discloses_secret(schema: &AdmittedToolHeaderSchema) -> bool {
    schema
        .header_plan()
        .bindings()
        .iter()
        .any(ParameterHeaderBinding::marks_secret_field)
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
    // Gateway plans come directly from an upstream catalog rather than from a
    // host review. Enforce the same non-overridable policy at their common
    // dispatch boundary, before producing even one field from the body.
    if header_plan_discloses_secret(schema) {
        return Err(ToolHeaderDispatchError::DisclosureDenied);
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
/// outgoing body, exactly as [`ReviewedToolHeaders`] does, without requiring a
/// caller review callback. This does not grant permission to expose secrets in
/// headers: a plan selecting a `writeOnly` or password-marked field, including
/// one inside a secret object, fails request preparation as a whole. The
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
    /// Secret-selecting plans remain identifiable and are refused at dispatch;
    /// they must not silently become an unplanned call with missing mirrors.
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
mod secret_exposure_tests {
    use super::*;
    use fastmcp_protocol::{ClientCapabilities, FinalRequestMeta};
    use serde_json::json;

    fn review(
        schema: Value,
        loopback: bool,
        calls: &mut usize,
    ) -> Result<ReviewedToolHeaders, ToolHeaderDispatchError> {
        let approve = |_: &ParameterHeaderBinding| {
            *calls += 1;
            true
        };
        if loopback {
            ReviewedToolHeaders::new_for_loopback_http(
                CanonicalHttpUrl::parse("http://127.0.0.1:8123/mcp").unwrap(),
                "lookup",
                schema,
                approve,
            )
        } else {
            ReviewedToolHeaders::new(
                CanonicalHttpUrl::parse("https://tools.example/mcp").unwrap(),
                "lookup",
                schema,
                approve,
            )
        }
    }

    #[test]
    fn secret_primitive_headers_are_denied_before_any_review() {
        for property in [
            json!({"type":"string", "writeOnly":true, "x-mcp-header":"Secret"}),
            json!({"type":"integer", "writeOnly":true, "x-mcp-header":"Secret"}),
            json!({"type":"boolean", "writeOnly":true, "x-mcp-header":"Secret"}),
            json!({"type":"string", "format":"password", "x-mcp-header":"Secret"}),
            json!({"type":"string", "format":"PaSsWoRd", "x-mcp-header":"Secret"}),
        ] {
            // The public binding sorts first: the entire secret check must run
            // before an approving callback can observe even this safe sibling.
            let schema = json!({"type":"object", "properties":{
                "a_public":{"type":"string", "x-mcp-header":"Public"},
                "z_secret":property
            }});
            for loopback in [false, true] {
                let mut calls = 0;
                let error = review(schema.clone(), loopback, &mut calls).unwrap_err();
                assert_eq!(error, ToolHeaderDispatchError::DisclosureDenied);
                assert_eq!(calls, 0);
                assert!(!format!("{error:?} {error}").contains("z_secret"));
            }
        }
    }

    #[test]
    fn containing_secret_objects_cannot_be_overridden_by_a_public_leaf() {
        let leaf = json!({
            "type":"string", "writeOnly":false, "x-mcp-header":"Region"
        });
        for schema in [
            json!({"type":"object", "writeOnly":true, "properties":{"region":leaf}}),
            json!({"type":"object", "properties":{
                "credentials":{"type":"object", "writeOnly":true, "properties":{"region":leaf}}
            }}),
            json!({"type":"object", "properties":{
                "credentials":{"type":"object", "format":"password", "properties":{"region":leaf}}
            }}),
            json!({"type":"object", "properties":{
                "a/b~c":{"type":"object", "writeOnly":true, "properties":{"0":leaf}}
            }}),
        ] {
            for loopback in [false, true] {
                let mut calls = 0;
                assert_eq!(
                    review(schema.clone(), loopback, &mut calls).unwrap_err(),
                    ToolHeaderDispatchError::DisclosureDenied
                );
                assert_eq!(calls, 0);
            }
        }
    }

    #[test]
    fn unrelated_secrets_stay_in_the_body_without_blocking_public_headers() {
        let schema = json!({"type":"object", "properties":{
            "region":{"type":"string", "writeOnly":false, "x-mcp-header":"Region",
                "examples":["password"], "default":"writeOnly"},
            "private":{"type":"string", "writeOnly":true, "format":"password"}
        }});
        for loopback in [false, true] {
            let mut calls = 0;
            let plan = review(schema.clone(), loopback, &mut calls).unwrap();
            assert_eq!(calls, 1);
            let body = serde_json::to_vec(&json!({
                "jsonrpc":"2.0", "id":1, "method":"tools/call", "params":{
                    "name":"lookup", "arguments":{"region":"eu", "private":"body-only-secret"},
                    "_meta":FinalRequestMeta::new(ClientCapabilities::default())
                }
            }))
            .unwrap();
            let original = ModernHttpRequest::new(
                plan.resource().as_str(),
                body,
                FINAL_PROTOCOL_VERSION,
                "tools/call",
                Some("lookup".to_owned()),
            )
            .unwrap();
            let projected = original.clone().with_reviewed_tool_headers(&plan).unwrap();
            assert_eq!(projected.body(), original.body());
            let fields: Vec<_> = projected
                .headers()
                .into_iter()
                .filter(|(name, _)| name.starts_with("Mcp-Param-"))
                .collect();
            assert_eq!(fields, vec![("Mcp-Param-Region".to_owned(), "eu".to_owned())]);
            assert!(
                !projected
                    .headers()
                    .iter()
                    .any(|(_, value)| value.contains("body-only-secret"))
            );
        }
    }

    fn gateway_request(name: &str, arguments: Option<Value>) -> ModernHttpRequest {
        let mut params = json!({
            "name":name, "_meta":FinalRequestMeta::new(ClientCapabilities::default())
        });
        if let Some(arguments) = arguments {
            params["arguments"] = arguments;
        }
        let body = serde_json::to_vec(&json!({
            "jsonrpc":"2.0", "id":17, "method":"tools/call", "params":params
        }))
        .unwrap();
        ModernHttpRequest::new(
            "https://tools.example/mcp",
            body,
            FINAL_PROTOCOL_VERSION,
            "tools/call",
            Some(name.to_owned()),
        )
        .unwrap()
    }

    fn parameter_fields(request: &ModernHttpRequest) -> Vec<(String, String)> {
        request
            .headers()
            .into_iter()
            .filter(|(name, _)| name.starts_with("Mcp-Param-"))
            .collect()
    }

    #[test]
    fn gateway_refuses_secret_plans_for_absent_null_and_populated_input() {
        for schema in [
            json!({"type":"object", "properties":{
                "a_public":{"type":"string", "x-mcp-header":"Public"},
                "region":{"type":"string", "writeOnly":true, "x-mcp-header":"Secret"}
            }}),
            json!({"type":"object", "properties":{
                "region":{"type":"string", "format":"password", "x-mcp-header":"Secret"}
            }}),
            json!({"type":"object", "writeOnly":true, "properties":{
                "region":{"type":"string", "x-mcp-header":"Secret"}
            }}),
            json!({"type":"object", "properties":{
                "credentials":{"type":"object", "writeOnly":true, "properties":{
                    "region":{"type":"string", "x-mcp-header":"Secret"}
                }}
            }}),
        ] {
            let gateway = GatewayToolHeaders::default();
            gateway.replace([("lookup", &schema)]);
            for arguments in [
                None,
                Some(json!({})),
                Some(json!({"region":null, "credentials":null})),
                Some(json!({
                    "a_public":"eu", "region":"secret-canary",
                    "credentials":{"region":"secret-canary"}
                })),
            ] {
                let original = gateway_request("lookup", arguments);
                let before = original.body().to_vec();
                let error = original
                    .clone()
                    .with_gateway_tool_headers(&gateway)
                    .unwrap_err();
                assert_eq!(error, ToolHeaderDispatchError::DisclosureDenied);
                assert_eq!(original.body(), before);
                assert!(parameter_fields(&original).is_empty());
                let diagnostics = format!("{gateway:?} {error:?} {error}");
                assert!(!diagnostics.contains("secret-canary"));
                assert!(!diagnostics.contains("credentials"));
                assert!(!diagnostics.contains("Mcp-Param-Secret"));
            }
        }
    }

    #[test]
    fn gateway_catalog_replacement_rechecks_secrets_without_poisoning_siblings() {
        let safe = json!({"type":"object", "properties":{
            "region":{"type":"string", "x-mcp-header":"Region"}
        }});
        let mut secret = safe.clone();
        secret["properties"]["region"]["writeOnly"] = json!(true);
        let gateway = GatewayToolHeaders::default();
        let call = |name| gateway_request(name, Some(json!({"region":"eu"})));
        gateway.replace([("lookup", &safe)]);
        assert_eq!(
            parameter_fields(&call("lookup").with_gateway_tool_headers(&gateway).unwrap()),
            vec![("Mcp-Param-Region".to_owned(), "eu".to_owned())]
        );

        gateway.replace([("lookup", &secret), ("other", &safe)]);
        assert_eq!(
            call("lookup").with_gateway_tool_headers(&gateway).unwrap_err(),
            ToolHeaderDispatchError::DisclosureDenied
        );
        assert_eq!(
            parameter_fields(&call("other").with_gateway_tool_headers(&gateway).unwrap()),
            vec![("Mcp-Param-Region".to_owned(), "eu".to_owned())]
        );

        gateway.replace([("lookup", &safe)]);
        assert!(call("lookup").with_gateway_tool_headers(&gateway).is_ok());
        gateway.replace([("other", &safe)]);
        let original = call("lookup");
        let unplanned = original.clone().with_gateway_tool_headers(&gateway).unwrap();
        assert_eq!(unplanned.body(), original.body());
        assert!(parameter_fields(&unplanned).is_empty());
    }

    #[test]
    fn gateway_preserves_unannotated_secrets_as_body_only_data() {
        let schema = json!({"type":"object", "properties":{
            "region":{"type":"string", "x-mcp-header":"Region"},
            "private":{"type":"string", "writeOnly":true, "format":"password"}
        }});
        let gateway = GatewayToolHeaders::default();
        gateway.replace([("lookup", &schema)]);
        let original = gateway_request(
            "lookup",
            Some(json!({"region":"eu", "private":"body-only-secret"})),
        );
        let projected = original.clone().with_gateway_tool_headers(&gateway).unwrap();
        assert_eq!(projected.body(), original.body());
        assert_eq!(
            parameter_fields(&projected),
            vec![("Mcp-Param-Region".to_owned(), "eu".to_owned())]
        );
        assert!(
            !projected
                .headers()
                .iter()
                .any(|(_, value)| value.contains("body-only-secret"))
        );
    }
}

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
