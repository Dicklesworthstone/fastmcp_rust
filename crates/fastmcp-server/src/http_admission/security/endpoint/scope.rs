//! Native method-scope admission for the secured modern HTTP endpoint.
//!
//! Authentication produces the existing request-bound receipt exactly once.
//! The method policy examines those admitted facts before an era is selected,
//! a transport request is enqueued, or an SSE response body is allocated. The
//! same receipt then enters the existing native dispatcher. No application
//! error code, message, response body or metadata is interpreted as an OAuth
//! challenge, and no authentication result is cached for a later POST.

use std::sync::Arc;

use asupersync::Cx;
use fastmcp_core::{AuthContext, McpRequestCancellation};
use fastmcp_protocol::JsonRpcRequest;
use fastmcp_protocol::protocol_policy::{ProtocolEra, ProtocolPolicy};
use fastmcp_transport::TransportError;
use fastmcp_transport::http::{HttpMethod, HttpRequest, HttpResponse, HttpStatus};

use super::{SecuredHttpEndpointError, checkpoint};
use super::super::{HttpSecurityError, HttpSecurityPolicy};
use super::super::scope_policy::request::{ScopeRequestPolicy, ScopeRequestRejection};
use crate::{
    AuthDispatchCustody, DualEraHttpEndpointError, DualEraHttpEndpointResponse,
    DualEraHttpSseResponse, LiveModernHttpSessionRegistry, ServerHttpEndpoint,
    ServerHttpEndpointError, ServerHttpEndpointResponse, ServerHttpSession,
    TransportAuthorization, http_endpoint_error_response, http_endpoint_response_to_static,
};

impl HttpSecurityPolicy {
    /// Requires method-wide scopes on the secured modern HTTP execution path.
    ///
    /// Both `ServerHttpEndpoint::handle_secured_async` and the secured socket
    /// listener use this policy. Strict protocol admission and the server's
    /// installed authentication provider run before scope evaluation. A valid
    /// principal lacking permissions receives an empty, uncacheable HTTP 403
    /// and a Bearer `insufficient_scope` challenge containing the complete
    /// configured requirement, not only its missing subset. Anonymous denial
    /// remains HTTP 401; an unconfigured method discloses no scope names.
    ///
    /// Public metadata GET and browser preflight remain unauthenticated. The
    /// head-only and structural `admit` helpers do not execute authentication
    /// or scope checks. Plain HTTP entry points that are not supplied this
    /// security policy, stdio, WebSocket and the exact-2024 adapter are unchanged.
    /// This method does not replace `Server::with_scope_authorization` for those
    /// ordinary dispatch paths, authorize individual tool/resource names, or
    /// revalidate an already-open subscription. Additional server middleware
    /// restrictions still apply, but their errors are not reclassified as OAuth.
    ///
    /// Configuration is immutable after installation. A second installation
    /// fails rather than replacing or widening the previous scope policy.
    pub fn with_scope_authorization(
        mut self,
        policy: ScopeRequestPolicy,
    ) -> Result<Self, HttpSecurityError> {
        if self.scope_authorization.is_some() {
            return Err(HttpSecurityError::InvalidPolicy);
        }
        self.scope_authorization = Some(policy);
        Ok(self)
    }
}

// A private, request-owned handoff, never a credential cache or a public permit.
// All three consumers use this single preparation path. Neither the socket
// JSON branch nor the SSE opener re-runs authentication after scope admission.
struct PreparedScopedPost {
    request: HttpRequest,
    raw_params: Option<Arc<str>>,
    receipt: AuthDispatchCustody,
}

fn check_admission(
    cx: &Cx,
    cancellation: Option<&McpRequestCancellation>,
) -> Result<(), HttpResponse> {
    if checkpoint(cx).is_err()
        || cancellation.is_some_and(McpRequestCancellation::is_cancel_requested)
    {
        return Err(refusal(503));
    }
    Ok(())
}

fn prepare(
    session: &mut ServerHttpSession,
    cx: &Cx,
    policy: &ScopeRequestPolicy,
    request: HttpRequest,
    authorization: &TransportAuthorization,
    cancellation: Option<&McpRequestCancellation>,
) -> Result<PreparedScopedPost, HttpResponse> {
    check_admission(cx, cancellation)?;
    if session.closed { return Err(refusal(503)); }
    session.reap_modern_dispatches();
    if request.method != HttpMethod::Post
        || request.path != session.server.http_config.handler_config.base_path
        || matches!(session.server.protocol_policy, ProtocolPolicy::LegacyOnly)
        || session.selected_era.is_some_and(|era| era != ProtocolEra::Modern2026)
        || request.header("mcp-session-id").is_some()
    {
        return Err(HttpResponse::bad_request());
    }
    let (request, admitted, raw_params) = session.prepare_modern_http_request(request)?;
    check_admission(cx, cancellation)?;
    let receipt = session.preauthenticate_modern_http_request(cx, &admitted, authorization)?;
    check_admission(cx, cancellation)?;
    let rejection = scope_rejection(policy, &admitted.method, receipt.authenticated.as_ref());
    check_admission(cx, cancellation)?;
    if let Some(response) = rejection { return Err(response); }
    Ok(PreparedScopedPost { request, raw_params, receipt: AuthDispatchCustody::Http(receipt) })
}

/// Embedding keeps its existing outer deadline guard and SSE/session owner.
pub(super) async fn dispatch(
    session: &mut ServerHttpSession,
    cx: &Cx,
    policy: &ScopeRequestPolicy,
    request: HttpRequest,
) -> Result<ServerHttpEndpointResponse, SecuredHttpEndpointError> {
    checkpoint(cx)?;
    let authorization = match crate::transport_authorization_from_http_request(&request) {
        Ok(authorization) => authorization,
        Err(response) => return Ok(ServerHttpEndpointResponse::Immediate(response)),
    };
    dispatch_with_authorization(session, cx, policy, request, authorization, None)
        .await.map_err(|_| SecuredHttpEndpointError::DispatchFailed)
}

async fn dispatch_with_authorization(
    session: &mut ServerHttpSession,
    cx: &Cx,
    policy: &ScopeRequestPolicy,
    request: HttpRequest,
    authorization: TransportAuthorization,
    cancellation: Option<McpRequestCancellation>,
) -> Result<ServerHttpEndpointResponse, DualEraHttpEndpointError> {
    let prepared = match prepare(session, cx, policy, request, &authorization, cancellation.as_ref()) {
        Ok(prepared) => prepared,
        Err(response) => return Ok(ServerHttpEndpointResponse::Immediate(response)),
    };
    // Only a fully admitted request can pin an era or enter transport state.
    session.selected_era.get_or_insert(ProtocolEra::Modern2026);
    let endpoint_response = {
        let mut endpoint = session.endpoint_session.lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        endpoint.handle(cx, prepared.request)?
    };
    session.handle_modern(
        cx, endpoint_response, authorization, prepared.raw_params,
        Some(prepared.receipt), cancellation,
    ).await
}

/// The socket's joined JSON dispatch child supplies its existing cancellation
/// token. Keep native error projection and fresh-session ownership; no second
/// middleware pipeline or asynchronous worker is introduced here.
pub(super) async fn dispatch_socket_json(
    cx: &Cx,
    endpoint: &ServerHttpEndpoint,
    sessions: &LiveModernHttpSessionRegistry,
    policy: &ScopeRequestPolicy,
    request: HttpRequest,
    authorization: TransportAuthorization,
    cancellation: McpRequestCancellation,
) -> HttpResponse {
    let error_request = request.clone();
    sessions.reap_retired_dispatches();
    let mut session = match endpoint.open_session(cx) {
        Ok(session) => session,
        Err(_) => return HttpResponse::internal_error(),
    };
    dispatch_with_authorization(&mut session, cx, policy, request, authorization, Some(cancellation))
        .await
        .map_err(ServerHttpEndpointError::from_internal)
        .map(|response| http_endpoint_response_to_static(cx, response))
        .unwrap_or_else(|error| http_endpoint_error_response(
            &error_request, error, endpoint.server.http_config.handler_config.max_body_size,
        ))
}

type ScopedSseOpening = Result<
    (JsonRpcRequest, DualEraHttpSseResponse, Option<Arc<str>>, AuthDispatchCustody),
    ServerHttpEndpointResponse,
>;

/// Scope-aware native SSE opening. The socket retains its existing peer
/// monitor, response-body registry, representation election and terminal drain.
/// Refusals return before an SSE body exists, so a 403 never follows a 200 head.
pub(super) async fn begin_sse(
    session: &mut ServerHttpSession,
    cx: &Cx,
    policy: &ScopeRequestPolicy,
    request: HttpRequest,
    authorization: TransportAuthorization,
) -> Result<ScopedSseOpening, DualEraHttpEndpointError> {
    let prepared = match prepare(session, cx, policy, request, &authorization, None) {
        Ok(prepared) => prepared,
        Err(response) => return Ok(Err(ServerHttpEndpointResponse::Immediate(response))),
    };
    let endpoint_response = {
        let mut endpoint = session.endpoint_session.lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        match endpoint.handle(cx, prepared.request) {
            Ok(response) => response,
            Err(DualEraHttpEndpointError::Transport(TransportError::Io(error)))
                if error.kind() == std::io::ErrorKind::InvalidInput =>
            {
                return Ok(Err(ServerHttpEndpointResponse::Immediate(HttpResponse::bad_request())));
            }
            Err(error) => return Err(error),
        }
    };
    let DualEraHttpEndpointResponse::ModernSse(sse) = endpoint_response else {
        return session.handle_modern(
            cx, endpoint_response, authorization, prepared.raw_params,
            Some(prepared.receipt), None,
        ).await.map(Err);
    };
    let request = session.endpoint_session.lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner).recv_modern_request(cx)?;
    if request.method == "notifications/cancelled" {
        return Ok(Err(ServerHttpEndpointResponse::Immediate(HttpResponse::bad_request())));
    }
    Ok(Ok((request, sse, prepared.raw_params, prepared.receipt)))
}

fn refusal(status: u16) -> HttpResponse {
    HttpResponse::new(HttpStatus(status)).with_header("cache-control", "no-store")
}

/// Only a server-owned policy decision and admitted facts can enter this
/// formatter. RequiredScopes has already bounded and validated every token:
/// no quote, backslash, whitespace or HTTP control can enter its scope value.
fn scope_rejection(
    policy: &ScopeRequestPolicy,
    method: &str,
    facts: Option<&AuthContext>,
) -> Option<HttpResponse> {
    let rejected = match policy.authorize_verified(method, facts) {
        Ok(()) => return None,
        Err(rejected) => rejected,
    };
    if rejected == ScopeRequestRejection::InvalidFacts {
        return Some(refusal(500));
    }
    let authenticated = facts.is_some_and(|facts| {
        facts.subject.as_ref().is_some_and(|subject| !subject.is_empty())
            || facts.session_owner().is_some()
    });
    if !authenticated {
        return Some(refusal(401).with_header("www-authenticate", "Bearer"));
    }
    match rejected {
        ScopeRequestRejection::InsufficientScope => Some(match policy.required_scopes(method) {
            Some(required) => refusal(403).with_header(
                "www-authenticate",
                format!("Bearer error=\"insufficient_scope\", scope=\"{}\"", required.challenge_scope()),
            ),
            // Defensive consistency failure: never manufacture a public or
            // empty scope rule if a policy invariant has been violated.
            None => refusal(500),
        }),
        ScopeRequestRejection::UnconfiguredMethod => Some(refusal(403)),
        ScopeRequestRejection::InvalidFacts => Some(refusal(500)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::http_admission::{HttpAdmissionLimits, HttpEndpointConfig};
    use super::super::super::scope_policy::{RequiredScopes, ScopeImplicationPolicy};

    fn policy() -> ScopeRequestPolicy {
        ScopeRequestPolicy::new(1, ScopeImplicationPolicy::new(1, vec![
            ("admin".to_owned(), "write".to_owned()),
            ("write".to_owned(), "read".to_owned()),
        ]).unwrap(), vec![
            ("tools/call".to_owned(), RequiredScopes::new(vec!["write".to_owned(), "read".to_owned()]).unwrap()),
            ("tools/list".to_owned(), RequiredScopes::new(vec![]).unwrap()),
        ]).unwrap()
    }
    fn facts(scopes: &[&str]) -> AuthContext {
        let mut facts = AuthContext::with_subject("private-principal-canary");
        facts.scopes = scopes.iter().map(|scope| (*scope).to_owned()).collect();
        facts
    }

    #[test]
    fn challenge_contains_the_complete_sorted_requirement_not_only_missing_scopes() {
        let response = scope_rejection(&policy(), "tools/call", Some(&facts(&["read"]))).unwrap();
        assert_eq!(response.status.0, 403);
        assert_eq!(response.headers["www-authenticate"], "Bearer error=\"insufficient_scope\", scope=\"read write\"");
        assert_eq!(response.headers["cache-control"], "no-store");
        assert!(response.body.is_empty());
        assert!(!format!("{:?}", response.headers).contains("canary"));
    }

    #[test]
    fn transitive_permission_is_accepted_without_rewriting_provider_facts() {
        let facts = facts(&["admin"]);
        let before = serde_json::to_vec(&facts).unwrap();
        assert!(scope_rejection(&policy(), "tools/call", Some(&facts)).is_none());
        assert_eq!(serde_json::to_vec(&facts).unwrap(), before);
    }

    #[test]
    fn anonymous_denial_is_401_without_scope_disclosure_and_public_is_explicit() {
        for method in ["tools/call", "unconfigured"] {
            for facts in [None, Some(AuthContext::anonymous())] {
                let response = scope_rejection(&policy(), method, facts.as_ref()).unwrap();
                assert_eq!(response.status.0, 401);
                assert_eq!(response.headers["www-authenticate"], "Bearer");
                assert!(response.body.is_empty());
            }
        }
        assert!(scope_rejection(&policy(), "tools/list", None).is_none());
    }

    #[test]
    fn unconfigured_method_has_no_scope_or_application_error_oracle() {
        let response = scope_rejection(&policy(), "private-method-canary", Some(&facts(&["admin"]))).unwrap();
        assert_eq!(response.status.0, 403);
        assert!(!response.headers.contains_key("www-authenticate"));
        assert!(response.body.is_empty());
        assert!(!format!("{:?}", response.headers).contains("canary"));
    }

    #[test]
    fn malformed_provider_facts_are_not_an_insufficient_scope_challenge() {
        let response = scope_rejection(&policy(), "tools/call", Some(&facts(&["bad scope"]))).unwrap();
        assert_eq!(response.status.0, 500);
        assert!(!response.headers.contains_key("www-authenticate"));
        assert!(response.body.is_empty());
    }

    #[test]
    fn installed_http_policy_cannot_be_silently_replaced_and_clones_keep_it() {
        let security = HttpSecurityPolicy::new(
            HttpEndpointConfig::new("/mcp", HttpAdmissionLimits::new(32, 8192, 65536).unwrap()).unwrap(),
            "https://service.example", vec![],
        ).unwrap().with_scope_authorization(policy()).unwrap();
        let before = security.scope_authorization.as_ref().unwrap().fingerprint();
        assert!(matches!(security.clone().with_scope_authorization(policy()), Err(HttpSecurityError::InvalidPolicy)));
        assert_eq!(security.scope_authorization.as_ref().unwrap().fingerprint(), before);
        assert_eq!(security.clone().scope_authorization.as_ref().unwrap().fingerprint(), before);
    }

    #[test]
    fn cancelled_socket_request_cannot_enter_authentication_or_scope_work() {
        let cancellation = McpRequestCancellation::new();
        cancellation.cancel();
        let cx = Cx::for_testing();
        let response = check_admission(&cx, Some(&cancellation)).unwrap_err();
        assert_eq!(response.status.0, 503);
        assert!(!response.headers.contains_key("www-authenticate"));
        assert!(response.body.is_empty());
        assert!(cx.checkpoint().is_ok());
    }
}
