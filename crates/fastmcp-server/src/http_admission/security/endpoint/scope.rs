//! Native method-scope admission for the secured modern HTTP endpoint.
//!
//! Authentication produces the existing request-bound receipt exactly once.
//! The method policy examines those admitted facts before an era is selected,
//! a transport request is enqueued, or an SSE response body is allocated. The
//! same receipt then enters the existing native dispatcher. No application
//! error code, message, response body or metadata is interpreted as an OAuth
//! challenge, and no authentication result is cached for a later POST.

use asupersync::Cx;
use fastmcp_core::AuthContext;
use fastmcp_protocol::protocol_policy::{ProtocolEra, ProtocolPolicy};
use fastmcp_transport::http::{HttpMethod, HttpRequest, HttpResponse, HttpStatus};

use super::{SecuredHttpEndpointError, checkpoint};
use super::super::{HttpSecurityError, HttpSecurityPolicy};
use super::super::scope_policy::request::{ScopeRequestPolicy, ScopeRequestRejection};
use crate::{AuthDispatchCustody, ServerHttpEndpointResponse, ServerHttpSession};

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

/// Called only with the fresh session owned by `handle_secured_async`, after
/// route, origin, framing and body-size checks. This is the native modern
/// admission sequence with a scope decision inserted between authentication
/// and transport admission; all actual execution remains in `handle_modern`.
pub(super) async fn dispatch(
    session: &mut ServerHttpSession,
    cx: &Cx,
    policy: &ScopeRequestPolicy,
    request: HttpRequest,
) -> Result<ServerHttpEndpointResponse, SecuredHttpEndpointError> {
    checkpoint(cx)?;
    if session.closed {
        return Err(SecuredHttpEndpointError::SessionUnavailable);
    }
    session.reap_modern_dispatches();
    if request.method != HttpMethod::Post
        || request.path != session.server.http_config.handler_config.base_path
        || matches!(session.server.protocol_policy, ProtocolPolicy::LegacyOnly)
        || session.selected_era.is_some_and(|era| era != ProtocolEra::Modern2026)
        || request.header("mcp-session-id").is_some()
    {
        return Ok(ServerHttpEndpointResponse::Immediate(HttpResponse::bad_request()));
    }
    let transport_authorization = match crate::transport_authorization_from_http_request(&request) {
        Ok(authorization) => authorization,
        Err(response) => return Ok(ServerHttpEndpointResponse::Immediate(response)),
    };
    let (request, admitted, raw_params) = match session.prepare_modern_http_request(request) {
        Ok(prepared) => prepared,
        Err(response) => return Ok(ServerHttpEndpointResponse::Immediate(response)),
    };
    let receipt = match session.preauthenticate_modern_http_request(cx, &admitted, &transport_authorization) {
        Ok(receipt) => receipt,
        Err(response) => return Ok(ServerHttpEndpointResponse::Immediate(response)),
    };
    checkpoint(cx)?;
    let rejection = scope_rejection(policy, &admitted.method, receipt.authenticated.as_ref());
    checkpoint(cx)?;
    if let Some(response) = rejection {
        return Ok(ServerHttpEndpointResponse::Immediate(response));
    }

    // Only successful authentication AND authorization may mutate the native
    // transport namespace. Keep the original request/body and opaque receipt;
    // dispatch commits those same provider facts, never a second evaluation.
    session.selected_era.get_or_insert(ProtocolEra::Modern2026);
    let endpoint_response = {
        let mut endpoint = session.endpoint_session.lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        endpoint.handle(cx, request).map_err(|_| SecuredHttpEndpointError::DispatchFailed)?
    };
    session.handle_modern(
        cx, endpoint_response, transport_authorization, raw_params,
        Some(AuthDispatchCustody::Http(receipt)), None,
    ).await.map_err(|_| SecuredHttpEndpointError::DispatchFailed)
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
}
