//! Explicit, operation-bounded OAuth scope upgrades after HTTP 403.
//!
//! The peer describes missing permissions; only the host approves requesting
//! them. One owner tracks attempts for one resource/operation. Each approval
//! is consumed by at most one discovery/login, including failed or abandoned
//! attempts. This module never stores, dispatches, or retries an MCP operation.

use std::fmt;
use std::future::Future;

use asupersync::Cx;
use asupersync::tls::Certificate;
use asupersync::types::Time;
use fastmcp_core::{CanonicalHttpUrl, McpRequestCancellation};

use super::{
    ChallengeParser, ChallengedOAuthDiscovery, OAuthChallengeError, OAuthDiscoveryError,
    OAuthDiscoveryPlan, ResourceMetadataChallenge, active, combine_challenge_headers,
    discovery_deadline, fetch_metadata, metadata_origin, metadata_url_from_text, origin_of,
    validate_https, validate_scope_hint,
};
use super::super::{TrustedOAuthIssuer, issuer};
use crate::http_auth::managed::{
    ManagedOAuthSession, OAuthCredentialSnapshot, OAuthSessionPolicy,
};
use crate::http_auth::oauth::{OAuthClient, OAuthClientConfiguration, OAuthError};

const MAX_SCOPES: usize = 32;
const MAX_SCOPE_BYTES: usize = 256;
const MAX_SCOPE_SET_BYTES: usize = 4096;
const MAX_ATTEMPTS: usize = 3;

/// Fixed diagnostics, without peer scope names, URLs, realms or error text.
#[derive(Debug)]
pub enum OAuthScopeStepUpError {
    Challenge(OAuthChallengeError),
    UnsupportedStatus { status: u16 },
    MissingInsufficientScope,
    AmbiguousChallenge,
    InvalidPolicy,
    ApprovalRequired,
    NoScopeIncrease,
    AttemptLimit,
    InsufficientGrant,
}

impl fmt::Display for OAuthScopeStepUpError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Challenge(_) => "OAuth scope-upgrade discovery or challenge rejected",
            Self::UnsupportedStatus { .. } => "scope upgrade requires HTTP 403",
            Self::MissingInsufficientScope => "response has no complete Bearer insufficient_scope challenge",
            Self::AmbiguousChallenge => "multiple Bearer scope/error challenges are ambiguous",
            Self::InvalidPolicy => "invalid OAuth scope-upgrade policy",
            Self::ApprovalRequired => "additional OAuth scopes require explicit host approval",
            Self::NoScopeIncrease => "scope challenge does not increase the previously requested scope set",
            Self::AttemptLimit => "OAuth scope-upgrade attempt limit reached",
            Self::InsufficientGrant => "new OAuth grant does not cover the approved scope union",
        })
    }
}
impl std::error::Error for OAuthScopeStepUpError {}
impl From<OAuthChallengeError> for OAuthScopeStepUpError {
    fn from(error: OAuthChallengeError) -> Self { Self::Challenge(error) }
}
impl From<OAuthDiscoveryError> for OAuthScopeStepUpError {
    fn from(error: OAuthDiscoveryError) -> Self { Self::Challenge(error.into()) }
}

/// A complete, bounded 403 challenge, not permission to acquire credentials.
/// Error and scope must occur on the SAME Bearer challenge. Metadata location
/// admission remains separate, following RFC 9728 across schemes. Bodies and
/// Proxy-Authenticate cannot supply any of these fields. No Clone or serde.
pub struct InsufficientScopeChallenge {
    metadata: ResourceMetadataChallenge,
    required_scopes: Vec<String>,
}
impl fmt::Debug for InsufficientScopeChallenge {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("InsufficientScopeChallenge")
            .field("scope_count", &self.required_scopes.len())
            .field("has_metadata_location", &self.metadata.metadata_url.is_some())
            .finish_non_exhaustive()
    }
}
impl InsufficientScopeChallenge {
    /// Admit a response head from the exact effective HTTPS resource, with
    /// redirects disabled and all field lines retained in wire order. As with
    /// the initial-login parser, the host is responsible for a head supplied
    /// directly here actually coming from that verified peer.
    pub fn from_response(
        resource: CanonicalHttpUrl, status: u16, headers: &[(String, String)],
    ) -> Result<Self, OAuthScopeStepUpError> {
        validate_https(&resource).map_err(|_| OAuthScopeStepUpError::InvalidPolicy)?;
        if status != 403 { return Err(OAuthScopeStepUpError::UnsupportedStatus { status }); }
        let combined = combine_challenge_headers(headers)?;
        let mut parser = ChallengeParser { text: &combined, offset: 0, count: 0 };
        let mut metadata_url = None;
        let mut selected = None;
        while let Some(challenge) = parser.next()? {
            if challenge.token68 { continue; }
            let bearer = challenge.scheme.eq_ignore_ascii_case("bearer");
            let mut error = None;
            let mut scope = None;
            for (name, value) in challenge.parameters {
                match name.as_str() {
                    "resource_metadata" => {
                        if metadata_url.is_some() {
                            return Err(OAuthChallengeError::AmbiguousMetadataLocation.into());
                        }
                        metadata_url = Some(metadata_url_from_text(&value)?);
                    }
                    "error" if bearer => error = Some(value),
                    "scope" if bearer => scope = Some(value),
                    _ => {},
                }
            }
            if bearer && (error.is_some() || scope.is_some()) {
                if selected.is_some() { return Err(OAuthScopeStepUpError::AmbiguousChallenge); }
                selected = Some((error, scope));
            }
        }
        let Some((Some(error), Some(scope))) = selected else {
            return Err(OAuthScopeStepUpError::MissingInsufficientScope);
        };
        // OAuth error values, unlike scheme/parameter names, are case-sensitive.
        if error != "insufficient_scope" { return Err(OAuthScopeStepUpError::MissingInsufficientScope); }
        validate_scope_hint(&scope)?;
        let required_scopes = scope_set(scope.split(' '))?;
        Ok(Self {
            metadata: ResourceMetadataChallenge { resource, metadata_url, scope_hint: None },
            required_scopes,
        })
    }

    pub fn resource(&self) -> &CanonicalHttpUrl { self.metadata.resource() }
    pub fn metadata_url(&self) -> Option<&CanonicalHttpUrl> { self.metadata.metadata_url() }
    /// Untrusted scope requirements for display/host policy, not approval.
    pub fn required_scopes(&self) -> &[String] { &self.required_scopes }
}

/// Non-cloneable attempt owner for ONE resource/operation combination.
/// Keep it across that operation's failed retries; do not recreate it in a loop.
/// At most three approvals are admitted, and repeated/reordered challenges that
/// add no new scope never cause another login. This API deliberately provides
/// no operation replay: the host must decide whether retrying an effectful call
/// is safe, even after receiving an authorization refusal.
pub struct ScopeStepUp {
    plan: OAuthDiscoveryPlan,
    requested_scopes: Vec<String>,
    maximum_attempts: usize,
    attempts: usize,
}
impl fmt::Debug for ScopeStepUp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ScopeStepUp")
            .field("attempts", &self.attempts)
            .field("maximum_attempts", &self.maximum_attempts)
            .finish_non_exhaustive()
    }
}
impl ScopeStepUp {
    /// The plan must retain the original preregistered client/resource and
    /// EXACTLY ONE administrator-trusted issuer: the original login's issuer.
    /// Scope upgrades cannot silently select another issuer. Supply actual
    /// previously granted scopes from the admitted token, not from peer metadata.
    /// Configured requested scopes are retained too, including a previously
    /// requested permission the issuer declined to grant.
    pub fn new(
        plan: OAuthDiscoveryPlan, previously_granted: &[String], maximum_attempts: usize,
    ) -> Result<Self, OAuthScopeStepUpError> {
        if plan.client_id.is_none() || plan.issuers.len() != 1
            || !(1..=MAX_ATTEMPTS).contains(&maximum_attempts)
        { return Err(OAuthScopeStepUpError::InvalidPolicy); }
        let granted = scope_set(previously_granted.iter().map(String::as_str))?;
        let requested_scopes = scope_set(plan.scopes.iter().chain(&granted).map(String::as_str))?;
        Ok(Self { plan, requested_scopes, maximum_attempts, attempts: 0 })
    }

    /// Binds the granted-scope input to the snapshot's exact resource. This
    /// reads no access-token bytes and does not acquire or refresh a credential.
    pub fn from_snapshot(
        plan: OAuthDiscoveryPlan, snapshot: &OAuthCredentialSnapshot, maximum_attempts: usize,
    ) -> Result<Self, OAuthScopeStepUpError> {
        if plan.resource != *snapshot.credential().resource() {
            return Err(OAuthChallengeError::ResourceMismatch.into());
        }
        Self::new(plan, snapshot.scopes(), maximum_attempts)
    }

    pub fn attempts(&self) -> usize { self.attempts }
    pub fn remaining_attempts(&self) -> usize { self.maximum_attempts - self.attempts }
    pub fn requested_scopes(&self) -> &[String] { &self.requested_scopes }

    /// Approves only challenged additions covered by an explicit host grant.
    /// A broad host allowlist is NOT itself requested. The resulting union is
    /// old requested/granted scopes plus current requirements, preserving order
    /// and case-sensitive identity. Every refusal leaves this owner unchanged.
    ///
    /// An accepted approval consumes an attempt immediately; dropping it or a
    /// failed/cancelled login does not refund the attempt. Its requested scopes
    /// are retained so the same refusal cannot trigger a second browser login.
    pub fn approve(
        &mut self, challenge: InsufficientScopeChallenge, approved_additions: &[String],
    ) -> Result<ApprovedScopeStepUp, OAuthScopeStepUpError> {
        if self.attempts >= self.maximum_attempts { return Err(OAuthScopeStepUpError::AttemptLimit); }
        if self.plan.resource != *challenge.resource() {
            return Err(OAuthChallengeError::ResourceMismatch.into());
        }
        let approved = scope_set(approved_additions.iter().map(String::as_str))?;
        let mut increases = false;
        for scope in &challenge.required_scopes {
            if !self.requested_scopes.contains(scope) {
                if !approved.contains(scope) { return Err(OAuthScopeStepUpError::ApprovalRequired); }
                increases = true;
            }
        }
        if !increases { return Err(OAuthScopeStepUpError::NoScopeIncrease); }
        let requested_scopes = scope_set(self.requested_scopes.iter()
            .chain(&challenge.required_scopes).map(String::as_str))?;
        let mut requested = self.plan.clone();
        requested.scopes = requested_scopes.clone();
        // Separate endpoint/trust admission from scope authority. For this
        // explicitly approved challenge ONLY, scopes_supported is validated as
        // metadata but is not a permission ceiling. Dynamic challenged scopes
        // need not occur in either PRM or issuer scopes_supported. No empty-scope
        // configuration is ever sent to authorization or the token endpoint.
        let mut endpoint_plan = self.plan.clone();
        endpoint_plan.scopes.clear();
        let discovery = ChallengedOAuthDiscovery::new(endpoint_plan, challenge.metadata)?;
        self.requested_scopes = requested_scopes;
        self.attempts += 1;
        Ok(ApprovedScopeStepUp { discovery, requested })
    }
}

/// One consumed approval, one bounded discovery and one explicit PKCE login.
/// The original session and grant are not modified, revoked or refreshed by
/// this owner. Successful authorization returns a NEW managed session. OAuth
/// scope coverage does not prove that its user identity matches the old one;
/// account selection/identity policy remains with the host, not an OIDC claim.
#[must_use = "consume an approved scope upgrade or drop it without starting login"]
pub struct ApprovedScopeStepUp {
    discovery: ChallengedOAuthDiscovery,
    requested: OAuthDiscoveryPlan,
}
impl fmt::Debug for ApprovedScopeStepUp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ApprovedScopeStepUp")
            .field("scope_count", &self.requested.scopes.len())
            .finish_non_exhaustive()
    }
}
impl ApprovedScopeStepUp {
    pub fn requested_scopes(&self) -> &[String] { &self.requested.scopes }

    /// Additional administrator-granted metadata location trust; never derive
    /// this grant directly from the challenge. It grants no issuer endpoints.
    pub fn with_metadata_origin(mut self, origin: CanonicalHttpUrl) -> Result<Self, OAuthScopeStepUpError> {
        self.discovery = self.discovery.with_metadata_origin(origin)?;
        Ok(self)
    }
    pub fn with_metadata_root_certificate(mut self, root: Certificate) -> Result<Self, OAuthScopeStepUpError> {
        self.discovery = self.discovery.with_metadata_root_certificate(root)?;
        Ok(self)
    }

    async fn configuration(
        &self, cx: &Cx, cancellation: &McpRequestCancellation,
    ) -> Result<OAuthClientConfiguration, OAuthScopeStepUpError> {
        let location = self.discovery.location()?;
        let plan = &self.discovery.plan;
        let deadline = discovery_deadline(cx, plan.timeout)?;
        let configuration = active(cx, cancellation, deadline, async {
            let selected = if let Some(location) = location {
                let roots = if metadata_origin(location) == origin_of(&plan.resource) {
                    &plan.resource_roots
                } else { &self.discovery.metadata_roots };
                let body = fetch_metadata(cx, deadline, location, roots).await?
                    .ok_or(OAuthDiscoveryError::MetadataNotFound)?;
                plan.select_issuer(&body)?
            } else {
                plan.discover_resource_issuer(cx, deadline).await?
            };
            Ok(issuer::discover(cx, deadline, selected, |body| self.admit_issuer(selected, body)).await?)
        }).await?;
        Ok(configuration)
    }

    fn admit_issuer(
        &self, selected: &TrustedOAuthIssuer, body: &[u8],
    ) -> Result<OAuthClientConfiguration, OAuthDiscoveryError> {
        // Reuse the complete native-flow, exact issuer, S256, endpoint-origin,
        // resource and metadata-shape checks; only advertised scope membership
        // has a different authority. Preserve revocation and private TLS roots.
        let (authorization, token) = self.discovery.plan.admit_issuer_endpoints(selected, body)?;
        let revocation = self.discovery.plan.admit_revocation_endpoint(selected, body)?;
        self.requested.configure_client(selected, authorization, token, revocation,
            self.requested.client_id.as_deref().ok_or(OAuthDiscoveryError::InvalidPolicy)?)
    }

    pub async fn authorize_managed<L, F>(
        self, cx: &Cx, policy: OAuthSessionPolicy, launch_browser: L,
    ) -> Result<ManagedOAuthSession, OAuthScopeStepUpError>
    where L: FnOnce(CanonicalHttpUrl) -> F, F: Future<Output = Result<(), OAuthError>>,
    {
        self.authorize_managed_with_cancellation(cx, &McpRequestCancellation::new(), policy, launch_browser).await
    }

    /// One cancellation domain spans metadata, browser launch, callback,
    /// redemption and final grant-coverage admission. The native login deadline
    /// remains finite, with the caller's tighter budget taking precedence.
    /// A narrowed token cannot be presented as successful scope recovery.
    pub async fn authorize_managed_with_cancellation<L, F>(
        self, cx: &Cx, cancellation: &McpRequestCancellation,
        policy: OAuthSessionPolicy, launch_browser: L,
    ) -> Result<ManagedOAuthSession, OAuthScopeStepUpError>
    where L: FnOnce(CanonicalHttpUrl) -> F, F: Future<Output = Result<(), OAuthError>>,
    {
        let configuration = self.configuration(cx, cancellation).await?;
        let deadline = cx.budget().deadline.unwrap_or(Time::from_nanos(u64::MAX));
        let session = active(cx, cancellation, deadline, async {
            let session = ManagedOAuthSession::authorize(cx, OAuthClient::new(configuration), policy, launch_browser)
                .await.map_err(OAuthDiscoveryError::Login)?;
            let snapshot = session.credential_with_cancellation(cx, cancellation)
                .await.map_err(OAuthDiscoveryError::Login)?;
            if !covers(&self.requested.scopes, snapshot.scopes()) {
                session.close();
                return Ok(None);
            }
            Ok(Some(session))
        }).await?;
        session.ok_or(OAuthScopeStepUpError::InsufficientGrant)
    }
}

fn covers(requested: &[String], granted: &[String]) -> bool {
    requested.iter().all(|scope| granted.contains(scope))
}

fn scope_set<'a>(scopes: impl IntoIterator<Item = &'a str>) -> Result<Vec<String>, OAuthScopeStepUpError> {
    let mut result: Vec<String> = Vec::new();
    let mut bytes = 0_usize;
    let mut inputs = 0_usize;
    for scope in scopes {
        // Each merge has at most two already bounded sets. Count duplicates as
        // work too, rather than accepting unbounded input with one unique scope.
        inputs += 1;
        if inputs > 2 * MAX_SCOPES || scope.len() > MAX_SCOPE_BYTES {
            return Err(OAuthScopeStepUpError::InvalidPolicy);
        }
        validate_scope_hint(scope).map_err(|_| OAuthScopeStepUpError::InvalidPolicy)?;
        if scope.contains(' ') { return Err(OAuthScopeStepUpError::InvalidPolicy); }
        if result.iter().any(|existing| existing == scope) { continue; }
        let additional = scope.len() + usize::from(!result.is_empty());
        if result.len() >= MAX_SCOPES || additional > MAX_SCOPE_SET_BYTES.saturating_sub(bytes) {
            return Err(OAuthScopeStepUpError::InvalidPolicy);
        }
        bytes += additional;
        result.push(scope.to_owned());
    }
    Ok(result)
}

#[cfg(test)]
mod tests;
