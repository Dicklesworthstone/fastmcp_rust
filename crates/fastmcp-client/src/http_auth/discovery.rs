//! Bounded OAuth discovery for native public clients (AUTH-03).
//!
//! Starting from a configured HTTPS MCP resource, fetch RFC 9728 protected
//! resource metadata, select an explicitly trusted issuer in LOCAL preference
//! order, and fetch its RFC 8414 or OpenID-location metadata. The admitted
//! configuration feeds the existing PKCE login and shared-refresh driver.
//!
//! Trust is never bootstrapped from peer URLs alone. The host must configure
//! the resource and issuer allowlist; cross-origin authorization/token endpoints
//! require an additional explicit origin grant. This is not arbitrary-issuer
//! discovery, DNS/IP pinning, signed-metadata verification, or OIDC identity
//! authentication. OpenID locations supply OAuth metadata only. Preregistered
//! discovery never registers a client; the separate [`registration`] API owns
//! explicit, single-attempt native-client registration.
//! No discovery result is persistently cached and no credential is sent on GET.

use std::collections::BTreeSet;
use std::fmt;
use std::future::{Future, poll_fn};
use std::task::Poll;
use std::time::Duration;

use asupersync::Cx;
use asupersync::channel::oneshot;
use asupersync::http::h1::{HttpClient, Method, RedirectPolicy, RetryPolicy};
use asupersync::time::Sleep;
use asupersync::tls::{Certificate, RootCertStore};
use asupersync::types::Time;
use fastmcp_core::{CanonicalHttpUrl, CanonicalResourceId, CanonicalResourceIdPolicy};
use serde::{Deserialize, Deserializer};

use super::managed::{ManagedOAuthSession, OAuthSessionError, OAuthSessionPolicy};
use super::oauth::{OAuthClient, OAuthClientConfiguration, OAuthError};

/// Explicit RFC 7591 native-public-client registration after trusted discovery.
pub mod registration;
/// Preregistered machine-to-machine authentication without browser or DCR fallback.
pub mod client_credentials;
/// Resource-bound Bearer challenges and explicitly trusted metadata relocation.
pub mod challenge;
/// Ordered same-issuer metadata retrieval and bounded aggregate diagnostics.
pub mod issuer;

/// Maximum retained bytes in each resource or issuer metadata document.
pub const MAX_OAUTH_METADATA_BYTES: usize = 64 * 1024;
const MAX_ISSUERS: usize = 16;
const MAX_ARRAY_ENTRIES: usize = 128;
const MAX_METADATA_STRING_BYTES: usize = 4096;

/// Fixed diagnostics: peer metadata bodies and URLs are never retained in errors.
#[derive(Debug)]
pub enum OAuthDiscoveryError {
    InvalidPolicy,
    RuntimeUnavailable,
    Cancelled,
    TimedOut,
    TransportFailed,
    HttpStatus { status: u16 },
    MetadataNotFound,
    InvalidRepresentation,
    InvalidMetadata,
    ResourceMismatch,
    NoTrustedIssuer,
    IssuerMismatch,
    EndpointNotTrusted,
    UnsupportedFlow,
    UnsupportedScopes,
    SignedMetadataUnsupported,
    /// Neither constructed resource-metadata location was usable. Diagnostics
    /// retain every attempted location's safe tag and cause, never peer bytes.
    ResourceMetadataExhausted(ResourceMetadataFailure),
    /// No permitted location of the selected issuer passed candidate admission.
    IssuerMetadataExhausted(issuer::IssuerMetadataFailure),
    Login(OAuthSessionError),
}

impl fmt::Display for OAuthDiscoveryError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::InvalidPolicy => "invalid OAuth discovery policy",
            Self::RuntimeUnavailable => "OAuth discovery requires caller-owned I/O and time",
            Self::Cancelled => "OAuth discovery cancelled",
            Self::TimedOut => "OAuth discovery deadline exceeded",
            Self::TransportFailed => "OAuth discovery transport failed",
            Self::HttpStatus { .. } => "OAuth metadata endpoint rejected discovery",
            Self::MetadataNotFound => "OAuth metadata not found at the permitted locations",
            Self::InvalidRepresentation => "OAuth metadata representation rejected",
            Self::InvalidMetadata => "OAuth metadata document rejected",
            Self::ResourceMismatch => "OAuth metadata does not identify the configured resource",
            Self::NoTrustedIssuer => "resource does not advertise an explicitly trusted issuer",
            Self::IssuerMismatch => "OAuth metadata issuer differs from the selected issuer",
            Self::EndpointNotTrusted => "OAuth endpoint origin is outside the issuer's trust policy",
            Self::UnsupportedFlow => "issuer does not admit the native S256 code flow",
            Self::UnsupportedScopes => "OAuth metadata does not admit the requested scopes",
            Self::SignedMetadataUnsupported => "signed OAuth metadata requires a separate verifier",
            Self::ResourceMetadataExhausted(_) => "no constructed resource-metadata location passed admission",
            Self::IssuerMetadataExhausted(_) => "no permitted issuer-metadata location passed admission",
            Self::Login(_) => "login after OAuth discovery failed",
        })
    }
}

impl std::error::Error for OAuthDiscoveryError {}

/// Safe canonical tags for the only two constructed PRM candidates. No URI,
/// tenant path, response body or authentication challenge enters diagnostics.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ResourceMetadataLocation {
    PathSpecific,
    OriginRoot,
}

/// A bounded candidate outcome, with no retained transport or parser error.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ResourceMetadataCause {
    NotFound,
    HttpStatus(u16),
    InvalidRepresentation,
    InvalidMetadata,
    ResourceMismatch,
    NoTrustedIssuer,
    UnsupportedFlow,
    UnsupportedScopes,
    SignedMetadataUnsupported,
    TransportFailed,
    CandidateDeadline,
    Cancelled,
    RuntimeUnavailable,
    InvalidPolicy,
}

/// Deterministic aggregate precedence: caller interruption, then trust and
/// integrity, then HTTP/protocol, then transport, then absence.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ResourceMetadataFailureClass {
    Cancelled,
    OverallDeadline,
    TrustOrIntegrity,
    ProtocolOrHttp,
    Transport,
    NotFound,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ResourceMetadataAttempt {
    location: ResourceMetadataLocation,
    cause: ResourceMetadataCause,
}

impl ResourceMetadataAttempt {
    pub fn location(&self) -> ResourceMetadataLocation { self.location }
    pub fn cause(&self) -> ResourceMetadataCause { self.cause }
}

/// Ordered failure record with exactly one or two attempted constructed URLs.
/// A root resource has only one distinct candidate. Cancellation/overall-budget
/// exhaustion can stop before the second candidate; unattempted slots are not
/// fabricated. Private construction keeps this vector's cardinality bounded.
#[derive(Debug)]
pub struct ResourceMetadataFailure {
    attempts: Vec<ResourceMetadataAttempt>,
    interrupted: Option<ResourceMetadataFailureClass>,
}

impl ResourceMetadataFailure {
    pub fn attempts(&self) -> &[ResourceMetadataAttempt] { &self.attempts }

    pub fn classification(&self) -> ResourceMetadataFailureClass {
        if let Some(interrupted) = self.interrupted { return interrupted; }
        let mut class = ResourceMetadataFailureClass::NotFound;
        let mut priority = 0;
        for attempt in &self.attempts {
            let (candidate, rank) = match attempt.cause {
                ResourceMetadataCause::Cancelled => (ResourceMetadataFailureClass::Cancelled, 5),
                ResourceMetadataCause::ResourceMismatch
                | ResourceMetadataCause::NoTrustedIssuer
                | ResourceMetadataCause::UnsupportedFlow
                | ResourceMetadataCause::UnsupportedScopes
                | ResourceMetadataCause::SignedMetadataUnsupported
                | ResourceMetadataCause::InvalidPolicy => (ResourceMetadataFailureClass::TrustOrIntegrity, 4),
                ResourceMetadataCause::HttpStatus(_)
                | ResourceMetadataCause::InvalidRepresentation
                | ResourceMetadataCause::InvalidMetadata => (ResourceMetadataFailureClass::ProtocolOrHttp, 3),
                ResourceMetadataCause::TransportFailed
                | ResourceMetadataCause::CandidateDeadline
                | ResourceMetadataCause::RuntimeUnavailable => (ResourceMetadataFailureClass::Transport, 2),
                ResourceMetadataCause::NotFound => (ResourceMetadataFailureClass::NotFound, 1),
            };
            if rank > priority { class = candidate; priority = rank; }
        }
        class
    }
}

fn resource_candidate_cause(error: &OAuthDiscoveryError) -> ResourceMetadataCause {
    match error {
        OAuthDiscoveryError::HttpStatus { status } => ResourceMetadataCause::HttpStatus(*status),
        OAuthDiscoveryError::MetadataNotFound => ResourceMetadataCause::NotFound,
        OAuthDiscoveryError::InvalidRepresentation => ResourceMetadataCause::InvalidRepresentation,
        OAuthDiscoveryError::InvalidMetadata => ResourceMetadataCause::InvalidMetadata,
        OAuthDiscoveryError::ResourceMismatch => ResourceMetadataCause::ResourceMismatch,
        OAuthDiscoveryError::NoTrustedIssuer => ResourceMetadataCause::NoTrustedIssuer,
        OAuthDiscoveryError::UnsupportedFlow => ResourceMetadataCause::UnsupportedFlow,
        OAuthDiscoveryError::UnsupportedScopes => ResourceMetadataCause::UnsupportedScopes,
        OAuthDiscoveryError::SignedMetadataUnsupported => ResourceMetadataCause::SignedMetadataUnsupported,
        OAuthDiscoveryError::TransportFailed => ResourceMetadataCause::TransportFailed,
        OAuthDiscoveryError::TimedOut => ResourceMetadataCause::CandidateDeadline,
        OAuthDiscoveryError::Cancelled => ResourceMetadataCause::Cancelled,
        OAuthDiscoveryError::RuntimeUnavailable => ResourceMetadataCause::RuntimeUnavailable,
        OAuthDiscoveryError::InvalidPolicy | OAuthDiscoveryError::IssuerMismatch
        | OAuthDiscoveryError::EndpointNotTrusted | OAuthDiscoveryError::ResourceMetadataExhausted(_)
        | OAuthDiscoveryError::IssuerMetadataExhausted(_) | OAuthDiscoveryError::Login(_) => ResourceMetadataCause::InvalidPolicy,
    }
}

/// One administrator-trusted issuer and its permitted endpoint origins.
/// The identifier keeps its exact spelling for RFC 9207 issuer comparison.
/// Network URLs are separately canonicalized for transport and origin checks.
#[derive(Clone, Debug)]
pub struct TrustedOAuthIssuer {
    identifier: String,
    url: CanonicalHttpUrl,
    endpoint_origins: Vec<String>,
    roots: Vec<Certificate>,
}

impl TrustedOAuthIssuer {
    /// Grants discovery access to one exact issuer, not to issuers named by it.
    /// The caller must not populate this allowlist directly from untrusted
    /// resource metadata. DNS for these explicitly trusted hosts is a host
    /// deployment responsibility; this API does not pin resolved addresses.
    pub fn new(identifier: impl Into<String>) -> Result<Self, OAuthDiscoveryError> {
        let identifier = identifier.into();
        let url = https_url(&identifier).map_err(|_| OAuthDiscoveryError::InvalidPolicy)?;
        Ok(Self { identifier, url, endpoint_origins: Vec::new(), roots: Vec::new() })
    }

    /// Allows a separately hosted login/token service. Pass an origin URL with
    /// path `/` and no query, fragment or credentials. It is never derived from
    /// the downloaded metadata. At most eight additional origins are admitted.
    /// This does not authorize cross-origin client registration writes.
    pub fn with_endpoint_origin(mut self, origin: CanonicalHttpUrl) -> Result<Self, OAuthDiscoveryError> {
        validate_https(&origin).map_err(|_| OAuthDiscoveryError::InvalidPolicy)?;
        let origin_text = origin_of(&origin);
        if origin.path() != "/" || self.endpoint_origins.len() >= 8
            || origin_text == origin_of(&self.url)
            || self.endpoint_origins.iter().any(|value| value == &origin_text)
        {
            return Err(OAuthDiscoveryError::InvalidPolicy);
        }
        self.endpoint_origins.push(origin_text);
        Ok(self)
    }

    /// Adds a private root for this issuer's metadata and subsequent token
    /// exchanges. Explicit registration also uses this selected issuer trust.
    /// It does not grant resource-metadata or MCP-resource trust.
    pub fn with_root_certificate(mut self, root: Certificate) -> Result<Self, OAuthDiscoveryError> {
        admit_root(&mut self.roots, root)?;
        Ok(self)
    }

    fn endpoint(&self, value: &str) -> Result<CanonicalHttpUrl, OAuthDiscoveryError> {
        let endpoint = https_url(value)?;
        let origin = origin_of(&endpoint);
        if origin != origin_of(&self.url) && !self.endpoint_origins.contains(&origin) {
            return Err(OAuthDiscoveryError::EndpointNotTrusted);
        }
        Ok(endpoint)
    }
}

/// Immutable discovery inputs for a preregistered native public client.
/// Peer metadata cannot change resource identity, client registration, requested
/// scopes, timeout, trust roots, or local issuer preference order.
#[derive(Clone, Debug)]
pub struct OAuthDiscoveryPlan {
    resource: CanonicalHttpUrl,
    issuers: Vec<TrustedOAuthIssuer>,
    // None is internal to the explicit registration owner. A public discovery
    // plan always has a real preregistered identity; no placeholder ID is sent.
    client_id: Option<String>,
    scopes: Vec<String>,
    resource_roots: Vec<Certificate>,
    timeout: Duration,
}

impl OAuthDiscoveryPlan {
    pub fn new(
        resource: CanonicalHttpUrl,
        issuers: Vec<TrustedOAuthIssuer>,
        client_id: impl Into<String>,
        scopes: Vec<String>,
    ) -> Result<Self, OAuthDiscoveryError> {
        Self::with_client_id(resource, issuers, Some(client_id.into()), scopes)
    }

    fn with_client_id(
        resource: CanonicalHttpUrl,
        issuers: Vec<TrustedOAuthIssuer>,
        client_id: Option<String>,
        scopes: Vec<String>,
    ) -> Result<Self, OAuthDiscoveryError> {
        validate_https(&resource).map_err(|_| OAuthDiscoveryError::InvalidPolicy)?;
        CanonicalResourceId::parse_for_endpoint(
            resource.as_str(), &resource, CanonicalResourceIdPolicy::DEFAULT,
        ).map_err(|_| OAuthDiscoveryError::InvalidPolicy)?;
        if issuers.is_empty() || issuers.len() > MAX_ISSUERS {
            return Err(OAuthDiscoveryError::InvalidPolicy);
        }
        for (index, issuer) in issuers.iter().enumerate() {
            if issuers[..index].iter().any(|other| {
                other.identifier == issuer.identifier || other.url == issuer.url
            }) {
                return Err(OAuthDiscoveryError::InvalidPolicy);
            }
        }
        if client_id.as_ref().is_some_and(|id| {
            id.is_empty() || id.len() > 1024 || id.chars().any(char::is_control)
        }) || scopes.len() > 32 || scopes.iter().map(String::len).sum::<usize>() > 4096
        {
            return Err(OAuthDiscoveryError::InvalidPolicy);
        }
        let mut seen = BTreeSet::new();
        for scope in &scopes {
            if scope.is_empty() || scope.len() > 256 || !seen.insert(scope)
                || !scope.bytes().all(|byte| {
                    byte == 0x21 || (0x23..=0x5b).contains(&byte) || (0x5d..=0x7e).contains(&byte)
                })
            {
                return Err(OAuthDiscoveryError::InvalidPolicy);
            }
        }
        Ok(Self { resource, issuers, client_id, scopes, resource_roots: Vec::new(), timeout: Duration::from_secs(30) })
    }

    /// One absolute bound across resource discovery and all permitted issuer
    /// locations, not a fresh timeout per fallback. Constructed PRM retrieval
    /// reserves half the remaining time for issuer discovery. The other half
    /// is divided equally between its one or two candidates, so a stalled first
    /// response cannot consume the root attempt. The caller's tighter budget
    /// wins. Browser login uses its separate existing authorization deadline.
    /// Issuer candidates likewise reserve independent time shares and leave
    /// half their entry-time budget for work following successful discovery.
    pub fn with_timeout(mut self, timeout: Duration) -> Result<Self, OAuthDiscoveryError> {
        if timeout.is_zero() || timeout > Duration::from_secs(120) {
            return Err(OAuthDiscoveryError::InvalidPolicy);
        }
        self.timeout = timeout;
        Ok(self)
    }

    /// Grants a private CA only for the configured resource's metadata GET.
    pub fn with_resource_root_certificate(mut self, root: Certificate) -> Result<Self, OAuthDiscoveryError> {
        admit_root(&mut self.resource_roots, root)?;
        Ok(self)
    }

    /// Discovers usable public-client code-flow endpoints. Constructed PRM
    /// locations are tried path-first then root after any unusable bounded
    /// candidate, with full identity/trust admission before selecting a winner.
    /// The fixed same-issuer metadata sequence then selects its first fully
    /// admitted native code-flow configuration, not merely its first HTTP 200.
    /// This never follows redirects, retries a URL, changes the selected issuer,
    /// relaxes endpoint trust, or accepts a rejected explicit challenge hint.
    pub async fn discover(&self, cx: &Cx) -> Result<OAuthClientConfiguration, OAuthDiscoveryError> {
        if self.client_id.is_none() {
            return Err(OAuthDiscoveryError::InvalidPolicy);
        }
        let deadline = discovery_deadline(cx, self.timeout)?;
        let issuer = self.discover_resource_issuer(cx, deadline).await?;
        self.discover_selected_issuer(cx, deadline, issuer).await
    }

    async fn discover_selected_issuer(
        &self, cx: &Cx, deadline: Time, selected: &TrustedOAuthIssuer,
    ) -> Result<OAuthClientConfiguration, OAuthDiscoveryError> {
        issuer::discover(cx, deadline, selected, |body| self.admit_issuer(selected, body)).await
    }

    // Registration, machine authentication and preregistered native discovery
    // share constructed PRM admission. An explicit challenge URI intentionally
    // bypasses this helper: its rejection never permits constructed fallback.
    async fn discover_resource_issuer(
        &self, cx: &Cx, deadline: Time,
    ) -> Result<&TrustedOAuthIssuer, OAuthDiscoveryError> {
        check_context(cx, deadline)?;
        let candidates = resource_metadata_urls(&self.resource)?;
        let deadlines = resource_candidate_deadlines(cx.now(), deadline, candidates.len())?;
        let mut failure = ResourceMetadataFailure { attempts: Vec::with_capacity(2), interrupted: None };
        for ((tag, location), candidate_deadline) in candidates.into_iter().zip(deadlines) {
            // Check the outer budget before opening each candidate. A candidate
            // timeout alone is NOT an outer-budget failure and permits the root.
            if cx.checkpoint().is_err() {
                failure.interrupted = Some(ResourceMetadataFailureClass::Cancelled);
                break;
            }
            if cx.now() >= deadline {
                failure.interrupted = Some(ResourceMetadataFailureClass::OverallDeadline);
                break;
            }
            let result = fetch_metadata(cx, candidate_deadline, &location, &self.resource_roots).await
                .and_then(|body| body.ok_or(OAuthDiscoveryError::MetadataNotFound))
                .and_then(|body| self.select_issuer(&body));
            // Admission is part of the candidate's allowance, not unbounded
            // work after its network timeout. A noncooperative synchronous
            // decoder cannot be preempted, but no later effect follows an overrun.
            let result = if cx.checkpoint().is_err() {
                Err(OAuthDiscoveryError::Cancelled)
            } else if cx.now() >= candidate_deadline {
                Err(OAuthDiscoveryError::TimedOut)
            } else { result };
            match result {
                Ok(issuer) => return Ok(issuer),
                Err(error) => failure.attempts.push(ResourceMetadataAttempt {
                    location: tag, cause: resource_candidate_cause(&error),
                }),
            }
        }
        if cx.checkpoint().is_err() {
            failure.interrupted = Some(ResourceMetadataFailureClass::Cancelled);
        } else if cx.now() >= deadline {
            failure.interrupted = Some(ResourceMetadataFailureClass::OverallDeadline);
        }
        Err(OAuthDiscoveryError::ResourceMetadataExhausted(failure))
    }

    // Registration and machine authentication share the same bounded transport,
    // identity and endpoint-document admission. Their subsequent registration
    // or selected authentication-method checks remain explicit and cannot switch
    // credentials or issuers. Exact source bytes reach their profile decoders.
    async fn discover_issuer_document(
        &self,
        cx: &Cx,
        deadline: Time,
    ) -> Result<(&TrustedOAuthIssuer, Vec<u8>), OAuthDiscoveryError> {
        let selected = self.discover_resource_issuer(cx, deadline).await?;
        let body = issuer::discover(cx, deadline, selected, |body| issuer::admit_document(selected, body)).await?;
        Ok((selected, body))
    }

    /// Resolves metadata and then drives the existing browser/PKCE/managed
    /// renewal workflow. The launcher is not invoked until all discovery and
    /// public-client policy checks succeed. This does not dynamically register
    /// a client or silently relogin a previously failed managed session.
    pub async fn authorize_managed<L, F>(
        &self,
        cx: &Cx,
        policy: OAuthSessionPolicy,
        launch_browser: L,
    ) -> Result<ManagedOAuthSession, OAuthDiscoveryError>
    where
        L: FnOnce(CanonicalHttpUrl) -> F,
        F: Future<Output = Result<(), OAuthError>>,
    {
        let configuration = self.discover(cx).await?;
        ManagedOAuthSession::authorize(cx, OAuthClient::new(configuration), policy, launch_browser)
            .await.map_err(OAuthDiscoveryError::Login)
    }
    fn select_issuer(&self, body: &[u8]) -> Result<&TrustedOAuthIssuer, OAuthDiscoveryError> {
        let metadata: ResourceMetadata = decode_metadata(body)?;
        if metadata.signed_metadata.is_some() {
            return Err(OAuthDiscoveryError::SignedMetadataUnsupported);
        }
        // RFC 9728 requires exact identity, not merely the same origin/path prefix.
        if metadata.resource != self.resource.as_str() {
            return Err(OAuthDiscoveryError::ResourceMismatch);
        }
        validate_optional_array(metadata.bearer_methods_supported.as_deref())?;
        if metadata.bearer_methods_supported.as_ref().is_some_and(|methods| {
            !methods.iter().any(|method| method == "header")
        }) {
            return Err(OAuthDiscoveryError::UnsupportedFlow);
        }
        admit_scopes(&self.scopes, metadata.scopes_supported.as_deref())?;
        let servers = metadata.authorization_servers.ok_or(OAuthDiscoveryError::NoTrustedIssuer)?;
        validate_array(&servers)?;
        if servers.len() > MAX_ISSUERS {
            return Err(OAuthDiscoveryError::InvalidMetadata);
        }
        // Untrusted entries are never followed, even when they precede a match.
        self.issuers.iter().find(|issuer| servers.contains(&issuer.identifier))
            .ok_or(OAuthDiscoveryError::NoTrustedIssuer)
    }

    fn admit_issuer(
        &self,
        issuer: &TrustedOAuthIssuer,
        body: &[u8],
    ) -> Result<OAuthClientConfiguration, OAuthDiscoveryError> {
        let (authorization, token) = self.admit_issuer_endpoints(issuer, body)?;
        let revocation = self.admit_revocation_endpoint(issuer, body)?;
        self.configure_client(
            issuer, authorization, token, revocation,
            self.client_id.as_deref().ok_or(OAuthDiscoveryError::InvalidPolicy)?,
        )
    }

    fn configure_client(
        &self,
        issuer: &TrustedOAuthIssuer,
        authorization: CanonicalHttpUrl,
        token: CanonicalHttpUrl,
        revocation: Option<CanonicalHttpUrl>,
        client_id: &str,
    ) -> Result<OAuthClientConfiguration, OAuthDiscoveryError> {
        let mut configuration = OAuthClientConfiguration::from_trusted_endpoints(
            issuer.identifier.clone(), authorization, token, self.resource.clone(),
            client_id, self.scopes.clone(),
        ).map_err(|_| OAuthDiscoveryError::InvalidMetadata)?;
        if let Some(endpoint) = revocation {
            configuration = configuration.with_trusted_revocation_endpoint(endpoint)
                .map_err(|_| OAuthDiscoveryError::InvalidMetadata)?;
        }
        for root in &issuer.roots {
            configuration = configuration.with_extra_root_certificate(root.clone())
                .map_err(|_| OAuthDiscoveryError::InvalidPolicy)?;
        }
        Ok(configuration)
    }

    // Validate the COMPLETE flow before a registration POST is permitted,
    // even though the client identity does not exist yet.
    fn admit_issuer_endpoints(
        &self,
        issuer: &TrustedOAuthIssuer,
        body: &[u8],
    ) -> Result<(CanonicalHttpUrl, CanonicalHttpUrl), OAuthDiscoveryError> {
        let metadata: IssuerMetadata = decode_metadata(body)?;
        if metadata.signed_metadata.is_some() {
            return Err(OAuthDiscoveryError::SignedMetadataUnsupported);
        }
        if metadata.issuer != issuer.identifier {
            return Err(OAuthDiscoveryError::IssuerMismatch);
        }
        for values in [
            Some(metadata.response_types_supported.as_slice()),
            metadata.grant_types_supported.as_deref(),
            metadata.response_modes_supported.as_deref(),
            metadata.token_endpoint_auth_methods_supported.as_deref(),
            metadata.code_challenge_methods_supported.as_deref(),
            metadata.protected_resources.as_deref(),
        ] {
            validate_optional_array(values)?;
        }
        if !metadata.response_types_supported.iter().any(|value| value == "code")
            || metadata.grant_types_supported.as_ref().is_some_and(|values| !has(values, "authorization_code"))
            || metadata.response_modes_supported.as_ref().is_some_and(|values| !has(values, "query"))
            || !metadata.token_endpoint_auth_methods_supported.as_ref().is_some_and(|values| has(values, "none"))
            || !metadata.code_challenge_methods_supported.as_ref().is_some_and(|values| has(values, "S256"))
            || metadata.authorization_response_iss_parameter_supported != Some(true)
        {
            return Err(OAuthDiscoveryError::UnsupportedFlow);
        }
        if metadata.protected_resources.as_ref().is_some_and(|values| !has(values, self.resource.as_str())) {
            return Err(OAuthDiscoveryError::ResourceMismatch);
        }
        admit_scopes(&self.scopes, metadata.scopes_supported.as_deref())?;
        Ok((issuer.endpoint(&metadata.authorization_endpoint)?, issuer.endpoint(&metadata.token_endpoint)?))
    }

    // Revocation is optional for login. Only advertise it to the runtime when
    // metadata explicitly says a public client may use the endpoint without a
    // client secret. If that claim exists, the endpoint must pass the same
    // explicit issuer-origin trust boundary as authorization/token endpoints.
    fn admit_revocation_endpoint(
        &self,
        issuer: &TrustedOAuthIssuer,
        body: &[u8],
    ) -> Result<Option<CanonicalHttpUrl>, OAuthDiscoveryError> {
        let metadata: IssuerMetadata = decode_metadata(body)?;
        validate_optional_array(metadata.revocation_endpoint_auth_methods_supported.as_deref())?;
        let Some(endpoint) = metadata.revocation_endpoint else { return Ok(None); };
        if !metadata.revocation_endpoint_auth_methods_supported.as_ref()
            .is_some_and(|methods| has(methods, "none"))
        {
            return Ok(None);
        }
        Ok(Some(issuer.endpoint(&endpoint)?))
    }
}

fn has(values: &[String], expected: &str) -> bool {
    values.iter().any(|value| value == expected)
}

fn validate_https(url: &CanonicalHttpUrl) -> Result<(), OAuthDiscoveryError> {
    if url.scheme() != "https" || url.has_userinfo() || url.query().is_some() || url.fragment().is_some() {
        return Err(OAuthDiscoveryError::InvalidMetadata);
    }
    Ok(())
}

fn https_url(text: &str) -> Result<CanonicalHttpUrl, OAuthDiscoveryError> {
    if text.is_empty() || text.len() > MAX_METADATA_STRING_BYTES
        || text.chars().any(|character| character.is_whitespace() || character.is_control())
        || text.contains('\\') || !text.starts_with("https://")
    {
        return Err(OAuthDiscoveryError::InvalidMetadata);
    }
    let url = CanonicalHttpUrl::parse(text).map_err(|_| OAuthDiscoveryError::InvalidMetadata)?;
    validate_https(&url)?;
    Ok(url)
}

// All callers have rejected query, fragment and userinfo. Slicing the canonical
// path suffix preserves IPv6 brackets and explicit non-default port spelling.
fn origin_of(url: &CanonicalHttpUrl) -> String {
    url.as_str()[..url.as_str().len() - url.path().len()].to_owned()
}

fn resource_metadata_url(resource: &CanonicalHttpUrl) -> Result<CanonicalHttpUrl, OAuthDiscoveryError> {
    let path = if resource.path() == "/" { "" } else { resource.path() };
    CanonicalHttpUrl::parse(&format!(
        "{}/.well-known/oauth-protected-resource{path}", origin_of(resource),
    )).map_err(|_| OAuthDiscoveryError::InvalidPolicy)
}

fn resource_metadata_urls(
    resource: &CanonicalHttpUrl,
) -> Result<Vec<(ResourceMetadataLocation, CanonicalHttpUrl)>, OAuthDiscoveryError> {
    validate_https(resource).map_err(|_| OAuthDiscoveryError::InvalidPolicy)?;
    let path = resource_metadata_url(resource)?;
    let root = CanonicalHttpUrl::parse(&format!(
        "{}/.well-known/oauth-protected-resource", origin_of(resource),
    )).map_err(|_| OAuthDiscoveryError::InvalidPolicy)?;
    if path == root { return Ok(vec![(ResourceMetadataLocation::OriginRoot, root)]); }
    Ok(vec![(ResourceMetadataLocation::PathSpecific, path), (ResourceMetadataLocation::OriginRoot, root)])
}

// Allocate the complete schedule before the first fetch. The root has its own
// time and 64-KiB body allowance, and at least half the original remaining time
// remains available for the issuer. There are no resets after trickled bytes.
fn resource_candidate_deadlines(
    now: Time, deadline: Time, count: usize,
) -> Result<Vec<Time>, OAuthDiscoveryError> {
    if !(1..=2).contains(&count) { return Err(OAuthDiscoveryError::InvalidPolicy); }
    let remaining = deadline.as_nanos().checked_sub(now.as_nanos()).ok_or(OAuthDiscoveryError::TimedOut)?;
    let share = remaining / 2 / count as u64;
    if share == 0 { return Err(OAuthDiscoveryError::TimedOut); }
    Ok((1..=count).map(|index| Time::from_nanos(now.as_nanos() + share * index as u64)).collect())
}

fn issuer_metadata_urls(issuer: &CanonicalHttpUrl) -> Result<Vec<CanonicalHttpUrl>, OAuthDiscoveryError> {
    let origin = origin_of(issuer);
    let path = issuer.path().trim_end_matches('/');
    let mut locations = Vec::new();
    // RFC 8414 insertion, RFC 8414's OpenID suffix, then OIDC's appending rule.
    for value in [
        format!("{origin}/.well-known/oauth-authorization-server{path}"),
        format!("{origin}/.well-known/openid-configuration{path}"),
        format!("{origin}{path}/.well-known/openid-configuration"),
    ] {
        let location = CanonicalHttpUrl::parse(&value).map_err(|_| OAuthDiscoveryError::InvalidPolicy)?;
        if !locations.contains(&location) {
            locations.push(location);
        }
    }
    Ok(locations)
}

fn admit_root(roots: &mut Vec<Certificate>, root: Certificate) -> Result<(), OAuthDiscoveryError> {
    if roots.len() >= 8 || root.as_der().is_empty() || root.as_der().len() > 16 * 1024
        || roots.iter().any(|existing| existing.as_der() == root.as_der())
    {
        return Err(OAuthDiscoveryError::InvalidPolicy);
    }
    RootCertStore::empty().add(&root).map_err(|_| OAuthDiscoveryError::InvalidPolicy)?;
    roots.push(root);
    Ok(())
}

fn validate_array(values: &[String]) -> Result<(), OAuthDiscoveryError> {
    if values.is_empty() || values.len() > MAX_ARRAY_ENTRIES {
        return Err(OAuthDiscoveryError::InvalidMetadata);
    }
    let mut seen = BTreeSet::new();
    for value in values {
        if value.is_empty() || value.len() > MAX_METADATA_STRING_BYTES
            || value.chars().any(char::is_control) || !seen.insert(value)
        {
            return Err(OAuthDiscoveryError::InvalidMetadata);
        }
    }
    Ok(())
}

fn validate_optional_array(values: Option<&[String]>) -> Result<(), OAuthDiscoveryError> {
    values.map_or(Ok(()), validate_array)
}

fn admit_scopes(requested: &[String], supported: Option<&[String]>) -> Result<(), OAuthDiscoveryError> {
    validate_optional_array(supported)?;
    if supported.is_some_and(|supported| requested.iter().any(|scope| !supported.contains(scope))) {
        return Err(OAuthDiscoveryError::UnsupportedScopes);
    }
    Ok(())
}

fn present<'de, D, T>(deserializer: D) -> Result<Option<T>, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de>,
{
    // Missing is default; explicit null does not impersonate absence.
    T::deserialize(deserializer).map(Some)
}

#[derive(Deserialize)]
struct ResourceMetadata {
    resource: String,
    #[serde(default, deserialize_with = "present")]
    authorization_servers: Option<Vec<String>>,
    #[serde(default, deserialize_with = "present")]
    bearer_methods_supported: Option<Vec<String>>,
    #[serde(default, deserialize_with = "present")]
    scopes_supported: Option<Vec<String>>,
    #[serde(default, deserialize_with = "present")]
    signed_metadata: Option<String>,
}

#[derive(Deserialize)]
struct IssuerMetadata {
    issuer: String,
    authorization_endpoint: String,
    token_endpoint: String,
    #[serde(default, deserialize_with = "present")]
    revocation_endpoint: Option<String>,
    #[serde(default, deserialize_with = "present")]
    revocation_endpoint_auth_methods_supported: Option<Vec<String>>,
    response_types_supported: Vec<String>,
    #[serde(default, deserialize_with = "present")]
    grant_types_supported: Option<Vec<String>>,
    #[serde(default, deserialize_with = "present")]
    response_modes_supported: Option<Vec<String>>,
    #[serde(default, deserialize_with = "present")]
    token_endpoint_auth_methods_supported: Option<Vec<String>>,
    #[serde(default, deserialize_with = "present")]
    code_challenge_methods_supported: Option<Vec<String>>,
    #[serde(default, deserialize_with = "present")]
    authorization_response_iss_parameter_supported: Option<bool>,
    #[serde(default, deserialize_with = "present")]
    scopes_supported: Option<Vec<String>>,
    #[serde(default, deserialize_with = "present")]
    protected_resources: Option<Vec<String>>,
    #[serde(default, deserialize_with = "present")]
    signed_metadata: Option<String>,
}

fn decode_metadata<T: serde::de::DeserializeOwned>(body: &[u8]) -> Result<T, OAuthDiscoveryError> {
    if body.len() > MAX_OAUTH_METADATA_BYTES
        || body.iter().copied().find(|byte| !matches!(byte, b' ' | b'\t' | b'\r' | b'\n')) != Some(b'{')
    {
        return Err(OAuthDiscoveryError::InvalidMetadata);
    }
    // Serde's derived struct decoder also accepts positional sequences. Require
    // the JSON object envelope first, without an intermediate Value that would
    // collapse duplicate keys. Derived structs then reject repeated declared
    // fields (including escaped aliases); unknown metadata remains inert.
    serde_json::from_slice(body).map_err(|_| OAuthDiscoveryError::InvalidMetadata)
}

fn validate_headers(headers: &[(String, String)]) -> Result<(), OAuthDiscoveryError> {
    let mut media = None;
    let mut encoding_seen = false;
    for (name, value) in headers {
        if name.eq_ignore_ascii_case("content-type") && media.replace(value.as_str()).is_some() {
            return Err(OAuthDiscoveryError::InvalidRepresentation);
        }
        if name.eq_ignore_ascii_case("content-encoding") {
            if encoding_seen || !value.trim().eq_ignore_ascii_case("identity") {
                return Err(OAuthDiscoveryError::InvalidRepresentation);
            }
            encoding_seen = true;
        }
    }
    let mut parts = media.ok_or(OAuthDiscoveryError::InvalidRepresentation)?.split(';');
    if !parts.next().is_some_and(|value| value.trim().eq_ignore_ascii_case("application/json")) {
        return Err(OAuthDiscoveryError::InvalidRepresentation);
    }
    if let Some(parameter) = parts.next() {
        let (name, value) = parameter.trim().split_once('=').ok_or(OAuthDiscoveryError::InvalidRepresentation)?;
        let value = value.trim();
        if !name.trim().eq_ignore_ascii_case("charset")
            || !(value.eq_ignore_ascii_case("utf-8") || value.eq_ignore_ascii_case("\"utf-8\""))
            || parts.next().is_some()
        {
            return Err(OAuthDiscoveryError::InvalidRepresentation);
        }
    }
    Ok(())
}

fn check_context(cx: &Cx, deadline: Time) -> Result<(), OAuthDiscoveryError> {
    if cx.now() >= deadline {
        return Err(OAuthDiscoveryError::TimedOut);
    }
    cx.checkpoint().map_err(|_| OAuthDiscoveryError::Cancelled)
}

fn discovery_deadline(cx: &Cx, timeout: Duration) -> Result<Time, OAuthDiscoveryError> {
    if cx.checkpoint().is_err() {
        return Err(OAuthDiscoveryError::Cancelled);
    }
    if !cx.capabilities().io || cx.timer_driver().is_none() {
        return Err(OAuthDiscoveryError::RuntimeUnavailable);
    }
    let nanos = u64::try_from(timeout.as_nanos()).map_err(|_| OAuthDiscoveryError::InvalidPolicy)?;
    let end = cx.now().as_nanos().checked_add(nanos).ok_or(OAuthDiscoveryError::InvalidPolicy)?;
    Ok(cx.budget().deadline.map_or(Time::from_nanos(end), |parent| parent.min(Time::from_nanos(end))))
}

async fn within<T>(
    cx: &Cx,
    deadline: Time,
    future: impl Future<Output = Result<T, OAuthDiscoveryError>>,
) -> Result<T, OAuthDiscoveryError> {
    // Public Sleep resolves the driver when polled. The caller guard below
    // binds every registration and time read to this exact discovery owner,
    // even when a different/no Cx was ambient at future construction.
    if cx.timer_driver().is_none() {
        return Err(OAuthDiscoveryError::RuntimeUnavailable);
    }
    let mut sleep = std::pin::pin!(Sleep::new(deadline));
    let (_sender, mut receiver) = oneshot::channel::<()>();
    let mut cancelled = std::pin::pin!(receiver.recv(cx));
    let mut future = std::pin::pin!(future);
    poll_fn(|task| {
        check_context(cx, deadline)?;
        let _caller = Cx::set_current(Some(cx.clone()));
        if cancelled.as_mut().poll(task).is_ready() {
            return Poll::Ready(Err(OAuthDiscoveryError::Cancelled));
        }
        if sleep.as_mut().poll(task).is_ready() {
            return Poll::Ready(Err(OAuthDiscoveryError::TimedOut));
        }
        let result = future.as_mut().poll(task);
        check_context(cx, deadline)?;
        result
    }).await
}

async fn fetch_metadata(
    cx: &Cx,
    deadline: Time,
    url: &CanonicalHttpUrl,
    roots: &[Certificate],
) -> Result<Option<Vec<u8>>, OAuthDiscoveryError> {
    check_context(cx, deadline)?;
    let mut builder = HttpClient::builder()
        .redirect_policy(RedirectPolicy::None)
        .retry_policy(RetryPolicy::None)
        .no_proxy()
        .no_cookie_store()
        .max_body_size(MAX_OAUTH_METADATA_BYTES)
        .max_total_connections(1);
    for root in roots {
        builder = builder.add_root_certificate(root.clone());
    }
    let client = builder.build();
    let response = within(cx, deadline, async {
        client.request(cx, Method::Get, url.as_str(), vec![
            ("Accept".to_owned(), "application/json".to_owned()),
            ("Accept-Encoding".to_owned(), "identity".to_owned()),
            ("Connection".to_owned(), "close".to_owned()),
        ], Vec::new()).await.map_err(|_| OAuthDiscoveryError::TransportFailed)
    }).await?;
    if matches!(response.status, 404 | 410) {
        return Ok(None);
    }
    if response.status != 200 {
        return Err(OAuthDiscoveryError::HttpStatus { status: response.status });
    }
    validate_headers(&response.headers)?;
    if response.body.len() > MAX_OAUTH_METADATA_BYTES || !response.trailers.is_empty() {
        return Err(OAuthDiscoveryError::InvalidRepresentation);
    }
    Ok(Some(response.body))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn url(value: &str) -> CanonicalHttpUrl { CanonicalHttpUrl::parse(value).unwrap() }

    fn plan() -> OAuthDiscoveryPlan {
        OAuthDiscoveryPlan::new(url("https://resource.example/mcp"), vec![
            TrustedOAuthIssuer::new("https://issuer.example/tenant").unwrap(),
        ], "registered-client", vec!["tools:read".to_owned()]).unwrap()
    }

    fn issuer_document() -> serde_json::Value {
        json!({
            "issuer": "https://issuer.example/tenant",
            "authorization_endpoint": "https://issuer.example/authorize",
            "token_endpoint": "https://issuer.example/token",
            "response_types_supported": ["code"],
            "token_endpoint_auth_methods_supported": ["none"],
            "code_challenge_methods_supported": ["S256"],
            "authorization_response_iss_parameter_supported": true,
            "scopes_supported": ["tools:read"],
            "protected_resources": ["https://resource.example/mcp"]
        })
    }

    fn admit(plan: &OAuthDiscoveryPlan, document: &serde_json::Value) -> Result<OAuthClientConfiguration, OAuthDiscoveryError> {
        plan.admit_issuer(&plan.issuers[0], &serde_json::to_vec(document).unwrap())
    }

    #[test]
    fn well_known_paths_preserve_tenant_and_distinguish_rfc_and_oidc_layouts() {
        let paths = issuer_metadata_urls(&url("https://issuer.example:8443/tenant/")).unwrap();
        assert_eq!(paths.iter().map(CanonicalHttpUrl::as_str).collect::<Vec<_>>(), [
            "https://issuer.example:8443/.well-known/oauth-authorization-server/tenant",
            "https://issuer.example:8443/.well-known/openid-configuration/tenant",
            "https://issuer.example:8443/tenant/.well-known/openid-configuration",
        ]);
        assert_eq!(issuer_metadata_urls(&url("https://issuer.example")).unwrap().len(), 2);
        assert_eq!(resource_metadata_url(&url("https://[::1]:8443/mcp")).unwrap().as_str(),
            "https://[::1]:8443/.well-known/oauth-protected-resource/mcp");
    }

    #[test]
    fn local_issuer_order_wins_and_unknown_peer_urls_never_become_fetch_targets() {
        let mut plan = plan();
        plan.issuers.push(TrustedOAuthIssuer::new("https://second.example").unwrap());
        let body = json!({"resource": plan.resource.as_str(), "authorization_servers": [
            "http://127.0.0.1/private", "https://second.example", "https://issuer.example/tenant"
        ]});
        assert_eq!(plan.select_issuer(&serde_json::to_vec(&body).unwrap()).unwrap().identifier,
            "https://issuer.example/tenant");
        let unknown = br#"{"resource":"https://resource.example/mcp","authorization_servers":["https://unknown.example"]}"#;
        assert!(matches!(plan.select_issuer(unknown), Err(OAuthDiscoveryError::NoTrustedIssuer)));
    }

    #[test]
    fn valid_discovery_preserves_registration_resource_and_pkce_flow() {
        let plan = plan();
        let actual = admit(&plan, &issuer_document()).unwrap();
        let expected = OAuthClientConfiguration::from_trusted_endpoints(
            "https://issuer.example/tenant", url("https://issuer.example/authorize"),
            url("https://issuer.example/token"), plan.resource.clone(),
            "registered-client", vec!["tools:read".to_owned()],
        ).unwrap();
        assert_eq!(actual, expected);
    }

    #[test]
    fn metadata_must_match_exact_resource_and_issuer_not_just_the_origin() {
        let plan = plan();
        let wrong_resource = br#"{"resource":"https://resource.example/","authorization_servers":["https://issuer.example/tenant"]}"#;
        assert!(matches!(plan.select_issuer(wrong_resource), Err(OAuthDiscoveryError::ResourceMismatch)));
        for issuer in ["https://issuer.example/tenant/", "https://ISSUER.example/tenant", "https://other.example/tenant"] {
            let mut document = issuer_document();
            document["issuer"] = json!(issuer);
            assert!(matches!(admit(&plan, &document), Err(OAuthDiscoveryError::IssuerMismatch)));
        }
    }

    #[test]
    fn metadata_cannot_relax_s256_public_client_or_query_response_requirements() {
        let plan = plan();
        for (member, value) in [
            ("code_challenge_methods_supported", json!(["plain"])),
            ("token_endpoint_auth_methods_supported", json!(["client_secret_basic"])),
            ("authorization_response_iss_parameter_supported", json!(false)),
            ("response_types_supported", json!(["token"])),
            ("grant_types_supported", json!(["client_credentials"])),
            ("response_modes_supported", json!(["fragment"])),
        ] {
            let mut document = issuer_document();
            document[member] = value;
            assert!(matches!(admit(&plan, &document), Err(OAuthDiscoveryError::UnsupportedFlow)));
        }
        for member in ["code_challenge_methods_supported", "token_endpoint_auth_methods_supported", "authorization_response_iss_parameter_supported"] {
            let mut document = issuer_document();
            document.as_object_mut().unwrap().remove(member);
            assert!(matches!(admit(&plan, &document), Err(OAuthDiscoveryError::UnsupportedFlow)));
        }
    }

    #[test]
    fn public_client_revocation_endpoint_requires_explicit_none_and_origin_trust() {
        let mut plan = plan();
        let mut document = issuer_document();
        document["revocation_endpoint"] = json!("https://issuer.example/revoke");
        document["revocation_endpoint_auth_methods_supported"] = json!(["none"]);
        let configuration = admit(&plan, &document).unwrap();
        assert_eq!(
            configuration.revocation_endpoint().map(CanonicalHttpUrl::as_str),
            Some("https://issuer.example/revoke"),
        );

        document["revocation_endpoint_auth_methods_supported"] = json!(["client_secret_basic"]);
        assert!(admit(&plan, &document).unwrap().revocation_endpoint().is_none());
        document.as_object_mut().unwrap().remove("revocation_endpoint_auth_methods_supported");
        assert!(admit(&plan, &document).unwrap().revocation_endpoint().is_none());

        document["revocation_endpoint_auth_methods_supported"] = json!(["none"]);
        document["revocation_endpoint"] = json!("https://tokens.example/revoke");
        assert!(matches!(admit(&plan, &document), Err(OAuthDiscoveryError::EndpointNotTrusted)));
        plan.issuers[0] = plan.issuers[0].clone()
            .with_endpoint_origin(url("https://tokens.example/")).unwrap();
        assert_eq!(
            admit(&plan, &document).unwrap().revocation_endpoint().map(CanonicalHttpUrl::as_str),
            Some("https://tokens.example/revoke"),
        );

        document["revocation_endpoint"] = serde_json::Value::Null;
        assert!(matches!(admit(&plan, &document), Err(OAuthDiscoveryError::InvalidMetadata)));
    }

    #[test]
    fn cross_origin_token_endpoint_needs_an_explicit_host_grant() {
        let mut plan = plan();
        let mut document = issuer_document();
        document["token_endpoint"] = json!("https://tokens.example/exchange");
        assert!(matches!(admit(&plan, &document), Err(OAuthDiscoveryError::EndpointNotTrusted)));
        plan.issuers[0] = plan.issuers[0].clone().with_endpoint_origin(url("https://tokens.example/")).unwrap();
        assert!(admit(&plan, &document).is_ok());
        for endpoint in ["http://tokens.example/exchange", "https://user@tokens.example/exchange", "https://tokens.example/exchange?q=1", "https://tokens.example/exchange#x"] {
            document["token_endpoint"] = json!(endpoint);
            assert!(admit(&plan, &document).is_err());
        }
    }

    #[test]
    fn scopes_and_reverse_resource_associations_cannot_expand_authority() {
        let plan = plan();
        let mut document = issuer_document();
        document["scopes_supported"] = json!(["admin"]);
        assert!(matches!(admit(&plan, &document), Err(OAuthDiscoveryError::UnsupportedScopes)));
        document = issuer_document();
        document["protected_resources"] = json!(["https://other.example/mcp"]);
        assert!(matches!(admit(&plan, &document), Err(OAuthDiscoveryError::ResourceMismatch)));
        let resource = br#"{"resource":"https://resource.example/mcp","authorization_servers":["https://issuer.example/tenant"],"bearer_methods_supported":["body"]}"#;
        assert!(matches!(plan.select_issuer(resource), Err(OAuthDiscoveryError::UnsupportedFlow)));
    }

    #[test]
    fn null_duplicate_and_signed_security_metadata_is_not_silently_accepted() {
        let plan = plan();
        for suffix in [",\"issuer\":\"https://other.example\"", ",\"iss\\u0075er\":\"https://other.example\""] {
            let encoded = serde_json::to_string(&issuer_document()).unwrap();
            let body = format!("{}{suffix}}}", &encoded[..encoded.len() - 1]);
            assert!(matches!(plan.admit_issuer(&plan.issuers[0], body.as_bytes()), Err(OAuthDiscoveryError::InvalidMetadata)));
        }
        let mut document = issuer_document();
        document["grant_types_supported"] = serde_json::Value::Null;
        assert!(matches!(admit(&plan, &document), Err(OAuthDiscoveryError::InvalidMetadata)));
        document = issuer_document();
        document["signed_metadata"] = json!("unverified.jwt.claims");
        assert!(matches!(admit(&plan, &document), Err(OAuthDiscoveryError::SignedMetadataUnsupported)));
        let oversized = vec![b' '; MAX_OAUTH_METADATA_BYTES + 1];
        assert!(matches!(plan.select_issuer(&oversized), Err(OAuthDiscoveryError::InvalidMetadata)));
    }

    #[test]
    fn metadata_requires_objects_not_positional_structs_or_batch_arrays() {
        let plan = plan();
        let resource = json!({
            "resource": "https://resource.example/mcp",
            "authorization_servers": ["https://issuer.example/tenant"]
        });
        let admitted = format!(" \r\n\t{resource}");
        assert!(plan.select_issuer(admitted.as_bytes()).is_ok());
        for body in [
            json!(["https://resource.example/mcp", ["https://issuer.example/tenant"]]),
            json!([resource]), json!(null), json!(true), json!("{}"),
        ] {
            assert!(matches!(plan.select_issuer(body.to_string().as_bytes()), Err(OAuthDiscoveryError::InvalidMetadata)));
        }
        let positional = json!([
            "https://issuer.example/tenant", "https://issuer.example/authorize",
            "https://issuer.example/token", ["code"], ["authorization_code"],
            ["query"], ["none"], ["S256"], true, ["tools:read"],
            ["https://resource.example/mcp"]
        ]);
        assert!(matches!(admit(&plan, &positional), Err(OAuthDiscoveryError::InvalidMetadata)));
        assert!(matches!(admit(&plan, &json!([issuer_document()])), Err(OAuthDiscoveryError::InvalidMetadata)));
        assert!(admit(&plan, &issuer_document()).is_ok());
    }

    #[test]
    fn representation_requires_single_uncoded_json_content_type() {
        assert!(validate_headers(&[("Content-Type".into(), "application/json; charset=\"utf-8\"".into())]).is_ok());
        for headers in [
            vec![],
            vec![("Content-Type".into(), "text/html".into())],
            vec![("Content-Type".into(), "application/json".into()), ("content-type".into(), "application/json".into())],
            vec![("Content-Type".into(), "application/json".into()), ("Content-Encoding".into(), "gzip".into())],
            vec![("Content-Type".into(), "application/json; charset=\"utf-8".into())],
        ] {
            assert!(matches!(validate_headers(&headers), Err(OAuthDiscoveryError::InvalidRepresentation)));
        }
    }

    #[test]
    fn trust_policy_rejects_ambiguous_issuers_and_overbroad_origin_grants() {
        assert!(TrustedOAuthIssuer::new("http://localhost/issuer").is_err());
        assert!(TrustedOAuthIssuer::new("https://issuer.example?query").is_err());
        assert!(TrustedOAuthIssuer::new("https://issuer.example").unwrap()
            .with_endpoint_origin(url("https://other.example/some-path")).is_err());
        let issuer = TrustedOAuthIssuer::new("https://issuer.example").unwrap();
        assert!(OAuthDiscoveryPlan::new(url("https://resource.example/mcp"),
            vec![issuer.clone(), issuer], "client", vec![]).is_err());
        assert!(plan().with_timeout(Duration::ZERO).is_err());
        assert!(plan().with_timeout(Duration::from_secs(121)).is_err());
    }

    #[test]
    fn constructed_resource_candidates_preserve_path_and_deduplicate_root() {
        let candidates = resource_metadata_urls(&url("https://[::1]:8443/a%2Fb/")).unwrap();
        assert_eq!(candidates.iter().map(|(_, url)| url.as_str()).collect::<Vec<_>>(), [
            "https://[::1]:8443/.well-known/oauth-protected-resource/a%2Fb/",
            "https://[::1]:8443/.well-known/oauth-protected-resource",
        ]);
        assert_eq!(candidates[0].0, ResourceMetadataLocation::PathSpecific);
        assert_eq!(candidates[1].0, ResourceMetadataLocation::OriginRoot);
        let root = resource_metadata_urls(&url("https://resource.example/")).unwrap();
        assert_eq!(root.len(), 1);
        assert_eq!(root[0].0, ResourceMetadataLocation::OriginRoot);
        assert_eq!(root[0].1.as_str(), "https://resource.example/.well-known/oauth-protected-resource");
    }

    #[test]
    fn constructed_resource_candidates_do_not_accept_unadmitted_endpoint_shapes() {
        for endpoint in ["http://resource.example/mcp", "https://resource.example/mcp?q=1",
            "https://resource.example/mcp#x", "https://user@resource.example/mcp"] {
            assert!(resource_metadata_urls(&url(endpoint)).is_err());
        }
    }

    #[test]
    fn constructed_schedule_reserves_root_and_issuer_before_first_fetch() {
        let now = Time::from_nanos(100);
        let end = Time::from_nanos(500);
        assert_eq!(resource_candidate_deadlines(now, end, 2).unwrap(), [Time::from_nanos(200), Time::from_nanos(300)]);
        assert_eq!(resource_candidate_deadlines(now, end, 1).unwrap(), [Time::from_nanos(300)]);
        for count in [0, 3, usize::MAX] { assert!(resource_candidate_deadlines(now, end, count).is_err()); }
        assert!(resource_candidate_deadlines(now, now, 2).is_err());
        assert!(resource_candidate_deadlines(now, Time::from_nanos(103), 2).is_err());
        let near_max = resource_candidate_deadlines(Time::from_nanos(u64::MAX - 40), Time::from_nanos(u64::MAX), 2).unwrap();
        assert_eq!(near_max, [Time::from_nanos(u64::MAX - 30), Time::from_nanos(u64::MAX - 20)]);
    }

    #[test]
    fn aggregate_prm_failure_keeps_order_and_integrity_precedes_later_absence() {
        let failure = ResourceMetadataFailure { attempts: vec![
            ResourceMetadataAttempt { location: ResourceMetadataLocation::PathSpecific, cause: ResourceMetadataCause::ResourceMismatch },
            ResourceMetadataAttempt { location: ResourceMetadataLocation::OriginRoot, cause: ResourceMetadataCause::NotFound },
        ], interrupted: None };
        assert_eq!(failure.classification(), ResourceMetadataFailureClass::TrustOrIntegrity);
        assert_eq!(failure.attempts()[0].cause(), ResourceMetadataCause::ResourceMismatch);
        assert_eq!(failure.attempts()[1].location(), ResourceMetadataLocation::OriginRoot);
        let error = OAuthDiscoveryError::ResourceMetadataExhausted(failure);
        let diagnostics = format!("{error:?} {error}");
        assert!(!diagnostics.contains("https://"));
        assert!(diagnostics.contains("PathSpecific") && diagnostics.contains("OriginRoot"));
    }

    #[test]
    fn aggregate_prm_failure_classification_is_independent_of_candidate_order() {
        let causes = [
            (ResourceMetadataCause::NotFound, ResourceMetadataFailureClass::NotFound),
            (ResourceMetadataCause::CandidateDeadline, ResourceMetadataFailureClass::Transport),
            (ResourceMetadataCause::InvalidMetadata, ResourceMetadataFailureClass::ProtocolOrHttp),
            (ResourceMetadataCause::NoTrustedIssuer, ResourceMetadataFailureClass::TrustOrIntegrity),
            (ResourceMetadataCause::Cancelled, ResourceMetadataFailureClass::Cancelled),
        ];
        for (low_index, (low, _)) in causes.iter().enumerate() {
            for (high, expected) in &causes[low_index..] {
                for pair in [[*low, *high], [*high, *low]] {
                    let failure = ResourceMetadataFailure { attempts: pair.into_iter().map(|cause| ResourceMetadataAttempt {
                        location: ResourceMetadataLocation::PathSpecific, cause,
                    }).collect(), interrupted: None };
                    assert_eq!(failure.classification(), *expected);
                }
            }
        }
    }

    #[test]
    fn interrupted_prm_failure_retains_attempts_without_inventing_a_root_fetch() {
        for reason in [ResourceMetadataFailureClass::Cancelled, ResourceMetadataFailureClass::OverallDeadline] {
            let failure = ResourceMetadataFailure { attempts: vec![ResourceMetadataAttempt {
                location: ResourceMetadataLocation::PathSpecific, cause: ResourceMetadataCause::ResourceMismatch,
            }], interrupted: Some(reason) };
            assert_eq!(failure.classification(), reason);
            assert_eq!(failure.attempts().len(), 1);
            assert_eq!(failure.attempts()[0].cause(), ResourceMetadataCause::ResourceMismatch);
        }
    }
}
