//! Caller-owned RFC 7662 authentication against a configured HTTPS endpoint.
//!
//! Install IntrospectionVerifier in TokenAuthProvider on asynchronous native HTTP
//! ingress. Each verification performs one fresh authenticated guarded POST.
//! There is no token cache, discovery, redirect, retry, ambient proxy, private
//! runtime or detached renewal task.
//!
//! This resource-server profile requires active=true plus trusted iss, aud, sub,
//! client_id, iat and exp evidence. RFC 7662 makes all but active optional in
//! general; a deployment that omits these facts cannot establish this profile's
//! resource authority. Audience mappings use AcceptedAudiencePolicy, shared with
//! JWT authentication. Only configured scopes grant authority. Sender-constrained
//! tokens are refused.
//! This local profile requires exactly one distinct locally accepted audience:
//! multiple different migration aliases in one response are refused. Repeated
//! copies of the same audience remain valid. RFC 7662 itself does not impose this
//! one-local-binding restriction; switching aliases across tokens preserves owner.
//!
//! Share one IntrospectionAdmissionPool across a deployment's verifiers. The
//! same configured provider/deployment uses one conservative source bucket (two
//! concurrent requests by default), irrespective of credentials, claims or
//! request IDs. This is not per-IP fairness. Native connection admission remains
//! separate. Saturation never dispatches a request or invents an inactive verdict.
//!
//! Secret replacement and local revocation fence in-flight responses. Already
//! admitted work is not cancelled by administrative changes. Enable secured SSE
//! revalidation when continuing output depends on fresh authorization.

use std::collections::{BTreeSet, HashMap};
use std::fmt;
use std::future::{Future, poll_fn};
use std::pin::pin;
use std::sync::{Arc, Mutex, RwLock};
use std::task::Poll;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use asupersync::security::SecretString;
use asupersync::time::Sleep;
use base64::{Engine as _, engine::general_purpose::STANDARD};
use fastmcp_core::{
    AbsoluteUri, AccessToken, AuthContext, MAX_ACCESS_TOKEN_BYTES, McpContext, McpError,
    McpErrorCode, McpResult, Sha256Digest, sha256_bounded,
};
use fastmcp_protocol::{SecurityDocumentKind, admit_security_document};
use fastmcp_transport::http::{
    GuardedHttpFetchError, GuardedHttpFetchResponse, GuardedHttpFetcher, GuardedHttpRequest,
    GuardedHttpsUrl,
};
use serde_json::{Value, json};
use zeroize::Zeroizing;

use super::jwt_resource::{AcceptedAudienceId, AcceptedAudiencePolicy};
use crate::auth::{AuthFuture, AuthRequest, TokenVerifier, principal_fingerprint};

const MAX_IDENTIFIER_BYTES: usize = 1024;
const MAX_ENDPOINT_BYTES: usize = 2048;
const MAX_SCOPES: usize = 64;
const MAX_SCOPE_BYTES: usize = 256;
const MAX_AUDIENCES: usize = 16;
const MAX_NUMERIC_DATE: u64 = 9_007_199_254_740_991;
const MAX_TOKEN_LIFETIME_SECONDS: u64 = 86_400;
/// Fetcher-enforced allocation ceiling for an introspection response.
pub const MAX_INTROSPECTION_RESPONSE_BYTES: usize = 16 * 1024;
const MAX_ATTEMPT_TIMEOUT: Duration = Duration::from_secs(30);
const SOURCE_DOMAIN: &[u8] = b"fastmcp/introspection-source/v1\0";
const POLICY_DOMAIN: &[u8] = b"fastmcp/introspection-policy/v1\0";
const OWNER_DOMAIN: &[u8] = b"fastmcp/introspection-owner/v1\0";
const MAX_SOURCE_BYTES: usize = SOURCE_DOMAIN.len() + 2 * (8 + MAX_IDENTIFIER_BYTES);
const MAX_POLICY_BYTES: usize = POLICY_DOMAIN.len()
    + 32
    + 24
    + 2 * (8 + MAX_ENDPOINT_BYTES)
    + (8 + MAX_IDENTIFIER_BYTES)
    + MAX_SCOPES * (8 + MAX_SCOPE_BYTES);
const MAX_OWNER_BYTES: usize = OWNER_DOMAIN.len() + 32 + 2 * (8 + MAX_IDENTIFIER_BYTES);

/// Fixed diagnostics contain no credential, URL, subject, scope or peer text.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IntrospectionError {
    InvalidPolicy,
    InvalidCredential,
    Inactive,
    InvalidResponse,
    InvalidClaims,
    Saturated,
    EndpointUnavailable,
    ClockUnavailable,
    Cancelled,
    TimedOut,
    Revoked,
    PolicyChanged,
    AsyncRequired,
}

impl fmt::Display for IntrospectionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::InvalidPolicy => "invalid introspection authentication policy",
            Self::InvalidCredential => "invalid opaque access credential",
            Self::Inactive => "inactive access credential",
            Self::InvalidResponse => "invalid introspection response",
            Self::InvalidClaims => "introspection facts do not satisfy resource policy",
            Self::Saturated => "introspection capacity exhausted",
            Self::EndpointUnavailable => "introspection endpoint unavailable",
            Self::ClockUnavailable => "introspection clock unavailable",
            Self::Cancelled => "introspection cancelled",
            Self::TimedOut => "introspection deadline exceeded",
            Self::Revoked => "introspection verifier revoked",
            Self::PolicyChanged => "introspection credential generation changed",
            Self::AsyncRequired => "introspection requires asynchronous authentication",
        })
    }
}
impl std::error::Error for IntrospectionError {}

/// Immutable issuer/resource, destination, grant and lifetime authority.
#[derive(Clone)]
pub struct IntrospectionPolicy {
    audiences: AcceptedAudiencePolicy,
    endpoint: GuardedHttpsUrl,
    endpoint_identity: String,
    scopes: BTreeSet<String>,
    maximum_lifetime_seconds: u64,
    source_limit: usize,
}

impl IntrospectionPolicy {
    /// Requires an explicitly configured HTTPS DNS endpoint of at most 2048
    /// bytes without userinfo/fragments, at most 64 unique RFC 6749 scope tokens,
    /// and a nonzero whole-second lifetime of at most 24 hours.
    ///
    /// The endpoint need not share the issuer's origin. That trust relationship
    /// comes only from configuration. offline_access is not a resource grant.
    pub fn new(
        audiences: AcceptedAudiencePolicy,
        endpoint: impl Into<String>,
        allowed_scopes: impl IntoIterator<Item = String>,
        maximum_token_lifetime: Duration,
    ) -> Result<Self, IntrospectionError> {
        let endpoint_identity = endpoint.into();
        if endpoint_identity.len() > MAX_ENDPOINT_BYTES
            || AbsoluteUri::parse(&endpoint_identity).is_err()
            || maximum_token_lifetime.is_zero()
            || maximum_token_lifetime.subsec_nanos() != 0
            || maximum_token_lifetime.as_secs() > MAX_TOKEN_LIFETIME_SECONDS
        {
            return Err(IntrospectionError::InvalidPolicy);
        }
        let endpoint = GuardedHttpsUrl::parse(&endpoint_identity)
            .map_err(|_| IntrospectionError::InvalidPolicy)?;
        let mut scopes = BTreeSet::new();
        for scope in allowed_scopes {
            if scopes.len() == MAX_SCOPES
                || !valid_scope(&scope)
                || scope == "offline_access"
                || !scopes.insert(scope)
            {
                return Err(IntrospectionError::InvalidPolicy);
            }
        }
        Ok(Self {
            audiences,
            endpoint,
            endpoint_identity,
            scopes,
            maximum_lifetime_seconds: maximum_token_lifetime.as_secs(),
            source_limit: 2,
        })
    }

    /// Limits the configured provider/deployment bucket to 1 through 8
    /// concurrent requests. The shared deployment bound also applies.
    pub fn with_source_limit(mut self, maximum: usize) -> Result<Self, IntrospectionError> {
        if !(1..=8).contains(&maximum) {
            return Err(IntrospectionError::InvalidPolicy);
        }
        self.source_limit = maximum;
        Ok(self)
    }
}

impl fmt::Debug for IntrospectionPolicy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("IntrospectionPolicy")
            .field(
                "configuration_generation",
                &self.audiences.configuration_generation(),
            )
            .field("scope_count", &self.scopes.len())
            .field("maximum_lifetime_seconds", &self.maximum_lifetime_seconds)
            .field("source_limit", &self.source_limit)
            .finish_non_exhaustive()
    }
}

/// Shared immediate admission; no queue or raw credential is retained.
#[derive(Clone)]
pub struct IntrospectionAdmissionPool {
    state: Arc<Mutex<AdmissionState>>,
    maximum: usize,
}

#[derive(Default)]
struct AdmissionState {
    total: usize,
    sources: HashMap<Sha256Digest, usize>,
}

impl IntrospectionAdmissionPool {
    /// A deployment permits 1 through 256 concurrent introspections. Retain and
    /// clone this pool for every provider in that deployment.
    pub fn new(maximum: usize) -> Result<Self, IntrospectionError> {
        if !(1..=256).contains(&maximum) {
            return Err(IntrospectionError::InvalidPolicy);
        }
        Ok(Self {
            state: Arc::new(Mutex::new(AdmissionState::default())),
            maximum,
        })
    }

    fn acquire(
        &self,
        source: Sha256Digest,
        maximum_source: usize,
    ) -> Result<IntrospectionPermit, IntrospectionError> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| IntrospectionError::EndpointUnavailable)?;
        let active = state.sources.get(&source).copied().unwrap_or(0);
        if state.total >= self.maximum || active >= maximum_source {
            return Err(IntrospectionError::Saturated);
        }
        state.sources.insert(source, active + 1);
        state.total += 1;
        Ok(IntrospectionPermit {
            pool: self.clone(),
            source,
        })
    }
}

impl Default for IntrospectionAdmissionPool {
    fn default() -> Self {
        Self {
            state: Arc::new(Mutex::new(AdmissionState::default())),
            maximum: 32,
        }
    }
}

impl fmt::Debug for IntrospectionAdmissionPool {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("IntrospectionAdmissionPool")
            .field("maximum", &self.maximum)
            .finish_non_exhaustive()
    }
}

struct IntrospectionPermit {
    pool: IntrospectionAdmissionPool,
    source: Sha256Digest,
}

impl Drop for IntrospectionPermit {
    fn drop(&mut self) {
        let Ok(mut state) = self.pool.state.lock() else {
            return;
        };
        if let Some(active) = state.sources.get_mut(&self.source) {
            *active -= 1;
            if *active == 0 {
                state.sources.remove(&self.source);
            }
            state.total -= 1;
        }
    }
}

struct EndpointCredential {
    authorization: SecretString,
}
struct CredentialState {
    generation: u64,
    active: Option<Arc<EndpointCredential>>,
}

/// Request-owned verification with shared administrative secret rotation.
///
/// The resource server authenticates with its own client_secret_basic
/// credential. The caller's Bearer token is sent only in the token form field.
/// Request data cannot select the destination, roots, policy or endpoint secret.
#[derive(Clone)]
pub struct IntrospectionVerifier {
    policy: Arc<IntrospectionPolicy>,
    fetcher: Arc<GuardedHttpFetcher>,
    client_id: Arc<str>,
    credentials: Arc<RwLock<CredentialState>>,
    admission: IntrospectionAdmissionPool,
    source: Sha256Digest,
    identity: Sha256Digest,
    #[cfg(test)]
    test_exchange: Option<Arc<dyn test_support::Exchange>>,
}

impl fmt::Debug for IntrospectionVerifier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("IntrospectionVerifier")
            .field("policy", &self.policy)
            .field("admission", &self.admission)
            .finish_non_exhaustive()
    }
}

impl IntrospectionVerifier {
    /// Binds the trusted endpoint and resource-server Basic credential. The
    /// fetcher must enforce at most 16 KiB response allocation and a finite
    /// total timeout of at most 30 seconds. A shorter caller deadline wins.
    pub fn new(
        policy: IntrospectionPolicy,
        fetcher: GuardedHttpFetcher,
        client_id: impl Into<String>,
        client_secret: SecretString,
        admission: IntrospectionAdmissionPool,
    ) -> Result<Self, IntrospectionError> {
        let client_id = client_id.into();
        if !valid_identifier(&client_id)
            || fetcher.policy().response_body_bytes() > MAX_INTROSPECTION_RESPONSE_BYTES
            || fetcher.policy().deadline() > MAX_ATTEMPT_TIMEOUT
            || fetcher.root_identity().len() > MAX_ENDPOINT_BYTES
        {
            return Err(IntrospectionError::InvalidPolicy);
        }
        let credential = Arc::new(endpoint_credential(&client_id, client_secret)?);
        let mut source = Vec::with_capacity(MAX_SOURCE_BYTES);
        source.extend_from_slice(SOURCE_DOMAIN);
        frame(&mut source, policy.audiences.provider_identity())?;
        frame(&mut source, policy.audiences.deployment_identity())?;
        let source = sha256_bounded(&source, MAX_SOURCE_BYTES)
            .map_err(|_| IntrospectionError::InvalidPolicy)?;
        let mut identity = Vec::with_capacity(MAX_POLICY_BYTES);
        identity.extend_from_slice(POLICY_DOMAIN);
        identity.extend_from_slice(policy.audiences.identity().as_bytes());
        frame(&mut identity, &policy.endpoint_identity)?;
        frame(&mut identity, fetcher.root_identity())?;
        frame(&mut identity, &client_id)?;
        identity.extend_from_slice(&policy.maximum_lifetime_seconds.to_be_bytes());
        identity.extend_from_slice(&(policy.source_limit as u64).to_be_bytes());
        identity.extend_from_slice(&(policy.scopes.len() as u64).to_be_bytes());
        for scope in &policy.scopes {
            frame(&mut identity, scope)?;
        }
        let identity = sha256_bounded(&identity, MAX_POLICY_BYTES)
            .map_err(|_| IntrospectionError::InvalidPolicy)?;
        Ok(Self {
            policy: Arc::new(policy),
            fetcher: Arc::new(fetcher),
            client_id: Arc::from(client_id),
            credentials: Arc::new(RwLock::new(CredentialState {
                generation: 1,
                active: Some(credential),
            })),
            admission,
            source,
            identity,
            #[cfg(test)]
            test_exchange: None,
        })
    }

    /// Atomically replaces the Basic secret for every clone. Client identity,
    /// policy and owner partition remain fixed. In-flight old-generation
    /// responses are rejected. Invalid replacement leaves current state intact.
    pub fn replace_client_secret(&self, secret: SecretString) -> Result<(), IntrospectionError> {
        let replacement = Arc::new(endpoint_credential(&self.client_id, secret)?);
        let mut state = self
            .credentials
            .write()
            .map_err(|_| IntrospectionError::EndpointUnavailable)?;
        let generation = state
            .generation
            .checked_add(1)
            .ok_or(IntrospectionError::PolicyChanged)?;
        let retired = state.active.replace(replacement);
        state.generation = generation;
        drop(state);
        drop(retired);
        Ok(())
    }

    /// Disables every clone and fences all in-flight responses. A valid explicit
    /// secret replacement is required to reactivate this verifier.
    pub fn revoke_all(&self) -> Result<(), IntrospectionError> {
        let mut state = self
            .credentials
            .write()
            .map_err(|_| IntrospectionError::EndpointUnavailable)?;
        let generation = state
            .generation
            .checked_add(1)
            .ok_or(IntrospectionError::PolicyChanged)?;
        let retired = state.active.take();
        state.generation = generation;
        drop(state);
        drop(retired);
        Ok(())
    }

    /// Performs one fresh bounded introspection on the caller's runtime.
    ///
    /// AuthContext receives only subject, configured scope grants, canonical
    /// resource, issuer and client. It carries a conservative monotonic expiry
    /// ceiling. No response token, username, raw audience, timestamps, or private
    /// claims are exposed. Secret rotation never silently retries a request.
    pub async fn verify_access_token_async(
        &self,
        ctx: &McpContext,
        token: &AccessToken,
    ) -> Result<AuthContext, IntrospectionError> {
        checkpoint(ctx)?;
        if !token.scheme.eq_ignore_ascii_case("Bearer")
            || token.token.len() > MAX_ACCESS_TOKEN_BYTES
            || !AccessToken::is_valid_token68(&token.token)
        {
            return Err(IntrospectionError::InvalidCredential);
        }
        let permit = Arc::new(
            self.admission
                .acquire(self.source, self.policy.source_limit)?,
        );
        let (generation, credential) = {
            let state = self
                .credentials
                .read()
                .map_err(|_| IntrospectionError::EndpointUnavailable)?;
            (
                state.generation,
                state.active.clone().ok_or(IntrospectionError::Revoked)?,
            )
        };
        let request = introspection_request(token, &credential)?;
        let started = Instant::now();
        let started_wall = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| IntrospectionError::ClockUnavailable)?;
        let lifetime: Arc<dyn Send + Sync> = permit.clone();
        let future = self.exchange(ctx, &request, lifetime);
        let mut future = pin!(future);
        let cancellation = ctx.request_cancelled();
        let mut cancellation = pin!(cancellation);
        let timeout = self.fetcher.policy().deadline();
        let nanos =
            u64::try_from(timeout.as_nanos()).map_err(|_| IntrospectionError::InvalidPolicy)?;
        let deadline = ctx.cx().now().saturating_add_nanos(nanos);
        let caller_deadline = ctx
            .budget()
            .deadline
            .map_or(deadline, |limit| limit.min(deadline));
        let timer = Sleep::new(caller_deadline);
        let mut timer = pin!(timer);
        let response = poll_fn(|task| {
            // Sleep binds its timer at poll time through the ambient Cx. Direct
            // callers may pass an explicit context without installing it; use
            // and restore that exact caller context for every poll.
            let ceiling = crate::auth::ambient_auth_capability_ceiling();
            let _current = asupersync::Cx::set_current(Some(ctx.cx().clone()));
            let _restriction = asupersync::Cx::push_restriction(ceiling);
            let capabilities = asupersync::Cx::current()
                .expect("caller context installed")
                .capabilities();
            if !capabilities.spawn
                || !capabilities.time
                || !capabilities.entropy
                || !capabilities.io
                || !capabilities.remote
            {
                return Poll::Ready(Err(IntrospectionError::EndpointUnavailable));
            }
            if let Err(error) = checkpoint(ctx) {
                return Poll::Ready(Err(error));
            }
            if started.elapsed() >= timeout {
                return Poll::Ready(Err(IntrospectionError::TimedOut));
            }
            if cancellation.as_mut().poll(task).is_ready() {
                return Poll::Ready(Err(IntrospectionError::Cancelled));
            }
            let response = future.as_mut().poll(task);
            if let Err(error) = checkpoint(ctx) {
                return Poll::Ready(Err(error));
            }
            if started.elapsed() >= timeout {
                return Poll::Ready(Err(IntrospectionError::TimedOut));
            }
            if let Poll::Ready(response) = response {
                return Poll::Ready(response);
            }
            if ctx.cx().timer_driver().is_none() {
                return Poll::Ready(Err(IntrospectionError::EndpointUnavailable));
            }
            if timer.as_mut().poll(task).is_ready() {
                return Poll::Ready(Err(IntrospectionError::TimedOut));
            }
            Poll::Pending
        })
        .await?;
        checkpoint(ctx)?;
        // Sample monotonic first: the time between the two samples can only
        // shorten, never extend, the expiry bound. Keep subsecond wall precision.
        let received = Instant::now();
        let wall = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| IntrospectionError::ClockUnavailable)?;
        if wall < started_wall {
            return Err(IntrospectionError::ClockUnavailable);
        }
        let elapsed_floor = started_wall
            .checked_add(started.elapsed())
            .ok_or(IntrospectionError::ClockUnavailable)?;
        let facts = self.admit_response(response, wall.max(elapsed_floor), received)?;
        let state = self
            .credentials
            .read()
            .map_err(|_| IntrospectionError::EndpointUnavailable)?;
        checkpoint(ctx)?;
        if state.generation != generation
            || !state
                .active
                .as_ref()
                .is_some_and(|current| Arc::ptr_eq(current, &credential))
        {
            return Err(IntrospectionError::PolicyChanged);
        }
        if facts
            .verification_valid_until()
            .is_none_or(|expiry| Instant::now() >= expiry)
        {
            return Err(IntrospectionError::InvalidClaims);
        }
        Ok(facts)
    }

    async fn exchange(
        &self,
        ctx: &McpContext,
        request: &GuardedHttpRequest,
        lifetime: Arc<dyn Send + Sync>,
    ) -> Result<GuardedHttpFetchResponse, IntrospectionError> {
        #[cfg(test)]
        if let Some(exchange) = &self.test_exchange {
            let _lifetime = lifetime;
            return exchange.post(ctx, &self.policy.endpoint, request).await;
        }
        self.fetcher
            .post_with_lifetime(ctx.cx(), &self.policy.endpoint, request, lifetime)
            .await
            .map_err(|error| match error {
                GuardedHttpFetchError::Cancelled => IntrospectionError::Cancelled,
                GuardedHttpFetchError::DeadlineExceeded => IntrospectionError::TimedOut,
                _ => IntrospectionError::EndpointUnavailable,
            })
    }

    fn admit_response(
        &self,
        response: GuardedHttpFetchResponse,
        now: Duration,
        received: Instant,
    ) -> Result<AuthContext, IntrospectionError> {
        if response.status != 200 || response.redirect.is_some() {
            return Err(IntrospectionError::EndpointUnavailable);
        }
        let mut content_types = response
            .headers
            .iter()
            .filter(|(name, _)| name.eq_ignore_ascii_case("content-type"));
        if !content_types
            .next()
            .is_some_and(|(_, value)| json_content_type(value))
            || content_types.next().is_some()
            || response.body.len() > MAX_INTROSPECTION_RESPONSE_BYTES
        {
            return Err(IntrospectionError::InvalidResponse);
        }
        let body = Zeroizing::new(response.body);
        admit_security_document(SecurityDocumentKind::TokenResponse, &body)
            .map_err(|_| IntrospectionError::InvalidResponse)?;
        let document: Value =
            serde_json::from_slice(&body).map_err(|_| IntrospectionError::InvalidResponse)?;
        self.admit_facts(&document, now, received)
    }

    fn admit_facts(
        &self,
        document: &Value,
        now: Duration,
        received: Instant,
    ) -> Result<AuthContext, IntrospectionError> {
        let object = document
            .as_object()
            .ok_or(IntrospectionError::InvalidResponse)?;
        match object.get("active").and_then(Value::as_bool) {
            Some(true) => {}
            Some(false) => return Err(IntrospectionError::Inactive),
            None => return Err(IntrospectionError::InvalidResponse),
        }
        let required = |key: &str| object.get(key).ok_or(IntrospectionError::InvalidClaims);
        if identifier(required("iss")?)? != self.policy.audiences.issuer()
            || [
                "cnf",
                "authorization_details",
                "error",
                "access_token",
                "refresh_token",
                "id_token",
            ]
            .iter()
            .any(|name| object.contains_key(*name))
        {
            return Err(IntrospectionError::InvalidClaims);
        }
        if let Some(kind) = object.get("token_type") {
            if !kind
                .as_str()
                .is_some_and(|kind| kind.eq_ignore_ascii_case("Bearer"))
            {
                return Err(IntrospectionError::InvalidClaims);
            }
        }
        admit_audiences(required("aud")?, &self.policy.audiences)?;
        let subject = identifier(required("sub")?)?;
        let client = identifier(required("client_id")?)?;
        let issued = numeric_date(required("iat")?)?;
        let expires = numeric_date(required("exp")?)?;
        let not_before = object.get("nbf").map(numeric_date).transpose()?;
        if now.as_secs() > MAX_NUMERIC_DATE
            || issued > now.as_secs()
            || issued >= expires
            || now.as_secs() >= expires
            || expires - issued > self.policy.maximum_lifetime_seconds
            || not_before.is_some_and(|date| date > now.as_secs() || date >= expires)
        {
            return Err(IntrospectionError::InvalidClaims);
        }
        let remaining = Duration::from_secs(expires)
            .checked_sub(now)
            .filter(|duration| !duration.is_zero())
            .ok_or(IntrospectionError::InvalidClaims)?;
        let valid_until = received
            .checked_add(remaining)
            .ok_or(IntrospectionError::InvalidClaims)?;
        let scopes = admit_scopes(object.get("scope"), &self.policy.scopes)?;
        let mut owner = Vec::with_capacity(MAX_OWNER_BYTES);
        owner.extend_from_slice(OWNER_DOMAIN);
        owner.extend_from_slice(self.identity.as_bytes());
        frame(&mut owner, client)?;
        frame(&mut owner, subject)?;
        let owner = sha256_bounded(&owner, MAX_OWNER_BYTES)
            .map_err(|_| IntrospectionError::InvalidClaims)?;
        let mut facts = AuthContext::with_subject(subject)
            .with_session_owner(owner)
            .with_verification_valid_until(valid_until);
        facts.scopes = scopes;
        facts.claims = Some(json!({
            "iss": self.policy.audiences.issuer(),
            "aud": self.policy.audiences.resource().as_str(),
            "client_id": client,
        }));
        principal_fingerprint(Some(&facts)).map_err(|_| IntrospectionError::InvalidClaims)?;
        Ok(facts)
    }
}

impl TokenVerifier for IntrospectionVerifier {
    fn verify(
        &self,
        _: &McpContext,
        _: AuthRequest<'_>,
        _: &AccessToken,
    ) -> McpResult<AuthContext> {
        Err(provider_error(IntrospectionError::AsyncRequired))
    }
    fn verify_async<'a>(
        &'a self,
        ctx: &'a McpContext,
        request: AuthRequest<'a>,
        token: &'a AccessToken,
    ) -> AuthFuture<'a> {
        Box::pin(async move {
            if request.transport_authorization.is_none() {
                return Err(provider_error(IntrospectionError::InvalidCredential));
            }
            self.verify_access_token_async(ctx, token)
                .await
                .map_err(provider_error)
        })
    }
}

fn provider_error(error: IntrospectionError) -> McpError {
    match error {
        IntrospectionError::Cancelled => McpError::request_cancelled(),
        IntrospectionError::Saturated
        | IntrospectionError::EndpointUnavailable
        | IntrospectionError::ClockUnavailable
        | IntrospectionError::TimedOut
        | IntrospectionError::Revoked
        | IntrospectionError::PolicyChanged
        | IntrospectionError::AsyncRequired => McpError::new(
            crate::auth::AUTH_PROVIDER_UNAVAILABLE_CODE,
            "Authentication service unavailable",
        ),
        _ => McpError::new(McpErrorCode::ResourceForbidden, "Invalid access token"),
    }
}
fn checkpoint(ctx: &McpContext) -> Result<(), IntrospectionError> {
    ctx.checkpoint()
        .map_err(|_| IntrospectionError::Cancelled)?;
    if ctx.deadline_expired() {
        return Err(IntrospectionError::TimedOut);
    }
    Ok(())
}
fn frame(bytes: &mut Vec<u8>, value: &str) -> Result<(), IntrospectionError> {
    let length = u64::try_from(value.len()).map_err(|_| IntrospectionError::InvalidPolicy)?;
    bytes.extend_from_slice(&length.to_be_bytes());
    bytes.extend_from_slice(value.as_bytes());
    Ok(())
}
fn valid_identifier(value: &str) -> bool {
    !value.is_empty() && value.len() <= MAX_IDENTIFIER_BYTES && !value.chars().any(char::is_control)
}
fn identifier(value: &Value) -> Result<&str, IntrospectionError> {
    value
        .as_str()
        .filter(|value| valid_identifier(value))
        .ok_or(IntrospectionError::InvalidClaims)
}
fn numeric_date(value: &Value) -> Result<u64, IntrospectionError> {
    value
        .as_u64()
        .filter(|date| *date <= MAX_NUMERIC_DATE)
        .ok_or(IntrospectionError::InvalidClaims)
}
fn valid_scope(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_SCOPE_BYTES
        && value
            .bytes()
            .all(|byte| matches!(byte, 0x21 | 0x23..=0x5b | 0x5d..=0x7e))
}
fn admit_scopes(
    value: Option<&Value>,
    allowed: &BTreeSet<String>,
) -> Result<Vec<String>, IntrospectionError> {
    let Some(value) = value else {
        return Ok(Vec::new());
    };
    let value = value
        .as_str()
        .filter(|value| value.len() <= MAX_SCOPES * (MAX_SCOPE_BYTES + 1))
        .ok_or(IntrospectionError::InvalidClaims)?;
    let mut scopes = BTreeSet::new();
    for scope in value.split(' ') {
        if scopes.len() == MAX_SCOPES
            || !valid_scope(scope)
            || !allowed.contains(scope)
            || !scopes.insert(scope.to_owned())
        {
            return Err(IntrospectionError::InvalidClaims);
        }
    }
    Ok(scopes.into_iter().collect())
}
fn admit_audiences(
    value: &Value,
    policy: &AcceptedAudiencePolicy,
) -> Result<(), IntrospectionError> {
    let values: &[Value] = match value {
        Value::String(_) => std::slice::from_ref(value),
        Value::Array(values) if !values.is_empty() && values.len() <= MAX_AUDIENCES => values,
        _ => return Err(IntrospectionError::InvalidClaims),
    };
    let mut accepted: Option<&str> = None;
    for value in values {
        let value = identifier(value)?;
        AcceptedAudienceId::new(value).map_err(|_| IntrospectionError::InvalidClaims)?;
        if policy
            .audiences()
            .iter()
            .any(|candidate| candidate.as_str() == value)
        {
            if accepted.is_some_and(|previous| previous != value) {
                return Err(IntrospectionError::InvalidClaims);
            }
            accepted = Some(value);
        }
    }
    accepted
        .map(|_| ())
        .ok_or(IntrospectionError::InvalidClaims)
}
fn json_content_type(value: &str) -> bool {
    let mut parts = value.split(';');
    if !parts
        .next()
        .is_some_and(|part| part.trim().eq_ignore_ascii_case("application/json"))
    {
        return false;
    }
    match (parts.next(), parts.next()) {
        (None, None) => true,
        (Some(parameter), None) => {
            parameter.trim().eq_ignore_ascii_case("charset=utf-8")
                || parameter.trim().eq_ignore_ascii_case("charset=\"utf-8\"")
        }
        _ => false,
    }
}
fn endpoint_credential(
    client: &str,
    secret: SecretString,
) -> Result<EndpointCredential, IntrospectionError> {
    if !valid_identifier(secret.as_str()) {
        return Err(IntrospectionError::InvalidPolicy);
    }
    let encoded_client: String = url::form_urlencoded::byte_serialize(client.as_bytes()).collect();
    let encoded_secret = Zeroizing::new(
        url::form_urlencoded::byte_serialize(secret.as_str().as_bytes()).collect::<String>(),
    );
    let basic = Zeroizing::new(format!("{encoded_client}:{}", encoded_secret.as_str()));
    let authorization =
        SecretString::from_string(format!("Basic {}", STANDARD.encode(basic.as_bytes())));
    GuardedHttpRequest::new("application/x-www-form-urlencoded", Vec::new())
        .and_then(|request| request.with_authorization(authorization.as_str()))
        .map_err(|_| IntrospectionError::InvalidPolicy)?;
    Ok(EndpointCredential { authorization })
}
fn introspection_request(
    token: &AccessToken,
    credential: &EndpointCredential,
) -> Result<GuardedHttpRequest, IntrospectionError> {
    let body = url::form_urlencoded::Serializer::new(String::new())
        .append_pair("token", &token.token)
        .append_pair("token_type_hint", "access_token")
        .finish();
    GuardedHttpRequest::new("application/x-www-form-urlencoded", body.into_bytes())
        .and_then(|request| request.with_authorization(credential.authorization.as_str()))
        .map_err(|_| IntrospectionError::InvalidCredential)
}

#[cfg(test)]
pub(crate) mod test_support {
    use super::*;
    use std::pin::Pin;
    pub(crate) trait Exchange: Send + Sync {
        fn post<'a>(
            &'a self,
            ctx: &'a McpContext,
            url: &'a GuardedHttpsUrl,
            request: &'a GuardedHttpRequest,
        ) -> Pin<
            Box<
                dyn Future<Output = Result<GuardedHttpFetchResponse, IntrospectionError>>
                    + Send
                    + 'a,
            >,
        >;
    }
    pub(crate) fn with_exchange(
        mut verifier: IntrospectionVerifier,
        exchange: Arc<dyn Exchange>,
    ) -> IntrospectionVerifier {
        verifier.test_exchange = Some(exchange);
        verifier
    }

    /// Scripted admitted transport response; this is not a TLS-wire fixture.
    pub(crate) fn response(document: &Value) -> GuardedHttpFetchResponse {
        GuardedHttpFetchResponse {
            status: 200,
            headers: vec![("content-type".to_owned(), "application/json".to_owned())],
            body: serde_json::to_vec(document).unwrap(),
            redirect: None,
            provenance: fastmcp_transport::http::GuardedHttpPeerProvenance {
                host: "issuer.example".to_owned(),
                selected_address: "93.184.216.34:443".parse().unwrap(),
                leaf_certificate_sha256: [7; 32],
                alpn: Some(b"http/1.1".to_vec()),
                tls_protocol: Some("test-only".to_owned()),
                root_policy_revision: "introspection-tests".to_owned(),
            },
        }
    }
    pub(crate) fn claims() -> Value {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        json!({
            "active": true, "iss": "https://issuer.example", "aud": "https://tools.example/mcp",
            "sub": "alice", "client_id": "mcp-client", "iat": now - 10, "exp": now + 600,
            "scope": "read", "token_type": "Bearer",
        })
    }
}

#[cfg(test)]
mod tests {
    use super::test_support::{Exchange, claims, response, with_exchange};
    use super::*;
    use crate::auth::{AuthProvider, TokenAuthProvider};
    use asupersync::{Budget, Cx};
    use fastmcp_core::{CanonicalHttpUrl, CanonicalResourceId, CanonicalResourceIdPolicy};
    use fastmcp_transport::http::{
        GuardedHttpFetchPolicy, GuardedHttpResolver, guarded_encode_post_request,
    };
    use std::collections::VecDeque;
    use std::pin::Pin;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::task::{Context, Waker};

    const ISSUER: &str = "https://issuer.example";
    const RESOURCE: &str = "https://tools.example/mcp";
    const ENDPOINT: &str = "https://issuer.example/introspect";

    fn audiences(provider: &str, generation: u64, accepted: &[&str]) -> AcceptedAudiencePolicy {
        let endpoint = CanonicalHttpUrl::parse(RESOURCE).unwrap();
        let configured = [fastmcp_core::uri::ConfiguredResourceEndpoint::new(
            "mcp",
            &endpoint,
            CanonicalResourceIdPolicy::DEFAULT,
        )];
        let resource =
            CanonicalResourceId::parse_for_configured_endpoints(RESOURCE, &configured).unwrap();
        AcceptedAudiencePolicy::new(
            ISSUER,
            resource,
            provider,
            "deployment-one",
            generation,
            accepted
                .iter()
                .map(|value| AcceptedAudienceId::new(*value).unwrap()),
        )
        .unwrap()
    }
    fn policy(provider: &str, generation: u64, accepted: &[&str]) -> IntrospectionPolicy {
        IntrospectionPolicy::new(
            audiences(provider, generation, accepted),
            ENDPOINT,
            ["read".to_owned(), "write".to_owned()],
            Duration::from_secs(3600),
        )
        .unwrap()
    }
    fn fetch_policy() -> GuardedHttpFetchPolicy {
        GuardedHttpFetchPolicy::new(
            MAX_INTROSPECTION_RESPONSE_BYTES,
            Duration::from_secs(2),
            Duration::from_secs(1),
            "introspection-tests",
        )
        .unwrap()
    }
    fn verifier_for(
        policy: IntrospectionPolicy,
        admission: IntrospectionAdmissionPool,
    ) -> IntrospectionVerifier {
        IntrospectionVerifier::new(
            policy,
            GuardedHttpFetcher::new(fetch_policy()).unwrap(),
            "resource-server",
            SecretString::from_string("endpoint-secret".to_owned()),
            admission,
        )
        .unwrap()
    }
    fn verifier() -> IntrospectionVerifier {
        verifier_for(
            policy("provider-one", 1, &[RESOURCE]),
            IntrospectionAdmissionPool::default(),
        )
    }
    fn ctx() -> McpContext {
        McpContext::new(Cx::for_testing(), 1)
    }
    fn token() -> AccessToken {
        AccessToken::parse("Bearer opaque.test-token").unwrap()
    }
    fn ready<T>(future: impl Future<Output = T>) -> T {
        let mut future = pin!(future);
        match future
            .as_mut()
            .poll(&mut Context::from_waker(Waker::noop()))
        {
            Poll::Ready(value) => value,
            Poll::Pending => panic!("immediate fixture unexpectedly pending"),
        }
    }
    fn authenticate(provider: &TokenAuthProvider, context: &McpContext) -> McpResult<AuthContext> {
        ready(provider.authenticate_async(
            context,
            AuthRequest {
                method: "tools/list",
                params: None,
                transport_authorization: Some("Bearer opaque.test-token"),
                request_id: 1,
            },
        ))
    }
    struct Script {
        answers: Mutex<VecDeque<Result<GuardedHttpFetchResponse, IntrospectionError>>>,
        wire: Mutex<Vec<Vec<u8>>>,
        calls: AtomicUsize,
    }
    impl Script {
        fn new(answers: Vec<Result<GuardedHttpFetchResponse, IntrospectionError>>) -> Arc<Self> {
            Arc::new(Self {
                answers: Mutex::new(answers.into()),
                wire: Mutex::new(Vec::new()),
                calls: AtomicUsize::new(0),
            })
        }
    }
    impl Exchange for Script {
        fn post<'a>(
            &'a self,
            _: &'a McpContext,
            url: &'a GuardedHttpsUrl,
            request: &'a GuardedHttpRequest,
        ) -> Pin<
            Box<
                dyn Future<Output = Result<GuardedHttpFetchResponse, IntrospectionError>>
                    + Send
                    + 'a,
            >,
        > {
            Box::pin(async move {
                self.calls.fetch_add(1, Ordering::SeqCst);
                self.wire
                    .lock()
                    .unwrap()
                    .push(guarded_encode_post_request(url, request).unwrap());
                assert!(!format!("{request:?}").contains("opaque.test-token"));
                assert!(!format!("{request:?}").contains("endpoint-secret"));
                self.answers
                    .lock()
                    .unwrap()
                    .pop_front()
                    .expect("one scripted response per call")
            })
        }
    }

    #[test]
    fn installed_async_provider_posts_exact_form_and_scoped_basic_credential() {
        let mut document = claims();
        document["username"] = json!("private-canary-name");
        document["jti"] = json!("private-canary-token-id");
        document["extension"] = json!({"private": "private-canary-claim"});
        let script = Script::new(vec![Ok(response(&document)), Ok(response(&document))]);
        let verifier = with_exchange(verifier(), script.clone());
        let provider = TokenAuthProvider::new(verifier);
        let context = ctx();
        let first = authenticate(&provider, &context).unwrap();
        let second = authenticate(&provider, &context).unwrap();
        assert_eq!(first.subject.as_deref(), Some("alice"));
        assert_eq!(first.scopes, vec!["read".to_owned()]);
        assert_eq!(first.session_owner(), second.session_owner());
        assert_eq!(
            script.calls.load(Ordering::SeqCst),
            2,
            "no token verdict cache"
        );
        assert!(first.verification_valid_until().unwrap() > Instant::now());
        assert_eq!(
            first.claims,
            Some(json!({"iss": ISSUER, "aud": RESOURCE, "client_id": "mcp-client"}))
        );
        let encoded_facts = serde_json::to_string(&first).unwrap();
        assert!(!encoded_facts.contains("private-canary"));
        assert!(!encoded_facts.contains("opaque.test-token"));
        let wire = String::from_utf8(script.wire.lock().unwrap()[0].clone()).unwrap();
        assert!(wire.starts_with("POST /introspect HTTP/1.1\r\n"));
        let lower = wire.to_ascii_lowercase();
        let expected_basic = format!(
            "authorization: basic {}",
            STANDARD.encode("resource-server:endpoint-secret")
        )
        .to_ascii_lowercase();
        assert!(lower.contains(&expected_basic));
        assert!(wire.ends_with("token=opaque.test-token&token_type_hint=access_token"));
        assert!(!lower.contains("authorization: bearer"));
        assert!(!lower.contains("proxy-authorization"));
    }

    #[test]
    fn inactive_and_endpoint_failure_never_publish_authentication_facts() {
        let script = Script::new(vec![
            Ok(response(&claims())),
            Ok(response(&json!({"active": false}))),
            Err(IntrospectionError::EndpointUnavailable),
            Ok(response(&claims())),
        ]);
        let provider = TokenAuthProvider::new(with_exchange(verifier(), script.clone()));
        assert!(authenticate(&provider, &ctx()).is_ok());
        assert_eq!(
            authenticate(&provider, &ctx()).unwrap_err().code,
            McpErrorCode::ResourceForbidden
        );
        let unavailable = authenticate(&provider, &ctx()).unwrap_err();
        assert_eq!(
            unavailable.code,
            crate::auth::AUTH_PROVIDER_UNAVAILABLE_CODE
        );
        assert!(unavailable.data.is_none());
        assert!(authenticate(&provider, &ctx()).is_ok());
        assert_eq!(script.calls.load(Ordering::SeqCst), 4);
    }

    #[test]
    fn same_active_response_requires_exact_issuer_identity_time_and_bearer_evidence() {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let mutations = [
            ("active", json!("true")),
            ("iss", json!("https://foreign.example")),
            ("sub", json!("")),
            ("client_id", json!(null)),
            ("iat", json!(now + 3600)),
            ("exp", json!(now)),
            ("exp", json!(now + 86_401)),
            ("nbf", json!(now + 60)),
            ("iat", json!(1.5)),
            ("exp", json!("9999999999")),
            ("token_type", json!("DPoP")),
            ("cnf", json!({})),
            ("authorization_details", json!([])),
            ("error", json!("private-canary")),
            ("access_token", json!("private-canary")),
            ("refresh_token", json!("private-canary")),
        ];
        for (name, value) in mutations {
            let mut altered = claims();
            altered[name] = value;
            let script = Script::new(vec![Ok(response(&claims())), Ok(response(&altered))]);
            let provider = TokenAuthProvider::new(with_exchange(verifier(), script.clone()));
            assert!(
                authenticate(&provider, &ctx()).is_ok(),
                "positive control for {name}"
            );
            assert!(
                authenticate(&provider, &ctx()).is_err(),
                "must refuse {name}"
            );
            assert_eq!(script.calls.load(Ordering::SeqCst), 2);
        }
        for name in ["iss", "aud", "sub", "client_id", "iat", "exp", "active"] {
            let mut altered = claims();
            altered.as_object_mut().unwrap().remove(name);
            let script = Script::new(vec![Ok(response(&altered))]);
            assert!(
                authenticate(
                    &TokenAuthProvider::new(with_exchange(verifier(), script)),
                    &ctx()
                )
                .is_err()
            );
        }
    }

    #[test]
    fn audience_migration_uses_one_local_binding_and_validates_every_array_member() {
        const ALIAS: &str = "urn:example:tools";
        let admitted = [
            json!(RESOURCE),
            json!(ALIAS),
            json!([RESOURCE, RESOURCE]),
            json!(["urn:foreign:resource", ALIAS]),
        ];
        let rejected = [
            json!([]),
            json!([RESOURCE, ALIAS]),
            json!(["urn:foreign:resource"]),
            json!([RESOURCE, 3]),
            json!([RESOURCE, null]),
            json!([RESOURCE, "urn:%invalid"]),
            json!([RESOURCE, "https://host/é"]),
            json!(vec![RESOURCE; MAX_AUDIENCES + 1]),
            json!("URN:EXAMPLE:TOOLS"),
        ];
        let mut owner = None;
        for audience in admitted {
            let mut document = claims();
            document["aud"] = audience;
            let script = Script::new(vec![Ok(response(&document))]);
            let provider = TokenAuthProvider::new(with_exchange(
                verifier_for(
                    policy("provider-one", 1, &[RESOURCE, ALIAS]),
                    IntrospectionAdmissionPool::default(),
                ),
                script,
            ));
            let facts = authenticate(&provider, &ctx()).unwrap();
            if let Some(previous) = owner {
                assert_eq!(facts.session_owner(), Some(previous));
            }
            owner = facts.session_owner();
            assert_eq!(facts.claims.as_ref().unwrap()["aud"], RESOURCE);
        }
        for audience in rejected {
            let mut document = claims();
            document["aud"] = audience;
            let script = Script::new(vec![Ok(response(&document))]);
            let provider = TokenAuthProvider::new(with_exchange(
                verifier_for(
                    policy("provider-one", 1, &[RESOURCE, ALIAS]),
                    IntrospectionAdmissionPool::default(),
                ),
                script,
            ));
            assert!(authenticate(&provider, &ctx()).is_err());
        }
    }

    #[test]
    fn scope_admission_requires_exact_configured_tokens_and_absence_grants_nothing() {
        let verifier = verifier();
        let now = Duration::from_secs(
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs(),
        );
        let mut document = claims();
        document.as_object_mut().unwrap().remove("scope");
        assert!(
            verifier
                .admit_facts(&document, now, Instant::now())
                .unwrap()
                .scopes
                .is_empty()
        );
        for scope in [
            json!(""),
            json!("read read"),
            json!("read  write"),
            json!("read\twrite"),
            json!(" read"),
            json!("write "),
            json!("admin"),
            json!(["read"]),
            json!(null),
            json!("offline_access"),
            json!("read\"write"),
            json!("réad"),
        ] {
            document["scope"] = scope;
            assert!(
                verifier
                    .admit_facts(&document, now, Instant::now())
                    .is_err()
            );
        }
        document["scope"] = json!("write read");
        assert_eq!(
            verifier
                .admit_facts(&document, now, Instant::now())
                .unwrap()
                .scopes,
            vec!["read".to_owned(), "write".to_owned()]
        );
    }

    #[test]
    fn ownership_isolates_configuration_endpoint_and_token_identity() {
        let now = Duration::from_secs(
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs(),
        );
        let original = verifier();
        let first = original
            .admit_facts(&claims(), now, Instant::now())
            .unwrap()
            .session_owner();
        for other in [
            verifier_for(
                policy("provider-two", 1, &[RESOURCE]),
                IntrospectionAdmissionPool::default(),
            ),
            verifier_for(
                policy("provider-one", 2, &[RESOURCE]),
                IntrospectionAdmissionPool::default(),
            ),
            verifier_for(
                IntrospectionPolicy::new(
                    audiences("provider-one", 1, &[RESOURCE]),
                    "https://issuer.example/other",
                    ["read".to_owned(), "write".to_owned()],
                    Duration::from_secs(3600),
                )
                .unwrap(),
                IntrospectionAdmissionPool::default(),
            ),
        ] {
            assert_ne!(
                first,
                other
                    .admit_facts(&claims(), now, Instant::now())
                    .unwrap()
                    .session_owner()
            );
        }
        for (name, value) in [("sub", "bob"), ("client_id", "other-client")] {
            let mut document = claims();
            document[name] = json!(value);
            assert_ne!(
                first,
                original
                    .admit_facts(&document, now, Instant::now())
                    .unwrap()
                    .session_owner()
            );
        }
        let mut refreshed = claims();
        refreshed["jti"] = json!("fresh-token");
        refreshed["iat"] = json!(now.as_secs() - 1);
        assert_eq!(
            first,
            original
                .admit_facts(&refreshed, now, Instant::now())
                .unwrap()
                .session_owner()
        );
    }

    #[test]
    fn response_admission_refuses_duplicate_json_wrong_status_and_media_types() {
        let verifier = verifier();
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap();
        let good = response(&claims());
        assert!(
            verifier
                .admit_response(good.clone(), now, Instant::now())
                .is_ok()
        );
        for body in [
            br#"{"active":true,"active":false}"#.to_vec(),
            br#"{"active":false,"extension":{"duplicate":1,"duplicate":2}}"#.to_vec(),
            br#"[]"#.to_vec(),
            vec![b' '; MAX_INTROSPECTION_RESPONSE_BYTES + 1],
        ] {
            let mut altered = good.clone();
            altered.body = body;
            assert!(
                verifier
                    .admit_response(altered, now, Instant::now())
                    .is_err()
            );
        }
        for status in [201, 204, 301, 400, 401, 429, 503] {
            let mut altered = good.clone();
            altered.status = status;
            assert_eq!(
                verifier
                    .admit_response(altered, now, Instant::now())
                    .unwrap_err(),
                IntrospectionError::EndpointUnavailable
            );
        }
        for media in [
            "text/plain",
            "application/jwt",
            "application/json, text/plain",
            "application/json; charset=latin1",
            "application/json; charset=utf-8; charset=utf-8",
        ] {
            let mut altered = good.clone();
            altered.headers[0].1 = media.to_owned();
            assert!(
                verifier
                    .admit_response(altered, now, Instant::now())
                    .is_err()
            );
        }
        let mut duplicate = good.clone();
        duplicate
            .headers
            .push(("Content-Type".to_owned(), "application/json".to_owned()));
        assert!(
            verifier
                .admit_response(duplicate, now, Instant::now())
                .is_err()
        );
        let mut charset = good;
        charset.headers[0].1 = "Application/JSON; charset=\"UTF-8\"".to_owned();
        assert!(
            verifier
                .admit_response(charset, now, Instant::now())
                .is_ok()
        );
    }

    #[test]
    fn policy_and_fetch_allocation_bounds_are_enforced_before_credentials_are_used() {
        for endpoint in [
            "http://issuer.example/introspect",
            "https://user@issuer.example/x",
            "https://issuer.example/x#fragment",
            "https://issuer.example/%no",
            "https://issuer.example/é",
        ] {
            assert!(
                IntrospectionPolicy::new(
                    audiences("provider-one", 1, &[RESOURCE]),
                    endpoint,
                    ["read".to_owned()],
                    Duration::from_secs(3600),
                )
                .is_err()
            );
        }
        for scopes in [
            vec!["read".to_owned(), "read".to_owned()],
            vec!["offline_access".to_owned()],
            vec!["bad scope".to_owned()],
            (0..65).map(|n| format!("scope{n}")).collect(),
        ] {
            assert!(
                IntrospectionPolicy::new(
                    audiences("provider-one", 1, &[RESOURCE]),
                    ENDPOINT,
                    scopes,
                    Duration::from_secs(3600)
                )
                .is_err()
            );
        }
        for maximum in [0, 257] {
            assert!(IntrospectionAdmissionPool::new(maximum).is_err());
        }
        for maximum in [0, 9] {
            assert!(
                policy("provider", 1, &[RESOURCE])
                    .with_source_limit(maximum)
                    .is_err()
            );
        }
        let fetch = GuardedHttpFetcher::new(
            GuardedHttpFetchPolicy::new(
                MAX_INTROSPECTION_RESPONSE_BYTES + 1,
                Duration::from_secs(2),
                Duration::from_secs(1),
                "roots",
            )
            .unwrap(),
        )
        .unwrap();
        assert!(
            IntrospectionVerifier::new(
                policy("provider", 1, &[RESOURCE]),
                fetch,
                "client",
                SecretString::from_string("secret".to_owned()),
                IntrospectionAdmissionPool::default()
            )
            .is_err()
        );
        // The guarded transport rejects an excessive full deadline before a
        // verifier can be constructed, so it has no unchecked timeout path.
        assert!(
            GuardedHttpFetchPolicy::new(
                MAX_INTROSPECTION_RESPONSE_BYTES,
                Duration::from_secs(31),
                Duration::from_secs(1),
                "roots"
            )
            .is_err()
        );
    }

    struct ActionExchange {
        action: Mutex<Option<Box<dyn FnOnce() + Send>>>,
    }
    impl Exchange for ActionExchange {
        fn post<'a>(
            &'a self,
            _: &'a McpContext,
            _: &'a GuardedHttpsUrl,
            _: &'a GuardedHttpRequest,
        ) -> Pin<
            Box<
                dyn Future<Output = Result<GuardedHttpFetchResponse, IntrospectionError>>
                    + Send
                    + 'a,
            >,
        > {
            Box::pin(async move {
                let action = self.action.lock().unwrap().take();
                if let Some(action) = action {
                    action();
                }
                Ok(response(&claims()))
            })
        }
    }

    #[test]
    fn secret_rotation_and_revocation_fence_inflight_results_without_retry() {
        for revoke in [false, true] {
            let base = verifier();
            let admin = base.clone();
            let exchange = Arc::new(ActionExchange {
                action: Mutex::new(Some(Box::new(move || {
                    if revoke {
                        admin.revoke_all().unwrap();
                    } else {
                        admin
                            .replace_client_secret(SecretString::from_string(
                                "new-secret".to_owned(),
                            ))
                            .unwrap();
                    }
                }))),
            });
            let installed = with_exchange(base, exchange);
            assert_eq!(
                ready(installed.verify_access_token_async(&ctx(), &token())).unwrap_err(),
                IntrospectionError::PolicyChanged
            );
            if revoke {
                assert_eq!(
                    ready(installed.verify_access_token_async(&ctx(), &token())).unwrap_err(),
                    IntrospectionError::Revoked
                );
                installed
                    .replace_client_secret(SecretString::from_string("reinstalled".to_owned()))
                    .unwrap();
            }
            assert!(ready(installed.verify_access_token_async(&ctx(), &token())).is_ok());
            assert!(
                installed
                    .replace_client_secret(SecretString::from_string(String::new()))
                    .is_err()
            );
            assert!(ready(installed.verify_access_token_async(&ctx(), &token())).is_ok());
        }
    }

    struct PendingExchange {
        started: AtomicUsize,
        dropped: Arc<AtomicUsize>,
    }
    struct DropCount(Arc<AtomicUsize>);
    impl Drop for DropCount {
        fn drop(&mut self) {
            self.0.fetch_add(1, Ordering::SeqCst);
        }
    }
    impl Exchange for PendingExchange {
        fn post<'a>(
            &'a self,
            _: &'a McpContext,
            _: &'a GuardedHttpsUrl,
            _: &'a GuardedHttpRequest,
        ) -> Pin<
            Box<
                dyn Future<Output = Result<GuardedHttpFetchResponse, IntrospectionError>>
                    + Send
                    + 'a,
            >,
        > {
            Box::pin(async move {
                self.started.fetch_add(1, Ordering::SeqCst);
                let _drop = DropCount(Arc::clone(&self.dropped));
                std::future::pending().await
            })
        }
    }
    fn virtual_runtime() -> (
        asupersync::runtime::Runtime,
        Arc<asupersync::time::VirtualClock>,
    ) {
        let clock = Arc::new(asupersync::time::VirtualClock::new());
        let runtime = asupersync::runtime::RuntimeBuilder::current_thread()
            .blocking_threads(0, 0)
            .with_timer_driver(asupersync::time::TimerDriverHandle::with_virtual_clock(
                Arc::clone(&clock),
            ))
            .build()
            .unwrap();
        (runtime, clock)
    }

    #[test]
    fn shared_provider_and_deployment_limits_charge_pending_work_until_drop() {
        let (runtime, _) = virtual_runtime();
        let context = McpContext::new(runtime.request_cx_with_budget(Budget::INFINITE), 1);
        let token = token();
        let pool = IntrospectionAdmissionPool::new(3).unwrap();
        let exchange = Arc::new(PendingExchange {
            started: AtomicUsize::new(0),
            dropped: Arc::new(AtomicUsize::new(0)),
        });
        let one = with_exchange(
            verifier_for(policy("one", 1, &[RESOURCE]), pool.clone()),
            exchange.clone(),
        );
        let two = with_exchange(
            verifier_for(policy("two", 1, &[RESOURCE]), pool.clone()),
            exchange.clone(),
        );
        let same_source = with_exchange(
            verifier_for(policy("one", 2, &[RESOURCE]), pool.clone()),
            exchange.clone(),
        );
        let mut first = Box::pin(one.verify_access_token_async(&context, &token));
        let mut second = Box::pin(one.verify_access_token_async(&context, &token));
        let mut poll = Context::from_waker(Waker::noop());
        assert!(first.as_mut().poll(&mut poll).is_pending());
        assert!(second.as_mut().poll(&mut poll).is_pending());
        assert_eq!(
            ready(same_source.verify_access_token_async(&context, &token)).unwrap_err(),
            IntrospectionError::Saturated,
            "configuration revision cannot create a fresh source bucket"
        );
        let mut sibling = Box::pin(two.verify_access_token_async(&context, &token));
        assert!(sibling.as_mut().poll(&mut poll).is_pending());
        assert_eq!(
            ready(two.verify_access_token_async(&context, &token)).unwrap_err(),
            IntrospectionError::Saturated,
            "deployment cap spans providers"
        );
        assert_eq!(exchange.started.load(Ordering::SeqCst), 3);
        drop(first);
        assert_eq!(exchange.dropped.load(Ordering::SeqCst), 1);
        let mut replacement = Box::pin(same_source.verify_access_token_async(&context, &token));
        assert!(replacement.as_mut().poll(&mut poll).is_pending());
        drop(replacement);
        drop(second);
        drop(sibling);
        assert_eq!(exchange.dropped.load(Ordering::SeqCst), 4);
        assert_eq!(pool.state.lock().unwrap().total, 0);
        assert!(pool.state.lock().unwrap().sources.is_empty());
        drop(context);
        assert!(runtime.shutdown_timeout(Duration::from_secs(2)));
    }

    #[test]
    fn request_cancellation_and_deadline_drop_pending_exchange_and_release_capacity() {
        for cancelled in [false, true] {
            let (runtime, clock) = virtual_runtime();
            let deadline = asupersync::types::Time::from_nanos(100_000_000);
            let context = McpContext::new(
                runtime.request_cx_with_budget(Budget::INFINITE.with_deadline(deadline)),
                1,
            );
            let token = token();
            let pool = IntrospectionAdmissionPool::new(1).unwrap();
            let exchange = Arc::new(PendingExchange {
                started: AtomicUsize::new(0),
                dropped: Arc::new(AtomicUsize::new(0)),
            });
            let verifier = with_exchange(
                verifier_for(policy("one", 1, &[RESOURCE]), pool.clone()),
                exchange.clone(),
            );
            let mut future = Box::pin(verifier.verify_access_token_async(&context, &token));
            let mut poll = Context::from_waker(Waker::noop());
            assert!(future.as_mut().poll(&mut poll).is_pending());
            if cancelled {
                assert!(context.request_cancellation().cancel());
            } else {
                clock.advance_to(deadline);
            }
            assert!(matches!(
                future.as_mut().poll(&mut poll),
                Poll::Ready(Err(_))
            ));
            drop(future);
            assert_eq!(exchange.dropped.load(Ordering::SeqCst), 1);
            assert_eq!(pool.state.lock().unwrap().total, 0);
            drop(context);
            assert!(runtime.shutdown_timeout(Duration::from_secs(2)));
        }
    }

    #[test]
    fn pending_work_without_a_caller_timer_fails_closed_and_drops() {
        let exchange = Arc::new(PendingExchange {
            started: AtomicUsize::new(0),
            dropped: Arc::new(AtomicUsize::new(0)),
        });
        let verifier = with_exchange(verifier(), exchange.clone());
        assert_eq!(
            ready(verifier.verify_access_token_async(&ctx(), &token())).unwrap_err(),
            IntrospectionError::EndpointUnavailable
        );
        assert_eq!(exchange.dropped.load(Ordering::SeqCst), 1);
        assert_eq!(verifier.admission.state.lock().unwrap().total, 0);
    }

    #[test]
    fn caller_timer_selection_never_restores_ambient_denied_effects() {
        use asupersync::cx::cap::{CapSet, CapSetRuntimeMask};
        let (runtime, _) = virtual_runtime();
        let caller = runtime.request_cx_with_budget(Budget::INFINITE);
        let context = McpContext::new(caller.clone(), 1);
        let token = token();
        for restriction in [
            CapSet::<false, true, true, true, true>::MASK,
            CapSet::<true, false, true, true, true>::MASK,
            CapSet::<true, true, false, true, true>::MASK,
            CapSet::<true, true, true, false, true>::MASK,
            CapSet::<true, true, true, true, false>::MASK,
        ] {
            let script = Script::new(vec![Ok(response(&claims()))]);
            let verifier = with_exchange(verifier(), script.clone());
            {
                let _caller = Cx::set_current(Some(caller.clone()));
                let _restriction = Cx::push_restriction(restriction);
                assert_eq!(
                    ready(verifier.verify_access_token_async(&context, &token)).unwrap_err(),
                    IntrospectionError::EndpointUnavailable
                );
                assert_eq!(script.calls.load(Ordering::SeqCst), 0);
                let capabilities = Cx::current().unwrap().capabilities();
                assert!(
                    !capabilities.spawn
                        || !capabilities.time
                        || !capabilities.entropy
                        || !capabilities.io
                        || !capabilities.remote
                );
            }
            assert!(ready(verifier.verify_access_token_async(&context, &token)).is_ok());
            assert_eq!(script.calls.load(Ordering::SeqCst), 1);
        }
        drop(context);
        drop(caller);
        assert!(runtime.shutdown_timeout(Duration::from_secs(2)));
    }

    #[test]
    fn precise_token_expiry_never_rounds_up_or_enters_serialized_facts() {
        let verifier = verifier();
        let received = Instant::now();
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let mut document = claims();
        document["iat"] = json!(now - 1);
        document["exp"] = json!(now + 1);
        let facts = verifier
            .admit_facts(
                &document,
                Duration::from_secs(now) + Duration::from_millis(750),
                received,
            )
            .unwrap();
        assert_eq!(
            facts.verification_valid_until(),
            Some(received + Duration::from_millis(250))
        );
        assert!(
            !serde_json::to_string(&facts)
                .unwrap()
                .contains("verification_valid_until")
        );
        assert!(
            verifier
                .admit_facts(&document, Duration::from_secs(now + 1), received)
                .is_err()
        );
    }

    struct PrivateAddressResolver {
        called: Arc<AtomicBool>,
    }
    impl GuardedHttpResolver for PrivateAddressResolver {
        fn resolve_all(
            &self,
            _: Cx,
            host: String,
        ) -> Pin<
            Box<
                dyn Future<Output = Result<Vec<std::net::IpAddr>, GuardedHttpFetchError>>
                    + Send
                    + 'static,
            >,
        > {
            assert_eq!(host, "issuer.example");
            self.called.store(true, Ordering::SeqCst);
            Box::pin(async { Ok(vec!["127.0.0.1".parse().unwrap()]) })
        }
    }

    #[test]
    fn shipped_guarded_fetcher_refuses_private_resolution_before_network_dispatch() {
        let called = Arc::new(AtomicBool::new(false));
        let fetcher = GuardedHttpFetcher::with_resolver(
            fetch_policy(),
            Arc::new(PrivateAddressResolver {
                called: Arc::clone(&called),
            }),
        )
        .unwrap();
        let verifier = IntrospectionVerifier::new(
            policy("one", 1, &[RESOURCE]),
            fetcher,
            "resource-server",
            SecretString::from_string("secret".to_owned()),
            IntrospectionAdmissionPool::default(),
        )
        .unwrap();
        let result = fastmcp_core::runtime::block_on(async {
            let context = McpContext::new(Cx::current().unwrap(), 1);
            verifier.verify_access_token_async(&context, &token()).await
        });
        assert_eq!(result.unwrap_err(), IntrospectionError::EndpointUnavailable);
        assert!(called.load(Ordering::SeqCst));
        assert_eq!(verifier.admission.state.lock().unwrap().total, 0);
    }
}
