//! Explicit preregistered machine-to-machine OAuth (AUTHX-02).
//!
//! Implements RFC 6749 `client_secret_basic`, not `private_key_jwt`, secret-post,
//! dynamic registration, browser login, or persistent credential custody. The
//! pinned draft's secret-body example differs from its Basic metadata: this
//! explicit API follows the Basic method and the pinned Basic conformance case,
//! never guessing or falling back to another way of transmitting the secret.
//!
//! Trusted resource/issuer discovery is shared with the native OAuth path.
//! Every protected operation additionally verifies the official extension by
//! fresh authenticated MCP discovery using the SAME token as the operation.
//! No failed POST is automatically retried. All work uses the caller's runtime.

use std::fmt;
use std::future::{Future, poll_fn};
use std::io::{self, Write};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::task::Poll;
use std::time::{Duration, Instant};

use asupersync::Cx;
use asupersync::http::h1::{HttpClient, Method, RedirectPolicy, Request, RetryPolicy};
use asupersync::sync::{Mutex, OwnedMutexGuard};
use asupersync::tls::Certificate;
use asupersync::types::Time;
use fastmcp_core::{AccessToken, CanonicalHttpUrl, McpRequestCancellation};
use fastmcp_protocol::protocol_policy::ProtocolEra;
use fastmcp_protocol::{
    CoreRequest, CoreResult, FinalCoreResult, RequestId, FINAL_CLIENT_CAPABILITIES_META_KEY,
    FINAL_PROTOCOL_VERSION, decode_strict_jsonrpc_response,
};
use serde::Deserialize;
use serde_json::{Value, json};

use super::{
    OAuthDiscoveryError, OAuthDiscoveryPlan, TrustedOAuthIssuer, admit_root,
    admit_scopes, check_context, decode_metadata, discovery_deadline, has,
    present, validate_array, validate_headers, validate_optional_array, within,
};
use crate::http_auth::BoundBearerCredential;
use crate::http_executor::{
    ModernHttpExecutor, ModernHttpRequest, ModernHttpResponseKind, ModernHttpResponseMetadata,
    ModernHttpResponseStream, ModernHttpSseResponseStream,
};
use crate::sse::SseLimits;

/// Official opt-in identifier. Settings are exactly the empty JSON object.
pub const CLIENT_CREDENTIALS_EXTENSION: &str = "io.modelcontextprotocol/oauth-client-credentials";
const MAX_TOKEN_BYTES: usize = 64 * 1024;
const MAX_SECRET_BYTES: usize = 4096;
const MAX_REQUEST_BYTES: usize = 8 * 1024 * 1024;
const MAX_ACQUISITIONS: usize = 64;

/// Fixed diagnostics never retain credentials, issuer bodies, request data,
/// or transport errors that could reflect an Authorization header.
#[derive(Debug)]
pub enum ClientCredentialsError {
    InvalidPolicy,
    Closed,
    Expired,
    Saturated,
    StateUnavailable,
    GenerationExhausted,
    UnsupportedAuthentication,
    InvalidToken,
    ExpandedScope,
    TokenEndpointRejected,
    Transport,
    InvalidRequest,
    RequestTooLarge,
    Negotiation,
    UnexpectedResponse,
    Discovery(OAuthDiscoveryError),
}
impl fmt::Display for ClientCredentialsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::InvalidPolicy => "invalid client-credentials policy",
            Self::Closed => "client-credentials owner is closed",
            Self::Expired => "client-credentials access token is expired or revoked",
            Self::Saturated => "client-credentials acquisition capacity exhausted",
            Self::StateUnavailable => "client-credentials state unavailable",
            Self::GenerationExhausted => "client-credentials generation exhausted",
            Self::UnsupportedAuthentication => "issuer does not admit client_credentials with client_secret_basic",
            Self::InvalidToken => "client-credentials token response rejected",
            Self::ExpandedScope => "client-credentials token exceeds requested scopes",
            Self::TokenEndpointRejected => "client-credentials token endpoint rejected the grant",
            Self::Transport => "client-credentials transport failed",
            Self::InvalidRequest => "invalid client-credentials MCP request",
            Self::RequestTooLarge => "client-credentials MCP request exceeds its byte bound",
            Self::Negotiation => "resource did not admit the client-credentials extension",
            Self::UnexpectedResponse => "client-credentials response rejected",
            Self::Discovery(_) => "client-credentials discovery or operation lifetime failed",
        })
    }
}
impl std::error::Error for ClientCredentialsError {}
impl From<OAuthDiscoveryError> for ClientCredentialsError {
    fn from(error: OAuthDiscoveryError) -> Self { Self::Discovery(error) }
}

// Process-local secrets are not serialized or formatted. Ordinary allocator
// memory is used; protected persistence and zeroized-memory custody are not claimed.
struct ClientSecret(String);

/// Administrator-selected resource, ONE issuer-bound registration and secret.
/// Extra token-endpoint origins and issuer roots are explicit host grants.
/// Metadata cannot move the registration to a different issuer.
pub struct ClientCredentialsPlan {
    discovery: OAuthDiscoveryPlan,
    secret: Arc<ClientSecret>,
    maximum_lifetime: Duration,
    leeway: Duration,
}
impl ClientCredentialsPlan {
    pub fn new(
        resource: CanonicalHttpUrl,
        issuer: TrustedOAuthIssuer,
        client_id: impl Into<String>,
        client_secret: impl Into<String>,
        scopes: Vec<String>,
    ) -> Result<Self, ClientCredentialsError> {
        let client_secret = client_secret.into();
        if client_secret.is_empty() || client_secret.len() > MAX_SECRET_BYTES
            || client_secret.chars().any(char::is_control)
        { return Err(ClientCredentialsError::InvalidPolicy); }
        Ok(Self {
            discovery: OAuthDiscoveryPlan::new(resource, vec![issuer], client_id, scopes)?,
            secret: Arc::new(ClientSecret(client_secret)),
            maximum_lifetime: Duration::from_secs(3600),
            leeway: Duration::from_secs(30),
        })
    }

    /// Bounds each explicit discovery/acquisition/operation, including queued
    /// acquisition time and response reads. A tighter Cx budget always wins.
    pub fn with_timeout(mut self, timeout: Duration) -> Result<Self, ClientCredentialsError> {
        self.discovery = self.discovery.with_timeout(timeout)?;
        Ok(self)
    }

    /// Local reuse ceiling, also applied when expires_in is absent.
    pub fn with_maximum_token_lifetime(mut self, lifetime: Duration) -> Result<Self, ClientCredentialsError> {
        if lifetime.is_zero() || lifetime > Duration::from_secs(86_400) {
            return Err(ClientCredentialsError::InvalidPolicy);
        }
        self.maximum_lifetime = lifetime;
        Ok(self)
    }
    pub fn with_renewal_leeway(mut self, leeway: Duration) -> Result<Self, ClientCredentialsError> {
        if leeway > Duration::from_secs(300) { return Err(ClientCredentialsError::InvalidPolicy); }
        self.leeway = leeway;
        Ok(self)
    }

    /// Adds private trust for resource-METADATA retrieval only. Protected MCP
    /// dispatch uses the native executor's bundled roots or explicit build-time
    /// native-tls-roots policy, just like the managed browser-login client.
    pub fn with_resource_root_certificate(mut self, root: Certificate) -> Result<Self, ClientCredentialsError> {
        admit_root(&mut self.discovery.resource_roots, root)?;
        Ok(self)
    }

    /// Discovers endpoints without transmitting the secret. A later credential
    /// call owns an explicit grant attempt. No DCR/browser branch is reachable.
    pub async fn discover(&self, cx: &Cx) -> Result<ClientCredentialsClient, ClientCredentialsError> {
        let deadline = discovery_deadline(cx, self.discovery.timeout)?;
        let (issuer, body) = self.discovery.discover_issuer_document(cx, deadline).await?;
        let token_endpoint = admit_machine_issuer(&self.discovery, issuer, &body)?;
        check_context(cx, deadline)?;
        Ok(ClientCredentialsClient {
            inner: Arc::new(ClientInner {
                resource: self.discovery.resource.clone(), token_endpoint,
                client_id: self.discovery.client_id.clone().ok_or(ClientCredentialsError::InvalidPolicy)?,
                scopes: self.discovery.scopes.clone(), secret: Arc::clone(&self.secret),
                issuer_roots: issuer.roots.clone(), timeout: self.discovery.timeout,
                maximum_lifetime: self.maximum_lifetime, leeway: self.leeway,
                closed: McpRequestCancellation::new(), pending: AtomicUsize::new(0),
                state: Arc::new(Mutex::new(TokenState::default())),
            }),
        })
    }
}
impl fmt::Debug for ClientCredentialsPlan {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ClientCredentialsPlan").field("authentication", &"client_secret_basic")
            .field("secret", &"<redacted>").finish_non_exhaustive()
    }
}

#[derive(Deserialize)]
struct MachineIssuerMetadata {
    issuer: String,
    token_endpoint: String,
    grant_types_supported: Vec<String>,
    token_endpoint_auth_methods_supported: Vec<String>,
    #[serde(default, deserialize_with = "present")]
    scopes_supported: Option<Vec<String>>,
    #[serde(default, deserialize_with = "present")]
    protected_resources: Option<Vec<String>>,
    #[serde(default, deserialize_with = "present")]
    signed_metadata: Option<String>,
}
fn admit_machine_issuer(plan: &OAuthDiscoveryPlan, issuer: &TrustedOAuthIssuer, body: &[u8])
    -> Result<CanonicalHttpUrl, ClientCredentialsError>
{
    let metadata: MachineIssuerMetadata = decode_metadata(body)?;
    if metadata.issuer != issuer.identifier { return Err(OAuthDiscoveryError::IssuerMismatch.into()); }
    if metadata.signed_metadata.is_some() { return Err(OAuthDiscoveryError::SignedMetadataUnsupported.into()); }
    validate_array(&metadata.grant_types_supported)?;
    validate_array(&metadata.token_endpoint_auth_methods_supported)?;
    validate_optional_array(metadata.protected_resources.as_deref())?;
    if !has(&metadata.grant_types_supported, "client_credentials")
        || !has(&metadata.token_endpoint_auth_methods_supported, "client_secret_basic")
    { return Err(ClientCredentialsError::UnsupportedAuthentication); }
    if metadata.protected_resources.as_ref().is_some_and(|values| !has(values, plan.resource.as_str())) {
        return Err(OAuthDiscoveryError::ResourceMismatch.into());
    }
    admit_scopes(&plan.scopes, metadata.scopes_supported.as_deref())?;
    Ok(issuer.endpoint(&metadata.token_endpoint)?)
}

struct ClientInner {
    resource: CanonicalHttpUrl,
    token_endpoint: CanonicalHttpUrl,
    client_id: String,
    scopes: Vec<String>,
    secret: Arc<ClientSecret>,
    issuer_roots: Vec<Certificate>,
    timeout: Duration,
    maximum_lifetime: Duration,
    leeway: Duration,
    closed: McpRequestCancellation,
    pending: AtomicUsize,
    state: Arc<Mutex<TokenState>>,
}
impl Drop for ClientInner {
    fn drop(&mut self) { self.closed.cancel(); }
}
#[derive(Default)]
struct TokenState { current: Option<ServiceToken>, generation: u64 }
struct ServiceToken {
    bearer: BoundBearerCredential,
    scopes: Vec<String>,
    expires_at: Instant,
    renew_after: Instant,
}

/// Clones share single-flight token acquisition. Expiry causes a new
/// client_credentials grant, never refresh_token. No background task is used.
/// After failure another caller may explicitly request a new acquisition; the
/// failing call itself does not retry or overwrite the previously admitted token.
#[derive(Clone)]
pub struct ClientCredentialsClient { inner: Arc<ClientInner> }
impl fmt::Debug for ClientCredentialsClient {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ClientCredentialsClient")
            .field("closed", &self.inner.closed.is_cancel_requested()).finish_non_exhaustive()
    }
}

/// Expiring, owner-bound snapshot. Generation is local, not a global cache key.
pub struct ClientCredentialsSnapshot {
    bearer: BoundBearerCredential,
    scopes: Vec<String>,
    expires_at: Instant,
    generation: u64,
}
impl ClientCredentialsSnapshot {
    pub fn credential(&self) -> &BoundBearerCredential { &self.bearer }
    pub fn scopes(&self) -> &[String] { &self.scopes }
    pub fn expires_at(&self) -> Instant { self.expires_at }
    pub fn generation(&self) -> u64 { self.generation }
}
impl fmt::Debug for ClientCredentialsSnapshot {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ClientCredentialsSnapshot").field("generation", &self.generation)
            .field("credential", &"<redacted>").finish_non_exhaustive()
    }
}

impl ClientCredentialsClient {
    pub fn resource(&self) -> &CanonicalHttpUrl { &self.inner.resource }

    /// Irreversible local closure, not an issuer revocation request. Old
    /// snapshots withhold new headers. Already-sent bytes cannot be recalled.
    pub fn close(&self) {
        self.inner.closed.cancel();
        if let Ok(mut state) = self.inner.state.try_lock_owned() { state.current = None; }
    }
    pub async fn credential(&self, cx: &Cx) -> Result<ClientCredentialsSnapshot, ClientCredentialsError> {
        self.credential_with_cancellation(cx, &McpRequestCancellation::new()).await
    }
    pub async fn credential_with_cancellation(
        &self, cx: &Cx, cancellation: &McpRequestCancellation,
    ) -> Result<ClientCredentialsSnapshot, ClientCredentialsError> {
        let deadline = discovery_deadline(cx, self.inner.timeout)?;
        let _permit = AcquisitionPermit::new(&self.inner.pending)?;
        active(cx, deadline, &self.inner.closed, cancellation, None, async {
            let mut state = OwnedMutexGuard::lock(Arc::clone(&self.inner.state), cx).await
                .map_err(|_| ClientCredentialsError::StateUnavailable)?;
            if state.current.as_ref().is_some_and(|token| token.bearer.is_revoked()) {
                return Err(ClientCredentialsError::Expired);
            }
            if state.current.as_ref().is_none_or(|token| Instant::now() >= token.renew_after) {
                let generation = state.generation.checked_add(1).ok_or(ClientCredentialsError::GenerationExhausted)?;
                let started = Instant::now();
                let body = form(&[("grant_type", "client_credentials"), ("resource", self.resource().as_str()),
                    ("scope", &self.inner.scopes.join(" "))]);
                let headers = vec![
                    ("Content-Type".to_owned(), "application/x-www-form-urlencoded".to_owned()),
                    ("Accept".to_owned(), "application/json".to_owned()),
                    ("Accept-Encoding".to_owned(), "identity".to_owned()),
                    ("Connection".to_owned(), "close".to_owned()),
                    ("Authorization".to_owned(), basic(&self.inner.client_id, &self.inner.secret.0)?),
                ];
                let transport = token_transport(&self.inner.issuer_roots);
                let response = transport.request(cx, Method::Post, self.inner.token_endpoint.as_str(), headers, body.into_bytes())
                    .await.map_err(|_| ClientCredentialsError::Transport)?;
                if response.status != 200 { return Err(ClientCredentialsError::TokenEndpointRejected); }
                validate_headers(&response.headers)?;
                if !response.trailers.is_empty() { return Err(ClientCredentialsError::InvalidToken); }
                let token = admit_token(&self.inner, &response.body, started)?;
                check_context(cx, deadline)?;
                if self.inner.closed.is_cancel_requested() { return Err(ClientCredentialsError::Closed); }
                if cancellation.is_cancel_requested() { return Err(OAuthDiscoveryError::Cancelled.into()); }
                // Revocation while renewal was pending must not be reversed by
                // installing a fresh token after the revocation decision.
                if state.current.as_ref().is_some_and(|old| old.bearer.is_revoked()) {
                    return Err(ClientCredentialsError::Expired);
                }
                state.current = Some(token);
                state.generation = generation;
            }
            let token = state.current.as_ref().ok_or(ClientCredentialsError::StateUnavailable)?;
            check_token(&token.bearer, token.expires_at)?;
            Ok(ClientCredentialsSnapshot {
                bearer: token.bearer.clone(), scopes: token.scopes.clone(),
                expires_at: token.expires_at, generation: state.generation,
            })
        }).await
    }

    /// Executes one core operation after fresh same-token extension discovery.
    /// Both request documents are validated before token acquisition. Metadata
    /// is retained and only this explicit client's empty auth declaration is
    /// added. Other extension compositions are refused, not inferred.
    ///
    /// No tool POST is replayed after a 401, redirect, lost reply or expiry.
    /// Response reads retain cancellation, closure and the opening token expiry.
    /// This path requires JSON server/discover; the operation can return JSON
    /// or SSE. It does not alter the browser ManagedOAuthSession API or negotiate
    /// Tasks, Apps, or subscription extension filters.
    pub async fn execute_core(
        &self, cx: &Cx, request: CoreRequest, discovery_id: RequestId, request_id: RequestId,
    ) -> Result<ClientCredentialsResponse, ClientCredentialsError> {
        self.execute_core_with_cancellation(cx, &McpRequestCancellation::new(), request, discovery_id, request_id).await
    }
    pub async fn execute_core_with_cancellation(
        &self, cx: &Cx, cancellation: &McpRequestCancellation,
        request: CoreRequest, discovery_id: RequestId, request_id: RequestId,
    ) -> Result<ClientCredentialsResponse, ClientCredentialsError> {
        if discovery_id.correlates_with(&request_id) { return Err(ClientCredentialsError::InvalidRequest); }
        let (wire, decoder) = prepare(self.resource(), &request, &request_id)?;
        let params = decoder.encode_params().map_err(|_| ClientCredentialsError::InvalidRequest)?
            .ok_or(ClientCredentialsError::InvalidRequest)?;
        let discovery = CoreRequest::decode(ProtocolEra::Modern2026, "server/discover", Some(&json!({"_meta":params["_meta"]})))
            .map_err(|_| ClientCredentialsError::InvalidRequest)?;
        let (discovery_wire, discovery) = prepare(self.resource(), &discovery, &discovery_id)?;
        let deadline = discovery_deadline(cx, self.inner.timeout)?;
        active(cx, deadline, &self.inner.closed, cancellation, None, async {
            let snapshot = self.credential_with_cancellation(cx, cancellation).await?;
            let executor = ModernHttpExecutor::new();
            let discovery_wire = authorize(&snapshot, discovery_wire)?;
            let response = active(cx, deadline, &self.inner.closed, cancellation, Some(&snapshot), async {
                executor.execute_with_cancellation(cx, cancellation, &discovery_wire).await
                    .map_err(|_| ClientCredentialsError::Transport)
            }).await?;
            if response.metadata().status() != 200 || response.metadata().kind() != ModernHttpResponseKind::Json {
                return Err(ClientCredentialsError::Negotiation);
            }
            let bytes = active(cx, deadline, &self.inner.closed, cancellation, Some(&snapshot), async {
                response.read_to_end_with_cancellation(cx, cancellation, MAX_TOKEN_BYTES).await
                    .map_err(|_| ClientCredentialsError::Transport)
            }).await?;
            admit_resource(&discovery, &discovery_id, &bytes)?;
            check_context(cx, deadline)?;
            let wire = authorize(&snapshot, wire)?;
            let response = active(cx, deadline, &self.inner.closed, cancellation, Some(&snapshot), async {
                executor.execute_with_cancellation(cx, cancellation, &wire).await
                    .map_err(|_| ClientCredentialsError::Transport)
            }).await?;
            Ok(ClientCredentialsResponse {
                response, snapshot, owner: self.inner.closed.clone(), cancellation: cancellation.clone(),
                request: decoder, request_id, deadline,
            })
        }).await
    }
}

struct AcquisitionPermit<'a>(&'a AtomicUsize);
impl<'a> AcquisitionPermit<'a> {
    fn new(pending: &'a AtomicUsize) -> Result<Self, ClientCredentialsError> {
        pending.try_update(Ordering::AcqRel, Ordering::Acquire, |n| (n < MAX_ACQUISITIONS).then(|| n + 1))
            .map_err(|_| ClientCredentialsError::Saturated)?;
        Ok(Self(pending))
    }
}
impl Drop for AcquisitionPermit<'_> {
    fn drop(&mut self) { self.0.fetch_sub(1, Ordering::AcqRel); }
}
fn token_transport(roots: &[Certificate]) -> HttpClient {
    let mut builder = HttpClient::builder().redirect_policy(RedirectPolicy::None).retry_policy(RetryPolicy::None)
        .no_proxy().no_cookie_store().max_body_size(MAX_TOKEN_BYTES).max_total_connections(1);
    for root in roots { builder = builder.add_root_certificate(root.clone()); }
    builder.build()
}

#[derive(Deserialize)]
struct TokenDocument {
    access_token: String,
    token_type: String,
    #[serde(default, deserialize_with = "present")]
    expires_in: Option<u64>,
    #[serde(default, deserialize_with = "present")]
    scope: Option<String>,
    #[serde(default, deserialize_with = "present")]
    resource: Option<String>,
    #[serde(default, deserialize_with = "present")]
    error: Option<String>,
}
fn admit_token(inner: &ClientInner, bytes: &[u8], started: Instant) -> Result<ServiceToken, ClientCredentialsError> {
    let token: TokenDocument = decode_metadata(bytes).map_err(|_| ClientCredentialsError::InvalidToken)?;
    if !token.token_type.eq_ignore_ascii_case("Bearer") || token.access_token.len() > 16 * 1024
        || !AccessToken::is_valid_token68(&token.access_token) || token.error.is_some()
        || token.resource.as_ref().is_some_and(|resource| resource != inner.resource.as_str())
    { return Err(ClientCredentialsError::InvalidToken); }
    let scopes = token.scope.map_or_else(|| inner.scopes.clone(), |scope| scope.split(' ').map(str::to_owned).collect());
    if scopes.len() > 32 || scopes.iter().enumerate().any(|(index, scope)| {
        scope.is_empty() || !inner.scopes.contains(scope) || scopes[..index].contains(scope)
    }) { return Err(ClientCredentialsError::ExpandedScope); }
    let lifetime = token.expires_in.map_or(inner.maximum_lifetime, |seconds| Duration::from_secs(seconds).min(inner.maximum_lifetime));
    let expires_at = started.checked_add(lifetime).ok_or(ClientCredentialsError::InvalidToken)?;
    if Instant::now() >= expires_at { return Err(ClientCredentialsError::Expired); }
    let bearer = BoundBearerCredential::bind_with_expiry(inner.resource.clone(), token.access_token, expires_at)
        .map_err(|_| ClientCredentialsError::InvalidToken)?
        .for_owner(&inner.closed).ok_or(ClientCredentialsError::StateUnavailable)?;
    let remaining = expires_at.saturating_duration_since(Instant::now());
    let renew_after = expires_at.checked_sub(inner.leeway.min(remaining / 2)).ok_or(ClientCredentialsError::InvalidToken)?;
    // Refresh tokens and registration URLs remain ignored, never persisted or
    // used to change this issuer-bound preregistered acquisition method.
    Ok(ServiceToken { bearer, scopes, expires_at, renew_after })
}

fn component(value: &str) -> String {
    let mut encoded = String::new();
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    for byte in value.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => encoded.push(char::from(byte)),
            b' ' => encoded.push('+'),
            _ => { encoded.push('%'); encoded.push(char::from(HEX[usize::from(byte >> 4)])); encoded.push(char::from(HEX[usize::from(byte & 15)])); }
        }
    }
    encoded
}
fn form(fields: &[(&str, &str)]) -> String {
    fields.iter().filter(|(name, value)| *name != "scope" || !value.is_empty())
        .map(|(name, value)| format!("{}={}", component(name), component(value))).collect::<Vec<_>>().join("&")
}
fn basic(id: &str, secret: &str) -> Result<String, ClientCredentialsError> {
    // Reuse asupersync's Basic encoder after the OAuth-specific form encoding
    // of each component. This builder constructs data only; it performs no I/O.
    Request::post("/").basic_auth(component(id), Some(&component(secret))).build()
        .headers.into_iter().find(|(name, _)| name.eq_ignore_ascii_case("authorization"))
        .map(|(_, value)| value).ok_or(ClientCredentialsError::StateUnavailable)
}
fn prepare(resource: &CanonicalHttpUrl, request: &CoreRequest, id: &RequestId) -> Result<(ModernHttpRequest, CoreRequest), ClientCredentialsError> {
    if request.era() != ProtocolEra::Modern2026 || !matches!(request.method(),
        "server/discover" | "tools/list" | "tools/call" | "resources/list" | "resources/templates/list"
        | "resources/read" | "prompts/list" | "prompts/get" | "completion/complete"
    ) { return Err(ClientCredentialsError::InvalidRequest); }
    id.validate().map_err(|_| ClientCredentialsError::InvalidRequest)?;
    let mut params = request.encode_params().map_err(|_| ClientCredentialsError::InvalidRequest)?
        .ok_or(ClientCredentialsError::InvalidRequest)?;
    let capabilities = params.get_mut("_meta").and_then(|meta| meta.get_mut(FINAL_CLIENT_CAPABILITIES_META_KEY))
        .and_then(Value::as_object_mut).ok_or(ClientCredentialsError::InvalidRequest)?;
    if let Some(extensions) = capabilities.get("extensions") {
        let extensions = extensions.as_object().ok_or(ClientCredentialsError::InvalidRequest)?;
        if extensions.iter().any(|(name, settings)| name != CLIENT_CREDENTIALS_EXTENSION
            || !settings.as_object().is_some_and(serde_json::Map::is_empty))
        { return Err(ClientCredentialsError::InvalidRequest); }
    }
    capabilities.insert("extensions".to_owned(), json!({CLIENT_CREDENTIALS_EXTENSION:{}}));
    let decoder = CoreRequest::decode(ProtocolEra::Modern2026, request.method(), Some(&params))
        .map_err(|_| ClientCredentialsError::InvalidRequest)?;
    let name = if matches!(request.method(), "tools/call" | "prompts/get") {
        params.get("name").and_then(Value::as_str).map(str::to_owned)
    } else { None };
    let envelope = json!({"jsonrpc":"2.0","id":id,"method":request.method(),"params":params});
    let mut body = BoundedBody(Vec::new());
    serde_json::to_writer(&mut body, &envelope).map_err(|_| ClientCredentialsError::RequestTooLarge)?;
    let wire = ModernHttpRequest::new(resource.as_str(), body.0, FINAL_PROTOCOL_VERSION, request.method(), name)
        .map_err(|_| ClientCredentialsError::InvalidRequest)?;
    Ok((wire, decoder))
}
struct BoundedBody(Vec<u8>);
impl Write for BoundedBody {
    fn write(&mut self, input: &[u8]) -> io::Result<usize> {
        if input.len() > MAX_REQUEST_BYTES.saturating_sub(self.0.len()) { return Err(io::Error::other("client-credentials request limit")); }
        self.0.extend_from_slice(input); Ok(input.len())
    }
    fn flush(&mut self) -> io::Result<()> { Ok(()) }
}
fn authorize(snapshot: &ClientCredentialsSnapshot, wire: ModernHttpRequest) -> Result<ModernHttpRequest, ClientCredentialsError> {
    check_token(&snapshot.bearer, snapshot.expires_at)?;
    let wire = wire.with_authorization(&snapshot.bearer);
    if !wire.headers().iter().any(|(name, _)| name.eq_ignore_ascii_case("authorization")) {
        return Err(ClientCredentialsError::Expired);
    }
    Ok(wire)
}
fn decoded_result(request: &CoreRequest, id: &RequestId, bytes: &[u8], maximum: usize) -> Result<CoreResult, ClientCredentialsError> {
    let admission = decode_strict_jsonrpc_response(bytes, maximum).map_err(|_| ClientCredentialsError::UnexpectedResponse)?;
    let (response, source) = admission.into_parts();
    if response.error.is_some() || !response.id.as_ref().is_some_and(|actual| actual.correlates_with(id)) {
        return Err(ClientCredentialsError::UnexpectedResponse);
    }
    if response.result.as_ref().and_then(|result| result.get("resultType")).and_then(Value::as_str)
        .is_some_and(|kind| !matches!(kind, "complete" | "input_required"))
    { return Err(ClientCredentialsError::UnexpectedResponse); }
    request.decode_response_result(&response, &source.ok_or(ClientCredentialsError::UnexpectedResponse)?)
        .map_err(|_| ClientCredentialsError::UnexpectedResponse)
}
fn admit_resource(request: &CoreRequest, id: &RequestId, bytes: &[u8]) -> Result<(), ClientCredentialsError> {
    let result = decoded_result(request, id, bytes, MAX_TOKEN_BYTES).map_err(|_| ClientCredentialsError::Negotiation)?;
    let CoreResult::Final(FinalCoreResult::Discover(discovery)) = &result else { return Err(ClientCredentialsError::Negotiation) };
    if !discovery.supported_versions().iter().any(|version| version == FINAL_PROTOCOL_VERSION) {
        return Err(ClientCredentialsError::Negotiation);
    }
    // Inspect the method-admitted typed result, not an unknown sibling or an
    // unvalidated raw Value whose duplicate security fields could be collapsed.
    let document: Value = serde_json::from_str(&result.encode().map_err(|_| ClientCredentialsError::Negotiation)?)
        .map_err(|_| ClientCredentialsError::Negotiation)?;
    if !document.get("capabilities").and_then(|value| value.get("extensions"))
        .and_then(|value| value.get(CLIENT_CREDENTIALS_EXTENSION))
        .is_some_and(|settings| settings.as_object().is_some_and(serde_json::Map::is_empty))
    { return Err(ClientCredentialsError::Negotiation); }
    Ok(())
}
fn check_token(token: &BoundBearerCredential, expiry: Instant) -> Result<(), ClientCredentialsError> {
    if token.is_revoked() || Instant::now() >= expiry { return Err(ClientCredentialsError::Expired); }
    Ok(())
}
async fn active<T>(
    cx: &Cx, deadline: Time, owner: &McpRequestCancellation, cancellation: &McpRequestCancellation,
    token: Option<&ClientCredentialsSnapshot>, future: impl Future<Output = Result<T, ClientCredentialsError>>,
) -> Result<T, ClientCredentialsError> {
    let expiry_deadline = token.map(|token| {
        check_token(&token.bearer, token.expires_at)?;
        discovery_deadline(cx, token.expires_at.saturating_duration_since(Instant::now())).map_err(ClientCredentialsError::from)
    }).transpose()?;
    let deadline = expiry_deadline.map_or(deadline, |expiry| deadline.min(expiry));
    let mut stopped = std::pin::pin!(owner.cancelled());
    let mut cancelled = std::pin::pin!(cancellation.cancelled());
    let mut future = std::pin::pin!(future);
    within(cx, deadline, async {
        Ok(poll_fn(|task| {
            if owner.is_cancel_requested() || stopped.as_mut().poll(task).is_ready() { return Poll::Ready(Err(ClientCredentialsError::Closed)); }
            if cancellation.is_cancel_requested() || cancelled.as_mut().poll(task).is_ready() { return Poll::Ready(Err(OAuthDiscoveryError::Cancelled.into())); }
            if let Some(token) = token { check_token(&token.bearer, token.expires_at)?; }
            let result = future.as_mut().poll(task);
            if owner.is_cancel_requested() { return Poll::Ready(Err(ClientCredentialsError::Closed)); }
            if cancellation.is_cancel_requested() { return Poll::Ready(Err(OAuthDiscoveryError::Cancelled.into())); }
            if let Some(token) = token { check_token(&token.bearer, token.expires_at)?; }
            result
        }).await)
    }).await?
}

/// Protected response tied to the original service token and typed decoder.
/// A polled read that is dropped owns socket cleanup; it cannot replay the POST.
pub struct ClientCredentialsResponse {
    response: ModernHttpResponseStream,
    snapshot: ClientCredentialsSnapshot,
    owner: McpRequestCancellation,
    cancellation: McpRequestCancellation,
    request: CoreRequest,
    request_id: RequestId,
    deadline: Time,
}
impl ClientCredentialsResponse {
    pub fn metadata(&self) -> &ModernHttpResponseMetadata { self.response.metadata() }
    pub fn credential_generation(&self) -> u64 { self.snapshot.generation }
    pub fn request(&self) -> &CoreRequest { &self.request }
    pub fn request_id(&self) -> &RequestId { &self.request_id }

    pub async fn read_to_end(self, cx: &Cx, maximum_bytes: usize) -> Result<Vec<u8>, ClientCredentialsError> {
        active(cx, self.deadline, &self.owner, &self.cancellation, Some(&self.snapshot), async {
            self.response.read_to_end_with_cancellation(cx, &self.cancellation, maximum_bytes)
                .await.map_err(|_| ClientCredentialsError::UnexpectedResponse)
        }).await
    }

    /// Decodes terminal JSON with the original method's strict codec, preserving
    /// exact unknown members and input_required. No result triggers another POST.
    pub async fn read_json_result(self, cx: &Cx, maximum_bytes: usize) -> Result<CoreResult, ClientCredentialsError> {
        if self.metadata().status() != 200 || self.metadata().kind() != ModernHttpResponseKind::Json {
            return Err(ClientCredentialsError::UnexpectedResponse);
        }
        let Self { response, snapshot, owner, cancellation, request, request_id, deadline } = self;
        active(cx, deadline, &owner, &cancellation, Some(&snapshot), async {
            let bytes = response.read_to_end_with_cancellation(cx, &cancellation, maximum_bytes)
                .await.map_err(|_| ClientCredentialsError::UnexpectedResponse)?;
            decoded_result(&request, &request_id, &bytes, maximum_bytes)
        }).await
    }

    /// Raw bounded SSE data records, not an implicit Tasks/subscription decoder.
    pub fn into_sse_stream(self, limits: SseLimits) -> Result<ClientCredentialsSseStream, ClientCredentialsError> {
        Ok(ClientCredentialsSseStream {
            stream: Some(self.response.into_sse_stream(limits).map_err(|_| ClientCredentialsError::UnexpectedResponse)?),
            snapshot: self.snapshot, owner: self.owner, cancellation: self.cancellation,
            deadline: self.deadline, finished: false,
        })
    }
}
pub struct ClientCredentialsSseStream {
    stream: Option<ModernHttpSseResponseStream>,
    snapshot: ClientCredentialsSnapshot,
    owner: McpRequestCancellation,
    cancellation: McpRequestCancellation,
    deadline: Time,
    finished: bool,
}
impl ClientCredentialsSseStream {
    pub fn close(&mut self) { self.stream = None; }
    pub async fn next_event(&mut self, cx: &Cx) -> Result<Option<String>, ClientCredentialsError> {
        if self.finished { return Ok(None); }
        let mut stream = self.stream.take().ok_or(ClientCredentialsError::Closed)?;
        let result = active(cx, self.deadline, &self.owner, &self.cancellation, Some(&self.snapshot), async {
            stream.next_event(cx).await.map_err(|_| ClientCredentialsError::UnexpectedResponse)
        }).await;
        match &result {
            Ok(Some(_)) => self.stream = Some(stream),
            Ok(None) => self.finished = true,
            Err(_) => {},
        }
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn url(text: &str) -> CanonicalHttpUrl { CanonicalHttpUrl::parse(text).unwrap() }
    fn plan() -> ClientCredentialsPlan {
        ClientCredentialsPlan::new(url("https://resource.example/mcp"), TrustedOAuthIssuer::new("https://issuer.example").unwrap(),
            "service-client", "unit-secret", vec!["read".to_owned(), "write".to_owned()]).unwrap()
    }
    fn issuer() -> Value { json!({"issuer":"https://issuer.example","token_endpoint":"https://issuer.example/token",
        "grant_types_supported":["client_credentials"],"token_endpoint_auth_methods_supported":["client_secret_basic"]}) }
    fn inner() -> ClientInner {
        let plan = plan();
        ClientInner { resource:plan.discovery.resource, token_endpoint:url("https://issuer.example/token"),
            client_id:"service-client".to_owned(), scopes:vec!["read".to_owned(),"write".to_owned()], secret:plan.secret,
            issuer_roots:vec![], timeout:Duration::from_secs(30), maximum_lifetime:Duration::from_secs(60),
            leeway:Duration::from_secs(30), closed:McpRequestCancellation::new(), pending:AtomicUsize::new(0),
            state:Arc::new(Mutex::new(TokenState::default())) }
    }
    fn core() -> CoreRequest {
        CoreRequest::decode(ProtocolEra::Modern2026, "tools/list", Some(&json!({"_meta":{
            "io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientCapabilities":{},
            "com.example/tenant":"preserved"}}))).unwrap()
    }
    #[test]
    fn machine_metadata_does_not_require_a_browser_endpoint_or_pkce() {
        let plan = plan();
        assert!(admit_machine_issuer(&plan.discovery, &plan.discovery.issuers[0], &serde_json::to_vec(&issuer()).unwrap()).is_ok());
        for (key, value) in [("issuer",json!("https://other.example")),("token_endpoint",json!("https://other.example/token")),
            ("grant_types_supported",json!(["authorization_code"])),("token_endpoint_auth_methods_supported",json!(["private_key_jwt"])),
            ("protected_resources",json!(["https://other.example/mcp"])),("signed_metadata",json!("unverified"))] {
            let mut document=issuer(); document[key]=value;
            assert!(admit_machine_issuer(&plan.discovery,&plan.discovery.issuers[0],&serde_json::to_vec(&document).unwrap()).is_err());
        }
    }
    #[test]
    fn basic_credentials_encode_components_before_encoding_the_pair() {
        assert_eq!(basic("service", "secret").unwrap(), "Basic c2VydmljZTpzZWNyZXQ=");
        assert_eq!(basic("a:b +", "c/d=\u{e9}").unwrap(), "Basic YSUzQWIrJTJCOmMlMkZkJTNEJUMzJUE5");
        assert_eq!(component("a:b +"), "a%3Ab+%2B");
        assert_eq!(component("c/d=\u{e9}"), "c%2Fd%3D%C3%A9");
        assert_eq!(form(&[("scope",""),("grant_type","client_credentials")]), "grant_type=client_credentials");
    }
    #[test]
    fn token_admission_bounds_expiry_scopes_and_resource_without_refresh_authority() {
        let inner=inner(); let now=Instant::now();
        let token=admit_token(&inner, br#"{"access_token":"access","token_type":"Bearer","expires_in":600,"scope":"read","refresh_token":"ignored"}"#,now).unwrap();
        assert_eq!(token.expires_at,now+Duration::from_secs(60));
        assert_eq!(token.scopes,["read"]);
        assert!(token.bearer.authorization_for_target(&inner.resource).is_some());
        assert!(token.bearer.authorization_for_target(&url("https://issuer.example/token")).is_none());
        for raw in [r#"{"access_token":"access","token_type":"Basic"}"#,r#"{"access_token":"access","token_type":"Bearer","scope":"admin"}"#,
            r#"{"access_token":"access","token_type":"Bearer","expires_in":null}"#,r#"{"access_token":"access","token_type":"Bearer","expires_in":0}"#,
            r#"{"access_token":"access","access_token":"duplicate","token_type":"Bearer"}"#,
            r#"["access","Bearer",60]"#,r#"{"access_token":"access","token_type":"Bearer","resource":"https://wrong.example"}"#] {
            assert!(admit_token(&inner,raw.as_bytes(),now).is_err());
        }
    }
    #[test]
    fn explicit_profile_stamping_preserves_metadata_and_refuses_other_extensions() {
        let (wire, _) = prepare(&url("https://resource.example/mcp"), &core(), &RequestId::Number(7)).unwrap();
        let body:Value=serde_json::from_slice(wire.body()).unwrap();
        assert_eq!(body["params"]["_meta"]["com.example/tenant"],"preserved");
        assert_eq!(body["params"]["_meta"][FINAL_CLIENT_CAPABILITIES_META_KEY]["extensions"],json!({CLIENT_CREDENTIALS_EXTENSION:{}}));
        assert!(!wire.headers().iter().any(|(name,_)| name.eq_ignore_ascii_case("authorization")));
        let mut params=core().encode_params().unwrap().unwrap();
        params["_meta"][FINAL_CLIENT_CAPABILITIES_META_KEY]["extensions"]=json!({"io.modelcontextprotocol/tasks":{}});
        let other=CoreRequest::decode(ProtocolEra::Modern2026,"tools/list",Some(&params)).unwrap();
        assert!(prepare(&url("https://resource.example/mcp"),&other,&RequestId::Number(7)).is_err());
    }
    #[test]
    fn source_closure_revokes_existing_token_clones_without_an_http_request() {
        let inner=inner();
        let token=admit_token(&inner,br#"{"access_token":"access","token_type":"Bearer"}"#,Instant::now()).unwrap();
        let clone=token.bearer.clone();
        assert!(clone.authorization_for_target(&inner.resource).is_some());
        inner.closed.cancel();
        assert!(clone.authorization_for_target(&inner.resource).is_none());
        assert!(check_token(&token.bearer,token.expires_at).is_err());
    }
    #[test]
    fn secrets_are_not_retained_by_debug_or_error_diagnostics() {
        let policy=plan();
        assert!(!format!("{policy:?}").contains("unit-secret"));
        assert!(ClientCredentialsPlan::new(url("https://resource.example/mcp"),TrustedOAuthIssuer::new("https://issuer.example").unwrap(),
            "service","bad\r\nsecret",vec![]).is_err());
        assert!(plan().with_maximum_token_lifetime(Duration::ZERO).is_err());
    }
    #[test]
    fn shared_acquisition_bound_releases_capacity_when_work_is_dropped() {
        let pending=AtomicUsize::new(0);
        let permits:Vec<_>=(0..MAX_ACQUISITIONS).map(|_| AcquisitionPermit::new(&pending).unwrap()).collect();
        assert!(matches!(AcquisitionPermit::new(&pending),Err(ClientCredentialsError::Saturated)));
        drop(permits);
        assert_eq!(pending.load(Ordering::Acquire),0);
        let permit=AcquisitionPermit::new(&pending).unwrap();
        drop(async move { let _permit=permit; std::future::pending::<()>().await; });
        assert_eq!(pending.load(Ordering::Acquire),0);
    }
    #[test]
    fn typed_json_admission_preserves_exact_members_and_refuses_foreign_ids() {
        let wire=br#"{"jsonrpc":"2.0","id":7,"result":{"resultType":"complete","tools":[],"ttlMs":0,"cacheScope":"private","x-exact":1.20e+4}}"#;
        let result=decoded_result(&core(),&RequestId::Number(7),wire,4096).unwrap();
        assert!(result.encode().unwrap().contains("1.20e+4"));
        assert!(decoded_result(&core(),&RequestId::Number(8),wire,4096).is_err());
        assert!(decoded_result(&core(),&RequestId::Number(7),wire,20).is_err());
    }
}
