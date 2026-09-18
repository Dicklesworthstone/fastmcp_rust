//! Resource-bound RFC 9728 challenges for explicit native OAuth login.
//!
//! A challenge selects a metadata LOCATION, never a trusted issuer, client
//! registration, requested scope set, or permission to replay a failed call.
//! The optional probe sends only an unauthenticated modern server/discover;
//! it never sends tools/call, a credential, or a legacy negotiation request.
//! A 401 head is sufficient: its response body is dropped without consumption.
//!
//! The generic parser follows RFC 9110 challenge/auth-param syntax, preserving
//! repeated field lines and quoted commas. RFC 9728 resource_metadata can occur
//! on ANY admitted scheme; exactly one occurrence may select a location. A
//! Bearer scope is admitted separately, at most once across the entire set.
//! Token68 challenges provide neither parameter, even on the Bearer scheme.
//! This does not activate unsupported authentication schemes or splice their
//! parameters into another challenge. No 403 escalation, DPoP, DCR, automatic
//! login/retry, DNS pinning, or OIDC identity authentication is installed.

use std::collections::BTreeSet;
use std::fmt;
use std::future::{Future, poll_fn};
use std::io::{self, Write};
use std::task::Poll;
use std::time::Duration;

use asupersync::Cx;
use asupersync::channel::oneshot;
use asupersync::http::h1::{HttpClient, Method, RedirectPolicy, RetryPolicy};
use asupersync::time::Sleep;
use asupersync::tls::Certificate;
use asupersync::types::Time;
use fastmcp_core::{AccessToken, CanonicalHttpUrl, McpRequestCancellation};
use fastmcp_protocol::{ClientCapabilities, FinalRequestMeta, RequestId, FINAL_PROTOCOL_VERSION};

use super::{
    OAuthDiscoveryError, OAuthDiscoveryPlan, admit_root, check_context,
    discovery_deadline, fetch_metadata, issuer_metadata_urls, origin_of, validate_https,
};
use crate::http_auth::managed::{ManagedOAuthSession, OAuthSessionPolicy};
use crate::http_auth::oauth::{OAuthClient, OAuthClientConfiguration, OAuthError};

const MAX_HEADER_FIELDS: usize = 128;
const MAX_HEADER_BYTES: usize = 64 * 1024;
const MAX_CHALLENGE_BYTES: usize = 16 * 1024;
const MAX_CHALLENGES: usize = 16;
const MAX_PARAMETERS: usize = 32;
const MAX_NAME_BYTES: usize = 128;
const MAX_VALUE_BYTES: usize = 4096;
const MAX_PROBE_BYTES: usize = 16 * 1024;

/// Fixed diagnostics. No raw challenge, peer URL, realm, scope, response body,
/// or transport error is retained in a failure.
#[derive(Debug)]
pub enum OAuthChallengeError {
    InvalidPolicy,
    InvalidChallenge,
    /// Multiple Bearer scope parameters, including identical values.
    AmbiguousBearerChallenge,
    /// Multiple metadata parameters, including identical values or other schemes.
    AmbiguousMetadataLocation,
    /// No metadata hint and no Bearer challenge permitting the no-hint path.
    MissingBearerChallenge,
    UnsupportedStatus { status: u16 },
    ResourceMismatch,
    MetadataOriginNotTrusted,
    LimitExceeded,
    Transport,
    Discovery(OAuthDiscoveryError),
}

impl fmt::Display for OAuthChallengeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::InvalidPolicy => "invalid OAuth challenge policy",
            Self::InvalidChallenge => "malformed OAuth challenge",
            Self::AmbiguousBearerChallenge => "multiple Bearer scope parameters are ambiguous",
            Self::AmbiguousMetadataLocation => "multiple challenged metadata locations are ambiguous",
            Self::MissingBearerChallenge => "response has neither a metadata hint nor a Bearer challenge",
            Self::UnsupportedStatus { .. } => "response is not an OAuth 401 challenge",
            Self::ResourceMismatch => "OAuth challenge belongs to another resource",
            Self::MetadataOriginNotTrusted => "challenged metadata origin requires an explicit host grant",
            Self::LimitExceeded => "OAuth challenge input exceeds its bound",
            Self::Transport => "OAuth challenge probe transport failed",
            Self::Discovery(_) => "challenged OAuth discovery or login failed",
        })
    }
}
impl std::error::Error for OAuthChallengeError {}
impl From<OAuthDiscoveryError> for OAuthChallengeError {
    fn from(error: OAuthDiscoveryError) -> Self { Self::Discovery(error) }
}

/// Admitted data from one resource's HTTP 401, not an authorization receipt.
/// No serialization or raw-header retention is provided. A scope hint is
/// advisory peer input only and is NEVER merged into requested scopes.
#[derive(Clone)]
pub struct ResourceMetadataChallenge {
    resource: CanonicalHttpUrl,
    metadata_url: Option<CanonicalHttpUrl>,
    scope_hint: Option<String>,
}

impl fmt::Debug for ResourceMetadataChallenge {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ResourceMetadataChallenge")
            .field("has_metadata_location", &self.metadata_url.is_some())
            .field("has_scope_hint", &self.scope_hint.is_some())
            .finish_non_exhaustive()
    }
}

impl ResourceMetadataChallenge {
    /// Admits an already-received response head. The host MUST supply the exact
    /// effective target of its verified HTTPS request, with redirects disabled,
    /// and every WWW-Authenticate field in wire order. This parser cannot verify
    /// that a caller-provided head came from a network peer; use probe() when
    /// FastMCP should own that association. Proxy challenges and bodies are not
    /// inspected. Statuses other than 401 are deliberately not login triggers.
    /// A metadata hint on another scheme does not select that scheme: the host's
    /// preregistered OAuth plan remains the authentication authority.
    pub fn from_response(
        resource: CanonicalHttpUrl,
        status: u16,
        headers: &[(String, String)],
    ) -> Result<Self, OAuthChallengeError> {
        validate_https(&resource).map_err(|_| OAuthChallengeError::InvalidPolicy)?;
        if status != 401 { return Err(OAuthChallengeError::UnsupportedStatus { status }); }
        if headers.len() > MAX_HEADER_FIELDS { return Err(OAuthChallengeError::LimitExceeded); }
        let mut total = 0_usize;
        let mut combined = String::new();
        for (name, value) in headers {
            total = total.saturating_add(name.len()).saturating_add(value.len());
            if total > MAX_HEADER_BYTES { return Err(OAuthChallengeError::LimitExceeded); }
            if !AccessToken::is_valid_http_scheme(name) {
                return Err(OAuthChallengeError::InvalidChallenge);
            }
            if !name.eq_ignore_ascii_case("www-authenticate") { continue; }
            if value.bytes().any(|b| b == 0x7f || (b < 0x20 && b != b'\t')) {
                return Err(OAuthChallengeError::InvalidChallenge);
            }
            let additional = value.len().saturating_add(usize::from(!combined.is_empty()));
            if additional > MAX_CHALLENGE_BYTES.saturating_sub(combined.len()) {
                return Err(OAuthChallengeError::LimitExceeded);
            }
            if !combined.is_empty() { combined.push(','); }
            combined.push_str(value);
        }
        let mut parser = ChallengeParser { text: &combined, offset: 0, count: 0 };
        let mut saw_bearer = false;
        let mut metadata_url = None;
        let mut scope_hint = None;
        while let Some(challenge) = parser.next()? {
            let bearer = challenge.scheme.eq_ignore_ascii_case("bearer");
            saw_bearer |= bearer;
            // Token68 is structurally distinct from auth-params, even when its
            // opaque characters look like an empty name= parameter. It supplies
            // neither a metadata location nor a scope hint.
            if challenge.token68 { continue; }
            for (name, value) in challenge.parameters {
                match name.as_str() {
                    "resource_metadata" => {
                        if metadata_url.is_some() { return Err(OAuthChallengeError::AmbiguousMetadataLocation); }
                        metadata_url = Some(metadata_url_from_text(&value)?);
                    }
                    "scope" if bearer => {
                        if scope_hint.is_some() { return Err(OAuthChallengeError::AmbiguousBearerChallenge); }
                        validate_scope_hint(&value)?;
                        scope_hint = Some(value);
                    }
                    _ => {},
                }
            }
        }
        if metadata_url.is_none() && !saw_bearer {
            return Err(OAuthChallengeError::MissingBearerChallenge);
        }
        Ok(Self { resource, metadata_url, scope_hint })
    }

    pub fn resource(&self) -> &CanonicalHttpUrl { &self.resource }
    pub fn metadata_url(&self) -> Option<&CanonicalHttpUrl> { self.metadata_url.as_ref() }
    /// Untrusted display/policy input, never permission to widen a grant.
    pub fn scope_hint(&self) -> Option<&str> { self.scope_hint.as_deref() }

    /// Performs ONE unauthenticated modern server/discover POST. It returns
    /// only an admitted 401 challenge set; 2xx, redirects, 403 and transport
    /// errors are terminal and never select another era or authentication.
    /// No body is read and no subsequent discovery, login or replay is started.
    /// The native client's bundled/native-root policy validates resource TLS;
    /// a metadata-only root grant does not alter this probe's trust policy.
    pub async fn probe(
        cx: &Cx, resource: CanonicalHttpUrl, id: RequestId, timeout: Duration,
    ) -> Result<Self, OAuthChallengeError> {
        Self::probe_with_cancellation(cx, &McpRequestCancellation::new(), resource, id, timeout).await
    }

    pub async fn probe_with_cancellation(
        cx: &Cx, cancellation: &McpRequestCancellation,
        resource: CanonicalHttpUrl, id: RequestId, timeout: Duration,
    ) -> Result<Self, OAuthChallengeError> {
        validate_https(&resource).map_err(|_| OAuthChallengeError::InvalidPolicy)?;
        id.validate().map_err(|_| OAuthChallengeError::InvalidPolicy)?;
        if timeout.is_zero() || timeout > Duration::from_secs(120) {
            return Err(OAuthChallengeError::InvalidPolicy);
        }
        let deadline = discovery_deadline(cx, timeout)?;
        let mut body = ProbeBody(Vec::new());
        let envelope = serde_json::json!({
            "jsonrpc":"2.0", "id":id, "method":"server/discover",
            "params":{"_meta":FinalRequestMeta::new(ClientCapabilities::default())},
        });
        serde_json::to_writer(&mut body, &envelope).map_err(|_| OAuthChallengeError::LimitExceeded)?;
        let client = HttpClient::builder().redirect_policy(RedirectPolicy::None)
            .retry_policy(RetryPolicy::None).no_proxy().no_cookie_store()
            .max_body_size(super::MAX_OAUTH_METADATA_BYTES).max_total_connections(1).build();
        active(cx, cancellation, deadline, async {
            let response = client.request_streaming(cx, Method::Post, resource.as_str(), vec![
                ("Content-Type".to_owned(), "application/json".to_owned()),
                ("Accept".to_owned(), "application/json, text/event-stream".to_owned()),
                ("Accept-Encoding".to_owned(), "identity".to_owned()),
                ("Mcp-Protocol-Version".to_owned(), FINAL_PROTOCOL_VERSION.to_owned()),
                ("Mcp-Method".to_owned(), "server/discover".to_owned()),
                ("Connection".to_owned(), "close".to_owned()),
            ], body.0).await.map_err(|_| OAuthChallengeError::Transport)?;
            // The owned body/socket is dropped even when the peer advertises
            // an unfinished body. Its bytes cannot forge authentication hints.
            Self::from_response(resource, response.head.status, &response.head.headers)
        }).await
    }
}

/// Explicitly combines a resource's challenge with an existing trusted native
/// client plan. It preserves that plan's issuer order, registration and scopes.
/// Cross-origin metadata GETs need a separate origin grant. Granting a metadata
/// origin or root never authorizes login/token/registration endpoints there.
/// This is a preregistered public-client API; existing discovery paths are unchanged.
pub struct ChallengedOAuthDiscovery {
    plan: OAuthDiscoveryPlan,
    challenge: ResourceMetadataChallenge,
    metadata_origins: Vec<String>,
    metadata_roots: Vec<Certificate>,
}
impl fmt::Debug for ChallengedOAuthDiscovery {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ChallengedOAuthDiscovery")
            .field("challenge", &self.challenge).finish_non_exhaustive()
    }
}
impl ChallengedOAuthDiscovery {
    pub fn new(plan: OAuthDiscoveryPlan, challenge: ResourceMetadataChallenge) -> Result<Self, OAuthChallengeError> {
        if plan.resource != challenge.resource { return Err(OAuthChallengeError::ResourceMismatch); }
        if plan.client_id.is_none() { return Err(OAuthChallengeError::InvalidPolicy); }
        Ok(Self { plan, challenge, metadata_origins: Vec::new(), metadata_roots: Vec::new() })
    }

    /// An administrator-granted metadata origin, not a peer-derived allowlist.
    /// Pass its HTTPS root URL without query, fragment or userinfo. Same-origin
    /// metadata needs no extra grant; at most eight different origins are kept.
    pub fn with_metadata_origin(mut self, origin: CanonicalHttpUrl) -> Result<Self, OAuthChallengeError> {
        validate_https(&origin).map_err(|_| OAuthChallengeError::InvalidPolicy)?;
        let origin_text = origin_of(&origin);
        if origin.path() != "/" || self.metadata_origins.len() >= 8
            || origin_text == origin_of(&self.plan.resource) || self.metadata_origins.contains(&origin_text)
        { return Err(OAuthChallengeError::InvalidPolicy); }
        self.metadata_origins.push(origin_text);
        Ok(self)
    }

    /// Private trust for additionally approved cross-origin METADATA only.
    /// Same-origin metadata uses the original plan's resource-metadata roots;
    /// issuer metadata and token exchanges retain their separate issuer roots.
    pub fn with_metadata_root_certificate(mut self, root: Certificate) -> Result<Self, OAuthChallengeError> {
        admit_root(&mut self.metadata_roots, root)?;
        Ok(self)
    }

    fn location(&self) -> Result<Option<&CanonicalHttpUrl>, OAuthChallengeError> {
        let Some(location) = self.challenge.metadata_url.as_ref() else { return Ok(None); };
        let origin = metadata_origin(location);
        if origin != origin_of(&self.plan.resource) && !self.metadata_origins.iter().any(|allowed| allowed == origin) {
            return Err(OAuthChallengeError::MetadataOriginNotTrusted);
        }
        Ok(Some(location))
    }

    pub async fn discover(&self, cx: &Cx) -> Result<OAuthClientConfiguration, OAuthChallengeError> {
        self.discover_with_cancellation(cx, &McpRequestCancellation::new()).await
    }

    /// Fetches the explicit hint once, without redirect or well-known fallback
    /// on failure. A valid Bearer challenge WITHOUT a hint uses the existing
    /// well-known path. All metadata GETs share one deadline. Every document
    /// still passes exact resource identity, local issuer selection and native
    /// flow admission. Scope/realm/error parameters do not change the plan.
    pub async fn discover_with_cancellation(
        &self, cx: &Cx, cancellation: &McpRequestCancellation,
    ) -> Result<OAuthClientConfiguration, OAuthChallengeError> {
        let location = self.location()?;
        let deadline = discovery_deadline(cx, self.plan.timeout)?;
        active(cx, cancellation, deadline, async {
            let Some(location) = location else { return Ok(self.plan.discover(cx).await?); };
            let roots = if metadata_origin(location) == origin_of(&self.plan.resource) {
                &self.plan.resource_roots
            } else { &self.metadata_roots };
            let body = fetch_metadata(cx, deadline, location, roots).await?
                .ok_or(OAuthDiscoveryError::MetadataNotFound)?;
            // RFC 9728 3.3: the metadata resource must identify the ORIGINAL
            // challenged request URL, not the URL/host serving this document.
            let issuer = self.plan.select_issuer(&body)?;
            for location in issuer_metadata_urls(&issuer.url)? {
                check_context(cx, deadline)?;
                if let Some(body) = fetch_metadata(cx, deadline, &location, &issuer.roots).await? {
                    let configuration = self.plan.admit_issuer(issuer, &body)?;
                    check_context(cx, deadline)?;
                    return Ok(configuration);
                }
            }
            Err(OAuthDiscoveryError::MetadataNotFound.into())
        }).await
    }

    /// Explicit login, only after challenged discovery succeeds. Login retains
    /// its own existing timeout; it is not a continuation of a failed tool call.
    /// No registration write, scope escalation, or failed-call replay occurs.
    pub async fn authorize_managed<L, F>(
        &self, cx: &Cx, policy: OAuthSessionPolicy, launch_browser: L,
    ) -> Result<ManagedOAuthSession, OAuthChallengeError>
    where L: FnOnce(CanonicalHttpUrl) -> F, F: Future<Output = Result<(), OAuthError>>,
    {
        self.authorize_managed_with_cancellation(cx, &McpRequestCancellation::new(), policy, launch_browser).await
    }

    /// The same request-owned cancellation domain spans discovery, browser
    /// launch, callback admission and token redemption. It never cancels the
    /// caller's Cx or another session. Dropping a polled operation releases the
    /// pending fetch/listener; a launched browser cannot be recalled. The login
    /// driver's finite deadline still applies independently of discovery time.
    pub async fn authorize_managed_with_cancellation<L, F>(
        &self, cx: &Cx, cancellation: &McpRequestCancellation,
        policy: OAuthSessionPolicy, launch_browser: L,
    ) -> Result<ManagedOAuthSession, OAuthChallengeError>
    where L: FnOnce(CanonicalHttpUrl) -> F, F: Future<Output = Result<(), OAuthError>>,
    {
        let configuration = self.discover_with_cancellation(cx, cancellation).await?;
        let deadline = cx.budget().deadline.unwrap_or(Time::from_nanos(u64::MAX));
        active(cx, cancellation, deadline, async {
            ManagedOAuthSession::authorize(cx, OAuthClient::new(configuration), policy, launch_browser)
                .await.map_err(|error| OAuthDiscoveryError::Login(error).into())
        }).await
    }
}

fn metadata_url_from_text(text: &str) -> Result<CanonicalHttpUrl, OAuthChallengeError> {
    if text.is_empty() || text.len() > MAX_VALUE_BYTES || !text.starts_with("https://")
        || text.contains('\\') || text.chars().any(|c| c.is_whitespace() || c.is_control())
    { return Err(OAuthChallengeError::InvalidChallenge); }
    let url = CanonicalHttpUrl::parse(text).map_err(|_| OAuthChallengeError::InvalidChallenge)?;
    if url.scheme() != "https" || url.has_userinfo() || url.fragment().is_some() {
        return Err(OAuthChallengeError::InvalidChallenge);
    }
    Ok(url)
}

fn validate_scope_hint(scope: &str) -> Result<(), OAuthChallengeError> {
    if scope.is_empty() || scope.split(' ').any(|part| part.is_empty() || !part.bytes().all(|b| {
        b == 0x21 || (0x23..=0x5b).contains(&b) || (0x5d..=0x7e).contains(&b)
    })) { return Err(OAuthChallengeError::InvalidChallenge); }
    Ok(())
}

// Unlike issuer/resource identity URLs, a metadata location MAY have a query.
// All canonical HTTP URLs include a slash after their authority; userinfo was
// rejected before this slice. IPv6 brackets and non-default ports are retained.
fn metadata_origin(url: &CanonicalHttpUrl) -> &str {
    let text = url.as_str();
    let end = text[8..].find('/').map_or(text.len(), |relative| 8 + relative);
    &text[..end]
}

struct ProbeBody(Vec<u8>);
impl Write for ProbeBody {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if bytes.len() > MAX_PROBE_BYTES.saturating_sub(self.0.len()) {
            return Err(io::Error::other("OAuth probe byte limit"));
        }
        self.0.extend_from_slice(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> { Ok(()) }
}

async fn active<T>(
    cx: &Cx, cancellation: &McpRequestCancellation, deadline: Time,
    future: impl Future<Output = Result<T, OAuthChallengeError>>,
) -> Result<T, OAuthChallengeError> {
    let deadline = cx.budget().deadline.map_or(deadline, |parent| parent.min(deadline));
    let timer = cx.timer_driver().ok_or(OAuthDiscoveryError::RuntimeUnavailable)?;
    let mut sleep = std::pin::pin!(Sleep::with_timer_driver(deadline, timer));
    let mut cancelled = std::pin::pin!(cancellation.cancelled());
    let (_sender, mut receiver) = oneshot::channel::<()>();
    let mut ambient = std::pin::pin!(receiver.recv(cx));
    let mut future = std::pin::pin!(future);
    poll_fn(|task| {
        check_context(cx, deadline)?;
        if cancellation.is_cancel_requested() { return Poll::Ready(Err(OAuthDiscoveryError::Cancelled.into())); }
        let _caller = Cx::set_current(Some(cx.clone()));
        if cancelled.as_mut().poll(task).is_ready() || ambient.as_mut().poll(task).is_ready() {
            return Poll::Ready(Err(OAuthDiscoveryError::Cancelled.into()));
        }
        if sleep.as_mut().poll(task).is_ready() { return Poll::Ready(Err(OAuthDiscoveryError::TimedOut.into())); }
        let result = future.as_mut().poll(task);
        check_context(cx, deadline)?;
        if cancellation.is_cancel_requested() { return Poll::Ready(Err(OAuthDiscoveryError::Cancelled.into())); }
        result
    }).await
}

struct ParsedChallenge<'a> {
    scheme: &'a str,
    token68: bool,
    parameters: Vec<(String, String)>,
}
struct ChallengeParser<'a> { text: &'a str, offset: usize, count: usize }
impl<'a> ChallengeParser<'a> {
    fn byte(&self) -> Option<u8> { self.text.as_bytes().get(self.offset).copied() }
    fn ows(&mut self) { while matches!(self.byte(), Some(b' ' | b'\t')) { self.offset += 1; } }
    fn commas(&mut self) {
        self.ows();
        while self.byte() == Some(b',') { self.offset += 1; self.ows(); }
    }
    fn token(&mut self, maximum: usize) -> Result<&'a str, OAuthChallengeError> {
        let start = self.offset;
        while self.byte().is_some_and(is_token) { self.offset += 1; }
        if self.offset == start { return Err(OAuthChallengeError::InvalidChallenge); }
        if self.offset - start > maximum { return Err(OAuthChallengeError::LimitExceeded); }
        Ok(&self.text[start..self.offset])
    }
    fn value(&mut self) -> Result<String, OAuthChallengeError> {
        if self.byte() != Some(b'"') { return Ok(self.token(MAX_VALUE_BYTES)?.to_owned()); }
        self.offset += 1;
        let mut value = Vec::new();
        loop {
            let byte = self.byte().ok_or(OAuthChallengeError::InvalidChallenge)?;
            self.offset += 1;
            match byte {
                b'"' => break,
                b'\\' => {
                    let escaped = self.byte().ok_or(OAuthChallengeError::InvalidChallenge)?;
                    if escaped != b'\t' && !(0x20..=0x7e).contains(&escaped) && escaped < 0x80 {
                        return Err(OAuthChallengeError::InvalidChallenge);
                    }
                    self.offset += 1;
                    if value.len() >= MAX_VALUE_BYTES { return Err(OAuthChallengeError::LimitExceeded); }
                    value.push(escaped);
                }
                b'\t' | 0x20..=0x21 | 0x23..=0x5b | 0x5d..=0xff => {
                    if value.len() >= MAX_VALUE_BYTES { return Err(OAuthChallengeError::LimitExceeded); }
                    value.push(byte);
                }
                _ => return Err(OAuthChallengeError::InvalidChallenge),
            }
        }
        String::from_utf8(value).map_err(|_| OAuthChallengeError::InvalidChallenge)
    }
    fn next(&mut self) -> Result<Option<ParsedChallenge<'a>>, OAuthChallengeError> {
        self.commas();
        if self.offset == self.text.len() { return Ok(None); }
        self.count += 1;
        if self.count > MAX_CHALLENGES { return Err(OAuthChallengeError::LimitExceeded); }
        let scheme = self.token(MAX_NAME_BYTES)?;
        let mut parsed = ParsedChallenge { scheme, token68: false, parameters: Vec::new() };
        if self.byte().is_none() || self.byte() == Some(b',') { return Ok(Some(parsed)); }
        if self.byte() != Some(b' ') { return Err(OAuthChallengeError::InvalidChallenge); }
        self.ows();
        if self.byte().is_none() || self.byte() == Some(b',') { return Ok(Some(parsed)); }
        let end = self.text[self.offset..].find(',').map_or(self.text.len(), |n| self.offset + n);
        let candidate = self.text[self.offset..end].trim_end_matches([' ', '\t']);
        if AccessToken::is_valid_token68(candidate) {
            if candidate.len() > MAX_VALUE_BYTES { return Err(OAuthChallengeError::LimitExceeded); }
            self.offset = end;
            parsed.token68 = true;
            return Ok(Some(parsed));
        }
        let mut names = BTreeSet::new();
        loop {
            let name = self.token(MAX_NAME_BYTES)?.to_ascii_lowercase();
            if names.len() >= MAX_PARAMETERS { return Err(OAuthChallengeError::LimitExceeded); }
            if !names.insert(name.clone()) { return Err(OAuthChallengeError::InvalidChallenge); }
            self.ows();
            if self.byte() != Some(b'=') { return Err(OAuthChallengeError::InvalidChallenge); }
            self.offset += 1;
            self.ows();
            parsed.parameters.push((name, self.value()?));
            self.ows();
            if self.byte().is_none() { break; }
            if self.byte() != Some(b',') { return Err(OAuthChallengeError::InvalidChallenge); }
            self.commas();
            if self.byte().is_none() { break; }
            let next = self.offset;
            self.token(MAX_NAME_BYTES)?;
            self.ows();
            let same_challenge = self.byte() == Some(b'=');
            self.offset = next;
            if !same_challenge { break; }
        }
        Ok(Some(parsed))
    }
}
fn is_token(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte,
        b'!' | b'#' | b'$' | b'%' | b'&' | b'\'' | b'*' | b'+' | b'-' | b'.'
        | b'^' | b'_' | b'`' | b'|' | b'~')
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::TrustedOAuthIssuer;
    fn url(text: &str) -> CanonicalHttpUrl { CanonicalHttpUrl::parse(text).unwrap() }
    fn parse(value: &str) -> Result<ResourceMetadataChallenge, OAuthChallengeError> {
        ResourceMetadataChallenge::from_response(url("https://resource.example/mcp"), 401,
            &[("WWW-Authenticate".to_owned(), value.to_owned())])
    }
    fn plan() -> OAuthDiscoveryPlan {
        OAuthDiscoveryPlan::new(url("https://resource.example/mcp"),
            vec![TrustedOAuthIssuer::new("https://issuer.example").unwrap()], "registered", vec!["read".to_owned()]).unwrap()
    }
    #[test]
    fn quoted_commas_unknown_schemes_and_escapes_do_not_split_the_bearer_challenge() {
        let challenge = parse(r#"Basic realm="decoy, realm", Negotiate YWJjZA==, bEaReR realm="escaped \"value\"", resource_metadata="https://resource.example/meta?tenant=a,b", scope="read write""#).unwrap();
        assert_eq!(challenge.metadata_url().unwrap().as_str(), "https://resource.example/meta?tenant=a,b");
        assert_eq!(challenge.scope_hint(), Some("read write"));
    }
    #[test]
    fn field_lines_are_combined_without_losing_parameters_or_challenges() {
        let challenge = ResourceMetadataChallenge::from_response(url("https://resource.example/mcp"), 401, &[
            ("WWW-Authenticate".to_owned(), "Basic realm=other, Bearer realm=primary".to_owned()),
            ("www-authenticate".to_owned(), "resource_metadata=\"https://resource.example/meta\"".to_owned()),
        ]).unwrap();
        assert_eq!(challenge.metadata_url().unwrap().as_str(), "https://resource.example/meta");
        assert!(parse(", , Bearer realm=primary, ,").is_ok());
    }
    #[test]
    fn duplicate_parameters_and_multiple_bearer_scopes_fail() {
        for value in [
            "Bearer realm=a, REALM=b", "Bearer scope=read, Scope=write",
            "Bearer resource_metadata=\"https://resource.example/a\", RESOURCE_METADATA=\"https://resource.example/a\"",
        ] { assert!(matches!(parse(value), Err(OAuthChallengeError::InvalidChallenge))); }
        for value in ["Bearer scope=read, Bearer scope=read", "Bearer scope=read, Bearer scope=write"] {
            assert!(matches!(parse(value), Err(OAuthChallengeError::AmbiguousBearerChallenge)));
        }
        // Distinct realms alone are not metadata or scope ambiguity. The host
        // plan selects authentication; realms cannot pick an issuer or grant.
        assert!(parse("Bearer realm=a, Bearer realm=b").is_ok());
    }
    #[test]
    fn malformed_hints_never_turn_into_well_known_fallback() {
        for value in [
            "Bearer resource_metadata=\"\"", "Bearer resource_metadata=\"/relative\"",
            "Bearer resource_metadata=\"http://resource.example/meta\"",
            "Bearer resource_metadata=\"https://user@resource.example/meta\"",
            "Bearer resource_metadata=\"https://resource.example/meta#fragment\"",
            "Bearer resource_metadata=\"https://resource.example/meta", "Bearer realm=\"bad\\",
            "Bearer realm=\"bad\r\nvalue\"", "Bearer scope=read trailing",
            "Basic resource_metadata=\"http://resource.example/meta\", Bearer",
        ] { assert!(parse(value).is_err(), "malformed challenge must fail"); }
    }
    #[test]
    fn status_proxy_headers_and_unrelated_scheme_data_do_not_initiate_login() {
        for status in [200, 302, 400, 403, 407, 500] {
            assert!(matches!(ResourceMetadataChallenge::from_response(url("https://resource.example/mcp"), status,
                &[("WWW-Authenticate".to_owned(), "Bearer".to_owned())]), Err(OAuthChallengeError::UnsupportedStatus { .. })));
        }
        assert!(matches!(ResourceMetadataChallenge::from_response(url("https://resource.example/mcp"), 401,
            &[("Proxy-Authenticate".to_owned(), "Bearer resource_metadata=\"https://evil.example/meta\"".to_owned())]),
            Err(OAuthChallengeError::MissingBearerChallenge)));
        assert!(matches!(parse("Other scope=admin"), Err(OAuthChallengeError::MissingBearerChallenge)));
    }
    #[test]
    fn hinted_scopes_never_change_the_registered_request() {
        let challenge = parse("Bearer scope=admin").unwrap();
        let discovered = ChallengedOAuthDiscovery::new(plan(), challenge).unwrap();
        assert_eq!(discovered.plan.scopes, ["read"]);
        assert_eq!(discovered.plan.client_id.as_deref(), Some("registered"));
        assert!(discovered.location().unwrap().is_none());
    }
    #[test]
    fn metadata_origin_grant_is_separate_from_issuer_endpoint_trust() {
        let challenge = parse("Bearer resource_metadata=\"https://metadata.example/meta?tenant=one\"").unwrap();
        let mut original = plan();
        original.issuers[0] = original.issuers[0].clone().with_endpoint_origin(url("https://metadata.example/")).unwrap();
        let discovered = ChallengedOAuthDiscovery::new(original, challenge).unwrap();
        assert!(matches!(discovered.location(), Err(OAuthChallengeError::MetadataOriginNotTrusted)));
        let discovered = discovered.with_metadata_origin(url("https://metadata.example/")).unwrap();
        assert_eq!(discovered.location().unwrap().unwrap().as_str(), "https://metadata.example/meta?tenant=one");
        assert!(ChallengedOAuthDiscovery::new(plan(), parse("Bearer").unwrap()).unwrap()
            .with_metadata_origin(url("https://metadata.example/path")).is_err());
    }
    #[test]
    fn challenge_cannot_be_rebound_to_a_sibling_resource() {
        let challenge = ResourceMetadataChallenge::from_response(url("https://resource.example/other"), 401,
            &[("WWW-Authenticate".to_owned(), "Bearer".to_owned())]).unwrap();
        assert!(matches!(ChallengedOAuthDiscovery::new(plan(), challenge), Err(OAuthChallengeError::ResourceMismatch)));
    }
    #[test]
    fn parser_bounds_each_allocation_and_total_challenge_work() {
        assert!(matches!(parse(&" ".repeat(MAX_CHALLENGE_BYTES + 1)), Err(OAuthChallengeError::LimitExceeded)));
        let oversized_value = format!("Bearer realm=\"{}\"", "x".repeat(MAX_VALUE_BYTES + 1));
        assert!(matches!(parse(&oversized_value), Err(OAuthChallengeError::LimitExceeded)));
        assert!(matches!(parse(&format!("Bearer {}=v", "x".repeat(MAX_NAME_BYTES + 1))), Err(OAuthChallengeError::LimitExceeded)));
        assert!(matches!(parse(&format!("{} realm=v, Bearer", "X".repeat(MAX_NAME_BYTES + 1))), Err(OAuthChallengeError::LimitExceeded)));
        let fields = (0..MAX_PARAMETERS + 1).map(|n| format!("p{n}=v")).collect::<Vec<_>>().join(",");
        assert!(matches!(parse(&format!("Bearer {fields}")), Err(OAuthChallengeError::LimitExceeded)));
        let schemes = format!("{}Bearer", "Other, ".repeat(MAX_CHALLENGES));
        assert!(matches!(parse(&schemes), Err(OAuthChallengeError::LimitExceeded)));
        let headers = vec![("X-Other".to_owned(), String::new()); MAX_HEADER_FIELDS + 1];
        assert!(matches!(ResourceMetadataChallenge::from_response(url("https://resource.example/mcp"), 401, &headers),
            Err(OAuthChallengeError::LimitExceeded)));
    }
    #[test]
    fn diagnostic_formatting_does_not_echo_peer_hint_values() {
        let challenge = parse("Bearer resource_metadata=\"https://resource.example/meta?private=canary-secret\", scope=canary-scope").unwrap();
        let text = format!("{challenge:?}");
        assert!(!text.contains("canary") && !text.contains("resource.example"));
        assert!(!format!("{:?}", ChallengedOAuthDiscovery::new(plan(), challenge).unwrap()).contains("canary"));
    }
    #[test]
    fn metadata_origin_keeps_ipv6_and_nondefault_ports_without_query_confusion() {
        assert_eq!(metadata_origin(&url("https://[::1]:8443/meta?x=1")), "https://[::1]:8443");
        assert_eq!(metadata_origin(&url("https://resource.example:443/meta")), "https://resource.example");
    }
    #[test]
    fn probe_writer_rejects_encoded_overflow_without_a_partial_append() {
        let mut body = ProbeBody(vec![0; MAX_PROBE_BYTES - 1]);
        assert!(body.write_all(b"ab").is_err());
        assert_eq!(body.0.len(), MAX_PROBE_BYTES - 1);
        body.write_all(b"a").unwrap();
        assert_eq!(body.0.len(), MAX_PROBE_BYTES);
    }
    #[test]
    fn metadata_location_is_selected_across_schemes_without_splicing_scope() {
        for text in [
            "Basic resource_metadata=\"https://resource.example/meta\", scope=admin, Bearer scope=read",
            "Bearer scope=read, Other scope=admin, resource_metadata=\"https://resource.example/meta\"",
        ] {
            let challenge = parse(text).unwrap();
            assert_eq!(challenge.metadata_url().unwrap().as_str(), "https://resource.example/meta");
            assert_eq!(challenge.scope_hint(), Some("read"));
        }
        let challenge = parse("Other resource_metadata=\"https://resource.example/meta\", scope=admin").unwrap();
        assert!(challenge.metadata_url().is_some());
        assert!(challenge.scope_hint().is_none());
        for text in [
            "Bearer resource_metadata=\"https://resource.example/meta\", Basic resource_metadata=\"https://resource.example/meta\"",
            "Basic resource_metadata=\"https://resource.example/meta\", Bearer resource_metadata=\"https://resource.example/other\"",
        ] { assert!(matches!(parse(text), Err(OAuthChallengeError::AmbiguousMetadataLocation))); }
    }
    #[test]
    fn bearer_token68_has_neither_metadata_nor_scope_parameters() {
        for token in ["YWJjZA==", "resource_metadata=", "scope="] {
            let challenge = parse(&format!("Bearer {token}")).unwrap();
            assert!(challenge.metadata_url().is_none() && challenge.scope_hint().is_none());
        }
        let challenge = parse("Bearer YWJjZA==, Basic resource_metadata=\"https://resource.example/meta\"").unwrap();
        assert!(challenge.metadata_url().is_some() && challenge.scope_hint().is_none());
    }
    #[test]
    fn bearer_scope_preserves_order_but_rejects_invalid_scope_token_syntax() {
        assert_eq!(parse("Bearer scope=\"write read\"").unwrap().scope_hint(), Some("write read"));
        for scope in ["", " read", "read ", "read  write", "read\twrite", "réad"] {
            assert!(matches!(parse(&format!("Bearer scope=\"{scope}\"")), Err(OAuthChallengeError::InvalidChallenge)));
        }
    }
}
