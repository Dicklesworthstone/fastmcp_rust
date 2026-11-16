//! Request-owned, credential-free acquisition of enterprise verification keys.
//!
//! A trusted profile freezes two purpose-specific JWKS endpoints and key
//! generations. Each acquisition makes two independent guarded HTTPS GETs and
//! publishes both typed key owners together. Response data, token headers and
//! unknown key identifiers never choose an endpoint or trigger another fetch.
//! This supplies keys to the existing signed response consumers; it does not
//! acquire credentials, attest registration, or activate enterprise authorization.

use std::fmt;
use std::future::{Future, poll_fn};
use std::sync::{Arc, atomic::{AtomicBool, Ordering}};
use std::task::Poll;
use std::time::{Duration, Instant};

use asupersync::Cx;
use asupersync::channel::oneshot;
use asupersync::time::Sleep;
use asupersync::types::Time;
use fastmcp_core::{CanonicalHttpUrl, Sha256Digest};
use fastmcp_core::runtime::CallerContextFuture;
use fastmcp_protocol::jose::MAX_JWKS_BYTES;
use fastmcp_transport::{
    GuardedHttpFetchError, GuardedHttpFetchPolicy, GuardedHttpFetchResponse,
    GuardedHttpFetcher, GuardedHttpPeerProvenance, GuardedHttpsUrl,
};

use super::policy::EnterpriseProfile;
use super::verification::{
    IdJagVerificationKeys, MAX_ENTERPRISE_IDENTIFIER_BYTES, OidcVerificationKeys,
};

/// Fixed diagnostics contain no endpoint, issuer, response bytes or key material.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EnterpriseKeyFetchError {
    InvalidProfile,
    InvalidEndpoint,
    InvalidFetchPolicy,
    RuntimeUnavailable,
    FetchInProgress,
    Cancelled,
    TimedOut,
    FetchFailed,
    InvalidResponse,
    EvidenceMismatch,
    InvalidKeys,
}

impl fmt::Display for EnterpriseKeyFetchError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidProfile => "invalid enterprise verification-key profile",
            Self::InvalidEndpoint => "invalid enterprise verification-key endpoint",
            Self::InvalidFetchPolicy => "invalid enterprise verification-key fetch policy",
            Self::RuntimeUnavailable => "enterprise key acquisition requires caller I/O, time, spawn and timer authority",
            Self::FetchInProgress => "enterprise key acquisition is already in progress",
            Self::Cancelled => "enterprise key acquisition was cancelled",
            Self::TimedOut => "enterprise key acquisition exceeded its deadline",
            Self::FetchFailed => "enterprise guarded key fetch failed",
            Self::InvalidResponse => "enterprise verification-key response was refused",
            Self::EvidenceMismatch => "enterprise key fetch evidence differs from its request",
            Self::InvalidKeys => "enterprise verification-key document was refused",
        })
    }
}
impl std::error::Error for EnterpriseKeyFetchError {}

/// Exact endpoint and transport observation for one admitted JWKS document.
///
/// These facts describe the fetch. They are not a deployment attestation or a
/// receipt authorizing an assertion exchange.
pub struct EnterpriseJwksObservation {
    endpoint: String,
    key_generation: u64,
    document_digest: Sha256Digest,
    provenance: GuardedHttpPeerProvenance,
}

impl EnterpriseJwksObservation {
    #[must_use]
    pub fn endpoint(&self) -> &str { &self.endpoint }
    #[must_use]
    pub const fn key_generation(&self) -> u64 { self.key_generation }
    #[must_use]
    pub const fn document_digest(&self) -> Sha256Digest { self.document_digest }
    #[must_use]
    pub fn provenance(&self) -> &GuardedHttpPeerProvenance { &self.provenance }
}

impl fmt::Debug for EnterpriseJwksObservation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.debug_struct("EnterpriseJwksObservation").finish_non_exhaustive()
    }
}

/// Two independently fetched purpose owners bound to one frozen profile.
///
/// Pass the OIDC owner to EnterpriseProfile::admit_oidc_code_response and the
/// ID-JAG owner to EnterpriseProfile::admit_id_jag_response. Those consumers
/// also enforce the exact issuer and purpose-specific generation. No partial
/// pair is returned when either document or fetch is refused.
pub struct EnterpriseVerificationKeySet {
    profile: EnterpriseProfile,
    oidc: OidcVerificationKeys,
    id_jag: IdJagVerificationKeys,
    oidc_observation: EnterpriseJwksObservation,
    id_jag_observation: EnterpriseJwksObservation,
    fetch_policy: GuardedHttpFetchPolicy,
    fetch_policy_generation: u64,
}

impl EnterpriseVerificationKeySet {
    #[must_use]
    pub fn profile(&self) -> &EnterpriseProfile { &self.profile }
    #[must_use]
    pub fn oidc(&self) -> &OidcVerificationKeys { &self.oidc }
    #[must_use]
    pub fn id_jag(&self) -> &IdJagVerificationKeys { &self.id_jag }
    #[must_use]
    pub fn oidc_observation(&self) -> &EnterpriseJwksObservation { &self.oidc_observation }
    #[must_use]
    pub fn id_jag_observation(&self) -> &EnterpriseJwksObservation { &self.id_jag_observation }
    #[must_use]
    pub fn fetch_policy(&self) -> &GuardedHttpFetchPolicy { &self.fetch_policy }
    #[must_use]
    pub const fn fetch_policy_generation(&self) -> u64 { self.fetch_policy_generation }
}

impl fmt::Debug for EnterpriseVerificationKeySet {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.debug_struct("EnterpriseVerificationKeySet").finish_non_exhaustive()
    }
}

struct KeySource {
    profile: EnterpriseProfile,
    oidc_url: GuardedHttpsUrl,
    id_jag_url: GuardedHttpsUrl,
    fetcher: GuardedHttpFetcher,
    policy_generation: u64,
    busy: Arc<AtomicBool>,
    #[cfg(test)]
    test_exchange: Option<Arc<dyn tests::Exchange>>,
}

/// A fixed native HTTPS producer shared by all of its clones.
///
/// Construction performs no I/O. Keep and clone one source for a configured
/// profile: at most one acquisition may remain unsettled across those clones.
/// A changed registration, endpoint, key generation or policy requires a new
/// source. There is no cache, background refresh, retry or credential dispatch.
#[derive(Clone)]
pub struct EnterpriseKeySource {
    inner: Arc<KeySource>,
}

impl EnterpriseKeySource {
    /// Freezes the admitted profile and the guarded fetcher's concrete policy.
    ///
    /// Each body is limited to 64 KiB. The fetcher's deadline, at most thirty
    /// seconds, bounds the entire pair, including both parses; the caller's
    /// shorter deadline still applies. The nonzero policy generation records
    /// the operator's policy revision, independently of concrete limits and
    /// the fetcher's actual root identity.
    pub fn new(
        profile: EnterpriseProfile,
        fetcher: GuardedHttpFetcher,
        fetch_policy_generation: u64,
    ) -> Result<Self, EnterpriseKeyFetchError> {
        if fetch_policy_generation == 0
            || fetcher.policy().response_body_bytes() > MAX_JWKS_BYTES
            || fetcher.policy().deadline() > Duration::from_secs(30)
        {
            return Err(EnterpriseKeyFetchError::InvalidFetchPolicy);
        }
        if profile.idp_issuer().len() > MAX_ENTERPRISE_IDENTIFIER_BYTES {
            return Err(EnterpriseKeyFetchError::InvalidProfile);
        }
        let oidc_url = endpoint(profile.oidc_jwks_uri())?;
        let id_jag_url = endpoint(profile.id_jag_jwks_uri())?;
        Ok(Self { inner: Arc::new(KeySource {
            profile, oidc_url, id_jag_url, fetcher,
            policy_generation: fetch_policy_generation,
            busy: Arc::new(AtomicBool::new(false)),
            #[cfg(test)]
            test_exchange: None,
        }) })
    }

    /// Fetches both exact configured endpoints under the supplied caller.
    ///
    /// The native guarded fetcher owns public-address admission, validated TLS,
    /// response bounds and phase cancellation. No redirect is followed and no
    /// ambient credentials, cookies or proxies are used. Even coincident URLs
    /// are fetched separately for their independently configured purposes.
    /// Capacity remains charged until all guarded phase children have dropped,
    /// including when this future is cancelled or abandoned.
    pub async fn fetch(&self, cx: &Cx) -> Result<EnterpriseVerificationKeySet, EnterpriseKeyFetchError> {
        let admitted = crate::http_auth::caller::with_caller(cx, admit_caller)?;
        let permit = Arc::new(FetchPermit::acquire(Arc::clone(&self.inner.busy))?);
        CallerContextFuture::new(&admitted, async {
            let timeout = self.inner.fetcher.policy().deadline();
            let started = Instant::now();
            let nanos = u64::try_from(timeout.as_nanos())
                .map_err(|_| EnterpriseKeyFetchError::InvalidFetchPolicy)?;
            let deadline = admitted.now().saturating_add_nanos(nanos);
            let deadline = admitted.budget().deadline.map_or(deadline, |limit| limit.min(deadline));
            let mut timer = std::pin::pin!(Sleep::new(deadline));
            let (_sender, mut receiver) = oneshot::channel::<()>();
            let mut cancelled = std::pin::pin!(receiver.recv(&admitted));
            let mut pair = std::pin::pin!(async {
                let profile = &self.inner.profile;
                let response = self.exchange(&admitted, &self.inner.oidc_url, permit.clone()).await?;
                checkpoint(&admitted, deadline, started, timeout)?;
                admit_response(&response, &self.inner.oidc_url, &self.inner.fetcher)?;
                let oidc = OidcVerificationKeys::from_trusted_jwks(
                    profile.idp_issuer(), profile.oidc_key_generation(), &response.body,
                ).map_err(|_| EnterpriseKeyFetchError::InvalidKeys)?;
                let oidc_observation = EnterpriseJwksObservation {
                    endpoint: profile.oidc_jwks_uri().to_owned(),
                    key_generation: oidc.generation(), document_digest: oidc.document_digest(),
                    provenance: response.provenance,
                };
                checkpoint(&admitted, deadline, started, timeout)?;
                let response = self.exchange(&admitted, &self.inner.id_jag_url, permit.clone()).await?;
                checkpoint(&admitted, deadline, started, timeout)?;
                admit_response(&response, &self.inner.id_jag_url, &self.inner.fetcher)?;
                let id_jag = IdJagVerificationKeys::from_trusted_jwks(
                    profile.idp_issuer(), profile.id_jag_key_generation(), &response.body,
                ).map_err(|_| EnterpriseKeyFetchError::InvalidKeys)?;
                let id_jag_observation = EnterpriseJwksObservation {
                    endpoint: profile.id_jag_jwks_uri().to_owned(),
                    key_generation: id_jag.generation(), document_digest: id_jag.document_digest(),
                    provenance: response.provenance,
                };
                Ok(EnterpriseVerificationKeySet {
                    profile: profile.clone(), oidc, id_jag, oidc_observation, id_jag_observation,
                    fetch_policy: self.inner.fetcher.policy().clone(),
                    fetch_policy_generation: self.inner.policy_generation,
                })
            });
            poll_fn(|task| {
                checkpoint(&admitted, deadline, started, timeout)?;
                if cancelled.as_mut().poll(task).is_ready() {
                    return Poll::Ready(Err(EnterpriseKeyFetchError::Cancelled));
                }
                if timer.as_mut().poll(task).is_ready() {
                    checkpoint(&admitted, deadline, started, timeout)?;
                    return Poll::Ready(Err(EnterpriseKeyFetchError::TimedOut));
                }
                let result = pair.as_mut().poll(task);
                checkpoint(&admitted, deadline, started, timeout)?;
                result
            }).await
        }).await
    }

    async fn exchange(
        &self,
        cx: &Cx,
        url: &GuardedHttpsUrl,
        lifetime: Arc<dyn Send + Sync>,
    ) -> Result<GuardedHttpFetchResponse, EnterpriseKeyFetchError> {
        #[cfg(test)]
        if let Some(exchange) = &self.inner.test_exchange {
            return exchange.get(cx, url, lifetime).await.map_err(fetch_error);
        }
        Box::pin(self.inner.fetcher.fetch_with_lifetime(cx, url, lifetime))
            .await.map_err(fetch_error)
    }
}

impl fmt::Debug for EnterpriseKeySource {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.debug_struct("EnterpriseKeySource").finish_non_exhaustive()
    }
}

struct FetchPermit(Arc<AtomicBool>);
impl FetchPermit {
    fn acquire(busy: Arc<AtomicBool>) -> Result<Self, EnterpriseKeyFetchError> {
        busy.compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .map_err(|_| EnterpriseKeyFetchError::FetchInProgress)?;
        Ok(Self(busy))
    }
}
impl Drop for FetchPermit {
    fn drop(&mut self) { self.0.store(false, Ordering::Release); }
}

fn endpoint(value: &str) -> Result<GuardedHttpsUrl, EnterpriseKeyFetchError> {
    let parsed = CanonicalHttpUrl::parse(value)
        .map_err(|_| EnterpriseKeyFetchError::InvalidEndpoint)?;
    if parsed.scheme() != "https" || parsed.as_str() != value
        || parsed.has_syntax_violation() || parsed.has_userinfo() || parsed.fragment().is_some()
    {
        return Err(EnterpriseKeyFetchError::InvalidEndpoint);
    }
    GuardedHttpsUrl::parse(value).map_err(|_| EnterpriseKeyFetchError::InvalidEndpoint)
}

fn admit_caller() -> Result<Cx, EnterpriseKeyFetchError> {
    let current = Cx::current().ok_or(EnterpriseKeyFetchError::RuntimeUnavailable)?;
    if current.checkpoint().is_err() { return Err(EnterpriseKeyFetchError::Cancelled); }
    let caps = current.capabilities();
    if !caps.io || !caps.time || !caps.spawn || current.timer_driver().is_none() {
        return Err(EnterpriseKeyFetchError::RuntimeUnavailable);
    }
    if current.budget().deadline.is_some_and(|limit| current.now() >= limit) {
        return Err(EnterpriseKeyFetchError::TimedOut);
    }
    Ok(current)
}

fn checkpoint(
    admitted: &Cx,
    deadline: Time,
    started: Instant,
    timeout: Duration,
) -> Result<(), EnterpriseKeyFetchError> {
    let current = admit_caller()?;
    let held = admitted.capabilities();
    let active = current.capabilities();
    if (held.entropy && !active.entropy) || (held.remote && !active.remote) {
        return Err(EnterpriseKeyFetchError::RuntimeUnavailable);
    }
    if current.now() >= deadline || started.elapsed() >= timeout {
        return Err(EnterpriseKeyFetchError::TimedOut);
    }
    Ok(())
}

fn fetch_error(error: GuardedHttpFetchError) -> EnterpriseKeyFetchError {
    match error {
        GuardedHttpFetchError::Cancelled => EnterpriseKeyFetchError::Cancelled,
        GuardedHttpFetchError::DeadlineExceeded => EnterpriseKeyFetchError::TimedOut,
        _ => EnterpriseKeyFetchError::FetchFailed,
    }
}

fn admit_response(
    response: &GuardedHttpFetchResponse,
    url: &GuardedHttpsUrl,
    fetcher: &GuardedHttpFetcher,
) -> Result<(), EnterpriseKeyFetchError> {
    if response.status != 200 || response.redirect.is_some() || response.body.is_empty()
        || response.body.len() > fetcher.policy().response_body_bytes()
        || response.body.len() > MAX_JWKS_BYTES
    {
        return Err(EnterpriseKeyFetchError::InvalidResponse);
    }
    admit_headers(&response.headers)?;
    let peer = &response.provenance;
    if peer.host != url.host() || peer.selected_address.port() != url.port()
        || peer.root_policy_revision != fetcher.root_identity()
        || peer.alpn.as_deref().is_some_and(|alpn| alpn != b"http/1.1")
        || peer.tls_protocol.as_deref().is_some_and(|protocol| {
            protocol.is_empty() || protocol.len() > 64 || !protocol.is_ascii()
                || protocol.chars().any(char::is_control)
        })
    {
        return Err(EnterpriseKeyFetchError::EvidenceMismatch);
    }
    Ok(())
}

fn admit_headers(headers: &[(String, String)]) -> Result<(), EnterpriseKeyFetchError> {
    let invalid = EnterpriseKeyFetchError::InvalidResponse;
    if headers.len() > 64 { return Err(invalid); }
    let mut bytes = 0usize;
    let mut content_type = None;
    let mut content_encoding = false;
    for (name, value) in headers {
        bytes = bytes.checked_add(name.len()).and_then(|sum| sum.checked_add(value.len()))
            .and_then(|sum| sum.checked_add(4)).ok_or(invalid)?;
        if bytes > 16 * 1024 || name.is_empty()
            || !name.bytes().all(|byte| byte.is_ascii_alphanumeric() || matches!(byte,
                b'!' | b'#' | b'$' | b'%' | b'&' | b'\'' | b'*' | b'+' | b'-'
                | b'.' | b'^' | b'_' | 0x60 | b'|' | b'~'))
            || value.bytes().any(|byte| (byte < 0x20 && byte != b'\t') || byte == 0x7f)
        {
            return Err(invalid);
        }
        if name.eq_ignore_ascii_case("content-type") {
            if content_type.replace(value.as_str()).is_some() { return Err(invalid); }
        } else if name.eq_ignore_ascii_case("content-encoding") {
            if content_encoding || !value.trim_matches([' ', '\t']).eq_ignore_ascii_case("identity") {
                return Err(invalid);
            }
            content_encoding = true;
        }
    }
    let mut parts = content_type.ok_or(invalid)?.split(';').map(|part| part.trim_matches([' ', '\t']));
    if !parts.next().is_some_and(|kind| {
        kind.eq_ignore_ascii_case("application/json")
            || kind.eq_ignore_ascii_case("application/jwk-set+json")
    }) {
        return Err(invalid);
    }
    if let Some(parameter) = parts.next() {
        let (name, value) = parameter.split_once('=').ok_or(invalid)?;
        let value = value.trim_matches([' ', '\t']);
        if !name.trim_matches([' ', '\t']).eq_ignore_ascii_case("charset")
            || !(value.eq_ignore_ascii_case("utf-8") || value.eq_ignore_ascii_case("\"utf-8\""))
            || parts.next().is_some()
        {
            return Err(invalid);
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests;
