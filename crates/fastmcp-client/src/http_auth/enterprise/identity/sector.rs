//! Guarded preregistration review of an OIDC pairwise sector document.
//!
//! The only public producer performs one credential-free guarded HTTPS GET.
//! A review freezes its complete registration, document bytes, exact final URL,
//! fetch policy and TLS observation. Consumers verify those bindings without
//! refetching. This evidence is not a deployment attestation or permission to
//! launch a browser, redeem an assertion or activate enterprise authorization.

use std::collections::BTreeSet;
use std::fmt;
use std::future::{Future, poll_fn};
use std::task::Poll;

use asupersync::Cx;
use fastmcp_core::{AbsoluteUri, CanonicalHttpUrl, Sha256Digest, crypto::sha256_bounded};
use fastmcp_core::runtime::CallerContextFuture;
use fastmcp_transport::{
    GuardedHttpFetchError, GuardedHttpFetchPolicy, GuardedHttpFetchResponse,
    GuardedHttpFetcher, GuardedHttpPeerProvenance, GuardedHttpsUrl,
};
use serde::de::{self, SeqAccess, Visitor};
use serde::{Deserialize, Deserializer};

use super::{
    EnterpriseIdentityError, EnterpriseOidcRelyingPartyConfiguration,
    EnterpriseOidcSubjectType, IdentityEncoding, MAX_REDIRECTS, MAX_TENANT_BYTES,
    MAX_URL_BYTES, OidcSubjectNamespace, admit_client_id, admit_issuer,
    admit_redirect, admit_text, encode_rp,
};

/// Hard response bound, including all additional document entries.
pub const MAX_OIDC_SECTOR_DOCUMENT_BYTES: usize = 64 * 1024;
/// Finite document cardinality; extra entries never grant callback authority.
pub const MAX_OIDC_SECTOR_DOCUMENT_REDIRECTS: usize = 128;

/// Registration roles remain distinct even when their literal inputs coincide.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OidcSectorRegistrationRole {
    Client,
    ResourceAuthorizationServer,
}

/// Fixed diagnostics retain no URL, document, tenant, client or peer text.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OidcSectorReviewError {
    InvalidRegistration,
    InvalidSectorUri,
    InvalidFetchPolicy,
    RuntimeUnavailable,
    Cancelled,
    TimedOut,
    FetchFailed,
    InvalidResponse,
    InvalidDocument,
    MissingRegisteredRedirect,
    EvidenceMismatch,
}

impl fmt::Display for OidcSectorReviewError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidRegistration => "invalid OIDC sector registration",
            Self::InvalidSectorUri => "invalid OIDC sector document URI",
            Self::InvalidFetchPolicy => "invalid OIDC sector fetch policy",
            Self::RuntimeUnavailable => "OIDC sector review requires caller I/O, time and spawn authority",
            Self::Cancelled => "OIDC sector review was cancelled",
            Self::TimedOut => "OIDC sector review exceeded its deadline",
            Self::FetchFailed => "OIDC sector guarded fetch failed",
            Self::InvalidResponse => "OIDC sector document response was refused",
            Self::InvalidDocument => "invalid OIDC sector document",
            Self::MissingRegisteredRedirect => "OIDC sector document omits a registered redirect",
            Self::EvidenceMismatch => "OIDC sector fetch evidence differs from its request",
        })
    }
}
impl std::error::Error for OidcSectorReviewError {}

/// Immutable evidence from one completed guarded sector-document review.
///
/// No constructor accepts caller-supplied bytes or peer provenance. The public
/// fetch producer admits a bounded HTTP 200 JSON array containing every exact
/// registered redirect. Additional valid entries affect the document digest
/// but never become registered callbacks. Cloning preserves the same review.
#[derive(Clone)]
pub struct OidcSectorDocumentReview {
    registration: EnterpriseOidcRelyingPartyConfiguration,
    role: OidcSectorRegistrationRole,
    registered_redirects: BTreeSet<String>,
    sector_identifier_uri: String,
    sector_host: String,
    document_digest: Sha256Digest,
    fetch_policy: GuardedHttpFetchPolicy,
    fetch_policy_generation: u64,
    provenance: GuardedHttpPeerProvenance,
    binding_digest: Sha256Digest,
}

impl OidcSectorDocumentReview {
    /// Fetches the exact preregistered HTTPS URI once under the caller's Cx.
    ///
    /// The supplied fetcher retains its production public-address fence, TLS
    /// validation and actual root identity. Redirects, ambient credentials,
    /// proxies and cookie persistence are absent from its one-shot GET path.
    /// Registration and bounds are admitted before resolver or socket effects.
    /// Resolver and transport children inherit the admitted caller ceiling.
    /// Resuming under a narrower ceiling terminates the review before another
    /// transport poll; cleanup retains the same restrictions.
    /// The nonzero policy generation is the operator's reviewed policy revision;
    /// concrete limits and observed TLS/root facts are also bound independently.
    pub async fn fetch(
        cx: &Cx,
        fetcher: &GuardedHttpFetcher,
        role: OidcSectorRegistrationRole,
        registration: &EnterpriseOidcRelyingPartyConfiguration,
        sector_identifier_uri: &str,
        fetch_policy_generation: u64,
    ) -> Result<Self, OidcSectorReviewError> {
        let prepared = PreparedSectorReview::new(
            role, registration, sector_identifier_uri,
            fetcher.policy(), fetch_policy_generation,
        )?;
        // Cx::spawn inherits its held Cx, so ambient poll restrictions alone
        // cannot constrain the guarded fetcher's resolver and transport children.
        let admitted_cx = crate::http_auth::caller::with_caller(cx, admit_caller)?;
        let response = CallerContextFuture::new(&admitted_cx, async {
            let mut fetch = std::pin::pin!(fetcher.fetch(&admitted_cx, &prepared.url));
            poll_fn(|task_cx| {
                if let Err(error) = review_checkpoint(&admitted_cx) {
                    return Poll::Ready(Err(error));
                }
                let result = fetch.as_mut().poll(task_cx);
                if let Err(error) = review_checkpoint(&admitted_cx) {
                    return Poll::Ready(Err(error));
                }
                result.map(|result| result.map_err(fetch_error))
            }).await
        }).await?;
        crate::http_auth::caller::with_caller(&admitted_cx, || {
            review_checkpoint(&admitted_cx)?;
            let review = prepared.admit_response(response)?;
            review_checkpoint(&admitted_cx)?;
            Ok(review)
        })
    }

    #[must_use]
    pub const fn role(&self) -> OidcSectorRegistrationRole { self.role }
    /// Exact requested and final URL; a redirect can never produce this review.
    #[must_use]
    pub fn sector_identifier_uri(&self) -> &str { &self.sector_identifier_uri }
    #[must_use]
    pub fn sector_host(&self) -> &str { &self.sector_host }
    /// Digest of the exact response bytes, including additional valid entries.
    #[must_use]
    pub const fn document_digest(&self) -> Sha256Digest { self.document_digest }
    /// Digest of registration, role, URL, document and concrete fetch evidence.
    #[must_use]
    pub const fn binding_digest(&self) -> Sha256Digest { self.binding_digest }
    #[must_use]
    pub const fn fetch_policy_generation(&self) -> u64 { self.fetch_policy_generation }
    #[must_use]
    pub fn fetch_policy(&self) -> &GuardedHttpFetchPolicy { &self.fetch_policy }
    #[must_use]
    pub fn provenance(&self) -> &GuardedHttpPeerProvenance { &self.provenance }

    pub(super) fn namespace_for(
        &self,
        registration: &EnterpriseOidcRelyingPartyConfiguration,
        role: OidcSectorRegistrationRole,
    ) -> Result<OidcSubjectNamespace, EnterpriseIdentityError> {
        let redirects = admit_registration(registration)
            .map_err(|_| EnterpriseIdentityError::RegistrationMismatch)?;
        if self.role != role || self.registration.issuer != registration.issuer
            || self.registration.tenant != registration.tenant
            || self.registration.client_id != registration.client_id
            || self.registration.registration_generation != registration.registration_generation
            || self.registered_redirects != redirects
        {
            return Err(EnterpriseIdentityError::RegistrationMismatch);
        }
        Ok(OidcSubjectNamespace {
            issuer: registration.issuer.clone(),
            subject_type: EnterpriseOidcSubjectType::Pairwise,
            sector_host: Some(self.sector_host.clone()),
            registration_generation: Some(registration.registration_generation),
            sector_review_digest: Some(self.binding_digest),
        })
    }
}

impl fmt::Debug for OidcSectorDocumentReview {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.debug_struct("OidcSectorDocumentReview").finish_non_exhaustive()
    }
}

struct PreparedSectorReview {
    registration: EnterpriseOidcRelyingPartyConfiguration,
    role: OidcSectorRegistrationRole,
    registered_redirects: BTreeSet<String>,
    sector_identifier_uri: String,
    url: GuardedHttpsUrl,
    policy: GuardedHttpFetchPolicy,
    policy_generation: u64,
}

impl PreparedSectorReview {
    fn new(
        role: OidcSectorRegistrationRole,
        registration: &EnterpriseOidcRelyingPartyConfiguration,
        sector_identifier_uri: &str,
        policy: &GuardedHttpFetchPolicy,
        policy_generation: u64,
    ) -> Result<Self, OidcSectorReviewError> {
        let registered_redirects = admit_registration(registration)?;
        if policy_generation == 0
            || policy.response_body_bytes() > MAX_OIDC_SECTOR_DOCUMENT_BYTES
        {
            return Err(OidcSectorReviewError::InvalidFetchPolicy);
        }
        let parsed = CanonicalHttpUrl::parse_with_max_bytes(
            sector_identifier_uri, MAX_URL_BYTES,
        ).map_err(|_| OidcSectorReviewError::InvalidSectorUri)?;
        if parsed.scheme() != "https" || parsed.as_str() != sector_identifier_uri
            || parsed.has_syntax_violation() || parsed.has_userinfo()
            || parsed.fragment().is_some()
        {
            return Err(OidcSectorReviewError::InvalidSectorUri);
        }
        let url = GuardedHttpsUrl::parse(sector_identifier_uri)
            .map_err(|_| OidcSectorReviewError::InvalidSectorUri)?;
        Ok(Self {
            registration: registration.clone(), role, registered_redirects,
            sector_identifier_uri: sector_identifier_uri.to_owned(), url,
            policy: policy.clone(), policy_generation,
        })
    }

    // Only the public guarded producer reaches this in shipped code. Unit tests
    // exercise this admission boundary with synthetic responses, not live proof.
    fn admit_response(
        self,
        response: GuardedHttpFetchResponse,
    ) -> Result<OidcSectorDocumentReview, OidcSectorReviewError> {
        if response.status != 200 || response.redirect.is_some()
            || response.body.is_empty()
            || response.body.len() > self.policy.response_body_bytes()
            || response.body.len() > MAX_OIDC_SECTOR_DOCUMENT_BYTES
        {
            return Err(OidcSectorReviewError::InvalidResponse);
        }
        admit_headers(&response.headers)?;
        let peer = &response.provenance;
        if peer.host != self.url.host()
            || peer.selected_address.port() != self.url.port()
            || peer.root_policy_revision != self.policy.root_policy_revision()
            || peer.alpn.as_deref().is_some_and(|alpn| alpn != b"http/1.1")
            || peer.tls_protocol.as_deref().is_some_and(|protocol| {
                protocol.is_empty() || protocol.len() > 64 || !protocol.is_ascii()
                    || protocol.chars().any(char::is_control)
            })
        {
            return Err(OidcSectorReviewError::EvidenceMismatch);
        }
        let document: SectorRedirects = serde_json::from_slice(&response.body)
            .map_err(|_| OidcSectorReviewError::InvalidDocument)?;
        if !self.registered_redirects.is_subset(&document.0) {
            return Err(OidcSectorReviewError::MissingRegisteredRedirect);
        }
        let document_digest = sha256_bounded(
            &response.body, MAX_OIDC_SECTOR_DOCUMENT_BYTES,
        ).map_err(|_| OidcSectorReviewError::InvalidDocument)?;
        let binding_digest = self.binding_digest(document_digest, peer)
            .map_err(|_| OidcSectorReviewError::InvalidDocument)?;
        Ok(OidcSectorDocumentReview {
            registration: self.registration, role: self.role,
            registered_redirects: self.registered_redirects,
            sector_identifier_uri: self.sector_identifier_uri,
            sector_host: self.url.host().to_owned(),
            document_digest, fetch_policy: self.policy,
            fetch_policy_generation: self.policy_generation,
            provenance: response.provenance, binding_digest,
        })
    }

    fn binding_digest(
        &self,
        document: Sha256Digest,
        peer: &GuardedHttpPeerProvenance,
    ) -> Result<Sha256Digest, EnterpriseIdentityError> {
        let mut encoded = IdentityEncoding::new(b"fastmcp-oidc-sector-review-v1");
        encoded.text(match self.role {
            OidcSectorRegistrationRole::Client => "client",
            OidcSectorRegistrationRole::ResourceAuthorizationServer => "resource-as",
        })?;
        encode_rp(&mut encoded, &self.registration)?;
        encoded.text(&self.sector_identifier_uri)?;
        encoded.text(self.url.host())?;
        encoded.field(document.as_bytes())?;
        encoded.number(self.policy_generation)?;
        encoded.number(self.policy.response_body_bytes() as u64)?;
        for duration in [self.policy.deadline(), self.policy.tls_handshake_timeout()] {
            encoded.number(duration.as_secs())?;
            encoded.number(u64::from(duration.subsec_nanos()))?;
        }
        encoded.text(self.policy.root_policy_revision())?;
        encoded.text(&peer.host)?;
        encoded.text(&peer.selected_address.to_string())?;
        encoded.field(&peer.leaf_certificate_sha256)?;
        encoded.field(&[u8::from(peer.alpn.is_some())])?;
        if let Some(alpn) = &peer.alpn { encoded.field(alpn)?; }
        encoded.optional(peer.tls_protocol.as_deref())?;
        encoded.finish()
    }
}

fn admit_registration(
    registration: &EnterpriseOidcRelyingPartyConfiguration,
) -> Result<BTreeSet<String>, OidcSectorReviewError> {
    if registration.subject_type != EnterpriseOidcSubjectType::Pairwise
        || registration.registration_generation == 0
        || registration.redirect_uris.is_empty()
        || registration.redirect_uris.len() > MAX_REDIRECTS
    {
        return Err(OidcSectorReviewError::InvalidRegistration);
    }
    admit_issuer(&registration.issuer)
        .and_then(|()| admit_client_id(&registration.client_id))
        .map_err(|_| OidcSectorReviewError::InvalidRegistration)?;
    if let Some(tenant) = &registration.tenant {
        admit_text(tenant, MAX_TENANT_BYTES)
            .map_err(|_| OidcSectorReviewError::InvalidRegistration)?;
    }
    let mut redirects = BTreeSet::new();
    for redirect in &registration.redirect_uris {
        admit_redirect(redirect).map_err(|_| OidcSectorReviewError::InvalidRegistration)?;
        if !redirects.insert(redirect.clone()) {
            return Err(OidcSectorReviewError::InvalidRegistration);
        }
    }
    Ok(redirects)
}

fn admit_caller() -> Result<Cx, OidcSectorReviewError> {
    let active = Cx::current().ok_or(OidcSectorReviewError::RuntimeUnavailable)?;
    if active.checkpoint().is_err() { return Err(OidcSectorReviewError::Cancelled); }
    let capabilities = active.capabilities();
    if !capabilities.io || !capabilities.time || !capabilities.spawn {
        return Err(OidcSectorReviewError::RuntimeUnavailable);
    }
    if active.budget().deadline.is_some_and(|deadline| active.now() >= deadline) {
        return Err(OidcSectorReviewError::TimedOut);
    }
    Ok(active)
}

fn review_checkpoint(admitted: &Cx) -> Result<(), OidcSectorReviewError> {
    let current = admit_caller()?.capabilities();
    let held = admitted.capabilities();
    // Existing transport children retain the admitted Cx. A later narrower
    // host must stop this review, not start another child with older authority.
    // The three required effects are checked by admit_caller above.
    if (held.entropy && !current.entropy) || (held.remote && !current.remote) {
        return Err(OidcSectorReviewError::RuntimeUnavailable);
    }
    Ok(())
}

fn fetch_error(error: GuardedHttpFetchError) -> OidcSectorReviewError {
    match error {
        GuardedHttpFetchError::Cancelled => OidcSectorReviewError::Cancelled,
        GuardedHttpFetchError::DeadlineExceeded => OidcSectorReviewError::TimedOut,
        _ => OidcSectorReviewError::FetchFailed,
    }
}

fn admit_headers(headers: &[(String, String)]) -> Result<(), OidcSectorReviewError> {
    let mut content_type = None;
    let mut content_encoding = false;
    for (name, value) in headers {
        if name.eq_ignore_ascii_case("content-type") {
            if content_type.replace(value.as_str()).is_some() {
                return Err(OidcSectorReviewError::InvalidResponse);
            }
        } else if name.eq_ignore_ascii_case("content-encoding") {
            if content_encoding || !value.trim().eq_ignore_ascii_case("identity") {
                return Err(OidcSectorReviewError::InvalidResponse);
            }
            content_encoding = true;
        }
    }
    let mut parts = content_type.ok_or(OidcSectorReviewError::InvalidResponse)?
        .split(';').map(str::trim);
    if !parts.next().is_some_and(|kind| kind.eq_ignore_ascii_case("application/json")) {
        return Err(OidcSectorReviewError::InvalidResponse);
    }
    if let Some(parameter) = parts.next() {
        let (name, value) = parameter.split_once('=')
            .ok_or(OidcSectorReviewError::InvalidResponse)?;
        if !name.trim().eq_ignore_ascii_case("charset")
            || !(value.trim().eq_ignore_ascii_case("utf-8")
                || value.trim().eq_ignore_ascii_case("\"utf-8\""))
            || parts.next().is_some()
        {
            return Err(OidcSectorReviewError::InvalidResponse);
        }
    }
    Ok(())
}

struct SectorRedirects(BTreeSet<String>);
impl<'de> Deserialize<'de> for SectorRedirects {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct RedirectVisitor;
        impl<'de> Visitor<'de> for RedirectVisitor {
            type Value = SectorRedirects;
            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("a bounded array of unique absolute redirect URIs")
            }
            fn visit_seq<A: SeqAccess<'de>>(self, mut sequence: A) -> Result<Self::Value, A::Error> {
                let mut redirects = BTreeSet::new();
                while let Some(redirect) = sequence.next_element::<String>()? {
                    if redirects.len() >= MAX_OIDC_SECTOR_DOCUMENT_REDIRECTS
                        || redirect.len() > MAX_URL_BYTES
                    {
                        return Err(de::Error::custom("sector document bound"));
                    }
                    let uri = AbsoluteUri::parse(&redirect)
                        .map_err(|_| de::Error::custom("invalid sector redirect"))?;
                    if uri.fragment().is_some() || !redirects.insert(redirect) {
                        return Err(de::Error::custom("ambiguous sector redirect"));
                    }
                }
                if redirects.is_empty() {
                    return Err(de::Error::custom("empty sector document"));
                }
                Ok(SectorRedirects(redirects))
            }
        }
        deserializer.deserialize_seq(RedirectVisitor)
    }
}

#[cfg(test)]
pub(crate) mod tests;
