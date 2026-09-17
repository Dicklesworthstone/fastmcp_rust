//! AUTH-00 A: the lower ingress-authentication seam.
//!
//! `fastmcp-core` owns the bounded verified facts
//! ([`fastmcp_core::ingress::VerifiedIngressAuthentication`]). This module
//! owns the transport side of the seam: the non-escapable borrowed
//! [`AuthRequestView`] an authenticator reads, the public implementable
//! [`IngressAuthenticator`] trait, and the opaque
//! [`AuthenticatedTransportIngress`] that combines verified facts with
//! sanitized transport provenance.
//!
//! # Where the seal actually is
//!
//! Anyone can *construct* verified facts — a provider is the thing that
//! decides what verified means, so the fact type cannot police itself. The
//! enforcement is here instead: [`AuthenticatedTransportIngress`] has no
//! public constructor. It is minted only by [`authenticate_ingress`], which
//! calls a registered [`IngressAuthenticator`] and stamps the transport
//! provenance itself. Downstream code accepts only the opaque type, so facts
//! assembled by a caller are facts no entrypoint will take.
//!
//! # What an authenticator cannot do
//!
//! [`AuthRequestView`] borrows the request for the duration of the call and is
//! neither `Clone`, `Copy`, `Debug`, nor `'static`, so an authenticator cannot
//! retain it past its deadline, log it, or smuggle it into a background task.
//! The trait returns verified facts and an optional rotation record; it has no
//! way to return a raw credential, because no type it can return carries one.
//!
//! # No-claim boundary
//!
//! AUTH-00 defines only these types, their lifetime and redaction
//! constraints, and the conformance seam. AUTH-01 supplies concrete provider
//! implementations. This leaf proves neither partition admission nor lookup,
//! nor the AUTH-00 aggregate, nor any aggregate MCP capability.

use std::fmt;
use std::time::{Duration, Instant};

use asupersync::Cx;
use fastmcp_core::ingress::{AuthorizationRotationFacts, VerifiedIngressAuthentication};

/// Largest credential presentation an authenticator will be shown.
///
/// A credential larger than this is refused before any provider sees it, so an
/// oversized presentation cannot be used to drive unbounded work in a provider
/// that forgot to bound its own input.
pub const MAX_PRESENTED_CREDENTIAL_BYTES: usize = 64 * 1024;

/// Largest transport provenance string retained.
pub const MAX_PROVENANCE_BYTES: usize = 1024;

/// Why ingress authentication was refused.
///
/// Every variant is a *denial*. There is deliberately no variant carrying
/// provider detail, a credential excerpt, or a comparison result: an error
/// type that can describe why a credential failed is an oracle, and callers
/// would log it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IngressAuthenticationError {
    /// No credential was presented.
    CredentialAbsent,
    /// The presented credential exceeded [`MAX_PRESENTED_CREDENTIAL_BYTES`].
    CredentialTooLarge,
    /// Transport provenance exceeded [`MAX_PROVENANCE_BYTES`].
    ProvenanceTooLarge,
    /// The authenticator refused the presentation.
    NotAuthenticated,
    /// The caller's context was cancelled or its deadline elapsed.
    Cancelled,
    /// The authenticator did not finish within its finite deadline.
    DeadlineExceeded,
    /// No authenticator was registered for this ingress.
    NoAuthenticatorRegistered,
}

impl fmt::Display for IngressAuthenticationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::CredentialAbsent => "no credential was presented at ingress",
            Self::CredentialTooLarge => "presented credential exceeds the ingress bound",
            Self::ProvenanceTooLarge => "transport provenance exceeds the ingress bound",
            Self::NotAuthenticated => "ingress authentication was refused",
            Self::Cancelled => "ingress authentication was cancelled",
            Self::DeadlineExceeded => "ingress authentication exceeded its deadline",
            Self::NoAuthenticatorRegistered => "no ingress authenticator is registered",
        })
    }
}

impl std::error::Error for IngressAuthenticationError {}

/// A borrowed, non-escapable view of one request's authentication inputs.
///
/// Deliberately not `Clone`, `Copy`, `Debug`, `Serialize`, or `'static`. The
/// lifetime is the enforcement: an authenticator physically cannot retain the
/// presented credential past the call, because the only handle it has borrows
/// a buffer the caller still owns.
pub struct AuthRequestView<'request> {
    presented_credential: &'request [u8],
    scheme: &'request str,
    transport_provenance: &'request str,
    canonical_resource: &'request str,
}

impl<'request> AuthRequestView<'request> {
    /// Borrows one request's authentication inputs.
    ///
    /// # Errors
    ///
    /// Returns [`IngressAuthenticationError::CredentialAbsent`] for an empty
    /// presentation, [`IngressAuthenticationError::CredentialTooLarge`] above
    /// [`MAX_PRESENTED_CREDENTIAL_BYTES`], and
    /// [`IngressAuthenticationError::ProvenanceTooLarge`] above
    /// [`MAX_PROVENANCE_BYTES`]. Bounds are checked here, before any provider
    /// is invoked.
    pub fn new(
        presented_credential: &'request [u8],
        scheme: &'request str,
        transport_provenance: &'request str,
        canonical_resource: &'request str,
    ) -> Result<Self, IngressAuthenticationError> {
        if presented_credential.is_empty() {
            return Err(IngressAuthenticationError::CredentialAbsent);
        }
        if presented_credential.len() > MAX_PRESENTED_CREDENTIAL_BYTES {
            return Err(IngressAuthenticationError::CredentialTooLarge);
        }
        if transport_provenance.len() > MAX_PROVENANCE_BYTES {
            return Err(IngressAuthenticationError::ProvenanceTooLarge);
        }
        Ok(Self {
            presented_credential,
            scheme,
            transport_provenance,
            canonical_resource,
        })
    }

    /// The presented credential bytes.
    ///
    /// The borrow is the whole point: this is the only place a raw credential
    /// appears in AUTH-00, and it cannot outlive the authenticator call.
    #[must_use]
    pub const fn presented_credential(&self) -> &'request [u8] {
        self.presented_credential
    }

    /// The presentation scheme, for example `Bearer`.
    #[must_use]
    pub const fn scheme(&self) -> &'request str {
        self.scheme
    }

    /// Sanitized transport provenance.
    #[must_use]
    pub const fn transport_provenance(&self) -> &'request str {
        self.transport_provenance
    }

    /// The canonical resource this request targets.
    #[must_use]
    pub const fn canonical_resource(&self) -> &'request str {
        self.canonical_resource
    }
}

/// What an authenticator returns on success.
///
/// Carries verified facts and, when the authorization outlives ingress, the
/// rotation record. It cannot carry a credential: no field type has one.
pub struct VerifiedIngressOutcome {
    /// The verified identity.
    pub authentication: VerifiedIngressAuthentication,
    /// Rotation and revalidation facts, when the authorization outlives ingress.
    pub rotation: Option<AuthorizationRotationFacts>,
}

/// A provider-supplied ingress authenticator.
///
/// Implementations receive the caller's `&Cx` and a finite deadline, and must
/// not exceed it. They return verified facts, never a raw credential — the
/// return type makes that structural rather than advisory.
///
/// AUTH-01 supplies the concrete implementations. Neither HTTP transport nor
/// server code may define a second callback contract for this purpose.
pub trait IngressAuthenticator: Send + Sync + 'static {
    /// Authenticates one request within `deadline`.
    ///
    /// # Errors
    ///
    /// Returns [`IngressAuthenticationError::NotAuthenticated`] on refusal.
    /// Implementations must map their own cancellation and timeout onto
    /// [`IngressAuthenticationError::Cancelled`] and
    /// [`IngressAuthenticationError::DeadlineExceeded`] rather than blocking
    /// past the deadline.
    fn authenticate(
        &self,
        cx: &Cx,
        request: &AuthRequestView<'_>,
        deadline: Duration,
    ) -> Result<VerifiedIngressOutcome, IngressAuthenticationError>;
}

/// Verified-principal ingress, and the only way into it.
///
/// Opaque by construction: there is no public constructor, no `Clone`, no
/// `Serialize`, and a redacting `Debug`. The only way to obtain one is
/// [`authenticate_ingress`], which calls a registered [`IngressAuthenticator`]
/// and stamps the transport provenance itself rather than accepting a
/// caller's claim about it.
pub struct AuthenticatedTransportIngress {
    authentication: VerifiedIngressAuthentication,
    rotation: Option<AuthorizationRotationFacts>,
    transport_provenance: String,
    scheme: String,
}

impl AuthenticatedTransportIngress {
    /// The verified identity.
    #[must_use]
    pub const fn authentication(&self) -> &VerifiedIngressAuthentication {
        &self.authentication
    }

    /// Rotation and revalidation facts, when the authorization outlives ingress.
    #[must_use]
    pub fn rotation(&self) -> Option<&AuthorizationRotationFacts> {
        self.rotation.as_ref()
    }

    /// Sanitized transport provenance, stamped by the framework.
    #[must_use]
    pub fn transport_provenance(&self) -> &str {
        &self.transport_provenance
    }

    /// The presentation scheme this principal authenticated under.
    #[must_use]
    pub fn scheme(&self) -> &str {
        &self.scheme
    }
}

impl fmt::Debug for AuthenticatedTransportIngress {
    /// Shows the scheme and whether rotation facts are present; no identity.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AuthenticatedTransportIngress")
            .field("scheme", &self.scheme)
            .field("has_rotation_facts", &self.rotation.is_some())
            .finish_non_exhaustive()
    }
}

/// Runs registered ingress authentication and mints the opaque ingress value.
///
/// This is the seal. Facts a caller assembled themselves never reach
/// downstream code, because downstream code accepts only
/// [`AuthenticatedTransportIngress`] and this function is its only producer.
///
/// The caller's context and the supplied relative timeout are checked before
/// provider work and again before admitting its verdict. Only the remaining
/// timeout is passed to the provider. A successful verdict for a different
/// canonical resource is refused without exposing the mismatched identity.
///
/// This synchronous boundary cannot preempt a blocking provider. Providers
/// still have to enforce their own I/O deadlines; a late return is rejected,
/// not a guarantee that the provider itself stopped on time.
///
/// # Errors
///
/// Returns [`IngressAuthenticationError::NoAuthenticatorRegistered`] when
/// `authenticator` is `None`, [`IngressAuthenticationError::Cancelled`] when
/// the caller's context is cancelled, and
/// [`IngressAuthenticationError::DeadlineExceeded`] for an exhausted or
/// unrepresentable timeout. Resource mismatches return the same
/// [`IngressAuthenticationError::NotAuthenticated`] as provider refusals.
pub fn authenticate_ingress(
    cx: &Cx,
    authenticator: Option<&dyn IngressAuthenticator>,
    request: &AuthRequestView<'_>,
    deadline: Duration,
) -> Result<AuthenticatedTransportIngress, IngressAuthenticationError> {
    let started = Instant::now();
    let Some(authenticator) = authenticator else {
        return Err(IngressAuthenticationError::NoAuthenticatorRegistered);
    };
    // Fail closed before provider work: an already-cancelled request must not
    // spend an authentication round trip, and must never be admitted.
    if cx.checkpoint().is_err() {
        return Err(IngressAuthenticationError::Cancelled);
    }
    let expires_at = started
        .checked_add(deadline)
        .ok_or(IngressAuthenticationError::DeadlineExceeded)?;
    let remaining = expires_at.saturating_duration_since(Instant::now());
    if remaining.is_zero() {
        return Err(IngressAuthenticationError::DeadlineExceeded);
    }

    // Keep the result until local cancellation and timeout have been checked.
    // Neither a success nor a provider-specific failure can revive an attempt
    // whose owner or authentication budget expired during the call.
    let outcome = authenticator.authenticate(cx, request, remaining);
    if cx.checkpoint().is_err() {
        return Err(IngressAuthenticationError::Cancelled);
    }
    if Instant::now() >= expires_at {
        return Err(IngressAuthenticationError::DeadlineExceeded);
    }
    let outcome = outcome?;
    if outcome.authentication.canonical_resource() != request.canonical_resource() {
        return Err(IngressAuthenticationError::NotAuthenticated);
    }

    Ok(AuthenticatedTransportIngress {
        authentication: outcome.authentication,
        rotation: outcome.rotation,
        // Provenance and scheme are stamped from the framework's own view of
        // the request, never from anything the authenticator returned.
        transport_provenance: request.transport_provenance().to_owned(),
        scheme: request.scheme().to_owned(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use asupersync::runtime::reactor::create_reactor;
    use asupersync::runtime::{Runtime, RuntimeBuilder};
    use fastmcp_core::ingress::{VerifiedAudienceBinding, VerifiedIdentityFacts};

    const RESOURCE: &str = "https://resource.example/mcp";

    struct Provider {
        calls: AtomicUsize,
        resource: &'static str,
        delay: Duration,
        refuse: bool,
    }

    impl Provider {
        fn new(resource: &'static str, delay: Duration, refuse: bool) -> Self {
            Self {
                calls: AtomicUsize::new(0),
                resource,
                delay,
                refuse,
            }
        }
    }

    impl IngressAuthenticator for Provider {
        fn authenticate(
            &self,
            _cx: &Cx,
            _request: &AuthRequestView<'_>,
            deadline: Duration,
        ) -> Result<VerifiedIngressOutcome, IngressAuthenticationError> {
            self.calls.fetch_add(1, Ordering::Relaxed);
            assert!(!deadline.is_zero());
            std::thread::sleep(self.delay);
            if self.refuse {
                return Err(IngressAuthenticationError::NotAuthenticated);
            }
            let authentication = VerifiedIngressAuthentication::from_verified_provider_output(
                VerifiedIdentityFacts {
                    provider: "org.fastmcp.provider.ingress-test",
                    configuration_generation: 1,
                    issuer: "https://issuer.example/auth",
                    canonical_resource: self.resource,
                    verified_audience_binding: VerifiedAudienceBinding::OAuth {
                        canonical_resource: self.resource.to_owned(),
                        validated_audience: self.resource.to_owned(),
                        audience_policy_id: "strict".to_owned(),
                        audience_policy_revision: 1,
                        provider: "org.fastmcp.provider.ingress-test".to_owned(),
                        configuration_generation: 1,
                    },
                    tenant: "tenant",
                    subject_or_principal: "subject",
                    authorized_party_or_client: "client",
                    verified_claims: &[("scope", "mcp.read")],
                    auth_policy_revision: 1,
                    trust_generation: 1,
                },
            )
            .map_err(|_| IngressAuthenticationError::NotAuthenticated)?;
            Ok(VerifiedIngressOutcome {
                authentication,
                rotation: None,
            })
        }
    }

    fn runtime() -> Runtime {
        RuntimeBuilder::current_thread()
            .with_reactor(create_reactor().expect("platform reactor"))
            .blocking_threads(0, 2)
            .build()
            .expect("application-owned runtime")
    }

    fn run(
        provider: &Provider,
        timeout: Duration,
    ) -> Result<AuthenticatedTransportIngress, IngressAuthenticationError> {
        runtime().block_on(async {
            let cx = Cx::current().expect("runtime context");
            let request = AuthRequestView::new(b"secret", "Bearer", "tls", RESOURCE)?;
            authenticate_ingress(&cx, Some(provider), &request, timeout)
        })
    }

    #[test]
    fn zero_timeout_refuses_before_provider_work() {
        let provider = Provider::new(RESOURCE, Duration::ZERO, false);
        assert_eq!(
            run(&provider, Duration::ZERO).unwrap_err(),
            IngressAuthenticationError::DeadlineExceeded
        );
        assert_eq!(provider.calls.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn timely_matching_verdict_preserves_verified_ingress() {
        let provider = Provider::new(RESOURCE, Duration::ZERO, false);
        let ingress = run(&provider, Duration::from_secs(60)).expect("timely admission");
        assert_eq!(ingress.authentication().canonical_resource(), RESOURCE);
        assert_eq!(ingress.scheme(), "Bearer");
        assert_eq!(ingress.transport_provenance(), "tls");
        assert_eq!(provider.calls.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn late_success_cannot_mint_authenticated_ingress() {
        let provider = Provider::new(RESOURCE, Duration::from_millis(20), false);
        assert_eq!(
            run(&provider, Duration::from_millis(1)).unwrap_err(),
            IngressAuthenticationError::DeadlineExceeded
        );
    }

    #[test]
    fn late_provider_refusal_does_not_hide_deadline_exhaustion() {
        let provider = Provider::new(RESOURCE, Duration::from_millis(20), true);
        assert_eq!(
            run(&provider, Duration::from_millis(1)).unwrap_err(),
            IngressAuthenticationError::DeadlineExceeded
        );
    }

    #[test]
    fn timely_provider_refusal_is_preserved() {
        let provider = Provider::new(RESOURCE, Duration::ZERO, true);
        assert_eq!(
            run(&provider, Duration::from_secs(60)).unwrap_err(),
            IngressAuthenticationError::NotAuthenticated
        );
    }

    #[test]
    fn verdict_for_another_resource_is_not_admitted() {
        let provider = Provider::new("https://resource.example/other", Duration::ZERO, false);
        assert_eq!(
            run(&provider, Duration::from_secs(60)).unwrap_err(),
            IngressAuthenticationError::NotAuthenticated
        );
        assert_eq!(provider.calls.load(Ordering::Relaxed), 1);
    }
}
