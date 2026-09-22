//! LEG-NEG-01 B — the HTTP `Auto` fallback coordinator.
//!
//! This module owns exactly one decision: given a typed observation of the one
//! modern HTTP discovery probe, may the client open a single legacy SSE `GET`
//! against its configured endpoint, and does the first event on that stream
//! actually select the exact-2024 era?
//!
//! It deliberately does **not** classify probe responses. `ClientHttpNegotiation`
//! (HTTP-03 / CLT-02) remains the sole observation producer, and this
//! coordinator consumes its [`ClientHttpNegotiationDecision`] rather than
//! restating the eligibility table. The dependency runs one way, `leg_neg` →
//! `negotiation`, so the classifier never learns that a coordinator exists.
//!
//! The eligibility matrix this coordinator enforces, under
//! [`ProtocolPolicy::Auto`] only:
//!
//! | status | `Empty` | `Unrecognized` | `RecognizedModernJsonRpc` |
//! |--------|---------|----------------|---------------------------|
//! | 400    | one GET | one GET        | no GET                    |
//! | 404    | one GET | one GET        | no GET                    |
//! | 405    | one GET | one GET        | no GET                    |
//!
//! Six rows authorize exactly one `GET`; the three recognized-modern rows
//! forbid it at every status, because a recognized modern JSON-RPC body — result
//! or error — is proof the peer speaks the modern era and must never be read as
//! a downgrade signal. Every other status/body combination is ineligible.
//!
//! Authorization is not selection. A permitted `GET` still selects nothing: only
//! the first valid `endpoint` event admitted from that stream moves the era to
//! [`ProtocolEra::Legacy2024`]. Missing, malformed, duplicate, late, or
//! wrong-target events are refused with a typed error and leave every observable
//! field untouched.

use fastmcp_protocol::protocol_policy::{
    HttpEndpointBundleKey, HttpModernProbe, HttpProbeBody, ProtocolEra, ProtocolPolicy,
};
use std::sync::Arc;

use crate::negotiation::{
    ClientHttpNegotiation, ClientHttpNegotiationDecision, ClientHttpNegotiationError,
};
use crate::session::ClientProtocolPlan;

/// Typed refusal from the HTTP fallback coordinator.
///
/// Every variant is reached before any effect: no legacy `GET` is opened, no
/// credential is acquired or mutated, no era or discovery cache entry is
/// written, and no era is selected.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HttpFallbackError {
    /// Only `Auto` may coordinate a fallback. `ModernOnly` has nothing to fall
    /// back to and `LegacyOnly` never probes the modern era first.
    PolicyForbidsFallback {
        /// The immutable policy that refused.
        policy: ProtocolPolicy,
    },
    /// The plan carried no configured HTTP endpoint bundle.
    MissingHttpEndpointBundle,
    /// The plan carried no configured modern POST target.
    MissingModernPostTarget,
    /// The plan carried no configured legacy SSE GET target.
    MissingLegacySseTarget,
    /// The classifier refused to start an attempt for this plan.
    Negotiation(ClientHttpNegotiationError),
    /// An observation must name a nonempty modern target and a nonzero attempt.
    InvalidObservation,
    /// The observation or GET permit belongs to a different endpoint bundle or
    /// coordinator instance.
    ///
    /// Bundle identity covers the complete canonical targets, the credential and
    /// security partitions, the transport profile, and the policy/configuration
    /// generations. Permits additionally bind their exact issuing coordinator:
    /// two attempts with identical configuration and IDs cannot exchange them.
    CrossBundleObservation,
    /// The observation names a different modern POST target than the plan.
    ModernTargetMismatch,
    /// This coordinator already settled a different attempt's observation.
    ObservationAlreadyAdmitted {
        /// The attempt that was admitted first.
        admitted_attempt: u64,
    },
    /// The same attempt's observation was replayed after it settled.
    ReplayedObservation {
        /// The attempt identity that was replayed.
        attempt_id: u64,
    },
    /// The status/body row cannot authorize a legacy `GET`.
    IneligibleObservation {
        /// The observed HTTP status.
        status: u16,
        /// The observed body classification.
        body: HttpProbeBody,
    },
    /// This coordinator has not authorized a legacy GET. In particular, a
    /// recognized modern response must never be bypassed by a foreign permit.
    LegacyGetNotAuthorized,
    /// The single authorized `GET` was already opened.
    LegacyGetAlreadyOpened,
    /// An `endpoint` event arrived without an authorized, opened `GET`.
    EndpointEventWithoutAuthorization,
    /// The `endpoint` event carried no usable target.
    EndpointEventMalformed,
    /// The advertised endpoint is not the configured legacy target.
    EndpointEventTargetMismatch,
    /// A second `endpoint` event arrived after the era was already selected.
    DuplicateEndpointEvent,
}

impl std::fmt::Display for HttpFallbackError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::PolicyForbidsFallback { policy } => {
                write!(formatter, "{policy:?} cannot coordinate an HTTP fallback")
            }
            Self::MissingHttpEndpointBundle => {
                formatter.write_str("the plan has no configured HTTP endpoint bundle")
            }
            Self::MissingModernPostTarget => {
                formatter.write_str("the plan has no configured modern POST target")
            }
            Self::MissingLegacySseTarget => {
                formatter.write_str("the plan has no configured legacy SSE GET target")
            }
            Self::Negotiation(error) => write!(formatter, "probe classification refused: {error}"),
            Self::InvalidObservation => {
                formatter.write_str("an observation needs a nonempty target and nonzero attempt")
            }
            Self::CrossBundleObservation => {
                formatter.write_str("the observation or permit belongs to another coordinator")
            }
            Self::ModernTargetMismatch => {
                formatter.write_str("the observation names another modern POST target")
            }
            Self::ObservationAlreadyAdmitted { admitted_attempt } => write!(
                formatter,
                "attempt {admitted_attempt} was already admitted by this coordinator"
            ),
            Self::ReplayedObservation { attempt_id } => {
                write!(formatter, "attempt {attempt_id} was replayed after settling")
            }
            Self::IneligibleObservation { status, body } => write!(
                formatter,
                "status {status} with {body:?} cannot authorize a legacy GET"
            ),
            Self::LegacyGetNotAuthorized => {
                formatter.write_str("this coordinator has not authorized a legacy GET")
            }
            Self::LegacyGetAlreadyOpened => {
                formatter.write_str("the one authorized legacy GET was already opened")
            }
            Self::EndpointEventWithoutAuthorization => {
                formatter.write_str("an endpoint event requires an opened authorized GET")
            }
            Self::EndpointEventMalformed => {
                formatter.write_str("the endpoint event carried no usable target")
            }
            Self::EndpointEventTargetMismatch => {
                formatter.write_str("the advertised endpoint is not the configured legacy target")
            }
            Self::DuplicateEndpointEvent => {
                formatter.write_str("the era was already selected by an earlier endpoint event")
            }
        }
    }
}

impl std::error::Error for HttpFallbackError {}

/// One typed observation of the single modern HTTP discovery probe.
///
/// The observation is bound to the exact attempt that produced it: the complete
/// endpoint bundle key, the exact configured modern target, and a caller-owned
/// nonzero attempt identity. A coordinator refuses any observation whose binding
/// does not match, which is what makes a stale, cross-bundle, or replayed
/// observation inert rather than merely unlikely.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ModernProbeObservation {
    bundle_key: HttpEndpointBundleKey,
    modern_target: String,
    attempt_id: u64,
    probe: HttpModernProbe,
}

impl ModernProbeObservation {
    /// Binds one probe observation to the attempt that produced it.
    pub fn new(
        bundle_key: HttpEndpointBundleKey,
        modern_target: impl Into<String>,
        attempt_id: u64,
        probe: HttpModernProbe,
    ) -> Result<Self, HttpFallbackError> {
        let modern_target = modern_target.into();
        if modern_target.is_empty() || attempt_id == 0 {
            return Err(HttpFallbackError::InvalidObservation);
        }
        Ok(Self {
            bundle_key,
            modern_target,
            attempt_id,
            probe,
        })
    }

    /// Returns the endpoint bundle identity this observation is bound to.
    #[must_use]
    pub const fn bundle_key(&self) -> &HttpEndpointBundleKey {
        &self.bundle_key
    }

    /// Returns the exact configured modern POST target.
    #[must_use]
    pub fn modern_target(&self) -> &str {
        &self.modern_target
    }

    /// Returns the caller-owned attempt identity.
    #[must_use]
    pub const fn attempt_id(&self) -> u64 {
        self.attempt_id
    }

    /// Returns the observed probe status and body classification.
    #[must_use]
    pub const fn probe(&self) -> HttpModernProbe {
        self.probe
    }
}

/// Single-use authorization for exactly one legacy SSE `GET`.
///
/// The type is deliberately neither `Clone` nor `Copy`, and
/// [`HttpFallbackCoordinator::open_legacy_get`] consumes it by value, so a
/// second `GET` cannot be opened from one authorization even by mistake.
/// Holding a permit is not an era selection and never mutates coordinator state.
/// Its private allocation identity binds it to its exact issuing coordinator,
/// even when another coordinator uses the same endpoint bundle and attempt ID.
#[derive(Debug)]
pub struct LegacyGetPermit {
    target: String,
    attempt_id: u64,
    owner: Arc<()>,
}

impl PartialEq for LegacyGetPermit {
    fn eq(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.owner, &other.owner)
            && self.target == other.target
            && self.attempt_id == other.attempt_id
    }
}

impl Eq for LegacyGetPermit {}

impl LegacyGetPermit {
    /// Returns the configured legacy SSE target this permit authorizes.
    #[must_use]
    pub fn target(&self) -> &str {
        &self.target
    }

    /// Returns the attempt identity that earned this authorization.
    #[must_use]
    pub const fn attempt_id(&self) -> u64 {
        self.attempt_id
    }
}

/// The coordinator's decision for one admitted observation.
#[derive(Debug, PartialEq, Eq)]
pub enum FallbackDecision {
    /// No legacy `GET` is permitted; the modern observation stands.
    ModernRetained,
    /// Exactly one legacy SSE `GET` is authorized.
    LegacyGetAuthorized(LegacyGetPermit),
}

/// Every externally observable field of one coordinator.
///
/// Tests compare this value before and after a refused path to prove that an
/// ineligible or invalid input changed nothing. `credential_mutations` and
/// `era_cache_mutations` are carried explicitly and are always zero: this
/// coordinator has no authority to acquire a credential or write an era cache
/// entry, and recording that as an observable rather than an assumption is what
/// lets the negative tests assert it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct FallbackState {
    /// Observations admitted by this coordinator, at most one.
    pub observations_admitted: usize,
    /// Legacy `GET` authorizations issued, at most one.
    pub legacy_gets_authorized: usize,
    /// Legacy `GET`s actually opened, at most one.
    pub legacy_gets_opened: usize,
    /// `endpoint` events admitted, at most one.
    pub endpoint_events_admitted: usize,
    /// The era selected, only ever by a valid first `endpoint` event.
    pub selected_era: Option<ProtocolEra>,
    /// Credential acquisitions or mutations performed. Always zero.
    pub credential_mutations: usize,
    /// Era or discovery cache entries written. Always zero.
    pub era_cache_mutations: usize,
}

/// The sole HTTP `Auto` fallback coordinator.
///
/// One coordinator serves one connection attempt: it admits at most one
/// observation, issues at most one `GET` authorization, and admits at most one
/// `endpoint` event.
#[derive(Debug)]
pub struct HttpFallbackCoordinator {
    plan: ClientProtocolPlan,
    bundle_key: HttpEndpointBundleKey,
    modern_target: String,
    legacy_sse_target: String,
    state: FallbackState,
    settled_attempt: Option<u64>,
    permit_owner: Arc<()>,
}

impl HttpFallbackCoordinator {
    /// Starts one coordinator from an immutable `Auto` HTTP plan.
    ///
    /// This is a side-effect-free admission boundary: it opens no socket and
    /// acquires no credential.
    pub fn new(plan: ClientProtocolPlan) -> Result<Self, HttpFallbackError> {
        let policy = plan.policy();
        if !matches!(policy, ProtocolPolicy::Auto) {
            return Err(HttpFallbackError::PolicyForbidsFallback { policy });
        }
        let bundle_key = plan
            .http_endpoints()
            .ok_or(HttpFallbackError::MissingHttpEndpointBundle)?
            .key();
        let modern_target = plan
            .modern_post_target()
            .ok_or(HttpFallbackError::MissingModernPostTarget)?
            .to_owned();
        let legacy_sse_target = plan
            .legacy_sse_target()
            .ok_or(HttpFallbackError::MissingLegacySseTarget)?
            .to_owned();
        // Prove the classifier will accept this plan now, so a later refusal
        // cannot be mistaken for an eligibility outcome.
        ClientHttpNegotiation::from_protocol_plan(&plan).map_err(HttpFallbackError::Negotiation)?;
        Ok(Self {
            plan,
            bundle_key,
            modern_target,
            legacy_sse_target,
            state: FallbackState::default(),
            settled_attempt: None,
            permit_owner: Arc::new(()),
        })
    }

    /// Returns every externally observable field.
    #[must_use]
    pub const fn state(&self) -> FallbackState {
        self.state
    }

    /// Returns the era selected so far, if any.
    #[must_use]
    pub const fn selected_era(&self) -> Option<ProtocolEra> {
        self.state.selected_era
    }

    /// Returns the exact configured legacy SSE target.
    #[must_use]
    pub fn legacy_sse_target(&self) -> &str {
        &self.legacy_sse_target
    }

    /// Returns the endpoint bundle identity this coordinator is bound to.
    #[must_use]
    pub const fn bundle_key(&self) -> &HttpEndpointBundleKey {
        &self.bundle_key
    }

    /// Classifies one probe through the shipped observation producer.
    ///
    /// A fresh attempt is used for every call so that a refused classification
    /// leaves no retained state anywhere — neither here nor in the classifier.
    /// This is also why the eligibility table is not restated in this module.
    fn classify(
        &self,
        probe: HttpModernProbe,
    ) -> Result<ClientHttpNegotiationDecision, ClientHttpNegotiationError> {
        let mut negotiation = ClientHttpNegotiation::from_protocol_plan(&self.plan)?;
        negotiation.observe_modern_probe(probe)
    }

    /// Admits one typed probe observation and applies the eligibility matrix.
    ///
    /// Binding is checked before classification, so an observation from another
    /// bundle, another modern target, or a settled attempt is inert.
    pub fn observe(
        &mut self,
        observation: &ModernProbeObservation,
    ) -> Result<FallbackDecision, HttpFallbackError> {
        if observation.bundle_key != self.bundle_key {
            return Err(HttpFallbackError::CrossBundleObservation);
        }
        if observation.modern_target != self.modern_target {
            return Err(HttpFallbackError::ModernTargetMismatch);
        }
        if let Some(settled) = self.settled_attempt {
            return Err(if settled == observation.attempt_id {
                HttpFallbackError::ReplayedObservation {
                    attempt_id: settled,
                }
            } else {
                HttpFallbackError::ObservationAlreadyAdmitted {
                    admitted_attempt: settled,
                }
            });
        }

        let probe = observation.probe;
        let decision =
            self.classify(probe)
                .map_err(|_| HttpFallbackError::IneligibleObservation {
                    status: probe.status,
                    body: probe.body,
                })?;

        // Only a settled decision mutates this coordinator.
        self.settled_attempt = Some(observation.attempt_id);
        self.state.observations_admitted += 1;
        match decision {
            // A recognized modern JSON-RPC body — result or error — is proof of
            // the modern era at every eligible status, so it forbids the GET.
            ClientHttpNegotiationDecision::ModernSelected => Ok(FallbackDecision::ModernRetained),
            ClientHttpNegotiationDecision::LegacySseFallbackAuthorized => {
                self.state.legacy_gets_authorized += 1;
                Ok(FallbackDecision::LegacyGetAuthorized(LegacyGetPermit {
                    target: self.legacy_sse_target.clone(),
                    attempt_id: observation.attempt_id,
                    owner: Arc::clone(&self.permit_owner),
                }))
            }
        }
    }

    /// Consumes the single authorization and opens the one permitted `GET`.
    ///
    /// Returns the exact configured target the caller must request. Opening a
    /// `GET` is still not an era selection. A matching attempt number alone is
    /// not authority: the permit must have been issued by this coordinator.
    pub fn open_legacy_get(
        &mut self,
        permit: LegacyGetPermit,
    ) -> Result<String, HttpFallbackError> {
        if self.state.legacy_gets_opened > 0 {
            return Err(HttpFallbackError::LegacyGetAlreadyOpened);
        }
        if self.state.legacy_gets_authorized != 1 {
            return Err(HttpFallbackError::LegacyGetNotAuthorized);
        }
        if !Arc::ptr_eq(&self.permit_owner, &permit.owner)
            || Some(permit.attempt_id) != self.settled_attempt
            || permit.target != self.legacy_sse_target
        {
            return Err(HttpFallbackError::CrossBundleObservation);
        }
        self.state.legacy_gets_opened += 1;
        Ok(self.legacy_sse_target.clone())
    }

    /// Admits the first valid `endpoint` event from the opened `GET`.
    ///
    /// Only this call may select [`ProtocolEra::Legacy2024`]. The advertised
    /// target must be the configured one, byte for byte, or the configured
    /// query-free target extended with a server-generated query — the exact-2024
    /// lane advertises a session query no client can preconfigure, and scheme,
    /// authority, and path can never change.
    pub fn admit_endpoint_event(
        &mut self,
        advertised: &str,
    ) -> Result<ProtocolEra, HttpFallbackError> {
        if self.state.legacy_gets_opened == 0 {
            return Err(HttpFallbackError::EndpointEventWithoutAuthorization);
        }
        if self.state.endpoint_events_admitted > 0 {
            return Err(HttpFallbackError::DuplicateEndpointEvent);
        }
        let advertised = advertised.trim();
        if advertised.is_empty() {
            return Err(HttpFallbackError::EndpointEventMalformed);
        }
        if !advertised_target_is_admissible(&self.legacy_sse_target, advertised) {
            return Err(HttpFallbackError::EndpointEventTargetMismatch);
        }
        self.state.endpoint_events_admitted += 1;
        self.state.selected_era = Some(ProtocolEra::Legacy2024);
        Ok(ProtocolEra::Legacy2024)
    }
}

/// Admits an advertised legacy endpoint against the immutable configured one.
///
/// Byte equality always admits. A configured target with no query component may
/// additionally be extended by a server-generated query, because the exact
/// 2024-11-05 lane advertises a session query that no client can preconfigure.
/// Scheme, authority, and path never change, so the admitted resource, era,
/// authorization, and cache partition stay pinned to the configured bundle.
fn advertised_target_is_admissible(configured: &str, advertised: &str) -> bool {
    if advertised == configured {
        return true;
    }
    match advertised.split_once('?') {
        Some((base, query)) => !query.is_empty() && base == configured && !configured.contains('?'),
        None => false,
    }
}

#[cfg(all(test, feature = "legacy-2024-11-05"))]
mod permit_tests {
    use super::*;
    use crate::CanonicalHttpUrl;

    const MODERN: &str = "https://mcp.example.test/mcp";
    const SSE: &str = "https://mcp.example.test/sse";

    fn coordinator(security_partition: &str) -> HttpFallbackCoordinator {
        let parse = |value: &str| CanonicalHttpUrl::parse(value).expect("canonical fixture URL");
        let plan = ClientProtocolPlan::http(
            ProtocolPolicy::Auto,
            Some(parse(MODERN)),
            Some(parse(SSE)),
            Some(parse("https://mcp.example.test/messages")),
            "credential-partition".to_owned(),
            security_partition.to_owned(),
            "native-h1".to_owned(),
            1,
            1,
            0,
        )
        .expect("valid dual-era plan");
        HttpFallbackCoordinator::new(plan).expect("Auto coordinator")
    }

    fn observe(
        coordinator: &mut HttpFallbackCoordinator,
        body: HttpProbeBody,
    ) -> FallbackDecision {
        let observation = ModernProbeObservation::new(
            coordinator.bundle_key().clone(),
            MODERN,
            1,
            HttpModernProbe { status: 404, body },
        )
        .expect("bound observation");
        coordinator.observe(&observation).expect("eligible observation")
    }

    fn authorize(coordinator: &mut HttpFallbackCoordinator) -> LegacyGetPermit {
        let FallbackDecision::LegacyGetAuthorized(permit) =
            observe(coordinator, HttpProbeBody::Unrecognized)
        else {
            panic!("404 with an unrecognized body must authorize the candidate GET");
        };
        permit
    }

    #[test]
    fn locally_issued_permit_opens_only_its_own_get() {
        let mut owner = coordinator("owner");
        let permit = authorize(&mut owner);
        assert_eq!(permit.target(), SSE);
        assert_eq!(permit.attempt_id(), 1);
        assert_eq!(owner.open_legacy_get(permit).unwrap(), SSE);
        assert_eq!(owner.state().legacy_gets_authorized, 1);
        assert_eq!(owner.state().legacy_gets_opened, 1);
        assert_eq!(owner.selected_era(), None);
    }

    #[test]
    fn same_bundle_and_attempt_cannot_exchange_permits() {
        let mut owner = coordinator("same-partition");
        let mut other = coordinator("same-partition");
        let owner_permit = authorize(&mut owner);
        let other_permit = authorize(&mut other);
        assert_ne!(owner_permit, other_permit);
        let before = owner.state();
        assert_eq!(
            owner.open_legacy_get(other_permit),
            Err(HttpFallbackError::CrossBundleObservation)
        );
        assert_eq!(owner.state(), before);
        // Rejecting foreign authority must not consume the local authorization.
        assert_eq!(owner.open_legacy_get(owner_permit).unwrap(), SSE);
    }

    #[test]
    fn foreign_permit_cannot_override_a_recognized_modern_response() {
        let mut modern = coordinator("same-partition");
        let mut legacy = coordinator("same-partition");
        let foreign_permit = authorize(&mut legacy);
        assert_eq!(
            observe(&mut modern, HttpProbeBody::RecognizedModernJsonRpc),
            FallbackDecision::ModernRetained
        );
        let before = modern.state();
        assert_eq!(
            modern.open_legacy_get(foreign_permit),
            Err(HttpFallbackError::LegacyGetNotAuthorized)
        );
        assert_eq!(modern.state(), before);
        assert_eq!(modern.state().legacy_gets_authorized, 0);
        assert_eq!(modern.state().legacy_gets_opened, 0);
    }

    #[test]
    fn same_target_and_attempt_cannot_cross_security_partitions() {
        let mut owner = coordinator("principal-a");
        let mut other = coordinator("principal-b");
        let owner_permit = authorize(&mut owner);
        let other_permit = authorize(&mut other);
        let before = owner.state();
        assert_eq!(
            owner.open_legacy_get(other_permit),
            Err(HttpFallbackError::CrossBundleObservation)
        );
        assert_eq!(owner.state(), before);
        assert_eq!(owner.open_legacy_get(owner_permit).unwrap(), SSE);
    }

    #[test]
    fn retired_coordinator_permit_cannot_authorize_a_replacement_attempt() {
        let stale_permit = {
            let mut retired = coordinator("same-partition");
            authorize(&mut retired)
        };
        let mut replacement = coordinator("same-partition");
        let fresh_permit = authorize(&mut replacement);
        let before = replacement.state();
        assert_eq!(
            replacement.open_legacy_get(stale_permit),
            Err(HttpFallbackError::CrossBundleObservation)
        );
        assert_eq!(replacement.state(), before);
        assert_eq!(replacement.open_legacy_get(fresh_permit).unwrap(), SSE);
    }
}
