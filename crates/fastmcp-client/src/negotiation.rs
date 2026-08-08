//! Client-owned modern-first HTTP negotiation.

use std::fmt;

use fastmcp_protocol::protocol_policy::{
    HttpEndpointBundle, HttpEraCache, HttpModernProbe, HttpProbeBody, ProtocolEra, ProtocolPolicy,
};

use crate::ClientProtocolPlan;

/// Immutable observable state for one configured HTTP classification attempt.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ClientHttpNegotiationState {
    probe_dispatched: bool,
    selected_era: Option<ProtocolEra>,
    legacy_sse_fallback_authorized: bool,
}

impl ClientHttpNegotiationState {
    /// Whether the one permitted modern probe has been consumed.
    #[must_use]
    pub const fn probe_dispatched(self) -> bool {
        self.probe_dispatched
    }

    /// Returns the era selected from a recognized modern response, if any.
    #[must_use]
    pub const fn selected_era(self) -> Option<ProtocolEra> {
        self.selected_era
    }

    /// Whether the probe permits one configured legacy SSE observation.
    ///
    /// Authorization is deliberately not a legacy-era selection: only the
    /// later validated legacy endpoint event can make that selection.
    #[must_use]
    pub const fn legacy_sse_fallback_authorized(self) -> bool {
        self.legacy_sse_fallback_authorized
    }
}

/// The outcome of one modern-first HTTP probe.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClientHttpNegotiationDecision {
    /// A recognized modern JSON-RPC response fixed the modern era.
    ModernSelected,
    /// An eligible response permits exactly one configured legacy SSE GET.
    LegacySseFallbackAuthorized,
}

/// Typed refusal from HTTP-era classification before a fallback side effect.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClientHttpNegotiationError {
    /// The selected builder plan has no configured HTTP endpoints.
    MissingHttpEndpointBundle { policy: ProtocolPolicy },
    /// A legacy-only plan must use its installed legacy adapter directly.
    ModernProbeForbiddenForLegacyOnly,
    /// A connection attempt never dispatches the modern probe twice.
    ModernProbeAlreadyDispatched,
    /// A transport failure is not a downgrade signal.
    ModernProbeTransportFailure,
    /// The response cannot authorize a legacy SSE fallback.
    ModernProbeRejectedWithoutLegacyFallback { status: u16, body: HttpProbeBody },
}

impl fmt::Display for ClientHttpNegotiationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingHttpEndpointBundle { policy } => {
                write!(
                    formatter,
                    "{policy:?} has no configured HTTP endpoint bundle"
                )
            }
            Self::ModernProbeForbiddenForLegacyOnly => formatter
                .write_str("legacy-only HTTP must use the installed legacy adapter directly"),
            Self::ModernProbeAlreadyDispatched => {
                formatter.write_str("the modern HTTP probe was already dispatched for this attempt")
            }
            Self::ModernProbeTransportFailure => {
                formatter.write_str("modern HTTP probe transport failure cannot authorize fallback")
            }
            Self::ModernProbeRejectedWithoutLegacyFallback { status, body } => write!(
                formatter,
                "modern HTTP probe status {status} with {body:?} cannot authorize legacy fallback"
            ),
        }
    }
}

impl std::error::Error for ClientHttpNegotiationError {}

/// A one-shot modern-first classifier bound to one immutable endpoint bundle.
///
/// Its cache is reachable only through the exact bundle stored here. An
/// endpoint with the same origin but a different path, query, partition, or
/// generation necessarily requires a separate instance.
#[derive(Debug)]
pub struct ClientHttpNegotiation {
    policy: ProtocolPolicy,
    bundle: HttpEndpointBundle,
    cache: HttpEraCache,
    state: ClientHttpNegotiationState,
}

impl ClientHttpNegotiation {
    /// Starts an HTTP classification attempt from an immutable client plan.
    pub fn from_protocol_plan(
        protocol_plan: &ClientProtocolPlan,
    ) -> Result<Self, ClientHttpNegotiationError> {
        let policy = protocol_plan.policy();
        let Some(bundle) = protocol_plan.http_endpoints() else {
            return Err(ClientHttpNegotiationError::MissingHttpEndpointBundle { policy });
        };

        Ok(Self {
            policy,
            bundle: bundle.clone(),
            cache: HttpEraCache::default(),
            state: ClientHttpNegotiationState {
                probe_dispatched: false,
                selected_era: None,
                legacy_sse_fallback_authorized: false,
            },
        })
    }

    /// Returns the current externally observable attempt state.
    #[must_use]
    pub const fn state(&self) -> ClientHttpNegotiationState {
        self.state
    }

    /// Processes the isolated first modern HTTP probe exactly once.
    ///
    /// An eligible 400, 404, or 405 response authorizes a legacy SSE
    /// observation but intentionally does not cache or select Legacy. This
    /// prevents HTTP status/body observations from becoming a downgrade.
    pub fn observe_modern_probe(
        &mut self,
        probe: HttpModernProbe,
    ) -> Result<ClientHttpNegotiationDecision, ClientHttpNegotiationError> {
        if self.state.probe_dispatched {
            return Err(ClientHttpNegotiationError::ModernProbeAlreadyDispatched);
        }

        // The observation proves that the one permitted probe was already
        // sent, including when its response cannot select either era.
        self.state.probe_dispatched = true;
        let decision = self.preflight_probe(probe)?;

        match decision {
            ClientHttpNegotiationDecision::ModernSelected => {
                // FND-03's exact-key cache is used only after a recognized
                // modern response. It therefore cannot cache an HTTP fallback
                // authorization as a legacy era.
                let _ = self.cache.classify_or_cached(&self.bundle, probe);
                self.state.selected_era = Some(ProtocolEra::Modern2026);
            }
            ClientHttpNegotiationDecision::LegacySseFallbackAuthorized => {
                self.state.legacy_sse_fallback_authorized = true;
            }
        }

        Ok(decision)
    }

    fn preflight_probe(
        &self,
        probe: HttpModernProbe,
    ) -> Result<ClientHttpNegotiationDecision, ClientHttpNegotiationError> {
        match self.policy {
            ProtocolPolicy::LegacyOnly => {
                Err(ClientHttpNegotiationError::ModernProbeForbiddenForLegacyOnly)
            }
            ProtocolPolicy::ModernOnly | ProtocolPolicy::Auto
                if matches!(probe.body, HttpProbeBody::RecognizedModernJsonRpc) =>
            {
                Ok(ClientHttpNegotiationDecision::ModernSelected)
            }
            ProtocolPolicy::Auto
                if matches!(probe.status, 400 | 404 | 405)
                    && matches!(
                        probe.body,
                        HttpProbeBody::Empty | HttpProbeBody::Unrecognized
                    ) =>
            {
                Ok(ClientHttpNegotiationDecision::LegacySseFallbackAuthorized)
            }
            ProtocolPolicy::ModernOnly | ProtocolPolicy::Auto
                if matches!(probe.body, HttpProbeBody::TransportFailure) =>
            {
                Err(ClientHttpNegotiationError::ModernProbeTransportFailure)
            }
            ProtocolPolicy::ModernOnly | ProtocolPolicy::Auto => Err(
                ClientHttpNegotiationError::ModernProbeRejectedWithoutLegacyFallback {
                    status: probe.status,
                    body: probe.body,
                },
            ),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use fastmcp_core::CanonicalHttpUrl;

    fn modern_only_plan() -> ClientProtocolPlan {
        ClientProtocolPlan::http(
            ProtocolPolicy::ModernOnly,
            Some(CanonicalHttpUrl::parse("https://api.example.test/mcp").unwrap()),
            None,
            None,
            "credential-partition".to_owned(),
            "security-partition".to_owned(),
            "http-test".to_owned(),
            1,
            1,
            1,
        )
        .expect("a modern-only plan needs only its modern target")
    }

    #[test]
    fn modern_only_rejects_one_unrecognized_probe_without_selecting_or_retrying() {
        let mut negotiation = ClientHttpNegotiation::from_protocol_plan(&modern_only_plan())
            .expect("the configured plan creates a negotiation attempt");

        let error = negotiation
            .observe_modern_probe(HttpModernProbe {
                status: 404,
                body: HttpProbeBody::Unrecognized,
            })
            .expect_err("changing only the probe body must not select modern");

        assert_eq!(
            error,
            ClientHttpNegotiationError::ModernProbeRejectedWithoutLegacyFallback {
                status: 404,
                body: HttpProbeBody::Unrecognized,
            }
        );
        assert!(negotiation.state().probe_dispatched());
        assert_eq!(negotiation.state().selected_era(), None);
        assert!(!negotiation.state().legacy_sse_fallback_authorized());
        assert_eq!(
            negotiation.observe_modern_probe(HttpModernProbe {
                status: 200,
                body: HttpProbeBody::RecognizedModernJsonRpc,
            }),
            Err(ClientHttpNegotiationError::ModernProbeAlreadyDispatched)
        );
    }
}
