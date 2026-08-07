//! Exact-name public-surface harness for CLT-02 implementation B.

use fastmcp_client::{
    CanonicalHttpUrl, ClientBuilder, ClientHttpNegotiationDecision, ClientHttpNegotiationError,
    ClientProtocolPlan, HttpModernProbe, HttpProbeBody, ProtocolEra, ProtocolPolicy,
};

fn plan() -> ClientProtocolPlan {
    ClientProtocolPlan::http(
        ProtocolPolicy::Auto,
        Some(CanonicalHttpUrl::parse("https://client.example.test/mcp").unwrap()),
        Some(CanonicalHttpUrl::parse("https://client.example.test/sse").unwrap()),
        Some(CanonicalHttpUrl::parse("https://client.example.test/messages").unwrap()),
        "credential-partition-a".to_owned(),
        "security-partition-a".to_owned(),
        "streamable-http-v1".to_owned(),
        8,
        4,
        0,
    )
    .expect("test HTTP plan must be accepted")
}

#[test]
fn clt_02_b_positive() {
    let builder = ClientBuilder::new().protocol_plan(plan());
    let mut modern = builder
        .http_negotiation()
        .expect("public builder must admit its configured HTTP plan");

    assert_eq!(
        modern.observe_modern_probe(HttpModernProbe {
            status: 500,
            body: HttpProbeBody::RecognizedModernJsonRpc,
        }),
        Ok(ClientHttpNegotiationDecision::ModernSelected)
    );
    assert_eq!(modern.state().selected_era(), Some(ProtocolEra::Modern2026));
    let selected_state = modern.state();
    assert_eq!(
        modern.observe_modern_probe(HttpModernProbe {
            status: 404,
            body: HttpProbeBody::Empty,
        }),
        Err(ClientHttpNegotiationError::ModernProbeAlreadyDispatched)
    );
    assert_eq!(modern.state(), selected_state);

    let mut fallback = builder
        .http_negotiation()
        .expect("a separate builder attempt must retain its exact endpoint key");
    assert_eq!(
        fallback.observe_modern_probe(HttpModernProbe {
            status: 404,
            body: HttpProbeBody::Empty,
        }),
        Ok(ClientHttpNegotiationDecision::LegacySseFallbackAuthorized)
    );
    assert_eq!(fallback.state().selected_era(), None);
    assert!(fallback.state().legacy_sse_fallback_authorized());
}

#[test]
fn clt_02_b_planted_negative() {
    let builder = ClientBuilder::new().protocol_plan(plan());
    let mut negotiation = builder
        .http_negotiation()
        .expect("accepted baseline must reach the public builder admission boundary");
    let state_before_refusal = negotiation.state();

    // Only the status differs from the accepted 404/empty fallback row.
    let refusal = negotiation.observe_modern_probe(HttpModernProbe {
        status: 401,
        body: HttpProbeBody::Empty,
    });

    assert_eq!(
        refusal,
        Err(
            ClientHttpNegotiationError::ModernProbeRejectedWithoutLegacyFallback {
                status: 401,
                body: HttpProbeBody::Empty,
            }
        )
    );
    assert_eq!(negotiation.state(), state_before_refusal);
}
