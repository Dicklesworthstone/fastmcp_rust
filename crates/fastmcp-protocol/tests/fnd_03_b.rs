//! Frozen FND-03 B public transport-era classification harnesses.

use fastmcp_core::CanonicalHttpUrl;
use fastmcp_protocol::protocol_policy::{
    HttpEndpointBundle, HttpEraCache, HttpEraDecision, HttpModernProbe, HttpProbeBody,
    ModernVersionSupport, ProtocolEra, ProtocolPolicy, ProtocolVersion, ProtocolVersionError,
    StdioEraClassifier, StdioEraDecision, StdioEraRejection, StdioOpeningFrame,
};

fn auto_bundle(security_partition: &str, policy_generation: u64) -> HttpEndpointBundle {
    HttpEndpointBundle::new(
        ProtocolPolicy::Auto,
        Some(CanonicalHttpUrl::parse("https://api.example.test/mcp?tenant=alpha").unwrap()),
        Some(CanonicalHttpUrl::parse("https://api.example.test/sse?tenant=alpha").unwrap()),
        Some(CanonicalHttpUrl::parse("https://api.example.test/messages?tenant=alpha").unwrap()),
        "credential-partition-a".to_owned(),
        security_partition.to_owned(),
        "http-sse-v2".to_owned(),
        policy_generation,
        7,
        11,
    )
    .expect("complete Auto bundle must be admitted")
}

#[test]
fn fnd_03_b_positive() {
    assert_eq!(
        ProtocolVersion::parse("2026-07-28"),
        Ok(ProtocolVersion::MODERN_2026)
    );
    assert_eq!(
        ProtocolVersion::parse("2024-11-05"),
        Ok(ProtocolVersion::LEGACY_2024)
    );
    assert_eq!(
        ProtocolVersion::parse("2025-11-25"),
        Err(ProtocolVersionError::UnsupportedVersion {
            received: "2025-11-25".to_owned(),
        })
    );

    let mut modern_stdio = StdioEraClassifier::new(ProtocolPolicy::Auto);
    assert_eq!(
        modern_stdio.classify_opening(StdioOpeningFrame::ModernRequest {
            protocol_version: "2026-07-28".to_owned(),
        }),
        StdioEraDecision::Selected {
            era: ProtocolEra::Modern2026,
            modern_version: Some(ModernVersionSupport::Supported),
        }
    );
    assert_eq!(
        modern_stdio.state(),
        &fastmcp_protocol::protocol_policy::StdioEraState::Selected(ProtocolEra::Modern2026)
    );

    let mut legacy_stdio = StdioEraClassifier::new(ProtocolPolicy::Auto);
    assert_eq!(
        legacy_stdio.classify_opening(StdioOpeningFrame::LegacyInitialize),
        StdioEraDecision::Selected {
            era: ProtocolEra::Legacy2024,
            modern_version: None,
        }
    );

    let security_a = auto_bundle("security-partition-a", 3);
    let security_b = auto_bundle("security-partition-b", 3);
    let regenerated_policy = auto_bundle("security-partition-a", 4);
    assert_ne!(security_a.key(), security_b.key());
    assert_ne!(security_a.key(), regenerated_policy.key());

    let mut cache = HttpEraCache::default();
    assert_eq!(
        cache.classify_or_cached(
            &security_a,
            HttpModernProbe {
                status: 500,
                body: HttpProbeBody::RecognizedModernJsonRpc,
            },
        ),
        HttpEraDecision::Selected(ProtocolEra::Modern2026)
    );
    assert_eq!(
        cache.classify_or_cached(
            &security_a,
            HttpModernProbe {
                status: 404,
                body: HttpProbeBody::Empty,
            },
        ),
        HttpEraDecision::Selected(ProtocolEra::Modern2026),
        "an already-modern bundle must not retry or downgrade"
    );
    assert_eq!(
        cache.classify_or_cached(
            &security_b,
            HttpModernProbe {
                status: 404,
                body: HttpProbeBody::Empty,
            },
        ),
        HttpEraDecision::Selected(ProtocolEra::Legacy2024)
    );
    assert_eq!(
        cache.selected_era(&security_a.key()),
        Some(ProtocolEra::Modern2026)
    );
    assert_eq!(
        cache.selected_era(&security_b.key()),
        Some(ProtocolEra::Legacy2024)
    );
}

#[test]
fn fnd_03_b_planted_negative() {
    let baseline = StdioOpeningFrame::ModernRequest {
        protocol_version: "2026-07-28".to_owned(),
    };
    let planted = StdioOpeningFrame::ModernRequest {
        protocol_version: "2025-11-25".to_owned(),
    };

    // The protocol-version field is the only planted dimension. The request
    // remains structurally modern, so it must select Modern once and expose a
    // typed unsupported-version result rather than retrying or downgrading.
    let mut accepted = StdioEraClassifier::new(ProtocolPolicy::Auto);
    assert_eq!(
        accepted.classify_opening(baseline),
        StdioEraDecision::Selected {
            era: ProtocolEra::Modern2026,
            modern_version: Some(ModernVersionSupport::Supported),
        }
    );
    let accepted_state = accepted.state().clone();

    let mut rejected = StdioEraClassifier::new(ProtocolPolicy::Auto);
    assert_eq!(
        rejected.classify_opening(planted),
        StdioEraDecision::Selected {
            era: ProtocolEra::Modern2026,
            modern_version: Some(ModernVersionSupport::Unsupported {
                received: "2025-11-25".to_owned(),
            }),
        }
    );
    assert_eq!(
        rejected.classify_opening(StdioOpeningFrame::LegacyInitialize),
        StdioEraDecision::RejectedUnderSelectedEra {
            era: ProtocolEra::Modern2026,
            reason: StdioEraRejection::CrossEraTraffic,
        }
    );
    assert_eq!(accepted.state(), &accepted_state);
    assert_eq!(
        rejected.state(),
        &fastmcp_protocol::protocol_policy::StdioEraState::Selected(ProtocolEra::Modern2026)
    );
}
