//! Frozen FND-03 B public transport-era classification harnesses.

use fastmcp_core::CanonicalHttpUrl;
use fastmcp_protocol::protocol_policy::{
    HttpEndpointBundle, HttpEndpointBundleError, HttpEraCache, HttpEraDecision, HttpModernProbe,
    HttpProbeBody, ModernVersionSupport, ProtocolEra, ProtocolPolicy, ProtocolVersion,
    ProtocolVersionError, StdioEraClassifier, StdioEraDecision, StdioEraRejection,
    StdioOpeningFrame,
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

#[test]
fn http_endpoint_bundle_errors_have_stable_display_and_error_surfaces() {
    let modern = CanonicalHttpUrl::parse("https://api.example.test/mcp").unwrap();
    let legacy_sse = CanonicalHttpUrl::parse("https://api.example.test/sse").unwrap();
    let legacy_message = CanonicalHttpUrl::parse("https://api.example.test/messages").unwrap();

    let errors = [
        (
            HttpEndpointBundle::new(
                ProtocolPolicy::Auto,
                None,
                Some(legacy_sse.clone()),
                Some(legacy_message.clone()),
                "credential-partition-a".to_owned(),
                "security-partition-a".to_owned(),
                "http-sse-v2".to_owned(),
                3,
                7,
                11,
            )
            .expect_err("Auto policy without modern target must be rejected"),
            "protocol policy auto requires a configured modern MCP POST target",
        ),
        (
            HttpEndpointBundle::new(
                ProtocolPolicy::Auto,
                Some(modern.clone()),
                None,
                Some(legacy_message.clone()),
                "credential-partition-a".to_owned(),
                "security-partition-a".to_owned(),
                "http-sse-v2".to_owned(),
                3,
                7,
                11,
            )
            .expect_err("Auto policy without legacy SSE target must be rejected"),
            "protocol policy auto requires a configured legacy SSE GET target",
        ),
        (
            HttpEndpointBundle::new(
                ProtocolPolicy::Auto,
                Some(modern.clone()),
                Some(legacy_sse.clone()),
                None,
                "credential-partition-a".to_owned(),
                "security-partition-a".to_owned(),
                "http-sse-v2".to_owned(),
                3,
                7,
                11,
            )
            .expect_err("Auto policy without legacy message target must be rejected"),
            "protocol policy auto requires a configured legacy message POST target",
        ),
        (
            HttpEndpointBundle::new(
                ProtocolPolicy::ModernOnly,
                Some(CanonicalHttpUrl::parse("https://api.example.test/mcp#fragment").unwrap()),
                None,
                None,
                "credential-partition-a".to_owned(),
                "security-partition-a".to_owned(),
                "http-sse-v2".to_owned(),
                3,
                7,
                11,
            )
            .expect_err("fragment-bearing modern target must be rejected"),
            "configured modern MCP POST target must not contain a fragment",
        ),
        (
            HttpEndpointBundle::new(
                ProtocolPolicy::Auto,
                Some(modern.clone()),
                Some(legacy_sse),
                Some(modern),
                "credential-partition-a".to_owned(),
                "security-partition-a".to_owned(),
                "http-sse-v2".to_owned(),
                3,
                7,
                11,
            )
            .expect_err("same-method canonical target collision must be rejected"),
            "configured modern MCP POST and legacy message POST routes collide at https://api.example.test/mcp",
        ),
    ];

    for (error, expected) in errors {
        let error: &dyn std::error::Error = &error;
        assert_eq!(error.to_string(), expected);
    }

    assert_eq!(
        HttpEndpointBundleError::FragmentNotAllowed {
            route: fastmcp_protocol::protocol_policy::HttpRouteKind::LegacySseGet,
        }
        .to_string(),
        "configured legacy SSE GET target must not contain a fragment"
    );
}
