//! Frozen FND-03 I integration harness: immutable dual-era policy through the
//! shipped facade entrypoints.
//!
//! External consumer of the packaged facade, matching the shape of the sibling
//! `fastmcp-protocol/tests/fnd_03_a.rs` and `fnd_03_b.rs`. Nothing here reaches
//! crate internals: no `use super::`, no `pub(crate)` item, no `cfg(test)`
//! module.
//!
//! # Why this target exists rather than reusing an existing location
//!
//! Both pre-existing copies of the frozen IDs were disqualified, for different
//! reasons, and the second one is the one worth remembering:
//!
//! * `fastmcp-server/src/builder.rs` holds them inside the `#[cfg(test)]`
//!   module at `:2830`. A `cfg(test)` function cannot prove shipped behavior
//!   (PL-3), so that copy is retained as in-crate coverage under
//!   `fnd_03_i_unit_*` and does not carry the frozen IDs.
//! * `fastmcp/tests/e2e_modern_http.rs` is the *right surface* — external
//!   target, facade crate, genuine `fastmcp_rust::` paths — but its
//!   `[[test]]` entry declares `required-features = ["legacy-2024-11-05",
//!   "tasks", "proxy"]`, and `proxy` is **not** in the facade's default set
//!   (`default = ["legacy-2024-11-05", "tasks"]`). The frozen runner passes no
//!   `--features`, so that target is never built and the frozen ID would be a
//!   feature-disabled row — which the acceptance criteria forbid outright.
//!   That copy is retained under `fnd_03_i_e2e_*`.
//!
//! This file is auto-discovered (`autotests` unset, so it defaults to true) and
//! builds under the facade's default features, so the frozen runner reaches it
//! with no feature flags and no manifest entry.
//!
//! # What "integration" means here
//!
//! The A and B leaves prove the protocol types in isolation. This leaf proves
//! the shipped facade *consumes* those exact types without duplicating era
//! policy: the era-pinned builder namespaces expose one immutable policy each
//! and offer no way to reset it, and the configurable component builder
//! commits its policy into the built server.

use fastmcp_rust::{
    LEGACY_PROTOCOL_VERSION, MODERN_PROTOCOL_VERSION, ProtocolEra, ProtocolPolicy,
    ProtocolPolicyVersionError, ProtocolVersion,
};
use fastmcp_server::ServerBuilder;

/// The syntactically valid but unsupported revision. It is a negative input
/// only and can never satisfy a 2026 or exact-2024 positive.
const UNSUPPORTED_VERSION: &str = "2025-11-25";

#[test]
fn fnd_03_i_positive() {
    // ---------------------------------------------------------------------
    // The era-pinned facade namespaces each expose exactly one immutable
    // policy. None of these wrappers has a policy setter, so the selection is
    // immutable by construction rather than by convention.
    // ---------------------------------------------------------------------
    let auto_builder = fastmcp_rust::auto::ServerBuilder::new("fnd03-i-auto", "1.0.0");
    assert_eq!(auto_builder.protocol_policy(), ProtocolPolicy::Auto);

    // The modern namespace does not return a `ProtocolPolicy` at all: its
    // accessor is typed `ModernOnly`, a unit marker, so a modern builder
    // cannot even name `Auto` or `LegacyOnly` in its signature. This is the
    // type-level form of "no legacy lifecycle state leaks into modern handler
    // signatures" — binding it to the marker type is the assertion.
    let modern_builder = fastmcp_rust::modern::ServerBuilder::new("fnd03-i-modern", "1.0.0");
    let _: fastmcp_rust::modern::ModernOnly = modern_builder.protocol_policy();

    // The legacy namespace exists only when its feature is compiled in, and
    // pins the complementary policy.
    #[cfg(feature = "legacy-2024-11-05")]
    {
        let legacy_builder =
            fastmcp_rust::legacy_2024::ServerBuilder::new("fnd03-i-legacy", "1.0.0");
        assert_eq!(
            legacy_builder.protocol_policy(),
            fastmcp_rust::legacy_2024::ProtocolPolicy::LegacyOnly
        );
    }

    // ---------------------------------------------------------------------
    // The configurable component builder consumes the same policy type, and
    // its configured default follows the compiled feature set.
    // ---------------------------------------------------------------------
    let builder = ServerBuilder::try_new("fnd03-i-integration", "1.0.0")
        .expect("the public server builder must construct through try_new");

    #[cfg(feature = "legacy-2024-11-05")]
    assert_eq!(builder.configured_protocol_policy(), ProtocolPolicy::Auto);
    #[cfg(not(feature = "legacy-2024-11-05"))]
    assert_eq!(
        builder.configured_protocol_policy(),
        ProtocolPolicy::ModernOnly
    );

    // A selected policy is carried into the built server, not re-derived.
    let mut modern = builder;
    modern
        .try_set_protocol_policy(ProtocolPolicy::ModernOnly)
        .expect("ModernOnly is available on every build");
    assert_eq!(
        modern.configured_protocol_policy(),
        ProtocolPolicy::ModernOnly
    );
    let server = modern.try_build().expect("the modern server builds");
    assert_eq!(server.protocol_policy(), ProtocolPolicy::ModernOnly);

    // ---------------------------------------------------------------------
    // Public diagnostics name exactly the supported revisions. The facade
    // re-exports the A types rather than mirroring them, so the identity
    // round-trip holds through the facade path.
    // ---------------------------------------------------------------------
    assert_eq!(MODERN_PROTOCOL_VERSION, "2026-07-28");
    assert_eq!(
        ProtocolVersion::parse(MODERN_PROTOCOL_VERSION),
        Ok(ProtocolVersion::MODERN_2026)
    );
    assert_eq!(ProtocolVersion::MODERN_2026.era(), ProtocolEra::Modern2026);
    assert_eq!(
        ProtocolEra::Modern2026.version(),
        ProtocolVersion::MODERN_2026
    );

    #[cfg(feature = "legacy-2024-11-05")]
    {
        assert_eq!(LEGACY_PROTOCOL_VERSION, "2024-11-05");
        assert_eq!(
            ProtocolVersion::parse(LEGACY_PROTOCOL_VERSION),
            Ok(ProtocolVersion::LEGACY_2024)
        );
        assert_eq!(ProtocolVersion::LEGACY_2024.era(), ProtocolEra::Legacy2024);
        assert_ne!(ProtocolVersion::MODERN_2026, ProtocolVersion::LEGACY_2024);
    }

    // The third revision is rejected through the facade path, with no alias.
    assert_eq!(
        ProtocolVersion::parse(UNSUPPORTED_VERSION),
        Err(ProtocolPolicyVersionError::UnsupportedVersion {
            received: UNSUPPORTED_VERSION.to_owned(),
        })
    );
}

#[test]
fn fnd_03_i_planted_negative() {
    // Accepted case, held for the unchanged-state comparison. Same call, same
    // facade path, same everything except the single changed variable below.
    let accepted = ProtocolVersion::parse(MODERN_PROTOCOL_VERSION)
        .expect("the supported revision parses through the facade");
    assert_eq!(accepted, ProtocolVersion::MODERN_2026);

    let auto_builder = fastmcp_rust::auto::ServerBuilder::new("fnd03-i-neg-auto", "1.0.0");
    assert_eq!(auto_builder.protocol_policy(), ProtocolPolicy::Auto);

    let builder = ServerBuilder::try_new("fnd03-i-integration-neg", "1.0.0")
        .expect("the public server builder must construct through try_new");
    let initial_policy = builder.configured_protocol_policy();

    // The sole changed variable is the public-export/version dimension: the
    // accepted revision string becomes the unsupported 2025-11-25. Nothing
    // else about the call differs.
    let planted = ProtocolVersion::parse(UNSUPPORTED_VERSION);

    assert_eq!(
        planted,
        Err(ProtocolPolicyVersionError::UnsupportedVersion {
            received: UNSUPPORTED_VERSION.to_owned(),
        }),
        "the unsupported revision must reach the typed refusal boundary"
    );

    // Refused, not aliased: the spelling is retained exactly and did not
    // normalize into either supported era.
    let Err(ProtocolPolicyVersionError::UnsupportedVersion { received }) = planted else {
        panic!("the planted input must be refused");
    };
    assert_eq!(received, UNSUPPORTED_VERSION);
    assert_ne!(received, MODERN_PROTOCOL_VERSION);
    assert_ne!(received, LEGACY_PROTOCOL_VERSION);

    // No policy admits it, so no era-pinned entrypoint could advertise it.
    for policy in [
        ProtocolPolicy::Auto,
        ProtocolPolicy::ModernOnly,
        ProtocolPolicy::LegacyOnly,
    ] {
        assert!(
            policy
                .supported_versions()
                .iter()
                .all(|version| version.as_str() != UNSUPPORTED_VERSION),
            "{policy:?} must not admit the unsupported revision"
        );
    }

    // Unchanged state after rejection: the accepted parse, the pinned facade
    // policies, and the configurable builder's selection are all exactly as
    // they were before the refusal.
    assert_eq!(
        ProtocolVersion::parse(MODERN_PROTOCOL_VERSION),
        Ok(accepted)
    );
    assert_eq!(auto_builder.protocol_policy(), ProtocolPolicy::Auto);
    assert_eq!(builder.configured_protocol_policy(), initial_policy);

    let modern_builder = fastmcp_rust::modern::ServerBuilder::new("fnd03-i-neg-modern", "1.0.0");
    let _: fastmcp_rust::modern::ModernOnly = modern_builder.protocol_policy();

    // The refusal did not disturb the ordinary build path.
    let mut modern = builder;
    modern
        .try_set_protocol_policy(ProtocolPolicy::ModernOnly)
        .expect("ModernOnly is available on every build");
    let server = modern.try_build().expect("the modern server still builds");
    assert_eq!(server.protocol_policy(), ProtocolPolicy::ModernOnly);
}
