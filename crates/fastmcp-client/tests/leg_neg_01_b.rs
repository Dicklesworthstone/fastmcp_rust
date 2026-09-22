//! LEG-NEG-01 B — downgrade-resistant HTTP `Auto` fallback coordination.
//!
//! External consumer of the shipped `fastmcp_client` public surface: this target
//! reaches the coordinator exactly as a downstream crate does, never through
//! `use super::` or a `#[cfg(test)]` module, so what it proves is the packaged
//! public API rather than crate-internal behaviour (PL-3).
//!
//! No socket fixture appears here, and that is deliberate rather than a gap. The
//! LEG-NEG-01 B leaf is a *coordinator*: it performs no I/O at all, so a
//! listener that observed zero connections would prove nothing a direct state
//! assertion does not already prove, and would read as fixture-as-live-proof.
//! "Zero legacy GET" is therefore asserted on the coordinator's own observable
//! `legacy_gets_opened` / `legacy_gets_authorized` counters, which are the fields
//! a real caller would have to consult before opening a socket.

use fastmcp_client::{
    CanonicalHttpUrl, ClientProtocolPlan, FallbackDecision, FallbackState, HttpFallbackCoordinator,
    HttpFallbackError, ModernProbeObservation,
};
use fastmcp_protocol::protocol_policy::{
    HttpModernProbe, HttpProbeBody, ProtocolEra, ProtocolPolicy,
};

/// The three statuses that may ever start a legacy candidate.
const ELIGIBLE_STATUSES: [u16; 3] = [400, 404, 405];

/// The two body classes that authorize exactly one GET on an eligible status.
const GET_ELIGIBLE_BODIES: [HttpProbeBody; 2] = [HttpProbeBody::Empty, HttpProbeBody::Unrecognized];

/// A recognized modern JSON-RPC body — result or error. Forbids the GET at every
/// status, because it is proof the peer speaks the modern era.
const RECOGNIZED_MODERN: HttpProbeBody = HttpProbeBody::RecognizedModernJsonRpc;

const MODERN_TARGET: &str = "https://mcp.example.test/mcp";
const LEGACY_SSE_TARGET: &str = "https://mcp.example.test/sse";
const LEGACY_MESSAGE_TARGET: &str = "https://mcp.example.test/messages";
const SECURITY_PARTITION: &str = "security-partition-leg-neg-01-b";

fn url(value: &str) -> CanonicalHttpUrl {
    CanonicalHttpUrl::parse(value).expect("every fixture target is canonical")
}

/// Builds one immutable HTTP plan. Callers vary exactly one field at a time.
fn plan_with(
    policy: ProtocolPolicy,
    modern: &str,
    legacy_sse: &str,
    security_partition: &str,
    configuration_generation: u64,
) -> ClientProtocolPlan {
    ClientProtocolPlan::http(
        policy,
        Some(url(modern)),
        Some(url(legacy_sse)),
        Some(url(LEGACY_MESSAGE_TARGET)),
        "credential-partition-leg-neg-01-b".to_owned(),
        security_partition.to_owned(),
        "native-h1-leg-neg-01-b".to_owned(),
        1,
        configuration_generation,
        0,
    )
    .expect("the configured dual-era plan is accepted")
}

fn auto_plan() -> ClientProtocolPlan {
    plan_with(
        ProtocolPolicy::Auto,
        MODERN_TARGET,
        LEGACY_SSE_TARGET,
        SECURITY_PARTITION,
        1,
    )
}

fn coordinator() -> HttpFallbackCoordinator {
    HttpFallbackCoordinator::new(auto_plan()).expect("an Auto HTTP plan starts one coordinator")
}

/// Builds an observation bound to the coordinator's own plan.
fn observation(
    coordinator: &HttpFallbackCoordinator,
    attempt_id: u64,
    status: u16,
    body: HttpProbeBody,
) -> ModernProbeObservation {
    ModernProbeObservation::new(
        coordinator.bundle_key().clone(),
        MODERN_TARGET,
        attempt_id,
        HttpModernProbe { status, body },
    )
    .expect("a bound observation is constructible")
}

/// The state of a coordinator that has done nothing.
fn pristine() -> FallbackState {
    FallbackState::default()
}

/// Asserts the coordinator performed no effect whatsoever.
fn assert_inert(coordinator: &HttpFallbackCoordinator, context: &str) {
    let state = coordinator.state();
    assert_eq!(
        state.legacy_gets_authorized, 0,
        "{context}: no GET may be authorized"
    );
    assert_eq!(
        state.legacy_gets_opened, 0,
        "{context}: no GET may be opened"
    );
    assert_eq!(
        state.endpoint_events_admitted, 0,
        "{context}: no endpoint event may be admitted"
    );
    assert_eq!(
        state.selected_era, None,
        "{context}: no era may be selected"
    );
    assert_eq!(
        state.credential_mutations, 0,
        "{context}: no credential may be acquired or mutated"
    );
    assert_eq!(
        state.era_cache_mutations, 0,
        "{context}: no era or discovery cache entry may be written"
    );
    assert_eq!(coordinator.advertised_message_post_target(), None);
}

#[test]
fn leg_neg_01_b_positive() {
    // ---------------------------------------------------------------------
    // The exact nine rows: {400,404,405} x {Empty, Unrecognized, Recognized}.
    // ---------------------------------------------------------------------
    let mut one_get_authorizations = 0_usize;
    let mut no_get_recognized_decisions = 0_usize;
    let mut evaluated_rows = Vec::new();

    for status in ELIGIBLE_STATUSES {
        for body in [
            GET_ELIGIBLE_BODIES[0],
            GET_ELIGIBLE_BODIES[1],
            RECOGNIZED_MODERN,
        ] {
            let mut coordinator = coordinator();
            assert_eq!(coordinator.state(), pristine());
            let observed = observation(&coordinator, 1, status, body);
            let decision = coordinator
                .observe(&observed)
                .unwrap_or_else(|error| panic!("row {status}/{body:?} must be evaluated: {error}"));

            match decision {
                FallbackDecision::LegacyGetAuthorized(permit) => {
                    assert!(
                        GET_ELIGIBLE_BODIES.contains(&body),
                        "only Empty and Unrecognized may authorize a GET, not {body:?}"
                    );
                    assert_eq!(permit.target(), LEGACY_SSE_TARGET);
                    assert_eq!(permit.attempt_id(), 1);
                    // Authorization alone is never a selection.
                    assert_eq!(coordinator.state().legacy_gets_authorized, 1);
                    assert_eq!(coordinator.state().legacy_gets_opened, 0);
                    assert_eq!(coordinator.selected_era(), None);
                    one_get_authorizations += 1;
                }
                FallbackDecision::ModernRetained => {
                    assert_eq!(
                        body, RECOGNIZED_MODERN,
                        "only a recognized modern body may forbid the GET at {status}"
                    );
                    assert_inert(&coordinator, "recognized modern row");
                    no_get_recognized_decisions += 1;
                }
            }
            assert_eq!(coordinator.state().observations_admitted, 1);
            evaluated_rows.push((status, body));
        }
    }

    assert_eq!(evaluated_rows.len(), 9, "the matrix has exactly nine rows");
    assert_eq!(
        one_get_authorizations, 6,
        "six rows authorize exactly one legacy GET"
    );
    assert_eq!(
        no_get_recognized_decisions, 3,
        "three recognized-modern rows forbid the GET at 400, 404 and 405"
    );

    // ---------------------------------------------------------------------
    // Legacy selection happens only after the first valid endpoint event.
    // ---------------------------------------------------------------------
    let mut selecting = coordinator();
    let observed = observation(&selecting, 7, 404, HttpProbeBody::Unrecognized);
    let FallbackDecision::LegacyGetAuthorized(permit) = selecting
        .observe(&observed)
        .expect("404/Unrecognized authorizes one GET")
    else {
        panic!("404/Unrecognized must authorize a legacy GET");
    };
    assert_eq!(
        selecting.selected_era(),
        None,
        "authorization is not selection"
    );

    let opened = selecting
        .open_legacy_get(permit)
        .expect("the single authorization opens one GET");
    assert_eq!(opened, LEGACY_SSE_TARGET);
    assert_eq!(
        selecting.selected_era(),
        None,
        "opening the GET is still not a selection"
    );
    assert_eq!(selecting.state().legacy_gets_opened, 1);

    assert_eq!(
        selecting
            .admit_endpoint_event(LEGACY_MESSAGE_TARGET)
            .expect("the first valid endpoint event selects the exact-2024 era"),
        ProtocolEra::Legacy2024
    );
    assert_eq!(selecting.selected_era(), Some(ProtocolEra::Legacy2024));
    assert_eq!(selecting.state().endpoint_events_admitted, 1);
    assert_eq!(selecting.state().credential_mutations, 0);
    assert_eq!(selecting.state().era_cache_mutations, 0);
    assert_eq!(
        selecting.advertised_message_post_target(),
        Some(LEGACY_MESSAGE_TARGET)
    );

    // A second event cannot re-select or change the era.
    let selected_state = selecting.state();
    assert_eq!(
        selecting.admit_endpoint_event(LEGACY_MESSAGE_TARGET),
        Err(HttpFallbackError::DuplicateEndpointEvent)
    );
    assert_eq!(selecting.state(), selected_state);

    // A server-generated session query on a query-free configured target is
    // admissible; scheme, authority and path still cannot move.
    let mut session_query = authorized_and_opened();
    assert_eq!(
        session_query
            .admit_endpoint_event(&format!("{LEGACY_MESSAGE_TARGET}?session_id=abc123"))
            .expect("a session query extends the configured target"),
        ProtocolEra::Legacy2024
    );

    // ---------------------------------------------------------------------
    // Every other status/body row is ineligible: zero GET, unchanged state.
    // ---------------------------------------------------------------------
    for status in [200_u16, 201, 301, 302, 401, 403, 429, 500, 502, 503] {
        for body in GET_ELIGIBLE_BODIES {
            let mut coordinator = coordinator();
            let observed = observation(&coordinator, 1, status, body);
            assert_eq!(
                coordinator.observe(&observed),
                Err(HttpFallbackError::IneligibleObservation { status, body }),
                "status {status} is not an eligible fallback status"
            );
            assert_eq!(coordinator.state(), pristine());
            assert_inert(&coordinator, "ineligible status row");
        }
        // A recognized modern body at any status retains the modern era and
        // still authorizes nothing.
        let mut recognized = coordinator();
        let observed = observation(&recognized, 1, status, RECOGNIZED_MODERN);
        assert!(matches!(
            recognized.observe(&observed),
            Ok(FallbackDecision::ModernRetained)
        ));
        assert_inert(&recognized, "recognized modern at ineligible status");
    }

    // A transport failure is never a downgrade signal, including on the three
    // otherwise-eligible statuses.
    for status in ELIGIBLE_STATUSES {
        let mut coordinator = coordinator();
        let observed = observation(&coordinator, 1, status, HttpProbeBody::TransportFailure);
        assert_eq!(
            coordinator.observe(&observed),
            Err(HttpFallbackError::IneligibleObservation {
                status,
                body: HttpProbeBody::TransportFailure,
            })
        );
        assert_eq!(coordinator.state(), pristine());
    }

    // ---------------------------------------------------------------------
    // Invalid endpoint-event forms leave the era unselected.
    // ---------------------------------------------------------------------
    for malformed in ["", "   ", "\t"] {
        let mut coordinator = authorized_and_opened();
        let before = coordinator.state();
        assert_eq!(
            coordinator.admit_endpoint_event(malformed),
            Err(HttpFallbackError::EndpointEventMalformed)
        );
        assert_eq!(coordinator.state(), before);
        assert_eq!(coordinator.selected_era(), None);
    }
    for mismatched in [
        "https://mcp.example.test/other",
        "https://other.example.test/messages",
        "http://mcp.example.test/messages",
        "https://mcp.example.test/messages/extra",
        LEGACY_SSE_TARGET,
    ] {
        let mut coordinator = authorized_and_opened();
        let before = coordinator.state();
        assert_eq!(
            coordinator.admit_endpoint_event(mismatched),
            Err(HttpFallbackError::EndpointEventTargetMismatch),
            "{mismatched} is not the configured legacy message POST target"
        );
        assert_eq!(coordinator.state(), before);
        assert_eq!(coordinator.selected_era(), None);
        assert_eq!(coordinator.advertised_message_post_target(), None);
    }

    // An endpoint event without an authorized, opened GET selects nothing.
    let mut unauthorized = coordinator();
    assert_eq!(
        unauthorized.admit_endpoint_event(LEGACY_MESSAGE_TARGET),
        Err(HttpFallbackError::EndpointEventWithoutAuthorization)
    );
    assert_eq!(unauthorized.state(), pristine());

    // A recognized-modern row never reaches the endpoint-event stage at all.
    let mut recognized = coordinator();
    let observed = observation(&recognized, 3, 404, RECOGNIZED_MODERN);
    assert!(matches!(
        recognized.observe(&observed),
        Ok(FallbackDecision::ModernRetained)
    ));
    assert_eq!(
        recognized.admit_endpoint_event(LEGACY_MESSAGE_TARGET),
        Err(HttpFallbackError::EndpointEventWithoutAuthorization)
    );
    assert_inert(&recognized, "recognized modern cannot reach selection");

    // ---------------------------------------------------------------------
    // Stale, cross-bundle, mismatched and replayed observations are inert.
    // ---------------------------------------------------------------------
    let mut cross = coordinator();
    let other_partition = HttpFallbackCoordinator::new(plan_with(
        ProtocolPolicy::Auto,
        MODERN_TARGET,
        LEGACY_SSE_TARGET,
        "security-partition-other",
        1,
    ))
    .expect("the repartitioned plan starts its own coordinator");
    let foreign = observation(&other_partition, 1, 404, HttpProbeBody::Empty);
    assert_eq!(
        cross.observe(&foreign),
        Err(HttpFallbackError::CrossBundleObservation),
        "a changed security partition is a different endpoint bundle"
    );
    assert_eq!(cross.state(), pristine());

    let regenerated = HttpFallbackCoordinator::new(plan_with(
        ProtocolPolicy::Auto,
        MODERN_TARGET,
        LEGACY_SSE_TARGET,
        SECURITY_PARTITION,
        2,
    ))
    .expect("the regenerated plan starts its own coordinator");
    let stale = observation(&regenerated, 1, 404, HttpProbeBody::Empty);
    assert_eq!(
        cross.observe(&stale),
        Err(HttpFallbackError::CrossBundleObservation),
        "a changed configuration generation is a different endpoint bundle"
    );
    assert_eq!(cross.state(), pristine());

    let mismatched_target = ModernProbeObservation::new(
        cross.bundle_key().clone(),
        "https://mcp.example.test/mcp-b",
        1,
        HttpModernProbe {
            status: 404,
            body: HttpProbeBody::Empty,
        },
    )
    .expect("the observation is constructible");
    assert_eq!(
        cross.observe(&mismatched_target),
        Err(HttpFallbackError::ModernTargetMismatch)
    );
    assert_eq!(cross.state(), pristine());

    // One coordinator settles exactly one attempt.
    let mut settled = coordinator();
    let first = observation(&settled, 11, 404, HttpProbeBody::Empty);
    assert!(settled.observe(&first).is_ok());
    let settled_state = settled.state();
    assert_eq!(
        settled.observe(&first),
        Err(HttpFallbackError::ReplayedObservation { attempt_id: 11 })
    );
    assert_eq!(settled.state(), settled_state);
    let second = observation(&settled, 12, 404, HttpProbeBody::Empty);
    assert_eq!(
        settled.observe(&second),
        Err(HttpFallbackError::ObservationAlreadyAdmitted {
            admitted_attempt: 11
        })
    );
    assert_eq!(settled.state(), settled_state);

    // ---------------------------------------------------------------------
    // Only `Auto` coordinates a fallback.
    // ---------------------------------------------------------------------
    for policy in [ProtocolPolicy::ModernOnly, ProtocolPolicy::LegacyOnly] {
        assert_eq!(
            HttpFallbackCoordinator::new(plan_with(
                policy,
                MODERN_TARGET,
                LEGACY_SSE_TARGET,
                SECURITY_PARTITION,
                1,
            ))
            .err(),
            Some(HttpFallbackError::PolicyForbidsFallback { policy }),
            "{policy:?} must not coordinate an HTTP fallback"
        );
    }

    // An observation must carry a real binding.
    assert_eq!(
        ModernProbeObservation::new(
            coordinator().bundle_key().clone(),
            "",
            1,
            HttpModernProbe {
                status: 404,
                body: HttpProbeBody::Empty,
            },
        )
        .err(),
        Some(HttpFallbackError::InvalidObservation)
    );
    assert_eq!(
        ModernProbeObservation::new(
            coordinator().bundle_key().clone(),
            MODERN_TARGET,
            0,
            HttpModernProbe {
                status: 404,
                body: HttpProbeBody::Empty,
            },
        )
        .err(),
        Some(HttpFallbackError::InvalidObservation)
    );

    // Every case above is conditional on the caller asking. This is not.
    assert_permit_issuance_is_sole_sourced();
}

/// A coordinator that authorized and opened its one legacy GET from the
/// accepted `404`/`Unrecognized` row, with no endpoint event admitted yet.
fn authorized_and_opened() -> HttpFallbackCoordinator {
    let mut coordinator = coordinator();
    let observed = observation(&coordinator, 5, 404, HttpProbeBody::Unrecognized);
    let FallbackDecision::LegacyGetAuthorized(permit) = coordinator
        .observe(&observed)
        .expect("404/Unrecognized authorizes one GET")
    else {
        panic!("404/Unrecognized must authorize a legacy GET");
    };
    coordinator
        .open_legacy_get(permit)
        .expect("the single authorization opens one GET");
    coordinator
}

/// Structural proof that a legacy `GET` authorization has exactly one issuer.
///
/// Every behavioral case drives the coordinator through its public methods.
/// This complementary source check guards the shipped permit's private fields,
/// accessor-only inherent impl, and single construction site inside `observe`.
/// It does not establish that a live transport consults the coordinator.
///
/// The former two-field layout did not bind the issuing coordinator. The
/// reviewed layout now requires the private `owner: Arc<()>` as well as target
/// and attempt, and the public behavioral regressions below exercise that
/// ownership. No constructor, public field, or extra issuance site is allowed.
/// This line-oriented check is not an AST proof of arbitrary Rust syntax.
fn assert_permit_issuance_is_sole_sourced() {
    let leg_neg = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src/leg_neg.rs");
    let source = std::fs::read_to_string(&leg_neg)
        .unwrap_or_else(|error| panic!("the shipped coordinator source must be readable: {error}"));

    let mut violations = Vec::new();

    // (1) and (2): the permit's only struct-literal construction, and the
    // function that encloses it.
    let mut constructions = Vec::new();
    let mut current = "<none>";
    for line in source.lines() {
        let trimmed = line.trim_start();
        if line.len() - trimmed.len() <= 4 {
            if let Some(rest) = trimmed
                .strip_prefix("pub fn ")
                .or_else(|| trimmed.strip_prefix("fn "))
                .or_else(|| trimmed.strip_prefix("pub const fn "))
                .or_else(|| trimmed.strip_prefix("const fn "))
            {
                current = rest.split(['(', '<']).next().unwrap_or("<none>");
            }
        }
        if trimmed.contains("LegacyGetPermit {")
            && !trimmed.starts_with("pub struct ")
            && !trimmed.starts_with("impl ")
        {
            constructions.push(current);
        }
    }
    if constructions.len() != 1 {
        violations.push(format!(
            "LegacyGetPermit must be constructed at exactly one site; found {constructions:?}"
        ));
    }
    if constructions != ["observe"] {
        violations.push(format!(
            "the only permit construction must sit inside `observe`; found {constructions:?}"
        ));
    }

    // (3): the permit's inherent impl exposes accessors only - no constructor.
    let mut methods = Vec::new();
    let mut inside = false;
    let mut saw_impl = false;
    for line in source.lines() {
        if line.starts_with("impl LegacyGetPermit {") {
            inside = true;
            saw_impl = true;
            continue;
        }
        if inside {
            if line == "}" {
                break;
            }
            let trimmed = line.trim_start();
            if let Some(rest) = trimmed
                .strip_prefix("pub fn ")
                .or_else(|| trimmed.strip_prefix("fn "))
                .or_else(|| trimmed.strip_prefix("pub const fn "))
                .or_else(|| trimmed.strip_prefix("const fn "))
            {
                methods.push(rest.split(['(', '<']).next().unwrap_or("<none>").to_owned());
            }
        }
    }
    if !saw_impl {
        violations.push(
            "`impl LegacyGetPermit` was not found: this guard cannot see its subject".to_owned(),
        );
    }
    methods.sort();
    if saw_impl && methods != ["attempt_id", "target"] {
        violations.push(format!(
            "`impl LegacyGetPermit` must expose the two accessors and no constructor; \
             found {methods:?}"
        ));
    }

    // (4): require the complete private binding, not merely a field count.
    let mut public_fields = Vec::new();
    let mut fields = Vec::new();
    let mut inside = false;
    let mut saw_struct = false;
    for line in source.lines() {
        if line.starts_with("pub struct LegacyGetPermit {") {
            inside = true;
            saw_struct = true;
            continue;
        }
        if inside {
            if line == "}" {
                break;
            }
            let trimmed = line.trim();
            if trimmed.contains(':') && !trimmed.starts_with("//") {
                fields.push(trimmed.to_owned());
            }
            if trimmed.starts_with("pub ") || trimmed.starts_with("pub(") {
                public_fields.push(trimmed.to_owned());
            }
        }
    }
    if !saw_struct {
        violations.push(
            "`pub struct LegacyGetPermit` was not found: this guard cannot see its subject"
                .to_owned(),
        );
    }
    if saw_struct && fields != ["target: String,", "attempt_id: u64,", "owner: Arc<()>,"] {
        violations.push(format!(
            "LegacyGetPermit must carry its private target, attempt and allocation owner; \
             found {fields:?}"
        ));
    }
    if !public_fields.is_empty() {
        violations.push(format!(
            "every LegacyGetPermit field must stay private; found public {public_fields:?}"
        ));
    }

    assert!(
        violations.is_empty(),
        "the legacy GET authorization boundary moved: {violations:#?}"
    );
}

#[test]
fn leg_neg_01_b_planted_negative() {
    // The accepted row. Status, target, attempt, plan, and every call below are
    // identical between the two halves of this test.
    let mut accepted = coordinator();
    let accepted_observation = observation(&accepted, 5, 404, HttpProbeBody::Unrecognized);
    let accepted_decision = accepted
        .observe(&accepted_observation)
        .expect("404/Unrecognized authorizes exactly one legacy GET");
    let FallbackDecision::LegacyGetAuthorized(permit) = accepted_decision else {
        panic!("the accepted row must authorize a legacy GET");
    };
    let accepted_target = accepted
        .open_legacy_get(permit)
        .expect("the accepted row opens its one GET");
    assert_eq!(accepted_target, LEGACY_SSE_TARGET);
    assert_eq!(
        accepted
            .admit_endpoint_event(LEGACY_MESSAGE_TARGET)
            .expect("the accepted row selects on its first valid endpoint event"),
        ProtocolEra::Legacy2024
    );
    let accepted_state = accepted.state();
    assert_eq!(accepted_state.legacy_gets_authorized, 1);
    assert_eq!(accepted_state.legacy_gets_opened, 1);
    assert_eq!(accepted_state.endpoint_events_admitted, 1);
    assert_eq!(accepted_state.selected_era, Some(ProtocolEra::Legacy2024));

    // The planted row. The ONLY changed variable is the probe body class: a
    // recognized modern JSON-RPC error is treated as GET-eligible. Status 404,
    // the attempt id, the plan, the target, and the call sequence are unchanged.
    let mut planted = coordinator();
    let planted_observation = observation(&planted, 5, 404, RECOGNIZED_MODERN);
    assert_eq!(
        planted_observation.probe().status,
        accepted_observation.probe().status,
        "the planted row changes only the body class"
    );
    assert_eq!(
        planted_observation.attempt_id(),
        accepted_observation.attempt_id()
    );
    assert_eq!(
        planted_observation.modern_target(),
        accepted_observation.modern_target()
    );
    assert_eq!(
        planted_observation.bundle_key(),
        accepted_observation.bundle_key()
    );
    assert_ne!(
        planted_observation.probe().body,
        accepted_observation.probe().body
    );

    // The typed boundary refuses to treat it as GET-eligible: no permit exists,
    // so the caller cannot open a GET at all.
    let planted_decision = planted
        .observe(&planted_observation)
        .expect("a recognized modern body is still an evaluated row");
    assert!(
        matches!(planted_decision, FallbackDecision::ModernRetained),
        "a recognized modern JSON-RPC error must never authorize a legacy GET"
    );

    let after_observe = planted.state();
    assert_eq!(after_observe.observations_admitted, 1);
    assert_eq!(
        after_observe.legacy_gets_authorized, 0,
        "zero GET authorizations on the planted row"
    );
    assert_eq!(
        after_observe.legacy_gets_opened, 0,
        "zero legacy GET opened"
    );

    // Proceeding as if it had been eligible reaches the typed refusal.
    assert_eq!(
        planted.admit_endpoint_event(LEGACY_MESSAGE_TARGET),
        Err(HttpFallbackError::EndpointEventWithoutAuthorization),
        "no endpoint event may be admitted without an authorized, opened GET"
    );

    // Every named mutable field is byte-for-byte what it was before the refused
    // call, and the era was never selected.
    assert_eq!(
        planted.state(),
        after_observe,
        "the refused endpoint event must change no observable field"
    );
    assert_inert(&planted, "planted recognized-modern row");
    assert_eq!(
        planted.selected_era(),
        None,
        "the planted row must not reach an era selection"
    );
    assert_ne!(
        planted.state().selected_era,
        accepted_state.selected_era,
        "the accepted and planted rows must terminate differently"
    );

    // The coordinator's own endpoint binding is untouched by the refusal.
    assert_eq!(planted.legacy_sse_target(), LEGACY_SSE_TARGET);
    assert_eq!(planted.bundle_key(), accepted.bundle_key());
}

fn authorize(coordinator: &mut HttpFallbackCoordinator) -> FallbackDecision {
    let observed = observation(coordinator, 1, 404, HttpProbeBody::Unrecognized);
    coordinator.observe(&observed).expect("eligible observation")
}

// These ownership regressions use the shipped public API rather than private
// fields or test-only constructors. Moving them here also keeps test helper
// signatures outside the production-source issuance inventory above.
#[test]
fn locally_issued_permit_opens_only_its_own_get() {
    let mut owner = coordinator();
    let FallbackDecision::LegacyGetAuthorized(permit) = authorize(&mut owner) else {
        panic!("eligible probe must authorize a GET");
    };
    assert_eq!(permit.target(), LEGACY_SSE_TARGET);
    assert_eq!(permit.attempt_id(), 1);
    assert_eq!(owner.open_legacy_get(permit).unwrap(), LEGACY_SSE_TARGET);
    assert_eq!(owner.state().legacy_gets_authorized, 1);
    assert_eq!(owner.state().legacy_gets_opened, 1);
    assert_eq!(owner.selected_era(), None);
    assert_eq!(owner.advertised_message_post_target(), None);
}

#[test]
fn same_bundle_and_attempt_cannot_exchange_permits() {
    let mut owner = coordinator();
    let mut other = coordinator();
    let FallbackDecision::LegacyGetAuthorized(owner_permit) = authorize(&mut owner) else {
        panic!("owner must authorize a GET");
    };
    let FallbackDecision::LegacyGetAuthorized(other_permit) = authorize(&mut other) else {
        panic!("other must authorize a GET");
    };
    assert_ne!(owner_permit, other_permit);
    let before = owner.state();
    assert_eq!(
        owner.open_legacy_get(other_permit),
        Err(HttpFallbackError::CrossBundleObservation)
    );
    assert_eq!(owner.state(), before);
    assert_eq!(owner.advertised_message_post_target(), None);
    // A rejected foreign permit does not consume the legitimate authorization.
    assert_eq!(owner.open_legacy_get(owner_permit).unwrap(), LEGACY_SSE_TARGET);
}

#[test]
fn foreign_permit_cannot_override_a_recognized_modern_response() {
    let mut modern = coordinator();
    let mut legacy = coordinator();
    let FallbackDecision::LegacyGetAuthorized(foreign_permit) = authorize(&mut legacy) else {
        panic!("legacy candidate must authorize a GET");
    };
    let observed = observation(&modern, 1, 404, RECOGNIZED_MODERN);
    assert_eq!(modern.observe(&observed).unwrap(), FallbackDecision::ModernRetained);
    let before = modern.state();
    assert_eq!(
        modern.open_legacy_get(foreign_permit),
        Err(HttpFallbackError::LegacyGetNotAuthorized)
    );
    assert_eq!(modern.state(), before);
    assert_inert(&modern, "foreign permit cannot override modern evidence");
}

#[test]
fn same_target_and_attempt_cannot_cross_security_partitions() {
    let mut owner = coordinator();
    let mut other = HttpFallbackCoordinator::new(plan_with(
        ProtocolPolicy::Auto,
        MODERN_TARGET,
        LEGACY_SSE_TARGET,
        "other-principal",
        1,
    ))
    .unwrap();
    let FallbackDecision::LegacyGetAuthorized(owner_permit) = authorize(&mut owner) else {
        panic!("owner must authorize a GET");
    };
    let FallbackDecision::LegacyGetAuthorized(other_permit) = authorize(&mut other) else {
        panic!("other must authorize a GET");
    };
    let before = owner.state();
    assert_eq!(
        owner.open_legacy_get(other_permit),
        Err(HttpFallbackError::CrossBundleObservation)
    );
    assert_eq!(owner.state(), before);
    assert_eq!(owner.open_legacy_get(owner_permit).unwrap(), LEGACY_SSE_TARGET);
}

#[test]
fn retired_coordinator_permit_cannot_authorize_a_replacement_attempt() {
    let stale = {
        let mut retired = coordinator();
        authorize(&mut retired)
    };
    let FallbackDecision::LegacyGetAuthorized(stale_permit) = stale else {
        panic!("retired coordinator must have authorized a GET");
    };
    let mut replacement = coordinator();
    let FallbackDecision::LegacyGetAuthorized(fresh_permit) = authorize(&mut replacement) else {
        panic!("replacement must authorize a GET");
    };
    let before = replacement.state();
    assert_eq!(
        replacement.open_legacy_get(stale_permit),
        Err(HttpFallbackError::CrossBundleObservation)
    );
    assert_eq!(replacement.state(), before);
    assert_eq!(replacement.open_legacy_get(fresh_permit).unwrap(), LEGACY_SSE_TARGET);
}

#[test]
fn endpoint_event_selects_message_post_not_sse_get() {
    let mut accepted = authorized_and_opened();
    assert_eq!(accepted.legacy_sse_target(), LEGACY_SSE_TARGET);
    assert_eq!(accepted.legacy_message_post_target(), LEGACY_MESSAGE_TARGET);
    assert_eq!(accepted.advertised_message_post_target(), None);
    assert_eq!(
        accepted.admit_endpoint_event(LEGACY_MESSAGE_TARGET),
        Ok(ProtocolEra::Legacy2024)
    );
    assert_eq!(accepted.advertised_message_post_target(), Some(LEGACY_MESSAGE_TARGET));

    // Only the event's route changes: advertising the GET route is not proof
    // that the configured message POST route exists.
    let mut rejected = authorized_and_opened();
    let before = rejected.state();
    assert_eq!(
        rejected.admit_endpoint_event(LEGACY_SSE_TARGET),
        Err(HttpFallbackError::EndpointEventTargetMismatch)
    );
    assert_eq!(rejected.state(), before);
    assert_eq!(rejected.advertised_message_post_target(), None);
}

#[test]
fn admitted_session_target_is_retained_and_cannot_be_replaced() {
    let mut coordinator = authorized_and_opened();
    let first = format!("{LEGACY_MESSAGE_TARGET}?session_id=private-a%2Fb%23c");
    assert_eq!(coordinator.admit_endpoint_event(&first), Ok(ProtocolEra::Legacy2024));
    assert_eq!(coordinator.advertised_message_post_target(), Some(first.as_str()));
    let before = coordinator.state();
    let second = format!("{LEGACY_MESSAGE_TARGET}?session_id=private-replacement");
    assert_eq!(
        coordinator.admit_endpoint_event(&second),
        Err(HttpFallbackError::DuplicateEndpointEvent)
    );
    assert_eq!(coordinator.state(), before);
    assert_eq!(coordinator.advertised_message_post_target(), Some(first.as_str()));
    assert!(!format!("{coordinator:?}").contains("private-a"));
    assert!(!format!("{coordinator:?}").contains("session_id"));
}

#[test]
fn malformed_endpoint_queries_never_select_or_retain_a_target() {
    let malformed = [
        format!(" {LEGACY_MESSAGE_TARGET}"),
        format!("{LEGACY_MESSAGE_TARGET} "),
        format!("{LEGACY_MESSAGE_TARGET}?session_id=abc#fragment"),
        format!("{LEGACY_MESSAGE_TARGET}?session_id=abc#"),
        format!("{LEGACY_MESSAGE_TARGET}?session_id=%"),
        format!("{LEGACY_MESSAGE_TARGET}?session_id=has space"),
        format!("{LEGACY_MESSAGE_TARGET}?session_id=abc\r\nInjected: yes"),
        "https://user:password@mcp.example.test/messages".to_owned(),
        format!("{LEGACY_MESSAGE_TARGET}?session_id={}", "x".repeat(65_537)),
    ];
    for advertised in malformed {
        let mut coordinator = authorized_and_opened();
        let before = coordinator.state();
        let error = coordinator.admit_endpoint_event(&advertised).unwrap_err();
        assert_eq!(error, HttpFallbackError::EndpointEventMalformed);
        assert_eq!(coordinator.state(), before);
        assert_eq!(coordinator.advertised_message_post_target(), None);
        assert!(!error.to_string().contains("session_id"));
        assert!(!error.to_string().contains("password"));
        // Refusing bad bytes did not destroy the valid path.
        assert_eq!(
            coordinator.admit_endpoint_event(LEGACY_MESSAGE_TARGET),
            Ok(ProtocolEra::Legacy2024)
        );
    }
}

#[test]
fn query_free_target_does_not_admit_an_empty_query_or_another_route() {
    for advertised in [
        format!("{LEGACY_MESSAGE_TARGET}?"),
        format!("{LEGACY_SSE_TARGET}?session_id=abc"),
        "https://other.example.test/messages?session_id=abc".to_owned(),
        "https://mcp.example.test/messages/extra?session_id=abc".to_owned(),
    ] {
        let mut coordinator = authorized_and_opened();
        let before = coordinator.state();
        assert_eq!(
            coordinator.admit_endpoint_event(&advertised),
            Err(HttpFallbackError::EndpointEventTargetMismatch)
        );
        assert_eq!(coordinator.state(), before);
        assert_eq!(coordinator.advertised_message_post_target(), None);
    }
}

#[test]
fn configured_message_query_is_immutable() {
    let configured = format!("{LEGACY_MESSAGE_TARGET}?tenant=alice");
    let plan = ClientProtocolPlan::http(
        ProtocolPolicy::Auto,
        Some(url(MODERN_TARGET)),
        Some(url(LEGACY_SSE_TARGET)),
        Some(url(&configured)),
        "credential-partition-leg-neg-01-b".to_owned(),
        SECURITY_PARTITION.to_owned(),
        "native-h1-leg-neg-01-b".to_owned(),
        1,
        1,
        0,
    )
    .expect("a configured query is part of the immutable bundle");
    for changed in [
        LEGACY_MESSAGE_TARGET.to_owned(),
        format!("{LEGACY_MESSAGE_TARGET}?tenant=bob"),
        format!("{configured}&session_id=abc"),
    ] {
        let mut coordinator = HttpFallbackCoordinator::new(plan.clone()).unwrap();
        let FallbackDecision::LegacyGetAuthorized(permit) = authorize(&mut coordinator) else {
            panic!("eligible probe must authorize the candidate GET");
        };
        coordinator.open_legacy_get(permit).unwrap();
        let before = coordinator.state();
        assert_eq!(
            coordinator.admit_endpoint_event(&changed),
            Err(HttpFallbackError::EndpointEventTargetMismatch)
        );
        assert_eq!(coordinator.state(), before);
        assert_eq!(coordinator.advertised_message_post_target(), None);
        assert_eq!(coordinator.admit_endpoint_event(&configured), Ok(ProtocolEra::Legacy2024));
        assert_eq!(coordinator.advertised_message_post_target(), Some(configured.as_str()));
    }
}
