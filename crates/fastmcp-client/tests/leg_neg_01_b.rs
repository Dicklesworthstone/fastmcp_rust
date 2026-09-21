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
            .admit_endpoint_event(LEGACY_SSE_TARGET)
            .expect("the first valid endpoint event selects the exact-2024 era"),
        ProtocolEra::Legacy2024
    );
    assert_eq!(selecting.selected_era(), Some(ProtocolEra::Legacy2024));
    assert_eq!(selecting.state().endpoint_events_admitted, 1);
    assert_eq!(selecting.state().credential_mutations, 0);
    assert_eq!(selecting.state().era_cache_mutations, 0);

    // A second event cannot re-select or change the era.
    let selected_state = selecting.state();
    assert_eq!(
        selecting.admit_endpoint_event(LEGACY_SSE_TARGET),
        Err(HttpFallbackError::DuplicateEndpointEvent)
    );
    assert_eq!(selecting.state(), selected_state);

    // A server-generated session query on a query-free configured target is
    // admissible; scheme, authority and path still cannot move.
    let mut session_query = authorized_and_opened();
    assert_eq!(
        session_query
            .admit_endpoint_event(&format!("{LEGACY_SSE_TARGET}?session_id=abc123"))
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
        "https://other.example.test/sse",
        "http://mcp.example.test/sse",
        "https://mcp.example.test/sse/extra",
        "https://mcp.example.test/messages",
    ] {
        let mut coordinator = authorized_and_opened();
        let before = coordinator.state();
        assert_eq!(
            coordinator.admit_endpoint_event(mismatched),
            Err(HttpFallbackError::EndpointEventTargetMismatch),
            "{mismatched} is not the configured legacy target"
        );
        assert_eq!(coordinator.state(), before);
        assert_eq!(coordinator.selected_era(), None);
    }

    // An endpoint event without an authorized, opened GET selects nothing.
    let mut unauthorized = coordinator();
    assert_eq!(
        unauthorized.admit_endpoint_event(LEGACY_SSE_TARGET),
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
        recognized.admit_endpoint_event(LEGACY_SSE_TARGET),
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
/// WHY THIS CANNOT BE AN OBSERVATIONAL TEST, WHICH IS THE WHOLE POINT.
/// Every case above drives the coordinator through its own public methods, so
/// each one is conditional on the caller choosing to ask. They prove that *this*
/// coordinator refuses an ineligible row; none of them can prove that a legacy
/// `GET` has no other door. The property that makes "downgrade-resistant" mean
/// anything is that [`LegacyGetPermit`] is unforgeable: private fields, no
/// public constructor, and exactly one struct-literal site, inside `observe`.
/// That is a claim about the shipped source, and no value assertion reaches it.
///
/// WHAT THIS DELIBERATELY DOES NOT CLAIM. It does not show that any production
/// path consults the coordinator - as of this commit nothing outside `lib.rs`
/// re-exports names it at all, and wiring it is LEG-HTTP-01's work, not this
/// leaf's. This guard fixes the boundary so that whoever wires it cannot
/// quietly route around it.
///
/// MUTATION BEHAVIOUR, which is what makes this a real check rather than a
/// restatement: adding `pub fn new` to the permit, publishing a field, adding a
/// second construction site, deleting the only one, adding a third field, or
/// renaming either anchor out from under the guard each produce a distinct
/// failure. All seven were run against a mutated copy of the shipped source
/// before this was committed; the two anchor cases exist because an earlier
/// draft passed vacuously when it could not find its own subject.
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

    // (4): every field is private, so no external crate can build one literally.
    let mut public_fields = Vec::new();
    let mut inside = false;
    let mut saw_struct = false;
    let mut field_count = 0_usize;
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
            let trimmed = line.trim_start();
            if trimmed.contains(':') && !trimmed.starts_with("//") {
                field_count += 1;
            }
            if let Some(rest) = trimmed.strip_prefix("pub ") {
                public_fields.push(rest.split(':').next().unwrap_or("<none>").to_owned());
            }
        }
    }
    if !saw_struct {
        violations.push(
            "`pub struct LegacyGetPermit` was not found: this guard cannot see its subject"
                .to_owned(),
        );
    }
    if saw_struct && field_count != 2 {
        violations.push(format!(
            "LegacyGetPermit must carry exactly its two bound fields; found {field_count}"
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
            .admit_endpoint_event(LEGACY_SSE_TARGET)
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
        planted.admit_endpoint_event(LEGACY_SSE_TARGET),
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
