use super::*;
use std::time::Duration;

fn url(text: &str) -> CanonicalHttpUrl { CanonicalHttpUrl::parse(text).unwrap() }
fn strings(values: &[&str]) -> Vec<String> { values.iter().map(|value| (*value).to_owned()).collect() }
fn plan() -> OAuthDiscoveryPlan {
    OAuthDiscoveryPlan::new(url("https://resource.example/mcp"),
        vec![TrustedOAuthIssuer::new("https://issuer.example").unwrap()],
        "registered", strings(&["read"])).unwrap()
}
fn parse(value: &str) -> Result<InsufficientScopeChallenge, OAuthScopeStepUpError> {
    InsufficientScopeChallenge::from_response(url("https://resource.example/mcp"), 403,
        &[("WWW-Authenticate".to_owned(), value.to_owned())])
}
fn challenge(scopes: &str) -> InsufficientScopeChallenge {
    parse(&format!("Bearer error=insufficient_scope, scope=\"{scopes}\"")).unwrap()
}
fn owner() -> ScopeStepUp { ScopeStepUp::new(plan(), &strings(&["read", "history"]), 3).unwrap() }
fn issuer_document(scopes: serde_json::Value) -> Vec<u8> {
    serde_json::to_vec(&serde_json::json!({
        "issuer":"https://issuer.example",
        "authorization_endpoint":"https://issuer.example/authorize",
        "token_endpoint":"https://issuer.example/token",
        "response_types_supported":["code"],
        "token_endpoint_auth_methods_supported":["none"],
        "code_challenge_methods_supported":["S256"],
        "authorization_response_iss_parameter_supported":true,
        "scopes_supported":scopes,
    })).unwrap()
}

#[test]
fn complete_bearer_error_and_scope_survive_repeated_fields_and_quoted_commas() {
    let parsed = InsufficientScopeChallenge::from_response(url("https://resource.example/mcp"), 403, &[
        ("WWW-Authenticate".to_owned(), "Basic realm=\"other, service\", scope=admin, bEaReR error=insufficient_scope".to_owned()),
        ("www-authenticate".to_owned(), "scope=\"write read write\", resource_metadata=\"https://resource.example/meta?tenant=a,b\"".to_owned()),
    ]).unwrap();
    assert_eq!(parsed.required_scopes(), strings(&["write", "read"]));
    assert_eq!(parsed.metadata_url().unwrap().as_str(), "https://resource.example/meta?tenant=a,b");
    assert!(parse("Bearer realm=other, Bearer error=insufficient_scope, scope=write").is_ok());
}

#[test]
fn errors_and_scopes_cannot_be_spliced_across_challenges_or_schemes() {
    for text in [
        "Bearer error=insufficient_scope, Bearer scope=write",
        "Bearer error=invalid_token, scope=read, Bearer error=insufficient_scope, scope=write",
        "Bearer error=insufficient_scope, scope=write, Bearer error=insufficient_scope, scope=write",
    ] { assert!(matches!(parse(text), Err(OAuthScopeStepUpError::AmbiguousChallenge))); }
    for text in [
        "Basic error=insufficient_scope, Bearer scope=write",
        "Bearer error=insufficient_scope, Basic scope=write",
        "Basic error=insufficient_scope, scope=write",
        "Bearer error=invalid_token, scope=write",
        "Bearer error=INSUFFICIENT_SCOPE, scope=write",
        "Bearer YWJjZA==", "Bearer error=insufficient_scope", "Bearer scope=write",
    ] { assert!(matches!(parse(text), Err(OAuthScopeStepUpError::MissingInsufficientScope))); }
}

#[test]
fn duplicate_malformed_and_oversized_parameters_remain_terminal() {
    for text in [
        "Bearer error=insufficient_scope, ERROR=insufficient_scope, scope=write",
        "Bearer error=insufficient_scope, scope=read, SCOPE=write",
        "Bearer error=insufficient_scope, scope=\"write  read\"",
        "Bearer error=insufficient_scope, scope=\"write\r\nread\"",
        "Bearer error=insufficient_scope, scope=write, resource_metadata=\"http://resource.example/meta\"",
        "Bearer error=insufficient_scope, scope=write, resource_metadata=\"/relative\"",
    ] { assert!(parse(text).is_err()); }
    assert!(parse(&format!("Bearer error=insufficient_scope, scope=\"{}\"", "s".repeat(257))).is_err());
    assert!(parse(&format!("Bearer error=insufficient_scope, scope=\"{}\"", "x ".repeat(4096))).is_err());
    let headers = vec![("Other".to_owned(), String::new()); 129];
    assert!(InsufficientScopeChallenge::from_response(url("https://resource.example/mcp"), 403, &headers).is_err());
}

#[test]
fn only_verified_resource_403_www_authenticate_heads_are_scope_inputs() {
    for status in [200, 302, 400, 401, 407, 500] {
        assert!(matches!(InsufficientScopeChallenge::from_response(url("https://resource.example/mcp"), status,
            &[("WWW-Authenticate".to_owned(), "Bearer error=insufficient_scope, scope=write".to_owned())]),
            Err(OAuthScopeStepUpError::UnsupportedStatus { .. })));
    }
    assert!(InsufficientScopeChallenge::from_response(url("http://resource.example/mcp"), 403, &[]).is_err());
    assert!(matches!(InsufficientScopeChallenge::from_response(url("https://resource.example/mcp"), 403,
        &[("Proxy-Authenticate".to_owned(), "Bearer error=insufficient_scope, scope=write".to_owned())]),
        Err(OAuthScopeStepUpError::MissingInsufficientScope)));
}

#[test]
fn approval_preserves_grants_without_requesting_the_whole_host_allowlist() {
    let mut owner = owner();
    let approved = owner.approve(challenge("write read"), &strings(&["write", "unneeded-admin"])).unwrap();
    assert_eq!(approved.requested_scopes(), strings(&["read", "history", "write"]));
    assert_eq!(owner.requested_scopes(), approved.requested_scopes());
    assert_eq!(owner.attempts(), 1);
    assert_eq!(owner.remaining_attempts(), 2);
    assert_eq!(approved.requested.client_id.as_deref(), Some("registered"));
    assert_eq!(approved.requested.issuers[0].identifier, "https://issuer.example");
    assert!(approved.discovery.plan.scopes.is_empty());
}

#[test]
fn refusal_is_atomic_and_does_not_spend_an_attempt_or_accumulate_scopes() {
    let mut owner = owner();
    assert!(matches!(owner.approve(challenge("write admin"), &strings(&["write"])),
        Err(OAuthScopeStepUpError::ApprovalRequired)));
    assert_eq!(owner.attempts(), 0);
    assert_eq!(owner.requested_scopes(), strings(&["read", "history"]));
    let wrong_resource = InsufficientScopeChallenge::from_response(url("https://resource.example/other"), 403,
        &[("WWW-Authenticate".to_owned(), "Bearer error=insufficient_scope, scope=write".to_owned())]).unwrap();
    assert!(matches!(owner.approve(wrong_resource, &strings(&["write"])),
        Err(OAuthScopeStepUpError::Challenge(OAuthChallengeError::ResourceMismatch))));
    assert_eq!(owner.attempts(), 0);
    assert!(owner.approve(challenge("write"), &strings(&["write"])).is_ok());
}

#[test]
fn abandoned_approvals_still_stop_repeated_and_unbounded_upgrade_loops() {
    let mut owner = owner();
    drop(owner.approve(challenge("write"), &strings(&["write"])).unwrap());
    assert!(matches!(owner.approve(challenge("write history read"), &strings(&["write"])),
        Err(OAuthScopeStepUpError::NoScopeIncrease)));
    assert_eq!(owner.attempts(), 1);
    drop(owner.approve(challenge("share"), &strings(&["share"])).unwrap());
    drop(owner.approve(challenge("archive"), &strings(&["archive"])).unwrap());
    assert_eq!(owner.remaining_attempts(), 0);
    assert!(matches!(owner.approve(challenge("delete"), &strings(&["delete"])), Err(OAuthScopeStepUpError::AttemptLimit)));
    assert!(!owner.requested_scopes().contains(&"delete".to_owned()));
}

#[test]
fn scope_names_are_case_sensitive_and_cumulative_sets_are_bounded() {
    let mut owner = owner();
    assert!(matches!(owner.approve(challenge("WRITE"), &strings(&["write"])), Err(OAuthScopeStepUpError::ApprovalRequired)));
    assert!(owner.approve(challenge("WRITE"), &strings(&["WRITE"])).is_ok());
    assert!(scope_set(["bad scope"]).is_err());
    assert!(scope_set(["réad"]).is_err());
    let full: Vec<_> = (0..MAX_SCOPES).map(|index| format!("s{index}")).collect();
    let mut full_plan = plan();
    full_plan.scopes = full.clone();
    let mut full_owner = ScopeStepUp::new(full_plan, &[], 1).unwrap();
    assert!(matches!(full_owner.approve(challenge("extra"), &strings(&["extra"])), Err(OAuthScopeStepUpError::InvalidPolicy)));
    assert_eq!(full_owner.attempts(), 0);
    assert_eq!(full_owner.requested_scopes(), full);
    let long: Vec<_> = (0..17).map(|index| format!("{index:03}{}", "x".repeat(253))).collect();
    assert!(scope_set(long.iter().map(String::as_str)).is_err());
    assert!(scope_set(std::iter::repeat_n("same", 65)).is_err());
}

#[test]
fn original_issuer_and_preregistered_client_are_mandatory() {
    for attempts in [0, 4, usize::MAX] {
        assert!(ScopeStepUp::new(plan(), &[], attempts).is_err());
    }
    let mut multiple = plan();
    multiple.issuers.push(TrustedOAuthIssuer::new("https://other.example").unwrap());
    assert!(ScopeStepUp::new(multiple, &[], 1).is_err());
    let mut unregistered = plan();
    unregistered.client_id = None;
    assert!(ScopeStepUp::new(unregistered, &[], 1).is_err());
}

#[test]
fn dynamic_scopes_do_not_need_to_be_advertised_but_native_trust_still_applies() {
    let approved = owner().approve(challenge("dynamic-write"), &strings(&["dynamic-write"])).unwrap();
    let endpoint_plan = &approved.discovery.plan;
    let prm = serde_json::to_vec(&serde_json::json!({
        "resource":"https://resource.example/mcp", "authorization_servers":["https://issuer.example"],
        "scopes_supported":["unrelated-basic"],
    })).unwrap();
    assert!(endpoint_plan.select_issuer(&prm).is_ok());
    let issuer = &endpoint_plan.issuers[0];
    let body = issuer_document(serde_json::json!(["unrelated-basic"]));
    let configuration = approved.admit_issuer(issuer, &body).unwrap();
    let expected = OAuthClientConfiguration::from_trusted_endpoints("https://issuer.example",
        url("https://issuer.example/authorize"), url("https://issuer.example/token"),
        url("https://resource.example/mcp"), "registered", strings(&["read", "history", "dynamic-write"])).unwrap();
    assert_eq!(configuration, expected);
    // The ordinary configured-scope path has NOT had its admission weakened.
    assert!(matches!(approved.requested.admit_issuer(issuer, &body), Err(OAuthDiscoveryError::UnsupportedScopes)));
    for (field, value) in [
        ("issuer", serde_json::json!("https://evil.example")),
        ("token_endpoint", serde_json::json!("https://evil.example/token")),
        ("code_challenge_methods_supported", serde_json::json!(["plain"])),
        ("scopes_supported", serde_json::json!(["duplicate", "duplicate"])),
    ] {
        let mut rejected: serde_json::Value = serde_json::from_slice(&body).unwrap();
        rejected[field] = value;
        assert!(approved.admit_issuer(issuer, &serde_json::to_vec(&rejected).unwrap()).is_err());
    }
}

#[test]
fn metadata_relocation_never_grants_login_endpoint_trust_or_changes_resource() {
    let mut owner = owner();
    let approved = owner.approve(parse("Bearer error=insufficient_scope, scope=write, resource_metadata=\"https://metadata.example/meta\"").unwrap(),
        &strings(&["write"])).unwrap();
    assert!(matches!(approved.discovery.location(), Err(OAuthChallengeError::MetadataOriginNotTrusted)));
    let approved = approved.with_metadata_origin(url("https://metadata.example/")).unwrap();
    assert!(approved.discovery.location().unwrap().is_some());
    assert!(approved.requested.issuers[0].endpoint("https://metadata.example/token").is_err());
    assert_eq!(approved.requested.resource.as_str(), "https://resource.example/mcp");
}

#[test]
fn issuer_revocation_and_discovery_timeout_are_preserved() {
    let configured = plan().with_timeout(Duration::from_secs(7)).unwrap();
    let mut owner = ScopeStepUp::new(configured, &[], 1).unwrap();
    let approved = owner.approve(challenge("write"), &strings(&["write"])).unwrap();
    assert_eq!(approved.discovery.plan.timeout, Duration::from_secs(7));
    let issuer = &approved.discovery.plan.issuers[0];
    let mut document: serde_json::Value = serde_json::from_slice(&issuer_document(serde_json::json!(["read"]))).unwrap();
    document["revocation_endpoint"] = serde_json::json!("https://issuer.example/revoke");
    document["revocation_endpoint_auth_methods_supported"] = serde_json::json!(["none"]);
    let configured = approved.admit_issuer(issuer, &serde_json::to_vec(&document).unwrap()).unwrap();
    let expected = OAuthClientConfiguration::from_trusted_endpoints("https://issuer.example",
        url("https://issuer.example/authorize"), url("https://issuer.example/token"),
        url("https://resource.example/mcp"), "registered", strings(&["read", "write"])).unwrap()
        .with_trusted_revocation_endpoint(url("https://issuer.example/revoke")).unwrap();
    assert_eq!(configured, expected);
}

#[test]
fn declined_or_narrowed_grants_cannot_claim_scope_recovery() {
    let requested = strings(&["read", "history", "write"]);
    assert!(covers(&requested, &strings(&["history", "write", "read"])));
    assert!(!covers(&requested, &strings(&["read", "write"])));
    assert!(!covers(&requested, &strings(&["read", "history", "WRITE"])));
}

#[test]
fn diagnostics_do_not_retain_peer_or_host_scope_names() {
    let mut owner = owner();
    let challenge = challenge("canary-secret");
    assert!(!format!("{challenge:?}").contains("canary"));
    let approved = owner.approve(challenge, &strings(&["canary-secret"])).unwrap();
    for debug in [format!("{owner:?}"), format!("{approved:?}")] {
        assert!(!debug.contains("canary") && !debug.contains("resource.example"));
    }
}

#[test]
fn pre_cancelled_approval_never_enters_browser_or_network_work() {
    use asupersync::runtime::{RuntimeBuilder, reactor::create_reactor};
    use std::sync::atomic::{AtomicUsize, Ordering};
    let launches = AtomicUsize::new(0);
    let mut owner = owner();
    let approved = owner.approve(challenge("write"), &strings(&["write"])).unwrap();
    RuntimeBuilder::current_thread().with_reactor(create_reactor().unwrap()).build().unwrap().block_on(async {
        let cx = Cx::current().unwrap();
        let cancellation = McpRequestCancellation::new();
        cancellation.cancel();
        let result = approved.authorize_managed_with_cancellation(&cx, &cancellation, OAuthSessionPolicy::default(), |_| async {
            launches.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }).await;
        assert!(matches!(result, Err(OAuthScopeStepUpError::Challenge(OAuthChallengeError::Discovery(OAuthDiscoveryError::Cancelled)))));
    });
    assert_eq!(launches.load(Ordering::SeqCst), 0);
    assert_eq!(owner.attempts(), 1);
}
