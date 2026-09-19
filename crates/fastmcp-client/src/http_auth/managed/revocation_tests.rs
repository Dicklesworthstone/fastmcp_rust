//! Credential-custody regressions using the production snapshot constructor.
//! These tests do not stand in for the separate live TLS login/refresh suite.

use super::*;
use crate::http_auth::oauth::OAuthClientConfiguration;

fn session() -> ManagedOAuthSession {
    let url = |text| CanonicalHttpUrl::parse(text).unwrap();
    let resource = url("https://mcp.example/mcp");
    let configuration = OAuthClientConfiguration::from_trusted_endpoints(
        "https://issuer.example",
        url("https://issuer.example/authorize"),
        url("https://issuer.example/token"),
        resource.clone(),
        "native-client",
        vec![],
    ).unwrap();
    ManagedOAuthSession {
        inner: Arc::new(SessionInner {
            client: OAuthClient::new(configuration),
            resource,
            policy: OAuthSessionPolicy::default(),
            state: Arc::new(Mutex::new(None)),
            closed: McpRequestCancellation::new(),
            logout_handoff: std::sync::atomic::AtomicBool::new(false),
            pending: AtomicUsize::new(0),
        }),
    }
}

fn snapshot(session: &ManagedOAuthSession, token: &str, generation: u64) -> OAuthCredentialSnapshot {
    let expiry = Instant::now() + Duration::from_secs(60);
    let credential = BoundBearerCredential::bind_with_expiry(
        session.resource().clone(), token, expiry,
    ).unwrap();
    OAuthCredentialSnapshot::new(&credential, &[], generation, expiry, &session.inner.closed).unwrap()
}

fn request(target: &str) -> ModernHttpRequest {
    ModernHttpRequest::new(target, b"{}".to_vec(), "2026-07-28", "tools/call", None).unwrap()
}

fn has_authorization(request: &ModernHttpRequest) -> bool {
    request.headers().iter().any(|(name, _)| name.eq_ignore_ascii_case("authorization"))
}

#[test]
fn close_revokes_all_snapshot_generations_without_waiting_for_the_grant_lock() {
    let owner = session();
    let sibling = session();
    let first = snapshot(&owner, "first-secret", 1);
    let second = snapshot(&owner, "second-secret", 2);
    let independent = snapshot(&sibling, "first-secret", 1);
    let first_clone = first.credential().clone();
    let second_clone = second.credential().clone();
    let wire = request(owner.resource().as_str());
    assert!(has_authorization(&first.authorize_request(&wire).unwrap()));
    assert!(has_authorization(&second.authorize_request(&wire).unwrap()));

    // A renewal can retain this lock. Closure must not need it to invalidate
    // credentials that have already escaped as independently owned snapshots.
    let guard = owner.inner.state.try_lock_owned().unwrap();
    owner.close();
    owner.close();
    for credential in [&first_clone, &second_clone, first.credential(), second.credential()] {
        assert!(credential.is_revoked());
        assert_eq!(credential.authorization_for_target(owner.resource()), None);
    }
    assert!(matches!(first.authorize_request(&wire), Err(OAuthSessionError::LoginRequired)));
    assert!(matches!(second.authorize_request(&wire), Err(OAuthSessionError::LoginRequired)));
    assert!(!independent.credential().is_revoked());
    assert!(has_authorization(&independent.authorize_request(&wire).unwrap()));
    assert_eq!(first.generation(), 1);
    assert_eq!(second.generation(), 2);
    drop(guard);
}

#[test]
fn snapshots_do_not_keep_the_last_session_owner_alive() {
    let owner = session();
    let sibling_handle = owner.clone();
    let snapshot = snapshot(&owner, "secret", 1);
    let credential = snapshot.credential().clone();
    let resource = owner.resource().clone();
    drop(owner);
    assert_eq!(credential.authorization_for_target(&resource), Some("Bearer secret".to_owned()));
    drop(sibling_handle);
    assert!(credential.is_revoked());
    assert_eq!(credential.authorization_for_target(&resource), None);
    assert_eq!(snapshot.credential().authorization_for_target(&resource), None);
}

#[test]
fn explicit_token_revocation_does_not_revoke_another_generation_or_close_its_owner() {
    let owner = session();
    let first = snapshot(&owner, "first-secret", 1);
    let second = snapshot(&owner, "second-secret", 2);
    let wire = request(owner.resource().as_str());
    first.credential().revoke();
    assert!(matches!(first.authorize_request(&wire), Err(OAuthSessionError::LoginRequired)));
    assert!(!owner.inner.closed.is_cancel_requested());
    assert!(has_authorization(&second.authorize_request(&wire).unwrap()));
}

#[test]
fn snapshot_admission_preserves_token_revocation_and_refuses_reparenting() {
    let owner = McpRequestCancellation::new();
    let other_owner = McpRequestCancellation::new();
    let resource = CanonicalHttpUrl::parse("https://mcp.example/mcp").unwrap();
    let credential = BoundBearerCredential::bind(resource.clone(), "secret").unwrap();
    let owned = credential.for_owner(&owner).unwrap();
    assert!(owned.for_owner(&other_owner).is_none());
    assert!(!owned.is_revoked());
    owner.cancel();
    assert!(owned.is_revoked());
    assert_eq!(owned.authorization_for_target(&resource), None);
    assert!(!credential.is_revoked(), "ownership constrains only the snapshot");
    credential.revoke();
    let another = credential.for_owner(&other_owner).unwrap();
    assert!(another.is_revoked(), "binding an owner cannot resurrect the token");
    assert_eq!(another.authorization_for_target(&resource), None);
}

#[test]
fn authenticated_request_admission_refuses_wrong_target_expiry_and_revocation() {
    let owner = session();
    let snapshot = snapshot(&owner, "secret", 1);
    let matching = request(owner.resource().as_str());
    assert!(has_authorization(&snapshot.authorize_request(&matching).unwrap()));
    for target in [
        "https://mcp.example/other",
        "https://other.example/mcp",
        "http://mcp.example/mcp",
        "https://mcp.example/mcp?other",
    ] {
        assert!(matches!(snapshot.authorize_request(&request(target)), Err(OAuthSessionError::TargetMismatch)));
    }
    snapshot.credential().revoke();
    assert!(matches!(snapshot.authorize_request(&matching), Err(OAuthSessionError::LoginRequired)));

    let expiry = Instant::now();
    let expired = BoundBearerCredential::bind_with_expiry(owner.resource().clone(), "expired", expiry).unwrap();
    assert!(matches!(OAuthCredentialSnapshot::new(&expired, &[], 2, expiry, &owner.inner.closed),
        Err(OAuthSessionError::LoginRequired)));
    let future_expiry = expiry + Duration::from_secs(60);
    let valid = BoundBearerCredential::bind_with_expiry(owner.resource().clone(), "valid", future_expiry).unwrap();
    owner.close();
    assert!(matches!(OAuthCredentialSnapshot::new(&valid, &[], 3, future_expiry, &owner.inner.closed),
        Err(OAuthSessionError::LoginRequired)));
}
