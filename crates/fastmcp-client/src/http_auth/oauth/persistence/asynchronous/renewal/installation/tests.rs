//! Access-installation tests use native admitted session owners with injected
//! grant fixtures. They do not assert issuer, encryption or storage durability.
use super::*;
use std::future::{Future, poll_fn};
use std::task::Poll;
use std::time::{Duration, Instant};

use fastmcp_core::{CanonicalHttpUrl, McpRequestCancellation};
use crate::http_auth::BoundBearerCredential;
use crate::http_auth::managed::{OAuthSessionError, OAuthSessionPolicy};
use crate::http_auth::oauth::{OAuthClient, OAuthClientConfiguration, OAuthCredentials};

fn config() -> OAuthClientConfiguration {
    let url = |s| CanonicalHttpUrl::parse(s).unwrap();
    OAuthClientConfiguration::from_trusted_endpoints(
        "https://issuer.example", url("https://issuer.example/auth"),
        url("https://issuer.example/token"), url("https://resource.example/mcp"),
        "native-client", vec!["read".to_owned(), "write".to_owned()],
    ).unwrap()
}
fn grant(configuration: &OAuthClientConfiguration, token: &str, scopes: &[&str], lifetime: Duration) -> OAuthCredentials {
    let expires_at = Instant::now() + lifetime;
    OAuthCredentials {
        configuration: configuration.clone(),
        access: BoundBearerCredential::bind_with_expiry(configuration.resource.clone(), token, expires_at).unwrap(),
        refresh_token: None, scopes: scopes.iter().map(|s| (*s).to_owned()).collect(), expires_at,
    }
}
fn session(cx: &Cx, configuration: &OAuthClientConfiguration, scopes: &[&str]) -> ManagedOAuthSession {
    ManagedOAuthSession::from_credentials(cx, OAuthClient::new(configuration.clone()),
        OAuthSessionPolicy::default(), grant(configuration, "old-access", scopes, Duration::from_secs(300))).unwrap()
}
fn run<F: Future<Output = ()>>(work: impl FnOnce(Cx) -> F) {
    asupersync::runtime::RuntimeBuilder::current_thread()
        .with_reactor(asupersync::runtime::reactor::create_reactor().unwrap())
        .build().unwrap().block_on(async {
            let cx = Cx::current().unwrap();
            asupersync::time::timeout_at(cx.now().saturating_add_nanos(10_000_000_000), Box::pin(work(cx))).await.unwrap();
        });
}
async fn install(session: &ManagedOAuthSession, cx: &Cx, expected: u64, candidate: OAuthCredentials)
    -> Result<u64, OAuthAccessRotationError>
{
    let cancellation = McpRequestCancellation::new();
    let reservation = session.reserve_access_rotation(cx, &cancellation, expected, &candidate).await?;
    reservation.commit(candidate).map_err(|(error, _)| error)
}
async fn pending<F: Future>(mut future: std::pin::Pin<&mut F>) {
    poll_fn(|task| { assert!(future.as_mut().poll(task).is_pending()); Poll::Ready(()) }).await;
}

#[test]
fn installed_access_reaches_existing_clones_without_rebinding_old_snapshots() {
    run(|cx| async move {
        let cfg = config(); let session = session(&cx, &cfg, &["read", "write"]); let clone = session.clone();
        let old = clone.credential(&cx).await.unwrap(); let expiry = old.expires_at();
        let candidate = grant(&cfg, "next-access", &["read"], Duration::from_secs(60)); let next_expiry = candidate.expires_at();
        assert_eq!(install(&session, &cx, old.generation(), candidate).await.unwrap(), 2);
        let new = clone.credential(&cx).await.unwrap();
        assert_eq!(new.generation(), 2); assert_eq!(new.expires_at(), next_expiry); assert_eq!(new.scopes(), ["read"]);
        assert_eq!(old.generation(), 1); assert_eq!(old.expires_at(), expiry); assert_eq!(old.scopes(), ["read", "write"]);
        assert_eq!(old.credential().authorization_for_target(&cfg.resource), Some("Bearer old-access".to_owned()));
        assert_eq!(new.credential().authorization_for_target(&cfg.resource), Some("Bearer next-access".to_owned()));
        session.close();
        assert!(old.credential().authorization_for_target(&cfg.resource).is_none());
        assert!(new.credential().authorization_for_target(&cfg.resource).is_none());
    });
}

#[test]
fn stale_generation_never_overwrites_a_newer_installation() {
    run(|cx| async move {
        let cfg = config(); let session = session(&cx, &cfg, &["read"]);
        assert_eq!(install(&session, &cx, 1, grant(&cfg, "newer", &["read"], Duration::from_secs(300))).await.unwrap(), 2);
        assert!(matches!(install(&session, &cx, 1, grant(&cfg, "late", &["read"], Duration::from_secs(300))).await,
            Err(OAuthAccessRotationError::GenerationMismatch)));
        let still = session.credential(&cx).await.unwrap(); assert_eq!(still.generation(), 2);
        assert_eq!(still.credential().authorization_for_target(&cfg.resource), Some("Bearer newer".to_owned()));
    });
}

#[test]
fn narrowing_is_permitted_but_later_scope_expansion_is_not() {
    run(|cx| async move {
        let cfg = config(); let session = session(&cx, &cfg, &["read", "write"]);
        install(&session, &cx, 1, grant(&cfg, "narrow", &["read"], Duration::from_secs(300))).await.unwrap();
        assert!(matches!(install(&session, &cx, 2, grant(&cfg, "expanded", &["read", "write"], Duration::from_secs(300))).await,
            Err(OAuthAccessRotationError::ScopeExpansion)));
        let still = session.credential(&cx).await.unwrap(); assert_eq!(still.generation(), 2); assert_eq!(still.scopes(), ["read"]);
        assert_eq!(install(&session, &cx, 2, grant(&cfg, "empty", &[], Duration::from_secs(300))).await.unwrap(), 3);
    });
}

#[test]
fn complete_configuration_is_checked_before_session_mutation() {
    run(|cx| async move {
        let cfg = config(); let session = session(&cx, &cfg, &["read"]);
        for dimension in 0..5 {
            let mut changed = cfg.clone();
            match dimension {
                0 => changed.client_id.push_str("-other"),
                1 => changed.issuer.push('/'),
                2 => changed.token_endpoint = CanonicalHttpUrl::parse("https://issuer.example/other").unwrap(),
                3 => changed.resource = CanonicalHttpUrl::parse("https://other.example/mcp").unwrap(),
                _ => changed.max_access_token_lifetime = Duration::from_secs(5),
            }
            assert!(matches!(install(&session, &cx, 1, grant(&changed, "foreign", &["read"], Duration::from_secs(300))).await,
                Err(OAuthAccessRotationError::Session(OAuthSessionError::OAuth(OAuthError::CredentialBindingMismatch)))));
            assert_eq!(session.credential(&cx).await.unwrap().generation(), 1);
        }
    });
}

#[test]
fn neither_candidate_nor_target_may_retain_in_memory_refresh_ownership() {
    run(|cx| async move {
        let cfg = config();
        for target_renewable in [false, true] {
            let mut old = grant(&cfg, "old", &["read"], Duration::from_secs(300));
            if target_renewable { old.refresh_token = Some("retained-refresh".to_owned()); }
            let session = ManagedOAuthSession::from_credentials(&cx, OAuthClient::new(cfg.clone()), OAuthSessionPolicy::default(), old).unwrap();
            let mut candidate = grant(&cfg, "next", &["read"], Duration::from_secs(300));
            if !target_renewable { candidate.refresh_token = Some("unpersisted-refresh".to_owned()); }
            assert!(matches!(install(&session, &cx, 1, candidate).await, Err(OAuthAccessRotationError::InMemoryRefreshOwnership)));
            assert_eq!(session.credential(&cx).await.unwrap().generation(), 1);
        }
    });
}

#[test]
fn revoked_current_access_is_not_resurrected_by_persistent_installation() {
    run(|cx| async move {
        let cfg = config(); let session = session(&cx, &cfg, &["read"]);
        session.credential(&cx).await.unwrap().credential().revoke();
        assert!(matches!(install(&session, &cx, 1, grant(&cfg, "next", &["read"], Duration::from_secs(300))).await,
            Err(OAuthAccessRotationError::Session(OAuthSessionError::LoginRequired))));
        assert!(matches!(session.credential(&cx).await, Err(OAuthSessionError::LoginRequired)));
    });
}

#[test]
fn expired_or_revoked_candidates_leave_live_access_unchanged() {
    run(|cx| async move {
        let cfg = config(); let session = session(&cx, &cfg, &["read"]);
        for expired in [false, true] {
            let mut candidate = grant(&cfg, "next", &["read"], Duration::from_secs(300));
            if expired { candidate.expires_at = Instant::now(); } else { candidate.access.revoke(); }
            assert!(matches!(install(&session, &cx, 1, candidate).await,
                Err(OAuthAccessRotationError::Session(OAuthSessionError::LoginRequired))));
            assert_eq!(session.credential(&cx).await.unwrap().generation(), 1);
        }
    });
}

#[test]
fn expired_access_can_be_replaced_without_renewing_it_in_memory() {
    run(|cx| async move {
        let cfg = config();
        let old = grant(&cfg, "old", &["read"], Duration::from_millis(100));
        let session = ManagedOAuthSession::from_credentials(&cx, OAuthClient::new(cfg.clone()), OAuthSessionPolicy::default(), old).unwrap();
        asupersync::time::sleep(cx.now(), Duration::from_millis(110)).await;
        assert!(matches!(session.credential(&cx).await, Err(OAuthSessionError::LoginRequired)));
        assert_eq!(install(&session, &cx, 1, grant(&cfg, "next", &["read"], Duration::from_secs(300))).await.unwrap(), 2);
        assert_eq!(session.credential(&cx).await.unwrap().generation(), 2);
    });
}

#[test]
fn abandoned_reservation_releases_lock_wait_and_keeps_candidate_owned() {
    run(|cx| async move {
        let cfg = config(); let session = session(&cx, &cfg, &["read"]); let cancellation = McpRequestCancellation::new();
        let first = grant(&cfg, "first", &["read"], Duration::from_secs(300));
        let second = grant(&cfg, "second", &["read"], Duration::from_secs(300));
        let held = session.reserve_access_rotation(&cx, &cancellation, 1, &first).await.unwrap();
        let mut waiting = Box::pin(session.reserve_access_rotation(&cx, &cancellation, 1, &second));
        pending(waiting.as_mut()).await; drop(waiting); drop(held);
        assert_eq!(session.credential(&cx).await.unwrap().generation(), 1);
        assert_eq!(install(&session, &cx, 1, second).await.unwrap(), 2);
        assert_eq!(first.access.authorization_for_target(&cfg.resource), Some("Bearer first".to_owned()));
    });
}

#[test]
fn cancelling_a_wait_does_not_close_the_shared_session_or_move_candidate() {
    run(|cx| async move {
        let cfg = config(); let session = session(&cx, &cfg, &["read"]); let held_cancel = McpRequestCancellation::new();
        let candidate = grant(&cfg, "next", &["read"], Duration::from_secs(300));
        let held = session.reserve_access_rotation(&cx, &held_cancel, 1, &candidate).await.unwrap();
        let cancel = McpRequestCancellation::new();
        let mut waiting = Box::pin(session.reserve_access_rotation(&cx, &cancel, 1, &candidate));
        pending(waiting.as_mut()).await; cancel.cancel();
        assert!(matches!(waiting.await, Err(OAuthAccessRotationError::Session(OAuthSessionError::Cancelled))));
        drop(held);
        assert_eq!(session.credential(&cx).await.unwrap().generation(), 1);
        assert_eq!(install(&session, &cx, 1, candidate).await.unwrap(), 2);
    });
}

#[test]
fn closure_between_reservation_and_commit_cannot_publish_new_access() {
    run(|cx| async move {
        let cfg = config(); let session = session(&cx, &cfg, &["read"]); let cancel = McpRequestCancellation::new();
        let candidate = grant(&cfg, "next", &["read"], Duration::from_secs(300));
        let held = session.reserve_access_rotation(&cx, &cancel, 1, &candidate).await.unwrap();
        session.close();
        let (error, original) = held.commit(candidate).unwrap_err();
        assert!(matches!(error, OAuthAccessRotationError::Session(OAuthSessionError::Closed)));
        assert_eq!(original.access.authorization_for_target(&cfg.resource), Some("Bearer next".to_owned()));
        assert!(matches!(session.credential(&cx).await, Err(OAuthSessionError::Closed)));
    });
}

#[test]
fn acquisition_deadline_is_not_reset_before_the_commit() {
    run(|cx| async move {
        let cfg = config(); let candidate = grant(&cfg, "next", &["read"], Duration::from_secs(300));
        let policy = OAuthSessionPolicy::new(Duration::ZERO, Duration::from_millis(30), Duration::from_secs(1), 2).unwrap();
        let session = ManagedOAuthSession::from_credentials(&cx, OAuthClient::new(cfg.clone()), policy,
            grant(&cfg, "old", &["read"], Duration::from_secs(300))).unwrap();
        let cancel = McpRequestCancellation::new();
        let held = session.reserve_access_rotation(&cx, &cancel, 1, &candidate).await.unwrap();
        asupersync::time::sleep(cx.now(), Duration::from_millis(40)).await;
        let (error, original) = held.commit(candidate).unwrap_err();
        assert!(matches!(error, OAuthAccessRotationError::Session(OAuthSessionError::TimedOut)));
        assert_eq!(original.access.authorization_for_target(&cfg.resource), Some("Bearer next".to_owned()));
        assert_eq!(session.credential(&cx).await.unwrap().generation(), 1);
    });
}

mod live;
