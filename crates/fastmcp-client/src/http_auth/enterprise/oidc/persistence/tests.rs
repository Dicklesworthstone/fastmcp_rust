//! Exercises the real restore/envelope/blob consumers. External providers are
//! bounded in-memory fixtures, not a durability or deployment attestation.

use super::*;
use std::future::{Future, poll_fn};
use std::task::Poll;

use crate::http_auth::enterprise::credentials::tests::CredentialStoreFixture;
use crate::http_auth::enterprise::oidc::tests::configuration;
use crate::http_auth::enterprise::response::tests::{profile, subject_mappings};
use crate::http_auth::enterprise::verification::OidcVerificationKeys;

fn now() -> SystemTime {
    SystemTime::UNIX_EPOCH + Duration::from_secs(2_000_000_000)
}

fn run<T>(future: impl Future<Output = T>) -> T {
    fastmcp_core::runtime::block_on(future)
}

fn selected(fixture: &CredentialStoreFixture) -> OidcPendingFlowStore {
    let configuration = configuration();
    let mappings = subject_mappings(&configuration.profile);
    OidcPendingFlowStore::new(configuration, mappings.snapshot().clone(), fixture.store()).unwrap()
}

fn callback(pending: &PersistedOidcAuthorization, suffix: &str) -> String {
    format!(
        "{}?state={}&iss=https%3A%2F%2Fidp.example&{suffix}",
        pending.pending.configuration.redirect_uri,
        pending.pending.state.as_str(),
    )
}

fn code(outcome: OidcCallbackOutcome) -> super::super::OidcCodeGrant {
    match outcome {
        OidcCallbackOutcome::Code(grant) => grant,
        OidcCallbackOutcome::Denied(_) => panic!("expected code grant"),
    }
}

fn keys() -> OidcVerificationKeys {
    let fixtures: serde_json::Value =
        serde_json::from_str(include_str!("../../response/assertions.json")).unwrap();
    OidcVerificationKeys::from_trusted_jwks(
        "https://idp.example",
        21,
        &serde_json::to_vec(&fixtures["jwks"]).unwrap(),
    )
    .unwrap()
}

#[test]
fn oidc_protected_pending_flow_resumes_exact_get_and_native_code_request() {
    run(async {
        let cx = Cx::current().unwrap();
        let fixture = CredentialStoreFixture::new(&cx).await;
        let original = selected(&fixture);
        let pending = original.prepare(&cx, now(), Duration::from_secs(300), Time::MAX).await.unwrap();
        let revision = pending.revision();
        let url = pending.authorization_url().unwrap().to_owned();
        let target = pending.request_target().unwrap().to_owned();
        let verifier = pending.pending.verifier.as_str().to_owned();
        let expires_at = pending.expires_at();
        drop(pending);
        drop(original);

        let resumed_store = selected(&fixture);
        let resumed = resumed_store.resume(&cx, revision, now() + Duration::from_secs(10), Time::MAX).await.unwrap();
        assert_eq!(resumed.authorization_url().unwrap(), url);
        assert_eq!(resumed.request_target().unwrap(), target);
        assert_eq!(resumed.expires_at(), expires_at);
        let reply = callback(&resumed, "code=one-use%2Bcode%3Dvalue");
        let grant = code(resumed.admit_callback(&cx, &reply, now() + Duration::from_secs(10), Time::MAX).await.unwrap());
        grant.admit_credential_snapshot(Some(&resumed_store.snapshot)).unwrap();
        let (request, response) = grant.into_token_request(
            &resumed_store.configuration.profile,
            resumed_store.configuration.response_policy,
            "protected-idp-client-secret",
            &keys(),
            now() + Duration::from_secs(10),
        ).unwrap();
        let form = std::str::from_utf8(request.body()).unwrap();
        assert!(form.contains("code=one-use%2Bcode%3Dvalue"));
        assert!(form.contains(&format!("code_verifier={verifier}")));
        response.check_custody().unwrap();
        assert!(matches!(
            resumed_store.resume(&cx, revision, now(), Time::MAX).await,
            Err(OidcPendingFlowError::ConsumedOrChanged)
        ));
        assert_eq!(fixture.current_revision(revision.record_id()).generation(), revision.generation() + 1);
    });
}

#[test]
fn oidc_protected_pending_flow_refuses_configuration_and_snapshot_substitution_without_mutation() {
    run(async {
        let cx = Cx::current().unwrap();
        let fixture = CredentialStoreFixture::new(&cx).await;
        let original = selected(&fixture);
        let pending = original.prepare(&cx, now(), Duration::from_secs(300), Time::MAX).await.unwrap();
        let revision = pending.revision();
        for dimension in 0..8 {
            let mut changed = original.configuration.clone();
            let mut snapshot = original.snapshot.clone();
            match dimension {
                0 => changed.profile = profile(&["write"]),
                1 => changed.metadata_digest[0] ^= 1,
                2 => changed.registration_digest[0] ^= 1,
                3 => changed.tenant = ConfiguredTenant::Exact("other-tenant".into()),
                4 => changed.require_callback_issuer = !changed.require_callback_issuer,
                5 => changed.maximum_authentication_age = Some(Duration::from_secs(30)),
                6 => changed.response_policy = crate::http_auth::enterprise::response::EnterpriseResponsePolicy::new(
                    Duration::from_secs(120), Duration::from_secs(60), Duration::from_secs(120),
                    Duration::ZERO, Duration::from_secs(60),
                ).unwrap(),
                7 => snapshot = subject_mappings(&profile(&["write"])).snapshot().clone(),
                _ => unreachable!(),
            }
            let other = OidcPendingFlowStore::new(changed, snapshot, fixture.store()).unwrap();
            assert!(matches!(other.resume(&cx, revision, now(), Time::MAX).await,
                Err(OidcPendingFlowError::BindingMismatch)), "dimension {dimension}");
            assert_eq!(fixture.current_revision(revision.record_id()).encode(), revision.encode());
            assert!(!fixture.store().is_quarantined());
        }
        let resumed = original.resume(&cx, revision, now(), Time::MAX).await.unwrap();
        assert_eq!(resumed.authorization_url().unwrap(), pending.authorization_url().unwrap());
    });
}

#[test]
fn oidc_protected_pending_flow_closed_record_refuses_changed_challenges_and_wire_digests() {
    run(async {
        let cx = Cx::current().unwrap();
        let fixture = CredentialStoreFixture::new(&cx).await;
        let store = selected(&fixture);
        for dimension in 0..5 {
            let pending = store.prepare(&cx, now(), Duration::from_secs(300), Time::MAX).await.unwrap();
            let mut bytes = encode_pending(&pending.pending, store.binding).unwrap().into_zeroizing();
            match dimension {
                0 => bytes[PREFIX.len()] = CONSUMED,
                1 => bytes.push(0),
                2 => bytes[RECORD_BYTES - 1] = b'!',
                3 => bytes[PREFIX.len() + 1 + 32 + 24] ^= 1,
                4 => bytes[RECORD_BYTES - 1] = b'B', // valid alphabet, noncanonical trailing bits
                _ => unreachable!(),
            }
            let revision = fixture.store().replace(
                &cx, &pending.revision(), BoundedPlaintext::new(bytes).unwrap(), Time::MAX,
            ).await.unwrap();
            assert!(matches!(store.resume(&cx, revision, now(), Time::MAX).await,
                Err(OidcPendingFlowError::InvalidRecord)), "dimension {dimension}");
            assert_eq!(fixture.current_revision(revision.record_id()).encode(), revision.encode());
        }
    });
}

#[test]
fn oidc_protected_pending_flow_competing_cas_returns_only_one_code_grant() {
    run(async {
        let cx = Cx::current().unwrap();
        let fixture = CredentialStoreFixture::new(&cx).await;
        let store = selected(&fixture);
        let first = store.prepare(&cx, now(), Duration::from_secs(300), Time::MAX).await.unwrap();
        let revision = first.revision();
        let second = store.resume(&cx, revision, now(), Time::MAX).await.unwrap();
        let first_reply = callback(&first, "code=losing-code");
        let second_reply = callback(&second, "code=winning-code");
        let gate = fixture.pause_next_commit();
        let mut losing = std::pin::pin!(first.admit_callback(&cx, &first_reply, now(), Time::MAX));
        poll_fn(|task| {
            assert!(losing.as_mut().poll(task).is_pending());
            Poll::Ready(())
        }).await;

        let winner = code(second.admit_callback(&cx, &second_reply, now(), Time::MAX).await.unwrap());
        gate.release();
        assert!(matches!(losing.await, Err(OidcPendingFlowError::ConsumedOrChanged)));
        assert!(!fixture.store().is_quarantined());
        winner.admit_credential_snapshot(Some(&store.snapshot)).unwrap();
        let (request, _) = winner.into_token_request(
            &store.configuration.profile, store.configuration.response_policy,
            "protected-client-secret", &keys(), now(),
        ).unwrap();
        assert!(std::str::from_utf8(request.body()).unwrap().contains("code=winning-code"));
        assert_eq!(fixture.current_revision(revision.record_id()).generation(), revision.generation() + 1);
        assert!(matches!(store.resume(&cx, revision, now(), Time::MAX).await,
            Err(OidcPendingFlowError::ConsumedOrChanged)));
    });
}

#[test]
fn oidc_protected_pending_flow_malformed_denied_and_discarded_flows_are_consumed() {
    run(async {
        let cx = Cx::current().unwrap();
        let fixture = CredentialStoreFixture::new(&cx).await;
        let store = selected(&fixture);
        for suffix in ["code=ok&state=duplicate", "code=ok#error", "error=access_denied"] {
            let pending = store.prepare(&cx, now(), Duration::from_secs(300), Time::MAX).await.unwrap();
            let revision = pending.revision();
            let reply = callback(&pending, suffix);
            let result = pending.admit_callback(&cx, &reply, now(), Time::MAX).await;
            if suffix == "error=access_denied" {
                assert!(matches!(result, Ok(OidcCallbackOutcome::Denied(
                    super::super::OidcAuthorizationError::AccessDenied
                ))));
            } else {
                assert!(matches!(result, Err(OidcPendingFlowError::CodeFlow(
                    OidcCodeFlowError::CallbackRejected
                ))));
            }
            let consumed = fixture.current_revision(revision.record_id());
            assert_eq!(consumed.generation(), revision.generation() + 1);
            let record = fixture.store().read(&cx, &consumed, Time::MAX).await.unwrap();
            assert_eq!(record.as_bytes().len(), PREFIX.len() + 1 + 32);
            assert_eq!(record.as_bytes()[PREFIX.len()], CONSUMED);
            assert!(matches!(store.resume(&cx, revision, now(), Time::MAX).await,
                Err(OidcPendingFlowError::ConsumedOrChanged)));
        }
        let pending = store.prepare(&cx, now(), Duration::from_secs(300), Time::MAX).await.unwrap();
        let revision = pending.revision();
        pending.discard(&cx, Time::MAX).await.unwrap();
        assert!(matches!(store.resume(&cx, revision, now(), Time::MAX).await,
            Err(OidcPendingFlowError::ConsumedOrChanged)));
    });
}

#[test]
fn oidc_protected_pending_flow_lost_commit_never_releases_launch_or_callback_authority() {
    run(async {
        let cx = Cx::current().unwrap();
        let fixture = CredentialStoreFixture::new(&cx).await;
        let store = selected(&fixture);
        fixture.lose_next_commit_response();
        assert!(store.prepare(&cx, now(), Duration::from_secs(300), Time::MAX).await.is_err());
        assert!(fixture.store().is_quarantined());

        let fixture = CredentialStoreFixture::new(&cx).await;
        let store = selected(&fixture);
        let pending = store.prepare(&cx, now(), Duration::from_secs(300), Time::MAX).await.unwrap();
        let revision = pending.revision();
        let reply = callback(&pending, "code=never-released");
        fixture.lose_next_commit_response();
        assert!(pending.admit_callback(&cx, &reply, now(), Time::MAX).await.is_err());
        assert!(fixture.store().is_quarantined());
        assert_eq!(fixture.current_revision(revision.record_id()).generation(), revision.generation() + 1);
        assert!(store.resume(&cx, revision, now(), Time::MAX).await.is_err());
    });
}

#[test]
fn oidc_protected_pending_flow_expiry_and_slow_resume_do_not_restart_lifetime() {
    run(async {
        let cx = Cx::current().unwrap();
        let fixture = CredentialStoreFixture::new(&cx).await;
        let store = selected(&fixture);
        let pending = store.prepare(&cx, now(), Duration::from_secs(300), Time::MAX).await.unwrap();
        let revision = pending.revision();
        assert!(matches!(store.resume(&cx, revision, now() + Duration::from_secs(300), Time::MAX).await,
            Err(OidcPendingFlowError::CodeFlow(OidcCodeFlowError::InvalidLifetime))));
        let resumed = store.resume(&cx, revision, now() + Duration::from_secs(299), Time::MAX).await.unwrap();
        assert!(resumed.custody.valid_until <= Instant::now() + Duration::from_secs(1));
        assert_eq!(resumed.expires_at(), pending.expires_at());

        let gate = fixture.pause_next_read();
        let mut slow = std::pin::pin!(store.resume(
            &cx, revision, now() + Duration::from_millis(299_950), Time::MAX,
        ));
        poll_fn(|task| {
            assert!(slow.as_mut().poll(task).is_pending());
            Poll::Ready(())
        }).await;
        std::thread::sleep(Duration::from_millis(80));
        gate.release();
        assert!(matches!(slow.await,
            Err(OidcPendingFlowError::CodeFlow(OidcCodeFlowError::InvalidLifetime))
                | Err(OidcPendingFlowError::Expired)));
        assert_eq!(fixture.current_revision(revision.record_id()).encode(), revision.encode());
    });
}

#[test]
fn oidc_protected_pending_flow_cancellation_while_consuming_releases_no_grant() {
    let runtime = asupersync::runtime::RuntimeBuilder::current_thread()
        .with_reactor(asupersync::runtime::reactor::create_reactor().unwrap())
        .build().unwrap();
    let cx = runtime.request_cx_with_budget(asupersync::Budget::INFINITE);
    runtime.block_on(async {
        let fixture = CredentialStoreFixture::new(&cx).await;
        let store = selected(&fixture);
        let pending = store.prepare(&cx, now(), Duration::from_secs(300), Time::MAX).await.unwrap();
        let revision = pending.revision();
        let reply = callback(&pending, "code=cancelled-before-commit");
        let gate = fixture.pause_next_commit();
        let mut consuming = std::pin::pin!(pending.admit_callback(&cx, &reply, now(), Time::MAX));
        poll_fn(|task| {
            assert!(consuming.as_mut().poll(task).is_pending());
            Poll::Ready(())
        }).await;
        cx.set_cancel_requested(true);
        assert!(matches!(consuming.await, Err(OidcPendingFlowError::Cancelled)));
        gate.release();
        assert_eq!(fixture.current_revision(revision.record_id()).encode(), revision.encode());
    });
}

#[test]
fn oidc_protected_pending_flow_grants_refuse_unbound_serializers_and_retain_quarantine_guard() {
    run(async {
        let cx = Cx::current().unwrap();
        let fixture = CredentialStoreFixture::new(&cx).await;
        let store = selected(&fixture);
        let pending = store.prepare(&cx, now(), Duration::from_secs(300), Time::MAX).await.unwrap();
        let reply = callback(&pending, "code=never-written-to-unbound-sink");
        let grant = code(pending.admit_callback(&cx, &reply, now(), Time::MAX).await.unwrap());
        let mut sink = Vec::new();
        assert!(matches!(grant.write_token_form(&mut sink, now()),
            Err(OidcCodeFlowError::PersistentCustodyUnavailable)));
        assert!(sink.is_empty());

        for after_serialization in [false, true] {
            let fixture = CredentialStoreFixture::new(&cx).await;
            let store = selected(&fixture);
            let pending = store.prepare(&cx, now(), Duration::from_secs(300), Time::MAX).await.unwrap();
            let revision = pending.revision();
            let reply = callback(&pending, "code=retained-custody");
            let grant = code(pending.admit_callback(&cx, &reply, now(), Time::MAX).await.unwrap());
            assert_eq!(grant.admit_credential_snapshot(None), Err(OidcCodeFlowError::PersistentCustodyUnavailable));
            grant.admit_credential_snapshot(Some(&store.snapshot)).unwrap();
            let mut grant = Some(grant);
            let response = if after_serialization {
                Some(grant.take().unwrap().into_token_request(
                    &store.configuration.profile, store.configuration.response_policy,
                    "protected-client-secret", &keys(), now(),
                ).unwrap().1)
            } else { None };
            let consumed = fixture.current_revision(revision.record_id());
            fixture.corrupt_next_read_receipt();
            assert!(fixture.store().read(&cx, &consumed, Time::MAX).await.is_err());
            assert!(fixture.store().is_quarantined());
            let check = if let Some(grant) = grant { grant.check_custody() }
                else { response.unwrap().check_custody() };
            assert_eq!(check, Err(OidcCodeFlowError::PersistentCustodyUnavailable));
        }
    });
}
