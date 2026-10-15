use super::*;
use std::task::{Context, Waker};
use std::time::Instant;
use fastmcp_core::CanonicalHttpUrl;
use fastmcp_protocol::dpop::DpopKey;
use crate::http_auth::dpop::DpopSession;
use crate::http_auth::dpop::native::DpopHttpPolicy;
use crate::http_auth::dpop::native::core::DpopCoreError;
use serde_json::json;

fn metadata() -> FinalRequestMeta {
    FinalRequestMeta::new(serde_json::from_value(json!({"roots":{}})).unwrap())
}

fn requests() -> TaskInputRequests {
    serde_json::from_value(json!({"one":{"method":"roots/list"}, "two":{"method":"roots/list"}})).unwrap()
}

fn responses(key: &str) -> TaskInputResponses {
    serde_json::from_value(json!({key:{"roots":[]}})).unwrap()
}

fn driver() -> InputDriver<(), ()> {
    InputDriver::new(DpopTaskWatchDriverPolicy::default().input, &metadata(), (), ()).unwrap()
}

fn task() -> Task {
    serde_json::from_value(json!({
        "taskId":"task-one", "status":"input_required", "ttlMs":null,
        "createdAt":"2026-09-16T00:00:00Z", "lastUpdatedAt":"2026-09-16T00:00:00Z",
        "inputRequests":{"one":{"method":"roots/list"}, "two":{"method":"roots/list"}}
    })).unwrap()
}

fn watch(snapshots: usize) -> WatchState {
    WatchState::new("watch", DpopTaskWatchPolicy::new(snapshots).unwrap(), DpopStreamLimits::default()).unwrap()
}

#[test]
fn input_policy_has_finite_independent_snapshot_update_key_state_and_time_limits() {
    for args in [(0, 1, 1, 64), (1025, 1, 1, 64), (1, 129, 1, 64),
        (1, 1, 4097, 64), (1, 1, 1, 0), (1, 1, 1, 4 * 1024 * 1024 + 1)]
    {
        assert!(DpopTaskWatchDriverPolicy::new(args.0, args.1, args.2, args.3, Duration::from_secs(1)).is_err());
    }
    for timeout in [Duration::ZERO, Duration::from_secs(86_401)] {
        assert!(DpopTaskWatchDriverPolicy::new(1, 1, 1, 64, timeout).is_err());
    }
    assert!(DpopTaskWatchDriverPolicy::new(1024, 128, 4096, 4 * 1024 * 1024,
        Duration::from_secs(86_400)).is_ok());
    assert!(DpopTaskWatchDriverPolicy::new(1, 0, 0, 1, Duration::from_secs(1)).is_ok());
}

#[test]
fn only_acknowledgement_advances_the_shared_ledger_and_partial_answers_remain_pending() {
    let mut driver = driver();
    let requests = requests();
    let (pending, fingerprints) = driver.ledger.unanswered(&requests, driver.policy).unwrap();
    driver.stage(&pending, fingerprints, &responses("one")).unwrap();
    assert_eq!(driver.ledger.unanswered(&requests, driver.policy).unwrap().0.len(), 2,
        "constructing or sending an update is not acknowledgement");
    driver.update_request(&watch(3), task(), responses("one")).unwrap();
    assert_eq!(driver.ledger.unanswered(&requests, driver.policy).unwrap().0.len(), 2);
    driver.acknowledged().unwrap();
    assert!(driver.pending.is_none());
    let (pending, fingerprints) = driver.ledger.unanswered(&requests, driver.policy).unwrap();
    assert_eq!(pending.keys().map(String::as_str).collect::<Vec<_>>(), ["two"]);
    driver.stage(&pending, fingerprints, &responses("two")).unwrap();
    driver.update_request(&watch(3), task(), responses("two")).unwrap();
    driver.acknowledged().unwrap();
    assert!(driver.ledger.unanswered(&requests, driver.policy).unwrap().0.is_empty());
    assert!(driver.acknowledged().is_err(), "an ACK cannot be applied twice");
}

#[test]
fn invalid_answers_never_stage_and_an_acknowledged_key_cannot_change_descriptor() {
    let mut driver = driver();
    for answers in [TaskInputResponses::new(), responses("foreign"),
        serde_json::from_value(json!({"one":{"action":"decline"}})).unwrap()]
    {
        let (pending, fingerprints) = driver.ledger.unanswered(&requests(), driver.policy).unwrap();
        assert!(matches!(driver.stage(&pending, fingerprints, &answers),
            Err(DpopTaskWatchError::Driver(ManagedTaskDriverError::InvalidInputResponse))));
        assert!(driver.pending.is_none());
    }
    let (pending, fingerprints) = driver.ledger.unanswered(&requests(), driver.policy).unwrap();
    driver.stage(&pending, fingerprints, &responses("one")).unwrap();
    driver.acknowledged().unwrap();
    let changed = serde_json::from_value(json!({"one":{
        "method":"sampling/createMessage", "params":{"messages":[],"maxTokens":16}
    }})).unwrap();
    let error = driver.ledger.unanswered(&changed, driver.policy).err().unwrap();
    assert!(matches!(error, ManagedTaskDriverError::InputKeyReused));
    assert!(!format!("{} {:?}", DpopTaskWatchError::from(error), driver.updates).contains("canary"));
}

#[test]
fn update_requires_remaining_reconciliation_capacity_and_never_replenishes_bytes() {
    for exhausted_bytes in [false, true] {
        let mut driver = driver();
        let (pending, fingerprints) = driver.ledger.unanswered(&requests(), driver.policy).unwrap();
        driver.stage(&pending, fingerprints, &responses("one")).unwrap();
        let mut watch = watch(1);
        if exhausted_bytes { watch.charge((watch.limits.core.total_bytes(), 0)).unwrap(); }
        else { watch.snapshot_request(&TaskId::parse("task-one").unwrap()).unwrap(); }
        let before = (watch.snapshots, watch.usage);
        assert!(driver.update_request(&watch, task(), responses("one")).is_err());
        assert_eq!(driver.updates, 0);
        assert_eq!((watch.snapshots, watch.usage), before);
        assert_eq!(driver.ledger.unanswered(&requests(), driver.policy).unwrap().0.len(), 2);
    }
    let mut driver = driver();
    driver.policy.maximum_updates = 0;
    let (pending, fingerprints) = driver.ledger.unanswered(&requests(), driver.policy).unwrap();
    driver.stage(&pending, fingerprints, &responses("one")).unwrap();
    assert!(matches!(driver.update_request(&watch(3), task(), responses("one")),
        Err(DpopTaskWatchError::Driver(ManagedTaskDriverError::UpdateLimit))));
}

#[test]
fn input_key_and_fingerprint_capacity_is_checked_before_any_answer_can_be_staged() {
    let mut driver = driver();
    driver.policy.maximum_input_keys = 1;
    assert!(matches!(driver.ledger.unanswered(&requests(), driver.policy),
        Err(ManagedTaskDriverError::InputLimit)));
    driver.policy.maximum_input_keys = 2;
    driver.policy.maximum_state_bytes = 69; // two three-byte keys plus two SHA-256 digests need 70
    assert!(matches!(driver.ledger.unanswered(&requests(), driver.policy),
        Err(ManagedTaskDriverError::StateByteLimit)));
    driver.policy.maximum_state_bytes = 70;
    assert!(driver.ledger.unanswered(&requests(), driver.policy).is_ok());
    assert!(driver.pending.is_none());
}

fn client() -> (DpopHttpClient, DpopCredential) {
    let issuer = CanonicalHttpUrl::parse("https://issuer.example/token").unwrap();
    let session = DpopSession::new(DpopKey::generate().unwrap(), issuer.clone(),
        CanonicalHttpUrl::parse("https://mcp.example/mcp").unwrap()).unwrap();
    let credential = session.admit_token_response(&issuer, 200,
        br#"{"access_token":"input-test-token","token_type":"DPoP","expires_in":60}"#,
        Instant::now(), Duration::from_secs(60)).unwrap();
    (DpopHttpClient::new(session, DpopHttpPolicy::default()).unwrap(), credential)
}

#[test]
fn public_input_drive_refuses_precancellation_without_publishing_or_polling_host_work() {
    for cancel_cx in [false, true] {
        let (mut client, credential) = client();
        let cx = Cx::for_testing();
        let cancellation = McpRequestCancellation::new();
        if cancel_cx { cx.set_cancel_requested(true); } else { cancellation.cancel(); }
        let mut drive = Box::pin(client.drive_task_with_subscription(
            &cx, &cancellation, &credential, metadata(), TaskId::parse("task-one").unwrap(),
            "", DpopTaskWatchDriverPolicy::default(), DpopStreamLimits::default(),
            |_| -> Ready<Result<ManagedTaskInputAction, ManagedTaskDriverError>> {
                panic!("cancelled drive cannot construct host work")
            },
            |_| panic!("cancelled drive cannot publish a snapshot"),
        ));
        assert!(matches!(drive.as_mut().poll(&mut Context::from_waker(Waker::noop())),
            Poll::Ready(Err(DpopTaskWatchError::Stream(DpopStreamError::Core(
                DpopCoreError::Transport(DpopHttpError::Cancelled)))))));
        drop(drive);
        assert!(!client.revocation_handle().is_revoked());
    }
}
