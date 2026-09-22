use super::*;
use super::super::tests::{consumer, runtime};
use fastmcp_core::partition::{DurableOwnerKey, PartitionDescriptor};
use serde_json::json;
use std::cell::Cell;

fn binding(client: &ClientCredentialsTasksClient, subject: &str) -> TaskResumeBinding {
    let resource = client.client.resource();
    let facts = PartitionDescriptor::from_verified_facts("fixture", 1, "https://issuer.example",
        resource.as_str(), "tenant", subject, "watch-fixture", 1, 1, &[b"bound-resource".as_slice()]).unwrap();
    let owner = DurableOwnerKey::derive(&facts, 1).unwrap();
    TaskResumeBinding::from_verified_owner(resource.clone(), "machine-restart", &owner,
        [1; 32], [2; 32], [3; 32]).unwrap()
}
fn task(id: &str, status: &str, second: u8) -> Task {
    let mut value = json!({"taskId":id, "status":status, "createdAt":"2020-01-01T00:00:00Z",
        "lastUpdatedAt":format!("2020-01-01T00:00:{second:02}Z"), "ttlMs":null,
        "statusMessage":"PRIVATE-STATUS"});
    if status == "input_required" { value["inputRequests"] = json!({"PRIVATE-INPUT":{"method":"roots/list"}}); }
    if status == "completed" { value["result"] = json!({"content":[{"type":"text","text":"PRIVATE-RESULT"}]}); }
    serde_json::from_value(value).unwrap()
}
fn record(cx: &Cx, owner: &TaskResumeBinding, id: &str) -> TaskResumeRecord {
    TaskResumeRecord::capture(cx, owner, &task(id, "working", 1), Duration::from_secs(3600)).unwrap()
}
fn expired(mut bytes: Vec<u8>) -> TaskResumeRecord {
    // FMTRSM01 retains its i128 expiry in the final 16 bytes. This valid
    // January 2020 deadline makes the public expired-record path deterministic.
    let end = bytes.len();
    bytes[end - 16..].copy_from_slice(&1_577_836_802_000_000_000_i128.to_be_bytes());
    TaskResumeRecord::decode(&bytes).unwrap()
}

#[test]
fn machine_resume_rejects_wrong_binding_and_invalid_ids_before_acquiring_a_grant() {
    runtime().block_on(async {
        let cx = Cx::current().unwrap();
        let client = consumer();
        let owner = binding(&client, "one");
        let saved = record(&cx, &owner, "one");
        let before = saved.encode().unwrap();
        let wrong = binding(&client, "other");
        assert!(matches!(Box::pin(client.reconcile_task_resume(&cx, &wrong, &saved,
            RequestId::Number(1), RequestId::Number(2))).await,
            Err(ClientCredentialsTaskResumeError::Resume(TaskResumeError::Unavailable))));
        let mut other_endpoint = consumer();
        std::sync::Arc::get_mut(&mut other_endpoint.client.inner).unwrap().resource =
            fastmcp_core::CanonicalHttpUrl::parse("https://machine.example/other").unwrap();
        assert!(matches!(Box::pin(other_endpoint.reconcile_task_resume(&cx, &owner, &saved,
            RequestId::Number(1), RequestId::Number(2))).await,
            Err(ClientCredentialsTaskResumeError::Resume(TaskResumeError::Unavailable))));
        assert!(other_endpoint.client.inner.state.try_lock_owned().unwrap().current.is_none());
        assert!(matches!(Box::pin(client.reconcile_task_resume(&cx, &owner, &saved,
            RequestId::Number(1), RequestId::Number(1))).await,
            Err(ClientCredentialsTaskResumeError::Task(ClientCredentialsTasksError::Protocol(ManagedTasksError::InvalidRequest)))));
        assert!(matches!(Box::pin(client.reconcile_task_resume(&cx, &owner, &expired(before.clone()),
            RequestId::Number(1), RequestId::Number(2))).await,
            Err(ClientCredentialsTaskResumeError::Resume(TaskResumeError::Unavailable))));
        let cancel = McpRequestCancellation::new();
        cancel.cancel();
        assert!(matches!(Box::pin(client.reconcile_task_resume_with_cancellation(&cx, &cancel,
            &owner, &saved, RequestId::Number(1), RequestId::Number(2))).await,
            Err(ClientCredentialsTaskResumeError::Task(ClientCredentialsTasksError::Authentication(
                ClientCredentialsError::Discovery(OAuthDiscoveryError::Cancelled))))));
        assert_eq!(saved.encode().unwrap(), before);
        assert!(client.client.inner.state.try_lock_owned().unwrap().current.is_none());
    });
}

#[test]
fn machine_restart_stages_exact_duplicates_in_opaque_key_order_without_network_work() {
    let cx = Cx::for_testing();
    let client = consumer();
    let owner = binding(&client, "one");
    let one = record(&cx, &owner, "é");
    let two = record(&cx, &owner, "e\u{301}");
    let mut restart = client.prepare_task_restart(&cx, owner.clone(), [two.clone(), one.clone(), one.clone()],
        "restore".to_owned(), ClientCredentialsTaskRestartPolicy::default()).unwrap();
    let mut expected = [one.key(), two.key()];
    expected.sort();
    assert_eq!(restart.unvisited().map(TaskResumeRecord::key).collect::<Vec<_>>(), expected);
    assert_eq!((restart.remaining(), restart.attempted(), restart.delivered()), (2, 0, 0));
    drop(restart.next_reconciled(&cx));
    assert!(restart.ready);
    assert!(restart.pending_record().is_none());
    restart.close();
    assert_eq!(restart.remaining(), 2);
    assert!(!format!("{restart:?}").contains("é"));
    assert!(client.client.inner.state.try_lock_owned().unwrap().current.is_none());
    assert!(!client.client.inner.closed.is_cancel_requested());
}

#[test]
fn machine_restart_shared_staging_limits_charge_duplicates_and_reject_the_whole_conflict() {
    let cx = Cx::for_testing();
    let client = consumer();
    let owner = binding(&client, "one");
    let saved = record(&cx, &owner, "one");
    let size = saved.encode().unwrap().len();
    let pulls = Cell::new(0);
    let endless = std::iter::repeat_with(|| { pulls.set(pulls.get() + 1); saved.clone() });
    let policy = ClientCredentialsTaskRestartPolicy::new(2, 4096, Duration::from_secs(1)).unwrap();
    assert!(matches!(client.prepare_task_restart(&cx, owner.clone(), endless, "restore".to_owned(), policy),
        Err(ClientCredentialsTaskResumeError::Resume(TaskResumeError::Capacity))));
    assert_eq!(pulls.get(), 3);
    let short = ClientCredentialsTaskRestartPolicy::new(2, size * 2 - 1, Duration::from_secs(1)).unwrap();
    assert!(matches!(client.prepare_task_restart(&cx, owner.clone(), [saved.clone(), saved.clone()], "restore".to_owned(), short),
        Err(ClientCredentialsTaskResumeError::Resume(TaskResumeError::TooLarge))));
    let newer = TaskResumeRecord::capture(&cx, &owner, &task("one", "input_required", 2), Duration::from_secs(3600)).unwrap();
    assert!(matches!(client.prepare_task_restart(&cx, owner, [saved, newer], "restore".to_owned(), policy),
        Err(ClientCredentialsTaskResumeError::Resume(TaskResumeError::ConflictingSnapshot))));
    assert!(client.client.inner.state.try_lock_owned().unwrap().current.is_none());
}

#[test]
fn machine_restart_expired_items_are_explicit_and_completion_survives_owner_close() {
    runtime().block_on(async {
        let cx = Cx::current().unwrap();
        let client = consumer();
        let owner = binding(&client, "one");
        let saved = expired(record(&cx, &owner, "one").encode().unwrap());
        let mut restart = client.prepare_task_restart(&cx, owner.clone(), [saved.clone()], "expired".to_owned(),
            ClientCredentialsTaskRestartPolicy::default()).unwrap();
        let item = Box::pin(restart.next_reconciled(&cx)).await.unwrap().unwrap();
        assert_eq!(item.previous, saved);
        assert!(matches!(item.outcome, ClientCredentialsTaskRestartOutcome::Unavailable));
        let change = item.storage_change(&cx, &owner).unwrap();
        assert_eq!(change.previous(), &saved);
        assert!(change.replacement().is_none());
        assert_eq!((restart.remaining(), restart.attempted(), restart.delivered()), (0, 0, 1));
        client.client.close();
        assert!(Box::pin(restart.next_reconciled(&cx)).await.unwrap().is_none());
        assert!(client.client.inner.state.try_lock_owned().unwrap().current.is_none());
    });
}

#[test]
fn machine_restart_deadline_and_cancellation_preserve_all_unvisited_controls() {
    runtime().block_on(async {
        let cx = Cx::current().unwrap();
        for cancel_first in [false, true] {
            let client = consumer();
            let owner = binding(&client, "one");
            let saved = [record(&cx, &owner, "one"), record(&cx, &owner, "two")];
            let cancellation = McpRequestCancellation::new();
            let mut restart = client.prepare_task_restart_with_cancellation(&cx, &cancellation, owner,
                saved.clone(), "stopped".to_owned(), ClientCredentialsTaskRestartPolicy::default()).unwrap();
            if cancel_first { cancellation.cancel(); } else { restart.deadline = cx.now(); }
            assert!(Box::pin(restart.next_reconciled(&cx)).await.is_err());
            assert_eq!((restart.remaining(), restart.attempted(), restart.delivered()), (2, 0, 0));
            assert!(restart.pending_record().is_none());
            assert!(restart.take_pending().is_none());
            assert!(matches!(Box::pin(restart.next_reconciled(&cx)).await, Err(ClientCredentialsTaskResumeError::Closed)));
            assert!(client.client.inner.state.try_lock_owned().unwrap().current.is_none());
        }
    });
}

#[test]
fn machine_restart_handoff_checks_fresh_controls_and_keeps_terminal_payload_out_of_storage() {
    let cx = Cx::for_testing();
    let client = consumer();
    let owner = binding(&client, "one");
    let previous = record(&cx, &owner, "one");
    let next = task("one", "input_required", 2);
    let controls = TaskResumeChange::from_snapshot(&cx, &owner, &previous, &next).unwrap().replacement().unwrap().clone();
    let mut item = ClientCredentialsTaskRestartItem { previous: previous.clone(),
        outcome: ClientCredentialsTaskRestartOutcome::Reconciled(ClientCredentialsTaskResumeReconciliation::Active {
            task: Box::new(next), record: controls.clone(),
        }) };
    assert_eq!(item.storage_change(&cx, &owner).unwrap().replacement(), Some(&controls));
    if let ClientCredentialsTaskRestartOutcome::Reconciled(ClientCredentialsTaskResumeReconciliation::Active { record, .. }) = &mut item.outcome {
        *record = previous.clone();
    }
    assert!(matches!(item.storage_change(&cx, &owner), Err(TaskResumeError::ConflictingSnapshot)));
    item.outcome = ClientCredentialsTaskRestartOutcome::Reconciled(
        ClientCredentialsTaskResumeReconciliation::Terminal(Box::new(task("one", "completed", 2))));
    let change = item.storage_change(&cx, &owner).unwrap();
    assert!(change.replacement().is_none());
    assert_eq!(change.previous(), &previous);
    assert!(!change.previous().encode().unwrap().windows(7).any(|part| part == b"PRIVATE"));
    assert!(matches!(item.storage_change(&cx, &binding(&client, "other")), Err(TaskResumeError::Unavailable)));
    assert_eq!(item.previous, previous);
}

#[test]
fn machine_resume_unavailable_mapping_does_not_hide_operational_or_security_protocol_errors() {
    for status in [401, 403, 404] {
        assert!(matches!(classify_unavailable(ManagedTasksError::HttpStatus { status }.into()),
            ClientCredentialsTaskResumeError::Resume(TaskResumeError::Unavailable)));
    }
    for error in [ManagedTasksError::HttpStatus { status: 503 }, ManagedTasksError::InvalidResponse,
        ManagedTasksError::TaskIdMismatch, ManagedTasksError::ResponseIdMismatch]
    {
        assert!(matches!(classify_unavailable(error.into()), ClientCredentialsTaskResumeError::Task(_)));
    }
    assert!(matches!(classify_unavailable(ClientCredentialsError::Expired.into()),
        ClientCredentialsTaskResumeError::Task(ClientCredentialsTasksError::Authentication(ClientCredentialsError::Expired))));
    assert!(ClientCredentialsTaskRestartPolicy::new(129, 4096, Duration::from_secs(1)).is_err());
    assert!(ClientCredentialsTaskRestartPolicy::new(1, 4096, Duration::ZERO).is_err());
}
