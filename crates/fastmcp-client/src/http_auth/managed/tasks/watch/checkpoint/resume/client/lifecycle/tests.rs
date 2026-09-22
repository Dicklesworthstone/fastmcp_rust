use super::*;
use super::super::super::tests::{binding, now, record};
use fastmcp_protocol::tasks_extension::{TaskStatus, TaskTimestamp};
use serde_json::json;
use std::cell::Cell;
use std::task::{Context, Poll, Waker};

fn snapshot(status: &str) -> Task {
    let mut value = json!({
        "taskId":"opaque / ID", "status":status,
        "createdAt":"2026-09-21T00:00:00Z", "lastUpdatedAt":"2026-09-21T00:00:02Z",
        "ttlMs":60000, "pollIntervalMs":2000, "statusMessage":"SECRET-STATUS",
    });
    match status {
        "input_required" => value["inputRequests"] = json!({"SECRET-INPUT":{"method":"roots/list"}}),
        "completed" => value["result"] = json!({"content":[{"type":"text","text":"SECRET-RESULT"}]}),
        "failed" => value["error"] = json!({"code":-32603,"message":"SECRET-ERROR"}),
        _ => {},
    }
    serde_json::from_value(value).unwrap()
}
fn change(status: &str) -> TaskResumeChange {
    TaskResumeChange::prepare_at(&binding(1), &record(), &snapshot(status), now()).unwrap()
}

#[test]
fn active_change_preserves_original_retention_and_never_carries_application_payloads() {
    let previous = record();
    for status in ["working", "input_required"] {
        let change = change(status);
        assert_eq!(change.previous, previous);
        let next = change.replacement().unwrap();
        assert_eq!(next.key(), previous.key());
        assert_eq!(next.retain_until, previous.retain_until);
        assert_eq!(next.updated_at.as_str(), "2026-09-21T00:00:02Z");
        assert!(!next.encode().unwrap().windows(6).any(|part| part == b"SECRET"));
        assert!(!format!("{change:?}").contains("opaque"));
        assert!(change.admit_expected(Some(&previous)).is_ok());
    }
}

#[test]
fn every_terminal_kind_prepares_only_a_conditional_removal() {
    for status in ["completed", "failed", "cancelled"] {
        let change = change(status);
        assert!(change.replacement().is_none());
        assert_eq!(change.key(), record().key());
        assert!(change.admit_expected(Some(&record())).is_ok());
        assert_eq!(change.admit_expected(None), Err(TaskResumeError::ConflictingSnapshot));
    }
}

#[test]
fn stale_cleanup_cannot_remove_a_newer_or_differently_retained_record() {
    for status in ["working", "cancelled"] {
        let change = change(status);
        for dimension in 0..3 {
            let mut actual = record();
            match dimension {
                0 => actual.updated_at = TaskTimestamp::parse("2026-09-21T00:00:03Z").unwrap(),
                1 => actual.retain_until -= 1,
                _ => actual.poll_interval_ms = Some(3000),
            }
            assert_eq!(actual.key(), change.key(), "Task ID equality is not version equality");
            assert_eq!(change.admit_expected(Some(&actual)), Err(TaskResumeError::ConflictingSnapshot));
        }
    }
}

#[test]
fn changed_authority_identity_or_stale_controls_do_not_prepare_a_write() {
    let previous = record();
    let saved = previous.encode().unwrap();
    assert!(matches!(TaskResumeChange::prepare_at(&binding(2), &previous, &snapshot("working"), now()),
        Err(TaskResumeError::Unavailable)));
    assert!(matches!(TaskResumeChange::prepare_at(&binding(1), &previous, &snapshot("cancelled"), previous.retain_until),
        Err(TaskResumeError::Unavailable)));
    for dimension in 0..3 {
        let mut task = snapshot("working");
        if let Task::Working(base) = &mut task {
            match dimension {
                0 => base.task_id = fastmcp_protocol::tasks_extension::TaskId::parse("other").unwrap(),
                1 => base.last_updated_at = TaskTimestamp::parse("2026-09-21T00:00:00Z").unwrap(),
                _ => base.status = TaskStatus::Cancelled,
            }
        }
        assert!(TaskResumeChange::prepare_at(&binding(1), &previous, &task, now()).is_err());
    }
    assert_eq!(previous.encode().unwrap(), saved);
}

#[test]
fn unpolled_write_has_no_effect_and_abandoned_write_remains_unconfirmed() {
    let calls = Cell::new(0);
    let mut persist = |_: TaskResumeChange| {
        calls.set(calls.get() + 1);
        std::future::pending::<Result<(), std::io::Error>>()
    };
    let mut state = TaskResumePersistenceState::NotAttempted;
    drop(persist_change(&mut state, &mut persist, change("working")));
    assert_eq!(calls.get(), 0);
    assert_eq!(state, TaskResumePersistenceState::NotAttempted);
    let mut writing = Box::pin(persist_change(&mut state, &mut persist, change("working")));
    let mut cx = Context::from_waker(Waker::noop());
    assert!(writing.as_mut().poll(&mut cx).is_pending());
    drop(writing);
    assert_eq!(calls.get(), 1);
    assert_eq!(state, TaskResumePersistenceState::Unconfirmed);
}

#[test]
fn only_a_successful_callback_acknowledges_a_storage_attempt() {
    for success in [true, false] {
        let mut state = TaskResumePersistenceState::NotAttempted;
        let mut persist = |_: TaskResumeChange| std::future::ready(
            if success { Ok(()) } else { Err(std::io::Error::other("SECRET-PROVIDER")) },
        );
        let mut writing = Box::pin(persist_change(&mut state, &mut persist, change("cancelled")));
        let mut cx = Context::from_waker(Waker::noop());
        let Poll::Ready(result) = writing.as_mut().poll(&mut cx) else { panic!("ready callback must settle"); };
        assert_eq!(result.is_ok(), success);
        drop(writing);
        assert_eq!(state, if success { TaskResumePersistenceState::Acknowledged } else { TaskResumePersistenceState::Unconfirmed });
    }
}

#[test]
fn pending_snapshot_keeps_application_state_separate_from_redacted_diagnostics() {
    let pending = PendingTaskResumeSnapshot {
        snapshot: ManagedTaskSnapshot {
            task: Box::new(snapshot("input_required")),
            cause: crate::http_auth::managed::tasks::watch::ManagedTaskSnapshotCause::Initial,
        },
        change: change("input_required"),
        persistence: TaskResumePersistenceState::Unconfirmed,
    };
    for secret in ["SECRET", "opaque", "2026-09"] { assert!(!format!("{pending:?}").contains(secret)); }
    let (observed, change, state) = pending.into_parts();
    assert!(matches!(*observed.task, Task::InputRequired { .. }));
    assert!(change.replacement().is_some());
    assert_eq!(state, TaskResumePersistenceState::Unconfirmed);
}

#[test]
fn host_failure_is_redacted_but_preserved_as_a_typed_error_source() {
    let error = PersistedTaskWatchError::Persistence(std::io::Error::other("SECRET-PROVIDER-PATH"));
    assert!(!format!("{error:?} {error}").contains("SECRET"));
    let source = std::error::Error::source(&error).unwrap();
    assert_eq!(source.downcast_ref::<std::io::Error>().unwrap().kind(), std::io::ErrorKind::Other);
}
