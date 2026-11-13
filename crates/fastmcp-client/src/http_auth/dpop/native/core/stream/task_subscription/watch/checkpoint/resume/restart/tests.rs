use super::super::super::DpopTaskWatchCheckpoint;
use super::super::reconciled;
use super::super::tests::{binding, record, snapshot};
use super::*;

fn active(cx: &Cx, current: &TaskResumeBinding) -> DpopTaskRestartItem {
    let previous = record(cx, current);
    let observed = reconciled(cx, current, &previous, snapshot("input_required", 2)).unwrap();
    DpopTaskRestartItem {
        previous,
        outcome: DpopTaskRestartOutcome::Reconciled(observed),
    }
}

#[test]
fn unavailable_disposition_requires_current_binding_and_keeps_exact_version() {
    let cx = Cx::for_testing();
    let current = binding("owner", "https://mcp.example/mcp");
    let item = DpopTaskRestartItem {
        previous: record(&cx, &current),
        outcome: DpopTaskRestartOutcome::Unavailable,
    };
    let before = item.previous.encode().unwrap();
    let change = item.storage_change(&cx, &current).unwrap();
    assert_eq!(change.previous().encode().unwrap(), before);
    assert!(change.replacement().is_none());
    assert!(matches!(
        item.storage_change(&cx, &binding("other", "https://mcp.example/mcp")),
        Err(TaskResumeError::Unavailable),
    ));
    assert_eq!(item.previous.encode().unwrap(), before);
}

#[test]
fn active_handoff_revalidates_controls_without_persisting_application_payloads() {
    let cx = Cx::for_testing();
    let current = binding("owner", "https://mcp.example/mcp");
    let item = active(&cx, &current);
    let change = item.storage_change(&cx, &current).unwrap();
    let replacement = change.replacement().unwrap().encode().unwrap();
    let previous = item.previous.encode().unwrap();
    assert_eq!(
        &replacement[replacement.len() - 16..],
        &previous[previous.len() - 16..]
    );
    assert!(!replacement.windows(6).any(|bytes| bytes == b"SECRET"));
    let DpopTaskRestartOutcome::Reconciled(observed) = &item.outcome else {
        panic!()
    };
    assert!(
        serde_json::to_string(observed.snapshot())
            .unwrap()
            .contains("SECRET-INPUT")
    );
    assert!(!format!("{item:?}").contains("SECRET"));
    assert!(!format!("{item:?}").contains("task-secret"));
}

#[test]
fn substituted_saved_version_or_selection_cannot_prepare_checkpoint_write() {
    let cx = Cx::for_testing();
    let current = binding("owner", "https://mcp.example/mcp");
    for changed_selection in [false, true] {
        let mut item = active(&cx, &current);
        if changed_selection {
            let DpopTaskRestartOutcome::Reconciled(observed) = &mut item.outcome else {
                panic!()
            };
            observed.selection = Some(
                DpopTaskWatchCheckpoint::new(
                    binding("owner", "https://mcp.example/other").resource(),
                    item.previous.task_id().clone(),
                )
                .unwrap(),
            );
        } else {
            // Change only the saved retention. The new value remains a valid
            // record but is not the exact version that produced this outcome.
            let mut bytes = item.previous.encode().unwrap();
            let end = bytes.len();
            let retain_until = i128::from_be_bytes(bytes[end - 16..].try_into().unwrap());
            bytes[end - 16..].copy_from_slice(&(retain_until - 1).to_be_bytes());
            item.previous = TaskResumeRecord::decode(&bytes).unwrap();
        }
        assert!(matches!(
            item.storage_change(&cx, &current),
            Err(TaskResumeError::ConflictingSnapshot)
        ));
    }
    assert!(active(&cx, &current).storage_change(&cx, &current).is_ok());
}

#[test]
fn terminal_handoff_keeps_result_until_explicit_local_disposition() {
    let cx = Cx::for_testing();
    let current = binding("owner", "https://mcp.example/mcp");
    let previous = record(&cx, &current);
    let mut value = serde_json::to_value(snapshot("working", 2)).unwrap();
    value["status"] = serde_json::json!("completed");
    value["result"] = serde_json::json!({"content":[{"type":"text","text":"PRIVATE-RESULT"}]});
    let snapshot = Box::new(serde_json::from_value(value).unwrap());
    let observed = reconciled(&cx, &current, &previous, snapshot).unwrap();
    let item = DpopTaskRestartItem {
        previous,
        outcome: DpopTaskRestartOutcome::Reconciled(observed),
    };
    let before = item.previous.encode().unwrap();
    let change = item.storage_change(&cx, &current).unwrap();
    assert!(change.replacement().is_none());
    assert_eq!(change.previous().encode().unwrap(), before);
    let DpopTaskRestartOutcome::Reconciled(observed) = &item.outcome else {
        panic!()
    };
    assert!(
        serde_json::to_string(observed.snapshot())
            .unwrap()
            .contains("PRIVATE-RESULT")
    );
    assert!(!format!("{change:?}").contains("PRIVATE"));
    assert_eq!(item.previous.encode().unwrap(), before);
}
