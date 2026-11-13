//! Real selected-root TLS peers exercise the public protected restart owner.
//! These tests establish transport and checkpoint custody, not deployment or
//! protection-provider qualification.

use super::super::super::super::DpopTaskWatchError;
use super::super::super::DpopTaskCheckpointError;
use super::super::tests::{binding, snapshot};
use super::super::tls::{Peer, closed, json_reply, limits, meta, pair, run, turn_envelope};
use super::*;
use crate::http_auth::dpop::native::core::DpopCoreError;
use crate::http_auth::dpop::native::core::stream::DpopStreamError;
use crate::http_auth::managed::tasks::watch::checkpoint::resume::client::restart::{
    TaskResumeRestartPlan, TaskResumeRestartPolicy,
};
use crate::http_auth::rpc::{ManagedCoreError, ManagedCoreLimits};
use fastmcp_protocol::tasks_extension::GetTaskResult;
use serde_json::{Value, json};
use std::future::{Future, poll_fn};
use std::time::Duration;

fn fresh(task_id: &str, status: &str, second: u8) -> Value {
    let active = if status == "completed" {
        "working"
    } else {
        status
    };
    let mut value = serde_json::to_value(snapshot(active, second)).unwrap();
    value["taskId"] = json!(task_id);
    value["status"] = json!(status);
    if status == "completed" {
        value["result"] = json!({"content":[{"type":"text","text":"RESTART-PRIVATE-RESULT"}],
            "_meta":{"private":"RESTART-PRIVATE-RESULT-META"}});
    }
    value
}

fn saved(cx: &Cx, current: &TaskResumeBinding, task_id: &str) -> TaskResumeRecord {
    let task: GetTaskResult = serde_json::from_value(fresh(task_id, "working", 1)).unwrap();
    TaskResumeRecord::capture(cx, current, &task.task, Duration::from_secs(3600)).unwrap()
}

fn plan(cx: &Cx, current: &TaskResumeBinding) -> TaskResumeRestartPlan {
    TaskResumeRestartPlan::from_records(
        cx,
        current,
        [
            saved(cx, current, "restart-second"),
            saved(cx, current, "restart-first"),
        ],
        TaskResumeRestartPolicy::default(),
    )
    .unwrap()
}

#[test]
fn protected_restart_reconciles_the_whole_staged_selection_with_fresh_proofs() {
    run(async {
        let cx = Cx::current().unwrap();
        let (mut peer, mut client, credential) = Peer::new().await;
        let current = binding("owner", client.resource().as_str());
        let plan = plan(&cx, &current);
        let ordered: Vec<_> = plan.records().cloned().collect();
        let original: Vec<_> = ordered
            .iter()
            .map(|record| record.encode().unwrap())
            .collect();
        let cancellation = McpRequestCancellation::new();
        let mut restart = client
            .prepare_task_restart(
                &cx,
                &cancellation,
                &credential,
                meta(),
                current.clone(),
                plan,
                "batch".to_owned(),
                limits(),
            )
            .unwrap();
        let read = async {
            for (index, previous) in ordered.iter().enumerate() {
                let item = restart.next_reconciled(&cx).await.unwrap().unwrap();
                assert_eq!(&item.previous, previous);
                let DpopTaskRestartOutcome::Reconciled(value) = item.outcome else {
                    panic!("fresh authorized Task must produce its snapshot");
                };
                let status = if index == 0 {
                    "input_required"
                } else {
                    "completed"
                };
                assert_eq!(
                    serde_json::to_value(value.snapshot()).unwrap(),
                    fresh(previous.task_id().as_str(), status, 2)
                );
                assert_eq!(value.change().previous(), previous);
                assert_eq!(value.change().replacement().is_some(), index == 0);
                assert_eq!(value.selection().is_some(), index == 0);
                if let Some(replacement) = value.change().replacement() {
                    let before = previous.encode().unwrap();
                    let after = replacement.encode().unwrap();
                    assert_eq!(
                        &after[after.len() - 16..],
                        &before[before.len() - 16..],
                        "an active restart retains the original host expiry"
                    );
                    assert!(
                        !after
                            .windows(b"SECRET".len())
                            .any(|bytes| bytes == b"SECRET")
                    );
                }
            }
            assert!(restart.next_reconciled(&cx).await.unwrap().is_none());
        };
        let serve = async {
            for (index, previous) in ordered.iter().enumerate() {
                let mut socket = peer
                    .get_turn("batch", index, previous.task_id().as_str())
                    .await;
                let status = if index == 0 {
                    "input_required"
                } else {
                    "completed"
                };
                json_reply(
                    &mut socket,
                    200,
                    &turn_envelope(
                        "batch",
                        index,
                        false,
                        fresh(previous.task_id().as_str(), status, 2),
                    ),
                )
                .await;
            }
        };
        pair(read, serve).await;
        assert_eq!(restart.attempted(), 2);
        assert_eq!(restart.delivered(), 2);
        assert!(restart.pending_record().is_none());
        assert!(restart.pending_outcome().is_none());
        assert_eq!(restart.unvisited().count(), 0);
        assert_eq!(
            ordered
                .iter()
                .map(|record| record.encode().unwrap())
                .collect::<Vec<_>>(),
            original
        );
        drop(restart);
        peer.no_extra(4);
        assert!(!client.revocation_handle().is_revoked());
    });
}

#[test]
fn protected_restart_rejects_foreign_owner_and_resource_before_any_connection() {
    run(async {
        let cx = Cx::current().unwrap();
        for different_resource in [false, true] {
            let (peer, mut client, credential) = Peer::new().await;
            let current = binding("owner", client.resource().as_str());
            let other = if different_resource {
                binding("owner", "https://different.example/mcp?tenant=one")
            } else {
                binding("different-owner", client.resource().as_str())
            };
            // Resource mismatch uses a plan genuinely bound to that resource,
            // so the selected transport itself must independently refuse it.
            let staged = plan(&cx, if different_resource { &other } else { &current });
            let cancellation = McpRequestCancellation::new();
            let result = client.prepare_task_restart(
                &cx,
                &cancellation,
                &credential,
                meta(),
                other,
                staged,
                "foreign".to_owned(),
                limits(),
            );
            assert!(matches!(
                result,
                Err(DpopTaskRestartError::Resume(DpopTaskResumeError::Resume(
                    TaskResumeError::Unavailable
                )))
            ));
            peer.no_extra(0);
        }
    });
}

#[test]
fn protected_restart_reports_expired_controls_without_contact_or_automatic_cleanup() {
    run(async {
        let cx = Cx::current().unwrap();
        let (peer, mut client, credential) = Peer::new().await;
        let current = binding("owner", client.resource().as_str());
        let mut bytes = saved(&cx, &current, "expired-task").encode().unwrap();
        let end = bytes.len();
        // Structurally valid controls whose original retention already ended.
        // This is a codec fixture, not a claim that raw bytes are authenticated.
        bytes[end - 16..].copy_from_slice(&1_600_000_000_000_000_000_i128.to_be_bytes());
        let expired = TaskResumeRecord::decode(&bytes).unwrap();
        assert_eq!(
            expired.admit(&cx, &current),
            Err(TaskResumeError::Unavailable)
        );
        let staged = TaskResumeRestartPlan::from_records(
            &cx,
            &current,
            [expired.clone()],
            TaskResumeRestartPolicy::default(),
        )
        .unwrap();
        let cancellation = McpRequestCancellation::new();
        let mut restart = client
            .prepare_task_restart(
                &cx,
                &cancellation,
                &credential,
                meta(),
                current.clone(),
                staged,
                "expired".to_owned(),
                limits(),
            )
            .unwrap();
        let item = restart.next_reconciled(&cx).await.unwrap().unwrap();
        assert_eq!(item.previous, expired);
        assert!(matches!(item.outcome, DpopTaskRestartOutcome::Unavailable));
        assert_eq!(restart.attempted(), 0);
        assert_eq!(restart.delivered(), 1);
        assert!(restart.next_reconciled(&cx).await.unwrap().is_none());
        assert_eq!(expired.encode().unwrap(), bytes);
        drop(restart);
        peer.no_extra(0);
        assert!(!client.revocation_handle().is_revoked());
    });
}

#[test]
fn protected_restart_abandoned_get_retains_current_and_unvisited_records_without_retry() {
    run(async {
        let cx = Cx::current().unwrap();
        let (mut peer, mut client, credential) = Peer::new().await;
        let current = binding("owner", client.resource().as_str());
        let staged = plan(&cx, &current);
        let ordered: Vec<_> = staged.records().cloned().collect();
        let cancellation = McpRequestCancellation::new();
        let arrived = McpRequestCancellation::new();
        let mut restart = client
            .prepare_task_restart(
                &cx,
                &cancellation,
                &credential,
                meta(),
                current.clone(),
                staged,
                "abandoned".to_owned(),
                limits(),
            )
            .unwrap();
        let mut read = Box::pin(restart.next_reconciled(&cx));
        let abandon = async {
            let mut ready = std::pin::pin!(arrived.cancelled());
            poll_fn(|task| {
                assert!(read.as_mut().poll(task).is_pending());
                ready.as_mut().poll(task)
            })
            .await;
            drop(read);
        };
        let serve = async {
            let mut socket = peer
                .get_turn("abandoned", 0, ordered[0].task_id().as_str())
                .await;
            arrived.cancel();
            closed(&mut socket).await;
        };
        pair(abandon, serve).await;
        assert_eq!(restart.pending_record(), Some(&ordered[0]));
        assert!(restart.pending_outcome().is_none());
        assert_eq!(
            restart.unvisited().cloned().collect::<Vec<_>>(),
            ordered[1..]
        );
        assert_eq!(restart.attempted(), 1);
        assert_eq!(restart.delivered(), 0);
        assert!(matches!(
            restart.next_reconciled(&cx).await,
            Err(DpopTaskRestartError::Closed)
        ));
        drop(restart);
        peer.no_extra(2);
        assert!(!cancellation.is_cancel_requested());
        assert!(!client.revocation_handle().is_revoked());
    });
}

#[test]
fn protected_restart_charges_unavailable_discovery_bodies_against_one_batch_budget() {
    // The same pair of denied responses is accepted at the exact aggregate
    // byte bound and refused when that single bound is one byte smaller.
    for total in [1800, 1799] {
        run(async {
            let cx = Cx::current().unwrap();
            let (mut peer, mut client, credential) = Peer::new().await;
            let current = binding("owner", client.resource().as_str());
            let staged = plan(&cx, &current);
            let ordered: Vec<_> = staged.records().cloned().collect();
            let limits = DpopStreamLimits::new(
                ManagedCoreLimits::new(8192, 900, total, 0, Duration::from_secs(30)).unwrap(),
                Duration::from_secs(30),
            )
            .unwrap();
            let cancellation = McpRequestCancellation::new();
            let mut restart = client
                .prepare_task_restart(
                    &cx,
                    &cancellation,
                    &credential,
                    meta(),
                    current.clone(),
                    staged,
                    "denied".to_owned(),
                    limits,
                )
                .unwrap();
            let read = async {
                let first = restart.next_reconciled(&cx).await.unwrap().unwrap();
                assert_eq!(first.previous, ordered[0]);
                assert!(matches!(first.outcome, DpopTaskRestartOutcome::Unavailable));
                let second = restart.next_reconciled(&cx).await;
                if total == 1800 {
                    let second = second.unwrap().unwrap();
                    assert_eq!(second.previous, ordered[1]);
                    assert!(matches!(
                        second.outcome,
                        DpopTaskRestartOutcome::Unavailable
                    ));
                    assert!(restart.next_reconciled(&cx).await.unwrap().is_none());
                } else {
                    assert!(matches!(
                        second,
                        Err(DpopTaskRestartError::Resume(
                            DpopTaskResumeError::Checkpoint(DpopTaskCheckpointError::Watch(
                                DpopTaskWatchError::Stream(DpopStreamError::Core(
                                    DpopCoreError::Protocol(ManagedCoreError::ResponseByteLimit)
                                ))
                            ))
                        ))
                    ));
                    assert_eq!(restart.pending_record(), Some(&ordered[1]));
                    assert!(restart.pending_outcome().is_none());
                    assert!(matches!(
                        restart.next_reconciled(&cx).await,
                        Err(DpopTaskRestartError::Closed)
                    ));
                }
            };
            let serve = async {
                for (index, previous) in ordered.iter().enumerate() {
                    let mut socket = peer
                        .request_turn("denied", index, true, previous.task_id().as_str())
                        .await;
                    json_reply(&mut socket, 403, &vec![b'x'; 900]).await;
                }
            };
            pair(read, serve).await;
            assert_eq!(restart.attempted(), 2);
            assert_eq!(restart.delivered(), if total == 1800 { 2 } else { 1 });
            drop(restart);
            peer.no_extra(2); // Rejected discovery never reaches tasks/get.
            assert!(!client.revocation_handle().is_revoked());
        });
    }
}
