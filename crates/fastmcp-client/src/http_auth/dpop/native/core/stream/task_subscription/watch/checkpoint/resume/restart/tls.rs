//! Real selected-root TLS peers exercise the public protected restart owner.
//! These tests establish transport and checkpoint custody, not deployment or
//! protection-provider qualification.

use super::super::super::super::DpopTaskWatchError;
use super::super::super::DpopTaskCheckpointError;
use super::super::tests::{binding, snapshot};
use super::super::tls::{Peer, closed, json_reply, limits, meta, pair, run, turn_envelope};
use super::*;
use crate::http_auth::dpop::DpopClientError;
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

fn transport_error(error: DpopTaskRestartError) -> DpopHttpError {
    let DpopTaskRestartError::Resume(DpopTaskResumeError::Checkpoint(
        DpopTaskCheckpointError::Watch(DpopTaskWatchError::Stream(DpopStreamError::Core(
            DpopCoreError::Transport(error),
        ))),
    )) = error
    else {
        panic!("the original remote lifetime must retain its typed cause");
    };
    error
}

#[test]
fn protected_restart_retains_each_original_cancellation_domain_between_records() {
    for stop in 0..4 {
        run(async {
            let cx = Cx::current().unwrap();
            let (mut peer, mut client, credential) = Peer::new().await;
            let session = client.revocation_handle();
            let current = binding("owner", client.resource().as_str());
            let staged = plan(&cx, &current);
            let ordered: Vec<_> = staged.records().cloned().collect();
            let cancellation = McpRequestCancellation::new();
            let mut restart = client
                .prepare_task_restart(
                    &cx,
                    &cancellation,
                    &credential,
                    meta(),
                    current.clone(),
                    staged,
                    "cancelled".to_owned(),
                    limits(),
                )
                .unwrap();
            let serve = async {
                let mut socket = peer
                    .get_turn("cancelled", 0, ordered[0].task_id().as_str())
                    .await;
                json_reply(
                    &mut socket,
                    200,
                    &turn_envelope(
                        "cancelled",
                        0,
                        false,
                        fresh(ordered[0].task_id().as_str(), "working", 2),
                    ),
                )
                .await;
            };
            let (first, ()) = pair(restart.next_reconciled(&cx), serve).await;
            assert!(matches!(
                first.unwrap().unwrap().outcome,
                DpopTaskRestartOutcome::Reconciled(_)
            ));
            match stop {
                0 => {
                    cancellation.cancel();
                }
                1 => {
                    session.revoke();
                }
                2 => {
                    credential.revoke();
                }
                3 => {
                    cx.set_cancel_requested(true);
                }
                _ => unreachable!(),
            }
            let error = transport_error(restart.next_reconciled(&cx).await.unwrap_err());
            assert!(match stop {
                0 | 3 => matches!(error, DpopHttpError::Cancelled),
                1 => matches!(
                    error,
                    DpopHttpError::Authorization(DpopClientError::SessionRevoked)
                ),
                2 => matches!(
                    error,
                    DpopHttpError::Authorization(DpopClientError::CredentialUnavailable)
                ),
                _ => false,
            });
            assert!(restart.is_closed());
            assert_eq!(restart.attempted(), 1);
            assert_eq!(restart.delivered(), 1);
            assert!(restart.pending_record().is_none());
            assert_eq!(
                restart.unvisited().cloned().collect::<Vec<_>>(),
                ordered[1..]
            );
            assert!(matches!(
                restart.next_reconciled(&cx).await,
                Err(DpopTaskRestartError::Closed)
            ));
            drop(restart);
            peer.no_extra(2);
            assert_eq!(client.revocation_handle().is_revoked(), stop == 1);
        });
    }
}

#[test]
fn protected_restart_host_pause_does_not_restart_the_original_batch_deadline() {
    run(async {
        let cx = Cx::current().unwrap();
        let (mut peer, mut client, credential) = Peer::new().await;
        let current = binding("owner", client.resource().as_str());
        let records: Vec<_> = plan(&cx, &current).records().cloned().collect();
        let staged = TaskResumeRestartPlan::from_records(
            &cx,
            &current,
            records.clone(),
            TaskResumeRestartPolicy::new(2, 4096, Duration::from_secs(3)).unwrap(),
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
                "deadline".to_owned(),
                limits(),
            )
            .unwrap();
        let serve = async {
            let mut socket = peer
                .get_turn("deadline", 0, records[0].task_id().as_str())
                .await;
            json_reply(
                &mut socket,
                200,
                &turn_envelope(
                    "deadline",
                    0,
                    false,
                    fresh(records[0].task_id().as_str(), "working", 2),
                ),
            )
            .await;
        };
        let (first, ()) = pair(restart.next_reconciled(&cx), serve).await;
        assert!(matches!(
            first.unwrap().unwrap().outcome,
            DpopTaskRestartOutcome::Reconciled(_)
        ));
        // Model host-side result handling. The next read must use the original
        // absolute deadline even though no network operation was being polled.
        asupersync::time::sleep(cx.now(), Duration::from_millis(3050)).await;
        assert!(matches!(
            transport_error(restart.next_reconciled(&cx).await.unwrap_err()),
            DpopHttpError::TimedOut
        ));
        assert!(restart.is_closed());
        assert_eq!(restart.attempted(), 1);
        assert_eq!(restart.delivered(), 1);
        assert_eq!(
            restart.unvisited().cloned().collect::<Vec<_>>(),
            records[1..]
        );
        assert!(
            records[1].admit(&cx, &current).is_ok(),
            "saved retention remains live"
        );
        drop(restart);
        peer.no_extra(2);
        assert!(!client.revocation_handle().is_revoked());
    });
}

#[test]
fn protected_restart_does_not_skip_operational_or_malformed_discovery_failures() {
    for status in [500, 200] {
        run(async {
            let cx = Cx::current().unwrap();
            let (mut peer, mut client, credential) = Peer::new().await;
            let current = binding("owner", client.resource().as_str());
            let staged = plan(&cx, &current);
            let ordered: Vec<_> = staged.records().cloned().collect();
            let cancellation = McpRequestCancellation::new();
            let mut restart = client
                .prepare_task_restart(
                    &cx,
                    &cancellation,
                    &credential,
                    meta(),
                    current.clone(),
                    staged,
                    "failed".to_owned(),
                    limits(),
                )
                .unwrap();
            let serve = async {
                let mut socket = peer
                    .request_turn("failed", 0, true, ordered[0].task_id().as_str())
                    .await;
                json_reply(&mut socket, status, b"PRIVATE-MALFORMED-RESPONSE").await;
            };
            let (result, ()) = pair(restart.next_reconciled(&cx), serve).await;
            let error = result.unwrap_err();
            assert!(!format!("{error:?}").contains("PRIVATE-MALFORMED-RESPONSE"));
            let DpopTaskRestartError::Resume(DpopTaskResumeError::Checkpoint(
                DpopTaskCheckpointError::Watch(DpopTaskWatchError::Stream(DpopStreamError::Core(
                    DpopCoreError::Protocol(error),
                ))),
            )) = error
            else {
                panic!("the failed read must keep its typed protocol error");
            };
            assert!(if status == 500 {
                matches!(error, ManagedCoreError::HttpStatus { status: 500 })
            } else {
                matches!(error, ManagedCoreError::InvalidResponse)
            });
            assert!(restart.is_closed());
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
            peer.no_extra(1);
            assert!(!client.revocation_handle().is_revoked());
        });
    }
}

#[cfg(target_os = "linux")]
mod persistence {
    use super::*;
    use std::collections::BTreeMap;
    use std::fs::{self, File};
    use std::os::unix::fs::DirBuilderExt;
    use std::path::PathBuf;
    use std::sync::{Arc, Condvar, Mutex};
    use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
    use std::task::Poll;
    use asupersync::runtime::{RuntimeBuilder, reactor::create_reactor};
    use fastmcp_core::runtime::ProcessGenerationGuard;
    use crate::http_auth::managed::tasks::watch::checkpoint::resume::store::{
        TaskResumeProtector, TaskResumeStoreLimits,
    };
    use crate::http_auth::managed::tasks::watch::checkpoint::resume::store::asynchronous::AsyncTaskResumeStore;
    use crate::http_auth::managed::tasks::watch::checkpoint::resume::store::asynchronous::persistence::{
        TaskResumePersistenceError, TaskResumePersistenceStatus,
    };
    use crate::http_auth::managed::tasks::watch::checkpoint::resume::store::asynchronous::restart::workflow::{
        PersistedTaskRestartError, RestartCheckpointState,
    };
    use crate::http_auth::secure_file::slot::coordinator::asynchronous::{
        CredentialIoError, CredentialIoLane, CredentialIoLimits,
    };

    struct Directory(PathBuf);
    impl Directory {
        fn new() -> Self {
            static NEXT: AtomicU64 = AtomicU64::new(0);
            for _ in 0..64 {
                let path = std::env::temp_dir().join(format!(
                    "fastmcp-dpop-restart-{}-{}",
                    std::process::id(),
                    NEXT.fetch_add(1, Ordering::Relaxed)
                ));
                match fs::DirBuilder::new().mode(0o700).create(&path) {
                    Ok(()) => return Self(path),
                    Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
                    Err(error) => panic!("private restart fixture directory: {error}"),
                }
            }
            panic!("private restart fixture name attempts exhausted");
        }
        fn bytes(&self) -> Vec<u8> {
            fs::read(self.0.join("tasks")).unwrap()
        }
    }
    impl Drop for Directory {
        fn drop(&mut self) {
            // Only names owned by this create-new private fixture directory.
            let _ = fs::remove_file(self.0.join("tasks"));
            let _ = fs::remove_file(self.0.join(".tasks.lock"));
            let _ = fs::remove_dir(&self.0);
        }
    }

    #[derive(Default)]
    struct Gate {
        entered: AtomicBool,
        released: Mutex<bool>,
        condition: Condvar,
    }
    impl Gate {
        fn block(&self) {
            self.entered.store(true, Ordering::Release);
            let held = self.released.lock().unwrap();
            let (held, _) = self
                .condition
                .wait_timeout_while(held, Duration::from_secs(5), |released| !*released)
                .unwrap();
            assert!(*held, "bounded fixture protector must be released");
        }
        fn release(&self) {
            *self.released.lock().unwrap() = true;
            self.condition.notify_all();
        }
        async fn wait_entered(&self, cx: &Cx) {
            asupersync::time::timeout(cx.now(), Duration::from_secs(2), async {
                while !self.entered.load(Ordering::Acquire) {
                    asupersync::time::sleep(cx.now(), Duration::from_millis(1)).await;
                }
            })
            .await
            .expect("worker must enter while the poller remains available");
        }
    }
    struct Release(Arc<Gate>);
    impl Drop for Release {
        fn drop(&mut self) {
            self.0.release();
        }
    }

    // Opaque reference tokens model a bounded protector; this is NOT encryption
    // or qualification of a host's cross-process key custody. The actual Linux
    // file adapter, exclusive I/O lane and ACK transaction are exercised here.
    type VaultRecords = BTreeMap<Vec<u8>, ([u8; 32], Vec<u8>)>;
    #[derive(Clone, Default)]
    struct Vault {
        records: Arc<Mutex<VaultRecords>>,
        seals: Arc<AtomicUsize>,
        pause: Arc<AtomicBool>,
        gate: Arc<Gate>,
    }
    impl TaskResumeProtector for Vault {
        fn profile(&self) -> [u8; 32] {
            [4; 32]
        }
        fn seal(
            &mut self,
            _: &Cx,
            binding: &[u8; 32],
            plaintext: &[u8],
            maximum: usize,
        ) -> Result<Vec<u8>, TaskResumeError> {
            let serial = self.seals.fetch_add(1, Ordering::SeqCst);
            if self.pause.load(Ordering::SeqCst) {
                self.gate.block();
            }
            if maximum < 8 || plaintext.len() > 65536 {
                return Err(TaskResumeError::Protection);
            }
            let mut records = self.records.lock().unwrap();
            if records.len() >= 16 {
                return Err(TaskResumeError::Capacity);
            }
            let token = (serial as u64).to_be_bytes().to_vec();
            records.insert(token.clone(), (*binding, plaintext.to_vec()));
            Ok(token)
        }
        fn open(
            &mut self,
            _: &Cx,
            binding: &[u8; 32],
            ciphertext: &[u8],
            maximum: usize,
        ) -> Result<Vec<u8>, TaskResumeError> {
            let records = self.records.lock().unwrap();
            let (owner, bytes) = records.get(ciphertext).ok_or(TaskResumeError::Protection)?;
            if owner != binding || bytes.len() > maximum {
                return Err(TaskResumeError::Protection);
            }
            Ok(bytes.clone())
        }
    }

    fn run(future: impl Future<Output = ()>) {
        let runtime = RuntimeBuilder::current_thread()
            .blocking_threads(1, 1)
            .with_reactor(create_reactor().unwrap())
            .build()
            .unwrap();
        runtime.block_on(async {
            let cx = Cx::current().unwrap();
            asupersync::time::timeout(cx.now(), Duration::from_secs(15), future)
                .await
                .expect("live protected restart must settle within its bound");
        });
        assert!(runtime.shutdown_timeout(Duration::from_secs(2)));
    }

    async fn open(
        cx: &Cx,
        lane: &CredentialIoLane,
        guard: &ProcessGenerationGuard,
        directory: &Directory,
        vault: Vault,
        current: &TaskResumeBinding,
    ) -> AsyncTaskResumeStore<Vault> {
        AsyncTaskResumeStore::open(
            cx,
            lane,
            guard.token(),
            File::open(&directory.0).unwrap(),
            "tasks".to_owned(),
            65536,
            vault,
            current.clone(),
            TaskResumeStoreLimits::new(8, 65536).unwrap(),
        )
        .unwrap()
        .wait(cx)
        .await
        .unwrap()
        .unwrap()
    }

    fn assert_terminal(item: &DpopTaskRestartItem) {
        let DpopTaskRestartOutcome::Reconciled(value) = &item.outcome else {
            panic!("the freshly received terminal result must remain in custody");
        };
        assert!(value.selection().is_none());
        assert_eq!(
            serde_json::to_value(value.snapshot()).unwrap(),
            fresh(item.previous.task_id().as_str(), "completed", 2)
        );
    }

    async fn close(cx: &Cx, lane: &CredentialIoLane, store: AsyncTaskResumeStore<Vault>) {
        store.close(cx).unwrap().wait(cx).await.unwrap();
        lane.begin_shutdown().unwrap();
        lane.wait_drained(cx, Duration::from_secs(2)).await.unwrap();
    }

    #[test]
    fn persisted_dpop_restart_stages_all_pages_and_requires_ack_before_successor() {
        run(async {
            let cx = Cx::current().unwrap();
            let (mut peer, mut client, credential) = Peer::new().await;
            let current = binding("owner", client.resource().as_str());
            let ordered: Vec<_> = plan(&cx, &current).records().cloned().collect();
            let guard = ProcessGenerationGuard::install().unwrap();
            let lane = CredentialIoLane::new(&guard, CredentialIoLimits::default()).unwrap();
            let directory = Directory::new();
            let vault = Vault::default();
            let mut store = open(&cx, &lane, &guard, &directory, vault.clone(), &current).await;
            for previous in &ordered {
                let (owner, result) = store
                    .try_insert(&cx, current.clone(), previous.clone())
                    .unwrap()
                    .wait(&cx)
                    .await
                    .unwrap()
                    .into_parts();
                result.unwrap();
                store = owner;
            }
            let original = directory.bytes();
            let staged = store
                .try_load_restart(&cx, current.clone(), 1, TaskResumeRestartPolicy::default())
                .unwrap()
                .wait(&cx)
                .await
                .unwrap();
            assert_eq!(directory.bytes(), original);
            let cancellation = McpRequestCancellation::new();
            let mut restart = staged
                .prepare_persisted_dpop_restart(
                    &cx,
                    &mut client,
                    &cancellation,
                    &credential,
                    meta(),
                    "stored".to_owned(),
                    limits(),
                )
                .unwrap();
            assert_eq!(restart.restart_state().unvisited().count(), 2);
            let read = async {
                let item = restart.next_reconciled(&cx).await.unwrap().unwrap();
                assert_eq!(item.previous, ordered[0]);
                let DpopTaskRestartOutcome::Reconciled(value) = &item.outcome else {
                    panic!("the first Task must remain active");
                };
                assert_eq!(
                    serde_json::to_value(value.snapshot()).unwrap(),
                    fresh(ordered[0].task_id().as_str(), "input_required", 2)
                );
                value.change().replacement().unwrap().clone()
            };
            let serve = async {
                let mut socket = peer
                    .get_turn("stored", 0, ordered[0].task_id().as_str())
                    .await;
                json_reply(
                    &mut socket,
                    200,
                    &turn_envelope(
                        "stored",
                        0,
                        false,
                        fresh(ordered[0].task_id().as_str(), "input_required", 2),
                    ),
                )
                .await;
            };
            let (replacement, ()) = pair(read, serve).await;
            assert_eq!(directory.bytes(), original);
            assert_eq!(
                restart.checkpoint_state(),
                RestartCheckpointState::NotAttempted
            );
            assert!(matches!(
                restart.next_reconciled(&cx).await,
                Err(PersistedDpopTaskRestartError::Checkpoint(
                    PersistedTaskRestartError::AcknowledgementRequired
                ))
            ));
            drop(restart.acknowledge(&cx)); // An unpolled ACK changes nothing.
            assert_eq!(vault.seals.load(Ordering::SeqCst), 2);
            assert_eq!(directory.bytes(), original);
            peer.no_extra(2);
            let acknowledged = restart.acknowledge(&cx).await.unwrap();
            assert_eq!(acknowledged.previous, ordered[0]);
            assert!(restart.pending().is_none());
            let updated = directory.bytes();
            assert_ne!(updated, original);

            let read = async {
                assert_terminal(restart.next_reconciled(&cx).await.unwrap().unwrap());
            };
            let serve = async {
                let mut socket = peer
                    .get_turn("stored", 1, ordered[1].task_id().as_str())
                    .await;
                json_reply(
                    &mut socket,
                    200,
                    &turn_envelope(
                        "stored",
                        1,
                        false,
                        fresh(ordered[1].task_id().as_str(), "completed", 2),
                    ),
                )
                .await;
            };
            pair(read, serve).await;
            assert_eq!(
                directory.bytes(),
                updated,
                "terminal delivery alone cannot remove its checkpoint"
            );
            assert_terminal(&restart.acknowledge(&cx).await.unwrap());
            assert!(restart.next_reconciled(&cx).await.unwrap().is_none());
            let parts = restart.into_parts();
            assert!(parts.pending.is_none());
            assert!(parts.pending_change.is_none());
            let store = parts.storage.take_store().unwrap();
            store.close(&cx).unwrap().wait(&cx).await.unwrap();
            drop(parts);

            // Verify the persisted effects through a fresh protected file open,
            // including the terminal removal and preserved active controls.
            let store = open(&cx, &lane, &guard, &directory, vault.clone(), &current).await;
            let (store, loaded) = store
                .try_get(&cx, current.clone(), ordered[0].key())
                .unwrap()
                .wait(&cx)
                .await
                .unwrap()
                .into_parts();
            assert_eq!(loaded.unwrap(), Some(replacement));
            let (store, loaded) = store
                .try_get(&cx, current.clone(), ordered[1].key())
                .unwrap()
                .wait(&cx)
                .await
                .unwrap()
                .into_parts();
            assert!(loaded.unwrap().is_none());
            assert_eq!(vault.seals.load(Ordering::SeqCst), 4);
            for (_, plaintext) in vault.records.lock().unwrap().values() {
                assert!(
                    !plaintext
                        .windows(b"RESTART-PRIVATE".len())
                        .any(|bytes| bytes == b"RESTART-PRIVATE")
                );
                assert!(
                    !plaintext
                        .windows(b"SECRET".len())
                        .any(|bytes| bytes == b"SECRET")
                );
            }
            close(&cx, &lane, store).await;
            peer.no_extra(4);
            assert!(!client.revocation_handle().is_revoked());
        });
    }

    #[test]
    fn persisted_dpop_restart_interrupted_ack_keeps_the_same_write_and_terminal_payload() {
        for recover_parts in [false, true] {
            run(async {
                let cx = Cx::current().unwrap();
                let (mut peer, mut client, credential) = Peer::new().await;
                let current = binding("owner", client.resource().as_str());
                let previous = saved(&cx, &current, "pending-terminal");
                let guard = ProcessGenerationGuard::install().unwrap();
                let lane = CredentialIoLane::new(&guard, CredentialIoLimits::default()).unwrap();
                let directory = Directory::new();
                let vault = Vault::default();
                let _release = Release(Arc::clone(&vault.gate));
                let store = open(&cx, &lane, &guard, &directory, vault.clone(), &current).await;
                let (store, inserted) = store
                    .try_insert(&cx, current.clone(), previous.clone())
                    .unwrap()
                    .wait(&cx)
                    .await
                    .unwrap()
                    .into_parts();
                inserted.unwrap();
                let original = directory.bytes();
                let staged = store
                    .try_load_restart(&cx, current.clone(), 1, TaskResumeRestartPolicy::default())
                    .unwrap()
                    .wait(&cx)
                    .await
                    .unwrap();
                let cancellation = McpRequestCancellation::new();
                let mut restart = staged
                    .prepare_persisted_dpop_restart(
                        &cx,
                        &mut client,
                        &cancellation,
                        &credential,
                        meta(),
                        "ack".to_owned(),
                        limits(),
                    )
                    .unwrap();
                let read = async {
                    assert_terminal(restart.next_reconciled(&cx).await.unwrap().unwrap());
                };
                let serve = async {
                    let mut socket = peer.get_turn("ack", 0, previous.task_id().as_str()).await;
                    json_reply(
                        &mut socket,
                        200,
                        &turn_envelope(
                            "ack",
                            0,
                            false,
                            fresh(previous.task_id().as_str(), "completed", 2),
                        ),
                    )
                    .await;
                };
                pair(read, serve).await;
                vault.pause.store(true, Ordering::SeqCst);
                let mut waiting = Box::pin(restart.acknowledge(&cx));
                poll_fn(|task| {
                    assert!(waiting.as_mut().poll(task).is_pending());
                    Poll::Ready(())
                })
                .await;
                vault.gate.wait_entered(&cx).await;
                drop(waiting);
                assert_eq!(restart.checkpoint_state(), RestartCheckpointState::Pending);
                assert_terminal(restart.pending().unwrap());
                assert!(restart.pending_change().is_some());
                assert_eq!(directory.bytes(), original);
                assert!(matches!(
                    restart.take_without_persisting(),
                    Err(PersistedDpopTaskRestartError::Checkpoint(
                        PersistedTaskRestartError::AcknowledgementRequired
                    ))
                ));

                // A cancelled wait observes the same mailbox, while revoking
                // remote read authority cannot undo or strand a local write.
                cancellation.cancel();
                let cancelled = Cx::for_testing();
                cancelled.set_cancel_requested(true);
                assert!(matches!(
                    restart.acknowledge(&cancelled).await,
                    Err(PersistedDpopTaskRestartError::Checkpoint(
                        PersistedTaskRestartError::Persistence(TaskResumePersistenceError::Io(
                            CredentialIoError::WaitCancelled
                        ))
                    ))
                ));
                assert_eq!(restart.checkpoint_state(), RestartCheckpointState::Pending);
                assert_eq!(lane.snapshot().unwrap().operations, 1);
                assert_eq!(vault.seals.load(Ordering::SeqCst), 2);
                vault.gate.release();

                let store = if recover_parts {
                    let parts = restart.into_parts();
                    assert_eq!(parts.checkpoint_state, RestartCheckpointState::Pending);
                    assert_eq!(
                        parts.storage.status().unwrap(),
                        TaskResumePersistenceStatus::Pending
                    );
                    assert_terminal(parts.pending.as_ref().unwrap());
                    assert!(parts.pending_change.is_some());
                    parts.storage.finish_pending(&cx).await.unwrap();
                    assert_terminal(parts.pending.as_ref().unwrap());
                    parts.storage.take_store().unwrap()
                } else {
                    assert_terminal(&restart.acknowledge(&cx).await.unwrap());
                    assert!(restart.pending().is_none());
                    assert_eq!(
                        restart.checkpoint_state(),
                        RestartCheckpointState::NotAttempted
                    );
                    restart.into_parts().storage.take_store().unwrap()
                };
                assert_eq!(
                    vault.seals.load(Ordering::SeqCst),
                    2,
                    "resuming or extracting an interrupted ACK must not submit another write"
                );
                let (store, loaded) = store
                    .try_get(&cx, current.clone(), previous.key())
                    .unwrap()
                    .wait(&cx)
                    .await
                    .unwrap()
                    .into_parts();
                assert!(loaded.unwrap().is_none());
                close(&cx, &lane, store).await;
                peer.no_extra(2);
                assert!(!client.revocation_handle().is_revoked());
            });
        }
    }
}
