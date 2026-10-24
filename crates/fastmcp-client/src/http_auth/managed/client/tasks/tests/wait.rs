//! Bounded waits over the same real OAuth/TLS peer as the individual Tasks verbs.

use super::*;

#[test]
fn managed_task_wait_honors_local_and_peer_polling_floors() {
    for (local, peer_interval) in [(250, 10), (1, 250)] {
        run(async {
            let cx = Cx::current().unwrap();
            let peer = Peer::new().await;
            let session = peer.login(&cx).await;
            let mut client = peer.client(session).with_tasks();
            let (result, ()) = pair(
                client.wait_task_final(&cx, id(), Duration::from_millis(local), 4),
                async {
                    peer.discovery("access-one", true).await;
                    let mut working = task("working", "complete");
                    working["pollIntervalMs"] = json!(peer_interval);
                    let first = peer.rpc("tasks/get", "access-one", working, false).await;
                    // The existing 100ms no-contact assertion must see silence.
                    // Removing the real delay causes this to observe another TCP
                    // connection, rather than passing on a nominal policy value.
                    peer.no_more(&cx).await;
                    let second = peer
                        .rpc(
                            "tasks/get",
                            "access-one",
                            task("completed", "complete"),
                            false,
                        )
                        .await;
                    assert_ne!(first["id"], second["id"]);
                    assert_eq!(first["params"]["taskId"], "task-1");
                    assert_eq!(second["params"]["taskId"], "task-1");
                },
            )
            .await;
            assert!(matches!(result.unwrap().task, FinalTask::Completed { .. }));
            assert_eq!(client.cached_credential_generation(), Some(1));
            peer.no_more(&cx).await;
        });
    }
}

#[test]
fn managed_task_wait_returns_all_actionable_variants_without_another_poll() {
    for status in ["input_required", "completed", "failed", "cancelled"] {
        run(async {
            let cx = Cx::current().unwrap();
            let peer = Peer::new().await;
            let session = peer.login(&cx).await;
            let mut client = peer.client(session).with_tasks();
            let mut wire = task(status, "complete");
            if status == "failed" {
                wire["error"] = json!({
                    "code":-32001, "message":"task failed", "data":{"retained":true}
                });
            }
            let (result, ()) = pair(
                client.wait_task_final(&cx, id(), Duration::from_millis(1), 8),
                async {
                    peer.discovery("access-one", true).await;
                    peer.rpc("tasks/get", "access-one", wire.clone(), false)
                        .await;
                },
            )
            .await;
            // An input-required or failed task is not reinterpreted as success,
            // and neither is discarded just because the wait stopped polling.
            // The typed tool result omits a default `isError: false` when it
            // is serialized, so that explicit default is the one member the
            // peer sent that does not come back textually.
            let mut expected = wire.clone();
            if expected.pointer("/result/isError") == Some(&json!(false)) {
                expected["result"]
                    .as_object_mut()
                    .unwrap()
                    .remove("isError");
            }
            assert_eq!(serde_json::to_value(result.unwrap()).unwrap(), expected);
            peer.no_more(&cx).await;
        });
    }
}

#[test]
fn managed_task_wait_returns_latest_working_snapshot_at_exact_poll_limit() {
    run(async {
        let cx = Cx::current().unwrap();
        let peer = Peer::new().await;
        let session = peer.login(&cx).await;
        let mut client = peer.client(session).with_tasks();
        let (result, requests) = pair(
            client.wait_task_final(&cx, id(), Duration::from_millis(1), 3),
            async {
                peer.discovery("access-one", true).await;
                let mut requests = BTreeSet::new();
                for index in 0..3 {
                    let mut working = task("working", "complete");
                    working["statusMessage"] = json!(format!("working-{index}"));
                    let request = peer.rpc("tasks/get", "access-one", working, false).await;
                    assert!(requests.insert(request["id"].to_string()));
                }
                requests
            },
        )
        .await;
        let result = result.unwrap();
        assert!(matches!(&result.task, FinalTask::Working(_)));
        assert_eq!(
            result.task.base().status_message.as_deref(),
            Some("working-2")
        );
        assert_eq!(requests.len(), 3);
        assert_eq!(client.cached_credential_generation(), Some(1));
        peer.no_more(&cx).await;
    });
}

#[test]
fn managed_task_wait_interrupts_idle_delay_on_cancellation_or_session_close() {
    for close_session in [false, true] {
        run(async {
            let cx = Cx::current().unwrap();
            let peer = Peer::new().await;
            let session = peer.login(&cx).await;
            let mut client = peer.client(session.clone()).with_tasks();
            let cancellation = McpRequestCancellation::new();
            let (result, ()) = pair(
                client.wait_task_final_with_cancellation(
                    &cx,
                    &cancellation,
                    id(),
                    Duration::from_secs(60),
                    8,
                ),
                async {
                    peer.discovery("access-one", true).await;
                    peer.rpc(
                        "tasks/get",
                        "access-one",
                        task("working", "complete"),
                        false,
                    )
                    .await;
                    peer.no_more(&cx).await;
                    if close_session {
                        session.close();
                    } else {
                        cancellation.cancel();
                    }
                },
            )
            .await;
            if close_session {
                assert!(matches!(
                    result,
                    Err(ManagedHttpClientError::Session(OAuthSessionError::Closed))
                ));
            } else {
                assert!(matches!(
                    result,
                    Err(ManagedHttpClientError::Session(
                        OAuthSessionError::Cancelled
                    ))
                ));
            }
            assert_eq!(client.cached_credential_generation(), None);
            assert!(!cx.is_cancel_requested());
            peer.no_more(&cx).await;
            if !close_session {
                assert!(session.check(&cx, &McpRequestCancellation::new()).is_ok());
                let (resumed, ()) = pair(client.get_task_final(&cx, id()), async {
                    peer.discovery("access-one", true).await;
                    peer.rpc(
                        "tasks/get",
                        "access-one",
                        task("working", "complete"),
                        false,
                    )
                    .await;
                })
                .await;
                assert!(
                    resumed.is_ok(),
                    "only the cancelled operation lost its connection"
                );
            }
        });
    }
}

#[test]
fn managed_task_wait_deadline_covers_idle_time_without_poll_reset() {
    run(async {
        let cx = Cx::current().unwrap();
        let peer = Peer::new().await;
        let session = peer.login(&cx).await;
        let mut client = peer.client(session).with_tasks();
        // Establish discovery under the ordinary generous fixture timeout.
        let (primed, ()) = pair(client.get_task_final(&cx, id()), async {
            peer.discovery("access-one", true).await;
            peer.rpc(
                "tasks/get",
                "access-one",
                task("working", "complete"),
                false,
            )
            .await;
        })
        .await;
        primed.unwrap();
        client.operation_timeout = Duration::from_secs(2);
        let (result, _) = pair(
            client.wait_task_final(&cx, id(), Duration::from_secs(60), 8),
            peer.rpc(
                "tasks/get",
                "access-one",
                task("working", "complete"),
                false,
            ),
        )
        .await;
        assert!(matches!(
            result,
            Err(ManagedHttpClientError::Session(OAuthSessionError::TimedOut))
        ));
        assert_eq!(client.cached_credential_generation(), None);
        assert!(!cx.is_cancel_requested());
        peer.no_more(&cx).await;
    });
}

#[test]
fn managed_task_wait_keeps_one_credential_generation_until_the_operation_ends() {
    run(async {
        let cx = Cx::current().unwrap();
        let peer = Peer::new().await;
        let session = peer.login(&cx).await;
        let mut client = peer.client(session.clone()).with_tasks();
        let (result, ()) = pair(
            client.wait_task_final(&cx, id(), Duration::from_millis(1), 8),
            async {
                peer.discovery("access-one", true).await;
                peer.rpc(
                    "tasks/get",
                    "access-one",
                    task("working", "complete"),
                    false,
                )
                .await;
                renew(&session);
                // Renewal is now due, but the running wait still has its original
                // valid credential and deadline. A token exchange here is wrong.
                peer.rpc(
                    "tasks/get",
                    "access-one",
                    task("completed", "complete"),
                    false,
                )
                .await;
            },
        )
        .await;
        assert!(matches!(result.unwrap().task, FinalTask::Completed { .. }));
        assert_eq!(client.cached_credential_generation(), Some(1));
        let (next, ()) = pair(client.get_task_final(&cx, id()), async {
            peer.token(true).await;
            peer.discovery("access-two", true).await;
            peer.rpc(
                "tasks/get",
                "access-two",
                task("completed", "complete"),
                false,
            )
            .await;
        })
        .await;
        assert!(next.is_ok());
        assert_eq!(client.cached_credential_generation(), Some(2));
    });
}

#[test]
fn managed_task_wait_invalid_bounds_and_precancellation_refuse_before_contact() {
    run(async {
        let cx = Cx::current().unwrap();
        let peer = Peer::new().await;
        let session = peer.login(&cx).await;
        let mut disabled = peer.client(session.clone());
        assert!(matches!(
            disabled
                .wait_task_final(&cx, id(), Duration::from_millis(1), 1)
                .await,
            Err(ManagedHttpClientError::InvalidPolicy)
        ));
        let mut client = peer.client(session).with_tasks();
        for (interval, count) in [
            (Duration::ZERO, 1),
            (Duration::from_millis(1), 0),
            (Duration::from_secs(60) + Duration::from_nanos(1), 1),
            (Duration::from_millis(1), MAX_TASK_WAIT_POLLS + 1),
            (Duration::MAX, 1),
        ] {
            assert!(matches!(
                client.wait_task_final(&cx, id(), interval, count).await,
                Err(ManagedHttpClientError::InvalidPolicy)
            ));
        }
        let cancelled = McpRequestCancellation::new();
        cancelled.cancel();
        assert!(matches!(
            client
                .wait_task_final_with_cancellation(
                    &cx,
                    &cancelled,
                    id(),
                    Duration::from_millis(1),
                    1
                )
                .await,
            Err(ManagedHttpClientError::Session(
                OAuthSessionError::Cancelled
            ))
        ));
        assert_eq!(client.cached_credential_generation(), None);
        peer.no_more(&cx).await;
    });
}

#[test]
fn managed_task_wait_interval_policy_preserves_unbounded_peer_delay_and_valid_edges() {
    assert!(admit_wait(Duration::from_millis(1), 1).is_ok());
    assert!(admit_wait(Duration::from_secs(60), MAX_TASK_WAIT_POLLS).is_ok());
    for (hint, floor, expected) in [
        (None, 5, 5),
        (Some(1), 5, 5),
        (Some(50), 5, 50),
        (Some(u64::MAX), 5, u64::MAX),
    ] {
        let mut wire = task("working", "complete");
        if let Some(hint) = hint {
            wire["pollIntervalMs"] = json!(hint);
        } else {
            wire.as_object_mut().unwrap().remove("pollIntervalMs");
        }
        let snapshot: FinalGetTaskResult = serde_json::from_str(&wire.to_string()).unwrap();
        assert_eq!(
            poll_interval(&snapshot.task, Duration::from_millis(floor)).unwrap(),
            Duration::from_millis(expected)
        );
    }
}

#[test]
fn managed_task_wait_abandonment_retires_local_owner_without_remote_cancellation() {
    run(async {
        let cx = Cx::current().unwrap();
        let peer = Peer::new().await;
        let session = peer.login(&cx).await;
        let mut client = peer.client(session.clone()).with_tasks();
        {
            let mut operation =
                Box::pin(client.wait_task_final(&cx, id(), Duration::from_secs(60), 8));
            let mut server = Box::pin(async {
                peer.discovery("access-one", true).await;
                peer.rpc(
                    "tasks/get",
                    "access-one",
                    task("working", "complete"),
                    false,
                )
                .await;
                peer.no_more(&cx).await;
            });
            poll_fn(|task| {
                assert!(operation.as_mut().poll(task).is_pending());
                server.as_mut().poll(task)
            })
            .await;
            // Dropping the pending wait must not put its connection back or
            // emit a tasks/cancel request using an unobserved task snapshot.
        }
        assert_eq!(client.cached_credential_generation(), None);
        assert!(!cx.is_cancel_requested());
        assert!(session.check(&cx, &McpRequestCancellation::new()).is_ok());
        peer.no_more(&cx).await;
        let (result, ()) = pair(client.get_task_final(&cx, id()), async {
            peer.discovery("access-one", true).await;
            peer.rpc(
                "tasks/get",
                "access-one",
                task("working", "complete"),
                false,
            )
            .await;
        })
        .await;
        assert!(matches!(result.unwrap().task, FinalTask::Working(_)));
    });
}

mod resolve;
mod tool_events;
mod watch;
